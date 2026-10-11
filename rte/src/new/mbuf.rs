//! Borrowed packet buffers and the RX timestamp dynamic field.
//!
//! A [`Mbuf`] is a *view* of a packet buffer that belongs to a mempool. It
//! borrows the pool for as long as it exists, so the borrow checker guarantees
//! a packet can never outlive the pool that backs it. Dropping it calls
//! `rte_pktmbuf_free()`, which handles reference counting and multi-segment
//! packets correctly.

use core::ffi::c_int;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::ffi;

use super::error::TimestampError;
use super::mempool::MemoryPoolRef;

/// Default data room size used by `rte_pktmbuf_pool_create()`.
///
/// Mirrors `RTE_MBUF_DEFAULT_BUF_SIZE` (`RTE_MBUF_DEFAULT_DATAROOM` plus the
/// packet mbuf headroom).
pub const DEFAULT_DATA_ROOM_SIZE: u16 = ffi::RTE_MBUF_DEFAULT_BUF_SIZE as u16;

/// A packet buffer checked out of a mempool.
///
/// `Mbuf` is not a [`PoolElement`](super::PoolElement): packet mbuf pools are
/// populated by DPDK itself (`rte_pktmbuf_pool_create()`), never by a Rust
/// `init` callback. Create the pool with
/// [`MemoryPool::pktmbuf_pool`](super::MemoryPool::pktmbuf_pool).
///
/// # Thread affinity
///
/// Like every other DPDK data plane handle this is deliberately `!Send` and
/// `!Sync`: packets are meant to be processed on the lcore that polled them.
/// Wrap it if you really need to move it.
#[repr(transparent)]
pub struct Mbuf<'pool> {
    raw: NonNull<ffi::rte_mbuf>,
    _pool: PhantomData<MemoryPoolRef<'pool>>,
}

// The layout of `Option<Mbuf>` is what makes `rx_burst()` able to hand a
// `&mut [Option<Mbuf>]` straight to DPDK: `NonNull` gives `Option` a null
// niche, so the slice has the same representation as `[*mut rte_mbuf]`.
const _: () = assert!(
    core::mem::size_of::<Option<Mbuf<'static>>>() == core::mem::size_of::<*mut ffi::rte_mbuf>()
);

impl<'pool> Mbuf<'pool> {
    /// Wrap a packet buffer borrowed from a live pool.
    ///
    /// # Safety
    ///
    /// `raw` must be a packet mbuf owned by the caller, and the pool backing it
    /// must outlive the returned value.
    #[inline]
    pub(crate) unsafe fn from_raw(raw: NonNull<ffi::rte_mbuf>) -> Self {
        Self {
            raw,
            _pool: PhantomData,
        }
    }

    /// Raw pointer, for passing to DPDK directly.
    #[inline]
    pub fn as_ptr(&self) -> NonNull<ffi::rte_mbuf> {
        self.raw
    }

    /// Total length of the packet, including all segments.
    #[inline]
    pub fn pkt_len(&self) -> usize {
        // SAFETY: the view is only constructed while the mbuf is alive.
        unsafe { self.raw.as_ref() }.pkt_len as usize
    }

    /// Length of this segment's data.
    #[inline]
    pub fn data_len(&self) -> usize {
        unsafe { self.raw.as_ref() }.data_len as usize
    }

    /// Offload flags (`PKT_RX_*` / `RTE_MBUF_F_*`) reported by the PMD.
    #[inline]
    pub fn ol_flags(&self) -> u64 {
        unsafe { self.raw.as_ref() }.ol_flags
    }

    /// Port the packet was received on.
    #[inline]
    pub fn port(&self) -> u16 {
        unsafe { self.raw.as_ref() }.port
    }

    /// Number of segments in the packet.
    #[inline]
    pub fn nb_segs(&self) -> u16 {
        unsafe { self.raw.as_ref() }.nb_segs
    }

    /// Read a registered `u64` dynamic field.
    ///
    /// # Safety
    ///
    /// `offset` must be the field offset returned by a
    /// `rte_mbuf_dyn_*_register()` call, and the field must be `u64` sized.
    /// Prefer the typed wrappers such as [`RxTimestamp::get`].
    #[inline]
    pub unsafe fn read_dynfield_u64(&self, offset: i32) -> u64 {
        // SAFETY: the caller vouches for `offset`; DPDK guarantees the field
        // lives inside every mbuf of the pool.
        unsafe {
            let base = self.raw.as_ptr() as *const u8;

            (base.offset(offset as isize) as *const u64).read_unaligned()
        }
    }

    /// Give up ownership without returning the buffer to its pool.
    ///
    /// Only useful when handing the mbuf to C/C++ code that will free it.
    #[inline]
    pub fn into_raw(self) -> NonNull<ffi::rte_mbuf> {
        let raw = self.raw;

        core::mem::forget(self);

        raw
    }
}

impl Drop for Mbuf<'_> {
    fn drop(&mut self) {
        // `rte_pktmbuf_free()` already handles the reference count, so it must
        // not be preceded by a manual `rte_mbuf_refcnt_update()`.
        unsafe { ffi::_rte_pktmbuf_free(self.raw.as_ptr()) };
    }
}

impl fmt::Debug for Mbuf<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mbuf")
            .field("pkt_len", &self.pkt_len())
            .field("data_len", &self.data_len())
            .field("nb_segs", &self.nb_segs())
            .field("port", &self.port())
            .field("ol_flags", &format_args!("{:#x}", self.ol_flags()))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Hardware RX timestamp
// ---------------------------------------------------------------------------

/// Handle for the RX timestamp dynamic field shared by all pools.
///
/// Registering is process wide and must happen **before** any port is
/// configured. [`get`](Self::get) encapsulates the `ol_flags` check and the
/// unaligned read, so callers never touch raw pointers.
#[derive(Debug, Clone, Copy)]
pub struct RxTimestamp {
    field_offset: i32,
    flag: u64,
}

impl RxTimestamp {
    /// Register the timestamp dynamic field and flag.
    pub fn register() -> Result<Self, TimestampError> {
        let mut field_offset: c_int = 0;
        let mut flag: u64 = 0;

        let ret = unsafe { ffi::rte_mbuf_dyn_rx_timestamp_register(&mut field_offset, &mut flag) };

        if ret != 0 {
            return Err(TimestampError::from_rte_errno());
        }

        Ok(Self { field_offset, flag })
    }

    /// Port RX offload bit that must be requested through
    /// [`PortConfig::with_rx_offloads`](super::PortConfig::with_rx_offloads).
    #[inline]
    pub fn port_offload(self) -> u64 {
        ffi::DEV_RX_OFFLOAD_TIMESTAMP as u64
    }

    /// Dynamic flag set by the PMD on timestamped packets.
    #[inline]
    pub fn flag(self) -> u64 {
        self.flag
    }

    /// Offset of the timestamp field inside `rte_mbuf`.
    #[inline]
    pub fn field_offset(self) -> i32 {
        self.field_offset
    }

    /// Hardware timestamp of `packet`, or `None` if the PMD did not stamp it.
    #[inline]
    pub fn get(self, packet: &Mbuf<'_>) -> Option<u64> {
        if packet.ol_flags() & self.flag == 0 {
            return None;
        }

        // SAFETY: `field_offset` comes from the register call above.
        Some(unsafe { packet.read_dynfield_u64(self.field_offset) })
    }
}
