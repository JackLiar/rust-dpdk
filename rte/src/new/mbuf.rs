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

use super::error::{MbufError, TimestampError};
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
/// [`MemoryPool::pktmbuf_pool`](super::MemoryPool::pktmbuf_pool), then allocate
/// buffers with [`MemoryPoolRef::alloc_mbuf`](super::MemoryPoolRef::alloc_mbuf)
/// or [`MemoryPoolRef::alloc_mbufs`](super::MemoryPoolRef::alloc_mbufs).
///
/// # Thread affinity
///
/// `Mbuf` is `Send` but **not** `Sync`: DPDK explicitly supports moving an mbuf
/// from one lcore to another (rings, distributors, hand-off queues), and
/// `rte_pktmbuf_free()` is thread safe. It is still the caller's job to ensure
/// that only one thread mutates a given mbuf at a time.
#[repr(transparent)]
pub struct Mbuf<'pool> {
    raw: NonNull<ffi::rte_mbuf>,
    _pool: PhantomData<MemoryPoolRef<'pool>>,
}

// SAFETY: a checked-out mbuf is owned by exactly one `Mbuf` (or shared through
// `Clone`'s refcount), and DPDK's mbuf allocator/free path is thread safe.
// `Mbuf` is deliberately not `Sync`: aliasing `&Mbuf` across threads would
// allow concurrent `rte_pktmbuf_*` mutation.
unsafe impl Send for Mbuf<'_> {}

// The layout of `Option<Mbuf>` is what makes `rx_burst()` able to hand a
// `&mut [Option<Mbuf>]` straight to DPDK: `NonNull` gives `Option` a null
// niche, so the slice has the same representation as `[*mut rte_mbuf]`.
const _: () = assert!(core::mem::size_of::<Option<Mbuf<'static>>>() == core::mem::size_of::<*mut ffi::rte_mbuf>());

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

    /// Offset of the packet data inside the mbuf buffer.
    #[inline]
    pub fn data_off(&self) -> u16 {
        unsafe { self.raw.as_ref() }.data_off
    }

    /// Size of the mbuf data buffer (including headroom and tailroom).
    #[inline]
    pub fn buf_len(&self) -> u16 {
        unsafe { self.raw.as_ref() }.buf_len
    }

    /// First segment of the packet data.
    ///
    /// For segmented packets this is only the first segment; use
    /// [`contiguous_data`](Self::contiguous_data) when the whole packet is
    /// needed as one slice, or [`segments`](Self::segments) to iterate all
    /// segments.
    #[inline]
    pub fn data(&self) -> &[u8] {
        // SAFETY: the view is only constructed while the mbuf is alive, and
        // `buf_addr`/`data_off`/`data_len` are maintained by DPDK.
        unsafe {
            let mbuf = self.raw.as_ref();
            let ptr = (mbuf.buf_addr as *const u8).add(mbuf.data_off as usize);

            core::slice::from_raw_parts(ptr, mbuf.data_len as usize)
        }
    }

    /// Whole packet data, but only if it is stored in a single segment.
    ///
    /// This is the zero-copy entry point used by the capture fast path. For
    /// multi-segment packets call [`linearize`](Self::linearize) first, or fall
    /// back to a copy.
    #[inline]
    pub fn contiguous_data(&self) -> Option<&[u8]> {
        if self.is_contiguous() { Some(self.data()) } else { None }
    }

    /// Iterate over every segment of the packet.
    #[inline]
    pub fn segments(&self) -> MbufSegments<'_> {
        MbufSegments {
            next: Some(unsafe { self.raw.as_ref() }),
            remaining: unsafe { self.raw.as_ref() }.nb_segs,
        }
    }

    /// Whether the whole packet is stored in a single contiguous segment.
    #[inline]
    pub fn is_contiguous(&self) -> bool {
        unsafe { ffi::_rte_pktmbuf_is_contiguous(self.raw.as_ptr()) != 0 }
    }

    /// Merge a multi-segment packet into its first segment.
    ///
    /// Returns [`MbufError::Shared`] if the mbuf reference count is greater
    /// than one (another `Mbuf` clone owns the same buffer), or
    /// [`MbufError::Linearize`] if DPDK cannot provide enough tailroom. The
    /// packet is left unchanged on failure.
    pub fn linearize(&mut self) -> Result<(), MbufError> {
        let refcnt = unsafe { ffi::_rte_mbuf_refcnt_read(self.raw.as_ptr()) };

        if refcnt != 1 {
            return Err(MbufError::Shared { refcnt });
        }

        let ret = unsafe { ffi::_rte_pktmbuf_linearize(self.raw.as_ptr()) };

        if ret != 0 {
            Err(MbufError::from_rte_errno())
        } else {
            Ok(())
        }
    }

    /// Hardware-stripped VLAN TCI, if the PMD stripped a VLAN tag.
    #[inline]
    pub fn vlan_tci(&self) -> Option<u16> {
        // SAFETY: the mbuf is alive for the duration of the borrow.
        unsafe {
            let mbuf = self.raw.as_ref();

            if mbuf.ol_flags & ffi::PKT_RX_VLAN_STRIPPED as u64 != 0 {
                Some(mbuf.vlan_tci & 0x0fff)
            } else {
                None
            }
        }
    }

    /// Hardware-stripped outer VLAN TCI for QinQ packets.
    #[inline]
    pub fn vlan_tci_outer(&self) -> Option<u16> {
        // SAFETY: the mbuf is alive for the duration of the borrow.
        unsafe {
            let mbuf = self.raw.as_ref();

            if mbuf.ol_flags & ffi::PKT_RX_QINQ_STRIPPED as u64 != 0 {
                Some(mbuf.vlan_tci_outer & 0x0fff)
            } else {
                None
            }
        }
    }

    /// Hardware RSS hash, if the PMD computed one for this packet.
    #[inline]
    pub fn rss_hash(&self) -> Option<u32> {
        // SAFETY: the mbuf is alive for the duration of the borrow; the RSS
        // union member is only read when the matching offload flag is set.
        unsafe {
            let mbuf = self.raw.as_ref();

            if mbuf.ol_flags & ffi::PKT_RX_RSS_HASH as u64 != 0 {
                Some(mbuf.__bindgen_anon_2.hash.rss)
            } else {
                None
            }
        }
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

impl Clone for Mbuf<'_> {
    /// Add one reference to the underlying mbuf.
    ///
    /// Both handles must be dropped for the buffer to return to its pool.
    #[inline]
    fn clone(&self) -> Self {
        // SAFETY: `self.raw` is a live mbuf owned by this handle.
        unsafe {
            ffi::_rte_mbuf_refcnt_update(self.raw.as_ptr(), 1);
        }

        Self {
            raw: self.raw,
            _pool: PhantomData,
        }
    }
}

/// Iterator over the segments of a [`Mbuf`].
pub struct MbufSegments<'a> {
    next: Option<&'a ffi::rte_mbuf>,
    remaining: u16,
}

impl<'a> Iterator for MbufSegments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let mbuf = self.next?;

        self.remaining -= 1;
        self.next = if self.remaining > 0 && !mbuf.next.is_null() {
            // SAFETY: DPDK owns the fragment chain for as long as the parent
            // mbuf is alive; the iterator borrows the parent.
            Some(unsafe { &*mbuf.next })
        } else {
            None
        };

        // SAFETY: `buf_addr`/`data_off`/`data_len` are maintained by DPDK.
        let ptr = unsafe { (mbuf.buf_addr as *const u8).add(mbuf.data_off as usize) };

        Some(unsafe { core::slice::from_raw_parts(ptr, mbuf.data_len as usize) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining as usize;

        (remaining, Some(remaining))
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
