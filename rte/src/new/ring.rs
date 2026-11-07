//! Ownership-correct ring wrappers.
//!
//! See the [module documentation](crate::new) for the ownership model. The
//! short version:
//!
//! * [`Ring<'eal>`] is **owned**; dropping it calls `rte_ring_free()`.
//! * [`RingRef<'a>`] is **borrowed**; it is `Copy`, has no `Drop` and
//!   therefore can never free a ring it does not own.
//! * [`Ring::leak`] and [`Ring::into_raw`] opt out of the free.
//!
//! A ring does **not** own its elements: it stores raw element copies. When a
//! ring containing pointers or other resource handles is dropped, those
//! resources are not released automatically; drain the ring first.
//!
//! # Synchronization
//!
//! The safe enqueue/dequeue methods always use the multi-producer /
//! multi-consumer DPDK paths, so they are safe to call concurrently. The
//! [`RingRef::sp_enqueue`] / [`RingRef::sc_dequeue`] families are `unsafe`
//! because DPDK requires the caller to guarantee a single producer or consumer.

use core::ffi::{CStr, c_uint, c_void};
use core::fmt;
use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::ptr::{self, NonNull};
use std::ffi::CString;
use std::os::unix::io::AsRawFd;

use cfile;
use cfile::foreign_types::ForeignType;

use crate::ffi;

use super::eal::Eal;
use super::error::{MbufError, RingError, rte_errno, rte_strerror};
use super::mbuf::{MBUF_PTR_SIZE, Mbuf};
use super::mempool::MemoryPoolRef;

/// Longest ring name DPDK accepts, excluding the terminating NUL.
///
/// Mirrors `RTE_RING_NAMESIZE`, derived from the memzone name limit and the
/// `RG_` memzone prefix.
pub const RING_NAMESIZE: usize = ffi::RTE_MEMZONE_NAMESIZE as usize - ffi::RTE_RING_MZ_PREFIX.len() + 1;

bitflags::bitflags! {
    /// Flags accepted by `rte_ring_create_elem()`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct RingFlags: u32 {
        /// The default enqueue behavior is single-producer.
        const SP_ENQ = ffi::RING_F_SP_ENQ;
        /// The default dequeue behavior is single-consumer.
        const SC_DEQ = ffi::RING_F_SC_DEQ;
        /// Store exactly the requested number of entries.
        const EXACT_SZ = ffi::RING_F_EXACT_SZ;
        /// The default enqueue behavior is multi-producer RTS.
        const MP_RTS_ENQ = ffi::RING_F_MP_RTS_ENQ;
        /// The default dequeue behavior is multi-consumer RTS.
        const MC_RTS_DEQ = ffi::RING_F_MC_RTS_DEQ;
        /// The default enqueue behavior is multi-producer HTS.
        const MP_HTS_ENQ = ffi::RING_F_MP_HTS_ENQ;
        /// The default dequeue behavior is multi-consumer HTS.
        const MC_HTS_DEQ = ffi::RING_F_MC_HTS_DEQ;
    }
}

/// An element type that can be copied into and out of an RTE ring.
///
/// # Safety
///
/// * `Self` must be `Copy`.
/// * `size_of::<Self>()` must be non-zero and a multiple of four.
/// * The type must have no padding bytes, and every bit pattern of
///   `size_of::<Self>()` bytes must be a valid value. A dequeue may materialise
///   a value from bytes that were written by another producer.
/// * If the ring is shared between threads, `Self` must also be `Send`.
pub unsafe trait RingElement: Copy {}

macro_rules! impl_ring_element {
    ($($ty:ty),* $(,)?) => {
        $(
            // SAFETY: these are plain integer/float types with no padding and
            // every bit pattern is a valid value.
            unsafe impl RingElement for $ty {}
        )*
    };
}

impl_ring_element!(u32, i32, u64, i64, u128, i128, usize, isize, f32, f64);

// SAFETY: a raw pointer is a plain word with no padding and every bit pattern
// is valid. Sharing a ring of pointers between threads is the caller's
// responsibility (the pointer's pointee must itself be safe to transfer).
unsafe impl<T> RingElement for *mut T {}
unsafe impl<T> RingElement for *const T {}

// SAFETY: a byte array has no padding and every bit pattern is valid. Sizes
// that are not a multiple of four are rejected when the ring is created.
unsafe impl<const N: usize> RingElement for [u8; N] {}

/// A snapshot of the interesting fields of an `rte_ring`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingInfo {
    pub name: String,
    pub flags: RingFlags,
    /// Element size supplied when the ring was created or looked up.
    pub element_size: usize,
    /// Number of slots in the data store.
    pub size: usize,
    /// Number of usable entries (`size - 1` unless `EXACT_SZ` was used).
    pub capacity: usize,
    /// Current number of entries.
    pub count: usize,
    /// Current number of free entries.
    pub free_count: usize,
    /// Whether the default producer behavior is single-producer.
    pub prod_single: bool,
    /// Whether the default consumer behavior is single-consumer.
    pub cons_single: bool,
}

/// Validate a ring name before handing it to DPDK.
fn validate_name(name: &str) -> Result<CString, RingError> {
    let invalid = || RingError::InvalidName {
        name: name.to_string(),
        len: name.len(),
        max: RING_NAMESIZE,
    };

    if name.is_empty() || name.len() > RING_NAMESIZE {
        return Err(invalid());
    }

    CString::new(name).map_err(|_| invalid())
}

/// DPDK requires an element size that is a non-zero multiple of four bytes.
fn validate_element_size(size: usize) -> Result<(), RingError> {
    if size == 0 || size % 4 != 0 || size > u32::MAX as usize {
        return Err(RingError::InvalidElementSize { size });
    }

    Ok(())
}

/// Validate the requested capacity against DPDK's power-of-two/exact-size rules.
fn validate_capacity(capacity: u32, flags: RingFlags) -> Result<(), RingError> {
    if capacity == 0
        || capacity > ffi::RTE_RING_SZ_MASK
        || (!flags.contains(RingFlags::EXACT_SZ) && !capacity.is_power_of_two())
    {
        return Err(RingError::InvalidCapacity { count: capacity });
    }

    Ok(())
}

/// RTS/HTS rings use a different head/tail layout and are not supported by the
/// explicit MP/MC entry points used by this wrapper.
const fn unsupported_flags_mask() -> u32 {
    RingFlags::MP_RTS_ENQ.bits()
        | RingFlags::MC_RTS_DEQ.bits()
        | RingFlags::MP_HTS_ENQ.bits()
        | RingFlags::MC_HTS_DEQ.bits()
}

fn validate_flags(flags: RingFlags) -> Result<(), RingError> {
    if flags.bits() & unsupported_flags_mask() != 0 {
        return Err(RingError::UnsupportedFlags { flags: flags.bits() });
    }

    Ok(())
}

/// Read the ring name into an owned `String`.
fn name_of(raw: NonNull<ffi::rte_ring>) -> String {
    // SAFETY: `name` is a NUL terminated character array inside a live ring.
    unsafe { CStr::from_ptr((*raw.as_ptr()).name.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// Read the ring fields into an owned snapshot.
fn info_of(raw: NonNull<ffi::rte_ring>, element_size: usize) -> RingInfo {
    // SAFETY: the caller holds a live ring handle for the duration of the call.
    let raw_ref = unsafe { raw.as_ref() };

    RingInfo {
        name: name_of(raw),
        flags: RingFlags::from_bits_truncate(raw_ref.flags as u32),
        element_size,
        // SAFETY: every helper below only reads fields of the live ring.
        size: unsafe { ffi::_rte_ring_get_size(raw.as_ptr()) } as usize,
        capacity: unsafe { ffi::_rte_ring_get_capacity(raw.as_ptr()) } as usize,
        count: unsafe { ffi::_rte_ring_count(raw.as_ptr()) } as usize,
        free_count: unsafe { ffi::_rte_ring_free_count(raw.as_ptr()) } as usize,
        prod_single: unsafe { ffi::_rte_ring_is_prod_single(raw.as_ptr()) } != 0,
        cons_single: unsafe { ffi::_rte_ring_is_cons_single(raw.as_ptr()) } != 0,
    }
}

/// Turn the raw result of `rte_ring_create_elem()` into a ring or a typed error.
fn wrap_created<'eal>(
    raw: *mut ffi::rte_ring,
    name: &str,
    capacity: u32,
    elt_size: usize,
) -> Result<Ring<'eal>, RingError> {
    match NonNull::new(raw) {
        Some(raw) => Ok(Ring {
            raw,
            element_size: elt_size,
            _eal: PhantomData,
        }),
        None => {
            let errno = rte_errno();

            Err(match errno {
                libc::EEXIST => RingError::AlreadyExists { name: name.to_string() },
                libc::ENOMEM | libc::ENOSPC => RingError::NoMemory {
                    name: name.to_string(),
                    capacity,
                    elt_size,
                },
                _ => RingError::Rte {
                    errno,
                    message: rte_strerror(errno),
                },
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Owned handle
// ---------------------------------------------------------------------------

/// An **owned** ring.
///
/// Dropping it calls `rte_ring_free()`. The handle borrows an [`Eal`], so the
/// ring can never outlive the EAL.
///
/// # Element ownership
///
/// The ring stores raw element copies and never runs destructors. If elements
/// are pointers or handles to owned resources, drain the ring before dropping
/// it.
#[must_use = "a Ring is freed when dropped; use `leak()` or `into_raw()` to opt out"]
pub struct Ring<'eal> {
    raw: NonNull<ffi::rte_ring>,
    element_size: usize,
    _eal: PhantomData<&'eal Eal>,
}

// SAFETY: DPDK rings are synchronization primitives designed for concurrent
// MP/MC use, and the safe methods always take the multi-producer/multi-consumer
// paths. The caller must ensure the element type is safe to transfer between
// threads (see `RingElement`).
unsafe impl Send for Ring<'_> {}
unsafe impl Sync for Ring<'_> {}

impl<'eal> Ring<'eal> {
    /// Create a ring of `T` with `capacity` entries.
    ///
    /// The ring is placed on [`Eal::socket_id`]; use
    /// [`create_on_socket`](Self::create_on_socket) to choose the NUMA socket
    /// explicitly.
    pub fn create<T: RingElement>(
        eal: &'eal Eal,
        name: &str,
        capacity: u32,
        flags: RingFlags,
    ) -> Result<Self, RingError> {
        Self::create_on_socket::<T>(eal, name, capacity, flags, eal.socket_id())
    }

    /// Create a ring of `T` on an explicit NUMA socket.
    pub fn create_on_socket<T: RingElement>(
        eal: &'eal Eal,
        name: &str,
        capacity: u32,
        flags: RingFlags,
        socket_id: i32,
    ) -> Result<Self, RingError> {
        Self::create_elem_on_socket(eal, name, mem::size_of::<T>(), capacity, flags, socket_id)
    }

    /// Create a raw ring with an explicit element size.
    ///
    /// Use this for element layouts that do not correspond to a Rust
    /// [`RingElement`], or when the size is only known at runtime.
    pub fn create_elem(
        eal: &'eal Eal,
        name: &str,
        element_size: usize,
        capacity: u32,
        flags: RingFlags,
    ) -> Result<Self, RingError> {
        Self::create_elem_on_socket(eal, name, element_size, capacity, flags, eal.socket_id())
    }

    /// Create a raw ring with an explicit element size and NUMA socket.
    pub fn create_elem_on_socket(
        eal: &'eal Eal,
        name: &str,
        element_size: usize,
        capacity: u32,
        flags: RingFlags,
        socket_id: i32,
    ) -> Result<Self, RingError> {
        let _ = eal;

        validate_flags(flags)?;
        validate_element_size(element_size)?;
        validate_capacity(capacity, flags)?;

        let cname = validate_name(name)?;

        // SAFETY: `cname` is a valid NUL terminated string and the remaining
        // arguments were validated above.
        let raw = unsafe {
            ffi::rte_ring_create_elem(
                cname.as_ptr(),
                element_size as c_uint,
                capacity,
                socket_id,
                flags.bits(),
            )
        };

        wrap_created(raw, name, capacity, element_size)
    }

    /// Take ownership of a raw ring.
    ///
    /// # Safety
    ///
    /// `raw` must be a ring this process created and nobody else will free,
    /// and `element_size` must be the size used to create it.
    pub unsafe fn from_raw(eal: &'eal Eal, raw: NonNull<ffi::rte_ring>, element_size: usize) -> Self {
        let _ = eal;

        debug_assert!(element_size != 0 && element_size % 4 == 0, "invalid ring element size");

        Self {
            raw,
            element_size,
            _eal: PhantomData,
        }
    }

    /// Borrow the ring.
    #[inline]
    pub fn as_ref(&self) -> RingRef<'_> {
        RingRef::from_raw(self.raw, self.element_size)
    }

    /// Raw pointer, for passing to DPDK directly.
    #[inline]
    pub fn as_ptr(&self) -> NonNull<ffi::rte_ring> {
        self.raw
    }

    /// Element size used to create the ring.
    #[inline]
    pub fn element_size(&self) -> usize {
        self.element_size
    }

    /// Snapshot of the ring fields.
    #[inline]
    pub fn info(&self) -> RingInfo {
        info_of(self.raw, self.element_size)
    }

    /// Flags supplied at creation time.
    #[inline]
    pub fn flags(&self) -> RingFlags {
        // SAFETY: the handle is only constructed while the ring is alive.
        RingFlags::from_bits_truncate(unsafe { self.raw.as_ref().flags } as u32)
    }

    /// Number of usable entries in the ring.
    #[inline]
    pub fn capacity(&self) -> usize {
        // SAFETY: the handle is only constructed while the ring is alive.
        unsafe { ffi::_rte_ring_get_capacity(self.raw.as_ptr()) as usize }
    }

    /// Number of slots in the ring's data store.
    #[inline]
    pub fn size(&self) -> usize {
        // SAFETY: the handle is only constructed while the ring is alive.
        unsafe { ffi::_rte_ring_get_size(self.raw.as_ptr()) as usize }
    }

    /// Current number of entries.
    #[inline]
    pub fn count(&self) -> usize {
        unsafe { ffi::_rte_ring_count(self.raw.as_ptr()) as usize }
    }

    /// Current number of free entries.
    #[inline]
    pub fn free_count(&self) -> usize {
        unsafe { ffi::_rte_ring_free_count(self.raw.as_ptr()) as usize }
    }

    /// Whether the ring is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        unsafe { ffi::_rte_ring_full(self.raw.as_ptr()) != 0 }
    }

    /// Whether the ring is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        unsafe { ffi::_rte_ring_empty(self.raw.as_ptr()) != 0 }
    }

    /// Whether the default producer behavior is single-producer.
    #[inline]
    pub fn prod_single(&self) -> bool {
        unsafe { ffi::_rte_ring_is_prod_single(self.raw.as_ptr()) != 0 }
    }

    /// Whether the default consumer behavior is single-consumer.
    #[inline]
    pub fn cons_single(&self) -> bool {
        unsafe { ffi::_rte_ring_is_cons_single(self.raw.as_ptr()) != 0 }
    }

    /// Give up ownership **without** freeing the ring.
    #[inline]
    pub fn leak(self) -> NonNull<ffi::rte_ring> {
        let raw = self.raw;

        mem::forget(self);

        raw
    }

    /// Alias for [`leak`](Self::leak), mirroring `Box::into_raw`.
    #[inline]
    pub fn into_raw(self) -> NonNull<ffi::rte_ring> {
        self.leak()
    }

    /// Explicitly free the ring.
    ///
    /// This is the explicit form of `Drop`; it does not drain the elements.
    pub fn destroy(self) {
        let raw = self.raw;

        mem::forget(self);

        // SAFETY: `raw` is owned by this handle and is freed exactly once.
        unsafe { ffi::rte_ring_free(raw.as_ptr()) };
    }

    /// Flush all elements from the ring (`rte_ring_reset()`).
    ///
    /// `&mut self` guarantees that no [`RingRef`] exists for the duration of
    /// the call. The elements themselves are discarded, not dropped.
    pub fn clear(&mut self) {
        // SAFETY: exclusive access is guaranteed by `&mut self`.
        unsafe { ffi::rte_ring_reset(self.raw.as_ptr()) };
    }

    /// Memory size needed for a ring of `T` with `capacity` slots.
    pub fn mem_size<T: RingElement>(capacity: u32) -> Result<usize, RingError> {
        Self::mem_size_elem(mem::size_of::<T>(), capacity)
    }

    /// Memory size needed for a ring with an explicit element size.
    pub fn mem_size_elem(element_size: usize, capacity: u32) -> Result<usize, RingError> {
        validate_element_size(element_size)?;

        if capacity == 0 || capacity > ffi::RTE_RING_SZ_MASK {
            return Err(RingError::InvalidCapacity { count: capacity });
        }

        // SAFETY: both arguments are plain scalars.
        let size = unsafe { ffi::rte_ring_get_memsize_elem(element_size as c_uint, capacity) };

        if size > 0 {
            return Ok(size as usize);
        }

        let errno = if size < 0 { (-size) as i32 } else { rte_errno() };

        Err(match errno {
            libc::EINVAL => RingError::InvalidCapacity { count: capacity },
            _ => RingError::Rte {
                errno,
                message: rte_strerror(errno),
            },
        })
    }

    /// Dump the ring status to `writer`.
    pub fn dump<S: AsRawFd>(&self, writer: &S) -> std::io::Result<()> {
        self.as_ref().dump(writer)
    }

    /// Dump every ring on the console.
    pub fn list_dump<S: AsRawFd>(writer: &S) -> std::io::Result<()> {
        let mut file = cfile::fdopen(writer, "w")?;

        // SAFETY: `file` is a valid stream for the duration of the call.
        unsafe { ffi::rte_ring_list_dump(file.as_ptr() as *mut _) };

        Ok(())
    }

    /// Enqueue one element. See [`RingRef::enqueue`].
    #[inline]
    pub fn enqueue<T: RingElement>(&self, value: T) -> Result<(), RingError> {
        self.as_ref().enqueue(value)
    }

    /// Enqueue a fixed-size batch. See [`RingRef::enqueue_bulk`].
    #[inline]
    pub fn enqueue_bulk<T: RingElement>(&self, objs: &[T]) -> Result<(), RingError> {
        self.as_ref().enqueue_bulk(objs)
    }

    /// Enqueue as many elements as fit. See [`RingRef::enqueue_burst`].
    #[inline]
    pub fn enqueue_burst<T: RingElement>(&self, objs: &[T]) -> Result<usize, RingError> {
        self.as_ref().enqueue_burst(objs)
    }

    /// Dequeue one element. See [`RingRef::dequeue`].
    #[inline]
    pub fn dequeue<T: RingElement>(&self) -> Result<T, RingError> {
        self.as_ref().dequeue()
    }

    /// Dequeue a fixed-size batch. See [`RingRef::dequeue_bulk`].
    #[inline]
    pub fn dequeue_bulk<T: RingElement>(&self, objs: &mut [T]) -> Result<(), RingError> {
        self.as_ref().dequeue_bulk(objs)
    }

    /// Dequeue as many elements as are available. See [`RingRef::dequeue_burst`].
    #[inline]
    pub fn dequeue_burst<T: RingElement>(&self, objs: &mut [T]) -> Result<usize, RingError> {
        self.as_ref().dequeue_burst(objs)
    }

    /// Single-producer enqueue. See [`RingRef::sp_enqueue`].
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only producer of this ring.
    #[inline]
    pub unsafe fn sp_enqueue<T: RingElement>(&self, value: T) -> Result<(), RingError> {
        // SAFETY: delegated to the caller.
        unsafe { self.as_ref().sp_enqueue(value) }
    }

    /// Single-producer enqueue batch. See [`RingRef::sp_enqueue_bulk`].
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only producer of this ring.
    #[inline]
    pub unsafe fn sp_enqueue_bulk<T: RingElement>(&self, objs: &[T]) -> Result<(), RingError> {
        // SAFETY: delegated to the caller.
        unsafe { self.as_ref().sp_enqueue_bulk(objs) }
    }

    /// Single-producer burst enqueue. See [`RingRef::sp_enqueue_burst`].
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only producer of this ring.
    #[inline]
    pub unsafe fn sp_enqueue_burst<T: RingElement>(&self, objs: &[T]) -> Result<usize, RingError> {
        // SAFETY: delegated to the caller.
        unsafe { self.as_ref().sp_enqueue_burst(objs) }
    }

    /// Single-consumer dequeue. See [`RingRef::sc_dequeue`].
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only consumer of this ring.
    #[inline]
    pub unsafe fn sc_dequeue<T: RingElement>(&self) -> Result<T, RingError> {
        // SAFETY: delegated to the caller.
        unsafe { self.as_ref().sc_dequeue() }
    }

    /// Single-consumer dequeue batch. See [`RingRef::sc_dequeue_bulk`].
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only consumer of this ring.
    #[inline]
    pub unsafe fn sc_dequeue_bulk<T: RingElement>(&self, objs: &mut [T]) -> Result<(), RingError> {
        // SAFETY: delegated to the caller.
        unsafe { self.as_ref().sc_dequeue_bulk(objs) }
    }

    /// Single-consumer burst dequeue. See [`RingRef::sc_dequeue_burst`].
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only consumer of this ring.
    #[inline]
    pub unsafe fn sc_dequeue_burst<T: RingElement>(&self, objs: &mut [T]) -> Result<usize, RingError> {
        // SAFETY: delegated to the caller.
        unsafe { self.as_ref().sc_dequeue_burst(objs) }
    }
}

impl Drop for Ring<'_> {
    fn drop(&mut self) {
        // SAFETY: `raw` is owned by this handle and freed exactly once.
        unsafe { ffi::rte_ring_free(self.raw.as_ptr()) };
    }
}

impl fmt::Debug for Ring<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.info().fmt(f)
    }
}

// ---------------------------------------------------------------------------
// Borrowed view
// ---------------------------------------------------------------------------

/// A **borrowed** view of a ring.
///
/// It is `Copy` and has no `Drop`, so it is structurally impossible to free a
/// ring through this handle.
#[derive(Clone, Copy)]
pub struct RingRef<'a> {
    raw: NonNull<ffi::rte_ring>,
    element_size: usize,
    _borrow: PhantomData<&'a ()>,
}

// SAFETY: the view is a read-only copy of the handle; the ring itself is safe
// for concurrent MP/MC use. See `Ring` for the element-type caveat.
unsafe impl Send for RingRef<'_> {}
unsafe impl Sync for RingRef<'_> {}

impl<'a> RingRef<'a> {
    /// Wrap a pointer that is known to be borrowed.
    #[inline]
    pub(crate) fn from_raw(raw: NonNull<ffi::rte_ring>, element_size: usize) -> Self {
        Self {
            raw,
            element_size,
            _borrow: PhantomData,
        }
    }

    /// Look a ring up by name.
    ///
    /// # Safety
    ///
    /// `rte_ring_lookup()` only establishes that the ring exists *right now*.
    /// The returned view borrows the caller supplied lifetime, so the caller
    /// must guarantee that nobody frees the ring while the view is alive.
    pub(crate) unsafe fn lookup(name: &str, element_size: usize) -> Result<Self, RingError> {
        validate_element_size(element_size)?;

        let cname = validate_name(name)?;

        // SAFETY: delegated to the caller, see above.
        let raw = unsafe { ffi::rte_ring_lookup(cname.as_ptr()) };

        let raw = NonNull::new(raw).ok_or_else(|| RingError::NotFound { name: name.to_string() })?;

        // SAFETY: the lookup just returned a live ring.
        let flags = unsafe { raw.as_ref().flags } as u32;

        if flags & unsupported_flags_mask() != 0 {
            return Err(RingError::UnsupportedFlags { flags });
        }

        Ok(Self::from_raw(raw, element_size))
    }

    /// Raw pointer, for passing to DPDK directly.
    #[inline]
    pub fn as_ptr(self) -> NonNull<ffi::rte_ring> {
        self.raw
    }

    /// Element size supplied when the ring was created or looked up.
    #[inline]
    pub fn element_size(self) -> usize {
        self.element_size
    }

    /// Snapshot of the ring fields.
    #[inline]
    pub fn info(self) -> RingInfo {
        info_of(self.raw, self.element_size)
    }

    /// Flags supplied at creation time.
    #[inline]
    pub fn flags(self) -> RingFlags {
        // SAFETY: the view is only constructed while the ring is alive.
        RingFlags::from_bits_truncate(unsafe { self.raw.as_ref().flags } as u32)
    }

    /// Number of usable entries in the ring.
    #[inline]
    pub fn capacity(self) -> usize {
        unsafe { ffi::_rte_ring_get_capacity(self.raw.as_ptr()) as usize }
    }

    /// Number of slots in the ring's data store.
    #[inline]
    pub fn size(self) -> usize {
        unsafe { ffi::_rte_ring_get_size(self.raw.as_ptr()) as usize }
    }

    /// Current number of entries.
    #[inline]
    pub fn count(self) -> usize {
        unsafe { ffi::_rte_ring_count(self.raw.as_ptr()) as usize }
    }

    /// Current number of free entries.
    #[inline]
    pub fn free_count(self) -> usize {
        unsafe { ffi::_rte_ring_free_count(self.raw.as_ptr()) as usize }
    }

    /// Whether the ring is full.
    #[inline]
    pub fn is_full(self) -> bool {
        unsafe { ffi::_rte_ring_full(self.raw.as_ptr()) != 0 }
    }

    /// Whether the ring is empty.
    #[inline]
    pub fn is_empty(self) -> bool {
        unsafe { ffi::_rte_ring_empty(self.raw.as_ptr()) != 0 }
    }

    /// Whether the default producer behavior is single-producer.
    #[inline]
    pub fn prod_single(self) -> bool {
        unsafe { ffi::_rte_ring_is_prod_single(self.raw.as_ptr()) != 0 }
    }

    /// Whether the default consumer behavior is single-consumer.
    #[inline]
    pub fn cons_single(self) -> bool {
        unsafe { ffi::_rte_ring_is_cons_single(self.raw.as_ptr()) != 0 }
    }

    /// Verify that `T` has the element size configured on this ring.
    #[inline]
    fn check_element<T: RingElement>(self) -> Result<(), RingError> {
        let actual = mem::size_of::<T>();

        if actual == self.element_size {
            Ok(())
        } else {
            Err(RingError::ElementSizeMismatch {
                expected: self.element_size,
                actual,
            })
        }
    }

    /// Enqueue one element using the multi-producer path.
    pub fn enqueue<T: RingElement>(self, value: T) -> Result<(), RingError> {
        self.check_element::<T>()?;

        // SAFETY: `value` is `element_size` bytes and lives for the call.
        let n = unsafe {
            ffi::_rte_ring_mp_enqueue_bulk_elem(
                self.raw.as_ptr(),
                (&value as *const T).cast::<c_void>(),
                self.element_size as c_uint,
                1,
                ptr::null_mut(),
            )
        };

        if n == 1 {
            Ok(())
        } else {
            Err(RingError::Full {
                name: name_of(self.raw),
            })
        }
    }

    /// Enqueue a fixed-size batch using the multi-producer path.
    ///
    /// Either every element is enqueued or `Full` is returned and none are.
    pub fn enqueue_bulk<T: RingElement>(self, objs: &[T]) -> Result<(), RingError> {
        self.check_element::<T>()?;

        if objs.is_empty() {
            return Ok(());
        }

        debug_assert!(objs.len() <= u32::MAX as usize);

        // SAFETY: `objs` is `objs.len() * element_size` bytes and lives for the call.
        let n = unsafe {
            ffi::_rte_ring_mp_enqueue_bulk_elem(
                self.raw.as_ptr(),
                objs.as_ptr().cast::<c_void>(),
                self.element_size as c_uint,
                objs.len() as c_uint,
                ptr::null_mut(),
            )
        };

        if n as usize == objs.len() {
            Ok(())
        } else {
            Err(RingError::Full {
                name: name_of(self.raw),
            })
        }
    }

    /// Enqueue as many elements as fit using the multi-producer path.
    ///
    /// Returns the number of elements actually enqueued.
    pub fn enqueue_burst<T: RingElement>(self, objs: &[T]) -> Result<usize, RingError> {
        self.check_element::<T>()?;

        if objs.is_empty() {
            return Ok(0);
        }

        debug_assert!(objs.len() <= u32::MAX as usize);

        // SAFETY: `objs` is `objs.len() * element_size` bytes and lives for the call.
        let n = unsafe {
            ffi::_rte_ring_mp_enqueue_burst_elem(
                self.raw.as_ptr(),
                objs.as_ptr().cast::<c_void>(),
                self.element_size as c_uint,
                objs.len() as c_uint,
                ptr::null_mut(),
            )
        };

        Ok(n as usize)
    }

    /// Dequeue one element using the multi-consumer path.
    pub fn dequeue<T: RingElement>(self) -> Result<T, RingError> {
        self.check_element::<T>()?;

        let mut out = MaybeUninit::<T>::uninit();

        // SAFETY: `out` has `element_size` bytes of writable storage.
        let n = unsafe {
            ffi::_rte_ring_mc_dequeue_bulk_elem(
                self.raw.as_ptr(),
                out.as_mut_ptr().cast::<c_void>(),
                self.element_size as c_uint,
                1,
                ptr::null_mut(),
            )
        };

        if n == 1 {
            // SAFETY: DPDK initialised the element, and `RingElement` promises
            // that every bit pattern is a valid value.
            Ok(unsafe { out.assume_init() })
        } else {
            Err(RingError::Empty {
                name: name_of(self.raw),
            })
        }
    }

    /// Dequeue a fixed-size batch using the multi-consumer path.
    ///
    /// Either every slot is filled or `Empty` is returned and none are changed.
    pub fn dequeue_bulk<T: RingElement>(self, objs: &mut [T]) -> Result<(), RingError> {
        self.check_element::<T>()?;

        if objs.is_empty() {
            return Ok(());
        }

        debug_assert!(objs.len() <= u32::MAX as usize);

        // SAFETY: `objs` has `objs.len() * element_size` bytes of writable storage.
        let n = unsafe {
            ffi::_rte_ring_mc_dequeue_bulk_elem(
                self.raw.as_ptr(),
                objs.as_mut_ptr().cast::<c_void>(),
                self.element_size as c_uint,
                objs.len() as c_uint,
                ptr::null_mut(),
            )
        };

        if n as usize == objs.len() {
            Ok(())
        } else {
            Err(RingError::Empty {
                name: name_of(self.raw),
            })
        }
    }

    /// Dequeue as many elements as are available using the multi-consumer path.
    ///
    /// Returns the number of elements actually dequeued.
    pub fn dequeue_burst<T: RingElement>(self, objs: &mut [T]) -> Result<usize, RingError> {
        self.check_element::<T>()?;

        if objs.is_empty() {
            return Ok(0);
        }

        debug_assert!(objs.len() <= u32::MAX as usize);

        // SAFETY: `objs` has `objs.len() * element_size` bytes of writable storage.
        let n = unsafe {
            ffi::_rte_ring_mc_dequeue_burst_elem(
                self.raw.as_ptr(),
                objs.as_mut_ptr().cast::<c_void>(),
                self.element_size as c_uint,
                objs.len() as c_uint,
                ptr::null_mut(),
            )
        };

        Ok(n as usize)
    }

    /// Enqueue one element using the single-producer path.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only producer of this ring.
    pub unsafe fn sp_enqueue<T: RingElement>(self, value: T) -> Result<(), RingError> {
        self.check_element::<T>()?;

        // SAFETY: `value` is `element_size` bytes and lives for the call; the
        // caller guarantees exclusive producer access.
        let n = unsafe {
            ffi::_rte_ring_sp_enqueue_bulk_elem(
                self.raw.as_ptr(),
                (&value as *const T).cast::<c_void>(),
                self.element_size as c_uint,
                1,
                ptr::null_mut(),
            )
        };

        if n == 1 {
            Ok(())
        } else {
            Err(RingError::Full {
                name: name_of(self.raw),
            })
        }
    }

    /// Enqueue a fixed-size batch using the single-producer path.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only producer of this ring.
    pub unsafe fn sp_enqueue_bulk<T: RingElement>(self, objs: &[T]) -> Result<(), RingError> {
        self.check_element::<T>()?;

        if objs.is_empty() {
            return Ok(());
        }

        debug_assert!(objs.len() <= u32::MAX as usize);

        // SAFETY: `objs` lives for the call; the caller guarantees exclusive
        // producer access.
        let n = unsafe {
            ffi::_rte_ring_sp_enqueue_bulk_elem(
                self.raw.as_ptr(),
                objs.as_ptr().cast::<c_void>(),
                self.element_size as c_uint,
                objs.len() as c_uint,
                ptr::null_mut(),
            )
        };

        if n as usize == objs.len() {
            Ok(())
        } else {
            Err(RingError::Full {
                name: name_of(self.raw),
            })
        }
    }

    /// Enqueue as many elements as fit using the single-producer path.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only producer of this ring.
    pub unsafe fn sp_enqueue_burst<T: RingElement>(self, objs: &[T]) -> Result<usize, RingError> {
        self.check_element::<T>()?;

        if objs.is_empty() {
            return Ok(0);
        }

        debug_assert!(objs.len() <= u32::MAX as usize);

        // SAFETY: `objs` lives for the call; the caller guarantees exclusive
        // producer access.
        let n = unsafe {
            ffi::_rte_ring_sp_enqueue_burst_elem(
                self.raw.as_ptr(),
                objs.as_ptr().cast::<c_void>(),
                self.element_size as c_uint,
                objs.len() as c_uint,
                ptr::null_mut(),
            )
        };

        Ok(n as usize)
    }

    /// Dequeue one element using the single-consumer path.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only consumer of this ring.
    pub unsafe fn sc_dequeue<T: RingElement>(self) -> Result<T, RingError> {
        self.check_element::<T>()?;

        let mut out = MaybeUninit::<T>::uninit();

        // SAFETY: `out` has `element_size` bytes of writable storage; the
        // caller guarantees exclusive consumer access.
        let n = unsafe {
            ffi::_rte_ring_sc_dequeue_bulk_elem(
                self.raw.as_ptr(),
                out.as_mut_ptr().cast::<c_void>(),
                self.element_size as c_uint,
                1,
                ptr::null_mut(),
            )
        };

        if n == 1 {
            // SAFETY: DPDK initialised the element, and `RingElement` promises
            // that every bit pattern is a valid value.
            Ok(unsafe { out.assume_init() })
        } else {
            Err(RingError::Empty {
                name: name_of(self.raw),
            })
        }
    }

    /// Dequeue a fixed-size batch using the single-consumer path.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only consumer of this ring.
    pub unsafe fn sc_dequeue_bulk<T: RingElement>(self, objs: &mut [T]) -> Result<(), RingError> {
        self.check_element::<T>()?;

        if objs.is_empty() {
            return Ok(());
        }

        debug_assert!(objs.len() <= u32::MAX as usize);

        // SAFETY: `objs` is writable for the call; the caller guarantees
        // exclusive consumer access.
        let n = unsafe {
            ffi::_rte_ring_sc_dequeue_bulk_elem(
                self.raw.as_ptr(),
                objs.as_mut_ptr().cast::<c_void>(),
                self.element_size as c_uint,
                objs.len() as c_uint,
                ptr::null_mut(),
            )
        };

        if n as usize == objs.len() {
            Ok(())
        } else {
            Err(RingError::Empty {
                name: name_of(self.raw),
            })
        }
    }

    /// Dequeue as many elements as are available using the single-consumer path.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that it is the only consumer of this ring.
    pub unsafe fn sc_dequeue_burst<T: RingElement>(self, objs: &mut [T]) -> Result<usize, RingError> {
        self.check_element::<T>()?;

        if objs.is_empty() {
            return Ok(0);
        }

        debug_assert!(objs.len() <= u32::MAX as usize);

        // SAFETY: `objs` is writable for the call; the caller guarantees
        // exclusive consumer access.
        let n = unsafe {
            ffi::_rte_ring_sc_dequeue_burst_elem(
                self.raw.as_ptr(),
                objs.as_mut_ptr().cast::<c_void>(),
                self.element_size as c_uint,
                objs.len() as c_uint,
                ptr::null_mut(),
            )
        };

        Ok(n as usize)
    }

    /// Flush all elements from the ring (`rte_ring_reset()`).
    ///
    /// # Safety
    ///
    /// DPDK requires that the ring is not in use while it is reset. Because
    /// [`RingRef`] is `Copy`, the caller must guarantee that no other producer
    /// or consumer is active.
    pub unsafe fn reset(self) {
        // SAFETY: delegated to the caller.
        unsafe { ffi::rte_ring_reset(self.raw.as_ptr()) };
    }

    /// Dump the ring status to `writer`.
    pub fn dump<S: AsRawFd>(self, writer: &S) -> std::io::Result<()> {
        let mut file = cfile::fdopen(writer, "w")?;

        // SAFETY: `file` is a valid stream for the duration of the call.
        unsafe { ffi::rte_ring_dump(file.as_ptr() as *mut _, self.raw.as_ptr()) };

        Ok(())
    }
}

impl fmt::Debug for RingRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.info().fmt(f)
    }
}

// ---------------------------------------------------------------------------
// Typed mbuf channel
// ---------------------------------------------------------------------------

/// A ring that transfers [`Mbuf`] ownership between lcores or processes.
///
/// RTE rings store their elements by value and never run destructors, so an
/// owning [`Mbuf`] cannot be enqueued directly. This wrapper performs the
/// explicit ownership dance instead:
///
/// * [`enqueue`](Self::enqueue) consumes an `Mbuf` and stores its raw pointer,
/// * [`dequeue`](Self::dequeue) turns a received pointer back into an `Mbuf`
///   bound to the pool carried by this wrapper, validating the owning pool.
///
/// A full ring hands the mbuf back to its pool, so the safe enqueue side never
/// leaks a packet.
///
/// # Cross-process use
///
/// The raw pointers are only meaningful when every process maps the shared
/// mempool at the same virtual address, which is a prerequisite of DPDK
/// multi-process operation. Create the ring with element size
/// [`MBUF_PTR_SIZE`] (or `Ring::create::<*mut rte_mbuf>`), then in a secondary
/// process look the ring and the pool up by name:
///
/// ```no_run
/// # use rte::new::{Eal, MBUF_PTR_SIZE, MbufRing};
/// # let eal = Eal::init(&["app", "-l", "0", "--no-huge"])?;
/// let ring = unsafe { eal.ring("p2s", MBUF_PTR_SIZE)? };
/// let pool = unsafe { eal.pool("packets")? };
/// let _channel = MbufRing::new(ring, pool)?;
/// // let mbuf = unsafe { _channel.dequeue()? };
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy)]
pub struct MbufRing<'a> {
    ring: RingRef<'a>,
    pool: MemoryPoolRef<'a>,
}

impl<'a> MbufRing<'a> {
    /// Wrap an existing ring of `*mut rte_mbuf` elements and its pool.
    ///
    /// Returns [`RingError::ElementSizeMismatch`] when the ring does not store
    /// pointers.
    pub fn new(ring: RingRef<'a>, pool: MemoryPoolRef<'a>) -> Result<Self, RingError> {
        let actual = ring.element_size();

        if actual != MBUF_PTR_SIZE {
            return Err(RingError::ElementSizeMismatch {
                expected: actual,
                actual: MBUF_PTR_SIZE,
            });
        }

        Ok(Self { ring, pool })
    }

    /// The underlying raw ring view.
    #[inline]
    pub fn as_ring(self) -> RingRef<'a> {
        self.ring
    }

    /// The pool every mbuf on this ring must belong to.
    #[inline]
    pub fn pool(self) -> MemoryPoolRef<'a> {
        self.pool
    }

    /// Number of usable entries in the ring.
    #[inline]
    pub fn capacity(self) -> usize {
        self.ring.capacity()
    }

    /// Current number of entries.
    #[inline]
    pub fn count(self) -> usize {
        self.ring.count()
    }

    /// Whether the ring is empty.
    #[inline]
    pub fn is_empty(self) -> bool {
        self.ring.is_empty()
    }

    /// Whether the ring is full.
    #[inline]
    pub fn is_full(self) -> bool {
        self.ring.is_full()
    }

    /// Transfer ownership of `mbuf` into the ring.
    ///
    /// On [`RingError::Full`] the buffer is returned to its pool, so no packet
    /// is leaked. An mbuf owned by a different pool is rejected with
    /// [`RingError::Mbuf`] and also returned to its own pool.
    pub fn enqueue(&self, mbuf: Mbuf<'_>) -> Result<(), RingError> {
        let owner = mbuf.pool();

        if owner != self.pool.as_ptr() {
            // Dropping `mbuf` returns the buffer to its own pool.
            return Err(RingError::Mbuf(MbufError::ForeignPool {
                expected: self.pool.as_ptr().as_ptr() as usize,
                actual: owner.as_ptr() as usize,
            }));
        }

        let raw = mbuf.into_raw();

        match self.ring.enqueue::<*mut ffi::rte_mbuf>(raw.as_ptr()) {
            Ok(()) => Ok(()),
            Err(err) => {
                // SAFETY: `raw` came from a live `Mbuf` of this pool; dropping
                // the reconstructed handle returns it to the pool.
                drop(unsafe { Mbuf::from_raw(raw) });

                Err(err)
            }
        }
    }

    /// Receive one mbuf from the ring, binding it to this wrapper's pool.
    ///
    /// # Safety
    ///
    /// Every producer of the ring must only enqueue live `rte_mbuf` pointers
    /// that belong to [`pool`](Self::pool) (in a secondary process: the shared
    /// pool looked up by name). A foreign or corrupt pointer is rejected, but
    /// it is already dereferenced for that check, so the trust decision is the
    /// caller's.
    pub unsafe fn dequeue(&self) -> Result<Mbuf<'a>, RingError> {
        let raw = self.ring.dequeue::<*mut ffi::rte_mbuf>()?;

        let Some(raw) = NonNull::new(raw) else {
            return Err(RingError::Mbuf(MbufError::ForeignPool {
                expected: self.pool.as_ptr().as_ptr() as usize,
                actual: 0,
            }));
        };

        // SAFETY: delegated to the caller.
        match unsafe { self.pool.mbuf_from_raw(raw) } {
            Ok(mbuf) => Ok(mbuf),
            Err(err) => {
                // Give the pointer back so a consumer that owns the pool can
                // retry. Best effort: a full ring would lose it, but the
                // producer violated the contract anyway.
                let _ = self.ring.enqueue::<*mut ffi::rte_mbuf>(raw.as_ptr());

                Err(RingError::Mbuf(err))
            }
        }
    }
}

impl fmt::Debug for MbufRing<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MbufRing")
            .field("ring", &self.ring.info())
            .field("pool", &self.pool.as_ptr())
            .finish()
    }
}
