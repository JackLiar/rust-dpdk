//! Ownership-correct mempool wrappers.
//!
//! See the [module documentation](crate::new) for the ownership model. The
//! short version:
//!
//! * [`MemoryPool<'eal>`] is **owned**; dropping it calls `rte_mempool_free()`.
//! * [`MemoryPoolRef<'a>`] is **borrowed**; it is `Copy`, has no `Drop` and
//!   therefore can never free a pool it does not own.
//! * [`MemoryPool::leak`] and [`MemoryPool::into_raw`] opt out of the free.

use core::any::Any;
use core::ffi::{c_int, c_uint, c_void, CStr};
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::ControlFlow;
use core::ptr::{self, NonNull};
use std::ffi::CString;

use crate::ffi;

use super::cache::CacheRef;
use super::eal::Eal;
use super::error::{errno_from_return, rte_strerror, rte_errno, MempoolError, Result};
use super::object::{PoolElement, PoolObject};

/// Longest mempool name DPDK accepts, excluding the terminating NUL.
///
/// Mirrors `RTE_MEMPOOL_NAMESIZE`, derived from the memzone/ring name limits
/// the same way the C headers do.
pub const MEMPOOL_NAMESIZE: usize = ffi::RTE_MEMZONE_NAMESIZE as usize
    - ffi::RTE_RING_MZ_PREFIX.len()
    + 1
    - ffi::RTE_MEMPOOL_MZ_PREFIX.len()
    + 1;

bitflags::bitflags! {
    /// Flags accepted by `rte_mempool_create()`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemoryPoolFlags: u32 {
        /// Do not spread objects in memory.
        const NO_SPREAD = ffi::MEMPOOL_F_NO_SPREAD;
        /// Do not align objects on cache lines.
        const NO_CACHE_ALIGN = ffi::MEMPOOL_F_NO_CACHE_ALIGN;
        /// Default `put` is single-producer.
        const SP_PUT = ffi::MEMPOOL_F_SP_PUT;
        /// Default `get` is single-consumer.
        const SC_GET = ffi::MEMPOOL_F_SC_GET;
        /// The pool does not need IOVA contiguous objects.
        const NO_IOVA_CONTIG = ffi::MEMPOOL_F_NO_IOVA_CONTIG;
    }
}

/// A snapshot of the interesting fields of an `rte_mempool`.
///
/// Deliberately a plain owned struct: safe code never gets a `&rte_mempool`,
/// so the C layout cannot be misread or mutated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolInfo {
    pub name: String,
    pub socket_id: i32,
    pub flags: MemoryPoolFlags,
    /// Total number of objects the pool was created with.
    pub size: usize,
    /// Number of objects that were actually populated.
    pub populated_size: usize,
    /// Size of one object.
    pub elt_size: usize,
    pub header_size: usize,
    pub trailer_size: usize,
    pub cache_size: usize,
    pub private_data_size: usize,
}

/// Read the pool fields into an owned snapshot.
fn info_of(raw: NonNull<ffi::rte_mempool>) -> PoolInfo {
    // SAFETY: the caller holds a live pool handle for the duration of the call.
    let mp = unsafe { raw.as_ref() };

    PoolInfo {
        // SAFETY: `name` is a NUL terminated `char[32]` inside a live mempool.
        name: unsafe { CStr::from_ptr(mp.name.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
        socket_id: mp.socket_id,
        flags: MemoryPoolFlags::from_bits_truncate(mp.flags),
        size: mp.size as usize,
        populated_size: mp.populated_size as usize,
        elt_size: mp.elt_size as usize,
        header_size: mp.header_size as usize,
        trailer_size: mp.trailer_size as usize,
        cache_size: mp.cache_size as usize,
        private_data_size: mp.private_data_size as usize,
    }
}

/// Validate a pool name before handing it to DPDK.
fn validate_name(name: &str) -> Result<CString, MempoolError> {
    let invalid = || MempoolError::InvalidName {
        name: name.to_string(),
        len: name.len(),
        max: MEMPOOL_NAMESIZE,
    };

    if name.is_empty() || name.len() > MEMPOOL_NAMESIZE {
        return Err(invalid());
    }

    CString::new(name).map_err(|_| invalid())
}

/// Turn the raw result of a `*_create()` call into a pool or a typed error.
fn wrap_created<'eal>(
    raw: *mut ffi::rte_mempool,
    name: &str,
    capacity: u32,
    elt_size: usize,
) -> Result<MemoryPool<'eal>, MempoolError> {
    match NonNull::new(raw) {
        Some(raw) => Ok(MemoryPool {
            raw,
            _eal: PhantomData,
        }),
        None => {
            let errno = rte_errno();

            Err(match errno {
                libc::EEXIST => MempoolError::AlreadyExists {
                    name: name.to_string(),
                },
                libc::ENOMEM | libc::ENOSPC => MempoolError::NoMemory {
                    name: name.to_string(),
                    capacity,
                    elt_size,
                },
                _ => MempoolError::Rte {
                    errno,
                    message: rte_strerror(errno),
                },
            })
        }
    }
}

/// `obj_init` trampoline used by [`MemoryPool::create`].
unsafe extern "C" fn init_trampoline<T: PoolElement>(
    _mp: *mut ffi::rte_mempool,
    _arg: *mut c_void,
    obj: *mut c_void,
    _idx: c_uint,
) {
    // SAFETY: DPDK passes a pointer to `T::ELT_SIZE` bytes of object storage.
    let ptr = unsafe { NonNull::new_unchecked(obj.cast::<T>()) };

    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe { T::init(ptr) }));

    if result.is_err() {
        // Unwinding across the C frames of `rte_mempool_create()` is undefined;
        // abort instead of corrupting the pool half way through population.
        std::process::abort();
    }
}

// ---------------------------------------------------------------------------
// Owned handle
// ---------------------------------------------------------------------------

/// An **owned** mempool.
///
/// Dropping it calls `rte_mempool_free()`. Because the handle borrows an
/// [`Eal`], the pool can never outlive the EAL; because it borrows nothing
/// else, it can be created and destroyed freely.
///
/// # Preconditions for dropping
///
/// DPDK requires that no object is still checked out when a pool is freed, and
/// that no other lcore is concurrently using it. The wrapper checks the first
/// condition with a `debug_assert` in [`Drop`] and offers
/// [`destroy`](Self::destroy) for an explicit, checked teardown.
#[repr(transparent)]
#[must_use = "a MemoryPool is freed when dropped; use `leak()` or `into_raw()` to opt out"]
pub struct MemoryPool<'eal> {
    raw: NonNull<ffi::rte_mempool>,
    _eal: PhantomData<&'eal Eal>,
}

// SAFETY: a DPDK mempool is designed for concurrent `get`/`put` (the underlying
// ring is multi-producer/multi-consumer), and freeing requires exclusive
// ownership which neither `Send` nor `Sync` hands out.
unsafe impl<'eal> Send for MemoryPool<'eal> {}
unsafe impl<'eal> Sync for MemoryPool<'eal> {}

impl<'eal> MemoryPool<'eal> {
    /// Create a pool of `T` with `capacity` elements.
    ///
    /// `T::init` is invoked once per element while DPDK populates the pool.
    pub fn create<T: PoolElement>(
        eal: &'eal Eal,
        name: &str,
        capacity: u32,
        cache_size: u32,
    ) -> Result<Self, MempoolError> {
        let cname = validate_name(name)?;
        let elt_size = T::ELT_SIZE;

        // SAFETY: `cname` is a valid NUL terminated string and every other
        // argument matches what DPDK expects.
        let raw = unsafe {
            ffi::rte_mempool_create(
                cname.as_ptr(),
                capacity,
                elt_size as c_uint,
                cache_size,
                0,
                None,
                ptr::null_mut(),
                Some(init_trampoline::<T>),
                ptr::null_mut(),
                eal.socket_id(),
                MemoryPoolFlags::empty().bits(),
            )
        };

        wrap_created(raw, name, capacity, elt_size)
    }

    /// Create a packet mbuf pool (`rte_pktmbuf_pool_create()`).
    ///
    /// Elements are `rte_mbuf` headers with `data_room_size` bytes of data room;
    /// the wrapper does not type-check them, it only owns the pool.
    pub fn pktmbuf_pool(
        eal: &'eal Eal,
        name: &str,
        capacity: u32,
        cache_size: u32,
        priv_size: u16,
        data_room_size: u16,
    ) -> Result<Self, MempoolError> {
        let cname = validate_name(name)?;

        let raw = unsafe {
            ffi::rte_pktmbuf_pool_create(
                cname.as_ptr(),
                capacity,
                cache_size,
                priv_size,
                data_room_size,
                eal.socket_id(),
            )
        };

        wrap_created(raw, name, capacity, data_room_size as usize)
    }

    /// Start configuring a raw pool of `elt_size` byte elements.
    pub fn builder<'n>(name: &'n str, capacity: u32, elt_size: usize) -> Builder<'n> {
        Builder::new(name, capacity, elt_size)
    }

    /// Take ownership of a raw `rte_mempool`.
    ///
    /// # Safety
    ///
    /// `raw` must be a pool this process created and nobody else will free, and
    /// it must not be registered under a name that another handle already owns.
    pub unsafe fn from_raw(eal: &'eal Eal, raw: NonNull<ffi::rte_mempool>) -> Self {
        let _ = eal;

        Self {
            raw,
            _eal: PhantomData,
        }
    }

    /// Borrow the pool.
    #[inline]
    pub fn as_ref(&self) -> MemoryPoolRef<'_> {
        MemoryPoolRef::from_raw(self.raw)
    }

    /// Raw pointer, for passing to DPDK directly.
    #[inline]
    pub fn as_ptr(&self) -> NonNull<ffi::rte_mempool> {
        self.raw
    }

    /// Give up ownership **without** freeing the pool.
    ///
    /// Use this when the pool is shared with another process, or when its
    /// ownership is handed to C/C++ code.
    #[inline]
    pub fn leak(self) -> NonNull<ffi::rte_mempool> {
        let raw = self.raw;

        core::mem::forget(self);

        raw
    }

    /// Alias for [`leak`](Self::leak), mirroring `Box::into_raw`.
    #[inline]
    pub fn into_raw(self) -> NonNull<ffi::rte_mempool> {
        self.leak()
    }

    /// Explicitly free the pool, refusing while objects are still checked out.
    ///
    /// This is the checked version of `Drop`; use it when the reason for a
    /// failure matters.
    pub fn destroy(self) -> Result<(), MempoolError> {
        let in_use = self.in_use();

        if in_use != 0 {
            return Err(MempoolError::ObjectsInUse {
                name: self.info().name,
                in_use,
            });
        }

        let this = ManuallyDrop::new(self);

        unsafe { ffi::rte_mempool_free(this.raw.as_ptr()) };

        Ok(())
    }

    // -- read only queries, delegated to the borrowed view -------------------

    #[inline]
    pub fn info(&self) -> PoolInfo {
        self.as_ref().info()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.as_ref().capacity()
    }

    #[inline]
    pub fn available(&self) -> usize {
        self.as_ref().available()
    }

    #[inline]
    pub fn in_use(&self) -> usize {
        self.as_ref().in_use()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.as_ref().is_full()
    }

    /// Visit every object in the pool. See [`MemoryPoolRef::for_each_object`].
    pub fn for_each_object<F>(&self, f: F) -> ControlFlow<()>
    where
        F: for<'x> FnMut(MemoryPoolRef<'x>, NonNull<c_void>, usize) -> ControlFlow<()>,
    {
        self.as_ref().for_each_object(f)
    }

    /// Check out one object. See [`MemoryPoolRef::get`].
    pub fn get<T: PoolElement>(&self) -> Result<PoolObject<'_, T>, MempoolError> {
        self.as_ref().get::<T>()
    }

    /// Check out one object using an explicit cache.
    pub fn generic_get<T: PoolElement>(
        &self,
        cache: Option<CacheRef<'_>>,
    ) -> Result<PoolObject<'_, T>, MempoolError> {
        self.as_ref().generic_get::<T>(cache)
    }
}

impl<'eal> Drop for MemoryPool<'eal> {
    fn drop(&mut self) {
        debug_assert_eq!(
            unsafe { ffi::rte_mempool_in_use_count(self.raw.as_ptr()) },
            0,
            "dropping a mempool while objects are still checked out"
        );

        unsafe { ffi::rte_mempool_free(self.raw.as_ptr()) };
    }
}

impl<'eal> fmt::Debug for MemoryPool<'eal> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.info().fmt(f)
    }
}

// ---------------------------------------------------------------------------
// Borrowed view
// ---------------------------------------------------------------------------

/// A **borrowed** view of a mempool.
///
/// It is `Copy` and has no `Drop`, so it is structurally impossible to free a
/// pool through this handle. That is exactly the guarantee DPDK needs from
/// secondary processes, from callback arguments, and from
/// `rte_mempool_from_obj()`.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct MemoryPoolRef<'a> {
    raw: NonNull<ffi::rte_mempool>,
    _borrow: PhantomData<&'a ()>,
}

// SAFETY: the view is a read-only copy of the handle; the pool itself is safe
// for concurrent use.
unsafe impl<'a> Send for MemoryPoolRef<'a> {}
unsafe impl<'a> Sync for MemoryPoolRef<'a> {}

impl<'a> MemoryPoolRef<'a> {
    /// Wrap a pointer that is known to be borrowed.
    #[inline]
    pub(crate) fn from_raw(raw: NonNull<ffi::rte_mempool>) -> Self {
        Self {
            raw,
            _borrow: PhantomData,
        }
    }

    /// Look a pool up by name.
    ///
    /// # Safety
    ///
    /// `rte_mempool_lookup()` only establishes that the pool exists *right
    /// now*. The returned view borrows the caller supplied lifetime, so the
    /// caller must guarantee that nobody frees the pool (in any process) while
    /// the view is alive. Prefer an owned [`MemoryPool`] whenever possible.
    pub(crate) unsafe fn lookup(name: &str) -> Result<Self, MempoolError> {
        let cname = validate_name(name)?;

        // SAFETY: delegated to the caller, see above.
        let raw = unsafe { ffi::rte_mempool_lookup(cname.as_ptr()) };

        NonNull::new(raw)
            .map(Self::from_raw)
            .ok_or_else(|| MempoolError::NotFound {
                name: name.to_string(),
            })
    }

    /// Raw pointer, for passing to DPDK directly.
    #[inline]
    pub fn as_ptr(self) -> NonNull<ffi::rte_mempool> {
        self.raw
    }

    /// Snapshot of the pool fields.
    #[inline]
    pub fn info(self) -> PoolInfo {
        info_of(self.raw)
    }

    /// Number of objects the pool was created with.
    #[inline]
    pub fn capacity(self) -> usize {
        // SAFETY: the view is only constructed while the pool is alive.
        unsafe { self.raw.as_ref().size as usize }
    }

    /// Number of objects currently available for allocation.
    #[inline]
    pub fn available(self) -> usize {
        unsafe { ffi::rte_mempool_avail_count(self.raw.as_ptr()) as usize }
    }

    /// Number of objects currently checked out (including cached ones).
    #[inline]
    pub fn in_use(self) -> usize {
        unsafe { ffi::rte_mempool_in_use_count(self.raw.as_ptr()) as usize }
    }

    /// Whether every object is checked out.
    #[inline]
    pub fn is_empty(self) -> bool {
        self.available() == 0
    }

    /// Whether no object is checked out.
    #[inline]
    pub fn is_full(self) -> bool {
        self.available() == self.capacity()
    }

    /// Check out one object using the per-lcore cache.
    ///
    /// DPDK's default cache is per-lcore, so this must run on an EAL thread.
    /// Debug builds assert that; release builds simply follow DPDK.
    #[inline]
    pub fn get<T: PoolElement>(self) -> Result<PoolObject<'a, T>, MempoolError> {
        debug_assert_ne!(
            unsafe { ffi::_rte_lcore_id() },
            ffi::LCORE_ID_ANY,
            "rte_mempool_get() must run on an EAL thread; \
             use generic_get(Some(&cache)) from other threads"
        );

        let mut obj: *mut c_void = ptr::null_mut();

        // SAFETY: `self` is a live pool and `obj` is a valid out parameter.
        let ret = unsafe { ffi::_rte_mempool_get(self.raw.as_ptr(), &mut obj) };

        self.finish_get::<T>(ret, obj)
    }

    /// Check out one object using an explicit cache (safe on non-EAL threads).
    #[inline]
    pub fn generic_get<T: PoolElement>(
        self,
        cache: Option<CacheRef<'_>>,
    ) -> Result<PoolObject<'a, T>, MempoolError> {
        let mut obj: *mut c_void = ptr::null_mut();
        let cache = cache.map_or(ptr::null_mut(), |cache| cache.as_ptr().as_ptr());

        // SAFETY: `self` is a live pool and `obj` is a valid out parameter.
        let ret = unsafe {
            ffi::_rte_mempool_generic_get(self.raw.as_ptr(), &mut obj, 1, cache)
        };

        self.finish_get::<T>(ret, obj)
    }

    /// Turn the outcome of a `get` into an object handle.
    #[inline]
    fn finish_get<T: PoolElement>(
        self,
        ret: c_int,
        obj: *mut c_void,
    ) -> Result<PoolObject<'a, T>, MempoolError> {
        if ret != 0 {
            let errno = errno_from_return(ret);

            return Err(if errno == libc::ENOENT {
                MempoolError::Exhausted {
                    name: info_of(self.raw).name,
                }
            } else {
                MempoolError::Rte {
                    errno,
                    message: rte_strerror(errno),
                }
            });
        }

        let ptr = NonNull::new(obj.cast::<T>()).ok_or_else(MempoolError::from_rte_errno)?;

        // SAFETY: DPDK just handed ownership of the object to us.
        Ok(unsafe { PoolObject::from_parts(self, ptr) })
    }

    /// Borrow the calling lcore's default cache, if any.
    #[inline]
    pub fn per_lcore_cache(self) -> Option<CacheRef<'a>> {
        let lcore_id = unsafe { ffi::_rte_lcore_id() };

        if lcore_id == ffi::LCORE_ID_ANY {
            return None;
        }

        NonNull::new(unsafe { ffi::_rte_mempool_default_cache(self.raw.as_ptr(), lcore_id) })
            .map(CacheRef::from_raw)
    }

    /// Visit every object in the pool.
    ///
    /// `rte_mempool_obj_iter()` always walks the whole pool, so returning
    /// [`ControlFlow::Break`] stops calling the closure but the underlying
    /// iteration still completes.
    ///
    /// A panic raised by `f` is caught at the FFI boundary and resumed once the
    /// iteration has returned, so it never unwinds through C frames.
    pub fn for_each_object<F>(self, f: F) -> ControlFlow<()>
    where
        F: for<'x> FnMut(MemoryPoolRef<'x>, NonNull<c_void>, usize) -> ControlFlow<()>,
    {
        struct Ctx<F> {
            f: F,
            panicked: Option<Box<dyn Any + Send>>,
            stopped: bool,
        }

        unsafe extern "C" fn trampoline<F>(
            mp: *mut ffi::rte_mempool,
            arg: *mut c_void,
            obj: *mut c_void,
            idx: c_uint,
        ) where
            F: for<'x> FnMut(MemoryPoolRef<'x>, NonNull<c_void>, usize) -> ControlFlow<()>,
        {
            let ctx = unsafe { &mut *arg.cast::<Ctx<F>>() };

            if ctx.panicked.is_some() || ctx.stopped {
                return;
            }

            // SAFETY: both pointers are provided by DPDK and stay valid for the
            // duration of this callback.
            let pool = MemoryPoolRef::from_raw(unsafe { NonNull::new_unchecked(mp) });
            let obj = unsafe { NonNull::new_unchecked(obj) };

            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (ctx.f)(pool, obj, idx as usize)
            })) {
                Ok(ControlFlow::Continue(())) => {}
                Ok(ControlFlow::Break(())) => ctx.stopped = true,
                Err(payload) => ctx.panicked = Some(payload),
            }
        }

        let mut ctx = Ctx {
            f,
            panicked: None,
            stopped: false,
        };

        // SAFETY: the context lives on this stack frame, and DPDK calls the
        // callback only during this call.
        unsafe {
            ffi::rte_mempool_obj_iter(
                self.raw.as_ptr(),
                Some(trampoline::<F>),
                (&mut ctx as *mut Ctx<F>).cast(),
            )
        };

        if let Some(payload) = ctx.panicked {
            std::panic::resume_unwind(payload);
        }

        if ctx.stopped {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

impl<'a> fmt::Debug for MemoryPoolRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.info().fmt(f)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for pools that are not typed by a [`PoolElement`].
///
/// Use this when the pool is populated by DPDK itself (mbuf pools) or by a
/// foreign object layout.
#[derive(Debug, Clone)]
pub struct Builder<'n> {
    name: &'n str,
    capacity: u32,
    elt_size: usize,
    cache_size: u32,
    private_size: u32,
    socket_id: Option<i32>,
    flags: MemoryPoolFlags,
}

impl<'n> Builder<'n> {
    /// New builder for `capacity` objects of `elt_size` bytes each.
    pub fn new(name: &'n str, capacity: u32, elt_size: usize) -> Self {
        Self {
            name,
            capacity,
            elt_size,
            cache_size: 0,
            private_size: 0,
            socket_id: None,
            flags: MemoryPoolFlags::empty(),
        }
    }

    /// Size of the per-lcore cache (`0` disables it).
    pub fn cache_size(mut self, cache_size: u32) -> Self {
        self.cache_size = cache_size;
        self
    }

    /// Extra private data attached to the pool.
    pub fn private_size(mut self, private_size: u32) -> Self {
        self.private_size = private_size;
        self
    }

    /// NUMA socket; defaults to the socket of the current lcore.
    pub fn socket_id(mut self, socket_id: i32) -> Self {
        self.socket_id = Some(socket_id);
        self
    }

    /// Pool flags.
    pub fn flags(mut self, flags: MemoryPoolFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Create the pool.
    pub fn build<'eal>(self, eal: &'eal Eal) -> Result<MemoryPool<'eal>, MempoolError> {
        let cname = validate_name(self.name)?;

        // SAFETY: `cname` is a valid NUL terminated string and the remaining
        // arguments are plain scalars.
        let raw = unsafe {
            ffi::rte_mempool_create(
                cname.as_ptr(),
                self.capacity,
                self.elt_size as c_uint,
                self.cache_size,
                self.private_size,
                None,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
                self.socket_id.unwrap_or_else(|| eal.socket_id()),
                self.flags.bits(),
            )
        };

        wrap_created(raw, self.name, self.capacity, self.elt_size)
    }
}
