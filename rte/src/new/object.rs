//! Pool elements and checked-out objects.

use core::ffi::c_void;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use crate::ffi;

use super::mempool::MemoryPoolRef;

/// A fixed-size object that can live inside a [`MemoryPool`](super::MemoryPool).
///
/// # Safety
///
/// * `ELT_SIZE` must be at least `core::mem::size_of::<Self>()`, and should
///   also be aligned to [`ffi::RTE_MEMPOOL_ALIGN`] so that objects do not share
///   cache lines.
/// * `init` receives uninitialised storage and must fully initialise it without
///   panicking. Panicking inside the DPDK populate callback cannot unwind
///   across the C frames, so the wrapper aborts the process instead.
pub unsafe trait PoolElement: Sized {
    /// Size of one element as passed to `rte_mempool_create()`.
    const ELT_SIZE: usize;

    /// Initialise one element in place.
    ///
    /// # Safety
    ///
    /// `obj` points at `ELT_SIZE` bytes of uninitialised storage owned by a
    /// DPDK mempool. The implementation must not panic.
    unsafe fn init(obj: NonNull<Self>);
}

/// An object checked out of a pool.
///
/// Dropping the object puts it back into its pool, which is the DPDK
/// equivalent of `rte_mempool_put()`. Because the pool handle is a
/// [`MemoryPoolRef`], the borrow checker also guarantees the object cannot
/// outlive its pool.
pub struct PoolObject<'pool, T: PoolElement> {
    ptr: NonNull<T>,
    pool: MemoryPoolRef<'pool>,
}

impl<'pool, T: PoolElement> PoolObject<'pool, T> {
    /// Assemble an object handle.
    ///
    /// # Safety
    ///
    /// `ptr` must be a live object obtained from `pool`.
    #[inline]
    pub(crate) unsafe fn from_parts(pool: MemoryPoolRef<'pool>, ptr: NonNull<T>) -> Self {
        Self { ptr, pool }
    }

    /// The pool this object came from.
    #[inline]
    pub fn pool(&self) -> MemoryPoolRef<'pool> {
        self.pool
    }

    /// Raw pointer to the object storage.
    #[inline]
    pub fn as_ptr(&self) -> NonNull<T> {
        self.ptr
    }

    /// Give up ownership without returning the object to the pool.
    ///
    /// The object stays checked out forever; only useful when ownership is
    /// being handed to C/C++ code that will call `rte_mempool_put()` itself.
    #[inline]
    pub fn into_raw(self) -> NonNull<T> {
        let ptr = self.ptr;

        core::mem::forget(self);

        ptr
    }
}

impl<'pool, T: PoolElement> Drop for PoolObject<'pool, T> {
    fn drop(&mut self) {
        unsafe {
            ffi::_rte_mempool_put(
                self.pool.as_ptr().as_ptr(),
                self.ptr.as_ptr().cast::<c_void>(),
            )
        };
    }
}

// Here `Deref` really is the smart-pointer case: `PoolObject` owns the object
// and is responsible for returning it, exactly like `Box` owns its allocation.
impl<'pool, T: PoolElement> Deref for PoolObject<'pool, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }
}

impl<'pool, T: PoolElement> DerefMut for PoolObject<'pool, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.ptr.as_mut() }
    }
}

// SAFETY: an object checked out of a DPDK mempool is plain memory that is no
// longer referenced by the pool until it is put back, so moving it between
// threads is fine as long as the payload itself is `Send`/`Sync`.
unsafe impl<'pool, T: PoolElement + Send> Send for PoolObject<'pool, T> {}
unsafe impl<'pool, T: PoolElement + Sync> Sync for PoolObject<'pool, T> {}
