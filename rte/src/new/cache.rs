//! User-owned mempool caches.
//!
//! DPDK keeps a per-lcore cache that `rte_mempool_get()`/`put()` use
//! implicitly. Threads that are not EAL threads should instead create their own
//! cache and use the `*_generic_*` entry points; that is what [`Cache`] wraps.
//!
//! A cache is inherently bound to the thread/lcore that uses it, so it is
//! deliberately `!Send + !Sync`.

use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::ffi;

use super::eal::Eal;
use super::error::{MempoolError, Result};
use super::mempool::MemoryPoolRef;

/// An owned, user-created mempool cache.
///
/// Freeing the cache is handled by `Drop`, so it can never be leaked by
/// forgetting to call a `free()` method.
pub struct Cache<'eal> {
    raw: NonNull<ffi::rte_mempool_cache>,
    _eal: PhantomData<&'eal Eal>,
    /// Per-lcore object: keep it on the thread that created it.
    _lcore: PhantomData<*mut ()>,
}

impl<'eal> Cache<'eal> {
    /// Create a cache holding at most `size` objects.
    ///
    /// `socket_id` should normally be [`Eal::socket_id`] of the lcore that will
    /// use the cache.
    pub fn create(eal: &'eal Eal, size: usize, socket_id: i32) -> Result<Self> {
        let _ = eal;

        let raw = unsafe { ffi::rte_mempool_cache_create(size as u32, socket_id) };

        let raw = NonNull::new(raw).ok_or_else(MempoolError::from_rte_errno)?;

        Ok(Self {
            raw,
            _eal: PhantomData,
            _lcore: PhantomData,
        })
    }

    /// Borrow the cache.
    #[inline]
    pub fn as_ref(&self) -> CacheRef<'_> {
        CacheRef::from_raw(self.raw)
    }

    /// Raw pointer, for passing to DPDK directly.
    #[inline]
    pub fn as_ptr(&self) -> NonNull<ffi::rte_mempool_cache> {
        self.raw
    }
}

impl Drop for Cache<'_> {
    fn drop(&mut self) {
        unsafe { ffi::rte_mempool_cache_free(self.raw.as_ptr()) };
    }
}

/// A borrowed view of a mempool cache.
///
/// `Copy` and without a `Drop`, so it can be passed to
/// [`MemoryPoolRef::generic_get`] and [`Cache::as_ref`] without ever taking
/// ownership of the cache.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct CacheRef<'a> {
    raw: NonNull<ffi::rte_mempool_cache>,
    _borrow: PhantomData<&'a ()>,
}

impl<'a> CacheRef<'a> {
    #[inline]
    pub(crate) fn from_raw(raw: NonNull<ffi::rte_mempool_cache>) -> Self {
        Self {
            raw,
            _borrow: PhantomData,
        }
    }

    /// Raw pointer, for passing to DPDK directly.
    #[inline]
    pub fn as_ptr(self) -> NonNull<ffi::rte_mempool_cache> {
        self.raw
    }

    /// Flush the cached objects back into `pool`.
    #[inline]
    pub fn flush(self, pool: MemoryPoolRef<'_>) {
        unsafe { ffi::_rte_mempool_cache_flush(self.raw.as_ptr(), pool.as_ptr().as_ptr()) };
    }
}
