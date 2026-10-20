//! The EAL lifetime token.

use core::ffi::{c_char, c_int, c_void};
use core::marker::PhantomData;
use core::ptr::NonNull;
use std::any::Any;
use std::ffi::CString;

use crate::ffi;

use super::error::{EalError, MempoolError, ThreadError, rte_errno};
use super::mempool::MemoryPoolRef;

/// Owns the DPDK Environment Abstraction Layer for as long as it is alive.
///
/// Every handle produced by [`rte::new`](crate::new) borrows this token, so the
/// borrow checker guarantees that all pools, caches and objects are gone before
/// `rte_eal_cleanup()` runs:
///
/// ```no_run
/// # use rte::new::Eal;
/// let eal = Eal::init(&["app", "-l", "0", "-n", "2"])?;
/// // ... create pools that borrow `&eal` ...
/// // locals are dropped in reverse order: pools first, then EAL.
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// The token is deliberately `!Send + !Sync`. DPDK lcore affinity and the
/// per-lcore caches mean the EAL is not something you want to bounce between
/// threads; opt in explicitly if you really need to.
#[must_use = "dropping `Eal` tears the EAL down and invalidates every DPDK handle"]
pub struct Eal {
    _not_send: PhantomData<*mut ()>,
}

impl Eal {
    /// Initialise the EAL.
    ///
    /// `args` is the full `argv`, including `argv[0]`, exactly like
    /// `rte_eal_init()` expects. Typical CLI code passes
    /// `std::env::args().collect::<Vec<_>>()`.
    ///
    /// # Errors
    ///
    /// Returns [`EalError`] if `rte_eal_init()` fails, or if any argument
    /// contains an interior NUL byte.
    pub fn init<S: AsRef<str>>(args: &[S]) -> Result<Self, EalError> {
        let cstrings = match args
            .iter()
            .map(|arg| CString::new(arg.as_ref()))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(args) => args,
            Err(_) => return Err(EalError::from_errno(libc::EINVAL)),
        };

        let mut argv: Vec<*mut c_char> = cstrings.iter().map(|arg| arg.as_ptr() as *mut c_char).collect();

        let parsed = unsafe { ffi::rte_eal_init(argv.len() as c_int, argv.as_mut_ptr()) };

        if parsed < 0 {
            return Err(EalError::from_errno(rte_errno()));
        }

        Ok(Self { _not_send: PhantomData })
    }

    /// Leak the EAL handle and return a process-lifetime reference.
    ///
    /// This is the supported way to keep DPDK alive for the whole process (the
    /// common case for a data-plane daemon): [`Drop`] never calls
    /// `rte_eal_cleanup()`, and every handle created from the returned
    /// reference can outlive the current function.
    #[must_use = "the leaked EAL reference must be stored somewhere"]
    pub fn leak(self) -> &'static Eal {
        Box::leak(Box::new(self))
    }

    /// Register the calling pthread as an EAL "non-EAL" lcore.
    ///
    /// DPDK worker threads created by `std::thread` are not EAL threads: their
    /// `rte_lcore_id()` is [`ffi::LCORE_ID_ANY`], which disables the per-lcore
    /// mempool cache and surprises some libraries. Call this once on every
    /// packet-processing thread, after pinning it to a CPU.
    ///
    /// The returned guard unregisters the thread on drop and is deliberately
    /// `!Send`: `rte_thread_unregister()` operates on the calling thread's TLS.
    pub fn register_current_thread(&self) -> Result<ThreadGuard, ThreadError> {
        register_current_thread()
    }

    /// Look up an existing mempool by name.
    ///
    /// The result is a **borrowed** view: it can never free the pool.
    ///
    /// # Safety
    ///
    /// A name lookup only proves the pool exists *right now*. The caller must
    /// guarantee that no thread in any process frees the pool while the
    /// returned view is alive. Prefer an owned
    /// [`MemoryPool`](super::MemoryPool) when this process created the pool.
    pub unsafe fn pool(&self, name: &str) -> Result<MemoryPoolRef<'_>, MempoolError> {
        unsafe { MemoryPoolRef::lookup(name) }
    }

    /// Visit every mempool currently registered in this process.
    ///
    /// `rte_mempool_walk()` cannot stop early, so neither can this. A panic
    /// raised by `f` is caught at the FFI boundary and resumed once the walk
    /// has returned.
    pub fn for_each_pool<F>(&self, f: F)
    where
        F: for<'p> FnMut(MemoryPoolRef<'p>),
    {
        struct Ctx<F> {
            f: F,
            panicked: Option<Box<dyn Any + Send>>,
        }

        unsafe extern "C" fn trampoline<F>(mp: *mut ffi::rte_mempool, arg: *mut c_void)
        where
            F: for<'p> FnMut(MemoryPoolRef<'p>),
        {
            let ctx = unsafe { &mut *arg.cast::<Ctx<F>>() };

            if ctx.panicked.is_some() {
                return;
            }

            // SAFETY: DPDK guarantees `mp` is alive for the duration of the call,
            // and `MemoryPoolRef` carries no ownership, so it can never free it.
            let pool = MemoryPoolRef::from_raw(unsafe { NonNull::new_unchecked(mp) });

            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (ctx.f)(pool))) {
                ctx.panicked = Some(payload);
            }
        }

        let mut ctx = Ctx { f, panicked: None };

        unsafe { ffi::rte_mempool_walk(Some(trampoline::<F>), (&mut ctx as *mut Ctx<F>).cast()) };

        if let Some(payload) = ctx.panicked {
            std::panic::resume_unwind(payload);
        }
    }

    /// Id of the calling lcore, or [`ffi::LCORE_ID_ANY`] outside an EAL thread.
    #[inline]
    pub fn lcore_id(&self) -> u32 {
        unsafe { ffi::_rte_lcore_id() }
    }

    /// NUMA socket of the calling lcore.
    #[inline]
    pub fn socket_id(&self) -> i32 {
        unsafe { ffi::rte_socket_id() as i32 }
    }

    /// Whether this is the primary process.
    ///
    /// Only the primary process may create or destroy shared resources.
    #[inline]
    pub fn is_primary(&self) -> bool {
        unsafe { ffi::rte_eal_process_type() == ffi::rte_proc_type_t::RTE_PROC_PRIMARY }
    }
}

/// Register the calling pthread as an EAL non-EAL lcore.
///
/// This is the free-function form of [`Eal::register_current_thread`], usable
/// on worker threads that do not have access to the `Eal` token. The EAL must
/// already be initialised and must outlive the returned guard.
pub fn register_current_thread() -> Result<ThreadGuard, ThreadError> {
    // SAFETY: `rte_thread_register()` only touches per-thread EAL state; the
    // caller is responsible for the EAL lifetime documented above.
    if unsafe { ffi::rte_thread_register() } != 0 {
        return Err(ThreadError::from_rte_errno());
    }

    Ok(ThreadGuard { _not_send: PhantomData })
}

/// Registration of the current thread as an EAL lcore.
///
/// The thread is unregistered when the guard is dropped. The guard is `!Send`
/// on purpose: DPDK's registration state lives in thread-local storage.
#[must_use = "the thread is unregistered when the guard is dropped"]
pub struct ThreadGuard {
    _not_send: PhantomData<*mut ()>,
}

impl ThreadGuard {
    /// lcore id assigned to this thread, or [`ffi::LCORE_ID_ANY`].
    #[inline]
    pub fn lcore_id(&self) -> u32 {
        unsafe { ffi::_rte_lcore_id() }
    }

    /// NUMA socket of this thread's current CPU affinity mask.
    #[inline]
    pub fn socket_id(&self) -> i32 {
        unsafe { ffi::rte_socket_id() as i32 }
    }
}

impl Drop for ThreadGuard {
    fn drop(&mut self) {
        unsafe { ffi::rte_thread_unregister() };
    }
}

impl Drop for Eal {
    fn drop(&mut self) {
        unsafe { ffi::rte_eal_cleanup() };
    }
}
