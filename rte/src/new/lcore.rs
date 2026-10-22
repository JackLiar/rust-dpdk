//! DPDK lcore discovery and scoped task launching.
//!
//! [`LcoreScope`] mirrors [`std::thread::scope`]: tasks may borrow local data,
//! because the scope waits for every task before it is dropped. Unlike
//! `std::thread::scope`, tasks run on DPDK lcores and are started with
//! `rte_eal_remote_launch()`.
//!
//! ```no_run
//! # use rte::new::{Eal, LcoreScope};
//! let eal = Eal::init(&["app", "-l", "0-1", "-n", "2"])?;
//! let main = eal.main_lcore();
//! let worker = eal
//!     .enabled_lcores()
//!     .into_iter()
//!     .find(|lcore| *lcore != main)
//!     .expect("need a worker lcore");
//!
//! let mut scope = LcoreScope::new(&eal);
//! scope.spawn(worker, || 0)?;
//! let exits = scope.wait();
//! assert_eq!(exits[0].code, 0);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use core::ffi::{c_int, c_void};
use core::fmt;
use core::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::ffi;

use super::eal::Eal;
use super::error::LcoreError;

/// Identifier of a DPDK logical core.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LcoreId(u32);

impl LcoreId {
    /// Wrap a raw lcore id.
    ///
    /// The id is validated by [`LcoreScope::spawn`] before use.
    #[inline]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Raw lcore id.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Whether this is the EAL main lcore.
    #[inline]
    pub fn is_main(self) -> bool {
        self.0 == unsafe { ffi::rte_get_main_lcore() }
    }

    /// Whether this lcore is part of the EAL core mask.
    #[inline]
    pub fn is_enabled(self) -> bool {
        unsafe { ffi::rte_lcore_is_enabled(self.0) != 0 }
    }

    /// NUMA socket of this lcore.
    #[inline]
    pub fn socket_id(self) -> i32 {
        unsafe { ffi::rte_lcore_to_socket_id(self.0) as i32 }
    }

    /// Dense index of this lcore among the enabled lcores.
    #[inline]
    pub fn index(self) -> usize {
        unsafe { ffi::rte_lcore_index(self.0 as c_int) as usize }
    }
}

impl From<LcoreId> for u32 {
    fn from(id: LcoreId) -> Self {
        id.0
    }
}

impl fmt::Display for LcoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Eal {
    /// The EAL main lcore.
    #[inline]
    pub fn main_lcore(&self) -> LcoreId {
        LcoreId::new(unsafe { ffi::rte_get_main_lcore() })
    }

    /// All enabled lcores, including the main lcore.
    pub fn enabled_lcores(&self) -> Vec<LcoreId> {
        (0..ffi::RTE_MAX_LCORE)
            .filter(|id| unsafe { ffi::rte_lcore_is_enabled(*id) != 0 })
            .map(LcoreId::new)
            .collect()
    }

    /// Number of enabled lcores.
    #[inline]
    pub fn lcore_count(&self) -> usize {
        unsafe { ffi::rte_lcore_count() as usize }
    }
}

/// Outcome of a task launched by [`LcoreScope`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LcoreExit {
    /// Lcore the task ran on.
    pub lcore: LcoreId,
    /// Value returned by the task, or `-1` if it panicked.
    pub code: i32,
}

impl LcoreExit {
    /// Whether the task returned zero.
    #[inline]
    pub fn is_ok(self) -> bool {
        self.code == 0
    }
}

struct LcoreTask<F> {
    task: Option<F>,
}

unsafe extern "C" fn task_stub<F>(arg: *mut c_void) -> c_int
where
    F: FnOnce() -> i32 + Send,
{
    // SAFETY: `LcoreScope::spawn` allocates this box and transfers it to DPDK
    // together with the function pointer. DPDK invokes the trampoline once.
    let mut task = unsafe { Box::from_raw(arg.cast::<LcoreTask<F>>()) };
    let Some(task) = task.task.take() else {
        return -1;
    };

    match catch_unwind(AssertUnwindSafe(task)) {
        Ok(code) => code,
        Err(_) => -1,
    }
}

/// Scoped DPDK lcore task launcher.
///
/// Tasks can borrow local data for `'scope`, because dropping the scope waits
/// for every launched task. Only the main lcore may call [`spawn`](Self::spawn)
/// and [`wait`](Self::wait).
#[must_use = "dropping a LcoreScope waits for its tasks"]
pub struct LcoreScope<'scope> {
    _eal: PhantomData<&'scope Eal>,
    launched: Vec<LcoreId>,
    waited: bool,
}

impl<'scope> LcoreScope<'scope> {
    /// Create a scope tied to the EAL lifetime.
    pub fn new(eal: &'scope Eal) -> Self {
        let _ = eal;

        Self {
            _eal: PhantomData,
            launched: Vec::new(),
            waited: false,
        }
    }

    /// Launch `task` on `lcore`.
    ///
    /// # Errors
    ///
    /// Rejects the main lcore, disabled lcores, and lcores that this scope
    /// already launched. A failed `rte_eal_remote_launch()` returns
    /// [`LcoreError::Launch`] and reclaims the task allocation.
    pub fn spawn<F>(&mut self, lcore: LcoreId, task: F) -> Result<(), LcoreError>
    where
        F: FnOnce() -> i32 + Send + 'scope,
    {
        if lcore.is_main() {
            return Err(LcoreError::MainLcore { id: lcore.as_u32() });
        }

        if !lcore.is_enabled() {
            return Err(LcoreError::Disabled { id: lcore.as_u32() });
        }

        if self.launched.contains(&lcore) {
            return Err(LcoreError::AlreadyLaunched { id: lcore.as_u32() });
        }

        let context = Box::into_raw(Box::new(LcoreTask { task: Some(task) })) as *mut c_void;

        // SAFETY: the context is a valid `LcoreTask<F>` allocation, and the
        // trampoline is monomorphised for the same `F`. The `'scope` bound is
        // upheld by `wait()`/`Drop`, which join the lcore before local borrowed
        // data can go away.
        let ret = unsafe { ffi::rte_eal_remote_launch(Some(task_stub::<F>), context, lcore.as_u32()) };

        if ret != 0 {
            // DPDK did not take ownership of the context.
            drop(unsafe { Box::from_raw(context.cast::<LcoreTask<F>>()) });

            return Err(LcoreError::from_rte_errno(lcore.as_u32()));
        }

        self.launched.push(lcore);

        Ok(())
    }

    /// Wait for every launched task and return their exit codes.
    pub fn wait(mut self) -> Vec<LcoreExit> {
        let exits = self.wait_launched();
        self.waited = true;

        exits
    }

    fn wait_launched(&mut self) -> Vec<LcoreExit> {
        self.launched
            .drain(..)
            .map(|lcore| LcoreExit {
                lcore,
                code: unsafe { ffi::rte_eal_wait_lcore(lcore.as_u32()) },
            })
            .collect()
    }
}

impl Drop for LcoreScope<'_> {
    fn drop(&mut self) {
        if !self.waited {
            let _ = self.wait_launched();
        }
    }
}
