//! Error types for the `rte::new` wrappers.
//!
//! Unlike the rest of the crate these are concrete, matchable error types
//! rather than `anyhow::Error`: a library should let the caller decide how to
//! react, and `anyhow` stays at the application/example level.

use core::ffi::CStr;

use crate::ffi;

/// Value of the calling thread's `rte_errno`.
#[inline]
pub(crate) fn rte_errno() -> i32 {
    unsafe { ffi::_rte_errno() }
}

/// Human readable description of a DPDK error number.
pub(crate) fn rte_strerror(errno: i32) -> String {
    let ptr = unsafe { ffi::rte_strerror(errno) };

    if ptr.is_null() {
        format!("unknown rte_errno {errno}")
    } else {
        unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
    }
}

/// Turning an integer return value into an error number.
///
/// DPDK is inconsistent here: some entry points return a negative errno
/// without touching `rte_errno`, others only set `rte_errno`. Prefer the
/// thread-local when it is set, otherwise fall back to `-ret`.
#[inline]
pub(crate) fn errno_from_return(ret: i32) -> i32 {
    match rte_errno() {
        0 => -ret,
        errno => errno,
    }
}

/// Failure while initialising the DPDK Environment Abstraction Layer.
#[derive(Debug, thiserror::Error)]
#[error("failed to initialize EAL (rte_errno {errno}: {message})")]
pub struct EalError {
    /// The `rte_errno` captured at the point of failure.
    pub errno: i32,
    /// `rte_strerror(errno)`.
    pub message: String,
}

impl EalError {
    pub(crate) fn from_errno(errno: i32) -> Self {
        Self {
            errno,
            message: rte_strerror(errno),
        }
    }
}

/// Failure while creating, looking up or destroying a mempool.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MempoolError {
    /// Another pool with the same name is already registered.
    #[error("a mempool named `{name}` already exists")]
    AlreadyExists { name: String },

    /// `rte_mempool_lookup()` found nothing.
    #[error("no mempool named `{name}`")]
    NotFound { name: String },

    /// Not enough memory to back the requested pool.
    #[error("not enough memory for mempool `{name}` ({capacity} objects of {elt_size} bytes)")]
    NoMemory {
        name: String,
        capacity: u32,
        elt_size: usize,
    },

    /// The name is empty, too long, or contains an interior NUL.
    #[error("invalid mempool name `{name}`: {len} bytes, at most {max} are allowed")]
    InvalidName {
        name: String,
        len: usize,
        max: usize,
    },

    /// `get()` found no free object.
    #[error("mempool `{name}` is exhausted")]
    Exhausted { name: String },

    /// `destroy()` refused because objects are still checked out.
    #[error("mempool `{name}` still has {in_use} object(s) checked out")]
    ObjectsInUse { name: String, in_use: usize },

    /// Anything else that came back through `rte_errno`.
    #[error("DPDK error {errno}: {message}")]
    Rte { errno: i32, message: String },
}

impl MempoolError {
    /// Capture the current `rte_errno`.
    pub(crate) fn from_rte_errno() -> Self {
        let errno = rte_errno();

        Self::Rte {
            errno,
            message: rte_strerror(errno),
        }
    }
}

/// Failure while operating on an ethernet port or one of its queues.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PortError {
    /// The requested port id is not available in this process.
    #[error("invalid port id {id}: only {count} port(s) are available")]
    InvalidPort { id: u16, count: u16 },

    /// `rte_eth_dev_configure()` failed.
    #[error("failed to configure port {id} (rte_errno {errno}: {message})")]
    Configure {
        id: u16,
        errno: i32,
        message: String,
    },

    /// `rte_eth_rx_queue_setup()` failed.
    #[error("failed to set up RX queue {queue} of port {id} (rte_errno {errno}: {message})")]
    RxQueueSetup {
        id: u16,
        queue: u16,
        errno: i32,
        message: String,
    },

    /// `rte_eth_dev_start()` failed.
    #[error("failed to start port {id} (rte_errno {errno}: {message})")]
    Start {
        id: u16,
        errno: i32,
        message: String,
    },

    /// A promiscuous mode query or update failed.
    #[error("promiscuous mode operation on port {id} failed (rte_errno {errno}: {message})")]
    Promiscuous {
        id: u16,
        errno: i32,
        message: String,
    },

    /// Anything else that came back through `rte_errno`.
    #[error("port {id}: DPDK error {errno}: {message}")]
    Rte {
        id: u16,
        errno: i32,
        message: String,
    },
}

impl PortError {
    /// Capture the current `rte_errno` with a port context.
    pub(crate) fn from_rte_errno(id: u16) -> Self {
        let errno = rte_errno();

        Self::Rte {
            id,
            errno,
            message: rte_strerror(errno),
        }
    }
}

/// Failure while registering the RX timestamp dynamic field.
#[derive(Debug, thiserror::Error)]
#[error("failed to register the RX timestamp dynamic field (rte_errno {errno}: {message})")]
pub struct TimestampError {
    /// The `rte_errno` captured at the point of failure.
    pub errno: i32,
    /// `rte_strerror(errno)`.
    pub message: String,
}

impl TimestampError {
    pub(crate) fn from_rte_errno() -> Self {
        let errno = rte_errno();

        Self {
            errno,
            message: rte_strerror(errno),
        }
    }
}

/// Convenience alias used throughout `rte::new`.
pub type Result<T, E = MempoolError> = core::result::Result<T, E>;
