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

/// Failure while operating on a packet buffer (`rte_mbuf`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MbufError {
    /// `rte_pktmbuf_linearize()` could not make the packet contiguous.
    #[error("failed to linearize mbuf (rte_errno {errno}: {message})")]
    Linearize {
        /// The `rte_errno` captured at the point of failure.
        errno: i32,
        /// `rte_strerror(errno)`.
        message: String,
    },

    /// The mbuf is shared (`refcnt > 1`), so mutating it would affect another owner.
    #[error("cannot modify a shared mbuf (refcnt {refcnt})")]
    Shared {
        /// Current mbuf reference count.
        refcnt: u16,
    },

    /// The packet does not fit in the mbuf's data room.
    #[error("packet of {len} bytes does not fit in the remaining {capacity} byte(s)")]
    TooLarge {
        /// Requested packet length.
        len: usize,
        /// Space available from `data_off` to `buf_len`.
        capacity: usize,
    },

    /// The operation only supports a single-segment mbuf.
    #[error("operation requires a single-segment mbuf (nb_segs {nb_segs})")]
    NotSingleSegment {
        /// Current number of segments.
        nb_segs: u16,
    },
}

impl MbufError {
    /// Capture the current `rte_errno`.
    pub(crate) fn from_rte_errno() -> Self {
        let errno = rte_errno();

        Self::Linearize {
            errno,
            message: rte_strerror(errno),
        }
    }
}

/// Failure while registering a non-EAL thread with the EAL.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ThreadError {
    /// `rte_thread_register()` failed.
    #[error("failed to register the current thread as an EAL thread (rte_errno {errno}: {message})")]
    Register {
        /// The `rte_errno` captured at the point of failure.
        errno: i32,
        /// `rte_strerror(errno)`.
        message: String,
    },
}

impl ThreadError {
    /// Capture the current `rte_errno`.
    pub(crate) fn from_rte_errno() -> Self {
        let errno = rte_errno();

        Self::Register {
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
    InvalidName { name: String, len: usize, max: usize },

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
    Configure { id: u16, errno: i32, message: String },

    /// `rte_eth_rx_queue_setup()` failed.
    #[error("failed to set up RX queue {queue} of port {id} (rte_errno {errno}: {message})")]
    RxQueueSetup {
        id: u16,
        queue: u16,
        errno: i32,
        message: String,
    },

    /// `rte_eth_tx_queue_setup()` failed.
    #[error("failed to set up TX queue {queue} of port {id} (rte_errno {errno}: {message})")]
    TxQueueSetup {
        id: u16,
        queue: u16,
        errno: i32,
        message: String,
    },

    /// `rte_eth_dev_start()` failed.
    #[error("failed to start port {id} (rte_errno {errno}: {message})")]
    Start { id: u16, errno: i32, message: String },

    /// A promiscuous mode query or update failed.
    #[error("promiscuous mode operation on port {id} failed (rte_errno {errno}: {message})")]
    Promiscuous { id: u16, errno: i32, message: String },

    /// `rte_eth_stats_get()` failed.
    #[error("failed to read statistics of port {id} (rte_errno {errno}: {message})")]
    Stats { id: u16, errno: i32, message: String },

    /// An MTU query or update failed.
    #[error("MTU operation on port {id} failed (rte_errno {errno}: {message})")]
    Mtu { id: u16, errno: i32, message: String },

    /// An RSS hash configuration operation failed.
    #[error("RSS hash operation on port {id} failed (rte_errno {errno}: {message})")]
    Rss { id: u16, errno: i32, message: String },

    /// `rte_eth_dev_adjust_nb_rx_tx_desc()` failed.
    #[error("failed to adjust descriptor counts of port {id} (rte_errno {errno}: {message})")]
    AdjustDesc { id: u16, errno: i32, message: String },

    /// Anything else that came back through `rte_errno`.
    #[error("port {id}: DPDK error {errno}: {message}")]
    Rte { id: u16, errno: i32, message: String },
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

/// Failure while launching a task on a DPDK lcore.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LcoreError {
    /// The main lcore cannot be used for a worker task.
    #[error("lcore {id} is the main lcore")]
    MainLcore { id: u32 },

    /// The lcore is not part of the EAL core mask.
    #[error("lcore {id} is not enabled")]
    Disabled { id: u32 },

    /// This scope already launched a task on the lcore.
    #[error("lcore {id} already has a task launched by this scope")]
    AlreadyLaunched { id: u32 },

    /// `rte_eal_remote_launch()` failed.
    #[error("failed to launch a task on lcore {id} (rte_errno {errno}: {message})")]
    Launch { id: u32, errno: i32, message: String },
}

impl LcoreError {
    /// Capture the current `rte_errno` with an lcore context.
    pub(crate) fn from_rte_errno(id: u32) -> Self {
        let errno = rte_errno();

        Self::Launch {
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

/// Failure while scanning, probing or dumping the registered buses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BusError {
    /// `rte_bus_scan()` reported a failure.
    #[error("failed to scan buses (rte_errno {errno}: {message})")]
    Scan { errno: i32, message: String },

    /// `rte_bus_probe()` reported a failure.
    #[error("failed to probe buses (rte_errno {errno}: {message})")]
    Probe { errno: i32, message: String },

    /// Opening a stream for `rte_bus_dump()` failed.
    #[error("failed to dump buses: {0}")]
    Dump(#[from] std::io::Error),
}

/// Convenience alias used throughout `rte::new`.
pub type Result<T, E = MempoolError> = core::result::Result<T, E>;
