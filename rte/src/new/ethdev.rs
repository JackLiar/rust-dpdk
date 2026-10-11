//! Ethernet ports and RX queues.
//!
//! The key property of this module is the lifetime chain:
//!
//! ```text
//! Eal  ──▶  MemoryPool<'eal>  ──▶  MemoryPoolRef<'pool>
//!                                        │
//!             Port  ──▶  RxQueue<'port, 'pool>  ──▶  Mbuf<'pool>
//! ```
//!
//! An [`RxQueue`] borrows both its [`Port`] and the pool its descriptors point
//! at, and every [`Mbuf`] borrows the pool as well. Consequently:
//!
//! * a pool cannot be freed while a queue (or a packet) still references it,
//! * a port is stopped and closed only after the queues borrowing it are gone.
//!
//! Both fall out of ordinary lexical scoping, no unsafe bookkeeping required.

use core::cell::Cell;
use core::ffi::c_uint;
use core::fmt;
use core::marker::PhantomData;
use core::ptr;

use crate::ffi;

use super::error::{rte_errno, rte_strerror, PortError};
use super::mbuf::Mbuf;
use super::mempool::MemoryPoolRef;

/// Identifier of an ethernet port.
pub type PortId = u16;

/// Identifier of a queue on a port.
pub type QueueId = u16;

/// Port RX offload bits.
///
/// Thin re-exports of `DEV_RX_OFFLOAD_*`, usable with
/// [`PortConfig::with_rx_offloads`].
pub mod rx_offloads {
    /// Ask the PMD to stamp packets with a hardware RX timestamp.
    pub const TIMESTAMP: u64 = crate::ffi::DEV_RX_OFFLOAD_TIMESTAMP as u64;
}

/// A 48 bit ethernet address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EtherAddr(pub [u8; 6]);

impl fmt::Display for EtherAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;

        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// Link status of a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatus {
    pub up: bool,
    pub speed: u32,
    pub duplex: bool,
    pub autoneg: bool,
}

/// A snapshot of the interesting fields of `rte_eth_dev_info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortInfo {
    pub driver_name: String,
    pub rx_offload_capa: u64,
    pub tx_offload_capa: u64,
    pub socket_id: i32,
    pub max_rx_queues: u16,
    pub max_tx_queues: u16,
    pub max_rx_pktlen: u32,
}

/// Port level configuration (`rte_eth_conf`).
///
/// The C structure is wrapped rather than exposed, so the only way to influence
/// it is through the explicit setters.
#[derive(Clone)]
pub struct PortConfig {
    conf: ffi::rte_eth_conf,
}

impl PortConfig {
    /// Request the given `DEV_RX_OFFLOAD_*` bits.
    #[must_use]
    pub fn with_rx_offloads(mut self, offloads: u64) -> Self {
        self.conf.rxmode.offloads |= offloads;
        self
    }

    /// Currently requested RX offload bits.
    #[inline]
    pub fn rx_offloads(&self) -> u64 {
        self.conf.rxmode.offloads
    }
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            conf: ffi::rte_eth_conf::default(),
        }
    }
}

impl fmt::Debug for PortConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortConfig")
            .field("rx_offloads", &format_args!("{:#x}", self.rx_offloads()))
            .finish()
    }
}

/// An opened ethernet port.
///
/// # Lifecycle
///
/// `Port::configure()` → `Port::rx_queue_setup()` → `Port::start()` is the
/// order DPDK requires; violating it is reported as a [`PortError`].
///
/// Dropping the port stops it (if started) and closes it (if configured), so
/// `Drop` order alone is enough to tear everything down cleanly.
///
/// Ports are process global rather than exclusively owned, so use
/// [`Port::leak`] if some other component is responsible for the port.
#[must_use = "dropping a Port stops and closes it"]
pub struct Port {
    id: PortId,
    configured: Cell<bool>,
    started: Cell<bool>,
    closed: Cell<bool>,
}

impl Port {
    /// Number of ethernet ports currently available.
    #[inline]
    pub fn count() -> u16 {
        unsafe { ffi::rte_eth_dev_count_avail() }
    }

    /// Open `id`, validating it against the available ports.
    pub fn open(id: PortId) -> Result<Self, PortError> {
        let count = Self::count();

        if id >= count || unsafe { ffi::rte_eth_dev_is_valid_port(id) } == 0 {
            return Err(PortError::InvalidPort { id, count });
        }

        Ok(Self {
            id,
            configured: Cell::new(false),
            started: Cell::new(false),
            closed: Cell::new(false),
        })
    }

    /// Port id.
    #[inline]
    pub fn id(&self) -> PortId {
        self.id
    }

    /// Driver name, offload capabilities and queue limits.
    pub fn info(&self) -> PortInfo {
        let mut info = ffi::rte_eth_dev_info::default();

        unsafe { ffi::rte_eth_dev_info_get(self.id, &mut info) };

        PortInfo {
            driver_name: if info.driver_name.is_null() {
                String::new()
            } else {
                unsafe { core::ffi::CStr::from_ptr(info.driver_name) }
                    .to_string_lossy()
                    .into_owned()
            },
            rx_offload_capa: info.rx_offload_capa,
            tx_offload_capa: info.tx_offload_capa,
            socket_id: unsafe { ffi::rte_eth_dev_socket_id(self.id) },
            max_rx_queues: info.max_rx_queues,
            max_tx_queues: info.max_tx_queues,
            max_rx_pktlen: info.max_rx_pktlen,
        }
    }

    /// MAC address of the port.
    pub fn mac_addr(&self) -> EtherAddr {
        let mut addr = ffi::rte_ether_addr {
            addr_bytes: [0; 6],
        };

        unsafe { ffi::rte_eth_macaddr_get(self.id, &mut addr) };

        EtherAddr(addr.addr_bytes)
    }

    /// Link status, waiting (up to 9 seconds) for the link to settle.
    #[inline]
    pub fn link(&self) -> LinkStatus {
        self.link_status(true)
    }

    /// Link status without waiting.
    #[inline]
    pub fn link_nowait(&self) -> LinkStatus {
        self.link_status(false)
    }

    fn link_status(&self, wait: bool) -> LinkStatus {
        let mut link = ffi::rte_eth_link::default();

        // SAFETY: `link` is a valid out parameter for both entry points.
        unsafe {
            if wait {
                ffi::rte_eth_link_get(self.id, &mut link);
            } else {
                ffi::rte_eth_link_get_nowait(self.id, &mut link);
            }
        }

        LinkStatus {
            up: link.link_status() != 0,
            speed: link.link_speed,
            duplex: link.link_duplex() != 0,
            autoneg: link.link_autoneg() != 0,
        }
    }

    /// Configure the port for `nb_rx`/`nb_tx` queues.
    pub fn configure(
        &self,
        nb_rx: QueueId,
        nb_tx: QueueId,
        conf: &PortConfig,
    ) -> Result<(), PortError> {
        let ret = unsafe { ffi::rte_eth_dev_configure(self.id, nb_rx, nb_tx, &conf.conf) };

        if ret != 0 {
            let errno = rte_errno();

            return Err(PortError::Configure {
                id: self.id,
                errno,
                message: rte_strerror(errno),
            });
        }

        self.configured.set(true);

        Ok(())
    }

    /// Set up an RX queue backed by `pool`.
    ///
    /// The returned queue borrows both this port and `pool`, which is what
    /// prevents the descriptors from ever outliving their buffers.
    pub fn rx_queue_setup<'port, 'pool>(
        &'port self,
        queue: QueueId,
        nb_desc: u16,
        conf: Option<ffi::rte_eth_rxconf>,
        pool: MemoryPoolRef<'pool>,
    ) -> Result<RxQueue<'port, 'pool>, PortError> {
        let socket_id = unsafe { ffi::rte_eth_dev_socket_id(self.id) } as c_uint;

        let ret = unsafe {
            ffi::rte_eth_rx_queue_setup(
                self.id,
                queue,
                nb_desc,
                socket_id,
                conf.as_ref().map_or(ptr::null(), |conf| conf as *const _),
                pool.as_ptr().as_ptr(),
            )
        };

        if ret != 0 {
            let errno = rte_errno();

            return Err(PortError::RxQueueSetup {
                id: self.id,
                queue,
                errno,
                message: rte_strerror(errno),
            });
        }

        Ok(RxQueue {
            port: self.id,
            queue,
            _port: PhantomData,
            _pool: PhantomData,
        })
    }

    /// Start the port.
    pub fn start(&self) -> Result<(), PortError> {
        let ret = unsafe { ffi::rte_eth_dev_start(self.id) };

        if ret != 0 {
            let errno = rte_errno();

            return Err(PortError::Start {
                id: self.id,
                errno,
                message: rte_strerror(errno),
            });
        }

        self.started.set(true);

        Ok(())
    }

    /// Stop the port, if it was started.
    pub fn stop(&self) {
        if self.started.replace(false) {
            unsafe { ffi::rte_eth_dev_stop(self.id) };
        }
    }

    /// Stop and close the port. Idempotent.
    ///
    /// Closing is irreversible: the device cannot be restarted afterwards.
    pub fn close(&self) {
        if self.closed.replace(true) {
            return;
        }

        self.stop();

        if self.configured.replace(false) {
            unsafe { ffi::rte_eth_dev_close(self.id) };
        }
    }

    /// Enable promiscuous mode.
    pub fn promiscuous_enable(&self) -> Result<(), PortError> {
        let ret = unsafe { ffi::rte_eth_promiscuous_enable(self.id) };

        if ret != 0 {
            let errno = rte_errno();

            return Err(PortError::Promiscuous {
                id: self.id,
                errno,
                message: rte_strerror(errno),
            });
        }

        Ok(())
    }

    /// Whether promiscuous mode is currently enabled.
    pub fn is_promiscuous(&self) -> Result<bool, PortError> {
        let ret = unsafe { ffi::rte_eth_promiscuous_get(self.id) };

        if ret < 0 {
            let errno = rte_errno();

            return Err(PortError::Promiscuous {
                id: self.id,
                errno,
                message: rte_strerror(errno),
            });
        }

        Ok(ret != 0)
    }

    /// Read the NIC hardware clock.
    ///
    /// The units and epoch are device specific; the value is mainly useful for
    /// interpreting the timestamps written into mbufs by the PMD.
    pub fn read_clock(&self) -> Result<u64, PortError> {
        let mut clock: u64 = 0;

        let ret = unsafe { ffi::rte_eth_read_clock(self.id, &mut clock) };

        if ret != 0 {
            return Err(PortError::from_rte_errno(self.id));
        }

        Ok(clock)
    }

    /// Give up ownership without stopping or closing the port.
    ///
    /// Returns the port id so the caller can keep using the low level API.
    pub fn leak(self) -> PortId {
        let id = self.id;

        core::mem::forget(self);

        id
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        if self.closed.get() {
            return;
        }

        if self.started.replace(false) {
            unsafe { ffi::rte_eth_dev_stop(self.id) };
        }

        if self.configured.replace(false) {
            unsafe { ffi::rte_eth_dev_close(self.id) };
        }

        self.closed.set(true);
    }
}

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Port")
            .field("id", &self.id)
            .field("configured", &self.configured.get())
            .field("started", &self.started.get())
            .field("closed", &self.closed.get())
            .finish()
    }
}

/// An RX queue.
///
/// Borrows the port (so the port cannot be closed while the queue exists) and
/// the mempool the descriptors point at (so the pool cannot be freed while
/// packets may still be in flight).
pub struct RxQueue<'port, 'pool> {
    port: PortId,
    queue: QueueId,
    _port: PhantomData<&'port Port>,
    _pool: PhantomData<MemoryPoolRef<'pool>>,
}

impl<'port, 'pool> RxQueue<'port, 'pool> {
    /// Port this queue belongs to.
    #[inline]
    pub fn port_id(&self) -> PortId {
        self.port
    }

    /// Queue id.
    #[inline]
    pub fn queue_id(&self) -> QueueId {
        self.queue
    }

    /// Receive up to `bufs.len()` packets.
    ///
    /// # Preconditions
    ///
    /// `bufs` must contain only `None`. DPDK writes raw pointers into the slice,
    /// so a still-populated slot would be overwritten without running `Drop`
    /// and the packet would leak. `take()`-ing the packets of the previous
    /// iteration (as the example does) keeps this invariant, and a debug build
    /// asserts it.
    pub fn rx_burst(&self, bufs: &mut [Option<Mbuf<'pool>>]) -> usize {
        if bufs.is_empty() {
            return 0;
        }

        debug_assert!(
            bufs.iter().all(Option::is_none),
            "rx_burst() needs an empty burst buffer: take() the packets of the previous burst first"
        );

        // SAFETY: `Option<Mbuf>` has the same representation as `*mut rte_mbuf`
        // (asserted in `new::mbuf`), and we only ever hand empty slots to DPDK.
        unsafe {
            ffi::_rte_eth_rx_burst(
                self.port,
                self.queue,
                bufs.as_mut_ptr() as *mut *mut ffi::rte_mbuf,
                bufs.len() as u16,
            ) as usize
        }
    }
}

impl fmt::Debug for RxQueue<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RxQueue")
            .field("port", &self.port)
            .field("queue", &self.queue)
            .finish()
    }
}
