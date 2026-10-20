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
use core::ops::Deref;
use core::ptr;

use bitflags::bitflags;

use crate::ffi;

use super::error::{PortError, rte_errno, rte_strerror};
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

    /// Strip the outer VLAN tag and report it through `Mbuf::vlan_tci`.
    pub const VLAN_STRIP: u64 = crate::ffi::DEV_RX_OFFLOAD_VLAN_STRIP as u64;

    /// Allow the PMD to split a packet into multiple mbuf segments.
    ///
    /// The zero-copy capture path deliberately does **not** request this: it
    /// wants every normal-MTU frame in one segment.
    pub const SCATTER: u64 = crate::ffi::DEV_RX_OFFLOAD_SCATTER as u64;
}

bitflags! {
    /// RSS hash types accepted by `rte_eth_conf.rx_adv_conf.rss_conf.rss_hf`.
    ///
    /// The individual bits mirror `ETH_RSS_*`. The combined `IP`/`TCP`/`UDP`/
    /// `SCTP` constants are the IPv4+IPv6 unions, matching the legacy
    /// `ETH_RSS_IP`/`ETH_RSS_TCP`/... macros.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RssHash: u64 {
        const IPV4 = ffi::ETH_RSS_IPV4 as u64;
        const IPV6 = ffi::ETH_RSS_IPV6 as u64;
        const IPV4_TCP = ffi::ETH_RSS_NONFRAG_IPV4_TCP as u64;
        const IPV6_TCP = ffi::ETH_RSS_NONFRAG_IPV6_TCP as u64;
        const IPV4_UDP = ffi::ETH_RSS_NONFRAG_IPV4_UDP as u64;
        const IPV6_UDP = ffi::ETH_RSS_NONFRAG_IPV6_UDP as u64;
        const IPV4_SCTP = ffi::ETH_RSS_NONFRAG_IPV4_SCTP as u64;
        const IPV6_SCTP = ffi::ETH_RSS_NONFRAG_IPV6_SCTP as u64;
    }
}

impl RssHash {
    /// IPv4 and IPv6 traffic.
    pub const IP: Self = Self::IPV4.union(Self::IPV6);
    /// IPv4 and IPv6 TCP traffic.
    pub const TCP: Self = Self::IPV4_TCP.union(Self::IPV6_TCP);
    /// IPv4 and IPv6 UDP traffic.
    pub const UDP: Self = Self::IPV4_UDP.union(Self::IPV6_UDP);
    /// IPv4 and IPv6 SCTP traffic.
    pub const SCTP: Self = Self::IPV4_SCTP.union(Self::IPV6_SCTP);
}

/// RSS configuration wrapping the native `rte_eth_rss_conf`.
///
/// The native struct stores a borrowed key pointer; this wrapper owns the key
/// bytes and keeps `raw.rss_key` pointing at them. `Deref` exposes the native
/// fields, while [`as_raw`](Self::as_raw) is convenient for FFI calls.
#[derive(Debug)]
pub struct RssConfig {
    raw: ffi::rte_eth_rss_conf,
    key: Option<Vec<u8>>,
}

impl RssConfig {
    /// Build an RSS configuration with the given hash types and the PMD default key.
    #[must_use]
    pub fn new(hf: RssHash) -> Self {
        let mut raw = ffi::rte_eth_rss_conf::default();
        raw.rss_hf = hf.bits();

        Self { raw, key: None }
    }

    /// Set an explicit RSS key.
    #[must_use]
    pub fn with_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        let key = key.into();
        assert!(
            key.len() <= u8::MAX as usize,
            "RSS key is too long for rte_eth_rss_conf"
        );

        self.key = Some(key);
        self.sync_key();
        self
    }

    /// RSS hash functions (`RssHash` bits).
    #[inline]
    pub fn hf(&self) -> u64 {
        self.raw.rss_hf
    }

    /// Owned RSS key, if configured.
    #[inline]
    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }

    /// Native `rte_eth_rss_conf` view.
    #[inline]
    pub fn as_raw(&self) -> &ffi::rte_eth_rss_conf {
        &self.raw
    }

    fn from_raw(raw: ffi::rte_eth_rss_conf, key: Option<Vec<u8>>) -> Self {
        let mut this = Self { raw, key };
        this.sync_key();
        this
    }

    fn sync_key(&mut self) {
        match &self.key {
            Some(key) => {
                self.raw.rss_key = key.as_ptr() as *mut u8;
                self.raw.rss_key_len = key.len() as u8;
            }
            None => {
                self.raw.rss_key = ptr::null_mut();
                self.raw.rss_key_len = 0;
            }
        }
    }
}

impl Default for RssConfig {
    fn default() -> Self {
        Self {
            raw: ffi::rte_eth_rss_conf::default(),
            key: None,
        }
    }
}

impl Clone for RssConfig {
    fn clone(&self) -> Self {
        Self::from_raw(self.raw, self.key.clone())
    }
}

impl Deref for RssConfig {
    type Target = ffi::rte_eth_rss_conf;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

/// A 48 bit ethernet address wrapping `rte_ether_addr`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct EtherAddr(ffi::rte_ether_addr);

impl EtherAddr {
    /// Native `rte_ether_addr` view.
    #[inline]
    pub fn as_raw(&self) -> &ffi::rte_ether_addr {
        &self.0
    }

    /// The six address octets.
    #[inline]
    pub fn octets(&self) -> [u8; 6] {
        self.0.addr_bytes
    }
}

impl Deref for EtherAddr {
    type Target = ffi::rte_ether_addr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 6]> for EtherAddr {
    fn from(addr_bytes: [u8; 6]) -> Self {
        Self(ffi::rte_ether_addr { addr_bytes })
    }
}

impl From<ffi::rte_ether_addr> for EtherAddr {
    fn from(addr: ffi::rte_ether_addr) -> Self {
        Self(addr)
    }
}

impl fmt::Display for EtherAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0.addr_bytes;

        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// Link status wrapping the native `rte_eth_link`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LinkStatus(ffi::rte_eth_link);

impl LinkStatus {
    /// Native `rte_eth_link` view.
    #[inline]
    pub fn as_raw(&self) -> &ffi::rte_eth_link {
        &self.0
    }

    /// Whether the link is up.
    #[inline]
    pub fn up(&self) -> bool {
        self.0.link_status() != 0
    }

    /// Link speed in Mbps.
    #[inline]
    pub fn speed(&self) -> u32 {
        self.0.link_speed
    }

    /// Whether the link is full duplex.
    #[inline]
    pub fn duplex(&self) -> bool {
        self.0.link_duplex() != 0
    }

    /// Whether autonegotiation is enabled.
    #[inline]
    pub fn autoneg(&self) -> bool {
        self.0.link_autoneg() != 0
    }
}

impl Deref for LinkStatus {
    type Target = ffi::rte_eth_link;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ffi::rte_eth_link> for LinkStatus {
    fn from(link: ffi::rte_eth_link) -> Self {
        Self(link)
    }
}

/// Port information wrapping the native `rte_eth_dev_info`.
///
/// The native struct contains pointers owned by DPDK; the `'port` lifetime ties
/// them to the [`Port`] they were read from. `socket_id` is extra metadata
/// because `rte_eth_dev_info` itself does not carry it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PortInfo<'port> {
    raw: ffi::rte_eth_dev_info,
    /// NUMA socket of the port (`rte_eth_dev_socket_id`).
    pub socket_id: i32,
    _port: PhantomData<&'port Port>,
}

impl<'port> PortInfo<'port> {
    /// Native `rte_eth_dev_info` view.
    #[inline]
    pub fn as_raw(&self) -> &ffi::rte_eth_dev_info {
        &self.raw
    }

    /// Safe driver-name view; returns `""` if DPDK has no name or the bytes are
    /// not valid UTF-8.
    #[inline]
    pub fn driver_name(&self) -> &str {
        if self.raw.driver_name.is_null() {
            return "";
        }

        // SAFETY: DPDK owns the driver name for the lifetime of the port.
        unsafe { core::ffi::CStr::from_ptr(self.raw.driver_name) }
            .to_str()
            .unwrap_or("")
    }

    /// NUMA socket of the port.
    #[inline]
    pub fn socket_id(&self) -> i32 {
        self.socket_id
    }
}

impl Deref for PortInfo<'_> {
    type Target = ffi::rte_eth_dev_info;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

/// Port statistics wrapping the native `rte_eth_stats`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PortStats(ffi::rte_eth_stats);

impl PortStats {
    /// Native `rte_eth_stats` view, including all `q_*` arrays.
    #[inline]
    pub fn as_raw(&self) -> &ffi::rte_eth_stats {
        &self.0
    }

    /// Snapshot of the counters for `queue`, if the PMD exposes them.
    ///
    /// DPDK 20.11 keeps only `RTE_ETHDEV_QUEUE_STAT_CNTRS` (16) queue slots,
    /// so larger queue ids return `None`.
    pub fn queue_stats(&self, queue: QueueId) -> Option<QueueStats> {
        if queue as usize >= ffi::RTE_ETHDEV_QUEUE_STAT_CNTRS as usize {
            return None;
        }

        Some(QueueStats { raw: self.0, queue })
    }
}

impl Deref for PortStats {
    type Target = ffi::rte_eth_stats;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ffi::rte_eth_stats> for PortStats {
    fn from(stats: ffi::rte_eth_stats) -> Self {
        Self(stats)
    }
}

/// Per-queue view over a native `rte_eth_stats` snapshot.
///
/// This is a thin wrapper around the whole native stats struct plus the queue
/// index; it does not re-declare the per-queue counters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QueueStats {
    raw: ffi::rte_eth_stats,
    queue: QueueId,
}

impl QueueStats {
    /// Queue id this view refers to.
    #[inline]
    pub fn queue_id(&self) -> QueueId {
        self.queue
    }

    /// Received packets on this queue.
    #[inline]
    pub fn packets(&self) -> u64 {
        self.raw.q_ipackets[self.queue as usize]
    }

    /// Received bytes on this queue.
    #[inline]
    pub fn bytes(&self) -> u64 {
        self.raw.q_ibytes[self.queue as usize]
    }

    /// Receive errors on this queue.
    #[inline]
    pub fn errors(&self) -> u64 {
        self.raw.q_errors[self.queue as usize]
    }

    /// Native stats snapshot, including all queue arrays.
    #[inline]
    pub fn as_raw(&self) -> &ffi::rte_eth_stats {
        &self.raw
    }
}

/// Per-queue RX configuration wrapping `rte_eth_rxconf`.
///
/// `nb_desc` is kept outside the native struct because
/// `rte_eth_rx_queue_setup()` takes it as a separate argument.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RxQueueConfig {
    /// Number of RX descriptors.
    pub nb_desc: u16,
    raw: ffi::rte_eth_rxconf,
}

impl Default for RxQueueConfig {
    fn default() -> Self {
        let mut raw = ffi::rte_eth_rxconf::default();
        raw.rx_free_thresh = 32;
        raw.rx_drop_en = 1;

        Self { nb_desc: 1024, raw }
    }
}

impl RxQueueConfig {
    /// Native `rte_eth_rxconf` view.
    #[inline]
    pub fn as_raw(&self) -> &ffi::rte_eth_rxconf {
        &self.raw
    }

    /// Set the descriptor count.
    #[must_use]
    pub fn with_nb_desc(mut self, nb_desc: u16) -> Self {
        self.nb_desc = nb_desc;
        self
    }

    /// Set `rx_free_thresh`.
    #[must_use]
    pub fn with_free_thresh(mut self, free_thresh: u16) -> Self {
        self.raw.rx_free_thresh = free_thresh;
        self
    }

    /// Set `rx_drop_en`.
    #[must_use]
    pub fn with_drop_en(mut self, drop_en: bool) -> Self {
        self.raw.rx_drop_en = u8::from(drop_en);
        self
    }

    /// Set `rx_deferred_start`.
    #[must_use]
    pub fn with_deferred_start(mut self, deferred_start: bool) -> Self {
        self.raw.rx_deferred_start = u8::from(deferred_start);
        self
    }

    /// Set queue-level offloads.
    #[must_use]
    pub fn with_offloads(mut self, offloads: u64) -> Self {
        self.raw.offloads = offloads;
        self
    }
}

impl Deref for RxQueueConfig {
    type Target = ffi::rte_eth_rxconf;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

/// Port level configuration wrapping the native `rte_eth_conf`.
///
/// The native RSS config stores a borrowed key pointer, so this wrapper owns the
/// key bytes and keeps `raw.rx_adv_conf.rss_conf.rss_key` pointing at them.
/// `Deref` exposes the native fields; the setters keep the pointer/backing store
/// consistent.
pub struct PortConfig {
    raw: ffi::rte_eth_conf,
    rss_key: Option<Vec<u8>>,
}

impl PortConfig {
    /// Request the given `DEV_RX_OFFLOAD_*` bits.
    #[must_use]
    pub fn with_rx_offloads(mut self, offloads: u64) -> Self {
        self.raw.rxmode.offloads |= offloads;
        self
    }

    /// Request the given `DEV_TX_OFFLOAD_*` bits.
    #[must_use]
    pub fn with_tx_offloads(mut self, offloads: u64) -> Self {
        self.raw.txmode.offloads |= offloads;
        self
    }

    /// Enable RSS with the given hash types and the PMD default key.
    ///
    /// This also sets `rxmode.mq_mode = ETH_MQ_RX_RSS`; setting `rss_hf` alone
    /// is not enough for most PMDs.
    #[must_use]
    pub fn with_rss(mut self, hf: RssHash) -> Self {
        self.raw.rxmode.mq_mode = ffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;
        self.raw.rx_adv_conf.rss_conf.rss_hf = hf.bits();
        self
    }

    /// Set an explicit RSS key.
    ///
    /// If RSS was not enabled yet, this enables it with [`RssHash::IP`].
    #[must_use]
    pub fn with_rss_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        let key = key.into();
        assert!(
            key.len() <= u8::MAX as usize,
            "RSS key is too long for rte_eth_rss_conf"
        );

        self.rss_key = Some(key);

        if self.raw.rxmode.mq_mode != ffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS {
            self.raw.rxmode.mq_mode = ffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;
            self.raw.rx_adv_conf.rss_conf.rss_hf = RssHash::IP.bits();
        }

        self.sync_key();
        self
    }

    /// Replace the whole RSS configuration.
    #[must_use]
    pub fn with_rss_config(mut self, rss: RssConfig) -> Self {
        self.raw.rx_adv_conf.rss_conf = *rss.as_raw();
        self.raw.rxmode.mq_mode = ffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;
        self.rss_key = rss.key().map(|key| key.to_vec());
        self.sync_key();
        self
    }

    /// Native `rte_eth_conf` view.
    #[inline]
    pub fn as_raw(&self) -> &ffi::rte_eth_conf {
        &self.raw
    }

    /// Currently requested RX offload bits.
    #[inline]
    pub fn rx_offloads(&self) -> u64 {
        self.raw.rxmode.offloads
    }

    /// Currently requested TX offload bits.
    #[inline]
    pub fn tx_offloads(&self) -> u64 {
        self.raw.txmode.offloads
    }

    /// Native RSS configuration, if RSS is enabled.
    #[inline]
    pub fn rss(&self) -> Option<&ffi::rte_eth_rss_conf> {
        if self.raw.rxmode.mq_mode == ffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS {
            Some(&self.raw.rx_adv_conf.rss_conf)
        } else {
            None
        }
    }

    /// Owned RSS key, if configured.
    #[inline]
    pub fn rss_key(&self) -> Option<&[u8]> {
        self.rss_key.as_deref()
    }

    /// `rxmode.max_rx_pkt_len`, if explicitly configured.
    #[inline]
    pub fn max_rx_pkt_len(&self) -> Option<u32> {
        (self.raw.rxmode.max_rx_pkt_len != 0).then_some(self.raw.rxmode.max_rx_pkt_len)
    }

    /// Set `rxmode.max_rx_pkt_len` (needed for jumbo frames and to size the
    /// PMD's receive buffers).
    #[must_use]
    pub fn with_max_rx_pkt_len(mut self, len: u32) -> Self {
        self.raw.rxmode.max_rx_pkt_len = len;
        self
    }

    fn sync_key(&mut self) {
        match &self.rss_key {
            Some(key) => {
                self.raw.rx_adv_conf.rss_conf.rss_key = key.as_ptr() as *mut u8;
                self.raw.rx_adv_conf.rss_conf.rss_key_len = key.len() as u8;
            }
            None => {
                self.raw.rx_adv_conf.rss_conf.rss_key = ptr::null_mut();
                self.raw.rx_adv_conf.rss_conf.rss_key_len = 0;
            }
        }
    }
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            raw: ffi::rte_eth_conf::default(),
            rss_key: None,
        }
    }
}

impl Clone for PortConfig {
    fn clone(&self) -> Self {
        let mut this = Self {
            raw: self.raw,
            rss_key: self.rss_key.clone(),
        };
        this.sync_key();
        this
    }
}

impl Deref for PortConfig {
    type Target = ffi::rte_eth_conf;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl fmt::Debug for PortConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortConfig")
            .field("rx_offloads", &format_args!("{:#x}", self.raw.rxmode.offloads))
            .field("tx_offloads", &format_args!("{:#x}", self.raw.txmode.offloads))
            .field("mq_mode", &self.raw.rxmode.mq_mode)
            .field("rss_hf", &format_args!("{:#x}", self.raw.rx_adv_conf.rss_conf.rss_hf))
            .field("rss_key_len", &self.raw.rx_adv_conf.rss_conf.rss_key_len)
            .field("max_rx_pkt_len", &self.raw.rxmode.max_rx_pkt_len)
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
    pub fn available_count() -> u16 {
        unsafe { ffi::rte_eth_dev_count_avail() }
    }

    /// Number of ethernet ports in total.
    #[inline]
    pub fn total_count() -> u16 {
        unsafe { ffi::rte_eth_dev_count_total() }
    }

    /// Open `id`, validating it against the available ports.
    pub fn open(id: PortId) -> Result<Self, PortError> {
        let count = Self::available_count();

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

    /// NUMA socket the port is attached to.
    #[inline]
    pub fn socket_id(&self) -> i32 {
        unsafe { ffi::rte_eth_dev_socket_id(self.id) }
    }

    /// Driver name, offload capabilities and queue limits.
    ///
    /// The returned snapshot wraps the native `rte_eth_dev_info`; the lifetime
    /// ties its pointer fields to this port.
    pub fn info(&self) -> PortInfo<'_> {
        let mut raw = ffi::rte_eth_dev_info::default();

        unsafe { ffi::rte_eth_dev_info_get(self.id, &mut raw) };

        PortInfo {
            raw,
            socket_id: self.socket_id(),
            _port: PhantomData,
        }
    }

    /// MAC address of the port.
    pub fn mac_addr(&self) -> EtherAddr {
        let mut addr = ffi::rte_ether_addr::default();

        unsafe { ffi::rte_eth_macaddr_get(self.id, &mut addr) };

        EtherAddr(addr)
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

        LinkStatus(link)
    }

    /// Configure the port for `nb_rx`/`nb_tx` queues.
    pub fn configure(&self, nb_rx: QueueId, nb_tx: QueueId, conf: &PortConfig) -> Result<(), PortError> {
        let ret = unsafe { ffi::rte_eth_dev_configure(self.id, nb_rx, nb_tx, conf.as_raw()) };

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

    /// Set the port MTU.
    pub fn set_mtu(&self, mtu: u16) -> Result<(), PortError> {
        let ret = unsafe { ffi::rte_eth_dev_set_mtu(self.id, mtu) };

        if ret != 0 {
            let errno = rte_errno();

            return Err(PortError::Mtu {
                id: self.id,
                errno,
                message: rte_strerror(errno),
            });
        }

        Ok(())
    }

    /// Read the current port MTU.
    pub fn mtu(&self) -> Result<u16, PortError> {
        let mut mtu: u16 = 0;
        let ret = unsafe { ffi::rte_eth_dev_get_mtu(self.id, &mut mtu) };

        if ret != 0 {
            let errno = rte_errno();

            return Err(PortError::Mtu {
                id: self.id,
                errno,
                message: rte_strerror(errno),
            });
        }

        Ok(mtu)
    }

    /// Clamp RX/TX descriptor counts to the values accepted by the PMD.
    ///
    /// Call this before [`configure`](Self::configure); DPDK adjusts both
    /// values in place.
    pub fn adjust_nb_rx_tx_desc(&self, rx: &mut u16, tx: &mut u16) -> Result<(), PortError> {
        let ret = unsafe { ffi::rte_eth_dev_adjust_nb_rx_tx_desc(self.id, rx, tx) };

        if ret != 0 {
            let errno = rte_errno();

            return Err(PortError::AdjustDesc {
                id: self.id,
                errno,
                message: rte_strerror(errno),
            });
        }

        Ok(())
    }

    /// Read the port-wide statistics.
    pub fn stats(&self) -> Result<PortStats, PortError> {
        let mut stats = ffi::rte_eth_stats::default();
        let ret = unsafe { ffi::rte_eth_stats_get(self.id, &mut stats) };

        if ret != 0 {
            let errno = rte_errno();

            return Err(PortError::Stats {
                id: self.id,
                errno,
                message: rte_strerror(errno),
            });
        }

        Ok(PortStats(stats))
    }

    /// Read per-queue statistics, if the PMD exposes them.
    ///
    /// DPDK 20.11 keeps only `RTE_ETHDEV_QUEUE_STAT_CNTRS` (16) queue slots,
    /// so larger queue ids return `None`.
    pub fn queue_stats(&self, queue: QueueId) -> Option<QueueStats> {
        self.stats().ok()?.queue_stats(queue)
    }

    /// Update the RSS hash configuration at runtime.
    pub fn rss_hash_update(&self, rss: &RssConfig) -> Result<(), PortError> {
        let mut conf = *rss.as_raw();
        let ret = unsafe { ffi::rte_eth_dev_rss_hash_update(self.id, &mut conf) };

        if ret != 0 {
            let errno = rte_errno();

            return Err(PortError::Rss {
                id: self.id,
                errno,
                message: rte_strerror(errno),
            });
        }

        Ok(())
    }

    /// Read the current RSS hash configuration, including the key.
    pub fn rss_hash_conf(&self) -> Result<RssConfig, PortError> {
        let mut key = [0u8; 64];
        let key_len = match self.info().hash_key_size as usize {
            0 => 40,
            len => len.min(key.len()),
        };
        let mut conf = ffi::rte_eth_rss_conf {
            rss_key: key.as_mut_ptr(),
            rss_key_len: key_len as u8,
            rss_hf: 0,
        };

        let ret = unsafe { ffi::rte_eth_dev_rss_hash_conf_get(self.id, &mut conf) };

        if ret != 0 {
            let errno = rte_errno();

            return Err(PortError::Rss {
                id: self.id,
                errno,
                message: rte_strerror(errno),
            });
        }

        let key_len = (conf.rss_key_len as usize).min(key.len());
        let key = (key_len > 0).then(|| key[..key_len].to_vec());

        Ok(RssConfig::from_raw(conf, key))
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
        let socket_id = self.socket_id() as c_uint;

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

    /// Set up an RX queue using the typed [`RxQueueConfig`].
    pub fn rx_queue_setup_with<'port, 'pool>(
        &'port self,
        queue: QueueId,
        cfg: &RxQueueConfig,
        pool: MemoryPoolRef<'pool>,
    ) -> Result<RxQueue<'port, 'pool>, PortError> {
        self.rx_queue_setup(queue, cfg.nb_desc, Some(*cfg.as_raw()), pool)
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

// SAFETY: an RX queue handle can be moved to the thread that will poll it. The
// borrow lifetimes still guarantee that the port and pool outlive the queue;
// `RxQueue` is deliberately **not** `Sync`, because DPDK requires a single
// poller per queue.
unsafe impl Send for RxQueue<'_, '_> {}

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
