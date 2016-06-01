use std::ptr;
use std::mem;
use std::ops::{Deref, Range};
use std::iter::Map;
use std::ffi::{CStr, CString};
use std::os::raw::c_void;

use libc;

use ffi;

use errors::{Error, Result};
use memory::SocketId;
use mempool;
use malloc;
use mbuf;
use pci;
use ether;

pub type PortId = u8;
pub type QueueId = u16;

/// A structure used to retrieve link-level information of an Ethernet port.
pub struct EthLink {
    pub speed: u32,
    pub duplex: bool,
    pub autoneg: bool,
    pub up: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthDevice(u8);

impl From<PortId> for EthDevice {
    fn from(portid: PortId) -> Self {
        EthDevice(portid)
    }
}

impl Deref for EthDevice {
    type Target = PortId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Get the total number of Ethernet devices that have been successfully initialized
/// by the matching Ethernet driver during the PCI probing phase.
///
/// All devices whose port identifier is in the range [0, rte::ethdev::count() - 1]
/// can be operated on by network applications immediately after invoking rte_eal_init().
/// If the application unplugs a port using hotplug function,
/// The enabled port numbers may be noncontiguous.
/// In the case, the applications need to manage enabled port by themselves.
pub fn count() -> u8 {
    unsafe { ffi::rte_eth_dev_count() }
}

pub fn ports() -> Range<PortId> {
    0..count()
}

pub fn devices() -> Map<Range<PortId>, fn(PortId) -> EthDevice> {
    ports().map(EthDevice::from)
}

pub fn dev(portid: PortId) -> EthDevice {
    EthDevice(portid)
}

/// Attach a new Ethernet device specified by aruguments.
pub fn attach(devargs: &str) -> Result<EthDevice> {
    let mut portid: u8 = 0;

    let ret = unsafe { ffi::rte_eth_dev_attach(try!(CString::new(devargs)).as_ptr(), &mut portid) };

    rte_check!(ret; ok => { EthDevice(portid) })
}

impl EthDevice {
    pub fn portid(&self) -> PortId {
        self.0
    }

    /// Configure an Ethernet device.
    ///
    /// This function must be invoked first before any other function in the Ethernet API.
    /// This function can also be re-invoked when a device is in the stopped state.
    ///
    pub fn configure(&self,
                     nb_rx_queue: QueueId,
                     nb_tx_queue: QueueId,
                     conf: &EthConf)
                     -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_configure(self.0,
                                       nb_rx_queue,
                                       nb_tx_queue,
                                       RawEthConf::from(conf).as_raw())
        }; ok => { self })
    }

    /// Retrieve the contextual information of an Ethernet device.
    pub fn info(&self) -> EthDeviceInfo {
        let mut info: RawEthDeviceInfo = Default::default();

        unsafe { ffi::rte_eth_dev_info_get(self.0, &mut info) }

        EthDeviceInfo(info)
    }

    /// Retrieve the general I/O statistics of an Ethernet device.
    pub fn stats(&self) -> Result<EthDeviceStats> {
        let mut stats: RawEthDeviceStats = Default::default();

        rte_check!(unsafe {
            ffi::rte_eth_stats_get(self.0, &mut stats)
        }; ok => { EthDeviceStats(stats)})
    }

    /// Reset the general I/O statistics of an Ethernet device.
    pub fn reset_stats(&self) -> &Self {
        unsafe { ffi::rte_eth_stats_reset(self.0) };

        self
    }

    /// Retrieve the Ethernet address of an Ethernet device.
    pub fn mac_addr(&self) -> ether::EtherAddr {
        unsafe {
            let mut addr: ffi::Struct_ether_addr = mem::zeroed();

            ffi::rte_eth_macaddr_get(self.0, &mut addr);

            ether::EtherAddr::from(addr.addr_bytes)
        }
    }

    /// Set the default MAC address.
    pub fn set_mac_addr(&self, addr: &[u8; ether::ETHER_ADDR_LEN]) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_default_mac_addr_set(self.0, mem::transmute(addr.as_ptr()))
        }; ok => { self })
    }

    /// Return the NUMA socket to which an Ethernet device is connected
    pub fn socket_id(&self) -> SocketId {
        unsafe { ffi::rte_eth_dev_socket_id(self.0) }
    }

    /// Check if port_id of device is attached
    pub fn is_valid(&self) -> bool {
        unsafe { ffi::rte_eth_dev_is_valid_port(self.0) != 0 }
    }

    /// Allocate and set up a receive queue for an Ethernet device.
    ///
    /// The function allocates a contiguous block of memory for *nb_rx_desc*
    /// receive descriptors from a memory zone associated with *socket_id*
    /// and initializes each receive descriptor with a network buffer allocated
    /// from the memory pool *mb_pool*.
    pub fn rx_queue_setup(&self,
                          rx_queue_id: QueueId,
                          nb_rx_desc: u16,
                          rx_conf: Option<ffi::Struct_rte_eth_rxconf>,
                          mb_pool: &mut mempool::RawMemoryPool)
                          -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_rx_queue_setup(self.0,
                                        rx_queue_id,
                                        nb_rx_desc,
                                        self.socket_id() as u32,
                                        mem::transmute(&rx_conf),
                                        mb_pool)
        }; ok => { self })
    }

    /// Allocate and set up a transmit queue for an Ethernet device.
    pub fn tx_queue_setup(&self,
                          tx_queue_id: QueueId,
                          nb_tx_desc: u16,
                          tx_conf: Option<ffi::Struct_rte_eth_txconf>)
                          -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_tx_queue_setup(self.0,
                                        tx_queue_id,
                                        nb_tx_desc,
                                        self.socket_id() as u32,
                                        mem::transmute(&tx_conf))
        }; ok => { self })
    }

    /// Enable receipt in promiscuous mode for an Ethernet device.
    pub fn promiscuous_enable(&self) -> &Self {
        unsafe { ffi::rte_eth_promiscuous_enable(self.0) };

        self
    }

    /// Disable receipt in promiscuous mode for an Ethernet device.
    pub fn promiscuous_disable(&self) -> &Self {
        unsafe { ffi::rte_eth_promiscuous_disable(self.0) };

        self
    }

    /// Return the value of promiscuous mode for an Ethernet device.
    pub fn is_promiscuous_enabled(&self) -> Result<bool> {
        let ret = unsafe { ffi::rte_eth_promiscuous_get(self.0) };

        rte_check!(ret; ok => { ret != 0 })
    }

    /// Retrieve the MTU of an Ethernet device.
    pub fn mtu(&self) -> Result<u16> {
        let mut mtu: u16 = 0;

        rte_check!(unsafe { ffi::rte_eth_dev_get_mtu(self.0, &mut mtu)}; ok => { mtu })
    }

    /// Change the MTU of an Ethernet device.
    pub fn set_mtu(&self, mtu: u16) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_set_mtu(self.0, mtu) }; ok => { self })
    }

    /// Enable/Disable hardware filtering by an Ethernet device
    /// of received VLAN packets tagged with a given VLAN Tag Identifier.
    pub fn set_vlan_filter(&self, vlan_id: u16, on: bool) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_vlan_filter(self.0, vlan_id, bool_value!(on) as i32)
        }; ok => { self })
    }

    /// Retrieve the Ethernet device link status
    #[inline]
    pub fn is_up(&self) -> bool {
        self.link().up
    }

    /// Retrieve the status (ON/OFF), the speed (in Mbps) and
    /// the mode (HALF-DUPLEX or FULL-DUPLEX) of the physical link of an Ethernet device.
    ///
    /// It might need to wait up to 9 seconds in it.
    ///
    pub fn link(&self) -> EthLink {
        let link = 0u64;

        unsafe { ffi::rte_eth_link_get(self.0, mem::transmute(&link)) }

        EthLink {
            speed: (link & 0xFFFFFFFF) as u32,
            duplex: (link & (1 << 32)) != 0,
            autoneg: (link & (1 << 33)) != 0,
            up: (link & (1 << 34)) != 0,
        }
    }

    /// Retrieve the status (ON/OFF), the speed (in Mbps) and
    /// the mode (HALF-DUPLEX or FULL-DUPLEX) of the physical link of an Ethernet device.
    ///
    /// It is a no-wait version of rte_eth_link_get().
    ///
    pub fn link_nowait(&self) -> EthLink {
        let link = 0u64;

        unsafe { ffi::rte_eth_link_get_nowait(self.0, mem::transmute(&link)) }

        EthLink {
            speed: (link & 0xFFFFFFFF) as u32,
            duplex: (link & (1 << 32)) != 0,
            autoneg: (link & (1 << 33)) != 0,
            up: (link & (1 << 34)) != 0,
        }
    }

    /// Link up an Ethernet device.
    pub fn set_link_up(&self) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_set_link_up(self.0) }; ok => { self })
    }

    /// Link down an Ethernet device.
    pub fn set_link_down(&self) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_set_link_down(self.0) }; ok => { self })
    }

    /// Allocate mbuf from mempool, setup the DMA physical address
    /// and then start RX for specified queue of a port. It is used
    /// when rx_deferred_start flag of the specified queue is true.
    pub fn rx_queue_start(&self, rx_queue_id: QueueId) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_rx_queue_start(self.0, rx_queue_id) }; ok => { self })
    }

    /// Stop specified RX queue of a port
    pub fn rx_queue_stop(&self, rx_queue_id: QueueId) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_rx_queue_stop(self.0, rx_queue_id) }; ok => { self })
    }

    /// Start TX for specified queue of a port.
    /// It is used when tx_deferred_start flag of the specified queue is true.
    pub fn tx_queue_start(&self, tx_queue_id: QueueId) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_tx_queue_start(self.0, tx_queue_id) }; ok => { self })
    }

    /// Stop specified TX queue of a port
    pub fn tx_queue_stop(&self, tx_queue_id: QueueId) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_tx_queue_stop(self.0, tx_queue_id) }; ok => { self })
    }

    /// Start an Ethernet device.
    pub fn start(&self) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_start(self.0) }; ok => { self })
    }

    /// Stop an Ethernet device.
    pub fn stop(&self) -> &Self {
        unsafe { ffi::rte_eth_dev_stop(self.0) };

        self
    }

    /// Close a stopped Ethernet device. The device cannot be restarted!
    pub fn close(&self) -> &Self {
        unsafe { ffi::rte_eth_dev_close(self.0) };

        self
    }

    /// Retrieve a burst of input packets from a receive queue of an Ethernet device.
    pub fn rx_burst(&self, queue_id: QueueId, rx_pkts: &mut [mbuf::RawMbufPtr]) -> usize {
        unsafe {
            _rte_eth_rx_burst(self.0, queue_id, rx_pkts.as_mut_ptr(), rx_pkts.len() as u16) as usize
        }
    }

    /// Send a burst of output packets on a transmit queue of an Ethernet device.
    pub fn tx_burst(&self, queue_id: QueueId, rx_pkts: &mut [mbuf::RawMbufPtr]) -> usize {
        unsafe {
            if rx_pkts.is_empty() {
                _rte_eth_tx_burst(self.0, queue_id, ptr::null_mut(), 0) as usize
            } else {
                _rte_eth_tx_burst(self.0,
                                  queue_id,
                                  rx_pkts.as_mut_ptr(),
                                  rx_pkts.len() as u16) as usize
            }
        }
    }

    /// Set RX L2 Filtering mode of a VF of an Ethernet device.
    pub fn set_vf_rxmode(&self, vf: u16, rx_mode: EthVmdqRxMode, on: bool) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_set_vf_rxmode(self.0, vf, rx_mode.bits, bool_value!(on))
        }; ok => { self })
    }

    /// Enable or disable a VF traffic transmit of the Ethernet device.
    pub fn set_vf_tx(&self, vf: u16, on: bool) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_set_vf_tx(self.0, vf, bool_value!(on))
        }; ok => { self })
    }

    /// Enable or disable a VF traffic receive of an Ethernet device.
    pub fn set_vf_rx(&self, vf: u16, on: bool) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_set_vf_rx(self.0, vf, bool_value!(on))
        }; ok => { self })
    }

    /// Read VLAN Offload configuration from an Ethernet device
    pub fn vlan_offload(&self) -> Result<EthVlanOffloadMode> {
        let mode = unsafe { ffi::rte_eth_dev_get_vlan_offload(self.0) };

        rte_check!(mode; ok => { EthVlanOffloadMode::from_bits_truncate(mode) })
    }

    /// Set VLAN offload configuration on an Ethernet device
    pub fn set_vlan_offload(&self, mode: EthVlanOffloadMode) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_set_vlan_offload(self.0, mode.bits)
        }; ok => { self })
    }
}

pub type RawEthDeviceInfo = ffi::Struct_rte_eth_dev_info;

pub struct EthDeviceInfo(RawEthDeviceInfo);

impl Deref for EthDeviceInfo {
    type Target = RawEthDeviceInfo;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EthDeviceInfo {
    /// Device Driver name.
    pub fn driver_name(&self) -> &str {
        unsafe { CStr::from_ptr(self.0.driver_name).to_str().unwrap() }
    }

    /// Index to bound host interface, or 0 if none.
    /// Use if_indextoname() to translate into an interface name.
    pub fn if_index(&self) -> u32 {
        self.0.if_index
    }

    pub fn pci_dev(&self) -> pci::RawDevicePtr {
        self.0.pci_dev
    }
}

pub type RawEthDeviceStats = ffi::Struct_rte_eth_stats;

pub struct EthDeviceStats(RawEthDeviceStats);

impl Deref for EthDeviceStats {
    type Target = RawEthDeviceStats;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

bitflags! {
    /// Definitions used for VMDQ pool rx mode setting
    pub flags EthVmdqRxMode : u16 {
        /// accept untagged packets.
        const ETH_VMDQ_ACCEPT_UNTAG     = 0x0001,
        /// accept packets in multicast table .
        const ETH_VMDQ_ACCEPT_HASH_MC   = 0x0002,
        /// accept packets in unicast table.
        const ETH_VMDQ_ACCEPT_HASH_UC   = 0x0004,
        /// accept broadcast packets.
        const ETH_VMDQ_ACCEPT_BROADCAST = 0x0008,
        /// multicast promiscuous.
        const ETH_VMDQ_ACCEPT_MULTICAST = 0x0010,
    }
}

/// A set of values to identify what method is to be used to route packets to multiple queues.
bitflags! {
    pub flags EthRxMultiQueueMode: u32 {
        const ETH_MQ_RX_RSS_FLAG    = 0x1,
        const ETH_MQ_RX_DCB_FLAG    = 0x2,
        const ETH_MQ_RX_VMDQ_FLAG   = 0x4,
    }
}

bitflags! {
    /// Definitions used for VLAN Offload functionality
    pub flags EthVlanOffloadMode: i32 {
        /// VLAN Strip  On/Off
        const ETH_VLAN_STRIP_OFFLOAD  = 0x0001,
        /// VLAN Filter On/Off
        const ETH_VLAN_FILTER_OFFLOAD = 0x0002,
        /// VLAN Extend On/Off
        const ETH_VLAN_EXTEND_OFFLOAD = 0x0004,

        /// VLAN Strip  setting mask
        const ETH_VLAN_STRIP_MASK     = 0x0001,
        /// VLAN Filter  setting mask
        const ETH_VLAN_FILTER_MASK    = 0x0002,
        /// VLAN Extend  setting mask
        const ETH_VLAN_EXTEND_MASK    = 0x0004,
        /// VLAN ID is in lower 12 bits
        const ETH_VLAN_ID_MAX         = 0x0FFF,
    }
}

/// A structure used to configure the RX features of an Ethernet port.
pub struct EthRxMode {
    /// The multi-queue packet distribution mode to be used, e.g. RSS.
    pub mq_mode: EthRxMultiQueueMode,
    /// Header Split enable.
    pub split_hdr_size: u16,
    /// IP/UDP/TCP checksum offload enable.
    pub hw_ip_checksum: bool,
    /// VLAN filter enable.
    pub hw_vlan_filter: bool,
    /// VLAN strip enable.
    pub hw_vlan_strip: bool,
    /// Extended VLAN enable.
    pub hw_vlan_extend: bool,
    /// Jumbo Frame Receipt enable.
    pub max_rx_pkt_len: u32,
    /// Enable CRC stripping by hardware.
    pub hw_strip_crc: bool,
    /// Enable scatter packets rx handler
    pub enable_scatter: bool,
    /// Enable LRO
    pub enable_lro: bool,
}

impl Default for EthRxMode {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

/**
 * A set of values to identify what method is to be used to transmit
 * packets using multi-TCs.
 */
pub type EthTxMultiQueueMode = ffi::Enum_rte_eth_tx_mq_mode;

pub struct EthTxMode {
    /// TX multi-queues mode.
    pub mq_mode: EthTxMultiQueueMode,
    /// If set, reject sending out tagged pkts
    pub hw_vlan_reject_tagged: bool,
    /// If set, reject sending out untagged pkts
    pub hw_vlan_reject_untagged: bool,
    /// If set, enable port based VLAN insertion
    pub hw_vlan_insert_pvid: bool,
}

impl Default for EthTxMode {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

/// The RSS offload types are defined based on flow types which are defined
/// in rte_eth_ctrl.h. Different NIC hardwares may support different RSS offload
/// types. The supported flow types or RSS offload types can be queried by
/// rte_eth_dev_info_get().
bitflags! {
    pub flags RssHashFunc: u64 {
        const ETH_RSS_IPV4               = 1 << ::ffi::consts::RTE_ETH_FLOW_IPV4,
        const ETH_RSS_FRAG_IPV4          = 1 << ::ffi::consts::RTE_ETH_FLOW_FRAG_IPV4,
        const ETH_RSS_NONFRAG_IPV4_TCP   = 1 << ::ffi::consts::RTE_ETH_FLOW_NONFRAG_IPV4_TCP,
        const ETH_RSS_NONFRAG_IPV4_UDP   = 1 << ::ffi::consts::RTE_ETH_FLOW_NONFRAG_IPV4_UDP,
        const ETH_RSS_NONFRAG_IPV4_SCTP  = 1 << ::ffi::consts::RTE_ETH_FLOW_NONFRAG_IPV4_SCTP,
        const ETH_RSS_NONFRAG_IPV4_OTHER = 1 << ::ffi::consts::RTE_ETH_FLOW_NONFRAG_IPV4_OTHER,
        const ETH_RSS_IPV6               = 1 << ::ffi::consts::RTE_ETH_FLOW_IPV6,
        const ETH_RSS_FRAG_IPV6          = 1 << ::ffi::consts::RTE_ETH_FLOW_FRAG_IPV6,
        const ETH_RSS_NONFRAG_IPV6_TCP   = 1 << ::ffi::consts::RTE_ETH_FLOW_NONFRAG_IPV6_TCP,
        const ETH_RSS_NONFRAG_IPV6_UDP   = 1 << ::ffi::consts::RTE_ETH_FLOW_NONFRAG_IPV6_UDP,
        const ETH_RSS_NONFRAG_IPV6_SCTP  = 1 << ::ffi::consts::RTE_ETH_FLOW_NONFRAG_IPV6_SCTP,
        const ETH_RSS_NONFRAG_IPV6_OTHER = 1 << ::ffi::consts::RTE_ETH_FLOW_NONFRAG_IPV6_OTHER,
        const ETH_RSS_L2_PAYLOAD         = 1 << ::ffi::consts::RTE_ETH_FLOW_L2_PAYLOAD,
        const ETH_RSS_IPV6_EX            = 1 << ::ffi::consts::RTE_ETH_FLOW_IPV6_EX,
        const ETH_RSS_IPV6_TCP_EX        = 1 << ::ffi::consts::RTE_ETH_FLOW_IPV6_TCP_EX,
        const ETH_RSS_IPV6_UDP_EX        = 1 << ::ffi::consts::RTE_ETH_FLOW_IPV6_UDP_EX,

        const ETH_RSS_IP =
            ETH_RSS_IPV4.bits |
            ETH_RSS_FRAG_IPV4.bits |
            ETH_RSS_NONFRAG_IPV4_OTHER.bits |
            ETH_RSS_IPV6.bits |
            ETH_RSS_FRAG_IPV6.bits |
            ETH_RSS_NONFRAG_IPV6_OTHER.bits |
            ETH_RSS_IPV6_EX.bits,

        const ETH_RSS_UDP =
            ETH_RSS_NONFRAG_IPV4_UDP.bits |
            ETH_RSS_NONFRAG_IPV6_UDP.bits |
            ETH_RSS_IPV6_UDP_EX.bits,

        const ETH_RSS_TCP =
            ETH_RSS_NONFRAG_IPV4_TCP.bits |
            ETH_RSS_NONFRAG_IPV6_TCP.bits |
            ETH_RSS_IPV6_TCP_EX.bits,

        const ETH_RSS_SCTP =
            ETH_RSS_NONFRAG_IPV4_SCTP.bits |
            ETH_RSS_NONFRAG_IPV6_SCTP.bits,

        /**< Mask of valid RSS hash protocols */
        const ETH_RSS_PROTO_MASK =
            ETH_RSS_IPV4.bits |
            ETH_RSS_FRAG_IPV4.bits |
            ETH_RSS_NONFRAG_IPV4_TCP.bits |
            ETH_RSS_NONFRAG_IPV4_UDP.bits |
            ETH_RSS_NONFRAG_IPV4_SCTP.bits |
            ETH_RSS_NONFRAG_IPV4_OTHER.bits |
            ETH_RSS_IPV6.bits |
            ETH_RSS_FRAG_IPV6.bits |
            ETH_RSS_NONFRAG_IPV6_TCP.bits |
            ETH_RSS_NONFRAG_IPV6_UDP.bits |
            ETH_RSS_NONFRAG_IPV6_SCTP.bits |
            ETH_RSS_NONFRAG_IPV6_OTHER.bits |
            ETH_RSS_L2_PAYLOAD.bits |
            ETH_RSS_IPV6_EX.bits |
            ETH_RSS_IPV6_TCP_EX.bits |
            ETH_RSS_IPV6_UDP_EX.bits,
    }
}

pub struct EthRssConf {
    pub key: Option<[u8; 40]>,
    pub hash: RssHashFunc,
}

impl Default for EthRssConf {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

#[derive(Default)]
pub struct RxAdvConf {
    /// Port RSS configuration
    pub rss_conf: Option<EthRssConf>,
    pub vmdq_dcb_conf: Option<ffi::Struct_rte_eth_vmdq_dcb_conf>,
    pub dcb_rx_conf: Option<ffi::Struct_rte_eth_dcb_rx_conf>,
    pub vmdq_rx_conf: Option<ffi::Struct_rte_eth_vmdq_rx_conf>,
}

pub enum TxAdvConf {

}

/// Device supported speeds bitmap flags
bitflags! {
    pub flags LinkSpeed: u32 {
        /**< Autonegotiate (all speeds) */
        const ETH_LINK_SPEED_AUTONEG  = 0 <<  0,
        /**< Disable autoneg (fixed speed) */
        const ETH_LINK_SPEED_FIXED    = 1 <<  0,
        /**<  10 Mbps half-duplex */
        const ETH_LINK_SPEED_10M_HD   = 1 <<  1,
         /**<  10 Mbps full-duplex */
        const ETH_LINK_SPEED_10M      = 1 <<  2,
        /**< 100 Mbps half-duplex */
        const ETH_LINK_SPEED_100M_HD  = 1 <<  3,
        /**< 100 Mbps full-duplex */
        const ETH_LINK_SPEED_100M     = 1 <<  4,
        const ETH_LINK_SPEED_1G       = 1 <<  5,
        const ETH_LINK_SPEED_2_5G     = 1 <<  6,
        const ETH_LINK_SPEED_5G       = 1 <<  7,
        const ETH_LINK_SPEED_10G      = 1 <<  8,
        const ETH_LINK_SPEED_20G      = 1 <<  9,
        const ETH_LINK_SPEED_25G      = 1 << 10,
        const ETH_LINK_SPEED_40G      = 1 << 11,
        const ETH_LINK_SPEED_50G      = 1 << 12,
        const ETH_LINK_SPEED_56G      = 1 << 13,
        const ETH_LINK_SPEED_100G     = 1 << 14,
    }
}

impl Default for LinkSpeed {
    fn default() -> Self {
        ETH_LINK_SPEED_AUTONEG
    }
}

#[derive(Default)]
pub struct EthConf {
    /// bitmap of ETH_LINK_SPEED_XXX of speeds to be used.
    ///
    /// ETH_LINK_SPEED_FIXED disables link autonegotiation, and a unique speed shall be set.
    /// Otherwise, the bitmap defines the set of speeds to be advertised.
    /// If the special value ETH_LINK_SPEED_AUTONEG (0) is used,
    /// all speeds supported are advertised.
    pub link_speeds: LinkSpeed,
    /// Port RX configuration.
    pub rxmode: Option<EthRxMode>,
    /// Port TX configuration.
    pub txmode: Option<EthTxMode>,
    /// Loopback operation mode.
    ///
    /// By default the value is 0, meaning the loopback mode is disabled.
    /// Read the datasheet of given ethernet controller for details.
    /// The possible values of this field are defined in implementation of each driver.
    pub lpbk_mode: u32,
    /// Port RX filtering configuration (union).
    pub rx_adv_conf: Option<RxAdvConf>,
    /// Port TX DCB configuration (union).
    pub tx_adv_conf: Option<TxAdvConf>,
    /// Currently,Priority Flow Control(PFC) are supported,
    /// if DCB with PFC is needed, and the variable must be set ETH_DCB_PFC_SUPPORT.
    pub dcb_capability_en: u32,
    pub fdir_conf: Option<ffi::Struct_rte_fdir_conf>,
    pub intr_conf: Option<ffi::Struct_rte_intr_conf>,
}

pub type RawEthConfPtr = *const ffi::Struct_rte_eth_conf;

pub struct RawEthConf(RawEthConfPtr);

impl RawEthConf {
    fn as_raw(&self) -> RawEthConfPtr {
        self.0
    }
}

impl Drop for RawEthConf {
    fn drop(&mut self) {
        unsafe { _rte_eth_conf_free(self.0) }
    }
}

impl<'a> From<&'a EthConf> for RawEthConf {
    fn from(c: &EthConf) -> Self {
        unsafe {
            let conf = _rte_eth_conf_new();

            if let Some(ref rxmode) = c.rxmode {
                _rte_eth_conf_set_rx_mode(conf,
                                          rxmode.mq_mode.bits,
                                          rxmode.split_hdr_size,
                                          rxmode.hw_ip_checksum as u8,
                                          rxmode.hw_vlan_filter as u8,
                                          rxmode.hw_vlan_strip as u8,
                                          rxmode.hw_vlan_extend as u8,
                                          rxmode.max_rx_pkt_len,
                                          rxmode.hw_strip_crc as u8,
                                          rxmode.enable_scatter as u8,
                                          rxmode.enable_lro as u8);
            }

            if let Some(ref txmode) = c.txmode {
                _rte_eth_conf_set_tx_mode(conf,
                                          txmode.mq_mode as u32,
                                          txmode.hw_vlan_reject_tagged as u8,
                                          txmode.hw_vlan_reject_untagged as u8,
                                          txmode.hw_vlan_insert_pvid as u8);
            }

            if let Some(ref adv_conf) = c.rx_adv_conf {
                if let Some(ref rss_conf) = adv_conf.rss_conf {
                    let (rss_key, rss_key_len) = rss_conf.key
                        .map_or_else(|| (ptr::null(), 0), |key| (key.as_ptr(), key.len() as u8));

                    _rte_eth_conf_set_rss_conf(conf, rss_key, rss_key_len, rss_conf.hash.bits);
                }
            }

            RawEthConf(conf)
        }
    }
}

pub type RawTxBuffer = ffi::Struct_rte_eth_dev_tx_buffer;
pub type RawTxBufferPtr = *mut ffi::Struct_rte_eth_dev_tx_buffer;

pub type TxBufferErrorCallback<T> = fn(unsent: *mut *mut ffi::Struct_rte_mbuf,
                                       count: u16,
                                       userdata: &T);

pub trait TxBuffer {
    fn free(&mut self);

    /// Configure a callback for buffered packets which cannot be sent
    fn set_err_callback<T>(&mut self,
                           callback: Option<TxBufferErrorCallback<T>>,
                           userdata: Option<&T>)
                           -> Result<&mut Self>;

    /// Silently dropping unsent buffered packets.
    fn drop_err_packets(&mut self) -> Result<&mut Self>;

    /// Tracking unsent buffered packets.
    fn count_err_packets(&mut self) -> Result<&mut Self>;
}

/// Initialize default values for buffered transmitting
pub fn alloc_buffer(size: usize, socket_id: i32) -> Result<RawTxBufferPtr> {
    unsafe {
        let p = malloc::zmalloc_socket("tx_buffer",
                                       _rte_eth_tx_buffer_size(size),
                                       0,
                                       socket_id) as RawTxBufferPtr;

        if p.is_null() {
            Err(Error::OsError(libc::ENOMEM))
        } else {
            let ret = ffi::rte_eth_tx_buffer_init(p, size as u16);

            if ret != 0 {
                Err(Error::OsError(ret))
            } else {
                Ok(p)
            }
        }
    }
}

impl TxBuffer for RawTxBuffer {
    fn free(&mut self) {
        malloc::free(self as RawTxBufferPtr as *mut c_void);
    }

    fn set_err_callback<T>(&mut self,
                           callback: Option<TxBufferErrorCallback<T>>,
                           userdata: Option<&T>)
                           -> Result<&mut Self> {
        rte_check!(unsafe {
            ffi::rte_eth_tx_buffer_set_err_callback(self,
                                                    mem::transmute(callback),
                                                    mem::transmute(userdata))
        }; ok => { self })
    }

    fn drop_err_packets(&mut self) -> Result<&mut Self> {
        rte_check!(unsafe {
            ffi::rte_eth_tx_buffer_set_err_callback(self,
                                                    Some(ffi::rte_eth_tx_buffer_drop_callback),
                                                    ptr::null_mut())
        }; ok => { self })
    }

    fn count_err_packets(&mut self) -> Result<&mut Self> {
        rte_check!(unsafe {
            ffi::rte_eth_tx_buffer_set_err_callback(self,
                                                    Some(ffi::rte_eth_tx_buffer_count_callback),
                                                    ptr::null_mut())
        }; ok => { self })
    }
}

extern "C" {
    fn _rte_eth_rx_burst(port_id: libc::uint8_t,
                         queue_id: libc::uint16_t,
                         rx_pkts: *mut mbuf::RawMbufPtr,
                         nb_pkts: libc::uint16_t)
                         -> libc::uint16_t;

    fn _rte_eth_tx_burst(port_id: libc::uint8_t,
                         queue_id: libc::uint16_t,
                         tx_pkts: *mut mbuf::RawMbufPtr,
                         nb_pkts: libc::uint16_t)
                         -> libc::uint16_t;

    fn _rte_eth_conf_new() -> RawEthConfPtr;

    fn _rte_eth_conf_free(conf: RawEthConfPtr);

    fn _rte_eth_conf_set_rx_mode(conf: RawEthConfPtr,
                                 mq_mode: libc::uint32_t,
                                 split_hdr_size: libc::uint16_t,
                                 hw_ip_checksum: libc::uint8_t,
                                 hw_vlan_filter: libc::uint8_t,
                                 hw_vlan_strip: libc::uint8_t,
                                 hw_vlan_extend: libc::uint8_t,
                                 max_rx_pkt_len: libc::uint32_t,
                                 hw_strip_crc: libc::uint8_t,
                                 enable_scatter: libc::uint8_t,
                                 enable_lro: libc::uint8_t);

    fn _rte_eth_conf_set_tx_mode(conf: RawEthConfPtr,
                                 mq_mode: libc::uint32_t,
                                 hw_vlan_reject_tagged: libc::uint8_t,
                                 hw_vlan_reject_untagged: libc::uint8_t,
                                 hw_vlan_insert_pvid: libc::uint8_t);

    fn _rte_eth_conf_set_rss_conf(conf: RawEthConfPtr,
                                  rss_key: *const libc::uint8_t,
                                  rss_key_len: libc::uint8_t,
                                  rss_hf: libc::uint64_t);

    fn _rte_eth_tx_buffer_size(size: libc::size_t) -> libc::size_t;
}
