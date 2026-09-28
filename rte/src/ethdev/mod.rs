//! Ethernet device API.
//!
//! `rte_ethdev`, `rte_flow`, `rte_mtr` and `rte_tm` live in the same
//! `librte_ethdev` compilation unit (see `lib/librte_ethdev/meson.build`), so
//! the corresponding wrappers are grouped here as submodules:
//!
//! * [`flow`]: generic flow API (`rte_flow`);
//! * [`info`]: device information and statistics;
//! * [`conf`]: device configuration;
//! * [`rss`]: RSS offload configuration;
//! * [`buffer`]: buffered TX helper.

use std::mem;
use std::ops::Range;
use std::ptr;

use anyhow::Result;

use crate::ether;
use crate::ffi;
use crate::mbuf;
use crate::memory::SocketId;
use crate::mempool;
use crate::utils::AsRaw;
use crate::{bool_value, rte_check};

mod buffer;
mod conf;
mod info;
mod rss;

pub mod flow;

pub use buffer::*;
pub use conf::*;
pub use info::*;
pub use rss::*;

pub type PortId = u16;
pub type QueueId = u16;

/// A structure used to retrieve link-level information of an Ethernet port.
pub struct EthLink {
    pub speed: u32,
    pub duplex: bool,
    pub autoneg: bool,
    pub up: bool,
}

pub trait EthDevice {
    fn portid(&self) -> PortId;

    /// Configure an Ethernet device.
    ///
    /// This function must be invoked first before any other function in the Ethernet API.
    /// This function can also be re-invoked when a device is in the stopped state.
    ///
    fn configure(&self, nb_rx_queue: QueueId, nb_tx_queue: QueueId, conf: &EthConf) -> Result<&Self>;

    /// Retrieve the contextual information of an Ethernet device.
    fn info(&self) -> RawEthDeviceInfo;

    /// Retrieve the general I/O statistics of an Ethernet device.
    fn stats(&self) -> Result<RawEthDeviceStats>;

    /// Reset the general I/O statistics of an Ethernet device.
    fn reset_stats(&self) -> &Self;

    /// Retrieve the Ethernet address of an Ethernet device.
    fn mac_addr(&self) -> ether::EtherAddr;

    /// Set the default MAC address.
    fn set_mac_addr(&self, addr: &[u8; ether::ETHER_ADDR_LEN]) -> Result<&Self>;

    /// Return the NUMA socket to which an Ethernet device is connected
    fn socket_id(&self) -> SocketId;

    /// Check if port_id of device is attached
    fn is_valid(&self) -> bool;

    /// Allocate and set up a receive queue for an Ethernet device.
    ///
    /// The function allocates a contiguous block of memory for *nb_rx_desc*
    /// receive descriptors from a memory zone associated with *socket_id*
    /// and initializes each receive descriptor with a network buffer allocated
    /// from the memory pool *mb_pool*.
    fn rx_queue_setup(
        &self,
        rx_queue_id: QueueId,
        nb_rx_desc: u16,
        rx_conf: Option<ffi::rte_eth_rxconf>,
        mb_pool: &mut mempool::MemoryPool,
    ) -> Result<&Self>;

    /// Allocate and set up a transmit queue for an Ethernet device.
    fn tx_queue_setup(
        &self,
        tx_queue_id: QueueId,
        nb_tx_desc: u16,
        tx_conf: Option<ffi::rte_eth_txconf>,
    ) -> Result<&Self>;

    /// Enable receipt in promiscuous mode for an Ethernet device.
    fn promiscuous_enable(&self) -> &Self;

    /// Disable receipt in promiscuous mode for an Ethernet device.
    fn promiscuous_disable(&self) -> &Self;

    /// Return the value of promiscuous mode for an Ethernet device.
    fn is_promiscuous_enabled(&self) -> Result<bool>;

    /// Retrieve the MTU of an Ethernet device.
    fn mtu(&self) -> Result<u16>;

    /// Change the MTU of an Ethernet device.
    fn set_mtu(&self, mtu: u16) -> Result<&Self>;

    /// Enable/Disable hardware filtering by an Ethernet device
    /// of received VLAN packets tagged with a given VLAN Tag Identifier.
    fn set_vlan_filter(&self, vlan_id: u16, on: bool) -> Result<&Self>;

    /// Retrieve the Ethernet device link status
    #[inline]
    fn is_up(&self) -> bool {
        self.link().up
    }

    /// Retrieve the status (ON/OFF), the speed (in Mbps) and
    /// the mode (HALF-DUPLEX or FULL-DUPLEX) of the physical link of an Ethernet device.
    ///
    /// It might need to wait up to 9 seconds in it.
    ///
    fn link(&self) -> EthLink;

    /// Retrieve the status (ON/OFF), the speed (in Mbps) and
    /// the mode (HALF-DUPLEX or FULL-DUPLEX) of the physical link of an Ethernet device.
    ///
    /// It is a no-wait version of rte_eth_link_get().
    ///
    fn link_nowait(&self) -> EthLink;

    /// Link up an Ethernet device.
    fn set_link_up(&self) -> Result<&Self>;

    /// Link down an Ethernet device.
    fn set_link_down(&self) -> Result<&Self>;

    /// Allocate mbuf from mempool, setup the DMA physical address
    /// and then start RX for specified queue of a port. It is used
    /// when rx_deferred_start flag of the specified queue is true.
    fn rx_queue_start(&self, rx_queue_id: QueueId) -> Result<&Self>;

    /// Stop specified RX queue of a port
    fn rx_queue_stop(&self, rx_queue_id: QueueId) -> Result<&Self>;

    /// Start TX for specified queue of a port.
    /// It is used when tx_deferred_start flag of the specified queue is true.
    fn tx_queue_start(&self, tx_queue_id: QueueId) -> Result<&Self>;

    /// Stop specified TX queue of a port
    fn tx_queue_stop(&self, tx_queue_id: QueueId) -> Result<&Self>;

    /// Start an Ethernet device.
    fn start(&self) -> Result<&Self>;

    /// Stop an Ethernet device.
    fn stop(&self) -> &Self;

    /// Close a stopped Ethernet device. The device cannot be restarted!
    fn close(&self) -> &Self;

    /// Retrieve a burst of input packets from a receive queue of an Ethernet device.
    fn rx_burst(&self, queue_id: QueueId, rx_pkts: &mut [Option<mbuf::MBuf>]) -> usize;

    /// Send a burst of output packets on a transmit queue of an Ethernet device.
    fn tx_burst<T: AsRaw<Raw = mbuf::RawMBuf>>(&self, queue_id: QueueId, rx_pkts: &mut [T]) -> usize;

    /// Read VLAN Offload configuration from an Ethernet device
    fn vlan_offload(&self) -> Result<EthVlanOffloadMode>;

    /// Set VLAN offload configuration on an Ethernet device
    fn set_vlan_offload(&self, mode: EthVlanOffloadMode) -> Result<&Self>;

    /// Check whether a flow rule can be created on this port.
    ///
    /// See [`flow`] for the rule builder and DPDK `rte_flow_validate()` for the
    /// exact validation semantics.
    fn flow_validate(&self, rule: &flow::FlowRule) -> Result<()>;

    /// Create a flow rule on this port, returning an RAII handle that destroys
    /// the rule when dropped.
    fn flow_create(&self, rule: &flow::FlowRule) -> Result<flow::PortFlow>;

    /// Destroy all flow rules associated with this port.
    fn flow_flush(&self) -> Result<()>;

    /// Restrict ingress traffic to the defined flow rules.
    ///
    /// Once effective, leaving isolated mode may not be possible depending on
    /// the PMD. Toggling it should happen as early as possible, ideally before
    /// [`EthDevice::configure`].
    fn flow_isolate(&self, set: bool) -> Result<()>;

    /// Dump the hardware internal representation of the flow rules of this port.
    fn flow_dev_dump(&self, file: *mut ffi::FILE) -> Result<()>;
}

/// Get the total number of Ethernet devices that have been successfully initialized
/// by the matching Ethernet driver during the PCI probing phase.
///
/// All devices whose port identifier is in the range [0, rte::ethdev::count() - 1]
/// can be operated on by network applications immediately after invoking rte_eal_init().
/// If the application unplugs a port using hotplug function,
/// The enabled port numbers may be noncontiguous.
/// In the case, the applications need to manage enabled port by themselves.
pub fn count() -> u16 {
    unsafe { ffi::rte_eth_dev_count_avail() }
}

pub fn devices() -> Range<PortId> {
    0..count()
}

impl EthDevice for PortId {
    fn portid(&self) -> PortId {
        *self
    }

    fn configure(&self, nb_rx_queue: QueueId, nb_tx_queue: QueueId, conf: &EthConf) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_configure(*self,
                                       nb_rx_queue,
                                       nb_tx_queue,
                                       RawEthConf::from(conf).as_raw())
        }; ok => { self })
    }

    fn info(&self) -> RawEthDeviceInfo {
        let mut info: RawEthDeviceInfo = Default::default();

        unsafe {
            ffi::rte_eth_dev_info_get(*self, &mut info);
        }

        info
    }

    fn stats(&self) -> Result<RawEthDeviceStats> {
        let mut stats: RawEthDeviceStats = Default::default();

        rte_check!(unsafe {
            ffi::rte_eth_stats_get(*self, &mut stats)
        }; ok => { stats })
    }

    fn reset_stats(&self) -> &Self {
        unsafe { ffi::rte_eth_stats_reset(*self) };

        self
    }

    fn mac_addr(&self) -> ether::EtherAddr {
        unsafe {
            let mut addr: ffi::rte_ether_addr = mem::zeroed();

            ffi::rte_eth_macaddr_get(*self, &mut addr);

            ether::EtherAddr::from(addr.addr_bytes)
        }
    }

    fn set_mac_addr(&self, addr: &[u8; ether::ETHER_ADDR_LEN]) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_default_mac_addr_set(*self, addr.as_ptr() as * mut _)
        }; ok => { self })
    }

    fn socket_id(&self) -> SocketId {
        unsafe { ffi::rte_eth_dev_socket_id(*self) }
    }

    fn is_valid(&self) -> bool {
        unsafe { ffi::rte_eth_dev_is_valid_port(*self) != 0 }
    }

    fn rx_queue_setup(
        &self,
        rx_queue_id: QueueId,
        nb_rx_desc: u16,
        rx_conf: Option<ffi::rte_eth_rxconf>,
        mb_pool: &mut mempool::MemoryPool,
    ) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_rx_queue_setup(*self,
                                        rx_queue_id,
                                        nb_rx_desc,
                                        self.socket_id() as u32,
                                        rx_conf.as_ref().map(|conf| conf as *const _).unwrap_or(ptr::null()),
                                        mb_pool.as_raw_mut())
        }; ok => { self })
    }

    fn tx_queue_setup(
        &self,
        tx_queue_id: QueueId,
        nb_tx_desc: u16,
        tx_conf: Option<ffi::rte_eth_txconf>,
    ) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_tx_queue_setup(*self,
                                        tx_queue_id,
                                        nb_tx_desc,
                                        self.socket_id() as u32,
                                        tx_conf.as_ref().map(|conf| conf as *const _).unwrap_or(ptr::null()))
        }; ok => { self })
    }

    fn promiscuous_enable(&self) -> &Self {
        unsafe { ffi::rte_eth_promiscuous_enable(*self) };

        self
    }

    fn promiscuous_disable(&self) -> &Self {
        unsafe { ffi::rte_eth_promiscuous_disable(*self) };

        self
    }

    fn is_promiscuous_enabled(&self) -> Result<bool> {
        let ret = unsafe { ffi::rte_eth_promiscuous_get(*self) };

        rte_check!(ret; ok => { ret != 0 })
    }

    fn mtu(&self) -> Result<u16> {
        let mut mtu: u16 = 0;

        rte_check!(unsafe { ffi::rte_eth_dev_get_mtu(*self, &mut mtu)}; ok => { mtu })
    }

    fn set_mtu(&self, mtu: u16) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_set_mtu(*self, mtu) }; ok => { self })
    }

    fn set_vlan_filter(&self, vlan_id: u16, on: bool) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_vlan_filter(*self, vlan_id, bool_value!(on) as i32)
        }; ok => { self })
    }

    fn link(&self) -> EthLink {
        let mut link = rte_sys::rte_eth_link::default();

        unsafe {
            ffi::rte_eth_link_get(*self, &mut link as *mut _);

            EthLink {
                speed: link.link_speed,
                duplex: link.link_duplex() != 0,
                autoneg: link.link_autoneg() != 0,
                up: link.link_status() != 0,
            }
        }
    }

    fn link_nowait(&self) -> EthLink {
        let mut link = rte_sys::rte_eth_link::default();

        unsafe {
            ffi::rte_eth_link_get_nowait(*self, &mut link as *mut _);

            EthLink {
                speed: link.link_speed,
                duplex: link.link_duplex() != 0,
                autoneg: link.link_autoneg() != 0,
                up: link.link_status() != 0,
            }
        }
    }

    fn set_link_up(&self) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_set_link_up(*self) }; ok => { self })
    }

    fn set_link_down(&self) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_set_link_down(*self) }; ok => { self })
    }

    fn rx_queue_start(&self, rx_queue_id: QueueId) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_rx_queue_start(*self, rx_queue_id) }; ok => { self })
    }

    fn rx_queue_stop(&self, rx_queue_id: QueueId) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_rx_queue_stop(*self, rx_queue_id) }; ok => { self })
    }

    fn tx_queue_start(&self, tx_queue_id: QueueId) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_tx_queue_start(*self, tx_queue_id) }; ok => { self })
    }

    fn tx_queue_stop(&self, tx_queue_id: QueueId) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_tx_queue_stop(*self, tx_queue_id) }; ok => { self })
    }

    fn start(&self) -> Result<&Self> {
        rte_check!(unsafe { ffi::rte_eth_dev_start(*self) }; ok => { self })
    }

    fn stop(&self) -> &Self {
        unsafe { ffi::rte_eth_dev_stop(*self) };

        self
    }

    fn close(&self) -> &Self {
        unsafe { ffi::rte_eth_dev_close(*self) };

        self
    }

    fn rx_burst(&self, queue_id: QueueId, rx_pkts: &mut [Option<mbuf::MBuf>]) -> usize {
        unsafe {
            ffi::_rte_eth_rx_burst(*self, queue_id, rx_pkts.as_mut_ptr() as *mut _, rx_pkts.len() as u16) as usize
        }
    }

    fn tx_burst<T: AsRaw<Raw = mbuf::RawMBuf>>(&self, queue_id: QueueId, rx_pkts: &mut [T]) -> usize {
        unsafe {
            if rx_pkts.is_empty() {
                ffi::_rte_eth_tx_burst(*self, queue_id, ptr::null_mut(), 0) as usize
            } else {
                ffi::_rte_eth_tx_burst(*self, queue_id, rx_pkts.as_mut_ptr() as *mut _, rx_pkts.len() as u16) as usize
            }
        }
    }

    fn vlan_offload(&self) -> Result<EthVlanOffloadMode> {
        let mode = unsafe { ffi::rte_eth_dev_get_vlan_offload(*self) };

        rte_check!(mode; ok => { EthVlanOffloadMode::from_bits_truncate(mode) })
    }

    fn set_vlan_offload(&self, mode: EthVlanOffloadMode) -> Result<&Self> {
        rte_check!(unsafe {
            ffi::rte_eth_dev_set_vlan_offload(*self, mode.bits())
        }; ok => { self })
    }

    fn flow_validate(&self, rule: &flow::FlowRule) -> Result<()> {
        flow::validate(*self, rule)
    }

    fn flow_create(&self, rule: &flow::FlowRule) -> Result<flow::PortFlow> {
        flow::PortFlow::create(*self, rule)
    }

    fn flow_flush(&self) -> Result<()> {
        flow::flush(*self)
    }

    fn flow_isolate(&self, set: bool) -> Result<()> {
        flow::isolate(*self, set)
    }

    fn flow_dev_dump(&self, file: *mut ffi::FILE) -> Result<()> {
        flow::dev_dump(*self, file)
    }
}
