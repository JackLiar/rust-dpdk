//! Ethernet device configuration definitions.

use std::ptr;

use crate::ffi;

use super::rss::EthRssConf;

bitflags! {
    /// Definitions used for VMDQ pool rx mode setting
    pub struct EthVmdqRxMode : u16 {
        /// accept untagged packets.
        const ETH_VMDQ_ACCEPT_UNTAG     = 0x0001;
        /// accept packets in multicast table .
        const ETH_VMDQ_ACCEPT_HASH_MC   = 0x0002;
        /// accept packets in unicast table.
        const ETH_VMDQ_ACCEPT_HASH_UC   = 0x0004;
        /// accept broadcast packets.
        const ETH_VMDQ_ACCEPT_BROADCAST = 0x0008;
        /// multicast promiscuous.
        const ETH_VMDQ_ACCEPT_MULTICAST = 0x0010;
    }
}

/// A set of values to identify what method is to be used to route packets to multiple queues.
pub type EthRxMultiQueueMode = ffi::rte_eth_rx_mq_mode::Type;

bitflags! {
    /// Definitions used for VLAN Offload functionality
    pub struct EthVlanOffloadMode: i32 {
        /// VLAN Strip  On/Off
        const ETH_VLAN_STRIP_OFFLOAD  = 0x0001;
        /// VLAN Filter On/Off
        const ETH_VLAN_FILTER_OFFLOAD = 0x0002;
        /// VLAN Extend On/Off
        const ETH_VLAN_EXTEND_OFFLOAD = 0x0004;

        /// VLAN Strip  setting mask
        const ETH_VLAN_STRIP_MASK     = 0x0001;
        /// VLAN Filter  setting mask
        const ETH_VLAN_FILTER_MASK    = 0x0002;
        /// VLAN Extend  setting mask
        const ETH_VLAN_EXTEND_MASK    = 0x0004;
        /// VLAN ID is in lower 12 bits
        const ETH_VLAN_ID_MAX         = 0x0FFF;
    }
}

/**
 * A set of values to identify what method is to be used to transmit
 * packets using multi-TCs.
 */
pub type EthTxMultiQueueMode = ffi::rte_eth_tx_mq_mode::Type;

#[derive(Default)]
pub struct RxAdvConf {
    /// Port RSS configuration
    pub rss_conf: Option<EthRssConf>,
    pub vmdq_dcb_conf: Option<ffi::rte_eth_vmdq_dcb_conf>,
    pub dcb_rx_conf: Option<ffi::rte_eth_dcb_rx_conf>,
    pub vmdq_rx_conf: Option<ffi::rte_eth_vmdq_rx_conf>,
}

pub enum TxAdvConf {}

/// Device supported speeds bitmap flags
bitflags! {
    pub struct LinkSpeed: u32 {
        /**< Autonegotiate (all speeds) */
        const ETH_LINK_SPEED_AUTONEG  = 0 <<  0;
        /**< Disable autoneg (fixed speed) */
        const ETH_LINK_SPEED_FIXED    = 1 <<  0;
        /**<  10 Mbps half-duplex */
        const ETH_LINK_SPEED_10M_HD   = 1 <<  1;
         /**<  10 Mbps full-duplex */
        const ETH_LINK_SPEED_10M      = 1 <<  2;
        /**< 100 Mbps half-duplex */
        const ETH_LINK_SPEED_100M_HD  = 1 <<  3;
        /**< 100 Mbps full-duplex */
        const ETH_LINK_SPEED_100M     = 1 <<  4;
        const ETH_LINK_SPEED_1G       = 1 <<  5;
        const ETH_LINK_SPEED_2_5G     = 1 <<  6;
        const ETH_LINK_SPEED_5G       = 1 <<  7;
        const ETH_LINK_SPEED_10G      = 1 <<  8;
        const ETH_LINK_SPEED_20G      = 1 <<  9;
        const ETH_LINK_SPEED_25G      = 1 << 10;
        const ETH_LINK_SPEED_40G      = 1 << 11;
        const ETH_LINK_SPEED_50G      = 1 << 12;
        const ETH_LINK_SPEED_56G      = 1 << 13;
        const ETH_LINK_SPEED_100G     = 1 << 14;
    }
}

impl Default for LinkSpeed {
    fn default() -> Self {
        LinkSpeed::ETH_LINK_SPEED_AUTONEG
    }
}

pub type EthRxMode = ffi::rte_eth_rxmode;
pub type EthTxMode = ffi::rte_eth_txmode;

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
    // pub fdir_conf: Option<ffi::rte_fdir_conf>,
    // pub intr_conf: Option<ffi::rte_intr_conf>,
}

pub type RawEthConfPtr = *const ffi::rte_eth_conf;

pub struct RawEthConf(ffi::rte_eth_conf);

impl RawEthConf {
    pub(crate) fn as_raw(&self) -> RawEthConfPtr {
        &self.0
    }
}

impl From<&EthConf> for RawEthConf {
    fn from(c: &EthConf) -> Self {
        let mut conf: ffi::rte_eth_conf = Default::default();

        if let Some(ref rxmode) = c.rxmode {
            conf.rxmode = *rxmode
        }

        if let Some(ref txmode) = c.txmode {
            conf.txmode = *txmode
        }

        if let Some(ref adv_conf) = c.rx_adv_conf {
            if let Some(ref rss_conf) = adv_conf.rss_conf {
                let (rss_key, rss_key_len) = rss_conf
                    .key
                    .map_or_else(|| (ptr::null(), 0), |key| (key.as_ptr(), key.len() as u8));

                conf.rx_adv_conf.rss_conf.rss_key = rss_key as *mut _;
                conf.rx_adv_conf.rss_conf.rss_key_len = rss_key_len;
                conf.rx_adv_conf.rss_conf.rss_hf = rss_conf.hash.bits();
            }
        }

        RawEthConf(conf)
    }
}
