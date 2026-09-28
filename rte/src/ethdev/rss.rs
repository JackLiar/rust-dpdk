//! RSS (Receive Side Scaling) related definitions.
//!
//! The RSS offload types are defined based on flow types which are defined
//! in `rte_eth_ctrl.h`. Different NIC hardwares may support different RSS offload
//! types. The supported flow types or RSS offload types can be queried by
//! `rte_eth_dev_info_get()`.

use std::mem;

use crate::ffi;

/// The RSS offload types are defined based on flow types which are defined
/// in rte_eth_ctrl.h. Different NIC hardwares may support different RSS offload
/// types. The supported flow types or RSS offload types can be queried by
/// rte_eth_dev_info_get().
bitflags! {
    pub struct RssHashFunc: u64 {
        const ETH_RSS_UNKNOWN            = 0;
        const ETH_RSS_IPV4               = 1 << ffi::RTE_ETH_FLOW_IPV4;
        const ETH_RSS_FRAG_IPV4          = 1 << ffi::RTE_ETH_FLOW_FRAG_IPV4;
        const ETH_RSS_NONFRAG_IPV4_TCP   = 1 << ffi::RTE_ETH_FLOW_NONFRAG_IPV4_TCP;
        const ETH_RSS_NONFRAG_IPV4_UDP   = 1 << ffi::RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
        const ETH_RSS_NONFRAG_IPV4_SCTP  = 1 << ffi::RTE_ETH_FLOW_NONFRAG_IPV4_SCTP;
        const ETH_RSS_NONFRAG_IPV4_OTHER = 1 << ffi::RTE_ETH_FLOW_NONFRAG_IPV4_OTHER;
        const ETH_RSS_IPV6               = 1 << ffi::RTE_ETH_FLOW_IPV6;
        const ETH_RSS_FRAG_IPV6          = 1 << ffi::RTE_ETH_FLOW_FRAG_IPV6;
        const ETH_RSS_NONFRAG_IPV6_TCP   = 1 << ffi::RTE_ETH_FLOW_NONFRAG_IPV6_TCP;
        const ETH_RSS_NONFRAG_IPV6_UDP   = 1 << ffi::RTE_ETH_FLOW_NONFRAG_IPV6_UDP;
        const ETH_RSS_NONFRAG_IPV6_SCTP  = 1 << ffi::RTE_ETH_FLOW_NONFRAG_IPV6_SCTP;
        const ETH_RSS_NONFRAG_IPV6_OTHER = 1 << ffi::RTE_ETH_FLOW_NONFRAG_IPV6_OTHER;
        const ETH_RSS_L2_PAYLOAD         = 1 << ffi::RTE_ETH_FLOW_L2_PAYLOAD;
        const ETH_RSS_IPV6_EX            = 1 << ffi::RTE_ETH_FLOW_IPV6_EX;
        const ETH_RSS_IPV6_TCP_EX        = 1 << ffi::RTE_ETH_FLOW_IPV6_TCP_EX;
        const ETH_RSS_IPV6_UDP_EX        = 1 << ffi::RTE_ETH_FLOW_IPV6_UDP_EX;
        const ETH_RSS_PORT               = 1 << ffi::RTE_ETH_FLOW_PORT;
        const ETH_RSS_VXLAN              = 1 << ffi::RTE_ETH_FLOW_VXLAN;
        const ETH_RSS_GENEVE             = 1 << ffi::RTE_ETH_FLOW_GENEVE;
        const ETH_RSS_NVGRE              = 1 << ffi::RTE_ETH_FLOW_NVGRE;
        const ETH_RSS_GTPU               = 1 << ffi::RTE_ETH_FLOW_GTPU;
        const ETH_RSS_ETH                = 1 << ffi::RTE_ETH_FLOW_MAX;
        const ETH_RSS_S_VLAN             = 1 << 25;
        const ETH_RSS_C_VLAN             = 1 << 26;
        const ETH_RSS_ESP                = 1 << 27;
        const ETH_RSS_AH                 = 1 << 28;
        const ETH_RSS_L2TPV3             = 1 << 29;
        const ETH_RSS_PFCP               = 1 << 30;
        const ETH_RSS_PPPOE              = 1 << 31;
        const ETH_RSS_ECPRI              = 1 << 32;

        const ETH_RSS_L3_SRC_ONLY        = 1 << 63;
        const ETH_RSS_L3_DST_ONLY        = 1 << 62;
        const ETH_RSS_L4_SRC_ONLY        = 1 << 61;
        const ETH_RSS_L4_DST_ONLY        = 1 << 60;
        const ETH_RSS_L2_SRC_ONLY        = 1 << 59;
        const ETH_RSS_L2_DST_ONLY        = 1 << 58;

        const RTE_ETH_RSS_L3_PRE32       = 1 << 57;
        const RTE_ETH_RSS_L3_PRE40       = 1 << 56;
        const RTE_ETH_RSS_L3_PRE48       = 1 << 55;
        const RTE_ETH_RSS_L3_PRE56       = 1 << 54;
        const RTE_ETH_RSS_L3_PRE64       = 1 << 53;
        const RTE_ETH_RSS_L3_PRE96       = 1 << 52;

        const ETH_RSS_LEVEL_PMD_DEFAULT  = 0 << 50;

        const ETH_RSS_LEVEL_OUTERMOST    = 1 << 50;

        const ETH_RSS_LEVEL_INNERMOST    = 2 << 50;
        const ETH_RSS_LEVEL_MASK         = 3 << 50;

        const ETH_RSS_IPV6_PRE32 =
            Self::ETH_RSS_IPV6.bits() |
            Self::RTE_ETH_RSS_L3_PRE32.bits();

        const ETH_RSS_IPV6_PRE40 =
            Self::ETH_RSS_IPV6.bits() |
            Self::RTE_ETH_RSS_L3_PRE40.bits();

        const ETH_RSS_IPV6_PRE48 =
            Self::ETH_RSS_IPV6.bits() |
            Self::RTE_ETH_RSS_L3_PRE48.bits();

        const ETH_RSS_IPV6_PRE56 =
            Self::ETH_RSS_IPV6.bits() |
            Self::RTE_ETH_RSS_L3_PRE56.bits();

        const ETH_RSS_IPV6_PRE64 =
            Self::ETH_RSS_IPV6.bits() |
            Self::RTE_ETH_RSS_L3_PRE64.bits();

        const ETH_RSS_IPV6_PRE96 =
            Self::ETH_RSS_IPV6.bits() |
            Self::RTE_ETH_RSS_L3_PRE96.bits();

        const ETH_RSS_IPV6_PRE32_UDP =
            Self::ETH_RSS_NONFRAG_IPV6_UDP.bits() |
            Self::RTE_ETH_RSS_L3_PRE32.bits();

        const ETH_RSS_IPV6_PRE40_UDP =
            Self::ETH_RSS_NONFRAG_IPV6_UDP.bits() |
            Self::RTE_ETH_RSS_L3_PRE40.bits();

        const ETH_RSS_IPV6_PRE48_UDP =
            Self::ETH_RSS_NONFRAG_IPV6_UDP.bits() |
            Self::RTE_ETH_RSS_L3_PRE48.bits();

        const ETH_RSS_IPV6_PRE56_UDP =
            Self::ETH_RSS_NONFRAG_IPV6_UDP.bits() |
            Self::RTE_ETH_RSS_L3_PRE56.bits();

        const ETH_RSS_IPV6_PRE64_UDP =
            Self::ETH_RSS_NONFRAG_IPV6_UDP.bits() |
            Self::RTE_ETH_RSS_L3_PRE64.bits();

        const ETH_RSS_IPV6_PRE96_UDP =
            Self::ETH_RSS_NONFRAG_IPV6_UDP.bits() |
            Self::RTE_ETH_RSS_L3_PRE96.bits();

        const ETH_RSS_IPV6_PRE32_TCP =
            Self::ETH_RSS_NONFRAG_IPV6_TCP.bits() |
            Self::RTE_ETH_RSS_L3_PRE32.bits();

        const ETH_RSS_IPV6_PRE40_TCP =
            Self::ETH_RSS_NONFRAG_IPV6_TCP.bits() |
            Self::RTE_ETH_RSS_L3_PRE40.bits();

        const ETH_RSS_IPV6_PRE48_TCP =
            Self::ETH_RSS_NONFRAG_IPV6_TCP.bits() |
            Self::RTE_ETH_RSS_L3_PRE48.bits();

        const ETH_RSS_IPV6_PRE56_TCP =
            Self::ETH_RSS_NONFRAG_IPV6_TCP.bits() |
            Self::RTE_ETH_RSS_L3_PRE56.bits();

        const ETH_RSS_IPV6_PRE64_TCP =
            Self::ETH_RSS_NONFRAG_IPV6_TCP.bits() |
            Self::RTE_ETH_RSS_L3_PRE64.bits();

        const ETH_RSS_IPV6_PRE96_TCP =
            Self::ETH_RSS_NONFRAG_IPV6_TCP.bits() |
            Self::RTE_ETH_RSS_L3_PRE96.bits();

        const ETH_RSS_IPV6_PRE32_SCTP =
            Self::ETH_RSS_NONFRAG_IPV6_SCTP.bits() |
            Self::RTE_ETH_RSS_L3_PRE32.bits();

        const ETH_RSS_IPV6_PRE40_SCTP =
            Self::ETH_RSS_NONFRAG_IPV6_SCTP.bits() |
            Self::RTE_ETH_RSS_L3_PRE40.bits();

        const ETH_RSS_IPV6_PRE48_SCTP =
            Self::ETH_RSS_NONFRAG_IPV6_SCTP.bits() |
            Self::RTE_ETH_RSS_L3_PRE48.bits();

        const ETH_RSS_IPV6_PRE56_SCTP =
            Self::ETH_RSS_NONFRAG_IPV6_SCTP.bits() |
            Self::RTE_ETH_RSS_L3_PRE56.bits();

        const ETH_RSS_IPV6_PRE64_SCTP =
            Self::ETH_RSS_NONFRAG_IPV6_SCTP.bits() |
            Self::RTE_ETH_RSS_L3_PRE64.bits();

        const ETH_RSS_IPV6_PRE96_SCTP =
            Self::ETH_RSS_NONFRAG_IPV6_SCTP.bits() |
            Self::RTE_ETH_RSS_L3_PRE96.bits();

        const ETH_RSS_IP =
            Self::ETH_RSS_IPV4.bits() |
            Self::ETH_RSS_FRAG_IPV4.bits() |
            Self::ETH_RSS_NONFRAG_IPV4_OTHER.bits() |
            Self::ETH_RSS_IPV6.bits() |
            Self::ETH_RSS_FRAG_IPV6.bits() |
            Self::ETH_RSS_NONFRAG_IPV6_OTHER.bits() |
            Self::ETH_RSS_IPV6_EX.bits();

        const ETH_RSS_UDP =
            Self::ETH_RSS_NONFRAG_IPV4_UDP.bits() |
            Self::ETH_RSS_NONFRAG_IPV6_UDP.bits() |
            Self::ETH_RSS_IPV6_UDP_EX.bits();

        const ETH_RSS_TCP =
            Self::ETH_RSS_NONFRAG_IPV4_TCP.bits() |
            Self::ETH_RSS_NONFRAG_IPV6_TCP.bits() |
            Self::ETH_RSS_IPV6_TCP_EX.bits();

        const ETH_RSS_SCTP =
            Self::ETH_RSS_NONFRAG_IPV4_SCTP.bits() |
            Self::ETH_RSS_NONFRAG_IPV6_SCTP.bits();

        const ETH_RSS_TUNNEL =
            Self::ETH_RSS_VXLAN.bits() |
            Self::ETH_RSS_GENEVE.bits() |
            Self::ETH_RSS_NVGRE.bits();

        const ETH_RSS_VLAN =
            Self::ETH_RSS_S_VLAN.bits() |
            Self::ETH_RSS_C_VLAN.bits();

        /**< Mask of valid RSS hash protocols */
        const ETH_RSS_PROTO_MASK =
            Self::ETH_RSS_IPV4.bits() |
            Self::ETH_RSS_FRAG_IPV4.bits() |
            Self::ETH_RSS_NONFRAG_IPV4_TCP.bits() |
            Self::ETH_RSS_NONFRAG_IPV4_UDP.bits() |
            Self::ETH_RSS_NONFRAG_IPV4_SCTP.bits() |
            Self::ETH_RSS_NONFRAG_IPV4_OTHER.bits() |
            Self::ETH_RSS_IPV6.bits() |
            Self::ETH_RSS_FRAG_IPV6.bits() |
            Self::ETH_RSS_NONFRAG_IPV6_TCP.bits() |
            Self::ETH_RSS_NONFRAG_IPV6_UDP.bits() |
            Self::ETH_RSS_NONFRAG_IPV6_SCTP.bits() |
            Self::ETH_RSS_NONFRAG_IPV6_OTHER.bits() |
            Self::ETH_RSS_L2_PAYLOAD.bits() |
            Self::ETH_RSS_IPV6_EX.bits() |
            Self::ETH_RSS_IPV6_TCP_EX.bits() |
            Self::ETH_RSS_IPV6_UDP_EX.bits() |
            Self::ETH_RSS_PORT.bits() |
            Self::ETH_RSS_VXLAN.bits() |
            Self::ETH_RSS_GENEVE.bits() |
            Self::ETH_RSS_NVGRE.bits();
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
