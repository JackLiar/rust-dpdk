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
///
/// The values mirror the `ETH_RSS_*` / `RTE_ETH_RSS_L3_*` macros of
/// `rte_ethdev.h`, including the combined protocol/level/prefix entries.
bitflags! {
    pub struct RssHashType: u64 {
        const Unknown = 0;
        const Ipv4 = ffi::ETH_RSS_IPV4 as _;
        const FragIpv4 = ffi::ETH_RSS_FRAG_IPV4 as _;
        const NonfragIpv4Tcp = ffi::ETH_RSS_NONFRAG_IPV4_TCP as _;
        const NonfragIpv4Udp = ffi::ETH_RSS_NONFRAG_IPV4_UDP as _;
        const NonfragIpv4Sctp = ffi::ETH_RSS_NONFRAG_IPV4_SCTP as _;
        const NonfragIpv4Other = ffi::ETH_RSS_NONFRAG_IPV4_OTHER as _;
        const Ipv6 = ffi::ETH_RSS_IPV6 as _;
        const FragIpv6 = ffi::ETH_RSS_FRAG_IPV6 as _;
        const NonfragIpv6Tcp = ffi::ETH_RSS_NONFRAG_IPV6_TCP as _;
        const NonfragIpv6Udp = ffi::ETH_RSS_NONFRAG_IPV6_UDP as _;
        const NonfragIpv6Sctp = ffi::ETH_RSS_NONFRAG_IPV6_SCTP as _;
        const NonfragIpv6Other = ffi::ETH_RSS_NONFRAG_IPV6_OTHER as _;
        const L2Payload = ffi::ETH_RSS_L2_PAYLOAD as _;
        const Ipv6Ex = ffi::ETH_RSS_IPV6_EX as _;
        const Ipv6TcpEx = ffi::ETH_RSS_IPV6_TCP_EX as _;
        const Ipv6UdpEx = ffi::ETH_RSS_IPV6_UDP_EX as _;
        const Port = ffi::ETH_RSS_PORT as _;
        const Vxlan = ffi::ETH_RSS_VXLAN as _;
        const Geneve = ffi::ETH_RSS_GENEVE as _;
        const Nvgre = ffi::ETH_RSS_NVGRE as _;
        const Gtpu = ffi::ETH_RSS_GTPU as _;
        const Eth = ffi::ETH_RSS_ETH as _;
        const SVlan = ffi::ETH_RSS_S_VLAN as _;
        const CVlan = ffi::ETH_RSS_C_VLAN as _;
        const Esp = ffi::ETH_RSS_ESP as _;
        const Ah = ffi::ETH_RSS_AH as _;
        const L2tpv3 = ffi::ETH_RSS_L2TPV3 as _;
        const Pfcp = ffi::ETH_RSS_PFCP as _;
        const Pppoe = ffi::ETH_RSS_PPPOE as _;
        const Ecpri = ffi::ETH_RSS_ECPRI as _;

        const L3SrcOnly = ffi::ETH_RSS_L3_SRC_ONLY as _;
        const L3DstOnly = ffi::ETH_RSS_L3_DST_ONLY as _;
        const L4SrcOnly = ffi::ETH_RSS_L4_SRC_ONLY as _;
        const L4DstOnly = ffi::ETH_RSS_L4_DST_ONLY as _;
        const L2SrcOnly = ffi::ETH_RSS_L2_SRC_ONLY as _;
        const L2DstOnly = ffi::ETH_RSS_L2_DST_ONLY as _;

        const L3Pre32 = ffi::RTE_ETH_RSS_L3_PRE32 as _;
        const L3Pre40 = ffi::RTE_ETH_RSS_L3_PRE40 as _;
        const L3Pre48 = ffi::RTE_ETH_RSS_L3_PRE48 as _;
        const L3Pre56 = ffi::RTE_ETH_RSS_L3_PRE56 as _;
        const L3Pre64 = ffi::RTE_ETH_RSS_L3_PRE64 as _;
        const L3Pre96 = ffi::RTE_ETH_RSS_L3_PRE96 as _;

        const LevelPmdDefault = ffi::ETH_RSS_LEVEL_PMD_DEFAULT as _;
        const LevelOutermost = ffi::ETH_RSS_LEVEL_OUTERMOST as _;
        const LevelInnermost = ffi::ETH_RSS_LEVEL_INNERMOST as _;
        const LevelMask = ffi::ETH_RSS_LEVEL_MASK as _;

        const Ipv6Pre32 = ffi::ETH_RSS_IPV6_PRE32 as _;
        const Ipv6Pre40 = ffi::ETH_RSS_IPV6_PRE40 as _;
        const Ipv6Pre48 = ffi::ETH_RSS_IPV6_PRE48 as _;
        const Ipv6Pre56 = ffi::ETH_RSS_IPV6_PRE56 as _;
        const Ipv6Pre64 = ffi::ETH_RSS_IPV6_PRE64 as _;
        const Ipv6Pre96 = ffi::ETH_RSS_IPV6_PRE96 as _;

        const Ipv6Pre32Udp = ffi::ETH_RSS_IPV6_PRE32_UDP as _;
        const Ipv6Pre40Udp = ffi::ETH_RSS_IPV6_PRE40_UDP as _;
        const Ipv6Pre48Udp = ffi::ETH_RSS_IPV6_PRE48_UDP as _;
        const Ipv6Pre56Udp = ffi::ETH_RSS_IPV6_PRE56_UDP as _;
        const Ipv6Pre64Udp = ffi::ETH_RSS_IPV6_PRE64_UDP as _;
        const Ipv6Pre96Udp = ffi::ETH_RSS_IPV6_PRE96_UDP as _;

        const Ipv6Pre32Tcp = ffi::ETH_RSS_IPV6_PRE32_TCP as _;
        const Ipv6Pre40Tcp = ffi::ETH_RSS_IPV6_PRE40_TCP as _;
        const Ipv6Pre48Tcp = ffi::ETH_RSS_IPV6_PRE48_TCP as _;
        const Ipv6Pre56Tcp = ffi::ETH_RSS_IPV6_PRE56_TCP as _;
        const Ipv6Pre64Tcp = ffi::ETH_RSS_IPV6_PRE64_TCP as _;
        const Ipv6Pre96Tcp = ffi::ETH_RSS_IPV6_PRE96_TCP as _;

        const Ipv6Pre32Sctp = ffi::ETH_RSS_IPV6_PRE32_SCTP as _;
        const Ipv6Pre40Sctp = ffi::ETH_RSS_IPV6_PRE40_SCTP as _;
        const Ipv6Pre48Sctp = ffi::ETH_RSS_IPV6_PRE48_SCTP as _;
        const Ipv6Pre56Sctp = ffi::ETH_RSS_IPV6_PRE56_SCTP as _;
        const Ipv6Pre64Sctp = ffi::ETH_RSS_IPV6_PRE64_SCTP as _;
        const Ipv6Pre96Sctp = ffi::ETH_RSS_IPV6_PRE96_SCTP as _;

        const Ip = ffi::ETH_RSS_IP as _;
        const Udp = ffi::ETH_RSS_UDP as _;
        const Tcp = ffi::ETH_RSS_TCP as _;
        const Sctp = ffi::ETH_RSS_SCTP as _;
        const Tunnel = ffi::ETH_RSS_TUNNEL as _;
        const Vlan = ffi::ETH_RSS_VLAN as _;

        /**< Mask of valid RSS hash protocols */
        const ProtoMask = ffi::ETH_RSS_PROTO_MASK as _;
    }
}

/// The RSS hash function used by a port or a `RTE_FLOW_ACTION_TYPE_RSS` action.
pub type RssHashFunction = ffi::rte_eth_hash_function::Type;

pub struct EthRssConf {
    pub key: Option<[u8; 40]>,
    pub hash: RssHashType,
}

impl Default for EthRssConf {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_hash_type_matches_native_constants() {
        assert_eq!(RssHashType::Unknown.bits(), 0);
        assert_eq!(RssHashType::Ipv4.bits(), ffi::ETH_RSS_IPV4 as u64);
        assert_eq!(RssHashType::Ipv6.bits(), ffi::ETH_RSS_IPV6 as u64);
        assert_eq!(RssHashType::Vxlan.bits(), ffi::ETH_RSS_VXLAN as u64);
        assert_eq!(RssHashType::Ecpri.bits(), ffi::ETH_RSS_ECPRI);
        assert_eq!(RssHashType::L3SrcOnly.bits(), ffi::ETH_RSS_L3_SRC_ONLY as u64);
        assert_eq!(RssHashType::L3Pre32.bits(), ffi::RTE_ETH_RSS_L3_PRE32);
        assert_eq!(RssHashType::LevelMask.bits(), ffi::ETH_RSS_LEVEL_MASK);
        assert_eq!(RssHashType::Ipv6Pre96Sctp.bits(), ffi::ETH_RSS_IPV6_PRE96_SCTP);
        assert_eq!(RssHashType::Ip.bits(), ffi::ETH_RSS_IP as u64);
        assert_eq!(RssHashType::ProtoMask.bits(), ffi::ETH_RSS_PROTO_MASK as u64);
    }

    #[test]
    fn combined_rss_entries_are_composed() {
        assert_eq!(
            RssHashType::Ip.bits(),
            (RssHashType::Ipv4
                | RssHashType::FragIpv4
                | RssHashType::NonfragIpv4Other
                | RssHashType::Ipv6
                | RssHashType::FragIpv6
                | RssHashType::NonfragIpv6Other
                | RssHashType::Ipv6Ex)
                .bits()
        );

        assert_eq!(
            RssHashType::Vlan.bits(),
            (RssHashType::SVlan | RssHashType::CVlan).bits()
        );

        assert_eq!(
            RssHashType::Ipv6Pre32.bits(),
            (RssHashType::Ipv6 | RssHashType::L3Pre32).bits()
        );
    }
}
