//! Generic flow API (`rte_flow`).
//!
//! `rte_flow.c` is compiled into `librte_ethdev`, so this wrapper lives next to
//! the rest of the Ethernet device API. It exposes the native structures
//! generated from `rte_flow.h` verbatim (attributes, items, actions, query
//! results, constants) and only adds the pieces C does not have:
//!
//! * [`Pattern`] and [`Actions`]: ownership adapters for the `spec`/`last`/`mask`
//!   and `conf` raw pointers, whose element types are the native
//!   [`ffi::rte_flow_item`] / [`ffi::rte_flow_action`];
//! * [`FlowRule`]: an aggregate of a [`FlowAttr`] plus the two adapters;
//! * [`Flow`]: a `raw!` handle for `struct rte_flow *`; it stores no owning port
//!   and has no `Drop`, so [`Flow::destroy`] takes the port explicitly;
//! * [`PortFlow`]: a [`Flow`] bundled with its [`PortId`]; dropping it destroys
//!   the rule (best effort) and its `query_*` methods need no port argument.
//!   [`EthDevice::flow_create`](super::EthDevice::flow_create) returns it;
//! * [`FlowError`]: an owned, decoded copy of `struct rte_flow_error`.
//!
//! The rule is programmed through the [`EthDevice`](super::EthDevice) trait:
//! [`flow_validate`](super::EthDevice::flow_validate),
//! [`flow_create`](super::EthDevice::flow_create),
//! [`flow_flush`](super::EthDevice::flow_flush),
//! [`flow_isolate`](super::EthDevice::flow_isolate) and
//! [`flow_dev_dump`](super::EthDevice::flow_dev_dump).
//!
//! ```no_run
//! use rte::ethdev::EthDevice;
//! use rte::ethdev::flow::{Actions, FlowAttr, FlowRule, Pattern};
//! use rte::ffi::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_DROP;
//! use rte::ffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH;
//!
//! let rule = FlowRule::new(FlowAttr::ingress())
//!     .pattern(Pattern::new().any(RTE_FLOW_ITEM_TYPE_ETH))
//!     .actions(Actions::new().simple(RTE_FLOW_ACTION_TYPE_DROP));
//!
//! let port: rte::ethdev::PortId = 0;
//! let _flow = port.flow_create(&rule).unwrap(); // dropped here -> rte_flow_destroy
//! ```

use std::ops::Deref;
use std::ops::DerefMut;
use std::os::raw::c_void;

use anyhow::{Result, anyhow};
use rte_sys::rte_flow_attr;

use crate::ethdev::PortId;
use crate::ffi;
use crate::utils::AsRaw;

pub mod action;
pub mod error;
pub mod handle;
pub mod pattern;

pub use action::Actions;
pub use error::FlowError;
pub use handle::{Flow, PortFlow};
pub use pattern::Pattern;

// Every `rte_flow_*_type` module also exports a `Type` alias; re-exporting them
// all is intentional (use the fully qualified `flow::rte_flow_item_type::Type`
// when the alias itself is needed).
#[allow(ambiguous_glob_reexports)]
pub use crate::ffi::rte_flow_action_type::*;
#[allow(ambiguous_glob_reexports)]
pub use crate::ffi::rte_flow_error_type::*;
#[allow(ambiguous_glob_reexports)]
pub use crate::ffi::rte_flow_item_type::*;

/// DPDK *flow type* identifiers (`enum rte_eth_flow_type`), used to index the
/// per-flow-type tables of the flow director and of the RSS configuration.
///
/// The values mirror `rte_sys::RTE_ETH_FLOW_*`.
bitflags! {
    pub struct FlowType: u32 {
        const Unknown = rte_sys::RTE_ETH_FLOW_UNKNOWN;
        const Raw = rte_sys::RTE_ETH_FLOW_RAW;
        const Ipv4 = rte_sys::RTE_ETH_FLOW_IPV4;
        const FragIpv4 = rte_sys::RTE_ETH_FLOW_FRAG_IPV4;
        const NonfragIpv4Tcp = rte_sys::RTE_ETH_FLOW_NONFRAG_IPV4_TCP;
        const NonfragIpv4Udp = rte_sys::RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
        const NonfragIpv4Sctp = rte_sys::RTE_ETH_FLOW_NONFRAG_IPV4_SCTP;
        const NonfragIpv4Other = rte_sys::RTE_ETH_FLOW_NONFRAG_IPV4_OTHER;
        const Ipv6 = rte_sys::RTE_ETH_FLOW_IPV6;
        const FragIpv6 = rte_sys::RTE_ETH_FLOW_FRAG_IPV6;
        const NonfragIpv6Tcp = rte_sys::RTE_ETH_FLOW_NONFRAG_IPV6_TCP;
        const NonfragIpv6Udp = rte_sys::RTE_ETH_FLOW_NONFRAG_IPV6_UDP;
        const NonfragIpv6Sctp = rte_sys::RTE_ETH_FLOW_NONFRAG_IPV6_SCTP;
        const NonfragIpv6Other = rte_sys::RTE_ETH_FLOW_NONFRAG_IPV6_OTHER;
        const L2Payload = rte_sys::RTE_ETH_FLOW_L2_PAYLOAD;
        const Ipv6Ex = rte_sys::RTE_ETH_FLOW_IPV6_EX;
        const Ipv6TcpEx = rte_sys::RTE_ETH_FLOW_IPV6_TCP_EX;
        const Ipv6UdpEx = rte_sys::RTE_ETH_FLOW_IPV6_UDP_EX;
        const Port = rte_sys::RTE_ETH_FLOW_PORT;
        const Vxlan = rte_sys::RTE_ETH_FLOW_VXLAN;
        const Geneve = rte_sys::RTE_ETH_FLOW_GENEVE;
        const Nvgre = rte_sys::RTE_ETH_FLOW_NVGRE;
        const VxlanGpe = rte_sys::RTE_ETH_FLOW_VXLAN_GPE;
        const Gtpu = rte_sys::RTE_ETH_FLOW_GTPU;
        const Max = rte_sys::RTE_ETH_FLOW_MAX;
    }
}

/// Thin wrapper over the native [`rte_flow_attr`] that adds ergonomic
/// direction setters ([`FlowAttr::set_ingress`], [`FlowAttr::set_egress`],
/// [`FlowAttr::set_transfer`]) while keeping `Deref`/`DerefMut` access to every
/// native field and bitfield getter.
#[derive(Clone, Copy, Debug, Default)]
pub struct FlowAttr(rte_flow_attr);

impl Deref for FlowAttr {
    type Target = rte_flow_attr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FlowAttr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FlowAttr {
    /// Flow rule attributes for egress traffic.
    pub fn set_egress(&mut self) {
        self.deref_mut().set_egress(1)
    }
    /// Flow rule attributes for ingress traffic.
    pub fn set_ingress(&mut self) {
        self.deref_mut().set_ingress(1);
    }
    /// Flow rule attributes for transfer (eSwitch/representor) traffic.
    pub fn set_transfer(&mut self) {
        self.deref_mut().set_transfer(1);
    }
    /// Flow rule attributes for egress traffic.
    pub fn egress() -> Self {
        let mut attr = Self::default();
        attr.set_egress();
        attr
    }
    /// Flow rule attributes for ingress traffic.
    pub fn ingress() -> Self {
        let mut attr = Self::default();
        attr.set_ingress();
        attr
    }
    /// Flow rule attributes for transfer (eSwitch/representor) traffic.
    pub fn transfer() -> Self {
        let mut attr = Self::default();
        attr.set_transfer();
        attr
    }
}

impl AsRaw for FlowAttr {
    type Raw = rte_flow_attr;

    fn as_raw(&self) -> *const Self::Raw {
        &self.0
    }

    fn as_raw_mut(&self) -> *mut Self::Raw {
        &self.0 as *const Self::Raw as *mut Self::Raw
    }
}

/// Complete flow rule description.
///
/// This only aggregates [`FlowAttr`] with the two ownership adapters; it does
/// not re-declare any DPDK field.
#[derive(Default)]
pub struct FlowRule {
    /// Rule attributes (group, priority, ingress/egress/transfer).
    pub attr: FlowAttr,
    /// Pattern (always `END`-terminated internally).
    pub pattern: Pattern,
    /// Associated actions (always `END`-terminated internally).
    pub actions: Actions,
}

impl FlowRule {
    /// Create a rule from native attributes and empty pattern/actions.
    pub fn new(attr: FlowAttr) -> Self {
        FlowRule {
            attr,
            pattern: Pattern::new(),
            actions: Actions::new(),
        }
    }

    /// Replace the pattern.
    pub fn pattern(mut self, pattern: Pattern) -> Self {
        self.pattern = pattern;

        self
    }

    /// Append actions.
    ///
    /// Note: this replaces the whole action list; chain multiple actions on the
    /// [`Actions`] value instead of calling this repeatedly.
    pub fn actions(mut self, actions: Actions) -> Self {
        self.actions = actions;

        self
    }

    /// Reject rules without any direction, as required by `rte_flow.h`.
    pub(crate) fn validate_local(&self) -> Result<()> {
        if self.attr.ingress() == 0 && self.attr.egress() == 0 && self.attr.transfer() == 0 {
            return Err(anyhow!(
                "rte_flow attribute must set at least one of ingress, egress or transfer"
            ));
        }

        Ok(())
    }
}

/// Check whether a flow rule can be created on `port`.
pub(crate) fn validate(port: PortId, rule: &FlowRule) -> Result<()> {
    rule.validate_local()?;

    let mut error: ffi::rte_flow_error = Default::default();

    error::check(
        unsafe {
            ffi::rte_flow_validate(
                port,
                rule.attr.as_raw(),
                rule.pattern.as_ptr(),
                rule.actions.as_ptr(),
                &mut error,
            )
        },
        &error,
    )
}

/// Destroy all flow rules associated with `port`.
pub(crate) fn flush(port: PortId) -> Result<()> {
    let mut error: ffi::rte_flow_error = Default::default();

    error::check(unsafe { ffi::rte_flow_flush(port, &mut error) }, &error)
}

/// Restrict ingress traffic of `port` to the defined flow rules.
pub(crate) fn isolate(port: PortId, set: bool) -> Result<()> {
    let mut error: ffi::rte_flow_error = Default::default();

    error::check(
        unsafe { ffi::rte_flow_isolate(port, i32::from(set), &mut error) },
        &error,
    )
}

/// Dump the hardware internal representation of the flow rules of `port`.
pub(crate) fn dev_dump(port: PortId, file: *mut ffi::FILE) -> Result<()> {
    let mut error: ffi::rte_flow_error = Default::default();

    error::check(unsafe { ffi::rte_flow_dev_dump(port, file, &mut error) }, &error)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ffi::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_DROP;
    use crate::ffi::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH;

    #[test]
    fn flow_type_matches_native_constants() {
        assert_eq!(FlowType::Unknown.bits(), rte_sys::RTE_ETH_FLOW_UNKNOWN);
        assert_eq!(FlowType::Raw.bits(), rte_sys::RTE_ETH_FLOW_RAW);
        assert_eq!(FlowType::Ipv4.bits(), rte_sys::RTE_ETH_FLOW_IPV4);
        assert_eq!(
            FlowType::NonfragIpv4Other.bits(),
            rte_sys::RTE_ETH_FLOW_NONFRAG_IPV4_OTHER
        );
        assert_eq!(FlowType::Ipv6Ex.bits(), rte_sys::RTE_ETH_FLOW_IPV6_EX);
        assert_eq!(FlowType::VxlanGpe.bits(), rte_sys::RTE_ETH_FLOW_VXLAN_GPE);
        assert_eq!(FlowType::Gtpu.bits(), rte_sys::RTE_ETH_FLOW_GTPU);
        assert_eq!(FlowType::Max.bits(), rte_sys::RTE_ETH_FLOW_MAX);
    }

    #[test]
    fn attr_helpers_set_the_right_direction() {
        let ingress = FlowAttr::ingress();
        assert_eq!(ingress.ingress(), 1);
        assert_eq!(ingress.egress(), 0);
        assert_eq!(ingress.transfer(), 0);

        let egress = FlowAttr::egress();
        assert_eq!(egress.egress(), 1);
        assert_eq!(egress.ingress(), 0);

        let transfer = FlowAttr::transfer();
        assert_eq!(transfer.transfer(), 1);
    }

    #[test]
    fn attr_keeps_group_and_priority() {
        let mut attr = FlowAttr::ingress();
        attr.group = 3;
        attr.priority = 9;

        assert_eq!(attr.group, 3);
        assert_eq!(attr.priority, 9);
    }

    #[test]
    fn validate_local_requires_direction() {
        let rule = FlowRule::new(FlowAttr::default());
        assert!(rule.validate_local().is_err());

        let rule = FlowRule::new(FlowAttr::ingress());
        assert!(rule.validate_local().is_ok());
    }

    #[test]
    fn rule_aggregates_native_pieces() {
        let rule = FlowRule::new(FlowAttr::ingress())
            .pattern(Pattern::new().any(RTE_FLOW_ITEM_TYPE_ETH))
            .actions(Actions::new().simple(RTE_FLOW_ACTION_TYPE_DROP));

        assert_eq!(rule.attr.ingress(), 1);
        assert_eq!(rule.pattern.items().last().unwrap().type_, RTE_FLOW_ITEM_TYPE_END);
        assert_eq!(
            rule.actions.actions().last().unwrap().type_,
            crate::ffi::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END
        );
    }
}
