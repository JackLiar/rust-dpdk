//! `rte_flow` rule handles.
//!
//! [`Flow`] is a thin [`raw!`](crate::raw) newtype around the native
//! `struct rte_flow *`. It deliberately does **not** store its owning port and
//! has no `Drop` implementation: every operation that needs the device
//! (`rte_flow_destroy`, `rte_flow_query`) takes the [`PortId`] explicitly.
//!
//! [`PortFlow`] builds on top of it, remembering the owning [`PortId`] so that
//! the rule is destroyed automatically when the wrapper is dropped.

use std::os::raw::c_void;

use anyhow::Result;

use crate::ethdev::PortId;
use crate::ffi;
use crate::raw;
use crate::utils::AsRaw;

use ffi::rte_flow_action_type::*;

use super::FlowRule;
use super::error::{check, check_handle};

pub type RawFlow = ffi::rte_flow;
pub type RawFlowPtr = *mut ffi::rte_flow;

raw!(pub Flow(RawFlow));

impl Flow {
    /// Create a flow rule described by `rule` on `port`.
    ///
    /// The rule direction is validated locally first, then `rte_flow_create` is
    /// called. A `NULL` handle is translated through `rte_errno` and the verbose
    /// `rte_flow_error` filled in by the PMD.
    pub fn create(port: PortId, rule: &FlowRule) -> Result<Flow> {
        rule.validate_local()?;

        let mut error: ffi::rte_flow_error = Default::default();

        let handle = check_handle(
            unsafe {
                ffi::rte_flow_create(
                    port,
                    rule.attr.as_raw(),
                    rule.pattern.as_ptr(),
                    rule.actions.as_ptr(),
                    &mut error,
                )
            },
            &error,
        )?;

        Ok(Flow(handle))
    }

    /// Destroy this flow rule on `port`, reporting errors.
    ///
    /// There is no implicit destruction on drop, so the rule must be destroyed
    /// explicitly (or all rules released at once through
    /// [`EthDevice::flow_flush`](crate::ethdev::EthDevice::flow_flush)).
    pub fn destroy(self, port: PortId) -> Result<()> {
        let mut error: ffi::rte_flow_error = Default::default();

        check(
            unsafe { ffi::rte_flow_destroy(port, self.as_raw_mut(), &mut error) },
            &error,
        )
    }

    /// Query an existing rule on `port` with an arbitrary native action definition.
    ///
    /// `action` must match the definition used when the rule was created.
    pub fn query_raw<T>(&self, port: PortId, action: &ffi::rte_flow_action, data: &mut T) -> Result<()> {
        let mut error: ffi::rte_flow_error = Default::default();

        let ret = unsafe {
            ffi::rte_flow_query(
                port,
                self.as_raw_mut(),
                action,
                data as *mut T as *mut c_void,
                &mut error,
            )
        };

        check(ret, &error)
    }

    /// Retrieve (and optionally reset) the `RTE_FLOW_ACTION_TYPE_COUNT` counters.
    pub fn query_count(&self, port: PortId, counter_id: u32, reset: bool) -> Result<ffi::rte_flow_query_count> {
        let mut count: ffi::rte_flow_action_count = Default::default();
        count.id = counter_id;

        let action = ffi::rte_flow_action {
            type_: RTE_FLOW_ACTION_TYPE_COUNT,
            conf: &count as *const ffi::rte_flow_action_count as *const c_void,
        };

        let mut data: ffi::rte_flow_query_count = Default::default();
        data.set_reset(u32::from(reset));

        self.query_raw(port, &action, &mut data)?;

        Ok(data)
    }

    /// Retrieve the `RTE_FLOW_ACTION_TYPE_AGE` aging status.
    pub fn query_age(&self, port: PortId) -> Result<ffi::rte_flow_query_age> {
        let age: ffi::rte_flow_action_age = Default::default();

        let action = ffi::rte_flow_action {
            type_: RTE_FLOW_ACTION_TYPE_AGE,
            conf: &age as *const ffi::rte_flow_action_age as *const c_void,
        };

        let mut data: ffi::rte_flow_query_age = Default::default();

        self.query_raw(port, &action, &mut data)?;

        Ok(data)
    }
}

/// RAII wrapper around [`Flow`] that remembers its owning [`PortId`].
///
/// Dropping a `PortFlow` destroys the underlying rule (best effort). Use
/// [`PortFlow::destroy`] to observe the error, or [`PortFlow::into_flow`] to
/// detach the raw handle and take over destruction.
#[derive(Debug)]
pub struct PortFlow {
    port: PortId,
    flow: Option<Flow>,
}

impl PortFlow {
    /// Wrap a raw `flow` created on `port`.
    pub fn new(port: PortId, flow: Flow) -> Self {
        PortFlow { port, flow: Some(flow) }
    }

    /// Create a rule on `port` and wrap it.
    pub fn create(port: PortId, rule: &FlowRule) -> Result<Self> {
        Ok(PortFlow::new(port, Flow::create(port, rule)?))
    }

    /// Port this rule belongs to.
    pub fn port(&self) -> PortId {
        self.port
    }

    /// Borrow the underlying raw handle.
    pub fn as_flow(&self) -> &Flow {
        self.flow.as_ref().expect("flow handle already released")
    }

    /// Detach the raw handle, disabling the automatic `Drop` destruction.
    pub fn into_flow(mut self) -> Flow {
        self.flow.take().expect("flow handle already released")
    }

    /// Destroy the rule now, reporting errors.
    ///
    /// Afterwards dropping the wrapper is a no-op.
    pub fn destroy(mut self) -> Result<()> {
        match self.flow.take() {
            Some(flow) => flow.destroy(self.port),
            None => Ok(()),
        }
    }

    /// [`Flow::query_raw`] without the port argument.
    pub fn query_raw<T>(&self, action: &ffi::rte_flow_action, data: &mut T) -> Result<()> {
        self.as_flow().query_raw(self.port, action, data)
    }

    /// [`Flow::query_count`] without the port argument.
    pub fn query_count(&self, counter_id: u32, reset: bool) -> Result<ffi::rte_flow_query_count> {
        self.as_flow().query_count(self.port, counter_id, reset)
    }

    /// [`Flow::query_age`] without the port argument.
    pub fn query_age(&self) -> Result<ffi::rte_flow_query_age> {
        self.as_flow().query_age(self.port)
    }
}

impl From<(PortId, Flow)> for PortFlow {
    fn from((port, flow): (PortId, Flow)) -> Self {
        PortFlow::new(port, flow)
    }
}

impl Drop for PortFlow {
    fn drop(&mut self) {
        if let Some(flow) = self.flow.take() {
            // Best effort: a closed/stopped port makes destroy fail, which
            // cannot be surfaced from `Drop`.
            let _ = flow.destroy(self.port);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ptr::NonNull;

    use crate::utils::{AsRaw, FromRaw};

    /// A non-null but dangling handle, only used to exercise the wrapper
    /// plumbing. Every test detaches it again so `rte_flow_destroy` is never
    /// reachable from `Drop`.
    fn dangling_flow() -> Flow {
        Flow::from_raw(NonNull::<ffi::rte_flow>::dangling().as_ptr()).expect("dangling pointer is non null")
    }

    #[test]
    fn port_flow_keeps_its_port() {
        let flow = PortFlow::new(7, dangling_flow());

        assert_eq!(flow.port(), 7);

        let _ = flow.into_flow();
    }

    #[test]
    fn into_flow_detaches_without_destroying() {
        let flow = PortFlow::new(3, dangling_flow());

        let raw = flow.into_flow();

        assert_eq!(
            raw.as_raw() as usize,
            NonNull::<ffi::rte_flow>::dangling().as_ptr() as usize
        );
    }

    #[test]
    fn from_tuple_builds_a_port_flow() {
        let flow = PortFlow::from((5, dangling_flow()));

        assert_eq!(flow.port(), 5);

        let _ = flow.into_flow();
    }
}
