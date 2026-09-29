//! Ownership adapter for a DPDK flow action list.
//!
//! DPDK expresses actions as a `NULL`-terminated array of native
//! [`ffi::rte_flow_action`], each holding a `conf` raw pointer to a
//! caller-owned configuration structure. [`Actions`] owns those structures
//! (boxed, hence address stable) and the native array. The element type is the
//! native `rte_flow_action`; no DPDK field is re-declared here.

use std::any::Any;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_void;
use std::ptr;

use anyhow::{Result, anyhow};
use rte_sys::rte_eth_hash_function::*;
use rte_sys::rte_flow_action_rss;

use crate::ethdev::RssHashType;
use crate::ethdev::flow::FlowType;
use crate::ffi;

use ffi::rte_flow_action_type::*;

use super::Pattern;

#[repr(u32)]
#[derive(Debug, Default)]
pub enum HashFunction {
    #[default]
    Default = RTE_ETH_HASH_FUNCTION_DEFAULT,
    Toeplitz = 1,
    SimpleXor = 2,
    SymmetricToeplitz = 3,
}

#[derive(Debug, Default)]
pub struct ActionRSS(rte_flow_action_rss);

impl Deref for ActionRSS {
    type Target = rte_flow_action_rss;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ActionRSS {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ActionRSS {
    pub fn set_func(&mut self, func: HashFunction) {
        self.func = func as _;
    }
    pub fn set_hash_type(&mut self, hash_type: RssHashType) {
        self.types = hash_type.bits()
    }
}

/// Builder owning a `NULL`-terminated array of native `rte_flow_action`.
#[derive(Default)]
pub struct Actions {
    actions: Vec<ffi::rte_flow_action>,
    owners: Vec<Box<dyn Any>>,
}

impl Actions {
    /// Create an empty action list (only the `END` action).
    pub fn new() -> Self {
        Actions {
            actions: vec![end_action()],
            owners: Vec::new(),
        }
    }

    /// Box `value` and return a stable pointer to it.
    fn store<T: 'static>(&mut self, value: T) -> *const c_void {
        let boxed = Box::new(value);
        let ptr = &*boxed as *const T as *const c_void;

        self.owners.push(boxed);
        ptr
    }

    /// Insert `action` before the terminating `END` action.
    fn insert(&mut self, action: ffi::rte_flow_action) {
        let end = self.actions.len() - 1;

        self.actions.insert(end, action);
    }

    /// Action without a configuration object (`conf = NULL`), e.g. `DROP`,
    /// `PASSTHRU`, `FLAG`, `VOID`, `MAC_SWAP`, `DEC_TTL`, `OF_*`.
    pub fn simple(mut self, ty: u32) -> Self {
        self.insert(ffi::rte_flow_action {
            type_: ty,
            conf: ptr::null(),
        });

        self
    }

    /// Action with a plain (pointer free, `COPY`) configuration object.
    ///
    /// Configuration structures that embed pointers (`rss`, `sample`, the
    /// encapsulation actions, ...) must use their dedicated constructors below
    /// or [`Actions::push_raw`].
    pub fn conf<T: 'static>(mut self, ty: u32, conf: T) -> Self {
        let conf = self.store(conf);

        self.insert(ffi::rte_flow_action { type_: ty, conf });

        self
    }

    /// `RTE_FLOW_ACTION_TYPE_RSS`.
    ///
    /// The native [`ffi::rte_flow_action_rss`] is built after the key/queue
    /// storage is stable so that `key`/`queue` point into this builder.
    pub fn rss(mut self, func: u32, level: u32, types: u64, key: Box<[u8]>, queue: Box<[u16]>) -> Result<Self> {
        if queue.is_empty() {
            return Err(anyhow!("rte_flow RSS action requires at least one queue"));
        }

        let key = key.into_vec();
        let queue = queue.into_vec();

        let mut raw: ffi::rte_flow_action_rss = Default::default();
        raw.func = func;
        raw.level = level;
        raw.types = types;
        raw.key_len = key.len() as u32;
        raw.queue_num = queue.len() as u32;
        raw.key = if key.is_empty() { ptr::null() } else { key.as_ptr() };
        raw.queue = queue.as_ptr();

        let raw = Box::new(raw);
        let conf = &*raw as *const ffi::rte_flow_action_rss as *const c_void;

        self.owners.push(Box::new(key));
        self.owners.push(Box::new(queue));
        self.owners.push(raw);

        self.insert(ffi::rte_flow_action {
            type_: RTE_FLOW_ACTION_TYPE_RSS,
            conf,
        });

        Ok(self)
    }

    /// `RTE_FLOW_ACTION_TYPE_SAMPLE` with a nested action list.
    pub fn sample(mut self, ratio: u32, sub: Actions) -> Self {
        let sub = Box::new(sub);
        let actions = sub.as_ptr();

        let mut raw: ffi::rte_flow_action_sample = Default::default();
        raw.ratio = ratio;
        raw.actions = actions;

        let raw = Box::new(raw);
        let conf = &*raw as *const ffi::rte_flow_action_sample as *const c_void;

        self.owners.push(sub);
        self.owners.push(raw);

        self.insert(ffi::rte_flow_action {
            type_: RTE_FLOW_ACTION_TYPE_SAMPLE,
            conf,
        });

        self
    }

    /// `RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP` using `definition` as the outer header pattern.
    pub fn vxlan_encap(mut self, definition: Pattern) -> Self {
        let definition = Box::new(definition);

        let mut raw: ffi::rte_flow_action_vxlan_encap = Default::default();
        raw.definition = definition.as_ptr() as *mut ffi::rte_flow_item;

        let conf = self.store(raw);
        self.owners.push(definition);

        self.insert(ffi::rte_flow_action {
            type_: RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP,
            conf,
        });

        self
    }

    /// `RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP` using `definition` as the outer header pattern.
    pub fn nvgre_encap(mut self, definition: Pattern) -> Self {
        let definition = Box::new(definition);

        let mut raw: ffi::rte_flow_action_nvgre_encap = Default::default();
        raw.definition = definition.as_ptr() as *mut ffi::rte_flow_item;

        let conf = self.store(raw);
        self.owners.push(definition);

        self.insert(ffi::rte_flow_action {
            type_: RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP,
            conf,
        });

        self
    }

    /// `RTE_FLOW_ACTION_TYPE_RAW_ENCAP` with owned `data`/`preserve` buffers.
    pub fn raw_encap(mut self, data: Box<[u8]>, preserve: Option<Box<[u8]>>) -> Self {
        let data = data.into_vec();
        let preserve = preserve.map(|preserve| preserve.into_vec());

        let mut raw: ffi::rte_flow_action_raw_encap = Default::default();
        raw.data = data.as_ptr() as *mut u8;
        raw.preserve = preserve
            .as_ref()
            .map_or(ptr::null_mut(), |preserve| preserve.as_ptr() as *mut u8);
        raw.size = data.len();

        self.owners.push(Box::new(data));
        if let Some(preserve) = preserve {
            self.owners.push(Box::new(preserve));
        }

        let conf = self.store(raw);

        self.insert(ffi::rte_flow_action {
            type_: RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
            conf,
        });

        self
    }

    /// `RTE_FLOW_ACTION_TYPE_RAW_DECAP` with an owned `data` buffer.
    pub fn raw_decap(mut self, data: Box<[u8]>) -> Self {
        let data = data.into_vec();

        let mut raw: ffi::rte_flow_action_raw_decap = Default::default();
        raw.data = data.as_ptr() as *mut u8;
        raw.size = data.len();

        self.owners.push(Box::new(data));

        let conf = self.store(raw);

        self.insert(ffi::rte_flow_action {
            type_: RTE_FLOW_ACTION_TYPE_RAW_DECAP,
            conf,
        });

        self
    }

    /// Push a fully formed native action.
    ///
    /// # Safety
    ///
    /// The caller is responsible for keeping every `conf` pointer valid for as
    /// long as the action list (or any rule built from it) is handed to DPDK.
    pub unsafe fn push_raw(mut self, action: ffi::rte_flow_action) -> Self {
        self.insert(action);

        self
    }

    /// `NULL`-terminated native array, valid while `self` is alive.
    pub(crate) fn as_ptr(&self) -> *const ffi::rte_flow_action {
        self.actions.as_ptr()
    }

    /// Native actions including the terminating `END` action.
    pub(crate) fn actions(&self) -> &[ffi::rte_flow_action] {
        &self.actions
    }
}

fn end_action() -> ffi::rte_flow_action {
    ffi::rte_flow_action {
        type_: RTE_FLOW_ACTION_TYPE_END,
        conf: ptr::null(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_action_has_null_conf_and_is_end_terminated() {
        let actions = Actions::new().simple(RTE_FLOW_ACTION_TYPE_DROP);

        assert_eq!(actions.actions[0].type_, RTE_FLOW_ACTION_TYPE_DROP);
        assert!(actions.actions[0].conf.is_null());
        assert_eq!(actions.actions.last().unwrap().type_, RTE_FLOW_ACTION_TYPE_END);
    }

    #[test]
    fn conf_action_roundtrips_id() {
        let mut count: ffi::rte_flow_action_count = Default::default();
        count.id = 7;

        let actions = Actions::new().conf(RTE_FLOW_ACTION_TYPE_COUNT, count);
        let action = &actions.actions[0];

        assert_eq!(action.type_, RTE_FLOW_ACTION_TYPE_COUNT);
        assert!(!action.conf.is_null());

        let count = unsafe { &*(action.conf as *const ffi::rte_flow_action_count) };
        assert_eq!(count.id, 7);
    }

    #[test]
    fn rss_wires_key_and_queue() {
        let actions = Actions::new()
            .rss(
                0,
                0,
                0,
                vec![0x01, 0x02, 0x03].into_boxed_slice(),
                vec![1u16, 2, 3].into_boxed_slice(),
            )
            .unwrap();

        let action = &actions.actions[0];
        assert_eq!(action.type_, RTE_FLOW_ACTION_TYPE_RSS);

        let rss = unsafe { &*(action.conf as *const ffi::rte_flow_action_rss) };
        assert_eq!(rss.key_len, 3);
        assert_eq!(rss.queue_num, 3);

        let key = unsafe { std::slice::from_raw_parts(rss.key, rss.key_len as usize) };
        assert_eq!(key, [0x01, 0x02, 0x03]);

        let queue = unsafe { std::slice::from_raw_parts(rss.queue, rss.queue_num as usize) };
        assert_eq!(queue, [1, 2, 3]);
    }

    #[test]
    fn rss_rejects_empty_queue() {
        assert!(Actions::new().rss(0, 0, 0, Box::new([]), Box::new([])).is_err());
    }

    #[test]
    fn sample_embeds_sub_actions() {
        let sub = Actions::new().simple(RTE_FLOW_ACTION_TYPE_DROP);
        let actions = Actions::new().sample(4, sub);

        let action = &actions.actions[0];
        assert_eq!(action.type_, RTE_FLOW_ACTION_TYPE_SAMPLE);

        let sample = unsafe { &*(action.conf as *const ffi::rte_flow_action_sample) };
        assert_eq!(sample.ratio, 4);

        let sub = unsafe { &*sample.actions };
        assert_eq!(sub.type_, RTE_FLOW_ACTION_TYPE_DROP);
    }
}
