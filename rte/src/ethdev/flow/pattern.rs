//! Ownership adapter for a DPDK flow pattern.
//!
//! DPDK expresses a pattern as a `NULL`-terminated array of native
//! [`ffi::rte_flow_item`], each holding `spec`/`last`/`mask` raw pointers to
//! caller-owned structures. [`Pattern`] owns those structures (boxed, hence
//! address stable) and the native array, so the pointers handed to the PMD stay
//! valid for as long as the adapter lives. The element type is the native
//! `rte_flow_item`; no DPDK field is re-declared here.

use std::any::Any;
use std::os::raw::c_void;
use std::ptr;

use crate::ffi;

use ffi::rte_flow_item_type::*;

/// Builder owning a `NULL`-terminated array of native `rte_flow_item`.
#[derive(Default)]
pub struct Pattern {
    items: Vec<ffi::rte_flow_item>,
    owners: Vec<Box<dyn Any>>,
}

impl Pattern {
    /// Create an empty pattern (only the `END` item).
    pub fn new() -> Self {
        Pattern {
            items: vec![end_item()],
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

    /// Insert `item` before the terminating `END` item.
    fn insert(&mut self, item: ffi::rte_flow_item) {
        let end = self.items.len() - 1;

        self.items.insert(end, item);
    }

    /// Broad (non specific) match of `ty`: `spec`, `last` and `mask` are all `NULL`.
    ///
    /// This is the form used for meta items (`VOID`, `INVERT`, `PF`, ...) and
    /// for protocol items when no field should be constrained.
    pub fn any(mut self, ty: u32) -> Self {
        self.insert(ffi::rte_flow_item {
            type_: ty,
            spec: ptr::null(),
            last: ptr::null(),
            mask: ptr::null(),
        });

        self
    }

    /// Match `spec` using the PMD default mask (`mask` stays `NULL`).
    pub fn spec<T: 'static>(mut self, ty: u32, spec: T) -> Self {
        let spec = self.store(spec);

        self.insert(ffi::rte_flow_item {
            type_: ty,
            spec,
            last: ptr::null(),
            mask: ptr::null(),
        });

        self
    }

    /// Match `spec` with an explicit `mask`.
    pub fn masked<T: 'static>(mut self, ty: u32, spec: T, mask: T) -> Self {
        let spec = self.store(spec);
        let mask = self.store(mask);

        self.insert(ffi::rte_flow_item {
            type_: ty,
            spec,
            last: ptr::null(),
            mask,
        });

        self
    }

    /// Match the inclusive range `spec`..=`last`, optionally masked.
    pub fn range<T: 'static>(mut self, ty: u32, spec: T, last: T, mask: Option<T>) -> Self {
        let spec = self.store(spec);
        let last = self.store(last);
        let mask = mask.map(|mask| self.store(mask)).unwrap_or(ptr::null());

        self.insert(ffi::rte_flow_item {
            type_: ty,
            spec,
            last,
            mask,
        });

        self
    }

    /// Match a byte string at a given offset (`RTE_FLOW_ITEM_TYPE_RAW`).
    ///
    /// The byte string is owned by the pattern; the native
    /// [`ffi::rte_flow_item_raw`] is built once its backing storage is stable.
    pub fn raw_pattern(mut self, relative: bool, search: bool, offset: i32, limit: u16, pattern: Box<[u8]>) -> Self {
        let bytes = pattern.into_vec();
        let length = bytes.len() as u16;
        let data = bytes.as_ptr();

        let mut raw: ffi::rte_flow_item_raw = Default::default();
        raw.set_relative(u32::from(relative));
        raw.set_search(u32::from(search));
        raw.offset = offset;
        raw.limit = limit;
        raw.length = length;
        raw.pattern = data;

        self.owners.push(Box::new(bytes));

        let spec = self.store(raw);

        self.insert(ffi::rte_flow_item {
            type_: RTE_FLOW_ITEM_TYPE_RAW,
            spec,
            last: ptr::null(),
            mask: ptr::null(),
        });

        self
    }

    /// Push a fully formed native item.
    ///
    /// # Safety
    ///
    /// The caller is responsible for keeping every `spec`/`last`/`mask` pointer
    /// valid for as long as the pattern (or any rule built from it) is handed to
    /// DPDK.
    pub unsafe fn push_raw(mut self, item: ffi::rte_flow_item) -> Self {
        self.insert(item);

        self
    }

    /// `NULL`-terminated native array, valid while `self` is alive.
    pub(crate) fn as_ptr(&self) -> *const ffi::rte_flow_item {
        self.items.as_ptr()
    }

    /// Native items including the terminating `END` item.
    pub(crate) fn items(&self) -> &[ffi::rte_flow_item] {
        &self.items
    }
}

fn end_item() -> ffi::rte_flow_item {
    ffi::rte_flow_item {
        type_: RTE_FLOW_ITEM_TYPE_END,
        spec: ptr::null(),
        last: ptr::null(),
        mask: ptr::null(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_item_has_null_spec_last_mask() {
        let pattern = Pattern::new().any(RTE_FLOW_ITEM_TYPE_ETH);

        let item = &pattern.items[0];
        assert_eq!(item.type_, RTE_FLOW_ITEM_TYPE_ETH);
        assert!(item.spec.is_null());
        assert!(item.last.is_null());
        assert!(item.mask.is_null());

        // always END-terminated
        assert_eq!(pattern.items.last().unwrap().type_, RTE_FLOW_ITEM_TYPE_END);
    }

    #[test]
    fn spec_sets_spec_only() {
        let mut eth: ffi::rte_flow_item_eth = Default::default();
        eth.type_ = 0x0800;

        let pattern = Pattern::new().spec(RTE_FLOW_ITEM_TYPE_ETH, eth);

        let item = &pattern.items[0];
        assert_eq!(item.type_, RTE_FLOW_ITEM_TYPE_ETH);
        assert!(!item.spec.is_null());
        assert!(item.last.is_null());
        assert!(item.mask.is_null());

        // the pointer addresses the owned copy stored in `owners`
        let roundtrip = unsafe { *(item.spec as *const ffi::rte_flow_item_eth) };
        assert_eq!(roundtrip.type_, eth.type_);
    }

    #[test]
    fn masked_sets_mask() {
        let eth: ffi::rte_flow_item_eth = Default::default();
        let mask: ffi::rte_flow_item_eth = Default::default();

        let pattern = Pattern::new().masked(RTE_FLOW_ITEM_TYPE_ETH, eth, mask);
        let item = &pattern.items[0];

        assert!(!item.spec.is_null());
        assert!(!item.mask.is_null());
        assert!(item.last.is_null());
    }

    #[test]
    fn range_sets_last() {
        let ipv4: ffi::rte_flow_item_ipv4 = Default::default();

        let pattern = Pattern::new().range(RTE_FLOW_ITEM_TYPE_IPV4, ipv4, ipv4, Some(ipv4));
        let item = &pattern.items[0];

        assert!(!item.spec.is_null());
        assert!(!item.last.is_null());
        assert!(!item.mask.is_null());
    }

    #[test]
    fn raw_pattern_wires_length_and_bytes() {
        let pattern = Pattern::new().raw_pattern(true, false, 0, 0, vec![0xde, 0xad, 0xbe, 0xef].into_boxed_slice());

        let item = &pattern.items[0];
        assert_eq!(item.type_, RTE_FLOW_ITEM_TYPE_RAW);
        assert!(!item.spec.is_null());
        assert!(item.mask.is_null());

        let raw = unsafe { &*(item.spec as *const ffi::rte_flow_item_raw) };
        assert_eq!(raw.length, 4);
        assert_eq!(raw.offset, 0);
        assert_eq!(raw.relative(), 1);
        assert_eq!(raw.search(), 0);

        let bytes = unsafe { std::slice::from_raw_parts(raw.pattern, raw.length as usize) };
        assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
    }
}
