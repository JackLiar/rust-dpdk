//! Ethernet device information and statistics.

use std::ffi::CStr;

use crate::dev;
use crate::ffi;

pub trait EthDeviceInfo {
    /// Device Driver name.
    fn driver_name(&self) -> &str;

    fn dev(&self) -> Option<dev::Device>;
}

pub type RawEthDeviceInfo = ffi::rte_eth_dev_info;

impl EthDeviceInfo for RawEthDeviceInfo {
    #[inline]
    fn driver_name(&self) -> &str {
        unsafe { CStr::from_ptr(self.driver_name).to_str().unwrap() }
    }

    #[inline]
    fn dev(&self) -> Option<dev::Device> {
        if self.device.is_null() {
            None
        } else {
            Some(self.device.into())
        }
    }
}

pub trait EthDeviceStats {}

pub type RawEthDeviceStats = ffi::rte_eth_stats;

impl EthDeviceStats for RawEthDeviceStats {}
