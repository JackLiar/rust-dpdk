//! Buffered TX helper.

use std::mem;
use std::os::raw::c_void;
use std::ptr;

use anyhow::Result;
use libc;

use crate::errors::{AsResult, ErrorKind::OsError};
use crate::ffi;
use crate::malloc;
use crate::rte_check;

/// Calculate the size of the tx buffer.
pub fn rte_eth_tx_buffer_size(size: usize) -> usize {
    mem::size_of::<ffi::rte_eth_dev_tx_buffer>() + mem::size_of::<*mut ffi::rte_mbuf>() * size
}

pub type RawTxBuffer = ffi::rte_eth_dev_tx_buffer;
pub type RawTxBufferPtr = *mut ffi::rte_eth_dev_tx_buffer;

pub type TxBufferErrorCallback<T> = fn(unsent: *mut *mut ffi::rte_mbuf, count: u16, userdata: &T);

pub trait TxBuffer {
    fn free(&mut self);

    /// Configure a callback for buffered packets which cannot be sent
    fn set_err_callback<T>(
        &mut self,
        callback: Option<TxBufferErrorCallback<T>>,
        userdata: Option<&T>,
    ) -> Result<&mut Self>;

    /// Silently dropping unsent buffered packets.
    fn drop_err_packets(&mut self) -> Result<&mut Self>;

    /// Tracking unsent buffered packets.
    fn count_err_packets(&mut self) -> Result<&mut Self>;
}

/// Initialize default values for buffered transmitting
pub fn alloc_buffer(size: usize, socket_id: i32) -> Result<RawTxBufferPtr> {
    unsafe {
        malloc::zmalloc_socket("tx_buffer", rte_eth_tx_buffer_size(size), 0, socket_id)
            .ok_or(OsError(libc::ENOMEM))
            .map(|p| p.as_ptr() as *mut _)
            .and_then(|p| ffi::rte_eth_tx_buffer_init(p, size as u16).as_result().map(|_| p))
    }
}

impl TxBuffer for RawTxBuffer {
    fn free(&mut self) {
        malloc::free(self as RawTxBufferPtr as *mut c_void);
    }

    fn set_err_callback<T>(
        &mut self,
        callback: Option<TxBufferErrorCallback<T>>,
        userdata: Option<&T>,
    ) -> Result<&mut Self> {
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
