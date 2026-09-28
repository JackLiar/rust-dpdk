//! Verbose error reporting for the generic flow API.
//!
//! DPDK reports flow errors through `struct rte_flow_error` (optionally filled
//! by the PMD) plus a return value / `rte_errno`. The native structure holds a
//! `const char *message` valid only as long as the associated port stays
//! configured, and raw pointers make it neither `Send` nor `Sync`, which is
//! incompatible with this crate's `anyhow::Result`. [`FlowError`] therefore
//! **decodes** the native structure once into an owned copy at the call site.

use std::ffi::CStr;
use std::fmt;
use std::ptr::NonNull;

use anyhow::Result;

use crate::errors::{RteError, rte_errno};
use crate::ffi;

/// Decoded, owned copy of a `struct rte_flow_error` plus the associated errno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowError {
    /// Negative errno returned by the call, or the positive `rte_errno` for
    /// `rte_flow_create` (which reports failure through a `NULL` handle).
    pub code: i32,
    /// Native `rte_flow_error_type` (see `ffi::rte_flow_error_type`).
    pub type_: ffi::rte_flow_error_type::Type,
    /// Native `#cause` pointer encoded as `usize` (`0` means `NULL`), kept as an
    /// address because the pointed-to object lifetime cannot be modelled here.
    pub cause: usize,
    /// Human readable message copied out of the native `#message` pointer.
    pub message: Option<String>,
}

impl FlowError {
    /// Decode a native [`ffi::rte_flow_error`] into an owned [`FlowError`].
    ///
    /// `code` should be the negative errno returned by the API call. When it is
    /// zero (e.g. `rte_flow_create` returning a `NULL` handle), the current
    /// `rte_errno` is used instead.
    pub fn new(code: i32, error: &ffi::rte_flow_error) -> Self {
        let code = if code != 0 { code } else { rte_errno() };

        let message = if error.message.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(error.message) }.to_string_lossy().into_owned())
        };

        FlowError {
            code,
            type_: error.type_,
            cause: error.cause as usize,
            message,
        }
    }

    /// Whether the PMD provided any detail besides the errno.
    pub fn is_verbose(&self) -> bool {
        self.type_ != ffi::rte_flow_error_type::RTE_FLOW_ERROR_TYPE_NONE || self.message.is_some()
    }
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rte_flow error")?;

        if self.type_ != ffi::rte_flow_error_type::RTE_FLOW_ERROR_TYPE_NONE {
            write!(f, " [type {}]", self.type_)?;
        }

        if let Some(ref message) = self.message {
            write!(f, ": {}", message)?;
        }

        if self.code != 0 {
            write!(f, " ({})", RteError(self.code))?;
        }

        Ok(())
    }
}

impl std::error::Error for FlowError {}

/// Check a `0` / negative-errno return code and translate the native error.
pub(crate) fn check(ret: i32, error: &ffi::rte_flow_error) -> Result<()> {
    if ret == 0 {
        Ok(())
    } else {
        Err(FlowError::new(-ret, error).into())
    }
}

/// Check a handle-returning call (`rte_flow_create` & friends).
pub(crate) fn check_handle<T>(ptr: *mut T, error: &ffi::rte_flow_error) -> Result<NonNull<T>> {
    match NonNull::new(ptr) {
        Some(ptr) => Ok(ptr),
        None => Err(FlowError::new(0, error).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn flow_error_is_send_sync() {
        assert_send_sync::<FlowError>();
    }

    #[test]
    fn display_includes_message_and_code() {
        let message = CString::new("rule rejected").unwrap();

        let mut error: ffi::rte_flow_error = Default::default();
        error.type_ = ffi::rte_flow_error_type::RTE_FLOW_ERROR_TYPE_ITEM;
        error.message = message.as_ptr();

        let err = FlowError::new(-22, &error);

        assert_eq!(err.code, -22);
        assert!(err.is_verbose());

        let text = err.to_string();
        assert!(text.contains("rule rejected"), "{text}");
        assert!(text.contains("-22"), "{text}");
    }

    #[test]
    fn check_maps_zero_to_ok() {
        let error: ffi::rte_flow_error = Default::default();

        assert!(check(0, &error).is_ok());
    }

    #[test]
    fn check_maps_negative_to_error() {
        let error: ffi::rte_flow_error = Default::default();

        assert!(check(-5, &error).is_err());
    }
}
