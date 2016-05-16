use std::io;
use std::fmt;
use std::error;
use std::result;
use std::ffi;

use errno::errno;

use ffi::rte_strerror;

extern "C" {
    fn _rte_errno() -> i32;
}

macro_rules! rte_check {
    ( $ret:expr ) => (
        rte_check!($ret; ok => {()}; err => {$crate::errors::Error::RteError($ret)})
    );
    ( $ret:expr; ok => $ok:block) => (
        rte_check!($ret; ok => $ok; err => {$crate::errors::Error::RteError($ret)})
    );
    ( $ret:expr; err => $err:block) => (
        rte_check!($ret; ok => {()}; err => $err)
    );
    ( $ret:expr; ok => $ok:block; err => $err:block ) => ({
        if ($ret) >= 0 {
            Ok($ok)
        } else {
            Err($err)
        }
    });
}

macro_rules! rte_check_ptr {
    ( $ret:expr ) => (
        rte_check_ptr!($ret; ok => {()}; err => {$crate::errors::Error::rte_error()})
    );
    ( $ret:expr; ok => $ok:block) => (
        rte_check_ptr!($ret; ok => $ok; err => {$crate::errors::Error::rte_error()})
    );
    ( $ret:expr; err => $err:block) => (
        rte_check_ptr!($ret; ok => {()}; err => $err)
    );
    ( $ret:expr; ok => $ok:block; err => $err:block ) => ({
        if !(($ret).is_null()) {
            Ok($ok)
        } else {
            Err($err)
        }
    });
}

#[derive(Debug)]
pub enum Error {
    RteError(i32),
    OsError(i32),
    IoError(io::Error),
    NulError(ffi::NulError),
}

impl Error {
    pub fn rte_error() -> Error {
        Error::RteError(unsafe { _rte_errno() })
    }

    pub fn os_error() -> Error {
        Error::OsError(errno().0 as i32)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::RteError(errno) => {
                write!(f,
                       "RTE error, {}",
                       unsafe { ffi::CStr::from_ptr(rte_strerror(errno)).to_str().unwrap() })
            }
            &Error::OsError(ref errno) => write!(f, "OS error, {}", errno),
            &Error::IoError(ref err) => write!(f, "IO error, {}", err),
            _ => write!(f, "{}", error::Error::description(self)),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::RteError(_) => "RTE error",
            &Error::OsError(_) => "OS error",
            &Error::IoError(ref err) => error::Error::description(err),
            &Error::NulError(ref err) => error::Error::description(err),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<ffi::NulError> for Error {
    fn from(err: ffi::NulError) -> Error {
        Error::NulError(err)
    }
}

pub type Result<T> = result::Result<T, Error>;
