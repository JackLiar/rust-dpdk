#![allow(
    deprecated,
    unused,
    clippy::useless_attribute,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::trivially_copy_pass_by_ref,
    clippy::many_single_char_names
)]

#[macro_use]
extern crate thiserror;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate num_derive;

pub mod ffi;

pub mod common;
pub mod errors;
pub mod macros;
pub mod utils;

pub mod mbuf;
pub mod mempool;
pub mod ring;

// pub mod bond;
pub mod ethdev;
// pub mod pci;

// pub mod arp;
pub mod ether;
// pub mod ip;

// #[macro_use]
pub mod cmdline;

pub use self::common::*;
// pub use self::errors::{ErrorKind, RteError};
// pub use self::ethdev::PortId;
// pub use self::ethdev::QueueId;

// #[cfg(test)]
// mod tests;
