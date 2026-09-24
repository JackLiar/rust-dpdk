#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]

#[macro_use]
extern crate cfg_if;

include!(concat!(env!("OUT_DIR"), "/rte.rs"));
