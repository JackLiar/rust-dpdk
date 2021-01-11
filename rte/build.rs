#[macro_use]
extern crate log;

extern crate rte_build;

use rte_build::*;

fn main() {
    pretty_env_logger::init();

    gcc_rte_config(&RTE_INCLUDE_DIR)
        .file("examples/l2fwd/l2fwd_core.c")
        .compile("libl2fwd_core.a");
    gcc_rte_config(&RTE_INCLUDE_DIR)
        .file("examples/kni/kni_core.c")
        .compile("libkni_core.a");

    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rustc-link-search=native=/usr/lib64");
        println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
    }
    println!("cargo:rustc-link-lib=dylib=rte_net_bond");
}
