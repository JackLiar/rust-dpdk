use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Result, anyhow};
use pkg_config::Library;

fn generate_rte_header(fpath: &Path) -> Result<()> {
    let mut file = BufWriter::new(File::create(fpath)?);
    file.write_all(b"#pragma once\n")?;
    file.write_all(b"\n")?;
    file.write_all(b"// Build Configuration\n")?;
    file.write_all(b"#include <rte_config.h>\n")?;
    file.write_all(b"\n")?;
    file.write_all(b"// Core DPDK headers\n")?;
    // file.write(b"#include <rte_graph.h>\n")?;
    // file.write(b"#include <rte_node_eth_api.h>\n")?;
    // file.write(b"#include <rte_node_eth_api.h>\n")?;
    // file.write(b"#include <rte_node_ip4_api.h>\n")?;
    // file.write(b"#include <rte_node_ip6_api.h>\n")?;
    // file.write(b"#include <rte_node_udp4_input_api.h>\n")?;
    file.write_all(b"#include <rte_common.h>\n")?;
    file.write_all(b"#include <rte_eal.h>\n")?;
    file.write_all(b"#include <rte_errno.h>\n")?;
    file.write_all(b"#include <rte_lcore.h>\n")?;
    file.write_all(b"#include <rte_malloc.h>\n")?;
    file.write_all(b"#include <rte_mempool.h>\n")?;
    file.write_all(b"#include <cmdline_cirbuf.h>\n")?;
    file.write_all(b"#include <cmdline.h>\n")?;
    file.write_all(b"#include <cmdline_parse_etheraddr.h>\n")?;
    file.write_all(b"#include <cmdline_parse.h>\n")?;
    file.write_all(b"#include <cmdline_parse_ipaddr.h>\n")?;
    file.write_all(b"#include <cmdline_parse_num.h>\n")?;
    file.write_all(b"#include <cmdline_parse_portlist.h>\n")?;
    file.write_all(b"#include <cmdline_parse_string.h>\n")?;
    file.write_all(b"#include <cmdline_rdline.h>\n")?;
    file.write_all(b"#include <cmdline_socket.h>\n")?;
    file.write_all(b"#include <cmdline_vt100.h>\n")?;
    Ok(())
}

fn generate_link_args(libdpdk: &Library) -> Result<()> {
    for p in &libdpdk.link_paths {
        cargo_emit::rustc_link_search!(format!("{}", p.display()));
    }
    cargo_emit::rustc_link_lib!("rte_cmdline");
    cargo_emit::rustc_link_lib!("rte_eal");
    cargo_emit::rustc_link_lib!("rte_ethdev");
    cargo_emit::rustc_link_lib!("rte_mbuf");
    cargo_emit::rustc_link_lib!("rte_mempool");
    Ok(())
}

fn main() -> Result<()> {
    pretty_env_logger::init();
    cargo_emit::rerun_if_env_changed!("PKG_CONFIG_PATH");
    let libdpdk = pkg_config::Config::new()
        .cargo_metadata(false)
        .env_metadata(false)
        .probe("libdpdk")
        .expect("RTE_LIBDIR - Failed to get information from libdpdk.pc");

    let out_dir = std::env::var("OUT_DIR")?;
    let out_path = Path::new(&out_dir).join("rte.rs");
    let header_file = Path::new(&out_dir).join("rte.h");

    generate_rte_header(&header_file)?;

    bindgen::builder()
        .header(
            header_file
                .to_str()
                .ok_or(anyhow!("Invalid header file name: {}", header_file.display()))?,
        )
        .header("src/stub.h")
        .clang_args(libdpdk.include_paths.iter().map(|p| format!("-I{}", p.display())))
        .blocklist_type(
            "rte_flow_item_gtp_psc|rte_l2tpv2_combined_msg_hdr|rte_arp_ipv4|rte_arp_hdr|rte_ecpri_combined_msg_hdr|rte_l2tpv2_common_hdr|rte_ecpri_common_hdr|rte_flow_item_l2tpv2|rte_flow_item_ecpri|rte_flow_item_arp_eth_ipv4|rte_flow_item_arp_eth_ipv4__bindgen_ty_1",
        )
        .blocklist_var("rte_flow_item_gtp_psc_mask|rte_flow_item_ecpri_mask|rte_flow_item_l2tpv2_mask|rte_flow_item_arp_eth_ipv4_mask")
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .generate_inline_functions(true)
        .time_phases(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");

    let mut build = cc::Build::new();
    build
        .includes(&libdpdk.include_paths)
        .cargo_metadata(true)
        .file("src/stub.c")
        .include("src")
        .flag("-march=native")
        .flag_if_supported("-mrtm")
        .compile("rte_stub");

    generate_link_args(&libdpdk)?;

    Ok(())
}
