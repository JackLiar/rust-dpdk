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
    #[cfg(feature = "ethdev")]
    {
        file.write_all(b"#include <rte_ethdev.h>\n")?;
        file.write_all(b"#include <rte_flow.h>\n")?;
    }

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

/// Emit `cargo:rustc-link-lib=rte_<feature>` for every enabled DPDK library feature.
///
/// Only linking is feature-gated. The generated header and `src/stub.c` are left
/// untouched, so bindings for all libraries are still generated.
macro_rules! link_libs {
    ($($feature:literal),* $(,)?) => {
        $(
            #[cfg(feature = $feature)]
            cargo_emit::rustc_link_lib!(concat!("rte_", $feature));
        )*
    };
}

fn generate_link_args(libdpdk: &Library) -> Result<()> {
    for p in &libdpdk.link_paths {
        cargo_emit::rustc_link_search!(format!("{}", p.display()));
    }

    // Feature list mirrors `rte-sys/Cargo.toml`. Derived from DPDK 20.11.10 as
    // installed by xmake, i.e. the `Libs:` order of `lib/pkgconfig/libdpdk-libs.pc`
    // (51 app-level libraries) followed by the remaining `lib/librte_*.so`
    // drivers/PMDs sorted alphabetically (102 libraries), 153 in total.
    link_libs![
        // --- libdpdk-libs.pc Libs order (app-level) ---
        "node",
        "graph",
        "bpf",
        "flow_classify",
        "pipeline",
        "table",
        "port",
        "fib",
        "ipsec",
        "vhost",
        "stack",
        "security",
        "sched",
        "reorder",
        "rib",
        "regexdev",
        "rawdev",
        "pdump",
        "power",
        "member",
        "lpm",
        "latencystats",
        "kni",
        "jobstats",
        "ip_frag",
        "gso",
        "gro",
        "eventdev",
        "efd",
        "distributor",
        "cryptodev",
        "compressdev",
        "cfgfile",
        "bitratestats",
        "bbdev",
        "acl",
        "timer",
        "hash",
        "metrics",
        "cmdline",
        "pci",
        "ethdev",
        "meter",
        "net",
        "mbuf",
        "mempool",
        "rcu",
        "ring",
        "eal",
        "telemetry",
        "kvargs",
        // --- remaining librte_*.so (drivers/PMDs, alphabetical) ---
        "baseband_acc100",
        "baseband_fpga_5gnr_fec",
        "baseband_fpga_lte_fec",
        "baseband_null",
        "baseband_turbo_sw",
        "bus_dpaa",
        "bus_fslmc",
        "bus_ifpga",
        "bus_pci",
        "bus_vdev",
        "bus_vmbus",
        "common_cpt",
        "common_dpaax",
        "common_iavf",
        "common_octeontx",
        "common_octeontx2",
        "common_qat",
        "common_sfc_efx",
        "compress_octeontx",
        "compress_zlib",
        "crypto_bcmfs",
        "crypto_caam_jr",
        "crypto_ccp",
        "crypto_dpaa2_sec",
        "crypto_dpaa_sec",
        "crypto_nitrox",
        "crypto_null",
        "crypto_octeontx",
        "crypto_octeontx2",
        "crypto_openssl",
        "crypto_scheduler",
        "crypto_virtio",
        "event_dlb",
        "event_dlb2",
        "event_dpaa",
        "event_dpaa2",
        "event_dsw",
        "event_octeontx",
        "event_octeontx2",
        "event_opdl",
        "event_skeleton",
        "event_sw",
        "mempool_bucket",
        "mempool_dpaa",
        "mempool_dpaa2",
        "mempool_octeontx",
        "mempool_octeontx2",
        "mempool_ring",
        "mempool_stack",
        "net_af_packet",
        "net_ark",
        "net_atlantic",
        "net_avp",
        "net_axgbe",
        "net_bnx2x",
        "net_bnxt",
        "net_bond",
        "net_cxgbe",
        "net_dpaa",
        "net_dpaa2",
        "net_e1000",
        "net_ena",
        "net_enetc",
        "net_enic",
        "net_failsafe",
        "net_fm10k",
        "net_hinic",
        "net_hns3",
        "net_i40e",
        "net_iavf",
        "net_ice",
        "net_igc",
        "net_ixgbe",
        "net_kni",
        "net_liquidio",
        "net_memif",
        "net_netvsc",
        "net_nfp",
        "net_null",
        "net_octeontx",
        "net_octeontx2",
        "net_pfe",
        "net_qede",
        "net_ring",
        "net_sfc",
        "net_softnic",
        "net_tap",
        "net_thunderx",
        "net_txgbe",
        "net_vdev_netvsc",
        "net_vhost",
        "net_virtio",
        "net_vmxnet3",
        "raw_dpaa2_cmdif",
        "raw_dpaa2_qdma",
        "raw_ioat",
        "raw_ntb",
        "raw_octeontx2_dma",
        "raw_octeontx2_ep",
        "raw_skeleton",
        "regex_octeontx2",
        "vdpa_ifc",
    ];

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
