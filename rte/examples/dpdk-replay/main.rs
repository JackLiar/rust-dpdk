//! Replay a pcap file in bursts through one or more DPDK ports.
//!
//! This is a Rust reimplementation of `dpdk-replay` built entirely on the
//! ownership-correct `rte::new` API. It uses `clap` for command-line parsing and
//! the `pcap` crate (libpcap) for reading traces.
//!
//! Run it as an example after sourcing `env.sh`:
//!
//! ```text
//! cargo run --example dpdk-replay -- --nbruns 3 trace.pcap 0000:04:00.0
//! ```
//!
//! EAL options can be placed before `--`:
//!
//! ```text
//! cargo run --example dpdk-replay -- -l 0-3 -- trace.pcap 0
//! ```

mod args;
mod cpu;
mod packet;
mod trace;
mod worker;

use std::collections::HashSet;
use std::io::{self, Write};
use std::process;
use std::sync::Arc;

use anyhow::{Context, Result, bail};

use rte::new::{
    Eal, LcoreId, LcoreScope, MemoryPool, PACKET_HEADROOM, Port, PortConfig, PortId, TxQueue, TxQueueConfig,
};

use crate::args::{Invocation, PortSpec};
use crate::packet::{MBUF_CACHE_SZ, build_caches, compute_data_room, compute_nb_mbuf};
use crate::worker::{StartGate, Worker, WorkerResult, WorkerStats};

const NB_TX_QUEUES: u16 = 64;
const TX_QUEUE_SIZE: u16 = 4096;
const TX_PTHRESH: u16 = 36;
const TX_FREE_THRESH: u16 = 32;
const GIB: u64 = 1024 * 1024 * 1024;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let invocation = Invocation::parse()?;
    invocation.validate()?;

    let port_specs = invocation.ports()?;
    let numa_node = invocation.numa_node();
    let eal_args = build_eal_args(&invocation, &port_specs, numa_node)?;

    println!("EAL args: {:?}", &eal_args[1..]);

    let eal = Eal::init(&eal_args).context("failed to initialize EAL")?;

    let worker_lcores = select_worker_lcores(&eal, port_specs.len())?;
    let meta = trace::scan(&invocation.app.pcap)?;

    println!(
        "trace: {} packets, max packet {} bytes, {} payload bytes, pcap {}.{}",
        meta.nb_pkts, meta.max_pkt_sz, meta.payload_bytes, meta.version.0, meta.version.1
    );
    println!("trace file size: {}", format_bytes(meta.file_size));

    if meta.truncated_pkts > 0 {
        println!(
            "warning: {} packet(s) were captured shorter than their original length; \
             only the captured bytes will be replayed",
            meta.truncated_pkts
        );
    }

    let socket_id = match numa_node {
        Some(node) => {
            i32::try_from(node).with_context(|| format!("NUMA node {node} cannot be passed to DPDK as a socket id"))?
        }
        None => -1,
    };

    let data_room = compute_data_room(meta.max_pkt_sz)?;
    let nb_mbuf = compute_nb_mbuf(meta.nb_pkts, port_specs.len())?;
    let pool_name = format!("dpdk_replay_{}", process::id());

    let pool = MemoryPool::pktmbuf_pool_on_socket(&eal, &pool_name, nb_mbuf, MBUF_CACHE_SZ, 0, data_room, socket_id)
        .with_context(|| {
            format!(
                "failed to create a mempool of {nb_mbuf} mbufs \
             (data room {data_room} bytes); check hugepages and available memory"
            )
        })?;

    let pool_info = pool.info();
    let estimated_bytes = pool_info.size as u64 * pool_info.elt_size as u64;

    println!(
        "-> Needed MBUF size: {} (data room {}, headroom {})",
        pool_info.elt_size, data_room, PACKET_HEADROOM
    );
    println!("-> Needed number of MBUFS: {}", pool_info.size);
    println!("-> Needed Memory = {}", format_bytes(estimated_bytes));
    println!("-> Needed Hugepages of 1 GiB = {}", hugepages_1g(estimated_bytes));

    let ports = resolve_ports(&port_specs, numa_node)?;
    let caches = build_caches(pool.as_ref(), &invocation.app.pcap, &meta, ports.len())?;
    let port_queues = setup_ports(&ports)?;

    let gate = Arc::new(StartGate::new());
    let mut results = Vec::with_capacity(ports.len());
    let mut workers = Vec::with_capacity(ports.len());

    for ((port_id, tx_queues), cache) in port_queues.into_iter().zip(caches) {
        let result = Arc::new(WorkerResult::new(
            port_id,
            invocation.app.nbruns,
            cache.packets.len() as u64,
            cache.total_bytes,
        ));

        results.push(result.clone());
        workers.push(Worker::new(
            tx_queues,
            invocation.app.nbruns,
            cache.packets,
            gate.clone(),
            result,
        ));
    }

    let mut scope = LcoreScope::new(&eal);
    let mut gate_guard = GateGuard {
        gate: gate.clone(),
        released: false,
    };

    for (worker, lcore_id) in workers.into_iter().zip(worker_lcores) {
        if let Err(err) = scope.spawn(lcore_id, move || worker.run()) {
            // Release already launched workers before `scope` waits for them.
            gate.abort();
            drop(scope);

            return Err(err).with_context(|| format!("failed to launch worker on lcore {lcore_id}"));
        }
    }

    if invocation.app.wait_enter {
        println!("Threads are ready, press ENTER to start sending packets.");

        let _ = io::stdout().flush();

        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
    }

    gate.go();
    gate_guard.released = true;
    let exits = scope.wait();

    let stats: Vec<WorkerStats> = results.iter().map(|result| result.stats()).collect();
    print_results(&stats);

    if exits.iter().any(|exit| !exit.is_ok()) {
        bail!("one or more replay workers failed; see the messages above");
    }

    Ok(())
}

fn build_eal_args(invocation: &Invocation, ports: &[PortSpec], numa_node: Option<u32>) -> Result<Vec<String>> {
    let mut eal_args = invocation.eal_args.clone();

    if !invocation.eal_has_core_option {
        let node = numa_node.unwrap_or(0);
        let needed = ports.len() + 1;
        let cpus = cpu::select_cpus(node, needed)?;
        let core_list = cpu::to_eal_core_list(&cpus);

        eal_args.push("-l".to_owned());
        eal_args.push(core_list);
        eal_args.push("--main-lcore".to_owned());
        eal_args.push(cpus[0].to_string());
    }

    if !invocation.eal_has_allow_option {
        for port in ports {
            if let Some(pci) = port.as_pci() {
                eal_args.push("-a".to_owned());
                eal_args.push(pci.to_owned());
            }
        }
    }

    if !invocation.explicit_eal {
        eal_args.push("-n".to_owned());
        eal_args.push("1".to_owned());
        eal_args.push("--proc-type".to_owned());
        eal_args.push("auto".to_owned());
        eal_args.push("--file-prefix".to_owned());
        eal_args.push(format!("dpdkreplay_{}", process::id()));
    }

    Ok(eal_args)
}

fn select_worker_lcores(eal: &Eal, needed: usize) -> Result<Vec<LcoreId>> {
    let main_lcore = eal.main_lcore();
    let workers: Vec<LcoreId> = eal
        .enabled_lcores()
        .into_iter()
        .filter(|lcore_id| *lcore_id != main_lcore)
        .collect();

    if workers.len() < needed {
        bail!(
            "EAL enabled {} worker lcore(s) besides main lcore {main_lcore}, \
             but {needed} are required (one per port); add more cores to -l/-c",
            workers.len()
        );
    }

    Ok(workers.into_iter().take(needed).collect())
}

fn resolve_ports(specs: &[PortSpec], numa_node: Option<u32>) -> Result<Vec<Port>> {
    let available = Port::available_count();

    if available == 0 {
        bail!("no available DPDK ethernet port; check --allow/-a and that the NIC is bound to DPDK");
    }

    let port_ids: Vec<PortId> = match specs.first() {
        Some(PortSpec::Id(_)) => specs
            .iter()
            .map(|spec| match spec {
                PortSpec::Id(id) => {
                    if *id >= available {
                        bail!(
                            "DPDK port {id} is out of range: {available} port(s) available (0..{})",
                            available - 1
                        );
                    }

                    Ok(*id)
                }
                PortSpec::Pci(_) => unreachable!("port list was validated as numeric"),
            })
            .collect::<Result<Vec<_>>>()?,
        Some(PortSpec::Pci(_)) => {
            if available as usize != specs.len() {
                bail!(
                    "wanted {} DPDK port(s), but EAL reports {available}; \
                     check the PCI addresses passed with -a/--allow",
                    specs.len()
                );
            }

            (0..available).collect()
        }
        None => bail!("no DPDK ports were specified"),
    };

    let mut seen = HashSet::new();
    let mut ports = Vec::with_capacity(port_ids.len());

    for id in port_ids {
        if !seen.insert(id) {
            bail!("duplicate DPDK port {id}");
        }

        let port = Port::open(id).with_context(|| format!("failed to open DPDK port {id}"))?;

        if let Some(node) = numa_node {
            let socket = port.socket_id();

            if socket >= 0 && socket as u32 != node {
                bail!("DPDK port {id} is on NUMA node {socket}, but --numacore is {node}");
            }

            if socket < 0 {
                println!("note: DPDK port {id} does not report a NUMA socket");
            }
        }

        ports.push(port);
    }

    Ok(ports)
}

fn setup_ports<'port>(ports: &'port [Port]) -> Result<Vec<(PortId, Vec<TxQueue<'port>>)>> {
    let mut result = Vec::with_capacity(ports.len());

    for port in ports {
        let info = port.info();
        let driver = info.driver_name().to_owned();

        if info.max_tx_queues == 0 {
            bail!("DPDK port {} reports no usable TX queues", port.id());
        }

        let nb_tx_queues = info.max_tx_queues.min(NB_TX_QUEUES);
        let limits = info.tx_desc_lim;
        let nb_tx_desc = choose_tx_desc(TX_QUEUE_SIZE, limits.nb_min, limits.nb_max, limits.nb_align);

        let txconf = TxQueueConfig::default()
            .with_nb_desc(nb_tx_desc)
            .with_thresh(TX_PTHRESH.min(nb_tx_desc / 2).max(1) as u8, 0, 0)
            .with_free_thresh(TX_FREE_THRESH.min(nb_tx_desc / 2));

        port.configure(0, nb_tx_queues, &PortConfig::default())
            .with_context(|| format!("failed to configure DPDK port {}", port.id()))?;

        let mut queues = Vec::with_capacity(nb_tx_queues as usize);

        for queue in 0..nb_tx_queues {
            queues.push(
                port.tx_queue_setup_with(queue, &txconf)
                    .with_context(|| format!("failed to set up TX queue {queue} on DPDK port {}", port.id()))?,
            );
        }

        port.start()
            .with_context(|| format!("failed to start DPDK port {}", port.id()))?;

        let link = port.link_nowait();

        println!(
            "-> NIC port {} ready (driver {driver}, {nb_tx_queues} TX queue(s), \
             {nb_tx_desc} descriptor(s), link {})",
            port.id(),
            if link.up() { "up" } else { "down" }
        );

        result.push((port.id(), queues));
    }

    Ok(result)
}

fn choose_tx_desc(base: u16, min: u16, max: u16, align: u16) -> u16 {
    let min = min.max(1);
    let max = if max == 0 { base } else { max };
    let mut count = base.min(max).max(min);
    let align = align.max(1);

    if align > 1 {
        let remainder = count % align;

        if remainder != 0 {
            count = count.saturating_sub(remainder);
        }

        if count < min {
            count = min;
        }
    }

    count.max(1)
}

fn print_results(stats: &[WorkerStats]) {
    let mut total_gbps = 0.0;
    let mut total_pps = 0.0;
    let mut total_packets = 0u64;
    let mut total_sent = 0u64;
    let mut total_dropped = 0u64;

    println!("RESULTS:");

    for worker in stats {
        println!(
            "[port {:02}]: {:.3} Gbit/s, {:.3} pps on {:.6} sec ({} pkts sent, {} dropped)",
            worker.port, worker.gbps, worker.pps, worker.duration_secs, worker.sent, worker.dropped
        );

        total_gbps += worker.gbps;
        total_pps += worker.pps;
        total_packets += worker.packets;
        total_sent += worker.sent;
        total_dropped += worker.dropped;
    }

    println!("-----");
    println!(
        "TOTAL        : {:.3} Gbit/s. {:.3} pps. {} packets sent.",
        total_gbps, total_pps, total_sent
    );

    let dropped_percent = if total_packets > 0 {
        total_dropped as f64 * 100.0 / total_packets as f64
    } else {
        0.0
    };

    println!(
        "Total dropped: {}/{} packets ({:.6}%)",
        total_dropped, total_packets, dropped_percent
    );
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

    let mut value = bytes as f64;
    let mut unit = 0;

    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.3} {}", UNITS[unit])
    }
}

fn hugepages_1g(bytes: u64) -> u64 {
    bytes.saturating_add(GIB - 1) / GIB
}

/// Abort waiting workers if the main lcore panics before opening the gate.
struct GateGuard {
    gate: Arc<StartGate>,
    released: bool,
}

impl Drop for GateGuard {
    fn drop(&mut self) {
        if !self.released {
            self.gate.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_byte_counts() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.500 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.000 MiB");
    }

    #[test]
    fn rounds_hugepage_counts_up() {
        assert_eq!(hugepages_1g(0), 0);
        assert_eq!(hugepages_1g(1), 1);
        assert_eq!(hugepages_1g(GIB), 1);
        assert_eq!(hugepages_1g(GIB + 1), 2);
    }

    #[test]
    fn clamps_descriptor_counts_to_device_limits() {
        assert_eq!(choose_tx_desc(4096, 0, 0, 0), 4096);
        assert_eq!(choose_tx_desc(4096, 64, 1024, 128), 1024);
        assert_eq!(choose_tx_desc(100, 64, 1024, 128), 64);
    }
}
