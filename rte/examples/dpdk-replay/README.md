# dpdk-replay (Rust)

A Rust reimplementation of [dpdk-burst-replay](https://github.com/FraudBuster/dpdk-burst-replay),
built entirely on the ownership-correct `rte::new` API in this repository. It
caches a pcap trace in a DPDK mempool and replays it in bursts through one or
more DPDK ports.

Compared with the C original:

- command-line parsing uses [`clap`](https://crates.io/crates/clap);
- pcap/pcapng reading uses the [`pcap`](https://crates.io/crates/pcap) crate
  (libpcap) instead of a built-in pcap parser;
- NUMA CPU discovery uses Linux sysfs instead of libnuma;
- EAL arguments are generated with the modern `-l`, `--main-lcore` and `-a`
  options, and can also be passed explicitly before `--`;
- DPDK access goes through `rte::new` (`Eal`, `MemoryPool`, `Mbuf`, `Port`,
  `TxQueue`, `LcoreScope`) instead of the legacy wrappers;
- the reported bitrate is based on captured packet bytes, not pcap record
  headers.

The example also exercises the TX/lcore additions made to `rte::new`:
`Port::tx_queue_setup_with()`, `TxQueue::tx_burst()`, `Mbuf::set_data()`,
`Mbuf::clone()`, `LcoreId` and `LcoreScope`.

## Build

libpcap is required by the `pcap` crate. The DPDK package installed by xmake is
built with `net/pcap`, so `env.sh` already exports the matching
`PKG_CONFIG_PATH` / `LD_LIBRARY_PATH`:

```bash
xmake -y
source env.sh
cargo build --example dpdk-replay
```

If `pkg-config --modversion libpcap` fails in your environment, install libpcap
and point `PKG_CONFIG_PATH` (or `LIBPCAP_LIBDIR`) at it.

The binary is written to `target/debug/examples/dpdk-replay`.

## Requirements

- Linux with hugepages configured and enough memory for the whole trace.
- The target NIC ports must be bound to a DPDK-compatible driver, for example
  with `dpdk-devbind.py`.
- Root or the usual VFIO/UIO permissions.
- Hugepage memory sized for all cached packets: the program prints the
  estimated requirement before allocating the mempool.

## Usage

```text
dpdk-replay [OPTIONS] PCAP_FILE PORT1[,PORTX...]
dpdk-replay [EAL options] -- [OPTIONS] PCAP_FILE PORT1[,PORTX...]
```

Options:

| Option | Description |
|---|---|
| `--nbruns <N>` | Number of complete replays (default: 1) |
| `--numacore <NODE>` | NUMA node for lcores, mempool and NIC ports (default: 0 when EAL cores are generated) |
| `--wait-enter` | Wait for ENTER after initialisation before sending |
| `-h, --help` | Print help |

`PORTS` is either a comma-separated list of PCI addresses (for example
`0000:04:00.0,0000:04:00.1`) or numeric DPDK port ids (for example `0,1`).
Do not mix the two forms in one invocation.

### Examples

Replay a trace once on one port:

```bash
sudo -E target/debug/examples/dpdk-replay trace.pcap 0000:04:00.0
```

Replay a thousand times on four ports from NUMA node 0:

```bash
sudo -E target/debug/examples/dpdk-replay \
    --nbruns 1000 --numacore 0 \
    trace.pcap 0000:04:00.0,0000:04:00.1,0000:04:00.2,0000:04:00.3
```

Prepare everything, then start on ENTER:

```bash
sudo -E target/debug/examples/dpdk-replay --wait-enter trace.pcap 0000:04:00.0
```

Pass EAL options explicitly. In this mode the program uses numeric DPDK port
ids and does not add its own `-l`, `-a`, `-n`, `--proc-type` or
`--file-prefix` arguments:

```bash
sudo -E target/debug/examples/dpdk-replay \
    --no-huge --vdev=net_null0 -l 0-1 -- trace.pcap 0
```

## How it works

1. The trace is scanned once to count packets, find the largest captured frame
   and size the mempool.
2. One mbuf cache per port is filled from a second read of the trace. Packet
   data is written with the safe `Mbuf::set_data()` API, keeping the mbuf
   headroom.
3. One `LcoreScope` task per port sends the trace in bursts of 128 packets over
   up to 64 `TxQueue`s, retrying failed bursts up to 128 times.
4. For each replay pass, the cached mbufs are cheaply `clone()`d and handed to
   `TxQueue::tx_burst()`. Accepted clones are transferred to the PMD; rejected
   clones are dropped and counted as packet drops, while the cache originals
   remain valid for the next pass.
5. Per-port and aggregate Gbit/s, pps, duration and drop counts are printed.

## Limitations

- Only Ethernet (`LINKTYPE_ETHERNET`) traces are accepted.
- Captured frame length must fit in `rte::new::MAX_PACKET_SIZE`, which is
  `u16::MAX - PACKET_HEADROOM` (65407 bytes with the default 128-byte headroom).
- `--nbruns` must fit in a `u16`.
- The trace must be a regular file that can be opened twice; it is read once to
  size the pool and once to populate it.
- `--maxbitrate` and replay according to pcap timestamps are not implemented,
  matching the C original's TODO list.
