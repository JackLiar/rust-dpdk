//! Multi-process mbuf round trip over RTE rings.
//!
//! One process (the **primary**) creates a shared packet mbuf pool and two
//! rings, allocates a packet and sends it to the **secondary** through the
//! `p2s` ring. The secondary looks the pool and the rings up by name, reads the
//! packet, sends a reply through the `s2p` ring, and the primary receives it.
//!
//! It demonstrates the ownership dance a ring requires: an owning `Mbuf`
//! cannot be stored in a ring (rings copy elements and never run destructors),
//! so the sender transfers ownership with `Mbuf::into_raw()` and the receiver
//! rebuilds the handle with `MbufRing::dequeue()`, which re-binds the received
//! pointer to the looked-up pool and validates that it really belongs there.
//!
//! # Running
//!
//! DPDK multi-process requires shared hugepages, the same `--file-prefix`, and
//! disjoint lcore lists:
//!
//! ```text
//! sudo ./dpdk-hugepages.py -p 2M --setup 1G
//! source env.sh
//! target/debug/examples/mp_ring primary \
//!     --file-prefix=mpring -m 256 --no-pci --iova-mode=va -l 0 --proc-type=primary
//! target/debug/examples/mp_ring secondary \
//!     --file-prefix=mpring -m 256 --no-pci --iova-mode=va -l 1 --proc-type=secondary
//! ```
//!
//! Start the primary first; it prints `PRIMARY_READY` once the packet is on the
//! `p2s` ring. The convenience script `examples/mp_ring/run.sh` sequences the
//! two processes and checks the `PRIMARY_OK` / `SECONDARY_OK` markers.

use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rte::new::{
    DEFAULT_DATA_ROOM_SIZE, Eal, MBUF_PTR_SIZE, MbufRing, MemoryPool, Ring, RingError, RingFlags,
};

const POOL_NAME: &str = "mp_ring_pool";
const P2S_RING: &str = "mp_ring_p2s";
const S2P_RING: &str = "mp_ring_s2p";
const PING: &[u8] = b"ping from primary";
const PONG: &[u8] = b"pong from secondary";
const POOL_SIZE: u32 = 512;
const RING_CAPACITY: u32 = 128;
const TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

fn main() -> Result<()> {
    run()
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).cloned().unwrap_or_default();

    let mut eal_args = vec!["mp_ring".to_string()];
    eal_args.extend(args.iter().skip(2).cloned());

    let eal = Eal::init(&eal_args).context("failed to initialize the EAL")?;

    match mode.as_str() {
        "primary" => {
            if !eal.is_primary() {
                bail!("`primary` mode needs --proc-type=primary");
            }

            primary(&eal)
        }
        "secondary" => {
            if eal.is_primary() {
                bail!("`secondary` mode needs --proc-type=secondary (and a running primary)");
            }

            secondary(&eal)
        }
        _ => bail!("usage: mp_ring <primary|secondary> [EAL options...]"),
    }
}

/// Create the shared pool and rings, send the ping, wait for the pong.
fn primary(eal: &Eal) -> Result<()> {
    let pool = MemoryPool::pktmbuf_pool(eal, POOL_NAME, POOL_SIZE, 0, 0, DEFAULT_DATA_ROOM_SIZE)
        .context("failed to create the shared pktmbuf pool")?;
    let p2s = Ring::create_elem(eal, P2S_RING, MBUF_PTR_SIZE, RING_CAPACITY, RingFlags::empty())
        .context("failed to create the primary->secondary ring")?;
    let s2p = Ring::create_elem(eal, S2P_RING, MBUF_PTR_SIZE, RING_CAPACITY, RingFlags::empty())
        .context("failed to create the secondary->primary ring")?;

    let tx = MbufRing::new(p2s.as_ref(), pool.as_ref()).context("wrap the p2s ring")?;
    let rx = MbufRing::new(s2p.as_ref(), pool.as_ref()).context("wrap the s2p ring")?;

    let mut ping = pool.alloc_mbuf().context("allocate the ping packet")?;
    ping.set_data(PING).context("fill the ping packet")?;
    tx.enqueue(ping).context("send the ping packet")?;

    println!("PRIMARY_READY");
    std::io::stdout().flush().ok();

    let deadline = Instant::now() + TIMEOUT;
    loop {
        // SAFETY: this program is the only producer of `p2s` and the only
        // consumer of `s2p`, and every producer uses `MbufRing`.
        match unsafe { rx.dequeue() } {
            Ok(reply) => {
                if reply.data() != PONG {
                    bail!("unexpected reply payload {:?}", reply.data());
                }

                break;
            }
            Err(RingError::Empty { .. }) if Instant::now() < deadline => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(RingError::Empty { .. }) => bail!("timed out waiting for the secondary reply"),
            Err(err) => return Err(err).context("failed to receive the pong"),
        }
    }

    println!("PRIMARY_OK");

    // Give the secondary a moment to return from its own EAL cleanup before the
    // primary frees the shared pool and rings.
    std::thread::sleep(Duration::from_millis(500));

    Ok(())
}

/// Look the shared objects up by name, read the ping, send the pong.
fn secondary(eal: &Eal) -> Result<()> {
    // SAFETY: the primary is alive and created these objects; the wrapper's
    // lifetime keeps them alive for as long as this process uses them.
    let pool = unsafe { eal.pool(POOL_NAME) }.context("failed to look up the shared pktmbuf pool")?;
    let p2s = unsafe { eal.ring(P2S_RING, MBUF_PTR_SIZE) }.context("failed to look up the p2s ring")?;
    let s2p = unsafe { eal.ring(S2P_RING, MBUF_PTR_SIZE) }.context("failed to look up the s2p ring")?;

    let rx = MbufRing::new(p2s, pool).context("wrap the p2s ring")?;
    let tx = MbufRing::new(s2p, pool).context("wrap the s2p ring")?;

    let deadline = Instant::now() + TIMEOUT;
    let ping = loop {
        // SAFETY: every producer on this ring is an `MbufRing` of the same
        // shared pool (this program or its primary).
        match unsafe { rx.dequeue() } {
            Ok(packet) => break packet,
            Err(RingError::Empty { .. }) if Instant::now() < deadline => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(RingError::Empty { .. }) => bail!("timed out waiting for the primary packet"),
            Err(err) => return Err(err).context("failed to receive the ping"),
        }
    };

    if ping.data() != PING {
        bail!("unexpected ping payload {:?}", ping.data());
    }

    // Dropping the packet returns the buffer to the shared pool.
    drop(ping);

    let mut pong = pool.alloc_mbuf().context("allocate the pong packet")?;
    pong.set_data(PONG).context("fill the pong packet")?;
    tx.enqueue(pong).context("send the pong packet")?;

    println!("SECONDARY_OK");

    Ok(())
}
