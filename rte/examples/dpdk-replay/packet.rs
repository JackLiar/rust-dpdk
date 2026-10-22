//! Per-port packet caches built with the ownership-correct `rte::new` API.

use std::path::Path;

use anyhow::{Context, Result, anyhow};

use rte::new::{DEFAULT_DATA_ROOM_SIZE, Mbuf, MemoryPoolRef, PACKET_HEADROOM};

use crate::trace::{self, TraceMeta};

pub const MBUF_CACHE_SZ: u32 = 32;
const MIN_MBUF_COUNT: u64 = 128;

pub struct PacketCache<'pool> {
    pub packets: Vec<Mbuf<'pool>>,
    pub total_bytes: u64,
}

impl<'pool> PacketCache<'pool> {
    fn with_capacity(packets: usize) -> Self {
        Self {
            packets: Vec::with_capacity(packets),
            total_bytes: 0,
        }
    }
}

/// Read the trace once more and build one mbuf cache per port.
pub fn build_caches<'pool>(
    pool: MemoryPoolRef<'pool>,
    path: &Path,
    meta: &TraceMeta,
    nb_ports: usize,
) -> Result<Vec<PacketCache<'pool>>> {
    let capacity =
        usize::try_from(meta.nb_pkts).context("pcap contains more packets than this platform can address")?;

    let mut caches: Vec<PacketCache<'pool>> = (0..nb_ports).map(|_| PacketCache::with_capacity(capacity)).collect();

    trace::for_each_packet(path, meta.nb_pkts, |payload| {
        for cache in caches.iter_mut() {
            let mut mbuf = pool
                .alloc_mbuf()
                .map_err(|err| anyhow!("failed to allocate an mbuf: {err}"))?;

            mbuf.set_data(payload)
                .map_err(|err| anyhow!("failed to copy a pcap packet into an mbuf: {err}"))?;

            cache.packets.push(mbuf);
            cache.total_bytes += payload.len() as u64;
        }

        Ok(())
    })?;

    Ok(caches)
}

/// Data room (including headroom) needed for the largest captured frame.
pub fn compute_data_room(max_pkt_sz: u32) -> Result<u16> {
    let default_payload_room = (DEFAULT_DATA_ROOM_SIZE - PACKET_HEADROOM) as u32;
    let payload_room = max_pkt_sz.max(default_payload_room);
    let data_room = payload_room
        .checked_add(PACKET_HEADROOM as u32)
        .context("packet size overflows the mbuf data room")?;

    u16::try_from(data_room)
        .with_context(|| format!("maximum frame size {max_pkt_sz} cannot be represented as a u16 data room"))
}

pub fn compute_nb_mbuf(nb_pkts: u64, nb_ports: usize) -> Result<u32> {
    let ports = u64::try_from(nb_ports).context("port count does not fit in u64")?;
    let total = nb_pkts
        .checked_mul(ports)
        .context("packet count times port count overflows u64")?
        .max(MIN_MBUF_COUNT);

    u32::try_from(total).with_context(|| format!("mempool would need {total} mbufs, which does not fit in a u32"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_room_uses_the_default_as_a_floor() {
        assert_eq!(compute_data_room(64).unwrap(), DEFAULT_DATA_ROOM_SIZE);
        assert_eq!(compute_data_room(9000).unwrap(), 9000 + PACKET_HEADROOM);
        assert_eq!(compute_data_room(rte::new::MAX_PACKET_SIZE as u32).unwrap(), u16::MAX);
        assert!(compute_data_room(rte::new::MAX_PACKET_SIZE as u32 + 1).is_err());
    }

    #[test]
    fn mbuf_count_has_a_minimum_and_checks_overflow() {
        assert_eq!(compute_nb_mbuf(1, 1).unwrap(), MIN_MBUF_COUNT as u32);
        assert_eq!(compute_nb_mbuf(1000, 2).unwrap(), 2000);
        assert!(compute_nb_mbuf(u64::MAX, 2).is_err());
    }
}
