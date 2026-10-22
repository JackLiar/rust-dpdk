//! pcap reading built on the `pcap` crate (libpcap).
//!
//! The file is read twice:
//!
//! 1. [`scan`] counts packets, finds the largest captured frame and sums the
//!    payload bytes so the mempool can be sized before anything is allocated.
//! 2. [`for_each_packet`] re-opens the file and hands each frame to the caller,
//!    which copies it straight into the per-port mbuf caches.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Result, anyhow, bail};
use pcap::{Capture, Error as PcapError, Linktype, Offline};
use rte::new::MAX_PACKET_SIZE;

pub struct TraceMeta {
    pub nb_pkts: u64,
    pub max_pkt_sz: u32,
    pub payload_bytes: u64,
    pub file_size: u64,
    pub version: (i32, i32),
    pub truncated_pkts: u64,
}

fn open(path: &Path) -> Result<Capture<Offline>> {
    let capture = Capture::from_file(path).map_err(|err| anyhow!("failed to open pcap {}: {err}", path.display()))?;
    let linktype = capture.get_datalink();

    if linktype != Linktype::ETHERNET {
        bail!("unsupported pcap datalink {linktype:?}; only Ethernet (LINKTYPE_ETHERNET) is supported");
    }

    Ok(capture)
}

fn next_packet<'a>(capture: &'a mut Capture<Offline>, path: &Path) -> Result<Option<pcap::Packet<'a>>> {
    match capture.next_packet() {
        Ok(packet) => Ok(Some(packet)),
        Err(PcapError::NoMorePackets) => Ok(None),
        Err(err) => Err(anyhow!("failed to read pcap {}: {err}", path.display())),
    }
}

pub fn scan(path: &Path) -> Result<TraceMeta> {
    let mut capture = open(path)?;
    let version = capture.version();
    let file_size = fs::metadata(path).map(|metadata| metadata.len()).unwrap_or_default();

    let mut nb_pkts = 0u64;
    let mut max_pkt_sz = 0u32;
    let mut payload_bytes = 0u64;
    let mut truncated_pkts = 0u64;

    while let Some(packet) = next_packet(&mut capture, path)? {
        let caplen = packet.header.caplen;

        if caplen > MAX_PACKET_SIZE as u32 {
            bail!(
                "packet #{} has captured length {caplen}, but the maximum supported frame is {} bytes",
                nb_pkts + 1,
                MAX_PACKET_SIZE
            );
        }

        if packet.header.len > caplen {
            truncated_pkts += 1;
        }

        nb_pkts += 1;
        max_pkt_sz = max_pkt_sz.max(caplen);
        payload_bytes += caplen as u64;
    }

    if nb_pkts == 0 {
        bail!("pcap {} contains no packets", path.display());
    }

    Ok(TraceMeta {
        nb_pkts,
        max_pkt_sz,
        payload_bytes,
        file_size,
        version,
        truncated_pkts,
    })
}

pub fn for_each_packet<F>(path: &Path, expected_pkts: u64, mut callback: F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut capture = open(path)?;
    let mut count = 0u64;
    let show_progress = expected_pkts >= 1024;

    while let Some(packet) = next_packet(&mut capture, path)? {
        count += 1;

        if count > expected_pkts {
            bail!(
                "pcap {} changed while it was being read: more than the {expected_pkts} packets found by the first pass",
                path.display()
            );
        }

        callback(packet.data)?;

        if show_progress && count % 1024 == 0 {
            print!("\rread {count}/{expected_pkts} packets");
            let _ = io::stdout().flush();
        }
    }

    if count != expected_pkts {
        bail!(
            "pcap {} changed while it was being read: expected {expected_pkts} packets, read {count}",
            path.display()
        );
    }

    if show_progress {
        println!("\rread {count}/{expected_pkts} packets");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use pcap::{Capture, Linktype, Packet, PacketHeader};

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();

        std::env::temp_dir().join(format!("dpdk-replay-{}-{name}-{stamp}.pcap", std::process::id()))
    }

    fn write_pcap(path: &Path, linktype: Linktype, packets: &[&[u8]]) -> Result<()> {
        let capture = Capture::dead(linktype).map_err(|err| anyhow!("failed to create dead pcap handle: {err}"))?;
        let mut savefile = capture
            .savefile(path)
            .map_err(|err| anyhow!("failed to create {}: {err}", path.display()))?;

        for data in packets {
            let header = PacketHeader {
                ts: libc::timeval { tv_sec: 0, tv_usec: 0 },
                caplen: data.len() as u32,
                len: data.len() as u32,
            };
            let packet = Packet { header: &header, data };

            savefile.write(&packet);
        }

        savefile
            .flush()
            .map_err(|err| anyhow!("failed to flush {}: {err}", path.display()))?;

        Ok(())
    }

    #[test]
    fn scans_and_iterates_an_ethernet_pcap() {
        let path = temp_path("ethernet");
        let first = [0x11u8; 60];
        let second = [0x22u8; 100];

        write_pcap(&path, Linktype::ETHERNET, &[&first, &second]).unwrap();

        let meta = scan(&path).unwrap();
        assert_eq!(meta.nb_pkts, 2);
        assert_eq!(meta.max_pkt_sz, 100);
        assert_eq!(meta.payload_bytes, 160);
        assert_eq!(meta.truncated_pkts, 0);

        let mut lengths = Vec::new();
        for_each_packet(&path, 2, |data| {
            lengths.push(data.len());
            Ok(())
        })
        .unwrap();
        assert_eq!(lengths, vec![60, 100]);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rejects_non_ethernet_linktype() {
        let path = temp_path("null");
        let packet = [0u8; 4];

        write_pcap(&path, Linktype::NULL, &[&packet]).unwrap();
        assert!(scan(&path).is_err());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rejects_empty_pcap() {
        let path = temp_path("empty");

        write_pcap(&path, Linktype::ETHERNET, &[]).unwrap();
        assert!(scan(&path).is_err());

        let _ = fs::remove_file(&path);
    }
}
