//! NUMA CPU discovery and EAL core-list generation.
//!
//! The C original used libnuma. We only need the CPU list of one NUMA node,
//! which Linux exposes through sysfs, so no extra system dependency is needed.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// Select `needed` CPUs from NUMA `node`, ascending.
pub fn select_cpus(node: u32, needed: usize) -> Result<Vec<u32>> {
    if needed == 0 {
        bail!("at least one CPU must be selected");
    }

    let path = PathBuf::from(format!("/sys/devices/system/node/node{node}/cpulist"));
    let text = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {} (is NUMA node {node} present?)", path.display()))?;
    let cpus = parse_cpu_list(&text)?;

    if cpus.len() < needed {
        bail!(
            "NUMA node {node} only has {} usable CPU(s), but {needed} are required \
             (one main lcore plus one worker per port)",
            cpus.len()
        );
    }

    Ok(cpus.into_iter().take(needed).collect())
}

/// Parse a Linux CPU list such as `0-3,8,10-11`.
pub fn parse_cpu_list(input: &str) -> Result<Vec<u32>> {
    let mut cpus = BTreeSet::new();

    for item in input.trim().split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }

        if let Some((start, end)) = item.split_once('-') {
            let start: u32 = start
                .trim()
                .parse()
                .with_context(|| format!("invalid CPU range start: {item}"))?;
            let end: u32 = end
                .trim()
                .parse()
                .with_context(|| format!("invalid CPU range end: {item}"))?;

            if start > end {
                bail!("invalid CPU range (start > end): {item}");
            }

            for cpu in start..=end {
                cpus.insert(cpu);
            }
        } else {
            let cpu: u32 = item.parse().with_context(|| format!("invalid CPU id: {item}"))?;
            cpus.insert(cpu);
        }
    }

    if cpus.is_empty() {
        bail!("CPU list is empty");
    }

    Ok(cpus.into_iter().collect())
}

/// Render sorted CPU ids as an EAL `-l` core list, merging consecutive ids.
pub fn to_eal_core_list(cpus: &[u32]) -> String {
    let mut sorted: Vec<u32> = cpus.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut parts = Vec::new();
    let mut index = 0;

    while index < sorted.len() {
        let start = sorted[index];
        let mut end = start;

        while index + 1 < sorted.len() && sorted[index + 1] == end.saturating_add(1) {
            index += 1;
            end = sorted[index];
        }

        if start == end {
            parts.push(start.to_string());
        } else {
            parts.push(format!("{start}-{end}"));
        }

        index += 1;
    }

    parts.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges_and_single_ids() {
        assert_eq!(parse_cpu_list("0-3,8,10-11\n").unwrap(), vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(parse_cpu_list("4").unwrap(), vec![4]);
        assert_eq!(parse_cpu_list("2,1,2").unwrap(), vec![1, 2]);
    }

    #[test]
    fn rejects_invalid_lists() {
        assert!(parse_cpu_list("").is_err());
        assert!(parse_cpu_list("3-1").is_err());
        assert!(parse_cpu_list("a-b").is_err());
        assert!(parse_cpu_list("1,").is_ok());
    }

    #[test]
    fn renders_compressed_core_lists() {
        assert_eq!(to_eal_core_list(&[0, 1, 2, 3, 8, 10, 11]), "0-3,8,10-11");
        assert_eq!(to_eal_core_list(&[5]), "5");
        assert_eq!(to_eal_core_list(&[1, 3, 2, 3]), "1-3");
    }

    #[test]
    fn zero_needed_cpus_is_rejected() {
        assert!(select_cpus(0, 0).is_err());
    }
}
