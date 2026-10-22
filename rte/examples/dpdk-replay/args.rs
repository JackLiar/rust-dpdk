//! Command-line parsing and EAL argument construction.
//!
//! The program accepts two equivalent forms:
//!
//! ```text
//! dpdk-replay [OPTIONS] PCAP_FILE PORT1[,PORTX...]
//! dpdk-replay [EAL options] -- [OPTIONS] PCAP_FILE PORT1[,PORTX...]
//! ```
//!
//! When the first form is used, EAL options are generated from `--numacore`
//! and the PCI addresses. When the second form is used, the arguments before
//! `--` are forwarded to EAL verbatim and only missing core/allow options are
//! appended.

use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;

/// NUMA node used when neither `--numacore` nor explicit EAL core options are
/// given.
const DEFAULT_NUMA_NODE: u32 = 0;

#[derive(Debug, Parser)]
#[command(
    name = "dpdk-replay",
    version,
    about = "Replay a pcap file in bursts through one or more DPDK ports",
    long_about = None,
)]
pub struct AppArgs {
    /// Number of complete replays of the pcap file.
    #[arg(long, default_value_t = 1, value_name = "N")]
    pub nbruns: u16,

    /// NUMA node whose CPUs and NIC ports should be used.
    #[arg(long, value_name = "NODE")]
    pub numacore: Option<u32>,

    /// Wait for ENTER after initialisation before starting the replay.
    #[arg(long = "wait-enter")]
    pub wait_enter: bool,

    /// pcap file to replay.
    #[arg(value_name = "PCAP_FILE")]
    pub pcap: PathBuf,

    /// Comma-separated DPDK PCI addresses or numeric port ids.
    #[arg(value_name = "PORT1[,PORTX...]")]
    pub ports: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PortSpec {
    /// A PCI address passed to EAL with `-a`.
    Pci(String),
    /// A DPDK port id selected directly.
    Id(u16),
}

impl PortSpec {
    pub fn as_pci(&self) -> Option<&str> {
        match self {
            PortSpec::Pci(addr) => Some(addr),
            PortSpec::Id(_) => None,
        }
    }
}

pub struct Invocation {
    pub app: AppArgs,
    pub eal_args: Vec<String>,
    pub eal_has_core_option: bool,
    pub eal_has_allow_option: bool,
    /// True when the user supplied a `--` separator, i.e. opted out of the
    /// automatic EAL defaults (`-n`, `--proc-type`, `--file-prefix`).
    pub explicit_eal: bool,
}

impl Invocation {
    pub fn parse() -> Result<Self> {
        Self::from_os_args(env::args_os().collect())
    }

    /// Split raw argv at the first `--` and parse the application part with
    /// clap. The EAL part keeps argv[0].
    pub fn from_os_args(raw: Vec<OsString>) -> Result<Self> {
        if raw.is_empty() {
            bail!("missing program name in argv");
        }

        let delimiter = raw.iter().position(|arg| arg == "--");
        let explicit_eal = delimiter.is_some();
        let program = raw[0].clone();

        let (eal_raw, app_raw) = match delimiter {
            Some(pos) => {
                let mut app_args = Vec::with_capacity(raw.len() - pos);
                app_args.push(program);
                app_args.extend(raw[pos + 1..].iter().cloned());

                (raw[..pos].to_vec(), app_args)
            }
            None => (vec![program], raw),
        };

        let eal_args = eal_raw
            .iter()
            .map(|arg| {
                arg.to_str()
                    .map(ToOwned::to_owned)
                    .context("EAL arguments must be valid UTF-8")
            })
            .collect::<Result<Vec<_>>>()?;

        // clap handles `--help` and `--version` by printing and exiting.
        let app = AppArgs::parse_from(app_raw);

        let eal_has_core_option = has_core_option(&eal_args);
        let eal_has_allow_option = has_allow_option(&eal_args);

        Ok(Self {
            app,
            eal_args,
            eal_has_core_option,
            eal_has_allow_option,
            explicit_eal,
        })
    }

    /// Validate the application arguments that clap cannot express.
    pub fn validate(&self) -> Result<()> {
        if self.app.nbruns == 0 {
            bail!("--nbruns must be at least 1 (refcount is stored in a u16)");
        }

        let ports = self.ports()?;

        if self.eal_has_allow_option && ports.iter().any(|port| port.as_pci().is_some()) {
            bail!(
                "PCI port arguments cannot be combined with an explicit -a/--allow option; \
                 pass numeric DPDK port ids instead"
            );
        }

        Ok(())
    }

    pub fn ports(&self) -> Result<Vec<PortSpec>> {
        parse_ports(&self.app.ports)
    }

    /// NUMA node selected for CPU/port affinity.
    ///
    /// An explicit `--numacore` always wins. Otherwise node 0 is the default
    /// when the program generates the EAL core list; when the user supplied
    /// core options explicitly, no node is assumed.
    pub fn numa_node(&self) -> Option<u32> {
        self.app.numacore.or_else(|| {
            if self.eal_has_core_option {
                None
            } else {
                Some(DEFAULT_NUMA_NODE)
            }
        })
    }
}

fn has_core_option(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "--lcores"
            || arg.starts_with("--lcores=")
            || (arg.starts_with("-l") && !arg.starts_with("--"))
            || (arg.starts_with("-c") && !arg.starts_with("--"))
    })
}

fn has_allow_option(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "--allow"
            || arg == "--pci-whitelist"
            || arg.starts_with("--allow=")
            || arg.starts_with("--pci-whitelist=")
            || (arg.starts_with("-a") && !arg.starts_with("--"))
            || (arg.starts_with("-w") && !arg.starts_with("--"))
    })
}

fn parse_ports(input: &str) -> Result<Vec<PortSpec>> {
    let tokens: Vec<&str> = input.split(',').map(str::trim).collect();

    if tokens.is_empty() || tokens.iter().any(|token| token.is_empty()) {
        bail!("the port list is empty or contains an empty entry");
    }

    let pci_count = tokens.iter().filter(|token| token.contains(':')).count();

    let ports = if pci_count == tokens.len() {
        tokens.iter().map(|token| PortSpec::Pci((*token).to_owned())).collect()
    } else if pci_count == 0 {
        tokens
            .iter()
            .map(|token| {
                token
                    .parse::<u16>()
                    .map(PortSpec::Id)
                    .with_context(|| format!("invalid DPDK port id: {token}"))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        bail!("cannot mix PCI addresses and numeric DPDK port ids in one port list");
    };

    let mut seen = HashSet::new();
    for port in &ports {
        if !seen.insert(port.clone()) {
            bail!("duplicate port in port list: {port:?}");
        }
    }

    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_simple_invocation() {
        let invocation = Invocation::from_os_args(argv(&["prog", "--nbruns", "3", "trace.pcap", "0,1"])).unwrap();

        assert_eq!(invocation.app.nbruns, 3);
        assert_eq!(invocation.app.pcap, PathBuf::from("trace.pcap"));
        assert_eq!(invocation.ports().unwrap(), vec![PortSpec::Id(0), PortSpec::Id(1)]);
        assert_eq!(invocation.eal_args, vec!["prog".to_owned()]);
        assert!(!invocation.explicit_eal);
        assert_eq!(invocation.numa_node(), Some(DEFAULT_NUMA_NODE));
    }

    #[test]
    fn splits_eal_and_application_arguments() {
        let invocation = Invocation::from_os_args(argv(&[
            "prog",
            "-l",
            "0-1",
            "--no-huge",
            "--",
            "--wait-enter",
            "trace.pcap",
            "0000:04:00.0",
        ]))
        .unwrap();

        assert_eq!(
            invocation.eal_args,
            vec![
                "prog".to_owned(),
                "-l".to_owned(),
                "0-1".to_owned(),
                "--no-huge".to_owned()
            ]
        );
        assert!(invocation.explicit_eal);
        assert!(invocation.eal_has_core_option);
        assert!(invocation.app.wait_enter);
        assert_eq!(invocation.numa_node(), None);
        assert_eq!(
            invocation.ports().unwrap(),
            vec![PortSpec::Pci("0000:04:00.0".to_owned())]
        );
    }

    #[test]
    fn detects_concatenated_core_and_allow_options() {
        let invocation =
            Invocation::from_os_args(argv(&["prog", "-l0-3", "-a0000:04:00.0", "--", "trace.pcap", "0"])).unwrap();

        assert!(invocation.eal_has_core_option);
        assert!(invocation.eal_has_allow_option);
    }

    #[test]
    fn parses_pci_and_numeric_ports() {
        assert_eq!(
            parse_ports("0000:04:00.0,0000:04:00.1").unwrap(),
            vec![
                PortSpec::Pci("0000:04:00.0".to_owned()),
                PortSpec::Pci("0000:04:00.1".to_owned())
            ]
        );
        assert_eq!(
            parse_ports("0, 1,2").unwrap(),
            vec![PortSpec::Id(0), PortSpec::Id(1), PortSpec::Id(2)]
        );
    }

    #[test]
    fn rejects_mixed_or_duplicate_ports() {
        assert!(parse_ports("0,0000:04:00.0").is_err());
        assert!(parse_ports("0,0").is_err());
        assert!(parse_ports("0,,1").is_err());
        assert!(parse_ports("not-a-port").is_err());
    }

    #[test]
    fn rejects_zero_runs() {
        let invocation = Invocation::from_os_args(argv(&["prog", "--nbruns", "0", "trace.pcap", "0"])).unwrap();

        assert!(invocation.validate().is_err());
    }

    #[test]
    fn rejects_pci_ports_with_explicit_allow() {
        let invocation = Invocation::from_os_args(argv(&[
            "prog",
            "-a",
            "0000:04:00.0",
            "--",
            "trace.pcap",
            "0000:04:00.1",
        ]))
        .unwrap();

        assert!(invocation.validate().is_err());
    }
}
