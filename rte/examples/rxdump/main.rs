//! A minimal DPDK RX-only example built on `rte::new`.
//!
//! It receives packets from a single DPDK port / single RX queue and prints the
//! timestamp and the length of every received packet to the command line.
//!
//! By default the timestamp is the software receive time (UTC, when
//! `rx_burst()` returned the packet). With `-t` the NIC hardware RX timestamp
//! is requested instead: the timestamp dynamic field/flag is registered with
//! [`RxTimestamp::register`] and the matching port offload is enabled through
//! [`PortConfig::with_rx_offloads`]. Packets that do not carry the hardware
//! timestamp flag fall back to the software time and are marked as such.
//!
//! Everything DPDK related comes from [`rte::new`], which encodes the ownership
//! and lifetime rules in the type system:
//!
//! * `Eal` owns the EAL and tears it down on drop,
//! * `MemoryPool` owns the mbuf pool and frees it on drop,
//! * `RxQueue` borrows both the port and the pool,
//! * `Mbuf` borrows the pool and frees the packet on drop.
//!
//! As a result the teardown order (queue → port → pool → EAL) is enforced by
//! ordinary lexical scoping; there is no manual `stop`/`close`/`free` anywhere.
//!
//! EAL options go before `--`, this program's options after it:
//!
//! ```text
//! sudo env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" ./target/debug/examples/rxdump \
//!     -l 0 -n 4 --no-huge --legacy-mem -- -p 0 [-t]
//! ```

use std::env;
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rte::new::{DEFAULT_DATA_ROOM_SIZE, Eal, Mbuf, MemoryPool, Port, PortConfig, RxTimestamp};

const NB_MBUF: u32 = 8192;
const MBUF_CACHE: u32 = 256;
const RX_DESC: u16 = 1024;
const MAX_PKT_BURST: usize = 32;

/// Set from the signal handler, checked by the RX polling loop.
static QUIT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    QUIT.store(true, Ordering::SeqCst);
}

struct Args {
    port: u16,
    hw_timestamp: bool,
}

fn print_usage(opts: &getopts::Options, code: i32) -> ! {
    eprintln!("{}", opts.usage("Usage: rxdump [EAL options] -- [options]"));

    process::exit(code);
}

/// Print an error and exit non-zero.
fn fail(msg: &str) -> ! {
    eprintln!("error: {}", msg);

    process::exit(1);
}

fn parse_app_args(args: &[String]) -> Args {
    let mut opts = getopts::Options::new();

    opts.optopt("p", "port", "DPDK port id to receive from (default: 0)", "PORT");
    opts.optflag("t", "hw-timestamp", "use the NIC hardware RX timestamp");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(args) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("invalid arguments: {}", err);

            print_usage(&opts, 2);
        }
    };

    if matches.opt_present("h") {
        print_usage(&opts, 0);
    }

    let port = match matches.opt_str("p") {
        Some(arg) => match arg.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                eprintln!("invalid port: {}", arg);

                print_usage(&opts, 2);
            }
        },
        None => 0,
    };

    Args {
        port,
        hw_timestamp: matches.opt_present("t"),
    }
}

/// Format a wall-clock instant as `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ` in UTC.
fn format_ts(t: SystemTime) -> String {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs() as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let mut buf = [0 as libc::c_char; 32];

    // gmtime_r(3) and strftime(3) from libc, so no extra date/time dependency.
    let n = unsafe {
        if libc::gmtime_r(&secs, &mut tm).is_null() {
            0
        } else {
            libc::strftime(
                buf.as_mut_ptr(),
                buf.len(),
                b"%Y-%m-%dT%H:%M:%S\0".as_ptr() as *const libc::c_char,
                &tm,
            )
        }
    };

    let datetime = if n > 0 {
        std::str::from_utf8(unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) })
            .unwrap_or("?")
            .to_string()
    } else {
        dur.as_secs().to_string()
    };

    format!("{}.{:09}Z", datetime, dur.subsec_nanos())
}

fn main() {
    let raw: Vec<String> = env::args().collect();
    let program = Path::new(&raw[0])
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("rxdump")
        .to_string();

    // EAL options live before `--`, our own options after it.
    let (eal_args, app_args) = match raw.iter().position(|arg| arg == "--") {
        Some(pos) => (raw[..pos].to_vec(), raw[pos + 1..].to_vec()),
        None => (raw.clone(), Vec::new()),
    };

    let mut opt_args = vec![program];
    opt_args.extend(app_args);

    let args = parse_app_args(&opt_args[1..]);

    if !eal_args.is_empty() {
        println!("EAL args: {:?}", &eal_args[1..]);
    }

    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }

    // Owns the EAL: dropped last, after every pool and port created below.
    let eal = match Eal::init(&eal_args) {
        Ok(eal) => eal,
        Err(err) => fail(&err.to_string()),
    };

    // The hardware timestamp lives in a dynamic mbuf field which must be
    // registered before any port is configured.
    let hw_ts = if args.hw_timestamp {
        match RxTimestamp::register() {
            Ok(ts) => {
                println!(
                    "hardware RX timestamp registered: field_offset={}, rx_flag={:#x}",
                    ts.field_offset(),
                    ts.flag()
                );

                Some(ts)
            }
            Err(err) => fail(&err.to_string()),
        }
    } else {
        None
    };

    // Owns the mbuf pool: dropped after the queue and port, before the EAL.
    let pool = match MemoryPool::pktmbuf_pool(&eal, "rx_pool", NB_MBUF, MBUF_CACHE, 0, DEFAULT_DATA_ROOM_SIZE) {
        Ok(pool) => pool,
        Err(err) => fail(&format!("fail to create the mbuf pool: {err}")),
    };

    let nb_ports = Port::available_count();

    if nb_ports == 0 {
        fail("no available DPDK ethernet port");
    }

    if args.port >= nb_ports {
        eprintln!(
            "port {} is not available, {} port(s) detected (0..{})",
            args.port,
            nb_ports,
            nb_ports - 1
        );

        process::exit(1);
    }

    // Owns the port: `Drop` stops and closes it after the queue is gone.
    let port = match Port::open(args.port) {
        Ok(port) => port,
        Err(err) => fail(&err.to_string()),
    };

    let info = port.info();

    println!(
        "port {}: driver={} mac={}",
        port.id(),
        info.driver_name(),
        port.mac_addr()
    );

    let conf = match hw_ts {
        Some(ts) => {
            if info.rx_offload_capa & ts.port_offload() == 0 {
                fail("the PMD does not support DEV_RX_OFFLOAD_TIMESTAMP");
            }

            PortConfig::default().with_rx_offloads(ts.port_offload())
        }
        None => PortConfig::default(),
    };

    if let Err(err) = port.configure(1, 0, &conf) {
        fail(&err.to_string());
    }

    // Borrows the port *and* the pool: neither can be torn down while it lives.
    let queue = match port.rx_queue_setup(0, RX_DESC, None, pool.as_ref()) {
        Ok(queue) => queue,
        Err(err) => fail(&err.to_string()),
    };

    if let Err(err) = port.start() {
        fail(&err.to_string());
    }

    if let Err(err) = port.promiscuous_enable() {
        fail(&err.to_string());
    }

    let link = port.link();

    println!(
        "link: {} ({} Mbps, {})",
        if link.up() { "up" } else { "down" },
        link.speed(),
        if link.duplex() { "full-duplex" } else { "half-duplex" }
    );

    if hw_ts.is_some() {
        if let Ok(clock) = port.read_clock() {
            println!("device clock base: {}", clock);
        }
    }

    println!("listening on port {} (Ctrl-C to stop)...", port.id());

    // Each `Mbuf` borrows the pool; `take()`-ing them keeps this buffer empty
    // for the next burst, which `rx_burst()` relies on.
    let mut bufs: [Option<Mbuf<'_>>; MAX_PKT_BURST] = std::array::from_fn(|_| None);
    let mut seq: u64 = 0;
    let mut total_pkts: u64 = 0;
    let mut total_bytes: u64 = 0;

    while !QUIT.load(Ordering::SeqCst) {
        let n = queue.rx_burst(&mut bufs);

        for pkt in bufs[..n].iter_mut().filter_map(Option::take) {
            seq += 1;
            total_pkts += 1;
            total_bytes += pkt.pkt_len() as u64;

            let hw = hw_ts.and_then(|ts| ts.get(&pkt));

            match hw {
                Some(hw) => println!(
                    "#{} ts={} hw={} len={} (data_len={}) port={}",
                    seq,
                    format_ts(SystemTime::now()),
                    hw,
                    pkt.pkt_len(),
                    pkt.data_len(),
                    pkt.port()
                ),
                None if args.hw_timestamp => println!(
                    "#{} ts={} hw=n/a len={} (data_len={}) port={} [sw fallback]",
                    seq,
                    format_ts(SystemTime::now()),
                    pkt.pkt_len(),
                    pkt.data_len(),
                    pkt.port()
                ),
                None => println!(
                    "#{} ts={} len={} (data_len={}) port={}",
                    seq,
                    format_ts(SystemTime::now()),
                    pkt.pkt_len(),
                    pkt.data_len(),
                    pkt.port()
                ),
            }
        }
    }

    println!(
        "\nstopping... received {} packet(s), {} byte(s)",
        total_pkts, total_bytes
    );

    // `queue`, `port`, `pool` and `eal` are dropped here in reverse declaration
    // order, which is exactly the order DPDK requires.
}
