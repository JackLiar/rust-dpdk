//! End to end tests for the `rte::new` wrappers.
//!
//! The EAL is a process wide singleton, so there must be exactly one test that
//! initialises it. Everything is therefore covered by [`end_to_end`], which
//! uses the `net_null` virtual PMD so it needs neither a real NIC nor root.
//!
//! Run with:
//!
//! ```text
//! source env.sh
//! mkdir -p .rt && chmod 700 .rt
//! XDG_RUNTIME_DIR="$PWD/.rt" cargo test -p rte --lib 'new::' -- --nocapture
//! ```
//!
//! Set `RTE_NEW_TEST_EAL_ARGS` to override the default EAL arguments.

use core::ops::ControlFlow;
use core::ptr::NonNull;

use super::*;

/// A 64 byte element with a recognisable initialisation tag.
#[repr(C, align(64))]
#[derive(Debug, PartialEq, Eq)]
struct Slot {
    magic: u64,
}

const MAGIC: u64 = 0xC0FFEE;

// SAFETY: `ELT_SIZE` matches `size_of::<Slot>()`, and `init` writes a valid
// `Slot` into the uninitialised storage without panicking.
unsafe impl PoolElement for Slot {
    const ELT_SIZE: usize = core::mem::size_of::<Slot>();

    unsafe fn init(obj: NonNull<Slot>) {
        unsafe { obj.as_ptr().write(Slot { magic: MAGIC }) };
    }
}

fn eal_args() -> Vec<String> {
    std::env::var("RTE_NEW_TEST_EAL_ARGS")
        .map(|args| args.split_whitespace().map(str::to_string).collect())
        .unwrap_or_else(|_| {
            [
                "rte-new-test",
                "-l",
                "0",
                "-n",
                "2",
                "--no-huge",
                "--legacy-mem",
                "--iova-mode=va",
                "--file-prefix=newtest",
                "--vdev=net_null0",
            ]
            .iter()
            .map(|arg| arg.to_string())
            .collect()
        })
}

#[test]
fn end_to_end() {
    let eal =
        Eal::init(&eal_args()).expect("EAL init failed; run with XDG_RUNTIME_DIR pointing at a writable directory");

    assert!(eal.is_primary());

    // ---------------------------------------------------------------- mempool

    let pool = MemoryPool::create::<Slot>(&eal, "new_test_slots", 64, 0).expect("create pool");
    assert_eq!(pool.info().name, "new_test_slots");
    assert_eq!(pool.capacity(), 64);
    assert_eq!(pool.available(), 64);
    assert_eq!(pool.in_use(), 0);
    assert!(pool.is_full());
    assert!(!pool.is_empty());
    assert_eq!(pool.info().elt_size, core::mem::size_of::<Slot>());

    // Checked out objects are initialised and returned by Drop.
    {
        let a = pool.get::<Slot>().expect("get a");
        let b = pool.get::<Slot>().expect("get b");

        assert_eq!(a.magic, MAGIC);
        assert_eq!(b.magic, MAGIC);
        assert_ne!(a.as_ptr(), b.as_ptr());
        assert_eq!(pool.in_use(), 2);
    }
    assert_eq!(pool.in_use(), 0);
    assert!(pool.is_full());

    // Exhaustion is a typed error, not a panic.
    let taken: Vec<_> = (0..64).map(|_| pool.get::<Slot>().unwrap()).collect();
    assert!(matches!(pool.get::<Slot>(), Err(MempoolError::Exhausted { .. })));
    assert!(!pool.is_full());
    drop(taken);
    assert!(pool.is_full());

    // Borrowed views are `Copy` and can never free the pool.
    let view: MemoryPoolRef<'_> = pool.as_ref();
    let view2 = view;
    assert_eq!(view2.capacity(), 64);
    {
        let obj = view2.get::<Slot>().unwrap();
        assert_eq!(obj.pool().as_ptr(), view2.as_ptr());
    }

    // Early exit from the object walk.
    let mut seen = 0usize;
    let flow = pool.for_each_object(|_pool, _obj, idx| {
        seen += 1;
        if idx >= 3 {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
    assert_eq!(flow, ControlFlow::Break(()));
    assert_eq!(seen, 4);

    // A panic in the visitor is resumed on the Rust side of the FFI boundary.
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pool.for_each_object(|_pool, _obj, _idx| -> ControlFlow<()> { panic!("visitor panic") })
    }));
    assert!(panicked.is_err());
    assert_eq!(pool.in_use(), 0);

    drop(pool);

    // The pool is gone, so the (unsafe) by-name lookup must report NotFound.
    let missing = unsafe { MemoryPoolRef::lookup("new_test_slots") };
    assert!(matches!(missing, Err(MempoolError::NotFound { .. })));

    // ------------------------------------------------------- port, queue, mbuf

    assert!(Port::count() >= 1, "net_null0 should have registered a port");

    let ts = RxTimestamp::register().expect("register RX timestamp dynfield");

    let mbuf_pool = MemoryPool::pktmbuf_pool(&eal, "new_test_pkts", 1024, 64, 0, DEFAULT_DATA_ROOM_SIZE)
        .expect("create pktmbuf pool");

    let port = Port::open(0).expect("open port 0");
    assert_eq!(port.id(), 0);

    let info = port.info();
    assert!(!info.driver_name.is_empty());
    let _mac = port.mac_addr();

    port.configure(1, 0, &PortConfig::default()).expect("configure port");
    let queue = port
        .rx_queue_setup(0, 128, None, mbuf_pool.as_ref())
        .expect("setup RX queue");
    port.start().expect("start port");
    port.promiscuous_enable().expect("enable promiscuous mode");

    let link = port.link_nowait();
    let _ = link;
    let _ = port.is_promiscuous();
    let _ = port.read_clock();

    // net_null fabricates 64 byte packets on every burst.
    let mut bufs: [Option<Mbuf<'_>>; 32] = std::array::from_fn(|_| None);
    let mut received = 0usize;

    for _ in 0..64 {
        let n = queue.rx_burst(&mut bufs);

        for packet in bufs[..n].iter_mut().filter_map(Option::take) {
            received += 1;

            assert_eq!(packet.pkt_len(), 64);
            assert_eq!(packet.data_len(), 64);
            assert_eq!(packet.port(), 0);
            assert_eq!(packet.nb_segs(), 1);
            // net_null does not stamp packets, so this must fall back.
            assert_eq!(ts.get(&packet), None);
        }

        if received > 0 {
            break;
        }
    }

    assert!(received > 0, "net_null0 should have delivered packets");
    assert_eq!(queue.port_id(), 0);
    assert_eq!(queue.queue_id(), 0);

    // `queue` is dropped here, before `port`, `mbuf_pool` and `eal`: the
    // lifetime chain in `RxQueue` makes the reverse order a compile error.
}
