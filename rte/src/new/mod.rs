//! # `rte::new` — ownership-correct DPDK wrappers (experimental)
//!
//! This module is a **parallel, opt-in** API. Nothing in it is used by the
//! existing `rte::mempool` / `rte::mbuf` modules, and the old API keeps
//! working unchanged. The plan is to exercise `rte::new` in real scenarios
//! before deciding whether the old wrappers can be retired.
//!
//! ## Why a new module
//!
//! The historical `MemoryPool` wrapper mixes two different owners behind one
//! type: a pool returned by `rte_mempool_create()` (owned by us) and a pool
//! handed to us by `rte_mempool_lookup()`, `rte_mempool_from_obj()` or a DPDK
//! callback (borrowed). Because the type cannot tell them apart, the old
//! module had to compensate:
//!
//! * no `Drop` at all (so nothing automatic happens to a borrowed handle),
//! * `free()` kept private (so safe code cannot destroy a borrowed pool),
//! * `mem::forget(mp)` sprinkled through the C callback stubs.
//!
//! That makes the wrappers "safe by omission" rather than safe by
//! construction. `rte::new` instead encodes the three lifetimes into the type
//! system:
//!
//! | concept | type | guarantees |
//! |---|---|---|
//! | EAL lifetime | [`Eal`] | nothing DPDK-allocated outlives `rte_eal_cleanup()` |
//! | pool ownership | [`MemoryPool<'eal>`] | owned, `Drop` calls `rte_mempool_free` |
//! | pool borrow | [`MemoryPoolRef<'a>`] | `Copy`, no `Drop`, cannot free |
//! | ring ownership | [`Ring<'eal>`] | owned, `Drop` calls `rte_ring_free` |
//! | ring borrow | [`RingRef<'a>`] | `Copy`, no `Drop`, cannot free |
//! | mbuf ring transfer | [`MbufRing<'a>`] | consumes an [`Mbuf`] on enqueue, validates the pool on dequeue |
//! | object ownership | [`PoolObject<'pool, T>`] | `Drop` returns the object to its pool |
//! | port ownership | [`Port`] | `Drop` stops and closes the port |
//! | queue borrow | [`RxQueue<'port, 'pool>`] / [`TxQueue<'port>`] | borrows the port; RX also borrows its pool |
//! | packet borrow | [`Mbuf<'pool>`] | `Drop` calls `rte_pktmbuf_free`, borrows the backing pool |
//! | packet read view | [`MbufRef<'a>`] | `Copy`, no `Drop`, no pool borrow, read-only |
//! | lcore tasks | [`LcoreScope`] | waits for every launched task before it is dropped |
//! | bus borrow | [`Bus<'a>`] / [`BusDevice<'a>`] | `Copy`, no `Drop`, cannot unregister a bus or free a device |
//!
//! Conversion from raw pointers is `unsafe` and explicit; there is no blanket
//! `From<*mut rte_mempool>`, because that conversion is exactly the ownership
//! information the compiler needs.
//!
//! ## Example
//!
//! ```no_run
//! use rte::new::{Eal, MemoryPool, MemoryPoolRef, PoolElement};
//! # use core::ptr::NonNull;
//! # #[repr(C, align(64))] struct Slot { magic: u64 }
//! # unsafe impl PoolElement for Slot {
//! #     const ELT_SIZE: usize = 64;
//! #     unsafe fn init(obj: NonNull<Slot>) { unsafe { obj.as_ptr().write(Slot { magic: 0xC0FFEE }) } }
//! # }
//! let eal = Eal::init(&["app", "-l", "0", "-n", "2"])?;
//! let pool = MemoryPool::create::<Slot>(&eal, "slots", 1024, 0)?;
//!
//! // borrowed view: cannot free, safe to copy around
//! let view: MemoryPoolRef<'_> = pool.as_ref();
//! assert_eq!(view.capacity(), 1024);
//!
//! // checked out object: returned to the pool when dropped
//! let obj = view.get::<Slot>()?;
//! assert_eq!(obj.magic, 0xC0FFEE);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Rings follow the same ownership split:
//!
//! ```no_run
//! use rte::new::{Eal, Ring, RingFlags};
//! let eal = Eal::init(&["app", "-l", "0", "-n", "2"])?;
//! let ring = Ring::create::<u64>(&eal, "events", 1024, RingFlags::empty())?;
//! ring.enqueue(42u64)?;
//! assert_eq!(ring.dequeue::<u64>()?, 42);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! For read-only packet consumers, [`RingRef::dequeue_mbuf_ref`] returns an
//! [`MbufRef`] without an EAL pool lookup.
//!
//! ## Deliberate omissions
//!
//! * No `Deref<Target = rte_mempool>`: the C struct layout is never exposed to
//!   safe code. Use [`PoolInfo`] for a snapshot of the interesting fields.
//! * No `impl From<*mut rte_mempool>`: use the `unsafe` [`MemoryPool::from_raw`]
//!   when you really do own a raw pointer.
//! * No `rte_ring_init`, RTS/HTS, peek/zero-copy or `rte_event_ring` wrappers:
//!   [`Ring`] covers the non-experimental create/lookup/enqueue/dequeue/count
//!   surface of DPDK 20.11, and a ring never owns or drops its elements.
//! * No direct `Ring::enqueue(Mbuf)`: rings copy elements and never run
//!   destructors, so packet ownership is transferred with [`Mbuf::into_raw`]
//!   plus [`MemoryPoolRef::mbuf_from_raw`], wrapped by the typed [`MbufRing`].

pub mod bus;
pub mod cache;
pub mod eal;
pub mod error;
pub mod ethdev;
pub mod lcore;
pub mod mbuf;
pub mod mempool;
pub mod object;
pub mod ring;

#[cfg(test)]
mod tests;

pub use bus::{Bus, BusDevice, IovaMode};
pub use cache::{Cache, CacheRef};
pub use eal::{Eal, Hypervisor, ThreadGuard, hypervisor, register_current_thread};
pub use error::{
    BusError, EalError, LcoreError, MbufError, MempoolError, PortError, Result, RingError, ThreadError, TimestampError,
};
pub use ethdev::{
    EtherAddr, LinkStatus, Port, PortConfig, PortId, PortInfo, PortStats, QueueId, QueueStats, RssConfig, RssHash,
    RxQueue, RxQueueConfig, TxQueue, TxQueueConfig, rx_offloads,
};
pub use lcore::{LcoreExit, LcoreId, LcoreScope};
pub use mbuf::{
    DEFAULT_DATA_ROOM_SIZE, MAX_PACKET_SIZE, MBUF_PTR_SIZE, Mbuf, MbufRef, MbufSegments, PACKET_HEADROOM, RxTimestamp,
};
pub use mempool::{Builder, MEMPOOL_NAMESIZE, MemoryPool, MemoryPoolFlags, MemoryPoolRef, PoolInfo};
pub use object::{PoolElement, PoolObject};
pub use ring::{MbufRing, RING_NAMESIZE, Ring, RingElement, RingFlags, RingInfo, RingRef};
