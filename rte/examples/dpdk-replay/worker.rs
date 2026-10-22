//! Worker lcore: burst transmission and result collection.
//!
//! The worker borrows its port through [`TxQueue`] and its mempool through
//! [`Mbuf`]. It is moved into a [`LcoreScope`](rte::new::LcoreScope) task, so
//! the scope's wait guarantees the worker has dropped its caches before the
//! port or pool is torn down.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rte::new::{Mbuf, PortId, TxQueue};

pub const BURST_SZ: usize = 128;
pub const NB_RETRY_TX: usize = 128;
const RETRY_SLEEP: Duration = Duration::from_micros(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateState {
    Wait,
    Go,
    Abort,
}

/// Release all workers at once, or abort them if launching failed.
pub struct StartGate {
    state: Mutex<GateState>,
    condvar: Condvar,
}

impl StartGate {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(GateState::Wait),
            condvar: Condvar::new(),
        }
    }

    pub fn go(&self) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *state = GateState::Go;
        self.condvar.notify_all();
    }

    pub fn abort(&self) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *state = GateState::Abort;
        self.condvar.notify_all();
    }

    fn wait(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        while *state == GateState::Wait {
            state = self
                .condvar
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }

        *state == GateState::Go
    }
}

impl Default for StartGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared result slot; the worker updates it and the main lcore reads it after
/// `LcoreScope::wait()`.
pub struct WorkerResult {
    pub port: PortId,
    packets: u64,
    bytes: u64,
    nbruns: u16,
    duration_ns: AtomicU64,
    dropped: AtomicU64,
    dropped_bytes: AtomicU64,
}

impl WorkerResult {
    pub fn new(port: PortId, nbruns: u16, packets: u64, bytes: u64) -> Self {
        Self {
            port,
            packets,
            bytes,
            nbruns,
            duration_ns: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
        }
    }

    pub fn stats(&self) -> WorkerStats {
        let attempts = self.packets.saturating_mul(self.nbruns as u64);
        let attempted_bytes = self.bytes.saturating_mul(self.nbruns as u64);
        let dropped = self.dropped.load(Ordering::Relaxed);
        let dropped_bytes = self.dropped_bytes.load(Ordering::Relaxed);
        let sent = attempts.saturating_sub(dropped);
        let sent_bytes = attempted_bytes.saturating_sub(dropped_bytes);
        let duration_secs = self.duration_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0;

        let (pps, gbps) = if duration_secs > 0.0 {
            (
                sent as f64 / duration_secs,
                sent_bytes as f64 * 8.0 / 1_000_000_000.0 / duration_secs,
            )
        } else {
            (0.0, 0.0)
        };

        WorkerStats {
            port: self.port,
            packets: attempts,
            sent,
            dropped,
            duration_secs,
            pps,
            gbps,
        }
    }
}

pub struct Worker<'port, 'pool> {
    tx_queues: Vec<TxQueue<'port>>,
    nbruns: u16,
    cache: Vec<Mbuf<'pool>>,
    gate: Arc<StartGate>,
    result: Arc<WorkerResult>,
}

impl<'port, 'pool> Worker<'port, 'pool> {
    pub fn new(
        tx_queues: Vec<TxQueue<'port>>,
        nbruns: u16,
        cache: Vec<Mbuf<'pool>>,
        gate: Arc<StartGate>,
        result: Arc<WorkerResult>,
    ) -> Self {
        debug_assert!(!tx_queues.is_empty());

        Self {
            tx_queues,
            nbruns,
            cache,
            gate,
            result,
        }
    }

    /// Run all replay passes, then return 0. The worker is consumed so its
    /// packet cache is dropped on this lcore as soon as the task returns.
    pub fn run(self) -> i32 {
        if !self.gate.wait() {
            return -1;
        }

        let started = Instant::now();
        let nb_tx_queues = self.tx_queues.len();
        let mut tx_queue = 0usize;
        let mut burst: Vec<Option<Mbuf<'pool>>> = Vec::with_capacity(BURST_SZ);

        for _ in 0..self.nbruns {
            for chunk in self.cache.chunks(BURST_SZ) {
                burst.clear();
                burst.extend(chunk.iter().cloned().map(Some));

                let mut sent = 0usize;
                let mut attempts = 0usize;

                while sent < burst.len() && attempts < NB_RETRY_TX {
                    let queue = tx_queue % nb_tx_queues;
                    let accepted = self.tx_queues[queue].tx_burst(&mut burst[sent..]);

                    sent += accepted;
                    attempts += 1;
                    tx_queue = tx_queue.wrapping_add(1);

                    if attempts > 1 && tx_queue % nb_tx_queues == 0 {
                        std::thread::sleep(RETRY_SLEEP);
                    }
                }

                if sent < burst.len() {
                    for packet in &burst[sent..] {
                        if let Some(packet) = packet {
                            self.result.dropped.fetch_add(1, Ordering::Relaxed);
                            self.result
                                .dropped_bytes
                                .fetch_add(packet.pkt_len() as u64, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        self.result
            .duration_ns
            .store(started.elapsed().as_nanos() as u64, Ordering::Relaxed);

        0
    }
}

pub struct WorkerStats {
    pub port: PortId,
    pub packets: u64,
    pub sent: u64,
    pub dropped: u64,
    pub duration_secs: f64,
    pub pps: f64,
    pub gbps: f64,
}
