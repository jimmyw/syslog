//! Entry ring buffer with monotonic sequence numbers plus a fan-out hub.
//! `publish` stores before it broadcasts, so a woken subscriber always finds the
//! entry already committed in the ring.

use crate::parse::Entry;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub struct Msg {
    pub entry: Entry,
    pub json: String,
}

struct Ring {
    entries: VecDeque<Arc<Msg>>,
    next_seq: u64,
    max: usize,
}

pub struct Shared {
    ring: Mutex<Ring>,
    subs: Mutex<Vec<(u64, flume::Sender<Arc<Msg>>)>>,
    next_sub: AtomicU64,
}

pub struct Subscription {
    pub rx: flume::Receiver<Arc<Msg>>,
    id: u64,
    shared: Arc<Shared>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.shared.subs.lock().unwrap().retain(|(id, _)| *id != self.id);
    }
}

impl Shared {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Shared {
            ring: Mutex::new(Ring { entries: VecDeque::with_capacity(max), next_seq: 0, max }),
            subs: Mutex::new(Vec::new()),
            next_sub: AtomicU64::new(0),
        })
    }

    pub fn publish(&self, msg: Arc<Msg>) {
        {
            let mut r = self.ring.lock().unwrap();
            r.entries.push_back(msg.clone());
            r.next_seq += 1;
            if r.entries.len() > r.max {
                r.entries.pop_front();
            }
        }
        for (_, tx) in self.subs.lock().unwrap().iter() {
            let _ = tx.try_send(msg.clone()); // drop when the subscriber is slow
        }
    }

    pub fn subscribe(self: &Arc<Self>) -> Subscription {
        let (tx, rx) = flume::bounded(64);
        let id = self.next_sub.fetch_add(1, Ordering::Relaxed);
        self.subs.lock().unwrap().push((id, tx));
        Subscription { rx, id, shared: self.clone() }
    }

    /// Entries with seq >= `after`, plus the current next sequence number.
    pub fn since(&self, after: u64) -> (Vec<Arc<Msg>>, u64) {
        let r = self.ring.lock().unwrap();
        let front = r.next_seq - r.entries.len() as u64;
        let start = after.saturating_sub(front) as usize;
        (r.entries.iter().skip(start).cloned().collect(), r.next_seq)
    }

    pub fn current_seq(&self) -> u64 {
        self.ring.lock().unwrap().next_seq
    }
}
