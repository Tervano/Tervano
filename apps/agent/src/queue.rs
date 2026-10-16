//! Bounded on-disk queue of agent events (T-213, PLAN §5): startups, state changes and shutdowns
//! that the Server has not acknowledged yet. It survives agent restarts, so a Server outage leaves
//! a gap in nothing but timing: the device history fills in once the Server is back. Heartbeats
//! are never queued; only the latest liveness matters.

use std::collections::VecDeque;
use std::path::PathBuf;
use tervano_protocol::{AgentEvent, EventKind};

/// Oldest events are dropped beyond this (about 2 MB of state snapshots).
const MAX_EVENTS: usize = 1000;
/// Events per request; the Server accepts up to 500.
pub const BATCH: usize = 100;

pub struct EventQueue {
    path: PathBuf,
    events: VecDeque<AgentEvent>,
}

impl EventQueue {
    /// Loads unsent events from an earlier run. An unreadable file is set aside, not fatal.
    pub fn load(path: PathBuf) -> Self {
        let events = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<VecDeque<AgentEvent>>(&bytes) {
                Ok(events) => events,
                Err(e) => {
                    let aside = path.with_extension("corrupt");
                    tracing::warn!(
                        "event queue {} unreadable ({e}); moved to {}",
                        path.display(),
                        aside.display()
                    );
                    let _ = std::fs::rename(&path, aside);
                    VecDeque::new()
                }
            },
            Err(_) => VecDeque::new(),
        };
        Self { path, events }
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn max_seq(&self) -> Option<u64> {
        self.events.back().map(|e| e.seq)
    }

    pub fn push(&mut self, event: AgentEvent) {
        self.events.push_back(event);
        let mut dropped = 0;
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
            dropped += 1;
        }
        if dropped > 0 {
            tracing::warn!(
                dropped,
                "event queue full; dropped the oldest unsent events"
            );
        }
        self.save();
    }

    /// The next events to send, oldest first.
    pub fn batch(&self) -> Vec<AgentEvent> {
        self.events.iter().take(BATCH).cloned().collect()
    }

    /// Drops what the Server has applied (seq <= `last_seq`); returns how many.
    pub fn acked(&mut self, last_seq: u64) -> usize {
        let before = self.events.len();
        while self.events.front().is_some_and(|e| e.seq <= last_seq) {
            self.events.pop_front();
        }
        let removed = before - self.events.len();
        if removed > 0 {
            self.save();
        }
        removed
    }

    /// Gives the queued events new consecutive sequence numbers from `next` (after the Server
    /// reported a higher seq than ours, e.g. our clock went backwards); returns the last one used.
    pub fn renumber_from(&mut self, next: u64) -> u64 {
        let mut seq = next;
        for e in &mut self.events {
            e.seq = seq;
            seq += 1;
        }
        self.save();
        seq - 1
    }

    /// Whether any queued event carries a device state (worth logging when delivered).
    pub fn has_state(events: &[AgentEvent]) -> bool {
        events.iter().any(|e| {
            matches!(
                e.kind,
                EventKind::Startup { .. } | EventKind::StateChanged { .. }
            )
        })
    }

    /// Write-then-rename so a crash never leaves a half-written queue.
    fn save(&self) {
        let tmp = self.path.with_extension("tmp");
        let result = serde_json::to_vec(&self.events)
            .map_err(std::io::Error::other)
            .and_then(|bytes| std::fs::write(&tmp, bytes))
            .and_then(|()| std::fs::rename(&tmp, &self.path));
        if let Err(e) = result {
            tracing::warn!(
                "could not save the event queue {}: {e}",
                self.path.display()
            );
        }
    }
}
