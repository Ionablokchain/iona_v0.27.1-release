use std::collections::HashMap;
use std::time::{Duration, Instant};

/// ULTRA: simple peer scoring scaffold.
/// This is intentionally conservative and easy to reason about.
/// Wire it into your swarm event loop to call `note_*` and periodically call `decay()`.
#[derive(Debug)]
pub struct PeerScore {
    scores: HashMap<String, i64>,
    last_decay: Instant,
    ban_threshold: i64,
    decay_every: Duration,
}

impl PeerScore {
    pub fn new(ban_threshold: i64, decay_every: Duration) -> Self {
        Self {
            scores: HashMap::new(),
            last_decay: Instant::now(),
            ban_threshold,
            decay_every,
        }
    }

    pub fn note_bad(&mut self, peer: impl Into<String>, penalty: i64) {
        let p = peer.into();
        *self.scores.entry(p).or_insert(0) -= penalty.abs();
    }

    pub fn note_good(&mut self, peer: impl Into<String>, reward: i64) {
        let p = peer.into();
        *self.scores.entry(p).or_insert(0) += reward.abs();
    }

    pub fn should_ban(&self, peer: &str) -> bool {
        self.scores.get(peer).copied().unwrap_or(0) <= -self.ban_threshold
    }

    pub fn score(&self, peer: &str) -> i64 {
        self.scores.get(peer).copied().unwrap_or(0)
    }

    /// Decays scores toward zero to forgive old behavior.
    pub fn decay(&mut self) {
        if self.last_decay.elapsed() < self.decay_every {
            return;
        }
        self.last_decay = Instant::now();
        for v in self.scores.values_mut() {
            *v = (*v * 9) / 10;
        }
    }
}
