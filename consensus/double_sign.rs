use crate::consensus::messages::{VoteType};
use crate::crypto::PublicKeyBytes;
use crate::types::{Hash32, Height, Round};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path, sync::Arc};

/// Persisted double-sign protection.
///
/// Records what this validator has signed so it can refuse to sign conflicting
/// messages across restarts.
#[derive(Clone)]
pub struct DoubleSignGuard {
    path: String,
    inner: Arc<Mutex<GuardState>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct GuardState {
    /// Key: "proposal:<h>:<r>" -> block_id hex
    proposals: BTreeMap<String, String>,
    /// Key: "vote:<type>:<h>:<r>" -> block_id hex (or "nil")
    votes: BTreeMap<String, String>,
}

fn h32_hex(id: &Hash32) -> String {
    hex::encode(&id.0)
}

fn load_state(path: &str) -> GuardState {
    if !Path::new(path).exists() {
        return GuardState::default();
    }
    match fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<GuardState>(&s).ok())
    {
        Some(st) => st,
        None => GuardState::default(),
    }
}

fn save_state(path: &str, st: &GuardState) {
    if let Ok(s) = serde_json::to_string_pretty(st) {
        let _ = fs::write(path, s);
    }
}

impl DoubleSignGuard {
    pub fn new(data_dir: &str, pk: &PublicKeyBytes) -> Self {
        let pk_hex = hex::encode(&pk.0);
        let path = format!("{}/doublesign_{}.json", data_dir, pk_hex);
        let st = load_state(&path);
        Self {
            path,
            inner: Arc::new(Mutex::new(st)),
        }
    }

    pub fn check_proposal(&self, height: Height, round: Round, block_id: &Hash32) -> Result<(), String> {
        let key = format!("proposal:{}:{}", height, round);
        let want = h32_hex(block_id);
        let st = self.inner.lock();
        if let Some(existing) = st.proposals.get(&key) {
            if existing != &want {
                return Err("double-proposal refused".into());
            }
        }
        Ok(())
    }

    pub fn record_proposal(&self, height: Height, round: Round, block_id: &Hash32) {
        let key = format!("proposal:{}:{}", height, round);
        let want = h32_hex(block_id);
        let mut st = self.inner.lock();
        st.proposals.insert(key, want);
        save_state(&self.path, &st);
    }

    pub fn check_vote(&self, vt: VoteType, height: Height, round: Round, block_id: &Option<Hash32>) -> Result<(), String> {
        let key = vote_guard_key(vt, height, round);
        let want = block_id.as_ref().map(h32_hex).unwrap_or_else(|| "nil".to_string());
        let st = self.inner.lock();
        if let Some(existing) = st.votes.get(&key) {
            if existing != &want {
                return Err("double-vote refused".into());
            }
        }
        Ok(())
    }

    pub fn record_vote(&self, vt: VoteType, height: Height, round: Round, block_id: &Option<Hash32>) {
        let key = vote_guard_key(vt, height, round);
        let want = block_id.as_ref().map(h32_hex).unwrap_or_else(|| "nil".to_string());
        let mut st = self.inner.lock();
        st.votes.insert(key, want);
        save_state(&self.path, &st);
    }
}

/// Utility to build the key used by the guard for vote record.
pub fn vote_guard_key(vt: VoteType, height: Height, round: Round) -> String {
    format!("vote:{:?}:{}:{}", vt, height, round)
}
