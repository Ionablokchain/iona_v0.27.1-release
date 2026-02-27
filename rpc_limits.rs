/// RPC rate limiting and input validation for IONA production node.
///
/// Prevents:
/// - DoS via mempool flooding (per-IP submit rate limit)
/// - Oversized payloads
/// - Invalid UTF-8 or excessively large transactions

use std::net::IpAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::Mutex;

// ── Per-IP rate limiter (token bucket) ───────────────────────────────────

const SUBMIT_RATE_PER_SEC: u32 = 100;  // max tx/s per IP for submission
const READ_RATE_PER_SEC:   u32 = 500;  // max requests/s per IP for reads

struct TokenBucket {
    tokens: f64,
    max: f64,
    last: Instant,
    rate_per_sec: f64,
}

impl TokenBucket {
    fn new(rate_per_sec: u32) -> Self {
        let r = rate_per_sec as f64;
        Self { tokens: r, max: r, last: Instant::now(), rate_per_sec: r }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.max);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RpcLimiter {
    submit_buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    read_buckets:   Mutex<HashMap<IpAddr, TokenBucket>>,
    last_cleanup:   Mutex<Instant>,
}

impl RpcLimiter {
    pub fn new() -> Self {
        Self {
            submit_buckets: Mutex::new(HashMap::new()),
            read_buckets:   Mutex::new(HashMap::new()),
            last_cleanup:   Mutex::new(Instant::now()),
        }
    }

    pub fn allow_submit(&self, ip: IpAddr) -> bool {
        self.cleanup_if_needed();
        self.submit_buckets.lock()
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(SUBMIT_RATE_PER_SEC))
            .try_consume()
    }

    pub fn allow_read(&self, ip: IpAddr) -> bool {
        self.read_buckets.lock()
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(READ_RATE_PER_SEC))
            .try_consume()
    }

    // Cleanup stale entries every 60s to prevent unbounded growth
    fn cleanup_if_needed(&self) {
        let mut last = self.last_cleanup.lock();
        if last.elapsed() < Duration::from_secs(60) { return; }
        *last = Instant::now();
        drop(last);

        let cutoff = Duration::from_secs(120);
        let mut sb = self.submit_buckets.lock();
        sb.retain(|_, b| b.last.elapsed() < cutoff);
        let mut rb = self.read_buckets.lock();
        rb.retain(|_, b| b.last.elapsed() < cutoff);
    }
}

// ── Input validation ──────────────────────────────────────────────────────

pub const MAX_PAYLOAD_BYTES: usize = 4096;
pub const MAX_TX_PUBKEY_BYTES: usize = 64;

#[derive(Debug, Clone)]
pub enum ValidationError {
    PayloadTooLong { len: usize, max: usize },
    InvalidUtf8,
    PubkeyTooLong,
    GasLimitZero,
    MaxFeeZero,
    ChainIdMismatch { got: u64, expected: u64 },
    NonceGap { sender: String, expected: u64, got: u64 },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLong { len, max } => write!(f, "payload too long: {len} > {max}"),
            Self::InvalidUtf8 => write!(f, "payload not valid UTF-8"),
            Self::PubkeyTooLong => write!(f, "pubkey too long"),
            Self::GasLimitZero => write!(f, "gas_limit must be > 0"),
            Self::MaxFeeZero => write!(f, "max_fee_per_gas must be > 0"),
            Self::ChainIdMismatch { got, expected } => write!(f, "chain_id {got} != {expected}"),
            Self::NonceGap { sender, expected, got } =>
                write!(f, "nonce gap: sender {sender} expected {expected}, got {got}"),
        }
    }
}

pub fn validate_tx(
    tx: &crate::types::Tx,
    expected_chain_id: u64,
    sender_nonce: u64,  // current confirmed nonce for this sender
) -> Result<(), ValidationError> {
    if tx.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ValidationError::PayloadTooLong { len: tx.payload.len(), max: MAX_PAYLOAD_BYTES });
    }
    if std::str::from_utf8(tx.payload.as_bytes()).is_err() {
        return Err(ValidationError::InvalidUtf8);
    }
    if tx.pubkey.len() > MAX_TX_PUBKEY_BYTES {
        return Err(ValidationError::PubkeyTooLong);
    }
    if tx.gas_limit == 0 {
        return Err(ValidationError::GasLimitZero);
    }
    if tx.max_fee_per_gas == 0 {
        return Err(ValidationError::MaxFeeZero);
    }
    if tx.chain_id != expected_chain_id {
        return Err(ValidationError::ChainIdMismatch { got: tx.chain_id, expected: expected_chain_id });
    }
    // Accept current or future nonces (mempool queuing), but not past nonces
    if tx.nonce < sender_nonce {
        return Err(ValidationError::NonceGap {
            sender: tx.from.clone(),
            expected: sender_nonce,
            got: tx.nonce,
        });
    }
    Ok(())
}
