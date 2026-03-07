// gateway/src/cache.rs
// ─────────────────────────────────────────────────────────────────────────────
// DashMap-backed in-memory risk cache.
//
// TODO [teammate — THIS IS YOUR MAIN TASK]:
//
//   1.  The cache maps  vpa_hash (String) → RiskEntry  using DashMap.
//       DashMap is a concurrent, lock-free hash map — no Mutex needed.
//
//   2.  `RiskEntry` must store:
//         - risk_score: f32
//         - reason:     String
//         - expires_at: std::time::Instant   (now() + Duration::from_secs(ttl))
//
//   3.  Implement `RiskCache::get()`:
//         - Look up vpa_hash in the DashMap.
//         - If not found → return (0.0, "UNKNOWN")
//         - If found but expired → remove and return (0.0, "EXPIRED")
//         - If found and valid  → return (entry.risk_score, &entry.reason)
//         LATENCY TARGET: this lookup must complete in < 1 ms (it will, since
//         DashMap uses shard-level locking and is O(1) average).
//
//   4.  Implement `RiskCache::upsert()`:
//         - Insert or replace entry for vpa_hash.
//         - Log the update at INFO level (log::info!).
//
//   5.  Optional background task: spawn a tokio background task in
//       `RiskCache::new()` that sweeps the map every 60 s and removes
//       expired entries to prevent unbounded growth.
//
//   6.  Expose `RiskCache` via `actix_web::web::Data<RiskCache>` in main.rs.
//       DashMap is internally Arc+Send+Sync, so this is safe.
//
// ─────────────────────────────────────────────────────────────────────────────

use dashmap::DashMap;
use std::time::{Duration, Instant};

/// A single cached risk entry for a hashed VPA.
#[derive(Debug, Clone)]
pub struct RiskEntry {
    pub risk_score: f32,
    pub reason:     String,
    pub expires_at: Instant,
}

/// The shared, thread-safe risk cache.
pub struct RiskCache {
    // TODO [teammate]: the field below is correct — just fill in the methods.
    inner: DashMap<String, RiskEntry>,
}

impl RiskCache {
    /// Create a new empty cache.
    /// TODO [teammate]: optionally spawn the background TTL sweep task here.
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Look up the risk score for a hashed VPA.
    /// Returns (risk_score, reason).
    ///
    /// TODO [teammate]: implement the three cases described in the header comment.
    pub fn get(&self, vpa_hash: &str) -> (f32, String) {
        // STUB — replace with real implementation
        todo!("Implement DashMap lookup with TTL check")
    }

    /// Insert or update an entry with a TTL.
    ///
    /// TODO [teammate]: implement the upsert as described in the header comment.
    pub fn upsert(&self, vpa_hash: String, risk_score: f32, reason: String, ttl_seconds: u64) {
        // STUB — replace with real implementation
        todo!("Implement DashMap upsert")
    }

    /// Returns the number of entries currently in the cache (for health checks).
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Default for RiskCache {
    fn default() -> Self {
        Self::new()
    }
}
