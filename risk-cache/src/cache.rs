use dashmap::DashMap;
use log::info;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cleaner::spawn_cleaner;
use crate::entry::RiskEntry;
use crate::metrics::CacheMetrics;

const TTL_SECONDS: u64 = 300;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct RiskCache {
    inner: DashMap<String, RiskEntry>,
    metrics: CacheMetrics,
}

impl RiskCache {
    pub fn new() -> Self {
        let map = DashMap::new();

        spawn_cleaner(map.clone());

        Self {
            inner: map,
            metrics: CacheMetrics::default(),
        }
    }

    pub fn get(&self, vpa_hash: &str) -> (f32, String) {
        if let Some(entry) = self.inner.get(vpa_hash) {
            let now = unix_now();
            if now.saturating_sub(entry.updated_at) > TTL_SECONDS {
                drop(entry);
                self.inner.remove(vpa_hash);
                self.metrics.inc_expired();
                return (0.0, "cold".to_string());
            }

            self.metrics.inc_hit();
            return (entry.risk_score, entry.reason.clone());
        }

        self.metrics.inc_miss();
        (0.0, "cold".to_string())
    }

    pub fn upsert(&self, vpa_hash: String, risk_score: f32, reason: String, _ttl_seconds: u64) {
        let entry = RiskEntry {
            risk_score,
            reason: reason.clone(),
            updated_at: unix_now(),
        };

        self.inner.insert(vpa_hash.clone(), entry);

        info!("cache_update hash={} score={} reason={}", vpa_hash, risk_score, reason);
    }

    pub fn snapshot(&self, limit: usize) -> Vec<(String, RiskEntry)> {
        self.inner
            .iter()
            .take(limit)
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    /// Remove a VPA hash from the cache entirely (DPDP §12(b) erasure right).
    /// Returns `true` if an entry existed and was removed.
    pub fn remove(&self, vpa_hash: &str) -> bool {
        self.inner.remove(vpa_hash).is_some()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Default for RiskCache {
    fn default() -> Self {
        Self::new()
    }
}