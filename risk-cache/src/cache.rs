use dashmap::DashMap;
use std::time::{Duration, Instant};
use log::info;

use crate::entry::RiskEntry;
use crate::cleaner::spawn_cleaner;
use crate::metrics::CacheMetrics;

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

            let now = Instant::now();

            if entry.expires_at <= now {

                drop(entry);

                self.inner.remove(vpa_hash);

                self.metrics.inc_expired();

                return (0.0, "EXPIRED".to_string());
            }

            self.metrics.inc_hit();

            return (entry.risk_score, entry.reason.clone());
        }

        self.metrics.inc_miss();

        (0.0, "UNKNOWN".to_string())
    }

    pub fn upsert(
        &self,
        vpa_hash: String,
        risk_score: f32,
        reason: String,
        ttl_seconds: u64,
    ) {

        let expires_at = Instant::now() + Duration::from_secs(ttl_seconds);

        let entry = RiskEntry {
            risk_score,
            reason: reason.clone(),
            expires_at,
        };

        self.inner.insert(vpa_hash.clone(), entry);

        info!(
            "cache_update hash={} score={} reason={} ttl={}",
            vpa_hash,
            risk_score,
            reason,
            ttl_seconds
        );
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