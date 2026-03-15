use dashmap::DashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

use crate::entry::RiskEntry;

const TTL_SECONDS: u64 = 300;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn spawn_cleaner(map: DashMap<String, RiskEntry>) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60)).await;

            let now = unix_now();

            let expired: Vec<String> = map
                .iter()
                .filter(|e| now.saturating_sub(e.value().updated_at) > TTL_SECONDS)
                .map(|e| e.key().clone())
                .collect();

            for key in expired {
                map.remove(&key);
            }
        }
    });
}