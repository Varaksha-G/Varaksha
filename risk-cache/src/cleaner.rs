use dashmap::DashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::entry::RiskEntry;

pub fn spawn_cleaner(map: DashMap<String, RiskEntry>) {

    tokio::spawn(async move {

        loop {

            sleep(Duration::from_secs(60)).await;

            let now = Instant::now();

            let expired: Vec<String> = map
                .iter()
                .filter(|e| e.value().expires_at <= now)
                .map(|e| e.key().clone())
                .collect();

            for key in expired {
                map.remove(&key);
            }
        }
    });
}