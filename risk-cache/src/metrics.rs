use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub expired: AtomicU64,
}
//atomic counters are defined for hits, misses and expired 

impl CacheMetrics {

    pub fn inc_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_expired(&self) {
        self.expired.fetch_add(1, Ordering::Relaxed);
    }
}
//impl means implementation so when we add it here what we are saying is that we are defining methods for CacheMetrics
//we are defining 3 public facing functions which allow us to add value to the counter while returning the previous value
//this allows for a safe and relaxed* implementaion of counters in a multithreaded environment 
//atomics are unique to rust, allow us to NOT use mutex or locks while still being multi-threading (resource allocatiion) safe