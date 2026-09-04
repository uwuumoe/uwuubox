//! Anonymous upload throttle: 10/hr per IP.
//!
//! `tower-governor` layers enforce the global ceilings (60/hr uploads,
//! 5/min auth); authed-vs-anon can't split at the routing layer, so anon
//! uploads additionally pass through this in-handler sliding window.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct AnonLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max: u32,
    window: Duration,
}

impl AnonLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max,
            window,
        }
    }

    /// `true` = allowed (and recorded).
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let hits = map.entry(ip).or_default();
        hits.retain(|t| now.duration_since(*t) < self.window);
        if hits.len() >= self.max as usize {
            return false;
        }
        hits.push(now);
        true
    }
}
