pub mod auth;
pub mod blind;
pub mod config;
pub mod db;
pub mod device_links;
pub mod error;
pub mod invite;
pub mod messaging;
pub mod legacy;
pub mod provisioning;
pub mod ratchet;
pub mod security;
pub mod server;
pub mod util;

use config::Config;
use db::Db;
use std::sync::Arc;
use tokio::sync::Notify;

pub const VERSION: &str = "3.0.0";
pub const VERSION_CODE: i64 = 30000;
pub const PROTOCOL_GENERATION: i64 = 4;
pub const SECURITY_EPOCH: i64 = 1;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    pub events: Arc<EventClock>,
    pub streams: Arc<blind::StreamBroker>,
}

pub struct EventClock {
    sequence: std::sync::atomic::AtomicI64,
    notify: Notify,
}
impl Default for EventClock {
    fn default() -> Self {
        // Use wall-clock microseconds as the process base rather than starting at 1. A mobile
        // client persists its event cursor; after a server restart the new base must be greater
        // than the previous process cursor or long-poll synchronization can stall indefinitely.
        let base = chrono::Utc::now().timestamp_micros().max(1);
        Self { sequence: std::sync::atomic::AtomicI64::new(base), notify: Notify::new() }
    }
}
impl EventClock {
    pub fn current(&self) -> i64 { self.sequence.load(std::sync::atomic::Ordering::Acquire) }
    pub fn bump(&self) -> i64 {
        let v = self.sequence.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1;
        self.notify.notify_waiters();
        v
    }
    pub async fn wait_after(&self, after: i64, timeout: std::time::Duration) -> i64 {
        // Register the waiter before checking the clock so a bump cannot be lost between the
        // initial comparison and Notify registration.
        let notified = self.notify.notified();
        let current = self.current();
        if current > after { return current; }
        let _ = tokio::time::timeout(timeout, notified).await;
        self.current()
    }
}
