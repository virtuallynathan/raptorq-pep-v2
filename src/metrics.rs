use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::watch;

#[derive(Debug, Default)]
pub(crate) struct SessionMetrics {
    active_flows: AtomicU64,
    flows_opened: AtomicU64,
    flows_closed: AtomicU64,
    target_denials: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    auth_drops: AtomicU64,
    replay_drops: AtomicU64,
    decode_drops: AtomicU64,
    path_challenges: AtomicU64,
    path_migrations: AtomicU64,
}

impl SessionMetrics {
    pub(crate) fn flow_opened(&self) {
        self.active_flows.fetch_add(1, Ordering::Relaxed);
        self.flows_opened.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn flow_closed(&self) {
        self.active_flows
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(1))
            })
            .ok();
        self.flows_closed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn target_denied(&self) {
        self.target_denials.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn packet_sent(&self, bytes: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn packet_received(&self, bytes: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn auth_drop(&self) {
        self.auth_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn replay_drop(&self) {
        self.replay_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn decode_drop(&self) {
        self.decode_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn path_challenge(&self) {
        self.path_challenges.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn path_migration(&self) {
        self.path_migrations.fetch_add(1, Ordering::Relaxed);
    }

    fn value(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    pub(crate) fn log_snapshot(&self) {
        tracing::info!(
            active_flows = Self::value(&self.active_flows),
            flows_opened = Self::value(&self.flows_opened),
            flows_closed = Self::value(&self.flows_closed),
            target_denials = Self::value(&self.target_denials),
            packets_sent = Self::value(&self.packets_sent),
            packets_received = Self::value(&self.packets_received),
            bytes_sent = Self::value(&self.bytes_sent),
            bytes_received = Self::value(&self.bytes_received),
            auth_drops = Self::value(&self.auth_drops),
            replay_drops = Self::value(&self.replay_drops),
            decode_drops = Self::value(&self.decode_drops),
            path_challenges = Self::value(&self.path_challenges),
            path_migrations = Self::value(&self.path_migrations),
            "wire-v2 session metrics"
        );
    }
}

pub(crate) async fn report(metrics: Arc<SessionMetrics>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    metrics.log_snapshot();
                    return;
                }
            }
            _ = interval.tick() => metrics.log_snapshot(),
        }
    }
}
