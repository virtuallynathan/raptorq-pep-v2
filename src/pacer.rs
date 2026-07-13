use std::time::{Duration, Instant};

/// Small-burst token-bucket pacer shared by all outbound tunnel traffic.
#[derive(Debug)]
pub(crate) struct Pacer {
    bytes_per_sec: f64,
    burst_bytes: f64,
    tokens: f64,
    last_refill: Instant,
}

impl Pacer {
    pub(crate) fn new(max_send_mbps: u32) -> Self {
        let bytes_per_sec = f64::from(max_send_mbps) * 1_000_000.0 / 8.0;
        // A one-millisecond bucket avoids injecting a large userspace burst
        // while still allowing at least one normal datagram immediately.
        let burst_bytes = (bytes_per_sec / 1_000.0).clamp(1500.0, 4500.0);
        Self {
            bytes_per_sec,
            burst_bytes,
            tokens: burst_bytes,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.bytes_per_sec).min(self.burst_bytes);
    }

    pub(crate) async fn acquire(&mut self, bytes: usize) {
        let required = bytes as f64;
        if required > self.burst_bytes {
            self.burst_bytes = required;
            self.tokens = self.tokens.min(self.burst_bytes);
        }

        loop {
            self.refill();
            if self.tokens >= required {
                self.tokens -= required;
                return;
            }
            let deficit = required - self.tokens;
            let wait_secs = (deficit / self.bytes_per_sec).max(0.000_5);
            tokio::time::sleep(Duration::from_secs_f64(wait_secs)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refill_increases_tokens() {
        let mut pacer = Pacer::new(10);
        pacer.tokens = 0.0;
        pacer.last_refill = Instant::now() - Duration::from_millis(100);
        pacer.refill();
        assert!(pacer.tokens > 0.0);
    }

    #[tokio::test]
    async fn acquire_consumes_tokens() {
        let mut pacer = Pacer::new(10);
        let before = pacer.tokens;
        pacer.acquire(1200).await;
        assert!(pacer.tokens < before);
    }

    #[tokio::test]
    async fn acquire_handles_packet_larger_than_initial_burst() {
        let mut pacer = Pacer::new(1);
        tokio::time::timeout(Duration::from_millis(300), pacer.acquire(20_000))
            .await
            .expect("pacer acquire should complete for oversized packets");
    }
}
