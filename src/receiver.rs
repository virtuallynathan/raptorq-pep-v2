use std::collections::{BTreeMap, HashMap};
use std::iter;
use std::time::{Duration, Instant};

use raptorq::{EncodingPacket, ObjectTransmissionInformation, PayloadId, SourceBlockDecoder};

use crate::config::{RAPTORQ_MAX_SOURCE_SYMBOLS, RepairConfig};
use crate::symbol::Symbol;

// ---------------------------------------------------------------------------
// ReceiverEvent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverEvent {
    Decoded { block_seq: u32, payload: Vec<u8> },
    RepairNeeded { block_seq: u32, count: u16 },
    Ack { block_seq: u32 },
    Failed { block_seq: u32 },
}

// ---------------------------------------------------------------------------
// BlockState (private)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BlockState {
    decoder: Option<SourceBlockDecoder>,
    decoded: bool,
    first_seen: Instant,
    repairs_sent: u8,
    k_eff: Option<u16>,
    block_payload_len: Option<u32>,
    last_repair_at: Option<Instant>,
}

impl BlockState {
    fn placeholder(now: Instant) -> Self {
        Self {
            decoder: None,
            decoded: false,
            first_seen: now,
            repairs_sent: 0,
            k_eff: None,
            block_payload_len: None,
            last_repair_at: None,
        }
    }
}

// ---------------------------------------------------------------------------
// BlockReceiver
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct BlockReceiver {
    symbol_size: u16,
    next_expected_seq: u32,
    blocks: HashMap<u32, BlockState>,
    delivered: BTreeMap<u32, Vec<u8>>,
    terminal_failure: Option<u32>,
    next_deliver_seq: u32,
    reorder_window: u32,
    repair_config: RepairConfig,
    /// Repair count to request when k_eff is unknown (gap-detected placeholder).
    /// Should be set to the peer's k_max so a full block can be recovered.
    peer_k_max: u16,
}

impl BlockReceiver {
    pub fn new(
        symbol_size: u16,
        repair_config: RepairConfig,
        reorder_window: u32,
        peer_k_max: u16,
    ) -> Self {
        Self {
            symbol_size,
            next_expected_seq: 0,
            blocks: HashMap::new(),
            delivered: BTreeMap::new(),
            terminal_failure: None,
            next_deliver_seq: 0,
            reorder_window,
            repair_config,
            peer_k_max,
        }
    }

    fn fail(&mut self, block_seq: u32) -> Vec<ReceiverEvent> {
        if self.terminal_failure.is_some() {
            return Vec::new();
        }
        self.terminal_failure = Some(block_seq);
        self.blocks.clear();
        self.delivered.retain(|&seq, _| seq < block_seq);
        vec![ReceiverEvent::Failed { block_seq }]
    }

    fn symbol_metadata_is_valid(&self, sym: &Symbol) -> bool {
        if self.symbol_size == 0
            || sym.data.len() != usize::from(self.symbol_size)
            || sym.k_eff == 0
            || sym.k_eff > self.peer_k_max
            || sym.k_eff > RAPTORQ_MAX_SOURCE_SYMBOLS
            || sym.block_payload_len == 0
        {
            return false;
        }

        sym.block_payload_len.div_ceil(u32::from(self.symbol_size)) == u32::from(sym.k_eff)
    }

    pub fn receive_symbol(&mut self, sym: Symbol) -> Vec<ReceiverEvent> {
        if self.terminal_failure.is_some() {
            return Vec::new();
        }

        let block_seq = sym.block_seq;
        // Late symbols for already-delivered blocks must be ignored.
        // After drain_deliverable removes a block from self.blocks, a late
        // repair/source symbol would otherwise recreate a fresh placeholder
        // that can never decode (not enough symbols) and eventually fails.
        if block_seq < self.next_deliver_seq {
            return Vec::new();
        }

        if !self.symbol_metadata_is_valid(&sym) {
            return self.fail(block_seq);
        }

        let max_pending_seq = self.next_deliver_seq.saturating_add(self.reorder_window);
        if block_seq > max_pending_seq {
            return self.fail(self.next_deliver_seq);
        }

        let now = Instant::now();
        // Gap detection: if sym.block_seq > next_expected_seq, create placeholders.
        if block_seq > self.next_expected_seq {
            for seq in self.next_expected_seq..block_seq {
                self.blocks
                    .entry(seq)
                    .or_insert_with(|| BlockState::placeholder(now));
            }
            self.next_expected_seq = block_seq.saturating_add(1);
        } else if block_seq == self.next_expected_seq {
            self.next_expected_seq = block_seq.saturating_add(1);
        }
        // else: late packet for older block, still process normally.

        let k_eff = sym.k_eff;
        let block_payload_len = sym.block_payload_len;
        let packet = EncodingPacket::new(PayloadId::new(0, sym.esi as u32), sym.data);

        let mut metadata_mismatch = false;
        let mut decoded_payload: Option<Vec<u8>> = None;
        {
            let state = self
                .blocks
                .entry(block_seq)
                .or_insert_with(|| BlockState::placeholder(now));

            if state.decoded {
                return Vec::new();
            }

            // Initialize decoder if not yet created (placeholder or first symbol).
            if state.decoder.is_none() {
                state.k_eff = Some(k_eff);
                state.block_payload_len = Some(block_payload_len);
                let transfer_length = k_eff as u64 * self.symbol_size as u64;
                let config = ObjectTransmissionInformation::new(
                    transfer_length,
                    self.symbol_size,
                    1, // source_blocks
                    1, // sub_blocks
                    8, // alignment
                );
                state.decoder = Some(SourceBlockDecoder::new(0, &config, transfer_length));
            } else if state.k_eff != Some(k_eff)
                || state.block_payload_len != Some(block_payload_len)
            {
                metadata_mismatch = true;
            }

            if !metadata_mismatch {
                let decoder = state.decoder.as_mut().expect("decoder initialized");
                if let Some(mut data) = decoder.decode(iter::once(packet)) {
                    state.decoded = true;
                    let bpl = state.block_payload_len.unwrap_or(data.len() as u32);
                    data.truncate(bpl as usize);
                    decoded_payload = Some(data);
                }
            }
        }

        if metadata_mismatch {
            return self.fail(block_seq);
        }

        if let Some(payload) = decoded_payload {
            self.delivered.insert(block_seq, payload.clone());
            return vec![
                ReceiverEvent::Decoded { block_seq, payload },
                ReceiverEvent::Ack { block_seq },
            ];
        }

        Vec::new()
    }

    /// Announce the sender's final block count so a completely lost trailing
    /// block becomes a repairable placeholder instead of an invisible gap.
    pub fn expect_block_count(&mut self, block_count: u32) -> Vec<ReceiverEvent> {
        if self.terminal_failure.is_some() || block_count <= self.next_expected_seq {
            return Vec::new();
        }

        let maximum_count = self
            .next_deliver_seq
            .saturating_add(self.reorder_window)
            .saturating_add(1);
        if block_count > maximum_count {
            return self.fail(self.next_deliver_seq);
        }

        let now = Instant::now();
        for seq in self.next_expected_seq..block_count {
            self.blocks
                .entry(seq)
                .or_insert_with(|| BlockState::placeholder(now));
        }
        self.next_expected_seq = block_count;
        Vec::new()
    }

    pub fn check_timers(&mut self, now: Instant) -> Vec<ReceiverEvent> {
        if self.terminal_failure.is_some() {
            return Vec::new();
        }

        let delay = Duration::from_millis(self.repair_config.delay_ms);
        let deadline = Duration::from_millis(self.repair_config.deadline_ms);
        let max_reqs = self.repair_config.max_reqs;
        let spread_retry_ms = if max_reqs == 0 {
            0
        } else {
            self.repair_config
                .deadline_ms
                .saturating_sub(self.repair_config.delay_ms)
                / u64::from(max_reqs)
        };
        let retry = Duration::from_millis(self.repair_config.retry_ms.max(spread_retry_ms));

        if let Some(failed_seq) = self
            .blocks
            .iter()
            .filter(|(_, state)| !state.decoded && now.duration_since(state.first_seen) >= deadline)
            .map(|(&seq, _)| seq)
            .min()
        {
            return self.fail(failed_seq);
        }

        let mut events = Vec::new();

        for (&seq, state) in &mut self.blocks {
            if state.decoded {
                continue;
            }
            let elapsed = now.duration_since(state.first_seen);

            if state.repairs_sent < max_reqs {
                let should_request = if state.repairs_sent == 0 {
                    elapsed >= delay
                } else {
                    state
                        .last_repair_at
                        .is_some_and(|last| now.duration_since(last) >= retry)
                };

                if should_request {
                    let count = state.k_eff.unwrap_or(self.peer_k_max);
                    events.push(ReceiverEvent::RepairNeeded {
                        block_seq: seq,
                        count,
                    });
                    state.repairs_sent += 1;
                    state.last_repair_at = Some(now);
                }
            }
        }

        events
    }

    pub fn drain_deliverable(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut result = Vec::new();
        while self
            .terminal_failure
            .is_none_or(|failed_seq| self.next_deliver_seq < failed_seq)
        {
            let Some(data) = self.delivered.remove(&self.next_deliver_seq) else {
                break;
            };
            let seq = self.next_deliver_seq;
            self.blocks.remove(&seq);
            result.push((seq, data));
            self.next_deliver_seq = self.next_deliver_seq.saturating_add(1);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raptorq::SourceBlockEncoder;
    use std::thread;

    fn test_repair_config() -> RepairConfig {
        RepairConfig {
            delay_ms: 1,
            retry_ms: 5,
            deadline_ms: 50,
            max_reqs: 2,
        }
    }

    const T: u16 = 64; // small symbol size for tests

    /// Encode a payload into Symbols using raptorq directly.
    fn encode_block(payload: &[u8], block_seq: u32) -> Vec<Symbol> {
        let k_eff = (payload.len() as u32).div_ceil(T as u32).max(1) as u16;
        let transfer_length = k_eff as u64 * T as u64;
        let config = ObjectTransmissionInformation::new(transfer_length, T, 1, 1, 8);
        // Pad payload to transfer_length.
        let mut padded = payload.to_vec();
        padded.resize(transfer_length as usize, 0);
        let encoder = SourceBlockEncoder::new(0, &config, &padded);

        let mut symbols = Vec::new();
        for pkt in encoder.source_packets() {
            let pid = pkt.payload_id();
            let esi = pid.encoding_symbol_id() as u16;
            let (_, data) = pkt.split();
            symbols.push(Symbol {
                block_seq,
                esi,
                k_eff,
                block_payload_len: payload.len() as u32,
                data,
            });
        }
        symbols
    }

    /// Encode repair symbols for a payload.
    fn encode_repair(payload: &[u8], block_seq: u32, count: u32) -> Vec<Symbol> {
        let k_eff = (payload.len() as u32).div_ceil(T as u32).max(1) as u16;
        let transfer_length = k_eff as u64 * T as u64;
        let config = ObjectTransmissionInformation::new(transfer_length, T, 1, 1, 8);
        let mut padded = payload.to_vec();
        padded.resize(transfer_length as usize, 0);
        let encoder = SourceBlockEncoder::new(0, &config, &padded);

        let mut symbols = Vec::new();
        for pkt in encoder.repair_packets(0, count) {
            let pid = pkt.payload_id();
            let esi = pid.encoding_symbol_id() as u16;
            let (_, data) = pkt.split();
            symbols.push(Symbol {
                block_seq,
                esi,
                k_eff,
                block_payload_len: payload.len() as u32,
                data,
            });
        }
        symbols
    }

    #[test]
    fn test_decode_single_block() {
        let payload = b"hello world, this is a test payload for raptorq receiver!";
        let symbols = encode_block(payload, 0);
        let mut rx = BlockReceiver::new(T, test_repair_config(), 64, 10);

        let mut events = Vec::new();
        for sym in symbols {
            events.extend(rx.receive_symbol(sym));
        }

        assert!(
            events.iter().any(|e| matches!(e,
                ReceiverEvent::Decoded { block_seq: 0, payload: p }
                if p == payload
            )),
            "expected Decoded event with correct payload, got: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ReceiverEvent::Ack { block_seq: 0 }))
        );
    }

    #[test]
    fn test_decode_truncates_padding() {
        // Payload shorter than k_eff * T (not a multiple of T).
        let payload = b"short";
        let symbols = encode_block(payload, 0);
        let mut rx = BlockReceiver::new(T, test_repair_config(), 64, 10);

        let mut events = Vec::new();
        for sym in symbols {
            events.extend(rx.receive_symbol(sym));
        }

        let decoded = events.iter().find_map(|e| match e {
            ReceiverEvent::Decoded { payload, .. } => Some(payload),
            _ => None,
        });
        assert_eq!(decoded.unwrap().as_slice(), payload);
    }

    #[test]
    fn test_gap_detection() {
        let mut rx = BlockReceiver::new(T, test_repair_config(), 64, 10);
        // Feed symbol for block 3 when expecting 0.
        let payload = vec![0xABu8; T as usize];
        let symbols = encode_block(&payload, 3);
        rx.receive_symbol(symbols.into_iter().next().unwrap());

        // Blocks 0, 1, 2 should have placeholder state.
        assert!(rx.blocks.contains_key(&0));
        assert!(rx.blocks.contains_key(&1));
        assert!(rx.blocks.contains_key(&2));
        assert!(rx.blocks.contains_key(&3));

        // Placeholders have no decoder yet.
        assert!(rx.blocks[&0].decoder.is_none());
        assert!(rx.blocks[&1].decoder.is_none());
        assert!(rx.blocks[&2].decoder.is_none());
    }

    #[test]
    fn test_fin_announcement_materializes_fully_lost_tail_block() {
        let mut rx = BlockReceiver::new(T, test_repair_config(), 64, 10);
        let events = rx.expect_block_count(1);
        assert!(events.is_empty());
        assert!(rx.blocks.contains_key(&0));
        assert!(rx.blocks[&0].decoder.is_none());
        assert_eq!(rx.next_expected_seq, 1);
    }

    #[test]
    fn test_gap_over_window_fails_fast() {
        let mut rx = BlockReceiver::new(T, test_repair_config(), 32, 10);
        let payload = vec![0xCDu8; T as usize];
        let symbols = encode_block(&payload, 1000);
        let events = rx.receive_symbol(symbols.into_iter().next().unwrap());

        assert!(
            events
                .iter()
                .any(|e| matches!(e, ReceiverEvent::Failed { block_seq: 0, .. }))
        );
        assert!(rx.blocks.is_empty());
        assert_eq!(rx.next_deliver_seq, 0);
        assert_eq!(rx.terminal_failure, Some(0));
    }

    #[test]
    fn test_drain_in_order() {
        let mut rx = BlockReceiver::new(T, test_repair_config(), 64, 10);
        let payload0 = b"block zero payload!!";
        let payload1 = b"block one payload!!!";
        let payload2 = b"block two payload!!!";

        // Decode blocks out of order: 2, 0, 1.
        for sym in encode_block(payload2, 2) {
            rx.receive_symbol(sym);
        }
        for sym in encode_block(payload0, 0) {
            rx.receive_symbol(sym);
        }

        // Drain should return 0 first — but block 1 is missing so only 0.
        let drained = rx.drain_deliverable();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 0);
        assert_eq!(drained[0].1, payload0);

        // Now decode block 1.
        for sym in encode_block(payload1, 1) {
            rx.receive_symbol(sym);
        }

        // Drain should now return 1 and 2 in order.
        let drained = rx.drain_deliverable();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].0, 1);
        assert_eq!(drained[0].1, payload1);
        assert_eq!(drained[1].0, 2);
        assert_eq!(drained[1].1, payload2);
    }

    #[test]
    fn test_deadline_failure() {
        let cfg = RepairConfig {
            delay_ms: 1,
            retry_ms: 2,
            deadline_ms: 5,
            max_reqs: 2,
        };
        let mut rx = BlockReceiver::new(T, cfg, 64, 10);

        // Create a placeholder by sending a symbol for block 1 (gap creates block 0).
        let payload = vec![0xAAu8; T as usize];
        let symbols = encode_block(&payload, 1);
        rx.receive_symbol(symbols.into_iter().next().unwrap());

        // Block 0 is a placeholder (undecoded). Wait past deadline.
        thread::sleep(Duration::from_millis(10));
        let now = Instant::now();
        let events = rx.check_timers(now);

        // Block 0 should have Failed.
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ReceiverEvent::Failed { block_seq: 0, .. })),
            "expected Failed for block 0, got: {events:?}"
        );
        // Block 0 should be removed.
        assert!(!rx.blocks.contains_key(&0));
    }

    #[test]
    fn test_repair_timing() {
        let cfg = RepairConfig {
            delay_ms: 1,
            retry_ms: 100,
            deadline_ms: 200,
            max_reqs: 2,
        };
        let mut rx = BlockReceiver::new(T, cfg, 64, 10);

        // Create placeholder block 0 by sending block 1.
        let payload = vec![0xBBu8; T as usize];
        let symbols = encode_block(&payload, 1);
        rx.receive_symbol(symbols.into_iter().next().unwrap());

        // Wait past delay_ms.
        thread::sleep(Duration::from_millis(5));
        let now = Instant::now();
        let events = rx.check_timers(now);

        // Should get RepairNeeded for block 0.
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ReceiverEvent::RepairNeeded { block_seq: 0, .. })),
            "expected RepairNeeded for block 0, got: {events:?}"
        );

        // repairs_sent should now be 1.
        assert_eq!(rx.blocks[&0].repairs_sent, 1);
    }

    #[test]
    fn test_failed_head_prevents_later_delivery() {
        let cfg = RepairConfig {
            delay_ms: 1,
            retry_ms: 2,
            deadline_ms: 5,
            max_reqs: 2,
        };
        let mut rx = BlockReceiver::new(T, cfg, 64, 10);

        // Block 0 missing; block 1 decodes immediately.
        let payload1 = vec![0xBCu8; T as usize];
        for sym in encode_block(&payload1, 1) {
            rx.receive_symbol(sym);
        }
        assert!(rx.drain_deliverable().is_empty());

        thread::sleep(Duration::from_millis(10));
        let _ = rx.check_timers(Instant::now());

        assert_eq!(rx.terminal_failure, Some(0));
        assert!(rx.drain_deliverable().is_empty());

        // Even a subsequently valid block cannot revive delivery.
        let later_events = rx.receive_symbol(encode_block(&payload1, 2).remove(0));
        assert!(later_events.is_empty());
        assert!(rx.drain_deliverable().is_empty());
    }

    #[test]
    fn test_retry_spacing_uses_last_request_time() {
        let cfg = RepairConfig {
            delay_ms: 1,
            retry_ms: 50,
            deadline_ms: 200,
            max_reqs: 3,
        };
        let mut rx = BlockReceiver::new(T, cfg, 64, 10);

        // Create placeholder block 0 by sending one symbol for block 1.
        let payload = vec![0xDDu8; T as usize];
        let symbols = encode_block(&payload, 1);
        rx.receive_symbol(symbols.into_iter().next().unwrap());

        thread::sleep(Duration::from_millis(5));
        let first = rx.check_timers(Instant::now());
        assert!(
            first
                .iter()
                .any(|e| matches!(e, ReceiverEvent::RepairNeeded { block_seq: 0, .. }))
        );

        let immediate = rx.check_timers(Instant::now());
        assert!(
            !immediate
                .iter()
                .any(|e| matches!(e, ReceiverEvent::RepairNeeded { block_seq: 0, .. }))
        );

        thread::sleep(Duration::from_millis(75));
        let second = rx.check_timers(Instant::now());
        assert!(
            second
                .iter()
                .any(|e| matches!(e, ReceiverEvent::RepairNeeded { block_seq: 0, .. }))
        );
    }

    #[test]
    fn test_metadata_mismatch_fails_block() {
        let mut rx = BlockReceiver::new(T, test_repair_config(), 64, 10);
        let payload = vec![0xEEu8; T as usize * 2];
        let mut symbols = encode_block(&payload, 0);

        let first = symbols.remove(0);
        let mut second = symbols.remove(0);
        second.k_eff = 1;
        second.block_payload_len = T as u32;

        let first_events = rx.receive_symbol(first);
        assert!(
            first_events
                .iter()
                .all(|e| !matches!(e, ReceiverEvent::Failed { .. }))
        );

        let events = rx.receive_symbol(second);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ReceiverEvent::Failed { block_seq: 0, .. }))
        );
        assert!(!rx.blocks.contains_key(&0));
        assert_eq!(rx.terminal_failure, Some(0));
    }

    #[test]
    fn test_malformed_symbols_fail_once_without_decoder_panic() {
        let payload = vec![0xA5u8; T as usize];
        let valid = encode_block(&payload, 0).remove(0);
        let malformed_symbols = [
            Symbol {
                data: vec![0; T as usize - 1],
                ..valid.clone()
            },
            Symbol {
                k_eff: 0,
                ..valid.clone()
            },
            Symbol {
                k_eff: 11,
                block_payload_len: T as u32 * 11,
                ..valid.clone()
            },
            Symbol {
                block_payload_len: 0,
                ..valid.clone()
            },
            Symbol {
                block_payload_len: T as u32 + 1,
                ..valid.clone()
            },
        ];

        for malformed in malformed_symbols {
            let mut rx = BlockReceiver::new(T, test_repair_config(), 64, 10);
            assert_eq!(
                rx.receive_symbol(malformed.clone()),
                vec![ReceiverEvent::Failed { block_seq: 0 }]
            );
            assert!(rx.receive_symbol(malformed).is_empty());
            assert_eq!(rx.terminal_failure, Some(0));
            assert!(rx.blocks.is_empty());
        }
    }

    #[test]
    fn test_pending_future_blocks_are_bounded_by_reorder_window() {
        let payload = vec![0xB6u8; T as usize];
        let mut rx = BlockReceiver::new(T, test_repair_config(), 4, 10);

        let boundary_events = rx.receive_symbol(encode_block(&payload, 4).remove(0));
        assert!(
            boundary_events
                .iter()
                .any(|event| matches!(event, ReceiverEvent::Decoded { block_seq: 4, .. }))
        );
        assert_eq!(rx.blocks.len(), 5);

        let events = rx.receive_symbol(encode_block(&payload, 5).remove(0));
        assert_eq!(events, vec![ReceiverEvent::Failed { block_seq: 0 }]);
        assert_eq!(rx.terminal_failure, Some(0));
        assert!(rx.blocks.is_empty());
    }

    #[test]
    fn test_late_symbol_after_drain_ignored() {
        // Regression: after a block is decoded and drained, a late repair
        // symbol must NOT recreate a placeholder that ghosts into a failure.
        let mut rx = BlockReceiver::new(T, test_repair_config(), 64, 10);
        let payload = vec![0xCCu8; T as usize * 3];

        // Decode and drain block 0.
        for sym in encode_block(&payload, 0) {
            rx.receive_symbol(sym);
        }
        let drained = rx.drain_deliverable();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 0);
        assert!(!rx.blocks.contains_key(&0));

        // A late repair symbol for block 0 arrives.
        let repairs = encode_repair(&payload, 0, 1);
        let events = rx.receive_symbol(repairs.into_iter().next().unwrap());

        // Must be ignored — no new block state created.
        assert!(events.is_empty());
        assert!(!rx.blocks.contains_key(&0), "ghost block recreated");
    }
}
