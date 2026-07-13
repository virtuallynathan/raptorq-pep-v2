use std::collections::{HashMap, VecDeque};

use raptorq::{ObjectTransmissionInformation, SourceBlockEncoder};

use crate::config::{FecProfile, WIRE_ESI_SPACE};
use crate::symbol::Symbol;

const MAX_REPAIR_SYMBOLS_PER_REQUEST: u32 = 1024;
const MAX_REPAIR_BYTES_PER_BATCH: u32 = 1024 * 1024;

// ---------------------------------------------------------------------------
// Cached state for a single encoded block
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct CachedEncoder {
    encoder: SourceBlockEncoder,
    next_repair_esi: u32,
    k_eff: u16,
    block_payload_len: u32,
}

// ---------------------------------------------------------------------------
// BlockSender
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct BlockSender {
    profile: FecProfile,
    symbol_size: u16,
    next_block_seq: u32,
    cache: HashMap<u32, CachedEncoder>,
    cache_order: VecDeque<u32>,
    cache_capacity: usize,
}

impl BlockSender {
    pub fn new(profile: FecProfile, symbol_size: u16, cache_capacity: usize) -> Self {
        Self {
            profile,
            symbol_size,
            next_block_seq: 0,
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
            cache_capacity: cache_capacity.max(1),
        }
    }

    /// Encode `payload` into source + repair symbols for one block.
    ///
    /// Caller guarantees `payload` is non-empty.
    pub fn form_block(&mut self, payload: &[u8]) -> Vec<Symbol> {
        let k_eff = self.profile.k_eff(payload.len() as u32, self.symbol_size);
        let repair_byte_budget = MAX_REPAIR_BYTES_PER_BATCH / u32::from(self.symbol_size).max(1);
        let r_eff = u32::from(self.profile.r_eff(k_eff))
            .min(repair_byte_budget)
            .min(WIRE_ESI_SPACE.saturating_sub(u32::from(k_eff)));

        let padded_len = k_eff as usize * self.symbol_size as usize;
        let mut padded_data = vec![0u8; padded_len];
        padded_data[..payload.len()].copy_from_slice(payload);

        let config = ObjectTransmissionInformation::new(
            padded_len as u64,
            self.symbol_size,
            1, // source_blocks
            1, // sub_blocks
            8, // alignment
        );

        let encoder = SourceBlockEncoder::new(0, &config, &padded_data);

        let source_pkts = encoder.source_packets();
        let repair_pkts = encoder.repair_packets(0, r_eff);

        let block_seq = self.next_block_seq;
        let block_payload_len = payload.len() as u32;

        let mut symbols = Vec::with_capacity(source_pkts.len() + repair_pkts.len());

        for pkt in source_pkts.into_iter().chain(repair_pkts.into_iter()) {
            let esi = u16::try_from(pkt.payload_id().encoding_symbol_id())
                .expect("source and initial repair ESIs fit the wire field");
            let (_, data) = pkt.split();
            symbols.push(Symbol {
                block_seq,
                esi,
                k_eff,
                block_payload_len,
                data,
            });
        }

        // Cache the encoder for potential repair requests.
        self.evict_if_full();
        self.cache.insert(
            block_seq,
            CachedEncoder {
                encoder,
                next_repair_esi: r_eff,
                k_eff,
                block_payload_len,
            },
        );
        self.cache_order.push_back(block_seq);

        self.next_block_seq += 1;
        symbols
    }

    /// Generate additional repair symbols for an earlier block.
    ///
    /// Returns an empty vec if the block is no longer cached.
    pub fn handle_repair_req(&mut self, block_seq: u32, count: u16) -> Vec<Symbol> {
        let cached = match self.cache.get_mut(&block_seq) {
            Some(c) => c,
            None => return Vec::new(),
        };

        let remaining_esi_budget = WIRE_ESI_SPACE
            .saturating_sub(u32::from(cached.k_eff))
            .saturating_sub(cached.next_repair_esi);
        let count = u32::from(count)
            .min(MAX_REPAIR_SYMBOLS_PER_REQUEST)
            .min(MAX_REPAIR_BYTES_PER_BATCH / u32::from(self.symbol_size).max(1))
            .min(remaining_esi_budget);
        if count == 0 {
            return Vec::new();
        }

        let repair_pkts = cached.encoder.repair_packets(cached.next_repair_esi, count);

        cached.next_repair_esi += count;

        repair_pkts
            .into_iter()
            .map(|pkt| {
                let esi = u16::try_from(pkt.payload_id().encoding_symbol_id())
                    .expect("repair ESI was capped to the wire field");
                let (_, data) = pkt.split();
                Symbol {
                    block_seq,
                    esi,
                    k_eff: cached.k_eff,
                    block_payload_len: cached.block_payload_len,
                    data,
                }
            })
            .collect()
    }

    /// Remove a block from the cache after receiving an ACK.
    pub fn handle_block_ack(&mut self, block_seq: u32) {
        self.cache.remove(&block_seq);
        self.cache_order.retain(|&seq| seq != block_seq);
    }

    fn evict_if_full(&mut self) {
        while self.cache.len() >= self.cache_capacity {
            if let Some(oldest) = self.cache_order.pop_front() {
                self.cache.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> FecProfile {
        FecProfile {
            k_max: 10,
            r_base: 5,
            timeout_ms: 100,
        }
    }

    const T: u16 = 64; // symbol size for tests

    #[test]
    fn test_form_block_full() {
        let profile = test_profile();
        let mut sender = BlockSender::new(profile.clone(), T, 8);

        // payload exactly k_max * T => k_eff should be k_max
        let payload = vec![0xAB; profile.k_max as usize * T as usize];
        let symbols = sender.form_block(&payload);

        let k_eff = profile.k_eff(payload.len() as u32, T);
        let r_eff = profile.r_eff(k_eff);
        assert_eq!(k_eff, profile.k_max);
        assert_eq!(symbols.len(), (k_eff + r_eff) as usize);

        // All symbols have the right block_seq and k_eff.
        for sym in &symbols {
            assert_eq!(sym.block_seq, 0);
            assert_eq!(sym.k_eff, k_eff);
            assert_eq!(sym.block_payload_len, payload.len() as u32);
            assert_eq!(sym.data.len(), T as usize);
        }
    }

    #[test]
    fn test_form_block_partial() {
        let profile = test_profile();
        let mut sender = BlockSender::new(profile, T, 8);

        let payload = vec![0x01; 100];
        let symbols = sender.form_block(&payload);

        // 100 bytes / 64 = ceil = 2 source symbols
        let k_eff = 2u16;
        let expected_r = 1u16; // ceil(2 * 5 / 10) = 1
        assert_eq!(symbols.len(), (k_eff + expected_r) as usize);
        assert_eq!(symbols[0].k_eff, k_eff);
    }

    #[test]
    fn test_repair_after_form() {
        let profile = test_profile();
        let mut sender = BlockSender::new(profile, T, 8);

        let payload = vec![0xCC; 256];
        sender.form_block(&payload);

        let repairs = sender.handle_repair_req(0, 3);
        assert_eq!(repairs.len(), 3);
        for sym in &repairs {
            assert_eq!(sym.block_seq, 0);
            assert_eq!(sym.data.len(), T as usize);
        }
    }

    #[test]
    fn test_extreme_repair_request_is_capped() {
        let profile = test_profile();
        let mut sender = BlockSender::new(profile, T, 8);
        sender.form_block(&[0xCC; 64]);

        let first = sender.handle_repair_req(0, u16::MAX);
        let second = sender.handle_repair_req(0, u16::MAX);

        assert_eq!(first.len(), MAX_REPAIR_SYMBOLS_PER_REQUEST as usize);
        assert_eq!(second.len(), MAX_REPAIR_SYMBOLS_PER_REQUEST as usize);
        assert!(first.last().unwrap().esi < second.first().unwrap().esi);
    }

    #[test]
    fn test_total_repair_esi_stops_at_u16_boundary() {
        let profile = test_profile();
        let mut sender = BlockSender::new(profile, T, 8);
        sender.form_block(&[0xCC; 64]);

        let cached = sender.cache.get_mut(&0).unwrap();
        cached.next_repair_esi = WIRE_ESI_SPACE - u32::from(cached.k_eff) - 2;

        let final_repairs = sender.handle_repair_req(0, u16::MAX);
        assert_eq!(final_repairs.len(), 2);
        assert_eq!(final_repairs[0].esi, u16::MAX - 1);
        assert_eq!(final_repairs[1].esi, u16::MAX);
        assert!(sender.handle_repair_req(0, u16::MAX).is_empty());
    }

    #[test]
    fn test_block_ack_evicts() {
        let profile = test_profile();
        let mut sender = BlockSender::new(profile, T, 8);

        sender.form_block(&[0x01; 64]);
        sender.handle_block_ack(0);

        let repairs = sender.handle_repair_req(0, 1);
        assert!(repairs.is_empty());
    }

    #[test]
    fn test_cache_fifo_eviction() {
        let profile = test_profile();
        let capacity = 3;
        let mut sender = BlockSender::new(profile, T, capacity);

        // Fill to capacity + 1
        for _ in 0..=capacity {
            sender.form_block(&[0xFF; 64]);
        }

        // Block 0 (oldest) should have been evicted.
        assert!(!sender.cache.contains_key(&0));
        // Blocks 1..=3 should still be present.
        for seq in 1..=capacity as u32 {
            assert!(sender.cache.contains_key(&seq));
        }
    }

    #[test]
    fn test_block_seq_increments() {
        let profile = test_profile();
        let mut sender = BlockSender::new(profile, T, 8);

        let seqs: Vec<u32> = (0..3)
            .map(|_| {
                let syms = sender.form_block(&[0x01; 64]);
                syms[0].block_seq
            })
            .collect();

        assert_eq!(seqs, vec![0, 1, 2]);
    }
}
