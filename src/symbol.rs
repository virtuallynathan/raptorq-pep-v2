/// A RaptorQ encoding symbol with the metadata needed to reconstruct its
/// independently ordered flow block.
#[derive(Clone, Debug)]
pub struct Symbol {
    pub block_seq: u32,
    pub esi: u16,
    pub k_eff: u16,
    pub block_payload_len: u32,
    pub data: Vec<u8>,
}
