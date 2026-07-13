//! Strict wire-v2 codec for the post-handshake, multi-flow data plane.
//!
//! The wire form is:
//!
//! ```text
//! 40-byte authenticated common header (AAD)
//! encrypted type-specific body
//! 16-byte ChaCha20-Poly1305 tag
//! ```
//!
//! The common header is intentionally fixed-size so a receiver can select a
//! session and direction key before decrypting. Header fields are untrusted
//! until the AEAD tag has been verified.

use std::fmt;

pub const MAGIC: [u8; 4] = *b"RQV2";
pub const VERSION: u8 = 2;
pub const COMMON_HEADER_LEN: usize = 40;
pub const AEAD_TAG_LEN: usize = 16;
pub const MAX_TARGET_LEN: usize = 512;
pub const MAX_OPEN_ERROR_MESSAGE_LEN: usize = 256;
pub const MAX_SYMBOL_SIZE: usize = u16::MAX as usize;
pub const MAX_DATA_BODY_LEN: usize = DATA_PREFIX_LEN + MAX_SYMBOL_SIZE;
pub const MAX_ENCRYPTED_BODY_LEN: usize = MAX_DATA_BODY_LEN;
// The current RaptorQ integration stores ESI in u16. Keep the wire contract
// aligned with the runtime until the encoder/decoder are migrated together.
pub const MAX_RAPTORQ_ESI: u32 = u16::MAX as u32;
pub const MAX_OPEN_ERROR_CODE: u16 = 4095;
pub const MAX_RESET_REASON_CODE: u16 = 4095;

pub const HANDSHAKE_TYPE_MIN: u8 = 0x01;
pub const HANDSHAKE_TYPE_MAX: u8 = 0x0f;

const OPEN_PREFIX_LEN: usize = 10;
const OPEN_ERROR_PREFIX_LEN: usize = 8;
const DATA_PREFIX_LEN: usize = 16;
const REPAIR_REQ_LEN: usize = 8;
const BLOCK_ACK_LEN: usize = 4;
const WINDOW_UPDATE_LEN: usize = 4;
const FIN_LEN: usize = 12;
const RESET_FLOW_LEN: usize = 4;
const TIMESTAMP_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    InitiatorToResponder = 0,
    ResponderToInitiator = 1,
}

impl TryFrom<u8> for Direction {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::InitiatorToResponder),
            1 => Ok(Self::ResponderToInitiator),
            other => Err(CodecError::InvalidDirection(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Open = 0x20,
    OpenOk = 0x21,
    OpenErr = 0x22,
    Data = 0x23,
    RepairReq = 0x24,
    BlockAck = 0x25,
    WindowUpdate = 0x26,
    Fin = 0x27,
    FinAck = 0x28,
    ResetFlow = 0x29,
    Ping = 0x2a,
    Pong = 0x2b,
    Rekey = 0x2c,
    ResetAck = 0x2d,
    PathChallenge = 0x2e,
    PathResponse = 0x2f,
}

impl TryFrom<u8> for MessageType {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x20 => Ok(Self::Open),
            0x21 => Ok(Self::OpenOk),
            0x22 => Ok(Self::OpenErr),
            0x23 => Ok(Self::Data),
            0x24 => Ok(Self::RepairReq),
            0x25 => Ok(Self::BlockAck),
            0x26 => Ok(Self::WindowUpdate),
            0x27 => Ok(Self::Fin),
            0x28 => Ok(Self::FinAck),
            0x29 => Ok(Self::ResetFlow),
            0x2a => Ok(Self::Ping),
            0x2b => Ok(Self::Pong),
            0x2c => Ok(Self::Rekey),
            0x2d => Ok(Self::ResetAck),
            0x2e => Ok(Self::PathChallenge),
            0x2f => Ok(Self::PathResponse),
            HANDSHAKE_TYPE_MIN..=HANDSHAKE_TYPE_MAX => Err(CodecError::HandshakePacketType(value)),
            other => Err(CodecError::InvalidMessageType(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    pub direction: Direction,
    pub session_id: u64,
    pub packet_seq: u64,
    pub flow_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireHeader {
    pub message_type: MessageType,
    pub direction: Direction,
    pub body_len: u32,
    pub session_id: u64,
    pub packet_seq: u64,
    pub flow_id: u64,
}

impl WireHeader {
    pub fn packet_header(self) -> PacketHeader {
        PacketHeader {
            direction: self.direction,
            session_id: self.session_id,
            packet_seq: self.packet_seq,
            flow_id: self.flow_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message<'a> {
    Open {
        target: &'a str,
        symbol_size: u16,
        up_k: u16,
        down_k: u16,
    },
    OpenOk,
    OpenErr {
        code: u16,
        message: &'a str,
    },
    Data {
        block_seq: u32,
        esi: u32,
        k_eff: u16,
        block_payload_len: u32,
        symbol: &'a [u8],
    },
    RepairReq {
        block_seq: u32,
        count: u16,
    },
    BlockAck {
        block_seq: u32,
    },
    WindowUpdate {
        credit_bytes: u32,
    },
    Fin {
        final_block_seq: u32,
        final_byte_count: u64,
    },
    FinAck,
    ResetFlow {
        reason: u16,
    },
    ResetAck,
    Ping {
        timestamp: u64,
    },
    Pong {
        timestamp: u64,
    },
    Rekey,
    PathChallenge {
        token: u64,
    },
    PathResponse {
        token: u64,
    },
}

impl Message<'_> {
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Open { .. } => MessageType::Open,
            Self::OpenOk => MessageType::OpenOk,
            Self::OpenErr { .. } => MessageType::OpenErr,
            Self::Data { .. } => MessageType::Data,
            Self::RepairReq { .. } => MessageType::RepairReq,
            Self::BlockAck { .. } => MessageType::BlockAck,
            Self::WindowUpdate { .. } => MessageType::WindowUpdate,
            Self::Fin { .. } => MessageType::Fin,
            Self::FinAck => MessageType::FinAck,
            Self::ResetFlow { .. } => MessageType::ResetFlow,
            Self::ResetAck => MessageType::ResetAck,
            Self::Ping { .. } => MessageType::Ping,
            Self::Pong { .. } => MessageType::Pong,
            Self::Rekey => MessageType::Rekey,
            Self::PathChallenge { .. } => MessageType::PathChallenge,
            Self::PathResponse { .. } => MessageType::PathResponse,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub header: PacketHeader,
    pub message: Message<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedParts {
    pub aad: [u8; COMMON_HEADER_LEN],
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedParts<'a> {
    /// Fixed common header. This is suitable for passing directly as AEAD AAD.
    aad: &'a [u8],
    /// Contiguous ciphertext followed by its 16-byte authentication tag.
    ciphertext_and_tag: &'a [u8],
    /// Parsed but unauthenticated header values.
    pub unverified_header: WireHeader,
}

impl<'a> SealedParts<'a> {
    pub fn aad(&self) -> &'a [u8] {
        self.aad
    }

    pub fn ciphertext_and_tag(&self) -> &'a [u8] {
        self.ciphertext_and_tag
    }

    #[cfg(test)]
    pub fn ciphertext(&self) -> &'a [u8] {
        let ciphertext_len = self.ciphertext_and_tag.len() - AEAD_TAG_LEN;
        &self.ciphertext_and_tag[..ciphertext_len]
    }

    #[cfg(test)]
    pub fn tag(&self) -> &'a [u8] {
        let tag_start = self.ciphertext_and_tag.len() - AEAD_TAG_LEN;
        &self.ciphertext_and_tag[tag_start..]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    BufferTooShort {
        context: &'static str,
        needed: usize,
        actual: usize,
    },
    InvalidLength {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidMagic,
    InvalidVersion(u8),
    HandshakePacketType(u8),
    InvalidMessageType(u8),
    InvalidDirection(u8),
    InvalidFlags(u8),
    NonZeroReserved {
        context: &'static str,
    },
    BodyTooLarge {
        actual: usize,
        maximum: usize,
    },
    BodyLengthMismatch {
        declared: usize,
        actual: usize,
    },
    MissingSymbolSize,
    InvalidSymbolSize(u16),
    InvalidSymbolLength {
        expected: usize,
        actual: usize,
    },
    InvalidEsi(u32),
    InvalidK {
        context: &'static str,
        value: u16,
    },
    InvalidBlockPayloadLength {
        actual: u32,
        maximum: u32,
    },
    InvalidRepairCount(u16),
    EmptyTarget,
    TargetTooLong {
        actual: usize,
        maximum: usize,
    },
    InvalidTarget,
    InvalidUtf8 {
        context: &'static str,
    },
    InvalidOpenErrorCode(u16),
    OpenErrorMessageTooLong {
        actual: usize,
        maximum: usize,
    },
    InvalidResetReason(u16),
    LengthOverflow {
        context: &'static str,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort {
                context,
                needed,
                actual,
            } => write!(
                f,
                "{context} is too short: need at least {needed} bytes, got {actual}"
            ),
            Self::InvalidLength {
                context,
                expected,
                actual,
            } => write!(
                f,
                "invalid {context} length: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidMagic => write!(f, "invalid wire-v2 magic"),
            Self::InvalidVersion(version) => write!(f, "unsupported wire version {version}"),
            Self::HandshakePacketType(value) => {
                write!(f, "packet type 0x{value:02x} is reserved for the handshake")
            }
            Self::InvalidMessageType(value) => {
                write!(f, "invalid data-plane message type 0x{value:02x}")
            }
            Self::InvalidDirection(value) => write!(f, "invalid direction {value}"),
            Self::InvalidFlags(value) => write!(f, "unsupported flags 0x{value:02x}"),
            Self::NonZeroReserved { context } => {
                write!(f, "{context} reserved field must be zero")
            }
            Self::BodyTooLarge { actual, maximum } => {
                write!(f, "encrypted body is too large: {actual} > {maximum}")
            }
            Self::BodyLengthMismatch { declared, actual } => write!(
                f,
                "encrypted body length mismatch: header declares {declared}, got {actual}"
            ),
            Self::MissingSymbolSize => write!(f, "flow symbol size is required for Data"),
            Self::InvalidSymbolSize(size) => write!(f, "invalid symbol size {size}"),
            Self::InvalidSymbolLength { expected, actual } => write!(
                f,
                "invalid symbol length: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidEsi(esi) => write!(f, "RaptorQ ESI exceeds wire limit: {esi}"),
            Self::InvalidK { context, value } => {
                write!(f, "invalid {context} value {value}; it must be nonzero")
            }
            Self::InvalidBlockPayloadLength { actual, maximum } => write!(
                f,
                "block payload length {actual} exceeds effective block capacity {maximum}"
            ),
            Self::InvalidRepairCount(count) => {
                write!(f, "invalid repair count {count}; it must be nonzero")
            }
            Self::EmptyTarget => write!(f, "Open target must not be empty"),
            Self::TargetTooLong { actual, maximum } => {
                write!(f, "Open target is too long: {actual} > {maximum}")
            }
            Self::InvalidTarget => write!(f, "Open target must be a valid host:port"),
            Self::InvalidUtf8 { context } => write!(f, "{context} is not valid UTF-8"),
            Self::InvalidOpenErrorCode(code) => write!(
                f,
                "OpenErr code {code} is outside 1..={MAX_OPEN_ERROR_CODE}"
            ),
            Self::OpenErrorMessageTooLong { actual, maximum } => {
                write!(f, "OpenErr message is too long: {actual} > {maximum}")
            }
            Self::InvalidResetReason(reason) => write!(
                f,
                "ResetFlow reason {reason} is outside 1..={MAX_RESET_REASON_CODE}"
            ),
            Self::LengthOverflow { context } => {
                write!(f, "{context} length cannot be represented on the wire")
            }
        }
    }
}

impl std::error::Error for CodecError {}

/// Encode a packet into the bytes supplied separately to ChaCha20-Poly1305.
///
/// `flow_symbol_size` is required for `Data` and must equal the symbol body
/// length. It should be `None` for messages that are not `Data`.
pub fn encode_parts(
    packet: &Packet<'_>,
    flow_symbol_size: Option<u16>,
) -> Result<EncodedParts, CodecError> {
    let body = encode_body(&packet.message, flow_symbol_size)?;
    if body.len() > MAX_ENCRYPTED_BODY_LEN {
        return Err(CodecError::BodyTooLarge {
            actual: body.len(),
            maximum: MAX_ENCRYPTED_BODY_LEN,
        });
    }
    let body_len = u32::try_from(body.len()).map_err(|_| CodecError::LengthOverflow {
        context: "encrypted body",
    })?;
    let wire_header = WireHeader {
        message_type: packet.message.message_type(),
        direction: packet.header.direction,
        body_len,
        session_id: packet.header.session_id,
        packet_seq: packet.header.packet_seq,
        flow_id: packet.header.flow_id,
    };
    let aad = encode_aad(wire_header);
    Ok(EncodedParts { aad, body })
}

/// Parse and validate the fixed AAD header.
///
/// Values returned by this function remain untrusted until AEAD verification.
pub fn decode_aad(aad: &[u8]) -> Result<WireHeader, CodecError> {
    if aad.len() != COMMON_HEADER_LEN {
        return Err(CodecError::InvalidLength {
            context: "AAD",
            expected: COMMON_HEADER_LEN,
            actual: aad.len(),
        });
    }
    if aad.get(0..4) != Some(MAGIC.as_slice()) {
        return Err(CodecError::InvalidMagic);
    }
    if aad[4] != VERSION {
        return Err(CodecError::InvalidVersion(aad[4]));
    }
    let message_type = MessageType::try_from(aad[5])?;
    let direction = Direction::try_from(aad[6])?;
    if aad[7] != 0 {
        return Err(CodecError::InvalidFlags(aad[7]));
    }
    let body_len = read_u32(aad, 8, "AAD body length")?;
    if aad.get(12..16) != Some(&[0, 0, 0, 0]) {
        return Err(CodecError::NonZeroReserved {
            context: "common header",
        });
    }
    let body_len_usize = usize::try_from(body_len).map_err(|_| CodecError::LengthOverflow {
        context: "encrypted body",
    })?;
    if body_len_usize > MAX_ENCRYPTED_BODY_LEN {
        return Err(CodecError::BodyTooLarge {
            actual: body_len_usize,
            maximum: MAX_ENCRYPTED_BODY_LEN,
        });
    }
    Ok(WireHeader {
        message_type,
        direction,
        body_len,
        session_id: read_u64(aad, 16, "AAD session id")?,
        packet_seq: read_u64(aad, 24, "AAD packet sequence")?,
        flow_id: read_u64(aad, 32, "AAD flow id")?,
    })
}

/// Split a complete datagram without allocating.
///
/// This validates all cleartext header fields and the exact datagram length,
/// but the returned header must not be acted on beyond key/session selection
/// until `ciphertext_and_tag` has been authenticated using `aad`.
pub fn split_sealed_datagram(datagram: &[u8]) -> Result<SealedParts<'_>, CodecError> {
    let minimum = COMMON_HEADER_LEN + AEAD_TAG_LEN;
    if datagram.len() < minimum {
        return Err(CodecError::BufferTooShort {
            context: "sealed datagram",
            needed: minimum,
            actual: datagram.len(),
        });
    }
    let aad = datagram
        .get(..COMMON_HEADER_LEN)
        .ok_or(CodecError::BufferTooShort {
            context: "sealed datagram",
            needed: COMMON_HEADER_LEN,
            actual: datagram.len(),
        })?;
    let header = decode_aad(aad)?;
    let body_len = usize::try_from(header.body_len).map_err(|_| CodecError::LengthOverflow {
        context: "encrypted body",
    })?;
    let expected = COMMON_HEADER_LEN
        .checked_add(body_len)
        .and_then(|length| length.checked_add(AEAD_TAG_LEN))
        .ok_or(CodecError::LengthOverflow {
            context: "sealed datagram",
        })?;
    if datagram.len() != expected {
        return Err(CodecError::InvalidLength {
            context: "sealed datagram",
            expected,
            actual: datagram.len(),
        });
    }
    let ciphertext_and_tag =
        datagram
            .get(COMMON_HEADER_LEN..)
            .ok_or(CodecError::BufferTooShort {
                context: "sealed datagram",
                needed: expected,
                actual: datagram.len(),
            })?;
    Ok(SealedParts {
        aad,
        ciphertext_and_tag,
        unverified_header: header,
    })
}

/// Decode an authenticated plaintext body, borrowing strings and symbols.
///
/// Call this only after successfully authenticating/decrypting the body with
/// the exact `aad` bytes. `flow_symbol_size` is required only for `Data`.
pub fn decode_parts<'a>(
    aad: &[u8],
    plaintext: &'a [u8],
    flow_symbol_size: Option<u16>,
) -> Result<Packet<'a>, CodecError> {
    let wire_header = decode_aad(aad)?;
    let declared =
        usize::try_from(wire_header.body_len).map_err(|_| CodecError::LengthOverflow {
            context: "encrypted body",
        })?;
    if plaintext.len() != declared {
        return Err(CodecError::BodyLengthMismatch {
            declared,
            actual: plaintext.len(),
        });
    }
    let message = decode_body(wire_header.message_type, plaintext, flow_symbol_size)?;
    Ok(Packet {
        header: wire_header.packet_header(),
        message,
    })
}

fn encode_aad(header: WireHeader) -> [u8; COMMON_HEADER_LEN] {
    let mut aad = [0u8; COMMON_HEADER_LEN];
    aad[0..4].copy_from_slice(&MAGIC);
    aad[4] = VERSION;
    aad[5] = header.message_type as u8;
    aad[6] = header.direction as u8;
    aad[7] = 0;
    aad[8..12].copy_from_slice(&header.body_len.to_be_bytes());
    aad[12..16].copy_from_slice(&0u32.to_be_bytes());
    aad[16..24].copy_from_slice(&header.session_id.to_be_bytes());
    aad[24..32].copy_from_slice(&header.packet_seq.to_be_bytes());
    aad[32..40].copy_from_slice(&header.flow_id.to_be_bytes());
    aad
}

fn encode_body(
    message: &Message<'_>,
    flow_symbol_size: Option<u16>,
) -> Result<Vec<u8>, CodecError> {
    let mut body = Vec::new();
    match message {
        Message::Open {
            target,
            symbol_size,
            up_k,
            down_k,
        } => {
            validate_target(target)?;
            validate_symbol_size(*symbol_size)?;
            validate_k("Open up_k", *up_k)?;
            validate_k("Open down_k", *down_k)?;
            let target_len =
                u16::try_from(target.len()).map_err(|_| CodecError::LengthOverflow {
                    context: "Open target",
                })?;
            body.reserve_exact(OPEN_PREFIX_LEN + target.len());
            push_u16(&mut body, target_len);
            push_u16(&mut body, *symbol_size);
            push_u16(&mut body, *up_k);
            push_u16(&mut body, *down_k);
            push_u16(&mut body, 0);
            body.extend_from_slice(target.as_bytes());
        }
        Message::OpenOk | Message::FinAck | Message::ResetAck | Message::Rekey => {}
        Message::OpenErr { code, message } => {
            validate_open_error(*code, message)?;
            let message_len =
                u16::try_from(message.len()).map_err(|_| CodecError::LengthOverflow {
                    context: "OpenErr message",
                })?;
            body.reserve_exact(OPEN_ERROR_PREFIX_LEN + message.len());
            push_u16(&mut body, *code);
            push_u16(&mut body, message_len);
            push_u32(&mut body, 0);
            body.extend_from_slice(message.as_bytes());
        }
        Message::Data {
            block_seq,
            esi,
            k_eff,
            block_payload_len,
            symbol,
        } => {
            let symbol_size = require_symbol_size(flow_symbol_size)?;
            validate_data(*esi, *k_eff, *block_payload_len, symbol, symbol_size)?;
            body.reserve_exact(DATA_PREFIX_LEN + symbol.len());
            push_u32(&mut body, *block_seq);
            push_u32(&mut body, *esi);
            push_u16(&mut body, *k_eff);
            push_u16(&mut body, 0);
            push_u32(&mut body, *block_payload_len);
            body.extend_from_slice(symbol);
        }
        Message::RepairReq { block_seq, count } => {
            if *count == 0 {
                return Err(CodecError::InvalidRepairCount(*count));
            }
            body.reserve_exact(REPAIR_REQ_LEN);
            push_u32(&mut body, *block_seq);
            push_u16(&mut body, *count);
            push_u16(&mut body, 0);
        }
        Message::BlockAck { block_seq } => {
            body.reserve_exact(BLOCK_ACK_LEN);
            push_u32(&mut body, *block_seq);
        }
        Message::WindowUpdate { credit_bytes } => {
            body.reserve_exact(WINDOW_UPDATE_LEN);
            push_u32(&mut body, *credit_bytes);
        }
        Message::Fin {
            final_block_seq,
            final_byte_count,
        } => {
            body.reserve_exact(FIN_LEN);
            push_u32(&mut body, *final_block_seq);
            push_u64(&mut body, *final_byte_count);
        }
        Message::ResetFlow { reason } => {
            validate_reset_reason(*reason)?;
            body.reserve_exact(RESET_FLOW_LEN);
            push_u16(&mut body, *reason);
            push_u16(&mut body, 0);
        }
        Message::Ping { timestamp } | Message::Pong { timestamp } => {
            body.reserve_exact(TIMESTAMP_LEN);
            push_u64(&mut body, *timestamp);
        }
        Message::PathChallenge { token } | Message::PathResponse { token } => {
            body.reserve_exact(TIMESTAMP_LEN);
            push_u64(&mut body, *token);
        }
    }
    Ok(body)
}

fn decode_body<'a>(
    message_type: MessageType,
    body: &'a [u8],
    flow_symbol_size: Option<u16>,
) -> Result<Message<'a>, CodecError> {
    match message_type {
        MessageType::Open => {
            require_min_len(body, OPEN_PREFIX_LEN, "Open body")?;
            let target_len = usize::from(read_u16(body, 0, "Open target length")?);
            let symbol_size = read_u16(body, 2, "Open symbol size")?;
            let up_k = read_u16(body, 4, "Open up_k")?;
            let down_k = read_u16(body, 6, "Open down_k")?;
            require_zero(body, 8..10, "Open")?;
            let expected =
                OPEN_PREFIX_LEN
                    .checked_add(target_len)
                    .ok_or(CodecError::LengthOverflow {
                        context: "Open body",
                    })?;
            require_exact_len(body, expected, "Open body")?;
            if target_len > MAX_TARGET_LEN {
                return Err(CodecError::TargetTooLong {
                    actual: target_len,
                    maximum: MAX_TARGET_LEN,
                });
            }
            let target_bytes = body
                .get(OPEN_PREFIX_LEN..)
                .ok_or(CodecError::BufferTooShort {
                    context: "Open target",
                    needed: expected,
                    actual: body.len(),
                })?;
            let target =
                std::str::from_utf8(target_bytes).map_err(|_| CodecError::InvalidUtf8 {
                    context: "Open target",
                })?;
            validate_target(target)?;
            validate_symbol_size(symbol_size)?;
            validate_k("Open up_k", up_k)?;
            validate_k("Open down_k", down_k)?;
            Ok(Message::Open {
                target,
                symbol_size,
                up_k,
                down_k,
            })
        }
        MessageType::OpenOk => {
            require_exact_len(body, 0, "OpenOk body")?;
            Ok(Message::OpenOk)
        }
        MessageType::OpenErr => {
            require_min_len(body, OPEN_ERROR_PREFIX_LEN, "OpenErr body")?;
            let code = read_u16(body, 0, "OpenErr code")?;
            let message_len = usize::from(read_u16(body, 2, "OpenErr message length")?);
            require_zero(body, 4..8, "OpenErr")?;
            let expected = OPEN_ERROR_PREFIX_LEN.checked_add(message_len).ok_or(
                CodecError::LengthOverflow {
                    context: "OpenErr body",
                },
            )?;
            require_exact_len(body, expected, "OpenErr body")?;
            if message_len > MAX_OPEN_ERROR_MESSAGE_LEN {
                return Err(CodecError::OpenErrorMessageTooLong {
                    actual: message_len,
                    maximum: MAX_OPEN_ERROR_MESSAGE_LEN,
                });
            }
            let message_bytes =
                body.get(OPEN_ERROR_PREFIX_LEN..)
                    .ok_or(CodecError::BufferTooShort {
                        context: "OpenErr message",
                        needed: expected,
                        actual: body.len(),
                    })?;
            let message =
                std::str::from_utf8(message_bytes).map_err(|_| CodecError::InvalidUtf8 {
                    context: "OpenErr message",
                })?;
            validate_open_error(code, message)?;
            Ok(Message::OpenErr { code, message })
        }
        MessageType::Data => {
            require_min_len(body, DATA_PREFIX_LEN, "Data body")?;
            let symbol_size = require_symbol_size(flow_symbol_size)?;
            let expected =
                DATA_PREFIX_LEN
                    .checked_add(symbol_size)
                    .ok_or(CodecError::LengthOverflow {
                        context: "Data body",
                    })?;
            require_exact_len(body, expected, "Data body")?;
            let block_seq = read_u32(body, 0, "Data block sequence")?;
            let esi = read_u32(body, 4, "Data ESI")?;
            let k_eff = read_u16(body, 8, "Data k_eff")?;
            require_zero(body, 10..12, "Data")?;
            let block_payload_len = read_u32(body, 12, "Data block payload length")?;
            let symbol = body
                .get(DATA_PREFIX_LEN..)
                .ok_or(CodecError::BufferTooShort {
                    context: "Data symbol",
                    needed: expected,
                    actual: body.len(),
                })?;
            validate_data(esi, k_eff, block_payload_len, symbol, symbol_size)?;
            Ok(Message::Data {
                block_seq,
                esi,
                k_eff,
                block_payload_len,
                symbol,
            })
        }
        MessageType::RepairReq => {
            require_exact_len(body, REPAIR_REQ_LEN, "RepairReq body")?;
            let block_seq = read_u32(body, 0, "RepairReq block sequence")?;
            let count = read_u16(body, 4, "RepairReq count")?;
            require_zero(body, 6..8, "RepairReq")?;
            if count == 0 {
                return Err(CodecError::InvalidRepairCount(count));
            }
            Ok(Message::RepairReq { block_seq, count })
        }
        MessageType::BlockAck => {
            require_exact_len(body, BLOCK_ACK_LEN, "BlockAck body")?;
            Ok(Message::BlockAck {
                block_seq: read_u32(body, 0, "BlockAck block sequence")?,
            })
        }
        MessageType::WindowUpdate => {
            require_exact_len(body, WINDOW_UPDATE_LEN, "WindowUpdate body")?;
            Ok(Message::WindowUpdate {
                credit_bytes: read_u32(body, 0, "WindowUpdate credit")?,
            })
        }
        MessageType::Fin => {
            require_exact_len(body, FIN_LEN, "Fin body")?;
            Ok(Message::Fin {
                final_block_seq: read_u32(body, 0, "Fin final block sequence")?,
                final_byte_count: read_u64(body, 4, "Fin final byte count")?,
            })
        }
        MessageType::FinAck => {
            require_exact_len(body, 0, "FinAck body")?;
            Ok(Message::FinAck)
        }
        MessageType::ResetFlow => {
            require_exact_len(body, RESET_FLOW_LEN, "ResetFlow body")?;
            let reason = read_u16(body, 0, "ResetFlow reason")?;
            require_zero(body, 2..4, "ResetFlow")?;
            validate_reset_reason(reason)?;
            Ok(Message::ResetFlow { reason })
        }
        MessageType::ResetAck => {
            require_exact_len(body, 0, "ResetAck body")?;
            Ok(Message::ResetAck)
        }
        MessageType::Ping => {
            require_exact_len(body, TIMESTAMP_LEN, "Ping body")?;
            Ok(Message::Ping {
                timestamp: read_u64(body, 0, "Ping timestamp")?,
            })
        }
        MessageType::Pong => {
            require_exact_len(body, TIMESTAMP_LEN, "Pong body")?;
            Ok(Message::Pong {
                timestamp: read_u64(body, 0, "Pong timestamp")?,
            })
        }
        MessageType::Rekey => {
            require_exact_len(body, 0, "Rekey body")?;
            Ok(Message::Rekey)
        }
        MessageType::PathChallenge => {
            require_exact_len(body, TIMESTAMP_LEN, "PathChallenge body")?;
            Ok(Message::PathChallenge {
                token: read_u64(body, 0, "PathChallenge token")?,
            })
        }
        MessageType::PathResponse => {
            require_exact_len(body, TIMESTAMP_LEN, "PathResponse body")?;
            Ok(Message::PathResponse {
                token: read_u64(body, 0, "PathResponse token")?,
            })
        }
    }
}

fn validate_symbol_size(symbol_size: u16) -> Result<(), CodecError> {
    if symbol_size == 0 {
        return Err(CodecError::InvalidSymbolSize(symbol_size));
    }
    Ok(())
}

fn require_symbol_size(symbol_size: Option<u16>) -> Result<usize, CodecError> {
    let symbol_size = symbol_size.ok_or(CodecError::MissingSymbolSize)?;
    validate_symbol_size(symbol_size)?;
    Ok(usize::from(symbol_size))
}

fn validate_k(context: &'static str, value: u16) -> Result<(), CodecError> {
    if value == 0 {
        return Err(CodecError::InvalidK { context, value });
    }
    Ok(())
}

fn validate_data(
    esi: u32,
    k_eff: u16,
    block_payload_len: u32,
    symbol: &[u8],
    symbol_size: usize,
) -> Result<(), CodecError> {
    if esi > MAX_RAPTORQ_ESI {
        return Err(CodecError::InvalidEsi(esi));
    }
    validate_k("Data k_eff", k_eff)?;
    if symbol.len() != symbol_size {
        return Err(CodecError::InvalidSymbolLength {
            expected: symbol_size,
            actual: symbol.len(),
        });
    }
    let maximum = u32::from(k_eff)
        .checked_mul(
            u32::try_from(symbol_size).map_err(|_| CodecError::LengthOverflow {
                context: "symbol size",
            })?,
        )
        .ok_or(CodecError::LengthOverflow {
            context: "block capacity",
        })?;
    if block_payload_len > maximum {
        return Err(CodecError::InvalidBlockPayloadLength {
            actual: block_payload_len,
            maximum,
        });
    }
    Ok(())
}

fn validate_target(target: &str) -> Result<(), CodecError> {
    let len = target.len();
    if len == 0 {
        return Err(CodecError::EmptyTarget);
    }
    if len > MAX_TARGET_LEN {
        return Err(CodecError::TargetTooLong {
            actual: len,
            maximum: MAX_TARGET_LEN,
        });
    }
    if target
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(CodecError::InvalidTarget);
    }

    let (host, port) = if let Some(bracketed) = target.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']').ok_or(CodecError::InvalidTarget)?;
        let port = suffix.strip_prefix(':').ok_or(CodecError::InvalidTarget)?;
        if suffix[1..].contains(':') {
            return Err(CodecError::InvalidTarget);
        }
        (host, port)
    } else {
        let (host, port) = target.rsplit_once(':').ok_or(CodecError::InvalidTarget)?;
        if host.contains(':') {
            return Err(CodecError::InvalidTarget);
        }
        (host, port)
    };

    if host.is_empty()
        || port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || host
            .bytes()
            .any(|byte| matches!(byte, b'[' | b']' | b'/' | b'\\' | b'\0'))
    {
        return Err(CodecError::InvalidTarget);
    }
    let port_number = port.parse::<u16>().map_err(|_| CodecError::InvalidTarget)?;
    if port_number == 0 {
        return Err(CodecError::InvalidTarget);
    }
    Ok(())
}

fn validate_open_error(code: u16, message: &str) -> Result<(), CodecError> {
    if !(1..=MAX_OPEN_ERROR_CODE).contains(&code) {
        return Err(CodecError::InvalidOpenErrorCode(code));
    }
    if message.len() > MAX_OPEN_ERROR_MESSAGE_LEN {
        return Err(CodecError::OpenErrorMessageTooLong {
            actual: message.len(),
            maximum: MAX_OPEN_ERROR_MESSAGE_LEN,
        });
    }
    Ok(())
}

fn validate_reset_reason(reason: u16) -> Result<(), CodecError> {
    if !(1..=MAX_RESET_REASON_CODE).contains(&reason) {
        return Err(CodecError::InvalidResetReason(reason));
    }
    Ok(())
}

fn require_min_len(input: &[u8], needed: usize, context: &'static str) -> Result<(), CodecError> {
    if input.len() < needed {
        return Err(CodecError::BufferTooShort {
            context,
            needed,
            actual: input.len(),
        });
    }
    Ok(())
}

fn require_exact_len(
    input: &[u8],
    expected: usize,
    context: &'static str,
) -> Result<(), CodecError> {
    if input.len() != expected {
        return Err(CodecError::InvalidLength {
            context,
            expected,
            actual: input.len(),
        });
    }
    Ok(())
}

fn require_zero(
    input: &[u8],
    range: std::ops::Range<usize>,
    context: &'static str,
) -> Result<(), CodecError> {
    let bytes = input.get(range.clone()).ok_or(CodecError::BufferTooShort {
        context,
        needed: range.end,
        actual: input.len(),
    })?;
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(CodecError::NonZeroReserved { context });
    }
    Ok(())
}

fn read_u16(input: &[u8], offset: usize, context: &'static str) -> Result<u16, CodecError> {
    let end = offset
        .checked_add(2)
        .ok_or(CodecError::LengthOverflow { context })?;
    let bytes = input.get(offset..end).ok_or(CodecError::BufferTooShort {
        context,
        needed: end,
        actual: input.len(),
    })?;
    let array: [u8; 2] = bytes.try_into().map_err(|_| CodecError::InvalidLength {
        context,
        expected: 2,
        actual: bytes.len(),
    })?;
    Ok(u16::from_be_bytes(array))
}

fn read_u32(input: &[u8], offset: usize, context: &'static str) -> Result<u32, CodecError> {
    let end = offset
        .checked_add(4)
        .ok_or(CodecError::LengthOverflow { context })?;
    let bytes = input.get(offset..end).ok_or(CodecError::BufferTooShort {
        context,
        needed: end,
        actual: input.len(),
    })?;
    let array: [u8; 4] = bytes.try_into().map_err(|_| CodecError::InvalidLength {
        context,
        expected: 4,
        actual: bytes.len(),
    })?;
    Ok(u32::from_be_bytes(array))
}

fn read_u64(input: &[u8], offset: usize, context: &'static str) -> Result<u64, CodecError> {
    let end = offset
        .checked_add(8)
        .ok_or(CodecError::LengthOverflow { context })?;
    let bytes = input.get(offset..end).ok_or(CodecError::BufferTooShort {
        context,
        needed: end,
        actual: input.len(),
    })?;
    let array: [u8; 8] = bytes.try_into().map_err(|_| CodecError::InvalidLength {
        context,
        expected: 8,
        actual: bytes.len(),
    })?;
    Ok(u64::from_be_bytes(array))
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYMBOL_SIZE: u16 = 4;
    const HEADER: PacketHeader = PacketHeader {
        direction: Direction::InitiatorToResponder,
        session_id: 0x0102_0304_0506_0708,
        packet_seq: 0x1112_1314_1516_1718,
        flow_id: 0x2122_2324_2526_2728,
    };

    fn expected_aad(message_type: MessageType, body_len: usize) -> [u8; COMMON_HEADER_LEN] {
        let mut expected = [
            b'R',
            b'Q',
            b'V',
            b'2',
            2,
            message_type as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x18,
            0x21,
            0x22,
            0x23,
            0x24,
            0x25,
            0x26,
            0x27,
            0x28,
        ];
        expected[8..12].copy_from_slice(&(body_len as u32).to_be_bytes());
        expected
    }

    fn golden_cases<'a>() -> Vec<(Message<'a>, Option<u16>, Vec<u8>)> {
        vec![
            (
                Message::Open {
                    target: "example.com:443",
                    symbol_size: 1280,
                    up_k: 24,
                    down_k: 32,
                },
                None,
                [&[0, 15, 5, 0, 0, 24, 0, 32, 0, 0][..], b"example.com:443"].concat(),
            ),
            (Message::OpenOk, None, vec![]),
            (
                Message::OpenErr {
                    code: 7,
                    message: "refused",
                },
                None,
                [&[0, 7, 0, 7, 0, 0, 0, 0][..], b"refused"].concat(),
            ),
            (
                Message::Data {
                    block_seq: 0x0102_0304,
                    esi: 0x0000_0b0c,
                    k_eff: 2,
                    block_payload_len: 8,
                    symbol: &[0xde, 0xad, 0xbe, 0xef],
                },
                Some(SYMBOL_SIZE),
                vec![
                    1, 2, 3, 4, 0, 0, 11, 12, 0, 2, 0, 0, 0, 0, 0, 8, 0xde, 0xad, 0xbe, 0xef,
                ],
            ),
            (
                Message::RepairReq {
                    block_seq: 0x0102_0304,
                    count: 5,
                },
                None,
                vec![1, 2, 3, 4, 0, 5, 0, 0],
            ),
            (
                Message::BlockAck {
                    block_seq: 0x0102_0304,
                },
                None,
                vec![1, 2, 3, 4],
            ),
            (
                Message::WindowUpdate {
                    credit_bytes: 0x0102_0304,
                },
                None,
                vec![1, 2, 3, 4],
            ),
            (
                Message::Fin {
                    final_block_seq: 0x0102_0304,
                    final_byte_count: 0x1112_1314_1516_1718,
                },
                None,
                vec![1, 2, 3, 4, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
            ),
            (Message::FinAck, None, vec![]),
            (Message::ResetFlow { reason: 9 }, None, vec![0, 9, 0, 0]),
            (Message::ResetAck, None, vec![]),
            (
                Message::Ping {
                    timestamp: 0x0102_0304_0506_0708,
                },
                None,
                vec![1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (
                Message::Pong {
                    timestamp: 0x1112_1314_1516_1718,
                },
                None,
                vec![0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
            ),
            (Message::Rekey, None, vec![]),
            (
                Message::PathChallenge {
                    token: 0x0102_0304_0506_0708,
                },
                None,
                vec![1, 2, 3, 4, 5, 6, 7, 8],
            ),
            (
                Message::PathResponse {
                    token: 0x1112_1314_1516_1718,
                },
                None,
                vec![0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
            ),
        ]
    }

    #[test]
    fn golden_roundtrips_every_variant() {
        for (message, symbol_size, expected_body) in golden_cases() {
            let packet = Packet {
                header: HEADER,
                message: message.clone(),
            };
            let encoded = encode_parts(&packet, symbol_size).unwrap();
            assert_eq!(
                encoded.aad,
                expected_aad(message.message_type(), expected_body.len())
            );
            assert_eq!(encoded.body, expected_body);
            assert_eq!(
                decode_parts(&encoded.aad, &encoded.body, symbol_size).unwrap(),
                packet
            );
        }
    }

    #[test]
    fn split_sealed_datagram_borrows_exact_regions() {
        let encoded = encode_parts(
            &Packet {
                header: HEADER,
                message: Message::Ping { timestamp: 3 },
            },
            None,
        )
        .unwrap();
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&encoded.aad);
        datagram.extend_from_slice(&encoded.body);
        datagram.extend_from_slice(&[0xaa; AEAD_TAG_LEN]);

        let split = split_sealed_datagram(&datagram).unwrap();
        assert_eq!(split.aad(), encoded.aad);
        assert_eq!(split.ciphertext(), encoded.body);
        assert_eq!(split.tag(), &[0xaa; AEAD_TAG_LEN]);
        assert_eq!(split.ciphertext_and_tag(), &datagram[COMMON_HEADER_LEN..]);
        assert_eq!(split.unverified_header.packet_seq, HEADER.packet_seq);
    }

    #[test]
    fn rejects_every_truncation_of_valid_datagrams_and_bodies() {
        for (message, symbol_size, _) in golden_cases() {
            let encoded = encode_parts(
                &Packet {
                    header: HEADER,
                    message,
                },
                symbol_size,
            )
            .unwrap();
            let mut datagram = encoded.aad.to_vec();
            datagram.extend_from_slice(&encoded.body);
            datagram.extend_from_slice(&[0; AEAD_TAG_LEN]);
            for len in 0..datagram.len() {
                assert!(
                    split_sealed_datagram(&datagram[..len]).is_err(),
                    "accepted datagram truncated to {len}"
                );
            }
            if !encoded.body.is_empty() {
                let mut short_aad = encoded.aad;
                short_aad[8..12].copy_from_slice(&((encoded.body.len() - 1) as u32).to_be_bytes());
                assert!(
                    decode_parts(
                        &short_aad,
                        &encoded.body[..encoded.body.len() - 1],
                        symbol_size
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn rejects_oversize_target_and_error_message() {
        let target = format!("{}:1", "a".repeat(MAX_TARGET_LEN));
        assert!(matches!(
            encode_parts(
                &Packet {
                    header: HEADER,
                    message: Message::Open {
                        target: &target,
                        symbol_size: 1,
                        up_k: 1,
                        down_k: 1,
                    },
                },
                None,
            ),
            Err(CodecError::TargetTooLong { .. })
        ));

        let message = "x".repeat(MAX_OPEN_ERROR_MESSAGE_LEN + 1);
        assert!(matches!(
            encode_parts(
                &Packet {
                    header: HEADER,
                    message: Message::OpenErr {
                        code: 1,
                        message: &message,
                    },
                },
                None,
            ),
            Err(CodecError::OpenErrorMessageTooLong { .. })
        ));
    }

    #[test]
    fn accepts_exact_text_bounds() {
        let host_len = MAX_TARGET_LEN - 2;
        let target = format!("{}:1", "a".repeat(host_len));
        let packet = Packet {
            header: HEADER,
            message: Message::Open {
                target: &target,
                symbol_size: 1,
                up_k: 1,
                down_k: 1,
            },
        };
        assert!(encode_parts(&packet, None).is_ok());

        let message = "x".repeat(MAX_OPEN_ERROR_MESSAGE_LEN);
        let packet = Packet {
            header: HEADER,
            message: Message::OpenErr {
                code: MAX_OPEN_ERROR_CODE,
                message: &message,
            },
        };
        assert!(encode_parts(&packet, None).is_ok());
    }

    #[test]
    fn rejects_nonzero_flags_and_all_reserved_fields() {
        let encoded = encode_parts(
            &Packet {
                header: HEADER,
                message: Message::RepairReq {
                    block_seq: 1,
                    count: 1,
                },
            },
            None,
        )
        .unwrap();

        let mut aad = encoded.aad;
        aad[7] = 1;
        assert_eq!(decode_aad(&aad), Err(CodecError::InvalidFlags(1)));

        let mut aad = encoded.aad;
        aad[12] = 1;
        assert_eq!(
            decode_aad(&aad),
            Err(CodecError::NonZeroReserved {
                context: "common header"
            })
        );

        for (message_type, body, reserved_offset, context) in [
            (
                MessageType::Open,
                vec![0, 3, 0, 1, 0, 1, 0, 1, 0, 0, b'a', b':', b'1'],
                8,
                "Open",
            ),
            (
                MessageType::OpenErr,
                vec![0, 1, 0, 0, 0, 0, 0, 0],
                4,
                "OpenErr",
            ),
            (
                MessageType::Data,
                vec![0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 9],
                10,
                "Data",
            ),
            (
                MessageType::RepairReq,
                vec![0, 0, 0, 1, 0, 1, 0, 0],
                6,
                "RepairReq",
            ),
            (MessageType::ResetFlow, vec![0, 1, 0, 0], 2, "ResetFlow"),
        ] {
            let mut body = body;
            body[reserved_offset] = 1;
            let symbol_size = (message_type == MessageType::Data).then_some(1);
            let aad = encode_aad(WireHeader {
                message_type,
                direction: HEADER.direction,
                body_len: body.len() as u32,
                session_id: HEADER.session_id,
                packet_seq: HEADER.packet_seq,
                flow_id: HEADER.flow_id,
            });
            assert_eq!(
                decode_parts(&aad, &body, symbol_size),
                Err(CodecError::NonZeroReserved { context })
            );
        }
    }

    #[test]
    fn rejects_wrong_version_magic_direction_and_handshake_type() {
        let encoded = encode_parts(
            &Packet {
                header: HEADER,
                message: Message::Rekey,
            },
            None,
        )
        .unwrap();

        let mut aad = encoded.aad;
        aad[4] = 1;
        assert_eq!(decode_aad(&aad), Err(CodecError::InvalidVersion(1)));

        let mut aad = encoded.aad;
        aad[0] ^= 1;
        assert_eq!(decode_aad(&aad), Err(CodecError::InvalidMagic));

        let mut aad = encoded.aad;
        aad[6] = 2;
        assert_eq!(decode_aad(&aad), Err(CodecError::InvalidDirection(2)));

        let mut aad = encoded.aad;
        aad[5] = 1;
        assert_eq!(decode_aad(&aad), Err(CodecError::HandshakePacketType(1)));
    }

    #[test]
    fn rejects_wrong_symbol_lengths_and_missing_symbol_size() {
        let packet = Packet {
            header: HEADER,
            message: Message::Data {
                block_seq: 1,
                esi: 2,
                k_eff: 1,
                block_payload_len: 4,
                symbol: &[1, 2, 3, 4],
            },
        };
        assert_eq!(
            encode_parts(&packet, Some(3)),
            Err(CodecError::InvalidSymbolLength {
                expected: 3,
                actual: 4
            })
        );
        assert_eq!(
            encode_parts(&packet, None),
            Err(CodecError::MissingSymbolSize)
        );

        let encoded = encode_parts(&packet, Some(4)).unwrap();
        assert!(matches!(
            decode_parts(&encoded.aad, &encoded.body, Some(3)),
            Err(CodecError::InvalidLength {
                context: "Data body",
                ..
            })
        ));
        assert_eq!(
            decode_parts(&encoded.aad, &encoded.body, None),
            Err(CodecError::MissingSymbolSize)
        );
    }

    #[test]
    fn enforces_runtime_esi_limit() {
        let make_packet = |esi| Packet {
            header: HEADER,
            message: Message::Data {
                block_seq: 1,
                esi,
                k_eff: 1,
                block_payload_len: 1,
                symbol: &[0],
            },
        };
        assert!(encode_parts(&make_packet(MAX_RAPTORQ_ESI), Some(1)).is_ok());
        assert_eq!(
            encode_parts(&make_packet(MAX_RAPTORQ_ESI + 1), Some(1)),
            Err(CodecError::InvalidEsi(MAX_RAPTORQ_ESI + 1))
        );

        let encoded = encode_parts(&make_packet(1), Some(1)).unwrap();
        let mut body = encoded.body;
        body[4..8].copy_from_slice(&(MAX_RAPTORQ_ESI + 1).to_be_bytes());
        assert_eq!(
            decode_parts(&encoded.aad, &body, Some(1)),
            Err(CodecError::InvalidEsi(MAX_RAPTORQ_ESI + 1))
        );
    }

    #[test]
    fn rejects_declared_and_actual_length_mismatches() {
        let encoded = encode_parts(
            &Packet {
                header: HEADER,
                message: Message::Ping { timestamp: 1 },
            },
            None,
        )
        .unwrap();
        assert_eq!(
            decode_parts(&encoded.aad, &encoded.body[..7], None),
            Err(CodecError::BodyLengthMismatch {
                declared: 8,
                actual: 7
            })
        );

        let mut datagram = encoded.aad.to_vec();
        datagram.extend_from_slice(&encoded.body);
        datagram.extend_from_slice(&[0; AEAD_TAG_LEN]);
        datagram.push(0);
        assert!(matches!(
            split_sealed_datagram(&datagram),
            Err(CodecError::InvalidLength {
                context: "sealed datagram",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_targets_codes_counts_and_capacity() {
        for target in ["", "missing-port", ":80", "host:0", "::1:80", "[::1]80"] {
            let packet = Packet {
                header: HEADER,
                message: Message::Open {
                    target,
                    symbol_size: 1,
                    up_k: 1,
                    down_k: 1,
                },
            };
            assert!(encode_parts(&packet, None).is_err(), "accepted {target:?}");
        }
        let ipv6 = Packet {
            header: HEADER,
            message: Message::Open {
                target: "[::1]:443",
                symbol_size: 1,
                up_k: 1,
                down_k: 1,
            },
        };
        assert!(encode_parts(&ipv6, None).is_ok());

        for code in [0, MAX_OPEN_ERROR_CODE + 1] {
            let packet = Packet {
                header: HEADER,
                message: Message::OpenErr { code, message: "" },
            };
            assert_eq!(
                encode_parts(&packet, None),
                Err(CodecError::InvalidOpenErrorCode(code))
            );
        }
        assert_eq!(
            encode_parts(
                &Packet {
                    header: HEADER,
                    message: Message::RepairReq {
                        block_seq: 1,
                        count: 0
                    },
                },
                None
            ),
            Err(CodecError::InvalidRepairCount(0))
        );
        assert!(matches!(
            encode_parts(
                &Packet {
                    header: HEADER,
                    message: Message::Data {
                        block_seq: 1,
                        esi: 1,
                        k_eff: 2,
                        block_payload_len: 9,
                        symbol: &[0; 4],
                    },
                },
                Some(4)
            ),
            Err(CodecError::InvalidBlockPayloadLength {
                actual: 9,
                maximum: 8
            })
        ));
    }

    #[test]
    fn invalid_utf8_is_rejected_without_copying() {
        let body = vec![0, 3, 0, 1, 0, 1, 0, 1, 0, 0, b'a', b':', 0xff];
        let aad = encode_aad(WireHeader {
            message_type: MessageType::Open,
            direction: HEADER.direction,
            body_len: body.len() as u32,
            session_id: HEADER.session_id,
            packet_seq: HEADER.packet_seq,
            flow_id: HEADER.flow_id,
        });
        assert_eq!(
            decode_parts(&aad, &body, None),
            Err(CodecError::InvalidUtf8 {
                context: "Open target"
            })
        );
    }

    #[test]
    fn arbitrary_short_slices_never_panic() {
        for len in 0..=COMMON_HEADER_LEN + AEAD_TAG_LEN + DATA_PREFIX_LEN {
            for fill in [0x00, 0x01, 0xff, len as u8] {
                let bytes = vec![fill; len];
                let split = std::panic::catch_unwind(|| split_sealed_datagram(&bytes));
                assert!(split.is_ok(), "split panicked for len={len}, fill={fill}");

                let aad_len = len.min(COMMON_HEADER_LEN);
                let aad = &bytes[..aad_len];
                let plaintext = &bytes[aad_len..];
                let decode = std::panic::catch_unwind(|| decode_parts(aad, plaintext, Some(1)));
                assert!(decode.is_ok(), "decode panicked for len={len}, fill={fill}");
            }
        }
    }

    #[test]
    fn oversized_declared_body_is_rejected_before_slicing() {
        let mut aad = expected_aad(MessageType::Data, 0);
        aad[8..12].copy_from_slice(&((MAX_ENCRYPTED_BODY_LEN + 1) as u32).to_be_bytes());
        assert_eq!(
            decode_aad(&aad),
            Err(CodecError::BodyTooLarge {
                actual: MAX_ENCRYPTED_BODY_LEN + 1,
                maximum: MAX_ENCRYPTED_BODY_LEN
            })
        );
    }
}
