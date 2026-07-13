use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    AuthFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::AuthFailed => write!(f, "AEAD authentication failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

// ---------------------------------------------------------------------------
// Nonce construction
// ---------------------------------------------------------------------------

/// Build a 12-byte AEAD nonce from a derived direction prefix and the
/// globally monotonic packet sequence.
pub fn make_nonce_v2(nonce_prefix: [u8; 4], packet_seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&nonce_prefix);
    nonce[4..].copy_from_slice(&packet_seq.to_be_bytes());
    nonce
}

// ---------------------------------------------------------------------------
// CipherState — single-direction encrypt/decrypt
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct CipherState {
    cipher: ChaCha20Poly1305,
    nonce_prefix: [u8; 4],
}

impl fmt::Debug for CipherState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherState")
            .field("nonce_prefix", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

const TAG_LEN: usize = 16;

impl CipherState {
    pub fn new_v2(key: &[u8; 32], nonce_prefix: [u8; 4]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            nonce_prefix,
        }
    }

    pub fn seal_v2(
        &self,
        packet_seq: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from(make_nonce_v2(self.nonce_prefix, packet_seq));

        let mut buffer = plaintext.to_vec();
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into())
            .map_err(|_| CryptoError::AuthFailed)?;
        buffer.extend_from_slice(tag.as_slice());
        Ok(buffer)
    }

    pub fn open_v2(
        &self,
        packet_seq: u64,
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_and_tag.len() < TAG_LEN {
            return Err(CryptoError::AuthFailed);
        }
        let split = ciphertext_and_tag.len() - TAG_LEN;
        let mut buffer = ciphertext_and_tag[..split].to_vec();
        let tag =
            Tag::try_from(&ciphertext_and_tag[split..]).map_err(|_| CryptoError::AuthFailed)?;
        let nonce = Nonce::from(make_nonce_v2(self.nonce_prefix, packet_seq));

        self.cipher
            .decrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into(), &tag)
            .map_err(|_| CryptoError::AuthFailed)?;
        Ok(buffer)
    }
}

// ---------------------------------------------------------------------------
// Wire-v2 authenticated handshake
// ---------------------------------------------------------------------------

pub mod wire_v2 {
    use super::{CipherState, CryptoError};
    use hkdf::Hkdf;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    use std::collections::{HashSet, VecDeque};
    use std::fmt;

    pub const MAGIC: [u8; 4] = *b"RQV2";
    pub const VERSION: u8 = 2;
    pub const NONCE_LEN: usize = 16;
    pub const AUTH_TAG_LEN: usize = 32;
    pub const CLIENT_HELLO_LEN: usize = 64;
    pub const SERVER_HELLO_LEN: usize = 84;
    pub const CLIENT_FINISH_LEN: usize = 102;
    pub const SERVER_FINISH_LEN: usize = 102;
    pub const DEFAULT_REPLAY_CAPACITY: usize = 4096;

    const HEADER_LEN: usize = 6;
    const CLIENT_HELLO_TYPE: u8 = 1;
    const SERVER_HELLO_TYPE: u8 = 2;
    const CLIENT_FINISH_TYPE: u8 = 3;
    const SERVER_FINISH_TYPE: u8 = 4;
    const HMAC_DOMAIN: &[u8] = b"raptorq-pep/wire-v2/handshake-auth";
    const TRANSCRIPT_DOMAIN: &[u8] = b"raptorq-pep/wire-v2/negotiated-transcript";
    const HKDF_SALT_DOMAIN: &[u8] = b"raptorq-pep/wire-v2/hkdf-salt";
    const HKDF_INFO_DOMAIN: &[u8] = b"raptorq-pep/wire-v2/session-material";

    type HmacSha256 = Hmac<Sha256>;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum HandshakeError {
        InvalidLength { expected: usize, actual: usize },
        InvalidMagic,
        InvalidVersion(u8),
        InvalidMessageType { expected: u8, actual: u8 },
        InvalidParameters,
        AuthenticationFailed,
        TranscriptMismatch,
        UnexpectedMessage,
        ReusedServerNonce,
        HandshakeNotComplete,
        KeyDerivation,
    }

    impl fmt::Display for HandshakeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidLength { expected, actual } => {
                    write!(
                        f,
                        "invalid message length: expected {expected}, got {actual}"
                    )
                }
                Self::InvalidMagic => write!(f, "invalid wire-v2 magic"),
                Self::InvalidVersion(version) => {
                    write!(f, "unsupported wire version {version}")
                }
                Self::InvalidMessageType { expected, actual } => {
                    write!(f, "invalid message type: expected {expected}, got {actual}")
                }
                Self::InvalidParameters => write!(f, "invalid negotiated parameters"),
                Self::AuthenticationFailed => write!(f, "handshake authentication failed"),
                Self::TranscriptMismatch => write!(f, "handshake transcript mismatch"),
                Self::UnexpectedMessage => write!(f, "unexpected handshake message"),
                Self::ReusedServerNonce => {
                    write!(f, "server nonce was already used with this client nonce")
                }
                Self::HandshakeNotComplete => write!(f, "handshake is not complete"),
                Self::KeyDerivation => write!(f, "wire-v2 key derivation failed"),
            }
        }
    }

    impl std::error::Error for HandshakeError {}

    impl From<CryptoError> for HandshakeError {
        fn from(_: CryptoError) -> Self {
            Self::KeyDerivation
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TransportParameters {
        pub symbol_size: u16,
        pub up_k: u16,
        pub down_k: u16,
    }

    impl TransportParameters {
        pub fn new(symbol_size: u16, up_k: u16, down_k: u16) -> Result<Self, HandshakeError> {
            let parameters = Self {
                symbol_size,
                up_k,
                down_k,
            };
            parameters.validate()?;
            Ok(parameters)
        }

        fn validate(&self) -> Result<(), HandshakeError> {
            if self.symbol_size == 0 || self.up_k == 0 || self.down_k == 0 {
                return Err(HandshakeError::InvalidParameters);
            }
            Ok(())
        }

        fn encode_into(&self, output: &mut [u8]) {
            output[0..2].copy_from_slice(&self.symbol_size.to_be_bytes());
            output[2..4].copy_from_slice(&self.up_k.to_be_bytes());
            output[4..6].copy_from_slice(&self.down_k.to_be_bytes());
        }

        fn decode(input: &[u8]) -> Result<Self, HandshakeError> {
            Self::new(
                u16::from_be_bytes(input[0..2].try_into().expect("fixed parameter field")),
                u16::from_be_bytes(input[2..4].try_into().expect("fixed parameter field")),
                u16::from_be_bytes(input[4..6].try_into().expect("fixed parameter field")),
            )
        }
    }

    fn write_header(output: &mut [u8], message_type: u8) {
        output[0..4].copy_from_slice(&MAGIC);
        output[4] = VERSION;
        output[5] = message_type;
    }

    fn check_header(input: &[u8], expected_type: u8) -> Result<(), HandshakeError> {
        if input[0..4] != MAGIC {
            return Err(HandshakeError::InvalidMagic);
        }
        if input[4] != VERSION {
            return Err(HandshakeError::InvalidVersion(input[4]));
        }
        if input[5] != expected_type {
            return Err(HandshakeError::InvalidMessageType {
                expected: expected_type,
                actual: input[5],
            });
        }
        Ok(())
    }

    fn check_length(input: &[u8], expected: usize) -> Result<(), HandshakeError> {
        if input.len() != expected {
            return Err(HandshakeError::InvalidLength {
                expected,
                actual: input.len(),
            });
        }
        Ok(())
    }

    fn compute_auth_tag(
        psk: &[u8],
        message_type: u8,
        parts: &[&[u8]],
    ) -> Result<[u8; AUTH_TAG_LEN], HandshakeError> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(psk)
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        mac.update(HMAC_DOMAIN);
        mac.update(&[VERSION, message_type]);
        for part in parts {
            mac.update(part);
        }
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_auth_tag(
        psk: &[u8],
        message_type: u8,
        parts: &[&[u8]],
        tag: &[u8],
    ) -> Result<(), HandshakeError> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(psk)
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        mac.update(HMAC_DOMAIN);
        mac.update(&[VERSION, message_type]);
        for part in parts {
            mac.update(part);
        }
        mac.verify_slice(tag)
            .map_err(|_| HandshakeError::AuthenticationFailed)
    }

    #[derive(Clone, PartialEq, Eq)]
    pub struct ClientHello {
        pub client_nonce: [u8; NONCE_LEN],
        pub capabilities: u32,
        pub parameters: TransportParameters,
        auth_tag: [u8; AUTH_TAG_LEN],
    }

    impl fmt::Debug for ClientHello {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ClientHello")
                .field("client_nonce", &self.client_nonce)
                .field("capabilities", &self.capabilities)
                .field("parameters", &self.parameters)
                .field("auth_tag", &"[REDACTED]")
                .finish()
        }
    }

    impl ClientHello {
        pub fn new(
            psk: &[u8],
            client_nonce: [u8; NONCE_LEN],
            capabilities: u32,
            parameters: TransportParameters,
        ) -> Result<Self, HandshakeError> {
            parameters.validate()?;
            let mut hello = Self {
                client_nonce,
                capabilities,
                parameters,
                auth_tag: [0; AUTH_TAG_LEN],
            };
            let unsigned = hello.encode_unsigned();
            hello.auth_tag = compute_auth_tag(psk, CLIENT_HELLO_TYPE, &[&unsigned])?;
            Ok(hello)
        }

        fn encode_unsigned(&self) -> [u8; CLIENT_HELLO_LEN - AUTH_TAG_LEN] {
            let mut output = [0u8; CLIENT_HELLO_LEN - AUTH_TAG_LEN];
            write_header(&mut output, CLIENT_HELLO_TYPE);
            output[HEADER_LEN..22].copy_from_slice(&self.client_nonce);
            output[22..26].copy_from_slice(&self.capabilities.to_be_bytes());
            self.parameters.encode_into(&mut output[26..32]);
            output
        }

        pub fn encode(&self) -> [u8; CLIENT_HELLO_LEN] {
            let mut output = [0u8; CLIENT_HELLO_LEN];
            output[..32].copy_from_slice(&self.encode_unsigned());
            output[32..].copy_from_slice(&self.auth_tag);
            output
        }

        pub fn decode(psk: &[u8], input: &[u8]) -> Result<Self, HandshakeError> {
            check_length(input, CLIENT_HELLO_LEN)?;
            check_header(input, CLIENT_HELLO_TYPE)?;
            verify_auth_tag(psk, CLIENT_HELLO_TYPE, &[&input[..32]], &input[32..])?;
            Ok(Self {
                client_nonce: input[HEADER_LEN..22]
                    .try_into()
                    .expect("fixed client nonce field"),
                capabilities: u32::from_be_bytes(
                    input[22..26].try_into().expect("fixed capability field"),
                ),
                parameters: TransportParameters::decode(&input[26..32])?,
                auth_tag: input[32..].try_into().expect("fixed auth tag"),
            })
        }
    }

    #[derive(Clone, PartialEq, Eq)]
    pub struct ServerHello {
        pub client_nonce: [u8; NONCE_LEN],
        pub server_nonce: [u8; NONCE_LEN],
        pub client_capabilities: u32,
        pub server_capabilities: u32,
        pub parameters: TransportParameters,
        auth_tag: [u8; AUTH_TAG_LEN],
    }

    impl fmt::Debug for ServerHello {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ServerHello")
                .field("client_nonce", &self.client_nonce)
                .field("server_nonce", &self.server_nonce)
                .field("client_capabilities", &self.client_capabilities)
                .field("server_capabilities", &self.server_capabilities)
                .field("parameters", &self.parameters)
                .field("auth_tag", &"[REDACTED]")
                .finish()
        }
    }

    impl ServerHello {
        pub fn new(
            psk: &[u8],
            client_hello: &ClientHello,
            server_nonce: [u8; NONCE_LEN],
            server_capabilities: u32,
            parameters: TransportParameters,
        ) -> Result<Self, HandshakeError> {
            parameters.validate()?;
            let mut hello = Self {
                client_nonce: client_hello.client_nonce,
                server_nonce,
                client_capabilities: client_hello.capabilities,
                server_capabilities,
                parameters,
                auth_tag: [0; AUTH_TAG_LEN],
            };
            let client_unsigned = client_hello.encode_unsigned();
            let server_unsigned = hello.encode_unsigned();
            hello.auth_tag = compute_auth_tag(
                psk,
                SERVER_HELLO_TYPE,
                &[&client_unsigned, &server_unsigned],
            )?;
            Ok(hello)
        }

        pub fn negotiated_capabilities(&self) -> u32 {
            self.client_capabilities & self.server_capabilities
        }

        fn encode_unsigned(&self) -> [u8; SERVER_HELLO_LEN - AUTH_TAG_LEN] {
            let mut output = [0u8; SERVER_HELLO_LEN - AUTH_TAG_LEN];
            write_header(&mut output, SERVER_HELLO_TYPE);
            output[HEADER_LEN..22].copy_from_slice(&self.client_nonce);
            output[22..38].copy_from_slice(&self.server_nonce);
            output[38..42].copy_from_slice(&self.client_capabilities.to_be_bytes());
            output[42..46].copy_from_slice(&self.server_capabilities.to_be_bytes());
            self.parameters.encode_into(&mut output[46..52]);
            output
        }

        pub fn encode(&self) -> [u8; SERVER_HELLO_LEN] {
            let mut output = [0u8; SERVER_HELLO_LEN];
            output[..52].copy_from_slice(&self.encode_unsigned());
            output[52..].copy_from_slice(&self.auth_tag);
            output
        }

        pub fn decode(
            psk: &[u8],
            client_hello: &ClientHello,
            input: &[u8],
        ) -> Result<Self, HandshakeError> {
            check_length(input, SERVER_HELLO_LEN)?;
            check_header(input, SERVER_HELLO_TYPE)?;
            let client_unsigned = client_hello.encode_unsigned();
            verify_auth_tag(
                psk,
                SERVER_HELLO_TYPE,
                &[&client_unsigned, &input[..52]],
                &input[52..],
            )?;
            let hello = Self {
                client_nonce: input[HEADER_LEN..22]
                    .try_into()
                    .expect("fixed client nonce field"),
                server_nonce: input[22..38].try_into().expect("fixed server nonce field"),
                client_capabilities: u32::from_be_bytes(
                    input[38..42].try_into().expect("fixed capability field"),
                ),
                server_capabilities: u32::from_be_bytes(
                    input[42..46].try_into().expect("fixed capability field"),
                ),
                parameters: TransportParameters::decode(&input[46..52])?,
                auth_tag: input[52..].try_into().expect("fixed auth tag"),
            };
            if hello.client_nonce != client_hello.client_nonce
                || hello.client_capabilities != client_hello.capabilities
            {
                return Err(HandshakeError::TranscriptMismatch);
            }
            Ok(hello)
        }
    }

    fn transcript_hash(client: &ClientHello, server: &ServerHello) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(TRANSCRIPT_DOMAIN);
        hash.update(client.encode_unsigned());
        hash.update(server.encode_unsigned());
        hash.finalize().into()
    }

    fn encode_finish_unsigned(
        message_type: u8,
        client_nonce: &[u8; NONCE_LEN],
        server_nonce: &[u8; NONCE_LEN],
        transcript_hash: &[u8; 32],
    ) -> [u8; CLIENT_FINISH_LEN - AUTH_TAG_LEN] {
        let mut output = [0u8; CLIENT_FINISH_LEN - AUTH_TAG_LEN];
        write_header(&mut output, message_type);
        output[HEADER_LEN..22].copy_from_slice(client_nonce);
        output[22..38].copy_from_slice(server_nonce);
        output[38..70].copy_from_slice(transcript_hash);
        output
    }

    #[derive(Clone, PartialEq, Eq)]
    pub struct ClientFinish {
        pub client_nonce: [u8; NONCE_LEN],
        pub server_nonce: [u8; NONCE_LEN],
        pub transcript_hash: [u8; 32],
        auth_tag: [u8; AUTH_TAG_LEN],
    }

    impl fmt::Debug for ClientFinish {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ClientFinish")
                .field("client_nonce", &self.client_nonce)
                .field("server_nonce", &self.server_nonce)
                .field("transcript_hash", &self.transcript_hash)
                .field("auth_tag", &"[REDACTED]")
                .finish()
        }
    }

    impl ClientFinish {
        pub fn new(
            psk: &[u8],
            client: &ClientHello,
            server: &ServerHello,
        ) -> Result<Self, HandshakeError> {
            let mut finish = Self {
                client_nonce: client.client_nonce,
                server_nonce: server.server_nonce,
                transcript_hash: transcript_hash(client, server),
                auth_tag: [0; AUTH_TAG_LEN],
            };
            let unsigned = finish.encode_unsigned();
            finish.auth_tag = compute_auth_tag(psk, CLIENT_FINISH_TYPE, &[&unsigned])?;
            Ok(finish)
        }

        fn encode_unsigned(&self) -> [u8; CLIENT_FINISH_LEN - AUTH_TAG_LEN] {
            encode_finish_unsigned(
                CLIENT_FINISH_TYPE,
                &self.client_nonce,
                &self.server_nonce,
                &self.transcript_hash,
            )
        }

        pub fn encode(&self) -> [u8; CLIENT_FINISH_LEN] {
            let mut output = [0u8; CLIENT_FINISH_LEN];
            output[..70].copy_from_slice(&self.encode_unsigned());
            output[70..].copy_from_slice(&self.auth_tag);
            output
        }

        pub fn decode(
            psk: &[u8],
            client: &ClientHello,
            server: &ServerHello,
            input: &[u8],
        ) -> Result<Self, HandshakeError> {
            check_length(input, CLIENT_FINISH_LEN)?;
            check_header(input, CLIENT_FINISH_TYPE)?;
            verify_auth_tag(psk, CLIENT_FINISH_TYPE, &[&input[..70]], &input[70..])?;
            let finish = Self {
                client_nonce: input[HEADER_LEN..22]
                    .try_into()
                    .expect("fixed client nonce field"),
                server_nonce: input[22..38].try_into().expect("fixed server nonce field"),
                transcript_hash: input[38..70].try_into().expect("fixed transcript hash"),
                auth_tag: input[70..].try_into().expect("fixed auth tag"),
            };
            if finish.client_nonce != client.client_nonce
                || finish.server_nonce != server.server_nonce
                || finish.transcript_hash != transcript_hash(client, server)
            {
                return Err(HandshakeError::TranscriptMismatch);
            }
            Ok(finish)
        }
    }

    #[derive(Clone, PartialEq, Eq)]
    pub struct ServerFinish {
        pub client_nonce: [u8; NONCE_LEN],
        pub server_nonce: [u8; NONCE_LEN],
        pub transcript_hash: [u8; 32],
        auth_tag: [u8; AUTH_TAG_LEN],
    }

    impl fmt::Debug for ServerFinish {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ServerFinish")
                .field("client_nonce", &self.client_nonce)
                .field("server_nonce", &self.server_nonce)
                .field("transcript_hash", &self.transcript_hash)
                .field("auth_tag", &"[REDACTED]")
                .finish()
        }
    }

    impl ServerFinish {
        pub fn new(
            psk: &[u8],
            client: &ClientHello,
            server: &ServerHello,
        ) -> Result<Self, HandshakeError> {
            let mut finish = Self {
                client_nonce: client.client_nonce,
                server_nonce: server.server_nonce,
                transcript_hash: transcript_hash(client, server),
                auth_tag: [0; AUTH_TAG_LEN],
            };
            let unsigned = finish.encode_unsigned();
            finish.auth_tag = compute_auth_tag(psk, SERVER_FINISH_TYPE, &[&unsigned])?;
            Ok(finish)
        }

        fn encode_unsigned(&self) -> [u8; SERVER_FINISH_LEN - AUTH_TAG_LEN] {
            encode_finish_unsigned(
                SERVER_FINISH_TYPE,
                &self.client_nonce,
                &self.server_nonce,
                &self.transcript_hash,
            )
        }

        pub fn encode(&self) -> [u8; SERVER_FINISH_LEN] {
            let mut output = [0u8; SERVER_FINISH_LEN];
            output[..70].copy_from_slice(&self.encode_unsigned());
            output[70..].copy_from_slice(&self.auth_tag);
            output
        }

        pub fn decode(
            psk: &[u8],
            client: &ClientHello,
            server: &ServerHello,
            input: &[u8],
        ) -> Result<Self, HandshakeError> {
            check_length(input, SERVER_FINISH_LEN)?;
            check_header(input, SERVER_FINISH_TYPE)?;
            verify_auth_tag(psk, SERVER_FINISH_TYPE, &[&input[..70]], &input[70..])?;
            let finish = Self {
                client_nonce: input[HEADER_LEN..22]
                    .try_into()
                    .expect("fixed client nonce field"),
                server_nonce: input[22..38].try_into().expect("fixed server nonce field"),
                transcript_hash: input[38..70].try_into().expect("fixed transcript hash"),
                auth_tag: input[70..].try_into().expect("fixed auth tag"),
            };
            if finish.client_nonce != client.client_nonce
                || finish.server_nonce != server.server_nonce
                || finish.transcript_hash != transcript_hash(client, server)
            {
                return Err(HandshakeError::TranscriptMismatch);
            }
            Ok(finish)
        }
    }

    #[derive(Clone)]
    pub struct V2SessionKeys {
        client_to_server_key: [u8; 32],
        server_to_client_key: [u8; 32],
        client_to_server_nonce_prefix: [u8; 4],
        server_to_client_nonce_prefix: [u8; 4],
        routing_id: u64,
    }

    impl fmt::Debug for V2SessionKeys {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("V2SessionKeys")
                .field("client_to_server_key", &"[REDACTED]")
                .field("server_to_client_key", &"[REDACTED]")
                .field("client_to_server_nonce_prefix", &"[REDACTED]")
                .field("server_to_client_nonce_prefix", &"[REDACTED]")
                .field("routing_id", &self.routing_id)
                .finish()
        }
    }

    impl V2SessionKeys {
        pub fn derive(
            psk: &[u8],
            client: &ClientHello,
            server: &ServerHello,
        ) -> Result<Self, HandshakeError> {
            if client.client_nonce != server.client_nonce
                || client.capabilities != server.client_capabilities
            {
                return Err(HandshakeError::TranscriptMismatch);
            }

            let mut salt_hash = Sha256::new();
            salt_hash.update(HKDF_SALT_DOMAIN);
            salt_hash.update(client.client_nonce);
            salt_hash.update(server.server_nonce);
            let salt: [u8; 32] = salt_hash.finalize().into();
            let hkdf = Hkdf::<Sha256>::new(Some(&salt), psk);
            let client_unsigned = client.encode_unsigned();
            let server_unsigned = server.encode_unsigned();

            fn expand<const N: usize>(
                hkdf: &Hkdf<Sha256>,
                label: &[u8],
                client_transcript: &[u8],
                server_transcript: &[u8],
            ) -> Result<[u8; N], HandshakeError> {
                let mut info = Vec::with_capacity(
                    HKDF_INFO_DOMAIN.len()
                        + label.len()
                        + client_transcript.len()
                        + server_transcript.len(),
                );
                info.extend_from_slice(HKDF_INFO_DOMAIN);
                info.extend_from_slice(label);
                info.extend_from_slice(client_transcript);
                info.extend_from_slice(server_transcript);
                let mut output = [0u8; N];
                hkdf.expand(&info, &mut output)
                    .map_err(|_| HandshakeError::KeyDerivation)?;
                Ok(output)
            }

            let client_to_server_key = expand(
                &hkdf,
                b"/client-to-server/key",
                &client_unsigned,
                &server_unsigned,
            )?;
            let server_to_client_key = expand(
                &hkdf,
                b"/server-to-client/key",
                &client_unsigned,
                &server_unsigned,
            )?;
            let client_to_server_nonce_prefix = expand(
                &hkdf,
                b"/client-to-server/nonce",
                &client_unsigned,
                &server_unsigned,
            )?;
            let server_to_client_nonce_prefix = expand(
                &hkdf,
                b"/server-to-client/nonce",
                &client_unsigned,
                &server_unsigned,
            )?;
            let routing_bytes: [u8; 8] = expand(
                &hkdf,
                b"/session-routing-id",
                &client_unsigned,
                &server_unsigned,
            )?;

            Ok(Self {
                client_to_server_key,
                server_to_client_key,
                client_to_server_nonce_prefix,
                server_to_client_nonce_prefix,
                routing_id: u64::from_be_bytes(routing_bytes),
            })
        }

        pub fn routing_id(&self) -> u64 {
            self.routing_id
        }

        pub fn client_to_server_cipher(&self) -> CipherState {
            CipherState::new_v2(
                &self.client_to_server_key,
                self.client_to_server_nonce_prefix,
            )
        }

        pub fn server_to_client_cipher(&self) -> CipherState {
            CipherState::new_v2(
                &self.server_to_client_key,
                self.server_to_client_nonce_prefix,
            )
        }
    }

    /// Tracks accepted nonce pairs beyond an individual active handshake.
    ///
    /// Active-handshake retransmissions should use `ServerHandshake::handle_client_hello`,
    /// which returns the cached ServerHello. Starting a new handshake with a replayed
    /// ClientHello must pass through this guard with a fresh server nonce.
    #[derive(Debug)]
    pub struct ReplayGuard {
        capacity: usize,
        accepted_nonce_pairs: HashSet<([u8; NONCE_LEN], [u8; NONCE_LEN])>,
        insertion_order: VecDeque<([u8; NONCE_LEN], [u8; NONCE_LEN])>,
    }

    impl Default for ReplayGuard {
        fn default() -> Self {
            Self::with_capacity(DEFAULT_REPLAY_CAPACITY)
        }
    }

    impl ReplayGuard {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_capacity(capacity: usize) -> Self {
            let capacity = capacity.max(1);
            Self {
                capacity,
                accepted_nonce_pairs: HashSet::with_capacity(capacity),
                insertion_order: VecDeque::with_capacity(capacity),
            }
        }

        #[cfg(test)]
        pub fn capacity(&self) -> usize {
            self.capacity
        }

        #[cfg(test)]
        pub fn len(&self) -> usize {
            self.accepted_nonce_pairs.len()
        }

        pub fn register(
            &mut self,
            client_nonce: [u8; NONCE_LEN],
            server_nonce: [u8; NONCE_LEN],
        ) -> Result<(), HandshakeError> {
            let nonce_pair = (client_nonce, server_nonce);
            if self.accepted_nonce_pairs.contains(&nonce_pair) {
                return Err(HandshakeError::ReusedServerNonce);
            }
            if self.accepted_nonce_pairs.len() == self.capacity {
                let oldest = self
                    .insertion_order
                    .pop_front()
                    .expect("full replay set has insertion order");
                self.accepted_nonce_pairs.remove(&oldest);
            }
            self.accepted_nonce_pairs.insert(nonce_pair);
            self.insertion_order.push_back(nonce_pair);
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    pub struct ClientHandshake {
        client_hello: ClientHello,
        server_hello: Option<ServerHello>,
        client_finish: Option<ClientFinish>,
        server_finish: Option<ServerFinish>,
    }

    impl ClientHandshake {
        pub fn start(
            psk: &[u8],
            client_nonce: [u8; NONCE_LEN],
            capabilities: u32,
            parameters: TransportParameters,
        ) -> Result<Self, HandshakeError> {
            Ok(Self {
                client_hello: ClientHello::new(psk, client_nonce, capabilities, parameters)?,
                server_hello: None,
                client_finish: None,
                server_finish: None,
            })
        }

        pub fn client_hello(&self) -> [u8; CLIENT_HELLO_LEN] {
            self.client_hello.encode()
        }

        pub fn handle_server_hello(
            &mut self,
            psk: &[u8],
            input: &[u8],
        ) -> Result<[u8; CLIENT_FINISH_LEN], HandshakeError> {
            let server = ServerHello::decode(psk, &self.client_hello, input)?;
            if let Some(existing) = &self.server_hello {
                if existing != &server {
                    return Err(HandshakeError::UnexpectedMessage);
                }
                return Ok(self
                    .client_finish
                    .as_ref()
                    .expect("finish cached with server hello")
                    .encode());
            }
            let finish = ClientFinish::new(psk, &self.client_hello, &server)?;
            let encoded = finish.encode();
            self.server_hello = Some(server);
            self.client_finish = Some(finish);
            Ok(encoded)
        }

        pub fn handle_server_finish(
            &mut self,
            psk: &[u8],
            input: &[u8],
        ) -> Result<(), HandshakeError> {
            let server = self
                .server_hello
                .as_ref()
                .ok_or(HandshakeError::UnexpectedMessage)?;
            let finish = ServerFinish::decode(psk, &self.client_hello, server, input)?;
            if let Some(existing) = &self.server_finish {
                if existing != &finish {
                    return Err(HandshakeError::UnexpectedMessage);
                }
                return Ok(());
            }
            self.server_finish = Some(finish);
            Ok(())
        }

        pub fn is_complete(&self) -> bool {
            self.server_finish.is_some()
        }

        pub fn negotiated_parameters(&self) -> Option<TransportParameters> {
            self.server_hello.as_ref().map(|hello| hello.parameters)
        }

        pub fn negotiated_capabilities(&self) -> Option<u32> {
            self.server_hello
                .as_ref()
                .map(ServerHello::negotiated_capabilities)
        }

        pub fn session_keys(&self, psk: &[u8]) -> Result<V2SessionKeys, HandshakeError> {
            if !self.is_complete() {
                return Err(HandshakeError::HandshakeNotComplete);
            }
            let client = ClientHello::decode(psk, &self.client_hello.encode())?;
            let server_state = self
                .server_hello
                .as_ref()
                .ok_or(HandshakeError::HandshakeNotComplete)?;
            let server = ServerHello::decode(psk, &client, &server_state.encode())?;
            let server_finish = self
                .server_finish
                .as_ref()
                .ok_or(HandshakeError::HandshakeNotComplete)?;
            ServerFinish::decode(psk, &client, &server, &server_finish.encode())?;
            V2SessionKeys::derive(psk, &client, &server)
        }
    }

    #[derive(Debug, Clone)]
    pub struct ServerHandshake {
        client_hello: ClientHello,
        server_hello: ServerHello,
        client_finish: Option<ClientFinish>,
        server_finish: Option<ServerFinish>,
    }

    impl ServerHandshake {
        pub fn accept(
            psk: &[u8],
            client_hello: &[u8],
            server_nonce: [u8; NONCE_LEN],
            server_capabilities: u32,
            parameters: TransportParameters,
            replay_guard: &mut ReplayGuard,
        ) -> Result<Self, HandshakeError> {
            let client = ClientHello::decode(psk, client_hello)?;
            parameters.validate()?;
            replay_guard.register(client.client_nonce, server_nonce)?;
            let server =
                ServerHello::new(psk, &client, server_nonce, server_capabilities, parameters)?;
            Ok(Self {
                client_hello: client,
                server_hello: server,
                client_finish: None,
                server_finish: None,
            })
        }

        pub fn server_hello(&self) -> [u8; SERVER_HELLO_LEN] {
            self.server_hello.encode()
        }

        pub fn handle_client_hello(
            &self,
            psk: &[u8],
            input: &[u8],
        ) -> Result<[u8; SERVER_HELLO_LEN], HandshakeError> {
            let replay = ClientHello::decode(psk, input)?;
            if replay != self.client_hello {
                return Err(HandshakeError::UnexpectedMessage);
            }
            Ok(self.server_hello.encode())
        }

        pub fn handle_client_finish(
            &mut self,
            psk: &[u8],
            input: &[u8],
        ) -> Result<[u8; SERVER_FINISH_LEN], HandshakeError> {
            let finish = ClientFinish::decode(psk, &self.client_hello, &self.server_hello, input)?;
            if let Some(existing) = &self.client_finish {
                if existing != &finish {
                    return Err(HandshakeError::UnexpectedMessage);
                }
                return Ok(self
                    .server_finish
                    .as_ref()
                    .expect("server finish cached with client finish")
                    .encode());
            }
            let response = ServerFinish::new(psk, &self.client_hello, &self.server_hello)?;
            let encoded = response.encode();
            self.client_finish = Some(finish);
            self.server_finish = Some(response);
            Ok(encoded)
        }

        pub fn is_complete(&self) -> bool {
            self.server_finish.is_some()
        }

        pub fn session_keys(&self, psk: &[u8]) -> Result<V2SessionKeys, HandshakeError> {
            if !self.is_complete() {
                return Err(HandshakeError::HandshakeNotComplete);
            }
            let client = ClientHello::decode(psk, &self.client_hello.encode())?;
            let server = ServerHello::decode(psk, &client, &self.server_hello.encode())?;
            let client_finish = self
                .client_finish
                .as_ref()
                .ok_or(HandshakeError::HandshakeNotComplete)?;
            ClientFinish::decode(psk, &client, &server, &client_finish.encode())?;
            V2SessionKeys::derive(psk, &client, &server)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::crypto::make_nonce_v2;
        use std::collections::HashSet;

        const PSK: &[u8] = b"wire-v2-test-pre-shared-key";
        const WRONG_PSK: &[u8] = b"definitely-the-wrong-key";

        fn nonce(value: u8) -> [u8; NONCE_LEN] {
            [value; NONCE_LEN]
        }

        fn parameters() -> TransportParameters {
            TransportParameters::new(1280, 24, 32).unwrap()
        }

        fn hello_pair(server_nonce: u8) -> (ClientHello, ServerHello) {
            let client = ClientHello::new(PSK, nonce(1), 0b1011, parameters()).unwrap();
            let server =
                ServerHello::new(PSK, &client, nonce(server_nonce), 0b1101, parameters()).unwrap();
            (client, server)
        }

        #[test]
        fn all_codecs_roundtrip_with_fixed_headers_and_lengths() {
            let (client, server) = hello_pair(2);
            let client_finish = ClientFinish::new(PSK, &client, &server).unwrap();
            let server_finish = ServerFinish::new(PSK, &client, &server).unwrap();

            let client_wire = client.encode();
            let server_wire = server.encode();
            let client_finish_wire = client_finish.encode();
            let server_finish_wire = server_finish.encode();

            assert_eq!(client_wire.len(), CLIENT_HELLO_LEN);
            assert_eq!(server_wire.len(), SERVER_HELLO_LEN);
            assert_eq!(client_finish_wire.len(), CLIENT_FINISH_LEN);
            assert_eq!(server_finish_wire.len(), SERVER_FINISH_LEN);
            for (wire, message_type) in [
                (client_wire.as_slice(), CLIENT_HELLO_TYPE),
                (server_wire.as_slice(), SERVER_HELLO_TYPE),
                (client_finish_wire.as_slice(), CLIENT_FINISH_TYPE),
                (server_finish_wire.as_slice(), SERVER_FINISH_TYPE),
            ] {
                assert_eq!(&wire[..4], &MAGIC);
                assert_eq!(wire[4], VERSION);
                assert_eq!(wire[5], message_type);
            }

            assert_eq!(ClientHello::decode(PSK, &client_wire).unwrap(), client);
            assert_eq!(
                ServerHello::decode(PSK, &client, &server_wire).unwrap(),
                server
            );
            assert_eq!(
                ClientFinish::decode(PSK, &client, &server, &client_finish_wire).unwrap(),
                client_finish
            );
            assert_eq!(
                ServerFinish::decode(PSK, &client, &server, &server_finish_wire).unwrap(),
                server_finish
            );
            assert_eq!(server.negotiated_capabilities(), 0b1001);
            assert_eq!(server.parameters, parameters());
        }

        #[test]
        fn state_helpers_complete_and_cache_retransmissions() {
            let mut replay_guard = ReplayGuard::new();
            let mut client = ClientHandshake::start(PSK, nonce(10), 0x0f, parameters()).unwrap();
            let client_hello = client.client_hello();
            let mut server = ServerHandshake::accept(
                PSK,
                &client_hello,
                nonce(11),
                0x07,
                parameters(),
                &mut replay_guard,
            )
            .unwrap();

            let server_hello = server.server_hello();
            assert_eq!(
                server.handle_client_hello(PSK, &client_hello).unwrap(),
                server_hello
            );
            let client_finish = client.handle_server_hello(PSK, &server_hello).unwrap();
            assert_eq!(
                client.handle_server_hello(PSK, &server_hello).unwrap(),
                client_finish
            );
            let server_finish = server.handle_client_finish(PSK, &client_finish).unwrap();
            assert_eq!(
                server.handle_client_finish(PSK, &client_finish).unwrap(),
                server_finish
            );
            client.handle_server_finish(PSK, &server_finish).unwrap();
            client.handle_server_finish(PSK, &server_finish).unwrap();

            assert!(client.is_complete());
            assert!(server.is_complete());
            assert_eq!(client.negotiated_parameters(), Some(parameters()));
            assert_eq!(client.negotiated_capabilities(), Some(0x07));
            assert_eq!(
                client.session_keys(WRONG_PSK).unwrap_err(),
                HandshakeError::AuthenticationFailed
            );
            assert_eq!(
                server.session_keys(WRONG_PSK).unwrap_err(),
                HandshakeError::AuthenticationFailed
            );
            let client_keys = client.session_keys(PSK).unwrap();
            let server_keys = server.session_keys(PSK).unwrap();
            assert_eq!(client_keys.routing_id(), server_keys.routing_id());

            let sealed = client_keys
                .client_to_server_cipher()
                .seal_v2(9, b"header", b"payload")
                .unwrap();
            assert_eq!(
                server_keys
                    .client_to_server_cipher()
                    .open_v2(9, b"header", &sealed)
                    .unwrap(),
                b"payload"
            );
        }

        #[test]
        fn every_message_rejects_tampering() {
            let (client, server) = hello_pair(2);
            let client_finish = ClientFinish::new(PSK, &client, &server).unwrap();
            let server_finish = ServerFinish::new(PSK, &client, &server).unwrap();

            let mut wire = client.encode();
            wire[25] ^= 1;
            assert_eq!(
                ClientHello::decode(PSK, &wire).unwrap_err(),
                HandshakeError::AuthenticationFailed
            );

            let mut wire = server.encode();
            wire[47] ^= 1;
            assert_eq!(
                ServerHello::decode(PSK, &client, &wire).unwrap_err(),
                HandshakeError::AuthenticationFailed
            );

            let mut wire = client_finish.encode();
            wire[38] ^= 1;
            assert_eq!(
                ClientFinish::decode(PSK, &client, &server, &wire).unwrap_err(),
                HandshakeError::AuthenticationFailed
            );

            let mut wire = server_finish.encode();
            wire[69] ^= 1;
            assert_eq!(
                ServerFinish::decode(PSK, &client, &server, &wire).unwrap_err(),
                HandshakeError::AuthenticationFailed
            );
        }

        #[test]
        fn every_message_rejects_wrong_psk() {
            let (client, server) = hello_pair(2);
            let client_finish = ClientFinish::new(PSK, &client, &server).unwrap();
            let server_finish = ServerFinish::new(PSK, &client, &server).unwrap();

            assert_eq!(
                ClientHello::decode(WRONG_PSK, &client.encode()).unwrap_err(),
                HandshakeError::AuthenticationFailed
            );
            assert_eq!(
                ServerHello::decode(WRONG_PSK, &client, &server.encode()).unwrap_err(),
                HandshakeError::AuthenticationFailed
            );
            assert_eq!(
                ClientFinish::decode(WRONG_PSK, &client, &server, &client_finish.encode())
                    .unwrap_err(),
                HandshakeError::AuthenticationFailed
            );
            assert_eq!(
                ServerFinish::decode(WRONG_PSK, &client, &server, &server_finish.encode())
                    .unwrap_err(),
                HandshakeError::AuthenticationFailed
            );
        }

        #[test]
        fn finish_rejects_a_different_negotiated_transcript() {
            let (client, server_a) = hello_pair(2);
            let server_b = ServerHello::new(
                PSK,
                &client,
                nonce(3),
                0b1101,
                TransportParameters::new(1200, 20, 30).unwrap(),
            )
            .unwrap();
            let finish_a = ClientFinish::new(PSK, &client, &server_a).unwrap();

            assert_eq!(
                ClientFinish::decode(PSK, &client, &server_b, &finish_a.encode()).unwrap_err(),
                HandshakeError::TranscriptMismatch
            );
        }

        #[test]
        fn codecs_reject_short_and_long_messages() {
            let (client, server) = hello_pair(2);
            let client_finish = ClientFinish::new(PSK, &client, &server).unwrap();
            let server_finish = ServerFinish::new(PSK, &client, &server).unwrap();

            let client_wire = client.encode();
            let server_wire = server.encode();
            let client_finish_wire = client_finish.encode();
            let server_finish_wire = server_finish.encode();

            assert_bad_lengths(CLIENT_HELLO_LEN, &client_wire, |wire| {
                ClientHello::decode(PSK, wire).map(|_| ())
            });
            assert_bad_lengths(SERVER_HELLO_LEN, &server_wire, |wire| {
                ServerHello::decode(PSK, &client, wire).map(|_| ())
            });
            assert_bad_lengths(CLIENT_FINISH_LEN, &client_finish_wire, |wire| {
                ClientFinish::decode(PSK, &client, &server, wire).map(|_| ())
            });
            assert_bad_lengths(SERVER_FINISH_LEN, &server_finish_wire, |wire| {
                ServerFinish::decode(PSK, &client, &server, wire).map(|_| ())
            });
        }

        fn assert_bad_lengths(
            expected: usize,
            wire: &[u8],
            decode: impl Fn(&[u8]) -> Result<(), HandshakeError>,
        ) {
            assert_eq!(
                decode(&wire[..wire.len() - 1]).unwrap_err(),
                HandshakeError::InvalidLength {
                    expected,
                    actual: expected - 1
                }
            );
            let mut long = wire.to_vec();
            long.push(0);
            assert_eq!(
                decode(&long).unwrap_err(),
                HandshakeError::InvalidLength {
                    expected,
                    actual: expected + 1
                }
            );
        }

        #[test]
        fn replayed_client_hello_requires_a_fresh_server_nonce() {
            let client = ClientHello::new(PSK, nonce(7), 0xff, parameters()).unwrap();
            let wire = client.encode();
            let mut replay_guard = ReplayGuard::new();
            let first = ServerHandshake::accept(
                PSK,
                &wire,
                nonce(8),
                0xff,
                parameters(),
                &mut replay_guard,
            )
            .unwrap();
            assert_eq!(
                ServerHandshake::accept(
                    PSK,
                    &wire,
                    nonce(8),
                    0xff,
                    parameters(),
                    &mut replay_guard
                )
                .unwrap_err(),
                HandshakeError::ReusedServerNonce
            );
            let second = ServerHandshake::accept(
                PSK,
                &wire,
                nonce(9),
                0xff,
                parameters(),
                &mut replay_guard,
            )
            .unwrap();

            let first_keys =
                V2SessionKeys::derive(PSK, &first.client_hello, &first.server_hello).unwrap();
            let second_keys =
                V2SessionKeys::derive(PSK, &second.client_hello, &second.server_hello).unwrap();
            assert_ne!(
                first_keys.client_to_server_key,
                second_keys.client_to_server_key
            );
            assert_ne!(
                first_keys.server_to_client_key,
                second_keys.server_to_client_key
            );
            assert_ne!(
                first_keys.client_to_server_nonce_prefix,
                second_keys.client_to_server_nonce_prefix
            );
            assert_ne!(
                first_keys.server_to_client_nonce_prefix,
                second_keys.server_to_client_nonce_prefix
            );
            assert_ne!(first_keys.routing_id, second_keys.routing_id);
        }

        #[test]
        fn replay_history_evicts_oldest_entry_at_capacity() {
            let mut guard = ReplayGuard::with_capacity(2);
            guard.register(nonce(1), nonce(11)).unwrap();
            guard.register(nonce(2), nonce(12)).unwrap();
            guard.register(nonce(3), nonce(13)).unwrap();
            assert_eq!(guard.capacity(), 2);
            assert_eq!(guard.len(), 2);

            // The first pair was evicted, while a retained pair is still rejected.
            guard.register(nonce(1), nonce(11)).unwrap();
            assert_eq!(
                guard.register(nonce(3), nonce(13)).unwrap_err(),
                HandshakeError::ReusedServerNonce
            );
        }

        #[test]
        fn directional_material_is_isolated() {
            let (client, server) = hello_pair(2);
            let keys = V2SessionKeys::derive(PSK, &client, &server).unwrap();
            assert_ne!(keys.client_to_server_key, keys.server_to_client_key);
            assert_ne!(
                keys.client_to_server_nonce_prefix,
                keys.server_to_client_nonce_prefix
            );

            let sealed = keys
                .client_to_server_cipher()
                .seal_v2(1, b"aad", b"secret")
                .unwrap();
            assert!(
                keys.server_to_client_cipher()
                    .open_v2(1, b"aad", &sealed)
                    .is_err()
            );
        }

        #[test]
        fn u64_packet_sequence_nonces_are_unique() {
            let prefix = [0xaa, 0xbb, 0xcc, 0xdd];
            let sequences = [
                0,
                1,
                u32::MAX as u64,
                u32::MAX as u64 + 1,
                u64::MAX - 1,
                u64::MAX,
            ];
            let nonces: HashSet<_> = sequences
                .into_iter()
                .map(|sequence| make_nonce_v2(prefix, sequence))
                .collect();
            assert_eq!(nonces.len(), sequences.len());
            assert_eq!(&make_nonce_v2(prefix, u64::MAX)[..4], &prefix);
            assert_eq!(
                &make_nonce_v2(prefix, 0x0102_0304_0506_0708)[4..],
                &0x0102_0304_0506_0708u64.to_be_bytes()
            );
        }

        #[test]
        fn v2_cipher_accepts_the_final_u64_sequence() {
            let (client, server) = hello_pair(2);
            let keys = V2SessionKeys::derive(PSK, &client, &server).unwrap();
            let cipher = keys.client_to_server_cipher();
            let sealed = cipher.seal_v2(u64::MAX, b"aad", b"payload").unwrap();
            assert_eq!(
                cipher.open_v2(u64::MAX, b"aad", &sealed).unwrap(),
                b"payload"
            );
        }

        #[test]
        fn debug_output_redacts_v2_secret_material() {
            let (client, server) = hello_pair(2);
            let keys = V2SessionKeys::derive(PSK, &client, &server).unwrap();
            let output = format!("{keys:?}");
            assert!(output.contains("[REDACTED]"));
            assert!(!output.contains(&format!("{:?}", keys.client_to_server_key)));
            assert!(!output.contains(&format!("{:?}", keys.server_to_client_key)));
        }
    }
}

#[path = "session_v2.rs"]
pub mod session_v2;
