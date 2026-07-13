use super::wire_v2::{
    CLIENT_FINISH_LEN, CLIENT_HELLO_LEN, ClientHandshake, ClientHello, HandshakeError, NONCE_LEN,
    ReplayGuard, SERVER_FINISH_LEN, SERVER_HELLO_LEN, ServerHandshake, TransportParameters,
    V2SessionKeys,
};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

const MAX_HANDSHAKE_DATAGRAM: usize = 2048;
const MAX_NONCE_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeOptions {
    /// Total sends allowed for each outbound handshake flight.
    pub max_attempts: usize,
    /// Time to wait for a response before retransmitting the current flight.
    pub flight_timeout: Duration,
}

impl Default for HandshakeOptions {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            flight_timeout: Duration::from_millis(250),
        }
    }
}

impl HandshakeOptions {
    fn attempts(self) -> usize {
        self.max_attempts.max(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeFlight {
    ClientHello,
    ServerHello,
    ClientFinish,
}

#[derive(Debug)]
pub enum SessionError {
    Io(io::Error),
    Handshake(HandshakeError),
    Timeout(HandshakeFlight),
    ParameterMismatch {
        expected: TransportParameters,
        received: TransportParameters,
    },
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "UDP handshake I/O error: {error}"),
            Self::Handshake(error) => write!(f, "wire-v2 handshake failed: {error}"),
            Self::Timeout(flight) => write!(f, "wire-v2 {flight:?} flight timed out"),
            Self::ParameterMismatch { expected, received } => write!(
                f,
                "transport parameter mismatch: expected {expected:?}, received {received:?}"
            ),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Handshake(error) => Some(error),
            Self::Timeout(_) | Self::ParameterMismatch { .. } => None,
        }
    }
}

impl From<io::Error> for SessionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<HandshakeError> for SessionError {
    fn from(error: HandshakeError) -> Self {
        Self::Handshake(error)
    }
}

#[derive(Clone)]
pub struct ResponderFinishCache {
    peer: SocketAddr,
    client_hello: [u8; CLIENT_HELLO_LEN],
    server_hello: [u8; SERVER_HELLO_LEN],
    client_finish: [u8; CLIENT_FINISH_LEN],
    server_finish: [u8; SERVER_FINISH_LEN],
}

impl fmt::Debug for ResponderFinishCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponderFinishCache")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl ResponderFinishCache {
    /// Returns the cached response for an exact authenticated handshake duplicate.
    ///
    /// The supervisor must call this only for datagrams received from `source`.
    pub fn response_for<'a>(&'a self, source: SocketAddr, datagram: &[u8]) -> Option<&'a [u8]> {
        if source != self.peer {
            return None;
        }
        if datagram == self.client_finish {
            return Some(&self.server_finish);
        }
        if datagram == self.client_hello {
            return Some(&self.server_hello);
        }
        None
    }

    /// Answers a duplicate ClientFinish or ClientHello when one matches this cache.
    pub async fn answer_duplicate(
        &self,
        socket: &UdpSocket,
        source: SocketAddr,
        datagram: &[u8],
    ) -> Result<bool, io::Error> {
        let Some(response) = self.response_for(source, datagram) else {
            return Ok(false);
        };
        send_datagram(socket, source, response).await?;
        Ok(true)
    }
}

#[derive(Debug, Clone)]
pub struct EstablishedSession {
    pub keys: V2SessionKeys,
    pub peer: SocketAddr,
    pub parameters: TransportParameters,
    pub capabilities: u32,
    /// Present on the responder so the data-plane supervisor can answer late
    /// handshake retransmissions without retaining the PSK or handshake state.
    pub responder_finish_cache: Option<ResponderFinishCache>,
}

pub async fn initiator_connect(
    socket: &UdpSocket,
    peer: SocketAddr,
    psk: &[u8],
    expected_parameters: TransportParameters,
    local_capabilities: u32,
) -> Result<EstablishedSession, SessionError> {
    initiator_connect_with_options(
        socket,
        peer,
        psk,
        expected_parameters,
        local_capabilities,
        HandshakeOptions::default(),
    )
    .await
}

pub async fn initiator_connect_with_options(
    socket: &UdpSocket,
    peer: SocketAddr,
    psk: &[u8],
    expected_parameters: TransportParameters,
    local_capabilities: u32,
    options: HandshakeOptions,
) -> Result<EstablishedSession, SessionError> {
    initiator_connect_with_nonce(
        socket,
        peer,
        psk,
        expected_parameters,
        local_capabilities,
        options,
        random_nonce(),
    )
    .await
}

async fn initiator_connect_with_nonce(
    socket: &UdpSocket,
    peer: SocketAddr,
    psk: &[u8],
    expected_parameters: TransportParameters,
    local_capabilities: u32,
    options: HandshakeOptions,
    client_nonce: [u8; NONCE_LEN],
) -> Result<EstablishedSession, SessionError> {
    let mut handshake =
        ClientHandshake::start(psk, client_nonce, local_capabilities, expected_parameters)?;
    let client_hello = handshake.client_hello();
    let mut client_finish = None;

    for _ in 0..options.attempts() {
        send_datagram(socket, peer, &client_hello).await?;
        let deadline = Instant::now() + options.flight_timeout;
        while let Some(datagram) = recv_from_peer_until(socket, peer, deadline).await? {
            let Ok(finish) = handshake.handle_server_hello(psk, &datagram) else {
                continue;
            };
            let received = handshake
                .negotiated_parameters()
                .ok_or(HandshakeError::UnexpectedMessage)?;
            if received != expected_parameters {
                return Err(SessionError::ParameterMismatch {
                    expected: expected_parameters,
                    received,
                });
            }
            client_finish = Some(finish);
            break;
        }
        if client_finish.is_some() {
            break;
        }
    }

    let client_finish = client_finish.ok_or(SessionError::Timeout(HandshakeFlight::ServerHello))?;
    for _ in 0..options.attempts() {
        send_datagram(socket, peer, &client_finish).await?;
        let deadline = Instant::now() + options.flight_timeout;
        while let Some(datagram) = recv_from_peer_until(socket, peer, deadline).await? {
            if handshake.handle_server_finish(psk, &datagram).is_ok() {
                let keys = handshake.session_keys(psk)?;
                return Ok(EstablishedSession {
                    keys,
                    peer,
                    parameters: expected_parameters,
                    capabilities: handshake
                        .negotiated_capabilities()
                        .ok_or(HandshakeError::UnexpectedMessage)?,
                    responder_finish_cache: None,
                });
            }

            // A duplicated ServerHello means the responder did not receive our
            // prior ClientFinish. Re-authenticate it and immediately resend.
            if let Ok(cached_finish) = handshake.handle_server_hello(psk, &datagram) {
                let received = handshake
                    .negotiated_parameters()
                    .ok_or(HandshakeError::UnexpectedMessage)?;
                if received != expected_parameters {
                    return Err(SessionError::ParameterMismatch {
                        expected: expected_parameters,
                        received,
                    });
                }
                send_datagram(socket, peer, &cached_finish).await?;
            }
        }
    }

    Err(SessionError::Timeout(HandshakeFlight::ClientFinish))
}

pub async fn responder_accept(
    socket: &UdpSocket,
    peer: SocketAddr,
    psk: &[u8],
    expected_parameters: TransportParameters,
    local_capabilities: u32,
    replay_guard: &mut ReplayGuard,
) -> Result<EstablishedSession, SessionError> {
    responder_accept_with_options(
        socket,
        peer,
        psk,
        expected_parameters,
        local_capabilities,
        replay_guard,
        HandshakeOptions::default(),
    )
    .await
}

pub async fn responder_accept_with_options(
    socket: &UdpSocket,
    peer: SocketAddr,
    psk: &[u8],
    expected_parameters: TransportParameters,
    local_capabilities: u32,
    replay_guard: &mut ReplayGuard,
    options: HandshakeOptions,
) -> Result<EstablishedSession, SessionError> {
    let mut accepted = None;
    for _ in 0..options.attempts() {
        let deadline = Instant::now() + options.flight_timeout;
        while let Some(datagram) = recv_from_peer_until(socket, peer, deadline).await? {
            let client_hello = match ClientHello::decode(psk, &datagram) {
                Ok(hello) => hello,
                Err(HandshakeError::AuthenticationFailed) if datagram.len() == CLIENT_HELLO_LEN => {
                    return Err(HandshakeError::AuthenticationFailed.into());
                }
                Err(_) => continue,
            };
            if client_hello.parameters != expected_parameters {
                return Err(SessionError::ParameterMismatch {
                    expected: expected_parameters,
                    received: client_hello.parameters,
                });
            }

            let mut fresh_handshake = None;
            for _ in 0..MAX_NONCE_ATTEMPTS {
                let server_nonce = random_nonce();
                match ServerHandshake::accept(
                    psk,
                    &datagram,
                    server_nonce,
                    local_capabilities,
                    expected_parameters,
                    replay_guard,
                ) {
                    Ok(handshake) => {
                        fresh_handshake = Some(handshake);
                        break;
                    }
                    Err(HandshakeError::ReusedServerNonce) => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            let handshake = fresh_handshake.ok_or(HandshakeError::ReusedServerNonce)?;
            accepted = Some((handshake, datagram));
            break;
        }
        if accepted.is_some() {
            break;
        }
    }

    let (mut handshake, client_hello) =
        accepted.ok_or(SessionError::Timeout(HandshakeFlight::ClientHello))?;
    let client_hello: [u8; CLIENT_HELLO_LEN] = client_hello
        .try_into()
        .expect("authenticated ClientHello has exact length");
    let server_hello = handshake.server_hello();

    for _ in 0..options.attempts() {
        send_datagram(socket, peer, &server_hello).await?;
        let deadline = Instant::now() + options.flight_timeout;
        while let Some(datagram) = recv_from_peer_until(socket, peer, deadline).await? {
            if let Ok(server_finish) = handshake.handle_client_finish(psk, &datagram) {
                let client_finish: [u8; CLIENT_FINISH_LEN] = datagram
                    .try_into()
                    .expect("authenticated ClientFinish has exact length");
                send_datagram(socket, peer, &server_finish).await?;
                let keys = handshake.session_keys(psk)?;
                return Ok(EstablishedSession {
                    keys,
                    peer,
                    parameters: expected_parameters,
                    capabilities: ClientHello::decode(psk, &client_hello)?.capabilities
                        & local_capabilities,
                    responder_finish_cache: Some(ResponderFinishCache {
                        peer,
                        client_hello,
                        server_hello,
                        client_finish,
                        server_finish,
                    }),
                });
            }

            // Idempotently answer a duplicate ClientHello while waiting for
            // ClientFinish.
            if let Ok(cached_hello) = handshake.handle_client_hello(psk, &datagram) {
                send_datagram(socket, peer, &cached_hello).await?;
            }
        }
    }

    Err(SessionError::Timeout(HandshakeFlight::ClientFinish))
}

fn random_nonce() -> [u8; NONCE_LEN] {
    rand::random()
}

async fn send_datagram(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: &[u8],
) -> Result<(), io::Error> {
    let sent = socket.send_to(datagram, peer).await?;
    if sent != datagram.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "UDP socket sent a partial handshake datagram",
        ));
    }
    Ok(())
}

async fn recv_from_peer_until(
    socket: &UdpSocket,
    peer: SocketAddr,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, io::Error> {
    let mut buffer = [0u8; MAX_HANDSHAKE_DATAGRAM];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let remaining = deadline - now;
        let received = match timeout(remaining, socket.recv_from(&mut buffer)).await {
            Ok(result) => result?,
            Err(_) => return Ok(None),
        };
        if received.1 != peer {
            continue;
        }
        return Ok(Some(buffer[..received.0].to_vec()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const PSK: &[u8] = b"wire-v2-udp-integration-test-key";

    fn parameters() -> TransportParameters {
        TransportParameters::new(1280, 24, 32).unwrap()
    }

    fn test_options() -> HandshakeOptions {
        HandshakeOptions {
            max_attempts: 4,
            flight_timeout: Duration::from_millis(80),
        }
    }

    async fn socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    #[tokio::test]
    async fn localhost_handshake_establishes_matching_session() {
        let client_socket = socket().await;
        let server_socket = socket().await;
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut replay_guard = ReplayGuard::with_capacity(32);
            responder_accept(
                &server_socket,
                client_addr,
                PSK,
                parameters(),
                0b1101,
                &mut replay_guard,
            )
            .await
        });

        let client = initiator_connect(&client_socket, server_addr, PSK, parameters(), 0b1011)
            .await
            .unwrap();
        let server = server.await.unwrap().unwrap();

        assert_eq!(client.peer, server_addr);
        assert_eq!(server.peer, client_addr);
        assert_eq!(client.parameters, parameters());
        assert_eq!(client.capabilities, 0b1001);
        assert_eq!(client.capabilities, server.capabilities);
        assert_eq!(client.keys.routing_id(), server.keys.routing_id());
        assert!(server.responder_finish_cache.is_some());

        let sealed = client
            .keys
            .client_to_server_cipher()
            .seal_v2(1, b"v2-header", b"payload")
            .unwrap();
        assert_eq!(
            server
                .keys
                .client_to_server_cipher()
                .open_v2(1, b"v2-header", &sealed)
                .unwrap(),
            b"payload"
        );
    }

    #[tokio::test]
    async fn wrong_psk_is_rejected_and_initiator_times_out() {
        let client_socket = socket().await;
        let server_socket = socket().await;
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut replay_guard = ReplayGuard::with_capacity(8);
            responder_accept_with_options(
                &server_socket,
                client_addr,
                PSK,
                parameters(),
                0xff,
                &mut replay_guard,
                test_options(),
            )
            .await
        });

        let client_error = initiator_connect_with_options(
            &client_socket,
            server_addr,
            b"wrong-key",
            parameters(),
            0xff,
            test_options(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            client_error,
            SessionError::Timeout(HandshakeFlight::ServerHello)
        ));
        assert!(matches!(
            server.await.unwrap().unwrap_err(),
            SessionError::Handshake(HandshakeError::AuthenticationFailed)
        ));
    }

    #[tokio::test]
    async fn parameter_mismatch_is_rejected_before_finish() {
        let client_socket = socket().await;
        let server_socket = socket().await;
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut replay_guard = ReplayGuard::with_capacity(8);
            responder_accept_with_options(
                &server_socket,
                client_addr,
                PSK,
                TransportParameters::new(1200, 24, 32).unwrap(),
                0xff,
                &mut replay_guard,
                test_options(),
            )
            .await
        });

        let client_error = initiator_connect_with_options(
            &client_socket,
            server_addr,
            PSK,
            parameters(),
            0xff,
            test_options(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            client_error,
            SessionError::Timeout(HandshakeFlight::ServerHello)
        ));
        assert!(matches!(
            server.await.unwrap().unwrap_err(),
            SessionError::ParameterMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn retransmits_when_proxy_drops_first_server_hello() {
        let client_socket = Arc::new(socket().await);
        let server_socket = Arc::new(socket().await);
        let proxy_socket = Arc::new(socket().await);
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let proxy_addr = proxy_socket.local_addr().unwrap();

        let proxy = {
            let proxy_socket = Arc::clone(&proxy_socket);
            tokio::spawn(async move {
                let mut buffer = [0u8; MAX_HANDSHAKE_DATAGRAM];
                let mut dropped_first_server_datagram = false;
                loop {
                    let (length, source) = proxy_socket.recv_from(&mut buffer).await.unwrap();
                    if source == client_addr {
                        proxy_socket
                            .send_to(&buffer[..length], server_addr)
                            .await
                            .unwrap();
                    } else if source == server_addr {
                        if !dropped_first_server_datagram {
                            dropped_first_server_datagram = true;
                            continue;
                        }
                        proxy_socket
                            .send_to(&buffer[..length], client_addr)
                            .await
                            .unwrap();
                    }
                }
            })
        };

        let server = {
            let server_socket = Arc::clone(&server_socket);
            tokio::spawn(async move {
                let mut replay_guard = ReplayGuard::with_capacity(8);
                responder_accept_with_options(
                    &server_socket,
                    proxy_addr,
                    PSK,
                    parameters(),
                    0xff,
                    &mut replay_guard,
                    test_options(),
                )
                .await
            })
        };

        let client = initiator_connect_with_options(
            &client_socket,
            proxy_addr,
            PSK,
            parameters(),
            0xff,
            test_options(),
        )
        .await
        .unwrap();
        let server = server.await.unwrap().unwrap();
        proxy.abort();
        assert_eq!(client.keys.routing_id(), server.keys.routing_id());
    }

    #[tokio::test]
    async fn finish_cache_recovers_a_lost_server_finish() {
        let client_socket = Arc::new(socket().await);
        let server_socket = Arc::new(socket().await);
        let proxy_socket = Arc::new(socket().await);
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let proxy_addr = proxy_socket.local_addr().unwrap();

        let proxy = {
            let proxy_socket = Arc::clone(&proxy_socket);
            tokio::spawn(async move {
                let mut buffer = [0u8; MAX_HANDSHAKE_DATAGRAM];
                let mut dropped_server_finish = false;
                loop {
                    let (length, source) = proxy_socket.recv_from(&mut buffer).await.unwrap();
                    if source == client_addr {
                        proxy_socket
                            .send_to(&buffer[..length], server_addr)
                            .await
                            .unwrap();
                    } else if source == server_addr {
                        if length == SERVER_FINISH_LEN && !dropped_server_finish {
                            dropped_server_finish = true;
                            continue;
                        }
                        proxy_socket
                            .send_to(&buffer[..length], client_addr)
                            .await
                            .unwrap();
                    }
                }
            })
        };

        let server = {
            let server_socket = Arc::clone(&server_socket);
            tokio::spawn(async move {
                let mut replay_guard = ReplayGuard::with_capacity(8);
                let session = responder_accept_with_options(
                    &server_socket,
                    proxy_addr,
                    PSK,
                    parameters(),
                    0xff,
                    &mut replay_guard,
                    test_options(),
                )
                .await?;
                let cache = session
                    .responder_finish_cache
                    .as_ref()
                    .expect("responder returns finish cache");
                let mut buffer = [0u8; MAX_HANDSHAKE_DATAGRAM];
                timeout(Duration::from_millis(500), async {
                    loop {
                        let (length, source) = server_socket.recv_from(&mut buffer).await?;
                        if cache
                            .answer_duplicate(&server_socket, source, &buffer[..length])
                            .await?
                        {
                            return Ok::<(), io::Error>(());
                        }
                    }
                })
                .await
                .map_err(|_| SessionError::Timeout(HandshakeFlight::ClientFinish))??;
                Ok::<_, SessionError>(session)
            })
        };

        let client = initiator_connect_with_options(
            &client_socket,
            proxy_addr,
            PSK,
            parameters(),
            0xff,
            test_options(),
        )
        .await
        .unwrap();
        let server = server.await.unwrap().unwrap();
        proxy.abort();
        assert_eq!(client.keys.routing_id(), server.keys.routing_id());
    }

    #[tokio::test]
    async fn repeated_client_nonce_gets_fresh_session_material() {
        let client_socket = Arc::new(socket().await);
        let server_socket = Arc::new(socket().await);
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let fixed_client_nonce = [0x42; NONCE_LEN];
        let mut replay_guard = ReplayGuard::with_capacity(8);
        let mut routing_ids = Vec::new();
        let mut ciphertexts = Vec::new();

        for _ in 0..2 {
            let server = {
                let server_socket = Arc::clone(&server_socket);
                let mut guard = replay_guard;
                tokio::spawn(async move {
                    let result = responder_accept_with_options(
                        &server_socket,
                        client_addr,
                        PSK,
                        parameters(),
                        0xff,
                        &mut guard,
                        test_options(),
                    )
                    .await;
                    (result, guard)
                })
            };
            let client = initiator_connect_with_nonce(
                &client_socket,
                server_addr,
                PSK,
                parameters(),
                0xff,
                test_options(),
                fixed_client_nonce,
            )
            .await
            .unwrap();
            let (server_result, returned_guard) = server.await.unwrap();
            let server_session = server_result.unwrap();
            replay_guard = returned_guard;
            assert_eq!(client.keys.routing_id(), server_session.keys.routing_id());
            routing_ids.push(client.keys.routing_id());
            ciphertexts.push(
                client
                    .keys
                    .client_to_server_cipher()
                    .seal_v2(0, b"same-aad", b"same-plaintext")
                    .unwrap(),
            );
        }

        assert_ne!(routing_ids[0], routing_ids[1]);
        assert_ne!(ciphertexts[0], ciphertexts[1]);
    }
}
