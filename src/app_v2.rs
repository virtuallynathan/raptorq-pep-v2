use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};

use crate::config::{Config, Mode};
use crate::crypto::session_v2::{initiator_connect, responder_accept};
use crate::crypto::wire_v2::{CLIENT_HELLO_LEN, ClientHello, ReplayGuard, TransportParameters};
use crate::runtime_v2::{run_initiator_established, run_responder_established};

const UDP_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const CAPABILITY_MULTI_FLOW: u32 = 1;

pub async fn run(config: Config) -> Result<()> {
    let udp = Arc::new(
        bind_udp(udp_bind_address(&config)?)
            .await
            .context("bind wire-v2 UDP socket")?,
    );
    info!(address = %udp.local_addr()?, "wire-v2 UDP socket bound");

    let parameters =
        TransportParameters::new(config.symbol_size, config.up.k_max, config.down.k_max)
            .context("build wire-v2 transport parameters")?;

    match config.mode {
        Mode::Local => run_initiator(udp, config, parameters).await,
        Mode::Remote => run_responder(udp, config, parameters).await,
    }
}

async fn run_initiator(
    udp: Arc<UdpSocket>,
    config: Config,
    parameters: TransportParameters,
) -> Result<()> {
    let peer = config.peer.context("local mode requires --peer")?;
    let listen = config
        .tcp_listen
        .context("local mode requires --tcp-listen")?;

    loop {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("bind local TCP listener {listen}"))?;
        info!(%peer, "starting authenticated wire-v2 handshake");
        let established =
            match initiator_connect(&udp, peer, &config.psk, parameters, CAPABILITY_MULTI_FLOW)
                .await
            {
                Ok(established) => established,
                Err(error) => {
                    warn!(%peer, %error, "wire-v2 initiator handshake failed; retrying");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            };
        if established.parameters != parameters {
            warn!(%peer, "peer returned unexpected transport parameters");
            continue;
        }
        if established.capabilities & CAPABILITY_MULTI_FLOW == 0 {
            warn!(%peer, "peer did not negotiate multi-flow capability");
            continue;
        }
        info!(
            peer = %established.peer,
            session_id = established.keys.routing_id(),
            "wire-v2 session established"
        );

        if let Err(error) = run_initiator_established(
            udp.clone(),
            established.peer,
            established.keys,
            Arc::new(config.clone()),
            listener,
        )
        .await
        {
            warn!(%error, "wire-v2 initiator runtime ended; re-handshaking");
        }
    }
}

async fn run_responder(
    udp: Arc<UdpSocket>,
    config: Config,
    parameters: TransportParameters,
) -> Result<()> {
    let mut replay_guard = ReplayGuard::new();
    if config.allowed_targets.is_empty() {
        warn!("no --allow-target entries configured; any PSK-authenticated target is permitted");
    }

    loop {
        let peer = await_authenticated_client_hello(&udp, &config.psk, parameters)
            .await
            .context("wait for authenticated ClientHello")?;
        info!(%peer, "accepting authenticated wire-v2 handshake");

        let established = match responder_accept(
            &udp,
            peer,
            &config.psk,
            parameters,
            CAPABILITY_MULTI_FLOW,
            &mut replay_guard,
        )
        .await
        {
            Ok(session) => session,
            Err(error) => {
                warn!(%peer, %error, "wire-v2 responder handshake failed");
                continue;
            }
        };
        if established.parameters != parameters {
            warn!(%peer, "peer returned unexpected transport parameters");
            continue;
        }
        if established.capabilities & CAPABILITY_MULTI_FLOW == 0 {
            warn!(%peer, "peer did not negotiate multi-flow capability");
            continue;
        }
        info!(
            peer = %established.peer,
            session_id = established.keys.routing_id(),
            "wire-v2 session established"
        );

        if let Err(error) = run_responder_established(
            udp.clone(),
            established.peer,
            established.keys,
            established.responder_finish_cache,
            Arc::new(config.clone()),
        )
        .await
        {
            warn!(%error, "wire-v2 responder runtime ended; awaiting a new handshake");
        }
    }
}

async fn await_authenticated_client_hello(
    udp: &UdpSocket,
    psk: &[u8],
    expected_parameters: TransportParameters,
) -> Result<SocketAddr> {
    let mut buffer = [0u8; CLIENT_HELLO_LEN];
    loop {
        let (length, source) = udp.peek_from(&mut buffer).await?;
        if length == CLIENT_HELLO_LEN
            && ClientHello::decode(psk, &buffer[..length])
                .is_ok_and(|hello| hello.parameters == expected_parameters)
        {
            return Ok(source);
        }

        // Consume invalid/noisy traffic so the next peek can make progress.
        let mut discard = [0u8; 2048];
        let _ = udp.recv_from(&mut discard).await?;
    }
}

fn udp_bind_address(config: &Config) -> Result<SocketAddr> {
    match config.mode {
        Mode::Local => {
            let peer = config.peer.context("local mode requires --peer")?;
            if peer.is_ipv6() {
                Ok("[::]:0".parse().expect("static IPv6 wildcard"))
            } else {
                Ok("0.0.0.0:0".parse().expect("static IPv4 wildcard"))
            }
        }
        Mode::Remote => config
            .udp_listen
            .context("remote mode requires --udp-listen"),
    }
}

async fn bind_udp(address: SocketAddr) -> Result<UdpSocket> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("create UDP socket")?;
    socket.set_reuse_address(true)?;
    socket.set_recv_buffer_size(UDP_SOCKET_BUFFER_BYTES)?;
    socket.set_send_buffer_size(UDP_SOCKET_BUFFER_BYTES)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into()).context("bind UDP socket")?;
    UdpSocket::from_std(socket.into()).context("register UDP socket with Tokio")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FecProfile, RepairConfig};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn test_config(mode: Mode) -> Config {
        Config {
            mode,
            tcp_listen: Some("127.0.0.1:1935".parse().unwrap()),
            udp_listen: Some("127.0.0.1:9000".parse().unwrap()),
            peer: Some("127.0.0.1:9000".parse().unwrap()),
            forward: Some("example.com:443".into()),
            allowed_targets: vec!["example.com:443".into()],
            psk: b"0123456789abcdef".to_vec(),
            mtu: 1500,
            symbol_size: 1400,
            ipv6: false,
            up: FecProfile {
                k_max: 10,
                r_base: 5,
                timeout_ms: 20,
            },
            down: FecProfile {
                k_max: 5,
                r_base: 2,
                timeout_ms: 50,
            },
            repair: RepairConfig {
                delay_ms: 200,
                retry_ms: 500,
                deadline_ms: 15_000,
                max_reqs: 5,
            },
            reorder_window: 64,
            control_dups: 2,
            max_send_mbps: 10,
        }
    }

    #[test]
    fn bind_family_tracks_peer_and_listener() {
        let local_v4 = test_config(Mode::Local);
        assert!(udp_bind_address(&local_v4).unwrap().is_ipv4());

        let mut local_v6 = local_v4;
        local_v6.peer = Some("[::1]:9000".parse().unwrap());
        assert!(udp_bind_address(&local_v6).unwrap().is_ipv6());

        let mut remote_v6 = test_config(Mode::Remote);
        remote_v6.udp_listen = Some("[::]:9000".parse().unwrap());
        assert!(udp_bind_address(&remote_v6).unwrap().is_ipv6());
    }

    #[tokio::test]
    async fn full_handshake_and_runtime_carry_two_concurrent_flows() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = echo_listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.into_split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });

        let local_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_address = local_probe.local_addr().unwrap();
        drop(local_probe);
        let remote_probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote_address = remote_probe.local_addr().unwrap();
        drop(remote_probe);

        let mut remote = test_config(Mode::Remote);
        remote.tcp_listen = None;
        remote.udp_listen = Some(remote_address);
        remote.peer = None;
        remote.forward = None;
        remote.allowed_targets = vec![echo_address.to_string()];

        let mut local = test_config(Mode::Local);
        local.tcp_listen = Some(local_address);
        local.udp_listen = None;
        local.peer = Some(remote_address);
        local.forward = Some(echo_address.to_string());
        local.allowed_targets.clear();

        let remote_task = tokio::spawn(run(remote));
        let local_task = tokio::spawn(run(local));

        let exercise = async {
            async fn connect_with_retry(address: SocketAddr) -> TcpStream {
                for _ in 0..100 {
                    if let Ok(stream) = TcpStream::connect(address).await {
                        return stream;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                panic!("local tunnel listener did not become ready");
            }

            let first = async {
                let payload = vec![0x11; 48_000];
                let mut stream = connect_with_retry(local_address).await;
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut echoed = Vec::new();
                stream.read_to_end(&mut echoed).await.unwrap();
                assert_eq!(echoed, payload);
            };
            let second = async {
                let payload = vec![0x22; 32_000];
                let mut stream = connect_with_retry(local_address).await;
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut echoed = Vec::new();
                stream.read_to_end(&mut echoed).await.unwrap();
                assert_eq!(echoed, payload);
            };
            tokio::join!(first, second);
        };

        tokio::time::timeout(Duration::from_secs(10), exercise)
            .await
            .expect("full wire-v2 multi-flow exchange timed out");

        local_task.abort();
        remote_task.abort();
        echo_task.abort();
    }

    #[tokio::test]
    async fn deterministic_loss_and_reordering_preserve_byte_exact_flow() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (stream, _) = echo_listener.accept().await.unwrap();
            let (mut reader, mut writer) = stream.into_split();
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
        });

        let local_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_address = local_probe.local_addr().unwrap();
        drop(local_probe);
        let remote_probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote_address = remote_probe.local_addr().unwrap();
        drop(remote_probe);
        let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy_address = proxy.local_addr().unwrap();

        let proxy_task = {
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 2048];
                let mut local_peer = None;
                let mut data_packets = 0u64;
                let mut held: Option<(Vec<u8>, SocketAddr)> = None;
                loop {
                    let (length, source) = proxy.recv_from(&mut buffer).await.unwrap();
                    let destination = if source == remote_address {
                        let Some(local) = local_peer else {
                            continue;
                        };
                        local
                    } else {
                        local_peer = Some(source);
                        remote_address
                    };
                    let packet = buffer[..length].to_vec();
                    let is_data = packet.get(5).copied() == Some(0x23);
                    if is_data {
                        data_packets += 1;
                        if data_packets.is_multiple_of(17) {
                            continue;
                        }
                        if data_packets.is_multiple_of(11) && held.is_none() {
                            held = Some((packet, destination));
                            continue;
                        }
                    }

                    proxy.send_to(&packet, destination).await.unwrap();
                    if let Some((delayed, delayed_destination)) = held.take() {
                        proxy.send_to(&delayed, delayed_destination).await.unwrap();
                    }
                }
            })
        };

        let mut remote = test_config(Mode::Remote);
        remote.tcp_listen = None;
        remote.udp_listen = Some(remote_address);
        remote.peer = None;
        remote.forward = None;
        remote.allowed_targets = vec![echo_address.to_string()];

        let mut local = test_config(Mode::Local);
        local.tcp_listen = Some(local_address);
        local.udp_listen = None;
        local.peer = Some(proxy_address);
        local.forward = Some(echo_address.to_string());
        local.allowed_targets.clear();

        let remote_task = tokio::spawn(run(remote));
        let local_task = tokio::spawn(run(local));
        let exercise = async {
            let mut stream = loop {
                match TcpStream::connect(local_address).await {
                    Ok(stream) => break stream,
                    Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                }
            };
            let payload = (0..512 * 1024)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload);
        };
        tokio::time::timeout(Duration::from_secs(15), exercise)
            .await
            .expect("lossy wire-v2 exchange timed out");

        local_task.abort();
        remote_task.abort();
        proxy_task.abort();
        echo_task.abort();
    }
}
