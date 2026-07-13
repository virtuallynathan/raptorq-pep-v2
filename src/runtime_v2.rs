//! Concurrent post-handshake runtime for wire-v2 sessions.
//!
//! One receive task authenticates and dispatches every inbound datagram.  One
//! transmit task owns the directional cipher and packet sequence, which makes
//! nonce reuse impossible and gives control/repair traffic strict priority.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};

use crate::config::Config;
use crate::crypto::CipherState;
use crate::crypto::session_v2::ResponderFinishCache;
use crate::crypto::wire_v2::V2SessionKeys;
use crate::flow_v2::{
    FlowId, Outbound, OwnedMessage, RegistryCommand, SESSION_EVENT_CAPACITY, SessionEvent,
    TxHandle, TxPriority, TxReceivers, flow_config, register_flow, spawn_flow_paused,
};
use crate::metrics::{self, SessionMetrics};
use crate::pacer::Pacer;
use crate::wire_v2::{
    self, AEAD_TAG_LEN, COMMON_HEADER_LEN, Direction, Message, Packet, PacketHeader,
};

const MAX_DATAGRAM_SIZE: usize = COMMON_HEADER_LEN + wire_v2::MAX_ENCRYPTED_BODY_LEN + AEAD_TAG_LEN;
const REPLAY_BITS: usize = 1024;
const REPLAY_WORDS: usize = REPLAY_BITS / 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const OPEN_RESULT_CAPACITY: usize = 128;
const EARLY_FLOW_LIMIT: usize = 128;
const EARLY_MESSAGE_LIMIT: usize = 8;
const OPEN_HISTORY_LIMIT: usize = 4096;
const PENDING_OPEN_LIMIT: usize = 128;
const OPEN_RETRY: Duration = Duration::from_millis(250);
const OPEN_MAX_ATTEMPTS: u8 = 20;
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const RESET_RETRIES: usize = 120;
const PATH_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(5);
const PATH_CHALLENGE_RETRY: Duration = Duration::from_millis(250);

struct FlowRoute {
    symbol_size: u16,
    inbound: mpsc::Sender<OwnedMessage>,
}

struct PathCandidate {
    address: SocketAddr,
    token: u64,
    expires_at: tokio::time::Instant,
    last_challenge: tokio::time::Instant,
    replay: ReplayWindow64,
}

type ResetWaiters = Arc<Mutex<HashMap<FlowId, watch::Sender<u64>>>>;

#[derive(Debug)]
struct ReplayWindow64 {
    highest: u64,
    bitmap: [u64; REPLAY_WORDS],
    initialized: bool,
}

impl ReplayWindow64 {
    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0; REPLAY_WORDS],
            initialized: false,
        }
    }

    fn check(&self, sequence: u64) -> bool {
        if !self.initialized || sequence > self.highest {
            return true;
        }
        let distance = self.highest - sequence;
        distance < REPLAY_BITS as u64 && !self.bit(distance as usize)
    }

    fn commit(&mut self, sequence: u64) -> bool {
        if !self.check(sequence) {
            return false;
        }
        if !self.initialized {
            self.initialized = true;
            self.highest = sequence;
            self.set(0);
            return true;
        }
        if sequence > self.highest {
            let shift = sequence - self.highest;
            self.shift(usize::try_from(shift).unwrap_or(usize::MAX));
            self.highest = sequence;
            self.set(0);
        } else {
            self.set((self.highest - sequence) as usize);
        }
        true
    }

    fn bit(&self, offset: usize) -> bool {
        self.bitmap[offset / 64] & (1u64 << (offset % 64)) != 0
    }

    fn set(&mut self, offset: usize) {
        self.bitmap[offset / 64] |= 1u64 << (offset % 64);
    }

    fn shift(&mut self, count: usize) {
        if count >= REPLAY_BITS {
            self.bitmap = [0; REPLAY_WORDS];
            return;
        }
        let words = count / 64;
        let bits = count % 64;
        if words != 0 {
            for index in (0..REPLAY_WORDS).rev() {
                self.bitmap[index] = index
                    .checked_sub(words)
                    .map_or(0, |source| self.bitmap[source]);
            }
        }
        if bits != 0 {
            for index in (0..REPLAY_WORDS).rev() {
                let carry = index
                    .checked_sub(1)
                    .map_or(0, |source| self.bitmap[source] >> (64 - bits));
                self.bitmap[index] = (self.bitmap[index] << bits) | carry;
            }
        }
    }

    fn merge_into(&self, target: &mut Self) {
        if !self.initialized {
            return;
        }
        for offset in (0..REPLAY_BITS).rev() {
            if self.bit(offset) {
                let sequence = self.highest - offset as u64;
                let _ = target.commit(sequence);
            }
        }
    }
}

struct PacketSequence {
    next: Option<u64>,
}

impl PacketSequence {
    fn new() -> Self {
        Self { next: Some(0) }
    }

    fn take(&mut self) -> io::Result<u64> {
        let sequence = self
            .next
            .ok_or_else(|| io::Error::other("wire-v2 packet sequence exhausted"))?;
        self.next = sequence.checked_add(1);
        Ok(sequence)
    }
}

impl TxReceivers {
    async fn next_scheduled(&mut self) -> Option<(TxPriority, Outbound, Option<SocketAddr>)> {
        loop {
            if let Ok((destination, packet)) = self.path_control.try_recv() {
                return Some((TxPriority::Control, packet, Some(destination)));
            }
            if self.high_priority_streak >= 8 {
                if let Ok(packet) = self.new_data.try_recv() {
                    self.high_priority_streak = 0;
                    return Some((TxPriority::NewData, packet, None));
                }
                self.high_priority_streak = 0;
            }
            match self.control.try_recv() {
                Ok(packet) => {
                    self.high_priority_streak = self.high_priority_streak.saturating_add(1);
                    return Some((TxPriority::Control, packet, None));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {}
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
            match self.repair.try_recv() {
                Ok(packet) => {
                    self.high_priority_streak = self.high_priority_streak.saturating_add(1);
                    return Some((TxPriority::Repair, packet, None));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {}
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
            match self.new_data.try_recv() {
                Ok(packet) => {
                    self.high_priority_streak = 0;
                    return Some((TxPriority::NewData, packet, None));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {}
                Err(mpsc::error::TryRecvError::Empty) => {}
            }

            tokio::select! {
                biased;
                packet = self.path_control.recv() => {
                    if let Some((destination, packet)) = packet {
                        return Some((TxPriority::Control, packet, Some(destination)));
                    }
                }
                packet = self.control.recv() => {
                    if let Some(packet) = packet {
                        self.high_priority_streak = self.high_priority_streak.saturating_add(1);
                        return Some((TxPriority::Control, packet, None));
                    }
                }
                packet = self.repair.recv() => {
                    if let Some(packet) = packet {
                        self.high_priority_streak = self.high_priority_streak.saturating_add(1);
                        return Some((TxPriority::Repair, packet, None));
                    }
                }
                packet = self.new_data.recv() => {
                    if let Some(packet) = packet {
                        self.high_priority_streak = 0;
                        return Some((TxPriority::NewData, packet, None));
                    }
                }
                else => return None,
            }
        }
    }
}

struct RuntimeParts {
    tx: TxHandle,
    registry: mpsc::Sender<RegistryCommand>,
    events: mpsc::Receiver<SessionEvent>,
    metrics: Arc<SessionMetrics>,
    _shutdown: ShutdownGuard,
}

struct PendingOpen {
    tcp: TcpStream,
    last_sent: tokio::time::Instant,
    attempts: u8,
}

struct ShutdownGuard {
    signal: watch::Sender<bool>,
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        let _ = self.signal.send(true);
    }
}

fn start_runtime(
    udp: Arc<UdpSocket>,
    peer: SocketAddr,
    keys: V2SessionKeys,
    config: &Config,
    initiator: bool,
    responder_finish_cache: Option<ResponderFinishCache>,
) -> RuntimeParts {
    let routing_id = keys.routing_id();
    let (send_cipher, receive_cipher, send_direction, receive_direction) = if initiator {
        (
            keys.client_to_server_cipher(),
            keys.server_to_client_cipher(),
            Direction::InitiatorToResponder,
            Direction::ResponderToInitiator,
        )
    } else {
        (
            keys.server_to_client_cipher(),
            keys.client_to_server_cipher(),
            Direction::ResponderToInitiator,
            Direction::InitiatorToResponder,
        )
    };
    let (tx, tx_receivers) = TxHandle::new(config.control_dups);
    let (registry, registry_rx) = mpsc::channel(crate::flow_v2::REGISTRY_CHANNEL_CAPACITY);
    let (events_tx, events) = mpsc::channel(SESSION_EVENT_CAPACITY);
    let (peer_tx, peer_rx) = watch::channel(peer);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics = Arc::new(SessionMetrics::default());
    let reset_waiters = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(transmit_loop(
        udp.clone(),
        peer_rx,
        shutdown_rx.clone(),
        routing_id,
        send_direction,
        send_cipher,
        Pacer::new(config.max_send_mbps),
        tx_receivers,
        metrics.clone(),
    ));
    tokio::spawn(receive_loop(
        udp,
        peer_tx,
        shutdown_rx.clone(),
        routing_id,
        receive_direction,
        receive_cipher,
        tx.clone(),
        registry_rx,
        events_tx,
        responder_finish_cache,
        metrics.clone(),
        reset_waiters,
    ));
    tokio::spawn(metrics::report(metrics.clone(), shutdown_rx));

    RuntimeParts {
        tx,
        registry,
        events,
        metrics,
        _shutdown: ShutdownGuard {
            signal: shutdown_tx,
        },
    }
}

/// Run the initiator side after the authenticated wire-v2 handshake.
///
/// The supplied listener remains active for the lifetime of the session.  A
/// monotonically increasing nonzero flow identifier is allocated per accept.
pub async fn run_initiator_established<C>(
    udp: Arc<UdpSocket>,
    peer: SocketAddr,
    keys: V2SessionKeys,
    config: C,
    listener: TcpListener,
) -> Result<()>
where
    C: Into<Arc<Config>>,
{
    let config = config.into();
    let target = config
        .forward
        .clone()
        .ok_or_else(|| anyhow!("initiator config has no forward target"))?;
    let mut runtime = start_runtime(udp, peer, keys, &config, true, None);
    let mut pending = HashMap::<FlowId, PendingOpen>::new();
    let mut next_flow_id = 1u64;
    let mut open_retry_tick = tokio::time::interval(Duration::from_millis(100));
    open_retry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut keepalive_tick = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut keepalive_sequence = 0u64;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, source) = accepted.context("accept local TCP flow")?;
                if pending.len() >= PENDING_OPEN_LIMIT {
                    tracing::warn!(%source, "pending flow-open limit reached; dropping TCP connection");
                    continue;
                }
                let flow_id = next_flow_id;
                next_flow_id = next_flow_id
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("wire-v2 flow identifier space exhausted"))?;
                pending.insert(
                    flow_id,
                    PendingOpen {
                        tcp,
                        last_sent: tokio::time::Instant::now(),
                        attempts: 1,
                    },
                );
                tracing::info!(flow_id, %source, target = %target, "accepted local TCP flow");
                runtime.tx.send(
                    TxPriority::Control,
                    Outbound {
                        flow_id,
                        message: OwnedMessage::Open {
                            target: target.clone(),
                            symbol_size: config.symbol_size,
                            up_k: config.up.k_max,
                            down_k: config.down.k_max,
                        },
                    },
                ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
            }
            event = runtime.events.recv() => {
                let Some(event) = event else {
                    return Err(anyhow!("wire-v2 receive task stopped"));
                };
                match event {
                    SessionEvent::OpenOk { flow_id } => {
                        let Some(pending_open) = pending.remove(&flow_id) else {
                            continue;
                        };
                        let flow = flow_config(
                            config.symbol_size,
                            config.up.clone(),
                            config.down.k_max,
                            config.repair.clone(),
                            config.reorder_window,
                            config.max_send_mbps,
                        );
                        let (inbound, start) = spawn_flow_paused(
                            flow_id,
                            pending_open.tcp,
                            flow,
                            runtime.tx.clone(),
                            runtime.registry.clone(),
                        );
                        register_flow(
                            &runtime.registry,
                            flow_id,
                            config.symbol_size,
                            inbound,
                        ).await?;
                        runtime.metrics.flow_opened();
                        tracing::info!(flow_id, "remote accepted TCP flow");
                        start.start();
                    }
                    SessionEvent::OpenErr { flow_id, code, message } => {
                        tracing::warn!(flow_id, code, %message, "wire-v2 flow open rejected");
                        pending.remove(&flow_id);
                    }
                    SessionEvent::FlowClosed { .. } => runtime.metrics.flow_closed(),
                    SessionEvent::Open { flow_id, .. } => {
                        runtime.tx.send(
                            TxPriority::Control,
                            Outbound {
                                flow_id,
                                message: OwnedMessage::ResetFlow { reason: 1 },
                            },
                        ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                    }
                }
            }
            _ = open_retry_tick.tick() => {
                let now = tokio::time::Instant::now();
                let due = pending
                    .iter()
                    .filter(|(_, pending)| now.duration_since(pending.last_sent) >= OPEN_RETRY)
                    .map(|(&flow_id, _)| flow_id)
                    .collect::<Vec<_>>();
                for flow_id in due {
                    let Some(pending_open) = pending.get_mut(&flow_id) else {
                        continue;
                    };
                    if pending_open.attempts >= OPEN_MAX_ATTEMPTS {
                        tracing::warn!(flow_id, "flow open timed out");
                        pending.remove(&flow_id);
                        continue;
                    }
                    runtime.tx.send(
                        TxPriority::Control,
                        Outbound {
                            flow_id,
                            message: OwnedMessage::Open {
                                target: target.clone(),
                                symbol_size: config.symbol_size,
                                up_k: config.up.k_max,
                                down_k: config.down.k_max,
                            },
                        },
                    ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                    pending_open.attempts += 1;
                    pending_open.last_sent = now;
                }
            }
            _ = keepalive_tick.tick() => {
                runtime.tx.send(
                    TxPriority::Control,
                    Outbound {
                        flow_id: 0,
                        message: OwnedMessage::Ping {
                            timestamp: keepalive_sequence,
                        },
                    },
                ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                keepalive_sequence = keepalive_sequence.wrapping_add(1);
            }
        }
    }
}

struct OpenResult {
    flow_id: FlowId,
    result: io::Result<TcpStream>,
}

/// Run the responder side after the authenticated wire-v2 handshake.
pub async fn run_responder_established<C>(
    udp: Arc<UdpSocket>,
    peer: SocketAddr,
    keys: V2SessionKeys,
    responder_finish_cache: Option<ResponderFinishCache>,
    config: C,
) -> Result<()>
where
    C: Into<Arc<Config>>,
{
    let config = config.into();
    let mut runtime = start_runtime(udp, peer, keys, &config, false, responder_finish_cache);
    let (open_result_tx, mut open_results) = mpsc::channel(OPEN_RESULT_CAPACITY);
    let mut opening = HashMap::<FlowId, (u16, u16, u16)>::new();
    let mut active_flows = HashSet::<FlowId>::new();
    let mut open_responses = HashMap::<FlowId, OwnedMessage>::new();
    let mut open_response_order = VecDeque::<FlowId>::new();
    let mut keepalive_tick = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut keepalive_sequence = 0u64;

    loop {
        tokio::select! {
            event = runtime.events.recv() => {
                let Some(event) = event else {
                    return Err(anyhow!("wire-v2 receive task stopped"));
                };
                if let SessionEvent::FlowClosed { flow_id } = &event {
                    active_flows.remove(flow_id);
                    runtime.metrics.flow_closed();
                    continue;
                }
                let SessionEvent::Open {
                    flow_id,
                    target,
                    symbol_size,
                    up_k,
                    down_k,
                } = event else {
                    continue;
                };

                if flow_id == 0 {
                    let message = OwnedMessage::OpenErr {
                        code: 3,
                        message: "flow id must be nonzero".into(),
                    };
                    runtime.tx.send(
                        TxPriority::Control,
                        Outbound { flow_id, message },
                    ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                    continue;
                }
                if let Some(message) = open_responses.get(&flow_id).cloned() {
                    runtime.tx.send(
                        TxPriority::Control,
                        Outbound { flow_id, message },
                    ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                    continue;
                }
                if opening.contains_key(&flow_id) {
                    continue;
                }
                if opening.len() + active_flows.len() >= PENDING_OPEN_LIMIT {
                    let message = OwnedMessage::OpenErr {
                        code: 5,
                        message: "active flow limit reached".into(),
                    };
                    runtime.tx.send(
                        TxPriority::Control,
                        Outbound {
                            flow_id,
                            message: message.clone(),
                        },
                    ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                    remember_open_response(
                        &mut open_responses,
                        &mut open_response_order,
                        flow_id,
                        message,
                    );
                    continue;
                }
                if !target_allowed(&config, &target) {
                    runtime.metrics.target_denied();
                    tracing::warn!(flow_id, %target, "denied requested target");
                    let message = OwnedMessage::OpenErr {
                        code: 1,
                        message: "target denied".into(),
                    };
                    runtime.tx.send(
                        TxPriority::Control,
                        Outbound {
                            flow_id,
                            message: message.clone(),
                        },
                    ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                    remember_open_response(
                        &mut open_responses,
                        &mut open_response_order,
                        flow_id,
                        message,
                    );
                    continue;
                }
                if symbol_size != config.symbol_size
                    || up_k != config.up.k_max
                    || down_k != config.down.k_max
                {
                    let message = OwnedMessage::OpenErr {
                        code: 2,
                        message: "transport parameters rejected".into(),
                    };
                    runtime.tx.send(
                        TxPriority::Control,
                        Outbound {
                            flow_id,
                            message: message.clone(),
                        },
                    ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                    remember_open_response(
                        &mut open_responses,
                        &mut open_response_order,
                        flow_id,
                        message,
                    );
                    continue;
                }

                opening.insert(flow_id, (symbol_size, up_k, down_k));
                let result_tx = open_result_tx.clone();
                tokio::spawn(async move {
                    let result = match tokio::time::timeout(
                        CONNECT_TIMEOUT,
                        TcpStream::connect(&target),
                    ).await {
                        Ok(result) => result,
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "target connect timed out",
                        )),
                    };
                    let _ = result_tx.send(OpenResult { flow_id, result }).await;
                });
            }
            result = open_results.recv() => {
                let Some(OpenResult { flow_id, result }) = result else {
                    return Err(anyhow!("wire-v2 target connector stopped"));
                };
                let Some((symbol_size, up_k, _down_k)) = opening.remove(&flow_id) else {
                    continue;
                };
                match result {
                    Ok(tcp) => {
                        tracing::info!(flow_id, "connected remote TCP target");
                        let flow = flow_config(
                            symbol_size,
                            config.down.clone(),
                            up_k,
                            config.repair.clone(),
                            config.reorder_window,
                            config.max_send_mbps,
                        );
                        let (inbound, start) = spawn_flow_paused(
                            flow_id,
                            tcp,
                            flow,
                            runtime.tx.clone(),
                            runtime.registry.clone(),
                        );
                        register_flow(&runtime.registry, flow_id, symbol_size, inbound).await?;
                        active_flows.insert(flow_id);
                        runtime.metrics.flow_opened();
                        remember_open_response(
                            &mut open_responses,
                            &mut open_response_order,
                            flow_id,
                            OwnedMessage::OpenOk,
                        );
                        runtime.tx.send(
                            TxPriority::Control,
                            Outbound { flow_id, message: OwnedMessage::OpenOk },
                        ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                        start.start();
                    }
                    Err(error) => {
                        let message = error.to_string();
                        let message = if message.len() > wire_v2::MAX_OPEN_ERROR_MESSAGE_LEN {
                            "target connect failed".to_string()
                        } else {
                            message
                        };
                        let message = OwnedMessage::OpenErr { code: 4, message };
                        runtime.tx.send(
                            TxPriority::Control,
                            Outbound {
                                flow_id,
                                message: message.clone(),
                            },
                        ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                        remember_open_response(
                            &mut open_responses,
                            &mut open_response_order,
                            flow_id,
                            message,
                        );
                    }
                }
            }
            _ = keepalive_tick.tick() => {
                runtime.tx.send(
                    TxPriority::Control,
                    Outbound {
                        flow_id: 0,
                        message: OwnedMessage::Ping {
                            timestamp: keepalive_sequence,
                        },
                    },
                ).await.map_err(|_| anyhow!("wire-v2 transmit task stopped"))?;
                keepalive_sequence = keepalive_sequence.wrapping_add(1);
            }
        }
    }
}

fn remember_open_response(
    responses: &mut HashMap<FlowId, OwnedMessage>,
    order: &mut VecDeque<FlowId>,
    flow_id: FlowId,
    message: OwnedMessage,
) {
    if !responses.contains_key(&flow_id) {
        while responses.len() >= OPEN_HISTORY_LIMIT {
            let Some(oldest) = order.pop_front() else {
                break;
            };
            responses.remove(&oldest);
        }
        order.push_back(flow_id);
    }
    responses.insert(flow_id, message);
}

fn target_allowed(config: &Config, target: &str) -> bool {
    config.allowed_targets.is_empty()
        || config
            .allowed_targets
            .iter()
            .any(|allowed| allowed == target)
}

fn is_transient_udp_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::AddrNotAvailable
    )
}

#[allow(clippy::too_many_arguments)]
async fn transmit_loop(
    udp: Arc<UdpSocket>,
    peer: watch::Receiver<SocketAddr>,
    mut shutdown: watch::Receiver<bool>,
    routing_id: u64,
    direction: Direction,
    cipher: CipherState,
    mut pacer: Pacer,
    mut queues: TxReceivers,
    metrics: Arc<SessionMetrics>,
) {
    let mut sequence = PacketSequence::new();
    loop {
        let outbound = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
            outbound = queues.next_scheduled() => outbound,
        };
        let Some((_priority, outbound, destination_override)) = outbound else {
            return;
        };
        let Ok(packet_seq) = sequence.take() else {
            return;
        };
        let packet = borrowed_packet(
            routing_id,
            packet_seq,
            direction,
            outbound.flow_id,
            &outbound.message,
        );
        let Ok(parts) = wire_v2::encode_parts(&packet, outbound.message.symbol_size()) else {
            continue;
        };
        let Ok(sealed) = cipher.seal_v2(packet_seq, &parts.aad, &parts.body) else {
            return;
        };
        let mut datagram = Vec::with_capacity(parts.aad.len() + sealed.len());
        datagram.extend_from_slice(&parts.aad);
        datagram.extend_from_slice(&sealed);
        pacer.acquire(datagram.len()).await;
        let destination = destination_override.unwrap_or(*peer.borrow());
        if let Err(error) = udp.send_to(&datagram, destination).await {
            if is_transient_udp_error(&error) {
                tracing::warn!(%destination, %error, "transient UDP send failure; packet dropped");
                continue;
            }
            return;
        }
        metrics.packet_sent(datagram.len());
    }
}

fn borrowed_packet<'a>(
    routing_id: u64,
    packet_seq: u64,
    direction: Direction,
    flow_id: FlowId,
    message: &'a OwnedMessage,
) -> Packet<'a> {
    let message = match message {
        OwnedMessage::Open {
            target,
            symbol_size,
            up_k,
            down_k,
        } => Message::Open {
            target,
            symbol_size: *symbol_size,
            up_k: *up_k,
            down_k: *down_k,
        },
        OwnedMessage::OpenOk => Message::OpenOk,
        OwnedMessage::OpenErr { code, message } => Message::OpenErr {
            code: *code,
            message,
        },
        OwnedMessage::Data {
            block_seq,
            esi,
            k_eff,
            block_payload_len,
            symbol,
        } => Message::Data {
            block_seq: *block_seq,
            esi: *esi,
            k_eff: *k_eff,
            block_payload_len: *block_payload_len,
            symbol,
        },
        OwnedMessage::RepairReq { block_seq, count } => Message::RepairReq {
            block_seq: *block_seq,
            count: *count,
        },
        OwnedMessage::BlockAck { block_seq } => Message::BlockAck {
            block_seq: *block_seq,
        },
        OwnedMessage::WindowUpdate { credit_bytes } => Message::WindowUpdate {
            credit_bytes: *credit_bytes,
        },
        OwnedMessage::Fin {
            final_block_seq,
            final_byte_count,
        } => Message::Fin {
            final_block_seq: *final_block_seq,
            final_byte_count: *final_byte_count,
        },
        OwnedMessage::FinAck => Message::FinAck,
        OwnedMessage::ResetFlow { reason } => Message::ResetFlow { reason: *reason },
        OwnedMessage::ResetAck => Message::ResetAck,
        OwnedMessage::Ping { timestamp } => Message::Ping {
            timestamp: *timestamp,
        },
        OwnedMessage::Pong { timestamp } => Message::Pong {
            timestamp: *timestamp,
        },
        OwnedMessage::Rekey => Message::Rekey,
        OwnedMessage::PathChallenge { token } => Message::PathChallenge { token: *token },
        OwnedMessage::PathResponse { token } => Message::PathResponse { token: *token },
    };
    Packet {
        header: PacketHeader {
            direction,
            session_id: routing_id,
            packet_seq,
            flow_id,
        },
        message,
    }
}

#[allow(clippy::too_many_arguments)]
async fn receive_loop(
    udp: Arc<UdpSocket>,
    peer: watch::Sender<SocketAddr>,
    mut shutdown: watch::Receiver<bool>,
    routing_id: u64,
    expected_direction: Direction,
    cipher: CipherState,
    tx: TxHandle,
    mut registry_commands: mpsc::Receiver<RegistryCommand>,
    events: mpsc::Sender<SessionEvent>,
    responder_finish_cache: Option<ResponderFinishCache>,
    metrics: Arc<SessionMetrics>,
    reset_waiters: ResetWaiters,
) {
    let mut routes = HashMap::<FlowId, FlowRoute>::new();
    let mut early_messages = HashMap::<FlowId, Vec<OwnedMessage>>::new();
    let mut closed_flows = HashSet::<FlowId>::new();
    let mut closed_flow_order = VecDeque::<FlowId>::new();
    let mut replay = ReplayWindow64::new();
    let mut buffer = vec![0u8; MAX_DATAGRAM_SIZE];
    let mut path_candidate: Option<PathCandidate> = None;
    let mut last_authenticated = tokio::time::Instant::now();
    let mut idle_tick = tokio::time::interval(Duration::from_secs(1));
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            command = registry_commands.recv() => {
                match command {
                    Some(RegistryCommand::Register {
                        flow_id,
                        symbol_size,
                        inbound,
                        ready,
                    }) => {
                        if let Some(messages) = early_messages.remove(&flow_id) {
                            for message in messages {
                                if inbound.try_send(message).is_err() {
                                    break;
                                }
                            }
                        }
                        routes.insert(flow_id, FlowRoute { symbol_size, inbound });
                        let _ = ready.send(());
                    }
                    Some(RegistryCommand::Remove { flow_id }) => {
                        routes.remove(&flow_id);
                        early_messages.remove(&flow_id);
                        remember_closed_flow(
                            &mut closed_flows,
                            &mut closed_flow_order,
                            flow_id,
                        );
                        let _ = events.try_send(SessionEvent::FlowClosed { flow_id });
                    }
                    None => return,
                }
            }
            _ = idle_tick.tick() => {
                if last_authenticated.elapsed() >= SESSION_IDLE_TIMEOUT {
                    tracing::warn!("wire-v2 session idle timeout; returning to handshake");
                    return;
                }
            }
            received = udp.recv_from(&mut buffer) => {
                let (length, source) = match received {
                    Ok(received) => received,
                    Err(error) if is_transient_udp_error(&error) => {
                        tracing::warn!(%error, "transient UDP receive failure");
                        continue;
                    }
                    Err(_) => return,
                };
                let datagram = &buffer[..length];
                metrics.packet_received(length);
                if let Some(cache) = &responder_finish_cache
                    && cache
                        .answer_duplicate(&udp, source, datagram)
                        .await
                        .unwrap_or(false)
                {
                    continue;
                }
                if datagram.len() < COMMON_HEADER_LEN + AEAD_TAG_LEN {
                    continue;
                }

                // These cleartext fields are used only to choose this session,
                // direction key, and nonce.  Every field is revalidated after AEAD.
                let direction_byte = datagram[6];
                let Ok(session_bytes) = <[u8; 8]>::try_from(&datagram[16..24]) else {
                    continue;
                };
                let session_id = u64::from_be_bytes(session_bytes);
                let Ok(sequence_bytes) = <[u8; 8]>::try_from(&datagram[24..32]) else {
                    continue;
                };
                let packet_seq = u64::from_be_bytes(sequence_bytes);
                if session_id != routing_id || direction_byte != expected_direction as u8 {
                    metrics.decode_drop();
                    continue;
                }
                if !replay.check(packet_seq) {
                    metrics.replay_drop();
                    continue;
                }

                let Ok(sealed) = wire_v2::split_sealed_datagram(datagram) else {
                    metrics.decode_drop();
                    continue;
                };
                let Ok(plaintext) =
                    cipher.open_v2(packet_seq, sealed.aad(), sealed.ciphertext_and_tag())
                else {
                    metrics.auth_drop();
                    continue;
                };
                let authenticated_header = sealed.unverified_header;
                if authenticated_header.session_id != routing_id
                    || authenticated_header.direction != expected_direction
                    || authenticated_header.packet_seq != packet_seq
                {
                    metrics.decode_drop();
                    continue;
                }
                let symbol_size = routes
                    .get(&authenticated_header.flow_id)
                    .map(|route| route.symbol_size);
                let Ok(packet) =
                    wire_v2::decode_parts(sealed.aad(), &plaintext, symbol_size)
                else {
                    metrics.decode_drop();
                    continue;
                };
                if *peer.borrow() != source {
                    let valid_response = matches!(
                        (&path_candidate, &packet.message),
                        (
                            Some(candidate),
                            Message::PathResponse { token }
                        ) if candidate.address == source
                            && candidate.token == *token
                            && tokio::time::Instant::now() <= candidate.expires_at
                    );
                    if valid_response {
                        let candidate = path_candidate.as_ref().expect("matched candidate");
                        candidate.replay.merge_into(&mut replay);
                        if replay.commit(packet_seq) {
                            let _ = peer.send(source);
                            last_authenticated = tokio::time::Instant::now();
                            path_candidate = None;
                            metrics.path_migration();
                            tracing::info!(new_peer = %source, "validated UDP path migration");
                        }
                        continue;
                    }

                    let now = tokio::time::Instant::now();
                    let (token, send_challenge) = match &mut path_candidate {
                        Some(candidate)
                            if candidate.address == source && now <= candidate.expires_at =>
                        {
                            if !candidate.replay.commit(packet_seq) {
                                metrics.replay_drop();
                                continue;
                            }
                            let should_send =
                                now.duration_since(candidate.last_challenge) >= PATH_CHALLENGE_RETRY;
                            if should_send {
                                candidate.last_challenge = now;
                            }
                            (candidate.token, should_send)
                        }
                        _ => {
                            let token = rand::random();
                            let mut candidate_replay = ReplayWindow64::new();
                            let _ = candidate_replay.commit(packet_seq);
                            path_candidate = Some(PathCandidate {
                                address: source,
                                token,
                                expires_at: now + PATH_CHALLENGE_TIMEOUT,
                                last_challenge: now,
                                replay: candidate_replay,
                            });
                            (token, true)
                        }
                    };
                    if send_challenge {
                        metrics.path_challenge();
                        if tx
                            .send_to(
                                source,
                                Outbound {
                                    flow_id: 0,
                                    message: OwnedMessage::PathChallenge { token },
                                },
                            )
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    continue;
                }
                if !replay.commit(packet_seq) {
                    metrics.replay_drop();
                    continue;
                }
                last_authenticated = tokio::time::Instant::now();
                dispatch_packet(
                    packet,
                    &mut routes,
                    &mut early_messages,
                    &closed_flows,
                    &events,
                    &tx,
                    &reset_waiters,
                );
            }
        }
    }
}

fn remember_closed_flow(
    closed: &mut HashSet<FlowId>,
    order: &mut VecDeque<FlowId>,
    flow_id: FlowId,
) {
    if closed.insert(flow_id) {
        while closed.len() > OPEN_HISTORY_LIMIT {
            let Some(oldest) = order.pop_front() else {
                break;
            };
            closed.remove(&oldest);
        }
        order.push_back(flow_id);
    }
}

fn dispatch_packet(
    packet: Packet<'_>,
    routes: &mut HashMap<FlowId, FlowRoute>,
    early_messages: &mut HashMap<FlowId, Vec<OwnedMessage>>,
    closed_flows: &HashSet<FlowId>,
    events: &mpsc::Sender<SessionEvent>,
    tx: &TxHandle,
    reset_waiters: &ResetWaiters,
) {
    let flow_id = packet.header.flow_id;
    let message = owned_message(packet.message);
    if matches!(&message, OwnedMessage::ResetAck) {
        let acknowledged = reset_waiters
            .lock()
            .ok()
            .and_then(|waiters| waiters.get(&flow_id).cloned())
            .is_some_and(|waiter| {
                waiter.send_modify(|count| *count = count.wrapping_add(1));
                true
            });
        if acknowledged {
            return;
        }
    }
    let message = match message {
        OwnedMessage::Open {
            target,
            symbol_size,
            up_k,
            down_k,
        } if flow_id != 0 => {
            if events
                .try_send(SessionEvent::Open {
                    flow_id,
                    target,
                    symbol_size,
                    up_k,
                    down_k,
                })
                .is_err()
            {
                queue_reset(tx, reset_waiters, flow_id, 5);
            }
            return;
        }
        OwnedMessage::OpenOk if flow_id != 0 => {
            if events.try_send(SessionEvent::OpenOk { flow_id }).is_err() {
                queue_reset(tx, reset_waiters, flow_id, 5);
            }
            return;
        }
        OwnedMessage::OpenErr { code, message } if flow_id != 0 => {
            if events
                .try_send(SessionEvent::OpenErr {
                    flow_id,
                    code,
                    message,
                })
                .is_err()
            {
                queue_reset(tx, reset_waiters, flow_id, 5);
            }
            return;
        }
        message => message,
    };
    if let Some(route) = routes.get(&flow_id) {
        match route.inbound.try_send(message) {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Full(_)) => {
                queue_reset(tx, reset_waiters, flow_id, 5);
                routes.remove(&flow_id);
                return;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                routes.remove(&flow_id);
                return;
            }
        }
    }
    if closed_flows.contains(&flow_id) {
        if matches!(message, OwnedMessage::ResetFlow { .. }) {
            queue_control(
                tx,
                Outbound {
                    flow_id,
                    message: OwnedMessage::ResetAck,
                },
            );
        }
        return;
    }

    match message {
        OwnedMessage::Ping { timestamp } if flow_id == 0 => {
            queue_control(
                tx,
                Outbound {
                    flow_id: 0,
                    message: OwnedMessage::Pong { timestamp },
                },
            );
        }
        OwnedMessage::PathChallenge { token } if flow_id == 0 => {
            queue_control(
                tx,
                Outbound {
                    flow_id: 0,
                    message: OwnedMessage::PathResponse { token },
                },
            );
        }
        OwnedMessage::PathResponse { .. } if flow_id == 0 => {}
        message if flow_id != 0 => {
            if early_messages.len() < EARLY_FLOW_LIMIT || early_messages.contains_key(&flow_id) {
                let queue = early_messages.entry(flow_id).or_default();
                if queue.len() < EARLY_MESSAGE_LIMIT {
                    queue.push(message);
                }
            }
        }
        _ => {}
    }
}

fn queue_reset(tx: &TxHandle, reset_waiters: &ResetWaiters, flow_id: FlowId, reason: u16) {
    let (acknowledge, mut acknowledgements) = watch::channel(0u64);
    let Ok(mut waiters) = reset_waiters.lock() else {
        return;
    };
    if waiters.contains_key(&flow_id) {
        return;
    }
    waiters.insert(flow_id, acknowledge);
    drop(waiters);

    let tx = tx.clone();
    let reset_waiters = reset_waiters.clone();
    tokio::spawn(async move {
        for attempt in 0..RESET_RETRIES {
            if tx
                .send(
                    TxPriority::Control,
                    Outbound {
                        flow_id,
                        message: OwnedMessage::ResetFlow { reason },
                    },
                )
                .await
                .is_err()
            {
                break;
            }
            if attempt + 1 < RESET_RETRIES
                && tokio::time::timeout(OPEN_RETRY, acknowledgements.changed())
                    .await
                    .is_ok()
            {
                break;
            }
        }
        if let Ok(mut waiters) = reset_waiters.lock() {
            waiters.remove(&flow_id);
        }
    });
}

fn queue_control(tx: &TxHandle, outbound: Outbound) {
    let tx = tx.clone();
    tokio::spawn(async move {
        let _ = tx.send(TxPriority::Control, outbound).await;
    });
}

fn owned_message(message: Message<'_>) -> OwnedMessage {
    match message {
        Message::Open {
            target,
            symbol_size,
            up_k,
            down_k,
        } => OwnedMessage::Open {
            target: target.to_owned(),
            symbol_size,
            up_k,
            down_k,
        },
        Message::OpenOk => OwnedMessage::OpenOk,
        Message::OpenErr { code, message } => OwnedMessage::OpenErr {
            code,
            message: message.to_owned(),
        },
        Message::Data {
            block_seq,
            esi,
            k_eff,
            block_payload_len,
            symbol,
        } => OwnedMessage::Data {
            block_seq,
            esi,
            k_eff,
            block_payload_len,
            symbol: symbol.to_vec(),
        },
        Message::RepairReq { block_seq, count } => OwnedMessage::RepairReq { block_seq, count },
        Message::BlockAck { block_seq } => OwnedMessage::BlockAck { block_seq },
        Message::WindowUpdate { credit_bytes } => OwnedMessage::WindowUpdate { credit_bytes },
        Message::Fin {
            final_block_seq,
            final_byte_count,
        } => OwnedMessage::Fin {
            final_block_seq,
            final_byte_count,
        },
        Message::FinAck => OwnedMessage::FinAck,
        Message::ResetFlow { reason } => OwnedMessage::ResetFlow { reason },
        Message::ResetAck => OwnedMessage::ResetAck,
        Message::Ping { timestamp } => OwnedMessage::Ping { timestamp },
        Message::Pong { timestamp } => OwnedMessage::Pong { timestamp },
        Message::Rekey => OwnedMessage::Rekey,
        Message::PathChallenge { token } => OwnedMessage::PathChallenge { token },
        Message::PathResponse { token } => OwnedMessage::PathResponse { token },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FecProfile, Mode, RepairConfig};
    use crate::crypto::wire_v2::{ClientHello, ServerHello, TransportParameters};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinHandle;

    fn outbound(flow_id: u64, value: u64) -> Outbound {
        Outbound {
            flow_id,
            message: OwnedMessage::Ping { timestamp: value },
        }
    }

    fn test_keys() -> V2SessionKeys {
        let psk = b"runtime-v2-test-pre-shared-key";
        let parameters = TransportParameters::new(128, 4, 4).unwrap();
        let client = ClientHello::new(psk, [1; 16], 0, parameters).unwrap();
        let server = ServerHello::new(psk, &client, [2; 16], 0, parameters).unwrap();
        V2SessionKeys::derive(psk, &client, &server).unwrap()
    }

    fn test_config(mode: Mode, forward: Option<String>, allowed_targets: Vec<String>) -> Config {
        Config {
            mode,
            tcp_listen: None,
            udp_listen: None,
            peer: None,
            forward,
            allowed_targets,
            psk: vec![],
            mtu: 1500,
            symbol_size: 128,
            ipv6: false,
            up: FecProfile {
                k_max: 4,
                r_base: 1,
                timeout_ms: 20,
            },
            down: FecProfile {
                k_max: 4,
                r_base: 1,
                timeout_ms: 20,
            },
            repair: RepairConfig {
                delay_ms: 20,
                retry_ms: 20,
                deadline_ms: 500,
                max_reqs: 2,
            },
            reorder_window: 16,
            control_dups: 1,
            max_send_mbps: 100,
        }
    }

    async fn start_pair(
        target: String,
        allowed_targets: Vec<String>,
        listener: TcpListener,
    ) -> (JoinHandle<Result<()>>, JoinHandle<Result<()>>) {
        let initiator_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let responder_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let initiator_addr = initiator_udp.local_addr().unwrap();
        let responder_addr = responder_udp.local_addr().unwrap();
        let keys = test_keys();
        let initiator = tokio::spawn(run_initiator_established(
            initiator_udp,
            responder_addr,
            keys.clone(),
            test_config(Mode::Local, Some(target), Vec::new()),
            listener,
        ));
        let responder = tokio::spawn(run_responder_established(
            responder_udp,
            initiator_addr,
            keys,
            None,
            test_config(Mode::Remote, None, allowed_targets),
        ));
        (initiator, responder)
    }

    #[tokio::test]
    async fn scheduler_priority_and_sequence_are_strict() {
        let (tx, mut queues) = TxHandle::new(1);
        tx.send(TxPriority::NewData, outbound(1, 3)).await.unwrap();
        tx.send(TxPriority::Repair, outbound(1, 2)).await.unwrap();
        tx.send(TxPriority::Control, outbound(1, 1)).await.unwrap();

        let mut priorities = Vec::new();
        let mut sequence = PacketSequence::new();
        let mut sequences = Vec::new();
        for _ in 0..3 {
            priorities.push(queues.next_scheduled().await.unwrap().0);
            sequences.push(sequence.take().unwrap());
        }
        assert_eq!(
            priorities,
            [TxPriority::Control, TxPriority::Repair, TxPriority::NewData]
        );
        assert_eq!(sequences, [0, 1, 2]);
    }

    #[tokio::test]
    async fn scheduler_bounds_high_priority_starvation() {
        let (tx, mut queues) = TxHandle::new(1);
        for value in 0..12 {
            tx.send(TxPriority::Control, outbound(1, value))
                .await
                .unwrap();
        }
        tx.send(TxPriority::NewData, outbound(2, 99)).await.unwrap();

        for _ in 0..8 {
            assert_eq!(
                queues.next_scheduled().await.unwrap().0,
                TxPriority::Control
            );
        }
        assert_eq!(
            queues.next_scheduled().await.unwrap().0,
            TxPriority::NewData
        );
    }

    #[tokio::test]
    async fn path_migration_requires_authenticated_challenge_response() {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let old_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let keys = test_keys();
        let routing_id = keys.routing_id();
        let client_cipher = keys.client_to_server_cipher();
        let server_cipher = keys.server_to_client_cipher();
        let _runtime = start_runtime(
            server.clone(),
            old_peer.local_addr().unwrap(),
            keys,
            &test_config(Mode::Remote, None, Vec::new()),
            false,
            None,
        );

        async fn send_message(
            socket: &UdpSocket,
            destination: SocketAddr,
            cipher: &CipherState,
            routing_id: u64,
            sequence: u64,
            message: Message<'_>,
        ) {
            let packet = Packet {
                header: PacketHeader {
                    direction: Direction::InitiatorToResponder,
                    session_id: routing_id,
                    packet_seq: sequence,
                    flow_id: 0,
                },
                message,
            };
            let parts = wire_v2::encode_parts(&packet, None).unwrap();
            let sealed = cipher.seal_v2(sequence, &parts.aad, &parts.body).unwrap();
            let mut datagram = parts.aad.to_vec();
            datagram.extend_from_slice(&sealed);
            socket.send_to(&datagram, destination).await.unwrap();
        }

        let server_address = server.local_addr().unwrap();
        send_message(
            &new_peer,
            server_address,
            &client_cipher,
            routing_id,
            0,
            Message::Ping { timestamp: 1 },
        )
        .await;

        let mut buffer = vec![0u8; 2048];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), new_peer.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        let sealed = wire_v2::split_sealed_datagram(&buffer[..length]).unwrap();
        let challenge_plaintext = server_cipher
            .open_v2(
                sealed.unverified_header.packet_seq,
                sealed.aad(),
                sealed.ciphertext_and_tag(),
            )
            .unwrap();
        let challenge = wire_v2::decode_parts(sealed.aad(), &challenge_plaintext, None).unwrap();
        let Message::PathChallenge { token } = challenge.message else {
            panic!("expected path challenge");
        };

        send_message(
            &new_peer,
            server_address,
            &client_cipher,
            routing_id,
            1,
            Message::PathResponse { token },
        )
        .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        send_message(
            &new_peer,
            server_address,
            &client_cipher,
            routing_id,
            2,
            Message::Ping { timestamp: 2 },
        )
        .await;

        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), new_peer.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        let sealed = wire_v2::split_sealed_datagram(&buffer[..length]).unwrap();
        let pong_plaintext = server_cipher
            .open_v2(
                sealed.unverified_header.packet_seq,
                sealed.aad(),
                sealed.ciphertext_and_tag(),
            )
            .unwrap();
        assert!(matches!(
            wire_v2::decode_parts(sealed.aad(), &pong_plaintext, None)
                .unwrap()
                .message,
            Message::Pong { timestamp: 2 }
        ));

        // The packet that initiated validation was consumed into replay state
        // when the path was accepted and cannot be replayed afterward.
        send_message(
            &new_peer,
            server_address,
            &client_cipher,
            routing_id,
            0,
            Message::Ping { timestamp: 1 },
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), new_peer.recv_from(&mut buffer),)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn two_simultaneous_flows_echo_byte_exactly() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap().to_string();
        let echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = target_listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_addr = ingress.local_addr().unwrap();
        let (initiator, responder) = start_pair(target.clone(), vec![target], ingress).await;

        let exchange = |payload: Vec<u8>| async move {
            let mut client = TcpStream::connect(ingress_addr).await.unwrap();
            client.write_all(&payload).await.unwrap();
            let mut echoed = vec![0; payload.len()];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload);
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            futures_join(exchange(vec![0x11; 777]), exchange(vec![0x22; 913])),
        )
        .await
        .expect("simultaneous echo flows timed out");

        initiator.abort();
        responder.abort();
        echo.abort();
    }

    async fn futures_join<A, B>(a: A, b: B)
    where
        A: std::future::Future<Output = ()>,
        B: std::future::Future<Output = ()>,
    {
        tokio::join!(a, b);
    }

    #[tokio::test]
    async fn reset_of_one_flow_does_not_affect_another() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap().to_string();
        let (first_dropped_tx, first_dropped_rx) = tokio::sync::oneshot::channel();
        let target_task = tokio::spawn(async move {
            let (first, _) = target_listener.accept().await.unwrap();
            #[allow(deprecated)]
            first.set_linger(Some(Duration::ZERO)).unwrap();
            drop(first);
            let _ = first_dropped_tx.send(());

            let (mut second, _) = target_listener.accept().await.unwrap();
            let (mut read, mut write) = second.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_addr = ingress.local_addr().unwrap();
        let (initiator, responder) = start_pair(target.clone(), vec![target], ingress).await;

        let mut failed = TcpStream::connect(ingress_addr).await.unwrap();
        failed.write_all(&[0x44; 1024]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), first_dropped_rx)
            .await
            .expect("first target was not connected")
            .unwrap();

        let mut healthy = TcpStream::connect(ingress_addr).await.unwrap();
        let payload = vec![0x5a; 1500];
        healthy.write_all(&payload).await.unwrap();
        let mut echoed = vec![0; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), healthy.read_exact(&mut echoed))
            .await
            .expect("healthy flow stalled")
            .unwrap();
        assert_eq!(echoed, payload);

        let mut byte = [0; 1];
        let failed_result =
            tokio::time::timeout(Duration::from_secs(3), failed.read(&mut byte)).await;
        assert!(
            matches!(failed_result, Ok(Ok(0)) | Ok(Err(_))),
            "reset flow remained open: {failed_result:?}"
        );

        initiator.abort();
        responder.abort();
        target_task.abort();
    }

    #[tokio::test]
    async fn open_target_denial_never_connects_target() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap().to_string();
        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_addr = ingress.local_addr().unwrap();
        let (initiator, responder) = start_pair(target, vec!["127.0.0.1:9".into()], ingress).await;

        let mut client = TcpStream::connect(ingress_addr).await.unwrap();
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), client.read(&mut byte))
            .await
            .expect("denied flow did not close")
            .unwrap();
        assert_eq!(read, 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), target_listener.accept())
                .await
                .is_err(),
            "denied target was connected"
        );

        initiator.abort();
        responder.abort();
    }

    #[test]
    fn replay_window_commits_u64_sequences_once() {
        let mut replay = ReplayWindow64::new();
        assert!(replay.commit(u32::MAX as u64 + 10));
        assert!(!replay.commit(u32::MAX as u64 + 10));
        assert!(replay.commit(u32::MAX as u64 + 12));
        assert!(replay.commit(u32::MAX as u64 + 11));
    }

    #[test]
    fn target_allowlist_denies_unlisted_target() {
        let config = test_config(Mode::Remote, None, vec!["127.0.0.1:443".into()]);
        assert!(target_allowed(&config, "127.0.0.1:443"));
        assert!(!target_allowed(&config, "127.0.0.1:444"));
    }
}
