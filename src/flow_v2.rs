//! Per-flow state machine for the authenticated wire-v2 runtime.
//!
//! A flow owns its FEC encoder/decoder and TCP halves.  The session runtime
//! only authenticates, schedules, and dispatches datagrams, so a blocked TCP
//! writer can never stall UDP receive or another flow.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};

use crate::config::{FecProfile, RepairConfig};
use crate::receiver::{BlockReceiver, ReceiverEvent};
use crate::sender::BlockSender;
use crate::symbol::Symbol;

pub type FlowId = u64;

pub(crate) const FLOW_CHANNEL_CAPACITY: usize = 128;
pub(crate) const REGISTRY_CHANNEL_CAPACITY: usize = 128;
pub(crate) const SESSION_EVENT_CAPACITY: usize = 128;
const WRITER_CHANNEL_CAPACITY: usize = 16;
const INITIAL_CREDIT_BYTES: u32 = 256 * 1024;
const MAX_BLOCK_BYTES: usize = INITIAL_CREDIT_BYTES as usize;
const FIN_RETRY: Duration = Duration::from_millis(200);
const FIN_ACK_LINGER: Duration = Duration::from_secs(1);
const FLOW_TICK: Duration = Duration::from_millis(20);
const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
// Retransmit until the session's 30-second idle supervisor would tear down
// both sides, preventing orphaned flows across long blackouts.
const RESET_RETRIES: usize = 150;
const CREDIT_RETRANSMIT: Duration = Duration::from_millis(500);
const MAX_BLOCKS_PER_FLOW: u32 = u32::MAX - 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxPriority {
    Control,
    Repair,
    NewData,
}

#[derive(Clone, Debug)]
pub(crate) enum OwnedMessage {
    Open {
        target: String,
        symbol_size: u16,
        up_k: u16,
        down_k: u16,
    },
    OpenOk,
    OpenErr {
        code: u16,
        message: String,
    },
    Data {
        block_seq: u32,
        esi: u32,
        k_eff: u16,
        block_payload_len: u32,
        symbol: Vec<u8>,
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

impl OwnedMessage {
    pub(crate) fn symbol_size(&self) -> Option<u16> {
        match self {
            Self::Data { symbol, .. } => u16::try_from(symbol.len()).ok(),
            _ => None,
        }
    }

    fn is_idempotent_control(&self) -> bool {
        matches!(
            self,
            Self::Open { .. }
                | Self::OpenOk
                | Self::OpenErr { .. }
                | Self::BlockAck { .. }
                | Self::WindowUpdate { .. }
                | Self::Fin { .. }
                | Self::FinAck
                | Self::ResetFlow { .. }
                | Self::ResetAck
                | Self::Ping { .. }
                | Self::Pong { .. }
                | Self::Rekey
                | Self::PathChallenge { .. }
                | Self::PathResponse { .. }
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Outbound {
    pub(crate) flow_id: FlowId,
    pub(crate) message: OwnedMessage,
}

#[derive(Clone)]
pub(crate) struct TxHandle {
    control: mpsc::Sender<Outbound>,
    repair: mpsc::Sender<Outbound>,
    new_data: mpsc::Sender<Outbound>,
    path_control: mpsc::Sender<(SocketAddr, Outbound)>,
    control_copies: u8,
}

pub(crate) struct TxReceivers {
    pub(crate) control: mpsc::Receiver<Outbound>,
    pub(crate) repair: mpsc::Receiver<Outbound>,
    pub(crate) new_data: mpsc::Receiver<Outbound>,
    pub(crate) path_control: mpsc::Receiver<(SocketAddr, Outbound)>,
    pub(crate) high_priority_streak: u8,
}

impl TxHandle {
    pub(crate) fn new(control_copies: u8) -> (Self, TxReceivers) {
        let (control, control_rx) = mpsc::channel(128);
        let (repair, repair_rx) = mpsc::channel(128);
        // A short shared data queue bounds head-of-line time when one flow is
        // much busier than its peers.
        let (new_data, new_data_rx) = mpsc::channel(64);
        let (path_control, path_control_rx) = mpsc::channel(16);
        (
            Self {
                control,
                repair,
                new_data,
                path_control,
                control_copies: control_copies.max(1),
            },
            TxReceivers {
                control: control_rx,
                repair: repair_rx,
                new_data: new_data_rx,
                path_control: path_control_rx,
                high_priority_streak: 0,
            },
        )
    }

    pub(crate) async fn send(
        &self,
        priority: TxPriority,
        outbound: Outbound,
    ) -> Result<(), mpsc::error::SendError<Outbound>> {
        match priority {
            TxPriority::Control => {
                let copies = if outbound.message.is_idempotent_control() {
                    self.control_copies
                } else {
                    1
                };
                for _ in 0..copies {
                    self.control.send(outbound.clone()).await?;
                }
                Ok(())
            }
            TxPriority::Repair => self.repair.send(outbound).await,
            TxPriority::NewData => self.new_data.send(outbound).await,
        }
    }

    pub(crate) async fn send_to(
        &self,
        destination: SocketAddr,
        outbound: Outbound,
    ) -> Result<(), mpsc::error::SendError<(SocketAddr, Outbound)>> {
        self.path_control.send((destination, outbound)).await
    }
}

#[derive(Debug)]
pub(crate) enum SessionEvent {
    Open {
        flow_id: FlowId,
        target: String,
        symbol_size: u16,
        up_k: u16,
        down_k: u16,
    },
    OpenOk {
        flow_id: FlowId,
    },
    OpenErr {
        flow_id: FlowId,
        code: u16,
        message: String,
    },
    FlowClosed {
        flow_id: FlowId,
    },
}

pub(crate) enum RegistryCommand {
    Register {
        flow_id: FlowId,
        symbol_size: u16,
        inbound: mpsc::Sender<OwnedMessage>,
        ready: oneshot::Sender<()>,
    },
    Remove {
        flow_id: FlowId,
    },
}

#[derive(Clone)]
pub(crate) struct FlowConfig {
    pub(crate) symbol_size: u16,
    pub(crate) outbound_profile: FecProfile,
    pub(crate) inbound_k_max: u16,
    pub(crate) repair: RepairConfig,
    pub(crate) reorder_window: u32,
    pub(crate) encoder_cache_blocks: usize,
}

enum WriterCommand {
    Data(Vec<u8>),
    Finish,
}

enum WriterEvent {
    Written(usize),
    Finished,
    Failed,
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn tcp_writer(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut commands: mpsc::Receiver<WriterCommand>,
    events: mpsc::Sender<WriterEvent>,
) {
    while let Some(command) = commands.recv().await {
        match command {
            WriterCommand::Data(data) => {
                let write_failed = !matches!(
                    tokio::time::timeout(TCP_WRITE_TIMEOUT, writer.write_all(&data)).await,
                    Ok(Ok(()))
                );
                if write_failed {
                    let _ = events.send(WriterEvent::Failed).await;
                    return;
                }
                if events.send(WriterEvent::Written(data.len())).await.is_err() {
                    return;
                }
            }
            WriterCommand::Finish => {
                let result = tokio::time::timeout(TCP_WRITE_TIMEOUT, writer.shutdown()).await;
                let event = if matches!(result, Ok(Ok(()))) {
                    WriterEvent::Finished
                } else {
                    WriterEvent::Failed
                };
                let _ = events.send(event).await;
                return;
            }
        }
    }
}

pub(crate) struct FlowStart {
    start: oneshot::Sender<()>,
}

impl FlowStart {
    pub(crate) fn start(self) {
        let _ = self.start.send(());
    }
}

pub(crate) fn spawn_flow_paused(
    flow_id: FlowId,
    tcp: TcpStream,
    config: FlowConfig,
    tx: TxHandle,
    registry: mpsc::Sender<RegistryCommand>,
) -> (mpsc::Sender<OwnedMessage>, FlowStart) {
    let (inbound_tx, mut inbound_rx) = mpsc::channel(FLOW_CHANNEL_CAPACITY);
    let (flow_tx, flow_rx) = mpsc::channel(FLOW_CHANNEL_CAPACITY);
    let (reset_ack_tx, reset_ack_rx) = watch::channel(0u64);
    let reset_tx = tx.clone();
    tokio::spawn(async move {
        let mut acknowledgements = 0u64;
        while let Some(message) = inbound_rx.recv().await {
            match message {
                OwnedMessage::ResetAck => {
                    acknowledgements = acknowledgements.wrapping_add(1);
                    let _ = reset_ack_tx.send(acknowledgements);
                }
                OwnedMessage::ResetFlow { .. } => {
                    let _ = reset_tx
                        .send(
                            TxPriority::Control,
                            Outbound {
                                flow_id,
                                message: OwnedMessage::ResetAck,
                            },
                        )
                        .await;
                    acknowledgements = acknowledgements.wrapping_add(1);
                    let _ = reset_ack_tx.send(acknowledgements);
                    if flow_tx.send(message).await.is_err() {
                        return;
                    }
                }
                message => {
                    if flow_tx.send(message).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    let (start_tx, start_rx) = oneshot::channel();
    tokio::spawn(async move {
        if start_rx.await.is_err() {
            return;
        }
        tracing::info!(flow_id, "TCP flow started");
        run_flow(flow_id, tcp, config, tx.clone(), flow_rx, reset_ack_rx).await;
        tracing::info!(flow_id, "TCP flow ended");
        let _ = registry.send(RegistryCommand::Remove { flow_id }).await;
    });
    (inbound_tx, FlowStart { start: start_tx })
}

async fn run_flow(
    flow_id: FlowId,
    tcp: TcpStream,
    config: FlowConfig,
    tx: TxHandle,
    mut inbound: mpsc::Receiver<OwnedMessage>,
    mut reset_acks: watch::Receiver<u64>,
) {
    let (mut reader, writer) = tcp.into_split();
    let (writer_tx, writer_rx) = mpsc::channel(WRITER_CHANNEL_CAPACITY);
    let (writer_event_tx, mut writer_events) = mpsc::channel(WRITER_CHANNEL_CAPACITY);
    let _writer_guard = AbortOnDrop(tokio::spawn(tcp_writer(writer, writer_rx, writer_event_tx)));

    let mut sender = BlockSender::new(
        config.outbound_profile.clone(),
        config.symbol_size,
        config.encoder_cache_blocks,
    );
    let mut receiver = BlockReceiver::new(
        config.symbol_size,
        config.repair.clone(),
        config.reorder_window,
        config.inbound_k_max,
    );
    let mut tick = tokio::time::interval(FLOW_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut granted_credit_total = INITIAL_CREDIT_BYTES;
    let mut last_credit_sent = Instant::now();

    let _ = tx
        .send(
            TxPriority::Control,
            Outbound {
                flow_id,
                message: OwnedMessage::WindowUpdate {
                    credit_bytes: INITIAL_CREDIT_BYTES,
                },
            },
        )
        .await;

    let max_profile_block = usize::from(config.outbound_profile.k_max)
        .saturating_mul(usize::from(config.symbol_size))
        .max(1);
    let max_block_bytes = max_profile_block.min(MAX_BLOCK_BYTES);
    let mut read_buf = vec![0u8; max_block_bytes.min(8192)];
    let mut block_buf = BytesMut::with_capacity(max_block_bytes);
    let block_timeout = Duration::from_millis(config.outbound_profile.timeout_ms);
    let mut block_deadline: Option<tokio::time::Instant> = None;
    let mut send_credit = 0u64;
    let mut last_credit_total = 0u32;
    let mut sent_bytes = 0u64;
    let mut formed_blocks = 0u32;
    let mut local_eof = false;
    let mut local_fin_acked = false;
    let mut last_fin_sent: Option<Instant> = None;
    let mut remote_fin: Option<(u32, u64)> = None;
    let mut written_bytes = 0u64;
    let mut writer_finishing = false;
    let mut writer_finished = false;
    let mut fin_ack_since: Option<Instant> = None;

    loop {
        if local_eof
            && local_fin_acked
            && remote_fin.is_some()
            && fin_ack_since.is_some_and(|sent| sent.elapsed() >= FIN_ACK_LINGER)
        {
            break;
        }

        let block_remaining = max_block_bytes.saturating_sub(block_buf.len());
        let read_limit = usize::try_from(send_credit)
            .unwrap_or(usize::MAX)
            .min(read_buf.len())
            .min(block_remaining);

        tokio::select! {
            biased;

            message = inbound.recv() => {
                let Some(message) = message else {
                    break;
                };
                let keep_running = handle_inbound(
                    flow_id,
                    message,
                    &mut sender,
                    &mut receiver,
                    &writer_tx,
                    &tx,
                    &mut reset_acks,
                    &mut send_credit,
                    &mut last_credit_total,
                    &mut local_fin_acked,
                    &mut remote_fin,
                    writer_finished,
                    &mut fin_ack_since,
                ).await;
                if !keep_running {
                    break;
                }
            }

            Some(event) = writer_events.recv() => {
                match event {
                    WriterEvent::Written(bytes) => {
                        written_bytes = written_bytes.saturating_add(bytes as u64);
                        granted_credit_total = granted_credit_total
                            .wrapping_add(u32::try_from(bytes).unwrap_or(u32::MAX));
                        if tx.send(
                            TxPriority::Control,
                            Outbound {
                                flow_id,
                                message: OwnedMessage::WindowUpdate {
                                    credit_bytes: granted_credit_total,
                                },
                            },
                        ).await.is_err() {
                            break;
                        }
                        last_credit_sent = Instant::now();
                    }
                    WriterEvent::Finished => {
                        writer_finished = true;
                        if remote_fin.is_some() {
                            if tx.send(
                                TxPriority::Control,
                                Outbound { flow_id, message: OwnedMessage::FinAck },
                            ).await.is_err() {
                                break;
                            }
                            fin_ack_since.get_or_insert_with(Instant::now);
                        }
                    }
                    WriterEvent::Failed => {
                        send_reset_reliably(&tx, &mut reset_acks, flow_id, 4).await;
                        break;
                    }
                }
            }

            read = reader.read(&mut read_buf[..read_limit]), if !local_eof && read_limit > 0 => {
                match read {
                    Ok(0) => {
                        local_eof = true;
                        if !flush_block(
                            flow_id,
                            &mut block_buf,
                            &mut sender,
                            &tx,
                            &mut reset_acks,
                            &mut formed_blocks,
                        ).await {
                            return;
                        }
                        block_deadline = None;
                    }
                    Ok(bytes) => {
                        send_credit -= bytes as u64;
                        sent_bytes = sent_bytes.saturating_add(bytes as u64);
                        block_buf.extend_from_slice(&read_buf[..bytes]);
                        block_deadline.get_or_insert_with(|| {
                            tokio::time::Instant::now() + block_timeout
                        });
                        if block_buf.len() == max_block_bytes {
                            if !flush_block(
                                flow_id,
                                &mut block_buf,
                                &mut sender,
                                &tx,
                                &mut reset_acks,
                                &mut formed_blocks,
                            ).await {
                                return;
                            }
                            block_deadline = None;
                        }
                    }
                    Err(_) => {
                        send_reset_reliably(&tx, &mut reset_acks, flow_id, 3).await;
                        break;
                    }
                }
            }

            _ = tick.tick() => {
                if last_credit_sent.elapsed() >= CREDIT_RETRANSMIT {
                    if tx.send(
                        TxPriority::Control,
                        Outbound {
                            flow_id,
                            message: OwnedMessage::WindowUpdate {
                                credit_bytes: granted_credit_total,
                            },
                        },
                    ).await.is_err() {
                        break;
                    }
                    last_credit_sent = Instant::now();
                }
                if block_deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
                    && !flush_block(
                        flow_id,
                        &mut block_buf,
                        &mut sender,
                        &tx,
                        &mut reset_acks,
                        &mut formed_blocks,
                    ).await
                {
                    return;
                }
                if block_buf.is_empty() {
                    block_deadline = None;
                }
                for event in receiver.check_timers(Instant::now()) {
                    if !handle_receiver_event(flow_id, event, &tx, &mut reset_acks).await {
                        return;
                    }
                }
                if !drain_receiver(
                    flow_id,
                    &mut receiver,
                    &writer_tx,
                    &tx,
                    &mut reset_acks,
                ).await {
                    return;
                }
            }

            else => break,
        }

        if local_eof
            && !local_fin_acked
            && last_fin_sent.is_none_or(|sent| sent.elapsed() >= FIN_RETRY)
        {
            if tx
                .send(
                    TxPriority::Control,
                    Outbound {
                        flow_id,
                        message: OwnedMessage::Fin {
                            final_block_seq: formed_blocks,
                            final_byte_count: sent_bytes,
                        },
                    },
                )
                .await
                .is_err()
            {
                break;
            }
            last_fin_sent = Some(Instant::now());
        }

        if let Some((_final_block, final_bytes)) = remote_fin
            && written_bytes == final_bytes
            && !writer_finishing
        {
            writer_finishing = true;
            if writer_tx.send(WriterCommand::Finish).await.is_err() {
                break;
            }
        }
    }
}

async fn flush_block(
    flow_id: FlowId,
    block_buf: &mut BytesMut,
    sender: &mut BlockSender,
    tx: &TxHandle,
    reset_acks: &mut watch::Receiver<u64>,
    formed_blocks: &mut u32,
) -> bool {
    if block_buf.is_empty() {
        return true;
    }
    if *formed_blocks >= MAX_BLOCKS_PER_FLOW {
        send_reset_reliably(tx, reset_acks, flow_id, 6).await;
        return false;
    }

    let payload = block_buf.split();
    let symbols = sender.form_block(&payload);
    *formed_blocks = formed_blocks.saturating_add(1);
    for symbol in symbols {
        let priority = if symbol.esi < symbol.k_eff {
            TxPriority::NewData
        } else {
            TxPriority::Repair
        };
        if send_symbol(tx, priority, flow_id, symbol).await.is_err() {
            return false;
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
async fn handle_inbound(
    flow_id: FlowId,
    message: OwnedMessage,
    sender: &mut BlockSender,
    receiver: &mut BlockReceiver,
    writer: &mpsc::Sender<WriterCommand>,
    tx: &TxHandle,
    reset_acks: &mut watch::Receiver<u64>,
    send_credit: &mut u64,
    last_credit_total: &mut u32,
    local_fin_acked: &mut bool,
    remote_fin: &mut Option<(u32, u64)>,
    writer_finished: bool,
    fin_ack_since: &mut Option<Instant>,
) -> bool {
    match message {
        OwnedMessage::Data {
            block_seq,
            esi,
            k_eff,
            block_payload_len,
            symbol,
        } => {
            let Ok(esi) = u16::try_from(esi) else {
                send_reset_reliably(tx, reset_acks, flow_id, 2).await;
                return false;
            };
            let events = receiver.receive_symbol(Symbol {
                block_seq,
                esi,
                k_eff,
                block_payload_len,
                data: symbol,
            });
            for event in events {
                if !handle_receiver_event(flow_id, event, tx, reset_acks).await {
                    return false;
                }
            }
            drain_receiver(flow_id, receiver, writer, tx, reset_acks).await
        }
        OwnedMessage::RepairReq { block_seq, count } => {
            for symbol in sender.handle_repair_req(block_seq, count) {
                if send_symbol(tx, TxPriority::Repair, flow_id, symbol)
                    .await
                    .is_err()
                {
                    return false;
                }
            }
            true
        }
        OwnedMessage::BlockAck { block_seq } => {
            sender.handle_block_ack(block_seq);
            true
        }
        OwnedMessage::WindowUpdate { credit_bytes } => {
            apply_cumulative_credit(send_credit, last_credit_total, credit_bytes);
            true
        }
        OwnedMessage::Fin {
            final_block_seq,
            final_byte_count,
        } => {
            for event in receiver.expect_block_count(final_block_seq) {
                if !handle_receiver_event(flow_id, event, tx, reset_acks).await {
                    return false;
                }
            }
            *remote_fin = Some((final_block_seq, final_byte_count));
            if writer_finished {
                if tx
                    .send(
                        TxPriority::Control,
                        Outbound {
                            flow_id,
                            message: OwnedMessage::FinAck,
                        },
                    )
                    .await
                    .is_err()
                {
                    return false;
                }
                fin_ack_since.get_or_insert_with(Instant::now);
            }
            true
        }
        OwnedMessage::FinAck => {
            *local_fin_acked = true;
            true
        }
        OwnedMessage::ResetFlow { .. } => false,
        OwnedMessage::ResetAck => true,
        OwnedMessage::Ping { timestamp } => tx
            .send(
                TxPriority::Control,
                Outbound {
                    flow_id,
                    message: OwnedMessage::Pong { timestamp },
                },
            )
            .await
            .is_ok(),
        OwnedMessage::Pong { .. }
        | OwnedMessage::Rekey
        | OwnedMessage::PathChallenge { .. }
        | OwnedMessage::PathResponse { .. }
        | OwnedMessage::Open { .. }
        | OwnedMessage::OpenOk
        | OwnedMessage::OpenErr { .. } => true,
    }
}

fn apply_cumulative_credit(send_credit: &mut u64, last_total: &mut u32, new_total: u32) {
    let delta = new_total.wrapping_sub(*last_total);
    if delta == 0 || delta >= (1u32 << 31) {
        return;
    }
    *last_total = new_total;
    *send_credit = send_credit
        .saturating_add(u64::from(delta))
        .min(u64::from(INITIAL_CREDIT_BYTES));
}

async fn handle_receiver_event(
    flow_id: FlowId,
    event: ReceiverEvent,
    tx: &TxHandle,
    reset_acks: &mut watch::Receiver<u64>,
) -> bool {
    let message = match event {
        ReceiverEvent::Decoded { .. } => return true,
        ReceiverEvent::RepairNeeded { block_seq, count } => {
            OwnedMessage::RepairReq { block_seq, count }
        }
        ReceiverEvent::Ack { block_seq } => OwnedMessage::BlockAck { block_seq },
        ReceiverEvent::Failed { .. } => {
            send_reset_reliably(tx, reset_acks, flow_id, 2).await;
            return false;
        }
    };
    tx.send(TxPriority::Control, Outbound { flow_id, message })
        .await
        .is_ok()
}

async fn drain_receiver(
    flow_id: FlowId,
    receiver: &mut BlockReceiver,
    writer: &mpsc::Sender<WriterCommand>,
    tx: &TxHandle,
    reset_acks: &mut watch::Receiver<u64>,
) -> bool {
    for (_, payload) in receiver.drain_deliverable() {
        if writer.send(WriterCommand::Data(payload)).await.is_err() {
            send_reset_reliably(tx, reset_acks, flow_id, 4).await;
            return false;
        }
    }
    true
}

async fn send_reset_reliably(
    tx: &TxHandle,
    reset_acks: &mut watch::Receiver<u64>,
    flow_id: FlowId,
    reason: u16,
) {
    let initial_ack = *reset_acks.borrow();
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
            return;
        }
        if attempt + 1 < RESET_RETRIES
            && tokio::time::timeout(FIN_RETRY, reset_acks.changed())
                .await
                .is_ok()
            && *reset_acks.borrow() != initial_ack
        {
            return;
        }
    }
}

async fn send_symbol(
    tx: &TxHandle,
    priority: TxPriority,
    flow_id: FlowId,
    symbol: Symbol,
) -> Result<(), mpsc::error::SendError<Outbound>> {
    tx.send(
        priority,
        Outbound {
            flow_id,
            message: OwnedMessage::Data {
                block_seq: symbol.block_seq,
                esi: u32::from(symbol.esi),
                k_eff: symbol.k_eff,
                block_payload_len: symbol.block_payload_len,
                symbol: symbol.data,
            },
        },
    )
    .await
}

pub(crate) fn flow_config(
    symbol_size: u16,
    outbound_profile: FecProfile,
    inbound_k_max: u16,
    repair: RepairConfig,
    reorder_window: u32,
    max_send_mbps: u32,
) -> FlowConfig {
    let block_bytes = u64::from(outbound_profile.k_max) * u64::from(symbol_size);
    let bytes_per_second = u64::from(max_send_mbps) * 1_000_000 / 8;
    let full_block_rate = bytes_per_second.div_ceil(block_bytes.max(1));
    let timeout_rate = 1_000u64.div_ceil(outbound_profile.timeout_ms.max(1));
    let blocks_per_second = full_block_rate.max(timeout_rate);
    let encoder_cache_blocks = blocks_per_second
        .saturating_mul(repair.deadline_ms)
        .div_ceil(1_000)
        .saturating_add(16)
        .clamp(64, 4096) as usize;
    FlowConfig {
        symbol_size,
        outbound_profile,
        inbound_k_max,
        repair,
        reorder_window,
        encoder_cache_blocks,
    }
}

pub(crate) async fn register_flow(
    registry: &mpsc::Sender<RegistryCommand>,
    flow_id: FlowId,
    symbol_size: u16,
    inbound: mpsc::Sender<OwnedMessage>,
) -> io::Result<()> {
    let (ready_tx, ready_rx) = oneshot::channel();
    registry
        .send(RegistryCommand::Register {
            flow_id,
            symbol_size,
            inbound,
            ready: ready_tx,
        })
        .await
        .map_err(|_| io::Error::other("wire-v2 receive task stopped"))?;
    ready_rx
        .await
        .map_err(|_| io::Error::other("wire-v2 receive registry stopped"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cumulative_credit_uses_configured_copies() {
        let (tx, mut receivers) = TxHandle::new(3);
        tx.send(
            TxPriority::Control,
            Outbound {
                flow_id: 1,
                message: OwnedMessage::WindowUpdate { credit_bytes: 1024 },
            },
        )
        .await
        .unwrap();

        for _ in 0..3 {
            assert!(receivers.control.recv().await.is_some());
        }
        assert!(matches!(
            receivers.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn idempotent_control_messages_use_configured_copies() {
        let (tx, mut receivers) = TxHandle::new(3);
        tx.send(
            TxPriority::Control,
            Outbound {
                flow_id: 1,
                message: OwnedMessage::FinAck,
            },
        )
        .await
        .unwrap();

        for _ in 0..3 {
            assert!(receivers.control.recv().await.is_some());
        }
        assert!(matches!(
            receivers.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn cumulative_credit_recovers_loss_and_ignores_duplicates() {
        let mut available = 0u64;
        let mut last_total = 0u32;

        apply_cumulative_credit(&mut available, &mut last_total, INITIAL_CREDIT_BYTES);
        assert_eq!(available, u64::from(INITIAL_CREDIT_BYTES));

        available -= 4096;
        // A duplicate cumulative update grants no additional bytes.
        apply_cumulative_credit(&mut available, &mut last_total, INITIAL_CREDIT_BYTES);
        assert_eq!(available, u64::from(INITIAL_CREDIT_BYTES - 4096));

        // If an intermediate update was lost, the next total includes it.
        apply_cumulative_credit(&mut available, &mut last_total, INITIAL_CREDIT_BYTES + 8192);
        assert_eq!(available, u64::from(INITIAL_CREDIT_BYTES));

        // An older reordered serial value is ignored.
        let accepted_total = last_total;
        apply_cumulative_credit(&mut available, &mut last_total, INITIAL_CREDIT_BYTES);
        assert_eq!(last_total, accepted_total);
        assert_eq!(available, u64::from(INITIAL_CREDIT_BYTES));
    }
}
