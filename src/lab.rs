//! Two real UDP/WebRTC peers on loopback, with trusted in-process SDP exchange.
//! This is a laboratory, deliberately not a public signaling service.
pub mod multi;
use crate::{
    media::{self, Clip, Schedule, ScheduledPacket},
    reliable::{Receiver, Sender},
    wire::{Frame, Kind, MAX_DATA},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};
use str0m::bwe::{Bitrate, BweKind};
use str0m::format::Codec;
use str0m::media::{Direction, MediaKind, Mid};
use str0m::net::{Protocol, Receive};
use str0m::rtp::RtpWrite;
use str0m::{Candidate, Event, Input, Output, Rtc};

pub const DEFAULT_WINDOW_BLOCKS: usize = 4096;
pub const DEFAULT_ACK_EVERY: usize = 32;

#[derive(Clone, Debug)]
pub struct Options {
    pub bytes: usize,
    pub block_size: usize,
    pub window_blocks: usize,
    pub ack_every: usize,
    /// Drop every Nth encrypted RTP packet in each direction; 0 disables.
    pub drop_every: u64,
    /// Corrupt the authentication tag of every Nth RTP packet; 0 disables.
    pub tamper_every: u64,
    pub timeout: Duration,
    pub one_way_delay: Duration,
    /// Configured bottleneck rate in each direction; 0 disables shaping.
    pub link_mbps: f64,
    /// Maximum queued data expressed as milliseconds at the configured rate.
    pub queue_ms: u64,
    /// Optional fixed retransmission timeout; None enables adaptive RTO.
    pub fixed_rto: Option<Duration>,
    /// If set, send unchanged video for this long without any SFERA messages.
    pub cover_only: Option<Duration>,
    /// Enable str0m's native TWCC bandwidth estimator and seed its initial estimate.
    pub bwe_initial_mbps: Option<f64>,
    /// Enable the lab's arrival-feedback congestion controller with this initial rate.
    pub arrival_initial_mbps: Option<f64>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            bytes: 256 * 1024,
            block_size: MAX_DATA,
            window_blocks: DEFAULT_WINDOW_BLOCKS,
            ack_every: DEFAULT_ACK_EVERY,
            drop_every: 0,
            tamper_every: 0,
            timeout: Duration::from_secs(30),
            one_way_delay: Duration::ZERO,
            link_mbps: 0.0,
            queue_ms: 100,
            fixed_rto: None,
            cover_only: None,
            bwe_initial_mbps: None,
            arrival_initial_mbps: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub mode: &'static str,
    pub transport: &'static str,
    pub integrity_verified: bool,
    pub source_encoded_mbps: f64,
    pub source_data_slot_capacity_mbps: f64,
    pub reliable_window_blocks: usize,
    pub one_way_delay_ms: f64,
    /// Configured loopback lab ceiling per direction; None means unshaped.
    pub configured_link_mbps_each_direction: Option<f64>,
    /// Application goodput divided by the configured lab ceiling.
    pub goodput_to_configured_link_pct_each_direction: Option<f64>,
    pub link_queue_overflow_packets: u64,
    pub link_queue_overflow_bytes: u64,
    pub configured_block_size: usize,
    pub configured_ack_every: usize,
    pub final_rto_ms: [f64; 2],
    pub fixed_rto_ms: Option<f64>,
    pub connected_ms: f64,
    pub transfer_ms: f64,
    pub received_bytes_each_direction: usize,
    pub goodput_mbps_each_direction: f64,
    pub left_received_sha256: String,
    pub right_received_sha256: String,
    /// UDP payload serialized through the configured channel, including injected RTP loss.
    pub udp_payload_bytes_sent: u64,
    pub rtp_packets_attempted: u64,
    pub rtp_packets_dropped: u64,
    pub rtp_packets_tampered: u64,
    pub rtp_packets_received: u64,
    pub reliable_retransmissions: u64,
    pub fast_retransmissions: u64,
    pub datagram_rtt_samples: usize,
    pub datagram_rtt_p50_ms: Option<f64>,
    pub datagram_rtt_p95_ms: Option<f64>,
}

struct App {
    tx: Sender,
    rx: Receiver,
    total_bytes: usize,
    seed: usize,
    block_size: usize,
    ack_every: usize,
    offset: usize,
    received_bytes: usize,
    sent_hash: Sha256,
    received_hash: Sha256,
    ack: Option<Frame>,
    feedback: Option<Frame>,
    datagrams: VecDeque<(Duration, Frame)>,
    slot_number: u64,
    next_probe: Duration,
    probe_seq: u32,
    probe_generation_enabled: bool,
    probe_measurement_start: Duration,
    probe_records: std::collections::BTreeMap<u32, ProbeRecord>,
    probe_latest_reply: Option<u32>,
    rtts: Vec<f64>,
    last_reply: u32,
    last_ack_sent: Duration,
    blocks_since_ack: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ProbeSummary {
    pub generated: usize,
    pub enqueued: usize,
    pub placed: usize,
    pub replied: usize,
    pub within_deadline: usize,
    pub late: usize,
    pub missed: usize,
    pub placement_expired: usize,
    pub queue_full: usize,
    pub out_of_order: usize,
    pub duplicate_replies: usize,
}

impl ProbeSummary {
    pub fn merge(mut self, other: Self) -> Self {
        self.generated += other.generated;
        self.enqueued += other.enqueued;
        self.placed += other.placed;
        self.replied += other.replied;
        self.within_deadline += other.within_deadline;
        self.late += other.late;
        self.missed += other.missed;
        self.placement_expired += other.placement_expired;
        self.queue_full += other.queue_full;
        self.out_of_order += other.out_of_order;
        self.duplicate_replies += other.duplicate_replies;
        self
    }
}

struct ProbeRecord {
    generated_at: Duration,
    enqueued: bool,
    placed_at: Option<Duration>,
    replied_at: Option<Duration>,
    out_of_order: bool,
    duplicate_replies: usize,
}

/// Per-direction lab channel scheduler. The configured queue budget is
/// converted to bytes at the link rate and applies through serialization finish.
/// Propagation retains packet memory separately and does not consume link queue
/// capacity. This models a bounded loopback bottleneck, not an Internet path.
#[doc(hidden)]
pub struct LinkScheduler {
    rate_mbps: f64,
    queue_ms: u64,
    max_queue_bytes: Option<usize>,
    queued_bytes: usize,
    pending_bytes: usize,
    next_free: Option<Instant>,
    packets: VecDeque<ChannelPacket>,
    propagating: VecDeque<ChannelPacket>,
    pub transmitted_bytes: u64,
    pub rtp_drops: u64,
    pub overflow_packets: u64,
    pub overflow_bytes: u64,
}

struct ChannelPacket {
    finish_at: Instant,
    deliver_at: Instant,
    address: SocketAddr,
    bytes: Vec<u8>,
    drop_rtp: bool,
}

const MAX_PENDING_PACKETS: usize = 8192;
const MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;
const MAX_NATIVE_PENDING_PACKETS: usize = 32;
const MAX_NATIVE_PENDING_BYTES: usize = 64 * 1024;
const CONTROL_VP8_PREFIX_LEN: usize = 17;

/// Conservative UDP-payload accounting for the RTP header, negotiated extensions,
/// and SRTP tag. The scheduler uses the same bound for bulk and control packets.
pub(crate) fn wire_cost(payload_len: usize) -> usize {
    payload_len.saturating_add(64)
}

impl LinkScheduler {
    pub fn new(rate_mbps: f64, queue_ms: u64) -> Result<Self> {
        ensure!(
            rate_mbps.is_finite() && (rate_mbps == 0.0 || (0.01..=10_000.0).contains(&rate_mbps)),
            "link rate must be 0 or 0.01..=10000 Mbps"
        );
        ensure!(
            (1..=10_000).contains(&queue_ms),
            "queue-ms must be 1..=10000"
        );
        let max_queue_bytes = (rate_mbps > 0.0).then(|| {
            // Allow at least one ordinary lab UDP datagram even at very low rates.
            (rate_mbps * 125.0 * queue_ms as f64).ceil().max(2048.0) as usize
        });
        Ok(Self {
            rate_mbps,
            queue_ms,
            max_queue_bytes,
            queued_bytes: 0,
            pending_bytes: 0,
            next_free: None,
            packets: VecDeque::new(),
            propagating: VecDeque::new(),
            transmitted_bytes: 0,
            rtp_drops: 0,
            overflow_packets: 0,
            overflow_bytes: 0,
        })
    }

    /// Enqueue a datagram. Loss injection is applied only after serialization.
    pub fn enqueue(
        &mut self,
        now: Instant,
        address: SocketAddr,
        bytes: Vec<u8>,
        delay: Duration,
        drop_rtp: bool,
    ) -> Option<(SocketAddr, Vec<u8>)> {
        self.advance_serialization(now);
        if self.rate_mbps == 0.0 && delay.is_zero() && !drop_rtp {
            self.transmitted_bytes += bytes.len() as u64;
            return Some((address, bytes));
        }
        if self.pending_bytes.saturating_add(bytes.len()) > MAX_PENDING_BYTES
            || self.packets.len() + self.propagating.len() >= MAX_PENDING_PACKETS
        {
            self.overflow_packets += 1;
            self.overflow_bytes += bytes.len() as u64;
            return None;
        }
        if let Some(limit) = self.max_queue_bytes
            && self.queued_bytes.saturating_add(bytes.len()) > limit
        {
            self.overflow_packets += 1;
            self.overflow_bytes += bytes.len() as u64;
            return None;
        }
        let start = now.max(self.next_free.unwrap_or(now));
        let serialization = if self.rate_mbps > 0.0 {
            Duration::from_secs_f64(bytes.len() as f64 * 8.0 / (self.rate_mbps * 1_000_000.0))
        } else {
            Duration::ZERO
        };
        if start.saturating_duration_since(now) > Duration::from_millis(self.queue_ms) {
            self.overflow_packets += 1;
            self.overflow_bytes += bytes.len() as u64;
            return None;
        }
        self.queued_bytes += bytes.len();
        self.pending_bytes += bytes.len();
        let finish = start + serialization;
        self.next_free = Some(finish);
        self.packets.push_back(ChannelPacket {
            finish_at: finish,
            deliver_at: finish + delay,
            address,
            bytes,
            drop_rtp,
        });
        None
    }

    fn advance_serialization(&mut self, now: Instant) {
        while self.packets.front().is_some_and(|p| p.finish_at <= now) {
            let packet = self.packets.pop_front().expect("front checked");
            self.queued_bytes -= packet.bytes.len();
            self.transmitted_bytes += packet.bytes.len() as u64;
            if packet.drop_rtp {
                self.rtp_drops += 1;
                self.pending_bytes -= packet.bytes.len();
            } else {
                self.propagating.push_back(packet);
            }
        }
    }

    pub fn pop_due(&mut self, now: Instant) -> Option<(SocketAddr, Vec<u8>)> {
        self.advance_serialization(now);
        if self.propagating.front().is_none_or(|p| p.deliver_at > now) {
            return None;
        }
        let packet = self.propagating.pop_front().expect("front checked");
        self.pending_bytes -= packet.bytes.len();
        Some((packet.address, packet.bytes))
    }

    pub fn next_delivery(&self) -> Option<Instant> {
        self.packets
            .front()
            .map(|p| p.finish_at)
            .into_iter()
            .chain(self.propagating.front().map(|p| p.deliver_at))
            .min()
    }
}

impl App {
    fn new(
        bytes: usize,
        seed: usize,
        block_size: usize,
        window_blocks: usize,
        ack_every: usize,
        fixed_rto: Option<Duration>,
    ) -> Result<Self> {
        let mut tx = Sender::with_window(1, window_blocks)?;
        if let Some(rto) = fixed_rto {
            tx.set_fixed_rto(rto)?;
        }
        Ok(Self {
            tx,
            rx: Receiver::with_window(1, window_blocks)?,
            total_bytes: bytes,
            seed,
            block_size,
            ack_every,
            offset: 0,
            received_bytes: 0,
            sent_hash: Sha256::new(),
            received_hash: Sha256::new(),
            ack: None,
            feedback: None,
            datagrams: VecDeque::new(),
            slot_number: 0,
            next_probe: Duration::ZERO,
            probe_seq: 0,
            probe_generation_enabled: true,
            probe_measurement_start: Duration::ZERO,
            probe_records: std::collections::BTreeMap::new(),
            probe_latest_reply: None,
            rtts: Vec::new(),
            last_reply: 0,
            last_ack_sent: Duration::ZERO,
            blocks_since_ack: 0,
        })
    }
    fn fill(&mut self) -> Result<()> {
        // Generate at most the next block: pre-filling 32 blocks per dispatch
        // multiplied synchronous hashing/allocation work across 20+ sessions.
        if !self.tx.can_enqueue() || self.offset >= self.total_bytes {
            return Ok(());
        }
        let start = self.offset;
        let end = (start + self.block_size).min(self.total_bytes);
        // Different deterministic payloads make reversed/misrouted flows visible.
        let block: Vec<u8> = (start..end)
            .map(|i| ((i.wrapping_mul(31) ^ (i >> 8) ^ self.seed) & 255) as u8)
            .collect();
        self.tx.enqueue(&block)?;
        // Retransmissions reuse pending blocks and never pass through this path.
        self.sent_hash.update(&block);
        self.offset = end;
        Ok(())
    }
    fn tick_probes(&mut self, now: Duration) {
        const PROBE_INTERVAL: Duration = Duration::from_millis(100);
        const MAX_PROBE_RECORDS: usize = 4096;
        if !self.probe_generation_enabled || now < self.next_probe {
            return;
        }
        if self.probe_records.len() >= MAX_PROBE_RECORDS {
            // Lab runs are capped at 300 s (at most 3001 regular probes). If a
            // future caller exceeds the ledger bound, stop creating untracked
            // IDs rather than make the measurement denominator incomplete.
            self.probe_generation_enabled = false;
            return;
        }
        self.next_probe = now + PROBE_INTERVAL;
        self.probe_seq = self.probe_seq.saturating_add(1);
        let sequence = self.probe_seq;
        let enqueued = self.datagrams.len() < 8;
        self.probe_records.insert(
            sequence,
            ProbeRecord {
                generated_at: now,
                enqueued,
                placed_at: None,
                replied_at: None,
                out_of_order: false,
                duplicate_replies: 0,
            },
        );
        if enqueued {
            self.datagrams.push_back((
                now,
                Frame {
                    kind: Kind::Datagram,
                    flow: 2,
                    sequence,
                    payload: (now.as_nanos() as u64).to_be_bytes().to_vec(),
                },
            ));
        }
    }
    fn stop_probes(&mut self) {
        self.probe_generation_enabled = false;
    }
    fn set_probe_measurement_start(&mut self, now: Duration) {
        self.probe_measurement_start = now;
    }
    fn probe_summary(&self, cutoff: Duration, deadline: Duration) -> ProbeSummary {
        self.probe_summary_since(self.probe_measurement_start, cutoff, deadline)
    }
    fn probe_summary_since(
        &self,
        since: Duration,
        cutoff: Duration,
        deadline: Duration,
    ) -> ProbeSummary {
        let records = self
            .probe_records
            .values()
            .filter(|record| record.generated_at >= since && record.generated_at <= cutoff);
        let mut summary = ProbeSummary {
            generated: 0,
            enqueued: 0,
            placed: 0,
            replied: 0,
            within_deadline: 0,
            late: 0,
            missed: 0,
            placement_expired: 0,
            queue_full: 0,
            out_of_order: 0,
            duplicate_replies: 0,
        };
        for record in records {
            summary.generated += 1;
            summary.enqueued += usize::from(record.enqueued);
            summary.queue_full += usize::from(!record.enqueued);
            summary.placed += usize::from(record.placed_at.is_some());
            summary.placement_expired += usize::from(
                record.enqueued
                    && record
                        .placed_at
                        .is_none_or(|placed| placed > record.generated_at + deadline),
            );
            summary.out_of_order += usize::from(record.out_of_order);
            summary.duplicate_replies += record.duplicate_replies;
            if let Some(replied_at) = record.replied_at {
                summary.replied += 1;
                if replied_at <= record.generated_at + deadline {
                    summary.within_deadline += 1;
                } else {
                    summary.late += 1;
                }
            }
        }
        summary.missed = summary.generated - summary.within_deadline;
        summary
    }
    fn expire_datagrams(&mut self, now: Duration) {
        while self
            .datagrams
            .front()
            .is_some_and(|(t, _)| now.saturating_sub(*t) > Duration::from_millis(100))
        {
            if let Some((_, frame)) = self.datagrams.pop_front()
                && frame.flow == 2
                && let Some(record) = self.probe_records.get_mut(&frame.sequence)
            {
                // Generated requests remain in the denominator after expiry.
                record.enqueued = true;
            }
        }
    }
    fn take_control(&mut self, now: Duration) -> Option<(Frame, Duration)> {
        self.expire_datagrams(now);
        if let Some((enqueued_at, frame)) = self.datagrams.pop_front() {
            self.slot_number = self.slot_number.saturating_add(1);
            return Some((frame, enqueued_at));
        }
        if let Some(frame) = self.feedback.take() {
            self.slot_number = self.slot_number.saturating_add(1);
            return Some((frame, now));
        }
        if (self.blocks_since_ack >= self.ack_every
            || now.saturating_sub(self.last_ack_sent) >= Duration::from_millis(25))
            && let Some(ack) = self.ack.take()
        {
            self.slot_number = self.slot_number.saturating_add(1);
            return Some((ack, now));
        }
        None
    }
    fn mark_control_placed(&mut self, frame: &Frame, now: Duration) {
        if frame.kind == Kind::Datagram
            && frame.flow == 2
            && let Some(record) = self.probe_records.get_mut(&frame.sequence)
        {
            record.placed_at = Some(now);
        }
        if frame.kind == Kind::Ack {
            self.blocks_since_ack = 0;
            self.last_ack_sent = now;
        }
    }
    fn receive(&mut self, frame: Frame, now: Duration) -> Result<()> {
        match frame.kind {
            Kind::Ack => self.tx.acknowledge_at(&frame, now)?,
            Kind::Data => {
                let (ack, data) = self.rx.accept(frame)?;
                // Keep only the newest cumulative + selective receipt state.
                self.ack = Some(ack);
                self.blocks_since_ack = self.blocks_since_ack.saturating_add(1);
                for block in data {
                    ensure!(
                        self.received_bytes + block.len() <= self.total_bytes,
                        "received too many bytes"
                    );
                    self.received_bytes += block.len();
                    self.received_hash.update(&block);
                }
            }
            Kind::Datagram => {
                ensure!(frame.payload.len() == 8, "invalid probe");
                if frame.flow == 2 {
                    if self.datagrams.len() < 8 {
                        self.datagrams.push_back((now, Frame { flow: 3, ..frame }));
                    }
                } else if frame.flow == 3 {
                    let sent =
                        Duration::from_nanos(u64::from_be_bytes(frame.payload[..].try_into()?));
                    ensure!(sent <= now, "probe timestamp in future");
                    if let Some(record) = self.probe_records.get_mut(&frame.sequence) {
                        ensure!(
                            record.enqueued && record.generated_at == sent,
                            "probe reply does not match a generated request"
                        );
                        if record.replied_at.is_some() {
                            record.duplicate_replies += 1;
                        } else {
                            record.out_of_order = self
                                .probe_latest_reply
                                .is_some_and(|latest| frame.sequence < latest);
                            self.probe_latest_reply = Some(
                                self.probe_latest_reply
                                    .map_or(frame.sequence, |latest| latest.max(frame.sequence)),
                            );
                            self.last_reply = self.last_reply.max(frame.sequence);
                            record.replied_at = Some(now);
                            self.rtts.push((now - sent).as_secs_f64() * 1000.0);
                        }
                    }
                } else {
                    anyhow::bail!("unknown datagram flow");
                }
            }
        }
        Ok(())
    }
    fn pick(&mut self, space: usize, now: Duration) -> Result<Option<Frame>> {
        self.fill()?;
        self.tick_probes(now);
        self.slot_number += 1;
        // Expire datagrams before placement; never retransmit old real-time data.
        self.expire_datagrams(now);
        if space >= 8
            && self.slot_number.is_multiple_of(4)
            && let Some((_, frame)) = self.datagrams.pop_front()
        {
            if frame.flow == 2
                && let Some(record) = self.probe_records.get_mut(&frame.sequence)
            {
                record.placed_at = Some(now);
            }
            return Ok(Some(frame));
        }
        if self
            .feedback
            .as_ref()
            .is_some_and(|frame| space >= frame.payload.len())
            && let Some(frame) = self.feedback.take()
        {
            return Ok(Some(frame));
        }
        if self
            .ack
            .as_ref()
            .is_some_and(|ack| space >= ack.payload.len())
            && (self.blocks_since_ack >= self.ack_every
                || space < self.block_size
                || now.saturating_sub(self.last_ack_sent) >= Duration::from_millis(25))
            && let Some(ack) = self.ack.take()
        {
            self.blocks_since_ack = 0;
            self.last_ack_sent = now;
            return Ok(Some(ack));
        }
        if space >= self.block_size
            && let Some(frame) = self.tx.next_frame(now)?
        {
            return Ok(Some(frame));
        }
        if space >= 8
            && let Some((_, frame)) = self.datagrams.pop_front()
        {
            if frame.flow == 2
                && let Some(record) = self.probe_records.get_mut(&frame.sequence)
            {
                record.placed_at = Some(now);
            }
            return Ok(Some(frame));
        }
        Ok(None)
    }
    fn done(&self) -> bool {
        self.offset == self.total_bytes && self.tx.idle() && self.received_bytes == self.total_bytes
    }
    fn sent_digest(&self) -> String {
        format!("{:x}", self.sent_hash.clone().finalize())
    }
    fn received_digest(&self) -> String {
        format!("{:x}", self.received_hash.clone().finalize())
    }
}

struct Peer {
    rtc: Rtc,
    socket: UdpSocket,
    deadline: Instant,
    app: App,
    rtp_seq: u64,
    rtp_attempted: u64,
    rtp_tampered: u64,
    rtp_received: u64,
    link: LinkScheduler,
    outbox: Option<VecDeque<(SocketAddr, Vec<u8>, bool)>>,
    outbox_bytes: usize,
    pub(crate) bwe_mbps: f64,
    pub(crate) bwe_updates: u64,
    pub(crate) bwe_can_probe: bool,
    arrival_controller: Option<crate::congestion::Controller>,
    arrival_rx_bytes: u64,
    arrival_rx_packets: u64,
    arrival_reported_packets: u64,
    arrival_feedback_dirty: bool,
    arrival_last_seq: u16,
    arrival_last_at: Duration,
    arrival_serial: u32,
    arrival_report_due: Duration,
    current_rx_datagram: Option<(u16, u32, usize)>,
    control_prefix: Option<[u8; CONTROL_VP8_PREFIX_LEN]>,
    pending_control: Option<(Frame, Duration)>,
    media_ssrc: Option<u32>,
    native_pending: VecDeque<(u16, usize)>,
    native_pending_bytes: usize,
}
impl Peer {
    fn new(start: Instant, bytes: usize, seed: usize, options: &Options) -> Result<Self> {
        ensure!(
            options.bwe_initial_mbps.is_none() || options.arrival_initial_mbps.is_none(),
            "native BWE and arrival-feedback BWE are mutually exclusive"
        );
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        if let Some(mbps) = options.arrival_initial_mbps {
            ensure!(
                mbps.is_finite() && (0.01..=10_000.0).contains(&mbps),
                "arrival initial bitrate must be 0.01..=10000 Mbps"
            );
        }
        let initial_bwe = options
            .bwe_initial_mbps
            .map(|mbps| Bitrate::from(mbps * 1_000_000.0));
        let rtc = Rtc::builder()
            .clear_codecs()
            .enable_vp8(true)
            .set_rtp_mode(true)
            .enable_bwe(initial_bwe)
            .build(start);
        let mut peer = Self {
            rtc,
            socket,
            deadline: start,
            app: App::new(
                bytes,
                seed,
                options.block_size,
                options.window_blocks,
                options.ack_every,
                options.fixed_rto,
            )?,
            rtp_seq: 1000,
            rtp_attempted: 0,
            rtp_tampered: 0,
            rtp_received: 0,
            link: LinkScheduler::new(options.link_mbps, options.queue_ms)?,
            outbox: None,
            outbox_bytes: 0,
            bwe_mbps: options
                .arrival_initial_mbps
                .or(options.bwe_initial_mbps)
                .unwrap_or(0.0),
            bwe_updates: 0,
            bwe_can_probe: false,
            arrival_controller: options
                .arrival_initial_mbps
                .map(|mbps| crate::congestion::Controller::new(mbps, mbps))
                .transpose()?,
            arrival_rx_bytes: 0,
            arrival_rx_packets: 0,
            arrival_reported_packets: 0,
            arrival_feedback_dirty: false,
            arrival_last_seq: 0,
            arrival_last_at: Duration::ZERO,
            arrival_serial: 0,
            arrival_report_due: Duration::from_millis(20),
            current_rx_datagram: None,
            control_prefix: None,
            pending_control: None,
            media_ssrc: None,
            native_pending: VecDeque::new(),
            native_pending_bytes: 0,
        };
        if let Some(mbps) = options.bwe_initial_mbps {
            peer.set_desired_bitrate(mbps, start, options)?;
        }
        peer.drain(start, start, options)?;
        peer.rtc
            .add_local_candidate(Candidate::host(peer.socket.local_addr()?, "udp")?);
        peer.drain(start, start, options)?;
        Ok(peer)
    }
    /// Every mutation is immediately drained, as required by str0m.
    fn drain(&mut self, now: Instant, start: Instant, options: &Options) -> Result<()> {
        loop {
            match self.rtc.poll_output()? {
                Output::Timeout(t) => {
                    self.deadline = t;
                    break;
                }
                Output::Transmit(t) => {
                    ensure!(
                        t.destination.ip().is_loopback(),
                        "lab must stay on loopback"
                    );
                    let mut bytes = t.contents.to_vec();
                    let rtp = is_rtp(&bytes);
                    if rtp && bytes.len() >= 12 && bytes[0] & 0x20 == 0 {
                        let seq = u16::from_be_bytes([bytes[2], bytes[3]]);
                        let ssrc = u32::from_be_bytes(bytes[8..12].try_into()?);
                        if self.media_ssrc == Some(ssrc)
                            && let Some(controller) = &mut self.arrival_controller
                        {
                            controller.on_sent(
                                seq,
                                now.saturating_duration_since(start),
                                bytes.len(),
                            );
                        }
                        if self.media_ssrc == Some(ssrc)
                            && let Some(index) = self
                                .native_pending
                                .iter()
                                .position(|(pending_seq, _)| *pending_seq == seq)
                        {
                            let (_, payload_bytes) = self.native_pending.remove(index).unwrap();
                            self.native_pending_bytes -= payload_bytes;
                        }
                    }
                    let mut drop_rtp = false;
                    if rtp {
                        self.rtp_attempted += 1;
                        if options.drop_every > 0
                            && self.rtp_attempted.is_multiple_of(options.drop_every)
                        {
                            drop_rtp = true;
                        }
                        if options.tamper_every > 0
                            && self.rtp_attempted.is_multiple_of(options.tamper_every)
                        {
                            *bytes.last_mut().expect("RTP is not empty") ^= 0x80;
                            self.rtp_tampered += 1;
                        }
                    }
                    if let Some(outbox) = &mut self.outbox {
                        ensure!(
                            outbox.len() < 256
                                && self.outbox_bytes.saturating_add(bytes.len()) <= 256 * 1024,
                            "peer UDP outbox limit reached"
                        );
                        self.outbox_bytes += bytes.len();
                        outbox.push_back((t.destination, bytes, drop_rtp));
                    } else if let Some((address, bytes)) = self.link.enqueue(
                        now,
                        t.destination,
                        bytes,
                        options.one_way_delay,
                        drop_rtp,
                    ) {
                        self.send_link_packet(address, &bytes)?;
                    }
                }
                Output::Event(Event::RtpPacket(packet)) => {
                    self.rtp_received += 1;
                    let elapsed = now.saturating_duration_since(start);
                    let frame = if options.cover_only.is_none() {
                        media::extract(&packet.payload)
                    } else {
                        None
                    };
                    let is_arrival_feedback = frame
                        .as_ref()
                        .is_some_and(|frame| frame.kind == Kind::Datagram && frame.flow == 4);
                    if self.arrival_controller.is_some() && *packet.header.ssrc != 0 {
                        let exact_udp_bytes = self
                            .current_rx_datagram
                            .take()
                            .filter(|(seq, ssrc, _)| {
                                *seq == packet.header.sequence_number
                                    && *ssrc == *packet.header.ssrc
                            })
                            .map(|(_, _, size)| size);
                        if let Some(size) = exact_udp_bytes {
                            self.arrival_rx_bytes =
                                self.arrival_rx_bytes.saturating_add(size as u64);
                            self.arrival_rx_packets = self.arrival_rx_packets.saturating_add(1);
                            let advance = packet
                                .header
                                .sequence_number
                                .wrapping_sub(self.arrival_last_seq);
                            if self.arrival_rx_packets == 1 || (advance > 0 && advance < 32768) {
                                self.arrival_last_seq = packet.header.sequence_number;
                                self.arrival_last_at = elapsed;
                            }
                            self.arrival_feedback_dirty |= !is_arrival_feedback;
                        }
                    }
                    if let Some(frame) = frame {
                        if frame.kind == Kind::Datagram && frame.flow == 4 {
                            if let Some(controller) = &mut self.arrival_controller {
                                let report = crate::congestion::ArrivalReport::decode(
                                    frame.sequence,
                                    &frame.payload,
                                )?;
                                if controller.on_feedback(&report, elapsed)? {
                                    self.bwe_mbps = controller.rate_mbps(elapsed);
                                    self.bwe_updates = self.bwe_updates.saturating_add(1);
                                }
                            }
                        } else {
                            self.app.receive(frame, elapsed)?;
                        }
                    }
                }
                Output::Event(Event::EgressBitrateEstimate(BweKind::Twcc {
                    estimate,
                    can_probe,
                })) => {
                    self.bwe_mbps = estimate.as_f64() / 1_000_000.0;
                    self.bwe_can_probe = can_probe;
                    self.bwe_updates += 1;
                }
                Output::Event(_) => {}
            }
        }
        Ok(())
    }
    fn pump(&mut self, start: Instant, options: &Options) -> Result<()> {
        let elapsed = Instant::now().saturating_duration_since(start);
        let application_backlogged = self.has_bulk_pending();
        if let Some(controller) = &mut self.arrival_controller {
            controller.set_application_backlogged(application_backlogged);
            self.bwe_mbps = controller.rate_mbps(elapsed);
        }
        if options.cover_only.is_none() && self.rtc.is_connected() {
            self.app.tick_probes(elapsed);
        }
        for _ in 0..256 {
            let Some((address, bytes)) = self.link.pop_due(Instant::now()) else {
                break;
            };
            self.send_link_packet(address, &bytes)?;
        }
        let mut buffer = [0u8; 2048];
        // Bound work per peer so one direction cannot starve the other.
        for _ in 0..256 {
            match self.socket.recv_from(&mut buffer) {
                Ok((size, source)) => {
                    let now = Instant::now();
                    let packet = Receive::new(
                        Protocol::Udp,
                        source,
                        self.socket.local_addr()?,
                        &buffer[..size],
                    )?;
                    self.current_rx_datagram =
                        if is_rtp(&buffer[..size]) && size >= 12 && buffer[0] & 0x20 == 0 {
                            Some((
                                u16::from_be_bytes([buffer[2], buffer[3]]),
                                u32::from_be_bytes(buffer[8..12].try_into()?),
                                size,
                            ))
                        } else {
                            None
                        };
                    self.rtc.handle_input(Input::Receive(now, packet))?;
                    self.drain(now, start, options)?;
                    self.current_rx_datagram = None;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        let now = Instant::now();
        if self.deadline <= now {
            self.rtc.handle_input(Input::Timeout(now))?;
            self.drain(now, start, options)?;
        }
        Ok(())
    }
    fn send_link_packet(&mut self, address: SocketAddr, bytes: &[u8]) -> Result<()> {
        let size = self.socket.send_to(bytes, address)?;
        ensure!(size == bytes.len(), "partial UDP send");
        Ok(())
    }
    fn send_packet(
        &mut self,
        packet: &ScheduledPacket,
        mid: Mid,
        start: Instant,
        options: &Options,
    ) -> Result<()> {
        let pt = self
            .rtc
            .codec_config()
            .params()
            .iter()
            .find(|p| p.spec().codec == Codec::Vp8)
            .context("VP8 not negotiated")?
            .pt();
        {
            let mut payload = packet.payload.clone();
            if self.control_prefix.is_none() && payload.len() >= CONTROL_VP8_PREFIX_LEN {
                self.seed_control_prefix(&payload)?;
            }
            let now = Instant::now();
            let elapsed = now.saturating_duration_since(start);
            self.prepare_arrival_feedback(elapsed, false);
            // Do not attempt mapping unless the complete wire header fits.
            if options.cover_only.is_none() && payload.len() >= 33 {
                let message = if self.arrival_controller.is_some() && self.outbox.is_some() {
                    // Compact controls have their own bounded share of the same
                    // pacer. Do not smuggle them into bulk slots to bypass it.
                    self.app.fill()?;
                    if media::capacity(&payload) >= self.app.block_size {
                        self.app.tx.next_frame(elapsed)?
                    } else {
                        None
                    }
                } else {
                    self.app.pick(media::capacity(&payload), elapsed)?
                };
                if let Some(message) = message {
                    media::embed(&mut payload, &message)?;
                }
            }
            let payload_bytes = payload.len();
            ensure!(
                payload_bytes <= MAX_NATIVE_PENDING_BYTES
                    && self.native_pending_bytes.saturating_add(payload_bytes)
                        <= MAX_NATIVE_PENDING_BYTES,
                "native RTP queue byte limit reached"
            );
            let ssrc = {
                let mut direct = self.rtc.direct_api();
                let stream = direct
                    .stream_tx_by_mid(mid, None)
                    .context("missing video stream")?;
                let ssrc = *stream.ssrc();
                stream.write_rtp(
                    RtpWrite::new(pt, self.rtp_seq.into(), packet.timestamp, now, payload)
                        .marker(packet.marker),
                );
                ssrc
            };
            self.media_ssrc = Some(ssrc);
            self.native_pending
                .push_back((self.rtp_seq as u16, payload_bytes));
            self.native_pending_bytes += payload_bytes;
            self.rtp_seq += 1;
            // Native RTP NACK is deliberately off: SFERA retries occupy future
            // media slots. A second retransmission engine would add extra RTP.
            self.drain(now, start, options)?;
        }
        Ok(())
    }

    pub(crate) fn can_admit_packet(&self, _mid: Mid) -> bool {
        self.native_pending.len() < MAX_NATIVE_PENDING_PACKETS
            && self.native_pending_bytes < MAX_NATIVE_PENDING_BYTES
    }

    pub(crate) fn seed_control_prefix(&mut self, payload: &[u8]) -> Result<()> {
        if self.control_prefix.is_some() {
            return Ok(());
        }
        ensure!(
            payload.len() >= CONTROL_VP8_PREFIX_LEN && (payload[0] == 0 || payload[0] == 0x10),
            "control packet requires a prefix from a mapped VP8 carrier"
        );
        if self.control_prefix.is_none() {
            self.control_prefix = Some(payload[..CONTROL_VP8_PREFIX_LEN].try_into()?);
        }
        Ok(())
    }

    pub(crate) fn has_bulk_pending(&self) -> bool {
        self.app.offset < self.app.total_bytes || !self.app.tx.idle()
    }

    /// Return the conservative paced cost without consuming the selected frame.
    /// Callers must charge this against the same byte-credit budget as media.
    pub(crate) fn control_packet_cost(&mut self, now: Duration) -> Option<usize> {
        if self.arrival_controller.is_none()
            || self.control_prefix.is_none()
            || !self.rtc.is_connected()
            || self.native_pending.len() >= MAX_NATIVE_PENDING_PACKETS
        {
            return None;
        }
        if self
            .pending_control
            .as_ref()
            .is_some_and(|(frame, enqueued_at)| {
                frame.kind == Kind::Datagram
                    && matches!(frame.flow, 2 | 3)
                    && now.saturating_sub(*enqueued_at) > Duration::from_millis(100)
            })
        {
            // Don't let a token-starved request/echo turn into a late probe.
            self.pending_control = None;
        }
        if self.pending_control.is_none() {
            self.app.tick_probes(now);
            self.prepare_arrival_feedback(now, true);
            self.pending_control = self.app.take_control(now);
        }
        self.pending_control.as_ref().map(|(frame, _)| {
            wire_cost(CONTROL_VP8_PREFIX_LEN + crate::wire::HEADER + frame.payload.len())
        })
    }

    /// Send one short control frame as a small encrypted RTP packet. The caller
    /// allocates the same pacing token that it uses for a regular media packet.
    pub(crate) fn send_control_packet(
        &mut self,
        mid: Mid,
        start: Instant,
        options: &Options,
    ) -> Result<Option<usize>> {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(start);
        let Some((frame, _enqueued_at)) = self.pending_control.take() else {
            return Ok(None);
        };
        let cost = wire_cost(CONTROL_VP8_PREFIX_LEN + crate::wire::HEADER + frame.payload.len());
        self.app.mark_control_placed(&frame, elapsed);
        let prefix = self.control_prefix.expect("cost checked control prefix");
        let mut payload =
            Vec::with_capacity(CONTROL_VP8_PREFIX_LEN + crate::wire::HEADER + frame.payload.len());
        payload.extend_from_slice(&prefix);
        payload.resize(
            CONTROL_VP8_PREFIX_LEN + crate::wire::HEADER + frame.payload.len(),
            0,
        );
        frame.encode(&mut payload[CONTROL_VP8_PREFIX_LEN..])?;
        ensure!(
            payload.len() <= MAX_NATIVE_PENDING_BYTES
                && self.native_pending_bytes.saturating_add(payload.len())
                    <= MAX_NATIVE_PENDING_BYTES,
            "native RTP queue byte limit reached"
        );
        let pt = self
            .rtc
            .codec_config()
            .params()
            .iter()
            .find(|p| p.spec().codec == Codec::Vp8)
            .context("VP8 not negotiated")?
            .pt();
        let timestamp = (elapsed.as_secs_f64() * 90_000.0) as u32;
        let ssrc = {
            let mut direct = self.rtc.direct_api();
            let stream = direct
                .stream_tx_by_mid(mid, None)
                .context("missing video stream")?;
            let ssrc = *stream.ssrc();
            stream.write_rtp(
                RtpWrite::new(pt, self.rtp_seq.into(), timestamp, now, payload).marker(true),
            );
            ssrc
        };
        self.media_ssrc = Some(ssrc);
        let payload_bytes = CONTROL_VP8_PREFIX_LEN + crate::wire::HEADER + frame.payload.len();
        self.native_pending
            .push_back((self.rtp_seq as u16, payload_bytes));
        self.native_pending_bytes += payload_bytes;
        self.rtp_seq += 1;
        self.drain(now, start, options)?;
        Ok(Some(cost))
    }

    fn prepare_arrival_feedback(&mut self, now: Duration, control_path: bool) {
        if self.arrival_controller.is_none()
            || !self.arrival_feedback_dirty
            || self.arrival_rx_packets <= self.arrival_reported_packets
            || now < self.arrival_report_due
        {
            return;
        }
        self.arrival_serial = self.arrival_serial.wrapping_add(1).max(1);
        let report = crate::congestion::ArrivalReport {
            serial: self.arrival_serial,
            received_bytes: self.arrival_rx_bytes,
            received_packets: self.arrival_rx_packets,
            last_sequence: self.arrival_last_seq,
            arrival_ns: self.arrival_last_at.as_nanos().min(u64::MAX as u128) as u64,
        };
        self.app.feedback = Some(Frame {
            kind: Kind::Datagram,
            flow: 4,
            sequence: self.arrival_serial,
            payload: report.encode(),
        });
        self.arrival_reported_packets = self.arrival_rx_packets;
        self.arrival_feedback_dirty = false;
        let feedback_ms = if self.bwe_mbps <= 1.0 {
            if control_path { 25 } else { 100 }
        } else if control_path {
            10
        } else {
            20
        };
        self.arrival_report_due = now + Duration::from_millis(feedback_ms);
    }

    pub(crate) fn set_desired_bitrate(
        &mut self,
        mbps: f64,
        start: Instant,
        options: &Options,
    ) -> Result<()> {
        ensure!(
            mbps.is_finite() && (0.01..=10_000.0).contains(&mbps),
            "desired BWE bitrate must be 0.01..=10000 Mbps"
        );
        ensure!(
            options.bwe_initial_mbps.is_some(),
            "native BWE must be enabled before setting a desired bitrate"
        );
        self.rtc
            .bwe()
            .set_bitrate(Bitrate::ZERO, Bitrate::from(mbps * 1_000_000.0));
        self.drain(Instant::now(), start, options)
    }

    pub(crate) fn set_arrival_desired(&mut self, mbps: f64) -> Result<()> {
        let controller = self
            .arrival_controller
            .as_mut()
            .context("arrival-feedback controller is not enabled")?;
        controller.set_desired(mbps)?;
        self.bwe_mbps = controller.rate_mbps(Duration::ZERO);
        Ok(())
    }
}

fn is_rtp(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && bytes[0] >> 6 == 2 && !(192..=223).contains(&bytes[1])
}

pub fn run(clip: &Clip, options: &Options) -> Result<Report> {
    ensure!(
        (1..=256).contains(&options.ack_every),
        "ack-every must be 1..256"
    );
    ensure!(
        options.one_way_delay <= Duration::from_secs(1),
        "one-way delay must be <= 1000 ms"
    );
    ensure!(
        options.link_mbps.is_finite()
            && (options.link_mbps == 0.0 || (0.01..=10_000.0).contains(&options.link_mbps)),
        "link-mbps must be 0 or 0.01..=10000 Mbps"
    );
    ensure!(
        (1..=10_000).contains(&options.queue_ms),
        "queue-ms must be 1..=10000"
    );
    ensure!(
        options.bytes > 0 && options.bytes <= 64 * 1024 * 1024,
        "bytes must be 1..=67108864"
    );
    ensure!(
        options.block_size > 0 && options.block_size <= MAX_DATA,
        "block-size must be 1..={MAX_DATA}"
    );
    if let Some(rto) = options.fixed_rto {
        ensure!(
            rto >= Duration::from_millis(10) && rto <= Duration::from_millis(5000),
            "fixed-rto-ms must be 10..=5000"
        );
    }
    if let Some(mbps) = options.bwe_initial_mbps {
        ensure!(
            mbps.is_finite() && (0.1..=1000.0).contains(&mbps),
            "bwe-initial-mbps must be 0.1..=1000"
        );
    }
    ensure!(
        options.timeout > Duration::ZERO && options.timeout <= Duration::from_secs(300),
        "timeout must be 0..=300 seconds"
    );
    if let Some(duration) = options.cover_only {
        ensure!(
            duration > Duration::ZERO && duration < options.timeout,
            "cover duration must be below timeout"
        );
    }
    let start = Instant::now();
    let bytes = if options.cover_only.is_some() {
        0
    } else {
        options.bytes
    };
    let mut left = Peer::new(start, bytes, 17, options)?;
    let mut right = Peer::new(start, bytes, 93, options)?;
    // SDP, including DTLS fingerprints, crosses a trusted in-process boundary.
    // Never reuse this setup as unauthenticated network signaling.
    let mut changes = left.rtc.sdp_api();
    let mid = changes.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (offer, pending) = changes.apply().context("empty SDP offer")?;
    left.drain(start, start, options)?;
    let answer = right.rtc.sdp_api().accept_offer(offer)?;
    right.drain(start, start, options)?;
    left.rtc.sdp_api().accept_answer(pending, answer)?;
    left.drain(start, start, options)?;
    let mut connected = None;
    let mut schedule = Schedule::new(clip);
    loop {
        left.pump(start, options)?;
        right.pump(start, options)?;
        let now = Instant::now();
        ensure!(
            now.duration_since(start) < options.timeout,
            "lab timed out: connected={}, received={}/{}, RTP received={}/{}, retransmits={}/{}",
            connected.is_some(),
            left.app.received_bytes,
            right.app.received_bytes,
            left.rtp_received,
            right.rtp_received,
            left.app.tx.retransmits,
            right.app.tx.retransmits
        );
        if left.rtc.is_connected() && right.rtc.is_connected() {
            let began = *connected.get_or_insert(now);
            if let Some(duration) = options.cover_only {
                if now.duration_since(began) >= duration {
                    break;
                }
            } else if left.app.done() && right.app.done() {
                break;
            }
            for _ in 0..64 {
                let Some(packet) = schedule.pop_due(Instant::now().duration_since(began)) else {
                    break;
                };
                left.send_packet(&packet, mid, start, options)?;
                right.send_packet(&packet, mid, start, options)?;
                left.pump(start, options)?;
                right.pump(start, options)?;
            }
        }
        let now = Instant::now();
        let mut wake = (now + Duration::from_millis(1))
            .min(left.deadline)
            .min(right.deadline);
        if let Some(began) = connected {
            wake = wake.min(began + schedule.next_at());
        }
        if let Some(at) = left.link.next_delivery() {
            wake = wake.min(at);
        }
        if let Some(at) = right.link.next_delivery() {
            wake = wake.min(at);
        }
        if wake > now {
            thread::sleep(wake - now);
        }
    }
    let end = Instant::now();
    let left_received_sha256 = left.app.received_digest();
    let right_received_sha256 = right.app.received_digest();
    ensure!(
        left_received_sha256 == right.app.sent_digest()
            && right_received_sha256 == left.app.sent_digest(),
        "integrity check failed"
    );
    let connected = connected.context("never connected")?;
    let duration = end.duration_since(connected).as_secs_f64();
    let mut rtts = left.app.rtts;
    rtts.extend(right.app.rtts);
    rtts.sort_by(f64::total_cmp);
    let percentile = |q: f64| -> Option<f64> {
        if rtts.is_empty() {
            None
        } else {
            Some(rtts[((rtts.len() - 1) as f64 * q).round() as usize])
        }
    };
    let goodput_mbps = bytes as f64 * 8.0 / duration / 1_000_000.0;
    let configured_link_mbps = (options.link_mbps > 0.0).then_some(options.link_mbps);
    Ok(Report {
        mode: if options.cover_only.is_some() {
            "cover-only"
        } else {
            "media-substitution"
        },
        transport: "WebRTC VP8 RTP / DTLS-SRTP / loopback UDP",
        integrity_verified: options.cover_only.is_none(),
        source_encoded_mbps: clip.encoded_mbps(),
        source_data_slot_capacity_mbps: clip.data_slot_capacity_mbps_for(options.block_size),
        reliable_window_blocks: options.window_blocks,
        one_way_delay_ms: options.one_way_delay.as_secs_f64() * 1000.0,
        configured_link_mbps_each_direction: configured_link_mbps,
        goodput_to_configured_link_pct_each_direction: configured_link_mbps
            .map(|capacity| goodput_mbps / capacity * 100.0),
        link_queue_overflow_packets: left.link.overflow_packets + right.link.overflow_packets,
        link_queue_overflow_bytes: left.link.overflow_bytes + right.link.overflow_bytes,
        configured_block_size: options.block_size,
        configured_ack_every: options.ack_every,
        final_rto_ms: [
            left.app.tx.current_rto().as_secs_f64() * 1000.0,
            right.app.tx.current_rto().as_secs_f64() * 1000.0,
        ],
        fixed_rto_ms: options.fixed_rto.map(|rto| rto.as_secs_f64() * 1000.0),
        connected_ms: connected.duration_since(start).as_secs_f64() * 1000.0,
        transfer_ms: duration * 1000.0,
        received_bytes_each_direction: bytes,
        goodput_mbps_each_direction: goodput_mbps,
        left_received_sha256,
        right_received_sha256,
        udp_payload_bytes_sent: left.link.transmitted_bytes + right.link.transmitted_bytes,
        rtp_packets_attempted: left.rtp_attempted + right.rtp_attempted,
        rtp_packets_dropped: left.link.rtp_drops + right.link.rtp_drops,
        rtp_packets_tampered: left.rtp_tampered + right.rtp_tampered,
        rtp_packets_received: left.rtp_received + right.rtp_received,
        reliable_retransmissions: left.app.tx.retransmits + right.app.tx.retransmits,
        fast_retransmissions: left.app.tx.fast_retransmits + right.app.tx.fast_retransmits,
        datagram_rtt_samples: rtts.len(),
        datagram_rtt_p50_ms: percentile(0.5),
        datagram_rtt_p95_ms: percentile(0.95),
    })
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;
    #[test]
    fn large_window_ack_waits_for_a_sufficient_carrier_slot() -> Result<()> {
        let mut app = App::new(4096, 17, 1068, 2048, 32, None)?;
        app.receive(
            Frame {
                kind: Kind::Data,
                flow: 1,
                sequence: 1,
                payload: vec![1],
            },
            Duration::ZERO,
        )?;
        let first = app.pick(64, Duration::from_millis(30))?;
        assert!(first.is_none_or(|f| f.kind != Kind::Ack));
        assert_eq!(app.ack.as_ref().unwrap().payload.len(), 256);
        let ack = app.pick(256, Duration::from_millis(31))?.unwrap();
        assert_eq!(ack.kind, Kind::Ack);
        assert_eq!(ack.payload.len(), 256);
        Ok(())
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    #[test]
    fn probes_generate_on_tick_without_media_picks_and_stop_cleanly() -> Result<()> {
        let mut app = App::new(0, 17, 1068, 4096, 32, None)?;
        app.tick_probes(Duration::ZERO);
        app.tick_probes(Duration::from_millis(50));
        app.tick_probes(Duration::from_millis(100));
        app.stop_probes();
        app.tick_probes(Duration::from_secs(1));

        assert_eq!(app.probe_seq, 2);
        let summary = app.probe_summary_since(
            Duration::from_millis(100),
            Duration::from_millis(500),
            Duration::from_millis(100),
        );
        assert_eq!(summary.generated, 1);
        assert_eq!(summary.enqueued, 1);
        assert_eq!(summary.placed, 0);
        assert_eq!(summary.placement_expired, 1);
        assert_eq!(summary.missed, 1);
        Ok(())
    }

    #[test]
    fn probe_summary_counts_unique_out_of_order_and_late_echoes() -> Result<()> {
        let mut app = App::new(0, 17, 1068, 4096, 32, None)?;
        app.tick_probes(Duration::ZERO);
        let first = app.pick(900, Duration::ZERO)?.unwrap();
        app.tick_probes(Duration::from_millis(100));
        let second = app.pick(900, Duration::from_millis(100))?.unwrap();
        assert_eq!(first.flow, 2);
        assert_eq!(second.flow, 2);

        app.receive(
            Frame {
                kind: Kind::Datagram,
                flow: 3,
                sequence: second.sequence,
                payload: second.payload.clone(),
            },
            Duration::from_millis(150),
        )?;
        app.receive(
            Frame {
                kind: Kind::Datagram,
                flow: 3,
                sequence: first.sequence,
                payload: first.payload.clone(),
            },
            Duration::from_millis(160),
        )?;
        // A duplicate does not inflate the unique-reply count.
        app.receive(
            Frame {
                kind: Kind::Datagram,
                flow: 3,
                sequence: first.sequence,
                payload: first.payload.clone(),
            },
            Duration::from_millis(170),
        )?;

        let summary = app.probe_summary_since(
            Duration::ZERO,
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        assert_eq!(summary.generated, 2);
        assert_eq!(summary.enqueued, 2);
        assert_eq!(summary.placed, 2);
        assert_eq!(summary.replied, 2);
        assert_eq!(summary.within_deadline, 1);
        assert_eq!(summary.late, 1);
        assert_eq!(summary.missed, 1);
        assert_eq!(summary.out_of_order, 1);
        assert_eq!(summary.duplicate_replies, 1);
        assert_eq!(app.rtts.len(), 2);
        Ok(())
    }

    #[test]
    fn probe_reply_timestamp_must_match_its_generated_record() -> Result<()> {
        let mut app = App::new(0, 17, 1068, 4096, 32, None)?;
        app.tick_probes(Duration::ZERO);
        let request = app.pick(900, Duration::ZERO)?.unwrap();
        let result = app.receive(
            Frame {
                kind: Kind::Datagram,
                flow: 3,
                sequence: request.sequence,
                payload: 1u64.to_be_bytes().to_vec(),
            },
            Duration::from_millis(10),
        );
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn short_control_selection_prioritizes_probe_then_feedback_then_ack() -> Result<()> {
        let mut app = App::new(0, 17, 1068, 4096, 32, None)?;
        app.feedback = Some(Frame {
            kind: Kind::Datagram,
            flow: 4,
            sequence: 1,
            payload: vec![9; 32],
        });
        app.ack = Some(Frame {
            kind: Kind::Ack,
            flow: 1,
            sequence: 1,
            payload: vec![0; 4],
        });
        app.tick_probes(Duration::ZERO);

        let (probe, _) = app.take_control(Duration::ZERO).unwrap();
        assert_eq!(probe.flow, 2);
        assert!(app.probe_records[&probe.sequence].placed_at.is_none());
        app.mark_control_placed(&probe, Duration::from_millis(1));
        assert_eq!(
            app.probe_records[&probe.sequence].placed_at,
            Some(Duration::from_millis(1))
        );

        let (feedback, _) = app.take_control(Duration::from_millis(2)).unwrap();
        assert_eq!(feedback.flow, 4);
        let (ack, _) = app.take_control(Duration::from_millis(25)).unwrap();
        assert_eq!(ack.kind, Kind::Ack);
        assert!(app.take_control(Duration::from_millis(26)).is_none());
        Ok(())
    }

    #[test]
    fn expired_short_probe_is_not_reused() -> Result<()> {
        let mut app = App::new(0, 17, 1068, 4096, 32, None)?;
        app.tick_probes(Duration::ZERO);
        let (probe, _) = app.take_control(Duration::ZERO).unwrap();
        assert_eq!(probe.flow, 2);
        assert!(app.take_control(Duration::from_millis(101)).is_none());
        let summary = app.probe_summary_since(
            Duration::ZERO,
            Duration::from_millis(200),
            Duration::from_millis(100),
        );
        assert_eq!(summary.generated, 1);
        assert_eq!(summary.placed, 0);
        assert_eq!(summary.missed, 1);
        Ok(())
    }
}
