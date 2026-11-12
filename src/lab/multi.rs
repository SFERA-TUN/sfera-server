//! Multi-session loopback experiment with ONE shared bottleneck per direction.
//! The packet pacer changes the prerecorded media timing. This measures queues
//! and transport capacity, not camera realism or censorship resistance.
use super::*;
use crate::fair::FairQueue;

#[derive(Clone, Debug)]
pub struct MultiOptions {
    pub clients: usize,
    pub offered_load: f64,
    pub interactive_last: bool,
    pub greedy_first: bool,
    pub adaptive: bool,
    pub native_cc: bool,
    /// Independent sender startup guess, not derived from the modeled capacity.
    pub initial_mbps: f64,
    pub min_duration: Duration,
    pub capacity_steps: Vec<CapacityStep>,
    pub random_loss_ppm: u32,
    pub loss_seed: u64,
    pub burst_every: u64,
    pub burst_len: u64,
    pub probe_deadline: Duration,
}

impl Default for MultiOptions {
    fn default() -> Self {
        Self {
            clients: 5,
            offered_load: 0.95,
            interactive_last: false,
            greedy_first: false,
            adaptive: true,
            native_cc: false,
            initial_mbps: 5.0,
            min_duration: Duration::ZERO,
            capacity_steps: Vec::new(),
            random_loss_ppm: 0,
            loss_seed: 1,
            burst_every: 0,
            burst_len: 0,
            probe_deadline: Duration::from_millis(100),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CapacityStep {
    pub after: Duration,
    pub mbps: f64,
}

#[derive(Serialize)]
pub struct IntervalReport {
    pub until_ms: f64,
    pub link_mbps: f64,
    pub goodput_mbps_each_direction: [f64; 2],
    pub serialized_mbps_each_direction: [f64; 2],
    pub queue_drops: u64,
    pub sender_budgets_mbps: Vec<f64>,
    pub probe_quality: super::ProbeSummary,
}

#[derive(Serialize)]
pub struct ProbeMiss {
    pub generated_ms_since_ready: f64,
    pub placement_delay_ms: Option<f64>,
    pub reply_rtt_ms: Option<f64>,
}

#[derive(Serialize)]
pub struct ClientReport {
    pub client: usize,
    pub workload: &'static str,
    pub received_bytes_each_direction: usize,
    pub completed_ms: Option<f64>,
    /// All clients use the same bulk observation interval, excluding final probe drain.
    pub goodput_mbps_each_direction: f64,
    /// Throughput during this client's active transfer, excluding other clients' tail.
    pub active_goodput_mbps_each_direction: Option<f64>,
    pub integrity_verified: bool,
    pub retransmissions: u64,
    pub probe_samples: usize,
    pub probe_requests: u32,
    pub probe_replies_within_100ms: usize,
    pub probe_rtt_p50_ms: Option<f64>,
    pub probe_rtt_p95_ms: Option<f64>,
    pub probe_rtt_p99_ms: Option<f64>,
    pub queue_drops: u64,
    pub bwe_updates: u64,
    pub final_bwe_mbps_each_direction: [f64; 2],
    pub probe_quality: super::ProbeSummary,
    pub generation_to_placement_p95_ms: Option<f64>,
    pub placement_to_reply_p95_ms: Option<f64>,
    /// First 16 deadline misses per client, including unplaced/unreplied probes.
    pub probe_miss_samples: Vec<ProbeMiss>,
}

#[derive(Serialize)]
pub struct MultiReport {
    pub experiment: &'static str,
    pub clients: Vec<ClientReport>,
    pub transfer_ms: f64,
    pub shared_link_mbps_each_direction: f64,
    pub offered_load: f64,
    pub greedy_first: bool,
    pub adaptive: bool,
    pub controller: &'static str,
    pub probe_deadline_ms: f64,
    pub baseline_propagation_rtt_ms: f64,
    pub compact_control_packets: bool,
    pub initial_mbps_per_sender: f64,
    pub capacity_steps: Vec<CapacityStep>,
    pub random_loss_ppm: u32,
    pub loss_seed: u64,
    pub intervals: Vec<IntervalReport>,
    pub aggregate_goodput_mbps_each_direction: f64,
    pub jain_fairness_bulk_clients: f64,
    pub queue_budget_bytes_each_direction: usize,
    pub queue_peak_bytes_each_direction: [usize; 2],
    pub queue_wait_max_ms_each_direction: [f64; 2],
    pub queue_dropped_packets: u64,
    pub injected_loss_packets: u64,
    pub serialized_udp_bytes: u64,
    pub event_loop_gap_max_ms: f64,
    pub propagation_peak_bytes_each_direction: [usize; 2],
}

struct InTransit {
    at: Instant,
    client: usize,
    payload: Vec<u8>,
}

struct Hub {
    queue: FairQueue,
    budget: usize,
    rate: f64,
    next_free: Instant,
    transit: VecDeque<InTransit>,
    transit_bytes: usize,
    transit_peak: usize,
    wait_max: Duration,
    serialized: u64,
    injected_loss: u64,
    random_loss_ppm: u32,
    random_state: u64,
    burst_every: u64,
    burst_len: u64,
    rtp_seen: u64,
}

impl Hub {
    fn new(clients: usize, options: &Options, start: Instant) -> Result<Self> {
        let per_client = ((options.link_mbps * 125.0 * options.queue_ms as f64) / clients as f64)
            .ceil()
            .max(2048.0) as usize;
        let budget = per_client * clients;
        Ok(Self {
            queue: FairQueue::new(clients, per_client, budget, 1200)?,
            budget,
            rate: options.link_mbps,
            next_free: start,
            transit: VecDeque::new(),
            transit_bytes: 0,
            transit_peak: 0,
            wait_max: Duration::ZERO,
            serialized: 0,
            injected_loss: 0,
            random_loss_ppm: 0,
            random_state: 1,
            burst_every: 0,
            burst_len: 0,
            rtp_seen: 0,
        })
    }

    fn collect(&mut self, peers: &mut [Peer], direction: usize, start: Instant) -> Result<()> {
        for client in 0..peers.len() / 2 {
            let destination = peers[client * 2 + 1 - direction].socket.local_addr()?;
            let source = &mut peers[client * 2 + direction];
            for (address, bytes, mut drop_rtp) in source.outbox.as_mut().unwrap().drain(..) {
                ensure!(address == destination, "unexpected loopback destination");
                if is_rtp(&bytes) {
                    self.rtp_seen += 1;
                    let mut x = self.random_state;
                    x ^= x >> 12;
                    x ^= x << 25;
                    x ^= x >> 27;
                    self.random_state = x;
                    let draw = x.wrapping_mul(2685821657736338717) % 1_000_000;
                    drop_rtp |= draw < self.random_loss_ppm as u64;
                    drop_rtp |=
                        self.burst_every > 0 && self.rtp_seen % self.burst_every < self.burst_len;
                }
                // The loss flag is local metadata, never transmitted. DRR charges
                // this one extra byte; actual link serialization excludes it.
                let mut wrapped = Vec::with_capacity(bytes.len() + 1);
                wrapped.push(u8::from(drop_rtp));
                wrapped.extend(bytes);
                self.queue.push(client, wrapped, start.elapsed());
            }
            source.outbox_bytes = 0;
        }
        Ok(())
    }

    fn pump(
        &mut self,
        peers: &mut [Peer],
        direction: usize,
        start: Instant,
        delay: Duration,
    ) -> Result<()> {
        let now = Instant::now();
        // Consume completed propagation before admitting more memory.
        while self.transit.front().is_some_and(|p| p.at <= now) {
            let p = self.transit.pop_front().unwrap();
            self.transit_bytes -= p.payload.len();
            let destination = peers[p.client * 2 + 1 - direction].socket.local_addr()?;
            peers[p.client * 2 + direction].send_link_packet(destination, &p.payload)?;
        }
        self.serialize(now, start, delay)
    }

    fn serialize(&mut self, now: Instant, start: Instant, delay: Duration) -> Result<()> {
        for _ in 0..256 {
            if self.next_free > now {
                break;
            }
            let Some(packet) = self.queue.pop(now.duration_since(start)) else {
                break;
            };
            let enqueued = now - packet.queued_for;
            let begin = self.next_free.max(enqueued);
            self.wait_max = self.wait_max.max(begin.duration_since(enqueued));
            let size = packet.payload.len() - 1;
            self.next_free = begin + Duration::from_secs_f64(size as f64 * 8.0 / (self.rate * 1e6));
            self.serialized += size as u64;
            if packet.payload[0] != 0 {
                self.injected_loss += 1;
                continue;
            }
            ensure!(
                self.transit.len() < MAX_PENDING_PACKETS
                    && self.transit_bytes + size <= MAX_PENDING_BYTES,
                "shared propagation memory limit reached"
            );
            self.transit_bytes += size;
            self.transit_peak = self.transit_peak.max(self.transit_bytes);
            self.transit.push_back(InTransit {
                at: self.next_free + delay,
                client: packet.client,
                payload: packet.payload[1..].to_vec(),
            });
        }
        Ok(())
    }

    fn wake(&self) -> Option<Instant> {
        let queue = (self.queue.queued_bytes() > 0).then_some(self.next_free);
        match (queue, self.transit.front().map(|p| p.at)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

fn percentile(samples: &[f64], q: f64) -> Option<f64> {
    (!samples.is_empty()).then(|| samples[((samples.len() - 1) as f64 * q).round() as usize])
}

fn admission_rate(desired: f64, estimate: f64, options: &MultiOptions) -> f64 {
    if !options.adaptive {
        return desired;
    }
    let margin = if options.native_cc { 0.98 } else { 1.0 };
    desired.min((estimate * margin).max(0.000_001))
}

/// Byte credit shared by data and control, bounded to at most two MTUs.
/// A small message can use accumulated credit before a full bulk packet fits.
struct BytePacer {
    credit: f64,
    control_credit: f64,
    updated: Duration,
}
impl BytePacer {
    const BURST_BYTES: f64 = 1200.0;
    fn new() -> Self {
        Self {
            credit: 0.0,
            control_credit: Self::BURST_BYTES,
            updated: Duration::ZERO,
        }
    }
    fn refresh(&mut self, now: Duration, mbps: f64) {
        self.control_credit = (self.control_credit
            + now.saturating_sub(self.updated).as_secs_f64() * mbps * 125_000.0 * 0.25)
            .min(Self::BURST_BYTES);
        self.credit = (self.credit
            + now.saturating_sub(self.updated).as_secs_f64() * mbps * 125_000.0)
            .min(Self::BURST_BYTES + (mbps * 125_000.0 * 0.000_250).min(Self::BURST_BYTES));
        self.updated = now;
    }
    fn permits(&self, bytes: usize) -> bool {
        self.credit >= bytes as f64
    }
    fn charge(&mut self, bytes: usize) {
        self.credit -= bytes as f64;
    }
    fn permits_control(&self, bytes: usize, bulk_pending: bool) -> bool {
        !bulk_pending || self.control_credit >= bytes as f64
    }
    fn charge_control(&mut self, bytes: usize) {
        self.charge(bytes);
        self.control_credit = (self.control_credit - bytes as f64).max(0.0);
    }
    fn wait(&self, bytes: usize, mbps: f64) -> Duration {
        Duration::from_secs_f64(
            ((bytes as f64 - self.credit).max(0.0) / (mbps * 125_000.0)).min(1.0),
        )
    }
}

pub fn run(clip: &Clip, options: &Options, multi: &MultiOptions) -> Result<MultiReport> {
    let mut controlled_options = options.clone();
    controlled_options.bwe_initial_mbps =
        (multi.adaptive && multi.native_cc).then_some(multi.initial_mbps);
    controlled_options.arrival_initial_mbps =
        (multi.adaptive && !multi.native_cc).then_some(multi.initial_mbps);
    let options = &controlled_options;
    ensure!((1..=32).contains(&multi.clients), "clients must be 1..32");
    ensure!(
        options.link_mbps.is_finite() && (0.1..=1000.0).contains(&options.link_mbps),
        "multi link must be 0.1..1000 Mbps"
    );
    ensure!(
        (0.1..=5.0).contains(&multi.offered_load),
        "offered-load must be 0.1..5"
    );
    ensure!(
        !multi.interactive_last || multi.clients > 1,
        "interactive-last needs at least 2 clients"
    );
    ensure!(
        (1..=64 * 1024 * 1024).contains(&options.bytes),
        "invalid transfer size"
    );
    ensure!(
        (1..=MAX_DATA).contains(&options.block_size),
        "invalid block size"
    );
    ensure!(
        (1..=256).contains(&options.ack_every),
        "invalid ACK cadence"
    );
    ensure!(
        (1..=1000).contains(&options.queue_ms),
        "queue-ms must be 1..1000"
    );
    ensure!(
        options.timeout > Duration::ZERO && options.timeout <= Duration::from_secs(300),
        "invalid timeout"
    );
    ensure!(
        options.one_way_delay <= Duration::from_secs(1),
        "invalid propagation delay"
    );
    ensure!(options.cover_only.is_none(), "multi requires probe traffic");
    ensure!(
        multi.probe_deadline >= Duration::from_millis(1)
            && multi.probe_deadline <= Duration::from_secs(5),
        "invalid probe deadline"
    );
    ensure!(
        multi.initial_mbps.is_finite() && (0.1..=1000.0).contains(&multi.initial_mbps),
        "invalid startup estimate"
    );
    ensure!(
        multi.random_loss_ppm <= 250_000 && multi.loss_seed != 0,
        "invalid random loss configuration"
    );
    ensure!(
        multi.burst_every == 0 || multi.burst_len < multi.burst_every,
        "burst must be shorter than its period"
    );
    ensure!(
        multi
            .capacity_steps
            .windows(2)
            .all(|p| p[0].after < p[1].after),
        "capacity steps must be time-ordered"
    );
    for step in &multi.capacity_steps {
        ensure!(
            step.mbps.is_finite() && (0.1..=1000.0).contains(&step.mbps),
            "invalid step capacity"
        );
    }
    let bulk_clients = multi.clients - usize::from(multi.interactive_last);
    let total_offer = options.link_mbps * multi.offered_load;
    let interactive_offer = if multi.interactive_last {
        total_offer.min(2.5) * 0.2
    } else {
        0.0
    };
    let mut desired_rates = Vec::new();
    for client in 0..multi.clients {
        let rate = if client >= bulk_clients {
            interactive_offer
        } else {
            (total_offer - interactive_offer) / bulk_clients as f64
        };
        let rate = if multi.greedy_first && client == 0 {
            rate * 4.0
        } else {
            rate
        };
        desired_rates.extend([rate, rate]);
    }
    let start = Instant::now();
    let mut peers = Vec::new();
    let mut mids = Vec::new();
    for client in 0..multi.clients {
        let count = if multi.interactive_last && client + 1 == multi.clients {
            0
        } else {
            options.bytes
        };
        for side in 0..2 {
            let mut peer = Peer::new(start, count, 17 + client * 113 + side * 76, options)?;
            peer.outbox = Some(VecDeque::new());
            if multi.adaptive {
                if multi.native_cc {
                    peer.set_desired_bitrate(desired_rates[client * 2 + side], start, options)?;
                } else {
                    peer.set_arrival_desired(desired_rates[client * 2 + side])?;
                }
            }
            peers.push(peer);
        }
        let (earlier, later) = peers.split_at_mut(client * 2 + 1);
        let (left, right) = (&mut earlier[client * 2], &mut later[0]);
        let mut changes = left.rtc.sdp_api();
        let mid = changes.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
        let (offer, pending) = changes.apply().context("empty SDP offer")?;
        left.drain(start, start, options)?;
        let answer = right.rtc.sdp_api().accept_offer(offer)?;
        right.drain(start, start, options)?;
        left.rtc.sdp_api().accept_answer(pending, answer)?;
        left.drain(start, start, options)?;
        mids.push(mid);
    }
    let mut hubs = [
        Hub::new(multi.clients, options, start)?,
        Hub::new(multi.clients, options, start)?,
    ];
    for (side, hub) in hubs.iter_mut().enumerate() {
        hub.random_loss_ppm = multi.random_loss_ppm;
        hub.random_state = multi
            .loss_seed
            .wrapping_add(side as u64 * 0x9e3779b97f4a7c15)
            .max(1);
        hub.burst_every = multi.burst_every;
        hub.burst_len = multi.burst_len;
    }
    let mut schedules: Vec<_> = (0..peers.len()).map(|_| Schedule::new(clip)).collect();
    let mut next_send = vec![Duration::ZERO; peers.len()];
    let mut byte_pacers: Vec<_> = (0..peers.len()).map(|_| BytePacer::new()).collect();
    let mut pending_packets: Vec<Option<ScheduledPacket>> =
        (0..peers.len()).map(|_| None).collect();
    let mut frame_original = vec![None; peers.len()];
    let mut frame_timestamp = vec![0; peers.len()];
    let mut finished = vec![None; multi.clients];
    let mut connected = None;
    let mut last_loop = Instant::now();
    let mut loop_gap = Duration::ZERO;
    let mut bulk_end = None;
    let mut step_index = 0;
    let mut intervals = Vec::new();
    let mut interval_windows = Vec::new();
    let mut last_interval = Duration::ZERO;
    let mut last_received = [0usize; 2];
    let mut last_serialized = [0u64; 2];
    let mut last_drops = 0;
    loop {
        let now = Instant::now();
        if connected.is_some() {
            loop_gap = loop_gap.max(now.duration_since(last_loop));
        }
        last_loop = now;
        ensure!(
            now.duration_since(start) < options.timeout,
            "multi timed out; received bytes {:?}",
            peers
                .iter()
                .map(|p| p.app.received_bytes)
                .collect::<Vec<_>>()
        );
        for (direction, hub) in hubs.iter_mut().enumerate() {
            hub.pump(&mut peers, direction, start, options.one_way_delay)?;
        }
        for peer in &mut peers {
            peer.pump(start, options)?;
        }
        if peers.iter().all(|p| p.rtc.is_connected()) {
            if connected.is_none() {
                let measurement_start = start.elapsed();
                for peer in &mut peers {
                    peer.app.set_probe_measurement_start(measurement_start);
                }
            }
            let began = *connected.get_or_insert_with(Instant::now);
            let elapsed = began.elapsed();
            // Ground-truth changes stay in the harness, never in sender control.
            while step_index < multi.capacity_steps.len()
                && elapsed >= multi.capacity_steps[step_index].after
            {
                for hub in &mut hubs {
                    hub.rate = multi.capacity_steps[step_index].mbps;
                }
                step_index += 1;
            }
            for client in 0..multi.clients {
                if finished[client].is_none()
                    && peers[client * 2].app.done()
                    && peers[client * 2 + 1].app.done()
                {
                    finished[client] = Some(elapsed.as_secs_f64() * 1000.0);
                }
            }
            if bulk_end.is_none()
                && finished.iter().all(Option::is_some)
                && elapsed >= multi.min_duration
            {
                bulk_end = Some(Instant::now());
                for peer in &mut peers {
                    peer.app.stop_probes();
                }
            }
            if bulk_end.is_some_and(|at| {
                at.elapsed()
                    >= multi
                        .probe_deadline
                        .saturating_mul(2)
                        .max(Duration::from_millis(200))
            }) {
                break;
            }
            if elapsed.saturating_sub(last_interval) >= Duration::from_secs(1) && bulk_end.is_none()
            {
                let received = [
                    peers
                        .iter()
                        .step_by(2)
                        .map(|p| p.app.received_bytes)
                        .sum::<usize>(),
                    peers
                        .iter()
                        .skip(1)
                        .step_by(2)
                        .map(|p| p.app.received_bytes)
                        .sum::<usize>(),
                ];
                let seconds = (elapsed - last_interval).as_secs_f64();
                let serialized = [hubs[0].serialized, hubs[1].serialized];
                let drops = hubs.iter().map(|h| h.queue.dropped_packets()).sum::<u64>();
                intervals.push(IntervalReport {
                    until_ms: elapsed.as_secs_f64() * 1000.0,
                    link_mbps: hubs[0].rate,
                    goodput_mbps_each_direction: std::array::from_fn(|i| {
                        (received[i] - last_received[i]) as f64 * 8.0 / seconds / 1e6
                    }),
                    serialized_mbps_each_direction: std::array::from_fn(|i| {
                        (serialized[i] - last_serialized[i]) as f64 * 8.0 / seconds / 1e6
                    }),
                    queue_drops: drops - last_drops,
                    sender_budgets_mbps: peers
                        .iter()
                        .enumerate()
                        .map(|(i, p)| admission_rate(desired_rates[i], p.bwe_mbps, multi))
                        .collect(),
                    probe_quality: super::ProbeSummary::default(),
                });
                interval_windows.push((
                    began.duration_since(start) + last_interval,
                    began.duration_since(start) + elapsed,
                ));
                last_received = received;
                last_serialized = serialized;
                last_drops = drops;
                last_interval = elapsed;
            }
            for index in 0..peers.len() {
                let rate = admission_rate(desired_rates[index], peers[index].bwe_mbps, multi);
                if multi.adaptive && !multi.native_cc {
                    // All payload classes share a byte budget. No catch-up train:
                    // at most one packet per endpoint in each event-loop turn.
                    byte_pacers[index].refresh(elapsed, rate);
                    if !peers[index].can_admit_packet(mids[index / 2])
                        || !peers[index].native_pending.is_empty()
                    {
                        next_send[index] = elapsed + Duration::from_millis(1);
                        continue;
                    }
                    if pending_packets[index].is_none() {
                        let at = schedules[index].next_at();
                        let packet = schedules[index].pop_due(at).unwrap();
                        peers[index].seed_control_prefix(&packet.payload)?;
                        pending_packets[index] = Some(packet);
                    }
                    if let Some(cost) = peers[index].control_packet_cost(start.elapsed())
                        && byte_pacers[index].permits_control(cost, peers[index].has_bulk_pending())
                    {
                        if byte_pacers[index].permits(cost) {
                            if let Some(actual_cost) =
                                peers[index].send_control_packet(mids[index / 2], start, options)?
                            {
                                ensure!(actual_cost <= cost, "control changed after admission");
                                byte_pacers[index].charge_control(actual_cost);
                            }
                            next_send[index] = elapsed + byte_pacers[index].wait(105, rate);
                        } else {
                            next_send[index] = elapsed + byte_pacers[index].wait(cost, rate);
                        }
                        continue;
                    }
                    if !peers[index].has_bulk_pending() {
                        next_send[index] = elapsed + Duration::from_millis(1);
                        continue;
                    }
                    let cost =
                        super::wire_cost(pending_packets[index].as_ref().unwrap().payload.len());
                    if !byte_pacers[index].permits(cost) {
                        next_send[index] = elapsed + byte_pacers[index].wait(cost, rate);
                        continue;
                    }
                    let mut packet = pending_packets[index].take().unwrap();
                    if frame_original[index] != Some(packet.timestamp) {
                        frame_original[index] = Some(packet.timestamp);
                        frame_timestamp[index] = (elapsed.as_secs_f64() * 90_000.0) as u32;
                    }
                    packet.timestamp = frame_timestamp[index];
                    byte_pacers[index].charge(cost);
                    peers[index].send_packet(&packet, mids[index / 2], start, options)?;
                    next_send[index] = elapsed + byte_pacers[index].wait(105, rate);
                    continue;
                }
                for _ in 0..8 {
                    if next_send[index] > elapsed {
                        break;
                    }
                    if multi.adaptive
                        && (!peers[index].can_admit_packet(mids[index / 2])
                            || !peers[index].native_pending.is_empty())
                    {
                        next_send[index] = elapsed + Duration::from_millis(1);
                        break;
                    }
                    let at = schedules[index].next_at();
                    let mut packet = schedules[index].pop_due(at).unwrap();
                    if frame_original[index] != Some(packet.timestamp) {
                        frame_original[index] = Some(packet.timestamp);
                        frame_timestamp[index] = (elapsed.as_secs_f64() * 90_000.0) as u32;
                    }
                    packet.timestamp = frame_timestamp[index];
                    // Admission happens BEFORE embedding reliable payload. A small
                    // catch-up burst is allowed; no unbounded backlog of cover slots.
                    let cost = packet.payload.len() + 32;
                    next_send[index] = (next_send[index]
                        + Duration::from_secs_f64(cost as f64 * 8.0 / (rate * 1e6)))
                    .max(elapsed.saturating_sub(Duration::from_millis(2)));
                    peers[index].send_packet(&packet, mids[index / 2], start, options)?;
                }
            }
        }
        for (direction, hub) in hubs.iter_mut().enumerate() {
            hub.collect(&mut peers, direction, start)?;
            hub.pump(&mut peers, direction, start, options.one_way_delay)?;
        }
        let now = Instant::now();
        let mut wake = now + Duration::from_millis(1);
        for peer in &peers {
            wake = wake.min(peer.deadline);
        }
        for hub in &hubs {
            if let Some(at) = hub.wake() {
                wake = wake.min(at);
            }
        }
        if let Some(began) = connected {
            for at in &next_send {
                wake = wake.min(began + *at);
            }
        }
        if wake > now {
            thread::sleep(wake - now);
        }
    }
    let bulk_end = bulk_end.context("bulk never completed")?;
    let cutoff = bulk_end.duration_since(start);
    let elapsed = bulk_end
        .duration_since(connected.context("never connected")?)
        .as_secs_f64();
    for (interval, (since, until)) in intervals.iter_mut().zip(interval_windows) {
        interval.probe_quality =
            peers
                .iter()
                .fold(super::ProbeSummary::default(), |summary, peer| {
                    summary.merge(peer.app.probe_summary_since(
                        since + Duration::from_nanos(1),
                        until,
                        multi.probe_deadline,
                    ))
                });
    }
    let mut clients = Vec::new();
    let drops = [
        hubs[0].queue.per_client_drops(),
        hubs[1].queue.per_client_drops(),
    ];
    for client in 0..multi.clients {
        let (left, right) = (&peers[client * 2], &peers[client * 2 + 1]);
        let integrity = left.app.received_digest() == right.app.sent_digest()
            && right.app.received_digest() == left.app.sent_digest();
        ensure!(integrity, "client {client} integrity failed");
        let mut rtts = Vec::new();
        let quality = left
            .app
            .probe_summary(cutoff, multi.probe_deadline)
            .merge(right.app.probe_summary(cutoff, multi.probe_deadline));
        let mut probe_miss_samples = Vec::new();
        let mut placements = Vec::new();
        let mut echoes = Vec::new();
        for record in left
            .app
            .probe_records
            .values()
            .chain(right.app.probe_records.values())
        {
            if record.generated_at < left.app.probe_measurement_start
                || record.generated_at > cutoff
            {
                continue;
            }
            if probe_miss_samples.len() < 16
                && record
                    .replied_at
                    .is_none_or(|at| at > record.generated_at + multi.probe_deadline)
            {
                probe_miss_samples.push(ProbeMiss {
                    generated_ms_since_ready: (record.generated_at
                        - left.app.probe_measurement_start)
                        .as_secs_f64()
                        * 1000.0,
                    placement_delay_ms: record
                        .placed_at
                        .map(|at| (at - record.generated_at).as_secs_f64() * 1000.0),
                    reply_rtt_ms: record
                        .replied_at
                        .map(|at| (at - record.generated_at).as_secs_f64() * 1000.0),
                });
            }
            if let Some(reply) = record.replied_at {
                rtts.push((reply - record.generated_at).as_secs_f64() * 1000.0);
            }
            if let Some(placed) = record.placed_at {
                placements.push((placed - record.generated_at).as_secs_f64() * 1000.0);
                if let Some(reply) = record.replied_at {
                    echoes.push((reply - placed).as_secs_f64() * 1000.0);
                }
            }
        }
        rtts.sort_by(f64::total_cmp);
        placements.sort_by(f64::total_cmp);
        echoes.sort_by(f64::total_cmp);
        clients.push(ClientReport {
            client,
            workload: if client < bulk_clients {
                "bulk+probes"
            } else {
                "probes-only"
            },
            received_bytes_each_direction: left.app.received_bytes,
            completed_ms: if client < bulk_clients {
                finished[client]
            } else {
                None
            },
            goodput_mbps_each_direction: left.app.received_bytes as f64 * 8.0 / elapsed / 1e6,
            active_goodput_mbps_each_direction: if client < bulk_clients {
                Some(left.app.received_bytes as f64 * 8.0 / finished[client].unwrap() / 1000.0)
            } else {
                None
            },
            integrity_verified: integrity,
            retransmissions: left.app.tx.retransmits + right.app.tx.retransmits,
            probe_samples: rtts.len(),
            probe_requests: quality.generated as u32,
            probe_replies_within_100ms: rtts.iter().filter(|&&rtt| rtt <= 100.0).count(),
            probe_rtt_p50_ms: percentile(&rtts, 0.5),
            probe_rtt_p95_ms: percentile(&rtts, 0.95),
            probe_rtt_p99_ms: percentile(&rtts, 0.99),
            queue_drops: drops[0][client] + drops[1][client],
            bwe_updates: left.bwe_updates + right.bwe_updates,
            final_bwe_mbps_each_direction: [left.bwe_mbps, right.bwe_mbps],
            probe_quality: quality,
            generation_to_placement_p95_ms: percentile(&placements, 0.95),
            placement_to_reply_p95_ms: percentile(&echoes, 0.95),
            probe_miss_samples,
        });
    }
    // Completion-rate fairness detects unequal service despite equal file sizes.
    let rates: Vec<_> = clients
        .iter()
        .take(bulk_clients)
        .map(|c| options.bytes as f64 / c.completed_ms.unwrap())
        .collect();
    let sum: f64 = rates.iter().sum();
    let fairness = sum * sum / (bulk_clients as f64 * rates.iter().map(|r| r * r).sum::<f64>());
    Ok(MultiReport {
        experiment: "shared DRR UDP bottleneck; synthetic paced VP8 slots; real DTLS-SRTP loopback",
        aggregate_goodput_mbps_each_direction: clients
            .iter()
            .map(|c| c.goodput_mbps_each_direction)
            .sum(),
        clients,
        transfer_ms: elapsed * 1000.0,
        shared_link_mbps_each_direction: options.link_mbps,
        offered_load: multi.offered_load,
        greedy_first: multi.greedy_first,
        adaptive: multi.adaptive,
        controller: if !multi.adaptive {
            "fixed-rate"
        } else if multi.native_cc {
            "str0m-twcc"
        } else {
            "arrival-delay-delivery-experimental"
        },
        initial_mbps_per_sender: multi.initial_mbps,
        probe_deadline_ms: multi.probe_deadline.as_secs_f64() * 1000.0,
        baseline_propagation_rtt_ms: options.one_way_delay.as_secs_f64() * 2000.0,
        compact_control_packets: multi.adaptive && !multi.native_cc,
        capacity_steps: multi.capacity_steps.clone(),
        random_loss_ppm: multi.random_loss_ppm,
        loss_seed: multi.loss_seed,
        intervals,
        jain_fairness_bulk_clients: fairness,
        queue_budget_bytes_each_direction: hubs[0].budget,
        queue_peak_bytes_each_direction: [hubs[0].queue.peak_bytes(), hubs[1].queue.peak_bytes()],
        queue_wait_max_ms_each_direction: [
            hubs[0].wait_max.as_secs_f64() * 1000.0,
            hubs[1].wait_max.as_secs_f64() * 1000.0,
        ],
        queue_dropped_packets: hubs.iter().map(|h| h.queue.dropped_packets()).sum(),
        injected_loss_packets: hubs.iter().map(|h| h.injected_loss).sum(),
        serialized_udp_bytes: hubs.iter().map(|h| h.serialized).sum(),
        event_loop_gap_max_ms: loop_gap.as_secs_f64() * 1000.0,
        propagation_peak_bytes_each_direction: [hubs[0].transit_peak, hubs[1].transit_peak],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_pacer_bounds_burst_and_control_uses_the_same_credit() {
        let mut pacer = BytePacer::new();
        pacer.refresh(Duration::from_secs(1), 100.0);
        assert!(pacer.permits(2400));
        assert!(!pacer.permits(2401));
        pacer.charge(2300);
        assert!(pacer.permits(90));
        pacer.charge(90);
        assert!(!pacer.permits(90));
        pacer.refresh(Duration::from_secs(2), 0.5);
        pacer.charge(1200);
        pacer.refresh(Duration::from_micros(2_001_600), 0.5);
        assert!(pacer.permits(90));
        assert!(!pacer.permits(1100));
        assert!(pacer.wait(1100, 0.5) > Duration::from_millis(15));
    }

    #[test]
    fn continuous_control_cannot_starve_bulk_at_the_minimum_rate() {
        let mut pacer = BytePacer::new();
        let mut bulk_packets = 0;
        let mut total_bytes = 0;
        for tick in 1..=1000 {
            pacer.refresh(Duration::from_millis(tick * 10), 0.01);
            if pacer.permits(105) && pacer.permits_control(105, true) {
                pacer.charge_control(105);
                total_bytes += 105;
            } else if pacer.permits(1165) {
                pacer.charge(1165);
                total_bytes += 1165;
                bulk_packets += 1;
            }
        }
        assert!(bulk_packets >= 5, "control prevented reliable progress");
        assert!(total_bytes <= 12_500, "the shared wire budget was bypassed");
    }

    #[test]
    fn five_sessions_share_one_serialization_clock() -> Result<()> {
        let start = Instant::now();
        let options = Options {
            link_mbps: 1.0,
            queue_ms: 100,
            ..Options::default()
        };
        let mut hub = Hub::new(5, &options, start)?;
        for client in 0..5 {
            assert!(hub.queue.push(client, vec![0; 1001], Duration::ZERO));
        }
        hub.serialize(start, start, Duration::from_millis(20))?;
        assert_eq!(hub.transit.len(), 1);
        assert_eq!(
            hub.next_free.duration_since(start),
            Duration::from_millis(8)
        );
        hub.serialize(
            start + Duration::from_millis(32),
            start,
            Duration::from_millis(20),
        )?;
        assert_eq!(hub.serialized, 5000);
        assert_eq!(
            hub.next_free.duration_since(start),
            Duration::from_millis(40)
        );
        for (i, p) in hub.transit.iter().enumerate() {
            assert_eq!(p.client, i);
            assert_eq!(
                p.at.duration_since(start),
                Duration::from_millis(28 + i as u64 * 8)
            );
        }
        Ok(())
    }

    #[test]
    fn injected_loss_consumes_shared_capacity_before_discard() -> Result<()> {
        let start = Instant::now();
        let options = Options {
            link_mbps: 1.0,
            queue_ms: 100,
            ..Options::default()
        };
        let mut hub = Hub::new(2, &options, start)?;
        assert!(hub.queue.push(0, vec![1; 1001], Duration::ZERO));
        assert!(hub.queue.push(1, vec![0; 1001], Duration::ZERO));
        hub.serialize(
            start + Duration::from_millis(8),
            start,
            Duration::from_millis(20),
        )?;
        assert_eq!(hub.injected_loss, 1);
        assert_eq!(hub.serialized, 2000);
        assert_eq!(hub.transit.len(), 1);
        assert_eq!(
            hub.transit[0].at.duration_since(start),
            Duration::from_millis(36)
        );
        Ok(())
    }
}
