//! Small arrival-feedback controller for the loopback lab.
//!
//! This is an experiment heuristic, not an implementation of GCC, BBR, or a
//! standardized congestion controller. It consumes authenticated cumulative
//! receive reports and bounds its own history and response to feedback.
use anyhow::{Result, ensure};
use std::collections::VecDeque;
use std::time::Duration;

const HISTORY_LIMIT: usize = 8192;
const MIN_RATE_MBPS: f64 = 0.01;
const MAX_RATE_MBPS: f64 = 10_000.0;
const MIN_SAMPLE: Duration = Duration::from_millis(40);
const MAX_SAMPLE: Duration = Duration::from_secs(2);
const BASE_FEEDBACK_TIMEOUT: Duration = Duration::from_millis(500);
const DECAY_INTERVAL: Duration = Duration::from_millis(500);
const MAX_SAMPLE_RATE_MBPS: f64 = 10_000.0;
const MAX_DELTA_PACKETS: u64 = 1_000_000;

/// Cumulative authenticated receiver-side arrival counters.
///
/// `serial` is carried by the enclosing SFERA frame sequence and is not part
/// of this fixed 32-byte payload. `arrival_ns` uses the receiver's monotonic
/// clock; only differences between reports are used for delivery-rate samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArrivalReport {
    pub serial: u32,
    pub received_bytes: u64,
    pub received_packets: u64,
    pub last_sequence: u16,
    pub arrival_ns: u64,
}

impl ArrivalReport {
    pub const ENCODED_LEN: usize = 32;

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(Self::ENCODED_LEN);
        payload.extend_from_slice(&self.received_bytes.to_be_bytes());
        payload.extend_from_slice(&self.received_packets.to_be_bytes());
        payload.extend_from_slice(&self.last_sequence.to_be_bytes());
        payload.extend_from_slice(&[0; 6]);
        payload.extend_from_slice(&self.arrival_ns.to_be_bytes());
        payload
    }

    pub fn decode(serial: u32, payload: &[u8]) -> Result<Self> {
        ensure!(
            payload.len() == Self::ENCODED_LEN,
            "arrival report payload must be exactly 32 bytes"
        );
        ensure!(
            payload[18..24].iter().all(|&byte| byte == 0),
            "arrival report reserved bytes must be zero"
        );
        Ok(Self {
            serial,
            received_bytes: u64::from_be_bytes(payload[0..8].try_into()?),
            received_packets: u64::from_be_bytes(payload[8..16].try_into()?),
            last_sequence: u16::from_be_bytes(payload[16..18].try_into()?),
            arrival_ns: u64::from_be_bytes(payload[24..32].try_into()?),
        })
    }
}

#[derive(Clone, Copy)]
struct SentPacket {
    sequence: u16,
    at: Duration,
    cumulative_bytes: u64,
}

/// Delay-and-delivery controller for controlled lab experiments.
pub struct Controller {
    desired_mbps: f64,
    rate_mbps: f64,
    application_backlogged: Option<bool>,
    started_at: Option<Duration>,
    sent: VecDeque<SentPacket>,
    sent_total_bytes: u64,
    sent_total_packets: u64,
    last_report_serial: Option<u32>,
    last_report_bytes: u64,
    last_report_packets: u64,
    last_report_arrival_ns: Option<u64>,
    sample_bytes: u64,
    sample_packets: u64,
    sample_arrival_ns: Option<u64>,
    sample_sender_time: Option<Duration>,
    sample_sent_total_bytes: u64,
    base_transit_ns: Option<i128>,
    queue_delay_ns: u64,
    smoothed_queue_delay_ns: f64,
    projected_queue_delay_ns: f64,
    previous_queue_delay_ns: Option<u64>,
    min_rtt: Option<Duration>,
    last_feedback_at: Option<Duration>,
    last_decay_at: Option<Duration>,
    last_control_at: Option<Duration>,
    last_congestion_at: Option<Duration>,
    feedback_updates: u64,
}

impl Controller {
    pub fn new(initial_mbps: f64, desired_mbps: f64) -> Result<Self> {
        validate_rate(initial_mbps, "initial bitrate")?;
        validate_rate(desired_mbps, "desired bitrate")?;
        Ok(Self {
            desired_mbps,
            rate_mbps: initial_mbps.min(desired_mbps),
            application_backlogged: None,
            started_at: None,
            sent: VecDeque::with_capacity(HISTORY_LIMIT),
            sent_total_bytes: 0,
            sent_total_packets: 0,
            last_report_serial: None,
            last_report_bytes: 0,
            last_report_packets: 0,
            last_report_arrival_ns: None,
            sample_bytes: 0,
            sample_packets: 0,
            sample_arrival_ns: None,
            sample_sender_time: None,
            sample_sent_total_bytes: 0,
            base_transit_ns: None,
            queue_delay_ns: 0,
            smoothed_queue_delay_ns: 0.0,
            projected_queue_delay_ns: 0.0,
            previous_queue_delay_ns: None,
            min_rtt: None,
            last_feedback_at: None,
            last_decay_at: None,
            last_control_at: None,
            last_congestion_at: None,
            feedback_updates: 0,
        })
    }

    pub fn set_desired(&mut self, mbps: f64) -> Result<()> {
        validate_rate(mbps, "desired bitrate")?;
        self.desired_mbps = mbps;
        self.rate_mbps = self.rate_mbps.min(mbps);
        Ok(())
    }

    /// Override the inferred sender utilization with the application's queue
    /// state. Pass true when bulk data is waiting for pacing/admission, and
    /// false when the application has no queued data to send.
    pub fn set_application_backlogged(&mut self, backlogged: bool) {
        self.application_backlogged = Some(backlogged);
    }

    /// Record a packet at the sender's network-submission boundary.
    pub fn on_sent(&mut self, sequence: u16, now: Duration, bytes: usize) {
        self.started_at.get_or_insert(now);
        self.sent_total_bytes = self
            .sent_total_bytes
            .saturating_add(bytes.min(u64::MAX as usize) as u64);
        self.sent_total_packets = self.sent_total_packets.saturating_add(1);
        self.sent.push_back(SentPacket {
            sequence,
            at: now,
            cumulative_bytes: self.sent_total_bytes,
        });
        while self.sent.len() > HISTORY_LIMIT {
            self.sent.pop_front();
        }
    }

    /// Accept a fresh cumulative receiver report.
    ///
    /// Returns false for stale/duplicate reports and reports whose sequence is
    /// outside the bounded send history; they do not affect the estimate.
    pub fn on_feedback(&mut self, report: &ArrivalReport, now: Duration) -> Result<bool> {
        ensure!(
            report.serial != 0
                && report.received_packets > 0
                && report.received_bytes > 0
                && report.received_bytes <= self.sent_total_bytes
                && report.received_packets <= self.sent_total_packets,
            "arrival report counters must be nonzero and no greater than sent totals"
        );
        if let Some(serial) = self.last_report_serial
            && !serial_is_newer(report.serial, serial)
        {
            return Ok(false);
        }
        if report.received_bytes < self.last_report_bytes
            || report.received_packets < self.last_report_packets
            || self.last_feedback_at.is_some_and(|last| now < last)
            || self
                .last_report_arrival_ns
                .is_some_and(|arrival| report.arrival_ns <= arrival)
        {
            return Ok(false);
        }
        let Some(sent) = self
            .sent
            .iter()
            .rev()
            .find(|packet| packet.sequence == report.last_sequence)
            .copied()
        else {
            return Ok(false);
        };
        if sent.at > now {
            return Ok(false);
        }

        let rtt = now.saturating_sub(sent.at);
        self.min_rtt = Some(self.min_rtt.map_or(rtt, |old| old.min(rtt)));
        let transit = i128::from(report.arrival_ns) - sent.at.as_nanos() as i128;
        self.base_transit_ns = Some(
            self.base_transit_ns
                .map_or(transit, |base| base.min(transit)),
        );
        let queue_ns = transit.saturating_sub(self.base_transit_ns.unwrap_or(transit));
        self.previous_queue_delay_ns = Some(self.queue_delay_ns);
        self.queue_delay_ns = queue_ns.clamp(0, u64::MAX as i128) as u64;
        let previous_smoothed = self.smoothed_queue_delay_ns;
        self.smoothed_queue_delay_ns = 0.5 * previous_smoothed + 0.5 * self.queue_delay_ns as f64;
        let feedback_interval = self.last_feedback_at.map(|last| now.saturating_sub(last));
        let rising_per_ns = feedback_interval
            .filter(|dt| !dt.is_zero())
            .map_or(0.0, |dt| {
                (self.smoothed_queue_delay_ns - previous_smoothed).max(0.0) / dt.as_nanos() as f64
            });
        // Do not increase into a queue that will exceed the target before
        // another RTT of feedback can return. Host jitter is filtered first.
        self.projected_queue_delay_ns = self.smoothed_queue_delay_ns
            + rising_per_ns * self.min_rtt.unwrap_or_default().as_nanos() as f64;
        // Use every fresh report for a fast delay signal; the delivered-rate
        // estimate below intentionally waits for a 100 ms sampling interval.
        let fast_delay_backoff = self.smoothed_queue_delay_ns >= 2_500_000.0
            && self
                .last_congestion_at
                .is_none_or(|last| now.saturating_sub(last) >= self.control_interval());
        if fast_delay_backoff {
            self.rate_mbps = (self.rate_mbps * 0.85)
                .max(MIN_RATE_MBPS)
                .min(self.desired_mbps);
            self.last_congestion_at = Some(now);
            self.last_control_at = Some(now);
        }

        self.last_report_serial = Some(report.serial);
        self.last_report_bytes = report.received_bytes;
        self.last_report_packets = report.received_packets;
        self.last_report_arrival_ns = Some(report.arrival_ns);
        self.last_feedback_at = Some(now);
        self.last_decay_at = None;
        self.feedback_updates = self.feedback_updates.saturating_add(1);

        let Some(sample_arrival_ns) = self.sample_arrival_ns else {
            self.sample_arrival_ns = Some(report.arrival_ns);
            self.sample_bytes = report.received_bytes;
            self.sample_packets = report.received_packets;
            self.sample_sender_time = Some(sent.at);
            self.sample_sent_total_bytes = sent.cumulative_bytes;
            self.last_control_at = Some(now);
            return Ok(true);
        };
        let arrival_delta_ns = report.arrival_ns.saturating_sub(sample_arrival_ns);
        if arrival_delta_ns < MIN_SAMPLE.as_nanos() as u64 {
            return Ok(true);
        }

        let byte_delta = report.received_bytes.saturating_sub(self.sample_bytes);
        let packet_delta = report.received_packets.saturating_sub(
            // The previous accepted report might have arrived more frequently
            // than the minimum rate-sampling interval. Keep the counter baseline
            // separate so short feedback cadence cannot starve rate updates.
            self.sample_packets,
        );
        let elapsed = Duration::from_nanos(arrival_delta_ns);
        let sample_valid = elapsed <= MAX_SAMPLE
            && byte_delta <= 256 * 1024 * 1024
            && packet_delta <= MAX_DELTA_PACKETS
            && packet_delta <= byte_delta
            && byte_delta as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0
                <= MAX_SAMPLE_RATE_MBPS;
        if !sample_valid {
            self.sample_arrival_ns = Some(report.arrival_ns);
            self.sample_bytes = report.received_bytes;
            self.sample_packets = report.received_packets;
            self.sample_sender_time = Some(sent.at);
            self.sample_sent_total_bytes = sent.cumulative_bytes;
            self.last_control_at = Some(now);
            return Ok(true);
        }

        let delivered_mbps = byte_delta as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0;
        // Compare matching packet ranges, not current TX totals: feedback is
        // delayed by a return path and later transmissions are still in flight.
        let sender_delta_bytes = sent
            .cumulative_bytes
            .saturating_sub(self.sample_sent_total_bytes);
        let sender_elapsed = self
            .sample_sender_time
            .map(|baseline| sent.at.saturating_sub(baseline))
            .unwrap_or(elapsed);
        let sender_mbps = if sender_elapsed.is_zero() {
            0.0
        } else {
            sender_delta_bytes as f64 * 8.0 / sender_elapsed.as_secs_f64() / 1_000_000.0
        };

        // Arrival variation above the minimum observed transit is queue delay;
        // the unknown constant clock offset cancels in both subtractions.
        let delay_pressure = self.smoothed_queue_delay_ns >= 4_000_000.0;
        let sender_backlogged = self
            .application_backlogged
            .unwrap_or(sender_mbps >= self.rate_mbps * 0.85);
        let delivery_pressure = sender_backlogged && delivered_mbps < sender_mbps * 0.85;
        let congestion_cooldown_elapsed = self
            .last_congestion_at
            .is_none_or(|last| now.saturating_sub(last) >= self.control_interval());
        // A newly measured capacity collapse is an absolute rate ceiling,
        // not another multiplicative penalty. Do not let the fast-path
        // cooldown suppress this information for successive RTTs.
        if delay_pressure && sender_backlogged && delivered_mbps < self.rate_mbps * 0.85 {
            self.rate_mbps = (delivered_mbps * 0.95)
                .max(MIN_RATE_MBPS)
                .min(self.desired_mbps);
            self.last_congestion_at = Some(now);
            self.last_control_at = Some(now);
        } else if !fast_delay_backoff
            && congestion_cooldown_elapsed
            && (delay_pressure || delivery_pressure)
        {
            self.rate_mbps = self
                .rate_mbps
                .min(self.rate_mbps * 0.85)
                .min(delivered_mbps * 0.95)
                .max(MIN_RATE_MBPS)
                .min(self.desired_mbps);
            self.last_congestion_at = Some(now);
            self.last_control_at = Some(now);
        } else if self.rate_mbps < self.desired_mbps
            && sender_backlogged
            && self.projected_queue_delay_ns <= 1_500_000.0
            && self
                .last_congestion_at
                .is_none_or(|last| now.saturating_sub(last) >= self.growth_interval())
        {
            let elapsed_control = self
                .last_control_at
                .map(|last| now.saturating_sub(last))
                .unwrap_or_default();
            if elapsed_control >= self.control_interval() {
                let recovery = self
                    .last_congestion_at
                    .is_some_and(|last| now.saturating_sub(last) < Duration::from_secs(30));
                let startup = self.last_congestion_at.is_none();
                self.rate_mbps = if recovery {
                    (self.rate_mbps * 1.04).min(self.desired_mbps)
                } else if startup {
                    (self.rate_mbps * 1.08).min(self.desired_mbps)
                } else {
                    (self.rate_mbps + 0.2).min(self.desired_mbps)
                };
                self.last_control_at = Some(now);
            }
        }

        self.sample_arrival_ns = Some(report.arrival_ns);
        self.sample_bytes = report.received_bytes;
        self.sample_packets = report.received_packets;
        self.sample_sender_time = Some(sent.at);
        self.sample_sent_total_bytes = sent.cumulative_bytes;
        Ok(true)
    }

    /// Current sender rate. Missing feedback halves it every 500 ms after the
    /// greater of 500 ms or three minimum RTT samples.
    pub fn rate_mbps(&mut self, now: Duration) -> f64 {
        let Some(last_feedback) = self.last_feedback_at else {
            if let Some(started_at) = self.started_at {
                self.apply_timeout_decay(started_at, now, BASE_FEEDBACK_TIMEOUT);
            }
            return self.rate_mbps;
        };
        let timeout = self
            .min_rtt
            .map(|rtt| rtt.saturating_mul(3).max(BASE_FEEDBACK_TIMEOUT))
            .unwrap_or(BASE_FEEDBACK_TIMEOUT);
        self.apply_timeout_decay(last_feedback, now, timeout);
        self.rate_mbps
    }

    pub fn queue_delay_ms(&self) -> f64 {
        self.queue_delay_ns as f64 / 1_000_000.0
    }

    pub fn feedback_updates(&self) -> u64 {
        self.feedback_updates
    }

    pub fn history_len(&self) -> usize {
        self.sent.len()
    }

    fn control_interval(&self) -> Duration {
        self.min_rtt.unwrap_or_default().max(MIN_SAMPLE)
    }

    fn growth_interval(&self) -> Duration {
        self.control_interval()
    }

    fn apply_timeout_decay(&mut self, reference: Duration, now: Duration, timeout: Duration) {
        let first_decay = reference.saturating_add(timeout);
        if now < first_decay {
            return;
        }
        let decay_at = self.last_decay_at.unwrap_or(first_decay);
        if now < decay_at {
            return;
        }
        let periods = (now.saturating_sub(decay_at).as_nanos() / DECAY_INTERVAL.as_nanos() + 1)
            .min(u32::MAX as u128) as u32;
        self.rate_mbps = (self.rate_mbps * 0.5_f64.powf(periods as f64))
            .max(MIN_RATE_MBPS)
            .min(self.desired_mbps);
        self.last_decay_at = Some(decay_at + DECAY_INTERVAL * periods);
    }
}

fn serial_is_newer(candidate: u32, previous: u32) -> bool {
    candidate != previous && candidate.wrapping_sub(previous) < (1u32 << 31)
}

fn validate_rate(mbps: f64, name: &str) -> Result<()> {
    ensure!(
        mbps.is_finite() && mbps > 0.0 && mbps <= MAX_RATE_MBPS,
        "{name} must be >0..=10000 Mbps"
    );
    Ok(())
}
