//! Experimental per-direction pacing using authenticated delivery samples.

use super::delivery::matched::Sample;
use std::time::{Duration, Instant};

const EPOCH: Duration = Duration::from_secs(1);
const STARTUP_EPOCH: Duration = Duration::from_millis(500);
const FEEDBACK_TIMEOUT: Duration = Duration::from_secs(3);
const INITIAL_MBPS: f64 = 2.0;
const MIN_MBPS: f64 = 0.5;
pub(super) const SMALL_PACKET_BYTES: usize = 128;
const RECENT: Duration = Duration::from_secs(30);

pub(super) struct Pacing {
    rate: f64,
    started: Instant,
    rate_since: Instant,
    wire_bytes: u64,
    fill_bytes: u64,
    blocked_sends: u64,
    backlogged: bool,
    payload_sent: bool,
    payload_packets: u64,
    small_payload_packets: u64,
    small_queue_full_visits: u32,
    unconfirmed_since: Option<Instant>,
    sent: u64,
    received: u64,
    min_delay: Option<(i64, Instant)>,
    epoch_delay: Option<i64>,
    recent_rate: Option<(f64, Instant)>,
    clean_epochs: u8,
    starting: bool,
}

impl Pacing {
    pub(super) fn new(now: Instant, wire_bytes: u64, fill_bytes: u64, blocked_sends: u64) -> Self {
        Self {
            rate: INITIAL_MBPS,
            started: now,
            rate_since: now,
            wire_bytes,
            fill_bytes,
            blocked_sends,
            backlogged: false,
            payload_sent: false,
            payload_packets: 0,
            small_payload_packets: 0,
            small_queue_full_visits: 0,
            unconfirmed_since: None,
            sent: 0,
            received: 0,
            min_delay: None,
            epoch_delay: None,
            recent_rate: None,
            clean_epochs: 0,
            starting: true,
        }
    }

    pub(super) fn rate(&self) -> f64 {
        self.rate
    }

    pub(super) fn backlog(&mut self, backlogged: bool) {
        self.backlogged |= backlogged;
    }

    pub(super) fn payload_sent(&mut self, bytes: usize) {
        self.payload_sent = true;
        self.payload_packets += 1;
        self.small_payload_packets += u64::from(bytes <= SMALL_PACKET_BYTES);
    }

    pub(super) fn note_small_queue_pressure(&mut self) {
        self.small_queue_full_visits = self.small_queue_full_visits.saturating_add(1);
    }

    pub(super) fn observe(&mut self, now: Instant, sample: Sample) {
        // Cohorts whose send window straddles a target change do not describe
        // either target. The sample age is rounded down to milliseconds.
        if now.saturating_duration_since(self.rate_since)
            < Duration::from_millis(sample.send_start_age_ms + 1)
        {
            return;
        }
        self.sent += sample.sent_packets;
        self.received += sample.received_packets;
        if let Some(delay) = sample.forward_delay_offset_ms {
            // The unknown clock offset cancels. Refresh the baseline to keep
            // steady drift from accumulating over long sessions.
            if self
                .min_delay
                .is_none_or(|(old, at)| delay <= old || now.duration_since(at) >= RECENT)
            {
                self.min_delay = Some((delay, now));
            }
            self.epoch_delay = Some(self.epoch_delay.map_or(delay, |old| old.min(delay)));
        }
    }

    pub(super) fn tick(
        &mut self,
        now: Instant,
        wire_bytes: u64,
        fill_bytes: u64,
        blocked_sends: u64,
    ) -> Option<f64> {
        let elapsed = now.saturating_duration_since(self.started);
        let early_startup =
            self.starting && self.backlogged && self.sent >= 2 && elapsed >= STARTUP_EPOCH;
        if elapsed < EPOCH && !early_startup {
            return None;
        }
        let sent = wire_bytes - self.wire_bytes;
        let useful = sent.saturating_sub(fill_bytes - self.fill_bytes);
        let sent_mbps = sent as f64 * 8e-6 / elapsed.as_secs_f64();
        let useful_mbps = useful as f64 * 8e-6 / elapsed.as_secs_f64();
        let blocked = blocked_sends - self.blocked_sends;
        let useful_load = self.backlogged && useful_mbps >= 0.90 * self.rate;
        if elapsed < EPOCH && !useful_load {
            return None;
        }
        // A persistently full packet queue can signal load in the gap
        // between the ordinary shrink and growth thresholds.
        let packet_limited = elapsed >= EPOCH
            && self.backlogged
            && self.small_queue_full_visits >= 16
            && self.payload_packets >= 16
            && self.small_payload_packets * 20 >= self.payload_packets * 19
            && (0.80 * self.rate..0.90 * self.rate).contains(&useful_mbps);
        let loaded = useful_load || packet_limited;
        let missing = self.sent - self.received;
        let loss = missing as f64 / self.sent.max(1) as f64;
        let evidence = self.sent >= 2;
        let queued = sent_mbps >= MIN_MBPS
            && self
                .epoch_delay
                .zip(self.min_delay)
                .is_some_and(|(delay, (baseline, _))| delay.saturating_sub(baseline) >= 35);
        let unconfirmed = if loaded && !evidence {
            now.saturating_duration_since(*self.unconfirmed_since.get_or_insert(self.started))
        } else {
            self.unconfirmed_since = None;
            Duration::ZERO
        };
        let previous = self.rate;

        if self
            .recent_rate
            .is_some_and(|(_, at)| now.duration_since(at) >= RECENT)
        {
            self.recent_rate = None;
        }
        let lossy = missing >= 2 && loss >= 0.08;
        let clean_delivery = evidence && loss <= 0.01 && blocked == 0;
        if !self.backlogged && !self.payload_sent {
            self.rate = MIN_MBPS;
            self.clean_epochs = 0;
            self.starting = true;
        } else if lossy || queued || blocked >= 3 || unconfirmed >= FEEDBACK_TIMEOUT {
            let factor = match (lossy, queued) {
                (true, _) => (0.95 * (1.0 - loss)).clamp(0.35, 0.85),
                (_, true) => (1.05 * sent_mbps / self.rate).clamp(0.40, 0.85),
                _ => 0.65,
            };
            self.rate = (self.rate * factor).max(MIN_MBPS);
            self.starting = false;
            self.clean_epochs = 0;
        } else if loaded && clean_delivery && elapsed < 2 * EPOCH {
            let confirmed = self.rate.min(useful_mbps * 1.08);
            if self.recent_rate.is_none_or(|(old, _)| confirmed >= old) {
                self.recent_rate = Some((confirmed, now));
            }
            self.clean_epochs += 1;
            if (self.starting && useful_load) || self.clean_epochs >= 2 {
                let recent = self.recent_rate.map_or(0.0, |(rate, _)| rate);
                self.rate = if !useful_load {
                    1.10 * self.rate
                } else if self.starting {
                    (1.5 * self.rate).max(INITIAL_MBPS)
                } else {
                    (1.2 * self.rate).max(recent.min(1.5 * self.rate))
                };
                self.clean_epochs = 0;
            }
        } else if !loaded && useful_mbps < 0.80 * self.rate {
            self.rate = (1.15 * useful_mbps).max(MIN_MBPS);
            // A short fall in useful traffic can still leave a queued sender
            // on a clean path. Keep probing in startup after this adjustment.
            if self.rate < previous
                && previous > INITIAL_MBPS
                && !(self.backlogged && clean_delivery)
            {
                self.starting = false;
            }
            self.clean_epochs = 0;
        } else {
            self.clean_epochs = 0;
        }
        self.started = now;
        self.wire_bytes = wire_bytes;
        self.fill_bytes = fill_bytes;
        self.blocked_sends = blocked_sends;
        self.backlogged = false;
        self.payload_sent = false;
        self.payload_packets = 0;
        self.small_payload_packets = 0;
        self.small_queue_full_visits = 0;
        self.sent = 0;
        self.received = 0;
        self.epoch_delay = None;
        if self.rate == previous {
            return None;
        }
        self.rate_since = now;
        Some(self.rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(sent: u64, received: u64, age: u64) -> Sample {
        Sample {
            sent_packets: sent,
            received_packets: received,
            sent_bytes: sent * 1300,
            received_bytes: received * 1300,
            span_ms: 200,
            send_start_age_ms: age,
            send_end_age_ms: 30,
            forward_delay_offset_ms: Some(0),
        }
    }

    #[test]
    fn startup_uses_an_early_epoch_only_with_measured_load() {
        let start = Instant::now();
        let half_second = start + Duration::from_millis(500);
        for (fill_bytes, expected) in [(0, Some(3.0)), (100_000, None)] {
            let mut pacing = Pacing::new(start, 0, 0, 0);
            pacing.backlog(true);
            assert_eq!(pacing.tick(half_second, 125_000, fill_bytes, 0), None);

            pacing.observe(half_second, sample(10, 10, 200));
            assert_eq!(pacing.tick(half_second, 125_000, fill_bytes, 0), expected);
        }
    }

    #[test]
    fn queued_small_packets_need_clean_delivery_to_increase_rate() {
        let start = Instant::now();
        for (received, visits, bytes, expected) in [
            (100, 16, 4_250_000, 44.0),
            (100, 1, 4_250_000, 40.0),
            (95, 16, 4_250_000, 40.0),
            (60, 16, 4_250_000, 22.8),
            (100, 16, 3_250_000, 29.9),
        ] {
            let mut pacing = Pacing::new(start, 0, 0, 0);
            pacing.rate = 40.0;
            let mut wire = 0;
            for second in 1..=2 {
                let now = start + second * EPOCH;
                pacing.backlog(true);
                for _ in 0..visits {
                    pacing.note_small_queue_pressure();
                }
                for _ in 0..32 {
                    pacing.payload_sent(52);
                }
                pacing.observe(now, sample(100, received, 200));
                wire += bytes;
                pacing.tick(now, wire, 0, 0);
                if received == 60 || bytes == 3_250_000 {
                    break;
                }
            }
            assert!((pacing.rate() - expected).abs() < 1e-6, "{}", pacing.rate());
        }
    }

    #[test]
    fn queued_startup_continues_after_clean_underuse() {
        let start = Instant::now();
        for (received, expects_startup) in [(100, true), (98, false)] {
            let mut pacing = Pacing::new(start, 0, 0, 0);
            pacing.rate = 4.0;
            let underused = start + EPOCH;
            pacing.backlog(true);
            pacing.observe(underused, sample(100, received, 200));
            assert!(pacing.tick(underused, 250_000, 0, 0).is_some());
            assert_eq!(pacing.starting, expects_startup);

            let resume = underused + STARTUP_EPOCH;
            pacing.backlog(true);
            pacing.observe(resume, sample(100, 100, 200));
            let new_rate = pacing.tick(resume, 393_750, 0, 0);
            assert_eq!(new_rate.is_some(), expects_startup);
        }
    }

    #[test]
    fn rises_on_confirmed_load_and_recovers_after_a_capacity_drop() {
        let start = Instant::now();
        let mut pacing = Pacing::new(start, 0, 0, 0);
        let mut wire = 0;
        for second in 1..=16 {
            let now = start + second * EPOCH;
            wire += (pacing.rate() * 125_000.0) as u64;
            pacing.backlog(true);
            let delivered = if second == 16 { 15 } else { 100 };
            pacing.observe(now, sample(100, delivered, 250));
            pacing.tick(now, wire, 0, 0);
        }
        let reduced = pacing.rate();
        assert!(reduced > 100.0 && reduced < 320.0);
        for second in 17..=18 {
            let now = start + second * EPOCH;
            wire += (pacing.rate() * 125_000.0) as u64;
            pacing.backlog(true);
            pacing.observe(now, sample(100, 100, 250));
            pacing.tick(now, wire, 0, 0);
        }
        assert!(pacing.rate() > reduced);
    }

    #[test]
    fn filling_unused_budget_does_not_drive_rate_growth() {
        let start = Instant::now();
        let mut pacing = Pacing::new(start, 0, 0, 0);
        let now = start + EPOCH;
        pacing.backlog(true);
        pacing.payload_sent(52);
        pacing.observe(now, sample(100, 100, 250));
        // The wire hit 2 Mbps, but only 0.2 Mbps was traffic other than fill.
        assert_eq!(pacing.tick(now, 250_000, 225_000, 0), Some(MIN_MBPS));
        // A partially utilized first active epoch at the floor does not
        // disable startup growth on the next full epoch.
        pacing.backlog(true);
        assert_eq!(pacing.tick(now + EPOCH, 312_500, 275_000, 0), None);
        pacing.backlog(true);
        pacing.observe(now + 2 * EPOCH, sample(20, 20, 250));
        assert_eq!(
            pacing.tick(now + 2 * EPOCH, 375_000, 275_000, 0),
            Some(INITIAL_MBPS)
        );
    }

    #[test]
    fn ignores_idle_and_old_cohorts_and_reduces_on_missing_feedback() {
        let start = Instant::now();
        let mut pacing = Pacing::new(start, 0, 0, 0);
        for second in 1..=3 {
            let now = start + second * EPOCH;
            pacing.observe(now, sample(20, 20, 250));
            pacing.tick(now, 0, 0, 0);
        }
        assert_eq!(pacing.rate(), MIN_MBPS);
        pacing.backlog(true);
        let now = start + 4 * EPOCH;
        pacing.observe(now, sample(20, 20, 250));
        assert_eq!(pacing.tick(now, 62_500, 0, 0), Some(INITIAL_MBPS));
        for second in 5..=7 {
            let now = start + second * EPOCH;
            pacing.backlog(true);
            pacing.observe(now, sample(20, 20, 7_050));
            pacing.tick(now, 62_500 + u64::from(second - 4) * 240_000, 0, 0);
        }
        assert!(pacing.rate() < INITIAL_MBPS);
    }

    #[test]
    fn responds_to_queue_delay_after_inner_tcp_backs_off() {
        let start = Instant::now();
        let mut pacing = Pacing::new(start, 0, 0, 0);
        let mut wire = 0;
        for second in 1..=4 {
            let now = start + second * EPOCH;
            wire += (pacing.rate() * 125_000.0) as u64;
            pacing.backlog(true);
            pacing.observe(now, sample(50, 50, 250));
            pacing.tick(now, wire, 0, 0);
        }
        let before = pacing.rate();
        for second in 5..=7 {
            wire += 375_000;
            pacing.payload_sent(52);
            let now = start + second * EPOCH;
            pacing.observe(
                now,
                Sample {
                    forward_delay_offset_ms: Some(59),
                    ..sample(10, 10, 250)
                },
            );
            pacing.tick(now, wire, 0, 0);
        }
        assert!(pacing.rate() <= 3.0);
        assert!(before > 10.0);
        assert_eq!(pacing.tick(start + 8 * EPOCH, wire, 0, 0), Some(MIN_MBPS));
    }
}
