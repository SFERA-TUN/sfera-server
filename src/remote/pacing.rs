//! Experimental per-direction pacing using authenticated delivery samples.

use super::delivery::matched::Sample;
use std::time::{Duration, Instant};

const EPOCH: Duration = Duration::from_secs(1);
const FEEDBACK_TIMEOUT: Duration = Duration::from_secs(3);
const INITIAL_MBPS: f64 = 2.0;
const MIN_MBPS: f64 = 0.5;
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

    pub(super) fn payload_sent(&mut self) {
        self.payload_sent = true;
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
        if elapsed < EPOCH {
            return None;
        }
        let sent = wire_bytes - self.wire_bytes;
        let useful = sent.saturating_sub(fill_bytes - self.fill_bytes);
        let sent_mbps = sent as f64 * 8e-6 / elapsed.as_secs_f64();
        let useful_mbps = useful as f64 * 8e-6 / elapsed.as_secs_f64();
        let blocked = blocked_sends - self.blocked_sends;
        let loaded = self.backlogged && useful_mbps >= 0.90 * self.rate;
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
        } else if loaded && evidence && loss <= 0.01 && blocked == 0 && elapsed < 2 * EPOCH {
            let confirmed = self.rate.min(useful_mbps * 1.08);
            if self.recent_rate.is_none_or(|(old, _)| confirmed >= old) {
                self.recent_rate = Some((confirmed, now));
            }
            self.clean_epochs += 1;
            if self.starting || self.clean_epochs >= 2 {
                let recent = self.recent_rate.map_or(0.0, |(rate, _)| rate);
                self.rate = if self.starting {
                    (1.5 * self.rate).max(INITIAL_MBPS)
                } else {
                    (1.2 * self.rate).max(recent.min(1.5 * self.rate))
                };
                self.clean_epochs = 0;
            }
        } else if !loaded && useful_mbps < 0.80 * self.rate {
            self.rate = (1.15 * useful_mbps).max(MIN_MBPS);
            self.starting = false;
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
        pacing.payload_sent();
        pacing.observe(now, sample(100, 100, 250));
        // The wire hit 2 Mbps, but only 0.2 Mbps was traffic other than fill.
        assert_eq!(pacing.tick(now, 250_000, 225_000, 0), Some(MIN_MBPS));
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
            pacing.payload_sent();
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
