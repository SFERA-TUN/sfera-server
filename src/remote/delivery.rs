use std::time::{Duration, Instant};

pub(super) mod matched;

pub(super) const VERSION: u8 = 1;
const MIN_REPORT_INTERVAL: Duration = Duration::from_millis(250);
const MAX_SAMPLE_INTERVAL_MS: u64 = 2_000;
const MIN_SAMPLE_INTERVAL_MS: u64 = 100;
const REPORT_DATA_BYTES: u64 = 16 * 1024;

pub(super) fn negotiate(ip_tunnel: bool, requested: Option<u8>) -> Option<u8> {
    (ip_tunnel && requested == Some(VERSION)).then_some(VERSION)
}

#[derive(Clone, Copy)]
pub(super) struct Report {
    elapsed_ms: u64,
    bytes: u64,
    packets: u64,
}

impl Report {
    pub(super) const LEN: usize = 24;

    pub(super) fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() != Self::LEN {
            return None;
        }
        Some(Self {
            elapsed_ms: u64::from_be_bytes(payload[..8].try_into().ok()?),
            bytes: u64::from_be_bytes(payload[8..16].try_into().ok()?),
            packets: u64::from_be_bytes(payload[16..].try_into().ok()?),
        })
    }

    pub(super) fn encode(self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(Self::LEN);
        payload.extend_from_slice(&self.elapsed_ms.to_be_bytes());
        payload.extend_from_slice(&self.bytes.to_be_bytes());
        payload.extend_from_slice(&self.packets.to_be_bytes());
        payload
    }
}

/// Transport telemetry. Receiver intervals measure arrived bytes, independently
/// of sender and receiver clock offsets. This never changes pacing.
#[derive(Default)]
pub(super) struct Observer {
    bytes: u64,
    packets: u64,
    unreported_data_bytes: u64,
    next_report: Duration,
    serial: u32,
    last_report: Option<(u32, Report)>,
    sample_at: Option<Instant>,
}

impl Observer {
    pub(super) fn receive(&mut self, ipv4_bytes: usize, carries_ip: bool) {
        self.bytes += ipv4_bytes as u64;
        self.packets += 1;
        if carries_ip {
            self.unreported_data_bytes += ipv4_bytes as u64;
        }
    }

    pub(super) fn due(&self, now: Duration) -> bool {
        now >= self.next_report && self.unreported_data_bytes >= REPORT_DATA_BYTES
    }

    pub(super) fn report(&mut self, now: Duration) -> (u32, Report) {
        self.next_report = now + MIN_REPORT_INTERVAL;
        self.unreported_data_bytes = 0;
        self.serial = super::next_serial(self.serial);
        (
            self.serial,
            Report {
                elapsed_ms: now.as_millis() as u64,
                bytes: self.bytes,
                packets: self.packets,
            },
        )
    }

    pub(super) fn observe(
        &mut self,
        serial: u32,
        report: Report,
        now: Instant,
        sent_bytes: u64,
        sent_packets: u64,
    ) -> Option<u64> {
        if serial == 0
            || report.bytes == 0
            || report.packets == 0
            || report.bytes > sent_bytes
            || report.packets > sent_packets
        {
            return None;
        }
        let previous = self.last_report;
        if let Some((serial_before, before)) = previous
            && (!(1..0x8000_0000).contains(&serial.wrapping_sub(serial_before))
                || report.elapsed_ms <= before.elapsed_ms
                || report.bytes <= before.bytes
                || report.packets <= before.packets)
        {
            return None;
        }
        self.last_report = Some((serial, report));
        let (_, before) = previous?;
        let delta_ms = report.elapsed_ms - before.elapsed_ms;
        if !(MIN_SAMPLE_INTERVAL_MS..=MAX_SAMPLE_INTERVAL_MS).contains(&delta_ms) {
            return None;
        }
        self.sample_at = Some(now);
        Some((report.bytes - before.bytes).saturating_mul(8) / delta_ms)
    }

    pub(super) fn sample_age_ms(&self, now: Instant) -> Option<u64> {
        self.sample_at
            .map(|at| now.saturating_duration_since(at).as_millis() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_defaults_to_absent_for_old_peers_and_other_modes() {
        assert_eq!(negotiate(true, None), None);
        assert_eq!(negotiate(true, Some(2)), None);
        assert_eq!(negotiate(false, Some(VERSION)), None);
        assert_eq!(negotiate(true, Some(VERSION)), Some(VERSION));
    }

    #[test]
    fn reports_are_rate_limited_and_idle_cover_does_not_trigger_them() {
        let mut receiver = Observer::default();
        receiver.receive(REPORT_DATA_BYTES as usize, false);
        assert!(!receiver.due(Duration::ZERO));
        receiver.receive(REPORT_DATA_BYTES as usize, true);
        assert!(receiver.due(Duration::ZERO));
        let (_, report) = receiver.report(Duration::ZERO);
        assert_eq!(
            Report::decode(&report.encode()).unwrap().bytes,
            REPORT_DATA_BYTES * 2
        );
        assert!(Report::decode(&report.encode()[..23]).is_none());
        receiver.receive(REPORT_DATA_BYTES as usize, true);
        assert!(!receiver.due(MIN_REPORT_INTERVAL - Duration::from_millis(1)));
        assert!(receiver.due(MIN_REPORT_INTERVAL));
    }

    #[test]
    fn delivery_estimate_rejects_replay_and_rebases_after_idle() {
        let mut observer = Observer::default();
        let now = Instant::now();
        let report = |elapsed_ms, bytes, packets| Report {
            elapsed_ms,
            bytes,
            packets,
        };
        let first = report(800, 125_000, 100);
        assert_eq!(observer.observe(1, first, now, 200_000, 110), None);
        let second = report(1050, 250_000, 200);
        assert_eq!(observer.observe(2, second, now, 240_000, 220), None);
        assert_eq!(observer.observe(2, second, now, 300_000, 220), Some(4000));
        assert_eq!(observer.observe(2, second, now, 300_000, 220), None);
        let idle = report(6_000, 375_000, 300);
        assert_eq!(observer.observe(3, idle, now, 400_000, 330), None);
        let resumed = report(6_250, 500_000, 400);
        assert_eq!(observer.observe(4, resumed, now, 510_000, 410), Some(4000));
    }
}
