//! Bounded, sampled successful-send / authenticated-arrival cohorts.
//! Counts describe sampled carrier packets, not extrapolated traffic or capacity.
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub(in crate::remote) const VERSION: u8 = 1;
const WINDOW: u64 = 256;
// The sender must retain a cohort beyond the receiver's bitmap window while
// its report is in flight. At high packet rates the bitmap spans under 100 ms.
const SEND_HISTORY: u64 = 2048;
const STRIDE: u64 = 16;
const MODULUS: u64 = 65536 / STRIDE;
const REORDER: Duration = Duration::from_millis(25);
const INTERVAL: Duration = Duration::from_millis(250);
const STALE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug)]
pub(in crate::remote) struct Ack {
    serial: u64,
    first: u64,
    tail: u64,
    bits: [u8; 32],
    arrival_ms: Option<u64>,
}

impl Ack {
    pub(in crate::remote) const LEN: usize = 56;
    pub(in crate::remote) const TIMED_LEN: usize = Self::LEN + 8;
    pub(in crate::remote) fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(if self.arrival_ms.is_some() {
            Self::TIMED_LEN
        } else {
            Self::LEN
        });
        for value in [self.serial, self.first, self.tail] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.bits);
        if let Some(arrival_ms) = self.arrival_ms {
            bytes.extend_from_slice(&arrival_ms.to_be_bytes());
        }
        bytes
    }
    pub(in crate::remote) fn decode(bytes: &[u8]) -> Option<Self> {
        let arrival_ms = match bytes.len() {
            Self::LEN => None,
            Self::TIMED_LEN => Some(u64::from_be_bytes(bytes[Self::LEN..].try_into().ok()?)),
            _ => return None,
        };
        let ack = Self {
            serial: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            first: u64::from_be_bytes(bytes[8..16].try_into().ok()?),
            tail: u64::from_be_bytes(bytes[16..24].try_into().ok()?),
            bits: bytes[24..Self::LEN].try_into().ok()?,
            arrival_ms,
        };
        ack.valid().then_some(ack)
    }
    fn valid(&self) -> bool {
        self.serial != 0
            && self.first <= self.tail
            && self.tail - self.first < WINDOW
            && self.has(self.tail)
            && (self.tail - self.first + 1..WINDOW)
                .all(|offset| self.bits[offset as usize / 8] & (1 << (offset % 8)) == 0)
    }
    fn has(&self, id: u64) -> bool {
        if id < self.first || id > self.tail {
            return false;
        }
        let offset = self.tail - id;
        self.bits[offset as usize / 8] & (1 << (offset % 8)) != 0
    }
}

// A jump of half the sequence space is ambiguous and is never interpreted as
// progress. Both sides start in the first observed sequence cycle; absent
// matching history after a very long silence produces no estimate.
fn extend(sequence: u16, high: Option<u64>) -> Option<u64> {
    if u64::from(sequence) % STRIDE != 0 {
        return None;
    }
    let raw = u64::from(sequence) / STRIDE;
    let Some(high) = high else {
        return Some(raw);
    };
    let forward = (raw + MODULUS - high % MODULUS) % MODULUS;
    if forward == MODULUS / 2 {
        return None;
    }
    if forward < MODULUS / 2 {
        high.checked_add(forward)
    } else {
        high.checked_sub(MODULUS - forward)
    }
}

#[derive(Default)]
pub(in crate::remote) struct Receiver {
    high: Option<u64>,
    arrivals: VecDeque<(u64, Instant)>,
    next: Option<Instant>,
    serial: u64,
    reported_tail: Option<u64>,
    clock_origin: Option<Instant>,
}
impl Receiver {
    pub(in crate::remote) fn new(clock_origin: Option<Instant>) -> Self {
        Self {
            clock_origin,
            ..Self::default()
        }
    }

    pub(in crate::remote) fn record(&mut self, sequence: u16, now: Instant) {
        let Some(id) = extend(sequence, self.high) else {
            return;
        };
        let high = self.high.unwrap_or(id).max(id);
        if high - id >= WINDOW || self.arrivals.iter().any(|&(old, _)| old == id) {
            return;
        }
        self.high = Some(high);
        self.arrivals.retain(|&(old, _)| high - old < WINDOW);
        self.arrivals.push_back((id, now));
    }
    fn tail(&self, now: Instant) -> Option<(u64, Instant)> {
        self.arrivals
            .iter()
            .filter(|&&(_, at)| now.saturating_duration_since(at) >= REORDER)
            .max_by_key(|&&(id, _)| id)
            .copied()
    }
    pub(in crate::remote) fn due(&self, now: Instant) -> bool {
        self.next.is_none_or(|next| now >= next)
            && self.high > self.reported_tail
            && self.tail(now).is_some_and(|(tail, _)| {
                self.reported_tail.is_none_or(|old| tail > old)
                    && self.arrivals.iter().filter(|&&(id, _)| id <= tail).count() >= 2
            })
    }
    pub(in crate::remote) fn take_ack(&mut self, now: Instant) -> Option<Ack> {
        if !self.due(now) {
            return None;
        }
        let (tail, arrival) = self.tail(now)?;
        let first = self.arrivals.iter().map(|&(id, _)| id).min()?;
        self.serial = self.serial.checked_add(1)?;
        let mut ack = Ack {
            serial: self.serial,
            first,
            tail,
            bits: [0; 32],
            arrival_ms: self
                .clock_origin
                .map(|origin| arrival.saturating_duration_since(origin).as_millis() as u64),
        };
        for &(id, _) in &self.arrivals {
            if id <= tail {
                let offset = tail - id;
                ack.bits[offset as usize / 8] |= 1 << (offset % 8);
            }
        }
        self.next = Some(now + INTERVAL);
        self.reported_tail = Some(tail);
        Some(ack)
    }
}

struct Sent {
    id: u64,
    bytes: usize,
    at: Instant,
}
#[derive(Default)]
pub(in crate::remote) struct Sender {
    high: Option<u64>,
    sent: VecDeque<Sent>,
    serial: u64,
    covered: Option<u64>,
    clock_origin: Option<Instant>,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(in crate::remote) struct Sample {
    pub(in crate::remote) sent_packets: u64,
    pub(in crate::remote) received_packets: u64,
    pub(in crate::remote) sent_bytes: u64,
    pub(in crate::remote) received_bytes: u64,
    pub(in crate::remote) span_ms: u64,
    pub(in crate::remote) send_start_age_ms: u64,
    pub(in crate::remote) send_end_age_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::remote) forward_delay_offset_ms: Option<i64>,
}
impl Sender {
    pub(in crate::remote) fn new(clock_origin: Option<Instant>) -> Self {
        Self {
            clock_origin,
            ..Self::default()
        }
    }

    /// Call only after the socket accepted this entire datagram.
    pub(in crate::remote) fn record(&mut self, sequence: u16, wire_bytes: usize, now: Instant) {
        let Some(id) = extend(sequence, self.high) else {
            return;
        };
        if self.high.is_some_and(|high| id <= high) {
            return;
        }
        self.high = Some(id);
        while self.sent.front().is_some_and(|old| {
            id - old.id >= SEND_HISTORY || now.saturating_duration_since(old.at) > STALE
        }) {
            self.sent.pop_front();
        }
        self.sent.push_back(Sent {
            id,
            bytes: wire_bytes,
            at: now,
        });
    }
    pub(in crate::remote) fn observe(&mut self, ack: Ack, now: Instant) -> Option<Sample> {
        if !ack.valid()
            || ack.arrival_ms.is_some() != self.clock_origin.is_some()
            || ack.serial <= self.serial
            || self.high.is_none_or(|high| ack.tail > high)
            || self.covered.is_some_and(|old| ack.tail <= old)
        {
            return None;
        }
        // Anchor the report to an actually sent packet still in bounded history.
        let anchor = self.sent.iter().find(|sent| sent.id == ack.tail)?;
        let age = now.saturating_duration_since(anchor.at);
        if !(REORDER..=STALE).contains(&age) {
            return None;
        }
        self.serial = ack.serial;
        let mut cohort = self.sent.iter().filter(|sent| {
            sent.id >= ack.first
                && sent.id <= ack.tail
                && self.covered.is_none_or(|old| sent.id > old)
        });
        let head = cohort.next()?;
        let first = head.at;
        let last = anchor.at;
        let span_ms = last.saturating_duration_since(first).as_millis() as u64;
        if span_ms == 0 || now.saturating_duration_since(first) > STALE {
            return None;
        }
        let mut sample = Sample {
            sent_packets: 0,
            received_packets: 0,
            sent_bytes: 0,
            received_bytes: 0,
            span_ms,
            send_start_age_ms: now.saturating_duration_since(first).as_millis() as u64,
            send_end_age_ms: age.as_millis() as u64,
            forward_delay_offset_ms: self.clock_origin.zip(ack.arrival_ms).and_then(
                |(origin, arrival)| {
                    let sent = anchor.at.saturating_duration_since(origin).as_millis() as i128;
                    i64::try_from(i128::from(arrival) - sent).ok()
                },
            ),
        };
        for sent in std::iter::once(head).chain(cohort) {
            sample.sent_packets += 1;
            sample.sent_bytes += sent.bytes as u64;
            if ack.has(sent.id) {
                sample.received_packets += 1;
                sample.received_bytes += sent.bytes as u64;
            }
        }
        self.covered = Some(ack.tail);
        Some(sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matched_loss_reorder_replay_and_wire_roundtrip() {
        let now = Instant::now();
        let mut tx = Sender::default();
        let mut rx = Receiver::default();
        for i in 0..4 {
            tx.record(
                i * 16,
                100 + i as usize,
                now + Duration::from_millis(i as u64 * 10),
            );
        }
        rx.record(0, now);
        rx.record(48, now + Duration::from_millis(30));
        assert!(!rx.due(now + Duration::from_millis(31)));
        rx.record(16, now + Duration::from_millis(40));
        let ack = rx.take_ack(now + Duration::from_millis(70)).unwrap();
        let ack = Ack::decode(&ack.encode()).unwrap();
        let sample = tx.observe(ack, now + Duration::from_millis(75)).unwrap();
        assert_eq!((sample.sent_packets, sample.received_packets), (4, 3));
        assert_eq!(
            (sample.sent_bytes, sample.received_bytes, sample.span_ms),
            (406, 304, 30)
        );
        assert!(tx.observe(ack, now + Duration::from_millis(80)).is_none());
        assert!(!rx.due(now + Duration::from_millis(80)));
    }

    #[test]
    fn timed_ack_excludes_reverse_path_delay_and_clock_origin_difference() {
        let tx_start = Instant::now();
        let rx_start = tx_start + Duration::from_millis(20);
        let mut tx = Sender::new(Some(tx_start));
        let mut rx = Receiver::new(Some(rx_start));
        for (batch, forward_ms, return_ms) in [(0u16, 45, 30), (1, 45, 150), (2, 80, 30)] {
            let sent = tx_start + Duration::from_millis(u64::from(batch) * 400 + 40);
            let last_sent = sent + Duration::from_millis(5);
            let last_received = last_sent + Duration::from_millis(forward_ms);
            tx.record(batch * 32, 100, sent);
            tx.record(batch * 32 + 16, 100, last_sent);
            rx.record(batch * 32, sent + Duration::from_millis(forward_ms));
            rx.record(batch * 32 + 16, last_received);
            let ack_at = last_received + REORDER;
            let ack = rx.take_ack(ack_at).unwrap();
            let encoded = ack.encode();
            assert_eq!(encoded.len(), Ack::TIMED_LEN);
            let sample = tx
                .observe(
                    Ack::decode(&encoded).unwrap(),
                    ack_at + Duration::from_millis(return_ms),
                )
                .unwrap();
            assert_eq!(sample.forward_delay_offset_ms, Some(forward_ms as i64 - 20));
        }
    }
    #[test]
    fn wraps_are_unique_and_history_is_bounded() {
        let now = Instant::now();
        let mut tx = Sender::default();
        let mut rx = Receiver::default();
        for i in 0..600u64 {
            let seq = (65504u64 + i * 16) as u16;
            let at = now + Duration::from_millis(i);
            tx.record(seq, 100, at);
            rx.record(seq, at);
            rx.record(seq, at);
        }
        assert_eq!(tx.sent.len(), 600);
        assert_eq!(rx.arrivals.len(), 256);
        let at = now + Duration::from_millis(650);
        let ack = rx.take_ack(at).unwrap();
        let sample = tx.observe(ack, at).unwrap();
        assert_eq!((sample.sent_packets, sample.received_packets), (256, 256));
    }

    #[test]
    fn sender_retains_the_bitmap_cohort_while_feedback_is_in_flight() {
        let now = Instant::now();
        let mut tx = Sender::default();
        let mut rx = Receiver::default();
        for id in 0..1_200u64 {
            let sequence = (id * STRIDE) as u16;
            let at = now + Duration::from_micros(id * 100);
            tx.record(sequence, 100, at);
            if id < 600 {
                rx.record(sequence, at);
            }
        }
        let ack = rx.take_ack(now + Duration::from_millis(90)).unwrap();
        let sample = tx.observe(ack, now + Duration::from_millis(130)).unwrap();
        assert_eq!((sample.sent_packets, sample.received_packets), (256, 256));
        assert!(sample.send_start_age_ms > sample.send_end_age_ms);
        for id in 1_200..3_000u64 {
            tx.record(
                (id * STRIDE) as u16,
                100,
                now + Duration::from_micros(id * 100),
            );
        }
        assert_eq!(tx.sent.len(), SEND_HISTORY as usize);
    }
    #[test]
    fn rejects_stale_unknown_and_malformed_reports() {
        let now = Instant::now();
        let mut tx = Sender::default();
        let mut rx = Receiver::default();
        for i in 0..2 {
            let at = now + Duration::from_millis(i);
            tx.record(i as u16 * 16, 100, at);
            rx.record(i as u16 * 16, at);
        }
        let ack = rx.take_ack(now + REORDER + INTERVAL).unwrap();
        assert!(Sender::default().observe(ack, now + INTERVAL).is_none());
        assert!(tx.observe(ack, now + STALE + INTERVAL).is_none());
        assert!(Ack::decode(&[0; Ack::LEN]).is_none());
        assert!(Ack::decode(&ack.encode()[..Ack::LEN - 1]).is_none());
    }

    #[test]
    fn young_tail_waits_and_later_reports_do_not_recount_old_cohorts() {
        let now = Instant::now();
        let mut tx = Sender::default();
        let mut rx = Receiver::default();
        for i in 0..3u64 {
            let at = now + Duration::from_millis(i * 20);
            tx.record(i as u16 * 16, 100, at);
            rx.record(i as u16 * 16, at);
        }
        let first_at = now + Duration::from_millis(50);
        let ack = rx.take_ack(first_at).unwrap();
        assert_eq!(ack.tail, 1);
        assert_eq!(tx.observe(ack, first_at).unwrap().sent_packets, 2);
        for i in 3..5u64 {
            let at = now + Duration::from_millis(200 + i * 10);
            tx.record(i as u16 * 16, 100, at);
            rx.record(i as u16 * 16, at);
        }
        assert!(!rx.due(first_at + INTERVAL - Duration::from_millis(1)));
        let next_at = first_at + INTERVAL;
        let ack = rx.take_ack(next_at).unwrap();
        let sample = tx.observe(ack, next_at).unwrap();
        assert_eq!((sample.sent_packets, sample.received_packets), (3, 3));
    }
}
