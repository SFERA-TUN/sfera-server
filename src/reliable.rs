//! Selective repeat for one ordered flow. No timers or sockets owned here.
use crate::wire::{ACK_BYTES, Frame, Kind, MAX_ACK_BYTES, MAX_DATA};
use anyhow::{Result, bail, ensure};
use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
};

pub const WINDOW: usize = ACK_BYTES * 8;
pub const QUEUE: usize = 1024;
// Unknown paths must permit an unambiguous initial sample before retransmitting.
pub const RTO: Duration = Duration::from_secs(1);
const REORDER_GRACE: Duration = Duration::from_millis(20);
const MAX_ATTEMPTS: u32 = 40;

struct Pending {
    data: Vec<u8>,
    sent: Duration,
    attempts: u32,
    newer_acked: u8,
}

pub struct Sender {
    flow: u32,
    window: usize,
    next: u32,
    queue: VecDeque<Vec<u8>>,
    flight: BTreeMap<u32, Pending>,
    pub retransmits: u64,
    pub fast_retransmits: u64,
    fixed_rto: Option<Duration>,
    estimated_rto: Duration,
    srtt: Option<f64>,
    rtt_variation: f64,
    last_rtt_sample: Option<Duration>,
}

impl Sender {
    pub fn new(flow: u32) -> Result<Self> {
        Self::with_window(flow, WINDOW)
    }
    pub fn with_window(flow: u32, window: usize) -> Result<Self> {
        ensure!(flow != 0, "zero flow");
        validate_window(window)?;
        Ok(Self {
            flow,
            window,
            next: 1,
            queue: VecDeque::new(),
            flight: BTreeMap::new(),
            retransmits: 0,
            fast_retransmits: 0,
            fixed_rto: None,
            estimated_rto: RTO,
            srtt: None,
            rtt_variation: 0.0,
            last_rtt_sample: None,
        })
    }
    pub fn can_enqueue(&self) -> bool {
        self.queue.len() < QUEUE
    }
    pub fn set_fixed_rto(&mut self, value: Duration) -> Result<()> {
        ensure!(
            (Duration::from_millis(10)..=Duration::from_secs(5)).contains(&value),
            "fixed RTO must be 10..5000 ms"
        );
        self.fixed_rto = Some(value);
        Ok(())
    }
    pub fn current_rto(&self) -> Duration {
        self.fixed_rto.unwrap_or(self.estimated_rto)
    }
    pub fn enqueue(&mut self, data: &[u8]) -> Result<()> {
        ensure!(
            !data.is_empty() && data.len() <= MAX_DATA,
            "invalid block length"
        );
        ensure!(self.can_enqueue(), "send queue full");
        self.queue.push_back(data.to_vec());
        Ok(())
    }
    pub fn idle(&self) -> bool {
        self.queue.is_empty() && self.flight.is_empty()
    }
    /// Call only when a carrier slot large enough for MAX_DATA is available.
    pub fn next_frame(&mut self, now: Duration) -> Result<Option<Frame>> {
        let rto = self.current_rto();
        for (&seq, pending) in &mut self.flight {
            let age = now.saturating_sub(pending.sent);
            // Do not fast-retransmit a retransmission:
            // ACKs already in flight could otherwise create a repeat storm.
            let fast = pending.attempts == 1 && pending.newer_acked >= 3 && age >= REORDER_GRACE;
            if age >= rto || fast {
                ensure!(
                    pending.attempts < MAX_ATTEMPTS,
                    "retransmission budget exhausted"
                );
                pending.sent = now;
                pending.attempts += 1;
                self.retransmits += 1;
                self.fast_retransmits += u64::from(fast);
                pending.newer_acked = 0;
                return Ok(Some(Frame {
                    kind: Kind::Data,
                    flow: self.flow,
                    sequence: seq,
                    payload: pending.data.clone(),
                }));
            }
        }
        let base = self
            .flight
            .first_key_value()
            .map(|(&s, _)| s)
            .unwrap_or(self.next);
        if self.next - base >= self.window as u32 || self.queue.is_empty() {
            return Ok(None);
        }
        ensure!(
            self.next < u32::MAX,
            "sequence exhausted; new session required"
        );
        let data = self.queue.pop_front().expect("queue checked");
        let seq = self.next;
        self.next += 1;
        self.flight.insert(
            seq,
            Pending {
                data: data.clone(),
                sent: now,
                attempts: 1,
                newer_acked: 0,
            },
        );
        Ok(Some(Frame {
            kind: Kind::Data,
            flow: self.flow,
            sequence: seq,
            payload: data,
        }))
    }
    pub fn acknowledge(&mut self, frame: &Frame) -> Result<()> {
        self.acknowledge_inner(frame, None)
    }
    pub fn acknowledge_at(&mut self, frame: &Frame, now: Duration) -> Result<()> {
        self.acknowledge_inner(frame, Some(now))
    }
    fn acknowledge_inner(&mut self, frame: &Frame, now: Option<Duration>) -> Result<()> {
        ensure!(
            frame.kind == Kind::Ack
                && frame.flow == self.flow
                && frame.payload.len() == self.window / 8,
            "invalid ACK"
        );
        ensure!(
            frame.sequence > 0 && frame.sequence <= self.next,
            "ACK for unsent data"
        );
        let bit_set = |offset: usize| frame.payload[offset / 8] & (1 << (offset % 8)) != 0;
        ensure!(!bit_set(0), "ACK base must be the first missing block");
        // Validate the entire ACK before releasing any pending data.
        for bit in 0..self.window {
            if bit_set(bit) {
                ensure!(
                    frame.sequence as u64 + (bit as u64) < self.next as u64,
                    "ACK bitmap covers unsent data"
                );
            }
        }
        let acknowledged = |seq: u32| {
            seq < frame.sequence || {
                let offset = (seq - frame.sequence) as usize;
                offset < self.window && bit_set(offset)
            }
        };
        let newly_acked: Vec<u32> = self
            .flight
            .keys()
            .copied()
            .filter(|s| acknowledged(*s))
            .collect();
        if let Some(now) = now {
            // Karn's rule: exclude retransmitted blocks. At most one update per
            // estimated RTT avoids rapidly forgetting variance on dense ACKs.
            let sample = newly_acked
                .iter()
                .filter_map(|seq| {
                    let pending = &self.flight[seq];
                    if pending.attempts == 1 {
                        now.checked_sub(pending.sent)
                    } else {
                        None
                    }
                })
                .max();
            if let Some(sample) = sample
                && self.last_rtt_sample.is_none_or(|last| {
                    now.saturating_sub(last).as_secs_f64() >= self.srtt.unwrap_or(0.0)
                })
            {
                let sample = sample.as_secs_f64();
                if let Some(srtt) = self.srtt {
                    self.rtt_variation = 0.75 * self.rtt_variation + 0.25 * (srtt - sample).abs();
                    self.srtt = Some(0.875 * srtt + 0.125 * sample);
                } else {
                    self.srtt = Some(sample);
                    self.rtt_variation = sample / 2.0;
                }
                // Laboratory bounds, NOT RFC6298 TCP timer compliance.
                let srtt = self.srtt.unwrap();
                self.estimated_rto = Duration::from_secs_f64(
                    (srtt + (4.0 * self.rtt_variation).max(0.001))
                        .max(2.0 * srtt + 0.025)
                        .clamp(0.100, 2.0),
                );
                self.last_rtt_sample = Some(now);
            }
        }
        self.flight.retain(|&seq, _| !acknowledged(seq));
        // Only newly acknowledged blocks count: duplicated/stale ACKs cannot
        // manufacture evidence of loss or repeatedly trigger fast retransmits.
        for (&seq, pending) in &mut self.flight {
            let count = newly_acked.len() - newly_acked.partition_point(|s| *s <= seq);
            pending.newer_acked = (pending.newer_acked as usize + count).min(3) as u8;
        }
        Ok(())
    }
}

pub struct Receiver {
    flow: u32,
    window: usize,
    next: u32,
    pending: BTreeMap<u32, Vec<u8>>,
}

impl Receiver {
    pub fn new(flow: u32) -> Result<Self> {
        Self::with_window(flow, WINDOW)
    }
    pub fn with_window(flow: u32, window: usize) -> Result<Self> {
        ensure!(flow != 0, "zero flow");
        validate_window(window)?;
        Ok(Self {
            flow,
            window,
            next: 1,
            pending: BTreeMap::new(),
        })
    }
    /// An ACK means accepted into this bounded receiver, not consumed by an app.
    /// Production flows need downstream credit in addition to this window.
    pub fn accept(&mut self, frame: Frame) -> Result<(Frame, Vec<Vec<u8>>)> {
        ensure!(
            frame.kind == Kind::Data && frame.flow == self.flow,
            "wrong reliable flow"
        );
        ensure!(
            frame.sequence > 0 && frame.sequence < u32::MAX,
            "invalid sequence"
        );
        ensure!(
            !frame.payload.is_empty() && frame.payload.len() <= MAX_DATA,
            "invalid data"
        );
        if frame.sequence >= self.next && frame.sequence - self.next >= self.window as u32 {
            bail!("outside receive window");
        }
        if frame.sequence >= self.next {
            self.pending.entry(frame.sequence).or_insert(frame.payload);
        }
        let mut delivered = Vec::new();
        while let Some(data) = self.pending.remove(&self.next) {
            delivered.push(data);
            self.next += 1;
        }
        let mut bitmap = vec![0u8; self.window / 8];
        for &seq in self.pending.keys() {
            let offset = (seq - self.next) as usize;
            bitmap[offset / 8] |= 1 << (offset % 8);
        }
        let ack = Frame {
            kind: Kind::Ack,
            flow: self.flow,
            sequence: self.next,
            payload: bitmap,
        };
        Ok((ack, delivered))
    }
}

fn validate_window(window: usize) -> Result<()> {
    ensure!(
        (32..=MAX_ACK_BYTES * 8).contains(&window) && window.is_power_of_two(),
        "window must be a power of two in 32..4096"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_slow_path_can_bootstrap_rtt_without_karn_starvation() -> Result<()> {
        let mut tx = Sender::new(1)?;
        let mut rx = Receiver::new(1)?;
        tx.enqueue(b"slow path")?;
        let data = tx.next_frame(Duration::ZERO)?.unwrap();
        assert!(tx.next_frame(Duration::from_millis(250))?.is_none());
        tx.acknowledge_at(&rx.accept(data)?.0, Duration::from_millis(300))?;
        assert!((tx.current_rto().as_secs_f64() - 0.9).abs() < 1e-8);
        assert_eq!(tx.retransmits, 0);
        Ok(())
    }
    #[test]
    fn larger_window_handles_sparse_receipts_and_rejects_mismatched_ack() -> Result<()> {
        let mut tx = Sender::with_window(1, 2048)?;
        let mut rx = Receiver::with_window(1, 2048)?;
        let mut last = None;
        for _ in 0..2048 {
            tx.enqueue(b"x")?;
            last = tx.next_frame(Duration::ZERO)?;
        }
        let (ack, _) = rx.accept(last.unwrap())?;
        assert_eq!(ack.payload.len(), 256);
        assert_eq!(ack.payload[255], 0x80);
        tx.acknowledge(&ack)?;
        let wrong = Frame {
            payload: vec![0; ACK_BYTES],
            ..ack
        };
        assert!(tx.acknowledge(&wrong).is_err());
        assert!(Sender::with_window(1, 513).is_err());
        assert!(Receiver::with_window(1, 8192).is_err());
        Ok(())
    }
    #[test]
    fn rtt_estimator_ignores_retransmissions_and_respects_fixed_override() -> Result<()> {
        let mut tx = Sender::new(1)?;
        let mut rx = Receiver::new(1)?;
        tx.enqueue(b"first")?;
        let data = tx.next_frame(Duration::ZERO)?.unwrap();
        tx.acknowledge_at(&rx.accept(data)?.0, Duration::from_millis(40))?;
        assert_eq!(tx.current_rto(), Duration::from_millis(120));
        tx.enqueue(b"lost")?;
        tx.next_frame(Duration::from_millis(40))?;
        let retry = tx.next_frame(Duration::from_millis(160))?.unwrap();
        tx.acknowledge_at(&rx.accept(retry)?.0, Duration::from_millis(170))?;
        assert_eq!(tx.current_rto(), Duration::from_millis(120));
        tx.set_fixed_rto(Duration::from_millis(80))?;
        assert_eq!(tx.current_rto(), Duration::from_millis(80));
        assert!(tx.set_fixed_rto(Duration::ZERO).is_err());
        Ok(())
    }
    #[test]
    fn fast_recovery_requires_distinct_later_receipts_and_reorder_grace() -> Result<()> {
        let mut tx = Sender::new(1)?;
        let mut rx = Receiver::new(1)?;
        for _ in 0..4 {
            tx.enqueue(b"x")?;
        }
        let missing = tx.next_frame(Duration::ZERO)?.unwrap();
        let mut ack = None;
        for _ in 0..3 {
            let f = tx.next_frame(Duration::ZERO)?.unwrap();
            ack = Some(rx.accept(f)?.0);
        }
        let ack = ack.unwrap();
        tx.acknowledge(&ack)?;
        assert!(tx.next_frame(REORDER_GRACE / 2)?.is_none());
        assert_eq!(tx.next_frame(REORDER_GRACE)?.unwrap(), missing);
        for _ in 0..10 {
            tx.acknowledge(&ack)?;
        }
        assert!(tx.next_frame(REORDER_GRACE * 2)?.is_none());
        assert_eq!(tx.fast_retransmits, 1);
        tx.acknowledge(&rx.accept(missing)?.0)?;
        assert!(tx.idle());
        Ok(())
    }
    #[test]
    fn selective_bitmap_acknowledges_the_far_end_of_window() -> Result<()> {
        let mut tx = Sender::new(1)?;
        let mut rx = Receiver::new(1)?;
        for _ in 0..WINDOW {
            tx.enqueue(b"x")?;
        }
        let mut last = None;
        for _ in 0..WINDOW {
            last = tx.next_frame(Duration::ZERO)?;
        }
        let (ack, data) = rx.accept(last.unwrap())?;
        assert!(data.is_empty());
        assert_eq!(ack.payload[ACK_BYTES - 1], 0x80);
        tx.acknowledge(&ack)?;
        assert_eq!(tx.flight.len(), WINDOW - 1);
        Ok(())
    }
    #[test]
    fn loss_reordering_duplicate_data_and_ack() -> Result<()> {
        let mut tx = Sender::new(1)?;
        let mut rx = Receiver::new(1)?;
        tx.enqueue(b"first")?;
        tx.enqueue(b"second")?;
        let first = tx.next_frame(Duration::ZERO)?.unwrap();
        let second = tx.next_frame(Duration::ZERO)?.unwrap();
        let (ack2, data) = rx.accept(second.clone())?;
        assert!(data.is_empty());
        tx.acknowledge(&ack2)?;
        assert!(rx.accept(second)?.1.is_empty());
        assert!(tx.next_frame(RTO / 2)?.is_none());
        let retry = tx.next_frame(RTO)?.unwrap();
        assert_eq!(retry, first);
        let (ack1, data) = rx.accept(retry.clone())?;
        assert_eq!(data, vec![b"first".to_vec(), b"second".to_vec()]);
        assert!(rx.accept(retry)?.1.is_empty());
        tx.acknowledge(&ack1)?;
        tx.acknowledge(&ack1)?;
        assert!(tx.idle());
        assert_eq!(tx.retransmits, 1);
        Ok(())
    }
    #[test]
    fn bounded_queues_and_window() -> Result<()> {
        let mut tx = Sender::new(1)?;
        for _ in 0..QUEUE {
            tx.enqueue(b"x")?;
        }
        assert!(tx.enqueue(b"x").is_err());
        let mut sparse = Receiver::new(1)?;
        for i in 0..WINDOW {
            let f = tx.next_frame(Duration::ZERO)?.unwrap();
            if i != 0 {
                tx.acknowledge(&sparse.accept(f)?.0)?;
            }
        }
        assert!(
            tx.next_frame(Duration::ZERO)?.is_none(),
            "a hole must hold the window"
        );
        let mut rx = Receiver::new(1)?;
        assert!(
            rx.accept(Frame {
                kind: Kind::Data,
                flow: 1,
                sequence: WINDOW as u32 + 1,
                payload: vec![1]
            })
            .is_err()
        );
        assert!(
            tx.acknowledge(&Frame {
                kind: Kind::Ack,
                flow: 1,
                sequence: WINDOW as u32 + 100,
                payload: vec![0; ACK_BYTES]
            })
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn permanent_loss_terminates() -> Result<()> {
        let mut tx = Sender::new(1)?;
        tx.enqueue(b"x")?;
        for i in 0..MAX_ATTEMPTS {
            assert!(tx.next_frame(RTO * i)?.is_some());
        }
        assert!(tx.next_frame(RTO * MAX_ATTEMPTS).is_err());
        Ok(())
    }
    #[test]
    fn invalid_bitmap_does_not_release_pending_data() -> Result<()> {
        let mut tx = Sender::new(1)?;
        tx.enqueue(b"one")?;
        let first = tx.next_frame(Duration::ZERO)?.unwrap();
        let invalid = Frame {
            kind: Kind::Ack,
            flow: 1,
            sequence: 2,
            payload: {
                let mut bits = vec![0; ACK_BYTES];
                bits[0] = 2;
                bits
            },
        };
        assert!(tx.acknowledge(&invalid).is_err());
        assert_eq!(tx.next_frame(RTO)?.unwrap(), first);
        Ok(())
    }
}
