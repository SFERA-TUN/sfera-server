//! Session-local, unordered, best-effort repair. The carrier authenticates requests.
//! Callers pace repairs and validate IP bytes; this module never waits for a gap.
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub(super) const MAX_AGE: Duration = Duration::from_millis(150);
const SHORT_CACHE_AGE: Duration = Duration::from_millis(450);
const EXTENDED_CACHE_AGE: Duration = Duration::from_millis(900);
const HIGH_LATE_FLOOR: Duration = Duration::from_millis(400);
const HIGH_LATE_HORIZON: Duration = Duration::from_millis(700);
const HIGH_FOURTH_FLOOR: Duration = Duration::from_millis(600);
const HIGH_FOURTH_HORIZON: Duration = Duration::from_millis(900);
const SHORT_FOLLOWUP_HORIZON: Duration = Duration::from_millis(300);
const LATE_REQUEST_FLOOR: Duration = Duration::from_millis(200);
const RTT_FRESHNESS: Duration = Duration::from_secs(3);
const EXTENDED_RETRY_HORIZON: Duration = Duration::from_millis(500);
const EXTENDED_RTT_MIN: Duration = Duration::from_millis(100);
const EXTENDED_RTT_MAX: Duration = Duration::from_millis(200);
const MAX_ENTRIES: usize = 2048;
const MAX_BYTES: usize = 2 * 1024 * 1024;
const GRACE: Duration = Duration::from_millis(3);
const REPAIR_QUIET: Duration = Duration::from_millis(8);
const MAX_REPAIR_DEFER: Duration = Duration::from_millis(16);
const BITS: usize = 256;

fn fresh_high(now: Instant, sample: Option<(Duration, Instant)>) -> bool {
    sample.is_some_and(|(rtt, at)| {
        now >= at && now.duration_since(at) < RTT_FRESHNESS && extended_rtt(Some(rtt)).is_some()
    })
}

pub(super) fn short_rtt(rtt: Option<Duration>) -> bool {
    rtt.is_some_and(|rtt| !rtt.is_zero() && rtt < EXTENDED_RTT_MIN)
}

pub(super) fn extended_rtt(rtt: Option<Duration>) -> Option<Duration> {
    rtt.filter(|rtt| (EXTENDED_RTT_MIN..=EXTENDED_RTT_MAX).contains(rtt))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Request {
    base: u32,
    bitmap: [u8; BITS / 8],
}

impl Request {
    pub(super) const ENCODED_LEN: usize = 4 + BITS / 8;

    pub(super) fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0; Self::ENCODED_LEN];
        bytes[..4].copy_from_slice(&self.base.to_be_bytes());
        bytes[4..].copy_from_slice(&self.bitmap);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN || bytes[4..].iter().all(|&b| b == 0) {
            return None;
        }
        Some(Self {
            base: u32::from_be_bytes(bytes[..4].try_into().ok()?),
            bitmap: bytes[4..].try_into().ok()?,
        })
    }

    fn sequences(&self) -> impl Iterator<Item = u32> + '_ {
        (0..BITS)
            .filter(|&bit| self.bitmap[bit / 8] & (1 << (bit % 8)) != 0)
            .map(|bit| self.base.wrapping_add(bit as u32))
    }
}

struct Cached {
    // Fixed when the original is cached; RTT promotion never upgrades old entries.
    fourth_eligible: bool,
    expires: Instant,
    packet: Vec<u8>,
    attempt: Attempt,
}

enum Attempt {
    Original,
    FirstQueued(u32),
    FirstSent(u32),
    RetryQueued(u32),
    SecondSent(u32),
    ThirdQueued(u32),
    ThirdSent(u32),
    FourthQueued,
}

#[derive(Default)]
pub(super) struct Sender {
    cache: HashMap<u32, Cached>,
    order: VecDeque<u32>,
    pending: VecDeque<u32>,
    bytes: usize,
    retention: Option<Duration>,
    current_rtt: Option<(Duration, Instant)>,
}

impl Sender {
    pub(super) fn observe_current_rtt(&mut self, rtt: Option<(Duration, Instant)>) {
        self.current_rtt = rtt;
    }

    fn third_allowed(&self, now: Instant) -> bool {
        self.current_rtt.is_some_and(|(rtt, at)| {
            now >= at
                && now.duration_since(at) < RTT_FRESHNESS
                && (short_rtt(Some(rtt)) || extended_rtt(Some(rtt)).is_some())
        })
    }

    fn fourth_allowed(&self, now: Instant) -> bool {
        fresh_high(now, self.current_rtt)
    }

    // Only the head can send. Keep the eligible path O(1), and retire
    // ineligible third/fourth repairs only as they reach the head.
    fn prune_ineligible_late_heads(&mut self, now: Instant) {
        let third = self.third_allowed(now);
        let fourth = self.fourth_allowed(now);
        if third && fourth {
            return;
        }
        while let Some(&seq) = self.pending.front() {
            match self.cache[&seq].attempt {
                Attempt::ThirdQueued(_) if !third => {}
                Attempt::FourthQueued if !fourth => {}
                _ => break,
            }
            self.pending.pop_front();
            let entry = self.cache.remove(&seq).expect("pending repair is cached");
            self.bytes -= entry.packet.len();
            self.order.retain(|&old| old != seq);
        }
    }

    pub(super) fn observe_rtt(&mut self, rtt: Duration) {
        let age = if rtt < EXTENDED_RTT_MIN {
            SHORT_CACHE_AGE
        } else if rtt <= EXTENDED_RTT_MAX {
            EXTENDED_CACHE_AGE
        } else {
            return;
        };
        // Retention only increases. Existing deadlines stay ordered and immutable.
        self.retention = Some(self.retention.unwrap_or(MAX_AGE).max(age));
    }

    /// Copies only the original packet retained for possible repair. Duplicate
    /// serials never replace cached content or renew its deadline.
    pub(super) fn remember(&mut self, now: Instant, seq: u32, packet: &[u8]) {
        self.expire(now);
        if packet.is_empty() || packet.len() > MAX_BYTES || self.cache.contains_key(&seq) {
            return;
        }
        while self.cache.len() >= MAX_ENTRIES || self.bytes + packet.len() > MAX_BYTES {
            if let Some(old) = self.order.pop_front() {
                self.remove(old);
            } else {
                break;
            }
        }
        self.bytes += packet.len();
        let age = self.retention.unwrap_or(MAX_AGE);
        self.cache.insert(
            seq,
            Cached {
                fourth_eligible: age == EXTENDED_CACHE_AGE,
                expires: now + age,
                packet: packet.to_vec(),
                attempt: Attempt::Original,
            },
        );
        self.order.push_back(seq);
    }

    /// Unknown, duplicate and expired requests allocate no packet storage.
    pub(super) fn request(&mut self, now: Instant, id: u32, request: &Request) {
        self.expire(now);
        let third_allowed = self.third_allowed(now);
        let fourth_allowed = self.fourth_allowed(now);
        for seq in request.sequences() {
            let Some(entry) = self.cache.get_mut(&seq) else {
                continue;
            };
            entry.attempt = match entry.attempt {
                Attempt::Original => Attempt::FirstQueued(id),
                Attempt::FirstSent(previous)
                    if (1..(1 << 31)).contains(&id.wrapping_sub(previous)) =>
                {
                    Attempt::RetryQueued(id)
                }
                Attempt::SecondSent(previous)
                    if third_allowed && (1..(1 << 31)).contains(&id.wrapping_sub(previous)) =>
                {
                    Attempt::ThirdQueued(id)
                }
                Attempt::ThirdSent(previous)
                    if fourth_allowed
                        && entry.fourth_eligible
                        && (1..(1 << 31)).contains(&id.wrapping_sub(previous)) =>
                {
                    Attempt::FourthQueued
                }
                _ => continue,
            };
            self.pending.push_back(seq);
        }
    }

    /// Inspect before reserving pacing credit.
    pub(super) fn peek_len(&mut self, now: Instant) -> Option<usize> {
        self.expire(now);
        self.prune_ineligible_late_heads(now);
        self.pending.front().map(|seq| self.cache[seq].packet.len())
    }

    /// Keep the original for a second repair, a fresh-RTT third, and a high-RTT fourth.
    /// Neither retention nor a request renews its original cache deadline.
    pub(super) fn next(&mut self, now: Instant) -> Option<(u32, Vec<u8>)> {
        self.expire(now);
        self.prune_ineligible_late_heads(now);
        let third_allowed = self.third_allowed(now);
        let fourth_allowed = self.fourth_allowed(now);
        let seq = self.pending.pop_front()?;
        let entry = self.cache.get_mut(&seq)?;
        if let Attempt::FirstQueued(id) = entry.attempt {
            entry.attempt = Attempt::FirstSent(id);
            return Some((seq, entry.packet.clone()));
        }
        if let Attempt::RetryQueued(id) = entry.attempt
            && third_allowed
        {
            entry.attempt = Attempt::SecondSent(id);
            return Some((seq, entry.packet.clone()));
        }
        if let Attempt::ThirdQueued(id) = entry.attempt
            && fourth_allowed
            && entry.fourth_eligible
        {
            entry.attempt = Attempt::ThirdSent(id);
            return Some((seq, entry.packet.clone()));
        }
        let entry = self.cache.remove(&seq)?;
        self.bytes -= entry.packet.len();
        self.order.retain(|&old| old != seq);
        Some((seq, entry.packet))
    }

    fn remove(&mut self, seq: u32) {
        if let Some(entry) = self.cache.remove(&seq) {
            self.bytes -= entry.packet.len();
        }
        self.pending.retain(|&old| old != seq);
    }

    fn expire(&mut self, now: Instant) {
        while let Some(&seq) = self.order.front() {
            if now < self.cache[&seq].expires {
                break;
            }
            self.order.pop_front();
            self.remove(seq);
        }
    }
}

struct Seen {
    seq: u32,
    missing: Option<Missing>,
}

struct Missing {
    discovered: Instant,
    expires: Instant,
    next_request: Instant,
    stage: RequestStage,
}

#[derive(Clone, Copy)]
enum RequestStage {
    Initial,
    RetryWithFollowup { horizon: Instant },
    FollowupWithLate { horizon: Instant },
    LateLast,
    HighRetryWithLate,
    HighLast,
    HighFourth,
    Last,
}

#[derive(Default)]
pub(super) struct Receiver {
    history: VecDeque<Seen>,
    last_request: Option<Instant>,
    last_repair: Option<Instant>,
    next_scan: Option<Instant>,
    current_rtt: Option<(Duration, Instant)>,
}

impl Receiver {
    pub(super) fn observe_current_rtt(&mut self, sample: Option<(Duration, Instant)>) {
        self.current_rtt = sample;
    }

    /// Call only for a fully reassembled, valid original/repair IP datagram.
    /// True means deliver immediately, including out of order. False means
    /// duplicate, outside the history, or an ambiguous half-range serial.
    pub(super) fn receive(&mut self, now: Instant, seq: u32) -> bool {
        if let Some(latest) = self.history.back() {
            let advance = seq.wrapping_sub(latest.seq);
            if advance == 0 || advance >= (1u32 << 31) {
                let first = self.history.front().expect("nonempty history").seq;
                let index = seq.wrapping_sub(first) as usize;
                if let Some(entry) = self.history.get_mut(index) {
                    return entry.missing.take().is_some();
                }
                return false;
            }
            // A discontinuity cannot allocate unbounded gap state. Forget old
            // history and start a fresh window without requesting the huge gap.
            if advance >= MAX_ENTRIES as u32 {
                self.history.clear();
                self.next_scan = None;
                self.last_repair = None;
            } else {
                let previous = latest.seq;
                for offset in 1..advance {
                    self.mark_missing(now, previous.wrapping_add(offset));
                }
            }
        } else if seq < MAX_ENTRIES as u32 {
            // The first original uses serial one in every session.
            for missing in 1..seq {
                self.mark_missing(now, missing);
            }
        }
        self.make_room();
        self.history.push_back(Seen { seq, missing: None });
        true
    }

    /// An authenticated end-of-frame packet also reveals losses at the tail
    /// of a traffic burst, even if no subsequent original arrives.
    pub(super) fn observe_sent(&mut self, now: Instant, highest: u32) {
        let previous = self.history.back().map_or(0, |entry| entry.seq);
        let advance = highest.wrapping_sub(previous);
        if highest == 0 || advance >= MAX_ENTRIES as u32 {
            return;
        }
        for offset in 1..=advance {
            self.mark_missing(now, previous.wrapping_add(offset));
        }
    }

    fn mark_missing(&mut self, now: Instant, seq: u32) {
        self.make_room();
        // Zero is reserved by the carrier. Keep its history position for
        // constant-time indexing across rollover, without requesting it.
        let missing = (seq != 0).then(|| {
            let next_request = now + GRACE;
            self.schedule_scan(next_request);
            Missing {
                discovered: now,
                expires: now + MAX_AGE,
                next_request,
                stage: RequestStage::Initial,
            }
        });
        self.history.push_back(Seen { seq, missing });
    }

    fn make_room(&mut self) {
        if self.history.len() == MAX_ENTRIES {
            self.history.pop_front();
        }
    }

    fn schedule_scan(&mut self, at: Instant) {
        self.next_scan = Some(self.next_scan.map_or(at, |previous| previous.min(at)));
    }

    pub(super) fn observe_repair(&mut self, now: Instant) {
        self.last_repair = Some(now);
    }

    /// Coalesced gap feedback, limited to one frame per 3 ms.
    pub(super) fn request(&mut self, now: Instant) -> Option<Request> {
        if self.next_scan.is_none_or(|at| now < at)
            || self.last_request.is_some_and(|last| now < last + GRACE)
        {
            return None;
        }
        self.next_scan = None;
        let mut request: Option<Request> = None;
        for entry in &self.history {
            let Some(missing) = &entry.missing else {
                continue;
            };
            let at = missing.due_at(self.last_repair);
            if now >= missing.expires || at >= missing.expires {
                continue;
            }
            self.next_scan = Some(self.next_scan.map_or(at, |previous| previous.min(at)));
            if now < at {
                continue;
            }
            let request = request.get_or_insert(Request {
                base: entry.seq,
                bitmap: [0; BITS / 8],
            });
            let bit = entry.seq.wrapping_sub(request.base) as usize;
            if bit < BITS {
                request.bitmap[bit / 8] |= 1 << (bit % 8);
            }
        }
        request
    }

    /// Start the retry timer only when feedback gets pacing credit. Clear
    /// packets that arrived while the feedback was waiting to be sent.
    pub(super) fn sent(
        &mut self,
        now: Instant,
        request: &mut Request,
        rtt: Option<Duration>,
    ) -> bool {
        let Some(first) = self.history.front().map(|entry| entry.seq) else {
            return false;
        };
        let extended = extended_rtt(rtt);
        let short = short_rtt(rtt);
        let rtt = extended.unwrap_or_else(|| rtt.unwrap_or(Duration::from_millis(50)).min(MAX_AGE));
        // A repair batch also needs time to pass through the repair pacer.
        let retry_delay =
            (rtt + (rtt / 4).max(Duration::from_millis(10))).max(Duration::from_millis(40));
        let retry_at = now + retry_delay;
        for bit in 0..BITS {
            let mask = 1 << (bit % 8);
            if request.bitmap[bit / 8] & mask == 0 {
                continue;
            }
            let index = request.base.wrapping_add(bit as u32).wrapping_sub(first) as usize;
            let missing = self
                .history
                .get_mut(index)
                .and_then(|entry| entry.missing.as_mut());
            let Some(missing) =
                missing.filter(|gap| now < gap.expires && now >= gap.due_at(self.last_repair))
            else {
                request.bitmap[bit / 8] &= !mask;
                continue;
            };
            // Recheck the RTT and absolute horizon at admission, not only
            // when the final short-RTT request was scheduled.
            if matches!(missing.stage, RequestStage::LateLast)
                && (!short || now + rtt >= missing.discovered + SHORT_FOLLOWUP_HORIZON)
            {
                missing.next_request = missing.expires;
                request.bitmap[bit / 8] &= !mask;
                continue;
            }
            if matches!(missing.stage, RequestStage::HighLast)
                && (extended.is_none() || now + rtt >= missing.discovered + HIGH_LATE_HORIZON)
            {
                missing.next_request = missing.expires;
                request.bitmap[bit / 8] &= !mask;
                continue;
            }
            if matches!(missing.stage, RequestStage::HighFourth)
                && (!fresh_high(now, self.current_rtt)
                    || extended.is_none()
                    || now + rtt >= missing.discovered + HIGH_FOURTH_HORIZON)
            {
                missing.next_request = missing.expires;
                request.bitmap[bit / 8] &= !mask;
                continue;
            }
            let mut scheduled_retry_at = retry_at;
            let followup = match missing.stage {
                RequestStage::Initial if extended.is_some() => Some((
                    RequestStage::HighRetryWithLate,
                    missing.expires + (EXTENDED_RETRY_HORIZON - MAX_AGE),
                )),
                RequestStage::HighRetryWithLate if extended.is_some() => {
                    scheduled_retry_at = retry_at.max(missing.discovered + HIGH_LATE_FLOOR);
                    Some((
                        RequestStage::HighLast,
                        missing.discovered + HIGH_LATE_HORIZON,
                    ))
                }
                RequestStage::HighLast
                    if fresh_high(now, self.current_rtt) && extended.is_some() =>
                {
                    scheduled_retry_at = retry_at.max(missing.discovered + HIGH_FOURTH_FLOOR);
                    Some((
                        RequestStage::HighFourth,
                        missing.discovered + HIGH_FOURTH_HORIZON,
                    ))
                }
                RequestStage::Initial => {
                    let stage = if short {
                        RequestStage::RetryWithFollowup {
                            horizon: missing.expires + (SHORT_FOLLOWUP_HORIZON - MAX_AGE),
                        }
                    } else {
                        RequestStage::Last
                    };
                    Some((stage, missing.expires))
                }
                // The short path gets one extra request after an admitted retry.
                // Anchor its deadline to discovery so pacing cannot extend it.
                RequestStage::RetryWithFollowup { horizon } if short => {
                    Some((RequestStage::FollowupWithLate { horizon }, horizon))
                }
                RequestStage::FollowupWithLate { horizon } if short => {
                    scheduled_retry_at = retry_at.max(missing.discovered + LATE_REQUEST_FLOOR);
                    Some((RequestStage::LateLast, horizon))
                }
                RequestStage::RetryWithFollowup { .. }
                | RequestStage::FollowupWithLate { .. }
                | RequestStage::LateLast
                | RequestStage::HighRetryWithLate
                | RequestStage::HighLast
                | RequestStage::HighFourth
                | RequestStage::Last => None,
            };
            if let Some((stage, horizon)) =
                followup.filter(|&(_, horizon)| scheduled_retry_at + rtt < horizon)
            {
                missing.next_request = scheduled_retry_at;
                missing.expires = horizon - rtt;
                missing.stage = stage;
            } else {
                missing.next_request = missing.expires;
            }
        }
        if request.bitmap.iter().all(|&byte| byte == 0) {
            return false;
        }
        self.last_request = Some(now);
        true
    }
}

impl Missing {
    fn due_at(&self, last_repair: Option<Instant>) -> Instant {
        if !matches!(self.stage, RequestStage::Initial)
            && let Some(at) = last_repair
        {
            let latest =
                (self.next_request + MAX_REPAIR_DEFER).min(self.expires - Duration::from_millis(1));
            return self.next_request.max((at + REPAIR_QUIET).min(latest));
        }
        self.next_request
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feedback(rx: &mut Receiver, now: Instant, rtt: Option<Duration>) -> Option<Request> {
        let mut request = rx.request(now)?;
        assert!(rx.sent(now, &mut request, rtt));
        Some(request)
    }

    #[test]
    fn retention_promotion_preserves_existing_deadlines() {
        let now = Instant::now();
        let mut tx = Sender::default();
        tx.remember(now, 1, b"legacy");
        tx.observe_rtt(Duration::from_millis(44));
        let short_at = now + Duration::from_millis(1);
        tx.remember(short_at, 2, b"short");
        tx.observe_rtt(Duration::from_millis(160));
        let extended_at = short_at + Duration::from_millis(1);
        tx.remember(extended_at, 3, b"extended");
        tx.observe_rtt(Duration::from_millis(44));
        let later_at = extended_at + Duration::from_millis(1);
        tx.remember(later_at, 4, b"later");
        let request = Request {
            base: 1,
            bitmap: std::array::from_fn(|index| if index == 0 { 15 } else { 0 }),
        };

        tx.request(now + MAX_AGE, 1, &request);
        assert!(!tx.cache.contains_key(&1));
        assert_eq!(tx.peek_len(now + MAX_AGE), Some(5));
        assert_eq!(tx.peek_len(short_at + SHORT_CACHE_AGE), Some(8));
        assert_eq!(tx.peek_len(extended_at + EXTENDED_CACHE_AGE), Some(5));
        assert!(tx.next(later_at + EXTENDED_CACHE_AGE).is_none());
        assert!(tx.cache.is_empty());
        assert!(tx.pending.is_empty());
    }

    #[test]
    fn extended_retry_requires_a_measured_high_rtt_and_timely_first_request() {
        let now = Instant::now();
        for rtt in [
            None,
            Some(Duration::from_millis(80)),
            Some(Duration::from_millis(160)),
            Some(Duration::from_millis(201)),
        ] {
            let mut rx = Receiver::default();
            assert!(rx.receive(now, 2));
            let first_at = now + GRACE;
            let mut first = rx.request(first_at).expect("first request");
            assert!(rx.sent(first_at, &mut first, rtt));
            let retry_at = first_at + Duration::from_millis(200);
            if rtt == Some(Duration::from_millis(160)) {
                assert!(rx.request(retry_at - Duration::from_nanos(1)).is_none());
                let mut retry = rx.request(retry_at).expect("high RTT retry");
                assert_eq!(retry, first);
                assert!(rx.sent(retry_at, &mut retry, rtt));
                assert!(rx.request(retry_at + Duration::from_millis(100)).is_none());
            } else if rtt.is_some() {
                assert!(rx.request(retry_at).is_none());
            }
        }
        let mut stale = Receiver::default();
        assert!(stale.receive(now, 2));
        let mut request = stale.request(now + GRACE).expect("initial feedback");
        assert!(!stale.sent(
            now + MAX_AGE,
            &mut request,
            Some(Duration::from_millis(160))
        ));
    }

    #[test]
    fn burst_repairs_are_unordered_and_once_only() {
        let t = Instant::now();
        let mut tx = Sender::default();
        let mut rx = Receiver::default();
        for seq in 1..=700u32 {
            tx.remember(t, seq, &seq.to_be_bytes());
            if !(20..58).contains(&seq) {
                assert!(rx.receive(t, seq));
            }
        }
        // Hundreds of later originals delivered without waiting for the gap.
        assert!(rx.request(t).is_none());
        let req = feedback(&mut rx, t + GRACE, None).unwrap();
        assert_eq!(
            req.sequences().collect::<Vec<_>>(),
            (20..58).collect::<Vec<_>>()
        );
        assert_eq!(Request::decode(&req.encode()), Some(req.clone()));
        tx.request(t + Duration::from_millis(30), 1, &req);
        tx.request(t + Duration::from_millis(30), 1, &req);
        for seq in 20..58u32 {
            assert_eq!(tx.peek_len(t + Duration::from_millis(60)), Some(4));
            let (actual, bytes) = tx.next(t + Duration::from_millis(60)).unwrap();
            assert_eq!(actual, seq);
            assert_eq!(bytes, seq.to_be_bytes());
            assert!(rx.receive(t + Duration::from_millis(90), actual));
            assert!(!rx.receive(t + Duration::from_millis(90), actual));
        }
        tx.request(t + Duration::from_millis(100), 1, &req);
        assert!(tx.next(t + Duration::from_millis(100)).is_none());
        assert!(rx.request(t + Duration::from_millis(100)).is_none());
    }

    #[test]
    fn retry_recovers_lost_feedback_or_lost_repair() {
        let t = Instant::now();
        let retry_delay = Duration::from_millis(55);
        let one_way = Duration::from_millis(22);
        let rtt = Some(one_way * 2);
        for lose_feedback in [true, false] {
            let mut tx = Sender::default();
            let mut rx = Receiver::default();
            tx.remember(t, 2, &[42]);
            rx.receive(t + one_way, 1);
            rx.receive(t + one_way, 3);
            let first_at = t + one_way + GRACE;
            let first = feedback(&mut rx, first_at, rtt).unwrap();
            if !lose_feedback {
                tx.request(first_at + one_way, u32::MAX, &first);
                assert_eq!(tx.next(first_at + one_way), Some((2, vec![42])));
            }
            let retry_at = first_at + retry_delay;
            assert!(rx.request(retry_at - Duration::from_millis(1)).is_none());
            let retry = feedback(&mut rx, retry_at, rtt).expect("missing packet requested again");
            assert_eq!(retry, first);
            let arrives = retry_at + one_way;
            tx.request(arrives, 1, &retry);
            let (seq, packet) = tx.next(arrives).expect("repair available for retry");
            assert_eq!((seq, packet), (2, vec![42]));
            assert!(rx.receive(arrives + one_way, seq));
            assert!(!rx.receive(arrives + one_way, seq));
            assert!(rx.request(retry_at + retry_delay).is_none());
            if !lose_feedback {
                tx.request(arrives, 2, &retry);
                assert!(tx.next(arrives).is_none());
            }
        }
    }

    #[test]
    fn recovers_when_initial_feedback_and_first_repair_are_both_lost() {
        let sent = Instant::now();
        let one_way = Duration::from_millis(22);
        let rtt = one_way * 2;
        let retry_delay = Duration::from_millis(55);
        let mut tx = Sender::default();
        let mut rx = Receiver::default();
        tx.observe_rtt(rtt);
        tx.remember(sent, 2, &[42]);

        assert!(rx.receive(sent + one_way, 1));
        assert!(rx.receive(sent + one_way, 3));
        let first_at = sent + one_way + GRACE;
        let first = feedback(&mut rx, first_at, Some(rtt)).expect("initial feedback");
        // The first logical request and all its copies are lost.
        let retry_at = first_at + retry_delay;
        let retry = feedback(&mut rx, retry_at, Some(rtt)).expect("second feedback");
        assert_eq!(retry, first);
        let second_arrival = retry_at + one_way;
        tx.request(second_arrival, 2, &retry);
        // The first repair sent for this gap is lost as well.
        assert_eq!(tx.next(second_arrival), Some((2, vec![42])));

        let followup_at = retry_at + retry_delay;
        let pending = rx.request(followup_at);
        let check_at = followup_at + one_way;
        if pending.is_none() {
            // Verify that the sender could have serviced a fresh request.
            tx.request(check_at, 3, &retry);
            assert_eq!(tx.next(check_at), Some((2, vec![42])));
        }
        let mut request = pending.expect("third feedback while original is still cached");
        assert!(rx.sent(followup_at, &mut request, Some(rtt)));
        tx.request(check_at, 3, &request);
        let (seq, packet) = tx.next(check_at).expect("second repair");
        assert_eq!(seq, 2);
        assert_eq!(packet, vec![42]);
        tx.request(check_at, 4, &request);
        assert!(tx.next(check_at).is_none());
        assert!(rx.receive(check_at + one_way, seq));
        assert!(rx.request(followup_at + retry_delay).is_none());
    }

    #[test]
    fn short_followup_waits_for_admission_before_late_request() {
        let now = Instant::now();
        let rtt = Some(Duration::from_millis(44));
        let retry_delay = Duration::from_millis(55);
        let mut rx = Receiver::default();
        assert!(rx.receive(now, 2));
        let first_at = now + GRACE;
        let first = feedback(&mut rx, first_at, rtt).unwrap();
        let retry_at = first_at + retry_delay;
        let mut retry = rx.request(retry_at).unwrap();
        let admitted_at = retry_at + Duration::from_millis(20);
        assert!(rx.sent(admitted_at, &mut retry, rtt));

        let followup_at = admitted_at + retry_delay;
        assert!(rx.request(followup_at - Duration::from_nanos(1)).is_none());
        assert_eq!(feedback(&mut rx, followup_at, rtt), Some(first));
        assert!(rx.request(followup_at + retry_delay).is_none());
    }

    #[test]
    fn feedback_waits_for_pacing_and_prunes_delivered_packets() {
        let t = Instant::now();
        let mut rx = Receiver::default();
        assert!(rx.receive(t, 3));
        let mut queued = rx.request(t + GRACE).unwrap();
        assert!(rx.receive(t + GRACE, 1));
        let sent_at = t + Duration::from_millis(30);
        let rtt = Some(Duration::from_millis(44));
        assert!(rx.sent(sent_at, &mut queued, rtt));
        assert_eq!(queued.sequences().collect::<Vec<_>>(), vec![2]);
        assert!(rx.request(sent_at + Duration::from_millis(54)).is_none());
        assert!(rx.receive(sent_at + Duration::from_millis(54), 2));
        assert!(rx.request(sent_at + Duration::from_millis(55)).is_none());

        let mut rx = Receiver::default();
        assert!(rx.receive(t, 2));
        let long_rtt = Some(Duration::from_millis(80));
        assert!(feedback(&mut rx, t + GRACE, long_rtt).is_some());
        assert!(rx.request(t + Duration::from_millis(130)).is_none());
    }

    #[test]
    fn ongoing_repairs_cannot_defer_retry_indefinitely() {
        let t = Instant::now();
        let mut rx = Receiver::default();
        assert!(rx.receive(t, 2));
        let rtt = Some(Duration::from_millis(44));
        let first_at = t + GRACE;
        assert!(feedback(&mut rx, first_at, rtt).is_some());
        let retry_at = first_at + Duration::from_millis(55);
        for elapsed in (0..16).step_by(2) {
            let now = retry_at + Duration::from_millis(elapsed);
            rx.observe_repair(now);
            assert!(rx.request(now).is_none());
        }
        let now = retry_at + MAX_REPAIR_DEFER;
        rx.observe_repair(now);
        let retry = feedback(&mut rx, now, rtt).unwrap();
        assert_eq!(retry.sequences().collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn reorder_expiry_wraparound_and_jumps_are_bounded() {
        let t = Instant::now();
        let mut rx = Receiver::default();
        assert!(rx.receive(t, u32::MAX - 2));
        assert!(rx.receive(t, 2));
        assert!(rx.receive(t + Duration::from_millis(1), u32::MAX));
        let req = feedback(&mut rx, t + GRACE, None).unwrap();
        assert_eq!(req.sequences().collect::<Vec<_>>(), vec![u32::MAX - 1, 1]);
        assert!(rx.receive(t + MAX_AGE, 1));
        assert!(!rx.receive(t + MAX_AGE, 1));
        assert!(rx.receive(t, 1_000_000));
        assert_eq!(rx.history.len(), 1);
        assert!(!rx.receive(t, 2));
        assert!(!rx.receive(t, 1_000_000u32.wrapping_add(1 << 31)));
        for seq in 1_000_001..1_010_000 {
            assert!(rx.receive(t, seq));
        }
        assert_eq!(rx.history.len(), MAX_ENTRIES);
    }

    #[test]
    fn sender_caps_and_deadlines_include_pending_repairs() {
        let t = Instant::now();
        let mut tx = Sender::default();
        for seq in 0..3000 {
            tx.remember(t, seq, &[1; 1500]);
        }
        assert!(tx.bytes <= MAX_BYTES);
        assert!(tx.cache.len() <= MAX_ENTRIES);
        assert_eq!(tx.order.len(), tx.cache.len());
        let req = Request {
            base: 2800,
            bitmap: [255; 32],
        };
        tx.request(t, 1, &req);
        assert!(tx.peek_len(t).is_some());
        assert!(tx.next(t + MAX_AGE).is_none());
        assert_eq!(tx.bytes, 0);
        assert!(tx.pending.is_empty());
        assert!(tx.cache.is_empty());
        assert!(tx.order.is_empty());
    }

    #[test]
    fn requests_coalesce_and_rate_limit() {
        let t = Instant::now();
        let mut rx = Receiver::default();
        for seq in 1..=10 {
            assert!(rx.receive(t, seq));
        }
        rx.receive(t, 700);
        let first = feedback(&mut rx, t + GRACE, None).unwrap();
        assert_eq!(first.sequences().count(), 256);
        assert!(rx.request(t + GRACE).is_none());
        let second = feedback(&mut rx, t + GRACE * 2, None).unwrap();
        assert_eq!(second.sequences().next(), Some(267));
        assert!(rx.request(t + MAX_AGE).is_none());
        assert!(Request::decode(&[0; Request::ENCODED_LEN]).is_none());
        assert!(Request::decode(&[1; Request::ENCODED_LEN - 1]).is_none());
    }

    #[test]
    fn initial_reordering_and_early_watermark_allow_late_originals() {
        let t = Instant::now();
        let mut rx = Receiver::default();
        assert!(rx.receive(t, 2));
        assert!(rx.receive(t, 1));
        assert!(!rx.receive(t, 1));
        assert!(rx.request(t + GRACE).is_none());

        let mut rx = Receiver::default();
        rx.observe_sent(t, 2);
        assert!(rx.receive(t, 2));
        assert!(rx.receive(t, 1));
        assert!(rx.request(t + GRACE).is_none());
    }
    fn single_request() -> Request {
        Request {
            base: 1,
            bitmap: std::array::from_fn(|i| u8::from(i == 0)),
        }
    }

    fn short_sender(now: Instant) -> Sender {
        let mut tx = Sender::default();
        tx.observe_rtt(Duration::from_millis(44));
        tx.observe_current_rtt(Some((Duration::from_millis(44), now)));
        tx.remember(now, 1, b"probe");
        tx
    }

    #[test]
    fn late_request_timing_is_bounded() {
        let now = Instant::now();
        let rtt = Some(Duration::from_millis(44));
        {
            let mut rx = Receiver::default();

            rx.receive(now, 2);
            for ms in [3, 58, 113] {
                assert!(feedback(&mut rx, now + Duration::from_millis(ms), rtt).is_some());
            }
            assert!(rx.request(now + Duration::from_millis(199)).is_none());
            assert!(feedback(&mut rx, now + Duration::from_millis(200), rtt).is_some());
            assert!(rx.request(now + Duration::from_millis(255)).is_none());
        }
        // The late timer starts only after pacing admits the third request.
        let mut rx = Receiver::default();

        rx.receive(now, 2);
        for ms in [3, 58] {
            assert!(feedback(&mut rx, now + Duration::from_millis(ms), rtt).is_some());
        }
        let mut third = rx.request(now + Duration::from_millis(113)).unwrap();
        assert!(rx.sent(now + Duration::from_millis(170), &mut third, rtt));
        assert!(rx.request(now + Duration::from_millis(224)).is_none());
        assert!(feedback(&mut rx, now + Duration::from_millis(225), rtt).is_some());
        assert!(rx.request(now + Duration::from_millis(280)).is_none());
    }

    #[test]
    fn third_repair_rejects_duplicate_and_stale_feedback_and_has_no_latch() {
        let now = Instant::now();
        let req = single_request();
        let mut tx = short_sender(now);
        tx.request(now, u32::MAX, &req);
        tx.request(now, 1, &req); // Newer while first pending is not retained.
        assert_eq!(tx.pending.len(), 1);
        assert!(tx.next(now).is_some());
        assert!(tx.next(now).is_none());
        tx.request(now, u32::MAX, &req);
        tx.request(now, u32::MAX - 1, &req);
        assert!(tx.next(now).is_none());
        tx.request(now, 1, &req); // A new authenticated arrival is required.
        tx.request(now, 1, &req);
        assert_eq!(tx.pending.len(), 1);
        assert!(tx.next(now).is_some());
        for id in [u32::MAX, 1, 1u32.wrapping_add(1 << 31)] {
            tx.request(now, id, &req);
            assert!(tx.next(now).is_none());
        }
        tx.request(now, 2, &req);
        tx.request(now, 2, &req);
        tx.request(now, 3, &req);
        assert_eq!(tx.pending.len(), 1);
        assert!(tx.next(now).is_some());
        tx.request(now, 4, &req);
        assert!(tx.next(now).is_none());
        assert_eq!(tx.bytes, 0);
        assert!(tx.cache.is_empty());
    }

    #[test]
    fn late_repair_keeps_original_deadlines_and_prunes_received_gaps() {
        let now = Instant::now();
        let req = single_request();
        let mut tx = short_sender(now);
        let deadline = tx.cache[&1].expires;
        for id in [1, 2] {
            tx.request(now, id, &req);
            assert!(tx.next(now).is_some());
            assert_eq!(tx.cache[&1].expires, deadline);
        }
        tx.request(deadline - Duration::from_nanos(1), 3, &req);
        assert_eq!(tx.pending.len(), 1);
        assert!(tx.peek_len(deadline).is_none());
        assert!(tx.next(deadline).is_none());
        assert!(tx.order.is_empty());
        assert_eq!(tx.bytes, 0);
        let rtt = Some(Duration::from_millis(44));
        for deliver in [false, true] {
            let mut rx = Receiver::default();

            rx.receive(now, 2);
            for ms in [3, 58, 113] {
                assert!(feedback(&mut rx, now + Duration::from_millis(ms), rtt).is_some());
            }
            let mut late = rx.request(now + Duration::from_millis(200)).unwrap();
            if deliver {
                assert!(rx.receive(now + Duration::from_millis(201), 1));
            }
            // No pacing delay may push admission beyond the discovery horizon minus RTT.
            assert!(!rx.sent(now + Duration::from_millis(256), &mut late, rtt));
            assert!(rx.request(now + Duration::from_millis(300)).is_none());
        }
        // A delayed third request cannot create a late request whose RTT does not fit.
        let mut rx = Receiver::default();

        rx.receive(now, 2);
        for ms in [3, 58] {
            assert!(feedback(&mut rx, now + Duration::from_millis(ms), rtt).is_some());
        }
        assert!(feedback(&mut rx, now + Duration::from_millis(210), rtt).is_some());
        assert!(rx.request(now + Duration::from_millis(265)).is_none());
    }

    #[test]
    fn third_repair_requires_fresh_short_sender_rtt() {
        let now = Instant::now();
        let req = single_request();
        {
            let mut tx = short_sender(now);
            for id in [1, 2] {
                tx.request(now, id, &req);
                assert!(tx.next(now).is_some());
            }
            tx.request(now, 3, &req);
            assert!(tx.next(now).is_some());
        }
        for sample in [
            None,
            Some((Duration::ZERO, now)),
            Some((Duration::from_millis(201), now)),
            Some((Duration::from_millis(44), now - RTT_FRESHNESS)),
        ] {
            let mut tx = short_sender(now);
            for id in [1, 2] {
                tx.request(now, id, &req);
                assert!(tx.next(now).is_some());
            }
            tx.observe_current_rtt(sample);
            tx.request(now, 3, &req);
            assert!(tx.peek_len(now).is_none());
            // Fresh RTT can permit a subsequent fresh request, without renewing the cache.
            tx.observe_current_rtt(Some((Duration::from_millis(44), now)));
            tx.request(now, 4, &req);
            assert!(tx.peek_len(now).is_some());
            tx.observe_current_rtt(sample);
            assert!(tx.peek_len(now).is_none());
            assert!(tx.next(now).is_none());
            assert_eq!(tx.bytes, 0);
        }
        // A late request queued at short RTT is cancelled if RTT leaves that band.
        for rtt in [None, Some(Duration::ZERO), Some(Duration::from_millis(100))] {
            let mut rx = Receiver::default();

            rx.receive(now, 2);
            for ms in [3, 58, 113] {
                assert!(
                    feedback(
                        &mut rx,
                        now + Duration::from_millis(ms),
                        Some(Duration::from_millis(44))
                    )
                    .is_some()
                );
            }
            let mut late = rx.request(now + Duration::from_millis(200)).unwrap();
            assert!(!rx.sent(now + Duration::from_millis(200), &mut late, rtt));
            assert!(rx.request(now + Duration::from_millis(250)).is_none());
        }
        // A still-short but larger RTT cannot push the late round trip past 300 ms.
        let mut growing = Receiver::default();

        growing.receive(now, 2);
        for ms in [3, 58, 113] {
            assert!(
                feedback(
                    &mut growing,
                    now + Duration::from_millis(ms),
                    Some(Duration::from_millis(44))
                )
                .is_some()
            );
        }
        let mut late = growing.request(now + Duration::from_millis(200)).unwrap();
        assert!(!growing.sent(
            now + Duration::from_millis(220),
            &mut late,
            Some(Duration::from_millis(90))
        ));
        // High-RTT receiver admits a third, but needs a fresh sample for a fourth.
        let mut rx = Receiver::default();

        rx.receive(now, 2);
        let rtt = Some(Duration::from_millis(160));
        assert!(feedback(&mut rx, now + GRACE, rtt).is_some());
        assert!(feedback(&mut rx, now + Duration::from_millis(203), rtt).is_some());
        assert!(feedback(&mut rx, now + Duration::from_millis(403), rtt).is_some());
        assert!(rx.request(now + Duration::from_millis(603)).is_none());
    }
    #[test]
    fn ineligible_third_head_does_not_block_ordinary_repairs_or_scan_the_queue() {
        let now = Instant::now();
        let req = single_request();
        for refresh_before_head in [false, true] {
            let mut tx = short_sender(now);
            for id in [1, 2] {
                tx.request(now, id, &req);
                assert!(tx.next(now).is_some());
            }
            tx.remember(now, 2, b"ordinary");
            let ordinary = Request {
                base: 2,
                ..req.clone()
            };
            tx.request(now, 1, &ordinary);
            tx.request(now, 3, &req);
            assert_eq!(tx.pending.iter().copied().collect::<Vec<_>>(), vec![2, 1]);
            tx.observe_current_rtt(Some((Duration::from_millis(201), now)));
            assert_eq!(tx.peek_len(now), Some(8));
            assert!(matches!(tx.cache[&1].attempt, Attempt::ThirdQueued(_)));
            if refresh_before_head {
                tx.observe_current_rtt(Some((Duration::from_millis(44), now)));
            }
            assert_eq!(tx.next(now), Some((2, b"ordinary".to_vec())));
            assert_eq!(tx.peek_len(now), refresh_before_head.then_some(5));
            assert_eq!(tx.next(now).is_some(), refresh_before_head);
            assert!(tx.pending.is_empty());
            assert!(!tx.cache.contains_key(&1));
            assert_eq!(tx.bytes, 8);
            assert_eq!(tx.order.iter().copied().collect::<Vec<_>>(), vec![2]);
        }
    }

    #[test]
    fn late_request_recovers_after_initial_feedback_and_two_repairs_are_lost() {
        let now = Instant::now();
        let one_way = Duration::from_millis(22);
        let rtt = Some(one_way * 2);
        let mut tx = short_sender(now);
        let mut rx = Receiver::default();
        rx.receive(now + one_way, 2);
        // The first request is lost; the next two requests elicit repairs that are lost.
        assert!(feedback(&mut rx, now + Duration::from_millis(25), rtt).is_some());
        for (id, ms) in [(2, 80), (3, 135)] {
            let at = now + Duration::from_millis(ms);
            let request = feedback(&mut rx, at, rtt).unwrap();
            tx.request(at + one_way, id, &request);
            assert_eq!(tx.next(at + one_way), Some((1, b"probe".to_vec())));
        }
        let at = now + one_way + LATE_REQUEST_FLOOR;
        let request = feedback(&mut rx, at, rtt).expect("one late logical request");
        tx.request(at + one_way, 4, &request);
        let (seq, _) = tx.next(at + one_way).expect("third repair");
        assert!(rx.receive(at + one_way * 2, seq));
        assert!(!rx.receive(at + one_way * 2, seq));
        tx.request(at + one_way * 2, 5, &request);
        assert!(tx.next(at + one_way * 2).is_none());
        assert!(rx.request(now + SHORT_FOLLOWUP_HORIZON).is_none());
        assert_eq!(tx.bytes, 0);
    }
}

#[cfg(test)]
mod fourth_tests {
    use super::*;
    fn req(seq: u32) -> Request {
        Request {
            base: seq,
            bitmap: std::array::from_fn(|i| u8::from(i == 0)),
        }
    }
    fn sender(t: Instant) -> Sender {
        let mut tx = Sender::default();
        tx.observe_rtt(Duration::from_millis(160));
        tx.observe_current_rtt(Some((Duration::from_millis(160), t)));
        tx.remember(t, 1, b"one");
        tx
    }
    fn third_sent(tx: &mut Sender, t: Instant) {
        for (id, ms) in [(1, 200), (2, 430), (3, 700)] {
            tx.request(t + Duration::from_millis(ms), id, &req(1));
            assert!(tx.next(t + Duration::from_millis(ms)).is_some());
        }
    }
    fn receiver(t: Instant, rtt: u64) -> Receiver {
        let mut rx = Receiver::default();
        rx.observe_current_rtt(Some((Duration::from_millis(rtt), t)));
        rx.receive(t, 2);
        rx
    }
    fn admitted(rx: &mut Receiver, at: Instant, rtt: u64) {
        let mut r = rx.request(at).expect("due request");
        assert!(rx.sent(at, &mut r, Some(Duration::from_millis(rtt))));
    }

    #[test]
    fn fourth_requires_new_request_after_third_and_uses_fifo_no_latch() {
        let t = Instant::now();
        let mut tx = sender(t);
        for id in [1, 2] {
            tx.request(t, id, &req(1));
            assert!(tx.next(t).is_some());
        }
        tx.request(t, 3, &req(1));
        tx.request(t, 4, &req(1)); // no pending intent is retained
        assert_eq!(tx.pending.len(), 1);
        assert!(tx.next(t).is_some());
        assert!(matches!(tx.cache[&1].attempt, Attempt::ThirdSent(3)));
        assert!(tx.pending.is_empty());
        for id in [2, 3, 3u32.wrapping_add(1 << 31)] {
            tx.request(t, id, &req(1));
        }
        assert!(tx.pending.is_empty());
        tx.remember(t, 2, b"two");
        tx.request(t, 10, &req(2));
        tx.request(t, 4, &req(1));
        tx.request(t, 4, &req(1));
        tx.request(t, 5, &req(1));
        assert_eq!(tx.pending.iter().copied().collect::<Vec<_>>(), vec![2, 1]);
        assert_eq!(tx.next(t).unwrap().0, 2);
        assert_eq!(tx.next(t).unwrap().0, 1);
        assert!(!tx.cache.contains_key(&1));
        tx.request(t, 6, &req(1));
        assert!(tx.pending.is_empty());
    }

    #[test]
    fn fourth_does_not_extend_original_deadline_and_peek_does_not_spend() {
        let t = Instant::now();
        for take_ms in [899, 900] {
            let mut tx = sender(t);
            third_sent(&mut tx, t);
            tx.request(t + Duration::from_millis(830), 4, &req(1));
            assert_eq!(tx.cache[&1].expires, t + EXTENDED_CACHE_AGE);
            for _ in 0..20 {
                assert_eq!(tx.peek_len(t + Duration::from_millis(850)), Some(3));
            }
            assert_eq!(tx.pending.len(), 1);
            assert_eq!(tx.bytes, 3);
            assert_eq!(
                tx.next(t + Duration::from_millis(take_ms)).is_some(),
                take_ms < 900
            );
            assert!(tx.cache.is_empty());
            assert_eq!(tx.bytes, 0);
            assert!(tx.order.is_empty());
        }
    }

    #[test]
    fn fourth_rechecks_fresh_high_on_admission_and_dequeue() {
        let t = Instant::now();
        for rtt in [0, 99, 100, 160, 200, 201] {
            let mut tx = sender(t);
            third_sent(&mut tx, t);
            tx.observe_current_rtt(Some((Duration::from_millis(rtt), t)));
            tx.request(t + Duration::from_millis(830), 4, &req(1));
            assert_eq!(!tx.pending.is_empty(), (100..=200).contains(&rtt));
        }
        for invalid in [
            None,
            Some((Duration::from_millis(160), t - Duration::from_secs(3))),
            Some((Duration::from_millis(160), t + Duration::from_secs(2))),
            Some((Duration::from_millis(44), t)),
        ] {
            let mut tx = sender(t);
            third_sent(&mut tx, t);
            tx.request(t + Duration::from_millis(830), 4, &req(1));
            tx.observe_current_rtt(invalid);
            tx.remember(t + Duration::from_millis(840), 2, b"two");
            tx.request(t + Duration::from_millis(840), 5, &req(2));
            assert_eq!(tx.peek_len(t + Duration::from_millis(850)), Some(3));
            assert!(!tx.cache.contains_key(&1));
            assert_eq!(tx.next(t + Duration::from_millis(850)).unwrap().0, 2);
        }
        let mut tx = sender(t);
        third_sent(&mut tx, t);
        tx.request(t + Duration::from_millis(830), 4, &req(1));
        tx.observe_current_rtt(None);
        assert!(tx.next(t + Duration::from_millis(850)).is_none());
    }

    #[test]
    fn fourth_receiver_floor_horizon_and_exactly_one_added_serial() {
        let t = Instant::now();
        {
            let mut rx = receiver(t, 160);
            for ms in [3, 203, 403] {
                admitted(&mut rx, t + Duration::from_millis(ms), 160);
            }
            assert!(rx.request(t + Duration::from_millis(602)).is_none());
            admitted(&mut rx, t + Duration::from_millis(603), 160);
            assert!(rx.request(t + Duration::from_millis(803)).is_none());
        }
        // At 100 ms RTT, discovery floor600 dominates the retry timer525.
        let mut rx = receiver(t, 100);
        for ms in [3, 128, 400] {
            admitted(&mut rx, t + Duration::from_millis(ms), 100);
        }
        assert!(rx.request(t + Duration::from_millis(599)).is_none());
        admitted(&mut rx, t + Duration::from_millis(600), 100);
    }

    #[test]
    fn fourth_receiver_rechecks_admission_freshness_band_arrival_and_horizon() {
        let t = Instant::now();
        for case in 0..5 {
            let mut rx = receiver(t, 160);
            for ms in [3, 203, 403] {
                admitted(&mut rx, t + Duration::from_millis(ms), 160);
            }
            let mut request = rx.request(t + Duration::from_millis(603)).unwrap();
            let at = if case == 4 {
                t + Duration::from_millis(740)
            } else {
                t + Duration::from_millis(603)
            };
            match case {
                0 => rx.observe_current_rtt(None),
                1 => rx.observe_current_rtt(Some((
                    Duration::from_millis(160),
                    t - Duration::from_secs(3),
                ))),
                2 => rx.observe_current_rtt(Some((Duration::from_millis(99), t))),
                3 => {
                    assert!(rx.receive(at, 1));
                }
                _ => {}
            }
            assert!(!rx.sent(at, &mut request, Some(Duration::from_millis(160))));
            assert!(request.sequences().next().is_none());
        }
    }

    #[test]
    fn fourth_keeps_short_behavior_and_pre_promotion_originals_unchanged() {
        let t = Instant::now();
        let mut tx = Sender::default();
        tx.observe_rtt(Duration::from_millis(44));
        tx.remember(t, 1, b"short");
        tx.observe_rtt(Duration::from_millis(160));
        tx.observe_current_rtt(Some((Duration::from_millis(160), t)));
        for id in [1, 2, 3] {
            tx.request(t, id, &req(1));
            assert!(tx.next(t).is_some());
        }
        assert!(tx.cache.is_empty());
        let mut tx = sender(t);
        tx.observe_current_rtt(Some((Duration::from_millis(44), t)));
        for id in [1, 2, 3] {
            tx.request(t, id, &req(1));
            assert!(tx.next(t).is_some());
        }
        assert!(tx.cache.is_empty());
        let mut rx = receiver(t, 44);
        for ms in [3, 58, 113, 200] {
            admitted(&mut rx, t + Duration::from_millis(ms), 44);
        }
        assert!(rx.request(t + Duration::from_millis(255)).is_none());
    }
    #[test]
    fn fourth_retention_remains_subject_to_entry_and_byte_caps() {
        let t = Instant::now();
        let mut tx = sender(t);
        third_sent(&mut tx, t);
        for seq in 2..=MAX_ENTRIES as u32 + 1 {
            tx.remember(t + Duration::from_millis(710), seq, b"x");
        }
        assert!(!tx.cache.contains_key(&1));
        assert_eq!(tx.cache.len(), MAX_ENTRIES);
        assert_eq!(tx.bytes, MAX_ENTRIES);
        let mut tx = sender(t);
        third_sent(&mut tx, t);
        tx.remember(t + Duration::from_millis(710), 2, &vec![0; MAX_BYTES]);
        assert!(!tx.cache.contains_key(&1));
        assert_eq!(tx.cache.len(), 1);
        assert_eq!(tx.bytes, MAX_BYTES);
    }

    #[test]
    fn latest_rtt_transitions_do_not_renew_originals_or_change_retention_order() {
        let t = Instant::now();
        let mut tx = Sender::default();
        tx.remember(t, 1, b"initial");
        for (seq, ms) in [(2, 44), (3, 160), (4, 44), (5, 201)] {
            let at = t + Duration::from_millis(u64::from(seq));
            tx.observe_rtt(Duration::from_millis(ms));
            tx.observe_current_rtt(Some((Duration::from_millis(ms), at)));
            tx.remember(at, seq, b"packet");
        }
        assert_eq!(tx.cache[&1].expires, t + MAX_AGE);
        assert_eq!(
            tx.cache[&2].expires,
            t + Duration::from_millis(2) + SHORT_CACHE_AGE
        );
        for seq in 3..=5 {
            assert_eq!(
                tx.cache[&seq].expires,
                t + Duration::from_millis(u64::from(seq)) + EXTENDED_CACHE_AGE
            );
        }
        // Latest 201 ms sample disables extra repairs despite prior high promotion.
        assert!(!tx.third_allowed(t + Duration::from_millis(5)));
        assert!(!tx.fourth_allowed(t + Duration::from_millis(5)));
        tx.observe_current_rtt(Some((Duration::from_millis(44), t)));
        assert!(tx.third_allowed(t));
        assert!(!tx.fourth_allowed(t));
        tx.observe_current_rtt(Some((Duration::from_millis(160), t)));
        assert!(tx.third_allowed(t));
        assert!(tx.fourth_allowed(t));
        assert!(!tx.fourth_allowed(t + RTT_FRESHNESS));
        tx.remember(t + Duration::from_millis(899), 6, b"sticky");
        assert_eq!(tx.cache[&6].expires, t + Duration::from_millis(1799));
        tx.expire(t + Duration::from_millis(906));
        assert_eq!(tx.order.iter().copied().collect::<Vec<_>>(), vec![6]);
    }

    #[test]
    fn receiver_uses_latest_band_and_horizon_after_high_rtt_changes() {
        let t = Instant::now();
        for next in [44, 100, 160, 200, 201] {
            let mut rx = receiver(t, 160);
            for ms in [3, 203, 403] {
                admitted(&mut rx, t + Duration::from_millis(ms), 160);
            }
            let at = t + Duration::from_millis(603);
            rx.observe_current_rtt(Some((Duration::from_millis(next), at)));
            let mut request = rx.request(at).unwrap();
            assert_eq!(
                rx.sent(at, &mut request, Some(Duration::from_millis(next))),
                (100..=200).contains(&next)
            );
            assert!(rx.request(t + Duration::from_millis(899)).is_none());
        }
        // A larger current RTT must fit the discovery-anchored horizon.
        let mut rx = receiver(t, 100);
        for ms in [3, 128, 400] {
            admitted(&mut rx, t + Duration::from_millis(ms), 100);
        }
        let mut request = rx.request(t + Duration::from_millis(600)).unwrap();
        let at = t + Duration::from_millis(700);
        rx.observe_current_rtt(Some((Duration::from_millis(200), at)));
        assert!(!rx.sent(at, &mut request, Some(Duration::from_millis(200))));
    }

    #[test]
    fn high_sender_serial_wrap_requires_a_new_arrival_for_each_attempt() {
        let t = Instant::now();
        let mut tx = sender(t);
        for id in [u32::MAX - 1, u32::MAX, 1, 2] {
            tx.request(t, id, &req(1));
            tx.request(t, id.wrapping_add(1), &req(1));
            assert_eq!(tx.pending.len(), 1);
            assert!(tx.next(t).is_some());
            assert!(tx.next(t).is_none());
        }
        tx.request(t, 3, &req(1));
        assert!(tx.cache.is_empty());
        assert!(tx.pending.is_empty());
    }
}
