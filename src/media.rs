//! VP8 IVF trace source and experimental payload replacement.
//!
//! This preserves RTP payload sizes and the VP8 descriptor, NOT a decodable
//! video bitstream after replacement. A fixed trace is not an adaptive encoder.
use crate::wire::{Frame, HEADER};
use anyhow::{Result, ensure};
use std::time::Duration;

pub const MAX_FILE: usize = 64 * 1024 * 1024;
pub const RTP_BODY: usize = 1100;
// One-byte VP8 payload descriptor plus 16 untouched encoded bytes per packet.
const SLOT_START: usize = 17;

#[derive(Clone, Debug)]
pub struct VideoFrame {
    pub at: Duration,
    pub encoded: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct Clip {
    pub frames: Vec<VideoFrame>,
    pub duration: Duration,
}

/// Packet deadlines distributed across each original video frame interval.
/// This preserves frame timestamps/sizes but is a lab pacer, not congestion control.
pub struct Schedule<'a> {
    clip: &'a Clip,
    frame: usize,
    packet: usize,
    cycle: u32,
    pending: Option<ScheduledPacket>,
}
pub struct ScheduledPacket {
    pub at: Duration,
    pub timestamp: u32,
    pub marker: bool,
    pub payload: Vec<u8>,
}
impl<'a> Schedule<'a> {
    pub fn new(clip: &'a Clip) -> Self {
        Self {
            clip,
            frame: 0,
            packet: 0,
            cycle: 0,
            pending: None,
        }
    }
    fn prepare_pending(&mut self) {
        if self.pending.is_some() {
            return;
        }
        let frame = &self.clip.frames[self.frame];
        let count = frame.encoded.len().div_ceil(RTP_BODY);
        let index = self.packet;
        let offset = index * RTP_BODY;
        let data = &frame.encoded[offset..(offset + RTP_BODY).min(frame.encoded.len())];
        let start = frame.at;
        let end = self
            .clip
            .frames
            .get(self.frame + 1)
            .map_or(self.clip.duration, |next| next.at);
        let origin = self.clip.duration * self.cycle + start;
        let mut payload = Vec::with_capacity(data.len() + 1);
        payload.push(if index == 0 { 0x10 } else { 0 });
        payload.extend_from_slice(data);
        self.pending = Some(ScheduledPacket {
            at: origin
                + Duration::from_nanos(
                    ((end - start).as_nanos() * index as u128 / count as u128) as u64,
                ),
            timestamp: (origin.as_nanos() * 90_000 / 1_000_000_000) as u32,
            marker: index + 1 == count,
            payload,
        });
    }
    fn advance(&mut self) {
        let count = self.clip.frames[self.frame]
            .encoded
            .len()
            .div_ceil(RTP_BODY);
        self.packet += 1;
        if self.packet == count {
            self.packet = 0;
            self.frame += 1;
            if self.frame == self.clip.frames.len() {
                self.frame = 0;
                self.cycle += 1;
            }
        }
    }
    pub fn next_at(&mut self) -> Duration {
        self.prepare_pending();
        self.pending.as_ref().expect("nonempty video frame").at
    }
    pub fn pop_due(&mut self, now: Duration) -> Option<ScheduledPacket> {
        if self.next_at() <= now {
            let packet = self.pending.take();
            self.advance();
            packet
        } else {
            None
        }
    }
}

impl Clip {
    pub fn encoded_mbps(&self) -> f64 {
        self.frames.iter().map(|f| f.encoded.len()).sum::<usize>() as f64 * 8.0
            / self.duration.as_secs_f64()
            / 1e6
    }
    pub fn data_slot_capacity_mbps(&self) -> f64 {
        self.data_slot_capacity_mbps_for(crate::wire::MAX_DATA)
    }
    pub fn data_slot_capacity_mbps_for(&self, block_size: usize) -> f64 {
        let slots = self
            .frames
            .iter()
            .flat_map(|f| f.encoded.chunks(RTP_BODY))
            .filter(|s| s.len() + 1 >= SLOT_START + HEADER + block_size)
            .count();
        (slots * block_size) as f64 * 8.0 / self.duration.as_secs_f64() / 1e6
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 32 && bytes.len() <= MAX_FILE,
            "invalid IVF size"
        );
        ensure!(
            &bytes[..4] == b"DKIF" && &bytes[8..12] == b"VP80",
            "expected VP8 IVF"
        );
        ensure!(
            u16::from_le_bytes(bytes[4..6].try_into()?) == 0,
            "unsupported IVF version"
        );
        ensure!(
            u16::from_le_bytes(bytes[6..8].try_into()?) == 32,
            "unsupported IVF header"
        );
        let rate = u32::from_le_bytes(bytes[16..20].try_into()?);
        let scale = u32::from_le_bytes(bytes[20..24].try_into()?);
        ensure!(
            rate > 0 && scale > 0 && rate as u64 <= 240 * scale as u64,
            "invalid timebase"
        );
        let mut frames: Vec<VideoFrame> = Vec::new();
        let mut cursor = 32;
        let mut first = None;
        while cursor < bytes.len() {
            ensure!(cursor + 12 <= bytes.len(), "truncated IVF frame header");
            let size = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into()?) as usize;
            let timestamp = u64::from_le_bytes(bytes[cursor + 4..cursor + 12].try_into()?);
            let origin = *first.get_or_insert(timestamp);
            ensure!(timestamp >= origin, "IVF timestamp before origin");
            let ns = (timestamp - origin) as u128 * scale as u128 * 1_000_000_000 / rate as u128;
            ensure!(ns < 3_600_000_000_000, "IVF clip too long");
            let at = Duration::from_nanos(ns as u64);
            ensure!(
                frames.last().is_none_or(|f| at > f.at),
                "nonmonotonic IVF timestamps"
            );
            cursor += 12;
            ensure!(
                size > 0 && size <= 4 * 1024 * 1024 && cursor + size <= bytes.len(),
                "invalid IVF frame size"
            );
            ensure!(frames.len() < 100_000, "too many IVF frames");
            frames.push(VideoFrame {
                at,
                encoded: bytes[cursor..cursor + size].to_vec(),
            });
            cursor += size;
        }
        ensure!(frames.len() >= 2, "at least two video frames required");
        let last = frames.last().expect("length checked").at;
        let duration = last + (last - frames[frames.len() - 2].at);
        Ok(Self { frames, duration })
    }
    pub fn slots(&self, index: usize) -> Vec<Vec<u8>> {
        self.frames[index]
            .encoded
            .chunks(RTP_BODY)
            .enumerate()
            .map(|(i, data)| {
                let mut out = Vec::with_capacity(data.len() + 1);
                // X=0, S=1 on first packet, PartID=0; no optional descriptor fields.
                out.push(if i == 0 { 0x10 } else { 0 });
                out.extend_from_slice(data);
                out
            })
            .collect()
    }
}

pub fn capacity(payload: &[u8]) -> usize {
    payload.len().saturating_sub(SLOT_START + HEADER)
}

pub fn embed(payload: &mut [u8], frame: &Frame) -> Result<()> {
    embed_with_wide_datagrams(payload, frame, false)
}

pub(crate) fn embed_with_wide_datagrams(
    payload: &mut [u8],
    frame: &Frame,
    wide_datagrams: bool,
) -> Result<()> {
    ensure!(
        payload.len() >= SLOT_START + HEADER && frame.payload.len() <= capacity(payload),
        "carrier slot too small"
    );
    frame.encode_with_wide_datagrams(&mut payload[SLOT_START..], wide_datagrams)?;
    Ok(())
}

pub fn extract(payload: &[u8]) -> Option<Frame> {
    extract_with_wide_datagrams(payload, false)
}

pub(crate) fn extract_with_wide_datagrams(payload: &[u8], wide_datagrams: bool) -> Option<Frame> {
    // Mapping v1 supports only the descriptor emitted above, not arbitrary VP8.
    if payload.len() < SLOT_START + HEADER || (payload[0] != 0 && payload[0] != 0x10) {
        return None;
    }
    Frame::decode_with_wide_datagrams(&payload[SLOT_START..], wide_datagrams).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Kind;
    #[test]
    fn pacing_preserves_packet_sizes_frame_boundaries_and_cycle_timing() -> Result<()> {
        let clip = Clip::parse(include_bytes!("../fixtures/cover-vp8.ivf"))?;
        let mut schedule = Schedule::new(&clip);
        let mut previous = None;
        for cycle in 0..2 {
            for (index, frame) in clip.frames.iter().enumerate() {
                let slots = clip.slots(index);
                let count = slots.len();
                for (i, expected) in slots.into_iter().enumerate() {
                    let at = schedule.next_at();
                    assert!(previous.is_none_or(|p| at > p));
                    if !at.is_zero() {
                        assert!(schedule.pop_due(at - Duration::from_nanos(1)).is_none());
                    }
                    let packet = schedule.pop_due(at).unwrap();
                    assert_eq!(packet.payload, expected);
                    assert_eq!(packet.marker, i + 1 == count);
                    let frame_at = clip.duration * cycle + frame.at;
                    assert_eq!(
                        packet.timestamp,
                        (frame_at.as_nanos() * 90_000 / 1_000_000_000) as u32
                    );
                    previous = Some(at);
                }
            }
        }
        Ok(())
    }
    #[test]
    fn keeps_size_descriptor_and_prefix() -> Result<()> {
        let mut slot = vec![0x55; 1101];
        slot[0] = 0x10;
        let before = slot.clone();
        let frame = Frame {
            kind: Kind::Data,
            flow: 1,
            sequence: 1,
            payload: vec![2; 900],
        };
        embed(&mut slot, &frame)?;
        assert_eq!(slot.len(), before.len());
        assert_eq!(&slot[..SLOT_START], &before[..SLOT_START]);
        assert_eq!(extract(&slot), Some(frame));
        assert!(extract(&before).is_none());
        Ok(())
    }
    #[test]
    fn fixture_and_truncation() -> Result<()> {
        let bytes = include_bytes!("../fixtures/cover-vp8.ivf");
        let clip = Clip::parse(bytes)?;
        assert!(clip.frames.len() >= 30);
        assert!(clip.slots(0).iter().all(|s| s.len() <= 1101));
        assert!(Clip::parse(&bytes[..bytes.len() - 1]).is_err());
        let mut broken = bytes.to_vec();
        broken[16..20].fill(0);
        assert!(Clip::parse(&broken).is_err());
        Ok(())
    }
}
