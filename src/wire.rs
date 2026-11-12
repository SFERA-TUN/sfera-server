//! Bounded, versioned messages carried inside authenticated SRTP payloads.

use anyhow::{Result, bail, ensure};

pub const HEADER: usize = 16;
// 1101-byte RTP payload minus the 17-byte preserved VP8 prefix and our header.
pub const MAX_DATA: usize = 1068;
pub(crate) const MAX_WIDE_DATAGRAM: usize = 1280;
pub const ACK_BYTES: usize = 64;
pub const MAX_ACK_BYTES: usize = 512;
const MAGIC: &[u8; 3] = b"SFM";
pub const VERSION: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Data = 1,
    Ack = 2,
    Datagram = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub flow: u32,
    pub sequence: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn encode(&self, destination: &mut [u8]) -> Result<usize> {
        self.encode_with_wide_datagrams(destination, false)
    }

    pub(crate) fn encode_with_wide_datagrams(
        &self,
        destination: &mut [u8],
        wide_datagrams: bool,
    ) -> Result<usize> {
        self.validate(wide_datagrams)?;
        let size = HEADER + self.payload.len();
        ensure!(destination.len() >= size, "slot too small");
        destination[..3].copy_from_slice(MAGIC);
        destination[3] = VERSION;
        destination[4] = self.kind as u8;
        destination[5] = 0;
        destination[6..8].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
        destination[8..12].copy_from_slice(&self.flow.to_be_bytes());
        destination[12..16].copy_from_slice(&self.sequence.to_be_bytes());
        destination[HEADER..size].copy_from_slice(&self.payload);
        Ok(size)
    }

    /// Trailing bytes belong to the unchanged cover payload, not the frame.
    pub fn decode(source: &[u8]) -> Result<Self> {
        Self::decode_with_wide_datagrams(source, false)
    }

    pub(crate) fn decode_with_wide_datagrams(source: &[u8], wide_datagrams: bool) -> Result<Self> {
        ensure!(source.len() >= HEADER, "truncated header");
        ensure!(
            &source[..3] == MAGIC && source[3] == VERSION,
            "unknown wire version"
        );
        ensure!(source[5] == 0, "reserved flags are nonzero");
        let kind = match source[4] {
            1 => Kind::Data,
            2 => Kind::Ack,
            3 => Kind::Datagram,
            _ => bail!("unknown frame kind"),
        };
        let size = u16::from_be_bytes(source[6..8].try_into()?) as usize;
        ensure!(
            size <= Self::payload_limit(kind, wide_datagrams) && source.len() >= HEADER + size,
            "invalid payload length"
        );
        let result = Self {
            kind,
            flow: u32::from_be_bytes(source[8..12].try_into()?),
            sequence: u32::from_be_bytes(source[12..16].try_into()?),
            payload: source[HEADER..HEADER + size].to_vec(),
        };
        result.validate(wide_datagrams)?;
        Ok(result)
    }

    fn payload_limit(kind: Kind, wide_datagrams: bool) -> usize {
        if wide_datagrams && kind == Kind::Datagram {
            MAX_WIDE_DATAGRAM
        } else {
            MAX_DATA
        }
    }

    fn validate(&self, wide_datagrams: bool) -> Result<()> {
        ensure!(
            self.flow != 0 && self.sequence != 0,
            "zero flow or sequence"
        );
        ensure!(
            self.payload.len() <= Self::payload_limit(self.kind, wide_datagrams),
            "payload exceeds limit"
        );
        if self.kind == Kind::Ack {
            ensure!(
                (4..=MAX_ACK_BYTES).contains(&self.payload.len())
                    && self.payload.len().is_power_of_two(),
                "ACK requires a power-of-two bitmap of 4..512 bytes"
            );
        } else {
            ensure!(!self.payload.is_empty(), "empty data");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_payload_requires_opt_in_and_is_bounded() -> Result<()> {
        let mut frame = Frame {
            kind: Kind::Datagram,
            flow: 10,
            sequence: 1,
            payload: vec![42; MAX_WIDE_DATAGRAM],
        };
        let mut bytes = [0; HEADER + MAX_WIDE_DATAGRAM + 1];
        assert!(frame.encode(&mut bytes).is_err());
        let length = frame.encode_with_wide_datagrams(&mut bytes, true)?;
        assert!(Frame::decode(&bytes[..length]).is_err());
        assert_eq!(
            Frame::decode_with_wide_datagrams(&bytes[..length], true)?,
            frame
        );
        frame.kind = Kind::Data;
        assert!(frame.encode_with_wide_datagrams(&mut bytes, true).is_err());
        frame.kind = Kind::Datagram;
        frame.payload.push(42);
        assert!(frame.encode_with_wide_datagrams(&mut bytes, true).is_err());
        Ok(())
    }

    #[test]
    fn roundtrip_and_reject_malformed() {
        let frame = Frame {
            kind: Kind::Data,
            flow: 1,
            sequence: 17,
            payload: vec![42; 50],
        };
        let mut bytes = [0xa5; 100];
        let len = frame.encode(&mut bytes).unwrap();
        assert_eq!(Frame::decode(&bytes).unwrap(), frame);
        assert!(bytes[len..].iter().all(|b| *b == 0xa5));
        for end in 0..len {
            assert!(Frame::decode(&bytes[..end]).is_err());
        }
        for (offset, value) in [(3, 9), (4, 99), (5, 1), (6, 255)] {
            let mut bad = bytes;
            bad[offset] = value;
            assert!(Frame::decode(&bad).is_err());
        }
        let mut bad = bytes;
        bad[4] = Kind::Ack as u8;
        assert!(Frame::decode(&bad).is_err());
    }
}
