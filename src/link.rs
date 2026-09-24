//! IEEE 1815 data link and transport functions: the frame — two start
//! bytes, a length, a control byte, destination and source, a CRC over
//! that header, then user data in blocks of sixteen each with its own CRC
//! — and the one-byte transport header that splits an application
//! fragment across frames. The CRC is CRC-16/DNP, codec's.

use std::io::Read;

use codec::crc::CRC_16_DNP;
use transport::error::{Result, classify, protocol_error};

/// The two start bytes.
pub const START: [u8; 2] = [0x05, 0x64];
/// The most user data one frame carries.
pub const MAX_USER_DATA: usize = 250;
/// The most application fragment one transport segment carries: the user
/// data less the transport header.
pub const MAX_SEGMENT: usize = MAX_USER_DATA - 1;
/// Primary-to-secondary unconfirmed user data, direction bit for a master.
pub const CONTROL_MASTER_DATA: u8 = 0xc4;
/// The same from an outstation.
pub const CONTROL_OUTSTATION_DATA: u8 = 0x44;

/// One link frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub control: u8,
    pub destination: u16,
    pub source: u16,
    pub user_data: Vec<u8>,
}

/// Encode `frame`.
///
/// # Errors
/// User data over [`MAX_USER_DATA`].
pub fn encode(frame: &Frame) -> Result<Vec<u8>> {
    if frame.user_data.len() > MAX_USER_DATA {
        return Err(protocol_error("user data over what one frame carries"));
    }
    let mut header = Vec::with_capacity(8);
    header.extend_from_slice(&START);
    header.push(u8::try_from(5 + frame.user_data.len()).unwrap_or(u8::MAX));
    header.push(frame.control);
    header.extend_from_slice(&frame.destination.to_le_bytes());
    header.extend_from_slice(&frame.source.to_le_bytes());
    let mut out = header.clone();
    out.extend_from_slice(&CRC_16_DNP.checksum(&header).to_le_bytes());
    for block in frame.user_data.chunks(16) {
        out.extend_from_slice(block);
        out.extend_from_slice(&CRC_16_DNP.checksum(block).to_le_bytes());
    }
    Ok(out)
}

/// Read one frame, or `None` when the peer closed between frames.
///
/// # Errors
/// A connection that closes mid-frame, no start bytes, a length under
/// five, or a CRC that does not check.
pub fn read(reader: &mut impl Read) -> Result<Option<Frame>> {
    let mut header = [0u8; 10];
    let first = reader
        .read(&mut header[..1])
        .map_err(|e| classify("reading the start", &e))?;
    if first == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut header[1..])
        .map_err(|e| classify("reading the link header", &e))?;
    if header[..2] != START {
        return Err(protocol_error("bytes that are not the DNP3 start"));
    }
    let length = usize::from(header[2]);
    if length < 5 {
        return Err(protocol_error("a length under five"));
    }
    if CRC_16_DNP.checksum(&header[..8]) != u16::from_le_bytes([header[8], header[9]]) {
        return Err(protocol_error("a header CRC that does not check"));
    }
    let mut user_data = Vec::with_capacity(length - 5);
    let mut remaining = length - 5;
    while remaining > 0 {
        let take = remaining.min(16);
        let mut block = vec![0u8; take + 2];
        reader
            .read_exact(&mut block)
            .map_err(|e| classify("reading a data block", &e))?;
        let check = u16::from_le_bytes([block[take], block[take + 1]]);
        if CRC_16_DNP.checksum(&block[..take]) != check {
            return Err(protocol_error("a block CRC that does not check"));
        }
        user_data.extend_from_slice(&block[..take]);
        remaining -= take;
    }
    Ok(Some(Frame {
        control: header[3],
        destination: u16::from_le_bytes([header[4], header[5]]),
        source: u16::from_le_bytes([header[6], header[7]]),
        user_data,
    }))
}

/// One transport segment's header: FIN, FIR and a sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub first: bool,
    pub last: bool,
    pub sequence: u8,
}

impl Segment {
    #[must_use]
    pub const fn header(self) -> u8 {
        (if self.last { 0x80 } else { 0 })
            | (if self.first { 0x40 } else { 0 })
            | (self.sequence & 0x3f)
    }

    #[must_use]
    pub const fn from_header(header: u8) -> Self {
        Self {
            first: header & 0x40 != 0,
            last: header & 0x80 != 0,
            sequence: header & 0x3f,
        }
    }
}

/// `fragment` split into transport segments, each with its header, the
/// sequence starting at `sequence` and wrapping at sixty-four however many
/// segments there are. An empty fragment is one empty segment.
#[must_use]
pub fn segments(fragment: &[u8], sequence: u8) -> Vec<Vec<u8>> {
    let pieces: Vec<&[u8]> = if fragment.is_empty() {
        vec![&[][..]]
    } else {
        fragment.chunks(MAX_SEGMENT).collect()
    };
    let count = pieces.len();
    pieces
        .into_iter()
        .enumerate()
        .map(|(i, piece)| {
            let header = Segment {
                first: i == 0,
                last: i + 1 == count,
                sequence: next_sequence(sequence, i),
            };
            let mut out = Vec::with_capacity(piece.len() + 1);
            out.push(header.header());
            out.extend_from_slice(piece);
            out
        })
        .collect()
}

/// The sequence `steps` segments after `sequence`: six bits, wrapping. Found
/// 2026-09-09 as `sequence + i` in a `u8`, which stopped counting at the
/// 256th segment and closed every fragment over 63 750 bytes.
#[must_use]
pub fn next_sequence(sequence: u8, steps: usize) -> u8 {
    u8::try_from((usize::from(sequence) + steps) % 64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crc_matches_the_standard_and_frames_round_trip() {
        // IEEE 1815 gives 0x05 0x64 0x05 0xc0 0x01 0x00 0x00 0x04 as a
        // header with CRC 0xe9 0x21.
        assert_eq!(
            CRC_16_DNP.checksum(&[0x05, 0x64, 0x05, 0xc0, 0x01, 0x00, 0x00, 0x04]),
            u16::from_le_bytes([0xe9, 0x21])
        );
        let frame = Frame {
            control: CONTROL_MASTER_DATA,
            destination: 1024,
            source: 1,
            user_data: (0..40).collect(),
        };
        let bytes = encode(&frame).expect("encode");
        assert_eq!(bytes.len(), 10 + 40 + 3 * 2);
        let back = read(&mut bytes.as_slice()).expect("read").expect("one");
        assert_eq!(back, frame);
        let empty = Frame {
            user_data: Vec::new(),
            ..frame.clone()
        };
        let bytes = encode(&empty).expect("encode");
        assert_eq!(bytes.len(), 10);
        assert_eq!(read(&mut bytes.as_slice()).expect("read"), Some(empty));
        assert!(read(&mut &[][..]).expect("closed").is_none());
    }

    #[test]
    fn a_bad_crc_or_start_is_refused_and_segments_split_a_fragment() {
        let frame = Frame {
            control: CONTROL_OUTSTATION_DATA,
            destination: 1,
            source: 1024,
            user_data: vec![1, 2, 3],
        };
        let mut bytes = encode(&frame).expect("encode");
        bytes[12] ^= 0xff;
        assert!(read(&mut bytes.as_slice()).is_err(), "block CRC");
        let mut bytes = encode(&frame).expect("encode");
        bytes[8] ^= 0xff;
        assert!(read(&mut bytes.as_slice()).is_err(), "header CRC");
        bytes[0] = 0x06;
        assert!(read(&mut bytes.as_slice()).is_err(), "start");
        assert!(read(&mut &bytes[..5]).is_err(), "cut off");
        assert!(
            encode(&Frame {
                user_data: vec![0; MAX_USER_DATA + 1],
                ..frame
            })
            .is_err()
        );
        let fragment = vec![7u8; MAX_SEGMENT * 2 + 1];
        let pieces = segments(&fragment, 62);
        assert_eq!(pieces.len(), 3);
        assert_eq!(
            Segment::from_header(pieces[0][0]),
            Segment {
                first: true,
                last: false,
                sequence: 62
            }
        );
        assert_eq!(Segment::from_header(pieces[1][0]).sequence, 63);
        let last = Segment::from_header(pieces[2][0]);
        assert!(last.last && !last.first);
        assert_eq!(last.sequence, 0, "wraps at 64");
        assert_eq!(pieces[2].len(), 2);
        assert_eq!(segments(&[], 3), vec![vec![0xc3]]);
    }

    #[test]
    fn a_fragment_of_hundreds_of_segments_keeps_counting() {
        let fragment = vec![7u8; MAX_SEGMENT * 300];
        let pieces = segments(&fragment, 60);
        assert_eq!(pieces.len(), 300);
        for (i, pair) in pieces.windows(2).enumerate() {
            let before = Segment::from_header(pair[0][0]);
            let after = Segment::from_header(pair[1][0]);
            assert_eq!(after.sequence, (before.sequence + 1) & 0x3f, "segment {i}");
            assert!(!after.first, "segment {i}");
        }
        assert!(Segment::from_header(pieces[299][0]).last);
        assert_eq!(next_sequence(60, 300), 40, "360 modulo 64");
        assert_eq!(next_sequence(63, 1), 0);
    }
}
