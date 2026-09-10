#![forbid(unsafe_code)]

//! Streams that arrive as DNP3 application fragments. One fragment is one
//! Stream: the link frames and transport segments that carried it are the
//! transport's, and the function code, objects and points inside are a
//! contract's.
//!
//! DNP3 is the utility SCADA protocol, IEEE 1815: an outstation in the
//! field, a master in the control centre, over TCP on port 20000 or a
//! serial line. A Receive Location listens as the outstation and hands each
//! fragment up; a Send Location connects as the master and sends one. A
//! fragment longer than a frame travels as transport segments, first to
//! last, and is reassembled here.
//!
//! What is here is the link frame with its CRCs, unconfirmed user data,
//! and the transport function over TCP. Link confirmation, the serial
//! carrier through `xmip-core-transport-serial`, and secure authentication
//! (IEEE 1815-2012 chapter 7) are the next layers.
//!
//! The origin URI carries what the link knew:
//! `dnp3://peer/1024?destination=1&seq=5`.

pub mod link;

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

pub use link::{Frame, MAX_SEGMENT, Segment};
use transport::error::{Result, classify, protocol_error};
use transport::socket;
use transport::{Arrived, Directions, Transport};

/// The outstation's side of one connection.
pub struct Outstation {
    stream: TcpStream,
    peer: SocketAddr,
}

impl Outstation {
    /// The next application fragment, reassembled from its segments, or
    /// `None` when the master closed.
    ///
    /// # Errors
    /// Where the connection broke, a segment came out of sequence, or a
    /// fragment began without its first segment.
    pub fn next_fragment(&mut self) -> Result<Option<Arrived>> {
        let mut fragment = Vec::new();
        let mut expected: Option<u8> = None;
        let mut origin = String::new();
        loop {
            let Some(frame) = link::read(&mut self.stream)? else {
                if expected.is_some() {
                    return Err(protocol_error("the master closed mid-fragment"));
                }
                return Ok(None);
            };
            let Some((header, data)) = frame.user_data.split_first() else {
                continue;
            };
            let segment = Segment::from_header(*header);
            match expected {
                None if segment.first => {
                    origin = format!(
                        "dnp3://{}/{}?destination={}&seq={}",
                        self.peer, frame.source, frame.destination, segment.sequence
                    );
                }
                None => return Err(protocol_error("a segment with no fragment begun")),
                Some(sequence) if sequence == segment.sequence && !segment.first => {}
                Some(sequence) => {
                    return Err(protocol_error(format!(
                        "segment {} where {sequence} was expected",
                        segment.sequence
                    )));
                }
            }
            fragment.extend_from_slice(data);
            if segment.last {
                return Ok(Some(Arrived::new(origin, fragment)));
            }
            expected = Some((segment.sequence + 1) & 0x3f);
        }
    }
}

/// The master's side of one connection.
pub struct Master {
    stream: TcpStream,
    source: u16,
    destination: u16,
    sequence: u8,
}

impl Master {
    /// Send `fragment` as one or more frames.
    ///
    /// # Errors
    /// Where the outstation went away.
    pub fn send_fragment(&mut self, fragment: &[u8]) -> Result<()> {
        let segments = link::segments(fragment, self.sequence);
        self.sequence = link::next_sequence(self.sequence, segments.len());
        for user_data in segments {
            let frame = Frame {
                control: link::CONTROL_MASTER_DATA,
                destination: self.destination,
                source: self.source,
                user_data,
            };
            self.stream
                .write_all(&link::encode(&frame)?)
                .map_err(|e| classify("writing a frame", &e))?;
        }
        self.stream
            .flush()
            .map_err(|e| classify("flushing the frames", &e))
    }
}

pub struct Dnp3Transport {
    bind: String,
    source: u16,
    destination: u16,
    timeout: Option<Duration>,
}

impl Dnp3Transport {
    /// Listen or connect at `bind`, `0.0.0.0:20000` being the standard
    /// port, as link address `source` speaking to `destination`.
    #[must_use]
    pub fn new(bind: impl Into<String>, source: u16, destination: u16) -> Self {
        Self {
            bind: bind.into(),
            source,
            destination,
            timeout: None,
        }
    }

    /// Give up on a peer that stops mid-frame.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bind and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.bind)
    }

    /// Accept one master on an already-bound listener.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Outstation> {
        let (stream, peer) = socket::accept_tcp(listener, self.timeout)?;
        Ok(Outstation { stream, peer })
    }

    /// Connect to the outstation at `target` as the master.
    ///
    /// # Errors
    /// Where the outstation refused or could not be reached.
    pub fn connect(&self, target: &str) -> Result<Master> {
        let stream = socket::connect_tcp(target, self.timeout)?;
        Ok(Master {
            stream,
            source: self.source,
            destination: self.destination,
            sequence: 0,
        })
    }
}

impl Transport for Dnp3Transport {
    fn name(&self) -> &'static str {
        "dnp3"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// One master's fragments until it closes.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let (listener, _) = self.bind()?;
        let mut outstation = self.accept_one(&listener)?;
        let mut arrived = Vec::new();
        while let Some(fragment) = outstation.next_fragment()? {
            arrived.push(fragment);
        }
        Ok(arrived)
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        self.connect(target)?.send_fragment(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outstation() -> Dnp3Transport {
        Dnp3Transport::new("127.0.0.1:0", 1024, 1).timing_out_after(Duration::from_secs(2))
    }

    #[test]
    fn fragments_travel_as_segments_and_come_back_whole() {
        let far_end = outstation();
        let (listener, address) = far_end.bind().expect("binding");
        let long: Vec<u8> = (0..2000)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();
        let sent = long.clone();
        let master = std::thread::spawn(move || {
            let mut master = Dnp3Transport::new("127.0.0.1:0", 1, 1024)
                .timing_out_after(Duration::from_secs(2))
                .connect(&address)?;
            master.send_fragment(&[0xc0, 0x01, 0x3c, 0x02, 0x06])?;
            master.send_fragment(&sent)?;
            master.send_fragment(&[])
        });
        let mut outstation = far_end.accept_one(&listener).expect("accepting");
        let read = outstation.next_fragment().expect("read").expect("one");
        assert_eq!(read.bytes, [0xc0, 0x01, 0x3c, 0x02, 0x06]);
        assert!(read.origin_uri.ends_with("/1?destination=1024&seq=0"));
        let big = outstation.next_fragment().expect("big").expect("one");
        assert_eq!(big.bytes, long);
        assert!(big.origin_uri.ends_with("&seq=1"));
        let empty = outstation.next_fragment().expect("empty").expect("one");
        assert!(empty.bytes.is_empty());
        assert!(outstation.next_fragment().expect("closed").is_none());
        master.join().expect("thread").expect("mastering");
    }

    #[test]
    fn a_fragment_over_two_hundred_and_fifty_six_segments_comes_back_whole() {
        let far_end = outstation();
        let (listener, address) = far_end.bind().expect("binding");
        let long: Vec<u8> = (0..70_000)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();
        let sent = long.clone();
        let master = std::thread::spawn(move || {
            let mut master = Dnp3Transport::new("127.0.0.1:0", 1, 1024)
                .timing_out_after(Duration::from_secs(2))
                .connect(&address)?;
            master.send_fragment(&sent)?;
            master.send_fragment(b"after")
        });
        let mut outstation = far_end.accept_one(&listener).expect("accepting");
        let big = outstation.next_fragment().expect("big").expect("one");
        assert_eq!(big.bytes, long);
        let next = outstation.next_fragment().expect("next").expect("one");
        assert_eq!(next.bytes, b"after");
        assert!(next.origin_uri.ends_with("&seq=26"), "{}", next.origin_uri);
        master.join().expect("thread").expect("mastering");
    }

    #[test]
    fn the_transport_trait_receives_and_sends() {
        let far_end = outstation();
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            Dnp3Transport::new("127.0.0.1:0", 1, 1024)
                .timing_out_after(Duration::from_secs(2))
                .send(&address, b"fragment")
        });
        let mut outstation = far_end.accept_one(&listener).expect("accepting");
        let mut arrived = Vec::new();
        while let Some(fragment) = outstation.next_fragment().expect("receiving") {
            arrived.push(fragment);
        }
        sender.join().expect("thread").expect("sending");
        assert_eq!(arrived.len(), 1);
        assert_eq!(arrived[0].bytes, b"fragment");
        assert!(far_end.claims().is_none());
    }

    #[test]
    fn a_segment_out_of_sequence_is_refused() {
        let far_end = outstation();
        let (listener, address) = far_end.bind().expect("binding");
        let rogue = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connecting");
            let frame = Frame {
                control: link::CONTROL_MASTER_DATA,
                destination: 1024,
                source: 1,
                user_data: vec![
                    Segment {
                        first: false,
                        last: true,
                        sequence: 3,
                    }
                    .header(),
                    1,
                ],
            };
            stream
                .write_all(&link::encode(&frame).expect("encode"))
                .expect("writing");
        });
        let mut outstation = far_end.accept_one(&listener).expect("accepting");
        let error = outstation.next_fragment().expect_err("no first segment");
        assert!(!error.retryable);
        rogue.join().expect("thread");
    }
}
