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
//! What is here is the link frame with its CRCs, unconfirmed and confirmed
//! user data with the reset of link states, and the transport function over
//! TCP. The serial carrier through `xmip-core-transport-serial`, and secure
//! authentication (IEEE 1815-2012 chapter 7) are the next layers.
//!
//! **The master is answered after the whole receive cycle.** It sends a
//! fragment's last segment as confirmed user data and waits for the link's
//! answer, a secondary function code of IEEE 1815-2012 chapter 9: ACK on
//! [`transport::Verdict::Accepted`]; `NOT_SUPPORTED`
//! ([`link::CONTROL_NOT_SUPPORTED`], the link layer's one permanent answer)
//! on [`transport::Verdict::Refused`], which it does not send again; NACK on
//! [`transport::Verdict::Failed`], which it sends again. A master that sends
//! unconfirmed user data waits for nothing, and such a fragment is
//! at-most-once ([`outstation::AT_MOST_ONCE`]). Each fragment arrives whole,
//! and the connection is kept for the master's next.
//!
//! The origin URI carries what the link knew:
//! `dnp3://peer/1024?destination=1&seq=5`.

pub mod link;
pub mod master;
pub mod outstation;

use std::net::TcpListener;
use std::time::Duration;

pub use link::{Frame, MAX_SEGMENT, Segment};
pub use master::Master;
pub use outstation::{Fragment, Outstation};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::serving::Serving;
use transport::socket;
use transport::{Arrived, Configured, Directions, Taken, Transport};
use xcore::settings::{Applies, Kind, Presence, Read, Setting, Settings};

#[derive(Clone)]
pub struct Dnp3Transport {
    bind: String,
    source: u16,
    destination: u16,
    timeout: Option<Duration>,
    /// The listener the first receive binds, and the masters' connections
    /// kept open on it between their fragments.
    receiving: Serving<Outstation>,
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
            receiving: Serving::new(),
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
        Ok(Outstation::new(stream, peer))
    }

    /// Connect to the outstation at `target` as the master.
    ///
    /// # Errors
    /// Where the outstation refused or could not be reached.
    pub fn connect(&self, target: &str) -> Result<Master> {
        let stream = socket::connect_tcp(target, self.timeout)?;
        Ok(Master::new(stream, self.source, self.destination))
    }
}

impl Transport for Dnp3Transport {
    fn name(&self) -> &'static str {
        "dnp3"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a link's frames are confirmed in sequence")
    }

    /// The next fragment from whichever master sends first, on the listener
    /// the first receive bound and kept, whole. A master that sent it
    /// confirmed waits for the link's answer until the receive cycle has
    /// ended: ACK on accepted, NACK on refused. One sent unconfirmed is
    /// at-most-once ([`outstation::AT_MOST_ONCE`]).
    fn receive(&self) -> Result<Vec<Arrived>> {
        let arrived = self.receiving.next(
            || self.bind(),
            self.timeout,
            |stream, peer| Ok(Outstation::new(stream, peer)),
            Outstation::turn,
        )?;
        Ok(vec![arrived])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        self.connect(target)?.send_fragment(bytes)
    }
}

impl Configured for Dnp3Transport {
    /// The address is where a Receive Location listens as the outstation —
    /// `0.0.0.0:20000` the standard port; a Send Location connects as the
    /// master to the target its route gives.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "source",
                kind: Kind::Integer {
                    minimum: 0,
                    maximum: 65_535,
                },
                presence: Presence::Required,
                meaning: "The master's own link address, which its frames come from.",
                applies: Applies::Send,
            },
            Setting {
                name: "destination",
                kind: Kind::Integer {
                    minimum: 0,
                    maximum: 65_535,
                },
                presence: Presence::Required,
                meaning: "The outstation's link address, which the master's frames go to.",
                applies: Applies::Send,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a peer that stops mid-frame is waited on; unbounded when \
                          left out.",
                applies: Applies::Both,
            },
        ],
    };

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        // An outstation reads no link address: it takes what a master sends.
        let link = |name: &str| {
            u16::try_from(settings.optional_integer(name).unwrap_or_default())
                .map_err(|_| protocol_error(format!("a {name} link address over 16 bits")))
        };
        let transport = Self::new(address, link("source")?, link("destination")?);
        Ok(match settings.optional_duration("timeout") {
            Some(timeout) => transport.timing_out_after(timeout),
            None => transport,
        })
    }
}

impl Dnp3Transport {
    /// Both ends on this machine: an ephemeral local port, the outstation at
    /// link address 1024 spoken to by a master at 1, the loopback timeout on
    /// either side.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", 1024, 1).timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for Dnp3Transport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        let mut outstation = self.accept_one(listener)?;
        outstation
            .next_arrival()?
            .ok_or_else(|| protocol_error("the master closed without a fragment"))?
            .taken()
    }
}

/// A Stream travels as one fragment: the master speaks from the far end's
/// destination to its source.
impl Loopback for Dnp3Transport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let mut master = Self::new("127.0.0.1:0", self.destination, self.source);
        master.timeout = self.timeout;
        master.send(address, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpStream;
    use transport::payload::edge_payloads;
    use xcore::settings::Given;

    #[test]
    fn every_receive_takes_from_the_listener_the_first_bound() {
        let receiver = Dnp3Transport::loopback();
        let address = receiver
            .receiving
            .bound(|| receiver.bind())
            .expect("bound")
            .to_string();
        transport::kept::held_across_receives(&receiver, &address, 5, |at, payload| {
            Dnp3Transport::loopback().send_to(at, payload)
        });
    }

    #[test]
    fn a_fragment_is_answered_not_supported_when_refused_nack_when_failed_then_ack() {
        let receiver = Dnp3Transport::loopback();
        let address = receiver
            .receiving
            .bound(|| receiver.bind())
            .expect("bound")
            .to_string();
        let master = std::thread::spawn(move || {
            let mut master = Dnp3Transport::new("127.0.0.1:0", 1, 1024)
                .timing_out_after(LOOPBACK_TIMEOUT)
                .connect(&address)?;
            let refused = master.send_fragment(b"R1").expect_err("NOT_SUPPORTED");
            let failed = master.send_fragment(b"C1").expect_err("NACK");
            master.send_fragment(b"C1")?;
            Ok::<_, transport::TransportError>((refused, failed))
        });
        let first = receiver.receive().expect("first").remove(0);
        assert!(first.defers(), "the master waits for the link's answer");
        first
            .refused(transport::Refusal::Unacceptable)
            .expect("refused");
        let second = receiver.receive().expect("second").remove(0);
        second.failed().expect("failed");
        let again = receiver.receive().expect("again, on the kept connection");
        let again = again.into_iter().next().expect("one").taken().expect("ACK");
        assert_eq!(again.bytes, b"C1");
        let (refused, failed) = master.join().expect("thread").expect("acknowledged");
        assert!(!refused.retryable, "{refused}");
        assert!(refused.message.contains("NOT_SUPPORTED"), "{refused}");
        assert!(failed.retryable, "{failed}");
        assert!(failed.message.contains("NACK"), "{failed}");
    }

    #[test]
    fn unconfirmed_user_data_is_at_most_once() {
        let far_end = outstation();
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connecting");
            let frame = Frame {
                control: link::CONTROL_MASTER_DATA,
                destination: 1024,
                source: 1,
                user_data: vec![0xc0, 7],
            };
            stream
                .write_all(&link::encode(&frame).expect("encode"))
                .expect("writing");
        });
        let mut outstation = far_end.accept_one(&listener).expect("accepting");
        let arrived = outstation.next_arrival().expect("read").expect("one");
        assert!(!arrived.defers(), "nobody waits for unconfirmed data");
        assert_eq!(arrived.taken().expect("taken").bytes, [7]);
        sender.join().expect("thread");
    }

    /// The next fragment on `outstation`, accepted: the master is answered
    /// ACK.
    fn accepted(outstation: &mut Outstation) -> Option<Taken> {
        let arrived = outstation.next_arrival().expect("read")?;
        Some(arrived.taken().expect("accepted"))
    }

    #[test]
    fn dnp3_declares_its_settings_and_reads_through_them() {
        assert_eq!(Dnp3Transport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("source".to_string(), Given::Integer(1)),
            ("destination".to_string(), Given::Integer(1024)),
            ("timeout".to_string(), Given::Text("2s".to_string())),
        ];
        let master = Dnp3Transport::open("0.0.0.0:0", Applies::Send, &given).expect("master");
        assert_eq!((master.source, master.destination), (1, 1024));
        assert_eq!(master.timeout, Some(Duration::from_secs(2)));
        assert!(Dnp3Transport::open("0.0.0.0:20000", Applies::Receive, &[]).is_ok());
        let given = [("source".to_string(), Given::Integer(1))];
        let Err(refused) = Dnp3Transport::open("0.0.0.0:0", Applies::Send, &given) else {
            panic!("destination is required on a Send Location");
        };
        assert!(
            refused.message.contains("\"destination\""),
            "{}",
            refused.message
        );
    }

    fn outstation() -> Dnp3Transport {
        Dnp3Transport::new("127.0.0.1:0", 1024, 1).timing_out_after(Duration::from_secs(2))
    }

    #[test]
    fn a_loopback_round_carries_a_stream_as_one_fragment() {
        let loopback = Dnp3Transport::loopback();
        let arrived = loopback.round(b"fragment").expect("round");
        assert_eq!(arrived.bytes, b"fragment");
        assert!(arrived.origin_uri.starts_with("dnp3://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/1?destination=1024&seq=0"));
        let long = vec![0x2a; 3000];
        assert_eq!(
            loopback.round(&long).expect("thirteen segments").bytes,
            long
        );
        assert!(
            loopback
                .round(b"")
                .expect("one empty segment")
                .bytes
                .is_empty()
        );
        assert!(loopback.ceiling().is_none());
        assert!(loopback.refuses(&long).is_none());
    }

    #[test]
    fn the_loopback_returns_the_edges_whole() {
        let loopback = Dnp3Transport::loopback();
        for (name, bytes) in edge_payloads() {
            let arrived = loopback
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
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
        let read = accepted(&mut outstation).expect("one");
        assert_eq!(read.bytes, [0xc0, 0x01, 0x3c, 0x02, 0x06]);
        assert!(read.origin_uri.ends_with("/1?destination=1024&seq=0"));
        let big = accepted(&mut outstation).expect("big");
        assert_eq!(big.bytes, long);
        assert!(big.origin_uri.ends_with("&seq=1"));
        let empty = accepted(&mut outstation).expect("empty");
        assert!(empty.bytes.is_empty());
        assert!(accepted(&mut outstation).is_none(), "closed");
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
        let big = accepted(&mut outstation).expect("big");
        assert_eq!(big.bytes, long);
        let next = accepted(&mut outstation).expect("next");
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
        while let Some(fragment) = accepted(&mut outstation) {
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
