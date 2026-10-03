//! The outstation's side of one DNP3 connection: fragments reassembled from
//! their segments, the link answered where the master asked to be.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};

use transport::answer::Answer;
use transport::error::{Result, classify, protocol_error};
use transport::serving::{Open, Turn};
use transport::{Acknowledgement, Arrived, Verdict};

use crate::link::{
    self, CONTROL_ACK, CONTROL_NACK, CONTROL_NOT_SUPPORTED, Frame, Function, Segment,
};

/// Why a fragment sent as unconfirmed user data cannot be acknowledged
/// after the receive cycle.
pub const AT_MOST_ONCE: &str = "DNP3 unconfirmed user data has no reply: the master sent the \
                                fragment and waits for nothing";

/// One application fragment as it arrived, not yet answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// `dnp3://peer/1024?destination=1&seq=5`.
    pub origin_uri: String,
    pub bytes: Vec<u8>,
    /// Where the master sent its last segment as confirmed user data and
    /// waits for ACK or NACK: the frame that answers it goes from the
    /// second address to the first.
    confirm: Option<(u16, u16)>,
}

/// The outstation's side of one connection.
pub struct Outstation {
    stream: TcpStream,
    peer: SocketAddr,
}

impl Outstation {
    /// A connection a master opened from `peer`.
    #[must_use]
    pub const fn new(stream: TcpStream, peer: SocketAddr) -> Self {
        Self { stream, peer }
    }

    /// The next application fragment, reassembled from its segments, or
    /// `None` when the master closed. A reset of link states, and a
    /// confirmed segment before the last, are answered ACK as they come;
    /// the last confirmed segment waits for [`Outstation::answer`].
    ///
    /// # Errors
    /// Where the connection broke, a segment came out of sequence, or a
    /// fragment began without its first segment.
    pub fn next_fragment(&mut self) -> Result<Option<Fragment>> {
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
            let function = Function::of(frame.control);
            match function {
                Function::Reset => {
                    write_link(&mut self.stream, &frame, CONTROL_ACK)?;
                    continue;
                }
                Function::Other => continue,
                Function::Confirmed | Function::Unconfirmed => {}
            }
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
            let confirmed = function == Function::Confirmed;
            if segment.last {
                return Ok(Some(Fragment {
                    origin_uri: origin,
                    bytes: fragment,
                    confirm: confirmed.then_some((frame.source, frame.destination)),
                }));
            }
            if confirmed {
                write_link(&mut self.stream, &frame, CONTROL_ACK)?;
            }
            expected = Some((segment.sequence + 1) & 0x3f);
        }
    }

    /// The next fragment as a Stream. Sent as confirmed user data, its
    /// verdict answers the master: ACK on accepted, `NOT_SUPPORTED` on
    /// refused, which the master does not send again, NACK on failed, which
    /// it sends again. Sent unconfirmed, it is at-most-once
    /// ([`AT_MOST_ONCE`]). `None` when the master closed.
    ///
    /// # Errors
    /// As [`Outstation::next_fragment`], or the connection could not be
    /// held for the answer.
    pub fn next_arrival(&mut self) -> Result<Option<Arrived>> {
        let Some(fragment) = self.next_fragment()? else {
            return Ok(None);
        };
        let acknowledgement = if fragment.confirm.is_some() {
            // Let go without a verdict, the connection is shut.
            let held = Answer::held(&self.stream)?;
            let answered = fragment.clone();
            Acknowledgement::deferred(move |verdict| {
                held.with(|stream| answer(stream, &answered, verdict))
            })
        } else {
            Acknowledgement::at_most_once(AT_MOST_ONCE)
        };
        Ok(Some(Arrived::whole(
            fragment.origin_uri,
            fragment.bytes,
            acknowledgement,
        )))
    }

    /// One turn for a kept listener: the next arrival, or the master gone.
    ///
    /// # Errors
    /// As [`Outstation::next_arrival`].
    pub fn turn(&mut self) -> Result<Turn<Arrived>> {
        Ok(self.next_arrival()?.map_or(Turn::Closed, Turn::Taken))
    }

    /// Answer `fragment` as `verdict` says, where its master waits.
    ///
    /// # Errors
    /// Where the master went away before the answer.
    pub fn answer(&mut self, fragment: &Fragment, verdict: Verdict) -> Result<()> {
        answer(&mut self.stream, fragment, verdict)
    }
}

impl Open for Outstation {
    fn socket(&self) -> &TcpStream {
        &self.stream
    }
}

fn answer(stream: &mut TcpStream, fragment: &Fragment, verdict: Verdict) -> Result<()> {
    let Some((master, outstation)) = fragment.confirm else {
        return Ok(());
    };
    let control = match verdict {
        Verdict::Accepted => CONTROL_ACK,
        Verdict::Refused(_) => CONTROL_NOT_SUPPORTED,
        Verdict::Failed => CONTROL_NACK,
    };
    let reply = Frame {
        control,
        destination: master,
        source: outstation,
        user_data: Vec::new(),
    };
    write_frame(stream, &reply)
}

/// Answer the primary `frame` with the secondary `control`.
fn write_link(stream: &mut TcpStream, frame: &Frame, control: u8) -> Result<()> {
    let reply = Frame {
        control,
        destination: frame.source,
        source: frame.destination,
        user_data: Vec::new(),
    };
    write_frame(stream, &reply)
}

fn write_frame(stream: &mut TcpStream, frame: &Frame) -> Result<()> {
    stream
        .write_all(&link::encode(frame)?)
        .map_err(|e| classify("writing the link answer", &e))?;
    stream
        .flush()
        .map_err(|e| classify("flushing the link answer", &e))
}
