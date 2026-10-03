//! The master's side of one DNP3 connection: fragments sent as segments,
//! the last as confirmed user data the outstation answers ACK or NACK.

use std::io::Write;
use std::net::TcpStream;

use transport::error::{Result, TransportError, classify, protocol_error};

use crate::link::{
    self, CONTROL_ACK, CONTROL_MASTER_CONFIRMED, CONTROL_MASTER_DATA, CONTROL_MASTER_RESET,
    CONTROL_NACK, CONTROL_NOT_SUPPORTED, FCB, Frame,
};

/// The master's side of one connection.
pub struct Master {
    stream: TcpStream,
    source: u16,
    destination: u16,
    sequence: u8,
    /// The frame count bit the next confirmed frame carries; `None` before
    /// the link states are reset.
    fcb: Option<bool>,
}

impl Master {
    /// A master at link address `source` speaking to `destination`.
    #[must_use]
    pub const fn new(stream: TcpStream, source: u16, destination: u16) -> Self {
        Self {
            stream,
            source,
            destination,
            sequence: 0,
            fcb: None,
        }
    }

    /// Send `fragment` as one or more frames, the last confirmed, and wait
    /// for the outstation to take it. The link states are reset first, once
    /// per connection, as confirmed user data requires.
    ///
    /// # Errors
    /// Where the outstation went away, answered NACK (retryable: it did not
    /// take the fragment, which is sent again), or answered something else.
    pub fn send_fragment(&mut self, fragment: &[u8]) -> Result<()> {
        if self.fcb.is_none() {
            self.write(CONTROL_MASTER_RESET, Vec::new())?;
            self.confirmed("the reset of link states")?;
            self.fcb = Some(true);
        }
        let segments = link::segments(fragment, self.sequence);
        self.sequence = link::next_sequence(self.sequence, segments.len());
        let last = segments.len() - 1;
        for (at, user_data) in segments.into_iter().enumerate() {
            if at < last {
                self.write(CONTROL_MASTER_DATA, user_data)?;
                continue;
            }
            let fcb = self.fcb.unwrap_or(true);
            let control = CONTROL_MASTER_CONFIRMED | if fcb { FCB } else { 0 };
            self.write(control, user_data)?;
            self.confirmed("the fragment")?;
            self.fcb = Some(!fcb);
        }
        Ok(())
    }

    fn write(&mut self, control: u8, user_data: Vec<u8>) -> Result<()> {
        let frame = Frame {
            control,
            destination: self.destination,
            source: self.source,
            user_data,
        };
        self.stream
            .write_all(&link::encode(&frame)?)
            .map_err(|e| classify("writing a frame", &e))?;
        self.stream
            .flush()
            .map_err(|e| classify("flushing the frames", &e))
    }

    /// Read the outstation's answer to `what`: ACK, or the failure NACK
    /// (retryable), `NOT_SUPPORTED` (permanent) or anything else is.
    fn confirmed(&mut self, what: &str) -> Result<()> {
        let answer = link::read(&mut self.stream)?
            .ok_or_else(|| protocol_error(format!("the outstation closed before {what}")))?;
        match answer.control {
            CONTROL_ACK => Ok(()),
            CONTROL_NACK => Err(TransportError::retryable(format!(
                "the outstation answered {what} NACK: not taken, send it again"
            ))),
            CONTROL_NOT_SUPPORTED => Err(TransportError::permanent(format!(
                "the outstation answered {what} NOT_SUPPORTED: refused, not to be sent again"
            ))),
            other => Err(protocol_error(format!(
                "the outstation answered {what} with control {other:#04x}"
            ))),
        }
    }
}
