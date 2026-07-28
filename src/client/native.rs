//! Native `std` transport built on synchronous `tungstenite` (blocking WebSocket
//! over rustls). For host tools and the e2e tests; a `no_std` target would supply
//! its own [`crate::client::RelayConnection`] instead. Enabled by the
//! `native-transport` feature.

use std::io::ErrorKind;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::client::{RelayConnection, Transport};
use crate::error::{Error, Result};

/// Opens blocking WebSocket connections with `tungstenite`.
pub struct NativeTransport;

impl Transport for NativeTransport {
    type Conn = NativeConnection;

    fn connect(&self, url: &str) -> Result<NativeConnection> {
        let (ws, _resp) =
            tungstenite::connect(url).map_err(|e| Error::Decode(format!("ws connect: {e}")))?;
        Ok(NativeConnection { ws })
    }
}

/// A single blocking WebSocket connection.
pub struct NativeConnection {
    ws: WebSocket<MaybeTlsStream<TcpStream>>,
}

impl NativeConnection {
    /// Set the read timeout on the underlying TCP socket, propagating failures
    /// (e.g. `TcpStream` rejects a zero-duration timeout) so a "timed" read can
    /// never silently fall back to a stale or unbounded timeout.
    fn set_read_timeout(&mut self, dur: Duration) -> Result<()> {
        let res = match self.ws.get_mut() {
            MaybeTlsStream::Plain(s) => s.set_read_timeout(Some(dur)),
            MaybeTlsStream::Rustls(s) => s.sock.set_read_timeout(Some(dur)),
            _ => Ok(()),
        };
        res.map_err(|e| Error::Decode(format!("set_read_timeout: {e}")))
    }
}

impl RelayConnection for NativeConnection {
    fn send(&mut self, text: &str) -> Result<()> {
        // Map each tungstenite error eagerly to our small Error, so no closure
        // yields a Result carrying the large `tungstenite::Error` (clippy::result_large_err).
        self.ws
            .write(Message::Text(text.to_string()))
            .map_err(|e| Error::Decode(format!("ws send: {e}")))?;
        self.ws
            .flush()
            .map_err(|e| Error::Decode(format!("ws flush: {e}")))?;
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<String>> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // Budget exhausted (also the correct immediate return for a
                // zero-duration, non-blocking recv).
                return Ok(None);
            }
            self.set_read_timeout(remaining)?;
            match self.ws.read() {
                Ok(Message::Text(t)) => return Ok(Some(t)),
                // A control/ignored frame must NOT be reported as a timeout —
                // that would make publish() fail or truncate query(). Flush any
                // queued pong and keep reading within the remaining budget.
                Ok(Message::Ping(_)) => {
                    self.ws
                        .flush()
                        .map_err(|e| Error::Decode(format!("ws flush: {e}")))?;
                }
                Ok(Message::Close(_)) => return Err(Error::Malformed("relay closed connection")),
                Ok(_) => {} // Pong / Binary / raw Frame — ignore, keep reading
                Err(tungstenite::Error::Io(e))
                    if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(Error::Decode(format!("ws read: {e}"))),
            }
        }
    }

    fn close(&mut self) {
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
    }
}
