//! Native `std` transport built on synchronous `tungstenite` (blocking WebSocket
//! over native-tls). For host tools and the e2e tests; NOT compiled for the
//! wasm capsule (which brings its own rustls+tungstenite transport over Astrid
//! `net`). Enabled by the `native-transport` feature.

use std::io::ErrorKind;
use std::net::TcpStream;
use std::time::Duration;

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
    fn set_read_timeout(&mut self, dur: Option<Duration>) {
        match self.ws.get_mut() {
            MaybeTlsStream::Plain(s) => {
                let _ = s.set_read_timeout(dur);
            }
            MaybeTlsStream::Rustls(s) => {
                let _ = s.sock.set_read_timeout(dur);
            }
            _ => {}
        }
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
        self.set_read_timeout(Some(timeout));
        match self.ws.read() {
            Ok(Message::Text(t)) => Ok(Some(t)),
            Ok(Message::Ping(_)) => {
                // tungstenite queues the Pong; flush it and report no message.
                let _ = self.ws.flush();
                Ok(None)
            }
            Ok(Message::Close(_)) => Err(Error::Malformed("relay closed connection")),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                Ok(None)
            }
            Err(e) => Err(Error::Decode(format!("ws read: {e}"))),
        }
    }

    fn close(&mut self) {
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
    }
}
