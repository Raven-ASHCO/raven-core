//! The line protocol between raven-node's macOS radio (`nearby/apple.rs`)
//! and `raven-nearby-helper` (P5.31; Nearby design step 5.10): one JSON
//! object per line each way, UUIDs as 32 hex digits in RNL1 byte order
//! (§2), frames in standard base64, lines of at most [`MAX_LINE`] bytes.
//! Internal: the two ship together and nothing else speaks it, so it is not
//! frozen. The helper's first line, `hello`, names [`VERSION`]; raven-node
//! refuses any other.
//!
//! - **To the helper:** `services` (the GATT services to publish, each with
//!   its characteristic, and the one to advertise), `scan`, `connect`
//!   (raven-node's own odd connection number, a device the helper reported
//!   in `seen`, the service and its characteristic), `send` (one frame) and
//!   `disconnect`. raven-node derives every UUID (RNL1 §2): the helper
//!   computes nothing and holds no key. End of input stops the helper: it stops advertising
//!   and scanning, drops its connections and services, and exits.
//! - **From the helper:** `hello`, then `state`, `seen`, `connected` (the
//!   helper numbers the connections centrals open to it with even numbers),
//!   `frame`, `sent` (one frame of that connection went to CoreBluetooth,
//!   or was dropped: the credit of raven-node's send window) and
//!   `disconnected` (every connection that ends gets one, also one
//!   raven-node ended).
//!
//! A helper that cannot run says why instead of `hello` (`state`
//! `unauthorized` when its bundle has no Bluetooth usage description) and
//! exits.
//!
//! This file is also compiled into raven-nearby-helper (`#[path]`), so it
//! uses only std, serde, serde_json, base64 and hex.

use std::io::{self, BufRead, Read};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// The protocol version in `hello`.
pub(crate) const VERSION: u32 = 1;
/// The longest line either side reads; a longer one is skipped whole.
pub(crate) const MAX_LINE: usize = 8 * 1024;
/// Services one `services` line may name.
pub(crate) const MAX_SERVICES: usize = 32;
/// Service UUIDs one `seen` line may carry.
pub(crate) const MAX_UUIDS: usize = 8;
/// The longest device handle (the helper's are 32 hex digits).
pub(crate) const MAX_DEV: usize = 64;
/// The largest frame (RNL1 §4: `min(ATT_MTU - 3, 512)`).
pub(crate) const MAX_FRAME: usize = 512;
/// The smallest `max_tx` a link reports (ATT's default MTU, 23, less 3).
pub(crate) const MIN_TX: usize = 20;
/// Connection numbers on the wire are below this.
pub(crate) const CONN_LIMIT: u64 = 1 << 32;

/// A GATT service `T` and its one characteristic `C(T)` (RNL1 §4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Gatt {
    pub(crate) service: String,
    pub(crate) characteristic: String,
}

/// A line to the helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub(crate) enum ToHelper {
    /// Publish exactly `services` and advertise exactly `advertise` (one of
    /// their services, or nothing).
    Services {
        services: Vec<Gatt>,
        #[serde(default)]
        advertise: Option<String>,
    },
    Scan {
        on: bool,
    },
    /// Connect to `dev` and subscribe to `characteristic` of `service`.
    Connect {
        conn: u64,
        dev: String,
        service: String,
        characteristic: String,
    },
    Send {
        conn: u64,
        b64: String,
    },
    Disconnect {
        conn: u64,
    },
}

/// The radio's power, as the helper reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Power {
    On,
    Off,
    Unauthorized,
    Unsupported,
}

/// This side's role on a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Side {
    Central,
    Peripheral,
}

/// A line from the helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub(crate) enum FromHelper {
    Hello {
        v: u32,
    },
    State {
        state: Power,
        #[serde(default)]
        detail: String,
    },
    /// An advert with candidate tokens (never a Bluetooth SIG UUID) from
    /// `dev`, the helper's handle for that device.
    Seen {
        dev: String,
        uuids: Vec<String>,
        rssi: i16,
    },
    Connected {
        conn: u64,
        role: Side,
        service: String,
        max_tx: usize,
        max_rx: usize,
    },
    Frame {
        conn: u64,
        b64: String,
    },
    Sent {
        conn: u64,
    },
    Disconnected {
        conn: u64,
    },
}

/// A UUID on the wire.
pub(crate) fn uuid_hex(u: &[u8; 16]) -> String {
    hex::encode(u)
}

/// The UUID a wire string names: exactly 32 hex digits.
pub(crate) fn uuid_from(s: &str) -> Option<[u8; 16]> {
    let mut u = [0u8; 16];
    hex::decode_to_slice(s, &mut u).ok()?;
    Some(u)
}

/// A frame on the wire.
pub(crate) fn b64_of(frame: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(frame)
}

/// The frame a wire string carries: 1 to [`MAX_FRAME`] bytes.
pub(crate) fn frame_from(s: &str) -> Option<Vec<u8>> {
    if s.len() > MAX_FRAME.div_ceil(3) * 4 {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()
        .filter(|f| (1..=MAX_FRAME).contains(&f.len()))
}

/// One line, newline included.
pub(crate) fn line<T: Serialize>(m: &T) -> String {
    let mut s = serde_json::to_string(m).unwrap_or_default();
    s.push('\n');
    s
}

/// The message a line holds, if it parses.
pub(crate) fn parse<T: for<'de> Deserialize<'de>>(line: &[u8]) -> Option<T> {
    serde_json::from_slice(line).ok()
}

/// Read one line into `buf` (cleared first). False at the end of the
/// stream. A line over [`MAX_LINE`] is read to its end and left empty, so
/// it does not parse.
pub(crate) fn read_line<R: BufRead>(r: &mut R, buf: &mut Vec<u8>) -> io::Result<bool> {
    buf.clear();
    let n = r
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(false);
    }
    if buf.last() == Some(&b'\n') || n <= MAX_LINE {
        return Ok(true);
    }
    buf.clear();
    loop {
        let (found, used) = {
            let avail = r.fill_buf()?;
            if avail.is_empty() {
                return Ok(true);
            }
            match avail.iter().position(|&b| b == b'\n') {
                Some(i) => (true, i + 1),
                None => (false, avail.len()),
            }
        };
        r.consume(used);
        if found {
            return Ok(true);
        }
    }
}
