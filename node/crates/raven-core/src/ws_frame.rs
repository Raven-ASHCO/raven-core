//! The WebSocket frames of RWS1 (`protocol/RAVEN_WSS_TRANSPORT_V1.md` §5):
//! Raven's own binary-only subset of RFC 6455 (owner decision O4-1: no
//! WebSocket crate). Pure: no IO. raven-swarm's `wss::ws` does the HTTP
//! upgrade and drives these over the TLS stream of a relay connection.
//!
//! - [`parse_head`] reads a frame head and refuses, with the close code
//!   RWS1 §5 names, every head the subset does not take: RSV bits, an
//!   unknown opcode, a control frame without FIN or over 125 bytes, the
//!   wrong mask presence, a length not in its minimal form ([`WsClose::PROTOCOL`]),
//!   a frame over [`WS_MAX_MESSAGE`] ([`WsClose::TOO_BIG`]).
//! - [`encode`] / [`encode_head`] write a frame with the minimal length
//!   form; [`apply_mask`] masks and unmasks.
//! - [`Reassembly`] joins a message's frames: binary, then continuations.
//!   A text message is refused ([`WsClose::UNSUPPORTED_DATA`]), and so is a
//!   message over [`WS_MAX_MESSAGE`].
//! - [`accept_token`] is the `Sec-WebSocket-Accept` value; the caller brings
//!   SHA-1 (raven-swarm uses ring's legacy SHA-1), so raven-core has none.
//!
//! Nothing here dials or listens; that sits behind [`crate::wss_gate`].
//! Vectors: `shared-vectors/rvn1/wss/rws1_ws_frames_001.json` and
//! `rws1_ws_handshake_001.json` (`protocol/reference/generate_wss.py`).

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Largest message, and so largest frame, in bytes (RWS1 §5). More closes
/// with [`WsClose::TOO_BIG`].
pub const WS_MAX_MESSAGE: usize = 262_144;
/// Largest HTTP head of the upgrade, through its blank line, both ways.
pub const WS_MAX_HEADER_BLOCK: usize = 8192;
/// Most header lines in an HTTP head of the upgrade, both ways.
pub const WS_MAX_HEADERS: usize = 32;
/// Largest payload of a close, ping or pong frame (RFC 6455 §5.5).
pub const WS_MAX_CONTROL: usize = 125;
/// The GUID appended to the key before hashing (RFC 6455 §1.3).
pub const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Continuation of a fragmented message.
pub const OP_CONTINUATION: u8 = 0x0;
/// Text message: refused by the subset.
pub const OP_TEXT: u8 = 0x1;
/// Binary message: the only data Raven sends.
pub const OP_BINARY: u8 = 0x2;
/// Close.
pub const OP_CLOSE: u8 = 0x8;
/// Ping (answered with a pong carrying the same payload).
pub const OP_PING: u8 = 0x9;
/// Pong.
pub const OP_PONG: u8 = 0xA;

/// A close code (RFC 6455 §7.4): what a reader that refuses a frame sends
/// in its close frame before it gives up on the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsClose(pub u16);

impl WsClose {
    /// Normal closure.
    pub const NORMAL: Self = Self(1000);
    /// A frame or message the subset refuses (RSV bits, an unknown opcode,
    /// a bad control frame, the wrong mask presence, a length not in its
    /// minimal form, a continuation out of place).
    pub const PROTOCOL: Self = Self(1002);
    /// A text message (the subset is binary-only).
    pub const UNSUPPORTED_DATA: Self = Self(1003);
    /// A frame or message over [`WS_MAX_MESSAGE`].
    pub const TOO_BIG: Self = Self(1009);

    /// The status code.
    pub fn code(self) -> u16 {
        self.0
    }

    /// The payload of a close frame with this code.
    pub fn payload(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// A frame head [`parse_head`] accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// The last frame of its message (always set on a control frame).
    pub fin: bool,
    /// The opcode: one of the `OP_*` constants.
    pub op: u8,
    /// The masking key: present exactly on a client's frame.
    pub mask: Option<[u8; 4]>,
    /// The payload length, at most [`WS_MAX_MESSAGE`].
    pub len: u64,
    /// The head's own length (2 to 14 bytes); the payload follows it.
    pub hdr_len: usize,
}

impl Head {
    /// The whole frame's length: head and payload.
    pub fn frame_len(&self) -> usize {
        // len <= WS_MAX_MESSAGE, checked by parse_head.
        self.hdr_len + self.len as usize
    }
}

/// Reads the head of the frame at the start of `b`. `Ok(None)`: more bytes
/// are needed (fewer than 2, or a head cut inside its extended length or
/// masking key). The checks run in this order, the first that fails
/// deciding the close code:
/// 1. RSV1-3 set: [`WsClose::PROTOCOL`] (no extension is ever agreed);
/// 2. an opcode other than 0, 1, 2, 8, 9 and 10: `PROTOCOL`;
/// 3. a control frame without FIN or with a length over 125: `PROTOCOL`;
/// 4. a mask bit that differs from `expect_masked` (a server reads masked
///    client frames, a client unmasked server frames): `PROTOCOL`;
/// 5. a 16-bit length under 126 or a 64-bit length under 65536 (RFC 6455
///    §5.2: the minimal form is a MUST): `PROTOCOL`;
/// 6. a length over [`WS_MAX_MESSAGE`]: [`WsClose::TOO_BIG`].
pub fn parse_head(b: &[u8], expect_masked: bool) -> Result<Option<Head>, WsClose> {
    let [b0, b1, ..] = *b else {
        return Ok(None);
    };
    if b0 & 0x70 != 0 {
        return Err(WsClose::PROTOCOL);
    }
    let fin = b0 & 0x80 != 0;
    let op = b0 & 0x0f;
    let short = b1 & 0x7f;
    match op {
        OP_CONTINUATION | OP_TEXT | OP_BINARY => {}
        OP_CLOSE | OP_PING | OP_PONG => {
            if !fin || usize::from(short) > WS_MAX_CONTROL {
                return Err(WsClose::PROTOCOL);
            }
        }
        _ => return Err(WsClose::PROTOCOL),
    }
    let masked = b1 & 0x80 != 0;
    if masked != expect_masked {
        return Err(WsClose::PROTOCOL);
    }
    let (len, mut at) = match short {
        126 => {
            let Some(&[x, y]) = b.get(2..4) else {
                return Ok(None);
            };
            let n = u16::from_be_bytes([x, y]);
            if n < 126 {
                return Err(WsClose::PROTOCOL);
            }
            (u64::from(n), 4)
        }
        127 => {
            let Some(x) = b.get(2..10) else {
                return Ok(None);
            };
            let mut be = [0u8; 8];
            be.copy_from_slice(x);
            let n = u64::from_be_bytes(be);
            if n <= 0xffff {
                return Err(WsClose::PROTOCOL);
            }
            (n, 10)
        }
        n => (u64::from(n), 2),
    };
    if len > WS_MAX_MESSAGE as u64 {
        return Err(WsClose::TOO_BIG);
    }
    let mask = if masked {
        let Some(&[k0, k1, k2, k3]) = b.get(at..at + 4) else {
            return Ok(None);
        };
        at += 4;
        Some([k0, k1, k2, k3])
    } else {
        None
    };
    Ok(Some(Head {
        fin,
        op,
        mask,
        len,
        hdr_len: at,
    }))
}

/// Appends a frame head: FIN, the opcode, the length in its minimal form
/// (7, 16 or 64 bits) and the masking key, if any.
pub fn encode_head(fin: bool, op: u8, len: u64, mask: Option<[u8; 4]>, out: &mut Vec<u8>) {
    let first = if fin { 0x80 } else { 0 };
    out.push(first | (op & 0x0f));
    let m = if mask.is_some() { 0x80 } else { 0 };
    match len {
        0..=125 => out.push(m | len as u8),
        126..=0xffff => {
            out.push(m | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 127);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
    if let Some(key) = mask {
        out.extend_from_slice(&key);
    }
}

/// Appends one whole frame (FIN set): its head, then the payload, masked
/// with `mask` when there is one (a client's frame).
pub fn encode(op: u8, payload: &[u8], mask: Option<[u8; 4]>, out: &mut Vec<u8>) {
    encode_head(true, op, payload.len() as u64, mask, out);
    let start = out.len();
    out.extend_from_slice(payload);
    if let Some(key) = mask {
        apply_mask(&mut out[start..], key, 0);
    }
}

/// XORs `data` with the masking key, `offset` being the payload position
/// `data` starts at, so a payload can be (un)masked in pieces. Masking is
/// its own inverse.
pub fn apply_mask(data: &mut [u8], key: [u8; 4], offset: usize) {
    // The key as it lines up with data[0..4]; XOR a word at a time.
    let k = [0, 1, 2, 3].map(|i| key[(offset % 4 + i) % 4]);
    let word = u32::from_ne_bytes(k);
    let (words, rest) = data.as_chunks_mut::<4>();
    for w in words {
        *w = (u32::from_ne_bytes(*w) ^ word).to_ne_bytes();
    }
    for (b, m) in rest.iter_mut().zip(k) {
        *b ^= m;
    }
}

/// Joins the data frames of one message: a binary frame, then
/// continuations, the last with FIN. Control frames may come between them
/// and never pass through here.
#[derive(Debug, Default)]
pub struct Reassembly {
    buf: Vec<u8>,
    open: bool,
}

impl Reassembly {
    /// No message open.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a message has started and not ended.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Takes one data frame's (unmasked) payload. `Ok(Some(message))` when
    /// the frame ends a message, `Ok(None)` while it goes on. Refused, with
    /// its close code:
    /// - a continuation with no message open, a binary or text frame while
    ///   one is open, or a control opcode: [`WsClose::PROTOCOL`];
    /// - a text frame: [`WsClose::UNSUPPORTED_DATA`];
    /// - a message over [`WS_MAX_MESSAGE`]: [`WsClose::TOO_BIG`].
    pub fn push(&mut self, fin: bool, op: u8, payload: &[u8]) -> Result<Option<Vec<u8>>, WsClose> {
        match op {
            OP_CONTINUATION if !self.open => return Err(WsClose::PROTOCOL),
            OP_CONTINUATION => {}
            OP_TEXT | OP_BINARY if self.open => return Err(WsClose::PROTOCOL),
            OP_TEXT => return Err(WsClose::UNSUPPORTED_DATA),
            OP_BINARY => {}
            _ => return Err(WsClose::PROTOCOL),
        }
        if payload.len() > WS_MAX_MESSAGE - self.buf.len() {
            return Err(WsClose::TOO_BIG);
        }
        self.buf.extend_from_slice(payload);
        self.open = !fin;
        Ok(fin.then(|| std::mem::take(&mut self.buf)))
    }
}

/// The status code of a received close frame: `None` without a payload. A
/// 1-byte payload is [`WsClose::PROTOCOL`] (RFC 6455 §5.5.1). A reason
/// after the code is ignored.
pub fn close_code(payload: &[u8]) -> Result<Option<u16>, WsClose> {
    match *payload {
        [] => Ok(None),
        [_] => Err(WsClose::PROTOCOL),
        [a, b, ..] => Ok(Some(u16::from_be_bytes([a, b]))),
    }
}

/// `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key` (as sent: its base64
/// text): base64 of SHA-1(key || [`WS_GUID`]). `sha1` hashes the bytes it
/// is given.
pub fn accept_token(sha1: impl FnOnce(&[u8]) -> [u8; 20], key_b64: &str) -> String {
    let mut input = Vec::with_capacity(key_b64.len() + WS_GUID.len());
    input.extend_from_slice(key_b64.as_bytes());
    input.extend_from_slice(WS_GUID);
    STANDARD.encode(sha1(&input))
}

/// Whether a `Sec-WebSocket-Key` is padded base64 (RFC 4648) of exactly 16
/// bytes in its canonical form: nothing else, and no non-zero bits in its
/// last character.
pub fn valid_key(key_b64: &str) -> bool {
    STANDARD.decode(key_b64).is_ok_and(|k| k.len() == 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    fn vector(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared-vectors/rvn1/wss")
            .join(name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
        serde_json::from_str(&raw).unwrap()
    }

    fn hex_of(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    fn mask_of(v: &Value) -> [u8; 4] {
        hex_of(v).try_into().unwrap()
    }

    /// A vector frame's payload: its bytes, or byte i = i mod 251 of its
    /// length.
    fn payload_of(case: &Value) -> Vec<u8> {
        match case.get("payload_hex") {
            Some(h) => hex_of(h),
            None => (0..case["payload_len"].as_u64().unwrap())
                .map(|i| (i % 251) as u8)
                .collect(),
        }
    }

    fn sha256_hex(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    fn frame(op: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = Vec::new();
        encode(op, payload, mask, &mut out);
        out
    }

    /// Frames read in a row, as the vectors' sequences define it: data
    /// frames through [`Reassembly`], pings and pongs skipped, a close ends
    /// the reading. (messages, outcome, code).
    fn read_frames(mut b: &[u8], expect_masked: bool) -> (Vec<Vec<u8>>, &'static str, Option<u16>) {
        let mut messages = Vec::new();
        let mut msg = Reassembly::new();
        loop {
            let head = match parse_head(b, expect_masked) {
                Ok(Some(h)) => h,
                Ok(None) => return (messages, "end", None),
                Err(c) => return (messages, "fail", Some(c.code())),
            };
            let Some(body) = b.get(head.hdr_len..head.frame_len()) else {
                return (messages, "end", None);
            };
            let mut payload = body.to_vec();
            if let Some(key) = head.mask {
                apply_mask(&mut payload, key, 0);
            }
            b = &b[head.frame_len()..];
            match head.op {
                OP_CLOSE => {
                    return match close_code(&payload) {
                        Ok(code) => (messages, "close", code),
                        Err(c) => (messages, "fail", Some(c.code())),
                    }
                }
                OP_PING | OP_PONG => {}
                op => match msg.push(head.fin, op, &payload) {
                    Ok(Some(m)) => messages.push(m),
                    Ok(None) => {}
                    Err(c) => return (messages, "fail", Some(c.code())),
                },
            }
        }
    }

    /// `rws1_ws_frames_001.json` (the Python reference): binary frames both
    /// ways at lengths 0/5/125/126/65535/65536 with the mask 37fa213d (the
    /// heads, the whole frames up to 126 bytes, the SHA-256 of the large
    /// ones); close 1000/1002/1003/1009, ping and pong; the heads
    /// parse_head reads, those it needs more bytes for and those it refuses
    /// with their close codes; frame sequences through the reassembly.
    #[test]
    fn ws_frame_vectors_match() {
        let v = vector("rws1_ws_frames_001.json");
        let mask = mask_of(&v["inputs"]["mask_hex"]);
        assert_eq!(mask, [0x37, 0xfa, 0x21, 0x3d]);
        assert_eq!(v["inputs"]["max_message"], WS_MAX_MESSAGE as u64);
        assert_eq!(v["inputs"]["max_control"], WS_MAX_CONTROL as u64);
        let e = &v["expected"];
        let mut lengths = Vec::new();
        for case in e["data"].as_array().unwrap() {
            let payload = payload_of(case);
            assert_eq!(payload.len() as u64, case["payload_len"].as_u64().unwrap());
            lengths.push(payload.len());
            for (side, key) in [("client", Some(mask)), ("server", None)] {
                let f = frame(OP_BINARY, &payload, key);
                let head = hex_of(&case[format!("{side}_head_hex")]);
                assert_eq!(f[..head.len()], head[..], "{side} {}", payload.len());
                assert_eq!(f.len() as u64, case[format!("{side}_frame_len")]);
                assert_eq!(sha256_hex(&f), case[format!("{side}_frame_sha256")]);
                if let Some(whole) = case.get(format!("{side}_frame_hex")) {
                    assert_eq!(f, hex_of(whole));
                }
                let h = parse_head(&f, key.is_some()).unwrap().unwrap();
                let expect = Head {
                    fin: true,
                    op: OP_BINARY,
                    mask: key,
                    len: payload.len() as u64,
                    hdr_len: head.len(),
                };
                assert_eq!(h, expect);
                assert_eq!(h.frame_len(), f.len());
                // Unmasking the wire payload gives the payload back.
                let mut body = f[h.hdr_len..].to_vec();
                if let Some(k) = h.mask {
                    apply_mask(&mut body, k, 0);
                }
                assert_eq!(body, payload);
            }
        }
        assert_eq!(lengths, [0, 5, 125, 126, 65535, 65536]);
        assert_eq!(
            e["data"][1]["client_frame_hex"], "828537fa213d7f9f4d5158",
            "'Hello' masked (RWS1 §5)"
        );
        let mut codes = Vec::new();
        for case in e["control"].as_array().unwrap() {
            let op = case["op"].as_u64().unwrap() as u8;
            let payload = hex_of(&case["payload_hex"]);
            assert_eq!(
                frame(op, &payload, Some(mask)),
                hex_of(&case["client_frame_hex"])
            );
            assert_eq!(frame(op, &payload, None), hex_of(&case["server_frame_hex"]));
            if op == OP_CLOSE {
                let code = close_code(&payload).unwrap();
                assert_eq!(code.map(u64::from), case["close_code"].as_u64());
                codes.push(code);
            }
        }
        assert_eq!(
            codes,
            [Some(1000), Some(1002), Some(1003), Some(1009), None],
            "close 1000/1002/1003/1009 and a close without a code"
        );
        for case in e["heads"].as_array().unwrap() {
            let head = hex_of(&case["head_hex"]);
            let masked = case["expect_masked"].as_bool().unwrap();
            let want = Head {
                fin: case["fin"].as_bool().unwrap(),
                op: case["op"].as_u64().unwrap() as u8,
                mask: case["mask_hex"]
                    .as_str()
                    .map(|_| mask_of(&case["mask_hex"])),
                len: case["len"].as_u64().unwrap(),
                hdr_len: case["hdr_len"].as_u64().unwrap() as usize,
            };
            assert_eq!(parse_head(&head, masked), Ok(Some(want)), "{}", case["why"]);
            let mut again = Vec::new();
            encode_head(want.fin, want.op, want.len, want.mask, &mut again);
            assert_eq!(again, head);
            for cut in 0..head.len() {
                assert_eq!(parse_head(&head[..cut], masked), Ok(None), "{cut}");
            }
        }
        for case in e["incomplete"].as_array().unwrap() {
            let head = hex_of(&case["head_hex"]);
            let masked = case["expect_masked"].as_bool().unwrap();
            assert_eq!(parse_head(&head, masked), Ok(None), "{}", case["why"]);
        }
        let mut seen = std::collections::BTreeSet::new();
        for case in e["reject"].as_array().unwrap() {
            let head = hex_of(&case["head_hex"]);
            let masked = case["expect_masked"].as_bool().unwrap();
            let code = parse_head(&head, masked).unwrap_err();
            assert_eq!(u64::from(code.code()), case["close"], "{}", case["why"]);
            seen.insert(code.code());
        }
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), [1002, 1009]);
        let mut outcomes = std::collections::BTreeSet::new();
        for case in e["sequences"].as_array().unwrap() {
            let masked = case["expect_masked"].as_bool().unwrap();
            let mut wire = Vec::new();
            for f in case["frames"].as_array().unwrap() {
                let payload = payload_of(f);
                let key = masked.then_some(mask);
                let op = f["op"].as_u64().unwrap() as u8;
                encode_head(
                    f["fin"].as_bool().unwrap(),
                    op,
                    payload.len() as u64,
                    key,
                    &mut wire,
                );
                let start = wire.len();
                wire.extend_from_slice(&payload);
                if let Some(k) = key {
                    apply_mask(&mut wire[start..], k, 0);
                }
            }
            let (messages, outcome, code) = read_frames(&wire, masked);
            let want = case["messages"].as_array().unwrap();
            assert_eq!(messages.len(), want.len(), "{}", case["why"]);
            for (m, w) in messages.iter().zip(want) {
                assert_eq!(m.len() as u64, w["len"], "{}", case["why"]);
                assert_eq!(sha256_hex(m), w["sha256"], "{}", case["why"]);
                if let Some(h) = w.get("hex") {
                    assert_eq!(*m, hex_of(h));
                }
            }
            assert_eq!(outcome, case["outcome"], "{}", case["why"]);
            assert_eq!(
                code.map(u64::from),
                case["code"].as_u64(),
                "{}",
                case["why"]
            );
            outcomes.insert((outcome, code));
        }
        for want in [
            ("end", None),
            ("close", Some(1000)),
            ("close", None),
            ("fail", Some(1002)),
            ("fail", Some(1003)),
            ("fail", Some(1009)),
        ] {
            assert!(outcomes.contains(&want), "no sequence ends {want:?}");
        }
    }

    /// RWS1 §5 refusals, one rule at a time: RSV bits, unknown opcodes,
    /// control frames over 125 bytes or fragmented, the wrong mask
    /// presence and lengths not in their minimal form close with 1002, a
    /// frame over 262144 bytes with 1009, a text message with 1003 (in the
    /// reassembly: its head is read).
    #[test]
    fn parse_head_refuses_what_the_subset_does_not_take() {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let head = |fin: bool, op: u8, len: u64, mask: Option<[u8; 4]>| {
            let mut out = Vec::new();
            encode_head(fin, op, len, mask, &mut out);
            out
        };
        let good = head(true, OP_BINARY, 5, Some(key));
        assert!(parse_head(&good, true).unwrap().is_some());
        for rsv in [0x40, 0x20, 0x10] {
            let mut b = good.clone();
            b[0] |= rsv;
            assert_eq!(parse_head(&b, true), Err(WsClose::PROTOCOL), "rsv {rsv:#x}");
        }
        for op in [3, 4, 5, 6, 7, 0xb, 0xc, 0xd, 0xe, 0xf] {
            let b = head(true, op, 0, Some(key));
            assert_eq!(parse_head(&b, true), Err(WsClose::PROTOCOL), "opcode {op}");
        }
        for op in [OP_CLOSE, OP_PING, OP_PONG] {
            assert!(parse_head(&head(true, op, 125, None), false).is_ok());
            let long = head(true, op, 126, None);
            assert_eq!(
                parse_head(&long, false),
                Err(WsClose::PROTOCOL),
                "{op} > 125"
            );
            let cut = head(false, op, 0, None);
            assert_eq!(
                parse_head(&cut, false),
                Err(WsClose::PROTOCOL),
                "{op} not FIN"
            );
        }
        // Mask presence: a server reads masked frames, a client unmasked.
        assert_eq!(parse_head(&good, false), Err(WsClose::PROTOCOL));
        let plain = head(true, OP_BINARY, 5, None);
        assert_eq!(parse_head(&plain, true), Err(WsClose::PROTOCOL));
        // Lengths: only the minimal form.
        assert_eq!(
            parse_head(&[0x82, 0x7e, 0x00, 0x7d], false),
            Err(WsClose::PROTOCOL)
        );
        let mut long64 = vec![0x82, 0x7f];
        long64.extend_from_slice(&0xffffu64.to_be_bytes());
        assert_eq!(parse_head(&long64, false), Err(WsClose::PROTOCOL));
        // Size: 262144 is the largest frame.
        let max = head(true, OP_BINARY, WS_MAX_MESSAGE as u64, None);
        assert_eq!(parse_head(&max, false).unwrap().unwrap().hdr_len, 10);
        for len in [WS_MAX_MESSAGE as u64 + 1, 1 << 63, u64::MAX] {
            let mut b = vec![0x82, 0xff];
            b.extend_from_slice(&len.to_be_bytes());
            assert_eq!(parse_head(&b, true), Err(WsClose::TOO_BIG), "{len}");
        }
        // A text frame's head is read; its message is refused.
        let text = head(true, OP_TEXT, 5, Some(key));
        let h = parse_head(&text, true).unwrap().unwrap();
        assert_eq!(h.op, OP_TEXT);
        assert_eq!(
            Reassembly::new().push(h.fin, h.op, b"Hello"),
            Err(WsClose::UNSUPPORTED_DATA)
        );
    }

    /// The reassembly: binary then continuations with control frames in
    /// between handled elsewhere; the limit counts the whole message;
    /// out-of-place frames close with 1002.
    #[test]
    fn reassembly_joins_binary_messages_only() {
        let mut r = Reassembly::new();
        assert_eq!(r.push(true, OP_BINARY, b"one"), Ok(Some(b"one".to_vec())));
        assert!(!r.is_open());
        assert_eq!(r.push(false, OP_BINARY, b"tw"), Ok(None));
        assert!(r.is_open());
        assert_eq!(r.push(false, OP_CONTINUATION, b""), Ok(None));
        assert_eq!(
            r.push(true, OP_CONTINUATION, b"o"),
            Ok(Some(b"two".to_vec()))
        );
        assert_eq!(r.push(true, OP_BINARY, b""), Ok(Some(Vec::new())));
        // Exactly the limit, then one byte over.
        let half = vec![7u8; WS_MAX_MESSAGE / 2];
        assert_eq!(r.push(false, OP_BINARY, &half), Ok(None));
        let whole = r.push(true, OP_CONTINUATION, &half).unwrap().unwrap();
        assert_eq!(whole.len(), WS_MAX_MESSAGE);
        let mut r = Reassembly::new();
        assert_eq!(r.push(false, OP_BINARY, &whole), Ok(None));
        assert_eq!(r.push(true, OP_CONTINUATION, b"x"), Err(WsClose::TOO_BIG));
        for (open, op, code) in [
            (false, OP_CONTINUATION, WsClose::PROTOCOL),
            (true, OP_BINARY, WsClose::PROTOCOL),
            (true, OP_TEXT, WsClose::PROTOCOL),
            (false, OP_TEXT, WsClose::UNSUPPORTED_DATA),
            (false, OP_PING, WsClose::PROTOCOL),
            (false, 3, WsClose::PROTOCOL),
        ] {
            let mut r = Reassembly::new();
            if open {
                r.push(false, OP_BINARY, b"a").unwrap();
            }
            assert_eq!(r.push(true, op, b"b"), Err(code), "open {open} op {op}");
        }
        assert_eq!(close_code(&[]), Ok(None));
        assert_eq!(close_code(&[3]), Err(WsClose::PROTOCOL));
        assert_eq!(close_code(&[3, 0xe8, b'o', b'k']), Ok(Some(1000)));
        assert_eq!(WsClose::TOO_BIG.payload(), [0x03, 0xf1]);
    }

    /// Masking in pieces at their payload offsets equals masking the
    /// whole; masking twice gives the data back.
    #[test]
    fn apply_mask_continues_at_an_offset() {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let data: Vec<u8> = (0..=40u8).collect();
        let mut whole = data.clone();
        apply_mask(&mut whole, key, 0);
        assert_eq!(whole[..5], [0x37, 0xfb, 0x23, 0x3e, 0x33]);
        for split in 0..data.len() {
            let mut pieces = data.clone();
            let (a, b) = pieces.split_at_mut(split);
            apply_mask(a, key, 0);
            apply_mask(b, key, split);
            assert_eq!(pieces, whole, "split at {split}");
        }
        apply_mask(&mut whole, key, 0);
        assert_eq!(whole, data);
        let mut hello = b"Hello".to_vec();
        apply_mask(&mut hello, key, usize::MAX - 3);
        let mut again = b"Hello".to_vec();
        apply_mask(&mut again, key, 0);
        assert_eq!(hello, again, "offset usize::MAX - 3 is a multiple of 4");
    }

    /// `accept_token` hashes the key text followed by the GUID and
    /// base64-encodes the digest it gets: with the digest of the
    /// handshake vector it gives the RFC 6455 accept value (the real
    /// SHA-1 is checked in raven-swarm, which has one).
    #[test]
    fn accept_token_joins_the_key_and_the_guid() {
        let v = vector("rws1_ws_handshake_001.json");
        let key = v["inputs"]["key"].as_str().unwrap();
        assert_eq!(key, "dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(v["inputs"]["guid"].as_str().unwrap().as_bytes(), WS_GUID);
        assert_eq!(v["inputs"]["max_header_block"], WS_MAX_HEADER_BLOCK as u64);
        assert_eq!(v["inputs"]["max_headers"], WS_MAX_HEADERS as u64);
        let digest: [u8; 20] = hex_of(&v["expected"]["sha1_hex"]).try_into().unwrap();
        let token = accept_token(
            |input| {
                assert_eq!(
                    input,
                    b"dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                );
                digest
            },
            key,
        );
        assert_eq!(token, v["expected"]["accept"]);
        assert_eq!(token, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    /// Keys: padded base64 of exactly 16 bytes, canonical.
    #[test]
    fn valid_key_is_canonical_base64_of_16_bytes() {
        assert!(valid_key("dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(valid_key("AQIDBAUGBwgJCgsMDQ4PEA=="));
        for bad in [
            "",
            "dGhlIHNhbXBsZSBub25jZQ",
            "dGhlIHNhbXBsZSBub25jZR==",
            "dGhlIHNhbXBsZSBub25jZQ==\n",
            " dGhlIHNhbXBsZSBub25jZQ==",
            "dGhlIHNhbXBsZSBub25j ZQ==",
            "AQIDBAUGBwgJCgsMDQ4P",
            "AQIDBAUGBwgJCgsMDQ4PEBE=",
            "dGhlIHNhbXBsZSBub25jZQ=\u{e9}",
        ] {
            assert!(!valid_key(bad), "{bad:?}");
        }
    }
}
