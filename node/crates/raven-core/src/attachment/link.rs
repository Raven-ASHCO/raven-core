//! `RAX1`: the link frames that carry an attachment's chunks
//! (`docs/design/2026-11-attachments.md` §10.2).
//!
//! Raw frames on the authenticated link between two nodes, beside the
//! message envelopes and sorted by their magic like `RUP1`'s; never inside
//! an envelope and never through the IPC. A chunk is the sealed chunk of
//! the blob ([`super::blob`]) with its audit path: the receiver checks it
//! against the root its offer named before it writes a byte.
//!
//! ```text
//! frame  = "RAX1" || 0x01 || op || req_id[4] || body          (at most 65,511 B)
//!
//! 0x01 HAVE        dialer, answered by LACK     n u8 (1..=8), then n times: handle[16] || chunks u16
//! 0x02 WANT        dialer, answered by CHUNKs   handle[16] || first u16 || count u8 (1..=16)
//! 0x03 DONE        dialer, no answer            handle[16]
//! 0x04 PUSH        dialer, no answer            a chunk (below)
//! 0x81 CHUNK       answer to WANT, not final    a chunk (below)
//! 0x82 CHUNKS_END  answer to WANT, final        code u8 || sent u8
//! 0x83 LACK        answer to HAVE, final        n u8 (1..=8), then n times: handle[16] || status u8
//!                                               || chunks u16 || wanted[ceil(chunks / 8)]
//! 0xFF ERROR       answer, final                code u8
//!
//! chunk  = handle[16] || index u16 || length u32 (1..=61,440) || bytes
//!          || path_len u8 (0..=11) || path_len * hash[32]
//! ```
//!
//! Integers are big endian. In a LACK entry, `status` 0 means "send the
//! chunks whose bits are set" (bit `i % 8` of byte `i / 8`, the bits past
//! the last chunk zero, at least one bit set); for every other status
//! (1 complete, 2 later, 3 declined, 4 not known) `chunks` is 0 and no
//! bitmap follows. A listener never speaks first: the dialer sends, the
//! listener only answers.
//!
//! Decoding follows `RUP1`'s rules: a fixed order, every length checked
//! before a byte is copied, nothing after the last field, and an accepted
//! frame re-encodes byte for byte.

use thiserror::Error;

use super::blob::{CHUNK_LEN, HANDLE_LEN, MAX_CHUNKS, MAX_PATH_LEN};

/// The frame magic.
pub const RAX1_MAGIC: &[u8; 4] = b"RAX1";
/// The version byte.
pub const RAX1_VERSION: u8 = 0x01;
/// Magic, version, op and request id.
pub const HEADER_LEN: usize = 10;
/// The longest frame: PAD1's inner limit, as for `RUP1`.
pub const MAX_FRAME_LEN: usize = 65_511;
/// The most entries of a HAVE or a LACK.
pub const MAX_ENTRIES: usize = 8;
/// The most chunks one WANT asks for.
pub const MAX_WANT: u8 = 16;

const OP_HAVE: u8 = 0x01;
const OP_WANT: u8 = 0x02;
const OP_DONE: u8 = 0x03;
const OP_PUSH: u8 = 0x04;
const OP_CHUNK: u8 = 0x81;
const OP_CHUNKS_END: u8 = 0x82;
const OP_LACK: u8 = 0x83;
const OP_ERROR: u8 = 0xFF;

const _: () =
    assert!(HEADER_LEN + HANDLE_LEN + 2 + 4 + CHUNK_LEN + 1 + MAX_PATH_LEN * 32 <= MAX_FRAME_LEN);

/// A handle on a link.
pub type Handle = [u8; HANDLE_LEN];

/// Why a frame is refused.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Rax1Error {
    /// Not a `RAX1` frame of version 1, or longer than a frame may be.
    #[error("RAX1 NOT_A_FRAME")]
    NotAFrame,
    /// An op this side never takes (an answer sent to a listener, a
    /// request sent to a dialer, or an op of tomorrow).
    #[error("RAX1 OP")]
    Op,
    /// The body ends inside a field.
    #[error("RAX1 TRUNCATED")]
    Truncated,
    /// Bytes after the last field.
    #[error("RAX1 TRAILING")]
    Trailing,
    /// A count, a length, a status or a bitmap out of its range.
    #[error("RAX1 FIELD")]
    Field,
}

/// What a LACK says about one attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lack {
    /// Send the chunks whose bits are set (of `chunks` in all).
    Wants {
        /// How many chunks the attachment has.
        chunks: u16,
        /// One bit per chunk still wanted.
        wanted: Vec<u8>,
    },
    /// Every chunk is here: the attachment is delivered.
    Complete,
    /// Not now (a file that waits for the user's tap, a full store).
    Later,
    /// Never (the user declined it, the offer is not from a friend).
    Declined,
    /// No offer with this handle is here.
    NotKnown,
}

impl Lack {
    /// Wants exactly these chunks of `chunks`; `Complete` for none.
    pub fn wanting(chunks: u16, missing: &[u32]) -> Lack {
        if missing.is_empty() {
            return Lack::Complete;
        }
        let mut wanted = vec![0u8; usize::from(chunks).div_ceil(8)];
        for index in missing.iter().filter(|i| **i < u32::from(chunks)) {
            wanted[(*index / 8) as usize] |= 1 << (*index % 8);
        }
        Lack::Wants { chunks, wanted }
    }

    /// The chunk indices a `Wants` names, in order.
    pub fn wanted_indices(&self) -> Vec<u32> {
        match self {
            Lack::Wants { chunks, wanted } => (0..u32::from(*chunks))
                .filter(|i| wanted[(*i / 8) as usize] & (1 << (*i % 8)) != 0)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn status(&self) -> u8 {
        match self {
            Lack::Wants { .. } => 0,
            Lack::Complete => 1,
            Lack::Later => 2,
            Lack::Declined => 3,
            Lack::NotKnown => 4,
        }
    }
}

/// Why a request was not served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// This node does not take the op.
    Unsupported = 1,
    /// No such attachment, or not for this friend.
    NotFound = 2,
    /// Too much going on; later.
    Busy = 3,
    /// This friend asked for too much today.
    RateLimited = 4,
    /// Not from a friend this node serves.
    PolicyDenied = 5,
    /// The request did not read.
    Malformed = 6,
    /// The author deleted it.
    Gone = 7,
}

impl ErrorCode {
    fn from_byte(b: u8) -> Option<ErrorCode> {
        Some(match b {
            1 => ErrorCode::Unsupported,
            2 => ErrorCode::NotFound,
            3 => ErrorCode::Busy,
            4 => ErrorCode::RateLimited,
            5 => ErrorCode::PolicyDenied,
            6 => ErrorCode::Malformed,
            7 => ErrorCode::Gone,
            _ => return None,
        })
    }
}

/// One chunk as it travels, with its audit path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkBody {
    /// The attachment.
    pub handle: Handle,
    /// Which chunk.
    pub index: u16,
    /// The sealed chunk (1 to 61,440 bytes).
    pub bytes: Vec<u8>,
    /// Its audit path (at most 11 hashes).
    pub path: Vec<[u8; 32]>,
}

/// The body of a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// "I hold these attachments for you": handle and chunk count.
    Have(Vec<(Handle, u16)>),
    /// "Send me `count` chunks of this attachment from `first`."
    Want {
        /// The attachment.
        handle: Handle,
        /// The first chunk asked for.
        first: u16,
        /// How many (1 to 16).
        count: u8,
    },
    /// "I have all of it."
    Done(Handle),
    /// A chunk nobody asked for by name (the sender's node pushes it).
    Push(ChunkBody),
    /// A chunk a WANT asked for.
    Chunk(ChunkBody),
    /// The end of a WANT's answer: `code` 0, or an [`ErrorCode`]; `sent`
    /// CHUNK frames came before it.
    ChunksEnd {
        /// 0 when every chunk asked for and held was sent.
        code: u8,
        /// How many CHUNK frames came.
        sent: u8,
    },
    /// The answer to a HAVE, entry for entry.
    Lack(Vec<(Handle, Lack)>),
    /// A request that was not served.
    Error(ErrorCode),
}

/// A `RAX1` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Ties an answer to its request.
    pub req: [u8; 4],
    /// What it says.
    pub body: Body,
}

/// Does `frame` carry the `RAX1` magic?
pub fn is_rax1(frame: &[u8]) -> bool {
    frame.len() >= 4 && &frame[..4] == RAX1_MAGIC
}

impl Frame {
    /// The frame as it travels.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        out.extend_from_slice(RAX1_MAGIC);
        out.push(RAX1_VERSION);
        out.push(match &self.body {
            Body::Have(_) => OP_HAVE,
            Body::Want { .. } => OP_WANT,
            Body::Done(_) => OP_DONE,
            Body::Push(_) => OP_PUSH,
            Body::Chunk(_) => OP_CHUNK,
            Body::ChunksEnd { .. } => OP_CHUNKS_END,
            Body::Lack(_) => OP_LACK,
            Body::Error(_) => OP_ERROR,
        });
        out.extend_from_slice(&self.req);
        match &self.body {
            Body::Have(entries) => {
                out.push(entries.len() as u8);
                for (handle, chunks) in entries {
                    out.extend_from_slice(handle);
                    out.extend_from_slice(&chunks.to_be_bytes());
                }
            }
            Body::Want {
                handle,
                first,
                count,
            } => {
                out.extend_from_slice(handle);
                out.extend_from_slice(&first.to_be_bytes());
                out.push(*count);
            }
            Body::Done(handle) => out.extend_from_slice(handle),
            Body::Push(chunk) | Body::Chunk(chunk) => {
                out.extend_from_slice(&chunk.handle);
                out.extend_from_slice(&chunk.index.to_be_bytes());
                out.extend_from_slice(&(chunk.bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&chunk.bytes);
                out.push(chunk.path.len() as u8);
                for hash in &chunk.path {
                    out.extend_from_slice(hash);
                }
            }
            Body::ChunksEnd { code, sent } => {
                out.push(*code);
                out.push(*sent);
            }
            Body::Lack(entries) => {
                out.push(entries.len() as u8);
                for (handle, lack) in entries {
                    out.extend_from_slice(handle);
                    out.push(lack.status());
                    match lack {
                        Lack::Wants { chunks, wanted } => {
                            out.extend_from_slice(&chunks.to_be_bytes());
                            out.extend_from_slice(wanted);
                        }
                        _ => out.extend_from_slice(&0u16.to_be_bytes()),
                    }
                }
            }
            Body::Error(code) => out.push(*code as u8),
        }
        out
    }

    /// Does this frame's sender wait for an answer?
    pub fn expects_reply(&self) -> bool {
        matches!(self.body, Body::Have(_) | Body::Want { .. })
    }

    /// Is this the last frame of an answer?
    pub fn is_terminal_reply(&self) -> bool {
        matches!(
            self.body,
            Body::ChunksEnd { .. } | Body::Lack(_) | Body::Error(_)
        )
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Rax1Error> {
        if self.bytes.len() < n {
            return Err(Rax1Error::Truncated);
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Rax1Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Rax1Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, Rax1Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn handle(&mut self) -> Result<Handle, Rax1Error> {
        Ok(self.take(HANDLE_LEN)?.try_into().expect("a handle"))
    }

    fn chunk(&mut self) -> Result<ChunkBody, Rax1Error> {
        let handle = self.handle()?;
        let index = self.u16()?;
        let length = self.u32()? as usize;
        if length == 0 || length > CHUNK_LEN || u32::from(index) >= MAX_CHUNKS {
            return Err(Rax1Error::Field);
        }
        let bytes = self.take(length)?.to_vec();
        let hashes = usize::from(self.u8()?);
        if hashes > MAX_PATH_LEN {
            return Err(Rax1Error::Field);
        }
        let mut path = Vec::with_capacity(hashes);
        for _ in 0..hashes {
            path.push(self.take(32)?.try_into().expect("a hash"));
        }
        Ok(ChunkBody {
            handle,
            index,
            bytes,
            path,
        })
    }

    fn count(&mut self) -> Result<usize, Rax1Error> {
        let n = usize::from(self.u8()?);
        if n == 0 || n > MAX_ENTRIES {
            return Err(Rax1Error::Field);
        }
        Ok(n)
    }
}

fn chunks_ok(chunks: u16) -> bool {
    chunks >= 1 && u32::from(chunks) <= MAX_CHUNKS
}

/// Which ops a side takes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Listener,
    Dialer,
}

fn decode_as(frame: &[u8], side: Side) -> Result<Frame, Rax1Error> {
    if frame.len() < HEADER_LEN
        || frame.len() > MAX_FRAME_LEN
        || !is_rax1(frame)
        || frame[4] != RAX1_VERSION
    {
        return Err(Rax1Error::NotAFrame);
    }
    let op = frame[5];
    let req: [u8; 4] = frame[6..HEADER_LEN].try_into().expect("four bytes");
    let request = matches!(op, OP_HAVE | OP_WANT | OP_DONE | OP_PUSH);
    let answer = matches!(op, OP_CHUNK | OP_CHUNKS_END | OP_LACK | OP_ERROR);
    if !(request && side == Side::Listener || answer && side == Side::Dialer) {
        return Err(Rax1Error::Op);
    }
    let mut r = Reader {
        bytes: &frame[HEADER_LEN..],
    };
    let body = match op {
        OP_HAVE => {
            let n = r.count()?;
            let mut entries = Vec::with_capacity(n);
            for _ in 0..n {
                let handle = r.handle()?;
                let chunks = r.u16()?;
                if !chunks_ok(chunks) {
                    return Err(Rax1Error::Field);
                }
                entries.push((handle, chunks));
            }
            Body::Have(entries)
        }
        OP_WANT => {
            let handle = r.handle()?;
            let first = r.u16()?;
            let count = r.u8()?;
            if count == 0 || count > MAX_WANT || u32::from(first) + u32::from(count) > MAX_CHUNKS {
                return Err(Rax1Error::Field);
            }
            Body::Want {
                handle,
                first,
                count,
            }
        }
        OP_DONE => Body::Done(r.handle()?),
        OP_PUSH => Body::Push(r.chunk()?),
        OP_CHUNK => Body::Chunk(r.chunk()?),
        OP_CHUNKS_END => {
            let code = r.u8()?;
            let sent = r.u8()?;
            if (code != 0 && ErrorCode::from_byte(code).is_none()) || sent > MAX_WANT {
                return Err(Rax1Error::Field);
            }
            Body::ChunksEnd { code, sent }
        }
        OP_LACK => {
            let n = r.count()?;
            let mut entries = Vec::with_capacity(n);
            for _ in 0..n {
                let handle = r.handle()?;
                let status = r.u8()?;
                let chunks = r.u16()?;
                let lack = match status {
                    0 => {
                        if !chunks_ok(chunks) {
                            return Err(Rax1Error::Field);
                        }
                        let wanted = r.take(usize::from(chunks).div_ceil(8))?.to_vec();
                        let lack = Lack::Wants { chunks, wanted };
                        // At least one chunk wanted, and no bit past the last chunk.
                        let named = lack.wanted_indices();
                        if named.is_empty() || Lack::wanting(chunks, &named) != lack {
                            return Err(Rax1Error::Field);
                        }
                        lack
                    }
                    1..=4 if chunks == 0 => match status {
                        1 => Lack::Complete,
                        2 => Lack::Later,
                        3 => Lack::Declined,
                        _ => Lack::NotKnown,
                    },
                    _ => return Err(Rax1Error::Field),
                };
                entries.push((handle, lack));
            }
            Body::Lack(entries)
        }
        OP_ERROR => Body::Error(ErrorCode::from_byte(r.u8()?).ok_or(Rax1Error::Field)?),
        _ => return Err(Rax1Error::Op),
    };
    if !r.bytes.is_empty() {
        return Err(Rax1Error::Trailing);
    }
    Ok(Frame { req, body })
}

/// Reads a frame a dialer sent (HAVE, WANT, DONE or PUSH).
pub fn decode_for_listener(frame: &[u8]) -> Result<Frame, Rax1Error> {
    decode_as(frame, Side::Listener)
}

/// Reads a frame a listener answered with (CHUNK, CHUNKS_END, LACK or
/// ERROR).
pub fn decode_for_dialer(frame: &[u8]) -> Result<Frame, Rax1Error> {
    decode_as(frame, Side::Dialer)
}

/// The op of a frame with this protocol's header.
fn op_of(frame: &[u8]) -> Option<u8> {
    (frame.len() >= HEADER_LEN && is_rax1(frame) && frame[4] == RAX1_VERSION).then(|| frame[5])
}

/// Does this frame of a dial wait for an answer: a HAVE or a WANT? By its
/// header alone: a listener answers one that does not read with an ERROR.
pub fn frame_expects_reply(frame: &[u8]) -> bool {
    matches!(op_of(frame), Some(OP_HAVE | OP_WANT))
}

/// Is this a frame of a dial that nothing answers: a PUSH or a DONE?
pub fn frame_never_answered(frame: &[u8]) -> bool {
    matches!(op_of(frame), Some(OP_PUSH | OP_DONE))
}

/// Is this reply the last frame of an answer (a CHUNKS_END, a LACK or an
/// ERROR, by its header)? `false` for a CHUNK and for any other frame.
pub fn reply_is_terminal(frame: &[u8]) -> bool {
    matches!(op_of(frame), Some(OP_CHUNKS_END | OP_LACK | OP_ERROR))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: [u8; 4] = [1, 2, 3, 4];
    const H: Handle = [0xA5; HANDLE_LEN];

    fn chunk(len: usize, hashes: usize) -> ChunkBody {
        ChunkBody {
            handle: H,
            index: 7,
            bytes: (0..len).map(|i| i as u8).collect(),
            path: (0..hashes).map(|i| [i as u8; 32]).collect(),
        }
    }

    fn requests() -> Vec<Frame> {
        vec![
            Frame {
                req: REQ,
                body: Body::Have(vec![
                    (H, 18),
                    ([1; HANDLE_LEN], 1),
                    ([2; HANDLE_LEN], 1_059),
                ]),
            },
            Frame {
                req: REQ,
                body: Body::Want {
                    handle: H,
                    first: 16,
                    count: 2,
                },
            },
            Frame {
                req: REQ,
                body: Body::Done(H),
            },
            Frame {
                req: REQ,
                body: Body::Push(chunk(CHUNK_LEN, MAX_PATH_LEN)),
            },
            Frame {
                req: REQ,
                body: Body::Push(chunk(1, 0)),
            },
        ]
    }

    fn answers() -> Vec<Frame> {
        vec![
            Frame {
                req: REQ,
                body: Body::Chunk(chunk(CHUNK_LEN, 5)),
            },
            Frame {
                req: REQ,
                body: Body::ChunksEnd { code: 0, sent: 16 },
            },
            Frame {
                req: REQ,
                body: Body::ChunksEnd {
                    code: ErrorCode::Busy as u8,
                    sent: 3,
                },
            },
            Frame {
                req: REQ,
                body: Body::Lack(vec![
                    (H, Lack::wanting(18, &[0, 9, 17])),
                    ([1; HANDLE_LEN], Lack::Complete),
                    ([2; HANDLE_LEN], Lack::Later),
                    ([3; HANDLE_LEN], Lack::Declined),
                    ([4; HANDLE_LEN], Lack::NotKnown),
                ]),
            },
            Frame {
                req: REQ,
                body: Body::Error(ErrorCode::NotFound),
            },
        ]
    }

    #[test]
    fn every_frame_reads_back_and_re_encodes_byte_for_byte() {
        for frame in requests() {
            let bytes = frame.encode();
            assert!(is_rax1(&bytes) && bytes.len() <= MAX_FRAME_LEN);
            assert_eq!(decode_for_listener(&bytes), Ok(frame.clone()), "{frame:?}");
            assert_eq!(decode_for_listener(&bytes).unwrap().encode(), bytes);
            // A dialer never takes a request.
            assert_eq!(decode_for_dialer(&bytes), Err(Rax1Error::Op));
        }
        for frame in answers() {
            let bytes = frame.encode();
            assert_eq!(decode_for_dialer(&bytes), Ok(frame.clone()), "{frame:?}");
            assert_eq!(decode_for_dialer(&bytes).unwrap().encode(), bytes);
            // A listener never takes an answer: it never has to speak first.
            assert_eq!(decode_for_listener(&bytes), Err(Rax1Error::Op));
        }
    }

    #[test]
    fn the_largest_chunk_frame_fits_a_link_frame() {
        let bytes = Frame {
            req: REQ,
            body: Body::Push(chunk(CHUNK_LEN, MAX_PATH_LEN)),
        }
        .encode();
        assert_eq!(bytes.len(), 61_825);
        assert!(bytes.len() <= MAX_FRAME_LEN);
    }

    #[test]
    fn who_waits_for_an_answer_and_which_answer_is_the_last() {
        let waits: Vec<bool> = requests()
            .iter()
            .map(|f| frame_expects_reply(&f.encode()))
            .collect();
        assert_eq!(
            waits,
            [true, true, false, false, false],
            "HAVE and WANT wait, DONE and PUSH do not"
        );
        let last: Vec<bool> = answers()
            .iter()
            .map(|f| reply_is_terminal(&f.encode()))
            .collect();
        assert_eq!(
            last,
            [false, true, true, true, true],
            "a CHUNK is never the last"
        );
        let unanswered: Vec<bool> = requests()
            .iter()
            .map(|f| frame_never_answered(&f.encode()))
            .collect();
        assert_eq!(unanswered, [false, false, true, true, true]);
        assert!(answers().iter().all(|f| !frame_never_answered(&f.encode())));
        assert!(!frame_expects_reply(b"RUP1 something else"));
        assert!(!frame_never_answered(b"RUP1\x01\x04aaaa"));
        assert!(!reply_is_terminal(b""));
        assert!(!reply_is_terminal(b"RAX1\x02\x83aaaa"), "another version");
    }

    #[test]
    fn a_lack_names_exactly_the_chunks_still_wanted() {
        let lack = Lack::wanting(18, &[0, 9, 17]);
        assert_eq!(lack.wanted_indices(), vec![0, 9, 17]);
        assert_eq!(
            lack,
            Lack::Wants {
                chunks: 18,
                wanted: vec![0b0000_0001, 0b0000_0010, 0b0000_0010]
            }
        );
        assert_eq!(Lack::wanting(18, &[]), Lack::Complete);
        // An index past the last chunk is not named.
        assert_eq!(
            Lack::wanting(18, &[18, 99]).wanted_indices(),
            Vec::<u32>::new()
        );
        assert!(Lack::Complete.wanted_indices().is_empty());
    }

    #[test]
    fn frames_that_are_cut_longer_or_out_of_range_are_refused() {
        for frame in requests() {
            let bytes = frame.encode();
            assert_eq!(
                decode_for_listener(&bytes[..bytes.len() - 1]),
                Err(Rax1Error::Truncated),
                "{frame:?}"
            );
            let mut longer = bytes.clone();
            longer.push(0);
            assert!(
                matches!(
                    decode_for_listener(&longer),
                    Err(Rax1Error::Trailing | Rax1Error::Truncated | Rax1Error::Field)
                ),
                "{frame:?}"
            );
        }
        let read = |body: Body| decode_for_listener(&Frame { req: REQ, body }.encode());
        // No entries, too many entries, an attachment of no chunks or too many.
        assert_eq!(read(Body::Have(vec![])), Err(Rax1Error::Field));
        assert_eq!(read(Body::Have(vec![(H, 1); 9])), Err(Rax1Error::Field));
        assert_eq!(read(Body::Have(vec![(H, 0)])), Err(Rax1Error::Field));
        assert_eq!(read(Body::Have(vec![(H, 1_060)])), Err(Rax1Error::Field));
        // A WANT of nothing, of too much, past the largest attachment.
        let want = |first, count| {
            read(Body::Want {
                handle: H,
                first,
                count,
            })
        };
        assert_eq!(want(0, 0), Err(Rax1Error::Field));
        assert_eq!(want(0, 17), Err(Rax1Error::Field));
        assert_eq!(want(1_058, 2), Err(Rax1Error::Field));
        assert!(want(1_058, 1).is_ok());
        // A chunk of no bytes, of too many, with too long a path.
        assert_eq!(read(Body::Push(chunk(0, 0))), Err(Rax1Error::Field));
        assert_eq!(
            read(Body::Push(chunk(CHUNK_LEN + 1, 0))),
            Err(Rax1Error::Field)
        );
        assert_eq!(
            read(Body::Push(chunk(10, MAX_PATH_LEN + 1))),
            Err(Rax1Error::Field)
        );
        // Answers: an unknown code, a LACK with a bit past the last chunk,
        // one that wants nothing, a status with a count it may not have.
        let answer = |body: Body| decode_for_dialer(&Frame { req: REQ, body }.encode());
        assert_eq!(
            answer(Body::ChunksEnd { code: 99, sent: 0 }),
            Err(Rax1Error::Field)
        );
        assert_eq!(
            answer(Body::ChunksEnd { code: 0, sent: 17 }),
            Err(Rax1Error::Field)
        );
        let wants =
            |chunks, wanted: Vec<u8>| answer(Body::Lack(vec![(H, Lack::Wants { chunks, wanted })]));
        assert_eq!(
            wants(18, vec![1, 0, 0b0000_0100]),
            Err(Rax1Error::Field),
            "bit 18 of 18 chunks"
        );
        assert_eq!(wants(18, vec![0, 0, 0]), Err(Rax1Error::Field));
        assert_eq!(wants(18, vec![1, 0]), Err(Rax1Error::Truncated));
        assert!(wants(18, vec![1, 0, 0]).is_ok());
        let mut bytes = Frame {
            req: REQ,
            body: Body::Lack(vec![(H, Lack::Complete)]),
        }
        .encode();
        let at = bytes.len() - 1;
        bytes[at] = 1; // complete, but with a chunk count
        assert_eq!(decode_for_dialer(&bytes), Err(Rax1Error::Field));
        let mut bytes = Frame {
            req: REQ,
            body: Body::Error(ErrorCode::Gone),
        }
        .encode();
        let at = bytes.len() - 1;
        bytes[at] = 0;
        assert_eq!(decode_for_dialer(&bytes), Err(Rax1Error::Field));
        // Not this protocol, another version, an op of tomorrow, too long.
        assert_eq!(
            decode_for_listener(b"RUP1\x01\x01aaaa"),
            Err(Rax1Error::NotAFrame)
        );
        assert_eq!(
            decode_for_listener(b"RAX1\x02\x03aaaa0123456789abcdef"),
            Err(Rax1Error::NotAFrame)
        );
        assert_eq!(decode_for_listener(b"RAX1\x01\x05aaaa"), Err(Rax1Error::Op));
        assert_eq!(decode_for_listener(b"RAX1"), Err(Rax1Error::NotAFrame));
        let mut huge = Frame {
            req: REQ,
            body: Body::Done(H),
        }
        .encode();
        huge.resize(MAX_FRAME_LEN + 1, 0);
        assert_eq!(decode_for_listener(&huge), Err(Rax1Error::NotAFrame));
    }
}
