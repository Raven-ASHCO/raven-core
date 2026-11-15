//! The chunk exchange of one profile (`docs/design/2026-11-attachments.md`
//! §9, §10.3): what a node answers to the `RAX1` frames a friend's dial
//! brings (the listener), and what its own dials say and take (the
//! dialer). Blocking: it reads and writes the attachment store. No network
//! here: raven-node hands it the frames of a link and makes the dials it
//! plans.
//!
//! - **Push** (the sender's node dials). As soon as the offer is delivered
//!   (its ACK came: the friend's node has kept its row), one dial pushes
//!   every chunk and says HAVE; the friend's node answers with a LACK:
//!   complete, and the attachment is delivered. After a cut, or whenever
//!   this node does not know what the friend has, it says HAVE first; the
//!   LACK names the chunks still wanted, the next dial pushes those and
//!   says HAVE again, until the LACK says complete. An offer whose delivery
//!   this node did not see (it was noted by a process that ended) is asked
//!   for with HAVE after a few seconds; a friend that does not know the
//!   offer yet answers "not known" and is asked again soon.
//! - **Pull** (the receiver's node dials). When no chunk landed for a
//!   while it asks the holder with WANT, takes the chunks, and says DONE
//!   once it has them all. This is how a cut resumes when the sender's node
//!   cannot reach the receiver.
//! - **Checks.** A chunk is taken only for an offer a verified friend sent
//!   in a chat with this node, from that friend, and only when it proves
//!   its place under the offer's root; three bad chunks from one source end
//!   that source for that attachment. A node serves only an attachment it
//!   offered to the friend who asks. Once every chunk is here the blob must
//!   open under the offer's key, or the attachment is failed.
//! - **Limits (phase 1).** Attachments up to [`LIVE_MAX_LEN`]; photos and
//!   voice notes come by themselves, a file waits until the user asks; at
//!   most [`MAX_PUSH_PER_DIAL`] chunks pushed and [`MAX_PULL_PER_DIAL`]
//!   pulled per dial; [`SERVE_BYTES_PER_DAY`] served to one friend a day.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use super::blob::Shape;
use super::link::{self, Body, ChunkBody, ErrorCode, Frame, Handle, Lack};
use super::offer::Kind;
use super::store::{self, Row, State, Taken};

/// The largest attachment that travels as live chunks (phase 1).
pub const LIVE_MAX_LEN: u64 = 1_048_576;
/// Chunks one dial pushes at most.
pub const MAX_PUSH_PER_DIAL: usize = 40;
/// Chunks one dial asks for at most.
pub const MAX_PULL_PER_DIAL: usize = 16;
/// WANT requests one dial carries at most.
const MAX_WANTS_PER_DIAL: usize = 4;
/// Bad chunks from one source for one attachment before it is not asked,
/// and not listened to, for that attachment again.
pub const MAX_BAD_CHUNKS: u32 = 3;
/// Bytes of chunks served to one friend a day.
pub const SERVE_BYTES_PER_DAY: u64 = 256 * 1024 * 1024;
/// A friend's attachment is pulled when no chunk landed for this long.
pub const PULL_AFTER_MS: u64 = 15_000;
/// A send of an offer counts as under way for this long after it set out:
/// the link that just carried it takes the chunks along.
pub const GOING_FRESH_MS: u64 = 120_000;
/// An offer of mine whose delivery was not seen is asked for with HAVE
/// this long after its row was last written.
pub const STAGED_PROBE_AFTER_MS: u64 = 5_000;
/// Dials planned in one pass at most.
const MAX_PLANS_PER_PASS: usize = 4;
/// Pushes that moved nothing before the attachment waits a long time.
const MAX_STALLS: u32 = 5;
/// Dials that say DONE before it is left to the holder's next HAVE.
const MAX_DONE_TRIES: u32 = 6;
const DAY_MS: u64 = 86_400_000;
/// The first wait after a dial that failed; doubled each time.
const RETRY_MS: u64 = 2_000;
/// The longest wait between tries.
const RETRY_MAX_MS: u64 = 300_000;
/// The longest wait between questions about an offer whose delivery this
/// node did not see: the delivery itself wakes the push, so the question
/// is only a net under it and need not be asked often.
const STAGED_RETRY_MAX_MS: u64 = 6 * 3_600_000;
/// An offer still not delivered this long after its row was made is not
/// asked about any more: its message's own time to arrive has run out.
const STAGED_MAX_AGE_MS: u64 = 8 * DAY_MS;
/// The friend answered "later" (its store is full, a file waits for a tap).
const LATER_MS: u64 = 300_000;
/// The friend declined, or does not take the request at all.
const DECLINED_MS: u64 = DAY_MS;
/// The friend's node is busy or counted too much.
const BUSY_MS: u64 = 60_000;

/// Does this attachment come by itself: a photo or a voice note of at most
/// [`LIVE_MAX_LEN`]? A file waits until the user asks for it.
pub fn comes_by_itself(kind: Kind, shape: &Shape) -> bool {
    matches!(kind, Kind::Photo | Kind::Voice) && shape.len() <= LIVE_MAX_LEN
}

/// What the exchange needs of a row, kept between passes.
#[derive(Debug, Clone)]
struct Brief {
    peer: Option<[u8; 32]>,
    outgoing: bool,
    state: State,
    shape: Shape,
    kind: Kind,
    asked: bool,
    friend_has: u32,
    going_ms: u64,
    created_ms: u64,
    updated_ms: u64,
}

impl Brief {
    fn of(row: &Row) -> Option<Brief> {
        let stored = row.stored()?;
        Some(Brief {
            peer: row.peer_key(),
            outgoing: row.outgoing,
            state: row.state,
            shape: stored.shape?,
            kind: stored.kind(),
            asked: row.asked,
            friend_has: row.friend_has,
            going_ms: row.going_ms,
            created_ms: row.created_ms,
            updated_ms: row.updated_ms,
        })
    }

    /// May its chunks be taken now?
    fn takes_chunks(&self) -> bool {
        !self.outgoing
            && self.state == State::Incoming
            && self.shape.len() <= LIVE_MAX_LEN
            && (self.asked || comes_by_itself(self.kind, &self.shape))
    }
}

/// A wait before the next try, and how many tries in a row failed.
#[derive(Debug, Clone, Copy, Default)]
struct Park {
    until_ms: u64,
    fails: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct Served {
    day_start_ms: u64,
    bytes: u64,
}

/// What the exchange keeps in memory between frames and passes. Nothing in
/// it is needed after a restart: a new process asks again.
#[derive(Debug, Default)]
pub struct Memory {
    /// Each row as last read, with the time its file had then.
    rows: HashMap<Handle, (SystemTime, Option<Brief>)>,
    /// Mine: the chunks the friend's last LACK still wanted. None: ask first.
    wanted: HashMap<Handle, Vec<u32>>,
    /// Mine: its chunks were pushed whole once since this process started
    /// (in a dial of the task's, or on the link that carried its offer).
    /// One that never was, and whose offer is delivered, is pushed whole
    /// without asking first; after that the friend is asked what it lacks.
    tried: HashSet<Handle>,
    /// Pushes in a row that moved nothing.
    stalls: HashMap<Handle, u32>,
    /// Not tried before this.
    parked: HashMap<Handle, Park>,
    /// Bad chunks a source sent for an attachment.
    bad: HashMap<([u8; 32], Handle), u32>,
    /// A friend's attachment that is all here: DONE is still to be said to
    /// its holder.
    done_due: Vec<([u8; 32], Handle)>,
    /// Bytes served to each friend today.
    served: HashMap<[u8; 32], Served>,
}

/// What became of a chunk that came.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Landed {
    /// Not taken: not expected, already here, or bad.
    No,
    /// Written.
    Written,
    /// Written, the last one missing, and the attachment opened.
    Last,
}

impl Plan {
    /// How many bytes its frames are in all.
    pub fn bytes(&self) -> usize {
        self.frames.iter().map(Vec::len).sum()
    }
}

/// One dial the exchange wants made.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The friend to dial.
    pub peer: [u8; 32],
    /// The attachment it is about.
    pub handle: Handle,
    /// The frames to send, in order.
    pub frames: Vec<Vec<u8>>,
    what: What,
}

#[derive(Debug, Clone)]
enum What {
    /// HAVE, after `pushed` PUSH frames.
    Push { req: [u8; 4], pushed: usize },
    /// WANT requests.
    Pull { reqs: Vec<[u8; 4]> },
    /// DONE.
    Done,
}

/// What a pass found.
#[derive(Debug, Default)]
pub struct Planned {
    /// The dials to make now.
    pub plans: Vec<Plan>,
    /// Something waits for its time or for a friend: look again soon.
    pub waiting: bool,
    /// How many attachments wait, and for what (counts for a log line).
    pub waits: Waits,
}

/// What the attachments that are not dialled now wait for.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Waits {
    /// Mine: its offer's delivery.
    pub offer: usize,
    /// The time of its next try (after a failure, or an answer that said
    /// later), or a turn behind another dial to the same friend.
    pub turn: usize,
    /// A friend whose Raven has not said that it takes attachments.
    pub friend: usize,
    /// A friend's: the time its sender has to push it before it is asked
    /// for.
    pub push: usize,
}

/// One profile's side of the exchange.
pub struct Exchange<'a> {
    data_dir: &'a Path,
    memory: &'a Mutex<Memory>,
}

fn locked(m: &Mutex<Memory>) -> MutexGuard<'_, Memory> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn req() -> [u8; 4] {
    rand::random()
}

fn encode(req: [u8; 4], body: Body) -> Vec<u8> {
    Frame { req, body }.encode()
}

/// The answer to a frame of a dialer this node does not exchange chunks
/// with (not a verified friend, or attachments are off): a refusal for a
/// request that waits for an answer, nothing otherwise.
pub fn refuse(frame: &[u8]) -> Vec<Vec<u8>> {
    answer_error(frame, ErrorCode::PolicyDenied)
}

fn answer_error(frame: &[u8], code: ErrorCode) -> Vec<Vec<u8>> {
    // HAVE and WANT wait for an answer, whether or not their body reads.
    if frame.len() < link::HEADER_LEN || !link::is_rax1(frame) || !matches!(frame[5], 0x01 | 0x02) {
        return Vec::new();
    }
    let req: [u8; 4] = frame[6..link::HEADER_LEN].try_into().expect("four bytes");
    vec![encode(req, Body::Error(code))]
}

impl<'a> Exchange<'a> {
    /// The exchange of the profile in `data_dir`, with what it remembers.
    pub fn new(data_dir: &'a Path, memory: &'a Mutex<Memory>) -> Self {
        Self { data_dir, memory }
    }

    fn row(&self, handle: &Handle) -> Option<Row> {
        store::get(self.data_dir, handle).ok().flatten()
    }

    /// A friend's row for `handle` that `peer` offered in a chat.
    fn theirs(&self, peer: &[u8; 32], handle: &Handle) -> Option<(Row, Brief)> {
        let row = self.row(handle)?;
        let brief = Brief::of(&row)?;
        (!brief.outgoing && brief.peer == Some(*peer)).then_some((row, brief))
    }

    /// My row for `handle` that I offered to `peer` in a chat.
    fn mine(&self, peer: &[u8; 32], handle: &Handle) -> Option<(Row, Brief)> {
        let row = self.row(handle)?;
        let brief = Brief::of(&row)?;
        (brief.outgoing && brief.peer == Some(*peer)).then_some((row, brief))
    }

    // ── The listener ──

    /// A `RAX1` frame the dialer `peer` sent: the replies to write. The
    /// caller made sure of `peer`: a verified friend on an authenticated
    /// link ([`refuse`] answers anyone else).
    pub fn listener_frame(&self, peer: &[u8; 32], frame: &[u8], now_ms: u64) -> Vec<Vec<u8>> {
        let Ok(Frame { req, body }) = link::decode_for_listener(frame) else {
            return answer_error(frame, ErrorCode::Malformed);
        };
        match body {
            Body::Have(entries) => {
                let lacks = entries
                    .into_iter()
                    .map(|(handle, chunks)| (handle, self.lack(peer, &handle, chunks, now_ms)))
                    .collect();
                vec![encode(req, Body::Lack(lacks))]
            }
            Body::Push(chunk) => {
                self.take(peer, &chunk, false, now_ms);
                Vec::new()
            }
            Body::Want {
                handle,
                first,
                count,
            } => self.serve(peer, req, &handle, first, count, now_ms),
            Body::Done(handle) => {
                if let Some((_, brief)) = self.mine(peer, &handle) {
                    if matches!(brief.state, State::Staged | State::Offered) {
                        let chunks = brief.shape.chunks();
                        let _ = store::update(self.data_dir, &handle, now_ms, |row| {
                            row.state = State::Delivered;
                            row.friend_has = chunks;
                        });
                        locked(self.memory).rows.remove(&handle);
                    }
                }
                Vec::new()
            }
            // decode_for_listener hands requests only.
            _ => Vec::new(),
        }
    }

    /// What this node still lacks of an attachment `peer` says it holds.
    fn lack(&self, peer: &[u8; 32], handle: &Handle, chunks: u16, now_ms: u64) -> Lack {
        let Some((row, brief)) = self.theirs(peer, handle) else {
            return Lack::NotKnown;
        };
        if brief.shape.chunks() != u32::from(chunks) {
            return Lack::NotKnown;
        }
        match brief.state {
            State::Complete => Lack::Complete,
            State::Gone | State::Failed => Lack::Declined,
            State::Incoming if self.spent(peer, handle) => Lack::Declined,
            State::Incoming if brief.takes_chunks() => {
                let Ok(have) = store::have(self.data_dir, handle, &brief.shape, false) else {
                    return Lack::Later;
                };
                if have.complete() {
                    // Every chunk landed and the last step did not run (a
                    // stop in between): it runs now.
                    return match self.finish(&row, false, now_ms) {
                        State::Complete => Lack::Complete,
                        _ => Lack::Declined,
                    };
                }
                Lack::wanting(chunks, &have.missing())
            }
            State::Incoming => Lack::Later,
            // A row of mine never answers for a friend's attachment.
            State::Staged | State::Offered | State::Delivered => Lack::NotKnown,
        }
    }

    /// Did `source` send too many bad chunks for `handle`?
    fn spent(&self, source: &[u8; 32], handle: &Handle) -> bool {
        locked(self.memory)
            .bad
            .get(&(*source, *handle))
            .is_some_and(|n| *n >= MAX_BAD_CHUNKS)
    }

    /// Takes a chunk `source` sent for a friend's attachment: only for an
    /// offer that friend made, checked against its root, then written.
    /// `tell`: when it is the last one, the holder is told with DONE (a
    /// chunk this node asked for; one the holder pushed is followed by its
    /// HAVE, whose answer tells it).
    fn take(&self, source: &[u8; 32], chunk: &ChunkBody, tell: bool, now_ms: u64) -> Landed {
        let Some((row, brief)) = self.theirs(source, &chunk.handle) else {
            return Landed::No;
        };
        if !brief.takes_chunks() || self.spent(source, &chunk.handle) {
            return Landed::No;
        }
        let Some(root) = row.root() else {
            return Landed::No;
        };
        let taken = store::take_chunk(
            self.data_dir,
            &chunk.handle,
            &brief.shape,
            &root,
            u32::from(chunk.index),
            &chunk.bytes,
            &chunk.path,
        );
        match taken {
            Ok(Taken::Written { complete: true }) => {
                if self.finish(&row, tell, now_ms) == State::Complete {
                    Landed::Last
                } else {
                    Landed::Written
                }
            }
            Ok(Taken::Written { complete: false }) => Landed::Written,
            Ok(Taken::Bad) => {
                *locked(self.memory)
                    .bad
                    .entry((*source, chunk.handle))
                    .or_insert(0) += 1;
                Landed::No
            }
            _ => Landed::No,
        }
    }

    /// Every chunk of a friend's attachment is here: it is complete when
    /// the blob opens under the offer's key, failed otherwise. `tell`: the
    /// holder is then told with DONE on a dial of this node's (not when the
    /// holder is on the link and hears it from its own HAVE's answer).
    fn finish(&self, row: &Row, tell: bool, now_ms: u64) -> State {
        let Some(handle) = row.handle_bytes() else {
            return State::Failed;
        };
        let state = match store::opens(self.data_dir, row) {
            Ok(true) => State::Complete,
            Ok(false) => State::Failed,
            // The disk did not answer: nothing is decided.
            Err(_) => return State::Incoming,
        };
        let _ = store::set_state(self.data_dir, &handle, state, now_ms);
        let mut m = locked(self.memory);
        m.rows.remove(&handle);
        if state == State::Complete && tell {
            if let Some(peer) = row.peer_key() {
                if !m.done_due.contains(&(peer, handle)) {
                    m.done_due.push((peer, handle));
                }
            }
        }
        state
    }

    /// Serves chunks of an attachment this node offered to `peer`.
    fn serve(
        &self,
        peer: &[u8; 32],
        req: [u8; 4],
        handle: &Handle,
        first: u16,
        count: u8,
        now_ms: u64,
    ) -> Vec<Vec<u8>> {
        let error = |code| vec![encode(req, Body::Error(code))];
        let Some((row, brief)) = self.mine(peer, handle) else {
            return error(ErrorCode::NotFound);
        };
        match brief.state {
            State::Gone => return error(ErrorCode::Gone),
            State::Failed => return error(ErrorCode::NotFound),
            _ => {}
        }
        if u32::from(first) >= brief.shape.chunks() {
            return error(ErrorCode::NotFound);
        }
        let Ok(tree) = store::tree(self.data_dir, &row) else {
            return error(ErrorCode::NotFound);
        };
        let end = (u32::from(first) + u32::from(count)).min(brief.shape.chunks());
        let mut out = Vec::new();
        let mut code = 0u8;
        for index in u32::from(first)..end {
            let len = brief.shape.chunk_len(index).unwrap_or(0) as u64;
            if !self.admit_served(peer, len, now_ms) {
                code = ErrorCode::RateLimited as u8;
                break;
            }
            let chunk = store::read_chunk(self.data_dir, handle, &brief.shape, true, index)
                .ok()
                .zip(tree.chunk_path(index as usize));
            let Some((bytes, path)) = chunk else {
                code = ErrorCode::NotFound as u8;
                break;
            };
            out.push(encode(
                req,
                Body::Chunk(ChunkBody {
                    handle: *handle,
                    index: index as u16,
                    bytes,
                    path,
                }),
            ));
        }
        let sent = out.len() as u8;
        out.push(encode(req, Body::ChunksEnd { code, sent }));
        out
    }

    fn admit_served(&self, peer: &[u8; 32], bytes: u64, now_ms: u64) -> bool {
        let mut m = locked(self.memory);
        let served = m.served.entry(*peer).or_default();
        if now_ms.saturating_sub(served.day_start_ms) >= DAY_MS {
            *served = Served {
                day_start_ms: now_ms,
                bytes: 0,
            };
        }
        if served.bytes.saturating_add(bytes) > SERVE_BYTES_PER_DAY {
            return false;
        }
        served.bytes += bytes;
        true
    }

    // ── The dialer ──

    /// Reads the rows that changed since the last pass.
    fn refresh(&self) {
        let on_disk = store::rows_on_disk(self.data_dir);
        let mut m = locked(self.memory);
        m.rows
            .retain(|handle, _| on_disk.iter().any(|(h, _)| h == handle));
        for (handle, changed) in on_disk {
            if m.rows.get(&handle).is_some_and(|(at, _)| *at == changed) {
                continue;
            }
            let brief = self.row(&handle).as_ref().and_then(Brief::of);
            // The user asked for it (again) since the last look: no wait
            // an earlier try set holds it back.
            let asked_now = brief.as_ref().is_some_and(|b| b.asked)
                && m.rows.get(&handle).is_some_and(|(_, old)| {
                    old.as_ref().is_some_and(|old| {
                        old.updated_ms != brief.as_ref().map_or(0, |b| b.updated_ms)
                    })
                });
            // The offer was delivered since the last look: the wait a
            // question asked too early set is over.
            let delivered_now = brief.as_ref().is_some_and(|b| b.state == State::Offered)
                && m.rows.get(&handle).is_some_and(|(_, old)| {
                    old.as_ref().is_some_and(|old| old.state == State::Staged)
                });
            if asked_now || delivered_now {
                m.parked.remove(&handle);
            }
            m.rows.insert(handle, (changed, brief));
        }
        let Memory {
            rows,
            wanted,
            tried,
            stalls,
            parked,
            bad,
            done_due,
            ..
        } = &mut *m;
        let live = |handle: &Handle| {
            rows.get(handle)
                .and_then(|(_, b)| b.as_ref())
                .is_some_and(|b| !matches!(b.state, State::Delivered | State::Gone | State::Failed))
        };
        wanted.retain(|h, _| live(h));
        tried.retain(|h| live(h));
        stalls.retain(|h, _| live(h));
        parked.retain(|h, _| live(h));
        bad.retain(|(_, h), _| live(h));
        done_due.retain(|(_, h)| rows.contains_key(h));
    }

    /// The dials due at `now_ms`. `speaks`: does this friend's node take
    /// `RAX1` frames, as far as this node knows?
    pub fn plans(&self, now_ms: u64, speaks: &dyn Fn(&[u8; 32]) -> bool) -> Planned {
        self.refresh();
        let mut out = Planned::default();
        let (briefs, done_due) = {
            let m = locked(self.memory);
            let briefs: Vec<(Handle, Brief)> = m
                .rows
                .iter()
                .filter_map(|(h, (_, b))| Some((*h, b.clone()?)))
                .collect();
            (briefs, m.done_due.clone())
        };
        let mut busy: Vec<[u8; 32]> = Vec::new();
        let mut add = |out: &mut Planned, plan: Plan| {
            // One dial per friend in a pass.
            if out.plans.len() >= MAX_PLANS_PER_PASS || busy.contains(&plan.peer) {
                out.waiting = true;
                out.waits.turn += 1;
                return;
            }
            busy.push(plan.peer);
            out.plans.push(plan);
        };
        for (peer, handle) in done_due {
            if self.parked(&handle, now_ms) {
                out.waiting = true;
                out.waits.turn += 1;
                continue;
            }
            if !speaks(&peer) {
                out.waiting = true;
                out.waits.friend += 1;
                continue;
            }
            add(
                &mut out,
                Plan {
                    peer,
                    handle,
                    frames: vec![encode(req(), Body::Done(handle))],
                    what: What::Done,
                },
            );
        }
        for (handle, brief) in briefs {
            let Some(peer) = brief.peer else {
                continue;
            };
            let push = brief.outgoing
                && matches!(brief.state, State::Staged | State::Offered)
                && brief.shape.len() <= LIVE_MAX_LEN;
            let pull = brief.takes_chunks() && !self.spent(&peer, &handle);
            if !push && !pull {
                continue;
            }
            if self.parked(&handle, now_ms) {
                out.waiting = true;
                out.waits.turn += 1;
                continue;
            }
            if !speaks(&peer) {
                out.waiting = true;
                out.waits.friend += 1;
                continue;
            }
            let plan = if push {
                // An offer still on its way: its delivery is waited for (the
                // row then says so, and everything is pushed at once). Only
                // one whose delivery was not seen for a while is asked for.
                if brief.state == State::Staged {
                    if now_ms.saturating_sub(brief.created_ms) >= STAGED_MAX_AGE_MS {
                        continue;
                    }
                    // A send of the offer is under way (over Tor it can
                    // take a quarter of a minute): its link takes the
                    // chunks along, or its delivery wakes the push. Nothing
                    // is asked beside it.
                    let going = brief.going_ms > 0
                        && now_ms.saturating_sub(brief.going_ms) < GOING_FRESH_MS;
                    if going || now_ms.saturating_sub(brief.updated_ms) < STAGED_PROBE_AFTER_MS {
                        out.waiting = true;
                        out.waits.offer += 1;
                        continue;
                    }
                }
                self.push_plan(peer, handle, &brief)
            } else {
                // One the user asked for is fetched at once; one that
                // comes by itself only when no chunk landed for a while
                // (its sender may be pushing it).
                let last = brief
                    .updated_ms
                    .max(store::last_chunk_ms(self.data_dir, &handle));
                if !brief.asked && now_ms.saturating_sub(last) < PULL_AFTER_MS {
                    out.waiting = true;
                    out.waits.push += 1;
                    continue;
                }
                self.pull_plan(peer, handle, &brief)
            };
            match plan {
                Some(plan) => add(&mut out, plan),
                None => {
                    out.waiting = true;
                    out.waits.turn += 1;
                }
            }
        }
        out
    }

    /// A dial to `peer` just carried a message that was answered, and a
    /// send of an offer to that friend set out a moment ago: every chunk of
    /// that attachment and HAVE, to ride the same link right behind the
    /// answer. No dial of its own, which on Tor is most of a small photo's
    /// time. None: no such attachment, or something was tried for it
    /// before (the task then asks first, as after a cut).
    ///
    /// The answer on the link may be to another message; the friend's
    /// node then does not know the offer yet and says so, as it would to a
    /// dial of the task's.
    pub fn link_push(&self, peer: &[u8; 32], now_ms: u64) -> Option<Plan> {
        self.link_push_or_why(peer, now_ms).ok()
    }

    /// [`Self::link_push`], or why nothing rides the link, for a log line
    /// (a word, no handle): `""` when this friend has no attachment of
    /// mine that is still to go at all.
    pub fn link_push_or_why(&self, peer: &[u8; 32], now_ms: u64) -> Result<Plan, &'static str> {
        self.refresh();
        let (handle, brief) = {
            let m = locked(self.memory);
            let mine: Vec<(Handle, Brief)> = m
                .rows
                .iter()
                .filter_map(|(handle, (_, brief))| Some((*handle, brief.clone()?)))
                .filter(|(_, brief)| {
                    brief.outgoing
                        && brief.peer == Some(*peer)
                        && matches!(brief.state, State::Staged | State::Offered)
                })
                .collect();
            if mine.is_empty() {
                return Err("");
            }
            let fresh = |brief: &Brief| {
                brief.going_ms > 0 && now_ms.saturating_sub(brief.going_ms) < GOING_FRESH_MS
            };
            let ready: Vec<&(Handle, Brief)> = mine
                .iter()
                .filter(|(handle, brief)| {
                    fresh(brief)
                        && brief.friend_has == 0
                        && brief.shape.len() <= LIVE_MAX_LEN
                        && !m.tried.contains(handle)
                        && !m.wanted.contains_key(handle)
                })
                .collect();
            // The send that set out last.
            match ready.into_iter().max_by_key(|(_, brief)| brief.going_ms) {
                Some(found) => found.clone(),
                None if !mine.iter().any(|(_, brief)| fresh(brief)) => {
                    return Err("no send of its offer set out lately")
                }
                None => return Err("its chunks were pushed or asked about before"),
            }
        };
        locked(self.memory).tried.insert(handle);
        let row = self.row(&handle).ok_or("its row is gone")?;
        let tree = store::tree(self.data_dir, &row).map_err(|_| "its sealed bytes do not read")?;
        let mut frames = Vec::new();
        for index in (0..brief.shape.chunks()).take(MAX_PUSH_PER_DIAL) {
            let bytes = store::read_chunk(self.data_dir, &handle, &brief.shape, true, index)
                .map_err(|_| "its sealed bytes do not read")?;
            let path = tree
                .chunk_path(index as usize)
                .ok_or("its sealed bytes do not read")?;
            frames.push(encode(
                req(),
                Body::Push(ChunkBody {
                    handle,
                    index: index as u16,
                    bytes,
                    path,
                }),
            ));
        }
        let pushed = frames.len();
        let req = req();
        frames.push(encode(
            req,
            Body::Have(vec![(handle, brief.shape.chunks() as u16)]),
        ));
        Ok(Plan {
            peer: *peer,
            handle,
            frames,
            what: What::Push { req, pushed },
        })
    }

    fn parked(&self, handle: &Handle, now_ms: u64) -> bool {
        locked(self.memory)
            .parked
            .get(handle)
            .is_some_and(|p| p.until_ms > now_ms)
    }

    /// HAVE, after the chunks the friend's last LACK wanted; after every
    /// chunk for an offer just delivered; alone when this node does not
    /// know what the friend has.
    fn push_plan(&self, peer: [u8; 32], handle: Handle, brief: &Brief) -> Option<Plan> {
        let (wanted, first_try) = {
            let m = locked(self.memory);
            (m.wanted.get(&handle).cloned(), !m.tried.contains(&handle))
        };
        // The offer is delivered and no chunk was pushed yet: the friend's
        // node kept its row before it answered, and lacks every chunk.
        let blind =
            wanted.is_none() && first_try && brief.state == State::Offered && brief.friend_has == 0;
        if blind {
            locked(self.memory).tried.insert(handle);
        }
        let wanted = wanted.or_else(|| blind.then(|| (0..brief.shape.chunks()).collect()));
        let mut frames = Vec::new();
        if let Some(wanted) = wanted.filter(|w| !w.is_empty()) {
            let row = self.row(&handle)?;
            let tree = store::tree(self.data_dir, &row).ok()?;
            for index in wanted.into_iter().take(MAX_PUSH_PER_DIAL) {
                let bytes =
                    store::read_chunk(self.data_dir, &handle, &brief.shape, true, index).ok()?;
                let path = tree.chunk_path(index as usize)?;
                frames.push(encode(
                    req(),
                    Body::Push(ChunkBody {
                        handle,
                        index: index as u16,
                        bytes,
                        path,
                    }),
                ));
            }
        } else if store::have(self.data_dir, &handle, &brief.shape, true).is_err() {
            // The blob is not written yet (or is gone): nothing to offer.
            return None;
        }
        let pushed = frames.len();
        let req = req();
        frames.push(encode(
            req,
            Body::Have(vec![(handle, brief.shape.chunks() as u16)]),
        ));
        Some(Plan {
            peer,
            handle,
            frames,
            what: What::Push { req, pushed },
        })
    }

    /// WANT for the first chunks still missing, in runs.
    fn pull_plan(&self, peer: [u8; 32], handle: Handle, brief: &Brief) -> Option<Plan> {
        let missing = store::have(self.data_dir, &handle, &brief.shape, false)
            .ok()?
            .missing();
        let mut runs: Vec<(u32, u8)> = Vec::new();
        for index in missing.into_iter().take(MAX_PULL_PER_DIAL) {
            let follows = runs.last().is_some_and(|(first, count)| {
                *first + u32::from(*count) == index && *count < link::MAX_WANT
            });
            if follows {
                if let Some((_, count)) = runs.last_mut() {
                    *count += 1;
                }
            } else if runs.len() >= MAX_WANTS_PER_DIAL {
                break;
            } else {
                runs.push((index, 1));
            }
        }
        if runs.is_empty() {
            return None;
        }
        let reqs: Vec<[u8; 4]> = runs.iter().map(|_| req()).collect();
        let frames = runs
            .iter()
            .zip(&reqs)
            .map(|((first, count), req)| {
                encode(
                    *req,
                    Body::Want {
                        handle,
                        first: *first as u16,
                        count: *count,
                    },
                )
            })
            .collect();
        Some(Plan {
            peer,
            handle,
            frames,
            what: What::Pull { reqs },
        })
    }

    fn park(&self, handle: &Handle, until_ms: u64) {
        let mut m = locked(self.memory);
        let park = m.parked.entry(*handle).or_default();
        park.until_ms = park.until_ms.max(until_ms);
    }

    /// A try that failed: wait, longer each time. Up to five minutes for
    /// an attachment whose offer is at the friend's (a friend seen again
    /// ends the wait); up to six hours for an offer whose delivery was not
    /// seen.
    fn back_off(&self, handle: &Handle, now_ms: u64) {
        let mut m = locked(self.memory);
        let staged = m
            .rows
            .get(handle)
            .and_then(|(_, brief)| brief.as_ref())
            .is_some_and(|brief| brief.outgoing && brief.state == State::Staged);
        let longest = if staged {
            STAGED_RETRY_MAX_MS
        } else {
            RETRY_MAX_MS
        };
        let park = m.parked.entry(*handle).or_default();
        let wait = RETRY_MS
            .saturating_mul(1 << park.fails.min(16))
            .min(longest);
        park.fails = park.fails.saturating_add(1);
        park.until_ms = now_ms.saturating_add(wait);
    }

    fn unpark(&self, handle: &Handle) {
        locked(self.memory).parked.remove(handle);
    }

    /// The friend `peer` is here now (a link with it came up): what waits
    /// for it is tried at once.
    pub fn peer_seen(&self, peer: &[u8; 32]) {
        let mut m = locked(self.memory);
        let theirs: Vec<Handle> = m
            .rows
            .iter()
            .filter(|(_, (_, b))| b.as_ref().is_some_and(|b| b.peer == Some(*peer)))
            .map(|(h, _)| *h)
            .collect();
        for handle in theirs {
            // A wait the friend's own answer set (later, declined) stays.
            if m.parked.get(&handle).is_some_and(|p| p.fails > 0) {
                m.parked.remove(&handle);
            }
        }
    }

    /// The dial of `plan` ended: with the friend's `replies`, or not at all
    /// (`None`). `true`: there is more to do for it right now.
    pub fn took(&self, plan: &Plan, replies: Option<&[Vec<u8>]>, now_ms: u64) -> bool {
        let Some(replies) = replies else {
            // Cut somewhere: what the friend has is not known any more.
            self.back_off(&plan.handle, now_ms);
            let mut m = locked(self.memory);
            m.wanted.remove(&plan.handle);
            let tries = m.parked.get(&plan.handle).map_or(0, |p| p.fails);
            if matches!(plan.what, What::Done) && tries >= MAX_DONE_TRIES {
                // The holder learns it from its next HAVE instead.
                m.done_due.retain(|(_, h)| *h != plan.handle);
                m.parked.remove(&plan.handle);
            }
            return false;
        };
        let answers: Vec<Frame> = replies
            .iter()
            .filter(|f| link::is_rax1(f))
            .filter_map(|f| link::decode_for_dialer(f).ok())
            .collect();
        match &plan.what {
            What::Push { req, pushed } => self.took_push(plan, *req, *pushed, &answers, now_ms),
            What::Pull { reqs } => self.took_pull(plan, reqs, &answers, now_ms),
            What::Done => {
                locked(self.memory)
                    .done_due
                    .retain(|(_, h)| *h != plan.handle);
                false
            }
        }
    }

    fn took_push(
        &self,
        plan: &Plan,
        req: [u8; 4],
        pushed: usize,
        answers: &[Frame],
        now_ms: u64,
    ) -> bool {
        let handle = plan.handle;
        let Some((_, brief)) = self.mine(&plan.peer, &handle) else {
            return false;
        };
        let chunks = brief.shape.chunks();
        let answer = answers
            .iter()
            .filter(|f| f.req == req)
            .find_map(|f| match &f.body {
                Body::Lack(entries) => entries
                    .iter()
                    .find(|(h, _)| *h == handle)
                    .map(|(_, lack)| Ok(lack.clone())),
                Body::Error(code) => Some(Err(*code)),
                _ => None,
            });
        let knows_offer = |friend_has: u32| {
            let _ = store::update(self.data_dir, &handle, now_ms, |row| {
                if row.state == State::Staged {
                    row.state = State::Offered;
                }
                row.friend_has = friend_has;
            });
            locked(self.memory).rows.remove(&handle);
        };
        match answer {
            Some(Ok(Lack::Complete)) => {
                let _ = store::update(self.data_dir, &handle, now_ms, |row| {
                    row.state = State::Delivered;
                    row.friend_has = chunks;
                });
                let mut m = locked(self.memory);
                m.rows.remove(&handle);
                m.wanted.remove(&handle);
                m.parked.remove(&handle);
                false
            }
            Some(Ok(lack @ Lack::Wants { .. })) => {
                let wanted = lack.wanted_indices();
                let Lack::Wants { chunks: theirs, .. } = lack else {
                    return false;
                };
                if u32::from(theirs) != chunks || wanted.is_empty() {
                    self.back_off(&handle, now_ms);
                    return false;
                }
                knows_offer(chunks - wanted.len() as u32);
                let mut m = locked(self.memory);
                let before = m.wanted.insert(handle, wanted.clone()).map(|w| w.len());
                // A push that moved nothing: the friend took none of it.
                let stalled = pushed > 0 && before.is_some_and(|b| wanted.len() >= b);
                let stalls = m.stalls.entry(handle).or_insert(0);
                *stalls = if stalled { *stalls + 1 } else { 0 };
                let stalls = *stalls;
                drop(m);
                if stalls >= MAX_STALLS {
                    self.park(&handle, now_ms.saturating_add(DECLINED_MS));
                    return false;
                }
                if stalled {
                    self.back_off(&handle, now_ms);
                    return false;
                }
                self.unpark(&handle);
                true
            }
            Some(Ok(Lack::Later)) => {
                knows_offer(0);
                locked(self.memory).wanted.remove(&handle);
                self.park(&handle, now_ms.saturating_add(LATER_MS));
                false
            }
            Some(Ok(Lack::Declined)) => {
                knows_offer(0);
                locked(self.memory).wanted.remove(&handle);
                self.park(&handle, now_ms.saturating_add(DECLINED_MS));
                false
            }
            // The offer is still on its way (or the friend lost it).
            Some(Ok(Lack::NotKnown)) | None => {
                locked(self.memory).wanted.remove(&handle);
                self.back_off(&handle, now_ms);
                false
            }
            Some(Err(ErrorCode::Busy | ErrorCode::RateLimited)) => {
                self.park(&handle, now_ms.saturating_add(BUSY_MS));
                false
            }
            Some(Err(_)) => {
                locked(self.memory).wanted.remove(&handle);
                self.park(&handle, now_ms.saturating_add(DECLINED_MS));
                false
            }
        }
    }

    fn took_pull(&self, plan: &Plan, reqs: &[[u8; 4]], answers: &[Frame], now_ms: u64) -> bool {
        let handle = plan.handle;
        let mut landed = 0usize;
        let mut done = false;
        // The code of the first request the holder did not serve to its end.
        let mut gave_up: Option<u8> = None;
        for answer in answers.iter().filter(|f| reqs.contains(&f.req)) {
            match &answer.body {
                Body::Chunk(chunk) if chunk.handle == handle => {
                    match self.take(&plan.peer, chunk, true, now_ms) {
                        Landed::No => {}
                        Landed::Written => landed += 1,
                        Landed::Last => {
                            landed += 1;
                            done = true;
                        }
                    }
                }
                Body::ChunksEnd { code: 0, .. } => {}
                Body::ChunksEnd { code, .. } => gave_up = gave_up.or(Some(*code)),
                Body::Error(code) => gave_up = gave_up.or(Some(*code as u8)),
                _ => {}
            }
        }
        if done {
            // DONE goes next.
            self.unpark(&handle);
            return true;
        }
        if gave_up == Some(ErrorCode::Gone as u8) {
            // The author deleted it before it was all here.
            let _ = store::set_state(self.data_dir, &handle, State::Gone, now_ms);
            locked(self.memory).rows.remove(&handle);
            return false;
        }
        if let Some(code) = gave_up {
            self.park(&handle, now_ms.saturating_add(Self::pull_wait(code)));
            return false;
        }
        if landed == 0 {
            self.back_off(&handle, now_ms);
            return false;
        }
        self.unpark(&handle);
        true
    }

    fn pull_wait(code: u8) -> u64 {
        if code == ErrorCode::Busy as u8 || code == ErrorCode::RateLimited as u8 {
            BUSY_MS
        } else {
            DECLINED_MS
        }
    }
}

#[cfg(test)]
mod tests;
