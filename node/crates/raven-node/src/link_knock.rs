//! The RLK1 link knock on the LAN and Internet direct links (Phase 6b step
//! P6.35, design B §3, `protocol/RAVEN_LINK_KNOCK_V1.md`,
//! [`raven_core::link_knock`]).
//!
//! - **Live** only while the knock gate is ([`live`]:
//!   `LINK_KNOCK_PRODUCTION_ENABLED`, or a debug build's
//!   `RAVEN_LAB_LINK_KNOCK=1` with `RAVEN_LAB_TEST_A=1`). With it shut no
//!   dial knocks, no listener reads a knock, and every handshake is byte for
//!   byte what earlier builds send. The p2p and nearby links never knock:
//!   the p2p peer gate refuses strangers before the Raven link starts, and a
//!   nearby pipe is knocked for already (RNK1).
//! - **Listener** ([`Ear`], [`hear`]): it reads message 1 before it builds
//!   its responder and tries the contacts its contact gate would take on
//!   that connection, from the LAN beacon's book
//!   (`crate::lan_beacon::book_peers_with`: every contact that is not
//!   blocked, pinned ones only under `raven lan verified-only`, at most
//!   1,024): on Internet direct, and on LAN from beyond the local network,
//!   the pinned (verified) ones alone, so an unverified contact's knock there
//!   gets a stranger's answer before the gate refuses it (owner decision
//!   2026-10-08). The mode is `security_silent_to_strangers`: automatic is
//!   strict once every contact of the book in use has the knock in its
//!   capability floor and legacy until then, on is silent, off is legacy.
//!   The keys are made again when
//!   the contact book, block list, policy or pair seeds change (Phase 6b
//!   P6.38: while pair seeds are live a contact has up to three key sets,
//!   `crate::pair_seed`; a match with the root while its seed is expected is
//!   `SEC_PAIR_SEED_ROOT`), the mode also when the capability floors do. One replay cache serves both listeners of the
//!   process; a replay is `SEC_KNOCK_REPLAY` about its source (R1 strike 4)
//!   and is answered as no match.
//! - **Dialer** ([`for_dial`], [`DialKnock`]): it knocks to every contact it
//!   can make keys with, with the pair's current seed while pair seeds are
//!   live (else the root). After message 2 a proof lets it go on with a fresh
//!   static; without one the M0 pin decides, then the contact's capability
//!   floor: a contact that knocked before and answers without a proof now is
//!   left before message 3 (`SEC_ADDRESS_IMPOSTOR`, M0's text); anyone else
//!   gets today's handshake.
//! - **Pins (M0):** a link whose knock matched carries fresh statics both
//!   ways, so neither end pins it; pins kept before stay the fallback for
//!   listeners without the knock.
//! - **Capability floor:** a LAN or Internet direct link shows whether it
//!   carried the knock ([`Knocked::showed`], the dialer's proof); p2p and
//!   nearby links cannot tell (`None`).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use raven_core::capability_floor::{self, CAPABILITY_FLOOR_FILE};
use raven_core::identity::Identity;
use raven_core::link_knock::{
    self as rlk, DialerStep, Dialing, KnockKeys, ListenerMode, PinCheck, ReplayCache, Reply,
};
use raven_core::security_gate::{self, SecGate};
use raven_core::OutboxCarrier;

use crate::lan_beacon::BookStamp;
use crate::p2p::{file_stamp, FileStamp};
use crate::pair_seed::KeyUse;
use raven_core::security_events::Via;

/// A listener in silent mode closed a connection whose message 1 carried no
/// contact's knock, before message 2 (design B §3). Not a security event:
/// a stranger's probe learns nothing, and nothing about it is kept.
pub(crate) const KNOCK_SILENT: &str =
    "link knock: no contact knocked, silent to strangers; closed before message 2";

/// The RLK1 link knock is live in this process (design B,
/// `SecGate::LinkKnock`): dials knock. A security notice's hold on it
/// (P6.45) shuts it.
pub(crate) fn live() -> bool {
    security_gate::live(SecGate::LinkKnock)
}

/// Listeners read knocks ([`Ear::of`]): [`live`], or a security notice holds
/// the knock (P6.45). Under such a hold this node knocks no more and its
/// capability floors do not note the knock
/// (`raven_core::capability_floor`), but its listener still proves itself
/// to a contact that knocks: a contact whose floor shows the knock and that
/// has no notice yet stops before message 3 where no proof comes, as at an
/// impostor (Phase 6 review traffic-4).
pub(crate) fn listener_live() -> bool {
    security_gate::live_despite_own_hold(SecGate::LinkKnock)
}

/// The knock open (`Some(true)`) or shut for the current thread until
/// dropped (`SecGate::LinkKnock`'s lab override; a `#[tokio::test]` runs
/// both ends of a scripted link on that thread). A release build ignores
/// it: a caller checks [`live`] after setting it.
#[cfg(test)]
pub(crate) struct KnockForTest;

#[cfg(test)]
impl KnockForTest {
    pub(crate) fn set(on: bool) -> Self {
        security_gate::set_lab_for_this_thread(SecGate::LinkKnock, Some(on));
        Self
    }
}

#[cfg(test)]
impl Drop for KnockForTest {
    fn drop(&mut self) {
        security_gate::set_lab_for_this_thread(SecGate::LinkKnock, None);
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The fresh statics, nonces and pads of the knock (and of
/// [`Dialing::finish`]).
pub(crate) fn rng() -> rand::rngs::OsRng {
    rand::rngs::OsRng
}

// ── Listener ───────────────────────────────────────────────────────────────

/// What a listener needs to read knocks: its profile and identity, and the
/// source and carrier a replay is about.
#[derive(Clone)]
pub(crate) struct Ear {
    data_dir: PathBuf,
    identity: Arc<Identity>,
    source: Option<IpAddr>,
    carrier: OutboxCarrier,
}

impl Ear {
    /// The ear of a LAN or Internet direct listener for one connection from
    /// `source`: `None` while the knock is shut (today's handshake), but
    /// not while a security notice only holds it ([`listener_live`]).
    pub(crate) fn of(
        data_dir: &Path,
        identity: &Arc<Identity>,
        source: Option<IpAddr>,
        carrier: OutboxCarrier,
    ) -> Option<Self> {
        let carries = matches!(carrier, OutboxCarrier::Lan | OutboxCarrier::Internet);
        (listener_live() && carries).then(|| Self {
            data_dir: data_dir.to_path_buf(),
            identity: Arc::clone(identity),
            source,
            carrier,
        })
    }

    /// Does this connection's contact gate take verified (pinned) contacts
    /// alone (`raven_core::lan_dispatch::link_admission`, owner decision
    /// 2026-10-08)? Internet direct always; LAN unless the source is on the
    /// local network (an unknown source counts as remote; `raven lan
    /// verified-only` narrows the book further). Only those contacts' knocks
    /// are tried then: an unverified contact's knock gets a stranger's
    /// answer, never the proof that would tell it whose address this is.
    fn pinned_only(&self) -> bool {
        self.carrier != OutboxCarrier::Lan
            || !self
                .source
                .is_some_and(raven_core::outbox::is_local_network_ip)
    }
}

/// What a listener's handshake learned from the knock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Knocked {
    /// The knock is shut on this side: today's handshake.
    Off,
    /// Message 1 carried no contact's knock (or a replayed one).
    Stranger,
    /// This contact knocked: it got a fresh static and the proof.
    Contact([u8; 32]),
}

impl Knocked {
    /// What this link showed the capability floor of `peer`, the contact
    /// its bind or hello named: whether it knocked, `None` while the knock
    /// is shut here.
    pub(crate) fn showed(self, peer: &[u8; 32]) -> Option<bool> {
        match self {
            Knocked::Off => None,
            Knocked::Stranger => Some(false),
            Knocked::Contact(k) => Some(k == *peer),
        }
    }

    /// The dialer's static is one it chose for this link (its knock
    /// matched, so it got the proof and goes on with a fresh static): it is
    /// never pinned (M0).
    pub(crate) fn fresh_dialer(self) -> bool {
        matches!(self, Knocked::Contact(_))
    }
}

/// The listener's book: the knock keys of its contacts (a contact with
/// pair seeds has up to three sets), what each set is for, and its mode.
struct Book {
    keys: Arc<Vec<KnockKeys>>,
    uses: Arc<Vec<KeyUse>>,
    mode: ListenerMode,
}

/// The book as last made, with what it was made from.
struct Cached {
    data_dir: PathBuf,
    me: [u8; 32],
    seeds: bool,
    book_stamp: BookStamp,
    floor_stamp: Option<FileStamp>,
    book: Arc<Book>,
}

/// The books as last made: every contact of the beacon's book (`[0]`), and
/// its pinned contacts alone (`[1]`, [`Ear::pinned_only`]).
static BOOK: Mutex<[Option<Cached>; 2]> = Mutex::new([None, None]);

/// Matched nonces of both listeners (spec §4: 4,096 for 3 days), kept in
/// the profile across restarts (Phase 6 review traffic-9): see [`replays`].
struct Replays {
    data_dir: PathBuf,
    cache: ReplayCache,
    /// The profile's file was read (or there was none): what is matched now
    /// is written to it. Until then the cache is this process's alone, and
    /// the file is never written over.
    kept: bool,
}

static REPLAYS: Mutex<Option<Replays>> = Mutex::new(None);

/// Blocking: the replay cache of the listeners of `data_dir`, the profile's
/// [`raven_core::link_knock::KNOCK_REPLAYS_FILE`] read into it the first
/// time (a missing file is an empty cache). A file that cannot be read now
/// (a sealed one before the at-rest key is here) leaves a cache of this
/// process's own, and is read again, with what was matched meanwhile kept
/// too, at the next knock.
fn replays<'a>(slot: &'a mut Option<Replays>, data_dir: &Path, now_ms: u64) -> &'a mut Replays {
    if slot.as_ref().is_some_and(|r| r.data_dir != data_dir) {
        *slot = None;
    }
    let r = slot.get_or_insert_with(|| Replays {
        data_dir: data_dir.to_path_buf(),
        cache: ReplayCache::new(),
        kept: false,
    });
    if !r.kept {
        let path = data_dir.join(rlk::KNOCK_REPLAYS_FILE);
        let read = raven_core::at_rest::load_bytes(
            data_dir,
            &path,
            raven_core::at_rest::Kind::KnockReplays,
        );
        if let Ok(bytes) = read {
            let mut cache =
                bytes.map_or_else(ReplayCache::new, |b| ReplayCache::decode(&b, now_ms));
            for (at, nonce) in r.cache.entries() {
                cache.replayed(&nonce, at);
            }
            r.cache = cache;
            r.kept = true;
        }
    }
    r
}

/// Blocking: `r`'s cache written to its profile, before the knock that
/// added to it is answered (a crash after the answer forgets nothing). Best
/// effort: a write that fails leaves the cache this process holds.
fn keep_replays(r: &Replays) {
    use raven_core::at_rest::{self, Kind};
    if !r.kept {
        return;
    }
    let path = r.data_dir.join(rlk::KNOCK_REPLAYS_FILE);
    if let Ok(lock) = at_rest::lock_file(&r.data_dir, &path, Kind::KnockReplays) {
        let _ = lock.store_bytes(&r.cache.encode());
    }
}

/// Blocking: the listener's book for `identity` in `data_dir`, made again
/// only when the contact book, block list, policy or pair seeds changed
/// (the keys; `seeds`: pair seeds live, read by the caller) or the
/// capability floors did (the mode). `pinned_only`: the verified contacts
/// alone ([`Ear::pinned_only`]), and the mode worked out from them. A book
/// that cannot be read is empty and legacy unless silent mode is on, and is
/// not kept: nobody's older pin breaks while the at-rest key is still
/// loading.
fn listener_book(
    data_dir: &Path,
    identity: &Identity,
    seeds: bool,
    pinned_only: bool,
) -> Arc<Book> {
    let me = identity.public_key_bytes();
    let book_stamp = crate::lan_beacon::book_stamp(data_dir);
    let floor_stamp = file_stamp(&data_dir.join(CAPABILITY_FLOOR_FILE));
    let mut books = lock(&BOOK);
    let cached = &mut books[usize::from(pinned_only)];
    let same_book = cached.as_ref().filter(|c| {
        c.data_dir == data_dir && c.me == me && c.seeds == seeds && c.book_stamp == book_stamp
    });
    if let Some(c) = same_book.filter(|c| c.floor_stamp == floor_stamp) {
        return Arc::clone(&c.book);
    }
    let setting = raven_core::node_policy::load_policy(data_dir).security_silent_to_strangers;
    let (keys, uses) = match same_book {
        Some(c) => (Arc::clone(&c.book.keys), Arc::clone(&c.book.uses)),
        None => match crate::lan_beacon::book_peers_with(data_dir, pinned_only) {
            Ok(peers) => {
                let seeds = crate::pair_seed::book(data_dir, seeds);
                let (keys, uses): (Vec<KnockKeys>, Vec<KeyUse>) = peers
                    .iter()
                    .filter_map(|peer| {
                        crate::pair_seed::key_sets(identity, peer, &seeds, rlk::knock_keys_from)
                            .ok()
                    })
                    .take(rlk::MAX_BOOK)
                    .flatten()
                    .unzip();
                (Arc::new(keys), Arc::new(uses))
            }
            Err(_) => {
                return Arc::new(Book {
                    keys: Arc::default(),
                    uses: Arc::default(),
                    mode: rlk::listener_mode(setting, false),
                })
            }
        },
    };
    let mut peers: Vec<[u8; 32]> = keys.iter().map(|k| k.peer).collect();
    peers.dedup();
    let every = capability_floor::all_knock(data_dir, &peers);
    let book = Arc::new(Book {
        keys,
        uses,
        mode: rlk::listener_mode(setting, every),
    });
    *cached = Some(Cached {
        data_dir: data_dir.to_path_buf(),
        me,
        seeds,
        book_stamp,
        floor_stamp,
        book: Arc::clone(&book),
    });
    book
}

/// The listener's answer to the raw message 1 `m1` (spec §4), worked out on
/// the blocking pool: the static to build its responder with and message
/// 2's payload, and what the knock showed. The contacts tried are those its
/// contact gate would take from `ear`'s carrier and source
/// ([`Ear::pinned_only`]). A replay is `SEC_KNOCK_REPLAY` about `ear`'s
/// source. Silent mode with no contact's knock: [`KNOCK_SILENT`], and the
/// caller closes without message 2.
pub(crate) async fn hear(ear: &Ear, m1: &[u8]) -> Result<(Reply, Knocked), String> {
    let (dd, identity, m1) = (ear.data_dir.clone(), Arc::clone(&ear.identity), m1.to_vec());
    let now = raven_core::clock::now_ms();
    let seeds = crate::pair_seed::live();
    let pinned_only = ear.pinned_only();
    let (heard, used) = tokio::task::spawn_blocking(move || {
        let book = listener_book(&dd, &identity, seeds, pinned_only);
        let mut slot = lock(&REPLAYS);
        let replays = replays(&mut slot, &dd, now);
        let heard = rlk::hear(
            &book.keys,
            book.mode,
            &identity,
            &m1,
            now,
            &mut replays.cache,
            &mut rng(),
        )?;
        // A new match: its nonce is remembered, in the profile too.
        if heard.matched.is_some() {
            keep_replays(replays);
        }
        let used = heard.matched_index.and_then(|i| book.uses.get(i).copied());
        Ok::<_, raven_core::lan_noise::LanNoiseError>((heard, used))
    })
    .await
    .map_err(|e| format!("link knock join: {e}"))?
    .map_err(|e| e.to_string())?;
    if heard.replay {
        if let Some(ip) = ear.source {
            crate::security::knock_replayed(ip, ear.carrier);
        }
    }
    // Phase 6b: the contact knocked with the pair's root while its seed was
    // expected (a Notice; the root keeps friends from a lockout).
    if let (Some(peer), Some(used)) = (heard.matched, used) {
        crate::pair_seed::root_matched(&peer, used, Via::DirectLink(ear.carrier));
    }
    let reply = heard.reply.ok_or_else(|| KNOCK_SILENT.to_string())?;
    Ok((
        reply,
        heard.matched.map_or(Knocked::Stranger, Knocked::Contact),
    ))
}

// ── Dialer ─────────────────────────────────────────────────────────────────

/// A dial knocked with the pair's seed and its listener gave no proof
/// (P6.38): it does not stop as at an impostor, but knocks once more with
/// the root on a new connection ([`DialKnock::fallback`]), since a contact
/// that lost its seed (or runs without seeds) proves itself only to that.
/// Also when an M0 pin would let the link go on without the knock while the
/// contact's floor shows it ([`DialKnock::unproved`]).
pub(crate) const KNOCK_SEED_UNPROVED: &str =
    "link knock: no proof for the pair seed's knock; knocking with the pair's root";

/// One attempt of a dial that knocked with the pair's seed: the listener
/// closed the connection before message 2. A listener silent to strangers
/// that lost the seed does that ([`dial_attempts`] then knocks once with the
/// root); so does one over its connection cap. Never returned by
/// [`dial_attempts`].
pub(crate) const KNOCK_SEED_CLOSED: &str =
    "link knock: the listener closed the connection after the pair seed's knock, before message 2";

/// The connect-and-handshake attempts of a dial that may knock (LAN and
/// Internet direct): `attempt` with `knock`, retried as
/// `netutil::with_handshake_retries` does; then, for a knock with the
/// pair's seed (Phase 6b P6.38), the pair's root's knock on a new connection
/// when the seed's got no proof ([`KNOCK_SEED_UNPROVED`], retried the same
/// way), or, once, when every attempt's listener closed before message 2
/// ([`KNOCK_SEED_CLOSED`]: a listener silent to strangers that lost the
/// seed proves itself to the root alone, and answers nothing else). Only
/// the root's knock then decides.
pub(crate) async fn dial_attempts<'k, T, F, Fut>(
    knock: Option<&'k DialKnock>,
    mut attempt: F,
) -> Result<T, String>
where
    F: FnMut(Option<&'k DialKnock>) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    use crate::netutil::{with_handshake_retries, PEER_CLOSED};
    use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
    let (tried, seed_closed) = (AtomicU32::new(0), AtomicU32::new(0));
    let got = with_handshake_retries(|| {
        let once = attempt(knock);
        let (tried, seed_closed) = (&tried, &seed_closed);
        async move {
            tried.fetch_add(1, Relaxed);
            once.await.map_err(|e| {
                if e != KNOCK_SEED_CLOSED {
                    return e;
                }
                seed_closed.fetch_add(1, Relaxed);
                PEER_CLOSED.to_string()
            })
        }
    })
    .await;
    let Some(root) = knock.and_then(DialKnock::fallback) else {
        return got;
    };
    match got {
        Err(e) if e == KNOCK_SEED_UNPROVED => with_handshake_retries(|| attempt(Some(root))).await,
        Err(e)
            if e.starts_with(PEER_CLOSED) && seed_closed.load(Relaxed) == tried.load(Relaxed) =>
        {
            match attempt(Some(root)).await {
                Err(again) if again == PEER_CLOSED => Err(e),
                other => other,
            }
        }
        other => other,
    }
}

/// What a knocking dial knows before it connects: the contact's knock keys
/// and whether its capability floor shows the knock.
#[derive(Debug)]
pub(crate) struct DialKnock {
    keys: KnockKeys,
    floor: bool,
    /// The knock with the pair's root, when `keys` are a pair seed's
    /// (Phase 6b P6.38).
    root: Option<Box<DialKnock>>,
}

/// Blocking: the knock of a dial from `identity` to `expected` in
/// `data_dir`, with the pair's current seed while pair seeds are live
/// (`seeds`), else its root. `live`: the gate; the caller reads both on its
/// own thread ([`live`], [`crate::pair_seed::live`]). `None` while the knock
/// is shut, and for a key no knock keys can be made with (today's handshake
/// then).
pub(crate) fn for_dial(
    live: bool,
    seeds: bool,
    data_dir: &Path,
    identity: &Identity,
    expected: &[u8; 32],
) -> Option<DialKnock> {
    if !live {
        return None;
    }
    let seeds = crate::pair_seed::book(data_dir, seeds);
    let mut sets =
        crate::pair_seed::key_sets(identity, expected, &seeds, rlk::knock_keys_from).ok()?;
    let floor = capability_floor::has_knock(data_dir, expected);
    // The root's set is the last; the one this node sends with may be it.
    let (root, _) = sets.pop()?;
    let send = sets
        .into_iter()
        .find_map(|(keys, used)| used.send.then_some(keys));
    Some(match send {
        Some(keys) => DialKnock {
            keys,
            floor,
            root: Some(Box::new(DialKnock {
                keys: root,
                floor,
                root: None,
            })),
        },
        None => DialKnock {
            keys: root,
            floor,
            root: None,
        },
    })
}

impl DialKnock {
    /// This knock as if the contact's capability floor did (`floor`) or did
    /// not show the knock (scripted dials).
    #[cfg(test)]
    pub(crate) fn with_floor(mut self, floor: bool) -> Self {
        self.floor = floor;
        if let Some(root) = self.root.take() {
            self.root = Some(Box::new(root.with_floor(floor)));
        }
        self
    }

    /// Does this knock use a pair seed (Phase 6b), with the root's knock to
    /// fall back on ([`Self::fallback`])?
    pub(crate) fn seeded(&self) -> bool {
        self.root.is_some()
    }

    /// The knock with the pair's root, for one more connection after this
    /// seeded knock got no proof ([`KNOCK_SEED_UNPROVED`]).
    pub(crate) fn fallback(&self) -> Option<&DialKnock> {
        self.root.as_deref()
    }

    /// After message 2 with `proof` and the `step` the table gave: does this
    /// seeded knock leave the decision to the root's knock
    /// ([`KNOCK_SEED_UNPROVED`])? Without a proof, when the step stops, and
    /// when the contact's floor shows the knock whatever the step: a friend
    /// that lost its seed answers in legacy mode with its derived static,
    /// which an M0 pin kept from before the knock matches, and only the
    /// root's knock tells that friend from a listener that dropped the knock
    /// (a Suspicious downgrade otherwise; Phase 6 review traffic-2). With
    /// a floor that lacks it a matching pin goes on as before (a listener
    /// without the knock), with no second connection and no root knock.
    pub(crate) fn unproved(&self, proof: bool, step: DialerStep) -> bool {
        self.seeded()
            && !proof
            && (self.floor || matches!(step, DialerStep::StopPin | DialerStep::StopKnock))
    }

    /// The error of a read of message 2 that failed with `e`: a seeded
    /// knock's listener that closed before it is [`KNOCK_SEED_CLOSED`]
    /// ([`dial_attempts`] retries it, then knocks with the root).
    pub(crate) fn m2_error(&self, e: String) -> String {
        if self.seeded() && e == crate::netutil::PEER_CLOSED {
            KNOCK_SEED_CLOSED.to_string()
        } else {
            e
        }
    }

    /// Message 1 with the knock, on the carrier's `prologue` (`None` on
    /// LAN), for today (Raven's clock).
    pub(crate) fn begin(
        &self,
        identity: &Identity,
        prologue: Option<&'static [u8]>,
    ) -> Result<Dialing, String> {
        let day = rlk::day_of(raven_core::clock::now_ms());
        Dialing::start(identity, &self.keys, day, prologue, &mut rng()).map_err(|e| e.to_string())
    }

    /// Message 2 read: the listener's static and whether it proved itself.
    pub(crate) fn read_m2(
        &self,
        dial: &mut Dialing,
        m2: &[u8],
    ) -> Result<([u8; 32], bool), String> {
        dial.read_m2(&self.keys, m2).map_err(|e| e.to_string())
    }

    /// The dialer's step after message 2 (design B §3): the proof, then the
    /// M0 pin (`pinned`, for `expected`, against the listener's
    /// `remote_static`), then the contact's capability floor.
    pub(crate) fn step(
        &self,
        proof: bool,
        identity: &Identity,
        pinned: Option<&[u8; 32]>,
        expected: &[u8; 32],
        remote_static: &[u8; 32],
    ) -> DialerStep {
        let pin = match pinned {
            None => PinCheck::None,
            Some(_) => {
                if crate::lan_direct::check_noise_pin(identity, pinned, expected, remote_static)
                    .is_ok()
                {
                    PinCheck::Match
                } else {
                    PinCheck::Mismatch
                }
            }
        };
        rlk::dialer_step(proof, pin, self.floor)
    }
}

/// Message 3's payload while knocking: RLX1 with the caps of the payload
/// the link would send without the knock (`plain`: empty, or RLX1) and a
/// `PAD` entry to a random length up to 64 bytes (spec §6).
pub(crate) fn m3_payload(plain: &[u8]) -> Vec<u8> {
    rlk::m3_payload(raven_core::route_hints::rlx1_caps(plain), &mut rng())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Off, a stranger and a contact as the capability floor and the pins
    /// see them.
    #[test]
    fn what_a_listener_learned() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(Knocked::Off.showed(&a), None);
        assert_eq!(Knocked::Stranger.showed(&a), Some(false));
        assert_eq!(Knocked::Contact(a).showed(&a), Some(true));
        assert_eq!(Knocked::Contact(b).showed(&a), Some(false));
        assert!(Knocked::Contact(a).fresh_dialer());
        assert!(!Knocked::Stranger.fresh_dialer() && !Knocked::Off.fresh_dialer());
    }

    /// The listener's book follows the contact book and the floors: legacy
    /// with a contact whose floor lacks the knock, strict once it has it,
    /// strict for an empty book, silent when the user turned it on; a
    /// blocked contact is not in it.
    #[test]
    fn the_listeners_book_and_mode() {
        use raven_core::capability_floor::observe_link;
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let me = Identity::from_seed(&[0x31; 32]);
        let friend = Identity::from_seed(&[0x32; 32]);
        let book = listener_book(dd, &me, false, false);
        assert!(book.keys.is_empty());
        assert_eq!(book.mode, ListenerMode::Strict, "nobody to wait for");
        std::fs::write(
            dd.join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}"}}]"#,
                hex::encode(friend.public_key_bytes())
            ),
        )
        .unwrap();
        let book = listener_book(dd, &me, false, false);
        assert_eq!(book.keys.len(), 1);
        assert_eq!(book.keys[0].peer, friend.public_key_bytes());
        assert_eq!(book.mode, ListenerMode::Legacy);
        // The floor shows the knock (events gate open for this thread).
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(true));
        if security_gate::live(SecGate::Events) {
            observe_link(dd, &friend.public_key_bytes(), 0, Some(true), 1).unwrap();
            assert_eq!(
                listener_book(dd, &me, false, false).mode,
                ListenerMode::Strict
            );
        }
        security_gate::set_lab_for_this_thread(SecGate::Events, None);
        let mut policy = raven_core::node_policy::load_policy(dd);
        policy.security_silent_to_strangers = raven_core::node_policy::SilentMode::On;
        raven_core::node_policy::save_policy(dd, &policy).unwrap();
        let book = listener_book(dd, &me, false, false);
        assert_eq!(book.mode, ListenerMode::Silent);
        assert_eq!(book.keys.len(), 1);
    }

    /// Phase 6 review (traffic-1): a connection whose contact gate takes
    /// verified contacts alone (Internet direct; LAN from beyond the local
    /// network or from an unknown source) tries the pinned contacts alone,
    /// and its automatic mode comes from them; one from the local network
    /// tries every contact.
    #[test]
    fn a_connection_the_gate_takes_verified_contacts_on_tries_them_alone() {
        use raven_core::capability_floor::observe_link;
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let me = Arc::new(Identity::from_seed(&[0x33; 32]));
        let pinned = Identity::from_seed(&[0x34; 32]).public_key_bytes();
        let unpinned = Identity::from_seed(&[0x37; 32]).public_key_bytes();
        std::fs::write(
            dd.join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}"}},{{"pub_hex":"{}","pinned":true}}]"#,
                hex::encode(unpinned),
                hex::encode(pinned)
            ),
        )
        .unwrap();
        let peers = |book: &Book| book.keys.iter().map(|k| k.peer).collect::<Vec<_>>();
        assert_eq!(
            peers(&listener_book(dd, &me, false, false)),
            [pinned, unpinned]
        );
        assert_eq!(peers(&listener_book(dd, &me, false, true)), [pinned]);
        // Only the pinned contact's floor shows the knock: strict for the
        // verified book, legacy for the whole one (the unpinned contact may
        // still pin the derived static).
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(true));
        if security_gate::live(SecGate::Events) {
            observe_link(dd, &pinned, 0, Some(true), 1).unwrap();
            assert_eq!(
                listener_book(dd, &me, false, false).mode,
                ListenerMode::Legacy
            );
            assert_eq!(
                listener_book(dd, &me, false, true).mode,
                ListenerMode::Strict
            );
        }
        security_gate::set_lab_for_this_thread(SecGate::Events, None);
        let _on = KnockForTest::set(true);
        if !live() {
            return;
        }
        let scope = |source: [u8; 4], carrier| {
            let ip = Some(IpAddr::from(source));
            Ear::of(dd, &me, ip, carrier).unwrap().pinned_only()
        };
        assert!(!scope([192, 168, 1, 20], OutboxCarrier::Lan));
        assert!(!scope([127, 0, 0, 1], OutboxCarrier::Lan));
        assert!(scope([100, 64, 0, 1], OutboxCarrier::Lan), "CGNAT");
        assert!(scope([203, 0, 113, 9], OutboxCarrier::Lan));
        assert!(scope([192, 168, 1, 20], OutboxCarrier::Internet));
        let unknown = Ear::of(dd, &me, None, OutboxCarrier::Lan).unwrap();
        assert!(unknown.pinned_only(), "an unknown source counts as remote");
    }

    /// P6.38: while pair seeds are live a listener's book holds a contact's
    /// key sets. A knock made with the pair's seed matches the seed's set;
    /// one made with the root still matches (the fallback: no lockout) and
    /// is `SEC_PAIR_SEED_ROOT`, since the seed was expected; a dial knocks
    /// with the seed. Shut, the book holds the root's set alone.
    #[tokio::test]
    async fn pair_seeds_knock_with_the_seed_and_fall_back_to_the_root() {
        use raven_core::pair_seed::{incoming, is_leader, outgoing, pair_key, SeedEntry};
        use raven_core::security_events::{Attribution, SecKind};
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let me = Arc::new(Identity::from_seed(&[0x35; 32]));
        let friend = Identity::from_seed(&[0x36; 32]);
        let (mine, theirs) = (me.public_key_bytes(), friend.public_key_bytes());
        std::fs::write(
            dd.join("contacts.json"),
            format!(r#"[{{"pub_hex":"{}","pinned":true}}]"#, hex::encode(theirs)),
        )
        .unwrap();
        let seed = [0x38; 32];
        if is_leader(&mine, &theirs) {
            outgoing(dd, &mine, &theirs, 1, || seed).unwrap();
        }
        incoming(dd, &mine, &theirs, Some(&SeedEntry::new(1, seed, 1)), 1).unwrap();
        let root = raven_core::lan_beacon::pair_root(&friend, &mine).unwrap();
        let k_pair = pair_key(&root, &seed);
        assert_eq!(
            listener_book(dd, &me, false, false).keys.len(),
            1,
            "shut: the root"
        );
        let book = listener_book(dd, &me, true, false);
        assert_eq!(book.keys.len(), 2);
        assert!(book.uses[0].send && !book.uses[0].notice);
        assert!(!book.uses[1].send && book.uses[1].notice);
        // The friend's knocks, as the friend makes them.
        let day = rlk::day_of(raven_core::clock::now_ms());
        let e = [0x42; 32];
        let knock = |r: &[u8; 32], n: u8| {
            let keys = rlk::knock_keys_from(&theirs, &mine, r);
            [
                e.as_slice(),
                &rlk::m1_payload_with(&keys, day, &e, &[n; 16], &[]),
            ]
            .concat()
        };
        let seeded = rlk::match_m1(&book.keys, &knock(&k_pair, 1), day).unwrap();
        assert_eq!((seeded.index, seeded.peer), (0, theirs));
        let fallback = rlk::match_m1(&book.keys, &knock(&root, 2), day).unwrap();
        assert_eq!((fallback.index, fallback.peer), (1, theirs));
        // A dial knocks with the seed: the friend's seeded book matches it,
        // the root's alone does not.
        let dial = for_dial(true, true, dd, &me, &theirs)
            .unwrap()
            .begin(&me, None)
            .unwrap();
        let friend_seeded = [rlk::knock_keys_from(&theirs, &mine, &k_pair)];
        let friend_root = [rlk::knock_keys(&friend, &mine).unwrap()];
        assert!(rlk::match_m1(&friend_seeded, dial.m1(), day).is_some());
        assert!(rlk::match_m1(&friend_root, dial.m1(), day).is_none());
        let plain = for_dial(true, false, dd, &me, &theirs)
            .unwrap()
            .begin(&me, None)
            .unwrap();
        assert!(rlk::match_m1(&friend_root, plain.m1(), day).is_some());
        // Heard by the listener: the root's knock is the Notice.
        let _on = KnockForTest::set(true);
        let _seeds = crate::pair_seed::SeedsForTest::set(true);
        if !live() {
            return;
        }
        let Some(capture) = crate::security::tests::Capture::start() else {
            return;
        };
        let ear = Ear::of(dd, &me, None, OutboxCarrier::Lan).unwrap();
        let (_, knocked) = hear(&ear, &knock(&k_pair, 3)).await.unwrap();
        assert_eq!(knocked, Knocked::Contact(theirs));
        assert!(capture.events().is_empty());
        let (_, knocked) = hear(&ear, &knock(&root, 4)).await.unwrap();
        assert_eq!(knocked, Knocked::Contact(theirs));
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::PairSeedRoot,
                Attribution::Contact { peer: theirs },
                Via::DirectLink(OutboxCarrier::Lan),
            )]
        );
    }

    /// Phase 6 review (traffic-9): a recorded knock sent again after the
    /// listener restarted is still a replay. The nonce of a match is kept in
    /// the profile before the knock is answered, and a process that starts
    /// reads it back: the second hearing is no match (`Knocked::Stranger`)
    /// and `SEC_KNOCK_REPLAY` about its source.
    #[tokio::test]
    async fn a_knock_replayed_after_a_restart_is_still_a_replay() {
        use raven_core::security_events::SecKind;
        let _on = KnockForTest::set(true);
        if !live() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let me = Arc::new(Identity::from_seed(&[0x45; 32]));
        let friend = Identity::from_seed(&[0x46; 32]);
        std::fs::write(
            dd.join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","pinned":true}}]"#,
                hex::encode(friend.public_key_bytes())
            ),
        )
        .unwrap();
        let mine = me.public_key_bytes();
        let day = rlk::day_of(raven_core::clock::now_ms());
        let e = [0x47; 32];
        let keys = rlk::knock_keys(&friend, &mine).unwrap();
        let m1 = [
            e.as_slice(),
            &rlk::m1_payload_with(&keys, day, &e, &[9; 16], &[]),
        ]
        .concat();
        let source = Some(IpAddr::from([192, 168, 1, 30]));
        let ear = Ear::of(dd, &me, source, OutboxCarrier::Lan).unwrap();
        let (_, knocked) = hear(&ear, &m1).await.unwrap();
        assert_eq!(knocked, Knocked::Contact(friend.public_key_bytes()));
        assert!(
            dd.join(rlk::KNOCK_REPLAYS_FILE).is_file(),
            "kept in the profile"
        );
        // raven-node starts again: nothing in memory.
        *lock(&REPLAYS) = None;
        let capture = crate::security::tests::Capture::start();
        let (_, knocked) = hear(&ear, &m1).await.unwrap();
        assert_eq!(knocked, Knocked::Stranger, "a replay is no match");
        if let Some(c) = capture {
            assert_eq!(
                c.kinds().into_iter().map(|(k, _, _)| k).collect::<Vec<_>>(),
                [SecKind::KnockReplay]
            );
        }
    }

    /// Only the LAN and Internet direct listeners read knocks, and only
    /// while the knock is live; p2p and nearby never do.
    #[test]
    fn only_lan_and_internet_direct_listeners_read_knocks() {
        let dir = tempfile::tempdir().unwrap();
        let me = Arc::new(Identity::from_seed(&[0x43; 32]));
        let peer = Identity::from_seed(&[0x44; 32]).public_key_bytes();
        let carriers = [
            OutboxCarrier::Lan,
            OutboxCarrier::Internet,
            OutboxCarrier::P2p,
            OutboxCarrier::Nearby,
        ];
        {
            let _off = KnockForTest::set(false);
            for carrier in carriers {
                assert!(Ear::of(dir.path(), &me, None, carrier).is_none());
            }
            assert!(for_dial(live(), false, dir.path(), &me, &peer).is_none());
        }
        let _on = KnockForTest::set(true);
        if !live() {
            return;
        }
        for carrier in carriers {
            assert_eq!(
                Ear::of(dir.path(), &me, None, carrier).is_some(),
                matches!(carrier, OutboxCarrier::Lan | OutboxCarrier::Internet),
                "{carrier:?}"
            );
        }
        let knock = for_dial(true, false, dir.path(), &me, &peer).expect("a contact's keys");
        assert!(!knock.floor, "no floor yet");
        assert!(for_dial(true, false, dir.path(), &me, &me.public_key_bytes()).is_none());
    }

    /// `RAVEN_LAB_LINK_KNOCK` (with `RAVEN_LAB_TEST_A`) is inert in a
    /// release build: no listener reads a knock and no dial knocks (the
    /// release test job sets every switch and runs this; a debug build
    /// returns early).
    #[test]
    fn link_knock_lab_switch_is_inert_in_release() {
        if cfg!(debug_assertions) {
            return;
        }
        const { assert!(!raven_core::security_gate::LINK_KNOCK_PRODUCTION_ENABLED) };
        assert!(!live());
        let _on = KnockForTest::set(true);
        assert!(!live());
        let dir = tempfile::tempdir().unwrap();
        let me = Arc::new(Identity::from_seed(&[0x41; 32]));
        let peer = Identity::from_seed(&[0x42; 32]).public_key_bytes();
        assert!(Ear::of(dir.path(), &me, None, OutboxCarrier::Lan).is_none());
        assert!(for_dial(live(), false, dir.path(), &me, &peer).is_none());
    }
}
