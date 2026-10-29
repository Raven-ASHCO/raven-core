//! The capability high-water mark per contact (`docs/roadmap/plans/phase6-design.json`,
//! step P6.29; design A R9, owner decisions OD6b-7 and OD6b-29): the best a
//! contact's Raven ever offered, so an offer that is worse later is seen.
//!
//! - **Link features** (route hints, update exchange, padding, the link
//!   knock). Every link with a contact raises the mark: a verified hello's
//!   caps (Internet, p2p) are complete and signed by the contact
//!   ([`observe_link`]); what a LAN link happened to show only ever raises
//!   it ([`observe_link_seen`]). A complete showing without a feature seen
//!   before is a downgrade: route hints or update exchange missing is a
//!   Notice, padding or the knock missing is Suspicious. The link goes on
//!   exactly as before: link features are recorded and shown, never refused
//!   (a friend who reinstalled an older build must still reach you). The
//!   RLK1 knock (P6.35) is a complete showing on any LAN or Internet direct
//!   link while this node's knock gate is live (`Some`), seen-only links
//!   included; p2p and nearby links cannot carry it (`None`). A knocking
//!   dialer reads the mark ([`has_knock`]) to stop before message 3 when
//!   such a contact's address answers without a proof, and a listener in
//!   automatic mode turns strict once every contact has it ([`all_knock`]).
//!   While a security notice holds padding or the knock on this node
//!   (P6.45), its marks leave that feature out: nothing raises it and no
//!   showing lacks it (Phase 6 review traffic-4,
//!   `docs/design/2026-10-suite-retirement.md` §6.4). PAD1 runs only when
//!   both sides offer it, so while padding is not live on this node (its
//!   gate shut, or held) a showing without it is no downgrade either; the
//!   mark still rises with what a contact shows (Phase 6 review sensing-3).
//! - **Session profiles** ([`observe_profile`], [`require_profile`]). The
//!   highest profile a verified bundle or a confirmed session showed is the
//!   contact's floor. An offer whose best common profile is below it is an
//!   Alert, and refused once [`SecGate::SuiteFloor`] is live: no new session
//!   at the lower level, existing sessions untouched. Only profile 1
//!   (indexed-session v1) exists today, so nothing changes yet.
//! - **The next profile plugs in** ([`NextProfile`], step P6.50; design D
//!   §8, OD6b-29): the HR v2 or HR3 program implements the trait and calls
//!   [`bundle_verified`], [`session_confirmed`] and [`choose_profile`], which
//!   add the applied security notice ([`crate::suite_policy`]) to the floor:
//!   the highest profile in common that no notice marks BROKEN, a warning
//!   while the one used is being retired (DEPRECATED). This build has no
//!   next profile, so nothing calls them yet; the contract is tested with a
//!   mock profile, and the procedure is
//!   `docs/design/2026-10-suite-retirement.md`.
//! - **Never lowered automatically.** Only the person lowers a mark, after
//!   comparing security words with the contact ([`CodeMatch`], which
//!   `raven contact verify` makes from the words typed) and typing `accept`
//!   ([`lower_floor`]). Removing the contact forgets its mark ([`forget`]).
//!
//! Recording runs only while [`SecGate::Events`] is live (a release build
//! records nothing); refusing needs [`SecGate::SuiteFloor`] too. A downgrade
//! is noted (`SEC_CAPABILITY_DOWNGRADE`, at the missing feature's level) at
//! most once a day per contact and feature.
//!
//! The marks are kept in [`CAPABILITY_FLOOR_FILE`], keyed by the contact's
//! identity key, under their own lock ([`CAPABILITY_FLOOR_LOCK`]). They name
//! contacts, so the file is RMS1 kind 11 in a sealed profile
//! (`at_rest::FILES`) and plain JSON (0600) in a plain one, sealed by the
//! migration with the rest. An advisory file: one this process cannot read
//! reads as empty and is never written over. At most [`MAX_FLOORS`]
//! contacts are kept.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::at_rest::{self, Advisory, Kind};
use crate::clock::now_ms;
use crate::security_events::{Attribution, SecEvent, SecKind, Severity, Via};
use crate::security_gate::{self, SecGate};
use crate::security_words::{self, Verdict};
use crate::suite_policy::{self, Status};
use crate::CAP_LINK_RRH1;

/// The file, in the profile folder.
pub const CAPABILITY_FLOOR_FILE: &str = "capability_floor.json";
/// Every writer of [`CAPABILITY_FLOOR_FILE`] takes it (`at_rest::FILES`).
pub const CAPABILITY_FLOOR_LOCK: &str = ".at_rest.capability_floor.lock.sqlite";
/// Contacts with a mark at most: past it, the one set longest ago goes.
pub const MAX_FLOORS: usize = 4_096;

/// Session profile 1: ATSAM indexed-session v1, the only one today.
pub const PROFILE_INDEXED_SESSION_V1: u8 = 1;
/// The session profiles this build speaks, lowest first.
pub const PROFILES: &[u8] = &[PROFILE_INDEXED_SESSION_V1];

/// The RIH1/RLX1 caps bits of PAD1 link padding (design B, bit 9) and of
/// RUP1 update exchange (design D, bit 10, which no build sends yet), defined
/// with the rest of the caps namespace in [`crate::internet`].
pub use crate::internet::{CAP_LINK_PAD1, CAP_LINK_RUP1};
/// The link feature bits of the hello caps namespace (bit 8 up; bits 0-7
/// say what a node is, not what a link carries).
pub const LINK_FEATURE_BITS: u32 = !0xFF;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Days since the Unix epoch: the only time a mark keeps.
fn day_of(now_ms: u64) -> u32 {
    u32::try_from(now_ms / DAY_MS).unwrap_or(u32::MAX)
}

/// What can go missing, in order of how serious its loss is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// RRH1 route hints (caps bit 8).
    RouteHints,
    /// RUP1 update exchange (design D).
    UpdateExchange,
    /// PAD1 link padding (design B).
    Padding,
    /// The RLK1 link knock (design B).
    Knock,
    /// A session profile at or above the floor.
    SessionProfile,
}

impl Feature {
    pub const ALL: [Feature; 5] = [
        Feature::RouteHints,
        Feature::UpdateExchange,
        Feature::Padding,
        Feature::Knock,
        Feature::SessionProfile,
    ];

    /// How serious its loss is (`docs/SECURITY_EVENTS.md`, kind 30): route
    /// hints and update exchange only cost reachability, padding and the
    /// knock hide traffic and identity, a lower session profile protects
    /// messages less.
    pub fn severity(self) -> Severity {
        match self {
            Feature::RouteHints | Feature::UpdateExchange => Severity::Notice,
            Feature::Padding | Feature::Knock => Severity::Suspicious,
            Feature::SessionProfile => Severity::Alert,
        }
    }

    /// A stable name (tests, `--json` later).
    pub fn name(self) -> &'static str {
        match self {
            Feature::RouteHints => "route_hints",
            Feature::UpdateExchange => "update_exchange",
            Feature::Padding => "padding",
            Feature::Knock => "knock",
            Feature::SessionProfile => "session_profile",
        }
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

fn bits(features: &[Feature]) -> u8 {
    features.iter().fold(0, |acc, f| acc | f.bit())
}

/// What raised a mark last.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetBy {
    /// A link's features.
    #[default]
    Link,
    /// A verified prekey bundle's profile set.
    Bundle,
    /// A confirmed session.
    Session,
    /// The person lowered it after comparing security words ([`lower_floor`]).
    User,
    /// A newer build's reason.
    #[serde(other)]
    Other,
}

/// One contact's mark.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Floor {
    /// Every link feature bit a link showed ([`LINK_FEATURE_BITS`]).
    pub link_caps_max: u32,
    /// A link knock was seen.
    pub knock: bool,
    /// Padding was seen (its caps bit, or a padding frame). Kept apart from
    /// `link_caps_max` so a feature seen as a frame counts like its bit.
    pub pad1: bool,
    /// Update exchange was seen (its caps bit, or a RUP1 HAVE).
    pub rup1: bool,
    /// The lowest session profile a new session may use
    /// ([`PROFILE_INDEXED_SESSION_V1`] until a higher one is seen).
    pub profile_floor: u8,
    pub set_by: SetBy,
    /// The day ([`day_of`]) the mark was last raised or lowered.
    pub at_day: u32,
    /// Downgrades noted since the mark was last lowered ([`Feature`] bits).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub open: u8,
    /// The best profile an offer below the floor held, until the floor is
    /// lowered or an offer reaches it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_profile: Option<u8>,
    /// The last day a downgrade was noted, and what was noted that day (one
    /// note per contact, feature and day).
    #[serde(default, skip_serializing_if = "is_zero_day")]
    pub noted_day: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub noted: u8,
}

fn is_zero(v: &u8) -> bool {
    *v == 0
}

fn is_zero_day(v: &u32) -> bool {
    *v == 0
}

impl Floor {
    /// A contact nothing was seen of yet, on `day`.
    pub fn new(day: u32) -> Self {
        Self {
            link_caps_max: 0,
            knock: false,
            pad1: false,
            rup1: false,
            profile_floor: PROFILE_INDEXED_SESSION_V1,
            set_by: SetBy::Link,
            at_day: day,
            open: 0,
            refused_profile: None,
            noted_day: 0,
            noted: 0,
        }
    }

    /// The link features seen before that a complete showing of `caps`
    /// (and `knock`) lacks, in [`Feature`] order. `knock`: whether the link
    /// carried the knock, `None` when it could not tell (a carrier without
    /// the knock, or this node's knock gate shut): never missing then.
    pub fn missing(&self, caps: u32, knock: Option<bool>) -> Vec<Feature> {
        Feature::ALL
            .into_iter()
            .filter(|f| match f {
                Feature::RouteHints => {
                    self.link_caps_max & CAP_LINK_RRH1 != 0 && caps & CAP_LINK_RRH1 == 0
                }
                Feature::UpdateExchange => self.rup1 && caps & CAP_LINK_RUP1 == 0,
                Feature::Padding => self.pad1 && caps & CAP_LINK_PAD1 == 0,
                Feature::Knock => self.knock_missing(knock),
                Feature::SessionProfile => false,
            })
            .collect()
    }

    /// A link that could tell showed no knock although one was seen before.
    fn knock_missing(&self, knock: Option<bool>) -> bool {
        self.knock && knock == Some(false)
    }

    /// Raise the link part by what a link showed (never lowers).
    fn raise_link(&mut self, caps: u32, knock: Option<bool>, day: u32) {
        let before = (self.link_caps_max, self.knock, self.pad1, self.rup1);
        let caps = caps & LINK_FEATURE_BITS;
        self.link_caps_max |= caps;
        self.pad1 |= caps & CAP_LINK_PAD1 != 0;
        self.rup1 |= caps & CAP_LINK_RUP1 != 0;
        self.knock |= knock == Some(true);
        if before != (self.link_caps_max, self.knock, self.pad1, self.rup1) {
            self.set_by = SetBy::Link;
            self.at_day = day;
        }
    }

    /// `missing` went missing on `day`: kept open, and whether to note it
    /// now (not when all of it was noted that day already).
    fn note(&mut self, missing: &[Feature], day: u32) -> bool {
        let bits = bits(missing);
        self.open |= bits;
        if self.noted_day == day && bits & !self.noted == 0 {
            return false;
        }
        if self.noted_day != day {
            self.noted_day = day;
            self.noted = 0;
        }
        self.noted |= bits;
        true
    }

    /// The downgrades noted since the mark was last lowered.
    pub fn open_features(&self) -> Vec<Feature> {
        Feature::ALL
            .into_iter()
            .filter(|f| self.open & f.bit() != 0)
            .collect()
    }

    /// Something worth the person's decision is open: a session profile
    /// below the floor, or padding or the knock gone (Suspicious and up).
    /// `raven contact verify` offers to lower the mark only then.
    pub fn open_downgrade(&self) -> bool {
        self.refused_profile.is_some()
            || self
                .open_features()
                .iter()
                .any(|f| f.severity() >= Severity::Suspicious)
    }
}

/// What an offer lacked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Downgrade {
    /// Link features seen before and missing now: shown, never refused.
    Link(Vec<Feature>),
    /// The best session profile offered in common is below the floor.
    Profile { floor: u8, best: u8 },
    /// No profile offered is one this build speaks: nothing to choose, and
    /// no downgrade either (a newer build may have retired one).
    NoCommonProfile,
}

impl Downgrade {
    /// Its level as a `SEC_CAPABILITY_DOWNGRADE`; `None` when it is no
    /// security event ([`Downgrade::NoCommonProfile`]).
    pub fn severity(&self) -> Option<Severity> {
        match self {
            Downgrade::Link(missing) => missing.iter().map(|f| f.severity()).max(),
            Downgrade::Profile { .. } => Some(Feature::SessionProfile.severity()),
            Downgrade::NoCommonProfile => None,
        }
    }

    /// The event this is about the contact `peer` (reached `via`), and its
    /// level: what [`note`] notes and raven-node hands its own sink.
    pub fn event(&self, peer: &[u8; 32], via: Via, at_ms: u64) -> Option<(SecEvent, Severity)> {
        let severity = self.severity()?;
        let ev = SecEvent::new(
            SecKind::CapabilityDowngrade,
            Attribution::Contact { peer: *peer },
            via,
            at_ms,
        );
        Some((ev, severity))
    }
}

/// Note `down` about the contact `peer`, at its level (raven-core and ash
/// callers; nothing while the events gate is shut).
pub fn note(down: &Downgrade, peer: &[u8; 32], via: Via) {
    if !crate::security_sense::live() {
        return;
    }
    if let Some((ev, severity)) = down.event(peer, via, now_ms()) {
        crate::security_sense::note_at_least(ev, severity);
    }
}

/// Proof that the person just compared security words with a contact and
/// they matched: what [`lower_floor`] takes, and only `raven contact verify`
/// makes one (a source scan checks it). Neither `Clone` nor `Default`: each
/// lowering needs its own match.
#[derive(Debug)]
pub struct CodeMatch {
    peer: [u8; 32],
}

impl CodeMatch {
    /// `typed` are the contact's 10 security words (the old code is not
    /// enough to lower a floor).
    pub fn check(typed: &str, peer: &[u8; 32]) -> Option<Self> {
        matches!(security_words::compare(typed, peer), Verdict::Match)
            .then_some(Self { peer: *peer })
    }

    /// The contact the words matched.
    pub fn peer(&self) -> &[u8; 32] {
        &self.peer
    }
}

/// The file's contents.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Book {
    /// Marks by the contact's identity key (lowercase hex).
    #[serde(default)]
    floors: BTreeMap<String, Floor>,
}

impl Book {
    /// Past [`MAX_FLOORS`], drop the marks set longest ago (never `keep`).
    fn bound(&mut self, keep: &str) {
        while self.floors.len() > MAX_FLOORS {
            let oldest = self
                .floors
                .iter()
                .filter(|(key, _)| key.as_str() != keep)
                .min_by_key(|(key, floor)| (floor.at_day, key.as_str()))
                .map(|(key, _)| key.clone());
            match oldest {
                Some(key) => self.floors.remove(&key),
                None => break,
            };
        }
    }
}

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(CAPABILITY_FLOOR_FILE)
}

fn key(peer: &[u8; 32]) -> String {
    hex::encode(peer)
}

/// The marks; empty for a missing file or plain bytes that do not parse,
/// an error for a file this process cannot read.
fn read(data_dir: &Path) -> Result<Book, String> {
    match at_rest::load_json_advisory::<Book>(data_dir, &path(data_dir), Kind::CapabilityFloor) {
        Advisory::Missing | Advisory::CorruptPlain => Ok(Book::default()),
        Advisory::Loaded(book) => Ok(book),
        Advisory::Unreadable(e) => Err(format!("{CAPABILITY_FLOOR_FILE}: {e}")),
    }
}

/// Change `peer`'s mark (a new one when there is none): `edit` returns what
/// the caller gets, and the file is written only when the mark changed. A
/// read without the lock comes first, since most links change nothing.
fn change<R>(
    data_dir: &Path,
    peer: &[u8; 32],
    day: u32,
    edit: impl Fn(&mut Floor) -> R,
) -> Result<R, String> {
    let k = key(peer);
    let edited = |book: &mut Book| {
        let before = book
            .floors
            .get(&k)
            .cloned()
            .unwrap_or_else(|| Floor::new(day));
        let mut floor = before.clone();
        let out = edit(&mut floor);
        let changed = floor != before;
        if changed {
            book.floors.insert(k.clone(), floor);
        }
        (out, changed)
    };
    let (out, changed) = edited(&mut read(data_dir)?);
    if !changed {
        return Ok(out);
    }
    let path = path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::CapabilityFloor)
        .map_err(|e| format!("{CAPABILITY_FLOOR_FILE}: {e}"))?;
    let mut book: Book = at_rest::load_json_for_write(data_dir, &path, Kind::CapabilityFloor)
        .map_err(|e| format!("{CAPABILITY_FLOOR_FILE}: {e}"))?;
    let (out, changed) = edited(&mut book);
    if !changed {
        return Ok(out);
    }
    book.bound(&k);
    lock.store_json(&book)
        .map_err(|e| format!("{CAPABILITY_FLOOR_FILE}: {e}"))?;
    Ok(out)
}

/// `peer`'s mark, if it has one (and the file can be read).
pub fn floor(data_dir: &Path, peer: &[u8; 32]) -> Option<Floor> {
    read(data_dir).ok()?.floors.remove(&key(peer))
}

/// The link features a security notice holds on this node (P6.45: a
/// `FEATURE_HOLD` BROKEN on `feature/link-padding` or `feature/link-knock`,
/// or a BROKEN `pad1/1` or `rlk1/1`; none while the advisory gate is shut).
/// This node cannot tell about them then: its own links lack them, and so
/// do those of every contact that applied the same notice, so a showing
/// without them is no downgrade, and one with them raises nothing (Phase 6
/// review traffic-4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Held {
    padding: bool,
    knock: bool,
}

impl Held {
    fn now() -> Self {
        use crate::suite_registry::{FEATURE_LINK_KNOCK, FEATURE_LINK_PADDING};
        Self {
            padding: !suite_policy::hold_allows(FEATURE_LINK_PADDING),
            knock: !suite_policy::hold_allows(FEATURE_LINK_KNOCK),
        }
    }

    /// A showing of `caps` and `knock` as the mark takes it: what is held
    /// neither raises it nor goes missing (the knock: cannot tell).
    fn showing(self, caps: u32, knock: Option<bool>) -> (u32, Option<bool>) {
        let caps = if self.padding {
            caps & !CAP_LINK_PAD1
        } else {
            caps
        };
        (caps, knock.filter(|_| !self.knock))
    }

    /// `missing` without what is held.
    fn keep(self, missing: Vec<Feature>) -> Vec<Feature> {
        missing
            .into_iter()
            .filter(|f| match f {
                Feature::Padding => !self.padding,
                Feature::Knock => !self.knock,
                _ => true,
            })
            .collect()
    }
}

/// A link with the contact `peer` showed all its features (a verified
/// hello's `caps`; `knock`: the link carried the RLK1 knock, `None` when it
/// could not tell): the mark is raised, and a feature seen before that is
/// missing now comes back as the downgrade to note (`None` when it was noted
/// today already). The link is never refused. A link feature a security
/// notice holds on this node is left out ([`Held`]), and padding is never
/// missing while it is not live here ([`SecGate::LinkPadding`]: PAD1 needs
/// both sides, so this node loses nothing when a contact stops offering
/// it; Phase 6 review sensing-3). Nothing while the events gate is shut.
pub fn observe_link(
    data_dir: &Path,
    peer: &[u8; 32],
    caps: u32,
    knock: Option<bool>,
    now_ms: u64,
) -> Result<Option<Downgrade>, String> {
    if !security_gate::live(SecGate::Events) {
        return Ok(None);
    }
    let day = day_of(now_ms);
    let held = Held::now();
    let padding_here = security_gate::live(SecGate::LinkPadding);
    let (shown, knock) = held.showing(caps, knock);
    change(data_dir, peer, day, |floor| {
        let mut missing = held.keep(floor.missing(caps, knock));
        missing.retain(|f| padding_here || *f != Feature::Padding);
        floor.raise_link(shown, knock, day);
        let noted = !missing.is_empty() && floor.note(&missing, day);
        noted.then_some(Downgrade::Link(missing))
    })
}

/// A link showed some of `peer`'s `caps`, not necessarily all (a LAN
/// dialer's message 3 asks for RRH1 only on a dial that reads; a listener's
/// RRH1 depends on what it sends that contact): the mark is raised, and no
/// caps bit missing is a downgrade. The knock is different: a link that can
/// carry it always shows whether it did (`knock`: `Some`), so a knock seen
/// before and missing now is the downgrade to note, as in [`observe_link`].
/// A link feature a security notice holds on this node is left out
/// ([`Held`]). Nothing while the events gate is shut.
pub fn observe_link_seen(
    data_dir: &Path,
    peer: &[u8; 32],
    caps: u32,
    knock: Option<bool>,
    now_ms: u64,
) -> Result<Option<Downgrade>, String> {
    if !security_gate::live(SecGate::Events) {
        return Ok(None);
    }
    let day = day_of(now_ms);
    let (caps, knock) = Held::now().showing(caps, knock);
    change(data_dir, peer, day, |floor| {
        let missing = if floor.knock_missing(knock) {
            vec![Feature::Knock]
        } else {
            Vec::new()
        };
        floor.raise_link(caps, knock, day);
        let noted = !missing.is_empty() && floor.note(&missing, day);
        noted.then_some(Downgrade::Link(missing))
    })
}

/// Does every contact of `peers` have the knock in its mark (RLK1's
/// automatic strict mode)? One read of the file; an empty list is `true`,
/// a file that cannot be read `false` (legacy: nobody's older pin breaks).
pub fn all_knock(data_dir: &Path, peers: &[[u8; 32]]) -> bool {
    let Ok(book) = read(data_dir) else {
        return false;
    };
    peers
        .iter()
        .all(|peer| book.floors.get(&key(peer)).is_some_and(|floor| floor.knock))
}

/// Does `peer`'s mark show the knock (a knocking dialer stops before
/// message 3 when such a contact answers without a proof)? A missing or
/// unreadable file is no.
pub fn has_knock(data_dir: &Path, peer: &[u8; 32]) -> bool {
    floor(data_dir, peer).is_some_and(|floor| floor.knock)
}

/// A verified bundle or a confirmed session (`how`) showed `peer` speaks
/// session profile `profile`: the floor rises to it (never down), and an
/// earlier refusal it answers is closed. A profile this build does not speak
/// is no floor it could keep. Nothing while the events gate is shut.
pub fn observe_profile(
    data_dir: &Path,
    peer: &[u8; 32],
    profile: u8,
    how: SetBy,
    now_ms: u64,
) -> Result<(), String> {
    observe_profile_in(data_dir, peer, PROFILES, profile, how, now_ms)
}

/// [`observe_profile`] for a build that speaks `ours` (tests: a mock
/// profile set).
fn observe_profile_in(
    data_dir: &Path,
    peer: &[u8; 32],
    ours: &[u8],
    profile: u8,
    how: SetBy,
    now_ms: u64,
) -> Result<(), String> {
    if !security_gate::live(SecGate::Events) || !ours.contains(&profile) {
        return Ok(());
    }
    let day = day_of(now_ms);
    change(data_dir, peer, day, |floor| {
        if profile > floor.profile_floor {
            floor.profile_floor = profile;
            floor.set_by = how;
            floor.at_day = day;
        }
        if profile >= floor.profile_floor {
            floor.refused_profile = None;
            floor.open &= !Feature::SessionProfile.bit();
        }
    })
}

/// The session profile to use with `peer` from those it `offered` (reached
/// `via`): the highest one in common, as long as it is not below `peer`'s
/// floor. Below it, the downgrade is noted as an Alert and kept open for
/// `raven contact verify`; the offer is refused only while
/// [`SecGate::SuiteFloor`] is live (otherwise the best common profile is
/// used, as before). The highest profile this build speaks never needs the
/// file. While the suite floor is live, a floor that cannot be read refuses
/// anything below that highest profile (fail closed). No profile in common
/// is [`Downgrade::NoCommonProfile`] whatever the gates.
pub fn require_profile(
    data_dir: &Path,
    peer: &[u8; 32],
    offered: &[u8],
    via: Via,
) -> Result<u8, Downgrade> {
    require_profile_in(data_dir, peer, PROFILES, offered, via, now_ms())
}

/// [`require_profile`] for a build that speaks `ours` (tests: a mock
/// profile set), at `now_ms`.
fn require_profile_in(
    data_dir: &Path,
    peer: &[u8; 32],
    ours: &[u8],
    offered: &[u8],
    via: Via,
    now_ms: u64,
) -> Result<u8, Downgrade> {
    let best = ours
        .iter()
        .copied()
        .filter(|p| offered.contains(p))
        .max()
        .ok_or(Downgrade::NoCommonProfile)?;
    let ours_max = ours.iter().copied().max().unwrap_or(best);
    if !security_gate::live(SecGate::Events) || best >= ours_max {
        return Ok(best);
    }
    let enforce = security_gate::live(SecGate::SuiteFloor);
    let floor = match read(data_dir) {
        Ok(mut book) => book
            .floors
            .remove(&key(peer))
            .map_or(PROFILE_INDEXED_SESSION_V1, |f| f.profile_floor),
        Err(_) if enforce => {
            return Err(Downgrade::Profile {
                floor: ours_max,
                best,
            })
        }
        Err(_) => return Ok(best),
    };
    if best >= floor {
        return Ok(best);
    }
    let down = Downgrade::Profile { floor, best };
    let day = day_of(now_ms);
    let noted = change(data_dir, peer, day, |f| {
        f.refused_profile = Some(best);
        f.note(&[Feature::SessionProfile], day)
    })
    // A refusal that could not be kept is still noted.
    .unwrap_or(true);
    if noted {
        note(&down, peer, via);
    }
    if enforce {
        Err(down)
    } else {
        Ok(best)
    }
}

/// The person compared security words with the contact and typed `accept`
/// (`raven contact verify`, and the terminal app's "Check again"): its mark
/// starts afresh, as the person accepts what its Raven offers now, and rises
/// again with what later links and sessions show. `Ok(false)`: it had no
/// mark. Works whatever the gates (a decision the person made stays made).
pub fn lower_floor(data_dir: &Path, matched: &CodeMatch, now_ms: u64) -> Result<bool, String> {
    let k = key(matched.peer());
    if !read(data_dir)?.floors.contains_key(&k) {
        return Ok(false);
    }
    let path = path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::CapabilityFloor)
        .map_err(|e| format!("{CAPABILITY_FLOOR_FILE}: {e}"))?;
    let mut book: Book = at_rest::load_json_for_write(data_dir, &path, Kind::CapabilityFloor)
        .map_err(|e| format!("{CAPABILITY_FLOOR_FILE}: {e}"))?;
    let Some(floor) = book.floors.get_mut(&k) else {
        return Ok(false);
    };
    *floor = Floor {
        set_by: SetBy::User,
        ..Floor::new(day_of(now_ms))
    };
    lock.store_json(&book)
        .map_err(|e| format!("{CAPABILITY_FLOOR_FILE}: {e}"))?;
    Ok(true)
}

/// The contact `peer` was removed: its mark goes (a contact added again
/// starts a new one). No write when the file does not name it; a file that
/// cannot be read is an error and stays as it is.
pub fn forget(data_dir: &Path, peer: &[u8; 32]) -> Result<(), String> {
    let k = key(peer);
    let path = path(data_dir);
    match at_rest::load_json_advisory::<Book>(data_dir, &path, Kind::CapabilityFloor) {
        Advisory::Missing | Advisory::CorruptPlain => return Ok(()),
        Advisory::Loaded(book) if !book.floors.contains_key(&k) => return Ok(()),
        Advisory::Loaded(_) | Advisory::Unreadable(_) => {}
    }
    let lock = at_rest::lock_file(data_dir, &path, Kind::CapabilityFloor)
        .map_err(|e| format!("{CAPABILITY_FLOOR_FILE}: {e}"))?;
    let mut book: Book = at_rest::load_json_for_write(data_dir, &path, Kind::CapabilityFloor)
        .map_err(|e| format!("{CAPABILITY_FLOOR_FILE}: {e}"))?;
    if book.floors.remove(&k).is_none() {
        return Ok(());
    }
    lock.store_json(&book)
        .map_err(|e| format!("{CAPABILITY_FLOOR_FILE}: {e}"))
}

// ── The next session profile (P6.50) ─────────────────────────────────

/// What a next session profile implements to plug into the floor (step
/// P6.50; design D §8, OD6b-29): the HR v2 or HR3 program (the ratchet
/// design §5.13, `ATSAM_HYBRID_RATCHET_V2.md` §15), which then calls
/// [`bundle_verified`] for every bundle it verified, [`session_confirmed`]
/// for every session the contact answered under, and [`choose_profile`]
/// before it makes or takes any new session, V1 included. Old peers keep
/// getting V1 bundles and nothing on the wire says which profiles were
/// considered: the bundle's profile set is signed, so there is nothing to
/// strip.
pub trait NextProfile {
    /// A prekey bundle of the contact's that the program verified (its
    /// PrekeyBundleV2: signature, lineage and rollback pin checked).
    type Bundle;
    /// A session in the program's own store.
    type Session;

    /// The profile's id, above [`PROFILE_INDEXED_SESSION_V1`]: one more
    /// than its bit in a bundle's signed `profile_set` (the ratchet design
    /// §5.13: bit 0 indexed-session v1, bit 1 the HR v2 lab, bit 2
    /// hybrid-ratchet v3; HR3 is profile 3).
    fn profile_id(&self) -> u8;

    /// The profiles `bundle`'s signed `profile_set` advertises.
    fn advertised(&self, bundle: &Self::Bundle) -> Vec<u8>;

    /// Whether `session` is confirmed: the contact answered under it, so its
    /// Raven speaks this profile.
    fn confirmed(&self, session: &Self::Session) -> bool;
}

/// The session profiles a build with `next` plugged in speaks, lowest
/// first ([`PROFILES`] and `next`'s; an id at or below them adds nothing).
pub fn profiles_with<P: NextProfile>(next: &P) -> Vec<u8> {
    let mut ours = PROFILES.to_vec();
    let id = next.profile_id();
    if ours.last().is_some_and(|top| id > *top) {
        ours.push(id);
    }
    ours
}

/// The program verified a bundle of `peer`'s: the floor rises to the
/// highest profile it advertises that this build speaks
/// ([`SetBy::Bundle`]; a V1-only bundle raises nothing). Nothing while the
/// events gate is shut.
pub fn bundle_verified<P: NextProfile>(
    data_dir: &Path,
    peer: &[u8; 32],
    next: &P,
    bundle: &P::Bundle,
    now_ms: u64,
) -> Result<(), String> {
    let ours = profiles_with(next);
    let advertised = next.advertised(bundle);
    match ours
        .iter()
        .copied()
        .filter(|p| advertised.contains(p))
        .max()
    {
        Some(best) => observe_profile_in(data_dir, peer, &ours, best, SetBy::Bundle, now_ms),
        None => Ok(()),
    }
}

/// `peer` answered under a session of the program's: once it is confirmed
/// the floor rises to the next profile ([`SetBy::Session`]). Nothing while
/// the events gate is shut.
pub fn session_confirmed<P: NextProfile>(
    data_dir: &Path,
    peer: &[u8; 32],
    next: &P,
    session: &P::Session,
    now_ms: u64,
) -> Result<(), String> {
    if !next.confirmed(session) {
        return Ok(());
    }
    let ours = profiles_with(next);
    observe_profile_in(
        data_dir,
        peer,
        &ours,
        next.profile_id(),
        SetBy::Session,
        now_ms,
    )
}

/// The profile of a new session ([`choose_profile`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choice {
    pub profile: u8,
    /// A security notice is retiring that profile (DEPRECATED) and the
    /// contact offers nothing newer: it is used, and the person is told now
    /// ([`suite_policy::retiring_contact_text`]); once per contact and
    /// notice in this process.
    pub warn: bool,
}

/// Why no new session is made or taken ([`choose_profile`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Below the contact's floor while the suite floor is live, or no
    /// profile in common ([`require_profile`]).
    Floor(Downgrade),
    /// A security notice marks every profile in common BROKEN: the text
    /// ([`suite_policy::SUITE_BROKEN`]).
    Broken(String),
}

/// The profile of a new session with `peer`, either way: `offered` is the
/// verified bundle's profile set (a session this node starts) or the
/// profile of the contact's PairInit (one it takes). The highest profile in
/// common that the applied notice does not mark BROKEN (`pairinit/1/1`,
/// `atsam/indexed-session/v1` or `rvna1/3` for V1); then the floor
/// ([`require_profile`]): a notice never lowers it, so with the profile at
/// the floor BROKEN the contact gets nothing lower either until the person
/// lowers it. While the advisory and events gates are shut this is the
/// highest profile in common, as before.
pub fn choose_profile<P: NextProfile>(
    data_dir: &Path,
    peer: &[u8; 32],
    next: &P,
    offered: &[u8],
    via: Via,
) -> Result<Choice, Refusal> {
    choose_in(data_dir, peer, &profiles_with(next), offered, via, now_ms())
}

/// [`choose_profile`] for a build that speaks `ours`, at `now_ms`.
fn choose_in(
    data_dir: &Path,
    peer: &[u8; 32],
    ours: &[u8],
    offered: &[u8],
    via: Via,
    now_ms: u64,
) -> Result<Choice, Refusal> {
    let policy = suite_policy::applied();
    let refusal = |p: u8| policy.as_ref().and_then(|policy| policy.profile_refusal(p));
    let best = ours
        .iter()
        .copied()
        .filter(|p| offered.contains(p))
        .max()
        .ok_or(Refusal::Floor(Downgrade::NoCommonProfile))?;
    let usable: Vec<u8> = offered
        .iter()
        .copied()
        .filter(|p| refusal(*p).is_none())
        .collect();
    if !ours.iter().any(|p| usable.contains(p)) {
        return Err(Refusal::Broken(refusal(best).unwrap_or_default()));
    }
    let profile =
        require_profile_in(data_dir, peer, ours, &usable, via, now_ms).map_err(Refusal::Floor)?;
    let warn = policy.is_some_and(|policy| {
        policy.profile_status(profile) == Status::Deprecated
            && suite_policy::retiring_warning_due(policy.serial, peer)
    });
    Ok(Choice { profile, warn })
}

#[cfg(test)]
mod tests;
