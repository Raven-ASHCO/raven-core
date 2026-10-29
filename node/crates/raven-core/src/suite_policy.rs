//! Applying security advisories (`docs/roadmap/plans/phase6-design.json`
//! step P6.45; design D §7; RAVEN_SECURITY_ADVISORY_V1 §4 and §8; owner
//! decision OD6b-21): what the advisory this profile accepted
//! ([`crate::update_state`]) refuses, closes and warns about.
//!
//! | Registry id ([`crate::suite_registry`]) | Consulted at | BROKEN means |
//! |---|---|---|
//! | `noise/xx-25519-chachapoly-blake2s`, `rih1/1`, `rlb1/1` | before every link handshake (raven-node: LAN direct, Internet direct, p2p, nearby; [`check_link`]) | no link either way ([`SUITE_BROKEN`]): Raven can't reach anyone until it is updated, and the text says so |
//! | `pairinit/1/1` | creating and accepting a PairInit (`lan_dispatch`, links and letters; [`check_pair_init`]) | no new session either way; sessions already open go on |
//! | `atsam/indexed-session/v1`, `rvna1/3` | sealing and accepting on an indexed session ([`session_allowed`]) | every session held ([`SUITE_HELD`]): this build has no next profile to re-seal under |
//! | the wire modules' ids (`rrh1/1`, ...) | the module's `*_live()` ([`hold_allows`]) | the feature is off |
//! | `feature/<gate>` (`FEATURE_HOLD`) | every `*_live()`, **after** its own gate ([`hold_allows`]) | the feature is off: a hold can only close |
//!
//! DEPRECATED never refuses and INFO says nothing: both only show
//! ([`Policy::lines`]); a new session prefers a newer profile, and one with a
//! contact that offers nothing newer warns once ([`retiring_contact_text`]).
//!
//! **Session profiles** (step P6.50; design D §8): profile 1's status is
//! the worst of `pairinit/1/1`, `atsam/indexed-session/v1` and `rvna1/3`
//! ([`Policy::profile_status`]), what the next-profile choice
//! ([`crate::capability_floor::choose_profile`]) refuses or warns about; a
//! profile the registry does not name yet is allowed (its program adds its
//! ids). Under a BROKEN session profile the V1 sessions already open are
//! held while this build has no next profile and retired for a build that
//! has one ([`v1_sessions`]), so Phase 2a re-seals what waited in them
//! under the next profile. The procedure is
//! `docs/design/2026-10-suite-retirement.md`.
//!
//! A `RELEASE_FLOOR` above this build's serial warns
//! ("This Raven version has a known security problem"); Raven keeps
//! working. A `NOTICE` is shown through
//! [`sanitize_terminal_line`](crate::sanitize::sanitize_terminal_line)
//! (escape sequences and bidirectional controls removed). There is no
//! local override of BROKEN (OD6b-21). An id this build does not have and
//! a kind it does not know are never enforced; a hold on
//! `feature/advisory` is shown and never enforced.
//!
//! **While [`SecGate::Advisory`] is shut** (`ADVISORY_PRODUCTION_ENABLED =
//! false`) every check here answers at once: [`status`] is always
//! [`Status::Allowed`] and [`hold_allows`] always `true`, so no build
//! changes behaviour before the flip.
//!
//! **Where the policy comes from.** A process names its profile once
//! ([`attach`]: raven-node at start, ash for its `--data-dir`); the policy
//! of the advisory stored there is cached in memory and read again when the
//! state file's stamp (length and modification time) changes, looked at at
//! most once a second ([`RECHECK`]), and at once after this process wrote
//! the state. A state that cannot be read (a sealed one before the at-rest
//! key is here) keeps the policy read before (none at start) and is tried
//! again a second later: until the key is here raven-node admits and dials
//! nobody anyway. A process that attached nothing has no policy. A freeze
//! (equivocation, split view) keeps the stored advisory's policy: nothing
//! new is applied, nothing is lifted.
//!
//! Every gate function calls in here, so nothing here takes a lock while it
//! reads the file, and a gate check made while this thread reads it gets
//! the cached policy.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use crate::advisory::{Advisory, Entry, EntryKind, Severity};
use crate::capability_floor::PROFILE_INDEXED_SESSION_V1;
use crate::sanitize::sanitize_terminal_line;
use crate::security_gate::{self, SecGate};
use crate::suite_registry::{self, Layer};
use crate::update_state::{self, Refused, UpdateState};

/// Local refusal code (RAVEN_ERROR_CODES_V1 §2): a security notice marks a
/// link suite or PairInit version 1 BROKEN.
pub const SUITE_BROKEN: &str = "SUITE_BROKEN";
/// Local refusal code (RAVEN_ERROR_CODES_V1 §2): a security notice marks the
/// session profile BROKEN, and the session is held.
pub const SUITE_HELD: &str = "SUITE_HELD";

/// How often the state file's stamp is looked at, at most.
pub const RECHECK: Duration = Duration::from_secs(1);

/// What a suite's status is under the applied advisory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    /// Nothing said, or INFO.
    Allowed,
    /// Being retired: warn, never refuse.
    Deprecated,
    /// Refused at its consult point.
    Broken,
}

impl Status {
    /// The status an entry's severity gives.
    fn of(severity: Severity) -> Self {
        match severity {
            Severity::Info => Self::Allowed,
            Severity::Deprecated => Self::Deprecated,
            Severity::Broken => Self::Broken,
        }
    }
}

/// The applied advisory, as the consult points and the texts read it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// The advisory's serial; 0: none applied.
    pub serial: u64,
    /// When the Raven project issued it (Unix ms; shown only).
    pub issued_at_ms: u64,
    /// The registered suites it marks DEPRECATED or BROKEN, in its order.
    suites: Vec<(&'static str, Status)>,
    /// The holdable features a `FEATURE_HOLD` marks DEPRECATED or BROKEN.
    holds: Vec<(&'static str, Status)>,
    /// The features that are off: held BROKEN, or the feature of a BROKEN
    /// wire module.
    closed: Vec<&'static str>,
    /// A hold on `feature/advisory`: shown, never enforced.
    holds_advisories: bool,
    /// Entries of kinds this build does not know.
    unknown_kinds: usize,
    /// The `RELEASE_FLOOR` (0: none).
    pub release_floor: u64,
    /// The `NOTICE` text, sanitized for one terminal line.
    pub notice: Option<String>,
    /// This build's serial ([`update_state::BUILD_SERIAL`]).
    pub build_serial: u64,
    /// Updates are frozen (equivocation or a split view).
    pub frozen: bool,
    /// This build has no release key set: it checks no advisory.
    pub no_release_keys: bool,
}

impl Policy {
    /// The policy of an advisory's entries for a build of `build_serial`.
    /// Any entries at all: an id this build does not have, a kind it does
    /// not know and a hold on `feature/advisory` are never enforced.
    pub fn of_entries(
        serial: u64,
        issued_at_ms: u64,
        entries: &[Entry],
        build_serial: u64,
    ) -> Self {
        let mut p = Self {
            serial,
            issued_at_ms,
            build_serial,
            ..Self::default()
        };
        for e in entries {
            let status = Status::of(e.severity);
            match e.kind {
                EntryKind::SuiteStatus => {
                    let Some(suite) = suite_registry::suite(&e.target) else {
                        continue;
                    };
                    if status == Status::Allowed {
                        continue;
                    }
                    p.suites.push((suite.id, status));
                    if status == Status::Broken && suite.layer == Layer::Module {
                        if let Some(f) = suite.gate.and_then(suite_registry::feature_for_gate) {
                            p.close(f.id);
                        }
                    }
                }
                EntryKind::FeatureHold => {
                    let Some(feature) = suite_registry::feature(&e.target) else {
                        continue;
                    };
                    if !feature.holdable() {
                        p.holds_advisories |= status != Status::Allowed;
                        continue;
                    }
                    if status == Status::Allowed {
                        continue;
                    }
                    p.holds.push((feature.id, status));
                    if status == Status::Broken {
                        p.close(feature.id);
                    }
                }
                EntryKind::ReleaseFloor => {
                    p.release_floor = p.release_floor.max(e.release_floor().unwrap_or(0));
                }
                EntryKind::Notice => {
                    p.notice = e.notice_text().map(sanitize_terminal_line);
                }
                EntryKind::KeySet => {}
                EntryKind::Other(_) => p.unknown_kinds += 1,
            }
        }
        p
    }

    /// The policy of a stored advisory.
    pub fn of_advisory(advisory: &Advisory, build_serial: u64) -> Self {
        Self::of_entries(
            advisory.serial,
            advisory.issued_at_ms,
            &advisory.entries,
            build_serial,
        )
    }

    /// The policy of a profile's update state: its advisory (none: nothing
    /// applied), the build reading it, the freeze and the keys.
    pub fn of_state(state: &UpdateState) -> Self {
        let serial = state.build().serial;
        let mut p = state.advisory().map_or_else(
            || Self {
                build_serial: serial,
                ..Self::default()
            },
            |a| Self::of_advisory(a, serial),
        );
        p.frozen = state.frozen().is_some();
        p.no_release_keys = state.key_set().is_none();
        p
    }

    fn close(&mut self, feature: &'static str) {
        if !self.closed.contains(&feature) {
            self.closed.push(feature);
        }
    }

    /// The status of the registered suite `id` (an id this build does not
    /// have is [`Status::Allowed`]).
    pub fn status(&self, id: &str) -> Status {
        self.suites
            .iter()
            .find(|(s, _)| *s == id)
            .map_or(Status::Allowed, |(_, status)| *status)
    }

    /// Whether the feature `feature` (`feature/<gate>`) may stay on: not
    /// held BROKEN, and not the feature of a BROKEN wire module.
    pub fn allows(&self, feature: &str) -> bool {
        !self.closed.contains(&feature)
    }

    /// The first BROKEN link suite, if any (no link either way).
    pub fn broken_link_suite(&self) -> Option<&'static str> {
        self.broken_at(Layer::Link).next()
    }

    /// Whether a new PairInit (version 1, suite 1) may be made or taken.
    pub fn pair_init_allowed(&self) -> bool {
        self.status(suite_registry::PAIRINIT_V1_SUITE1) != Status::Broken
    }

    /// Whether the indexed sessions (V1, RVNA1 version 3) may seal and
    /// accept.
    pub fn session_allowed(&self) -> bool {
        self.broken_at(Layer::Session).next().is_none()
    }

    /// Whether this build is below the advisory's release floor.
    pub fn below_release_floor(&self) -> bool {
        self.release_floor > self.build_serial
    }

    /// The status of session profile `profile` for a new session (step
    /// P6.50): the worst of its registered ids ([`profile_ids`]); a profile
    /// the registry does not name yet is [`Status::Allowed`].
    pub fn profile_status(&self, profile: u8) -> Status {
        profile_ids(profile)
            .iter()
            .map(|id| self.status(id))
            .max()
            .unwrap_or(Status::Allowed)
    }

    /// The text refusing a new session of `profile`, when this notice marks
    /// one of its ids BROKEN; `None`: it may be made and taken.
    pub fn profile_refusal(&self, profile: u8) -> Option<String> {
        let broken: Vec<&str> = profile_ids(profile)
            .iter()
            .copied()
            .filter(|id| self.status(id) == Status::Broken)
            .collect();
        (!broken.is_empty()).then(|| profile_refused_text(&broken, self.serial))
    }

    /// What becomes of the V1 sessions already open, for a build whose next
    /// session profile is `next` (none in this build).
    pub fn v1_sessions(&self, next: Option<u8>) -> V1Sessions {
        if self.session_allowed() {
            return V1Sessions::Go;
        }
        match next.filter(|p| *p > PROFILE_INDEXED_SESSION_V1 && self.profile_refusal(*p).is_none())
        {
            Some(into) => V1Sessions::Retire { into },
            None => V1Sessions::Held,
        }
    }

    fn broken_at(&self, layer: Layer) -> impl Iterator<Item = &'static str> + '_ {
        self.suites
            .iter()
            .filter(move |(id, status)| {
                *status == Status::Broken
                    && suite_registry::suite(id).is_some_and(|s| s.layer == layer)
            })
            .map(|(id, _)| *id)
    }

    /// The registered ids at `status`: suites first, then features (without
    /// `feature/`), joined for a text.
    fn ids_at(&self, status: Status, layer: Option<Layer>) -> Vec<&'static str> {
        let suites = self
            .suites
            .iter()
            .filter(|(id, s)| {
                *s == status
                    && layer.is_none_or(|l| suite_registry::suite(id).is_some_and(|x| x.layer == l))
            })
            .map(|(id, _)| *id);
        let holds = self
            .holds
            .iter()
            .filter(|(_, s)| *s == status && layer.is_none_or(|l| l == Layer::Module))
            .map(|(id, _)| feature_name(id));
        suites.chain(holds).collect()
    }

    /// What `raven status`, the terminal app's SEC and `raven doctor` say
    /// about security notices from the Raven project at `now_ms`, one line
    /// each: the freeze, the keys, the newest notice and how old it is,
    /// then what it refuses, turns off and warns about, and its text.
    pub fn lines(&self, now_ms: u64) -> Vec<String> {
        let mut out = Vec::new();
        if self.frozen {
            out.push(FROZEN_TEXT.to_owned());
        }
        if self.serial == 0 {
            out.push(if self.no_release_keys {
                update_state::NO_RELEASE_KEYS_TEXT.to_owned()
            } else {
                NONE_YET_TEXT.to_owned()
            });
            return out;
        }
        let n = self.serial;
        out.push(format!(
            "Security notices from the Raven project: #{n} (issued {}).",
            crate::local_time::ago_text(self.issued_at_ms, now_ms)
        ));
        if self.below_release_floor() {
            out.push(format!(
                "This Raven version has a known security problem (notice #{n}). Get the \
                 update from a friend who has it, or from the Raven website. Raven keeps working."
            ));
        }
        let link = self.ids_at(Status::Broken, Some(Layer::Link));
        if !link.is_empty() {
            out.push(format!(
                "Security notice #{n}: Raven's link security method ({}) is no longer safe. \
                 Raven now refuses it, so it can't reach anyone and nobody can reach it until \
                 Raven is updated. Get the update from the Raven website, or as a file from a \
                 friend.",
                link.join(", ")
            ));
        }
        if !self.pair_init_allowed() {
            out.push(format!(
                "Security notice #{n}: the way Raven starts a new session ({}) is no longer \
                 safe. Raven now refuses it both ways until it is updated; sessions already \
                 open go on.",
                suite_registry::PAIRINIT_V1_SUITE1
            ));
        }
        let session = self.ids_at(Status::Broken, Some(Layer::Session));
        if !session.is_empty() {
            out.push(format!(
                "Security notice #{n}: the security method of your sessions ({}) is no longer \
                 safe. Raven holds them (it seals and takes nothing on them) until it is \
                 updated.",
                session.join(", ")
            ));
        }
        let off = self.ids_at(Status::Broken, Some(Layer::Module));
        if !off.is_empty() {
            out.push(format!(
                "Security notice #{n}: Raven turned off {}, as the notice says.",
                off.join(", ")
            ));
        }
        let retiring = self.ids_at(Status::Deprecated, None);
        if !retiring.is_empty() {
            out.push(format!(
                "Security notice #{n}: an older security method is being retired ({}). Raven \
                 still uses it for now; update Raven when a newer version is out.",
                retiring.join(", ")
            ));
        }
        if self.holds_advisories {
            out.push(format!(
                "Security notice #{n} asks Raven to stop taking security notices. Raven never \
                 does that: it would also stop the notice that lifts it."
            ));
        }
        if let Some(text) = &self.notice {
            out.push(format!("Notice #{n} from the Raven project: {text}"));
        }
        if self.unknown_kinds > 0 {
            out.push(format!(
                "Security notice #{n} has a part this version doesn't understand: update Raven."
            ));
        }
        out
    }

    /// `raven doctor`'s `updates` row: the notice and its age,
    /// then what it refuses, turns off and retires, in ids.
    pub fn doctor_row(&self, now_ms: u64) -> String {
        if self.serial == 0 {
            let mut row = if self.no_release_keys {
                "no release keys in this build".to_owned()
            } else {
                "no notice yet".to_owned()
            };
            if self.frozen {
                row.push_str("; frozen (two versions of the release history)");
            }
            return row;
        }
        let mut parts = vec![format!(
            "notice #{} (issued {})",
            self.serial,
            crate::local_time::ago_text(self.issued_at_ms, now_ms)
        )];
        if self.frozen {
            parts.push("frozen (two versions of the release history)".to_owned());
        }
        let refused: Vec<_> = self
            .ids_at(Status::Broken, Some(Layer::Link))
            .into_iter()
            .chain(self.ids_at(Status::Broken, Some(Layer::PairInit)))
            .chain(self.ids_at(Status::Broken, Some(Layer::Session)))
            .collect();
        if !refused.is_empty() {
            parts.push(format!("refuses {}", refused.join(", ")));
        }
        let off = self.ids_at(Status::Broken, Some(Layer::Module));
        if !off.is_empty() {
            parts.push(format!("turned off {}", off.join(", ")));
        }
        let retiring = self.ids_at(Status::Deprecated, None);
        if !retiring.is_empty() {
            parts.push(format!("retiring {}", retiring.join(", ")));
        }
        if self.below_release_floor() {
            parts.push(format!(
                "this version ({}) is below the release floor ({})",
                self.build_serial, self.release_floor
            ));
        }
        parts.join("; ")
    }
}

/// A feature's id as the texts name it: without `feature/`.
fn feature_name(id: &'static str) -> &'static str {
    id.strip_prefix(crate::advisory::FEATURE_PREFIX)
        .unwrap_or(id)
}

/// Shown while updates are frozen (design D, UX).
pub const FROZEN_TEXT: &str = "Raven saw two different versions of the Raven release history. \
    Someone may be showing different updates to different people. Raven won't install updates \
    until this is cleared up. Keep your current version and tell the Raven project.";
/// Shown while no notice was applied.
pub const NONE_YET_TEXT: &str = "Security notices from the Raven project: none yet.";

// ── Session profiles (P6.50) ─────────────────────────────────────────

/// The registered ids of session profile `profile`: profile 1's PairInit
/// (which makes its sessions), its session and its sealed body. The
/// next-profile program adds its own ids here and in the registry.
pub fn profile_ids(profile: u8) -> &'static [&'static str] {
    match profile {
        PROFILE_INDEXED_SESSION_V1 => &[
            suite_registry::PAIRINIT_V1_SUITE1,
            suite_registry::ATSAM_INDEXED_SESSION_V1,
            suite_registry::RVNA1_V3,
        ],
        _ => &[],
    }
}

/// What becomes of the V1 sessions already open ([`v1_sessions`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V1Sessions {
    /// They seal and accept as before (DEPRECATED included).
    Go,
    /// Their session profile is BROKEN and this build has no next profile:
    /// they seal and take nothing ([`SUITE_HELD`]) and what waits in them
    /// stays until Raven is updated.
    Held,
    /// BROKEN, and this build speaks the next profile `into`: each is
    /// retired for sending, Phase 2a re-seals what waited in it under a
    /// session of `into` with that contact (chosen by
    /// [`crate::capability_floor::choose_profile`]; a contact that does not
    /// speak `into` yet keeps it waiting), and it takes nothing more (still
    /// [`SUITE_HELD`]).
    Retire { into: u8 },
}

/// The text a refused session profile gives (its BROKEN ids, `broken`).
pub fn profile_refused_text(broken: &[&str], serial: u64) -> String {
    format!(
        "{SUITE_BROKEN}: Raven security notice #{serial} says this security method ({}) is no \
         longer safe; Raven starts and accepts no new session with it",
        broken.join(", ")
    )
}

/// What the person is told the first time a new session with `name` uses
/// a profile a notice is retiring (design D §7).
pub fn retiring_contact_text(name: &str) -> String {
    format!(
        "{name}'s Raven still uses an older security method that is being retired. Ask {name} to \
         update Raven."
    )
}

/// Contacts told about a retiring profile, at most (then the memory starts
/// over).
const MAX_RETIRING_WARNED: usize = 4_096;

/// The contacts told about a retiring profile, by notice serial.
static RETIRING_WARNED: Mutex<BTreeSet<(u64, [u8; 32])>> = Mutex::new(BTreeSet::new());

/// Whether to tell the person now that `peer` uses a profile notice
/// `serial` retires: the first time for that contact and notice in this
/// process.
pub(crate) fn retiring_warning_due(serial: u64, peer: &[u8; 32]) -> bool {
    let mut warned = RETIRING_WARNED
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if warned.len() >= MAX_RETIRING_WARNED {
        warned.clear();
    }
    warned.insert((serial, *peer))
}

// ── The consult points ───────────────────────────────────────────────

/// The status of the registered suite `id` under the applied advisory:
/// always [`Status::Allowed`] while the advisory gate is shut.
pub fn status(id: &str) -> Status {
    if !security_gate::live(SecGate::Advisory) {
        return Status::Allowed;
    }
    current().status(id)
}

/// Whether the feature `feature` (`feature/<gate>`, a
/// [`suite_registry`] id) may stay on. Every `*_live()` asks **after** its
/// own gate, so a hold can only close. Always `true` while the advisory
/// gate is shut, and for `feature/advisory` (asked first, so the advisory
/// gate's own check never comes back here).
pub fn hold_allows(feature: &str) -> bool {
    if feature == suite_registry::FEATURE_ADVISORY || !security_gate::live(SecGate::Advisory) {
        return true;
    }
    current().allows(feature)
}

/// [`hold_allows`] for the feature of the gate constant named `gate`
/// (`security_gate`'s gates; a name without a feature is allowed).
pub fn hold_allows_gate(gate: &str) -> bool {
    match suite_registry::feature_for_gate(gate) {
        Some(f) => hold_allows(f.id),
        None => true,
    }
}

/// Before every link handshake, either way (raven-node): `Err` with the
/// text when a link suite is BROKEN.
pub fn check_link() -> Result<(), String> {
    if !security_gate::live(SecGate::Advisory) {
        return Ok(());
    }
    let policy = current();
    match policy.broken_link_suite() {
        None => Ok(()),
        Some(id) => Err(link_refused_text(id, policy.serial)),
    }
}

/// The text a link refusal gives ([`check_link`]).
pub fn link_refused_text(id: &str, serial: u64) -> String {
    format!(
        "{SUITE_BROKEN}: Raven security notice #{serial} says this Raven's link security method \
         ({id}) is no longer safe; Raven makes no link and takes none until it is updated"
    )
}

/// Before a PairInit is made or taken (links and letters): `Err` with the
/// text when `pairinit/1/1` is BROKEN. Sessions already open are not
/// touched.
pub fn check_pair_init() -> Result<(), String> {
    if !security_gate::live(SecGate::Advisory) {
        return Ok(());
    }
    let policy = current();
    if policy.pair_init_allowed() {
        return Ok(());
    }
    Err(pair_init_refused_text(policy.serial))
}

/// The text a PairInit refusal gives ([`check_pair_init`]).
pub fn pair_init_refused_text(serial: u64) -> String {
    format!(
        "{SUITE_BROKEN}: Raven security notice #{serial} says the way Raven starts a new session \
         ({}) is no longer safe; Raven starts and accepts none until it is updated (sessions \
         already open go on)",
        suite_registry::PAIRINIT_V1_SUITE1
    )
}

/// Whether the indexed sessions may seal and accept: `false` while
/// `atsam/indexed-session/v1` or `rvna1/3` is BROKEN (the store refuses with
/// `SuiteHeld` and changes nothing).
pub fn session_allowed() -> bool {
    !security_gate::live(SecGate::Advisory) || current().session_allowed()
}

/// What becomes of the V1 sessions already open, for a build whose next
/// session profile is `next` ([`Policy::v1_sessions`]; the next-profile
/// program asks whenever the policy may have changed): always
/// [`V1Sessions::Go`] while the advisory gate is shut.
pub fn v1_sessions(next: Option<u8>) -> V1Sessions {
    if !security_gate::live(SecGate::Advisory) {
        return V1Sessions::Go;
    }
    current().v1_sessions(next)
}

/// The applied policy, read once for a decision that asks it several
/// things (the next-profile choice); `None` while the advisory gate is
/// shut.
pub fn applied() -> Option<Arc<Policy>> {
    security_gate::live(SecGate::Advisory).then(current)
}

// ── What the person reads ────────────────────────────────────────────

/// The policy of `data_dir`'s update state read now (not the cache): `None`
/// while the advisory gate is shut; `Err` with the reason when the state
/// cannot be read.
pub fn read(data_dir: &Path) -> Option<Result<Policy, String>> {
    match update_state::load(data_dir) {
        Ok(state) => Some(Ok(Policy::of_state(&state))),
        Err(Refused::Off) => None,
        Err(e) => Some(Err(sanitize_terminal_line(&e.to_string()))),
    }
}

/// `raven status`'s and the terminal app's lines about security notices
/// from the Raven project ([`Policy::lines`]); none while the gate is shut.
pub fn status_lines(data_dir: &Path, now_ms: u64) -> Vec<String> {
    match read(data_dir) {
        None => Vec::new(),
        Some(Ok(policy)) => policy.lines(now_ms),
        Some(Err(why)) => vec![format!(
            "Raven can't read its security notices from the Raven project right now ({why})."
        )],
    }
}

/// `raven doctor`'s `updates` row ([`Policy::doctor_row`]); none
/// while the gate is shut.
pub fn doctor_row(data_dir: &Path, now_ms: u64) -> Option<String> {
    read(data_dir).map(|read| match read {
        Ok(policy) => policy.doctor_row(now_ms),
        Err(why) => format!("can't be read ({why})"),
    })
}

// ── The cache ────────────────────────────────────────────────────────

/// What a read saw: the state file's length and modification time, and
/// this process's write count.
type Stamp = (Option<(u64, SystemTime)>, u64);

/// The attached profile's policy.
struct Cache {
    data_dir: PathBuf,
    policy: Arc<Policy>,
    /// The stamp `policy` was read at; `None`: not read yet, or the read
    /// failed (the policy before it stays).
    read_at: Option<Stamp>,
    /// When the stamp was last looked at, and the write count then.
    checked: Option<(Instant, u64)>,
}

impl Cache {
    fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            policy: none(),
            read_at: None,
            checked: None,
        }
    }

    /// Whether to look at the stamp again: never looked, the process wrote
    /// the state since, or [`RECHECK`] passed.
    fn due(&self, writes: u64, now: Instant) -> bool {
        self.checked
            .is_none_or(|(at, seen)| seen != writes || now.saturating_duration_since(at) >= RECHECK)
    }

    /// The policy at `now`: looked at again when due, read again when the
    /// stamp changed. Used without the global lock by tests.
    #[cfg(test)]
    fn current_at(&mut self, now: Instant) -> Arc<Policy> {
        let writes = WRITES.load(Ordering::Acquire);
        if !self.due(writes, now) {
            return Arc::clone(&self.policy);
        }
        let stamp = stamp_of(&self.data_dir, writes);
        if self.read_at != Some(stamp) {
            self.take(stamp, read_policy(&self.data_dir));
        }
        self.checked = Some((now, writes));
        Arc::clone(&self.policy)
    }

    /// A read at `stamp`: kept when it succeeded.
    fn take(&mut self, stamp: Stamp, read: Option<Policy>) {
        match read {
            Some(policy) => {
                self.policy = Arc::new(policy);
                self.read_at = Some(stamp);
            }
            None => self.read_at = None,
        }
    }
}

static ATTACHED: Mutex<Option<Cache>> = Mutex::new(None);
/// Writes of the update state by this process ([`note_written`]).
static WRITES: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Set while this thread reads the state for the cache.
    static READING: Cell<bool> = const { Cell::new(false) };
    /// Tests: this thread's policy in place of the attached profile's.
    static THREAD_POLICY: RefCell<Option<Arc<Policy>>> = const { RefCell::new(None) };
}

fn attached() -> MutexGuard<'static, Option<Cache>> {
    ATTACHED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// No advisory applied.
fn none() -> Arc<Policy> {
    static NONE: OnceLock<Arc<Policy>> = OnceLock::new();
    Arc::clone(NONE.get_or_init(|| Arc::new(Policy::default())))
}

fn stamp_of(data_dir: &Path, writes: u64) -> Stamp {
    let file = std::fs::metadata(data_dir.join(update_state::UPDATE_STATE_FILE))
        .ok()
        .and_then(|meta| Some((meta.len(), meta.modified().ok()?)));
    (file, writes)
}

/// The profile's policy, or `None` when its state cannot be read.
fn read_policy(data_dir: &Path) -> Option<Policy> {
    struct Done;
    impl Drop for Done {
        fn drop(&mut self) {
            READING.with(|r| r.set(false));
        }
    }
    READING.with(|r| r.set(true));
    let _done = Done;
    update_state::load(data_dir)
        .ok()
        .map(|state| Policy::of_state(&state))
}

/// The profile this process serves: its advisory's policy applies from
/// now on (nothing while the advisory gate is shut). raven-node names its
/// `--data-dir` at start, ash its own.
pub fn attach(data_dir: &Path) {
    let mut guard = attached();
    if guard.as_ref().is_some_and(|c| c.data_dir == data_dir) {
        return;
    }
    *guard = Some(Cache::new(data_dir.to_path_buf()));
}

/// Tests: no profile attached any more (when `data_dir` still is).
#[cfg(test)]
fn detach(data_dir: &Path) {
    let mut guard = attached();
    if guard.as_ref().is_some_and(|c| c.data_dir == data_dir) {
        *guard = None;
    }
}

/// The update state was written by this process: the next check reads it
/// again ([`crate::update_state`] calls it).
pub(crate) fn note_written() {
    WRITES.fetch_add(1, Ordering::AcqRel);
}

/// The applied policy (the gate is the caller's): this thread's in a test,
/// else the attached profile's, read again when its stamp changed; none
/// without a profile.
fn current() -> Arc<Policy> {
    if cfg!(debug_assertions) {
        if let Some(policy) = THREAD_POLICY.with(|p| p.borrow().clone()) {
            return policy;
        }
    }
    let now = Instant::now();
    let writes = WRITES.load(Ordering::Acquire);
    let (dir, read_at) = {
        let guard = attached();
        let Some(cache) = guard.as_ref() else {
            return none();
        };
        if READING.with(Cell::get) || !cache.due(writes, now) {
            return Arc::clone(&cache.policy);
        }
        (cache.data_dir.clone(), cache.read_at)
    };
    let stamp = stamp_of(&dir, writes);
    let read = (read_at != Some(stamp)).then(|| read_policy(&dir));
    let mut guard = attached();
    let Some(cache) = guard.as_mut().filter(|c| c.data_dir == dir) else {
        return none();
    };
    if let Some(read) = read {
        cache.take(stamp, read);
    }
    cache.checked = Some((now, writes));
    Arc::clone(&cache.policy)
}

/// In-process tests apply `policy` on the current thread only, in place of
/// the attached profile's (`None`: back to it). The advisory gate still
/// decides whether any of it applies. Ignored in release builds.
#[doc(hidden)]
pub fn set_policy_for_this_thread(policy: Option<Policy>) {
    THREAD_POLICY.with(|p| *p.borrow_mut() = policy.map(Arc::new));
}

#[cfg(test)]
mod tests;
