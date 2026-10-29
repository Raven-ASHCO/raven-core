//! The update state (`docs/roadmap/plans/phase6-design.json` step P6.44;
//! design D §1-§3; owner decisions OD6b-20, OD6b-21, OD6b-22): the release
//! key set this profile trusts, the newest security advisory (RAD1) it
//! accepted, the transparency log (RTL1) it stored, the build installed, and
//! whether updates are frozen.
//!
//! - **Release keys.** A build trusts the key set compiled into it,
//!   [`RELEASE_KEY_SET_V1`]: `None` until the owner's key ceremony, so such a
//!   build refuses every artifact with `NO_RELEASE_KEYS`
//!   ([`NO_RELEASE_KEYS_TEXT`]). A debug build with the Lab Test A unlock
//!   loads a test key set from the file [`LAB_RELEASE_KEYS_FILE`] names
//!   instead; a release build never reads the variable. A `KEY_SET` entry in
//!   an accepted advisory rotates to the next set (RAVEN_SECURITY_ADVISORY_V1
//!   §6.2): the state keeps the current set and the digests of the sets
//!   before it, and the last [`MAX_ROTATIONS`] rotations with the logs they
//!   came with, for friends that missed one (RUP1 GET_ROTATION). An
//!   artifact under a key set this state never trusted cannot be checked
//!   yet ([`Refused::UnknownKeySet`]: no event). A compile-time check
//!   refuses a compiled set that holds a published test key or lets fewer
//!   than 2 keys sign.
//! - **Advisories** ([`accept_advisory`]), in the normative order of wire
//!   spec W-D1: decode, the key set, the threshold signatures (a refusal is
//!   forged: SEC_ADVISORY_FORGED), the serial against the newest one known
//!   (lower: SEC_ADVISORY_ROLLBACK, ignored; the same serial with another
//!   signed body, or the next serial naming another `prev_digest`:
//!   SEC_ADVISORY_EQUIVOCATION, frozen; the same body with another
//!   signature block is the same advisory), then the log snapshot it came with
//!   (checked, else forged; listing the advisory, else SEC_UPDATE_UNLOGGED;
//!   consistent with the stored log, else SEC_LOG_SPLIT_VIEW, frozen), and
//!   only then it is stored, with the log when that is longer. This build's
//!   compiled floor ([`BUILD_ADVISORY_FLOOR`], the newest advisory known when
//!   it was built) is the lowest serial it accepts: it counts as the newest
//!   one known while nothing newer is stored.
//! - **Logs** ([`accept_log`]): a snapshot on its own (a friend's log, a
//!   bundle's) is checked and stored when it extends the stored one; one
//!   that contradicts it freezes.
//! - **Frozen.** Equivocation or a split view keeps both pieces of evidence
//!   ([`Evidence`]) and applies nothing new: no advisory, no log and (P6.47)
//!   no install. Only a release installed by hand (a higher [`BUILD_SERIAL`])
//!   clears it (design D, responses): the key set that froze signed two
//!   histories, so no advisory it signs, a rotation included, can lift it
//!   (Phase 6 review updates-protocol-2; `docs/RELEASE_KEY_CEREMONY.md` §7).
//!
//! The state is [`UPDATE_STATE_FILE`] (`updates/state`): JSON, sealed at rest
//! from its first version (RMS1 kind 23 in a sealed profile,
//! [`crate::at_rest::FILES`]), written only under its lock
//! ([`UPDATE_STATE_LOCK`]). A state file that cannot be read fails closed:
//! nothing is accepted, since an empty state would take an old advisory back.
//! Nothing here reads or writes it while [`SecGate::Advisory`] is shut
//! (`ADVISORY_PRODUCTION_ENABLED = false`). Events are noted after the lock
//! is released, "passed on by" the friend who handed the artifact over
//! ([`Origin`]), never blamed; an advisory stored raises SEC_ADVISORY_APPLIED
//! (an informational alert) the same way. Applying its entries (the suite
//! policy, holds, the release floor warning) is [`crate::suite_policy`]'s
//! (P6.45), which reads this file again after every write; staging and
//! installing bundles is ash's `update_install` (P6.47), which records here
//! the build it put in place and what it swapped ([`InstallRecord`]).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::advisory::{succession, Advisory, Entry, Rad1Error, Succession};
use crate::at_rest::{self, Kind};
use crate::clock::now_ms;
use crate::release_bundle::{BundleError, VerifyCtx, THIS_TARGET};
use crate::release_keys::{
    KeySet, SigError, KEYSET_ALG_ED25519, KEYSET_HEADER_LEN, KEYSET_MAX_KEYS,
};
use crate::security_events::{SecKind, Via};
use crate::security_gate::{self, SecGate};
use crate::tlog::{Consistency, EntryType, LogCheckError, LogEntry, Rtl1Error, Snapshot};

mod release_build;

pub use release_build::{BUILD_ADVISORY_FLOOR, BUILD_SERIAL};

/// The folder of everything updates keep in a profile (P6.47 and P6.49 add
/// `staged/`, `incoming/` and `quarantine/`; [`crate::update_downloads`]).
pub const UPDATES_DIR: &str = "updates";
/// The verified releases waiting to be installed (P6.47, ash's
/// `update_install`): `staged/<build serial>/`, written only by the CLI or
/// the terminal app, never by raven-node.
pub const STAGED_DIR: &str = "updates/staged";
/// The most builds [`STAGED_DIR`] keeps (design D §6).
pub const MAX_STAGED_BUILDS: usize = 2;
/// A staged build's manifest, beside its files (P6.47; raven-node serves
/// staged builds to friends, P6.49).
pub const STAGED_MANIFEST: &str = "manifest.rrb1";
/// A staged build's log snapshot.
pub const STAGED_SNAPSHOT: &str = "snapshot.rtl1";
/// A staged build's advisory, when its bundle carried one.
pub const STAGED_ADVISORY: &str = "advisory.rad1";

/// A staged file's name in its build's folder: its index in the manifest
/// and its path's last segment (`1-raven-node`), so the folder stays flat.
pub fn staged_file_name(index: usize, path: &str) -> String {
    format!("{index}-{}", path.rsplit('/').next().unwrap_or(path))
}
/// The update state, below the profile folder.
pub const UPDATE_STATE_FILE: &str = "updates/state";
/// Every writer of [`UPDATE_STATE_FILE`] takes it (`at_rest::FILES`).
pub const UPDATE_STATE_LOCK: &str = ".at_rest.update_state.lock.sqlite";
/// The format of [`UPDATE_STATE_FILE`] this build writes; a later one is
/// refused (fail closed), never rewritten without its fields.
pub const STATE_VERSION: u32 = 1;

/// The release key set this build trusts (RAVEN_SECURITY_ADVISORY_V1 §2.1):
/// `None` until the owner's key ceremony (OD6b-20). The ceremony's commit
/// changes this one line to `Some(&hex_bytes::<99>("0102..."))` (a 2-of-3
/// set is 99 bytes); the checks below refuse to build with a set that holds
/// a published test key or lets fewer than 2 keys sign.
pub const RELEASE_KEY_SET_V1: Option<&[u8]> = None;

/// Debug builds with `RAVEN_LAB_TEST_A=1` only: a file holding a key set
/// (its bytes, or their hex on one line) that replaces the compiled one.
/// Release builds never read it.
pub const LAB_RELEASE_KEYS_FILE: &str = "RAVEN_LAB_RELEASE_KEYS_FILE";
/// The longest lab key file read (a key set is at most 259 bytes, 518 hex
/// digits).
pub const MAX_LAB_KEYS_FILE: u64 = 4_096;
/// The most key set digests the state keeps (the current one last).
pub const MAX_KEY_SET_HISTORY: usize = 32;
/// The most `KEY_SET` rotations the state keeps, with the logs they came
/// with (the newest): what a friend still on an older set is served (RUP1
/// GET_ROTATION).
pub const MAX_ROTATIONS: usize = 4;

/// What the person reads when this build cannot check updates (design D
/// §1).
pub const NO_RELEASE_KEYS_TEXT: &str =
    "This build has no Raven release keys; it can't check updates.";

/// The published test keys (RAVEN_SECURITY_ADVISORY_V1 §2.4: the Ed25519
/// keys of the seeds `0x11 x 32`, `0x22 x 32`, `0x33 x 32`), in every build:
/// what the compile-time check below looks for. A unit test derives them
/// from the seeds.
pub const TEST_PUBLIC_KEYS: [[u8; 32]; 3] = [
    hex_bytes::<32>("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"),
    hex_bytes::<32>("a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"),
    hex_bytes::<32>("17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"),
];

// A compiled key set holds no test key and needs at least 2 signatures; the
// floor names an advisory exactly when its serial is above 0. A wrong value
// fails the build, release builds included.
const _: () = {
    assert!(
        compiled_set_shape_ok(RELEASE_KEY_SET_V1),
        "RELEASE_KEY_SET_V1 is not a key set of 1..=8 Ed25519 keys with a threshold of 2 or more"
    );
    assert!(
        !holds_test_key(RELEASE_KEY_SET_V1),
        "RELEASE_KEY_SET_V1 holds a published test key"
    );
    assert!(
        (BUILD_ADVISORY_FLOOR.0 == 0) == all_zero(&BUILD_ADVISORY_FLOOR.1),
        "BUILD_ADVISORY_FLOOR: a serial above 0 needs a digest, and 0 none"
    );
};

/// `N` bytes from `2 * N` lower-case hex digits, at compile time: the form
/// the key ceremony and the release script write.
pub const fn hex_bytes<const N: usize>(hex: &str) -> [u8; N] {
    let s = hex.as_bytes();
    assert!(s.len() == 2 * N, "wrong number of hex digits");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not a lower-case hex digit"),
    }
}

const fn all_zero(b: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if b[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Is a compiled key set (`None` passes) in shape: algorithm 1, `n`
/// 1..=8, exactly `3 + 32 * n` bytes, a threshold of at least 2 and at most
/// `n`? Whether the keys are usable points is [`KeySet::decode`]'s (a unit
/// test decodes the compiled set).
pub const fn compiled_set_shape_ok(set: Option<&[u8]>) -> bool {
    let Some(b) = set else {
        return true;
    };
    if b.len() < KEYSET_HEADER_LEN {
        return false;
    }
    let (threshold, n) = (b[1] as usize, b[2] as usize);
    b[0] == KEYSET_ALG_ED25519
        && n >= 1
        && n <= KEYSET_MAX_KEYS
        && b.len() == KEYSET_HEADER_LEN + 32 * n
        && threshold >= 2
        && threshold <= n
}

/// Does key set bytes' key list hold one of the [`TEST_PUBLIC_KEYS`]?
pub const fn holds_test_key(set: Option<&[u8]>) -> bool {
    let Some(b) = set else {
        return false;
    };
    let mut at = KEYSET_HEADER_LEN;
    while at + 32 <= b.len() {
        let mut t = 0;
        while t < TEST_PUBLIC_KEYS.len() {
            let mut i = 0;
            while i < 32 && b[at + i] == TEST_PUBLIC_KEYS[t][i] {
                i += 1;
            }
            if i == 32 {
                return true;
            }
            t += 1;
        }
        at += 32;
    }
    false
}

/// The compiled key set ([`RELEASE_KEY_SET_V1`]), decoded: `None` before the
/// key ceremony.
pub fn compiled_key_set() -> Option<KeySet> {
    RELEASE_KEY_SET_V1.and_then(|bytes| KeySet::decode(bytes).ok())
}

/// The lab key set: `Some` only in a debug build with the Lab Test A unlock
/// and [`LAB_RELEASE_KEYS_FILE`] set, and then the key set in that file
/// (`Some(None)`: a file that cannot be read or holds no key set, so no
/// keys at all). `None`: the switch does not apply; a release build never
/// reads the variable or the file.
pub fn lab_key_set() -> Option<Option<KeySet>> {
    lab_key_set_from(
        cfg!(debug_assertions),
        crate::pair_init::lab_test_a_enabled,
        || std::env::var(LAB_RELEASE_KEYS_FILE).ok(),
        read_key_file,
    )
}

/// [`lab_key_set`] with the build, the unlock, the variable and the file
/// reader passed in: none of them is called in a release build.
fn lab_key_set_from(
    debug: bool,
    test_a: impl FnOnce() -> bool,
    value: impl FnOnce() -> Option<String>,
    read: impl FnOnce(&Path) -> Option<Vec<u8>>,
) -> Option<Option<KeySet>> {
    if !debug || !test_a() {
        return None;
    }
    let path = crate::p2p_gate::lab_value(debug, value, crate::p2p_gate::lab_switch_text)?;
    Some(read(Path::new(path.trim())).and_then(|bytes| parse_key_set_file(&bytes)))
}

/// A lab key file's bytes, at most [`MAX_LAB_KEYS_FILE`].
fn read_key_file(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_LAB_KEYS_FILE + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_LAB_KEYS_FILE).then_some(bytes)
}

/// A key set file: the key set's hex on one line (surrounding white space
/// ignored), or its bytes.
pub fn parse_key_set_file(bytes: &[u8]) -> Option<KeySet> {
    let hex = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| hex::decode(text.trim()).ok());
    KeySet::decode(hex.as_deref().unwrap_or(bytes)).ok()
}

/// What this build brings to the update state (design D §1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Build {
    /// The release key set it trusts: [`RELEASE_KEY_SET_V1`], or the lab
    /// file's in a debug build. `None`: it can check no update.
    pub key_set: Option<KeySet>,
    /// [`BUILD_SERIAL`].
    pub serial: u64,
    /// [`BUILD_ADVISORY_FLOOR`].
    pub floor: (u64, [u8; 32]),
}

impl Build {
    /// This build: its compiled key set (or the lab key file's), serial and
    /// floor.
    pub fn this() -> Self {
        Self {
            key_set: lab_key_set().unwrap_or_else(compiled_key_set),
            serial: BUILD_SERIAL,
            floor: BUILD_ADVISORY_FLOOR,
        }
    }
}

/// Who handed an artifact to this node: the friend who passed it on, or the
/// person (a file they imported). Its events name the friend as the one who
/// passed it on, never as its author.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    /// The contact's device key; `None` for an imported file.
    pub passed_by: Option<[u8; 32]>,
    pub via: Via,
}

impl Origin {
    /// A file the person imported (`raven update import`).
    pub const IMPORTED: Origin = Origin {
        passed_by: None,
        via: Via::Local,
    };

    /// Passed on by the contact `peer` (its device key) over `via`.
    pub fn friend(peer: [u8; 32], via: Via) -> Self {
        Self {
            passed_by: Some(peer),
            via,
        }
    }
}

/// Why an advisory or a log snapshot is forged: it failed a check that only
/// the release keys can pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forgery {
    /// The advisory does not decode (RAVEN_SECURITY_ADVISORY_V1 §5).
    Advisory(Rad1Error),
    /// The advisory is not signed by the current key set (§2.3).
    Signature(SigError),
    /// The log snapshot does not decode (RAVEN_TRANSPARENCY_LOG_V1 §4, §5).
    LogFormat(Rtl1Error),
    /// The log snapshot does not check (§6.1).
    Log(LogCheckError),
}

impl Forgery {
    /// The failed check's own code.
    pub fn code(self) -> &'static str {
        match self {
            Self::Advisory(e) => e.code(),
            Self::Signature(e) => e.code(),
            Self::LogFormat(e) => e.code(),
            Self::Log(e) => e.code(),
        }
    }
}

/// Why the update state took nothing (the state is unchanged unless the
/// refusal froze it: [`Refused::Equivocation`], [`Refused::SplitView`]).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Refused {
    /// [`SecGate::Advisory`] is shut: nothing read or written.
    #[error("UPDATE OFF")]
    Off,
    /// This build has no release key set ([`NO_RELEASE_KEYS_TEXT`]).
    #[error("UPDATE NO_RELEASE_KEYS")]
    NoReleaseKeys,
    /// Frozen ([`UpdateState::frozen`]): nothing new is applied.
    #[error("UPDATE FROZEN")]
    Frozen,
    /// The artifact failed its check: ignored (SEC_ADVISORY_FORGED).
    #[error("UPDATE FORGED {}", .0.code())]
    Forged(Forgery),
    /// Older than the newest advisory known (`newest`, its serial): ignored;
    /// the newer one can be offered back (SEC_ADVISORY_ROLLBACK).
    #[error("UPDATE ROLLBACK")]
    Rollback { newest: u64 },
    /// Another advisory with the newest one's serial, or the next serial
    /// naming another advisory before it: frozen now
    /// (SEC_ADVISORY_EQUIVOCATION).
    #[error("UPDATE EQUIVOCATION")]
    Equivocation,
    /// The log it came with does not list it (SEC_UPDATE_UNLOGGED).
    #[error("UPDATE UNLOGGED")]
    Unlogged,
    /// Signed by a release key set this state never trusted (most often a
    /// `KEY_SET` rotation it has not taken yet): it cannot be checked yet,
    /// so it is ignored with no event, nothing quarantined and no friend
    /// blamed (Phase 6 review updates-protocol-3). An artifact under a set
    /// rotated out since is still forged. raven-node's update exchange
    /// counts it as forged (SEC_ADVISORY_FORGED about that friend) once the
    /// friend that passed it on was asked for the rotation and gave none,
    /// or that friend's catch-ups of the day are spent (Phase 6 review
    /// re-verify).
    #[error("UPDATE UNKNOWN_KEY_SET")]
    UnknownKeySet,
    /// The log contradicts the stored one: frozen now (SEC_LOG_SPLIT_VIEW).
    #[error("UPDATE SPLIT_VIEW")]
    SplitView,
    /// The state file could not be read or written: nothing was taken.
    #[error("UPDATE STATE {0}")]
    Store(String),
}

impl Refused {
    /// A stable name (tests, `--json` later).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Off => "OFF",
            Self::NoReleaseKeys => "NO_RELEASE_KEYS",
            Self::Frozen => "FROZEN",
            Self::Forged(_) => "FORGED",
            Self::Rollback { .. } => "ROLLBACK",
            Self::Equivocation => "EQUIVOCATION",
            Self::Unlogged => "UNLOGGED",
            Self::UnknownKeySet => "UNKNOWN_KEY_SET",
            Self::SplitView => "SPLIT_VIEW",
            Self::Store(_) => "STATE",
        }
    }

    /// The security event the refusal raises (design D sensing points
    /// D1-D4). A forged log snapshot is SEC_ADVISORY_FORGED too: logs travel
    /// with the security notices (an advisory's, or a friend's log on its
    /// own). The gate, the keys, a freeze, a key set this state never
    /// trusted and the state file raise none.
    pub fn sec_kind(&self) -> Option<SecKind> {
        match self {
            Self::Forged(_) => Some(SecKind::AdvisoryForged),
            Self::Rollback { .. } => Some(SecKind::AdvisoryRollback),
            Self::Equivocation => Some(SecKind::AdvisoryEquivocation),
            Self::Unlogged => Some(SecKind::UpdateUnlogged),
            Self::SplitView => Some(SecKind::LogSplitView),
            Self::Off
            | Self::NoReleaseKeys
            | Self::Frozen
            | Self::UnknownKeySet
            | Self::Store(_) => None,
        }
    }
}

/// What an accepted advisory did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The stored advisory itself: nothing changed.
    Unchanged,
    /// Stored as the newest advisory.
    Stored {
        serial: u64,
        /// `FIRST`, `NEXT`, `GAP`, or `SAME` for the build's compiled floor
        /// (whose bytes were not stored before).
        succession: Succession,
        /// The digest of the key set a `KEY_SET` entry rotated to.
        rotated_to: Option<[u8; 32]>,
        /// How the log it came with relates to the stored one (`EXTENDS`:
        /// stored too).
        log: Consistency,
    },
}

/// Why updates are frozen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeReason {
    /// Two advisories with one serial, or a broken chain.
    Equivocation,
    /// Two signed logs that are not prefixes of each other.
    SplitView,
}

/// The evidence a freeze keeps: what this node held and what contradicted
/// it (design D, responses: "keep both as evidence").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub reason: FreezeReason,
    /// When this node froze (Unix ms; shown only).
    pub at_ms: u64,
    /// The key set current when it froze (evidence; no advisory clears a
    /// freeze).
    #[serde(with = "hex_array")]
    pub key_set_digest: [u8; 32],
    /// The build that froze ([`BUILD_SERIAL`]): a higher one, installed by
    /// hand, clears it.
    pub build_serial: u64,
    /// The newest advisory serial known when it froze (0: none).
    pub advisory_serial: u64,
    /// What this node held: the advisory (equivocation) or the signed tree
    /// head (split view). Empty when that was the build's compiled floor.
    #[serde(with = "hex_vec")]
    pub ours: Vec<u8>,
    /// The digest of the advisory, or the root of the tree head, it held.
    #[serde(with = "hex_array")]
    pub ours_digest: [u8; 32],
    /// What contradicted it: the other advisory or signed tree head.
    #[serde(with = "hex_vec")]
    pub theirs: Vec<u8>,
}

/// The file's JSON. The advisory and the log are kept as received (their
/// serial, digest, entries and tree head are read from them), the key set
/// as its bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    #[serde(default)]
    v: u32,
    /// The current key set.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_opt")]
    key_set: Option<Vec<u8>>,
    /// The digests of the key sets this state went through, oldest first;
    /// the current one last.
    #[serde(default, with = "hex_list")]
    key_sets: Vec<[u8; 32]>,
    /// The newest advisory accepted (RAD1 bytes).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_opt")]
    advisory: Option<Vec<u8>>,
    /// The longest log accepted (RTL1 snapshot bytes).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_opt")]
    log: Option<Vec<u8>>,
    #[serde(default)]
    installed_build_serial: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    frozen: Option<Evidence>,
    /// Raven's own last install or rollback (P6.47); an older build drops
    /// it when it writes the state (`raven update rollback` then has
    /// nothing to swap back).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    install: Option<InstallRecord>,
    /// The `KEY_SET` rotations this state applied, oldest first (at most
    /// [`MAX_ROTATIONS`]): each rotation advisory with the log it was
    /// accepted with, both under the set it rotated away from (Phase 6
    /// review updates-protocol-3). An older build drops them when it writes
    /// the state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rotations: Vec<StoredRotation>,
}

/// One kept rotation: RAD1 and RTL1 snapshot bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredRotation {
    #[serde(with = "hex_vec")]
    advisory: Vec<u8>,
    #[serde(with = "hex_vec")]
    log: Vec<u8>,
}

/// What Raven's own last install (or rollback) swapped (P6.47's `raven
/// update install` and `rollback`; design D §5): what a rollback swaps
/// back. Release versions and the program folder only; nothing about a
/// contact or a person.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallRecord {
    /// The folder whose programs were swapped (the running build's).
    pub dir: String,
    /// The programs swapped, by file name: each is `<name>` and, for the
    /// build before, `<name>.prev` (a program one of the two builds lacks
    /// has only one of them).
    pub files: Vec<String>,
    /// The build in place now, and its version.
    pub serial: u64,
    pub version: String,
    /// The build kept as `.prev` (0: a development build), and its version.
    pub prev_serial: u64,
    pub prev_version: String,
}

/// The update state of one profile, with the build reading it.
#[derive(Clone, Debug)]
pub struct UpdateState {
    build: Build,
    key_set: Option<KeySet>,
    /// The current key set's bytes as the file held them: written back
    /// as they were by a build that trusts no key set.
    kept_key_set: Option<Vec<u8>>,
    key_sets: Vec<[u8; 32]>,
    advisory: Option<Advisory>,
    log: Option<Snapshot>,
    installed_build_serial: u64,
    frozen: Option<Evidence>,
    install: Option<InstallRecord>,
    /// The rotations applied, with their logs ([`MAX_ROTATIONS`]).
    rotations: Vec<(Advisory, Snapshot)>,
    /// Something changed since it was read: the file is written.
    changed: bool,
}

impl UpdateState {
    /// Nothing stored yet, read by `build`.
    pub fn empty(build: Build) -> Self {
        Self::from_stored(Stored::default(), build).expect("an empty state reads")
    }

    /// The state the file held, read by `build`: the stored advisory and log
    /// decode again (a state that does not is refused, never read as
    /// empty); the current key set is this build's, or the one a rotation
    /// reached from it ([`resolve_key_set`]); a freeze made by an older
    /// build is cleared.
    fn from_stored(stored: Stored, build: Build) -> Result<Self, String> {
        if stored.v > STATE_VERSION {
            return Err(format!(
                "{UPDATE_STATE_FILE} is version {}, written by a newer Raven",
                stored.v
            ));
        }
        let advisory = stored
            .advisory
            .as_deref()
            .map(Advisory::decode)
            .transpose()
            .map_err(|e| format!("{UPDATE_STATE_FILE}: the stored advisory: {e}"))?;
        let log = stored
            .log
            .as_deref()
            .map(Snapshot::decode)
            .transpose()
            .map_err(|e| format!("{UPDATE_STATE_FILE}: the stored log: {e}"))?;
        let (key_set, key_sets) = resolve_key_set(
            build.key_set.as_ref(),
            stored.key_set.as_deref(),
            stored.key_sets,
        );
        let frozen = stored
            .frozen
            .filter(|evidence| build.serial <= evidence.build_serial);
        // Kept for friends only: one that does not decode is left out (it
        // takes nothing back).
        let rotations = stored
            .rotations
            .iter()
            .filter_map(|r| {
                Some((
                    Advisory::decode(&r.advisory).ok()?,
                    Snapshot::decode(&r.log).ok()?,
                ))
            })
            .collect();
        Ok(Self {
            build,
            key_set,
            kept_key_set: stored.key_set,
            key_sets,
            advisory,
            log,
            installed_build_serial: stored.installed_build_serial,
            frozen,
            install: stored.install,
            rotations,
            changed: false,
        })
    }

    fn to_stored(&self) -> Stored {
        Stored {
            v: STATE_VERSION,
            key_set: self
                .key_set
                .as_ref()
                .map(KeySet::encode)
                .or_else(|| self.kept_key_set.clone()),
            key_sets: self.key_sets.clone(),
            advisory: self.advisory.as_ref().map(|a| a.bytes().to_vec()),
            log: self.log.as_ref().map(Snapshot::encode),
            installed_build_serial: self.installed_build_serial,
            frozen: self.frozen.clone(),
            install: self.install.clone(),
            rotations: self
                .rotations
                .iter()
                .map(|(advisory, log)| StoredRotation {
                    advisory: advisory.bytes().to_vec(),
                    log: log.encode(),
                })
                .collect(),
        }
    }

    /// The build reading the state.
    pub fn build(&self) -> &Build {
        &self.build
    }

    /// The release key set artifacts are checked against now; `None`: this
    /// build has none.
    pub fn key_set(&self) -> Option<&KeySet> {
        self.key_set.as_ref()
    }

    /// The digests of the key sets this state went through, oldest first;
    /// the current one last.
    pub fn key_set_history(&self) -> &[[u8; 32]] {
        &self.key_sets
    }

    /// The newest advisory accepted.
    pub fn advisory(&self) -> Option<&Advisory> {
        self.advisory.as_ref()
    }

    /// The newest advisory known, `(serial, digest)`: the stored one, or
    /// this build's compiled floor when that is newer (RAVEN_SECURITY_ADVISORY_V1
    /// §7: the floor is the lowest stored serial a build accepts). On equal
    /// serials the stored one counts (a different floor digest is
    /// equivocation the next time that advisory arrives).
    pub fn newest(&self) -> Option<(u64, [u8; 32])> {
        let stored = self.advisory.as_ref().map(|a| (a.serial, a.digest()));
        let floor = (self.build.floor.0 > 0).then_some(self.build.floor);
        match (stored, floor) {
            (Some(stored), Some(floor)) if floor.0 > stored.0 => Some(floor),
            (Some(stored), _) => Some(stored),
            (None, floor) => floor,
        }
    }

    /// The longest log accepted (its entries and signed tree head).
    pub fn log(&self) -> Option<&Snapshot> {
        self.log.as_ref()
    }

    /// The kept rotation away from the key set of digest `key_set_digest`:
    /// its advisory (signed by that set) and the log it was accepted with
    /// (under that set too), which a friend still on that set can check
    /// (RUP1 GET_ROTATION).
    pub fn rotation_from(&self, key_set_digest: &[u8; 32]) -> Option<(&Advisory, &Snapshot)> {
        self.rotations
            .iter()
            .find(|(advisory, _)| advisory.key_set_digest == *key_set_digest)
            .map(|(advisory, log)| (advisory, log))
    }

    /// The stored log's entries, oldest first (none: empty).
    pub fn log_entries(&self) -> &[LogEntry] {
        self.log.as_ref().map_or(&[], Snapshot::entries)
    }

    /// The evidence while updates are frozen.
    pub fn frozen(&self) -> Option<&Evidence> {
        self.frozen.as_ref()
    }

    /// The installed build's serial: this build's, or the one an install
    /// recorded when that is higher (P6.47).
    pub fn installed_serial(&self) -> u64 {
        self.build.serial.max(self.installed_build_serial)
    }

    /// The release floor of the stored advisory (its `RELEASE_FLOOR` entry;
    /// 0: none).
    pub fn release_floor(&self) -> u64 {
        self.advisory
            .as_ref()
            .and_then(|a| a.entries.iter().find_map(Entry::release_floor))
            .unwrap_or(0)
    }

    /// What a bundle is verified against (RAVEN_RELEASE_BUNDLE_V1 §7): the
    /// current key set, the stored log, the installed serial, this build's
    /// target and the release floor. An install also checks [`Self::frozen`]
    /// first (P6.47).
    pub fn verify_ctx(&self, allow_downgrade: bool) -> VerifyCtx<'_> {
        VerifyCtx {
            key_set: self.key_set.as_ref(),
            stored_log: self.log_entries(),
            installed_serial: self.installed_serial(),
            target: THIS_TARGET,
            release_floor: self.release_floor(),
            allow_downgrade,
        }
    }

    /// Accept an advisory and the log snapshot it came with, in the
    /// normative order (RAVEN_SECURITY_ADVISORY_V1 §6.1, wire spec W-D1):
    /// decode, the current key set and its threshold signatures, the
    /// serial against [`Self::newest`] (rollback, equivocation), the log
    /// (checked, listing the advisory, consistent with the stored one),
    /// then store it, rotating to the key set its `KEY_SET` entry names.
    /// While frozen nothing is taken (a forged advisory is still refused as
    /// forged); only a release installed by hand clears a freeze.
    pub fn accept_advisory(
        &mut self,
        bytes: &[u8],
        snapshot: &[u8],
        now_ms: u64,
    ) -> Result<Applied, Refused> {
        let key_set = self.key_set.clone().ok_or(Refused::NoReleaseKeys)?;
        let advisory =
            Advisory::decode(bytes).map_err(|e| Refused::Forged(Forgery::Advisory(e)))?;
        advisory
            .verify(&key_set)
            .map_err(|e| self.sig_refused(e, &advisory.key_set_digest, Forgery::Signature))?;
        // Frozen: nothing new is applied. No advisory lifts a freeze (Phase 6
        // review updates-protocol-2): the key set that froze signed two
        // histories, so nothing it signs (a rotation included) can be
        // trusted to end it; only a release installed by hand does.
        if self.frozen.is_some() {
            return Err(Refused::Frozen);
        }
        let newest = self.newest();
        let order = succession(newest, &advisory);
        match order {
            Succession::Rollback => {
                return Err(Refused::Rollback {
                    newest: newest.map_or(0, |(serial, _)| serial),
                });
            }
            Succession::Equivocation => {
                let (serial, digest) = newest.expect("equivocation needs a newest advisory");
                let stored = self.advisory.as_ref().filter(|a| a.serial == serial);
                if advisory.serial == serial {
                    match stored {
                        // The same signed body with another signature block
                        // (a signature dropped from a block above the
                        // threshold, which needs no key): one advisory, not
                        // two histories (Phase 6 review updates-protocol-1).
                        // Nothing changes; a copy its log does not list is
                        // unlogged.
                        Some(stored) if same_body(stored, &advisory) => {
                            let log = self.check_log(&key_set, snapshot)?;
                            if !crate::tlog::contains(
                                log.entries(),
                                EntryType::Advisory,
                                &advisory.digest(),
                            ) {
                                return Err(Refused::Unlogged);
                            }
                            return Ok(Applied::Unchanged);
                        }
                        Some(_) => {}
                        // The compiled floor (no bytes to compare the body
                        // with): only a copy a checked log lists is the
                        // second history.
                        None => {
                            let log = self.check_log(&key_set, snapshot)?;
                            if !crate::tlog::contains(
                                log.entries(),
                                EntryType::Advisory,
                                &advisory.digest(),
                            ) {
                                return Err(Refused::Unlogged);
                            }
                        }
                    }
                }
                let ours = stored.map(|a| a.bytes().to_vec()).unwrap_or_default();
                self.freeze(Evidence {
                    reason: FreezeReason::Equivocation,
                    at_ms: now_ms,
                    key_set_digest: key_set.digest(),
                    build_serial: self.build.serial,
                    advisory_serial: serial.max(advisory.serial),
                    ours,
                    ours_digest: digest,
                    theirs: advisory.bytes().to_vec(),
                });
                return Err(Refused::Equivocation);
            }
            Succession::Same
                if self
                    .advisory
                    .as_ref()
                    .is_some_and(|a| a.serial == advisory.serial) =>
            {
                return Ok(Applied::Unchanged);
            }
            Succession::Same | Succession::First | Succession::Next | Succession::Gap => {}
        }
        let log = self.check_log(&key_set, snapshot)?;
        if !crate::tlog::contains(log.entries(), EntryType::Advisory, &advisory.digest()) {
            return Err(Refused::Unlogged);
        }
        let next = advisory
            .entries
            .iter()
            .find_map(Entry::key_set)
            .filter(|next| next.digest() != key_set.digest());
        let rotation_log = next.is_some().then(|| log.clone());
        let consistency = self.take_log(&key_set, log, now_ms)?;
        let rotated_to = next.map(|next| self.rotate(next));
        if let Some(log) = rotation_log {
            self.keep_rotation(advisory.clone(), log);
        }
        let serial = advisory.serial;
        self.advisory = Some(advisory);
        self.changed = true;
        Ok(Applied::Stored {
            serial,
            succession: order,
            rotated_to,
            log: consistency,
        })
    }

    /// Accept a log snapshot on its own (RAVEN_TRANSPARENCY_LOG_V1 §6):
    /// checked against the current key set, stored when it extends the
    /// stored log (`EXTENDS`), nothing for `SAME` and `OLDER` (the sender is
    /// behind), and a split view freezes.
    pub fn accept_log(&mut self, snapshot: &[u8], now_ms: u64) -> Result<Consistency, Refused> {
        let key_set = self.key_set.clone().ok_or(Refused::NoReleaseKeys)?;
        let log = self.check_log(&key_set, snapshot)?;
        if self.frozen.is_some() {
            return Err(Refused::Frozen);
        }
        self.take_log(&key_set, log, now_ms)
    }

    /// Record the build an install put in place (P6.47).
    pub fn record_installed(&mut self, build_serial: u64) {
        if self.installed_build_serial != build_serial {
            self.installed_build_serial = build_serial;
            self.changed = true;
        }
    }

    /// Raven's own last install or rollback (P6.47): what `raven update
    /// rollback` swaps back.
    pub fn install_record(&self) -> Option<&InstallRecord> {
        self.install.as_ref()
    }

    /// Record what an install or rollback put in place: the build serial
    /// installed now and what it swapped (`None`: nothing to swap back, as
    /// after an install that rolled itself back to before it).
    pub fn record_install(&mut self, build_serial: u64, record: Option<InstallRecord>) {
        self.record_installed(build_serial);
        if self.install != record {
            self.install = record;
            self.changed = true;
        }
    }

    /// Decode and check a snapshot against `key_set` (a refusal is forged,
    /// one under a key set this state never trusted cannot be checked yet).
    fn check_log(&self, key_set: &KeySet, snapshot: &[u8]) -> Result<Snapshot, Refused> {
        let decoded =
            Snapshot::decode(snapshot).map_err(|e| Refused::Forged(Forgery::LogFormat(e)))?;
        let checked = decoded.check(key_set).map_err(|e| match e {
            LogCheckError::Sig(e) => self.sig_refused(e, &decoded.sth().key_set_digest, |e| {
                Forgery::Log(LogCheckError::Sig(e))
            }),
            e => Refused::Forged(Forgery::Log(e)),
        })?;
        Ok(checked.snapshot().clone())
    }

    /// A signature check's refusal of an artifact naming the key set
    /// `signed_by`: [`Refused::UnknownKeySet`] for a set this state never
    /// trusted (not in [`Self::key_set_history`]: a rotation not taken
    /// yet), else forged.
    fn sig_refused(
        &self,
        e: SigError,
        signed_by: &[u8; 32],
        forgery: impl FnOnce(SigError) -> Forgery,
    ) -> Refused {
        if e == SigError::WrongKeySet && !self.key_sets.contains(signed_by) {
            Refused::UnknownKeySet
        } else {
            Refused::Forged(forgery(e))
        }
    }

    /// Keep a rotation applied with the log it came with, the newest
    /// [`MAX_ROTATIONS`].
    fn keep_rotation(&mut self, advisory: Advisory, log: Snapshot) {
        self.rotations
            .retain(|(kept, _)| kept.key_set_digest != advisory.key_set_digest);
        self.rotations.push((advisory, log));
        let excess = self.rotations.len().saturating_sub(MAX_ROTATIONS);
        self.rotations.drain(..excess);
    }

    /// A checked log against the stored one: stored when it extends it, a
    /// freeze when it contradicts it.
    fn take_log(
        &mut self,
        key_set: &KeySet,
        log: Snapshot,
        now_ms: u64,
    ) -> Result<Consistency, Refused> {
        let consistency = crate::tlog::consistency(self.log_entries(), log.entries());
        match consistency {
            Consistency::Split => {
                let (ours, ours_digest) = self.log.as_ref().map_or_else(
                    || (Vec::new(), [0; 32]),
                    |stored| (stored.sth().bytes().to_vec(), stored.sth().root_hash),
                );
                self.freeze(Evidence {
                    reason: FreezeReason::SplitView,
                    at_ms: now_ms,
                    key_set_digest: key_set.digest(),
                    build_serial: self.build.serial,
                    advisory_serial: self.newest().map_or(0, |(serial, _)| serial),
                    ours,
                    ours_digest,
                    theirs: log.sth().bytes().to_vec(),
                });
                Err(Refused::SplitView)
            }
            Consistency::Extends => {
                self.log = Some(log);
                self.changed = true;
                Ok(consistency)
            }
            Consistency::Same | Consistency::Older => Ok(consistency),
        }
    }

    fn freeze(&mut self, evidence: Evidence) {
        self.frozen = Some(evidence);
        self.changed = true;
    }

    /// Rotate to `next` (RAVEN_SECURITY_ADVISORY_V1 §6.2): its digest.
    fn rotate(&mut self, next: KeySet) -> [u8; 32] {
        let digest = next.digest();
        push_history(&mut self.key_sets, digest);
        self.key_set = Some(next);
        digest
    }
}

/// Do two advisories carry the same signed bytes (everything before the
/// signature block)? Then they are one advisory whatever signatures each
/// carries: only the release keys can change those bytes, while anyone can
/// drop a signature from a block above the threshold.
fn same_body(a: &Advisory, b: &Advisory) -> bool {
    a.bytes()[..a.signed_len()] == b.bytes()[..b.signed_len()]
}

/// Append `digest` to a key set history, keeping the newest
/// [`MAX_KEY_SET_HISTORY`].
fn push_history(history: &mut Vec<[u8; 32]>, digest: [u8; 32]) {
    history.push(digest);
    let excess = history.len().saturating_sub(MAX_KEY_SET_HISTORY);
    history.drain(..excess);
}

/// The current key set for a build that trusts `base`, given the stored
/// current set and history: none without a base; the stored current set
/// when the history reached it from `base` (a rotation stays rotated for
/// older and newer builds alike); otherwise `base` itself, appended to the
/// history (a release with a new key set, installed by hand, or another lab
/// key file). A stored current set that does not decode, or is not the
/// history's last, falls back to `base` too.
fn resolve_key_set(
    base: Option<&KeySet>,
    stored: Option<&[u8]>,
    mut history: Vec<[u8; 32]>,
) -> (Option<KeySet>, Vec<[u8; 32]>) {
    let Some(base) = base else {
        return (None, history);
    };
    let digest = base.digest();
    if history.contains(&digest) {
        let current = stored
            .and_then(|bytes| KeySet::decode(bytes).ok())
            .filter(|set| history.last() == Some(&set.digest()));
        if let Some(current) = current {
            return (Some(current), history);
        }
        if history.last() == Some(&digest) {
            return (Some(base.clone()), history);
        }
    }
    push_history(&mut history, digest);
    (Some(base.clone()), history)
}

// ── The file ─────────────────────────────────────────────────────────

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(UPDATE_STATE_FILE)
}

fn store_error(e: impl std::fmt::Display) -> Refused {
    Refused::Store(format!("{UPDATE_STATE_FILE}: {e}"))
}

/// The stored JSON: missing is empty; anything that cannot be read or
/// parsed is refused (fail closed: an empty state would take an old
/// advisory back).
fn read(data_dir: &Path) -> Result<Stored, Refused> {
    match at_rest::load_json_advisory::<Stored>(data_dir, &path(data_dir), Kind::UpdateState) {
        at_rest::Advisory::Missing => Ok(Stored::default()),
        at_rest::Advisory::Loaded(stored) => Ok(stored),
        at_rest::Advisory::CorruptPlain => Err(store_error("does not parse")),
        at_rest::Advisory::Unreadable(e) => Err(store_error(e)),
    }
}

/// The profile's update state as this build reads it. Nothing while the
/// advisory gate is shut.
pub fn load(data_dir: &Path) -> Result<UpdateState, Refused> {
    load_with(data_dir, &Build::this())
}

/// [`load`] read by `build` (tests, and the lab).
#[doc(hidden)]
pub fn load_with(data_dir: &Path, build: &Build) -> Result<UpdateState, Refused> {
    if !security_gate::live(SecGate::Advisory) {
        return Err(Refused::Off);
    }
    UpdateState::from_stored(read(data_dir)?, build.clone()).map_err(Refused::Store)
}

/// Read, change and write the state under its lock: written only when
/// `edit` changed it (a refusal that froze it included).
fn change<T>(
    data_dir: &Path,
    build: &Build,
    edit: impl FnOnce(&mut UpdateState) -> Result<T, Refused>,
) -> Result<T, Refused> {
    let path = path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::UpdateState).map_err(store_error)?;
    let mut state =
        UpdateState::from_stored(read(data_dir)?, build.clone()).map_err(Refused::Store)?;
    let out = edit(&mut state);
    if state.changed {
        lock.store_json(&state.to_stored()).map_err(store_error)?;
        crate::suite_policy::note_written();
    }
    out
}

/// A refusal's event, about the update `origin` handed over.
fn note_refused(out: &Result<impl Sized, Refused>, origin: Origin) {
    if let Some(kind) = out.as_ref().err().and_then(Refused::sec_kind) {
        crate::security_sense::update(kind, origin.passed_by, origin.via);
    }
}

/// Accept an advisory (RAD1 `bytes`) and the RTL1 `snapshot` it came with
/// into the profile's update state ([`UpdateState::accept_advisory`]),
/// noting a refusal's event about `origin`, or SEC_ADVISORY_APPLIED when it
/// was stored (P6.45; [`crate::suite_policy`] applies it from then on).
/// Nothing while the advisory gate is shut; nothing is read or written
/// without release keys.
pub fn accept_advisory(
    data_dir: &Path,
    bytes: &[u8],
    snapshot: &[u8],
    origin: Origin,
) -> Result<Applied, Refused> {
    accept_advisory_with(data_dir, &Build::this(), bytes, snapshot, origin)
}

/// [`accept_advisory`] by `build` (tests, and the lab).
#[doc(hidden)]
pub fn accept_advisory_with(
    data_dir: &Path,
    build: &Build,
    bytes: &[u8],
    snapshot: &[u8],
    origin: Origin,
) -> Result<Applied, Refused> {
    if !security_gate::live(SecGate::Advisory) {
        return Err(Refused::Off);
    }
    if build.key_set.is_none() {
        return Err(Refused::NoReleaseKeys);
    }
    let out = change(data_dir, build, |state| {
        state.accept_advisory(bytes, snapshot, now_ms())
    });
    note_refused(&out, origin);
    if matches!(out, Ok(Applied::Stored { .. })) {
        crate::security_sense::update(SecKind::AdvisoryApplied, origin.passed_by, origin.via);
    }
    out
}

/// Accept an RTL1 `snapshot` on its own ([`UpdateState::accept_log`]): a
/// friend's log, or a bundle's before the bundle is verified (so a split
/// view freezes before anything else happens), noting a refusal's event
/// about `origin`. Nothing while the advisory gate is shut; nothing is
/// read or written without release keys.
pub fn accept_log(
    data_dir: &Path,
    snapshot: &[u8],
    origin: Origin,
) -> Result<Consistency, Refused> {
    accept_log_with(data_dir, &Build::this(), snapshot, origin)
}

/// [`accept_log`] by `build` (tests, and the lab).
#[doc(hidden)]
pub fn accept_log_with(
    data_dir: &Path,
    build: &Build,
    snapshot: &[u8],
    origin: Origin,
) -> Result<Consistency, Refused> {
    if !security_gate::live(SecGate::Advisory) {
        return Err(Refused::Off);
    }
    if build.key_set.is_none() {
        return Err(Refused::NoReleaseKeys);
    }
    let out = change(data_dir, build, |state| {
        state.accept_log(snapshot, now_ms())
    });
    note_refused(&out, origin);
    out
}

/// Record the build an install put in place (P6.47's `raven update
/// install` and `rollback`). Nothing while the advisory gate is shut.
pub fn record_installed(data_dir: &Path, build_serial: u64) -> Result<(), Refused> {
    if !security_gate::live(SecGate::Advisory) {
        return Err(Refused::Off);
    }
    change(data_dir, &Build::this(), |state| {
        state.record_installed(build_serial);
        Ok(())
    })
}

/// Record what Raven's own install or rollback put in place
/// ([`UpdateState::record_install`]), read by `build`. Nothing while the
/// advisory gate is shut.
pub fn record_install_with(
    data_dir: &Path,
    build: &Build,
    build_serial: u64,
    record: Option<InstallRecord>,
) -> Result<(), Refused> {
    if !security_gate::live(SecGate::Advisory) {
        return Err(Refused::Off);
    }
    change(data_dir, build, |state| {
        state.record_install(build_serial, record);
        Ok(())
    })
}

/// Note the event a refused bundle raises (`BundleError::sec_kind`; design
/// D sensing points D4, D5), about `origin`. A bundle's log goes through
/// [`accept_log`] first, which freezes on a split view and notes it, so a
/// verified bundle never meets a split view here.
pub fn note_bundle_refusal(error: BundleError, origin: Origin) {
    if let Some(kind) = error.sec_kind() {
        crate::security_sense::update(kind, origin.passed_by, origin.via);
    }
}

// ── JSON helpers ─────────────────────────────────────────────────────

pub(crate) mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

mod hex_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_some(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| hex::decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

pub(crate) mod hex_list {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        v: &[[u8; N]],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(hex::encode))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<Vec<[u8; N]>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|s| {
                hex::decode(&s)
                    .map_err(serde::de::Error::custom)?
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("wrong length"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
