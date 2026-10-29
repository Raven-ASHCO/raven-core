//! `raven update` (Phase 6 P6.47; `docs/roadmap/plans/phase6-design.json`
//! design D §5, owner decisions OD6b-24, OD6b-25, OD6b-26): Raven's own
//! updates, behind `RELEASE_BUNDLE` (still false; a debug build opens it with
//! `RAVEN_LAB_RELEASE_BUNDLE=1` on top of `RAVEN_LAB_ADVISORY=1` and
//! `RAVEN_LAB_TEST_A=1`). Security notices and release log snapshots need only
//! the advisory gate.
//!
//! - `raven update status`: the security notices, this build, what waits to
//!   be installed and what an install kept to go back to.
//! - `raven update import FILE`: a release bundle (`.rrb`), a security notice
//!   (`.rad1`, with the release log snapshot that lists it) or a release log
//!   snapshot (`.rtl1`), told apart by their first bytes. A bundle's log goes
//!   to the update state first (a split view freezes there), then the bundle
//!   is verified in full (`verify_bundle`, spec §7) and its files are
//!   staged: extracted by offset into `updates/staged/<build serial>/` (0700;
//!   files 0600, never executable) and hashed again from the disk. At most
//!   two builds stay staged.
//! - `raven update verify FILE`: the same checks against the update state;
//!   nothing is stored and no event is noted.
//! - `raven update install`: the newest staged build newer than this one,
//!   verified again against the update state as it is now. It shows the
//!   version, the notes (sanitized), who signed it, its place in the release
//!   log and its size, and goes on only after the person types `install`
//!   (`downgrade` for an older build, which also needs `--allow-downgrade`;
//!   never below the release floor). Raven swaps its own programs only when
//!   the running program's folder (`current_exe`) is writable, holds Raven's
//!   programs (raven-node among them, none of them a link) and no package
//!   manager owns it: the new programs are copied beside the old ones and
//!   synced, the node stops, each old program is renamed to `<name>.prev`,
//!   each new one is renamed into place, the node starts and must answer
//!   `Ping` within 20 s, else every program goes back and the node starts
//!   again. Otherwise it prints the manual steps and changes nothing. Never
//!   `sudo`, never a script, never a file from a bundle run before the swap.
//!   A release names its command-line program `bin/ash` (the build scripts
//!   ship `ash`, `raven-node` and `raven-swarm`); the installers install it
//!   as `raven`, with `ash` beside it as a link to it (macOS, Linux) or as a
//!   second copy (Windows). The swap replaces whichever of `raven` and `ash`
//!   is a regular file there with the release's `ash`, and never writes
//!   through a link: `ash -> raven` (or the tarball's `raven -> ash`) stays
//!   and names the new program ([`installed_names`]).
//! - `raven update rollback`: swaps each `<name>` and `<name>.prev` back
//!   (typed `rollback`; a warning when the build it goes back to is below
//!   the release floor), with the same health check.
//!
//! Only this process (the CLI or the terminal app) writes `updates/staged/`
//! or a program folder; raven-node stages and installs nothing. The program
//! folder ([`InstallFs`]) and the node ([`NodeHost`]) are seams: the tests
//! use a temp prefix with fake programs that note when they run, and a mock
//! file system with Windows' rules (a running program can be renamed, but
//! not replaced or deleted), which [`Rules::Windows`] follows everywhere.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use raven_core::advisory::{Advisory, MAX_RAD1_LEN, RAD1_MAGIC};
use raven_core::release_bundle::{
    verify_bundle, Authority, BundleError, Container, FileMode, Manifest, Parts, VerifiedBundle,
    MAX_CONTAINER_LEN, MAX_MANIFEST_LEN, RRBC_MAGIC,
};
use raven_core::release_keys::KeySet;
use raven_core::release_sign::sha256;
use raven_core::sanitize::{sanitize_terminal_line, sanitize_terminal_text};
use raven_core::security_gate::{self, SecGate};
use raven_core::tlog::{Checked, Consistency, EntryType, Snapshot, MAX_SNAPSHOT_LEN, RTL1_MAGIC};
use raven_core::update_state::{
    self, Applied, Build, InstallRecord, Origin, Refused, UpdateState, MAX_STAGED_BUILDS,
    STAGED_DIR,
};

mod download;
#[cfg(test)]
mod tests;

pub(super) use download::cmd_download;

/// What `raven update` says while the bundle gate (or the advisory gate it
/// sits on) is shut.
pub(super) const OFF_TEXT: &str = "Raven updates are not part of this version.";
/// Every update text repeats it (design D, UX).
pub(super) const NEVER_WITHOUT_ASKING: &str = "Raven never installs anything without asking you.";
/// The word an install is confirmed with.
pub(super) const INSTALL_WORD: &str = "install";
/// The word an install of an older build is confirmed with (OD6b-26).
pub(super) const DOWNGRADE_WORD: &str = "downgrade";
/// The word a rollback is confirmed with.
pub(super) const ROLLBACK_WORD: &str = "rollback";
/// The new node must answer `Ping` within this (design D §5).
pub(super) const HEALTH_WAIT: Duration = Duration::from_secs(20);
/// What `raven update install` says with nothing staged.
pub(super) const NOTHING_WAITING: &str =
    "No Raven update is waiting. Import one first: raven update import FILE";
/// What `raven update rollback` says with nothing to go back to.
pub(super) const NOTHING_TO_GO_BACK: &str = "Raven has no earlier version to go back to: it keeps \
     one after `raven update install` replaced its programs.";

/// A staged build's files besides its programs and documents (raven-node
/// reads them too, to serve staged builds to friends: P6.49).
const MANIFEST_NAME: &str = update_state::STAGED_MANIFEST;
const SNAPSHOT_NAME: &str = update_state::STAGED_SNAPSHOT;
const ADVISORY_NAME: &str = update_state::STAGED_ADVISORY;
/// What a release log folder calls its snapshot (the ceremony's log kit).
const LOG_SNAPSHOT_NAME: &str = "snapshot.rtl1";
/// Beside each swapped program: the build before.
const PREV_SUFFIX: &str = ".prev";
/// A new program copied beside the old one, before the swap.
const NEW_SUFFIX: &str = ".raven-new";
/// A program moved out of the way (Windows: one that may be running).
const ASIDE_SUFFIX: &str = ".raven-old";
/// A program on its way between `<name>` and `<name>.prev` (rollback).
const SWAP_SUFFIX: &str = ".raven-swap";
/// Staging leftovers of an interrupted import are removed after this.
const LEFTOVER_AGE: Duration = Duration::from_secs(60 * 60);
/// The program every release carries and the health check asks.
const NODE_PROGRAM: &str = "raven-node";
/// The command-line program as a release names it (`bin/ash`).
const CLI_PROGRAM: &str = "ash";
/// What the installers name the command-line program: `raven` (a copy of
/// `ash`), with `ash` beside it as a link to it (macOS, Linux, unless
/// another `ash` shell is on the system) or as a second copy (Windows).
const CLI_INSTALLED: &str = "raven";

/// The update commands that change something (bundles, install,
/// rollback): the bundle gate, and the advisory gate below it.
pub(super) fn live() -> bool {
    security_gate::live(SecGate::ReleaseBundle)
}

/// Security notices and log snapshots on their own: the advisory gate.
fn notices_live() -> bool {
    security_gate::live(SecGate::Advisory)
}

fn shown(path: &Path) -> String {
    sanitize_terminal_line(&path.display().to_string())
}

/// This build's version, as people read it.
pub(super) fn this_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// "Raven 1.5.0 (build 5)", or "(a development build)" for serial 0.
fn build_name(version: &str, serial: u64) -> String {
    if serial == 0 {
        format!("Raven {version} (a development build)")
    } else {
        format!("Raven {version} (build {serial})")
    }
}

/// A size as people read it: kB below a megabyte, else MB with one decimal.
pub(super) fn size_text(bytes: u64) -> String {
    if bytes < 1_000_000 {
        format!("{} kB", bytes.div_ceil(1_000).max(1))
    } else {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    }
}

// ── The update state ─────────────────────────────────────────────────────────

/// The profile's update state as `build` reads it: refused while the gate is
/// shut, and for a build without release keys.
fn open_state(data_dir: &Path, build: &Build) -> Result<UpdateState, String> {
    let state = update_state::load_with(data_dir, build).map_err(|e| refused_text(&e))?;
    if state.key_set().is_none() {
        return Err(update_state::NO_RELEASE_KEYS_TEXT.to_owned());
    }
    Ok(state)
}

/// What a refusal of the update state says.
fn refused_text(refused: &Refused) -> String {
    match refused {
        Refused::Off => OFF_TEXT.to_owned(),
        Refused::NoReleaseKeys => update_state::NO_RELEASE_KEYS_TEXT.to_owned(),
        Refused::Frozen | Refused::Equivocation | Refused::SplitView => {
            raven_core::suite_policy::FROZEN_TEXT.to_owned()
        }
        Refused::Forged(_) => "This file failed its check: it is not from the Raven project. \
             Raven ignored it."
            .to_owned(),
        Refused::Rollback { newest } => format!(
            "This security notice is older than the one Raven has (#{newest}). Raven kept the \
             newer one."
        ),
        Refused::Unlogged => "This file is not listed in the Raven release log it came with. \
             Raven ignored it."
            .to_owned(),
        Refused::UnknownKeySet => "This file is signed by Raven release keys this Raven does \
             not know yet. Import the security notice that introduced them first (with its \
             log), or update Raven. Raven ignored it."
            .to_owned(),
        Refused::Store(why) => format!(
            "Raven can't read its update state right now ({}).",
            sanitize_terminal_line(why)
        ),
    }
}

// ── Files people hand over ───────────────────────────────────────────────────

/// What a file holds, by its first four bytes.
pub(super) enum Artifact {
    /// A release bundle (RRBC), decoded; nothing verified yet.
    Bundle(Box<Parts>),
    /// A security notice (RAD1 bytes).
    Advisory(Vec<u8>),
    /// A release log snapshot (RTL1 bytes).
    Log(Vec<u8>),
}

/// Read a file someone handed over: each kind capped before it is read.
pub(super) fn read_artifact(path: &Path) -> Result<Artifact, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", shown(path)))?;
    let len = file
        .metadata()
        .map_err(|e| format!("{}: {e}", shown(path)))?
        .len();
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return Err(not_an_update(path));
    }
    let rest = (&magic[..]).chain(file);
    match &magic {
        m if m == RRBC_MAGIC => {
            if len > MAX_CONTAINER_LEN {
                return Err(format!(
                    "{} is larger than any Raven release bundle.",
                    shown(path)
                ));
            }
            Container::open(io::BufReader::new(rest))
                .map(|parts| Artifact::Bundle(Box::new(parts)))
                .map_err(|e| {
                    format!(
                        "{} is not a Raven release bundle Raven can read ({}).",
                        shown(path),
                        e.code()
                    )
                })
        }
        m if m == RAD1_MAGIC => read_capped(rest, MAX_RAD1_LEN, path).map(Artifact::Advisory),
        m if m == RTL1_MAGIC => read_capped(rest, MAX_SNAPSHOT_LEN, path).map(Artifact::Log),
        _ => Err(not_an_update(path)),
    }
}

fn not_an_update(path: &Path) -> String {
    format!(
        "{} is not a Raven update file (a release bundle .rrb, a security notice .rad1 or a \
         release log snapshot .rtl1).",
        shown(path)
    )
}

/// At most `cap` bytes of `reader`; more is refused.
fn read_capped(reader: impl Read, cap: usize, path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", shown(path)))?;
    if bytes.len() > cap {
        return Err(format!(
            "{} is larger than any Raven update file of its kind.",
            shown(path)
        ));
    }
    Ok(bytes)
}

/// The release log snapshot a security notice is checked with: `--log`, or
/// `snapshot.rtl1` beside it or one folder up (a release log folder keeps
/// notices in `advisories/`).
fn log_for(advisory: &Path, given: Option<&Path>) -> Result<Vec<u8>, String> {
    let candidates: Vec<PathBuf> = match given {
        Some(path) => vec![path.to_path_buf()],
        None => {
            let folder = advisory.parent().unwrap_or(Path::new("."));
            [Some(folder), folder.parent()]
                .into_iter()
                .flatten()
                .map(|dir| dir.join(LOG_SNAPSHOT_NAME))
                .filter(|path| path.is_file())
                .collect()
        }
    };
    let Some(path) = candidates.first() else {
        return Err(
            "A security notice is checked against the Raven release log that lists it: \
                    give its snapshot with --log FILE (snapshot.rtl1 in the release log folder)."
                .to_owned(),
        );
    };
    match read_artifact(path)? {
        Artifact::Log(bytes) => Ok(bytes),
        _ => Err(format!(
            "{} is not a Raven release log snapshot.",
            shown(path)
        )),
    }
}

// ── What a verified bundle is ────────────────────────────────────────────────

/// What `install` (and `import`) shows of a verified bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Summary {
    pub(super) serial: u64,
    pub(super) version: String,
    /// "signed by 2 of the 3 Raven project keys", or how the log vouches.
    pub(super) signers: String,
    /// "listed in the public release log (entry 3 of 3)".
    pub(super) log: String,
    pub(super) size: String,
    /// The release notes, sanitized (may be empty).
    pub(super) notes: String,
}

impl Summary {
    fn of(verified: &VerifiedBundle<'_>, key_set: &KeySet) -> Self {
        let manifest = verified.manifest();
        Summary {
            serial: manifest.build_serial,
            version: manifest.version.clone(),
            signers: signers_text(manifest, key_set, verified.authority()),
            log: log_text(verified.log(), &manifest.digest()),
            size: size_text(manifest.payload_len),
            notes: sanitize_terminal_text(manifest.notes.trim()),
        }
    }

    /// "Raven 1.5.0 (build 5)".
    pub(super) fn name(&self) -> String {
        build_name(&self.version, self.serial)
    }

    /// "It is signed by ... and listed in ...".
    pub(super) fn checked_line(&self) -> String {
        format!("It is {} and {}.", self.signers, self.log)
    }
}

fn signers_text(manifest: &Manifest, key_set: &KeySet, authority: Authority) -> String {
    match authority {
        Authority::Signed => format!(
            "signed by {} of the {} Raven project keys",
            manifest.sigs().sigs().len(),
            key_set.keys().len()
        ),
        Authority::Logged => "vouched for by the Raven project keys in use now (it was signed \
                              by the keys used before them)"
            .to_owned(),
    }
}

fn log_text(log: &Checked, digest: &[u8; 32]) -> String {
    let entries = log.entries();
    let at = entries
        .iter()
        .position(|e| e.kind == EntryType::Manifest && &e.digest == digest)
        .map_or(0, |i| i + 1);
    format!(
        "listed in the public release log (entry {at} of {})",
        entries.len()
    )
}

/// What a refused bundle says (spec §7.2), about the release it names.
fn bundle_refusal_text(error: BundleError, parts: &Parts, state: &UpdateState) -> String {
    let manifest = &parts.manifest;
    let name = build_name(&manifest.version, manifest.build_serial);
    // The floor checked: the stored notice's, raised by the bundle's own.
    let floor = parts
        .advisory
        .iter()
        .flat_map(|a| a.entries.iter())
        .find_map(|e| e.release_floor())
        .unwrap_or(0)
        .max(state.release_floor());
    match error {
        BundleError::NoReleaseKeys => update_state::NO_RELEASE_KEYS_TEXT.to_owned(),
        BundleError::WrongTarget => format!(
            "{name} is for another kind of computer ({}), not this one. Raven didn't keep it.",
            sanitize_terminal_line(&manifest.target)
        ),
        BundleError::Downgrade => format!(
            "{name} is not newer than the Raven you have (build {}). To go back to it anyway: \
             raven update import FILE --allow-downgrade, then raven update install \
             --allow-downgrade.",
            state.installed_serial()
        ),
        BundleError::BelowFloor => format!(
            "{name} has a known security problem (a security notice from the Raven project asks \
             for build {floor} or later). Raven won't install it."
        ),
        BundleError::SplitView => raven_core::suite_policy::FROZEN_TEXT.to_owned(),
        BundleError::Unlogged | BundleError::AdvisoryUnlogged => {
            format!("{name} is not listed in the public Raven release log. Raven ignored it.")
        }
        BundleError::AdvisorySig(_)
        | BundleError::ManifestSig(_)
        | BundleError::Log(_)
        | BundleError::PayloadLength
        | BundleError::BadChunkRoot
        | BundleError::BadPayloadHash
        | BundleError::BadFileHash(_) => format!(
            "This file failed its check ({}): it is not a release of the Raven project. Raven \
             ignored it and runs nothing from it.",
            error.code()
        ),
    }
}

// ── Staging ──────────────────────────────────────────────────────────────────

/// A staged file's name in its build's folder: its index and its last
/// segment (`1-raven-node`), so the folder stays flat
/// ([`update_state::staged_file_name`]).
fn staged_name(index: usize, path: &str) -> String {
    update_state::staged_file_name(index, path)
}

fn staged_root(data_dir: &Path) -> PathBuf {
    data_dir.join(STAGED_DIR)
}

/// A folder (and those above it, up to the profile) owner only.
fn private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// A new file, owner only (never executable), written and synced.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// A staged file's hash, read back from the disk (at most 64 MiB).
fn sha256_of_file(path: &Path) -> io::Result<[u8; 32]> {
    Ok(sha256(&std::fs::read(path)?))
}

fn sync_dir(dir: &Path) {
    raven_core::paths::sync_dir_best_effort(dir);
}

/// Stage a verified bundle into `updates/staged/<build serial>/`: written
/// into a temp folder, every file hashed again from the disk, then renamed
/// into place (a build staged before under that serial is replaced). Only
/// the newest [`MAX_STAGED_BUILDS`] stay, this one always among them.
pub(super) fn stage(data_dir: &Path, verified: &VerifiedBundle<'_>) -> Result<PathBuf, String> {
    let root = staged_root(data_dir);
    let failed = |e: &dyn std::fmt::Display| format!("Raven couldn't keep the update ({e}).");
    private_dir(&root).map_err(|e| failed(&e))?;
    let serial = verified.manifest().build_serial;
    let tmp = root.join(format!(
        ".tmp-{serial}-{}",
        hex::encode(rand::random::<[u8; 8]>())
    ));
    private_dir(&tmp).map_err(|e| failed(&e))?;
    let written = (|| -> Result<(), String> {
        let write = |name: &str, bytes: &[u8]| write_private(&tmp.join(name), bytes);
        write(MANIFEST_NAME, verified.manifest().bytes()).map_err(|e| failed(&e))?;
        write(SNAPSHOT_NAME, &verified.log().snapshot().encode()).map_err(|e| failed(&e))?;
        if let Some(advisory) = verified.advisory() {
            write(ADVISORY_NAME, advisory.bytes()).map_err(|e| failed(&e))?;
        }
        for (i, (entry, bytes)) in verified.files().enumerate() {
            let path = tmp.join(staged_name(i, &entry.path));
            write_private(&path, bytes).map_err(|e| failed(&e))?;
            if sha256_of_file(&path).map_err(|e| failed(&e))? != entry.sha256 {
                return Err(format!(
                    "Raven's copy of {} does not match the release: the disk may be failing. \
                     Nothing was kept.",
                    entry.path
                ));
            }
        }
        sync_dir(&tmp);
        Ok(())
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    let dest = root.join(serial.to_string());
    if dest.exists() {
        let old = root.join(format!(
            ".old-{serial}-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        if let Err(e) = std::fs::rename(&dest, &old) {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(failed(&e));
        }
        let _ = std::fs::remove_dir_all(&old);
    }
    if let Err(e) = std::fs::rename(&tmp, &dest) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(failed(&e));
    }
    sync_dir(&root);
    prune_staged(&root, serial, raven_core::clock::system_now());
    Ok(dest)
}

/// Keep `kept` and the newest other builds up to [`MAX_STAGED_BUILDS`];
/// remove an interrupted import's leftovers once they are an hour old.
fn prune_staged(root: &Path, kept: u64, now: SystemTime) {
    let Ok(list) = std::fs::read_dir(root) else {
        return;
    };
    let mut builds = Vec::new();
    for entry in list.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Ok(serial) = name.parse::<u64>() {
            if serial != kept {
                builds.push((serial, path));
            }
        } else if name.starts_with(".tmp-") || name.starts_with(".old-") {
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|at| now.duration_since(at).unwrap_or_default() >= LEFTOVER_AGE);
            if old {
                let _ = std::fs::remove_dir_all(&path);
            }
        }
    }
    builds.sort_by_key(|b| std::cmp::Reverse(b.0));
    for (_, path) in builds.into_iter().skip(MAX_STAGED_BUILDS.saturating_sub(1)) {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// A build in `updates/staged/<serial>/`, as read back.
#[derive(Debug, Clone)]
pub(super) struct Staged {
    pub(super) serial: u64,
    pub(super) dir: PathBuf,
    pub(super) manifest: Manifest,
    snapshot: Snapshot,
    advisory: Option<Advisory>,
}

impl Staged {
    fn read(dir: &Path, serial: u64) -> Result<Staged, String> {
        let read = |name: &str, cap: usize| -> Result<Vec<u8>, String> {
            let path = dir.join(name);
            let file = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", shown(&path)))?;
            read_capped(file, cap, &path)
        };
        let manifest = Manifest::decode(&read(MANIFEST_NAME, MAX_MANIFEST_LEN)?)
            .map_err(|e| format!("a staged manifest: {}", e.code()))?;
        if manifest.build_serial != serial {
            return Err("a staged manifest is in the wrong folder".to_owned());
        }
        let snapshot = Snapshot::decode(&read(SNAPSHOT_NAME, MAX_SNAPSHOT_LEN)?)
            .map_err(|e| format!("a staged log: {}", e.code()))?;
        let advisory = if dir.join(ADVISORY_NAME).exists() {
            Some(
                Advisory::decode(&read(ADVISORY_NAME, MAX_RAD1_LEN)?)
                    .map_err(|e| format!("a staged notice: {}", e.code()))?,
            )
        } else {
            None
        };
        Ok(Staged {
            serial,
            dir: dir.to_path_buf(),
            manifest,
            snapshot,
            advisory,
        })
    }

    /// File `index` of the manifest, as staged.
    pub(super) fn file(&self, index: usize) -> PathBuf {
        self.dir
            .join(staged_name(index, &self.manifest.files[index].path))
    }

    /// The bundle again, from the staged files (each exactly its size), for
    /// a full verification.
    fn parts(&self) -> Result<Parts, String> {
        let mut payload = Vec::with_capacity(self.manifest.payload_len as usize);
        for (i, entry) in self.manifest.files.iter().enumerate() {
            let path = self.file(i);
            let file = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", shown(&path)))?;
            let bytes = read_capped(file, entry.size as usize, &path)?;
            if bytes.len() as u64 != entry.size {
                return Err(format!("{} is not the size the release says", shown(&path)));
            }
            payload.extend_from_slice(&bytes);
        }
        Ok(Parts {
            manifest: self.manifest.clone(),
            snapshot: self.snapshot.clone(),
            advisory: self.advisory.clone(),
            payload,
        })
    }
}

/// The staged builds, newest first; one that can't be read is skipped.
pub(super) fn staged_builds(data_dir: &Path) -> Vec<Staged> {
    let Ok(list) = std::fs::read_dir(staged_root(data_dir)) else {
        return Vec::new();
    };
    let mut out: Vec<Staged> = list
        .flatten()
        .filter_map(|entry| {
            let serial = entry.file_name().to_str()?.parse::<u64>().ok()?;
            Staged::read(&entry.path(), serial).ok()
        })
        .collect();
    out.sort_by_key(|s| std::cmp::Reverse(s.serial));
    out
}

/// The build `install` takes: the newest one newer than `installed`, else
/// (an explicit downgrade) the newest one.
fn choose(staged: &[Staged], installed: u64, allow_downgrade: bool) -> Option<&Staged> {
    staged
        .iter()
        .find(|s| s.serial > installed)
        .or_else(|| staged.first().filter(|_| allow_downgrade))
}

// ── import and verify ────────────────────────────────────────────────────────

/// What `import` and `verify` take.
#[derive(Debug, Clone, Default)]
pub(super) struct FileArgs {
    pub(super) file: PathBuf,
    /// The release log snapshot of a security notice.
    pub(super) log: Option<PathBuf>,
    pub(super) allow_downgrade: bool,
}

/// `raven update import FILE`: check it and keep it (a bundle staged, a
/// notice applied, a log stored). Its lines, or why it was refused.
pub(super) fn import(
    data_dir: &Path,
    build: &Build,
    args: &FileArgs,
) -> Result<Vec<String>, String> {
    if !notices_live() {
        return Err(OFF_TEXT.to_owned());
    }
    let origin = Origin::IMPORTED;
    match read_artifact(&args.file)? {
        Artifact::Bundle(parts) => import_bundle(data_dir, build, &parts, args.allow_downgrade),
        Artifact::Advisory(bytes) => {
            let log = log_for(&args.file, args.log.as_deref())?;
            match update_state::accept_advisory_with(data_dir, build, &bytes, &log, origin) {
                Ok(Applied::Stored { serial, .. }) => {
                    let mut lines = vec![format!(
                        "Security notice #{serial} from the Raven project is checked (signed by \
                         the Raven project keys and listed in the public release log) and \
                         applied."
                    )];
                    lines.extend(raven_core::suite_policy::status_lines(
                        data_dir,
                        raven_core::clock::now_ms(),
                    ));
                    Ok(lines)
                }
                Ok(Applied::Unchanged) => {
                    Ok(vec!["Raven has this security notice already.".to_owned()])
                }
                Err(e) => Err(refused_text(&e)),
            }
        }
        Artifact::Log(bytes) => {
            match update_state::accept_log_with(data_dir, build, &bytes, origin) {
                Ok(Consistency::Extends) => Ok(vec![
                    "Raven's copy of the public release log is up to date with this one."
                        .to_owned(),
                ]),
                Ok(_) => Ok(vec![
                    "Raven has this release log (or a newer one) already.".to_owned()
                ]),
                Err(e) => Err(refused_text(&e)),
            }
        }
    }
}

fn import_bundle(
    data_dir: &Path,
    build: &Build,
    parts: &Parts,
    allow_downgrade: bool,
) -> Result<Vec<String>, String> {
    import_bundle_from(data_dir, build, parts, allow_downgrade, Origin::IMPORTED)
}

/// [`import_bundle`] of a bundle `origin` handed over (a file, or a friend's
/// complete download, P6.49).
fn import_bundle_from(
    data_dir: &Path,
    build: &Build,
    parts: &Parts,
    allow_downgrade: bool,
    origin: Origin,
) -> Result<Vec<String>, String> {
    stage_bundle(data_dir, build, parts, allow_downgrade, origin).map_err(NotStaged::text)
}

/// Why a bundle was not staged (Phase 6 review updates-protocol-7): what
/// the person reads either way.
pub(super) enum NotStaged {
    /// Refused: the bundle's checks, or this profile's state (frozen, a
    /// newer build installed since, a security notice): nothing is kept.
    Refused(String),
    /// Not now: the gate, the update state file or the disk. Nothing
    /// changed; it can be tried again.
    Later(String),
}

impl NotStaged {
    pub(super) fn text(self) -> String {
        match self {
            Self::Refused(why) | Self::Later(why) => why,
        }
    }
}

/// [`import_bundle_from`] with why it was not staged.
fn stage_bundle(
    data_dir: &Path,
    build: &Build,
    parts: &Parts,
    allow_downgrade: bool,
    origin: Origin,
) -> Result<Vec<String>, NotStaged> {
    if !live() {
        return Err(NotStaged::Later(OFF_TEXT.to_owned()));
    }
    let refused = |e: &Refused| match e {
        Refused::Store(_) | Refused::Off => NotStaged::Later(refused_text(e)),
        _ => NotStaged::Refused(refused_text(e)),
    };
    // The log first: a split view freezes before anything else happens.
    update_state::accept_log_with(data_dir, build, &parts.snapshot.encode(), origin)
        .map_err(|e| refused(&e))?;
    let state = update_state::load_with(data_dir, build).map_err(|e| refused(&e))?;
    let Some(key_set) = state.key_set().cloned() else {
        return Err(NotStaged::Refused(
            update_state::NO_RELEASE_KEYS_TEXT.to_owned(),
        ));
    };
    if state.frozen().is_some() {
        return Err(NotStaged::Refused(
            raven_core::suite_policy::FROZEN_TEXT.to_owned(),
        ));
    }
    let verified = match verify_bundle(parts, &state.verify_ctx(allow_downgrade)) {
        Ok(verified) => verified,
        Err(e) => {
            update_state::note_bundle_refusal(e, origin);
            return Err(NotStaged::Refused(bundle_refusal_text(e, parts, &state)));
        }
    };
    // The notice it carries is the update state's to take (or not: an
    // older one, the same one).
    if let Some(advisory) = verified.advisory() {
        let taken = update_state::accept_advisory_with(
            data_dir,
            build,
            advisory.bytes(),
            &parts.snapshot.encode(),
            origin,
        );
        if let Err(e @ (Refused::Equivocation | Refused::SplitView | Refused::Frozen)) = taken {
            return Err(NotStaged::Refused(refused_text(&e)));
        }
    }
    let summary = Summary::of(&verified, &key_set);
    stage(data_dir, &verified).map_err(NotStaged::Later)?;
    let older = summary.serial <= state.installed_serial();
    Ok(vec![
        format!(
            "{} for this computer ({}) is checked and ready to install.",
            summary.name(),
            summary.size
        ),
        summary.checked_line(),
        if older {
            "It is not newer than this Raven: install it with raven update install \
             --allow-downgrade."
                .to_owned()
        } else {
            "Install it with: raven update install".to_owned()
        },
        NEVER_WITHOUT_ASKING.to_owned(),
    ])
}

/// `raven update verify FILE`: the same checks as `import` against the
/// update state as it is; nothing stored, no event noted.
pub(super) fn verify(
    data_dir: &Path,
    build: &Build,
    args: &FileArgs,
) -> Result<Vec<String>, String> {
    if !notices_live() {
        return Err(OFF_TEXT.to_owned());
    }
    let state = open_state(data_dir, build)?;
    let key_set = state.key_set().cloned().expect("open_state has keys");
    match read_artifact(&args.file)? {
        Artifact::Bundle(parts) => {
            if !live() {
                return Err(OFF_TEXT.to_owned());
            }
            let verified = verify_bundle(&parts, &state.verify_ctx(args.allow_downgrade))
                .map_err(|e| bundle_refusal_text(e, &parts, &state))?;
            let summary = Summary::of(&verified, &key_set);
            let mut lines = vec![
                format!(
                    "{} for this computer ({}) checks.",
                    summary.name(),
                    summary.size
                ),
                summary.checked_line(),
            ];
            if !summary.notes.is_empty() {
                lines.push(format!("What's new: {}", summary.notes));
            }
            lines.push("Nothing was kept: raven update import FILE keeps it.".to_owned());
            Ok(lines)
        }
        Artifact::Advisory(bytes) => {
            let log = log_for(&args.file, args.log.as_deref())?;
            let mut copy = state;
            match copy.accept_advisory(&bytes, &log, raven_core::clock::now_ms()) {
                Ok(Applied::Stored { serial, .. }) => Ok(vec![format!(
                    "Security notice #{serial} checks: signed by the Raven project keys and \
                     listed in the public release log. Nothing was kept: raven update import \
                     FILE applies it."
                )]),
                Ok(Applied::Unchanged) => {
                    Ok(vec!["Raven has this security notice already.".to_owned()])
                }
                Err(e) => Err(verify_refused_text(&e)),
            }
        }
        Artifact::Log(bytes) => {
            let mut copy = state;
            copy.accept_log(&bytes, raven_core::clock::now_ms())
                .map(|_| {
                    vec!["This release log checks: signed by the Raven project keys.".to_owned()]
                })
                .map_err(|e| verify_refused_text(&e))
        }
    }
}

/// What `verify` says of a refusal: nothing was stored, so a contradiction
/// froze nothing yet.
fn verify_refused_text(refused: &Refused) -> String {
    match refused {
        Refused::Equivocation | Refused::SplitView => "This file contradicts what Raven has: \
             two different versions of the Raven release history. Importing it would stop \
             updates until this is cleared up."
            .to_owned(),
        other => refused_text(other),
    }
}

// ── status ───────────────────────────────────────────────────────────────────

/// `raven update status`'s own lines (after the security notices'): this
/// build, the release log, what waits and what an install kept.
pub(super) fn update_lines(data_dir: &Path, build: &Build) -> Vec<String> {
    if !live() {
        return Vec::new();
    }
    let state = match update_state::load_with(data_dir, build) {
        Ok(state) => state,
        Err(e) => return vec![refused_text(&e)],
    };
    let mut lines = vec![format!(
        "This Raven: {}.",
        installed_name(&state, this_version())
    )];
    if state.key_set().is_none() {
        return lines;
    }
    if let Some(log) = state.log() {
        let n = log.entries().len();
        lines.push(format!(
            "Public release log: {n} {} checked.",
            if n == 1 { "entry" } else { "entries" }
        ));
    }
    let staged = staged_builds(data_dir);
    lines.push(match choose(&staged, state.installed_serial(), false) {
        Some(ready) => format!(
            "Updates: {} is ready to install (raven update install).",
            build_name(&ready.manifest.version, ready.serial)
        ),
        None => "Updates: none waiting.".to_owned(),
    });
    // Friends' offers and downloads (P6.49).
    lines.extend(download::download_lines(data_dir));
    if let Some(record) = state.install_record() {
        lines.push(format!(
            "{} is kept to go back to (raven update rollback).",
            build_name(&record.prev_version, record.prev_serial)
        ));
    }
    lines.push(NEVER_WITHOUT_ASKING.to_owned());
    lines
}

/// The installed build's name: the version the last install noted when it
/// is that build, else this build's.
fn installed_name(state: &UpdateState, version: &str) -> String {
    let installed = state.installed_serial();
    let version = state
        .install_record()
        .filter(|record| record.serial == installed)
        .map_or(version, |record| record.version.as_str());
    build_name(version, installed)
}

/// The terminal app's NET row: "1.5.0 ready to install", "none waiting";
/// None while the gate is shut or without keys.
pub(super) fn net_row(data_dir: &Path, build: &Build) -> Option<String> {
    if !live() {
        return None;
    }
    let state = update_state::load_with(data_dir, build).ok()?;
    state.key_set()?;
    let staged = staged_builds(data_dir);
    Some(match choose(&staged, state.installed_serial(), false) {
        Some(ready) => format!(
            "{} ready to install",
            sanitize_terminal_line(&ready.manifest.version)
        ),
        None => "none waiting".to_owned(),
    })
}

// ── The program folder ───────────────────────────────────────────────────────

/// What swapping programs goes through: the real folder, or the tests'
/// mock with Windows' rules.
pub(super) trait InstallFs {
    /// Whether this user can create files in `dir`.
    fn dir_writable(&self, dir: &Path) -> bool;
    /// A regular file (a link is not one).
    fn is_file(&self, path: &Path) -> bool;
    /// Anything at all there (a link too).
    fn exists(&self, path: &Path) -> bool;
    /// A new file with these bytes and this mode, synced; never replaces one.
    fn write_new(&self, path: &Path, bytes: &[u8], mode: FileMode) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove(&self, path: &Path) -> io::Result<()>;
    fn sync_dir(&self, dir: &Path);
}

/// The real file system.
pub(super) struct RealFs;

impl InstallFs for RealFs {
    fn dir_writable(&self, dir: &Path) -> bool {
        let probe = dir.join(format!(
            ".raven-write-check-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
        {
            Ok(_) => {
                let _ = std::fs::remove_file(&probe);
                true
            }
            Err(_) => false,
        }
    }

    fn is_file(&self, path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
    }

    fn exists(&self, path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    fn write_new(&self, path: &Path, bytes: &[u8], mode: FileMode) -> io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode.unix_mode());
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut file = opts.open(path)?;
        file.write_all(bytes)?;
        #[cfg(unix)]
        {
            // The umask may have taken bits off.
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(mode.unix_mode()))?;
        }
        file.sync_all()
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn sync_dir(&self, dir: &Path) {
        sync_dir(dir);
    }
}

/// How a program folder's files can be renamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rules {
    /// A rename replaces what is there, atomically, running or not.
    Unix,
    /// A running program can be renamed, but not replaced or deleted: what
    /// is in the way is renamed aside first.
    Windows,
}

impl Rules {
    pub(super) const THIS: Rules = if cfg!(windows) {
        Rules::Windows
    } else {
        Rules::Unix
    };
}

/// `path` with `suffix` added to its file name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// A name beside `path` that nothing has yet (`.raven-old`, `.raven-old-2`).
fn free_name(fs: &dyn InstallFs, path: &Path, suffix: &str) -> PathBuf {
    let first = with_suffix(path, suffix);
    if !fs.exists(&first) {
        return first;
    }
    (2..)
        .map(|n| with_suffix(path, &format!("{suffix}-{n}")))
        .find(|p| !fs.exists(p))
        .expect("a free name")
}

/// `from` renamed to `to`, replacing what is at `to`. Windows can't replace
/// a running program, so it is renamed aside first (and deleted when it
/// can be; a running one stays aside).
fn replace(fs: &dyn InstallFs, rules: Rules, from: &Path, to: &Path) -> io::Result<()> {
    if rules == Rules::Windows && fs.exists(to) {
        let aside = free_name(fs, to, ASIDE_SUFFIX);
        fs.rename(to, &aside)?;
        if let Err(e) = fs.rename(from, to) {
            let _ = fs.rename(&aside, to);
            return Err(e);
        }
        let _ = fs.remove(&aside);
        return Ok(());
    }
    fs.rename(from, to)
}

/// `path` out of the way: deleted, or (a running program on Windows)
/// renamed aside.
fn discard(fs: &dyn InstallFs, rules: Rules, path: &Path) -> io::Result<()> {
    if !fs.exists(path) {
        return Ok(());
    }
    match rules {
        Rules::Unix => fs.remove(path),
        Rules::Windows => {
            let aside = free_name(fs, path, ASIDE_SUFFIX);
            fs.rename(path, &aside)?;
            let _ = fs.remove(&aside);
            Ok(())
        }
    }
}

/// Where the running program lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Place {
    pub(super) dir: PathBuf,
}

impl Place {
    /// The running program's folder (`current_exe`, links resolved).
    pub(super) fn this() -> Result<Place, String> {
        let exe = std::env::current_exe()
            .map_err(|e| format!("Raven can't find its own programs ({e})."))?;
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        let dir = exe
            .parent()
            .ok_or("Raven can't find its own programs' folder.")?
            .to_path_buf();
        Ok(Place { dir })
    }
}

/// The name of a program as this system writes it (`raven-node.exe`).
fn program_file(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

/// One program of a release to swap in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Swap {
    /// The program's file name in the folder.
    name: String,
    /// Its index in the manifest.
    index: usize,
    mode: FileMode,
}

/// Why Raven can't swap its programs in a folder, for the manual steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotHere {
    NotWritable,
    PackageManager,
    NotRavens,
    Layout,
}

/// The release's programs (`bin/<name>`): each one's index in the manifest
/// and its name; a program in a folder below `bin/` is [`NotHere::Layout`].
fn release_programs(manifest: &Manifest) -> Result<Vec<(usize, &str)>, NotHere> {
    let mut programs = Vec::new();
    for (index, entry) in manifest.files.iter().enumerate() {
        let mut segments = entry.path.split('/');
        if segments.next() != Some("bin") {
            continue;
        }
        let name = segments.next().unwrap_or_default();
        if segments.next().is_some() {
            return Err(NotHere::Layout);
        }
        programs.push((index, name));
    }
    Ok(programs)
}

/// The files in `dir` the release's program `name` replaces: itself, but
/// for the command-line program ([`CLI_PROGRAM`], `ash`), which replaces
/// each of the installed `raven` ([`CLI_INSTALLED`]) and `ash` that is a
/// regular file there (Windows keeps two copies). A link is never written
/// through: the installers' `ash -> raven` and the tarball's `raven -> ash`
/// stay as they are and name the new program. With neither one a file it
/// is `ash` itself (a program the release adds, or a link [`plan_swap`]
/// refuses). A release that ships `raven` too is taken name by name.
fn installed_names(fs: &dyn InstallFs, dir: &Path, name: &str, ships_raven: bool) -> Vec<String> {
    let Some(suffix) = program_suffix(name, CLI_PROGRAM).filter(|_| !ships_raven) else {
        return vec![name.to_owned()];
    };
    let files: Vec<String> = [CLI_INSTALLED, CLI_PROGRAM]
        .into_iter()
        .map(|stem| format!("{stem}{suffix}"))
        .filter(|installed| fs.is_file(&dir.join(installed)))
        .collect();
    if files.is_empty() {
        vec![name.to_owned()]
    } else {
        files
    }
}

/// The suffix of `name` when it is the program `stem` as a release for any
/// system names it (`ash`, `ash.exe`): a release is built for one target,
/// so its own names say which, whatever system checks it.
fn program_suffix<'a>(name: &'a str, stem: &str) -> Option<&'a str> {
    name.strip_prefix(stem)
        .filter(|rest| rest.is_empty() || *rest == ".exe")
}

/// Each of the release's programs with the files in `dir` it replaces
/// ([`installed_names`]), in manifest order.
fn program_targets(
    fs: &dyn InstallFs,
    dir: &Path,
    manifest: &Manifest,
) -> Result<Vec<(usize, Vec<String>)>, NotHere> {
    let programs = release_programs(manifest)?;
    let ships_raven = programs
        .iter()
        .any(|(_, name)| program_suffix(name, CLI_INSTALLED).is_some());
    Ok(programs
        .into_iter()
        .map(|(index, name)| (index, installed_names(fs, dir, name, ships_raven)))
        .collect())
}

/// What an install swaps in `place`, or why Raven can't (nothing changes).
fn plan_swap(
    fs: &dyn InstallFs,
    place: &Place,
    manifest: &Manifest,
    node_program: &str,
) -> Result<Vec<Swap>, NotHere> {
    let mut swaps = Vec::new();
    for (index, names) in program_targets(fs, &place.dir, manifest)? {
        for name in names {
            swaps.push(Swap {
                name,
                index,
                mode: manifest.files[index].mode,
            });
        }
    }
    if package_managed(&place.dir) {
        return Err(NotHere::PackageManager);
    }
    // The folder holds Raven's programs: raven-node is in the release and
    // here as a file, and none of the files the release replaces is a link
    // (someone else keeps those; the command-line program's alias links are
    // not among them: [`installed_names`]).
    let node_here = swaps
        .iter()
        .any(|s| s.name == node_program && fs.is_file(&place.dir.join(&s.name)));
    let linked = swaps.iter().any(|s| {
        let path = place.dir.join(&s.name);
        fs.exists(&path) && !fs.is_file(&path)
    });
    if !node_here || linked {
        return Err(NotHere::NotRavens);
    }
    if !fs.dir_writable(&place.dir) {
        return Err(NotHere::NotWritable);
    }
    Ok(swaps)
}

/// A folder a package manager keeps (Homebrew's Cellar, Nix's store, a
/// snap): its programs are updated by it, never swapped by Raven.
fn package_managed(dir: &Path) -> bool {
    let text = dir.to_string_lossy();
    dir.components().any(|c| c.as_os_str() == "Cellar")
        || text.starts_with("/nix/store/")
        || text.starts_with("/snap/")
}

/// The manual steps (design D, UX: "Not writable"): each checked program
/// over the files it replaces ([`installed_names`]).
fn manual_steps(fs: &dyn InstallFs, why: NotHere, place: &Place, staged: &Staged) -> Vec<String> {
    let dir = shown(&place.dir);
    let mut lines = vec![match why {
        NotHere::NotWritable => format!(
            "Raven can't replace its own programs in {dir}: this user can't change that folder. \
             Install it the way you installed Raven:"
        ),
        NotHere::PackageManager => format!(
            "Raven can't replace its own programs in {dir}: a package manager keeps them. Update \
             Raven with that package manager, or install it the way you installed Raven:"
        ),
        NotHere::NotRavens => format!(
            "Raven can't replace its own programs in {dir}: that folder doesn't hold Raven's \
             programs as Raven expects (raven-node, no links). Install it the way you installed \
             Raven:"
        ),
        NotHere::Layout => "Raven can't place this release's programs itself (they are in a \
                            folder of their own). Install it the way you installed Raven:"
            .to_owned(),
    }];
    lines.push("  1. Stop Raven: raven lock, and quit the terminal app.".to_owned());
    lines.push(format!(
        "  2. Copy each checked program over the one in {dir}, with the rights that folder needs:"
    ));
    match program_targets(fs, &place.dir, &staged.manifest) {
        Ok(targets) => {
            for (i, names) in targets {
                for name in names {
                    lines.push(format!(
                        "       {}  ->  {}",
                        shown(&staged.file(i)),
                        shown(&place.dir.join(name))
                    ));
                }
            }
        }
        Err(_) => {
            for (i, entry) in staged.manifest.files.iter().enumerate() {
                if let Some(name) = entry.path.strip_prefix("bin/") {
                    lines.push(format!(
                        "       {}  ->  {}",
                        shown(&staged.file(i)),
                        shown(&place.dir.join(name))
                    ));
                }
            }
        }
    }
    if !cfg!(windows) {
        lines.push("     and make them executable (chmod 755).".to_owned());
    }
    lines.push("  3. Start Raven again: raven unlock".to_owned());
    lines
        .push("Raven never asks for an administrator's rights and never runs a script.".to_owned());
    lines
}

// ── The node around the swap ─────────────────────────────────────────────────

/// The profile's raven-node around a swap: the real one, or the tests'.
pub(super) trait NodeHost {
    /// Stop it and wait until it is gone; why not otherwise (nothing has
    /// changed yet).
    fn stop(&mut self) -> Result<(), String>;
    /// Start it from the program folder (the programs there now).
    fn start(&mut self) -> Result<(), String>;
    /// It answers `Ping` within `wait`.
    fn healthy(&mut self, wait: Duration) -> bool;
    /// It runs locked by Lock v2 (P6.40): an update would start it again
    /// unlocked (a keychain profile's) and on the default address (a locked
    /// node tells none), so none is installed or rolled back until `raven
    /// unlock` (review lock-updates-local-6).
    fn locked(&mut self) -> bool {
        false
    }
    /// The node started from the new programs didn't answer: end it (the
    /// one this process started too, should it hang), as far as it can.
    fn stop_failed(&mut self) {
        let _ = self.stop();
    }
}

/// This profile's real raven-node: Raven's own login item for it when there
/// is one (unloaded for the session, then loaded again), else the stop rules
/// and the start a send uses, on the address the stopped node listened on.
pub(super) struct LiveHost<'a> {
    data_dir: &'a Path,
    /// A node the terminal app started (Windows may end only that one).
    started_by_app: Option<u32>,
    env: Option<super::node_control::LoginEnv>,
    item: Option<super::node_control::LoginItem>,
    /// The node the first stop found, where no login item starts it again.
    before: Option<Before>,
    /// The node this process started last (not through a login item),
    /// while it runs.
    started: Option<u32>,
}

/// The node an install or a rollback stopped first (review
/// lock-updates-local-6 and -7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Before {
    /// One ran (it answered, or did not answer but was there).
    pub(super) ran: bool,
    /// Where its LAN listener was (`Status.lan_listen`, else the address
    /// it failed to bind, `lan_listen_wanted`); unknown while LAN is off
    /// (a locked node is never stopped for an update: [`NodeHost::locked`]).
    pub(super) listen: Option<String>,
    /// It ran locked by Lock v2 (`Status.locked`).
    pub(super) locked: bool,
}

impl Before {
    /// This profile's node now, asked once.
    fn read(data_dir: &Path) -> Self {
        use raven_core::ipc::{IpcRequest, IpcResponse};
        match super::ipc_client::ipc_request_timeout(
            data_dir,
            &IpcRequest::status(),
            Duration::from_secs(3),
        ) {
            Ok(IpcResponse::Status {
                lan_listen,
                lan_listen_wanted,
                locked,
                ..
            }) => Before {
                ran: true,
                listen: lan_listen.or(lan_listen_wanted),
                locked: locked == Some(true),
            },
            Err(e) if super::ipc_client::error_means_not_running(&e) => Before::default(),
            _ => Before {
                ran: true,
                listen: None,
                locked: false,
            },
        }
    }
}

/// How long a stopped node may take to be gone.
const STOP_CONFIRM_WAIT: Duration = Duration::from_secs(5);

/// A node Lock v2 locked is not updated (review lock-updates-local-6): a
/// restart would start a keychain profile's unlocked, and where no login
/// item starts it, on the default address (a locked node tells none).
const LOCKED_INSTALL_TEXT: &str =
    "Raven is locked: run raven unlock first, then raven update install.";
const LOCKED_ROLLBACK_TEXT: &str =
    "Raven is locked: run raven unlock first, then raven update rollback.";
/// It locked between the question and the stop.
const LOCKED_NOW_TEXT: &str =
    "Raven locked meanwhile, so it was not updated: run raven unlock, then try again. Nothing \
     was changed.";

impl<'a> LiveHost<'a> {
    pub(super) fn new(data_dir: &'a Path, started_by_app: Option<u32>) -> Self {
        // A debug build without the login-item lab switches reads no login
        // item: a node one runs then fails to stop, and nothing changes.
        let env = super::node_control::LoginEnv::current().ok();
        let item = env
            .as_ref()
            .and_then(|env| super::node_control::own_login_item(env, data_dir));
        LiveHost {
            data_dir,
            started_by_app,
            env,
            item,
            before: None,
            started: None,
        }
    }

    /// The node this host started from this process, as the terminal
    /// app's own (review lock-updates-local-7): only when the one it
    /// replaced was the app's (`started_by_app`) or none ran, as the app's
    /// own start decides it; never one a login item started.
    pub(super) fn adopted(&self) -> Option<u32> {
        let replaced_own =
            self.started_by_app.is_some() || self.before.as_ref().is_some_and(|b| !b.ran);
        self.started.filter(|_| replaced_own)
    }
}

impl NodeHost for LiveHost<'_> {
    fn stop(&mut self) -> Result<(), String> {
        use super::node_control;
        if self.before.is_none() {
            // Where it listened, and whether one ran at all (started again
            // by this process, where no login item does), and whether it
            // locked since the update was confirmed: nothing is stopped.
            let before = Before::read(self.data_dir);
            if before.locked {
                return Err(LOCKED_NOW_TEXT.to_owned());
            }
            self.before = Some(before);
        }
        let unload_failed = match (&self.env, &self.item) {
            (Some(env), Some(item)) => node_control::stop_for_session(env, item).err(),
            _ => None,
        };
        let (outcome, stopped_pid) = node_control::stop_as(self.data_dir, self.started_by_app);
        match node_control::wait_gone(self.data_dir, STOP_CONFIRM_WAIT) {
            node_control::Gone::Yes => Ok(()),
            node_control::Gone::No { pid } => {
                let restarted = matches!(outcome, node_control::StopOutcome::Stopped)
                    && pid.is_some()
                    && pid != stopped_pid;
                let advice = super::ext::profile_stop_advice(self.data_dir, pid);
                let how = if restarted {
                    format!(
                        "it is run by a service Raven didn't install; stop that service ({advice})"
                    )
                } else {
                    format!("stop it yourself ({advice})")
                };
                let mut text = format!(
                    "Raven is still running, so it can't be updated: {how}, then run raven \
                     update install again. Nothing was changed."
                );
                if let Some(e) = unload_failed {
                    text.push_str(&format!(" Unloading Raven's login item failed: {e}."));
                }
                Err(text)
            }
        }
    }

    fn start(&mut self) -> Result<(), String> {
        match (&self.env, &self.item) {
            (Some(env), Some(item)) => super::node_control::enable_login_item(env, item, true),
            _ => {
                let was = self.before.as_ref().and_then(|b| b.listen.as_deref());
                super::ext::ensure_lan_daemon_as_before(self.data_dir, was)?;
                self.started = super::ext::started_daemon_pid();
                Ok(())
            }
        }
    }

    fn locked(&mut self) -> bool {
        super::ext::node_runs_locked(self.data_dir)
    }

    fn stop_failed(&mut self) {
        // A node that hangs answers no Status, so the stop rules can't find
        // it: the one this process started is ended first.
        let _ = super::ext::end_started_daemon();
        self.started = None;
        let _ = self.stop();
    }

    fn healthy(&mut self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            if super::ipc_client::ipc_daemon_up_within(self.data_dir, Duration::from_secs(1)) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

// ── install ──────────────────────────────────────────────────────────────────

/// What an install or a rollback works with.
pub(super) struct Ctx<'a> {
    pub(super) data_dir: &'a Path,
    pub(super) build: &'a Build,
    pub(super) fs: &'a dyn InstallFs,
    pub(super) rules: Rules,
    pub(super) place: Place,
    /// This build's version (the `.prev` an install keeps).
    pub(super) version: &'a str,
    /// The program the health check needs (`raven-node`, with `.exe` on
    /// Windows).
    pub(super) node_program: String,
    /// How long the started node has to answer.
    pub(super) health_wait: Duration,
}

impl<'a> Ctx<'a> {
    /// The real program folder and file system of this build.
    pub(super) fn live(data_dir: &'a Path, build: &'a Build) -> Result<Self, String> {
        Ok(Ctx {
            data_dir,
            build,
            fs: &RealFs,
            rules: Rules::THIS,
            place: Place::this()?,
            version: this_version(),
            node_program: program_file(NODE_PROGRAM),
            health_wait: HEALTH_WAIT,
        })
    }
}

/// What `install` was asked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct InstallArgs {
    pub(super) allow_downgrade: bool,
    /// The terminal app's: the build it showed, and nothing else.
    pub(super) expect_serial: Option<u64>,
}

/// An install ready to be confirmed: what it shows and what it swaps.
pub(super) struct Ready {
    pub(super) summary: Summary,
    /// The lines shown before the typed word.
    pub(super) lines: Vec<String>,
    /// `install`, or `downgrade` for an older build.
    pub(super) word: &'static str,
    staged: Staged,
    swaps: Vec<Swap>,
    /// The installed build's serial and what the last install swapped,
    /// before this one (put back if it rolls back).
    before: (u64, Option<InstallRecord>),
}

/// Before anything is confirmed: ready, or the manual steps.
pub(super) enum Prepared {
    Ready(Box<Ready>),
    Manual(Vec<String>),
}

/// How an install (or a rollback) ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum End {
    /// In place, and the node answered.
    Done(Vec<String>),
    /// The new programs didn't start: the old ones are back.
    RolledBack(Vec<String>),
    /// Raven printed how; nothing changed.
    Manual(Vec<String>),
}

/// Everything `install` checks before it asks: the gate, the update state
/// (keys, no freeze), a lock, the staged build verified again in full, and
/// whether Raven may swap its programs here.
pub(super) fn prepare(ctx: &Ctx<'_>, args: InstallArgs) -> Result<Prepared, String> {
    prepare_with(ctx, args, true)
}

/// [`prepare`]; `note`: a refused build notes its event (not when the
/// terminal app only looks).
fn prepare_with(ctx: &Ctx<'_>, args: InstallArgs, note: bool) -> Result<Prepared, String> {
    if !live() {
        return Err(OFF_TEXT.to_owned());
    }
    let state = open_state(ctx.data_dir, ctx.build)?;
    if state.frozen().is_some() {
        return Err(raven_core::suite_policy::FROZEN_TEXT.to_owned());
    }
    if raven_core::privacy::lock_state(ctx.data_dir).locked_by_user {
        return Err(LOCKED_INSTALL_TEXT.to_owned());
    }
    let installed = state.installed_serial();
    let staged = staged_builds(ctx.data_dir);
    let chosen = choose(&staged, installed, args.allow_downgrade)
        .ok_or_else(|| NOTHING_WAITING.to_owned())?
        .clone();
    if args
        .expect_serial
        .is_some_and(|serial| serial != chosen.serial)
    {
        return Err("The update waiting to be installed changed meanwhile: look again.".to_owned());
    }
    let parts = chosen.parts()?;
    let key_set = state.key_set().cloned().expect("open_state has keys");
    let verified = match verify_bundle(&parts, &state.verify_ctx(args.allow_downgrade)) {
        Ok(verified) => verified,
        Err(e) => {
            if note {
                update_state::note_bundle_refusal(e, Origin::IMPORTED);
            }
            return Err(bundle_refusal_text(e, &parts, &state));
        }
    };
    let summary = Summary::of(&verified, &key_set);
    let swaps = match plan_swap(ctx.fs, &ctx.place, &chosen.manifest, &ctx.node_program) {
        Ok(swaps) => swaps,
        Err(why) => {
            return Ok(Prepared::Manual(manual_steps(
                ctx.fs, why, &ctx.place, &chosen,
            )))
        }
    };
    let downgrade = chosen.serial <= installed;
    let mut lines = vec![format!(
        "{} is ready to install ({}). {}",
        summary.name(),
        summary.size,
        summary.checked_line()
    )];
    if downgrade {
        lines.push(format!(
            "It is not newer than this Raven ({}): Raven would go back to an older version.",
            installed_name(&state, ctx.version)
        ));
    }
    lines.push(format!(
        "Raven will replace its programs in {} and restart. Your messages and friends stay. The \
         programs it has now are kept, to go back with raven update rollback.",
        shown(&ctx.place.dir)
    ));
    if !summary.notes.is_empty() {
        lines.push(format!("What's new: {}", summary.notes));
    }
    lines.push(NEVER_WITHOUT_ASKING.to_owned());
    let before = (installed, state.install_record().cloned());
    Ok(Prepared::Ready(Box::new(Ready {
        summary,
        lines,
        word: if downgrade {
            DOWNGRADE_WORD
        } else {
            INSTALL_WORD
        },
        staged: chosen,
        swaps,
        before,
    })))
}

/// The new programs, copied beside the old ones and synced.
fn place_new(ctx: &Ctx<'_>, ready: &Ready) -> Result<Vec<(String, PathBuf)>, String> {
    let mut placed: Vec<(String, PathBuf)> = Vec::new();
    for swap in &ready.swaps {
        let to = ctx.place.dir.join(format!(".{}{NEW_SUFFIX}", swap.name));
        let written = discard(ctx.fs, ctx.rules, &to).and_then(|()| {
            let bytes = std::fs::read(ready.staged.file(swap.index))?;
            let entry = &ready.staged.manifest.files[swap.index];
            if bytes.len() as u64 != entry.size || sha256(&bytes) != entry.sha256 {
                return Err(io::Error::other("the staged copy changed"));
            }
            ctx.fs.write_new(&to, &bytes, swap.mode)
        });
        if let Err(e) = written {
            for (_, path) in &placed {
                let _ = ctx.fs.remove(path);
            }
            let _ = ctx.fs.remove(&to);
            return Err(format!(
                "Raven couldn't copy its new programs into {} ({e}). Nothing was changed.",
                shown(&ctx.place.dir)
            ));
        }
        placed.push((swap.name.clone(), to));
    }
    ctx.fs.sync_dir(&ctx.place.dir);
    Ok(placed)
}

/// One program swapped in: whether there was one before (now `.prev`),
/// and where the `.prev` of the install before went meanwhile.
#[derive(Debug, Clone)]
struct Swapped {
    name: String,
    had_old: bool,
    kept_prev: Option<PathBuf>,
}

/// Each old program renamed to `<name>.prev` (a `.prev` of the install
/// before moved aside first, so a rollback puts it back too), each new one
/// renamed into place; on a failure what was swapped is put back.
fn swap_in(ctx: &Ctx<'_>, placed: &[(String, PathBuf)]) -> Result<Vec<Swapped>, String> {
    let mut done: Vec<Swapped> = Vec::new();
    for (name, new) in placed {
        let current = ctx.place.dir.join(name);
        let prev = with_suffix(&current, PREV_SUFFIX);
        let had_old = ctx.fs.exists(&current);
        let mut kept_prev = None;
        let step = (|| {
            if had_old && ctx.fs.exists(&prev) {
                let aside = free_name(ctx.fs, &prev, ASIDE_SUFFIX);
                ctx.fs.rename(&prev, &aside)?;
                kept_prev = Some(aside);
            }
            if had_old {
                replace(ctx.fs, ctx.rules, &current, &prev)?;
            }
            if let Err(e) = ctx.fs.rename(new, &current) {
                if had_old {
                    let _ = replace(ctx.fs, ctx.rules, &prev, &current);
                }
                return Err(e);
            }
            Ok(())
        })();
        if let Err(e) = step {
            if let Some(aside) = &kept_prev {
                let _ = ctx.fs.rename(aside, &prev);
            }
            let _ = swap_out(ctx, &done);
            for (_, path) in placed {
                let _ = ctx.fs.remove(path);
            }
            return Err(format!(
                "Raven couldn't replace its programs ({e}); it put back the ones it had. Nothing \
                 was lost."
            ));
        }
        done.push(Swapped {
            name: name.clone(),
            had_old,
            kept_prev,
        });
    }
    ctx.fs.sync_dir(&ctx.place.dir);
    Ok(done)
}

/// What [`swap_in`] did, undone (newest first): the old programs back from
/// `.prev`, the `.prev` before them back too, the programs the release
/// added gone.
fn swap_out(ctx: &Ctx<'_>, done: &[Swapped]) -> Result<(), String> {
    for swapped in done.iter().rev() {
        let current = ctx.place.dir.join(&swapped.name);
        let prev = with_suffix(&current, PREV_SUFFIX);
        let undone = if swapped.had_old {
            replace(ctx.fs, ctx.rules, &prev, &current)
        } else {
            discard(ctx.fs, ctx.rules, &current)
        };
        undone.map_err(|e| {
            format!(
                "Raven couldn't put back {} ({e}): rename {} back to {} by hand.",
                swapped.name,
                shown(&prev),
                shown(&current)
            )
        })?;
        if let Some(aside) = &swapped.kept_prev {
            let _ = ctx.fs.rename(aside, &prev);
        }
    }
    ctx.fs.sync_dir(&ctx.place.dir);
    Ok(())
}

/// The install answered: the `.prev` programs of the install before go
/// (a running one on Windows stays aside).
fn forget_kept(ctx: &Ctx<'_>, done: &[Swapped]) {
    for aside in done.iter().filter_map(|s| s.kept_prev.as_ref()) {
        let _ = ctx.fs.remove(aside);
    }
}

/// Carry out a confirmed install: the new programs placed, the node
/// stopped, the swap, the record, the node started and checked; back to the
/// old programs when it doesn't answer.
pub(super) fn carry_out(
    ctx: &Ctx<'_>,
    ready: &Ready,
    host: &mut dyn NodeHost,
) -> Result<End, String> {
    let placed = place_new(ctx, ready)?;
    if let Err(e) = host.stop() {
        for (_, path) in &placed {
            let _ = ctx.fs.remove(path);
        }
        return Err(e);
    }
    let done = match swap_in(ctx, &placed) {
        Ok(done) => done,
        Err(e) => {
            let _ = host.start();
            return Err(e);
        }
    };
    let summary = &ready.summary;
    let (prev_serial, prev_record) = ready.before.clone();
    let record = InstallRecord {
        dir: ctx.place.dir.to_string_lossy().into_owned(),
        files: done.iter().map(|s| s.name.clone()).collect(),
        serial: summary.serial,
        version: summary.version.clone(),
        prev_serial,
        prev_version: prev_record
            .as_ref()
            .filter(|r| r.serial == prev_serial)
            .map_or_else(|| ctx.version.to_owned(), |r| r.version.clone()),
    };
    let prev_name = build_name(&record.prev_version, prev_serial);
    let mut notes = Vec::new();
    if let Err(e) =
        update_state::record_install_with(ctx.data_dir, ctx.build, summary.serial, Some(record))
    {
        notes.push(format!(
            "Raven couldn't note the install ({}): raven update rollback won't know it.",
            refused_text(&e)
        ));
    }
    let started = host.start();
    if started.is_ok() && host.healthy(ctx.health_wait) {
        forget_kept(ctx, &done);
        let mut lines = vec![
            format!("{} is installed and running.", summary.name()),
            format!("{prev_name} is kept: raven update rollback goes back to it."),
        ];
        lines.extend(notes);
        return Ok(End::Done(lines));
    }
    // It didn't answer: the old programs go back, and run again.
    host.stop_failed();
    if let Err(e) = swap_out(ctx, &done) {
        return Err(format!("{} didn't start, and {e}", summary.name()));
    }
    let _ = update_state::record_install_with(ctx.data_dir, ctx.build, prev_serial, prev_record);
    let restarted = host.start().is_ok() && host.healthy(ctx.health_wait);
    let mut lines = vec![format!(
        "{} didn't start, so Raven went back to {prev_name}. Nothing was lost.",
        summary.name()
    )];
    if let Err(e) = started {
        let first = e.lines().next().unwrap_or_default();
        lines.push(format!(
            "Starting it said: {}",
            sanitize_terminal_line(first)
        ));
    }
    if !restarted {
        lines.push("Raven isn't running now: raven status says why.".to_owned());
    }
    Ok(End::RolledBack(lines))
}

/// `raven update install`, with how it asks (`confirm`: the lines and the
/// word to type; false cancels) and the node.
pub(super) fn install(
    ctx: &Ctx<'_>,
    args: InstallArgs,
    host: &mut dyn NodeHost,
    confirm: &mut dyn FnMut(&[String], &str) -> bool,
) -> Result<End, String> {
    let ready = match prepare(ctx, args)? {
        Prepared::Manual(lines) => return Ok(End::Manual(lines)),
        Prepared::Ready(ready) => ready,
    };
    // Lock v2 (review lock-updates-local-6): as with `raven lock` stopping
    // Raven (Lock now v1, in `prepare`), nothing is updated while locked.
    if host.locked() {
        return Err(LOCKED_INSTALL_TEXT.to_owned());
    }
    if !confirm(&ready.lines, ready.word) {
        return Err("cancelled — nothing changed".to_owned());
    }
    carry_out(ctx, &ready, host)
}

// ── rollback ─────────────────────────────────────────────────────────────────

/// `<name>` and `<name>.prev` trade places (either may be missing).
fn exchange(fs: &dyn InstallFs, dir: &Path, name: &str) -> io::Result<()> {
    let current = dir.join(name);
    let prev = with_suffix(&current, PREV_SUFFIX);
    match (fs.exists(&current), fs.exists(&prev)) {
        (true, true) => {
            let between = free_name(fs, &current, SWAP_SUFFIX);
            fs.rename(&current, &between)?;
            if let Err(e) = fs.rename(&prev, &current) {
                let _ = fs.rename(&between, &current);
                return Err(e);
            }
            fs.rename(&between, &prev)
        }
        (true, false) => fs.rename(&current, &prev),
        (false, true) => fs.rename(&prev, &current),
        (false, false) => Ok(()),
    }
}

/// Every program of `names` exchanged; on a failure those done go back.
fn exchange_all(fs: &dyn InstallFs, dir: &Path, names: &[String]) -> Result<(), String> {
    for (i, name) in names.iter().enumerate() {
        if let Err(e) = exchange(fs, dir, name) {
            for done in names[..i].iter().rev() {
                let _ = exchange(fs, dir, done);
            }
            return Err(format!(
                "Raven couldn't swap {name} back ({e}). Nothing was changed."
            ));
        }
    }
    fs.sync_dir(dir);
    Ok(())
}

/// `raven update rollback`: the programs before the last install (or
/// rollback) back in place, after the person types `rollback`.
pub(super) fn rollback(
    ctx: &Ctx<'_>,
    host: &mut dyn NodeHost,
    confirm: &mut dyn FnMut(&[String], &str) -> bool,
) -> Result<End, String> {
    if !live() {
        return Err(OFF_TEXT.to_owned());
    }
    let state = update_state::load_with(ctx.data_dir, ctx.build).map_err(|e| refused_text(&e))?;
    let record = state
        .install_record()
        .cloned()
        .ok_or_else(|| NOTHING_TO_GO_BACK.to_owned())?;
    let dir = PathBuf::from(&record.dir);
    let same = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone()) == ctx.place.dir;
    if !same {
        return Err(format!(
            "Raven's last update replaced the programs in {}, not these: run raven update \
             rollback from there.",
            shown(&dir)
        ));
    }
    let has_prev = record
        .files
        .iter()
        .any(|name| ctx.fs.exists(&with_suffix(&dir.join(name), PREV_SUFFIX)));
    if !has_prev {
        return Err(NOTHING_TO_GO_BACK.to_owned());
    }
    if raven_core::privacy::lock_state(ctx.data_dir).locked_by_user || host.locked() {
        return Err(LOCKED_ROLLBACK_TEXT.to_owned());
    }
    let back = build_name(&record.prev_version, record.prev_serial);
    let now = build_name(&record.version, record.serial);
    let mut lines = vec![format!(
        "Raven will go back to {back} and keep {now}, to return to with raven update rollback. \
         Your messages and friends stay."
    )];
    let floor = state.release_floor();
    if floor > 0 && record.prev_serial < floor {
        lines.push(format!(
            "Warning: {back} has a known security problem (a security notice from the Raven \
             project asks for build {floor} or later). Go back to it only if this version \
             doesn't work for you."
        ));
    }
    if !confirm(&lines, ROLLBACK_WORD) {
        return Err("cancelled — nothing changed".to_owned());
    }
    host.stop()?;
    if let Err(e) = exchange_all(ctx.fs, &dir, &record.files) {
        let _ = host.start();
        return Err(e);
    }
    let flipped = InstallRecord {
        serial: record.prev_serial,
        version: record.prev_version.clone(),
        prev_serial: record.serial,
        prev_version: record.version.clone(),
        ..record.clone()
    };
    let _ =
        update_state::record_install_with(ctx.data_dir, ctx.build, flipped.serial, Some(flipped));
    if host.start().is_ok() && host.healthy(ctx.health_wait) {
        return Ok(End::Done(vec![
            format!("Raven went back to {back} and is running."),
            format!("{now} is kept: raven update rollback returns to it."),
        ]));
    }
    host.stop_failed();
    exchange_all(ctx.fs, &dir, &record.files)?;
    let _ = update_state::record_install_with(
        ctx.data_dir,
        ctx.build,
        record.serial,
        Some(record.clone()),
    );
    let restarted = host.start().is_ok() && host.healthy(ctx.health_wait);
    let mut lines = vec![format!(
        "{back} didn't start, so Raven stayed with {now}. Nothing was lost."
    )];
    if !restarted {
        lines.push("Raven isn't running now: raven status says why.".to_owned());
    }
    Ok(End::RolledBack(lines))
}

// ── The CLI ──────────────────────────────────────────────────────────────────

/// `raven update`'s subcommands, as cli.rs parsed them.
#[derive(Debug, Clone)]
pub(super) enum UpdateOp {
    Status,
    Import(FileArgs),
    Verify(FileArgs),
    Download(Option<String>),
    Install { allow_downgrade: bool },
    Rollback,
}

/// The CLI's question: the lines, then the word to type, on a terminal only
/// (the lab auto-approval types it, P6.49: debug builds with Lab Test A).
fn ask_typed(lines: &[String], word: &str) -> bool {
    for line in lines {
        println!("{line}");
    }
    if raven_core::update_downloads::lab_auto_approve() {
        println!(
            "(lab: {word} typed by {})",
            raven_core::update_downloads::LAB_UPDATE_AUTO_APPROVE
        );
        return true;
    }
    if !super::stdin_is_tty() {
        eprintln!("stdin is not a terminal: Raven goes on only after you type {word} at one.");
        return false;
    }
    print!("Type {word} to continue: ");
    let _ = io::stdout().flush();
    super::read_decision_line().is_some_and(|answer| super::typed_word_is(&answer, word))
}

/// Lines on stderr, the last one as the command's error (exit 1).
fn fail_with(lines: Vec<String>) -> Result<(), String> {
    let Some((last, rest)) = lines.split_last() else {
        return Err("Raven didn't install the update.".to_owned());
    };
    for line in rest {
        eprintln!("{line}");
    }
    Err(last.clone())
}

/// `raven update ...`.
pub(super) fn cmd_update(data_dir: &Path, op: UpdateOp) -> Result<(), String> {
    let build = Build::this();
    let print = |lines: Vec<String>| {
        for line in lines {
            println!("{line}");
        }
    };
    match op {
        UpdateOp::Status => {
            if !notices_live() {
                println!("{OFF_TEXT}");
                return Ok(());
            }
            let mut lines =
                raven_core::suite_policy::status_lines(data_dir, raven_core::clock::now_ms());
            lines.extend(update_lines(data_dir, &build));
            print(lines);
            Ok(())
        }
        UpdateOp::Import(args) => import(data_dir, &build, &args).map(print),
        UpdateOp::Verify(args) => verify(data_dir, &build, &args).map(print),
        UpdateOp::Download(offer) => cmd_download(data_dir, offer.as_deref()),
        UpdateOp::Install { allow_downgrade } => {
            if !live() {
                return Err(OFF_TEXT.to_owned());
            }
            // A complete download from a friend is staged first (P6.49).
            for line in download::stage_downloads(data_dir, &build) {
                eprintln!("{line}");
            }
            let ctx = Ctx::live(data_dir, &build)?;
            let mut host = LiveHost::new(data_dir, None);
            let args = InstallArgs {
                allow_downgrade,
                expect_serial: None,
            };
            match install(&ctx, args, &mut host, &mut ask_typed)? {
                End::Done(lines) => {
                    print(lines);
                    Ok(())
                }
                End::RolledBack(lines) | End::Manual(lines) => fail_with(lines),
            }
        }
        UpdateOp::Rollback => {
            if !live() {
                return Err(OFF_TEXT.to_owned());
            }
            let ctx = Ctx::live(data_dir, &build)?;
            let mut host = LiveHost::new(data_dir, None);
            match rollback(&ctx, &mut host, &mut ask_typed)? {
                End::Done(lines) => {
                    print(lines);
                    Ok(())
                }
                End::RolledBack(lines) | End::Manual(lines) => fail_with(lines),
            }
        }
    }
}

// ── The terminal app ─────────────────────────────────────────────────────────

/// UPDATES' Y on a friend's offer (P6.49): approved, raven-node woken, and
/// the view read again (its first line says what happens now).
pub(crate) fn approve_from_app(data_dir: &Path, digest: &[u8; 32]) -> UpdateView {
    let said = download::approve(data_dir, &hex::encode(digest));
    let mut view = view(data_dir, true);
    let lines = match said {
        Ok(lines) => lines,
        Err(why) => vec![why],
    };
    view.lines.splice(0..0, lines);
    view
}

/// What the terminal app's Updates overlay (U) and NET row show.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UpdateView {
    /// The bundle gate is live.
    pub(crate) live: bool,
    /// A full read: `ready` and `manual` say what installing would do.
    pub(crate) full: bool,
    /// What `raven update status` says.
    pub(crate) lines: Vec<String>,
    /// A build ready to install, with what installing it shows.
    pub(crate) ready: Option<ReadyView>,
    /// The manual steps instead, when Raven can't swap its programs here.
    pub(crate) manual: Vec<String>,
    /// NET's row.
    pub(crate) net_row: Option<String>,
    /// A release a friend offered, waiting for the download approval (Y),
    /// with its prompt (P6.49).
    pub(crate) offer: Option<OfferView>,
}

/// A friend's offer as UPDATES shows it (P6.49).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OfferView {
    pub(crate) digest: [u8; 32],
    pub(crate) lines: Vec<String>,
}

/// A build ready to install, as the overlay shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadyView {
    pub(crate) serial: u64,
    pub(crate) version: String,
    pub(crate) lines: Vec<String>,
    /// The word to type.
    pub(crate) word: &'static str,
}

/// The overlay's view of this profile. `full`: a complete download from a
/// friend is staged first (verified in full, P6.49) and the staged build is
/// verified again in full for what installing it shows (UPDATES); without
/// it only the status, a friend's offer and NET's row (NET, which reads it
/// each time it opens): nothing is staged, stored or noted.
pub(crate) fn view(data_dir: &Path, full: bool) -> UpdateView {
    let build = Build::this();
    if !notices_live() {
        return UpdateView {
            lines: vec![OFF_TEXT.to_owned()],
            ..UpdateView::default()
        };
    }
    let staging = if full && live() {
        download::stage_downloads(data_dir, &build)
    } else {
        Vec::new()
    };
    let mut lines = raven_core::suite_policy::status_lines(data_dir, raven_core::clock::now_ms());
    lines.extend(staging);
    lines.extend(update_lines(data_dir, &build));
    let mut view = UpdateView {
        live: live(),
        full,
        lines,
        net_row: net_row(data_dir, &build),
        offer: download::first_offer(data_dir).map(|(row, lines)| OfferView {
            digest: row.digest,
            lines,
        }),
        ..UpdateView::default()
    };
    if !view.live || !full {
        return view;
    }
    let Ok(ctx) = Ctx::live(data_dir, &build) else {
        return view;
    };
    match prepare_with(&ctx, InstallArgs::default(), false) {
        Ok(Prepared::Ready(ready)) => {
            view.ready = Some(ReadyView {
                serial: ready.summary.serial,
                version: ready.summary.version.clone(),
                lines: ready.lines.clone(),
                word: ready.word,
            })
        }
        Ok(Prepared::Manual(lines)) => view.manual = lines,
        Err(_) => {}
    }
    view
}

/// The overlay's install, once the person typed the word: the build it
/// showed (`serial`) only, with the terminal app's node. With its lines (or
/// why not): the node it started from this process, now the app's own
/// ([`LiveHost::adopted`]; review lock-updates-local-7).
pub(crate) fn install_from_app(
    data_dir: &Path,
    serial: u64,
    started_by_app: Option<u32>,
) -> (Result<Vec<String>, String>, Option<u32>) {
    let build = Build::this();
    // A complete download from a friend is staged first (P6.49).
    download::stage_downloads(data_dir, &build);
    let ctx = match Ctx::live(data_dir, &build) {
        Ok(ctx) => ctx,
        Err(e) => return (Err(e), None),
    };
    let mut host = LiveHost::new(data_dir, started_by_app);
    let args = InstallArgs {
        allow_downgrade: false,
        expect_serial: Some(serial),
    };
    let result = match install(&ctx, args, &mut host, &mut |_, _| true) {
        Ok(End::Done(mut lines)) => {
            lines.push("Quit Raven and open it again to use the new version here.".to_owned());
            Ok(lines)
        }
        Ok(End::RolledBack(lines) | End::Manual(lines)) => Err(lines.join(" ")),
        Err(e) => Err(e),
    };
    (result, host.adopted())
}
