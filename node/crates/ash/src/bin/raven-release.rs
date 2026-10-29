//! `raven-release`: the offline release tool of the key ceremony
//! (`docs/RELEASE_KEY_CEREMONY.md`; `docs/roadmap/plans/phase6-design.json`
//! step P6.46, design D §9; owner decision OD6b-28).
//!
//! Built only with the non-default feature `release-tool`
//! (`cargo build --locked --release -p ash --features release-tool --bin
//! raven-release`); `scripts/release/build_unsigned.sh`,
//! `scripts/release/build_reproducible.sh` and the CI release jobs never
//! enable it (`node/scripts/release_tool_feature_audit.sh`), so no shipped
//! Raven contains it.
//!
//! Passphrases come only from the controlling terminal, typed without echo
//! (never an argument, the environment or a pipe). A signing run opens one
//! key and writes one detached signature per draft; `combine` builds the
//! signed artifact from the signatures of different runs. The work itself
//! (key files, drafts, signatures, the log folder, packing) is
//! `raven_core::release_sign`, tested with raven-core's verifiers.

use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use raven_core::advisory::Advisory;
use raven_core::clock::now_ms;
use raven_core::identity::Identity;
use raven_core::release_bundle::{
    verify_bundle, Container, VerifyCtx, RRBC_MAGIC, SOURCE_COMMIT_LEN,
};
use raven_core::release_keys::KeySet;
use raven_core::release_sign::{
    self as rs, Artifact, DetachedSig, KeyFile, ManifestSpec, Previous, ReleaseFile, ReleaseLog,
    SignError,
};
use raven_core::tlog::{Snapshot, KIND_SNAPSHOT, RTL1_MAGIC};
use zeroize::Zeroizing;

/// The offline release tool: release keys, drafts, signatures, the release
/// log and bundles. Run it on the ceremony's offline machine
/// (docs/RELEASE_KEY_CEREMONY.md).
#[derive(Parser)]
#[command(name = "raven-release", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make a new release key (its file goes on its own removable medium).
    Keygen {
        /// A label such as `release-a` (a-z, 0-9, '-'; never a person's name).
        #[arg(long)]
        label: String,
        /// The key file to create (never written over).
        #[arg(long)]
        out: PathBuf,
        /// Weak Argon2id parameters, for tests only (debug builds).
        #[arg(long)]
        test_kdf: bool,
    },
    /// Make a key set from public keys (key files, .pub files or hex).
    Keyset {
        /// How many keys must sign.
        #[arg(long, default_value_t = 2)]
        threshold: u8,
        /// The key set file to create (hex on one line).
        #[arg(long)]
        out: PathBuf,
        /// The keys, in key index order.
        #[arg(required = true)]
        keys: Vec<String>,
    },
    /// Draft a release manifest for one target.
    Manifest(ManifestArgs),
    /// Draft a security advisory from a JSON description.
    Advisory {
        #[arg(long)]
        key_set: PathBuf,
        /// The JSON description (the whole current list of entries).
        #[arg(long)]
        spec: PathBuf,
        /// The signed advisory one serial lower (not for serial 1).
        #[arg(long, conflicts_with = "prev_digest")]
        previous: Option<PathBuf>,
        /// Its advisory digest, when the file is not at hand.
        #[arg(long)]
        prev_digest: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign drafts with one key: writes `<draft>.sig-<key index>` for each.
    Sign {
        #[arg(long)]
        key_set: PathBuf,
        /// The key file (its passphrase is asked for on the terminal).
        #[arg(
            long,
            conflicts_with = "test_key",
            required_unless_present = "test_key"
        )]
        key: Option<PathBuf>,
        /// Published test key 0, 1 or 2 instead (debug builds, tests only).
        #[arg(long)]
        test_key: Option<u8>,
        /// Where the signatures go (default: next to each draft).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(required = true)]
        drafts: Vec<PathBuf>,
    },
    /// Combine detached signatures into the signed artifact.
    Combine {
        #[arg(long)]
        key_set: PathBuf,
        #[arg(long)]
        draft: PathBuf,
        /// The signed artifact to create.
        #[arg(long, required_unless_present = "log", conflicts_with = "log")]
        out: Option<PathBuf>,
        /// For a tree head: keep it in this log folder as `sth/<size>.rtl1`.
        #[arg(long)]
        log: Option<PathBuf>,
        #[arg(required = true)]
        sigs: Vec<PathBuf>,
    },
    /// The release log folder.
    Log {
        #[command(subcommand)]
        cmd: LogCmd,
    },
    /// Draft the tree head of the whole log (default `tree-head-<size>.draft`
    /// here; the signed one goes into the log with `combine --log`).
    Sth {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        key_set: PathBuf,
        /// Unix ms (default: now).
        #[arg(long)]
        timestamp_ms: Option<u64>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Pack the .rrb bundle of a signed manifest.
    Pack {
        #[arg(long)]
        key_set: PathBuf,
        /// The signed manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// The log folder (its snapshot must list the manifest).
        #[arg(long)]
        log: PathBuf,
        /// The newest signed advisory, to travel with the bundle.
        #[arg(long)]
        advisory: Option<PathBuf>,
        /// The folder holding the manifest's files (bin/..., docs/...).
        #[arg(long)]
        files: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Check a signed artifact, a log snapshot or a bundle against a key set.
    Verify {
        #[arg(long)]
        key_set: PathBuf,
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum LogCmd {
    /// List signed manifests and advisories (and a next key set) in the log.
    Append {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        key_set: PathBuf,
        /// Unix ms (default: now).
        #[arg(long)]
        at_ms: Option<u64>,
        /// A next key set (named by a KEY_SET advisory entry) to list.
        #[arg(long)]
        next_key_set: Option<PathBuf>,
        artifacts: Vec<PathBuf>,
    },
    /// Write the snapshot of the whole log (default `<log>/snapshot.rtl1`).
    Snapshot {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        key_set: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Args)]
struct ManifestArgs {
    #[arg(long)]
    key_set: PathBuf,
    /// The build serial compiled into the binaries (BUILD_SERIAL).
    #[arg(long)]
    build_serial: u64,
    /// The version shown to people (`0.2.0`).
    #[arg(long)]
    version: String,
    /// The target triple.
    #[arg(long)]
    target: String,
    /// The git commit the release is built from (40 hex digits).
    #[arg(long)]
    source_commit: String,
    /// The Rust toolchain (`1.98.0`).
    #[arg(long)]
    toolchain: String,
    /// Unix ms (default: now).
    #[arg(long)]
    created_at_ms: Option<u64>,
    /// The newest advisory serial when the release is made.
    #[arg(long, default_value_t = 0)]
    min_advisory_serial: u64,
    /// The release notes (UTF-8 text file).
    #[arg(long)]
    notes: Option<PathBuf>,
    /// `bin/<name>=<file>` or `docs/<name>=<file>`, in payload order.
    #[arg(long = "file", required = true)]
    files: Vec<String>,
    /// `<path>=<sha256 hex>`: the reproducible build's hash of that file
    /// before platform signing (default: the file's own hash).
    #[arg(long = "rebuild")]
    rebuilds: Vec<String>,
    #[arg(long)]
    out: PathBuf,
}

fn main() -> ExitCode {
    match run(Cli::parse().cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("raven-release: {e}");
            ExitCode::FAILURE
        }
    }
}

type Res = Result<(), String>;

fn err(e: SignError) -> String {
    e.to_string()
}

fn run(cmd: Cmd) -> Res {
    match cmd {
        Cmd::Keygen {
            label,
            out,
            test_kdf,
        } => keygen(&label, &out, test_kdf),
        Cmd::Keyset {
            threshold,
            out,
            keys,
        } => keyset(threshold, &out, &keys),
        Cmd::Manifest(args) => manifest(&args),
        Cmd::Advisory {
            key_set,
            spec,
            previous,
            prev_digest,
            out,
        } => advisory(
            &key_set,
            &spec,
            previous.as_deref(),
            prev_digest.as_deref(),
            &out,
        ),
        Cmd::Sign {
            key_set,
            key,
            test_key,
            out_dir,
            drafts,
        } => sign(
            &key_set,
            key.as_deref(),
            test_key,
            out_dir.as_deref(),
            &drafts,
        ),
        Cmd::Combine {
            key_set,
            draft,
            out,
            log,
            sigs,
        } => combine(&key_set, &draft, out.as_deref(), log.as_deref(), &sigs),
        Cmd::Log {
            cmd:
                LogCmd::Append {
                    log,
                    key_set,
                    at_ms,
                    next_key_set,
                    artifacts,
                },
        } => log_append(&log, &key_set, at_ms, next_key_set.as_deref(), &artifacts),
        Cmd::Log {
            cmd: LogCmd::Snapshot { log, key_set, out },
        } => log_snapshot(&log, &key_set, out.as_deref()),
        Cmd::Sth {
            log,
            key_set,
            timestamp_ms,
            out,
        } => sth(&log, &key_set, timestamp_ms, out.as_deref()),
        Cmd::Pack {
            key_set,
            manifest,
            log,
            advisory,
            files,
            out,
        } => pack(&key_set, &manifest, &log, advisory.as_deref(), &files, &out),
        Cmd::Verify { key_set, file } => verify(&key_set, &file),
    }
}

// ── Passphrases ─────────────────────────────────────────────────────

/// One passphrase from the controlling terminal, without echo.
fn read_passphrase(prompt: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if !std::io::stdin().is_terminal() {
        return Err(
            "raven-release reads passphrases only from a terminal (never from \
                    arguments, the environment or a pipe)"
                .into(),
        );
    }
    raven_core::keystore_vault::read_hidden_passphrase(prompt)
        .map_err(|e| format!("passphrase: {e}"))
}

/// A new key's passphrase, typed twice (three tries).
fn read_new_passphrase(label: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    for _ in 0..3 {
        let first = read_passphrase(&format!("New passphrase (key {label}): "))?;
        if let Err(e) = rs::check_new_passphrase(&first) {
            eprintln!("{e}");
            continue;
        }
        let second = read_passphrase("Same passphrase again: ")?;
        if *first == *second {
            return Ok(first);
        }
        eprintln!("The two passphrases did not match.");
    }
    Err("no new passphrase was set".into())
}

// ── Commands ────────────────────────────────────────────────────────

fn keygen(label: &str, out: &Path, test_kdf: bool) -> Res {
    if !rs::label_well_formed(label) {
        return Err(err(SignError::BadLabel));
    }
    let params = rs::keygen_params(test_kdf).map_err(err)?;
    let pub_path = path_with_suffix(out, ".pub");
    for path in [out, pub_path.as_path()] {
        if path.exists() {
            return Err(format!(
                "{} already exists: a key is never written over",
                path.display()
            ));
        }
    }
    println!(
        "A new Raven release key, `{label}`. Its seed is sealed with your passphrase \
         (Argon2id m={} KiB t={} p={}, XChaCha20-Poly1305).",
        params.m_kib, params.t, params.p
    );
    let passphrase = read_new_passphrase(label)?;
    let file = KeyFile::generate(label, &passphrase, params).map_err(err)?;
    write_private(out, &file.encode())?;
    // Read it back and open it: the medium holds a key this passphrase opens.
    let back = KeyFile::read(out).map_err(err)?;
    let id = back.unlock(&passphrase).map_err(err)?;
    if id.public_key_bytes() != file.public_key() {
        return Err("the key file read back is not the key just made".into());
    }
    let public = rs::to_hex(&file.public_key());
    rs::write_new(&pub_path, format!("{public}  {label}\n").as_bytes()).map_err(err)?;
    println!("key file:   {}", out.display());
    println!("public key: {public}");
    println!("            (also in {})", pub_path.display());
    println!("Next: the paper backup of this file, then `raven-release keyset`.");
    Ok(())
}

fn keyset(threshold: u8, out: &Path, keys: &[String]) -> Res {
    let keys = keys
        .iter()
        .map(|k| rs::read_public_key(k))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    if keys.iter().any(rs::is_test_key) {
        if cfg!(debug_assertions) {
            eprintln!(
                "warning: this key set holds a published test key: tests only, never a release"
            );
        } else {
            return Err(err(SignError::TestOnly("published test keys")));
        }
    }
    let set = KeySet::new(threshold, keys).map_err(|e| format!("not a key set: {e}"))?;
    let hex = rs::to_hex(&set.encode());
    rs::write_new(out, format!("{hex}\n").as_bytes()).map_err(err)?;
    println!(
        "key set:    {} ({} of {})",
        out.display(),
        set.threshold(),
        set.keys().len()
    );
    println!("digest:     {}", rs::to_hex(&set.digest()));
    for (i, k) in set.keys().iter().enumerate() {
        println!("key {i}:      {}", rs::to_hex(k));
    }
    println!("The key ceremony's commit sets (node/crates/raven-core/src/update_state.rs):");
    println!(
        "pub const RELEASE_KEY_SET_V1: Option<&[u8]> = Some(&hex_bytes::<{}>(\"{hex}\"));",
        set.encode().len()
    );
    Ok(())
}

fn manifest(a: &ManifestArgs) -> Res {
    let key_set = rs::read_key_set(&a.key_set).map_err(err)?;
    let source_commit = rs::parse_hex::<SOURCE_COMMIT_LEN>(&a.source_commit)
        .ok_or("--source-commit is a git commit id: 40 hex digits")?;
    let notes = match &a.notes {
        Some(path) => String::from_utf8(read(path)?)
            .map_err(|_| format!("{} is not UTF-8 text", path.display()))?,
        None => String::new(),
    };
    let mut rebuilds = Vec::new();
    for r in &a.rebuilds {
        let (path, hex) = r
            .split_once('=')
            .ok_or_else(|| format!("--rebuild {r}: write <path>=<sha256 hex>"))?;
        let hash =
            rs::parse_hex::<32>(hex).ok_or_else(|| format!("--rebuild {r}: not a SHA-256"))?;
        rebuilds.push((path.to_owned(), hash));
    }
    let mut files = Vec::new();
    for f in &a.files {
        let (path, src) = f
            .split_once('=')
            .ok_or_else(|| format!("--file {f}: write <bin/... or docs/...>=<file>"))?;
        let bytes = read_regular(Path::new(src))?;
        let rebuild_sha256 = rebuilds
            .iter()
            .find(|(p, _)| p == path)
            .map_or_else(|| rs::sha256(&bytes), |(_, h)| *h);
        files.push(ReleaseFile {
            path: path.to_owned(),
            bytes,
            rebuild_sha256,
        });
    }
    if let Some((p, _)) = rebuilds
        .iter()
        .find(|(p, _)| !files.iter().any(|f| f.path == *p))
    {
        return Err(format!("--rebuild {p}: no --file has that path"));
    }
    let spec = ManifestSpec {
        build_serial: a.build_serial,
        created_at_ms: a.created_at_ms.unwrap_or_else(now_ms),
        version: a.version.clone(),
        target: a.target.clone(),
        source_commit,
        toolchain: a.toolchain.clone(),
        min_advisory_serial: a.min_advisory_serial,
        notes,
        files,
    };
    let draft = rs::manifest_draft(&spec, &key_set).map_err(err)?;
    write_draft(&a.out, &draft)
}

fn advisory(
    key_set: &Path,
    spec: &Path,
    previous: Option<&Path>,
    prev_digest: Option<&str>,
    out: &Path,
) -> Res {
    let key_set = rs::read_key_set(key_set).map_err(err)?;
    let prev_advisory = match previous {
        Some(path) => match Artifact::read(path).map_err(err)? {
            Artifact::Advisory(a) => Some(a),
            _ => return Err(format!("{} is not an advisory", path.display())),
        },
        None => None,
    };
    let previous = match (&prev_advisory, prev_digest) {
        (Some(a), _) => Previous::Advisory(a),
        (None, Some(hex)) => {
            Previous::Digest(rs::parse_hex::<32>(hex).ok_or("--prev-digest is 64 hex digits")?)
        }
        (None, None) => Previous::None,
    };
    let draft = rs::advisory_draft(&read(spec)?, &key_set, previous).map_err(err)?;
    write_draft(out, &draft)
}

fn sign(
    key_set: &Path,
    key: Option<&Path>,
    test_key: Option<u8>,
    out_dir: Option<&Path>,
    drafts: &[PathBuf],
) -> Res {
    let key_set = rs::read_key_set(key_set).map_err(err)?;
    let drafts = drafts
        .iter()
        .map(|p| Artifact::read(p).map(|a| (p, a)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    for (path, draft) in &drafts {
        if draft.key_set_digest() != key_set.digest() {
            return Err(format!(
                "{} names key set {}, not this one ({})",
                path.display(),
                rs::to_hex(&draft.key_set_digest()),
                rs::to_hex(&key_set.digest())
            ));
        }
    }
    // The key, before anything is shown: a key outside the set stops here.
    let (signer, name): (Identity, String) = match (key, test_key) {
        (Some(path), _) => {
            let file = KeyFile::read(path).map_err(err)?;
            if !key_set.keys().contains(&file.public_key()) {
                return Err(err(SignError::KeyNotInSet(rs::to_hex(&file.public_key()))));
            }
            for (path, draft) in &drafts {
                println!("{}:", path.display());
                for line in draft.summary() {
                    println!("  {line}");
                }
                println!("  signing hash {}", rs::to_hex(&draft.signing_hash()));
            }
            let passphrase = read_passphrase(&format!(
                "Passphrase (key {}) to sign the above: ",
                file.label()
            ))?;
            (
                file.unlock(&passphrase).map_err(err)?,
                file.label().to_owned(),
            )
        }
        (None, Some(index)) => {
            eprintln!("warning: signing with published test key {index}: tests only");
            (
                rs::test_signer(index).map_err(err)?,
                format!("test key {index}"),
            )
        }
        (None, None) => return Err("give --key".into()),
    };
    for (path, draft) in &drafts {
        let sig = rs::sign_detached(draft, &key_set, &signer).map_err(err)?;
        let name_of = |p: &Path| {
            format!(
                "{}.sig-{}",
                p.file_name().and_then(|n| n.to_str()).unwrap_or("draft"),
                sig.key_index
            )
        };
        let out = match out_dir {
            Some(dir) => dir.join(name_of(path)),
            None => path.with_file_name(name_of(path)),
        };
        rs::write_new(&out, &sig.encode()).map_err(err)?;
        println!(
            "signed {} with {name} (key index {}): {}",
            draft.kind().name(),
            sig.key_index,
            out.display()
        );
    }
    Ok(())
}

fn combine(
    key_set: &Path,
    draft: &Path,
    out: Option<&Path>,
    log: Option<&Path>,
    sigs: &[PathBuf],
) -> Res {
    let key_set = rs::read_key_set(key_set).map_err(err)?;
    let draft = Artifact::read(draft).map_err(err)?;
    let sigs = sigs
        .iter()
        .map(|p| DetachedSig::read(p))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    let signed = rs::combine(&draft, &key_set, &sigs).map_err(err)?;
    let path = match (out, log, &signed) {
        (Some(out), _, _) => {
            rs::write_new(out, signed.bytes()).map_err(err)?;
            out.to_owned()
        }
        (None, Some(log), Artifact::TreeHead(sth)) => ReleaseLog::open(log)
            .and_then(|l| l.store_tree_head(sth, &key_set))
            .map_err(err)?,
        (None, _, _) => return Err("--log keeps only a tree head: give --out".into()),
    };
    println!(
        "{} signed by {} keys: {}",
        signed.kind().name(),
        signed.sigs().sigs().len(),
        path.display()
    );
    if let Some((kind, digest)) = signed.log_name() {
        println!("{} digest {}", kind.name(), rs::to_hex(&digest));
    }
    Ok(())
}

fn log_append(
    log: &Path,
    key_set: &Path,
    at_ms: Option<u64>,
    next_key_set: Option<&Path>,
    artifacts: &[PathBuf],
) -> Res {
    let key_set = rs::read_key_set(key_set).map_err(err)?;
    if artifacts.is_empty() && next_key_set.is_none() {
        return Err("nothing to append: give signed artifacts or --next-key-set".into());
    }
    let mut release_log = ReleaseLog::open(log).map_err(err)?;
    let at = at_ms.unwrap_or_else(now_ms);
    for path in artifacts {
        let artifact = Artifact::read(path).map_err(err)?;
        let (entry, published) = release_log
            .append_artifact(&artifact, &key_set, at)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        println!(
            "entry {}: {} {} ({})",
            release_log.entries().len(),
            entry.kind.name(),
            rs::to_hex(&entry.digest),
            published.display()
        );
    }
    if let Some(path) = next_key_set {
        let next = rs::read_key_set(path).map_err(err)?;
        let (entry, published) = release_log.append_key_set(&next, at).map_err(err)?;
        println!(
            "entry {}: KEY_SET {} ({})",
            release_log.entries().len(),
            rs::to_hex(&entry.digest),
            published.display()
        );
    }
    println!(
        "The log has {} entries. Next: `raven-release sth`, two signatures, `combine --log`.",
        release_log.entries().len()
    );
    Ok(())
}

fn log_snapshot(log: &Path, key_set: &Path, out: Option<&Path>) -> Res {
    let key_set = rs::read_key_set(key_set).map_err(err)?;
    let release_log = ReleaseLog::open(log).map_err(err)?;
    let path = match out {
        Some(out) => {
            let snapshot = release_log.snapshot(&key_set).map_err(err)?;
            rs::write_new(out, &snapshot.encode()).map_err(err)?;
            out.to_owned()
        }
        None => release_log.write_snapshot(&key_set).map_err(err)?,
    };
    println!(
        "snapshot of {} entries: {}",
        release_log.entries().len(),
        path.display()
    );
    Ok(())
}

fn sth(log: &Path, key_set: &Path, timestamp_ms: Option<u64>, out: Option<&Path>) -> Res {
    let key_set = rs::read_key_set(key_set).map_err(err)?;
    let release_log = ReleaseLog::open(log).map_err(err)?;
    let draft = release_log
        .tree_head_draft(&key_set, timestamp_ms.unwrap_or_else(now_ms))
        .map_err(err)?;
    let out = out.map_or_else(
        || PathBuf::from(format!("tree-head-{}.draft", release_log.entries().len())),
        Path::to_owned,
    );
    write_draft(&out, &draft)
}

fn pack(
    key_set: &Path,
    manifest: &Path,
    log: &Path,
    advisory: Option<&Path>,
    files: &Path,
    out: &Path,
) -> Res {
    let key_set = rs::read_key_set(key_set).map_err(err)?;
    let Artifact::Manifest(manifest) = Artifact::read(manifest).map_err(err)? else {
        return Err(format!("{} is not a release manifest", manifest.display()));
    };
    let advisory: Option<Advisory> = match advisory {
        Some(path) => match Artifact::read(path).map_err(err)? {
            Artifact::Advisory(a) => Some(a),
            _ => return Err(format!("{} is not an advisory", path.display())),
        },
        None => None,
    };
    let snapshot = ReleaseLog::open(log)
        .and_then(|l| l.snapshot(&key_set))
        .map_err(err)?;
    let payload = rs::read_payload(&manifest, files).map_err(err)?;
    let bytes =
        rs::pack(&key_set, &manifest, &snapshot, advisory.as_ref(), payload).map_err(err)?;
    rs::write_new(out, &bytes).map_err(err)?;
    println!(
        "bundle: {} ({} bytes, sha256 {})",
        out.display(),
        bytes.len(),
        rs::to_hex(&rs::sha256(&bytes))
    );
    println!(
        "Raven {} for {}, build serial {}: verified as a Raven build would on import.",
        manifest.version, manifest.target, manifest.build_serial
    );
    Ok(())
}

fn verify(key_set: &Path, file: &Path) -> Res {
    let key_set = rs::read_key_set(key_set).map_err(err)?;
    let meta = fs::metadata(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    if meta.len() > raven_core::release_bundle::MAX_CONTAINER_LEN {
        return Err(format!("{} is larger than any bundle", file.display()));
    }
    let bytes = read(file)?;
    if bytes.starts_with(RRBC_MAGIC) {
        let parts = Container::open(&bytes[..]).map_err(|e| e.to_string())?;
        let target = parts.manifest.target.clone();
        let verified = verify_bundle(
            &parts,
            &VerifyCtx {
                key_set: Some(&key_set),
                stored_log: &[],
                installed_serial: 0,
                target: &target,
                release_floor: 0,
                allow_downgrade: false,
            },
        )
        .map_err(|e| format!("refused: {e}"))?;
        for line in Artifact::Manifest(verified.manifest().clone()).summary() {
            println!("{line}");
        }
        println!(
            "OK: bundle signed by {} keys, listed in a log of {} entries",
            verified.manifest().sigs().sigs().len(),
            verified.log().entries().len()
        );
        return Ok(());
    }
    if bytes.starts_with(RTL1_MAGIC) && bytes.get(5) == Some(&KIND_SNAPSHOT) {
        let snapshot = Snapshot::decode(&bytes).map_err(|e| e.to_string())?;
        snapshot
            .check(&key_set)
            .map_err(|e| format!("refused: {e}"))?;
        println!(
            "OK: log snapshot of {} entries, root {}",
            snapshot.entries().len(),
            rs::to_hex(&snapshot.sth().root_hash)
        );
        return Ok(());
    }
    let artifact = Artifact::decode(&bytes).map_err(err)?;
    for line in artifact.summary() {
        println!("{line}");
    }
    artifact
        .verify(&key_set)
        .map_err(|e| format!("refused: {e}"))?;
    if let Some((kind, digest)) = artifact.log_name() {
        println!("{} digest {}", kind.name(), rs::to_hex(&digest));
    }
    println!("OK: {} signed by this key set", artifact.kind().name());
    Ok(())
}

// ── Files ───────────────────────────────────────────────────────────

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// A regular file (not a link), at most the largest payload.
fn read_regular(path: &Path) -> Result<Vec<u8>, String> {
    let meta =
        fs::symlink_metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.len() > raven_core::release_bundle::MAX_PAYLOAD_LEN {
        return Err(format!(
            "{} is larger than a bundle carries",
            path.display()
        ));
    }
    read(path)
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// A key file: new, readable by its owner only.
fn write_private(path: &Path, bytes: &[u8]) -> Res {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn write_draft(out: &Path, draft: &Artifact) -> Res {
    rs::write_new(out, draft.bytes()).map_err(err)?;
    for line in draft.summary() {
        println!("{line}");
    }
    println!("signing hash {}", rs::to_hex(&draft.signing_hash()));
    println!("draft: {}", out.display());
    Ok(())
}
