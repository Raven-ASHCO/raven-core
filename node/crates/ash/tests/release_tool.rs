//! `raven-release`, the offline release tool (P6.46), run as the ceremony
//! runs it: a key set of the published test keys, a manifest and an
//! advisory drafted, signed one key per run, combined, listed in a log
//! folder whose tree head is signed the same way, and packed; raven-core's
//! own verifiers accept every piece. Passphrases come only from a terminal:
//! with a pipe for stdin the tool refuses, and under `script` (a real
//! pseudo-terminal, skipped where there is none) a key made with `keygen`
//! signs with its passphrase and refuses a wrong one.
//!
//! Built and run only with `--features release-tool` (Cargo.toml
//! `required-features`), in debug builds (the tool takes the published test
//! keys and the weak test cost only there). Everything is in throwaway
//! folders; nothing here touches a profile, the keychain or the network.
#![cfg(debug_assertions)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use raven_core::advisory::Advisory;
use raven_core::release_bundle::{verify_bundle, Container, Manifest, VerifyCtx};
use raven_core::release_keys::test_keys::key_set;
use raven_core::release_sign::{to_hex, KeyFile, TEST_KDF};
use raven_core::tlog::{EntryType, Snapshot};

const TOOL: &str = env!("CARGO_BIN_EXE_raven-release");
const TARGET: &str = "x86_64-unknown-linux-gnu";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const PASS: &str = "correct horse battery staple";

fn tool(dir: &Path, args: &[&str]) -> Output {
    Command::new(TOOL)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .expect("run raven-release")
}

/// Run and expect success; the output's text.
fn ok(dir: &Path, args: &[&str]) -> String {
    let out = tool(dir, args);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "raven-release {args:?} failed:\n{text}"
    );
    text
}

/// Run and expect a refusal; its message.
fn refused(dir: &Path, args: &[&str]) -> String {
    let out = tool(dir, args);
    assert!(!out.status.success(), "raven-release {args:?} succeeded");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The 2-of-3 key set of the published test keys, as the tool writes it.
fn write_key_set(dir: &Path) {
    let keys: Vec<String> = key_set().keys().iter().map(|k| to_hex(k)).collect();
    let mut args = vec!["keyset", "--threshold", "2", "--out", "keys.keyset"];
    args.extend(keys.iter().map(String::as_str));
    let text = ok(dir, &args);
    assert!(text.contains("published test key"), "{text}");
    assert!(
        text.contains("pub const RELEASE_KEY_SET_V1: Option<&[u8]> = Some(&hex_bytes::<99>(\""),
        "{text}"
    );
}

/// The release's files under `files/`.
fn write_files(dir: &Path) {
    std::fs::create_dir_all(dir.join("files/bin")).unwrap();
    std::fs::create_dir_all(dir.join("files/docs")).unwrap();
    std::fs::write(dir.join("files/bin/ash"), vec![0x5a; 100_000]).unwrap();
    std::fs::write(dir.join("files/bin/raven-node"), vec![0xa5; 70_001]).unwrap();
    std::fs::write(dir.join("files/docs/INSTALL_Linux.md"), b"# Install\n").unwrap();
    std::fs::write(
        dir.join("notes.txt"),
        b"Raven 0.1.0 (test): first release.\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("advisory-1.json"),
        br#"{"serial": 1, "issued_at_ms": 1792800000000, "entries": [
            {"kind": "SUITE_STATUS", "target": "rlb1/1", "severity": "DEPRECATED"},
            {"kind": "RELEASE_FLOOR", "min_build_serial": 3}
        ]}"#,
    )
    .unwrap();
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn the_tool_signs_a_manifest_and_an_advisory_that_raven_core_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    write_key_set(dir);
    write_files(dir);
    std::fs::create_dir(dir.join("log")).unwrap();

    // Draft.
    ok(
        dir,
        &[
            "manifest",
            "--key-set",
            "keys.keyset",
            "--build-serial",
            "4",
            "--version",
            "0.1.0",
            "--target",
            TARGET,
            "--source-commit",
            COMMIT,
            "--toolchain",
            "1.98.0",
            "--created-at-ms",
            "1792800000000",
            "--notes",
            "notes.txt",
            "--file",
            "bin/ash=files/bin/ash",
            "--file",
            "bin/raven-node=files/bin/raven-node",
            "--file",
            "docs/INSTALL_Linux.md=files/docs/INSTALL_Linux.md",
            "--rebuild",
            &format!("bin/ash={}", "11".repeat(32)),
            "--out",
            "manifest.draft",
        ],
    );
    ok(
        dir,
        &[
            "advisory",
            "--key-set",
            "keys.keyset",
            "--spec",
            "advisory-1.json",
            "--out",
            "advisory-1.draft",
        ],
    );
    // Sign: one key per run, two drafts in each run.
    for key in ["0", "2"] {
        let text = ok(
            dir,
            &[
                "sign",
                "--key-set",
                "keys.keyset",
                "--test-key",
                key,
                "manifest.draft",
                "advisory-1.draft",
            ],
        );
        assert!(text.contains("tests only"), "{text}");
    }
    // One signature is not enough.
    let err = refused(
        dir,
        &[
            "combine",
            "--key-set",
            "keys.keyset",
            "--draft",
            "manifest.draft",
            "--out",
            "x",
            "manifest.draft.sig-0",
        ],
    );
    assert!(err.contains("needs 2"), "{err}");
    assert!(!dir.join("x").exists());
    ok(
        dir,
        &[
            "combine",
            "--key-set",
            "keys.keyset",
            "--draft",
            "manifest.draft",
            "--out",
            "manifest.rrb1",
            "manifest.draft.sig-2",
            "manifest.draft.sig-0",
        ],
    );
    ok(
        dir,
        &[
            "combine",
            "--key-set",
            "keys.keyset",
            "--draft",
            "advisory-1.draft",
            "--out",
            "advisory-1.rad1",
            "advisory-1.draft.sig-0",
            "advisory-1.draft.sig-2",
        ],
    );

    // raven-core verifies both.
    let ks = key_set();
    let manifest = Manifest::decode(&read(dir, "manifest.rrb1")).expect("manifest");
    manifest
        .verify(&ks)
        .expect("raven-core verifies the manifest");
    assert_eq!(manifest.build_serial, 4);
    assert_eq!(manifest.files[0].rebuild_sha256, [0x11; 32]);
    assert_eq!(manifest.files.len(), 3);
    let advisory = Advisory::decode(&read(dir, "advisory-1.rad1")).expect("advisory");
    advisory
        .verify(&ks)
        .expect("raven-core verifies the advisory");
    assert_eq!(advisory.entries.len(), 2);
    ok(
        dir,
        &["verify", "--key-set", "keys.keyset", "manifest.rrb1"],
    );
    ok(
        dir,
        &["verify", "--key-set", "keys.keyset", "advisory-1.rad1"],
    );
    let err = refused(
        dir,
        &["verify", "--key-set", "keys.keyset", "manifest.draft"],
    );
    assert!(err.contains("BELOW_THRESHOLD"), "{err}");

    // The log: listed, a signed tree head, a snapshot.
    let err = refused(
        dir,
        &[
            "log",
            "append",
            "--log",
            "log",
            "--key-set",
            "keys.keyset",
            "--at-ms",
            "1792800000001",
            "manifest.draft",
        ],
    );
    assert!(err.contains("draft"), "{err}");
    ok(
        dir,
        &[
            "log",
            "append",
            "--log",
            "log",
            "--key-set",
            "keys.keyset",
            "--at-ms",
            "1792800000001",
            "advisory-1.rad1",
            "manifest.rrb1",
        ],
    );
    assert_eq!(read(dir, "log/entries.bin").len(), 2 * 41);
    assert_eq!(
        read(dir, "log/advisories/1.rad1"),
        read(dir, "advisory-1.rad1")
    );
    assert_eq!(
        read(dir, &format!("log/manifests/4-{TARGET}.rrb1")),
        read(dir, "manifest.rrb1")
    );
    ok(
        dir,
        &[
            "sth",
            "--log",
            "log",
            "--key-set",
            "keys.keyset",
            "--timestamp-ms",
            "1792800000002",
        ],
    );
    for key in ["1", "2"] {
        ok(
            dir,
            &[
                "sign",
                "--key-set",
                "keys.keyset",
                "--test-key",
                key,
                "tree-head-2.draft",
            ],
        );
    }
    ok(
        dir,
        &[
            "combine",
            "--key-set",
            "keys.keyset",
            "--draft",
            "tree-head-2.draft",
            "--log",
            "log",
            "tree-head-2.draft.sig-1",
            "tree-head-2.draft.sig-2",
        ],
    );
    assert!(dir.join("log/sth/2.rtl1").is_file());
    ok(
        dir,
        &[
            "log",
            "snapshot",
            "--log",
            "log",
            "--key-set",
            "keys.keyset",
        ],
    );
    let snapshot = Snapshot::decode(&read(dir, "log/snapshot.rtl1")).expect("snapshot");
    let checked = snapshot.check(&ks).expect("raven-core checks the log");
    assert!(checked.contains(EntryType::Manifest, &manifest.digest()));
    assert!(checked.contains(EntryType::Advisory, &advisory.digest()));
    ok(
        dir,
        &["verify", "--key-set", "keys.keyset", "log/snapshot.rtl1"],
    );

    // Pack, twice: the same bytes, and a bundle raven-core verifies.
    for out in ["a.rrb", "b.rrb"] {
        ok(
            dir,
            &[
                "pack",
                "--key-set",
                "keys.keyset",
                "--manifest",
                "manifest.rrb1",
                "--log",
                "log",
                "--advisory",
                "advisory-1.rad1",
                "--files",
                "files",
                "--out",
                out,
            ],
        );
    }
    let bundle = read(dir, "a.rrb");
    assert_eq!(bundle, read(dir, "b.rrb"), "packing is deterministic");
    let parts = Container::open(&bundle[..]).expect("container");
    let verified = verify_bundle(
        &parts,
        &VerifyCtx {
            key_set: Some(&ks),
            stored_log: &[],
            installed_serial: 3,
            target: TARGET,
            release_floor: 0,
            allow_downgrade: false,
        },
    )
    .expect("raven-core verifies the bundle");
    assert_eq!(verified.release_floor(), 3);
    let text = ok(dir, &["verify", "--key-set", "keys.keyset", "a.rrb"]);
    assert!(text.contains("OK: bundle signed by 2 keys"), "{text}");

    // Nothing is written over; a changed file is not packed.
    let err = refused(
        dir,
        &[
            "pack",
            "--key-set",
            "keys.keyset",
            "--manifest",
            "manifest.rrb1",
            "--log",
            "log",
            "--files",
            "files",
            "--out",
            "a.rrb",
        ],
    );
    assert!(err.contains("already exists"), "{err}");
    std::fs::write(dir.join("files/bin/ash"), vec![0x5b; 100_000]).unwrap();
    let err = refused(
        dir,
        &[
            "pack",
            "--key-set",
            "keys.keyset",
            "--manifest",
            "manifest.rrb1",
            "--log",
            "log",
            "--files",
            "files",
            "--out",
            "c.rrb",
        ],
    );
    assert!(
        err.contains("BAD_PAYLOAD_HASH") || err.contains("BAD_CHUNK_ROOT"),
        "{err}"
    );
    assert!(!dir.join("c.rrb").exists());
}

#[test]
fn passphrases_are_never_read_from_a_pipe() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    // keygen with stdin a pipe: refused, nothing written.
    let mut child = Command::new(TOOL)
        .args([
            "keygen",
            "--label",
            "release-a",
            "--out",
            "a.rrk",
            "--test-kdf",
        ])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASS}\n{PASS}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("only from a terminal"), "{err}");
    assert!(!dir.join("a.rrk").exists());

    // sign with a key file: refused before anything is signed.
    write_key_set(dir);
    write_files(dir);
    let file = KeyFile::seal("release-a", &[0x11; 32], PASS.as_bytes(), TEST_KDF).unwrap();
    std::fs::write(dir.join("a.rrk"), file.encode()).unwrap();
    ok(
        dir,
        &[
            "advisory",
            "--key-set",
            "keys.keyset",
            "--spec",
            "advisory-1.json",
            "--out",
            "advisory-1.draft",
        ],
    );
    let err = refused(
        dir,
        &[
            "sign",
            "--key-set",
            "keys.keyset",
            "--key",
            "a.rrk",
            "advisory-1.draft",
        ],
    );
    assert!(err.contains("only from a terminal"), "{err}");
    assert!(!dir.join("advisory-1.draft.sig-0").exists());
    // A key outside the set is refused before the passphrase is asked for.
    let other = KeyFile::seal("release-x", &[0x44; 32], PASS.as_bytes(), TEST_KDF).unwrap();
    std::fs::write(dir.join("x.rrk"), other.encode()).unwrap();
    let err = refused(
        dir,
        &[
            "sign",
            "--key-set",
            "keys.keyset",
            "--key",
            "x.rrk",
            "advisory-1.draft",
        ],
    );
    assert!(err.contains("is not in the key set"), "{err}");
}

// ── Under a real terminal ───────────────────────────────────────────

/// `script` on PATH, if there is one.
fn script_on_path() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("script"))
        .find(|candidate| {
            std::fs::metadata(candidate)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
}

/// `script` killed and reaped when this goes out of scope (the tool under
/// it is hung up when its terminal closes).
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// How long a run under `script` may take.
const LIMIT: Duration = Duration::from_secs(60);

/// Run the tool under `script` in `dir`, typing each `(prompt, line)`'s
/// line once the prompt has been shown that many times; what the terminal
/// showed.
fn in_terminal(script: &Path, dir: &Path, args: &[&str], typed: &[(&str, &str)]) -> String {
    let mut c = Command::new(script);
    if cfg!(target_os = "linux") {
        let quoted: Vec<String> = std::iter::once(TOOL)
            .chain(args.iter().copied())
            .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
            .collect();
        c.args(["-q", "-e", "-c", &quoted.join(" "), "/dev/null"])
            .env("SHELL", "/bin/sh");
    } else {
        c.args(["-q", "/dev/null", TOOL]).args(args);
    }
    let mut child = Running(
        c.current_dir(dir)
            .env("TERM", "dumb")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn script"),
    );
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut stdout = child.0.stdout.take().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut stdin = child.0.stdin.take().unwrap();
    let started = Instant::now();
    let mut output = Vec::new();
    let mut seen: Vec<(&str, usize)> = Vec::new();
    for (prompt, line) in typed {
        let n = match seen.iter_mut().find(|(p, _)| p == prompt) {
            Some((_, n)) => {
                *n += 1;
                *n
            }
            None => {
                seen.push((prompt, 1));
                1
            }
        };
        while String::from_utf8_lossy(&output).matches(prompt).count() < n {
            assert!(
                started.elapsed() < LIMIT,
                "no prompt {prompt:?}; the terminal showed:\n{}",
                String::from_utf8_lossy(&output)
            );
            if let Ok(bytes) = rx.recv_timeout(Duration::from_millis(50)) {
                output.extend(bytes);
            }
        }
        // Echo goes off just after the prompt is shown.
        thread::sleep(Duration::from_millis(300));
        stdin.write_all(format!("{line}\r").as_bytes()).unwrap();
        stdin.flush().unwrap();
    }
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(bytes) => output.extend(bytes),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                assert!(
                    started.elapsed() < LIMIT,
                    "the run did not end; the terminal showed:\n{}",
                    String::from_utf8_lossy(&output)
                );
            }
        }
    }
    drop(stdin);
    String::from_utf8_lossy(&output).into_owned()
}

#[test]
fn a_key_made_at_a_terminal_signs_with_its_passphrase_and_never_with_another() {
    let Some(script) = script_on_path() else {
        eprintln!("skipped: `script` is not on PATH");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let shown = in_terminal(
        &script,
        dir,
        &[
            "keygen",
            "--label",
            "release-a",
            "--out",
            "a.rrk",
            "--test-kdf",
        ],
        &[("New passphrase", PASS), ("Same passphrase again", PASS)],
    );
    assert!(shown.contains("public key:"), "{shown}");
    let file = KeyFile::decode(&read(dir, "a.rrk")).expect("a key file");
    assert_eq!(file.label(), "release-a");
    assert_eq!(file.params(), TEST_KDF);
    assert!(file.unlock(PASS.as_bytes()).is_ok());
    let public = to_hex(&file.public_key());
    assert!(String::from_utf8_lossy(&read(dir, "a.rrk.pub")).starts_with(&public));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("a.rrk"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // A 1-of-1 set of that key; an advisory signed at the terminal.
    ok(
        dir,
        &["keyset", "--threshold", "1", "--out", "one.keyset", "a.rrk"],
    );
    write_files(dir);
    ok(
        dir,
        &[
            "advisory",
            "--key-set",
            "one.keyset",
            "--spec",
            "advisory-1.json",
            "--out",
            "advisory-1.draft",
        ],
    );
    let shown = in_terminal(
        &script,
        dir,
        &[
            "sign",
            "--key-set",
            "one.keyset",
            "--key",
            "a.rrk",
            "advisory-1.draft",
        ],
        &[("Passphrase (key release-a)", "not the passphrase at all")],
    );
    assert!(shown.contains("does not open this key file"), "{shown}");
    assert!(!dir.join("advisory-1.draft.sig-0").exists());
    let shown = in_terminal(
        &script,
        dir,
        &[
            "sign",
            "--key-set",
            "one.keyset",
            "--key",
            "a.rrk",
            "advisory-1.draft",
        ],
        &[("Passphrase (key release-a)", PASS)],
    );
    assert!(shown.contains("security advisory #1"), "{shown}");
    assert!(!shown.contains(PASS), "the passphrase was shown:\n{shown}");
    ok(
        dir,
        &[
            "combine",
            "--key-set",
            "one.keyset",
            "--draft",
            "advisory-1.draft",
            "--out",
            "advisory-1.rad1",
            "advisory-1.draft.sig-0",
        ],
    );
    let advisory = Advisory::decode(&read(dir, "advisory-1.rad1")).unwrap();
    let one = raven_core::release_sign::read_key_set(&dir.join("one.keyset")).unwrap();
    advisory.verify(&one).expect("raven-core verifies it");
}
