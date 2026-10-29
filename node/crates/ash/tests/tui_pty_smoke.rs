//! The full screen in a real pseudo-terminal: `raven` with RAVEN_UI=tui runs
//! under `script`, opens on an empty profile (WZ-1), takes a `q`, and leaves
//! the terminal exactly as it found it (`stty -g` before and after). And on a
//! profile with one friend not verified yet, VF takes the friend's security
//! words as they are read out and says they match. `raven erase` takes its
//! typed word, and so does the app's 'Erase Raven from this computer', which
//! then leaves nothing of the profile behind (privacy pack PP.16, PP.22).
//! L on Home locks: with Raven's own login item (a lab one, fake tools) the
//! item is unloaded for this login session only, the lock is recorded, and
//! opening the app again clears it (PP.23). A lock `raven lock` set is kept
//! when the app opens: UNLOCK asks, Esc keeps it, Enter clears it (review
//! E-harness-docs-ci-3).
//!
//! Every run uses a throwaway profile, the file-backed (`locked-file`) secret
//! stores and a loopback listen address, so nothing here can reach the OS
//! keychain or the network. A profile with no identity starts no node.
//! Every `script` runs inside a [`Running`], so a test that fails leaves
//! nothing running (review E-harness-docs-ci-4).
//!
//! Skipped (with a message) where `script` is not on PATH. Unix only: it is
//! the Unix terminal this checks.
#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// The alternate screen on and off: the screen opened, and was put back.
const ALT_SCREEN_ON: &str = "\x1b[?1049h";
const ALT_SCREEN_OFF: &str = "\x1b[?1049l";

/// The terminal's settings before and after the run, with Raven run between
/// them in an 80x24 window; Raven's exit code is the shell's.
const SNIPPET: &str = "stty rows 24 cols 80; stty -g > before; \
                       RAVEN_UI=tui \"$RAVEN\" --data-dir \"$D\"; status=$?; \
                       stty -g > after; exit $status";

/// How long after the start the `q` goes in, at the least.
const KEY_AFTER: Duration = Duration::from_secs(2);

/// How long the screen may take to open, and the run to end after the `q`.
const LIMIT: Duration = Duration::from_secs(60);

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

/// `script` running [`SNIPPET`] in `work`, with Raven's profile in `profile`
/// (util-linux's options on Linux, the BSD ones elsewhere).
fn script_command(script: &Path, work: &Path, profile: &Path) -> Command {
    let mut c = Command::new(script);
    if cfg!(target_os = "linux") {
        c.args(["-q", "-e", "-c", SNIPPET, "/dev/null"])
            .env("SHELL", "/bin/sh");
    } else {
        c.args(["-q", "/dev/null", "/bin/sh", "-c", SNIPPET]);
    }
    c.current_dir(work)
        .env("RAVEN", env!("CARGO_BIN_EXE_raven"))
        .env("D", profile)
        .env("TERM", "xterm-256color")
        .env("RAVEN_IDENTITY_BACKEND", "locked-file")
        .env("RAVEN_SESSION_BACKEND", "locked-file")
        .env("RAVEN_PREKEY_BACKEND", "locked-file")
        .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
        .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
        .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0")
        .env_remove("RAVEN_UI")
        .env_remove("RAVEN_PEER")
        .env_remove("ASH_LAN_DIAL")
        .env_remove("RAVEN_INTERNET_LISTEN")
        .env_remove("RAVEN_P2P_LISTEN")
        .env_remove("RAVEN_P2P_RELAYS")
        .env_remove("RAVEN_P2P_RELAY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    without_privacy_switches(&mut c);
    c
}

/// Plain profiles, whatever privacy switches the suite runs with (the
/// scripts expect no one-time sealing notice, and the tests read the
/// profile's files themselves); a test that wants a lab login item or an
/// erase root sets it after this.
fn without_privacy_switches(c: &mut Command) {
    for switch in raven_core::lan_gate::PRIVACY_LAB_SWITCHES {
        c.env_remove(switch);
    }
}

/// What a profile may hold before its identity exists (raven-core's inert
/// first-install entries, as far as an app that made nothing could leave
/// them).
fn inert(name: &str) -> bool {
    name.starts_with(".identity_store.lock.sqlite")
        || name == raven_core::keystore_select::KEYSTORE_MARKER_NAME
        || name == ".DS_Store"
}

/// How long a guard waits, once `script` is gone, for what ran under it to
/// end with its terminal (it is killed after that).
const GONE_WAIT: Duration = Duration::from_secs(10);

/// `script` and what runs under it, stopped when this goes out of scope, on
/// a failed assert's unwinding too (review E-harness-docs-ci-4): a
/// `std::process::Child` is not killed on drop, so a test that failed left
/// `script`, its shell and the app running in a profile its `TempDir` then
/// deleted. `script` is killed and reaped; the app, hung up when its
/// pseudo-terminal closes, is waited for and, should it stay, killed by its
/// process id. What ran under it is found by the profile's path, which its
/// command line names (`--data-dir`).
struct Running {
    child: std::process::Child,
    profile: PathBuf,
}

impl Running {
    fn new(child: std::process::Child, profile: &Path) -> Running {
        Running {
            child,
            profile: profile.to_path_buf(),
        }
    }
}

impl std::ops::Deref for Running {
    type Target = std::process::Child;

    fn deref(&self) -> &std::process::Child {
        &self.child
    }
}

impl std::ops::DerefMut for Running {
    fn deref_mut(&mut self) -> &mut std::process::Child {
        &mut self.child
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let started = Instant::now();
        loop {
            let left = processes_naming(&self.profile);
            if left.is_empty() {
                return;
            }
            if started.elapsed() > GONE_WAIT {
                for pid in left {
                    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
                }
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The ids of the processes whose command line names `path` (`pgrep -f`;
/// none where there is no pgrep). A test's profile path is its own.
fn processes_naming(path: &Path) -> Vec<u32> {
    let Ok(out) = Command::new("pgrep").arg("-f").arg(path).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

/// What reached the terminal next, within 50 ms, added to `output`.
fn take(rx: &mpsc::Receiver<Vec<u8>>, output: &mut Vec<u8>) {
    if let Ok(bytes) = rx.recv_timeout(Duration::from_millis(50)) {
        output.extend(bytes);
    }
}

#[test]
fn the_full_screen_opens_quits_on_q_and_restores_the_terminal() {
    let Some(script) = script_on_path() else {
        eprintln!("skipped: `script` is not on PATH");
        return;
    };
    let (profile, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut child = Running::new(
        script_command(&script, work.path(), profile.path())
            .spawn()
            .expect("spawn script"),
        profile.path(),
    );
    let started = Instant::now();
    // Everything the terminal was sent, as it arrives.
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stderr.read_to_end(&mut text);
        text
    });
    let mut output = Vec::new();
    // The `q` once the screen is up (and no sooner than 2 s in). The pipe
    // stays open until the end: some `script`s end the session at EOF.
    let mut stdin = child.stdin.take().unwrap();
    while !String::from_utf8_lossy(&output).contains(ALT_SCREEN_ON) || started.elapsed() < KEY_AFTER
    {
        let ended = child.try_wait().expect("wait for script");
        assert!(
            ended.is_none() && started.elapsed() < LIMIT,
            "the screen did not open ({ended:?}):\n{}",
            String::from_utf8_lossy(&output)
        );
        take(&rx, &mut output);
    }
    stdin.write_all(b"q").expect("type q");
    stdin.flush().expect("type q");
    let typed = Instant::now();
    let status = loop {
        take(&rx, &mut output);
        if let Some(status) = child.try_wait().expect("wait for script") {
            break status;
        }
        if typed.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "raven did not quit on q:\n{}",
                String::from_utf8_lossy(&output)
            );
        }
    };
    drop(stdin);
    reader.join().expect("the output reader");
    output.extend(rx.try_iter().flatten());
    let output = String::from_utf8_lossy(&output).into_owned();
    let errors = String::from_utf8_lossy(&errors.join().expect("stderr")).into_owned();

    assert!(
        status.success(),
        "exit {status}:\n{output}\nstderr:\n{errors}"
    );
    assert!(output.contains(ALT_SCREEN_ON), "{output}");
    assert!(output.contains(ALT_SCREEN_OFF), "{output}");
    let on = output.find(ALT_SCREEN_ON).unwrap();
    assert!(output.rfind(ALT_SCREEN_OFF).unwrap() > on, "{output}");
    let read = |name: &str| {
        std::fs::read_to_string(work.path().join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}\n{output}"))
    };
    let (before, after) = (read("before"), read("after"));
    assert!(!before.trim().is_empty(), "{output}");
    assert_eq!(before, after, "the terminal was not put back as it was");
    // Nothing was made in the profile: no identity, no settings, no node.
    for entry in std::fs::read_dir(profile.path()).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(inert(&name), "{name} in a profile that was only opened");
    }
}

/// Review E-harness-docs-ci-4: a test that fails while the app runs (a
/// wait that ran out, say) leaves nothing running: unwinding drops its
/// [`Running`], which stops `script` and what ran under it, before the
/// test's `TempDir` deletes the profile.
#[test]
fn a_test_that_fails_while_the_app_runs_leaves_nothing_running() {
    let Some(script) = script_on_path() else {
        eprintln!("skipped: `script` is not on PATH");
        return;
    };
    let (profile, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let path = profile.path().to_path_buf();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut child = Running::new(
            script_command(&script, work.path(), &path)
                .spawn()
                .expect("spawn script"),
            &path,
        );
        // What the terminal is sent is read to its end, as by the reader
        // of each test above: blocked in a read while the app is idle, it
        // keeps `script`'s output open after a failure.
        let mut stdout = child.stdout.take().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });
        // The app runs (its command line names the profile) ...
        let started = Instant::now();
        while processes_naming(&path).is_empty() {
            let ended = child.try_wait().expect("wait for script");
            assert!(
                ended.is_none() && started.elapsed() < LIMIT,
                "the app did not start ({ended:?})"
            );
            thread::sleep(Duration::from_millis(50));
        }
        // ... when a wait of the test runs out.
        let waited = Instant::now();
        while waited.elapsed() < Duration::from_secs(1) {
            assert!(child.try_wait().expect("wait for script").is_none());
            thread::sleep(Duration::from_millis(50));
        }
        panic!("waiting for a screen that never came (on purpose)");
    }));
    assert!(failed.is_err(), "the test did not fail");
    let left = processes_naming(&path);
    assert!(left.is_empty(), "still running after the failure: {left:?}");
}

/// What an 80x24 terminal shows after the bytes Raven sent it: as much of a
/// VT100 as ratatui's output needs (cursor moves and clears; colours and
/// modes are ignored).
struct Screen {
    rows: Vec<Vec<char>>,
    at: (usize, usize),
    /// The start of a character or escape sequence cut by a read.
    pending: Vec<u8>,
}

impl Screen {
    const ROWS: usize = 24;
    const COLS: usize = 80;

    fn new() -> Screen {
        Screen {
            rows: vec![vec![' '; Screen::COLS]; Screen::ROWS],
            at: (0, 0),
            pending: Vec::new(),
        }
    }

    fn clear(&mut self) {
        self.rows = vec![vec![' '; Screen::COLS]; Screen::ROWS];
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        let valid = match std::str::from_utf8(&self.pending) {
            Ok(text) => text.len(),
            Err(e) => e.valid_up_to(),
        };
        let text = String::from_utf8_lossy(&self.pending[..valid]).into_owned();
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '\x1b' => match self.escape(&chars[i..]) {
                    Some(len) => i += len,
                    // Cut by the read: the rest comes with the next one.
                    None => break,
                },
                '\r' => {
                    self.at.1 = 0;
                    i += 1;
                }
                '\n' => {
                    self.at.0 = (self.at.0 + 1).min(Screen::ROWS - 1);
                    i += 1;
                }
                c if c >= ' ' => {
                    let (row, col) = self.at;
                    if row < Screen::ROWS && col < Screen::COLS {
                        self.rows[row][col] = c;
                    }
                    self.at.1 += 1;
                    i += 1;
                }
                _ => i += 1,
            }
        }
        let used: usize = chars[..i].iter().map(|c| c.len_utf8()).sum();
        self.pending.drain(..used);
    }

    /// The escape sequence at the start of `chars`, carried out: its
    /// length, or None when it is not all there yet.
    fn escape(&mut self, chars: &[char]) -> Option<usize> {
        match chars.get(1)? {
            '[' => {
                let end = chars
                    .iter()
                    .skip(2)
                    .position(|c| ('\x40'..='\x7e').contains(c))?
                    + 2;
                let params: String = chars[2..end].iter().collect();
                let numbers: Vec<usize> = params
                    .split(';')
                    .map(|n| n.trim_start_matches('?').parse().unwrap_or(0))
                    .collect();
                let n = |i: usize| numbers.get(i).copied().unwrap_or(0).max(1);
                match chars[end] {
                    'H' | 'f' => self.at = (n(0) - 1, n(1) - 1),
                    'J' => self.clear(),
                    'K' => {
                        let (row, col) = self.at;
                        if row < Screen::ROWS {
                            for cell in self.rows[row].iter_mut().skip(col) {
                                *cell = ' ';
                            }
                        }
                    }
                    'h' if params == "?1049" => self.clear(),
                    _ => {}
                }
                Some(end + 1)
            }
            ']' => {
                let end = chars.iter().position(|c| *c == '\x07')?;
                Some(end + 1)
            }
            _ => Some(2),
        }
    }

    fn text(&self) -> String {
        self.rows
            .iter()
            .map(|row| row.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// `ash --data-dir <profile> <args>` with the file-backed stores: it must
/// succeed.
fn ash(profile: &Path, args: &[&str]) {
    ash_with(profile, args, &[]);
}

/// [`ash`] with more environment (the lab's login-item folders, say).
fn ash_with(profile: &Path, args: &[&str], env: &[(&str, &Path)]) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ash"));
    c.arg("--data-dir")
        .arg(profile)
        .args(args)
        .env("RAVEN_IDENTITY_BACKEND", "locked-file")
        .env("RAVEN_SESSION_BACKEND", "locked-file")
        .env("RAVEN_PREKEY_BACKEND", "locked-file")
        .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
        .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
        .env_remove("RAVEN_PEER")
        .env_remove("ASH_LAN_DIAL")
        .env_remove("RAVEN_SERVICE_LAN_LISTEN")
        .stdin(Stdio::null());
    without_privacy_switches(&mut c);
    for (key, value) in env {
        c.env(key, value);
    }
    let out = c.output().expect("run ash");
    assert!(
        out.status.success(),
        "ash {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// RFC 8032's first test key: the security words of
/// shared-vectors/rvn1/security_words/words_alice_001.json.
const ALICE_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ALICE_WORDS: &str = "turtle frog bread wolf paper laptop funnel mango honey wagon";

#[test]
fn vf_takes_alices_words_as_she_reads_them() {
    use raven_core::identity::Identity;
    let Some(script) = script_on_path() else {
        eprintln!("skipped: `script` is not on PATH");
        return;
    };
    let (profile, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    // A profile with Alice saved, not verified.
    let seed: [u8; 32] = hex::decode(ALICE_SEED).unwrap().try_into().unwrap();
    let alice = Identity::from_seed(&seed);
    let alice_hex = hex::encode(alice.public_key_bytes());
    ash(profile.path(), &["init"]);
    ash(
        profile.path(),
        &[
            "contact",
            "add",
            "--address",
            &alice.address(),
            "--pub-hex",
            &alice_hex,
            "--petname",
            "Alice",
        ],
    );
    let mut child = Running::new(
        script_command(&script, work.path(), profile.path())
            .spawn()
            .expect("spawn script"),
        profile.path(),
    );
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stderr.read_to_end(&mut text);
        text
    });
    let mut stdin = child.stdin.take().unwrap();
    let mut screen = Screen::new();
    // Until `text` is on the screen (or, with `gone`, off it).
    let wait = |screen: &mut Screen, child: &mut std::process::Child, text: &str, gone| {
        let started = Instant::now();
        while screen.text().contains(text) == gone {
            let ended = child.try_wait().expect("wait for script");
            assert!(
                ended.is_none() && started.elapsed() < LIMIT,
                "waiting for {text:?} (gone: {gone}, {ended:?}):\n{}",
                screen.text()
            );
            if let Ok(bytes) = rx.recv_timeout(Duration::from_millis(50)) {
                screen.feed(&bytes);
            }
        }
    };
    let mut type_text = |text: &str| {
        stdin.write_all(text.as_bytes()).expect("type");
        stdin.flush().expect("type");
    };
    // Receiving: not now. Home, Alice highlighted: V.
    wait(
        &mut screen,
        &mut child,
        "Receive messages on this computer?",
        false,
    );
    type_text("n");
    wait(
        &mut screen,
        &mut child,
        "Receive messages on this computer?",
        true,
    );
    type_text("v");
    wait(&mut screen, &mut child, "Check it's really Alice", false);
    assert!(screen.text().contains("Word 1 of 10:"), "{}", screen.text());
    // Her words as she reads them; Enter once a paste's guard is over.
    type_text(ALICE_WORDS);
    wait(&mut screen, &mut child, "Word 10 of 10: wagon", false);
    assert!(!screen.text().contains("They match"), "{}", screen.text());
    thread::sleep(Duration::from_millis(500));
    type_text("\r");
    wait(&mut screen, &mut child, "They match", false);
    // Her words, numbered, now that they matched.
    wait(&mut screen, &mut child, "10 wagon", false);
    // Esc: nothing saved.
    type_text("\x1b");
    wait(&mut screen, &mut child, "Check it's really Alice", true);
    // Q, then Enter: an Enter within 30 ms of a typed key is a paste's
    // line break, which never confirms.
    type_text("q");
    wait(&mut screen, &mut child, "[Enter] Quit", false);
    thread::sleep(Duration::from_millis(200));
    type_text("\r");
    let typed = Instant::now();
    let status = loop {
        while let Ok(bytes) = rx.try_recv() {
            screen.feed(&bytes);
        }
        if let Some(status) = child.try_wait().expect("wait for script") {
            break status;
        }
        if typed.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("raven did not quit:\n{}", screen.text());
        }
        thread::sleep(Duration::from_millis(50));
    };
    // The typing closure's borrow of stdin ended at its last use.
    drop(stdin);
    reader.join().expect("the output reader");
    let errors = String::from_utf8_lossy(&errors.join().expect("stderr")).into_owned();
    assert!(
        status.success(),
        "exit {status}:\n{}\nstderr:\n{errors}",
        screen.text()
    );
    let read = |name: &str| std::fs::read_to_string(work.path().join(name)).unwrap();
    assert_eq!(
        read("before"),
        read("after"),
        "the terminal was not put back"
    );
    // Alice is still not verified: Esc saved nothing.
    let contacts = std::fs::read_to_string(profile.path().join("contacts.json")).unwrap();
    assert!(contacts.contains(&alice_hex), "{contacts}");
    assert!(!contacts.contains("\"pinned\": true"), "{contacts}");
}

/// Privacy pack PP.16: `raven erase` in a real terminal. A word typed ahead
/// of the question is dropped, the typed `erase` (after a human pause)
/// erases, the result is the UX copy's, and the profile folder is gone. Lab
/// switches: the erase root (debug builds erase only inside it) and empty
/// login-item folders, so nothing real is read or run.
#[test]
fn erase_on_a_terminal_takes_the_typed_word() {
    let Some(script) = script_on_path() else {
        eprintln!("skipped: `script` is not on PATH");
        return;
    };
    let (root, work, lab) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let profile = root.path().join("a");
    std::fs::create_dir_all(&profile).unwrap();
    ash(&profile, &["init"]);
    assert!(profile.join("identity.backend").exists());
    let (items, tools) = (lab.path().join("items"), lab.path().join("tools"));
    std::fs::create_dir_all(&items).unwrap();
    std::fs::create_dir_all(&tools).unwrap();
    let mut c = Command::new(&script);
    let snippet = "\"$RAVEN\" --data-dir \"$D\" erase; exit $?";
    if cfg!(target_os = "linux") {
        c.args(["-q", "-e", "-c", snippet, "/dev/null"])
            .env("SHELL", "/bin/sh");
    } else {
        c.args(["-q", "/dev/null", "/bin/sh", "-c", snippet]);
    }
    let child = c
        .current_dir(work.path())
        .env("RAVEN", env!("CARGO_BIN_EXE_raven"))
        .env("D", &profile)
        .env("TERM", "xterm-256color")
        .env("RAVEN_IDENTITY_BACKEND", "locked-file")
        .env("RAVEN_SESSION_BACKEND", "locked-file")
        .env("RAVEN_PREKEY_BACKEND", "locked-file")
        .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
        .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
        .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0")
        .env("RAVEN_LAB_ERASE_ROOT", root.path())
        .env("RAVEN_LAB_LOGIN_ITEM_ROOT", &items)
        .env("RAVEN_LAB_LOGIN_ITEM_TOOLS", &tools)
        .env_remove("RAVEN_PEER")
        .env_remove("ASH_LAN_DIAL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn script");
    let mut child = Running::new(child, &profile);
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut stdin = child.stdin.take().unwrap();
    let started = Instant::now();
    let mut output = Vec::new();
    // Typed ahead, before the question is there: dropped unread (or, should
    // it arrive late, refused as too fast). Never taken.
    stdin.write_all(b"erase\n").unwrap();
    stdin.flush().unwrap();
    while !String::from_utf8_lossy(&output).contains("Type erase to confirm:") {
        let ended = child.try_wait().expect("wait for script");
        assert!(
            ended.is_none() && started.elapsed() < LIMIT,
            "no question ({ended:?}):\n{}",
            String::from_utf8_lossy(&output)
        );
        take(&rx, &mut output);
    }
    assert!(
        String::from_utf8_lossy(&output).contains("Erase Raven from this computer?"),
        "{}",
        String::from_utf8_lossy(&output)
    );
    // A person reads, then types. Until then nothing happens.
    let reading = Instant::now();
    while reading.elapsed() < Duration::from_millis(1200) {
        take(&rx, &mut output);
    }
    assert!(
        child.try_wait().expect("wait for script").is_none()
            && !String::from_utf8_lossy(&output).contains("Stopping Raven"),
        "the typed-ahead word was taken:\n{}",
        String::from_utf8_lossy(&output)
    );
    stdin.write_all(b"erase\n").unwrap();
    stdin.flush().unwrap();
    let typed = Instant::now();
    let status = loop {
        take(&rx, &mut output);
        if let Some(status) = child.try_wait().expect("wait for script") {
            break status;
        }
        if typed.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("erase did not end:\n{}", String::from_utf8_lossy(&output));
        }
    };
    drop(stdin);
    reader.join().expect("the output reader");
    output.extend(rx.try_iter().flatten());
    let output = String::from_utf8_lossy(&output).into_owned();
    assert!(status.success(), "exit {status}:\n{output}");
    assert!(output.contains("Stopping Raven..."), "{output}");
    assert!(
        output.contains("Erased: identity, friends, chats, waiting messages and "),
        "{output}"
    );
    assert!(
        output.contains("Not erased: your shell history and terminal scrollback;"),
        "{output}"
    );
    assert!(!profile.exists(), "the profile folder is gone:\n{output}");
}

/// Privacy pack PP.22: the full-screen app's 'Erase Raven from this
/// computer' in a real terminal. SET's last row, the word typed key by key
/// (a paste would clear it), then Enter after a human pause: the app ends
/// on a cleared terminal with the result list, exit 0, the terminal as it
/// was, and the profile folder gone: nothing (no tui_state.json) was saved
/// after the erase. Lab switches as for `raven erase` above.
#[test]
fn the_app_erases_the_profile_and_saves_nothing_after() {
    let Some(script) = script_on_path() else {
        eprintln!("skipped: `script` is not on PATH");
        return;
    };
    let (root, work, lab) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let profile = root.path().join("a");
    std::fs::create_dir_all(&profile).unwrap();
    ash(&profile, &["init"]);
    let (items, tools) = (lab.path().join("items"), lab.path().join("tools"));
    std::fs::create_dir_all(&items).unwrap();
    std::fs::create_dir_all(&tools).unwrap();
    let mut child = Running::new(
        script_command(&script, work.path(), &profile)
            .env("RAVEN_LAB_ERASE_ROOT", root.path())
            .env("RAVEN_LAB_LOGIN_ITEM_ROOT", &items)
            .env("RAVEN_LAB_LOGIN_ITEM_TOOLS", &tools)
            .spawn()
            .expect("spawn script"),
        &profile,
    );
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stderr.read_to_end(&mut text);
        text
    });
    let mut stdin = child.stdin.take().unwrap();
    let mut screen = Screen::new();
    let mut output = Vec::new();
    // Until `text` is on the screen.
    let mut wait = |screen: &mut Screen, output: &mut Vec<u8>, text: &str| {
        let started = Instant::now();
        while !screen.text().contains(text) {
            let ended = child.try_wait().expect("wait for script");
            assert!(
                ended.is_none() && started.elapsed() < LIMIT,
                "waiting for {text:?} ({ended:?}):\n{}",
                screen.text()
            );
            if let Ok(bytes) = rx.recv_timeout(Duration::from_millis(50)) {
                screen.feed(&bytes);
                output.extend(bytes);
            }
        }
    };
    // One key at a time, as a person types: a burst would be a paste.
    let mut type_keys = |keys: &str| {
        for key in keys.bytes() {
            stdin.write_all(&[key]).expect("type");
            stdin.flush().expect("type");
            thread::sleep(Duration::from_millis(80));
        }
    };
    wait(&mut screen, &mut output, "R A V E N");
    thread::sleep(KEY_AFTER);
    type_keys("s");
    wait(&mut screen, &mut output, "Settings");
    type_keys(&"j".repeat(16));
    wait(
        &mut screen,
        &mut output,
        ">  Erase Raven from this computer",
    );
    type_keys("\r");
    wait(&mut screen, &mut output, "Type erase to confirm:");
    assert!(screen.text().contains("your identity"), "{}", screen.text());
    type_keys("erase");
    wait(&mut screen, &mut output, "> erase");
    thread::sleep(Duration::from_millis(500));
    type_keys("\r");
    let typed = Instant::now();
    let status = loop {
        while let Ok(bytes) = rx.try_recv() {
            output.extend(bytes);
        }
        if let Some(status) = child.try_wait().expect("wait for script") {
            break status;
        }
        if typed.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "the erase did not end:\n{}",
                String::from_utf8_lossy(&output)
            );
        }
        thread::sleep(Duration::from_millis(50));
    };
    reader.join().expect("the output reader");
    output.extend(rx.try_iter().flatten());
    let output = String::from_utf8_lossy(&output).into_owned();
    let errors = String::from_utf8_lossy(&errors.join().expect("stderr")).into_owned();
    assert!(
        status.success(),
        "exit {status}:\n{output}\nstderr:\n{errors}"
    );
    // After the full screen: the terminal cleared (its scrollback too), then
    // the result list, and only that.
    let after = &output[output.rfind(ALT_SCREEN_OFF).expect("the screen left")..];
    let cleared = after.find("\x1b[3J").expect("the terminal cleared");
    let result = after
        .find("Erased: identity, friends, chats, waiting messages and ")
        .unwrap_or_else(|| panic!("no result list:\n{after}"));
    assert!(cleared < result, "{after}");
    assert!(
        after.contains("Not erased: your shell history and terminal scrollback;"),
        "{after}"
    );
    assert!(!after.contains("When I quit"), "{after}");
    let read = |name: &str| std::fs::read_to_string(work.path().join(name)).unwrap();
    assert_eq!(
        read("before"),
        read("after"),
        "the terminal was not put back"
    );
    assert!(!profile.exists(), "the profile folder is gone:\n{after}");
}

/// Raven's login item for `profile` as the installers write it, in the lab
/// folder `items`, and fake `launchctl` and `systemctl` in `tools` that
/// append each run to `runs`: no real login item is read or changed.
fn lab_login_item(items: &Path, tools: &Path, runs: &Path, profile: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(items).unwrap();
    std::fs::create_dir_all(tools).unwrap();
    let dir = profile.display().to_string();
    let (file, text) = if cfg!(target_os = "macos") {
        (
            "com.raven.raven-node.plist",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n  \
                 <key>Label</key><string>com.raven.raven-node</string>\n  \
                 <key>ProgramArguments</key>\n  <array>\n    \
                 <string>/opt/raven/bin/raven-node</string>\n    <string>service</string>\n    \
                 <string>--data-dir</string>\n    <string>{dir}</string>\n  </array>\n  \
                 <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n</dict>\n</plist>\n"
            ),
        )
    } else {
        (
            "raven-node.service",
            format!(
                "[Service]\nExecStart=\"/opt/raven/bin/raven-node\" service --data-dir \
                 \"{dir}\"\nRestart=on-failure\n"
            ),
        )
    };
    std::fs::write(items.join(file), text).unwrap();
    for name in ["launchctl", "systemctl"] {
        let path = tools.join(name);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$(basename \"$0\") $*\" >> '{}'\n",
                runs.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// The app on `profile` with the lab login item, until it exits: each
/// `(text, keys)` waits for `text` on the screen, then types `keys` one at
/// a time. Its exit status and everything it wrote.
fn run_app_with(
    script: &Path,
    work: &Path,
    profile: &Path,
    lab: (&Path, &Path),
    steps: &[(&str, &str)],
) -> (std::process::ExitStatus, String) {
    let mut child = Running::new(
        script_command(script, work, profile)
            .env("RAVEN_LAB_LOGIN_ITEM_ROOT", lab.0)
            .env("RAVEN_LAB_LOGIN_ITEM_TOOLS", lab.1)
            .spawn()
            .expect("spawn script"),
        profile,
    );
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stderr.read_to_end(&mut text);
        text
    });
    let mut stdin = child.stdin.take().unwrap();
    let mut screen = Screen::new();
    let mut output = Vec::new();
    let started = Instant::now();
    for (at, (text, keys)) in steps.iter().enumerate() {
        while !screen.text().contains(text) {
            let ended = child.try_wait().expect("wait for script");
            if ended.is_some() || started.elapsed() > LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "waiting for {text:?} ({ended:?}):\n{}\n{}",
                    screen.text(),
                    String::from_utf8_lossy(&output)
                );
            }
            if let Ok(bytes) = rx.recv_timeout(Duration::from_millis(50)) {
                screen.feed(&bytes);
                output.extend(bytes);
            }
        }
        // The first keys after the screen opened, and every Enter, come as
        // a person's would: not with the screen, nor with a paste.
        thread::sleep(if at == 0 {
            KEY_AFTER
        } else {
            Duration::from_millis(500)
        });
        for key in keys.bytes() {
            stdin.write_all(&[key]).expect("type");
            stdin.flush().expect("type");
            thread::sleep(Duration::from_millis(80));
        }
    }
    let typed = Instant::now();
    let status = loop {
        while let Ok(bytes) = rx.try_recv() {
            output.extend(bytes);
        }
        if let Some(status) = child.try_wait().expect("wait for script") {
            break status;
        }
        if typed.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the app did not end:\n{}", String::from_utf8_lossy(&output));
        }
        thread::sleep(Duration::from_millis(50));
    };
    reader.join().expect("the output reader");
    output.extend(rx.try_iter().flatten());
    let errors = String::from_utf8_lossy(&errors.join().expect("stderr")).into_owned();
    let output = String::from_utf8_lossy(&output).into_owned();
    assert!(
        status.success(),
        "exit {status}:\n{output}\nstderr:\n{errors}"
    );
    (status, output)
}

#[test]
fn l_on_home_locks_until_login_and_opening_the_app_clears_it() {
    use raven_core::privacy::{lock_state, LockedItem};
    let Some(script) = script_on_path() else {
        eprintln!("skipped: `script` is not on PATH");
        return;
    };
    let (root, work, lab) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let profile = root.path().join("a");
    std::fs::create_dir_all(&profile).unwrap();
    ash(&profile, &["init"]);
    let (items, tools, runs) = (
        lab.path().join("items"),
        lab.path().join("tools"),
        lab.path().join("runs.log"),
    );
    lab_login_item(&items, &tools, &runs, &profile);
    // L on the friend list: LOCK says Raven's own login item starts Raven
    // again at the next login; Enter locks.
    let (_, output) = run_app_with(
        &script,
        work.path(),
        &profile,
        (&items, &tools),
        &[
            ("R A V E N", "l"),
            ("run `raven lock` in a terminal.", "\r"),
        ],
    );
    let after = &output[output.rfind(ALT_SCREEN_OFF).expect("the screen left")..];
    let cleared = after.find("\x1b[3J").expect("the terminal cleared");
    let line = after
        .find("Raven is stopped until you log in again.")
        .unwrap_or_else(|| panic!("no exit line:\n{after}"));
    assert!(cleared < line, "{after}");
    // Unloaded for this login session, never turned off; the lock is kept,
    // so a send starts no Raven, and `raven unlock` would load it again.
    let ran = std::fs::read_to_string(&runs).expect("the tool ran");
    let ran: Vec<&str> = ran.lines().collect();
    assert_eq!(ran.len(), 1, "{ran:?}");
    assert!(
        ran[0].starts_with("launchctl bootout gui/")
            || ran[0] == "systemctl --user stop raven-node.service",
        "{ran:?}"
    );
    let locked = lock_state(&profile);
    assert!(locked.locked_by_user);
    assert_eq!(locked.login_item, Some(LockedItem::Unloaded));
    // Opening the app again is its way to start Raven: the lock is gone,
    // and no tool ran (the app never turns the item on or off).
    run_app_with(
        &script,
        work.path(),
        &profile,
        (&items, &tools),
        &[("R A V E N", "q"), ("[Enter] Quit", "\r")],
    );
    let opened = lock_state(&profile);
    assert!(!opened.locked_by_user);
    assert_eq!(opened.login_item, Some(LockedItem::Unloaded));
    assert_eq!(
        std::fs::read_to_string(&runs)
            .expect("the runs")
            .lines()
            .count(),
        1
    );
}

/// Review E-harness-docs-ci-3: a lock `raven lock` set is kept when the app
/// opens. UNLOCK asks first; Esc keeps it (the app quits with the profile
/// still locked), and Enter, the next time, clears it.
#[test]
fn after_raven_lock_the_app_asks_before_it_starts_raven() {
    use raven_core::privacy::lock_state;
    let Some(script) = script_on_path() else {
        eprintln!("skipped: `script` is not on PATH");
        return;
    };
    let (root, work, lab) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let profile = root.path().join("a");
    std::fs::create_dir_all(&profile).unwrap();
    ash(&profile, &["init"]);
    // Empty lab login-item folders: nothing real is read or run.
    let (items, tools) = (lab.path().join("items"), lab.path().join("tools"));
    std::fs::create_dir_all(&items).unwrap();
    std::fs::create_dir_all(&tools).unwrap();
    ash_with(
        &profile,
        &["lock", "--yes"],
        &[
            ("RAVEN_LAB_LOGIN_ITEM_ROOT", &items),
            ("RAVEN_LAB_LOGIN_ITEM_TOOLS", &tools),
        ],
    );
    assert!(lock_state(&profile).locked_by_user);
    // Esc: kept stopped, and the lock with it.
    let (_, output) = run_app_with(
        &script,
        work.path(),
        &profile,
        (&items, &tools),
        &[
            ("Start Raven again now?", "\x1b"),
            ("Raven stays stopped.", "q"),
            ("[Enter] Quit", "\r"),
        ],
    );
    assert!(output.contains(ALT_SCREEN_OFF), "{output}");
    assert!(lock_state(&profile).locked_by_user, "Esc keeps the lock");
    // Enter: the lock goes.
    run_app_with(
        &script,
        work.path(),
        &profile,
        (&items, &tools),
        &[
            ("Start Raven again now?", "\r"),
            ("R A V E N", "q"),
            ("[Enter] Quit", "\r"),
        ],
    );
    assert!(
        !lock_state(&profile).locked_by_user,
        "Enter clears the lock"
    );
}

/// Colors > Automatic in a terminal that says nothing of its background
/// in the environment (no COLORFGBG): the app asks it (OSC 11, then DA1) at
/// start, draws the Calm palette for the background it answers, never
/// shows the answer, and puts the terminal back as it was.
#[test]
fn automatic_colours_ask_the_terminal_and_draw_the_palette_it_answers() {
    const QUESTION: &str = "\x1b]11;?\x07\x1b[c";
    // A light background, then DA1's answer.
    const ANSWER: &[u8] = b"\x1b]11;rgb:fafa/f9f9/f5f5\x07\x1b[?62;22c";
    let Some(script) = script_on_path() else {
        eprintln!("skipped: `script` is not on PATH");
        return;
    };
    let (profile, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut command = script_command(&script, work.path(), profile.path());
    for name in ["COLORFGBG", "NO_COLOR", "COLORTERM", "WT_SESSION"] {
        command.env_remove(name);
    }
    let mut child = Running::new(command.spawn().expect("spawn script"), profile.path());
    let started = Instant::now();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stderr.read_to_end(&mut text);
        text
    });
    let mut output = Vec::new();
    let mut stdin = child.stdin.take().unwrap();
    // The question, then the terminal's answer.
    while !String::from_utf8_lossy(&output).contains(QUESTION) {
        let ended = child.try_wait().expect("wait for script");
        assert!(
            ended.is_none() && started.elapsed() < LIMIT,
            "the app never asked ({ended:?}):\n{}",
            String::from_utf8_lossy(&output)
        );
        take(&rx, &mut output);
    }
    stdin.write_all(ANSWER).expect("answer");
    stdin.flush().expect("answer");
    // The light palette's background (256 colours: #FAF9F5 is 231).
    let light = "48;5;231";
    while !String::from_utf8_lossy(&output).contains(light) || started.elapsed() < KEY_AFTER {
        let ended = child.try_wait().expect("wait for script");
        assert!(
            ended.is_none() && started.elapsed() < LIMIT,
            "no light palette ({ended:?}):\n{}",
            String::from_utf8_lossy(&output)
        );
        take(&rx, &mut output);
    }
    stdin.write_all(b"q").expect("type q");
    stdin.flush().expect("type q");
    let typed = Instant::now();
    let status = loop {
        take(&rx, &mut output);
        if let Some(status) = child.try_wait().expect("wait for script") {
            break status;
        }
        assert!(
            typed.elapsed() < LIMIT,
            "raven did not quit on q:\n{}",
            String::from_utf8_lossy(&output)
        );
    };
    drop(stdin);
    reader.join().expect("the output reader");
    output.extend(rx.try_iter().flatten());
    let output = String::from_utf8_lossy(&output).into_owned();
    let errors = String::from_utf8_lossy(&errors.join().expect("stderr")).into_owned();
    assert!(
        status.success(),
        "exit {status}:\n{output}\nstderr:\n{errors}"
    );
    // Asked once, before the first frame; the answer never on screen.
    assert_eq!(output.matches(QUESTION).count(), 1, "{output}");
    let asked = output.find(QUESTION).unwrap();
    assert!(output.find(light).unwrap() > asked, "{output}");
    assert!(
        !output.contains("rgb:fafa") && !output.contains("62;22c"),
        "{output}"
    );
    let read = |name: &str| {
        std::fs::read_to_string(work.path().join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}\n{output}"))
    };
    assert_eq!(
        read("before"),
        read("after"),
        "the terminal was not put back as it was"
    );
}
