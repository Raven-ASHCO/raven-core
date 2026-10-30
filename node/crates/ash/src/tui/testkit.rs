//! Test support for the terminal app, and the source scans that keep it
//! mergeable with the CLI it is built on.
//!
//! The scans read every `tui/*.rs` and `tui/ui/*.rs` file through
//! `include_str!` ([`SOURCES`]). A new file joins that list in the change that
//! creates it; `scan_list_covers_every_tui_file` fails until it does. Every
//! needle is built with `concat!`, so this file is scanned like any other.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;
use raven_core::chat_history::{BlockList, ChatHistoryEntry};
use raven_core::identity::Identity;
use raven_core::ipc::{IpcRequest, IpcResponse, OutboxItem, P2pStatusInfo};
use raven_core::node_policy::NodePolicy;

use super::app::{
    App, Cmd, IdentityStart, JobResult, Key, ListenOverride, Look, LookEnv, Msg, PasteVia, SendJob,
    Session, StoreJob,
};
use super::controller::{Conversations, PrivacyRead, RowView, SendOutcome, SendResult};
use super::live::{Carrier, Route};
use super::node::{Ensured, GatesView, Probe, Program, Vault};
use super::state_file::{Receive, TuiState};
use super::theme::{self, Glyphs, Motion, TermEnv, Theme};
use super::{bridge, errors, ui, workers};

/// Every tui source file, as (path under `src/tui/`, contents).
const SOURCES: &[(&str, &str)] = &[
    ("anim.rs", include_str!("anim.rs")),
    ("app.rs", include_str!("app.rs")),
    ("app/groups.rs", include_str!("app/groups.rs")),
    ("app/lock_v2.rs", include_str!("app/lock_v2.rs")),
    ("app/updates.rs", include_str!("app/updates.rs")),
    ("background.rs", include_str!("background.rs")),
    ("bridge.rs", include_str!("bridge.rs")),
    ("controller.rs", include_str!("controller.rs")),
    ("delivery.rs", include_str!("delivery.rs")),
    ("display.rs", include_str!("display.rs")),
    ("e2e_tests.rs", include_str!("e2e_tests.rs")),
    ("errors.rs", include_str!("errors.rs")),
    ("gate.rs", include_str!("gate.rs")),
    ("hidden.rs", include_str!("hidden.rs")),
    ("keys_fa.rs", include_str!("keys_fa.rs")),
    ("live.rs", include_str!("live.rs")),
    ("logo.rs", include_str!("logo.rs")),
    ("mod.rs", include_str!("mod.rs")),
    ("node.rs", include_str!("node.rs")),
    ("presence.rs", include_str!("presence.rs")),
    ("read_marks.rs", include_str!("read_marks.rs")),
    ("screens.rs", include_str!("screens.rs")),
    ("state_file.rs", include_str!("state_file.rs")),
    ("stdio.rs", include_str!("stdio.rs")),
    ("term.rs", include_str!("term.rs")),
    ("testkit.rs", include_str!("testkit.rs")),
    ("theme.rs", include_str!("theme.rs")),
    ("ui/add_friend.rs", include_str!("ui/add_friend.rs")),
    ("ui/groups.rs", include_str!("ui/groups.rs")),
    ("ui/groups/tests.rs", include_str!("ui/groups/tests.rs")),
    ("ui/home.rs", include_str!("ui/home.rs")),
    ("ui/lock.rs", include_str!("ui/lock.rs")),
    ("ui/lock/tests.rs", include_str!("ui/lock/tests.rs")),
    ("ui/meet.rs", include_str!("ui/meet.rs")),
    ("ui/network.rs", include_str!("ui/network.rs")),
    ("ui/mod.rs", include_str!("ui/mod.rs")),
    ("ui/overlays.rs", include_str!("ui/overlays.rs")),
    ("ui/security.rs", include_str!("ui/security.rs")),
    ("ui/settings.rs", include_str!("ui/settings.rs")),
    ("ui/updates.rs", include_str!("ui/updates.rs")),
    ("ui/verify.rs", include_str!("ui/verify.rs")),
    ("ui/widgets.rs", include_str!("ui/widgets.rs")),
    ("ui/wizard.rs", include_str!("ui/wizard.rs")),
    ("workers.rs", include_str!("workers.rs")),
];

/// The one file allowed to name items of cli.rs and its sibling modules.
const ADAPTER: &str = "bridge.rs";

/// Paths that reach cli.rs (and through it ext.rs, pair_init_lab.rs,
/// p2p_cli.rs and ipc_client.rs) from a tui file.
const ADAPTER_NEEDLES: &[&str] = &[
    concat!("super", "::", "super", "::"),
    concat!("crate", "::", "ash_cli"),
    concat!("ash_cli", "::"),
];

/// In tui/mod.rs `super` is cli.rs itself, so any `super` path there reaches in.
const MOD_RS_NEEDLE: &str = concat!("super", "::");

/// The files that call into the CLI, and so must stay clear of its exiting and
/// prompting helpers.
const FORBIDDEN_SCAN: &[&str] = &["bridge.rs", "controller.rs"];

/// Calls the app must never make, each with the reason a failure prints.
const FORBIDDEN_CALLS: &[(&str, &str)] = &[
    (
        concat!("ensure_identity", "("),
        "creates an identity, and exits the process on error",
    ),
    (
        concat!("require_identity", "("),
        "exits the process when the identity is missing or unreadable",
    ),
    (
        concat!("contacts_or_die", "("),
        "exits the process when contacts.json cannot be read",
    ),
    (concat!("exit_on_err", "("), "exits the process on error"),
    (
        concat!("is_own_pub_hex", "("),
        "loads the identity (a Keychain round trip) on every call; compare with MeView.pub_hex",
    ),
    (
        concat!("cmd_send_cli", "("),
        "the `send` command: reads stdin and exits the process",
    ),
    (
        concat!("run_send", "("),
        "sends a target resolve_send_target planned (RAVEN_PEER, OD-17); bridge.rs's send_routes \
         mirrors it",
    ),
    (
        concat!("resolve_send_target", "("),
        "honours RAVEN_PEER / ASH_LAN_DIAL, which the app ignores (OD-17)",
    ),
    (
        concat!("env_peer_lan_dial", "("),
        "one process-wide peer address, which the app ignores (OD-17)",
    ),
    (
        concat!("cmd_chat_session", "("),
        "the line-mode chat: reads stdin and exits the process",
    ),
    (concat!("refuse_argv_plaintext", "("), "exits the process"),
    (
        concat!("refuse_unready_contact_session", "("),
        "exits the process",
    ),
    (
        concat!("prompt_verify_choice", "("),
        "prompts on the terminal",
    ),
    (
        concat!("verify_prompt_flow", "("),
        "prompts on the terminal",
    ),
    (
        concat!("confirm_contact_removal", "("),
        "prompts on the terminal",
    ),
    (concat!("ask_petname_again", "("), "prompts on the terminal"),
    (concat!("read_tty_message", "("), "prompts on the terminal"),
    (
        concat!("read", "_line"),
        "reads stdin, which the input thread owns while the screen is up",
    ),
    (
        concat!("stdin", "()"),
        "reads stdin, which the input thread owns while the screen is up",
    ),
    (concat!("upnp_decision", "("), "prompts on the terminal"),
    (
        concat!("process", "::exit"),
        "exits without restoring the terminal",
    ),
];

/// The files allowed `unsafe`: stdio.rs for its FFI, and the test-only files
/// (`std::env::set_var` in a Once).
const UNSAFE_ALLOWED: &[&str] = &["stdio.rs", "testkit.rs", "e2e_tests.rs"];

/// Names the one test that a child copy of the test binary runs.
const CHILD_TEST_ENV: &str = "RAVEN_TUI_CHILD_TEST";

/// Texts of ext.rs the app reads, each with the place in the app that reads
/// it: when ext.rs words one differently, update that place too.
const EXT_TEXTS: &[(&str, &str)] = &[
    (
        "started raven-node (process",
        "tui/node.rs: how ensure tells a node this app started (started_by_app)",
    ),
    (
        "may have it anyway",
        "tui/delivery.rs: the write evidence of a cancelled message",
    ),
    (
        "is waiting for macOS Keychain access to {what}.",
        "tui/workers.rs: keychain_wait (KC for a raven-node that waits, SERVICE_WAIT_MARK)",
    ),
    (
        "is not waiting to be delivered",
        "tui/app.rs: the retry and cancel toasts (EXT_NOT_WAITING)",
    ),
    (
        "outbox is not running here",
        "tui/app.rs: the retry toast (EXT_NO_OUTBOX)",
    ),
    (
        "confirmed it before it could be cancelled",
        "tui/app.rs: the cancel toast (EXT_DELIVERED_FIRST)",
    ),
    (
        "--- ash: starting raven-node service ---",
        "tui/node.rs: listener_in_log (a new run's lines, RUN_MARK)",
    ),
    (
        "and a new one needs you both on the same network at the same time",
        "tui/errors.rs: needs_meeting (SESSION_ENDED_MARK)",
    ),
    (
        "first message needs you and {who} both online (RAVEN hasn't connected",
        "tui/errors.rs: first_message_away (FIRST_MESSAGE_MARK)",
    ),
];

/// Texts of raven-core's macos_keychain.rs the app reads, each with its
/// reader.
const KEYCHAIN_TEXTS: &[(&str, &str)] = &[(
    "still waiting for macOS Keychain access ({what})",
    "tui/workers.rs: keychain_wait (KC for this process's own wait, WATCHDOG_MARK)",
)];

/// What raven-node writes to its service log about its LAN listener, which
/// node.rs's `listener_in_log` reads: each text with the raven-node file
/// that writes it.
const NODE_LOG_TEXTS: &[(&str, &str)] = &[
    ("raven-node lan_direct: listen {local}", "lan_direct.rs"),
    ("retry_until_ok(\"lan_direct\"", "lan_direct.rs"),
    ("lan_direct bind {lan_listen}: {e}", "lan_direct.rs"),
    ("{name} failed: {e}", "main.rs"),
];

/// raven-node's outbox codes (`pub(crate) mod code` in
/// raven-node/src/outbox.rs), which tui/errors.rs's `OUTBOX_CODES` words.
const OUTBOX_CODE_BLOCK: &str = "pub(crate) mod code";
/// [`drift_hash`] of that block as errors.rs last mirrored it.
const OUTBOX_CODE_HASH: u64 = 0x394b_6d80_b7eb_fe27;

/// cli.rs's send to a contact's routes, which bridge.rs's `send_routes`
/// mirrors.
const RUN_SEND_HEAD: &str = concat!("fn run_send", "(");
/// [`drift_hash`] of that function as `send_routes` last mirrored it.
const RUN_SEND_HASH: u64 = 0x9bef_5fb8_b75f_8ad4;

/// cli.rs's plan of a send (`--contact` and `--peer`), whose `--contact`
/// part bridge.rs's `plan_friend_send` mirrors.
const RESOLVE_SEND_HEAD: &str = concat!("fn resolve_send_target", "(");
/// [`drift_hash`] of that function as `plan_friend_send` last mirrored it.
const RESOLVE_SEND_HASH: u64 = 0xf009_6a66_26d5_48f9;

/// cli.rs's one comparator of security words and the old code, which
/// bridge.rs's `security_check` wraps.
const SECURITY_CHECK_HEAD: &str = concat!("fn security_check", "(");
/// [`drift_hash`] of that function as `security_check` last wrapped it.
const SECURITY_CHECK_HASH: u64 = 0xea04_1df3_d324_4081;

/// The lab file-backed stores, for every test that makes an identity: set
/// once for the whole test binary and left set (a restore would race with the
/// tests beside it). Without them the identity and keys would go into the
/// login Keychain on macOS.
pub(super) fn lab_backends() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        for key in [
            "RAVEN_IDENTITY_BACKEND",
            "RAVEN_SESSION_BACKEND",
            "RAVEN_PREKEY_BACKEND",
            "RAVEN_CHAT_HISTORY_BACKEND",
        ] {
            unsafe { std::env::set_var(key, "locked-file") };
        }
    });
}

/// A new empty profile directory. On Unix its path is at most 60 bytes, so
/// its IPC socket path fits `sun_path` (as tests/ux_send_chat.rs's
/// `short_dir`); Windows uses a named pipe.
pub(super) fn short_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a temporary profile");
    if cfg!(not(unix)) || dir.path().as_os_str().len() <= 60 {
        return dir;
    }
    tempfile::Builder::new()
        .prefix("tui")
        .tempdir_in("/tmp")
        .expect("a temporary profile in /tmp")
}

/// A drift hash: 64-bit FNV-1a over `text` with each run of whitespace made
/// one space, so reformatting leaves it as it was and any other edit does
/// not. A test pins the hash of CLI code the app mirrors.
pub(super) fn drift_hash(text: &str) -> u64 {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// The item of `source` that starts at the first `head` (say `mod code`):
/// from there to the brace that closes its first `{`. Braces in string and
/// character literals don't count.
pub(super) fn item_text<'a>(source: &'a str, head: &str) -> &'a str {
    let start = source
        .find(head)
        .unwrap_or_else(|| panic!("`{head}` is no longer in the source"));
    let bytes = source.as_bytes();
    let (mut at, mut depth) = (start, 0usize);
    while at < bytes.len() {
        match bytes[at] {
            b'"' => {
                at += 1;
                while at < bytes.len() && bytes[at] != b'"' {
                    at += if bytes[at] == b'\\' { 2 } else { 1 };
                }
            }
            b'\'' if bytes.get(at + 1) == Some(&b'\\') && bytes.get(at + 3) == Some(&b'\'') => {
                at += 3;
            }
            b'\'' if bytes.get(at + 2) == Some(&b'\'') => at += 2,
            b'{' => depth += 1,
            b'}' if depth == 1 => return &source[start..=at],
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        at += 1;
    }
    panic!("`{head}` has no closing brace")
}

/// Runs one test alone in a fresh copy of this test binary, so the
/// process-wide state it changes (fd 2, SCREEN_ACTIVE) never reaches the
/// tests running beside it.
///
/// `test_name` is `module_path!()`, `::` and the test function's name. In the
/// parent this runs the child, asserts that exactly that test ran and passed,
/// and returns the child's stdout and stderr. In the child it returns None,
/// and the caller goes on with the test's body:
///
/// ```ignore
/// if testkit::run_in_child(&format!("{}::my_test", module_path!())).is_some() {
///     return;
/// }
/// ```
pub(super) fn run_in_child(test_name: &str) -> Option<String> {
    let (name, out, text) = run_child(test_name)?;
    assert!(
        out.status.success(),
        "{name} failed in its child process ({}):\n{text}",
        out.status
    );
    assert!(
        text.contains("test result: ok. 1 passed;"),
        "the child process ran no test named {name}:\n{text}"
    );
    Some(text)
}

/// [`run_in_child`] for a test whose child ends the process itself, with
/// exit code `code`, before the test can finish: the parent asserts that
/// code. A child that runs to the end of its body has failed, so it should
/// panic there. (Only the Unix signal tests need it.)
#[cfg(unix)]
pub(super) fn run_in_child_exiting(test_name: &str, code: i32) -> Option<String> {
    let (name, out, text) = run_child(test_name)?;
    assert_eq!(
        out.status.code(),
        Some(code),
        "{name} should have exited with {code} in its child process ({}):\n{text}",
        out.status
    );
    assert!(
        text.contains(&format!("test {name} ...")),
        "the child process ran no test named {name}:\n{text}"
    );
    Some(text)
}

/// Runs `test_name` in a child copy of this test binary: (its libtest name,
/// how the child ended, its stdout and stderr). None in the child itself.
fn run_child(test_name: &str) -> Option<(String, Output, String)> {
    // libtest names a test by its path inside the crate; module_path!() also
    // starts with the crate's own name (`raven` or `ash`).
    let name = test_name
        .split_once("::")
        .map_or(test_name, |(_, path)| path);
    if std::env::var(CHILD_TEST_ENV).is_ok_and(|running| running == name) {
        return None;
    }
    let exe = std::env::current_exe().expect("path of the running test binary");
    let out = Command::new(exe)
        .args([name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_TEST_ENV, name)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("cannot run {name} in a child process: {e}"));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Some((name.to_owned(), out, text))
}

/// The text of each row of `buf`: every cell's symbol, left to right. Styles
/// are not compared (`assert_buffer_lines` would compare them too).
pub(super) fn buffer_lines(buf: &Buffer) -> Vec<String> {
    let area = buf.area;
    (area.top()..area.bottom())
        .map(|y| {
            (area.left()..area.right())
                .map(|x| buf[(x, y)].symbol())
                .collect()
        })
        .collect()
}

/// Set to print the rows a render test got, as source to paste over its
/// expected rows. Nothing is written to any file.
const BLESS_ENV: &str = "RAVEN_TUI_BLESS";

/// The wall clock a test app starts at (milliseconds since the Unix epoch).
const TEST_WALL_MS: u64 = 1_760_000_000_000;

/// The look of the render tests: Simple glyphs, no colours, full motion, the
/// spinner's rate away from SSH.
pub(super) fn simple_mono() -> Look {
    Look {
        glyphs: Glyphs::simple(),
        theme: Theme::mono(),
        motion: Motion::Full,
        spinner_interval: theme::spinner_interval(&TermEnv::default()),
    }
}

/// A new app in a terminal of `size`, in the render tests' look. Its clock
/// starts now and moves only with [`tick`] (or an explicit `update`).
pub(super) fn app(size: (u16, u16)) -> App {
    app_in(simple_mono(), size)
}

/// [`app`] in `look`.
pub(super) fn app_in(look: Look, size: (u16, u16)) -> App {
    // Groups are on in release builds since 2026-10; their screens have
    // tests of their own (ui/groups, screens) that switch them on for their
    // thread. Every other screen's test sees them off on its thread (a debug
    // build's `RAVEN_LAB_GROUPS=0`), so its rows stay those of the screen it
    // is about.
    if raven_core::group::lab_groups_for_this_thread().is_none() {
        raven_core::group::set_lab_groups_for_this_thread(Some(false));
    }
    let mut app = App::new(look, size, Instant::now(), TEST_WALL_MS);
    // The same rows on every system; a test asks for the macOS or Windows
    // copy itself.
    app.set_mac_for_tests(false);
    app.set_windows_for_tests(false);
    app
}

/// What a release build lets on (2026-10): the local network, Internet
/// direct, peer-to-peer and friends who carry messages; Bluetooth nearby on
/// macOS only.
pub(super) fn release_gates() -> GatesView {
    let on = bridge::Gate {
        production: true,
        live: true,
    };
    let nearby = cfg!(target_os = "macos");
    GatesView::of(
        bridge::Gates {
            lan: on,
            internet: on,
            p2p: on,
            custody: on,
            nearby: bridge::Gate {
                production: nearby,
                live: nearby,
            },
        },
        false,
    )
}

/// What a build held everything but the local network on (a release build
/// before 2026-10, or a debug build with `RAVEN_LAB_TEST_A=0`).
pub(super) fn lan_only_gates() -> GatesView {
    let closed = bridge::Gate {
        production: false,
        live: false,
    };
    GatesView::of(
        bridge::Gates {
            lan: bridge::Gate {
                production: true,
                live: true,
            },
            internet: closed,
            p2p: closed,
            custody: closed,
            nearby: closed,
        },
        false,
    )
}

/// The profile folder a test session names.
pub(super) const FOLDER: &str = "/home/sam/.raven";

/// A new app whose session started with an identity (a fixed one), receiving
/// `receive`, and every other setting as default: its first jobs are out.
pub(super) fn ready_app(size: (u16, u16), receive: Receive) -> App {
    let mut app = app(size);
    app.start(session(receive));
    app
}

/// A new app whose profile has no identity yet: on WZ-1.
pub(super) fn wizard_app(size: (u16, u16)) -> App {
    let mut app = app(size);
    let cmds = app.start(Session {
        identity: IdentityStart::Missing,
        settings: TuiState::default(),
        ..session(Receive::Unset)
    });
    assert!(cmds.is_empty(), "the wizard asks for nothing: {cmds:?}");
    app
}

/// The public half of the identity with seed `seed` (7 is [`session`]'s).
pub(super) fn me(seed: u8) -> bridge::MeView {
    bridge::me_view(&Identity::from_seed(&[seed; 32]))
}

/// The session [`ready_app`] starts: a profile that has seen every note
/// shown once ([`notes_seen`]).
pub(super) fn session(receive: Receive) -> Session {
    Session {
        identity: IdentityStart::Ready(me(7)),
        data_dir: FOLDER.into(),
        settings: notes_seen(TuiState {
            receive,
            ..TuiState::default()
        }),
        program: Program {
            binary: "/opt/raven/raven-node".into(),
            exe_known: true,
        },
        listen: ListenOverride::None,
        over_ssh: false,
        // The local network alone: the screens' rows these tests pin do not
        // depend on the other ways; NET's release rows have their own test
        // (`net_in_a_release_build`, [`release_gates`]).
        gates: lan_only_gates(),
        look_env: LookEnv::default(),
        locked: false,
    }
}

/// [`session`] for a profile that has seen none of the notes shown once
/// (UXF.9): every one of them is still to show.
pub(super) fn unseen_session(receive: Receive) -> Session {
    Session {
        settings: TuiState {
            receive,
            ..TuiState::default()
        },
        ..session(receive)
    }
}

/// `state` once every note shown once (UXF.9) has been seen: none of them
/// shows any more. A test of a note starts from settings without it.
pub(super) fn notes_seen(state: TuiState) -> TuiState {
    TuiState {
        network_note_shown: true,
        hotspot_note_shown: true,
        names_note_shown: true,
        exit_note_shown: true,
        copy_note_shown: true,
        ..state
    }
}

/// A saved friend, not verified, with no address; `n` makes the key.
pub(super) fn friend(n: u8) -> bridge::ContactView {
    bridge::ContactView {
        pub_hex: format!("{n:02x}").repeat(32),
        address: format!("rvn1friend{n}"),
        label: format!("Friend {n}"),
        tag: String::new(),
        fingerprint: String::new(),
        pinned: false,
        blocked: false,
        lan_dial: String::new(),
        internet_dial: String::new(),
        p2p: String::new(),
    }
}

/// The card of the identity with seed `seed` (as [`me`]), with `lan` or no
/// address: what a friend pastes.
pub(super) fn card(seed: u8, lan: &str) -> String {
    bridge::format_card_with(&Identity::from_seed(&[seed; 32]), "", lan, None).expect("a card")
}

/// Zero on a Persian keyboard's number row (U+06F0).
pub(super) const PERSIAN_ZERO: u32 = 0x06F0;
/// The Arabic-Indic zero (U+0660).
pub(super) const ARABIC_INDIC_ZERO: u32 = 0x0660;

/// `text` with its digits written from `zero` on ([`PERSIAN_ZERO`] or
/// [`ARABIC_INDIC_ZERO`]).
pub(super) fn digits_from(text: &str, zero: u32) -> String {
    text.chars()
        .map(|c| {
            c.to_digit(10)
                .and_then(|d| char::from_u32(zero + d))
                .unwrap_or(c)
        })
        .collect()
}

/// `text` typed with a Persian keyboard layout on: an Arabic-script letter
/// for each letter key (either case; which letter does not matter here),
/// Persian digits on the number row, other keys as they are.
pub(super) fn on_persian_keyboard(text: &str) -> String {
    const LETTERS: [char; 26] = [
        '\u{0634}', '\u{0630}', '\u{0632}', '\u{06CC}', '\u{062B}', '\u{0628}', '\u{0644}',
        '\u{0627}', '\u{0647}', '\u{062A}', '\u{0646}', '\u{0645}', '\u{067E}', '\u{062F}',
        '\u{062E}', '\u{062D}', '\u{0636}', '\u{0642}', '\u{0633}', '\u{0641}', '\u{0639}',
        '\u{0631}', '\u{0635}', '\u{0637}', '\u{063A}', '\u{0638}',
    ];
    digits_from(text, PERSIAN_ZERO)
        .chars()
        .map(|c| {
            "abcdefghijklmnopqrstuvwxyz"
                .find(c.to_ascii_lowercase())
                .map_or(c, |at| LETTERS[at])
        })
        .collect()
}

/// The identity with seed `seed` saved as `name`, verified or not, with
/// `lan` as its address.
pub(super) fn saved_as(seed: u8, name: &str, pinned: bool, lan: &str) -> bridge::ContactView {
    let them = me(seed);
    bridge::ContactView {
        pub_hex: them.pub_hex,
        address: them.address,
        label: name.into(),
        fingerprint: them.fingerprint,
        pinned,
        lan_dial: lan.into(),
        ..friend(seed)
    }
}

/// [`friend`] with a LAN address: Raven knows where to reach them.
pub(super) fn reachable(n: u8) -> bridge::ContactView {
    bridge::ContactView {
        lan_dial: format!("192.168.1.{}:7420", 10 + u16::from(n)),
        ..friend(n)
    }
}

/// [`ready_app`] with its first jobs answered: no vault problem, no node
/// running, not a login service, and `friends` friends saved.
pub(super) fn settled_app(size: (u16, u16), receive: Receive, friends: u8) -> App {
    home_app(
        size,
        receive,
        (1..=friends).map(friend).collect(),
        Conversations::new(),
    )
}

/// [`ready_app`] with its first jobs answered: no vault problem, no node
/// running, not a login service, `friends` saved and `history` loaded. The
/// privacy read says not available: the privacy pack's rows, actions and
/// notices stay hidden ([`privacy_on`] answers it again).
pub(super) fn home_app(
    size: (u16, u16),
    receive: Receive,
    friends: Vec<bridge::ContactView>,
    history: Conversations,
) -> App {
    home_app_in(simple_mono(), size, receive, friends, history)
}

/// [`home_app`] in `look`.
pub(super) fn home_app_in(
    look: Look,
    size: (u16, u16),
    receive: Receive,
    friends: Vec<bridge::ContactView>,
    history: Conversations,
) -> App {
    home_app_from(look, size, session(receive), friends, history)
}

/// [`home_app_in`] for `session`.
pub(super) fn home_app_from(
    look: Look,
    size: (u16, u16),
    session: Session,
    friends: Vec<bridge::ContactView>,
    history: Conversations,
) -> App {
    let mut app = app_in(look, size);
    app.start(session);
    let not_running = Probe::of(&Err("raven-node is not running; start it".into()));
    for result in [
        JobResult::Vault(Vault::default()),
        JobResult::Probed(not_running),
        JobResult::Managed(None),
        JobResult::Contacts {
            contacts: Ok(friends),
            stamp: workers::FileStamp::default(),
        },
        JobResult::History {
            history: Ok(history),
            stamp: workers::FileStamp::default(),
        },
        JobResult::Privacy(Err(bridge::NotAvailable)),
    ] {
        send(&mut app, Msg::Job(result));
    }
    app
}

/// The privacy read answered for `app` (PP.21): chats kept for `keep`,
/// `notices` due, no free disk space waited for. What `update` asked for.
pub(super) fn privacy_on(
    app: &mut App,
    keep: bridge::ChatKeepView,
    notices: bridge::PrivacyNotices,
) -> Vec<Cmd> {
    send(
        app,
        Msg::Job(JobResult::Privacy(Ok(PrivacyRead {
            keep,
            notices,
            disk_needed: None,
            login_item_stays_off: false,
        }))),
    )
}

/// A history row: message `id`, written `minutes_ago` before the test
/// clock (on the sender's clock), `delivery` as the history says it.
pub(super) fn row(
    id: u32,
    outgoing: bool,
    delivery: &str,
    minutes_ago: u64,
    body: &str,
) -> RowView {
    RowView {
        id: format!("{id:032x}"),
        outgoing,
        created_at_ms: TEST_WALL_MS - minutes_ago * 60_000,
        delivery: delivery.into(),
        body: body.into(),
        id_conflict: false,
    }
}

/// Conversations by friend: each row with the [`friend`] number it is with,
/// in history order.
pub(super) fn conversations(rows: &[(u8, RowView)]) -> Conversations {
    let mut conversations = Conversations::new();
    for (n, row) in rows {
        conversations
            .entry(friend(*n).pub_hex)
            .or_default()
            .push(row.clone());
    }
    conversations
}

/// The history loaded again with `rows`, seen at `stamp`.
pub(super) fn reload(app: &mut App, rows: &[(u8, RowView)], stamp: workers::FileStamp) -> Vec<Cmd> {
    send(
        app,
        Msg::Job(JobResult::History {
            history: Ok(conversations(rows)),
            stamp,
        }),
    )
}

// ── Sends ───────────────────────────────────────────────────────────────────

/// What raven-node says when nothing listens at a friend's address.
pub(super) const REFUSED: &str =
    "lan connect: cannot connect to 127.0.0.1:9 (127.0.0.1:9: Connection refused (os error 61))";

/// The CLI's context for a send to friend `n` (named as [`friend`] names
/// them; no file is read).
fn send_ctx(n: u8) -> bridge::SendCtx {
    bridge::send_ctx(Path::new(FOLDER), &friend(n).label, "", &friend(n).pub_hex)
}

/// When a test message's sealed envelope expires.
const TEST_EXPIRY_MS: u64 = TEST_WALL_MS + 24 * 3_600_000;

/// The CLI's outcome for "hi" to friend `n`, queued after a dial nobody
/// answered: retried by raven-node in the background, or only by the next
/// send.
pub(super) fn queued_outcome(n: u8, background: bool) -> String {
    let note = bridge::RetryNote {
        expires_at_ms: TEST_EXPIRY_MS,
        copy_expires_at_ms: 0,
        background,
        custodians: Vec::new(),
        carry_first: None,
    };
    bridge::queued_text(&send_ctx(n), REFUSED, "hi", &note)
}

/// The CLI's outcome for "hi" to friend `n`, written but not confirmed.
pub(super) fn unconfirmed_outcome(n: u8) -> String {
    let note = bridge::RetryNote {
        expires_at_ms: TEST_EXPIRY_MS,
        copy_expires_at_ms: 0,
        background: true,
        custodians: Vec::new(),
        carry_first: None,
    };
    bridge::unconfirmed_text(&send_ctx(n), "LAN_DIAL_PEER_CLOSED: no ACK", "hi", &note)
}

/// The CLI's outcome for a first message to friend `n` whose computer runs
/// no Raven.
pub(super) fn not_sent_outcome(n: u8) -> String {
    bridge::not_sent_text(&send_ctx(n), REFUSED, true)
}

/// A dial that found nobody at friend `n`'s address.
const UNREACHABLE: &str = "lan connect: cannot connect to 127.0.0.1:9 (timed out)";

/// The CLI's outcome for a first message to friend `n` whose computer
/// couldn't be reached: Raven hasn't connected with them yet, so it goes
/// only while you are both online.
pub(super) fn first_message_outcome(n: u8) -> String {
    bridge::not_sent_text(&send_ctx(n), UNREACHABLE, true)
}

/// The CLI's outcome for a message to friend `n` whose computer couldn't be
/// reached once the last secure connection with them ended (ext.rs's
/// `session_ended_sentence`): meet first.
pub(super) fn meet_first_outcome(n: u8) -> String {
    let who = &friend(n).label;
    format!(
        "NOT SENT: {who} did not answer: their computer may be off or asleep, on another \
         network, or have a new IP address. Nothing was queued: RAVEN's secure connection with \
         {who} ended yesterday at 14:05 (each one lasts a day from when it is set up), and {} at \
         the same time. Send it when you meet. (technical: {UNREACHABLE})",
        super::errors::SESSION_ENDED_MARK
    )
}

/// The answer to send job `local_id`.
pub(super) fn sent(local_id: u64, result: SendResult) -> Msg {
    Msg::Job(JobResult::Sent {
        local_id,
        outcome: SendOutcome {
            result,
            learned_dial_used: None,
            captured: String::new(),
        },
    })
}

/// A send's answer: their Raven confirmed it, sent over the local network
/// to `dial`.
pub(super) fn delivered_to(dial: &str) -> SendResult {
    SendResult::Delivered(Route {
        carrier: Carrier::Lan,
        dial: Some(dial.to_owned()),
        path: String::new(),
    })
}

/// The send job among `cmds`: its number and text.
pub(super) fn send_job(cmds: &[Cmd]) -> Option<(u64, String)> {
    cmds.iter().find_map(|cmd| match cmd {
        Cmd::Send(SendJob::Send { local_id, text, .. }) => Some((*local_id, text.clone())),
        _ => None,
    })
}

/// `text` typed into the composer, then Enter: the send job it asks for.
pub(super) fn type_and_send(app: &mut App, text: &str) -> Option<(u64, String)> {
    for c in text.chars() {
        press(app, KeyCode::Char(c));
    }
    send_job(&press(app, KeyCode::Enter))
}

/// raven-node's outbox item for message `id` ([`row`]'s numbering) to friend
/// `n`, in `state`.
pub(super) fn outbox_item(n: u8, id: u32, state: &str) -> OutboxItem {
    OutboxItem {
        message_id_hex: format!("{id:032x}"),
        peer_pub_hex: friend(n).pub_hex,
        kind: "message".into(),
        state: state.into(),
        expires_at_ms: TEST_EXPIRY_MS,
        ..OutboxItem::default()
    }
}

/// The outbox as the poller lists it for every friend.
pub(super) fn outbox(items: Vec<OutboxItem>) -> Msg {
    Msg::Poll(workers::PollUpdate::Outbox { peer: None, items })
}

/// A background program answers Status for the profile, listening.
pub(super) fn node_up() -> Msg {
    Msg::Poll(workers::PollUpdate::Status(status(4242, "0.0.0.0:7420")))
}

/// raven-node `pid` answering Status, its listener at `listen`.
pub(super) fn status(pid: u32, listen: &str) -> Probe {
    Probe::of(&Ok(IpcResponse::Status {
        v: raven_core::ipc::IPC_VERSION,
        bridge: false,
        store: false,
        relay: false,
        forward_pending: 0,
        capabilities: vec!["ipc".into(), "lan_direct".into()],
        p2p: None,
        pid: Some(pid),
        lan_listen: Some(listen.into()),
        last_paths: Vec::new(),
        route_hints: None,
        unreachable: Vec::new(),
        egress: None,
        lan_listen_wanted: None,
        lan_bind_error: None,
        clock_skew: Vec::new(),
        unanswered: Vec::new(),
        at_rest: None,
        lan: None,
        security: None,
        nearby: None,
        tor: None,
        learning: None,
        locked: None,
        updates: None,
    }))
}

/// The start this app asked for answered: it started raven-node `pid`,
/// listening on the network.
pub(super) fn started_here(app: &mut App, pid: u32) -> Vec<Cmd> {
    send(
        app,
        Msg::Job(JobResult::Ensured(Ensured {
            result: Ok(()),
            after: status(pid, "0.0.0.0:7420"),
            started_by_app: Some(pid),
            captured: String::new(),
            ring: 0..0,
        })),
    )
}

/// [`reload`] with a stamp no poll reports.
pub(super) fn reload_rows(app: &mut App, rows: &[(u8, RowView)]) -> Vec<Cmd> {
    reload(app, rows, workers::FileStamp::default())
}

/// The security read answered for `app` (P6.31). What `update` asked for.
pub(super) fn answer_security(app: &mut App, read: bridge::SecurityView) -> Vec<Cmd> {
    send(app, Msg::Job(JobResult::Security(Ok(read))))
}

/// The words `app` draws in its own window ([`screen_text`] of [`render`]).
pub(super) fn render_text(app: &App) -> String {
    let (cols, rows) = app.size();
    screen_text(&render(app, cols, rows))
}

/// The store jobs among `cmds`.
pub(super) fn store_jobs(cmds: &[Cmd]) -> Vec<&StoreJob> {
    cmds.iter()
        .filter_map(|cmd| match cmd {
            Cmd::Store(job) => Some(job),
            _ => None,
        })
        .collect()
}

/// The window sizes the render tests of P6.31 draw in: two panes, the
/// smallest window, and one pane with the status row (narrow).
pub(super) const SIZES: [(u16, u16); 3] = [(80, 24), (60, 16), (70, 20)];

/// Every glyph set, each in colour and in mono.
pub(super) fn every_look() -> Vec<Look> {
    let mut looks = Vec::new();
    for glyphs in [Glyphs::fancy(), Glyphs::simple(), Glyphs::ascii()] {
        for theme in [Theme::color(), Theme::mono()] {
            looks.push(Look {
                glyphs,
                theme,
                ..simple_mono()
            });
        }
    }
    looks
}

/// The rows `app` draws in a terminal of `width` by `height` cells, at the
/// time of its last update.
pub(super) fn render(app: &App, width: u16, height: u16) -> Vec<String> {
    render_at(app, width, height, app.now())
}

/// The rows `app` draws at `now`: for frames of an animation.
pub(super) fn render_at(app: &App, width: u16, height: u16, now: Instant) -> Vec<String> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("a test terminal");
    terminal
        .draw(|f| ui::render(f, app, now))
        .expect("draw on a test terminal");
    buffer_lines(terminal.backend().buffer())
}

/// Asserts the rendered rows, each a full padded row. With RAVEN_TUI_BLESS
/// set it prints them as source instead, after the caller's place (run with
/// --nocapture --test-threads=1 to see them), and asserts nothing.
#[track_caller]
pub(super) fn assert_rows(got: &[String], expected: &[&str]) {
    if std::env::var_os(BLESS_ENV).is_some() {
        let at = std::panic::Location::caller();
        println!("BLESS {}:{}", at.file(), at.line());
        for row in got {
            println!("    {row:?},");
        }
        println!("BLESS END");
        return;
    }
    let differ: Vec<String> = got
        .iter()
        .zip(expected)
        .enumerate()
        .filter(|(_, (got, expected))| got != expected)
        .map(|(y, (got, expected))| {
            format!("row {y}:\n  got      {got:?}\n  expected {expected:?}")
        })
        .collect();
    assert!(
        differ.is_empty() && got.len() == expected.len(),
        "{} rows rendered, {} expected (set {BLESS_ENV}=1 to print them):\n{}",
        got.len(),
        expected.len(),
        differ.join("\n")
    );
}

/// The words on `rows`, box lines taken out and every run of spaces made
/// one: a sentence wrapped over rows reads as one.
pub(super) fn screen_text(rows: &[String]) -> String {
    let words: String = rows
        .iter()
        .map(|row| {
            row.chars()
                .map(|c| {
                    if "│┌┐└┘─╭╮╰╯".contains(c) {
                        ' '
                    } else {
                        c
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ");
    words.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `msg` arriving at the time of the app's last update.
pub(super) fn send(app: &mut App, msg: Msg) -> Vec<Cmd> {
    app.update(msg, app.now(), app.now_ms())
}

/// `code` pressed with no modifier.
pub(super) fn press(app: &mut App, code: KeyCode) -> Vec<Cmd> {
    send(
        app,
        Msg::Key(Key::Event(KeyEvent::new(code, KeyModifiers::NONE))),
    )
}

/// Ctrl+`c`.
pub(super) fn ctrl(app: &mut App, c: char) -> Vec<Cmd> {
    send(
        app,
        Msg::Key(Key::Event(KeyEvent::new(
            KeyCode::Char(c),
            KeyModifiers::CONTROL,
        ))),
    )
}

/// `text` pasted, as the input thread reports it.
pub(super) fn paste(app: &mut App, text: &str, via: PasteVia) -> Vec<Cmd> {
    send(
        app,
        Msg::Paste {
            text: text.to_owned(),
            via,
        },
    )
}

/// The terminal resized to `cols` by `rows`.
pub(super) fn resize(app: &mut App, cols: u16, rows: u16) -> Vec<Cmd> {
    send(app, Msg::Resize { cols, rows })
}

/// The clock moved on by `by` with no message: the UI thread's tick.
pub(super) fn tick(app: &mut App, by: Duration) -> Vec<Cmd> {
    let ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
    app.update(Msg::Tick, app.now() + by, app.now_ms().saturating_add(ms))
}

#[cfg(unix)]
pub(super) use fake_node::{DialPeer, FakeNode, FakeStatus};

/// A fake raven-node for one profile (Unix: its socket in the profile).
#[cfg(unix)]
mod fake_node {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use base64::Engine;
    use raven_core::identity::Identity;
    use raven_core::ipc::{decode_request, IpcRequest, IpcResponse, OutboxItem, IPC_VERSION};
    use raven_core::lan_dispatch::{dispatch_frame, encode_local_offer, local_bundle};

    /// What raven-node's dial says when the friend's Raven closed the
    /// connection after a frame it refused (tests/ux_send_chat.rs's).
    const PEER_CLOSED: &str = "LAN_DIAL_PEER_CLOSED: the peer closed the connection without \
                               replying; the frames were sent, delivery is unconfirmed and a \
                               retry is safe";

    /// The friend a LanDial reaches (their profile and identity), and the
    /// profile that dials. Their dispatcher checks every frame against the
    /// dialler's bundle and key (what the Noise handshake binds on a real
    /// link); the bundle is made at each dial, as the dialler's own
    /// raven-node makes it for its side of a link, so nothing is created
    /// ahead of the app.
    pub(crate) struct DialPeer {
        pub(crate) dir: PathBuf,
        pub(crate) id: Arc<Identity>,
        pub(crate) from_dir: PathBuf,
        pub(crate) from_id: Arc<Identity>,
    }

    /// What the fake's Status says.
    #[derive(Debug, Clone, Default)]
    pub(crate) struct FakeStatus {
        pub(crate) pid: Option<u32>,
        pub(crate) capabilities: Vec<String>,
        pub(crate) lan_listen: Option<String>,
    }

    impl FakeStatus {
        /// A node whose listener is up on `lan_listen`.
        pub(crate) fn listening(pid: u32, lan_listen: &str) -> FakeStatus {
            FakeStatus {
                pid: Some(pid),
                capabilities: vec!["ipc".into(), "lan_direct".into()],
                lan_listen: Some(lan_listen.into()),
            }
        }
    }

    struct Shared {
        status: Mutex<FakeStatus>,
        outbox: Mutex<Vec<OutboxItem>>,
        /// What a LanDial is answered with: raven-node's error, as when
        /// nothing listens at the friend's address.
        dial_error: Mutex<Option<String>>,
        /// Who answers a LanDial while no error is set.
        peer: Mutex<Option<DialPeer>>,
        /// The address of every LanDial, in order.
        dials: Mutex<Vec<String>>,
        /// The `op` of every request, in order, decodable or not.
        ops: Mutex<Vec<String>>,
        stop: AtomicBool,
    }

    /// Answers Ping, Status and OutboxList on the profile's IPC socket; a
    /// LanDial with the error [`FakeNode::refuse_dials`] set, else through
    /// the friend's own dispatcher ([`FakeNode::answer_dials_as`]); and an
    /// error to anything else. Records every request's op and every dial's
    /// address. Stops answering (the socket goes) on [`FakeNode::stop`] or
    /// when dropped.
    pub(crate) struct FakeNode {
        shared: Arc<Shared>,
        thread: Mutex<Option<JoinHandle<()>>>,
    }

    impl FakeNode {
        pub(crate) fn start(data_dir: &Path, status: FakeStatus) -> FakeNode {
            let socket = raven_core::default_socket_path(data_dir);
            let listener = UnixListener::bind(&socket).expect("bind the fake node's socket");
            listener
                .set_nonblocking(true)
                .expect("a socket that can be stopped");
            let shared = Arc::new(Shared {
                status: Mutex::new(status),
                outbox: Mutex::new(Vec::new()),
                dial_error: Mutex::new(None),
                peer: Mutex::new(None),
                dials: Mutex::new(Vec::new()),
                ops: Mutex::new(Vec::new()),
                stop: AtomicBool::new(false),
            });
            let serving = Arc::clone(&shared);
            let thread = thread::spawn(move || serve(&listener, &socket, &serving));
            FakeNode {
                shared,
                thread: Mutex::new(Some(thread)),
            }
        }

        /// The ops received so far (`ping`, `status`, `outbox_list`, …).
        pub(crate) fn ops(&self) -> Vec<String> {
            self.shared.ops.lock().unwrap().clone()
        }

        pub(crate) fn set_outbox(&self, items: Vec<OutboxItem>) {
            *self.shared.outbox.lock().unwrap() = items;
        }

        /// Every LanDial from now on fails with `message`, as raven-node's
        /// own dial does (code `LAN_DIAL`).
        pub(crate) fn refuse_dials(&self, message: &str) {
            *self.shared.dial_error.lock().unwrap() = Some(message.to_owned());
        }

        /// Dials go through again, as when the friend's Raven is back.
        pub(crate) fn accept_dials(&self) {
            *self.shared.dial_error.lock().unwrap() = None;
        }

        /// Every LanDial from now on (while none is refused) reaches `peer`:
        /// their offer, then what their real dispatcher answers each frame,
        /// as raven-node's dial would bring back from their Raven.
        pub(crate) fn answer_dials_as(&self, peer: DialPeer) {
            *self.shared.peer.lock().unwrap() = Some(peer);
        }

        /// The addresses dialled so far.
        pub(crate) fn dials(&self) -> Vec<String> {
            self.shared.dials.lock().unwrap().clone()
        }

        /// Stops answering and removes the socket, as a node that stopped.
        pub(crate) fn stop(&self) {
            self.shared.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.lock().unwrap().take() {
                thread.join().expect("the fake node's thread");
            }
        }
    }

    impl Drop for FakeNode {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn serve(listener: &UnixListener, socket: &PathBuf, shared: &Shared) {
        while !shared.stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => answer(stream, shared),
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
        let _ = std::fs::remove_file(socket);
    }

    /// One framed request in, one framed answer out.
    fn answer(mut stream: UnixStream, shared: &Shared) {
        // macOS hands the listener's non-blocking mode on to the stream.
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut frame = len.to_vec();
        frame.resize(4 + u32::from_be_bytes(len) as usize, 0);
        if stream.read_exact(&mut frame[4..]).is_err() {
            return;
        }
        let op = serde_json::from_slice::<serde_json::Value>(&frame[4..])
            .ok()
            .and_then(|body| body.get("op").and_then(|op| op.as_str()).map(str::to_owned))
            .unwrap_or_default();
        shared.ops.lock().unwrap().push(op.clone());
        let response = match op.as_str() {
            "ping" => IpcResponse::Pong { v: IPC_VERSION },
            "status" => {
                let status = shared.status.lock().unwrap().clone();
                IpcResponse::Status {
                    v: IPC_VERSION,
                    bridge: false,
                    store: false,
                    relay: false,
                    forward_pending: 0,
                    capabilities: status.capabilities,
                    p2p: None,
                    pid: status.pid,
                    lan_listen: status.lan_listen,
                    last_paths: Vec::new(),
                    route_hints: None,
                    unreachable: Vec::new(),
                    egress: None,
                    lan_listen_wanted: None,
                    lan_bind_error: None,
                    clock_skew: Vec::new(),
                    unanswered: Vec::new(),
                    at_rest: None,
                    lan: None,
                    security: None,
                    nearby: None,
                    tor: None,
                    learning: None,
                    locked: None,
                    updates: None,
                }
            }
            "outbox_list" => IpcResponse::OutboxListResult {
                v: IPC_VERSION,
                worker_running: true,
                items: shared.outbox.lock().unwrap().clone(),
            },
            "lan_dial" => answer_dial(&frame, shared),
            other => not_answered(other),
        };
        let _ = stream.write_all(&raven_core::encode_response(&response).expect("encode"));
    }

    /// A LanDial, its address recorded: refused while an error is set, else
    /// answered by the peer, else not answered.
    fn answer_dial(frame: &[u8], shared: &Shared) -> IpcResponse {
        let request = decode_request(frame);
        if let Ok(IpcRequest::LanDial { lan_dial, .. }) = &request {
            shared.dials.lock().unwrap().push(lan_dial.clone());
        }
        if let Some(message) = shared.dial_error.lock().unwrap().clone() {
            return dial_error(&message);
        }
        match (&*shared.peer.lock().unwrap(), request) {
            (Some(peer), Ok(IpcRequest::LanDial { frames_b64, .. })) => {
                dial_peer(peer, &frames_b64)
            }
            _ => not_answered("lan_dial"),
        }
    }

    /// One dial reaching the peer: their offer, then their real
    /// dispatcher's replies to each frame (tests/ux_send_chat.rs's
    /// `dial_bob`, without its failure modes). A frame the dispatcher
    /// refuses closes the link, as their Raven would.
    fn dial_peer(peer: &DialPeer, frames_b64: &[String]) -> IpcResponse {
        let base64 = base64::engine::general_purpose::STANDARD;
        let (from_bundle, offer) = match (
            local_bundle(&peer.from_dir, &peer.from_id),
            encode_local_offer(&peer.dir, &peer.id),
        ) {
            (Ok(from_bundle), Ok(offer)) => (from_bundle, offer),
            (Err(e), _) | (_, Err(e)) => return dial_error(&e),
        };
        let from_pub = peer.from_id.public_key_bytes();
        let mut replies = vec![base64.encode(offer)];
        for frame in frames_b64 {
            let Ok(frame) = base64.decode(frame) else {
                return dial_error(PEER_CLOSED);
            };
            match dispatch_frame(&peer.dir, &peer.id, &from_bundle, &from_pub, &frame) {
                Ok(more) => replies.extend(more.iter().map(|reply| base64.encode(reply))),
                Err(_) => return dial_error(PEER_CLOSED),
            }
        }
        IpcResponse::LanDialResult {
            v: IPC_VERSION,
            frames_b64: replies,
        }
    }

    /// raven-node's answer to a dial that failed with `message`.
    fn dial_error(message: &str) -> IpcResponse {
        IpcResponse::Error {
            v: IPC_VERSION,
            code: "LAN_DIAL".into(),
            message: message.to_owned(),
        }
    }

    fn not_answered(op: &str) -> IpcResponse {
        IpcResponse::Error {
            v: IPC_VERSION,
            code: "IPC_FRAME".into(),
            message: format!("the fake node does not answer {op}"),
        }
    }
}

/// Messages that reach `rx` within `for_how_long`.
#[cfg(unix)]
pub(super) fn collect_msgs(
    rx: &std::sync::mpsc::Receiver<Msg>,
    for_how_long: Duration,
) -> Vec<Msg> {
    let until = Instant::now() + for_how_long;
    let mut msgs = Vec::new();
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(msg) => msgs.push(msg),
            Err(_) => break,
        }
    }
    msgs
}

/// The text of `tui/<file>` from [`SOURCES`].
fn source(file: &str) -> &'static str {
    SOURCES
        .iter()
        .find(|(name, _)| *name == file)
        .map(|(_, text)| *text)
        .unwrap_or_else(|| panic!("tui/{file} is missing from testkit's SOURCES"))
}

/// 1-based lines where `needle` starts a token of `text`: the character before
/// it is not part of an identifier. So a needle never matches the tail of a
/// longer name, but does match its head (see the test below).
fn token_lines(text: &str, needle: &str) -> Vec<usize> {
    text.match_indices(needle)
        .filter(|(at, _)| {
            !text[..*at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
        .map(|(at, _)| text[..at].matches('\n').count() + 1)
        .collect()
}

/// Every `.rs` file under `dir`, as a `/`-separated path relative to it.
fn rs_files_under(dir: &Path, prefix: &str, out: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            rs_files_under(&path, &format!("{prefix}{name}/"), out);
        } else if name.ends_with(".rs") {
            out.push(format!("{prefix}{name}"));
        }
    }
}

#[test]
fn scan_list_covers_every_tui_file() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("tui");
    let mut on_disk = Vec::new();
    rs_files_under(&root, "", &mut on_disk);
    on_disk.sort();
    let mut listed: Vec<&str> = SOURCES.iter().map(|(name, _)| *name).collect();
    listed.sort_unstable();
    assert_eq!(
        on_disk, listed,
        "testkit's SOURCES must list every file under src/tui/, and nothing else"
    );
}

#[test]
fn only_bridge_names_cli_items() {
    let mut found = Vec::new();
    for &(file, text) in SOURCES {
        if file == ADAPTER {
            continue;
        }
        let mut needles = ADAPTER_NEEDLES.to_vec();
        if file == "mod.rs" {
            needles.push(MOD_RS_NEEDLE);
        }
        for needle in needles {
            for line in token_lines(text, needle) {
                found.push(format!("tui/{file}:{line}: `{needle}`"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "only tui/{ADAPTER} may name items of cli.rs, ext.rs, pair_init_lab.rs, p2p_cli.rs \
         or ipc_client.rs: re-export or wrap the item there and use `bridge::…` \
         (in tui/mod.rs `super` is cli.rs itself)\n{}",
        found.join("\n")
    );
}

#[test]
fn adapter_files_make_no_exiting_or_prompting_calls() {
    let mut found = Vec::new();
    for &file in FORBIDDEN_SCAN {
        let text = source(file);
        for &(needle, why) in FORBIDDEN_CALLS {
            for line in token_lines(text, needle) {
                found.push(format!("tui/{file}:{line}: `{needle}` {why}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "the app must not exit, prompt or read stdin from inside its adapter files\n{}",
        found.join("\n")
    );
}

#[test]
fn unsafe_stays_in_stdio() {
    let needle = concat!("un", "safe");
    let mut found = Vec::new();
    for &(file, text) in SOURCES {
        if UNSAFE_ALLOWED.contains(&file) {
            continue;
        }
        for line in token_lines(text, needle) {
            found.push(format!("tui/{file}:{line}"));
        }
    }
    assert!(
        found.is_empty(),
        "only tui/stdio.rs may use `{needle}` (its FFI): give the call a safe wrapper there\n{}",
        found.join("\n")
    );
}

/// A waiting message has a deadline (at most a day after the two computers
/// were last connected): no screen may promise it goes whenever the friend
/// is back.
#[test]
fn no_screen_promises_delivery_whenever_the_friend_is_back() {
    let promise = concat!("delivers it", " when");
    let found: Vec<&str> = SOURCES
        .iter()
        .filter(|(_, text)| text.contains(promise))
        .map(|(path, _)| *path)
        .collect();
    assert!(found.is_empty(), "{found:?}");
}

/// What MEET's file never names: running a program, or Raven's background
/// program started, stopped or given the terminal. MEET explains and waits
/// (UXF.6); `no_step_runs_a_system_command` in ui/meet.rs checks what the
/// keys app.rs handles for it hand out.
const MEET_NEVER: &[&str] = &[
    concat!("Command", "::"),
    concat!("process", "::"),
    concat!("spawn", "("),
    concat!("NodeJob", "::Ensure"),
    concat!("NodeJob", "::Stop"),
    concat!("Cmd", "::Suspend"),
];

#[test]
fn meet_runs_no_command() {
    let text = source("ui/meet.rs");
    let found: Vec<String> = MEET_NEVER
        .iter()
        .filter(|needle| text.contains(**needle))
        .map(|needle| format!("tui/ui/meet.rs: `{needle}`"))
        .collect();
    assert!(
        found.is_empty(),
        "MEET explains and waits: it runs nothing\n{}",
        found.join("\n")
    );
}

/// What turns a login item on or off (node_control.rs, cli.rs's `raven
/// lock` and `raven unlock`): the app never does (OD-11; OD-PP-12 option
/// (a), PP.23). Its Lock unloads Raven's own item for this login session
/// only, and opening the app leaves an item a lock turned off as it is.
const LOGIN_ITEM_SWITCHES: &[&str] = &[
    concat!("disable", "_login_item"),
    concat!("enable", "_login_item"),
    concat!("clear_lock", "_login_item"),
];

#[test]
fn the_app_never_turns_a_login_item_on_or_off() {
    let mut found = Vec::new();
    for &(file, text) in SOURCES {
        for &needle in LOGIN_ITEM_SWITCHES {
            for line in token_lines(text, needle) {
                found.push(format!("tui/{file}:{line}: `{needle}`"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "the app doesn't change login settings itself (OD-11)\n{}",
        found.join("\n")
    );
}

/// `text` without its test module: the code that ships.
fn shipped(text: &str) -> &str {
    let tests = concat!("#[cfg(test)]\n", "mod tests");
    text.find(tests).map_or(text, |at| &text[..at])
}

/// What the files that draw or decide motion never do (UXF.10): read a
/// clock themselves, wait, or start a thread. A frame is drawn for the time
/// the UI thread passes in, and the UI thread wakes only when anim.rs says.
const DRAW_NEVER: &[&str] = &[
    concat!("Instant", "::now("),
    concat!("SystemTime", "::now("),
    concat!("bridge::", "now_ms("),
    concat!("thread", "::sleep"),
    concat!("thread", "::spawn"),
    concat!("recv", "_timeout("),
];

/// The files that draw or decide what moves, besides every file in ui/.
const MOTION_FILES: &[&str] = &[
    "anim.rs",
    "app.rs",
    "delivery.rs",
    "display.rs",
    "live.rs",
    "logo.rs",
    "presence.rs",
    "theme.rs",
];

#[test]
fn no_motion_starts_outside_the_scheduler() {
    let mut found = Vec::new();
    for &(file, text) in SOURCES {
        if !(file.starts_with("ui/") || MOTION_FILES.contains(&file)) {
            continue;
        }
        let code = shipped(text);
        for &needle in DRAW_NEVER {
            for line in token_lines(code, needle) {
                found.push(format!("tui/{file}:{line}: `{needle}`"));
            }
        }
        // Every motion is listed where anim.rs's `moving` collects it: in a
        // screen's `moving`, a part of it (`route_moving`), or WZ-1's reveal.
        if file == "anim.rs" {
            continue;
        }
        let needle = concat!("Moving", "::");
        for line in token_lines(code, needle) {
            let lines: Vec<&str> = code.lines().take(line).collect();
            let within = lines
                .iter()
                .rev()
                .find_map(|row| {
                    let at = row.find("fn ")?;
                    let name: String = row[at + 3..]
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    (!name.is_empty()).then_some(name)
                })
                .unwrap_or_default();
            if !(within.ends_with("moving") || within == "mark_reveal") {
                found.push(format!("tui/{file}:{line}: `{needle}` in fn {within}"));
            }
        }
    }
    // The UI thread waits for a message only as long as anim.rs says.
    let ui_loop = shipped(source("mod.rs"));
    let waits = token_lines(ui_loop, concat!("recv", "_timeout("));
    assert_eq!(waits.len(), 1, "one wait in the UI thread's loop");
    let before = ui_loop.lines().nth(waits[0] - 2).unwrap_or_default();
    assert!(
        before.contains(concat!("anim::", "next_wait(")),
        "the UI thread's wait comes from anim::next_wait: {before:?}"
    );
    assert!(
        found.is_empty(),
        "motion starts only from what the screens list for anim.rs, and is drawn \
         for the time it is given\n{}",
        found.join("\n")
    );
}

/// Honest motion (UXF.10): Raven says nothing about a friend it doesn't
/// know. No typing indicator, and no online state or label (HELP says what
/// the in-touch mark does not mean; advice may still say 'when they are
/// online').
const NEVER_SAID: &[&str] = &[
    concat!("is ", "typing"),
    concat!("are ", "typing"),
    concat!("typing", "…"),
    concat!("typing", "..."),
    concat!("On", "line"),
    concat!("last ", "seen"),
    concat!("Last ", "seen"),
];

#[test]
fn no_typing_or_online_state_is_shown() {
    let mut found = Vec::new();
    for &(file, text) in SOURCES {
        let code = shipped(text);
        for &needle in NEVER_SAID {
            if code.contains(needle) {
                found.push(format!("tui/{file}: `{needle}`"));
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn scans_match_tokens_not_substrings() {
    let call = concat!("run_send", "(");
    assert_eq!(
        token_lines(concat!("fn f() {\n    run_send", "(a);\n}"), call),
        vec![2]
    );
    assert_eq!(token_lines(concat!("x.run_send", "(a)"), call), vec![1]);
    assert!(token_lines(concat!("try_run_send", "(a)"), call).is_empty());
    assert!(token_lines(concat!("run_send_secure", "(a)"), call).is_empty());

    let read = concat!("read", "_line");
    assert_eq!(
        token_lines(concat!("let t = read", "_line_opt();"), read),
        vec![1]
    );

    let reach_in = ADAPTER_NEEDLES[0];
    assert_eq!(
        token_lines(
            concat!("pub(super) use super", "::", "super", "::{Contact};"),
            reach_in
        ),
        vec![1]
    );
    // `pub(super)` items are fine in tui/mod.rs; only `super` paths are not.
    assert!(token_lines("pub(super) fn run_or_classic() {}", MOD_RS_NEEDLE).is_empty());
    assert_eq!(
        token_lines(concat!("use super", "::interactive;"), MOD_RS_NEEDLE),
        vec![1]
    );
}

/// Names every item bridge.rs re-exports or wraps, with the type the app
/// relies on, so a change to one of them in cli.rs or its siblings fails
/// here, next to its name, instead of deep inside a screen.
#[test]
fn bridge_api_pins() {
    let _: usize = bridge::TTY_BODY_MAX_CHARS;
    // The classic menu, for the gate and the ways back to it.
    let _: fn(&Path) = bridge::interactive;
    // Before the screen: the identity on the plain terminal, and the listen
    // address while receiving is off.
    let _: fn(&Path) -> bridge::IdentityLoad = bridge::load_identity;
    let _: fn() -> Option<String> = bridge::service_lan_listen_env;
    let _: fn() = bridge::set_listen_loopback_env;
    // The wall clock every update carries, for the age of a message.
    let _: fn() -> u64 = bridge::now_ms;
    // Home's clock (UXF.10): this computer's time, or none.
    let clock: fn(u64) -> Option<String> = bridge::clock_text;
    assert_eq!(clock(1_760_000_000_000), None, "no offset under test");
    assert_eq!(
        bridge::with_local_offset(Some(3 * 3600 + 1800), || clock(1_760_000_000_999)),
        Some("12:23:20 UTC+3:30".to_owned())
    );
    let clip_body: fn(String, Option<usize>) -> String = bridge::clip_body;
    // display.rs and the clipped-body hint follow this marker.
    assert_eq!(
        clip_body("abcdef".into(), Some(4)),
        "abcd\u{2026} (+2 more characters)"
    );
    assert_eq!(clip_body("abcdef".into(), Some(6)), "abcdef");
    assert_eq!(clip_body("abcdef".into(), None), "abcdef");
    // Home: ages as `ash messages` words them, and the composer's checks.
    let age: fn(u64, u64) -> String = bridge::short_age;
    assert_eq!(age(120_000, 0), "", "an unknown time");
    assert_eq!(age(3_600_001, 1), "1 h ago");
    assert_eq!(age(1, 5_000), "just now", "a clock ahead of this one");
    let problem: fn(&str) -> Option<&'static str> = bridge::tty_message_problem;
    assert!(problem("a\u{1b}[A").is_some() && problem("a\u{7f}").is_some());
    assert_eq!(problem("a\tb\r\nc"), None);
    let allowed: fn(&str) -> bool = bridge::chat_text_allowed;
    assert!(!allowed("RVNAPP/1 x") && allowed(" RVNAPP/") && allowed("hi"));
    assert_eq!(bridge::MAX_LAN_ENDPOINT_TEXT, 48 * 1024);
    let _: fn(&Path) -> Result<Vec<ChatHistoryEntry>, String> = bridge::load_history;
    // Groups (lab): after a send or a change, raven-node's outbox is asked
    // to send what was parked, as `raven group` asks it.
    let _: fn(&Path) -> bool = bridge::outbox_kick;

    // The identity: created as the menu's first run does, then its first
    // prekey; the screens get its public half only.
    let _: fn(&Path) -> Result<Arc<Identity>, String> = bridge::load_or_create_identity;
    let _: fn(&Path, &Identity) -> Result<(), String> = bridge::ensure_local_prekey;
    let me: fn(&Identity) -> bridge::MeView = bridge::me_view;
    // WZ-5 shows my security words, numbered, and my old-style code.
    let _: Box<[String; raven_core::security_words::WORDS]> =
        me(&Identity::from_seed(&[7; 32])).words;
    // Contacts, with the block list (which fails closed when unreadable).
    let _: fn(&Path) -> Result<Vec<bridge::Contact>, String> = bridge::load_contacts;
    let _: fn(&Path) -> PathBuf = bridge::contacts_path;
    let _: fn(&Path) -> Result<Vec<bridge::ContactView>, String> = bridge::contact_views;
    let _: fn(&Path) -> Result<BlockList, String> = BlockList::load_checked;
    let _: fn(&BlockList, &str) -> bool = BlockList::is_blocked;
    let _: fn(&str) -> Option<String> = bridge::fingerprint_of;
    // Cards and invites, mine and pasted.
    let _: fn(&str) -> Result<bridge::FriendPreview, String> = bridge::parse_card_or_invite;
    let _: fn(&str) -> Option<Result<bridge::FriendPreview, String>> = bridge::parse_raven_invite;
    let _: fn(&Identity, &str, &str, Option<&bridge::P2pView>) -> Result<String, String> =
        bridge::format_card_with;
    #[allow(clippy::type_complexity)]
    let _: fn(&Identity, &NodePolicy, Option<u64>) -> Result<Option<bridge::P2pView>, String> =
        bridge::own_card_p2p;
    let _: fn(&Path) -> Option<u64> = bridge::own_rotation_epoch;
    let _: fn(&Path) -> Result<NodePolicy, String> = bridge::try_load_policy;
    let _: fn(&Result<IpcResponse, String>) -> Option<&P2pStatusInfo> = bridge::service_p2p;
    let _: fn() -> Option<Ipv4Addr> = bridge::egress_v4;
    // Whether this computer is on any network, read by the poller, and every
    // address of it a friend could dial, read by the node worker for MEET.
    let _: fn(Option<u32>) -> Option<bool> = bridge::on_any_network;
    let _: fn(&Result<IpcResponse, String>) -> Option<u32> = bridge::friends_here_10m;
    let _: fn() -> Option<Vec<std::net::IpAddr>> = bridge::lan_addresses_for_friends;
    let _: fn(std::net::IpAddr, std::net::IpAddr) -> bool = bridge::listener_takes;
    let _: usize = bridge::CARD_MAX_LEN;
    // Addresses.
    let _: fn(&str) -> Result<String, String> = bridge::parse_lan_dial;
    let _: fn(&Path, &str, &str) -> Result<(), String> = bridge::update_contact_lan_dial;
    // Adding, pinning, removing (always confirmed) and unblocking.
    #[allow(clippy::type_complexity)]
    let _: fn(
        &Path,
        &str,
        &str,
        &str,
        &str,
        Option<&str>,
        &str,
        &str,
        Option<&bridge::P2pView>,
    ) -> Result<(), String> = bridge::add_contact_with_routes;
    let _: fn(&Path, &str) -> Result<(), String> = bridge::cmd_contact_remove;
    let _: fn(&Path, &str) -> Result<(), String> = bridge::cmd_contact_unblock;
    // NAME-CLASH notes the key change attempt as the CLI's refusal does.
    let _: fn(&str) = bridge::note_key_change_attempt;
    // Security codes and confirmation codes, checked in the App before any
    // save: separators ignored, case not; the confirmation code ignores case.
    // Persian and Arabic-Indic digits are read as 0-9 in both, and a code
    // with Arabic-script letters gets the keyboard hint.
    let fingerprint_matches: fn(&str, &str) -> bool = bridge::fingerprint_matches;
    let case_only: fn(&str, &str) -> bool = bridge::fingerprint_case_only_mismatch;
    let new_code: fn(&mut rand::rngs::ThreadRng) -> String = bridge::new_confirm_code;
    let code_matches: fn(&str, &str) -> bool = bridge::confirm_code_matches;
    let fold: fn(&str) -> String = bridge::fold_code_digits;
    let other_letters: fn(&str) -> bool = bridge::code_has_non_latin_letters;
    assert!(fingerprint_matches("If4x 36FU omFi", "If4x-36FU-omFi"));
    assert!(!fingerprint_matches("if4x-36fu-omfi", "If4x-36FU-omFi"));
    assert!(fingerprint_matches(
        "If\u{06F4}x-\u{0663}\u{0666}FU-omFi",
        "If4x-36FU-omFi"
    ));
    assert!(case_only("if4x-36fu-omfi", "If4x-36FU-omFi"));
    assert!(!case_only("If4x-36FU-omFj", "If4x-36FU-omFi"));
    assert!(bridge::FINGERPRINT_CASE_HINT.contains("case"));
    // Security words or the old code, against a friend's key: cli.rs's one
    // comparator. VF's words entry turns each outcome into its text.
    let security_check: fn(&str, &str) -> bridge::SecurityCheck = bridge::security_check;
    let bob = me(&Identity::from_seed(&[0xB0; 32]));
    let other_case: String = bob
        .fingerprint
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect();
    for (typed, outcome) in [
        (bob.words.join(" "), bridge::SecurityCheck::Match),
        (bob.fingerprint.clone(), bridge::SecurityCheck::Match),
        (other_case, bridge::SecurityCheck::CodeCaseOnly),
        ("If4x-36FU-omFi".into(), bridge::SecurityCheck::Mismatch),
        (
            bob.words[..9].join(" "),
            bridge::SecurityCheck::Invalid(raven_core::security_words::ParseError::WrongCount {
                count: 9,
            }),
        ),
    ] {
        assert_eq!(security_check(&typed, &bob.pub_hex), outcome, "{typed}");
    }
    // VF's words field: what is typed is words whatever its length, so 3
    // words get the count, never the old code's mismatch.
    let words_check: fn(&str, &str) -> bridge::SecurityCheck = bridge::words_check;
    assert_eq!(
        words_check(&bob.words.join(" "), &bob.pub_hex),
        bridge::SecurityCheck::Match
    );
    assert_eq!(
        words_check(&bob.words[..3].join(" "), &bob.pub_hex),
        bridge::SecurityCheck::Invalid(bridge::ParseError::WrongCount { count: 3 })
    );
    // Its chips, suggestions and statuses: raven-core's list, from the typed
    // text alone; a saved friend's words from their key.
    let list_word: fn(u8) -> &'static str = bridge::list_word;
    let suggest: fn(&str) -> Vec<u8> = bridge::word_suggestions;
    let resolve: fn(&str) -> Result<u8, bridge::TokenError> = bridge::resolve_word;
    let tokens: fn(&str) -> Vec<String> = bridge::word_tokens;
    let words_of: fn(&str) -> Option<Box<[String; bridge::WORDS]>> = bridge::words_of;
    let first = bob.words[0].as_str();
    let index = resolve(first).expect("a Raven word");
    assert_eq!(list_word(index), first);
    assert_eq!(suggest(&first[..3]), [index]);
    assert_eq!(resolve("zzzz"), Err(bridge::TokenError::Unknown));
    assert_eq!(tokens("1. turtle, 2. frog"), ["turtle", "frog"]);
    assert_eq!(words_of(&bob.pub_hex), Some(bob.words.clone()));
    assert_eq!(words_of("not a key"), None);
    assert_eq!(fold("\u{06F1}\u{0662}3x"), "123x");
    assert!(other_letters("\u{0645}") && !other_letters("\u{06F1}\u{0661}a1"));
    let code = new_code(&mut rand::thread_rng());
    assert_eq!(code.chars().count(), 5);
    assert!(code_matches(&code.to_lowercase(), &code));
    assert!(!code_matches("", &code));
    // What the CLI says to a pasted own invite (the app words it itself).
    assert!(!bridge::OWN_INVITE_REFUSAL.is_empty());

    // Send outcomes: errors.rs reads where each stands from how its text
    // starts, and why with ext.rs's classifier.
    let classify: fn(&str) -> bridge::Cause = bridge::classify_cause;
    assert_eq!(classify("connection refused"), bridge::Cause::NotListening);
    let _: [&str; 3] = [
        bridge::QUEUED_PREFIX,
        bridge::UNCONFIRMED_PREFIX,
        bridge::BACKGROUND_RETRY,
    ];
    // When a waiting message runs out of time, in words (no "UTC").
    let deadline: fn(u64, u64) -> bridge::DeadlineText = bridge::deadline_text;
    assert_eq!(
        deadline(22 * 3_600_000, 0),
        bridge::DeadlineText {
            short: "about 22 h from now".into(),
            long: "about 22 hours from now".into(),
            hh_mm: None,
            left_ms: 22 * 3_600_000,
        }
    );
    // How long a message to a friend could wait, read on the store worker.
    let _: fn(&Path, &str, u64) -> Option<bridge::QueueReach> = bridge::queue_horizon;
    // The CLI's outcome and refusal texts that errors.rs's tests read.
    let _: fn(&Path, &str, &str, &str) -> bridge::SendCtx = bridge::send_ctx;
    let _: fn(&bridge::SendCtx, &str, bool) -> String = bridge::not_sent_text;
    let _: fn(&bridge::SendCtx, &str, &str, &bridge::RetryNote) -> String = bridge::queued_text;
    let _: fn(&bridge::SendCtx, &str, &str, &bridge::RetryNote) -> String =
        bridge::unconfirmed_text;
    let _: fn(&bridge::SendCtx, &str, &str, &bridge::RetryNote) -> String =
        bridge::earlier_undelivered_text;
    let _: fn(&bridge::SendCtx, &str) -> String = bridge::earlier_unconfirmed_text;
    let _: fn(&bridge::SendCtx, usize) -> String = bridge::queue_full_text;
    let _: fn(&bridge::SendCtx) -> String = bridge::offline_stage_full_text;
    let _: fn(&bridge::SendCtx) -> String = bridge::peer_reset_unreachable_text;
    let _ = bridge::RetryNote {
        expires_at_ms: 0,
        copy_expires_at_ms: 0,
        background: false,
        custodians: Vec::new(),
        carry_first: None,
    };
    let _: fn(&str, &str, &str, &str) -> String = bridge::unverified_carrier_text;
    let _: fn(&str, &str, &str, &str) -> String = bridge::unverified_remote_lan_text;
    let _: [&str; 2] = [
        bridge::INTERNET_DIRECT_HOLD,
        bridge::RESERVED_PREFIX_REFUSAL,
    ];

    // Sending: the routes `raven send --contact` plans (no address from the
    // environment, OD-17), the learned LAN addresses, where the LAN beacon
    // found the friend, the mirror of cli.rs's plan, what the outbox
    // records, the three ways ext.rs sends, the mirror of cli.rs's send, and
    // `raven outbox retry|cancel`.
    #[allow(clippy::type_complexity)]
    let _: fn(
        &Path,
        &bridge::Contact,
        bridge::CarrierChoice,
        Option<String>,
        bool,
        bool,
        &[String],
        &[String],
    ) -> Result<(Vec<bridge::DialRoute>, Option<String>), String> =
        bridge::plan_contact_routes_with;
    let _: fn(&Path, &bridge::Contact, bridge::CarrierChoice, bool) -> Vec<String> =
        bridge::unsaved_lan_routes;
    let _: fn(&Path, &bridge::Contact, bridge::CarrierChoice) -> Vec<String> =
        bridge::beacon_routes;
    #[allow(clippy::type_complexity)]
    let _: fn(
        &Path,
        &bridge::Contact,
        &mut Vec<bridge::DialRoute>,
    ) -> (Vec<String>, Vec<String>) = bridge::add_learned_routes;
    let _: fn(&Path, &bridge::Contact) -> Result<bridge::FriendSend, String> =
        bridge::plan_friend_send;
    let _ = |plan: bridge::FriendSend| -> (Vec<bridge::DialRoute>, Vec<String>, Vec<String>) {
        (plan.routes, plan.unrecorded, plan.learned_lan_dials)
    };
    let intent: fn(bridge::CarrierChoice, bool) -> (raven_core::outbox::CarrierChoice, bool) =
        bridge::send_intent;
    assert_eq!(
        intent(bridge::CarrierChoice::Auto, false),
        (raven_core::outbox::CarrierChoice::Auto, true),
        "the app's sends are `auto`, and a friend may carry them"
    );
    #[allow(clippy::type_complexity)]
    let _: fn(
        &Path,
        &Identity,
        &str,
        &str,
        &str,
        &str,
        raven_core::outbox::CarrierChoice,
        bool,
        &[String],
    ) -> Result<(), String> = bridge::run_send_secure;
    #[allow(clippy::type_complexity)]
    let _: fn(
        &Path,
        &Identity,
        &str,
        &str,
        &str,
        &str,
        bridge::DialCarrier,
    ) -> Result<(), String> = bridge::run_send_secure_on;
    #[allow(clippy::type_complexity)]
    let _: fn(
        &Path,
        &Identity,
        &[bridge::DialRoute],
        &str,
        &str,
        bool,
        raven_core::outbox::CarrierChoice,
        &[String],
    ) -> Result<bridge::DialRoute, String> = bridge::run_send_secure_routes;
    #[allow(clippy::type_complexity)]
    let _: fn(
        &Path,
        &Identity,
        &[bridge::DialRoute],
        &str,
        &str,
        &str,
        &[String],
    ) -> Result<bridge::DialRoute, String> = bridge::send_routes;
    let _: fn(&Path, bridge::OutboxCmd) -> Result<(), String> = bridge::cmd_outbox;
    let _ = [
        bridge::OutboxCmd::Retry { mid: String::new() },
        bridge::OutboxCmd::Cancel {
            mid: String::new(),
            yes: true,
        },
    ];
    let lan = bridge::DialRoute {
        carrier: bridge::DialCarrier::Lan,
        dial: "192.168.1.30:7420".into(),
    };
    assert_eq!(lan.clone(), lan);

    // The background program: its Status as `ash status` reads it, where it
    // listens, starting it as a send does, asking it, and stopping it.
    let reach = |status: &Result<IpcResponse, String>| {
        bridge::classify_node_reach(status, |_: std::net::IpAddr| None)
    };
    assert_eq!(
        reach(&Err("raven-node is not running; x".into())),
        bridge::NodeReach::NotRunning
    );
    // Whether a listen address is still this computer's, read by the probe.
    let here: fn(std::net::IpAddr) -> Option<bool> = bridge::is_on_this_computer;
    assert_eq!(here("127.0.0.1".parse().unwrap()), Some(true));
    let loopback: fn(&str) -> bool = bridge::listen_is_loopback;
    assert!(loopback("127.0.0.1:0") && !loopback("0.0.0.0:7420"));
    // The other forms on this computer only count the same.
    assert!(loopback("[::1]:7420") && loopback("localhost:7420"));
    assert!(!loopback("[::]:7420") && !loopback("192.168.1.20:7420"));
    let _: fn() -> PathBuf = bridge::raven_node_bin_public;
    let _: fn(&Path) -> Result<(), String> = bridge::ensure_mac_lan_daemon;
    let _: fn(&Path, &IpcRequest, Duration) -> Result<IpcResponse, String> =
        bridge::ipc_request_timeout;
    // The stop step (node_control.rs, `raven lock` runs it too).
    let _: fn(bool, bool, bool, Option<u32>, Option<u32>) -> bridge::StopPlan = bridge::stop_plan;
    let _: fn(&Path, bridge::StopPlan) -> bridge::StopOutcome = bridge::carry_out_stop;
    let _: fn(Option<&std::ffi::OsStr>, &str) -> Option<PathBuf> = bridge::system_tool;
    let _: &str = bridge::SCHEDULED_TASK;
    let no_answer: fn(&str) -> bool = bridge::error_means_no_answer;
    assert!(!no_answer("raven-node is not running; start it"));
    let advice: fn(&Path, Option<u32>) -> String = bridge::profile_stop_advice;
    assert!(advice(Path::new("/p"), Some(42)).contains("42"));
    // The privacy pack (PP.21): 'Keep chats for', Delete chat, Forget
    // address, the one-time notices and the at-rest state, each raven-core's
    // or the CLI's own path.
    let _: fn(&Path) -> Result<bridge::ChatKeepView, bridge::NotAvailable> = bridge::chat_keep;
    let _: fn(&Path, bridge::ChatKeepView) -> Result<(), String> = bridge::set_chat_keep;
    let _: fn(&Path, &str) -> Result<bridge::DeleteChatOutcome, String> = bridge::delete_chat;
    let _: fn(&Path, &str) -> Result<Vec<String>, String> = bridge::forget_address;
    let _: fn(&Path) -> bridge::PrivacyNotices = bridge::privacy_notices;
    let _: fn(&Path, bridge::Notice) = bridge::mark_notice_shown;
    let _: fn(bridge::ChatKeepView, u64, u64) -> String = bridge::retention_notice_text;
    let _: fn(&Result<IpcResponse, String>) -> Option<bridge::AtRestStateView> =
        bridge::at_rest_state;
    let _: fn(&Path) -> Option<u64> = bridge::disk_space_needed;
    let _: fn(Option<u64>) -> String = bridge::disk_space_text;
    let _: [&str; 5] = [
        bridge::SEALING_NOTICE,
        bridge::KEYCHAIN_AT_START_TEXT,
        bridge::KEY_UNAVAILABLE_TEXT,
        bridge::KEY_LOST_TEXT,
        bridge::UNSEALED_TEXT,
    ];
    // Erase (PP.22): `raven erase`'s question, refusal, plan and erase.
    assert_eq!(bridge::ERASE_TITLE, "Erase Raven from this computer?");
    assert!(bridge::ERASE_PARAGRAPH.starts_with("This deletes your Raven identity, friends,"));
    let _: fn(&Path) -> Result<bridge::ErasePlanView, String> = bridge::erase_plan;
    let _: fn(&Path, &mut dyn FnMut()) -> bridge::EraseEnd = bridge::erase;
    let _: fn(&Path, &mut dyn FnMut()) -> bridge::EraseEnd = bridge::erase_in_lab;
    let _: fn(&Path) = bridge::forget_profile_keys;
    // Lock (PP.23): Raven's own login item, unloaded for this login session
    // only; the lock in privacy.json; opening the app clears it.
    let _: fn(&Path) -> Result<Option<bridge::LoginItemView>, bridge::NotAvailable> =
        bridge::own_login_item;
    let _: fn(&Path) -> Result<(), String> = bridge::stop_for_session;
    let _: fn(&Path, bool) -> Result<(), String> = bridge::set_locked_by_user;
    let _: fn(&Path) -> Result<bridge::Reopened, String> = bridge::reopen_after_lock;
    // UNLOCK's Start (review E-harness-docs-ci-3): a `raven lock` lock is
    // cleared only after the user said yes.
    let _: fn(&Path) -> Result<bool, String> = bridge::unlock_from_app;
    // The read markers and the name (PP.24): raven-core's at-rest file
    // tui_private.rms in a sealed profile.
    assert_eq!(bridge::TUI_PRIVATE_FILE, "tui_private.rms");
    let _: fn(&Path) -> bool = bridge::tui_private_sealed;
    let _: fn(&Path) -> bridge::TuiPrivateRead = bridge::load_tui_private;
    let _: fn(&Path, &super::state_file::TuiPrivate) -> Result<(), String> =
        bridge::store_tui_private;
    let _: fn(&Path) -> Result<(), String> = bridge::remove_tui_private;
    // Review D-lock-tui-1: the move at the top of every command, and what a
    // sealed profile still keeps in plain.
    let _: fn(&Path) -> bool = bridge::at_rest_keys_loaded;
    let _: fn(&Path) -> Result<bool, String> = bridge::seal_tui_private_in_place;
    let _: fn(&Path) -> bool = bridge::tui_private_in_plain;
    // Review D-lock-tui-2: LOCK's passphrase file (the vault check reads it
    // on Linux) and `raven lock`'s paragraph about it.
    let _: fn(&Path) -> Option<std::path::PathBuf> = bridge::saved_passphrase_file;
    let _: fn(&str) -> String = bridge::passphrase_file_paragraph;
    // FW's rule, for the LAN port; NET's labels, from the gates read once.
    let rule: fn(&str) -> String = bridge::internet_firewall_hint;
    // Windows and macOS name the program, Linux's rule the port.
    if cfg!(any(windows, target_os = "macos")) {
        assert!(rule("7420").contains("raven-node"), "{}", rule("7420"));
    } else {
        assert!(rule("7420").contains("7420/tcp"), "{}", rule("7420"));
    }
    let gates: fn() -> bridge::Gates = bridge::gates_now;
    let lan = gates().lan;
    assert!(lan.production && lan.live, "{lan:?}");
    // The vault, the files the poller watches, and the Keychain waits.
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _: fn(&Path) -> Result<bool, String> = bridge::uses_vault;
        assert_eq!(
            bridge::PASSPHRASE_FILE_ENV,
            "RAVEN_KEYSTORE_PASSPHRASE_FILE"
        );
    }
    assert_eq!(bridge::SYSTEMD_CREDENTIAL_NAME, "raven-keystore-passphrase");
    let _: fn(&Path) -> PathBuf = bridge::service_log_path;
    let _: fn(&Path) -> PathBuf = bridge::history_path;
    let waits: fn(&str) -> Option<&'static str> = bridge::service_keychain_wait;
    let marker = raven_core::macos_keychain::daemon_marker_line(
        raven_core::macos_keychain::KeychainWhat::ChatHistoryKey,
        30,
    );
    assert_eq!(waits(&format!("x\n{marker}\n")), Some("your chat history"));
    assert_eq!(waits("raven-node: started"), None);
    assert_eq!(
        bridge::KEYCHAIN_ITEMS,
        [
            "your Raven identity",
            "your chat history",
            "a conversation key",
            "key-exchange data"
        ]
    );
    // The security notices, the pause and "Check again" (P6.31), and the
    // words security_text.rs has for them.
    let _: fn(&Path) -> bridge::SecurityView = bridge::security_view;
    let _: fn(&Path, i64) -> Result<bool, String> = bridge::resolve_notice;
    let _: fn(&Path, &str, bool) -> Result<bool, String> = bridge::set_send_hold;
    let _: fn(&Path, &str, &str) -> Result<bridge::Resolved, String> = bridge::resolve_on_match;
    let _: fn(&Path, &str, &str) -> Result<bool, String> = bridge::accept_older_method;
    let _: fn(&Result<IpcResponse, String>) -> Option<bridge::SecurityCounts> =
        bridge::security_counts;
    for words in [
        bridge::floor_intro,
        bridge::floor_question,
        bridge::floor_kept,
        bridge::floor_accepted,
    ] {
        let text: String = words("Sara");
        assert!(text.contains("Sara"), "{text}");
    }
    assert_eq!(
        bridge::resolved_by_verify("Sara", 2),
        "Resolved 2 security notices about Sara."
    );
    assert!(bridge::strangers_line(37).contains("37"));
    assert_eq!(
        bridge::notices_line(3),
        "Also 3 smaller notices, only counted."
    );
    assert_eq!(
        bridge::NOT_IN_THIS_VERSION,
        "Security notices are not part of this version."
    );
    assert!(bridge::NOT_KEPT_UNSEALED.starts_with("This profile is not encrypted"));
    assert_eq!(bridge::SecAct::CompareWords.as_str(), "compare_words");
    assert_eq!(bridge::SecKept::default(), bridge::SecKept::Off);
}

/// `source` with each string continuation (a `\` ending a line, and the
/// next line's indent) taken out, as the compiler takes it out: a text the
/// app reads may be split over lines there.
fn joined_strings(source: &str) -> String {
    let mut joined = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(at) = rest.find("\\\n") {
        joined.push_str(&rest[..at]);
        rest = rest[at + 2..].trim_start();
    }
    joined.push_str(rest);
    joined
}

#[test]
fn ext_still_prints_the_texts_the_app_reads() {
    let ext = joined_strings(include_str!("../ext.rs"));
    let missing: Vec<String> = EXT_TEXTS
        .iter()
        .filter(|(text, _)| !ext.contains(text))
        .map(|(text, reader)| format!("`{text}`: update {reader}"))
        .collect();
    assert!(
        missing.is_empty(),
        "ext.rs no longer prints a text the app reads\n{}",
        missing.join("\n")
    );
}

#[test]
fn raven_core_still_words_the_keychain_wait_as_the_app_reads_it() {
    let keychain = joined_strings(include_str!("../../../raven-core/src/macos_keychain.rs"));
    let missing: Vec<String> = KEYCHAIN_TEXTS
        .iter()
        .filter(|(text, _)| !keychain.contains(text))
        .map(|(text, reader)| format!("`{text}`: update {reader}"))
        .collect();
    assert!(
        missing.is_empty(),
        "raven-core/src/macos_keychain.rs no longer words a text the app reads\n{}",
        missing.join("\n")
    );
    // The marks the stderr reader looks for are those texts' fixed parts.
    assert!(KEYCHAIN_TEXTS[0].0.starts_with(workers::WATCHDOG_MARK));
    assert!(EXT_TEXTS[2].0.starts_with(workers::SERVICE_WAIT_MARK));
    assert!(EXT_TEXTS[0].0 == super::node::STARTED_MARK.trim_end());
    assert_eq!(EXT_TEXTS[1].0, super::delivery::MAY_HAVE_IT);
    assert_eq!(EXT_TEXTS[3].0, super::app::EXT_NOT_WAITING);
    assert_eq!(EXT_TEXTS[4].0, super::app::EXT_NO_OUTBOX);
    assert!(EXT_TEXTS[5].0.ends_with(super::app::EXT_DELIVERED_FIRST));
    assert_eq!(EXT_TEXTS[6].0, super::node::RUN_MARK);
    assert!(EXT_TEXTS[7].0.contains(super::errors::SESSION_ENDED_MARK));
    // ext.rs writes "a " (or "A ") before its first-message words.
    assert!(format!("a {}", EXT_TEXTS[8].0).starts_with(super::errors::FIRST_MESSAGE_MARK));
    assert_eq!(joined_strings("a \\\n      b\\\n\tc \\ d"), "a bc \\ d");
}

#[test]
fn raven_node_still_logs_its_listener_as_the_app_reads_it() {
    let lan_direct = joined_strings(include_str!("../../../raven-node/src/lan_direct.rs"));
    let main = joined_strings(include_str!("../../../raven-node/src/main.rs"));
    let missing: Vec<String> = NODE_LOG_TEXTS
        .iter()
        .filter(|(text, file)| {
            let source = if *file == "main.rs" {
                &main
            } else {
                &lan_direct
            };
            !source.contains(text)
        })
        .map(|(text, file)| format!("`{text}` ({file}): update tui/node.rs's listener_in_log"))
        .collect();
    assert!(
        missing.is_empty(),
        "raven-node no longer logs its LAN listener as the app reads it\n{}",
        missing.join("\n")
    );
    // The marks node.rs looks for are those texts' fixed parts: the bound
    // line, and `retry_until_ok`'s failure line around the bind's error.
    assert!(NODE_LOG_TEXTS[0].0.starts_with(super::node::LISTENING_MARK));
    assert_eq!(
        super::node::BIND_FAILED_MARK,
        "lan_direct failed: lan_direct bind "
    );
}

/// The names a `mod code` block makes public: each `pub const NAME: &str =
/// "VALUE"` by its value, each name of a `pub use path::{A, B}`.
fn exported_codes(block: &str) -> Vec<String> {
    let mut codes = Vec::new();
    for line in block.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("pub const ") {
            let value = rest.split('"').nth(1);
            codes.push(
                value
                    .unwrap_or_else(|| panic!("no value in `{line}`"))
                    .to_owned(),
            );
        } else if let Some(rest) = line.strip_prefix("pub use ") {
            let names = match (rest.find('{'), rest.rfind('}')) {
                (Some(open), Some(close)) => &rest[open + 1..close],
                _ => rest.rsplit("::").next().unwrap_or(rest),
            };
            codes.extend(
                names
                    .split(',')
                    .map(|name| name.trim().trim_end_matches(';').to_owned())
                    .filter(|name| !name.is_empty()),
            );
        }
    }
    codes
}

#[test]
fn errors_words_every_outbox_code_of_raven_node() {
    let outbox = include_str!("../../../raven-node/src/outbox.rs");
    let block = item_text(outbox, OUTBOX_CODE_BLOCK);
    let words = errors::outbox_codes();
    let missing: Vec<String> = exported_codes(block)
        .into_iter()
        .filter(|code| !words.contains(&code.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "raven-node/src/outbox.rs has outbox codes tui/errors.rs has no words for (add them to \
         OUTBOX_CODES): {missing:?}"
    );
    // The codes re-exported there from raven-core are their own names.
    use raven_core::session_reset::code::{PEER_RESET, PEER_RESET_NO_BODY, RESEAL_CAP};
    assert_eq!(
        [PEER_RESET, PEER_RESET_NO_BODY, RESEAL_CAP],
        ["PEER_RESET", "PEER_RESET_NO_BODY", "RESEAL_CAP"]
    );
    // And the one errors.rs adds from raven-core.
    assert_eq!(raven_core::CONTACT_NOT_VERIFIED, "CONTACT_NOT_VERIFIED");
    let hash = drift_hash(block);
    assert_eq!(
        hash, OUTBOX_CODE_HASH,
        "raven-node/src/outbox.rs's `{OUTBOX_CODE_BLOCK}` changed (hash {hash:#018x}): check \
         tui/errors.rs's OUTBOX_CODES and explain_outbox_code against it, then update \
         OUTBOX_CODE_HASH"
    );
}

#[test]
fn bridge_still_mirrors_the_clis_send() {
    let cli = include_str!("../cli.rs");
    let hash = drift_hash(item_text(cli, RUN_SEND_HEAD));
    assert_eq!(
        hash, RUN_SEND_HASH,
        "cli.rs's `{RUN_SEND_HEAD}…)` changed (hash {hash:#018x}): make tui/bridge.rs's \
         send_routes do what it does now, then update RUN_SEND_HASH"
    );
}

#[test]
fn bridge_still_mirrors_the_clis_send_plan() {
    let cli = include_str!("../cli.rs");
    let hash = drift_hash(item_text(cli, RESOLVE_SEND_HEAD));
    assert_eq!(
        hash, RESOLVE_SEND_HASH,
        "cli.rs's `{RESOLVE_SEND_HEAD}…)` changed (hash {hash:#018x}): make tui/bridge.rs's \
         plan_friend_send plan what its `--contact` part plans now, then update \
         RESOLVE_SEND_HASH"
    );
}

#[test]
fn bridge_still_wraps_the_clis_security_check() {
    let cli = include_str!("../cli.rs");
    let hash = drift_hash(item_text(cli, SECURITY_CHECK_HEAD));
    assert_eq!(
        hash, SECURITY_CHECK_HASH,
        "cli.rs's `{SECURITY_CHECK_HEAD}…)` changed (hash {hash:#018x}): check tui/bridge.rs's \
         security_check and what VF says for each outcome against it, then update \
         SECURITY_CHECK_HASH"
    );
}

#[test]
fn raven_core_still_says_it_cannot_ask_for_the_passphrase() {
    let vault = include_str!("../../../raven-core/src/keystore_vault.rs");
    assert!(
        vault.contains(errors::PASSPHRASE_MARK),
        "raven-core/src/keystore_vault.rs no longer says `{}`: update tui/errors.rs's \
         PASSPHRASE_MARK (explain_node_start, explain_node_unavailable)",
        errors::PASSPHRASE_MARK
    );
}

#[test]
fn drift_hashes_ignore_layout_only() {
    // FNV-1a's published values.
    assert_eq!(drift_hash(""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(drift_hash("a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(
        drift_hash("fn f() {\n    g(1,\t2);\n}\n"),
        drift_hash("fn f() { g(1, 2); }")
    );
    assert_ne!(
        drift_hash("fn f() { g(1, 2); }"),
        drift_hash("fn f() { g(1, 3); }")
    );

    let source = concat!(
        "fn before() {}\n",
        "fn pick(x: char) -> &'static str {\n",
        "    if x == '{' {\n",
        "        return \"}}\\\"{\";\n",
        "    }\n",
        "    match x { '\\'' => \"{\", _ => \"\" }\n",
        "}\n",
        "fn after() { }\n",
    );
    let pick = item_text(source, "fn pick(");
    assert!(
        pick.starts_with("fn pick(") && pick.ends_with("_ => \"\" }\n}"),
        "{pick}"
    );
    assert_eq!(item_text(source, "fn after("), "fn after() { }");
}
