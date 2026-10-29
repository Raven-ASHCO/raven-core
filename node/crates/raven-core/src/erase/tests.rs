//! PP.16 tests: `raven erase`'s plan, its order and its refusals, on temp
//! profiles only. K_hist is Windows' key file here (`windows_key::ForTests`,
//! with the DPAPI stand-in off Windows): a real, deletable key root inside
//! the test's own folder, so nothing here calls a keystore. The keychain and
//! Secret Service deletes run in the owner's real row R34; their items are
//! planned here by name only ([`plan_with`] with `platform`, executed by a
//! recorder that deletes nothing).

use super::*;
use crate::at_rest::{MigratePolicy, META_KEY_FILE};
use crate::chat_history::windows_key::{key_path, ForTests};
use crate::chat_history::{ChatHistory, ChatHistoryEntry};
use crate::contact_book::tests::{fixture, profile};
use crate::privacy::{migrate_all, MigrateOutcome};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

const T0: u64 = 20_300 * 86_400_000 + 3_600_000;

fn row(n: u8) -> ChatHistoryEntry {
    ChatHistoryEntry {
        message_id_hex: hex::encode([n; 16]),
        direction: "in".into(),
        peer_petname: String::new(),
        peer_tag: String::new(),
        // Wrapping: the writer thread of `no_process_remints_k_hist_after_step_2`
        // counts n up to 255 when the erase steps run slowly.
        peer_pub_hex: hex::encode([0x40u8.wrapping_add(n); 32]),
        created_at_ms: T0,
        delivery: "delivered".into(),
        preview: String::new(),
        body: format!("message {n}"),
        stored_at_ms: None,
        id_conflict: false,
    }
}

/// A sealed profile with a contact book, a chat, Windows' K_hist (the
/// caller's thread runs Windows' path) and the files a profile collects:
/// lock files, a quarantine copy, an export, an inbox file, a log and the
/// lab backends' secrets.
fn sealed_profile() -> tempfile::TempDir {
    assert!(crate::chat_history::windows_key::active());
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    ChatHistory::append_persisted(dd, row(1)).unwrap();
    // A chat before the sealing mints no K_hist (review A-keys-format-2):
    // the sealing does.
    assert!(!key_path(dd).exists());
    crate::at_rest::tests::expect_key_file(dd);
    let report = migrate_all(dd, T0, MigratePolicy::Allow).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
    assert!(key_path(dd).exists(), "K_hist is minted by the sealing");
    for (name, bytes) in [
        ("identity.seed", &b"seed bytes"[..]),
        ("identity.binding", b"binding"),
        ("device_x25519.secret", b"secret"),
        ("contacts.json.corrupt", b"{}"),
        ("lan_noise_pins.json.corrupt-1700", b"{}"),
        ("contact_request_00ff.wire", b"wire"),
        ("raven-node-service.log", b"log line\n"),
        (".contacts.lock.sqlite", b""),
        (".contacts.lock.sqlite-wal", b""),
        (".x.json.tmp.00aa", b"tmp"),
        ("prekey_lifecycle.protected", b"lab prekey"),
    ] {
        std::fs::write(dd.join(name), bytes).unwrap();
    }
    for (folder, name) in [
        ("indexed-session-secrets", "abcd.bin"),
        ("prekey-lifecycle-secrets", "ef01.dpapi"),
        ("contact_inbox", "00ff.wire"),
        ("lan_pair_response", "0011"),
    ] {
        std::fs::create_dir_all(dd.join(folder)).unwrap();
        std::fs::write(dd.join(folder).join(name), b"x").unwrap();
    }
    dir
}

/// A session store holding only what the plan reads: the heads' record keys
/// (clear in every schema).
fn heads(dd: &Path, keys: &[[u8; 32]]) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(
            dd.join(format!("{}{suffix}", crate::INDEXED_SESSION_METADATA_FILE)),
        );
    }
    let conn = rusqlite::Connection::open(dd.join(crate::INDEXED_SESSION_METADATA_FILE)).unwrap();
    conn.execute_batch("CREATE TABLE indexed_session_heads (record_key BLOB PRIMARY KEY)")
        .unwrap();
    for key in keys {
        conn.execute(
            "INSERT INTO indexed_session_heads (record_key) VALUES (?1)",
            [key.as_slice()],
        )
        .unwrap();
    }
}

fn canonical(dir: &tempfile::TempDir) -> PathBuf {
    std::fs::canonicalize(dir.path()).unwrap()
}

/// Every regular file and link below `dir`, as `/`-separated names.
fn files_below(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).into_iter().flatten().flatten() {
            let path = entry.path();
            if is_real_dir(&path) {
                stack.push(path);
            } else {
                out.push(relative(dir, &path));
            }
        }
    }
    out.sort();
    out
}

/// Every file a plan names, below its data dir.
fn planned(plan: &ErasePlan) -> Vec<String> {
    let dir = &plan.data_dir;
    let mut out: Vec<String> = plan
        .keystore
        .iter()
        .filter_map(|item| match item {
            KeystoreItem::File { path, .. } => Some(relative(dir, path)),
            _ => None,
        })
        .chain(plan.key_files.iter().map(|p| relative(dir, p)))
        .chain(plan.data_files.iter().map(|p| relative(dir, p)))
        .chain(
            plan.socket_files
                .iter()
                .filter(|p| p.starts_with(dir))
                .map(|p| relative(dir, p)),
        )
        .collect();
    out.sort();
    out
}

fn erase(dd: &Path) -> EraseReport {
    begin(dd).unwrap();
    execute(&plan(dd).unwrap(), &mut |_| {})
}

/// Records each delete in order; files and folders really go, keystore
/// items of the OS keystore are only recorded.
#[derive(Default)]
struct Recorder {
    ops: Vec<String>,
    fail_on: Option<String>,
}

impl Remover for Recorder {
    fn keystore_item(&mut self, item: &KeystoreItem) -> Result<bool, String> {
        match item {
            KeystoreItem::Platform { role, account, .. } => {
                self.ops.push(format!("keystore {role:?} {account}"));
                Ok(true)
            }
            KeystoreItem::PlatformPrefix { prefix, .. } => {
                self.ops.push(format!("keystore prefix {prefix}"));
                Ok(false)
            }
            KeystoreItem::File { role, path } => {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                self.ops.push(format!("keystore {role:?} file {name}"));
                remove_file(path, true)
            }
        }
    }

    fn file(&mut self, path: &Path, overwrite: bool) -> Result<bool, String> {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        self.ops.push(format!("file {name}"));
        if self.fail_on.as_deref() == Some(name.as_str()) {
            return Err("Permission denied (test)".into());
        }
        remove_file(path, overwrite)
    }

    fn empty_dir(&mut self, path: &Path) -> Result<bool, String> {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        self.ops.push(format!("dir {name}"));
        remove_empty_dir(path)
    }
}

#[test]
fn plan_lists_every_item_of_profile_a_and_none_of_b() {
    let _windows = ForTests::on();
    let (a_dir, b_dir) = (sealed_profile(), sealed_profile());
    let (a, b) = (canonical(&a_dir), canonical(&b_dir));
    let (a_keys, b_keys) = ([[1u8; 32], [2; 32]], [[3u8; 32]]);
    heads(&a, &a_keys);
    heads(&b, &b_keys);
    std::fs::write(a.join("notes.txt"), b"mine").unwrap();
    std::fs::write(a.join("keystore.backend"), b"secret-service\n").unwrap();
    std::fs::write(a.join("keystore.vault"), b"vault bytes").unwrap();

    let p = plan_with(&a, true).unwrap();
    // K_hist first: the keychain / Secret Service item, then its file.
    assert_eq!(
        p.keystore[0],
        KeystoreItem::platform(KeyRole::HistKey, crate::chat_history::history_key_item(&a))
    );
    assert_eq!(
        p.keystore[1],
        KeystoreItem::File {
            role: KeyRole::HistKey,
            path: a.join(crate::chat_history::WINDOWS_HISTORY_KEY_FILE)
        }
    );
    // The passphrase vault holds K_hist too (and every other key).
    assert_eq!(
        p.keystore[2],
        KeystoreItem::File {
            role: KeyRole::Vault,
            path: a.join("keystore.vault")
        }
    );
    let (service, namespace) = crate::indexed_session_store::erase_namespace(&a);
    let accounts: Vec<(KeyRole, &'static str, String)> = p
        .keystore
        .iter()
        .filter_map(|item| match item {
            KeystoreItem::Platform {
                role,
                service,
                account,
            } => Some((*role, *service, account.clone())),
            _ => None,
        })
        .collect();
    let mut want = vec![
        {
            let (s, a) = crate::chat_history::history_key_item(&a);
            (KeyRole::HistKey, s, a)
        },
        {
            let (s, a) = crate::identity_store::keychain_item(&a);
            (KeyRole::Identity, s, a)
        },
    ];
    for key in a_keys {
        want.push((
            KeyRole::Session,
            service,
            format!("{namespace}:{}", hex::encode(key)),
        ));
    }
    want.push({
        let (s, a) = crate::prekey_lifecycle::erase_item(&a);
        (KeyRole::Prekey, s, a)
    });
    assert_eq!(accounts, want);
    // Then every item of A's namespace, after the ones named (macOS and
    // GNU/Linux; the keychain since review C-deletion-erase-1).
    let prefixes: Vec<&KeystoreItem> = p
        .keystore
        .iter()
        .filter(|item| matches!(item, KeystoreItem::PlatformPrefix { .. }))
        .collect();
    if cfg!(any(
        target_os = "macos",
        all(target_os = "linux", target_env = "gnu")
    )) {
        assert_eq!(
            prefixes,
            [&KeystoreItem::PlatformPrefix {
                role: KeyRole::Session,
                service,
                prefix: format!("{namespace}:"),
            }]
        );
    } else {
        assert!(prefixes.is_empty());
    }
    assert_eq!(
        [
            "app.raven.node.chat-history.v1",
            "app.raven.node.identity",
            "app.raven.node.atsam-indexed-session",
            "app.raven.node.prekey-lifecycle"
        ],
        [want[0].1, want[1].1, want[2].1, want.last().unwrap().1]
    );
    // Nothing of B: no account B's dir derives, no record key of B, no path.
    let b_names = [
        crate::chat_history::history_key_item(&b).1,
        crate::identity_store::keychain_item(&b).1,
        crate::indexed_session_store::erase_namespace(&b).1,
        crate::prekey_lifecycle::erase_item(&b).1,
        hex::encode(b_keys[0]),
    ];
    for (_, _, account) in &accounts {
        for name in &b_names {
            assert!(!account.contains(name.as_str()), "{account} names B");
        }
    }
    let every_path = p
        .key_files
        .iter()
        .chain(&p.data_files)
        .chain(&p.raven_dirs)
        .chain(&p.socket_files)
        .chain(&p.left_unknown);
    for path in every_path {
        assert!(path.starts_with(&a) && !path.starts_with(&b), "{path:?}");
    }
    // Every file of A is planned, except the one Raven didn't create.
    let mut all = files_below(&a);
    all.retain(|name| name != "notes.txt");
    assert_eq!(planned(&p), all);
    assert_eq!(p.left_unknown, [a.join("notes.txt")]);
    assert!(planned(&p).contains(&"contacts.json.corrupt".to_owned()));
    assert!(planned(&p).contains(&"lan_noise_pins.json.corrupt-1700".to_owned()));
    for folder in [
        "indexed-session-secrets",
        "prekey-lifecycle-secrets",
        "contact_inbox",
        "lan_pair_response",
    ] {
        assert!(p.raven_dirs.contains(&a.join(folder)), "{folder}");
    }
    // The key files are overwritten first (step 3), K_hist's file is a key.
    for name in [META_KEY_FILE, "identity.seed", "device_x25519.secret"] {
        assert!(p.key_files.contains(&a.join(name)), "{name}");
    }
    // In a unit test the OS keystore is never planned by `plan`.
    assert!(!plan(&a)
        .unwrap()
        .keystore
        .iter()
        .any(|item| matches!(item, KeystoreItem::Platform { .. })));
}

#[test]
fn key_root_is_deleted_before_any_file() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    heads(&dd, &[[9; 32]]);
    begin(&dd).unwrap();
    let mut recorder = Recorder::default();
    let report = execute_with(&plan_with(&dd, true).unwrap(), &mut recorder, &mut |_| {});
    assert!(report.finished, "{:?}", report.failures);
    let ops = &recorder.ops;
    assert!(ops[0].starts_with("keystore HistKey "), "{ops:?}");
    assert_eq!(ops[1], "keystore HistKey file chat_history_key.dpapi");
    let last_key = ops
        .iter()
        .rposition(|op| op.starts_with("keystore"))
        .unwrap();
    let first_file = ops.iter().position(|op| op.starts_with("file")).unwrap();
    assert!(last_key < first_file, "{ops:?}");
    // The key files come first among the files, meta_key.rmk among them.
    assert_eq!(ops[first_file], format!("file {META_KEY_FILE}"));
    // The marker last, then the folder.
    assert_eq!(
        &ops[ops.len() - 2..],
        [
            format!("file {MARKER_FILE}"),
            format!("dir {}", dd.file_name().unwrap().to_string_lossy())
        ]
    );
    assert!(report.folder_removed && !dd.exists());
}

#[test]
fn erase_leaves_unknown_files_and_the_dir() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    std::fs::write(dd.join("notes.txt"), b"mine").unwrap();
    std::fs::create_dir_all(dd.join("photos")).unwrap();
    std::fs::write(dd.join("photos/cat.jpg"), b"cat").unwrap();
    std::fs::write(dd.join("contact_inbox/mine.txt"), b"mine too").unwrap();
    // A link out of the profile is deleted as a link, never followed.
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("keep.json"), b"{}").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), dd.join("lan_pair_response/linked")).unwrap();

    let report = erase(&dd);
    assert!(report.finished, "{:?}", report.failures);
    assert!(!report.folder_removed);
    assert!(report.keys >= 5 && report.files >= 10, "{report:?}");
    assert_eq!(
        files_below(&dd),
        ["contact_inbox/mine.txt", "notes.txt", "photos/cat.jpg"]
    );
    assert_eq!(
        report.left_unknown,
        [
            dd.join("contact_inbox/mine.txt"),
            dd.join("notes.txt"),
            dd.join("photos")
        ]
    );
    assert!(!dd.join(MARKER_FILE).exists() && !key_path(&dd).exists());
    assert!(outside.path().join("keep.json").exists());
    // What is left is not a Raven profile any more.
    assert!(refusal_with(&dd, None, false, None).is_some());
}

/// The verified releases waiting to be installed (P6.47) are Raven's, one
/// folder per build below `updates/staged/`: erased with the profile, and
/// a folder the registry does not name below them is left as it is.
#[test]
fn staged_updates_go_with_the_profile() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    for name in [
        "updates/state",
        "updates/staged/5/manifest.rrb1",
        "updates/staged/5/0-raven",
        "updates/staged/7/1-raven-node",
        "updates/staged/.tmp-8-00aa/0-raven",
        "updates/staged/7/deeper/kept.txt",
    ] {
        std::fs::create_dir_all(dd.join(name).parent().unwrap()).unwrap();
        std::fs::write(dd.join(name), b"x").unwrap();
    }
    let p = plan_with(&dd, true).unwrap();
    for folder in [
        "updates",
        "updates/staged",
        "updates/staged/5",
        "updates/staged/7",
    ] {
        assert!(p.raven_dirs.contains(&dd.join(folder)), "{folder}");
    }
    assert_eq!(p.left_unknown, [dd.join("updates/staged/7/deeper")]);
    let report = erase(&dd);
    assert!(report.finished, "{:?}", report.failures);
    assert_eq!(files_below(&dd), ["updates/staged/7/deeper/kept.txt"]);
    assert!(!dd.join("updates/staged/5").exists());
    assert!(!dd.join("updates/staged/.tmp-8-00aa").exists());
}

#[test]
fn erase_refuses_home_root_and_non_raven_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let profile = home.join(".raven");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(profile.join("identity.backend"), b"locked-file\n").unwrap();
    let refused = |dir: &Path| refusal_with(dir, Some(&home), false, None);
    assert_eq!(refused(&profile), None);
    // The home folder itself, a folder above it, the root: never, even with
    // Raven's files in them.
    std::fs::write(home.join("identity.backend"), b"locked-file\n").unwrap();
    std::fs::write(tmp.path().join("meta_key.rmk"), b"RMK1").unwrap();
    for dir in [home.as_path(), tmp.path(), Path::new("/")] {
        assert_eq!(refused(dir), Some(not_a_profile_text(dir)), "{dir:?}");
    }
    // A folder that only shares names any program could use, a missing one
    // and a file.
    let docs = tmp.path().join("docs");
    std::fs::create_dir_all(&docs).unwrap();
    for name in [
        "contacts.json",
        "bootstrap.json",
        "queue.sqlite",
        "notes.txt",
    ] {
        std::fs::write(docs.join(name), b"{}").unwrap();
    }
    assert_eq!(refused(&docs), Some(not_a_profile_text(&docs)));
    assert!(refused(&tmp.path().join("missing")).is_some());
    assert!(refused(&docs.join("notes.txt")).is_some());
    // Raven's own files make one: a half-erased profile (its marker), a
    // profile whose identity record went.
    for proof in [MARKER_FILE, META_KEY_FILE, "keystore.vault", "privacy.json"] {
        let dir = tmp.path().join(format!("p-{proof}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(proof), b"x").unwrap();
        assert_eq!(refused(&dir), None, "{proof}");
    }
    // Nothing was changed by any refusal.
    assert_eq!(files_below(&docs).len(), 4);
}

#[test]
fn debug_build_refuses_outside_the_erase_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("runs");
    let inside = root.join("case/a");
    let live = tmp.path().join("home/.raven");
    for dir in [&inside, &live] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("identity.backend"), b"locked-file\n").unwrap();
    }
    let root_text = Some(root.display().to_string());
    let guard = Some(LAB_GUARD_TEXT.to_owned());
    assert_eq!(refusal_with(&inside, None, true, root_text.clone()), None);
    // Outside the root (a live profile), the root itself, no switch, a
    // relative or missing root.
    assert_eq!(refusal_with(&live, None, true, root_text.clone()), guard);
    std::fs::write(root.join("identity.backend"), b"locked-file\n").unwrap();
    assert_eq!(refusal_with(&root, None, true, root_text), guard);
    assert_eq!(refusal_with(&inside, None, true, None), guard);
    assert_eq!(
        refusal_with(&inside, None, true, Some("runs".into())),
        guard
    );
    assert_eq!(
        refusal_with(
            &inside,
            None,
            true,
            Some(tmp.path().join("gone").display().to_string())
        ),
        guard
    );
    // A spelling through `..` is the same folder: outside stays outside.
    let sneaky = root.join("../home/.raven");
    assert_eq!(
        refusal_with(&sneaky, None, true, Some(root.display().to_string())),
        guard
    );
    // A release build never reads the switch.
    assert_eq!(refusal_with(&live, None, false, None), None);
    // This test process (debug, the switch unset in tests): `refusal` uses
    // the guard.
    if cfg!(debug_assertions) && std::env::var_os(crate::lan_gate::LAB_ERASE_ROOT).is_none() {
        assert_eq!(refusal(&inside), guard);
    }
}

#[test]
fn marker_blocks_every_other_entry_point() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    begin(&dd).unwrap();
    assert!(in_progress(&dd));
    assert_eq!(refuse_if_unfinished(&dd), Err(UNFINISHED_TEXT.to_owned()));
    let said = |e: String| assert!(e.contains(UNFINISHED_TEXT), "{e}");
    said(
        crate::paths::DataDirLock::acquire(&dd, ".contacts.lock.sqlite")
            .err()
            .unwrap(),
    );
    said(
        ChatHistory::append_persisted(&dd, row(2))
            .unwrap_err()
            .to_string(),
    );
    said(
        crate::contact_book::write_rows::<serde_json::Value>(&dd, &[])
            .unwrap_err()
            .to_string(),
    );
    said(
        crate::indexed_session_store::IndexedSessionStore::open(&dd)
            .err()
            .unwrap()
            .to_string(),
    );
    assert!(crate::prekey_lifecycle::PrekeyLifecycleActor::open(&dd).is_err());
    said(
        crate::identity_store::load_or_create_identity(&dd)
            .err()
            .unwrap()
            .to_string(),
    );
    assert!(migrate_all(&dd, T0, MigratePolicy::Allow).is_err());
    let lock = crate::paths::open_private_data_dir_sqlite(&dd.join("owed_acks.sqlite"));
    said(lock.err().unwrap().to_string());

    // Once K_hist and the key file are gone, nothing creates either again.
    std::fs::remove_file(key_path(&dd)).unwrap();
    std::fs::remove_file(dd.join(META_KEY_FILE)).unwrap();
    crate::at_rest::forget_cached_keys(&dd);
    assert!(crate::at_rest::keys_load_with(&dd, MigratePolicy::Allow).is_err());
    assert!(ChatHistory::append_persisted(&dd, row(3)).is_err());
    assert!(!key_path(&dd).exists() && !dd.join(META_KEY_FILE).exists());

    // Taken back before anything went (a node answered again): the profile
    // opens as before.
    let dir = sealed_profile();
    let dd = canonical(&dir);
    begin(&dd).unwrap();
    assert!(ChatHistory::append_persisted(&dd, row(4)).is_err());
    abandon(&dd).unwrap();
    assert!(!in_progress(&dd));
    ChatHistory::append_persisted(&dd, row(4)).unwrap();
    assert_eq!(ChatHistory::load(&dd).unwrap().entries.len(), 2);
}

#[test]
fn no_process_remints_k_hist_after_step_2() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    // Another Raven process's writer, which mints K_hist when it is missing.
    let stop = Arc::new(AtomicBool::new(false));
    let (wrote, refused) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let writer = {
        let (dd, stop, wrote, refused) = (dd.clone(), stop.clone(), wrote.clone(), refused.clone());
        std::thread::spawn(move || {
            let _windows = ForTests::on();
            let mut n = 10u8;
            while !stop.load(Ordering::SeqCst) {
                n = n.wrapping_add(1).max(10);
                match ChatHistory::append_persisted(&dd, row(n)) {
                    Ok(()) => wrote.fetch_add(1, Ordering::SeqCst),
                    Err(_) => refused.fetch_add(1, Ordering::SeqCst),
                };
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        })
    };
    while wrote.load(Ordering::SeqCst) < 3 {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    begin(&dd).unwrap();
    let p = plan(&dd).unwrap();
    // The writer keeps running through steps 2 to 4; it is stopped (as a
    // process that gives up) only when the marker is about to go.
    struct StopsTheWriterLast<'a> {
        inner: Recorder,
        stop: &'a AtomicBool,
        writer: Option<std::thread::JoinHandle<()>>,
        key_seen: bool,
    }
    impl Remover for StopsTheWriterLast<'_> {
        fn keystore_item(&mut self, item: &KeystoreItem) -> Result<bool, String> {
            self.inner.keystore_item(item)
        }
        fn file(&mut self, path: &Path, overwrite: bool) -> Result<bool, String> {
            if path.ends_with(MARKER_FILE) {
                self.key_seen |= key_path(path.parent().unwrap()).exists();
                self.stop.store(true, Ordering::SeqCst);
                self.writer.take().unwrap().join().unwrap();
                self.key_seen |= key_path(path.parent().unwrap()).exists();
            } else {
                std::thread::sleep(std::time::Duration::from_millis(3));
            }
            self.inner.file(path, overwrite)
        }
        fn empty_dir(&mut self, path: &Path) -> Result<bool, String> {
            self.inner.empty_dir(path)
        }
    }
    let mut remover = StopsTheWriterLast {
        inner: Recorder::default(),
        stop: &stop,
        writer: Some(writer),
        key_seen: false,
    };
    let report = execute_with(&p, &mut remover, &mut |_| {});
    assert!(report.finished, "{:?}", report.failures);
    assert!(!remover.key_seen, "K_hist came back during the erase");
    assert!(
        refused.load(Ordering::SeqCst) > 0,
        "the writer was refused while the erase ran"
    );
    assert!(!dd.exists(), "nothing of the profile is left");
}

#[test]
fn failure_in_the_middle_reports_what_is_left_and_rerun_finishes() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    begin(&dd).unwrap();
    let mut failing = Recorder {
        fail_on: Some("contacts.json".into()),
        ..Recorder::default()
    };
    let report = execute_with(&plan(&dd).unwrap(), &mut failing, &mut |_| {});
    assert!(!report.finished && !report.folder_removed);
    assert_eq!(
        report.failures,
        [Failure {
            what: "contacts.json could not be deleted (Permission denied (test))".into(),
            left: "contacts.json".into(),
        }]
    );
    assert_eq!(report.still_here(), ["contacts.json"]);
    // Crypto-erase first: the key root went all the same, and every other
    // file of Raven's; the marker keeps the profile closed.
    assert!(!key_path(&dd).exists());
    assert_eq!(files_below(&dd), ["contacts.json", MARKER_FILE]);
    assert!(in_progress(&dd));
    assert_eq!(refusal_with(&dd, None, false, None), None, "still Raven's");
    // `raven erase` again: the plan from what exists, and it finishes.
    let report = execute(&plan(&dd).unwrap(), &mut |_| {});
    assert!(report.finished && report.folder_removed, "{report:?}");
    assert_eq!((report.keys, report.files), (0, 1));
    assert!(!dd.exists());
}

#[test]
fn a_copy_of_the_sealed_data_dir_taken_before_erase_cannot_be_opened_after() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    assert_eq!(ChatHistory::load(&dd).unwrap().entries.len(), 1);
    assert_eq!(
        crate::contact_book::read_rows::<serde_json::Value>(&dd)
            .unwrap()
            .unwrap()
            .len(),
        4
    );
    // A copy of the folder as someone takes it: K_hist stands for the
    // keychain item here, which is not in the folder on macOS or Linux (on
    // Windows its DPAPI-wrapped file is; design doc 4.14, honest limit).
    let copy = tempfile::tempdir().unwrap();
    for name in files_below(&dd) {
        if name == crate::chat_history::WINDOWS_HISTORY_KEY_FILE {
            continue;
        }
        let to = copy.path().join(&name);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(dd.join(&name), to).unwrap();
    }
    let report = erase(&dd);
    assert!(report.finished && !dd.exists(), "{report:?}");
    // Put back where it was (the keys are bound to the folder's path), in a
    // new process: nothing opens, and nothing mints a key root.
    for name in files_below(copy.path()) {
        let to = dd.join(&name);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(copy.path().join(&name), to).unwrap();
    }
    crate::at_rest::forget_cached_keys(&dd);
    assert!(crate::at_rest::keys_load_with(&dd, MigratePolicy::Never).is_err());
    assert!(ChatHistory::load(&dd).is_err());
    assert!(crate::contact_book::read_rows::<serde_json::Value>(&dd).is_err());
    assert!(crate::privacy::verify_copy(&dd, &dd.join("contacts.json")).is_err());
    assert!(!key_path(&dd).exists());
}

/// The long-path fallback: only this profile's `/tmp/raven-<euid>/raven-
/// <hash>.sock` and its lock go; another profile's stay, and so does the
/// shared folder.
#[cfg(unix)]
#[test]
fn only_this_profiles_socket_files_go() {
    let _windows = ForTests::on();
    let tmp = tempfile::tempdir().unwrap();
    let long = "p".repeat(110);
    let make = |name: &str| {
        let dd = tmp.path().join(name).join(&long);
        std::fs::create_dir_all(&dd).unwrap();
        std::fs::write(dd.join("identity.backend"), b"locked-file\n").unwrap();
        let dd = std::fs::canonicalize(dd).unwrap();
        let socket = crate::ipc::default_socket_path(&dd);
        assert!(!socket.starts_with(&dd), "the fallback: {socket:?}");
        let lock = crate::ipc::instance_lock_path(&socket);
        std::fs::write(&socket, b"").unwrap();
        std::fs::write(&lock, b"").unwrap();
        (dd, socket, lock)
    };
    let (a, a_socket, a_lock) = make("a");
    let (_b, b_socket, b_lock) = make("b");
    std::fs::write(a.join("raven-node.sock.lock"), b"").unwrap();
    let p = plan(&a).unwrap();
    assert_eq!(p.socket_files, [a_socket.clone(), a_lock.clone()]);
    let report = erase(&a);
    assert!(report.finished, "{:?}", report.failures);
    assert!(!a_socket.exists() && !a_lock.exists());
    assert!(!a.join("raven-node.sock.lock").exists());
    assert!(b_socket.exists() && b_lock.exists());
    assert!(
        a_socket.parent().unwrap().is_dir(),
        "the shared folder stays"
    );
    let _ = std::fs::remove_file(b_socket);
    let _ = std::fs::remove_file(b_lock);
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
#[test]
fn the_planned_history_item_is_the_one_the_keystore_holds() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        crate::chat_history::history_key_item(dir.path()).1,
        crate::chat_history::history_account_for_tests(dir.path())
    );
}

// ── Review C-deletion-erase ─────────────────────────────────────────────────

/// The OS keystore as a set of (service, account) generic passwords, for
/// [`plan_with`]'s `platform` items: a delete takes its item out, and the
/// prefix pass every account of the service that starts with the prefix, as
/// the keychain and Secret Service passes do. While `deny_sessions` is set
/// every conversation key that is there is refused (a locked keychain, a
/// denied dialog). Files and folders really go.
#[derive(Default)]
struct FakeKeystore {
    items: std::collections::BTreeSet<(String, String)>,
    deny_sessions: bool,
}

impl FakeKeystore {
    const DENIED: &'static str = "keychain delete failed: User interaction is not allowed (test)";

    fn holding(items: &[(&'static str, String)]) -> Self {
        FakeKeystore {
            items: items
                .iter()
                .map(|(service, account)| ((*service).to_owned(), account.clone()))
                .collect(),
            ..FakeKeystore::default()
        }
    }

    fn matching(&self, service: &str, wanted: impl Fn(&str) -> bool) -> Vec<(String, String)> {
        self.items
            .iter()
            .filter(|(s, a)| s == service && wanted(a))
            .cloned()
            .collect()
    }
}

impl Remover for FakeKeystore {
    fn keystore_item(&mut self, item: &KeystoreItem) -> Result<bool, String> {
        let (role, found) = match item {
            KeystoreItem::Platform {
                role,
                service,
                account,
            } => (*role, self.matching(service, |a| a == account)),
            KeystoreItem::PlatformPrefix {
                role,
                service,
                prefix,
            } => (*role, self.matching(service, |a| a.starts_with(prefix))),
            KeystoreItem::File { path, .. } => return remove_file(path, true),
        };
        if role == KeyRole::Session && self.deny_sessions && !found.is_empty() {
            return Err(Self::DENIED.to_owned());
        }
        for key in &found {
            self.items.remove(key);
        }
        Ok(!found.is_empty())
    }

    fn file(&mut self, path: &Path, overwrite: bool) -> Result<bool, String> {
        remove_file(path, overwrite)
    }

    fn empty_dir(&mut self, path: &Path) -> Result<bool, String> {
        remove_empty_dir(path)
    }
}

/// [`heads`] as a node leaves them that stopped before a checkpoint: the
/// rows only in the store's WAL, so the main file alone names no session.
fn heads_in_the_wal(dd: &Path, keys: &[[u8; 32]]) {
    let name = crate::INDEXED_SESSION_METADATA_FILE;
    let scratch = tempfile::tempdir().unwrap();
    let conn = rusqlite::Connection::open(scratch.path().join(name)).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; \
         CREATE TABLE indexed_session_heads (record_key BLOB PRIMARY KEY)",
    )
    .unwrap();
    for key in keys {
        conn.execute(
            "INSERT INTO indexed_session_heads (record_key) VALUES (?1)",
            [key.as_slice()],
        )
        .unwrap();
    }
    for suffix in ["", "-wal", "-shm"] {
        let file = format!("{name}{suffix}");
        std::fs::copy(scratch.path().join(&file), dd.join(&file)).unwrap();
    }
    drop(conn);
}

/// The conversation keys a plan names one by one.
fn session_accounts(plan: &ErasePlan) -> Vec<String> {
    plan.keystore
        .iter()
        .filter_map(|item| match item {
            KeystoreItem::Platform {
                role: KeyRole::Session,
                account,
                ..
            } => Some(account.clone()),
            _ => None,
        })
        .collect()
}

/// Review C-deletion-erase-1: a run that could not delete a conversation
/// key (a locked keychain, a denied dialog) keeps the session store that
/// names it, with its WAL, so the next run names the same items again; the
/// erase finishes only once they are gone. The namespace pass also takes an
/// item whose head was never recorded, and nothing of another profile.
#[test]
fn a_conversation_key_that_stays_keeps_its_store_for_the_next_run() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    let keys = [[1u8; 32], [2; 32]];
    heads_in_the_wal(&dd, &keys);
    let (service, namespace) = crate::indexed_session_store::erase_namespace(&dd);
    let account = |key: [u8; 32]| format!("{namespace}:{}", hex::encode(key));
    let other = tempfile::tempdir().unwrap();
    let other_item = (
        service,
        format!(
            "{}:{}",
            crate::indexed_session_store::erase_namespace(other.path()).1,
            hex::encode(keys[0])
        ),
    );
    let mut keystore = FakeKeystore::holding(&[
        crate::chat_history::history_key_item(&dd),
        crate::identity_store::keychain_item(&dd),
        (service, account(keys[0])),
        (service, account(keys[1])),
        // A session start that stopped before its head was recorded.
        (service, account([7; 32])),
        crate::prekey_lifecycle::erase_item(&dd),
        other_item.clone(),
    ]);
    begin(&dd).unwrap();
    let first = plan_with(&dd, true).unwrap();
    assert_eq!(
        session_accounts(&first),
        [account(keys[0]), account(keys[1])]
    );
    keystore.deny_sessions = true;
    let report = execute_with(&first, &mut keystore, &mut |_| {});
    assert!(!report.finished, "{report:?}");
    assert!(
        !report.failures.is_empty()
            && report
                .failures
                .iter()
                .all(|f| f.what.contains(FakeKeystore::DENIED)),
        "{report:?}"
    );
    // Crypto-erase went ahead all the same: K_hist, the identity, the
    // prekeys.
    assert!(!key_path(&dd).exists());
    assert_eq!(keystore.items.len(), 4, "{:?}", keystore.items);
    // The store that names the keys left stays, with its WAL (the heads are
    // only there), and the report says so.
    let store = crate::INDEXED_SESSION_METADATA_FILE;
    for suffix in ["", "-wal", "-shm"] {
        assert!(
            dd.join(format!("{store}{suffix}")).exists(),
            "{store}{suffix} went: {report:?}"
        );
    }
    assert!(
        report.still_here().contains(&store.to_owned()),
        "{:?}",
        report.still_here()
    );
    assert!(in_progress(&dd));
    // `raven erase` again: the same accounts, and it finishes once they are
    // gone, with every item of this profile's namespace.
    keystore.deny_sessions = false;
    let second = plan_with(&dd, true).unwrap();
    assert_eq!(session_accounts(&second), session_accounts(&first));
    let report = execute_with(&second, &mut keystore, &mut |_| {});
    assert!(report.finished && report.folder_removed, "{report:?}");
    let mut left = vec![(other_item.0.to_owned(), other_item.1)];
    if !cfg!(any(
        target_os = "macos",
        all(target_os = "linux", target_env = "gnu")
    )) {
        // No namespace pass where no OS keystore holds Raven's keys
        // (Windows plans none of these items outside this test).
        left.push((service.to_owned(), account([7; 32])));
        left.sort();
    }
    assert_eq!(keystore.items.into_iter().collect::<Vec<_>>(), left);
}

/// Review C-deletion-erase-1: a damaged session store names nothing, so the
/// namespace pass looks for the profile's conversation keys (on macOS too
/// since the review). No run says Erased while that pass or the listing
/// fails, and the store stays until a pass got through.
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
#[test]
fn a_damaged_session_store_never_ends_in_erased_while_its_keys_may_stay() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    let store = dd.join(crate::INDEXED_SESSION_METADATA_FILE);
    std::fs::write(&store, vec![0x5a; 8192]).unwrap();
    let (service, namespace) = crate::indexed_session_store::erase_namespace(&dd);
    let mut keystore = FakeKeystore::holding(&[
        (service, format!("{namespace}:{}", hex::encode([1u8; 32]))),
        (service, format!("{namespace}:{}", hex::encode([2u8; 32]))),
    ]);
    begin(&dd).unwrap();
    let first = plan_with(&dd, true).unwrap();
    assert!(
        first.failed_before[0]
            .what
            .starts_with("the conversation keys could not be listed"),
        "{:?}",
        first.failed_before
    );
    assert!(first.keystore.contains(&KeystoreItem::PlatformPrefix {
        role: KeyRole::Session,
        service,
        prefix: format!("{namespace}:"),
    }));
    // The pass fails too (a locked keychain): nothing went, the store stays.
    keystore.deny_sessions = true;
    let report = execute_with(&first, &mut keystore, &mut |_| {});
    assert!(!report.finished && store.exists(), "{report:?}");
    assert_eq!(keystore.items.len(), 2);
    // The pass gets through: both keys go. The listing failed, so this run
    // does not finish either, but the store, which names nothing left, goes.
    keystore.deny_sessions = false;
    let report = execute_with(&plan_with(&dd, true).unwrap(), &mut keystore, &mut |_| {});
    assert!(!report.finished, "{report:?}");
    assert!(keystore.items.is_empty() && !store.exists(), "{report:?}");
    let report = execute_with(&plan_with(&dd, true).unwrap(), &mut keystore, &mut |_| {});
    assert!(report.finished && report.folder_removed, "{report:?}");
}

/// Review C-deletion-erase-2: a `friend_relay` that is a symbolic link is
/// never followed: the relay key in the folder it points to stays byte for
/// byte (a hard link to it is not overwritten either), and the link is left
/// as a file Raven didn't create.
#[cfg(unix)]
#[test]
fn a_linked_friend_relay_folder_is_not_followed() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    let outside = tempfile::tempdir().unwrap();
    let key = outside.path().join("relay_key.ed25519");
    std::fs::write(&key, [0x42; 32]).unwrap();
    let witness = outside.path().join("witness");
    std::fs::hard_link(&key, &witness).unwrap();
    let relay = dd.join("friend_relay");
    std::os::unix::fs::symlink(outside.path(), &relay).unwrap();
    let p = plan(&dd).unwrap();
    assert!(
        p.key_files
            .iter()
            .chain(&p.data_files)
            .all(|path| !path.starts_with(&relay)),
        "{p:?}"
    );
    let report = erase(&dd);
    assert!(report.finished, "{report:?}");
    assert_eq!(std::fs::read(&key).unwrap(), [0x42; 32]);
    assert_eq!(std::fs::read(&witness).unwrap(), [0x42; 32]);
    assert_eq!(report.left_unknown, std::slice::from_ref(&relay));
    assert!(std::fs::symlink_metadata(&relay)
        .unwrap()
        .file_type()
        .is_symlink());
}

/// Review C-deletion-erase-2: a folder swapped for a link after the plan
/// was made is not followed either: what was planned in it is refused and
/// reported, and the next run leaves the link and finishes.
#[cfg(unix)]
#[test]
fn a_link_put_in_place_after_the_plan_is_not_followed() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    let relay = dd.join("friend_relay");
    std::fs::create_dir(&relay).unwrap();
    std::fs::write(relay.join("relay_key.ed25519"), [0x11; 32]).unwrap();
    begin(&dd).unwrap();
    let p = plan(&dd).unwrap();
    assert!(p.key_files.contains(&relay.join("relay_key.ed25519")));
    let outside = tempfile::tempdir().unwrap();
    let key = outside.path().join("relay_key.ed25519");
    std::fs::write(&key, [0x42; 32]).unwrap();
    let witness = outside.path().join("witness");
    std::fs::hard_link(&key, &witness).unwrap();
    let moved = tempfile::tempdir().unwrap();
    std::fs::rename(&relay, moved.path().join("friend_relay")).unwrap();
    std::os::unix::fs::symlink(outside.path(), &relay).unwrap();
    let report = execute(&p, &mut |_| {});
    assert!(!report.finished, "{report:?}");
    assert_eq!(report.still_here(), ["friend_relay/relay_key.ed25519"]);
    assert_eq!(std::fs::read(&key).unwrap(), [0x42; 32]);
    assert_eq!(std::fs::read(&witness).unwrap(), [0x42; 32]);
    let report = execute(&plan(&dd).unwrap(), &mut |_| {});
    assert!(report.finished, "{report:?}");
    assert_eq!(report.left_unknown, std::slice::from_ref(&relay));
    assert_eq!(std::fs::read(&key).unwrap(), [0x42; 32]);
}

/// Review C-deletion-erase-3: the temp file of an interrupted write
/// (`.<name>.tmp.<16 hex>`) in one of Raven's folders is Raven's, as at the
/// top; the temp of a key file is overwritten like the key.
#[test]
fn temp_files_of_interrupted_writes_go_with_ravens_folders() {
    let _windows = ForTests::on();
    let dir = sealed_profile();
    let dd = canonical(&dir);
    std::fs::create_dir(dd.join("friend_relay")).unwrap();
    let temps = [
        "contact_inbox/.00ff.wire.tmp.0123456789abcdef",
        "friend_relay/.relay_status.json.tmp.0123456789abcdef",
        "friend_relay/.relay_key.ed25519.tmp.0123456789abcdef",
        ".device_x25519.secret.tmp.0123456789abcdef",
    ];
    for name in temps {
        std::fs::write(dd.join(name), [0x42; 32]).unwrap();
    }
    let p = plan(&dd).unwrap();
    for name in &temps[..2] {
        assert!(p.data_files.contains(&dd.join(name)), "{name}: {p:?}");
    }
    for name in &temps[2..] {
        assert!(p.key_files.contains(&dd.join(name)), "{name}: {p:?}");
    }
    #[cfg(unix)]
    let witness = {
        let outside = tempfile::tempdir().unwrap();
        let witness = outside.path().join("witness");
        std::fs::hard_link(dd.join(temps[2]), &witness).unwrap();
        (outside, witness)
    };
    let report = erase(&dd);
    assert!(report.finished && report.folder_removed, "{report:?}");
    assert!(report.left_unknown.is_empty(), "{report:?}");
    #[cfg(unix)]
    assert_eq!(std::fs::read(&witness.1).unwrap(), [0; 32]);
}
