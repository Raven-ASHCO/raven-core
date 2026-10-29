//! PP.18 tests of the privacy commands: `raven privacy unseal` writes every
//! sealed file and store back in the forms a build before the pack reads,
//! byte for byte where it read them, can be run again after a crash, keeps
//! the profile plain until `raven privacy seal-now`, and refuses while a node
//! answers; `raven privacy rotate-meta` changes every keyed value and every
//! key; `raven privacy status --json`; `forget-moved-aside`. Profiles are
//! temp folders with an identity marker; keys come from the test build's lab
//! K_hist (never a keychain item).

use super::tests::{arm, kh_row_like_an_epoch_row, Crash};
use super::*;
use crate::app_store::{AppInboxItem, AppStore, PlatformRowSealer};
use crate::chat_history::{
    history_path, load_staged_outbound_body, outbound_body_stage_path, ChatHistory,
    ChatHistoryEntry,
};
use crate::contact_book::tests::{fixture, profile, seal};
use crate::contact_book::CONTACTS_FILE;
use crate::node_policy::{save_policy, NodePolicy, POLICY_FILE, POLICY_PEERS_FILE};
use crate::owed_acks::{Origin, OwedAcks};
use std::collections::BTreeMap;
use std::path::PathBuf;

const T0: u64 = 20_300 * DAY_MS + HOUR_MS;
const LATER: u64 = 1_900_000_000_000;
const RELAY: &str = "/ip4/198.51.100.7/tcp/7423/p2p/12D3KooWExampleRelay";
/// A noise pin row, compact as `lan_noise_pin` writes its file.
const PINS: &str = concat!(
    r#"{"v":2,"pins":[{"c":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","#,
    r#""d":"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"}]}"#
);
const CURSORS: &str = r#"{
  "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0": {
    "received_at_ms": 5,
    "message_id_hex": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
  }
}"#;

fn entry(n: u8) -> ChatHistoryEntry {
    ChatHistoryEntry {
        message_id_hex: hex::encode([n; 16]),
        direction: "out".into(),
        peer_petname: "Bob".into(),
        peer_tag: String::new(),
        peer_pub_hex: hex::encode([0xB0; 32]),
        created_at_ms: T0,
        delivery: "delivered".into(),
        preview: String::new(),
        body: format!("message {n}"),
        stored_at_ms: None,
    }
}

fn app_item(n: u8) -> AppInboxItem {
    AppInboxItem {
        sender_device: [n; 32],
        message_id: [n; 16],
        app_id: [n ^ 0x80; 16],
        sender_identity: [n; 32],
        content_type: "a2a-request/1".into(),
        created_at_ms: T0,
        received_at_ms: T0 + u64::from(n),
        expires_at_ms: LATER,
        cert_json: "{}".into(),
        cert_hash: [0; 32],
        body: format!("task {n}"),
    }
}

/// The plain bytes a registered file of `kind` gets here: a raw secret's 32
/// bytes, JSON naming the file otherwise.
fn plain_bytes(name: &str, kind: Kind) -> Vec<u8> {
    if kind.is_raw_secret() {
        return vec![kind.code(); 32];
    }
    serde_json::to_vec_pretty(&serde_json::json!({ "file": name })).unwrap()
}

/// A plain profile (a build before the pack wrote it) with every file this
/// build seals, the noise pins, relay addresses in the policy, a history,
/// a staged body, an owed ACK, an app row and two session heads.
fn full_profile() -> tempfile::TempDir {
    // A plain profile, whatever `RAVEN_TEST_SEALED_SESSIONS` asks (its lab
    // key would create the session store keyed before the test seals).
    crate::indexed_session_store::test_switch::off();
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    for (name, kind) in MIGRATED {
        if *name == CONTACTS_FILE {
            continue;
        }
        let path = dd.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = if *name == crate::chat_history::CHAT_INBOX_CURSORS_FILE {
            CURSORS.as_bytes().to_vec()
        } else {
            plain_bytes(name, *kind)
        };
        std::fs::write(path, bytes).unwrap();
    }
    let inbox = dd.join(crate::contact_request::CONTACT_INBOX_DIR);
    std::fs::create_dir_all(&inbox).unwrap();
    std::fs::write(inbox.join("req1.wire"), b"a request as it travels").unwrap();
    std::fs::write(dd.join(crate::lan_noise_pin::NOISE_PIN_FILE), PINS).unwrap();
    save_policy(
        dd,
        &NodePolicy {
            p2p_relays: vec![RELAY.to_owned()],
            ..NodePolicy::default()
        },
    )
    .unwrap();
    ChatHistory::append_persisted(dd, entry(1)).unwrap();
    crate::chat_history::stage_outbound_body(
        dd,
        &[0xB0; 32],
        &[2; 32],
        &[3; 32],
        &[4; 16],
        T0,
        "staged",
    )
    .unwrap();
    OwedAcks::open(dd)
        .unwrap()
        .0
        .record(&[5; 32], None, &[6; 32], b"ack", LATER, Origin::Link, T0)
        .unwrap();
    let sealer = PlatformRowSealer::new(dd);
    assert!(AppStore::open(dd, &sealer)
        .unwrap()
        .ingest(&app_item(7))
        .unwrap());
    for (seq, peer) in [(1, [0xB0; 32]), (2, [0xC0; 32])] {
        drop(crate::indexed_session_store::test_rows::insert_head(
            dd, seq, &peer, T0, LATER, true, None,
        ));
    }
    dir
}

/// Every file below `dir` with its bytes, but the lock databases (taken
/// and left by every writer).
fn tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).unwrap().flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                stack.push(path);
            } else if !name.ends_with(".lock.sqlite") {
                out.insert(
                    path.strip_prefix(dir).unwrap().to_path_buf(),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    out
}

/// The JSON and secret files of [`full_profile`] (what an older build reads
/// byte for byte): every file but the SQLite stores, the history, the stage,
/// the settings this build keeps (`privacy.json`) and, on Windows, K_hist's
/// key file (a Keychain item elsewhere: the sealing creates it there, and
/// `raven privacy unseal` keeps it, as it keeps the Keychain item).
fn plain_files_of(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    tree(dir)
        .into_iter()
        .filter(|(path, _)| {
            let name = path.to_string_lossy();
            !(name.contains(".sqlite")
                || name.ends_with(".sqlite3")
                || name.contains("-wal")
                || name.contains("-shm")
                || name == "chat_history.json"
                || name == "outbound_body_stage.bin"
                || name == PRIVACY_FILE
                || name == crate::chat_history::WINDOWS_HISTORY_KEY_FILE)
        })
        .collect()
}

/// Every row of every table of a SQLite store, by column name (its own
/// schema table aside), in rowid order.
fn store_rows(path: &Path) -> BTreeMap<String, Vec<BTreeMap<String, String>>> {
    let conn = rusqlite::Connection::open(path).unwrap();
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table'
                 AND name NOT IN ('raven_schema', 'sqlite_sequence') ORDER BY name",
            )
            .unwrap();
        let names = stmt.query_map([], |r| r.get(0)).unwrap();
        names.collect::<Result<_, _>>().unwrap()
    };
    let mut out = BTreeMap::new();
    for table in tables {
        let mut stmt = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
        let rows = stmt
            .query_map([], |r| {
                let mut row = BTreeMap::new();
                for (at, column) in columns.iter().enumerate() {
                    let value: rusqlite::types::Value = r.get(at)?;
                    row.insert(column.clone(), format!("{value:?}"));
                }
                Ok(row)
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        out.insert(table, rows);
    }
    out
}

/// What the readers of the profile answer (no keystore beyond the lab key).
#[derive(Debug, PartialEq)]
struct Reads {
    book: Vec<serde_json::Value>,
    history: Vec<(String, Option<u64>)>,
    staged: String,
    owed: Vec<crate::owed_acks::OwedAck>,
    app: Vec<AppInboxItem>,
    relays: Vec<String>,
    sessions: BTreeMap<String, Vec<BTreeMap<String, String>>>,
}

fn reads(dd: &Path) -> Reads {
    let sealer = PlatformRowSealer::new(dd);
    let sessions_path = dd.join(crate::indexed_session_store::INDEXED_SESSION_METADATA_FILE);
    Reads {
        book: crate::contact_book::read_rows(dd).unwrap().unwrap(),
        history: ChatHistory::load(dd)
            .unwrap()
            .entries
            .into_iter()
            .map(|e| (e.body, e.stored_at_ms))
            .collect(),
        staged: load_staged_outbound_body(dd, &[4; 16])
            .unwrap()
            .expect("still staged")
            .body,
        owed: OwedAcks::open(dd).unwrap().0.list(T0).unwrap(),
        app: AppStore::open(dd, &sealer)
            .unwrap()
            .page("c", false, 10, T0, &|_| Ok(None))
            .unwrap(),
        relays: crate::node_policy::try_load_policy(dd).unwrap().p2p_relays,
        sessions: if mode(dd) == Mode::Sealed {
            BTreeMap::new()
        } else {
            store_rows(&sessions_path)
        },
    }
}

/// No file below `dir` is sealed (RMS1), and nothing is under the epoch
/// keys: what a build before the pack opens. The app rows by opening each
/// with the chat-history key: their first bytes cannot tell, a K_hist row
/// looks like an epoch row once in 256 (it made the round trip below fail
/// about one run in 128).
fn nothing_sealed(dir: &Path) {
    for (path, bytes) in tree(dir) {
        assert!(!at_rest::is_sealed(&bytes), "{} is sealed", path.display());
    }
    assert!(std::fs::read(history_path(dir))
        .unwrap()
        .starts_with(b"RVNHIST1"));
    assert!(std::fs::read(outbound_body_stage_path(dir))
        .unwrap()
        .starts_with(b"RVNOSTG1"));
    assert!(crate::app_store::rows_open_with_hist_key(dir).unwrap());
    for store in store_versions(dir) {
        assert!(!store.keyed, "{store:?}");
    }
    assert!(!dir.join(META_KEY_FILE).exists());
}

/// Seals every row as the same bytes (a row written as an older build
/// wrote it).
struct SameBytes(Vec<u8>);

impl crate::app_store::RowSealer for SameBytes {
    fn seal(&self, _plaintext: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.0.clone())
    }

    fn open(&self, _sealed: &[u8]) -> Result<Vec<u8>, String> {
        Err("seal only".into())
    }
}

/// [`nothing_sealed`] reads an app row the chat-history key sealed whose
/// random nonce starts like an epoch row's (once in 256) as the older form
/// it is. By its first bytes alone ([`crate::app_store::row_epochs`]) such a
/// row looked sealed: the round trip below failed about one run in 128. On
/// Windows' path no such row exists ([`kh_row_like_an_epoch_row`]): an
/// ordinary one, whose first bytes do not mislead, is checked there.
#[test]
fn nothing_sealed_opens_an_app_row_that_looks_like_an_epoch_row() {
    let dir = full_profile();
    let dd = dir.path();
    let item = app_item(8);
    let plaintext = serde_json::to_vec(&item).unwrap();
    let protector = crate::chat_history::DomainProtector::new(b"raven/app-inbox/v1");
    let lookalike = kh_row_like_an_epoch_row(dd, &protector, &plaintext);
    let misleads = lookalike.is_some();
    let row = lookalike.unwrap_or_else(|| protector.protect(dd, &plaintext).unwrap());
    assert!(AppStore::open(dd, &SameBytes(row))
        .unwrap()
        .ingest(&item)
        .unwrap());
    assert_eq!(
        crate::app_store::row_epochs(dd)
            .unwrap()
            .iter()
            .any(Option::is_some),
        misleads,
        "its first bytes mislead"
    );
    nothing_sealed(dd);
    // A row under the epoch keys does not pass.
    seal(dd);
    assert!(!crate::app_store::rows_open_with_hist_key(dd).unwrap());
}

/// [`nothing_sealed_opens_an_app_row_that_looks_like_an_epoch_row`] on Windows'
/// path (its DPAPI stand-in here; the Windows CI job runs the test itself
/// there).
#[test]
fn nothing_sealed_opens_an_app_row_that_looks_like_an_epoch_row_on_the_windows_path() {
    let _windows = crate::chat_history::windows_key::ForTests::on();
    nothing_sealed_opens_an_app_row_that_looks_like_an_epoch_row();
}

#[test]
fn unseal_then_seal_round_trip_on_every_store_and_file() {
    let dir = full_profile();
    let dd = dir.path();
    let plain = plain_files_of(dd);
    let before = reads(dd);
    let sessions = before.sessions.clone();
    seal(dd);
    // Sealed: the book, every friend file, the stores keyed.
    assert!(at_rest::is_sealed(
        &std::fs::read(dd.join(CONTACTS_FILE)).unwrap()
    ));
    assert!(dd.join(POLICY_PEERS_FILE).exists());
    assert!(!dd.join(crate::lan_noise_pin::NOISE_PIN_FILE).exists());
    let stores = store_versions(dd);
    assert_eq!(stores.len(), 3, "{stores:?}");
    assert!(stores.iter().all(|store| store.keyed), "{stores:?}");
    // A message stored while sealed carries its stored time.
    ChatHistory::append_persisted(dd, entry(2)).unwrap();
    let sealed_reads = reads(dd);
    assert!(sealed_reads.history[1].1.is_some());

    for round in 0..2 {
        let report = unseal_all(dd, &|| true).unwrap();
        assert!(!report.already_plain);
        assert!(
            report.files >= u16::try_from(MIGRATED.len()).unwrap(),
            "{report:?}"
        );
        assert!(report.history && report.stage, "{report:?}");
        assert_eq!(report.app_rows, 1);
        assert_eq!((report.dropped, report.unreadable), (0, 0), "{report:?}");
        assert_eq!(mode(dd), Mode::UnsealedByUser);
        nothing_sealed(dd);
        // The files read back byte for byte as they were before sealing,
        // the pins and the relays under their older names.
        assert_eq!(plain_files_of(dd), plain, "round {round}");
        assert!(!dd.join(POLICY_PEERS_FILE).exists());
        // The stores at the versions this pack started from, every row there.
        let versions: Vec<(&str, i64)> = store_versions(dd)
            .iter()
            .map(|s| (s.file, s.user_version))
            .collect();
        assert_eq!(
            versions,
            [
                ("indexed_sessions.sqlite", 1),
                ("owed_acks.sqlite", 1),
                ("app_channel.sqlite3", 2),
            ]
        );
        let after = reads(dd);
        assert_eq!(after.sessions, sessions);
        assert_eq!(after.book, before.book);
        assert_eq!(after.staged, before.staged);
        assert_eq!((&after.owed, &after.app), (&before.owed, &before.app));
        assert_eq!(after.relays, [RELAY]);
        // Older builds deny unknown fields: no stored time is left.
        assert_eq!(
            after.history,
            [
                ("message 1".to_owned(), None),
                ("message 2".to_owned(), None)
            ]
        );
        // Again: nothing more to do.
        let again = unseal_all(dd, &|| true).unwrap();
        assert_eq!((again.files, again.rows), (0, 0), "{again:?}");
        // And sealed again.
        let sealed = seal_now(dd, T0, MigratePolicy::Allow, None).unwrap();
        assert_eq!(sealed.outcome, MigrateOutcome::Sealed);
        assert!(at_rest::is_sealed(
            &std::fs::read(dd.join(CONTACTS_FILE)).unwrap()
        ));
        assert!(store_versions(dd).iter().all(|store| store.keyed));
        assert!(take_sealing_notice(dd), "a first sealing again: its notice");
        assert!(
            !take_older_build_note(dd),
            "nothing is a downgrade leftover"
        );
        let resealed = reads(dd);
        assert_eq!(
            (&resealed.book, &resealed.owed, &resealed.app),
            (&before.book, &before.owed, &before.app)
        );
    }
}

/// [`unseal_then_seal_round_trip_on_every_store_and_file`] on Windows' path
/// (its DPAPI stand-in here; the Windows CI job runs the test itself there).
#[test]
fn unseal_then_seal_round_trip_on_every_store_and_file_on_the_windows_path() {
    let _windows = crate::chat_history::windows_key::ForTests::on();
    unseal_then_seal_round_trip_on_every_store_and_file();
}

/// Review learning-3: the learning model is never in clear (no clear shape,
/// and no older build reads it), so `raven privacy unseal` deletes it, as
/// it deletes the security ledger: no file of the profile holds its
/// plaintext (`RVNLRN01`, the secret its HMAC keys are under) afterwards.
#[test]
fn unseal_deletes_the_learning_model_and_writes_none_of_it_in_clear() {
    use crate::learning::store::{self, PlatformSealer, LEARNING_FILE, MAGIC};
    let dir = full_profile();
    let dd = dir.path();
    seal(dd);
    let model = crate::learning::model::Model::new_empty([0x5E; 32]);
    store::save(dd, &PlatformSealer, &model, T0).unwrap();
    let file = dd.join(LEARNING_FILE);
    assert!(at_rest::is_sealed_as(
        Kind::LearningStore,
        &std::fs::read(&file).unwrap()
    ));
    let report = unseal_all(dd, &|| true).unwrap();
    assert_eq!((report.dropped, report.unreadable), (0, 0), "{report:?}");
    assert!(!file.exists(), "the learning model went");
    let secret = hex::encode([0x5E; 32]);
    for (path, bytes) in tree(dd) {
        assert!(
            !bytes.starts_with(MAGIC),
            "{} holds the model",
            path.display()
        );
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "{} holds the model's secret",
            path.display()
        );
    }
    nothing_sealed(dd);
    // Again: nothing to do, and still no file.
    unseal_all(dd, &|| true).unwrap();
    assert!(!file.exists());
}

#[test]
fn unseal_is_rerunnable_after_a_crash() {
    for at in [
        Crash::UnsealedFiles,
        Crash::UnsealedStores,
        Crash::UnsealedAll,
    ] {
        let dir = full_profile();
        let dd = dir.path();
        let plain = plain_files_of(dd);
        let before = reads(dd);
        seal(dd);
        arm(at);
        let err = unseal_all(dd, &|| true).unwrap_err();
        assert!(err.to_string().contains("injected crash"), "{at:?}: {err}");
        // Unsealed (no writer seals, nothing seals again), the key kept.
        assert_eq!(mode(dd), Mode::UnsealedByUser, "{at:?}");
        assert!(unseal_unfinished(dd), "{at:?}");
        assert!(report(dd, T0).unseal_unfinished);
        let outcome = migrate_all(dd, T0, MigratePolicy::Allow).unwrap().outcome;
        assert_eq!(outcome, MigrateOutcome::UnsealedByUser);
        // Every reader still reads (both forms are read in every mode).
        assert_eq!(
            crate::contact_book::read_rows::<serde_json::Value>(dd)
                .unwrap()
                .unwrap(),
            before.book
        );
        // A new process finishes it.
        at_rest::forget_cached_keys(dd);
        unseal_all(dd, &|| true).unwrap();
        nothing_sealed(dd);
        assert!(!unseal_unfinished(dd));
        assert_eq!(plain_files_of(dd), plain, "{at:?}");
        assert_eq!(reads(dd).sessions, before.sessions, "{at:?}");
    }
}

/// [`unseal_is_rerunnable_after_a_crash`] on Windows' path (its DPAPI stand-in
/// here; the Windows CI job runs the test itself there).
#[test]
fn unseal_is_rerunnable_after_a_crash_on_the_windows_path() {
    let _windows = crate::chat_history::windows_key::ForTests::on();
    unseal_is_rerunnable_after_a_crash();
}

#[test]
fn unseal_is_sticky_until_seal_now() {
    let dir = full_profile();
    let dd = dir.path();
    seal(dd);
    unseal_all(dd, &|| true).unwrap();
    let book = std::fs::read(dd.join(CONTACTS_FILE)).unwrap();
    // No migration pass seals it again (a node's start, any command), and no
    // key file is created.
    for _ in 0..2 {
        let report = migrate_all(dd, T0, MigratePolicy::Allow).unwrap();
        assert_eq!(report.outcome, MigrateOutcome::UnsealedByUser);
    }
    assert!(matches!(
        at_rest::keys_load_with(dd, MigratePolicy::Allow),
        Err(AtRestError::NotSealedMode)
    ));
    assert!(!dd.join(META_KEY_FILE).exists());
    assert_eq!(std::fs::read(dd.join(CONTACTS_FILE)).unwrap(), book);
    // Writers write plain: a book change, a new message.
    let rows = crate::contact_book::read_rows::<serde_json::Value>(dd)
        .unwrap()
        .unwrap();
    crate::contact_book::write_rows(dd, &rows).unwrap();
    assert!(!at_rest::is_sealed(
        &std::fs::read(dd.join(CONTACTS_FILE)).unwrap()
    ));
    ChatHistory::append_persisted(dd, entry(3)).unwrap();
    assert!(std::fs::read(history_path(dd))
        .unwrap()
        .starts_with(b"RVNHIST1"));
    assert!(ChatHistory::load(dd)
        .unwrap()
        .entries
        .iter()
        .all(|e| e.stored_at_ms.is_none()));
    assert_eq!(
        rotate_data_key_now(dd, T0, true).unwrap(),
        RotationReport::default()
    );
    assert_eq!(report(dd, T0).status.state(), STATE_UNSEALED_BY_USER);
    // A build that does not seal changes nothing; one that does seals it.
    assert_eq!(
        seal_now(dd, T0, MigratePolicy::Never, None).unwrap_err(),
        SEAL_NOT_ALLOWED_TEXT
    );
    assert_eq!(mode(dd), Mode::UnsealedByUser);
    // An older raven-node answers: nothing changes either.
    let older = || true;
    let held = seal_now(dd, T0, MigratePolicy::Allow, Some(&older)).unwrap();
    assert_eq!(held.outcome, MigrateOutcome::OlderNodeRunning);
    assert_eq!(mode(dd), Mode::UnsealedByUser);
    let sealed = seal_now(dd, T0, MigratePolicy::Allow, None).unwrap();
    assert_eq!(sealed.outcome, MigrateOutcome::Sealed);
    assert_eq!(mode(dd), Mode::Sealed);
    assert!(at_rest::is_sealed(
        &std::fs::read(dd.join(CONTACTS_FILE)).unwrap()
    ));
    assert_eq!(report(dd, T0).status.state(), STATE_SEALED);
}

#[test]
fn unseal_refuses_while_a_node_it_cannot_stop_answers() {
    let dir = full_profile();
    let dd = dir.path();
    seal(dd);
    let before = tree(dd);
    let err = unseal_all(dd, &|| false).unwrap_err();
    assert_eq!(err, CommandError::NodeRunning);
    assert_eq!(tree(dd), before, "nothing changed");
    assert_eq!(mode(dd), Mode::Sealed);
    // rotate-meta refuses the same way.
    assert_eq!(
        rotate_meta(dd, T0, &|| false).unwrap_err(),
        CommandError::NodeRunning
    );
    assert_eq!(tree(dd), before, "nothing changed");
    // A plain profile: nothing to write back, but not while a node runs.
    let plain = profile();
    assert_eq!(
        unseal_all(plain.path(), &|| false).unwrap_err(),
        CommandError::NodeRunning
    );
    assert_eq!(mode(plain.path()), Mode::Plain);
    let done = unseal_all(plain.path(), &|| true).unwrap();
    assert!(done.already_plain);
    assert_eq!(mode(plain.path()), Mode::UnsealedByUser);
    // An unfinished erase closes the profile to it.
    crate::erase::begin(dd).unwrap();
    assert!(matches!(
        unseal_all(dd, &|| true),
        Err(CommandError::Failed(text)) if text == crate::erase::UNFINISHED_TEXT
    ));
}

#[test]
fn unseal_strips_stored_at_and_restores_rvnhist1() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    ChatHistory::append_persisted(dd, entry(1)).unwrap();
    seal(dd);
    ChatHistory::append_persisted(dd, entry(2)).unwrap();
    let raw = std::fs::read(history_path(dd)).unwrap();
    assert!(raw.starts_with(b"RVNHIST2"));
    let stamped: Vec<Option<u64>> = ChatHistory::load(dd)
        .unwrap()
        .entries
        .iter()
        .map(|e| e.stored_at_ms)
        .collect();
    assert!(stamped[0].is_none() && stamped[1].is_some(), "{stamped:?}");
    let report = unseal_all(dd, &|| true).unwrap();
    assert!(report.history);
    assert!(std::fs::read(history_path(dd))
        .unwrap()
        .starts_with(b"RVNHIST1"));
    // The plaintext an older build parses (it denies unknown fields): read
    // with K_hist directly, no field it does not know.
    let plain = ChatHistory::load(dd).unwrap();
    assert_eq!(plain.entries.len(), 2);
    let json = serde_json::to_string(&plain).unwrap();
    assert!(!json.contains("stored_at_ms"), "{json}");
    // A later save in this profile (not sealed) writes no stored time either.
    ChatHistory::append_persisted(dd, entry(3)).unwrap();
    assert!(ChatHistory::load(dd)
        .unwrap()
        .entries
        .iter()
        .all(|e| e.stored_at_ms.is_none()));
}

#[test]
fn rotate_meta_changes_every_kh_and_keeps_every_lookup() {
    let dir = full_profile();
    let dd = dir.path();
    seal(dd);
    ChatHistory::append_persisted(dd, entry(2)).unwrap();
    let before = reads(dd);
    let key_file = std::fs::read(dd.join(META_KEY_FILE)).unwrap();
    let old = at_rest::keys_cached(dd).unwrap();
    let owed_path = crate::owed_acks::owed_acks_path(dd);
    let digests = |path: &Path| -> Vec<Vec<u8>> {
        let conn = rusqlite::Connection::open(path).unwrap();
        let mut stmt = conn
            .prepare("SELECT kh_ack_digest FROM owed_acks_v1 ORDER BY rowid")
            .unwrap();
        let rows = stmt.query_map([], |r| r.get(0)).unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    };
    let old_digests = digests(&owed_path);
    // A friend's keyed send-lock file, held by nobody.
    let bob: [u8; 32] = hex::decode(
        crate::contact_book::read_rows::<serde_json::Value>(dd)
            .unwrap()
            .unwrap()[0]["pub_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let old_lock = at_rest::lock_name(&old, &bob);
    drop(DataDirLock::acquire(dd, &old_lock).unwrap());
    let report = rotate_meta(dd, T0, &|| true).unwrap();
    assert!(!report.resumed);
    assert!(report.rows >= 4, "{report:?}");
    assert_eq!(report.dropped, 0);
    assert!(report.resealed >= 3, "{report:?}");
    assert_eq!(report.lock_files, 1);
    let new = at_rest::keys_cached(dd).unwrap();
    // One epoch, a new one; a new k_index: every keyed value and lock name
    // changes, every lookup still finds its row.
    assert_eq!(new.epochs(), [report.epoch]);
    assert!(!old.epochs().contains(&report.epoch));
    assert_ne!(std::fs::read(dd.join(META_KEY_FILE)).unwrap(), key_file);
    let new_digests = digests(&owed_path);
    assert_eq!(new_digests.len(), old_digests.len());
    assert!(new_digests.iter().all(|d| !old_digests.contains(d)));
    assert_eq!(
        at_rest::index(&new, at_rest::ValueType::ObjectDigest, &[6; 32]).to_vec(),
        new_digests[0]
    );
    let new_lock = at_rest::lock_name(&new, &bob);
    assert_ne!(new_lock, old_lock);
    assert!(!dd.join(&old_lock).exists() && dd.join(&new_lock).exists());
    assert_eq!(rotation_state(dd).old_objects, 0);
    assert!(!meta_rotation_unfinished(dd));
    let after = reads(dd);
    assert_eq!(after, before);
    // Data sealed before no longer opens: the old epochs are gone.
    assert!(at_rest::open(
        &new,
        Kind::Contacts,
        &at_rest::seal(&old, Kind::Contacts, b"x")
    )
    .is_err());
    // The way back still works from here.
    unseal_all(dd, &|| true).unwrap();
    nothing_sealed(dd);
}

#[test]
fn rotate_meta_after_a_crash_closes_the_profile_and_is_finished_by_running_it_again() {
    for at in [
        Crash::MetaRotationRecorded,
        Crash::MetaKeyChanged,
        Crash::MetaStoreRekeyed,
    ] {
        let dir = full_profile();
        let dd = dir.path();
        seal(dd);
        let before = reads(dd);
        arm(at);
        assert!(rotate_meta(dd, T0, &|| true).is_err(), "{at:?}");
        assert!(meta_rotation_unfinished(dd), "{at:?}");
        assert_eq!(
            refuse_if_meta_rotation_unfinished(dd).unwrap_err(),
            META_ROTATION_UNFINISHED_TEXT
        );
        assert!(report(dd, T0).meta_rotation_unfinished);
        // The data-key rotation leaves it to this command.
        assert_eq!(
            rotate_data_key_now(dd, T0, true).unwrap(),
            RotationReport::default()
        );
        let again = rotate_meta(dd, T0, &|| true).unwrap();
        assert!(again.resumed, "{at:?}");
        assert!(!meta_rotation_unfinished(dd));
        assert_eq!(at_rest::keys_cached(dd).unwrap().epochs().len(), 1);
        assert_eq!(reads(dd), before, "{at:?}");
    }
    // Unsealing finishes an interrupted key change too.
    let dir = full_profile();
    let dd = dir.path();
    seal(dd);
    let before = reads(dd);
    arm(Crash::MetaStoreRekeyed);
    assert!(rotate_meta(dd, T0, &|| true).is_err());
    unseal_all(dd, &|| true).unwrap();
    nothing_sealed(dd);
    assert!(!meta_rotation_unfinished(dd));
    let after = reads(dd);
    assert_eq!(
        (after.book, after.owed, after.app),
        (before.book, before.owed, before.app)
    );
    // A profile that is not sealed has no keys to change.
    let plain = profile();
    assert_eq!(
        rotate_meta(plain.path(), T0, &|| true).unwrap_err(),
        CommandError::Failed(NOT_SEALED_TEXT.to_owned())
    );
}

/// Review B-sealed-stores-3: an unseal that stopped during an unfinished key
/// change (the mode already says unsealed) is finished by unsealing again:
/// the refusal names that command. It named `raven privacy rotate-meta`,
/// which refuses a profile that is not encrypted: only erase was left.
#[test]
fn an_unseal_that_stopped_during_a_key_change_points_to_unseal() {
    let dir = full_profile();
    let dd = dir.path();
    seal(dd);
    arm(Crash::MetaStoreRekeyed);
    assert!(rotate_meta(dd, T0, &|| true).is_err());
    arm(Crash::UnsealedFiles);
    assert!(unseal_all(dd, &|| true).is_err());
    assert_eq!(mode(dd), Mode::UnsealedByUser);
    assert!(unseal_unfinished(dd));
    assert!(!meta_rotation_unfinished(dd));
    assert!(!report(dd, T0).meta_rotation_unfinished);
    assert_eq!(
        refuse_if_meta_rotation_unfinished(dd).unwrap_err(),
        UNSEAL_UNFINISHED_TEXT
    );
    assert_eq!(
        rotate_meta(dd, T0, &|| true).unwrap_err(),
        CommandError::Failed(NOT_SEALED_TEXT.to_owned())
    );
    unseal_all(dd, &|| true).unwrap();
    refuse_if_meta_rotation_unfinished(dd).unwrap();
    nothing_sealed(dd);
}

/// Review E-harness-docs-ci-8: the app store's keyed schema (3) keys only
/// its sender columns, and its outbox and pairing budget keep the friend's
/// key and device in clear (only the app channel writes them, gated off in
/// release). A sealed profile whose app store holds such a row (a lab
/// build's app channel wrote it) does not call that store keyed, and the
/// JSON names the table; once they are empty it is keyed again.
#[test]
fn an_app_store_with_rows_in_its_clear_tables_is_not_keyed() {
    let dir = full_profile();
    let dd = dir.path();
    seal(dd);
    let app = |dd: &Path| {
        store_versions(dd)
            .into_iter()
            .find(|s| s.file == crate::app_store::APP_STORE_FILE)
            .unwrap()
    };
    let sealed = app(dd);
    assert_eq!((sealed.user_version, sealed.keyed), (3, true), "{sealed:?}");
    assert!(sealed.clear_tables.is_empty());
    let conn = rusqlite::Connection::open(dd.join(crate::app_store::APP_STORE_FILE)).unwrap();
    conn.execute(
        "INSERT INTO app_outbox(peer_identity, client_ref, peer_device, content_type, app_id,
           body_sha256, message_id, session_id, object_digest, created_at_ms, expires_at_ms,
           state, attempt_seq, updated_at_ms)
         VALUES (?1, 'r1', ?2, 'a2a-request/1', ?3, ?4, ?5, ?6, ?7, 1, ?8, 'queued', 0, 1)",
        rusqlite::params![
            vec![0xB0u8; 32],
            vec![0xB1u8; 32],
            vec![0xA1u8; 16],
            vec![0xA2u8; 32],
            vec![0xA3u8; 16],
            vec![0xA4u8; 16],
            vec![0xA5u8; 32],
            i64::try_from(LATER).unwrap(),
        ],
    )
    .unwrap();
    let outbox = app(dd);
    assert!(!outbox.keyed, "{outbox:?}");
    assert_eq!(outbox.clear_tables, ["app_outbox"]);
    let json = report(dd, T0).to_json();
    let entry = json["stores"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["file"] == crate::app_store::APP_STORE_FILE)
        .unwrap()
        .clone();
    assert_eq!(
        entry,
        serde_json::json!({
            "file": crate::app_store::APP_STORE_FILE,
            "user_version": 3,
            "keyed": false,
            "clear_tables": ["app_outbox"]
        })
    );
    conn.execute(
        "INSERT INTO app_pair_attempts(peer_device, at_ms) VALUES (?1, 1)",
        [vec![0xB1u8; 32]],
    )
    .unwrap();
    assert_eq!(app(dd).clear_tables, ["app_outbox", "app_pair_attempts"]);
    conn.execute_batch("DELETE FROM app_outbox; DELETE FROM app_pair_attempts;")
        .unwrap();
    assert!(app(dd).keyed);
}

#[test]
fn status_json_schema() {
    let dir = full_profile();
    let dd = dir.path();
    let moved = dd.join("chat_history.json.untrusted-plaintext.0123456789abcdef");
    std::fs::write(&moved, b"{\"entries\":[]}").unwrap();
    let plain = report(dd, T0).to_json();
    assert_eq!(plain["v"], 1);
    assert_eq!(plain["mode"], "plain");
    assert_eq!(plain["state"], STATE_PLAIN);
    assert!(plain["files"]["sealed"].as_array().unwrap().is_empty());
    assert!(plain["files"]["plain"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!(CONTACTS_FILE)));
    assert_eq!(
        plain["moved_aside"],
        serde_json::json!(["chat_history.json.untrusted-plaintext.0123456789abcdef"])
    );
    seal(dd);
    let sealed = report(dd, T0).to_json();
    let keys: Vec<&str> = sealed
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "addresses",
            "chats",
            "files",
            "mode",
            "moved_aside",
            "notes",
            "rotation",
            "scrub_pending",
            "set_aside_stores",
            "state",
            "stores",
            "unfinished",
            "v"
        ]
    );
    assert_eq!(sealed["mode"], "sealed");
    assert_eq!(sealed["state"], STATE_SEALED);
    assert!(sealed["files"]["plain"].as_array().unwrap().is_empty());
    assert!(sealed["files"]["sealed"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!(POLICY_PEERS_FILE)));
    assert_eq!(sealed["chats"]["keep"], "30d");
    assert_eq!(sealed["addresses"]["forget_after_days"], 30);
    assert_eq!(
        sealed["stores"][0],
        serde_json::json!({
            "file": "indexed_sessions.sqlite",
            "user_version": 4,
            "keyed": true,
            "clear_tables": []
        })
    );
    assert_eq!(
        sealed["unfinished"],
        serde_json::json!({"unseal": false, "rotate_meta": false})
    );
    assert_eq!(sealed["rotation"]["old_epoch_held"], false);
    // No friend's key, name or address anywhere in it.
    let text = sealed.to_string();
    for needle in ["Bob", "192.168.", RELAY, &hex::encode([0xB0; 32])] {
        assert!(!text.contains(needle), "{needle} in {text}");
    }
    assert!(!text.contains(POLICY_FILE) || text.contains("node_policy_peers"));
    unseal_all(dd, &|| true).unwrap();
    assert_eq!(report(dd, T0).to_json()["mode"], "unsealed_by_user");
}

#[test]
fn forget_moved_aside_overwrites_and_deletes_only_those_copies() {
    let dir = profile();
    let dd = dir.path();
    let copies = [
        "chat_history.json.untrusted-plaintext.0000000000000001",
        "chat_history.json.untrusted-plaintext.0000000000000002",
    ];
    for name in copies {
        std::fs::write(dd.join(name), b"{\"entries\":[]}").unwrap();
    }
    std::fs::write(dd.join("chat_history.json"), b"RVNHIST1 kept").unwrap();
    assert_eq!(moved_aside_files(dd).len(), 2);
    assert_eq!(forget_moved_aside(dd).unwrap(), 2);
    assert!(moved_aside_files(dd).is_empty());
    assert!(dd.join("chat_history.json").exists());
    assert_eq!(forget_moved_aside(dd).unwrap(), 0);
}

#[test]
fn stores_report_the_schema_of_each_mode() {
    // The table of STORES against what the stores write: keyed in a sealed
    // profile, the pre-pack version once unsealed (friend custody's own
    // suite moves its store both ways).
    let dir = full_profile();
    let dd = dir.path();
    let versions = |dd: &Path| -> Vec<(&'static str, i64, bool)> {
        store_versions(dd)
            .into_iter()
            .map(|s| (s.file, s.user_version, s.keyed))
            .collect()
    };
    assert_eq!(
        versions(dd),
        [
            ("indexed_sessions.sqlite", 1, false),
            ("owed_acks.sqlite", 1, false),
            ("app_channel.sqlite3", 2, false),
        ]
    );
    seal(dd);
    // Each store's header after its WAL is checkpointed by the scrub.
    assert_eq!(
        versions(dd),
        [
            ("indexed_sessions.sqlite", 4, true),
            ("owed_acks.sqlite", 2, true),
            ("app_channel.sqlite3", 3, true),
        ]
    );
}

/// Review A-keys-format-3: a data-key rotation pass that runs after
/// `raven privacy rotate-meta` read the keys but before it took the at-rest
/// lock (another ash process's prune with a rotation due, or `raven privacy
/// rotate-now`) makes the next epoch current. rotate-meta then still gives
/// the profile a new `k_index` and an epoch of its own: every keyed lookup
/// and lock name changes, and only that epoch is left.
#[test]
fn rotate_meta_changes_k_index_after_a_data_key_rotation_in_its_window() {
    let probe = [0x42u8; 32];
    for scheduled in [true, false] {
        let dir = full_profile();
        let dd = dir.path();
        seal(dd);
        if scheduled {
            mark_rotation_due(dd).unwrap();
        }
        let old = at_rest::keys_cached(dd).unwrap();
        assert_eq!(old.epochs(), [1]);
        let old_lock = at_rest::lock_name(&old, &probe);
        let old_index = at_rest::index(&old, at_rest::ValueType::DeviceKey, &probe);
        let before = reads(dd);
        // The window between the keys read and the at-rest lock.
        let node_gone = || {
            let pass = if scheduled {
                rotate_data_key(dd, T0).unwrap()
            } else {
                rotate_data_key_now(dd, T0, false).unwrap()
            };
            assert!(pass.started, "{pass}");
            assert_eq!(at_rest::keys_cached(dd).unwrap().epochs(), [1, 2]);
            true
        };
        let report = rotate_meta(dd, T0, &node_gone).unwrap();
        let new = at_rest::keys_cached(dd).unwrap();
        assert_eq!(report.epoch, 3, "scheduled {scheduled}: {report:?}");
        assert_eq!(new.epochs(), [3]);
        assert_ne!(at_rest::lock_name(&new, &probe), old_lock);
        assert_ne!(
            at_rest::index(&new, at_rest::ValueType::DeviceKey, &probe),
            old_index
        );
        assert!(!meta_rotation_unfinished(dd));
        assert_eq!(rotation_state(dd).old_objects, 0);
        assert_eq!(reads(dd), before, "scheduled {scheduled}");
    }
}
