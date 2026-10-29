//! The update harness (Phase 6b P6.51; design D's testing,
//! `protocol/RAVEN_UPDATE_EXCHANGE_V1.md`): real `raven-node service`
//! daemons pass security notices, the release log and a release to each
//! other over RUP1, and the CLI imports, refuses, stages and installs. The
//! in-process fixture of raven-node's `update_exchange::tests` holds the
//! same rules without processes; these cases run them over real links.
//!
//! Every profile here runs with the update gates' debug switches
//! (`RAVEN_LAB_ADVISORY=1`, `RAVEN_LAB_RELEASE_BUNDLE=1`,
//! `RAVEN_LAB_MESH_UPDATE=1`, Lab Test A), the published 2-of-3 test key
//! set as its release key set (`RAVEN_LAB_RELEASE_KEYS_FILE`, written into
//! the test's root) and the security events' switch
//! (`RAVEN_LAB_SECURITY_EVENTS=1`), so every refusal is asserted by its
//! event kind in the profile's own ledger, read without its keys
//! (`security_ledger::rows_on_disk`). The notices, logs and releases are
//! built here with raven-core's own builders and the published test keys
//! (debug builds only), as the release tool builds them.
//!
//! - **C88 forged, rolled-back and equivocating notices over RUP1; a split
//!   view between two friends.** A imports notice #2 (one log lists #1, #2
//!   and another #2); B gets it from A and C from B with no command (each
//!   SEC_ADVISORY_APPLIED). F holds #1 and runs the lab switch
//!   `RAVEN_LAB_UPDATE_CLAIM_NEWER=1` (its HAVE claims #2 with #1's
//!   digest; its own route to B is dead, so it never catches up): B asks
//!   and refuses what comes as a rollback (SEC_ADVISORY_ROLLBACK), keeping
//!   #2, unfrozen, nothing quarantined. F's stored #1 is then changed on its
//!   disk (one signature byte): B refuses it as forged (SEC_ADVISORY_FORGED)
//!   and quarantines it. D holds the other #2: B freezes
//!   (SEC_ADVISORY_EQUIVOCATION). E holds a second signed log of the same
//!   size that differs: C, which has B's log, freezes on the split view
//!   (SEC_LOG_SPLIT_VIEW); A is never frozen. `raven security --json`
//!   shows the forged notice, the equivocation and the split view, and
//!   counts the rollback.
//! - **C89 bad releases refused; a good one passed A -> B -> C, staged and
//!   installed into a temp prefix** (Unix: the release's raven-node is a
//!   shell script that runs this build's). C refuses an unsigned release,
//!   a forged payload and an unlogged release from files
//!   (SEC_BUNDLE_FORGED, SEC_UPDATE_UNLOGGED) and stages none. Three
//!   friends offer an unsigned, a forged-signature and an unlogged release
//!   over RUP1 (each written into its staged folder on its disk, as a
//!   modified build would offer it): B lists them, fetches nothing until
//!   each is approved (`raven update download CODE` with the lab approval),
//!   then refuses each manifest (the same kinds; the unlogged one said to
//!   be listed in no log B has, not to have failed its checks) and keeps
//!   none. A imports
//!   the good release (build 5): B is offered it and waits; after the
//!   approval it downloads it from A and offers it to C, which waits too,
//!   downloads it after its own approval, and installs it with `raven
//!   update install` run from a copy of this build's `raven` in a temp
//!   prefix (the lab switch types the word): the old raven-node is kept as
//!   `raven-node.prev`, the new one has mode 755 and answers, `raven update
//!   status` names build 5. An older release (build 3) is then refused as a
//!   downgrade (SEC_BUNDLE_DOWNGRADE). The node the install started is
//!   stopped by its pid at the end.
//!
//! The privacy pack's C87 runs again with every Phase 6 switch on
//! ([`phase6_profile`], [`exercise_updates`]): the Phase 6 files (update
//! state, downloads and incoming releases, the security ledger, the
//! capability floor) must not bring back plaintext friend metadata.

use raven_core::advisory::{Advisory, AdvisoryDraft};
use raven_core::at_rest::Kind;
use raven_core::release_bundle::{FileMode, Manifest, ManifestDraft, PackFile, Parts, THIS_TARGET};
use raven_core::release_keys::test_keys::{key_set, signer, signers};
use raven_core::release_keys::SigBlock;
use raven_core::release_sign::sha256;
use raven_core::security_events::SecKind;
use raven_core::tlog::{EntryType, LogEntry, Snapshot, SthDraft};
use raven_core::update_state::{staged_file_name, STAGED_DIR, STAGED_MANIFEST, STAGED_SNAPSHOT};
use raven_core::Identity;

use super::*;

const T0: u64 = 1_792_800_000_000;
const DAY_MS: u64 = 86_400_000;
/// How long a refusal or a fetch may take to show (a link, a follow-up dial,
/// the ledger's writer).
const UPDATE_WAIT: Duration = Duration::from_secs(60);
/// How long a case watches that nothing is fetched before an approval.
const NOTHING_WAIT: Duration = Duration::from_secs(4);
const AUTO_APPROVE: (&str, &str) = ("RAVEN_LAB_UPDATE_AUTO_APPROVE", "1");

/// The Raven project as these cases publish it, with the published test
/// keys: one log that starts with the key set; tree heads signed by keys 0
/// and 1, notices by 0 and 2, releases by whom a case says.
#[derive(Clone)]
struct TestProject {
    log: Vec<LogEntry>,
}

impl TestProject {
    fn new() -> Self {
        TestProject {
            log: vec![LogEntry {
                kind: EntryType::KeySet,
                digest: key_set().digest(),
                logged_at_ms: T0,
            }],
        }
    }

    /// `digest` as the next entry of the log.
    fn list(&mut self, kind: EntryType, digest: [u8; 32]) {
        let at = self.log.len() as u64;
        self.log.push(LogEntry {
            kind,
            digest,
            logged_at_ms: T0 + at * DAY_MS,
        });
    }

    /// The whole log with its signed tree head.
    fn snapshot(&self) -> Snapshot {
        let [a, b, _] = signers();
        let sth = SthDraft::of_entries(
            &self.log,
            T0 + self.log.len() as u64 * DAY_MS,
            key_set().digest(),
        )
        .sign(&[(0, &a), (1, &b)])
        .unwrap();
        Snapshot::new(self.log.clone(), sth).unwrap()
    }

    /// Notice `serial`, issued on `day`, naming `prev` before it (not
    /// listed yet).
    fn advisory(&self, serial: u64, day: u64, prev: [u8; 32]) -> Advisory {
        let [a, _, c] = signers();
        AdvisoryDraft {
            serial,
            issued_at_ms: T0 + day * DAY_MS,
            key_set_digest: key_set().digest(),
            prev_digest: prev,
            entries: Vec::new(),
        }
        .sign(&[(0, &a), (2, &c)])
        .unwrap()
    }

    /// A release for this computer (not listed yet): `bin/raven-node` is
    /// `program`, with a short document; signed by `sig`, or carrying no
    /// signature at all. The manifest and its payload.
    fn release(
        &self,
        serial: u64,
        program: &[u8],
        sig: Option<&[(u8, &Identity)]>,
    ) -> (Manifest, Vec<u8>) {
        let docs = format!("Raven 1.{serial}.0, a release of the update harness.\n").into_bytes();
        let mut draft = ManifestDraft {
            build_serial: serial,
            created_at_ms: T0 + serial * DAY_MS,
            key_set_digest: key_set().digest(),
            version: format!("1.{serial}.0"),
            target: THIS_TARGET.to_owned(),
            source_commit: [0xC8; 20],
            toolchain: "1.98.0".to_owned(),
            min_advisory_serial: 0,
            chunk_size: 0,
            payload_len: 0,
            payload_chunk_root: [0; 32],
            payload_sha256: [0; 32],
            files: Vec::new(),
            notes: format!("Release {serial} of the update harness."),
        };
        let files = [
            ("bin/raven-node", FileMode::Executable, program),
            ("docs/README.txt", FileMode::Regular, &docs[..]),
        ];
        let pack: Vec<PackFile<'_>> = files
            .iter()
            .map(|(path, mode, bytes)| PackFile {
                path,
                mode: *mode,
                bytes,
                rebuild_sha256: sha256(bytes),
            })
            .collect();
        let payload = draft.fill_payload(&pack);
        let manifest = match sig {
            Some(signers) => draft.sign(signers).unwrap(),
            None => draft.assemble(&SigBlock::default()).unwrap(),
        };
        (manifest, payload)
    }
}

/// The published test key set as a lab key file in `root`
/// (`RAVEN_LAB_RELEASE_KEYS_FILE`: the set's hex on one line).
pub(super) fn test_key_set_file(root: &Path) -> PathBuf {
    let path = root.join("release-keys.hex");
    std::fs::write(&path, format!("{}\n", hex::encode(key_set().encode()))).unwrap();
    path
}

/// `bytes` as the file `name` in `root`.
fn put(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn text(path: &Path) -> &str {
    path.to_str().expect("a test path is UTF-8")
}

/// A new profile for the update cases: Lab Test A, the three update gates'
/// switches, the security events' switch and the test key set `keys`.
fn update_profile(root: &Path, name: &'static str, keys: &Path) -> Profile {
    Profile::create_with(root, name, true)
        .with_lab_env("RAVEN_LAB_ADVISORY", "1")
        .with_lab_env("RAVEN_LAB_RELEASE_BUNDLE", "1")
        .with_lab_env("RAVEN_LAB_MESH_UPDATE", "1")
        .with_lab_env("RAVEN_LAB_SECURITY_EVENTS", "1")
        .with_lab_env("RAVEN_LAB_RELEASE_KEYS_FILE", text(keys))
}

/// `p` with every Phase 6 lab switch on (C87's second run): Lab Test A,
/// learning (6a), every 6b gate's switch that this build has (sensing and
/// responses, the suite floor, link padding, the knock, the random port,
/// pair seeds, Lock now v2, the three update gates), the lab approval of
/// downloads, and the test key set `keys`.
pub(super) fn phase6_profile(mut p: Profile, keys: &Path) -> Profile {
    p.lab_internet = true;
    for k in [
        "RAVEN_LAB_LEARNING",
        "RAVEN_LAB_SECURITY_EVENTS",
        "RAVEN_LAB_SECURITY_RESPONSES",
        "RAVEN_LAB_SUITE_FLOOR",
        "RAVEN_LAB_LINK_PADDING",
        "RAVEN_LAB_LINK_KNOCK",
        "RAVEN_LAB_RANDOM_PORT",
        "RAVEN_LAB_PAIR_SEED",
        "RAVEN_LAB_LOCAL_PROTECTION",
        "RAVEN_LAB_ADVISORY",
        "RAVEN_LAB_RELEASE_BUNDLE",
        "RAVEN_LAB_MESH_UPDATE",
        AUTO_APPROVE.0,
    ] {
        p = p.with_lab_env(k, "1");
    }
    p.with_lab_env("RAVEN_LAB_RELEASE_KEYS_FILE", text(keys))
}

/// C87's second run: A imports a notice and a release (build 5) from files,
/// and B, whose contact A is `a_tag`, messages A over LAN (a link that
/// carries RUP1), takes the notice and downloads the release from A by
/// itself (the lab approval), so both profiles hold the Phase 6 update
/// files: the update state, the downloads list (which names the friend
/// that offered), the incoming release, the security ledger, the capability
/// floor of a verified contact and (lane 6b's P6.38, live here with route
/// hints) the pair seeds their RRH1 frames agreed.
pub(super) fn exercise_updates(a: &Profile, b: &Profile, a_tag: &str, b_svc: &Service) {
    let root = a.root.clone();
    let mut project = TestProject::new();
    let notice = project.advisory(1, 1, [0; 32]);
    project.list(EntryType::Advisory, notice.digest());
    let [k0, k1, _] = signers();
    let (manifest, payload) =
        project.release(5, b"#!/bin/sh\nexit 0\n", Some(&[(0, &k0), (1, &k1)]));
    project.list(EntryType::Manifest, manifest.digest());
    let snapshot = project.snapshot();
    let log = put(&root, "c87-log.rtl1", &snapshot.encode());
    let notice_file = put(&root, "c87-notice.rad1", notice.bytes());
    let bundle = put(
        &root,
        "c87-release.rrb",
        &Parts {
            manifest: manifest.clone(),
            snapshot,
            advisory: None,
            payload,
        }
        .encode(),
    );
    for (file, log) in [(&notice_file, Some(log.as_path())), (&bundle, None)] {
        let out = import(a, file, log);
        assert!(out.ok, "C87: {} import:\n{}", a.name, out.all());
    }
    assert_delivered("C87 b→a", &link_by_message(b, a_tag));
    assert!(
        wait_until(UPDATE_WAIT, || {
            let u = updates_of(b);
            u["advisory_serial"].as_u64() == Some(1) && u["ready"].as_u64() == Some(1)
        }),
        "C87: B took no notice or release from A ({}):\n{}",
        updates_of(b),
        b_svc.log.text()
    );
    // The Phase 6 files the scan then reads: the update state, the security
    // ledger, the capability floor and the pair seeds of each, B's downloads
    // list (it names A as the friend that offered) and its incoming release.
    // The pair seeds ride the RRH1 frames of the links so far (a leader's
    // proposal, the follower's ack).
    assert!(
        wait_until(UPDATE_WAIT, || {
            [a, b]
                .iter()
                .all(|p| p.dir.join(raven_core::pair_seed::PAIR_SEEDS_FILE).is_file())
        }),
        "C87: no pair seeds after the links (A {}, B {})",
        a.dir.join(raven_core::pair_seed::PAIR_SEEDS_FILE).is_file(),
        b.dir.join(raven_core::pair_seed::PAIR_SEEDS_FILE).is_file()
    );
    for (p, downloads) in [(a, false), (b, true)] {
        let mut want = vec![
            raven_core::update_state::UPDATE_STATE_FILE,
            raven_core::security_ledger::SECURITY_LEDGER_FILE,
            raven_core::capability_floor::CAPABILITY_FLOOR_FILE,
            raven_core::pair_seed::PAIR_SEEDS_FILE,
        ];
        if downloads {
            want.push(raven_core::update_downloads::DOWNLOADS_FILE);
        }
        let missing: Vec<&str> = want
            .into_iter()
            .filter(|name| !p.dir.join(name).is_file())
            .collect();
        assert!(missing.is_empty(), "C87: {} lacks {missing:?}", p.name);
    }
    assert!(raven_core::update_downloads::incoming_dir(&b.dir, &manifest.digest()).is_dir());
    // The links that carried the notice and the release knocked (RLK1,
    // lane 6b's P6.35, live here): each side's capability floor holds the
    // knock for the other.
    for (p, friend) in [(a, b), (b, a)] {
        load_profile_key(&p.dir);
        let key: [u8; 32] = hex::decode(&friend.pub_hex).unwrap().try_into().unwrap();
        assert!(
            raven_core::capability_floor::has_knock(&p.dir, &key),
            "C87: {}'s links with {} never knocked",
            p.name,
            friend.name
        );
    }
}

/// `from` messages its contact `to_tag`: a link, which carries RUP1.
fn link_by_message(from: &Profile, to_tag: &str) -> Output {
    from.send(to_tag, &format!("update link from {}", from.name))
}

/// `raven update import FILE [--log LOG]`.
fn import(p: &Profile, file: &Path, log: Option<&Path>) -> Output {
    let mut args = vec!["update", "import", text(file)];
    if let Some(log) = log {
        args.extend(["--log", text(log)]);
    }
    p.raven(&args, None)
}

/// `raven update status`'s lines.
fn update_status(p: &Profile) -> String {
    let out = p.raven(&["update", "status"], None);
    assert!(out.ok, "{} update status:\n{}", p.name, out.all());
    out.stdout
}

/// The node's `Status.updates` (null while its exchange does not run).
fn updates_of(p: &Profile) -> serde_json::Value {
    ipc_status(p)["updates"].clone()
}

fn count_of(p: &Profile, field: &str) -> u64 {
    updates_of(p)[field].as_u64().unwrap_or(0)
}

/// The kinds of the rows in `p`'s security ledger so far (its node's and its
/// commands' events), read without the profile's keys.
fn ledger_kinds(p: &Profile) -> Vec<u16> {
    raven_core::security_ledger::rows_on_disk(&p.dir)
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .map(|(_, kind)| kind)
        .collect()
}

/// Wait until `p`'s ledger has a `kind` row.
fn wait_event(p: &Profile, kind: SecKind, why: &str, log: &Service) {
    assert!(
        wait_until(UPDATE_WAIT, || ledger_kinds(p).contains(&kind.code())),
        "{why}: no {} in {}'s ledger (kinds {:?}):\n{}",
        kind.name(),
        p.name,
        ledger_kinds(p),
        log.log.text()
    );
}

/// `raven security --json`: the kinds of the notices it shows, and how many
/// it only counts.
fn security_view(p: &Profile) -> (Vec<String>, u64) {
    let out = p.raven(&["security", "--json"], None);
    assert!(out.ok, "{} security --json:\n{}", p.name, out.all());
    let v: serde_json::Value = serde_json::from_str(out.stdout.trim())
        .unwrap_or_else(|e| panic!("{} security --json: {e}:\n{}", p.name, out.stdout));
    let kinds = v["alerts"]
        .as_array()
        .map(|alerts| {
            alerts
                .iter()
                .filter_map(|a| a["kind"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    (kinds, v["counted"].as_u64().unwrap_or(0))
}

/// Change one byte of the last signature of the notice `p`'s update state
/// holds, on its disk (its node stopped): the bytes still decode, their
/// signature no longer checks. What a friend whose stored notice was changed
/// (or a modified build) passes on. The new digest.
fn forge_stored_advisory(p: &Profile) -> [u8; 32] {
    load_profile_key(&p.dir);
    let path = p.dir.join(raven_core::update_state::UPDATE_STATE_FILE);
    let lock = raven_core::at_rest::lock_file(&p.dir, &path, Kind::UpdateState)
        .unwrap_or_else(|e| panic!("{}: the update state's lock: {e}", p.name));
    let plain = lock.load_bytes().unwrap().expect("an update state");
    let mut state: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    let mut bytes = hex::decode(state["advisory"].as_str().expect("a stored notice")).unwrap();
    *bytes.last_mut().unwrap() ^= 0x01;
    let digest = Advisory::decode(&bytes).expect("still decodes").digest();
    state["advisory"] = serde_json::Value::String(hex::encode(&bytes));
    lock.store_bytes(&serde_json::to_vec(&state).unwrap())
        .unwrap();
    digest
}

/// C88: see the module docs.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c88_forged_rolled_back_and_equivocating_notices_and_a_split_view_over_rup1() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let keys = test_key_set_file(r);

    // One log lists notice #1, #2 and another #2 (the project signed both:
    // stolen keys, say); a second signed log of the same size differs in
    // its last entry.
    let mut project = TestProject::new();
    let first = project.advisory(1, 1, [0; 32]);
    project.list(EntryType::Advisory, first.digest());
    let second = project.advisory(2, 2, first.digest());
    project.list(EntryType::Advisory, second.digest());
    let mut fork = project.clone();
    let other = project.advisory(2, 3, first.digest());
    project.list(EntryType::Advisory, other.digest());
    fork.list(EntryType::Manifest, [0x5A; 32]);
    let log = put(r, "log.rtl1", &project.snapshot().encode());
    let fork_log = put(r, "fork.rtl1", &fork.snapshot().encode());
    let first_file = put(r, "first.rad1", first.bytes());
    let second_file = put(r, "second.rad1", second.bytes());
    let other_file = put(r, "other.rad1", other.bytes());

    let a = update_profile(r, "ua", &keys);
    let b = update_profile(r, "ub", &keys);
    let c = update_profile(r, "uc", &keys);
    let d = update_profile(r, "ud", &keys);
    let e = update_profile(r, "ue", &keys);
    let f = update_profile(r, "uf", &keys).with_lab_env("RAVEN_LAB_UPDATE_CLAIM_NEWER", "1");
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    let c_svc = c.start_service();
    let d_svc = d.start_service();
    let e_svc = e.start_service();
    let mut f_svc = f.start_service();
    let f_dial = f_svc.lan_dial.clone();
    for (x, y, y_tag, y_dial) in [
        (&a, &b, "bob", &b_svc.lan_dial),
        (&b, &a, "alice", &a_svc.lan_dial),
        (&b, &c, "carol", &c_svc.lan_dial),
        (&c, &b, "bob", &b_svc.lan_dial),
        (&b, &d, "dave", &d_svc.lan_dial),
        (&d, &b, "bob", &b_svc.lan_dial),
        (&c, &e, "erin", &e_svc.lan_dial),
        (&e, &c, "carol", &c_svc.lan_dial),
        (&b, &f, "frank", &f_dial),
    ] {
        x.pin_contact(y, y_tag, Some(y_dial));
    }
    // F's own route to B is dead: it never fetches B's newer notice, so it
    // keeps the old one it hands out.
    let dead = format!("127.0.0.1:{}", free_loopback_port());
    f.pin_contact(&b, "bob", Some(&dead));

    for (p, file, log) in [
        (&a, &second_file, Some(&log)),
        (&d, &other_file, Some(&log)),
        (&e, &fork_log, None),
        (&f, &first_file, Some(&log)),
    ] {
        let out = import(p, file, log.map(PathBuf::as_path));
        assert!(out.ok, "{} import:\n{}", p.name, out.all());
    }

    // ── A -> B -> C: notice #2 by itself ─────────────────────────────────
    assert_delivered("b→a", &link_by_message(&b, "alice"));
    assert!(
        wait_until(UPDATE_WAIT, || count_of(&b, "advisory_serial") == 2),
        "B did not take #2 from A ({}):\n{}",
        updates_of(&b),
        b_svc.log.text()
    );
    wait_event(&b, SecKind::AdvisoryApplied, "B applied #2", &b_svc);
    assert_delivered("c→b", &link_by_message(&c, "bob"));
    assert!(
        wait_until(UPDATE_WAIT, || count_of(&c, "advisory_serial") == 2),
        "C did not take #2 from B ({}):\n{}",
        updates_of(&c),
        c_svc.log.text()
    );
    wait_event(&c, SecKind::AdvisoryApplied, "C applied #2", &c_svc);

    // ── A rolled-back notice: F claims #2 and hands over #1 ──────────────
    assert_delivered("b→f", &link_by_message(&b, "frank"));
    wait_event(&b, SecKind::AdvisoryRollback, "the rolled-back #1", &b_svc);
    let ub = updates_of(&b);
    assert_eq!(ub["advisory_serial"].as_u64(), Some(2), "B keeps #2: {ub}");
    assert_eq!(ub["frozen"].as_bool(), Some(false), "{ub}");
    assert_eq!(
        ub["quarantined"].as_u64(),
        Some(0),
        "a rollback is no forgery: {ub}"
    );
    assert_eq!(count_of(&f, "advisory_serial"), 1, "F kept #1");

    // ── A forged notice: F's stored #1 changed on its disk ───────────────
    drop(f_svc);
    let forged = forge_stored_advisory(&f);
    assert_ne!(forged, first.digest());
    f_svc = f.start_service_on(&f_dial, None);
    assert_delivered("b→f again", &link_by_message(&b, "frank"));
    wait_event(&b, SecKind::AdvisoryForged, "the forged #1", &b_svc);
    assert!(
        wait_until(UPDATE_WAIT, || count_of(&b, "quarantined") == 1),
        "B quarantined nothing ({})",
        updates_of(&b)
    );
    assert_eq!(count_of(&b, "advisory_serial"), 2);
    assert_eq!(updates_of(&b)["frozen"].as_bool(), Some(false));

    // ── Equivocation: D holds another #2 ─────────────────────────────────
    assert_delivered("b→d", &link_by_message(&b, "dave"));
    wait_event(&b, SecKind::AdvisoryEquivocation, "the other #2", &b_svc);
    assert!(
        wait_until(UPDATE_WAIT, || updates_of(&b)["frozen"].as_bool()
            == Some(true)),
        "B is not frozen ({})",
        updates_of(&b)
    );

    // ── A split view: C has B's log, E another of the same size ──────────
    assert_delivered("c→e", &link_by_message(&c, "erin"));
    wait_event(&c, SecKind::LogSplitView, "E's log", &c_svc);
    assert!(
        wait_until(UPDATE_WAIT, || updates_of(&c)["frozen"].as_bool()
            == Some(true)),
        "C is not frozen ({})",
        updates_of(&c)
    );
    assert_eq!(count_of(&c, "advisory_serial"), 2, "C keeps #2");
    assert_eq!(
        updates_of(&a)["frozen"].as_bool(),
        Some(false),
        "A never froze"
    );

    // What the person sees: the forged notice, the equivocation and the
    // split view shown, the rollback only counted; the freeze in words.
    let (shown, counted) = security_view(&b);
    for kind in [SecKind::AdvisoryForged, SecKind::AdvisoryEquivocation] {
        assert!(shown.iter().any(|k| k == kind.name()), "B shows {shown:?}");
    }
    assert!(counted >= 1, "B counts the rollback: {counted}");
    eprintln!("C88: B shows {shown:?} and counts {counted}");
    let (shown, _) = security_view(&c);
    assert!(
        shown.iter().any(|k| k == SecKind::LogSplitView.name()),
        "C shows {shown:?}"
    );
    eprintln!("C88: C shows {shown:?}");
    for p in [&b, &c] {
        let status = update_status(p);
        assert!(
            status.contains(raven_core::suite_policy::FROZEN_TEXT),
            "{}: {status}",
            p.name
        );
    }
    // No log names a friend's key or address in what the exchange printed.
    for (p, svc) in [(&b, &b_svc), (&c, &c_svc), (&f, &f_svc)] {
        let lines: Vec<String> = svc
            .log
            .text()
            .lines()
            .filter(|l| l.contains("raven-node updates:"))
            .map(str::to_owned)
            .collect();
        for friend in [&a, &b, &c, &d, &e, &f] {
            assert!(
                !lines.iter().any(|l| l.contains(&friend.pub_hex)),
                "{}: {lines:?}",
                p.name
            );
        }
    }
}

/// Stops the node `raven update install` started for a profile (not this
/// process's child) by the pid its Status names, when dropped; nothing when
/// none answers.
#[cfg(unix)]
struct InstalledNode<'a> {
    p: &'a Profile,
}

#[cfg(unix)]
impl Drop for InstalledNode<'_> {
    fn drop(&mut self) {
        let endpoint = ipc_endpoint_of(self.p);
        let frame =
            raven_core::ipc::encode_request(&raven_core::ipc::IpcRequest::status()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(ipc_transact(&endpoint, &frame));
        });
        let Ok(Ok(body)) = rx.recv_timeout(Duration::from_secs(10)) else {
            return;
        };
        let Some(pid) = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["pid"].as_u64())
        else {
            return;
        };
        let pid = pid.to_string();
        let alive = |pid: &str| {
            Command::new("kill")
                .args(["-0", pid])
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        };
        let _ = Command::new("kill").args(["-TERM", &pid]).status();
        if !wait_until(Duration::from_secs(10), || !alive(&pid)) {
            let _ = Command::new("kill").args(["-KILL", &pid]).status();
        }
    }
}

/// `p`'s `raven` command run from `bin` (an installed copy).
#[cfg(unix)]
fn raven_at(p: &Profile, bin: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin);
    p.env(&mut cmd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.arg("--data-dir").arg(&p.dir).args(args);
    run_bounded(
        cmd,
        None,
        COMMAND_TIMEOUT,
        &format!("{} {bin:?} {args:?}", p.name),
    )
}

/// Write a release into `p`'s staged folder (`updates/staged/<serial>/`)
/// straight on its disk: its node offers and serves it without checking it
/// again (a staged build was checked when the CLI staged it).
#[cfg(unix)]
fn plant_staged(p: &Profile, manifest: &Manifest, snapshot: &Snapshot, payload: &[u8]) {
    let dir = p
        .dir
        .join(STAGED_DIR)
        .join(manifest.build_serial.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(STAGED_MANIFEST), manifest.bytes()).unwrap();
    std::fs::write(dir.join(STAGED_SNAPSHOT), snapshot.encode()).unwrap();
    for (i, file) in manifest.files.iter().enumerate() {
        std::fs::write(
            dir.join(staged_file_name(i, &file.path)),
            &payload[file.range()],
        )
        .unwrap();
    }
}

/// The offer code `raven update download` takes for `manifest`.
#[cfg(unix)]
fn offer_code(manifest: &Manifest) -> String {
    hex::encode(manifest.digest())[..8].to_owned()
}

/// Whether `p` holds anything of the release `manifest` in
/// `updates/incoming/`.
#[cfg(unix)]
fn incoming(p: &Profile, manifest: &Manifest) -> bool {
    raven_core::update_downloads::incoming_dir(&p.dir, &manifest.digest()).exists()
}

/// `raven update download CODE` with the lab approval (it answers y).
#[cfg(unix)]
fn approve(p: &Profile, manifest: &Manifest) {
    let out = p.raven_with(
        &["update", "download", &offer_code(manifest)],
        None,
        &[AUTO_APPROVE],
    );
    assert!(
        out.ok
            && out
                .stdout
                .contains("(lab: approved by RAVEN_LAB_UPDATE_AUTO_APPROVE)"),
        "{} download {}:\n{}",
        p.name,
        offer_code(manifest),
        out.all()
    );
}

/// C89: see the module docs.
#[cfg(unix)]
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c89_bad_releases_refused_and_a_good_one_passed_on_staged_and_installed() {
    use std::os::unix::fs::PermissionsExt;
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let keys = test_key_set_file(r);
    // A release's raven-node: a script that runs this build's.
    let program = |what: &str| -> Vec<u8> {
        format!("#!/bin/sh\n# {what} (carrier_matrix C89)\nexec '{NODE}' \"$@\"\n").into_bytes()
    };
    let installed_before = program("the raven-node installed before");
    let [k0, k1, _] = signers();
    let good: &[(u8, &Identity)] = &[(0, &k0), (1, &k1)];
    let (wrong0, wrong1) = (signer(0x44), signer(0x55));
    let mut project = TestProject::new();
    let (m3, p3) = project.release(3, &program("Raven 1.3.0 (build 3)"), Some(good));
    project.list(EntryType::Manifest, m3.digest());
    let (m5, p5) = project.release(5, &program("Raven 1.5.0 (build 5)"), Some(good));
    project.list(EntryType::Manifest, m5.digest());
    let (m6, p6) = project.release(6, &program("Raven 1.6.0 (build 6)"), None);
    project.list(EntryType::Manifest, m6.digest());
    let (m7, p7) = project.release(
        7,
        &program("Raven 1.7.0 (build 7)"),
        Some(&[(0, &wrong0), (1, &wrong1)]),
    );
    project.list(EntryType::Manifest, m7.digest());
    // Build 8 is signed and never listed.
    let (m8, p8) = project.release(8, &program("Raven 1.8.0 (build 8)"), Some(good));
    let snapshot = project.snapshot();
    let bundle = |name: &str, manifest: &Manifest, payload: &[u8]| {
        let parts = Parts {
            manifest: manifest.clone(),
            snapshot: snapshot.clone(),
            advisory: None,
            payload: payload.to_vec(),
        };
        put(r, name, &parts.encode())
    };
    let good_file = bundle("raven-5.rrb", &m5, &p5);
    let older_file = bundle("raven-3.rrb", &m3, &p3);
    let unsigned_file = bundle("raven-6-unsigned.rrb", &m6, &p6);
    let unlogged_file = bundle("raven-8-unlogged.rrb", &m8, &p8);
    let mut tampered = p5.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    let forged_file = bundle("raven-5-forged.rrb", &m5, &tampered);

    let a = update_profile(r, "ia", &keys);
    let b = update_profile(r, "ib", &keys);
    let c = update_profile(r, "ic", &keys);
    // One hostile friend for each bad release: a friend whose release was
    // refused is not asked for anything for 30 s.
    let hostile = [
        ("ih", "hank", &m6, &p6),
        ("ij", "jack", &m7, &p7),
        ("ik", "kim", &m8, &p8),
    ]
    .map(|(name, tag, m, p)| {
        let h = update_profile(r, name, &keys);
        plant_staged(&h, m, &snapshot, p);
        (h, tag)
    });
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    let c_svc = c.start_service();
    let hostile_svcs: Vec<Service> = hostile.iter().map(|(h, _)| h.start_service()).collect();
    for (x, y, y_tag, y_dial) in [
        (&a, &b, "bob", &b_svc.lan_dial),
        (&b, &a, "alice", &a_svc.lan_dial),
        (&b, &c, "carol", &c_svc.lan_dial),
        (&c, &b, "bob", &b_svc.lan_dial),
    ] {
        x.pin_contact(y, y_tag, Some(y_dial));
    }
    for ((h, tag), svc) in hostile.iter().zip(&hostile_svcs) {
        b.pin_contact(h, tag, Some(&svc.lan_dial));
        h.pin_contact(&b, "bob", Some(&b_svc.lan_dial));
    }

    // C's programs: a copy of this build's raven and the raven-node it
    // "installed" before, in a temp prefix (never the build folder).
    let prefix = r.join("prefix");
    std::fs::create_dir_all(&prefix).unwrap();
    let installed_cli = prefix.join("raven");
    std::fs::copy(raven_bin(), &installed_cli).unwrap();
    let installed_node = prefix.join("raven-node");
    std::fs::write(&installed_node, &installed_before).unwrap();
    std::fs::set_permissions(&installed_node, std::fs::Permissions::from_mode(0o755)).unwrap();

    // ── Bad releases from files: refused, nothing staged ─────────────────
    for (file, says, kind) in [
        (
            &unsigned_file,
            "failed its check (MANIFEST_SIG)",
            SecKind::BundleForged,
        ),
        (
            &forged_file,
            "failed its check (BAD_CHUNK_ROOT)",
            SecKind::BundleForged,
        ),
        (
            &unlogged_file,
            "is not listed in the public Raven release log",
            SecKind::UpdateUnlogged,
        ),
    ] {
        let out = import(&c, file, None);
        assert!(
            !out.ok && out.all().contains(says),
            "C imported {file:?}:\n{}",
            out.all()
        );
        wait_event(&c, kind, says, &c_svc);
    }
    for serial in [5, 6, 8] {
        assert!(
            !c.dir.join(STAGED_DIR).join(serial.to_string()).exists(),
            "C staged build {serial}"
        );
    }

    // ── Bad releases over RUP1: listed, approved, refused, none kept ─────
    for (_, tag) in &hostile {
        assert_delivered(&format!("b→{tag}"), &link_by_message(&b, tag));
    }
    assert!(
        wait_until(UPDATE_WAIT, || count_of(&b, "offers") == 3),
        "B was not offered the 3 bad releases ({}):\n{}",
        updates_of(&b),
        b_svc.log.text()
    );
    assert!(
        !wait_until(NOTHING_WAIT, || [&m6, &m7, &m8]
            .iter()
            .any(|m| incoming(&b, m))),
        "B fetched before anyone approved"
    );
    for m in [&m6, &m7, &m8] {
        approve(&b, m);
    }
    wait_event(
        &b,
        SecKind::BundleForged,
        "the unsigned and forged releases",
        &b_svc,
    );
    wait_event(&b, SecKind::UpdateUnlogged, "the unlogged release", &b_svc);
    // The unlogged one is not called a failed check: no log B has, nor
    // the one Kim sent, lists it (Phase 6 review re-verify,
    // updates-protocol-6).
    assert!(
        wait_until(UPDATE_WAIT, || {
            let status = update_status(&b);
            status.matches("that failed its checks").count() == 2
                && status.matches("but no Raven release log lists it").count() == 1
        }),
        "B's three failed downloads:\n{}",
        update_status(&b)
    );
    let ub = updates_of(&b);
    assert_eq!(
        (ub["downloading"].as_u64(), ub["ready"].as_u64()),
        (Some(0), Some(0)),
        "{ub}"
    );

    // ── The good release: A -> B -> C, each after its approval ───────────
    let out = import(&a, &good_file, None);
    assert!(out.ok, "A import:\n{}", out.all());
    assert!(a.dir.join(STAGED_DIR).join("5").is_dir());
    assert_delivered("b→a", &link_by_message(&b, "alice"));
    assert!(
        wait_until(UPDATE_WAIT, || count_of(&b, "offers") == 1),
        "B was not offered A's build 5 ({})",
        updates_of(&b)
    );
    assert!(
        !wait_until(NOTHING_WAIT, || incoming(&b, &m5)),
        "B fetched build 5 before the approval"
    );
    approve(&b, &m5);
    assert!(
        wait_until(UPDATE_WAIT, || count_of(&b, "ready") == 1),
        "B did not download build 5 from A ({}):\n{}",
        updates_of(&b),
        b_svc.log.text()
    );
    assert_delivered("c→b", &link_by_message(&c, "bob"));
    assert!(
        wait_until(UPDATE_WAIT, || count_of(&c, "offers") == 1),
        "C was not offered build 5 by B ({})",
        updates_of(&c)
    );
    assert!(
        !wait_until(NOTHING_WAIT, || incoming(&c, &m5)),
        "C fetched build 5 before the approval"
    );
    approve(&c, &m5);
    assert!(
        wait_until(UPDATE_WAIT, || count_of(&c, "ready") == 1),
        "C did not download build 5 from B ({}):\n{}",
        updates_of(&c),
        c_svc.log.text()
    );
    assert_eq!(std::fs::read(&installed_node).unwrap(), installed_before);

    // ── Installed from the temp prefix; the old raven-node kept ──────────
    let before_pid = ipc_status(&c)["pid"].as_u64();
    let _installed = InstalledNode { p: &c };
    let out = raven_at(&c, &installed_cli, &["update", "install"], &[AUTO_APPROVE]);
    assert!(
        out.ok
            && out
                .stdout
                .contains("(lab: install typed by RAVEN_LAB_UPDATE_AUTO_APPROVE)"),
        "C install:\n{}\n{}",
        out.all(),
        c_svc.log.text()
    );
    assert_eq!(
        std::fs::read(&installed_node).unwrap(),
        p5[m5.files[0].range()],
        "the new raven-node is in place"
    );
    assert_eq!(
        std::fs::read(prefix.join("raven-node.prev")).unwrap(),
        installed_before,
        "the old one is kept"
    );
    let mode = std::fs::metadata(&installed_node)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o755);
    let ping = c.raven(&["ipc-ping"], None);
    assert!(ping.ok, "the installed node answers:\n{}", ping.all());
    let after_pid = ipc_status(&c)["pid"].as_u64();
    assert!(
        after_pid.is_some() && after_pid != before_pid,
        "{before_pid:?} {after_pid:?}"
    );
    let status = update_status(&c);
    assert!(status.contains("1.5.0 (build 5)"), "{status}");
    eprintln!(
        "C89: the install said:\n{}\nC89: then `raven update status`:\n{status}",
        out.stdout
    );

    // ── An older release now: a downgrade ────────────────────────────────
    let out = import(&c, &older_file, None);
    assert!(
        !out.ok
            && out
                .all()
                .contains("is not newer than the Raven you have (build 5)"),
        "C imported build 3:\n{}",
        out.all()
    );
    wait_event(&c, SecKind::BundleDowngrade, "build 3", &c_svc);
    assert!(!c.dir.join(STAGED_DIR).join("3").exists());
}
