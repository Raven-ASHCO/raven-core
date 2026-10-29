//! P6.23 tests of the security ledger: the file's protection, version and
//! damage rules, nothing created while the gate is shut or the profile is
//! plain, the rate limit, retention, the open-alert cap, resolve and clear,
//! the privacy passes, and the privacy scan (10,000 random events, then the
//! file's bytes searched for every address, port, message id, network tag
//! and clear key that was fed in). Profiles are temp folders whose keys come
//! from the test build's lab K_hist (never a keychain item); the events gate
//! is opened for the test's thread only (debug builds; a release test build
//! cannot open it, so those tests have nothing to check there).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use super::*;
use crate::outbox::OutboxCarrier;
use crate::security_events::{
    classify_link_error, Aggregator, SourceKey, Via, BIND_BAD_SIGNATURE, BIND_TRUNCATED,
    INTERNET_FRAME_LENGTH, INTERNET_HANDSHAKE_TIMEOUT, LAN_FRAME_LENGTH, LAN_HANDSHAKE_TIMEOUT,
    LINK_TAG_FAILED, NOISE_HANDSHAKE_FAILED,
};

/// Day 20,000 since the epoch, 05:00.
const NOW: u64 = 20_000 * DAY_MS + 5 * HOUR_MS;
const SECOND: u64 = 1_000;

/// Open the events gate for this thread: false in a release build, where it
/// cannot open (the test then has nothing to check).
fn gate_open() -> bool {
    security_gate::set_lab_for_this_thread(SecGate::Events, Some(true));
    security_gate::live(SecGate::Events)
}

/// A sealed profile with its keys loaded, as raven-node's start leaves it.
fn sealed_profile() -> tempfile::TempDir {
    let dir = crate::contact_book::tests::profile();
    crate::contact_book::tests::seal(dir.path());
    dir
}

fn key(n: u16) -> [u8; 32] {
    let mut key = [0xA5; 32];
    key[..2].copy_from_slice(&n.to_be_bytes());
    key
}

fn contact(kind: SecKind, peer: [u8; 32], at_ms: u64) -> SecEvent {
    SecEvent::new(
        kind,
        Attribution::Contact { peer },
        Via::DirectLink(OutboxCarrier::Lan),
        at_ms,
    )
}

fn network(kind: SecKind, ip: IpAddr, at_ms: u64) -> SecEvent {
    SecEvent::new(
        kind,
        Attribution::Network {
            source: SourceKey::of(ip),
        },
        Via::Dial(OutboxCarrier::Lan),
        at_ms,
    )
}

fn raw(dir: &Path) -> Connection {
    Connection::open(ledger_path(dir)).unwrap()
}

fn files_named(dir: &Path, prefix: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.unwrap().file_name().into_string().ok())
        .filter(|name| name.starts_with(prefix))
        .collect();
    names.sort();
    names
}

fn count_of(ledger: &SecurityLedger, kind: SecKind, subject: Option<[u8; 32]>) -> u64 {
    ledger
        .counts(0)
        .unwrap()
        .iter()
        .filter(|c| c.kind == kind && c.subject.map(|s| *s.key()) == subject)
        .map(|c| c.n)
        .sum()
}

#[test]
fn the_file_is_private_versioned_and_keyed() {
    if !gate_open() {
        return;
    }
    let dir = sealed_profile();
    let dd = dir.path();
    let path = ledger_path(dd);
    assert_eq!(path.file_name().unwrap(), "security_events.sqlite");
    let mut ledger = SecurityLedger::open(dd).unwrap();
    let peer = key(1);
    let id = ledger
        .record(
            &contact(SecKind::ObjectAuthFail, peer, NOW),
            Severity::Suspicious,
            NOW,
        )
        .unwrap()
        .expect("a contact event opens an alert");
    {
        let conn = &ledger.conn;
        let pragma = |name: &str| -> String {
            conn.query_row(&format!("PRAGMA {name}"), [], |r| {
                r.get::<_, rusqlite::types::Value>(0)
            })
            .map(|v| match v {
                rusqlite::types::Value::Integer(n) => n.to_string(),
                rusqlite::types::Value::Text(t) => t,
                other => format!("{other:?}"),
            })
            .unwrap()
        };
        assert_eq!(pragma("user_version"), "1");
        assert_eq!(pragma("secure_delete"), "1");
        assert_eq!(pragma("journal_mode"), "wal");
        assert_eq!(pragma("auto_vacuum"), "2", "INCREMENTAL");
        assert_eq!(pragma("synchronous"), "1", "NORMAL");
        assert_eq!(pragma("busy_timeout"), "2000");
        assert_eq!(
            rebuild::columns(conn, COUNTS).unwrap(),
            ["day", "kind", "kh_subject", "n", "meta"]
        );
        assert_eq!(
            rebuild::columns(conn, ALERTS).unwrap(),
            [
                "id",
                "kind",
                "kh_subject",
                "first_hour",
                "last_hour",
                "n",
                "severity",
                "state",
                "action",
                "resolved_hour",
                "meta"
            ]
        );
        // Keyed: the lookup digest is stored, the clear key only sealed.
        let keys = at_rest::keys_cached(dd).unwrap();
        let (kh, meta): (Vec<u8>, Vec<u8>) = conn
            .query_row("SELECT kh_subject, meta FROM sec_alerts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(kh, at_rest::index(&keys, ValueType::DeviceKey, &peer));
        assert_ne!(kh, peer);
        let kind = i64::from(SecKind::ObjectAuthFail.code());
        assert_eq!(
            open_subject(&keys, ALERTS, &alert_pk(kind, &kh), &meta),
            Some(LedgerSubject::Contact(peer))
        );
        // Bound to its row: another row's key does not open it.
        assert_eq!(
            open_subject(&keys, ALERTS, &alert_pk(kind + 1, &kh), &meta),
            None
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal"] {
            let file = sidecar(&path, suffix);
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", file.display());
        }
    }
    #[cfg(windows)]
    {
        let sid = crate::win_acl::user_sid().unwrap();
        assert!(crate::win_acl::read_dacl(&path)
            .unwrap()
            .is_owner_only(crate::win_acl::Kind::File, sid));
    }
    // Registered as keyed SQLite, with its moved-aside copy.
    for name in ["security_events.sqlite", "security_events.sqlite.corrupt"] {
        assert_eq!(
            at_rest::registry::rule_for(name).map(|r| (r.rule, r.erase)),
            Some((at_rest::registry::Rule::KeyedSqlite, true)),
            "{name}"
        );
    }
    drop(ledger);
    let ledger = SecurityLedger::open(dd).unwrap();
    let alerts = ledger.open_alerts().unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts[0],
        Alert {
            id,
            kind: SecKind::ObjectAuthFail,
            subject: Some(LedgerSubject::Contact(peer)),
            first_hour: NOW / HOUR_MS,
            last_hour: NOW / HOUR_MS,
            n: 1,
            severity: Severity::Suspicious,
            state: AlertState::New,
            action: None,
        }
    );
    assert_eq!(
        ledger.counts(NOW / DAY_MS).unwrap(),
        [DayCount {
            day: NOW / DAY_MS,
            kind: SecKind::ObjectAuthFail,
            subject: Some(LedgerSubject::Contact(peer)),
            n: 1,
        }]
    );
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

/// Acceptance: nothing is created while the events gate is shut; never a
/// plain ledger (a profile that is not sealed, or no key loaded here).
#[test]
fn nothing_is_created_while_the_gate_is_shut_or_without_the_key() {
    let dir = sealed_profile();
    let dd = dir.path();
    security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
    let shut = SecurityLedger::open(dd).err().unwrap();
    assert!(matches!(shut, LedgerError::GateClosed), "{shut}");
    assert!(shut.is_skipped());
    let sink = DirectSink::new(dd);
    sink.accept(
        &contact(SecKind::BindingMismatch, key(1), NOW),
        Severity::Alert,
    );
    sink.flush();
    assert_eq!(sink.failures(), 0, "a skipped ledger is not a failure");
    assert!(files_named(dd, "security_events").is_empty());

    if gate_open() {
        // A profile that is not sealed keeps no ledger.
        let plain = crate::contact_book::tests::profile();
        let e = SecurityLedger::open(plain.path()).err().unwrap();
        assert!(matches!(e, LedgerError::NotSealed), "{e}");
        assert!(e.is_skipped());
        assert!(files_named(plain.path(), "security_events").is_empty());
        // A sealed one without its key loaded in this process: none either.
        at_rest::forget_cached_keys(dd);
        let e = SecurityLedger::open(dd).err().unwrap();
        assert!(matches!(e, LedgerError::KeyUnavailable(_)), "{e}");
        assert!(e.is_skipped());
        let sink = DirectSink::new(dd);
        sink.accept(
            &contact(SecKind::BindingMismatch, key(1), NOW),
            Severity::Alert,
        );
        assert_eq!(sink.failures(), 0);
        assert!(files_named(dd, "security_events").is_empty());
        // With the key, the sink writes.
        at_rest::keys_load_with(dd, at_rest::MigratePolicy::Never).unwrap();
        sink.accept(
            &contact(SecKind::BindingMismatch, key(1), NOW),
            Severity::Alert,
        );
        assert_eq!(sink.failures(), 0);
        let ledger = SecurityLedger::open(dd).unwrap();
        assert_eq!(ledger.open_alerts().unwrap().len(), 1);
    }
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

#[test]
fn a_newer_ledger_is_refused_and_a_damaged_one_moved_aside() {
    if !gate_open() {
        return;
    }
    let dir = sealed_profile();
    let dd = dir.path();
    let path = ledger_path(dd);
    let mut ledger = SecurityLedger::open(dd).unwrap();
    ledger
        .record(
            &contact(SecKind::ResetLoop, key(1), NOW),
            Severity::Suspicious,
            NOW,
        )
        .unwrap();
    drop(ledger);
    raw(dd).execute_batch("PRAGMA user_version = 3;").unwrap();
    let e = SecurityLedger::open(dd).err().unwrap();
    assert!(matches!(e, LedgerError::Newer(3)), "{e}");
    assert!(!e.is_skipped());
    assert_eq!(
        rebuild::user_version(&raw(dd)).unwrap(),
        3,
        "a refused ledger is left as it is"
    );
    // The privacy passes refuse it too, and leave it.
    assert!(rekey(dd).unwrap_err().contains("newer"));
    assert!(path.exists());

    // Damaged: moved aside, and a new ledger in its place.
    let garbage = b"this is not a database ".repeat(200);
    std::fs::write(&path, &garbage).unwrap();
    let _ = std::fs::remove_file(sidecar(&path, "-wal"));
    let mut ledger = SecurityLedger::open(dd).unwrap();
    assert_eq!(std::fs::read(quarantine_path(dd)).unwrap(), garbage);
    assert!(ledger.open_alerts().unwrap().is_empty());
    ledger
        .record(
            &contact(SecKind::ResetLoop, key(2), NOW),
            Severity::Suspicious,
            NOW,
        )
        .unwrap();
    assert_eq!(ledger.open_alerts().unwrap().len(), 1);
    drop(ledger);

    // Keyed under another key (a profile sealed anew): nothing in it opens
    // here, so it is moved aside too.
    raw(dd)
        .execute(
            "UPDATE sec_meta SET v = ?1 WHERE k = ?2",
            params![[7u8; 32].as_slice(), META_KEY_CHECK],
        )
        .unwrap();
    let ledger = SecurityLedger::open(dd).unwrap();
    assert!(ledger.open_alerts().unwrap().is_empty());
    assert_eq!(
        files_named(dd, "security_events.sqlite.corrupt"),
        ["security_events.sqlite.corrupt"],
        "one copy: the newer one replaces the older"
    );
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

/// One write per kind and subject per 60 s; what comes between is counted
/// and goes with the next write. A rising severity writes at once.
#[test]
fn writes_are_rate_limited_and_counts_aggregated() {
    if !gate_open() {
        return;
    }
    let dir = sealed_profile();
    let mut ledger = SecurityLedger::open(dir.path()).unwrap();
    let (one, two) = (key(1), key(2));
    let kind = SecKind::ObjectAuthFail;
    let first = ledger
        .record(&contact(kind, one, NOW), Severity::Suspicious, NOW)
        .unwrap()
        .unwrap();
    for s in [10, 20, 30, 40] {
        let at = NOW + s * SECOND;
        let id = ledger
            .record(&contact(kind, one, at), Severity::Suspicious, at)
            .unwrap();
        assert_eq!(id, Some(first), "the alert is known without a write");
    }
    assert_eq!(count_of(&ledger, kind, Some(one)), 1, "four are pending");
    assert_eq!(ledger.open_alerts().unwrap()[0].n, 1);
    // Another subject is its own pair: written at once.
    let at = NOW + 15 * SECOND;
    ledger
        .record(&contact(kind, two, at), Severity::Suspicious, at)
        .unwrap();
    assert_eq!(count_of(&ledger, kind, Some(two)), 1);
    // A rising severity does not wait.
    let at = NOW + 50 * SECOND;
    ledger
        .record(&contact(kind, one, at), Severity::Alert, at)
        .unwrap();
    assert_eq!(count_of(&ledger, kind, Some(one)), 6);
    let alert = ledger
        .open_alerts()
        .unwrap()
        .into_iter()
        .find(|a| a.id == first)
        .unwrap();
    assert_eq!((alert.n, alert.severity), (6, Severity::Alert));
    // Then the interval again, counted from that write.
    for s in [60, 90, 109] {
        let at = NOW + s * SECOND;
        ledger
            .record(&contact(kind, one, at), Severity::Suspicious, at)
            .unwrap();
    }
    assert_eq!(count_of(&ledger, kind, Some(one)), 6);
    let at = NOW + 110 * SECOND;
    ledger
        .record(&contact(kind, one, at), Severity::Suspicious, at)
        .unwrap();
    assert_eq!(count_of(&ledger, kind, Some(one)), 10);

    // Network sources: one count per kind and day, no subject, no alert.
    for n in 0..100u32 {
        let ip = IpAddr::V4(Ipv4Addr::from(0x0A00_0001 + n));
        let at = NOW + u64::from(n) * 100;
        let id = ledger
            .record(
                &network(SecKind::HandshakeFail, ip, at),
                Severity::Notice,
                at,
            )
            .unwrap();
        assert_eq!(id, None);
    }
    assert_eq!(count_of(&ledger, SecKind::HandshakeFail, None), 1);
    // The pass of a later event writes every pair whose interval passed.
    let at = NOW + 200 * SECOND;
    ledger
        .record(
            &contact(SecKind::ResetLoop, two, at),
            Severity::Suspicious,
            at,
        )
        .unwrap();
    assert_eq!(count_of(&ledger, SecKind::HandshakeFail, None), 100);
    // An hourly flush of network counts kept in memory: the same row.
    ledger
        .add_network_count(NOW / DAY_MS, SecKind::HandshakeFail, 25)
        .unwrap();
    ledger
        .add_network_count(NOW / DAY_MS, SecKind::StrangerRefused, 0)
        .unwrap();
    assert_eq!(count_of(&ledger, SecKind::HandshakeFail, None), 125);
    assert_eq!(count_of(&ledger, SecKind::StrangerRefused, None), 0);
    assert!(ledger
        .open_alerts()
        .unwrap()
        .iter()
        .all(|a| a.kind != SecKind::HandshakeFail));
    // A local event: an alert about nobody.
    let local = SecEvent::new(SecKind::LocalRollback, Attribution::Local, Via::Local, at);
    let id = ledger.record(&local, Severity::Alert, at).unwrap().unwrap();
    let alert = ledger
        .open_alerts()
        .unwrap()
        .into_iter()
        .find(|a| a.id == id)
        .unwrap();
    assert_eq!((alert.kind, alert.subject), (SecKind::LocalRollback, None));
    // What is pending is written by flush (and the drop).
    for s in [210, 220] {
        let at = NOW + s * SECOND;
        ledger
            .record(&contact(kind, one, at), Severity::Suspicious, at)
            .unwrap();
    }
    assert_eq!(count_of(&ledger, kind, Some(one)), 11, "one is pending");
    ledger.flush(NOW + 221 * SECOND).unwrap();
    assert_eq!(count_of(&ledger, kind, Some(one)), 12);
    drop(ledger);
    let ledger = SecurityLedger::open(dir.path()).unwrap();
    assert_eq!(count_of(&ledger, kind, Some(one)), 12);
    // The drop writes what is pending.
    let mut ledger = ledger;
    let at = NOW + 230 * SECOND;
    ledger
        .record(&contact(kind, two, at), Severity::Suspicious, at)
        .unwrap();
    let at = NOW + 240 * SECOND;
    ledger
        .record(&contact(kind, two, at), Severity::Suspicious, at)
        .unwrap();
    assert_eq!(count_of(&ledger, kind, Some(two)), 2);
    drop(ledger);
    let ledger = SecurityLedger::open(dir.path()).unwrap();
    assert_eq!(count_of(&ledger, kind, Some(two)), 3);
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

#[test]
fn a_new_day_gets_its_own_count() {
    if !gate_open() {
        return;
    }
    let dir = sealed_profile();
    let mut ledger = SecurityLedger::open(dir.path()).unwrap();
    let midnight = (NOW / DAY_MS + 1) * DAY_MS;
    let peer = key(3);
    let kind = SecKind::IndexJump;
    for at in [
        midnight - 20 * SECOND,
        midnight - 10 * SECOND,
        midnight + 5 * SECOND,
    ] {
        ledger
            .record(&contact(kind, peer, at), Severity::Notice, at)
            .unwrap();
    }
    ledger.flush(midnight + 6 * SECOND).unwrap();
    let days: Vec<(u64, u64)> = ledger
        .counts(0)
        .unwrap()
        .iter()
        .map(|c| (c.day, c.n))
        .collect();
    assert_eq!(days, [(NOW / DAY_MS, 2), (NOW / DAY_MS + 1, 1)]);
    let alert = &ledger.open_alerts().unwrap()[0];
    assert_eq!(
        (alert.n, alert.first_hour, alert.last_hour),
        (3, midnight / HOUR_MS - 1, midnight / HOUR_MS)
    );
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

/// P6.24: raven-node's writer thread runs the once-a-minute pass on its own
/// (what is due is written without a new event, what is not waits) and
/// reads the open alerts' number without opening any `meta`.
#[test]
fn a_sweep_alone_writes_what_is_due_and_open_alerts_are_counted() {
    if !gate_open() {
        return;
    }
    let dir = sealed_profile();
    let mut ledger = SecurityLedger::open(dir.path()).unwrap();
    let (one, two) = (key(1), key(2));
    let kind = SecKind::ObjectAuthFail;
    assert_eq!(ledger.open_alert_count().unwrap(), 0);
    for at in [NOW, NOW + 10 * SECOND] {
        ledger
            .record(&contact(kind, one, at), Severity::Suspicious, at)
            .unwrap();
    }
    assert_eq!(count_of(&ledger, kind, Some(one)), 1, "one is pending");
    ledger.sweep_due(NOW + 30 * SECOND);
    assert_eq!(count_of(&ledger, kind, Some(one)), 1, "not due yet");
    ledger.sweep_due(NOW + 60 * SECOND);
    assert_eq!(count_of(&ledger, kind, Some(one)), 2, "due: written");
    assert_eq!(ledger.open_alert_count().unwrap(), 1);
    let at = NOW + 61 * SECOND;
    let other = ledger
        .record(&contact(kind, two, at), Severity::Suspicious, at)
        .unwrap()
        .unwrap();
    // A network count is never an alert.
    ledger
        .record(
            &network(
                SecKind::StrangerRefused,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
                at,
            ),
            Severity::Notice,
            at,
        )
        .unwrap();
    assert_eq!(ledger.open_alert_count().unwrap(), 2);
    assert!(ledger.resolve(other, at).unwrap());
    assert_eq!(ledger.open_alert_count().unwrap(), 1);
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

/// Counts and resolved alerts are kept 30 days; open alerts until resolved.
#[test]
fn retention_is_thirty_days() {
    if !gate_open() {
        return;
    }
    let dir = sealed_profile();
    let mut ledger = SecurityLedger::open(dir.path()).unwrap();
    let today = NOW / DAY_MS;
    let at = |days_ago: u64| NOW - days_ago * DAY_MS;
    let kind = SecKind::ContactMalformed;
    for (n, days_ago) in [40u64, 31, 30, 29, 0].into_iter().enumerate() {
        let peer = key(10 + n as u16);
        ledger
            .record(
                &contact(kind, peer, at(days_ago)),
                Severity::Notice,
                at(days_ago),
            )
            .unwrap();
    }
    let ids: Vec<(AlertId, [u8; 32])> = ledger
        .open_alerts()
        .unwrap()
        .iter()
        .map(|a| (a.id, *a.subject.unwrap().key()))
        .collect();
    let id_of = |peer: [u8; 32]| ids.iter().find(|(_, k)| *k == peer).unwrap().0;
    // Resolved 31 and 29 days ago; the oldest stays open.
    assert!(ledger.resolve(id_of(key(11)), at(31)).unwrap());
    assert!(ledger.resolve(id_of(key(13)), at(29)).unwrap());
    ledger.prune(NOW).unwrap();
    let days: Vec<u64> = ledger.counts(0).unwrap().iter().map(|c| c.day).collect();
    assert_eq!(days, [today - 29, today]);
    let open: Vec<[u8; 32]> = ledger
        .open_alerts()
        .unwrap()
        .iter()
        .map(|a| *a.subject.unwrap().key())
        .collect();
    assert_eq!(open.len(), 3, "open alerts stay until resolved");
    assert!(open.contains(&key(10)));
    let resolved: Vec<i64> = {
        let mut stmt = ledger
            .conn
            .prepare("SELECT id FROM sec_alerts WHERE state = 2")
            .unwrap();
        let rows = stmt.query_map([], |r| r.get(0)).unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    };
    assert_eq!(resolved, [id_of(key(13)).0], "resolved 31 days ago: gone");
    let last: i64 = ledger
        .conn
        .query_row(
            "SELECT v FROM sec_meta WHERE k = ?1",
            params![META_LAST_PRUNE],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(uint(last), today);
    // A damaged ledger's copy goes once it is 30 days old.
    let aside = quarantine_path(dir.path());
    std::fs::write(&aside, b"old").unwrap();
    ledger.prune(NOW).unwrap();
    assert!(aside.exists(), "Raven's clock is in the past here");
    ledger.prune(crate::clock::now_ms() + 31 * DAY_MS).unwrap();
    assert!(!aside.exists());
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

/// At most 256 open alerts: the oldest Notice goes first, Alerts last.
#[test]
fn open_alerts_are_capped_with_notices_dropped_first() {
    if !gate_open() {
        return;
    }
    let dir = sealed_profile();
    let mut ledger = SecurityLedger::open(dir.path()).unwrap();
    for n in 0..200u16 {
        let at = NOW + u64::from(n) * HOUR_MS;
        ledger
            .record(
                &contact(SecKind::BindingMismatch, key(n), at),
                Severity::Alert,
                at,
            )
            .unwrap();
    }
    for n in 0..100u16 {
        let at = NOW + u64::from(n) * HOUR_MS;
        ledger
            .record(
                &contact(SecKind::IndexJump, key(1_000 + n), at),
                Severity::Notice,
                at,
            )
            .unwrap();
    }
    let alerts = ledger.open_alerts().unwrap();
    assert_eq!(alerts.len(), 256);
    let alerts_kept = alerts
        .iter()
        .filter(|a| a.severity == Severity::Alert)
        .count();
    assert_eq!(alerts_kept, 200);
    let mut notices: Vec<u16> = alerts
        .iter()
        .filter(|a| a.severity == Severity::Notice)
        .map(|a| u16::from_be_bytes([a.subject.unwrap().key()[0], a.subject.unwrap().key()[1]]))
        .collect();
    notices.sort();
    assert_eq!(notices, (1_044..1_100).collect::<Vec<u16>>(), "the newest");
    // A Notice older than every kept one is dropped at once.
    let id = ledger
        .record(
            &contact(SecKind::IndexJump, key(2_000), NOW - HOUR_MS),
            Severity::Notice,
            NOW,
        )
        .unwrap();
    assert_eq!(id, None);
    assert_eq!(ledger.open_alerts().unwrap().len(), 256);
    // Once only Alerts are left, the oldest of them goes.
    for n in 0..60u16 {
        let at = NOW + (300 + u64::from(n)) * HOUR_MS;
        ledger
            .record(
                &contact(SecKind::RevokedDeviceUsed, key(3_000 + n), at),
                Severity::Alert,
                at,
            )
            .unwrap();
    }
    let alerts = ledger.open_alerts().unwrap();
    assert_eq!(alerts.len(), 256);
    assert!(alerts.iter().all(|a| a.severity == Severity::Alert));
    let binding: Vec<u16> = alerts
        .iter()
        .filter(|a| a.kind == SecKind::BindingMismatch)
        .map(|a| u16::from_be_bytes([a.subject.unwrap().key()[0], a.subject.unwrap().key()[1]]))
        .collect();
    assert_eq!(binding.len(), 196);
    assert!(binding.iter().all(|&n| n >= 4), "the four oldest went");
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

#[test]
fn resolve_actions_seen_and_clear() {
    if !gate_open() {
        return;
    }
    let dir = sealed_profile();
    let dd = dir.path();
    let mut ledger = SecurityLedger::open(dd).unwrap();
    let (one, two) = (key(1), key(2));
    let replay = ledger
        .record(
            &contact(SecKind::ObjectReplay, one, NOW),
            Severity::Suspicious,
            NOW,
        )
        .unwrap()
        .unwrap();
    let skew = ledger
        .record(
            &contact(SecKind::ClockSkew, one, NOW),
            Severity::Notice,
            NOW,
        )
        .unwrap()
        .unwrap();
    let other = ledger
        .record(
            &contact(SecKind::ObjectReplay, two, NOW),
            Severity::Suspicious,
            NOW,
        )
        .unwrap()
        .unwrap();
    // Fixed codes only.
    assert!(ledger.set_action(replay, "REKEY_REQUESTED").unwrap());
    for bad in [
        "rekey requested",
        "",
        "A_CODE_THAT_IS_LONGER_THAN_THIRTY_TWO",
    ] {
        let e = ledger.set_action(replay, bad).err().unwrap();
        assert!(matches!(e, LedgerError::BadAction(_)), "{bad:?}");
    }
    assert!(!ledger.set_action(AlertId(9_999), "PARKED").unwrap());
    let find = |ledger: &SecurityLedger, id: AlertId| {
        ledger
            .open_alerts()
            .unwrap()
            .into_iter()
            .find(|a| a.id == id)
    };
    assert_eq!(
        find(&ledger, replay).unwrap().action.as_deref(),
        Some("REKEY_REQUESTED")
    );
    // Seen: new again only when the severity rises.
    assert!(ledger.mark_seen(replay).unwrap());
    assert!(!ledger.mark_seen(replay).unwrap());
    let at = NOW + 61 * SECOND;
    ledger
        .record(
            &contact(SecKind::ObjectReplay, one, at),
            Severity::Suspicious,
            at,
        )
        .unwrap();
    assert_eq!(find(&ledger, replay).unwrap().state, AlertState::Seen);
    let at = NOW + 62 * SECOND;
    ledger
        .record(
            &contact(SecKind::ObjectReplay, one, at),
            Severity::Alert,
            at,
        )
        .unwrap();
    let alert = find(&ledger, replay).unwrap();
    assert_eq!(
        (alert.state, alert.severity),
        (AlertState::New, Severity::Alert)
    );
    // Resolved: gone from the open list; the next event opens a new alert.
    assert!(ledger.resolve(replay, at).unwrap());
    assert!(!ledger.resolve(replay, at).unwrap());
    assert!(find(&ledger, replay).is_none());
    let at = NOW + 200 * SECOND;
    let again = ledger
        .record(
            &contact(SecKind::ObjectReplay, one, at),
            Severity::Suspicious,
            at,
        )
        .unwrap()
        .unwrap();
    assert_ne!(again, replay);
    // Every open alert about one contact at once; another's stays.
    assert_eq!(ledger.resolve_contact(&one, at).unwrap(), 2);
    let open: Vec<AlertId> = ledger.open_alerts().unwrap().iter().map(|a| a.id).collect();
    assert_eq!(open, [other]);
    assert!(find(&ledger, skew).is_none());
    // The dropped-event counter.
    ledger.note_dropped(3).unwrap();
    ledger.note_dropped(2).unwrap();
    assert_eq!(ledger.dropped().unwrap(), 5);
    // Clear: every row, the counter and a damaged copy go; the ledger stays usable.
    std::fs::write(quarantine_path(dd), b"old").unwrap();
    ledger.clear().unwrap();
    assert!(ledger.open_alerts().unwrap().is_empty());
    assert!(ledger.counts(0).unwrap().is_empty());
    assert_eq!(ledger.dropped().unwrap(), 0);
    assert!(!quarantine_path(dd).exists());
    let resolved: i64 = ledger
        .conn
        .query_row("SELECT COUNT(*) FROM sec_alerts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(resolved, 0, "resolved alerts go too");
    drop(ledger);
    let mut ledger = SecurityLedger::open(dd).unwrap();
    assert!(ledger
        .record(
            &contact(SecKind::ObjectReplay, two, at),
            Severity::Suspicious,
            at
        )
        .unwrap()
        .is_some());
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

/// The data-key rotation reseals the ledger's `meta`, `rotate-meta` keys it
/// again, and `unseal` deletes it (there is no clear shape).
#[test]
fn the_privacy_passes_reseal_rekey_and_unseal_it() {
    if !gate_open() {
        return;
    }
    let dir = sealed_profile();
    let dd = dir.path();
    let (one, relay) = (key(1), key(2));
    let mut ledger = SecurityLedger::open(dd).unwrap();
    ledger
        .record(
            &contact(SecKind::ObjectAuthFail, one, NOW),
            Severity::Suspicious,
            NOW,
        )
        .unwrap();
    let carrier = SecEvent::new(
        SecKind::RelayLinkBroken,
        Attribution::Carrier {
            carrier: relay,
            role: CarrierRole::Relay,
        },
        Via::Relay,
        NOW,
    );
    ledger.record(&carrier, Severity::Suspicious, NOW).unwrap();
    ledger
        .record(
            &network(
                SecKind::StrangerRefused,
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                NOW,
            ),
            Severity::Notice,
            NOW,
        )
        .unwrap();
    let reads =
        |ledger: &SecurityLedger| (ledger.open_alerts().unwrap(), ledger.counts(0).unwrap());
    let before = reads(&ledger);
    assert_eq!(before.0.len(), 2);
    assert_eq!(before.1.len(), 3);
    drop(ledger);

    // The data-key rotation: four sealed `meta` blobs move to the new epoch.
    let current = at_rest::keys_cached(dd).unwrap().current_epoch();
    assert_eq!(rows_off_epoch(dd, current).unwrap(), 0);
    let started = crate::privacy::rotate_data_key_now(dd, NOW, false).unwrap();
    assert!(started.started, "{started:?}");
    let next = at_rest::keys_cached(dd).unwrap().current_epoch();
    assert_ne!(next, current);
    assert_eq!(rows_off_epoch(dd, next).unwrap(), 0);
    let dropped = crate::privacy::rotate_data_key_now(dd, NOW, true).unwrap();
    assert!(dropped.dropped, "{dropped:?}");
    assert_eq!(at_rest::keys_cached(dd).unwrap().epochs(), [next]);
    let ledger = SecurityLedger::open(dd).unwrap();
    assert_eq!(reads(&ledger), before);
    let kh_before: Vec<u8> = ledger
        .conn
        .query_row(
            "SELECT kh_subject FROM sec_alerts WHERE kind = ?1",
            params![i64::from(SecKind::ObjectAuthFail.code())],
            |r| r.get(0),
        )
        .unwrap();
    drop(ledger);

    // rotate-meta: a new lookup key; every subject keyed again.
    let report = crate::privacy::rotate_meta(dd, NOW, &|| true).unwrap();
    assert!(report.rows >= 4, "{report:?}");
    assert_eq!(report.dropped, 0);
    let keys = at_rest::keys_cached(dd).unwrap();
    let ledger = SecurityLedger::open(dd).unwrap();
    assert_eq!(reads(&ledger), before, "the same rows, keyed anew");
    let kh_after: Vec<u8> = ledger
        .conn
        .query_row(
            "SELECT kh_subject FROM sec_alerts WHERE kind = ?1",
            params![i64::from(SecKind::ObjectAuthFail.code())],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(kh_after, kh_before);
    assert_eq!(kh_after, at_rest::index(&keys, ValueType::DeviceKey, &one));
    drop(ledger);

    // unseal: no clear shape, so the ledger goes, and none is made again.
    crate::privacy::unseal_all(dd, &|| true).unwrap();
    assert!(files_named(dd, "security_events").is_empty());
    let e = SecurityLedger::open(dd).err().unwrap();
    assert!(matches!(e, LedgerError::NotSealed), "{e}");
    assert_eq!(unseal(dd).unwrap(), Migration::already());
    assert_eq!(rekey(dd).unwrap(), Migration::already());
    assert_eq!(rows_off_epoch(dd, next).unwrap(), 0);
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

/// Byte patterns the scan looks for, by length (no allocation per probe).
#[derive(Default)]
struct Needles {
    six: HashSet<[u8; 6]>,
    eight: HashSet<[u8; 8]>,
    sixteen: HashSet<[u8; 16]>,
    thirty_two: HashSet<[u8; 32]>,
    /// Text forms (addresses, ports, hex ids), searched in printable runs.
    text: HashSet<String>,
}

impl Needles {
    fn hits(&self, bytes: &[u8]) -> Vec<String> {
        let mut hits = Vec::new();
        for at in 0..bytes.len() {
            let rest = &bytes[at..];
            if rest.len() >= 6 && self.six.contains(&<[u8; 6]>::try_from(&rest[..6]).unwrap()) {
                hits.push(format!("6 bytes at {at}"));
            }
            if rest.len() >= 8
                && self
                    .eight
                    .contains(&<[u8; 8]>::try_from(&rest[..8]).unwrap())
            {
                hits.push(format!("8 bytes at {at}"));
            }
            if rest.len() >= 16
                && self
                    .sixteen
                    .contains(&<[u8; 16]>::try_from(&rest[..16]).unwrap())
            {
                hits.push(format!("16 bytes at {at}"));
            }
            if rest.len() >= 32
                && self
                    .thirty_two
                    .contains(&<[u8; 32]>::try_from(&rest[..32]).unwrap())
            {
                hits.push(format!("32 bytes at {at}"));
            }
        }
        // Printable runs: the text forms can only be inside one.
        let lengths: HashSet<usize> = self.text.iter().map(String::len).collect();
        for run in bytes.split(|b| !(0x20..0x7f).contains(b)) {
            let Ok(run) = std::str::from_utf8(run) else {
                continue;
            };
            for start in 0..run.len() {
                for &len in &lengths {
                    if let Some(piece) = run.get(start..start + len) {
                        if self.text.contains(piece) {
                            hits.push(format!("text {piece:?}"));
                        }
                    }
                }
            }
        }
        hits
    }
}

/// The design's privacy scan: 10,000 random events with random addresses,
/// ports, message ids and network tags through the classifier, the
/// aggregator and the ledger (its writes, the cap, a prune and a resolve
/// that free pages), then every byte of every ledger file searched: no
/// address (raw, with its port, or as text), port, message id, network tag
/// or clear key is there.
#[test]
fn the_privacy_scan_finds_no_address_port_message_id_or_clear_key() {
    if !gate_open() {
        return;
    }
    const LINK_TEXTS: [&str; 8] = [
        LINK_TAG_FAILED,
        NOISE_HANDSHAKE_FAILED,
        BIND_TRUNCATED,
        BIND_BAD_SIGNATURE,
        LAN_HANDSHAKE_TIMEOUT,
        INTERNET_HANDSHAKE_TIMEOUT,
        LAN_FRAME_LENGTH,
        INTERNET_FRAME_LENGTH,
    ];
    let contact_kinds: Vec<SecKind> = SecKind::ALL
        .iter()
        .copied()
        .filter(|k| (20..40).contains(&k.code()))
        .collect();
    let carrier_kinds: Vec<SecKind> = SecKind::ALL
        .iter()
        .copied()
        .filter(|k| (40..60).contains(&k.code()))
        .collect();
    let dir = sealed_profile();
    let dd = dir.path();
    let mut ledger = SecurityLedger::open(dd).unwrap();
    let mut aggregator = Aggregator::new();
    let mut rng = StdRng::seed_from_u64(0x5ec_1ed6e5);
    let mut needles = Needles::default();
    fn random_key(rng: &mut StdRng, needles: &mut Needles) -> [u8; 32] {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        needles.thirty_two.insert(key);
        needles.text.insert(hex::encode(key));
        key
    }
    let contacts: Vec<[u8; 32]> = (0..300)
        .map(|_| random_key(&mut rng, &mut needles))
        .collect();
    let carriers: Vec<[u8; 32]> = (0..20)
        .map(|_| random_key(&mut rng, &mut needles))
        .collect();
    let mut now = NOW;
    let mut network_events = 0;
    for i in 0..10_000u32 {
        now += rng.gen_range(0..2_000);
        let ip = if rng.gen_bool(0.7) {
            let o: [u8; 4] = [
                rng.gen_range(1..=254),
                rng.gen_range(1..=254),
                rng.gen_range(1..=254),
                rng.gen_range(1..=254),
            ];
            IpAddr::V4(Ipv4Addr::from(o))
        } else {
            let mut o = [0u8; 16];
            rng.fill_bytes(&mut o);
            o[0] = 0x20;
            IpAddr::V6(Ipv6Addr::from(o))
        };
        let port: u16 = rng.gen_range(1_024..=65_535);
        let mut message_id = [0u8; 16];
        rng.fill_bytes(&mut message_id);
        let mut tag = [0u8; 8];
        rng.fill_bytes(&mut tag);
        match ip {
            IpAddr::V4(v4) => {
                let mut with_port = [0u8; 6];
                with_port[..4].copy_from_slice(&v4.octets());
                with_port[4..].copy_from_slice(&port.to_be_bytes());
                needles.six.insert(with_port);
            }
            IpAddr::V6(v6) => {
                needles.sixteen.insert(v6.octets());
                needles
                    .eight
                    .insert(<[u8; 8]>::try_from(&v6.octets()[..8]).unwrap());
            }
        }
        needles.text.insert(ip.to_string());
        needles.text.insert(format!("{ip}:{port}"));
        needles.sixteen.insert(message_id);
        needles.text.insert(hex::encode(message_id));
        needles.eight.insert(tag);
        // The classifier: exact texts only, so an error text that carries
        // an address, a port or an id never becomes an event.
        let exact = LINK_TEXTS[rng.gen_range(0..LINK_TEXTS.len())];
        let carrying = format!("{exact}: {ip}:{port} id {}", hex::encode(message_id));
        assert_eq!(classify_link_error(&carrying), None);
        let roll = rng.gen_range(0..100);
        let (kind, who, via) = if roll < 60 {
            network_events += 1;
            (
                classify_link_error(exact).unwrap(),
                Attribution::Network {
                    source: SourceKey::of(ip),
                },
                Via::DirectLink(OutboxCarrier::Internet),
            )
        } else if roll < 85 {
            (
                contact_kinds[rng.gen_range(0..contact_kinds.len())],
                Attribution::Contact {
                    peer: contacts[rng.gen_range(0..contacts.len())],
                },
                Via::Dial(OutboxCarrier::Lan),
            )
        } else if roll < 93 {
            let carrier = carriers[rng.gen_range(0..carriers.len())];
            (
                carrier_kinds[rng.gen_range(0..carrier_kinds.len())],
                Attribution::Carrier {
                    carrier,
                    role: [
                        CarrierRole::Custodian,
                        CarrierRole::Depositor,
                        CarrierRole::Relay,
                    ][rng.gen_range(0..3)],
                },
                Via::Custodian(carrier),
            )
        } else if roll < 97 {
            (SecKind::LocalRollback, Attribution::Local, Via::Local)
        } else {
            (
                SecKind::AdvisoryForged,
                Attribution::Update {
                    passed_by: rng
                        .gen_bool(0.5)
                        .then(|| contacts[rng.gen_range(0..contacts.len())]),
                },
                Via::Relay,
            )
        };
        let ev = SecEvent::new(kind, who, via, now).on_network(tag);
        let severity = aggregator.record(&ev);
        ledger.record(&ev, severity, now).unwrap();
        if i == 5_000 {
            // Free pages: every count and resolved alert so far goes, as if
            // 31 days had passed (the network total counts from here).
            ledger.flush(now).unwrap();
            let open: Vec<AlertId> = ledger.open_alerts().unwrap().iter().map(|a| a.id).collect();
            for id in open {
                ledger.resolve(id, now).unwrap();
            }
            ledger.prune(now + 31 * DAY_MS).unwrap();
            assert!(ledger.counts(0).unwrap().is_empty());
            network_events = 0;
        }
    }
    ledger.flush(now).unwrap();
    // The ledger did keep what it should.
    let counts = ledger.counts(0).unwrap();
    let network_total: u64 = counts
        .iter()
        .filter(|c| (1..20).contains(&c.kind.code()) && c.subject.is_none())
        .map(|c| c.n)
        .sum();
    assert_eq!(network_total, network_events);
    assert!(counts.iter().any(|c| c.subject.is_some()));
    assert!(!ledger.open_alerts().unwrap().is_empty());
    drop(ledger);

    // The scan itself finds what it looks for (each form once).
    let mut planted = vec![0u8; 64];
    planted.extend_from_slice(needles.six.iter().next().unwrap());
    planted.extend_from_slice(&[0; 8]);
    planted.extend_from_slice(needles.sixteen.iter().next().unwrap());
    planted.extend_from_slice(&[0; 8]);
    planted.extend_from_slice(needles.thirty_two.iter().next().unwrap());
    planted.push(0);
    let address = needles.text.iter().find(|t| t.contains('.')).unwrap();
    planted.extend_from_slice(format!("<{address}>").as_bytes());
    planted.push(0);
    assert!(
        needles.hits(&planted).len() >= 4,
        "{:?}",
        needles.hits(&planted)
    );

    let files = files_named(dd, "security_events.sqlite");
    assert!(!files.is_empty());
    let mut scanned = 0;
    for name in files {
        let bytes = std::fs::read(dd.join(&name)).unwrap();
        scanned += bytes.len();
        let hits = needles.hits(&bytes);
        assert!(hits.is_empty(), "{name}: {:?}", &hits[..hits.len().min(10)]);
    }
    assert!(scanned > 64 * 1024, "the scan read {scanned} bytes");
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}
