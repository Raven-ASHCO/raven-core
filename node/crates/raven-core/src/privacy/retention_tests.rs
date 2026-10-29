//! PP.9 tests: chats kept for 7 / 30 / 90 days or always ([`chat_keep`],
//! [`apply_retention`]). An existing profile waits out the grace and is told
//! once; a new one starts at once; each setting deletes exactly the older
//! rows and "always" nothing; a received message's age counts from when
//! this computer stored it (a legacy row's from its conservative age); a
//! plain profile writes no `stored_at_ms`; messages still waiting to be sent
//! stay; an older build's `node_policy.json` cannot change the setting; a
//! pass that found nothing old reads no history until something can go; the
//! log line is counts only. Profiles are temp folders; the sealed ones take
//! their keys from the test build's lab K_hist (never a keychain item).

use super::*;
use crate::chat_history::{ChatHistory, ChatHistoryEntry};
use crate::contact_book::tests::profile;
use std::collections::HashSet;

const MIN: u64 = 60 * 1000;

fn no_outbox() -> Result<HashSet<[u8; 16]>, String> {
    Ok(HashSet::new())
}

fn row(n: u8, direction: &str, created_at_ms: u64) -> ChatHistoryEntry {
    ChatHistoryEntry {
        message_id_hex: hex::encode([n; 16]),
        direction: direction.into(),
        peer_petname: String::new(),
        peer_tag: String::new(),
        peer_pub_hex: hex::encode([0x40 + n % 4; 32]),
        created_at_ms,
        delivery: if direction == "in" {
            "received"
        } else {
            "delivered"
        }
        .into(),
        preview: String::new(),
        body: format!("m{n}"),
        stored_at_ms: None,
    }
}

/// Append `entry` as this computer stores it `age_ms` ago (this thread's
/// clock moved back; a sealed profile stamps `stored_at_ms` with it).
fn store_aged(dd: &Path, entry: ChatHistoryEntry, age_ms: u64) {
    crate::clock::set_for_this_thread(Some(-i64::try_from(age_ms).unwrap()));
    let stored = ChatHistory::append_persisted(dd, entry);
    crate::clock::set_for_this_thread(None);
    stored.unwrap();
}

fn bodies(dd: &Path) -> Vec<String> {
    ChatHistory::load(dd)
        .unwrap()
        .entries
        .into_iter()
        .map(|e| e.body)
        .collect()
}

fn recorded(dd: &Path) -> PrivacyFile {
    read_file(dd).unwrap().unwrap_or_default()
}

/// Seal `dd` as raven-node's start would at `now`.
fn sealed_at(dd: &Path, now: u64) {
    crate::at_rest::tests::expect_key_file(dd);
    let report = migrate_all(dd, now, MigratePolicy::Allow).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
}

/// A sealed profile created by this build, its retention clock started.
fn new_sealed_profile() -> tempfile::TempDir {
    let dir = profile();
    sealed_at(dir.path(), crate::clock::now_ms());
    dir
}

/// The next pass looks again at once (`raven chats keep` does this).
fn forget_marker(dd: &Path) {
    update(dd, |file| file.retention_next_at_ms = None).unwrap();
}

#[test]
fn retention_waits_for_the_grace_on_an_existing_profile() {
    assert_eq!(RETENTION_GRACE_MS, 7 * DAY_MS);
    let dir = profile();
    let dd = dir.path();
    let t0 = crate::clock::now_ms();
    // An older build's chats (plain profile: no `stored_at_ms`).
    ChatHistory::append_persisted(dd, row(1, "out", t0 - 40 * DAY_MS)).unwrap();
    sealed_at(dd, t0);
    let grace = retention_grace_ms();
    let file = recorded(dd);
    assert_eq!(file.retention_starts_at_ms, Some(t0 + grace));
    assert!(file.notices.retention_pending);
    // A second pass does not move the start.
    sealed_at(dd, t0 + DAY_MS);
    assert_eq!(retention_starts_at(dd), Some(t0 + grace));

    if grace > 0 {
        let waiting = apply_retention_with(dd, t0 + grace - 1, no_outbox).unwrap();
        assert!(!waiting.ran);
        assert_eq!(bodies(dd), ["m1"], "nothing goes during the grace");
    }
    let went = apply_retention_with(dd, t0 + grace, no_outbox).unwrap();
    assert!(went.ran);
    assert_eq!((went.history, went.chats), (1, 1));
    assert!(bodies(dd).is_empty());
    assert!(
        rotation_due(dd),
        "what went is in older copies until a rotation"
    );
}

#[test]
fn new_profile_retention_starts_at_once() {
    let dir = profile();
    let dd = dir.path();
    let t0 = crate::clock::now_ms();
    sealed_at(dd, t0);
    let file = recorded(dd);
    assert_eq!(file.retention_starts_at_ms, Some(t0));
    assert!(!file.notices.retention_pending);
    assert_eq!(take_retention_notice(dd), None);
    store_aged(dd, row(1, "in", 0), 31 * DAY_MS);
    store_aged(dd, row(2, "in", 0), 29 * DAY_MS);
    let went = apply_retention_with(dd, crate::clock::now_ms(), no_outbox).unwrap();
    assert_eq!(went.history, 1);
    assert_eq!(bodies(dd), ["m2"]);
}

/// 7 / 30 / 90 days: a row a minute younger than the setting stays, one a
/// minute older goes, in both directions (ages on this thread's lab clock).
#[test]
fn each_setting_deletes_exactly_the_older_entries() {
    for keep in [ChatKeep::Days7, ChatKeep::Days30, ChatKeep::Days90] {
        let dir = new_sealed_profile();
        let dd = dir.path();
        set_chat_keep(dd, keep).unwrap();
        assert_eq!(chat_keep(dd), keep);
        let keep_ms = keep.days().unwrap() * DAY_MS;
        store_aged(dd, row(1, "in", 0), keep_ms + MIN);
        store_aged(dd, row(2, "out", 0), keep_ms + MIN);
        store_aged(dd, row(3, "in", 0), keep_ms - MIN);
        store_aged(dd, row(4, "out", 0), keep_ms - MIN);
        let went = apply_retention_with(dd, crate::clock::now_ms(), no_outbox).unwrap();
        assert_eq!((went.history, went.chats), (2, 2), "{keep:?}");
        assert_eq!(bodies(dd), ["m3", "m4"], "{keep:?}");
    }
    // The default, and what the file says.
    let dir = new_sealed_profile();
    assert_eq!(chat_keep(dir.path()), ChatKeep::Days30);
    for keep in ChatKeep::ALL {
        assert_eq!(ChatKeep::parse(keep.as_str()), Some(keep));
    }
    assert_eq!(ChatKeep::parse("365d"), None);
}

#[test]
fn always_deletes_nothing() {
    let dir = new_sealed_profile();
    let dd = dir.path();
    set_chat_keep(dd, ChatKeep::Always).unwrap();
    store_aged(dd, row(1, "in", 0), 400 * DAY_MS);
    let before = std::fs::read(dd.join(PRIVACY_FILE)).unwrap();
    let went = apply_retention_with(dd, crate::clock::now_ms(), || {
        panic!("always read the outbox")
    })
    .unwrap();
    assert_eq!(went, RetentionReport::default());
    assert_eq!(bodies(dd), ["m1"]);
    assert_eq!(std::fs::read(dd.join(PRIVACY_FILE)).unwrap(), before);
    // A word this build does not know (a newer build's) keeps everything.
    update(dd, |file| file.chat_keep = Some("365d".into())).unwrap();
    assert_eq!(chat_keep(dd), ChatKeep::Always);
    let went = apply_retention_with(dd, crate::clock::now_ms(), no_outbox).unwrap();
    assert!(!went.ran);
    assert_eq!(bodies(dd), ["m1"]);
    // So does a settings file that cannot be read.
    std::fs::write(dd.join(PRIVACY_FILE), b"{not json").unwrap();
    assert_eq!(chat_keep(dd), ChatKeep::Always);
    let went = apply_retention_with(dd, crate::clock::now_ms(), no_outbox).unwrap();
    assert!(!went.ran);
    assert_eq!(bodies(dd), ["m1"]);
    assert_eq!(std::fs::read(dd.join(PRIVACY_FILE)).unwrap(), b"{not json");
}

/// Review R09: a message its sender stamped 6 days before it arrived stays
/// the whole 7 days after it arrived (by its own stamp it would go a day
/// later).
#[test]
fn an_inbound_message_carried_6_days_is_kept_7_days_after_arrival() {
    let dir = new_sealed_profile();
    let dd = dir.path();
    set_chat_keep(dd, ChatKeep::Days7).unwrap();
    let arrived = crate::clock::now_ms();
    ChatHistory::append_persisted(dd, row(1, "in", arrived - 6 * DAY_MS)).unwrap();
    let stored = ChatHistory::load(dd).unwrap().entries[0]
        .stored_at_ms
        .unwrap();
    assert!(stored >= arrived, "stamped with this computer's clock");
    for at in [arrived + DAY_MS + HOUR_MS, stored + 7 * DAY_MS - MIN] {
        forget_marker(dd);
        let went = apply_retention_with(dd, at, no_outbox).unwrap();
        assert_eq!(went.history, 0);
        assert_eq!(bodies(dd), ["m1"]);
    }
    forget_marker(dd);
    let went = apply_retention_with(dd, stored + 7 * DAY_MS + MIN, no_outbox).unwrap();
    assert_eq!(went.history, 1);
    assert!(bodies(dd).is_empty());
}

/// Rows an older build (or a plain profile) wrote have no `stored_at_ms`:
/// an outbound row counts from its own stamp, a received one from its
/// sender's stamp plus the longest an envelope lives (7 days).
#[test]
fn legacy_rows_without_stored_at_use_the_conservative_age() {
    let dir = profile();
    let dd = dir.path();
    let now = crate::clock::now_ms();
    let lifetime = crate::indexed_session_store::MAX_ENDPOINT_ENVELOPE_LIFETIME_MS;
    for entry in [
        row(1, "out", now - 30 * DAY_MS - MIN),
        row(2, "out", now - 30 * DAY_MS + MIN),
        row(3, "in", now - 30 * DAY_MS - lifetime - MIN),
        row(4, "in", now - 30 * DAY_MS - MIN),
    ] {
        ChatHistory::append_persisted(dd, entry).unwrap();
    }
    sealed_at(dd, now);
    start_retention_for_tests(dd, now, ChatKeep::Days30);
    let history = ChatHistory::load(dd).unwrap();
    assert!(history.entries.iter().all(|e| e.stored_at_ms.is_none()));
    assert_eq!(history.entries[0].kept_since_ms(), now - 30 * DAY_MS - MIN);
    assert_eq!(
        history.entries[3].kept_since_ms(),
        now - 30 * DAY_MS - MIN + lifetime
    );
    let went = apply_retention_with(dd, now, no_outbox).unwrap();
    assert_eq!(went.history, 2);
    assert_eq!(bodies(dd), ["m2", "m4"]);
}

#[test]
fn plain_mode_writes_no_stored_at_field() {
    let dir = profile();
    let dd = dir.path();
    assert_eq!(mode(dd), Mode::Plain);
    ChatHistory::append_persisted(dd, row(1, "in", 5)).unwrap();
    let plain = ChatHistory::load(dd).unwrap();
    assert_eq!(plain.entries[0].stored_at_ms, None);
    let text = serde_json::to_string(&plain).unwrap();
    assert!(!text.contains("stored_at_ms"), "{text}");
    // Sealed: a new row records it and an update keeps it.
    sealed_at(dd, crate::clock::now_ms());
    store_aged(dd, row(2, "out", 6), DAY_MS);
    let first = ChatHistory::load(dd).unwrap().entries[1]
        .stored_at_ms
        .unwrap();
    let mut delivered = row(2, "out", 6);
    delivered.delivery = "read".into();
    ChatHistory::append_persisted(dd, delivered).unwrap();
    let rows = ChatHistory::load(dd).unwrap().entries;
    assert_eq!(rows[1].stored_at_ms, Some(first));
    assert_eq!(rows[0].stored_at_ms, None, "a legacy row stays without one");
    assert!(serde_json::to_string(&rows[1])
        .unwrap()
        .contains("\"stored_at_ms\""));
}

/// A message still waiting to be sent keeps its old row and its staged
/// body; a finished message's leftover staged body goes with the old chats;
/// an outbox that cannot be read deletes nothing.
#[test]
fn waiting_messages_are_never_deleted() {
    let dir = new_sealed_profile();
    let dd = dir.path();
    set_chat_keep(dd, ChatKeep::Days7).unwrap();
    let now = crate::clock::now_ms();
    for n in [1, 2] {
        store_aged(dd, row(n, "out", now - 8 * DAY_MS), 8 * DAY_MS);
    }
    for n in [1, 3] {
        crate::chat_history::stage_outbound_body(
            dd,
            &[0x41; 32],
            &[n; 32],
            &[n; 32],
            &[n; 16],
            now - 8 * DAY_MS,
            "staged",
        )
        .unwrap();
    }
    let staged = |dd: &Path| -> Vec<String> {
        crate::chat_history::list_staged_outbound_bodies(dd)
            .unwrap()
            .into_iter()
            .map(|e| e.message_id_hex)
            .collect()
    };
    let unreadable = apply_retention_with(dd, now, || Err("store busy".into()));
    assert!(unreadable.is_err());
    assert_eq!(bodies(dd), ["m1", "m2"]);
    assert_eq!(staged(dd).len(), 2);

    forget_marker(dd);
    let waiting = || Ok(HashSet::from([[1u8; 16]]));
    let went = apply_retention_with(dd, now, waiting).unwrap();
    assert_eq!(
        (went.history, went.waiting, went.staged),
        (1, 1, 1),
        "{went:?}"
    );
    assert_eq!(bodies(dd), ["m1"]);
    assert_eq!(staged(dd), [hex::encode([1u8; 16])]);
}

/// The setting lives in `privacy.json`: an older build that saves
/// `node_policy.json` (it drops fields it does not know) cannot turn
/// "always" back into the default, and an older build of the pack that
/// rewrites `privacy.json` keeps the fields it does not know.
#[test]
fn an_older_build_saving_node_policy_cannot_change_retention() {
    let dir = new_sealed_profile();
    let dd = dir.path();
    set_chat_keep(dd, ChatKeep::Always).unwrap();
    let starts = retention_starts_at(dd);
    std::fs::write(
        dd.join(crate::node_policy::POLICY_FILE),
        br#"{"bridge":false,"store":false,"relay":false,"endpoint":true,"auto_policy":true}"#,
    )
    .unwrap();
    crate::node_policy::save_policy(dd, &crate::node_policy::NodePolicy::default()).unwrap();
    assert_eq!(chat_keep(dd), ChatKeep::Always);

    #[derive(Serialize, Deserialize)]
    struct OlderPrivacyFile {
        #[serde(default)]
        v: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<String>,
        #[serde(flatten)]
        other: serde_json::Map<String, serde_json::Value>,
    }
    let path = dd.join(PRIVACY_FILE);
    let mut older: OlderPrivacyFile =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    older.mode = Some("sealed".into());
    std::fs::write(&path, serde_json::to_vec(&older).unwrap()).unwrap();
    assert_eq!(chat_keep(dd), ChatKeep::Always);
    assert_eq!(retention_starts_at(dd), starts);
}

#[test]
fn notice_once() {
    let dir = profile();
    let dd = dir.path();
    let t0 = crate::clock::now_ms();
    ChatHistory::append_persisted(dd, row(1, "in", t0)).unwrap();
    sealed_at(dd, t0);
    let first = t0 + retention_grace_ms();
    assert_eq!(retention_notice_due(dd), Some(first));
    assert_eq!(take_retention_notice(dd), Some((ChatKeep::Days30, first)));
    assert_eq!(take_retention_notice(dd), None);
    assert_eq!(retention_notice_due(dd), None);
    assert_eq!(
        retention_notice_text(ChatKeep::Days30, "on Sat 25 Oct"),
        "New: Raven deletes chats older than 30 days from this computer. The first deletion is \
         on Sat 25 Oct. To keep chats longer or always: `raven chats keep 90d` or `raven chats \
         keep always`."
    );
    // Someone who chose "always" first is not told.
    let other = profile();
    ChatHistory::append_persisted(other.path(), row(1, "in", t0)).unwrap();
    sealed_at(other.path(), t0);
    set_chat_keep(other.path(), ChatKeep::Always).unwrap();
    assert_eq!(retention_notice_due(other.path()), None);
    assert_eq!(take_retention_notice(other.path()), None);
    assert!(!recorded(other.path()).notices.retention_pending);
    // The `raven chats keep` words (UX copy).
    assert_eq!(
        chat_keep_text(ChatKeep::Days30),
        "Keep chats on this computer for 30 days. Older chats are deleted from this computer. \
         Your friends' copies aren't."
    );
    assert_eq!(
        chat_keep_text(ChatKeep::Always),
        "Raven keeps your chats on this computer until you delete them."
    );
}

#[test]
fn counts_only_logs() {
    let report = RetentionReport {
        ran: true,
        history: 2,
        chats: 1,
        inbox: InboxDeletion {
            deleted: 3,
            skipped: 1,
            scrubbed: true,
        },
        staged: 1,
        waiting: 4,
    };
    assert_eq!(report.removed(), 6);
    let line = report.to_string();
    assert_eq!(
        line,
        "history=2 chats=1 inbox=3 staged=1 waiting=4 skipped=1"
    );
    for word in line.split(' ') {
        let (key, value) = word.split_once('=').unwrap();
        assert!(key.bytes().all(|b| b.is_ascii_lowercase()), "{word}");
        assert!(value.bytes().all(|b| b.is_ascii_digit()), "{word}");
    }
}

/// A pass that found nothing old records when something can go; until then
/// a pass reads no history (no keystore call), and a pass that failed
/// tries again an hour later. A new setting looks again at once.
#[test]
fn a_pass_that_found_nothing_old_reads_no_history_until_something_can_go() {
    let dir = new_sealed_profile();
    let dd = dir.path();
    let t0 = crate::clock::now_ms();
    ChatHistory::append_persisted(dd, row(1, "in", t0)).unwrap();
    let first = apply_retention_with(dd, t0, no_outbox).unwrap();
    assert!(first.ran);
    assert_eq!(first.removed(), 0);
    assert_eq!(recorded(dd).retention_next_at_ms, Some(t0 + DAY_MS));
    // An unreadable history is not even opened before then.
    let history = crate::chat_history::history_path(dd);
    let good = std::fs::read(&history).unwrap();
    std::fs::write(&history, b"RVNHIST1 not a history").unwrap();
    let skipped = apply_retention_with(dd, t0 + DAY_MS - 1, || panic!("read the outbox")).unwrap();
    assert!(!skipped.ran);
    let failed = apply_retention_with(dd, t0 + DAY_MS, no_outbox);
    assert!(failed.is_err());
    assert_eq!(
        recorded(dd).retention_next_at_ms,
        Some(t0 + DAY_MS + RETENTION_RETRY_MS)
    );
    std::fs::write(&history, good).unwrap();
    // The row is 30 days old: the next pass after that deletes it, and a
    // shorter setting looks at once.
    let stored = ChatHistory::load(dd).unwrap().entries[0]
        .stored_at_ms
        .unwrap();
    set_chat_keep(dd, ChatKeep::Days7).unwrap();
    assert_eq!(recorded(dd).retention_next_at_ms, None);
    let at = stored + 7 * DAY_MS + MIN;
    assert_eq!(apply_retention_with(dd, at, no_outbox).unwrap().history, 1);
    // A clock set far back does not wait for a time it cannot reach.
    update(dd, |file| {
        file.retention_next_at_ms = Some(at + 400 * DAY_MS)
    })
    .unwrap();
    assert!(apply_retention_with(dd, at, no_outbox).unwrap().ran);
}

/// Only a build that may seal starts the clock: a debug build without the
/// lab switch records nothing (and so deletes nothing), whatever the
/// profile holds; a profile without an identity is never given a
/// `privacy.json` by `raven chats keep`.
#[test]
fn only_a_build_that_may_seal_starts_the_clock() {
    let dir = profile();
    let dd = dir.path();
    ChatHistory::append_persisted(dd, row(1, "in", 1)).unwrap();
    let report = migrate_all(dd, crate::clock::now_ms(), MigratePolicy::Never).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::NotAllowed);
    assert_eq!(retention_starts_at(dd), None);
    assert!(
        !apply_retention_with(dd, u64::MAX / 2, no_outbox)
            .unwrap()
            .ran
    );
    assert_eq!(bodies(dd), ["m1"]);

    let fresh = tempfile::tempdir().unwrap();
    assert!(set_chat_keep(fresh.path(), ChatKeep::Days7).is_err());
    assert!(!fresh.path().join(PRIVACY_FILE).exists());
    assert!(crate::identity_store::first_install_allowed(fresh.path()));
}

/// `raven chats status`: when the next messages go and how many, from the
/// grace's end on an existing profile; nothing for "always" or a message
/// still waiting.
#[test]
fn the_outlook_says_when_and_how_many() {
    let dir = new_sealed_profile();
    let dd = dir.path();
    let now = crate::clock::now_ms();
    let mut a = row(1, "in", 0);
    a.peer_pub_hex = hex::encode([0x51; 32]);
    let mut b = row(2, "in", 0);
    b.peer_pub_hex = hex::encode([0x52; 32]);
    store_aged(dd, a, 29 * DAY_MS);
    store_aged(dd, b, 29 * DAY_MS);
    store_aged(dd, row(3, "out", 0), 10 * DAY_MS);
    let outlook = retention_outlook(dd, now).unwrap();
    assert_eq!(outlook.keep, ChatKeep::Days30);
    let next = outlook.next_at_ms.unwrap();
    assert!(
        next > now + DAY_MS - MIN && next <= now + DAY_MS + MIN,
        "{next} {now}"
    );
    assert_eq!((outlook.messages, outlook.chats), (2, 2));
    // Due already: now, everything old.
    let later = retention_outlook(dd, now + 25 * DAY_MS).unwrap();
    assert!(later.next_at_ms.unwrap() <= now + 25 * DAY_MS);
    assert_eq!((later.messages, later.chats), (3, 3));
    // The grace of an existing profile: nothing before its end.
    start_retention_for_tests(dd, now + 3 * DAY_MS, ChatKeep::Days30);
    let grace = retention_outlook(dd, now).unwrap();
    assert_eq!(grace.next_at_ms, Some(now + 3 * DAY_MS));
    assert_eq!((grace.messages, grace.chats), (2, 2));
    set_chat_keep(dd, ChatKeep::Always).unwrap();
    let always = retention_outlook(dd, now).unwrap();
    assert_eq!((always.next_at_ms, always.messages), (None, 0));
    // Nothing changed on disk.
    assert_eq!(bodies(dd), ["m1", "m2", "m3"]);
}
