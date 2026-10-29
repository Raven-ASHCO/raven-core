//! The update state (step P6.44): the acceptance rules on an in-memory
//! state first (any build), then the file, the gate and the events (a debug
//! build opens the gates for its own thread; a release build checks only
//! that nothing opens).

use super::*;
use crate::advisory::{AdvisoryDraft, EntryKind, Severity};
use crate::identity::Identity;
use crate::release_keys::test_keys::{key_set, key_set_of, signer, signers};
use crate::security_events::{Attribution, SecEvent};
use crate::security_sense::tests::Capture;
use crate::tlog::{SthDraft, MAX_LOG_ENTRIES};

/// 2026-10-24T00:00:00Z.
const T0: u64 = 1_792_800_000_000;
const DAY_MS: u64 = 86_400_000;
/// The test key set's seed bytes, by key index.
const CURRENT: [u8; 3] = [0x11, 0x22, 0x33];
/// The set a rotation names: key 0x11 replaced by 0x44.
const NEXT: [u8; 3] = [0x22, 0x33, 0x44];
/// A friend who passes things on.
const FRIEND: [u8; 32] = [0xF1; 32];

fn set(seeds: &[u8; 3]) -> KeySet {
    key_set_of(2, seeds)
}

fn build(seeds: &[u8; 3]) -> Build {
    Build {
        key_set: Some(set(seeds)),
        serial: 0,
        floor: (0, [0; 32]),
    }
}

fn no_keys() -> Build {
    Build {
        key_set: None,
        serial: 0,
        floor: (0, [0; 32]),
    }
}

/// Keys 0 and 1 of the set with these seed bytes.
fn sign_with(seeds: &[u8; 3]) -> [Identity; 2] {
    [signer(seeds[0]), signer(seeds[1])]
}

fn notice(text: &str) -> Entry {
    Entry {
        kind: EntryKind::Notice,
        severity: Severity::Info,
        target: "notice".to_owned(),
        arg: text.as_bytes().to_vec(),
        text_id: 0,
    }
}

fn rotation(seeds: &[u8; 3]) -> Entry {
    Entry {
        kind: EntryKind::KeySet,
        severity: Severity::Info,
        target: "keys".to_owned(),
        arg: set(seeds).encode(),
        text_id: 0,
    }
}

fn floor_entry(serial: u64) -> Entry {
    Entry {
        kind: EntryKind::ReleaseFloor,
        severity: Severity::Deprecated,
        target: "raven".to_owned(),
        arg: serial.to_be_bytes().to_vec(),
        text_id: 0,
    }
}

fn advisory(seeds: &[u8; 3], serial: u64, prev: [u8; 32], entries: Vec<Entry>) -> Advisory {
    let ids = sign_with(seeds);
    AdvisoryDraft {
        serial,
        issued_at_ms: T0 + serial * DAY_MS,
        key_set_digest: set(seeds).digest(),
        prev_digest: prev,
        entries,
    }
    .sign(&[(0, &ids[0]), (1, &ids[1])])
    .unwrap()
}

/// The snapshot of `entries`, its tree head signed by keys 0 and 1 of the
/// set with these seed bytes.
fn snapshot(entries: &[LogEntry], seeds: &[u8; 3]) -> Vec<u8> {
    let ids = sign_with(seeds);
    let sth = SthDraft::of_entries(entries, T0 + entries.len() as u64, set(seeds).digest())
        .sign(&[(0, &ids[0]), (1, &ids[1])])
        .unwrap();
    Snapshot::new(entries.to_vec(), sth).unwrap().encode()
}

fn entry(kind: EntryType, digest: [u8; 32], at: usize) -> LogEntry {
    LogEntry {
        kind,
        digest,
        logged_at_ms: T0 + at as u64 * DAY_MS,
    }
}

/// The Raven project's history as the tests publish it: each advisory is
/// signed by the current signers, names the one before it and is logged
/// (after the key set at entry 0).
struct Project {
    seeds: [u8; 3],
    log: Vec<LogEntry>,
    prev: [u8; 32],
    serial: u64,
}

impl Project {
    fn new() -> Self {
        Self {
            seeds: CURRENT,
            log: vec![entry(EntryType::KeySet, set(&CURRENT).digest(), 0)],
            prev: [0; 32],
            serial: 0,
        }
    }

    /// The next advisory with these entries, logged: (its bytes, the
    /// snapshot it travels with).
    fn publish(&mut self, entries: Vec<Entry>) -> (Vec<u8>, Vec<u8>) {
        self.serial += 1;
        let a = advisory(&self.seeds, self.serial, self.prev, entries);
        self.prev = a.digest();
        self.log
            .push(entry(EntryType::Advisory, a.digest(), self.log.len()));
        let snap = snapshot(&self.log, &self.seeds);
        if let Some(next) = a.entries.iter().find_map(Entry::key_set) {
            self.seeds = if next == set(&NEXT) {
                NEXT
            } else {
                panic!("tests rotate to NEXT only")
            };
        }
        (a.bytes().to_vec(), snap)
    }

    /// An advisory signed and logged like the next one, but not published
    /// (`prev`: the digest it names), and the snapshot of the log with it.
    fn fork(&self, serial: u64, prev: [u8; 32], text: &str) -> (Vec<u8>, Vec<u8>) {
        let a = advisory(&self.seeds, serial, prev, vec![notice(text)]);
        let mut log = self.log.clone();
        log.push(entry(EntryType::Advisory, a.digest(), log.len()));
        (a.bytes().to_vec(), snapshot(&log, &self.seeds))
    }

    fn snapshot(&self) -> Vec<u8> {
        snapshot(&self.log, &self.seeds)
    }
}

// ── The rules, in memory ────────────────────────────────────────────

#[test]
fn no_key_set_refuses_everything_with_no_release_keys() {
    // This build: nothing compiled before the key ceremony.
    assert_eq!(RELEASE_KEY_SET_V1, None);
    assert_eq!(compiled_key_set(), None);
    if lab_key_set().is_none() {
        assert_eq!(Build::this().key_set, None);
    }
    assert_eq!(Build::this().serial, BUILD_SERIAL);
    assert_eq!(BUILD_SERIAL, 0, "a development build");
    assert_eq!(BUILD_ADVISORY_FLOOR, (0, [0; 32]));
    let mut project = Project::new();
    let (bytes, snap) = project.publish(vec![notice("one")]);
    let mut state = UpdateState::empty(no_keys());
    assert_eq!(state.key_set(), None);
    assert_eq!(
        state.accept_advisory(&bytes, &snap, T0),
        Err(Refused::NoReleaseKeys)
    );
    // Not even garbage gets as far as the decoder.
    assert_eq!(
        state.accept_advisory(b"junk", b"junk", T0),
        Err(Refused::NoReleaseKeys)
    );
    assert_eq!(state.accept_log(&snap, T0), Err(Refused::NoReleaseKeys));
    assert_eq!(state.verify_ctx(false).key_set, None);
    assert!(!state.changed);
    assert_eq!(Refused::NoReleaseKeys.sec_kind(), None);
    assert_eq!(Refused::NoReleaseKeys.code(), "NO_RELEASE_KEYS");
    assert!(NO_RELEASE_KEYS_TEXT.contains("no Raven release keys"));
}

#[test]
fn advisories_are_accepted_in_order_and_gaps_are_accepted() {
    let mut project = Project::new();
    let mut state = UpdateState::empty(build(&CURRENT));
    let (one, snap1) = project.publish(vec![notice("one")]);
    assert_eq!(
        state.accept_advisory(&one, &snap1, T0),
        Ok(Applied::Stored {
            serial: 1,
            succession: Succession::First,
            rotated_to: None,
            log: Consistency::Extends,
        })
    );
    assert_eq!(state.advisory().unwrap().bytes(), &one[..]);
    assert_eq!(state.log_entries(), &project.log[..]);
    // The same one again changes nothing.
    state.changed = false;
    assert_eq!(
        state.accept_advisory(&one, &snap1, T0),
        Ok(Applied::Unchanged)
    );
    assert!(!state.changed);
    let (two, snap2) = project.publish(vec![notice("two")]);
    assert!(matches!(
        state.accept_advisory(&two, &snap2, T0),
        Ok(Applied::Stored {
            serial: 2,
            succession: Succession::Next,
            ..
        })
    ));
    // #3 never reached this node: #4 is accepted across the gap.
    project.publish(vec![notice("three")]);
    let (four, snap4) = project.publish(vec![notice("four"), floor_entry(9)]);
    assert!(matches!(
        state.accept_advisory(&four, &snap4, T0),
        Ok(Applied::Stored {
            serial: 4,
            succession: Succession::Gap,
            log: Consistency::Extends,
            ..
        })
    ));
    assert_eq!(state.newest().unwrap().0, 4);
    assert_eq!(state.release_floor(), 9);
    assert_eq!(state.verify_ctx(false).release_floor, 9);
    assert_eq!(state.log_entries().len(), 5);
    assert_eq!(state.frozen(), None);
}

#[test]
fn a_rollback_is_ignored_and_counted() {
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let (two, snap2) = project.publish(vec![notice("two")]);
    let mut state = UpdateState::empty(build(&CURRENT));
    state.accept_advisory(&two, &snap2, T0).unwrap();
    state.changed = false;
    let before = state.to_stored();
    let refused = state.accept_advisory(&one, &snap1, T0);
    assert_eq!(refused, Err(Refused::Rollback { newest: 2 }));
    assert_eq!(state.to_stored(), before, "ignored");
    assert!(!state.changed, "nothing to write");
    assert_eq!(
        refused.unwrap_err().sec_kind(),
        Some(SecKind::AdvisoryRollback)
    );
    // Counted: the file-level test below notes it as an event about the
    // friend who passed it on.
}

#[test]
fn equivocation_freezes_and_keeps_both() {
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let mut state = UpdateState::empty(build(&CURRENT));
    state.accept_advisory(&one, &snap1, T0).unwrap();
    // Another #1.
    let (other_one, other_snap) = project.fork(1, [0; 32], "another one");
    assert_eq!(
        state.accept_advisory(&other_one, &other_snap, T0 + 5),
        Err(Refused::Equivocation)
    );
    let evidence = state.frozen().unwrap().clone();
    assert_eq!(evidence.reason, FreezeReason::Equivocation);
    assert_eq!(evidence.ours, one);
    assert_eq!(evidence.theirs, other_one);
    assert_eq!(
        evidence.ours_digest,
        Advisory::decode(&one).unwrap().digest()
    );
    assert_eq!(evidence.advisory_serial, 1);
    assert_eq!(evidence.at_ms, T0 + 5);
    assert_eq!(evidence.key_set_digest, set(&CURRENT).digest());
    assert!(state.changed, "the freeze is written");
    assert_eq!(state.advisory().unwrap().bytes(), &one[..], "#1 kept");
    // Frozen: nothing new is applied, not even the real #2 or a longer log.
    let (two, snap2) = project.publish(vec![notice("two")]);
    assert_eq!(
        state.accept_advisory(&two, &snap2, T0),
        Err(Refused::Frozen)
    );
    assert_eq!(state.accept_log(&snap2, T0), Err(Refused::Frozen));
    assert_eq!(Refused::Frozen.sec_kind(), None);
    // A forged one is still recognised as forged.
    let mut forged = two.clone();
    forged[100] ^= 1;
    assert!(matches!(
        state.accept_advisory(&forged, &snap2, T0),
        Err(Refused::Forged(_))
    ));
    // The broken chain: #2 naming another #1.
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let mut state = UpdateState::empty(build(&CURRENT));
    state.accept_advisory(&one, &snap1, T0).unwrap();
    let (bad_two, bad_snap) = project.fork(2, [0x77; 32], "two after another one");
    assert_eq!(
        state.accept_advisory(&bad_two, &bad_snap, T0),
        Err(Refused::Equivocation)
    );
    assert_eq!(state.frozen().unwrap().advisory_serial, 2);
    assert_eq!(
        Refused::Equivocation.sec_kind(),
        Some(SecKind::AdvisoryEquivocation)
    );
}

/// Phase 6 review updates-protocol-1: an advisory signed by all three keys
/// of the 2-of-3 set, and the same advisory with its last signature
/// dropped (anyone can do that, no key needed). The copy has another
/// digest, but it is one advisory: nothing freezes; the copy is unlogged
/// when its log does not list it, and nothing at all when it does.
#[test]
fn a_copy_with_a_signature_dropped_is_no_equivocation() {
    let [a, b, c] = signers();
    let draft = AdvisoryDraft {
        serial: 1,
        issued_at_ms: T0,
        key_set_digest: set(&CURRENT).digest(),
        prev_digest: [0; 32],
        entries: vec![notice("one")],
    };
    let full = draft.sign(&[(0, &a), (1, &b), (2, &c)]).unwrap();
    let stripped = draft.sign(&[(0, &a), (1, &b)]).unwrap();
    assert_eq!(stripped.verify(&set(&CURRENT)), Ok(()));
    assert_ne!(full.digest(), stripped.digest());
    let mut log = vec![entry(EntryType::KeySet, set(&CURRENT).digest(), 0)];
    log.push(entry(EntryType::Advisory, full.digest(), 1));
    let real = snapshot(&log, &CURRENT);
    let mut state = UpdateState::empty(build(&CURRENT));
    state.accept_advisory(full.bytes(), &real, T0).unwrap();
    state.changed = false;
    let before = state.to_stored();
    // Passed on with the real log, which lists only the full copy.
    assert_eq!(
        state.accept_advisory(stripped.bytes(), &real, T0),
        Err(Refused::Unlogged)
    );
    assert_eq!(state.frozen(), None);
    assert_eq!(state.to_stored(), before, "nothing changed");
    assert!(!state.changed);
    // A log that lists both copies: the same advisory, nothing to do.
    let mut both = log.clone();
    both.push(entry(EntryType::Advisory, stripped.digest(), 2));
    assert_eq!(
        state.accept_advisory(stripped.bytes(), &snapshot(&both, &CURRENT), T0),
        Ok(Applied::Unchanged)
    );
    assert_eq!(state.frozen(), None);
    // The other way round (the stored copy is the shorter one) too.
    let mut short_first = UpdateState::empty(build(&CURRENT));
    short_first
        .accept_advisory(stripped.bytes(), &snapshot(&both, &CURRENT), T0)
        .unwrap();
    assert_eq!(
        short_first.accept_advisory(full.bytes(), &real, T0),
        Ok(Applied::Unchanged)
    );
    assert_eq!(short_first.frozen(), None);
    // A build whose compiled floor is the full copy: the stripped copy has
    // no stored bytes to be compared with, and its log does not list it.
    let mut floored = build(&CURRENT);
    floored.floor = (1, full.digest());
    let mut state = UpdateState::empty(floored.clone());
    assert_eq!(
        state.accept_advisory(stripped.bytes(), &real, T0),
        Err(Refused::Unlogged)
    );
    assert_eq!(state.frozen(), None);
    // Another body under the floor's serial, listed in its log, is still
    // equivocation (two bodies need the keys).
    let other = advisory(&CURRENT, 1, [0; 32], vec![notice("another one")]);
    let mut forked = log.clone();
    forked.push(entry(EntryType::Advisory, other.digest(), 2));
    let mut state = UpdateState::empty(floored);
    assert_eq!(
        state.accept_advisory(other.bytes(), &snapshot(&forked, &CURRENT), T0),
        Err(Refused::Equivocation)
    );
    assert!(state.frozen().is_some());
}

/// Only a release installed by hand lifts a freeze (Phase 6 review
/// updates-protocol-2): the set that froze signed two histories, so no
/// advisory lifts it, a rotation it signs included, nor one under another
/// key set.
#[test]
fn only_a_later_release_lifts_a_freeze() {
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let mut state = UpdateState::empty(build(&CURRENT));
    state.accept_advisory(&one, &snap1, T0).unwrap();
    let (other, other_snap) = project.fork(1, [0; 32], "another one");
    state.accept_advisory(&other, &other_snap, T0).unwrap_err();
    let stored = state.to_stored();
    // The same build reads it frozen; a release installed by hand (a higher
    // build serial) does not.
    let same = UpdateState::from_stored(stored.clone(), build(&CURRENT)).unwrap();
    assert!(same.frozen().is_some());
    let mut later = build(&CURRENT);
    later.serial = 1;
    let mut released = UpdateState::from_stored(stored.clone(), later).unwrap();
    assert_eq!(released.frozen(), None);
    let (two, snap2) = project.publish(vec![notice("two")]);
    assert!(released.accept_advisory(&two, &snap2, T0).is_ok());
    // The freezing set's rotation to the next set, newer than the freeze:
    // refused, still frozen.
    let mut frozen = UpdateState::from_stored(stored.clone(), build(&CURRENT)).unwrap();
    let (rotate, rotate_snap) = project.publish(vec![notice("new keys"), rotation(&NEXT)]);
    assert_eq!(
        frozen.accept_advisory(&rotate, &rotate_snap, T0),
        Err(Refused::Frozen)
    );
    assert!(frozen.frozen().is_some());
    assert_eq!(frozen.key_set(), Some(&set(&CURRENT)), "not rotated");
    // A build trusting another key set at the same serial (a lab key file):
    // an advisory under it newer than the freeze does not lift it either.
    let mut renewed = UpdateState::from_stored(stored, build(&NEXT)).unwrap();
    assert!(renewed.frozen().is_some());
    let newer = advisory(&NEXT, 4, project.prev, vec![notice("after the freeze")]);
    let mut log = project.log.clone();
    log.push(entry(EntryType::Advisory, newer.digest(), log.len()));
    assert_eq!(
        renewed.accept_advisory(newer.bytes(), &snapshot(&log, &NEXT), T0),
        Err(Refused::Frozen)
    );
    assert!(renewed.frozen().is_some());
}

#[test]
fn the_compiled_floor_is_the_lowest_serial_accepted() {
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let (two, snap2) = project.publish(vec![notice("two")]);
    let (three, snap3) = project.publish(vec![notice("three")]);
    let floor = (2, Advisory::decode(&two).unwrap().digest());
    let mut b = build(&CURRENT);
    b.floor = floor;
    let mut state = UpdateState::empty(b.clone());
    assert_eq!(state.newest(), Some(floor));
    assert_eq!(
        state.accept_advisory(&one, &snap1, T0),
        Err(Refused::Rollback { newest: 2 })
    );
    // The floor's own advisory: stored now (its bytes were not).
    assert!(matches!(
        state.accept_advisory(&two, &snap2, T0),
        Ok(Applied::Stored {
            serial: 2,
            succession: Succession::Same,
            ..
        })
    ));
    assert_eq!(
        state.accept_advisory(&two, &snap2, T0),
        Ok(Applied::Unchanged)
    );
    assert!(matches!(
        state.accept_advisory(&three, &snap3, T0),
        Ok(Applied::Stored {
            succession: Succession::Next,
            ..
        })
    ));
    // Another #2 than the floor's is equivocation, with the floor as ours.
    let mut state = UpdateState::empty(b);
    let (other_two, other_snap) = project.fork(2, floor.1, "another two");
    assert_eq!(
        state.accept_advisory(&other_two, &other_snap, T0),
        Err(Refused::Equivocation)
    );
    let evidence = state.frozen().unwrap();
    assert!(evidence.ours.is_empty());
    assert_eq!(evidence.ours_digest, floor.1);
    // A stored advisory older than the floor: the floor counts.
    let mut b = build(&CURRENT);
    b.floor = (3, Advisory::decode(&three).unwrap().digest());
    let mut older = UpdateState::empty(build(&CURRENT));
    older.accept_advisory(&one, &snap1, T0).unwrap();
    let mut state = UpdateState::from_stored(older.to_stored(), b).unwrap();
    assert_eq!(state.newest().unwrap().0, 3);
    assert_eq!(
        state.accept_advisory(&two, &snap2, T0),
        Err(Refused::Rollback { newest: 3 })
    );
}

#[test]
fn rotation_then_an_artifact_under_the_new_set() {
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let (two, snap2) = project.publish(vec![notice("two: new keys"), rotation(&NEXT)]);
    assert_eq!(project.seeds, NEXT);
    let mut state = UpdateState::empty(build(&CURRENT));
    state.accept_advisory(&one, &snap1, T0).unwrap();
    assert_eq!(
        state.accept_advisory(&two, &snap2, T0),
        Ok(Applied::Stored {
            serial: 2,
            succession: Succession::Next,
            rotated_to: Some(set(&NEXT).digest()),
            log: Consistency::Extends,
        })
    );
    assert_eq!(state.key_set(), Some(&set(&NEXT)));
    assert_eq!(
        state.key_set_history(),
        &[set(&CURRENT).digest(), set(&NEXT).digest()]
    );
    // #3 under the old set is refused: it names a set rotated out.
    let old = advisory(
        &CURRENT,
        3,
        Advisory::decode(&two).unwrap().digest(),
        vec![],
    );
    let mut log = project.log.clone();
    log.push(entry(EntryType::Advisory, old.digest(), log.len()));
    assert_eq!(
        state.accept_advisory(old.bytes(), &snapshot(&log, &CURRENT), T0),
        Err(Refused::Forged(Forgery::Signature(SigError::WrongKeySet)))
    );
    // A log signed by the old set no longer checks either.
    assert!(matches!(
        state.accept_log(&snapshot(&log, &CURRENT), T0),
        Err(Refused::Forged(Forgery::Log(LogCheckError::Sig(
            SigError::WrongKeySet
        ))))
    ));
    // #3 under the new set, with its log signed by the new set.
    let (three, snap3) = project.publish(vec![notice("three"), rotation(&NEXT)]);
    assert!(matches!(
        state.accept_advisory(&three, &snap3, T0),
        Ok(Applied::Stored {
            serial: 3,
            rotated_to: None,
            ..
        })
    ));
    // Read again by this build (compiled: the old set), the rotation holds.
    let again = UpdateState::from_stored(state.to_stored(), build(&CURRENT)).unwrap();
    assert_eq!(again.key_set(), Some(&set(&NEXT)));
    // A build without keys keeps the history and trusts nothing.
    let none = UpdateState::from_stored(state.to_stored(), no_keys()).unwrap();
    assert_eq!(none.key_set(), None);
    assert_eq!(none.key_set_history().len(), 2);
}

/// Phase 6 review updates-protocol-3: a state that missed a rotation
/// cannot check what came after it (an unknown key set: no event, nothing
/// forged), and catches up with the rotation a friend kept, with the log
/// it came with.
#[test]
fn a_kept_rotation_lets_a_state_that_missed_it_catch_up() {
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let (two, snap2) = project.publish(vec![notice("two: new keys"), rotation(&NEXT)]);
    let (three, snap3) = project.publish(vec![notice("three")]);
    // The friend took all three and kept the rotation, with its log.
    let mut friend = UpdateState::empty(build(&CURRENT));
    for (a, s) in [(&one, &snap1), (&two, &snap2), (&three, &snap3)] {
        friend.accept_advisory(a, s, T0).unwrap();
    }
    assert_eq!(friend.key_set(), Some(&set(&NEXT)));
    let (kept, kept_log) = friend.rotation_from(&set(&CURRENT).digest()).unwrap();
    assert_eq!(kept.bytes(), &two[..]);
    assert_eq!(kept_log.encode(), snap2);
    assert!(friend.rotation_from(&set(&NEXT).digest()).is_none());
    // Kept across a write and a read.
    let again = UpdateState::from_stored(friend.to_stored(), build(&CURRENT)).unwrap();
    assert_eq!(
        again
            .rotation_from(&set(&CURRENT).digest())
            .map(|(a, _)| a.digest()),
        Some(kept.digest())
    );
    // This state took #1 only. The friend's newest and its log are under a
    // set it never trusted: nothing forged, nothing stored.
    let mut lagging = UpdateState::empty(build(&CURRENT));
    lagging.accept_advisory(&one, &snap1, T0).unwrap();
    lagging.changed = false;
    assert_eq!(
        lagging.accept_advisory(&three, &snap3, T0),
        Err(Refused::UnknownKeySet)
    );
    assert_eq!(lagging.accept_log(&snap3, T0), Err(Refused::UnknownKeySet));
    assert!(!lagging.changed);
    // The kept rotation checks under its set: rotated, then #3 is taken.
    assert!(matches!(
        lagging.accept_advisory(kept.bytes(), &kept_log.encode(), T0),
        Ok(Applied::Stored {
            serial: 2,
            rotated_to: Some(_),
            ..
        })
    ));
    assert!(matches!(
        lagging.accept_advisory(&three, &snap3, T0),
        Ok(Applied::Stored { serial: 3, .. })
    ));
    assert_eq!(lagging.key_set(), Some(&set(&NEXT)));
    // At most MAX_ROTATIONS are kept, the newest, one per set.
    let mut many = UpdateState::empty(build(&CURRENT));
    for i in 0..(MAX_ROTATIONS as u8 + 2) {
        let a = advisory(&CURRENT, 1 + u64::from(i), [i; 32], vec![]);
        let log = Snapshot::decode(&snap1).unwrap();
        many.keep_rotation(a, log);
    }
    assert_eq!(many.rotations.len(), 1, "one per set");
    let log = Snapshot::decode(&snap1).unwrap();
    for seeds in [
        [0x44, 0x55, 0x66],
        [0x55, 0x66, 0x77],
        [0x66, 0x77, 0x88],
        [0x77, 0x88, 0x99],
    ] {
        many.keep_rotation(advisory(&seeds, 9, [1; 32], vec![]), log.clone());
    }
    assert_eq!(many.rotations.len(), MAX_ROTATIONS);
    assert!(
        many.rotation_from(&set(&CURRENT).digest()).is_none(),
        "the oldest went"
    );
}

#[test]
fn key_sets_resolve_from_the_build_and_the_history() {
    let a = set(&CURRENT);
    let b = set(&NEXT);
    let c = key_set_of(2, &[0x55, 0x66, 0x77]);
    // Nothing stored: the build's set starts the history.
    assert_eq!(
        resolve_key_set(Some(&a), None, vec![]),
        (Some(a.clone()), vec![a.digest()])
    );
    // Rotated from the build's set: the stored current set.
    let rotated = vec![a.digest(), b.digest()];
    assert_eq!(
        resolve_key_set(Some(&a), Some(&b.encode()), rotated.clone()),
        (Some(b.clone()), rotated.clone())
    );
    // A build that compiles the rotated set agrees.
    assert_eq!(
        resolve_key_set(Some(&b), Some(&b.encode()), rotated.clone()),
        (Some(b.clone()), rotated.clone())
    );
    // A build with a set the history never reached (installed by hand):
    // its set, appended.
    assert_eq!(
        resolve_key_set(Some(&c), Some(&b.encode()), rotated.clone()),
        (Some(c.clone()), vec![a.digest(), b.digest(), c.digest()])
    );
    // A stored current set that is not the history's last: the build's.
    assert_eq!(
        resolve_key_set(Some(&a), Some(&c.encode()), rotated.clone()).0,
        Some(a.clone())
    );
    assert_eq!(
        resolve_key_set(Some(&a), Some(b"junk"), vec![a.digest()]),
        (Some(a.clone()), vec![a.digest()])
    );
    // No keys: nothing current, the history kept.
    assert_eq!(
        resolve_key_set(None, Some(&b.encode()), rotated.clone()),
        (None, rotated)
    );
    // The history is bounded.
    let mut long: Vec<[u8; 32]> = (0..MAX_KEY_SET_HISTORY as u8).map(|i| [i; 32]).collect();
    push_history(&mut long, [0xEE; 32]);
    assert_eq!(long.len(), MAX_KEY_SET_HISTORY);
    assert_eq!(long[0], [1; 32]);
    assert_eq!(long.last(), Some(&[0xEE; 32]));
}

#[test]
fn forged_and_unlogged_advisories_are_refused() {
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let mut state = UpdateState::empty(build(&CURRENT));
    // Garbage, a flipped byte, too few signatures, another key set.
    assert!(matches!(
        state.accept_advisory(b"RAD1", &snap1, T0),
        Err(Refused::Forged(Forgery::Advisory(Rad1Error::Truncated)))
    ));
    let mut flipped = one.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert_eq!(
        state.accept_advisory(&flipped, &snap1, T0),
        Err(Refused::Forged(Forgery::Signature(SigError::BadSignature)))
    );
    let a = Advisory::decode(&one).unwrap();
    let ids = signers();
    let one_sig = a.draft().sign(&[(0, &ids[0])]).unwrap();
    assert_eq!(
        state.accept_advisory(one_sig.bytes(), &snap1, T0),
        Err(Refused::Forged(Forgery::Signature(
            SigError::BelowThreshold
        )))
    );
    // A key set this state never trusted: it cannot be checked yet (no
    // event, Phase 6 review updates-protocol-3).
    let other = advisory(&[0x44, 0x55, 0x66], 1, [0; 32], vec![notice("other")]);
    assert_eq!(
        state.accept_advisory(other.bytes(), &snap1, T0),
        Err(Refused::UnknownKeySet)
    );
    // A log that does not decode or check makes the advisory forged too.
    assert!(matches!(
        state.accept_advisory(&one, b"RTL1", T0),
        Err(Refused::Forged(Forgery::LogFormat(_)))
    ));
    let mut bad_root = Snapshot::decode(&snap1).unwrap().entries().to_vec();
    bad_root[0].logged_at_ms += 1;
    let sth = Snapshot::decode(&snap1).unwrap().sth().clone();
    let bad_root = Snapshot::new(bad_root, sth).unwrap().encode();
    assert_eq!(
        state.accept_advisory(&one, &bad_root, T0),
        Err(Refused::Forged(Forgery::Log(LogCheckError::BadRoot)))
    );
    // A log that does not list it.
    let unlisted = snapshot(&project.log[..1], &CURRENT);
    assert_eq!(
        state.accept_advisory(&one, &unlisted, T0),
        Err(Refused::Unlogged)
    );
    assert_eq!(state.advisory(), None, "nothing stored");
    assert!(!state.changed);
    for (refused, kind) in [
        (
            Refused::Forged(Forgery::LogFormat(Rtl1Error::Truncated)),
            SecKind::AdvisoryForged,
        ),
        (Refused::Unlogged, SecKind::UpdateUnlogged),
        (Refused::SplitView, SecKind::LogSplitView),
    ] {
        assert_eq!(refused.sec_kind(), Some(kind), "{refused:?}");
    }
    assert_eq!(Refused::UnknownKeySet.sec_kind(), None);
    assert_eq!(Refused::UnknownKeySet.code(), "UNKNOWN_KEY_SET");
    assert!(state.accept_advisory(&one, &snap1, T0).is_ok());
}

#[test]
fn logs_extend_and_a_split_view_freezes_with_both_tree_heads() {
    let mut project = Project::new();
    for i in 0..4 {
        project.publish(vec![notice(&format!("n{i}"))]);
    }
    let mut state = UpdateState::empty(build(&CURRENT));
    let three = snapshot(&project.log[..3], &CURRENT);
    let five = project.snapshot();
    assert_eq!(state.accept_log(&three, T0), Ok(Consistency::Extends));
    assert_eq!(state.accept_log(&five, T0), Ok(Consistency::Extends));
    state.changed = false;
    assert_eq!(state.accept_log(&five, T0), Ok(Consistency::Same));
    assert_eq!(state.accept_log(&three, T0), Ok(Consistency::Older));
    assert!(!state.changed);
    assert_eq!(state.log_entries(), &project.log[..]);
    // A validly signed log that differs in entry 2 (and is longer).
    let mut split = project.log.clone();
    split[2].logged_at_ms += 1;
    split.push(entry(EntryType::Manifest, [0x99; 32], 5));
    let split = snapshot(&split, &CURRENT);
    assert_eq!(state.accept_log(&split, T0 + 7), Err(Refused::SplitView));
    let evidence = state.frozen().unwrap();
    assert_eq!(evidence.reason, FreezeReason::SplitView);
    let ours = Snapshot::decode(&five).unwrap();
    assert_eq!(evidence.ours, ours.sth().bytes());
    assert_eq!(evidence.ours_digest, ours.sth().root_hash);
    assert_eq!(
        evidence.theirs,
        Snapshot::decode(&split).unwrap().sth().bytes()
    );
    assert_eq!(evidence.advisory_serial, 0);
    assert_eq!(state.log_entries(), &project.log[..], "ours kept");
    // An advisory carrying a split log freezes too.
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let mut state = UpdateState::empty(build(&CURRENT));
    state.accept_advisory(&one, &snap1, T0).unwrap();
    let a = advisory(
        &CURRENT,
        2,
        Advisory::decode(&one).unwrap().digest(),
        vec![],
    );
    let mut other = vec![entry(EntryType::KeySet, [0x42; 32], 0)];
    other.push(entry(EntryType::Advisory, a.digest(), 1));
    assert_eq!(
        state.accept_advisory(a.bytes(), &snapshot(&other, &CURRENT), T0),
        Err(Refused::SplitView)
    );
    assert_eq!(state.frozen().unwrap().advisory_serial, 1);
    assert_eq!(state.advisory().unwrap().serial, 1, "#2 not taken");
}

#[test]
fn a_log_at_the_limit_is_kept() {
    let entries: Vec<LogEntry> = (0..MAX_LOG_ENTRIES)
        .map(|i| entry(EntryType::Manifest, [i as u8; 32], i))
        .collect();
    let mut state = UpdateState::empty(build(&CURRENT));
    assert_eq!(
        state.accept_log(&snapshot(&entries, &CURRENT), T0),
        Ok(Consistency::Extends)
    );
    let again = UpdateState::from_stored(state.to_stored(), build(&CURRENT)).unwrap();
    assert_eq!(again.log_entries().len(), MAX_LOG_ENTRIES);
}

#[test]
fn installs_are_recorded_and_feed_the_bundle_check() {
    let mut b = build(&CURRENT);
    b.serial = 7;
    let mut state = UpdateState::empty(b);
    assert_eq!(state.installed_serial(), 7);
    state.record_installed(5);
    assert!(state.changed);
    assert_eq!(state.installed_serial(), 7, "the running build is newer");
    state.record_installed(9);
    let ctx = state.verify_ctx(true);
    assert_eq!(ctx.installed_serial, 9);
    assert!(ctx.allow_downgrade);
    assert_eq!(ctx.target, THIS_TARGET);
    assert_eq!(ctx.key_set, Some(&set(&CURRENT)));
    assert!(ctx.stored_log.is_empty());
    assert_eq!(ctx.release_floor, 0);
}

fn install_record(serial: u64, prev_serial: u64) -> InstallRecord {
    InstallRecord {
        dir: "/opt/raven/bin".to_owned(),
        files: vec!["raven".to_owned(), "raven-node".to_owned()],
        serial,
        version: format!("1.{serial}.0"),
        prev_serial,
        prev_version: format!("1.{prev_serial}.0"),
    }
}

#[test]
fn an_install_record_round_trips_and_an_older_file_has_none() {
    let mut state = UpdateState::empty(build(&CURRENT));
    assert_eq!(state.install_record(), None);
    state.record_install(5, Some(install_record(5, 4)));
    assert!(state.changed);
    assert_eq!(state.installed_serial(), 5);
    assert_eq!(state.install_record(), Some(&install_record(5, 4)));
    let stored = state.to_stored();
    let json = serde_json::to_value(&stored).unwrap();
    assert_eq!(json["install"]["files"][1], "raven-node");
    assert_eq!(json["install"]["prev_serial"], 4);
    let again = UpdateState::from_stored(stored, build(&CURRENT)).unwrap();
    assert_eq!(again.install_record(), Some(&install_record(5, 4)));
    // The same again changes nothing; an install that rolled itself back
    // clears the record.
    let mut again = again;
    again.record_install(5, Some(install_record(5, 4)));
    assert!(!again.changed);
    again.record_install(4, None);
    assert!(again.changed);
    assert_eq!(again.install_record(), None);
    // A state written before P6.47 reads with no record.
    let older: Stored = serde_json::from_value(serde_json::json!({
        "v": 1, "installed_build_serial": 3
    }))
    .unwrap();
    let older = UpdateState::from_stored(older, build(&CURRENT)).unwrap();
    assert_eq!(older.install_record(), None);
    assert_eq!(older.installed_serial(), 3);
}

// ── Compiled values ─────────────────────────────────────────────────

/// The form the key ceremony's commit uses, with the test set: it builds,
/// decodes to the test set, and the check finds the test keys in it.
const CEREMONY_FORM: Option<&[u8]> = Some(&hex_bytes::<99>(
    "010203d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737a09aa5f47a\
     6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f017cb79fb2b4120f2b1ec65e419\
     8d6e08b28e813feb01e4a400839b85e18080ce",
));

#[test]
fn the_production_key_set_never_holds_a_test_key() {
    let derived: Vec<[u8; 32]> = signers().iter().map(Identity::public_key_bytes).collect();
    assert_eq!(derived, TEST_PUBLIC_KEYS.to_vec());
    assert_eq!(KeySet::decode(CEREMONY_FORM.unwrap()), Ok(key_set()));
    assert!(holds_test_key(CEREMONY_FORM));
    assert!(compiled_set_shape_ok(CEREMONY_FORM));
    // The compiled set, whatever the ceremony puts there: a usable key set
    // without a test key, at least 2 of its keys needed (checked at
    // compile time as well).
    assert!(!holds_test_key(RELEASE_KEY_SET_V1));
    assert!(compiled_set_shape_ok(RELEASE_KEY_SET_V1));
    if let Some(bytes) = RELEASE_KEY_SET_V1 {
        let compiled = KeySet::decode(bytes).expect("the compiled key set decodes");
        assert!(compiled.threshold() >= 2);
        for key in compiled.keys() {
            assert!(!TEST_PUBLIC_KEYS.contains(key));
        }
    }
    // One test key among others is found; other keys are not.
    let mixed = key_set_of(2, &[0x44, 0x55, 0x33]).encode();
    assert!(holds_test_key(Some(&mixed)));
    let clean = key_set_of(2, &[0x44, 0x55, 0x66]).encode();
    assert!(!holds_test_key(Some(&clean)));
    assert!(!holds_test_key(None));
    // The shape check.
    assert!(compiled_set_shape_ok(None));
    assert!(compiled_set_shape_ok(Some(&clean)));
    assert!(!compiled_set_shape_ok(Some(
        &key_set_of(1, &[0x44, 0x55, 0x66]).encode()
    )));
    let mut wrong = clean.clone();
    wrong[0] = 2;
    assert!(!compiled_set_shape_ok(Some(&wrong)));
    let mut wrong = clean.clone();
    wrong[1] = 4;
    assert!(!compiled_set_shape_ok(Some(&wrong)));
    assert!(!compiled_set_shape_ok(Some(&clean[..clean.len() - 1])));
    assert!(!compiled_set_shape_ok(Some(&[1, 2])));
    assert!(all_zero(&BUILD_ADVISORY_FLOOR.1));
    assert_eq!(hex_bytes::<2>("00ff"), [0, 0xff]);
}

// ── The lab key file ────────────────────────────────────────────────

#[test]
fn lab_key_files_are_read_only_in_a_debug_build_with_the_unlock() {
    let unread = || -> Option<String> { panic!("the variable was read") };
    let no_file = |_: &Path| -> Option<Vec<u8>> { panic!("the file was read") };
    assert_eq!(lab_key_set_from(false, || true, unread, no_file), None);
    assert_eq!(lab_key_set_from(true, || false, unread, no_file), None);
    assert_eq!(lab_key_set_from(true, || true, || None, no_file), None);
    assert_eq!(
        lab_key_set_from(true, || true, || Some("  ".into()), no_file),
        None
    );
    let hex = format!("{}\n", hex::encode(key_set().encode()));
    let read = |want: &'static str, bytes: Vec<u8>| {
        move |p: &Path| -> Option<Vec<u8>> {
            assert_eq!(p, Path::new(want));
            Some(bytes)
        }
    };
    let value = || Some(" /lab/keys \n".to_owned());
    assert_eq!(
        lab_key_set_from(true, || true, value, read("/lab/keys", hex.into_bytes())),
        Some(Some(key_set()))
    );
    assert_eq!(
        lab_key_set_from(true, || true, value, read("/lab/keys", key_set().encode())),
        Some(Some(key_set()))
    );
    // A file that is not a key set (or not there): no keys at all.
    assert_eq!(
        lab_key_set_from(
            true,
            || true,
            value,
            read("/lab/keys", b"nonsense".to_vec())
        ),
        Some(None)
    );
    assert_eq!(
        lab_key_set_from(true, || true, value, |_: &Path| None),
        Some(None)
    );
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("keys");
    std::fs::write(&file, hex::encode(key_set().encode())).unwrap();
    assert_eq!(
        read_key_file(&file),
        Some(hex::encode(key_set().encode()).into_bytes())
    );
    std::fs::write(&file, vec![b'0'; MAX_LAB_KEYS_FILE as usize + 1]).unwrap();
    assert_eq!(read_key_file(&file), None, "too long");
    assert_eq!(read_key_file(&dir.path().join("missing")), None);
}

/// Runs in both builds: the release test job sets the lab key file (a
/// valid test key set), Lab Test A and the advisory switch, and this build
/// still trusts only its compiled set (none) and reads and writes nothing;
/// a debug build follows the variables.
#[test]
fn release_keys_file_is_inert_without_debug_assertions() {
    if !cfg!(debug_assertions) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lab-release-keys");
        std::fs::write(&file, hex::encode(key_set().encode())).unwrap();
        // Edition 2021: plain calls. No other release test reads these.
        std::env::set_var(LAB_RELEASE_KEYS_FILE, &file);
        std::env::set_var("RAVEN_LAB_TEST_A", "1");
        assert_eq!(lab_key_set(), None);
        assert_eq!(Build::this().key_set, compiled_key_set());
        assert!(!security_gate::live(SecGate::Advisory));
        let profile = tempfile::tempdir().unwrap();
        let mut project = Project::new();
        let (one, snap1) = project.publish(vec![notice("one")]);
        assert_eq!(
            accept_advisory(profile.path(), &one, &snap1, Origin::IMPORTED),
            Err(Refused::Off)
        );
        assert_eq!(
            accept_log(profile.path(), &snap1, Origin::IMPORTED),
            Err(Refused::Off)
        );
        assert!(matches!(load(profile.path()), Err(Refused::Off)));
        assert!(!profile.path().join(UPDATES_DIR).exists());
        return;
    }
    let file = std::env::var(LAB_RELEASE_KEYS_FILE).ok();
    let unlocked = crate::pair_init::lab_test_a_enabled();
    match (unlocked, file.as_deref().map(str::trim)) {
        (true, Some(path)) if !path.is_empty() => {
            let want = read_key_file(Path::new(path)).and_then(|b| parse_key_set_file(&b));
            assert_eq!(lab_key_set(), Some(want.clone()));
            assert_eq!(Build::this().key_set, want);
        }
        _ => {
            assert_eq!(lab_key_set(), None);
            assert_eq!(Build::this().key_set, compiled_key_set());
        }
    }
}

/// Runs in both builds: the release test job sets Lab Test A, the advisory
/// switch and the release bundle switch (P6.47), and a release build still
/// keeps both gates shut, so `raven update` stages, installs and records
/// nothing; a debug build opens the bundle gate only on the advisory gate.
#[test]
fn the_bundle_gate_is_inert_without_debug_assertions() {
    if !cfg!(debug_assertions) {
        // Edition 2021: plain calls. No other release test reads these.
        std::env::set_var("RAVEN_LAB_TEST_A", "1");
        std::env::set_var(security_gate::LAB_ADVISORY, "1");
        std::env::set_var(security_gate::LAB_RELEASE_BUNDLE, "1");
        assert!(!security_gate::live(SecGate::ReleaseBundle));
        assert!(!security_gate::live(SecGate::Advisory));
        let profile = tempfile::tempdir().unwrap();
        assert_eq!(
            record_install_with(
                profile.path(),
                &build(&CURRENT),
                5,
                Some(install_record(5, 4))
            ),
            Err(Refused::Off)
        );
        assert!(!profile.path().join(UPDATES_DIR).exists());
        return;
    }
    security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, Some(true));
    security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(false));
    assert!(
        !security_gate::live(SecGate::ReleaseBundle),
        "advisory shut"
    );
    security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
    assert!(security_gate::live(SecGate::ReleaseBundle));
    security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, None);
    security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
}

// ── The file, the gate and the events ───────────────────────────────

/// The advisory gate open for this thread; `None` in a release build.
struct Gate(());

impl Gate {
    fn open() -> Option<Self> {
        security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
        if !security_gate::live(SecGate::Advisory) {
            security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
            return None;
        }
        Some(Self(()))
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
    }
}

fn profile() -> tempfile::TempDir {
    crate::contact_book::tests::profile()
}

#[test]
fn a_shut_gate_reads_and_writes_nothing() {
    security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(false));
    let dir = profile();
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let b = build(&CURRENT);
    let origin = Origin::IMPORTED;
    assert_eq!(
        accept_advisory_with(dir.path(), &b, &one, &snap1, origin),
        Err(Refused::Off)
    );
    assert_eq!(
        accept_log_with(dir.path(), &b, &snap1, origin),
        Err(Refused::Off)
    );
    assert!(matches!(load_with(dir.path(), &b), Err(Refused::Off)));
    assert_eq!(record_installed(dir.path(), 3), Err(Refused::Off));
    assert_eq!(
        record_install_with(dir.path(), &b, 3, Some(install_record(3, 2))),
        Err(Refused::Off)
    );
    assert!(!dir.path().join(UPDATES_DIR).exists());
    security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
    // No keys: refused before the file or its lock is touched.
    let Some(_gate) = Gate::open() else {
        return;
    };
    assert_eq!(
        accept_advisory_with(dir.path(), &no_keys(), &one, &snap1, origin),
        Err(Refused::NoReleaseKeys)
    );
    assert_eq!(
        accept_log_with(dir.path(), &no_keys(), &snap1, origin),
        Err(Refused::NoReleaseKeys)
    );
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        names
            .iter()
            .all(|n| !n.to_string_lossy().contains("update")),
        "{names:?}"
    );
}

#[test]
fn the_state_file_round_trips_and_fails_closed() {
    let Some(_gate) = Gate::open() else {
        return;
    };
    let dir = profile();
    let dd = dir.path();
    let b = build(&CURRENT);
    let origin = Origin::IMPORTED;
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let (two, snap2) = project.publish(vec![notice("two")]);
    accept_advisory_with(dd, &b, &one, &snap1, origin).unwrap();
    accept_advisory_with(dd, &b, &two, &snap2, origin).unwrap();
    let path = dd.join(UPDATE_STATE_FILE);
    // A refusal that changes nothing does not write.
    let plain = std::fs::read(&path).unwrap();
    assert_eq!(
        accept_advisory_with(dd, &b, &one, &snap1, origin),
        Err(Refused::Rollback { newest: 2 })
    );
    assert_eq!(std::fs::read(&path).unwrap(), plain);
    let (three, snap3) = project.publish(vec![notice("three"), rotation(&NEXT)]);
    accept_advisory_with(dd, &b, &three, &snap3, origin).unwrap();
    let plain = std::fs::read(&path).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(json["v"], 1);
    assert_eq!(json["advisory"], hex::encode(&three));
    assert_eq!(json["key_set"], hex::encode(set(&NEXT).encode()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dd.join(UPDATES_DIR)), 0o700);
    }
    let state = load_with(dd, &b).unwrap();
    assert_eq!(state.advisory().unwrap().serial, 3);
    assert_eq!(state.key_set(), Some(&set(&NEXT)));
    assert_eq!(state.log_entries(), &project.log[..]);
    // A write by a build without keys (this one, before the ceremony)
    // keeps the rotated set.
    record_installed(dd, 4).unwrap();
    let state = load_with(dd, &b).unwrap();
    assert_eq!(state.installed_serial(), 4);
    assert_eq!(state.key_set(), Some(&set(&NEXT)));
    let plain = std::fs::read(&path).unwrap();
    // Fail closed: a file that does not parse, a stored advisory that does
    // not decode, a newer version. Nothing is accepted, nothing written.
    let (four, snap4) = project.publish(vec![notice("four")]);
    for bad in [
        b"{ not json".to_vec(),
        serde_json::to_vec(&serde_json::json!({ "v": 1, "advisory": "00" })).unwrap(),
        serde_json::to_vec(&serde_json::json!({ "v": 2 })).unwrap(),
    ] {
        std::fs::write(&path, &bad).unwrap();
        assert!(matches!(load_with(dd, &b), Err(Refused::Store(_))));
        assert!(matches!(
            accept_advisory_with(dd, &b, &four, &snap4, origin),
            Err(Refused::Store(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bad, "left as it was");
    }
    std::fs::write(&path, &plain).unwrap();
    assert!(accept_advisory_with(dd, &b, &four, &snap4, origin).is_ok());
}

#[test]
fn a_sealed_profile_seals_the_state() {
    let Some(_gate) = Gate::open() else {
        return;
    };
    let dir = profile();
    let dd = dir.path();
    crate::contact_book::tests::seal(dd);
    let b = build(&CURRENT);
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    accept_advisory_with(dd, &b, &one, &snap1, Origin::IMPORTED).unwrap();
    let bytes = std::fs::read(dd.join(UPDATE_STATE_FILE)).unwrap();
    assert!(at_rest::is_sealed_as(Kind::UpdateState, &bytes));
    assert_eq!(Kind::from_code(23), Some(Kind::UpdateState));
    let state = load_with(dd, &b).unwrap();
    assert_eq!(state.advisory().unwrap().bytes(), &one[..]);
    // Registered: sealed under its own lock, erased with the profile.
    let rule = at_rest::rule_for(UPDATE_STATE_FILE).unwrap();
    assert_eq!(rule.rule, at_rest::Rule::Sealed(Kind::UpdateState));
    assert_eq!(rule.lock, Some(UPDATE_STATE_LOCK));
    assert!(rule.erase);
}

#[test]
fn refusals_are_noted_against_the_friend_who_passed_them_on() {
    let Some(_gate) = Gate::open() else {
        return;
    };
    let Some(cap) = Capture::start() else {
        return;
    };
    let dir = profile();
    let dd = dir.path();
    let b = build(&CURRENT);
    let via = Via::DirectLink(crate::outbox::OutboxCarrier::Lan);
    let friend = Origin::friend(FRIEND, via);
    let about = Attribution::Update {
        passed_by: Some(FRIEND),
    };
    let mut project = Project::new();
    let (one, snap1) = project.publish(vec![notice("one")]);
    let (two, snap2) = project.publish(vec![notice("two")]);
    accept_advisory_with(dd, &b, &two, &snap2, Origin::IMPORTED).unwrap();
    // Stored: an informational alert (P6.45), about the person's import.
    assert_eq!(
        cap.kinds(),
        vec![(
            SecKind::AdvisoryApplied,
            Attribution::Update { passed_by: None },
            Via::Local
        )]
    );
    cap.clear();
    // The same one again changes nothing and raises nothing.
    accept_advisory_with(dd, &b, &two, &snap2, friend).unwrap();
    assert!(cap.kinds().is_empty());
    // Rolled back: ignored and counted.
    assert_eq!(
        accept_advisory_with(dd, &b, &one, &snap1, friend),
        Err(Refused::Rollback { newest: 2 })
    );
    assert_eq!(cap.kinds(), vec![(SecKind::AdvisoryRollback, about, via)]);
    assert!(crate::security_events::with_aggregator(|a| a.total(SecKind::AdvisoryRollback)) >= 1);
    cap.clear();
    // Forged, and imported by the person: about no friend.
    let mut forged = two.clone();
    forged[90] ^= 1;
    accept_advisory_with(dd, &b, &forged, &snap2, Origin::IMPORTED).unwrap_err();
    assert_eq!(
        cap.kinds(),
        vec![(
            SecKind::AdvisoryForged,
            Attribution::Update { passed_by: None },
            Via::Local
        )]
    );
    cap.clear();
    // Equivocation, written: the next read is frozen.
    let (other, other_snap) = project.fork(2, Advisory::decode(&one).unwrap().digest(), "x");
    assert_eq!(
        accept_advisory_with(dd, &b, &other, &other_snap, friend),
        Err(Refused::Equivocation)
    );
    assert_eq!(
        cap.kinds(),
        vec![(SecKind::AdvisoryEquivocation, about, via)]
    );
    assert!(load_with(dd, &b).unwrap().frozen().is_some());
    cap.clear();
    // Frozen: refused without an event.
    let (three, snap3) = project.publish(vec![notice("three")]);
    assert_eq!(
        accept_advisory_with(dd, &b, &three, &snap3, friend),
        Err(Refused::Frozen)
    );
    assert!(cap.kinds().is_empty());
    // A refused bundle's event.
    note_bundle_refusal(BundleError::Unlogged, friend);
    note_bundle_refusal(BundleError::WrongTarget, friend);
    assert_eq!(cap.kinds(), vec![(SecKind::UpdateUnlogged, about, via)]);
    let events: Vec<SecEvent> = cap.events();
    assert!(events.iter().all(|e| e.at_ms > 0));
}

#[test]
fn a_split_view_between_two_friends_is_written_and_noted() {
    let Some(_gate) = Gate::open() else {
        return;
    };
    let Some(cap) = Capture::start() else {
        return;
    };
    let dir = profile();
    let dd = dir.path();
    let b = build(&CURRENT);
    let mut project = Project::new();
    project.publish(vec![notice("one")]);
    let ours = project.snapshot();
    let mut theirs = project.log.clone();
    theirs[1].digest = [0x13; 32];
    let theirs = snapshot(&theirs, &CURRENT);
    let via = Via::Dial(crate::outbox::OutboxCarrier::Internet);
    assert_eq!(
        accept_log_with(dd, &b, &ours, Origin::friend([0xA1; 32], via)),
        Ok(Consistency::Extends)
    );
    assert_eq!(
        accept_log_with(dd, &b, &theirs, Origin::friend([0xB2; 32], via)),
        Err(Refused::SplitView)
    );
    assert_eq!(
        cap.kinds(),
        vec![(
            SecKind::LogSplitView,
            Attribution::Update {
                passed_by: Some([0xB2; 32])
            },
            via
        )]
    );
    let state = load_with(dd, &b).unwrap();
    let evidence = state.frozen().unwrap();
    assert_eq!(evidence.reason, FreezeReason::SplitView);
    assert_eq!(
        evidence.theirs,
        Snapshot::decode(&theirs).unwrap().sth().bytes()
    );
    assert_eq!(
        accept_log_with(dd, &b, &ours, Origin::IMPORTED),
        Err(Refused::Frozen)
    );
}
