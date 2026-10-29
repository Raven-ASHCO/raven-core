//! P6.29 tests of the capability high-water mark: what raises a mark and
//! that nothing lowers it by itself, the downgrade levels, one note a day,
//! a mock profile set {1, 3} for `require_profile`, the security-words token
//! (and that only `raven contact verify` lowers a mark), forgetting a removed
//! contact, sealing, and nothing at all while the events gate is shut. The
//! gates are opened for the test's thread only: a release test build cannot
//! open them, so those tests have nothing to check there.
//!
//! P6.50's contract tests of [`NextProfile`] with a mock profile (HR3,
//! profile 3) and security notices applied on the test's thread: the
//! highest profile in common, the floor raised by a verified bundle or a
//! confirmed session, V1 refused both ways, lowered only after the words
//! match, a DEPRECATED V1 warning and preferring profile 3, a BROKEN V1
//! refused both ways and its sessions retired into profile 3.

use super::*;
use crate::advisory::{Entry, EntryKind, Severity as Level};
use crate::outbox::OutboxCarrier;
use crate::security_sense::tests::{Capture, Shut};
use crate::suite_policy::{Policy, V1Sessions};
use crate::suite_registry as reg;

const PEER: [u8; 32] = [0x5E; 32];
const OTHER: [u8; 32] = [0x6F; 32];
/// A day in 2026, in ms.
const NOW: u64 = 20_400 * DAY_MS + 3_600_000;
const MOCK: &[u8] = &[1, 3];
const VIA: Via = Via::Dial(OutboxCarrier::Internet);

/// The suite floor open for this thread too (on a [`Capture`]); shut again
/// on drop.
struct SuiteFloor;

impl SuiteFloor {
    fn on(open: bool) -> Self {
        security_gate::set_lab_for_this_thread(SecGate::SuiteFloor, Some(open));
        Self
    }
}

impl Drop for SuiteFloor {
    fn drop(&mut self) {
        security_gate::set_lab_for_this_thread(SecGate::SuiteFloor, None);
    }
}

/// Link padding open (or shut) on this thread, as this node's own state
/// ([`SecGate::LinkPadding`]); back to the variables on drop. Padding can
/// go missing only while it is live here (Phase 6 review sensing-3).
struct PaddingHere;

impl PaddingHere {
    fn on(open: bool) -> Self {
        security_gate::set_lab_for_this_thread(SecGate::LinkPadding, Some(open));
        Self
    }
}

impl Drop for PaddingHere {
    fn drop(&mut self) {
        security_gate::set_lab_for_this_thread(SecGate::LinkPadding, None);
    }
}

/// A plain file holding `floors`, as a build would write it.
fn write_book(dd: &Path, floors: &[([u8; 32], Floor)]) {
    let mut book = Book::default();
    for (peer, floor) in floors {
        book.floors.insert(key(peer), floor.clone());
    }
    std::fs::write(path(dd), serde_json::to_vec_pretty(&book).unwrap()).unwrap();
}

fn mark(dd: &Path, peer: &[u8; 32]) -> Floor {
    floor(dd, peer).expect("a mark")
}

/// A mark rises with what links show and never falls by itself: a complete
/// showing without a feature keeps it (and is the downgrade); a partial one
/// only raises; a lower profile never lowers the floor; caps bits 0-7 are
/// no link features.
#[test]
fn observations_raise_the_mark_and_never_lower_it() {
    let Some(cap) = Capture::start() else {
        return;
    };
    let _padding = PaddingHere::on(true);
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    // A contact that shows nothing gets no mark (no write).
    assert_eq!(
        observe_link(dd, &PEER, crate::CAP_INTERNET, Some(false), NOW),
        Ok(None)
    );
    assert!(!path(dd).exists());
    observe_link(
        dd,
        &PEER,
        crate::CAP_INTERNET | CAP_LINK_RRH1,
        Some(false),
        NOW,
    )
    .unwrap();
    let first = mark(dd, &PEER);
    assert_eq!(first.link_caps_max, CAP_LINK_RRH1, "bits 0-7 are not kept");
    assert_eq!((first.set_by, first.at_day), (SetBy::Link, day_of(NOW)));
    // Seen-only showings raise (padding seen as its bit) and never note.
    observe_link_seen(dd, &PEER, CAP_LINK_PAD1, None, NOW + DAY_MS).unwrap();
    observe_link_seen(dd, &PEER, 0, None, NOW + DAY_MS).unwrap();
    let raised = mark(dd, &PEER);
    assert_eq!(raised.link_caps_max, CAP_LINK_RRH1 | CAP_LINK_PAD1);
    assert!(raised.pad1 && !raised.rup1 && !raised.knock);
    assert!(cap.events().is_empty(), "the caller notes, never the store");
    // A complete showing without them keeps the mark.
    let down = observe_link(dd, &PEER, crate::CAP_INTERNET, Some(false), NOW + DAY_MS).unwrap();
    assert_eq!(
        down,
        Some(Downgrade::Link(vec![Feature::RouteHints, Feature::Padding]))
    );
    let kept = mark(dd, &PEER);
    assert_eq!(kept.link_caps_max, CAP_LINK_RRH1 | CAP_LINK_PAD1);
    assert!(kept.pad1);
    // Profiles: up to one this build speaks, never down, never past it.
    observe_profile_in(dd, &PEER, MOCK, 3, SetBy::Bundle, NOW).unwrap();
    observe_profile_in(dd, &PEER, MOCK, 1, SetBy::Session, NOW).unwrap();
    observe_profile_in(dd, &PEER, MOCK, 7, SetBy::Session, NOW).unwrap();
    let profile = mark(dd, &PEER);
    assert_eq!((profile.profile_floor, profile.set_by), (3, SetBy::Bundle));
    // The real build speaks profile 1 only: nothing to keep.
    observe_profile(dd, &OTHER, 1, SetBy::Session, NOW).unwrap();
    observe_profile(dd, &OTHER, 3, SetBy::Session, NOW).unwrap();
    assert_eq!(floor(dd, &OTHER), None);
}

/// The levels of kind 30 (`docs/SECURITY_EVENTS.md`): route hints and
/// update exchange a Notice, padding and the knock Suspicious, a session
/// profile an Alert; no profile in common is no event at all.
#[test]
fn downgrades_are_classified_by_what_went_missing() {
    let mut all = Floor::new(1);
    all.raise_link(CAP_LINK_RRH1 | CAP_LINK_PAD1 | CAP_LINK_RUP1, Some(true), 1);
    assert_eq!(all.missing(!0, Some(true)), vec![]);
    assert_eq!(
        all.missing(0, Some(false)),
        vec![
            Feature::RouteHints,
            Feature::UpdateExchange,
            Feature::Padding,
            Feature::Knock
        ]
    );
    assert_eq!(
        all.missing(CAP_LINK_RRH1 | CAP_LINK_RUP1, Some(true)),
        vec![Feature::Padding]
    );
    // Nothing seen before, nothing missing.
    assert_eq!(Floor::new(1).missing(0, Some(false)), vec![]);
    let level = |f: Vec<Feature>| Downgrade::Link(f).severity();
    assert_eq!(level(vec![Feature::RouteHints]), Some(Severity::Notice));
    assert_eq!(level(vec![Feature::UpdateExchange]), Some(Severity::Notice));
    assert_eq!(level(vec![Feature::Padding]), Some(Severity::Suspicious));
    assert_eq!(
        level(vec![Feature::RouteHints, Feature::Knock]),
        Some(Severity::Suspicious)
    );
    assert_eq!(
        Downgrade::Profile { floor: 3, best: 1 }.severity(),
        Some(Severity::Alert)
    );
    assert_eq!(Downgrade::NoCommonProfile.severity(), None);
    assert_eq!(Downgrade::NoCommonProfile.event(&PEER, VIA, NOW), None);
    let (ev, severity) = Downgrade::Link(vec![Feature::Knock])
        .event(&PEER, VIA, NOW)
        .unwrap();
    assert_eq!(
        (ev.kind, ev.who, ev.via, severity),
        (
            SecKind::CapabilityDowngrade,
            Attribution::Contact { peer: PEER },
            VIA,
            Severity::Suspicious
        )
    );
    for f in Feature::ALL {
        assert!(!f.name().is_empty());
    }
    // What `raven contact verify` offers to lower: Suspicious and up only.
    let mut open = Floor::new(1);
    open.open = Feature::RouteHints.bit() | Feature::UpdateExchange.bit();
    assert!(!open.open_downgrade());
    open.open |= Feature::Padding.bit();
    assert!(open.open_downgrade());
    let refused = Floor {
        refused_profile: Some(1),
        ..Floor::new(1)
    };
    assert!(refused.open_downgrade());
}

/// One note per contact, feature and day: the same loss again that day is
/// not noted, a new one is, and the next day it is noted again. The loss
/// stays open until the mark is lowered.
#[test]
fn a_downgrade_is_noted_once_a_day_per_feature() {
    let Some(_cap) = Capture::start() else {
        return;
    };
    let _padding = PaddingHere::on(true);
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    observe_link_seen(dd, &PEER, CAP_LINK_RRH1 | CAP_LINK_PAD1, None, NOW).unwrap();
    let route = Some(Downgrade::Link(vec![Feature::RouteHints]));
    assert_eq!(
        observe_link(dd, &PEER, CAP_LINK_PAD1, Some(false), NOW),
        Ok(route.clone())
    );
    let written = std::fs::read(path(dd)).unwrap();
    assert_eq!(
        observe_link(dd, &PEER, CAP_LINK_PAD1, Some(false), NOW + 1),
        Ok(None)
    );
    assert_eq!(std::fs::read(path(dd)).unwrap(), written, "no write");
    assert_eq!(
        observe_link(dd, &PEER, 0, Some(false), NOW + 2),
        Ok(Some(Downgrade::Link(vec![
            Feature::RouteHints,
            Feature::Padding
        ])))
    );
    assert_eq!(observe_link(dd, &PEER, 0, Some(false), NOW + 3), Ok(None));
    assert_eq!(
        observe_link(dd, &PEER, CAP_LINK_PAD1, Some(false), NOW + DAY_MS),
        Ok(route)
    );
    let m = mark(dd, &PEER);
    assert_eq!(
        m.open_features(),
        vec![Feature::RouteHints, Feature::Padding]
    );
    // A full showing again: nothing missing, nothing noted, still open.
    assert_eq!(
        observe_link(
            dd,
            &PEER,
            CAP_LINK_RRH1 | CAP_LINK_PAD1,
            Some(false),
            NOW + DAY_MS
        ),
        Ok(None)
    );
    assert!(mark(dd, &PEER).open_downgrade());
}

/// The step's contract test with a mock profile set {1, 3}: the highest
/// common profile is used; with the floor at 3 an offer of {1} is an Alert,
/// refused while the suite floor is live and used (as before) while it is
/// not; no profile in common is refused whatever the gates; an offer at the
/// floor again closes the refusal.
#[test]
fn require_profile_refuses_an_offer_below_the_floor() {
    let Some(cap) = Capture::start() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let require = |offered: &[u8], now: u64| require_profile_in(dd, &PEER, MOCK, offered, VIA, now);
    // No floor yet: the best in common.
    assert_eq!(require(&[1], NOW), Ok(1));
    assert_eq!(require(&[1, 3, 9], NOW), Ok(3));
    assert_eq!(require(&[2, 9], NOW), Err(Downgrade::NoCommonProfile));
    assert!(!path(dd).exists() && cap.events().is_empty());
    observe_profile_in(dd, &PEER, MOCK, 3, SetBy::Session, NOW).unwrap();
    let below = Downgrade::Profile { floor: 3, best: 1 };
    {
        let _floor = SuiteFloor::on(true);
        assert_eq!(require(&[1], NOW), Err(below.clone()));
        assert_eq!(require(&[1, 3], NOW), Ok(3));
        // Noted once that day.
        assert_eq!(require(&[1], NOW + 1), Err(below.clone()));
    }
    let downgrade = (
        SecKind::CapabilityDowngrade,
        Attribution::Contact { peer: PEER },
        VIA,
    );
    assert_eq!(cap.kinds(), vec![downgrade]);
    let m = mark(dd, &PEER);
    assert_eq!(m.refused_profile, Some(1));
    assert_eq!(m.open_features(), vec![Feature::SessionProfile]);
    assert!(m.open_downgrade());
    {
        // Without the suite floor it is noted, not refused.
        let _floor = SuiteFloor::on(false);
        assert_eq!(require(&[1], NOW + DAY_MS), Ok(1));
        assert_eq!(cap.kinds(), vec![downgrade, downgrade]);
    }
    // Profile 3 seen again (a confirmed session): the refusal is closed.
    observe_profile_in(dd, &PEER, MOCK, 3, SetBy::Session, NOW + DAY_MS).unwrap();
    let m = mark(dd, &PEER);
    assert_eq!((m.refused_profile, m.open_features()), (None, vec![]));
    // The real build: profile 1 is its highest, so no file is read.
    let unreadable = tempfile::tempdir().unwrap();
    std::fs::create_dir(unreadable.path().join(CAPABILITY_FLOOR_FILE)).unwrap();
    let _floor = SuiteFloor::on(true);
    assert_eq!(require_profile(unreadable.path(), &PEER, &[1], VIA), Ok(1));
    // A floor that cannot be read refuses below this build's best while the
    // suite floor is live (fail closed).
    assert_eq!(
        require_profile_in(unreadable.path(), &PEER, MOCK, &[1], VIA, NOW),
        Err(Downgrade::Profile { floor: 3, best: 1 })
    );
}

/// With the events gate shut nothing is recorded or refused, and nothing is
/// noted: a release build behaves exactly as before.
#[test]
fn nothing_is_kept_or_refused_while_the_events_gate_is_shut() {
    let shut = Shut::start();
    let _floor = SuiteFloor::on(true);
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    assert_eq!(
        observe_link(dd, &PEER, CAP_LINK_RRH1, Some(true), NOW),
        Ok(None)
    );
    observe_link_seen(dd, &PEER, CAP_LINK_PAD1, Some(true), NOW).unwrap();
    observe_profile_in(dd, &PEER, MOCK, 3, SetBy::Bundle, NOW).unwrap();
    assert!(!path(dd).exists());
    write_book(
        dd,
        &[(
            PEER,
            Floor {
                profile_floor: 3,
                ..Floor::new(1)
            },
        )],
    );
    assert_eq!(require_profile_in(dd, &PEER, MOCK, &[1], VIA, NOW), Ok(1));
    note(&Downgrade::Profile { floor: 3, best: 1 }, &PEER, VIA);
    assert_eq!(shut.noted(), 0);
}

/// Only the contact's 10 security words make the token (not the old code,
/// not another contact's words), and it lowers only that contact's mark:
/// the mark starts afresh, set by the person, and rises again later.
#[test]
fn lowering_needs_the_contacts_security_words() {
    let Some(_cap) = Capture::start() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let words = |peer: &[u8; 32]| security_words::words_v1(peer).join(" ");
    assert!(CodeMatch::check(&words(&OTHER), &PEER).is_none());
    assert!(CodeMatch::check(&crate::fingerprint::device_fingerprint_v1(&PEER), &PEER).is_none());
    assert!(CodeMatch::check("", &PEER).is_none());
    let matched = CodeMatch::check(&words(&PEER), &PEER).expect("their words");
    assert_eq!(matched.peer(), &PEER);
    // No mark: nothing to lower, nothing written.
    assert_eq!(lower_floor(dd, &matched, NOW), Ok(false));
    assert!(!path(dd).exists());
    for peer in [&PEER, &OTHER] {
        observe_link_seen(dd, peer, CAP_LINK_RRH1 | CAP_LINK_PAD1, Some(true), NOW).unwrap();
        observe_profile_in(dd, peer, MOCK, 3, SetBy::Bundle, NOW).unwrap();
        observe_link(dd, peer, 0, Some(false), NOW).unwrap();
    }
    assert!(mark(dd, &PEER).open_downgrade());
    assert_eq!(lower_floor(dd, &matched, NOW + DAY_MS), Ok(true));
    let lowered = mark(dd, &PEER);
    assert_eq!(
        lowered,
        Floor {
            set_by: SetBy::User,
            ..Floor::new(day_of(NOW + DAY_MS))
        }
    );
    assert!(!lowered.open_downgrade());
    assert!(mark(dd, &OTHER).open_downgrade(), "only that contact's");
    // What the contact offers now is the new mark.
    assert_eq!(
        observe_link(dd, &PEER, CAP_LINK_RRH1, Some(false), NOW + DAY_MS),
        Ok(None)
    );
    assert_eq!(mark(dd, &PEER).link_caps_max, CAP_LINK_RRH1);
}

/// The step's visibility test: outside this module, only `raven contact
/// verify` (ash's cli.rs) and the terminal app's "Check again" (its
/// tui/bridge.rs, P6.31) make the token and lower a mark; raven-node and
/// the rest of raven-core never do (a network event must never be able to).
#[test]
fn only_contact_verify_lowers_a_floor() {
    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for krate in ["raven-core", "raven-node", "ash"] {
        rust_files(&crates.join(krate).join("src"), &mut files);
    }
    let own = Path::new("raven-core/src/capability_floor");
    let mut callers = std::collections::BTreeSet::new();
    for file in &files {
        let relative = file.strip_prefix(crates).unwrap();
        if relative.starts_with(own) || relative == Path::new("raven-core/src/capability_floor.rs")
        {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap();
        if ["lower_floor(", "CodeMatch::check("]
            .iter()
            .any(|call| text.contains(call))
        {
            callers.insert(relative.to_string_lossy().replace('\\', "/"));
        }
    }
    assert_eq!(
        callers.into_iter().collect::<Vec<_>>(),
        vec![
            "ash/src/cli.rs".to_string(),
            "ash/src/tui/bridge.rs".to_string()
        ]
    );
}

/// A removed contact's mark goes; the others stay; nothing is written when
/// the file does not name it, and a file that cannot be read stays as it
/// is.
#[test]
fn forget_deletes_a_removed_contacts_mark() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    assert_eq!(forget(dd, &PEER), Ok(()));
    assert!(!path(dd).exists());
    write_book(dd, &[(PEER, Floor::new(1)), (OTHER, Floor::new(2))]);
    forget(dd, &PEER).unwrap();
    assert_eq!(floor(dd, &PEER), None);
    assert_eq!(floor(dd, &OTHER), Some(Floor::new(2)));
    let written = std::fs::read(path(dd)).unwrap();
    forget(dd, &PEER).unwrap();
    assert_eq!(std::fs::read(path(dd)).unwrap(), written, "no write");
    assert!(!String::from_utf8_lossy(&written).contains(&hex::encode(PEER)));
}

/// Past [`MAX_FLOORS`] the mark set longest ago goes, never the one just
/// written.
#[test]
fn the_marks_are_bounded() {
    let mut book = Book::default();
    for n in 0..=MAX_FLOORS {
        let day = u32::try_from(n).unwrap() + 10;
        book.floors.insert(format!("{n:064x}"), Floor::new(day));
    }
    let newest = format!("{:064x}", MAX_FLOORS + 1);
    book.floors.insert(newest.clone(), Floor::new(1));
    book.bound(&newest);
    assert_eq!(book.floors.len(), MAX_FLOORS);
    assert!(book.floors.contains_key(&newest));
    assert!(!book.floors.contains_key(&format!("{:064x}", 0)));
    assert!(!book.floors.contains_key(&format!("{:064x}", 1)));
    assert!(book.floors.contains_key(&format!("{:064x}", 2)));
}

/// The privacy pack's migration seals the marks (kind 11) and later writes
/// keep them sealed: no contact key in clear. An older or newer build's
/// fields are tolerated.
#[test]
fn the_marks_are_sealed_in_a_sealed_profile() {
    let Some(_cap) = Capture::start() else {
        return;
    };
    let dir = crate::contact_book::tests::profile();
    let dd = dir.path();
    observe_link(dd, &PEER, CAP_LINK_RRH1, Some(false), NOW).unwrap();
    assert!(!at_rest::is_sealed(&std::fs::read(path(dd)).unwrap()));
    crate::contact_book::tests::seal(dd);
    let clear = |raw: &[u8]| {
        let peer = hex::encode(PEER);
        raw.windows(peer.len()).any(|w| w == peer.as_bytes())
    };
    let raw = std::fs::read(path(dd)).unwrap();
    assert!(at_rest::is_sealed_as(Kind::CapabilityFloor, &raw) && !clear(&raw));
    assert_eq!(mark(dd, &PEER).link_caps_max, CAP_LINK_RRH1);
    observe_link(dd, &OTHER, CAP_LINK_RRH1, Some(false), NOW).unwrap();
    forget(dd, &PEER).unwrap();
    let raw = std::fs::read(path(dd)).unwrap();
    assert!(at_rest::is_sealed_as(Kind::CapabilityFloor, &raw) && !clear(&raw));
    assert_eq!(floor(dd, &PEER), None);
    assert_eq!(mark(dd, &OTHER).link_caps_max, CAP_LINK_RRH1);
    // Unknown fields and reasons: read, not refused.
    let newer: Floor = serde_json::from_value(serde_json::json!({
        "link_caps_max": 256, "knock": false, "pad1": false, "rup1": false,
        "profile_floor": 1, "set_by": "advisory", "at_day": 5, "later": true
    }))
    .unwrap();
    assert_eq!(newer.set_by, SetBy::Other);
}

/// P6.35 (RLK1): every LAN and Internet direct link shows whether it
/// carried the knock, so on a seen-only showing too a knock seen before and
/// missing now is the Suspicious downgrade (once a day); a link that cannot
/// tell (`None`: p2p, nearby, this node's knock gate shut) neither raises
/// nor lowers. `all_knock` and `has_knock` read the marks once.
#[test]
fn the_knock_is_a_complete_showing_on_every_link_that_can_carry_it() {
    let Some(_cap) = Capture::start() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    assert!(all_knock(dd, &[]), "nobody to wait for");
    assert!(!all_knock(dd, &[PEER]) && !has_knock(dd, &PEER));
    // Nothing seen yet: no knock is nothing missing.
    assert_eq!(
        observe_link_seen(dd, &PEER, CAP_LINK_RRH1, Some(false), NOW),
        Ok(None)
    );
    assert!(!mark(dd, &PEER).knock);
    assert_eq!(observe_link_seen(dd, &PEER, 0, Some(true), NOW), Ok(None));
    assert!(mark(dd, &PEER).knock && has_knock(dd, &PEER));
    assert!(all_knock(dd, &[PEER]) && !all_knock(dd, &[PEER, OTHER]));
    // Unknown: neither raised nor missing.
    assert_eq!(
        observe_link(dd, &PEER, crate::CAP_INTERNET | CAP_LINK_RRH1, None, NOW),
        Ok(None)
    );
    assert_eq!(observe_link_seen(dd, &PEER, 0, None, NOW), Ok(None));
    let knock = Some(Downgrade::Link(vec![Feature::Knock]));
    assert_eq!(
        observe_link_seen(dd, &PEER, 0, Some(false), NOW),
        Ok(knock.clone())
    );
    assert_eq!(
        knock.as_ref().and_then(|d| d.severity()),
        Some(Severity::Suspicious)
    );
    // The same day again: kept open, not noted twice (Seen or Complete).
    assert_eq!(
        observe_link_seen(dd, &PEER, 0, Some(false), NOW + 1),
        Ok(None)
    );
    assert_eq!(
        observe_link(
            dd,
            &PEER,
            crate::CAP_INTERNET | CAP_LINK_RRH1,
            Some(false),
            NOW + 2
        ),
        Ok(None)
    );
    assert_eq!(
        observe_link(
            dd,
            &PEER,
            crate::CAP_INTERNET | CAP_LINK_RRH1,
            Some(false),
            NOW + DAY_MS
        ),
        Ok(knock)
    );
    let m = mark(dd, &PEER);
    assert!(m.knock, "never lowered by itself");
    assert_eq!(m.open_features(), vec![Feature::Knock]);
    assert!(m.open_downgrade());
}

// ── The next-profile contract (P6.50) ────────────────────────────────

/// A mock next profile with id `.0` (HR3 is 3).
struct Next(u8);

const HR3: Next = Next(3);

/// A bundle as the mock program verified it: its signed `profile_set`
/// bits (bit 0 V1, bit 2 HR3).
struct Bundle(u8);

const V1_ONLY: Bundle = Bundle(0b001);
const V1_AND_HR3: Bundle = Bundle(0b101);

/// A session of the mock program's: whether the contact answered under it.
struct Session(bool);

impl NextProfile for Next {
    type Bundle = Bundle;
    type Session = Session;

    fn profile_id(&self) -> u8 {
        self.0
    }

    fn advertised(&self, bundle: &Bundle) -> Vec<u8> {
        (0..8u8)
            .filter(|bit| bundle.0 & (1 << bit) != 0)
            .map(|bit| bit + 1)
            .collect()
    }

    fn confirmed(&self, session: &Session) -> bool {
        session.0
    }
}

/// The profile set of a bundle, as a new session this node starts offers it.
fn set_of(bundle: &Bundle) -> Vec<u8> {
    HR3.advertised(bundle)
}

/// A contact's PairInit V1 that this node takes: it offers profile 1 only.
const PAIR_INIT_V1: &[u8] = &[1];

/// Security notice #`serial` with these suite statuses, applied on this
/// thread with the advisory gate open; both undone on drop. `None` in a
/// release build (nothing opens there).
struct Notice(());

impl Notice {
    fn apply(serial: u64, statuses: &[(&str, Level)]) -> Option<Self> {
        security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
        if !security_gate::live(SecGate::Advisory) {
            security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
            return None;
        }
        let entries: Vec<Entry> = statuses
            .iter()
            .map(|(id, severity)| Entry {
                kind: EntryKind::SuiteStatus,
                severity: *severity,
                target: (*id).to_owned(),
                arg: Vec::new(),
                text_id: 0,
            })
            .collect();
        suite_policy::set_policy_for_this_thread(Some(Policy::of_entries(
            serial, NOW, &entries, 1,
        )));
        Some(Self(()))
    }
}

impl Drop for Notice {
    fn drop(&mut self) {
        suite_policy::set_policy_for_this_thread(None);
        security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
    }
}

/// Phase 6 review (traffic-4): while a security notice holds link padding
/// (`FEATURE_HOLD` BROKEN) and the knock (a BROKEN `rlk1/1`) on this node,
/// its own links lack them and so do those of every contact that applied
/// the notice: a showing without them from a contact whose mark has both
/// is no downgrade (complete or seen), and one with them raises nothing.
/// Lifted, the same showing is the downgrade again.
#[test]
fn a_link_feature_this_node_holds_is_no_downgrade() {
    let Some(_cap) = Capture::start() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    assert_eq!(
        observe_link(dd, &PEER, CAP_LINK_PAD1, Some(true), NOW),
        Ok(None)
    );
    let hold = Entry {
        kind: EntryKind::FeatureHold,
        severity: Level::Broken,
        target: reg::FEATURE_LINK_PADDING.to_owned(),
        arg: Vec::new(),
        text_id: 0,
    };
    let Some(_notice) = Notice::apply(7, &[(reg::RLK1_V1, Level::Broken)]) else {
        return;
    };
    let rlk1 = Entry {
        kind: EntryKind::SuiteStatus,
        severity: Level::Broken,
        target: reg::RLK1_V1.to_owned(),
        arg: Vec::new(),
        text_id: 0,
    };
    suite_policy::set_policy_for_this_thread(Some(Policy::of_entries(7, NOW, &[hold, rlk1], 1)));
    assert!(!suite_policy::hold_allows(reg::FEATURE_LINK_PADDING));
    assert!(!suite_policy::hold_allows(reg::FEATURE_LINK_KNOCK));
    assert_eq!(observe_link(dd, &PEER, 0, Some(false), NOW + 1), Ok(None));
    assert_eq!(
        observe_link_seen(dd, &PEER, 0, Some(false), NOW + 1),
        Ok(None)
    );
    assert!(mark(dd, &PEER).open_features().is_empty());
    let both = CAP_LINK_RRH1 | CAP_LINK_PAD1;
    observe_link(dd, &OTHER, both, Some(true), NOW + 1).unwrap();
    let other = mark(dd, &OTHER);
    assert!(
        !other.pad1 && !other.knock,
        "nothing held raised: {other:?}"
    );
    assert_eq!(other.link_caps_max, CAP_LINK_RRH1);
    // Lifted (padding live here again).
    suite_policy::set_policy_for_this_thread(None);
    let _padding = PaddingHere::on(true);
    assert_eq!(
        observe_link(dd, &PEER, 0, Some(false), NOW + 2),
        Ok(Some(Downgrade::Link(vec![
            Feature::Padding,
            Feature::Knock
        ])))
    );
}

/// Phase 6 review (sensing-3): PAD1 runs only when both sides offer it, so
/// while padding is not live on this node (its gate shut) a contact's
/// complete showing without it is no downgrade, today or the next day; the
/// mark still rises with what the contact shows. With padding live here
/// the same showing is the Suspicious downgrade.
#[test]
fn padding_this_node_does_not_use_is_no_downgrade() {
    let Some(_cap) = Capture::start() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let shut = PaddingHere::on(false);
    assert_eq!(observe_link(dd, &PEER, CAP_LINK_PAD1, None, NOW), Ok(None));
    assert!(mark(dd, &PEER).pad1, "the mark still rises");
    for at in [NOW + 1, NOW + DAY_MS] {
        assert_eq!(observe_link(dd, &PEER, 0, None, at), Ok(None), "{at}");
    }
    assert!(mark(dd, &PEER).open_features().is_empty());
    drop(shut);
    let _live = PaddingHere::on(true);
    let down = observe_link(dd, &PEER, 0, None, NOW + DAY_MS + 1).unwrap();
    assert_eq!(down, Some(Downgrade::Link(vec![Feature::Padding])));
    assert_eq!(down.and_then(|d| d.severity()), Some(Severity::Suspicious));
}

fn choose(dd: &Path, peer: &[u8; 32], offered: &[u8]) -> Result<Choice, Refusal> {
    choose_in(dd, peer, &profiles_with(&HR3), offered, VIA, NOW)
}

fn chose(profile: u8, warn: bool) -> Result<Choice, Refusal> {
    Ok(Choice { profile, warn })
}

/// The highest profile in common, whatever the order of the offer or what
/// else it holds; a profile set's bits read as profile ids; nothing in
/// common is refused. No floor is needed for that, and nothing is written.
#[test]
fn the_highest_profile_in_common_is_chosen_deterministically() {
    let Some(cap) = Capture::start() else {
        return;
    };
    assert_eq!(profiles_with(&HR3), vec![1, 3]);
    assert_eq!(profiles_with(&Next(1)), vec![1], "not above V1: nothing");
    assert_eq!(HR3.advertised(&Bundle(0b111)), vec![1, 2, 3]);
    assert_eq!(set_of(&V1_AND_HR3), vec![1, 3]);
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    for offered in [&[3, 1][..], &[1, 3], &[1, 3, 3, 9], &[9, 3], &[3]] {
        assert_eq!(choose(dd, &PEER, offered), chose(3, false), "{offered:?}");
    }
    assert_eq!(choose(dd, &PEER, &[1, 2]), chose(1, false));
    for offered in [&[2][..], &[], &[4, 9]] {
        assert_eq!(
            choose(dd, &PEER, offered),
            Err(Refusal::Floor(Downgrade::NoCommonProfile))
        );
    }
    assert!(!path(dd).exists() && cap.events().is_empty());
}

/// A verified bundle with HR3 in its set or a confirmed HR3 session raises
/// the contact's floor to 3 (a V1-only bundle or an unconfirmed session
/// raise nothing); from then on V1 is refused to and from that contact
/// while the suite floor is live (a replayed V1-only bundle, a PairInit V1
/// taken), noted as an Alert, and HR3 still works; a contact without the
/// floor still gets V1. Without the suite floor it is noted, not refused.
#[test]
fn the_floor_rises_with_the_next_profile_and_then_refuses_v1_both_ways() {
    let Some(cap) = Capture::start() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    const THIRD: [u8; 32] = [0x7A; 32];
    bundle_verified(dd, &PEER, &HR3, &V1_ONLY, NOW).unwrap();
    session_confirmed(dd, &OTHER, &HR3, &Session(false), NOW).unwrap();
    assert!(!path(dd).exists(), "nothing to keep");
    bundle_verified(dd, &PEER, &HR3, &V1_AND_HR3, NOW).unwrap();
    session_confirmed(dd, &OTHER, &HR3, &Session(true), NOW).unwrap();
    let (peer, other) = (mark(dd, &PEER), mark(dd, &OTHER));
    assert_eq!((peer.profile_floor, peer.set_by), (3, SetBy::Bundle));
    assert_eq!((other.profile_floor, other.set_by), (3, SetBy::Session));
    let below = Err(Refusal::Floor(Downgrade::Profile { floor: 3, best: 1 }));
    {
        let _floor = SuiteFloor::on(true);
        for who in [&PEER, &OTHER] {
            assert_eq!(choose(dd, who, &set_of(&V1_ONLY)), below, "starting");
            assert_eq!(choose(dd, who, PAIR_INIT_V1), below, "taking");
            assert_eq!(choose(dd, who, &set_of(&V1_AND_HR3)), chose(3, false));
        }
        assert_eq!(choose(dd, &THIRD, PAIR_INIT_V1), chose(1, false));
    }
    let downgrade = |peer: [u8; 32]| {
        (
            SecKind::CapabilityDowngrade,
            Attribution::Contact { peer },
            VIA,
        )
    };
    assert_eq!(cap.kinds(), vec![downgrade(PEER), downgrade(OTHER)]);
    assert_eq!(mark(dd, &PEER).refused_profile, Some(1));
    // The suite floor shut: used as before, noted the next day again.
    let _floor = SuiteFloor::on(false);
    assert_eq!(
        choose_in(
            dd,
            &PEER,
            &profiles_with(&HR3),
            PAIR_INIT_V1,
            VIA,
            NOW + DAY_MS
        ),
        chose(1, false)
    );
    assert_eq!(cap.kinds().len(), 3);
}

/// Nothing but the contact's own security words lowers the floor (the old
/// code, another contact's words: no token; no call without one), and only
/// for that contact; then V1 goes both ways again. In ash, `raven contact
/// verify` and the terminal app's "Check again" make the token only after
/// the words match and the person typed `accept`
/// (`only_contact_verify_lowers_a_floor` keeps them the only callers).
#[test]
fn only_the_words_and_accept_let_v1_back_in() {
    let Some(_cap) = Capture::start() else {
        return;
    };
    let _floor = SuiteFloor::on(true);
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    for who in [&PEER, &OTHER] {
        bundle_verified(dd, who, &HR3, &V1_AND_HR3, NOW).unwrap();
    }
    let words = |peer: &[u8; 32]| security_words::words_v1(peer).join(" ");
    assert!(CodeMatch::check(&words(&OTHER), &PEER).is_none());
    assert!(CodeMatch::check(&crate::fingerprint::device_fingerprint_v1(&PEER), &PEER).is_none());
    assert!(choose(dd, &PEER, PAIR_INIT_V1).is_err());
    let matched = CodeMatch::check(&words(&PEER), &PEER).unwrap();
    assert_eq!(lower_floor(dd, &matched, NOW + 1), Ok(true));
    assert_eq!(choose(dd, &PEER, PAIR_INIT_V1), chose(1, false));
    assert_eq!(choose(dd, &PEER, &set_of(&V1_ONLY)), chose(1, false));
    assert!(
        choose(dd, &OTHER, PAIR_INIT_V1).is_err(),
        "only that contact"
    );
    // A later HR3 session raises it again.
    session_confirmed(dd, &PEER, &HR3, &Session(true), NOW + 2).unwrap();
    assert!(choose(dd, &PEER, PAIR_INIT_V1).is_err());
}

/// A notice marking `atsam/indexed-session/v1` (or `pairinit/1/1`)
/// DEPRECATED refuses nothing: a contact that offers HR3 gets HR3 without a
/// word, one that offers V1 only gets V1 and a warning, once per contact
/// and notice; the sessions open go on, PairInit V1 goes both ways, and
/// the lines say V1 is being retired.
#[test]
fn a_deprecated_v1_warns_once_per_contact_and_prefers_the_next_profile() {
    const SARA: [u8; 32] = [0x71; 32];
    const RENA: [u8; 32] = [0x72; 32];
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    {
        let Some(_notice) = Notice::apply(7, &[(reg::ATSAM_INDEXED_SESSION_V1, Level::Deprecated)])
        else {
            return;
        };
        let policy = suite_policy::applied().expect("the gate is open");
        assert_eq!(policy.profile_status(1), Status::Deprecated);
        assert_eq!(policy.profile_status(3), Status::Allowed);
        assert_eq!(policy.profile_refusal(1), None);
        assert_eq!(suite_policy::v1_sessions(Some(3)), V1Sessions::Go);
        assert!(suite_policy::session_allowed());
        assert_eq!(suite_policy::check_pair_init(), Ok(()));
        assert!(policy
            .lines(NOW)
            .iter()
            .any(|l| l.contains("being retired (atsam/indexed-session/v1)")));
        assert_eq!(choose(dd, &SARA, &set_of(&V1_AND_HR3)), chose(3, false));
        assert_eq!(choose(dd, &SARA, PAIR_INIT_V1), chose(1, true));
        assert_eq!(choose(dd, &SARA, &set_of(&V1_ONLY)), chose(1, false));
        assert_eq!(choose(dd, &RENA, PAIR_INIT_V1), chose(1, true));
    }
    // A later notice that still retires V1 warns again, once.
    let Some(_notice) = Notice::apply(8, &[(reg::PAIRINIT_V1_SUITE1, Level::Deprecated)]) else {
        return;
    };
    assert_eq!(choose(dd, &SARA, PAIR_INIT_V1), chose(1, true));
    assert_eq!(choose(dd, &SARA, PAIR_INIT_V1), chose(1, false));
    assert_eq!(
        suite_policy::retiring_contact_text("Sara"),
        "Sara's Raven still uses an older security method that is being retired. Ask Sara to \
         update Raven."
    );
    assert!(!path(dd).exists(), "no floor was written");
}

/// A notice marking `atsam/indexed-session/v1` BROKEN refuses V1 both ways
/// (no V1 session started or taken; HR3 still is) and retires the V1
/// sessions open: the mock program's sweep re-seals what waited in them
/// into an HR3 session with each contact that speaks HR3 (Phase 2a), and a
/// contact that speaks V1 only keeps them waiting; nothing seals on V1. A
/// build without a next profile holds them instead. `pairinit/1/1` BROKEN
/// alone refuses new V1 sessions and lets the open ones go on.
#[test]
fn a_broken_v1_is_refused_both_ways_and_its_sessions_retire_into_the_next_profile() {
    const OLD: [u8; 32] = [0x73; 32];
    /// The mock program's V1 sessions (contact, what waits, retired) and
    /// the HR3 sessions it made (contact, what was re-sealed into it).
    struct Program {
        v1: Vec<([u8; 32], Vec<&'static str>, bool)>,
        hr3: Vec<([u8; 32], Vec<&'static str>)>,
    }
    impl Program {
        /// What the program runs when the policy may have changed: its V1
        /// sessions as [`suite_policy::v1_sessions`] says, each contact's
        /// HR3 session chosen like any new session.
        fn sweep(&mut self, dd: &Path, sets: &[([u8; 32], &Bundle)]) {
            let V1Sessions::Retire { into } = suite_policy::v1_sessions(Some(HR3.profile_id()))
            else {
                return;
            };
            for (peer, waiting, retired) in &mut self.v1 {
                *retired = true;
                let (_, bundle) = sets.iter().find(|(p, _)| p == peer).unwrap();
                if choose(dd, peer, &set_of(bundle)).is_ok_and(|c| c.profile == into) {
                    self.hr3.push((*peer, std::mem::take(waiting)));
                }
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let Some(notice) = Notice::apply(9, &[(reg::ATSAM_INDEXED_SESSION_V1, Level::Broken)]) else {
        return;
    };
    let policy = suite_policy::applied().unwrap();
    let text = policy.profile_refusal(1).expect("refused");
    assert!(text.starts_with("SUITE_BROKEN: Raven security notice #9"));
    assert!(text.contains("(atsam/indexed-session/v1)"), "{text}");
    for offered in [set_of(&V1_ONLY), PAIR_INIT_V1.to_vec()] {
        assert_eq!(
            choose(dd, &PEER, &offered),
            Err(Refusal::Broken(text.clone()))
        );
    }
    assert_eq!(choose(dd, &PEER, &set_of(&V1_AND_HR3)), chose(3, false));
    assert!(!suite_policy::session_allowed(), "nothing seals on V1");
    assert_eq!(
        suite_policy::v1_sessions(Some(3)),
        V1Sessions::Retire { into: 3 }
    );
    assert_eq!(suite_policy::v1_sessions(None), V1Sessions::Held);
    let mut program = Program {
        v1: vec![(PEER, vec!["m1", "m2"], false), (OLD, vec!["m3"], false)],
        hr3: Vec::new(),
    };
    program.sweep(dd, &[(PEER, &V1_AND_HR3), (OLD, &V1_ONLY)]);
    assert_eq!(program.hr3, vec![(PEER, vec!["m1", "m2"])]);
    assert_eq!(
        program.v1,
        vec![(PEER, vec![], true), (OLD, vec!["m3"], true)]
    );
    drop(notice);
    // The PairInit alone: no new V1 session, the open ones go on.
    let Some(_notice) = Notice::apply(10, &[(reg::PAIRINIT_V1_SUITE1, Level::Broken)]) else {
        return;
    };
    assert!(
        matches!(choose(dd, &OLD, PAIR_INIT_V1), Err(Refusal::Broken(t)) if t.contains("(pairinit/1/1)"))
    );
    assert_eq!(suite_policy::v1_sessions(Some(3)), V1Sessions::Go);
    assert!(suite_policy::session_allowed());
    assert!(!path(dd).exists(), "a notice writes no floor");
}

/// With the advisory and events gates shut (a release build) the choice is
/// the highest profile in common: no floor, no notice, no warning, no
/// retirement, nothing written.
#[test]
fn with_the_gates_shut_the_choice_is_the_highest_in_common() {
    let _shut = Shut::start();
    security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(false));
    let _floor = SuiteFloor::on(true);
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    write_book(
        dd,
        &[(
            PEER,
            Floor {
                profile_floor: 3,
                ..Floor::new(1)
            },
        )],
    );
    let written = std::fs::read(path(dd)).unwrap();
    assert!(suite_policy::applied().is_none());
    assert_eq!(choose(dd, &PEER, PAIR_INIT_V1), chose(1, false));
    assert_eq!(choose(dd, &PEER, &set_of(&V1_AND_HR3)), chose(3, false));
    bundle_verified(dd, &OTHER, &HR3, &V1_AND_HR3, NOW).unwrap();
    session_confirmed(dd, &OTHER, &HR3, &Session(true), NOW).unwrap();
    assert_eq!(suite_policy::v1_sessions(Some(3)), V1Sessions::Go);
    assert_eq!(std::fs::read(path(dd)).unwrap(), written, "no write");
    security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
}
