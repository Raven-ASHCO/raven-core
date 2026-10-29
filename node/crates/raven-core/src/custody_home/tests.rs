//! P3.18 tests of the home-custodian choice: the pure selection table and
//! the file raven-node keeps (written only on change, a corrupt file read as
//! empty, the drain, unusable custodians, consent, sealing).

use super::*;
use crate::chat_history::BlockList;
use crate::node_policy::{save_policy, NodePolicy};
use crate::outbox::OutboxCarrier;
use crate::route_hints::{HintLink, ValidHints, RRH1_DEFAULT_TTL_S};

const MIN: u64 = 60 * 1000;
const HOUR: u64 = 60 * MIN;
const T0: u64 = 20_000 * 24 * HOUR;
const LOCAL: [u8; 32] = [0x01; 32];
const WAN: u8 = OFFER_WAN;
const REACH: u8 = OFFER_REACHABLE;

fn k(n: u8) -> [u8; 32] {
    [n; 32]
}

fn o(n: u8, flags: u8, heard_ms: u64) -> OfferView {
    OfferView {
        custodian: k(n),
        flags,
        heard_ms,
    }
}

// ── The pure table ──

#[test]
fn manual_wins_and_is_capped_at_two() {
    let offers = [o(3, WAN | REACH, T0), o(4, REACH, T0)];
    assert_eq!(
        select(&[k(5), k(6), k(7)], true, &offers, &[k(3)], true),
        [k(5), k(6)]
    );
    // Duplicates count once; one manual pick leaves the other slot empty.
    assert_eq!(select(&[k(5), k(5)], true, &offers, &[], true), [k(5)]);
    // Without a manual list the offers decide.
    assert_eq!(select(&[], true, &offers, &[], true), [k(3), k(4)]);
}

#[test]
fn no_consent_selects_nothing() {
    let offers = [o(3, REACH, T0)];
    assert!(select(&[], false, &offers, &[k(3)], false).is_empty());
    assert!(select(&[k(5)], false, &offers, &[], false).is_empty());
    assert!(
        select(&[], true, &[], &[k(3)], false).is_empty(),
        "no offer"
    );
}

#[test]
fn sticky_while_offering() {
    // k(3) is picked; newer and better offers do not move it while it still
    // offers and is reachable.
    let offers = [
        o(3, REACH, T0),
        o(4, REACH, T0 + HOUR),
        o(5, REACH, T0 + HOUR),
    ];
    assert_eq!(select(&[], true, &offers, &[k(3)], false), [k(3), k(4)]);
    // Both picks keep their places (and their order).
    assert_eq!(
        select(&[], true, &offers, &[k(5), k(3)], false),
        [k(5), k(3)]
    );
    // An unreachable pick stays while no reachable offer is unpicked.
    let only = [o(3, 0, T0), o(4, REACH, T0)];
    assert_eq!(select(&[], true, &only, &[k(3), k(4)], false), [k(3), k(4)]);
    // A pick that stopped offering goes; the slot is filled again.
    assert_eq!(
        select(&[], true, &offers[1..], &[k(3)], false),
        [k(4), k(5)]
    );
}

#[test]
fn reachable_offer_replaces_an_unreachable_pick() {
    let offers = [o(3, 0, T0 + HOUR), o(4, REACH, T0), o(6, REACH, T0)];
    assert_eq!(
        select(&[], true, &offers, &[k(3), k(4)], false),
        [k(6), k(4)]
    );
    // A WAN offer that is not reachable does not displace anything.
    let wan = [o(3, REACH, T0), o(4, REACH, T0), o(5, WAN, T0 + HOUR)];
    assert_eq!(select(&[], true, &wan, &[k(3), k(4)], true), [k(3), k(4)]);
}

#[test]
fn wan_offer_preferred_only_when_wan_live() {
    let offers = [o(3, REACH, T0 + HOUR), o(4, WAN | REACH, T0), o(5, WAN, T0)];
    assert_eq!(select(&[], true, &offers, &[], true), [k(4), k(5)]);
    assert_eq!(select(&[], true, &offers, &[], false), [k(3), k(4)]);
    // WAN first, then REACHABLE: a WAN offer that is not reachable still
    // goes before a reachable one while WAN is live.
    let mixed = [o(3, REACH, T0 + HOUR), o(5, WAN, T0)];
    assert_eq!(select(&[], true, &mixed, &[], true), [k(5), k(3)]);
    assert_eq!(select(&[], true, &mixed, &[], false), [k(3), k(5)]);
}

#[test]
fn tie_break_is_deterministic() {
    let offers = [o(9, REACH, T0), o(7, REACH, T0), o(8, REACH, T0)];
    let picks = select(&[], true, &offers, &[], false);
    assert_eq!(picks, [k(7), k(8)], "equal offers: the lower key");
    let mut reversed = offers;
    reversed.reverse();
    assert_eq!(select(&[], true, &reversed, &[], false), picks);
    // Newest heard first; one custodian's newest offer counts.
    let twice = [
        o(9, 0, T0 + HOUR),
        o(9, REACH, T0 + 2 * HOUR),
        o(7, REACH, T0),
    ];
    assert_eq!(select(&[], true, &twice, &[], false), [k(9), k(7)]);
    let stale = [o(9, REACH, T0), o(9, 0, T0 + 2 * HOUR), o(7, REACH, T0)];
    assert_eq!(select(&[], true, &stale, &[], false), [k(7), k(9)]);
}

// ── The file ──

/// The contact book: `(key, verified)` rows.
fn book(dd: &Path, rows: &[([u8; 32], bool)]) {
    let rows: Vec<serde_json::Value> = rows
        .iter()
        .map(|(key, pinned)| {
            serde_json::json!({
                "petname": format!("p{}", key[0]), "pub_hex": hex::encode(key),
                "pinned": pinned, "lan_dial": "", "internet_dial": "",
            })
        })
        .collect();
    std::fs::write(dd.join("contacts.json"), serde_json::to_vec(&rows).unwrap()).unwrap();
}

fn consent(dd: &Path, on: Option<bool>, manual: &[[u8; 32]]) {
    save_policy(
        dd,
        &NodePolicy {
            custody_use: on,
            custody_home: manual.iter().map(hex::encode).collect(),
            ..NodePolicy::default()
        },
    )
    .unwrap();
}

/// `custodian`'s RRH1 stored at `at`: an offer with `flags`, or none.
fn heard(dd: &Path, custodian: [u8; 32], flags: Option<u8>, at: u64) {
    let v = ValidHints {
        generation: at,
        ttl_s: RRH1_DEFAULT_TTL_S,
        custody_offer: flags,
        ..Default::default()
    };
    let link = HintLink::fixture(OutboxCarrier::P2p, true);
    crate::learned_routes::apply_ungated(dd, &custodian, &v, &link, None, at).unwrap();
}

fn saved(dd: &Path) -> HomeFile {
    serde_json::from_slice(&std::fs::read(dd.join(CUSTODY_HOME_FILE)).unwrap()).unwrap()
}

fn mtime(dd: &Path) -> std::time::SystemTime {
    std::fs::metadata(dd.join(CUSTODY_HOME_FILE))
        .unwrap()
        .modified()
        .unwrap()
}

/// Three verified friends that offer (k(3) and k(4) reachable), one that
/// is not verified (k(9), offering too), consent given.
fn world() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    book(
        dd,
        &[(k(3), true), (k(4), true), (k(5), true), (k(9), false)],
    );
    consent(dd, Some(true), &[]);
    heard(dd, k(3), Some(REACH), T0);
    heard(dd, k(4), Some(REACH), T0 + 1);
    heard(dd, k(5), Some(0), T0 + 2);
    heard(dd, k(9), Some(WAN | REACH), T0 + 3);
    dir
}

#[test]
fn refresh_persists_only_on_change_and_corrupt_file_reads_empty() {
    let dir = world();
    let dd = dir.path();
    assert!(home(dd, &LOCAL, T0).is_empty(), "nothing chosen yet");
    let now = T0 + MIN;
    assert_eq!(refresh(dd, &LOCAL, now), Ok((vec![k(4), k(3)], true)));
    assert_eq!(home(dd, &LOCAL, now), [k(4), k(3)]);
    assert_eq!(fetch_from(dd, &LOCAL, now), [k(4), k(3)]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dd.join(CUSTODY_HOME_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Nothing changed: the file is not written again.
    let old = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
    std::fs::OpenOptions::new()
        .write(true)
        .open(dd.join(CUSTODY_HOME_FILE))
        .unwrap()
        .set_modified(old)
        .unwrap();
    assert_eq!(
        refresh(dd, &LOCAL, now + MIN),
        Ok((vec![k(4), k(3)], false))
    );
    assert_eq!(mtime(dd), old);
    // A corrupt file reads as empty and is replaced.
    std::fs::write(dd.join(CUSTODY_HOME_FILE), b"{not json").unwrap();
    assert!(home(dd, &LOCAL, now).is_empty());
    assert!(fetch_from(dd, &LOCAL, now).is_empty());
    let (picks, changed) = refresh(dd, &LOCAL, now + 2 * MIN).unwrap();
    assert_eq!((picks.len(), changed), (2, true));
    assert_eq!(saved(dd).picked.len(), 2);
}

#[test]
fn a_withdrawn_offer_retires_the_pick_for_drain_ms() {
    let dir = world();
    let dd = dir.path();
    let now = T0 + MIN;
    refresh(dd, &LOCAL, now).unwrap();
    // k(3) stops offering: k(5) (the only other offer) takes its place.
    let later = now + HOUR;
    heard(dd, k(3), None, later);
    assert_eq!(refresh(dd, &LOCAL, later), Ok((vec![k(4), k(5)], true)));
    assert_eq!(saved(dd).retired, [(hex::encode(k(3)), later + DRAIN_MS)]);
    assert_eq!(
        DRAIN_MS,
        u64::from(RRH1_DEFAULT_TTL_S) * 1000
            + crate::carrier_admission::MAX_CUSTODY_VALIDITY_MS
            + HOUR,
        "the announced TTL, the custody validity limit and an hour"
    );
    const { assert!(DRAIN_MS >= 97 * HOUR) };
    assert_eq!(home(dd, &LOCAL, later), [k(4), k(5)]);
    assert_eq!(fetch_from(dd, &LOCAL, later), [k(4), k(5), k(3)]);
    let end = later + DRAIN_MS;
    assert_eq!(fetch_from(dd, &LOCAL, end - 1), [k(4), k(5), k(3)]);
    assert_eq!(fetch_from(dd, &LOCAL, end), [k(4), k(5)]);
    // Picked again, it is no longer retired.
    heard(dd, k(4), None, later + MIN);
    heard(dd, k(3), Some(REACH), later + 2 * MIN);
    let (picks, _) = refresh(dd, &LOCAL, later + 3 * MIN).unwrap();
    assert_eq!(picks, [k(3), k(5)]);
    let retired = saved(dd).retired;
    assert_eq!(
        retired,
        [(hex::encode(k(4)), later + 3 * MIN + DRAIN_MS)],
        "only k(4) drains now"
    );
    // A drained entry leaves the file at the next refresh after its end
    // (the picks still offer: their snapshots, which outlive no drain, were
    // heard again meanwhile).
    let after = later + 3 * MIN + DRAIN_MS;
    heard(dd, k(3), Some(REACH), after - MIN);
    heard(dd, k(5), Some(0), after - MIN);
    assert_eq!(refresh(dd, &LOCAL, after), Ok((vec![k(3), k(5)], false)));
    assert!(saved(dd).retired.is_empty());
}

#[test]
fn unpinned_custodian_dropped_without_drain() {
    let dir = world();
    let dd = dir.path();
    let now = T0 + MIN;
    refresh(dd, &LOCAL, now).unwrap();
    // k(9) offered WAN | REACHABLE but is not verified: never picked.
    assert!(!home(dd, &LOCAL, now).contains(&k(9)));
    // k(3) is no longer verified, k(4) is blocked: both go at once.
    book(dd, &[(k(3), false), (k(4), true), (k(5), true)]);
    let mut blocks = BlockList::default();
    blocks.block(&hex::encode(k(4)));
    blocks.save(dd).unwrap();
    assert_eq!(home(dd, &LOCAL, now), Vec::<[u8; 32]>::new());
    assert!(fetch_from(dd, &LOCAL, now).is_empty());
    assert_eq!(refresh(dd, &LOCAL, now + MIN), Ok((vec![k(5)], true)));
    let file = saved(dd);
    assert!(file.retired.is_empty(), "{file:?}");
    assert_eq!(fetch_from(dd, &LOCAL, now + MIN), [k(5)]);
    // A retired pick that becomes unusable stops draining at once too.
    heard(dd, k(5), None, now + 2 * MIN);
    refresh(dd, &LOCAL, now + 3 * MIN).unwrap();
    assert_eq!(saved(dd).retired.len(), 1);
    book(dd, &[(k(3), false), (k(4), true)]);
    assert!(fetch_from(dd, &LOCAL, now + 4 * MIN).is_empty());
    refresh(dd, &LOCAL, now + 4 * MIN).unwrap();
    assert!(saved(dd).retired.is_empty());
    // A manual pick that is not usable is ignored; this node never is one.
    consent(dd, Some(true), &[k(3), LOCAL]);
    assert!(home(dd, &LOCAL, now).is_empty());
    // An unreadable contact book picks nobody and writes nothing.
    std::fs::write(dd.join("contacts.json"), b"[{").unwrap();
    assert!(home(dd, &LOCAL, now).is_empty());
    let before = std::fs::read(dd.join(CUSTODY_HOME_FILE)).unwrap();
    assert!(refresh(dd, &LOCAL, now + 5 * MIN).is_err());
    assert_eq!(std::fs::read(dd.join(CUSTODY_HOME_FILE)).unwrap(), before);
}

#[test]
fn consent_off_retires_all_and_fetch_from_still_drains() {
    let dir = world();
    let dd = dir.path();
    let now = T0 + MIN;
    refresh(dd, &LOCAL, now).unwrap();
    consent(dd, Some(false), &[]);
    assert!(home(dd, &LOCAL, now).is_empty(), "no consent, no home");
    let off = now + HOUR;
    assert_eq!(refresh(dd, &LOCAL, off), Ok((Vec::new(), true)));
    let file = saved(dd);
    assert!(file.picked.is_empty());
    assert_eq!(file.retired.len(), 2);
    assert!(file
        .retired
        .iter()
        .all(|(_, until)| *until == off + DRAIN_MS));
    // Mail already left there, or left by a sender who did not hear of the
    // change yet, is still collected for the whole drain.
    assert_eq!(fetch_from(dd, &LOCAL, off + DRAIN_MS - 1), [k(3), k(4)]);
    assert!(fetch_from(dd, &LOCAL, off + DRAIN_MS).is_empty());
    // Never asked is the same as no.
    consent(dd, None, &[k(3)]);
    assert_eq!(refresh(dd, &LOCAL, off + MIN), Ok((Vec::new(), false)));
    // Yes again, with a manual pick: manual wins, and the drains of the
    // others go on.
    consent(dd, Some(true), &[k(5)]);
    assert_eq!(refresh(dd, &LOCAL, off + 2 * MIN), Ok((vec![k(5)], true)));
    assert_eq!(home(dd, &LOCAL, off + 2 * MIN), [k(5)]);
    assert_eq!(fetch_from(dd, &LOCAL, off + 2 * MIN), [k(5), k(3), k(4)]);
}

/// `friends` offer two at a time, a pair each round (the previous pair
/// withdraws), each round a minute after the last: each pair is picked and
/// the pair before it retires. The time of the last round.
fn churn(dd: &Path, friends: &[[u8; 32]], mut now: u64) -> u64 {
    book(dd, &friends.iter().map(|f| (*f, true)).collect::<Vec<_>>());
    consent(dd, Some(true), &[]);
    let mut previous: &[[u8; 32]] = &[];
    for pair in friends.chunks(2) {
        now += MIN;
        for f in pair {
            heard(dd, *f, Some(REACH), now);
        }
        for f in previous {
            heard(dd, *f, None, now);
        }
        refresh(dd, &LOCAL, now).unwrap();
        previous = pair;
    }
    now
}

/// The Phase 3 re-verify's D-1 follow-on: more than 8 different picks
/// dropped within one drain (the old cap, which cut the oldest drains short)
/// all drain until their own ends.
#[test]
fn every_dropped_pick_drains_until_its_end() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let friends: Vec<[u8; 32]> = (10..22).map(k).collect();
    let start = T0;
    let now = churn(dd, &friends, start);
    let file = saved(dd);
    assert_eq!(file.picked.len(), 2);
    assert_eq!(file.retired.len(), 10, "{file:?}");
    // Every friend: the two picks and the ten dropped ones, each until its
    // drain ends (the pair of round r was dropped in round r + 1).
    let mut all = fetch_from(dd, &LOCAL, now);
    all.sort();
    assert_eq!(all, friends);
    for (r, pair) in friends.chunks(2).take(5).enumerate() {
        let end = start + (r as u64 + 2) * MIN + DRAIN_MS;
        for f in pair {
            assert!(fetch_from(dd, &LOCAL, end - 1).contains(f), "round {r}");
            assert!(!fetch_from(dd, &LOCAL, end).contains(f), "round {r}");
        }
    }
}

#[test]
fn retired_list_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let n = u8::try_from(MAX_RETIRED + 4).unwrap();
    let friends: Vec<[u8; 32]> = (10..10 + n).map(k).collect();
    let now = churn(dd, &friends, T0);
    let file = saved(dd);
    assert_eq!(file.picked.len(), 2);
    assert_eq!(file.retired.len(), MAX_RETIRED);
    // The drains that end first went: the first pair dropped.
    let first = [hex::encode(friends[0]), hex::encode(friends[1])];
    assert!(file.retired.iter().all(|(key, _)| !first.contains(key)));
    assert!(fetch_from(dd, &LOCAL, now).len() <= MAX_HOME + MAX_RETIRED);
}

#[test]
fn sealed_in_a_sealed_profile() {
    use crate::contact_book::tests::{profile, seal};
    let dir = profile();
    let dd = dir.path();
    book(dd, &[(k(3), true), (k(4), true)]);
    consent(dd, Some(true), &[]);
    heard(dd, k(3), Some(REACH), T0);
    let now = T0 + MIN;
    // A plain file is sealed by the migration with the rest.
    refresh(dd, &LOCAL, now).unwrap();
    assert!(std::fs::read(dd.join(CUSTODY_HOME_FILE))
        .unwrap()
        .windows(64)
        .any(|w| w == hex::encode(k(3)).as_bytes()));
    seal(dd);
    let raw = std::fs::read(dd.join(CUSTODY_HOME_FILE)).unwrap();
    assert!(raw.starts_with(b"RMS1"), "sealed");
    assert_eq!(raw[5], Kind::CustodyHome.code());
    assert_eq!(home(dd, &LOCAL, now), [k(3)]);
    // Written sealed.
    heard(dd, k(4), Some(REACH), now + MIN);
    assert_eq!(
        refresh(dd, &LOCAL, now + 2 * MIN),
        Ok((vec![k(3), k(4)], true))
    );
    let raw = std::fs::read(dd.join(CUSTODY_HOME_FILE)).unwrap();
    assert!(raw.starts_with(b"RMS1"));
    for key in [k(3), k(4)] {
        let hex = hex::encode(key);
        assert!(!raw.windows(64).any(|w| w == hex.as_bytes()));
    }
    assert_eq!(home(dd, &LOCAL, now + 2 * MIN), [k(3), k(4)]);
}

/// Review D-1: a sender that never heard the newer announcement keeps P's
/// old custodian tag as long as P's last snapshot lives (the TTL P
/// announced), and what it leaves there lives up to the custody validity
/// limit: a dropped pick is fetched from until both have run out.
#[test]
fn dropped_pick_is_fetched_until_every_tag_a_sender_may_still_hold_has_expired() {
    let dir = world();
    let dd = dir.path();
    let now = T0 + MIN;
    assert_eq!(refresh(dd, &LOCAL, now), Ok((vec![k(4), k(3)], true)));
    // Mailboxes off at `off`: both picks retire.
    consent(dd, Some(false), &[]);
    let off = now + MIN;
    refresh(dd, &LOCAL, off).unwrap();
    // The last snapshot a sender holds was sent just before `off`; it
    // deposits at k(3) until that snapshot expires, and the object it left
    // last lives up to the validity limit after that.
    let last_deposit = off + u64::from(RRH1_DEFAULT_TTL_S) * 1000;
    let last_object_ends = last_deposit + crate::carrier_admission::MAX_CUSTODY_VALIDITY_MS;
    for at in [
        off + 25 * HOUR,
        off + 48 * HOUR,
        last_deposit,
        last_object_ends - 1,
    ] {
        assert!(
            fetch_from(dd, &LOCAL, at).contains(&k(3)),
            "still collected {} h after the drop",
            (at - off) / HOUR
        );
    }
    assert!(fetch_from(dd, &LOCAL, off + DRAIN_MS).is_empty());
}

/// Review D-1, both ends (the reviewer's experiment): P drops its home
/// custodian C while S, not linked to P, keeps P's last announcement.
/// Whenever S would still leave P's mail at C, P still collects from C until
/// what S left there has expired.
#[test]
fn a_sender_deposits_only_where_the_recipient_still_collects() {
    use crate::custody_gate::{
        set_custody_gates_for_this_thread, set_custody_hints_for_this_thread, CustodyGates,
    };
    let (s, p, c) = (k(0x51), k(0x52), k(0x53));
    let ttl = u64::from(RRH1_DEFAULT_TTL_S) * 1000;
    /// What a contact told: (sender, custodian tags, custody offer).
    type Told = ([u8; 32], Vec<[u8; 32]>, Option<u8>);
    /// learned_routes.json: each [`Told`], heard at `at`.
    fn learned(dd: &Path, at: u64, ttl: u64, rows: &[Told]) {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|(from, tags, offer)| {
                let mut r = serde_json::json!({
                    "pub_hex": hex::encode(from), "generation": at, "received_at_ms": at,
                    "expires_at_ms": at + ttl, "via": "lan",
                });
                if !tags.is_empty() {
                    r["custodian_tags"] = tags.iter().map(hex::encode).collect();
                    r["custodian_tag_flags"] = vec![0u8; tags.len()].into();
                }
                if let Some(f) = offer {
                    r["custody_offer"] = (*f).into();
                }
                r
            })
            .collect();
        std::fs::write(
            dd.join(crate::learned_routes::LEARNED_ROUTES_FILE),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
    set_custody_gates_for_this_thread(Some(CustodyGates {
        live: true,
        wan: false,
    }));
    set_custody_hints_for_this_thread(Some(true));
    // P collects its mail at C, which offers.
    let pd = tempfile::tempdir().unwrap();
    book(pd.path(), &[(s, true), (c, true)]);
    consent(pd.path(), Some(true), &[]);
    learned(pd.path(), T0, ttl, &[(c, vec![], Some(0))]);
    assert_eq!(refresh(pd.path(), &p, T0), Ok((vec![c], true)));
    // S heard P announce C (its tag), and C's offer, at T0.
    let sd = tempfile::tempdir().unwrap();
    book(sd.path(), &[(p, true), (c, true)]);
    consent(sd.path(), Some(true), &[]);
    let tag = crate::route_hints::custodian_tag(&p, &s, &c);
    learned(
        sd.path(),
        T0,
        ttl,
        &[(p, vec![tag], None), (c, vec![], Some(0))],
    );
    // A minute later P turns mailboxes off; S does not hear of it.
    consent(pd.path(), Some(false), &[]);
    let t1 = T0 + MIN;
    refresh(pd.path(), &p, t1).unwrap();
    let mut deposited = 0;
    for hours in [1u64, 24, 25, 26, 48, 71, 72, 73] {
        let at = t1 + hours * HOUR;
        let deposits = crate::custody_client::deposit_custodians(sd.path(), &s, &p, at)
            .iter()
            .any(|(key, _)| *key == c);
        if deposits {
            deposited += 1;
            let ends = at + crate::carrier_admission::MAX_CUSTODY_VALIDITY_MS;
            assert!(
                fetch_from(pd.path(), &p, ends - 1).contains(&c),
                "S leaves P's mail at C {hours} h after the drop, P stopped collecting there"
            );
        }
    }
    assert!(deposited >= 5, "S kept depositing while P's snapshot lived");
    set_custody_hints_for_this_thread(None);
    set_custody_gates_for_this_thread(None);
}

/// Review D-8: forgetting a contact takes it out of the file, picked or
/// draining; nothing else changes, and a file that names it nowhere is not
/// written.
#[test]
fn forget_drops_a_removed_contact_picked_or_draining() {
    let dir = world();
    let dd = dir.path();
    let now = T0 + MIN;
    refresh(dd, &LOCAL, now).unwrap();
    // k(3) stops offering: retired (draining), k(5) takes its place.
    heard(dd, k(3), None, now + MIN);
    refresh(dd, &LOCAL, now + 2 * MIN).unwrap();
    let file = saved(dd);
    assert_eq!(file.picked, [hex::encode(k(4)), hex::encode(k(5))]);
    assert_eq!(file.retired.len(), 1);
    forget(dd, &k(3)).unwrap();
    assert!(saved(dd).retired.is_empty());
    forget(dd, &k(4)).unwrap();
    assert_eq!(saved(dd).picked, [hex::encode(k(5))]);
    // Nobody to forget: not written.
    let old = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
    std::fs::OpenOptions::new()
        .write(true)
        .open(dd.join(CUSTODY_HOME_FILE))
        .unwrap()
        .set_modified(old)
        .unwrap();
    forget(dd, &k(9)).unwrap();
    assert_eq!(mtime(dd), old);
    // No file: nothing to do.
    let empty = tempfile::tempdir().unwrap();
    forget(empty.path(), &k(3)).unwrap();
    assert!(!empty.path().join(CUSTODY_HOME_FILE).exists());
}
