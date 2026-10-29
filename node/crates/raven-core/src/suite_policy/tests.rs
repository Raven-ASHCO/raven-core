//! The suite policy (step P6.45): what an advisory's entries make of it
//! (any build), the consult points and every gate under it (a debug build
//! applies a policy to its own thread; a release build checks that nothing
//! applies), and the cache over a profile's state file.

use super::*;
use crate::advisory::{AdvisoryDraft, Entry, EntryKind, Severity};
use crate::outbox::OutboxCarrier;
use crate::release_keys::test_keys::{key_set, signers};
use crate::security_gate::SecGate as G;
use crate::suite_registry::{self as reg, FEATURES, SUITES};
use crate::tlog::{EntryType, LogEntry, Snapshot, SthDraft};
use crate::update_state::{Build, Origin};

/// 2026-10-24T00:00:00Z.
const T0: u64 = 1_792_800_000_000;
const DAY_MS: u64 = 86_400_000;

fn entry(kind: EntryKind, severity: Severity, target: &str) -> Entry {
    Entry {
        kind,
        severity,
        target: target.to_owned(),
        arg: Vec::new(),
        text_id: 0,
    }
}

fn suite(severity: Severity, id: &str) -> Entry {
    entry(EntryKind::SuiteStatus, severity, id)
}

fn hold(severity: Severity, id: &str) -> Entry {
    entry(EntryKind::FeatureHold, severity, id)
}

fn notice(text: &str) -> Entry {
    Entry {
        arg: text.as_bytes().to_vec(),
        ..entry(EntryKind::Notice, Severity::Info, "notice")
    }
}

fn floor(serial: u64) -> Entry {
    Entry {
        arg: serial.to_be_bytes().to_vec(),
        ..entry(EntryKind::ReleaseFloor, Severity::Deprecated, "raven")
    }
}

/// Notice #6, issued at T0, read by a build of serial 3.
fn policy(entries: Vec<Entry>) -> Policy {
    Policy::of_entries(6, T0, &entries, 3)
}

/// Every suite and every feature at `severity`.
fn everything(severity: Severity) -> Vec<Entry> {
    SUITES
        .iter()
        .map(|s| suite(severity, s.id))
        .chain(FEATURES.iter().map(|f| hold(severity, f.id)))
        .collect()
}

/// The advisory gate open on this thread with a policy applied to it; both
/// undone on drop. `None` in a release build (nothing opens there).
struct Applied(());

impl Applied {
    fn open(policy: Policy) -> Option<Self> {
        security_gate::set_lab_for_this_thread(G::Advisory, Some(true));
        if !security_gate::live(G::Advisory) {
            security_gate::set_lab_for_this_thread(G::Advisory, None);
            return None;
        }
        set_policy_for_this_thread(Some(policy));
        Some(Self(()))
    }

    fn set(&self, policy: Policy) {
        set_policy_for_this_thread(Some(policy));
    }
}

impl Drop for Applied {
    fn drop(&mut self) {
        set_policy_for_this_thread(None);
        security_gate::set_lab_for_this_thread(G::Advisory, None);
    }
}

/// Every gate that has a per-thread switch opened (or shut) on this thread;
/// all back to the variables on drop.
struct Labs(());

impl Labs {
    fn set(open: bool) -> Self {
        for g in G::ALL.into_iter().filter(|g| *g != G::Advisory) {
            security_gate::set_lab_for_this_thread(g, Some(open));
        }
        crate::session_renewal::set_lab_session_renewal_for_this_thread(Some(open));
        crate::session_reset::set_lab_session_reset_for_this_thread(Some(if open { 2 } else { 0 }));
        crate::horizon::set_lab_horizon_for_this_thread(Some(open));
        crate::horizon::set_lab_letter_for_this_thread(Some(open));
        crate::custody_gate::set_custody_gates_for_this_thread(Some(
            crate::custody_gate::CustodyGates {
                live: open,
                wan: open,
            },
        ));
        crate::custody_gate::set_handoff_gate_for_this_thread(Some(open));
        crate::app_channel::set_test_lab(Some(open));
        Self(())
    }
}

impl Drop for Labs {
    fn drop(&mut self) {
        for g in G::ALL.into_iter().filter(|g| *g != G::Advisory) {
            security_gate::set_lab_for_this_thread(g, None);
        }
        crate::session_renewal::set_lab_session_renewal_for_this_thread(None);
        crate::session_reset::set_lab_session_reset_for_this_thread(None);
        crate::horizon::set_lab_horizon_for_this_thread(None);
        crate::horizon::set_lab_letter_for_this_thread(None);
        crate::custody_gate::set_custody_gates_for_this_thread(None);
        crate::custody_gate::set_handoff_gate_for_this_thread(None);
        crate::app_channel::set_test_lab(None);
    }
}

type Check = (&'static str, fn() -> bool);

/// Every gate's live check, by the feature a hold names.
fn gate_checks() -> Vec<Check> {
    use crate::security_gate::live;
    vec![
        (reg::FEATURE_ADVISORY, || live(G::Advisory)),
        (
            reg::FEATURE_APP_CHANNEL,
            crate::app_channel::app_channel_live_enabled,
        ),
        (
            reg::FEATURE_ASYNC_LETTER,
            crate::horizon::letter_live_enabled,
        ),
        (
            reg::FEATURE_CUSTODY_HANDOFF,
            crate::custody_gate::handoff_live,
        ),
        (reg::FEATURE_FRIEND_CUSTODY, || {
            crate::custody_gate::CustodyGates::current().live
        }),
        (
            reg::FEATURE_FRIEND_RELAY,
            crate::p2p_gate::friend_relay_live_enabled,
        ),
        (reg::FEATURE_GROUPS, crate::group::group_live_enabled),
        (
            reg::FEATURE_INDEXED_SESSION_STORE,
            crate::indexed_session_store::live_enabled,
        ),
        (
            reg::FEATURE_INTERNET_DIRECT,
            crate::internet_gate::internet_direct_live_enabled,
        ),
        (reg::FEATURE_LAN_AUTO_LISTEN, crate::lan_gate::lan_auto_live),
        (reg::FEATURE_LAN_BEACON, crate::lan_beacon::lan_beacon_live),
        (
            reg::FEATURE_LAN_DIRECT,
            crate::lan_gate::lan_direct_live_enabled,
        ),
        (
            reg::FEATURE_LAN_NOISE_PIN,
            crate::lan_gate::lan_noise_pin_live,
        ),
        (reg::FEATURE_LEARNING, crate::learning::learning_live),
        (reg::FEATURE_LINK_KNOCK, || live(G::LinkKnock)),
        (reg::FEATURE_LINK_PADDING, || live(G::LinkPadding)),
        (reg::FEATURE_LISTEN_PORT_RANDOM, || live(G::RandomPort)),
        (reg::FEATURE_LOCAL_PROTECTION, || live(G::LocalProtection)),
        (
            reg::FEATURE_LONG_HORIZON,
            crate::horizon::horizon_live_enabled,
        ),
        (reg::FEATURE_MESH_UPDATE, || live(G::MeshUpdate)),
        (
            reg::FEATURE_NAT_CLASS,
            crate::portmap_gate::nat_class_live_enabled,
        ),
        (reg::FEATURE_NEARBY, crate::nearby_gate::nearby_live_enabled),
        (reg::FEATURE_OFFLINE_LAN, crate::lan_gate::offline_lan_live),
        (reg::FEATURE_ONION, crate::onion_gate::onion_live_enabled),
        (reg::FEATURE_P2P, crate::p2p_gate::p2p_live_enabled),
        (reg::FEATURE_PAIR_SEED, || live(G::PairSeed)),
        (
            reg::FEATURE_PEER_ROTATION,
            crate::portmap_gate::peer_rotation_live_enabled,
        ),
        (
            reg::FEATURE_PORT_MAP,
            crate::portmap_gate::port_map_live_enabled,
        ),
        (
            reg::FEATURE_PREKEY_LIFECYCLE,
            crate::prekey_lifecycle::live_enabled,
        ),
        (reg::FEATURE_RELEASE_BUNDLE, || live(G::ReleaseBundle)),
        (
            reg::FEATURE_ROUTE_HINTS,
            crate::route_hints::route_hints_live,
        ),
        (reg::FEATURE_SECURITY_EVENTS, || live(G::Events)),
        (reg::FEATURE_SECURITY_RESPONSES, || live(G::Responses)),
        (
            reg::FEATURE_SERVERLESS_PUNCH,
            crate::portmap_gate::serverless_punch_live_enabled,
        ),
        (
            reg::FEATURE_SESSION_RENEWAL,
            crate::session_renewal::session_renewal_live_enabled,
        ),
        (
            reg::FEATURE_SESSION_RESET,
            crate::session_reset::session_reset_live_enabled,
        ),
        (
            reg::FEATURE_SESSION_RESET_RESTORE,
            crate::session_reset::session_reset_restore_live_enabled,
        ),
        (
            reg::FEATURE_STUN_DISCOVERY,
            crate::portmap_gate::stun_discovery_live_enabled,
        ),
        (reg::FEATURE_SUITE_FLOOR, || live(G::SuiteFloor)),
        (
            reg::FEATURE_V6_PINHOLE,
            crate::portmap_gate::v6_pinhole_live_enabled,
        ),
        (reg::FEATURE_WSS, crate::wss_gate::wss_live_enabled),
        (
            reg::FEATURE_WSS_PROXY,
            crate::wss_gate::wss_proxy_live_enabled,
        ),
    ]
}

/// Checks made of the gates: they follow them.
fn composite_checks() -> Vec<Check> {
    vec![
        ("lan_usable_now", crate::lan_gate::lan_usable_now),
        ("relay_offers_live", crate::p2p_gate::relay_offers_live),
        (
            "custody_hints_live",
            crate::custody_gate::custody_hints_live,
        ),
        ("receiver_dedup_live", crate::horizon::receiver_dedup_live),
        ("rrh1 on lan", || {
            crate::route_hints::route_hints_live_on(OutboxCarrier::Lan)
        }),
        ("rrh1 on internet", || {
            crate::route_hints::route_hints_live_on(OutboxCarrier::Internet)
        }),
        ("rrh1 on p2p", || {
            crate::route_hints::route_hints_live_on(OutboxCarrier::P2p)
        }),
        ("rrh1 on nearby", || {
            crate::route_hints::route_hints_live_on(OutboxCarrier::Nearby)
        }),
        ("security_sense", crate::security_sense::live),
    ]
}

/// The table above names every gate of raven-core, each once.
#[test]
fn every_gate_has_its_live_check_here() {
    let named: Vec<&str> = gate_checks().iter().map(|(id, _)| *id).collect();
    let registry: Vec<&str> = FEATURES.iter().map(|f| f.id).collect();
    assert_eq!(named, registry, "one check per feature, in registry order");
}

/// A small deterministic generator (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Advisory content of every shape: each id at each severity under its own
/// kind and the other's, everything BROKEN at once, ids and kinds this
/// build does not know, and random lists (valid RAD1 or not).
fn contents() -> Vec<Vec<Entry>> {
    let severities = [Severity::Info, Severity::Deprecated, Severity::Broken];
    let mut targets: Vec<&str> = SUITES
        .iter()
        .map(|s| s.id)
        .chain(FEATURES.iter().map(|f| f.id))
        .collect();
    targets.extend([
        "feature/nothing",
        "noise/xx-448-aesgcm-sha512",
        "pairinit/1/2",
        "raven",
        "notice",
        "keys",
    ]);
    let mut out = Vec::new();
    for target in &targets {
        for severity in severities {
            out.push(vec![suite(severity, target)]);
            out.push(vec![hold(severity, target)]);
            out.push(vec![entry(EntryKind::Other(0x77), severity, target)]);
        }
    }
    out.push(everything(Severity::Broken));
    out.push(everything(Severity::Deprecated));
    out.push(vec![
        floor(u64::MAX),
        notice("\u{1b}[2J open everything"),
        Entry {
            arg: vec![0xFF; 40],
            ..entry(EntryKind::KeySet, Severity::Broken, "keys")
        },
    ]);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..300 {
        let n = 1 + rng.below(64);
        let list = (0..n)
            .map(|_| {
                let kind = match rng.below(7) {
                    0 => EntryKind::SuiteStatus,
                    1 => EntryKind::ReleaseFloor,
                    2 => EntryKind::FeatureHold,
                    3 => EntryKind::Notice,
                    4 => EntryKind::KeySet,
                    _ => EntryKind::Other(0x06 + rng.below(0xFA) as u8),
                };
                Entry {
                    arg: (0..rng.below(12)).map(|_| rng.next() as u8).collect(),
                    ..entry(
                        kind,
                        severities[rng.below(3)],
                        targets[rng.below(targets.len())],
                    )
                }
            })
            .collect();
        out.push(list);
    }
    out
}

/// Design D §7, the acceptance property: no advisory content can make a
/// closed gate live. Every gate and every check made of them, with the
/// per-thread switches shut and open: under any policy each answers at
/// most what it answers under none.
#[test]
fn no_advisory_content_makes_a_closed_gate_live() {
    // `raven lan off` is one switch per process: unchanged while we read.
    let _lan = crate::lan_gate::lan_user_switch_untouched();
    let checks: Vec<Check> = gate_checks()
        .into_iter()
        .chain(composite_checks())
        .collect();
    let contents = contents();
    for open in [false, true] {
        let _labs = Labs::set(open);
        let Some(applied) = Applied::open(Policy::default()) else {
            // A release build: no policy applies at all.
            set_policy_for_this_thread(Some(policy(everything(Severity::Broken))));
            assert!(FEATURES.iter().all(|f| hold_allows(f.id)));
            set_policy_for_this_thread(None);
            return;
        };
        let before: Vec<bool> = checks.iter().map(|(_, live)| live()).collect();
        let mut closed = 0;
        for entries in &contents {
            applied.set(Policy::of_entries(1, T0, entries, 0));
            for ((name, live), was) in checks.iter().zip(&before) {
                let now = live();
                assert!(!now || *was, "{name} opened (open={open}) by {entries:?}");
                closed += usize::from(*was && !now);
            }
        }
        // The holds do close what was open.
        assert!(!open || closed > 0, "nothing closed");
    }
}

/// A hold closes its feature and what sits on it; a BROKEN wire module
/// closes its feature; DEPRECATED and INFO change nothing.
#[test]
fn holds_close_their_feature_and_what_sits_on_it() {
    let _lan = crate::lan_gate::lan_user_switch_untouched();
    let _labs = Labs::set(true);
    let Some(applied) = Applied::open(Policy::default()) else {
        return;
    };
    let live = |g| security_gate::live(g);
    assert!(live(G::LinkPadding) && live(G::Responses) && live(G::MeshUpdate));
    applied.set(policy(vec![hold(
        Severity::Broken,
        reg::FEATURE_LINK_PADDING,
    )]));
    assert!(!live(G::LinkPadding));
    assert!(live(G::LinkKnock), "only the feature held");
    applied.set(policy(vec![suite(Severity::Broken, reg::PAD1_V1)]));
    assert!(!live(G::LinkPadding), "a BROKEN wire module is off");
    applied.set(policy(vec![suite(Severity::Deprecated, reg::PAD1_V1)]));
    assert!(live(G::LinkPadding), "DEPRECATED only warns");
    applied.set(policy(vec![hold(
        Severity::Info,
        reg::FEATURE_LINK_PADDING,
    )]));
    assert!(live(G::LinkPadding));
    // What a gate sits on: events under responses and the floor, bundles
    // under mesh updates.
    applied.set(policy(vec![hold(
        Severity::Broken,
        reg::FEATURE_SECURITY_EVENTS,
    )]));
    assert!(!live(G::Events) && !live(G::Responses) && !live(G::SuiteFloor));
    applied.set(policy(vec![hold(
        Severity::Broken,
        reg::FEATURE_RELEASE_BUNDLE,
    )]));
    assert!(!live(G::ReleaseBundle) && !live(G::MeshUpdate));
    assert!(live(G::Advisory));
    // A hold on advisories is shown, never enforced.
    applied.set(policy(vec![hold(Severity::Broken, reg::FEATURE_ADVISORY)]));
    assert!(live(G::Advisory) && live(G::MeshUpdate));
    // Custody, and what sits on it: handoffs, letters, custody hints.
    applied.set(policy(vec![suite(Severity::Broken, reg::RFC1_V1)]));
    let custody = crate::custody_gate::CustodyGates::current();
    assert!(!custody.live && !custody.wan);
    assert!(!crate::custody_gate::handoff_live());
    assert!(!crate::horizon::letter_live_enabled());
    // LAN direct is open in every build: a hold closes it, and with it the
    // LAN carrier.
    assert!(crate::lan_gate::lan_direct_live_enabled());
    applied.set(policy(vec![hold(
        Severity::Broken,
        reg::FEATURE_LAN_DIRECT,
    )]));
    assert!(!crate::lan_gate::lan_direct_live_enabled());
    assert!(!crate::lan_gate::lan_usable_now());
    // M0's hold closes the offline-LAN behaviours too: never live without
    // the pin (`offline_lan_needs_noise_pin`).
    applied.set(policy(vec![hold(
        Severity::Broken,
        reg::FEATURE_LAN_NOISE_PIN,
    )]));
    assert!(!crate::lan_gate::lan_noise_pin_live());
    assert!(!crate::lan_gate::offline_lan_live());
    // Session reset and its restore; route hints and pair seeds.
    applied.set(policy(vec![suite(Severity::Broken, reg::RSR1_V1)]));
    assert!(!crate::session_reset::session_reset_live_enabled());
    assert!(!crate::session_reset::session_reset_restore_live_enabled());
    applied.set(policy(vec![suite(Severity::Broken, reg::RRH1_V1)]));
    assert!(!crate::route_hints::route_hints_live());
    assert!(!live(G::PairSeed));
}

/// Acceptance: with the advisory gate shut, `hold_allows` is always true
/// and `status` always Allowed, whatever this thread's policy says (in a
/// release build the gate is shut and the policy ignored).
#[test]
fn a_shut_advisory_gate_applies_nothing() {
    security_gate::set_lab_for_this_thread(G::Advisory, Some(false));
    set_policy_for_this_thread(Some(policy(everything(Severity::Broken))));
    if !security_gate::live(G::Advisory) {
        for f in FEATURES {
            assert!(hold_allows(f.id), "{}", f.id);
            assert!(hold_allows_gate(f.gate), "{}", f.gate);
        }
        for s in SUITES {
            assert_eq!(status(s.id), Status::Allowed, "{}", s.id);
        }
        assert_eq!(check_link(), Ok(()));
        assert_eq!(check_pair_init(), Ok(()));
        assert!(session_allowed());
        assert_eq!(v1_sessions(Some(3)), V1Sessions::Go);
        assert!(applied().is_none());
    }
    set_policy_for_this_thread(None);
    security_gate::set_lab_for_this_thread(G::Advisory, None);
    // No profile attached on this thread's policy: nothing applies either.
    let Some(_applied) = Applied::open(Policy::default()) else {
        return;
    };
    assert!(FEATURES.iter().all(|f| hold_allows(f.id)));
    assert_eq!(check_link(), Ok(()));
}

/// A BROKEN link suite refuses every link, either way, with the text that
/// says why and for how long; DEPRECATED and the other layers do not.
#[test]
fn broken_link_suites_refuse_every_link_with_the_text() {
    let Some(applied) = Applied::open(Policy::default()) else {
        return;
    };
    for id in [
        reg::NOISE_XX_25519_CHACHAPOLY_BLAKE2S,
        reg::RIH1_V1,
        reg::RLB1_V1,
    ] {
        applied.set(policy(vec![suite(Severity::Broken, id)]));
        let err = check_link().unwrap_err();
        assert_eq!(err, link_refused_text(id, 6));
        assert!(
            err.starts_with("SUITE_BROKEN: Raven security notice #6"),
            "{err}"
        );
        assert!(err.contains(id) && err.contains("no link"), "{err}");
        assert_eq!(status(id), Status::Broken);
        // A link refusal is no PairInit or session refusal.
        assert_eq!(check_pair_init(), Ok(()));
        assert!(session_allowed());
        applied.set(policy(vec![suite(Severity::Deprecated, id)]));
        assert_eq!(check_link(), Ok(()));
        assert_eq!(status(id), Status::Deprecated);
    }
    applied.set(policy(vec![suite(
        Severity::Broken,
        reg::PAIRINIT_V1_SUITE1,
    )]));
    assert_eq!(check_link(), Ok(()));
    assert_eq!(check_pair_init(), Err(pair_init_refused_text(6)));
    assert!(session_allowed());
    for id in [reg::ATSAM_INDEXED_SESSION_V1, reg::RVNA1_V3] {
        applied.set(policy(vec![suite(Severity::Broken, id)]));
        assert!(!session_allowed(), "{id}");
        assert_eq!(check_link(), Ok(()));
        assert_eq!(check_pair_init(), Ok(()));
    }
}

/// DEPRECATED never refuses: every suite and feature DEPRECATED, and a
/// release floor above this build, only warn.
#[test]
fn deprecated_only_warns() {
    let mut entries = everything(Severity::Deprecated);
    entries.push(floor(9));
    let p = policy(entries);
    assert!(FEATURES.iter().all(|f| p.allows(f.id)));
    assert!(SUITES.iter().all(|s| p.status(s.id) == Status::Deprecated));
    assert_eq!(p.broken_link_suite(), None);
    assert!(p.pair_init_allowed() && p.session_allowed());
    assert!(p.below_release_floor());
    let lines = p.lines(T0 + 3 * DAY_MS);
    assert_eq!(
        lines[0],
        "Security notices from the Raven project: #6 (issued about 3 days ago)."
    );
    assert!(lines[1].starts_with("This Raven version has a known security problem (notice #6)."));
    assert!(lines[1].ends_with("Raven keeps working."));
    assert!(lines[2].starts_with(
        "Security notice #6: an older security method is being retired (noise/xx-25519"
    ));
    assert!(lines[2].contains("route-hints") && !lines[2].contains("feature/"));
    assert!(
        !lines[2].contains("advisory"),
        "a hold on advisories is not listed as retired"
    );
    assert_eq!(lines.len(), 4, "{lines:#?}");
    assert!(lines[3].starts_with("Security notice #6 asks Raven to stop taking"));
    let Some(_applied) = Applied::open(p) else {
        return;
    };
    assert_eq!(check_link(), Ok(()));
    assert_eq!(check_pair_init(), Ok(()));
    assert!(session_allowed());
    assert!(FEATURES.iter().all(|f| hold_allows(f.id)));
}

/// Session profiles (step P6.50): profile 1 takes the worst status of its
/// three ids, and the refusal text names every BROKEN one; the V1 sessions
/// open go on under DEPRECATED and under a BROKEN PairInit, and under a
/// BROKEN session they are held without a next profile and retire into it
/// with one. A profile the registry does not name (the next one, until its
/// program adds its ids) is never refused, and an id at or below V1 is no
/// next profile.
#[test]
fn session_profiles_take_the_worst_of_their_ids() {
    assert_eq!(
        profile_ids(1),
        [
            reg::PAIRINIT_V1_SUITE1,
            reg::ATSAM_INDEXED_SESSION_V1,
            reg::RVNA1_V3
        ]
    );
    assert!(profile_ids(3).is_empty() && profile_ids(0).is_empty());
    let none = policy(Vec::new());
    assert_eq!(none.profile_status(1), Status::Allowed);
    assert_eq!(none.profile_refusal(1), None);
    assert_eq!(none.v1_sessions(Some(3)), V1Sessions::Go);
    for id in profile_ids(1) {
        let retiring = policy(vec![suite(Severity::Deprecated, id)]);
        assert_eq!(retiring.profile_status(1), Status::Deprecated, "{id}");
        assert_eq!(retiring.profile_refusal(1), None);
        assert_eq!(retiring.v1_sessions(Some(3)), V1Sessions::Go);
        let broken = policy(vec![suite(Severity::Broken, id)]);
        assert_eq!(broken.profile_status(1), Status::Broken, "{id}");
        let text = broken.profile_refusal(1).unwrap();
        assert!(
            text.contains(&format!("({id})")) && text.contains("#6"),
            "{text}"
        );
        if *id == reg::PAIRINIT_V1_SUITE1 {
            assert_eq!(broken.v1_sessions(Some(3)), V1Sessions::Go);
            assert_eq!(broken.v1_sessions(None), V1Sessions::Go);
        } else {
            assert_eq!(broken.v1_sessions(Some(3)), V1Sessions::Retire { into: 3 });
            assert_eq!(broken.v1_sessions(None), V1Sessions::Held);
            assert_eq!(broken.v1_sessions(Some(1)), V1Sessions::Held);
        }
    }
    let worst = policy(vec![
        suite(Severity::Deprecated, reg::PAIRINIT_V1_SUITE1),
        suite(Severity::Broken, reg::ATSAM_INDEXED_SESSION_V1),
        suite(Severity::Broken, reg::RVNA1_V3),
    ]);
    assert_eq!(worst.profile_status(1), Status::Broken);
    assert_eq!(
        worst.profile_refusal(1).unwrap(),
        "SUITE_BROKEN: Raven security notice #6 says this security method \
         (atsam/indexed-session/v1, rvna1/3) is no longer safe; Raven starts and accepts no new \
         session with it"
    );
    let all = policy(everything(Severity::Broken));
    assert_eq!(all.profile_status(3), Status::Allowed);
    assert_eq!(all.profile_refusal(3), None);
    assert_eq!(all.v1_sessions(Some(3)), V1Sessions::Retire { into: 3 });
}

/// A NOTICE is shown on one line, its escape sequences and bidirectional
/// controls stripped (`sanitize_terminal_line`); a kind this build does not
/// know is shown as such.
#[test]
fn a_notice_is_shown_sanitized() {
    let text = "Update now\u{1b}[31m red\u{1b}]8;;http://x\u{7}link\u{202E}txt.exe\u{2066}\r\nnext";
    let p = policy(vec![
        notice(text),
        entry(EntryKind::Other(0x09), Severity::Broken, "something/else"),
    ]);
    let lines = p.lines(T0);
    let shown = lines
        .iter()
        .find(|l| l.starts_with("Notice #6 from the Raven project: "))
        .expect("the notice is shown");
    for bad in ['\u{1b}', '\u{7}', '\u{202E}', '\u{2066}', '\r', '\n'] {
        assert!(!shown.contains(bad), "{bad:?} in {shown:?}");
    }
    assert!(
        shown.contains("Update now red") && shown.contains("txt.exe"),
        "{shown}"
    );
    assert_eq!(
        lines.last().unwrap(),
        "Security notice #6 has a part this version doesn't understand: update Raven."
    );
    // An unknown kind closes nothing.
    assert!(FEATURES.iter().all(|f| p.allows(f.id)));
}

/// What the person reads: the freeze, the keys, none yet, and every kind of
/// refusal; `raven doctor`'s row in ids.
#[test]
fn the_lines_and_the_doctor_row_say_what_applies() {
    let none = Policy::default();
    assert_eq!(none.lines(T0), [NONE_YET_TEXT]);
    assert_eq!(none.doctor_row(T0), "no notice yet");
    let keyless = Policy {
        no_release_keys: true,
        frozen: true,
        ..Policy::default()
    };
    assert_eq!(
        keyless.lines(T0),
        [FROZEN_TEXT, update_state::NO_RELEASE_KEYS_TEXT]
    );
    assert_eq!(
        keyless.doctor_row(T0),
        "no release keys in this build; frozen (two versions of the release history)"
    );
    let p = policy(vec![
        suite(Severity::Broken, reg::NOISE_XX_25519_CHACHAPOLY_BLAKE2S),
        suite(Severity::Broken, reg::PAIRINIT_V1_SUITE1),
        suite(Severity::Broken, reg::RVNA1_V3),
        suite(Severity::Broken, reg::RRH1_V1),
        hold(Severity::Broken, reg::FEATURE_NEARBY),
        suite(Severity::Deprecated, reg::RIH1_V1),
        floor(2),
    ]);
    assert!(!p.below_release_floor(), "build 3 is not below 2");
    assert!(!p.allows(reg::FEATURE_ROUTE_HINTS) && !p.allows(reg::FEATURE_NEARBY));
    assert!(p.allows(reg::FEATURE_LAN_DIRECT));
    let lines = p.lines(T0 + DAY_MS / 2);
    assert_eq!(lines.len(), 6, "{lines:#?}");
    assert_eq!(
        lines[0],
        "Security notices from the Raven project: #6 (issued about 12 h ago)."
    );
    assert!(lines[1].contains("link security method (noise/xx-25519-chachapoly-blake2s)"));
    assert!(lines[1].contains("can't reach anyone and nobody can reach it"));
    assert!(
        lines[2].contains("(pairinit/1/1)") && lines[2].contains("sessions already open go on")
    );
    assert!(lines[3].contains("(rvna1/3)") && lines[3].contains("Raven holds them"));
    assert_eq!(
        lines[4],
        "Security notice #6: Raven turned off rrh1/1, nearby, as the notice says."
    );
    assert!(lines[5].contains("being retired (rih1/1)"));
    assert_eq!(
        p.doctor_row(T0 + DAY_MS / 2),
        "notice #6 (issued about 12 h ago); refuses noise/xx-25519-chachapoly-blake2s, \
         pairinit/1/1, rvna1/3; turned off rrh1/1, nearby; retiring rih1/1"
    );
    let below = Policy {
        frozen: true,
        ..policy(vec![floor(4)])
    };
    assert_eq!(below.lines(T0)[0], FROZEN_TEXT);
    assert!(below
        .doctor_row(T0)
        .ends_with("frozen (two versions of the release history); this version (3) is below the release floor (4)"));
}

// ── The profile's state ──────────────────────────────────────────────

/// A build that trusts the test key set.
fn build() -> Build {
    Build {
        key_set: Some(key_set()),
        serial: 3,
        floor: (0, [0; 32]),
    }
}

/// The Raven project's notices as the tests publish them, each logged.
struct Project {
    log: Vec<LogEntry>,
    prev: [u8; 32],
    serial: u64,
}

impl Project {
    fn new() -> Self {
        Self {
            log: vec![LogEntry {
                kind: EntryType::KeySet,
                digest: key_set().digest(),
                logged_at_ms: T0,
            }],
            prev: [0; 32],
            serial: 0,
        }
    }

    /// The next notice with these entries: its bytes and the snapshot of
    /// the log that lists it.
    fn publish(&mut self, entries: Vec<Entry>) -> (Vec<u8>, Vec<u8>) {
        let [a, b, _] = signers();
        self.serial += 1;
        let advisory = AdvisoryDraft {
            serial: self.serial,
            issued_at_ms: T0 + self.serial * DAY_MS,
            key_set_digest: key_set().digest(),
            prev_digest: self.prev,
            entries,
        }
        .sign(&[(0, &a), (1, &b)])
        .unwrap();
        self.prev = advisory.digest();
        self.log.push(LogEntry {
            kind: EntryType::Advisory,
            digest: advisory.digest(),
            logged_at_ms: T0 + self.serial * DAY_MS,
        });
        let sth = SthDraft::of_entries(&self.log, T0 + self.serial, key_set().digest())
            .sign(&[(0, &a), (1, &b)])
            .unwrap();
        let snapshot = Snapshot::new(self.log.clone(), sth).unwrap().encode();
        (advisory.bytes().to_vec(), snapshot)
    }
}

fn accept(dir: &Path, (advisory, snapshot): &(Vec<u8>, Vec<u8>)) {
    update_state::accept_advisory_with(dir, &build(), advisory, snapshot, Origin::IMPORTED)
        .unwrap();
}

/// The cache reads the state again when this process wrote it (at once) or
/// its stamp changed (at most a second later); a state that cannot be read
/// keeps the policy read before.
#[test]
fn the_cache_reads_a_changed_state_again() {
    let Some(_applied) = Applied::open(Policy::default()) else {
        return;
    };
    let dir = crate::contact_book::tests::profile();
    let dd = dir.path();
    let path = dd.join(update_state::UPDATE_STATE_FILE);
    let mut cache = Cache::new(dd.to_path_buf());
    let t0 = Instant::now();
    assert_eq!(cache.current_at(t0).serial, 0, "nothing stored");
    let mut project = Project::new();
    accept(
        dd,
        &project.publish(vec![suite(Severity::Broken, reg::PAIRINIT_V1_SUITE1)]),
    );
    // Written by this process: read again at once.
    let one = cache.current_at(t0);
    assert_eq!(one.serial, 1);
    assert!(!one.pair_init_allowed());
    assert_eq!(
        one.build_serial,
        update_state::BUILD_SERIAL,
        "the build reading"
    );
    let bytes_one = std::fs::read(&path).unwrap();
    accept(
        dd,
        &project.publish(vec![
            suite(Severity::Broken, reg::RLB1_V1),
            notice("the second notice, a little longer"),
        ]),
    );
    assert_eq!(cache.current_at(t0).serial, 2);
    let bytes_two = std::fs::read(&path).unwrap();
    // Changed by another process: seen once the second is over (unless a
    // write by this process, another test's, came in between).
    std::fs::write(&path, &bytes_one).unwrap();
    let writes = WRITES.load(Ordering::Acquire);
    let half = cache.current_at(t0 + RECHECK / 2);
    if WRITES.load(Ordering::Acquire) == writes {
        assert_eq!(half.serial, 2, "not looked at yet");
    }
    assert_eq!(cache.current_at(t0 + RECHECK).serial, 1);
    // Unreadable: the policy before stays, and it is tried again later.
    std::fs::write(&path, b"{ not json").unwrap();
    let held = cache.current_at(t0 + 2 * RECHECK);
    assert_eq!(held.serial, 1);
    assert!(!held.pair_init_allowed());
    assert_eq!(cache.read_at, None);
    std::fs::write(&path, &bytes_two).unwrap();
    let two = cache.current_at(t0 + 3 * RECHECK);
    assert_eq!(two.serial, 2);
    assert_eq!(two.broken_link_suite(), Some(reg::RLB1_V1));
    assert!(
        two.pair_init_allowed(),
        "the second notice is the whole list"
    );
    // A sealed profile reads the same.
    let sealed = crate::contact_book::tests::profile();
    crate::contact_book::tests::seal(sealed.path());
    let mut project = Project::new();
    accept(
        sealed.path(),
        &project.publish(vec![hold(Severity::Broken, reg::FEATURE_NEARBY)]),
    );
    let p = read(sealed.path()).unwrap().unwrap();
    assert!(!p.allows(reg::FEATURE_NEARBY));
    assert_eq!(
        status_lines(sealed.path(), T0 + DAY_MS)[1],
        "Security notice #1: Raven turned off nearby, as the notice says."
    );
    assert!(doctor_row(sealed.path(), T0 + DAY_MS)
        .unwrap()
        .starts_with("notice #1 (issued "));
}

/// The attached profile, through the consult points: a profile whose
/// notice only says something (no other test on another thread can be
/// closed by it).
#[test]
fn the_attached_profile_applies() {
    let dir = crate::contact_book::tests::profile();
    let dd = dir.path();
    {
        let Some(_applied) = Applied::open(Policy::default()) else {
            return;
        };
        let mut project = Project::new();
        accept(dd, &project.publish(vec![notice("hello")]));
    }
    security_gate::set_lab_for_this_thread(G::Advisory, Some(true));
    attach(dd);
    let seen = current();
    assert_eq!(seen.serial, 1);
    assert_eq!(seen.notice.as_deref(), Some("hello"));
    assert!(hold_allows(reg::FEATURE_LAN_DIRECT));
    // This thread's policy goes first.
    set_policy_for_this_thread(Some(policy(vec![])));
    assert_eq!(current().serial, 6);
    set_policy_for_this_thread(None);
    detach(dd);
    assert_eq!(current().serial, 0);
    // Shut: nothing is read or applied.
    security_gate::set_lab_for_this_thread(G::Advisory, Some(false));
    assert_eq!(status_lines(dd, T0), Vec::<String>::new());
    assert_eq!(doctor_row(dd, T0), None);
    security_gate::set_lab_for_this_thread(G::Advisory, None);
}
