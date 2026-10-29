//! P6.24 tests of raven-node's security events: what each helper notes and
//! about whom, nothing at all while the gate is shut, the learning seam,
//! the `Status` counts, and the writer (a network event costs no ledger
//! write until its hourly count; a contact's goes in at once). P6.26 adds
//! the penalty box (design A R1) on a paused clock and fake addresses: bans,
//! probation, doubling, the /64 grouping, loopback, the p2p gate and the
//! beacon. The gates are opened for the test's thread only (debug builds: a
//! release test build cannot open them, so those tests have nothing to
//! check there). The box is the process's one: each test strikes its own
//! addresses.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use raven_core::lan_dispatch::{LINK_REFUSED_BLOCKED, LINK_REFUSED_NOT_CONTACT};
use raven_core::security_events::{BIND_BAD_SIGNATURE, LAN_FRAME_LENGTH, LAN_HANDSHAKE_TIMEOUT};
use raven_core::security_ledger::ledger_path;

use super::*;

thread_local! {
    static CAPTURE: RefCell<Option<Vec<SecEvent>>> = const { RefCell::new(None) };
}

/// [`note`]'s test hook: what this thread noted while a [`Capture`] runs.
pub(super) fn captured(ev: &SecEvent) {
    CAPTURE.with(|c| {
        if let Some(seen) = c.borrow_mut().as_mut() {
            seen.push(*ev);
        }
    });
}

/// The events gate open for this thread, and what it notes kept (a
/// current-thread runtime's tasks run here too). Shut again on drop.
pub(crate) struct Capture(());

impl Capture {
    /// `None` in a release build, where the gate cannot open: the caller
    /// has nothing to check.
    pub(crate) fn start() -> Option<Self> {
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(true));
        if !live() {
            security_gate::set_lab_for_this_thread(SecGate::Events, None);
            return None;
        }
        CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
        Some(Self(()))
    }

    pub(crate) fn events(&self) -> Vec<SecEvent> {
        CAPTURE.with(|c| c.borrow().clone().unwrap_or_default())
    }

    /// The events with their times left out (what a test compares).
    pub(crate) fn kinds(&self) -> Vec<(SecKind, Attribution, Via)> {
        self.events()
            .iter()
            .map(|e| (e.kind, e.who, e.via))
            .collect()
    }

    /// Wait (on this thread's runtime) until `n` events were noted.
    pub(crate) async fn until(&self, n: usize) -> Vec<SecEvent> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while self.events().len() < n && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.events()
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        CAPTURE.with(|c| *c.borrow_mut() = None);
        security_gate::set_lab_for_this_thread(SecGate::Events, None);
    }
}

/// The responses gate open for this thread too (with a [`Capture`], which
/// opens the events gate it sits on); shut again on drop.
pub(crate) struct Responding(());

impl Responding {
    /// `None` when the gate cannot open here (a release build).
    pub(crate) fn start() -> Option<Self> {
        security_gate::set_lab_for_this_thread(SecGate::Responses, Some(true));
        if !responding() {
            security_gate::set_lab_for_this_thread(SecGate::Responses, None);
            return None;
        }
        Some(Self(()))
    }
}

impl Drop for Responding {
    fn drop(&mut self) {
        security_gate::set_lab_for_this_thread(SecGate::Responses, None);
    }
}

fn key(n: u8) -> [u8; 32] {
    [n; 32]
}

fn network(ip: &str) -> Attribution {
    Attribution::Network {
        source: SourceKey::of(ip.parse().unwrap()),
    }
}

fn contact(peer: [u8; 32]) -> Attribution {
    Attribution::Contact { peer }
}

#[test]
fn nothing_is_noted_or_reported_while_the_gate_is_shut() {
    security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
    let ip: IpAddr = "192.0.2.4".parse().unwrap();
    inbound_refused(ip, OutboxCarrier::Lan, LINK_REFUSED_NOT_CONTACT);
    inbound_link_error(&key(0x31), OutboxCarrier::Lan, LINK_TAG_FAILED);
    dial_link_error(&key(0x32), OutboxCarrier::Internet, LINK_TAG_FAILED);
    address_impostor(&key(0x33), OutboxCarrier::Lan, Some(ip));
    relay_link_broken([b"relay".to_vec()]);
    custody_fetched(
        &key(0x34),
        &FetchReport {
            misbehaviour: vec![SecKind::CustodianUnrequested],
            sender_events: vec![(key(0x35), SecKind::ObjectAuthFail)],
            ..FetchReport::default()
        },
    );
    handoff_refused(&key(0x36), OutboxCarrier::Lan);
    knock_failed(ip, false);
    cap_refused(ip, OutboxCarrier::Lan);
    beacon_refused(ip, true, clock());
    let seen = CAPTURE.with(|c| c.borrow_mut().take().unwrap());
    assert!(seen.is_empty(), "{seen:?}");
    assert!(
        p2p_gate_hook().is_none(),
        "nothing installed in the p2p gate"
    );
    assert!(p2p_admit_hook().is_none(), "nor asked of it");
    assert_eq!(admit_source(ip, OutboxCarrier::Lan), Admit::Allow);
    assert!(!beacon_banned(ip, clock()));
    assert!(!source_banned(ip), "no strike");
    assert!(status().is_none(), "no Status.security");
    // A tampered dial still teaches learning nothing.
    assert!(take_excluded_dial(&key(0x32), OutboxCarrier::Internet));
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
}

/// S2, S3: before the handler knows whom it serves, a link error is about
/// the network source; a tag failure that early is garbage. S1: past the
/// gate it is about the contact's path, on this network.
#[test]
fn early_failures_are_the_sources_and_later_tag_failures_the_contacts_path() {
    let Some(capture) = Capture::start() else {
        return;
    };
    let lan = Via::DirectLink(OutboxCarrier::Lan);
    for (error, kind) in [
        (LINK_REFUSED_NOT_CONTACT, SecKind::StrangerRefused),
        (LINK_REFUSED_BLOCKED, SecKind::BlockedRefused),
        (LAN_HANDSHAKE_TIMEOUT, SecKind::HandshakeFail),
        (LAN_FRAME_LENGTH, SecKind::PreauthMalformed),
        (BIND_BAD_SIGNATURE, SecKind::PreauthMalformed),
        (LINK_TAG_FAILED, SecKind::PreauthMalformed),
    ] {
        inbound_refused("192.0.2.5".parse().unwrap(), OutboxCarrier::Lan, error);
        assert_eq!(
            capture.kinds().pop(),
            Some((kind, network("192.0.2.5"), lan)),
            "{error}"
        );
    }
    let n = capture.events().len();
    // Not events: hang-ups, our own deadlines, anything else.
    for error in [PEER_CLOSED, "lan read timeout", "blocked peer", ""] {
        inbound_refused("192.0.2.5".parse().unwrap(), OutboxCarrier::Lan, error);
        inbound_link_error(&key(0x41), OutboxCarrier::Lan, error);
    }
    assert_eq!(capture.events().len(), n);
    // A v6 source is its /64, as the admission keys it.
    inbound_refused(
        "2001:db8:1:2:aaaa::1".parse().unwrap(),
        OutboxCarrier::Internet,
        LINK_REFUSED_NOT_CONTACT,
    );
    assert_eq!(
        capture.kinds().pop(),
        Some((
            SecKind::StrangerRefused,
            network("2001:db8:1:2::"),
            Via::DirectLink(OutboxCarrier::Internet)
        ))
    );
    inbound_link_error(&key(0x41), OutboxCarrier::P2p, LINK_TAG_FAILED);
    let last = *capture.events().last().unwrap();
    assert_eq!(
        (last.kind, last.who, last.via),
        (
            SecKind::LinkTagFail,
            contact(key(0x41)),
            Via::DirectLink(OutboxCarrier::P2p)
        )
    );
    assert_eq!(last.network, network_now(), "on this computer's network");
}

fn network_now() -> Option<[u8; 8]> {
    super::network()
}

/// S1 on a dial, and the merge amendment: a tampered dial is excluded from
/// learning, once, for its contact and carrier only.
#[test]
fn a_tampered_dial_is_the_contacts_path_and_teaches_learning_nothing() {
    let Some(capture) = Capture::start() else {
        return;
    };
    let peer = key(0x51);
    dial_link_error(
        &peer,
        OutboxCarrier::Internet,
        "internet frame read timeout",
    );
    assert!(capture.events().is_empty());
    assert!(!take_excluded_dial(&peer, OutboxCarrier::Internet));
    dial_link_error(&peer, OutboxCarrier::Internet, LINK_TAG_FAILED);
    assert_eq!(
        capture.kinds(),
        [(
            SecKind::LinkTagFail,
            contact(peer),
            Via::Dial(OutboxCarrier::Internet)
        )]
    );
    assert!(!take_excluded_dial(&peer, OutboxCarrier::Lan));
    assert!(!take_excluded_dial(&key(0x52), OutboxCarrier::Internet));
    assert!(take_excluded_dial(&peer, OutboxCarrier::Internet));
    assert!(!take_excluded_dial(&peer, OutboxCarrier::Internet), "once");
    // Bounded: a flood of tampered dials holds at most EXCLUDED_MAX.
    for n in 0..200u16 {
        let mut k = [0x53; 32];
        k[..2].copy_from_slice(&n.to_be_bytes());
        exclude_dial(&k, OutboxCarrier::Lan);
    }
    assert!(lock(&EXCLUDED).len() <= EXCLUDED_MAX);
}

/// S13: another key at a contact's address, attributed to that contact.
#[test]
fn an_impostor_is_noted_about_the_contact_whose_address_it_was() {
    let Some(capture) = Capture::start() else {
        return;
    };
    address_impostor(&key(0x61), OutboxCarrier::Lan, None);
    let ev = capture.events()[0];
    assert_eq!(
        (ev.kind, ev.who, ev.via),
        (
            SecKind::AddressImpostor,
            contact(key(0x61)),
            Via::Dial(OutboxCarrier::Lan)
        )
    );
    assert_eq!(ev.network, network_now());
}

/// S5: the p2p peer gate's hook notes the remote's source, never a peer;
/// a relayed link that broke inside is about its relays' digests.
#[test]
fn the_p2p_gate_notes_sources_and_broken_relayed_links_their_relays() {
    let Some(capture) = Capture::start() else {
        return;
    };
    let hook = p2p_gate_hook().expect("installed while the gate is live");
    hook(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        RefusalKind::Inbound,
    );
    hook(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 9, 1, 2, 3, 4)),
        RefusalKind::Outbound,
    );
    assert_eq!(
        capture.kinds(),
        [
            (
                SecKind::P2pGateRefused,
                network("198.51.100.7"),
                Via::DirectLink(OutboxCarrier::P2p)
            ),
            (
                SecKind::P2pGateRefused,
                network("2001:db8:0:9::"),
                Via::Dial(OutboxCarrier::P2p)
            ),
        ]
    );
    for broke in [
        LINK_TAG_FAILED,
        NOISE_HANDSHAKE_FAILED,
        INTERNET_FRAME_LENGTH,
        PEER_CLOSED,
        "P2P_DIAL_BAD_REPLY: the peer's reply could not be read (noise transport failed); \
         the frames were sent, delivery is unconfirmed and a retry is safe",
    ] {
        assert!(link_broke(broke), "{broke}");
    }
    for not in [
        crate::netutil::LINK_NOT_ACCEPTED,
        "P2P_DIAL_PEER_CLOSED: the peer closed the connection without replying; the frames \
         were sent, delivery is unconfirmed and a retry is safe",
        "peer closed the connection during the handshake (3 attempts); the peer may be at its \
         connection limit or may not be a RAVEN node",
        "internet frame read timeout",
        "P2P_DIAL_BAD_REPLY: the peer's reply could not be read (lan frame budget)",
    ] {
        assert!(!link_broke(not), "{not}");
    }
    let before = capture.events().len();
    relay_link_broken([b"relay-one".to_vec(), b"relay-two".to_vec()]);
    let relays: Vec<_> = capture.kinds()[before..].to_vec();
    assert_eq!(
        relays,
        [b"relay-one".as_slice(), b"relay-two"].map(|r| (
            SecKind::RelayLinkBroken,
            Attribution::Carrier {
                carrier: events::relay_subject(r),
                role: CarrierRole::Relay
            },
            Via::Relay
        ))
    );
}

/// E1 (three machines): right after an Unlock the p2p gate's set could not
/// be read (the book held while the at-rest key loaded), and a verified
/// friend's connection was refused, noted and struck as a stranger's. A gate
/// that cannot read its set judges nobody: nothing is noted, no strike; once
/// it reads its set again, a stranger's refusal is noted as before.
#[tokio::test(start_paused = true)]
async fn an_unreadable_p2p_gate_notes_no_refusal() {
    use raven_swarm::gate::GateHandle;
    let Some(capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let friend: IpAddr = "192.0.2.60".parse().unwrap();
    let peers = GateHandle::new(None);
    peers.replace(Default::default(), true, std::time::Instant::now());
    let refused = p2p_gate_hook_of(peers.clone()).expect("installed");
    for _ in 0..16 {
        refused(friend, RefusalKind::Inbound);
    }
    assert!(capture.events().is_empty(), "{:?}", capture.kinds());
    assert!(!source_banned_on(friend, OutboxCarrier::P2p), "no strike");
    peers.replace(Default::default(), false, std::time::Instant::now());
    refused(friend, RefusalKind::Inbound);
    assert_eq!(
        capture.kinds(),
        [(
            SecKind::P2pGateRefused,
            network("192.0.2.60"),
            Via::DirectLink(OutboxCarrier::P2p)
        )]
    );
}

#[test]
fn status_windows_count_the_last_hour_and_day() {
    let mut w: Window<60, MINUTE_MS> = Window::new();
    let t0 = 1_000 * DAY_MS;
    w.add(t0);
    w.add(t0 + 30 * 1000);
    w.add(t0 + 59 * MINUTE_MS);
    assert_eq!(w.sum(t0 + 59 * MINUTE_MS), 3);
    assert_eq!(w.sum(t0 + HOUR_MS), 1, "the first minute's two are out");
    assert_eq!(w.sum(t0 + 3 * HOUR_MS), 0);
    // A slot reused an hour later starts over.
    w.add(t0 + HOUR_MS + 1);
    assert_eq!(w.sum(t0 + HOUR_MS + 1), 2);
    // An event dated ahead of now is not counted yet.
    assert_eq!(w.sum(t0 - MINUTE_MS), 0);
    let mut day: Window<24, HOUR_MS> = Window::new();
    for h in 0..30 {
        day.add(t0 + h * HOUR_MS);
    }
    assert_eq!(day.sum(t0 + 29 * HOUR_MS), 24);
}

/// `Status.security` is there only while the gate is live, and the sink's
/// counts reach it.
#[test]
fn status_is_reported_only_while_the_gate_is_live() {
    security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
    assert!(status().is_none());
    let Some(_capture) = Capture::start() else {
        return;
    };
    // Shut for this thread even when a run sets the responses switch
    // (P6.26 runs the suite once with it).
    security_gate::set_lab_for_this_thread(SecGate::Responses, Some(false));
    let before = status().expect("live");
    assert!(!before.responses_live, "the responses gate stays shut");
    let (tx, _rx) = mpsc::sync_channel(QUEUE);
    let sink = NodeSink { tx };
    let now = now_ms();
    let source = network("192.0.2.77");
    for kind in [SecKind::StrangerRefused, SecKind::P2pGateRefused] {
        sink.accept(
            &SecEvent::new(kind, source, Via::DirectLink(OutboxCarrier::Lan), now),
            Severity::Notice,
        );
    }
    sink.accept(
        &SecEvent::new(
            SecKind::HandshakeFail,
            source,
            Via::DirectLink(OutboxCarrier::Lan),
            now,
        ),
        Severity::Notice,
    );
    sink.accept(
        &SecEvent::new(
            SecKind::LinkTagFail,
            contact(key(0x71)),
            Via::Dial(OutboxCarrier::Lan),
            now,
        ),
        Severity::Notice,
    );
    let after = status().unwrap();
    // Other tests' sinks may count at the same time: at least these.
    assert!(after.strangers_refused_1h >= before.strangers_refused_1h + 2);
    assert!(after.preauth_failures_1h > before.preauth_failures_1h);
    assert!(after.link_tag_failures_24h > before.link_tag_failures_24h);
    let json = serde_json::to_string(&after).unwrap();
    assert!(!json.contains("192.0.2.77") && !json.contains(&hex::encode(key(0x71))));
    security_gate::set_lab_for_this_thread(SecGate::Responses, None);
}

/// A sink whose queue is full drops the event and counts it; the writer
/// adds the drops to the ledger's counter by the hour.
#[test]
fn a_full_queue_drops_and_counts() {
    let (tx, _rx) = mpsc::sync_channel(1);
    let sink = NodeSink { tx };
    let before = DROPPED.load(Ordering::Relaxed);
    let ev = SecEvent::new(
        SecKind::StrangerRefused,
        network("192.0.2.8"),
        Via::DirectLink(OutboxCarrier::Lan),
        now_ms(),
    );
    sink.accept(&ev, Severity::Notice);
    sink.accept(&ev, Severity::Notice);
    sink.accept(&ev, Severity::Notice);
    assert!(DROPPED.load(Ordering::Relaxed) >= before + 2);
}

/// Design A §3 and the step's test: a stranger's event is a network count
/// in memory, so it costs no ledger write (no file at all) until the
/// hourly count, which is one row with no subject and no alert; a contact's
/// event goes in at once, as an alert about that contact. A plain profile
/// never gets a ledger.
#[test]
fn a_stranger_costs_no_ledger_write_until_the_hourly_count() {
    use crate::at_rest_boot::tests::{lab_hist_key, profile_with, seal, serial};
    if !lab_hist_key() {
        return;
    }
    // The gate for this thread, where the writer runs in this test.
    let Some(_capture) = Capture::start() else {
        return;
    };
    let dir = profile_with(&[]);
    let dd = dir.path().to_path_buf();
    {
        let _serial = serial();
        seal(&dd);
    }
    let opener = dd.clone();
    let now = now_ms();
    let mut writer = Writer::new(move || SecurityLedger::open(&opener), now);
    let stranger = SecEvent::new(
        SecKind::StrangerRefused,
        network("203.0.113.9"),
        Via::DirectLink(OutboxCarrier::Lan),
        now,
    );
    writer.event(&stranger, Severity::Notice, now);
    writer.tick(now + TICK.as_millis() as u64);
    assert!(!ledger_path(&dd).exists(), "no ledger write for a stranger");
    assert!(writer.ledger.is_none());

    // The hour: one count, no subject, no alert.
    writer.tick(now + HOUR_MS);
    assert!(ledger_path(&dd).exists());
    let counts = writer.ledger.as_ref().unwrap().counts(0).unwrap();
    assert_eq!(counts.len(), 1, "{counts:?}");
    assert_eq!(
        (counts[0].kind, counts[0].n, counts[0].subject.is_none()),
        (SecKind::StrangerRefused, 1, true)
    );
    assert_eq!(
        writer.ledger.as_ref().unwrap().open_alert_count().unwrap(),
        0
    );
    assert!(writer.network.is_empty());

    // A contact's tag failure: written at once, an alert about it.
    let at = now + HOUR_MS + 1;
    let tamper = SecEvent::new(
        SecKind::LinkTagFail,
        contact(key(0x81)),
        Via::Dial(OutboxCarrier::Lan),
        at,
    );
    writer.event(&tamper, Severity::Notice, at);
    let ledger = writer.ledger.as_ref().unwrap();
    assert_eq!(ledger.open_alert_count().unwrap(), 1);
    let alerts = ledger.open_alerts().unwrap();
    assert_eq!(alerts[0].kind, SecKind::LinkTagFail);
    assert_eq!(alerts[0].subject.map(|s| *s.key()), Some(key(0x81)));
    writer.finish(at);

    // A plain profile: nothing, ever.
    let plain = profile_with(&[]);
    let opener = plain.path().to_path_buf();
    let mut writer = Writer::new(move || SecurityLedger::open(&opener), now);
    writer.event(&tamper, Severity::Notice, now);
    writer.event(&stranger, Severity::Notice, now);
    writer.tick(now + HOUR_MS);
    writer.finish(now + HOUR_MS);
    assert!(!ledger_path(plain.path()).exists());
}

/// P6.25 (S18, S20): a fetch round's custodian misbehaviour is about the
/// custodian and its senders' bad objects about them, all fetched from it;
/// a HOP_REFUSED to this node's own forward is about the custodian that
/// answered it; a failed RNK1 knock is about the pipe's radio source.
#[test]
fn custody_and_nearby_events_name_whom_they_are_about() {
    let Some(capture) = Capture::start() else {
        return;
    };
    let custodian = key(0x51);
    let report = FetchReport {
        misbehaviour: vec![SecKind::CustodianBadObject, SecKind::CustodianReplay],
        sender_events: vec![(key(0x52), SecKind::ObjectAuthFail)],
        ..FetchReport::default()
    };
    custody_fetched(&custodian, &report);
    handoff_refused(&key(0x53), OutboxCarrier::Internet);
    let radio: IpAddr = "fd00:5300::".parse().unwrap();
    knock_failed(radio, true);
    knock_failed(radio, false);
    let held = |carrier| Attribution::Carrier {
        carrier,
        role: CarrierRole::Custodian,
    };
    let from = Via::Custodian(custodian);
    assert_eq!(
        capture.kinds(),
        vec![
            (SecKind::CustodianBadObject, held(custodian), from),
            (SecKind::CustodianReplay, held(custodian), from),
            (SecKind::ObjectAuthFail, contact(key(0x52)), from),
            (
                SecKind::HandoffRefused,
                held(key(0x53)),
                Via::Dial(OutboxCarrier::Internet)
            ),
            (
                SecKind::KnockFail,
                network("fd00:5300::"),
                Via::Dial(OutboxCarrier::Nearby)
            ),
            (
                SecKind::KnockFail,
                network("fd00:5300::"),
                Via::DirectLink(OutboxCarrier::Nearby)
            ),
        ]
    );
    // An empty round notes nothing.
    let before = capture.events().len();
    custody_fetched(&custodian, &FetchReport::default());
    assert_eq!(capture.events().len(), before);
}

// ── The penalty box (P6.26) ────────────────────────────────────────────────

/// `n` junk handshakes from `ip` at a LAN listener, as the accept loop
/// reports them (a Noise message that does not parse: one strike each).
fn junk(ip: &str, n: u32) {
    junk_on(ip, n, OutboxCarrier::Lan);
}

/// `n` junk handshakes from `ip` at `carrier`'s listener.
fn junk_on(ip: &str, n: u32, carrier: OutboxCarrier) {
    for _ in 0..n {
        inbound_refused(ip.parse().unwrap(), carrier, NOISE_HANDSHAKE_FAILED);
    }
}

fn floods(capture: &Capture) -> Vec<(Attribution, Via)> {
    capture
        .events()
        .iter()
        .filter(|e| e.kind == SecKind::PreauthFlood)
        .map(|e| (e.who, e.via))
        .collect()
}

/// 16 junk handshakes from one address ban it: its connections are refused
/// save one probation connection per 10 s, a contact's address is not
/// touched, and a contact that authenticates on the probation connection
/// clears the source. The ban is one SEC_PREAUTH_FLOOD (a day count in the
/// ledger: a network source), and `Status` counts it.
#[tokio::test(start_paused = true)]
async fn sixteen_junk_handshakes_ban_a_source_until_a_contact_authenticates() {
    use crate::netutil::{Admission, Refused, PRODUCTION_INBOUND};
    let Some(capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let (bad, friend) = ("10.0.1.9", "10.0.1.10");
    let bad_ip: IpAddr = bad.parse().unwrap();
    let friend_ip: IpAddr = friend.parse().unwrap();
    let adm = Admission::for_addresses(PRODUCTION_INBOUND, OutboxCarrier::Lan);
    junk(bad, 15);
    assert!(!source_banned(bad_ip), "15 strikes are no ban");
    assert!(floods(&capture).is_empty());
    junk(bad, 1);
    assert!(source_banned(bad_ip));
    assert_eq!(
        floods(&capture),
        [(network(bad), Via::DirectLink(OutboxCarrier::Lan))],
        "one SEC_PREAUTH_FLOOD for the ban"
    );
    assert!(status().unwrap().bans_active >= 1);
    // The contact's address is untouched.
    let mut held = vec![adm.admit(friend_ip).expect("a contact's address")];
    assert!(!source_banned(friend_ip));
    // The banned one: a probation connection, then nothing for 10 s.
    let probation = adm.admit(bad_ip).expect("probation");
    drop(probation);
    assert_eq!(adm.admit(bad_ip).err(), Some(Refused::Banned));
    assert!(adm.try_admit(bad_ip).is_none());
    // Strikes while banned keep it banned and note no second flood.
    junk(bad, 3);
    assert_eq!(floods(&capture).len(), 1);
    tokio::time::advance(Duration::from_secs(9)).await;
    assert_eq!(adm.admit(bad_ip).err(), Some(Refused::Banned));
    held.push(adm.admit(friend_ip).expect("the contact's address still"));
    tokio::time::advance(Duration::from_secs(1)).await;
    // A contact behind the banned address gets through within 10 s and
    // clears it.
    let mut contact = adm.admit(bad_ip).expect("the next probation");
    contact.authenticated();
    assert!(!source_banned(bad_ip), "a contact cleared the source");
    for _ in 0..3 {
        held.push(adm.admit(bad_ip).expect("no longer banned"));
    }
    assert_eq!(floods(&capture).len(), 1);
}

/// Each ban doubles (60 s, 120 s, ...) up to an hour, and each is one
/// SEC_PREAUTH_FLOOD.
#[tokio::test(start_paused = true)]
async fn bans_double_and_stop_at_an_hour() {
    let Some(capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let src = "10.0.1.20";
    let ip: IpAddr = src.parse().unwrap();
    let mut bans = 0;
    for want in [60, 120, 240, 480, 960, 1_920, 3_600, 3_600] {
        junk(src, 16);
        bans += 1;
        assert!(source_banned(ip), "ban {bans}");
        tokio::time::advance(Duration::from_secs(want - 1)).await;
        assert!(source_banned(ip), "ban {bans} lasts {want} s");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!source_banned(ip), "ban {bans} is over after {want} s");
    }
    assert_eq!(floods(&capture).len(), bans);
}

/// With the responses gate shut (the events gate open), the same flood is
/// noted and bans nobody: every connection is admitted.
#[tokio::test(start_paused = true)]
async fn with_the_responses_gate_shut_a_flood_bans_nobody() {
    use crate::netutil::{Admission, PRODUCTION_INBOUND};
    let Some(capture) = Capture::start() else {
        return;
    };
    security_gate::set_lab_for_this_thread(SecGate::Responses, Some(false));
    let src = "10.0.1.30";
    let ip: IpAddr = src.parse().unwrap();
    junk(src, 64);
    for _ in 0..32 {
        cap_refused(ip, OutboxCarrier::Lan);
        beacon_refused(ip, true, clock());
        p2p_gate_refused(ip, RefusalKind::Inbound);
    }
    assert!(!source_banned(ip));
    assert!(floods(&capture).is_empty());
    assert_eq!(
        capture
            .events()
            .iter()
            .filter(|e| e.kind == SecKind::HandshakeFail)
            .count(),
        64,
        "still noted"
    );
    let adm = Admission::for_addresses(PRODUCTION_INBOUND, OutboxCarrier::Lan);
    let held: Vec<_> = (0..PRODUCTION_INBOUND.max_handshaking_per_ip)
        .map(|_| adm.try_admit(ip).expect("admitted"))
        .collect();
    assert_eq!(held.len(), 4);
    assert!(p2p_admit_hook().is_none());
    assert!(p2p_authenticated_hook().is_none(), "nothing told either");
    assert!(!status().unwrap().responses_live);
    security_gate::set_lab_for_this_thread(SecGate::Responses, None);
}

/// An IPv6 source at the Internet listener (and the p2p gate) is its /64
/// (a host holds the whole /64); an IPv4-mapped one is its IPv4 address.
#[tokio::test(start_paused = true)]
async fn ipv6_sources_are_their_64() {
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let inet = OutboxCarrier::Internet;
    for host in 1..=16 {
        junk_on(&format!("2001:db8:6:1::{host:x}"), 1, inet);
    }
    let banned = |ip: &str| source_banned_on(ip.parse().unwrap(), inet);
    assert!(banned("2001:db8:6:1::99"));
    assert!(banned("2001:db8:6:1:ffff::1"));
    assert!(!banned("2001:db8:6:2::1"));
    assert!(
        source_banned_on("2001:db8:6:1::99".parse().unwrap(), OutboxCarrier::P2p),
        "the p2p gate keys the same /64"
    );
    junk_on("::ffff:10.0.1.40", 16, inet);
    assert!(banned("10.0.1.40"));
}

/// Phase 6 review (sensing-2): a source on the local network (the LAN
/// listener, the beacon answerer) is its whole address. One stranger's
/// junk over IPv6 on the Wi-Fi bans only that stranger: another
/// link-local host and another SLAAC host of the same /64 (on one of this
/// computer's networks) are admitted at once, again and again (no
/// probation), and the beacon answers them.
#[tokio::test(start_paused = true)]
async fn a_lan_neighbour_is_not_banned_with_a_stranger() {
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let _on_link = OnLinkForTest::set(
        |ip| matches!(ip, IpAddr::V6(v6) if v6.segments()[..4] == [0x2001, 0xdb8, 7, 1]),
    );
    let lan = OutboxCarrier::Lan;
    for (bad, friend) in [
        ("fe80::bad:1", "fe80::f00d:2"),
        ("2001:db8:7:1::bad", "2001:db8:7:1::f00d"),
    ] {
        junk(bad, 16);
        let (bad, friend): (IpAddr, IpAddr) = (bad.parse().unwrap(), friend.parse().unwrap());
        assert!(source_banned(bad), "{bad}");
        assert!(beacon_banned(bad, clock()));
        assert!(!source_banned(friend), "{friend}");
        assert!(!beacon_banned(friend, clock()));
        for _ in 0..3 {
            assert_eq!(admit_source(friend, lan), Admit::Allow, "{friend}");
        }
        assert_eq!(admit_source(bad, lan), Admit::Probation);
        assert_eq!(admit_source(bad, lan), Admit::Deny);
    }
    // The beacon's strikes keep apart too.
    for _ in 0..4 {
        beacon_refused("fe80::bad:3".parse().unwrap(), true, clock());
    }
    assert!(beacon_banned("fe80::bad:3".parse().unwrap(), clock()));
    assert!(!beacon_banned("fe80::f00d:4".parse().unwrap(), clock()));
}

/// Phase 6 review re-verify (sensing-2): the LAN listener takes dials from
/// anywhere before they authenticate. A global IPv6 source from outside
/// this computer's networks is its /64 there, as at the Internet listener:
/// an attacker holding a /64 cannot dodge its ban by moving inside it.
/// Link-local, unique-local and on-link sources stay their whole address.
#[tokio::test(start_paused = true)]
async fn a_remote_ipv6_source_at_the_lan_listener_is_its_64() {
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let _on_link = OnLinkForTest::set(
        |ip| matches!(ip, IpAddr::V6(v6) if v6.segments()[..4] == [0x2001, 0xdb8, 8, 1]),
    );
    let lan = OutboxCarrier::Lan;
    let banned = |ip: &str| source_banned_on(ip.parse().unwrap(), lan);
    // From outside: one /64, whatever the interface ID.
    for host in 1..=16 {
        junk_on(&format!("2001:db8:9:1::{host:x}"), 1, lan);
    }
    assert!(
        banned("2001:db8:9:1::99"),
        "another address of the same /64"
    );
    assert!(banned("2001:db8:9:1:ffff::1"));
    assert!(!banned("2001:db8:9:2::1"), "another /64");
    assert_eq!(
        admit_source("2001:db8:9:1::abcd".parse().unwrap(), lan),
        Admit::Probation
    );
    assert_eq!(
        admit_source("2001:db8:9:1::abce".parse().unwrap(), lan),
        Admit::Deny,
        "a new address in the /64 is no way around the ban"
    );
    // On the local network: each host is its own.
    for (bad, neighbour) in [
        ("2001:db8:8:1::bad", "2001:db8:8:1::f00d"),
        ("fd00:8:1::bad", "fd00:8:1::f00d"),
        ("fe80::8:bad", "fe80::8:f00d"),
    ] {
        junk(bad, 16);
        assert!(banned(bad), "{bad}");
        assert!(!banned(neighbour), "{neighbour}");
        assert_eq!(admit_source(neighbour.parse().unwrap(), lan), Admit::Allow);
    }
    // The pure rule: the /64 only for a global source off this computer's
    // networks, and only IPv6.
    let off = |_: IpAddr| false;
    let on = |_: IpAddr| true;
    let key = |ip: &str, on_link: &dyn Fn(IpAddr) -> bool| {
        penalty_key_with(ip.parse().unwrap(), lan, on_link)
    };
    assert_eq!(
        key("2001:db8:9:1::1", &off),
        key("2001:db8:9:1::2", &off),
        "global, off-link: its /64"
    );
    assert_ne!(
        key("2001:db8:9:1::1", &on),
        key("2001:db8:9:1::2", &on),
        "global, on-link: its whole address"
    );
    for (a, b) in [("fe80::1", "fe80::2"), ("fd00::1", "fd00::2")] {
        assert_ne!(key(a, &off), key(b, &off), "{a} is local wherever it is");
    }
    assert_ne!(key("198.51.100.1", &off), key("198.51.100.2", &off));
    assert_eq!(
        key("::ffff:198.51.100.1", &off),
        key("198.51.100.1", &off),
        "an IPv4-mapped source is its IPv4 address"
    );
    assert_eq!(
        penalty_key_with(
            "2001:db8:9:1::1".parse().unwrap(),
            OutboxCarrier::Internet,
            on
        ),
        penalty_key_with(
            "2001:db8:9:1::2".parse().unwrap(),
            OutboxCarrier::Internet,
            on
        ),
        "the Internet listener keys the /64 even on-link"
    );
}

/// Loopback (other local profiles, every harness) is never banned, unless
/// the debug switch `RAVEN_LAB_SEC_PENALTY_LOOPBACK=1` says so. (Its own
/// loopback address, so a ban never touches another test's.)
#[tokio::test(start_paused = true)]
async fn loopback_is_never_banned_without_the_lab_switch() {
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let lo: IpAddr = "127.0.0.77".parse().unwrap();
    junk("127.0.0.77", 64);
    assert_eq!(
        source_banned(lo),
        security_gate::lab_penalty_loopback(),
        "loopback is banned only with the lab switch"
    );
    assert_eq!(
        admit_source(lo, OutboxCarrier::Lan) == Admit::Allow,
        !security_gate::lab_penalty_loopback()
    );
    source_authenticated(lo, OutboxCarrier::Lan);
    assert!(!source_banned(lo));
}

/// Only addresses are struck: the listeners' cap refusals and pre-auth
/// failures (LAN, Internet), never the p2p responder's per-PeerId keys or
/// a radio pipe's per-contact key (a failed knock is noted, no strike).
#[tokio::test(start_paused = true)]
async fn only_addresses_are_struck() {
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let (keyed, radio, inet, capped) = ("fd00:1:2:3::", "fd00:5300::", "203.0.113.5", "10.0.1.50");
    for _ in 0..32 {
        inbound_refused(
            keyed.parse().unwrap(),
            OutboxCarrier::P2p,
            NOISE_HANDSHAKE_FAILED,
        );
        inbound_refused(
            radio.parse().unwrap(),
            OutboxCarrier::Nearby,
            NOISE_HANDSHAKE_FAILED,
        );
        knock_failed(radio.parse().unwrap(), false);
        cap_refused(keyed.parse().unwrap(), OutboxCarrier::P2p);
    }
    assert!(!source_banned(keyed.parse().unwrap()));
    assert!(!source_banned(radio.parse().unwrap()));
    // Internet direct's listener: weight 2 for a malformed frame, 8 ban.
    for _ in 0..8 {
        inbound_refused(
            inet.parse().unwrap(),
            OutboxCarrier::Internet,
            raven_core::security_events::INTERNET_FRAME_LENGTH,
        );
    }
    assert!(source_banned(inet.parse().unwrap()));
    // A source at its own cap: one strike each.
    for _ in 0..15 {
        cap_refused(capped.parse().unwrap(), OutboxCarrier::Lan);
    }
    assert!(!source_banned(capped.parse().unwrap()));
    cap_refused(capped.parse().unwrap(), OutboxCarrier::Lan);
    assert!(source_banned(capped.parse().unwrap()));
}

/// The p2p peer gate: its inbound refusals are strikes (a dial of ours that
/// reached a stranger is not), and a banned IP's direct connections are
/// refused before Noise by the hook the host installs, save the probation
/// one.
#[tokio::test(start_paused = true)]
async fn the_p2p_gate_refuses_a_banned_ip_before_noise() {
    use raven_swarm::gate::{GateHandle, PeerGate, SourceRefused};
    use raven_swarm::libp2p::swarm::{ConnectionId, NetworkBehaviour};
    use raven_swarm::libp2p::Multiaddr;
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let (stranger, dialled): (IpAddr, IpAddr) =
        ("192.0.2.40".parse().unwrap(), "192.0.2.41".parse().unwrap());
    let refused = p2p_gate_hook().expect("installed");
    for _ in 0..32 {
        refused(dialled, RefusalKind::Outbound);
    }
    assert!(!source_banned(dialled), "our own dial is no strike");
    for _ in 0..16 {
        refused(stranger, RefusalKind::Inbound);
    }
    assert!(source_banned(stranger));
    let mut gate = PeerGate::new(GateHandle::new(None));
    gate.set_admit_hook(p2p_admit_hook());
    let local: Multiaddr = "/ip4/192.0.2.1/tcp/7423".parse().unwrap();
    let from: Multiaddr = "/ip4/192.0.2.40/tcp/40001".parse().unwrap();
    let other: Multiaddr = "/ip4/192.0.2.42/udp/4001/quic-v1".parse().unwrap();
    let mut pending = |n: usize, remote: &Multiaddr| {
        gate.handle_pending_inbound_connection(ConnectionId::new_unchecked(n), &local, remote)
    };
    assert!(pending(1, &from).is_ok(), "the probation connection");
    let denied = pending(2, &from).unwrap_err();
    assert_eq!(
        denied
            .downcast_ref::<SourceRefused>()
            .map(ToString::to_string),
        Some("a source that failed too often was refused".to_string())
    );
    assert!(pending(3, &other).is_ok(), "another source");
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(pending(4, &from).is_ok(), "the next probation");
}

/// Phase 6 review (sensing-7): a contact's direct inbound p2p connection
/// from a banned source (a friend behind a stranger's CGNAT address)
/// clears that source, as an authenticated contact does at the TCP
/// listeners: its next connections are admitted at once, not one per 10 s.
/// A relay's connection from there clears nothing.
#[tokio::test(start_paused = true)]
async fn a_contacts_p2p_connection_clears_its_banned_source() {
    use raven_swarm::gate::{GateHandle, PeerClass, PeerGate};
    use raven_swarm::libp2p::swarm::{ConnectionId, NetworkBehaviour};
    use raven_swarm::libp2p::{Multiaddr, PeerId};
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let shared: IpAddr = "192.0.2.50".parse().unwrap();
    let refused = p2p_gate_hook().expect("installed");
    for _ in 0..16 {
        refused(shared, RefusalKind::Inbound);
    }
    let banned = || source_banned_on(shared, OutboxCarrier::P2p);
    assert!(banned());
    let (friend, relay) = (PeerId::random(), PeerId::random());
    let handle = GateHandle::new(None);
    handle.replace(
        [(friend, PeerClass::CONTACT), (relay, PeerClass::OWN_RELAY)]
            .into_iter()
            .collect(),
        false,
        std::time::Instant::now(),
    );
    let mut gate = PeerGate::new(handle);
    gate.set_admit_hook(p2p_admit_hook());
    gate.set_authenticated_hook(p2p_authenticated_hook());
    let local: Multiaddr = "/ip4/192.0.2.1/tcp/4001".parse().unwrap();
    let from: Multiaddr = "/ip4/192.0.2.50/tcp/40001".parse().unwrap();
    let id = ConnectionId::new_unchecked;
    assert!(gate
        .handle_pending_inbound_connection(id(1), &local, &from)
        .is_ok());
    assert!(gate
        .handle_pending_inbound_connection(id(2), &local, &from)
        .is_err());
    gate.handle_established_inbound_connection(id(1), relay, &local, &from)
        .unwrap();
    assert!(banned(), "a relay is no contact");
    gate.handle_established_inbound_connection(id(3), friend, &local, &from)
        .unwrap();
    assert!(!banned(), "the contact cleared its source");
    for n in 4..8 {
        assert!(gate
            .handle_pending_inbound_connection(id(n), &local, &from)
            .is_ok());
    }
}

/// The beacon answerer (S22): a replay of a matched query is
/// SEC_BEACON_REPLAY and a strike of 4, a query over its source's rate
/// SEC_BEACON_FLOOD and a strike of 1; a banned source is reported banned
/// without using its probation.
#[tokio::test(start_paused = true)]
async fn beacon_replays_and_floods_are_noted_and_struck() {
    let Some(capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let (replayer, flooder): (IpAddr, IpAddr) = (
        "192.168.7.66".parse().unwrap(),
        "192.168.7.77".parse().unwrap(),
    );
    for _ in 0..3 {
        beacon_refused(replayer, true, clock());
    }
    assert!(!beacon_banned(replayer, clock()));
    beacon_refused(replayer, true, clock());
    assert!(beacon_banned(replayer, clock()));
    for _ in 0..15 {
        beacon_refused(flooder, false, clock());
    }
    assert!(!beacon_banned(flooder, clock()));
    beacon_refused(flooder, false, clock());
    assert!(beacon_banned(flooder, clock()));
    let lan = Via::DirectLink(OutboxCarrier::Lan);
    let kinds: Vec<_> = capture.kinds();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == (SecKind::BeaconReplay, network("192.168.7.66"), lan))
            .count(),
        4
    );
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == (SecKind::BeaconFlood, network("192.168.7.77"), lan))
            .count(),
        16
    );
    assert_eq!(floods(&capture).len(), 2, "one per ban");
    // Looking used no probation: a listener still gets it.
    assert_eq!(admit_source(replayer, OutboxCarrier::Lan), Admit::Probation);
    assert_eq!(beacon_strike_weight(true), 4);
    assert_eq!(beacon_strike_weight(false), 1);
}

// ── P6.27: early re-key and rollback recovery (design A R2, R3) ────────────

/// What the responder asked for (a test's [`Act`]).
#[derive(Default)]
struct Recorder {
    policy_off: bool,
    rotate_fails: bool,
    /// No identity yet (the outbox worker has not started).
    not_yet: bool,
    /// How many contacts R3's re-keys reach.
    live_peers: usize,
    rekeys: Vec<([u8; 32], SecKind)>,
    rotations: usize,
    live_rekeys: usize,
    // R4-R8 (step P6.28).
    paths: Vec<([u8; 32], [u8; 8], OutboxCarrier, u64)>,
    /// How many addresses R5 finds to forget.
    impostor_addrs: usize,
    custodian_strikes: Vec<[u8; 32]>,
    throttled: bool,
    relays_last: Vec<([u8; 32], u64)>,
}

impl Act for Recorder {
    fn auto_rekey_on(&self) -> bool {
        !self.policy_off
    }

    fn rekey(&mut self, peer: &[u8; 32], reason: SecKind, _now_ms: u64) -> bool {
        self.rekeys.push((*peer, reason));
        true
    }

    fn rotate_prekey(&mut self) -> Option<bool> {
        if self.not_yet {
            return None;
        }
        self.rotations += 1;
        Some(!self.rotate_fails)
    }

    fn rekey_live_peers(&mut self, _now_ms: u64) -> Option<usize> {
        if self.not_yet {
            return None;
        }
        self.live_rekeys += 1;
        Some(self.live_peers)
    }

    fn demote_path(
        &mut self,
        peer: &[u8; 32],
        network: [u8; 8],
        carrier: OutboxCarrier,
        until_ms: u64,
    ) -> bool {
        self.paths.push((*peer, network, carrier, until_ms));
        true
    }

    fn forget_impostor(&mut self, _peer: &[u8; 32], _now_ms: u64) -> usize {
        self.impostor_addrs
    }

    /// Like custody: the third strike against one custodian parks it.
    fn strike_custodian(&mut self, custodian: &[u8; 32]) -> bool {
        self.custodian_strikes.push(*custodian);
        self.custodian_strikes
            .iter()
            .filter(|c| *c == custodian)
            .count()
            % 3
            == 0
    }

    fn depositor_throttled(&mut self, _depositor: &[u8; 32], _now_ms: u64) -> bool {
        self.throttled
    }

    fn relay_last(&mut self, subject: &[u8; 32], until_ms: u64) -> bool {
        self.relays_last.push((*subject, until_ms));
        true
    }
}

/// The responses gate shut for this thread whatever the variables say (the
/// suite's lab run opens it for every thread); back on drop.
struct ResponsesShut;

impl ResponsesShut {
    fn start() -> Self {
        security_gate::set_lab_for_this_thread(SecGate::Responses, Some(false));
        Self
    }
}

impl Drop for ResponsesShut {
    fn drop(&mut self) {
        security_gate::set_lab_for_this_thread(SecGate::Responses, None);
    }
}

const T0: u64 = 1_900_000_000_000;

fn on_link(kind: SecKind, who: Attribution, at: u64) -> SecEvent {
    SecEvent::new(kind, who, Via::DirectLink(OutboxCarrier::Lan), at)
}

/// OD6b-5: only what the contact's own signature or this computer's disk
/// raises asks for a response: an object of a contact's that failed
/// authentication or was replayed (R2), its third index jump within an
/// hour (R2), a rollback here (R3). A stranger's junk, a custodian's
/// unrequested or replayed object, a relay's broken link and a path's tag
/// failures never do: no third party can spend a contact's re-key budget.
#[test]
fn only_the_contacts_signature_or_this_disk_asks_for_a_response() {
    let mut t = Triggers::default();
    let (alice, bob) = (key(0x91), key(0x92));
    for kind in [SecKind::ObjectAuthFail, SecKind::ObjectReplay] {
        assert_eq!(
            t.response(&on_link(kind, contact(alice), T0)),
            Some(Response::Rekey(alice, kind))
        );
    }
    let minute = MINUTE_MS;
    let jump = |t: &mut Triggers, who: [u8; 32], at: u64| {
        t.response(&on_link(SecKind::IndexJump, contact(who), at))
    };
    assert_eq!(jump(&mut t, alice, T0), None);
    assert_eq!(jump(&mut t, alice, T0 + 20 * minute), None);
    assert_eq!(
        jump(&mut t, bob, T0 + 30 * minute),
        None,
        "Bob's are his own"
    );
    assert_eq!(
        jump(&mut t, alice, T0 + 40 * minute),
        Some(Response::Rekey(alice, SecKind::IndexJump))
    );
    // The count starts again; jumps more than an hour apart never add up.
    assert_eq!(jump(&mut t, alice, T0 + 50 * minute), None);
    assert_eq!(jump(&mut t, alice, T0 + 111 * minute), None);
    assert_eq!(jump(&mut t, alice, T0 + 172 * minute), None);
    assert_eq!(
        t.response(&SecEvent::new(
            SecKind::LocalRollback,
            Attribution::Local,
            Via::Local,
            T0
        )),
        Some(Response::Rollback)
    );
    let custodian = Attribution::Carrier {
        carrier: key(0x93),
        role: CarrierRole::Custodian,
    };
    let relay = Attribution::Carrier {
        carrier: key(0x94),
        role: CarrierRole::Relay,
    };
    let never = [
        on_link(SecKind::PreauthMalformed, network("203.0.113.7"), T0),
        on_link(SecKind::StrangerRefused, network("203.0.113.7"), T0),
        SecEvent::new(
            SecKind::CustodianUnrequested,
            custodian,
            Via::Custodian(key(0x93)),
            T0,
        ),
        SecEvent::new(
            SecKind::CustodianReplay,
            custodian,
            Via::Custodian(key(0x93)),
            T0,
        ),
        SecEvent::new(SecKind::RelayLinkBroken, relay, Via::Relay, T0),
        on_link(SecKind::LinkTagFail, contact(alice), T0),
        on_link(SecKind::BindingMismatch, contact(alice), T0),
        on_link(SecKind::SessionUnknown, contact(alice), T0),
    ];
    for ev in never {
        assert_eq!(t.response(&ev), None, "{ev:?}");
    }
}

/// The responder answers only while the responses gate is live and
/// `node_policy.security_auto_rekey` is on; R2 once per contact per 6 h
/// (the store is not asked again); R3 rotates the prekey and asks every
/// live contact, at most once per 6 h (a rollback found before the outbox
/// worker runs is tried again by the next one), and says REKEY_REQUESTED
/// when the rotation failed but re-keys were asked. Each answer is the
/// alert's action code.
#[test]
fn the_responder_rekeys_once_per_six_hours_and_recovers_from_a_rollback() {
    let alice = key(0x95);
    let bad = |at| on_link(SecKind::ObjectAuthFail, contact(alice), at);
    let rollback = |at| SecEvent::new(SecKind::LocalRollback, Attribution::Local, Via::Local, at);
    {
        let _shut = ResponsesShut::start();
        let mut r = Responder::new(Recorder::default());
        assert_eq!(r.respond(&bad(T0), T0), None);
        assert_eq!(r.respond(&rollback(T0), T0), None);
        assert!(r.act.rekeys.is_empty());
        assert_eq!((r.act.rotations, r.act.live_rekeys), (0, 0));
    }
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let mut r = Responder::new(Recorder {
        live_peers: 2,
        ..Recorder::default()
    });
    assert_eq!(r.respond(&bad(T0), T0), Some(REKEY_REQUESTED));
    let replay = on_link(SecKind::ObjectReplay, contact(alice), T0 + HOUR_MS);
    assert_eq!(r.respond(&replay, T0 + HOUR_MS), None, "6 h cap");
    let later = T0 + session_renewal::EARLY_MIN_GAP_MS;
    assert_eq!(r.respond(&bad(later), later), Some(REKEY_REQUESTED));
    assert_eq!(
        r.act.rekeys,
        vec![
            (alice, SecKind::ObjectAuthFail),
            (alice, SecKind::ObjectAuthFail)
        ]
    );
    // The policy off: nothing.
    r.act.policy_off = true;
    let carol = on_link(SecKind::ObjectAuthFail, contact(key(0x96)), T0);
    assert_eq!(r.respond(&carol, T0), None);
    assert_eq!(r.respond(&rollback(T0), T0), None);
    assert_eq!(r.act.rekeys.len(), 2);
    r.act.policy_off = false;
    // R3 before the outbox worker runs: nothing yet, tried again.
    r.act.not_yet = true;
    assert_eq!(r.respond(&rollback(T0), T0), None);
    r.act.not_yet = false;
    // R3: the prekey, then every live contact; once per 6 h.
    assert_eq!(r.respond(&rollback(T0), T0), Some(PREKEY_ROTATED));
    assert_eq!((r.act.rotations, r.act.live_rekeys), (1, 1));
    assert_eq!(r.respond(&rollback(T0 + HOUR_MS), T0 + HOUR_MS), None);
    assert_eq!((r.act.rotations, r.act.live_rekeys), (1, 1));
    r.act.rotate_fails = true;
    assert_eq!(r.respond(&rollback(later), later), Some(REKEY_REQUESTED));
    assert_eq!((r.act.rotations, r.act.live_rekeys), (2, 2));
    // A stranger's junk never reaches the act.
    let junk = on_link(SecKind::PreauthMalformed, network("203.0.113.8"), later);
    assert_eq!(r.respond(&junk, later), None);
    assert_eq!(r.act.rekeys.len(), 2);
}

/// The real act on a profile: the policy file decides (`security_auto_rekey`
/// off: nothing), an early re-key is noted in the profile's session store
/// with its reason, and a second one within 6 h is refused there too.
#[test]
fn the_node_act_reads_the_policy_and_notes_the_request_in_the_store() {
    use raven_core::indexed_session_store::IndexedSessionStore;
    use raven_core::node_policy::{load_policy, save_policy};
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let mut act = NodeAct {
        data_dir: dir.path().to_path_buf(),
    };
    assert!(act.auto_rekey_on());
    let mut policy = load_policy(dir.path());
    policy.security_auto_rekey = false;
    save_policy(dir.path(), &policy).unwrap();
    assert!(!act.auto_rekey_on());
    let alice = key(0x97);
    let now = now_ms();
    assert!(act.rekey(&alice, SecKind::ObjectReplay, now));
    assert!(!act.rekey(&alice, SecKind::ObjectAuthFail, now + 1));
    let state = IndexedSessionStore::open(dir.path())
        .unwrap()
        .peer_renewal_state(&alice)
        .unwrap();
    assert_eq!(
        (state.early_requested_at_ms, state.early_reason),
        (Some(now), Some(SecKind::ObjectReplay.code()))
    );
    {
        let _shut = ResponsesShut::start();
        assert!(!act.auto_rekey_on());
        assert!(!act.rekey(&key(0x98), SecKind::ObjectReplay, now));
    }
}

/// Each response writes its alert's action: the early re-key's alert about
/// the contact says REKEY_REQUESTED, the rollback's PREKEY_ROTATED; an
/// event nobody answered keeps none.
#[test]
fn a_response_writes_its_alerts_action() {
    use crate::at_rest_boot::tests::{lab_hist_key, profile_with, seal, serial};
    if !lab_hist_key() {
        return;
    }
    let Some(_capture) = Capture::start() else {
        return;
    };
    let dir = profile_with(&[]);
    let dd = dir.path().to_path_buf();
    {
        let _serial = serial();
        seal(&dd);
    }
    let opener = dd.clone();
    let now = now_ms();
    let mut writer = Writer::new(move || SecurityLedger::open(&opener), now).responding_with(
        Box::new(|ev, _, _| match ev.kind {
            SecKind::ObjectAuthFail => Some(REKEY_REQUESTED),
            SecKind::LocalRollback => Some(PREKEY_ROTATED),
            _ => None,
        }),
    );
    let alice = key(0x99);
    writer.event(
        &on_link(SecKind::ObjectAuthFail, contact(alice), now),
        Severity::Suspicious,
        now,
    );
    writer.event(
        &SecEvent::new(SecKind::LocalRollback, Attribution::Local, Via::Local, now),
        Severity::Alert,
        now,
    );
    writer.event(
        &on_link(SecKind::LinkTagFail, contact(key(0x9a)), now),
        Severity::Notice,
        now,
    );
    let alerts = writer.ledger.as_ref().unwrap().open_alerts().unwrap();
    let action = |kind| {
        alerts
            .iter()
            .find(|a| a.kind == kind)
            .map(|a| a.action.clone())
            .unwrap_or_else(|| panic!("{kind:?}: {alerts:?}"))
    };
    assert_eq!(
        action(SecKind::ObjectAuthFail).as_deref(),
        Some(REKEY_REQUESTED)
    );
    assert_eq!(
        action(SecKind::LocalRollback).as_deref(),
        Some(PREKEY_ROTATED)
    );
    assert_eq!(action(SecKind::LinkTagFail), None);
    writer.finish(now);
}

/// Acceptance (OD6b-6, "never auto-block"): the node's security responder
/// and renewer never block, unpin or remove a contact (raven-core checks
/// its security modules and session renewal the same way).
#[test]
fn the_responder_and_the_renewer_never_block_unpin_or_remove_a_contact() {
    const NEEDLES: [&str; 8] = [
        "BlockList",
        ".block(",
        "contact_book::write_rows",
        "contact_book::lock(",
        "forget_peer_prekey_pin",
        "pinned = false",
        "save_contact",
        "remove_contact",
    ];
    for (file, source) in [
        ("security.rs", include_str!("../security.rs")),
        ("renewal.rs", include_str!("../renewal.rs")),
    ] {
        for needle in NEEDLES {
            assert!(!source.contains(needle), "{file} names {needle}");
        }
    }
}

// ── P6.28: path, custodian, depositor and relay responses (R4-R8) ─────────

fn custodian(key: [u8; 32]) -> Attribution {
    Attribution::Carrier {
        carrier: key,
        role: CarrierRole::Custodian,
    }
}

fn relay(subject: [u8; 32]) -> Attribution {
    Attribution::Carrier {
        carrier: subject,
        role: CarrierRole::Relay,
    }
}

/// Which events R4-R8 take, and at what level: a contact's tag failures
/// once Suspicious and on a known network (R4), a contact's impostor once
/// Suspicious (R5), what a custodian served (R6; a bad letter whose
/// signature verified is its sender's), a depositor's refused object (R7),
/// a relay once Suspicious (R8). None of them is a re-key (R2/R3 keep
/// theirs), and network sources never get one.
#[test]
fn paths_custodians_depositors_and_relays_get_their_own_answers() {
    use Severity::{Notice, Suspicious};
    let (alice, rena) = (key(0xa1), key(0xa2));
    let net = [0x5c; 8];
    let tag = on_link(SecKind::LinkTagFail, contact(alice), T0).on_network(net);
    assert_eq!(path_answer(&tag, Notice), None);
    assert_eq!(
        path_answer(&tag, Suspicious),
        Some(PathAnswer::Interference {
            peer: alice,
            network: net,
            carrier: OutboxCarrier::Lan
        })
    );
    let dialled = SecEvent::new(
        SecKind::LinkTagFail,
        contact(alice),
        Via::Dial(OutboxCarrier::P2p),
        T0,
    )
    .on_network(net);
    assert_eq!(
        path_answer(&dialled, Severity::Alert),
        Some(PathAnswer::Interference {
            peer: alice,
            network: net,
            carrier: OutboxCarrier::P2p
        })
    );
    let nowhere = on_link(SecKind::LinkTagFail, contact(alice), T0);
    assert_eq!(path_answer(&nowhere, Suspicious), None, "no network");
    let impostor = SecEvent::new(
        SecKind::AddressImpostor,
        contact(alice),
        Via::Dial(OutboxCarrier::Lan),
        T0,
    );
    assert_eq!(path_answer(&impostor, Notice), None);
    assert_eq!(
        path_answer(&impostor, Suspicious),
        Some(PathAnswer::Impostor(alice))
    );
    let served = Via::Custodian(rena);
    for kind in [
        SecKind::CustodianBadObject,
        SecKind::CustodianUnrequested,
        SecKind::LetterBad,
    ] {
        let ev = SecEvent::new(kind, custodian(rena), served, T0);
        assert_eq!(
            path_answer(&ev, Suspicious),
            Some(PathAnswer::Custodian(rena)),
            "{kind:?}"
        );
    }
    let depositor = on_link(SecKind::DepositorBadObject, contact(alice), T0);
    assert_eq!(
        path_answer(&depositor, Suspicious),
        Some(PathAnswer::Depositor(alice))
    );
    let subject = events::relay_subject(b"relay-peer");
    for kind in [SecKind::RelayNoReceipt, SecKind::RelayLinkBroken] {
        let ev = SecEvent::new(kind, relay(subject), Via::Relay, T0);
        assert_eq!(path_answer(&ev, Notice), None, "{kind:?}");
        assert_eq!(
            path_answer(&ev, Suspicious),
            Some(PathAnswer::Relay(subject)),
            "{kind:?}"
        );
    }
    let never = [
        SecEvent::new(SecKind::LetterBad, contact(alice), served, T0),
        SecEvent::new(SecKind::CustodianReplay, custodian(rena), served, T0),
        on_link(SecKind::DepositorFlood, contact(alice), T0),
        on_link(SecKind::ObjectAuthFail, contact(alice), T0),
        on_link(SecKind::PreauthMalformed, network("203.0.113.9"), T0).on_network(net),
        on_link(SecKind::BindingMismatch, contact(alice), T0).on_network(net),
    ];
    for ev in never {
        assert_eq!(path_answer(&ev, Severity::Alert), None, "{ev:?}");
    }
}

/// The responder carries R4-R8 out only while the responses gate is live
/// (the re-key policy does not apply to them) and answers each with its
/// alert's action: PATH_DEMOTED for 10 minutes, ADDRESS_FORGOTTEN when an
/// address was forgotten, CUSTODIAN_PARKED on the strike that parks,
/// DEPOSITS_THROTTLED once the custodian code throttles, RELAY_DEMOTED for
/// an hour. A re-key event still goes to R2.
#[test]
fn the_responder_demotes_forgets_parks_throttles_and_puts_relays_last() {
    use Severity::Suspicious;
    let (alice, rena) = (key(0xa3), key(0xa4));
    let net = [0x5d; 8];
    let tag = on_link(SecKind::LinkTagFail, contact(alice), T0).on_network(net);
    let subject = events::relay_subject(b"relay-peer-2");
    let lost = SecEvent::new(SecKind::RelayNoReceipt, relay(subject), Via::Relay, T0);
    {
        let _shut = ResponsesShut::start();
        let mut r = Responder::new(Recorder::default());
        assert_eq!(r.respond_at(&tag, Suspicious, T0), None);
        assert_eq!(r.respond_at(&lost, Suspicious, T0), None);
        assert!(r.act.paths.is_empty() && r.act.relays_last.is_empty());
    }
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let mut r = Responder::new(Recorder {
        policy_off: true,
        ..Recorder::default()
    });
    // R4.
    assert_eq!(r.respond_at(&tag, Severity::Notice, T0), None);
    assert_eq!(r.respond_at(&tag, Suspicious, T0), Some(PATH_DEMOTED));
    assert_eq!(
        r.act.paths,
        vec![(alice, net, OutboxCarrier::Lan, T0 + 10 * MINUTE_MS)]
    );
    // R5: an address to forget, or none.
    let impostor = SecEvent::new(
        SecKind::AddressImpostor,
        contact(alice),
        Via::Dial(OutboxCarrier::Lan),
        T0,
    );
    assert_eq!(r.respond_at(&impostor, Suspicious, T0), None);
    r.act.impostor_addrs = 1;
    assert_eq!(
        r.respond_at(&impostor, Suspicious, T0),
        Some(ADDRESS_FORGOTTEN)
    );
    // R6: the third strike parks.
    let bad = SecEvent::new(
        SecKind::CustodianBadObject,
        custodian(rena),
        Via::Custodian(rena),
        T0,
    );
    assert_eq!(r.respond_at(&bad, Suspicious, T0), None);
    assert_eq!(r.respond_at(&bad, Suspicious, T0), None);
    assert_eq!(
        r.respond_at(&bad, Severity::Alert, T0),
        Some(CUSTODIAN_PARKED)
    );
    // R7.
    let refused = on_link(SecKind::DepositorBadObject, contact(alice), T0);
    assert_eq!(r.respond_at(&refused, Suspicious, T0), None);
    r.act.throttled = true;
    assert_eq!(
        r.respond_at(&refused, Suspicious, T0),
        Some(DEPOSITS_THROTTLED)
    );
    // R8.
    assert_eq!(r.respond_at(&lost, Severity::Notice, T0), None);
    assert_eq!(r.respond_at(&lost, Suspicious, T0), Some(RELAY_DEMOTED));
    assert_eq!(r.act.relays_last, vec![(subject, T0 + HOUR_MS)]);
    // R2 still answers through the same door (the policy is off here).
    let replay = on_link(SecKind::ObjectReplay, contact(alice), T0);
    assert_eq!(r.respond_at(&replay, Suspicious, T0), None);
    r.act.policy_off = false;
    assert_eq!(r.respond_at(&replay, Suspicious, T0), Some(REKEY_REQUESTED));
}

/// The real act on a profile: R4 notes the interference the outbox plans
/// by; R5 forgets where the contact was seen when another key answered
/// there (only that sighting, never the address saved in the contact book,
/// and once); R7 reads the custodian code's throttle; R8 puts the relay
/// last for an hour.
#[test]
fn the_node_act_carries_out_r4_r5_r7_and_r8() {
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let mut act = NodeAct {
        data_dir: d.to_path_buf(),
    };
    let now = now_ms();
    // R4.
    let (alice, net) = (key(0xa5), [0x5e; 8]);
    assert!(act.demote_path(&alice, net, OutboxCarrier::Lan, now + 10 * MINUTE_MS));
    assert_eq!(
        raven_core::route_memory::interfered_carriers(&alice, Some(net), now),
        [OutboxCarrier::Lan]
    );
    // R5: Bob was seen at .37; another key answered there.
    let bob = key(0xa6);
    let book = format!(
        r#"[{{"petname":"Bob","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":true,"lan_dial":"192.168.9.20:7420","internet_dial":""}}]"#,
        hex::encode(bob)
    );
    std::fs::write(d.join("contacts.json"), &book).unwrap();
    let seen: IpAddr = "192.168.9.37".parse().unwrap();
    raven_core::lan_seen::record_contact_seen(d, &bob, seen, None, now).unwrap();
    assert_eq!(act.forget_impostor(&bob, now), 0, "nothing noted yet");
    address_impostor(&bob, OutboxCarrier::Lan, Some(seen));
    address_impostor(&key(0xa7), OutboxCarrier::Internet, Some(seen));
    assert_eq!(
        act.forget_impostor(&key(0xa7), now),
        0,
        "LAN addresses only"
    );
    assert_eq!(act.forget_impostor(&bob, now + 2 * DAY_MS), 0, "too old");
    address_impostor(&bob, OutboxCarrier::Lan, Some(seen));
    assert_eq!(act.forget_impostor(&bob, now), 1);
    assert_eq!(raven_core::lan_seen::seen_ip(d, &bob, now), None);
    assert_eq!(
        std::fs::read_to_string(d.join("contacts.json")).unwrap(),
        book
    );
    assert_eq!(act.forget_impostor(&bob, now), 0, "once");
    // R7.
    assert!(!act.depositor_throttled(&key(0xa8), now));
    // R8: the relay goes last for an hour.
    let peer_id = b"relay-peer-3";
    assert!(act.relay_last(&events::relay_subject(peer_id), now + HOUR_MS));
    assert!(relay_demoted_at(peer_id, now) && any_relay_demoted());
    assert!(!relay_demoted_at(peer_id, now + HOUR_MS));
    assert!(!relay_demoted_at(b"relay-peer-4", now));
    {
        let _shut = ResponsesShut::start();
        assert!(!relay_demoted_at(peer_id, now));
    }
}

/// P6.28's merge amendment: with learning on, a relay's security events
/// (a broken link, a Suspicious lost receipt) lower its learned term and
/// R8 puts no relay last by hand; a lost receipt that is not Suspicious
/// does nothing. With learning off, R8's fallback puts it last as before.
#[test]
fn with_learning_on_a_relays_events_lower_its_term_and_none_goes_last_by_hand() {
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let mut act = NodeAct {
        data_dir: dir.path().to_path_buf(),
    };
    let (broke, lost, quiet) = (
        b"relay-learn-broke".to_vec(),
        b"relay-learn-lost".to_vec(),
        b"relay-learn-quiet".to_vec(),
    );
    let now = now_ms();
    {
        let learn_dir = tempfile::tempdir().unwrap();
        let mut t = crate::learning::TestService::loaded(learn_dir.path(), Some("home"));
        t.set_now(now);
        for _ in 0..3 {
            relay_link_broken([broke.clone()]);
            relay_no_receipt(&lost, true);
            relay_no_receipt(&quiet, false);
        }
        t.drain();
        assert_eq!(
            crate::learning::relay_terms(&[broke.clone(), lost.clone(), quiet.clone()]),
            [-90, -90, 0]
        );
        assert!(!act.relay_last(&events::relay_subject(&broke), now + HOUR_MS));
        assert!(!relay_demoted_at(&broke, now), "nothing by hand");
    }
    // Learning off: R8's fallback.
    assert!(crate::learning::relay_terms(std::slice::from_ref(&broke)).is_empty());
    assert!(act.relay_last(&events::relay_subject(&broke), now + HOUR_MS));
    assert!(relay_demoted_at(&broke, now));
}

/// Acceptance (design A, step P6.28): every automatic action of R4-R8 is
/// written into its alert's `action`, a fixed code.
#[test]
fn each_path_response_writes_its_alerts_action() {
    use crate::at_rest_boot::tests::{lab_hist_key, profile_with, seal, serial};
    if !lab_hist_key() {
        return;
    }
    let Some(_capture) = Capture::start() else {
        return;
    };
    let Some(_responding) = Responding::start() else {
        return;
    };
    let dir = profile_with(&[]);
    let dd = dir.path().to_path_buf();
    {
        let _serial = serial();
        seal(&dd);
    }
    let opener = dd.clone();
    let now = now_ms();
    let mut responder = Responder::new(Recorder {
        impostor_addrs: 1,
        throttled: true,
        ..Recorder::default()
    });
    let mut writer = Writer::new(move || SecurityLedger::open(&opener), now).responding_with(
        Box::new(move |ev, severity, at| responder.respond_at(ev, severity, at)),
    );
    let (alice, rena) = (key(0xa9), key(0xaa));
    let subject = events::relay_subject(b"relay-peer-5");
    let events = [
        (
            on_link(SecKind::LinkTagFail, contact(alice), now).on_network([0x5f; 8]),
            PATH_DEMOTED,
        ),
        (
            SecEvent::new(
                SecKind::AddressImpostor,
                contact(alice),
                Via::Dial(OutboxCarrier::Lan),
                now,
            ),
            ADDRESS_FORGOTTEN,
        ),
        (
            on_link(SecKind::DepositorBadObject, contact(alice), now),
            DEPOSITS_THROTTLED,
        ),
        (
            SecEvent::new(SecKind::RelayLinkBroken, relay(subject), Via::Relay, now),
            RELAY_DEMOTED,
        ),
    ];
    for (ev, _) in &events {
        writer.event(ev, Severity::Suspicious, now);
    }
    let bad = SecEvent::new(
        SecKind::CustodianUnrequested,
        custodian(rena),
        Via::Custodian(rena),
        now,
    );
    for _ in 0..3 {
        writer.event(&bad, Severity::Suspicious, now);
    }
    let alerts = writer.ledger.as_ref().unwrap().open_alerts().unwrap();
    let action = |kind| {
        alerts
            .iter()
            .find(|a| a.kind == kind)
            .map(|a| a.action.clone())
            .unwrap_or_else(|| panic!("{kind:?}: {alerts:?}"))
    };
    for (ev, code) in &events {
        assert_eq!(action(ev.kind).as_deref(), Some(*code), "{:?}", ev.kind);
    }
    assert_eq!(
        action(SecKind::CustodianUnrequested).as_deref(),
        Some(CUSTODIAN_PARKED)
    );
    writer.finish(now);
}

/// P6.29 (design A R9): a contact's link features raise its capability
/// floor, a partial showing (LAN) never counts as a loss, and a complete one
/// (a verified hello) without a feature seen before is one
/// `SEC_CAPABILITY_DOWNGRADE` about that contact a day; the floor never
/// falls. Nothing is kept or noted while the gate is shut.
#[test]
fn link_features_raise_the_floor_and_a_lost_one_is_noted_once_a_day() {
    use raven_core::{CAP_INTERNET, CAP_LINK_RRH1};
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let peer = key(0x29);
    let lan = Via::DirectLink(OutboxCarrier::Lan);
    let dial = Via::Dial(OutboxCarrier::Internet);
    security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
    link_features(dd, &peer, LinkFeatures::Complete(CAP_LINK_RRH1), None, dial);
    assert!(!dd.join(capability_floor::CAPABILITY_FLOOR_FILE).exists());
    let Some(capture) = Capture::start() else {
        return;
    };
    link_features(dd, &peer, LinkFeatures::Seen(CAP_LINK_RRH1), None, lan);
    link_features(dd, &peer, LinkFeatures::Seen(0), None, lan);
    link_features(
        dd,
        &peer,
        LinkFeatures::Complete(CAP_INTERNET | CAP_LINK_RRH1),
        None,
        dial,
    );
    assert!(capture.events().is_empty());
    for _ in 0..2 {
        link_features(dd, &peer, LinkFeatures::Complete(CAP_INTERNET), None, dial);
    }
    assert_eq!(
        capture.kinds(),
        vec![(SecKind::CapabilityDowngrade, contact(peer), dial)]
    );
    let floor = capability_floor::floor(dd, &peer).unwrap();
    assert_eq!(floor.link_caps_max, CAP_LINK_RRH1, "never lowered");
    assert_eq!(
        floor.open_features(),
        vec![capability_floor::Feature::RouteHints]
    );
    assert!(!floor.open_downgrade(), "route hints: a Notice only");
}

/// P6.35 (RLK1): a LAN or Internet direct link shows whether it carried the
/// knock. Once a contact knocked, a link that did not (a seen-only LAN
/// showing included) is one Suspicious `SEC_CAPABILITY_DOWNGRADE` a day; a
/// link that cannot tell (`None`: p2p, nearby, the knock shut here) is
/// none.
#[test]
fn a_lost_knock_is_a_suspicious_downgrade_on_any_direct_link() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let peer = key(0x35);
    let lan = Via::DirectLink(OutboxCarrier::Lan);
    let Some(capture) = Capture::start() else {
        return;
    };
    link_features(dd, &peer, LinkFeatures::Seen(0), Some(false), lan);
    link_features(dd, &peer, LinkFeatures::Seen(0), Some(true), lan);
    link_features(dd, &peer, LinkFeatures::Seen(0), None, lan);
    assert!(capture.events().is_empty());
    for _ in 0..2 {
        link_features(dd, &peer, LinkFeatures::Seen(0), Some(false), lan);
    }
    assert_eq!(
        capture.kinds(),
        vec![(SecKind::CapabilityDowngrade, contact(peer), lan)]
    );
    let floor = capability_floor::floor(dd, &peer).unwrap();
    assert!(
        floor.knock && floor.open_downgrade(),
        "the knock: Suspicious"
    );
}

/// P6.35: a replayed knock at a LAN listener is one `SEC_KNOCK_REPLAY`
/// about its source and R1's strike 4 (four of them ban it).
#[test]
fn a_replayed_knock_is_noted_against_its_source() {
    let Some(capture) = Capture::start() else {
        return;
    };
    let ip: IpAddr = "192.0.2.35".parse().unwrap();
    knock_replayed(ip, OutboxCarrier::Lan);
    assert_eq!(
        capture.kinds(),
        vec![(
            SecKind::KnockReplay,
            network("192.0.2.35"),
            Via::DirectLink(OutboxCarrier::Lan)
        )]
    );
    assert_eq!(events::strike_weight(SecKind::KnockReplay), 4);
}
