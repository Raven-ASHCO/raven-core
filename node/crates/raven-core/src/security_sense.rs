//! Where raven-core's sensing points note security events
//! (`docs/roadmap/plans/phase6-design.json`, step P6.25; design A sensing
//! points S6-S20, S23 and S24): a typed refusal on a session, contact,
//! custody, letter or at-rest path becomes one [`SecEvent`] about whoever it
//! is about. ash notes here too (a refused key change, step P6.25).
//!
//! **Whom an event is about.** A refusal of an object the contact signed is
//! the contact's ([`Attribution::Contact`], its device key); junk a custodian
//! served before any signature vouches for it, and an object it serves again
//! after this node released it, are the custodian's
//! ([`Attribution::Carrier`]); this computer's own state changed outside
//! Raven is [`Attribution::Local`]. The callers know which: the helpers here
//! only build the event ([`store_event`] decides it for a session-store
//! refusal).
//!
//! Everything is a no-op while [`SecGate::Events`] is shut: no event, no
//! clock read, and every refusal reads, returns and logs exactly as before.
//! [`note`] never notes twice on one thread at once: a sink that reaches a
//! sensing point itself (ash's direct ledger write opening a sealed row)
//! drops that inner event instead of waiting on itself.

use std::cell::Cell;

use crate::clock::now_ms;
use crate::clock_skew::PeerClock;
use crate::indexed_session_store::IndexedSessionStoreError;
use crate::security_events::{
    self as events, classify_store_error_at, Attribution, CarrierRole, SecEvent, SecKind, Severity,
    Via,
};
use crate::security_gate::{self, SecGate};

thread_local! {
    /// Set while this thread is inside [`note`].
    static NOTING: Cell<bool> = const { Cell::new(false) };
}

/// Whether events are noted at all ([`SecGate::Events`]): a sensing point
/// with work to do before it can name the event asks first.
pub fn live() -> bool {
    security_gate::live(SecGate::Events)
}

/// Note one event: raven-core's sensing points and ash come here, never to
/// [`events::note`] directly. Nothing happens while the gate is shut, or
/// while this thread is already noting one.
pub fn note(ev: SecEvent) {
    note_at_least(ev, Severity::Notice);
}

/// [`note`], with this occurrence raised to at least `floor`
/// ([`events::note_at_least`]): SEC_CAPABILITY_DOWNGRADE's level is the
/// missing feature's (step P6.29, [`crate::capability_floor`]).
pub fn note_at_least(ev: SecEvent, floor: Severity) {
    if !live() || NOTING.with(|n| n.replace(true)) {
        return;
    }
    struct Done;
    impl Drop for Done {
        fn drop(&mut self) {
            NOTING.with(|n| n.set(false));
        }
    }
    let _done = Done;
    #[cfg(test)]
    tests::captured(&ev);
    events::note_at_least(ev, floor);
}

/// An event about the contact `peer` (its device key), reaching this node
/// `via`.
pub fn contact(kind: SecKind, peer: &[u8; 32], via: Via) {
    if live() {
        note(SecEvent::new(
            kind,
            Attribution::Contact { peer: *peer },
            via,
            now_ms(),
        ));
    }
}

/// An event about the carrier `key` in `role` (a custodian, a depositor or
/// forwarder, a relay digest).
pub fn carrier(kind: SecKind, key: &[u8; 32], role: CarrierRole, via: Via) {
    if live() {
        note(SecEvent::new(
            kind,
            Attribution::Carrier {
                carrier: *key,
                role,
            },
            via,
            now_ms(),
        ));
    }
}

/// An event about this computer's own state (S23).
pub fn local(kind: SecKind) {
    if live() {
        note(SecEvent::new(
            kind,
            Attribution::Local,
            Via::Local,
            now_ms(),
        ));
    }
}

/// An event about a security update (design D, step P6.44): `passed_by` is
/// the friend who handed it over (never blamed), `None` for a file the
/// person imported.
pub fn update(kind: SecKind, passed_by: Option<[u8; 32]>, via: Via) {
    if live() {
        note(SecEvent::new(
            kind,
            Attribution::Update { passed_by },
            via,
            now_ms(),
        ));
    }
}

/// The event a session-store refusal of an object from the contact `peer`
/// is, and whom it is about: [`classify_store_error_at`]'s kind (`clock`:
/// what the refused envelope said about the sender's clock); a custodian's
/// kind (an object it served, [`Via::Custodian`]) is about that custodian,
/// this computer's state ([`SecKind::LocalRollback`]) is local, the rest is
/// the contact's. `RollbackDetected` is None here: the store notes it where
/// it finds it (`load_and_reconcile`), so a caller that sees it pass by does
/// not count it twice.
pub fn store_event(
    e: &IndexedSessionStoreError,
    via: Via,
    clock: Option<PeerClock>,
    peer: &[u8; 32],
) -> Option<(SecKind, Attribution)> {
    if matches!(e, IndexedSessionStoreError::RollbackDetected) {
        return None;
    }
    let kind = classify_store_error_at(e, via, clock)?;
    let who = match (kind, via) {
        (SecKind::LocalRollback, _) => Attribution::Local,
        (SecKind::CustodianBadObject | SecKind::CustodianReplay, Via::Custodian(custodian)) => {
            Attribution::Carrier {
                carrier: custodian,
                role: CarrierRole::Custodian,
            }
        }
        _ => Attribution::Contact { peer: *peer },
    };
    Some((kind, who))
}

/// Note a session-store refusal of an object from `peer` ([`store_event`]).
pub fn store_refusal(
    e: &IndexedSessionStoreError,
    via: Via,
    clock: Option<PeerClock>,
    peer: &[u8; 32],
) {
    if !live() {
        return;
    }
    if let Some((kind, who)) = store_event(e, via, clock, peer) {
        let via = match who {
            Attribution::Local => Via::Local,
            _ => via,
        };
        note(SecEvent::new(kind, who, via, now_ms()));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::outbox::OutboxCarrier;

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

    /// The events gate open for this thread, and what raven-core notes on
    /// it kept. Shut again on drop.
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

        /// The events noted so far.
        pub(crate) fn events(&self) -> Vec<SecEvent> {
            CAPTURE.with(|c| c.borrow().clone().unwrap_or_default())
        }

        /// The events noted so far, times left out (what a test compares).
        pub(crate) fn kinds(&self) -> Vec<(SecKind, Attribution, Via)> {
            self.events()
                .iter()
                .map(|e| (e.kind, e.who, e.via))
                .collect()
        }

        /// Forget what was noted so far.
        pub(crate) fn clear(&self) {
            CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            CAPTURE.with(|c| *c.borrow_mut() = None);
            security_gate::set_lab_for_this_thread(SecGate::Events, None);
        }
    }

    /// Shut for this thread whatever the variables say (the suite's lab
    /// run sets them for every thread): what a test of the shut gate runs
    /// under. Back to the variables on drop.
    pub(crate) struct Shut(());

    impl Shut {
        pub(crate) fn start() -> Self {
            security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
            CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
            Self(())
        }

        pub(crate) fn noted(&self) -> usize {
            CAPTURE.with(|c| c.borrow().as_ref().map_or(0, Vec::len))
        }
    }

    impl Drop for Shut {
        fn drop(&mut self) {
            CAPTURE.with(|c| *c.borrow_mut() = None);
            security_gate::set_lab_for_this_thread(SecGate::Events, None);
        }
    }

    /// The responses gate open for this thread too, on a [`Capture`] (the
    /// events gate it sits on); `None` in a release build. Both shut again
    /// on drop (step P6.28's tests).
    pub(crate) struct Responses(pub(crate) Capture);

    impl Responses {
        pub(crate) fn on() -> Option<Self> {
            let capture = Capture::start()?;
            security_gate::set_lab_for_this_thread(SecGate::Responses, Some(true));
            Some(Self(capture))
        }
    }

    impl Drop for Responses {
        fn drop(&mut self) {
            security_gate::set_lab_for_this_thread(SecGate::Responses, None);
        }
    }

    const PEER: [u8; 32] = [0x5E; 32];
    const CUSTODIAN: [u8; 32] = [0xC0; 32];

    #[test]
    fn store_refusals_are_the_contacts_the_custodians_or_local() {
        use IndexedSessionStoreError as E;
        let link = Via::DirectLink(OutboxCarrier::Lan);
        let served = Via::Custodian(CUSTODIAN);
        let contact = Attribution::Contact { peer: PEER };
        let custodian = Attribution::Carrier {
            carrier: CUSTODIAN,
            role: CarrierRole::Custodian,
        };
        for (e, via, want) in [
            (
                E::AuthenticationFailed,
                link,
                Some((SecKind::ObjectAuthFail, contact)),
            ),
            (
                E::AuthenticationFailed,
                served,
                Some((SecKind::ObjectAuthFail, contact)),
            ),
            (
                E::OuterSignatureInvalid,
                served,
                Some((SecKind::CustodianBadObject, custodian)),
            ),
            (
                E::Replay,
                served,
                Some((SecKind::CustodianReplay, custodian)),
            ),
            (E::Replay, link, Some((SecKind::ObjectReplay, contact))),
            (
                E::LocalInboxAuthenticationFailed,
                link,
                Some((SecKind::LocalRollback, Attribution::Local)),
            ),
            // Noted by the store where it finds it, never twice.
            (E::RollbackDetected, link, None),
            (
                E::RouteTagMismatch,
                link,
                Some((SecKind::SessionUnknown, contact)),
            ),
            (E::NotFound, link, None),
        ] {
            assert_eq!(store_event(&e, via, None, &PEER), want, "{e:?} {via:?}");
        }
        assert_eq!(
            store_event(
                &E::EndpointNotCurrentlyValid,
                link,
                Some(PeerClock::Ahead(600_000)),
                &PEER
            ),
            Some((SecKind::ClockSkew, contact))
        );
    }

    #[test]
    fn a_shut_gate_notes_nothing_and_an_inner_note_is_dropped() {
        {
            let shut = Shut::start();
            contact(SecKind::ObjectAuthFail, &PEER, Via::Local);
            local(SecKind::LocalRollback);
            store_refusal(
                &IndexedSessionStoreError::AuthenticationFailed,
                Via::Local,
                None,
                &PEER,
            );
            assert_eq!(shut.noted(), 0);
        }
        let Some(cap) = Capture::start() else {
            return;
        };
        // A sink that reaches a sensing point on the noting thread: the
        // inner note is dropped, the outer one kept.
        NOTING.with(|n| n.set(true));
        local(SecKind::LocalRollback);
        NOTING.with(|n| n.set(false));
        assert!(cap.kinds().is_empty());
        local(SecKind::LocalRollback);
        assert_eq!(
            cap.kinds(),
            vec![(SecKind::LocalRollback, Attribution::Local, Via::Local)]
        );
        // A local refusal seen by a link is noted as local, not via the link.
        cap.clear();
        store_refusal(
            &IndexedSessionStoreError::LocalInboxAuthenticationFailed,
            Via::DirectLink(OutboxCarrier::Lan),
            None,
            &PEER,
        );
        assert_eq!(
            cap.kinds(),
            vec![(SecKind::LocalRollback, Attribution::Local, Via::Local)]
        );
    }

    /// The step's acceptance: with the events gate shut no sensing point
    /// creates a ledger, not even with ash's direct sink handed an event;
    /// with it open, what a scenario notes becomes exactly the expected
    /// ledger rows (one alert and one day count per kind and subject).
    #[test]
    fn a_shut_gate_creates_no_ledger_and_an_open_one_keeps_exactly_the_events() {
        use crate::security_events::{Aggregator, SecSink, Severity};
        use crate::security_ledger::{ledger_path, DirectSink, LedgerSubject, SecurityLedger};
        let dir = crate::contact_book::tests::profile();
        crate::contact_book::tests::seal(dir.path());
        let scenario = || {
            contact(
                SecKind::ObjectAuthFail,
                &PEER,
                Via::DirectLink(OutboxCarrier::Lan),
            );
            store_refusal(
                &IndexedSessionStoreError::AuthenticationFailed,
                Via::Dial(OutboxCarrier::Internet),
                None,
                &PEER,
            );
            carrier(
                SecKind::CustodianUnrequested,
                &CUSTODIAN,
                CarrierRole::Custodian,
                Via::Custodian(CUSTODIAN),
            );
            local(SecKind::LocalRollback);
            // Noted where the store finds it, not here.
            store_refusal(
                &IndexedSessionStoreError::RollbackDetected,
                Via::DirectLink(OutboxCarrier::Lan),
                None,
                &PEER,
            );
        };
        let sink = DirectSink::new(dir.path());
        {
            let shut = Shut::start();
            scenario();
            assert_eq!(shut.noted(), 0);
            sink.accept(
                &SecEvent::new(
                    SecKind::ObjectAuthFail,
                    Attribution::Contact { peer: PEER },
                    Via::Local,
                    now_ms(),
                ),
                Severity::Suspicious,
            );
            sink.flush();
            assert!(!ledger_path(dir.path()).exists(), "no ledger while shut");
        }
        let Some(cap) = Capture::start() else {
            return;
        };
        scenario();
        let mut severities = Aggregator::new();
        for ev in cap.events() {
            sink.accept(&ev, severities.record(&ev));
        }
        sink.flush();
        assert_eq!(sink.failures(), 0);
        let ledger = SecurityLedger::open(dir.path()).unwrap();
        let mut alerts: Vec<(SecKind, Option<LedgerSubject>, u64)> = ledger
            .open_alerts()
            .unwrap()
            .into_iter()
            .map(|a| (a.kind, a.subject, a.n))
            .collect();
        alerts.sort_by_key(|(kind, ..)| *kind);
        let custodian = LedgerSubject::Carrier {
            key: CUSTODIAN,
            role: CarrierRole::Custodian,
        };
        assert_eq!(
            alerts,
            vec![
                (
                    SecKind::ObjectAuthFail,
                    Some(LedgerSubject::Contact(PEER)),
                    2
                ),
                (SecKind::CustodianUnrequested, Some(custodian), 1),
                (SecKind::LocalRollback, None, 1),
            ]
        );
        let mut counts: Vec<(SecKind, Option<LedgerSubject>, u64)> = ledger
            .counts(0)
            .unwrap()
            .into_iter()
            .map(|c| (c.kind, c.subject, c.n))
            .collect();
        counts.sort_by_key(|(kind, ..)| *kind);
        assert_eq!(counts, alerts);
    }
}
