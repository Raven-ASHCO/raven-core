//! Security notices at the PairInit and session consult points (step
//! P6.45, design D §7): a BROKEN `pairinit/1/1` refuses PairInit both ways
//! (made and taken, on a link and in a letter) and leaves the sessions
//! already open; a BROKEN session profile holds every session (nothing
//! sealed or taken, nothing changed) until the notice no longer says so.

use super::*;
use crate::advisory::{Entry, EntryKind, Severity};
use crate::security_gate::{self, SecGate};
use crate::suite_policy::{self, Policy, SUITE_BROKEN};
use crate::suite_registry as reg;

/// Notice #7 marking the suite `id` BROKEN.
fn broken(id: &str) -> Policy {
    let entry = Entry {
        kind: EntryKind::SuiteStatus,
        severity: Severity::Broken,
        target: id.to_owned(),
        arg: Vec::new(),
        text_id: 0,
    };
    Policy::of_entries(7, 0, &[entry], 0)
}

/// The advisory gate open on this thread with `policy` applied; undone on
/// drop. `None` in a release build.
struct Applied(());

impl Applied {
    fn open(policy: Policy) -> Option<Self> {
        security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
        if !security_gate::live(SecGate::Advisory) {
            security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
            return None;
        }
        suite_policy::set_policy_for_this_thread(Some(policy));
        Some(Self(()))
    }

    fn lift(&self) {
        suite_policy::set_policy_for_this_thread(Some(Policy::default()));
    }
}

impl Drop for Applied {
    fn drop(&mut self) {
        suite_policy::set_policy_for_this_thread(None);
        security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
    }
}

/// Seal `text` under `key` on `dir`'s store, or why not.
fn try_seal(
    dir: &Path,
    id: &Identity,
    key: &IndexedSessionRecordKey,
    text: &str,
) -> Result<Vec<u8>, IndexedSessionStoreError> {
    let mut store = IndexedSessionStore::open(dir).unwrap();
    let (cert, reg) = ensure_local_device_certificate(dir, id, PRIMARY_DEVICE_ID).unwrap();
    let device = AuthorizedEndpointDevice::authorize(&cert, id, &reg, now()).unwrap();
    let t = now();
    let expires = envelope_expires(t, store.session_expires_at(key).unwrap()).unwrap();
    let mut queued = None;
    store.send_message_envelope(
        key,
        text,
        &device,
        t,
        expires,
        t,
        &mut OsRng,
        &mut |digest, bytes| {
            queued = Some(bytes.to_vec());
            Ok(*digest)
        },
    )?;
    Ok(queued.unwrap())
}

fn record_keys(dir: &Path) -> usize {
    IndexedSessionStore::open(dir)
        .unwrap()
        .list_record_keys()
        .unwrap()
        .len()
}

#[test]
fn a_broken_pair_init_is_refused_both_ways_and_open_sessions_go_on() {
    let alice = Identity::from_seed(&[0xa7; 32]);
    let bob = Identity::from_seed(&[0xa8; 32]);
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (a_dir.path(), b_dir.path());
    publish_and_install(a, &alice);
    publish_and_install(b, &bob);
    let (a_bundle, b_bundle) = confirm_alice_to_bob(a, b, &alice, &bob);
    let key = IndexedSessionStore::open(a)
        .unwrap()
        .find_confirmed_session_for_peer_at(&bob.public_key_bytes(), now())
        .unwrap()
        .unwrap();
    // Bob's PairInit to Alice, made before the notice.
    let (init_b, _) = create_initiator_pair_init(b, &bob, &a_bundle).unwrap();
    let frame_b = wrap_pair_init(&bob, &init_b).unwrap();
    let Some(_applied) = Applied::open(broken(reg::PAIRINIT_V1_SUITE1)) else {
        return;
    };
    let refused = suite_policy::pair_init_refused_text(7);
    assert!(refused.starts_with(SUITE_BROKEN));
    // Made: refused on a link and in a letter; nothing stored.
    let sessions = record_keys(a);
    assert_eq!(
        create_initiator_pair_init(a, &alice, &b_bundle).unwrap_err(),
        refused
    );
    assert_eq!(
        create_letter_pair_init(a, &alice, &b_bundle).unwrap_err(),
        refused
    );
    assert_eq!(record_keys(a), sessions);
    // Taken: refused from a link and from a letter (the shared core).
    let err = dispatch_frame(a, &alice, &b_bundle, &bob.public_key_bytes(), &frame_b).unwrap_err();
    assert!(err.contains(&refused), "{err}");
    assert_eq!(
        accept_pair_init_core(a, &alice, &b_bundle, &init_b, PairOrigin::Letter, now())
            .unwrap_err(),
        PairAcceptError::Refused(refused.clone())
    );
    assert_eq!(record_keys(a), sessions);
    // The session already open goes on, both ways: a message, its ACK.
    let packed = try_seal(a, &alice, &key, "still here").unwrap();
    let replies = dispatch_frame(b, &bob, &a_bundle, &alice.public_key_bytes(), &packed)
        .expect("an open session still takes messages");
    assert_eq!(replies.len(), 1);
    IndexedSessionStore::open(a)
        .unwrap()
        .accept_ack_envelope(&key, &replies[0], &b_bundle.cert, false, now())
        .expect("and its ACK");
}

#[test]
fn a_broken_session_profile_holds_every_session_until_lifted() {
    let alice = Identity::from_seed(&[0xa9; 32]);
    let bob = Identity::from_seed(&[0xaa; 32]);
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (a_dir.path(), b_dir.path());
    publish_and_install(a, &alice);
    publish_and_install(b, &bob);
    let (a_bundle, b_bundle) = confirm_alice_to_bob(a, b, &alice, &bob);
    let key = IndexedSessionStore::open(a)
        .unwrap()
        .find_confirmed_session_for_peer_at(&bob.public_key_bytes(), now())
        .unwrap()
        .unwrap();
    let before = try_seal(a, &alice, &key, "sealed before").unwrap();
    for id in [reg::ATSAM_INDEXED_SESSION_V1, reg::RVNA1_V3] {
        let Some(applied) = Applied::open(broken(id)) else {
            return;
        };
        // Nothing sealed: no new outbox row, no ratchet step.
        let pending = IndexedSessionStore::open(a)
            .unwrap()
            .pending_endpoint_outbound()
            .unwrap()
            .len();
        assert!(matches!(
            try_seal(a, &alice, &key, "held"),
            Err(IndexedSessionStoreError::SuiteHeld)
        ));
        assert_eq!(
            IndexedSessionStore::open(a)
                .unwrap()
                .pending_endpoint_outbound()
                .unwrap()
                .len(),
            pending
        );
        // Nothing taken: the message sealed before waits, unstored.
        let inbox = || {
            IndexedSessionStore::open(b)
                .unwrap()
                .list_endpoint_inbox()
                .unwrap()
                .len()
        };
        let taken = inbox();
        let err =
            dispatch_frame(b, &bob, &a_bundle, &alice.public_key_bytes(), &before).unwrap_err();
        assert_eq!(err, IndexedSessionStoreError::SuiteHeld.to_string());
        assert!(err.starts_with("SUITE_HELD: "), "{err}");
        assert_eq!(inbox(), taken);
        // Lifted (a later notice no longer says so): it goes on as before.
        applied.lift();
        let next = try_seal(a, &alice, &key, id).unwrap();
        assert_eq!(
            dispatch_frame(b, &bob, &a_bundle, &alice.public_key_bytes(), &next)
                .unwrap()
                .len(),
            1
        );
    }
    let replies = dispatch_frame(b, &bob, &a_bundle, &alice.public_key_bytes(), &before)
        .expect("the message held is taken once lifted");
    IndexedSessionStore::open(a)
        .unwrap()
        .accept_ack_envelope(&key, &replies[0], &b_bundle.cert, false, now())
        .unwrap();
}
