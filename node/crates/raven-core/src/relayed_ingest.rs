//! Relayed ingest (`docs/design/2026-10-friend-custody.md` §8.2, §8.3): the
//! recipient accepts an object it fetched from a custodian, under exactly the
//! session the store tag names, with the same checks and the same store calls
//! as a link delivery. Its ACK is durably owed before the object is released.
//!
//! Order (errata rule 5): size → strict decode → TTL → contact → outer
//! signature (cheap, before any protected load) → owed-ACK room → session-
//! bound certificate → AEAD → commit → owed ACK.

use std::path::Path;

use crate::carrier_admission::{admit_relayable, CustodyRefusal};
use crate::envelope::{EnvType, Envelope};
use crate::identity::Identity;
use crate::indexed_session_store::{
    AuthorizedEndpointDevice, EndpointAcceptance, EndpointAckAcceptance, IndexedSessionRecordKey,
    IndexedSessionStore, IndexedSessionStoreError,
};
use crate::outbox::{contact_admission, ContactAdmission};
use crate::owed_acks::{Origin, OwedAcks, OwedError};
use crate::security_events::{classify_relayed, classify_store_error, SecKind, Via};
use crate::store_object::StoreObject;

/// Where a fetched object was filed: its sender, and the one session its tag
/// names (from the recipient's own reverse tag map).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHint {
    pub record_key: IndexedSessionRecordKey,
    pub peer_device: [u8; 32],
    pub store_tag: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryScope {
    /// Keep this object; try it again on a later fetch.
    Item,
    /// Leave this sender's objects for now (per-peer backoff).
    Peer,
    /// Stop this fetch round (store-wide trouble).
    Store,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayedOutcome {
    MessageAccepted {
        peer: [u8; 32],
        message_id: [u8; 16],
        duplicate: bool,
        /// It carried a group frame (a group copy).
        group: bool,
    },
    AckAccepted {
        peer: [u8; 32],
        acked_message_id: [u8; 16],
    },
    /// Permanent for this recipient: release (hide) it at the custodian.
    Refused(&'static str),
    /// Keep it at the custodian; no history, no ACK.
    Retry(RetryScope, &'static str),
}

impl RelayedOutcome {
    /// Released at the custodian after this outcome.
    pub fn releases(&self) -> bool {
        !matches!(self, Self::Retry(..))
    }
}

/// The security event a store refusal of a served object is (Phase 6b S6-S11,
/// S23): the kind [`classify_store_error`] gives it for an object a
/// custodian served (the custodian's key does not change the kind: the fetch
/// round knows whose it is, [`crate::custody_client::FetchReport`]). None
/// for `RollbackDetected`: the store notes it where it finds it.
fn served_kind(error: &IndexedSessionStoreError) -> Option<SecKind> {
    if matches!(error, IndexedSessionStoreError::RollbackDetected) {
        return None;
    }
    classify_store_error(error, Via::Custodian([0; 32]))
}

/// §8.3: a typed store error as an outcome, with the security event it is
/// ([`served_kind`]).
fn classify(
    error: &IndexedSessionStoreError,
    env: &Envelope,
    now_ms: u64,
) -> (RelayedOutcome, Option<SecKind>) {
    (classify_outcome(error, env, now_ms), served_kind(error))
}

fn classify_outcome(
    error: &IndexedSessionStoreError,
    env: &Envelope,
    now_ms: u64,
) -> RelayedOutcome {
    use IndexedSessionStoreError as E;
    match error {
        E::AuthenticationFailed
        | E::OuterSignatureInvalid
        | E::DeviceBindingMismatch
        | E::InvalidDeviceCertificate
        | E::RevokedDevice
        | E::LogicalMessageConflict
        | E::InvalidIndexedMessage
        | E::InvalidEndpointEnvelope
        | E::EndpointTypeMismatch
        | E::InvalidEndpointPayload
        | E::DeviceHintMismatch
        | E::RouteTagMismatch
        | E::Replay
        | E::SessionNotConfirmed
        | E::BindingConflict
        | E::IndexExhausted
        | E::AckOutstandingMismatch
        | E::AckTimestampMismatch
        | E::AckInnerSignatureInvalid
        | E::AckNonceConflict => RelayedOutcome::Refused("CUSTODY_REFUSED"),
        E::EndpointNotCurrentlyValid if env.expires_at <= now_ms => {
            RelayedOutcome::Refused("ENVELOPE_EXPIRED")
        }
        // A session an early security re-key closed takes no new object
        // again: released, never served again until it expires. The
        // contact's own copy comes back re-sealed (Phase 6 review
        // sensing-1). No event (the store's classification).
        E::SessionRetired => RelayedOutcome::Refused("SESSION_RETIRED"),
        E::Sqlite(_)
        | E::ProtectedStore(_)
        | E::CorruptProtectedState
        | E::CorruptEndpointState
        | E::ProtectedStateMissing
        | E::RollbackDetected => RelayedOutcome::Retry(RetryScope::Store, "STORE"),
        // Clock behind or before session start; a forward jump that shrinks
        // once earlier objects arrive; a busy lane; anything else: keep it.
        _ => RelayedOutcome::Retry(RetryScope::Item, "RETRY"),
    }
}

/// Accept one fetched object (Bob's side).
pub fn ingest_relayed_object(
    data_dir: &Path,
    identity: &Identity,
    object: &StoreObject,
    hint: &RelayHint,
    now_ms: u64,
) -> RelayedOutcome {
    ingest_relayed(data_dir, identity, object, hint, now_ms, &mut None)
}

/// [`ingest_relayed_object`] with the security event its refusal is
/// (Phase 6b S6-S11, S18): junk before the contact's signature (malformed,
/// another tag, a shape or hop fields the custodian's own admission
/// refuses, an outer signature that fails) is
/// [`SecKind::CustodianBadObject`]; a store refusal after it is
/// [`served_kind`]'s (so `CUSTODY_REFUSED` is split by where it came from).
/// Clock skew is not one here: the envelope dated in our future was not
/// verified yet. The caller attributes it (the custodian for its kinds,
/// else the contact `hint` names).
pub fn ingest_relayed_object_sensed(
    data_dir: &Path,
    identity: &Identity,
    object: &StoreObject,
    hint: &RelayHint,
    now_ms: u64,
) -> (RelayedOutcome, Option<SecKind>) {
    let mut event = None;
    let outcome = ingest_relayed(data_dir, identity, object, hint, now_ms, &mut event);
    (outcome, event)
}

/// A refusal of junk a custodian served (before any signature vouched for
/// it): [`SecKind::CustodianBadObject`] kept in `event`.
fn served_junk(outcome: RelayedOutcome, event: &mut Option<SecKind>) -> RelayedOutcome {
    *event = Some(SecKind::CustodianBadObject);
    outcome
}

/// Steps 1-3, then [`ingest_envelope_sensed`]; `event`: as for
/// [`ingest_relayed_object_sensed`].
fn ingest_relayed(
    data_dir: &Path,
    identity: &Identity,
    object: &StoreObject,
    hint: &RelayHint,
    now_ms: u64,
    event: &mut Option<SecKind>,
) -> RelayedOutcome {
    // 1. Size and strict decode.
    let Ok(rso1) = object.pack() else {
        return served_junk(RelayedOutcome::Refused("CUSTODY_MALFORMED"), event);
    };
    let Ok((object, env)) = crate::friend_custody::check_rfc1_rso1(&rso1) else {
        return served_junk(RelayedOutcome::Refused("CUSTODY_MALFORMED"), event);
    };
    if object.store_tag != hint.store_tag {
        return served_junk(RelayedOutcome::Refused("CUSTODY_MALFORMED"), event);
    }
    let packed = &object.packed_envelope;
    // 2. TTL and shape (PairInit never enters).
    match admit_relayable(packed, now_ms) {
        Ok(_) => {}
        Err(CustodyRefusal::Expired) => return RelayedOutcome::Refused("ENVELOPE_EXPIRED"),
        Err(CustodyRefusal::FromTheFuture) => {
            return RelayedOutcome::Retry(RetryScope::Item, "CLOCK")
        }
        Err(_) => return served_junk(RelayedOutcome::Refused("CUSTODY_REFUSED"), event),
    }
    // 3. Canonical hop fields.
    if !crate::friend_custody::canonical_outbound_fields(&env) {
        return served_junk(RelayedOutcome::Refused("CUSTODY_REFUSED"), event);
    }
    ingest_envelope_sensed(
        data_dir,
        identity,
        packed,
        &env,
        hint,
        AckLife::Link,
        now_ms,
        event,
    )
}

/// How long the ACK owed for an accepted message may live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AckLife {
    /// As on a link: at most `ENVELOPE_VALIDITY_MS` (24 h) and the session.
    Link,
    /// Until the session ends (at most `MAX_ENDPOINT_ENVELOPE_LIFETIME_MS`):
    /// a letter session's ACKs travel back in a REPLY letter that may wait
    /// days at a custodian (`RAVEN_ASYNC_LETTER_V1.md` §8).
    Session,
}

/// Steps 4-9 for one envelope whose shape and hop fields its carrier
/// checked: the same checks and store calls as a link delivery, under the
/// one session `hint` names. Relayed ingest runs it for a fetched object,
/// the letter intake ([`crate::async_letter::intake`]) for each envelope a
/// letter carries.
pub(crate) fn ingest_envelope(
    data_dir: &Path,
    identity: &Identity,
    packed: &[u8],
    env: &Envelope,
    hint: &RelayHint,
    ack_life: AckLife,
    now_ms: u64,
) -> RelayedOutcome {
    ingest_envelope_sensed(
        data_dir, identity, packed, env, hint, ack_life, now_ms, &mut None,
    )
}

/// [`ingest_envelope`] that keeps the security event its refusal is in
/// `event` (as for [`ingest_relayed_object_sensed`]).
#[allow(clippy::too_many_arguments)]
fn ingest_envelope_sensed(
    data_dir: &Path,
    identity: &Identity,
    packed: &[u8],
    env: &Envelope,
    hint: &RelayHint,
    ack_life: AckLife,
    now_ms: u64,
    event: &mut Option<SecKind>,
) -> RelayedOutcome {
    // 4. The sender is a current, pinned contact.
    let peer = hint.peer_device;
    match contact_admission(data_dir, &peer) {
        ContactAdmission::Allowed(c) if c.pinned => {}
        ContactAdmission::Allowed(_) => return RelayedOutcome::Refused("CONTACT_NOT_VERIFIED"),
        ContactAdmission::NotContact => return RelayedOutcome::Refused("SENDER_NOT_CONTACT"),
        ContactAdmission::Blocked => return RelayedOutcome::Refused("SENDER_BLOCKED"),
        ContactAdmission::Unreadable => {
            return RelayedOutcome::Retry(RetryScope::Store, "CONTACTS_UNREADABLE")
        }
    }
    // 5. Cheap outer-signature pre-check before any protected load: junk
    //    another depositor filed under a known tag ends here.
    if !env.verify(&peer) {
        let refused = RelayedOutcome::Refused("OUTER_SIGNATURE_INVALID");
        *event = classify_relayed(&refused);
        return refused;
    }
    let is_message = env.env_type == EnvType::Message as u8;
    // 6. Message only: room to owe its ACK (back-pressure otherwise).
    let mut owed = None;
    if is_message {
        match OwedAcks::open(data_dir) {
            Ok((store, _)) => match store.has_room(&peer) {
                Ok(true) => owed = Some(store),
                Ok(false) => return RelayedOutcome::Retry(RetryScope::Peer, "OWED_ACK_FULL"),
                Err(_) => return RelayedOutcome::Retry(RetryScope::Store, "OWED_ACKS_UNAVAILABLE"),
            },
            Err(_) => return RelayedOutcome::Retry(RetryScope::Store, "OWED_ACKS_UNAVAILABLE"),
        }
    }
    // 7. The certificate bound into the hinted session.
    let mut store = match IndexedSessionStore::open(data_dir) {
        Ok(store) => store,
        Err(_) => return RelayedOutcome::Retry(RetryScope::Store, "STORE"),
    };
    let cert = match crate::lan_dispatch::session_bound_peer_certificate(
        data_dir,
        &mut store,
        &hint.record_key,
        &peer,
    ) {
        Ok(Some(cert)) => cert,
        Ok(None) => return RelayedOutcome::Retry(RetryScope::Peer, "NO_PEER_CERT"),
        Err(_) => return RelayedOutcome::Retry(RetryScope::Store, "STORE"),
    };
    // Lineage: the same predicate link delivery uses for the sender.
    let revoked = match crate::outbox::peer_lineage_denied(data_dir, &cert) {
        Ok(v) => v,
        Err(_) => return RelayedOutcome::Retry(RetryScope::Store, "STORE"),
    };
    if is_message {
        accept_message(
            data_dir,
            identity,
            &mut store,
            owed.as_mut().expect("opened above"),
            hint,
            &cert,
            revoked,
            packed,
            env,
            ack_life,
            now_ms,
            event,
        )
    } else {
        // 9. ACK: the same store call and settlement as an ACK on a link.
        match store.accept_ack_envelope(&hint.record_key, packed, &cert, revoked, now_ms) {
            Ok(EndpointAckAcceptance::Committed {
                session_id,
                acked_message_id,
                ..
            })
            | Ok(EndpointAckAcceptance::Duplicate {
                session_id,
                acked_message_id,
                ..
            }) => {
                let _ = crate::outbox::record_outbound_delivered(
                    data_dir,
                    &mut store,
                    &peer,
                    &session_id,
                    &acked_message_id,
                );
                RelayedOutcome::AckAccepted {
                    peer,
                    acked_message_id,
                }
            }
            Err(e) => sensed(classify(&e, env, now_ms), event),
        }
    }
}

/// §8.2 step 8: accept, history (fail closed), then the ACK owed durably.
#[allow(clippy::too_many_arguments)]
fn accept_message(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    owed: &mut OwedAcks,
    hint: &RelayHint,
    cert: &crate::device_cert::DeviceCertificate,
    revoked: bool,
    packed: &[u8],
    env: &Envelope,
    ack_life: AckLife,
    now_ms: u64,
    event: &mut Option<SecKind>,
) -> RelayedOutcome {
    let peer = hint.peer_device;
    let key = &hint.record_key;
    // The same application policy and delivery as a direct link (app
    // channel §7.2, CORE-13): the session-bound certificate, never a bundle.
    let mut policy = |plaintext: &[u8]| {
        crate::app_channel::inbound_policy(data_dir, &peer, &env.message_id, plaintext)
    };
    let accepted = match store.accept_message_envelope_with_policy(
        key,
        packed,
        cert,
        revoked,
        now_ms,
        &mut policy,
    ) {
        Ok(a) => a,
        // Nothing committed: keep it at the custodian and try again later.
        Err(e) if crate::app_channel::is_deferred(&e) => {
            return RelayedOutcome::Retry(RetryScope::Item, "APP_DEFERRED")
        }
        Err(e) => {
            crate::lan_dispatch::note_message_id_conflict(data_dir, &e, &peer, &env.message_id);
            return sensed(classify(&e, env, now_ms), event);
        }
    };
    // The copy carried a group frame (the custody fetch line counts those
    // apart, E2 r9).
    let mut group = false;
    let (session_id, digest, message_id, duplicate) = match &accepted {
        EndpointAcceptance::Committed {
            session_id,
            object_digest,
            message_id,
            plaintext,
            received_at_ms,
        } => {
            // From a keeper (E2 r9): the group store keeps it with a group
            // message, the inbox and the log learn it.
            let delivered =
                crate::arrivals::during(Some(crate::arrivals::ArrivedVia::Keeper), || {
                    crate::app_channel::deliver_committed(
                        data_dir,
                        store,
                        key,
                        &peer,
                        message_id,
                        now_ms,
                        *received_at_ms,
                        plaintext,
                    )
                });
            match delivered {
                Ok(true) => {}
                Ok(false) => return RelayedOutcome::Retry(RetryScope::Item, "APP_INBOX"),
                Err(_) => return RelayedOutcome::Retry(RetryScope::Item, "HISTORY"),
            }
            group = crate::group::is_group_text(plaintext);
            crate::arrivals::note(crate::arrivals::Arrival {
                sender: cert.user_ed_pub,
                message_id: *message_id,
                via: crate::arrivals::ArrivedVia::Keeper,
                at_ms: *received_at_ms,
                group,
            });
            (*session_id, *object_digest, *message_id, false)
        }
        EndpointAcceptance::Duplicate {
            session_id,
            object_digest,
            message_id,
        } => {
            match store.load_endpoint_inbox(key, object_digest) {
                Ok(Some(row)) => {
                    group = crate::group::is_group_text(&row.plaintext);
                    match crate::app_channel::deliver_committed(
                        data_dir,
                        store,
                        key,
                        &peer,
                        message_id,
                        row.created_at_ms,
                        row.received_at_ms,
                        &row.plaintext,
                    ) {
                        Ok(true) => {}
                        Ok(false) => return RelayedOutcome::Retry(RetryScope::Item, "APP_INBOX"),
                        Err(_) => return RelayedOutcome::Retry(RetryScope::Item, "HISTORY"),
                    }
                }
                // Deleted by the user (PP.8): delivered, so it is answered
                // and never fetched again; nothing is shown.
                Ok(None) => match store.inbox_row_deleted(session_id, object_digest) {
                    Ok(true) => {}
                    Ok(false) => return RelayedOutcome::Retry(RetryScope::Item, "HISTORY"),
                    Err(_) => return RelayedOutcome::Retry(RetryScope::Store, "STORE"),
                },
                Err(e) => return sensed(classify(&e, env, now_ms), event),
            }
            (*session_id, *object_digest, *message_id, true)
        }
    };
    let (local_cert, registry) = match crate::device_cert::ensure_local_device_certificate(
        data_dir,
        identity,
        crate::paths::PRIMARY_DEVICE_ID,
    ) {
        Ok(v) => v,
        Err(_) => return RelayedOutcome::Retry(RetryScope::Store, "LOCAL_DEVICE"),
    };
    let device = match AuthorizedEndpointDevice::authorize(&local_cert, identity, &registry, now_ms)
    {
        Ok(d) => d,
        Err(_) => return RelayedOutcome::Retry(RetryScope::Store, "LOCAL_DEVICE"),
    };
    let ack_expires = match store
        .session_expires_at(key)
        .map_err(|_| ())
        .and_then(|end| match ack_life {
            AckLife::Link => crate::outbox::envelope_expires_at(now_ms, end).map_err(|_| ()),
            AckLife::Session => {
                let until = end.min(now_ms.saturating_add(
                    crate::indexed_session_store::MAX_ENDPOINT_ENVELOPE_LIFETIME_MS,
                ));
                if until > now_ms {
                    Ok(until)
                } else {
                    Err(())
                }
            }
        }) {
        Ok(v) => v,
        Err(()) => return RelayedOutcome::Retry(RetryScope::Item, "SESSION_ENDING"),
    };
    let mut recorded = false;
    let mut owed_error = None;
    let mut rng = rand::rngs::OsRng;
    let result = store.enqueue_committed_ack(
        key,
        &digest,
        &device,
        now_ms,
        ack_expires,
        now_ms,
        &mut rng,
        &mut |d: &[u8; 32], bytes: &[u8]| match owed.record(
            &peer,
            Some(session_id),
            d,
            bytes,
            ack_expires,
            Origin::Relayed,
            now_ms,
        ) {
            Ok(()) => {
                recorded = true;
                Ok(*d)
            }
            Err(e) => {
                owed_error = Some(e);
                Err(())
            }
        },
    );
    match result {
        Ok(row) => {
            // A Queued intent returns without running the callback: owe it now.
            if !recorded
                && owed
                    .record(
                        &peer,
                        Some(session_id),
                        &row.object_digest,
                        &row.immutable_envelope_bytes,
                        ack_expires,
                        Origin::Relayed,
                        now_ms,
                    )
                    .is_err()
            {
                return RelayedOutcome::Retry(RetryScope::Item, "OWED_ACK_WRITE");
            }
            RelayedOutcome::MessageAccepted {
                peer,
                message_id,
                duplicate,
                group,
            }
        }
        Err(_) if matches!(owed_error, Some(OwedError::Full)) => {
            RelayedOutcome::Retry(RetryScope::Peer, "OWED_ACK_FULL")
        }
        // The ACK row stays Prepared: the worker pushes or deposits it.
        Err(IndexedSessionStoreError::OutboundQueueHandoff) => {
            RelayedOutcome::Retry(RetryScope::Item, "OWED_ACK_WRITE")
        }
        Err(e) => sensed(classify(&e, env, now_ms), event),
    }
}

/// The outcome of a [`classify`]d refusal, its event kept in `event`.
fn sensed(
    (outcome, kind): (RelayedOutcome, Option<SecKind>),
    event: &mut Option<SecKind>,
) -> RelayedOutcome {
    *event = kind;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexed_session_store::{fetch_days, MailboxDirection};
    use crate::lan_dispatch::{
        cache_peer_bundle, create_initiator_pair_init, dispatch_frame, local_bundle, wrap_pair_init,
    };
    use crate::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};

    /// Raven's clock, as the code under test reads it (the suite may run on
    /// a lab clock).
    fn now() -> u64 {
        crate::clock::now_ms()
    }

    fn contacts(dir: &Path, entries: &[(&Identity, &str, bool)]) {
        let rows: Vec<String> = entries
            .iter()
            .map(|(id, name, pinned)| {
                format!(
                    r#"{{"petname":"{name}","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":{pinned},"lan_dial":"192.168.1.9:7420","internet_dial":""}}"#,
                    hex::encode(id.public_key_bytes())
                )
            })
            .collect();
        std::fs::write(dir.join("contacts.json"), format!("[{}]", rows.join(","))).unwrap();
    }

    /// Alice and Bob, mutual pinned contacts with a confirmed session that
    /// Alice initiated. Returns (alice key, bob key).
    struct Pair {
        alice: Identity,
        bob: Identity,
        a: tempfile::TempDir,
        b: tempfile::TempDir,
        a_key: IndexedSessionRecordKey,
    }

    fn pair(seed: u8) -> Pair {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let (alice, bob) = (
            Identity::from_seed(&[seed; 32]),
            Identity::from_seed(&[seed.wrapping_add(1); 32]),
        );
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let a_bundle = local_bundle(a.path(), &alice).unwrap();
        let b_bundle = local_bundle(b.path(), &bob).unwrap();
        contacts(a.path(), &[(&bob, "Bob", true)]);
        contacts(b.path(), &[(&alice, "Alice", true)]);
        cache_peer_bundle(a.path(), &b_bundle).unwrap();
        cache_peer_bundle(b.path(), &a_bundle).unwrap();
        let (init, a_key) = create_initiator_pair_init(a.path(), &alice, &b_bundle).unwrap();
        let replies = dispatch_frame(
            b.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &wrap_pair_init(&alice, &init).unwrap(),
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!()
        };
        IndexedSessionStore::open(a.path())
            .unwrap()
            .confirm_verified_pair_response(
                &a_key,
                &init,
                &crate::pair_init::decode_response(&wire).unwrap(),
                now(),
            )
            .unwrap();
        Pair {
            alice,
            bob,
            a,
            b,
            a_key,
        }
    }

    impl Pair {
        fn seal(&self, text: &str) -> Vec<u8> {
            let mut store = IndexedSessionStore::open(self.a.path()).unwrap();
            let (cert, reg) = crate::device_cert::ensure_local_device_certificate(
                self.a.path(),
                &self.alice,
                crate::paths::PRIMARY_DEVICE_ID,
            )
            .unwrap();
            let device =
                AuthorizedEndpointDevice::authorize(&cert, &self.alice, &reg, now()).unwrap();
            let t = now();
            let end = store.session_expires_at(&self.a_key).unwrap();
            let expires = crate::outbox::envelope_expires_at(t, end).unwrap();
            let mut out = None;
            store
                .send_message_envelope(
                    &self.a_key,
                    text,
                    &device,
                    t,
                    expires,
                    t,
                    &mut rand::rngs::OsRng,
                    &mut |d, bytes| {
                        out = Some(bytes.to_vec());
                        Ok(*d)
                    },
                )
                .unwrap();
            out.unwrap()
        }

        /// Bob's view of the session (same key fields).
        fn bob_hint(&self, packed: &[u8]) -> (StoreObject, RelayHint) {
            let mut astore = IndexedSessionStore::open(self.a.path()).unwrap();
            let tag = astore
                .outbound_store_tag_for_object(&self.a_key, packed, now())
                .unwrap();
            let rso1 = crate::friend_custody::rfc1_rso1(tag, packed).unwrap();
            (
                StoreObject::unpack(&rso1).unwrap(),
                RelayHint {
                    record_key: self.a_key.clone(),
                    peer_device: self.alice.public_key_bytes(),
                    store_tag: tag,
                },
            )
        }
    }

    #[test]
    fn a_relayed_message_is_accepted_once_and_its_ack_is_owed() {
        let p = pair(0x71);
        let packed = p.seal("via a friend");
        let (object, hint) = p.bob_hint(&packed);
        // Bob's inbound tags for this session include the deposit tag.
        let mut bstore = IndexedSessionStore::open(p.b.path()).unwrap();
        let heads = bstore
            .live_session_heads(&p.bob.public_key_bytes(), now())
            .unwrap();
        assert_eq!(heads.len(), 1);
        let days = fetch_days(heads[0].created_at_ms, heads[0].expires_at_ms, now());
        let tags = bstore
            .mailbox_store_tags(&heads[0].key, MailboxDirection::Inbound, &days, now())
            .unwrap();
        assert!(tags.contains(&hint.store_tag));
        drop(bstore);
        let first = ingest_relayed_object(p.b.path(), &p.bob, &object, &hint, now());
        assert!(
            matches!(
                first,
                RelayedOutcome::MessageAccepted {
                    duplicate: false,
                    group: false,
                    ..
                }
            ),
            "{first:?}"
        );
        // E2 r9 #12: it came from a keeper, by the sender's key.
        let RelayedOutcome::MessageAccepted { message_id, .. } = first else {
            unreachable!()
        };
        let arrived = crate::arrivals::recent()
            .into_iter()
            .rev()
            .find(|a| a.message_id == message_id)
            .expect("noted");
        assert_eq!(arrived.via, crate::arrivals::ArrivedVia::Keeper);
        assert_eq!(arrived.sender, p.alice.public_key_bytes());
        assert!(!arrived.group);
        let inbox = IndexedSessionStore::open(p.b.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].plaintext, b"via a friend");
        let (mut owed, _) = OwedAcks::open(p.b.path()).unwrap();
        let list = owed.list(now()).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].peer, p.alice.public_key_bytes());
        // A second fetch of the same object: a duplicate, still one owed ACK.
        let again = ingest_relayed_object(p.b.path(), &p.bob, &object, &hint, now());
        assert!(matches!(
            again,
            RelayedOutcome::MessageAccepted {
                duplicate: true,
                ..
            }
        ));
        assert_eq!(owed.list(now()).unwrap().len(), 1);
        assert!(first.releases() && again.releases());

        // The owed ACK, relayed back the other way, settles Alice's message.
        let ack = list[0].bytes.clone();
        let mut bstore = IndexedSessionStore::open(p.b.path()).unwrap();
        let back_tag = bstore
            .outbound_store_tag_for_object(&p.a_key, &ack, now())
            .unwrap();
        let ack_object =
            StoreObject::unpack(&crate::friend_custody::rfc1_rso1(back_tag, &ack).unwrap())
                .unwrap();
        let ack_hint = RelayHint {
            record_key: p.a_key.clone(),
            peer_device: p.bob.public_key_bytes(),
            store_tag: back_tag,
        };
        let got = ingest_relayed_object(p.a.path(), &p.alice, &ack_object, &ack_hint, now());
        let env = Envelope::unpack(&packed).unwrap();
        assert_eq!(
            got,
            RelayedOutcome::AckAccepted {
                peer: p.bob.public_key_bytes(),
                acked_message_id: env.message_id
            }
        );
    }

    #[test]
    fn junk_wrong_tag_and_unverified_senders_are_refused_cheaply() {
        let p = pair(0x73);
        let packed = p.seal("x");
        let (object, hint) = p.bob_hint(&packed);
        // Wrong tag for the hint.
        let mut other = hint.clone();
        other.store_tag[0] ^= 1;
        assert_eq!(
            ingest_relayed_object(p.b.path(), &p.bob, &object, &other, now()),
            RelayedOutcome::Refused("CUSTODY_MALFORMED")
        );
        // Re-signed by someone else under the right tag.
        let mut env = Envelope::unpack(&packed).unwrap();
        env.sign_with(&Identity::from_seed(&[0x99; 32]));
        let junk = StoreObject::unpack(
            &crate::friend_custody::rfc1_rso1(hint.store_tag, &env.pack()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            ingest_relayed_object(p.b.path(), &p.bob, &junk, &hint, now()),
            RelayedOutcome::Refused("OUTER_SIGNATURE_INVALID")
        );
        // Phase 6b (S6, S7, S18): the event each refusal is. Junk before
        // Alice's signature vouched for it is the custodian's; Alice's own
        // signature over a changed AEAD tag is hers (the custodian could not
        // have made it).
        let sensed = |object: &StoreObject, hint: &RelayHint| {
            ingest_relayed_object_sensed(p.b.path(), &p.bob, object, hint, now())
        };
        assert_eq!(
            sensed(&object, &other),
            (
                RelayedOutcome::Refused("CUSTODY_MALFORMED"),
                Some(SecKind::CustodianBadObject)
            )
        );
        assert_eq!(
            sensed(&junk, &hint),
            (
                RelayedOutcome::Refused("OUTER_SIGNATURE_INVALID"),
                Some(SecKind::CustodianBadObject)
            )
        );
        let mut env = Envelope::unpack(&p.seal("y")).unwrap();
        *env.message_ciphertext.last_mut().unwrap() ^= 1;
        env.sign_with(&p.alice);
        let tampered = StoreObject::unpack(
            &crate::friend_custody::rfc1_rso1(hint.store_tag, &env.pack()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            sensed(&tampered, &hint),
            (
                RelayedOutcome::Refused("CUSTODY_REFUSED"),
                Some(SecKind::ObjectAuthFail)
            )
        );
        // A sender Bob has not verified.
        contacts(p.b.path(), &[(&p.alice, "Alice", false)]);
        assert_eq!(
            ingest_relayed_object(p.b.path(), &p.bob, &object, &hint, now()),
            RelayedOutcome::Refused("CONTACT_NOT_VERIFIED")
        );
        assert_eq!(
            sensed(&object, &hint),
            (RelayedOutcome::Refused("CONTACT_NOT_VERIFIED"), None)
        );
        assert!(IndexedSessionStore::open(p.b.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn clock_and_owed_table_push_back_without_accepting() {
        let p = pair(0x75);
        let packed = p.seal("later");
        let (object, hint) = p.bob_hint(&packed);
        let env = Envelope::unpack(&packed).unwrap();
        // Bob's clock far behind: kept, not refused.
        assert_eq!(
            ingest_relayed_object(
                p.b.path(),
                &p.bob,
                &object,
                &hint,
                env.created_at - 3_600_000
            ),
            RelayedOutcome::Retry(RetryScope::Item, "CLOCK")
        );
        // Past its expiry: refused (released).
        assert_eq!(
            ingest_relayed_object(p.b.path(), &p.bob, &object, &hint, env.expires_at + 1),
            RelayedOutcome::Refused("ENVELOPE_EXPIRED")
        );
        // The owed table full for Alice: back-pressure, nothing accepted.
        let (mut owed, _) = OwedAcks::open(p.b.path()).unwrap();
        for i in 0..crate::owed_acks::MAX_OWED_PER_PEER {
            let mut d = [0u8; 32];
            d[..8].copy_from_slice(&(i as u64).to_be_bytes());
            owed.record(
                &p.alice.public_key_bytes(),
                None,
                &d,
                b"ack",
                now() + 60_000,
                Origin::Link,
                now(),
            )
            .unwrap();
        }
        assert_eq!(
            ingest_relayed_object(p.b.path(), &p.bob, &object, &hint, now()),
            RelayedOutcome::Retry(RetryScope::Peer, "OWED_ACK_FULL")
        );
        assert!(IndexedSessionStore::open(p.b.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .is_empty());
    }

    /// Phase 6 review (sensing-1): an object a custodian serves under a
    /// session an early security re-key closed (retired more than ten
    /// minutes ago) is refused for good and released, never served again
    /// on every fetch until it expires; no event (the contact re-seals its
    /// own copy).
    #[test]
    fn an_object_for_a_rekey_closed_session_is_released() {
        use crate::indexed_session_store::SessionRetireCause;
        let p = pair(0x7d);
        let packed = p.seal("sealed before the re-key");
        let (object, hint) = p.bob_hint(&packed);
        let retired_at = now() - crate::session_renewal::EARLY_OLD_ACCEPT_MS - 60_000;
        assert!(IndexedSessionStore::open(p.b.path())
            .unwrap()
            .retire_session(
                &p.a_key,
                &p.alice.public_key_bytes(),
                SessionRetireCause::LocalSecurityRekey,
                retired_at,
            )
            .unwrap());
        let (outcome, event) =
            ingest_relayed_object_sensed(p.b.path(), &p.bob, &object, &hint, now());
        assert_eq!(outcome, RelayedOutcome::Refused("SESSION_RETIRED"));
        assert!(outcome.releases());
        assert_eq!(event, None);
        assert!(IndexedSessionStore::open(p.b.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .is_empty());
    }

    /// Privacy pack PP.8 (review R05): Bob deletes his chat after a relayed
    /// message was accepted, and the custodian (which never got his ACK)
    /// hands it over again. It is a delivered duplicate: answered with the
    /// ACK owed, released, and never shown; not `Retry(HISTORY)` on every
    /// fetch until it expires.
    #[test]
    fn relayed_duplicate_after_delete_is_not_retried_forever() {
        let p = pair(0x75);
        let packed = p.seal("relayed, then deleted");
        let (object, hint) = p.bob_hint(&packed);
        let first = ingest_relayed_object(p.b.path(), &p.bob, &object, &hint, now());
        assert!(matches!(
            first,
            RelayedOutcome::MessageAccepted {
                duplicate: false,
                ..
            }
        ));
        let deleted =
            crate::privacy::delete_chat(p.b.path(), &p.alice.public_key_bytes(), None).unwrap();
        assert_eq!((deleted.history, deleted.inbox.deleted), (1, 1));
        for _ in 0..2 {
            let again = ingest_relayed_object(p.b.path(), &p.bob, &object, &hint, now());
            assert!(
                matches!(
                    again,
                    RelayedOutcome::MessageAccepted {
                        duplicate: true,
                        ..
                    }
                ),
                "{again:?}"
            );
            assert!(again.releases());
        }
        let history = crate::chat_history::ChatHistory::load(p.b.path()).unwrap();
        assert!(history
            .for_peer(&hex::encode(p.alice.public_key_bytes()))
            .is_empty());
        assert!(IndexedSessionStore::open(p.b.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .is_empty());
        let (mut owed, _) = OwedAcks::open(p.b.path()).unwrap();
        assert_eq!(owed.list(now()).unwrap().len(), 1, "still one owed ACK");
    }
}
