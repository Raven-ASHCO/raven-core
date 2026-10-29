//! RAL1 intake (Phase 5b, P5.14): what the recipient of a fetched letter does
//! with it (`protocol/RAVEN_ASYNC_LETTER_V1.md` §6), fail closed, every
//! refusal a stable [`Ral1Error`] code.
//!
//! Steps 1-9 are [`super::open`]: strict decode, the recipient, the time
//! window, the pinned sender, the signature (checked before the prekey actor
//! is asked anything), the wrap DH ([`LetterKeys`]), the AEAD, the inner and
//! the stateless bindings. Then, for a LETTER (kind 1):
//!
//! 10. its PairInit through the responder's shared core
//!     ([`crate::lan_dispatch::accept_pair_init_core`] with
//!     [`PairOrigin::Letter`]: the archived bundle the PairInit names, no
//!     one-time prekey, at most 8 letter sessions per initiator, the session
//!     marked letter-class with its PairResponse kept), then each envelope by
//!     the same store calls as a fetched object
//!     ([`crate::relayed_ingest`] steps 4-9: the route tag of its index and
//!     direction is checked there, under the session's root);
//! 11. the REPLY is owed durably: the session's letter row keeps the exact
//!     PairResponse ([`IndexedSessionStore::letter_reply`]) and each accepted
//!     message's ACK is in the owed-ACK store, valid until the session ends.
//!
//! A LETTER whose session is here already (the same letter fetched again, or
//! a later letter of the same session) skips the core: its PairInit was
//! accepted and its REPLY is owed (the core's cached PairResponse lasts
//! minutes, the letter row as long as the session). For a REPLY (kind 2):
//! the PairResponse must answer one of this node's live letter sessions with
//! its sender ([`LetterRole::Initiator`]; else `LETTER_BINDING`), it confirms
//! that session (`verify_response` inside the store's confirm; the same
//! PairResponse again is a no-op), then each ACK settles its message.
//!
//! What happens to the custodian's copy follows [`LetterOutcome::releases`]:
//! released once intake committed, or at once when the letter can never
//! succeed; kept on `LETTER_CLAIM_LIMIT`, `LETTER_STORE` or when an envelope
//! asks to be tried again (a refetch is idempotent: the PairInit is not
//! claimed twice, a message already taken is a duplicate whose ACK is owed
//! again, one inbox row).

use std::path::Path;

use zeroize::Zeroizing;

use super::{open, wrap_dh_with_actor, Opened, OpenedLetter, OpenedReply, Ral1Error, Ral1Header};
use crate::envelope::{EnvType, Envelope};
use crate::friend_custody::canonical_outbound_fields;
use crate::identity::Identity;
use crate::indexed_session_store::{
    record_key_for_init, IndexedSessionRecordKey, IndexedSessionStore, IndexedSessionStoreError,
    LetterRole,
};
use crate::lan_dispatch::{accept_pair_init_core, load_cached_peer_bundle, PairOrigin};
use crate::outbox::{contact_admission, ContactAdmission};
use crate::pair_init::{decode_init, session_id};
use crate::prekey_lifecycle::PrekeyLifecycleActor;
use crate::relayed_ingest::{ingest_envelope, AckLife, RelayHint, RelayedOutcome, RetryScope};

/// Step 6's lookup: the wrap DH of a letter addressed to this device. The
/// prekey lifecycle actor answers it ([`wrap_dh_with_actor`]); tests count
/// the calls.
pub trait LetterKeys {
    /// `X25519(spk, wrap_ephemeral)` for the generation `header` names, or
    /// the refusal ([`Ral1Error::UnknownPrekey`], [`Ral1Error::Unwrap`],
    /// [`Ral1Error::Store`]).
    fn wrap_dh(&self, header: &Ral1Header, now_ms: u64) -> Result<Zeroizing<[u8; 32]>, Ral1Error>;
}

impl LetterKeys for PrekeyLifecycleActor {
    fn wrap_dh(&self, header: &Ral1Header, now_ms: u64) -> Result<Zeroizing<[u8; 32]>, Ral1Error> {
        wrap_dh_with_actor(self, header, now_ms)
    }
}

/// What one letter's envelopes did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LetterReport {
    /// The sender (the letter's `sender_device`).
    pub peer: [u8; 32],
    /// The letter session.
    pub session_id: [u8; 32],
    /// A LETTER whose PairInit made a new session here.
    pub new_session: bool,
    /// Messages taken for the first time.
    pub messages: usize,
    /// Messages taken before (their ACK owed again).
    pub duplicates: usize,
    /// ACKs that settled a message (a REPLY).
    pub acks: usize,
    /// Envelopes refused for good (the rest of the letter still counts).
    pub refused: usize,
}

/// What intake did with one letter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LetterOutcome {
    /// A LETTER whose PairInit is accepted (now or before) and every
    /// envelope settled: its REPLY is owed.
    Letter(LetterReport),
    /// A REPLY that confirmed this node's letter session and settled its
    /// ACKs.
    Reply(LetterReport),
    /// Refused with a stable code.
    Refused(Ral1Error),
    /// The PairInit (or the REPLY's confirmation) holds, but an envelope must
    /// be tried again (`why`: the relayed-ingest reason, e.g.
    /// `OWED_ACK_FULL`): what was taken stays taken, the letter stays at
    /// the custodian.
    Kept {
        report: LetterReport,
        scope: RetryScope,
        why: &'static str,
    },
}

impl LetterOutcome {
    /// Whether the custodian's copy is released after this outcome (RAL1
    /// §6): yes once intake committed or when the letter can never succeed.
    pub fn releases(&self) -> bool {
        match self {
            Self::Letter(_) | Self::Reply(_) => true,
            Self::Refused(code) => code.releases_letter(),
            Self::Kept { .. } => false,
        }
    }

    /// The report of a letter whose PairInit or PairResponse held.
    pub fn report(&self) -> Option<&LetterReport> {
        match self {
            Self::Letter(report) | Self::Reply(report) | Self::Kept { report, .. } => Some(report),
            Self::Refused(_) => None,
        }
    }
}

/// Intake of one fetched letter with this device's prekey lifecycle actor
/// (opened here; a failure to open it keeps the letter).
pub fn intake_letter(
    data_dir: &Path,
    identity: &Identity,
    letter: &[u8],
    now_ms: u64,
) -> LetterOutcome {
    intake_letter_sensed(data_dir, identity, letter, now_ms).0
}

/// Whose fault a letter refused for what it carries is (Phase 6b S20,
/// `SEC_LETTER_BAD`): the fetcher notes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadLetter {
    /// Its signature does not verify (step 5): the carrier that served it.
    Carrier,
    /// Signed by this pinned contact, but its AEAD, inner bytes or
    /// stateless bindings do not hold (steps 6-9).
    Sender([u8; 32]),
}

/// [`intake_letter`] that also says whose fault a bad letter is.
pub fn intake_letter_sensed(
    data_dir: &Path,
    identity: &Identity,
    letter: &[u8],
    now_ms: u64,
) -> (LetterOutcome, Option<BadLetter>) {
    // Gate first: a node with letters off touches nothing (and its open
    // actor would be wasted).
    if !crate::horizon::letter_live_enabled() {
        return (LetterOutcome::Refused(Ral1Error::Gate), None);
    }
    let actor = match PrekeyLifecycleActor::open(data_dir) {
        Ok(actor) => actor,
        Err(_) => return (LetterOutcome::Refused(Ral1Error::Store), None),
    };
    intake_letter_with_sensed(data_dir, identity, letter, &actor, now_ms)
}

/// [`intake_letter`] with `keys` answering step 6.
pub fn intake_letter_with<K: LetterKeys + ?Sized>(
    data_dir: &Path,
    identity: &Identity,
    letter: &[u8],
    keys: &K,
    now_ms: u64,
) -> LetterOutcome {
    intake_letter_with_sensed(data_dir, identity, letter, keys, now_ms).0
}

/// [`intake_letter_with`] that also says whose fault a bad letter is.
pub fn intake_letter_with_sensed<K: LetterKeys + ?Sized>(
    data_dir: &Path,
    identity: &Identity,
    letter: &[u8],
    keys: &K,
    now_ms: u64,
) -> (LetterOutcome, Option<BadLetter>) {
    if !crate::horizon::letter_live_enabled() {
        return (LetterOutcome::Refused(Ral1Error::Gate), None);
    }
    let local = identity.public_key_bytes();
    // Step 4 reads the book; an unreadable one keeps the letter (a store
    // error), it does not make the sender a stranger.
    let mut unreadable = false;
    // The sender step 4 admitted: steps 6-9 run only once its signature
    // verified.
    let mut sender = None;
    let opened = open(
        letter,
        &local,
        now_ms,
        |device| {
            sender = Some(*device);
            match contact_admission(data_dir, device) {
                ContactAdmission::Allowed(contact) => contact.pinned,
                ContactAdmission::Unreadable => {
                    unreadable = true;
                    false
                }
                ContactAdmission::NotContact | ContactAdmission::Blocked => false,
            }
        },
        |header| keys.wrap_dh(header, now_ms),
    );
    match opened {
        Ok(Opened::Letter(letter)) => (accept_letter(data_dir, identity, *letter, now_ms), None),
        Ok(Opened::Reply(reply)) => (accept_reply(data_dir, identity, *reply, now_ms), None),
        Err(Ral1Error::NotContact) if unreadable => {
            (LetterOutcome::Refused(Ral1Error::Store), None)
        }
        Err(code) => {
            let bad = match code {
                Ral1Error::BadSignature => Some(BadLetter::Carrier),
                Ral1Error::Unwrap | Ral1Error::Inner | Ral1Error::Binding => {
                    sender.map(BadLetter::Sender)
                }
                _ => None,
            };
            (LetterOutcome::Refused(code), bad)
        }
    }
}

/// A store error as a letter code: one the same bytes may get past later
/// keeps the letter; everything else refuses it.
fn store_code(error: &IndexedSessionStoreError) -> Ral1Error {
    use IndexedSessionStoreError as E;
    match error {
        E::Sqlite(_)
        | E::ProtectedStore(_)
        | E::CorruptProtectedState
        | E::CorruptEndpointState
        | E::ProtectedStateMissing
        | E::RollbackDetected => Ral1Error::Store,
        _ => Ral1Error::PairRefused,
    }
}

/// Whether `key`'s session is here, confirmed and live at `now_ms`.
fn confirmed_here(
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    key: &IndexedSessionRecordKey,
    now_ms: u64,
) -> Result<bool, IndexedSessionStoreError> {
    Ok(store
        .find_confirmed_sessions_for_peer_at(peer, now_ms)?
        .contains(key))
}

/// Steps 10-11 for a LETTER that opened.
fn accept_letter(
    data_dir: &Path,
    identity: &Identity,
    opened: OpenedLetter,
    now_ms: u64,
) -> LetterOutcome {
    let peer = opened.header.sender_device;
    let init = opened.pair_init;
    let Ok(sid) = session_id(&init) else {
        return LetterOutcome::Refused(Ral1Error::PairRefused);
    };
    let key = record_key_for_init(&init);
    let mut store = match IndexedSessionStore::open(data_dir) {
        Ok(store) => store,
        Err(_) => return LetterOutcome::Refused(Ral1Error::Store),
    };
    // Accepted before (this letter again, or another letter of the same
    // session): the PairInit is not run again; its REPLY is owed already.
    let here = match (
        store.letter_role(&sid),
        confirmed_here(&mut store, &peer, &key, now_ms),
    ) {
        (Ok(role), Ok(confirmed)) => role == Some(LetterRole::Responder) && confirmed,
        (Err(e), _) | (_, Err(e)) => return LetterOutcome::Refused(store_code(&e)),
    };
    drop(store);
    let mut new_session = false;
    if !here {
        // The initiator's certificate and bundle as this node cached them
        // when they last met; none (or another device's) refuses the
        // PairInit, which binds that certificate.
        let bundle = match load_cached_peer_bundle(data_dir, &peer) {
            Ok(Some(bundle)) if bundle.cert.device_ed_pub == peer => bundle,
            Ok(_) => return LetterOutcome::Refused(Ral1Error::PairRefused),
            Err(_) => return LetterOutcome::Refused(Ral1Error::Store),
        };
        let core = accept_pair_init_core(
            data_dir,
            identity,
            &bundle,
            &init,
            PairOrigin::Letter,
            now_ms,
        );
        let mut store = match IndexedSessionStore::open(data_dir) {
            Ok(store) => store,
            Err(_) => return LetterOutcome::Refused(Ral1Error::Store),
        };
        // The session must be here and confirmed: an exact replay of a
        // PairInit whose session has ended is answered from its claim, but
        // its messages have nowhere to go.
        let confirmed = match confirmed_here(&mut store, &peer, &key, now_ms) {
            Ok(confirmed) => confirmed,
            Err(e) => return LetterOutcome::Refused(store_code(&e)),
        };
        match core {
            Ok(_) if confirmed => new_session = true,
            Ok(_) => return LetterOutcome::Refused(Ral1Error::PairRefused),
            // A session this PairInit set up over a link (the initiator
            // completed it directly) takes the letter's envelopes too.
            Err(crate::lan_dispatch::PairAcceptError::Refused(_)) if confirmed => {}
            Err(error) => return LetterOutcome::Refused(error.letter_code()),
        }
    }
    let mut report = LetterReport {
        peer,
        session_id: sid,
        new_session,
        ..LetterReport::default()
    };
    let hint = RelayHint {
        record_key: key,
        peer_device: peer,
        store_tag: [0; 16],
    };
    for carried in &opened.envelopes {
        let envelope = &carried.envelope;
        if !canonical_outbound_fields(envelope) {
            report.refused += 1;
            continue;
        }
        let outcome = ingest_envelope(
            data_dir,
            identity,
            &carried.packed,
            envelope,
            &hint,
            AckLife::Session,
            now_ms,
        );
        match outcome {
            RelayedOutcome::MessageAccepted {
                duplicate: false, ..
            } => report.messages += 1,
            RelayedOutcome::MessageAccepted {
                duplicate: true, ..
            } => report.duplicates += 1,
            // A LETTER carries messages only (its inner decode checked).
            RelayedOutcome::AckAccepted { .. } | RelayedOutcome::Refused(_) => report.refused += 1,
            RelayedOutcome::Retry(scope, why) => {
                return LetterOutcome::Kept { report, scope, why };
            }
        }
    }
    LetterOutcome::Letter(report)
}

/// Step 10 for a REPLY that opened: find the letter session it answers,
/// confirm it, settle the ACKs.
fn accept_reply(
    data_dir: &Path,
    identity: &Identity,
    opened: OpenedReply,
    now_ms: u64,
) -> LetterOutcome {
    let peer = opened.header.sender_device;
    let response = opened.pair_response;
    let mut store = match IndexedSessionStore::open(data_dir) {
        Ok(store) => store,
        Err(_) => return LetterOutcome::Refused(Ral1Error::Store),
    };
    let sessions = match store.live_letter_sessions_for_peer(&peer, LetterRole::Initiator, now_ms) {
        Ok(sessions) => sessions,
        Err(e) => return LetterOutcome::Refused(store_code(&e)),
    };
    // The binding the stateless check could not make: `init_id` names a
    // letter session this node started with the sender.
    let found = sessions.into_iter().find_map(|(key, row)| {
        let init = decode_init(row.pair_init.as_deref()?).ok()?;
        (init.init_id == response.init_id).then_some((key, row.session_id, init))
    });
    let Some((key, sid, init)) = found else {
        return LetterOutcome::Refused(Ral1Error::Binding);
    };
    if let Err(e) = store.confirm_verified_pair_response(&key, &init, &response, now_ms) {
        return LetterOutcome::Refused(store_code(&e));
    }
    drop(store);
    let mut report = LetterReport {
        peer,
        session_id: sid,
        ..LetterReport::default()
    };
    let hint = RelayHint {
        record_key: key,
        peer_device: peer,
        store_tag: [0; 16],
    };
    for carried in &opened.acks {
        let envelope: &Envelope = &carried.envelope;
        if envelope.env_type != EnvType::Ack as u8 || !canonical_outbound_fields(envelope) {
            report.refused += 1;
            continue;
        }
        match ingest_envelope(
            data_dir,
            identity,
            &carried.packed,
            envelope,
            &hint,
            AckLife::Session,
            now_ms,
        ) {
            RelayedOutcome::AckAccepted { .. } => report.acks += 1,
            RelayedOutcome::MessageAccepted { .. } | RelayedOutcome::Refused(_) => {
                report.refused += 1
            }
            RelayedOutcome::Retry(scope, why) => {
                return LetterOutcome::Kept { report, scope, why };
            }
        }
    }
    LetterOutcome::Reply(report)
}

/// The letter fixture is shared with the custody client's letter tests.
#[cfg(test)]
pub(crate) mod tests;
