//! Outbox policy and delivery bookkeeping shared by `raven send` (ash) and the
//! raven-node background outbox worker (transports design 2026-10 §2.4-§2.5).
//!
//! Both processes serialise their work on one peer with the same
//! [`PeerSendLock`], verify a sealed ACK with the same
//! [`finish_outbound_delivered`] (including the check that the ACK confirms
//! *this* message), and give a message up with the same
//! [`mark_outbound_undelivered`]. A message is therefore delivered, expired or
//! failed in exactly the same way whichever of them saw the outcome.
//!
//! Nothing here does network I/O, and nothing runs inside a session-store
//! transaction: the store commits before any callback dials.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::device_cert::DeviceCertificate;
use crate::device_sync::RevocationStore;
use crate::envelope::{EnvType, Envelope};
use crate::indexed_session_store::{
    EndpointAckAcceptance, EndpointDeliveryState, EndpointOutboundKind, IndexedSessionRecordKey,
    IndexedSessionStore,
};
use crate::paths::DataDirLock;

/// How long a sealed message or ACK envelope stays valid: `min(session end,
/// now + ENVELOPE_VALIDITY_MS)` (transports design F2, owner decision Q4: no
/// automatic re-seal after expiry). The frozen profile only requires the
/// envelope to end inside its session and to live at most
/// `MAX_ENDPOINT_ENVELOPE_LIFETIME_MS` (7 days); sessions this node initiates
/// last 24 h, so in practice the session end decides. Was 1 h before P2a
/// (docs/WAIVER_LAN_DIRECT_P2A_AMENDMENT_DRAFT.md).
///
/// The envelope keeps this limit with the long message horizon too (Phase
/// 5a, [`crate::horizon`]): with the horizon gate on, the *message* lives
/// until its own deadline, `created_at +` [`crate::horizon::MESSAGE_HORIZON_MS`]
/// ([`crate::horizon::message_deadline`]); an envelope that expires before
/// it parks the message ([`park_or_give_up_expired`]) to be sealed again
/// into a fresh session.
pub const ENVELOPE_VALIDITY_MS: u64 = 24 * 60 * 60 * 1_000;

const _: () = assert!(
    ENVELOPE_VALIDITY_MS <= crate::indexed_session_store::MAX_ENDPOINT_ENVELOPE_LIFETIME_MS
);

/// Expiry for an envelope sealed at `now_ms` under a session that ends at
/// `session_expires_ms`. `Err` once the session has no time left.
pub fn envelope_expires_at(now_ms: u64, session_expires_ms: u64) -> Result<u64, String> {
    let expires = now_ms
        .saturating_add(ENVELOPE_VALIDITY_MS)
        .min(session_expires_ms);
    if expires <= now_ms {
        return Err("session expired".into());
    }
    Ok(expires)
}

// ── Per-peer send lock ───────────────────────────────────────────────────────

/// Cross-process lock serialising the stateful part of every send to one peer
/// from this profile: pairing (first contact), the retry of an earlier queued
/// message, staging a new one and its dial. `ash send` and the raven-node
/// outbox worker take the very same lock file, so they never dial the same
/// staged bytes at the same time nor race for the one prepared-message slot.
///
/// Without it, concurrent senders interleave in ways the store can only
/// refuse: two first-contact sends each ran PairInit and left two sessions the
/// peer then refused, and a burst of sends fought over the single
/// outstanding-message slot, so some of them lost their text.
///
/// Privacy pack PP.6: in a sealed profile the lock file is named by a keyed
/// hash of the peer's key ([`crate::at_rest::lock_name`]), so a folder
/// listing names no friend. An older build names it by the key in hex
/// ([`Self::legacy_file_name`]): while such a file exists, it is taken too
/// (the keyed one first, then the older one, always in that order), so an
/// older `ash` still running and this build exclude each other; it is
/// deleted when both are let go, and this build never creates one in a
/// sealed profile.
pub struct PeerSendLock {
    /// An older build's lock file for this peer, held while it existed when
    /// the keyed one was taken, and its path (deleted on drop).
    legacy: Option<(DataDirLock, std::path::PathBuf)>,
    _lock: DataDirLock,
}

impl PeerSendLock {
    /// The lock file for `peer_device` in `data_dir`: dot-prefixed
    /// `*.lock.sqlite`, the inert lock-database shape the first-install check
    /// already tolerates. In a sealed profile the keyed name (from the stable
    /// index key: a rotation never renames it; the key must be loaded), the
    /// key in hex otherwise ([`Self::legacy_file_name`]).
    pub fn file_name(data_dir: &Path, peer_device: &[u8; 32]) -> Result<String, String> {
        match crate::privacy::mode(data_dir) {
            crate::at_rest::Mode::Sealed => {
                let keys = crate::at_rest::keys_cached(data_dir).map_err(|e| e.to_string())?;
                Ok(crate::at_rest::lock_name(&keys, peer_device))
            }
            crate::at_rest::Mode::Plain | crate::at_rest::Mode::UnsealedByUser => {
                Ok(Self::legacy_file_name(peer_device))
            }
        }
    }

    /// The name every build before the privacy pack used, and this one uses
    /// in a plain profile: `.send_<device key hex>.lock.sqlite`.
    pub fn legacy_file_name(peer_device: &[u8; 32]) -> String {
        format!(".send_{}.lock.sqlite", hex::encode(peer_device))
    }

    /// Wait at most `wait` for the other holder (for each of the two locks
    /// when an older build's exists). The error is the raw lock text;
    /// [`send_lock_busy`] tells "held by someone else" apart.
    pub fn acquire_within(
        data_dir: &Path,
        peer_device: &[u8; 32],
        wait: Duration,
    ) -> Result<Self, String> {
        let name = Self::file_name(data_dir, peer_device)?;
        let lock = DataDirLock::acquire_within(data_dir, &name, wait)?;
        let legacy_name = Self::legacy_file_name(peer_device);
        let legacy = if name == legacy_name {
            None
        } else {
            DataDirLock::acquire_existing_within(data_dir, &legacy_name, wait)?
                .map(|held| (held, data_dir.join(&legacy_name)))
        };
        Ok(Self {
            legacy,
            _lock: lock,
        })
    }

    /// Delete `peer_device`'s lock files (its contact was removed): the one
    /// this profile uses now and an older build's, each taken for a moment
    /// first (without waiting); one held by a send still running is left,
    /// and that is an error. Missing files are fine.
    pub fn remove_files(data_dir: &Path, peer_device: &[u8; 32]) -> Result<(), String> {
        let legacy = Self::legacy_file_name(peer_device);
        let mut names = vec![legacy.clone()];
        let current = Self::file_name(data_dir, peer_device)?;
        if current != legacy {
            names.insert(0, current);
        }
        for name in names {
            if let Some(held) =
                DataDirLock::acquire_existing_within(data_dir, &name, Duration::ZERO)?
            {
                drop(held);
                remove_lock_file(&data_dir.join(&name));
            }
        }
        Ok(())
    }
}

impl Drop for PeerSendLock {
    fn drop(&mut self) {
        // Both were free when they were taken: the older build's file goes
        // now, while the keyed lock is still held (best effort; on Windows a
        // file another process has open stays, and the next send tries again).
        if let Some((held, path)) = self.legacy.take() {
            drop(held);
            remove_lock_file(&path);
        }
    }
}

/// What [`PeerSendLock::remove_legacy_files`] did: counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegacyLocks {
    /// Older names deleted now.
    pub removed: u16,
    /// Older names still there (a send holds one): the next pass tries again.
    pub left: u16,
}

impl PeerSendLock {
    /// Review B-sealed-stores-4: in a sealed profile with its key loaded,
    /// every older name ([`Self::legacy_file_name`], and its `-journal`)
    /// goes, so a folder listing no longer names the friends sent to before
    /// the upgrade (only a send to that friend deleted one before). Each is
    /// taken without waiting after the friend's keyed lock, the order every
    /// send takes them in, and deleted while both are held; one a send holds
    /// is left for the next pass. A name whose friend is not in the book (a
    /// contact removed before the upgrade) gets no keyed lock file: its keyed
    /// lock is taken only when that file exists already, since nothing would
    /// ever delete a new one (`raven contact remove` needs the book entry).
    /// Nothing to do in a plain profile, which names its locks that way
    /// itself.
    pub fn remove_legacy_files(data_dir: &Path) -> LegacyLocks {
        let mut report = LegacyLocks::default();
        if crate::privacy::mode(data_dir) != crate::at_rest::Mode::Sealed {
            return report;
        }
        let Ok(keys) = crate::at_rest::keys_cached(data_dir) else {
            return report;
        };
        let legacy = legacy_send_lock_files(data_dir);
        if legacy.is_empty() {
            return report;
        }
        // A book that cannot be read now names no friend: no keyed file is
        // created then.
        let friends = book_devices(data_dir).unwrap_or_default();
        let count = |n: &mut u16| *n = n.saturating_add(1);
        for (peer, name) in legacy {
            let path = data_dir.join(&name);
            let Some(main) = name.strip_suffix("-journal") else {
                let keyed = crate::at_rest::lock_name(&keys, &peer);
                let held = if friends.contains(&peer) {
                    DataDirLock::acquire_within(data_dir, &keyed, Duration::ZERO).map(Some)
                } else {
                    DataDirLock::acquire_existing_within(data_dir, &keyed, Duration::ZERO)
                };
                let Ok(_keyed) = held else {
                    count(&mut report.left);
                    continue;
                };
                match DataDirLock::acquire_existing_within(data_dir, &name, Duration::ZERO) {
                    Ok(Some(held)) => {
                        drop(held);
                        remove_lock_file(&path);
                        if std::fs::symlink_metadata(&path).is_ok() {
                            count(&mut report.left);
                        } else {
                            count(&mut report.removed);
                        }
                    }
                    // Gone meanwhile.
                    Ok(None) => {}
                    Err(_) => count(&mut report.left),
                }
                continue;
            };
            // A journal beside no database: nobody has it open. One beside a
            // database went with it above, or stays with it.
            if std::fs::symlink_metadata(&path).is_err()
                || std::fs::symlink_metadata(data_dir.join(main)).is_ok()
            {
                continue;
            }
            if std::fs::remove_file(&path).is_ok() {
                count(&mut report.removed);
            } else {
                count(&mut report.left);
            }
        }
        if report.removed > 0 {
            crate::paths::sync_dir_best_effort(data_dir);
        }
        report
    }
}

/// The device keys of the friends in the book (`pub_hex`); `None` while it
/// cannot be read (a sealed book without its key, a damaged one), empty
/// without one.
pub(crate) fn book_devices(data_dir: &Path) -> Option<Vec<[u8; 32]>> {
    #[derive(Deserialize)]
    struct Row {
        #[serde(default)]
        pub_hex: String,
    }
    let rows: Vec<Row> = crate::contact_book::read_rows(data_dir)
        .ok()?
        .unwrap_or_default();
    Some(
        rows.iter()
            .filter_map(|row| hex::decode(row.pub_hex.trim()).ok())
            .filter_map(|raw| <[u8; 32]>::try_from(raw).ok())
            .collect(),
    )
}

/// Every older per-friend lock name in `data_dir`
/// (`.send_<64 lowercase hex>.lock.sqlite`, and a `-journal` beside one),
/// with the key it names, databases before journals. Its name holds the
/// friend's key: in a sealed profile `raven privacy status` counts each as
/// a plain file until [`PeerSendLock::remove_legacy_files`] deletes it.
pub fn legacy_send_lock_files(data_dir: &Path) -> Vec<([u8; 32], String)> {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return Vec::new();
    };
    let mut found: Vec<([u8; 32], String)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let base = name.strip_suffix("-journal").unwrap_or(&name);
            let hex_key = base.strip_prefix(".send_")?.get(..64)?;
            if !hex_key
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return None;
            }
            let peer = <[u8; 32]>::try_from(hex::decode(hex_key).ok()?).ok()?;
            // Exactly the older name (a keyed one has 32 hex digits).
            (base == PeerSendLock::legacy_file_name(&peer)).then_some((peer, name))
        })
        .collect();
    found.sort_by(|a, b| (a.1.ends_with("-journal"), &a.1).cmp(&(b.1.ends_with("-journal"), &b.1)));
    found
}

/// Every keyed per-friend lock name in `data_dir`
/// (`.send_<32 lowercase hex>.lock.sqlite`, [`crate::at_rest::lock_name`],
/// and a `-journal` beside one), databases before journals.
fn keyed_send_lock_files(data_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let base = name.strip_suffix("-journal").unwrap_or(&name);
            let digest = base.strip_prefix(".send_")?.get(..32)?;
            // Exactly a keyed name (an older one has 64 hex digits).
            (digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                && base == format!(".send_{digest}.lock.sqlite"))
            .then_some(name)
        })
        .collect();
    found.sort_by(|a, b| (a.ends_with("-journal"), a).cmp(&(b.ends_with("-journal"), b)));
    found
}

impl PeerSendLock {
    /// `raven privacy rotate-meta`, once each friend's lock has its new name:
    /// every keyed lock file (and its `-journal`) whose name is no book
    /// friend's under `keys` goes, taken for a moment first (without
    /// waiting); one a send holds stays. Such a file was left by a contact
    /// removed before the upgrade or by a run that stopped before its
    /// renames, and would otherwise stay keyed under the old `k_index` for
    /// good (review B-sealed-stores-4 follow-up). Nothing while the book
    /// cannot be read. How many went.
    pub fn remove_stray_keyed_files(data_dir: &Path, keys: &crate::at_rest::MetaKeys) -> u16 {
        let Some(friends) = book_devices(data_dir) else {
            return 0;
        };
        let keep: std::collections::BTreeSet<String> = friends
            .iter()
            .map(|device| crate::at_rest::lock_name(keys, device))
            .collect();
        let mut removed = 0u16;
        for name in keyed_send_lock_files(data_dir) {
            let path = data_dir.join(&name);
            let gone = match name.strip_suffix("-journal") {
                None if keep.contains(&name) => false,
                None => match DataDirLock::acquire_existing_within(data_dir, &name, Duration::ZERO)
                {
                    Ok(Some(held)) => {
                        drop(held);
                        remove_lock_file(&path);
                        std::fs::symlink_metadata(&path).is_err()
                    }
                    _ => false,
                },
                // A journal beside no database: nobody has it open. One
                // beside a database went with it above, or stays with it.
                Some(main) => {
                    !keep.contains(main)
                        && std::fs::symlink_metadata(data_dir.join(main)).is_err()
                        && std::fs::remove_file(&path).is_ok()
                }
            };
            if gone {
                removed = removed.saturating_add(1);
            }
        }
        if removed > 0 {
            crate::paths::sync_dir_best_effort(data_dir);
        }
        removed
    }
}

/// Remove a lock database and the journal SQLite may leave beside it (best
/// effort).
fn remove_lock_file(path: &Path) {
    let _ = std::fs::remove_file(path);
    let mut journal = path.as_os_str().to_owned();
    journal.push("-journal");
    let _ = std::fs::remove_file(std::path::PathBuf::from(journal));
}

/// True when a [`PeerSendLock::acquire_within`] error means another sender
/// (ash or the outbox worker) still holds the lock.
pub fn send_lock_busy(err: &str) -> bool {
    err.contains("database is locked") || err.contains("database is busy")
}

// ── ACK acceptance and history ───────────────────────────────────────────────

/// Start of the error [`finish_outbound_delivered`] returns when the ACK that
/// came back belongs to another outstanding message of the session.
pub const ACK_FOR_ANOTHER_MESSAGE: &str = "ACK_FOR_ANOTHER_MESSAGE";

/// History delivery states written for an outbound message that was given up.
pub const HISTORY_FAILED: &str = "failed";
/// Its envelope expired before any ACK came back (shown as "expired, not
/// delivered").
pub const HISTORY_EXPIRED: &str = "expired";
/// The user cancelled it (`raven outbox cancel`).
pub const HISTORY_CANCELLED: &str = "cancelled";

/// Lineage-aware peer denial, the same predicate the receive side uses
/// (`RevocationStore::denies_certificate`): legacy `(user, device_id)` records
/// plus RVDR1 claims covering the device id, either device key or the cert
/// hash.
pub fn peer_lineage_denied(data_dir: &Path, peer_cert: &DeviceCertificate) -> Result<bool, String> {
    RevocationStore::load_checked(data_dir)?.denies_certificate(peer_cert)
}

/// The first packed ACK envelope among dial replies.
pub fn first_ack_frame(frames: &[Vec<u8>]) -> Option<&[u8]> {
    ack_frames(frames).into_iter().next()
}

/// Every packed ACK envelope among dial replies (a dial may carry several
/// objects, each answered by its own ACK).
pub fn ack_frames(frames: &[Vec<u8>]) -> Vec<&[u8]> {
    frames
        .iter()
        .filter(|packed| is_ack_frame(packed))
        .map(Vec::as_slice)
        .collect()
}

/// Whether one dial reply is a packed ACK envelope ([`ack_frames`]).
pub fn is_ack_frame(packed: &[u8]) -> bool {
    Envelope::unpack(packed).is_some_and(|env| env.env_type == EnvType::Ack as u8)
}

/// Why [`accept_sealed_ack`] did not accept an ACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckRejected {
    /// Not sealed under this session: try the next candidate session.
    OtherSession,
    /// Refused by the store or the revocation check (redacted text).
    Refused(String),
}

/// Verify one sealed ACK under `record_key` (session-bound device, inner and
/// outer signatures, an outstanding row, replay checks, the peer lineage) and
/// return the message it confirms. The one ACK check `raven send` and the
/// outbox worker share; a message is delivered only when an ACK this accepts
/// names *its* id. `carrier`: the dial it came back on; a store refusal that
/// is a security event is noted about the contact (Phase 6b S6-S11).
pub fn accept_sealed_ack(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_cert: &DeviceCertificate,
    ack: &[u8],
    carrier: OutboxCarrier,
) -> Result<[u8; 16], AckRejected> {
    let denied = peer_lineage_denied(data_dir, peer_cert).map_err(AckRejected::Refused)?;
    let now = crate::clock::now_ms();
    match store.accept_ack_envelope(record_key, ack, peer_cert, denied, now) {
        Ok(EndpointAckAcceptance::Committed {
            acked_message_id, ..
        }) => {
            let local = if record_key.initiator_device_ed25519 == peer_cert.device_ed_pub {
                record_key.responder_device_ed25519
            } else {
                record_key.initiator_device_ed25519
            };
            let made_at = Envelope::unpack(ack).map_or(0, |env| env.created_at);
            crate::session_reset::note_inbound_on_session(store, record_key, &local, made_at, now);
            Ok(acked_message_id)
        }
        Ok(EndpointAckAcceptance::Duplicate {
            acked_message_id, ..
        }) => Ok(acked_message_id),
        Err(crate::IndexedSessionStoreError::RouteTagMismatch) => Err(AckRejected::OtherSession),
        Err(e) => {
            crate::security_sense::store_refusal(
                &e,
                crate::security_events::Via::Dial(carrier),
                None,
                &peer_cert.user_ed_pub,
            );
            Err(AckRejected::Refused(e.redacted_display()))
        }
    }
}

/// Record that `message_id` was delivered (an accepted ACK names it): an
/// outbox row still `Prepared` is settled so nothing dials it again, the
/// history row becomes `delivered` (never back again, see
/// `chat_history::delivery_after`) and the staged body is cleared.
pub fn record_outbound_delivered(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<(), String> {
    store
        .settle_delivered_outbound(session_id, message_id)
        .map_err(|e| e.redacted_display())?;
    record_inbound_ack_delivery(data_dir, peer_pub, session_id, message_id)
}

/// Did an accepted ACK already deliver this message (outstanding row
/// `Delivered` or `Read`)? Checked before every retry, by `raven send` and the
/// worker alike: a delivered message is never dialled again.
pub fn outbound_already_delivered(
    store: &IndexedSessionStore,
    session_id: &[u8; 32],
    message_id: &[u8; 16],
    recipient: &[u8; 32],
) -> Result<bool, String> {
    Ok(matches!(
        store
            .outstanding_delivery_state(session_id, message_id, recipient)
            .map_err(|e| e.redacted_display())?,
        Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
    ))
}

/// Verify the sealed `ack` for `message_id` and record the delivery: the store
/// accepts the ACK ([`accept_sealed_ack`]), the history row becomes
/// `delivered` and the staged body is cleared.
///
/// An ACK the store accepts for *another* outstanding message of the session
/// marks that one delivered and returns [`ACK_FOR_ANOTHER_MESSAGE`]: it must
/// never make this message read "delivered". `carrier`: the dial the ACK came
/// back on.
#[allow(clippy::too_many_arguments)]
pub fn finish_outbound_delivered(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_cert: &DeviceCertificate,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    ack: &[u8],
    now_ms: u64,
    carrier: OutboxCarrier,
) -> Result<(), String> {
    // History body must exist before Delivered is committed.
    crate::lan_dispatch::ensure_outbound_queued_history(
        data_dir,
        &peer_cert.device_ed_pub,
        session_id,
        object_digest,
        message_id,
        now_ms,
        None,
    )?;
    let acked = accept_sealed_ack(data_dir, store, record_key, peer_cert, ack, carrier).map_err(
        |e| match e {
            AckRejected::OtherSession => {
                crate::IndexedSessionStoreError::RouteTagMismatch.redacted_display()
            }
            AckRejected::Refused(text) => text,
        },
    )?;
    if acked != *message_id {
        // A genuine ACK (the store matched it to an outstanding message of this
        // session) but for ANOTHER message: that one is delivered, this one is
        // still unconfirmed.
        let _ = record_outbound_delivered(
            data_dir,
            store,
            &peer_cert.device_ed_pub,
            session_id,
            &acked,
        );
        return Err(format!(
            "{ACK_FOR_ANOTHER_MESSAGE}: the acknowledgement that came back is for message \
             {}…, not for this one",
            hex::encode(&acked[..4])
        ));
    }
    store
        .settle_delivered_outbound(session_id, message_id)
        .map_err(|e| e.redacted_display())?;
    crate::lan_dispatch::mark_lan_chat_history_delivery(
        data_dir,
        "out",
        &peer_cert.device_ed_pub,
        message_id,
        "delivered",
    )?;
    crate::chat_history::clear_staged_outbound_body(data_dir, message_id)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Record an outbound message that will never be delivered: the history row
/// takes `delivery` ([`HISTORY_FAILED`], [`HISTORY_EXPIRED`] or
/// [`HISTORY_CANCELLED`]) with the staged body, and the stage is cleared. The
/// staged binding must match exactly. A row already `delivered` stays so.
pub fn mark_outbound_undelivered(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    delivery: &str,
) -> Result<(), String> {
    if let Some(staged) = crate::chat_history::load_staged_outbound_body(data_dir, message_id)
        .map_err(|e| e.to_string())?
    {
        let bound = staged
            .peer_pub_hex
            .eq_ignore_ascii_case(&hex::encode(peer_pub))
            && staged
                .session_id_hex
                .eq_ignore_ascii_case(&hex::encode(session_id))
            && staged
                .object_digest_hex
                .eq_ignore_ascii_case(&hex::encode(object_digest))
            && staged
                .message_id_hex
                .eq_ignore_ascii_case(&hex::encode(message_id));
        if !bound {
            return Err(format!(
                "staged outbound binding mismatch on fail mid={}",
                hex::encode(message_id)
            ));
        }
        crate::lan_dispatch::persist_lan_chat_history(
            data_dir,
            "out",
            peer_pub,
            message_id,
            staged.created_at_ms,
            delivery,
            staged.body.as_bytes(),
        )?;
    } else {
        crate::lan_dispatch::mark_lan_chat_history_delivery(
            data_dir, "out", peer_pub, message_id, delivery,
        )?;
    }
    crate::chat_history::clear_staged_outbound_body(data_dir, message_id)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// What [`give_up_outbound`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GiveUp {
    /// Abandoned; the history says why.
    Abandoned,
    /// An ACK delivered it in the meantime: nothing was abandoned, and the
    /// history now says delivered.
    Delivered,
}

/// Abandon one undelivered message and record why (`delivery`), unless an ACK
/// delivered it in the meantime: then the delivery is recorded instead. The
/// one give-up step `raven send` and the worker share.
#[allow(clippy::too_many_arguments)]
pub fn give_up_outbound(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    delivery: &str,
) -> Result<GiveUp, String> {
    let dropped = store
        .abandon_undelivered_outbound(record_key, object_digest)
        .map_err(|e| e.redacted_display())?;
    if dropped {
        mark_outbound_undelivered(
            data_dir,
            peer_pub,
            session_id,
            object_digest,
            message_id,
            delivery,
        )?;
        Ok(GiveUp::Abandoned)
    } else {
        record_outbound_delivered(data_dir, store, peer_pub, session_id, message_id)?;
        Ok(GiveUp::Delivered)
    }
}

/// What [`park_or_give_up_expired`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiredMessage {
    /// Given up, as [`give_up_outbound`] with [`HISTORY_EXPIRED`].
    GaveUp(GiveUp),
    /// Parked until its deadline (the horizon gate is on): its history stays
    /// `queued`, its stage and route record stay.
    Parked { deadline_ms: u64 },
}

/// A message whose envelope expired: with the horizon gate on and before
/// its deadline it is parked ([`park_expired_message`]); otherwise, and
/// always with the gate off, exactly [`give_up_outbound`] with
/// [`HISTORY_EXPIRED`]. The one expiry step `raven send` and the worker
/// share. `never_sent`: no carrier ever wrote it (kept for the parked
/// message, see [`park_expired_message`]).
#[allow(clippy::too_many_arguments)]
pub fn park_or_give_up_expired(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    never_sent: bool,
    now_ms: u64,
) -> Result<ExpiredMessage, String> {
    if let Some(deadline_ms) = park_expired_message(
        data_dir,
        store,
        peer_pub,
        message_id,
        Some(session_id),
        never_sent,
        now_ms,
    )? {
        return Ok(ExpiredMessage::Parked { deadline_ms });
    }
    give_up_outbound(
        data_dir,
        store,
        record_key,
        peer_pub,
        session_id,
        object_digest,
        message_id,
        HISTORY_EXPIRED,
    )
    .map(ExpiredMessage::GaveUp)
}

/// Park the message `message_id` to `peer_pub` whose envelope or session
/// ran out (Phase 5a, [`crate::horizon`]): only with the horizon gate on,
/// for a message with a deadline ([`crate::horizon::deadline_for`]: a
/// staged or history body) that has not passed. The store moves its copy in
/// `from_session` out of the outbox
/// ([`IndexedSessionStore::park_outbound`]); its route record (carrier
/// choice, routes, custody consent) is kept until the deadline
/// ([`extend_object_route_expiry`]), and one that `never_sent` says so
/// ([`ObjectRoutes::unsent`]) until a copy is written. The deadline, or
/// `None` when nothing was parked: the gate is off (nothing is read), there
/// is no deadline, it passed, or an ACK settled a copy (the caller gives
/// the message up, which records that delivery).
pub fn park_expired_message(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer_pub: &[u8; 32],
    message_id: &[u8; 16],
    from_session: Option<&[u8; 32]>,
    never_sent: bool,
    now_ms: u64,
) -> Result<Option<u64>, String> {
    if !crate::horizon::horizon_live_enabled() {
        return Ok(None);
    }
    let Some((created_at_ms, deadline_ms)) =
        crate::horizon::deadline_for(data_dir, peer_pub, message_id)
    else {
        return Ok(None);
    };
    if now_ms >= deadline_ms {
        return Ok(None);
    }
    let parked = store
        .park_outbound(
            peer_pub,
            message_id,
            from_session,
            created_at_ms,
            deadline_ms,
            now_ms,
        )
        .map_err(|e| e.redacted_display())?;
    if !parked {
        return Ok(None);
    }
    // Hints only: a record that is gone plans from the contact book.
    let _ = extend_object_route_expiry(data_dir, message_id, deadline_ms, now_ms);
    if never_sent {
        let _ = set_object_unsent(data_dir, message_id, true, now_ms);
    }
    Ok(Some(deadline_ms))
}

/// Abandon every undelivered message to `recipient` (a revoked peer lineage)
/// and mark each [`HISTORY_FAILED`], so it is not retried again. Messages an
/// ACK delivered meanwhile are recorded as delivered instead.
pub fn abandon_undelivered_to_peer(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    recipient: &[u8; 32],
) -> Result<(), String> {
    let mut rows = store
        .pending_endpoint_outbound_for_recipient(Some(recipient))
        .map_err(|e| e.redacted_display())?;
    rows.extend(
        store
            .awaiting_ack_endpoint_outbound_for_recipient(Some(recipient))
            .map_err(|e| e.redacted_display())?,
    );
    for row in rows {
        if row.kind != EndpointOutboundKind::Message {
            continue;
        }
        let Some(key) = store
            .record_key_for_session_id(&row.session_id)
            .map_err(|e| e.redacted_display())?
        else {
            continue;
        };
        // An app record keeps why (a final state keeps its first reason), so
        // a later submit of the same task is refused as lineage-revoked
        // instead of being retried. A late ACK still makes it delivered.
        let _ = crate::app_channel::mark_app_outbound(
            data_dir,
            &row.message_id,
            HISTORY_FAILED,
            PEER_REVOKED,
            crate::clock::now_ms(),
        );
        give_up_outbound(
            data_dir,
            store,
            &key,
            recipient,
            &row.session_id,
            &row.object_digest,
            &row.message_id,
            HISTORY_FAILED,
        )?;
    }
    Ok(())
}

/// Why messages to a revoked peer lineage were abandoned.
pub const PEER_REVOKED: &str = "PEER_REVOKED";

/// After an ACK that arrived on an inbound link (pushed by the receiver's
/// outbox, transports design F8) was committed: the history row of the message
/// it confirms becomes `delivered` and its staged body is cleared. Best effort
/// by design: the ACK is already committed in the store, and a missing history
/// row is repaired by `reconcile_outbound_stage_history` later.
pub fn record_inbound_ack_delivery(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    acked_message_id: &[u8; 16],
) -> Result<(), String> {
    let staged = crate::chat_history::load_staged_outbound_body(data_dir, acked_message_id)
        .map_err(|e| e.to_string())?;
    match staged {
        Some(staged)
            if staged
                .peer_pub_hex
                .eq_ignore_ascii_case(&hex::encode(peer_pub))
                && staged
                    .session_id_hex
                    .eq_ignore_ascii_case(&hex::encode(session_id)) =>
        {
            crate::lan_dispatch::persist_lan_chat_history(
                data_dir,
                "out",
                peer_pub,
                acked_message_id,
                staged.created_at_ms,
                "delivered",
                staged.body.as_bytes(),
            )?;
            crate::chat_history::clear_staged_outbound_body(data_dir, acked_message_id)
                .map_err(|e| e.to_string())
        }
        _ => crate::lan_dispatch::mark_lan_chat_history_delivery(
            data_dir,
            "out",
            peer_pub,
            acked_message_id,
            "delivered",
        ),
    }
}

// ── Routes the worker may use ────────────────────────────────────────────────

/// A carrier the outbox may retry on, in plan order (transports design
/// §2.3). All four are endpoint-authenticated Raven Noise links that
/// terminate at the intended contact, so all are confidential to the endpoint
/// (PairInit V1 §7): `P2p` runs the same Raven Noise link (prologue
/// `raven/p2p-link/v1`) inside a libp2p stream, so a relay on a circuit sees
/// only libp2p-Noise(Raven-Noise(...)) (`OPAQUE_CIRCUIT`); `Nearby` runs it
/// (prologue `raven/nearby-link/v1`) over the Bluetooth LE pipe of
/// `protocol/RAVEN_NEARBY_LINK_V1.md` (RNL1) §7; `Onion` runs it (prologue
/// `raven/onion-link/v1`) inside a Tor onion stream
/// (`protocol/RAVEN_ONION_CARRIER_V1.md`), so Tor relays see only Tor
/// cells around Raven-Noise(...) (`OPAQUE_CIRCUIT`). `Onion` is the last
/// variant, so the plan order (`Ord`) tries it last; the worker races it
/// against the others ([`with_onion_route`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxCarrier {
    Lan,
    Internet,
    P2p,
    /// Bluetooth LE nearby (Phase 5, RNL1): verified contacts only, behind
    /// [`crate::nearby_gate::NEARBY_PRODUCTION_ENABLED`]. Its route
    /// ([`nearby_dial_for`]) is derived live for each plan
    /// ([`with_nearby_route`]) and never stored.
    Nearby,
    /// A Tor onion service (lab, `RAVEN_ONION_CARRIER_V1`): verified
    /// contacts only, behind [`crate::onion_gate::ONION_PRODUCTION_ENABLED`].
    /// Its route ([`crate::onion::dial_for`]) is derived live for each plan
    /// from a binding that verifies ([`with_onion_route`]) and never stored.
    Onion,
}

impl OutboxCarrier {
    /// The label `raven send` and the IPC dial ops use.
    pub fn label(self) -> &'static str {
        match self {
            Self::Lan => "lan_dial",
            Self::Internet => "internet_dial",
            Self::P2p => "p2p_dial",
            Self::Nearby => "nearby_dial",
            Self::Onion => "onion_dial",
        }
    }

    /// May this carrier carry PairInit? Only links whose Raven Noise session
    /// ends at the intended contact (transports design §3.3) say yes.
    pub fn confidential_to_endpoint(self) -> bool {
        match self {
            Self::Lan | Self::Internet | Self::P2p | Self::Nearby | Self::Onion => true,
        }
    }
}

/// How the link that carried a delivery travelled (any-network plan §3 Phase 1
/// item 4), relative to whoever started that link. LAN and Internet direct are
/// always `Direct`; for p2p it is the libp2p connection the Raven link rode.
/// The tokens ([`Self::label`]) are what `raven send` (`path=`), the IPC
/// replies, `raven outbox status` and the logs print.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryPath {
    /// A connection the link's own initiator opened (no relay).
    Direct,
    /// A connection the *other* side opened (connection reversal).
    Reversed,
    /// A `/p2p-circuit` connection through a relay.
    Relayed,
    /// A direct connection DCUtR made from a relayed one.
    HolePunched,
}

impl DeliveryPath {
    pub const ALL: [Self; 4] = [
        Self::Direct,
        Self::Reversed,
        Self::Relayed,
        Self::HolePunched,
    ];

    /// `direct` | `reversed` | `relayed` | `hole_punched`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Reversed => "reversed",
            Self::Relayed => "relayed",
            Self::HolePunched => "hole_punched",
        }
    }

    /// The exact token only: anything else (another spelling, other case,
    /// empty) is `None`.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.label() == s)
    }
}

/// What a send asked for, stored with each queued object so the worker never
/// widens it. `Auto` unless the user forced a carrier (`--carrier
/// lan|internet|p2p|nearby`) or typed the exact LAN address (`--peer`, the
/// menu's direct host:port). `Auto` still obeys the carrier gates and the
/// verified-contact rule ([`plan_object_routes`]): with Internet, p2p and
/// nearby held it plans exactly what `Lan` plans. `Nearby` is the one
/// nearby value [`OUTBOX_ROUTES_FILE`] ever holds (its routes never are).
/// `Onion` (lab: `raven send --carrier onion` in a debug build with the Tor
/// switch) is the same for the Tor onion carrier: field tests of Tor
/// between two computers on one LAN. An older build reads it as a record it
/// does not know and leaves it as it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierChoice {
    Auto,
    Lan,
    Internet,
    P2p,
    Nearby,
    Onion,
}

impl CarrierChoice {
    pub fn allows(self, carrier: OutboxCarrier) -> bool {
        match self {
            Self::Auto => true,
            Self::Lan => carrier == OutboxCarrier::Lan,
            Self::Internet => carrier == OutboxCarrier::Internet,
            Self::P2p => carrier == OutboxCarrier::P2p,
            Self::Nearby => carrier == OutboxCarrier::Nearby,
            Self::Onion => carrier == OutboxCarrier::Onion,
        }
    }
}

/// One way to reach a peer: a carrier and its dial string (`host:port` for
/// LAN and Internet, a p2p dial such as `/p2p/<PeerId>` for p2p, see
/// [`crate::p2p_route::parse_p2p_dial`], `nearby:<64 lowercase hex>` for
/// nearby, [`nearby_dial_for`]). A reachability hint only: every link still
/// proves the pinned key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutboxRoute {
    pub carrier: OutboxCarrier,
    pub dial: String,
}

/// Where `raven send` records, per queued object, the carrier choice and the
/// routes it used, so the worker retries within exactly that (never wider).
/// Hints only: entries expire with their envelope and are cleared on
/// delivery; their routes (not their choice) are cleared whenever the
/// contact's addresses change or it is removed. When an entry expires, only
/// whether its object ever left this computer is kept a while longer
/// ([`RouteEvidence`], [`ROUTE_EVIDENCE_KEEP_MS`]).
pub const OUTBOX_ROUTES_FILE: &str = "outbox_routes.json";
/// How long the evidence of whether an object left this computer
/// ([`ObjectRoutes::unsent`], [`ObjectRoutes::written`], a friend's copy)
/// outlives its envelope: that is still needed when the object is given up
/// after its deadline (raven-node was off across it, or `raven send` reached
/// it first; review C-time-deadlines-1), until the prune settles it with its
/// session (which clears it). Only [`RouteEvidence`] is kept: the message
/// id, its deadline and three bits; no contact key, carrier choice, friend
/// key or address (review FU-3). [`object_route_evidence`] reads it;
/// [`object_route_records`] never returns an expired record.
pub const ROUTE_EVIDENCE_KEEP_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const OUTBOX_ROUTES_LOCK: &str = ".outbox_routes.lock.sqlite";
const MAX_ROUTE_OBJECTS: usize = 256;
/// LAN, Internet and p2p, a few addresses each. A plan's nearby route (one,
/// derived live) comes on top ([`plan_object_routes`]).
const MAX_ROUTES_PER_OBJECT: usize = 6;
const MAX_DIAL_CHARS: usize = 300;

/// The record of one queued object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRoutes {
    pub peer_pub_hex: String,
    pub choice: CarrierChoice,
    pub routes: Vec<OutboxRoute>,
    pub expires_at_ms: u64,
    /// Handed to the outbox queue while the peer could not be reached: no
    /// carrier has written it yet, although the store holds it as queued
    /// (awaiting an ACK). Cleared by the first real write ([`set_object_unsent`]).
    #[serde(default, skip_serializing_if = "is_false")]
    pub unsent: bool,
    /// A carrier wrote it and the contact read it, although the store still
    /// holds it as prepared: the contact took the frames and refused them (a
    /// clock apart, a removed or blocked contact). Never cleared: when its
    /// time runs out it did not "never leave this computer" (review
    /// C-time-deadlines-1). Set by [`set_object_written`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub written: bool,
    /// Friend custody: custodians (hex keys) that answered STORED/DUPLICATE
    /// for this object. Written only after the answer; never shrinks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custodians_held: Vec<String>,
    /// One of [`Self::custodians_held`] took it to pass on to the contact's
    /// own friend (a custody handoff FORWARD answered STORED or DUPLICATE,
    /// Phase 5): the contact collects it there, and its receipt can come
    /// back through friends only if the contact verified this node's friend
    /// too, so once time runs out nobody knows whether it was collected
    /// (review handoff-3). Set with the hold ([`add_object_custodians`]);
    /// cleared with the holders ([`clear_object_custodians`]).
    #[serde(default, skip_serializing_if = "is_false")]
    pub custody_forwarded: bool,
    /// Friend custody allowed for this object: its send did not force a
    /// carrier (`--carrier lan|internet|p2p`). The gate is the worker's check.
    #[serde(default, skip_serializing_if = "is_false")]
    pub custody: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Whether an object ever left this computer: all that an expired record
/// keeps ([`ROUTE_EVIDENCE_KEEP_MS`]), and what [`object_route_evidence`]
/// returns for live and expired records alike. It names no one: no contact
/// key, carrier choice, friend key or address (review FU-3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEvidence {
    /// The object's deadline: what the keep window counts from.
    pub expires_at_ms: u64,
    /// [`ObjectRoutes::unsent`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub unsent: bool,
    /// [`ObjectRoutes::written`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub written: bool,
    /// A friend answered that it holds a copy ([`ObjectRoutes::custodians_held`]
    /// was not empty); which friends is not kept.
    #[serde(default, skip_serializing_if = "is_false")]
    pub with_friend: bool,
}

impl RouteEvidence {
    fn of(r: &ObjectRoutes) -> Self {
        Self {
            expires_at_ms: r.expires_at_ms,
            unsent: r.unsent,
            written: r.written,
            with_friend: !r.custodians_held.is_empty(),
        }
    }

    /// Says something no record says (otherwise it is not kept).
    fn holds(&self) -> bool {
        self.unsent || self.written || self.with_friend
    }
}

/// [`OUTBOX_ROUTES_FILE`]. `objects` is decoded entry by entry (Phase 5,
/// RNL1 §11): one entry this build cannot parse (a newer build's carrier
/// or choice) no longer makes the whole file unreadable.
#[derive(Debug, Default)]
struct RouteFile {
    /// Message id (hex) -> its record, while its envelope is valid. Files
    /// from older builds (per peer) simply hold no objects.
    objects: BTreeMap<String, ObjectRoutes>,
    /// Message id (hex) -> an entry of `objects` this build cannot parse:
    /// never planned, written back unchanged (but for what
    /// [`set_object_written`] and [`clear_peer_routes`] say of every record),
    /// aged by its own `expires_at_ms` like the others ([`age_route_file`])
    /// and counted against [`MAX_ROUTE_OBJECTS`]. Never re-recorded by this
    /// build ([`record_object_routes`]), so its send's choice is never
    /// widened here.
    unknown: BTreeMap<String, serde_json::Value>,
    /// Message id (hex) -> what an expired record keeps
    /// ([`ROUTE_EVIDENCE_KEEP_MS`]). Older builds ignore it.
    ended: BTreeMap<String, RouteEvidence>,
}

/// [`RouteFile`] as read: `objects` still as JSON values.
#[derive(Deserialize)]
struct RouteFileIn {
    #[serde(default)]
    objects: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    ended: BTreeMap<String, RouteEvidence>,
}

/// [`RouteFile`] as written: the same bytes as before the per-entry
/// decoding for a file without unknown entries.
#[derive(Serialize)]
struct RouteFileOut<'a> {
    objects: BTreeMap<&'a str, RouteEntryOut<'a>>,
    #[serde(skip_serializing_if = "no_evidence")]
    ended: &'a BTreeMap<String, RouteEvidence>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum RouteEntryOut<'a> {
    Known(&'a ObjectRoutes),
    Unknown(&'a serde_json::Value),
}

fn no_evidence(ended: &&BTreeMap<String, RouteEvidence>) -> bool {
    ended.is_empty()
}

impl<'de> Deserialize<'de> for RouteFile {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = RouteFileIn::deserialize(d)?;
        let mut file = RouteFile {
            ended: raw.ended,
            ..RouteFile::default()
        };
        for (key, value) in raw.objects {
            match ObjectRoutes::deserialize(&value) {
                Ok(record) => {
                    file.objects.insert(key, record);
                }
                Err(_) => {
                    file.unknown.insert(key, value);
                }
            }
        }
        Ok(file)
    }
}

impl Serialize for RouteFile {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let objects = self
            .objects
            .iter()
            .map(|(k, r)| (k.as_str(), RouteEntryOut::Known(r)))
            .chain(
                self.unknown
                    .iter()
                    .filter(|(k, _)| !self.objects.contains_key(*k))
                    .map(|(k, v)| (k.as_str(), RouteEntryOut::Unknown(v))),
            )
            .collect();
        RouteFileOut {
            objects,
            ended: &self.ended,
        }
        .serialize(s)
    }
}

/// An unknown entry's deadline (`expires_at_ms`, the one field every build's
/// record has); `None` when it has none.
fn unknown_expiry(entry: &serde_json::Value) -> Option<u64> {
    entry.get("expires_at_ms")?.as_u64()
}

/// What an unknown entry says about whether its object left this computer,
/// read field by field as [`ObjectRoutes`] names them (a field it lacks or
/// cannot read says no).
fn unknown_evidence(entry: &serde_json::Value) -> Option<RouteEvidence> {
    let flag = |name: &str| entry.get(name).and_then(serde_json::Value::as_bool) == Some(true);
    Some(RouteEvidence {
        expires_at_ms: unknown_expiry(entry)?,
        unsent: flag("unsent"),
        written: flag("written"),
        with_friend: entry
            .get("custodians_held")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|held| !held.is_empty()),
    })
}

/// A `host:port` the carriers can dial (port 1-65535, no spaces, not an
/// address or the "local listen" placeholder).
pub fn plausible_dial(dial: &str) -> bool {
    let t = dial.trim();
    if t.is_empty()
        || t.len() > MAX_DIAL_CHARS
        || t.contains(char::is_whitespace)
        || t.starts_with("rvn1")
        || t.eq_ignore_ascii_case("local")
        || t.eq_ignore_ascii_case("local-listen")
    {
        return false;
    }
    let Some((host, port)) = t.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0)
}

/// [`plausible_dial`] for LAN and Internet routes; a strict
/// [`crate::p2p_route::parse_p2p_dial`] for p2p ones; a strict
/// [`nearby_dial_peer`] for nearby ones.
pub fn plausible_route(route: &OutboxRoute) -> bool {
    match route.carrier {
        OutboxCarrier::Lan | OutboxCarrier::Internet => plausible_dial(&route.dial),
        OutboxCarrier::P2p => crate::p2p_route::parse_p2p_dial(&route.dial).is_ok(),
        OutboxCarrier::Nearby => nearby_dial_peer(&route.dial).is_some(),
        OutboxCarrier::Onion => crate::onion::dial_hs_id(&route.dial).is_some(),
    }
}

/// The dial string of a nearby route: this prefix and the contact's device
/// key in 64 lowercase hex (RNL1 §7). A name for the contact the pipe is
/// knocked for, never an address.
pub const NEARBY_DIAL_PREFIX: &str = "nearby:";

/// The nearby route's dial string for `peer` ([`NEARBY_DIAL_PREFIX`]).
pub fn nearby_dial_for(peer: &[u8; 32]) -> String {
    format!("{NEARBY_DIAL_PREFIX}{}", hex::encode(peer))
}

/// The contact a nearby dial string names: exactly [`NEARBY_DIAL_PREFIX`]
/// and 64 lowercase hex digits (no spaces, no other case, no other prefix);
/// anything else is `None`.
pub fn nearby_dial_peer(dial: &str) -> Option<[u8; 32]> {
    let hex_part = dial.strip_prefix(NEARBY_DIAL_PREFIX)?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    hex::decode(hex_part).ok()?.try_into().ok()
}

/// The file, sealed (privacy pack PP.6: RMS1 kind 4 in a sealed profile) or
/// plain; missing is empty. `Err` when it cannot be read or parsed.
fn load_route_file(data_dir: &Path) -> Result<RouteFile, String> {
    let path = data_dir.join(OUTBOX_ROUTES_FILE);
    match crate::at_rest::load_json(data_dir, &path, crate::at_rest::Kind::OutboxRoutes) {
        Ok(file) => Ok(file.unwrap_or_default()),
        // Already "outbox_routes.json corrupt: <why>".
        Err(crate::at_rest::AtRestError::Json(text)) => Err(text),
        Err(e) => Err(format!("{OUTBOX_ROUTES_FILE}: {e}")),
    }
}

/// An expired record leaves `objects`: what says whether it left this
/// computer goes to `ended` ([`RouteEvidence`]; nothing else of it outlives
/// its envelope), which keeps it [`ROUTE_EVIDENCE_KEEP_MS`] and at most
/// [`MAX_ROUTE_OBJECTS`] of them. True when anything changed.
fn age_route_file(file: &mut RouteFile, now_ms: u64) -> bool {
    // The long message horizon (lab): a record outlives its envelope by the
    // horizon, so the message parked after it ran out
    // ([`extend_object_route_expiry`]) still finds its carrier choice, routes
    // and custody consent, whatever another write did meanwhile. Planning
    // never sees it unless parked ([`object_route_records`]); a finished
    // message clears its record ([`clear_object_routes`]).
    let grace = if crate::horizon::horizon_live_enabled() {
        crate::horizon::MESSAGE_HORIZON_MS
    } else {
        0
    };
    let expired: Vec<String> = file
        .objects
        .iter()
        .filter(|(_, r)| r.expires_at_ms.saturating_add(grace) <= now_ms)
        .map(|(k, _)| k.clone())
        .collect();
    // An unknown entry ages by its own deadline; one without a deadline is
    // no record of any build and goes now.
    let expired_unknown: Vec<String> = file
        .unknown
        .iter()
        .filter(|(_, v)| unknown_expiry(v).is_none_or(|e| e.saturating_add(grace) <= now_ms))
        .map(|(k, _)| k.clone())
        .collect();
    let changed = !expired.is_empty() || !expired_unknown.is_empty();
    for key in expired {
        if let Some(r) = file.objects.remove(&key) {
            let evidence = RouteEvidence::of(&r);
            if evidence.holds() {
                file.ended.insert(key, evidence);
            }
        }
    }
    for key in expired_unknown {
        if let Some(evidence) = file
            .unknown
            .remove(&key)
            .as_ref()
            .and_then(unknown_evidence)
        {
            if evidence.holds() {
                file.ended.insert(key, evidence);
            }
        }
    }
    let before = file.ended.len();
    file.ended
        .retain(|_, e| e.expires_at_ms.saturating_add(ROUTE_EVIDENCE_KEEP_MS) > now_ms);
    while file.ended.len() > MAX_ROUTE_OBJECTS {
        // The one that ran out first goes first.
        let Some(first) = file
            .ended
            .iter()
            .min_by_key(|(_, e)| e.expires_at_ms)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        file.ended.remove(&first);
    }
    changed || file.ended.len() != before
}

/// Rewrite the file under its lock with `edit`, after ageing it
/// ([`age_route_file`]): `edit` sees only live records in `objects`. Plain
/// bytes that do not parse are replaced (it holds hints only); a file this
/// process could not read (privacy pack PP.6: a sealed one whose key is not
/// loaded, a changed byte) is never written over: an error, counted
/// ([`crate::at_rest::note_skipped_write`]).
fn edit_route_file(
    data_dir: &Path,
    now_ms: u64,
    edit: impl FnOnce(&mut RouteFile),
) -> Result<(), String> {
    let path = data_dir.join(OUTBOX_ROUTES_FILE);
    let _lock = DataDirLock::acquire(data_dir, OUTBOX_ROUTES_LOCK)?;
    let existed = path.exists();
    let mut file: RouteFile =
        crate::at_rest::load_json_for_write(data_dir, &path, crate::at_rest::Kind::OutboxRoutes)
            .map_err(|e| format!("{OUTBOX_ROUTES_FILE} kept as it is: {e}"))?;
    let pruned = age_route_file(&mut file, now_ms);
    let snapshot = serde_json::to_vec(&file).unwrap_or_default();
    edit(&mut file);
    // A new record of an object replaces what an expired one of it kept,
    // and an entry of it this build could not parse.
    let RouteFile {
        objects,
        unknown,
        ended,
    } = &mut file;
    ended.retain(|k, _| !objects.contains_key(k));
    unknown.retain(|k, _| !objects.contains_key(k));
    while file.objects.len() + file.unknown.len() > MAX_ROUTE_OBJECTS {
        // The entry that expires first goes first.
        let known = file
            .objects
            .iter()
            .min_by_key(|(_, r)| r.expires_at_ms)
            .map(|(k, r)| (r.expires_at_ms, k.clone()));
        let unknown = file
            .unknown
            .iter()
            .map(|(k, v)| (unknown_expiry(v).unwrap_or(0), k))
            .min()
            .map(|(e, k)| (e, k.clone()));
        match (known, unknown) {
            (Some((known_e, _)), Some((e, key))) if e < known_e => {
                file.unknown.remove(&key);
            }
            (Some((_, key)), _) => {
                file.objects.remove(&key);
            }
            (None, Some((_, key))) => {
                file.unknown.remove(&key);
            }
            (None, None) => break,
        }
    }
    let changed = pruned || serde_json::to_vec(&file).unwrap_or_default() != snapshot;
    if !changed || (!existed && file.objects.is_empty() && file.ended.is_empty()) {
        return Ok(());
    }
    let out = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
    // Under OUTBOX_ROUTES_LOCK: sealed in a sealed profile.
    crate::at_rest::write_held(data_dir, &path, crate::at_rest::Kind::OutboxRoutes, &out)
        .map_err(|e| e.to_string())
}

/// Remember, for the queued object `message_id`, the carrier choice and routes
/// of the send that queued it, until its envelope expires.
///
/// An object already recorded keeps its own send's carrier choice: a later
/// send that re-notes it (an earlier row it dialled) only refreshes its routes
/// within that choice, so a `--carrier lan` row never widens and an `auto` row
/// never narrows. A caller that must change an object's choice clears its
/// record first ([`clear_object_routes`]).
pub fn record_object_routes(
    data_dir: &Path,
    message_id: &[u8; 16],
    peer_device: &[u8; 32],
    choice: CarrierChoice,
    routes: &[OutboxRoute],
    expires_at_ms: u64,
    now_ms: u64,
) -> Result<(), String> {
    if expires_at_ms <= now_ms {
        return Ok(());
    }
    // A nearby or onion route is derived live for each plan
    // ([`with_nearby_route`], [`with_onion_route`]): never stored. Only a
    // `--carrier nearby` choice says "nearby" here.
    let routes: Vec<OutboxRoute> = routes
        .iter()
        .filter(|r| {
            !matches!(r.carrier, OutboxCarrier::Nearby | OutboxCarrier::Onion)
                && plausible_route(r)
                && choice.allows(r.carrier)
        })
        .take(MAX_ROUTES_PER_OBJECT)
        .map(|r| OutboxRoute {
            carrier: r.carrier,
            dial: r.dial.trim().to_string(),
        })
        .collect();
    let mut record = ObjectRoutes {
        peer_pub_hex: hex::encode(peer_device),
        choice,
        routes,
        expires_at_ms,
        unsent: false,
        written: false,
        custodians_held: Vec::new(),
        custody_forwarded: false,
        custody: false,
    };
    edit_route_file(data_dir, now_ms, |file| {
        let key = hex::encode(message_id);
        // A newer build's record of it: its choice is unknown here, so it is
        // left as it is (never widened or narrowed by this build).
        if file.unknown.contains_key(&key) {
            return;
        }
        // Re-recording routes never says anything about whether it was sent,
        // which friends hold a copy, or which carriers its own send allowed.
        if let Some(old) = file.objects.get(&key) {
            record.unsent = old.unsent;
            record.written = old.written;
            record.custodians_held = old.custodians_held.clone();
            record.custody_forwarded = old.custody_forwarded;
            record.custody = old.custody;
            // The carrier choice is its own send's (G4): never re-decided here.
            record.choice = old.choice;
            record.routes.retain(|r| old.choice.allows(r.carrier));
        }
        file.objects.insert(key, record);
    })
}

/// Keep the record of `message_id` until `deadline_ms` (its message's
/// deadline, the long message horizon: [`park_expired_message`]), so its
/// carrier choice, routes and custody consent outlive its envelope and are
/// planned again ([`object_route_records`]). A record whose envelope ran
/// out is still there while the horizon is live ([`age_route_file`]); a
/// later expiry is never shortened. Whether a record was kept.
pub fn extend_object_route_expiry(
    data_dir: &Path,
    message_id: &[u8; 16],
    deadline_ms: u64,
    now_ms: u64,
) -> Result<bool, String> {
    if deadline_ms <= now_ms || !data_dir.join(OUTBOX_ROUTES_FILE).exists() {
        return Ok(false);
    }
    let key = hex::encode(message_id);
    let mut kept = false;
    edit_route_file(data_dir, now_ms, |file| {
        if let Some(record) = file.objects.get_mut(&key) {
            kept = true;
            record.expires_at_ms = record.expires_at_ms.max(deadline_ms);
        }
    })?;
    Ok(kept)
}

/// Friend custody is allowed for `message_id` (its own send asked for no
/// particular carrier). Only ever set by that send; a message without a
/// record is left alone.
pub fn set_object_custody(
    data_dir: &Path,
    message_id: &[u8; 16],
    now_ms: u64,
) -> Result<(), String> {
    edit_route_file(data_dir, now_ms, |file| {
        if let Some(record) = file.objects.get_mut(&hex::encode(message_id)) {
            record.custody = true;
        }
    })
}

/// Friend custody: `custodians` now hold a copy of `message_id` (idempotent
/// union). A message without a record is left alone.
pub fn add_object_custodians(
    data_dir: &Path,
    message_id: &[u8; 16],
    custodians: &[[u8; 32]],
    now_ms: u64,
) -> Result<(), String> {
    add_object_holds(data_dir, message_id, custodians, false, now_ms)
}

/// [`add_object_custodians`], and with `forwarded` one of them took it to
/// pass on to the contact's own friend ([`ObjectRoutes::custody_forwarded`],
/// custody handoff). A message without a record is left alone.
pub fn add_object_holds(
    data_dir: &Path,
    message_id: &[u8; 16],
    custodians: &[[u8; 32]],
    forwarded: bool,
    now_ms: u64,
) -> Result<(), String> {
    edit_route_file(data_dir, now_ms, |file| {
        if let Some(record) = file.objects.get_mut(&hex::encode(message_id)) {
            for c in custodians {
                let c = hex::encode(c);
                if !record.custodians_held.contains(&c) {
                    record.custodians_held.push(c);
                }
            }
            record.custody_forwarded |= forwarded && !custodians.is_empty();
        }
    })
}

/// Forget the friends holding a copy of `message_id`: after a re-seal they
/// hold only the old copy (sealed under a session the contact lost), which
/// the contact can never fetch, so the new copy must be left again.
pub fn clear_object_custodians(
    data_dir: &Path,
    message_id: &[u8; 16],
    now_ms: u64,
) -> Result<(), String> {
    edit_route_file(data_dir, now_ms, |file| {
        if let Some(record) = file.objects.get_mut(&hex::encode(message_id)) {
            record.custodians_held.clear();
            record.custody_forwarded = false;
        }
    })
}

/// Mark whether `message_id` has been written by a carrier yet (see
/// [`ObjectRoutes::unsent`]). A message without a record is left alone.
pub fn set_object_unsent(
    data_dir: &Path,
    message_id: &[u8; 16],
    unsent: bool,
    now_ms: u64,
) -> Result<(), String> {
    edit_route_file(data_dir, now_ms, |file| {
        if let Some(record) = file.objects.get_mut(&hex::encode(message_id)) {
            record.unsent = unsent;
        }
    })
}

/// `message_id` was written by a carrier and read by the contact, which
/// refused it, while the store keeps it prepared (see
/// [`ObjectRoutes::written`]). A message without a record gets a bare one
/// (LAN from the contact book, no routes, no custody: what no record plans);
/// a caller that knows its send's carrier choice records that first.
pub fn set_object_written(
    data_dir: &Path,
    message_id: &[u8; 16],
    peer_device: &[u8; 32],
    expires_at_ms: u64,
    now_ms: u64,
) -> Result<(), String> {
    if expires_at_ms <= now_ms {
        return Ok(());
    }
    edit_route_file(data_dir, now_ms, |file| {
        let key = hex::encode(message_id);
        // A newer build's record of it says so too, as it is otherwise.
        if let Some(entry) = file
            .unknown
            .get_mut(&key)
            .and_then(serde_json::Value::as_object_mut)
        {
            entry.insert("written".into(), serde_json::Value::Bool(true));
            return;
        }
        file.objects
            .entry(key)
            .or_insert_with(|| ObjectRoutes {
                peer_pub_hex: hex::encode(peer_device),
                choice: CarrierChoice::Lan,
                routes: Vec::new(),
                expires_at_ms,
                unsent: false,
                written: false,
                custodians_held: Vec::new(),
                custody_forwarded: false,
                custody: false,
            })
            .written = true;
    })
}

/// The live records, by message id (expired ones are not returned).
pub fn object_route_records(
    data_dir: &Path,
    now_ms: u64,
) -> Result<BTreeMap<[u8; 16], ObjectRoutes>, String> {
    Ok(load_route_file(data_dir)?
        .objects
        .into_iter()
        .filter(|(_, r)| r.expires_at_ms > now_ms)
        .filter_map(|(k, r)| {
            let id: [u8; 16] = hex::decode(k).ok()?.try_into().ok()?;
            Some((id, r))
        })
        .collect())
}

/// Whether objects ever left this computer, by message id: the live records
/// and what the expired ones keep ([`ROUTE_EVIDENCE_KEEP_MS`]); a live record
/// wins over an older expired one of the same id. Never for planning a dial:
/// that is [`object_route_records`].
pub fn object_route_evidence(
    data_dir: &Path,
    now_ms: u64,
) -> Result<BTreeMap<[u8; 16], RouteEvidence>, String> {
    let mut file = load_route_file(data_dir)?;
    let _ = age_route_file(&mut file, now_ms);
    let live = file
        .objects
        .iter()
        .map(|(k, r)| (k.clone(), RouteEvidence::of(r)))
        .chain(
            file.unknown
                .iter()
                .filter_map(|(k, v)| Some((k.clone(), unknown_evidence(v)?))),
        );
    Ok(file
        .ended
        .into_iter()
        .chain(live)
        .filter_map(|(k, e)| {
            let id: [u8; 16] = hex::decode(k).ok()?.try_into().ok()?;
            Some((id, e))
        })
        .collect())
}

/// Forget the records of these objects (delivered, given up, cancelled,
/// settled by the prune), and what they kept once expired.
pub fn clear_object_routes(data_dir: &Path, message_ids: &[[u8; 16]]) -> Result<(), String> {
    if message_ids.is_empty() || !data_dir.join(OUTBOX_ROUTES_FILE).exists() {
        return Ok(());
    }
    edit_route_file(data_dir, crate::clock::now_ms(), |file| {
        for id in message_ids {
            let key = hex::encode(id);
            file.objects.remove(&key);
            file.unknown.remove(&key);
            file.ended.remove(&key);
        }
    })
}

/// Forget the routes recorded for `peer_device`'s objects (contact removed, or
/// its addresses changed): the worker then plans from the contact book alone.
/// The records themselves stay until their envelope expires: whether an
/// object was ever written by a carrier, the carrier choice it was sent with
/// and its friend-custody marks are not stale.
pub fn clear_peer_routes(data_dir: &Path, peer_device: &[u8; 32]) -> Result<(), String> {
    if !data_dir.join(OUTBOX_ROUTES_FILE).exists() {
        return Ok(());
    }
    let key = hex::encode(peer_device);
    edit_route_file(data_dir, crate::clock::now_ms(), |file| {
        for r in file.objects.values_mut() {
            if r.peer_pub_hex.eq_ignore_ascii_case(&key) {
                r.routes.clear();
            }
        }
        // A newer build's record of the contact forgets its routes too.
        for entry in file
            .unknown
            .values_mut()
            .filter_map(serde_json::Value::as_object_mut)
        {
            let theirs = entry
                .get("peer_pub_hex")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|p| p.eq_ignore_ascii_case(&key));
            if theirs && entry.contains_key("routes") {
                entry.insert("routes".into(), serde_json::Value::Array(Vec::new()));
            }
        }
    })
}

/// Privacy pack PP.7: forget the records of objects the outbox no longer
/// holds (delivered, given up, cancelled or settled with their session while
/// a record stayed behind: a crash, a lost write), and what such objects
/// kept once expired. A record of an object the outbox holds stays under
/// today's rules ([`age_route_file`]). `in_outbox` reads the message ids the
/// store holds; it is asked after this file was read and before its lock is
/// taken, so no store is opened under the lock: a record written after that
/// read is never a candidate, and every writer records an object only once
/// the store holds it, so a candidate the store no longer holds has left it
/// for good. Lock-free first: no record, nothing else is read. How many
/// records went.
pub fn forget_finished_object_routes(
    data_dir: &Path,
    now_ms: u64,
    in_outbox: impl FnOnce() -> Result<std::collections::HashSet<[u8; 16]>, String>,
) -> Result<usize, String> {
    let file = load_route_file(data_dir)?;
    if file.objects.is_empty() && file.unknown.is_empty() && file.ended.is_empty() {
        return Ok(0);
    }
    let held: std::collections::HashSet<String> = in_outbox()?.iter().map(hex::encode).collect();
    let gone: std::collections::HashSet<String> = file
        .objects
        .keys()
        .chain(file.unknown.keys())
        .chain(file.ended.keys())
        .filter(|k| !held.contains(&k.to_ascii_lowercase()))
        .cloned()
        .collect();
    if gone.is_empty() {
        return Ok(0);
    }
    let mut removed = 0;
    edit_route_file(data_dir, now_ms, |file| {
        let count = |file: &RouteFile| file.objects.len() + file.unknown.len() + file.ended.len();
        let before = count(file);
        file.objects.retain(|k, _| !gone.contains(k));
        file.unknown.retain(|k, _| !gone.contains(k));
        file.ended.retain(|k, _| !gone.contains(k));
        removed = before - count(file);
    })?;
    Ok(removed)
}

// ── Verified contacts only beyond the LAN ───────────────────────────────────

/// Refusal / status code: the carrier needs a verified (pinned) contact.
pub const CONTACT_NOT_VERIFIED: &str = "CONTACT_NOT_VERIFIED";

/// May a contact use `carrier`? Owner decision 2026-10-08 (transports design
/// risk 5, Q15): unverified contacts are LAN only (and only at local-network
/// addresses, [`localize_lan_route`]); Internet direct, p2p and nearby
/// delivery (the "mesh" of that decision, arrived as the Bluetooth nearby
/// carrier, owner decision O5-12; later the mailbox) are only for a
/// **verified** contact, one whose fingerprint was confirmed out of band
/// (`pinned`: `--verify-fp` or the interactive verify). The one rule `raven
/// send`, the outbox worker, the IPC dial ops and the listeners / p2p
/// responder apply.
pub fn carrier_allowed_for_contact(carrier: OutboxCarrier, pinned: bool) -> bool {
    match carrier {
        OutboxCarrier::Lan => true,
        OutboxCarrier::Internet
        | OutboxCarrier::P2p
        | OutboxCarrier::Nearby
        | OutboxCarrier::Onion => pinned,
    }
}

/// Is `ip` on the local network: loopback, private (10/8, 172.16/12,
/// 192.168/16), link-local (169.254/16, fe80::/10) or unique-local (fc00::/7)?
/// IPv4-mapped IPv6 counts by its IPv4 address. Carrier-grade NAT space
/// (100.64/10), public and unspecified addresses do not count.
pub fn is_local_network_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let v4_local =
        |v4: std::net::Ipv4Addr| v4.is_loopback() || v4.is_private() || v4.is_link_local();
    match ip {
        IpAddr::V4(v4) => v4_local(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4_local(v4);
            }
            let first = v6.segments()[0];
            v6.is_loopback() || (first & 0xffc0) == 0xfe80 || (first & 0xfe00) == 0xfc00
        }
    }
}

/// How a dial error says macOS refused the connection itself: EHOSTUNREACH,
/// which macOS (and only it among RAVEN's systems) numbers 65.
const LOCAL_NETWORK_REFUSED_NEEDLE: &str = "no route to host (os error 65)";

/// Did macOS refuse this program's own connection to a local-network
/// address? macOS 15 and later do that, at once and with only "No route to
/// host", while the app that started the program has no Local Network
/// permission (System Settings > Privacy & Security > Local Network), and a
/// program started before the permission was given keeps being refused until
/// it is started again. The contact was never asked. True when `text` (a dial
/// error, `… 192.168.0.16:17420: No route to host (os error 65)`, any case)
/// says that of a local-network address ([`is_local_network_ip`]); a public
/// address's "no route" is a real one.
pub fn local_network_refused(text: &str) -> bool {
    !local_network_refused_at(text).is_empty() || {
        // A text whose addresses were left out ([`crate::ipc::without_addresses`])
        // keeps the local-network fact in its placeholder.
        let lower = text.to_ascii_lowercase();
        lower.contains(crate::ipc::LOCAL_ADDRESS_PLACEHOLDER)
            && lower.contains(LOCAL_NETWORK_REFUSED_NEEDLE)
    }
}

/// The local-network addresses `text` says macOS refused
/// ([`local_network_refused`]), each once, in order. raven-node's log line
/// weighs them against this computer's own networks (E1: a saved address
/// on another subnet is refused for real).
pub fn local_network_refused_at(text: &str) -> Vec<std::net::IpAddr> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    for (at, _) in lower.match_indices(LOCAL_NETWORK_REFUSED_NEEDLE) {
        let before = lower[..at].trim_end_matches([' ', '(', ':']);
        let addr = before.rsplit([' ', '(', ';']).next().unwrap_or_default();
        if let Ok(addr) = addr.parse::<std::net::SocketAddr>() {
            if is_local_network_ip(addr.ip()) && !out.contains(&addr.ip()) {
                out.push(addr.ip());
            }
        }
    }
    out
}

/// Does a delivery over the LAN route `route` (as it was dialled) show that
/// the local network works (cutoff F5)? Only at a local-network IP address
/// ([`is_local_network_ip`]) other than loopback: a verified contact's LAN
/// route may be any address (a friend's public IP on a national network),
/// and a contact on this computer says nothing about the network. A name is
/// never looked up again for this (no extra lookup on the network): an
/// unverified contact's name was dialled as its resolved literal
/// ([`localize_lan_route`]), and a verified contact's name route proves
/// nothing (its inbound links still do).
pub fn lan_route_proves_network(route: &OutboxRoute) -> bool {
    let ip = crate::lan_seen::split_host_port(route.dial.trim())
        .and_then(|(host, _)| host.split('%').next()?.parse::<std::net::IpAddr>().ok());
    route.carrier == OutboxCarrier::Lan
        && ip.is_some_and(|ip| is_local_network_ip(ip) && !ip.to_canonical().is_loopback())
}

/// Why a LAN route may not be used for an unverified contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteRefusal {
    /// It resolves (at least partly) outside the local network.
    NotLocal,
    /// It could not be resolved; nothing is known, so nothing is dialled.
    Unresolved(String),
}

/// The [`RouteRefusal::Unresolved`] reasons of an address that is not a
/// usable `host:port` at all: no later resolution can make it one.
const NOT_HOST_PORT: &str = "not host:port";
const BAD_PORT: &str = "bad port";
const BAD_SCOPED_V6: &str = "bad scoped IPv6";

impl RouteRefusal {
    /// A computer name that did not resolve now (no answer, no address,
    /// timed out): the computer may simply be away. Never a malformed
    /// address (not `host:port`, a bad port, a bad scoped IPv6 literal) and
    /// never [`RouteRefusal::NotLocal`].
    pub fn is_unresolved_name(&self) -> bool {
        match self {
            Self::NotLocal => false,
            Self::Unresolved(e) => ![NOT_HOST_PORT, BAD_PORT, BAD_SCOPED_V6].contains(&e.as_str()),
        }
    }
}

/// How long [`localize_lan_route`] waits for a name to resolve.
pub const LOCALIZE_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// The LAN route to dial for a contact: unchanged for a verified contact (and
/// for any non-LAN route); for an unverified one, `host:port` must be on the
/// local network ([`is_local_network_ip`]): a literal as it is, a name by
/// what it resolves to ([`pick_local`]: with the offline-LAN gate open its
/// first local-network address, else only when every address is local). The
/// route to dial is the resolved literal, so a later resolution cannot point
/// it elsewhere. A `[v6%zone]:port` literal keeps its zone.
pub fn localize_lan_route(
    route: &OutboxRoute,
    pinned: bool,
    timeout: Duration,
) -> Result<OutboxRoute, RouteRefusal> {
    localize_lan_route_with(
        route,
        pinned,
        timeout,
        crate::lan_gate::offline_lan_live(),
        resolve_within,
    )
}

/// What `name` resolves to on `port`, within `timeout` (on a thread of its
/// own: the system resolver has no timeout).
fn resolve_within(
    name: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<std::net::SocketAddr>, RouteRefusal> {
    let name = name.to_string();
    crate::lab_audit::dns();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::net::ToSocketAddrs;
        let _ = tx.send(
            (name.as_str(), port)
                .to_socket_addrs()
                .map(|it| it.collect::<Vec<_>>()),
        );
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(e)) => Err(RouteRefusal::Unresolved(e.to_string())),
        Err(_) => Err(RouteRefusal::Unresolved("resolution timed out".into())),
    }
}

/// The address to dial for an unverified contact among what its name
/// resolved to (`addrs`, at least one). `any_local` (cutoff F1, the
/// offline-LAN gate): the first local-network one, refused only when none is
/// local, so a computer whose name also carries a global IPv6 address (a
/// home network with an IPv6 prefix) is still reached at its local one.
/// Closed (the rule before the pack): every address must be local, and the
/// first is dialled. Either way only a local-network address is dialled.
fn pick_local(
    addrs: &[std::net::SocketAddr],
    any_local: bool,
) -> Result<std::net::SocketAddr, RouteRefusal> {
    let local = |a: &&std::net::SocketAddr| is_local_network_ip(a.ip());
    let picked = if any_local {
        addrs.iter().find(local)
    } else if addrs.iter().all(|a| local(&a)) {
        addrs.first()
    } else {
        None
    };
    picked.copied().ok_or(RouteRefusal::NotLocal)
}

/// [`localize_lan_route`] with the gate and the resolver passed in.
fn localize_lan_route_with(
    route: &OutboxRoute,
    pinned: bool,
    timeout: Duration,
    any_local: bool,
    resolve: impl FnOnce(&str, u16, Duration) -> Result<Vec<std::net::SocketAddr>, RouteRefusal>,
) -> Result<OutboxRoute, RouteRefusal> {
    if pinned || route.carrier != OutboxCarrier::Lan {
        return Ok(route.clone());
    }
    let dial = route.dial.trim();
    if let Ok(addr) = dial.parse::<std::net::SocketAddr>() {
        return if is_local_network_ip(addr.ip()) {
            Ok(route.clone())
        } else {
            Err(RouteRefusal::NotLocal)
        };
    }
    let (host, port) = dial
        .rsplit_once(':')
        .ok_or_else(|| RouteRefusal::Unresolved(NOT_HOST_PORT.into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| RouteRefusal::Unresolved(BAD_PORT.into()))?;
    let inner = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Some((ip, _zone)) = inner.split_once('%') {
        // A scoped IPv6 literal (`fe80::1%en0`): local only if link-local / ULA.
        let ip: std::net::Ipv6Addr = ip
            .parse()
            .map_err(|_| RouteRefusal::Unresolved(BAD_SCOPED_V6.into()))?;
        return if is_local_network_ip(ip.into()) {
            Ok(route.clone())
        } else {
            Err(RouteRefusal::NotLocal)
        };
    }
    let addrs = resolve(inner, port, timeout)?;
    if addrs.is_empty() {
        return Err(RouteRefusal::Unresolved("no address".into()));
    }
    Ok(OutboxRoute {
        carrier: OutboxCarrier::Lan,
        dial: pick_local(&addrs, any_local)?.to_string(),
    })
}

/// What the local contact book says about one key: its saved routes (LAN
/// first, then Internet, then p2p) and whether it is verified.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContactRoutes {
    pub routes: Vec<OutboxRoute>,
    pub pinned: bool,
    /// The contact's libp2p PeerId and `via=` addresses, when it has them:
    /// what a `/p2p/<PeerId>` route dials (hints only, never identity).
    pub p2p: Option<crate::p2p_route::ContactP2p>,
    /// This node hides its IP from the contact (D4): no Internet direct
    /// dial, p2p through its own relays only. The book's `hide_ip` (any
    /// row); [`with_learned_routes`] adds the node policy's.
    pub hide_ip: bool,
    /// What the contact's route hints say about its PeerId
    /// ([`with_learned_routes`], verified contacts only). The p2p dialler
    /// merges it with `p2p` ([`crate::p2p_route::P2pDialSet::merge`]: the
    /// book's PeerId wins). Boxed: it keeps [`ContactAdmission`] small.
    pub p2p_learned: Option<Box<crate::learned_routes::LearnedP2p>>,
    /// `raven lan verified-only on` (Phase 3 P3.C2): the node policy's
    /// `lan_verified_only`, which [`with_learned_routes`] adds. An unverified
    /// contact then gets no LAN route ([`ContactRoutes::allows`]).
    pub lan_verified_only: bool,
    /// The contact's onion binding from the book (a card's `onion=`), only
    /// one that verifies against the row's key
    /// ([`crate::onion::OnionBinding::verify`]); the newest of several
    /// rows. [`with_onion_route`] plans from it (or a newer learned one).
    pub onion: Option<crate::onion::OnionBinding>,
    /// The book's LAN routes that keep the local-network rule even for a
    /// verified contact ([`Self::lan_local_only`]): one a card gave (nobody
    /// signs a card's route fields; the security words cover the key
    /// only), or one saved before the book recorded where it came from.
    pub card_lan: Vec<String>,
}

impl ContactRoutes {
    /// Is `route` one of the book's LAN routes that only a local-network
    /// address may answer, whatever the verified state ([`Self::card_lan`])?
    /// Only a LAN address this computer's user typed, or one learned from
    /// the contact's own authenticated link, may lie beyond the local
    /// network for a verified contact.
    pub fn lan_local_only(&self, route: &OutboxRoute) -> bool {
        route.carrier == OutboxCarrier::Lan
            && self.card_lan.iter().any(|dial| dial == route.dial.trim())
    }

    /// The `pinned` to localize `route` with ([`localize_lan_route`]): the
    /// contact is verified, and `route` is not a LAN route that keeps the
    /// local-network rule ([`Self::lan_local_only`]).
    pub fn localize_pinned(&self, route: &OutboxRoute) -> bool {
        self.pinned && !self.lan_local_only(route)
    }

    /// May this contact be reached over `carrier`:
    /// [`carrier_allowed_for_contact`], and on the LAN under `raven lan
    /// verified-only on` a verified contact only.
    pub fn allows(&self, carrier: OutboxCarrier) -> bool {
        carrier_allowed_for_contact(carrier, self.pinned)
            && (carrier != OutboxCarrier::Lan || self.pinned || !self.lan_verified_only)
    }
}

#[derive(Debug, Deserialize)]
struct ContactRouteRow {
    #[serde(default)]
    pub_hex: String,
    #[serde(default)]
    pinned: bool,
    #[serde(default)]
    lan_dial: String,
    #[serde(default)]
    internet_dial: String,
    /// libp2p PeerId (`raven contact set-addr --p2p`, a card's `p2p=`).
    #[serde(default)]
    p2p: String,
    /// Relay (or direct) multiaddrs for it (a card's `via=`).
    #[serde(default)]
    p2p_via: Vec<String>,
    /// The PeerId of the contact's next epoch (a `raven-card/3`'s `p2pn=`,
    /// Phase 4 PeerId rotation); empty: none.
    #[serde(default)]
    p2p_next: String,
    /// Hide this node's IP from the contact (`raven contact hide-ip`).
    #[serde(default)]
    hide_ip: bool,
    /// The contact's onion binding (a card's `onion=`, base64url,
    /// [`crate::onion::OnionBinding::from_text`]); empty: none.
    #[serde(default)]
    onion: String,
    /// `lan_dial` was typed on this computer, or learned from the contact's
    /// own authenticated link; false (or absent, a book from before) for a
    /// card's `lan=`, which then keeps the local-network rule
    /// ([`ContactRoutes::card_lan`]).
    #[serde(default)]
    lan_dial_trusted: bool,
}

/// The contact whose key is `peer_device`, or `None` when there is none. An
/// unreadable or corrupt book is an error (callers fail closed).
pub fn contact_routes(
    data_dir: &Path,
    peer_device: &[u8; 32],
) -> Result<Option<ContactRoutes>, String> {
    let Some(rows) = crate::contact_book::read_rows::<ContactRouteRow>(data_dir)? else {
        return Ok(None);
    };
    let key = hex::encode(peer_device);
    let mut found: Option<ContactRoutes> = None;
    for row in rows
        .iter()
        .filter(|r| r.pub_hex.trim().eq_ignore_ascii_case(&key))
    {
        let entry = found.get_or_insert_with(|| ContactRoutes {
            routes: Vec::new(),
            pinned: true,
            p2p: None,
            hide_ip: false,
            p2p_learned: None,
            lan_verified_only: false,
            onion: None,
            card_lan: Vec::new(),
        });
        // Several rows for one key (an old book): verified only if all are,
        // hidden if any is.
        entry.pinned &= row.pinned;
        entry.hide_ip |= row.hide_ip;
        // Only a binding the contact's own key signed: never an unsigned
        // onion address, never one signed by anyone else.
        let onion = crate::onion::OnionBinding::from_text(row.onion.trim())
            .filter(|b| b.verify(peer_device, crate::onion::now_s()));
        entry.onion = crate::onion::newest(entry.onion, onion);
        for (carrier, dial) in [
            (OutboxCarrier::Lan, &row.lan_dial),
            (OutboxCarrier::Internet, &row.internet_dial),
        ] {
            if plausible_dial(dial) {
                if carrier == OutboxCarrier::Lan && !row.lan_dial_trusted {
                    entry.card_lan.push(dial.trim().to_string());
                }
                entry.routes.push(OutboxRoute {
                    carrier,
                    dial: dial.trim().to_string(),
                });
            }
        }
        // One p2p route per PeerId: the dialer tries its addresses in order.
        if entry.p2p.is_none() {
            if let Some(p2p) = crate::p2p_route::ContactP2p::from_fields(&row.p2p, &row.p2p_via) {
                entry.routes.push(OutboxRoute {
                    carrier: OutboxCarrier::P2p,
                    dial: crate::p2p_route::peer_route(&p2p.peer_id),
                });
                entry.p2p = Some(p2p);
            }
        }
    }
    if let Some(entry) = found.as_mut() {
        entry.routes.sort_by_key(|r| r.carrier);
    }
    Ok(found)
}

/// May this node tell `peer` its IP addresses (D4)? False when it hides its
/// IP from every contact (node policy `hide_ip`, also when the policy is
/// unreadable) or from this one (the book's `hide_ip`), or when the book
/// cannot be read. Nothing hidden (no such contact either) is true.
pub fn may_share_ip(data_dir: &Path, peer: &[u8; 32]) -> bool {
    if crate::node_policy::load_policy(data_dir).hide_ip {
        return false;
    }
    match contact_routes(data_dir, peer) {
        Ok(contact) => !contact.is_some_and(|c| c.hide_ip),
        Err(_) => false,
    }
}

/// `contact` plus what was learned about reaching it, after its saved routes
/// within each carrier: where it last reached us from ([`crate::lan_seen`])
/// and, while route hints are live ([`crate::route_hints::route_hints_live`]),
/// what it told us ([`crate::learned_routes`]): its announced LAN port (also
/// past the hint's expiry, for [`crate::learned_routes::LAN_KEEP_MS`] after
/// it came: Phase 3 P3.C1), and for a verified contact its PeerId (a
/// `/p2p/<PeerId>` route when the book has none). Learned LAN routes total
/// at most [`crate::learned_routes::MAX_LEARNED_LAN_DIALS`], and never push
/// a p2p route past `MAX_ROUTES_PER_OBJECT`. The node policy's `hide_ip` is
/// added too, whatever the gate: `raven node hide-ip on` holds for every
/// planner (as [`may_share_ip`] does for the p2p dial); so is its
/// `lan_verified_only` (Phase 3 P3.C2: no LAN route for an unverified
/// contact, [`ContactRoutes::allows`]).
///
/// Last, under cutoff F7 ([`default_port_guess_live`]), a contact with no
/// LAN route at all is tried where it last reached us from, on the default
/// LAN port ([`with_default_port_sighting`]).
///
/// With route hints and F7 off the routes are exactly
/// [`with_learned_lan_routes`]' (release plans are byte-identical: the
/// policy's `hide_ip` only drops Internet direct routes, which release
/// builds never plan). For the delivery planners only, after admission
/// ([`contact_admission`]).
pub fn with_learned_routes(
    data_dir: &Path,
    peer_device: &[u8; 32],
    contact: ContactRoutes,
) -> ContactRoutes {
    with_learned_routes_where(data_dir, peer_device, contact, |_| true)
}

/// [`with_learned_routes`], but a learned local-network address that `keep`
/// refuses is left out, as in [`with_learned_lan_routes_where`].
pub fn with_learned_routes_where(
    data_dir: &Path,
    peer_device: &[u8; 32],
    contact: ContactRoutes,
    keep: impl Fn(std::net::IpAddr) -> bool,
) -> ContactRoutes {
    with_learned_routes_gated(data_dir, peer_device, contact, keep, LearnedGates::now())
}

/// At most this many of the LAN beacon's finds go into a plan
/// (RAVEN_LAN_BEACON_V1 §9). With a saved LAN route, an Internet route and a
/// p2p route that makes 5, within `MAX_ROUTES_PER_OBJECT`.
pub const MAX_BEACON_LAN_ROUTES: usize = 2;

/// Where the LAN beacon found a contact's LAN listener (RAVEN_LAN_BEACON_V1
/// §9), as the dial strings a plan takes: an IP literal at a local-network
/// address ([`is_local_network_ip`]; an IPv6 link-local one only with its
/// zone) and a port, written as [`crate::lan_seen::ScopedIp::dial`] writes
/// it, each once, IPv4 first (within a family in the order given), at most
/// [`MAX_BEACON_LAN_ROUTES`]. Anything else (a name, a public address, no
/// port) is left out: a find is local by construction, so this only checks
/// what raven-node's beacon or its IPC `LanLocate` handed over.
pub fn beacon_lan_dials(sightings: &[String]) -> Vec<String> {
    let mut found: Vec<(bool, String)> = Vec::new();
    for sighting in sightings {
        let Some((host, port)) = crate::lan_seen::split_host_port(sighting.trim()) else {
            continue;
        };
        let Some(ip) = crate::lan_seen::ScopedIp::parse(host)
            .filter(|ip| ip.dialable() && is_local_network_ip(ip.ip()))
        else {
            continue;
        };
        let dial = ip.dial(port);
        if !found.iter().any(|(_, known)| *known == dial) {
            found.push((ip.ip().is_ipv6(), dial));
        }
    }
    // Stable: within a family the order given (the beacon's newest first).
    found.sort_by_key(|(v6, _)| *v6);
    found
        .into_iter()
        .take(MAX_BEACON_LAN_ROUTES)
        .map(|(_, dial)| dial)
        .collect()
}

/// `contact` with the LAN beacon's finds (`sightings`, RAVEN_LAN_BEACON_V1
/// §9) first among its LAN routes: [`beacon_lan_dials`] (at most two, IPv4
/// first, local-network addresses only). Its own routes stay after them in
/// their order, the saved LAN route first; a find it already has moves to
/// the front. While there are finds, callers plan `contact` with
/// [`with_learned_routes_where`] and `keep = |_| false` first, so the
/// learned LAN routes of `lan_seen` and RRH1 (older evidence of the same
/// contact) are not added. A find the contact does not have takes only the
/// room left under `MAX_ROUTES_PER_OBJECT`, so the plan's p2p route (last)
/// is never cut off. No usable find: `contact` as it was. Nothing here is
/// written anywhere.
pub fn with_beacon_lan_routes(mut contact: ContactRoutes, sightings: &[String]) -> ContactRoutes {
    let has = |contact: &ContactRoutes, dial: &str| {
        contact
            .routes
            .iter()
            .any(|r| r.carrier == OutboxCarrier::Lan && r.dial == dial)
    };
    let mut room = MAX_ROUTES_PER_OBJECT.saturating_sub(contact.routes.len());
    let mut front: Vec<String> = Vec::new();
    for dial in beacon_lan_dials(sightings) {
        if has(&contact, &dial) {
            front.push(dial);
        } else if room > 0 {
            room -= 1;
            front.push(dial);
        }
    }
    if front.is_empty() {
        return contact;
    }
    contact
        .routes
        .retain(|r| !(r.carrier == OutboxCarrier::Lan && front.contains(&r.dial)));
    // LAN first, as in every plan: the finds lead the LAN routes.
    contact.routes.splice(
        0..0,
        front.into_iter().map(|dial| OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial,
        }),
    );
    contact
}

/// [`with_learned_routes_where`] with the gates as an argument (the custody
/// planner's tests).
pub(crate) fn with_learned_routes_gated(
    data_dir: &Path,
    peer_device: &[u8; 32],
    contact: ContactRoutes,
    keep: impl Fn(std::net::IpAddr) -> bool,
    gates: LearnedGates,
) -> ContactRoutes {
    learned_routes_into(
        data_dir,
        peer_device,
        contact,
        keep,
        gates,
        &crate::route_memory::egress_tag,
        crate::clock::now_ms(),
    )
}

/// The gates [`learned_routes_into`] plans by.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LearnedGates {
    /// Route hints ([`crate::route_hints::route_hints_live`]).
    pub(crate) hints: bool,
    /// Cutoff F7 ([`default_port_guess_live`]).
    pub(crate) default_port: bool,
    /// Auto-reach: a verified contact's INET_DIRECT addresses (route hints
    /// spec §13.3) are planned ([`crate::stun_discovery_live_enabled`]).
    pub(crate) inet: bool,
}

impl LearnedGates {
    /// As this process reads them now.
    pub(crate) fn now() -> Self {
        Self {
            hints: crate::route_hints::route_hints_live(),
            default_port: default_port_guess_live(),
            inet: crate::stun_discovery_live_enabled(),
        }
    }
}

/// [`with_learned_routes_where`] with the gates, this computer's network now
/// (`here`, asked only when a LAN part has a tag) and the clock as
/// arguments.
fn learned_routes_into(
    data_dir: &Path,
    peer_device: &[u8; 32],
    contact: ContactRoutes,
    keep: impl Fn(std::net::IpAddr) -> bool,
    gates: LearnedGates,
    here: &dyn Fn() -> Option<String>,
    now_ms: u64,
) -> ContactRoutes {
    let lan_count = |c: &ContactRoutes| {
        c.routes
            .iter()
            .filter(|r| r.carrier == OutboxCarrier::Lan)
            .count()
    };
    let saved = lan_count(&contact);
    // The book's own LAN routes (they stay first, [`order_learned_lan`]).
    let book_lan: Vec<String> = contact
        .routes
        .iter()
        .filter(|r| r.carrier == OutboxCarrier::Lan)
        .map(|r| r.dial.clone())
        .collect();
    // F7 comes last on every path (hints off, nothing learned, RRH1's
    // routes): only a contact with no LAN route left gets the guess.
    let guess = |contact: ContactRoutes| {
        with_default_port_sighting(data_dir, peer_device, contact, &keep, gates.default_port)
    };
    let mut contact = with_learned_lan_routes_where(data_dir, peer_device, contact, &keep);
    let policy = crate::node_policy::load_policy(data_dir);
    contact.hide_ip |= policy.hide_ip;
    contact.lan_verified_only |= policy.lan_verified_only;
    if !gates.hints {
        return guess(contact);
    }
    // The live snapshot, and the LAN part to dial: its own, or one an
    // expired hint left (Phase 3 P3.C1: the LAN port of a friend met weekly).
    let (view, lan) = crate::learned_routes::learned_with_lan(data_dir, peer_device, now_ms);
    if view.is_none() && lan.is_none() {
        return guess(contact);
    }
    // A PeerId (and what it names) only from a verified contact.
    let p2p = view
        .as_ref()
        .and_then(crate::learned_routes::LearnedView::p2p)
        .filter(|_| contact.pinned);
    let p2p_route = p2p
        .as_ref()
        .filter(|_| contact.p2p.is_none())
        .map(|p| OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: crate::p2p_route::peer_route(&p.peer_id),
        });
    // lan_seen's routes count against the learned budget, and the plan's
    // p2p route (last) must stay within MAX_ROUTES_PER_OBJECT.
    let added = lan_count(&contact).saturating_sub(saved);
    let room = MAX_ROUTES_PER_OBJECT
        .saturating_sub(contact.routes.len() + usize::from(p2p_route.is_some()));
    let budget = crate::learned_routes::MAX_LEARNED_LAN_DIALS
        .saturating_sub(added)
        .min(room);
    let saved_lan: Vec<String> = contact
        .routes
        .iter()
        .filter(|r| r.carrier == OutboxCarrier::Lan)
        .map(|r| r.dial.clone())
        .collect();
    // Where it last reached us from, unless another contact came from there
    // too (a router's address, E2: never a contact's own).
    let seen = crate::lan_seen::usable_sighting(data_dir, peer_device, now_ms);
    // A LAN part learned on another network than this one plans nothing;
    // its IP is the link's peer address, as a sighting is, and is held to
    // the same rule.
    let lan = lan
        .filter(|l| l.local_tag.is_none() || l.on_network(here().as_deref()))
        .map(|mut l| {
            if l.ip.is_some_and(|ip| {
                crate::lan_seen::shared_with_another(data_dir, Some(peer_device), ip, now_ms)
            }) {
                l.ip = None;
            }
            l
        });
    // The contact's own addresses on this network, as its route hints name
    // them (its same-LAN DIRECT entries): an observed address among them is
    // its own, not a router's.
    let told_ips: Vec<std::net::IpAddr> = lan.as_ref().map_or(Vec::new(), |l| {
        l.local_direct
            .iter()
            .filter_map(|v| {
                let mut parts = v.text.split('/').skip(1);
                match (parts.next(), parts.next()) {
                    (Some("ip4" | "ip6"), Some(host)) => host.parse().ok(),
                    _ => None,
                }
            })
            .collect()
    });
    let rrh1_lan =
        crate::learned_routes::rrh1_lan_dials(lan.as_ref(), seen.as_ref(), &saved_lan, budget);
    for dial in rrh1_lan {
        // An unverified contact's learned address must be on the local
        // network, as its saved one (a name is checked at dial time).
        let allowed = learned_dial_kept(&dial, &keep)
            && dial
                .parse::<std::net::SocketAddr>()
                .map_or(true, |a| contact.pinned || is_local_network_ip(a.ip()));
        let known = contact
            .routes
            .iter()
            .any(|r| r.carrier == OutboxCarrier::Lan && r.dial == dial);
        if allowed && !known {
            contact.routes.push(OutboxRoute {
                carrier: OutboxCarrier::Lan,
                dial,
            });
        }
    }
    // Auto-reach (route hints spec §13.3): the public address of a verified
    // contact's Internet direct listener, after its saved Internet route,
    // confirmed ones first, within the room the p2p route (last) leaves.
    if gates.inet && contact.pinned {
        let mut found: Vec<(std::net::SocketAddr, bool)> =
            view.as_ref().map_or(Vec::new(), |v| v.inet.clone());
        found.sort_by_key(|(_, confirmed)| !*confirmed);
        for (addr, _) in found {
            let dial = addr.to_string();
            let known = contact
                .routes
                .iter()
                .any(|r| r.carrier == OutboxCarrier::Internet && r.dial == dial);
            let room = MAX_ROUTES_PER_OBJECT
                .saturating_sub(contact.routes.len() + usize::from(p2p_route.is_some()));
            if !known && room > 0 && learned_dial_kept(&dial, &keep) {
                contact.routes.push(OutboxRoute {
                    carrier: OutboxCarrier::Internet,
                    dial,
                });
            }
        }
    }
    contact.routes.extend(p2p_route);
    // The same-PeerId check is P2pDialSet::merge's: the book wins.
    contact.p2p_learned = p2p.map(Box::new);
    order_learned_lan(&mut contact.routes, &book_lan, |ip| {
        told_ips.contains(&ip.to_canonical())
            || crate::lan_seen::reached_at(data_dir, peer_device, ip, now_ms)
    });
    // Stable: within one carrier the saved address stays first.
    contact.routes.sort_by_key(|r| r.carrier);
    guess(contact)
}

/// The learned LAN routes after the saved ones (`saved`, in their order),
/// most trusted first (E2: mac-b's sends started at an address its friends
/// were merely seen from, a router's): the contact's saved host on the port
/// its route hints announce, then an address known to be its own
/// (`reached`: a dial reached its key there, or its route hints name it),
/// then any other address it was only seen at. Other carriers stay where
/// they are.
fn order_learned_lan(
    routes: &mut [OutboxRoute],
    saved: &[String],
    reached: impl Fn(std::net::IpAddr) -> bool,
) {
    let host_ip = |dial: &str| {
        crate::lan_seen::split_host_port(dial.trim())
            .and_then(|(h, _)| crate::lan_seen::ScopedIp::parse(h))
            .map(|a| a.ip())
    };
    let saved_ips: Vec<std::net::IpAddr> = saved.iter().filter_map(|d| host_ip(d)).collect();
    let saved_hosts: Vec<&str> = saved
        .iter()
        .filter_map(|d| crate::lan_seen::split_host_port(d.trim()).map(|(h, _)| h))
        .collect();
    let rank = |r: &OutboxRoute| -> u8 {
        if r.carrier != OutboxCarrier::Lan || saved.contains(&r.dial) {
            return 0;
        }
        let host = crate::lan_seen::split_host_port(r.dial.trim()).map(|(h, _)| h);
        match host_ip(&r.dial) {
            _ if host.is_some_and(|h| saved_hosts.contains(&h)) => 1,
            Some(ip) if saved_ips.contains(&ip) => 1,
            Some(ip) if reached(ip) => 2,
            _ => 3,
        }
    };
    let lan: Vec<usize> = (0..routes.len())
        .filter(|i| routes[*i].carrier == OutboxCarrier::Lan)
        .collect();
    let mut sorted: Vec<OutboxRoute> = lan.iter().map(|i| routes[*i].clone()).collect();
    // Each rank once: `reached` reads a file.
    sorted.sort_by_cached_key(&rank);
    for (slot, route) in lan.into_iter().zip(sorted) {
        routes[slot] = route;
    }
}

/// Cutoff F7's gate: [`crate::lan_gate::offline_lan_live`] and M0's
/// [`crate::lan_gate::lan_noise_pin_live`], both (a guess is only dialled
/// where a noise pin can tell who answers).
pub fn default_port_guess_live() -> bool {
    crate::lan_gate::offline_lan_live() && crate::lan_gate::lan_noise_pin_live()
}

/// Cutoff F7 (`live`: [`default_port_guess_live`]): a contact with **no**
/// LAN route at all (after its saved, lan_seen and RRH1 routes: one added
/// from an invite line, whose port nothing tells) is tried where it last
/// reached us from over an authenticated link, on the default LAN port
/// ([`crate::lan_seen::learned_lan_dial_default_port`]). So it never
/// displaces a real port and stays within the learned LAN budget and
/// `MAX_ROUTES_PER_OBJECT`; `keep` is asked as for the other learned routes.
///
/// Only for a contact with a noise pin (M0, [`crate::lan_noise_pin`]): that
/// address may belong to someone else by now, and whatever answers there
/// then gets Noise message 1 and nothing more. An unreadable pin store is no
/// pin. Pure in `live`: closed, `contact` comes back unchanged and nothing
/// is read.
pub fn with_default_port_sighting(
    data_dir: &Path,
    peer_device: &[u8; 32],
    mut contact: ContactRoutes,
    keep: impl Fn(std::net::IpAddr) -> bool,
    live: bool,
) -> ContactRoutes {
    let has_lan = contact
        .routes
        .iter()
        .any(|r| r.carrier == OutboxCarrier::Lan);
    if !live || has_lan || contact.routes.len() >= MAX_ROUTES_PER_OBJECT {
        return contact;
    }
    if !matches!(
        crate::lan_noise_pin::load_pin(data_dir, peer_device),
        Ok(Some(_))
    ) {
        return contact;
    }
    let Some(dial) = crate::lan_seen::learned_lan_dial_default_port(
        data_dir,
        peer_device,
        contact.pinned,
        crate::clock::now_ms(),
    ) else {
        return contact;
    };
    if learned_dial_kept(&dial, &keep) {
        contact.routes.push(OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial,
        });
        // LAN first, as in every plan.
        contact.routes.sort_by_key(|r| r.carrier);
    }
    contact
}

/// Whether a learned LAN `ip:port` passes `keep`: only a local-network
/// address ([`is_local_network_ip`], not loopback) is asked about. Anything
/// else (a public or loopback address, a name) is not ours to drop.
fn learned_dial_kept(dial: &str, keep: &impl Fn(std::net::IpAddr) -> bool) -> bool {
    match dial.parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            let ip = addr.ip();
            !is_local_network_ip(ip) || ip.is_loopback() || keep(ip)
        }
        Err(_) => true,
    }
}

/// `contact` plus where it last reached us from on its saved LAN port
/// ([`crate::lan_seen`]), after its saved LAN address: a contact whose address
/// changed (DHCP) is reached again. For the delivery planner only, after
/// admission ([`contact_admission`] reads the same files for every peer).
/// The route hints form is [`with_learned_routes`].
pub fn with_learned_lan_routes(
    data_dir: &Path,
    peer_device: &[u8; 32],
    contact: ContactRoutes,
) -> ContactRoutes {
    with_learned_lan_routes_where(data_dir, peer_device, contact, |_| true)
}

/// [`with_learned_lan_routes`], but a learned local-network address
/// ([`is_local_network_ip`], not loopback) that `keep` refuses is left out
/// (the outbox worker, lab: one on none of this computer's current
/// networks). Saved routes and learned loopback or public addresses are never
/// asked about.
pub fn with_learned_lan_routes_where(
    data_dir: &Path,
    peer_device: &[u8; 32],
    mut contact: ContactRoutes,
    keep: impl Fn(std::net::IpAddr) -> bool,
) -> ContactRoutes {
    let now = crate::clock::now_ms();
    let learned: Vec<String> = contact
        .routes
        .iter()
        .filter(|r| r.carrier == OutboxCarrier::Lan)
        .filter_map(|r| {
            crate::lan_seen::learned_lan_dial(data_dir, peer_device, &r.dial, contact.pinned, now)
        })
        // learned_lan_dial writes `ip:port`; anything else is not ours to drop.
        .filter(|dial| learned_dial_kept(dial, &keep))
        .collect();
    for dial in learned {
        let known = contact
            .routes
            .iter()
            .any(|r| r.carrier == OutboxCarrier::Lan && r.dial == dial);
        if !known {
            contact.routes.push(OutboxRoute {
                carrier: OutboxCarrier::Lan,
                dial,
            });
        }
    }
    // Stable: within one carrier the saved address stays first.
    contact.routes.sort_by_key(|r| r.carrier);
    contact
}

/// Whether the contact whose key is `peer_device` is verified (pinned). No
/// such contact is `false`; an unreadable book is an error.
pub fn contact_is_pinned(data_dir: &Path, peer_device: &[u8; 32]) -> Result<bool, String> {
    Ok(contact_routes(data_dir, peer_device)?.is_some_and(|c| c.pinned))
}

/// May anything be exchanged with `peer` at all?
// One per contact per plan, moved and never kept in bulk: the routes'
// size (the card LAN list included) costs nothing worth a box.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactAdmission {
    /// A current, unblocked contact (with its routes and pin).
    Allowed(ContactRoutes),
    NotContact,
    Blocked,
    /// The contact book or block list cannot be read: nobody is admitted.
    Unreadable,
}

/// The device keys (lowercase hex) of every current, unblocked contact,
/// verified or not, by the rows and block list [`contact_admission`] reads:
/// what per-contact state may keep (a removed or blocked contact's key goes,
/// storage rule "real erase"). No contact book is no contact; an unreadable
/// or corrupt book or block list is an error.
pub fn admitted_contact_keys(data_dir: &Path) -> Result<std::collections::HashSet<String>, String> {
    let rows: Vec<ContactRouteRow> = crate::contact_book::read_rows(data_dir)?.unwrap_or_default();
    let blocks = crate::chat_history::BlockList::load_checked(data_dir)?;
    Ok(rows
        .iter()
        .map(|r| r.pub_hex.trim().to_ascii_lowercase())
        .filter(|key| !key.is_empty() && !blocks.is_blocked(key))
        .collect())
}

/// The contact and block-list check every sender and listener runs first.
/// It always reads both files once, whatever the answer, so refusing a
/// stranger costs the same as refusing a contact. The p2p host's peer gate
/// applies the same rows, pin rule and block list to every contact at once
/// ([`p2p_gate_peers`]).
pub fn contact_admission(data_dir: &Path, peer: &[u8; 32]) -> ContactAdmission {
    let contact = contact_routes(data_dir, peer);
    let blocks = crate::chat_history::BlockList::load_checked(data_dir);
    match (contact, blocks) {
        (Ok(Some(contact)), Ok(blocks)) => {
            if blocks.is_blocked(&hex::encode(peer)) {
                ContactAdmission::Blocked
            } else {
                ContactAdmission::Allowed(contact)
            }
        }
        (Ok(None), Ok(_)) => ContactAdmission::NotContact,
        (Ok(Some(_)), Err(_)) => ContactAdmission::Blocked,
        (Err(_), _) | (Ok(None), Err(_)) => ContactAdmission::Unreadable,
    }
}

/// The verified (pinned), unblocked contacts in book order, each once, by
/// the rows, pin rule and block list of [`contact_admission`] (several rows
/// for one key are verified only if all are), with both files read once for
/// all of them. No contact book is no contact; an unreadable or corrupt book
/// or block list is an error (callers fail closed).
pub fn pinned_unblocked_contacts(data_dir: &Path) -> Result<Vec<[u8; 32]>, String> {
    let rows: Vec<ContactRouteRow> = crate::contact_book::read_rows(data_dir)?.unwrap_or_default();
    let blocks = crate::chat_history::BlockList::load_checked(data_dir)?;
    let mut book: Vec<([u8; 32], bool)> = Vec::new();
    let mut at: std::collections::HashMap<[u8; 32], usize> = std::collections::HashMap::new();
    for row in &rows {
        let mut key = [0u8; 32];
        if hex::decode_to_slice(row.pub_hex.trim(), &mut key).is_err() {
            continue;
        }
        match at.get(&key) {
            Some(&i) => book[i].1 &= row.pinned,
            None => {
                at.insert(key, book.len());
                book.push((key, row.pinned));
            }
        }
    }
    Ok(book
        .into_iter()
        .filter(|(key, pinned)| *pinned && !blocks.is_blocked(&hex::encode(key)))
        .map(|(key, _)| key)
        .collect())
}

/// What a message written to a contact now could do (cutoff pack CP.6, M2),
/// from the session store's metadata only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueReach {
    /// A secure connection can take it: sealed now, it can wait for the
    /// contact until `until_ms` ([`queue_horizon`]).
    CanWait { until_ms: u64 },
    /// The last secure connection ended at `at_ms`: nothing can wait for
    /// the contact until they meet and set up a new one.
    Ended { at_ms: u64 },
    /// No secure connection with the contact yet (or none within
    /// [`crate::indexed_session_store::SESSION_END_KEEP_MS`]): a first
    /// message needs them online.
    NeverPaired,
}

impl QueueReach {
    /// The expiry a message sealed now would get, when it could wait.
    pub fn horizon(self) -> Option<u64> {
        match self {
            Self::CanWait { until_ms } => Some(until_ms),
            Self::Ended { .. } | Self::NeverPaired => None,
        }
    }
}

/// [`QueueReach`] for the contact whose device key is `peer`, from a reader
/// the caller opened once for many contacts. `None` (a profile with no
/// session store) is [`QueueReach::NeverPaired`].
pub fn queue_reach_with(
    reader: Option<&crate::indexed_session_store::SessionMetadataReader>,
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<QueueReach, String> {
    let Some(reader) = reader else {
        return Ok(QueueReach::NeverPaired);
    };
    let h = reader
        .peer_horizon(peer, now_ms)
        .map_err(|e| e.redacted_display())?;
    Ok(match (h.sendable_until_ms, h.ended_at_ms) {
        (Some(session_end), _) => match envelope_expires_at(now_ms, session_end) {
            Ok(until_ms) => QueueReach::CanWait { until_ms },
            Err(_) => QueueReach::Ended { at_ms: session_end },
        },
        (None, Some(at_ms)) => QueueReach::Ended { at_ms },
        (None, None) => QueueReach::NeverPaired,
    })
}

/// [`queue_reach_with`], opening the profile's session metadata (only when
/// it exists: a fresh profile's store is never created here).
pub fn queue_reach(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> Result<QueueReach, String> {
    let reader = crate::indexed_session_store::SessionMetadataReader::open(data_dir)
        .map_err(|e| e.redacted_display())?;
    queue_reach_with(reader.as_ref(), peer, now_ms)
}

/// The expiry a message to `peer` sealed now would get: `min(now +
/// ENVELOPE_VALIDITY_MS, the newest sendable session's expiry)`. A
/// metadata-only read (no protected load, so no Keychain prompt), which
/// creates no store. `None`: no sendable session (meet first).
pub fn queue_horizon(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> Result<Option<u64>, String> {
    Ok(queue_reach(data_dir, peer, now_ms)?.horizon())
}

/// A verified contact the p2p host admits (any-network plan §2.4, the peer
/// gate): its card's `p2p=` PeerId and the relays its `via=` names, or what
/// its route hints said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2pGatePeer {
    pub peer_id: String,
    /// The PeerIds of its `via=` relays (a `via=` that names the contact
    /// itself is a direct address, not a relay), then of the relays its
    /// route hints name.
    pub relays: Vec<String>,
    /// No hole punching or Identify with it: this node hides its IP from it
    /// (D4: its row's or the node policy's `hide_ip`), or its PeerId is
    /// learned and no p2p link has proved it yet.
    pub hidden: bool,
    /// The PeerId came from its route hints ([`crate::learned_routes`]): the
    /// book has none.
    pub learned: bool,
    /// The PeerId is the book's, or a learned one a p2p link has proved. The
    /// friend relay admits a learned PeerId only once it is proved (with
    /// [`Self::hidden`] alone, a contact this node hides its IP from looks
    /// the same).
    pub proven: bool,
    /// Phase 4 PeerId rotation, while its gate is live: the contact's other
    /// PeerIds, admitted like [`Self::peer_id`] (its card's `p2pn=` and the
    /// epochs around its clock that its schedule names,
    /// [`crate::peer_rotation::admitted_peer_ids`]). Empty otherwise.
    pub rotated: Vec<String>,
}

impl P2pGatePeer {
    /// [`Self::peer_id`], then [`Self::rotated`].
    pub fn peer_ids(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.peer_id).chain(&self.rotated)
    }
}

/// The contact half of the p2p peer gate: every verified (pinned), unblocked
/// contact with a usable `p2p=` PeerId, by the rows, pin rule and block list
/// of [`contact_admission`] (several rows for one key are verified only if
/// all are, hidden if any is). Both files are read whatever they hold. No
/// contact book is no contact; an unreadable or corrupt contact book or block
/// list is an error, and the caller then admits no contact at all.
///
/// While route hints are live, a verified contact with no book PeerId is
/// admitted with the PeerId its route hints name (hidden until a p2p link
/// proves it), and the relays they name are added to every contact whose
/// PeerId they match. A learned PeerId other than the book's is ignored.
///
/// While PeerId rotation is live (Phase 4), each contact is expanded
/// through [`crate::peer_rotation::admitted_peer_ids`]: its card's `p2pn=`
/// and the epochs its schedule names around its clock
/// ([`P2pGatePeer::rotated`]). A schedules file that cannot be read adds
/// none.
pub fn p2p_gate_peers(data_dir: &Path) -> Result<Vec<P2pGatePeer>, String> {
    gate_peers(
        data_dir,
        crate::route_hints::route_hints_live(),
        crate::portmap_gate::peer_rotation_live_enabled(),
        crate::clock::now_ms(),
    )
}

/// What a block takes from every other list that admits a PeerId (the
/// friend relay's manual allow-list): [`blocked_p2p`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockedP2p {
    /// The blocked contacts' device keys (lowercase hex): an allow-list
    /// entry that names one of them as its contact
    /// ([`crate::relay_allow::RelayAllowEntry::contact`]) is left out.
    pub keys: Vec<String>,
    /// Their libp2p PeerIds: every usable `p2p=` PeerId their rows in the
    /// contact book name, and every PeerId their route hints named (proven
    /// or not).
    pub peer_ids: Vec<String>,
}

/// The blocked contacts and their PeerIds ([`BlockedP2p`]). A block holds
/// over every other list that admits a PeerId: the caller leaves these
/// out. An unreadable or corrupt block list is an error, and the caller
/// then cannot tell who is blocked (it must admit nobody from such a list);
/// an unreadable contact book only leaves the book's PeerIds out (the
/// caller already knows it cannot read the book).
pub fn blocked_p2p(data_dir: &Path) -> Result<BlockedP2p, String> {
    let blocks = crate::chat_history::BlockList::load_checked(data_dir)?;
    let mut keys: Vec<String> = Vec::new();
    for key in &blocks.pub_hex {
        let key = key.trim().to_ascii_lowercase();
        if !key.is_empty() && !keys.contains(&key) {
            keys.push(key);
        }
    }
    let peer_ids = p2p_peer_ids_where(data_dir, |key| blocks.is_blocked(key));
    Ok(BlockedP2p { keys, peer_ids })
}

/// Every libp2p PeerId the contact `pub_hex` is known by now: the usable
/// `p2p=` (and `p2pn=`) PeerIds of its rows in the contact book, every
/// PeerId its route hints named (proven or not) and every one its PeerId
/// schedule names (Phase 4). Best effort: an unreadable file gives what the
/// others hold.
pub fn contact_p2p_peer_ids(data_dir: &Path, pub_hex: &str) -> Vec<String> {
    let want = pub_hex.trim();
    p2p_peer_ids_where(data_dir, |key| key.trim().eq_ignore_ascii_case(want))
}

/// The PeerIds of the contact `pub_hex` that do not rest on its PeerId
/// schedule or an unproven route hint: its book's usable `p2p=` and
/// `p2pn=`, and the PeerIds its route hints named that a p2p link proved.
/// What the friend relay's manual allow-list may be told is the contact's
/// ([`crate::relay_allow::tag_contact`]): a schedule's epoch keys are
/// announced without proof that the contact holds them, so they could name
/// another peer's PeerIds (review D-4).
pub fn contact_proven_p2p_peer_ids(data_dir: &Path, pub_hex: &str) -> Vec<String> {
    let want = pub_hex.trim();
    p2p_peer_ids_of(data_dir, |key| key.trim().eq_ignore_ascii_case(want), true)
}

/// Whether a PEER_SCHEDULE the contact `pub_hex` announced names a PeerId
/// this node knows as another peer's (review D-4): another contact's book
/// `p2p=` or `p2pn=`, a PeerId another contact's route hints named, an
/// entry of another contact's stored schedule, or a relay's (a contact's
/// `via=` relay, a relay route hints named, or one node_policy.json
/// names). An epoch key comes without proof that the sender holds it, so
/// such a schedule must be ignored whole: it would let the sender's hints
/// be kept under another peer's PeerId, and a later forget or block of the
/// sender would reach that peer. Best effort: a file that cannot be read
/// adds nothing.
pub fn schedule_names_another_peer(
    data_dir: &Path,
    pub_hex: &str,
    s: &crate::route_hints::PeerSchedule,
) -> bool {
    if s.entries.is_empty() {
        return false;
    }
    let want = pub_hex.trim();
    let mut taken: std::collections::HashSet<String> =
        p2p_peer_ids_where(data_dir, |key| !key.trim().eq_ignore_ascii_case(want))
            .into_iter()
            .collect();
    let rows: Vec<ContactRouteRow> = crate::contact_book::read_rows(data_dir)
        .ok()
        .flatten()
        .unwrap_or_default();
    for p2p in rows
        .iter()
        .filter_map(|row| crate::p2p_route::ContactP2p::from_fields(&row.p2p, &row.p2p_via))
    {
        taken.extend(
            p2p.via
                .iter()
                .filter(|v| v.peer_id != p2p.peer_id)
                .map(|v| v.peer_id.clone()),
        );
    }
    for (_, learned) in crate::learned_routes::learned_p2p(data_dir, crate::clock::now_ms()) {
        taken.extend(learned.relays.iter().map(|v| v.peer_id.clone()));
    }
    taken.extend(
        crate::node_policy::load_policy(data_dir)
            .p2p_relays
            .iter()
            .filter_map(|text| crate::p2p_route::parse_via(text).ok())
            .map(|v| v.peer_id),
    );
    s.entries
        .iter()
        .any(|(_, key)| taken.contains(&crate::p2p_route::peer_id_from_ed25519_public(key)))
}

/// The PeerIds ([`contact_p2p_peer_ids`]) of every contact whose device key
/// `pick` selects, once each.
fn p2p_peer_ids_where(data_dir: &Path, pick: impl Fn(&str) -> bool) -> Vec<String> {
    p2p_peer_ids_of(data_dir, pick, false)
}

/// [`p2p_peer_ids_where`]; `proven_only`: without the PeerIds a schedule
/// names or a route hint named unproven ([`contact_proven_p2p_peer_ids`]).
fn p2p_peer_ids_of(data_dir: &Path, pick: impl Fn(&str) -> bool, proven_only: bool) -> Vec<String> {
    let rows: Vec<ContactRouteRow> = crate::contact_book::read_rows(data_dir)
        .ok()
        .flatten()
        .unwrap_or_default();
    let book = rows
        .iter()
        .filter(|row| pick(&row.pub_hex))
        .filter_map(|row| crate::p2p_route::ContactP2p::from_fields(&row.p2p, &row.p2p_via))
        .map(|p2p| p2p.peer_id);
    let next = rows
        .iter()
        .filter(|row| pick(&row.pub_hex))
        .filter_map(|row| crate::p2p_route::normalize_peer_id(&row.p2p_next).ok());
    let learned = crate::learned_routes::learned_peer_ids(data_dir, crate::clock::now_ms())
        .into_iter()
        .filter(|(key, _, proven)| pick(key) && (*proven || !proven_only))
        .map(|(_, peer_id, _)| peer_id);
    let scheduled = if proven_only {
        Default::default()
    } else {
        crate::peer_rotation::load_schedules(data_dir).unwrap_or_default()
    }
    .into_iter()
    .filter(|(key, _)| pick(key))
    .flat_map(|(_, s)| crate::peer_rotation::schedule_peer_ids(&s));
    let mut out: Vec<String> = Vec::new();
    for peer_id in book.chain(next).chain(learned).chain(scheduled) {
        if !out.contains(&peer_id) {
            out.push(peer_id);
        }
    }
    out
}

/// [`p2p_gate_peers`] with the route hints and PeerId rotation gates and the
/// clock as arguments.
fn gate_peers(
    data_dir: &Path,
    hints_live: bool,
    rotation_live: bool,
    now_ms: u64,
) -> Result<Vec<P2pGatePeer>, String> {
    let rows: Vec<ContactRouteRow> = crate::contact_book::read_rows(data_dir)?.unwrap_or_default();
    let blocks = crate::chat_history::BlockList::load_checked(data_dir)?;
    // (verified, hidden, the book's PeerId and via=, its p2pn=)
    type Row = (bool, bool, Option<crate::p2p_route::ContactP2p>, String);
    let mut by_key: std::collections::BTreeMap<String, Row> = std::collections::BTreeMap::new();
    for row in &rows {
        let key = row.pub_hex.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        let entry = by_key
            .entry(key)
            .or_insert((true, false, None, String::new()));
        entry.0 &= row.pinned;
        entry.1 |= row.hide_ip;
        // One PeerId per key: the first usable one, as contact_routes, and
        // the p2pn= of its row.
        if entry.2.is_none() {
            entry.2 = crate::p2p_route::ContactP2p::from_fields(&row.p2p, &row.p2p_via);
            if entry.2.is_some() {
                entry.3 = row.p2p_next.clone();
            }
        }
    }
    let schedules = if rotation_live {
        crate::peer_rotation::load_schedules(data_dir).unwrap_or_default()
    } else {
        Default::default()
    };
    let hide_all = crate::node_policy::load_policy(data_dir).hide_ip;
    let learned: std::collections::HashMap<String, crate::learned_routes::LearnedP2p> =
        if hints_live {
            crate::learned_routes::learned_p2p(data_dir, now_ms)
                .into_iter()
                .collect()
        } else {
            std::collections::HashMap::new()
        };
    Ok(by_key
        .into_iter()
        .filter(|(key, (pinned, ..))| *pinned && !blocks.is_blocked(key))
        .filter_map(|(key, (_, hidden, book, next))| {
            let hidden = hidden || hide_all;
            let hint = learned.get(&key);
            let (peer_id, book_relays, from_hints, proven) = match (book, hint) {
                (Some(book), _) => {
                    let relays = book
                        .via
                        .iter()
                        .filter(|v| v.peer_id != book.peer_id)
                        .map(|v| v.peer_id.clone())
                        .collect::<Vec<_>>();
                    (book.peer_id, relays, false, true)
                }
                (None, Some(hint)) => (hint.peer_id.clone(), Vec::new(), true, hint.proven),
                (None, None) => return None,
            };
            let rotated: Vec<String> = if rotation_live {
                let next = (!from_hints && !next.is_empty()).then_some(next.as_str());
                crate::peer_rotation::admitted_peer_ids(
                    Some(&peer_id),
                    next,
                    schedules.get(&key),
                    now_ms / 1000,
                )
                .into_iter()
                .filter(|p| *p != peer_id)
                .collect()
            } else {
                Vec::new()
            };
            let mut relays = book_relays;
            // The book wins: hints naming another PeerId are ignored whole,
            // unless (PeerId rotation live) it is one of the contact's
            // admitted epoch PeerIds: a rotating contact's hints name the
            // PeerId of its current epoch.
            let own = |p: &String| *p == peer_id || rotated.contains(p);
            for relay in hint
                .filter(|h| own(&h.peer_id))
                .into_iter()
                .flat_map(|h| &h.relays)
            {
                if !own(&relay.peer_id) && !relays.contains(&relay.peer_id) {
                    relays.push(relay.peer_id.clone());
                }
            }
            Some(P2pGatePeer {
                peer_id,
                relays,
                hidden: hidden || !proven,
                learned: from_hints,
                proven,
                rotated,
            })
        })
        .collect())
}

/// PeerId rotation (Phase 4, `protocol/RAVEN_P2P_PEER_ROTATION_V1.md` §8):
/// how many verified (pinned), unblocked contacts with a usable `p2p=`
/// PeerId have not announced that they can follow a rotating PeerId (no
/// stored schedule, or one without the capable bit). A profile rotates only
/// when this is 0. An unreadable contact book or block list is an error; an
/// unreadable schedules file counts every such contact (the caller then
/// keeps the fixed PeerId).
pub fn rotation_waiting_on(data_dir: &Path) -> Result<u32, String> {
    let rows: Vec<ContactRouteRow> = crate::contact_book::read_rows(data_dir)?.unwrap_or_default();
    let blocks = crate::chat_history::BlockList::load_checked(data_dir)?;
    let schedules = crate::peer_rotation::load_schedules(data_dir).unwrap_or_default();
    // (verified, has a usable p2p=)
    let mut by_key: std::collections::BTreeMap<String, (bool, bool)> =
        std::collections::BTreeMap::new();
    for row in &rows {
        let key = row.pub_hex.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        let entry = by_key.entry(key).or_insert((true, false));
        entry.0 &= row.pinned;
        entry.1 |= crate::p2p_route::ContactP2p::from_fields(&row.p2p, &row.p2p_via).is_some();
    }
    let waiting = by_key
        .iter()
        .filter(|(key, (pinned, p2p))| *pinned && *p2p && !blocks.is_blocked(key))
        .filter(|(key, _)| !schedules.get(*key).is_some_and(|s| s.capable))
        .count();
    Ok(u32::try_from(waiting).unwrap_or(u32::MAX))
}

/// PeerId rotation (Phase 4, spec §9): the PeerIds to dial the contact
/// `peer_device` under, in order, at most 2
/// ([`crate::peer_rotation::dial_peer_ids`]), while the rotation gate is
/// live and they are not just its book's `p2p=`: the epochs its schedule
/// names for now, or its card's `p2p=` then `p2pn=`. `None` otherwise (the
/// book's PeerId is dialled as in Phase 1), and for a contact with no
/// usable `p2p=`.
pub fn rotated_dial_peer_ids(
    data_dir: &Path,
    peer_device: &[u8; 32],
    now_ms: u64,
) -> Option<Vec<String>> {
    rotated_dial_ids(
        data_dir,
        peer_device,
        crate::portmap_gate::peer_rotation_live_enabled(),
        now_ms,
    )
}

/// [`rotated_dial_peer_ids`] with the rotation gate as an argument.
pub fn rotated_dial_ids(
    data_dir: &Path,
    peer_device: &[u8; 32],
    rotation_live: bool,
    now_ms: u64,
) -> Option<Vec<String>> {
    if !rotation_live {
        return None;
    }
    let key = hex::encode(peer_device);
    let rows: Vec<ContactRouteRow> = crate::contact_book::read_rows(data_dir).ok()??;
    // The first usable p2p= of the key, as contact_routes, and its p2pn=.
    let (book, next) = rows
        .iter()
        .filter(|r| r.pub_hex.trim().eq_ignore_ascii_case(&key))
        .find_map(|r| {
            crate::p2p_route::ContactP2p::from_fields(&r.p2p, &r.p2p_via)
                .map(|p| (p.peer_id, r.p2p_next.clone()))
        })?;
    let schedules = crate::peer_rotation::load_schedules(data_dir).unwrap_or_default();
    let next = (!next.is_empty()).then_some(next.as_str());
    let ids = crate::peer_rotation::dial_peer_ids(&book, next, schedules.get(&key), now_ms / 1000);
    (!ids.is_empty() && ids != [book]).then_some(ids)
}

/// What the worker may try, in order, and why a route was held back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutePlan {
    pub routes: Vec<OutboxRoute>,
    /// A route was held back only because the contact is not verified
    /// ([`CONTACT_NOT_VERIFIED`]).
    pub unverified_withheld: bool,
    /// [`plan_object_routes_ranked`] got a learned order that did not give a
    /// pure reorder of this plan: `routes` is the unranked plan, and the
    /// caller pins the contact-network to it
    /// ([`crate::learning::model::Model::note_contradiction`]).
    pub learning_contradiction: bool,
}

/// Which carrier gates are open, read once per attempt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CarrierGates {
    /// `lan_direct_live_enabled`.
    pub lan: bool,
    /// `internet_direct_live_enabled`.
    pub internet: bool,
    /// `p2p_live_enabled`.
    pub p2p: bool,
    /// `nearby_live_enabled` ([`crate::nearby_gate`]).
    pub nearby: bool,
    /// `onion_live_enabled` ([`crate::onion_gate`]).
    pub onion: bool,
}

impl CarrierGates {
    pub fn allows(self, carrier: OutboxCarrier) -> bool {
        match carrier {
            OutboxCarrier::Lan => self.lan,
            OutboxCarrier::Internet => self.internet,
            OutboxCarrier::P2p => self.p2p,
            OutboxCarrier::Nearby => self.nearby,
            OutboxCarrier::Onion => self.onion,
        }
    }
}

/// `contact` with its nearby route ([`nearby_dial_for`] of `peer`) last,
/// when `available` and the contact is verified (nearby is for pinned
/// contacts only, [`carrier_allowed_for_contact`]). The caller computes
/// `available`: the nearby engine runs, the user turned nearby on and the
/// pair key can be derived. Derived live for each plan and never stored
/// ([`record_object_routes`] drops it); planned last, and only while
/// [`CarrierGates::nearby`] is open. Not available: `contact` as it was.
pub fn with_nearby_route(
    mut contact: ContactRoutes,
    peer: &[u8; 32],
    available: bool,
) -> ContactRoutes {
    if available && contact.pinned {
        let route = OutboxRoute {
            carrier: OutboxCarrier::Nearby,
            dial: nearby_dial_for(peer),
        };
        if !contact.routes.contains(&route) {
            // The last carrier: pushed last, the plan order holds.
            contact.routes.push(route);
        }
    }
    contact
}

/// `contact` with its onion route ([`crate::onion::dial_for`]) last, when
/// `available` (the Tor helper is ready: the caller's
/// [`crate::onion_gate::onion_usable_now`]) and the contact is verified,
/// from the newest of the book's binding ([`ContactRoutes::onion`]) and
/// `learned` (route hints, RRH1 ONION) that verifies against `peer` at
/// `now_s` (checked again here, whatever the caller checked). Derived live
/// for each plan and never stored ([`record_object_routes`] drops it);
/// planned after every other route, nearby included, and only while
/// [`CarrierGates::onion`] is open. "Hide my IP" (D4) does not drop it: an
/// onion dial shows the contact no IP of this computer. Not available, not
/// verified or no binding: `contact` as it was.
pub fn with_onion_route(
    mut contact: ContactRoutes,
    peer: &[u8; 32],
    learned: Option<crate::onion::OnionBinding>,
    available: bool,
    now_s: u64,
) -> ContactRoutes {
    if !available || !contact.pinned {
        return contact;
    }
    let verified = |b: Option<crate::onion::OnionBinding>| b.filter(|b| b.verify(peer, now_s));
    let Some(binding) = crate::onion::newest(verified(contact.onion), verified(learned)) else {
        return contact;
    };
    let route = OutboxRoute {
        carrier: OutboxCarrier::Onion,
        dial: crate::onion::dial_for(&binding.hs_id),
    };
    contact.routes.retain(|r| r.carrier != OutboxCarrier::Onion);
    // The last carrier: pushed last, the plan order holds.
    contact.routes.push(route);
    contact
}

/// The routes the worker tries for one object, in order:
/// - the carriers its send allowed (`record.choice`; with no record, the
///   narrowest plan: LAN only), each only while its gate is open
///   ([`CarrierGates`]), and Internet and p2p only for a verified contact;
/// - the contact's **current** addresses first (LAN, Internet, p2p: the plan
///   order of transports design §2.3), then the ones the send used (an
///   address changed since the send is still found, the new one first);
/// - no Internet route at all, not even the send's, for a contact this node
///   hides its IP from ([`ContactRoutes::hide_ip`]);
/// - a nearby route only from `contact` ([`with_nearby_route`], derived
///   live), never from the record: after every other route (the send's
///   too), and on top of the routes the `MAX_ROUTES_PER_OBJECT` cap keeps,
///   so it is planned last and never cut off;
/// - an onion route likewise only from `contact` ([`with_onion_route`]),
///   after the nearby route, on top of the cap too, and kept under "hide my
///   IP" (Tor shows the contact no IP of this computer).
///
/// Nothing at all is planned when every gate is off. LAN routes of an
/// unverified contact must still pass [`localize_lan_route`] at dial time.
///
/// A record is missing only for rows queued by older builds, after a failed
/// best-effort write, or after eviction past `MAX_ROUTE_OBJECTS`. Their own
/// choice is unknown, so they fail narrow; the session-reset step (raven-node
/// `run_reset_for_attempt`) relies on `None` being LAN only.
pub fn plan_object_routes(
    record: Option<&ObjectRoutes>,
    contact: &ContactRoutes,
    gates: CarrierGates,
) -> RoutePlan {
    plan_object_routes_preferring(record, contact, gates, None)
}

/// [`plan_object_routes`] with `preferred` (the contact's remembered route,
/// [`crate::route_memory`]) first when the plan holds it. Order only: a route
/// the rules above left out is never added.
pub fn plan_object_routes_preferring(
    record: Option<&ObjectRoutes>,
    contact: &ContactRoutes,
    gates: CarrierGates,
    preferred: Option<&OutboxRoute>,
) -> RoutePlan {
    let mut plan = filtered_routes(record, contact, gates);
    // Before the cap, so the remembered route is never cut off.
    if let Some(i) = preferred.and_then(|p| plan.routes.iter().position(|r| r == p)) {
        let route = plan.routes.remove(i);
        plan.routes.insert(0, route);
    }
    cap_routes(&mut plan.routes);
    plan
}

/// [`plan_object_routes`] with the learned carrier order
/// ([`crate::learning::rank`]). Same filters; the order is applied before
/// the cap (as `preferred` is). Order only: a route the rules left out is
/// never added, and nearby keeps its place. When the result is not a pure
/// reorder of the static plan ([`crate::learning::rank::same_set_as_static`],
/// or an order that is not well formed), the static plan is returned with
/// [`RoutePlan::learning_contradiction`] set. `None` plans exactly what
/// [`plan_object_routes`] plans.
pub fn plan_object_routes_ranked(
    record: Option<&ObjectRoutes>,
    contact: &ContactRoutes,
    gates: CarrierGates,
    order: Option<&crate::learning::rank::Order>,
) -> RoutePlan {
    let uncapped = filtered_routes(record, contact, gates);
    let mut plan = uncapped.clone();
    cap_routes(&mut plan.routes);
    if let Some(order) = order {
        let mut learned = uncapped.routes.clone();
        crate::learning::rank::apply(&mut learned, order);
        cap_routes(&mut learned);
        if order.well_formed()
            && crate::learning::rank::same_set_as_static(
                &learned,
                &uncapped.routes,
                plan.routes.len(),
            )
        {
            plan.routes = learned;
        } else {
            plan.learning_contradiction = true;
        }
    }
    plan
}

/// The rules of [`plan_object_routes`] before the per-object cap: every
/// route they allow, in plan order. The preferring and the ranked planner
/// share it, so they cannot drift apart.
fn filtered_routes(
    record: Option<&ObjectRoutes>,
    contact: &ContactRoutes,
    gates: CarrierGates,
) -> RoutePlan {
    let choice = record.map_or(CarrierChoice::Lan, |r| r.choice);
    let recorded: &[OutboxRoute] = record.map_or(&[], |r| r.routes.as_slice());
    let mut plan = RoutePlan::default();
    // A nearby route and an onion route are the contact's, derived live,
    // and planned after every other route, the send's own too (nearby, then
    // onion); a recorded one (none is ever written) is not planned.
    let is_live =
        |r: &&OutboxRoute| matches!(r.carrier, OutboxCarrier::Nearby | OutboxCarrier::Onion);
    let others = contact.routes.iter().filter(|r| !is_live(r));
    let recorded = recorded.iter().filter(|r| !is_live(r));
    let nearby = contact
        .routes
        .iter()
        .filter(|r| r.carrier == OutboxCarrier::Nearby);
    let onion = contact
        .routes
        .iter()
        .filter(|r| r.carrier == OutboxCarrier::Onion);
    for route in others.chain(recorded).chain(nearby).chain(onion) {
        if !choice.allows(route.carrier) || !gates.allows(route.carrier) || !plausible_route(route)
        {
            continue;
        }
        // Hide my IP (D4): an Internet direct dial shows the contact our IP,
        // whether the route is the book's or the send's.
        if contact.hide_ip && route.carrier == OutboxCarrier::Internet {
            continue;
        }
        if !contact.allows(route.carrier) {
            plan.unverified_withheld = true;
            continue;
        }
        let route = OutboxRoute {
            carrier: route.carrier,
            dial: route.dial.trim().to_string(),
        };
        if !plan.routes.contains(&route) {
            plan.routes.push(route);
        }
    }
    plan
}

/// The per-object cap. It counts the other carriers' routes: the contact's
/// one nearby route and one onion route ride on top of it. Without them, a
/// plain truncation.
fn cap_routes(routes: &mut Vec<OutboxRoute>) {
    let mut kept = 0;
    routes.retain(|r| {
        matches!(r.carrier, OutboxCarrier::Nearby | OutboxCarrier::Onion) || {
            kept += 1;
            kept <= MAX_ROUTES_PER_OBJECT
        }
    });
}

// ── Retry timing ─────────────────────────────────────────────────────────────

/// First retry delay (before jitter).
pub const RETRY_BASE: Duration = Duration::from_secs(5);
/// No retry waits longer than this, whatever the jitter.
pub const RETRY_MAX: Duration = Duration::from_secs(10 * 60);

/// Delay before the next attempt after `failures` failed ones (0 = the first
/// failure): `min(RETRY_MAX, RETRY_BASE * 2^failures)` with ±50 % jitter, and
/// never above [`RETRY_MAX`]. `jitter` is a uniform sample from `[0, 1]`;
/// callers supply it so tests stay deterministic (0.5 = no jitter).
pub fn retry_delay(failures: u32, jitter: f64) -> Duration {
    let ceiling = RETRY_BASE
        .saturating_mul(1u32 << failures.min(16))
        .min(RETRY_MAX);
    let jitter = if jitter.is_finite() {
        jitter.clamp(0.0, 1.0)
    } else {
        0.5
    };
    ceiling.mul_f64(0.5 + jitter).min(RETRY_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three-machine test 2026-10-25: macOS refused every LAN dial of one
    /// Mac's raven-node (its Local Network permission) with "No route to
    /// host (os error 65)" while the contacts were up. raven-node's dial
    /// error says it of the address; a public address's, a timeout's and
    /// Linux's (113) do not count.
    #[test]
    fn local_network_refused_is_macos_no_route_at_a_local_address() {
        for refused in [
            "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.25:17420 (192.168.0.25:17420: \
             No route to host (os error 65)); mid=1fb52189…",
            "lan_dial 10.0.0.5:7420: lan connect: cannot connect to 10.0.0.5:7420 (10.0.0.5:7420: \
             no answer within 5.0s; 10.0.0.6:7420: No route to host (os error 65)); \
             internet_dial 203.0.113.7:7422: internet connect: no answer within 10s",
            "cannot connect to 192.168.1.30:7420 (No route to host (os error 65))",
            "cannot connect to [fe80::1]:7420 ([fe80::1]:7420: No route to host (os error 65))",
        ] {
            assert!(local_network_refused(refused), "{refused}");
        }
        for not in [
            "internet connect: cannot connect to 203.0.113.7:7422 (203.0.113.7:7422: No route to \
             host (os error 65))",
            "lan connect: cannot connect to 192.168.0.25:17420 (192.168.0.25:17420: No route to \
             host (os error 113))",
            "lan connect: cannot connect to 192.168.0.25:17420 (192.168.0.25:17420: no answer \
             within 5.0s)",
            "lan connect: cannot connect to 192.168.0.25:17420 (192.168.0.25:17420: Host is down \
             (os error 64))",
            "No route to host (os error 65)",
        ] {
            assert!(!local_network_refused(not), "{not}");
            assert!(local_network_refused_at(not).is_empty(), "{not}");
        }
        let two = "lan connect: cannot connect to bob.local:7420 (192.168.0.25:7420: No route to \
                   host (os error 65); 192.168.0.26:7420: No route to host (os error 65); \
                   192.168.0.25:7420: No route to host (os error 65))";
        assert_eq!(
            local_network_refused_at(two),
            [
                "192.168.0.25".parse::<std::net::IpAddr>().unwrap(),
                "192.168.0.26".parse().unwrap()
            ]
        );
    }

    /// Holds the long message horizon on this thread, whatever
    /// `RAVEN_LAB_HORIZON` the suite runs with, until dropped: its grace
    /// keeps a record past its envelope (P5.6), which these tests check
    /// without it.
    struct HorizonHeld;

    impl HorizonHeld {
        fn on() -> Self {
            crate::horizon::set_lab_horizon_for_this_thread(Some(false));
            Self
        }
    }

    impl Drop for HorizonHeld {
        fn drop(&mut self) {
            crate::horizon::set_lab_horizon_for_this_thread(None);
        }
    }

    /// Cutoff pack CP.6: what a message written now could do, per contact.
    #[test]
    fn queue_horizon_table() {
        use crate::indexed_session_store::test_rows::insert_head;
        const HOUR: u64 = 3_600_000;
        let now = 1_800_000_000_000;
        let (bob, carol, dave) = ([0xBB; 32], [0xCC; 32], [0xDD; 32]);
        // None: a fresh profile has no store, and reading creates none.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(queue_horizon(dir.path(), &bob, now), Ok(None));
        assert_eq!(
            queue_reach(dir.path(), &bob, now),
            Ok(QueueReach::NeverPaired)
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        // 3 h left on the session: the session's end.
        insert_head(
            dir.path(),
            1,
            &bob,
            now - 21 * HOUR,
            now + 3 * HOUR,
            true,
            None,
        );
        assert_eq!(
            queue_horizon(dir.path(), &bob, now),
            Ok(Some(now + 3 * HOUR))
        );
        // A long session: capped at a day from now (ENVELOPE_VALIDITY_MS).
        insert_head(
            dir.path(),
            2,
            &carol,
            now - HOUR,
            now + 72 * HOUR,
            true,
            None,
        );
        assert_eq!(
            queue_horizon(dir.path(), &carol, now),
            Ok(Some(now + ENVELOPE_VALIDITY_MS))
        );
        // Ended (expired) and never paired.
        insert_head(
            dir.path(),
            3,
            &dave,
            now - 30 * HOUR,
            now - 6 * HOUR,
            true,
            None,
        );
        assert_eq!(queue_horizon(dir.path(), &dave, now), Ok(None));
        assert_eq!(
            queue_reach(dir.path(), &dave, now),
            Ok(QueueReach::Ended {
                at_ms: now - 6 * HOUR
            })
        );
        assert_eq!(
            queue_reach(dir.path(), &[0xEE; 32], now),
            Ok(QueueReach::NeverPaired)
        );
        // At the very end the session has no time left: ended.
        assert_eq!(
            queue_reach(dir.path(), &bob, now + 3 * HOUR - 1).map(QueueReach::horizon),
            Ok(Some(now + 3 * HOUR))
        );
        assert_eq!(
            queue_reach(dir.path(), &bob, now + 3 * HOUR),
            Ok(QueueReach::Ended {
                at_ms: now + 3 * HOUR
            })
        );
    }

    #[test]
    fn validity_is_a_day_capped_by_the_session() {
        let now = 1_000_000;
        assert_eq!(
            envelope_expires_at(now, u64::MAX).unwrap(),
            now + ENVELOPE_VALIDITY_MS
        );
        assert_eq!(envelope_expires_at(now, now + 5_000).unwrap(), now + 5_000);
        assert!(envelope_expires_at(now, now).is_err());
        assert!(envelope_expires_at(now, now - 1).is_err());
        assert_eq!(ENVELOPE_VALIDITY_MS, 24 * 60 * 60 * 1_000);
    }

    #[test]
    fn retry_delay_doubles_from_five_seconds_with_bounded_jitter_and_cap() {
        let secs = |d: Duration| d.as_secs_f64();
        // No jitter: exactly 5 s, 10 s, 20 s ... capped at 10 min.
        assert_eq!(retry_delay(0, 0.5), Duration::from_secs(5));
        assert_eq!(retry_delay(1, 0.5), Duration::from_secs(10));
        assert_eq!(retry_delay(2, 0.5), Duration::from_secs(20));
        assert_eq!(retry_delay(7, 0.5), RETRY_MAX);
        assert_eq!(retry_delay(u32::MAX, 0.5), RETRY_MAX);
        // ±50 % around the ceiling, never above the cap.
        for failures in 0..40 {
            let ceiling = (5.0 * 2f64.powi(failures.min(16) as i32)).min(600.0);
            for jitter in [0.0, 0.25, 0.5, 0.75, 1.0, -3.0, 9.0, f64::NAN] {
                let d = secs(retry_delay(failures, jitter));
                assert!(d >= ceiling * 0.5 - 1e-9, "{failures} {jitter}: {d}");
                assert!(
                    d <= (ceiling * 1.5).min(600.0) + 1e-9,
                    "{failures} {jitter}: {d}"
                );
                assert!(d <= 600.0, "{d}");
            }
        }
        assert_eq!(retry_delay(0, 0.0), Duration::from_millis(2_500));
        assert_eq!(retry_delay(0, 1.0), Duration::from_millis(7_500));
        assert_eq!(retry_delay(10, 0.0), Duration::from_secs(300));
    }

    fn lan(d: &str) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: d.into(),
        }
    }

    fn inet(d: &str) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Internet,
            dial: d.into(),
        }
    }

    fn contact(routes: &[OutboxRoute], pinned: bool) -> ContactRoutes {
        ContactRoutes {
            routes: routes.to_vec(),
            pinned,
            ..ContactRoutes::default()
        }
    }

    fn gates(lan: bool, internet: bool) -> CarrierGates {
        CarrierGates {
            lan,
            internet,
            p2p: false,
            nearby: false,
            onion: false,
        }
    }

    fn record(choice: CarrierChoice, routes: &[OutboxRoute]) -> ObjectRoutes {
        ObjectRoutes {
            peer_pub_hex: hex::encode([7u8; 32]),
            choice,
            routes: routes.to_vec(),
            expires_at_ms: u64::MAX,
            unsent: false,
            written: false,
            custodians_held: Vec::new(),
            custody_forwarded: false,
            custody: false,
        }
    }

    fn plan(
        rec: Option<&ObjectRoutes>,
        c: &ContactRoutes,
        lan_live: bool,
        internet_live: bool,
    ) -> Vec<OutboxRoute> {
        plan_object_routes(rec, c, gates(lan_live, internet_live)).routes
    }

    /// P6.5: every plan test of this module plans through this and
    /// [`plan_object_routes_preferring`] below (they shadow the module's),
    /// so each one also checks that the ranked planner with no order plans
    /// exactly what the unranked ones plan.
    fn plan_object_routes(
        record: Option<&ObjectRoutes>,
        contact: &ContactRoutes,
        gates: CarrierGates,
    ) -> RoutePlan {
        let plan = super::plan_object_routes(record, contact, gates);
        assert_eq!(
            plan,
            plan_object_routes_ranked(record, contact, gates, None)
        );
        plan
    }

    /// See [`plan_object_routes`] above.
    fn plan_object_routes_preferring(
        record: Option<&ObjectRoutes>,
        contact: &ContactRoutes,
        gates: CarrierGates,
        preferred: Option<&OutboxRoute>,
    ) -> RoutePlan {
        let plan = super::plan_object_routes_preferring(record, contact, gates, preferred);
        if preferred.is_none() {
            assert_eq!(
                plan,
                plan_object_routes_ranked(record, contact, gates, None)
            );
        }
        plan
    }

    #[test]
    fn plan_keeps_the_send_choice_current_addresses_first_and_both_gates() {
        let both = contact(&[lan("10.0.0.9:7420"), inet("203.0.113.7:7422")], true);
        let auto = record(CarrierChoice::Auto, &[lan("10.0.0.2:7420")]);
        // The contact's current addresses first, then the send's own.
        assert_eq!(
            plan(Some(&auto), &both, true, true),
            vec![
                lan("10.0.0.9:7420"),
                inet("203.0.113.7:7422"),
                lan("10.0.0.2:7420")
            ]
        );
        // The Internet gate off: no Internet route, whatever was recorded.
        assert_eq!(
            plan(Some(&auto), &both, true, false),
            vec![lan("10.0.0.9:7420"), lan("10.0.0.2:7420")]
        );
        // The LAN gate off: no LAN route (M); both off: nothing at all.
        assert_eq!(
            plan(Some(&auto), &both, false, true),
            vec![inet("203.0.113.7:7422")]
        );
        assert!(plan(Some(&auto), &both, false, false).is_empty());
        // `--carrier lan` stays LAN-only, `--carrier internet` Internet-only.
        let lan_only = record(CarrierChoice::Lan, &[lan("10.0.0.2:7420")]);
        assert_eq!(
            plan(Some(&lan_only), &both, true, true),
            vec![lan("10.0.0.9:7420"), lan("10.0.0.2:7420")]
        );
        let inet_only = record(CarrierChoice::Internet, &[inet("[::1]:7422")]);
        assert_eq!(
            plan(Some(&inet_only), &both, true, true),
            vec![inet("203.0.113.7:7422"), inet("[::1]:7422")]
        );
        // No record: the narrowest plan, LAN from the contact book only.
        assert_eq!(plan(None, &both, true, true), vec![lan("10.0.0.9:7420")]);
        // Junk is never dialled; duplicates collapse.
        let junk = contact(&[lan("10.0.0.2:7420")], false);
        let rec = record(
            CarrierChoice::Lan,
            &[
                lan("local-listen"),
                lan("10.0.0.2:0"),
                lan(" 10.0.0.2:7420 "),
            ],
        );
        assert_eq!(
            plan(Some(&rec), &junk, true, false),
            vec![lan("10.0.0.2:7420")]
        );
        assert!(OutboxCarrier::Lan.confidential_to_endpoint());
        assert!(OutboxCarrier::Internet.confidential_to_endpoint());
    }

    /// The path tokens are exact: what `label` prints, `parse` reads back,
    /// and serde agrees; nothing else parses.
    #[test]
    fn delivery_path_labels_round_trip_and_reject_junk() {
        let want = ["direct", "reversed", "relayed", "hole_punched"];
        for (p, label) in DeliveryPath::ALL.into_iter().zip(want) {
            assert_eq!(p.label(), label);
            assert_eq!(DeliveryPath::parse(label), Some(p));
            assert_eq!(serde_json::to_string(&p).unwrap(), format!("\"{label}\""));
        }
        for junk in ["", "Direct", "hole-punched", " direct", "relay", "p2p_dial"] {
            assert_eq!(DeliveryPath::parse(junk), None, "{junk:?}");
        }
    }

    /// G4, release equivalence:while Internet and p2p are held, an `auto`
    /// record plans exactly what a `lan` one plans (routes and the
    /// verified-contact flag), whatever the contact and the recorded routes.
    #[test]
    fn auto_and_lan_plan_alike_while_internet_and_p2p_are_held() {
        let peer = crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[9; 32]));
        let p2p = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: crate::p2p_route::peer_route(&peer),
        };
        let (l, i) = (lan("10.0.0.9:7420"), inet("203.0.113.7:7422"));
        let books: [Vec<OutboxRoute>; 4] = [
            vec![l.clone()],
            vec![l.clone(), i.clone()],
            vec![i.clone()],
            vec![l.clone(), i.clone(), p2p],
        ];
        let recorded: [Vec<OutboxRoute>; 2] =
            [vec![], vec![lan("10.0.0.2:7420"), inet("[::1]:7422")]];
        let held = [
            CarrierGates {
                lan: true,
                internet: false,
                p2p: false,
                nearby: false,
                onion: false,
            },
            CarrierGates::default(),
        ];
        let mut cases = 0;
        for book in &books {
            for pinned in [false, true] {
                let c = contact(book, pinned);
                for routes in &recorded {
                    for g in held {
                        let auto = record(CarrierChoice::Auto, routes);
                        let lan_only = record(CarrierChoice::Lan, routes);
                        assert_eq!(
                            plan_object_routes(Some(&auto), &c, g),
                            plan_object_routes(Some(&lan_only), &c, g),
                            "{book:?} pinned={pinned} recorded={routes:?} {g:?}"
                        );
                        cases += 1;
                    }
                }
            }
        }
        assert_eq!(cases, 32);
        // Not vacuous: with the Internet gate open they differ.
        let open = gates(true, true);
        let c = contact(&[l.clone(), i.clone()], true);
        let auto = plan_object_routes(Some(&record(CarrierChoice::Auto, &[])), &c, open);
        let lan_only = plan_object_routes(Some(&record(CarrierChoice::Lan, &[])), &c, open);
        assert_eq!(auto.routes, vec![l.clone(), i]);
        assert_eq!(lan_only.routes, vec![l]);
    }

    /// G2: a remembered route only moves to the front of a plan that already
    /// holds it, after every rule; it never adds a route, and it is not cut
    /// off by the per-object cap.
    #[test]
    fn a_remembered_route_only_reorders_the_plan() {
        let (l, i) = (lan("10.0.0.9:7420"), inet("203.0.113.7:7422"));
        let auto = record(CarrierChoice::Auto, &[]);
        let pinned = contact(&[l.clone(), i.clone()], true);
        let open = gates(true, true);
        let preferring = |rec: &ObjectRoutes, c: &ContactRoutes, g, p: &OutboxRoute| {
            plan_object_routes_preferring(Some(rec), c, g, Some(p))
        };
        assert_eq!(
            preferring(&auto, &pinned, open, &i).routes,
            vec![i.clone(), l.clone()]
        );
        assert_eq!(
            plan_object_routes_preferring(Some(&auto), &pinned, open, None),
            plan_object_routes(Some(&auto), &pinned, open)
        );
        // Unpinned (the verified-contact rule), the Internet gate closed, a
        // `--carrier lan` record, a route the plan does not hold: the plain plan.
        let unpinned = contact(&[l.clone(), i.clone()], false);
        let p = preferring(&auto, &unpinned, open, &i);
        assert_eq!(p, plan_object_routes(Some(&auto), &unpinned, open));
        assert_eq!(p.routes, vec![l.clone()]);
        assert!(p.unverified_withheld);
        let held = gates(true, false);
        assert_eq!(
            preferring(&auto, &pinned, held, &i),
            plan_object_routes(Some(&auto), &pinned, held)
        );
        let lan_only = record(CarrierChoice::Lan, &[]);
        assert_eq!(
            preferring(&lan_only, &pinned, open, &i),
            plan_object_routes(Some(&lan_only), &pinned, open)
        );
        let elsewhere = inet("198.51.100.9:7422");
        assert_eq!(
            preferring(&auto, &pinned, open, &elsewhere),
            plan_object_routes(Some(&auto), &pinned, open)
        );
        // Recorded past the cap: the remembered route survives it, and the
        // routes stay unique.
        let late = inet("[2001:db8::7]:7422");
        let many = record(
            CarrierChoice::Auto,
            &[
                lan("10.0.0.2:7420"),
                lan("10.0.0.3:7420"),
                l.clone(),
                lan("10.0.0.4:7420"),
                lan("10.0.0.5:7420"),
                lan("10.0.0.6:7420"),
                late.clone(),
            ],
        );
        let plain = plan_object_routes(Some(&many), &pinned, open).routes;
        assert_eq!(plain.len(), MAX_ROUTES_PER_OBJECT);
        assert!(!plain.contains(&late), "past the cap");
        let first = preferring(&many, &pinned, open, &late).routes;
        assert_eq!(first.len(), MAX_ROUTES_PER_OBJECT);
        assert_eq!(first[0], late);
        assert_eq!(first[1..], plain[..MAX_ROUTES_PER_OBJECT - 1]);
        let mut unique = first.clone();
        unique.sort_by_key(|r| (r.carrier, r.dial.clone()));
        unique.dedup();
        assert_eq!(unique.len(), first.len());
    }

    /// A random contact, record and gates for the ranked-plan properties:
    /// LAN, Internet, p2p and nearby routes (some junk, some repeated), any
    /// carrier choice, any gates, verified or not, hide-IP and LAN
    /// verified-only either way.
    fn random_plan_case(
        rng: &mut rand::rngs::StdRng,
        peers: &[String; 2],
    ) -> (ContactRoutes, ObjectRoutes, CarrierGates) {
        use rand::Rng;
        let route = |rng: &mut rand::rngs::StdRng| match rng.gen_range(0..8) {
            0..=2 => lan(&format!("10.0.0.{}:7420", rng.gen_range(1..9))),
            3 | 4 => inet(&format!("203.0.113.{}:7422", rng.gen_range(1..5))),
            5 => p2p_route(&peers[rng.gen_range(0..2)]),
            6 => nearby(&[rng.gen_range(1u8..3); 32]),
            _ => lan("junk"),
        };
        let book: Vec<OutboxRoute> = (0..rng.gen_range(0..6)).map(|_| route(rng)).collect();
        let sent: Vec<OutboxRoute> = (0..rng.gen_range(0..6)).map(|_| route(rng)).collect();
        let mut c = contact(&book, rng.gen_bool(0.7));
        c.hide_ip = rng.gen_bool(0.2);
        c.lan_verified_only = rng.gen_bool(0.2);
        let choices = [
            CarrierChoice::Auto,
            CarrierChoice::Auto,
            CarrierChoice::Lan,
            CarrierChoice::Internet,
            CarrierChoice::P2p,
            CarrierChoice::Nearby,
        ];
        let rec = record(choices[rng.gen_range(0..choices.len())], &sent);
        let g = CarrierGates {
            lan: rng.gen_bool(0.8),
            internet: rng.gen_bool(0.8),
            p2p: rng.gen_bool(0.7),
            nearby: rng.gen_bool(0.5),
            onion: false,
        };
        (c, rec, g)
    }

    fn two_peer_ids() -> [String; 2] {
        [3, 4].map(|s| crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[s; 32])))
    }

    /// P6.5: with no order, the ranked planner plans exactly what the
    /// unranked ones plan. Every plan test of this module checks it on each
    /// call (the shadowing `plan_object_routes` wrappers); this adds a
    /// seeded sweep.
    #[test]
    fn ranked_with_none_equals_preferring_with_none() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x6a_0405);
        let peers = two_peer_ids();
        for _ in 0..5_000 {
            let (c, rec, g) = random_plan_case(&mut rng, &peers);
            let rec = rng.gen_bool(0.8).then_some(&rec);
            let ranked = plan_object_routes_ranked(rec, &c, g, None);
            assert_eq!(
                ranked,
                super::plan_object_routes_preferring(rec, &c, g, None)
            );
            assert_eq!(ranked, super::plan_object_routes(rec, &c, g));
            assert!(!ranked.learning_contradiction);
        }
    }

    /// P6.5: whatever the model learned, a ranked plan is a reorder of the
    /// static one: the same length, only routes the rules planned before the
    /// cap (so no carrier outside the gates), no route twice, nearby in its
    /// slot, and the plan's own order within each carrier.
    #[test]
    fn ranked_plan_is_a_permutation_property() {
        use crate::learning::model::Model;
        use crate::learning::observe::{DialTiming, Evidence, FrameKind, Observation};
        use crate::learning::rank;
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x6a_0406);
        let peers = two_peer_ids();
        let carriers = [
            OutboxCarrier::Lan,
            OutboxCarrier::Internet,
            OutboxCarrier::P2p,
        ];
        let (mut reordered, mut cut_differently) = (0, 0);
        for round in 0..10_000u64 {
            let (c, rec, g) = random_plan_case(&mut rng, &peers);
            let peer = [(round % 7) as u8; 32];
            let mut model = Model::new_empty([(round % 5) as u8; 32]);
            let now = 1_800_000_000_000 + round;
            for _ in 0..rng.gen_range(0..10) {
                let evidence = match rng.gen_range(0..4) {
                    0 => Evidence::Receipt,
                    1 => Evidence::Link,
                    2 => Evidence::Silent,
                    _ => Evidence::Fail {
                        code: "NOT_REACHABLE",
                        weight_milli: 1_000,
                    },
                };
                let obs = Observation {
                    contact: peer,
                    net: None,
                    net_changed: false,
                    carrier: carriers[rng.gen_range(0..3)],
                    path: None,
                    relay: None,
                    kind: FrameKind::Message,
                    evidence,
                    timing: DialTiming {
                        connect_ms: None,
                        reply_ms: None,
                        total_ms: rng.gen_range(1..40_000),
                    },
                    karn_exclude: false,
                    at_ms: now,
                };
                model.observe(&obs, now);
            }
            let uncapped = filtered_routes(Some(&rec), &c, g).routes;
            let fixed = plan_object_routes(Some(&rec), &c, g);
            let static_carriers = if rng.gen_bool(0.5) {
                rank::carriers_of(&uncapped)
            } else {
                rank::carriers_of(&fixed.routes)
            };
            if rng.gen_bool(0.3) {
                let mut current = static_carriers.clone();
                current.reverse();
                let o = rank::order(&model, &peer, None, &current, None, now);
                model.remember_order(&peer, None, &o);
            }
            let order = rank::order(&model, &peer, None, &static_carriers, None, now);
            assert!(order.well_formed());
            let ranked = plan_object_routes_ranked(Some(&rec), &c, g, Some(&order));
            assert!(!ranked.learning_contradiction, "{order:?}");
            assert_eq!(ranked.unverified_withheld, fixed.unverified_withheld);
            assert_eq!(ranked.routes.len(), fixed.routes.len());
            for (i, r) in ranked.routes.iter().enumerate() {
                assert!(uncapped.contains(r) && g.allows(r.carrier), "{r:?}");
                assert!(!ranked.routes[..i].contains(r));
                if fixed.routes[i].carrier == OutboxCarrier::Nearby {
                    assert_eq!(*r, fixed.routes[i]);
                }
            }
            for carrier in carriers {
                let within = |routes: &[OutboxRoute]| -> Vec<OutboxRoute> {
                    routes
                        .iter()
                        .filter(|r| r.carrier == carrier)
                        .cloned()
                        .collect()
                };
                let (got, all) = (within(&ranked.routes), within(&uncapped));
                assert_eq!(got[..], all[..got.len()]);
            }
            reordered += usize::from(ranked.routes != fixed.routes);
            let mut a = ranked.routes.clone();
            let mut b = fixed.routes.clone();
            a.sort_by(|x, y| (x.carrier, &x.dial).cmp(&(y.carrier, &y.dial)));
            b.sort_by(|x, y| (x.carrier, &x.dial).cmp(&(y.carrier, &y.dial)));
            cut_differently += usize::from(a != b);
        }
        // Not vacuous: many plans were reordered, and some lost a different
        // route to the cap.
        assert!(reordered > 500, "{reordered}");
        assert!(cut_differently > 0, "{cut_differently}");
    }

    /// The order the model wants, for `peer`: LAN failed twice, Internet
    /// delivered twice.
    fn internet_first_model(peer: &[u8; 32]) -> crate::learning::model::Model {
        use crate::learning::observe::{DialTiming, Evidence, FrameKind, Observation};
        let mut m = crate::learning::model::Model::new_empty([5; 32]);
        for (carrier, evidence) in [
            (
                OutboxCarrier::Lan,
                Evidence::Fail {
                    code: "NOT_REACHABLE",
                    weight_milli: 1_000,
                },
            ),
            (
                OutboxCarrier::Lan,
                Evidence::Fail {
                    code: "NOT_REACHABLE",
                    weight_milli: 1_000,
                },
            ),
            (OutboxCarrier::Internet, Evidence::Receipt),
            (OutboxCarrier::Internet, Evidence::Receipt),
        ] {
            let obs = Observation {
                contact: *peer,
                net: None,
                net_changed: false,
                carrier,
                path: None,
                relay: None,
                kind: FrameKind::Message,
                evidence,
                timing: DialTiming {
                    connect_ms: None,
                    reply_ms: None,
                    total_ms: 900,
                },
                karn_exclude: false,
                at_ms: 1_800_000_000_000,
            };
            m.observe(&obs, 1_800_000_000_000);
        }
        m
    }

    /// A send that forced one carrier, or a contact that is not verified
    /// (LAN only), leaves the ranker nothing to reorder: the plan is the
    /// static one, with no contradiction.
    #[test]
    fn a_forced_carrier_or_unverified_contact_has_nothing_to_reorder() {
        use crate::learning::rank;
        let now = 1_800_000_000_000;
        let bob = [0xB0; 32];
        let m = internet_first_model(&bob);
        let (l, i) = (lan("10.0.0.9:7420"), inet("203.0.113.7:7422"));
        let open = gates(true, true);
        let pinned = contact(&[l.clone(), i.clone()], true);
        let auto = record(CarrierChoice::Auto, &[lan("10.0.0.2:7420")]);
        // Not vacuous: an `auto` send to a verified contact is reordered.
        let fixed = plan_object_routes(Some(&auto), &pinned, open);
        let o = rank::order(&m, &bob, None, &rank::carriers_of(&fixed.routes), None, now);
        assert_eq!(o.carriers, [OutboxCarrier::Internet, OutboxCarrier::Lan]);
        assert_eq!(
            plan_object_routes_ranked(Some(&auto), &pinned, open, Some(&o)).routes,
            vec![i.clone(), l.clone(), lan("10.0.0.2:7420")]
        );
        // `--carrier lan` / `--carrier internet`: one carrier in the plan.
        for choice in [CarrierChoice::Lan, CarrierChoice::Internet] {
            let forced = record(choice, &[]);
            let fixed = plan_object_routes(Some(&forced), &pinned, open);
            let own = rank::order(&m, &bob, None, &rank::carriers_of(&fixed.routes), None, now);
            assert_eq!(own.carriers.len(), 1);
            for order in [&own, &o] {
                let p = plan_object_routes_ranked(Some(&forced), &pinned, open, Some(order));
                assert_eq!(p, fixed);
            }
        }
        // Not verified: LAN only, whatever the order says.
        let unpinned = contact(&[l.clone(), i.clone()], false);
        let fixed = plan_object_routes(Some(&auto), &unpinned, open);
        assert_eq!(
            rank::order(&m, &bob, None, &rank::carriers_of(&fixed.routes), None, now).carriers,
            [OutboxCarrier::Lan]
        );
        let p = plan_object_routes_ranked(Some(&auto), &unpinned, open, Some(&o));
        assert_eq!(p, fixed);
        assert!(p.unverified_withheld && !p.learning_contradiction);
        assert!(p.routes.iter().all(|r| r.carrier == OutboxCarrier::Lan));
    }

    /// An order that is not a pure reorder (a corrupted one) gives the
    /// static plan and says so; the caller then pins the contact-network to
    /// the static order for an hour.
    #[test]
    fn contradiction_falls_back() {
        use crate::learning::explain::{Detail, State, Why};
        use crate::learning::model::CONTRADICTION_PIN_MS;
        use crate::learning::rank::{self, Order};
        let now = 1_800_000_000_000;
        let bob = [0xB0; 32];
        let (l, i) = (lan("10.0.0.9:7420"), inet("203.0.113.7:7422"));
        let all = CarrierGates {
            lan: true,
            internet: true,
            p2p: true,
            nearby: true,
            onion: false,
        };
        let pinned = with_nearby_route(contact(&[l.clone(), i.clone()], true), &bob, true);
        let auto = record(CarrierChoice::Auto, &[]);
        let fixed = plan_object_routes(Some(&auto), &pinned, all);
        assert_eq!(fixed.routes.len(), 3);
        let corrupted = |carriers: Vec<OutboxCarrier>| Order {
            carriers,
            why: Why::Faster,
            detail: Detail::default(),
        };
        for bad in [
            corrupted(vec![
                OutboxCarrier::Internet,
                OutboxCarrier::Internet,
                OutboxCarrier::Lan,
            ]),
            corrupted(vec![OutboxCarrier::Nearby, OutboxCarrier::Internet]),
            corrupted(vec![
                OutboxCarrier::Internet,
                OutboxCarrier::Lan,
                OutboxCarrier::Nearby,
            ]),
        ] {
            let p = plan_object_routes_ranked(Some(&auto), &pinned, all, Some(&bad));
            assert!(p.learning_contradiction, "{bad:?}");
            assert_eq!(p.routes, fixed.routes);
            assert_eq!(p.unverified_withheld, fixed.unverified_withheld);
        }
        // A well-formed order never contradicts, even one naming a carrier
        // the plan does not hold.
        let fine = corrupted(vec![
            OutboxCarrier::P2p,
            OutboxCarrier::Internet,
            OutboxCarrier::Lan,
        ]);
        let p = plan_object_routes_ranked(Some(&auto), &pinned, all, Some(&fine));
        assert!(!p.learning_contradiction);
        assert_eq!(p.routes, vec![i.clone(), l.clone(), nearby(&bob)]);
        // The invariant itself refuses an added, a lost or a doubled route.
        let uncapped = filtered_routes(Some(&auto), &pinned, all).routes;
        let n = fixed.routes.len();
        assert!(rank::same_set_as_static(&p.routes, &uncapped, n));
        let extra = vec![i.clone(), lan("10.0.0.66:7420"), nearby(&bob)];
        assert!(!rank::same_set_as_static(&extra, &uncapped, n));
        assert!(!rank::same_set_as_static(&p.routes[..2], &uncapped, n));
        let doubled = vec![i.clone(), i.clone(), nearby(&bob)];
        assert!(!rank::same_set_as_static(&doubled, &uncapped, n));
        // The caller's pin: the static order, as a contradiction, for an hour.
        let mut m = internet_first_model(&bob);
        let carriers = rank::carriers_of(&fixed.routes);
        assert_eq!(
            rank::order(&m, &bob, None, &carriers, None, now).carriers[0],
            OutboxCarrier::Internet
        );
        m.note_contradiction(&bob, None, now);
        let o = rank::order(&m, &bob, None, &carriers, None, now);
        assert_eq!(o, Order::fixed(&carriers, Why::Contradiction, State::On));
        let p = plan_object_routes_ranked(Some(&auto), &pinned, all, Some(&o));
        assert_eq!(
            (p.routes, p.learning_contradiction),
            (fixed.routes.clone(), false)
        );
        let later = rank::order(&m, &bob, None, &carriers, None, now + CONTRADICTION_PIN_MS);
        assert_eq!(later.carriers[0], OutboxCarrier::Internet);
        assert_eq!(m.counters().contradictions, 1);
    }

    /// G4: a re-recorded object keeps the carrier choice of the send that
    /// queued it; only its routes are refreshed, within that choice.
    #[test]
    fn a_re_recorded_object_keeps_its_own_sends_choice() {
        let dir = tempfile::tempdir().unwrap();
        let bob = [7u8; 32];
        let now = crate::clock::now_ms();
        let (a, b) = ([0xa; 16], [0xb; 16]);
        let rec = |mid: &[u8; 16], choice: CarrierChoice, routes: &[OutboxRoute]| {
            record_object_routes(dir.path(), mid, &bob, choice, routes, now + 10_000, now).unwrap();
        };
        // `--carrier lan` first: a later auto send never widens it.
        rec(&a, CarrierChoice::Lan, &[lan("10.0.0.2:7420")]);
        set_object_unsent(dir.path(), &a, true, now).unwrap();
        set_object_custody(dir.path(), &a, now).unwrap();
        add_object_custodians(dir.path(), &a, &[[3u8; 32]], now).unwrap();
        rec(
            &a,
            CarrierChoice::Auto,
            &[lan("10.0.0.3:7420"), inet("203.0.113.7:7422")],
        );
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(got[&a].choice, CarrierChoice::Lan);
        assert_eq!(got[&a].routes, vec![lan("10.0.0.3:7420")]);
        assert!(got[&a].unsent && got[&a].custody);
        assert_eq!(got[&a].custodians_held, vec![hex::encode([3u8; 32])]);
        // An auto send first: a later `--carrier lan` send never narrows it.
        rec(&b, CarrierChoice::Auto, &[lan("10.0.0.2:7420")]);
        rec(&b, CarrierChoice::Lan, &[lan("10.0.0.4:7420")]);
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(got[&b].choice, CarrierChoice::Auto);
        assert_eq!(got[&b].routes, vec![lan("10.0.0.4:7420")]);
        // Cleared first, it takes the new send's choice.
        clear_object_routes(dir.path(), &[b]).unwrap();
        rec(&b, CarrierChoice::Internet, &[inet("203.0.113.7:7422")]);
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(got[&b].choice, CarrierChoice::Internet);
    }

    /// Owner decision 2026-10-08: Internet only for verified (pinned) contacts;
    /// LAN for every contact, at local-network addresses unless verified.
    #[test]
    fn internet_needs_a_verified_contact_and_lan_does_not() {
        assert!(carrier_allowed_for_contact(OutboxCarrier::Lan, false));
        assert!(carrier_allowed_for_contact(OutboxCarrier::Lan, true));
        assert!(!carrier_allowed_for_contact(OutboxCarrier::Internet, false));
        assert!(carrier_allowed_for_contact(OutboxCarrier::Internet, true));
        let auto = record(CarrierChoice::Auto, &[]);
        let unpinned = contact(&[lan("10.0.0.2:7420"), inet("203.0.113.7:7422")], false);
        let p = plan_object_routes(Some(&auto), &unpinned, gates(true, true));
        assert_eq!(p.routes, vec![lan("10.0.0.2:7420")]);
        assert!(p.unverified_withheld);
        let only_inet = contact(&[inet("[::1]:7422")], false);
        let p = plan_object_routes(Some(&auto), &only_inet, gates(true, true));
        assert!(p.routes.is_empty() && p.unverified_withheld);
        // The gate decides first: with it off nothing was withheld for trust.
        let p = plan_object_routes(Some(&auto), &only_inet, gates(true, false));
        assert!(p.routes.is_empty() && !p.unverified_withheld);
        let p = plan_object_routes(
            Some(&auto),
            &contact(&[inet("[::1]:7422")], true),
            gates(true, true),
        );
        assert_eq!(p.routes, vec![inet("[::1]:7422")]);
    }

    /// Phase 3 P3.C2 (cutoff M1): under `raven lan verified-only on` an
    /// unverified contact gets no LAN route either (withheld for trust, so
    /// the worker holds the message as CONTACT_NOT_VERIFIED and dials
    /// nothing); a verified one keeps its plan. The delivery planners take the
    /// setting from the node policy ([`with_learned_routes`]).
    #[test]
    fn verified_only_withholds_the_lan_routes_of_an_unverified_contact() {
        let auto = record(CarrierChoice::Auto, &[]);
        let routes = [lan("10.0.0.2:7420"), inet("203.0.113.7:7422")];
        let unpinned = ContactRoutes {
            lan_verified_only: true,
            ..contact(&routes, false)
        };
        assert!(!unpinned.allows(OutboxCarrier::Lan));
        assert!(!unpinned.allows(OutboxCarrier::Internet));
        let p = plan_object_routes(Some(&auto), &unpinned, gates(true, true));
        assert!(p.routes.is_empty() && p.unverified_withheld, "{p:?}");
        let p = plan_object_routes(None, &unpinned, gates(true, false));
        assert!(p.routes.is_empty() && p.unverified_withheld, "{p:?}");
        let pinned = ContactRoutes {
            lan_verified_only: true,
            ..contact(&routes, true)
        };
        assert!(pinned.allows(OutboxCarrier::Lan));
        let p = plan_object_routes(Some(&auto), &pinned, gates(true, true));
        assert_eq!(p.routes, routes.to_vec());
        assert!(!p.unverified_withheld);
        // Off (the default): as before.
        assert!(contact(&routes, false).allows(OutboxCarrier::Lan));

        let dir = tempfile::tempdir().unwrap();
        let peer = [0x6au8; 32];
        let learned = |dd: &Path| with_learned_routes(dd, &peer, contact(&routes, false));
        assert!(!learned(dir.path()).lan_verified_only);
        crate::node_policy::set_lan_verified_only(dir.path(), true).unwrap();
        assert!(learned(dir.path()).lan_verified_only);
        let p = plan_object_routes(Some(&auto), &learned(dir.path()), gates(true, true));
        assert!(p.routes.is_empty() && p.unverified_withheld, "{p:?}");
    }

    /// P3: p2p is for verified contacts only, behind its own gate, planned
    /// after LAN and Internet (last among LAN, Internet and p2p: Phase 5's
    /// nearby comes after it, [`nearby_is_planned_last_and_only_for_verified_contacts`]);
    /// `--carrier p2p` stays p2p-only; PairInit may ride it (the Raven Noise
    /// link ends at the contact).
    #[test]
    fn p2p_is_planned_last_for_verified_contacts_behind_its_gate() {
        assert!(!carrier_allowed_for_contact(OutboxCarrier::P2p, false));
        assert!(carrier_allowed_for_contact(OutboxCarrier::P2p, true));
        assert!(OutboxCarrier::P2p.confidential_to_endpoint());
        assert_eq!(OutboxCarrier::P2p.label(), "p2p_dial");
        let peer = crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[9; 32]));
        let p2p = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: crate::p2p_route::peer_route(&peer),
        };
        let all = CarrierGates {
            lan: true,
            internet: true,
            p2p: true,
            nearby: false,
            onion: false,
        };
        let pinned = contact(
            &[lan("10.0.0.9:7420"), inet("203.0.113.7:7422"), p2p.clone()],
            true,
        );
        let auto = record(CarrierChoice::Auto, &[]);
        assert_eq!(
            plan_object_routes(Some(&auto), &pinned, all).routes,
            vec![lan("10.0.0.9:7420"), inet("203.0.113.7:7422"), p2p.clone()]
        );
        // The p2p gate off: nothing p2p, and nothing "withheld" for trust.
        let no_p2p = CarrierGates { p2p: false, ..all };
        let p = plan_object_routes(
            Some(&auto),
            &contact(std::slice::from_ref(&p2p), true),
            no_p2p,
        );
        assert!(p.routes.is_empty() && !p.unverified_withheld);
        // Unverified: withheld, LAN kept.
        let unpinned = contact(&[lan("10.0.0.9:7420"), p2p.clone()], false);
        let p = plan_object_routes(Some(&auto), &unpinned, all);
        assert_eq!(p.routes, vec![lan("10.0.0.9:7420")]);
        assert!(p.unverified_withheld);
        // `--carrier p2p` never widens to LAN or Internet.
        let only = record(CarrierChoice::P2p, &[p2p.clone(), lan("10.0.0.2:7420")]);
        assert_eq!(
            plan_object_routes(Some(&only), &pinned, all).routes,
            vec![p2p.clone()]
        );
        assert!(CarrierChoice::P2p.allows(OutboxCarrier::P2p));
        assert!(!CarrierChoice::P2p.allows(OutboxCarrier::Internet));
        // Junk p2p dials are never planned or recorded.
        let junk = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: "203.0.113.7:7423".into(),
        };
        assert!(!plausible_route(&junk));
        assert!(plausible_route(&p2p));
        let p = plan_object_routes(
            Some(&record(CarrierChoice::P2p, &[junk])),
            &contact(&[], true),
            all,
        );
        assert!(p.routes.is_empty());
    }

    fn nearby(peer: &[u8; 32]) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Nearby,
            dial: nearby_dial_for(peer),
        }
    }

    /// Phase 5 (P5.25, RNL1 §7): nearby is for verified contacts only,
    /// behind its own gate, derived live by [`with_nearby_route`] and planned
    /// after every other carrier; a `--carrier nearby` object never widens;
    /// PairInit may ride it; the cap never cuts it off.
    #[test]
    fn nearby_is_planned_last_and_only_for_verified_contacts() {
        let bob = [0x4b; 32];
        assert!(!carrier_allowed_for_contact(OutboxCarrier::Nearby, false));
        assert!(carrier_allowed_for_contact(OutboxCarrier::Nearby, true));
        assert!(OutboxCarrier::Nearby.confidential_to_endpoint());
        assert_eq!(OutboxCarrier::Nearby.label(), "nearby_dial");
        assert_eq!(
            serde_json::to_string(&OutboxCarrier::Nearby).unwrap(),
            r#""nearby""#
        );
        assert_eq!(
            serde_json::to_string(&CarrierChoice::Nearby).unwrap(),
            r#""nearby""#
        );
        // The last carrier: the plan order puts it after p2p.
        assert!(OutboxCarrier::P2p < OutboxCarrier::Nearby);
        let peer = crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[9; 32]));
        let p2p = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: crate::p2p_route::peer_route(&peer),
        };
        let all = CarrierGates {
            lan: true,
            internet: true,
            p2p: true,
            nearby: true,
            onion: false,
        };
        let routes = [lan("10.0.0.9:7420"), inet("203.0.113.7:7422"), p2p.clone()];
        let pinned = with_nearby_route(contact(&routes, true), &bob, true);
        assert_eq!(pinned.routes.last(), Some(&nearby(&bob)));
        let auto = record(CarrierChoice::Auto, &[lan("10.0.0.2:7420")]);
        assert_eq!(
            plan_object_routes(Some(&auto), &pinned, all).routes,
            vec![
                lan("10.0.0.9:7420"),
                inet("203.0.113.7:7422"),
                p2p.clone(),
                lan("10.0.0.2:7420"),
                nearby(&bob)
            ]
        );
        // Added once, however often it is asked for.
        let twice = with_nearby_route(pinned.clone(), &bob, true);
        assert_eq!(twice, pinned);
        // Not available (engine off, nearby not enabled, no pair key): the
        // contact as it was.
        assert_eq!(
            with_nearby_route(contact(&routes, true), &bob, false),
            contact(&routes, true)
        );
        // Unverified: never added, and a nearby route such a contact holds
        // anyway is withheld for trust (CONTACT_NOT_VERIFIED); LAN is kept.
        let unpinned = contact(&[lan("10.0.0.9:7420")], false);
        assert_eq!(with_nearby_route(unpinned.clone(), &bob, true), unpinned);
        let holding = contact(&[lan("10.0.0.9:7420"), nearby(&bob)], false);
        let p = plan_object_routes(Some(&auto), &holding, all);
        assert_eq!(p.routes, vec![lan("10.0.0.9:7420"), lan("10.0.0.2:7420")]);
        assert!(p.unverified_withheld);
        // The nearby gate off: nothing nearby, and nothing withheld for trust.
        let no_nearby = CarrierGates {
            nearby: false,
            ..all
        };
        let only = contact(&[nearby(&bob)], true);
        let bare = record(CarrierChoice::Auto, &[]);
        let p = plan_object_routes(Some(&bare), &only, no_nearby);
        assert!(p.routes.is_empty() && !p.unverified_withheld);
        assert_eq!(
            plan_object_routes(Some(&bare), &only, all).routes,
            vec![nearby(&bob)]
        );
        // `--carrier nearby` never widens; other forced carriers never
        // narrow to nearby.
        let forced = record(CarrierChoice::Nearby, &[lan("10.0.0.2:7420")]);
        assert_eq!(
            plan_object_routes(Some(&forced), &pinned, all).routes,
            vec![nearby(&bob)]
        );
        assert!(CarrierChoice::Nearby.allows(OutboxCarrier::Nearby));
        assert!(!CarrierChoice::Nearby.allows(OutboxCarrier::Lan));
        for choice in [
            CarrierChoice::Lan,
            CarrierChoice::Internet,
            CarrierChoice::P2p,
        ] {
            assert!(!choice.allows(OutboxCarrier::Nearby), "{choice:?}");
            let p = plan_object_routes(Some(&record(choice, &[])), &pinned, all);
            assert!(
                p.routes.iter().all(|r| r.carrier != OutboxCarrier::Nearby),
                "{choice:?}"
            );
        }
        // No record (rows of older builds): LAN only, as before.
        assert_eq!(
            plan_object_routes(None, &pinned, all).routes,
            vec![lan("10.0.0.9:7420")]
        );
        // A nearby route in a record (none is ever written) is not planned:
        // nearby routes are the contact's, derived live.
        let carol = [0x4c; 32];
        let stray = record(CarrierChoice::Auto, &[nearby(&carol)]);
        let p = plan_object_routes(Some(&stray), &contact(&routes, true), all);
        assert!(p.routes.iter().all(|r| r.carrier != OutboxCarrier::Nearby));
        // A full plan: the cap keeps six routes of the other carriers and the
        // nearby route on top; without nearby, exactly the six of before.
        let many: Vec<OutboxRoute> = (1..=8).map(|i| lan(&format!("10.0.0.{i}:7420"))).collect();
        let full = with_nearby_route(contact(&many, true), &bob, true);
        let p = plan_object_routes(Some(&auto), &full, all);
        assert_eq!(p.routes.len(), MAX_ROUTES_PER_OBJECT + 1);
        assert_eq!(
            p.routes[..MAX_ROUTES_PER_OBJECT],
            many[..MAX_ROUTES_PER_OBJECT]
        );
        assert_eq!(p.routes.last(), Some(&nearby(&bob)));
        assert_eq!(
            plan_object_routes(Some(&auto), &contact(&many, true), all).routes,
            many[..MAX_ROUTES_PER_OBJECT].to_vec()
        );
        // A remembered nearby route goes first, as any remembered route.
        let p = plan_object_routes_preferring(Some(&auto), &pinned, all, Some(&nearby(&bob)));
        assert_eq!(p.routes.first(), Some(&nearby(&bob)));
        assert_eq!(p.routes.len(), 5);
    }

    /// Phase 5 (P5.25): the nearby route is derived live and never stored;
    /// only a `--carrier nearby` choice says "nearby" in the file.
    #[test]
    fn nearby_route_is_never_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000;
        let bob = [0x4b; 32];
        let (a, b) = ([0xA1; 16], [0xA2; 16]);
        record_object_routes(
            dir.path(),
            &a,
            &bob,
            CarrierChoice::Auto,
            &[lan("10.0.0.2:7420"), nearby(&bob)],
            now + 60_000,
            now,
        )
        .unwrap();
        record_object_routes(
            dir.path(),
            &b,
            &bob,
            CarrierChoice::Nearby,
            &[nearby(&bob)],
            now + 60_000,
            now,
        )
        .unwrap();
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(got[&a].routes, vec![lan("10.0.0.2:7420")]);
        assert_eq!(got[&b].choice, CarrierChoice::Nearby);
        assert!(got[&b].routes.is_empty());
        let raw = std::fs::read_to_string(dir.path().join(OUTBOX_ROUTES_FILE)).unwrap();
        assert!(!raw.contains(NEARBY_DIAL_PREFIX), "{raw}");
        assert_eq!(raw.matches(r#""nearby""#).count(), 1, "{raw}");
        // Re-recording an object never adds one either.
        record_object_routes(
            dir.path(),
            &a,
            &bob,
            CarrierChoice::Auto,
            &[nearby(&bob)],
            now + 60_000,
            now,
        )
        .unwrap();
        assert!(object_route_records(dir.path(), now).unwrap()[&a]
            .routes
            .is_empty());
    }

    /// Phase 5 (P5.25, RNL1 §11): `objects` is decoded entry by entry. An
    /// entry this build cannot parse (a newer build's carrier or choice) no
    /// longer makes the file unreadable: the others are read, and every
    /// edit writes it back unchanged until it expires or its object is
    /// cleared. It is never planned or re-recorded; it counts against the
    /// cap; a file without one is written exactly as before.
    #[test]
    fn an_unknown_object_entry_survives_an_edit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OUTBOX_ROUTES_FILE);
        // Raven's clock: clear_peer_routes and clear_object_routes age the
        // file at it.
        let now = crate::clock::now_ms();
        const HOUR: u64 = 3_600_000;
        // A record outlives its envelope by the horizon while it is live.
        let grace = if crate::horizon::horizon_live_enabled() {
            crate::horizon::MESSAGE_HORIZON_MS
        } else {
            0
        };
        let bob = [0x4b; 32];
        let (known, newer, older) = ([0xB1; 16], [0xB2; 16], [0xB3; 16]);
        record_object_routes(
            dir.path(),
            &known,
            &bob,
            CarrierChoice::Auto,
            &[lan("10.0.0.2:7420")],
            now + HOUR,
            now,
        )
        .unwrap();
        // Without unknown entries, the very bytes of the old writer.
        let mut before: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        #[derive(Serialize)]
        struct OldRouteFile<'a> {
            objects: &'a BTreeMap<String, ObjectRoutes>,
        }
        let records: BTreeMap<String, ObjectRoutes> = object_route_records(dir.path(), now)
            .unwrap()
            .into_iter()
            .map(|(k, r)| (hex::encode(k), r))
            .collect();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            serde_json::to_vec_pretty(&OldRouteFile { objects: &records }).unwrap()
        );
        // A newer build's entry (an unknown carrier and choice) next to it.
        let entry = serde_json::json!({
            "peer_pub_hex": hex::encode(bob),
            "choice": "carrier_of_tomorrow",
            "routes": [{"carrier": "carrier_of_tomorrow", "dial": "somewhere"}],
            "expires_at_ms": now + 2 * HOUR,
            "custody": true,
            "future_field": [1, 2, 3]
        });
        before["objects"][hex::encode(newer)] = entry.clone();
        std::fs::write(&path, serde_json::to_vec_pretty(&before).unwrap()).unwrap();
        // Read: the known record; the unknown one is not planned.
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(got.keys().copied().collect::<Vec<_>>(), vec![known]);
        // An edit of another record keeps it verbatim.
        set_object_unsent(dir.path(), &known, true, now).unwrap();
        record_object_routes(
            dir.path(),
            &older,
            &bob,
            CarrierChoice::Lan,
            &[lan("10.0.0.3:7420")],
            now + HOUR / 2,
            now,
        )
        .unwrap();
        let on_disk = |key: &[u8; 16]| -> Option<serde_json::Value> {
            let file: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            file["objects"].get(hex::encode(key)).cloned()
        };
        assert_eq!(on_disk(&newer), Some(entry.clone()));
        assert!(object_route_records(dir.path(), now).unwrap()[&known].unsent);
        // This build never re-records it (its choice is unknown here).
        record_object_routes(
            dir.path(),
            &newer,
            &bob,
            CarrierChoice::Auto,
            &[lan("10.0.0.4:7420")],
            now + HOUR,
            now,
        )
        .unwrap();
        assert_eq!(on_disk(&newer), Some(entry.clone()));
        assert!(!object_route_records(dir.path(), now)
            .unwrap()
            .contains_key(&newer));
        // Rules every record follows: a refused write is noted in place, the
        // contact's routes are forgotten with it, and the evidence counts it.
        set_object_written(dir.path(), &newer, &bob, now + 2 * HOUR, now).unwrap();
        clear_peer_routes(dir.path(), &bob).unwrap();
        let kept = on_disk(&newer).unwrap();
        assert_eq!(kept["written"], serde_json::Value::Bool(true));
        assert_eq!(kept["routes"], serde_json::json!([]));
        assert_eq!(kept["choice"], entry["choice"]);
        assert_eq!(kept["future_field"], entry["future_field"]);
        let evidence = object_route_evidence(dir.path(), now).unwrap();
        assert!(evidence[&newer].written);
        // Expired: what it kept goes to `ended`, as for a known record (while
        // the horizon is live its grace equals the evidence's keep window,
        // so nothing is left to keep then).
        let later = now + 2 * HOUR + grace;
        set_object_unsent(dir.path(), &known, false, later).unwrap();
        assert_eq!(on_disk(&newer), None);
        let evidence = object_route_evidence(dir.path(), later).unwrap();
        if grace < ROUTE_EVIDENCE_KEEP_MS {
            assert!(evidence[&newer].written);
        } else {
            assert!(!evidence.contains_key(&newer));
        }
        // Cleared with its object; an entry with no deadline is no record.
        before["objects"] = serde_json::json!({
            hex::encode(newer): entry.clone(),
            hex::encode(older): {"routes": "not a record"},
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&before).unwrap()).unwrap();
        clear_object_routes(dir.path(), &[newer]).unwrap();
        assert_eq!(on_disk(&newer), None);
        assert_eq!(on_disk(&older), None, "no deadline: dropped");
        // Counted against the cap: the one that expires first goes first.
        let mut file: serde_json::Value = serde_json::json!({"objects": {}});
        for i in 0..MAX_ROUTE_OBJECTS as u64 {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&i.to_be_bytes());
            file["objects"][hex::encode(id)] = serde_json::json!({
                "choice": "carrier_of_tomorrow",
                "expires_at_ms": now + HOUR + i,
            });
        }
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        record_object_routes(
            dir.path(),
            &known,
            &bob,
            CarrierChoice::Lan,
            &[],
            now + 2 * HOUR,
            now,
        )
        .unwrap();
        let after: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let objects = after["objects"].as_object().unwrap();
        assert_eq!(objects.len(), MAX_ROUTE_OBJECTS);
        assert!(objects.contains_key(&hex::encode(known)));
        assert!(
            !objects.contains_key(&hex::encode([0u8; 16])),
            "soonest first"
        );
        // PP.7: one the outbox no longer holds is forgotten like the others.
        let removed =
            forget_finished_object_routes(dir.path(), now, || Ok(Default::default())).unwrap();
        assert_eq!(removed, MAX_ROUTE_OBJECTS);
    }

    /// The Tor onion carrier (lab, design 2026-10-tor-fallback §3.4): its
    /// route comes only from a binding the contact's own key signed, for a
    /// verified contact, while the helper is ready; it is planned last
    /// (after nearby), above the route cap, kept under "hide my IP", never
    /// from a record, and an older binding never wins over a newer one.
    #[test]
    fn onion_is_planned_last_from_a_signed_binding_only() {
        use crate::onion::{dial_for, OnionBinding};
        let bob_id = crate::Identity::from_seed(&[0x4b; 32]);
        let bob = bob_id.public_key_bytes();
        let mallory = crate::Identity::from_seed(&[0x4d; 32]);
        let now = 1_790_000_000;
        let hs = |seed: u8| crate::Identity::from_seed(&[seed; 32]).public_key_bytes();
        let onion = |hs_id: &[u8; 32]| OutboxRoute {
            carrier: OutboxCarrier::Onion,
            dial: dial_for(hs_id),
        };
        assert!(!carrier_allowed_for_contact(OutboxCarrier::Onion, false));
        assert!(carrier_allowed_for_contact(OutboxCarrier::Onion, true));
        assert!(OutboxCarrier::Onion.confidential_to_endpoint());
        assert_eq!(OutboxCarrier::Onion.label(), "onion_dial");
        assert_eq!(
            serde_json::to_string(&OutboxCarrier::Onion).unwrap(),
            r#""onion""#
        );
        assert!(OutboxCarrier::Nearby < OutboxCarrier::Onion);
        let all = CarrierGates {
            lan: true,
            internet: true,
            p2p: true,
            nearby: true,
            onion: true,
        };
        let signed = OnionBinding::sign(&bob_id, hs(1), now);
        let routes = [lan("10.0.0.9:7420"), inet("203.0.113.7:7422")];
        let with = |c: ContactRoutes, learned, available| {
            with_onion_route(c, &bob, learned, available, now)
        };
        // From the book's binding (a card), last, after nearby too.
        let mut book = contact(&routes, true);
        book.onion = Some(signed);
        let planned = with(with_nearby_route(book.clone(), &bob, true), None, true);
        let auto = record(CarrierChoice::Auto, &[lan("10.0.0.2:7420")]);
        assert_eq!(
            plan_object_routes(Some(&auto), &planned, all).routes,
            vec![
                lan("10.0.0.9:7420"),
                inet("203.0.113.7:7422"),
                lan("10.0.0.2:7420"),
                nearby(&bob),
                onion(&hs(1)),
            ]
        );
        // `--carrier onion` (lab): Tor only, the record's and the
        // contact's other routes left out; an older build's word for it.
        let forced = record(CarrierChoice::Onion, &[lan("10.0.0.2:7420")]);
        assert_eq!(
            plan_object_routes(Some(&forced), &planned, all).routes,
            vec![onion(&hs(1))]
        );
        assert!(CarrierChoice::Onion.allows(OutboxCarrier::Onion));
        assert!(!CarrierChoice::Onion.allows(OutboxCarrier::Lan));
        assert_eq!(
            serde_json::to_string(&CarrierChoice::Onion).unwrap(),
            r#""onion""#
        );
        // From route hints alone, the same.
        let learned = with(contact(&routes, true), Some(signed), true);
        assert_eq!(learned.routes.last(), Some(&onion(&hs(1))));
        // Never unsigned, never signed by someone else, never tampered.
        let foreign = OnionBinding::sign(&mallory, hs(2), now);
        let mut swapped = signed;
        swapped.hs_id = hs(3);
        for bad in [
            OnionBinding {
                sig: [0; 64],
                ..signed
            },
            foreign,
            swapped,
        ] {
            let mut c = contact(&routes, true);
            c.onion = Some(bad);
            assert_eq!(with(c.clone(), None, true).routes, routes.to_vec());
            assert_eq!(
                with(contact(&routes, true), Some(bad), true).routes,
                routes.to_vec()
            );
        }
        // The newest binding wins, from either side; an older one never.
        let newer = OnionBinding::sign(&bob_id, hs(4), now + 60);
        assert_eq!(
            with(book.clone(), Some(newer), true).routes.last(),
            Some(&onion(&hs(4)))
        );
        let mut book_new = contact(&routes, true);
        book_new.onion = Some(newer);
        assert_eq!(
            with(book_new, Some(signed), true).routes.last(),
            Some(&onion(&hs(4)))
        );
        // Helper not ready, or an unverified contact: as it was.
        assert_eq!(with(book.clone(), None, false), book);
        let mut unpinned = contact(&routes, false);
        unpinned.onion = Some(signed);
        assert_eq!(with(unpinned.clone(), None, true), unpinned);
        // Once, however often it is asked for.
        let twice = with(planned.clone(), None, true);
        assert_eq!(
            twice
                .routes
                .iter()
                .filter(|r| r.carrier == OutboxCarrier::Onion)
                .count(),
            1
        );
        // Hide my IP drops Internet direct but keeps Tor (it shows no IP).
        let mut hidden = planned.clone();
        hidden.hide_ip = true;
        let p = plan_object_routes(Some(&auto), &hidden, all);
        assert!(p
            .routes
            .iter()
            .all(|r| r.carrier != OutboxCarrier::Internet));
        assert_eq!(p.routes.last(), Some(&onion(&hs(1))));
        // The gate closed: no onion route and nothing withheld for trust.
        let closed = CarrierGates {
            onion: false,
            ..all
        };
        let p = plan_object_routes(Some(&auto), &planned, closed);
        assert!(p.routes.iter().all(|r| r.carrier != OutboxCarrier::Onion));
        // A record's onion route (none is ever written) is not planned.
        let stray = record(CarrierChoice::Auto, &[onion(&hs(5))]);
        let p = plan_object_routes(Some(&stray), &contact(&routes, true), all);
        assert!(p.routes.iter().all(|r| r.carrier != OutboxCarrier::Onion));
        // A full plan: six routes of the other carriers, then nearby and
        // onion on top of the cap.
        let many: Vec<OutboxRoute> = (1..=8).map(|i| lan(&format!("10.0.0.{i}:7420"))).collect();
        let mut full = contact(&many, true);
        full.onion = Some(signed);
        let full = with(with_nearby_route(full, &bob, true), None, true);
        let p = plan_object_routes(Some(&auto), &full, all);
        assert_eq!(p.routes.len(), MAX_ROUTES_PER_OBJECT + 2);
        assert_eq!(p.routes[MAX_ROUTES_PER_OBJECT], nearby(&bob));
        assert_eq!(p.routes[MAX_ROUTES_PER_OBJECT + 1], onion(&hs(1)));
        // A forced carrier never widens to Tor.
        for choice in [
            CarrierChoice::Lan,
            CarrierChoice::Internet,
            CarrierChoice::P2p,
        ] {
            let p = plan_object_routes(Some(&record(choice, &[])), &planned, all);
            assert!(p.routes.iter().all(|r| r.carrier != OutboxCarrier::Onion));
        }
    }

    /// The onion route is derived live and never stored in the routes file.
    #[test]
    fn onion_route_is_never_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000;
        let bob = [0x4b; 32];
        let hs_id = crate::Identity::from_seed(&[1; 32]).public_key_bytes();
        let route = OutboxRoute {
            carrier: OutboxCarrier::Onion,
            dial: crate::onion::dial_for(&hs_id),
        };
        assert!(plausible_route(&route));
        let id = [0xA1; 16];
        record_object_routes(
            dir.path(),
            &id,
            &bob,
            CarrierChoice::Auto,
            &[lan("10.0.0.2:7420"), route],
            now + 60_000,
            now,
        )
        .unwrap();
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(got[&id].routes, vec![lan("10.0.0.2:7420")]);
        let raw = std::fs::read_to_string(dir.path().join(OUTBOX_ROUTES_FILE)).unwrap();
        assert!(!raw.contains(crate::onion::ONION_DIAL_PREFIX), "{raw}");
    }

    /// The book keeps a card's `onion=` binding; the planner reads it only
    /// when the row's own key signed it.
    #[test]
    fn contact_routes_read_only_a_binding_the_contacts_key_signed() {
        use crate::onion::{now_s, OnionBinding};
        let dir = tempfile::tempdir().unwrap();
        let bob_id = crate::Identity::from_seed(&[0x4b; 32]);
        let bob = bob_id.public_key_bytes();
        let hs_id = crate::Identity::from_seed(&[1; 32]).public_key_bytes();
        let write = |binding: &str| {
            std::fs::write(
                dir.path().join("contacts.json"),
                format!(
                    r#"[{{"petname":"Bob","pub_hex":"{}","pinned":true,"lan_dial":"","onion":"{binding}"}}]"#,
                    hex::encode(bob)
                ),
            )
            .unwrap();
        };
        let good = OnionBinding::sign(&bob_id, hs_id, now_s());
        write(&good.to_text());
        assert_eq!(
            contact_routes(dir.path(), &bob).unwrap().unwrap().onion,
            Some(good)
        );
        let other = OnionBinding::sign(&crate::Identity::from_seed(&[9; 32]), hs_id, now_s());
        write(&other.to_text());
        assert_eq!(
            contact_routes(dir.path(), &bob).unwrap().unwrap().onion,
            None
        );
        write("not-a-binding");
        assert_eq!(
            contact_routes(dir.path(), &bob).unwrap().unwrap().onion,
            None
        );
    }

    /// Phase 5 (P5.25): a nearby dial string is exactly `nearby:` and 64
    /// lowercase hex digits.
    #[test]
    fn nearby_dial_peer_rejects_uppercase_short_and_foreign_prefix() {
        let bob = [0xAB; 32];
        let dial = nearby_dial_for(&bob);
        assert_eq!(dial, format!("nearby:{}", "ab".repeat(32)));
        assert_eq!(nearby_dial_peer(&dial), Some(bob));
        assert!(plausible_route(&nearby(&bob)));
        for bad in [
            format!("nearby:{}", "AB".repeat(32)),
            format!("nearby:{}Ab", "ab".repeat(31)),
            format!("nearby:{}", "ab".repeat(31)),
            format!("nearby:{}", "ab".repeat(33)),
            format!("nearby:{}a", "ab".repeat(32)),
            format!("NEARBY:{}", "ab".repeat(32)),
            format!("nearby: {}", "ab".repeat(32)),
            format!(" nearby:{}", "ab".repeat(32)),
            format!("nearby:{} ", "ab".repeat(32)),
            format!("near:{}", "ab".repeat(32)),
            format!("lan:{}", "ab".repeat(32)),
            "ab".repeat(32),
            format!("nearby:{}", "zz".repeat(32)),
            format!("nearby:0x{}", "ab".repeat(31)),
            "nearby:".to_string(),
            String::new(),
        ] {
            assert_eq!(nearby_dial_peer(&bad), None, "{bad:?}");
            assert!(
                !plausible_route(&OutboxRoute {
                    carrier: OutboxCarrier::Nearby,
                    dial: bad.clone(),
                }),
                "{bad:?}"
            );
        }
        // Another carrier's dial is no nearby route, and the reverse.
        assert!(!plausible_route(&OutboxRoute {
            carrier: OutboxCarrier::Nearby,
            dial: "10.0.0.2:7420".into(),
        }));
        assert!(!plausible_route(&OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: dial.clone(),
        }));
    }

    /// Phase 5 (P5.25): with the nearby gate closed (release builds, and the
    /// lab without `RAVEN_LAB_NEARBY`), every plan is the very plan of
    /// before the carrier existed (same routes in the same order, the same
    /// withheld flag), whatever `with_nearby_route` was told.
    #[test]
    fn release_plan_is_unchanged_when_the_nearby_gate_is_closed() {
        let bob = [0x4b; 32];
        let peer = crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[9; 32]));
        let p2p = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: crate::p2p_route::peer_route(&peer),
        };
        let route_sets: Vec<Vec<OutboxRoute>> = vec![
            vec![],
            vec![lan("10.0.0.9:7420")],
            vec![lan("10.0.0.9:7420"), inet("203.0.113.7:7422"), p2p.clone()],
            (1..=8).map(|i| lan(&format!("10.0.0.{i}:7420"))).collect(),
        ];
        let records: Vec<Option<ObjectRoutes>> = [
            CarrierChoice::Auto,
            CarrierChoice::Lan,
            CarrierChoice::Internet,
            CarrierChoice::P2p,
            CarrierChoice::Nearby,
        ]
        .into_iter()
        .map(|c| Some(record(c, &[lan("10.0.0.2:7420"), inet("[::1]:7422")])))
        .chain([None])
        .collect();
        let mut compared = 0;
        for routes in &route_sets {
            for pinned in [false, true] {
                for available in [false, true] {
                    let before = contact(routes, pinned);
                    let with = with_nearby_route(before.clone(), &bob, available);
                    for bits in 0..8u8 {
                        let gates = CarrierGates {
                            lan: bits & 1 != 0,
                            internet: bits & 2 != 0,
                            p2p: bits & 4 != 0,
                            nearby: false,
                            onion: false,
                        };
                        for rec in &records {
                            let old = plan_object_routes(rec.as_ref(), &before, gates);
                            let new = plan_object_routes(rec.as_ref(), &with, gates);
                            assert_eq!(new, old, "{routes:?} pinned={pinned} {gates:?} {rec:?}");
                            compared += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(compared, 4 * 2 * 2 * 8 * 6);
        // The gates as this process reads them: closed unless the lab
        // switch is set, and then nothing nearby is planned by the gate.
        if !crate::nearby_live_enabled() {
            assert!(!crate::custody_gate::carrier_gates_now().nearby);
        }
    }

    #[test]
    fn contact_book_p2p_fields_become_one_route() {
        let dir = tempfile::tempdir().unwrap();
        let key = [5u8; 32];
        let peer = crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[5; 32]));
        let relay = crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[6; 32]));
        let via = format!("/ip4/198.51.100.1/tcp/7423/p2p/{relay}");
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","pinned":true,"lan_dial":"10.0.0.2:7420","p2p":"{peer}",
                    "p2p_via":["{via}","not a multiaddr"]}}]"#,
                hex::encode(key)
            ),
        )
        .unwrap();
        let c = contact_routes(dir.path(), &key).unwrap().unwrap();
        assert_eq!(
            c.routes,
            vec![
                lan("10.0.0.2:7420"),
                OutboxRoute {
                    carrier: OutboxCarrier::P2p,
                    dial: format!("/p2p/{peer}"),
                }
            ]
        );
        let p2p = c.p2p.unwrap();
        assert_eq!(p2p.peer_id, peer);
        assert_eq!(p2p.via.len(), 1, "junk via dropped");
        // A malformed PeerId gives no p2p route at all.
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","p2p":"12D3KooWnope"}}]"#,
                hex::encode(key)
            ),
        )
        .unwrap();
        let c = contact_routes(dir.path(), &key).unwrap().unwrap();
        assert!(c.routes.is_empty() && c.p2p.is_none());
    }

    #[test]
    fn local_network_addresses_are_exactly_the_private_ranges() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.20",
            "169.254.3.4",
            "::1",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:192.168.1.20",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_local_network_ip(ip(local)), "{local}");
        }
        for remote in [
            "100.64.0.1",
            "100.127.255.255",
            "172.32.0.1",
            "8.8.8.8",
            "203.0.113.7",
            "0.0.0.0",
            "::",
            "2001:db8::1",
            "fec0::1",
            "::ffff:8.8.8.8",
            "::ffff:100.64.0.1",
        ] {
            assert!(!is_local_network_ip(ip(remote)), "{remote}");
        }
    }

    #[test]
    fn an_unverified_contact_is_dialled_only_at_local_resolved_addresses() {
        let t = LOCALIZE_RESOLVE_TIMEOUT;
        // A verified contact is unrestricted (no resolution at all).
        assert_eq!(
            localize_lan_route(&lan("203.0.113.7:7420"), true, t),
            Ok(lan("203.0.113.7:7420"))
        );
        // Literals: local ones as they are, public ones refused.
        for ok in [
            "192.168.1.20:7420",
            "[fe80::1%en0]:7420",
            "[::1]:7420",
            "[fd00::5]:7420",
        ] {
            assert_eq!(localize_lan_route(&lan(ok), false, t), Ok(lan(ok)), "{ok}");
        }
        for bad in ["203.0.113.7:7420", "100.64.0.1:7420", "[2001:db8::1]:7420"] {
            assert_eq!(
                localize_lan_route(&lan(bad), false, t),
                Err(RouteRefusal::NotLocal),
                "{bad}"
            );
        }
        // A name is resolved first and dialled as the resolved literal.
        let got = localize_lan_route(&lan("localhost:7420"), false, t).unwrap();
        let addr: std::net::SocketAddr = got.dial.parse().unwrap();
        assert!(addr.ip().is_loopback() && addr.port() == 7420, "{got:?}");
        // An unresolvable name is not dialled.
        assert!(matches!(
            localize_lan_route(&lan("no-such-host.invalid:7420"), false, t),
            Err(RouteRefusal::Unresolved(_))
        ));
        // Internet routes are not this function's business.
        assert_eq!(
            localize_lan_route(&inet("203.0.113.7:7422"), false, t),
            Ok(inet("203.0.113.7:7422"))
        );
    }

    /// F5's proof: a LAN delivery says the local network works only at a
    /// local-network IP address that is not loopback; a name is not looked
    /// up again.
    #[test]
    fn only_a_local_non_loopback_lan_delivery_proves_the_network() {
        for proves in [
            "192.168.1.20:7420",
            "10.1.2.3:7420",
            "172.20.10.2:7420",
            "169.254.7.9:7420",
            "[fd00::5]:7420",
            "[fe80::1%en0]:7420",
            "[::ffff:192.168.1.20]:7420",
        ] {
            assert!(lan_route_proves_network(&lan(proves)), "{proves}");
        }
        for not in [
            "203.0.113.7:7420",
            "100.64.1.1:7420",
            "[2001:db8::7]:7420",
            "127.0.0.1:7420",
            "[::1]:7420",
            "[::ffff:127.0.0.1]:7420",
            "localhost:7420",
            "bob-mac.local:7420",
            "not host port",
        ] {
            assert!(!lan_route_proves_network(&lan(not)), "{not}");
        }
        assert!(!lan_route_proves_network(&inet("192.168.1.20:7422")));
    }

    /// Cutoff F1: an unverified contact's name that resolves to a local
    /// address and a global IPv6 one (a home network with an IPv6 prefix:
    /// mDNS gives both) is dialled at the local one, so the message F1
    /// queued for it goes out; a name with no local address is still
    /// refused. With the gate closed every address must be local, as
    /// before the pack.
    #[test]
    fn a_name_with_a_local_address_is_dialled_there_under_f1() {
        let t = LOCALIZE_RESOLVE_TIMEOUT;
        let sa = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        let mixed = [sa("[2001:db8::5]:7420"), sa("192.168.1.5:7420")];
        let global = [sa("[2001:db8::5]:7420"), sa("203.0.113.5:7420")];
        let all_local = [sa("[fd00::5]:7420"), sa("192.168.1.5:7420")];
        assert_eq!(pick_local(&mixed, true), Ok(sa("192.168.1.5:7420")));
        assert_eq!(pick_local(&mixed, false), Err(RouteRefusal::NotLocal));
        for any_local in [true, false] {
            assert_eq!(pick_local(&global, any_local), Err(RouteRefusal::NotLocal));
            assert_eq!(pick_local(&[], any_local), Err(RouteRefusal::NotLocal));
            assert_eq!(pick_local(&all_local, any_local), Ok(sa("[fd00::5]:7420")));
        }
        // Through the route as the worker and `raven send` localize it.
        let bob = lan("bob-mac.local:7420");
        let answers = |addrs: &[std::net::SocketAddr]| {
            let addrs = addrs.to_vec();
            move |name: &str, port: u16, _: Duration| {
                assert_eq!((name, port), ("bob-mac.local", 7420));
                Ok(addrs)
            }
        };
        assert_eq!(
            localize_lan_route_with(&bob, false, t, true, answers(&mixed)),
            Ok(lan("192.168.1.5:7420"))
        );
        assert_eq!(
            localize_lan_route_with(&bob, false, t, false, answers(&mixed)),
            Err(RouteRefusal::NotLocal)
        );
        assert_eq!(
            localize_lan_route_with(&bob, false, t, true, answers(&global)),
            Err(RouteRefusal::NotLocal)
        );
        assert_eq!(
            localize_lan_route_with(&bob, false, t, true, answers(&[])),
            Err(RouteRefusal::Unresolved("no address".into()))
        );
        // A verified contact and a literal never ask the resolver.
        let never =
            |_: &str, _: u16, _: Duration| -> Result<Vec<std::net::SocketAddr>, RouteRefusal> {
                panic!("resolved")
            };
        assert_eq!(
            localize_lan_route_with(&bob, true, t, true, never),
            Ok(bob.clone())
        );
        assert_eq!(
            localize_lan_route_with(&lan("203.0.113.5:7420"), false, t, true, never),
            Err(RouteRefusal::NotLocal)
        );
    }

    /// Cutoff F1 (CP.9): only a name that did not resolve now counts as an
    /// unresolved name; a malformed address and one off the local network
    /// stay what they are.
    #[test]
    fn only_a_name_that_did_not_resolve_is_an_unresolved_name() {
        let t = LOCALIZE_RESOLVE_TIMEOUT;
        let away = localize_lan_route(&lan("no-such-host.invalid:7420"), false, t).unwrap_err();
        assert!(away.is_unresolved_name(), "{away:?}");
        for reason in ["no address", "resolution timed out", "failed to lookup"] {
            assert!(RouteRefusal::Unresolved(reason.into()).is_unresolved_name());
        }
        for malformed in ["no-port-here", "bob-mac.local:http", "[fe80::zz%en0]:7420"] {
            let why = localize_lan_route(&lan(malformed), false, t).unwrap_err();
            assert!(matches!(why, RouteRefusal::Unresolved(_)), "{malformed}");
            assert!(!why.is_unresolved_name(), "{malformed}: {why:?}");
        }
        assert!(!RouteRefusal::NotLocal.is_unresolved_name());
    }

    #[test]
    fn admission_reads_both_files_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (friend, stranger) = ([1u8; 32], [2u8; 32]);
        assert_eq!(
            contact_admission(dir.path(), &friend),
            ContactAdmission::NotContact
        );
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(r#"[{{"pub_hex":"{}","pinned":true}}]"#, hex::encode(friend)),
        )
        .unwrap();
        assert!(matches!(
            contact_admission(dir.path(), &friend),
            ContactAdmission::Allowed(ContactRoutes { pinned: true, .. })
        ));
        assert_eq!(
            contact_admission(dir.path(), &stranger),
            ContactAdmission::NotContact
        );
        let mut blocks = crate::chat_history::BlockList::default();
        blocks.block(&hex::encode(friend));
        blocks.save(dir.path()).unwrap();
        assert_eq!(
            contact_admission(dir.path(), &friend),
            ContactAdmission::Blocked
        );
        std::fs::write(dir.path().join("contacts.json"), b"{not json").unwrap();
        assert_eq!(
            contact_admission(dir.path(), &friend),
            ContactAdmission::Unreadable
        );
    }

    /// The peer gate's contacts follow contact_admission: verified,
    /// unblocked, with a usable `p2p=` PeerId, its relays listed; and a
    /// broken contact book or block list admits nobody.
    #[test]
    fn p2p_gate_peers_follows_contact_admission() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(p2p_gate_peers(dir.path()), Ok(Vec::new()), "no book");
        let peer = |n: u8| crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[n; 32]));
        let via = |n: u8, ip: &str| format!("/ip4/{ip}/tcp/7423/p2p/{}", peer(n));
        let row = |key: &str, pinned: bool, p2p: String, via: Vec<String>| serde_json::json!({ "pub_hex": key, "pinned": pinned, "p2p": p2p, "p2p_via": via });
        let book = serde_json::json!([
            // Verified: its relay (2) is listed, the via naming itself is not.
            row(
                &"AA".repeat(32),
                true,
                peer(1),
                vec![via(2, "203.0.113.9"), via(1, "198.51.100.1")]
            ),
            // Not verified.
            row(
                &"bb".repeat(32),
                false,
                peer(3),
                vec![via(4, "203.0.113.9")]
            ),
            // Verified, but no PeerId, or a junk one.
            row(&"cc".repeat(32), true, String::new(), Vec::new()),
            row(&"dd".repeat(32), true, "junk".into(), Vec::new()),
            // One key, one row verified and one not: not verified.
            row(&"ee".repeat(32), true, peer(5), Vec::new()),
            row(&"EE".repeat(32), false, String::new(), Vec::new()),
            // Verified, then blocked (below).
            row(&"ff".repeat(32), true, peer(6), Vec::new()),
        ]);
        std::fs::write(dir.path().join("contacts.json"), book.to_string()).unwrap();
        let mut blocks = crate::chat_history::BlockList::default();
        blocks.block(&"FF".repeat(32));
        blocks.save(dir.path()).unwrap();
        assert_eq!(
            p2p_gate_peers(dir.path()),
            Ok(vec![P2pGatePeer {
                peer_id: peer(1),
                relays: vec![peer(2)],
                hidden: false,
                learned: false,
                proven: true,
                rotated: Vec::new(),
            }])
        );
        // The same answers as the one-peer admission check.
        assert_eq!(
            contact_admission(dir.path(), &[0xff; 32]),
            ContactAdmission::Blocked
        );
        assert!(matches!(
            contact_admission(dir.path(), &[0xbb; 32]),
            ContactAdmission::Allowed(ContactRoutes { pinned: false, .. })
        ));
        // A broken block list or contact book: an error (nobody admitted).
        std::fs::write(crate::chat_history::blocked_path(dir.path()), b"{broken").unwrap();
        assert!(p2p_gate_peers(dir.path()).is_err());
        std::fs::remove_file(crate::chat_history::blocked_path(dir.path())).unwrap();
        assert_eq!(p2p_gate_peers(dir.path()).unwrap().len(), 2, "6 unblocked");
        std::fs::write(dir.path().join("contacts.json"), b"[{").unwrap();
        assert!(p2p_gate_peers(dir.path()).is_err());
    }

    /// Phase 3 P3.19: the pinned, unblocked contacts in book order, each
    /// once, by contact_admission's rules; an unreadable book or block list
    /// is an error, never an empty or partial list.
    #[test]
    fn pinned_unblocked_contacts_fails_closed_on_unreadable_book_or_blocklist() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert_eq!(pinned_unblocked_contacts(d), Ok(Vec::new()), "no book");
        let row = |key: &str, pinned: bool| serde_json::json!({ "pub_hex": key, "pinned": pinned });
        let book = serde_json::json!([
            row(&"cc".repeat(32), true),
            row(&"aa".repeat(32), true),
            // Not verified.
            row(&"bb".repeat(32), false),
            // One key, one row verified and one not: not verified.
            row(&"ee".repeat(32), true),
            row(&"EE".repeat(32), false),
            // Verified, then blocked (below).
            row(&"ff".repeat(32), true),
            // Junk key, and a second verified row of the first key.
            row("zz", true),
            row(&"CC".repeat(32), true),
        ]);
        std::fs::write(d.join("contacts.json"), book.to_string()).unwrap();
        let mut blocks = crate::chat_history::BlockList::default();
        blocks.block(&"FF".repeat(32));
        blocks.save(d).unwrap();
        assert_eq!(
            pinned_unblocked_contacts(d),
            Ok(vec![[0xcc; 32], [0xaa; 32]])
        );
        // The same answers as the one-contact check.
        for key in [[0xcc; 32], [0xaa; 32], [0xbb; 32], [0xee; 32], [0xff; 32]] {
            let admitted = matches!(
                contact_admission(d, &key),
                ContactAdmission::Allowed(ContactRoutes { pinned: true, .. })
            );
            assert_eq!(
                admitted,
                key == [0xcc; 32] || key == [0xaa; 32],
                "{}",
                hex::encode(key)
            );
        }
        // A broken block list or contact book: an error.
        std::fs::write(crate::chat_history::blocked_path(d), b"{broken").unwrap();
        assert!(pinned_unblocked_contacts(d).is_err());
        std::fs::remove_file(crate::chat_history::blocked_path(d)).unwrap();
        assert_eq!(
            pinned_unblocked_contacts(d).unwrap().len(),
            3,
            "ff unblocked"
        );
        std::fs::write(d.join("contacts.json"), b"[{").unwrap();
        assert!(pinned_unblocked_contacts(d).is_err());
    }

    /// Q: a stranger costs the listener the same reads as a contact (the block
    /// list is read for it too: a broken one is noticed), and every refusal,
    /// stranger, unverified or blocked, comes out of that one admission call.
    #[test]
    fn a_stranger_costs_the_same_reads_as_a_contact() {
        let dir = tempfile::tempdir().unwrap();
        let (unverified, stranger) = ([3u8; 32], [4u8; 32]);
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","pinned":false}}]"#,
                hex::encode(unverified)
            ),
        )
        .unwrap();
        std::fs::write(crate::chat_history::blocked_path(dir.path()), b"{broken").unwrap();
        assert_eq!(
            contact_admission(dir.path(), &stranger),
            ContactAdmission::Unreadable
        );
        assert_eq!(
            contact_admission(dir.path(), &unverified),
            ContactAdmission::Blocked
        );
        std::fs::remove_file(crate::chat_history::blocked_path(dir.path())).unwrap();
        assert_eq!(
            contact_admission(dir.path(), &stranger),
            ContactAdmission::NotContact
        );
        assert!(matches!(
            contact_admission(dir.path(), &unverified),
            ContactAdmission::Allowed(ContactRoutes { pinned: false, .. })
        ));
    }

    /// Review C-time-deadlines-1: `written` survives re-recording, a bare
    /// record (what no record plans) carries it when there was none, and an
    /// expired record with such evidence is kept, without its routes, for
    /// ROUTE_EVIDENCE_KEEP_MS: readable as evidence, never planned from.
    #[test]
    fn written_evidence_outlives_the_envelope_without_its_routes() {
        let _horizon = HorizonHeld::on();
        let dir = tempfile::tempdir().unwrap();
        let bob = [7u8; 32];
        let now = crate::clock::now_ms();
        let end = now + 10_000;
        let mid = |i: u8| [i; 16];
        set_object_written(dir.path(), &mid(1), &bob, end, now).unwrap();
        let got = object_route_records(dir.path(), now).unwrap();
        let bare = &got[&mid(1)];
        assert!(bare.written && !bare.unsent && !bare.custody, "{bare:?}");
        assert_eq!(bare.choice, CarrierChoice::Lan, "what no record plans");
        assert!(bare.routes.is_empty());
        // A send's own record keeps its choice and routes; re-recording keeps
        // the mark.
        let route = lan("10.0.0.2:7420");
        let rec = |i: u8, at: u64| {
            record_object_routes(
                dir.path(),
                &mid(i),
                &bob,
                CarrierChoice::Auto,
                std::slice::from_ref(&route),
                end,
                at,
            )
            .unwrap()
        };
        rec(2, now);
        set_object_written(dir.path(), &mid(2), &bob, end, now).unwrap();
        rec(2, now);
        rec(3, now);
        let got = object_route_records(dir.path(), now).unwrap();
        assert!(got[&mid(2)].written && got[&mid(2)].choice == CarrierChoice::Auto);
        assert_eq!(got[&mid(2)].routes, vec![route.clone()]);
        assert!(!got[&mid(3)].written);
        // Expired: nothing to plan from, the evidence is kept.
        assert!(object_route_records(dir.path(), end).unwrap().is_empty());
        let kept = object_route_evidence(dir.path(), end).unwrap();
        assert!(kept[&mid(1)].written && kept[&mid(2)].written);
        assert!(!kept.contains_key(&mid(3)), "nothing to keep it for");
        // A write after the deadline keeps it too, and drops the address.
        record_object_routes(
            dir.path(),
            &mid(4),
            &bob,
            CarrierChoice::Lan,
            &[],
            end + 10_000,
            end,
        )
        .unwrap();
        let raw = std::fs::read_to_string(dir.path().join(OUTBOX_ROUTES_FILE)).unwrap();
        assert!(!raw.contains("10.0.0.2"), "{raw}");
        assert!(object_route_evidence(dir.path(), end).unwrap()[&mid(2)].written);
        // Gone after the keep window; never set on what already expired.
        let gone = end + ROUTE_EVIDENCE_KEEP_MS;
        assert!(!object_route_evidence(dir.path(), gone)
            .unwrap()
            .contains_key(&mid(2)));
        set_object_written(dir.path(), &mid(5), &bob, end, end).unwrap();
        assert!(!object_route_evidence(dir.path(), end)
            .unwrap()
            .contains_key(&mid(5)));
    }

    /// P5.6 (the long message horizon): a parked message's route record
    /// (its carrier choice, routes and custody consent) is planned past its
    /// envelope's 24 h until the deadline, even when other writes came
    /// between the envelope's end and the park; never shortened, and gone
    /// after the deadline. With the gate off a record ages with its envelope
    /// as before.
    #[test]
    fn route_record_survives_past_24h_with_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let bob = [7u8; 32];
        let now = crate::clock::now_ms();
        let end = now + ENVELOPE_VALIDITY_MS;
        let deadline = crate::horizon::message_deadline(now);
        let route = lan("10.0.0.2:7420");
        let rec = |i: u8| {
            record_object_routes(
                dir.path(),
                &[i; 16],
                &bob,
                CarrierChoice::Auto,
                std::slice::from_ref(&route),
                end,
                now,
            )
            .unwrap();
            set_object_custody(dir.path(), &[i; 16], now).unwrap();
        };
        crate::horizon::set_lab_horizon_for_this_thread(Some(true));
        rec(1);
        rec(2);
        // Another object's write after both envelopes ran out.
        let after = end + 60_000;
        record_object_routes(
            dir.path(),
            &[3; 16],
            &bob,
            CarrierChoice::Lan,
            &[],
            after + 1,
            after,
        )
        .unwrap();
        assert!(object_route_records(dir.path(), after).unwrap()[&[3; 16]]
            .routes
            .is_empty());
        for i in [1u8, 2] {
            assert!(extend_object_route_expiry(dir.path(), &[i; 16], deadline, after).unwrap());
        }
        // Never shortened.
        assert!(extend_object_route_expiry(dir.path(), &[1; 16], end, now).unwrap());
        let later = now + 25 * 60 * 60 * 1_000;
        let got = object_route_records(dir.path(), later).unwrap();
        for i in [1u8, 2] {
            let r = &got[&[i; 16]];
            assert_eq!(r.expires_at_ms, deadline);
            assert_eq!((r.choice, r.custody), (CarrierChoice::Auto, true));
            assert_eq!(r.routes, vec![route.clone()]);
        }
        assert!(!object_route_records(dir.path(), deadline)
            .unwrap()
            .contains_key(&[1; 16]));
        // Nothing to extend for an object without a record.
        assert!(!extend_object_route_expiry(dir.path(), &[9; 16], deadline, later).unwrap());
        // Gate off: the next write ages a record with its envelope.
        let dir = tempfile::tempdir().unwrap();
        crate::horizon::set_lab_horizon_for_this_thread(Some(false));
        record_object_routes(
            dir.path(),
            &[1; 16],
            &bob,
            CarrierChoice::Auto,
            std::slice::from_ref(&route),
            end,
            now,
        )
        .unwrap();
        record_object_routes(
            dir.path(),
            &[3; 16],
            &bob,
            CarrierChoice::Lan,
            &[],
            after + 1,
            after,
        )
        .unwrap();
        crate::horizon::set_lab_horizon_for_this_thread(Some(true));
        assert!(!extend_object_route_expiry(dir.path(), &[1; 16], deadline, after).unwrap());
        crate::horizon::set_lab_horizon_for_this_thread(None);
    }

    /// Review FU-3: the records `an_expired_record_keeps_only_whether_it_left`
    /// works on: one written and refused, one left with a friend, one handed
    /// to the queue unsent, each with an address, all ending at `end`.
    fn evidence_records(dir: &Path, now: u64, end: u64, peers: [&[u8; 32]; 3], friend: &[u8; 32]) {
        for (i, peer) in (1u8..).zip(peers) {
            record_object_routes(
                dir,
                &[i; 16],
                peer,
                CarrierChoice::Lan,
                &[lan("10.0.0.2:7420")],
                end,
                now,
            )
            .unwrap();
        }
        set_object_written(dir, &[1; 16], peers[0], end, now).unwrap();
        set_object_custody(dir, &[2; 16], now).unwrap();
        add_object_custodians(dir, &[2; 16], &[*friend], now).unwrap();
        set_object_unsent(dir, &[3; 16], true, now).unwrap();
    }

    /// Review FU-3: once its envelope expired, a record names no one: not the
    /// contact's key, the friend's key, the carrier choice, custody or an
    /// address; and an edit after the deadline cannot bring any of it back.
    #[test]
    fn an_expired_record_names_no_one() {
        let _horizon = HorizonHeld::on();
        let dir = tempfile::tempdir().unwrap();
        let (bob, carol, dave) = ([0xB7u8; 32], [0xC8u8; 32], [0xD9u8; 32]);
        let now = crate::clock::now_ms();
        let end = now + 10_000;
        let raw = || std::fs::read_to_string(dir.path().join(OUTBOX_ROUTES_FILE)).unwrap();
        evidence_records(dir.path(), now, end, [&bob, &dave, &bob], &carol);
        assert!(
            raw().contains(&hex::encode(carol)),
            "live: the friend is kept"
        );
        // Any edit after the deadline ages the file.
        set_object_unsent(dir.path(), &[9; 16], true, end).unwrap();
        // And edits of the expired objects themselves.
        add_object_custodians(dir.path(), &[2; 16], &[carol], end).unwrap();
        set_object_custody(dir.path(), &[2; 16], end).unwrap();
        let file = raw();
        for gone in [hex::encode(bob), hex::encode(carol), hex::encode(dave)] {
            assert!(!file.contains(&gone), "{file}");
        }
        for word in ["choice", "custody", "routes", "10.0.0.2"] {
            assert!(!file.contains(word), "{word}: {file}");
        }
        assert!(object_route_records(dir.path(), end).unwrap().is_empty());
    }

    /// Review FU-3: what an expired record keeps still says whether it left
    /// this computer, until a settle clears it or the keep window ends; a
    /// new record of the same id replaces it.
    #[test]
    fn an_expired_record_keeps_only_whether_it_left() {
        let _horizon = HorizonHeld::on();
        let dir = tempfile::tempdir().unwrap();
        let (bob, carol, dave) = ([0xB7u8; 32], [0xC8u8; 32], [0xD9u8; 32]);
        let now = crate::clock::now_ms();
        let end = now + 10_000;
        let mid = |i: u8| [i; 16];
        evidence_records(dir.path(), now, end, [&bob, &dave, &bob], &carol);
        set_object_unsent(dir.path(), &mid(9), true, end).unwrap();
        let kept = object_route_evidence(dir.path(), end).unwrap();
        let only = |unsent, written, with_friend| RouteEvidence {
            expires_at_ms: end,
            unsent,
            written,
            with_friend,
        };
        assert_eq!(kept[&mid(1)], only(false, true, false));
        assert_eq!(kept[&mid(2)], only(false, false, true));
        assert_eq!(kept[&mid(3)], only(true, false, false));
        // A new record of the same id wins over what the old one kept.
        record_object_routes(
            dir.path(),
            &mid(3),
            &bob,
            CarrierChoice::Auto,
            &[],
            end + 20_000,
            end,
        )
        .unwrap();
        assert!(!object_route_evidence(dir.path(), end).unwrap()[&mid(3)].unsent);
        assert!(
            !object_route_evidence(dir.path(), end + 20_000)
                .unwrap()
                .contains_key(&mid(3)),
            "what the old one kept went with it"
        );
        // The prune's settle (or a delivery, a cancel) clears it.
        clear_object_routes(dir.path(), &[mid(1)]).unwrap();
        let kept = object_route_evidence(dir.path(), end).unwrap();
        assert!(!kept.contains_key(&mid(1)) && kept.contains_key(&mid(2)));
        // Gone after the keep window.
        assert!(
            !object_route_evidence(dir.path(), end + ROUTE_EVIDENCE_KEEP_MS)
                .unwrap()
                .contains_key(&mid(2))
        );
    }

    #[test]
    fn object_records_expire_clear_and_stay_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let (bob, carol) = ([7u8; 32], [8u8; 32]);
        // The clearing helpers prune by the wall clock.
        let now = crate::clock::now_ms();
        let mid = |i: u8| [i; 16];
        assert!(object_route_records(dir.path(), now).unwrap().is_empty());
        record_object_routes(
            dir.path(),
            &mid(1),
            &bob,
            CarrierChoice::Lan,
            &[lan("10.0.0.2:7420"), inet("[::1]:7422"), lan("bad")],
            now + 10_000,
            now,
        )
        .unwrap();
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(
            got[&mid(1)].routes,
            vec![lan("10.0.0.2:7420")],
            "only what the choice allows"
        );
        assert_eq!(got[&mid(1)].choice, CarrierChoice::Lan);
        // It expires with the envelope.
        assert!(object_route_records(dir.path(), now + 10_000)
            .unwrap()
            .is_empty());
        // Cleared on delivery, and per peer (contact removed / addresses changed).
        record_object_routes(
            dir.path(),
            &mid(2),
            &bob,
            CarrierChoice::Auto,
            &[],
            now + 10_000,
            now,
        )
        .unwrap();
        record_object_routes(
            dir.path(),
            &mid(3),
            &carol,
            CarrierChoice::Auto,
            &[],
            now + 10_000,
            now,
        )
        .unwrap();
        clear_object_routes(dir.path(), &[mid(2)]).unwrap();
        let got = object_route_records(dir.path(), now).unwrap();
        assert!(!got.contains_key(&mid(2)) && got.contains_key(&mid(1)));
        // Every record of the contact stays (unsent, carrier choice) when its
        // addresses change; only its stale routes go (G4: an auto record
        // does not fall back to the no-record LAN-only plan).
        record_object_routes(
            dir.path(),
            &mid(5),
            &bob,
            CarrierChoice::Lan,
            &[lan("10.0.0.2:7420")],
            now + 10_000,
            now,
        )
        .unwrap();
        set_object_unsent(dir.path(), &mid(5), true, now).unwrap();
        record_object_routes(
            dir.path(),
            &mid(6),
            &bob,
            CarrierChoice::Auto,
            &[lan("10.0.0.2:7420"), inet("203.0.113.7:7422")],
            now + 10_000,
            now,
        )
        .unwrap();
        record_object_routes(
            dir.path(),
            &mid(7),
            &carol,
            CarrierChoice::Auto,
            &[lan("10.0.0.8:7420")],
            now + 10_000,
            now,
        )
        .unwrap();
        clear_peer_routes(dir.path(), &bob).unwrap();
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(
            got.keys().copied().collect::<Vec<_>>(),
            vec![mid(1), mid(3), mid(5), mid(6), mid(7)]
        );
        assert!(got[&mid(1)].routes.is_empty());
        assert_eq!(got[&mid(1)].choice, CarrierChoice::Lan);
        assert!(got[&mid(5)].unsent && got[&mid(5)].routes.is_empty());
        assert_eq!(got[&mid(5)].choice, CarrierChoice::Lan);
        assert!(got[&mid(6)].routes.is_empty() && !got[&mid(6)].unsent);
        assert_eq!(got[&mid(6)].choice, CarrierChoice::Auto);
        assert_eq!(
            got[&mid(7)].routes,
            vec![lan("10.0.0.8:7420")],
            "another contact's record keeps its routes"
        );
        clear_object_routes(dir.path(), &[mid(6), mid(7)]).unwrap();
        // Re-recording routes keeps the marker; only a real write clears it.
        record_object_routes(
            dir.path(),
            &mid(5),
            &bob,
            CarrierChoice::Lan,
            &[lan("10.0.0.3:7420")],
            now + 10_000,
            now,
        )
        .unwrap();
        assert!(object_route_records(dir.path(), now).unwrap()[&mid(5)].unsent);
        set_object_unsent(dir.path(), &mid(5), false, now).unwrap();
        assert!(!object_route_records(dir.path(), now).unwrap()[&mid(5)].unsent);
        clear_object_routes(dir.path(), &[mid(5)]).unwrap();
        // A corrupt hint file is replaced, never wedging a send.
        std::fs::write(dir.path().join(OUTBOX_ROUTES_FILE), b"{not json").unwrap();
        assert!(object_route_records(dir.path(), now).is_err());
        record_object_routes(
            dir.path(),
            &mid(4),
            &bob,
            CarrierChoice::Lan,
            &[],
            u64::MAX,
            now,
        )
        .unwrap();
        assert!(object_route_records(dir.path(), now)
            .unwrap()
            .contains_key(&mid(4)));
        // Bounded: the soonest-expiring records go first.
        for i in 0..(MAX_ROUTE_OBJECTS as u64 + 5) {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&i.to_be_bytes());
            record_object_routes(
                dir.path(),
                &id,
                &carol,
                CarrierChoice::Lan,
                &[],
                now + 100 + i,
                now,
            )
            .unwrap();
        }
        let got = object_route_records(dir.path(), now).unwrap();
        assert_eq!(got.len(), MAX_ROUTE_OBJECTS);
        assert!(got.contains_key(&mid(4)), "the longest-lived record stays");
    }

    #[test]
    fn contact_pin_is_read_from_the_book_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (pinned, plain, absent) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert!(!contact_is_pinned(dir.path(), &pinned).unwrap());
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","pinned":true}},{{"pub_hex":"{}"}}]"#,
                hex::encode(pinned),
                hex::encode(plain)
            ),
        )
        .unwrap();
        assert!(contact_is_pinned(dir.path(), &pinned).unwrap());
        assert!(!contact_is_pinned(dir.path(), &plain).unwrap());
        assert!(!contact_is_pinned(dir.path(), &absent).unwrap());
        assert_eq!(contact_routes(dir.path(), &absent).unwrap(), None);
        std::fs::write(dir.path().join("contacts.json"), b"{not json").unwrap();
        assert!(contact_is_pinned(dir.path(), &pinned).is_err());
    }

    #[test]
    fn contact_routes_come_from_the_matching_contact_only() {
        let dir = tempfile::tempdir().unwrap();
        let peer = [9u8; 32];
        assert_eq!(contact_routes(dir.path(), &peer).unwrap(), None);
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","internet_dial":"203.0.113.7:7422","lan_dial":"10.0.0.2:7420"}},
                    {{"pub_hex":"{}","lan_dial":"10.0.0.8:7420"}}]"#,
                hex::encode(peer).to_uppercase(),
                hex::encode([1u8; 32])
            ),
        )
        .unwrap();
        assert_eq!(
            contact_routes(dir.path(), &peer).unwrap(),
            Some(ContactRoutes {
                routes: vec![lan("10.0.0.2:7420"), inet("203.0.113.7:7422")],
                pinned: false,
                p2p: None,
                hide_ip: false,
                p2p_learned: None,
                lan_verified_only: false,
                onion: None,
                // Not marked as typed or learned: a card's (or older).
                card_lan: vec!["10.0.0.2:7420".into()],
            })
        );
        std::fs::write(dir.path().join("contacts.json"), b"{not json").unwrap();
        assert!(contact_routes(dir.path(), &peer).is_err());
    }

    /// Phase 0b (lab): `keep` is asked about a learned local-network address
    /// only, and one it refuses is left out; the saved route never is, and
    /// learned loopback and public addresses are kept without asking.
    #[test]
    fn with_learned_lan_routes_where_keeps_saved_routes_and_loopback() {
        let dir = tempfile::tempdir().unwrap();
        let bob = [9u8; 32];
        // A saved address on some other network than ours.
        let saved = contact(&[lan("10.0.0.5:7420")], true);
        let asked = std::cell::RefCell::new(Vec::new());
        let refuse = |ip| {
            asked.borrow_mut().push(ip);
            false
        };
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let seen = |at: &str| {
            crate::lan_seen::record_contact_seen(
                dir.path(),
                &bob,
                ip(at),
                None,
                crate::clock::now_ms(),
            )
            .unwrap();
        };
        // The routes when `keep` refuses every address it is asked about.
        let refused =
            || with_learned_lan_routes_where(dir.path(), &bob, saved.clone(), refuse).routes;
        assert_eq!(refused(), saved.routes, "nothing learned");
        assert!(asked.borrow().is_empty());

        seen("192.168.1.20");
        assert_eq!(
            refused(),
            [lan("10.0.0.5:7420")],
            "the learned address is left out, the saved one never"
        );
        assert_eq!(*asked.borrow(), [ip("192.168.1.20")]);
        let all = with_learned_lan_routes_where(dir.path(), &bob, saved.clone(), |_| true);
        assert_eq!(all.routes, [lan("10.0.0.5:7420"), lan("192.168.1.20:7420")]);
        assert_eq!(
            with_learned_lan_routes(dir.path(), &bob, saved.clone()),
            all,
            "the plain form keeps everything"
        );

        // An IPv4-mapped sighting is asked about as IPv4.
        seen("::ffff:192.168.1.30");
        let _ = refused();
        assert_eq!(asked.borrow().last(), Some(&ip("192.168.1.30")));

        // Loopback and (verified contact) public addresses: kept, unasked.
        let before = asked.borrow().len();
        for (at, dial) in [
            ("127.0.0.1", "127.0.0.1:7420"),
            ("203.0.113.7", "203.0.113.7:7420"),
        ] {
            seen(at);
            assert_eq!(refused(), [lan("10.0.0.5:7420"), lan(dial)], "{at}");
        }
        assert_eq!(asked.borrow().len(), before);
    }

    // ── Route hints (RRH1) in the planner ──

    fn pid(seed: u8) -> String {
        crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[seed; 32]))
    }

    fn via(text: &str) -> crate::p2p_route::ViaAddr {
        crate::p2p_route::parse_via(text).unwrap()
    }

    fn p2p_route(peer_id: &str) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: crate::p2p_route::peer_route(peer_id),
        }
    }

    /// A route hints snapshot of generation `generation`.
    fn hints(generation: u64) -> crate::route_hints::ValidHints {
        crate::route_hints::ValidHints {
            generation,
            ttl_s: crate::route_hints::RRH1_DEFAULT_TTL_S,
            ..Default::default()
        }
    }

    /// `sender` told this node `v` over `carrier`, stored as raven-node
    /// stores it: on LAN from `peer_ip`, on p2p over a link whose PeerId is
    /// `link_peer_id` (the same as `v`'s proves it).
    fn told(
        dir: &Path,
        sender: &[u8; 32],
        carrier: OutboxCarrier,
        peer_ip: Option<&str>,
        link_peer_id: Option<&str>,
        v: &crate::route_hints::ValidHints,
    ) {
        told_on(dir, sender, carrier, peer_ip, link_peer_id, v, None);
    }

    /// [`told`], on the network `tag` ([`crate::route_memory::egress_tag`]).
    fn told_on(
        dir: &Path,
        sender: &[u8; 32],
        carrier: OutboxCarrier,
        peer_ip: Option<&str>,
        link_peer_id: Option<&str>,
        v: &crate::route_hints::ValidHints,
        tag: Option<&str>,
    ) {
        let link = crate::route_hints::HintLink {
            carrier,
            peer_ip: peer_ip.map(|ip| ip.parse().unwrap()),
            peer_zone: None,
            link_peer_id,
            book_peer_id: None,
            pinned: true,
            sender: *sender,
            local: [0x52; 32],
            local_p2p: [0x53; 32],
            local_relay: None,
            lab_local: false,
            lab_loopback: false,
        };
        let applied = crate::learned_routes::apply_ungated(
            dir,
            sender,
            v,
            &link,
            tag.map(String::from),
            crate::clock::now_ms(),
        )
        .unwrap();
        assert!(
            matches!(applied, crate::learned_routes::Applied::Changed { .. }),
            "{applied:?}"
        );
    }

    /// [`with_learned_routes`] with route hints live.
    fn learned_on(dir: &Path, peer: &[u8; 32], c: ContactRoutes) -> ContactRoutes {
        learned_routes_into(
            dir,
            peer,
            c,
            |_| true,
            hints_gates(true),
            &|| None,
            crate::clock::now_ms(),
        )
    }

    /// The gates of a plan with route hints as given and F7 closed.
    fn hints_gates(hints: bool) -> LearnedGates {
        LearnedGates {
            hints,
            default_port: false,
            inet: false,
        }
    }

    /// F7 open, route hints off.
    const F7: LearnedGates = LearnedGates {
        hints: false,
        default_port: true,
        inet: false,
    };

    /// [`learned_routes_into`] with the network unknown and the clock now.
    fn planned_with(
        dir: &Path,
        peer: &[u8; 32],
        c: ContactRoutes,
        gates: LearnedGates,
    ) -> ContactRoutes {
        learned_routes_into(
            dir,
            peer,
            c,
            |_| true,
            gates,
            &|| None,
            crate::clock::now_ms(),
        )
    }

    /// F7's fixture: `peer` reached us from `ip` just now, over a link that
    /// pinned its Noise static (M0).
    fn seen_and_pinned(dir: &Path, peer: &[u8; 32], ip: &str) {
        crate::lan_seen::record_contact_seen(
            dir,
            peer,
            ip.parse().unwrap(),
            None,
            crate::clock::now_ms(),
        )
        .unwrap();
        crate::lan_noise_pin::record(dir, &crate::lan_noise_pin::test_key(), peer, &[0x51; 32])
            .unwrap();
    }

    /// F7's guess at `ip` in this run: the lab port when one is exported.
    fn guessed(ip: &str) -> OutboxRoute {
        let port =
            crate::lan_gate::lab_default_lan_port().unwrap_or(crate::paths::DEFAULT_LAN_PORT);
        lan(&std::net::SocketAddr::new(ip.parse().unwrap(), port).to_string())
    }

    fn all_gates() -> CarrierGates {
        CarrierGates {
            lan: true,
            internet: true,
            p2p: true,
            nearby: false,
            onion: false,
        }
    }

    fn hide_everywhere(dir: &Path, hide_ip: bool) {
        crate::node_policy::save_policy(
            dir,
            &crate::NodePolicy {
                hide_ip,
                ..Default::default()
            },
        )
        .unwrap();
    }

    /// The s04 unit: a contact restarts its LAN listener on another port and
    /// says so. The new port is tried right after the saved route, verified
    /// or not, and a newer generation moves it again.
    #[test]
    fn with_learned_routes_adds_the_announced_port_after_the_saved_route() {
        for pinned in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path();
            let bob = [9u8; 32];
            let saved = contact(&[lan("192.168.7.20:7420")], pinned);
            assert_eq!(learned_on(d, &bob, saved.clone()), saved, "nothing learned");
            let mut v = hints(5);
            v.lan_port = Some(7531);
            told(d, &bob, OutboxCarrier::Lan, Some("192.168.7.20"), None, &v);
            let got = learned_on(d, &bob, saved.clone());
            assert_eq!(
                got.routes,
                [lan("192.168.7.20:7420"), lan("192.168.7.20:7531")],
                "pinned {pinned}"
            );
            assert_eq!(
                plan(None, &got, true, false),
                [lan("192.168.7.20:7420"), lan("192.168.7.20:7531")]
            );
            // Another contact learns nothing from Bob's hints.
            assert_eq!(learned_on(d, &[8u8; 32], saved.clone()), saved);

            v.generation = 6;
            v.lan_port = Some(7532);
            told(d, &bob, OutboxCarrier::Lan, Some("192.168.7.20"), None, &v);
            assert_eq!(
                learned_on(d, &bob, saved.clone()).routes,
                [lan("192.168.7.20:7420"), lan("192.168.7.20:7532")]
            );
            // Back on the saved port: nothing new to try.
            v.generation = 7;
            v.lan_port = Some(7420);
            told(d, &bob, OutboxCarrier::Lan, Some("192.168.7.20"), None, &v);
            assert_eq!(learned_on(d, &bob, saved.clone()), saved);
        }
    }

    /// Phase 3 P3.C1 (people who meet weekly): a week after the contact's
    /// route hint expired, the LAN port it announced is still tried, right
    /// after the saved route, verified or not, inside the learned LAN budget
    /// (where it last reached us from goes first) and only on the network it
    /// was learned on; the expired snapshot plans nothing else (no PeerId).
    /// 30 days after it came it is not tried any more.
    #[test]
    fn the_kept_lan_port_is_dialled_after_the_saved_route() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        let mut v = hints(5);
        v.lan_port = Some(7531);
        v.peer_id = Some(pid(0x51));
        told_on(
            d,
            &bob,
            OutboxCarrier::Lan,
            Some("192.168.7.20"),
            None,
            &v,
            Some("net-a"),
        );
        let t0 = crate::clock::now_ms();
        let week = t0 + 7 * 24 * 3_600_000;
        let saved = [lan("192.168.7.20:7420")];
        let at = |now: u64, pinned: bool, here: &'static str| {
            learned_routes_into(
                d,
                &bob,
                contact(&saved, pinned),
                |_| true,
                hints_gates(true),
                &|| Some(here.to_string()),
                now,
            )
        };
        // While the hint lives: its port and, verified, its PeerId.
        assert_eq!(
            at(t0, true, "net-a").routes,
            [
                lan("192.168.7.20:7420"),
                lan("192.168.7.20:7531"),
                p2p_route(&pid(0x51))
            ]
        );
        assert!(crate::learned_routes::learned(d, &bob, week).is_none());
        let kept = [lan("192.168.7.20:7420"), lan("192.168.7.20:7531")];
        for pinned in [true, false] {
            let got = at(week, pinned, "net-a");
            assert_eq!(got.routes, kept, "pinned {pinned}");
            assert_eq!(got.p2p_learned, None);
            assert_eq!(plan(None, &got, true, false), kept);
        }
        assert_eq!(at(week, true, "net-b").routes, saved, "another network");
        let gone = t0 + crate::learned_routes::LAN_KEEP_MS;
        assert_eq!(at(gone, true, "net-a").routes, saved, "30 days on");

        // Inside the learned LAN budget: the kept port on his saved host
        // first, then where Bob last reached us from (on his saved port): an
        // address he was only seen at goes last (E2).
        crate::lan_seen::record_contact_seen(
            d,
            &bob,
            "192.168.7.33".parse().unwrap(),
            None,
            crate::clock::now_ms(),
        )
        .unwrap();
        assert_eq!(
            at(week, true, "net-a").routes,
            [
                lan("192.168.7.20:7420"),
                lan("192.168.7.20:7531"),
                lan("192.168.7.33:7420")
            ]
        );
    }

    /// A LAN part (its port, on the IP of the LAN link that carried it)
    /// belongs to the network it was learned on: on another network it plans
    /// nothing, so neither `raven send` nor the worker dials a private
    /// address of a network this computer left (where the LAN initiator's
    /// identity bind would go to whoever holds it). On that network, or with
    /// the network unknown, it plans as before.
    #[test]
    fn a_lan_part_learned_on_another_network_plans_no_lan_route() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        let mut v = hints(3);
        v.lan_port = Some(7531);
        told_on(
            d,
            &bob,
            OutboxCarrier::Lan,
            Some("192.168.7.20"),
            None,
            &v,
            Some("net-a"),
        );
        let book = contact(&[lan("bob-mac.local:7420")], true);
        let on = |here: Option<&str>| {
            let here = here.map(String::from);
            let here = move || here.clone();
            learned_routes_into(
                d,
                &bob,
                book.clone(),
                |_| true,
                hints_gates(true),
                &here,
                crate::clock::now_ms(),
            )
            .routes
        };
        // The saved host on the told port before the link's address (E2).
        let planned = [
            lan("bob-mac.local:7420"),
            lan("bob-mac.local:7531"),
            lan("192.168.7.20:7531"),
        ];
        assert_eq!(on(Some("net-a")), planned);
        assert_eq!(on(None), planned, "no default route: as before");
        assert_eq!(on(Some("net-b")), [lan("bob-mac.local:7420")]);
    }

    /// An unverified contact's learned LAN routes are on the local network
    /// only (its saved one is checked at dial time), and it gets nothing p2p.
    /// The caller's on-link filter is asked about learned local addresses
    /// only, as for lan_seen's.
    #[test]
    fn unverified_contacts_get_only_local_learned_lan_routes() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        let mut v = hints(3);
        v.lan_port = Some(7531);
        v.peer_id = Some(pid(0x51));
        v.relays = vec![via(&format!("/ip4/11.0.2.1/tcp/7423/p2p/{}", pid(0x61)))];
        // A "LAN" link from a public address.
        told(d, &bob, OutboxCarrier::Lan, Some("198.51.100.4"), None, &v);

        let unverified = learned_on(d, &bob, contact(&[lan("10.0.0.5:7420")], false));
        assert_eq!(
            unverified.routes,
            [lan("10.0.0.5:7420"), lan("10.0.0.5:7531")],
            "the public link address is left out"
        );
        assert_eq!(unverified.p2p_learned, None);

        let verified = learned_on(d, &bob, contact(&[lan("10.0.0.5:7420")], true));
        assert_eq!(
            verified.routes,
            [
                lan("10.0.0.5:7420"),
                lan("10.0.0.5:7531"),
                lan("198.51.100.4:7531"),
                p2p_route(&pid(0x51)),
            ]
        );
        assert!(verified.p2p_learned.is_some());

        // The on-link filter: asked about 10.0.0.5 only (never about the
        // public address), and what it refuses is left out.
        let asked = std::cell::RefCell::new(Vec::new());
        let filtered = learned_routes_into(
            d,
            &bob,
            contact(&[lan("10.0.0.5:7420")], true),
            |ip| {
                asked.borrow_mut().push(ip);
                false
            },
            hints_gates(true),
            &|| None,
            crate::clock::now_ms(),
        );
        assert_eq!(
            filtered.routes,
            [
                lan("10.0.0.5:7420"),
                lan("198.51.100.4:7531"),
                p2p_route(&pid(0x51))
            ]
        );
        assert_eq!(
            *asked.borrow(),
            ["10.0.0.5".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    /// With route hints off nothing they brought changes a plan: the routes
    /// are exactly with_learned_lan_routes'. The node policy's hide_ip is
    /// added whatever the gate (`raven node hide-ip on` holds for every
    /// planner); it only drops Internet direct routes, so a release plan
    /// (the Internet gate closed) is the same.
    #[test]
    fn release_plan_is_byte_identical_with_the_gate_off() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        crate::lan_seen::record_contact_seen(
            d,
            &bob,
            "192.168.1.30".parse().unwrap(),
            None,
            crate::clock::now_ms(),
        )
        .unwrap();
        let mut v = hints(3);
        v.lan_port = Some(7531);
        v.peer_id = Some(pid(0x51));
        told(d, &bob, OutboxCarrier::Lan, Some("192.168.7.20"), None, &v);
        hide_everywhere(d, true);
        let book = contact(&[lan("192.168.7.20:7420"), inet("203.0.113.7:7422")], true);
        let off = |keep: fn(std::net::IpAddr) -> bool| {
            learned_routes_into(
                d,
                &bob,
                book.clone(),
                keep,
                hints_gates(false),
                &|| None,
                crate::clock::now_ms(),
            )
        };
        let today = with_learned_lan_routes(d, &bob, book.clone());
        assert_eq!(
            today.routes,
            [
                lan("192.168.7.20:7420"),
                lan("192.168.1.30:7420"),
                inet("203.0.113.7:7422")
            ]
        );
        let hidden = |c: ContactRoutes| ContactRoutes { hide_ip: true, ..c };
        assert_eq!(off(|_| true), hidden(today.clone()));
        assert_eq!(
            off(|_| false),
            hidden(with_learned_lan_routes_where(d, &bob, book.clone(), |_| {
                false
            }))
        );
        if !crate::route_hints::route_hints_live() {
            assert_eq!(
                with_learned_routes(d, &bob, book.clone()),
                hidden(today.clone())
            );
        }
        let rec = record(CarrierChoice::Auto, &[inet("203.0.113.8:7422")]);
        // Release: the Internet gate is closed, so hiding changes nothing.
        assert_eq!(
            plan_object_routes(Some(&rec), &off(|_| true), gates(true, false)),
            plan_object_routes(Some(&rec), &today, gates(true, false))
        );
        // Lab with Internet direct open: no Internet route to a contact
        // hidden from (it would show it our IP).
        for open in [all_gates(), gates(true, true)] {
            let plan = plan_object_routes(Some(&rec), &off(|_| true), open);
            assert!(
                plan.routes
                    .iter()
                    .all(|r| r.carrier != OutboxCarrier::Internet),
                "{plan:?}"
            );
        }
        // The same files with route hints on do change it.
        let on = learned_on(d, &bob, book.clone());
        assert!(on.hide_ip && on.p2p_learned.is_some());
        assert_ne!(on.routes, today.routes);
    }

    /// Cutoff F7: a contact with no LAN route (added from an invite line),
    /// pinned (M0) when it reached us, is tried where it came from on the
    /// default LAN port, verified or not (a local address), LAN first, once;
    /// a guess the caller's on-link filter refuses is left out.
    #[test]
    fn no_lan_route_uses_the_sighting_when_live_and_pinned() {
        for pinned in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path();
            let bob = [9u8; 32];
            seen_and_pinned(d, &bob, "192.168.1.30");
            let none = contact(&[], pinned);
            assert_eq!(
                planned_with(d, &bob, none.clone(), F7).routes,
                [guessed("192.168.1.30")],
                "pinned {pinned}"
            );
            let refused = learned_routes_into(
                d,
                &bob,
                none.clone(),
                |_| false,
                F7,
                &|| None,
                crate::clock::now_ms(),
            );
            assert!(refused.routes.is_empty(), "{refused:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        seen_and_pinned(d, &bob, "10.0.0.9");
        let inet_only = contact(&[inet("203.0.113.7:7422")], true);
        assert_eq!(
            planned_with(d, &bob, inet_only, F7).routes,
            [guessed("10.0.0.9"), inet("203.0.113.7:7422")]
        );
        // A public sighting: only for a verified contact.
        seen_and_pinned(d, &bob, "198.51.100.4");
        assert!(planned_with(d, &bob, contact(&[], false), F7)
            .routes
            .is_empty());
        assert_eq!(
            planned_with(d, &bob, contact(&[], true), F7).routes,
            [guessed("198.51.100.4")]
        );
    }

    /// Review fix: the guess is added on every path of the planner, with
    /// route hints off (when it is needed most) and with them on but nothing
    /// (or no LAN part) learned from the contact.
    #[test]
    fn the_hints_off_branch_adds_it_too() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        seen_and_pinned(d, &bob, "10.0.0.9");
        let none = contact(&[], true);
        for hints in [false, true] {
            let gates = LearnedGates {
                hints,
                default_port: true,
                inet: false,
            };
            assert_eq!(
                planned_with(d, &bob, none.clone(), gates).routes,
                [guessed("10.0.0.9")],
                "hints {hints}"
            );
        }
        // Hints that hold a PeerId and no LAN port: the guess, then p2p.
        let mut v = hints(3);
        v.peer_id = Some(pid(0x51));
        told(d, &bob, OutboxCarrier::Lan, Some("10.0.0.9"), None, &v);
        let both = LearnedGates {
            hints: true,
            default_port: true,
            inet: false,
        };
        assert_eq!(
            planned_with(d, &bob, none, both).routes,
            [guessed("10.0.0.9"), p2p_route(&pid(0x51))]
        );
    }

    /// A port the contact told us (RRH1) or its saved one always wins: the
    /// guess is only for a contact with no LAN route left.
    #[test]
    fn an_rrh1_port_wins_over_the_guess() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        seen_and_pinned(d, &bob, "192.168.7.20");
        let mut v = hints(3);
        v.lan_port = Some(7531);
        told(d, &bob, OutboxCarrier::Lan, Some("192.168.7.20"), None, &v);
        let none = contact(&[], true);
        let both = LearnedGates {
            hints: true,
            default_port: true,
            inet: false,
        };
        assert_eq!(
            planned_with(d, &bob, none.clone(), both).routes,
            [lan("192.168.7.20:7531")]
        );
        // Route hints off (an older peer): the guess.
        assert_eq!(
            planned_with(d, &bob, none, F7).routes,
            [guessed("192.168.7.20")]
        );
        // A saved route: lan_seen keeps its port, no guess.
        let saved = contact(&[lan("192.168.7.21:7420")], true);
        assert_eq!(
            planned_with(d, &bob, saved.clone(), F7).routes,
            [lan("192.168.7.21:7420"), lan("192.168.7.20:7420")]
        );
        // With route hints the told port on the saved host comes before the
        // address Bob was only seen at (E2), within the learned budget.
        assert_eq!(
            planned_with(d, &bob, saved, both).routes,
            [
                lan("192.168.7.21:7420"),
                lan("192.168.7.21:7531"),
                lan("192.168.7.20:7420")
            ]
        );
    }

    /// No noise pin, no guess: not Bob's own (another contact's pin is not
    /// his), not when the pin store cannot be read.
    #[test]
    fn no_noise_pin_no_guess() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        crate::lan_seen::record_contact_seen(
            d,
            &bob,
            "192.168.1.30".parse().unwrap(),
            None,
            crate::clock::now_ms(),
        )
        .unwrap();
        let none = contact(&[], true);
        assert!(planned_with(d, &bob, none.clone(), F7).routes.is_empty());
        crate::lan_noise_pin::record(
            d,
            &crate::lan_noise_pin::test_key(),
            &[8u8; 32],
            &[0x52; 32],
        )
        .unwrap();
        assert!(planned_with(d, &bob, none.clone(), F7).routes.is_empty());
        let pins = d.join(crate::lan_noise_pin::NOISE_PIN_FILE);
        std::fs::remove_file(&pins).unwrap();
        std::fs::create_dir(&pins).unwrap();
        assert!(crate::lan_noise_pin::load_pin(d, &bob).is_err());
        assert!(planned_with(d, &bob, none.clone(), F7).routes.is_empty());
        std::fs::remove_dir(&pins).unwrap();
        crate::lan_noise_pin::record(d, &crate::lan_noise_pin::test_key(), &bob, &[0x51; 32])
            .unwrap();
        assert_eq!(
            planned_with(d, &bob, none, F7).routes,
            [guessed("192.168.1.30")]
        );
    }

    /// Gate closed (`live = false`, release today): every plan is what it
    /// was before F7, and a contact with no LAN route still has none (the
    /// send says it has no address saved).
    #[test]
    fn gate_closed_plan_is_identical() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        seen_and_pinned(d, &bob, "192.168.1.30");
        let books = [
            contact(&[], true),
            contact(&[], false),
            contact(&[inet("203.0.113.7:7422")], true),
            contact(&[lan("192.168.1.20:7420")], true),
        ];
        for book in books {
            assert_eq!(
                with_default_port_sighting(d, &bob, book.clone(), |_| true, false),
                book
            );
            assert_eq!(
                planned_with(d, &bob, book.clone(), hints_gates(false)),
                with_learned_lan_routes(d, &bob, book.clone()),
                "{book:?}"
            );
            let lan_before = book.routes.iter().any(|r| r.carrier == OutboxCarrier::Lan);
            let planned = planned_with(d, &bob, book, hints_gates(false));
            let lan_after = planned
                .routes
                .iter()
                .any(|r| r.carrier == OutboxCarrier::Lan);
            assert_eq!(lan_before, lan_after, "{planned:?}");
        }
        if !default_port_guess_live() && !crate::route_hints::route_hints_live() {
            assert!(with_learned_routes(d, &bob, contact(&[], true))
                .routes
                .is_empty());
        }
    }

    /// Hide my IP (D4): no Internet direct dial to that contact, neither the
    /// book's nor one a send recorded. The book's flag (any row) and the
    /// node policy's both hold whatever the route hints gate.
    #[test]
    fn hide_ip_drops_internet_routes() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (bob, carol) = ([1u8; 32], [2u8; 32]);
        let row = |key: [u8; 32], lan: &str, hide: bool| {
            serde_json::json!({ "pub_hex": hex::encode(key), "pinned": true, "lan_dial": lan,
                "internet_dial": "203.0.113.7:7422", "hide_ip": hide })
        };
        let book = serde_json::json!([
            row(bob, "10.0.0.2:7420", false),
            row(bob, "10.0.0.3:7420", true),
            row(carol, "10.0.0.4:7420", false),
        ]);
        std::fs::write(d.join("contacts.json"), book.to_string()).unwrap();
        let rec = record(CarrierChoice::Auto, &[inet("198.51.100.9:7422")]);
        let hidden = contact_routes(d, &bob).unwrap().unwrap();
        assert!(hidden.hide_ip, "one hidden row hides the contact");
        assert_eq!(
            plan_object_routes(Some(&rec), &hidden, all_gates()).routes,
            [lan("10.0.0.2:7420"), lan("10.0.0.3:7420")]
        );
        let shown = contact_routes(d, &carol).unwrap().unwrap();
        assert!(!shown.hide_ip);
        assert_eq!(
            plan_object_routes(Some(&rec), &shown, all_gates()).routes,
            [
                lan("10.0.0.4:7420"),
                inet("203.0.113.7:7422"),
                inet("198.51.100.9:7422")
            ]
        );
        // Hidden from everyone (the node policy), while route hints are live.
        hide_everywhere(d, true);
        let everyone = learned_on(d, &carol, shown.clone());
        assert!(everyone.hide_ip);
        assert_eq!(
            plan_object_routes(Some(&rec), &everyone, all_gates()).routes,
            [lan("10.0.0.4:7420")]
        );
        // Route hints off: the policy holds all the same.
        let off = learned_routes_into(
            d,
            &carol,
            shown.clone(),
            |_| true,
            hints_gates(false),
            &|| None,
            crate::clock::now_ms(),
        );
        assert!(off.hide_ip);
        assert_eq!(
            plan_object_routes(Some(&rec), &off, all_gates()).routes,
            [lan("10.0.0.4:7420")]
        );
    }

    /// A verified contact's learned PeerId becomes a `/p2p/<PeerId>` route
    /// when the book has none, and the plan holds it only while p2p is live.
    /// An unverified contact's is never used, and a book PeerId is never
    /// doubled.
    #[test]
    fn learned_p2p_route_only_for_pinned_contacts_and_only_while_p2p_is_live() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        let relay = via(&format!("/ip4/11.0.2.1/tcp/7423/p2p/{}", pid(0x61)));
        let mut v = hints(4);
        v.peer_id = Some(pid(0x51));
        v.relays = vec![relay.clone()];
        told(d, &bob, OutboxCarrier::P2p, None, Some(&pid(0x51)), &v);
        let book = contact(&[lan("10.0.0.5:7420")], true);
        let got = learned_on(d, &bob, book.clone());
        assert_eq!(got.routes, [lan("10.0.0.5:7420"), p2p_route(&pid(0x51))]);
        let learned = got.p2p_learned.clone().expect("the learned part");
        assert_eq!(
            (learned.peer_id.as_str(), learned.proven),
            (pid(0x51).as_str(), true)
        );
        assert_eq!(learned.relays, std::slice::from_ref(&relay));
        let auto = record(CarrierChoice::Auto, &[]);
        let p2p_off = CarrierGates {
            p2p: false,
            ..all_gates()
        };
        assert_eq!(
            plan_object_routes(Some(&auto), &got, p2p_off).routes,
            [lan("10.0.0.5:7420")]
        );
        assert_eq!(
            plan_object_routes(Some(&auto), &got, all_gates()).routes,
            [lan("10.0.0.5:7420"), p2p_route(&pid(0x51))]
        );
        // What the p2p dialler makes of it: a circuit through the learned
        // relay.
        let set = crate::p2p_route::P2pDialSet::merge(
            got.p2p.as_ref(),
            got.p2p_learned.as_deref(),
            |_| false,
            got.hide_ip.then_some(&[][..]),
        )
        .unwrap();
        assert_eq!(
            set.dial_addrs(),
            [crate::p2p_route::circuit_addr(&relay, &pid(0x51))]
        );

        // Unverified: nothing p2p.
        let unverified = learned_on(d, &bob, contact(&[lan("10.0.0.5:7420")], false));
        assert_eq!(unverified.routes, [lan("10.0.0.5:7420")]);
        assert_eq!(unverified.p2p_learned, None);

        // A book PeerId: one p2p route, the book's, and the dial set ignores
        // hints naming another PeerId.
        let mut with_book = book.clone();
        with_book.p2p = crate::p2p_route::ContactP2p::from_fields(&pid(0x71), &[]);
        with_book.routes.push(p2p_route(&pid(0x71)));
        let got = learned_on(d, &bob, with_book.clone());
        assert_eq!(got.routes, with_book.routes);
        let set = crate::p2p_route::P2pDialSet::merge(
            got.p2p.as_ref(),
            got.p2p_learned.as_deref(),
            |_| true,
            None,
        )
        .unwrap();
        assert_eq!(set.peer_id, pid(0x71));
        assert!(set.relays.is_empty() && set.direct.is_empty());
    }

    /// E2 (mac-b): two friends behind a second router (192.168.1.0/24, their
    /// saved addresses there) dialled mac-b's home address through it, so
    /// mac-b saw both come from the router's address on its home network
    /// (192.168.0.50), and their route hints' LAN part named that address
    /// too: both sends began with "lan_dial 192.168.0.50:17420 did not
    /// answer". An address two contacts are seen at is neither's: no route
    /// there for either (lan_seen's or RRH1's), and the remembered route
    /// there does not go first. A friend seen alone at a new address (a new
    /// DHCP lease) is still tried there, after its saved address and the
    /// port its route hints name on it; once a dial there reached its key
    /// it goes before an address it was only seen at.
    #[test]
    fn an_address_two_friends_are_seen_at_is_neither_friends() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (mac_a, win_c) = ([0xa1u8; 32], [0xc1u8; 32]);
        let nat = "192.168.0.50";
        let now = crate::clock::now_ms();
        let mut v = hints(3);
        v.lan_port = Some(17420);
        for peer in [&mac_a, &win_c] {
            crate::lan_seen::record_contact_seen(d, peer, nat.parse().unwrap(), None, now).unwrap();
            told(d, peer, OutboxCarrier::Lan, Some(nat), None, &v);
        }
        let saved = |ip: &str| contact(&[lan(&format!("{ip}:17420"))], true);
        for (peer, ip) in [(&mac_a, "192.168.1.20"), (&win_c, "192.168.1.30")] {
            let got = learned_on(d, peer, saved(ip));
            assert_eq!(got.routes, [lan(&format!("{ip}:17420"))], "{ip}");
            let plain = with_learned_lan_routes(d, peer, saved(ip));
            assert_eq!(
                plain.routes,
                [lan(&format!("{ip}:17420"))],
                "{ip}: lan_seen's"
            );
        }
        // The route memory's preference for that address is not taken.
        let net = Some("home");
        let there = lan(&format!("{nat}:17420"));
        crate::route_memory::learn(
            d,
            &mac_a,
            &[lan("192.168.1.20:17420"), there.clone()],
            None,
            &[(lan("192.168.1.20:17420"), false), (there.clone(), true)],
            net,
            now,
            now,
        )
        .unwrap();
        assert_eq!(
            crate::route_memory::preferred_route(d, &mac_a, net, now),
            None
        );

        // One friend alone at a new address: tried, last.
        let bob = [0xb0u8; 32];
        crate::lan_seen::record_contact_seen(d, &bob, "192.168.0.77".parse().unwrap(), None, now)
            .unwrap();
        told(d, &bob, OutboxCarrier::Lan, Some("192.168.0.77"), None, &v);
        let book = contact(&[lan("192.168.0.20:7420")], true);
        let got = learned_on(d, &bob, book.clone());
        assert_eq!(
            got.routes,
            [
                lan("192.168.0.20:7420"),
                lan("192.168.0.20:17420"),
                lan("192.168.0.77:7420"),
            ]
        );
        // A dial there reached Bob's key: it goes after his saved host (and
        // the port he told for it), before an address he was only seen at.
        assert!(
            crate::lan_seen::note_reached(d, &bob, "192.168.0.77".parse().unwrap(), None, now)
                .unwrap()
        );
        assert!(crate::lan_seen::reached_at(
            d,
            &bob,
            "192.168.0.77".parse().unwrap(),
            now
        ));
        let mut routes = vec![
            lan("192.168.0.20:7420"),
            lan("192.168.0.99:7420"),
            lan("192.168.0.77:7420"),
            lan("192.168.0.20:17420"),
            inet("203.0.113.7:7422"),
        ];
        order_learned_lan(&mut routes, &["192.168.0.20:7420".to_string()], |ip| {
            crate::lan_seen::reached_at(d, &bob, ip, now)
        });
        assert_eq!(
            routes,
            [
                lan("192.168.0.20:7420"),
                lan("192.168.0.20:17420"),
                lan("192.168.0.77:7420"),
                lan("192.168.0.99:7420"),
                inet("203.0.113.7:7422"),
            ]
        );
    }

    /// lan_seen's and RRH1's learned LAN routes share one budget of two, and
    /// the p2p route stays within the plan's MAX_ROUTES_PER_OBJECT, for a
    /// one-row and a two-row book.
    #[test]
    fn lan_seen_and_rrh1_learned_routes_together_stay_at_two_and_p2p_is_never_truncated() {
        let bob = [9u8; 32];
        let peer_id = pid(0x51);
        let auto = record(CarrierChoice::Auto, &[]);
        let learned_lan = |c: &ContactRoutes, saved: usize| {
            c.routes
                .iter()
                .filter(|r| r.carrier == OutboxCarrier::Lan)
                .count()
                - saved
        };
        let row = |lan: &str, inet: &str, p2p: &str| {
            serde_json::json!({ "pub_hex": hex::encode(bob), "pinned": true, "lan_dial": lan,
                "internet_dial": inet, "p2p": p2p })
        };
        let books = [
            (
                vec![row("192.168.7.20:7420", "203.0.113.7:7422", &peer_id)],
                1,
            ),
            (
                vec![
                    row("192.168.7.20:7420", "203.0.113.7:7422", ""),
                    row("192.168.7.21:7420", "", &peer_id),
                ],
                2,
            ),
        ];
        for (rows, saved) in books {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path();
            std::fs::write(
                d.join("contacts.json"),
                serde_json::Value::from(rows).to_string(),
            )
            .unwrap();
            let book = contact_routes(d, &bob).unwrap().unwrap();
            // Seen from a third address: lan_seen adds one route (the saved
            // routes share their port).
            crate::lan_seen::record_contact_seen(
                d,
                &bob,
                "192.168.7.30".parse().unwrap(),
                None,
                crate::clock::now_ms(),
            )
            .unwrap();
            let mut v = hints(2);
            v.lan_port = Some(7531);
            told(d, &bob, OutboxCarrier::Lan, Some("192.168.7.40"), None, &v);
            let got = learned_on(d, &bob, book.clone());
            assert_eq!(learned_lan(&got, saved), 2, "{:?}", got.routes);
            // The told port on the saved host first (RRH1's one place),
            // then where Bob was seen (E2: the link's address no longer
            // fits).
            assert_eq!(
                got.routes[saved..saved + 2],
                [lan("192.168.7.20:7531"), lan("192.168.7.30:7420")]
            );
            let plan = plan_object_routes(Some(&auto), &got, all_gates());
            assert!(plan.routes.len() <= MAX_ROUTES_PER_OBJECT);
            assert_eq!(
                plan.routes.last(),
                Some(&p2p_route(&peer_id)),
                "{saved} rows"
            );
            // No lan_seen route: RRH1 alone fills the budget (each saved
            // host, then the link's address, then the seen one).
            crate::lan_seen::forget(d, &bob).unwrap();
            let got = learned_on(d, &bob, book.clone());
            assert_eq!(learned_lan(&got, saved), 2, "{:?}", got.routes);
            let second = if saved == 1 {
                lan("192.168.7.40:7531")
            } else {
                lan("192.168.7.21:7531")
            };
            assert_eq!(
                got.routes[saved..saved + 2],
                [lan("192.168.7.20:7531"), second]
            );
            let plan = plan_object_routes(Some(&auto), &got, all_gates());
            assert_eq!(
                plan.routes.last(),
                Some(&p2p_route(&peer_id)),
                "{saved} rows"
            );
        }

        // A fuller book leaves RRH1 only the room the learned p2p route does
        // not need.
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let full = contact(
            &[
                lan("192.168.7.20:7420"),
                lan("192.168.7.21:7421"),
                inet("203.0.113.7:7422"),
                inet("203.0.113.8:7422"),
            ],
            true,
        );
        let mut v = hints(2);
        v.lan_port = Some(7531);
        v.peer_id = Some(peer_id.clone());
        told(d, &bob, OutboxCarrier::Lan, Some("192.168.7.40"), None, &v);
        let got = learned_on(d, &bob, full);
        assert_eq!(got.routes.len(), MAX_ROUTES_PER_OBJECT);
        assert_eq!(got.routes[2], lan("192.168.7.20:7531"));
        let plan = plan_object_routes(Some(&auto), &got, all_gates());
        assert_eq!(plan.routes.last(), Some(&p2p_route(&peer_id)));
    }

    // ── The LAN beacon's finds (Phase 3 P3.11, RAVEN_LAN_BEACON_V1 §9) ──

    fn finds(dials: &[&str]) -> Vec<String> {
        dials.iter().map(|d| d.to_string()).collect()
    }

    /// The finds lead the LAN routes, at most two, IPv4 first (in the order
    /// given within a family); the saved route stays right after them, and
    /// a find that is the saved route moves to the front, once. Only a
    /// local-network IP literal with a port counts (a link-local IPv6 one
    /// with its zone), written as a sighting writes it.
    #[test]
    fn with_beacon_lan_routes_goes_first_caps_two_ipv4_first() {
        let saved = contact(&[lan("192.168.1.20:7420"), inet("203.0.113.7:7422")], true);
        let got = with_beacon_lan_routes(
            saved.clone(),
            &finds(&["[fe80::1%en0]:7499", "192.168.1.40:7499"]),
        );
        assert_eq!(
            got.routes,
            [
                lan("192.168.1.40:7499"),
                lan("[fe80::1%en0]:7499"),
                lan("192.168.1.20:7420"),
                inet("203.0.113.7:7422")
            ]
        );
        assert_eq!(got.pinned, saved.pinned);
        // Two IPv4 finds fill the two places; a repeat counts once.
        let got = with_beacon_lan_routes(
            saved.clone(),
            &finds(&[
                "[fe80::1%en0]:7499",
                "10.0.0.9:7499",
                "10.0.0.9:7499",
                "192.168.1.40:7499",
            ]),
        );
        assert_eq!(
            got.routes,
            [
                lan("10.0.0.9:7499"),
                lan("192.168.1.40:7499"),
                lan("192.168.1.20:7420"),
                inet("203.0.113.7:7422")
            ]
        );
        // The saved address found again: first, never twice.
        let got = with_beacon_lan_routes(saved.clone(), &finds(&["192.168.1.20:7420"]));
        assert_eq!(
            got.routes,
            [lan("192.168.1.20:7420"), inet("203.0.113.7:7422")]
        );
        // What a find may be: a local-network IP literal with a port, an
        // IPv4-mapped one as IPv4, a link-local IPv6 one only with its zone,
        // and loopback (the lab bus). Never a name or another address.
        assert_eq!(
            beacon_lan_dials(&finds(&[
                " [::ffff:192.168.1.41]:7499 ",
                "[fd00::5]:7499",
                "127.0.0.1:47001",
            ])),
            ["192.168.1.41:7499", "127.0.0.1:47001"]
        );
        assert_eq!(
            beacon_lan_dials(&finds(&["[fd00::5]:7499"])),
            ["[fd00::5]:7499"]
        );
        for not in [
            "bob-mac.local:7499",
            "203.0.113.9:7499",
            "100.64.0.1:7499",
            "[2001:db8::1]:7499",
            "[fe80::1]:7499",
            "0.0.0.0:7499",
            "224.0.0.1:7499",
            "192.168.1.40:0",
            "192.168.1.40",
            "",
        ] {
            assert!(beacon_lan_dials(&finds(&[not])).is_empty(), "{not}");
        }
    }

    /// While there are finds the plan takes no learned LAN route (lan_seen,
    /// RRH1): the saved LAN, Internet and p2p routes stay after the finds,
    /// within `MAX_ROUTES_PER_OBJECT` and with the p2p route last, for a
    /// one-row and a two-row book; in a book already at the cap a find takes
    /// no room.
    #[test]
    fn beacon_present_drops_learned_lan_and_keeps_saved_and_p2p() {
        let bob = [9u8; 32];
        let peer_id = pid(0x51);
        let auto = record(CarrierChoice::Auto, &[]);
        let row = |lan: &str, inet: &str, p2p: &str| {
            serde_json::json!({ "pub_hex": hex::encode(bob), "pinned": true, "lan_dial": lan,
                "internet_dial": inet, "p2p": p2p })
        };
        let found = finds(&["192.168.7.50:7599", "[fe80::7%en0]:7599"]);
        let books = [
            (
                vec![row("192.168.7.20:7420", "203.0.113.7:7422", &peer_id)],
                vec![
                    lan("192.168.7.50:7599"),
                    lan("[fe80::7%en0]:7599"),
                    lan("192.168.7.20:7420"),
                    inet("203.0.113.7:7422"),
                    p2p_route(&peer_id),
                ],
            ),
            (
                vec![
                    row("192.168.7.20:7420", "203.0.113.7:7422", ""),
                    row("192.168.7.21:7420", "", &peer_id),
                ],
                vec![
                    lan("192.168.7.50:7599"),
                    lan("[fe80::7%en0]:7599"),
                    lan("192.168.7.20:7420"),
                    lan("192.168.7.21:7420"),
                    inet("203.0.113.7:7422"),
                    p2p_route(&peer_id),
                ],
            ),
        ];
        for (rows, want) in books {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path();
            std::fs::write(
                d.join("contacts.json"),
                serde_json::Value::from(rows).to_string(),
            )
            .unwrap();
            let book = contact_routes(d, &bob).unwrap().unwrap();
            crate::lan_seen::record_contact_seen(
                d,
                &bob,
                "192.168.7.30".parse().unwrap(),
                None,
                crate::clock::now_ms(),
            )
            .unwrap();
            let mut v = hints(2);
            v.lan_port = Some(7531);
            told(d, &bob, OutboxCarrier::Lan, Some("192.168.7.40"), None, &v);
            // Without a find both learned routes are planned (the told port
            // on the saved host before the link's address, E2).
            let learned = learned_on(d, &bob, book.clone());
            assert!(learned.routes.contains(&lan("192.168.7.30:7420")));
            assert!(learned.routes.contains(&lan("192.168.7.20:7531")));
            // With finds: `keep = |_| false`, then the finds.
            let none = learned_routes_into(
                d,
                &bob,
                book.clone(),
                |_| false,
                hints_gates(true),
                &|| None,
                crate::clock::now_ms(),
            );
            let got = with_beacon_lan_routes(none, &found);
            assert_eq!(got.routes, want);
            assert!(got.routes.len() <= MAX_ROUTES_PER_OBJECT);
            let plan = plan_object_routes(Some(&auto), &got, all_gates());
            assert_eq!(plan.routes, want, "nothing cut off");
            assert_eq!(plan.routes.last(), Some(&p2p_route(&peer_id)));
        }
        // A book already at the cap: a find takes no room, so it is not
        // planned (the p2p route is never pushed out); a find that is one of
        // the book's addresses still moves first.
        let full = contact(
            &[
                lan("192.168.7.20:7420"),
                lan("192.168.7.21:7420"),
                lan("192.168.7.22:7420"),
                inet("203.0.113.7:7422"),
                inet("203.0.113.8:7422"),
                p2p_route(&peer_id),
            ],
            true,
        );
        assert_eq!(with_beacon_lan_routes(full.clone(), &found), full);
        let moved = with_beacon_lan_routes(
            full.clone(),
            &finds(&["192.168.7.50:7599", "192.168.7.22:7420"]),
        );
        assert_eq!(moved.routes.len(), MAX_ROUTES_PER_OBJECT);
        assert_eq!(moved.routes[0], lan("192.168.7.22:7420"));
        assert_eq!(moved.routes.last(), Some(&p2p_route(&peer_id)));
    }

    /// No find (or none usable): the contact and its plan are exactly what
    /// they were, so release plans (no beacon) do not change.
    #[test]
    fn release_plan_identical_without_sightings() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [9u8; 32];
        crate::lan_seen::record_contact_seen(
            d,
            &bob,
            "192.168.7.30".parse().unwrap(),
            None,
            crate::clock::now_ms(),
        )
        .unwrap();
        let auto = record(CarrierChoice::Auto, &[lan("192.168.7.9:7420")]);
        for pinned in [true, false] {
            let saved = contact(
                &[lan("192.168.7.20:7420"), inet("203.0.113.7:7422")],
                pinned,
            );
            let today = with_learned_routes(d, &bob, saved);
            for unusable in [
                finds(&[]),
                finds(&["203.0.113.9:7499", "bob-mac.local:7499", "[fe80::1]:7499"]),
            ] {
                let got = with_beacon_lan_routes(today.clone(), &unusable);
                assert_eq!(got, today, "{unusable:?}");
                assert_eq!(
                    plan_object_routes(Some(&auto), &got, all_gates()),
                    plan_object_routes(Some(&auto), &today, all_gates())
                );
            }
        }
    }

    /// A find on an IPv6 link-local address keeps its zone through the plan
    /// and the dial-time check of an unverified contact (which takes a
    /// local-network literal as it is).
    #[test]
    fn localize_lan_route_keeps_a_zoned_find_for_an_unverified_contact() {
        let unverified = contact(&[lan("192.168.1.20:7420")], false);
        let got = with_beacon_lan_routes(unverified, &finds(&["[fe80::1%en0]:7420"]));
        let plan = plan_object_routes(None, &got, gates(true, false));
        assert_eq!(
            plan.routes,
            [lan("[fe80::1%en0]:7420"), lan("192.168.1.20:7420")]
        );
        assert!(!plan.unverified_withheld);
        assert_eq!(
            localize_lan_route(&plan.routes[0], false, LOCALIZE_RESOLVE_TIMEOUT),
            Ok(lan("[fe80::1%en0]:7420"))
        );
    }

    /// The p2p peer gate admits a verified contact with no book PeerId by its
    /// learned one, hidden until a p2p link proves it. The book's PeerId wins
    /// over a different learned one, and learned relays become contact
    /// relays. Unverified and blocked contacts stay out, and with route hints
    /// off nothing learned counts.
    #[test]
    fn p2p_gate_peers_merges_learned_peer_ids_hidden_until_proven_and_book_wins() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let key = |n: u8| [n; 32];
        let relay = |n: u8| via(&format!("/ip4/11.0.2.{n}/tcp/7423/p2p/{}", pid(n)));
        let row = |n: u8, pinned: bool, p2p: String, via: Vec<String>, hide: bool| {
            serde_json::json!({ "pub_hex": hex::encode(key(n)), "pinned": pinned, "p2p": p2p,
                "p2p_via": via, "hide_ip": hide })
        };
        let book = serde_json::json!([
            // A book PeerId and relay; its hints name the same PeerId.
            row(1, true, pid(0x11), vec![relay(0x21).text], false),
            // No book PeerId: learned, unproven.
            row(2, true, String::new(), Vec::new(), false),
            // No book PeerId: learned, proven by a p2p link.
            row(3, true, String::new(), Vec::new(), false),
            // A book PeerId; its hints name another one.
            row(4, true, pid(0x14), Vec::new(), false),
            // Unverified, and verified but blocked: out, learned or not.
            row(5, false, String::new(), Vec::new(), false),
            row(6, true, String::new(), Vec::new(), false),
            // Hidden by its row.
            row(7, true, pid(0x17), Vec::new(), true),
        ]);
        std::fs::write(d.join("contacts.json"), book.to_string()).unwrap();
        let mut blocks = crate::chat_history::BlockList::default();
        blocks.block(&hex::encode(key(6)));
        blocks.save(d).unwrap();
        let tell = |n: u8, peer_id: String, relays: Vec<u8>, proven: bool| {
            let mut v = hints(9);
            v.relays = relays.into_iter().map(relay).collect();
            v.peer_id = Some(peer_id.clone());
            let link = proven.then_some(peer_id.as_str());
            told(d, &key(n), OutboxCarrier::P2p, None, link, &v);
        };
        tell(1, pid(0x11), vec![0x31, 0x21], false);
        tell(2, pid(0x12), vec![0x32], false);
        tell(3, pid(0x13), Vec::new(), true);
        tell(4, pid(0x24), vec![0x34], true);
        tell(5, pid(0x15), Vec::new(), true);
        tell(6, pid(0x16), Vec::new(), true);
        let peer = |peer_id: String, relays: &[u8], hidden: bool, learned: bool, proven: bool| {
            P2pGatePeer {
                peer_id,
                relays: relays.iter().map(|n| pid(*n)).collect(),
                hidden,
                learned,
                proven,
                rotated: Vec::new(),
            }
        };
        let now = crate::clock::now_ms();
        assert_eq!(
            gate_peers(d, true, false, now).unwrap(),
            [
                peer(pid(0x11), &[0x21, 0x31], false, false, true),
                peer(pid(0x12), &[0x32], true, true, false),
                peer(pid(0x13), &[], false, true, true),
                peer(pid(0x14), &[], false, false, true),
                peer(pid(0x17), &[], true, false, true),
            ]
        );
        // Route hints off: the book alone, as in Phase 1.
        let book_only = [
            peer(pid(0x11), &[0x21], false, false, true),
            peer(pid(0x14), &[], false, false, true),
            peer(pid(0x17), &[], true, false, true),
        ];
        assert_eq!(gate_peers(d, false, false, now).unwrap(), book_only);
        if !crate::route_hints::route_hints_live() {
            assert_eq!(p2p_gate_peers(d).unwrap(), book_only);
        }
        // Hidden from everyone: every contact is, and a learned PeerId a
        // link proved stays proved (`hidden` alone no longer says).
        hide_everywhere(d, true);
        let hidden = gate_peers(d, true, false, now).unwrap();
        assert!(hidden.iter().all(|p| p.hidden));
        assert_eq!(
            hidden
                .iter()
                .map(|p| (p.learned, p.proven))
                .collect::<Vec<_>>(),
            [
                (false, true),
                (true, false),
                (true, true),
                (false, true),
                (false, true)
            ]
        );
        assert!(gate_peers(d, false, false, now)
            .unwrap()
            .iter()
            .all(|p| p.hidden));
        // Still fail closed on a broken book.
        std::fs::write(d.join("contacts.json"), b"[{").unwrap();
        assert!(gate_peers(d, true, false, now).is_err());
    }

    /// Review D-4: a schedule that names another contact's PeerIds (its
    /// book's, or its stored schedule's) or a relay's is told apart from
    /// one naming the sender's own epochs; and what tag_contact may mark as
    /// a contact's leaves its schedule's epochs (and unproven learned
    /// PeerIds) out.
    #[test]
    fn a_schedule_naming_another_peers_peer_ids_is_told() {
        use crate::peer_rotation::{self as pr, ContactSchedule};
        use crate::route_hints::PeerSchedule;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let mallory = crate::Identity::from_seed(&[0x51; 32]);
        let victor = crate::Identity::from_seed(&[0x52; 32]);
        let mallory_key = hex::encode(mallory.public_key_bytes());
        let victor_key = hex::encode(victor.public_key_bytes());
        let relay = format!("/ip4/203.0.113.7/tcp/7423/p2p/{}", pid(0x53));
        let book = serde_json::json!([
            { "pub_hex": mallory_key, "pinned": true, "p2p": pid(0x54) },
            { "pub_hex": victor_key, "pinned": true,
              "p2p": pr::epoch_peer_id(&victor, 40), "p2p_via": [relay] },
        ]);
        std::fs::write(d.join("contacts.json"), book.to_string()).unwrap();
        let len = 600u64;
        // Mallory's own epochs: fine.
        let own = pr::announced_schedule(&mallory, Some((40, false)), len);
        assert!(!schedule_names_another_peer(d, &mallory_key, &own));
        // Victor's epochs, sent by Mallory: Victor's card names epoch 40.
        let claimed = pr::announced_schedule(&victor, Some((40, false)), len);
        assert!(schedule_names_another_peer(d, &mallory_key, &claimed));
        // ...but they are Victor's own when Victor sends them.
        assert!(!schedule_names_another_peer(d, &victor_key, &claimed));
        // Only Victor's stored schedule names them (not his card): still
        // another's.
        let later = pr::announced_schedule(&victor, Some((44, false)), len);
        let mut far = later.clone();
        far.entries.retain(|(e, _)| *e > 41);
        pr::save_schedule(
            d,
            &victor_key,
            &ContactSchedule::from_announced(&later, 1_800_000_000_000),
        )
        .unwrap();
        assert!(schedule_names_another_peer(d, &mallory_key, &far));
        // A relay's PeerId (Victor's via=).
        let mut via = own.clone();
        via.entries[0].1 = crate::p2p_route::parse_peer_id(&pid(0x53)).unwrap();
        assert!(schedule_names_another_peer(d, &mallory_key, &via));
        // Capability alone names nothing.
        assert!(!schedule_names_another_peer(
            d,
            &mallory_key,
            &PeerSchedule::capability_only(600)
        ));

        // What tag_contact may mark: the card's PeerId, never the epochs
        // a stored schedule names.
        pr::save_schedule(
            d,
            &mallory_key,
            &ContactSchedule::from_announced(&claimed, 1_800_000_000_000),
        )
        .unwrap();
        assert!(contact_p2p_peer_ids(d, &mallory_key).contains(&pr::epoch_peer_id(&victor, 41)));
        assert_eq!(contact_proven_p2p_peer_ids(d, &mallory_key), [pid(0x54)]);
    }

    /// Phase 4 PeerId rotation: while its gate is live, the peer gate admits
    /// a rotating contact under its card's `p2p=` and `p2pn=` and the
    /// previous, current and next epochs of its schedule around its clock
    /// (plus the epoch it announced); a contact that only says it is capable
    /// adds its `p2pn=` alone. With the gate closed nothing is added. Every
    /// one of its PeerIds is what a block takes away
    /// ([`contact_p2p_peer_ids`]).
    #[test]
    fn p2p_gate_peers_admits_prev_cur_next_of_a_rotating_contact() {
        use crate::peer_rotation::{self as pr, ContactSchedule};
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (bob, carol) = (crate::Identity::from_seed(&[0x41; 32]), [0x42u8; 32]);
        let bob_key = hex::encode(bob.public_key_bytes());
        let len = 600u64;
        let (active, received_ms) = (40u64, 1_800_000_000_000u64);
        let epoch = |e: u64| pr::epoch_peer_id(&bob, e);
        let book = serde_json::json!([
            { "pub_hex": bob_key, "pinned": true, "p2p": epoch(active),
              "p2p_next": epoch(active + 1) },
            { "pub_hex": hex::encode(carol), "pinned": true, "p2p": pid(0x43),
              "p2p_next": pid(0x44) },
        ]);
        std::fs::write(d.join("contacts.json"), book.to_string()).unwrap();
        let announced = pr::announced_schedule(&bob, Some((active, false)), len);
        let s = ContactSchedule::from_announced(&announced, received_ms);
        pr::save_schedule(d, &bob_key, &s).unwrap();
        let capable = crate::route_hints::PeerSchedule::capability_only(600);
        let only = ContactSchedule::from_announced(&capable, received_ms);
        pr::save_schedule(d, &hex::encode(carol), &only).unwrap();

        // Two epochs later (just after the boundary: 2 or 3 epochs on).
        let now_ms = received_ms + 2 * len * 1000 + 1000;
        let got = gate_peers(d, false, true, now_ms).unwrap();
        let bob_peer = got.iter().find(|p| p.peer_id == epoch(active)).unwrap();
        // Card p2p= (active) and p2pn= (active + 1), then the clock window
        // active + 2 - 1 ..= active + 2 + 2 and the announced epoch.
        let want: Vec<String> = [41, 42, 43, 44].into_iter().map(epoch).collect();
        assert_eq!(bob_peer.rotated, want);
        assert_eq!(
            bob_peer.peer_ids().cloned().collect::<Vec<_>>(),
            [epoch(40), epoch(41), epoch(42), epoch(43), epoch(44)]
        );
        // The first epoch of the schedule (39, the previous one) and the
        // last ones (45, 46) are not admitted now.
        for e in [39, 45, 46] {
            assert!(!bob_peer.peer_ids().any(|p| *p == epoch(e)), "{e}");
        }
        let carol_peer = got.iter().find(|p| p.peer_id == pid(0x43)).unwrap();
        assert_eq!(carol_peer.rotated, [pid(0x44)]);
        // Right after it was received: prev, cur and next of epoch 40.
        let at_receipt = gate_peers(d, false, true, received_ms).unwrap();
        let bob_then = at_receipt
            .iter()
            .find(|p| p.peer_id == epoch(active))
            .unwrap();
        assert_eq!(
            bob_then.rotated,
            [41, 39, 42].into_iter().map(epoch).collect::<Vec<_>>()
        );
        // The rotation gate closed: the Phase 1 answer.
        let closed = gate_peers(d, false, false, now_ms).unwrap();
        assert!(closed.iter().all(|p| p.rotated.is_empty()));
        // A block (or a removal) takes every one of them.
        let all = contact_p2p_peer_ids(d, &bob_key);
        for e in [active, active + 1, 39, 45, 46] {
            assert!(all.contains(&epoch(e)), "{e}");
        }
        assert!(contact_p2p_peer_ids(d, &hex::encode(carol)).contains(&pid(0x44)));
        // An unreadable schedules file adds nothing beyond the card.
        std::fs::write(d.join(pr::PEER_SCHEDULES_FILE), b"\x00garbage").unwrap();
        let got = gate_peers(d, false, true, now_ms).unwrap();
        let bob_peer = got.iter().find(|p| p.peer_id == epoch(active)).unwrap();
        assert_eq!(bob_peer.rotated, [epoch(active + 1)]);
    }

    /// Phase 4 (P4.28): a profile rotates only once every verified,
    /// unblocked contact with a p2p route said it can follow
    /// ([`rotation_waiting_on`]); and while rotation is live, the relays a
    /// rotating contact's route hints name under one of its epoch PeerIds
    /// are its contact relays (with the gate closed, the book wins as in
    /// Phase 2).
    #[test]
    fn rotation_waits_on_contacts_that_cannot_follow_and_epoch_hints_count() {
        use crate::peer_rotation::{self as pr, ContactSchedule};
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = crate::Identity::from_seed(&[0x45; 32]);
        let bob_key = hex::encode(bob.public_key_bytes());
        let (carol, dave, erin, frank) = ([0x46u8; 32], [0x48u8; 32], [0x4au8; 32], [0x4cu8; 32]);
        let (len, active) = (600u64, 40u64);
        let now = crate::clock::now_ms();
        let epoch = |e: u64| pr::epoch_peer_id(&bob, e);
        let book = serde_json::json!([
            { "pub_hex": bob_key, "pinned": true, "p2p": epoch(active) },
            { "pub_hex": hex::encode(carol), "pinned": true, "p2p": pid(0x47) },
            // Unverified, no p2p route, blocked: never waited on.
            { "pub_hex": hex::encode(dave), "pinned": false, "p2p": pid(0x49) },
            { "pub_hex": hex::encode(erin), "pinned": true },
            { "pub_hex": hex::encode(frank), "pinned": true, "p2p": pid(0x4d) },
        ]);
        std::fs::write(d.join("contacts.json"), book.to_string()).unwrap();
        let mut blocks = crate::chat_history::BlockList::default();
        blocks.block(&hex::encode(frank));
        blocks.save(d).unwrap();
        assert_eq!(rotation_waiting_on(d).unwrap(), 2);
        let announced = pr::announced_schedule(&bob, Some((active, false)), len);
        pr::save_schedule(
            d,
            &bob_key,
            &ContactSchedule::from_announced(&announced, now),
        )
        .unwrap();
        assert_eq!(rotation_waiting_on(d).unwrap(), 1);
        let capable = crate::route_hints::PeerSchedule::capability_only(600);
        pr::save_schedule(
            d,
            &hex::encode(carol),
            &ContactSchedule::from_announced(&capable, now),
        )
        .unwrap();
        assert_eq!(rotation_waiting_on(d).unwrap(), 0);

        // Bob's hints name the PeerId of his next epoch and a relay.
        let relay = via(&format!("/ip4/11.0.2.54/tcp/7423/p2p/{}", pid(0x36)));
        let mut v = hints(9);
        v.relays = vec![relay];
        v.peer_id = Some(epoch(active + 1));
        let link = epoch(active + 1);
        told(
            d,
            &bob.public_key_bytes(),
            OutboxCarrier::P2p,
            None,
            Some(&link),
            &v,
        );
        let bob_of = |peers: Vec<P2pGatePeer>| {
            peers
                .into_iter()
                .find(|p| p.peer_id == epoch(active))
                .unwrap()
        };
        let live = bob_of(gate_peers(d, true, true, now).unwrap());
        assert_eq!(live.relays, [pid(0x36)]);
        assert!(live.rotated.contains(&epoch(active + 1)));
        let closed = bob_of(gate_peers(d, true, false, now).unwrap());
        assert!(closed.relays.is_empty(), "{closed:?}");

        // Dialled under the clock's epoch, then the other side of the
        // boundary (only while the gate is live); a contact that does not
        // rotate and has no p2pn= is dialled as in Phase 1.
        assert_eq!(
            rotated_dial_ids(d, &bob.public_key_bytes(), true, now),
            Some(vec![epoch(active), epoch(active + 1)])
        );
        assert_eq!(
            rotated_dial_ids(d, &bob.public_key_bytes(), false, now),
            None
        );
        assert_eq!(rotated_dial_ids(d, &carol, true, now), None);
        assert_eq!(rotated_dial_ids(d, &erin, true, now), None);

        // Unreadable schedules: every contact with a p2p route waits.
        std::fs::write(d.join(pr::PEER_SCHEDULES_FILE), b"\x00garbage").unwrap();
        assert_eq!(rotation_waiting_on(d).unwrap(), 2);
        std::fs::write(d.join("contacts.json"), b"[{").unwrap();
        assert!(rotation_waiting_on(d).is_err());
    }

    #[test]
    fn may_share_ip_table() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (bob, carol, stranger) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        // No book, no policy: nothing is hidden.
        assert!(may_share_ip(d, &bob));
        let book = serde_json::json!([
            { "pub_hex": hex::encode(bob), "pinned": true },
            { "pub_hex": hex::encode(carol), "pinned": true, "hide_ip": true },
        ]);
        std::fs::write(d.join("contacts.json"), book.to_string()).unwrap();
        assert!(may_share_ip(d, &bob));
        assert!(!may_share_ip(d, &carol), "hidden from this contact");
        assert!(may_share_ip(d, &stranger));
        // Hidden from everyone, and an unreadable policy hides too.
        hide_everywhere(d, true);
        assert!(!may_share_ip(d, &bob) && !may_share_ip(d, &stranger));
        hide_everywhere(d, false);
        assert!(may_share_ip(d, &bob));
        std::fs::write(crate::node_policy::policy_path(d), b"{broken").unwrap();
        assert!(!may_share_ip(d, &bob));
        hide_everywhere(d, false);
        // An unreadable book: nothing is known, so nothing is shared.
        std::fs::write(d.join("contacts.json"), b"{not json").unwrap();
        assert!(!may_share_ip(d, &bob) && !may_share_ip(d, &stranger));
    }

    #[test]
    fn send_lock_is_one_file_per_peer_shared_by_every_sender() {
        let dir = tempfile::tempdir().unwrap();
        let (bob, carol) = ([1u8; 32], [2u8; 32]);
        // A plain profile keeps the name by the key in hex (privacy pack
        // PP.6 keys it in a sealed one).
        assert_eq!(
            PeerSendLock::file_name(dir.path(), &bob).unwrap(),
            format!(".send_{}.lock.sqlite", hex::encode(bob))
        );
        let held = PeerSendLock::acquire_within(dir.path(), &bob, Duration::ZERO).unwrap();
        let err = PeerSendLock::acquire_within(dir.path(), &bob, Duration::from_millis(50))
            .err()
            .expect("a second holder must wait");
        assert!(send_lock_busy(&err), "{err}");
        // Another peer never waits on Bob's lock.
        let _carol = PeerSendLock::acquire_within(dir.path(), &carol, Duration::ZERO).unwrap();
        drop(held);
        PeerSendLock::acquire_within(dir.path(), &bob, Duration::ZERO).unwrap();
    }

    #[test]
    fn first_ack_frame_skips_messages_and_junk() {
        let env = |kind: EnvType, id: u8| {
            Envelope {
                env_type: kind as u8,
                flags: 0,
                message_id: [id; 16],
                routing_tag: [0x44; 16],
                dest_device_hint: 0,
                created_at: 1,
                expires_at: 2,
                hop_limit: 4,
                replication_budget: 1,
                anti_replay_nonce: [0x55; 12],
                ratchet_header_ciphertext: vec![],
                message_ciphertext: vec![id; 8],
                sender_authentication: vec![0u8; 64],
            }
            .pack()
        };
        let frames = vec![
            b"RLB1junk".to_vec(),
            env(EnvType::Message, 1),
            env(EnvType::Ack, 2),
        ];
        assert_eq!(first_ack_frame(&frames), Some(frames[2].as_slice()));
        assert_eq!(first_ack_frame(&frames[..2]), None);
    }
}
