//! App channel v1: RDAP tasks over the Raven node
//! (`docs/design/2026-10-rdap-app-channel.md`, revision 2).
//!
//! An app payload is an ordinary indexed-session Message whose ATSAM
//! plaintext starts with `RVNAPP/1 <content-type> <app-id>\n`. This module holds
//! the gate, the frame grammar, the classification of received plaintext and
//! the compiled content-type registry (§5). No envelope or crypto change.

use std::path::Path;

use crate::app_store::{Admit, AppInboxItem, AppStore, MetadataOnly, PlatformRowSealer};
use crate::indexed_session_store::{
    InboundPolicy, IndexedSessionRecordKey, IndexedSessionStore, IndexedSessionStoreError,
};

/// App channel production gate. Stays false until the owner's GO.
pub const APP_CHANNEL_PRODUCTION_ENABLED: bool = false;
/// Owner decision on daemon-owned-secrets Q6: UID-only IPC for RDAP on macOS
/// (the app ops return content and use the identity key without a Keychain
/// dialog). Until then the channel stays closed on macOS outside the lab.
pub const APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED: bool = false;

#[cfg(test)]
thread_local! {
    /// Unit tests set the lab unlock per thread (the env var is process-wide).
    static TEST_LAB: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_test_lab(value: Option<bool>) {
    TEST_LAB.with(|c| c.set(value));
}

/// The debug lab unlock (`RAVEN_LAB_TEST_A=1`, never in release builds).
fn lab_unlocked() -> bool {
    #[cfg(test)]
    if let Some(value) = TEST_LAB.with(|c| c.get()) {
        return value;
    }
    crate::pair_init::lab_test_a_enabled()
}

/// Live app channel: the production gate (on macOS only with the Q6
/// decision), or the debug lab unlock `RAVEN_LAB_TEST_A=1`, unless a
/// security notice holds it (P6.45, close-only).
pub fn app_channel_live_enabled() -> bool {
    let platform_ok = !cfg!(target_os = "macos") || APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED;
    ((APP_CHANNEL_PRODUCTION_ENABLED && platform_ok) || lab_unlocked())
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_APP_CHANNEL)
}

pub const APP_FRAME_MAGIC: &str = "RVNAPP/1";
pub const APP_RESERVED_PREFIX: &str = "RVNAPP/";
pub const MAX_APP_HEADER_BYTES: usize = 128;
pub const MAX_APP_FRAME_BYTES: usize = crate::lan_noise::MAX_LAN_ENDPOINT_TEXT;
pub const MAX_APP_BODY_BYTES: usize = 49_024;
const _: () = assert!(MAX_APP_BODY_BYTES + MAX_APP_HEADER_BYTES <= MAX_APP_FRAME_BYTES);
const MAX_CONTENT_TYPE_LEN: usize = 36;

pub const CT_A2A_REQUEST: &str = "a2a-request/1";
pub const CT_A2A_RESPONSE: &str = "a2a-response/1";
pub const CT_TEST: &str = "test/1";

/// A parsed app frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppFrame {
    pub content_type: String,
    pub app_id: [u8; 16],
    pub body: String,
}

/// What a received plaintext is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadClass {
    /// Not an app frame: unchanged chat behaviour.
    Chat,
    App(AppFrame),
    /// A group frame (`protocol/RAVEN_GROUP_V1.md`): the group store's,
    /// never chat history's.
    Group(Box<crate::group::GroupFrame>),
    /// Starts with a reserved prefix (`RVNAPP/`, `RVNGRP/`) but is not a
    /// valid v1 frame: deferred, never committed, never shown.
    ReservedInvalid,
}

/// The body character rule of endpoint text, allowing empty: TAB, LF, CR, or
/// any char at or above U+0020 except U+007F.
pub fn app_body_text_ok(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    text.chars()
        .all(|c| matches!(c, '\t' | '\n' | '\r') || (c >= '\u{20}' && c != '\u{7f}'))
}

/// `CONTENT_TYPE = LOWER *30( LOWER / DIGIT / "." / "+" / "-" ) "/" NZDIGIT *2DIGIT`.
pub fn content_type_ok(ct: &str) -> bool {
    if ct.is_empty() || ct.len() > MAX_CONTENT_TYPE_LEN {
        return false;
    }
    let Some((name, version)) = ct.split_once('/') else {
        return false;
    };
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    let rest_ok = name.len() <= 31
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '+' | '-'));
    let version_ok = (1..=3).contains(&version.len())
        && version.chars().all(|c| c.is_ascii_digit())
        && !version.starts_with('0');
    first_ok && rest_ok && version_ok
}

/// Is `ct` registered for this node (`test/1` only under the lab unlock)?
pub fn content_type_registered(ct: &str, lab: bool) -> bool {
    match ct {
        CT_A2A_REQUEST | CT_A2A_RESPONSE => true,
        CT_TEST => lab,
        _ => false,
    }
}

/// Strict classification of a received (or about-to-be-sealed) plaintext.
pub fn classify(plaintext: &[u8]) -> PayloadClass {
    if crate::group::is_group_text(plaintext) {
        return crate::group::parse_frame(plaintext).map_or(PayloadClass::ReservedInvalid, |f| {
            PayloadClass::Group(Box::new(f))
        });
    }
    if !plaintext.starts_with(APP_RESERVED_PREFIX.as_bytes()) {
        return PayloadClass::Chat;
    }
    parse_frame(plaintext).map_or(PayloadClass::ReservedInvalid, PayloadClass::App)
}

fn parse_frame(plaintext: &[u8]) -> Option<AppFrame> {
    if plaintext.len() > MAX_APP_FRAME_BYTES {
        return None;
    }
    let lf = plaintext.iter().position(|b| *b == b'\n')?;
    if lf > MAX_APP_HEADER_BYTES {
        return None;
    }
    let header = std::str::from_utf8(&plaintext[..lf]).ok()?;
    let mut parts = header.split(' ');
    let (magic, ct, id) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || magic != APP_FRAME_MAGIC || !content_type_ok(ct) {
        return None;
    }
    if id.len() != 32 || !id.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return None;
    }
    let mut app_id = [0u8; 16];
    hex::decode_to_slice(id, &mut app_id).ok()?;
    let body = &plaintext[lf + 1..];
    if body.len() > MAX_APP_BODY_BYTES || !app_body_text_ok(body) {
        return None;
    }
    Some(AppFrame {
        content_type: ct.to_string(),
        app_id,
        body: String::from_utf8(body.to_vec()).ok()?,
    })
}

/// Errors when building a frame to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppFrameError {
    BadContentType,
    PayloadTooLarge,
    BadBody,
}

impl AppFrameError {
    pub fn code(self) -> &'static str {
        match self {
            Self::BadContentType => "APP_BAD_CONTENT_TYPE",
            Self::PayloadTooLarge => "RAVEN_PAYLOAD_TOO_LARGE",
            Self::BadBody => "APP_BAD_BODY",
        }
    }
}

/// Build `RVNAPP/1 <ct> <app_id>\n<body>`; the sender refuses an unregistered
/// type.
pub fn encode_frame(
    ct: &str,
    app_id: &[u8; 16],
    body: &str,
    lab: bool,
) -> Result<String, AppFrameError> {
    if !content_type_ok(ct) || !content_type_registered(ct, lab) {
        return Err(AppFrameError::BadContentType);
    }
    if body.len() > MAX_APP_BODY_BYTES {
        return Err(AppFrameError::PayloadTooLarge);
    }
    if !app_body_text_ok(body.as_bytes()) {
        return Err(AppFrameError::BadBody);
    }
    let frame = format!("{APP_FRAME_MAGIC} {ct} {}\n{body}", hex::encode(app_id));
    debug_assert!(matches!(classify(frame.as_bytes()), PayloadClass::App(_)));
    Ok(frame)
}

/// SHA-256 of an app body: the `(peer, client_ref)` idempotency check
/// compares it (§8.3).
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(body).into()
}

/// The composer guard: chat text may not start with a reserved prefix
/// (`RVNAPP/`, or the groups' `RVNGRP/`).
pub fn chat_text_allowed(text: &str) -> bool {
    !text.starts_with(APP_RESERVED_PREFIX) && !crate::group::is_group_text(text.as_bytes())
}

// ------------------------------------------------------------------ receive

/// How long a received item waits for RDAP before it expires (§7.4).
pub use crate::app_store::APP_INBOX_ITEM_TTL_MS;

/// §7.2: the application policy for one opened plaintext from
/// `sender_device` (ATSAM_ENDPOINT_TRANSACTION_V1 §1 step 7). Chat is
/// accepted; an app frame only when the gate is live, its type is registered
/// and the inbox has room. Metadata reads only: no keystore inside the
/// session-store transaction.
pub fn inbound_policy(
    data_dir: &Path,
    sender_device: &[u8; 32],
    message_id: &[u8; 16],
    plaintext: &[u8],
) -> InboundPolicy {
    let frame = match classify(plaintext) {
        PayloadClass::Chat => return InboundPolicy::Accept,
        PayloadClass::ReservedInvalid => return InboundPolicy::Defer("app_reserved_invalid"),
        // Groups: the gate only; the group store is read after commit.
        PayloadClass::Group(_) if crate::group::group_live_enabled() => {
            return InboundPolicy::Accept
        }
        PayloadClass::Group(_) => return InboundPolicy::Defer("group_gate_closed"),
        PayloadClass::App(frame) => frame,
    };
    if !app_channel_live_enabled() {
        return InboundPolicy::Defer("app_gate_closed");
    }
    if !content_type_registered(&frame.content_type, lab_unlocked()) {
        return InboundPolicy::Defer("app_type_unregistered");
    }
    let admitted = AppStore::open(data_dir, &MetadataOnly).and_then(|store| {
        store.admit(
            sender_device,
            message_id,
            &frame.app_id,
            &frame.content_type,
            frame.body.len(),
        )
    });
    match admitted {
        Ok(Admit::Room | Admit::Duplicate | Admit::AlreadyDone) => InboundPolicy::Accept,
        Ok(Admit::Full) => InboundPolicy::Defer("app_inbox_full"),
        // Fail closed: commit nothing; the sender retries the same bytes.
        Err(_) => InboundPolicy::Defer("app_store_unavailable"),
    }
}

/// The policy deferred the message: nothing was committed, so answer
/// nothing and keep the link open (the sender retries the same bytes).
pub fn is_deferred(err: &IndexedSessionStoreError) -> bool {
    matches!(err, IndexedSessionStoreError::ApplicationDeferred)
}

/// After commit, or for a duplicate of a committed object: hand the accepted
/// plaintext to its consumer. Chat goes to history (an error propagates:
/// never ACK what history cannot keep), unless it is a later copy of a
/// message already taken ([`received_again`]): the history is left alone and
/// the ACK still goes. An app frame goes to the app inbox
/// with the session-bound certificate (never a link bundle, §7.2, CORE-13);
/// `Ok(false)` when it could not be stored now: send no ACK, the endpoint
/// row stays durable and a retry, [`ingest_pending_committed`] or the expiry
/// archive stores it later. `received_at_ms`: the inbox row's own stamp
/// ([`crate::indexed_session_store::EndpointAcceptance::Committed`]).
#[allow(clippy::too_many_arguments)]
pub fn deliver_committed(
    data_dir: &Path,
    sessions: &mut IndexedSessionStore,
    key: &IndexedSessionRecordKey,
    sender_device: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    received_at_ms: u64,
    plaintext: &[u8],
) -> Result<bool, String> {
    match classify(plaintext) {
        PayloadClass::Chat => {
            if !received_again(sessions, sender_device, message_id, received_at_ms) {
                crate::lan_dispatch::persist_lan_chat_history(
                    data_dir,
                    "in",
                    sender_device,
                    message_id,
                    created_at_ms,
                    "received",
                    plaintext,
                )?;
            } else {
                // A later copy is not written again; one with other text
                // marks the first copy's row (ATSAM_ENDPOINT_TRANSACTION_V1
                // §3), whose body stays.
                crate::chat_history::ChatHistory::note_inbound_copy_persisted(
                    data_dir,
                    &hex::encode(sender_device),
                    &hex::encode(message_id),
                    Some(&String::from_utf8_lossy(plaintext)),
                )
                .map_err(|e| e.to_string())?;
            }
            Ok(true)
        }
        PayloadClass::App(frame) => Ok(ingest_app_frame(
            data_dir,
            sessions,
            key,
            sender_device,
            message_id,
            created_at_ms,
            received_at_ms,
            &frame,
        )
        .is_ok()),
        // The group store, never chat history; `Ok(false)` sends no ACK.
        PayloadClass::Group(frame) => crate::group::deliver(
            data_dir,
            sessions,
            key,
            sender_device,
            &frame,
            received_at_ms,
        ),
        // Unreachable after the policy; never shown, never ACKed.
        PayloadClass::ReservedInvalid => Ok(false),
    }
}

/// Receiver dedup (P5.5) for the chat history: is the inbox row of
/// `message_id` from `sender` received at `received_at_ms` (its own stamp) a
/// later copy of a message already taken (the contact re-sealed it under a
/// new session, its ACK lost)? Such a copy is answered but never written to
/// the history again (review 5a-4): its first copy's entry is there, or it
/// left on purpose (the 2,000-entry cap, a chat deletion), and the history's
/// readers (the terminal app, `raven messages`) would show it as a new
/// message. The first copy is noted at its own stamp, so it never tests as
/// one. A store that cannot answer says no (the copy is written, as before).
pub fn received_again(
    sessions: &IndexedSessionStore,
    sender: &[u8; 32],
    message_id: &[u8; 16],
    received_at_ms: u64,
) -> bool {
    crate::horizon::receiver_dedup_live()
        && sessions
            .inbound_received_again(sender, message_id, received_at_ms)
            .unwrap_or(false)
}

/// Store one committed app frame. `Ok(true)` stored now, `Ok(false)` already
/// there or already handled (tombstone).
#[allow(clippy::too_many_arguments)]
fn ingest_app_frame(
    data_dir: &Path,
    sessions: &mut IndexedSessionStore,
    key: &IndexedSessionRecordKey,
    sender_device: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    received_at_ms: u64,
    frame: &AppFrame,
) -> Result<bool, String> {
    let cert = crate::lan_dispatch::session_bound_peer_certificate(
        data_dir,
        sessions,
        key,
        sender_device,
    )?
    .ok_or_else(|| "APP_STORE: no session-bound certificate for the sender".to_string())?;
    let cert_hash = crate::pair_init::device_certificate_hash(&cert)
        .map_err(|e| format!("APP_STORE: certificate hash: {e:?}"))?;
    let cert_json = serde_json::to_string(&cert).map_err(|e| format!("APP_STORE: {e}"))?;
    let item = AppInboxItem {
        sender_device: cert.device_ed_pub,
        message_id: *message_id,
        app_id: frame.app_id,
        sender_identity: cert.user_ed_pub,
        content_type: frame.content_type.clone(),
        created_at_ms,
        received_at_ms,
        expires_at_ms: received_at_ms.saturating_add(APP_INBOX_ITEM_TTL_MS),
        cert_json,
        cert_hash,
        body: frame.body.clone(),
    };
    let sealer = PlatformRowSealer::new(data_dir);
    let stored = AppStore::open(data_dir, &sealer)?.ingest(&item)?;
    if stored {
        bump_generation();
    }
    Ok(stored)
}

/// Bumped on every inbox change; the long-poll watches it (§7.4).
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn bump_generation() {
    GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

pub fn generation() -> u64 {
    GENERATION.load(std::sync::atomic::Ordering::SeqCst)
}

/// §7.3: every committed app row reaches the app inbox. Ingests the app rows
/// behind pending ACK intents (normally none: the receive path ACKs only after
/// ingest). Chat rows are left to their own paths. Returns rows stored.
pub fn ingest_pending_committed(data_dir: &Path, now_ms: u64) -> Result<usize, String> {
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let intents = sessions
        .pending_endpoint_ack_intents()
        .map_err(|e| e.redacted_display())?;
    let mut stored = 0;
    for intent in intents {
        let Some(key) = sessions
            .record_key_for_session_id(&intent.session_id)
            .map_err(|e| e.redacted_display())?
        else {
            continue;
        };
        let row = match sessions.load_endpoint_inbox(&key, &intent.object_digest) {
            Ok(Some(row)) => row,
            Ok(None) | Err(IndexedSessionStoreError::ProtectedStateMissing) => continue,
            Err(e) => return Err(e.redacted_display()),
        };
        let received = if row.received_at_ms > 0 {
            row.received_at_ms
        } else {
            now_ms
        };
        if let PayloadClass::Group(frame) = classify(&row.plaintext) {
            if crate::group::deliver(
                data_dir,
                &mut sessions,
                &key,
                &row.sender_device,
                &frame,
                received,
            )? {
                stored += 1;
            }
            continue;
        }
        if let PayloadClass::App(frame) = classify(&row.plaintext) {
            if ingest_app_frame(
                data_dir,
                &mut sessions,
                &key,
                &row.sender_device,
                &row.message_id,
                row.created_at_ms,
                received,
                &frame,
            )? {
                stored += 1;
            }
        }
    }
    Ok(stored)
}

/// The expiry archive's handling of one endpoint inbox row before its
/// session's roots are destroyed (§7.3): chat to history, app frames to the
/// app inbox, never an app frame into history. An app row whose sender
/// certificate is no longer known cannot be re-checked when served: it is
/// dropped (counted), never shown. Store errors propagate so the prune retries.
pub fn archive_inbox_row(
    data_dir: &Path,
    sessions: &mut IndexedSessionStore,
    key: &IndexedSessionRecordKey,
    row: &crate::indexed_session_store::EndpointInboxRow,
) -> Result<(), String> {
    match classify(&row.plaintext) {
        PayloadClass::Chat
            if received_again(
                sessions,
                &row.sender_device,
                &row.message_id,
                row.received_at_ms,
            ) =>
        {
            Ok(())
        }
        PayloadClass::Chat => crate::lan_dispatch::persist_lan_chat_history(
            data_dir,
            "in",
            &row.sender_device,
            &row.message_id,
            row.created_at_ms,
            "received",
            &row.plaintext,
        ),
        PayloadClass::ReservedInvalid => Ok(()),
        // Idempotent: a frame stored already changes nothing.
        PayloadClass::Group(frame) => crate::group::deliver(
            data_dir,
            sessions,
            key,
            &row.sender_device,
            &frame,
            row.received_at_ms,
        )
        .map(|_| ()),
        PayloadClass::App(frame) => {
            let known = crate::lan_dispatch::session_bound_peer_certificate(
                data_dir,
                sessions,
                key,
                &row.sender_device,
            )?;
            if known.is_none() {
                return Ok(());
            }
            ingest_app_frame(
                data_dir,
                sessions,
                key,
                &row.sender_device,
                &row.message_id,
                row.created_at_ms,
                row.received_at_ms,
                &frame,
            )
            .map(|_| ())
        }
    }
}

// ------------------------------------------------------------------ send bookkeeping

/// The outcome a delivery word (`delivered`, `expired`, `failed`,
/// `cancelled`) gives an app outbox record.
fn out_state_for(delivery: &str) -> Option<crate::app_store::OutState> {
    use crate::app_store::OutState;
    Some(match delivery {
        "delivered" => OutState::Delivered,
        crate::outbox::HISTORY_EXPIRED => OutState::Expired,
        crate::outbox::HISTORY_FAILED => OutState::Failed,
        crate::outbox::HISTORY_CANCELLED => OutState::Cancelled,
        "sent" => OutState::Sent,
        _ => return None,
    })
}

/// An outbound object with no chat stage and no history row (§8.5): if it is
/// an app object, move its record to `delivery` and answer `Ok(true)`.
/// `Ok(false)`: not an app object (no app store, or no record), so the chat
/// path's own answer stands. Never creates the app store.
pub fn mark_app_outbound(
    data_dir: &Path,
    message_id: &[u8; 16],
    delivery: &str,
    code: &str,
    now_ms: u64,
) -> Result<bool, String> {
    if !crate::app_store::app_store_path(data_dir).exists() {
        return Ok(false);
    }
    let mut store = AppStore::open(data_dir, &MetadataOnly)?;
    if !store.is_app_message(message_id)? {
        return Ok(false);
    }
    if let Some(state) = out_state_for(delivery) {
        // A move the monotonic rule refuses (e.g. after `delivered`) is fine.
        let _ = store.set_state(message_id, state, code, now_ms)?;
    }
    Ok(true)
}

/// Is `message_id` one of our app objects? `false` when there is no app
/// store. Errors are the caller's to treat as "unknown" (fail closed).
pub fn is_app_outbound(data_dir: &Path, message_id: &[u8; 16]) -> Result<bool, String> {
    if !crate::app_store::app_store_path(data_dir).exists() {
        return Ok(false);
    }
    AppStore::open(data_dir, &MetadataOnly)?.is_app_message(message_id)
}

/// A record younger than this is never reconciled (its seal may still be
/// committing).
pub const APP_RECONCILE_GRACE_MS: u64 = 60_000;

/// §8.6: app records the session store no longer knows. Runs before sessions
/// are destroyed (preflight, prune, worker start), so a daemon that was down
/// across an expiry still settles them: delivered when an ACK was committed,
/// expired past the envelope's validity, otherwise failed(STORE).
pub fn reconcile_app_outbound(
    data_dir: &Path,
    sessions: &IndexedSessionStore,
    now_ms: u64,
) -> Result<usize, String> {
    use crate::app_store::OutState;
    use crate::indexed_session_store::EndpointDeliveryState;
    if !crate::app_store::app_store_path(data_dir).exists() {
        return Ok(0);
    }
    let mut store = AppStore::open(data_dir, &MetadataOnly)?;
    // Records first, then the session rows: a record sealed after this
    // snapshot is not judged, and one written in the seal callback (before
    // its session transaction commits) is left alone for a grace period.
    let records = store.live_records(now_ms.saturating_sub(APP_RECONCILE_GRACE_MS))?;
    if records.is_empty() {
        return Ok(0);
    }
    let mut live_rows: std::collections::HashSet<[u8; 16]> = sessions
        .pending_endpoint_outbound()
        .map_err(|e| e.redacted_display())?
        .into_iter()
        .map(|row| row.message_id)
        .collect();
    live_rows.extend(
        sessions
            .awaiting_ack_endpoint_outbound()
            .map_err(|e| e.redacted_display())?
            .into_iter()
            .map(|row| row.message_id),
    );
    let mut changed = 0;
    for rec in records {
        if live_rows.contains(&rec.message_id) {
            continue;
        }
        let state = match sessions.outstanding_delivery_state(
            &rec.session_id,
            &rec.message_id,
            &rec.peer_device,
        ) {
            Ok(Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)) => {
                OutState::Delivered
            }
            _ if rec.expires_at_ms <= now_ms => OutState::Expired,
            _ => OutState::Failed,
        };
        let code = if state == OutState::Failed {
            "STORE"
        } else {
            ""
        };
        if store.set_state(&rec.message_id, state, code, now_ms)? {
            changed += 1;
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: [u8; 16] = [0xab; 16];

    #[test]
    fn reconcile_never_judges_a_record_whose_seal_may_still_be_committing() {
        use crate::app_store::{AppOutRecord, OutState};
        let dir = tempfile::tempdir().unwrap();
        let now = 1_800_000_000_000;
        let mid = [0x42; 16];
        AppStore::open(dir.path(), &MetadataOnly)
            .unwrap()
            .put_record(
                &AppOutRecord {
                    peer_identity: [4; 32],
                    client_ref: "task-1".into(),
                    peer_device: [4; 32],
                    content_type: CT_A2A_REQUEST.into(),
                    app_id: [5; 16],
                    body_sha256: [6; 32],
                    message_id: mid,
                    session_id: [7; 32],
                    object_digest: [8; 32],
                    created_at_ms: now,
                    expires_at_ms: now + 3_600_000,
                    state: OutState::Queued,
                    last_error_code: String::new(),
                    attempt_seq: 0,
                },
                now,
            )
            .unwrap();
        let sessions = IndexedSessionStore::open(dir.path()).unwrap();
        // No session row (yet): inside the grace period nothing is decided.
        assert_eq!(
            reconcile_app_outbound(dir.path(), &sessions, now + 1).unwrap(),
            0
        );
        let state = |d: &Path| {
            AppStore::open(d, &MetadataOnly)
                .unwrap()
                .record_by_message(&mid)
                .unwrap()
                .unwrap()
        };
        assert_eq!(state(dir.path()).state, OutState::Queued);
        // Still unknown after it: settled as failed(STORE).
        let later = now + APP_RECONCILE_GRACE_MS;
        assert_eq!(
            reconcile_app_outbound(dir.path(), &sessions, later).unwrap(),
            1
        );
        let rec = state(dir.path());
        assert_eq!(rec.state, OutState::Failed);
        assert_eq!(rec.last_error_code, "STORE");
    }

    #[test]
    fn production_flags_stay_false() {
        const {
            assert!(!APP_CHANNEL_PRODUCTION_ENABLED);
            assert!(!APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED);
        }
        if !crate::pair_init::lab_test_a_enabled() {
            assert!(!app_channel_live_enabled());
        }
    }

    #[test]
    fn frames_roundtrip_and_classify() {
        let frame = encode_frame(CT_A2A_REQUEST, &ID, "{\"jsonrpc\":\"2.0\"}", false).unwrap();
        assert_eq!(
            classify(frame.as_bytes()),
            PayloadClass::App(AppFrame {
                content_type: CT_A2A_REQUEST.into(),
                app_id: ID,
                body: "{\"jsonrpc\":\"2.0\"}".into()
            })
        );
        let empty = encode_frame(CT_A2A_RESPONSE, &ID, "", false).unwrap();
        assert!(matches!(classify(empty.as_bytes()), PayloadClass::App(f) if f.body.is_empty()));
        assert_eq!(classify(b"hello bob"), PayloadClass::Chat);
        assert_eq!(classify(b"RVNAPP"), PayloadClass::Chat);
        assert_eq!(
            encode_frame("x-unknown/1", &ID, "", false),
            Err(AppFrameError::BadContentType)
        );
        assert_eq!(
            encode_frame(CT_TEST, &ID, "", false),
            Err(AppFrameError::BadContentType)
        );
        assert!(encode_frame(CT_TEST, &ID, "", true).is_ok());
        assert!(!chat_text_allowed("RVNAPP/1 hi"));
        assert!(chat_text_allowed("RVNAPP hi"));
    }

    #[test]
    fn body_limit_is_exact() {
        let ok = "a".repeat(MAX_APP_BODY_BYTES);
        let frame = encode_frame(CT_A2A_REQUEST, &ID, &ok, false).unwrap();
        assert!(matches!(classify(frame.as_bytes()), PayloadClass::App(_)));
        assert_eq!(
            encode_frame(CT_A2A_REQUEST, &ID, &format!("{ok}a"), false),
            Err(AppFrameError::PayloadTooLarge)
        );
        let over = format!("RVNAPP/1 a2a-request/1 {}\n{ok}a", hex::encode(ID));
        assert_eq!(classify(over.as_bytes()), PayloadClass::ReservedInvalid);
    }

    #[test]
    fn negatives_are_reserved_invalid() {
        let id = hex::encode(ID);
        let cases = [
            format!("RVNAPP/2 a2a-request/1 {id}\nx"),
            format!("RVNAPP/1 a2a-request/1 {}\nx", id.to_uppercase()),
            format!("RVNAPP/1 a2a-request/1 {id}"),
            format!("RVNAPP/1 a2a-request/1 {id}\nnul\u{0}"),
            format!("RVNAPP/1 a2a-request/1 {id}\ndel\u{7f}"),
            format!("RVNAPP/1 a2a-request/1 {id}\nesc\u{1b}[2J"),
            format!("RVNAPP/1  {id}\nx"),
            format!("RVNAPP/1 A2A-request/1 {id}\nx"),
            format!("RVNAPP/1 a2a-request/0 {id}\nx"),
            format!("RVNAPP/1 a2a-request/1000 {id}\nx"),
            format!("RVNAPP/1 a2a-request/1 {id} extra\nx"),
            format!("RVNAPP/1 {} {id}\nx", "a".repeat(140)),
        ];
        for case in cases {
            assert_eq!(
                classify(case.as_bytes()),
                PayloadClass::ReservedInvalid,
                "{case:?}"
            );
        }
        assert!(content_type_ok("a2a-request/1"));
        assert!(content_type_ok("x.y+z-1/999"));
        assert!(!content_type_ok("1abc/1"));
        assert!(!content_type_ok(""));
    }

    fn vectors_dir() -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        p.join("shared-vectors/rvn1/app_payload")
    }

    /// Shared with RDAP's selftest. Regenerate with `RAVEN_REGEN_APP_VECTORS=1`.
    #[test]
    fn app_payload_vectors() {
        let id = hex::encode(ID);
        type Case<'a> = (&'a str, String, Option<(&'a str, &'a str)>);
        let cases: Vec<Case> = vec![
            (
                "valid_request_001.json",
                format!("RVNAPP/1 a2a-request/1 {id}\n{{\"jsonrpc\":\"2.0\",\"id\":\"{id}\"}}"),
                Some((
                    CT_A2A_REQUEST,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"abababababababababababababababab\"}",
                )),
            ),
            (
                "valid_response_empty_body_001.json",
                format!("RVNAPP/1 a2a-response/1 {id}\n"),
                Some((CT_A2A_RESPONSE, "")),
            ),
            (
                "negative_bad_magic_001.json",
                format!("RVNAPP/2 a2a-request/1 {id}\nx"),
                None,
            ),
            (
                "negative_uppercase_hex_001.json",
                format!("RVNAPP/1 a2a-request/1 {}\nx", id.to_uppercase()),
                None,
            ),
            (
                "negative_missing_lf_001.json",
                format!("RVNAPP/1 a2a-request/1 {id}"),
                None,
            ),
            (
                "negative_nul_001.json",
                format!("RVNAPP/1 a2a-request/1 {id}\n\u{0}"),
                None,
            ),
            (
                "negative_del_001.json",
                format!("RVNAPP/1 a2a-request/1 {id}\n\u{7f}"),
                None,
            ),
            (
                "negative_esc_001.json",
                format!("RVNAPP/1 a2a-request/1 {id}\n\u{1b}"),
                None,
            ),
            (
                "negative_uppercase_type_001.json",
                format!("RVNAPP/1 A2A-request/1 {id}\nx"),
                None,
            ),
            (
                "negative_version_0_001.json",
                format!("RVNAPP/1 a2a-request/0 {id}\nx"),
                None,
            ),
            (
                "negative_version_1000_001.json",
                format!("RVNAPP/1 a2a-request/1000 {id}\nx"),
                None,
            ),
        ];
        for (name, plaintext, want) in cases {
            let got = classify(plaintext.as_bytes());
            match want {
                Some((ct, body)) => assert_eq!(
                    got,
                    PayloadClass::App(AppFrame {
                        content_type: ct.into(),
                        app_id: ID,
                        body: body.into()
                    }),
                    "{name}"
                ),
                None => assert_eq!(got, PayloadClass::ReservedInvalid, "{name}"),
            }
            let expected = serde_json::json!({
                "name": name.trim_end_matches(".json"),
                "protocol_version": "rvn1",
                "deterministic": true,
                "description": "RVNAPP/1 app frame inside the ATSAM plaintext of an indexed-session Message",
                "inputs": { "plaintext_hex": hex::encode(plaintext.as_bytes()) },
                "expected": match want {
                    Some((ct, body)) => serde_json::json!({
                        "class": "app", "content_type": ct, "app_id_hex": id, "body": body
                    }),
                    None => serde_json::json!({ "class": "reserved_invalid" }),
                },
            });
            let path = vectors_dir().join(name);
            if std::env::var("RAVEN_REGEN_APP_VECTORS").as_deref() == Ok("1") {
                std::fs::create_dir_all(vectors_dir()).unwrap();
                std::fs::write(
                    &path,
                    serde_json::to_string_pretty(&expected).unwrap() + "\n",
                )
                .unwrap();
            }
            let stored: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(stored, expected, "{name}");
        }
    }
}
