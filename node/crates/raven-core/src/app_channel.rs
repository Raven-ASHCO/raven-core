//! App channel v1: RDAP tasks over the Raven node
//! (`docs/design/2026-10-rdap-app-channel.md`, revision 2).
//!
//! An app payload is an ordinary indexed-session Message whose ATSAM
//! plaintext starts with `RVNAPP/1 <content-type> <app-id>\n`. This module holds
//! the gate, the frame grammar, the classification of received plaintext and
//! the compiled content-type registry (§5). No envelope or crypto change.

use std::path::Path;

use crate::app_store::{Admit, AppInboxItem, AppStore, MetadataOnly, PlatformRowSealer};
use crate::attachment::shown::AttClass;
use crate::indexed_session_store::{
    InboundPolicy, IndexedSessionRecordKey, IndexedSessionStore, IndexedSessionStoreError,
};

/// App channel production gate: RDAP, Raven's companion for software
/// agents, sends its tasks and answers through the Raven node. Switched on
/// in release builds in 2026-10 (the owner's GO, with the features that
/// passed the three-machine field test; RDAP over Raven proven on loopback
/// over LAN and the Tor onion carrier); not independently reviewed. Only
/// verified contacts, over the same carriers and sessions as messages. A
/// debug build closes it with `RAVEN_LAB_TEST_A=0`.
pub const APP_CHANNEL_PRODUCTION_ENABLED: bool = true;
/// Owner decision on daemon-owned-secrets Q6 (2026-10-29: accepted): the app
/// channel's IPC is UID-only on macOS too, as on Windows and Linux. The
/// residual: any process of the same macOS user can use the app channel, so
/// it can read the RDAP task and answer content the channel carries and send
/// RDAP tasks as this identity, without a Keychain dialog. Ordinary Raven
/// messages are not exposed through it. A stronger check of the peer
/// process (its code-signing identity, daemon-owned-secrets §4.4) is future
/// work. Recorded in docs/THREAT_MODEL.md.
pub const APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED: bool = true;

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
/// decision, accepted 2026-10-29), or the debug lab unlock
/// `RAVEN_LAB_TEST_A=1`; a debug build closes it with `RAVEN_LAB_TEST_A=0`
/// ([`crate::pair_init::test_a_gate`]); unless a security notice holds it
/// (P6.45, close-only).
pub fn app_channel_live_enabled() -> bool {
    let platform_ok = !cfg!(target_os = "macos") || APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED;
    (crate::pair_init::test_a_gate(APP_CHANNEL_PRODUCTION_ENABLED && platform_ok) || lab_unlocked())
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
    /// An attachment text (`RVNATT/`; `docs/design/2026-11-attachments.md`
    /// §8.4): an offer of a photo, a voice note or a file is kept like chat
    /// and shown as a line of words, a profile offer is kept silently, and
    /// anything else under the prefix is taken and dropped. Never chat
    /// text, and never deferred.
    Att(crate::attachment::shown::AttClass),
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
    if crate::attachment::offer::is_att_text(plaintext) {
        return PayloadClass::Att(crate::attachment::shown::class(plaintext));
    }
    if !plaintext.starts_with(APP_RESERVED_PREFIX.as_bytes()) {
        return PayloadClass::Chat;
    }
    parse_frame(plaintext).map_or(PayloadClass::ReservedInvalid, PayloadClass::App)
}

/// Is this plaintext a row a chat shows: chat text, or an attachment's
/// offer, which a chat shows as a line of words ([`chat_row_text`])?
pub fn is_chat_row(plaintext: &[u8]) -> bool {
    matches!(
        classify(plaintext),
        PayloadClass::Chat | PayloadClass::Att(AttClass::Offer(_))
    )
}

/// What a chat shows for a chat row's plaintext from `name` (the reader's
/// name for the friend): the text as it is, or, for an attachment's offer,
/// its line of words. Never the offer as text.
pub fn chat_row_text(plaintext: &[u8], name: &str) -> String {
    let text = String::from_utf8_lossy(plaintext);
    match crate::attachment::shown::shown(&text, name) {
        crate::attachment::shown::Shown::Words(words) => words,
        crate::attachment::shown::Shown::Text | crate::attachment::shown::Shown::Hidden => {
            text.into_owned()
        }
    }
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
/// (`RVNAPP/`, the groups' `RVNGRP/`, or the attachments' `RVNATT/`: typed
/// or pasted, such text would be an offer on the friend's side).
pub fn chat_text_allowed(text: &str) -> bool {
    !text.starts_with(APP_RESERVED_PREFIX)
        && !crate::group::is_group_text(text.as_bytes())
        && !crate::attachment::offer::is_att_text(text.as_bytes())
}

// ------------------------------------------------------------------ receive

/// How long a received item waits for RDAP before it expires (§7.4).
pub use crate::app_store::APP_INBOX_ITEM_TTL_MS;

// ------------------------------------------------------------------ guard

/// The receiver guard's rate window (RAVEN_APP_PAYLOAD_V1 §3.1).
pub const APP_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// New app payloads of one content type taken from one sender per
/// [`APP_RATE_WINDOW`]; more are deferred (the sender retries later).
pub const APP_RATE_PER_SENDER_TYPE: usize = 30;
/// New app payloads of one content type taken from all senders together per
/// [`APP_RATE_WINDOW`].
pub const APP_RATE_PER_TYPE: usize = 120;

/// Who may send this node an app payload (RAVEN_APP_PAYLOAD_V1 §3.1): a
/// current, unblocked contact whose key is verified (security words or code
/// checked). An unverified contact's app payloads are deferred, never
/// stored: an agent task acts on this computer, so it comes only from
/// someone the user checked. A book that cannot be read admits nobody.
pub fn sender_may_send(data_dir: &Path, sender_identity: &[u8; 32]) -> bool {
    matches!(
        crate::outbox::contact_admission(data_dir, sender_identity),
        crate::outbox::ContactAdmission::Allowed(c) if c.pinned
    )
}

/// The guard's rate windows: when each payload taken in the last
/// [`APP_RATE_WINDOW`] was taken, per (sender device, content type) and per
/// content type.
#[derive(Default)]
pub struct AppRate {
    per_sender: std::collections::HashMap<
        ([u8; 32], String),
        std::collections::VecDeque<std::time::Instant>,
    >,
    per_type: std::collections::HashMap<String, std::collections::VecDeque<std::time::Instant>>,
}

impl AppRate {
    /// Take one slot for a new payload of `content_type` from `sender` at
    /// `now`; `false` (nothing taken) when either window is full.
    pub fn take(&mut self, sender: &[u8; 32], content_type: &str, now: std::time::Instant) -> bool {
        let fresh = |q: &mut std::collections::VecDeque<std::time::Instant>| {
            while q
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= APP_RATE_WINDOW)
            {
                q.pop_front();
            }
            !q.is_empty()
        };
        self.per_sender.retain(|_, q| fresh(q));
        self.per_type.retain(|_, q| fresh(q));
        let key = (*sender, content_type.to_string());
        let mine = self.per_sender.get(&key).map_or(0, |q| q.len());
        let all = self.per_type.get(content_type).map_or(0, |q| q.len());
        if mine >= APP_RATE_PER_SENDER_TYPE || all >= APP_RATE_PER_TYPE {
            return false;
        }
        self.per_sender.entry(key).or_default().push_back(now);
        self.per_type
            .entry(content_type.to_string())
            .or_default()
            .push_back(now);
        true
    }
}

#[cfg(test)]
thread_local! {
    /// Unit tests keep their own windows (the process-wide ones are shared
    /// by every test thread).
    static TEST_RATE: std::cell::RefCell<AppRate> = std::cell::RefCell::new(AppRate::default());
}

/// [`AppRate::take`] on this process's windows.
fn take_rate_slot(sender: &[u8; 32], content_type: &str) -> bool {
    let now = std::time::Instant::now();
    #[cfg(test)]
    {
        TEST_RATE.with(|r| r.borrow_mut().take(sender, content_type, now))
    }
    #[cfg(not(test))]
    {
        static RATE: std::sync::OnceLock<std::sync::Mutex<AppRate>> = std::sync::OnceLock::new();
        RATE.get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(sender, content_type, now)
    }
}

/// §7.2 and the receiver guard (RAVEN_APP_PAYLOAD_V1 §3.1): the application
/// policy for one opened plaintext from `sender_device` of the identity
/// `sender_identity` (the session-bound certificate's user key;
/// ATSAM_ENDPOINT_TRANSACTION_V1 §1 step 7). Chat is accepted. An app frame
/// is taken only when the gate is live, its type is registered (what), its
/// sender is a verified contact (who), the frame keeps the size limits (how
/// big: it parsed), the sender and the type are within their rate windows
/// (how often: [`APP_RATE_PER_SENDER_TYPE`], [`APP_RATE_PER_TYPE`]) and the
/// inbox has room (how many). A copy of a payload already held or handled
/// is taken without a slot. Anything else is deferred: nothing is committed
/// and the sender retries the same bytes. Metadata and the contact book
/// only: no keystore inside the session-store transaction.
pub fn inbound_policy(
    data_dir: &Path,
    sender_identity: &[u8; 32],
    sender_device: &[u8; 32],
    message_id: &[u8; 16],
    plaintext: &[u8],
) -> InboundPolicy {
    let frame = match classify(plaintext) {
        PayloadClass::Chat => return InboundPolicy::Accept,
        // An attachment text is never deferred: kept or dropped after the
        // commit, and always answered (attachments design §8.4).
        PayloadClass::Att(_) => return InboundPolicy::Accept,
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
    if !sender_may_send(data_dir, sender_identity) {
        return InboundPolicy::Defer("app_sender_not_verified");
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
        Ok(Admit::Duplicate | Admit::AlreadyDone) => InboundPolicy::Accept,
        Ok(Admit::Room) if take_rate_slot(sender_device, &frame.content_type) => {
            InboundPolicy::Accept
        }
        Ok(Admit::Room) => InboundPolicy::Defer("app_sender_rate"),
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
        // An attachment's offer is kept as it came, like chat: a later
        // build opens it, and readers show its line of words.
        PayloadClass::Chat | PayloadClass::Att(AttClass::Offer(_)) => {
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
                // §3), whose body stays. An attachment's row holds the
                // stored form, so a copy of its offer is compared by what a
                // reader shows, and with the kept offer's digest for the
                // rest (its key and root; attachments design §8.3).
                let text = String::from_utf8_lossy(plaintext);
                let other_offer = crate::attachment::flow::copy_differs(data_dir, &text);
                crate::chat_history::ChatHistory::note_inbound_copy_persisted(
                    data_dir,
                    &hex::encode(sender_device),
                    &hex::encode(message_id),
                    (!other_offer).then_some(text.as_ref()),
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
        // A friend's profile offer: kept silently, the newest only.
        PayloadClass::Att(AttClass::Profile { seq }) => {
            crate::lan_dispatch::persist_profile_offer(
                data_dir,
                sender_device,
                message_id,
                created_at_ms,
                seq,
                plaintext,
            )?;
            Ok(true)
        }
        // Any other attachment text: taken (ACKed) and dropped.
        PayloadClass::Att(AttClass::Other) => Ok(true),
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
/// ingest), and the group rows, all in one read of the group store (a group
/// frame refused for lack of room stays pending until its sender sends it
/// again). Chat rows are left to their own paths. Returns rows stored.
pub fn ingest_pending_committed(data_dir: &Path, now_ms: u64) -> Result<usize, String> {
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let intents = sessions
        .pending_endpoint_ack_intents()
        .map_err(|e| e.redacted_display())?;
    let mut stored = 0;
    let mut groups = Vec::new();
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
            groups.push(crate::group::PendingFrame {
                key,
                sender_device: row.sender_device,
                frame: *frame,
                at_ms: received,
            });
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
    stored += crate::group::deliver_pending(data_dir, &mut sessions, &groups)?;
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
        PayloadClass::Chat | PayloadClass::Att(AttClass::Offer(_))
            if received_again(
                sessions,
                &row.sender_device,
                &row.message_id,
                row.received_at_ms,
            ) =>
        {
            Ok(())
        }
        PayloadClass::Chat | PayloadClass::Att(AttClass::Offer(_)) => {
            crate::lan_dispatch::persist_lan_chat_history(
                data_dir,
                "in",
                &row.sender_device,
                &row.message_id,
                row.created_at_ms,
                "received",
                &row.plaintext,
            )
        }
        PayloadClass::Att(AttClass::Profile { seq }) => crate::lan_dispatch::persist_profile_offer(
            data_dir,
            &row.sender_device,
            &row.message_id,
            row.created_at_ms,
            seq,
            &row.plaintext,
        ),
        PayloadClass::Att(AttClass::Other) | PayloadClass::ReservedInvalid => Ok(()),
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

    /// A contact book with `rows` (`(key, pinned)`) and, with `blocked`, the
    /// first key on the block list.
    fn book(dir: &Path, rows: &[([u8; 32], bool)], blocked: bool) {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|(key, pinned)| {
                serde_json::json!({"petname": "Friend", "pub_hex": hex::encode(key),
                                   "address": "", "pinned": pinned})
            })
            .collect();
        std::fs::write(
            dir.join("contacts.json"),
            serde_json::to_string(&rows).unwrap(),
        )
        .unwrap();
        let mut blocks = crate::chat_history::BlockList::default();
        if blocked {
            blocks.block(&hex::encode(rows_key(&rows[0])));
        }
        blocks.save(dir).unwrap();
    }

    fn rows_key(row: &serde_json::Value) -> [u8; 32] {
        let mut key = [0u8; 32];
        hex::decode_to_slice(row["pub_hex"].as_str().unwrap(), &mut key).unwrap();
        key
    }

    fn request(n: u32) -> ([u8; 16], String) {
        let mut mid = [0u8; 16];
        mid[..4].copy_from_slice(&n.to_be_bytes());
        let frame = encode_frame(CT_A2A_REQUEST, &mid, "{}", false).unwrap();
        (mid, frame)
    }

    /// RAVEN_APP_PAYLOAD_V1 §3.1, who: only a verified, unblocked contact's
    /// app payloads are taken; an unverified contact's, a stranger's and a
    /// blocked contact's are deferred (nothing committed), while their chat
    /// is not the guard's business.
    #[test]
    fn the_guard_takes_app_payloads_from_verified_contacts_only() {
        let dir = tempfile::tempdir().unwrap();
        let friend = [0x51; 32];
        let (mid, frame) = request(1);
        let policy = |dir: &Path| inbound_policy(dir, &friend, &friend, &mid, frame.as_bytes());
        let not_verified = InboundPolicy::Defer("app_sender_not_verified");
        assert_eq!(policy(dir.path()), not_verified, "no contact book");
        book(dir.path(), &[([0x52; 32], true)], false);
        assert_eq!(policy(dir.path()), not_verified, "a stranger");
        book(dir.path(), &[(friend, false)], false);
        assert_eq!(policy(dir.path()), not_verified, "not verified");
        assert_eq!(
            inbound_policy(dir.path(), &friend, &friend, &mid, b"hello"),
            InboundPolicy::Accept,
            "chat is not the guard's"
        );
        book(dir.path(), &[(friend, true)], true);
        assert_eq!(policy(dir.path()), not_verified, "blocked");
        book(dir.path(), &[(friend, true)], false);
        assert_eq!(policy(dir.path()), InboundPolicy::Accept, "verified");
        assert!(sender_may_send(dir.path(), &friend));
        // What and how big stay the frame's: an unregistered type or an
        // oversized body is deferred whoever sends it.
        let unregistered = format!("RVNAPP/1 x-other/1 {}\n{{}}", hex::encode(mid));
        assert_eq!(
            inbound_policy(dir.path(), &friend, &friend, &mid, unregistered.as_bytes()),
            InboundPolicy::Defer("app_type_unregistered")
        );
        let big = format!(
            "RVNAPP/1 a2a-request/1 {}\n{}",
            hex::encode(mid),
            "a".repeat(MAX_APP_BODY_BYTES + 1)
        );
        assert_eq!(
            inbound_policy(dir.path(), &friend, &friend, &mid, big.as_bytes()),
            InboundPolicy::Defer("app_reserved_invalid")
        );
    }

    /// RAVEN_APP_PAYLOAD_V1 §3.1, how often: at most
    /// [`APP_RATE_PER_SENDER_TYPE`] new payloads of a type from one sender a
    /// minute (more are deferred and taken once the window moves on), at
    /// most [`APP_RATE_PER_TYPE`] from everyone, each type and each sender
    /// on its own.
    #[test]
    fn the_guard_limits_how_often_a_sender_may_send() {
        let dir = tempfile::tempdir().unwrap();
        let (alice, bob) = ([0x61; 32], [0x62; 32]);
        book(dir.path(), &[(alice, true), (bob, true)], false);
        for n in 0..APP_RATE_PER_SENDER_TYPE as u32 {
            let (mid, frame) = request(n);
            assert_eq!(
                inbound_policy(dir.path(), &alice, &alice, &mid, frame.as_bytes()),
                InboundPolicy::Accept,
                "{n}"
            );
        }
        let (mid, frame) = request(1_000);
        assert_eq!(
            inbound_policy(dir.path(), &alice, &alice, &mid, frame.as_bytes()),
            InboundPolicy::Defer("app_sender_rate")
        );
        // Another sender, and the same sender's answers, have their own.
        assert_eq!(
            inbound_policy(dir.path(), &bob, &bob, &mid, frame.as_bytes()),
            InboundPolicy::Accept
        );
        let answer = encode_frame(CT_A2A_RESPONSE, &mid, "{}", false).unwrap();
        assert_eq!(
            inbound_policy(dir.path(), &alice, &alice, &mid, answer.as_bytes()),
            InboundPolicy::Accept
        );

        // The windows themselves.
        let t0 = std::time::Instant::now();
        let mut rate = AppRate::default();
        for _ in 0..APP_RATE_PER_SENDER_TYPE {
            assert!(rate.take(&alice, CT_A2A_REQUEST, t0));
        }
        assert!(!rate.take(&alice, CT_A2A_REQUEST, t0));
        assert!(!rate.take(&alice, CT_A2A_REQUEST, t0 + APP_RATE_WINDOW / 2));
        assert!(rate.take(&alice, CT_A2A_REQUEST, t0 + APP_RATE_WINDOW));
        let mut rate = AppRate::default();
        for n in 0..APP_RATE_PER_TYPE {
            let sender = [n as u8; 32];
            assert!(rate.take(&sender, CT_A2A_REQUEST, t0), "{n}");
        }
        assert!(!rate.take(&[0xff; 32], CT_A2A_REQUEST, t0), "everyone's");
        assert!(rate.take(&[0xff; 32], CT_A2A_RESPONSE, t0), "another type");
    }

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

    /// 2026-10: the app channel is on in release builds, on macOS too
    /// (owner decision Q6, UID-only IPC accepted); a debug build closes it
    /// with `RAVEN_LAB_TEST_A=0`.
    #[test]
    fn production_flags_are_on() {
        const {
            assert!(APP_CHANNEL_PRODUCTION_ENABLED);
            assert!(APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED);
        }
        let test_a = std::env::var(crate::pair_init::LAB_TEST_A).ok();
        let want = crate::pair_init::test_a_gate_value(
            cfg!(debug_assertions),
            APP_CHANNEL_PRODUCTION_ENABLED,
            test_a.as_deref(),
        );
        assert_eq!(app_channel_live_enabled(), want);
        if !cfg!(debug_assertions) {
            assert!(app_channel_live_enabled(), "release");
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
    #[test]
    fn an_attachment_text_is_never_chat_text_and_never_deferred() {
        use crate::attachment::offer::Kind;
        use crate::attachment::testing::{photo_offer, profile_offer};
        let dir = tempfile::tempdir().unwrap();
        let friend = [7u8; 32];
        let mid = [1u8; 16];
        let photo = photo_offer();
        assert_eq!(
            classify(photo.as_bytes()),
            PayloadClass::Att(AttClass::Offer(Kind::Photo))
        );
        assert_eq!(
            classify(profile_offer(9).as_bytes()),
            PayloadClass::Att(AttClass::Profile { seq: 9 })
        );
        for other in [
            "RVNATT/",
            "RVNATT/1 offer\n{}",
            "RVNATT/2 anything",
            "RVNATT/1 gone\n{}",
        ] {
            assert_eq!(
                classify(other.as_bytes()),
                PayloadClass::Att(AttClass::Other),
                "{other}"
            );
        }
        // Taken whatever it is: kept or dropped after the commit, and always
        // answered. From a stranger to this profile too, as chat is.
        for text in [photo.clone(), profile_offer(9), "RVNATT/x".to_string()] {
            assert_eq!(
                inbound_policy(dir.path(), &friend, &friend, &mid, text.as_bytes()),
                InboundPolicy::Accept
            );
        }
        // An offer is a chat row that says words; the others are no rows.
        assert!(is_chat_row(photo.as_bytes()) && is_chat_row(b"hello"));
        assert!(!is_chat_row(profile_offer(9).as_bytes()) && !is_chat_row(b"RVNATT/x"));
        assert_eq!(
            chat_row_text(photo.as_bytes(), "Max"),
            "Max sent a photo. Update Raven to see it."
        );
        assert_eq!(chat_row_text(b"hello", "Max"), "hello");
        // Nobody types or pastes one.
        assert!(!chat_text_allowed(&photo));
        assert!(!chat_text_allowed("RVNATT/anything"));
        assert!(chat_text_allowed("rvnatt/ in lower case"));
        assert!(chat_text_allowed("a RVNATT/ later in the text"));
    }

    /// The attachments gate for this test's thread, whatever the
    /// environment says; back to it when dropped.
    struct AttGate;
    impl AttGate {
        fn set(on: bool) -> AttGate {
            crate::attachment_gate::set_lab_attachments_for_this_thread(Some(on));
            AttGate
        }
    }
    impl Drop for AttGate {
        fn drop(&mut self) {
            crate::attachment_gate::set_lab_attachments_for_this_thread(None);
        }
    }

    #[test]
    fn an_offer_is_kept_as_it_came_and_readers_see_its_words() {
        use crate::attachment::testing::photo_offer;
        use crate::chat_history::ChatHistory;
        let _gate = AttGate::set(false);
        let dir = tempfile::tempdir().unwrap();
        let friend = [7u8; 32];
        book(dir.path(), &[(friend, true)], false);
        let photo = photo_offer();
        let keep = |mid: u8, text: &[u8]| {
            crate::lan_dispatch::persist_lan_chat_history(
                dir.path(),
                "in",
                &friend,
                &[mid; 16],
                10,
                "received",
                text,
            )
            .unwrap()
        };
        keep(1, photo.as_bytes());
        keep(2, b"hello");
        let raw = ChatHistory::load(dir.path()).unwrap();
        assert_eq!(raw.entries.len(), 2);
        let of = |h: &ChatHistory, mid: u8| {
            h.entries
                .iter()
                .find(|e| e.message_id_hex == hex::encode([mid; 16]))
                .cloned()
                .unwrap()
        };
        let row = of(&raw, 1);
        assert_eq!(row.body, photo, "kept as it came, for a later build");
        assert_eq!(row.preview, "Friend sent a photo. Update Raven to see it.");
        assert!(!row.is_hidden());
        // What every reader gets: words, never the offer.
        let shown = raw.shown();
        assert_eq!(shown.entries.len(), 2);
        let row = of(&shown, 1);
        assert_eq!(row.body, "Friend sent a photo. Update Raven to see it.");
        assert_eq!(row.preview, row.body);
        assert!(shown.entries.iter().all(|e| !e.body.contains("RVNATT/")));
        assert_eq!(of(&shown, 2).body, "hello");
    }

    /// Attachments live (phase 1b): the history keeps an offer's stored
    /// form, never its key, and a verified friend's offer gets its row.
    #[test]
    fn with_attachments_live_the_history_keeps_the_stored_form_and_a_friends_row() {
        use crate::attachment::offer::{parse_frame, parse_ref, Frame};
        use crate::attachment::store::{self, State};
        use crate::attachment::testing::photo_offer;
        use crate::chat_history::ChatHistory;
        if !cfg!(debug_assertions) {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (friend, stranger) = ([7u8; 32], [8u8; 32]);
        book(d, &[(friend, true), (stranger, false)], false);
        let photo = photo_offer();
        let Some(Frame::Offer(offer)) = parse_frame(photo.as_bytes()) else {
            panic!("an offer");
        };
        let blob = offer.blob.as_ref().unwrap();
        let (key, root) = (hex::encode(blob.key.bytes()), hex::encode(blob.root));
        let write = |direction: &str, peer: &[u8; 32], mid: u8| {
            crate::lan_dispatch::persist_lan_chat_history(
                d,
                direction,
                peer,
                &[mid; 16],
                10,
                if direction == "in" {
                    "received"
                } else {
                    "queued"
                },
                photo.as_bytes(),
            )
            .unwrap()
        };
        let row_of = |peer: &[u8; 32], direction: &str| {
            ChatHistory::load(d)
                .unwrap()
                .entries
                .into_iter()
                .find(|e| e.peer_pub_hex == hex::encode(peer) && e.direction == direction)
                .unwrap()
        };

        // Shut: a friend's offer stays as it came (phase 1a) and has no row.
        {
            let _gate = AttGate::set(false);
            write("in", &friend, 1);
            assert_eq!(row_of(&friend, "in").body, photo);
            assert!(store::get(d, &offer.handle).unwrap().is_none());
        }
        let _gate = AttGate::set(true);
        // Live, from someone not verified: the stored form, and no row.
        write("in", &stranger, 2);
        let row = row_of(&stranger, "in");
        assert_eq!(row.body, offer.stored().encode());
        assert_eq!(row.preview, "Photo");
        assert!(!row.body.contains(&key) && !row.body.contains(&root));
        assert!(!row.is_hidden());
        assert!(store::get(d, &offer.handle).unwrap().is_none());

        // The friend's message written again once attachments are live (its
        // inbox row archived, say): the first body stays and is no conflict.
        write("in", &friend, 1);
        let row = row_of(&friend, "in");
        assert_eq!(row.body, photo);
        assert!(!row.id_conflict);
        // The offers kept as they came take the stored form when the live
        // build starts, and the verified friend's has its row.
        assert_eq!(
            crate::attachment::flow::adopt_kept_offers(d, 20).unwrap(),
            1
        );
        let row = row_of(&friend, "in");
        assert_eq!(row.body, offer.stored().encode());
        assert_eq!(row.preview, "Photo");
        let kept = store::get(d, &offer.handle).unwrap().unwrap();
        assert_eq!(
            (kept.state, kept.peer_key()),
            (State::Incoming, Some(friend))
        );
        assert_eq!(
            crate::attachment::flow::adopt_kept_offers(d, 21).unwrap(),
            0
        );

        // Live, from a verified friend: the stored form and the row.
        let other = tempfile::tempdir().unwrap();
        let d2 = other.path();
        book(d2, &[(friend, true)], false);
        let write2 = |direction: &str, mid: u8, delivery: &str| {
            crate::lan_dispatch::persist_lan_chat_history(
                d2,
                direction,
                &friend,
                &[mid; 16],
                10,
                delivery,
                photo.as_bytes(),
            )
            .unwrap()
        };
        write2("in", 3, "received");
        let kept = store::get(d2, &offer.handle).unwrap().unwrap();
        assert_eq!((kept.state, kept.outgoing), (State::Incoming, false));
        assert_eq!(kept.peer_key(), Some(friend));
        assert_eq!(kept.message_id_bytes(), Some([3u8; 16]));
        assert_eq!(hex::encode(kept.key().unwrap().bytes()), key);
        let history = ChatHistory::load(d2).unwrap();
        assert_eq!(history.entries[0].body, offer.stored().encode());
        // A copy that comes again is the same attachment, not a conflict;
        // another offer under its handle is.
        write2("in", 3, "received");
        assert!(!ChatHistory::load(d2).unwrap().entries[0].id_conflict);
        assert!(!crate::attachment::flow::copy_differs(d2, &photo));
        let mut other_pad = photo.clone();
        let at = other_pad.len() - 3;
        other_pad.replace_range(at..at + 1, " ");
        assert_ne!(other_pad, photo);
        // (Not an offer any more: only the encoder's own bytes read.)
        assert!(!crate::attachment::flow::copy_differs(d2, &other_pad));

        // A verified friend who is blocked: the stored form, and no row.
        let blocked_dir = tempfile::tempdir().unwrap();
        book(blocked_dir.path(), &[(friend, true)], true);
        crate::lan_dispatch::persist_lan_chat_history(
            blocked_dir.path(),
            "in",
            &friend,
            &[5; 16],
            10,
            "received",
            photo.as_bytes(),
        )
        .unwrap();
        assert!(store::get(blocked_dir.path(), &offer.handle)
            .unwrap()
            .is_none());
        assert!(!crate::attachment::flow::is_friend(
            blocked_dir.path(),
            &friend
        ));
        assert!(crate::attachment::flow::is_friend(d2, &friend));

        // What readers get: the list words; a reader of attachments, the
        // stored form.
        let shown = history.clone().shown();
        assert_eq!(shown.entries[0].body, "Photo");
        assert_eq!(shown.entries[0].preview, "Photo");
        let with = history.shown_with_attachments();
        assert_eq!(with.entries[0].preview, "Photo");
        let stored = parse_ref(with.entries[0].body.as_bytes()).unwrap();
        assert_eq!(stored, offer.stored());
        assert_eq!(
            chat_row_text(with.entries[0].body.as_bytes(), "Max"),
            "Photo"
        );

        // An offer of mine: the stored form from its first write, also when
        // its delivery is written with the staged offer again.
        write2("out", 4, "queued");
        write2("out", 4, "delivered");
        let mine = ChatHistory::load(d2)
            .unwrap()
            .entries
            .into_iter()
            .find(|e| e.direction == "out")
            .unwrap();
        assert_eq!(mine.body, offer.stored().encode());
        assert_eq!(
            (mine.preview.as_str(), mine.delivery.as_str()),
            ("Photo", "delivered")
        );
        // A stored form that comes from a link is never a message.
        assert_eq!(
            classify(offer.stored().encode().as_bytes()),
            PayloadClass::Att(AttClass::Other)
        );
    }

    #[test]
    fn a_profile_offer_is_kept_silently_and_only_the_newest_of_a_friend() {
        use crate::attachment::testing::profile_offer;
        use crate::chat_history::{ChatHistory, ChatHistoryEntry};
        let dir = tempfile::tempdir().unwrap();
        let friend = [7u8; 32];
        let other = [8u8; 32];
        book(dir.path(), &[(friend, true), (other, true)], false);
        let keep = |peer: &[u8; 32], mid: u8, seq: u64| {
            crate::lan_dispatch::persist_profile_offer(
                dir.path(),
                peer,
                &[mid; 16],
                10,
                seq,
                profile_offer(seq).as_bytes(),
            )
            .unwrap()
        };
        keep(&friend, 1, 50);
        keep(&friend, 2, 40); // older: dropped
        keep(&friend, 3, 50); // the same order again: dropped
        keep(&other, 4, 5);
        let raw = ChatHistory::load(dir.path()).unwrap();
        assert_eq!(raw.entries.len(), 2);
        assert!(raw.entries.iter().all(ChatHistoryEntry::is_hidden));
        assert!(raw.entries.iter().all(|e| e.preview == "Not shown"));
        keep(&friend, 5, 60); // newer: in the older one's place
        let raw = ChatHistory::load(dir.path()).unwrap();
        assert_eq!(raw.entries.len(), 2);
        let mine: Vec<_> = raw
            .entries
            .iter()
            .filter(|e| e.peer_pub_hex == hex::encode(friend))
            .collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].message_id_hex, hex::encode([5u8; 16]));
        assert_eq!(mine[0].body, profile_offer(60));
        // No reader shows, lists or counts them.
        assert!(raw.shown().entries.is_empty());
    }
}
