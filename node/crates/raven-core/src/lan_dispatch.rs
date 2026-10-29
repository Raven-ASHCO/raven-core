//! Inbound LAN-direct dispatch after Noise XX.
//!
//! Handles RLB1 offers, PairInit responder, indexed messages, and sealed ACKs.

#[cfg(test)]
use std::cell::Cell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::address::encode_address;
use crate::at_rest::Kind;
use crate::atsam_mlkem::{begin_hybrid_initiation, HybridKeypair};
use crate::chat_history::{
    clear_staged_outbound_body, list_staged_outbound_bodies, load_staged_outbound_body,
    stage_outbound_body, BlockList, ChatHistory, ChatHistoryEntry, StagedOutboundBody,
};
use crate::clock::now_ms;
use crate::clock_skew::{frame_future_by_ms, future_by_ms, PeerClock};
use crate::device_cert::{
    ensure_local_device_certificate, load_device_registry_checked, DeviceCertificate,
    DeviceRegistry,
};
use crate::device_sync::RevocationStore;
use crate::envelope::{EnvType, Envelope};
use crate::horizon::{
    LETTER_MIN_SESSION_LIFETIME_MS, LETTER_SESSION_LIFETIME_MS, MAX_LETTER_CLAIMS_PER_INITIATOR,
};
use crate::identity::Identity;
use crate::indexed_session_store::{
    record_key_for_init, AuthorizedEndpointDevice, EndpointAcceptance, EndpointAckAcceptance,
    EndpointDeliveryState, IndexedSessionRecordKey, IndexedSessionStore, IndexedSessionStoreError,
    LetterRole, LocalRole,
};
use crate::lan_rlb1::{decode_offer, encode_offer, is_rlb1, LanBundle};
use crate::pair_init::{
    confirmation_tag, decode_init, decode_response, device_certificate_hash, encode_init,
    encode_response, init_hash, init_signing_bytes, prekey_bundle_hash, response_signing_bytes,
    session_id, transcript_hash, verify_init, PairInit, PairInitTrust, PairResponse,
};
use crate::pair_init_lan_oob::{
    classify_packed_envelope, wrap_oob_wire, PairInitOobClassify, PairInitOobKind,
};
use crate::paths::{DataDirLock, PRIMARY_DEVICE_ID};
use crate::prekey_bundle::{PrekeyBundle, PrekeyBundleJson, PrekeyStore};
use crate::prekey_lifecycle::{
    local_prekey_rotation_due, PrekeyClaimOutcome, PrekeyGenerationPrivate, PrekeyLifecycleActor,
    PrekeyLifecycleError, MAX_PREKEY_GENERATIONS, PREKEY_RETENTION_GRACE_MS,
};
use crate::security_events::{SecKind, Via};
use crate::security_sense;
use zeroize::Zeroize;

/// Contacts' device certificates (privacy pack PP.5: RMS1 kind 5 in a sealed
/// profile, like the prekey store, kind 6, and the stage, kind 18; the
/// generation counter stays plain).
pub(crate) const PEER_CERT_CACHE: &str = "peer_device_certs.json";
pub(crate) const PEER_CACHE_STAGE: &str = "peer_cache.stage.json";
const PEER_CACHE_LOCK: &str = ".lan_peer_cache.lock.sqlite";
/// This device's own published prekey bundles (Phase 5 P5.11: RMS1 kind 68
/// in a sealed profile), written under `PEER_CACHE_LOCK` with the prekey
/// store: [`local_published_bundle_by_hash`].
pub(crate) const PREKEY_PUBLISHED_LOCAL_FILE: &str = "prekey_published_local.json";
// Durable peer caches are capped per contact, not globally: one cert slot keyed
// by the verified signer (`user_ed_pub`) and one prekey slot per identity, for
// current contacts only. Strangers cannot consume capacity.
const EPHEMERAL_PEER_TTL: Duration = Duration::from_secs(15 * 60);
const EPHEMERAL_PEER_MAX: usize = 16;

#[derive(Clone)]
struct EphemeralPeer {
    bundle: LanBundle,
    expires_at: Instant,
}

type EphemeralDirMap = HashMap<String, HashMap<[u8; 32], EphemeralPeer>>;

/// Per data-dir ephemeral peers, keyed only by device_ed (one slot per peer).
static EPHEMERAL_PEERS: Mutex<Option<EphemeralDirMap>> = Mutex::new(None);

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_PEER_CACHE_STAGE: Cell<bool> = const { Cell::new(false) };
    /// A crash inside the stage's replay, after this many of its writes
    /// (1: the certificates, 2: the prekey store, 3: the generation); 0: none.
    static CRASH_IN_PEER_CACHE_REPLAY: Cell<u8> = const { Cell::new(0) };
}

/// `Err` once the replay made `writes` writes, when a test armed that crash.
#[cfg(test)]
fn peer_cache_replay_crash(writes: u8) -> Result<(), String> {
    if CRASH_IN_PEER_CACHE_REPLAY.with(|armed| armed.get() == writes) {
        CRASH_IN_PEER_CACHE_REPLAY.with(|armed| armed.set(0));
        return Err(format!("injected crash after replay write {writes}"));
    }
    Ok(())
}

fn ephemeral_dir_key(data_dir: &Path) -> String {
    std::fs::canonicalize(data_dir)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| data_dir.to_string_lossy().into_owned())
}

/// A LAN bundle binds exactly one identity. The certificate must be
/// self-certified (`device_ed_pub == user_ed_pub`): the certificate signature
/// is then the device key's proof of possession, and every field the caches
/// key on is covered by that signature. Cert + prekey signatures and validity
/// windows must verify. Every cache write and trust decision runs this first.
///
/// Certificates for a separate device key carry no device proof of possession
/// in RLB1, and the LAN caches hold one device per identity, so they are
/// refused here rather than trusted on the signer's word.
pub fn verify_lan_bundle(bundle: &LanBundle, now_ms: u64) -> Result<(), String> {
    if bundle.cert.device_ed_pub != bundle.cert.user_ed_pub {
        return Err("lan bundle device key is not the certificate signer".into());
    }
    bundle.verify_bound(now_ms)
}

/// Keep a LAN peer in process memory only (TTL + LRU). Never writes
/// `peer_device_certs.json` / `prekey_store.json`. The bundle is verified
/// first, so a slot keyed by `device_ed_pub` can only be filled by the holder
/// of that key.
pub fn remember_ephemeral_peer(data_dir: &Path, bundle: &LanBundle) -> Result<(), String> {
    verify_lan_bundle(bundle, now_ms())?;
    let now = Instant::now();
    let dir_key = ephemeral_dir_key(data_dir);
    let mut guard = EPHEMERAL_PEERS
        .lock()
        .map_err(|_| "ephemeral peer lock poisoned".to_string())?;
    let root = guard.get_or_insert_with(HashMap::new);
    let map = root.entry(dir_key).or_insert_with(HashMap::new);
    map.retain(|_, e| e.expires_at > now);
    while map.len() >= EPHEMERAL_PEER_MAX {
        let victim = map
            .iter()
            .min_by_key(|(_, e)| e.expires_at)
            .map(|(k, _)| *k);
        let Some(k) = victim else {
            break;
        };
        map.remove(&k);
    }
    map.insert(
        bundle.cert.device_ed_pub,
        EphemeralPeer {
            bundle: bundle.clone(),
            expires_at: now + EPHEMERAL_PEER_TTL,
        },
    );
    Ok(())
}

/// Forget this process's in-memory peers of `data_dir` (tests: what a
/// restart does), so the next lookup reads the durable cache.
#[cfg(test)]
pub(crate) fn forget_ephemeral_peers(data_dir: &Path) {
    let mut guard = EPHEMERAL_PEERS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(root) = guard.as_mut() {
        root.remove(&ephemeral_dir_key(data_dir));
    }
}

fn load_ephemeral_peer(data_dir: &Path, peer_pub: &[u8; 32]) -> Option<LanBundle> {
    let now = Instant::now();
    let dir_key = ephemeral_dir_key(data_dir);
    let mut guard = EPHEMERAL_PEERS.lock().ok()?;
    let root = guard.as_mut()?;
    let map = root.get_mut(&dir_key)?;
    map.retain(|_, e| e.expires_at > now);
    // Exact key only: no lookup by any other (unverified) certificate field.
    let bundle = map.get(peer_pub)?.bundle.clone();
    if bundle.cert.device_ed_pub != *peer_pub || verify_lan_bundle(&bundle, now_ms()).is_err() {
        map.remove(peer_pub);
        return None;
    }
    Some(bundle)
}

#[derive(Debug, Deserialize)]
struct ContactPubRow {
    #[serde(default)]
    pub_hex: String,
    #[serde(default)]
    petname: String,
    #[serde(default)]
    public_tag: String,
    #[serde(default)]
    alias: String,
}

/// The contact book's rows ([`crate::contact_book`]); no book is none, an
/// unreadable one (sealed without its key, corrupt) an error.
fn contact_rows(data_dir: &Path) -> Result<Vec<ContactPubRow>, String> {
    Ok(crate::contact_book::read_rows(data_dir)?.unwrap_or_default())
}

fn contact_pub_set(data_dir: &Path) -> Result<std::collections::HashSet<String>, String> {
    Ok(contact_rows(data_dir)?
        .into_iter()
        .map(|r| r.pub_hex.trim().to_lowercase())
        .filter(|h| !h.is_empty())
        .collect())
}

/// The petname and tag history keeps for `pub_hex` (empty for a stranger).
/// A book that cannot be read is an error of the write that needed it, never
/// an empty label written into history (privacy pack PP.4, review R23).
fn contact_label_for_pub(data_dir: &Path, pub_hex: &str) -> Result<(String, String), String> {
    let want = pub_hex.trim().to_lowercase();
    for r in contact_rows(data_dir)? {
        if r.pub_hex.trim().eq_ignore_ascii_case(&want) {
            let tag = if !r.public_tag.is_empty() {
                r.public_tag
            } else {
                r.alias
            };
            return Ok((r.petname, tag));
        }
    }
    Ok((String::new(), String::new()))
}

/// Persist a LAN message into durable ChatHistory (full body + short preview).
/// Deduped/upserted by (peer_pub, direction, message_id). Failures must be propagated.
pub fn persist_lan_chat_history(
    data_dir: &Path,
    direction: &str,
    peer_pub: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    delivery: &str,
    plaintext: &[u8],
) -> Result<(), String> {
    let peer_pub_hex = hex::encode(peer_pub);
    let (peer_petname, peer_tag) = contact_label_for_pub(data_dir, &peer_pub_hex)?;
    let text = String::from_utf8_lossy(plaintext);
    let body = text.as_ref().to_string();
    let preview: String = body.chars().take(120).collect();
    let entry = ChatHistoryEntry {
        message_id_hex: hex::encode(message_id),
        direction: direction.into(),
        peer_petname,
        peer_tag,
        peer_pub_hex,
        created_at_ms,
        delivery: delivery.into(),
        preview,
        body,
        // Stamped by `append_persisted` in a sealed profile (PP.9).
        stored_at_ms: None,
        id_conflict: false,
    };
    ChatHistory::append_persisted(data_dir, entry).map_err(|e| e.to_string())
}

/// Upgrade an existing history row's delivery (e.g. `queued` → `delivered`).
/// Fails if no matching row exists — callers must not treat missing as success
/// when committing Delivered / Failed.
pub fn mark_lan_chat_history_delivery(
    data_dir: &Path,
    direction: &str,
    peer_pub: &[u8; 32],
    message_id: &[u8; 16],
    delivery: &str,
) -> Result<(), String> {
    let updated = ChatHistory::set_delivery_persisted(
        data_dir,
        &hex::encode(peer_pub),
        direction,
        &hex::encode(message_id),
        delivery,
    )
    .map_err(|e| e.to_string())?;
    if !updated {
        // No chat row: an app channel object keeps its state in the app
        // outbox instead (stage, then history, then app record; §8.5).
        if direction == "out"
            && crate::app_channel::mark_app_outbound(data_dir, message_id, delivery, "", now_ms())
                .unwrap_or(false)
        {
            return Ok(());
        }
        // A group copy's row goes once its delivery is final and kept in
        // the group store (`group::refresh_deliveries`).
        if direction == "out"
            && crate::group::mark_copy(data_dir, message_id, delivery).unwrap_or(false)
        {
            return Ok(());
        }
        return Err(format!(
            "chat history row missing for delivery={delivery} mid={}",
            hex::encode(message_id)
        ));
    }
    Ok(())
}

fn parse_stage_hex32(hex_s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_s).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("staged binding hex must be 32 bytes".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_stage_hex16(hex_s: &str) -> Result<[u8; 16], String> {
    let bytes = hex::decode(hex_s).map_err(|e| e.to_string())?;
    if bytes.len() != 16 {
        return Err("staged message_id hex must be 16 bytes".into());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn map_stage_persist_err(err: crate::chat_history::ChatHistoryError) -> String {
    match err {
        crate::chat_history::ChatHistoryError::TooLarge => {
            "outbound stage capacity exceeded".into()
        }
        other => other.to_string(),
    }
}

fn staged_binding_matches(
    staged: &StagedOutboundBody,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
) -> bool {
    staged
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
            .eq_ignore_ascii_case(&hex::encode(message_id))
}

/// Ensure outbound history has the exact body (from stage and/or compose text)
/// before dialing. Writes durable protected stage first, then ChatHistory `queued`.
/// Uses the staged `created_at_ms` on retry (never the caller's "now").
pub fn ensure_outbound_queued_history(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    compose_text: Option<&str>,
) -> Result<(), String> {
    ensure_outbound_queued_history_inner(
        data_dir,
        None,
        peer_pub,
        session_id,
        object_digest,
        message_id,
        created_at_ms,
        compose_text,
    )
}

/// Same as [`ensure_outbound_queued_history`], but stages under an already-held
/// [`OutboundStageSendGuard`] so capacity preflight cannot race the write.
pub fn ensure_outbound_queued_history_under_send_guard(
    guard: &crate::chat_history::OutboundStageSendGuard,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    compose_text: Option<&str>,
) -> Result<(), String> {
    ensure_outbound_queued_history_inner(
        guard.data_dir(),
        Some(guard),
        peer_pub,
        session_id,
        object_digest,
        message_id,
        created_at_ms,
        compose_text,
    )
}

#[allow(clippy::too_many_arguments)]
fn ensure_outbound_queued_history_inner(
    data_dir: &Path,
    stage_guard: Option<&crate::chat_history::OutboundStageSendGuard>,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    compose_text: Option<&str>,
) -> Result<(), String> {
    let load_staged = || -> Result<Option<_>, String> {
        match stage_guard {
            Some(guard) => guard
                .load_staged_outbound_body(message_id)
                .map_err(map_stage_persist_err),
            None => load_staged_outbound_body(data_dir, message_id).map_err(map_stage_persist_err),
        }
    };
    let (body, stamped_at) = if let Some(text) = compose_text {
        if let Some(guard) = stage_guard {
            guard
                .stage_outbound_body(
                    peer_pub,
                    session_id,
                    object_digest,
                    message_id,
                    created_at_ms,
                    text,
                )
                .map_err(map_stage_persist_err)?;
        } else {
            stage_outbound_body(
                data_dir,
                peer_pub,
                session_id,
                object_digest,
                message_id,
                created_at_ms,
                text,
            )
            .map_err(map_stage_persist_err)?;
        }
        let staged =
            load_staged()?.ok_or_else(|| "staged outbound missing after write".to_string())?;
        if !staged_binding_matches(&staged, peer_pub, session_id, object_digest, message_id) {
            return Err("staged outbound binding mismatch after write".into());
        }
        (staged.body, staged.created_at_ms)
    } else if let Some(staged) = load_staged()? {
        if !staged_binding_matches(&staged, peer_pub, session_id, object_digest, message_id) {
            return Err(format!(
                "staged outbound binding mismatch for mid={}",
                hex::encode(message_id)
            ));
        }
        (staged.body, staged.created_at_ms)
    } else if ChatHistory::has_body_persisted(
        data_dir,
        &hex::encode(peer_pub),
        "out",
        &hex::encode(message_id),
    )
    .map_err(|e| e.to_string())?
    {
        return Ok(());
    } else {
        return Err(format!(
            "outbound body unavailable for mid={}",
            hex::encode(message_id)
        ));
    };
    persist_lan_chat_history(
        data_dir,
        "out",
        peer_pub,
        message_id,
        stamped_at,
        "queued",
        body.as_bytes(),
    )
}

/// Reconcile protected stage after crash between accept_ack and mark/clear.
/// - `Delivered`/`Read` outstanding → history `delivered`, clear stage
/// - `Sent` outstanding → re-ensure `queued` history from stage
/// - no outstanding row → treat as abandoned → history `failed`, clear stage;
///   `expired` when its session or envelope has ended (pruned with it).
///   Not a message that waits for a new session (the long message horizon,
///   Phase 5a): one parked in the store keeps its stage and its history
///   `queued`. One staged with the zero sentinel binding
///   ([`crate::horizon::is_sentinel_stage`]: no sealed copy named) waits
///   only while it is parked or a live copy of it exists
///   ([`sentinel_stage`]); with neither it is finished (review 5a-2):
///   `delivered` when a copy was confirmed, else `expired` past its deadline
///   and `failed` before it, and its stage cleared.
pub fn reconcile_outbound_stage_history(data_dir: &Path) -> Result<(), String> {
    let staged = list_staged_outbound_bodies(data_dir).map_err(|e| e.to_string())?;
    if staged.is_empty() {
        return Ok(());
    }
    let now = now_ms();
    let store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let mut parked: HashMap<[u8; 32], Option<Vec<[u8; 16]>>> = HashMap::new();
    for entry in staged {
        let peer = parse_stage_hex32(&entry.peer_pub_hex)?;
        let session_id = parse_stage_hex32(&entry.session_id_hex)?;
        let object_digest = parse_stage_hex32(&entry.object_digest_hex)?;
        let message_id = parse_stage_hex16(&entry.message_id_hex)?;
        let delivery = store
            .outstanding_delivery_state(&session_id, &message_id, &peer)
            .map_err(|e| e.redacted_display())?;
        match delivery {
            Some(EndpointDeliveryState::Delivered) | Some(EndpointDeliveryState::Read) => {
                ensure_outbound_queued_history(
                    data_dir,
                    &peer,
                    &session_id,
                    &object_digest,
                    &message_id,
                    entry.created_at_ms,
                    None,
                )?;
                mark_lan_chat_history_delivery(data_dir, "out", &peer, &message_id, "delivered")?;
                clear_staged_outbound_body(data_dir, &message_id).map_err(|e| e.to_string())?;
            }
            Some(EndpointDeliveryState::Sent) => {
                ensure_outbound_queued_history(
                    data_dir,
                    &peer,
                    &session_id,
                    &object_digest,
                    &message_id,
                    entry.created_at_ms,
                    None,
                )?;
            }
            None if crate::horizon::is_sentinel_stage(&entry) => {
                match sentinel_stage(&store, &mut parked, &peer, &message_id) {
                    SentinelStage::Waits => {
                        // Parked, or a live copy took it over (the re-seal
                        // reconcile binds the stage to that copy).
                        ensure_outbound_queued_history(
                            data_dir,
                            &peer,
                            &session_id,
                            &object_digest,
                            &message_id,
                            entry.created_at_ms,
                            None,
                        )?;
                    }
                    finished => {
                        // Unless the stage went meanwhile (a give-up clears
                        // the stage before it drops the parked row, which
                        // this pass found gone): its history is written.
                        let still = load_staged_outbound_body(data_dir, &message_id)
                            .map_err(|e| e.to_string())?
                            .is_some_and(|s| crate::horizon::is_sentinel_stage(&s));
                        if !still {
                            continue;
                        }
                        let delivery = if finished == SentinelStage::Delivered {
                            "delivered"
                        } else if crate::horizon::message_deadline(entry.created_at_ms) <= now {
                            crate::outbox::HISTORY_EXPIRED
                        } else {
                            crate::outbox::HISTORY_FAILED
                        };
                        persist_lan_chat_history(
                            data_dir,
                            "out",
                            &peer,
                            &message_id,
                            entry.created_at_ms,
                            delivery,
                            entry.body.as_bytes(),
                        )?;
                        clear_staged_outbound_body(data_dir, &message_id)
                            .map_err(|e| e.to_string())?;
                    }
                }
            }
            None if parked_message(&store, &mut parked, &peer, &message_id) == Some(true) => {
                // Waiting for a new session until its deadline: the worker
                // seals it again or gives it up.
                ensure_outbound_queued_history(
                    data_dir,
                    &peer,
                    &session_id,
                    &object_digest,
                    &message_id,
                    entry.created_at_ms,
                    None,
                )?;
            }
            None => {
                // Pruned with its session, or past its envelope's own end:
                // it ran out (review C-time-deadlines-2), not a failure.
                let ran_out = session_ended(&store, &session_id, now)
                    || entry
                        .created_at_ms
                        .saturating_add(crate::outbox::ENVELOPE_VALIDITY_MS)
                        <= now;
                persist_lan_chat_history(
                    data_dir,
                    "out",
                    &peer,
                    &message_id,
                    entry.created_at_ms,
                    if ran_out {
                        crate::outbox::HISTORY_EXPIRED
                    } else {
                        crate::outbox::HISTORY_FAILED
                    },
                    entry.body.as_bytes(),
                )?;
                clear_staged_outbound_body(data_dir, &message_id).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

/// What [`reconcile_outbound_stage_history`] does with a stage that names no
/// sealed copy ([`crate::horizon::SENTINEL_BINDING`], P5.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SentinelStage {
    /// Parked, or a live copy of it exists (the window of a re-seal, whose
    /// reconcile binds the stage to that copy), or the store cannot say
    /// (decided again on the next pass): it keeps waiting.
    Waits,
    /// Not parked, and a copy of it was confirmed.
    Delivered,
    /// Not parked and no live copy: nothing would ever send, expire or
    /// clear it (review 5a-2: a contact removal of an older build dropped
    /// the parked row only). Its parked row is written before its stage and
    /// dropped after it, so this is never a park in progress.
    Finished,
}

/// [`SentinelStage`] of the message `message_id` to `peer`.
fn sentinel_stage(
    store: &IndexedSessionStore,
    cache: &mut HashMap<[u8; 32], Option<Vec<[u8; 16]>>>,
    peer: &[u8; 32],
    message_id: &[u8; 16],
) -> SentinelStage {
    if parked_message(store, cache, peer, message_id) != Some(false) {
        return SentinelStage::Waits;
    }
    let Ok(copies) = store.message_copies_for_recipient(peer, message_id) else {
        return SentinelStage::Waits;
    };
    if copies.iter().any(|c| {
        matches!(
            c.delivery_state,
            Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
        )
    }) {
        SentinelStage::Delivered
    } else if copies.iter().any(|c| !c.retired && c.has_outbox_row) {
        SentinelStage::Waits
    } else {
        SentinelStage::Finished
    }
}

/// Is `message_id` to `peer` parked in the store (the long message horizon)?
/// Each contact's parked ids are read once (`cache`). `None`: the store
/// cannot say (a stage that names a copy is then not taken for parked, as
/// before the horizon; a sentinel stage keeps waiting).
fn parked_message(
    store: &IndexedSessionStore,
    cache: &mut HashMap<[u8; 32], Option<Vec<[u8; 16]>>>,
    peer: &[u8; 32],
    message_id: &[u8; 16],
) -> Option<bool> {
    cache
        .entry(*peer)
        .or_insert_with(|| {
            store
                .parked_for_recipient(peer)
                .map(|rows| rows.into_iter().map(|r| r.message_id).collect())
                .ok()
        })
        .as_ref()
        .map(|ids| ids.contains(message_id))
}

/// Has `session_id`'s session ended at `now`? Its head's expiry, from
/// metadata only. A head no longer there was pruned, which happens only
/// once it expired.
fn session_ended(store: &IndexedSessionStore, session_id: &[u8; 32], now: u64) -> bool {
    match store.record_key_for_session_id(session_id) {
        Ok(Some(key)) => store.head_expires_at_ms(&key).is_ok_and(|end| end <= now),
        Ok(None) => true,
        Err(_) => false,
    }
}

/// Outbound messages of the sessions this prune destroys (review
/// C-time-deadlines-2): every message runs out with its session at the
/// latest (`outbox::envelope_expires_at`), and the prune deletes its rows.
/// Before that, each is settled the way the outbox worker settles one that
/// expired: `delivered` when an ACK was committed, else `expired` (the app
/// record for an agent payload), its staged body cleared and its route
/// record dropped. Without this, a node that was off across the deadline
/// pruned them before its worker's first scan: nothing said "expired", and
/// the history kept "queued". Best effort, row by row, like the app
/// reconcile; the prune itself must still run. With the horizon gate on, a
/// message not delivered and before its deadline is parked instead
/// ([`crate::outbox::park_expired_message`]): it keeps its stage, its route
/// record and its `queued` history, and waits for a new session.
fn settle_outbound_of_ended_sessions(
    data_dir: &Path,
    sessions: &mut IndexedSessionStore,
    now: u64,
) -> usize {
    let mut rows = sessions.pending_endpoint_outbound().unwrap_or_default();
    rows.extend(
        sessions
            .awaiting_ack_endpoint_outbound()
            .unwrap_or_default(),
    );
    let mut settled = Vec::new();
    for row in rows {
        if row.kind != crate::indexed_session_store::EndpointOutboundKind::Message
            || !session_ended(sessions, &row.session_id, now)
        {
            continue;
        }
        let delivered = matches!(
            sessions.outstanding_delivery_state(
                &row.session_id,
                &row.message_id,
                &row.recipient_device
            ),
            Ok(Some(
                EndpointDeliveryState::Delivered | EndpointDeliveryState::Read
            ))
        );
        if !delivered {
            // The worker's evidence decides what an expired one shows; a
            // parked message is never "never sent" here (not known).
            let parked = crate::outbox::park_expired_message(
                data_dir,
                sessions,
                &row.recipient_device,
                &row.message_id,
                Some(&row.session_id),
                false,
                now,
            );
            if matches!(parked, Ok(Some(_))) {
                continue;
            }
        }
        let done = if delivered {
            crate::outbox::record_inbound_ack_delivery(
                data_dir,
                &row.recipient_device,
                &row.session_id,
                &row.message_id,
            )
        } else {
            crate::outbox::mark_outbound_undelivered(
                data_dir,
                &row.recipient_device,
                &row.session_id,
                &row.object_digest,
                &row.message_id,
                crate::outbox::HISTORY_EXPIRED,
            )
        };
        if done.is_ok() {
            settled.push(row.message_id);
        }
    }
    let _ = crate::outbox::clear_object_routes(data_dir, &settled);
    settled.len()
}

fn archive_expired_inbox_to_history(data_dir: &Path, now: u64) -> Result<(), String> {
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    // A head whose meta does not open (a changed byte, an epoch no key
    // holds) is left out, logged once: its inbox cannot be read anyway, and
    // the prune after this removes it by its hour (review B-sealed-stores-2:
    // it stopped the archive, and with it that prune and every new session,
    // for good). Without the at-rest key nothing is read (closed).
    for key in sessions
        .list_readable_record_keys()
        .map_err(|e| e.redacted_display())?
    {
        // Metadata-only expiry — must not load protected state (secret may already be gone).
        let expires = sessions
            .head_expires_at_ms(&key)
            .map_err(|e| e.redacted_display())?;
        if expires > now {
            continue;
        }
        match sessions.list_endpoint_inbox_for_record(&key) {
            Ok(rows) => {
                // Chat to history, app frames to the app inbox (never history).
                for row in rows {
                    crate::app_channel::archive_inbox_row(data_dir, &mut sessions, &key, &row)?;
                }
            }
            // Secret already deleted after a prior crash — history must have been
            // written on accept; continue so SQLite metadata can be pruned.
            Err(IndexedSessionStoreError::ProtectedStateMissing) => {}
            Err(e) => return Err(e.redacted_display()),
        }
    }
    Ok(())
}

/// Durable peer cache requires **user trust** (local contact book), not merely a
/// cryptographically confirmed PairInit session (attackers can self-PairInit).
///
/// Trust is computed only from the verified signer (`user_ed_pub`) of a bundle
/// that passes [`verify_lan_bundle`]; an unverified or foreign-keyed bundle is
/// an error, never "trusted".
pub fn peer_is_trusted(data_dir: &Path, bundle: &LanBundle) -> Result<bool, String> {
    verify_lan_bundle(bundle, now_ms())?;
    let contacts = contact_pub_set(data_dir)?;
    Ok(contacts.contains(&hex::encode(bundle.cert.user_ed_pub)))
}

/// Why a link responder closed a dialer before sending its own identity.
/// Local log text only: the dialer sees nothing but the connection closing.
pub const LINK_REFUSED_NOT_CONTACT: &str =
    "inbound peer is not a local contact; link closed before our identity was sent";
pub const LINK_REFUSED_BLOCKED: &str =
    "inbound peer is blocked; link closed before our identity was sent";
/// Why a responder closed a link it could not judge: this process holds the
/// contact book ([`crate::contact_book::hold`]: raven-node waits for the
/// at-rest key at start or after an Unlock, or Raven is locked), so the
/// dialer cannot be told from a stranger. Not a refusal of the dialer: no
/// security event, and the dialer tries again (E1). Local log text only.
pub const LINK_REFUSED_NOT_READY: &str =
    "CONTACTS_NOT_READY: the contact book is not open yet (its key is loading); link closed \
     before our identity was sent, the dialer tries again";

/// An unreadable book or block list admits nobody: a held book
/// ([`LINK_REFUSED_NOT_READY`]) says nothing about the dialer, any other
/// (corrupt, unreadable) is the stranger's refusal it always was.
fn unreadable_refusal(data_dir: &Path) -> &'static str {
    if crate::contact_book::is_held(data_dir) {
        LINK_REFUSED_NOT_READY
    } else {
        LINK_REFUSED_NOT_CONTACT
    }
}

/// Responder-side link admission (LAN bind / Internet RIH1 hello), decided on
/// the Ed25519 key the dialer's signed bind/hello bound to its Noise static,
/// **before** this node reveals its own identity or RLB1 bundle.
///
/// The rule is the one [`peer_is_trusted`] applies to PairInit, messages and
/// ACKs (the key is a local contact), plus the block list. The link layer
/// requires the dialer's RLB1 to bind exactly this key as device key and
/// signer ([`rlb1_matches_noise_identity`]), so contact-ness of the bound key
/// equals `peer_is_trusted` of the bundle that follows. A stranger completes
/// Noise XX only: it learns the responder's Noise static (which does not name
/// the Raven ID) and that it was not accepted. Fail closed: an unreadable
/// contact book or block list admits nobody (a held book:
/// [`LINK_REFUSED_NOT_READY`]).
pub fn link_peer_admission(data_dir: &Path, noise_ed: &[u8; 32]) -> Result<(), &'static str> {
    match crate::outbox::contact_admission(data_dir, noise_ed) {
        crate::outbox::ContactAdmission::Allowed(_) => Ok(()),
        crate::outbox::ContactAdmission::Blocked => Err(LINK_REFUSED_BLOCKED),
        crate::outbox::ContactAdmission::NotContact => Err(LINK_REFUSED_NOT_CONTACT),
        crate::outbox::ContactAdmission::Unreadable => Err(unreadable_refusal(data_dir)),
    }
}

/// Why a responder closed a dialer that is a local contact but not a verified
/// one, on a link where that is not enough (Internet; LAN from outside the
/// local network). Local log text only.
pub const LINK_REFUSED_NOT_VERIFIED: &str =
    "inbound peer is a contact but not verified (this link needs a pinned fingerprint); link \
     closed before our identity was sent";

/// Why a LAN responder closed a dialer that is a local contact but not a
/// verified one while `raven lan verified-only on` holds (Phase 3 P3.C2): the
/// local code [`crate::lan_gate::LAN_VERIFIED_ONLY`] first. Local log text
/// only.
pub const LINK_REFUSED_VERIFIED_ONLY: &str =
    "LAN_VERIFIED_ONLY: inbound peer is a contact but not verified, and only verified \
     contacts may link on the LAN (raven lan verified-only on); link closed before our \
     identity was sent";

/// [`link_peer_admission`] for one carrier, as the listeners apply it before
/// they reveal anything: the dialer must be a current, unblocked contact, and
/// beyond the local network a **verified** (pinned) one
/// ([`crate::outbox::carrier_allowed_for_contact`] and
/// [`crate::outbox::is_local_network_ip`], owner decision 2026-10-08):
/// - Internet direct: pinned contacts only;
/// - LAN direct: any contact from a local-network source address (`source`),
///   pinned contacts from anywhere. An unknown source counts as remote.
///   While `raven lan verified-only on` holds (Phase 3 P3.C2,
///   [`crate::node_policy::lan_verified_only`]), pinned contacts only,
///   wherever they dial from ([`LINK_REFUSED_VERIFIED_ONLY`]).
///
/// A refused contact is treated exactly like a stranger. Every refusal path
/// does the same work (one contact-book read, one block-list read, and for
/// LAN one node-policy read), so the time to refuse does not tell a scanner
/// whether a key is a contact. Fail closed on an unreadable book or block
/// list (and an unreadable policy is verified-only); a book this process
/// holds while its key loads judges nobody ([`LINK_REFUSED_NOT_READY`]).
pub fn link_admission(
    data_dir: &Path,
    noise_ed: &[u8; 32],
    carrier: crate::outbox::OutboxCarrier,
    source: Option<std::net::IpAddr>,
) -> Result<(), &'static str> {
    use crate::outbox::{
        carrier_allowed_for_contact, contact_admission, is_local_network_ip, ContactAdmission,
        OutboxCarrier,
    };
    let local = source.is_some_and(is_local_network_ip);
    // Read for every LAN link, before the book: the same work whoever dials.
    let verified_only =
        carrier == OutboxCarrier::Lan && crate::node_policy::lan_verified_only(data_dir);
    match contact_admission(data_dir, noise_ed) {
        ContactAdmission::Allowed(contact) => {
            let allowed = carrier_allowed_for_contact(carrier, contact.pinned)
                && (carrier != OutboxCarrier::Lan || contact.pinned || local);
            if !allowed {
                Err(LINK_REFUSED_NOT_VERIFIED)
            } else if verified_only && !contact.pinned {
                Err(LINK_REFUSED_VERIFIED_ONLY)
            } else {
                Ok(())
            }
        }
        ContactAdmission::Blocked => Err(LINK_REFUSED_BLOCKED),
        ContactAdmission::NotContact => Err(LINK_REFUSED_NOT_CONTACT),
        ContactAdmission::Unreadable => Err(unreadable_refusal(data_dir)),
    }
}

/// Envelope expiry must stay inside the PairInit session window (typically
/// 24h): the shared validity policy of `raven send` and the outbox
/// ([`crate::outbox::ENVELOPE_VALIDITY_MS`]).
fn envelope_expires(now: u64, session_expires: u64) -> Result<u64, String> {
    crate::outbox::envelope_expires_at(now, session_expires)
}

/// Publish a local hybrid prekey if none is valid or the current one is due
/// for rotation (see `PREKEY_ROTATION_LEAD_MS`).
pub fn ensure_local_prekey(data_dir: &Path, id: &Identity) -> Result<(), String> {
    let _ = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID)?;
    let identity_pub = id.public_key_bytes();
    // Common case: nothing to do, and no lock is taken.
    let store = PrekeyStore::load_checked(data_dir)?;
    if !local_prekey_rotation_due(&store, &identity_pub, now_ms()) {
        seed_published_prekey_archive(data_dir, &identity_pub);
        return Ok(());
    }
    // Every inbound connection (and ash) can arrive the moment rotation becomes
    // due. Serialize on the shared prekey-store lock, recover an interrupted
    // cache stage like every other writer of prekey_store.json (a pending stage
    // would otherwise be replayed over the store saved below), and re-check:
    // the winner of the race has already published.
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let now = now_ms();
    let store = PrekeyStore::load_checked(data_dir)?;
    if !local_prekey_rotation_due(&store, &identity_pub, now) {
        return Ok(());
    }
    match rotate_local_prekey_locked(data_dir, id, store, now) {
        Ok(()) => Ok(()),
        // Rotation was only due (the current bundle is still valid) but failed,
        // for example the actor is at MAX_PREKEY_GENERATIONS or the clock stepped
        // back behind the published bundle: keep offering the current one.
        // Failing here would fail every LAN link (`local_bundle`).
        Err(error)
            if PrekeyStore::load_checked(data_dir)?
                .fetch_valid(&identity_pub, now)
                // Never past its own expiry (fetch_valid tolerates skew).
                .is_some_and(|bundle| bundle.expires_at_ms > now) =>
        {
            note_rotation_failure(&error);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// `prekey rotation failed` on stderr at most once an hour (every link calls
/// `ensure_local_prekey`).
fn note_rotation_failure(error: &str) {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if rotation_failure_log_due(&mut last, Instant::now()) {
        eprintln!("raven: prekey rotation failed ({error}); still offering the current prekey");
    }
}

fn rotation_failure_log_due(last: &mut Option<Instant>, now: Instant) -> bool {
    let due = last.is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(3600));
    if due {
        *last = Some(now);
    }
    due
}

/// Rotate this device's signed prekey now, however young the current one
/// is (Phase 6b R3, step P6.27: this computer's protected state looked
/// rolled back, so whoever copied it may hold the current prekey's secret).
/// The same path as a due rotation ([`ensure_local_prekey`]), under the
/// shared prekey-store lock; contacts pick the new bundle up from the next
/// offer. `why` is a fixed code for the one log line (never a key or an
/// address). An error leaves the current prekey offered (the lifecycle
/// keeps at most `MAX_PREKEY_GENERATIONS`; the caller bounds how often it
/// asks).
pub fn rotate_local_prekey_now(
    data_dir: &Path,
    id: &Identity,
    why: &'static str,
) -> Result<(), String> {
    let _ = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID)?;
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let store = PrekeyStore::load_checked(data_dir)?;
    rotate_local_prekey_locked(data_dir, id, store, now_ms())?;
    eprintln!("raven: rotated this computer's prekey early ({why})");
    Ok(())
}

/// Rotate the local prekey under `PEER_CACHE_LOCK` (held by the caller).
fn rotate_local_prekey_locked(
    data_dir: &Path,
    id: &Identity,
    mut store: PrekeyStore,
    now: u64,
) -> Result<(), String> {
    let identity_pub = id.public_key_bytes();
    let mut rng = rand::thread_rng();
    let mut kp = HybridKeypair::generate(&mut rng);
    let actor = PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    // Never reuse an id already published for us: after lifecycle state loss
    // the actor's counter restarts below the id our store still pins, and a
    // lower or equal id is refused as rollback/equivocation on every retry.
    let published_id = store
        .fetch_valid(&identity_pub, now)
        .map_or(0, |bundle| bundle.signed_prekey_id);
    let next_id = crate::prekey_lifecycle::next_signed_prekey_id(
        actor
            .status()
            .map_err(|e| e.to_string())?
            .highest_signed_prekey_id,
        published_id,
        0,
        now,
    )
    .map_err(|e| e.to_string())?;
    let bundle = PrekeyBundle::from_hybrid_public(
        PRIMARY_DEVICE_ID,
        kp.x25519_public,
        kp.mlkem_ek_bytes.clone(),
        next_id,
        now,
        now.saturating_add(30 * 24 * 3600 * 1000),
    )?
    .sign(id)?;
    // Installing the generation is durable and irreversible, and the actor
    // retains at most `MAX_PREKEY_GENERATIONS`. Refuse a bundle the store would
    // reject (rollback/equivocation against a desynced store) *before*
    // installing, so retries cannot burn the cap on a generation that can never
    // be published. The private key must stay durable before the bundle is
    // public, so publishing first is not an option. The archive of published
    // bundles must be writable too (a sealed one that does not open is never
    // written over), and it holds the bundle before the store offers it.
    store.clone().publish(&bundle, now)?;
    load_published_prekey_archive_for_write(data_dir)?;
    actor
        .rotate_generation(
            std::slice::from_ref(&bundle),
            PrekeyGenerationPrivate::new(kp.x25519_secret, kp.mlkem_seed, vec![]),
            now,
        )
        .map_err(|e| e.to_string())?;
    kp.x25519_secret.zeroize();
    archive_published_prekey_locked(data_dir, &bundle, now)?;
    store.publish(&bundle, now)?;
    store.save(data_dir)?;
    Ok(())
}

/// `prekey_published_local.json`: this device's own signed bundles as
/// published, newest last.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PublishedPrekeyArchive {
    bundles: Vec<PrekeyBundleJson>,
}

fn published_prekey_archive_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(PREKEY_PUBLISHED_LOCAL_FILE)
}

/// Whether an archived bundle may still name a letter's generation: its
/// signature verifies and `now` is at most its expiry plus
/// [`PREKEY_RETENTION_GRACE_MS`], the prekey lifecycle actor's
/// `destroy_after_ms` for it.
fn archived_bundle_retained(bundle: &PrekeyBundle, now: u64) -> bool {
    bundle.verify(bundle.created_at_ms).is_ok()
        && bundle
            .expires_at_ms
            .checked_add(PREKEY_RETENTION_GRACE_MS)
            .is_some_and(|destroy_after| now <= destroy_after)
}

/// The archive to change: empty when it is missing or holds plain bytes that
/// do not parse (rewritten whole); an error for a sealed file this process
/// cannot open, which is never written over.
fn load_published_prekey_archive_for_write(
    data_dir: &Path,
) -> Result<PublishedPrekeyArchive, String> {
    crate::at_rest::load_json_for_write(
        data_dir,
        &published_prekey_archive_path(data_dir),
        Kind::PrekeyPublishedLocal,
    )
    .map_err(|e| format!("{PREKEY_PUBLISHED_LOCAL_FILE}: {e}"))
}

/// Add one of this device's own bundles to the archive, as it is published.
/// Bundles past their expiry plus grace, of another identity, or not
/// verifying are dropped; at most [`MAX_PREKEY_GENERATIONS`] stay (the
/// actor's own bound), the highest `signed_prekey_id`s. The caller holds
/// `PEER_CACHE_LOCK`; the write is atomic (RMS1 in a sealed profile).
fn archive_published_prekey_locked(
    data_dir: &Path,
    bundle: &PrekeyBundle,
    now: u64,
) -> Result<(), String> {
    bundle.verify(now)?;
    let digest = prekey_bundle_hash(bundle).map_err(|e| e.to_string())?;
    let archive = load_published_prekey_archive_for_write(data_dir)?;
    let mut kept: Vec<PrekeyBundle> = archive
        .bundles
        .iter()
        .filter_map(|json| PrekeyBundle::from_json(json).ok())
        .filter(|old| {
            old.identity_ed25519_pub == bundle.identity_ed25519_pub
                && archived_bundle_retained(old, now)
                && prekey_bundle_hash(old).is_ok_and(|old_digest| old_digest != digest)
        })
        .collect();
    kept.push(bundle.clone());
    kept.sort_by_key(|kept| (kept.signed_prekey_id, kept.created_at_ms));
    let excess = kept.len().saturating_sub(MAX_PREKEY_GENERATIONS);
    kept.drain(..excess);
    let archive = PublishedPrekeyArchive {
        bundles: kept.iter().map(PrekeyBundle::to_json).collect(),
    };
    let bytes = serde_json::to_vec_pretty(&archive).map_err(|e| e.to_string())?;
    write_peer_cache_file(
        data_dir,
        &published_prekey_archive_path(data_dir),
        Kind::PrekeyPublishedLocal,
        &bytes,
    )
}

/// A profile whose current bundle was published before the archive existed
/// gets it archived once, at the first [`ensure_local_prekey`] that finds no
/// archive file (one stat per call after that). Best effort: a failure here
/// never fails a link; a letter to that bundle is then refused as
/// `LETTER_UNKNOWN_PREKEY` until the next rotation archives its successor.
fn seed_published_prekey_archive(data_dir: &Path, identity_pub: &[u8; 32]) {
    let path = published_prekey_archive_path(data_dir);
    if std::fs::symlink_metadata(&path).is_ok() {
        return;
    }
    let _ = with_prekey_store_lock(data_dir, || {
        if std::fs::symlink_metadata(&path).is_ok() {
            return Ok(());
        }
        let now = now_ms();
        match PrekeyStore::load_checked(data_dir)?.fetch_valid(identity_pub, now) {
            Some(bundle) => archive_published_prekey_locked(data_dir, &bundle, now),
            None => Ok(()),
        }
    });
}

/// One of this device's own published bundles by its `prekey_bundle_hash`
/// (the hash a letter names in `wrap_bundle_hash`, and its PairInit in
/// `responder_prekey_bundle_hash`), while `now` is at most its expiry plus
/// [`PREKEY_RETENTION_GRACE_MS`]. Unlike the prekey store, which keeps only
/// the current bundle, this still finds a generation retired since. `None`
/// when no retained bundle has that hash; an error when the archive cannot
/// be read (a sealed one that does not open: fail closed).
pub fn local_published_bundle_by_hash(
    data_dir: &Path,
    bundle_hash: &[u8; 32],
    now: u64,
) -> Result<Option<PrekeyBundle>, String> {
    let path = published_prekey_archive_path(data_dir);
    let archive = match crate::at_rest::load_json_advisory::<PublishedPrekeyArchive>(
        data_dir,
        &path,
        Kind::PrekeyPublishedLocal,
    ) {
        crate::at_rest::Advisory::Loaded(archive) => archive,
        crate::at_rest::Advisory::Missing | crate::at_rest::Advisory::CorruptPlain => {
            return Ok(None)
        }
        crate::at_rest::Advisory::Unreadable(e) => {
            return Err(format!("{PREKEY_PUBLISHED_LOCAL_FILE}: {e}"))
        }
    };
    Ok(archive
        .bundles
        .iter()
        .filter_map(|json| PrekeyBundle::from_json(json).ok())
        .find(|bundle| {
            prekey_bundle_hash(bundle).is_ok_and(|digest| &digest == bundle_hash)
                && archived_bundle_retained(bundle, now)
        }))
}

pub fn local_bundle(data_dir: &Path, id: &Identity) -> Result<LanBundle, String> {
    ensure_local_prekey(data_dir, id)?;
    let (cert, _) = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID)?;
    let now = now_ms();
    let store = PrekeyStore::load_checked(data_dir)?;
    let prekey = store
        .fetch(&id.public_key_bytes(), now)?
        .ok_or_else(|| "local prekey missing after ensure".to_string())?;
    Ok(LanBundle { cert, prekey })
}

/// Exactly one identity per connection: the Noise-bound key must be both the
/// certificate's device key and its signer (see [`verify_lan_bundle`]).
pub fn rlb1_matches_noise_identity(peer: &LanBundle, noise_ed: &[u8; 32]) -> bool {
    peer.cert.device_ed_pub == *noise_ed && peer.cert.user_ed_pub == *noise_ed
}

pub fn lan_peer_blocked(
    data_dir: &Path,
    peer: &LanBundle,
    noise_ed: &[u8; 32],
) -> Result<bool, String> {
    let blocks = BlockList::load_checked(data_dir)?;
    Ok(blocks.is_blocked(&hex::encode(noise_ed))
        || blocks.is_blocked(&hex::encode(peer.cert.user_ed_pub))
        || blocks.is_blocked(&hex::encode(peer.cert.device_ed_pub)))
}

fn pair_revocation(
    data_dir: &Path,
    local_registry: &DeviceRegistry,
    local_role: LocalRole,
    initiator_cert: &DeviceCertificate,
    responder_cert: &DeviceCertificate,
) -> Result<(bool, bool), String> {
    let rev = RevocationStore::load_checked(data_dir)?;
    // DeviceRegistry is local-identity-scoped. Apply it only to the local role's
    // side — never by comparing device_id strings (both peers are often ash-primary).
    let initiator_revoked = identity_denies_device_lineage(
        &rev,
        local_registry,
        initiator_cert,
        local_role == LocalRole::Initiator,
    )?;
    let responder_revoked = identity_denies_device_lineage(
        &rev,
        local_registry,
        responder_cert,
        local_role == LocalRole::Responder,
    )?;
    Ok((initiator_revoked, responder_revoked))
}

/// The folder of the responder's cached PairResponses.
const PAIR_RESPONSE_DIR: &str = "lan_pair_response";
/// Their writer lock (RMS1 kind [`Kind::PairResponse`]).
pub(crate) const PAIR_RESPONSE_LOCK: &str = ".at_rest.pair_response.lock.sqlite";

/// The cached PairResponse of the PairInit `init_id`. In a sealed profile it
/// is named by the init_id's keyed lookup (the session store's `kh_init_id`,
/// 64 hex) and sealed (RMS1 [`Kind::PairResponse`]): neither its name nor
/// its bytes give the init_id, which with the store's clear record key would
/// name the friend, nor the session's exact times (review B-sealed-stores-1
/// and -5). A plain profile names it by the init_id in hex, as before. The
/// key must be loaded in a sealed profile.
fn cached_pair_response_path(
    data_dir: &Path,
    init_id: &[u8; 16],
) -> Result<std::path::PathBuf, String> {
    use crate::at_rest::{self, Mode, ValueType};
    let name = match crate::privacy::mode(data_dir) {
        Mode::Sealed => {
            let keys = at_rest::keys_cached(data_dir).map_err(|e| e.to_string())?;
            hex::encode(at_rest::index(&keys, ValueType::Nonce, init_id))
        }
        Mode::Plain | Mode::UnsealedByUser => hex::encode(init_id),
    };
    Ok(data_dir.join(PAIR_RESPONSE_DIR).join(name))
}

fn verify_cached_pair_response_bytes(
    packed: &[u8],
    init: &PairInit,
    local_device_ed: &[u8; 32],
) -> Result<Vec<u8>, String> {
    if packed.is_empty() {
        return Err("pair response cache empty".into());
    }
    let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(packed) else {
        return Err("pair response cache is not PairResponse OOB".into());
    };
    let response =
        decode_response(&wire).map_err(|e| format!("pair response cache decode: {e}"))?;
    let digest = init_hash(init).map_err(|e| format!("{e}"))?;
    if response.init_id != init.init_id {
        return Err("pair response cache init_id mismatch".into());
    }
    if response.init_hash != digest {
        return Err("pair response cache init_hash mismatch".into());
    }
    if &response.responder_device_ed_pub != local_device_ed {
        return Err("pair response cache responder mismatch".into());
    }
    let signing = response_signing_bytes(&response).map_err(|e| format!("{e}"))?;
    if !Identity::verify(
        &response.responder_device_ed_pub,
        &signing,
        &response.signature,
    ) {
        return Err("pair response cache bad signature".into());
    }
    Ok(packed.to_vec())
}

fn load_verified_cached_pair_response(
    data_dir: &Path,
    init: &PairInit,
    local_device_ed: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let unavailable = || "pair response unavailable for retry".to_string();
    let path = cached_pair_response_path(data_dir, &init.init_id)?;
    let bytes = match crate::at_rest::load_bytes(data_dir, &path, Kind::PairResponse) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(unavailable()),
        // A sealed copy that does not open (a changed byte, an epoch no key
        // holds any more) is as good as none.
        Err(_) => {
            let _ = std::fs::remove_file(&path);
            return Err(unavailable());
        }
    };
    match verify_cached_pair_response_bytes(&bytes, init, local_device_ed) {
        Ok(v) => Ok(v),
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            Err(e)
        }
    }
}

/// Cache `packed`, the PairResponse to the PairInit `init_id`, under its
/// writer lock: sealed in a sealed profile ([`cached_pair_response_path`]).
fn store_cached_pair_response(
    data_dir: &Path,
    init_id: &[u8; 16],
    packed: &[u8],
) -> Result<(), String> {
    let path = cached_pair_response_path(data_dir, init_id)?;
    crate::at_rest::store_bytes(data_dir, &path, Kind::PairResponse, packed)
        .map_err(|e| e.to_string())
}

pub fn encode_local_offer(data_dir: &Path, id: &Identity) -> Result<Vec<u8>, String> {
    encode_offer(&local_bundle(data_dir, id)?)
}

/// The durable certificate cache, sealed or plain; missing is empty.
fn load_peer_cert_map_checked(
    data_dir: &Path,
) -> Result<HashMap<String, DeviceCertificate>, String> {
    let path = data_dir.join(PEER_CERT_CACHE);
    let raw = match crate::at_rest::load_bytes(data_dir, &path, Kind::PeerDeviceCerts) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Ok(HashMap::new()),
        Err(e) if e.is_unavailable() => return Err(format!("peer cert cache read: {e}")),
        Err(e) => return Err(format!("peer cert cache corrupt: {e}")),
    };
    serde_json::from_slice(&raw).map_err(|e| format!("peer cert cache corrupt: {e}"))
}

/// Write one of the peer cache's files (RMS1 in a sealed profile). The
/// caller holds `PEER_CACHE_LOCK`.
fn write_peer_cache_file(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
    bytes: &[u8],
) -> Result<(), String> {
    crate::at_rest::write_held(data_dir, path, kind, bytes).map_err(|e| e.to_string())
}

#[derive(Debug, Serialize, Deserialize)]
struct PeerCacheStage {
    generation: u64,
    certs_json: String,
    prekey_json: String,
}

fn peer_cache_stage_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(PEER_CACHE_STAGE)
}

fn peer_cache_gen_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("peer_cache.generation")
}

fn read_committed_peer_cache_generation(data_dir: &Path) -> Result<u64, String> {
    let path = peer_cache_gen_path(data_dir);
    if !path.exists() {
        return Ok(0);
    }
    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("peer_cache.generation read: {e}"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("peer_cache.generation empty".into());
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| "peer_cache.generation corrupt".to_string())
}

fn write_committed_peer_cache_generation(data_dir: &Path, generation: u64) -> Result<(), String> {
    if generation == 0 {
        return Err("peer_cache.generation refuse zero".into());
    }
    crate::paths::atomic_write_private(
        &peer_cache_gen_path(data_dir),
        format!("{generation}\n").as_bytes(),
    )
}

/// A durable peer-cert entry is usable only when it is keyed by its verified
/// signer, self-certified, and inside its validity window.
fn durable_peer_cert_entry_valid(key: &str, cert: &DeviceCertificate, now: u64) -> bool {
    cert.device_ed_pub == cert.user_ed_pub
        && *key == hex::encode(cert.user_ed_pub)
        && cert.verify(now).is_ok()
}

/// Verify stage payloads, drop expired/unbound entries, return sanitized
/// cert/prekey JSON. Entries are pruned individually so one stale contact
/// cannot block persistence for every other contact.
fn sanitize_peer_cache_stage_payloads(
    stage: &PeerCacheStage,
    now: u64,
) -> Result<(String, String), String> {
    if stage.generation == 0 {
        return Err("peer cache stage generation missing".into());
    }
    let mut map: HashMap<String, DeviceCertificate> = serde_json::from_str(&stage.certs_json)
        .map_err(|e| format!("peer cache stage certs corrupt: {e}"))?;
    let mut store: PrekeyStore = serde_json::from_str(&stage.prekey_json)
        .map_err(|e| format!("peer cache stage prekey corrupt: {e}"))?;
    let _ = store.retain_valid(now);
    if store.is_empty() {
        return Err("peer cache stage prekey empty after expiry prune".into());
    }
    // Every peer cert must have a currently valid prekey bound to the same
    // identity and device_id; local/other identities may coexist in the shared
    // prekey_store.json without a peer cert entry.
    map.retain(|key, cert| {
        durable_peer_cert_entry_valid(key, cert, now)
            && matches!(
                store.fetch(&cert.user_ed_pub, now),
                Ok(Some(prekey)) if prekey.device_id == cert.device_id
            )
    });
    if map.is_empty() {
        return Err("peer cache stage certs empty after expiry prune".into());
    }
    let certs_json = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
    let prekey_json = serde_json::to_string_pretty(&store).map_err(|e| e.to_string())?;
    Ok((certs_json, prekey_json))
}

/// Move an unusable cache file aside (kept for inspection, one copy) so it
/// stops failing every cache operation; falls back to removal.
fn quarantine_peer_cache_file(path: &Path) -> Result<(), String> {
    let mut aside = path.as_os_str().to_owned();
    aside.push(".corrupt");
    let aside = std::path::PathBuf::from(aside);
    // Windows refuses to rename over a leftover from an earlier quarantine.
    let _ = std::fs::remove_file(&aside);
    if std::fs::rename(path, &aside).is_ok() {
        return Ok(());
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("peer cache quarantine {}: {e}", path.display())),
    }
}

/// An empty or non-numeric `peer_cache.generation` cannot order a stage against
/// the committed files, and would fail every cache operation until deleted by
/// hand. The committed cert/prekey files are the source of truth and the stage
/// is only a replayable snapshot of them, so quarantine the counter together
/// with any stage; the next commit restarts it from `now_ms()`.
fn heal_corrupt_peer_cache_generation(data_dir: &Path) -> Result<(), String> {
    let path = peer_cache_gen_path(data_dir);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        // Not UTF-8: corrupt, not an I/O fault.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => String::new(),
        Err(e) => return Err(format!("peer_cache.generation read: {e}")),
    };
    if raw.trim().parse::<u64>().is_ok() {
        return Ok(());
    }
    quarantine_peer_cache_file(&path)?;
    let stage_path = peer_cache_stage_path(data_dir);
    if stage_path.exists() {
        quarantine_peer_cache_file(&stage_path)?;
    }
    Ok(())
}

/// Finish or discard an interrupted cert+prekey dual write.
///
/// An unparseable stage (a sealed one that does not open with this
/// profile's key included), or a corrupt generation counter, is quarantined
/// and treated as "nothing to replay" instead of failing every caller until
/// someone deletes the file by hand. A sealed stage this process cannot open
/// yet (the at-rest key not loaded) is kept for the next try. The stage and
/// the files it replays into are sealed in a sealed profile (PP.5).
fn recover_peer_cache_stage(data_dir: &Path) -> Result<(), String> {
    heal_corrupt_peer_cache_generation(data_dir)?;
    let stage_path = peer_cache_stage_path(data_dir);
    let raw = match crate::at_rest::load_bytes(data_dir, &stage_path, Kind::PeerCacheStage) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Ok(()),
        Err(e) if e.is_unavailable() => return Err(format!("peer cache stage read: {e}")),
        Err(_) => return quarantine_peer_cache_file(&stage_path),
    };
    let Ok(stage) = serde_json::from_slice::<PeerCacheStage>(&raw) else {
        return quarantine_peer_cache_file(&stage_path);
    };
    let committed = read_committed_peer_cache_generation(data_dir)?;
    if stage.generation < committed {
        // Stale stage from an older writer — discard.
        std::fs::remove_file(&stage_path)
            .map_err(|e| format!("peer cache stale stage remove: {e}"))?;
        return Ok(());
    }
    let now = now_ms();
    let (certs_json, prekey_json) = match sanitize_peer_cache_stage_payloads(&stage, now) {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&stage_path);
            return Err(e);
        }
    };
    write_peer_cache_file(
        data_dir,
        &data_dir.join(PEER_CERT_CACHE),
        Kind::PeerDeviceCerts,
        certs_json.as_bytes(),
    )?;
    #[cfg(test)]
    peer_cache_replay_crash(1)?;
    write_peer_cache_file(
        data_dir,
        &PrekeyStore::path(data_dir),
        Kind::PrekeyStore,
        prekey_json.as_bytes(),
    )?;
    #[cfg(test)]
    peer_cache_replay_crash(2)?;
    write_committed_peer_cache_generation(data_dir, stage.generation)?;
    #[cfg(test)]
    peer_cache_replay_crash(3)?;
    std::fs::remove_file(&stage_path).map_err(|e| format!("peer cache stage remove: {e}"))?;
    Ok(())
}

fn commit_peer_cache_pair(
    data_dir: &Path,
    certs_bytes: &[u8],
    prekey_bytes: &[u8],
) -> Result<(), String> {
    recover_peer_cache_stage(data_dir)?;
    let committed = read_committed_peer_cache_generation(data_dir)?;
    let generation = now_ms().max(committed.saturating_add(1)).max(1);
    let stage = PeerCacheStage {
        generation,
        certs_json: String::from_utf8(certs_bytes.to_vec())
            .map_err(|_| "peer cache certs utf8".to_string())?,
        prekey_json: String::from_utf8(prekey_bytes.to_vec())
            .map_err(|_| "peer cache prekey utf8".to_string())?,
    };
    let (certs_json, prekey_json) = sanitize_peer_cache_stage_payloads(&stage, now_ms())?;
    let stage = PeerCacheStage {
        generation,
        certs_json,
        prekey_json,
    };
    let stage_bytes = serde_json::to_vec_pretty(&stage).map_err(|e| e.to_string())?;
    write_peer_cache_file(
        data_dir,
        &peer_cache_stage_path(data_dir),
        Kind::PeerCacheStage,
        &stage_bytes,
    )?;
    #[cfg(test)]
    if FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.get()) {
        return Err("injected peer cache stage failure".into());
    }
    recover_peer_cache_stage(data_dir)?;
    Ok(())
}

/// Shared lock for prekey_store.json / peer cache mutations (ash + node).
pub fn with_prekey_store_lock<F, T>(data_dir: &Path, f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    f()
}

/// [`publish_prekey_bundle_checked`] for one of this device's own bundles,
/// whose private half the prekey lifecycle actor already holds: also kept in
/// the archive of published bundles ([`local_published_bundle_by_hash`]),
/// under the same lock, before the store offers it.
pub fn publish_local_prekey_bundle_checked(
    data_dir: &Path,
    bundle: &PrekeyBundle,
    now: u64,
) -> Result<(), String> {
    with_prekey_store_lock(data_dir, || {
        let mut store = PrekeyStore::load_checked(data_dir)?;
        store.publish(bundle, now)?;
        archive_published_prekey_locked(data_dir, bundle, now)?;
        store.save(data_dir)
    })
}

/// Fail-closed load + publish + atomic save under the shared prekey lock.
pub fn publish_prekey_bundle_checked(
    data_dir: &Path,
    bundle: &PrekeyBundle,
    now: u64,
) -> Result<(), String> {
    with_prekey_store_lock(data_dir, || {
        let mut store = PrekeyStore::load_checked(data_dir)?;
        store.publish(bundle, now)?;
        store.save(data_dir)
    })
}

/// Status prefix of the error [`persist_trusted_peer_bundle`] returns when the
/// durable prekey pin refuses a verified bundle of a contact as a rollback or
/// equivocation (lower or equal `signed_prekey_id`): the contact reinstalled or
/// reset its prekey counter while this node still pins its old bundle.
pub const PEER_PREKEY_RESET: &str = "PEER_PREKEY_RESET";

fn peer_prekey_policy_error(peer_user_pub: &[u8; 32], err: String) -> String {
    if err == "PREKEY_ROLLBACK" || err == "PREKEY_EQUIVOCATION" {
        format!(
            "{PEER_PREKEY_RESET}: contact {} offered a prekey the pinned bundle refuses ({err}); \
             it reinstalled or reset. No new session is started on it. To accept it now, \
             verify the contact's fingerprint out of band, then `ash contact remove` it and \
             add it again; otherwise this clears when the old pinned prekey expires",
            hex::encode(&peer_user_pub[..4])
        )
    } else {
        err
    }
}

/// Forget the durable prekey pin of a contact: the explicit re-pin behind
/// `ash contact remove`. A contact that reinstalled (counter reset) is refused by
/// the pin ([`PEER_PREKEY_RESET`]) until the old pinned bundle expires; the user
/// can deliberately drop the pin, after verifying the contact's fingerprint out
/// of band, and the next offer is pinned afresh. Never reachable from the network.
/// `Ok(true)` when a pin was removed.
pub fn forget_peer_prekey_pin(data_dir: &Path, peer_user_pub: &[u8; 32]) -> Result<bool, String> {
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let mut store = PrekeyStore::load_checked(data_dir)?;
    if !store.remove(peer_user_pub) {
        return Ok(false);
    }
    // One atomic file write. A cert cache entry left without its prekey is
    // already treated as absent by every reader and pruned at the next commit.
    store.save(data_dir)?;
    Ok(true)
}

/// A new session may only start on a prekey bundle the durable pin would accept.
///
/// [`cache_peer_bundle`] keeps a *connection* to a contact that reinstalled
/// working (the offer is verified, bound to the peer's identity, and a refused
/// durable pin is only reported), and existing sessions never needed the prekey.
/// But PairInit encapsulates to the offered prekey, so a rolled-back or
/// equivocating bundle (lower id, or same id with other keys) must not seed a
/// new session unless the user explicitly re-pinned (see
/// [`forget_peer_prekey_pin`]) or the pinned bundle expired. Dry run on a copy of
/// the store: nothing is written here.
fn require_prekey_acceptable_to_pin(
    data_dir: &Path,
    peer: &LanBundle,
    now: u64,
) -> Result<(), String> {
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let mut store = PrekeyStore::load_checked(data_dir)?;
    let _ = store.retain_valid(now);
    store
        .publish(&peer.prekey, now)
        .map_err(|e| peer_prekey_policy_error(&peer.cert.user_ed_pub, e))
}

/// Persist cert+prekey for a **contact-trusted** peer via a crash-recoverable stage.
///
/// The bundle is verified before anything is cached. The durable entry is keyed
/// only by the verified signer (`user_ed_pub`, equal to `device_ed_pub`), so a
/// contact owns exactly one cert slot and one prekey slot; entries for peers
/// that are no longer contacts are pruned instead of counting against a
/// global cap.
pub fn persist_trusted_peer_bundle(data_dir: &Path, bundle: &LanBundle) -> Result<(), String> {
    let now = now_ms();
    verify_lan_bundle(bundle, now)?;
    let contacts = contact_pub_set(data_dir)?;
    let user_key = hex::encode(bundle.cert.user_ed_pub);
    if !contacts.contains(&user_key) {
        return Err("refusing durable peer cache for untrusted peer".into());
    }
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let mut map = load_peer_cert_map_checked(data_dir)?;
    map.retain(|key, cert| durable_peer_cert_entry_valid(key, cert, now) && contacts.contains(key));
    map.insert(user_key, bundle.cert.clone());
    let mut store = PrekeyStore::load_checked(data_dir)?;
    let _ = store.retain_valid(now);
    store
        .publish(&bundle.prekey, now)
        .map_err(|e| peer_prekey_policy_error(&bundle.cert.user_ed_pub, e))?;
    let certs_bytes = serde_json::to_string_pretty(&map)
        .map_err(|e| e.to_string())?
        .into_bytes();
    let prekey_bytes = serde_json::to_string_pretty(&store)
        .map_err(|e| e.to_string())?
        .into_bytes();
    commit_peer_cache_pair(data_dir, &certs_bytes, &prekey_bytes)?;
    remember_ephemeral_peer(data_dir, bundle)?;
    Ok(())
}

/// Remember peer for this process; durable write only when in the local contact book.
/// Signatures and validity are verified before either cache is touched.
///
/// A contact that reset its prekey counter (reinstall, data wipe) is refused by
/// the durable pin ([`PEER_PREKEY_RESET`]). That must not drop the *connection*
/// (existing sessions never needed the prekey), so it is reported on stderr and
/// this still returns `Ok`. But the refused bundle is **not** remembered, and
/// [`create_initiator_pair_init`] re-checks the pin: it is never used to start a
/// new session unless the user explicitly re-pins ([`forget_peer_prekey_pin`]) or
/// the pinned bundle expires. That refusal is `SEC_PREKEY_ROLLBACK` about the
/// contact (Phase 6b S12).
pub fn cache_peer_bundle(data_dir: &Path, bundle: &LanBundle) -> Result<(), String> {
    verify_lan_bundle(bundle, now_ms())?;
    if peer_is_trusted(data_dir, bundle)? {
        // The durable pin decides first: only an accepted bundle is remembered
        // (`persist_trusted_peer_bundle` does that itself once it committed).
        return match persist_trusted_peer_bundle(data_dir, bundle) {
            Ok(()) => Ok(()),
            Err(e) if e.starts_with(PEER_PREKEY_RESET) => {
                eprintln!("raven: {e}");
                security_sense::contact(
                    SecKind::PrekeyRollback,
                    &bundle.cert.user_ed_pub,
                    Via::Local,
                );
                Ok(())
            }
            Err(e) => Err(e),
        };
    }
    remember_ephemeral_peer(data_dir, bundle)
}

/// A contact that dialled us: keep its certificate durably when none is kept
/// yet, so what it leaves with a friend (friend custody) can still be checked
/// against the session after this node restarts (the in-memory copy lasts
/// 15 minutes). Never replaces a kept certificate or prekey pin: that stays
/// the dialling side's [`cache_peer_bundle`]. `true` when it wrote.
pub fn remember_inbound_contact(data_dir: &Path, bundle: &LanBundle) -> Result<bool, String> {
    if !peer_is_trusted(data_dir, bundle)? {
        return Ok(false);
    }
    if load_durable_peer_cert_raw(data_dir, &bundle.cert.user_ed_pub)?.is_some() {
        return Ok(false);
    }
    cache_peer_bundle(data_dir, bundle).map(|()| true)
}

pub fn parse_peer_offer(bytes: &[u8]) -> Result<LanBundle, String> {
    decode_offer(bytes)
}

/// How long a cached PairResponse is kept after it was written: an exact
/// retry of its PairInit gets the same response (a PairInit travels only on
/// a direct dial, never through a relay, and is retried only within that
/// dial: seconds, a few minutes at most). Then it goes, whether its session
/// lives or not, so neither its name nor its time stays on the disk for the
/// session's life (review B-sealed-stores-5); raven-node prunes every 10
/// minutes. The daemon and ash both prune, unlocked: the same age spares an
/// atomic-write temp file (`.<name>.tmp.<rand>`) another thread or process
/// may still be writing.
const PAIR_RESPONSE_KEEP: Duration = Duration::from_secs(10 * 60);

fn prune_lan_pair_response_files(data_dir: &Path) -> Result<usize, String> {
    let plain = remove_plain_pair_responses(data_dir);
    // The age is measured against modification times the OS stamps with its
    // own clock, never the lab clock: a lab offset would age a file another
    // process is still writing.
    Ok(plain + prune_lan_pair_response_files_at(data_dir, crate::clock::system_now())?)
}

/// In a sealed profile, every cached PairResponse named by its init_id in
/// hex (an older build's, or this build's from before the profile was
/// sealed) goes at once, whatever its age: its name and its bytes give the
/// init_id that, with the session store's record key, names the friend
/// (review B-sealed-stores-1). Nothing writes that name in a sealed profile,
/// and the node's restart ended every dial a retry of it could serve.
/// Nothing to do in a profile that is not sealed, which names them so
/// itself. How many went.
pub(crate) fn remove_plain_pair_responses(data_dir: &Path) -> usize {
    if crate::privacy::mode(data_dir) != crate::at_rest::Mode::Sealed {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(data_dir.join(PAIR_RESPONSE_DIR)) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let plain_name = entry.file_name().to_str().is_some_and(|name| {
            name.len() == 32 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        });
        if plain_name
            && entry.file_type().is_ok_and(|t| t.is_file())
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

fn prune_lan_pair_response_files_at(
    data_dir: &Path,
    now: std::time::SystemTime,
) -> Result<usize, String> {
    let dir = data_dir.join(PAIR_RESPONSE_DIR);
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("lan_pair_response read: {e}"))? {
        // A concurrent pruner may have removed the entry already.
        let Ok(entry) = entry else {
            continue;
        };
        // Responses past their retry window, leftover temp files and stray
        // names alike, once nobody can still be writing them. An unreadable
        // or future mtime counts as young.
        let aged = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= PAIR_RESPONSE_KEEP);
        if !aged {
            continue;
        }
        // Best effort: pruning is housekeeping and must not fail PairInit or
        // maintenance (NotFound is a lost race; Windows refuses open files).
        if std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Drop expired lifecycle claims, expired SQLite sessions, and pair-response
/// files past their retry window.
fn prune_lan_durable_state(data_dir: &Path, now: u64) -> Result<(), String> {
    let actor = PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    let _ = actor.prune_expired(now).map_err(|e| e.to_string())?;
    // App channel (§7.3, §7.4), best effort: committed app rows still behind a
    // pending ACK intent reach the app inbox; inbox items past their TTL turn
    // into tombstones. Neither may block the prune (the archive below does
    // the must-succeed part for expiring sessions).
    let _ = crate::app_channel::ingest_pending_committed(data_dir, now);
    if let Ok(mut sessions) = IndexedSessionStore::open(data_dir) {
        // Before any session is destroyed, so delivered/expired is still known.
        let _ = crate::app_channel::reconcile_app_outbound(data_dir, &sessions, now);
        let _ = settle_outbound_of_ended_sessions(data_dir, &mut sessions, now);
    }
    if crate::app_store::app_store_path(data_dir).exists() {
        if let Ok(mut store) =
            crate::app_store::AppStore::open(data_dir, &crate::app_store::MetadataOnly)
        {
            let _ = store.maintain(now);
        }
    }
    // Friend custody (custodian side, §6.6), best effort: expired objects,
    // and those of parties that are no longer pinned contacts, go.
    let _ = crate::friend_custody::maintain(data_dir, now);
    // Custody handoff (Phase 5 P5.19), best effort and only if its store
    // exists: expired rows, and those of parties no longer pinned, go.
    let _ = crate::custody_handoff::maintain(data_dir, now);
    // Archive sealed inbox plaintext into ChatHistory (app frames into the app
    // inbox) before session roots are destroyed.
    archive_expired_inbox_to_history(data_dir, now)?;
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    // A removed contact added back is no longer erased: the end of a session
    // it goes on using is remembered again (review FU-5). An unreadable book
    // keeps every mark (erase wins). Best effort.
    if let Ok(contacts) = contact_pub_set(data_dir) {
        let _ = sessions.readmit_session_ends(&contacts);
    }
    let _ = sessions
        .prune_expired_sessions(now)
        .map_err(|e| e.redacted_display())?;
    // Session renewal's per-contact state (Phase 3 item 4), best effort: it
    // never fails the prune.
    let _ = sessions.prune_renewal_state(now);
    let _ = prune_lan_pair_response_files(data_dir)?;
    Ok(())
}

/// Operational maintenance for LAN durable state (listener preflight / PairInit).
pub fn maintain_lan_durable_state(data_dir: &Path) -> Result<(), String> {
    reconcile_outbound_stage_history(data_dir)?;
    prune_lan_durable_state(data_dir, now_ms())
}

/// Expiry-only pass for raven-node's periodic service prune: destroys expired
/// sessions (protected `K_root`, outbox envelopes and inbox rows, after the
/// inbox is archived to ChatHistory), expired prekey claims and pair-response
/// files past their retry window. Unlike [`maintain_lan_durable_state`] it leaves the
/// outbound stage of live sessions alone (it settles only the messages of the
/// sessions it destroys, which no send can still seal under), so it is safe
/// while `ash` sends are in flight.
///
/// Then, whatever that pass did, friends' addresses unused for 30 days and
/// the routes no plan reads any more leave the disk (privacy pack PP.7,
/// [`crate::privacy::forget_stale_addresses`]), and so do chats older than
/// the user's setting (PP.9, [`crate::privacy::apply_retention`]). Last
/// comes a data-key rotation pass (PP.10, [`crate::privacy::rotate_data_key`]:
/// at most one start a day after a deletion, and the old epoch dropped once
/// its grace is over), so what went becomes unreadable with this computer's
/// keys. Each is logged as counts only.
pub fn prune_expired_lan_durable_state(data_dir: &Path) -> Result<(), String> {
    let now = now_ms();
    let pruned = prune_lan_durable_state(data_dir, now);
    let forgot = crate::privacy::forget_stale_addresses(data_dir, now);
    if forgot.removed() > 0 {
        eprintln!("raven: forgot old addresses: {forgot}");
    }
    // Chats older than the user's setting (PP.9), after the session prune
    // archived what its expired sessions held.
    match crate::privacy::apply_retention(data_dir, now) {
        Ok(went) if went.removed() > 0 => eprintln!("raven: deleted old chats: {went}"),
        Ok(_) => {}
        Err(_) => eprintln!("raven: old chats could not be deleted now; Raven tries again later"),
    }
    // After the deletions above, which mark it due (PP.10). Silent when the
    // key is not loaded yet: the next pass tries again.
    if let Ok(rotation) = crate::privacy::rotate_data_key(data_dir, now) {
        if rotation.did_anything() {
            eprintln!("raven: data key rotation: {rotation}");
        }
    }
    // The SQLite stores' keyed schemas (PP.12): a move the start could not
    // make, an older build's set-aside, a scrub a reader held up.
    let stores = crate::privacy::upkeep_stores(data_dir);
    if stores.did_anything() {
        eprintln!("raven: encrypted stores: {stores}");
    }
    pruned
}

/// How long a PairResponse to a direct link's PairInit stays valid (at most
/// the PairInit's own end).
const LINK_PAIR_RESPONSE_VALIDITY_MS: u64 = 24 * 3600 * 1000;

/// `validity_ms`: the longest the response stays valid, cut to the
/// PairInit's end ([`LINK_PAIR_RESPONSE_VALIDITY_MS`] on a link; a letter's
/// REPLY may take days to come back, [`PairOrigin::Letter`]).
fn build_pair_response(
    init: &PairInit,
    root: &[u8; 32],
    identity: &Identity,
    now: u64,
    validity_ms: u64,
) -> Result<PairResponse, String> {
    let digest = init_hash(init).map_err(|e| format!("{e}"))?;
    // The initiator's clock may run ahead of ours (verification tolerates a
    // bounded skew). A response stamped before the init it confirms is refused
    // by `verify_response`, so never go below `init.created_at_ms`.
    let created = now.max(init.created_at_ms);
    let expires = init.expires_at_ms.min(created.saturating_add(validity_ms));
    if expires <= created {
        return Err("pair response expired".into());
    }
    let mut response = PairResponse {
        init_id: init.init_id,
        init_hash: digest,
        responder_device_ed_pub: identity.public_key_bytes(),
        created_at_ms: created,
        expires_at_ms: expires,
        confirmation_tag: confirmation_tag(root, &digest),
        signature: [0u8; 64],
    };
    let signing = response_signing_bytes(&response).map_err(|e| format!("{e}"))?;
    response.signature = identity.sign(&signing);
    Ok(response)
}

/// `clock`: the contact's clock as this PairInit shows it (cutoff pack CP.7):
/// [`PeerClock::Ahead`] when it is refused while dated past the window (the
/// side value of `PairInitClockSkew` and `verify_init`'s `NotCurrentlyValid`;
/// the refusal itself is unchanged), [`PeerClock::Agrees`] when accepted.
/// `via`: the link it came on; a prekey refusal that is an event (the claim
/// quota, clock skew: Phase 6b S16, S24) is noted about the contact.
fn handle_pair_init(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    wire: &[u8],
    clock: &mut Option<PeerClock>,
    via: Via,
) -> Result<Vec<Vec<u8>>, String> {
    // Contact book is the durable trust root: strangers must not create sessions,
    // lifecycle claims, or lan_pair_response/* (claim cap is finite).
    if !peer_is_trusted(data_dir, peer)? {
        return Err("pair init refused: peer is not a local contact".into());
    }
    let init = decode_init(wire).map_err(|e| format!("pair init: {e}"))?;
    let now = now_ms();
    let mut refused_as = None;
    let result = accept_pair_init_sensed(
        data_dir,
        identity,
        peer,
        &init,
        PairOrigin::Link,
        now,
        &mut refused_as,
    )
    .map(|(_, packed)| vec![packed])
    .map_err(String::from);
    if let Some(kind) = refused_as {
        security_sense::contact(kind, &peer.cert.user_ed_pub, via);
    }
    *clock = match (&result, future_by_ms(init.created_at_ms, now)) {
        (Ok(_), _) => Some(PeerClock::Agrees),
        (Err(_), Some(ahead)) => Some(PeerClock::Ahead(ahead)),
        (Err(_), None) => None,
    };
    result
}

/// Where a PairInit reached this responder ([`accept_pair_init_core`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairOrigin {
    /// A direct link's PairInit frame (after Noise XX): the trust bundle is
    /// this device's current prekey bundle.
    Link,
    /// The PairInit of an RAL1 letter (Phase 5b; the letter intake runs this
    /// once the letter opened and its bindings held,
    /// `protocol/RAVEN_ASYNC_LETTER_V1.md`). It differs from a link's in
    /// four ways: the trust bundle is the published generation the PairInit
    /// names ([`local_published_bundle_by_hash`], one retired since still
    /// counts); a one-time prekey is refused; an initiator holds at most
    /// [`MAX_LETTER_CLAIMS_PER_INITIATOR`] live letter sessions here
    /// ([`PairAcceptError::ClaimLimit`]); the session is marked
    /// [`LetterRole::Responder`] (letter-class: ACKs only) and its
    /// PairResponse stays valid as long as the PairInit, since a REPLY
    /// letter may take days to come back.
    Letter,
}

/// Why [`accept_pair_init_core`] did not accept a PairInit. Its text is the
/// error a direct link's PairInit always gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairAcceptError {
    /// The PairInit, its trust records or its claim were refused: the same
    /// bytes never get better.
    Refused(String),
    /// [`PairOrigin::Letter`]: the initiator already holds
    /// [`MAX_LETTER_CLAIMS_PER_INITIATOR`] live letter sessions here.
    ClaimLimit,
    /// A local store failed: the same PairInit may be accepted later.
    Store(String),
}

impl std::fmt::Display for PairAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(text) | Self::Store(text) => f.write_str(text),
            Self::ClaimLimit => f.write_str(
                "letter pair init refused: the initiator holds the most letter sessions allowed",
            ),
        }
    }
}

impl From<PairAcceptError> for String {
    fn from(error: PairAcceptError) -> Self {
        error.to_string()
    }
}

impl PairAcceptError {
    /// The refusal a letter's intake reports (`RAVEN_ASYNC_LETTER_V1.md`
    /// §6): a claim limit or a store error keeps the letter at its
    /// custodian ([`crate::async_letter::Ral1Error::releases_letter`]).
    pub fn letter_code(&self) -> crate::async_letter::Ral1Error {
        use crate::async_letter::Ral1Error;
        match self {
            Self::Refused(_) => Ral1Error::PairRefused,
            Self::ClaimLimit => Ral1Error::ClaimLimit,
            Self::Store(_) => Ral1Error::Store,
        }
    }
}

/// A prekey lifecycle error: a store that failed may work later; everything
/// else refuses the PairInit.
fn claim_error(error: PrekeyLifecycleError) -> PairAcceptError {
    let text = error.to_string();
    match error {
        PrekeyLifecycleError::ProtectedStoreUnavailable
        | PrekeyLifecycleError::ProtectedStore
        | PrekeyLifecycleError::CorruptProtectedState
        | PrekeyLifecycleError::LockFailed
        | PrekeyLifecycleError::Database
        | PrekeyLifecycleError::ResourceLimit => PairAcceptError::Store(text),
        _ => PairAcceptError::Refused(text),
    }
}

fn session_store_error(error: IndexedSessionStoreError) -> PairAcceptError {
    PairAcceptError::Store(error.redacted_display())
}

/// The responder's acceptance of a contact's PairInit at `now`, for every
/// origin ([`PairOrigin`]): the trust records, the prekey claim, the
/// session, the PairResponse (wrapped as the link's OOB PairResponse,
/// cached for an exact retry), the confirmation and the claim's end, in that
/// order. `peer` is the initiator's bundle (a letter's intake passes the
/// pinned contact's). An exact replay of a PairInit already accepted gets
/// the cached PairResponse back while it is kept. Returns the session's
/// record key and the packed PairResponse.
/// The packed PairResponse that answers an exact replay of `init`: the
/// cached one (it lasts minutes), else, for a session this node accepted
/// from a letter, the one its letter row keeps, wrapped afresh (P5.15: the
/// initiator may complete a letter session directly days later by
/// replaying its PairInit).
fn replay_pair_response(
    data_dir: &Path,
    identity: &Identity,
    sessions: &IndexedSessionStore,
    init: &PairInit,
    now: u64,
) -> Result<Vec<u8>, String> {
    let cached = load_verified_cached_pair_response(data_dir, init, &identity.public_key_bytes());
    let Err(why) = cached else {
        return cached;
    };
    let Ok(sid) = session_id(init) else {
        return Err(why);
    };
    let Ok(Some(wire)) = sessions.letter_reply(&sid) else {
        return Err(why);
    };
    let mut rng = OsRng;
    let mut tag = [0u8; 16];
    rng.fill_bytes(&mut tag);
    wrap_oob_wire(
        &wire,
        PairInitOobKind::PairResponse,
        identity,
        tag,
        now,
        &mut rng,
    )
}

pub fn accept_pair_init_core(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    init: &PairInit,
    origin: PairOrigin,
    now: u64,
) -> Result<(IndexedSessionRecordKey, Vec<u8>), PairAcceptError> {
    accept_pair_init_sensed(data_dir, identity, peer, init, origin, now, &mut None)
}

/// [`accept_pair_init_core`] that also says which security event a prekey
/// lifecycle refusal of the PairInit is (`refused_as`,
/// [`crate::security_events::classify_prekey_error`]): a direct link's
/// handler notes it about the contact. The result is exactly the core's.
fn accept_pair_init_sensed(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    init: &PairInit,
    origin: PairOrigin,
    now: u64,
    refused_as: &mut Option<SecKind>,
) -> Result<(IndexedSessionRecordKey, Vec<u8>), PairAcceptError> {
    use PairAcceptError::{Refused, Store};
    // A security notice that marks PairInit version 1 BROKEN (P6.45): none
    // is accepted either, from a link or a letter (sessions already open go
    // on).
    crate::suite_policy::check_pair_init().map_err(Refused)?;
    let mut claim_refused = |error: PrekeyLifecycleError| {
        *refused_as = crate::security_events::classify_prekey_error(&error);
        claim_error(error)
    };
    let letter = origin == PairOrigin::Letter;
    if letter {
        // A letter session never uses a one-time prekey (its RAL1 bindings
        // refuse one too); and a letter is accepted from a contact only.
        if init.one_time_prekey_id != 0 {
            return Err(Refused(
                "letter pair init refused: it names a one-time prekey".into(),
            ));
        }
        if !peer_is_trusted(data_dir, peer).map_err(Store)? {
            return Err(Refused(
                "pair init refused: peer is not a local contact".into(),
            ));
        }
    }
    let key = record_key_for_init(init);
    // Housekeeping, best effort: it never blocks a new session (review
    // B-sealed-stores-2). Without the at-rest key the session store below
    // does not open either (closed).
    let _ = prune_lan_durable_state(data_dir, now);
    let (local_cert, registry) =
        ensure_local_device_certificate(data_dir, identity, PRIMARY_DEVICE_ID).map_err(Store)?;
    let local_prekey = if letter {
        local_published_bundle_by_hash(data_dir, &init.responder_prekey_bundle_hash, now)
            .map_err(Store)?
            .ok_or_else(|| {
                Refused(
                    "letter pair init refused: no retained prekey generation has its bundle".into(),
                )
            })?
    } else {
        let store = PrekeyStore::load_checked(data_dir).map_err(Store)?;
        store
            .fetch(&identity.public_key_bytes(), now)
            .map_err(Store)?
            .ok_or_else(|| Refused("local prekey missing for PairInit".to_string()))?
    };
    let (initiator_revoked, responder_revoked) = pair_revocation(
        data_dir,
        &registry,
        LocalRole::Responder,
        &peer.cert,
        &local_cert,
    )
    .map_err(Store)?;
    let trust = PairInitTrust {
        initiator_certificate: &peer.cert,
        responder_certificate: &local_cert,
        responder_prekey: &local_prekey,
        initiator_revoked,
        responder_revoked,
    };

    let actor = PrekeyLifecycleActor::open(data_dir).map_err(|e| Store(e.to_string()))?;
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(session_store_error)?;
    if let Some(existing) = sessions
        .find_confirmed_session_for_peer(&peer.cert.device_ed_pub)
        .map_err(session_store_error)?
    {
        if existing.init_id == init.init_id {
            let packed =
                replay_pair_response(data_dir, identity, &sessions, init, now).map_err(Refused)?;
            // Crash between confirm and complete_claim leaves the claim pending;
            // exact replay must finish handoff so rotation is not wedged.
            match actor.claim_pair_init(init, &trust, now) {
                Ok(PrekeyClaimOutcome::Accepted(claim))
                | Ok(PrekeyClaimOutcome::DuplicatePending(claim)) => {
                    let claim_id = claim.claim_id();
                    let sid = claim.session_id();
                    actor
                        .complete_claim(&claim_id, &sid)
                        .map_err(|e| Store(e.to_string()))?;
                }
                Ok(PrekeyClaimOutcome::DuplicateCompleted { .. }) => {}
                Ok(PrekeyClaimOutcome::DuplicateAbandoned { .. }) => {
                    return Err(Refused("pair init claim abandoned".into()));
                }
                Err(e) => return Err(claim_refused(e)),
            }
            return Ok((key, packed));
        }
        // Different init_id: allow replacement so a lost PairResponse does not
        // lock pairing. find_confirmed already skipped expired sessions.
    }

    // A letter's claim counts against its initiator's live letter sessions
    // here, before anything is claimed; a PairInit whose session is here
    // already (the same letter again) is not counted twice.
    if letter {
        let sid = session_id(init).map_err(|e| Refused(format!("pair init: {e}")))?;
        if sessions
            .letter_role(&sid)
            .map_err(session_store_error)?
            .is_none()
            && sessions
                .live_letter_sessions_for_peer(&peer.cert.device_ed_pub, LetterRole::Responder, now)
                .map_err(session_store_error)?
                .len()
                >= MAX_LETTER_CLAIMS_PER_INITIATOR
        {
            return Err(PairAcceptError::ClaimLimit);
        }
    }

    // Run the exact check the session store will apply below *before* the
    // claim is journaled, so a root is never durably claimed for an init the
    // session store then refuses (that would leak a claim slot per attempt).
    verify_init(init, &trust, now)
        .map_err(|e| Refused(format!("PairInit validation failed: {e}")))?;
    let mut outcome = actor
        .claim_pair_init(init, &trust, now)
        .map_err(&mut claim_refused)?;
    let (claim_id, sid, root) = match &mut outcome {
        PrekeyClaimOutcome::Accepted(claim) | PrekeyClaimOutcome::DuplicatePending(claim) => {
            // Stays `Zeroizing`: wiped on every return path below.
            let root = claim
                .take_provisional_root()
                .ok_or_else(|| Store("pair init claim missing root".to_string()))?;
            (claim.claim_id(), claim.session_id(), root)
        }
        PrekeyClaimOutcome::DuplicateCompleted { .. } => {
            return replay_pair_response(data_dir, identity, &sessions, init, now)
                .map(|packed| (key, packed))
                .map_err(Refused);
        }
        PrekeyClaimOutcome::DuplicateAbandoned { .. } => {
            return Err(Refused("pair init claim abandoned".into()));
        }
    };

    let key = sessions
        .create_verified_pair_init_session(init, &trust, now, LocalRole::Responder, *root)
        .map_err(session_store_error)?;
    let validity = if letter {
        LETTER_SESSION_LIFETIME_MS
    } else {
        LINK_PAIR_RESPONSE_VALIDITY_MS
    };
    let response = build_pair_response(init, &root, identity, now, validity).map_err(Refused)?;
    let response_wire = encode_response(&response).map_err(|e| Store(format!("{e}")))?;
    // A letter session is letter-class before it is ever confirmed, and it
    // keeps its PairResponse: the REPLY letter that carries it back may
    // leave days later, the cached copy below lasts minutes (P5.14).
    if letter {
        sessions
            .mark_letter_responder(&key, &response_wire)
            .map_err(session_store_error)?;
    }
    let mut rng = OsRng;
    let mut tag = [0u8; 16];
    rng.fill_bytes(&mut tag);
    let packed = wrap_oob_wire(
        &response_wire,
        PairInitOobKind::PairResponse,
        identity,
        tag,
        now,
        &mut rng,
    )
    .map_err(Store)?;
    // Cache before confirm/complete so a crash cannot leave a Confirmed session
    // without a replayable PairResponse.
    store_cached_pair_response(data_dir, &init.init_id, &packed).map_err(Store)?;
    sessions
        .confirm_verified_pair_response(&key, init, &response, now)
        .map_err(session_store_error)?;
    actor
        .complete_claim(&claim_id, &sid)
        .map_err(|e| Store(e.to_string()))?;
    // Keep peer ephemeral only — PairInit Confirm ≠ user contact trust.
    remember_ephemeral_peer(data_dir, peer).map_err(Store)?;
    let _ = session_id(init);
    Ok((key, packed))
}

/// `clock`: the contact's clock as this message shows it (CP.7): the side
/// value of `endpoint_time_window_valid`'s refusal, or accepted. `via`: the
/// link it came on; a store refusal that is a security event is noted
/// (Phase 6b S6-S11, S24).
fn handle_indexed_message(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    packed: &[u8],
    clock: &mut Option<PeerClock>,
    via: Via,
) -> Result<Vec<Vec<u8>>, String> {
    if !peer_is_trusted(data_dir, peer)? {
        return Err("message refused: peer is not a local contact".into());
    }
    let now = now_ms();
    let (local_cert, registry) =
        ensure_local_device_certificate(data_dir, identity, PRIMARY_DEVICE_ID)?;
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let candidates = sessions
        .find_confirmed_sessions_for_peer_at(&peer.cert.device_ed_pub, now)
        .map_err(|e| e.redacted_display())?;
    if candidates.is_empty() {
        return Err("no confirmed LAN session for peer".to_string());
    }
    // Full lineage check on the sender cert; accept_message_envelope then binds
    // that exact cert to the session's PairInit certificate digest.
    let sender_revoked = identity_denies_device_lineage(
        &RevocationStore::load_checked(data_dir)?,
        &registry,
        &peer.cert,
        false,
    )?;
    // The route tag identifies the session (ATSAM_ENDPOINT_TRANSACTION_V1 §1
    // step 4), so try every Confirmed session with this peer, newest first.
    // Peers that paired at the same moment hold two of them and each sealed its
    // first message under the session its *own* pairing produced; trying only
    // the newest refused the other direction for good. A mismatch is decided
    // before any state is touched, so the next candidate starts clean.
    // The application policy (app channel §7.2) sees each opened plaintext
    // before commit; it needs the logical message id for its dedup.
    let message_id = Envelope::unpack(packed)
        .map(|env| env.message_id)
        .unwrap_or([0u8; 16]);
    let sender_device = peer.cert.device_ed_pub;
    let mut policy = |plaintext: &[u8]| {
        crate::app_channel::inbound_policy(data_dir, &sender_device, &message_id, plaintext)
    };
    let mut chosen = None;
    for key in candidates {
        let session_expires = sessions
            .session_expires_at(&key)
            .map_err(|e| e.redacted_display())?;
        let ack_expires = envelope_expires(now, session_expires)?;
        match sessions.accept_message_envelope_with_policy(
            &key,
            packed,
            &peer.cert,
            sender_revoked,
            now,
            &mut policy,
        ) {
            Err(IndexedSessionStoreError::RouteTagMismatch) => continue,
            result => {
                chosen = Some((key, ack_expires, result));
                break;
            }
        }
    }
    let Some((key, ack_expires, accepted)) = chosen else {
        let e = IndexedSessionStoreError::RouteTagMismatch;
        security_sense::store_refusal(&e, via, None, &peer.cert.user_ed_pub);
        return Err(e.redacted_display());
    };
    *clock = envelope_clock(&accepted, packed, now);
    if let Err(e) = &accepted {
        security_sense::store_refusal(e, via, *clock, &peer.cert.user_ed_pub);
        note_message_id_conflict(data_dir, e, &sender_device, &message_id);
    }
    let accepted = match accepted {
        // Deferred before commit: nothing stored, no ACK, link stays open.
        Err(e) if crate::app_channel::is_deferred(&e) => return Ok(Vec::new()),
        other => other.map_err(|e| e.redacted_display())?,
    };
    let digest = match &accepted {
        EndpointAcceptance::Committed {
            object_digest,
            message_id,
            plaintext,
            received_at_ms,
            ..
        } => {
            crate::session_reset::note_inbound_on_session(
                &mut sessions,
                &key,
                &local_cert.device_ed_pub,
                made_at(packed),
                now,
            );
            // Fail-closed: never ACK if durable history cannot retain the body
            // (chat), or before the app inbox holds it (an app frame). The
            // row's own receive stamp tells a later copy (receiver dedup).
            // How it came goes with it (E2 r9: the group store keeps a group
            // message's path; the inbox and the log learn the carrier).
            let arrived = crate::arrivals::ArrivedVia::of_via(via);
            if !crate::arrivals::during(arrived, || {
                crate::app_channel::deliver_committed(
                    data_dir,
                    &mut sessions,
                    &key,
                    &peer.cert.device_ed_pub,
                    message_id,
                    now,
                    *received_at_ms,
                    plaintext,
                )
            })? {
                return Ok(Vec::new());
            }
            if let Some(via) = arrived {
                crate::arrivals::note(crate::arrivals::Arrival {
                    sender: peer.cert.user_ed_pub,
                    message_id: *message_id,
                    via,
                    at_ms: *received_at_ms,
                    group: crate::group::is_group_text(plaintext),
                });
            }
            *object_digest
        }
        EndpointAcceptance::Duplicate {
            session_id,
            object_digest,
            message_id,
        } => {
            // Retry path after a prior history (or app inbox) failure — load
            // the sealed inbox row and deliver it again (idempotent).
            if let Some(row) = sessions
                .load_endpoint_inbox(&key, object_digest)
                .map_err(|e| e.redacted_display())?
            {
                if !crate::app_channel::deliver_committed(
                    data_dir,
                    &mut sessions,
                    &key,
                    &peer.cert.device_ed_pub,
                    message_id,
                    row.created_at_ms,
                    row.received_at_ms,
                    &row.plaintext,
                )? {
                    return Ok(Vec::new());
                }
            } else if sessions
                .inbox_row_deleted(session_id, object_digest)
                .map_err(|e| e.redacted_display())?
            {
                // The user deleted this chat (PP.8): the sender's ACK was
                // lost, so answer with the same ACK and show nothing.
                eprintln!("raven: a deleted message arrived again; answered, not shown");
            } else {
                return Err("duplicate message missing local inbox row for history".into());
            }
            *object_digest
        }
    };
    let local_device = AuthorizedEndpointDevice::authorize(&local_cert, identity, &registry, now)
        .map_err(|e| e.redacted_display())?;
    let mut rng = OsRng;
    let outbound = sessions
        .enqueue_committed_ack(
            &key,
            &digest,
            &local_device,
            now,
            ack_expires,
            now,
            &mut rng,
            &mut |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest),
        )
        .map_err(|e| e.redacted_display())?;
    if outbound.immutable_envelope_bytes.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![outbound.immutable_envelope_bytes])
}

/// ATSAM_ENDPOINT_TRANSACTION_V1 §3: the session store refused another
/// object from `sender` under a message id it had used before
/// ([`IndexedSessionStoreError::LogicalMessageConflict`]). The received row
/// of that id keeps its body and is marked, so the conflict shows (best
/// effort: the refusal stands either way).
pub(crate) fn note_message_id_conflict(
    data_dir: &Path,
    error: &IndexedSessionStoreError,
    sender: &[u8; 32],
    message_id: &[u8; 16],
) {
    if matches!(error, IndexedSessionStoreError::LogicalMessageConflict) {
        let _ = ChatHistory::note_inbound_copy_persisted(
            data_dir,
            &hex::encode(sender),
            &hex::encode(message_id),
            None,
        );
    }
}

/// When the packed envelope `packed` says it was made (its `created_at`;
/// 0 for bytes that do not unpack): what fork evidence weighs
/// ([`crate::session_reset::note_inbound_on_session`]).
fn made_at(packed: &[u8]) -> u64 {
    Envelope::unpack(packed).map_or(0, |env| env.created_at)
}

/// `clock` and `via`: as for [`handle_indexed_message`].
fn handle_ack(
    data_dir: &Path,
    peer: &LanBundle,
    packed: &[u8],
    clock: &mut Option<PeerClock>,
    via: Via,
) -> Result<Vec<Vec<u8>>, String> {
    if !peer_is_trusted(data_dir, peer)? {
        return Err("ack refused: peer is not a local contact".into());
    }
    let now = now_ms();
    // Remote peer revocation is composite RevocationStore only — never the local registry.
    let sender_revoked = identity_denies_device_lineage(
        &RevocationStore::load_checked(data_dir)?,
        &DeviceRegistry::default(),
        &peer.cert,
        false,
    )?;
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let candidates = sessions
        .find_confirmed_sessions_for_peer_at(&peer.cert.device_ed_pub, now)
        .map_err(|e| e.redacted_display())?;
    if candidates.is_empty() {
        return Err("no confirmed LAN session for ACK".to_string());
    }
    // Resolve the session by route tag over every Confirmed session with this
    // peer, newest first (see `handle_indexed_message`).
    for key in candidates {
        match sessions.accept_ack_envelope(&key, packed, &peer.cert, sender_revoked, now) {
            Err(IndexedSessionStoreError::RouteTagMismatch) => continue,
            result => {
                *clock = envelope_clock(&result, packed, now);
                if let Err(e) = &result {
                    security_sense::store_refusal(e, via, *clock, &peer.cert.user_ed_pub);
                }
                let accepted = result.map_err(|e| e.redacted_display())?;
                if matches!(accepted, EndpointAckAcceptance::Committed { .. }) {
                    let local = if key.initiator_device_ed25519 == peer.cert.device_ed_pub {
                        key.responder_device_ed25519
                    } else {
                        key.initiator_device_ed25519
                    };
                    crate::session_reset::note_inbound_on_session(
                        &mut sessions,
                        &key,
                        &local,
                        made_at(packed),
                        now,
                    );
                }
                let (EndpointAckAcceptance::Committed {
                    session_id,
                    acked_message_id,
                    ..
                }
                | EndpointAckAcceptance::Duplicate {
                    session_id,
                    acked_message_id,
                    ..
                }) = accepted;
                // An ACK that arrives on a link the peer opened (its outbox
                // pushing an ACK our dial never got back, transports design
                // F8) is the delivery: record it in the history now. Best
                // effort: the ACK is committed, and a missing history row is
                // repaired by `reconcile_outbound_stage_history` later.
                // The ACK proves delivery: a row still `Prepared` (our dial
                // ended before the reply) must not be dialled again.
                let _ = sessions.settle_delivered_outbound(&session_id, &acked_message_id);
                let _ = crate::outbox::record_inbound_ack_delivery(
                    data_dir,
                    &peer.cert.device_ed_pub,
                    &session_id,
                    &acked_message_id,
                );
                return Ok(Vec::new());
            }
        }
    }
    let e = IndexedSessionStoreError::RouteTagMismatch;
    security_sense::store_refusal(&e, via, None, &peer.cert.user_ed_pub);
    Err(e.redacted_display())
}

/// What a contact's message or ACK showed about its clock (CP.7): accepted,
/// or refused by the store's time window while dated past it (the store
/// checks the window before anything else, so that refusal is this one).
fn envelope_clock<T>(
    result: &Result<T, IndexedSessionStoreError>,
    packed: &[u8],
    now: u64,
) -> Option<PeerClock> {
    match result {
        Ok(_) => Some(PeerClock::Agrees),
        Err(IndexedSessionStoreError::EndpointNotCurrentlyValid) => {
            frame_future_by_ms(packed, now).map(PeerClock::Ahead)
        }
        Err(_) => None,
    }
}

/// Dispatch one plaintext (already Noise-decrypted) LAN frame.
///
/// `noise_ed` is the peer Ed25519 bound by the Noise/bind handshake for this
/// connection. The connection's `peer` bundle and any mid-session RLB1 offer
/// must bind exactly that identity and verify; they cannot introduce a new
/// cache identity.
pub fn dispatch_frame(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    noise_ed: &[u8; 32],
    frame: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    dispatch_frame_on(
        data_dir,
        identity,
        peer,
        noise_ed,
        frame,
        crate::friend_custody::InboundLink {
            carrier: crate::outbox::OutboxCarrier::Lan,
            source: None,
        },
    )
}

/// [`dispatch_frame`] knowing the link the frame came on (friend custody
/// applies its gate per carrier and source, design §6.1).
pub fn dispatch_frame_on(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    noise_ed: &[u8; 32],
    frame: &[u8],
    link: crate::friend_custody::InboundLink,
) -> Result<Vec<Vec<u8>>, String> {
    dispatch_frame_clocked(data_dir, identity, peer, noise_ed, frame, link, &mut None)
}

/// [`dispatch_frame_on`] that also says what the frame showed about the
/// contact's clock (cutoff pack CP.7): `clock` is set to
/// [`PeerClock::Ahead`] when a PairInit, message or ACK from this contact
/// (`peer`, after the contact check) is refused while dated past the
/// window, and to [`PeerClock::Agrees`] when one is accepted; it is left as
/// it is otherwise. The result is exactly [`dispatch_frame_on`]'s.
pub fn dispatch_frame_clocked(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    noise_ed: &[u8; 32],
    frame: &[u8],
    link: crate::friend_custody::InboundLink,
    clock: &mut Option<PeerClock>,
) -> Result<Vec<Vec<u8>>, String> {
    // Phase 6b: what an authenticated contact sends that breaks the rules is
    // noted about the identity its link bound (S11, S15).
    let via = Via::DirectLink(link.carrier);
    let refused = |kind: SecKind, why: &str| {
        security_sense::contact(kind, noise_ed, via);
        Err(why.to_string())
    };
    if !rlb1_matches_noise_identity(peer, noise_ed) {
        return refused(SecKind::BindingMismatch, "rlb1/noise identity mismatch");
    }
    verify_lan_bundle(peer, now_ms())?;
    // Session reset (lost-state recovery): a contact asking whether we still
    // hold the session of one of its objects. Gate off: today's refusal below.
    if crate::session_reset::session_reset_live_enabled() && crate::session_reset::is_rsr1(frame) {
        return crate::session_reset::handle_inbound_rsr1(
            data_dir, identity, peer, noise_ed, frame,
        );
    }
    if is_rlb1(frame) {
        let offer = decode_offer(frame)?;
        if !rlb1_matches_noise_identity(&offer, noise_ed) {
            return refused(SecKind::BindingMismatch, "rlb1/noise identity mismatch");
        }
        if offer.cert.device_ed_pub != peer.cert.device_ed_pub {
            return refused(SecKind::BindingMismatch, "rlb1 device identity drift");
        }
        cache_peer_bundle(data_dir, &offer)?;
        return Ok(Vec::new());
    }
    // Friend custody (RFC1): the custodian's side.
    if crate::friend_custody::is_rfc1(frame) {
        return crate::friend_custody::handle_frame(
            data_dir,
            identity,
            noise_ed,
            &link,
            frame,
            now_ms(),
        );
    }
    match classify_packed_envelope(frame) {
        PairInitOobClassify::PairInit(wire) => {
            return handle_pair_init(data_dir, identity, peer, &wire, clock, via);
        }
        PairInitOobClassify::PairResponse(_) => {
            return Ok(Vec::new());
        }
        PairInitOobClassify::NotPairInitOob => {}
    }
    let Some(env) = Envelope::unpack(frame) else {
        return refused(
            SecKind::ContactMalformed,
            "lan frame is not RavenEnvelopeV1",
        );
    };
    if env.env_type == EnvType::Ack as u8 {
        return handle_ack(data_dir, peer, frame, clock, via);
    }
    if env.env_type == EnvType::Message as u8 {
        return handle_indexed_message(data_dir, identity, peer, frame, clock, via);
    }
    Ok(Vec::new())
}

/// Cached peer material for `peer_pub` (ephemeral first, then durable).
///
/// Only entries that re-verify under [`verify_lan_bundle`] and are keyed by
/// their own signer are returned; anything else (including entries written by
/// older builds under an unverified key) is treated as absent.
pub fn load_cached_peer_bundle(
    data_dir: &Path,
    peer_pub: &[u8; 32],
) -> Result<Option<LanBundle>, String> {
    if let Some(ephemeral) = load_ephemeral_peer(data_dir, peer_pub) {
        return Ok(Some(ephemeral));
    }
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let now = now_ms();
    let map = load_peer_cert_map_checked(data_dir)?;
    let key = hex::encode(peer_pub);
    let Some(cert) = map.get(&key).cloned() else {
        return Ok(None);
    };
    if !durable_peer_cert_entry_valid(&key, &cert, now) {
        return Ok(None);
    }
    let store = PrekeyStore::load_checked(data_dir)?;
    let Some(prekey) = store.fetch(peer_pub, now)? else {
        return Ok(None);
    };
    let bundle = LanBundle { cert, prekey };
    if verify_lan_bundle(&bundle, now).is_err() {
        return Ok(None);
    }
    Ok(Some(bundle))
}

/// The contact's cached device certificate (the durable cache, written after
/// an earlier authenticated link), when it is keyed by its own signer,
/// self-certified and inside its validity window. Unlike
/// [`load_cached_peer_bundle`] it needs no live prekey: an expired prekey
/// does not hide a still-valid certificate (the nearby carrier admits a
/// pinned contact by its certificate, RAVEN_NEARBY_LINK_V1 §0). Revocation
/// is the caller's check (`outbox::peer_lineage_denied`).
pub fn cached_peer_certificate(
    data_dir: &Path,
    peer_pub: &[u8; 32],
) -> Result<Option<DeviceCertificate>, String> {
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let key = hex::encode(peer_pub);
    let map = load_peer_cert_map_checked(data_dir)?;
    Ok(map
        .get(&key)
        .filter(|cert| durable_peer_cert_entry_valid(&key, cert, now_ms()))
        .cloned())
}

/// Where the contacts' cached device certificates live
/// ([`cached_peer_certificate`]): a file whose change tells the nearby
/// carrier to read its pair keys again.
pub fn peer_cert_cache_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(PEER_CERT_CACHE)
}

/// Durable peer cert stored under `peer_pub`, without validity-window checks.
/// Callers must bind it to something already verified (e.g. a session digest).
fn load_durable_peer_cert_raw(
    data_dir: &Path,
    peer_pub: &[u8; 32],
) -> Result<Option<DeviceCertificate>, String> {
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let map = load_peer_cert_map_checked(data_dir)?;
    Ok(map.get(&hex::encode(peer_pub)).cloned())
}

/// The peer certificate bound into `record_key` at PairInit: the candidate from
/// the ephemeral or durable cache whose `device_certificate_hash` equals the
/// session's remote certificate digest. Cache contents never feed security
/// decisions unless they hash to that digest.
fn load_session_bound_peer_cert(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_device: &[u8; 32],
) -> Result<Option<DeviceCertificate>, String> {
    let bound = store
        .remote_certificate_digest(record_key)
        .map_err(map_seal_store_error)?;
    let mut candidates = Vec::new();
    if let Some(ephemeral) = load_ephemeral_peer(data_dir, peer_device) {
        candidates.push(ephemeral.cert);
    }
    if let Some(durable) = load_durable_peer_cert_raw(data_dir, peer_device)? {
        candidates.push(durable);
    }
    for cert in candidates {
        if cert.device_ed_pub != *peer_device {
            continue;
        }
        if device_certificate_hash(&cert).map_err(|e| format!("{e:?}"))? == bound {
            return Ok(Some(cert));
        }
    }
    Ok(None)
}

/// The peer certificate bound into `record_key` at PairInit, from the local
/// caches (see `load_session_bound_peer_cert`): the only certificate the send
/// path and the outbox worker evaluate revocation against and verify ACKs with.
/// `None` when no cached certificate hashes to the session's digest.
pub fn session_bound_peer_certificate(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_device: &[u8; 32],
) -> Result<Option<DeviceCertificate>, String> {
    load_session_bound_peer_cert(data_dir, store, record_key, peer_device)
}

pub fn find_confirmed_peer_session(
    data_dir: &Path,
    peer_device: &[u8; 32],
) -> Result<Option<IndexedSessionRecordKey>, String> {
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    store
        .find_confirmed_session_for_peer(peer_device)
        .map_err(|e| e.redacted_display())
}

/// Newest session with `peer_device` that may seal new Messages: confirmed,
/// unexpired and not retired by a session reset.
pub fn find_sendable_peer_session(
    data_dir: &Path,
    peer_device: &[u8; 32],
) -> Result<Option<IndexedSessionRecordKey>, String> {
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    store
        .find_sendable_session_for_peer(peer_device)
        .map_err(|e| e.redacted_display())
}

/// `ATSAM_SESSION_REQUIRED` text when every session with the contact was
/// retired because the contact reset RAVEN.
pub const SESSION_REQUIRED_AFTER_RESET: &str =
    "the contact reset its session; a new one is set up the next time it is reachable directly";

/// Frozen IPC refuse: no persisted authenticated ATSAM session is usable.
/// Distinct from [`ATSAM_LINEAGE_REVOKED`].
pub const ATSAM_SESSION_REQUIRED: &str = "ATSAM_SESSION_REQUIRED";

/// Frozen IPC refuse: session lineage is covered by Identity RVDR1 / denylist.
/// Do not collapse this to [`ATSAM_SESSION_REQUIRED`] (no re-PairInit same lineage).
pub const ATSAM_LINEAGE_REVOKED: &str = "ATSAM_LINEAGE_REVOKED";

fn parse_peer_device_hint(peer_hint: &str) -> Result<[u8; 32], String> {
    let h = peer_hint.trim().to_lowercase();
    if h.len() != 64 {
        return Err("SEAL_PEER_HINT: peer_hint must be 64 hex chars (device Ed25519)".into());
    }
    let v = hex::decode(&h).map_err(|_| {
        "SEAL_PEER_HINT: peer_hint must be 64 hex chars (device Ed25519)".to_string()
    })?;
    if v.len() != 32 {
        return Err("SEAL_PEER_HINT: peer_hint must be 64 hex chars (device Ed25519)".into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

/// Identity denylist / RVDR1 sticky deny for one device lineage.
///
/// Every G5 covering identifier of `cert` is checked: `device_id` (exact
/// bytes), `device_ed_pub`, `device_x_pub` and `device_cert_hash`, against the
/// signed revocation store (legacy records + verified RVDR1 claims, scoped to
/// the cert's identity) and — for the local identity only — the lineages the
/// local registry retired. A cert that reuses any retired identifier under a
/// new `device_id` is denied (RAVEN_DEVICE_REVOCATION_V1 §2.2).
///
/// Uses existing Identity loaders only (`RevocationStore::load_checked`,
/// `load_device_registry_checked`). Soft `unwrap_or_default` empty-denylist
/// loaders are forbidden on this path.
fn identity_denies_device_lineage(
    rev: &RevocationStore,
    local_reg: &DeviceRegistry,
    cert: &DeviceCertificate,
    apply_local_registry: bool,
) -> Result<bool, String> {
    if rev.denies_certificate(cert)? {
        return Ok(true);
    }
    if apply_local_registry && local_reg.denies_lineage(cert)? {
        return Ok(true);
    }
    Ok(false)
}

/// Fail-closed Identity lineage check for the peer (and local) lineages used
/// by a persisted session. Must run **before** any ATSAM seal crypto.
pub fn refuse_if_session_lineage_revoked(
    data_dir: &Path,
    local_cert: &DeviceCertificate,
    peer_cert: &DeviceCertificate,
) -> Result<(), String> {
    let rev = RevocationStore::load_checked(data_dir)?;
    let local_reg = load_device_registry_checked(data_dir)?;
    if identity_denies_device_lineage(&rev, &local_reg, peer_cert, false)?
        || identity_denies_device_lineage(&rev, &local_reg, local_cert, true)?
    {
        return Err(ATSAM_LINEAGE_REVOKED.into());
    }
    Ok(())
}

fn map_seal_store_error(err: IndexedSessionStoreError) -> String {
    match err {
        IndexedSessionStoreError::RevokedDevice
        | IndexedSessionStoreError::LocalDeviceUnauthorized => ATSAM_LINEAGE_REVOKED.into(),
        IndexedSessionStoreError::SessionNotConfirmed
        | IndexedSessionStoreError::NotFound
        | IndexedSessionStoreError::EndpointNotCurrentlyValid
        | IndexedSessionStoreError::ProtectedStateMissing => {
            format!("{ATSAM_SESSION_REQUIRED}: {}", err.redacted_display())
        }
        IndexedSessionStoreError::SessionRetired => {
            format!("{ATSAM_SESSION_REQUIRED}: {SESSION_REQUIRED_AFTER_RESET}")
        }
        other => other.redacted_display(),
    }
}

/// Seal application payload bytes under the persisted confirmed ATSAM session.
///
/// NON-RELEASE. Reuses `IndexedSessionStore::send_message_envelope` (same
/// indexed seal as LAN / pair_init_lab). Does not flip production tripwires.
/// Identity lineage/deny runs before seal crypto.
pub fn seal_app_payload_under_session(
    data_dir: &Path,
    identity: &Identity,
    peer_hint: &str,
    app_payload: &[u8],
) -> Result<Vec<u8>, String> {
    // Same cap `ash send` enforces before sealing: a larger payload would seal
    // (burning a ratchet index and committing an outbox row) into an envelope
    // no LAN/Internet carrier can ever send, wedging later resends.
    if app_payload.len() > crate::lan_noise::MAX_LAN_ENDPOINT_TEXT {
        return Err(format!(
            "SEAL_PAYLOAD: app payload exceeds {} bytes (LAN/Internet transport limit)",
            crate::lan_noise::MAX_LAN_ENDPOINT_TEXT
        ));
    }
    let peer_device = parse_peer_device_hint(peer_hint)?;
    let (local_cert, local_reg) =
        ensure_local_device_certificate(data_dir, identity, PRIMARY_DEVICE_ID)?;

    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let record_key = match store
        .find_sendable_session_for_peer(&peer_device)
        .map_err(|e| e.redacted_display())?
    {
        Some(key) => key,
        None => {
            let all_retired = store
                .find_confirmed_session_for_peer(&peer_device)
                .map_err(|e| e.redacted_display())?
                .is_some();
            return Err(if all_retired {
                format!("{ATSAM_SESSION_REQUIRED}: {SESSION_REQUIRED_AFTER_RESET}")
            } else {
                format!(
                    "{ATSAM_SESSION_REQUIRED}: no authenticated persisted ATSAM session is available"
                )
            });
        }
    };
    // Revocation is evaluated against the certificate bound into this session
    // at PairInit — never an unbound cached/ephemeral cert for the same key.
    let peer_cert = load_session_bound_peer_cert(data_dir, &mut store, &record_key, &peer_device)?
        .ok_or_else(|| {
            format!("{ATSAM_SESSION_REQUIRED}: no persisted peer certificate bound to the session")
        })?;

    // BEFORE any seal crypto: Identity lineage/deny for lineages used by this session.
    refuse_if_session_lineage_revoked(data_dir, &local_cert, &peer_cert)?;

    let text = std::str::from_utf8(app_payload).map_err(|_| {
        "SEAL_PAYLOAD: app payload must be UTF-8 under indexed-session policy".to_string()
    })?;
    let now = now_ms();
    let session_expires = store
        .session_expires_at(&record_key)
        .map_err(|e| e.redacted_display())?;
    let expires = envelope_expires(now, session_expires).map_err(|_| {
        format!("{ATSAM_SESSION_REQUIRED}: persisted ATSAM session is not currently usable")
    })?;
    if local_reg.is_revoked(&local_cert.device_id) {
        return Err(ATSAM_LINEAGE_REVOKED.into());
    }
    let local_device = AuthorizedEndpointDevice::authorize(&local_cert, identity, &local_reg, now)
        .map_err(map_seal_store_error)?;
    let mut captured = None;
    let mut rng = OsRng;
    match store.send_message_envelope(
        &record_key,
        text,
        &local_device,
        now,
        expires,
        now,
        &mut rng,
        &mut |digest, bytes| {
            captured = Some(bytes.to_vec());
            Ok(*digest)
        },
    ) {
        Ok(_) => captured.ok_or_else(|| "SEAL: missing sealed envelope after handoff".into()),
        Err(err) => Err(map_seal_store_error(err)),
    }
}

/// Lifetime of the sessions this node initiates. The indexed-session profile
/// has no forward secrecy inside a session (ATSAM_INDEXED_SESSION_PROFILE_V1
/// §2.4): whoever obtains a session's state reads all of it, in both
/// directions. A session is therefore kept short and replaced by a fresh
/// PairInit once it expires (owner decision 2026-10-07,
/// docs/WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md). Responders still
/// accept up to `prekey_lifecycle::MAX_PAIR_INIT_LIFETIME_MS` from older peers.
pub const LAN_SESSION_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;
// A responder refuses PairInits longer than this; never initiate one it would refuse.
const _: () =
    assert!(LAN_SESSION_LIFETIME_MS <= crate::prekey_lifecycle::MAX_PAIR_INIT_LIFETIME_MS);

thread_local! {
    static LIFETIME_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Tests only (ignored in release builds): sessions this thread initiates
/// last `ms` (clamped to at most [`LAN_SESSION_LIFETIME_MS`]).
#[doc(hidden)]
pub fn set_lab_session_lifetime_for_this_thread(ms: Option<u64>) {
    LIFETIME_OVERRIDE.with(|cell| cell.set(ms));
}

/// Lifetime of a session this node initiates now (Phase 3 item 4, session
/// renewal). Release: always [`LAN_SESSION_LIFETIME_MS`]. Debug: the
/// thread's override ([`set_lab_session_lifetime_for_this_thread`]), else
/// `RAVEN_LAB_SESSION_LIFETIME_MS` clamped to [60 s, 24 h] (the harnesses'
/// "the session ends in 11 h": the first `raven send` sets it; raven-node,
/// which renews, never does). It can only shorten a session.
pub fn initiator_session_lifetime_ms() -> u64 {
    if !cfg!(debug_assertions) {
        return LAN_SESSION_LIFETIME_MS;
    }
    if let Some(ms) = LIFETIME_OVERRIDE.with(std::cell::Cell::get) {
        return ms.clamp(1, LAN_SESSION_LIFETIME_MS);
    }
    lab_lifetime_from(
        std::env::var("RAVEN_LAB_SESSION_LIFETIME_MS")
            .ok()
            .as_deref(),
    )
}

/// `RAVEN_LAB_SESSION_LIFETIME_MS`'s value: whole milliseconds, clamped to
/// [60 s, [`LAN_SESSION_LIFETIME_MS`]]; anything else is the constant.
fn lab_lifetime_from(value: Option<&str>) -> u64 {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(LAN_SESSION_LIFETIME_MS, |ms| {
            ms.clamp(60_000, LAN_SESSION_LIFETIME_MS)
        })
}

/// Build a signed PairInit and persist the initiator provisional session:
/// a link session of exactly [`initiator_session_lifetime_ms`] (24 h).
pub fn create_initiator_pair_init(
    data_dir: &Path,
    id: &Identity,
    peer: &LanBundle,
) -> Result<(PairInit, IndexedSessionRecordKey), String> {
    build_initiator_pair_init(
        data_dir,
        id,
        peer,
        PairInitShape::Link {
            lifetime_ms: initiator_session_lifetime_ms(),
        },
    )
}

/// Build a signed PairInit for an RAL1 letter (Phase 5b) and persist its
/// provisional session, marked [`LetterRole::Initiator`] with the exact
/// PairInit bytes (a retry or a direct completion resends them,
/// `RAVEN_PAIR_INIT_V1.md` §6). Its lifetime is
/// [`letter_session_lifetime_ms`] (up to 7 days, never below a day) and it
/// uses the signed prekey only: a contact bundle that names a one-time
/// prekey is refused (the PairInit binds the bundle's hash). The session's
/// provisional initiator may seal message indices 0 to 15
/// ([`crate::horizon::LETTER_SESSION_MAX_MESSAGES`]); it never takes a
/// direct Message (letter-class).
pub fn create_letter_pair_init(
    data_dir: &Path,
    id: &Identity,
    peer: &LanBundle,
) -> Result<(PairInit, IndexedSessionRecordKey), String> {
    build_initiator_pair_init(data_dir, id, peer, PairInitShape::Letter)
}

/// The lifetime of a letter session started at `now_ms`:
/// [`LETTER_SESSION_LIFETIME_MS`], cut to the end of the contact's prekey
/// bundle and of both device certificates (the PairInit's trust window,
/// `verify_init`), and refused below [`LETTER_MIN_SESSION_LIFETIME_MS`].
pub fn letter_session_lifetime_ms(
    now_ms: u64,
    prekey_expires_at_ms: u64,
    local_cert_not_after_ms: u64,
    peer_cert_not_after_ms: u64,
) -> Result<u64, String> {
    let lifetime = LETTER_SESSION_LIFETIME_MS
        .min(prekey_expires_at_ms.saturating_sub(now_ms))
        .min(local_cert_not_after_ms.saturating_sub(now_ms))
        .min(peer_cert_not_after_ms.saturating_sub(now_ms));
    if lifetime < LETTER_MIN_SESSION_LIFETIME_MS {
        return Err(
            "letter pair init refused: the contact's prekey bundle or a device certificate ends within a day"
                .into(),
        );
    }
    Ok(lifetime)
}

/// What kind of PairInit [`build_initiator_pair_init`] makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairInitShape {
    /// A link session: exactly `lifetime_ms`, with the bundle's one-time
    /// prekey when it names one.
    Link { lifetime_ms: u64 },
    /// A letter session: [`letter_session_lifetime_ms`], the signed prekey
    /// only, marked [`LetterRole::Initiator`].
    Letter,
}

/// Build a signed PairInit of `shape` to `peer` and persist the initiator
/// provisional session.
fn build_initiator_pair_init(
    data_dir: &Path,
    id: &Identity,
    peer: &LanBundle,
    shape: PairInitShape,
) -> Result<(PairInit, IndexedSessionRecordKey), String> {
    // A security notice that marks PairInit version 1 BROKEN (P6.45): no
    // new session is started, on a link or in a letter.
    crate::suite_policy::check_pair_init()?;
    if !peer_is_trusted(data_dir, peer)? {
        return Err("pair init refused: peer is not a local contact".into());
    }
    let letter = shape == PairInitShape::Letter;
    if letter && peer.prekey.one_time_prekey_id != 0 {
        return Err(
            "letter pair init refused: the contact's prekey bundle names a one-time prekey".into(),
        );
    }
    let now = now_ms();
    // Before anything is created: a prekey the durable pin refuses (rollback /
    // equivocation) never seeds a new session.
    require_prekey_acceptable_to_pin(data_dir, peer, now)?;
    // Housekeeping, best effort: it never blocks a new session (review
    // B-sealed-stores-2). Without the at-rest key the session store below
    // does not open either (closed).
    let _ = prune_lan_durable_state(data_dir, now);
    let (local_cert, registry) = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID)?;
    let lifetime_ms = match shape {
        PairInitShape::Link { lifetime_ms } => lifetime_ms,
        PairInitShape::Letter => letter_session_lifetime_ms(
            now,
            peer.prekey.expires_at_ms,
            local_cert.not_after_ms,
            peer.cert.not_after_ms,
        )?,
    };
    let (initiator_revoked, responder_revoked) = pair_revocation(
        data_dir,
        &registry,
        LocalRole::Initiator,
        &local_cert,
        &peer.cert,
    )?;
    let trust = PairInitTrust {
        initiator_certificate: &local_cert,
        responder_certificate: &peer.cert,
        responder_prekey: &peer.prekey,
        initiator_revoked,
        responder_revoked,
    };
    let mut rng = OsRng;
    let mut eph = HybridKeypair::generate(&mut rng);
    let selected_x = if peer.prekey.one_time_prekey_id != 0 {
        peer.prekey.one_time_x25519_pub.ok_or("peer OTP missing")?
    } else {
        peer.prekey.x25519_pub
    };
    let pending = begin_hybrid_initiation(
        &mut rng,
        &eph.x25519_secret,
        &selected_x,
        &peer.prekey.mlkem768_ek,
    )
    .map_err(|e| format!("hybrid begin: {e}"))?;
    let ciphertext = pending.ciphertext().to_vec();
    let mut init_id = [0u8; 16];
    rng.fill_bytes(&mut init_id);
    let mut pairing_nonce = [0u8; 32];
    rng.fill_bytes(&mut pairing_nonce);
    let otp_pub = peer.prekey.one_time_x25519_pub.unwrap_or([0u8; 32]);
    // Stamp the init with our own clock and never later. The session binding
    // takes `created_at_ms` from it and the session store refuses traffic
    // dated before that instant, so future-dating it (for instance up to the
    // peer prekey's `created_at_ms`, which comes from the peer's clock) would
    // lock our own session out of sealing. A prekey or cert created slightly
    // after this instant is covered by the verifiers' bounded skew
    // (`MAX_PREKEY_FUTURE_SKEW_MS`) instead.
    let created_at_ms = now;
    let mut init = PairInit {
        initiator_address: id.address(),
        responder_address: encode_address(&peer.cert.user_ed_pub),
        init_id,
        pairing_nonce,
        initiator_device_ed_pub: id.public_key_bytes(),
        responder_device_ed_pub: peer.cert.device_ed_pub,
        initiator_ephemeral_x25519_pub: eph.x25519_public,
        responder_signed_x25519_pub: peer.prekey.x25519_pub,
        responder_one_time_x25519_pub: otp_pub,
        initiator_device_cert_hash: device_certificate_hash(&local_cert)
            .map_err(|e| format!("{e:?}"))?,
        responder_device_cert_hash: device_certificate_hash(&peer.cert)
            .map_err(|e| format!("{e:?}"))?,
        responder_prekey_bundle_hash: prekey_bundle_hash(&peer.prekey)
            .map_err(|e| format!("{e:?}"))?,
        signed_prekey_id: peer.prekey.signed_prekey_id,
        one_time_prekey_id: peer.prekey.one_time_prekey_id,
        responder_mlkem768_ek: peer.prekey.mlkem768_ek.clone(),
        mlkem768_ciphertext: ciphertext,
        created_at_ms,
        expires_at_ms: created_at_ms.saturating_add(lifetime_ms),
        signature: [0u8; 64],
    };
    let signing = init_signing_bytes(&init).map_err(|e| format!("{e:?}"))?;
    init.signature = id.sign(&signing);
    eph.x25519_secret = [0u8; 32];
    let digest = transcript_hash(&init).map_err(|e| format!("{e:?}"))?;
    // `root` is `Zeroizing`: wiped on every return path below.
    let (_ct, root) = pending.finalize(&digest);
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let record_key = store
        .create_verified_pair_init_session(&init, &trust, now, LocalRole::Initiator, *root)
        .map_err(|e| e.redacted_display())?;
    if letter {
        // Not one transaction with the session: a stop in between leaves a
        // provisional session nothing seals into (no row names it) until it
        // expires.
        let wire = encode_init(&init).map_err(|e| format!("{e:?}"))?;
        store
            .mark_letter_session(&record_key, LetterRole::Initiator, Some(&wire))
            .map_err(|e| e.redacted_display())?;
    }
    Ok((init, record_key))
}

pub fn wrap_pair_init(id: &Identity, init: &PairInit) -> Result<Vec<u8>, String> {
    let wire = encode_init(init).map_err(|e| format!("{e:?}"))?;
    let mut tag = [0u8; 16];
    OsRng.fill_bytes(&mut tag);
    wrap_oob_wire(
        &wire,
        PairInitOobKind::PairInit,
        id,
        tag,
        now_ms(),
        &mut OsRng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_sync::RevocationRecord;
    use crate::prekey_lifecycle::PrekeyGenerationPrivate;
    use zeroize::Zeroize;

    fn now() -> u64 {
        now_ms()
    }

    fn publish_and_install(data_dir: &Path, id: &Identity) {
        publish_and_install_with(data_dir, id, 1, now());
    }

    /// Install and publish a local prekey with an explicit id and creation
    /// instant (a peer whose clock or counter differs from ours).
    fn publish_and_install_with(data_dir: &Path, id: &Identity, prekey_id: u32, t: u64) {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let mut rng = rand::thread_rng();
        let mut kp = HybridKeypair::generate(&mut rng);
        let bundle = crate::prekey_bundle::PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            prekey_id,
            t,
            t.saturating_add(30 * 24 * 3600 * 1000),
        )
        .unwrap()
        .sign(id)
        .unwrap();
        let actor = PrekeyLifecycleActor::open(data_dir).unwrap();
        actor
            .install_generation(
                std::slice::from_ref(&bundle),
                PrekeyGenerationPrivate::new(kp.x25519_secret, kp.mlkem_seed, vec![]),
                t,
            )
            .unwrap();
        kp.x25519_secret.zeroize();
        let mut store = PrekeyStore::load_checked(data_dir).unwrap();
        store.publish(&bundle, t).unwrap();
        store.save(data_dir).unwrap();
        let _ = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID).unwrap();
    }

    fn write_contact(data_dir: &Path, peer_device_ed: &[u8; 32], petname: &str) {
        let contacts = serde_json::json!([{
            "petname": petname,
            "pub_hex": hex::encode(peer_device_ed),
            "address": "",
        }]);
        std::fs::write(
            data_dir.join("contacts.json"),
            serde_json::to_string_pretty(&contacts).unwrap(),
        )
        .unwrap();
    }

    /// Far-future bundle signed by `signer` that names `device_ed` as its device key.
    fn signed_bundle(signer: &Identity, device_ed: [u8; 32], device_id: &str) -> LanBundle {
        let t = now();
        let far = t.saturating_add(10 * 365 * 24 * 3600 * 1000);
        let cert = DeviceCertificate::issue(
            signer,
            device_ed,
            [0x42; 32],
            device_id,
            t.saturating_sub(60_000),
            far,
            0,
        )
        .unwrap();
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        let prekey = PrekeyBundle::from_hybrid_public(
            device_id,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            1,
            t,
            far,
        )
        .unwrap()
        .sign(signer)
        .unwrap();
        LanBundle { cert, prekey }
    }

    /// Simulates cache state written before offers were verified.
    fn inject_ephemeral_unchecked(data_dir: &Path, key: [u8; 32], bundle: &LanBundle) {
        let mut guard = EPHEMERAL_PEERS.lock().unwrap();
        let root = guard.get_or_insert_with(HashMap::new);
        root.entry(ephemeral_dir_key(data_dir)).or_default().insert(
            key,
            EphemeralPeer {
                bundle: bundle.clone(),
                expires_at: Instant::now() + EPHEMERAL_PEER_TTL,
            },
        );
    }

    fn clear_ephemeral(data_dir: &Path) {
        let mut guard = EPHEMERAL_PEERS.lock().unwrap();
        if let Some(root) = guard.as_mut() {
            root.remove(&ephemeral_dir_key(data_dir));
        }
    }

    /// Seal `text` under `key` on `dir`'s store (what `ash send` does right
    /// after its own pairing) and return the packed message envelope.
    fn seal_under(dir: &Path, id: &Identity, key: &IndexedSessionRecordKey, text: &str) -> Vec<u8> {
        let mut store = IndexedSessionStore::open(dir).unwrap();
        let (cert, reg) = ensure_local_device_certificate(dir, id, PRIMARY_DEVICE_ID).unwrap();
        let device = AuthorizedEndpointDevice::authorize(&cert, id, &reg, now()).unwrap();
        let t = now();
        let expires = envelope_expires(t, store.session_expires_at(key).unwrap()).unwrap();
        let mut queued = None;
        store
            .send_message_envelope(
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
            )
            .unwrap();
        queued.unwrap()
    }

    /// Sessions this node initiates last `LAN_SESSION_LIFETIME_MS` (24 h), not
    /// the 7-day maximum a responder accepts: the profile has no forward secrecy
    /// inside a session, so a short session bounds what a stolen state reveals.
    #[test]
    fn initiated_sessions_last_one_day() {
        let alice = Identity::from_seed(&[0xd5; 32]);
        let bob = Identity::from_seed(&[0xd6; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, key) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        assert_eq!(LAN_SESSION_LIFETIME_MS, 24 * 60 * 60 * 1_000);
        assert_eq!(
            init.expires_at_ms - init.created_at_ms,
            LAN_SESSION_LIFETIME_MS
        );
        let mut store = IndexedSessionStore::open(a_dir.path()).unwrap();
        assert_eq!(store.session_expires_at(&key).unwrap(), init.expires_at_ms);
    }

    /// Phase 3 item 4: the debug-only lifetime override (the tests' and the
    /// harnesses' "the session ends in 11 h") can only shorten a session, the
    /// variable is clamped to [60 s, 24 h], and a release build reads neither.
    #[test]
    fn session_lifetime_override_only_shortens_and_is_debug_only() {
        const DAY: u64 = LAN_SESSION_LIFETIME_MS;
        for (value, expected) in [
            (None, DAY),
            (Some("garbage"), DAY),
            (Some("-5"), DAY),
            (Some("0"), 60_000),
            (Some(" 39600000 "), 39_600_000),
            (Some("1000000000000"), DAY),
        ] {
            assert_eq!(lab_lifetime_from(value), expected, "{value:?}");
        }
        set_lab_session_lifetime_for_this_thread(Some(11 * 3_600_000));
        let shortened = initiator_session_lifetime_ms();
        set_lab_session_lifetime_for_this_thread(Some(10 * DAY));
        let capped = initiator_session_lifetime_ms();
        set_lab_session_lifetime_for_this_thread(None);
        if cfg!(debug_assertions) {
            assert_eq!(shortened, 11 * 3_600_000);
            assert_eq!(capped, DAY);
        } else {
            assert_eq!((shortened, capped), (DAY, DAY));
        }
        if std::env::var("RAVEN_LAB_SESSION_LIFETIME_MS").is_err() || !cfg!(debug_assertions) {
            assert_eq!(initiator_session_lifetime_ms(), DAY);
        }
    }

    /// One prune pass (what raven-node's periodic `durable_prune` runs) destroys
    /// an expired session's protected root, not only its metadata, and keeps
    /// a session that has not expired yet.
    #[test]
    fn one_prune_pass_destroys_an_expired_sessions_protected_root() {
        let alice = Identity::from_seed(&[0xd1; 32]);
        let bob = Identity::from_seed(&[0xd2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, key) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();

        let record_keys = || {
            IndexedSessionStore::open(a_dir.path())
                .unwrap()
                .list_record_keys()
                .unwrap()
        };
        // Under the lab locked-file backend each protected root is one file.
        let locked_file = ["RAVEN_SESSION_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var_os(k).is_some_and(|v| v == "locked-file"));
        let secrets = a_dir.path().join("indexed-session-secrets");
        let protected_roots = || {
            std::fs::read_dir(&secrets)
                .map(|dir| {
                    dir.flatten()
                        .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
                        .count()
                })
                .unwrap_or(0)
        };
        assert_eq!(record_keys(), vec![key]);
        if locked_file {
            assert_eq!(protected_roots(), 1);
        }

        prune_lan_durable_state(a_dir.path(), init.expires_at_ms - 1).unwrap();
        assert_eq!(record_keys().len(), 1, "a live session must be kept");
        if locked_file {
            assert_eq!(protected_roots(), 1);
        }

        prune_lan_durable_state(a_dir.path(), init.expires_at_ms).unwrap();
        assert!(record_keys().is_empty());
        if locked_file {
            assert_eq!(protected_roots(), 0, "expired K_root left in the store");
        }
    }

    /// Two peers that say hello at the same moment each run a PairInit and so
    /// each hold two confirmed sessions with the other. Each sealed its first
    /// message under the session its *own* pairing produced; the receiver used to
    /// try only its newest session, so the direction whose session was not the
    /// newest was refused with a route-tag mismatch, and the pair stayed wedged.
    /// The receiver now resolves the session by route tag, so both directions
    /// deliver (and the ACKs come back).
    #[test]
    fn crossed_first_contact_delivers_in_both_directions() {
        let alice = Identity::from_seed(&[0xe1; 32]);
        let bob = Identity::from_seed(&[0xe2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (a_pub, b_pub) = (alice.public_key_bytes(), bob.public_key_bytes());

        // Both start pairing before either has heard from the other.
        let (init_a, key_a) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let (init_b, key_b) = create_initiator_pair_init(b_dir.path(), &bob, &a_bundle).unwrap();
        // Each answers the other's init as responder...
        let to_b = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &a_pub,
            &wrap_pair_init(&alice, &init_a).unwrap(),
        )
        .unwrap();
        let to_a = dispatch_frame(
            a_dir.path(),
            &alice,
            &b_bundle,
            &b_pub,
            &wrap_pair_init(&bob, &init_b).unwrap(),
        )
        .unwrap();
        // ...and each confirms its own init from the PairResponse it gets back.
        let response = |frames: &[Vec<u8>]| {
            let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&frames[0])
            else {
                panic!("expected PairResponse");
            };
            crate::pair_init::decode_response(&wire).unwrap()
        };
        IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .confirm_verified_pair_response(&key_a, &init_a, &response(&to_b), now())
            .unwrap();
        IndexedSessionStore::open(b_dir.path())
            .unwrap()
            .confirm_verified_pair_response(&key_b, &init_b, &response(&to_a), now())
            .unwrap();

        // Both nodes hold both sessions, and agree which one is newest.
        let sessions = |dir: &Path, peer: &[u8; 32]| {
            IndexedSessionStore::open(dir)
                .unwrap()
                .find_confirmed_sessions_for_peer_at(peer, now())
                .unwrap()
        };
        let at_alice = sessions(a_dir.path(), &b_pub);
        let at_bob = sessions(b_dir.path(), &a_pub);
        assert_eq!(at_alice.len(), 2);
        assert_eq!(
            at_alice, at_bob,
            "both nodes order the sessions identically"
        );
        // One direction is therefore sealed under a session the receiver does not
        // consider newest: the case that used to be refused.
        let newest = at_alice[0].clone();
        assert!(key_a != newest || key_b != newest);

        for (
            label,
            sender_dir,
            sender,
            sender_bundle,
            key,
            receiver_dir,
            receiver,
            receiver_bundle,
        ) in [
            (
                "alice->bob",
                a_dir.path(),
                &alice,
                &a_bundle,
                &key_a,
                b_dir.path(),
                &bob,
                &b_bundle,
            ),
            (
                "bob->alice",
                b_dir.path(),
                &bob,
                &b_bundle,
                &key_b,
                a_dir.path(),
                &alice,
                &a_bundle,
            ),
        ] {
            let packed = seal_under(sender_dir, sender, key, label);
            let replies = dispatch_frame(
                receiver_dir,
                receiver,
                sender_bundle,
                &sender.public_key_bytes(),
                &packed,
            )
            .unwrap_or_else(|e| panic!("{label}: refused: {e}"));
            assert_eq!(replies.len(), 1, "{label}: one sealed ACK");
            // The receiver committed it...
            let inbox = IndexedSessionStore::open(receiver_dir)
                .unwrap()
                .list_endpoint_inbox()
                .unwrap();
            assert!(
                inbox.iter().any(|row| row.plaintext == label.as_bytes()),
                "{label}: not in the receiver's inbox"
            );
            // ...and its ACK is accepted by the sender under the session it used.
            IndexedSessionStore::open(sender_dir)
                .unwrap()
                .accept_ack_envelope(key, &replies[0], &receiver_bundle.cert, false, now())
                .unwrap_or_else(|e| panic!("{label}: ACK refused: {e:?}"));
            // An ACK frame that arrives unsolicited is resolved by route tag too.
            dispatch_frame(
                sender_dir,
                sender,
                receiver_bundle,
                &receiver.public_key_bytes(),
                &replies[0],
            )
            .unwrap_or_else(|e| panic!("{label}: unsolicited ACK refused: {e}"));
        }
    }

    /// The route-tag search is not a way around the session binding: a message
    /// no confirmed session of the peer recognises is refused (with the usual
    /// text), and so is one from a peer the receiver holds no session with.
    #[test]
    fn message_no_session_recognises_is_still_refused() {
        let alice = Identity::from_seed(&[0xe3; 32]);
        let bob = Identity::from_seed(&[0xe4; 32]);
        let carol = Identity::from_seed(&[0xe5; 32]);
        let (a_dir, b_dir, c_dir) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        for (d, id) in [(&a_dir, &alice), (&b_dir, &bob), (&c_dir, &carol)] {
            publish_and_install(d.path(), id);
        }
        let (a_bundle, _b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
        let key = IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .find_confirmed_session_for_peer_at(&bob.public_key_bytes(), now())
            .unwrap()
            .unwrap();
        let packed = seal_under(a_dir.path(), &alice, &key, "to bob");

        // A routing tag no session derives: every candidate mismatches.
        let mut env = Envelope::unpack(&packed).unwrap();
        env.routing_tag[0] ^= 0xff;
        let err = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &env.pack(),
        )
        .unwrap_err();
        assert!(err.contains("route tag does not match"), "{err}");

        // The untouched message is accepted by the session it was sealed under.
        let replies = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &packed,
        )
        .expect("the genuine message is accepted");
        assert_eq!(replies.len(), 1);

        // A contact Bob holds no session with: no candidate at all.
        let c_bundle = local_bundle(c_dir.path(), &carol).unwrap();
        write_contact(b_dir.path(), &c_bundle.cert.device_ed_pub, "Carol");
        let err = dispatch_frame(
            b_dir.path(),
            &bob,
            &c_bundle,
            &carol.public_key_bytes(),
            &packed,
        )
        .unwrap_err();
        assert!(err.contains("no confirmed LAN session"), "{err}");
    }

    /// Alice and Bob paired (Alice initiated); `seal` seals one Message from
    /// Alice under that session (handed to her queue, never dialled).
    struct AppLab {
        alice: Identity,
        bob: Identity,
        a_dir: tempfile::TempDir,
        b_dir: tempfile::TempDir,
        a_bundle: LanBundle,
        b_bundle: LanBundle,
        key: IndexedSessionRecordKey,
    }

    impl AppLab {
        fn new() -> Self {
            let alice = Identity::from_seed(&[0xa7; 32]);
            let bob = Identity::from_seed(&[0xb7; 32]);
            let a_dir = tempfile::tempdir().unwrap();
            let b_dir = tempfile::tempdir().unwrap();
            publish_and_install(a_dir.path(), &alice);
            publish_and_install(b_dir.path(), &bob);
            let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
            let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
            write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
            write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
            cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
            cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
            let (init, key) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
            let init_frame = wrap_pair_init(&alice, &init).unwrap();
            let replies = dispatch_frame(
                b_dir.path(),
                &bob,
                &a_bundle,
                &alice.public_key_bytes(),
                &init_frame,
            )
            .unwrap();
            let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0])
            else {
                panic!("expected PairResponse");
            };
            let response = crate::pair_init::decode_response(&wire).unwrap();
            IndexedSessionStore::open(a_dir.path())
                .unwrap()
                .confirm_verified_pair_response(&key, &init, &response, now())
                .unwrap();
            Self {
                alice,
                bob,
                a_dir,
                b_dir,
                a_bundle,
                b_bundle,
                key,
            }
        }

        fn seal(&self, text: &str) -> Vec<u8> {
            let mut store = IndexedSessionStore::open(self.a_dir.path()).unwrap();
            let (cert, reg) =
                ensure_local_device_certificate(self.a_dir.path(), &self.alice, PRIMARY_DEVICE_ID)
                    .unwrap();
            let device =
                AuthorizedEndpointDevice::authorize(&cert, &self.alice, &reg, now()).unwrap();
            let t = now();
            let expires =
                envelope_expires(t, store.session_expires_at(&self.key).unwrap()).unwrap();
            let mut packed = None;
            store
                .send_message_envelope(
                    &self.key,
                    text,
                    &device,
                    t,
                    expires,
                    t,
                    &mut OsRng,
                    &mut |digest, bytes| {
                        packed = Some(bytes.to_vec());
                        Ok(*digest)
                    },
                )
                .unwrap();
            packed.unwrap()
        }

        fn deliver(&self, packed: &[u8]) -> Vec<Vec<u8>> {
            dispatch_frame(
                self.b_dir.path(),
                &self.bob,
                &self.a_bundle,
                &self.alice.public_key_bytes(),
                packed,
            )
            .unwrap()
        }

        fn bob_inbox_len(&self) -> usize {
            IndexedSessionStore::open(self.b_dir.path())
                .unwrap()
                .list_endpoint_inbox()
                .unwrap()
                .len()
        }

        fn bob_pending_intents(&self) -> usize {
            IndexedSessionStore::open(self.b_dir.path())
                .unwrap()
                .pending_endpoint_ack_intents()
                .unwrap()
                .len()
        }

        fn bob_history(&self) -> Vec<String> {
            ChatHistory::load(self.b_dir.path())
                .map(|h| {
                    h.for_peer(&hex::encode(self.a_bundle.cert.device_ed_pub))
                        .iter()
                        .map(|e| e.preview.clone())
                        .collect()
                })
                .unwrap_or_default()
        }

        fn bob_app_items(&self) -> Vec<crate::app_store::AppInboxItem> {
            let sealer = crate::app_store::PlatformRowSealer::new(self.b_dir.path());
            let Ok(mut store) = crate::app_store::AppStore::open(self.b_dir.path(), &sealer) else {
                return Vec::new();
            };
            store
                .page("rdap:test", false, 32, now(), &|_| Ok(None))
                .unwrap()
        }
    }

    fn app_frame(ct: &str, id: u8, body: &str) -> String {
        format!("RVNAPP/1 {ct} {}\n{body}", hex::encode([id; 16]))
    }

    struct LabGuard;
    impl LabGuard {
        fn set(on: bool) -> Self {
            crate::app_channel::set_test_lab(Some(on));
            Self
        }
    }
    impl Drop for LabGuard {
        fn drop(&mut self) {
            crate::app_channel::set_test_lab(None);
        }
    }

    #[test]
    fn an_app_frame_reaches_the_app_inbox_and_never_chat_history() {
        let _lab = LabGuard::set(true);
        let lab = AppLab::new();
        let replies = lab.deliver(&lab.seal(&app_frame("test/1", 1, "agent task")));
        assert_eq!(replies.len(), 1, "ACKed once stored");
        let items = lab.bob_app_items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].body, "agent task");
        assert_eq!(items[0].sender_identity, lab.a_bundle.cert.user_ed_pub);
        assert!(lab.bob_history().is_empty(), "{:?}", lab.bob_history());
        // Chat in the same session is unchanged.
        assert_eq!(lab.deliver(&lab.seal("plain chat")).len(), 1);
        assert!(lab.bob_history().iter().any(|p| p.contains("plain chat")));
        assert_eq!(lab.bob_app_items().len(), 1);
    }

    #[test]
    fn a_deferred_app_frame_commits_nothing_and_the_same_bytes_are_accepted_later() {
        let lab = AppLab::new();
        let packed = {
            let _lab = LabGuard::set(true);
            lab.seal(&app_frame("test/1", 2, "later"))
        };
        {
            // Gate closed at the receiver: deferred.
            let _closed = LabGuard::set(false);
            assert!(lab.deliver(&packed).is_empty());
            assert_eq!(lab.bob_inbox_len(), 0);
            assert_eq!(lab.bob_pending_intents(), 0);
            assert!(lab.bob_history().is_empty());
            // A later chat message (the next index) is still accepted.
            assert_eq!(lab.deliver(&lab.seal("chat after")).len(), 1);
        }
        // Gate open: the very same bytes are a fresh accept (skipped key).
        let _open = LabGuard::set(true);
        assert_eq!(lab.deliver(&packed).len(), 1);
        assert_eq!(lab.bob_app_items().len(), 1);
        assert!(!lab.bob_history().iter().any(|p| p.contains("later")));
    }

    #[test]
    fn malformed_reserved_and_unregistered_frames_are_deferred_never_shown() {
        let _lab = LabGuard::set(true);
        let lab = AppLab::new();
        for text in [
            "RVNAPP/2 test/1 00000000000000000000000000000000\nnext version",
            "RVNAPP/1 test/1 NOT-HEX\nbad id",
            &app_frame("unknown-type/1", 3, "unregistered"),
        ] {
            assert!(lab.deliver(&lab.seal(text)).is_empty(), "{text}");
        }
        assert_eq!(lab.bob_inbox_len(), 0);
        assert_eq!(lab.bob_pending_intents(), 0);
        assert!(lab.bob_history().is_empty());
        assert!(lab.bob_app_items().is_empty());
        // test/1 is a lab-only type: refused (deferred) without the unlock.
        let _closed = LabGuard::set(false);
        assert!(lab
            .deliver(&lab.seal(&app_frame("test/1", 4, "lab only")))
            .is_empty());
        assert_eq!(lab.bob_inbox_len(), 0);
    }

    #[test]
    fn the_unacknowledged_span_counts_from_the_newest_ack() {
        let lab = AppLab::new();
        let span = || {
            IndexedSessionStore::open(lab.a_dir.path())
                .unwrap()
                .unacknowledged_message_span(&lab.key)
                .unwrap()
        };
        assert_eq!(span(), 0);
        let _first = lab.seal("one");
        let second = lab.seal("two");
        let _third = lab.seal("three");
        assert_eq!(span(), 3);
        // Bob commits the second (the first is still deferred or lost); its
        // ACK reaches Alice: only the third may still be unread.
        let acks = lab.deliver(&second);
        assert_eq!(acks.len(), 1);
        dispatch_frame(
            lab.a_dir.path(),
            &lab.alice,
            &lab.b_bundle,
            &lab.bob.public_key_bytes(),
            &acks[0],
        )
        .unwrap();
        assert_eq!(span(), 1);
    }

    /// The same sealed bytes again (a resend after a lost ACK, on any carrier)
    /// are an exact duplicate: the same ACK bytes come back and nothing is
    /// stored twice. The worker's resends on another route rely on this.
    #[test]
    fn the_same_sealed_bytes_twice_get_the_same_ack_and_one_inbox_row() {
        let lab = AppLab::new();
        let packed = lab.seal("once");
        let first = lab.deliver(&packed);
        let again = lab.deliver(&packed);
        assert_eq!(first.len(), 1, "ACKed once stored");
        assert_eq!(first, again, "byte-identical ACK");
        assert_eq!(lab.bob_inbox_len(), 1);
        assert_eq!(lab.bob_history().len(), 1, "{:?}", lab.bob_history());
    }

    #[test]
    fn a_revoked_peer_give_up_records_why_on_the_app_record() {
        use crate::app_store::{AppOutRecord, AppStore, Dedup, MetadataOnly, OutState};
        let lab = AppLab::new();
        let _ = lab.seal(&app_frame("a2a-request/1", 7, "{}"));
        let mut store = IndexedSessionStore::open(lab.a_dir.path()).unwrap();
        let row = store
            .awaiting_ack_endpoint_outbound()
            .unwrap()
            .pop()
            .unwrap();
        let peer = lab.b_bundle.cert.device_ed_pub;
        AppStore::open(lab.a_dir.path(), &MetadataOnly)
            .unwrap()
            .put_record(
                &AppOutRecord {
                    peer_identity: peer,
                    client_ref: "task-1".into(),
                    peer_device: peer,
                    content_type: "a2a-request/1".into(),
                    app_id: [7; 16],
                    body_sha256: [6; 32],
                    message_id: row.message_id,
                    session_id: row.session_id,
                    object_digest: row.object_digest,
                    created_at_ms: now(),
                    expires_at_ms: now() + 600_000,
                    state: OutState::Queued,
                    last_error_code: String::new(),
                    attempt_seq: 0,
                },
                now(),
            )
            .unwrap();
        crate::outbox::abandon_undelivered_to_peer(lab.a_dir.path(), &mut store, &peer).unwrap();
        assert!(store.awaiting_ack_endpoint_outbound().unwrap().is_empty());
        let app = AppStore::open(lab.a_dir.path(), &MetadataOnly).unwrap();
        let got = app.record_by_message(&row.message_id).unwrap().unwrap();
        assert_eq!(got.state, OutState::Failed);
        assert_eq!(got.last_error_code, crate::outbox::PEER_REVOKED);
        // A resend of the same task is refused, not retried.
        assert_eq!(
            app.dedup(&peer, "task-1", "a2a-request/1", &[6; 32], true)
                .unwrap(),
            Dedup::LineageRevoked
        );
    }

    #[test]
    fn a_full_app_inbox_defers_app_frames_but_never_chat() {
        let _lab = LabGuard::set(true);
        let lab = AppLab::new();
        let cap = crate::app_store::APP_INBOX_MAX_PER_SENDER_TYPE as u8;
        for i in 0..cap {
            assert_eq!(
                lab.deliver(&lab.seal(&app_frame("test/1", 10 + i, "fill")))
                    .len(),
                1
            );
        }
        let over = lab.seal(&app_frame("test/1", 200, "over the cap"));
        assert!(lab.deliver(&over).is_empty(), "deferred at the cap");
        assert_eq!(lab.deliver(&lab.seal("chat still flows")).len(), 1);
        // An answer type has its own cap.
        assert_eq!(
            lab.deliver(&lab.seal(&app_frame("a2a-response/1", 201, "{}")))
                .len(),
            1
        );
        // Room again after the consumer acks one: the retry is stored.
        let first = lab.bob_app_items()[0].clone();
        let sealer = crate::app_store::PlatformRowSealer::new(lab.b_dir.path());
        crate::app_store::AppStore::open(lab.b_dir.path(), &sealer)
            .unwrap()
            .ack(
                "rdap:test",
                &first.sender_device,
                &first.message_id,
                crate::app_store::Disposition::Done,
                now(),
            )
            .unwrap();
        assert_eq!(lab.deliver(&over).len(), 1);
        let _ = (&lab.bob, &lab.b_bundle);
    }

    #[test]
    fn pair_init_message_ack_dispatch() {
        let alice = Identity::from_seed(&[0xa1; 32]);
        let bob = Identity::from_seed(&[0xb2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();

        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let alice_noise = alice.public_key_bytes();
        let pair_replies =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap();
        assert_eq!(pair_replies.len(), 1);
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();

        let (a_cert, a_reg) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        let local_device =
            AuthorizedEndpointDevice::authorize(&a_cert, &alice, &a_reg, now()).unwrap();
        let t = now();
        let expires =
            envelope_expires(t, a_store.session_expires_at(&record_key).unwrap()).unwrap();
        let mut queued = None;
        a_store
            .send_message_envelope(
                &record_key,
                "hello lan",
                &local_device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    queued = Some((*digest, bytes.to_vec()));
                    Ok(*digest)
                },
            )
            .unwrap();
        let packed = queued.unwrap().1;
        let replies = dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &packed).unwrap();
        assert_eq!(replies.len(), 1);

        let mut b_store = IndexedSessionStore::open(b_dir.path()).unwrap();
        let inbox = b_store.list_endpoint_inbox().unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].plaintext, b"hello lan");
        let history = ChatHistory::load(b_dir.path()).unwrap();
        let rows = history.for_peer(&hex::encode(a_bundle.cert.device_ed_pub));
        assert!(
            rows.iter()
                .any(|e| e.preview.contains("hello lan") && e.direction == "in"),
            "inbound must be in durable ChatHistory"
        );

        a_store
            .accept_ack_envelope(&record_key, &replies[0], &b_bundle.cert, false, now())
            .unwrap();

        let replay_pair =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap();
        assert_eq!(replay_pair.len(), 1);
        assert!(matches!(
            classify_packed_envelope(&replay_pair[0]),
            PairInitOobClassify::PairResponse(_)
        ));

        let replay_ack =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &packed).unwrap();
        assert_eq!(replay_ack.len(), 1);
        assert_eq!(replay_ack[0], replies[0]);
    }

    /// Cutoff pack CP.7: the clocked dispatch says how far a contact's clock
    /// runs ahead when its PairInit, message or ACK is refused as dated in
    /// our future, and that it agrees once one is accepted; every refusal
    /// keeps its text.
    #[test]
    fn dispatch_reports_the_contacts_clock_and_keeps_every_refusal() {
        const MIN: i64 = 60_000;
        let set = crate::clock::set_for_this_thread;
        let alice = Identity::from_seed(&[0xa9; 32]);
        let bob = Identity::from_seed(&[0xb9; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        // Trust material from 20 minutes ago, so a clock 10 minutes back
        // still accepts both bundles.
        set(Some(-20 * MIN));
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        set(None);
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let link = || crate::friend_custody::InboundLink {
            carrier: crate::outbox::OutboxCarrier::Lan,
            source: None,
        };
        let alice_noise = alice.public_key_bytes();
        let bob_noise = bob.public_key_bytes();
        let ahead_min = |clock: Option<PeerClock>| match clock {
            Some(PeerClock::Ahead(ms)) => crate::clock_skew::minutes(ms as i64),
            other => panic!("not ahead: {other:?}"),
        };

        // Bob's clock 10 minutes behind: Alice's PairInit is refused.
        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        set(Some(-10 * MIN));
        let mut clock = None;
        let err = dispatch_frame_clocked(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice_noise,
            &init_frame,
            link(),
            &mut clock,
        )
        .unwrap_err();
        assert!(err.starts_with("PairInit validation failed: "), "{err}");
        assert_eq!(ahead_min(clock), 10);
        // In time: accepted.
        set(None);
        let mut clock = None;
        let replies = dispatch_frame_clocked(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice_noise,
            &init_frame,
            link(),
            &mut clock,
        )
        .unwrap();
        assert_eq!(clock, Some(PeerClock::Agrees));
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();

        // Alice's clock 10 minutes ahead seals a message: refused by Bob.
        set(Some(10 * MIN));
        let (a_cert, a_reg) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        let device = AuthorizedEndpointDevice::authorize(&a_cert, &alice, &a_reg, now()).unwrap();
        let t = now();
        let expires =
            envelope_expires(t, a_store.session_expires_at(&record_key).unwrap()).unwrap();
        let mut packed = None;
        a_store
            .send_message_envelope(
                &record_key,
                "from ahead",
                &device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    packed = Some(bytes.to_vec());
                    Ok(*digest)
                },
            )
            .unwrap();
        let packed = packed.unwrap();
        set(None);
        let mut clock = None;
        let err = dispatch_frame_clocked(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice_noise,
            &packed,
            link(),
            &mut clock,
        )
        .unwrap_err();
        assert_eq!(
            err,
            IndexedSessionStoreError::EndpointNotCurrentlyValid.redacted_display()
        );
        assert_eq!(ahead_min(clock), 10);
        // Bob's clock 6 minutes ahead: in time, accepted, and his ACK is
        // dated 6 minutes in Alice's future.
        set(Some(6 * MIN));
        let mut clock = None;
        let acks = dispatch_frame_clocked(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice_noise,
            &packed,
            link(),
            &mut clock,
        )
        .unwrap();
        assert_eq!(clock, Some(PeerClock::Agrees));
        assert_eq!(acks.len(), 1);
        set(None);
        let mut clock = None;
        let err = dispatch_frame_clocked(
            a_dir.path(),
            &alice,
            &b_bundle,
            &bob_noise,
            &acks[0],
            link(),
            &mut clock,
        )
        .unwrap_err();
        assert_eq!(
            err,
            IndexedSessionStoreError::EndpointNotCurrentlyValid.redacted_display()
        );
        assert_eq!(ahead_min(clock), 6);
        set(Some(2 * MIN));
        let mut clock = None;
        dispatch_frame_clocked(
            a_dir.path(),
            &alice,
            &b_bundle,
            &bob_noise,
            &acks[0],
            link(),
            &mut clock,
        )
        .unwrap();
        assert_eq!(clock, Some(PeerClock::Agrees));
        set(None);
    }

    #[test]
    fn mid_session_rlb1_must_match_noise_and_peer_device() {
        let alice = Identity::from_seed(&[0xa3; 32]);
        let bob = Identity::from_seed(&[0xb4; 32]);
        let mallory = Identity::from_seed(&[0xc5; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let m_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        publish_and_install(m_dir.path(), &mallory);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let m_bundle = local_bundle(m_dir.path(), &mallory).unwrap();
        let alice_noise = alice.public_key_bytes();
        let foreign = encode_offer(&m_bundle).unwrap();
        let err =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &foreign).unwrap_err();
        assert!(
            err.contains("mismatch") || err.contains("drift"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn peer_cache_rejects_corrupt_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PEER_CERT_CACHE);
        std::fs::write(&path, b"{not-json").unwrap();
        let err = load_peer_cert_map_checked(dir.path()).unwrap_err();
        assert!(err.contains("corrupt"));
    }

    #[test]
    fn unknown_peer_stays_ephemeral_not_durable() {
        let alice = Identity::from_seed(&[0xd1; 32]);
        let dir = tempfile::tempdir().unwrap();
        publish_and_install(dir.path(), &alice);
        let bundle = local_bundle(dir.path(), &alice).unwrap();
        cache_peer_bundle(dir.path(), &bundle).unwrap();
        assert!(load_ephemeral_peer(dir.path(), &bundle.cert.device_ed_pub).is_some());
        assert!(!dir.path().join(PEER_CERT_CACHE).exists());
        assert!(
            !peer_is_trusted(dir.path(), &bundle).unwrap(),
            "no contact yet"
        );
    }

    /// F4 link gate: same contact rule as `peer_is_trusted`, plus the block
    /// list, keyed by the bound Noise identity; fails closed on unreadable files
    /// and never names the key in its reason.
    #[test]
    fn link_admission_is_contact_and_not_blocked_only() {
        let dir = tempfile::tempdir().unwrap();
        let friend = [0x41u8; 32];
        let stranger = [0x42u8; 32];
        assert_eq!(
            link_peer_admission(dir.path(), &friend),
            Err(LINK_REFUSED_NOT_CONTACT),
            "no contact book"
        );
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}"}}]"#,
                hex::encode(friend).to_uppercase()
            ),
        )
        .unwrap();
        assert_eq!(link_peer_admission(dir.path(), &friend), Ok(()));
        assert_eq!(
            link_peer_admission(dir.path(), &stranger),
            Err(LINK_REFUSED_NOT_CONTACT)
        );
        let mut blocks = BlockList::default();
        blocks.block(&hex::encode(friend));
        blocks.save(dir.path()).unwrap();
        assert_eq!(
            link_peer_admission(dir.path(), &friend),
            Err(LINK_REFUSED_BLOCKED)
        );
        std::fs::write(crate::chat_history::blocked_path(dir.path()), "{corrupt").unwrap();
        assert_eq!(
            link_peer_admission(dir.path(), &friend),
            Err(LINK_REFUSED_BLOCKED),
            "unreadable block list admits nobody"
        );
        std::fs::write(dir.path().join("contacts.json"), "not json").unwrap();
        assert_eq!(
            link_peer_admission(dir.path(), &friend),
            Err(LINK_REFUSED_NOT_CONTACT),
            "unreadable contact book admits nobody"
        );
        for reason in [LINK_REFUSED_NOT_CONTACT, LINK_REFUSED_BLOCKED] {
            assert!(!reason.contains(&hex::encode(friend)));
            // The smoke scripts grep the service log for this phrase.
            assert!(reason.contains("not a local contact") || reason.contains("blocked"));
        }
    }

    /// E1 (three machines): right after an Unlock the key loader still held
    /// the book, and a verified friend's every link was refused as a
    /// stranger's ("not a local contact"). A held book judges nobody: the
    /// friend, a stranger and a blocked key all get the same not-ready
    /// answer (never "not a contact"), and once the book opens each its own.
    #[test]
    fn a_held_book_judges_nobody() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let (friend, stranger, blocked) = ([0x51u8; 32], [0x52u8; 32], [0x53u8; 32]);
        std::fs::write(
            dd.join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","pinned":true}},{{"pub_hex":"{}","pinned":true}}]"#,
                hex::encode(friend),
                hex::encode(blocked)
            ),
        )
        .unwrap();
        let mut blocks = BlockList::default();
        blocks.block(&hex::encode(blocked));
        blocks.save(dd).unwrap();
        let lan = |key: &[u8; 32]| {
            link_admission(
                dd,
                key,
                crate::outbox::OutboxCarrier::Lan,
                Some("192.168.1.20".parse().unwrap()),
            )
        };
        crate::contact_book::hold(dd, "raven-node is waiting for the at-rest key");
        for key in [&friend, &stranger, &blocked] {
            assert_eq!(lan(key), Err(LINK_REFUSED_NOT_READY));
            assert_eq!(link_peer_admission(dd, key), Err(LINK_REFUSED_NOT_READY));
        }
        assert!(!LINK_REFUSED_NOT_READY.contains("not a local contact"));
        crate::contact_book::enable_process_cache(dd);
        assert_eq!(lan(&friend), Ok(()));
        assert_eq!(lan(&stranger), Err(LINK_REFUSED_NOT_CONTACT));
        assert_eq!(lan(&blocked), Err(LINK_REFUSED_BLOCKED));
    }

    /// Owner decision 2026-10-08 on the listeners: an unverified contact is
    /// accepted on LAN direct from a local-network source only, never on
    /// Internet direct; a verified one is accepted from anywhere. Refused
    /// contacts get the stranger's treatment.
    #[test]
    fn link_admission_needs_a_verified_contact_beyond_the_local_network() {
        use crate::outbox::OutboxCarrier::{Internet, Lan};
        let dir = tempfile::tempdir().unwrap();
        let (plain, pinned, stranger) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}"}},{{"pub_hex":"{}","pinned":true}}]"#,
                hex::encode(plain),
                hex::encode(pinned)
            ),
        )
        .unwrap();
        let ip = |s: &str| Some(s.parse::<std::net::IpAddr>().unwrap());
        let admit =
            |key: &[u8; 32], carrier, source| link_admission(dir.path(), key, carrier, source);
        // LAN: an unverified contact from the local network only.
        assert_eq!(admit(&plain, Lan, ip("192.168.1.20")), Ok(()));
        assert_eq!(admit(&plain, Lan, ip("::ffff:10.0.0.4")), Ok(()));
        for remote in [ip("203.0.113.7"), ip("100.64.1.1"), ip("2001:db8::1"), None] {
            assert_eq!(
                admit(&plain, Lan, remote),
                Err(LINK_REFUSED_NOT_VERIFIED),
                "{remote:?}"
            );
        }
        assert_eq!(admit(&pinned, Lan, ip("203.0.113.7")), Ok(()));
        // Internet: verified contacts only, whatever the source.
        assert_eq!(
            admit(&plain, Internet, ip("127.0.0.1")),
            Err(LINK_REFUSED_NOT_VERIFIED)
        );
        assert_eq!(admit(&pinned, Internet, ip("203.0.113.7")), Ok(()));
        assert_eq!(
            admit(&stranger, Lan, ip("127.0.0.1")),
            Err(LINK_REFUSED_NOT_CONTACT)
        );
        assert!(!LINK_REFUSED_NOT_VERIFIED.contains(&hex::encode(plain)));
    }

    /// Phase 3 P3.C2 (cutoff M1): with `raven lan verified-only on` an
    /// unverified contact is refused on the LAN from any source, local ones
    /// too (where every source is local in a cutoff), before our bind; a
    /// verified one is admitted as before, a stranger and a blocked key keep
    /// their own refusals, and the Internet rule is unchanged. An unreadable
    /// policy counts as on (fail closed); off again admits as before.
    #[test]
    fn link_admission_under_verified_only_needs_a_pinned_contact_on_the_lan() {
        use crate::outbox::OutboxCarrier::{Internet, Lan};
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let (plain, pinned, stranger) = ([0x41u8; 32], [0x42u8; 32], [0x43u8; 32]);
        std::fs::write(
            dd.join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}"}},{{"pub_hex":"{}","pinned":true}}]"#,
                hex::encode(plain),
                hex::encode(pinned)
            ),
        )
        .unwrap();
        let ip = |s: &str| Some(s.parse::<std::net::IpAddr>().unwrap());
        let admit = |key: &[u8; 32], carrier, source| link_admission(dd, key, carrier, source);
        let set = |on: bool| {
            crate::node_policy::set_lan_verified_only(dd, on).unwrap();
        };
        set(true);
        for local in [ip("192.168.1.20"), ip("127.0.0.1"), ip("fe80::1")] {
            assert_eq!(
                admit(&plain, Lan, local),
                Err(LINK_REFUSED_VERIFIED_ONLY),
                "{local:?}"
            );
            assert_eq!(admit(&pinned, Lan, local), Ok(()));
            assert_eq!(admit(&stranger, Lan, local), Err(LINK_REFUSED_NOT_CONTACT));
        }
        // Beyond the local network the older reason holds.
        assert_eq!(
            admit(&plain, Lan, ip("203.0.113.7")),
            Err(LINK_REFUSED_NOT_VERIFIED)
        );
        assert_eq!(admit(&pinned, Internet, ip("203.0.113.7")), Ok(()));
        assert!(LINK_REFUSED_VERIFIED_ONLY.starts_with(crate::lan_gate::LAN_VERIFIED_ONLY));
        assert!(!LINK_REFUSED_VERIFIED_ONLY.contains(&hex::encode(plain)));
        // An unreadable policy: verified contacts only.
        std::fs::write(dd.join("node_policy.json"), b"{\"lan_off\": fals").unwrap();
        assert_eq!(
            admit(&plain, Lan, ip("192.168.1.20")),
            Err(LINK_REFUSED_VERIFIED_ONLY)
        );
        std::fs::remove_file(dd.join("node_policy.json")).unwrap();
        set(false);
        assert_eq!(admit(&plain, Lan, ip("192.168.1.20")), Ok(()));
    }

    #[test]
    fn pair_init_refuses_stranger_without_durable_state() {
        let alice = Identity::from_seed(&[0xa1; 32]);
        let bob = Identity::from_seed(&[0xb2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        // A treats B as a contact so initiator can build PairInit; B has no contact for A.
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        remember_ephemeral_peer(b_dir.path(), &a_bundle).unwrap();
        let claims_before = PrekeyLifecycleActor::open(b_dir.path())
            .unwrap()
            .status()
            .unwrap()
            .accepted_claims;
        let (init, _) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let alice_noise = alice.public_key_bytes();
        let err =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap_err();
        assert!(err.contains("not a local contact"), "unexpected: {err}");
        assert!(
            !b_dir.path().join(PEER_CERT_CACHE).exists(),
            "stranger PairInit must not durable-poison peer cache"
        );
        assert!(!b_dir.path().join("lan_pair_response").exists());
        let mut sessions = IndexedSessionStore::open(b_dir.path()).unwrap();
        assert!(sessions
            .find_confirmed_session_for_peer(&a_bundle.cert.device_ed_pub)
            .unwrap()
            .is_none());
        assert!(sessions.list_record_keys().unwrap().is_empty());
        let claims_after = PrekeyLifecycleActor::open(b_dir.path())
            .unwrap()
            .status()
            .unwrap()
            .accepted_claims;
        assert_eq!(claims_before, claims_after);
        assert!(!peer_is_trusted(b_dir.path(), &a_bundle).unwrap());
    }

    #[test]
    fn create_initiator_refuses_stranger() {
        let alice = Identity::from_seed(&[0xa8; 32]);
        let bob = Identity::from_seed(&[0xb9; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let err = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap_err();
        assert!(err.contains("not a local contact"), "unexpected: {err}");
    }

    #[test]
    fn contact_makes_peer_trusted_for_durable_cache() {
        let alice = Identity::from_seed(&[0xd2; 32]);
        let bob = Identity::from_seed(&[0xd3; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let contacts = serde_json::json!([{
            "petname": "Bob",
            "pub_hex": hex::encode(b_bundle.cert.device_ed_pub),
            "address": "",
        }]);
        std::fs::write(
            a_dir.path().join("contacts.json"),
            serde_json::to_string_pretty(&contacts).unwrap(),
        )
        .unwrap();
        assert!(peer_is_trusted(a_dir.path(), &b_bundle).unwrap());
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        assert!(a_dir.path().join(PEER_CERT_CACHE).exists());
        let loaded = load_cached_peer_bundle(a_dir.path(), &b_bundle.cert.device_ed_pub)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.cert.device_ed_pub, b_bundle.cert.device_ed_pub);
    }

    #[test]
    fn an_inbound_contact_is_kept_durably_once_and_a_stranger_never() {
        let alice = Identity::from_seed(&[0xd7; 32]);
        let bob = Identity::from_seed(&[0xd8; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        // A stranger dialling in leaves nothing on disk.
        assert!(!remember_inbound_contact(a_dir.path(), &b_bundle).unwrap());
        assert!(!a_dir.path().join(PEER_CERT_CACHE).exists());
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        assert!(remember_inbound_contact(a_dir.path(), &b_bundle).unwrap());
        let kept = load_durable_peer_cert_raw(a_dir.path(), &b_bundle.cert.device_ed_pub)
            .unwrap()
            .unwrap();
        assert_eq!(kept, b_bundle.cert);
        // Already kept: never rewritten (the dialling side owns updates).
        assert!(!remember_inbound_contact(a_dir.path(), &b_bundle).unwrap());
    }

    #[test]
    fn persist_trusted_refuses_unknown() {
        let alice = Identity::from_seed(&[0xd4; 32]);
        let dir = tempfile::tempdir().unwrap();
        publish_and_install(dir.path(), &alice);
        let bundle = local_bundle(dir.path(), &alice).unwrap();
        let err = persist_trusted_peer_bundle(dir.path(), &bundle).unwrap_err();
        assert!(err.contains("untrusted"));
    }

    #[test]
    fn durable_cache_stage_failure_leaves_no_partial_finals() {
        let alice = Identity::from_seed(&[0xd5; 32]);
        let bob = Identity::from_seed(&[0xd6; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let contacts = serde_json::json!([{
            "petname": "Bob",
            "pub_hex": hex::encode(b_bundle.cert.device_ed_pub),
            "address": "",
        }]);
        std::fs::write(
            a_dir.path().join("contacts.json"),
            serde_json::to_string_pretty(&contacts).unwrap(),
        )
        .unwrap();
        FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.set(true));
        let err = persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap_err();
        FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.set(false));
        assert!(err.contains("injected"));
        // Stage may remain for recovery; finals must not appear without successful apply.
        // Recovery should finish the apply on next persist/load.
        assert!(a_dir.path().join(PEER_CACHE_STAGE).exists());
        assert!(!a_dir.path().join(PEER_CERT_CACHE).exists());
        // Next successful path recovers from stage.
        recover_peer_cache_stage(a_dir.path()).unwrap();
        assert!(a_dir.path().join(PEER_CERT_CACHE).exists());
        assert!(!a_dir.path().join(PEER_CACHE_STAGE).exists());
        assert!(a_dir.path().join("peer_cache.generation").exists());
    }

    /// Privacy pack PP.5: in a sealed profile the dual write works on sealed
    /// bytes. A crash after the stage, after the certificates, after the
    /// prekey store or after the generation leaves only sealed files and the
    /// stage; the next lookup replays it (re-opening its sealed bytes) into
    /// the same cache, sealed.
    #[test]
    fn sealed_peer_cache_dual_write_survives_a_crash_at_each_point() {
        let alice = Identity::from_seed(&[0x3d; 32]);
        let bob = Identity::from_seed(&[0x3e; 32]);
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let sealed = |dir: &Path, name: &str| {
            std::fs::read(dir.join(name)).is_ok_and(|raw| crate::at_rest::is_sealed(&raw))
        };
        for crash in 0u8..=3 {
            let a = crate::contact_book::tests::profile();
            let a_dir = a.path();
            publish_and_install(a_dir, &alice);
            write_contact(a_dir, &b_bundle.cert.device_ed_pub, "Bob");
            crate::contact_book::tests::seal(a_dir);
            if crash == 0 {
                FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.set(true));
            } else {
                CRASH_IN_PEER_CACHE_REPLAY.with(|armed| armed.set(crash));
            }
            let err = persist_trusted_peer_bundle(a_dir, &b_bundle).unwrap_err();
            FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.set(false));
            assert!(err.contains("injected"), "{crash}: {err}");
            assert!(
                sealed(a_dir, PEER_CACHE_STAGE),
                "{crash}: the stage waits, sealed"
            );
            for name in [PEER_CERT_CACHE, crate::prekey_bundle::PREKEY_STORE_FILE] {
                let exists = a_dir.join(name).exists();
                assert!(!exists || sealed(a_dir, name), "{crash}: {name} in plain");
            }
            assert_eq!(a_dir.join(PEER_CERT_CACHE).exists(), crash >= 1, "{crash}");
            forget_ephemeral_peers(a_dir);
            let got = load_cached_peer_bundle(a_dir, &b_bundle.cert.device_ed_pub)
                .unwrap()
                .expect("replayed");
            assert_eq!(
                (got.cert.user_ed_pub, got.prekey.signed_prekey_id),
                (b_bundle.cert.user_ed_pub, b_bundle.prekey.signed_prekey_id),
                "{crash}"
            );
            assert!(!a_dir.join(PEER_CACHE_STAGE).exists(), "{crash}");
            for name in [PEER_CERT_CACHE, crate::prekey_bundle::PREKEY_STORE_FILE] {
                assert!(sealed(a_dir, name), "{crash}: {name}");
            }
            let generation = std::fs::read_to_string(a_dir.join("peer_cache.generation")).unwrap();
            assert!(
                generation.trim().parse::<u64>().unwrap() > 0,
                "plain: a number"
            );
        }
    }

    /// A sealed stage this process cannot open yet (its key not loaded) is
    /// kept for the next try, never quarantined; one that does not open
    /// under this profile's key (a changed byte) is set aside like an
    /// unparsable stage.
    #[test]
    fn a_sealed_stage_waits_for_its_key_and_a_tampered_one_is_set_aside() {
        let alice = Identity::from_seed(&[0x3f; 32]);
        let a = crate::contact_book::tests::profile();
        let a_dir = a.path();
        publish_and_install(a_dir, &alice);
        crate::contact_book::tests::seal(a_dir);
        let stage = PeerCacheStage {
            generation: 1,
            certs_json: "{}".into(),
            prekey_json: "{}".into(),
        };
        write_peer_cache_file(
            a_dir,
            &peer_cache_stage_path(a_dir),
            Kind::PeerCacheStage,
            &serde_json::to_vec(&stage).unwrap(),
        )
        .unwrap();
        let bytes = std::fs::read(peer_cache_stage_path(a_dir)).unwrap();
        crate::at_rest::forget_cached_keys(a_dir);
        let err = recover_peer_cache_stage(a_dir).unwrap_err();
        assert!(err.starts_with("peer cache stage read:"), "{err}");
        assert_eq!(std::fs::read(peer_cache_stage_path(a_dir)).unwrap(), bytes);
        crate::at_rest::keys_load_with(a_dir, crate::at_rest::MigratePolicy::Allow).unwrap();
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(peer_cache_stage_path(a_dir), &changed).unwrap();
        recover_peer_cache_stage(a_dir).unwrap();
        assert!(!peer_cache_stage_path(a_dir).exists());
        assert_eq!(
            std::fs::read(a_dir.join("peer_cache.stage.json.corrupt")).unwrap(),
            changed
        );
    }

    #[test]
    fn recover_discards_invalid_stage_payload() {
        let dir = tempfile::tempdir().unwrap();
        let stage = PeerCacheStage {
            generation: 1,
            certs_json: r#"{"bad":"not-a-cert"}"#.into(),
            prekey_json: r#"{"bundles":{}}"#.into(),
        };
        std::fs::write(
            dir.path().join(PEER_CACHE_STAGE),
            serde_json::to_string_pretty(&stage).unwrap(),
        )
        .unwrap();
        let err = recover_peer_cache_stage(dir.path()).unwrap_err();
        assert!(
            err.contains("stage") || err.contains("corrupt") || err.contains("empty"),
            "unexpected: {err}"
        );
        assert!(!dir.path().join(PEER_CACHE_STAGE).exists());
        assert!(!dir.path().join(PEER_CERT_CACHE).exists());
    }

    #[test]
    fn recover_discards_stale_generation_stage() {
        let alice = Identity::from_seed(&[0xd7; 32]);
        let bob = Identity::from_seed(&[0xd8; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let committed = read_committed_peer_cache_generation(a_dir.path()).unwrap();
        assert!(committed > 0);
        let stale = PeerCacheStage {
            generation: committed.saturating_sub(1),
            certs_json: r#"{}"#.into(),
            prekey_json: r#"{"bundles":{}}"#.into(),
        };
        std::fs::write(
            a_dir.path().join(PEER_CACHE_STAGE),
            serde_json::to_string_pretty(&stale).unwrap(),
        )
        .unwrap();
        recover_peer_cache_stage(a_dir.path()).unwrap();
        assert!(!a_dir.path().join(PEER_CACHE_STAGE).exists());
        assert!(a_dir.path().join(PEER_CERT_CACHE).exists());
    }

    #[test]
    fn corrupt_generation_file_is_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("peer_cache.generation"), b"not-a-number\n").unwrap();
        let err = read_committed_peer_cache_generation(dir.path()).unwrap_err();
        assert!(err.contains("corrupt"), "unexpected: {err}");
    }

    #[test]
    fn lan_bundle_rejects_identity_mismatch() {
        let alice = Identity::from_seed(&[0xe1; 32]);
        let bob = Identity::from_seed(&[0xe2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let mixed = LanBundle {
            cert: a_bundle.cert.clone(),
            prekey: b_bundle.prekey.clone(),
        };
        let err = mixed.require_identity_bound().unwrap_err();
        assert!(err.contains("mismatch"), "unexpected: {err}");
        write_contact(a_dir.path(), &a_bundle.cert.device_ed_pub, "Self");
        let err = persist_trusted_peer_bundle(a_dir.path(), &mixed).unwrap_err();
        assert!(
            err.contains("mismatch") || err.contains("identity"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn message_path_refuses_removed_contact() {
        let alice = Identity::from_seed(&[0xf1; 32]);
        let bob = Identity::from_seed(&[0xf2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let alice_noise = alice.public_key_bytes();
        let pair_replies =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();
        let (a_cert, a_reg) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        let local_device =
            AuthorizedEndpointDevice::authorize(&a_cert, &alice, &a_reg, now()).unwrap();
        let t = now();
        let expires =
            envelope_expires(t, a_store.session_expires_at(&record_key).unwrap()).unwrap();
        let mut queued = None;
        a_store
            .send_message_envelope(
                &record_key,
                "after revoke contact",
                &local_device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    queued = Some((*digest, bytes.to_vec()));
                    Ok(*digest)
                },
            )
            .unwrap();
        let packed = queued.unwrap().1;
        // Remove Alice from Bob's contacts — message/ACK must fail closed.
        std::fs::write(b_dir.path().join("contacts.json"), "[]").unwrap();
        let err = dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &packed).unwrap_err();
        assert!(err.contains("not a local contact"), "unexpected: {err}");
    }

    #[test]
    fn reconcile_outbound_stage_marks_delivered_after_ack_crash_window() {
        use crate::indexed_session_store::EndpointDeliveryState;

        let alice = Identity::from_seed(&[0xa7; 32]);
        let bob = Identity::from_seed(&[0xb8; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();

        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let alice_noise = alice.public_key_bytes();
        let pair_replies =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap();
        assert_eq!(pair_replies.len(), 1);
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();

        let (a_cert, a_reg) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        let local_device =
            AuthorizedEndpointDevice::authorize(&a_cert, &alice, &a_reg, now()).unwrap();
        let t = now();
        let expires =
            envelope_expires(t, a_store.session_expires_at(&record_key).unwrap()).unwrap();
        let mut queued = None;
        let outbound = a_store
            .send_message_envelope(
                &record_key,
                "reconcile-body",
                &local_device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    queued = Some((*digest, bytes.to_vec()));
                    Ok(*digest)
                },
            )
            .unwrap();
        let packed = queued.unwrap().1;
        let replies = dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &packed).unwrap();
        assert_eq!(replies.len(), 1);
        a_store
            .accept_ack_envelope(&record_key, &replies[0], &b_bundle.cert, false, now())
            .unwrap();
        assert_eq!(
            a_store
                .outstanding_delivery_state(
                    &outbound.session_id,
                    &outbound.message_id,
                    &b_bundle.cert.device_ed_pub
                )
                .unwrap(),
            Some(EndpointDeliveryState::Delivered)
        );

        // Crash window: ACK committed, history mark/stage clear not done — stage remains.
        stage_outbound_body(
            a_dir.path(),
            &b_bundle.cert.device_ed_pub,
            &outbound.session_id,
            &outbound.object_digest,
            &outbound.message_id,
            t,
            "reconcile-body",
        )
        .unwrap();
        reconcile_outbound_stage_history(a_dir.path()).unwrap();
        let history = ChatHistory::load(a_dir.path()).unwrap();
        let row = history
            .entries
            .iter()
            .find(|e| e.message_id_hex == hex::encode(outbound.message_id))
            .expect("history row");
        assert_eq!(row.delivery, "delivered");
        assert_eq!(row.body, "reconcile-body");
        assert!(
            load_staged_outbound_body(a_dir.path(), &outbound.message_id)
                .unwrap()
                .is_none()
        );
    }

    /// Review FU-5, through the prune: Bob and Carol are removed while their
    /// confirmed session is live (each removal leaves its mark); Bob is
    /// added back to the book and goes on using that session. When the prune
    /// deletes the sessions, Bob's end is remembered and Carol's is not.
    #[test]
    fn the_prune_remembers_the_end_of_a_contact_added_back() {
        use crate::indexed_session_store::{forget_session_end, SessionMetadataReader};
        let alice = Identity::from_seed(&[0xa5; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        // A confirmed session with the contact of `seed`: its device key and end.
        let pair = |seed: u8, name: &str| -> ([u8; 32], u64) {
            let peer = Identity::from_seed(&[seed; 32]);
            let p_dir = tempfile::tempdir().unwrap();
            publish_and_install(p_dir.path(), &peer);
            let p_bundle = local_bundle(p_dir.path(), &peer).unwrap();
            write_contact(a_dir.path(), &p_bundle.cert.device_ed_pub, name);
            write_contact(p_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
            cache_peer_bundle(p_dir.path(), &a_bundle).unwrap();
            cache_peer_bundle(a_dir.path(), &p_bundle).unwrap();
            let (init, record_key) =
                create_initiator_pair_init(a_dir.path(), &alice, &p_bundle).unwrap();
            let frame = wrap_pair_init(&alice, &init).unwrap();
            let replies = dispatch_frame(
                p_dir.path(),
                &peer,
                &a_bundle,
                &alice.public_key_bytes(),
                &frame,
            )
            .unwrap();
            let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0])
            else {
                panic!("expected PairResponse");
            };
            let response = crate::pair_init::decode_response(&wire).unwrap();
            let mut store = IndexedSessionStore::open(a_dir.path()).unwrap();
            store
                .confirm_verified_pair_response(&record_key, &init, &response, now())
                .unwrap();
            let end = store.session_expires_at(&record_key).unwrap();
            (p_bundle.cert.device_ed_pub, end)
        };
        let (bob, bob_end) = pair(0xb5, "Bob");
        let (carol, carol_end) = pair(0xc5, "Carol");
        // `raven contact remove` for both, then Bob is added back.
        std::fs::write(a_dir.path().join("contacts.json"), "[]").unwrap();
        forget_session_end(a_dir.path(), &bob).unwrap();
        forget_session_end(a_dir.path(), &carol).unwrap();
        write_contact(a_dir.path(), &bob, "Bob");
        let after = bob_end.max(carol_end);
        prune_lan_durable_state(a_dir.path(), after).unwrap();
        let reader = SessionMetadataReader::open(a_dir.path()).unwrap().unwrap();
        let ended = |peer: &[u8; 32]| reader.peer_horizon(peer, after).unwrap().ended_at_ms;
        assert_eq!(ended(&bob), Some(bob_end), "added back: remembered");
        assert_eq!(ended(&carol), None, "still removed: still erased");
    }

    /// Review C-time-deadlines-2: a prune that destroys a session first
    /// settles its outbound messages (prepared or handed to the queue) as
    /// expired, so a node that was off across the deadline never loses them
    /// silently; a staged body left without a row says expired once its
    /// session ended, failed while the session lives.
    #[test]
    fn a_prune_settles_the_messages_of_the_sessions_it_destroys() {
        let _horizon = HorizonHeld::on();
        let alice = Identity::from_seed(&[0xa3; 32]);
        let bob = Identity::from_seed(&[0xb3; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let pair_replies = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &init_frame,
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();
        let (a_cert, a_reg) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        let device = AuthorizedEndpointDevice::authorize(&a_cert, &alice, &a_reg, now()).unwrap();
        let bob_dev = b_bundle.cert.device_ed_pub;
        let session_end = a_store.session_expires_at(&record_key).unwrap();
        let session_id = a_store.session_id_for_record_key(&record_key).unwrap();
        // `raven send` while Bob is away: the first handed to the queue, the
        // second left prepared (its dial failed).
        let mut stage = |text: &str, hand_off: bool| -> [u8; 16] {
            let t = now();
            let mut mid = None;
            let _ = a_store.send_message_envelope(
                &record_key,
                text,
                &device,
                t,
                envelope_expires(t, session_end).unwrap(),
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    let env = Envelope::unpack(bytes).unwrap();
                    ensure_outbound_queued_history(
                        a_dir.path(),
                        &bob_dev,
                        &session_id,
                        digest,
                        &env.message_id,
                        t,
                        Some(text),
                    )
                    .unwrap();
                    mid = Some(env.message_id);
                    if hand_off {
                        Ok(*digest)
                    } else {
                        Err(())
                    }
                },
            );
            mid.expect("staged")
        };
        let queued = stage("handed to the queue", true);
        let prepared = stage("left prepared", false);
        let delivery = |mid: &[u8; 16]| {
            ChatHistory::load(a_dir.path())
                .unwrap()
                .entries
                .into_iter()
                .find(|e| e.direction == "out" && e.message_id_hex == hex::encode(mid))
                .map(|e| e.delivery)
        };
        // A staged body with no row under the live session: failed.
        let orphan = [0x5a; 16];
        stage_outbound_body(
            a_dir.path(),
            &bob_dev,
            &session_id,
            &[0x5a; 32],
            &orphan,
            now(),
            "orphan",
        )
        .unwrap();
        reconcile_outbound_stage_history(a_dir.path()).unwrap();
        assert_eq!(delivery(&orphan).as_deref(), Some("failed"));
        // Before the end nothing changes.
        prune_lan_durable_state(a_dir.path(), session_end - 1).unwrap();
        for mid in [&queued, &prepared] {
            assert_eq!(delivery(mid).as_deref(), Some("queued"));
        }
        // The prune that destroys the session settles both first.
        prune_lan_durable_state(a_dir.path(), session_end).unwrap();
        for mid in [&queued, &prepared] {
            assert_eq!(delivery(mid).as_deref(), Some("expired"));
            assert!(load_staged_outbound_body(a_dir.path(), mid)
                .unwrap()
                .is_none());
        }
        let store = IndexedSessionStore::open(a_dir.path()).unwrap();
        assert!(store.pending_endpoint_outbound().unwrap().is_empty());
        assert!(store.list_record_keys().unwrap().is_empty());
        // A staged body left behind once its session is gone: expired.
        let late = [0x5b; 16];
        stage_outbound_body(
            a_dir.path(),
            &bob_dev,
            &session_id,
            &[0x5b; 32],
            &late,
            now(),
            "late",
        )
        .unwrap();
        reconcile_outbound_stage_history(a_dir.path()).unwrap();
        assert_eq!(delivery(&late).as_deref(), Some("expired"));
    }

    /// P5.6 (the long message horizon): with its gate on, the prune that
    /// destroys a session parks its undelivered messages (stage, `queued`
    /// history and route record kept, deadline = written + horizon) instead
    /// of settling them expired, and the stage reconcile keeps a parked
    /// message and one parked and staged with the zero sentinel binding at
    /// `queued`, with their stages; a plain orphan still runs out, and so
    /// does a sentinel stage whose parked row is gone (review 5a-2).
    #[test]
    fn reconcile_outbound_stage_history_keeps_parked_and_sentinel_stages_queued() {
        let alice = Identity::from_seed(&[0xa6; 32]);
        let bob = Identity::from_seed(&[0xb6; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let pair_replies = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &init_frame,
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();
        let (a_cert, a_reg) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        let device = AuthorizedEndpointDevice::authorize(&a_cert, &alice, &a_reg, now()).unwrap();
        let bob_dev = b_bundle.cert.device_ed_pub;
        let session_end = a_store.session_expires_at(&record_key).unwrap();
        let session_id = a_store.session_id_for_record_key(&record_key).unwrap();
        // `raven send` while Bob is away: handed to the queue.
        let written = now();
        let mut mid = None;
        a_store
            .send_message_envelope(
                &record_key,
                "parked by the prune",
                &device,
                written,
                envelope_expires(written, session_end).unwrap(),
                written,
                &mut OsRng,
                &mut |digest, bytes| {
                    let env = Envelope::unpack(bytes).unwrap();
                    ensure_outbound_queued_history(
                        a_dir.path(),
                        &bob_dev,
                        &session_id,
                        digest,
                        &env.message_id,
                        written,
                        Some("parked by the prune"),
                    )
                    .unwrap();
                    mid = Some(env.message_id);
                    Ok(*digest)
                },
            )
            .unwrap();
        drop(a_store);
        let parked = mid.expect("staged");
        crate::outbox::record_object_routes(
            a_dir.path(),
            &parked,
            &bob_dev,
            crate::outbox::CarrierChoice::Auto,
            &[],
            session_end,
            now(),
        )
        .unwrap();
        let delivery = |mid: &[u8; 16]| {
            ChatHistory::load(a_dir.path())
                .unwrap()
                .entries
                .into_iter()
                .find(|e| e.direction == "out" && e.message_id_hex == hex::encode(mid))
                .map(|e| e.delivery)
        };
        let staged = |mid: &[u8; 16]| {
            load_staged_outbound_body(a_dir.path(), mid)
                .unwrap()
                .is_some()
        };
        crate::horizon::set_lab_horizon_for_this_thread(Some(true));
        prune_lan_durable_state(a_dir.path(), session_end).unwrap();
        assert_eq!(delivery(&parked).as_deref(), Some("queued"));
        assert!(staged(&parked), "the stage stays");
        let store = IndexedSessionStore::open(a_dir.path()).unwrap();
        assert!(store.list_record_keys().unwrap().is_empty(), "session gone");
        let rows = store.parked_for_recipient(&bob_dev).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message_id, parked);
        assert_eq!(rows[0].from_session, Some(session_id));
        assert_eq!(
            rows[0].deadline_ms,
            crate::horizon::message_deadline(written)
        );
        drop(store);
        let records = crate::outbox::object_route_records(a_dir.path(), session_end + 1).unwrap();
        assert_eq!(
            records[&parked].expires_at_ms,
            crate::horizon::message_deadline(written)
        );
        // Parked and staged before any session exists (P5.8): the zero
        // sentinel, its parked row written first.
        let sentinel = [0x5c; 16];
        assert!(IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .park_outbound(
                &bob_dev,
                &sentinel,
                None,
                now(),
                crate::horizon::message_deadline(now()),
                now()
            )
            .unwrap());
        stage_outbound_body(
            a_dir.path(),
            &bob_dev,
            &crate::horizon::SENTINEL_BINDING,
            &crate::horizon::SENTINEL_BINDING,
            &sentinel,
            now(),
            "no session yet",
        )
        .unwrap();
        // A sentinel stage whose parked row is gone (an older build's
        // contact removal dropped the row only, review 5a-2).
        let unparked = [0x5e; 16];
        stage_outbound_body(
            a_dir.path(),
            &bob_dev,
            &crate::horizon::SENTINEL_BINDING,
            &crate::horizon::SENTINEL_BINDING,
            &unparked,
            now(),
            "no row left",
        )
        .unwrap();
        // A staged body left behind once its session is gone, not parked.
        let orphan = [0x5d; 16];
        stage_outbound_body(
            a_dir.path(),
            &bob_dev,
            &session_id,
            &[0x5d; 32],
            &orphan,
            now(),
            "orphan",
        )
        .unwrap();
        reconcile_outbound_stage_history(a_dir.path()).unwrap();
        for mid in [&parked, &sentinel] {
            assert_eq!(delivery(mid).as_deref(), Some("queued"));
            assert!(staged(mid));
        }
        assert_eq!(delivery(&orphan).as_deref(), Some("expired"));
        assert!(!staged(&orphan));
        assert_eq!(delivery(&unparked).as_deref(), Some("failed"));
        assert!(!staged(&unparked));
        // The store says what waits, whatever the gate says now.
        crate::horizon::set_lab_horizon_for_this_thread(Some(false));
        reconcile_outbound_stage_history(a_dir.path()).unwrap();
        for mid in [&parked, &sentinel] {
            assert_eq!(delivery(mid).as_deref(), Some("queued"));
            assert!(staged(mid));
        }
        crate::horizon::set_lab_horizon_for_this_thread(None);
    }

    #[test]
    fn stage_capacity_preflight_blocks_before_outbox_reservation() {
        let alice = Identity::from_seed(&[0xa9; 32]);
        let bob = Identity::from_seed(&[0xba; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();

        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let alice_noise = alice.public_key_bytes();
        let pair_replies =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();
        let session_id = a_store.session_id_for_record_key(&record_key).unwrap();

        // Fill stage to entry cap so one more body is refused.
        for i in 0..256u16 {
            let mut mid = [0u8; 16];
            mid[14..].copy_from_slice(&i.to_be_bytes());
            let mut digest = [0u8; 32];
            digest[30..].copy_from_slice(&i.to_be_bytes());
            stage_outbound_body(
                a_dir.path(),
                &b_bundle.cert.device_ed_pub,
                &session_id,
                &digest,
                &mid,
                i as u64,
                "pad",
            )
            .unwrap();
        }
        assert!(matches!(
            crate::OutboundStageSendGuard::acquire(a_dir.path(), "another", now()),
            Err(crate::ChatHistoryError::TooLarge)
        ));
        assert!(
            a_store.pending_endpoint_outbound().unwrap().is_empty(),
            "preflight must run before any outbox reservation"
        );
        // Guarded send path: capacity failure means we never call send_message_envelope.
        let before = a_store.pending_endpoint_outbound().unwrap().len();
        assert!(crate::OutboundStageSendGuard::acquire(a_dir.path(), "x", now()).is_err());
        assert_eq!(
            a_store.pending_endpoint_outbound().unwrap().len(),
            before,
            "no new Prepared/Queued outbox after capacity refusal"
        );
    }

    fn confirm_alice_to_bob(
        a_dir: &Path,
        b_dir: &Path,
        alice: &Identity,
        bob: &Identity,
    ) -> (LanBundle, LanBundle) {
        let a_bundle = local_bundle(a_dir, alice).unwrap();
        let b_bundle = local_bundle(b_dir, bob).unwrap();
        write_contact(a_dir, &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir, &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir, &a_bundle).unwrap();
        cache_peer_bundle(a_dir, &b_bundle).unwrap();
        let (init, record_key) = create_initiator_pair_init(a_dir, alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(alice, &init).unwrap();
        let pair_replies = dispatch_frame(
            b_dir,
            bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &init_frame,
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();
        (a_bundle, b_bundle)
    }

    #[test]
    fn seal_under_session_roundtrip_with_lab_session() {
        let alice = Identity::from_seed(&[0xc1; 32]);
        let bob = Identity::from_seed(&[0xc2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let (_a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
        let peer_hint = hex::encode(b_bundle.cert.device_ed_pub);
        let packed =
            seal_app_payload_under_session(a_dir.path(), &alice, &peer_hint, b"m2-daemon-seal")
                .expect("lab session should seal under persisted ATSAM session");
        let env = Envelope::unpack(&packed).expect("RavenEnvelopeV1");
        assert_eq!(env.env_type, EnvType::Message as u8);
        assert!(!env.message_ciphertext.is_empty());
    }

    #[test]
    fn seal_under_session_refuses_without_session() {
        let alice = Identity::from_seed(&[0xc3; 32]);
        let bob = Identity::from_seed(&[0xc4; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let err = seal_app_payload_under_session(
            a_dir.path(),
            &alice,
            &hex::encode(b_bundle.cert.device_ed_pub),
            b"no-session",
        )
        .unwrap_err();
        assert!(
            err.starts_with(ATSAM_SESSION_REQUIRED),
            "expected {ATSAM_SESSION_REQUIRED}, got {err}"
        );
        assert!(
            !err.contains(ATSAM_LINEAGE_REVOKED),
            "missing session must not collapse into revoke: {err}"
        );
    }

    #[test]
    fn seal_under_session_revoked_lineage_is_hard_deny_before_seal() {
        let alice = Identity::from_seed(&[0xc5; 32]);
        let bob = Identity::from_seed(&[0xc6; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let (_a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);

        let rec =
            RevocationRecord::issue(&bob, &b_bundle.cert.device_id, 1, now(), "lost").unwrap();
        let mut rev = RevocationStore::load_checked(a_dir.path()).unwrap();
        assert!(rev.apply(rec).unwrap());
        rev.save(a_dir.path()).unwrap();

        let before = {
            let store = IndexedSessionStore::open(a_dir.path()).unwrap();
            store.pending_endpoint_outbound().unwrap().len()
        };
        let err = seal_app_payload_under_session(
            a_dir.path(),
            &alice,
            &hex::encode(b_bundle.cert.device_ed_pub),
            b"must-not-seal",
        )
        .unwrap_err();
        assert_eq!(
            err, ATSAM_LINEAGE_REVOKED,
            "revoked lineage must freeze ATSAM_LINEAGE_REVOKED, got {err}"
        );
        assert!(
            !err.contains(ATSAM_SESSION_REQUIRED),
            "do not collapse revoke to session-required: {err}"
        );
        let after = {
            let store = IndexedSessionStore::open(a_dir.path()).unwrap();
            store.pending_endpoint_outbound().unwrap().len()
        };
        assert_eq!(
            after, before,
            "lineage deny must run before seal crypto (no outbox reservation)"
        );
    }

    /// networking-core#0: a stranger's cert that names a contact's key as its
    /// device key (signed by the stranger) must not pass the identity bind or
    /// contact trust, and must not reach either cache.
    #[test]
    fn stranger_cannot_poison_contact_cache_via_foreign_device_key() {
        let alice = Identity::from_seed(&[0x31; 32]);
        let bob = Identity::from_seed(&[0x32; 32]);
        let mallory = Identity::from_seed(&[0x33; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let bob_pub = bob.public_key_bytes();
        let m_noise = mallory.public_key_bytes();
        write_contact(a_dir.path(), &bob_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();

        let forged = signed_bundle(&mallory, bob_pub, "x");
        assert!(
            forged.verify_bound(now()).is_ok(),
            "signatures alone verify"
        );
        assert!(!rlb1_matches_noise_identity(&forged, &m_noise));
        assert!(!rlb1_matches_noise_identity(&forged, &bob_pub));
        assert!(peer_is_trusted(a_dir.path(), &forged).is_err());
        assert!(remember_ephemeral_peer(a_dir.path(), &forged).is_err());
        assert!(cache_peer_bundle(a_dir.path(), &forged).is_err());
        assert!(persist_trusted_peer_bundle(a_dir.path(), &forged).is_err());

        // Mid-session RLB1 on Mallory's own (self-certified) connection.
        let m_self = signed_bundle(&mallory, m_noise, "ash-primary");
        let frame = encode_offer(&forged).unwrap();
        let err = dispatch_frame(a_dir.path(), &alice, &m_self, &m_noise, &frame).unwrap_err();
        assert!(err.contains("mismatch"), "unexpected: {err}");
        // The forged bundle as the connection peer is refused before any handler.
        assert!(dispatch_frame(a_dir.path(), &alice, &forged, &m_noise, &frame).is_err());

        let map = load_peer_cert_map_checked(a_dir.path()).unwrap();
        assert_eq!(map.len(), 1, "one slot for the one contact");
        assert_eq!(map[&hex::encode(bob_pub)], b_bundle.cert);
        let loaded = load_cached_peer_bundle(a_dir.path(), &bob_pub)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.cert, b_bundle.cert);
        assert!(PrekeyStore::load_checked(a_dir.path())
            .unwrap()
            .fetch(&m_noise, now())
            .unwrap()
            .is_none());
    }

    /// networking-core#0: unverified offers never enter the in-memory map, and
    /// throwaway identities cannot consume durable capacity or break later
    /// persistence for real contacts.
    #[test]
    fn stranger_flood_cannot_fill_caches_or_break_contact_persist() {
        let alice = Identity::from_seed(&[0x34; 32]);
        let bob = Identity::from_seed(&[0x35; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &bob.public_key_bytes(), "Bob");
        let store_before = PrekeyStore::load_checked(a_dir.path()).unwrap().len();

        for i in 0..24u8 {
            let m = Identity::from_seed(&[0x90u8.wrapping_add(i); 32]);
            let own = signed_bundle(&m, m.public_key_bytes(), "ash-primary");
            // Self-certified strangers stay ephemeral and never become durable.
            cache_peer_bundle(a_dir.path(), &own).unwrap();
            assert!(persist_trusted_peer_bundle(a_dir.path(), &own).is_err());
            // Cross-keyed certs naming the contact are refused outright.
            let cross = signed_bundle(&m, bob.public_key_bytes(), "ash-primary");
            assert!(cache_peer_bundle(a_dir.path(), &cross).is_err());
            // Tampered signatures never reach (or replace) the ephemeral entry.
            let mut bad_sig = own.clone();
            bad_sig.cert.not_after_ms += 1;
            assert!(remember_ephemeral_peer(a_dir.path(), &bad_sig).is_err());
            let kept = load_ephemeral_peer(a_dir.path(), &m.public_key_bytes()).unwrap();
            assert_eq!(kept.cert, own.cert);
        }
        assert!(load_ephemeral_peer(a_dir.path(), &bob.public_key_bytes()).is_none());
        assert!(!a_dir.path().join(PEER_CERT_CACHE).exists());
        assert_eq!(
            PrekeyStore::load_checked(a_dir.path()).unwrap().len(),
            store_before
        );
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let map = load_peer_cert_map_checked(a_dir.path()).unwrap();
        assert_eq!(map.len(), 1);
    }

    /// Per-contact slots: entries for peers no longer in contacts are pruned
    /// and a poisoned legacy entry (unverified key) is never served.
    #[test]
    fn durable_cache_is_per_contact_and_drops_unbound_entries() {
        let alice = Identity::from_seed(&[0x36; 32]);
        let bob = Identity::from_seed(&[0x37; 32]);
        let carol = Identity::from_seed(&[0x38; 32]);
        let mallory = Identity::from_seed(&[0x39; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let c_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        publish_and_install(c_dir.path(), &carol);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let c_bundle = local_bundle(c_dir.path(), &carol).unwrap();
        let contacts = serde_json::json!([
            {"petname": "Bob", "pub_hex": hex::encode(bob.public_key_bytes())},
            {"petname": "Carol", "pub_hex": hex::encode(carol.public_key_bytes())},
        ]);
        std::fs::write(
            a_dir.path().join("contacts.json"),
            serde_json::to_string(&contacts).unwrap(),
        )
        .unwrap();
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        persist_trusted_peer_bundle(a_dir.path(), &c_bundle).unwrap();
        let path = a_dir.path().join(PEER_CERT_CACHE);
        assert_eq!(load_peer_cert_map_checked(a_dir.path()).unwrap().len(), 2);

        // Older builds could leave a foreign cert under a contact's key.
        let forged = signed_bundle(&mallory, carol.public_key_bytes(), "x");
        let mut map = load_peer_cert_map_checked(a_dir.path()).unwrap();
        map.insert(hex::encode(carol.public_key_bytes()), forged.cert.clone());
        std::fs::write(&path, serde_json::to_string(&map).unwrap()).unwrap();
        clear_ephemeral(a_dir.path());
        assert!(
            load_cached_peer_bundle(a_dir.path(), &carol.public_key_bytes())
                .unwrap()
                .is_none()
        );

        // Carol leaves contacts: the next persist keeps only live contact slots.
        write_contact(a_dir.path(), &bob.public_key_bytes(), "Bob");
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let map = load_peer_cert_map_checked(a_dir.path()).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&hex::encode(bob.public_key_bytes())));
    }

    /// RAVEN_NEARBY_LINK_V1 §0: a contact's cached certificate outlives its
    /// prekey. Entries not keyed by their own self-certified signer, or out
    /// of their validity window, are absent; revocation is the caller's
    /// lineage check.
    #[test]
    fn cached_peer_certificate_survives_an_expired_prekey() {
        let bob = Identity::from_seed(&[0x4b; 32]);
        let mallory = Identity::from_seed(&[0x4c; 32]);
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let bob_pub = bob.public_key_bytes();
        assert_eq!(cached_peer_certificate(dd, &bob_pub).unwrap(), None);
        let (t, hour) = (now(), 3_600_000);
        let cert = DeviceCertificate::issue(
            &bob,
            bob_pub,
            [0x42; 32],
            PRIMARY_DEVICE_ID,
            t - 60_000,
            t + 365 * 24 * hour,
            0,
        )
        .unwrap();
        // A prekey that expired an hour ago, pinned while it was valid.
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        let prekey = PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            1,
            t - 2 * hour,
            t - hour,
        )
        .unwrap()
        .sign(&bob)
        .unwrap();
        let mut store = PrekeyStore::load_checked(dd).unwrap();
        store.publish(&prekey, t - 2 * hour + 1).unwrap();
        store.save(dd).unwrap();
        let write_cert = |cert: &DeviceCertificate| {
            let map = HashMap::from([(hex::encode(bob_pub), cert.clone())]);
            std::fs::write(
                dd.join(PEER_CERT_CACHE),
                serde_json::to_string(&map).unwrap(),
            )
            .unwrap();
        };
        write_cert(&cert);
        clear_ephemeral(dd);
        assert!(
            !matches!(load_cached_peer_bundle(dd, &bob_pub), Ok(Some(_))),
            "no bundle without a live prekey"
        );
        assert_eq!(
            cached_peer_certificate(dd, &bob_pub).unwrap(),
            Some(cert.clone())
        );
        assert_eq!(
            cached_peer_certificate(dd, &mallory.public_key_bytes()).unwrap(),
            None
        );
        // The caller's revocation check sees a revoked lineage.
        assert!(!crate::outbox::peer_lineage_denied(dd, &cert).unwrap());
        let rec = RevocationRecord::issue(&bob, &cert.device_id, 1, now(), "lost").unwrap();
        let mut rev = RevocationStore::load_checked(dd).unwrap();
        assert!(rev.apply(rec).unwrap());
        rev.save(dd).unwrap();
        assert!(crate::outbox::peer_lineage_denied(dd, &cert).unwrap());
        // Another signer's certificate under bob's key, and an expired one.
        let forged = signed_bundle(&mallory, bob_pub, "x").cert;
        let expired =
            DeviceCertificate::issue(&bob, bob_pub, [0x42; 32], PRIMARY_DEVICE_ID, 1, 50, 0)
                .unwrap();
        for bad in [forged, expired] {
            write_cert(&bad);
            assert_eq!(cached_peer_certificate(dd, &bob_pub).unwrap(), None);
        }
    }

    /// networking-core#1: the pre-seal revocation check uses the certificate
    /// bound into the session at PairInit, so a poisoned cache entry for the
    /// revoked peer's key can neither bypass the deny nor be sealed to.
    #[test]
    fn seal_revocation_uses_session_bound_cert_not_cached_offer() {
        let alice = Identity::from_seed(&[0x3a; 32]);
        let bob = Identity::from_seed(&[0x3b; 32]);
        let mallory = Identity::from_seed(&[0x3c; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let (_a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
        let bob_pub = bob.public_key_bytes();
        let hint = hex::encode(bob_pub);

        // After a restart only the durable cache is left: still sealable.
        clear_ephemeral(a_dir.path());
        seal_app_payload_under_session(a_dir.path(), &alice, &hint, b"durable-bound").unwrap();

        let rec =
            RevocationRecord::issue(&bob, &b_bundle.cert.device_id, 1, now(), "lost").unwrap();
        let mut rev = RevocationStore::load_checked(a_dir.path()).unwrap();
        assert!(rev.apply(rec).unwrap());
        rev.save(a_dir.path()).unwrap();

        let forged = signed_bundle(&mallory, bob_pub, "x");
        assert!(remember_ephemeral_peer(a_dir.path(), &forged).is_err());
        // Even an injected (pre-fix) ephemeral entry cannot redirect the check.
        inject_ephemeral_unchecked(a_dir.path(), bob_pub, &forged);
        let before = IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .pending_endpoint_outbound()
            .unwrap()
            .len();
        let err = seal_app_payload_under_session(a_dir.path(), &alice, &hint, b"must-not-seal")
            .unwrap_err();
        assert_eq!(err, ATSAM_LINEAGE_REVOKED);

        // A poisoned durable entry with no bound cert anywhere fails closed.
        clear_ephemeral(a_dir.path());
        let path = a_dir.path().join(PEER_CERT_CACHE);
        let mut map = load_peer_cert_map_checked(a_dir.path()).unwrap();
        map.insert(hex::encode(bob_pub), forged.cert.clone());
        std::fs::write(&path, serde_json::to_string(&map).unwrap()).unwrap();
        let err = seal_app_payload_under_session(a_dir.path(), &alice, &hint, b"must-not-seal")
            .unwrap_err();
        assert!(err.starts_with(ATSAM_SESSION_REQUIRED), "unexpected: {err}");
        let after = IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .pending_endpoint_outbound()
            .unwrap()
            .len();
        assert_eq!(after, before, "nothing may be sealed to the revoked peer");
    }

    fn rvdr1_for(owner: &Identity, cert: &DeviceCertificate) -> Vec<u8> {
        crate::device_revocation::DeviceRevocationV1 {
            identity_address: owner.address(),
            device_id: cert.device_id.as_bytes().to_vec(),
            device_ed_pub: cert.device_ed_pub,
            device_x_pub: cert.device_x_pub,
            device_cert_hash: device_certificate_hash(cert).unwrap(),
            issuer_device_id: b"ash-primary".to_vec(),
            issuer_seq: 1,
            revocation_id: [7u8; 16],
            reason_code: 1,
            created_at_ms: now(),
            signature: [0u8; 64],
        }
        .sign(owner)
        .unwrap()
        .encode()
        .unwrap()
    }

    /// identity-devices#1 / protocol-reference#0: a revoked lineage that is
    /// re-certified under a new device_id with the same keys stays denied.
    #[test]
    fn pair_init_refuses_recertified_revoked_lineage() {
        let alice = Identity::from_seed(&[0x3d; 32]);
        let bob = Identity::from_seed(&[0x3e; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let bob_pub = bob.public_key_bytes();
        write_contact(a_dir.path(), &bob_pub, "Bob");

        let mut rev = RevocationStore::load_checked(a_dir.path()).unwrap();
        assert!(rev
            .apply_rvdr1(&bob_pub, &rvdr1_for(&bob, &b_bundle.cert))
            .unwrap());
        rev.save(a_dir.path()).unwrap();

        let t = now();
        let cert = DeviceCertificate::issue(
            &bob,
            bob_pub,
            b_bundle.cert.device_x_pub,
            "fresh-id",
            t.saturating_sub(60_000),
            t + 86_400_000,
            0,
        )
        .unwrap();
        let prekey = PrekeyBundle::from_hybrid_public(
            "fresh-id",
            b_bundle.prekey.x25519_pub,
            b_bundle.prekey.mlkem768_ek.clone(),
            2,
            t,
            t + 86_400_000,
        )
        .unwrap()
        .sign(&bob)
        .unwrap();
        let recert = LanBundle { cert, prekey };
        assert!(peer_is_trusted(a_dir.path(), &recert).unwrap());
        let rev = RevocationStore::load_checked(a_dir.path()).unwrap();
        assert!(!rev.is_revoked(&hex::encode(bob_pub), "fresh-id"));
        assert!(rev.denies_certificate(&recert.cert).unwrap());
        let err = create_initiator_pair_init(a_dir.path(), &alice, &recert).unwrap_err();
        assert!(err.to_lowercase().contains("revoked"), "unexpected: {err}");
        let (local_cert, _) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        assert_eq!(
            refuse_if_session_lineage_revoked(a_dir.path(), &local_cert, &recert.cert).unwrap_err(),
            ATSAM_LINEAGE_REVOKED
        );
    }

    /// connection-reliability: the two peers' wall clocks differ. Bob's prekey
    /// is "created" two minutes after Alice's `now` (his clock runs ahead), so
    /// Alice's init predates the trust window she verifies against. Neither
    /// verifier may refuse the other's timestamps, and the session that comes
    /// out of it must carry traffic both ways straight away: the init must not
    /// be future-dated, because the session binding takes its instant from it.
    #[test]
    fn pair_init_completes_across_bounded_peer_clock_skew() {
        let alice = Identity::from_seed(&[0xa7; 32]);
        let bob = Identity::from_seed(&[0xb7; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install_with(b_dir.path(), &bob, 1, now() + 120_000);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        assert!(b_bundle.prekey.created_at_ms > now());
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();

        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        assert!(
            init.created_at_ms <= now(),
            "init must carry the initiator's own clock, never a later instant"
        );
        assert!(init.created_at_ms < b_bundle.prekey.created_at_ms);
        let frame = wrap_pair_init(&alice, &init).unwrap();
        let replies = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &frame,
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        assert!(response.created_at_ms >= init.created_at_ms);
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();
        assert!(
            find_confirmed_peer_session(b_dir.path(), &alice.public_key_bytes())
                .unwrap()
                .is_some()
        );
        let status = PrekeyLifecycleActor::open(b_dir.path())
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(status.pending_handoffs, 0, "claim completed, not leaked");

        // The first message right after PairResponse (what ash sends next):
        // Alice seals, Bob accepts and ACKs, Alice accepts the ACK.
        let (a_cert, a_reg) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        let local_device =
            AuthorizedEndpointDevice::authorize(&a_cert, &alice, &a_reg, now()).unwrap();
        let t = now();
        let expires =
            envelope_expires(t, a_store.session_expires_at(&record_key).unwrap()).unwrap();
        let mut queued = None;
        a_store
            .send_message_envelope(
                &record_key,
                "hello skew",
                &local_device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    queued = Some(bytes.to_vec());
                    Ok(*digest)
                },
            )
            .expect("the initiator's own session must be usable at once");
        let packed = queued.unwrap();
        let acks = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &packed,
        )
        .unwrap();
        assert_eq!(acks.len(), 1);
        let mut b_store = IndexedSessionStore::open(b_dir.path()).unwrap();
        let inbox = b_store.list_endpoint_inbox().unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].plaintext, b"hello skew");
        a_store
            .accept_ack_envelope(&record_key, &acks[0], &b_bundle.cert, false, now())
            .unwrap();
    }

    /// The responder stamps its PairResponse no earlier than the init it
    /// confirms, even when the initiator's clock runs ahead of its own: a
    /// response dated before its init is refused by `verify_response`.
    #[test]
    fn pair_response_is_never_stamped_before_its_init() {
        let alice = Identity::from_seed(&[0xa9; 32]);
        let bob = Identity::from_seed(&[0xb9; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, _) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();

        let root = [0x5a; 32];
        // Responder clock behind the init by a minute (initiator ahead).
        let behind = init.created_at_ms.saturating_sub(60_000);
        let response =
            build_pair_response(&init, &root, &bob, behind, LINK_PAIR_RESPONSE_VALIDITY_MS)
                .unwrap();
        assert_eq!(response.created_at_ms, init.created_at_ms);
        assert!(response.expires_at_ms > response.created_at_ms);
        // Responder clock ahead: the response carries the responder's clock.
        let ahead = init.created_at_ms + 60_000;
        let response =
            build_pair_response(&init, &root, &bob, ahead, LINK_PAIR_RESPONSE_VALIDITY_MS).unwrap();
        assert_eq!(response.created_at_ms, ahead);
    }

    /// connection-core-0 + security-regression: a contact that reinstalled
    /// (counter restarted below, or equal to with different keys, the id we
    /// pinned) must stay *reachable* (the connection and existing sessions keep
    /// working), but a prekey the durable pin refuses must never seed a NEW
    /// session unless the user explicitly re-pins (`ash contact remove`) or the
    /// pinned bundle has expired.
    #[test]
    fn contact_that_reset_its_prekey_counter_stays_reachable_but_gets_no_new_session() {
        for (pinned_id, reset_id, expect) in [
            (3u32, 1u32, "PREKEY_ROLLBACK"),
            (1u32, 1u32, "PREKEY_EQUIVOCATION"),
        ] {
            let alice = Identity::from_seed(&[0xa8; 32]);
            let bob = Identity::from_seed(&[0xb8; 32]);
            let a_dir = tempfile::tempdir().unwrap();
            let b_dir = tempfile::tempdir().unwrap();
            let b2_dir = tempfile::tempdir().unwrap();
            publish_and_install(a_dir.path(), &alice);
            publish_and_install_with(b_dir.path(), &bob, pinned_id, now());
            let b_old = local_bundle(b_dir.path(), &bob).unwrap();
            write_contact(a_dir.path(), &b_old.cert.device_ed_pub, "Bob");
            cache_peer_bundle(a_dir.path(), &b_old).unwrap();

            // Bob reinstalls: same identity seed, fresh data dir, counter reset.
            publish_and_install_with(b2_dir.path(), &bob, reset_id, now() + 1);
            let b_new = local_bundle(b2_dir.path(), &bob).unwrap();
            assert_ne!(b_new.prekey, b_old.prekey);

            // The durable pin refuses it, with a distinct typed status that says
            // how to proceed...
            let err = persist_trusted_peer_bundle(a_dir.path(), &b_new).unwrap_err();
            assert!(err.starts_with(PEER_PREKEY_RESET), "{err}");
            assert!(err.contains(expect), "{err}");
            assert!(err.contains("ash contact remove"), "{err}");
            // ...but the dial / mid-session offer path no longer fails on it
            // (Phase 6b S12: noted as SEC_PREKEY_ROLLBACK about Bob),
            let cap = crate::security_sense::tests::Capture::start();
            cache_peer_bundle(a_dir.path(), &b_new).unwrap();
            if let Some(cap) = cap {
                let bob_pub = bob.public_key_bytes();
                assert_eq!(
                    cap.kinds(),
                    vec![(
                        SecKind::PrekeyRollback,
                        crate::security_events::Attribution::Contact { peer: bob_pub },
                        Via::Local
                    )]
                );
            }
            // ...and the refused bundle is NOT remembered: the cache still serves
            // the pinned one.
            let live = load_cached_peer_bundle(a_dir.path(), &bob.public_key_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(
                live.prekey, b_old.prekey,
                "refused bundle must not be cached"
            );
            // A NEW session is refused outright, and nothing was created.
            let err = create_initiator_pair_init(a_dir.path(), &alice, &b_new).unwrap_err();
            assert!(err.starts_with(PEER_PREKEY_RESET), "{err}");
            assert!(IndexedSessionStore::open(a_dir.path())
                .unwrap()
                .find_confirmed_sessions_for_peer_at(&bob.public_key_bytes(), now())
                .unwrap()
                .is_empty());

            // Offline use stays fail-closed: the pin is untouched.
            clear_ephemeral(a_dir.path());
            let pinned = load_cached_peer_bundle(a_dir.path(), &bob.public_key_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(pinned.prekey, b_old.prekey);

            // Explicit re-pin (what `ash contact remove` does): the next offer is
            // pinned afresh and a session can start on it.
            assert!(forget_peer_prekey_pin(a_dir.path(), &bob.public_key_bytes()).unwrap());
            assert!(
                !forget_peer_prekey_pin(a_dir.path(), &bob.public_key_bytes()).unwrap(),
                "nothing left to forget"
            );
            cache_peer_bundle(a_dir.path(), &b_new).unwrap();
            let repinned = load_cached_peer_bundle(a_dir.path(), &bob.public_key_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(repinned.prekey, b_new.prekey);
            create_initiator_pair_init(a_dir.path(), &alice, &b_new).unwrap();
        }
    }

    /// The pin protects a bundle only while it is usable: once the pinned
    /// bundle has expired, the contact's reset counter is accepted and a new
    /// session can start (no user action needed).
    #[test]
    fn expired_pin_no_longer_blocks_a_reset_contact() {
        let alice = Identity::from_seed(&[0xa7; 32]);
        let bob = Identity::from_seed(&[0xb7; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b2_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        let month = 30 * 24 * 3600 * 1000u64;
        let long_ago = now() - 2 * month;
        // Bob's old bundle, pinned while it was valid; it has since expired.
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        let old = crate::prekey_bundle::PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            9,
            long_ago,
            long_ago + month,
        )
        .unwrap()
        .sign(&bob)
        .unwrap();
        let mut store = PrekeyStore::load_checked(a_dir.path()).unwrap();
        store.publish(&old, long_ago + 1_000).unwrap();
        store.save(a_dir.path()).unwrap();

        // Bob reinstalled: counter restarted at 1.
        publish_and_install_with(b2_dir.path(), &bob, 1, now());
        let b_new = local_bundle(b2_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_new.cert.device_ed_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_new).unwrap();
        create_initiator_pair_init(a_dir.path(), &alice, &b_new)
            .expect("an expired pin must not block the reset contact");
    }

    /// connection-core-6: concurrent callers at the moment rotation becomes
    /// due must rotate once (the loser used to fail its connection).
    #[test]
    fn concurrent_ensure_local_prekey_rotates_exactly_once() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let id = Identity::from_seed(&[0xc7; 32]);
        let dir = tempfile::tempdir().unwrap();
        let floor = crate::prekey_lifecycle::time_floor_signed_prekey_id(now());
        let barrier = std::sync::Barrier::new(6);
        std::thread::scope(|scope| {
            for _ in 0..6 {
                scope.spawn(|| {
                    barrier.wait();
                    ensure_local_prekey(dir.path(), &id).unwrap();
                });
            }
        });
        let status = PrekeyLifecycleActor::open(dir.path())
            .unwrap()
            .status()
            .unwrap();
        assert!(status.highest_signed_prekey_id >= floor);
        assert_eq!(status.retained_generations, 1);
        ensure_local_prekey(dir.path(), &id).unwrap();
    }

    /// ratchet-v2-5: a publish the store would refuse must not burn one of the
    /// actor's few retained generations per attempt. Local clock stepped back
    /// behind the pinned bundle's `created_at_ms`: the new bundle is refused
    /// until the clock catches up. Meanwhile the still-valid pinned bundle keeps
    /// serving connections (lost-state recovery §4.3) instead of failing each.
    #[test]
    fn ensure_local_prekey_does_not_burn_generations_on_publish_rollback() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let id = Identity::from_seed(&[0xc8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let t = now();
        let day = 24 * 3600 * 1000;
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        // Pinned local bundle created "in the future" (within the verify skew)
        // and inside the rotation lead, so a bundle stamped `now` is stale.
        let pinned = PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            1,
            t + 60_000,
            t + 2 * day,
        )
        .unwrap()
        .sign(&id)
        .unwrap();
        let mut store = PrekeyStore::default();
        store.publish(&pinned, t).unwrap();
        store.save(dir.path()).unwrap();
        assert!(local_prekey_rotation_due(&store, &id.public_key_bytes(), t));

        for _ in 0..(crate::prekey_lifecycle::MAX_PREKEY_GENERATIONS + 2) {
            ensure_local_prekey(dir.path(), &id).expect("the pinned bundle still serves");
            assert_eq!(
                rotate_local_prekey_locked(
                    dir.path(),
                    &id,
                    PrekeyStore::load_checked(dir.path()).unwrap(),
                    now()
                )
                .unwrap_err(),
                "PREKEY_ROLLBACK"
            );
        }
        let served = PrekeyStore::load_checked(dir.path())
            .unwrap()
            .fetch_valid(&id.public_key_bytes(), now())
            .unwrap();
        assert_eq!(served.signed_prekey_id, 1);
        let status = PrekeyLifecycleActor::open(dir.path())
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(status.retained_generations, 0);
        assert_eq!(status.highest_signed_prekey_id, 0);
    }

    /// A signed local bundle with `signed_prekey_id = id`, valid 30 days from
    /// `created`.
    fn archive_test_bundle(signer: &Identity, id: u32, created: u64) -> PrekeyBundle {
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            id,
            created,
            created + 30 * 24 * 3600 * 1000,
        )
        .unwrap()
        .sign(signer)
        .unwrap()
    }

    fn archive_bundle_at(data_dir: &Path, bundle: &PrekeyBundle, at: u64) {
        with_prekey_store_lock(data_dir, || {
            archive_published_prekey_locked(data_dir, bundle, at)
        })
        .unwrap();
    }

    fn archived_ids(data_dir: &Path) -> Vec<u32> {
        let raw = std::fs::read(published_prekey_archive_path(data_dir)).unwrap();
        let archive: PublishedPrekeyArchive = serde_json::from_slice(&raw).unwrap();
        archive
            .bundles
            .iter()
            .map(|json| json.signed_prekey_id)
            .collect()
    }

    #[test]
    fn local_bundle_archive_bounded_and_pruned_at_destroy_after() {
        let id = Identity::from_seed(&[0xd1; 32]);
        let other = Identity::from_seed(&[0xd2; 32]);
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let t = now();
        let hash = |bundle: &PrekeyBundle| prekey_bundle_hash(bundle).unwrap();
        assert_eq!(
            local_published_bundle_by_hash(dd, &[0x77; 32], t).unwrap(),
            None
        );
        // Another identity's bundle never survives the next write.
        let stranger = archive_test_bundle(&other, 9, t);
        archive_bundle_at(dd, &stranger, t);
        // Six of ours, a second apart: the archive keeps the newest
        // MAX_PREKEY_GENERATIONS, like the actor.
        let ours: Vec<PrekeyBundle> = (0..6u32)
            .map(|i| archive_test_bundle(&id, i + 1, t + u64::from(i) * 1_000))
            .collect();
        for bundle in &ours {
            archive_bundle_at(dd, bundle, bundle.created_at_ms);
        }
        // The same bundle again is no second entry.
        archive_bundle_at(dd, &ours[5], ours[5].created_at_ms);
        assert_eq!(archived_ids(dd), vec![3, 4, 5, 6]);
        let at = ours[5].created_at_ms;
        for old in [&ours[0], &ours[1], &stranger] {
            assert_eq!(
                local_published_bundle_by_hash(dd, &hash(old), at).unwrap(),
                None
            );
        }
        for kept in &ours[2..] {
            assert_eq!(
                local_published_bundle_by_hash(dd, &hash(kept), at).unwrap(),
                Some(kept.clone())
            );
        }
        // Past its expiry, inside the grace: still found (the prekey store
        // has stopped offering it by then).
        let third = &ours[2];
        let destroy_after = third.expires_at_ms + PREKEY_RETENTION_GRACE_MS;
        assert!(third.verify(third.expires_at_ms + 3_600_000).is_err());
        for found_at in [third.expires_at_ms + 1, destroy_after] {
            assert_eq!(
                local_published_bundle_by_hash(dd, &hash(third), found_at).unwrap(),
                Some(third.clone())
            );
        }
        // Gone one millisecond after the actor's destroy_after for it.
        assert_eq!(
            local_published_bundle_by_hash(dd, &hash(third), destroy_after + 1).unwrap(),
            None
        );
        // The next write prunes every bundle past it from the file.
        let last_destroy = ours[5].expires_at_ms + PREKEY_RETENTION_GRACE_MS;
        let next = archive_test_bundle(&id, 7, last_destroy + 1);
        archive_bundle_at(dd, &next, last_destroy + 1);
        assert_eq!(archived_ids(dd), vec![7]);
        // A bundle that does not verify is never archived.
        let mut forged = archive_test_bundle(&id, 8, last_destroy + 2);
        forged.signature[0] ^= 1;
        assert!(with_prekey_store_lock(dd, || {
            archive_published_prekey_locked(dd, &forged, last_destroy + 2)
        })
        .is_err());
        assert_eq!(archived_ids(dd), vec![7]);
        // An archive that does not parse reads as empty and is rewritten.
        std::fs::write(published_prekey_archive_path(dd), b"{not json").unwrap();
        assert_eq!(
            local_published_bundle_by_hash(dd, &hash(&next), last_destroy + 1).unwrap(),
            None
        );
        archive_bundle_at(dd, &next, last_destroy + 1);
        assert_eq!(archived_ids(dd), vec![7]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(published_prekey_archive_path(dd))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// A rotation archives the new bundle before the store offers it, so a
    /// letter sealed to the retired generation still finds its bundle, and the
    /// actor still holds its key; a profile whose bundle predates the archive
    /// gets it archived at its next ensure.
    #[test]
    fn rotation_archives_published_bundles_and_seeds_an_older_profile() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let id = Identity::from_seed(&[0xd3; 32]);
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        // Published before this build: store and actor, no archive.
        publish_and_install(dd, &id);
        assert!(!published_prekey_archive_path(dd).exists());
        let first = local_bundle(dd, &id).unwrap().prekey;
        let first_hash = prekey_bundle_hash(&first).unwrap();
        assert_eq!(
            local_published_bundle_by_hash(dd, &first_hash, now()).unwrap(),
            Some(first.clone())
        );
        // A rotation (forced: the bundle is not due yet).
        let later = now() + 1_000;
        with_prekey_store_lock(dd, || {
            rotate_local_prekey_locked(dd, &id, PrekeyStore::load_checked(dd)?, later)
        })
        .unwrap();
        let second = PrekeyStore::load_checked(dd)
            .unwrap()
            .fetch_valid(&id.public_key_bytes(), later)
            .unwrap();
        assert!(second.signed_prekey_id > first.signed_prekey_id);
        let second_hash = prekey_bundle_hash(&second).unwrap();
        assert_eq!(
            local_published_bundle_by_hash(dd, &second_hash, later).unwrap(),
            Some(second.clone())
        );
        assert_eq!(
            local_published_bundle_by_hash(dd, &first_hash, later).unwrap(),
            Some(first.clone())
        );
        // The archived hash is the actor's binding: the retired generation
        // still answers a letter's wrap DH.
        let e_w = [0x5d; 32];
        let eph = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(e_w)).to_bytes();
        let actor = PrekeyLifecycleActor::open(dd).unwrap();
        for bundle in [&first, &second] {
            let expected =
                crate::atsam_root::x25519_shared_checked(&e_w, &bundle.x25519_pub).unwrap();
            let shared = actor
                .letter_shared_secret(&prekey_bundle_hash(bundle).unwrap(), &eph, later)
                .unwrap();
            assert_eq!(*shared, expected);
        }
        // The lab publish of a real prekey archives its bundle as well.
        let third = archive_test_bundle(&id, second.signed_prekey_id + 1, later + 1_000);
        publish_local_prekey_bundle_checked(dd, &third, later + 1_000).unwrap();
        assert_eq!(
            local_published_bundle_by_hash(dd, &prekey_bundle_hash(&third).unwrap(), later)
                .unwrap(),
            Some(third)
        );
    }

    #[test]
    fn published_prekey_archive_is_sealed_in_a_sealed_profile() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let id = Identity::from_seed(&[0xd4; 32]);
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        publish_and_install(dd, &id);
        let bundle = local_bundle(dd, &id).unwrap().prekey;
        let digest = prekey_bundle_hash(&bundle).unwrap();
        let path = published_prekey_archive_path(dd);
        assert!(!crate::at_rest::is_sealed(&std::fs::read(&path).unwrap()));
        if !dd.join(crate::BACKEND_MARKER_NAME).exists() {
            std::fs::write(dd.join(crate::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        }
        crate::at_rest::tests::expect_key_file(dd);
        let sealed =
            crate::privacy::migrate_all(dd, now(), crate::at_rest::MigratePolicy::Allow).unwrap();
        assert_eq!(sealed.outcome, crate::privacy::MigrateOutcome::Sealed);
        let raw = std::fs::read(&path).unwrap();
        assert!(crate::at_rest::is_sealed_as(
            Kind::PrekeyPublishedLocal,
            &raw
        ));
        let key_hex = hex::encode(bundle.x25519_pub);
        assert!(!raw
            .windows(key_hex.len())
            .any(|window| window == key_hex.as_bytes()));
        assert_eq!(
            local_published_bundle_by_hash(dd, &digest, now()).unwrap(),
            Some(bundle.clone())
        );
        // Rewritten sealed.
        let next = archive_test_bundle(&id, bundle.signed_prekey_id + 1, now() + 1_000);
        publish_local_prekey_bundle_checked(dd, &next, now() + 1_000).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(crate::at_rest::is_sealed_as(
            Kind::PrekeyPublishedLocal,
            &raw
        ));
        assert_eq!(
            local_published_bundle_by_hash(dd, &digest, now()).unwrap(),
            Some(bundle)
        );
        // A sealed archive that does not open (one changed byte) fails
        // closed and is never written over.
        let mut changed = raw.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        std::fs::write(&path, &changed).unwrap();
        assert!(local_published_bundle_by_hash(dd, &digest, now()).is_err());
        let newer = archive_test_bundle(&id, next.signed_prekey_id + 1, now() + 2_000);
        assert!(with_prekey_store_lock(dd, || {
            archive_published_prekey_locked(dd, &newer, now() + 2_000)
        })
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), changed);
    }

    /// Lost-state recovery §4: a contact that lost everything (fresh data dir,
    /// same seed) and publishes again later takes a wall-clock id above the
    /// one we pinned, so our unchanged pin accepts it as a plain rotation and a
    /// new session can start without `ash contact remove`.
    #[test]
    fn reinstalled_contact_with_time_ids_is_pinned_and_paired() {
        let alice = Identity::from_seed(&[0xa9; 32]);
        let bob = Identity::from_seed(&[0xb9; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let b2_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        // Bob's first install, ten seconds ago, already on time ids.
        let earlier = now() - 10_000;
        let old_id = crate::prekey_lifecycle::time_floor_signed_prekey_id(earlier);
        publish_and_install_with(b_dir.path(), &bob, old_id, earlier);
        let b_old = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_old.cert.device_ed_pub, "Bob");
        persist_trusted_peer_bundle(a_dir.path(), &b_old).unwrap();

        // Bob lost his data dir: the real rotation path publishes afresh.
        let b_new = local_bundle(b2_dir.path(), &bob).unwrap();
        assert!(b_new.prekey.signed_prekey_id > old_id);
        persist_trusted_peer_bundle(a_dir.path(), &b_new).expect("the pin accepts the rotation");
        let pinned = load_cached_peer_bundle(a_dir.path(), &bob.public_key_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(pinned.prekey, b_new.prekey);
        create_initiator_pair_init(a_dir.path(), &alice, &b_new).unwrap();
    }

    /// A pin taken from an old build (small counter id) accepts the first
    /// time-id bundle of a reinstalled contact.
    #[test]
    fn legacy_counter_pin_accepts_a_time_id_bundle() {
        let alice = Identity::from_seed(&[0xaa; 32]);
        let bob = Identity::from_seed(&[0xba; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let b2_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install_with(b_dir.path(), &bob, 3, now() - 5_000);
        let b_old = local_bundle(b_dir.path(), &bob).unwrap();
        assert_eq!(b_old.prekey.signed_prekey_id, 3);
        write_contact(a_dir.path(), &b_old.cert.device_ed_pub, "Bob");
        persist_trusted_peer_bundle(a_dir.path(), &b_old).unwrap();

        let b_new = local_bundle(b2_dir.path(), &bob).unwrap();
        assert!(
            b_new.prekey.signed_prekey_id
                >= crate::prekey_lifecycle::time_floor_signed_prekey_id(now() - 5_000)
        );
        persist_trusted_peer_bundle(a_dir.path(), &b_new).unwrap();
        create_initiator_pair_init(a_dir.path(), &alice, &b_new).unwrap();
    }

    /// Security: time ids change nothing for replays. An older signed bundle,
    /// a same-id bundle with other keys, and a higher id with an older
    /// creation instant are all refused by the pin, and none seeds a session.
    #[test]
    fn replayed_old_signed_bundle_is_still_refused() {
        let alice = Identity::from_seed(&[0xab; 32]);
        let bob = Identity::from_seed(&[0xbb; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        let t = now();
        let t1 = t - 20_000;
        let t2 = t - 10_000;
        let id1 = crate::prekey_lifecycle::time_floor_signed_prekey_id(t1);
        let id2 = crate::prekey_lifecycle::time_floor_signed_prekey_id(t2);
        let bundle_in = |id: u32, at: u64| {
            let dir = tempfile::tempdir().unwrap();
            publish_and_install_with(dir.path(), &bob, id, at);
            local_bundle(dir.path(), &bob).unwrap()
        };
        let p1 = bundle_in(id1, t1);
        let p2 = bundle_in(id2, t2);
        write_contact(a_dir.path(), &p2.cert.device_ed_pub, "Bob");
        persist_trusted_peer_bundle(a_dir.path(), &p2).unwrap();

        let p2_other_keys = bundle_in(id2, t2);
        let higher_but_older = bundle_in(id2 + 100, t2 - 1);
        for (offer, expect) in [
            (&p1, "PREKEY_ROLLBACK"),
            (&p2_other_keys, "PREKEY_EQUIVOCATION"),
            (&higher_but_older, "PREKEY_ROLLBACK"),
        ] {
            let err = persist_trusted_peer_bundle(a_dir.path(), offer).unwrap_err();
            assert!(err.starts_with(PEER_PREKEY_RESET), "{err}");
            assert!(err.contains(expect), "{expect}: {err}");
            let err = create_initiator_pair_init(a_dir.path(), &alice, offer).unwrap_err();
            assert!(err.starts_with(PEER_PREKEY_RESET), "{expect}: {err}");
        }
        let pinned = load_cached_peer_bundle(a_dir.path(), &bob.public_key_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(pinned.prekey, p2.prekey);
        assert!(IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .find_confirmed_sessions_for_peer_at(&bob.public_key_bytes(), now())
            .unwrap()
            .is_empty());
    }

    /// §4.3: rotation is due but the actor already retains
    /// MAX_PREKEY_GENERATIONS unexpired generations. The still-valid bundle
    /// keeps serving every link instead of failing each one.
    #[test]
    fn failed_due_rotation_keeps_serving_the_current_bundle() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let id = Identity::from_seed(&[0xce; 32]);
        let dir = tempfile::tempdir().unwrap();
        let t = now();
        let day = 24 * 3600 * 1000;
        let actor = PrekeyLifecycleActor::open(dir.path()).unwrap();
        let mut store = PrekeyStore::default();
        let max = crate::prekey_lifecycle::MAX_PREKEY_GENERATIONS as u64;
        for i in 1..=max {
            let at = t - (max + 1 - i) * 1_000;
            let mut kp = HybridKeypair::generate(&mut rand::thread_rng());
            let bundle = PrekeyBundle::from_hybrid_public(
                PRIMARY_DEVICE_ID,
                kp.x25519_public,
                kp.mlkem_ek_bytes.clone(),
                i as u32,
                at,
                t + day,
            )
            .unwrap()
            .sign(&id)
            .unwrap();
            actor
                .install_generation(
                    std::slice::from_ref(&bundle),
                    PrekeyGenerationPrivate::new(kp.x25519_secret, kp.mlkem_seed, vec![]),
                    at,
                )
                .unwrap();
            kp.x25519_secret.zeroize();
            store.publish(&bundle, at).unwrap();
        }
        store.save(dir.path()).unwrap();
        assert!(local_prekey_rotation_due(&store, &id.public_key_bytes(), t));
        assert!(rotate_local_prekey_locked(dir.path(), &id, store, now()).is_err());

        let served = local_bundle(dir.path(), &id).expect("links keep working");
        assert_eq!(served.prekey.signed_prekey_id, max as u32);
        local_bundle(dir.path(), &id).expect("and keep working");
        let status = PrekeyLifecycleActor::open(dir.path())
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(status.retained_generations, max as usize);

        // The note is printed at most once an hour.
        let mut last = None;
        let start = Instant::now();
        assert!(rotation_failure_log_due(&mut last, start));
        assert!(!rotation_failure_log_due(
            &mut last,
            start + Duration::from_secs(60)
        ));
        assert!(rotation_failure_log_due(
            &mut last,
            start + Duration::from_secs(3_600)
        ));
    }

    /// Lifecycle state lost while prekey_store.json survives: the new bundle
    /// must take an id above the pinned one instead of failing as a rollback
    /// on every connection.
    #[test]
    fn ensure_local_prekey_never_reuses_a_published_id() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let id = Identity::from_seed(&[0xcd; 32]);
        let dir = tempfile::tempdir().unwrap();
        let t = now();
        let day = 24 * 3600 * 1000;
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        let pinned = PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            5,
            t - 28 * day,
            t + 2 * day,
        )
        .unwrap()
        .sign(&id)
        .unwrap();
        let mut store = PrekeyStore::default();
        store.publish(&pinned, t).unwrap();
        store.save(dir.path()).unwrap();
        assert!(local_prekey_rotation_due(&store, &id.public_key_bytes(), t));

        ensure_local_prekey(dir.path(), &id).unwrap();
        let store = PrekeyStore::load_checked(dir.path()).unwrap();
        let fresh = store.fetch_valid(&id.public_key_bytes(), now()).unwrap();
        let floor = crate::prekey_lifecycle::time_floor_signed_prekey_id(t);
        assert!(fresh.signed_prekey_id > 5 && fresh.signed_prekey_id >= floor);
        let status = PrekeyLifecycleActor::open(dir.path())
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(status.highest_signed_prekey_id, fresh.signed_prekey_id);
        assert_eq!(status.retained_generations, 1);
    }

    /// connection-core-6 (a): a pending stage must be recovered before the new
    /// local bundle is saved, not replayed over it later.
    #[test]
    fn ensure_local_prekey_recovers_pending_stage_before_saving() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let alice = Identity::from_seed(&[0xc9; 32]);
        let bob = Identity::from_seed(&[0xca; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        // A crash leaves a stage holding a snapshot of Bob's cache only.
        FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.set(true));
        let err = persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap_err();
        FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.set(false));
        assert!(err.contains("injected"));
        assert!(a_dir.path().join(PEER_CACHE_STAGE).exists());

        // Our own first prekey is published afterwards; it must survive.
        ensure_local_prekey(a_dir.path(), &alice).unwrap();
        assert!(!a_dir.path().join(PEER_CACHE_STAGE).exists());
        let store = PrekeyStore::load_checked(a_dir.path()).unwrap();
        assert!(store
            .fetch_valid(&alice.public_key_bytes(), now())
            .is_some());
        assert!(store.fetch_valid(&bob.public_key_bytes(), now()).is_some());
        recover_peer_cache_stage(a_dir.path()).unwrap();
        let store = PrekeyStore::load_checked(a_dir.path()).unwrap();
        assert!(
            store
                .fetch_valid(&alice.public_key_bytes(), now())
                .is_some(),
            "a later recovery must not replay a stale snapshot over our bundle"
        );
    }

    fn contact_cache_fixture() -> (tempfile::TempDir, LanBundle) {
        let alice = Identity::from_seed(&[0xd9; 32]);
        let bob = Identity::from_seed(&[0xda; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        (a_dir, b_bundle)
    }

    /// connection-core-7: an unparseable stage used to fail every cache
    /// operation until someone deleted it by hand.
    #[test]
    fn truncated_peer_cache_stage_is_quarantined_and_cache_recovers() {
        let (a_dir, b_bundle) = contact_cache_fixture();
        std::fs::write(
            a_dir.path().join(PEER_CACHE_STAGE),
            br#"{"generation":12,"certs_json":"{"#,
        )
        .unwrap();
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        assert!(!a_dir.path().join(PEER_CACHE_STAGE).exists());
        assert!(a_dir.path().join("peer_cache.stage.json.corrupt").exists());
        clear_ephemeral(a_dir.path());
        let loaded = load_cached_peer_bundle(a_dir.path(), &b_bundle.cert.device_ed_pub)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.prekey, b_bundle.prekey);
    }

    /// connection-core-7: same for an empty / non-numeric generation counter;
    /// a stage that cannot be ordered against it is dropped with it.
    #[test]
    fn corrupt_generation_file_is_quarantined_and_cache_recovers() {
        for junk in [&b"not-a-number\n"[..], &b""[..], &[0xff, 0xfe][..]] {
            let (a_dir, b_bundle) = contact_cache_fixture();
            persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
            std::fs::write(a_dir.path().join("peer_cache.generation"), junk).unwrap();
            let stage = PeerCacheStage {
                generation: 7,
                certs_json: "{}".into(),
                prekey_json: r#"{"bundles":{}}"#.into(),
            };
            std::fs::write(
                a_dir.path().join(PEER_CACHE_STAGE),
                serde_json::to_vec(&stage).unwrap(),
            )
            .unwrap();
            persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
            assert!(a_dir.path().join("peer_cache.generation.corrupt").exists());
            assert!(!a_dir.path().join(PEER_CACHE_STAGE).exists());
            assert!(read_committed_peer_cache_generation(a_dir.path()).unwrap() > 0);
            clear_ephemeral(a_dir.path());
            assert!(
                load_cached_peer_bundle(a_dir.path(), &b_bundle.cert.device_ed_pub)
                    .unwrap()
                    .is_some()
            );
        }
    }

    /// connection-core-5: the daemon and ash prune unlocked, so nothing young
    /// (in-flight temp file, just-written response) may be deleted, and losing
    /// a race with another pruner is not an error. Review B-sealed-stores-5:
    /// past its retry window a response goes, whether its session lives or
    /// not (a live session's response used to stay for the session's life).
    #[test]
    fn pair_response_prune_spares_young_files() {
        let dir = tempfile::tempdir().unwrap();
        let rdir = dir.path().join(PAIR_RESPONSE_DIR);
        std::fs::create_dir_all(&rdir).unwrap();
        let names = [
            hex::encode([1u8; 16]),
            // A sealed profile's name: the keyed init_id.
            hex::encode([2u8; 32]),
            format!(".{}.tmp.0000000000000001", hex::encode([3u8; 16])),
            "stray.txt".to_string(),
        ];
        for name in &names {
            std::fs::write(rdir.join(name), b"x").unwrap();
        }
        // Everything was written just now: nothing is old enough to prune.
        assert_eq!(prune_lan_pair_response_files(dir.path()).unwrap(), 0);
        let within = std::time::SystemTime::now() + PAIR_RESPONSE_KEEP - Duration::from_secs(60);
        assert_eq!(
            prune_lan_pair_response_files_at(dir.path(), within).unwrap(),
            0
        );
        assert!(names.iter().all(|n| rdir.join(n).exists()));

        let later = std::time::SystemTime::now() + PAIR_RESPONSE_KEEP + Duration::from_secs(1);
        assert_eq!(
            prune_lan_pair_response_files_at(dir.path(), later).unwrap(),
            names.len()
        );
        assert_eq!(std::fs::read_dir(&rdir).unwrap().count(), 0);
        // A second pruner finds nothing left and is not an error.
        assert_eq!(
            prune_lan_pair_response_files_at(dir.path(), later).unwrap(),
            0
        );
    }

    /// connection-core-4: a payload no LAN/Internet carrier can send must be
    /// refused before it burns a ratchet index or an outbox row.
    #[test]
    fn seal_under_session_refuses_oversize_payload_before_any_state_change() {
        let alice = Identity::from_seed(&[0xcb; 32]);
        let bob = Identity::from_seed(&[0xcc; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let (_a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
        let peer_hint = hex::encode(b_bundle.cert.device_ed_pub);
        let outbox = |dir: &Path| {
            IndexedSessionStore::open(dir)
                .unwrap()
                .pending_endpoint_outbound()
                .unwrap()
                .len()
        };
        let before = outbox(a_dir.path());

        let too_big = vec![b'x'; crate::lan_noise::MAX_LAN_ENDPOINT_TEXT + 1];
        let err =
            seal_app_payload_under_session(a_dir.path(), &alice, &peer_hint, &too_big).unwrap_err();
        assert!(err.starts_with("SEAL_PAYLOAD"), "{err}");
        assert_eq!(outbox(a_dir.path()), before, "no outbox row for a refusal");

        // The cap itself seals into an envelope that fits one transport frame.
        let at_cap = vec![b'x'; crate::lan_noise::MAX_LAN_ENDPOINT_TEXT];
        let packed =
            seal_app_payload_under_session(a_dir.path(), &alice, &peer_hint, &at_cap).unwrap();
        assert!(packed.len() <= crate::lan_noise::MAX_TRANSPORT_PLAINTEXT);
    }

    // ---- session reset (lost-state recovery §7, §8) ----

    use crate::session_reset::{
        self, apply_query_replies, decode as rsr1_decode, encode_signed, note_presented_cert,
        session_query_frame, set_lab_session_reset_for_this_thread, QueryOutcome, Rsr1Body,
        Rsr1Decode, SessionStatusCode,
    };

    /// Lab switch on for this test thread; restored when dropped.
    struct ResetGate;
    impl ResetGate {
        fn on() -> Self {
            set_lab_session_reset_for_this_thread(Some(1));
            ResetGate
        }
    }
    impl Drop for ResetGate {
        fn drop(&mut self) {
            set_lab_session_reset_for_this_thread(None);
        }
    }

    /// Holds the long message horizon on this thread, whatever
    /// `RAVEN_LAB_HORIZON` the suite runs with, until dropped: with it on, a
    /// prune or a reset step parks what these tests expect to expire (Phase
    /// 5a, P5.6).
    struct HorizonHeld;
    impl HorizonHeld {
        fn on() -> Self {
            crate::horizon::set_lab_horizon_for_this_thread(Some(false));
            HorizonHeld
        }
    }
    impl Drop for HorizonHeld {
        fn drop(&mut self) {
            crate::horizon::set_lab_horizon_for_this_thread(None);
        }
    }

    /// Alice paired with Bob (Alice initiated) and sealed one message; Bob
    /// then lost everything and runs from `b2` with the same seed.
    struct Wiped {
        alice: Identity,
        bob: Identity,
        a_dir: tempfile::TempDir,
        b_dir: tempfile::TempDir,
        b2_dir: tempfile::TempDir,
        a_bundle: LanBundle,
        key: IndexedSessionRecordKey,
        packed: Vec<u8>,
    }

    fn wiped(seed: u8) -> Wiped {
        let alice = Identity::from_seed(&[seed; 32]);
        let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
        let (a_dir, b_dir, b2_dir) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let (a_bundle, _) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
        let key = IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .find_confirmed_session_for_peer_at(&bob.public_key_bytes(), now())
            .unwrap()
            .unwrap();
        let packed = seal_under(a_dir.path(), &alice, &key, "lost on the way");
        // Bob reinstalls: the real first-run path (phase 1 time-floored id).
        local_bundle(b2_dir.path(), &bob).unwrap();
        write_contact(b2_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b2_dir.path(), &a_bundle).unwrap();
        Wiped {
            alice,
            bob,
            a_dir,
            b_dir,
            b2_dir,
            a_bundle,
            key,
            packed,
        }
    }

    fn status_of(reply: &[u8]) -> (SessionStatusCode, [u8; 32], [u8; 16]) {
        match rsr1_decode(reply).unwrap() {
            Rsr1Decode::Frame(frame) => match frame.body {
                Rsr1Body::SessionStatus {
                    status,
                    echoed_object,
                    echoed_mid,
                    ..
                } => (status, echoed_object, echoed_mid),
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
    }

    fn query(w: &Wiped, dir: &Path) -> Result<Vec<Vec<u8>>, String> {
        let frame =
            session_query_frame(&w.alice, &w.bob.public_key_bytes(), &w.packed, now()).unwrap();
        dispatch_frame(
            dir,
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &frame,
        )
    }

    #[test]
    fn query_for_lost_session_gets_signed_no_session() {
        let _gate = ResetGate::on();
        let w = wiped(0x31);
        let history_before = std::fs::read(w.b2_dir.path().join("chat_history.json")).ok();
        let replies = query(&w, w.b2_dir.path()).unwrap();
        assert_eq!(replies.len(), 1);
        let Rsr1Decode::Frame(frame) = rsr1_decode(&replies[0]).unwrap() else {
            panic!()
        };
        session_reset::verify(
            &replies[0],
            &frame,
            &w.bob.public_key_bytes(),
            &w.alice.public_key_bytes(),
        )
        .unwrap();
        let env = Envelope::unpack(&w.packed).unwrap();
        assert_eq!(
            status_of(&replies[0]),
            (
                SessionStatusCode::NoSession,
                crate::bridge::authenticated_object_digest(&env),
                env.message_id
            )
        );
        // Read-only: nothing was accepted or recorded at the receiver.
        let mut b2 = IndexedSessionStore::open(w.b2_dir.path()).unwrap();
        assert!(b2.list_endpoint_inbox().unwrap().is_empty());
        assert!(b2.list_record_keys().unwrap().is_empty());
        assert_eq!(
            std::fs::read(w.b2_dir.path().join("chat_history.json")).ok(),
            history_before
        );
    }

    #[test]
    fn query_for_live_session_gets_present() {
        let _gate = ResetGate::on();
        let w = wiped(0x33);
        let replies = query(&w, w.b_dir.path()).unwrap();
        assert_eq!(status_of(&replies[0]).0, SessionStatusCode::Present);
        // The query did not deliver the message.
        assert!(IndexedSessionStore::open(w.b_dir.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn envelope_frames_still_close_without_reply_when_gate_on() {
        let _gate = ResetGate::on();
        let w = wiped(0x35);
        let err = dispatch_frame(
            w.b2_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &w.packed,
        )
        .unwrap_err();
        assert!(err.contains("no confirmed LAN session"), "{err}");
    }

    #[test]
    fn stranger_query_is_refused_and_gets_no_rsr1() {
        let _gate = ResetGate::on();
        let w = wiped(0x37);
        let carol = Identity::from_seed(&[0x39; 32]);
        let c_dir = tempfile::tempdir().unwrap();
        publish_and_install(c_dir.path(), &carol);
        let c_bundle = local_bundle(c_dir.path(), &carol).unwrap();
        let frame =
            session_query_frame(&carol, &w.bob.public_key_bytes(), &w.packed, now()).unwrap();
        let err = dispatch_frame(
            w.b2_dir.path(),
            &w.bob,
            &c_bundle,
            &carol.public_key_bytes(),
            &frame,
        )
        .unwrap_err();
        assert!(err.contains("not a local contact"), "{err}");
    }

    #[test]
    fn query_with_foreign_signed_envelope_is_refused() {
        let _gate = ResetGate::on();
        let w = wiped(0x3b);
        let mut env = Envelope::unpack(&w.packed).unwrap();
        env.sign_with(&Identity::from_seed(&[0x3d; 32]));
        let frame =
            session_query_frame(&w.alice, &w.bob.public_key_bytes(), &env.pack(), now()).unwrap();
        let err = dispatch_frame(
            w.b2_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &frame,
        )
        .unwrap_err();
        assert!(err.contains("not signed by the contact"), "{err}");
        // A query signed by Alice but sent over Carol's link: wrong signer.
        let carol = Identity::from_seed(&[0x3e; 32]);
        let c_dir = tempfile::tempdir().unwrap();
        publish_and_install(c_dir.path(), &carol);
        let c_bundle = local_bundle(c_dir.path(), &carol).unwrap();
        write_contact(w.b2_dir.path(), &c_bundle.cert.device_ed_pub, "Carol");
        let alice_query =
            session_query_frame(&w.alice, &w.bob.public_key_bytes(), &w.packed, now()).unwrap();
        let err = dispatch_frame(
            w.b2_dir.path(),
            &w.bob,
            &c_bundle,
            &carol.public_key_bytes(),
            &alice_query,
        )
        .unwrap_err();
        assert_eq!(err, "RSR1_WRONG_SIGNER");
    }

    #[test]
    fn query_store_wide_error_closes_instead_of_no_session() {
        let _gate = ResetGate::on();
        let w = wiped(0x41);
        let db = w
            .b2_dir
            .path()
            .join(crate::indexed_session_store::INDEXED_SESSION_METADATA_FILE);
        let _ = std::fs::remove_file(db.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(db.with_extension("sqlite-shm"));
        std::fs::write(&db, b"this is not a database at all, not even close......").unwrap();
        assert!(query(&w, w.b2_dir.path()).is_err());
    }

    #[test]
    fn unknown_rsr1_version_or_kind_is_dropped_without_closing() {
        let _gate = ResetGate::on();
        let w = wiped(0x43);
        let mut frame =
            session_query_frame(&w.alice, &w.bob.public_key_bytes(), &w.packed, now()).unwrap();
        frame[4] = 2;
        assert_eq!(
            dispatch_frame(
                w.b2_dir.path(),
                &w.bob,
                &w.a_bundle,
                &w.alice.public_key_bytes(),
                &frame
            )
            .unwrap(),
            Vec::<Vec<u8>>::new()
        );
        frame[4] = 1;
        frame[5] = 9;
        assert!(dispatch_frame(
            w.b2_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &frame
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn gate_off_rsr1_frame_errors_exactly_as_today() {
        set_lab_session_reset_for_this_thread(Some(0));
        let w = wiped(0x45);
        let err = query(&w, w.b2_dir.path()).unwrap_err();
        set_lab_session_reset_for_this_thread(None);
        assert_eq!(err, "lan frame is not RavenEnvelopeV1");
    }

    fn apply(w: &Wiped, replies: &[Vec<u8>], at: u64) -> QueryOutcome {
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        apply_query_replies(
            &mut store,
            &w.alice.public_key_bytes(),
            &w.bob.public_key_bytes(),
            &w.packed,
            replies,
            at,
        )
        .unwrap()
    }

    #[test]
    fn status_retires_only_the_echoed_session() {
        let _gate = ResetGate::on();
        let w = wiped(0x47);
        // A second, older-style session with Bob (initiated again by Alice).
        let b_bundle = local_bundle(w.b_dir.path(), &w.bob).unwrap();
        let (init, key2) = create_initiator_pair_init(w.a_dir.path(), &w.alice, &b_bundle).unwrap();
        let replies = dispatch_frame(
            w.b_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &wrap_pair_init(&w.alice, &init).unwrap(),
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!()
        };
        IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .confirm_verified_pair_response(
                &key2,
                &init,
                &crate::pair_init::decode_response(&wire).unwrap(),
                now(),
            )
            .unwrap();
        let replies = query(&w, w.b2_dir.path()).unwrap();
        let outcome = apply(&w, &replies, now());
        let QueryOutcome::Retired { session_id, cause } = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(
            cause,
            crate::indexed_session_store::SessionRetireCause::PeerNoSession
        );
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        assert_eq!(
            store.record_key_for_session_id(&session_id).unwrap(),
            Some(w.key.clone())
        );
        assert_eq!(
            store
                .find_sendable_sessions_for_peer_at(&w.bob.public_key_bytes(), now())
                .unwrap(),
            vec![key2]
        );
        // Idempotent.
        assert!(matches!(
            apply(&w, &replies, now()),
            QueryOutcome::Retired { .. }
        ));
    }

    #[test]
    fn status_for_delivered_or_unknown_object_is_ignored() {
        let _gate = ResetGate::on();
        let w = wiped(0x49);
        // Unknown echo: a status for an object Alice never sent.
        let mut other = Envelope::unpack(&w.packed).unwrap();
        other.message_id = [0x5a; 16];
        other.sign_with(&w.alice);
        let forged_query =
            session_query_frame(&w.alice, &w.bob.public_key_bytes(), &other.pack(), now()).unwrap();
        let replies = dispatch_frame(
            w.b2_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &forged_query,
        )
        .unwrap();
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        assert_eq!(
            apply_query_replies(
                &mut store,
                &w.alice.public_key_bytes(),
                &w.bob.public_key_bytes(),
                &other.pack(),
                &replies,
                now()
            )
            .unwrap(),
            QueryOutcome::Transient(session_reset::RESET_UNKNOWN_ECHO)
        );
        // Echo mismatch: the reply answers another object than the one asked.
        assert_eq!(
            apply(&w, &replies, now()),
            QueryOutcome::Transient(session_reset::RESET_ECHO_MISMATCH)
        );
        // Delivered: Bob (with state) ACKs it first.
        let ack = dispatch_frame(
            w.b_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &w.packed,
        )
        .unwrap();
        let b_bundle = local_bundle(w.b_dir.path(), &w.bob).unwrap();
        store
            .accept_ack_envelope(&w.key, &ack[0], &b_bundle.cert, false, now())
            .unwrap();
        let replies = query(&w, w.b2_dir.path()).unwrap();
        assert_eq!(
            apply(&w, &replies, now()),
            QueryOutcome::Transient(session_reset::RESET_ALREADY_DELIVERED)
        );
        assert_eq!(apply(&w, &[], now()), QueryOutcome::NoAnswer);
    }

    #[test]
    fn status_signed_by_another_contact_cannot_retire() {
        let _gate = ResetGate::on();
        let w = wiped(0x4b);
        let carol = Identity::from_seed(&[0x4d; 32]);
        let env = Envelope::unpack(&w.packed).unwrap();
        let forged = encode_signed(
            &carol,
            &w.alice.public_key_bytes(),
            now(),
            &Rsr1Body::SessionStatus {
                status: SessionStatusCode::NoSession,
                echoed_env_type: env.env_type,
                echoed_object: crate::bridge::authenticated_object_digest(&env),
                echoed_mid: env.message_id,
            },
        )
        .unwrap();
        assert_eq!(apply(&w, &[forged], now()), QueryOutcome::NoAnswer);
        assert_eq!(
            IndexedSessionStore::open(w.a_dir.path())
                .unwrap()
                .find_sendable_sessions_for_peer_at(&w.bob.public_key_bytes(), now())
                .unwrap(),
            vec![w.key.clone()]
        );
    }

    /// Bob initiated; Alice (responder) sealed under it. Bob says "no
    /// session": young sessions are transient for the responder, older ones
    /// retire. Fallback without `confirmed_at` uses the head plus the skew.
    #[test]
    fn young_responder_session_is_transient_initiator_is_definitive() {
        let _gate = ResetGate::on();
        let alice = Identity::from_seed(&[0x51; 32]);
        let bob = Identity::from_seed(&[0x52; 32]);
        let (a_dir, b_dir, b2_dir) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        // Bob → Alice pairing: Alice is the responder.
        let (b_bundle, a_bundle) = confirm_alice_to_bob(b_dir.path(), a_dir.path(), &bob, &alice);
        let key = IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .find_confirmed_session_for_peer_at(&bob.public_key_bytes(), now())
            .unwrap()
            .unwrap();
        assert_eq!(key.responder_device_ed25519, alice.public_key_bytes());
        let packed = seal_under(a_dir.path(), &alice, &key, "young");
        publish_and_install(b2_dir.path(), &bob);
        write_contact(b2_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b2_dir.path(), &a_bundle).unwrap();
        let frame = session_query_frame(&alice, &bob.public_key_bytes(), &packed, now()).unwrap();
        let replies = dispatch_frame(
            b2_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &frame,
        )
        .unwrap();
        let _ = b_bundle;
        let run = |at: u64| {
            let mut store = IndexedSessionStore::open(a_dir.path()).unwrap();
            apply_query_replies(
                &mut store,
                &alice.public_key_bytes(),
                &bob.public_key_bytes(),
                &packed,
                &replies,
                at,
            )
            .unwrap()
        };
        let min_age = session_reset::RESET_NO_SESSION_MIN_AGE_MS;
        assert_eq!(
            run(now()),
            QueryOutcome::Transient(session_reset::RESET_TRANSIENT_YOUNG_SESSION)
        );
        // `confirmed_at_ms` decides: stamped two minutes ago, the same answer
        // now retires (the head alone would still say young).
        IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .set_confirmed_at_for_tests((now() - 2 * min_age) as i64);
        let mut copy = IndexedSessionStore::open(a_dir.path()).unwrap();
        let sid = copy.session_id_for_record_key(&key).unwrap();
        assert!(copy
            .session_reset_info(&sid)
            .unwrap()
            .unwrap()
            .confirmed_at_ms
            .is_some());
        drop(copy);
        // Check on a throwaway copy of the decision: retire is idempotent, so
        // undo by deleting the retirement before the head-fallback checks.
        assert!(matches!(run(now()), QueryOutcome::Retired { .. }));
        rusqlite::Connection::open(
            a_dir
                .path()
                .join(crate::indexed_session_store::INDEXED_SESSION_METADATA_FILE),
        )
        .unwrap()
        .execute("DELETE FROM indexed_session_reset", [])
        .unwrap();
        // Without the confirmed_at sidecar: head created_at + skew + min age.
        let skew = crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS;
        assert_eq!(
            run(now() + min_age + 1_000),
            QueryOutcome::Transient(session_reset::RESET_TRANSIENT_YOUNG_SESSION)
        );
        assert!(matches!(
            run(now() + skew + min_age + 1_000),
            QueryOutcome::Retired { .. }
        ));
    }

    #[test]
    fn initiator_no_session_is_definitive_at_once() {
        let _gate = ResetGate::on();
        let w = wiped(0x53);
        let replies = query(&w, w.b2_dir.path()).unwrap();
        assert!(matches!(
            apply(&w, &replies, now()),
            QueryOutcome::Retired { .. }
        ));
    }

    #[test]
    fn presented_cert_renewal_retires_sessions_bound_to_other_certs() {
        let w = wiped(0x55);
        let peer = w.bob.public_key_bytes();
        let old = local_bundle(w.b_dir.path(), &w.bob).unwrap();
        let fresh = local_bundle(w.b2_dir.path(), &w.bob).unwrap();
        assert_ne!(old.cert, fresh.cert);
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        // The bound cert itself changes nothing.
        assert_eq!(
            note_presented_cert(w.a_dir.path(), &mut store, &peer, &old.cert, now()).unwrap(),
            0
        );
        // Another key's cert changes nothing.
        let carol = Identity::from_seed(&[0x57; 32]);
        let c_dir = tempfile::tempdir().unwrap();
        publish_and_install(c_dir.path(), &carol);
        let carol_cert = local_bundle(c_dir.path(), &carol).unwrap().cert;
        assert_eq!(
            note_presented_cert(w.a_dir.path(), &mut store, &peer, &carol_cert, now()).unwrap(),
            0
        );
        assert_eq!(
            note_presented_cert(w.a_dir.path(), &mut store, &peer, &fresh.cert, now()).unwrap(),
            1
        );
        assert!(store
            .find_sendable_sessions_for_peer_at(&peer, now())
            .unwrap()
            .is_empty());
        let sid = store.session_id_for_record_key(&w.key).unwrap();
        let info = store.session_reset_info(&sid).unwrap().unwrap();
        assert_eq!(
            info.retire_cause,
            Some(crate::indexed_session_store::SessionRetireCause::PeerCertRenewed)
        );
    }

    /// Security: a revoked lineage that shows up with a new certificate is
    /// the revocation path's business; it never retires (and so never
    /// re-pairs) anything.
    #[test]
    fn revoked_lineage_recertified_under_new_device_id_is_not_retired_or_repaired() {
        let _gate = ResetGate::on();
        let w = wiped(0x59);
        let peer = w.bob.public_key_bytes();
        // Bob's device "ash-primary" was revoked (legacy record, device id only).
        let rec = RevocationRecord::issue(&w.bob, PRIMARY_DEVICE_ID, 1, now(), "lost").unwrap();
        let mut rev = RevocationStore::load_checked(w.a_dir.path()).unwrap();
        assert!(rev.apply(rec).unwrap());
        rev.save(w.a_dir.path()).unwrap();
        // The seed holder re-certifies the same key under a new device id.
        let evil_dir = tempfile::tempdir().unwrap();
        let (evil_cert, _) =
            ensure_local_device_certificate(evil_dir.path(), &w.bob, "evil-id").unwrap();
        assert_eq!(evil_cert.device_id, "evil-id");
        assert!(!crate::outbox::peer_lineage_denied(w.a_dir.path(), &evil_cert).unwrap());
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        assert_eq!(
            note_presented_cert(w.a_dir.path(), &mut store, &peer, &evil_cert, now()).unwrap(),
            0,
            "a revoked identity's sessions are never retired by a new certificate"
        );
        assert_eq!(
            store
                .find_sendable_sessions_for_peer_at(&peer, now())
                .unwrap(),
            vec![w.key.clone()]
        );
    }

    #[test]
    fn seal_app_payload_under_session_reports_session_required_when_all_retired() {
        let w = wiped(0x5b);
        let peer = w.bob.public_key_bytes();
        IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .retire_session(
                &w.key,
                &peer,
                crate::indexed_session_store::SessionRetireCause::PeerNoSession,
                now(),
            )
            .unwrap();
        let err = seal_app_payload_under_session(
            w.a_dir.path(),
            &w.alice,
            &hex::encode(peer),
            b"after reset",
        )
        .unwrap_err();
        assert_eq!(
            err,
            format!("{ATSAM_SESSION_REQUIRED}: {SESSION_REQUIRED_AFTER_RESET}")
        );
        assert_eq!(
            map_seal_store_error(IndexedSessionStoreError::SessionRetired),
            err
        );
    }

    // ---- reset step (§9) ----

    use crate::outbox::{OutboxCarrier, OutboxRoute};
    use crate::session_reset::{run_reset_step, ResetEnv, ResetIo, ResetStep};

    /// A's side of the link to one Bob directory: probes return Bob's offer,
    /// frames are dispatched at Bob exactly as the listener does.
    struct LinkTo<'a> {
        a_dir: &'a Path,
        b_dir: &'a Path,
        bob: &'a Identity,
        a_bundle: &'a LanBundle,
        alice: &'a Identity,
        dials: Vec<usize>,
    }

    impl ResetIo for LinkTo<'_> {
        fn locked(
            &mut self,
            f: &mut dyn FnMut(&mut IndexedSessionStore) -> Result<(), String>,
        ) -> Result<(), String> {
            let mut store =
                IndexedSessionStore::open(self.a_dir).map_err(|e| e.redacted_display())?;
            f(&mut store)
        }
        fn dial(
            &mut self,
            _route: &OutboxRoute,
            frames: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            self.dials.push(frames.len());
            let offer = crate::lan_rlb1::encode_offer(&local_bundle(self.b_dir, self.bob)?)?;
            let mut replies = vec![offer];
            for frame in frames {
                replies.extend(dispatch_frame(
                    self.b_dir,
                    self.bob,
                    self.a_bundle,
                    &self.alice.public_key_bytes(),
                    frame,
                )?);
            }
            Ok(replies)
        }
    }

    fn link<'a>(w: &'a Wiped, b_dir: &'a Path) -> LinkTo<'a> {
        LinkTo {
            a_dir: w.a_dir.path(),
            b_dir,
            bob: &w.bob,
            a_bundle: &w.a_bundle,
            alice: &w.alice,
            dials: Vec::new(),
        }
    }

    /// Seal `text` like `ash send` does: stage the body and write `queued`.
    fn send_staged(w: &Wiped, key: &IndexedSessionRecordKey, text: &str) -> ([u8; 16], Vec<u8>) {
        let packed = seal_under(w.a_dir.path(), &w.alice, key, text);
        let env = Envelope::unpack(&packed).unwrap();
        let sid = IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .session_id_for_record_key(key)
            .unwrap();
        ensure_outbound_queued_history(
            w.a_dir.path(),
            &w.bob.public_key_bytes(),
            &sid,
            &crate::bridge::authenticated_object_digest(&env),
            &env.message_id,
            env.created_at,
            Some(text),
        )
        .unwrap();
        (env.message_id, packed)
    }

    fn env_for<'a>(
        w: &'a Wiped,
        routes: &'a [OutboxRoute],
        confirmed: bool,
        at: u64,
    ) -> ResetEnv<'a> {
        ResetEnv {
            data_dir: w.a_dir.path(),
            identity: &w.alice,
            peer: w.bob.public_key_bytes(),
            routes,
            user_confirmed: confirmed,
            now_ms: at,
        }
    }

    fn lan(dial: &str) -> Vec<OutboxRoute> {
        vec![OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: dial.into(),
        }]
    }

    /// Wiped Bob, three staged messages from Alice; the first was queried and
    /// its session retired.
    fn wiped_with_backlog(seed: u8) -> (Wiped, Vec<[u8; 16]>) {
        let w = wiped(seed);
        // `w.packed` was sealed without a body: replace the backlog with
        // staged messages (abandon the body-less one first).
        let digest =
            crate::bridge::authenticated_object_digest(&Envelope::unpack(&w.packed).unwrap());
        IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .abandon_undelivered_outbound(&w.key, &digest)
            .unwrap();
        let mut mids = Vec::new();
        let mut first = None;
        for text in ["q1", "q2", "q3"] {
            let (mid, packed) = send_staged(&w, &w.key, text);
            first.get_or_insert(packed);
            mids.push(mid);
        }
        let frame = session_query_frame(
            &w.alice,
            &w.bob.public_key_bytes(),
            first.as_ref().unwrap(),
            now(),
        )
        .unwrap();
        let replies = dispatch_frame(
            w.b2_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &frame,
        )
        .unwrap();
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        let outcome = apply_query_replies(
            &mut store,
            &w.alice.public_key_bytes(),
            &w.bob.public_key_bytes(),
            first.as_ref().unwrap(),
            &replies,
            now(),
        )
        .unwrap();
        assert!(
            matches!(outcome, QueryOutcome::Retired { .. }),
            "{outcome:?}"
        );
        (w, mids)
    }

    fn deliver_resealed(w: &Wiped, report: &crate::session_reset::ResealReport) -> Vec<Vec<u8>> {
        report
            .resealed
            .iter()
            .map(|r| {
                dispatch_frame(
                    w.b2_dir.path(),
                    &w.bob,
                    &w.a_bundle,
                    &w.alice.public_key_bytes(),
                    &r.new.immutable_envelope_bytes,
                )
                .unwrap()
                .remove(0)
            })
            .collect()
    }

    fn history_delivery(w: &Wiped, mid: &[u8; 16]) -> Option<String> {
        ChatHistory::load(w.a_dir.path())
            .unwrap()
            .for_peer(&hex::encode(w.bob.public_key_bytes()))
            .into_iter()
            .find(|e| e.direction == "out" && e.message_id_hex == hex::encode(mid))
            .map(|e| e.delivery.clone())
    }

    #[test]
    fn reset_step_reseals_backlog_in_order_into_a_new_local_session() {
        let _gate = ResetGate::on();
        let (w, mids) = wiped_with_backlog(0x61);
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap();
        let ResetStep::Resealed(report) = step else {
            panic!("{step:?}")
        };
        assert_eq!(
            report
                .resealed
                .iter()
                .map(|r| r.message_id)
                .collect::<Vec<_>>(),
            mids
        );
        // One probe, then one PairInit dial (one frame).
        assert_eq!(io.dials, vec![0, 1]);
        let originals = IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .message_copies_for_recipient(&w.bob.public_key_bytes(), &mids[0])
            .unwrap();
        assert_eq!(originals.len(), 2);
        for (r, mid) in report.resealed.iter().zip(&mids) {
            assert_eq!(r.new.message_id, *mid);
            assert_ne!(r.new.object_digest, r.old_digest);
            assert_eq!(history_delivery(&w, mid).as_deref(), Some("queued"));
        }
        // §9.4 step 5: the deadline is never extended. The target session ends
        // later than the original, so each copy keeps its original expiry.
        let target_end = IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .session_expires_at(
                &IndexedSessionStore::open(w.a_dir.path())
                    .unwrap()
                    .record_key_for_session_id(&report.resealed[0].new.session_id)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let old_end = IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .session_expires_at(&w.key)
            .unwrap();
        assert!(target_end > old_end);
        for r in &report.resealed {
            let new_env = Envelope::unpack(&r.new.immutable_envelope_bytes).unwrap();
            assert!(new_env.expires_at <= old_end, "deadline extended");
        }
        let acks = deliver_resealed(&w, &report);
        assert_eq!(acks.len(), 3);
        let inbox = IndexedSessionStore::open(w.b2_dir.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap();
        assert_eq!(
            inbox
                .iter()
                .map(|r| r.plaintext.clone())
                .collect::<Vec<_>>(),
            vec![b"q1".to_vec(), b"q2".to_vec(), b"q3".to_vec()]
        );
        // Nothing left to do.
        let mut io = link(&w, w.b2_dir.path());
        assert!(matches!(
            run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap(),
            ResetStep::Nothing
        ));
    }

    /// Security (P2): a contact routed to a non-local address — someone who
    /// holds the seed elsewhere — gets no PairInit and no re-sealed plaintext
    /// without the user's confirmation.
    #[test]
    fn seed_only_impersonator_on_non_local_route_gets_no_plaintext() {
        let _gate = ResetGate::on();
        let (w, _mids) = wiped_with_backlog(0x63);
        let routes = lan("203.0.113.5:7420");
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap();
        assert!(
            matches!(
                step,
                ResetStep::Held {
                    code: "PEER_RESET_CONFIRM",
                    rows: 3
                }
            ),
            "{step:?}"
        );
        assert!(io.dials.is_empty(), "no dial at all: {:?}", io.dials);
        // Bob lost the session and set up nothing since: ash says he lost
        // it (Phase 6 review re-verify, sensing-1), not that he replaced it.
        assert!(!IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .contact_replaced_retired_session(&w.bob.public_key_bytes(), now())
            .unwrap());
        // The user confirms: the same route is used.
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, true, now()), &mut io).unwrap();
        let ResetStep::Resealed(report) = step else {
            panic!("{step:?}")
        };
        assert_eq!(report.resealed.len(), 3);
    }

    #[test]
    fn peer_initiated_twin_is_never_a_target() {
        let _gate = ResetGate::on();
        let (w, _mids) = wiped_with_backlog(0x65);
        // Bob (fresh) pairs with Alice: Alice is the responder of this one.
        let b2_bundle = local_bundle(w.b2_dir.path(), &w.bob).unwrap();
        cache_peer_bundle(w.a_dir.path(), &b2_bundle).unwrap();
        let (init, key) = create_initiator_pair_init(w.b2_dir.path(), &w.bob, &w.a_bundle).unwrap();
        let replies = dispatch_frame(
            w.a_dir.path(),
            &w.alice,
            &b2_bundle,
            &w.bob.public_key_bytes(),
            &wrap_pair_init(&w.bob, &init).unwrap(),
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!()
        };
        IndexedSessionStore::open(w.b2_dir.path())
            .unwrap()
            .confirm_verified_pair_response(
                &key,
                &init,
                &crate::pair_init::decode_response(&wire).unwrap(),
                now(),
            )
            .unwrap();
        assert_eq!(
            IndexedSessionStore::open(w.a_dir.path())
                .unwrap()
                .reseal_target_for_peer(&w.bob.public_key_bytes(), false, now())
                .unwrap(),
            None
        );
        let routes = lan("10.0.0.7:7420");
        let mut io = link(&w, w.b2_dir.path());
        let ResetStep::Resealed(report) =
            run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap()
        else {
            panic!()
        };
        let store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        for r in &report.resealed {
            let k = store
                .record_key_for_session_id(&r.new.session_id)
                .unwrap()
                .unwrap();
            assert_eq!(k.initiator_device_ed25519, w.alice.public_key_bytes());
        }
    }

    #[test]
    fn fork_evidence_holds_automatic_reseal_until_confirmed() {
        let _gate = ResetGate::on();
        let (w, _mids) = wiped_with_backlog(0x67);
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        let sid = store.session_id_for_record_key(&w.key).unwrap();
        let grace = crate::session_reset::RESET_FORK_GRACE_MS;
        let made = now() + crate::session_reset::RESET_FORK_MADE_AFTER_MS;
        assert!(store
            .note_inbound_on_retired(&sid, true, made, now() + grace)
            .unwrap());
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let step =
            run_reset_step(&env_for(&w, &routes, false, now() + grace + 1), &mut io).unwrap();
        assert!(
            matches!(
                step,
                ResetStep::Held {
                    code: "PEER_IDENTITY_FORK",
                    ..
                }
            ),
            "{step:?}"
        );
        assert!(io.dials.is_empty());
        store
            .confirm_peer_reset(&w.bob.public_key_bytes(), now() + grace + 2)
            .unwrap();
        let mut io = link(&w, w.b2_dir.path());
        assert!(matches!(
            run_reset_step(&env_for(&w, &routes, false, now() + grace + 3), &mut io).unwrap(),
            ResetStep::Resealed(_)
        ));
    }

    #[test]
    fn third_round_in_24h_holds_loop_and_does_not_fail_history() {
        let _gate = ResetGate::on();
        let (w, mids) = wiped_with_backlog(0x69);
        let b2_bundle = local_bundle(w.b2_dir.path(), &w.bob).unwrap();
        cache_peer_bundle(w.a_dir.path(), &b2_bundle).unwrap();
        // Three earlier rounds today (provisional sessions that never confirmed).
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        for _ in 0..3 {
            let (_init, key) =
                create_initiator_pair_init(w.a_dir.path(), &w.alice, &b2_bundle).unwrap();
            store
                .mark_session_initiated(
                    &key,
                    &w.bob.public_key_bytes(),
                    true,
                    true,
                    now() - 120_000,
                )
                .unwrap();
        }
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap();
        assert!(
            matches!(
                step,
                ResetStep::Held {
                    code: "PEER_RESET_LOOP",
                    rows: 3
                }
            ),
            "{step:?}"
        );
        for mid in &mids {
            assert_eq!(history_delivery(&w, mid).as_deref(), Some("queued"));
        }
        // `raven outbox resend` confirms and releases them.
        let mut io = link(&w, w.b2_dir.path());
        assert!(matches!(
            run_reset_step(&env_for(&w, &routes, true, now()), &mut io).unwrap(),
            ResetStep::Resealed(_)
        ));
    }

    #[test]
    fn cooldown_holds_a_second_round_within_a_minute() {
        let _gate = ResetGate::on();
        let (w, _mids) = wiped_with_backlog(0x6b);
        let b2_bundle = local_bundle(w.b2_dir.path(), &w.bob).unwrap();
        cache_peer_bundle(w.a_dir.path(), &b2_bundle).unwrap();
        let (_init, key) =
            create_initiator_pair_init(w.a_dir.path(), &w.alice, &b2_bundle).unwrap();
        IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .mark_session_initiated(&key, &w.bob.public_key_bytes(), true, true, now())
            .unwrap();
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap();
        assert!(
            matches!(
                step,
                ResetStep::Held {
                    code: "PEER_RESET",
                    ..
                }
            ),
            "{step:?}"
        );
    }

    #[test]
    fn bodyless_row_is_abandoned_as_peer_reset_no_body() {
        let _gate = ResetGate::on();
        let w = wiped(0x6d);
        let replies = query(&w, w.b2_dir.path()).unwrap();
        assert!(matches!(
            apply(&w, &replies, now()),
            QueryOutcome::Retired { .. }
        ));
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let ResetStep::Resealed(report) =
            run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap()
        else {
            panic!()
        };
        let env = Envelope::unpack(&w.packed).unwrap();
        assert_eq!(report.no_body, vec![env.message_id]);
        assert!(report.resealed.is_empty());
        assert!(io.dials.is_empty());
    }

    #[test]
    fn expired_original_deadline_is_marked_expired_not_resealed() {
        let _gate = ResetGate::on();
        let _horizon = HorizonHeld::on();
        let (w, mids) = wiped_with_backlog(0x6f);
        let orig = IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .retired_undelivered_messages_for_recipient(&w.bob.public_key_bytes())
            .unwrap()
            .iter()
            .map(|r| {
                Envelope::unpack(&r.immutable_envelope_bytes)
                    .unwrap()
                    .expires_at
            })
            .min()
            .unwrap();
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let at = orig - 10_000;
        let ResetStep::Resealed(report) =
            run_reset_step(&env_for(&w, &routes, false, at), &mut io).unwrap()
        else {
            panic!()
        };
        assert_eq!(report.expired.len(), 3);
        for mid in &mids {
            assert_eq!(history_delivery(&w, mid).as_deref(), Some("expired"));
        }
    }

    #[test]
    fn late_ack_on_old_session_settles_resealed_sibling_and_vice_versa() {
        let _gate = ResetGate::on();
        let (w, mids) = wiped_with_backlog(0x71);
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let ResetStep::Resealed(report) =
            run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap()
        else {
            panic!()
        };
        // The re-sealed copy of q2 is ACKed by the reinstalled Bob; the store
        // accepts it under the new session, and reconcile settles every other
        // copy and the history.
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        let acks = deliver_resealed(&w, &report);
        let b2_bundle = local_bundle(w.b2_dir.path(), &w.bob).unwrap();
        let new_key = store
            .record_key_for_session_id(&report.resealed[1].new.session_id)
            .unwrap()
            .unwrap();
        store
            .accept_ack_envelope(&new_key, &acks[1], &b2_bundle.cert, false, now())
            .unwrap();
        crate::session_reset::reconcile_resealed_outbound(
            w.a_dir.path(),
            &w.alice,
            &mut store,
            &w.bob.public_key_bytes(),
            now(),
        )
        .unwrap();
        assert_eq!(history_delivery(&w, &mids[1]).as_deref(), Some("delivered"));
        let copies = store
            .message_copies_for_recipient(&w.bob.public_key_bytes(), &mids[1])
            .unwrap();
        assert!(copies.iter().all(|c| !c.has_outbox_row
            || c.delivery_state
                == Some(crate::indexed_session_store::EndpointDeliveryState::Delivered)));
    }

    #[test]
    fn crash_injection_converges_to_exactly_one_live_copy() {
        use crate::session_reset::fault::{arm, ResealFault};
        for point in [
            ResealFault::AfterLedger,
            ResealFault::AfterW1,
            ResealFault::AfterW2,
        ] {
            let _gate = ResetGate::on();
            let (w, mids) = wiped_with_backlog(0x73 + point as u8 * 2);
            let routes = lan("192.168.1.20:7420");
            arm(Some(point));
            let mut io = link(&w, w.b2_dir.path());
            let first = run_reset_step(&env_for(&w, &routes, false, now()), &mut io);
            assert!(first.is_err(), "{point:?}: {first:?}");
            arm(None);
            // Next attempt: reconcile, then finish.
            let mut io = link(&w, w.b2_dir.path());
            let step =
                run_reset_step(&env_for(&w, &routes, false, now() + 61_000), &mut io).unwrap();
            assert!(
                matches!(step, ResetStep::Resealed(_) | ResetStep::Nothing),
                "{point:?}: {step:?}"
            );
            let store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
            for mid in &mids {
                let live: Vec<_> = store
                    .message_copies_for_recipient(&w.bob.public_key_bytes(), mid)
                    .unwrap()
                    .into_iter()
                    .filter(|c| c.has_outbox_row)
                    .collect();
                assert_eq!(live.len(), 1, "{point:?}: {live:?}");
                assert!(!live[0].retired, "{point:?}");
                assert_ne!(history_delivery(&w, mid).as_deref(), Some("failed"));
                let staged = crate::chat_history::load_staged_outbound_body(w.a_dir.path(), mid)
                    .unwrap()
                    .unwrap();
                assert_eq!(staged.session_id_hex, hex::encode(live[0].session_id));
            }
        }
    }

    #[test]
    fn reseal_hands_off_a_leftover_prepared_row_first() {
        let _gate = ResetGate::on();
        let (w, mids) = wiped_with_backlog(0x7b);
        let peer = w.bob.public_key_bytes();
        // Alice already set up a local session with the reinstalled Bob...
        let b2_bundle = local_bundle(w.b2_dir.path(), &w.bob).unwrap();
        cache_peer_bundle(w.a_dir.path(), &b2_bundle).unwrap();
        let (init, target) =
            create_initiator_pair_init(w.a_dir.path(), &w.alice, &b2_bundle).unwrap();
        let replies = dispatch_frame(
            w.b2_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &wrap_pair_init(&w.alice, &init).unwrap(),
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!()
        };
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        store
            .confirm_verified_pair_response(
                &target,
                &init,
                &crate::pair_init::decode_response(&wire).unwrap(),
                now(),
            )
            .unwrap();
        store
            .mark_session_initiated(&target, &peer, true, false, now())
            .unwrap();
        // ...and a message in it whose handoff failed: Prepared, staged.
        let (cert, reg) =
            ensure_local_device_certificate(w.a_dir.path(), &w.alice, PRIMARY_DEVICE_ID).unwrap();
        let device = AuthorizedEndpointDevice::authorize(&cert, &w.alice, &reg, now()).unwrap();
        let t = now();
        let expires = envelope_expires(t, store.session_expires_at(&target).unwrap()).unwrap();
        assert!(store
            .send_message_envelope(
                &target,
                "stuck",
                &device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |_, _| { Err(()) }
            )
            .is_err());
        let stuck = store
            .pending_endpoint_outbound_for_recipient(Some(&peer))
            .unwrap()
            .pop()
            .unwrap();
        ensure_outbound_queued_history(
            w.a_dir.path(),
            &peer,
            &stuck.session_id,
            &stuck.object_digest,
            &stuck.message_id,
            t,
            Some("stuck"),
        )
        .unwrap();
        drop(store);
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap();
        let ResetStep::Resealed(report) = step else {
            panic!("{step:?}")
        };
        assert!(io.dials.is_empty(), "the existing target needs no round");
        assert_eq!(
            report
                .resealed
                .iter()
                .map(|r| r.message_id)
                .collect::<Vec<_>>(),
            mids
        );
        assert!(IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .pending_endpoint_outbound_for_recipient(Some(&peer))
            .unwrap()
            .is_empty());
        assert_eq!(
            history_delivery(&w, &stuck.message_id).as_deref(),
            Some("queued")
        );
    }

    // ---- review regressions (lost-state recovery) ----

    /// Give Alice a locally initiated, confirmed session with the reinstalled
    /// Bob (what an ordinary `ash send` would set up), without a reset round.
    fn ordinary_local_session(w: &Wiped) -> IndexedSessionRecordKey {
        let b2_bundle = local_bundle(w.b2_dir.path(), &w.bob).unwrap();
        cache_peer_bundle(w.a_dir.path(), &b2_bundle).unwrap();
        let (init, key) = create_initiator_pair_init(w.a_dir.path(), &w.alice, &b2_bundle).unwrap();
        let replies = dispatch_frame(
            w.b2_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &wrap_pair_init(&w.alice, &init).unwrap(),
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!()
        };
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        store
            .confirm_verified_pair_response(
                &key,
                &init,
                &crate::pair_init::decode_response(&wire).unwrap(),
                now(),
            )
            .unwrap();
        store
            .mark_session_initiated(&key, &w.bob.public_key_bytes(), true, false, now())
            .unwrap();
        key
    }

    #[test]
    fn loop_hold_is_not_bypassed_by_an_ordinary_session() {
        let _gate = ResetGate::on();
        let (w, mids) = wiped_with_backlog(0x91);
        let b2_bundle = local_bundle(w.b2_dir.path(), &w.bob).unwrap();
        cache_peer_bundle(w.a_dir.path(), &b2_bundle).unwrap();
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        for _ in 0..3 {
            let (_init, key) =
                create_initiator_pair_init(w.a_dir.path(), &w.alice, &b2_bundle).unwrap();
            store
                .mark_session_initiated(
                    &key,
                    &w.bob.public_key_bytes(),
                    true,
                    true,
                    now() - 120_000,
                )
                .unwrap();
        }
        drop(store);
        ordinary_local_session(&w);
        let routes = lan("192.168.1.20:7420");
        let cap = crate::security_sense::tests::Capture::start();
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap();
        assert!(
            matches!(
                step,
                ResetStep::Held {
                    code: "PEER_RESET_LOOP",
                    rows: 3
                }
            ),
            "{step:?}"
        );
        // Phase 6b S17: the hold is SEC_RESET_LOOP about Bob, once however
        // often a step finds it.
        let mut io = link(&w, w.b2_dir.path());
        let again = run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap();
        assert!(matches!(again, ResetStep::Held { .. }), "{again:?}");
        if let Some(cap) = cap {
            let loops: Vec<_> = cap
                .kinds()
                .into_iter()
                .filter(|(kind, ..)| *kind == SecKind::ResetLoop)
                .collect();
            let bob = crate::security_events::Attribution::Contact {
                peer: w.bob.public_key_bytes(),
            };
            assert_eq!(loops, vec![(SecKind::ResetLoop, bob, Via::Local)]);
        }
        for mid in &mids {
            assert_eq!(history_delivery(&w, mid).as_deref(), Some("queued"));
        }
        // The user confirms: re-sealed into the ordinary session.
        let mut io = link(&w, w.b2_dir.path());
        assert!(matches!(
            run_reset_step(&env_for(&w, &routes, true, now()), &mut io).unwrap(),
            ResetStep::Resealed(r) if r.resealed.len() == 3
        ));
    }

    #[test]
    fn an_unreadable_revocation_store_abandons_nothing() {
        let _gate = ResetGate::on();
        let (w, mids) = wiped_with_backlog(0x93);
        ordinary_local_session(&w);
        let rev = w.a_dir.path().join("revocations.json");
        std::fs::write(&rev, b"{not json").unwrap();
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, false, now()), &mut io);
        assert!(step.is_err(), "{step:?}");
        for mid in &mids {
            assert_eq!(history_delivery(&w, mid).as_deref(), Some("queued"));
        }
        assert_eq!(
            IndexedSessionStore::open(w.a_dir.path())
                .unwrap()
                .retired_undelivered_messages_for_recipient(&w.bob.public_key_bytes())
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn rows_at_the_cap_are_held_not_reported_as_resealed() {
        let _gate = ResetGate::on();
        let (w, mids) = wiped_with_backlog(0x95);
        ordinary_local_session(&w);
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        for mid in &mids {
            for _ in 0..crate::session_reset::RESET_MAX_RESEALS_PER_MESSAGE {
                store
                    .bump_reseal_ledger(&w.bob.public_key_bytes(), mid, now() + 3_600_000, now())
                    .unwrap();
            }
        }
        drop(store);
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap();
        assert!(
            matches!(
                step,
                ResetStep::Held {
                    code: "PEER_RESET_LOOP",
                    rows: 3
                }
            ),
            "{step:?}"
        );
        // With the user's confirmation they are given up as capped, not resealed.
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, true, now()), &mut io).unwrap();
        let ResetStep::Resealed(report) = step else {
            panic!("{step:?}")
        };
        assert_eq!(report.capped.len(), 3);
        for mid in &mids {
            assert_eq!(history_delivery(&w, mid).as_deref(), Some("failed"));
        }
    }

    #[test]
    fn a_peer_clock_ahead_does_not_starve_target_selection() {
        let _gate = ResetGate::on();
        let (w, _mids) = wiped_with_backlog(0x97);
        // The retired session looks created 4 min in the future (peer clock).
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        let sid = store.session_id_for_record_key(&w.key).unwrap();
        store.set_head_created_at_for_tests(&sid, (now() + 240_000) as i64);
        drop(store);
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap();
        assert!(
            matches!(step, ResetStep::Resealed(ref r) if r.resealed.len() == 3),
            "{step:?}"
        );
    }

    /// Security (review): a retired backlog of a revoked identity is never
    /// re-sealed, whatever certificate the key shows next.
    #[test]
    fn a_revoked_identity_backlog_is_given_up_not_resealed() {
        let _gate = ResetGate::on();
        let (w, mids) = wiped_with_backlog(0x99);
        ordinary_local_session(&w);
        let rec = RevocationRecord::issue(&w.bob, "some-old-device", 1, now(), "lost").unwrap();
        let mut rev = RevocationStore::load_checked(w.a_dir.path()).unwrap();
        assert!(rev.apply(rec).unwrap());
        rev.save(w.a_dir.path()).unwrap();
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        let step = run_reset_step(&env_for(&w, &routes, true, now()), &mut io).unwrap();
        let ResetStep::Resealed(report) = step else {
            panic!("{step:?}")
        };
        assert!(report.resealed.is_empty());
        assert_eq!(report.revoked.len(), 3);
        assert!(io.dials.is_empty(), "no PairInit for a revoked identity");
        for mid in &mids {
            assert_eq!(history_delivery(&w, mid).as_deref(), Some("failed"));
        }
    }

    /// I8 via real traffic: Bob's old state (a second instance with the same
    /// seed) keeps using the session he said was lost.
    #[test]
    fn inbound_traffic_on_a_session_said_lost_records_fork_evidence() {
        let _gate = ResetGate::on();
        let w = wiped(0x9b);
        let peer = w.bob.public_key_bytes();
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        let grace = session_reset::RESET_FORK_GRACE_MS;
        store
            .retire_session(
                &w.key,
                &peer,
                crate::indexed_session_store::SessionRetireCause::PeerNoSession,
                now() - 2 * grace - session_reset::RESET_FORK_MADE_AFTER_MS,
            )
            .unwrap();
        drop(store);
        // The old instance (b_dir still holds the session) sends on it.
        let packed = seal_under(w.b_dir.path(), &w.bob, &w.key, "still here");
        let b_bundle = local_bundle(w.b_dir.path(), &w.bob).unwrap();
        dispatch_frame(w.a_dir.path(), &w.alice, &b_bundle, &peer, &packed).unwrap();
        let state = IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .peer_reset_state(&peer)
            .unwrap();
        assert!(state.fork_evidence_at_ms.is_some());
    }

    /// A late ACK on the old session (Bob's old state delivered the old copy)
    /// settles the re-sealed sibling: the history says delivered and the new
    /// copy is never sent.
    #[test]
    fn a_real_late_ack_on_the_old_session_settles_the_resealed_copy() {
        let _gate = ResetGate::on();
        let w = wiped(0x9d);
        let peer = w.bob.public_key_bytes();
        let digest =
            crate::bridge::authenticated_object_digest(&Envelope::unpack(&w.packed).unwrap());
        IndexedSessionStore::open(w.a_dir.path())
            .unwrap()
            .abandon_undelivered_outbound(&w.key, &digest)
            .unwrap();
        let (mid, old_packed) = send_staged(&w, &w.key, "late");
        // Retire S (Bob-new said no session) and re-seal into a new session.
        let frame = session_query_frame(&w.alice, &peer, &old_packed, now()).unwrap();
        let replies = dispatch_frame(
            w.b2_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &frame,
        )
        .unwrap();
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        assert!(matches!(
            apply_query_replies(
                &mut store,
                &w.alice.public_key_bytes(),
                &peer,
                &old_packed,
                &replies,
                now()
            )
            .unwrap(),
            QueryOutcome::Retired { .. }
        ));
        drop(store);
        let routes = lan("192.168.1.20:7420");
        let mut io = link(&w, w.b2_dir.path());
        assert!(matches!(
            run_reset_step(&env_for(&w, &routes, false, now()), &mut io).unwrap(),
            ResetStep::Resealed(ref r) if r.resealed.len() == 1
        ));
        // Bob's OLD instance receives the old copy and ACKs it under S.
        let ack = dispatch_frame(
            w.b_dir.path(),
            &w.bob,
            &w.a_bundle,
            &w.alice.public_key_bytes(),
            &old_packed,
        )
        .unwrap()
        .remove(0);
        let b_bundle = local_bundle(w.b_dir.path(), &w.bob).unwrap();
        dispatch_frame(w.a_dir.path(), &w.alice, &b_bundle, &peer, &ack).unwrap();
        let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
        crate::session_reset::reconcile_resealed_outbound(
            w.a_dir.path(),
            &w.alice,
            &mut store,
            &peer,
            now(),
        )
        .unwrap();
        assert_eq!(history_delivery(&w, &mid).as_deref(), Some("delivered"));
        let live: Vec<_> = store
            .message_copies_for_recipient(&peer, &mid)
            .unwrap()
            .into_iter()
            .filter(|c| c.has_outbox_row)
            .collect();
        assert!(
            live.is_empty(),
            "the re-sealed copy is never sent: {live:?}"
        );
    }

    // --- Privacy pack PP.8: a clear that sticks ---

    const PP8_HOUR: u64 = 60 * 60 * 1000;

    /// Alice and Bob, contacts of each other, with a confirmed session that
    /// Alice initiated (the same record key on both sides).
    struct ChatPair {
        alice: Identity,
        bob: Identity,
        a_dir: tempfile::TempDir,
        b_dir: tempfile::TempDir,
        a_bundle: LanBundle,
        b_bundle: LanBundle,
        key: IndexedSessionRecordKey,
    }

    fn chat_pair(seed: u8) -> ChatPair {
        let alice = Identity::from_seed(&[seed; 32]);
        let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, key) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let replies = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &wrap_pair_init(&alice, &init).unwrap(),
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!("expected PairResponse");
        };
        IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .confirm_verified_pair_response(
                &key,
                &init,
                &crate::pair_init::decode_response(&wire).unwrap(),
                now(),
            )
            .unwrap();
        ChatPair {
            alice,
            bob,
            a_dir,
            b_dir,
            a_bundle,
            b_bundle,
            key,
        }
    }

    impl ChatPair {
        fn alice_key(&self) -> [u8; 32] {
            self.a_bundle.cert.device_ed_pub
        }

        fn bob_key(&self) -> [u8; 32] {
            self.b_bundle.cert.device_ed_pub
        }

        /// Alice's message to Bob, sealed and staged as `raven send` does it
        /// (history `queued`).
        fn staged(&self, text: &str) -> ([u8; 16], Vec<u8>) {
            let packed = seal_under(self.a_dir.path(), &self.alice, &self.key, text);
            let env = Envelope::unpack(&packed).unwrap();
            let sid = IndexedSessionStore::open(self.a_dir.path())
                .unwrap()
                .session_id_for_record_key(&self.key)
                .unwrap();
            ensure_outbound_queued_history(
                self.a_dir.path(),
                &self.bob_key(),
                &sid,
                &crate::bridge::authenticated_object_digest(&env),
                &env.message_id,
                env.created_at,
                Some(text),
            )
            .unwrap();
            (env.message_id, packed)
        }

        /// One of Alice's frames over a link to Bob: Bob's replies.
        fn to_bob(&self, packed: &[u8]) -> Vec<Vec<u8>> {
            dispatch_frame(
                self.b_dir.path(),
                &self.bob,
                &self.a_bundle,
                &self.alice.public_key_bytes(),
                packed,
            )
            .unwrap()
        }

        /// One of Bob's frames (an ACK) over a link to Alice.
        fn to_alice(&self, packed: &[u8]) {
            dispatch_frame(
                self.a_dir.path(),
                &self.alice,
                &self.b_bundle,
                &self.bob.public_key_bytes(),
                packed,
            )
            .unwrap();
        }

        /// `dir`'s chat history with `peer`: (direction, delivery, body).
        fn history(dir: &Path, peer: &[u8; 32]) -> Vec<(String, String, String)> {
            ChatHistory::load(dir)
                .unwrap()
                .for_peer(&hex::encode(peer))
                .into_iter()
                .map(|e| (e.direction.clone(), e.delivery.clone(), e.body.clone()))
                .collect()
        }

        fn bob_history(&self) -> Vec<(String, String, String)> {
            Self::history(self.b_dir.path(), &self.alice_key())
        }

        fn bob_inbox(&self) -> Vec<String> {
            IndexedSessionStore::open(self.b_dir.path())
                .unwrap()
                .list_endpoint_inbox()
                .unwrap()
                .into_iter()
                .map(|row| String::from_utf8(row.plaintext).unwrap())
                .collect()
        }

        /// Bob deletes his chat with Alice ("delete chat", `/clear-local-history`).
        fn bob_deletes_chat(&self) -> crate::privacy::ChatDeletion {
            crate::privacy::delete_chat(self.b_dir.path(), &self.alice_key(), None).unwrap()
        }
    }

    /// Phase 6b P6.25 (S6, S10, S11, S15): what Alice's authenticated link
    /// sends Bob that breaks the rules is noted about Alice, via that link,
    /// and refused with the same text as before; nothing is noted while the
    /// events gate is shut. The object Alice signed over a changed
    /// ciphertext is made here with her own key (in-process; the carrier
    /// matrix needs P6.32's lab helper for it).
    #[test]
    fn a_contacts_refused_frames_are_noted_about_it() {
        use crate::security_events::Attribution;
        use crate::security_sense::tests::{Capture, Shut};
        let p = chat_pair(0x6C);
        let alice_pub = p.alice.public_key_bytes();
        let link = Via::DirectLink(crate::outbox::OutboxCarrier::Lan);
        let alice = Attribution::Contact { peer: alice_pub };
        let to_bob = |bundle: &LanBundle, frame: &[u8]| {
            dispatch_frame(p.b_dir.path(), &p.bob, bundle, &alice_pub, frame)
        };
        let resigned = |change: &dyn Fn(&mut Envelope)| {
            let packed = seal_under(p.a_dir.path(), &p.alice, &p.key, "changed");
            let mut env = Envelope::unpack(&packed).unwrap();
            change(&mut env);
            env.sign_with(&p.alice);
            env.pack()
        };
        let not_rvn1 = "lan frame is not RavenEnvelopeV1";
        {
            let shut = Shut::start();
            assert_eq!(to_bob(&p.a_bundle, b"junk").unwrap_err(), not_rvn1);
            assert_eq!(
                to_bob(&p.b_bundle, b"junk").unwrap_err(),
                "rlb1/noise identity mismatch"
            );
            assert_eq!(shut.noted(), 0);
        }
        let Some(cap) = Capture::start() else {
            return;
        };
        // S15: not RVN1.
        assert_eq!(to_bob(&p.a_bundle, b"junk").unwrap_err(), not_rvn1);
        // S11: a bundle for another identity than the link bound, and an
        // RLB1 offer for another device mid-session.
        assert_eq!(
            to_bob(&p.b_bundle, b"junk").unwrap_err(),
            "rlb1/noise identity mismatch"
        );
        let carol = Identity::from_seed(&[0x6E; 32]);
        let offer = encode_offer(&signed_bundle(
            &carol,
            carol.public_key_bytes(),
            PRIMARY_DEVICE_ID,
        ))
        .unwrap();
        assert_eq!(
            to_bob(&p.a_bundle, &offer).unwrap_err(),
            "rlb1/noise identity mismatch"
        );
        // S6: Alice's signature over a ciphertext whose AEAD tag changed.
        let tampered = resigned(&|env: &mut Envelope| {
            *env.message_ciphertext.last_mut().unwrap() ^= 1;
        });
        assert!(to_bob(&p.a_bundle, &tampered).is_err());
        // S10: a route tag none of Bob's sessions with Alice has.
        let elsewhere = resigned(&|env: &mut Envelope| env.routing_tag[0] ^= 1);
        assert!(to_bob(&p.a_bundle, &elsewhere).is_err());
        // An accepted message notes nothing.
        let fine = seal_under(p.a_dir.path(), &p.alice, &p.key, "fine");
        assert_eq!(to_bob(&p.a_bundle, &fine).unwrap().len(), 1);
        assert_eq!(
            cap.kinds(),
            vec![
                (SecKind::ContactMalformed, alice, link),
                (SecKind::BindingMismatch, alice, link),
                (SecKind::BindingMismatch, alice, link),
                (SecKind::ObjectAuthFail, alice, link),
                (SecKind::SessionUnknown, alice, link),
            ]
        );
    }

    /// Phase 6b P6.25 (S16): Alice's PairInit over the per-initiator claim
    /// quota is refused as before and noted as `SEC_PAIRINIT_FLOOD` about
    /// her, via the link; the ones under it note nothing.
    #[test]
    fn a_pairinit_flood_is_noted_about_the_contact() {
        use crate::prekey_lifecycle::MAX_ACCEPTED_PREKEY_CLAIMS_PER_INITIATOR;
        use crate::security_events::Attribution;
        let p = chat_pair(0x7A);
        let pair_init = || {
            let (init, _) =
                create_initiator_pair_init(p.a_dir.path(), &p.alice, &p.b_bundle).unwrap();
            dispatch_frame(
                p.b_dir.path(),
                &p.bob,
                &p.a_bundle,
                &p.alice.public_key_bytes(),
                &wrap_pair_init(&p.alice, &init).unwrap(),
            )
        };
        let cap = crate::security_sense::tests::Capture::start();
        // chat_pair's own PairInit holds the first claim.
        for _ in 1..MAX_ACCEPTED_PREKEY_CLAIMS_PER_INITIATOR {
            assert_eq!(pair_init().unwrap().len(), 1);
        }
        let refused = pair_init().unwrap_err();
        assert_eq!(refused, PrekeyLifecycleError::ResourceLimit.to_string());
        if let Some(cap) = cap {
            assert_eq!(
                cap.kinds(),
                vec![(
                    SecKind::PairinitFlood,
                    Attribution::Contact {
                        peer: p.alice_key()
                    },
                    Via::DirectLink(crate::outbox::OutboxCarrier::Lan)
                )]
            );
        }
    }

    /// Phase 6b P6.25 (S7): an ACK that comes back on a dial and fails its
    /// outer signature is noted about the contact via that dial (`raven
    /// send` and the worker share `accept_sealed_ack`); the refusal reads as
    /// before.
    #[test]
    fn a_refused_ack_is_noted_about_the_contact_via_the_dial() {
        use crate::outbox::{accept_sealed_ack, AckRejected, OutboxCarrier};
        use crate::security_events::Attribution;
        let p = chat_pair(0x6F);
        let packed = seal_under(p.a_dir.path(), &p.alice, &p.key, "acked");
        let replies = p.to_bob(&packed);
        let mut ack = Envelope::unpack(&replies[0]).unwrap();
        *ack.message_ciphertext.last_mut().unwrap() ^= 1;
        let forged = ack.pack();
        let mut store = IndexedSessionStore::open(p.a_dir.path()).unwrap();
        let mut accept = |carrier| {
            accept_sealed_ack(
                p.a_dir.path(),
                &mut store,
                &p.key,
                &p.b_bundle.cert,
                &forged,
                carrier,
            )
        };
        let shut = crate::security_sense::tests::Shut::start();
        assert!(matches!(
            accept(OutboxCarrier::Lan),
            Err(AckRejected::Refused(_))
        ));
        assert_eq!(shut.noted(), 0);
        drop(shut);
        let Some(cap) = crate::security_sense::tests::Capture::start() else {
            return;
        };
        assert!(matches!(
            accept(OutboxCarrier::Internet),
            Err(AckRejected::Refused(_))
        ));
        assert_eq!(
            cap.kinds(),
            vec![(
                SecKind::ObjectSigFail,
                Attribution::Contact { peer: p.bob_key() },
                Via::Dial(OutboxCarrier::Internet)
            )]
        );
    }

    /// The bug PP.8 fixes (path 1): a cleared chat came back once its session
    /// expired, when the expiry archive wrote every inbox row back into the
    /// history. Received, deleted, then the archive and the whole durable
    /// prune a day later (the lab clock): nothing comes back.
    #[test]
    fn cleared_messages_return_after_session_expiry() {
        let p = chat_pair(0x61);
        for text in ["one", "two", "three"] {
            let packed = seal_under(p.a_dir.path(), &p.alice, &p.key, text);
            assert_eq!(p.to_bob(&packed).len(), 1, "an ACK for {text}");
        }
        assert_eq!(p.bob_history().len(), 3);
        assert_eq!(p.bob_inbox().len(), 3);
        let deleted = p.bob_deletes_chat();
        assert_eq!((deleted.history, deleted.inbox.deleted), (3, 3));
        assert!(p.bob_history().is_empty());
        assert!(p.bob_inbox().is_empty());

        let expires = IndexedSessionStore::open(p.b_dir.path())
            .unwrap()
            .session_expires_at(&p.key)
            .unwrap();
        archive_expired_inbox_to_history(p.b_dir.path(), expires + PP8_HOUR).unwrap();
        assert!(p.bob_history().is_empty(), "{:?}", p.bob_history());
        crate::clock::set_for_this_thread(Some(25 * PP8_HOUR as i64));
        let pruned = prune_expired_lan_durable_state(p.b_dir.path());
        let sessions_left = IndexedSessionStore::open(p.b_dir.path())
            .unwrap()
            .list_record_keys()
            .unwrap();
        crate::clock::set_for_this_thread(None);
        pruned.unwrap();
        assert!(sessions_left.is_empty(), "the session was pruned");
        assert!(p.bob_history().is_empty(), "{:?}", p.bob_history());
    }

    /// The bug PP.8 fixes (path 2, review R05): the sender re-sends an object
    /// Bob already accepted (its ACK was lost). The duplicate path delivered
    /// the stored row again, so a cleared message was back at once.
    #[test]
    fn cleared_message_returns_on_a_duplicate_redelivery() {
        let p = chat_pair(0x63);
        let packed = seal_under(p.a_dir.path(), &p.alice, &p.key, "only once");
        assert_eq!(p.to_bob(&packed).len(), 1);
        assert_eq!(p.bob_deletes_chat().inbox.deleted, 1);
        assert_eq!(p.to_bob(&packed).len(), 1, "the duplicate is answered");
        assert!(p.bob_history().is_empty(), "{:?}", p.bob_history());
        assert!(p.bob_inbox().is_empty());
    }

    /// A re-delivered object after the deletion is answered as a duplicate
    /// with the same ACK (not an error the sender retries until expiry), is
    /// not shown, and the sender's message turns delivered; a new message
    /// afterwards is shown once.
    #[test]
    fn deleted_inbox_rows_keep_dedup() {
        let p = chat_pair(0x65);
        let packed = seal_under(p.a_dir.path(), &p.alice, &p.key, "ack was lost");
        let first = p.to_bob(&packed);
        p.bob_deletes_chat();
        let again = p.to_bob(&packed);
        assert_eq!(again, first, "the same immutable ACK");
        p.to_alice(&again[0]);
        let env = Envelope::unpack(&packed).unwrap();
        let mut a_store = IndexedSessionStore::open(p.a_dir.path()).unwrap();
        let sid = a_store.session_id_for_record_key(&p.key).unwrap();
        assert_eq!(
            a_store
                .outstanding_delivery_state(&sid, &env.message_id, &p.bob_key())
                .unwrap(),
            Some(EndpointDeliveryState::Delivered)
        );
        assert!(p.bob_history().is_empty());
        let later = seal_under(p.a_dir.path(), &p.alice, &p.key, "after the deletion");
        assert_eq!(p.to_bob(&later).len(), 1);
        assert_eq!(p.bob_inbox(), vec!["after the deletion".to_string()]);
        let shown = p.bob_history();
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].2, "after the deletion");
    }

    /// A message still waiting to be sent survives "delete chat": its
    /// outbox row and staged body stay, the stage reconcile shows it as
    /// waiting again, and its row turns `delivered` once its ACK arrives
    /// (the UX copy's promise). The delivered message stays deleted.
    #[test]
    fn waiting_messages_survive_delete_chat() {
        let p = chat_pair(0x67);
        let (sent_mid, sent) = p.staged("delivered before");
        let ack = p.to_bob(&sent);
        p.to_alice(&ack[0]);
        let (waiting_mid, waiting) = p.staged("still waiting");
        let a = p.a_dir.path();
        assert_eq!(ChatPair::history(a, &p.bob_key()).len(), 2);

        let deleted = crate::privacy::delete_chat(a, &p.bob_key(), None).unwrap();
        assert_eq!(deleted.history, 2);
        assert!(ChatPair::history(a, &p.bob_key()).is_empty());
        assert!(
            crate::chat_history::load_staged_outbound_body(a, &waiting_mid)
                .unwrap()
                .is_some()
        );
        assert!(crate::chat_history::load_staged_outbound_body(a, &sent_mid)
            .unwrap()
            .is_none());
        let store = IndexedSessionStore::open(a).unwrap();
        let outbox: Vec<[u8; 16]> = [
            store.pending_endpoint_outbound().unwrap(),
            store.awaiting_ack_endpoint_outbound().unwrap(),
        ]
        .concat()
        .into_iter()
        .map(|row| row.message_id)
        .collect();
        drop(store);
        assert!(outbox.contains(&waiting_mid), "the outbox row stays");
        // The stage reconcile (raven-node's start, every send) puts back the
        // row of a message still waiting, as waiting; not the delivered one.
        reconcile_outbound_stage_history(a).unwrap();
        assert_eq!(
            ChatPair::history(a, &p.bob_key()),
            vec![(
                "out".to_string(),
                "queued".to_string(),
                "still waiting".to_string()
            )]
        );

        let ack = p.to_bob(&waiting);
        p.to_alice(&ack[0]);
        assert_eq!(
            ChatPair::history(a, &p.bob_key()),
            vec![(
                "out".to_string(),
                "delivered".to_string(),
                "still waiting".to_string()
            )]
        );
    }

    /// Privacy pack PP.9 on real stores: chats older than the setting go
    /// from the history and the session store (received rows first, each
    /// leaving a tombstone, so the session-expiry archive brings nothing
    /// back), while a message still waiting to be sent keeps its row, its
    /// staged body and its outbox row. A plain profile: the rows carry no
    /// `stored_at_ms`, so a received row counts from its sender's stamp plus
    /// 7 days.
    #[test]
    fn retention_takes_old_chats_and_keeps_waiting_messages() {
        use crate::privacy::{apply_retention, start_retention_for_tests, ChatKeep};
        // A plain profile, whatever `RAVEN_TEST_SEALED_SESSIONS` asks (its
        // lab key would seal the profile: the history then stamps rows).
        crate::indexed_session_store::test_switch::off();
        const DAY_MS: u64 = 24 * PP8_HOUR;
        let p = chat_pair(0x69);
        let (a, b) = (p.a_dir.path(), p.b_dir.path());
        let (_, delivered) = p.staged("delivered long ago");
        let ack = p.to_bob(&delivered);
        p.to_alice(&ack[0]);
        let (waiting_mid, _) = p.staged("still waiting");
        assert_eq!(p.bob_history().len(), 1);
        assert_eq!(p.bob_inbox().len(), 1);
        let t0 = now();
        for dir in [a, b] {
            start_retention_for_tests(dir, t0, ChatKeep::Days7);
        }
        // Eight days on: Bob's received row is a day old by the conservative
        // age (its stamp plus 7 days), and stays; its store row is 8 days.
        let kept = apply_retention(b, t0 + 8 * DAY_MS).unwrap();
        assert_eq!((kept.history, kept.inbox.deleted), (0, 1), "{kept}");
        assert_eq!(p.bob_history().len(), 1);
        assert!(p.bob_inbox().is_empty());

        let at = t0 + 15 * DAY_MS;
        let went = apply_retention(b, at).unwrap();
        assert_eq!(went.history, 1, "{went}");
        assert!(p.bob_history().is_empty());
        let expires = IndexedSessionStore::open(b)
            .unwrap()
            .session_expires_at(&p.key)
            .unwrap();
        archive_expired_inbox_to_history(b, expires + PP8_HOUR).unwrap();
        assert!(p.bob_history().is_empty(), "{:?}", p.bob_history());

        let went = apply_retention(a, at).unwrap();
        assert_eq!((went.history, went.waiting), (1, 1), "{went}");
        assert_eq!(
            ChatPair::history(a, &p.bob_key()),
            vec![(
                "out".to_string(),
                "queued".to_string(),
                "still waiting".to_string()
            )]
        );
        assert!(
            crate::chat_history::load_staged_outbound_body(a, &waiting_mid)
                .unwrap()
                .is_some()
        );
        let store = IndexedSessionStore::open(a).unwrap();
        assert!(store
            .awaiting_ack_endpoint_outbound()
            .unwrap()
            .into_iter()
            .chain(store.pending_endpoint_outbound().unwrap())
            .any(|row| row.message_id == waiting_mid));
    }

    // --- Privacy pack PP.16: erase one profile ---

    /// Every file below `dir` with its bytes.
    fn tree_bytes(dir: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(folder) = stack.pop() {
            for entry in std::fs::read_dir(&folder).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.insert(path.clone(), std::fs::read(&path).unwrap());
                }
            }
        }
        out
    }

    /// `raven erase` of one profile on this computer touches nothing of
    /// another (in-process; carrier_matrix C91 runs it with real processes):
    /// Alice and Bob of one pair, byte for byte as they were after the
    /// erase of a third profile (a real one, with a session, keys and a chat
    /// of its own), still send, receive and confirm.
    #[test]
    fn b_still_sends_and_receives() {
        let other = chat_pair(0x71);
        let p = chat_pair(0x73);
        let packed = seal_under(other.a_dir.path(), &other.alice, &other.key, "to be erased");
        assert_eq!(other.to_bob(&packed).len(), 1);
        let (_, first) = p.staged("before the erase");
        let ack = p.to_bob(&first);
        p.to_alice(&ack[0]);
        let before = (tree_bytes(p.a_dir.path()), tree_bytes(p.b_dir.path()));

        let erased = std::fs::canonicalize(other.a_dir.path()).unwrap();
        crate::erase::begin(&erased).unwrap();
        let plan = crate::erase::plan(&erased).unwrap();
        assert!(plan.left_unknown.is_empty(), "{:?}", plan.left_unknown);
        let report = crate::erase::execute(&plan, &mut |_| {});
        assert!(report.finished && report.folder_removed, "{report:?}");
        assert!(!erased.exists());

        assert_eq!(
            (tree_bytes(p.a_dir.path()), tree_bytes(p.b_dir.path())),
            before,
            "the pair's files are untouched"
        );
        let (mid, after) = p.staged("after the erase");
        let ack = p.to_bob(&after);
        assert_eq!(ack.len(), 1, "an ACK");
        p.to_alice(&ack[0]);
        let bodies: Vec<String> = p
            .bob_history()
            .into_iter()
            .map(|(_, _, body)| body)
            .collect();
        assert_eq!(bodies, ["before the erase", "after the erase"]);
        let env = Envelope::unpack(&after).unwrap();
        assert_eq!(env.message_id, mid);
        let mut a_store = IndexedSessionStore::open(p.a_dir.path()).unwrap();
        let sid = a_store.session_id_for_record_key(&p.key).unwrap();
        assert_eq!(
            a_store
                .outstanding_delivery_state(&sid, &mid, &p.bob_key())
                .unwrap(),
            Some(EndpointDeliveryState::Delivered)
        );
    }

    // ── Review B-sealed-stores: the session store and the pairing cache of
    // a profile sealed by `migrate_all` ──

    /// Alice paired with Bob (Alice initiated) while her profile was plain,
    /// then her profile was sealed as a release build seals it at its first
    /// start (`migrate_all`: the session store moves to schema 4). Carol is
    /// a second friend of Alice's, with a profile of her own.
    struct SealedLab {
        alice: Identity,
        carol: Identity,
        a_dir: tempfile::TempDir,
        _b_dir: tempfile::TempDir,
        c_dir: tempfile::TempDir,
        a_bundle: LanBundle,
        b_bundle: LanBundle,
        c_bundle: LanBundle,
    }

    fn sealed_lab(seed: u8) -> SealedLab {
        // The layout comes from the profile's own sealing, whatever
        // `RAVEN_TEST_SEALED_SESSIONS` asks; session secrets are the lab
        // backend's files ([`session_secret`]) whatever the job's backend.
        crate::indexed_session_store::test_switch::off();
        crate::indexed_session_store::test_use_lab_secret_files();
        let alice = Identity::from_seed(&[seed; 32]);
        let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
        let carol = Identity::from_seed(&[seed.wrapping_add(2); 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let c_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        publish_and_install(c_dir.path(), &carol);
        let (a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
        let c_bundle = local_bundle(c_dir.path(), &carol).unwrap();
        let book = serde_json::json!([
            {"petname": "Bob", "pub_hex": hex::encode(b_bundle.cert.device_ed_pub), "address": ""},
            {"petname": "Carol", "pub_hex": hex::encode(c_bundle.cert.device_ed_pub), "address": ""},
        ]);
        std::fs::write(
            a_dir.path().join("contacts.json"),
            serde_json::to_string_pretty(&book).unwrap(),
        )
        .unwrap();
        cache_peer_bundle(a_dir.path(), &c_bundle).unwrap();
        write_contact(c_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(c_dir.path(), &a_bundle).unwrap();
        let dd = a_dir.path();
        if !dd.join(crate::BACKEND_MARKER_NAME).exists() {
            std::fs::write(dd.join(crate::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        }
        crate::at_rest::tests::expect_key_file(dd);
        let sealed =
            crate::privacy::migrate_all(dd, now(), crate::at_rest::MigratePolicy::Allow).unwrap();
        assert_eq!(sealed.outcome, crate::privacy::MigrateOutcome::Sealed);
        assert!(!crate::indexed_session_store::needs_migration(dd));
        assert_eq!(session_heads(dd), 1);
        SealedLab {
            alice,
            carol,
            a_dir,
            _b_dir: b_dir,
            c_dir,
            a_bundle,
            b_bundle,
            c_bundle,
        }
    }

    /// Carol pairs with Alice (Alice answers): her PairInit, its frame and
    /// Alice's replies.
    fn carol_pairs_with_alice(lab: &SealedLab) -> (PairInit, Vec<u8>, Vec<Vec<u8>>) {
        let (init, _) =
            create_initiator_pair_init(lab.c_dir.path(), &lab.carol, &lab.a_bundle).unwrap();
        let frame = wrap_pair_init(&lab.carol, &init).unwrap();
        let replies = dispatch_frame(
            lab.a_dir.path(),
            &lab.alice,
            &lab.c_bundle,
            &lab.carol.public_key_bytes(),
            &frame,
        )
        .unwrap();
        (init, frame, replies)
    }

    fn session_heads(dd: &Path) -> i64 {
        rusqlite::Connection::open(dd.join(crate::INDEXED_SESSION_METADATA_FILE))
            .unwrap()
            .query_row("SELECT count(*) FROM indexed_session_heads", [], |r| {
                r.get(0)
            })
            .unwrap()
    }

    /// The meta of Alice's first session head (with Bob) made unreadable: one
    /// bit flipped, or (`epoch`) sealed under an epoch the key file does not
    /// hold (one a rotation dropped). Its record key.
    fn damage_the_head(dd: &Path, epoch: bool) -> Vec<u8> {
        let conn =
            rusqlite::Connection::open(dd.join(crate::INDEXED_SESSION_METADATA_FILE)).unwrap();
        let (record_key, mut meta): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT record_key, meta FROM indexed_session_heads
                 WHERE rowid = (SELECT MIN(rowid) FROM indexed_session_heads)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        if epoch {
            meta[1..5].copy_from_slice(&7u32.to_be_bytes());
        } else {
            let middle = meta.len() / 2;
            meta[middle] ^= 0x01;
        }
        conn.execute(
            "UPDATE indexed_session_heads SET meta = ?1 WHERE record_key = ?2",
            rusqlite::params![meta, record_key],
        )
        .unwrap();
        record_key
    }

    /// The lab backend's file for a session's protected state (a keychain
    /// item in a release build; [`sealed_lab`] keeps it here).
    fn session_secret(dd: &Path, record_key: &[u8]) -> std::path::PathBuf {
        dd.join("indexed-session-secrets")
            .join(format!("{}.bin", hex::encode(record_key)))
    }

    /// The record key `IndexedSessionStore` stores for a session, as anyone
    /// can work it out from public values (an unkeyed digest of the domain,
    /// the length-prefixed profile id and both addresses, then both device
    /// keys and the init_id); a friend's address and device key both come
    /// from its public key (a primary device).
    fn record_key_of(initiator: &[u8; 32], responder: &[u8; 32], init_id: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"rvn1/indexed-session/record-key/v1");
        for value in [
            crate::atsam_indexed_session::PROFILE_ID,
            encode_address(initiator).as_bytes(),
            encode_address(responder).as_bytes(),
        ] {
            h.update((value.len() as u32).to_be_bytes());
            h.update(value);
        }
        h.update(initiator);
        h.update(responder);
        h.update(init_id);
        h.finalize().to_vec()
    }

    /// Every file below `dir`, as its path below `dir` with `/`, and its
    /// path.
    fn profile_files(dir: &Path) -> Vec<(String, std::path::PathBuf)> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(folder) = stack.pop() {
            for entry in std::fs::read_dir(&folder).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.is_file() {
                    let name = path
                        .strip_prefix(dir)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.push((name, path));
                }
            }
        }
        out
    }

    /// Review B-sealed-stores-1: the session store's record key is an
    /// unkeyed digest of public values and the `init_id`. After real
    /// pairings in a profile sealed by `migrate_all` (Alice initiated with
    /// Bob before the sealing, Carol with Alice after it), someone with
    /// Alice's files and her friends' public keys cannot tell which friend a
    /// session is with: no 16-byte value of any clear column of the store
    /// and no 32-hex run of a file name, taken as the `init_id`, gives a
    /// stored record key for either role and any friend. The real `init_id`s
    /// do (the check works), and no file holds them, as bytes, as hex or in
    /// its name: the lab keystore's files are left out (a release build
    /// keeps those in the keychain), as carrier_matrix C87 leaves them out.
    #[test]
    fn b1_no_record_key_names_the_friend_in_a_sealed_profile() {
        use rusqlite::types::ValueRef;
        let lab = sealed_lab(0xd1);
        let dd = lab.a_dir.path();
        let (carol_init, _, _) = carol_pairs_with_alice(&lab);
        let alice = lab.alice.public_key_bytes();
        let friends = [
            lab.b_bundle.cert.device_ed_pub,
            lab.c_bundle.cert.device_ed_pub,
            Identity::from_seed(&[0x13; 32]).public_key_bytes(),
        ];
        let conn =
            rusqlite::Connection::open(dd.join(crate::INDEXED_SESSION_METADATA_FILE)).unwrap();
        let stored: std::collections::HashSet<Vec<u8>> = conn
            .prepare("SELECT record_key FROM indexed_session_heads")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(stored.len(), 2);
        let names_a_friend = |init_id: &[u8]| {
            friends.iter().any(|friend| {
                stored.contains(&record_key_of(&alice, friend, init_id))
                    || stored.contains(&record_key_of(friend, &alice, init_id))
            })
        };
        // The control: the real init_ids name the friends.
        let real: Vec<[u8; 16]> = IndexedSessionStore::open(dd)
            .unwrap()
            .list_record_keys()
            .unwrap()
            .into_iter()
            .map(|key| key.init_id)
            .collect();
        assert_eq!(real.len(), 2);
        assert!(real.contains(&carol_init.init_id));
        assert!(real.iter().all(|init_id| names_a_friend(init_id)));
        // What the files offer.
        let mut candidates: Vec<Vec<u8>> = Vec::new();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for table in &tables {
            let mut statement = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let width = statement.column_count();
            let mut rows = statement.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                for at in 0..width {
                    match row.get_ref(at).unwrap() {
                        ValueRef::Blob(value) if value.len() == 16 => {
                            candidates.push(value.to_vec())
                        }
                        ValueRef::Text(text) => {
                            if let Ok(value) = hex::decode(text) {
                                if value.len() == 16 {
                                    candidates.push(value);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        let files = profile_files(dd);
        for (name, _) in &files {
            let bytes = name.as_bytes();
            for start in 0..bytes.len().saturating_sub(31) {
                if let Ok(value) = hex::decode(&bytes[start..start + 32]) {
                    candidates.push(value);
                }
            }
        }
        assert!(!candidates.is_empty());
        for candidate in &candidates {
            assert!(
                !names_a_friend(candidate),
                "{} names a friend's session",
                hex::encode(candidate)
            );
        }
        for (name, path) in &files {
            if name.starts_with("indexed-session-secrets/") || name == "prekey_lifecycle.protected"
            {
                continue;
            }
            let bytes = std::fs::read(path).unwrap();
            for init_id in &real {
                let hex = hex::encode(init_id);
                assert!(
                    !name.contains(&hex),
                    "the file name {name} holds an init_id"
                );
                assert!(
                    !bytes.windows(16).any(|w| w == init_id)
                        && !bytes
                            .windows(hex.len())
                            .any(|w| w.eq_ignore_ascii_case(hex.as_bytes())),
                    "{name} holds an init_id"
                );
            }
        }
    }

    /// Review B-sealed-stores-1 (found by s120's record-key check): a
    /// response Alice cached while her profile was plain (Carol's PairInit
    /// to her), named by its init_id in hex, goes when the profile is
    /// sealed, though its retry window is not over: its name gave the
    /// init_id that names Carol with the session store's record key.
    #[test]
    fn b1_a_response_cached_before_the_sealing_goes_with_it() {
        crate::indexed_session_store::test_switch::off();
        let alice = Identity::from_seed(&[0xd8; 32]);
        let carol = Identity::from_seed(&[0xd9; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let c_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(c_dir.path(), &carol);
        // Carol initiates; Alice answers while her profile is plain.
        confirm_alice_to_bob(c_dir.path(), a_dir.path(), &carol, &alice);
        let dd = a_dir.path();
        let names = || -> Vec<String> {
            std::fs::read_dir(dd.join(PAIR_RESPONSE_DIR))
                .map(|entries| {
                    entries
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default()
        };
        assert_eq!(names().len(), 1, "the control: {:?}", names());
        assert_eq!(names()[0].len(), 32, "named by the init_id");
        if !dd.join(crate::BACKEND_MARKER_NAME).exists() {
            std::fs::write(dd.join(crate::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        }
        crate::at_rest::tests::expect_key_file(dd);
        let sealed =
            crate::privacy::migrate_all(dd, now(), crate::at_rest::MigratePolicy::Allow).unwrap();
        assert_eq!(sealed.outcome, crate::privacy::MigrateOutcome::Sealed);
        assert!(names().is_empty(), "{:?}", names());
        let (own, friend) = (alice.public_key_bytes(), carol.public_key_bytes());
        for init_id in crate::indexed_session_store::init_id_candidates(dd) {
            assert!(!crate::indexed_session_store::record_key_names_friend(
                dd, &own, &friend, &init_id
            ));
        }
    }

    /// Review B-sealed-stores-5: Alice answers Carol's PairInit in a sealed
    /// profile. The response she keeps for an exact retry is sealed (RMS1,
    /// not the plain RVN1 envelope with the init_id and the session's exact
    /// times) and named by the keyed init_id; a retry gets the same response
    /// from it; once its retry window is over the prune deletes it, though
    /// the session lives on.
    #[test]
    fn b5_the_cached_pair_response_is_sealed_and_short_lived() {
        let lab = sealed_lab(0xd5);
        let dd = lab.a_dir.path();
        let (init, frame, replies) = carol_pairs_with_alice(&lab);
        let files: Vec<std::path::PathBuf> = std::fs::read_dir(dd.join(PAIR_RESPONSE_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "{files:?}");
        let keys = crate::at_rest::keys_cached(dd).unwrap();
        assert_eq!(
            files[0].file_name().unwrap().to_string_lossy(),
            hex::encode(crate::at_rest::index(
                &keys,
                crate::at_rest::ValueType::Nonce,
                &init.init_id
            ))
        );
        let bytes = std::fs::read(&files[0]).unwrap();
        assert!(crate::at_rest::is_sealed_as(Kind::PairResponse, &bytes));
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!("expected a PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        for needle in [
            &init.init_id[..],
            &response.created_at_ms.to_be_bytes()[..],
            &response.expires_at_ms.to_be_bytes()[..],
            &replies[0][..16],
        ] {
            assert!(!bytes.windows(needle.len()).any(|w| w == needle));
        }
        // An exact retry of the PairInit: the same response.
        let again = dispatch_frame(
            dd,
            &lab.alice,
            &lab.c_bundle,
            &lab.carol.public_key_bytes(),
            &frame,
        )
        .unwrap();
        assert_eq!(again, replies);
        // Within its retry window the prune keeps it; past it, it goes.
        prune_lan_durable_state(dd, now()).unwrap();
        assert!(files[0].exists());
        let old = std::time::SystemTime::now() - PAIR_RESPONSE_KEEP - Duration::from_secs(1);
        std::fs::File::options()
            .write(true)
            .open(&files[0])
            .unwrap()
            .set_modified(old)
            .unwrap();
        prune_lan_durable_state(dd, now()).unwrap();
        assert!(!files[0].exists());
        let mut store = IndexedSessionStore::open(dd).unwrap();
        assert!(
            store
                .find_confirmed_session_for_peer(&lab.c_bundle.cert.device_ed_pub)
                .unwrap()
                .is_some(),
            "the session lives on"
        );
    }

    /// Review B-sealed-stores-2: one session head whose meta does not open
    /// (a flipped bit; an epoch the key file no longer holds) in a profile
    /// sealed by `migrate_all`. New sessions start both ways, the listener's
    /// preflight step passes, and the prune removes that head, with its
    /// secret, once its hour is past. It used to stop all of them for good.
    #[test]
    fn b2_an_unreadable_head_stops_no_session_and_the_prune_removes_it() {
        for (seed, epoch) in [(0xd2, false), (0xd3, true)] {
            let lab = sealed_lab(seed);
            let dd = lab.a_dir.path();
            let record_key = damage_the_head(dd, epoch);
            let secret = session_secret(dd, &record_key);
            assert!(secret.exists());
            create_initiator_pair_init(dd, &lab.alice, &lab.c_bundle).unwrap();
            carol_pairs_with_alice(&lab);
            maintain_lan_durable_state(dd).unwrap();
            prune_lan_durable_state(dd, now()).unwrap();
            assert_eq!(session_heads(dd), 3, "nothing goes before its hour");
            prune_lan_durable_state(dd, now() + 3 * 24 * 3_600_000).unwrap();
            assert_eq!(session_heads(dd), 0, "epoch {epoch}");
            assert!(!secret.exists());
        }
    }

    /// Review B-sealed-stores-3: with one unreadable session head, `raven
    /// privacy rotate-meta` finishes (that head goes, with its rows and its
    /// secret, counted as dropped; a healthy session stays and works) and
    /// leaves the profile open; so does `raven privacy unseal`. Both used to
    /// stop at that head, the first after it had closed the profile.
    #[test]
    fn b3_rotate_meta_and_unseal_get_past_an_unreadable_head() {
        let lab = sealed_lab(0xd6);
        let dd = lab.a_dir.path();
        carol_pairs_with_alice(&lab);
        assert_eq!(session_heads(dd), 2);
        let record_key = damage_the_head(dd, false);
        let secret = session_secret(dd, &record_key);
        assert!(secret.exists());
        let rotated = crate::privacy::rotate_meta(dd, now(), &|| true).unwrap();
        assert!(
            rotated.dropped >= 2,
            "the head and its reset row: {rotated:?}"
        );
        assert!(!crate::privacy::meta_rotation_unfinished(dd));
        crate::privacy::refuse_if_meta_rotation_unfinished(dd).unwrap();
        assert!(!secret.exists());
        assert_eq!(session_heads(dd), 1);
        let mut store = IndexedSessionStore::open(dd).unwrap();
        assert!(store
            .find_confirmed_session_for_peer(&lab.c_bundle.cert.device_ed_pub)
            .unwrap()
            .is_some());
        drop(store);

        let lab = sealed_lab(0xd7);
        let dd = lab.a_dir.path();
        let record_key = damage_the_head(dd, true);
        let secret = session_secret(dd, &record_key);
        let unsealed = crate::privacy::unseal_all(dd, &|| true).unwrap();
        assert!(unsealed.dropped >= 2, "{unsealed:?}");
        crate::privacy::refuse_if_meta_rotation_unfinished(dd).unwrap();
        assert_eq!(
            crate::privacy::mode(dd),
            crate::at_rest::Mode::UnsealedByUser
        );
        assert!(!crate::privacy::unseal_unfinished(dd));
        assert!(!secret.exists());
        assert_eq!(session_heads(dd), 0);
    }

    /// Review B-sealed-stores-3 residual (privacy re-verify): the protected
    /// state of an unreadable session head goes before `raven privacy
    /// rotate-meta` records its key change and before `raven privacy unseal`
    /// changes the mode. A delete that fails (a locked keychain, a denied
    /// access dialog; here a folder stands where the lab file was) stops
    /// either with the profile as it was: raven-node's start check passes,
    /// and running the command again finishes it. Inside rotate-meta it used
    /// to fail after the record, leaving raven-node refused.
    #[test]
    fn b3_a_secret_delete_that_fails_leaves_the_profile_as_it_was() {
        let in_the_way = |secret: &Path| {
            std::fs::remove_file(secret).unwrap();
            std::fs::create_dir_all(secret.join("in-the-way")).unwrap();
        };
        let key_file = |dd: &Path| std::fs::read(dd.join(crate::at_rest::META_KEY_FILE)).unwrap();

        let lab = sealed_lab(0xd8);
        let dd = lab.a_dir.path();
        let secret = session_secret(dd, &damage_the_head(dd, false));
        in_the_way(&secret);
        let before = key_file(dd);
        assert!(crate::privacy::rotate_meta(dd, now(), &|| true).is_err());
        assert!(!crate::privacy::meta_rotation_unfinished(dd));
        crate::privacy::refuse_if_meta_rotation_unfinished(dd).unwrap();
        assert_eq!(key_file(dd), before, "no key change began");
        assert_eq!(session_heads(dd), 1);
        std::fs::remove_dir_all(&secret).unwrap();
        let rotated = crate::privacy::rotate_meta(dd, now(), &|| true).unwrap();
        assert!(rotated.dropped >= 2, "{rotated:?}");
        crate::privacy::refuse_if_meta_rotation_unfinished(dd).unwrap();
        assert_eq!(session_heads(dd), 0);

        let lab = sealed_lab(0xd9);
        let dd = lab.a_dir.path();
        let secret = session_secret(dd, &damage_the_head(dd, true));
        in_the_way(&secret);
        assert!(crate::privacy::unseal_all(dd, &|| true).is_err());
        assert_eq!(crate::privacy::mode(dd), crate::at_rest::Mode::Sealed);
        assert!(!crate::privacy::unseal_unfinished(dd));
        crate::privacy::refuse_if_meta_rotation_unfinished(dd).unwrap();
        assert_eq!(session_heads(dd), 1);
        std::fs::remove_dir_all(&secret).unwrap();
        let unsealed = crate::privacy::unseal_all(dd, &|| true).unwrap();
        assert!(unsealed.dropped >= 2, "{unsealed:?}");
        assert_eq!(
            crate::privacy::mode(dd),
            crate::at_rest::Mode::UnsealedByUser
        );
        assert!(!crate::privacy::unseal_unfinished(dd));
        assert_eq!(session_heads(dd), 0);
    }

    mod horizon_tests;
    mod letter_session_tests;
    mod message_id_tests;
    mod session_renewal_tests;
    mod suite_policy_tests;
}
