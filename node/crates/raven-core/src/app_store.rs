//! App channel store: `<data_dir>/app_channel.sqlite3`
//! (`docs/design/2026-10-rdap-app-channel.md` §7.4, §7.5, §8.3, §10).
//!
//! One file. Inbox rows are sealed by a [`RowSealer`] (the node's chat-history
//! key under its own domain; in a sealed profile the epoch `app-row` key,
//! privacy pack PP.10); the sealed plaintext embeds the row's identity
//! fields and `open` checks them against the columns, so swapping blobs or
//! editing columns is detected and the row quarantined. Outbox rows carry no
//! content. Corruption is an error (`APP_STORE`), never an empty store.
//!
//! **At rest (privacy pack PP.12; docs/design/2026-10-at-rest-metadata.md
//! section 7).** In a sealed profile the store is at schema 3: the sender
//! device of the inbox, tombstone and quarantine rows is a keyed lookup
//! (`kh_sender`, [`crate::at_rest::index`] of the device key), and the clear
//! sender with the other values that name the sender and no query needs
//! (identity key, certificate hash, creation time) is in each row's sealed
//! `meta`. A profile that is not sealed keeps schema 2. A schema-2 store in
//! a sealed profile moves to schema 3 with the rebuild recipe of
//! [`crate::sqlite_rebuild`] (from `privacy::migrate_all`, and on open);
//! [`unseal`] is the way back. Without the profile's at-rest key a sealed
//! profile's store does not open, never a clear fallback. Older builds
//! refuse schema 3 ("newer than this build").

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::at_rest::{MetaKeys, Mode, ValueType};
use crate::sqlite_rebuild::{self as rebuild, Migration, RebuildError, Shape, Steps};

pub const APP_STORE_FILE: &str = "app_channel.sqlite3";
/// Schema 3 (PP.12): keyed sender devices and sealed `meta`.
const SCHEMA_VERSION: i64 = 3;
/// Schema 2: clear sender devices (a profile that is not sealed, and every
/// older build since `app_quarantine`).
const CLEAR_VERSION: i64 = 2;
/// This store's row in `raven_schema`.
const STORE: &str = "app_channel";
/// The keyed column that tells the two shapes apart.
const KEYED_COLUMN: &str = "kh_sender";
/// The AAD label of an inbox row's `meta`; a quarantined row keeps its
/// inbox `meta` byte for byte, under the same label.
const INBOX_META: &str = "app_inbox";
const TOMBSTONE_META: &str = "app_tombstones";
/// The start of the error of a sealed profile's store opened without the
/// at-rest key (never a clear fallback).
pub const STORE_KEY_UNAVAILABLE: &str = "APP_STORE: the at-rest key is unavailable";
pub const APP_INBOX_MAX_ITEMS: i64 = 128;
pub const APP_INBOX_MAX_BODY_BYTES: i64 = 4 * 1024 * 1024;
pub const APP_INBOX_MAX_PER_SENDER_TYPE: i64 = 16;
pub const APP_INBOX_ITEM_TTL_MS: u64 = 7 * 86_400_000;
pub const APP_TOMBSTONE_RETENTION_MS: u64 = 8 * 86_400_000;
pub const APP_TOMBSTONE_MAX: i64 = 8_192;
/// Rows set aside because they could not be opened (kept for inspection).
pub const APP_QUARANTINE_MAX: i64 = 256;
pub const APP_OUTBOX_MAX_RECORDS: i64 = 512;
pub const APP_OUTBOX_FINAL_RETENTION_MS: u64 = 8 * 86_400_000;
pub const APP_PAIR_BUDGET_PER_DAY: i64 = 4;

/// Seals inbox rows. Production: the chat-history key, domain
/// `raven/app-inbox/v1`; tests use a fixed key.
pub trait RowSealer {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String>;
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInboxItem {
    #[serde(with = "hex_array")]
    pub sender_device: [u8; 32],
    #[serde(with = "hex_array")]
    pub message_id: [u8; 16],
    #[serde(with = "hex_array")]
    pub app_id: [u8; 16],
    #[serde(with = "hex_array")]
    pub sender_identity: [u8; 32],
    pub content_type: String,
    pub created_at_ms: u64,
    pub received_at_ms: u64,
    pub expires_at_ms: u64,
    /// The session-bound sender certificate (JSON), re-checked when served.
    pub cert_json: String,
    #[serde(with = "hex_array")]
    pub cert_hash: [u8; 32],
    pub body: String,
}

mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

/// Before commit (§7.2): may this frame be committed now?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Room: commit, then ingest.
    Room,
    /// Already in the inbox: commit (the endpoint dedups), ingest is a no-op.
    Duplicate,
    /// Already handled (tombstone): commit and ACK, store nothing.
    AlreadyDone,
    /// No room: defer (nothing committed, no ACK).
    Full,
}

/// Why an item left the inbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Done,
    Rejected,
    Expired,
    Revoked,
    NotContact,
    Blocked,
}

impl Disposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::NotContact => "not_contact",
            Self::Blocked => "blocked",
        }
    }
}

/// Outbox record states (monotonic: `delivered` is final).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutState {
    Queued,
    Sent,
    Delivered,
    Expired,
    Failed,
    Cancelled,
}

impl OutState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn parse(s: &str) -> Result<Self, String> {
        Ok(match s {
            "queued" => Self::Queued,
            "sent" => Self::Sent,
            "delivered" => Self::Delivered,
            "expired" => Self::Expired,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => return Err("APP_STORE: unknown outbox state".into()),
        })
    }

    pub fn is_final(self) -> bool {
        matches!(
            self,
            Self::Delivered | Self::Expired | Self::Failed | Self::Cancelled
        )
    }

    /// Forward only: `delivered` is final; `sent` only from `queued` (a
    /// cancel, expiry or failure is never undone by a late "written"); a late
    /// ACK may still make any non-delivered record `delivered`.
    fn may_become(self, next: Self) -> bool {
        match (self, next) {
            (Self::Delivered, _) => false,
            (_, Self::Delivered) => true,
            (_, Self::Queued) => matches!(self, Self::Queued),
            (_, Self::Sent) => matches!(self, Self::Queued | Self::Sent),
            (Self::Queued | Self::Sent, _) => true,
            // A final record keeps its first reason (e.g. PEER_REVOKED).
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppOutRecord {
    pub peer_identity: [u8; 32],
    pub client_ref: String,
    pub peer_device: [u8; 32],
    pub content_type: String,
    pub app_id: [u8; 16],
    pub body_sha256: [u8; 32],
    pub message_id: [u8; 16],
    pub session_id: [u8; 32],
    pub object_digest: [u8; 32],
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: OutState,
    pub last_error_code: String,
    pub attempt_seq: u32,
}

/// One inbox page request (§9.1).
pub struct PageQuery<'a> {
    pub content_type: Option<&'a str>,
    /// Serve only items after this `(received_at_ms, sender_device, message_id)`.
    pub after: Option<(u64, [u8; 32], [u8; 16])>,
    pub limit: usize,
    /// Base64 bytes of bodies per page; the first item is always served.
    pub byte_budget: usize,
}

#[derive(Debug, Default)]
pub struct PageResult {
    pub items: Vec<AppInboxItem>,
    /// Cursor of the last item served.
    pub next: Option<(u64, [u8; 32], [u8; 16])>,
    pub more: bool,
    pub pending: u32,
}

/// §8.3 decisions for `(peer_identity, client_ref)`.
/// [`AppStore::spend_pair_attempt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairSpend {
    Spent,
    /// Spacing: not before this time (unix ms).
    TooSoon(u64),
    /// The daily budget is used up.
    UsedUp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dedup {
    Fresh,
    /// Nothing to do: report the current record.
    Return {
        state: OutState,
        message_id: [u8; 16],
    },
    Conflict,
    LineageRevoked,
    /// Seal again with the same `app_id` (full path).
    Resend {
        app_id: [u8; 16],
        seq: u32,
    },
}

fn ms(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn arr<const N: usize>(v: &[u8]) -> Result<[u8; N], String> {
    v.try_into()
        .map_err(|_| "APP_STORE: corrupt row".to_string())
}

/// The row format of a sealed profile (privacy pack PP.10): `0x02 || epoch
/// u32 BE || nonce[24] || ct || tag[16]` under the epoch's `app-row` data key,
/// AAD `raven/app-inbox/v1` || epoch. Rows the chat-history key sealed
/// directly (`nonce[12] || ct || tag`; on Windows `RKH1 || ...` since PP.11,
/// or an older build's DPAPI blob) are read forever. An older build cannot
/// open a `0x02` row and quarantines it.
pub const APP_ROW_V2: u8 = 0x02;
const APP_ROW_DOMAIN: &[u8] = b"raven/app-inbox/v1";
/// The start of a sealer error that says a key is unavailable, not that the
/// row is bad: the page fails and keeps every row.
pub const ROW_KEY_UNAVAILABLE: &str = "APP_STORE: the inbox key is unavailable";

/// The epoch body of a row that looks like the `0x02` format.
fn v2_body(blob: &[u8]) -> Option<&[u8]> {
    match blob.split_first() {
        Some((&APP_ROW_V2, body)) if body.len() >= crate::at_rest::EPOCH_BODY_OVERHEAD => {
            Some(body)
        }
        _ => None,
    }
}

/// The epoch a row names (`None`: the chat-history key's format). A K_hist
/// row's random nonce starts like a `0x02` row once in 256: only opening
/// tells for sure ([`open_row_any`]).
fn row_epoch(blob: &[u8]) -> Option<u32> {
    v2_body(blob).and_then(crate::at_rest::epoch_of)
}

fn seal_row_v2(keys: &crate::at_rest::MetaKeys, plaintext: &[u8]) -> Vec<u8> {
    let body = crate::at_rest::seal_epoch(
        keys,
        crate::at_rest::DataUse::AppRow,
        APP_ROW_DOMAIN,
        plaintext,
    );
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(APP_ROW_V2);
    out.extend_from_slice(&body);
    out
}

/// Opens a row the chat-history key sealed directly, through the keystore.
type HistOpen<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>, String>;

/// Open a row in either format: a `0x02` row with its epoch key; any other
/// row, or a `0x02`-looking one that does not open that way, with the
/// chat-history key, from the at-rest key cache when this process loaded it
/// (no keystore call) and from `hist_open` otherwise. Also says which epoch
/// it was under (`None`: the chat-history key).
fn open_row_any(
    data_dir: &Path,
    blob: &[u8],
    hist_open: HistOpen<'_>,
) -> Result<(zeroize::Zeroizing<Vec<u8>>, Option<u32>), String> {
    use crate::at_rest::AtRestError;
    let mut epoch_error = None;
    if let Some(body) = v2_body(blob) {
        let opened = crate::at_rest::keys_cached(data_dir).and_then(|keys| {
            crate::at_rest::open_epoch(&keys, crate::at_rest::DataUse::AppRow, APP_ROW_DOMAIN, body)
        });
        match opened {
            Ok(plain) => return Ok((plain, crate::at_rest::epoch_of(body))),
            Err(e) => epoch_error = Some(e),
        }
    }
    let hist = match crate::at_rest::cached_hist(data_dir) {
        Ok(hist) => crate::chat_history::DomainProtector::new(APP_ROW_DOMAIN)
            .unprotect_with(&hist, data_dir, blob)
            .map_err(|e| e.to_string()),
        Err(_) => hist_open(blob).map(zeroize::Zeroizing::new),
    };
    match (hist, epoch_error) {
        (Ok(plain), _) => Ok((plain, None)),
        // The epoch key is not loaded here (an epoch the key file no longer
        // holds is a bad row, as a changed byte is).
        (
            Err(_),
            Some(
                e @ (AtRestError::KeyUnavailable(_) | AtRestError::KeyLost(_) | AtRestError::Io(_)),
            ),
        ) => Err(format!("{ROW_KEY_UNAVAILABLE}: {e}")),
        (Err(e), _) => Err(format!("APP_STORE: {e}")),
    }
}

/// The production sealer: the chat-history protection under the domain
/// `raven/app-inbox/v1` (the chat-history key, on Windows since PP.11 too),
/// and in a sealed profile the epoch `app-row` key ([`APP_ROW_V2`]).
pub struct PlatformRowSealer {
    data_dir: PathBuf,
    protector: crate::chat_history::DomainProtector,
}

impl PlatformRowSealer {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            protector: crate::chat_history::DomainProtector::new(b"raven/app-inbox/v1"),
        }
    }
}

impl RowSealer for PlatformRowSealer {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if crate::privacy::mode(&self.data_dir) == crate::at_rest::Mode::Sealed {
            let keys = crate::at_rest::keys_cached(&self.data_dir)
                .map_err(|e| format!("{ROW_KEY_UNAVAILABLE}: {e}"))?;
            return Ok(seal_row_v2(&keys, plaintext));
        }
        self.protector
            .protect(&self.data_dir, plaintext)
            .map_err(|e| format!("APP_STORE: {e}"))
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, String> {
        open_row_any(&self.data_dir, sealed, &|blob| {
            self.protector.unprotect(&self.data_dir, blob)
        })
        .map(|(plain, _)| plain.to_vec())
    }
}

/// What [`reseal_rows`] did.
pub use crate::sqlite_rebuild::RowReseal;

/// Privacy pack PP.10 (the migration and the data-key rotation): in one
/// IMMEDIATE transaction, every inbox row the chat-history key sealed
/// directly, or that names another epoch than the current one, is opened and
/// sealed again under the current epoch ([`APP_ROW_V2`]), and (PP.12) every
/// row `meta` of the inbox, the tombstones and the quarantine not on the
/// current epoch too; then the WAL is checkpointed (`secure_delete` already
/// overwrote the old bytes in the file). A sealed profile with its at-rest
/// keys loaded: no keystore call (the chat-history key comes from the
/// at-rest key cache). A profile without the store is not touched, and the
/// bodies of rows set aside stay as they are (they did not open).
pub fn reseal_rows(data_dir: &Path) -> Result<RowReseal, String> {
    let mut report = RowReseal::default();
    if !app_store_path(data_dir).exists()
        || crate::privacy::mode(data_dir) != crate::at_rest::Mode::Sealed
    {
        return Ok(report);
    }
    let keys =
        crate::at_rest::keys_cached(data_dir).map_err(|e| format!("{ROW_KEY_UNAVAILABLE}: {e}"))?;
    let current = keys.current_epoch();
    // The rows' first bytes, without the write lock: nothing to move, no
    // transaction (the migration asks at every command's start).
    if row_epochs(data_dir)?
        .into_iter()
        .all(|epoch| epoch == Some(current))
        && meta_rows_off_epoch(data_dir, current)? == 0
    {
        return Ok(report);
    }
    let mut store = AppStore::open(data_dir, &MetadataOnly)?;
    let s = store.sender_col();
    let keyed = store.keyed;
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(AppStore::e)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx
            .prepare(&format!("SELECT {s}, message_id, sealed FROM app_inbox"))
            .map_err(AppStore::e)?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(AppStore::e)?;
        mapped.collect::<Result<_, _>>().map_err(AppStore::e)?
    };
    let no_keystore = |_: &[u8]| -> Result<Vec<u8>, String> {
        Err("the chat-history key is not loaded in this process".into())
    };
    for (sender, mid, sealed) in rows {
        if row_epoch(&sealed) == Some(current) {
            continue;
        }
        let Ok((plain, _)) = open_row_any(data_dir, &sealed, &no_keystore) else {
            report.unreadable += 1;
            continue;
        };
        tx.execute(
            &format!("UPDATE app_inbox SET sealed = ?3 WHERE {s} = ?1 AND message_id = ?2"),
            params![sender, mid, seal_row_v2(&keys, &plain)],
        )
        .map_err(AppStore::e)?;
        report.resealed += 1;
    }
    if keyed {
        let epoch = current.to_be_bytes().to_vec();
        for (table, label) in [
            ("app_inbox", INBOX_META),
            ("app_quarantine", INBOX_META),
            ("app_tombstones", TOMBSTONE_META),
        ] {
            let metas: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
                let mut stmt = tx
                    .prepare(&format!(
                        "SELECT kh_sender, message_id, meta FROM {table}
                         WHERE substr(meta, 2, 4) != ?1"
                    ))
                    .map_err(AppStore::e)?;
                let mapped = stmt
                    .query_map(params![epoch], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                    .map_err(AppStore::e)?;
                mapped.collect::<Result<_, _>>().map_err(AppStore::e)?
            };
            for (kh, mid, meta) in metas {
                let pk = row_pk(&kh, &mid);
                let Ok(plain) = crate::at_rest::open_row(&keys, label, &pk, &meta) else {
                    report.unreadable += 1;
                    continue;
                };
                tx.execute(
                    &format!(
                        "UPDATE {table} SET meta = ?3 WHERE kh_sender = ?1 AND message_id = ?2"
                    ),
                    params![kh, mid, crate::at_rest::seal_row(&keys, label, &pk, &plain)],
                )
                .map_err(AppStore::e)?;
                report.resealed += 1;
            }
        }
    }
    tx.commit().map_err(AppStore::e)?;
    if report.resealed > 0 {
        report.scrub_pending = crate::paths::checkpoint_truncate(&store.conn)
            .map_or(true, |checkpoint| checkpoint.busy);
    }
    Ok(report)
}

/// Windows (privacy pack PP.11), in a profile that is not sealed: in one
/// IMMEDIATE transaction, every inbox row an older Windows build sealed with
/// DPAPI directly is sealed again under K_hist (behind its format tag), then
/// the WAL is checkpointed, as [`reseal_rows`] does in a sealed profile
/// (whose rows move under the epoch keys instead). K_hist is read before the
/// transaction: the migration created it first, and without it nothing is
/// written. Rows that do not open stay as they are, for the page.
#[cfg(any(test, windows))]
pub(crate) fn rewrap_dpapi_rows(data_dir: &Path) -> Result<RowReseal, String> {
    use crate::chat_history::{windows_key, DomainProtector, HistKey};
    let mut report = RowReseal::default();
    if !app_store_path(data_dir).exists()
        || crate::privacy::mode(data_dir) == crate::at_rest::Mode::Sealed
        || !dpapi_rows_left(data_dir)?
    {
        return Ok(report);
    }
    let protector = DomainProtector::new(APP_ROW_DOMAIN);
    let hist = match protector.load_hist_key(data_dir, false) {
        Ok(hist @ HistKey::Wrapped(_)) => hist,
        Ok(_) => return Err(format!("{ROW_KEY_UNAVAILABLE}: no K_hist yet")),
        Err(e) => return Err(format!("{ROW_KEY_UNAVAILABLE}: {e}")),
    };
    let mut store = AppStore::open(data_dir, &MetadataOnly)?;
    let s = store.sender_col();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(AppStore::e)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx
            .prepare(&format!("SELECT {s}, message_id, sealed FROM app_inbox"))
            .map_err(AppStore::e)?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(AppStore::e)?;
        mapped.collect::<Result<_, _>>().map_err(AppStore::e)?
    };
    for (sender, mid, sealed) in rows {
        if !windows_key::is_dpapi_direct(&sealed) {
            continue;
        }
        let Ok(plain) = protector.unprotect_with(&hist, data_dir, &sealed) else {
            report.unreadable += 1;
            continue;
        };
        let rewrapped = protector
            .protect_with(&hist, data_dir, &plain)
            .map_err(|e| format!("APP_STORE: {e}"))?;
        tx.execute(
            &format!("UPDATE app_inbox SET sealed = ?3 WHERE {s} = ?1 AND message_id = ?2"),
            params![sender, mid, rewrapped],
        )
        .map_err(AppStore::e)?;
        report.resealed += 1;
    }
    tx.commit().map_err(AppStore::e)?;
    if report.resealed > 0 {
        report.scrub_pending = crate::paths::checkpoint_truncate(&store.conn)
            .map_or(true, |checkpoint| checkpoint.busy);
    }
    Ok(report)
}

/// Windows, `raven privacy unseal` (PP.18) in a profile without
/// `meta_key.rmk` (review A-keys-format-1): in one IMMEDIATE transaction
/// every inbox row K_hist sealed behind PP.11's tag is sealed again
/// DPAPI-direct, the form a build before PP.11 reads, then the WAL is
/// checkpointed. K_hist from its file, read before the transaction (no
/// at-rest keys exist here). Rows that do not open stay as they are
/// (`unreadable`), for the page.
#[cfg(any(test, windows))]
pub(crate) fn untag_rows(data_dir: &Path) -> Result<RowReseal, String> {
    use crate::chat_history::{windows_key, DomainProtector};
    let mut report = RowReseal::default();
    if !app_store_path(data_dir).exists()
        || crate::privacy::mode(data_dir) != crate::at_rest::Mode::UnsealedByUser
        || !rows_left_for_older_build(data_dir)?
    {
        return Ok(report);
    }
    let protector = DomainProtector::new(APP_ROW_DOMAIN);
    let hist = protector
        .load_hist_key(data_dir, false)
        .map_err(|e| format!("{ROW_KEY_UNAVAILABLE}: {e}"))?;
    let mut store = AppStore::open(data_dir, &MetadataOnly)?;
    let s = store.sender_col();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(AppStore::e)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx
            .prepare(&format!("SELECT {s}, message_id, sealed FROM app_inbox"))
            .map_err(AppStore::e)?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(AppStore::e)?;
        mapped.collect::<Result<_, _>>().map_err(AppStore::e)?
    };
    for (sender, mid, sealed) in rows {
        if !sealed.starts_with(windows_key::TAG) {
            continue;
        }
        let Ok(plain) = protector.unprotect_with(&hist, data_dir, &sealed) else {
            report.unreadable += 1;
            continue;
        };
        let older = protector
            .protect_for_older_build(&hist, data_dir, &plain)
            .map_err(|e| format!("APP_STORE: {e}"))?;
        tx.execute(
            &format!("UPDATE app_inbox SET sealed = ?3 WHERE {s} = ?1 AND message_id = ?2"),
            params![sender, mid, older],
        )
        .map_err(AppStore::e)?;
        report.resealed += 1;
    }
    tx.commit().map_err(AppStore::e)?;
    if report.resealed > 0 {
        report.scrub_pending = crate::paths::checkpoint_truncate(&store.conn)
            .map_or(true, |checkpoint| checkpoint.busy);
    }
    Ok(report)
}

/// A look at the store's rows by their first bytes (status, the rotation's
/// counts, the migration's checks): no schema change, no migration, no
/// write, in either schema. `None` without the store or its inbox.
fn peek(data_dir: &Path) -> Result<Option<Connection>, String> {
    let path = app_store_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(AppStore::e)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(AppStore::e)?;
    if rebuild::shape(&conn, "app_inbox", KEYED_COLUMN).map_err(AppStore::e)? == Shape::Missing {
        return Ok(None);
    }
    Ok(Some(conn))
}

/// Whether an inbox row is still DPAPI-direct (an older Windows build's), by
/// its first bytes. `false` without the store.
#[cfg(any(test, windows))]
pub(crate) fn dpapi_rows_left(data_dir: &Path) -> Result<bool, String> {
    let Some(conn) = peek(data_dir)? else {
        return Ok(false);
    };
    let mut stmt = conn
        .prepare("SELECT substr(sealed, 1, 4) FROM app_inbox")
        .map_err(AppStore::e)?;
    let mapped = stmt
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .map_err(AppStore::e)?;
    for head in mapped {
        if crate::chat_history::windows_key::is_dpapi_direct(&head.map_err(AppStore::e)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The epoch each inbox row names, `None` for the chat-history key's format
/// (by its first bytes, no key; [`row_epoch`]). Empty without the store.
pub fn row_epochs(data_dir: &Path) -> Result<Vec<Option<u32>>, String> {
    let Some(conn) = peek(data_dir)? else {
        return Ok(Vec::new());
    };
    let mut stmt = conn
        .prepare("SELECT substr(sealed, 1, 5), length(sealed) FROM app_inbox")
        .map_err(AppStore::e)?;
    let mapped = stmt
        .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))
        .map_err(AppStore::e)?;
    let mut epochs = Vec::new();
    for row in mapped {
        let (head, len) = row.map_err(AppStore::e)?;
        let long_enough =
            usize::try_from(len).is_ok_and(|len| len > crate::at_rest::EPOCH_BODY_OVERHEAD);
        epochs.push(match head.as_slice() {
            [APP_ROW_V2, a, b, c, d] if long_enough => Some(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => None,
        });
    }
    Ok(epochs)
}

/// Test builds: whether every inbox row's body opens with the chat-history
/// key directly, the form a build before the privacy pack reads (`true`
/// without the store). Opening tells: a row's first bytes do not, since a
/// K_hist row's random nonce starts like an [`APP_ROW_V2`] row once in 256
/// ([`row_epochs`] reads such a row as an epoch's).
#[cfg(test)]
pub(crate) fn rows_open_with_hist_key(data_dir: &Path) -> Result<bool, String> {
    let Some(conn) = peek(data_dir)? else {
        return Ok(true);
    };
    let protector = crate::chat_history::DomainProtector::new(APP_ROW_DOMAIN);
    let mut stmt = conn
        .prepare("SELECT sealed FROM app_inbox")
        .map_err(AppStore::e)?;
    let mapped = stmt
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .map_err(AppStore::e)?;
    for blob in mapped {
        if protector
            .unprotect(data_dir, &blob.map_err(AppStore::e)?)
            .is_err()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The tables whose rows still name a friend in clear at the keyed schema,
/// which keys only the sender columns: `app_outbox` (the friend's key and
/// device, the message, session and object ids) and `app_pair_attempts`
/// (the friend's device). Only the app channel writes them, gated off in
/// release builds (design 7.2's open item: they have to be keyed before the
/// gate flips).
const CLEAR_ROW_TABLES: [&str; 2] = ["app_outbox", "app_pair_attempts"];

/// Which of [`CLEAR_ROW_TABLES`] hold rows (by name; nothing is read from a
/// row): `raven privacy status` does not call such a store keyed (review
/// E-harness-docs-ci-8). Empty without the store.
pub fn clear_tables_with_rows(data_dir: &Path) -> Result<Vec<&'static str>, String> {
    let Some(conn) = peek(data_dir)? else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for table in CLEAR_ROW_TABLES {
        let any: bool = conn
            .query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |r| {
                r.get(0)
            })
            .map_err(AppStore::e)?;
        if any {
            found.push(table);
        }
    }
    Ok(found)
}

/// For metadata-only work (admission, outbox records, the pairing budget):
/// never touches the keystore, so it is safe inside a session-store
/// transaction (§7.2 lock order).
pub struct MetadataOnly;

impl RowSealer for MetadataOnly {
    fn seal(&self, _plaintext: &[u8]) -> Result<Vec<u8>, String> {
        Err("APP_STORE: metadata-only handle cannot seal".into())
    }

    fn open(&self, _sealed: &[u8]) -> Result<Vec<u8>, String> {
        Err("APP_STORE: metadata-only handle cannot open".into())
    }
}

pub fn app_store_path(data_dir: &Path) -> PathBuf {
    data_dir.join(APP_STORE_FILE)
}

pub struct AppStore<'s> {
    conn: Connection,
    sealer: &'s dyn RowSealer,
    /// Rows that failed to open or whose identity did not match (tamper).
    pub quarantined: u64,
    data_dir: PathBuf,
    /// Schema 3: keyed senders and sealed `meta` (PP.12).
    keyed: bool,
    /// A schema-3 store's keys, as this process held them at the open (a
    /// handle lives for an operation or a few; the lookup key never changes,
    /// and a `meta` that names an epoch they lack is read with the keys
    /// held now).
    keys: Option<Arc<MetaKeys>>,
}

// ── Schemas ──────────────────────────────────────────────────────────────

/// `app_inbox` as `create` (`CREATE TABLE IF NOT EXISTS app_inbox`, or a
/// rebuild's new table), in either shape.
fn inbox_table(create: &str, keyed: bool) -> String {
    if keyed {
        format!(
            "{create}(
               kh_sender BLOB NOT NULL, message_id BLOB NOT NULL, app_id BLOB NOT NULL,
               content_type TEXT NOT NULL, received_at_ms INTEGER NOT NULL,
               expires_at_ms INTEGER NOT NULL, body_len INTEGER NOT NULL, sealed BLOB NOT NULL,
               meta BLOB NOT NULL,
               PRIMARY KEY(kh_sender, message_id), UNIQUE(kh_sender, app_id));"
        )
    } else {
        format!(
            "{create}(
               sender_device BLOB NOT NULL, message_id BLOB NOT NULL, app_id BLOB NOT NULL,
               sender_identity BLOB NOT NULL, content_type TEXT NOT NULL,
               created_at_ms INTEGER NOT NULL, received_at_ms INTEGER NOT NULL,
               expires_at_ms INTEGER NOT NULL, body_len INTEGER NOT NULL, cert_hash BLOB NOT NULL,
               sealed BLOB NOT NULL,
               PRIMARY KEY(sender_device, message_id), UNIQUE(sender_device, app_id));"
        )
    }
}

fn tombstones_table(create: &str, keyed: bool) -> String {
    let (sender, meta) = if keyed {
        ("kh_sender", "meta BLOB NOT NULL, ")
    } else {
        ("sender_device", "")
    };
    format!(
        "{create}(
           {sender} BLOB NOT NULL, message_id BLOB NOT NULL, app_id BLOB NOT NULL,
           disposition TEXT NOT NULL CHECK(disposition IN
             ('done','rejected','expired','revoked','not_contact','blocked')),
           at_ms INTEGER NOT NULL, {meta}PRIMARY KEY({sender}, message_id));"
    )
}

/// The tombstones' index keeps its name in both shapes, so an older build's
/// `CREATE INDEX IF NOT EXISTS` is a no-op on a migrated store.
fn tombstones_index(create: &str, keyed: bool) -> String {
    let sender = if keyed { "kh_sender" } else { "sender_device" };
    format!("{create} app_tombstones_app ON app_tombstones({sender}, app_id);")
}

fn quarantine_table(create: &str, keyed: bool) -> String {
    if keyed {
        format!(
            "{create}(
               kh_sender BLOB NOT NULL, message_id BLOB NOT NULL, app_id BLOB NOT NULL,
               content_type TEXT NOT NULL, received_at_ms INTEGER NOT NULL,
               expires_at_ms INTEGER NOT NULL, body_len INTEGER NOT NULL, sealed BLOB NOT NULL,
               meta BLOB NOT NULL, quarantined_at_ms INTEGER NOT NULL,
               PRIMARY KEY(kh_sender, message_id));"
        )
    } else {
        format!(
            "{create}(
               sender_device BLOB NOT NULL, message_id BLOB NOT NULL, app_id BLOB NOT NULL,
               sender_identity BLOB NOT NULL, content_type TEXT NOT NULL,
               created_at_ms INTEGER NOT NULL, received_at_ms INTEGER NOT NULL,
               expires_at_ms INTEGER NOT NULL, body_len INTEGER NOT NULL, cert_hash BLOB NOT NULL,
               sealed BLOB NOT NULL, quarantined_at_ms INTEGER NOT NULL,
               PRIMARY KEY(sender_device, message_id));"
        )
    }
}

/// The tables no sender column is in: the same in both shapes.
const OTHER_TABLES: &str = "CREATE TABLE IF NOT EXISTS app_outbox(
       peer_identity BLOB NOT NULL, client_ref TEXT NOT NULL, peer_device BLOB NOT NULL,
       content_type TEXT NOT NULL, app_id BLOB NOT NULL, body_sha256 BLOB NOT NULL,
       message_id BLOB NOT NULL UNIQUE, session_id BLOB NOT NULL,
       object_digest BLOB NOT NULL, created_at_ms INTEGER NOT NULL,
       expires_at_ms INTEGER NOT NULL,
       state TEXT NOT NULL CHECK(state IN
         ('queued','sent','delivered','expired','failed','cancelled')),
       last_error_code TEXT NOT NULL DEFAULT '', attempt_seq INTEGER NOT NULL,
       updated_at_ms INTEGER NOT NULL,
       PRIMARY KEY(peer_identity, client_ref));
     CREATE TABLE IF NOT EXISTS app_consumer(
       id INTEGER PRIMARY KEY CHECK(id = 1), consumer TEXT NOT NULL,
       bound_at_ms INTEGER NOT NULL);
     CREATE TABLE IF NOT EXISTS app_pair_attempts(
       peer_device BLOB NOT NULL, at_ms INTEGER NOT NULL);";

/// Schema 2 as every build since `app_quarantine` creates it (and this one
/// in a profile that is not sealed): additive, then stamped.
fn clear_schema() -> String {
    format!(
        "PRAGMA journal_mode=WAL;
         {}
         {}
         {}
         {OTHER_TABLES}
         {}
         PRAGMA user_version = 2;",
        inbox_table("CREATE TABLE IF NOT EXISTS app_inbox", false),
        tombstones_table("CREATE TABLE IF NOT EXISTS app_tombstones", false),
        tombstones_index("CREATE INDEX IF NOT EXISTS", false),
        quarantine_table("CREATE TABLE IF NOT EXISTS app_quarantine", false),
    )
}

// ── Sealed values (schema 3) ─────────────────────────────────────────────

/// An inbox (or quarantined) row's clear values that name the sender.
#[derive(Serialize, Deserialize)]
struct InboxMeta {
    sender_device: String,
    sender_identity: String,
    created_at_ms: u64,
    cert_hash: String,
}

#[derive(Serialize, Deserialize)]
struct TombstoneMeta {
    sender_device: String,
}

/// A row's primary key as stored (the meta AAD): `kh_sender || message_id`.
fn row_pk(kh_sender: &[u8], message_id: &[u8]) -> Vec<u8> {
    [kh_sender, message_id].concat()
}

/// What a sender column holds for `sender`: the device key itself, or its
/// keyed lookup (`keys` given: schema 3).
fn sender_key(keys: Option<&MetaKeys>, sender: &[u8]) -> Vec<u8> {
    match keys {
        None => sender.to_vec(),
        Some(keys) => crate::at_rest::index(keys, ValueType::DeviceKey, sender).to_vec(),
    }
}

fn seal_inbox_meta(keys: &MetaKeys, pk: &[u8], meta: &InboxMeta) -> Vec<u8> {
    let plain = Zeroizing::new(serde_json::to_vec(meta).expect("strings and numbers serialize"));
    crate::at_rest::seal_row(keys, INBOX_META, pk, &plain)
}

fn open_inbox_meta(keys: &MetaKeys, pk: &[u8], blob: &[u8]) -> Result<InboxMeta, String> {
    let plain = crate::at_rest::open_row(keys, INBOX_META, pk, blob)
        .map_err(|e| format!("APP_STORE: {e}"))?;
    serde_json::from_slice(&plain).map_err(|_| "APP_STORE: corrupt row".to_string())
}

fn seal_tombstone_meta(keys: &MetaKeys, pk: &[u8], sender: &[u8]) -> Vec<u8> {
    let plain = serde_json::to_vec(&TombstoneMeta {
        sender_device: hex::encode(sender),
    })
    .expect("strings serialize");
    crate::at_rest::seal_row(keys, TOMBSTONE_META, pk, &plain)
}

fn open_tombstone_meta(keys: &MetaKeys, pk: &[u8], blob: &[u8]) -> Result<Vec<u8>, String> {
    let plain = crate::at_rest::open_row(keys, TOMBSTONE_META, pk, blob)
        .map_err(|e| format!("APP_STORE: {e}"))?;
    let meta: TombstoneMeta =
        serde_json::from_slice(&plain).map_err(|_| "APP_STORE: corrupt row".to_string())?;
    hex::decode(meta.sender_device).map_err(|_| "APP_STORE: corrupt row".to_string())
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    hex::decode(text).map_err(|_| "APP_STORE: corrupt row".to_string())
}

/// The at-rest keys this process loaded (never a keystore call).
fn cached_keys(data_dir: &Path) -> Result<Arc<MetaKeys>, String> {
    crate::at_rest::keys_cached(data_dir).map_err(|e| format!("{STORE_KEY_UNAVAILABLE}: {e}"))
}

impl<'s> AppStore<'s> {
    /// Open (creating it) the store, at the schema the profile's mode asks
    /// for: schema 3 in a sealed profile (created so, or migrated from
    /// schema 2), schema 2 otherwise. A schema-3 store opens only with the
    /// at-rest keys loaded, whatever the mode ([`STORE_KEY_UNAVAILABLE`]);
    /// too little free disk space to migrate leaves a schema-2 store as it
    /// is until a later pass. An open of a current store writes nothing.
    pub fn open(data_dir: &Path, sealer: &'s dyn RowSealer) -> Result<Self, String> {
        Self::open_inner(data_dir, sealer).map(|(store, _)| store)
    }

    /// [`Self::open`], and whether it moved the store to schema 3 now.
    fn open_inner(data_dir: &Path, sealer: &'s dyn RowSealer) -> Result<(Self, bool), String> {
        let path = app_store_path(data_dir);
        let sealed = crate::privacy::mode(data_dir) == Mode::Sealed;
        // Before anything is created: no key, no store (never a clear one).
        if sealed {
            cached_keys(data_dir)?;
        }
        let mut conn = crate::paths::open_private_data_dir_sqlite(&path)
            .map_err(|e| format!("APP_STORE: {e}"))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| format!("APP_STORE: {e}"))?;
        // Per-connection settings only: an ordinary open never takes the write
        // lock (the receive path opens this inside its session transaction).
        conn.execute_batch("PRAGMA synchronous=FULL;")
            .map_err(|e| format!("APP_STORE: {e}"))?;
        crate::paths::harden_sqlite(&conn).map_err(|e| format!("APP_STORE: {e}"))?;
        let mut migrated = false;
        // Three rounds at most: create or migrate, then open what is there.
        for _ in 0..3 {
            let version = rebuild::user_version(&conn).map_err(Self::e)?;
            let recorded = rebuild::recorded(&conn, STORE)
                .map_err(Self::e)?
                .map(|(version, _)| version);
            if version > SCHEMA_VERSION || recorded.is_some_and(|v| v > SCHEMA_VERSION) {
                return Err("APP_STORE: app_channel.sqlite3 is newer than this build".into());
            }
            let keys = match rebuild::shape(&conn, "app_inbox", KEYED_COLUMN).map_err(Self::e)? {
                Shape::Keyed => {
                    let keys = cached_keys(data_dir)?;
                    // Stamped again where an older process stamped its own
                    // number (review R06): never migrated twice.
                    if version != SCHEMA_VERSION || recorded != Some(SCHEMA_VERSION) {
                        rebuild::restamp(&mut conn, STORE, SCHEMA_VERSION).map_err(Self::e)?;
                    }
                    Some(keys)
                }
                Shape::Missing if sealed => {
                    create_keyed(&mut conn)?;
                    continue;
                }
                Shape::Clear if sealed => {
                    if version != CLEAR_VERSION {
                        // A store from before app_quarantine: schema 2 first.
                        conn.execute_batch(&clear_schema()).map_err(Self::e)?;
                    }
                    let keys = cached_keys(data_dir)?;
                    match migrate_forward(&path, &keys, &crate::disk_space::free_bytes) {
                        Ok(done) => {
                            migrated |= !done.already;
                            continue;
                        }
                        // Deferred: the store keeps working as it is, and
                        // the next pass (or open) tries again.
                        Err(RebuildError::NoSpace { .. }) => None,
                        Err(e) => return Err(format!("APP_STORE: {e}")),
                    }
                }
                Shape::Missing | Shape::Clear => {
                    if version != CLEAR_VERSION {
                        conn.execute_batch(&clear_schema()).map_err(Self::e)?;
                    }
                    None
                }
            };
            return Ok((
                Self {
                    conn,
                    sealer,
                    quarantined: 0,
                    data_dir: data_dir.to_path_buf(),
                    keyed: keys.is_some(),
                    keys,
                },
                migrated,
            ));
        }
        Err("APP_STORE: app_channel.sqlite3 changed shape while it was opened; try again".into())
    }

    /// The sender column of the inbox, tombstones and quarantine.
    fn sender_col(&self) -> &'static str {
        if self.keyed {
            "kh_sender"
        } else {
            "sender_device"
        }
    }

    /// The at-rest keys of a schema-3 store (`None`: schema 2).
    fn keys(&self) -> Result<Option<Arc<MetaKeys>>, String> {
        Ok(self.keys.clone())
    }

    fn e(err: rusqlite::Error) -> String {
        format!("APP_STORE: {err}")
    }

    // ---------------------------------------------------------- inbox

    /// Read-only admission before the endpoint commit (§7.2).
    pub fn admit(
        &self,
        sender: &[u8; 32],
        message_id: &[u8; 16],
        app_id: &[u8; 16],
        content_type: &str,
        body_len: usize,
    ) -> Result<Admit, String> {
        let s = self.sender_col();
        let sender = sender_key(self.keys()?.as_deref(), sender);
        let tomb: Option<i64> = self
            .conn
            .query_row(
                &format!(
                    "SELECT 1 FROM app_tombstones WHERE {s} = ?1
                       AND (message_id = ?2 OR app_id = ?3) LIMIT 1"
                ),
                params![sender, message_id.as_slice(), app_id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(Self::e)?;
        if tomb.is_some() {
            return Ok(Admit::AlreadyDone);
        }
        let dup: Option<i64> = self
            .conn
            .query_row(
                &format!(
                    "SELECT 1 FROM app_inbox WHERE {s} = ?1
                       AND (message_id = ?2 OR app_id = ?3) LIMIT 1"
                ),
                params![sender, message_id.as_slice(), app_id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(Self::e)?;
        if dup.is_some() {
            return Ok(Admit::Duplicate);
        }
        let (items, bytes, per): (i64, i64, i64) = self
            .conn
            .query_row(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(body_len), 0),
                            COALESCE(SUM(CASE WHEN {s} = ?1 AND content_type = ?2
                                         THEN 1 ELSE 0 END), 0)
                     FROM app_inbox"
                ),
                params![sender, content_type],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(Self::e)?;
        let room = items < APP_INBOX_MAX_ITEMS
            && bytes + body_len as i64 <= APP_INBOX_MAX_BODY_BYTES
            && per < APP_INBOX_MAX_PER_SENDER_TYPE;
        Ok(if room { Admit::Room } else { Admit::Full })
    }

    /// Store a committed app payload (§7.3). Idempotent: `false` when it was
    /// already there or already handled.
    pub fn ingest(&mut self, item: &AppInboxItem) -> Result<bool, String> {
        // Keystore work before the write transaction, never inside it.
        let plaintext = serde_json::to_vec(item).map_err(|e| format!("APP_STORE: {e}"))?;
        let sealed = self.sealer.seal(&plaintext)?;
        let s = self.sender_col();
        let keys = self.keys()?;
        let sender = sender_key(keys.as_deref(), &item.sender_device);
        let meta = keys.as_deref().map(|keys| {
            seal_inbox_meta(
                keys,
                &row_pk(&sender, &item.message_id),
                &InboxMeta {
                    sender_device: hex::encode(item.sender_device),
                    sender_identity: hex::encode(item.sender_identity),
                    created_at_ms: item.created_at_ms,
                    cert_hash: hex::encode(item.cert_hash),
                },
            )
        });
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(Self::e)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let tomb: Option<i64> = tx
            .query_row(
                &format!(
                    "SELECT 1 FROM app_tombstones WHERE {s} = ?1
                       AND (message_id = ?2 OR app_id = ?3) LIMIT 1"
                ),
                params![sender, item.message_id.as_slice(), item.app_id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(Self::e)?;
        if tomb.is_some() {
            tx.commit().map_err(Self::e)?;
            return Ok(false);
        }
        let changed = match meta {
            None => tx.execute(
                "INSERT OR IGNORE INTO app_inbox (sender_device, message_id, app_id,
                   sender_identity, content_type, created_at_ms, received_at_ms, expires_at_ms,
                   body_len, cert_hash, sealed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    item.sender_device.as_slice(),
                    item.message_id.as_slice(),
                    item.app_id.as_slice(),
                    item.sender_identity.as_slice(),
                    item.content_type,
                    ms(item.created_at_ms),
                    ms(item.received_at_ms),
                    ms(item.expires_at_ms),
                    item.body.len() as i64,
                    item.cert_hash.as_slice(),
                    sealed,
                ],
            ),
            Some(meta) => tx.execute(
                "INSERT OR IGNORE INTO app_inbox (kh_sender, message_id, app_id, content_type,
                   received_at_ms, expires_at_ms, body_len, sealed, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    sender,
                    item.message_id.as_slice(),
                    item.app_id.as_slice(),
                    item.content_type,
                    ms(item.received_at_ms),
                    ms(item.expires_at_ms),
                    item.body.len() as i64,
                    sealed,
                    meta,
                ],
            ),
        }
        .map_err(Self::e)?;
        tx.commit().map_err(Self::e)?;
        Ok(changed > 0)
    }

    fn bind_consumer(&mut self, consumer: &str, takeover: bool, now: u64) -> Result<(), String> {
        let read = |conn: &Connection| -> Result<Option<String>, String> {
            conn.query_row("SELECT consumer FROM app_consumer WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(Self::e)
        };
        // The common case (already bound to this consumer) takes no write lock.
        if read(&self.conn)?.as_deref() == Some(consumer) {
            return Ok(());
        }
        // Read and bind in one write transaction: two first consumers never
        // both succeed.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(Self::e)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        match read(&tx)? {
            Some(b) if b == consumer => Ok(()),
            Some(b) if !takeover => Err(format!(
                "APP_CONSUMER_BUSY: bound to {}",
                b.chars().take(8).collect::<String>()
            )),
            _ => {
                tx.execute(
                    "INSERT INTO app_consumer (id, consumer, bound_at_ms) VALUES (1, ?1, ?2)
                     ON CONFLICT(id) DO UPDATE SET consumer = excluded.consumer,
                       bound_at_ms = excluded.bound_at_ms",
                    params![consumer, ms(now)],
                )
                .map_err(Self::e)?;
                tx.commit().map_err(Self::e)
            }
        }
    }

    /// The item of `sender` (its device key, in clear) leaves the inbox for
    /// a tombstone; `keys` given: schema 3.
    fn tombstone(
        tx: &rusqlite::Transaction<'_>,
        keys: Option<&MetaKeys>,
        sender: &[u8],
        mid: &[u8; 16],
        app_id: &[u8; 16],
        disposition: Disposition,
        now: u64,
    ) -> Result<(), String> {
        let Some(keys) = keys else {
            tx.execute(
                "DELETE FROM app_inbox WHERE sender_device = ?1 AND message_id = ?2",
                params![sender, mid.as_slice()],
            )
            .map_err(Self::e)?;
            tx.execute(
                "INSERT OR REPLACE INTO app_tombstones
                   (sender_device, message_id, app_id, disposition, at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    sender,
                    mid.as_slice(),
                    app_id.as_slice(),
                    disposition.as_str(),
                    ms(now)
                ],
            )
            .map_err(Self::e)?;
            return Ok(());
        };
        let kh = sender_key(Some(keys), sender);
        tx.execute(
            "DELETE FROM app_inbox WHERE kh_sender = ?1 AND message_id = ?2",
            params![kh, mid.as_slice()],
        )
        .map_err(Self::e)?;
        tx.execute(
            "INSERT OR REPLACE INTO app_tombstones
               (kh_sender, message_id, app_id, disposition, at_ms, meta)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                kh,
                mid.as_slice(),
                app_id.as_slice(),
                disposition.as_str(),
                ms(now),
                seal_tombstone_meta(keys, &row_pk(&kh, mid), sender),
            ],
        )
        .map_err(Self::e)?;
        Ok(())
    }

    /// An inbox row that cannot be served moves to `app_quarantine`, kept
    /// for inspection (not tombstoned: a genuine resend can still be stored).
    /// `sender` is the sender column's value.
    fn set_aside(
        tx: &rusqlite::Transaction<'_>,
        keyed: bool,
        sender: &[u8],
        mid: &[u8],
        now: u64,
    ) -> Result<(), String> {
        let (copy, column) = if keyed {
            (
                "INSERT OR REPLACE INTO app_quarantine (kh_sender, message_id, app_id, content_type,
               received_at_ms, expires_at_ms, body_len, sealed, meta, quarantined_at_ms)
             SELECT kh_sender, message_id, app_id, content_type, received_at_ms, expires_at_ms,
               body_len, sealed, meta, ?3
             FROM app_inbox WHERE kh_sender = ?1 AND message_id = ?2",
                "kh_sender",
            )
        } else {
            (
                "INSERT OR REPLACE INTO app_quarantine SELECT sender_device, message_id,
               app_id, sender_identity, content_type, created_at_ms, received_at_ms,
               expires_at_ms, body_len, cert_hash, sealed, ?3
             FROM app_inbox WHERE sender_device = ?1 AND message_id = ?2",
                "sender_device",
            )
        };
        tx.execute(copy, params![sender, mid, ms(now)])
            .map_err(Self::e)?;
        tx.execute(
            &format!("DELETE FROM app_inbox WHERE {column} = ?1 AND message_id = ?2"),
            params![sender, mid],
        )
        .map_err(Self::e)?;
        Ok(())
    }

    /// One page for the bound consumer (§7.5). Each item is re-checked by
    /// `recheck` (contact, block, lineage) and expired items go; failures are
    /// tombstoned with their disposition, never served. A contact book that
    /// cannot be read fails the page (`recheck` returns `Err`).
    pub fn page(
        &mut self,
        consumer: &str,
        takeover: bool,
        limit: usize,
        now: u64,
        recheck: &dyn Fn(&AppInboxItem) -> Result<Option<Disposition>, String>,
    ) -> Result<Vec<AppInboxItem>, String> {
        let query = PageQuery {
            content_type: None,
            after: None,
            limit,
            byte_budget: usize::MAX,
        };
        Ok(self
            .page_query(consumer, takeover, &query, now, recheck)?
            .items)
    }

    /// [`Self::page`] with a content-type filter, a cursor and a byte budget
    /// (the first item is always served), plus the cursor of the last item
    /// served, whether more wait, and how many servable items wait in all
    /// (`limit: 0` only binds and counts).
    pub fn page_query(
        &mut self,
        consumer: &str,
        takeover: bool,
        query: &PageQuery<'_>,
        now: u64,
        recheck: &dyn Fn(&AppInboxItem) -> Result<Option<Disposition>, String>,
    ) -> Result<PageResult, String> {
        self.bind_consumer(consumer, takeover, now)?;
        let pending = self.pending(query.content_type, now)?;
        let mut result = PageResult {
            pending,
            ..PageResult::default()
        };
        if query.limit == 0 {
            return Ok(result);
        }
        type Row = (Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>, i64);
        let s = self.sender_col();
        let keys = self.keys()?;
        // In schema 3 the order (and so the cursor) is by the keyed sender:
        // a total order all the same.
        let (after_at, after_sender, after_mid) = query
            .after
            .map(|(at, sender, mid)| (ms(at), sender_key(keys.as_deref(), &sender), mid.to_vec()))
            .unwrap_or((-1, Vec::new(), Vec::new()));
        let rows: Vec<Row> = {
            let mut stmt = self
                .conn
                .prepare(&format!(
                    "SELECT {s}, message_id, app_id, content_type, sealed, received_at_ms
                     FROM app_inbox
                     WHERE (?1 IS NULL OR content_type = ?1)
                       AND (received_at_ms, {s}, message_id) > (?2, ?3, ?4)
                     ORDER BY received_at_ms, {s}, message_id"
                ))
                .map_err(Self::e)?;
            let mapped = stmt
                .query_map(
                    params![query.content_type, after_at, after_sender, after_mid],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    },
                )
                .map_err(Self::e)?;
            mapped.collect::<Result<_, _>>().map_err(Self::e)?
        };
        let mut out = Vec::new();
        let mut spent = 0usize;
        type Gone = ([u8; 32], [u8; 16], [u8; 16], Disposition);
        let mut gone: Vec<Gone> = Vec::new();
        // The sender column's value (the keyed sender in schema 3).
        let mut bad: Vec<(Vec<u8>, [u8; 16])> = Vec::new();
        let mut sealer_ok: Option<bool> = None;
        let limit = query.limit;
        for (sender, mid, app_id, ct, sealed, received) in rows {
            if out.len() >= limit {
                result.more = true;
                break;
            }
            let (mid, app_id) = (arr::<16>(&mid)?, arr::<16>(&app_id)?);
            let opened = self.sealer.open(&sealed);
            if let Err(e) = &opened {
                // The key itself unavailable (locked keyring, DPAPI, the
                // at-rest key not loaded): fail the page and keep every row.
                // Only a row that fails while the sealer works is set aside.
                if e.starts_with(ROW_KEY_UNAVAILABLE) {
                    return Err(e.clone());
                }
                let works = *sealer_ok.get_or_insert_with(|| {
                    self.sealer
                        .seal(b"probe")
                        .and_then(|s| self.sealer.open(&s))
                        .is_ok_and(|p| p == b"probe")
                });
                if !works {
                    return Err(format!("{ROW_KEY_UNAVAILABLE}: {e}"));
                }
            }
            let item = match opened
                .ok()
                .and_then(|p| serde_json::from_slice::<AppInboxItem>(&p).ok())
            {
                Some(item)
                    if sender_key(keys.as_deref(), &item.sender_device) == sender
                        && item.message_id == mid
                        && item.app_id == app_id
                        && item.content_type == ct =>
                {
                    item
                }
                _ => {
                    self.quarantined += 1;
                    bad.push((sender, mid));
                    continue;
                }
            };
            let sender = item.sender_device;
            if item.expires_at_ms <= now {
                gone.push((sender, mid, app_id, Disposition::Expired));
                continue;
            }
            match recheck(&item)? {
                Some(disposition) => gone.push((sender, mid, app_id, disposition)),
                None => {
                    // base64 of the body: about 4/3 of it.
                    let cost = item.body.len().div_ceil(3) * 4;
                    if !out.is_empty() && spent.saturating_add(cost) > query.byte_budget {
                        result.more = true;
                        break;
                    }
                    spent = spent.saturating_add(cost);
                    result.next = Some((u64::try_from(received).unwrap_or(0), sender, mid));
                    out.push(item);
                }
            }
        }
        if !gone.is_empty() || !bad.is_empty() {
            let keyed = self.keyed;
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(Self::e)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            for (sender, mid, app_id, d) in gone {
                Self::tombstone(&tx, keys.as_deref(), &sender, &mid, &app_id, d, now)?;
            }
            // Set aside (not tombstoned): kept for inspection; a genuine resend
            // can still be stored.
            for (sender, mid) in bad {
                Self::set_aside(&tx, keyed, &sender, &mid, now)?;
            }
            tx.commit().map_err(Self::e)?;
        }
        result.items = out;
        Ok(result)
    }

    /// Unacked, unexpired items (optionally of one content type).
    pub fn pending(&self, content_type: Option<&str>, now: u64) -> Result<u32, String> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM app_inbox
                 WHERE (?1 IS NULL OR content_type = ?1) AND expires_at_ms > ?2",
                params![content_type, ms(now)],
                |r| r.get(0),
            )
            .map_err(Self::e)?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// The bound consumer finished an item. `true` when it was there.
    pub fn ack(
        &mut self,
        consumer: &str,
        sender: &[u8; 32],
        message_id: &[u8; 16],
        disposition: Disposition,
        now: u64,
    ) -> Result<bool, String> {
        let bound: Option<String> = self
            .conn
            .query_row("SELECT consumer FROM app_consumer WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(Self::e)?;
        if bound.as_deref() != Some(consumer) {
            return Err("APP_CONSUMER_BUSY: not the bound consumer".into());
        }
        let keys = self.keys()?;
        let app_id: Option<Vec<u8>> = self
            .conn
            .query_row(
                &format!(
                    "SELECT app_id FROM app_inbox WHERE {} = ?1 AND message_id = ?2",
                    self.sender_col()
                ),
                params![sender_key(keys.as_deref(), sender), message_id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(Self::e)?;
        let Some(app_id) = app_id else {
            return Ok(false);
        };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(Self::e)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        Self::tombstone(
            &tx,
            keys.as_deref(),
            sender,
            message_id,
            &arr::<16>(&app_id)?,
            disposition,
            now,
        )?;
        tx.commit().map_err(Self::e)?;
        Ok(true)
    }

    /// Item TTL, tombstone retention and cap. Rows affected.
    pub fn maintain(&mut self, now: u64) -> Result<usize, String> {
        let keys = self.keys()?;
        let (column, keyed) = (self.sender_col(), self.keyed);
        let data_dir = self.data_dir.clone();
        let meta_col = if keyed { "meta" } else { "NULL" };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(Self::e)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        type Stale = (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);
        let stale: Vec<Stale> = {
            let mut stmt = tx
                .prepare(&format!(
                    "SELECT {column}, message_id, app_id, {meta_col} FROM app_inbox
                     WHERE received_at_ms + ?1 <= ?2 OR expires_at_ms <= ?2"
                ))
                .map_err(Self::e)?;
            let mapped = stmt
                .query_map(params![ms(APP_INBOX_ITEM_TTL_MS), ms(now)], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })
                .map_err(Self::e)?;
            mapped.collect::<Result<_, _>>().map_err(Self::e)?
        };
        let mut n = stale.len();
        for (s, m, a, meta) in stale {
            // Schema 3: the clear sender from the row's meta; a row whose
            // meta does not open is set aside instead (a bad row).
            let sender = match (keys.as_deref(), meta) {
                (Some(keys), Some(meta)) => {
                    let pk = row_pk(&s, &m);
                    // An epoch these keys lack (a rotation since the open):
                    // once more with the keys held now, before a row is
                    // taken for a bad one.
                    match open_inbox_meta(keys, &pk, &meta)
                        .or_else(|_| {
                            cached_keys(&data_dir)
                                .and_then(|fresh| open_inbox_meta(&fresh, &pk, &meta))
                        })
                        .and_then(|meta| unhex(&meta.sender_device))
                    {
                        Ok(sender) => sender,
                        Err(_) => {
                            Self::set_aside(&tx, keyed, &s, &m, now)?;
                            continue;
                        }
                    }
                }
                _ => s,
            };
            Self::tombstone(
                &tx,
                keys.as_deref(),
                &sender,
                &arr(&m)?,
                &arr(&a)?,
                Disposition::Expired,
                now,
            )?;
        }
        n += tx
            .execute(
                "DELETE FROM app_tombstones WHERE at_ms + ?1 <= ?2",
                params![ms(APP_TOMBSTONE_RETENTION_MS), ms(now)],
            )
            .map_err(Self::e)?;
        n += tx
            .execute(
                "DELETE FROM app_tombstones WHERE rowid IN (
                   SELECT rowid FROM app_tombstones ORDER BY at_ms DESC LIMIT -1 OFFSET ?1)",
                params![APP_TOMBSTONE_MAX],
            )
            .map_err(Self::e)?;
        n += tx
            .execute(
                "DELETE FROM app_pair_attempts WHERE at_ms + 86400000 <= ?1",
                params![ms(now)],
            )
            .map_err(Self::e)?;
        n += tx
            .execute(
                "DELETE FROM app_quarantine WHERE quarantined_at_ms + ?1 <= ?2
                   OR rowid IN (SELECT rowid FROM app_quarantine
                                ORDER BY quarantined_at_ms DESC LIMIT -1 OFFSET ?3)",
                params![ms(APP_INBOX_ITEM_TTL_MS), ms(now), APP_QUARANTINE_MAX],
            )
            .map_err(Self::e)?;
        tx.commit().map_err(Self::e)?;
        Ok(n)
    }

    // ---------------------------------------------------------- outbox

    fn record_at(&self, peer: &[u8; 32], client_ref: &str) -> Result<Option<AppOutRecord>, String> {
        type Row = (
            Vec<u8>,
            String,
            Vec<u8>,
            String,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            i64,
            i64,
            String,
            String,
            i64,
        );
        let raw: Option<Row> = self
            .conn
            .query_row(
                "SELECT peer_identity, client_ref, peer_device, content_type, app_id, body_sha256,
                        message_id, session_id, object_digest, created_at_ms, expires_at_ms,
                        state, last_error_code, attempt_seq
                 FROM app_outbox WHERE peer_identity = ?1 AND client_ref = ?2",
                params![peer.as_slice(), client_ref],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                        r.get(11)?,
                        r.get(12)?,
                        r.get(13)?,
                    ))
                },
            )
            .optional()
            .map_err(Self::e)?;
        let Some((pi, cr, pd, ct, aid, sha, mid, sid, od, c, x, st, err, seq)) = raw else {
            return Ok(None);
        };
        Ok(Some(AppOutRecord {
            peer_identity: arr(&pi)?,
            client_ref: cr,
            peer_device: arr(&pd)?,
            content_type: ct,
            app_id: arr(&aid)?,
            body_sha256: arr(&sha)?,
            message_id: arr(&mid)?,
            session_id: arr(&sid)?,
            object_digest: arr(&od)?,
            created_at_ms: u64::try_from(c).unwrap_or(0),
            expires_at_ms: u64::try_from(x).unwrap_or(0),
            state: OutState::parse(&st)?,
            last_error_code: err,
            attempt_seq: u32::try_from(seq).unwrap_or(0),
        }))
    }

    pub fn outbox_record(
        &self,
        peer: &[u8; 32],
        client_ref: &str,
    ) -> Result<Option<AppOutRecord>, String> {
        self.record_at(peer, client_ref)
    }

    /// §8.3, recomputed under the peer's send lock.
    pub fn dedup(
        &self,
        peer: &[u8; 32],
        client_ref: &str,
        content_type: &str,
        body_sha256: &[u8; 32],
        resend: bool,
    ) -> Result<Dedup, String> {
        let Some(rec) = self.record_at(peer, client_ref)? else {
            return Ok(Dedup::Fresh);
        };
        if rec.body_sha256 != *body_sha256 || rec.content_type != content_type {
            return Ok(Dedup::Conflict);
        }
        let back = Dedup::Return {
            state: rec.state,
            message_id: rec.message_id,
        };
        if !resend {
            return Ok(back);
        }
        Ok(match rec.state {
            OutState::Queued | OutState::Sent | OutState::Delivered => back,
            OutState::Failed
                if matches!(
                    rec.last_error_code.as_str(),
                    "PEER_REVOKED" | "ATSAM_LINEAGE_REVOKED"
                ) =>
            {
                Dedup::LineageRevoked
            }
            OutState::Expired | OutState::Failed | OutState::Cancelled => Dedup::Resend {
                app_id: rec.app_id,
                seq: rec.attempt_seq.saturating_add(1),
            },
        })
    }

    /// Insert (fresh) or replace (resend) the record after the seal committed.
    /// At the cap the oldest final record is evicted; a live one never is.
    pub fn put_record(&mut self, rec: &AppOutRecord, now: u64) -> Result<(), String> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(Self::e)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        tx.execute(
            "DELETE FROM app_outbox WHERE state IN ('delivered','expired','failed','cancelled')
               AND updated_at_ms + ?1 <= ?2",
            params![ms(APP_OUTBOX_FINAL_RETENTION_MS), ms(now)],
        )
        .map_err(Self::e)?;
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM app_outbox WHERE peer_identity = ?1 AND client_ref = ?2",
                params![rec.peer_identity.as_slice(), rec.client_ref],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(Self::e)?
            .is_some();
        if !exists {
            let n: i64 = tx
                .query_row("SELECT COUNT(*) FROM app_outbox", [], |r| r.get(0))
                .map_err(Self::e)?;
            if n >= APP_OUTBOX_MAX_RECORDS {
                let evicted = tx
                    .execute(
                        "DELETE FROM app_outbox WHERE rowid = (SELECT rowid FROM app_outbox
                           WHERE state IN ('delivered','expired','failed','cancelled')
                           ORDER BY updated_at_ms LIMIT 1)",
                        [],
                    )
                    .map_err(Self::e)?;
                if evicted == 0 {
                    return Err("APP_STORE: app outbox full of live records".into());
                }
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO app_outbox (peer_identity, client_ref, peer_device,
               content_type, app_id, body_sha256, message_id, session_id, object_digest,
               created_at_ms, expires_at_ms, state, last_error_code, attempt_seq, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                rec.peer_identity.as_slice(),
                rec.client_ref,
                rec.peer_device.as_slice(),
                rec.content_type,
                rec.app_id.as_slice(),
                rec.body_sha256.as_slice(),
                rec.message_id.as_slice(),
                rec.session_id.as_slice(),
                rec.object_digest.as_slice(),
                ms(rec.created_at_ms),
                ms(rec.expires_at_ms),
                rec.state.as_str(),
                rec.last_error_code,
                i64::from(rec.attempt_seq),
                ms(now),
            ],
        )
        .map_err(Self::e)?;
        tx.commit().map_err(Self::e)?;
        Ok(())
    }

    /// Move the record of `message_id` to `state` (monotonic). `true` if moved.
    pub fn set_state(
        &mut self,
        message_id: &[u8; 16],
        state: OutState,
        code: &str,
        now: u64,
    ) -> Result<bool, String> {
        let current: Option<String> = self
            .conn
            .query_row(
                "SELECT state FROM app_outbox WHERE message_id = ?1",
                params![message_id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(Self::e)?;
        let Some(current) = current else {
            return Ok(false);
        };
        if !OutState::parse(&current)?.may_become(state) {
            return Ok(false);
        }
        let n = self
            .conn
            .execute(
                "UPDATE app_outbox SET state = ?2, last_error_code = ?3, updated_at_ms = ?4
                 WHERE message_id = ?1",
                params![message_id.as_slice(), state.as_str(), code, ms(now)],
            )
            .map_err(Self::e)?;
        Ok(n > 0)
    }

    /// The record of one sealed app object, by its message id.
    pub fn record_by_message(&self, message_id: &[u8; 16]) -> Result<Option<AppOutRecord>, String> {
        let key: Option<(Vec<u8>, String)> = self
            .conn
            .query_row(
                "SELECT peer_identity, client_ref FROM app_outbox WHERE message_id = ?1",
                params![message_id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(Self::e)?;
        match key {
            Some((peer, client_ref)) => self.record_at(&arr::<32>(&peer)?, &client_ref),
            None => Ok(None),
        }
    }

    /// App objects still in flight to `peer_device` (§8.1 cap).
    pub fn inflight_for_device(&self, peer_device: &[u8; 32]) -> Result<u32, String> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM app_outbox
                 WHERE peer_device = ?1 AND state IN ('queued','sent')",
                params![peer_device.as_slice()],
                |r| r.get(0),
            )
            .map_err(Self::e)?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// Message ids of every app object recorded for `peer_device` (the
    /// worker's "this has a body" set).
    pub fn message_ids_for_device(
        &self,
        peer_device: &[u8; 32],
    ) -> Result<std::collections::HashSet<[u8; 16]>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT message_id FROM app_outbox WHERE peer_device = ?1")
            .map_err(Self::e)?;
        let rows = stmt
            .query_map(params![peer_device.as_slice()], |r| r.get::<_, Vec<u8>>(0))
            .map_err(Self::e)?;
        let mut out = std::collections::HashSet::new();
        for row in rows {
            out.insert(arr::<16>(&row.map_err(Self::e)?)?);
        }
        Ok(out)
    }

    /// Non-final records (reconcile, §8.6).
    /// Queued or sent records last written at or before `settled_at_ms`.
    pub fn live_records(&self, settled_at_ms: u64) -> Result<Vec<AppOutRecord>, String> {
        let keys: Vec<(Vec<u8>, String)> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT peer_identity, client_ref FROM app_outbox
                     WHERE state IN ('queued','sent') AND updated_at_ms <= ?1",
                )
                .map_err(Self::e)?;
            let rows = stmt
                .query_map(params![ms(settled_at_ms)], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(Self::e)?;
            rows.collect::<Result<_, _>>().map_err(Self::e)?
        };
        let mut out = Vec::new();
        for (peer, client_ref) in keys {
            if let Some(rec) = self.record_at(&arr::<32>(&peer)?, &client_ref)? {
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Is `message_id` an app outbox object (worker / history bookkeeping)?
    pub fn is_app_message(&self, message_id: &[u8; 16]) -> Result<bool, String> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM app_outbox WHERE message_id = ?1",
                params![message_id.as_slice()],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(Self::e)?
            .is_some())
    }

    // ------------------------------------------------- pairing budget

    pub fn pair_attempts_today(&self, peer_device: &[u8; 32], now: u64) -> Result<i64, String> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM app_pair_attempts WHERE peer_device = ?1 AND at_ms > ?2",
                params![peer_device.as_slice(), ms(now.saturating_sub(86_400_000))],
                |r| r.get(0),
            )
            .map_err(Self::e)
    }

    /// When the last automatic PairInit to `peer_device` was spent.
    pub fn last_pair_attempt_at(&self, peer_device: &[u8; 32]) -> Result<Option<u64>, String> {
        let at: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(at_ms) FROM app_pair_attempts WHERE peer_device = ?1",
                params![peer_device.as_slice()],
                |r| r.get(0),
            )
            .map_err(Self::e)?;
        Ok(at.and_then(|v| u64::try_from(v).ok()))
    }

    /// Spend one PairInit of the daily budget, at least `spacing_ms` after
    /// the last one. Check and spend are one write transaction, so two
    /// submitters never both pass.
    pub fn spend_pair_attempt(
        &mut self,
        peer_device: &[u8; 32],
        now: u64,
        spacing_ms: u64,
    ) -> Result<PairSpend, String> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(Self::e)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let (last, today): (Option<i64>, i64) = tx
            .query_row(
                "SELECT MAX(at_ms), COALESCE(SUM(at_ms > ?2), 0)
                 FROM app_pair_attempts WHERE peer_device = ?1",
                params![peer_device.as_slice(), ms(now.saturating_sub(86_400_000))],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(Self::e)?;
        if let Some(last) = last.and_then(|v| u64::try_from(v).ok()) {
            let until = last.saturating_add(spacing_ms);
            if now < until {
                return Ok(PairSpend::TooSoon(until));
            }
        }
        if today >= APP_PAIR_BUDGET_PER_DAY {
            return Ok(PairSpend::UsedUp);
        }
        tx.execute(
            "INSERT INTO app_pair_attempts (peer_device, at_ms) VALUES (?1, ?2)",
            params![peer_device.as_slice(), ms(now)],
        )
        .map_err(Self::e)?;
        tx.commit().map_err(Self::e)?;
        Ok(PairSpend::Spent)
    }
}

/// A schema-3 store created in one IMMEDIATE transaction (a sealed
/// profile's first store). A racing creator's store is kept as it is.
fn create_keyed(conn: &mut Connection) -> Result<(), String> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(AppStore::e)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(AppStore::e)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, "app_inbox", KEYED_COLUMN).map_err(AppStore::e)? == Shape::Missing {
        tx.execute_batch(&format!(
            "{} {} {} {OTHER_TABLES} {}",
            inbox_table("CREATE TABLE IF NOT EXISTS app_inbox", true),
            tombstones_table("CREATE TABLE IF NOT EXISTS app_tombstones", true),
            tombstones_index("CREATE INDEX IF NOT EXISTS", true),
            quarantine_table("CREATE TABLE IF NOT EXISTS app_quarantine", true),
        ))
        .map_err(AppStore::e)?;
        rebuild::record(&tx, STORE, SCHEMA_VERSION, false).map_err(AppStore::e)?;
    }
    tx.commit().map_err(AppStore::e)
}

// ── Migration (privacy pack PP.12) ───────────────────────────────────────

/// One row of `app_inbox` or `app_quarantine` with its clear sender values.
struct SenderRow {
    rowid: i64,
    sender: Vec<u8>,
    message_id: Vec<u8>,
    app_id: Vec<u8>,
    sender_identity: Vec<u8>,
    content_type: String,
    created_at_ms: i64,
    received_at_ms: i64,
    expires_at_ms: i64,
    body_len: i64,
    cert_hash: Vec<u8>,
    sealed: Vec<u8>,
    /// `app_quarantine` only.
    quarantined_at_ms: Option<i64>,
}

impl SenderRow {
    fn inbox_meta(&self) -> InboxMeta {
        InboxMeta {
            sender_device: hex::encode(&self.sender),
            sender_identity: hex::encode(&self.sender_identity),
            created_at_ms: u64::try_from(self.created_at_ms).unwrap_or(0),
            cert_hash: hex::encode(&self.cert_hash),
        }
    }
}

/// The clear rows of `table` (`app_inbox` or `app_quarantine`, schema 2).
fn clear_sender_rows(conn: &Connection, table: &str) -> rusqlite::Result<Vec<SenderRow>> {
    let quarantined = if table == "app_quarantine" {
        "quarantined_at_ms"
    } else {
        "NULL"
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT rowid, sender_device, message_id, app_id, sender_identity, content_type,
                created_at_ms, received_at_ms, expires_at_ms, body_len, cert_hash, sealed,
                {quarantined}
         FROM {table}"
    ))?;
    let rows = stmt.query_map([], |r| {
        Ok(SenderRow {
            rowid: r.get(0)?,
            sender: r.get(1)?,
            message_id: r.get(2)?,
            app_id: r.get(3)?,
            sender_identity: r.get(4)?,
            content_type: r.get(5)?,
            created_at_ms: r.get(6)?,
            received_at_ms: r.get(7)?,
            expires_at_ms: r.get(8)?,
            body_len: r.get(9)?,
            cert_hash: r.get(10)?,
            sealed: r.get(11)?,
            quarantined_at_ms: r.get(12)?,
        })
    })?;
    rows.collect()
}

/// The rows of `table` (`app_inbox` or `app_quarantine`, schema 3) with
/// their meta opened; a row whose meta does not open is `Err` (its rowid).
fn keyed_sender_rows(
    conn: &Connection,
    keys: &MetaKeys,
    table: &str,
) -> rusqlite::Result<Vec<Result<SenderRow, i64>>> {
    let quarantined = if table == "app_quarantine" {
        "quarantined_at_ms"
    } else {
        "NULL"
    };
    type Raw = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        i64,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<i64>,
    );
    let raw: Vec<Raw> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT rowid, kh_sender, message_id, app_id, content_type, received_at_ms,
                    expires_at_ms, body_len, sealed, meta, {quarantined}
             FROM {table}"
        ))?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
                r.get(9)?,
                r.get(10)?,
            ))
        })?;
        rows.collect::<Result<_, _>>()?
    };
    Ok(raw
        .into_iter()
        .map(
            |(rowid, kh, mid, app_id, ct, received, expires, len, sealed, meta, q)| {
                let meta = open_inbox_meta(keys, &row_pk(&kh, &mid), &meta).map_err(|_| rowid)?;
                Ok(SenderRow {
                    rowid,
                    sender: unhex(&meta.sender_device).map_err(|_| rowid)?,
                    message_id: mid,
                    app_id,
                    sender_identity: unhex(&meta.sender_identity).map_err(|_| rowid)?,
                    content_type: ct,
                    created_at_ms: i64::try_from(meta.created_at_ms).unwrap_or(i64::MAX),
                    received_at_ms: received,
                    expires_at_ms: expires,
                    body_len: len,
                    cert_hash: unhex(&meta.cert_hash).map_err(|_| rowid)?,
                    sealed,
                    quarantined_at_ms: q,
                })
            },
        )
        .collect())
}

/// Schema 2 -> 3 with the rebuild recipe ([`crate::sqlite_rebuild`]): the
/// inbox, the tombstones and the quarantine rebuilt in one IMMEDIATE
/// transaction, rowids kept, counts checked before the commit, then the
/// scrub. The other tables hold no sender column and stay as they are.
fn migrate_forward(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let mut steps = Steps::default();
    let mut conn = rebuild::dedicated(path)?;
    rebuild::arm_disk_full(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    // Again inside the transaction: another process may have migrated.
    if rebuild::shape(&tx, "app_inbox", KEYED_COLUMN)? != Shape::Clear {
        return Ok(Migration::already());
    }
    let before = [
        ("app_inbox", rebuild::count(&tx, "app_inbox")?),
        ("app_tombstones", rebuild::count(&tx, "app_tombstones")?),
        ("app_quarantine", rebuild::count(&tx, "app_quarantine")?),
    ];
    let rows = forward_tables(&tx, keys, &mut steps)?;
    steps.step()?;
    rebuild::verify(&tx, &before)?;
    rebuild::record(&tx, STORE, SCHEMA_VERSION, true)?;
    steps.step()?;
    tx.commit()?;
    steps.step()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    Ok(Migration {
        rows,
        scrub_pending: !scrubbed.complete,
        ..Migration::default()
    })
}

/// Schema 2 -> 3's tables inside the caller's transaction (the migration,
/// and the second half of a re-key): the inbox, the quarantine and the
/// tombstones rebuilt keyed, rowids kept. The rows moved.
fn forward_tables(
    tx: &rusqlite::Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
) -> Result<u32, RebuildError> {
    let mut rows = 0u32;
    let leave_one_out = rebuild::drop_one_row();
    for table in ["app_inbox", "app_quarantine"] {
        steps.step()?;
        let new = format!("{table}__new");
        tx.execute_batch(&if table == "app_inbox" {
            inbox_table(&format!("CREATE TABLE {new}"), true)
        } else {
            quarantine_table(&format!("CREATE TABLE {new}"), true)
        })?;
        for (n, row) in clear_sender_rows(tx, table)?.into_iter().enumerate() {
            if leave_one_out && table == "app_inbox" && n == 0 {
                continue;
            }
            steps.step()?;
            let kh = sender_key(Some(keys), &row.sender);
            let meta = seal_inbox_meta(keys, &row_pk(&kh, &row.message_id), &row.inbox_meta());
            tx.execute(
                &format!(
                    "INSERT INTO {new} (rowid, kh_sender, message_id, app_id, content_type,
                       received_at_ms, expires_at_ms, body_len, sealed, meta{})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10{})",
                    if row.quarantined_at_ms.is_some() {
                        ", quarantined_at_ms"
                    } else {
                        ""
                    },
                    if row.quarantined_at_ms.is_some() {
                        ", ?11"
                    } else {
                        ""
                    },
                ),
                rusqlite::params_from_iter(
                    [
                        rusqlite::types::Value::Integer(row.rowid),
                        kh.into(),
                        row.message_id.into(),
                        row.app_id.into(),
                        row.content_type.into(),
                        row.received_at_ms.into(),
                        row.expires_at_ms.into(),
                        row.body_len.into(),
                        row.sealed.into(),
                        meta.into(),
                    ]
                    .into_iter()
                    .chain(row.quarantined_at_ms.map(rusqlite::types::Value::Integer)),
                ),
            )?;
            rows += 1;
        }
        steps.step()?;
        tx.execute_batch(&format!("DROP TABLE {table};"))?;
        steps.step()?;
        tx.execute_batch(&format!("ALTER TABLE {new} RENAME TO {table};"))?;
    }
    steps.step()?;
    tx.execute_batch(&tombstones_table("CREATE TABLE app_tombstones__new", true))?;
    type Tombstone = (i64, Vec<u8>, Vec<u8>, Vec<u8>, String, i64);
    let tombstones: Vec<Tombstone> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, sender_device, message_id, app_id, disposition, at_ms
             FROM app_tombstones",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, sender, mid, app_id, disposition, at) in tombstones {
        steps.step()?;
        let kh = sender_key(Some(keys), &sender);
        let meta = seal_tombstone_meta(keys, &row_pk(&kh, &mid), &sender);
        tx.execute(
            "INSERT INTO app_tombstones__new
               (rowid, kh_sender, message_id, app_id, disposition, at_ms, meta)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![rowid, kh, mid, app_id, disposition, at, meta],
        )?;
        rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE app_tombstones;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE app_tombstones__new RENAME TO app_tombstones;")?;
    steps.step()?;
    tx.execute_batch(&tombstones_index("CREATE INDEX", true))?;
    Ok(rows)
}

/// Schema 3 -> 2 (`raven privacy unseal`, PP.18): the same recipe; rows
/// whose `meta` does not open with the keys loaded here are left out and
/// counted (`dropped`), and the count check expects exactly that.
fn migrate_back(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let mut steps = Steps::default();
    let mut conn = rebuild::dedicated(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, "app_inbox", KEYED_COLUMN)? != Shape::Keyed {
        return Ok(Migration::already());
    }
    let mut report = Migration::default();
    let expected = back_tables(&tx, keys, &mut steps, &mut report)?;
    steps.step()?;
    rebuild::verify(&tx, &expected)?;
    rebuild::record(&tx, STORE, CLEAR_VERSION, true)?;
    steps.step()?;
    tx.commit()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    report.scrub_pending = !scrubbed.complete;
    Ok(report)
}

/// Schema 3 -> 2's tables inside the caller's transaction (the way back,
/// and the first half of a re-key): rows whose `meta` does not open with
/// `keys` are left out and counted in `report`. What each table must hold
/// afterwards.
fn back_tables(
    tx: &rusqlite::Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    report: &mut Migration,
) -> Result<Vec<(&'static str, i64)>, RebuildError> {
    let mut expected = Vec::new();
    for table in ["app_inbox", "app_quarantine"] {
        let before = rebuild::count(tx, table)?;
        let mut dropped = 0i64;
        steps.step()?;
        let new = format!("{table}__new");
        tx.execute_batch(&if table == "app_inbox" {
            inbox_table(&format!("CREATE TABLE {new}"), false)
        } else {
            quarantine_table(&format!("CREATE TABLE {new}"), false)
        })?;
        for row in keyed_sender_rows(tx, keys, table)? {
            steps.step()?;
            let Ok(row) = row else {
                dropped += 1;
                continue;
            };
            tx.execute(
                &format!(
                    "INSERT INTO {new} (rowid, sender_device, message_id, app_id,
                       sender_identity, content_type, created_at_ms, received_at_ms,
                       expires_at_ms, body_len, cert_hash, sealed{})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12{})",
                    if row.quarantined_at_ms.is_some() {
                        ", quarantined_at_ms"
                    } else {
                        ""
                    },
                    if row.quarantined_at_ms.is_some() {
                        ", ?13"
                    } else {
                        ""
                    },
                ),
                rusqlite::params_from_iter(
                    [
                        rusqlite::types::Value::Integer(row.rowid),
                        row.sender.into(),
                        row.message_id.into(),
                        row.app_id.into(),
                        row.sender_identity.into(),
                        row.content_type.into(),
                        row.created_at_ms.into(),
                        row.received_at_ms.into(),
                        row.expires_at_ms.into(),
                        row.body_len.into(),
                        row.cert_hash.into(),
                        row.sealed.into(),
                    ]
                    .into_iter()
                    .chain(row.quarantined_at_ms.map(rusqlite::types::Value::Integer)),
                ),
            )?;
            report.rows += 1;
        }
        steps.step()?;
        tx.execute_batch(&format!("DROP TABLE {table};"))?;
        steps.step()?;
        tx.execute_batch(&format!("ALTER TABLE {new} RENAME TO {table};"))?;
        expected.push((table, before - dropped));
        report.dropped += u32::try_from(dropped).unwrap_or(u32::MAX);
    }
    let before = rebuild::count(tx, "app_tombstones")?;
    let mut dropped = 0i64;
    steps.step()?;
    tx.execute_batch(&tombstones_table("CREATE TABLE app_tombstones__new", false))?;
    type Tombstone = (i64, Vec<u8>, Vec<u8>, Vec<u8>, String, i64, Vec<u8>);
    let tombstones: Vec<Tombstone> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, kh_sender, message_id, app_id, disposition, at_ms, meta
             FROM app_tombstones",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, kh, mid, app_id, disposition, at, meta) in tombstones {
        steps.step()?;
        let Ok(sender) = open_tombstone_meta(keys, &row_pk(&kh, &mid), &meta) else {
            dropped += 1;
            continue;
        };
        tx.execute(
            "INSERT INTO app_tombstones__new
               (rowid, sender_device, message_id, app_id, disposition, at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![rowid, sender, mid, app_id, disposition, at],
        )?;
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE app_tombstones;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE app_tombstones__new RENAME TO app_tombstones;")?;
    steps.step()?;
    tx.execute_batch(&tombstones_index("CREATE INDEX", false))?;
    expected.push(("app_tombstones", before - dropped));
    report.dropped += u32::try_from(dropped).unwrap_or(u32::MAX);
    Ok(expected)
}

/// Privacy pack PP.12, the eager half of the migration
/// (`privacy::migrate_all`, and the prune passes): in a sealed profile with
/// its keys loaded, an existing schema-2 store moves to schema 3. `true`
/// when it moved now.
pub fn migrate(data_dir: &Path) -> Result<bool, String> {
    // Schema 3 by its header: nothing to open (an older process's stamp still
    // in the WAL is put right by the next open).
    if !needs_migration(data_dir) || crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(false);
    }
    AppStore::open_inner(data_dir, &MetadataOnly).map(|(_, migrated)| migrated)
}

/// Whether the store's header says it is not at schema 3 yet (no SQLite
/// open; a commit still in the WAL is not seen, so `true` may only mean
/// "look").
pub fn needs_migration(data_dir: &Path) -> bool {
    let path = app_store_path(data_dir);
    path.exists() && rebuild::header_user_version(&path).is_none_or(|v| v < SCHEMA_VERSION)
}

/// The way back (`raven privacy unseal`, PP.18): a schema-3 store moves to
/// schema 2 with the keys this process loaded.
pub fn unseal(data_dir: &Path) -> Result<Migration, String> {
    let path = app_store_path(data_dir);
    if !path.exists() {
        return Ok(Migration::already());
    }
    let keys = cached_keys(data_dir)?;
    migrate_back(&path, &keys, &crate::disk_space::free_bytes)
        .map_err(|e| format!("APP_STORE: {e}"))
}

/// Schema 3 -> 3 under new keys (`raven privacy rotate-meta`, PP.18): in
/// one IMMEDIATE transaction on a connection that writes nothing before
/// the commit ([`rebuild::rekey_connection`]), the three tables go back to
/// their clear columns and forward again, so every keyed sender is computed
/// anew and every `meta` sealed under the current epoch; counts checked,
/// then the scrub. `keys` open every epoch the rows are under. The bodies
/// are the data-key rotation's ([`reseal_rows`]).
fn rekey_store(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let mut steps = Steps::default();
    let mut conn = rebuild::rekey_connection(path)?;
    rebuild::arm_disk_full(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, "app_inbox", KEYED_COLUMN)? != Shape::Keyed {
        return Ok(Migration::already());
    }
    let mut report = Migration::default();
    let expected = back_tables(&tx, keys, &mut steps, &mut report)?;
    report.rows = forward_tables(&tx, keys, &mut steps)?;
    rebuild::verify(&tx, &expected)?;
    rebuild::record(&tx, STORE, SCHEMA_VERSION, true)?;
    tx.commit()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    report.scrub_pending = !scrubbed.complete;
    Ok(report)
}

/// `raven privacy rotate-meta` (PP.18): a schema-3 store is keyed again
/// with the keys this process holds now (a new `k_index`; the epochs it
/// holds open the old rows). Nothing to do without a store or on a schema-2
/// one.
pub fn rekey(data_dir: &Path) -> Result<Migration, String> {
    let path = app_store_path(data_dir);
    if !path.exists() {
        return Ok(Migration::already());
    }
    let keys = cached_keys(data_dir)?;
    rekey_store(&path, &keys, &crate::disk_space::free_bytes).map_err(|e| format!("APP_STORE: {e}"))
}

/// `raven privacy unseal` (PP.18): in one IMMEDIATE transaction, every
/// inbox row under the epoch keys ([`APP_ROW_V2`]) is opened and sealed
/// again in the form an older build reads (the chat-history key directly;
/// on Windows DPAPI directly, as before PP.11), then the WAL is
/// checkpointed. The profile is no longer sealed (its mode first) and this
/// process holds its keys; no keystore call. Rows that do not open stay as
/// they are (`unreadable`), for the page.
pub fn unseal_rows(data_dir: &Path) -> Result<RowReseal, String> {
    let mut report = RowReseal::default();
    if !app_store_path(data_dir).exists() || !rows_left_for_older_build(data_dir)? {
        return Ok(report);
    }
    let hist =
        crate::at_rest::cached_hist(data_dir).map_err(|e| format!("{ROW_KEY_UNAVAILABLE}: {e}"))?;
    let protector = crate::chat_history::DomainProtector::new(APP_ROW_DOMAIN);
    let mut store = AppStore::open(data_dir, &MetadataOnly)?;
    let s = store.sender_col();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(AppStore::e)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx
            .prepare(&format!("SELECT {s}, message_id, sealed FROM app_inbox"))
            .map_err(AppStore::e)?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(AppStore::e)?;
        mapped.collect::<Result<_, _>>().map_err(AppStore::e)?
    };
    let no_keystore = |_: &[u8]| -> Result<Vec<u8>, String> {
        Err("the chat-history key is not loaded in this process".into())
    };
    for (sender, mid, sealed) in rows {
        if !row_needs_older_form(&sealed) {
            continue;
        }
        let Ok((plain, _)) = open_row_any(data_dir, &sealed, &no_keystore) else {
            report.unreadable += 1;
            continue;
        };
        let older = protector
            .protect_for_older_build(&hist, data_dir, &plain)
            .map_err(|e| format!("APP_STORE: {e}"))?;
        tx.execute(
            &format!("UPDATE app_inbox SET sealed = ?3 WHERE {s} = ?1 AND message_id = ?2"),
            params![sender, mid, older],
        )
        .map_err(AppStore::e)?;
        report.resealed += 1;
    }
    tx.commit().map_err(AppStore::e)?;
    if report.resealed > 0 {
        report.scrub_pending = crate::paths::checkpoint_truncate(&store.conn)
            .map_or(true, |checkpoint| checkpoint.busy);
    }
    Ok(report)
}

/// Whether a row's body is in a form an older build cannot open: under the
/// epoch keys ([`APP_ROW_V2`], by its first bytes) or, on Windows, under
/// K_hist behind PP.11's tag. A K_hist row whose random nonce starts like a
/// `0x02` row is opened and written again too (harmless).
fn row_needs_older_form(blob: &[u8]) -> bool {
    #[cfg(any(test, windows))]
    if crate::chat_history::windows_key::active()
        && blob.starts_with(crate::chat_history::windows_key::TAG)
    {
        return true;
    }
    row_epoch(blob).is_some()
}

/// Whether an inbox row's body is still in a form an older build cannot
/// open (`raven privacy unseal`; by first bytes, no key). `false` without
/// the store.
pub fn rows_left_for_older_build(data_dir: &Path) -> Result<bool, String> {
    let Some(conn) = peek(data_dir)? else {
        return Ok(false);
    };
    let mut stmt = conn
        .prepare("SELECT substr(sealed, 1, 5), length(sealed) FROM app_inbox")
        .map_err(AppStore::e)?;
    let mapped = stmt
        .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))
        .map_err(AppStore::e)?;
    for row in mapped {
        let (head, len) = row.map_err(AppStore::e)?;
        let long_enough =
            usize::try_from(len).is_ok_and(|len| len > crate::at_rest::EPOCH_BODY_OVERHEAD);
        let epoch = matches!(head.as_slice(), [APP_ROW_V2, ..]) && long_enough;
        #[cfg(any(test, windows))]
        let epoch = epoch
            || (crate::chat_history::windows_key::active()
                && head.starts_with(crate::chat_history::windows_key::TAG));
        if epoch {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A pending scrub is done now (the prune passes). `None`: nothing pending.
pub fn finish_scrub(data_dir: &Path) -> Option<bool> {
    rebuild::finish_scrub(
        &app_store_path(data_dir),
        STORE,
        &crate::disk_space::free_bytes,
    )
    .ok()
    .flatten()
}

/// Whether a scrub of the store is pending (`raven privacy status`).
pub fn scrub_pending(data_dir: &Path) -> bool {
    rebuild::scrub_pending(&app_store_path(data_dir), STORE)
}

/// Row `meta` blobs not on epoch `current` (the inbox, the tombstones, the
/// quarantine; by their first bytes, no key, no lock): the rotation's
/// old-object count. `0` without a schema-3 store.
pub fn meta_rows_off_epoch(data_dir: &Path, current: u32) -> Result<u32, String> {
    let Some(conn) = peek(data_dir)? else {
        return Ok(0);
    };
    if rebuild::shape(&conn, "app_inbox", KEYED_COLUMN).map_err(AppStore::e)? != Shape::Keyed {
        return Ok(0);
    }
    let n: i64 = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM app_inbox WHERE substr(meta, 2, 4) != ?1)
                  + (SELECT COUNT(*) FROM app_tombstones WHERE substr(meta, 2, 4) != ?1)
                  + (SELECT COUNT(*) FROM app_quarantine WHERE substr(meta, 2, 4) != ?1)",
            params![current.to_be_bytes().to_vec()],
            |r| r.get(0),
        )
        .map_err(AppStore::e)?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed-key test sealer (not a cipher: tests only need open∘seal = id
    /// and a detectable mismatch).
    pub(super) struct TestSealer;
    impl RowSealer for TestSealer {
        fn seal(&self, p: &[u8]) -> Result<Vec<u8>, String> {
            let mut out = b"TS1".to_vec();
            out.extend(p.iter().map(|b| b ^ 0x5a));
            Ok(out)
        }
        fn open(&self, s: &[u8]) -> Result<Vec<u8>, String> {
            s.strip_prefix(b"TS1")
                .map(|b| b.iter().map(|x| x ^ 0x5a).collect())
                .ok_or_else(|| "bad seal".into())
        }
    }

    const NOW: u64 = 1_800_000_000_000;

    /// Where the suite runs (privacy pack PP.12).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Setup {
        /// A profile that is not sealed: schema 2, as before the pack.
        Plain,
        /// A sealed profile's first store: created at schema 3.
        SealedFresh,
        /// A schema-2 store from before the profile was sealed, migrated by
        /// the sealing pass.
        Migrated,
    }

    pub(super) const SETUPS: [Setup; 3] = [Setup::Plain, Setup::SealedFresh, Setup::Migrated];

    pub(super) fn profile(setup: Setup) -> tempfile::TempDir {
        let dir = crate::contact_book::tests::profile();
        match setup {
            Setup::Plain => {}
            Setup::SealedFresh => crate::contact_book::tests::seal(dir.path()),
            Setup::Migrated => {
                drop(AppStore::open(dir.path(), &TestSealer).unwrap());
                crate::contact_book::tests::seal(dir.path());
                let conn = Connection::open(app_store_path(dir.path())).unwrap();
                assert_eq!(rebuild::user_version(&conn).unwrap(), SCHEMA_VERSION);
            }
        }
        dir
    }

    pub(super) fn item(sender: u8, mid: u8, ct: &str) -> AppInboxItem {
        AppInboxItem {
            sender_device: [sender; 32],
            message_id: [mid; 16],
            app_id: [mid ^ 0xff; 16],
            sender_identity: [sender; 32],
            content_type: ct.into(),
            created_at_ms: NOW,
            received_at_ms: NOW,
            expires_at_ms: NOW + 3_600_000,
            cert_json: "{}".into(),
            cert_hash: [9; 32],
            body: format!("body {mid}"),
        }
    }

    #[test]
    fn admit_ingest_page_ack_lifecycle() {
        for setup in SETUPS {
            let dir = profile(setup);
            let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
            let it = item(1, 1, "a2a-request/1");
            assert_eq!(
                store
                    .admit(
                        &it.sender_device,
                        &it.message_id,
                        &it.app_id,
                        &it.content_type,
                        10
                    )
                    .unwrap(),
                Admit::Room
            );
            assert!(store.ingest(&it).unwrap());
            assert!(!store.ingest(&it).unwrap());
            assert_eq!(
                store
                    .admit(
                        &it.sender_device,
                        &[7; 16],
                        &it.app_id,
                        &it.content_type,
                        10
                    )
                    .unwrap(),
                Admit::Duplicate,
                "same app_id under a new message id (resend) is the same item"
            );
            let page = store.page("rdap-1", false, 10, NOW, &|_| Ok(None)).unwrap();
            assert_eq!(page, vec![it.clone()]);
            // Another consumer is refused; takeover rebinds.
            assert!(store
                .page("rdap-2", false, 10, NOW, &|_| Ok(None))
                .unwrap_err()
                .starts_with("APP_CONSUMER_BUSY"));
            assert!(store
                .ack(
                    "rdap-2",
                    &it.sender_device,
                    &it.message_id,
                    Disposition::Done,
                    NOW
                )
                .is_err());
            assert!(store
                .ack(
                    "rdap-1",
                    &it.sender_device,
                    &it.message_id,
                    Disposition::Done,
                    NOW
                )
                .unwrap());
            assert!(store
                .page("rdap-1", false, 10, NOW, &|_| Ok(None))
                .unwrap()
                .is_empty());
            // Tombstoned: a resend is acknowledged but never stored again.
            assert_eq!(
                store
                    .admit(
                        &it.sender_device,
                        &[8; 16],
                        &it.app_id,
                        &it.content_type,
                        10
                    )
                    .unwrap(),
                Admit::AlreadyDone
            );
            assert!(!store.ingest(&it).unwrap());
            assert!(store
                .page("rdap-3", true, 10, NOW, &|_| Ok(None))
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn caps_defer_and_rechecks_tombstone() {
        for setup in SETUPS {
            let dir = profile(setup);
            let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
            for i in 0..APP_INBOX_MAX_PER_SENDER_TYPE as u8 {
                assert!(store.ingest(&item(2, i, "a2a-request/1")).unwrap());
            }
            assert_eq!(
                store
                    .admit(&[2; 32], &[200; 16], &[201; 16], "a2a-request/1", 10)
                    .unwrap(),
                Admit::Full
            );
            // Requests and responses have separate caps.
            assert_eq!(
                store
                    .admit(&[2; 32], &[200; 16], &[201; 16], "a2a-response/1", 10)
                    .unwrap(),
                Admit::Room
            );
            // A sender that is no longer a contact: tombstoned, not served.
            let page = store
                .page("c", false, 100, NOW, &|it| {
                    Ok((it.message_id[0] % 2 == 0).then_some(Disposition::NotContact))
                })
                .unwrap();
            assert_eq!(page.len(), 8);
            assert_eq!(
                store
                    .page("c", false, 100, NOW, &|_| Ok(None))
                    .unwrap()
                    .len(),
                8
            );
            // An unreadable contact book fails the page and keeps the items.
            assert!(store
                .page("c", false, 100, NOW, &|_| Err("CONTACTS_UNREADABLE".into()))
                .is_err());
            assert_eq!(
                store
                    .page("c", false, 100, NOW, &|_| Ok(None))
                    .unwrap()
                    .len(),
                8
            );
            // Expiry.
            assert_eq!(
                store
                    .page("c", false, 100, NOW + 3_600_000, &|_| Ok(None))
                    .unwrap()
                    .len(),
                0
            );
        }
    }

    #[test]
    fn tampered_rows_are_quarantined() {
        for setup in SETUPS {
            let dir = profile(setup);
            let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
            store.ingest(&item(3, 1, "a2a-request/1")).unwrap();
            store.ingest(&item(3, 2, "a2a-request/1")).unwrap();
            // Swap the two sealed blobs.
            store
            .conn
            .execute_batch(
                "UPDATE app_inbox SET sealed = (SELECT sealed FROM app_inbox ORDER BY message_id DESC LIMIT 1)
                 WHERE message_id = (SELECT message_id FROM app_inbox ORDER BY message_id LIMIT 1);",
            )
            .unwrap();
            let page = store.page("c", false, 10, NOW, &|_| Ok(None)).unwrap();
            assert_eq!(page.len(), 1);
            assert_eq!(store.quarantined, 1);
            // Set aside, not tombstoned: kept for inspection, out of the inbox.
            let count = |table: &str| -> i64 {
                store
                    .conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap()
            };
            assert_eq!(count("app_quarantine"), 1);
            assert_eq!(count("app_tombstones"), 0);
            assert_eq!(count("app_inbox"), 1);
        }
    }

    /// A sealer whose key is unavailable (locked keyring, DPAPI failure).
    struct LockedSealer;
    impl RowSealer for LockedSealer {
        fn seal(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Err("keyring locked".into())
        }
        fn open(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Err("keyring locked".into())
        }
    }

    #[test]
    fn a_locked_inbox_key_fails_the_page_and_loses_nothing() {
        for setup in SETUPS {
            let dir = profile(setup);
            {
                let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
                store.ingest(&item(3, 1, "a2a-request/1")).unwrap();
                store.ingest(&item(3, 2, "a2a-request/1")).unwrap();
            }
            {
                let mut locked = AppStore::open(dir.path(), &LockedSealer).unwrap();
                let err = locked.page("c", false, 10, NOW, &|_| Ok(None)).unwrap_err();
                assert!(err.starts_with("APP_STORE"), "{err}");
                assert_eq!(locked.quarantined, 0);
            }
            // The key is back: every item is still there.
            let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
            let page = store.page("c", false, 10, NOW, &|_| Ok(None)).unwrap();
            assert_eq!(page.len(), 2);
        }
    }

    #[test]
    fn a_current_store_opens_without_taking_the_write_lock() {
        for setup in SETUPS {
            let dir = profile(setup);
            drop(AppStore::open(dir.path(), &TestSealer).unwrap());
            // Another connection holds the write lock (as the receive path's
            // session transaction does); a plain open must not wait on it.
            let holder =
                crate::paths::open_private_data_dir_sqlite(&app_store_path(dir.path())).unwrap();
            holder.execute_batch("BEGIN IMMEDIATE;").unwrap();
            let started = std::time::Instant::now();
            let store = AppStore::open(dir.path(), &TestSealer).unwrap();
            assert!(started.elapsed() < std::time::Duration::from_secs(1));
            drop(store);
            holder.execute_batch("ROLLBACK;").unwrap();
        }
    }

    #[test]
    fn outbound_states_only_move_forward() {
        use OutState::*;
        assert!(Queued.may_become(Sent));
        assert!(Sent.may_become(Sent));
        for done in [Expired, Failed, Cancelled] {
            assert!(!done.may_become(Sent), "{done:?} -> sent");
            assert!(!done.may_become(Queued));
            assert!(done.may_become(Delivered), "a late ACK still counts");
            for other in [Expired, Failed, Cancelled] {
                assert!(!done.may_become(other), "{done:?} keeps its reason");
            }
        }
        for any in [Queued, Sent, Expired, Failed, Cancelled, Delivered] {
            assert!(!Delivered.may_become(any));
        }
    }

    fn record(seq: u32, state: OutState, code: &str) -> AppOutRecord {
        AppOutRecord {
            peer_identity: [4; 32],
            client_ref: "task-1".into(),
            peer_device: [4; 32],
            content_type: "a2a-request/1".into(),
            app_id: [5; 16],
            body_sha256: [6; 32],
            message_id: [seq as u8 + 10; 16],
            session_id: [7; 32],
            object_digest: [8; 32],
            created_at_ms: NOW,
            expires_at_ms: NOW + 1,
            state,
            last_error_code: code.into(),
            attempt_seq: seq,
        }
    }

    #[test]
    fn outbox_dedup_decisions_follow_the_table() {
        for setup in SETUPS {
            let dir = profile(setup);
            let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
            let ct = "a2a-request/1";
            assert_eq!(
                store
                    .dedup(&[4; 32], "task-1", ct, &[6; 32], false)
                    .unwrap(),
                Dedup::Fresh
            );
            store
                .put_record(&record(0, OutState::Sent, ""), NOW)
                .unwrap();
            assert_eq!(
                store
                    .dedup(&[4; 32], "task-1", ct, &[0; 32], false)
                    .unwrap(),
                Dedup::Conflict
            );
            assert!(matches!(
                store.dedup(&[4; 32], "task-1", ct, &[6; 32], true).unwrap(),
                Dedup::Return {
                    state: OutState::Sent,
                    ..
                }
            ));
            assert!(store
                .set_state(&[10; 16], OutState::Expired, "EXPIRED", NOW)
                .unwrap());
            assert_eq!(
                store.dedup(&[4; 32], "task-1", ct, &[6; 32], true).unwrap(),
                Dedup::Resend {
                    app_id: [5; 16],
                    seq: 1
                }
            );
            store
                .put_record(&record(1, OutState::Failed, "PEER_REVOKED"), NOW)
                .unwrap();
            assert_eq!(
                store.dedup(&[4; 32], "task-1", ct, &[6; 32], true).unwrap(),
                Dedup::LineageRevoked
            );
            // Monotonic: delivered is final.
            store
                .put_record(&record(2, OutState::Sent, ""), NOW)
                .unwrap();
            assert!(store
                .set_state(&[12; 16], OutState::Delivered, "", NOW)
                .unwrap());
            assert!(!store
                .set_state(&[12; 16], OutState::Expired, "", NOW)
                .unwrap());
            assert!(store.is_app_message(&[12; 16]).unwrap());
        }
    }

    #[test]
    fn pairing_budget_is_four_a_day() {
        for setup in SETUPS {
            let dir = profile(setup);
            let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
            for _ in 0..APP_PAIR_BUDGET_PER_DAY {
                assert_eq!(
                    store.spend_pair_attempt(&[1; 32], NOW, 0).unwrap(),
                    PairSpend::Spent
                );
            }
            assert_eq!(
                store.spend_pair_attempt(&[1; 32], NOW, 0).unwrap(),
                PairSpend::UsedUp
            );
            assert_eq!(
                store
                    .spend_pair_attempt(&[1; 32], NOW + 86_400_001, 0)
                    .unwrap(),
                PairSpend::Spent
            );
            // Spacing is checked in the same transaction.
            assert_eq!(
                store
                    .spend_pair_attempt(&[1; 32], NOW + 86_400_002, 60_000)
                    .unwrap(),
                PairSpend::TooSoon(NOW + 86_400_001 + 60_000)
            );
            assert_eq!(
                store
                    .pair_attempts_today(&[1; 32], NOW + 2 * 86_400_000)
                    .unwrap(),
                1
            );
            store.maintain(NOW + 3 * 86_400_000).unwrap();
            assert_eq!(
                store
                    .pair_attempts_today(&[1; 32], NOW + 3 * 86_400_000)
                    .unwrap(),
                0
            );
        }
    }

    /// Privacy pack PP.10: the `0x02` row format is fixed forever (the value
    /// was computed with the stdlib-only Python reference in
    /// `scripts/lan_fault_matrix.py`).
    #[test]
    fn epoch_row_format_is_pinned() {
        let keys = crate::at_rest::tests::fixed_keys();
        let mut row = vec![APP_ROW_V2];
        row.extend_from_slice(&crate::at_rest::seal_epoch_with(
            &keys,
            crate::at_rest::DataUse::AppRow,
            APP_ROW_DOMAIN,
            1,
            &[0x88; 24],
            b"{}",
        ));
        assert_eq!(
            hex::encode(&row),
            "0200000001888888888888888888888888888888888888888888888888\
             1ad508f4e44b2f6fdd84218b9190a1e8e50b"
        );
        assert_eq!(row_epoch(&row), Some(1));
        let shortest = 1 + crate::at_rest::EPOCH_BODY_OVERHEAD;
        assert_eq!(row_epoch(&row[..shortest]), Some(1));
        assert_eq!(row_epoch(&row[..shortest - 1]), None, "too short");
        assert_eq!(
            row_epoch(&[0x01; 64]),
            None,
            "the chat-history key's format"
        );
    }

    #[test]
    fn secure_delete_is_on_after_open() {
        for setup in SETUPS {
            let dir = profile(setup);
            let store = AppStore::open(dir.path(), &TestSealer).unwrap();
            assert_eq!(crate::paths::scrub_test::secure_delete(&store.conn), 1);
            // A store already at this schema takes the early return: hardened too.
            drop(store);
            let again = AppStore::open(dir.path(), &TestSealer).unwrap();
            assert_eq!(crate::paths::scrub_test::secure_delete(&again.conn), 1);
        }
    }

    /// PP.2: an item past its TTL is overwritten when `maintain` turns it
    /// into a tombstone; a checkpoint takes that into the main file.
    #[test]
    fn a_deleted_row_leaves_no_bytes_after_checkpoint() {
        use crate::paths::scrub_test;
        let dir = tempfile::tempdir().unwrap();
        let path = app_store_path(dir.path());
        let marker = scrub_test::marker();
        let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
        let mut it = item(1, 1, "a2a-request/1");
        it.cert_hash = marker;
        assert!(store.ingest(&it).unwrap());
        scrub_test::assert_written(&store.conn, &path, &marker);
        assert_eq!(store.maintain(it.expires_at_ms).unwrap(), 1);
        let checkpoint = crate::paths::checkpoint_truncate(&store.conn).unwrap();
        assert!(checkpoint.completed(), "{checkpoint:?}");
        scrub_test::assert_scrubbed(&path, &marker);
    }
}

/// A schema-2 store at `data_dir`, as an older build creates it (tests of
/// other modules).
#[cfg(test)]
pub(crate) fn create_clear_store_for_tests(data_dir: &Path) {
    Connection::open(app_store_path(data_dir))
        .unwrap()
        .execute_batch(&clear_schema())
        .unwrap();
}

#[cfg(test)]
mod sealed_tests;
