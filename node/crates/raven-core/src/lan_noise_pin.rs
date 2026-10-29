//! M0 (cutoff pack): each contact's Noise static, pinned as a digest.
//!
//! The LAN dialer sends Noise message 3 (its own static) and its signed
//! identity bind before it learns who answered, so whatever answers at a
//! friend's old DHCP address would learn this user's Raven identity and keep
//! a signed proof of it. A dial that holds a noise pin for its contact reads
//! the responder's static after message 2 and stops there when another key
//! answered (raven-node's `lan_direct`; Internet direct and the p2p inner
//! link use the same static, so one pin covers all three).
//!
//! - **A keyed digest, never the static.** [`pin_digest`] is HMAC-SHA256 over
//!   a domain, the contact's Ed25519 key and its Noise static, keyed with
//!   [`PinKey`]: HKDF of this computer's identity seed, which is not in the
//!   data dir. Every listener shows its static to any dialer (Noise message
//!   2), so an unkeyed digest would let whoever copies the data dir test the
//!   static of each computer it meets against every pin and name your
//!   friends' laptops on any network; without the seed it cannot. The
//!   contact keys are already in `contacts.json`.
//! - **No times.** Entries keep insertion order only (oldest first), bounded at
//!   [`MAX_PINS`]: the file says nothing about when you last met anyone.
//! - **Written after an authenticated link only:** the dialer once the
//!   responder's bind verified, the listener for a contact's inbound link.
//!   `ash contact remove` forgets; an address change keeps it.
//! - **Advisory, never lost.** A missing file is "no pins" (today's
//!   behaviour). A row that does not parse is skipped and the others are
//!   kept; a plain file that does not parse at all is "no pins" too. Either
//!   way the next record moves the file aside to [`NOISE_PIN_CORRUPT_FILE`]
//!   before it writes, so nothing is overwritten. A file of the unkeyed
//!   version 1 (lab builds only) is no pins and is replaced quietly. `Err` is
//!   reserved for a store that exists but cannot be opened, for one a newer
//!   Raven wrote (a version above [`FILE_VERSION`]: never read as no pins,
//!   never overwritten), and for a sealed store that does not open or read
//!   (the at-rest key not loaded, a changed byte); callers then do not dial.
//! - **Sealed (privacy pack PP.5).** A sealed profile keeps its pins in
//!   [`NOISE_PIN_SEALED_FILE`] (RMS1 kind 16), a name of their own (review
//!   R07): an older build that found the old name unreadable would rewrite it
//!   with trust-on-first-use pins. Such a profile reads and writes only that
//!   file. An older build finds no plain file and pins on first use into a
//!   new [`NOISE_PIN_FILE`]; the next `privacy::migrate_all` merges those pins
//!   only for contacts without a sealed pin, keeps the sealed pin where they
//!   differ (counted), and deletes the plain file ([`merge_plain_into_sealed`]).
//!
//! Nothing here reads the gate: callers check
//! [`crate::lan_gate::lan_noise_pin_live`] first, so with the gate closed
//! nothing is read or written. All file I/O goes through `load_file` and
//! `save_file`.

use std::path::Path;
use std::time::Duration;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::at_rest::{self, AtRestError, Kind, Mode};
use crate::identity::Identity;
use crate::paths::DataDirLock;

/// The file in the data dir: `{"v":2,"pins":[{"c":"<contact hex>","d":"<digest hex>"}, ...]}`,
/// oldest first. A sealed profile keeps the same JSON in
/// [`NOISE_PIN_SEALED_FILE`] instead.
pub const NOISE_PIN_FILE: &str = "lan_noise_pins.json";
/// A sealed profile's pins: RMS1 (kind 16) of the same JSON, under a name an
/// older build never opens (privacy pack PP.5, review R07).
pub const NOISE_PIN_SEALED_FILE: &str = "lan_noise_pins.rms";
/// Where [`record`] moves a file that did not parse (wholly or in part)
/// before it writes a new one (0600; a later one replaces it). Sealed in
/// place in a sealed profile.
pub const NOISE_PIN_CORRUPT_FILE: &str = "lan_noise_pins.json.corrupt";
/// Its own data-dir lock: raven-node records and `ash contact remove` forgets.
const NOISE_PIN_LOCK: &str = ".lan_noise_pins.lock.sqlite";
const PIN_DOMAIN: &[u8] = b"rvn1/lan-noise-pin/v1";
/// HKDF-SHA256 salt and info of [`PinKey`] (its own salt: never the Noise
/// static's, `lan_noise::HKDF_SALT`).
const PIN_KEY_SALT: &[u8] = b"rvn1/lan-noise-pin-key/v1";
const PIN_KEY_INFO: &[u8] = b"hmac-sha256-key";
/// 2: keyed digests ([`PinKey`]). Version 1 (unkeyed SHA-256, lab builds
/// only) reads as no pins and is replaced on the next record.
const FILE_VERSION: u32 = 2;
/// At most this many contacts are pinned (the oldest-inserted goes first).
pub const MAX_PINS: usize = 4096;
/// A busy lock skips the record (best effort: the next link records it).
const RECORD_LOCK_WAIT: Duration = Duration::from_secs(2);

#[derive(Debug, Serialize, Deserialize)]
struct PinFile {
    v: u32,
    pins: Vec<PinRow>,
}

/// What [`load_file`] parses first: the version, and the rows as they are
/// (each one parsed on its own, so one bad row costs only itself).
#[derive(Debug, Deserialize)]
struct RawPinFile {
    v: u32,
    pins: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PinRow {
    c: String,
    d: String,
}

/// (contact Ed25519 key, pin digest), in insertion order.
type Pins = Vec<([u8; 32], [u8; 32])>;

/// The key this computer's pin digests are made with: HKDF-SHA256 of its
/// identity seed (salt `rvn1/lan-noise-pin-key/v1`), wiped on drop. Never
/// stored: whoever has the data dir alone cannot recompute a digest.
pub struct PinKey(Zeroizing<[u8; 32]>);

impl PinKey {
    /// Derived like [`crate::lan_noise::derive_noise_static`], from the same
    /// seed, so a profile restored from its seed checks its pins again.
    pub fn derive(identity: &Identity) -> Self {
        let mut seed = identity.seed_bytes();
        let hk = Hkdf::<Sha256>::new(Some(PIN_KEY_SALT), &seed);
        seed.zeroize();
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(PIN_KEY_INFO, okm.as_mut_slice())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self(okm)
    }
}

/// A pin key for other modules' tests (any fixed identity).
#[cfg(test)]
pub(crate) fn test_key() -> PinKey {
    PinKey::derive(&Identity::from_seed(&[0xC0; 32]))
}

impl std::fmt::Debug for PinKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinKey(..)")
    }
}

/// HMAC-SHA256(`key`, domain || contact Ed25519 || Noise static).
pub fn pin_digest(key: &PinKey, contact: &[u8; 32], noise_static: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.0.as_slice()).expect("hmac takes any key");
    mac.update(PIN_DOMAIN);
    mac.update(contact);
    mac.update(noise_static);
    mac.finalize().into_bytes().into()
}

fn key32(text: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(text).ok()?;
    raw.try_into().ok()
}

/// Which file holds this profile's pins: [`NOISE_PIN_SEALED_FILE`] in a
/// sealed profile, [`NOISE_PIN_FILE`] otherwise. Decided once per operation
/// (`privacy.json` is read once).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Store {
    Plain,
    Sealed,
}

impl Store {
    fn of(data_dir: &Path) -> Store {
        if crate::privacy::mode(data_dir) == Mode::Sealed {
            Store::Sealed
        } else {
            Store::Plain
        }
    }

    fn file(self) -> &'static str {
        match self {
            Store::Plain => NOISE_PIN_FILE,
            Store::Sealed => NOISE_PIN_SEALED_FILE,
        }
    }
}

/// The file this profile's pins are in now ([`NOISE_PIN_SEALED_FILE`] when
/// it is sealed): what `raven doctor` names.
pub fn store_file_name(data_dir: &Path) -> &'static str {
    Store::of(data_dir).file()
}

/// The pins in `store`, and whether its file was there but did not parse as
/// pins, wholly (then read as none) or in part (the rows that parse are
/// kept). `Err` when it exists and cannot be read at all, a newer Raven wrote
/// it, or it is sealed (RMS1) and does not open or read in full: a sealed
/// store is never read as no pins.
fn load_file(data_dir: &Path, store: Store) -> Result<(Pins, bool), String> {
    let name = store.file();
    let raw = match std::fs::read(data_dir.join(name)) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), false)),
        Err(e) => return Err(format!("{name}: {}", e.kind())),
    };
    if !at_rest::is_sealed(&raw) {
        return parse_pins(name, &raw);
    }
    let plain = at_rest::keys_cached(data_dir)
        .and_then(|keys| at_rest::open(&keys, Kind::NoisePins, &raw))
        .map_err(|e| format!("{name}: {e}"))?;
    match parse_pins(name, &plain)? {
        (pins, false) => Ok((pins, false)),
        (_, true) => Err(format!("{name}: the sealed pins do not read in full")),
    }
}

/// [`load_file`]'s parse of a file's JSON (`name` for the error text).
fn parse_pins(name: &str, raw: &[u8]) -> Result<(Pins, bool), String> {
    let Ok(file) = serde_json::from_slice::<RawPinFile>(raw) else {
        return Ok((Vec::new(), true));
    };
    match file.v {
        // The unkeyed version 1: no pins, replaced quietly on the next record.
        1 => return Ok((Vec::new(), false)),
        FILE_VERSION => {}
        v if v > FILE_VERSION => {
            return Err(format!("{name}: version {v}, written by a newer Raven"))
        }
        _ => return Ok((Vec::new(), true)),
    }
    let mut pins = Pins::with_capacity(file.pins.len());
    let mut corrupt = false;
    for row in file.pins {
        let row = serde_json::from_value::<PinRow>(row)
            .ok()
            .and_then(|row| Some((key32(&row.c)?, key32(&row.d)?)));
        match row {
            Some(pin) => pins.push(pin),
            None => corrupt = true,
        }
    }
    Ok((pins, corrupt))
}

/// Move `store`'s file that did not parse aside ([`NOISE_PIN_CORRUPT_FILE`],
/// 0600) before a new one replaces it: what it held is kept for a look
/// later, sealed in place in a sealed profile. The caller holds
/// [`NOISE_PIN_LOCK`] (the lock of the copy too).
fn move_aside(data_dir: &Path, store: Store) -> Result<(), String> {
    let name = store.file();
    let aside = data_dir.join(NOISE_PIN_CORRUPT_FILE);
    std::fs::rename(data_dir.join(name), &aside)
        .map_err(|e| format!("{name}: moving it aside: {}", e.kind()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&aside, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{NOISE_PIN_CORRUPT_FILE}: {}", e.kind()))?;
    }
    if store == Store::Sealed {
        at_rest::migrate_file_held(data_dir, &aside, Kind::NoisePins)
            .map_err(|e| format!("{NOISE_PIN_CORRUPT_FILE}: {e}"))?;
    }
    Ok(())
}

/// The file's JSON (compact, oldest first).
fn pin_file_bytes(pins: &Pins) -> Result<Vec<u8>, String> {
    let file = PinFile {
        v: FILE_VERSION,
        pins: pins
            .iter()
            .map(|(c, d)| PinRow {
                c: hex::encode(c),
                d: hex::encode(d),
            })
            .collect(),
    };
    serde_json::to_vec(&file).map_err(|e| e.to_string())
}

/// Write `store`'s file. The caller holds [`NOISE_PIN_LOCK`].
fn save_file(data_dir: &Path, store: Store, pins: &Pins) -> Result<(), String> {
    let raw = pin_file_bytes(pins)?;
    match store {
        Store::Plain => crate::paths::atomic_write_private(&data_dir.join(NOISE_PIN_FILE), &raw),
        Store::Sealed => at_rest::write_held(
            data_dir,
            &data_dir.join(NOISE_PIN_SEALED_FILE),
            Kind::NoisePins,
            &raw,
        )
        .map_err(|e| format!("{NOISE_PIN_SEALED_FILE}: {e}")),
    }
}

/// `Ok(None)`: no pin, file missing, or the file (or the contact's row)
/// does not parse (today's behaviour). `Err` is reserved for "the pin store
/// exists but cannot be opened", "a newer Raven wrote it" and "it is sealed
/// and does not open"; every caller treats it as "do not dial this route".
pub fn load_pin(data_dir: &Path, contact: &[u8; 32]) -> Result<Option<[u8; 32]>, String> {
    load_pin_in(data_dir, Store::of(data_dir), contact)
}

fn load_pin_in(
    data_dir: &Path,
    store: Store,
    contact: &[u8; 32],
) -> Result<Option<[u8; 32]>, String> {
    let (pins, _) = load_file(data_dir, store)?;
    Ok(pins.into_iter().find(|(c, _)| c == contact).map(|(_, d)| d))
}

/// How many contacts are pinned (`ash doctor`): 0 for a missing file or one
/// that does not parse, the rows that parse otherwise; `Err` when it exists
/// but cannot be read, a newer Raven wrote it, or it is sealed and does not
/// open (then no dial goes out).
pub fn pinned_count(data_dir: &Path) -> Result<usize, String> {
    load_file(data_dir, Store::of(data_dir)).map(|(pins, _)| pins.len())
}

/// Pin `noise_static` for `contact` after an authenticated link, under this
/// computer's `key`. Writes only when the digest is new or changed (no write
/// on the hot path); `true` when it wrote. A full store drops its
/// oldest-inserted entry. A file that did not parse (wholly or in part) is
/// moved aside first ([`NOISE_PIN_CORRUPT_FILE`]), never overwritten.
pub fn record(
    data_dir: &Path,
    key: &PinKey,
    contact: &[u8; 32],
    noise_static: &[u8; 32],
) -> Result<bool, String> {
    let digest = pin_digest(key, contact, noise_static);
    let store = Store::of(data_dir);
    // Lock-free look first: an unchanged pin costs one small read.
    if load_pin_in(data_dir, store, contact)? == Some(digest) {
        return Ok(false);
    }
    let _lock = DataDirLock::acquire_within(data_dir, NOISE_PIN_LOCK, RECORD_LOCK_WAIT)?;
    let (mut pins, corrupt) = load_file(data_dir, store)?;
    match pins.iter_mut().find(|(c, _)| c == contact) {
        Some((_, d)) if *d == digest => return Ok(false),
        Some((_, d)) => *d = digest,
        None => pins.push((*contact, digest)),
    }
    if pins.len() > MAX_PINS {
        let excess = pins.len() - MAX_PINS;
        pins.drain(..excess);
    }
    if corrupt {
        move_aside(data_dir, store)?;
    }
    save_file(data_dir, store, &pins)?;
    if corrupt {
        eprintln!(
            "raven: {} did not read in full; it was moved to {NOISE_PIN_CORRUPT_FILE} and a new \
             one written ({} entr{} now)",
            store.file(),
            pins.len(),
            if pins.len() == 1 { "y" } else { "ies" }
        );
    }
    Ok(true)
}

/// Forget `contact`'s pin (its contact was removed). A missing file or entry
/// is fine, and nothing is created then.
pub fn forget(data_dir: &Path, contact: &[u8; 32]) -> Result<(), String> {
    let store = Store::of(data_dir);
    if load_pin_in(data_dir, store, contact)?.is_none() {
        return Ok(());
    }
    let _lock = DataDirLock::acquire(data_dir, NOISE_PIN_LOCK)?;
    let (mut pins, corrupt) = load_file(data_dir, store)?;
    let before = pins.len();
    pins.retain(|(c, _)| c != contact);
    if pins.len() == before {
        return Ok(());
    }
    if corrupt {
        move_aside(data_dir, store)?;
    }
    save_file(data_dir, store, &pins)
}

/// What [`merge_plain_into_sealed`] found and did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PinMerge {
    /// A plain [`NOISE_PIN_FILE`] was there; it is gone now (moved aside to
    /// [`NOISE_PIN_CORRUPT_FILE`], sealed, when it did not read in full).
    pub found: bool,
    /// Its pins taken over: contacts the sealed file did not pin.
    pub merged: usize,
    /// Contacts it pinned to another key than the sealed file: the sealed
    /// pin was kept (`older_build_pinned_differently`).
    pub conflicts: usize,
}

/// `privacy::migrate_all` in a sealed profile (the mode is sealed and the
/// key loaded): move a plain [`NOISE_PIN_FILE`] into
/// [`NOISE_PIN_SEALED_FILE`] under [`NOISE_PIN_LOCK`]. At the first sealing
/// every plain pin moves; later, a plain file is an older build's (it pins on
/// first use into a new one, R07), and its pins are taken only for contacts
/// the sealed file does not pin: where both pin a contact differently the
/// sealed pin stays (counted). The sealed file is written and checked to
/// open to exactly the merged pins before the plain file goes. A plain file
/// a newer Raven wrote, or a sealed one that does not open, stops it with
/// both files as they were.
pub fn merge_plain_into_sealed(data_dir: &Path) -> Result<PinMerge, AtRestError> {
    let plain_path = data_dir.join(NOISE_PIN_FILE);
    match std::fs::symlink_metadata(&plain_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(PinMerge::default()),
        Err(e) => return Err(AtRestError::Io(format!("{NOISE_PIN_FILE}: {e}"))),
    }
    if crate::privacy::mode(data_dir) != Mode::Sealed {
        return Err(AtRestError::NotSealedMode);
    }
    let _lock = DataDirLock::acquire(data_dir, NOISE_PIN_LOCK).map_err(AtRestError::Io)?;
    let (plain, plain_corrupt) = load_file(data_dir, Store::Plain).map_err(AtRestError::Io)?;
    let (mut pins, sealed_corrupt) = load_file(data_dir, Store::Sealed).map_err(AtRestError::Io)?;
    if sealed_corrupt {
        // Plain bytes under the sealed name that do not parse: left for
        // the next record to move aside, never merged over.
        return Err(AtRestError::Json(format!(
            "{NOISE_PIN_SEALED_FILE} did not read in full"
        )));
    }
    let mut merge = PinMerge {
        found: true,
        ..PinMerge::default()
    };
    for (contact, digest) in plain {
        match pins.iter().find(|(c, _)| *c == contact) {
            Some((_, kept)) if *kept == digest => {}
            Some(_) => merge.conflicts += 1,
            None => {
                pins.push((contact, digest));
                merge.merged += 1;
            }
        }
    }
    if pins.len() > MAX_PINS {
        let excess = pins.len() - MAX_PINS;
        pins.drain(..excess);
    }
    let raw = pin_file_bytes(&pins).map_err(AtRestError::Json)?;
    at_rest::seal_verified_held(
        data_dir,
        &data_dir.join(NOISE_PIN_SEALED_FILE),
        Kind::NoisePins,
        &raw,
    )?;
    if plain_corrupt {
        move_aside(data_dir, Store::Plain).map_err(AtRestError::Io)?;
        at_rest::migrate_file_held(
            data_dir,
            &data_dir.join(NOISE_PIN_CORRUPT_FILE),
            Kind::NoisePins,
        )?;
    } else {
        std::fs::remove_file(&plain_path)
            .map_err(|e| AtRestError::Io(format!("{NOISE_PIN_FILE}: {e}")))?;
        crate::paths::sync_dir_best_effort(data_dir);
    }
    Ok(merge)
}

/// The way back (`raven privacy unseal`, PP.18; the profile is no longer
/// sealed and this process holds its key): under [`NOISE_PIN_LOCK`], the
/// sealed pins go back to [`NOISE_PIN_FILE`], the name a build before the
/// pack reads. A plain file there already (an older build pinned on first
/// use while the profile was sealed) keeps its pins for contacts the sealed
/// file does not pin; where both pin a contact differently the sealed pin
/// stays (counted), as [`merge_plain_into_sealed`] decides the other way.
/// The plain file is written and checked before the sealed one goes. A
/// sealed file that does not open stops it with both files as they were.
pub fn unseal_into_plain(data_dir: &Path) -> Result<PinMerge, AtRestError> {
    let sealed_path = data_dir.join(NOISE_PIN_SEALED_FILE);
    match std::fs::symlink_metadata(&sealed_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(PinMerge::default()),
        Err(e) => return Err(AtRestError::Io(format!("{NOISE_PIN_SEALED_FILE}: {e}"))),
    }
    let _lock = DataDirLock::acquire(data_dir, NOISE_PIN_LOCK).map_err(AtRestError::Io)?;
    let (mut pins, sealed_corrupt) = load_file(data_dir, Store::Sealed).map_err(AtRestError::Io)?;
    if sealed_corrupt {
        return Err(AtRestError::Json(format!(
            "{NOISE_PIN_SEALED_FILE} did not read in full"
        )));
    }
    let (plain, plain_corrupt) = load_file(data_dir, Store::Plain).map_err(AtRestError::Io)?;
    let mut merge = PinMerge {
        found: true,
        ..PinMerge::default()
    };
    for (contact, digest) in plain {
        match pins.iter().find(|(c, _)| *c == contact) {
            Some((_, kept)) if *kept == digest => {}
            Some(_) => merge.conflicts += 1,
            None => {
                pins.push((contact, digest));
                merge.merged += 1;
            }
        }
    }
    if pins.len() > MAX_PINS {
        let excess = pins.len() - MAX_PINS;
        pins.drain(..excess);
    }
    if plain_corrupt {
        // What the older build wrote and this one cannot read is kept for a
        // look, as a plain record does.
        move_aside(data_dir, Store::Plain).map_err(AtRestError::Io)?;
    }
    let raw = pin_file_bytes(&pins).map_err(AtRestError::Json)?;
    crate::paths::atomic_write_private_verified(&data_dir.join(NOISE_PIN_FILE), &raw, |temp| {
        match std::fs::read(temp) {
            Ok(written) if written == raw => Ok(()),
            Ok(_) => Err(format!("{NOISE_PIN_FILE}: the written copy differs")),
            Err(e) => Err(format!("{NOISE_PIN_FILE}: {e}")),
        }
    })
    .map_err(AtRestError::Io)?;
    std::fs::remove_file(&sealed_path)
        .map_err(|e| AtRestError::Io(format!("{NOISE_PIN_SEALED_FILE}: {e}")))?;
    crate::paths::sync_dir_best_effort(data_dir);
    Ok(merge)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [0xA1; 32];
    const BOB: [u8; 32] = [0xB0; 32];
    const STATIC_1: [u8; 32] = [0x51; 32];
    const STATIC_2: [u8; 32] = [0x52; 32];

    /// This computer's pin key (its identity seed is not in the data dir).
    fn key() -> PinKey {
        test_key()
    }

    fn digest(contact: &[u8; 32], noise_static: &[u8; 32]) -> [u8; 32] {
        pin_digest(&key(), contact, noise_static)
    }

    fn record(dir: &Path, contact: &[u8; 32], noise_static: &[u8; 32]) -> Result<bool, String> {
        super::record(dir, &key(), contact, noise_static)
    }

    /// What anyone with the file could compute: SHA-256 over the domain and
    /// the two public keys (the unkeyed version 1).
    fn unkeyed(contact: &[u8; 32], noise_static: &[u8; 32]) -> [u8; 32] {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(PIN_DOMAIN);
        h.update(contact);
        h.update(noise_static);
        h.finalize().into()
    }

    fn file_text(dir: &Path) -> String {
        std::fs::read_to_string(dir.join(NOISE_PIN_FILE)).unwrap()
    }

    #[test]
    fn digest_is_contact_bound() {
        let d = digest(&ALICE, &STATIC_1);
        assert_eq!(d, digest(&ALICE, &STATIC_1));
        // The same static under another contact key is another pin, and the
        // two inputs are not interchangeable.
        assert_ne!(d, digest(&BOB, &STATIC_1));
        assert_ne!(d, digest(&ALICE, &STATIC_2));
        assert_ne!(digest(&ALICE, &BOB), digest(&BOB, &ALICE));
        // Domain-separated: not a bare MAC of the two keys.
        let mut bare = Hmac::<Sha256>::new_from_slice(key().0.as_slice()).unwrap();
        bare.update(&ALICE);
        bare.update(&STATIC_1);
        assert_ne!(d, <[u8; 32]>::from(bare.finalize().into_bytes()));
    }

    /// A-noise-pin-3: the digest is keyed by this computer's identity seed.
    /// Whoever copies the data dir knows each contact key (`c`) and can learn
    /// any listener's static by connecting to it, but cannot compute the
    /// digest that would name the laptop: another identity's key, or no key,
    /// gives another one.
    #[test]
    fn digest_is_keyed_by_the_local_identity() {
        let other = PinKey::derive(&Identity::from_seed(&[0xC1; 32]));
        assert_ne!(
            digest(&ALICE, &STATIC_1),
            pin_digest(&other, &ALICE, &STATIC_1)
        );
        assert_eq!(
            pin_digest(
                &PinKey::derive(&Identity::from_seed(&[0xC0; 32])),
                &ALICE,
                &STATIC_1
            ),
            digest(&ALICE, &STATIC_1),
            "the same seed (a restore) gives the same key"
        );
        // Not the Noise static's derivation either.
        let noise =
            crate::lan_noise::derive_noise_static(&Identity::from_seed(&[0xC0; 32])).unwrap();
        assert_ne!(key().0.as_slice(), noise.as_slice());
        assert_eq!(format!("{:?}", key()), "PinKey(..)");
    }

    #[test]
    fn a_disk_reader_cannot_recompute_a_digest() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), &ALICE, &STATIC_1).unwrap();
        let value: serde_json::Value = serde_json::from_str(&file_text(dir.path())).unwrap();
        let row = &value["pins"][0];
        assert_eq!(row["c"], hex::encode(ALICE));
        let stored = row["d"].as_str().unwrap();
        assert_ne!(stored, hex::encode(unkeyed(&ALICE, &STATIC_1)));
    }

    /// The unkeyed version 1 (lab builds before A-noise-pin-3): read as no
    /// pins, left alone by `forget`, replaced by version 2 on the next record
    /// without the "unreadable" warning.
    #[test]
    fn a_v1_file_reads_as_no_pin_and_is_rewritten_as_v2() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = format!(
            r#"{{"v":1,"pins":[{{"c":"{}","d":"{}"}}]}}"#,
            hex::encode(ALICE),
            hex::encode(unkeyed(&ALICE, &STATIC_1))
        );
        std::fs::write(dir.path().join(NOISE_PIN_FILE), &v1).unwrap();
        assert_eq!(load_pin(dir.path(), &ALICE), Ok(None));
        assert_eq!(
            load_file(dir.path(), Store::Plain),
            Ok((Vec::new(), false)),
            "not corrupt"
        );
        forget(dir.path(), &ALICE).unwrap();
        assert_eq!(file_text(dir.path()), v1);
        assert_eq!(record(dir.path(), &ALICE, &STATIC_1), Ok(true));
        let value: serde_json::Value = serde_json::from_str(&file_text(dir.path())).unwrap();
        assert_eq!(value["v"], 2);
        assert_eq!(
            load_pin(dir.path(), &ALICE),
            Ok(Some(digest(&ALICE, &STATIC_1)))
        );
    }

    #[test]
    fn record_load_forget_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_pin(dir.path(), &ALICE), Ok(None), "no file");
        assert_eq!(record(dir.path(), &ALICE, &STATIC_1), Ok(true));
        assert_eq!(record(dir.path(), &BOB, &STATIC_2), Ok(true));
        assert_eq!(
            load_pin(dir.path(), &ALICE),
            Ok(Some(digest(&ALICE, &STATIC_1)))
        );
        assert_eq!(
            load_pin(dir.path(), &BOB),
            Ok(Some(digest(&BOB, &STATIC_2)))
        );
        // A new static (a rotation, or a reinstall from the same seed on
        // another key) replaces the pin.
        assert_eq!(record(dir.path(), &ALICE, &STATIC_2), Ok(true));
        assert_eq!(
            load_pin(dir.path(), &ALICE),
            Ok(Some(digest(&ALICE, &STATIC_2)))
        );
        forget(dir.path(), &ALICE).unwrap();
        assert_eq!(load_pin(dir.path(), &ALICE), Ok(None));
        assert!(load_pin(dir.path(), &BOB).unwrap().is_some(), "only Alice");
        forget(dir.path(), &ALICE).unwrap();
        // Forgetting with no file creates nothing.
        let empty = tempfile::tempdir().unwrap();
        forget(empty.path(), &ALICE).unwrap();
        assert_eq!(std::fs::read_dir(empty.path()).unwrap().count(), 0);
    }

    #[test]
    fn record_writes_only_on_change() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(record(dir.path(), &ALICE, &STATIC_1), Ok(true));
        let path = dir.path().join(NOISE_PIN_FILE);
        // A marker the next write would replace (atomic rename).
        let marker = format!("{} ", file_text(dir.path()));
        std::fs::write(&path, &marker).unwrap();
        for _ in 0..3 {
            assert_eq!(record(dir.path(), &ALICE, &STATIC_1), Ok(false));
        }
        assert_eq!(file_text(dir.path()), marker, "not rewritten");
        assert_eq!(record(dir.path(), &ALICE, &STATIC_2), Ok(true));
        assert_ne!(file_text(dir.path()), marker);
    }

    #[test]
    fn corrupt_file_reads_as_no_pin_and_is_moved_aside() {
        for corrupt in [
            "{not json",
            r#"{"v":0,"pins":[]}"#,
            r#"{"v":2,"pins":{}}"#,
            r#"[]"#,
            "",
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(NOISE_PIN_FILE), corrupt).unwrap();
            assert_eq!(load_pin(dir.path(), &ALICE), Ok(None), "{corrupt}");
            assert_eq!(pinned_count(dir.path()), Ok(0), "{corrupt}");
            forget(dir.path(), &ALICE).unwrap();
            assert_eq!(file_text(dir.path()), corrupt, "forget leaves it");
            assert_eq!(record(dir.path(), &ALICE, &STATIC_1), Ok(true));
            assert_eq!(
                load_pin(dir.path(), &ALICE),
                Ok(Some(digest(&ALICE, &STATIC_1))),
                "{corrupt}"
            );
            // E-custody-harness-docs-4: kept beside it, not overwritten.
            let aside = dir.path().join(NOISE_PIN_CORRUPT_FILE);
            assert_eq!(std::fs::read_to_string(&aside).unwrap(), corrupt);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&aside).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{mode:o}");
            }
        }
    }

    /// E-custody-harness-docs-4: one row that does not parse costs that row
    /// only; the next record keeps the others and moves the file aside
    /// first, and so does a forget.
    #[test]
    fn a_bad_row_costs_only_itself() {
        const CAROL: [u8; 32] = [0xC0; 32];
        let dir = tempfile::tempdir().unwrap();
        let text = format!(
            r#"{{"v":2,"pins":[{{"c":"{}","d":"{}"}},{{"c":"zz","d":"00"}},{{"x":1}},{{"c":"{}","d":"{}"}}]}}"#,
            hex::encode(ALICE),
            hex::encode(digest(&ALICE, &STATIC_1)),
            hex::encode(BOB),
            hex::encode(digest(&BOB, &STATIC_2))
        );
        std::fs::write(dir.path().join(NOISE_PIN_FILE), &text).unwrap();
        assert_eq!(
            load_pin(dir.path(), &ALICE),
            Ok(Some(digest(&ALICE, &STATIC_1)))
        );
        assert_eq!(
            load_pin(dir.path(), &BOB),
            Ok(Some(digest(&BOB, &STATIC_2)))
        );
        assert_eq!(pinned_count(dir.path()), Ok(2));
        // The same pin again: nothing written, nothing moved.
        assert_eq!(record(dir.path(), &ALICE, &STATIC_1), Ok(false));
        assert!(!dir.path().join(NOISE_PIN_CORRUPT_FILE).exists());
        assert_eq!(record(dir.path(), &CAROL, &STATIC_1), Ok(true));
        let aside = dir.path().join(NOISE_PIN_CORRUPT_FILE);
        assert_eq!(std::fs::read_to_string(&aside).unwrap(), text);
        let (pins, corrupt) = load_file(dir.path(), Store::Plain).unwrap();
        assert!(!corrupt);
        assert_eq!(
            pins.iter().map(|(c, _)| *c).collect::<Vec<_>>(),
            [ALICE, BOB, CAROL]
        );
        // A forget moves a partly bad file aside too.
        std::fs::remove_file(&aside).unwrap();
        std::fs::write(dir.path().join(NOISE_PIN_FILE), &text).unwrap();
        forget(dir.path(), &BOB).unwrap();
        assert_eq!(std::fs::read_to_string(&aside).unwrap(), text);
        assert_eq!(
            load_file(dir.path(), Store::Plain).unwrap(),
            (vec![(ALICE, digest(&ALICE, &STATIC_1))], false)
        );
    }

    /// E-custody-harness-docs-4: a file a newer Raven wrote (a rollback) is
    /// never read as no pins and never overwritten: the dial stops (`Err`,
    /// as an unreadable store), and the file stays as it was.
    #[test]
    fn a_newer_version_is_an_error_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let newer = format!(
            r#"{{"v":3,"pins":[{{"c":"{}","d":"{}","x":"new"}}]}}"#,
            hex::encode(ALICE),
            hex::encode(digest(&ALICE, &STATIC_1))
        );
        std::fs::write(dir.path().join(NOISE_PIN_FILE), &newer).unwrap();
        let err = load_pin(dir.path(), &ALICE).unwrap_err();
        assert!(
            err.starts_with(NOISE_PIN_FILE) && err.contains("newer"),
            "{err}"
        );
        assert!(pinned_count(dir.path()).is_err());
        assert!(record(dir.path(), &BOB, &STATIC_2).is_err());
        assert!(forget(dir.path(), &ALICE).is_err());
        assert_eq!(file_text(dir.path()), newer);
        assert!(!dir.path().join(NOISE_PIN_CORRUPT_FILE).exists());
    }

    #[test]
    fn an_unreadable_store_is_an_error_not_no_pin() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(pinned_count(dir.path()), Ok(0));
        record(dir.path(), &ALICE, &STATIC_1).unwrap();
        assert_eq!(pinned_count(dir.path()), Ok(1));
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(NOISE_PIN_FILE)).unwrap();
        let err = pinned_count(dir.path()).unwrap_err();
        assert!(err.starts_with(NOISE_PIN_FILE), "{err}");
        assert!(load_pin(dir.path(), &ALICE).is_err());
        assert!(record(dir.path(), &ALICE, &STATIC_1).is_err());
        assert!(forget(dir.path(), &ALICE).is_err());
    }

    #[test]
    fn bounded_at_max_pins_drops_the_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let key = |i: usize| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_be_bytes());
            k
        };
        let full: Pins = (0..MAX_PINS)
            .map(|i| (key(i), digest(&key(i), &STATIC_1)))
            .collect();
        save_file(dir.path(), Store::Plain, &full).unwrap();
        // A changed pin keeps its place: nothing is dropped.
        assert_eq!(record(dir.path(), &key(5), &STATIC_2), Ok(true));
        assert_eq!(
            load_file(dir.path(), Store::Plain).unwrap().0.len(),
            MAX_PINS
        );
        assert!(load_pin(dir.path(), &key(0)).unwrap().is_some());
        // A new contact: the oldest-inserted goes.
        assert_eq!(record(dir.path(), &key(MAX_PINS), &STATIC_1), Ok(true));
        let (pins, corrupt) = load_file(dir.path(), Store::Plain).unwrap();
        assert!(!corrupt);
        assert_eq!(pins.len(), MAX_PINS);
        assert_eq!(pins[0].0, key(1));
        assert_eq!(pins[MAX_PINS - 1].0, key(MAX_PINS));
        assert_eq!(load_pin(dir.path(), &key(0)), Ok(None));
        assert_eq!(
            load_pin(dir.path(), &key(5)),
            Ok(Some(digest(&key(5), &STATIC_2)))
        );
    }

    #[test]
    fn file_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), &ALICE, &STATIC_1).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(NOISE_PIN_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{mode:o}");
            let lock = std::fs::metadata(dir.path().join(NOISE_PIN_LOCK))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(lock & 0o777, 0o600, "{lock:o}");
        }
    }

    #[test]
    fn the_static_never_appears_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), &ALICE, &STATIC_1).unwrap();
        record(dir.path(), &BOB, &STATIC_2).unwrap();
        let raw = std::fs::read(dir.path().join(NOISE_PIN_FILE)).unwrap();
        let text = String::from_utf8(raw.clone()).unwrap();
        for s in [STATIC_1, STATIC_2] {
            assert!(!text.contains(&hex::encode(s)), "{text}");
            assert!(!raw.windows(32).any(|w| w == s));
        }
        // What it does hold: the contacts (already in contacts.json) and
        // their digests.
        assert!(text.contains(&hex::encode(ALICE)));
        assert!(text.contains(&hex::encode(digest(&ALICE, &STATIC_1))));
    }

    #[test]
    fn no_time_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), &ALICE, &STATIC_1).unwrap();
        record(dir.path(), &BOB, &STATIC_2).unwrap();
        let value: serde_json::Value = serde_json::from_str(&file_text(dir.path())).unwrap();
        let mut top: Vec<&String> = value.as_object().unwrap().keys().collect();
        top.sort();
        assert_eq!(top, ["pins", "v"]);
        assert_eq!(value["v"], 2);
        let pins = value["pins"].as_array().unwrap();
        assert_eq!(pins.len(), 2);
        for pin in pins {
            let fields = pin.as_object().unwrap();
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort();
            assert_eq!(keys, ["c", "d"]);
            assert!(fields
                .values()
                .all(|v| v.as_str().is_some_and(|s| s.len() == 64)));
        }
        // Insertion order, oldest first.
        assert_eq!(pins[0]["c"], hex::encode(ALICE));
    }
}
