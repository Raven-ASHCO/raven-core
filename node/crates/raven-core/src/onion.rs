//! The Tor onion carrier's identity binding and route names
//! (`protocol/RAVEN_ONION_CARRIER_V1.md` §3-§4; design
//! `docs/design/2026-10-tor-fallback.md` §3.2-§3.4).
//!
//! A node's onion service key (Arti's, kept under `<profile>/tor/`) is bound
//! to its Raven identity by an [`OnionBinding`]: the onion key, when it was
//! issued and an Ed25519 signature by the Raven identity key over both and
//! that identity key. A friend dials an onion address only with a binding
//! that verifies against that friend's pinned key ([`OnionBinding::verify`]);
//! an unsigned address, or one signed by anyone else, is never used.
//!
//! The binding is public material (it travels in cards and route hints). It
//! proves "this Raven identity runs this onion service" and nothing about
//! where either is: an onion address carries no IP.
//!
//! The onion route's dial string names the onion key, never a `.onion` text:
//! `onion:<64 lowercase hex>` ([`dial_for`], [`dial_hs_id`]). Only the Tor
//! helper turns a key into an address.

use base64::Engine as _;

use crate::identity::Identity;

/// The signing domain: the first bytes of every binding's signed message.
/// No other Raven signature starts with it (and none may look like an
/// AgentSign delegation: [`Identity::sign`]).
pub const ONION_BIND_DOMAIN: &[u8] = b"RAVEN-ONION-BIND-V1\0";

/// A binding on the wire: `hs_id[32] || issued_s u64 BE || sig[64]`.
pub const BINDING_LEN: usize = 32 + 8 + 64;

/// A binding as card text: [`BINDING_LEN`] bytes in base64url without
/// padding.
pub const BINDING_TEXT_LEN: usize = (BINDING_LEN * 4).div_ceil(3);

/// The dial string prefix of an onion route ([`dial_for`]).
pub const ONION_DIAL_PREFIX: &str = "onion:";

/// The onion service's virtual port: the one port the Tor helper accepts
/// streams on and the one an onion dial asks for. A number in the onion
/// service's own address space: nothing binds it on any computer.
pub const ONION_VIRTUAL_PORT: u16 = 7422;

/// The head start of the direct paths in the outbox's race (design §2): the
/// onion dial of an attempt starts this long after the attempt, or at once
/// when every other route already failed.
pub const ONION_HEAD_START: std::time::Duration = std::time::Duration::from_millis(1_500);

/// An onion dial's connect wait: the Tor helper's circuit to the friend's
/// onion service (descriptor, introduction, rendezvous). A first contact is
/// typically 10-30 s.
pub const ONION_CONNECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);

/// The whole onion dial: connect, the Raven handshake over Tor, the frames
/// and their receipts.
pub const ONION_DIAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(75);

/// The wait between two replies on an onion link (a Tor round trip is
/// 0.3-0.7 s; LAN and Internet direct wait 2 s).
pub const ONION_REPLY_IDLE: std::time::Duration = std::time::Duration::from_secs(5);

/// An inbound onion link's handshake deadline (Noise XX, the hellos and
/// RLB1 over a fresh circuit; LAN and Internet direct allow 10 s).
pub const ONION_HANDSHAKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Seconds a binding may be dated in the receiver's future before it is
/// refused (clock skew between friends).
pub const MAX_FUTURE_SKEW_S: u64 = 24 * 60 * 60;

/// One Raven identity's statement "my onion service key is `hs_id`, since
/// `issued_s`" ([`ONION_BIND_DOMAIN`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OnionBinding {
    /// The onion service's Ed25519 identity public key (`KP_hs_id`): the
    /// 32 bytes a `.onion` address encodes.
    pub hs_id: [u8; 32],
    /// Unix seconds when the owner signed it. A higher value replaces a
    /// lower one ([`newest`]).
    pub issued_s: u64,
    /// Ed25519 signature by the owner's Raven identity key over
    /// [`signing_input`].
    pub sig: [u8; 64],
}

impl std::fmt::Debug for OnionBinding {
    /// Never the key itself: logs and test output carry states only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionBinding")
            .field("issued_s", &self.issued_s)
            .finish_non_exhaustive()
    }
}

/// The bytes the owner signs: [`ONION_BIND_DOMAIN`] || hs_id || raven_pub ||
/// issued_s (u64 BE). The identity key is inside, so a binding cannot be
/// moved to another identity even if two identities ever shared a signature
/// scheme quirk.
pub fn signing_input(hs_id: &[u8; 32], raven_pub: &[u8; 32], issued_s: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(ONION_BIND_DOMAIN.len() + 72);
    out.extend_from_slice(ONION_BIND_DOMAIN);
    out.extend_from_slice(hs_id);
    out.extend_from_slice(raven_pub);
    out.extend_from_slice(&issued_s.to_be_bytes());
    out
}

/// Is `hs_id` a usable onion service key: a valid Ed25519 point that is not
/// of small order (an all-zero or identity point could never be a service).
pub fn hs_id_usable(hs_id: &[u8; 32]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(hs_id).is_ok_and(|k| !k.is_weak())
}

impl OnionBinding {
    /// `identity` binds `hs_id` as of `issued_s`.
    pub fn sign(identity: &Identity, hs_id: [u8; 32], issued_s: u64) -> Self {
        let msg = signing_input(&hs_id, &identity.public_key_bytes(), issued_s);
        Self {
            hs_id,
            issued_s,
            sig: identity.sign(&msg),
        }
    }

    /// Does this binding come from the Raven identity `raven_pub` (strict
    /// Ed25519, [`Identity::verify`]), name a usable onion key and is it not
    /// dated more than [`MAX_FUTURE_SKEW_S`] past `now_s`? The only test
    /// before an onion address is used or kept.
    pub fn verify(&self, raven_pub: &[u8; 32], now_s: u64) -> bool {
        hs_id_usable(&self.hs_id)
            && self.issued_s <= now_s.saturating_add(MAX_FUTURE_SKEW_S)
            && Identity::verify(
                raven_pub,
                &signing_input(&self.hs_id, raven_pub, self.issued_s),
                &self.sig,
            )
    }

    /// The wire form ([`BINDING_LEN`] bytes).
    pub fn to_bytes(&self) -> [u8; BINDING_LEN] {
        let mut out = [0u8; BINDING_LEN];
        out[..32].copy_from_slice(&self.hs_id);
        out[32..40].copy_from_slice(&self.issued_s.to_be_bytes());
        out[40..].copy_from_slice(&self.sig);
        out
    }

    /// Exactly [`BINDING_LEN`] bytes, else `None`. Structure only: whether
    /// it verifies is [`Self::verify`]'s question.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BINDING_LEN {
            return None;
        }
        Some(Self {
            hs_id: bytes[..32].try_into().ok()?,
            issued_s: u64::from_be_bytes(bytes[32..40].try_into().ok()?),
            sig: bytes[40..].try_into().ok()?,
        })
    }

    /// The card form: base64url without padding ([`BINDING_TEXT_LEN`]
    /// characters).
    pub fn to_text(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.to_bytes())
    }

    /// Strict: exactly [`BINDING_TEXT_LEN`] base64url characters without
    /// padding that decode to [`BINDING_LEN`] bytes and encode back to the
    /// same text.
    pub fn from_text(text: &str) -> Option<Self> {
        if text.len() != BINDING_TEXT_LEN
            || !text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .ok()?;
        let binding = Self::from_bytes(&bytes)?;
        (binding.to_text() == text).then_some(binding)
    }
}

/// The newer of two bindings of one identity (higher `issued_s`; on a tie
/// the first). Callers pass only bindings that verified.
pub fn newest(a: Option<OnionBinding>, b: Option<OnionBinding>) -> Option<OnionBinding> {
    match (a, b) {
        (Some(a), Some(b)) if b.issued_s > a.issued_s => Some(b),
        (Some(a), _) => Some(a),
        (None, b) => b,
    }
}

/// The onion route's dial string for the onion key `hs_id`.
pub fn dial_for(hs_id: &[u8; 32]) -> String {
    format!("{ONION_DIAL_PREFIX}{}", hex::encode(hs_id))
}

/// The onion key an onion dial string names: exactly [`ONION_DIAL_PREFIX`]
/// and 64 lowercase hex digits naming a usable key ([`hs_id_usable`]);
/// anything else is `None`.
pub fn dial_hs_id(dial: &str) -> Option<[u8; 32]> {
    let hex_part = dial.strip_prefix(ONION_DIAL_PREFIX)?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let hs_id: [u8; 32] = hex::decode(hex_part).ok()?.try_into().ok()?;
    hs_id_usable(&hs_id).then_some(hs_id)
}

/// This node's own binding, as raven-node signed it when its Tor helper
/// reported the onion key: `{"v":1,"binding":"<base64url>"}`. Plain JSON on
/// purpose: the binding is public (every card and route hint carries it) and
/// names no friend; `raven whoami --card` reads it without a running node.
pub const SELF_FILE: &str = "onion_self.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct SelfFile {
    v: u32,
    binding: String,
}

/// The saved own binding ([`SELF_FILE`]), structure checked only (callers
/// verify it against the identity); `None` when missing or unreadable.
pub fn load_own(data_dir: &std::path::Path) -> Option<OnionBinding> {
    let text = std::fs::read(data_dir.join(SELF_FILE)).ok()?;
    if text.len() > 4096 {
        return None;
    }
    let file: SelfFile = serde_json::from_slice(&text).ok()?;
    (file.v == 1)
        .then(|| OnionBinding::from_text(&file.binding))
        .flatten()
}

/// Save the own binding ([`SELF_FILE`], atomically, owner-only).
pub fn save_own(data_dir: &std::path::Path, binding: &OnionBinding) -> Result<(), String> {
    let file = SelfFile {
        v: 1,
        binding: binding.to_text(),
    };
    let json = serde_json::to_vec(&file).map_err(|e| format!("onion binding: {e}"))?;
    crate::paths::atomic_write_private(&data_dir.join(SELF_FILE), &json)
}

/// This node's own binding for a card: the saved one when it verifies
/// against `own_pub` now. Whether the carrier is live is the caller's
/// question.
pub fn own_for_card(data_dir: &std::path::Path, own_pub: &[u8; 32]) -> Option<OnionBinding> {
    load_own(data_dir).filter(|b| b.verify(own_pub, now_s()))
}

/// Keep `binding` in the contact `peer`'s book row (`onion`, a card's
/// `onion=` or a route hint's ONION entry) when it verifies against `peer`
/// and is newer than the one there (or there is none). Read and written
/// under the book's writer lock; fields this build does not know are kept.
/// `Ok(true)` when a row changed; `Ok(false)` when nothing did (no such
/// contact, an older or equal binding, or one that does not verify).
pub fn store_contact_binding(
    data_dir: &std::path::Path,
    peer: &[u8; 32],
    binding: &OnionBinding,
) -> Result<bool, String> {
    let now = now_s();
    if !binding.verify(peer, now) {
        return Ok(false);
    }
    let lock = crate::contact_book::lock(data_dir).map_err(|e| e.to_string())?;
    let Some(mut rows) = lock
        .read_rows::<serde_json::Value>()
        .map_err(|e| e.to_string())?
    else {
        return Ok(false);
    };
    let key = hex::encode(peer);
    let mut changed = false;
    for row in rows.iter_mut().filter(|r| {
        r.get("pub_hex")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|h| h.trim().eq_ignore_ascii_case(&key))
    }) {
        let held = row
            .get("onion")
            .and_then(serde_json::Value::as_str)
            .and_then(|t| OnionBinding::from_text(t.trim()))
            .filter(|b| b.verify(peer, now));
        if held.is_none_or(|h| binding.issued_s > h.issued_s) {
            if let Some(obj) = row.as_object_mut() {
                obj.insert("onion".into(), binding.to_text().into());
                changed = true;
            }
        }
    }
    if changed {
        lock.write_rows(&rows).map_err(|e| e.to_string())?;
    }
    Ok(changed)
}

/// Unix seconds now, by Raven's wall clock ([`crate::clock::now_ms`]).
pub fn now_s() -> u64 {
    crate::clock::now_ms() / 1000
}

/// Whether raven-node's Tor status line (IPC `Status.tor`, raven-node
/// `onion::status_line`) says Tor is ready and this computer's onion
/// service is reachable: `Tor: ready`, or `Tor: ready (onion service
/// outages since start: ...)`; not while the service is publishing or
/// unreachable, nor in any other state. (`raven status` reads it, E2 r38.)
pub fn status_line_says_reachable(line: &str) -> bool {
    let line = line.trim();
    line.strip_prefix("Tor: ready")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(" (onion service outages"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ready_tor_with_a_reachable_service_reads_as_reachable() {
        for line in [
            "Tor: ready",
            "Tor: ready (onion service outages since start: 1, the last lasted 16 min and ended \
             25 min ago)",
        ] {
            assert!(status_line_says_reachable(line), "{line}");
        }
        for line in [
            "Tor: ready (onion service publishing)",
            "Tor: ready, onion service unreachable for 12 min",
            "Tor: starting (45 %)",
            "Tor: blocked on this network",
            "Tor: off",
            "",
        ] {
            assert!(!status_line_says_reachable(line), "{line}");
        }
    }

    fn alice() -> Identity {
        Identity::from_seed(&[7u8; 32])
    }

    fn bob() -> Identity {
        Identity::from_seed(&[9u8; 32])
    }

    /// A usable onion key (any Ed25519 public key is one).
    fn hs(seed: u8) -> [u8; 32] {
        Identity::from_seed(&[seed; 32]).public_key_bytes()
    }

    const NOW: u64 = 1_790_000_000;

    #[test]
    fn a_signed_binding_verifies_against_its_owner_only() {
        let b = OnionBinding::sign(&alice(), hs(1), NOW);
        assert!(b.verify(&alice().public_key_bytes(), NOW));
        // Never against another identity: an address signed by someone
        // else is not this friend's.
        assert!(!b.verify(&bob().public_key_bytes(), NOW));
    }

    #[test]
    fn a_tampered_or_unsigned_binding_never_verifies() {
        let owner = alice().public_key_bytes();
        let good = OnionBinding::sign(&alice(), hs(1), NOW);
        let mut other_key = good;
        other_key.hs_id = hs(2);
        assert!(!other_key.verify(&owner, NOW), "the address was swapped");
        let mut older = good;
        older.issued_s -= 1;
        assert!(!older.verify(&owner, NOW), "the date was changed");
        let mut sig = good;
        sig.sig[0] ^= 1;
        assert!(!sig.verify(&owner, NOW), "the signature was changed");
        let unsigned = OnionBinding {
            sig: [0; 64],
            ..good
        };
        assert!(!unsigned.verify(&owner, NOW), "an unsigned address");
    }

    #[test]
    fn an_unusable_onion_key_never_verifies_even_when_signed() {
        let owner = alice();
        for hs_id in [[0u8; 32], {
            // The Ed25519 identity point (small order).
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        }] {
            let b = OnionBinding::sign(&owner, hs_id, NOW);
            assert!(!b.verify(&owner.public_key_bytes(), NOW));
            assert!(dial_hs_id(&dial_for(&hs_id)).is_none());
        }
    }

    #[test]
    fn a_binding_dated_too_far_ahead_is_refused() {
        let owner = alice();
        let ahead = OnionBinding::sign(&owner, hs(1), NOW + MAX_FUTURE_SKEW_S + 1);
        assert!(!ahead.verify(&owner.public_key_bytes(), NOW));
        let skewed = OnionBinding::sign(&owner, hs(1), NOW + MAX_FUTURE_SKEW_S);
        assert!(skewed.verify(&owner.public_key_bytes(), NOW));
    }

    #[test]
    fn wire_and_text_forms_round_trip_strictly() {
        let b = OnionBinding::sign(&alice(), hs(1), NOW);
        let bytes = b.to_bytes();
        assert_eq!(bytes.len(), BINDING_LEN);
        assert_eq!(OnionBinding::from_bytes(&bytes), Some(b));
        assert!(OnionBinding::from_bytes(&bytes[..BINDING_LEN - 1]).is_none());
        assert!(OnionBinding::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_none());
        let text = b.to_text();
        assert_eq!(text.len(), BINDING_TEXT_LEN);
        assert_eq!(OnionBinding::from_text(&text), Some(b));
        // Padding, the standard alphabet, spaces and a short text are refused.
        assert!(OnionBinding::from_text(&format!("{text}=")).is_none());
        let mut standard = text.clone();
        standard.replace_range(0..1, "+");
        assert!(OnionBinding::from_text(&standard).is_none());
        assert!(OnionBinding::from_text(&text[1..]).is_none());
        assert!(OnionBinding::from_text(&format!(" {}", &text[1..])).is_none());
    }

    #[test]
    fn the_newest_binding_wins_and_an_older_one_never_replaces_it() {
        let old = OnionBinding::sign(&alice(), hs(1), NOW);
        let new = OnionBinding::sign(&alice(), hs(2), NOW + 60);
        assert_eq!(newest(Some(old), Some(new)), Some(new));
        assert_eq!(newest(Some(new), Some(old)), Some(new));
        assert_eq!(newest(None, Some(old)), Some(old));
        assert_eq!(newest(Some(old), None), Some(old));
        assert_eq!(newest(None, None), None);
    }

    #[test]
    fn dial_strings_are_strict() {
        let key = hs(3);
        let dial = dial_for(&key);
        assert!(dial.starts_with("onion:"));
        assert_eq!(dial_hs_id(&dial), Some(key));
        assert!(dial_hs_id(&dial.to_uppercase()).is_none());
        assert!(dial_hs_id(&dial.replace("onion:", "nearby:")).is_none());
        assert!(dial_hs_id(&format!("{dial}0")).is_none());
        assert!(dial_hs_id(&format!(" {dial}")).is_none());
        assert!(dial_hs_id("onion:xyz.onion").is_none());
    }

    #[test]
    fn debug_output_never_shows_the_onion_key() {
        let b = OnionBinding::sign(&alice(), hs(1), NOW);
        let text = format!("{b:?}");
        assert!(!text.contains(&hex::encode(b.hs_id)), "{text}");
        assert!(!text.contains(&hex::encode(&b.hs_id[..4])), "{text}");
    }

    #[test]
    fn the_own_binding_round_trips_through_its_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_own(dir.path()).is_none());
        let owner = alice();
        let b = OnionBinding::sign(&owner, hs(1), now_s());
        save_own(dir.path(), &b).unwrap();
        assert_eq!(load_own(dir.path()), Some(b));
        assert_eq!(own_for_card(dir.path(), &owner.public_key_bytes()), Some(b));
        // Never another identity's.
        assert_eq!(own_for_card(dir.path(), &bob().public_key_bytes()), None);
        std::fs::write(dir.path().join(SELF_FILE), b"{not json").unwrap();
        assert!(load_own(dir.path()).is_none());
    }

    /// A card's or a route hint's binding goes into the contact's row only
    /// when the contact's key signed it and it is newer; other fields stay.
    #[test]
    fn contact_rows_keep_the_newest_signed_binding() {
        let dir = tempfile::tempdir().unwrap();
        let bob = bob();
        let peer = bob.public_key_bytes();
        std::fs::write(
            dir.path().join(crate::contact_book::CONTACTS_FILE),
            format!(
                r#"[{{"petname":"Bob","pub_hex":"{}","pinned":true,"lan_dial":"","future_field":7}}]"#,
                hex::encode(peer)
            ),
        )
        .unwrap();
        let row = || -> serde_json::Value {
            crate::contact_book::read_rows::<serde_json::Value>(dir.path())
                .unwrap()
                .unwrap()
                .remove(0)
        };
        let now = now_s();
        let first = OnionBinding::sign(&bob, hs(1), now);
        assert!(store_contact_binding(dir.path(), &peer, &first).unwrap());
        assert_eq!(row()["onion"], first.to_text());
        assert_eq!(row()["future_field"], 7, "unknown fields are kept");
        // Equal or older: nothing changes.
        assert!(!store_contact_binding(dir.path(), &peer, &first).unwrap());
        let older = OnionBinding::sign(&bob, hs(2), now - 10);
        assert!(!store_contact_binding(dir.path(), &peer, &older).unwrap());
        // Signed by someone else: never.
        let foreign = OnionBinding::sign(&alice(), hs(3), now + 10);
        assert!(!store_contact_binding(dir.path(), &peer, &foreign).unwrap());
        assert_eq!(row()["onion"], first.to_text());
        // Newer: replaces.
        let newer = OnionBinding::sign(&bob, hs(4), now + 10);
        assert!(store_contact_binding(dir.path(), &peer, &newer).unwrap());
        assert_eq!(row()["onion"], newer.to_text());
        // No such contact: nothing.
        let carol = Identity::from_seed(&[3; 32]);
        let theirs = OnionBinding::sign(&carol, hs(5), now);
        assert!(!store_contact_binding(dir.path(), &carol.public_key_bytes(), &theirs).unwrap());
    }

    /// `shared-vectors/rvn1/onion/binding_001.json` (spec §11): written only
    /// under `RAVEN_REGEN_SECURITY_VECTORS=1`, checked always.
    #[test]
    fn binding_vector() {
        const ALICE: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        const BOB_PUB: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        const ISSUED: u64 = 1_792_756_800;
        let alice = Identity::from_seed(&hex::decode(ALICE).unwrap().try_into().unwrap());
        let hs_id: [u8; 32] = hex::decode(BOB_PUB).unwrap().try_into().unwrap();
        let b = OnionBinding::sign(&alice, hs_id, ISSUED);
        assert!(b.verify(&alice.public_key_bytes(), ISSUED));
        let expected = serde_json::json!({
            "description": "RAVEN_ONION_CARRIER_V1 §3: the onion binding. signing_input = \
                'RAVEN-ONION-BIND-V1' || 0x00 || hs_id[32] || raven_pub[32] || issued_s u64 BE; \
                binding = hs_id[32] || issued_s u64 BE || Ed25519 signature by the Raven identity \
                over signing_input (104 bytes); card text = base64url without padding. The \
                identity is RFC 8032 test 1 (alice); the onion key is RFC 8032 test 2's public key",
            "deterministic": true,
            "inputs": {
                "raven_seed_hex": ALICE,
                "hs_id_hex": BOB_PUB,
                "issued_s": ISSUED,
            },
            "expected": {
                "raven_pub_hex": hex::encode(alice.public_key_bytes()),
                "signing_input_hex": hex::encode(signing_input(
                    &hs_id,
                    &alice.public_key_bytes(),
                    ISSUED
                )),
                "binding_hex": hex::encode(b.to_bytes()),
                "card_text": b.to_text(),
                "dial": dial_for(&hs_id),
            },
        });
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..3 {
            path.pop();
        }
        let path = path.join("shared-vectors/rvn1/onion/binding_001.json");
        if std::env::var("RAVEN_REGEN_SECURITY_VECTORS").as_deref() == Ok("1") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&expected).unwrap() + "\n",
            )
            .unwrap();
        }
        let stored: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display())),
        )
        .unwrap();
        assert_eq!(stored, expected);
    }

    /// `shared-vectors/rvn1/onion/noise_static_001.json` (spec §5.1, §11):
    /// the onion link's own Noise static, written only under
    /// `RAVEN_REGEN_SECURITY_VECTORS=1`, checked always.
    #[test]
    fn onion_noise_static_vector() {
        use crate::lan_noise::{
            derive_noise_static, derive_onion_noise_static, noise_static_public, HKDF_INFO,
            ONION_HKDF_SALT,
        };
        const ALICE: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let alice = Identity::from_seed(&hex::decode(ALICE).unwrap().try_into().unwrap());
        let onion = noise_static_public(&derive_onion_noise_static(&alice).unwrap());
        let device = noise_static_public(&derive_noise_static(&alice).unwrap());
        assert_ne!(onion, device);
        let expected = serde_json::json!({
            "description": "RAVEN_ONION_CARRIER_V1 §5.1: the onion link's Noise static. \
                onion_static = HKDF-SHA256(salt = 'rvn1/onion-noise/v1', IKM = identity seed, \
                info = 'static-x25519', 32 bytes) as an X25519 private key; never the device \
                static of rvn1/lan/noise_static_001.json (same seed, other salt). The identity \
                is RFC 8032 test 1 (alice)",
            "deterministic": true,
            "name": "Onion link Noise static X25519 derive",
            "protocol_version": "rvn1",
            "inputs": {
                "device_seed_hex": ALICE,
                "hkdf_salt": std::str::from_utf8(ONION_HKDF_SALT).unwrap(),
                "hkdf_info": std::str::from_utf8(HKDF_INFO).unwrap(),
            },
            "expected": {
                "onion_static_pub_hex": hex::encode(onion),
                "device_static_pub_hex": hex::encode(device),
            },
        });
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..3 {
            path.pop();
        }
        let path = path.join("shared-vectors/rvn1/onion/noise_static_001.json");
        if std::env::var("RAVEN_REGEN_SECURITY_VECTORS").as_deref() == Ok("1") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&expected).unwrap() + "\n",
            )
            .unwrap();
        }
        let stored: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display())),
        )
        .unwrap();
        assert_eq!(stored, expected);
    }

    #[test]
    fn the_signing_domain_is_not_an_agent_delegation() {
        assert!(!ONION_BIND_DOMAIN.starts_with(&crate::agent_sign::AGENT_DELEGATION_PREFIX[..2]));
    }
}
