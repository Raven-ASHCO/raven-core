# RAVEN Async Letter V1 (RAL1)

**Version:** 1 (`RAL1`, version byte `1`)
**Status:** Draft; **production disabled** (`ASYNC_LETTER_PRODUCTION_ENABLED = false`,
which also needs `LONG_HORIZON_PRODUCTION_ENABLED` and the friend custody gates). Lab
only: debug builds with `RAVEN_LAB_TEST_A=1`, `RAVEN_LAB_HORIZON=1`,
`RAVEN_LAB_LETTER=1` and the friend custody lab gate (see
`raven_core::horizon::letter_live_enabled`). Release builds ignore the switches.
**Audience:** re-implementers of the sealer's outbox, the custodian and the
recipient's letter intake.
**Reference code:** `raven_core::async_letter` (Rust),
`protocol/reference/raven_protocol/async_letter.py` (Python).

---

## 1. Purpose

A message to a contact who stays offline for longer than a 24 h session used to
expire unread. A letter lets the sender leave, with a friend both contacts trust
(a custodian, RFC1), everything the contact needs to read the messages later:
a PairInit V1 for a new session of up to 7 days and the first messages of that
session, sealed in it. When the contact comes back it fetches the letter,
accepts the PairInit, accepts the messages, and answers with a REPLY letter
carrying the PairResponse and the ACKs.

RAL1 adds an outer wrapper only. It changes nothing in `RavenEnvelopeV1`, the
indexed-session sealing, PairInit V1 / PairResponse V1 or the prekey bundle:
the carried bytes are exactly what a direct link would carry.

## 2. Where RAL1 may appear

- A letter travels only inside the RFC1 letter custody ops of the RFC1 op
  registry ([`RAVEN_FRIEND_CUSTODY_V1.md`](RAVEN_FRIEND_CUSTODY_V1.md) §10:
  0x04 DEPOSIT_LETTER, 0x05 FETCH_LETTERS, 0x06 WITHDRAW_LETTERS; replies
  0x85 LETTER_ITEM, 0x86 WITHDRAW_RESULT). A custodian admits a letter by its
  header alone (RFC1 §10.2) and never opens it; a listener without the
  letter ops answers them `UNSUPPORTED`.
- A letter is **never** an RVN1 envelope and is never sent on a direct link as
  a frame. Custody admission of RVN1 objects (`carrier_admission`) refuses it
  (it is not RVN1).
- The same letter bytes go to every custodian the sender uses.

## 3. Wire format

Integers are big-endian.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `RAL1` |
| 4 | 1 | version = 1 |
| 5 | 1 | kind: 1 LETTER (initiator to responder), 2 REPLY (responder to initiator) |
| 6 | 2 | flags = 0 |
| 8 | 16 | `letter_id` (random, non-zero) |
| 24 | 32 | `sender_device` (Ed25519 device key; signs the letter) |
| 56 | 32 | `recipient_device` |
| 88 | 8 | `created_at_ms` |
| 96 | 8 | `expires_at_ms` |
| 104 | 32 | `wrap_bundle_hash` = `prekey_bundle_hash` (domain `rvn1/pair-prekey`, [`RAVEN_PAIR_INIT_V1.md`](RAVEN_PAIR_INIT_V1.md)) of the recipient bundle used |
| 136 | 32 | `wrap_ephemeral` (X25519 public key `E_w`) |
| 168 | 12 | `wrap_nonce` |
| 180 | 4 | `ct_len` = `inner_len + 16` |

Then `ciphertext` (`ct_len` bytes), then `signature` (64 bytes):

```
signature = Ed25519(sender_device, "rvn1/async-letter/v1\0" || bytes[0 .. 184 + ct_len])
```

- Total length = 248 + `ct_len` = 264 + `inner_len`. `inner_len` is a multiple of
  512, at least 512 and at most `MAX_RAL1_INNER` = 65,024, so
  `MIN_RAL1_LEN` = 776 (a REPLY with no ACKs) and `MAX_RAL1_LEN` = 65,288 (fits
  one RFC1 frame).
- Strict decode (step 1 of §6) also requires: `letter_id`, both devices and
  `wrap_bundle_hash` not all-zero; `sender_device` != `recipient_device`;
  `expires_at_ms` > `created_at_ms`; `wrap_ephemeral` contributory (not
  all-zero and not any other small-order point; such a key makes every wrap DH
  all-zero); no trailing bytes.
- `letter_digest` = SHA-256(letter): custody dedup, RELEASE and WITHDRAW name a
  letter by it.
- `page_token` = SHA-256(`raven/custody-letter/page-token/v1` || letter): the
  custodian's fetch order.
- The signing domain `rvn1/async-letter/v1\0` is not a prefix of any other
  Raven domain and no other domain is a prefix of it (the NUL makes it so).

## 4. Key schedule

```
dh         = X25519(e_w, spk_R) = X25519(spk_R_secret, E_w)      all-zero => reject
salt       = SHA-256("rvn1/async-letter/v1/salt" || wrap_bundle_hash)
okm        = HKDF-SHA256(IKM = dh, salt, info = "rvn1/async-letter/v1/wrap" || 0x00 || header[0..168], L = 64)
K_wrap     = okm[0..32]
K_nonce    = okm[32..64]
wrap_nonce = HMAC-SHA256(K_nonce, "rvn1/async-letter/v1/nonce" || 0x00 || inner)[0..12]
ciphertext = ChaCha20-Poly1305(K_wrap, wrap_nonce, AAD = header[0..184], inner)
```

- `spk_R` is the recipient's signed X25519 prekey (`x25519_pub`) of the bundle
  named by `wrap_bundle_hash`. A REPLY is wrapped to one of the letter
  initiator's own bundles. Letters never use one-time prekeys.
- `header[0..168]` is everything before `wrap_nonce`, so the keys are bound to
  the kind, the ids, both devices, the times, the bundle and `E_w`; the AEAD
  binds the whole header.
- The nonce is the sender rule: it is derived from the plaintext, so a replayed
  random generator (the same `e_w` and header) never reuses a nonce for a
  different inner. Receivers use `wrap_nonce` as sent.

## 5. Inner formats

Kind 1, LETTER:

```
u8  inner_version = 1
u8  pair_kind = 1                       PairInit V1
u16 pair_len = 2788
    PairInit V1 wire (the exact signed bytes)
u8  count                               1..=16
    count x { u32 env_len (86..=65,024) || packed RVN1 Message }
u16 pad_len
    pad_len x 0x00
```

Kind 2, REPLY:

```
u8  inner_version = 1
u8  pair_kind = 2                       PairResponse V1
u16 pair_len = 228
    PairResponse V1 wire
u8  count                               0..=32
    count x { u32 len (86..=65,024) || packed RVN1 Ack }
u16 pad_len
    pad_len x 0x00
```

- A carried LETTER envelope is a strict `RavenEnvelopeV1` with `env_type` 1,
  `flags` 0, an empty ratchet header and a body that is a sealed RVNA1 `0x03`
  indexed-session message (`RVNA1\0\0\0 || 0x03 || 0x01 || ...`, at least 42
  bytes) of the session the PairInit opens, direction 0 (initiator to
  responder). A REPLY ACK is `env_type` 2 with a body of exactly one sealed
  indexed ACK (143 bytes) of the same session, direction 1.
- `pad_len` is the smallest value that makes the inner length a multiple of 512
  (so `pad_len` < 512); every pad byte is zero; nothing follows the padding.
- `pair_kind` 3 is reserved for PairInit V3. Any `pair_kind` other than the one
  of the letter's kind is refused.

## 6. Recipient verification order

The recipient runs these steps in order and stops at the first refusal. Every
refusal has a stable code (`RAVEN_ERROR_CODES_V1.md` rules: ASCII, no secrets).

| Step | Check | Refusal |
|---:|---|---|
| 1 | Strict decode (§3): magic, version, kind, flags, the field rules, `ct_len`, exact length | `LETTER_MALFORMED` |
| 2 | `recipient_device` is this device | `LETTER_WRONG_RECIPIENT` |
| 3 | `now < expires_at` | `LETTER_EXPIRED` |
| 3 | `created_at <= now + 5 min` and `expires_at - created_at <= 7 d` | `LETTER_TIME` |
| 4 | `sender_device` is a pinned, unblocked contact | `LETTER_NOT_CONTACT` |
| 5 | The signature verifies (strict Ed25519) | `LETTER_BAD_SIGNATURE` |
| 6 | `wrap_bundle_hash` names a retained local generation with `now <= destroy_after` (kind 2: one of our own bundles) | `LETTER_UNKNOWN_PREKEY` |
| 7 | The AEAD opens | `LETTER_UNWRAP` |
| 8 | Strict inner decode (§5): `pair_kind` matches the kind, the pair bytes decode, counts and lengths in range, every item has the carried shape, minimal all-zero padding | `LETTER_INNER` |
| 9 | Bindings (below) | `LETTER_BINDING` |
| 10 | Accept the PairInit, then the envelopes (kind 2: confirm the session, then the ACKs) | `LETTER_PAIR_REFUSED`, `LETTER_CLAIM_LIMIT`, `LETTER_STORE` |
| 11 | RELEASE the letter at the custodian, only after commit | |

The signature (step 5) is checked before any secret is used (step 6).

Bindings for kind 1 (step 9):

- PairInit `initiator_device` = `sender_device`;
- PairInit `responder_device` = `recipient_device`;
- PairInit `responder_prekey_bundle_hash` = `wrap_bundle_hash`;
- PairInit `one_time_prekey_id` = 0;
- PairInit `created_at` <= letter `created_at` and letter `expires_at` <= PairInit `expires_at`;
- `E_w` != the PairInit's initiator ephemeral key;
- every envelope is signed by `sender_device`, expires no later than the letter,
  and carries the route tag of its index, type and `created_at` in direction 0
  of the PairInit's session (checked once the session root is derived).

Bindings for kind 2: PairResponse `responder_device` = `sender_device`; every
ACK is signed by `sender_device` and carries the route tag of direction 1;
`init_id` names a provisional letter session of ours (initiator role) with
that peer.

What happens to the custodian's copy:

| Code | Custodian copy |
|---|---|
| `LETTER_MALFORMED` .. `LETTER_BINDING`, `LETTER_PAIR_REFUSED`, `LETTER_GATE` (this node's letter gate is closed) | released: the letter can never succeed |
| `LETTER_CLAIM_LIMIT`, `LETTER_STORE` | kept: a later fetch may succeed |

`LETTER_TOO_LARGE` and `LETTER_SEAL` are the sender's own refusals (an inner
over the cap; a letter that cannot be sealed); they never reach a custodian.

## 7. Sender rules

- The letter gate is on and the recipient is a pinned contact.
- A cached recipient bundle valid for at least 24 h more.
- The PairInit V1 uses the signed prekey only (`one_time_prekey_id` 0, slot
  all-zero); its lifetime is min(7 d, bundle expiry, both certificates'
  `not_after`) and at least 24 h.
- At most 1 new letter session per peer per day; a session is reused while it
  has at least 24 h left and indices below 16.
- Letter `expires_at` = the latest `expires_at` of the envelopes it carries
  (each min(session end, its message's deadline)), so every envelope expires
  no later than the letter (§6 step 9); a letter never lives longer than 7
  days.
- At most 16 envelopes per letter and at most `MAX_RAL1_LEN` bytes.
- A fresh random `e_w` and `letter_id` per letter.

## 8. Letter sessions

- ACK-only at both ends; never a target for new chat.
- The responder treats any peer-initiated session with
  `expires_at - created_at > 24 h` as letter-class.
- The initiator may seal indices 0-15 while the session is provisional
  ([`ATSAM_ENDPOINT_TRANSACTION_V1.md`](ATSAM_ENDPOINT_TRANSACTION_V1.md) §4.1
  addendum); ACKs still need confirmation.
- A responder's ACK envelopes in a letter-class session may stay valid until
  the session ends (up to 7 d) instead of 24 h.
- The responder's PairResponse to a letter's PairInit is valid until the
  PairInit's `expires_at_ms` (a direct link's for at most 24 h), so a REPLY
  fetched days later still confirms the session
  ([`RAVEN_PAIR_INIT_V1.md`](RAVEN_PAIR_INIT_V1.md) §4, letter sessions).
- The initiator closes the session early once all its messages are settled.
- Direct completion: an initiator that reaches the recipient directly while
  the session is provisional replays the exact PairInit (RAVEN_PAIR_INIT_V1
  §6). A responder answers an exact replay of a PairInit it accepted from a
  letter with the PairResponse it keeps for the REPLY (the same bytes in a
  fresh out-of-band wrapper), also after its short-lived link cache is gone.
  An initiator that gets no PairResponse gives the letter session up,
  withdraws its letters and seals the messages again into a fresh session.

## 9. Compatibility

| Peer | Behaviour |
|---|---|
| A custodian without the letter ops (older build, or its letter gate closed) | Answers `UNSUPPORTED`; the sender caches that for 24 h, moves no message and uses the base RFC1 deposit of the direct copy. |
| A recipient without RAL1 | Never fetches letters; they expire at the custodian. Delivery then happens when both are online: the letter session is completed directly (a responder accepts PairInits of up to 7 d), or the messages are re-sealed into a 24 h session. |
| Older senders and custodians | Unchanged. |

## 10. Security considerations

- **Two layers.** The carried messages are sealed under the session's hybrid
  root (X25519 + ML-KEM-768, PairInit V1), exactly as on a direct link. The
  RAL1 wrap is classical X25519 to the signed prekey: it hides the PairInit
  (addresses, trust hashes) and the envelope headers from the custodian. A
  future quantum adversary that records a letter may open the wrap, not the
  messages.
- **Forward secrecy window.** Letters use no one-time prekey. The PairInit's
  secrecy rests on the signed prekey generation (and its ML-KEM key) until that
  generation's `destroy_after`; the wrap rests on the same signed prekey.
  Letter messages are chain indices 0-15 of a provisional session.
- **What the custodian learns.** The header: both devices, the times, the
  bundle hash and the size rounded to 512 bytes. A custodian is a friend of
  both contacts, as in RFC1.
- **Replay.** Intake is idempotent: a re-fetched letter replays a PairInit the
  responder already claimed (the cached PairResponse) and envelopes it already
  accepted. Custodians dedup by `letter_digest`; letters expire within 7 days.
- **Prekey and claim budget.** Every letter PairInit is a claim on the signed
  prekey; the responder accepts at most 8 live letter claims per initiator
  (`LETTER_CLAIM_LIMIT` keeps the letter), and senders open at most one letter
  session per peer per day.
- **Order.** The signature is checked before the prekey is used, so only a
  letter signed by a contact's device makes the recipient compute a DH with its
  signed prekey. `E_w` is checked structurally at step 1, so a small-order key
  never reaches the DH.

## 11. Vectors

Rust generates the vectors (`RAVEN_REGEN_LETTER_VECTORS=1`,
`raven_core::async_letter` tests); the Python reference recomputes every byte
(`protocol/reference/tests/test_async_letter.py`).

| File | Content |
|---|---|
| `shared-vectors/rvn1/letter/ral1_wrap_kdf_001.json` | The key schedule alone: DH, salt, info, OKM, `K_wrap`, `K_nonce`, two nonces for inners one bit apart |
| `shared-vectors/rvn1/letter/ral1_letter_001.json` | A LETTER: the PairInit of `atsam/pair_init_v1_001.json` reshaped for a letter (signed prekey only, 7 d, re-signed), its provisional root, two RVNA1 `0x03` messages (indices 0 and 1), the inner, the sealed letter |
| `shared-vectors/rvn1/letter/ral1_reply_001.json` | The REPLY: that session's PairResponse and one sealed ACK |
| `shared-vectors/rvn1/letter/negative/ral1_negatives_001.json` | One letter per check of §6 steps 1-9 with its code: bad magic, version 2, kind 3, flags, `ct_len` / trailing / truncated, oversize, zero `letter_id`, small-order `E_w`, wrong recipient, expired, lifetime over 7 d, future-dated, not a contact, bad signature, unknown prekey, header tamper (AEAD), ciphertext tamper, non-zero padding, padding not minimal, count 0 and 17, an ACK in a LETTER, a non-`0x03` envelope, reserved `pair_kind` 3, signer differs from the PairInit initiator, bundle hash mismatch, one-time prekey non-zero, `E_w` equal to the PairInit ephemeral, letter starting before the PairInit, envelope outliving the letter, envelope signer mismatch, REPLY with `pair_kind` 1, REPLY from another responder |
