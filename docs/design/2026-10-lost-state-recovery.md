# Automatic recovery when a contact lost its Raven session or prekey state (revision 2)

**Status:** design for implementation. Nothing here is in force until it is implemented and its gate (§18) is flipped.

**Scope:** the contact kept its identity seed. On LAN direct, the device key equals the identity key (`lan_dispatch::verify_lan_bundle`, `lan_dispatch.rs:89-94`). The contact lost some or all of the following:
- sessions;
- prekey state;
- the device registry and the device X25519 files, so it holds a **new device certificate for the same key**;
- its outbox, stage and history.

The causes covered are a reinstall with the same seed, a partial wipe, and a restore from an older backup.

**Code read:**
- the Raven tree of that date: the staged `feature/reliability-and-mesh` branch, plus the untracked `scripts/lan_fault_matrix.py`.
- the RDAP tree of that date.

---

## 0. What changed from revision 1, and why

| Critique issue | Verdict (code evidence) | Resolution | § |
|---|---|---|---|
| A reinstall with a fresh data dir re-issues the device cert, so no envelope ever reaches B (C1-M1, C2-B1) | **Correct.** `ensure_local_device_certificate` re-issues the cert with a new `device_x25519` key when the registry and X files are missing (`device_cert.rs:282-375`). ash compares the **presented** cert against the session digest and stops with "nothing was sent" (`pair_init_lab.rs:1033-1052`, `:1113`). The worker holds `NO_PEER_CERT` (`raven-node/src/outbox.rs:1617-1621`). B cannot use the session either: `validate_outbound_session_and_signer` requires the local cert digest bound into the session (`indexed_session_store.rs:4526-4536`). | New evidence **E2, PeerCertRenewed**. A verified, non-revoked cert for the same key with a different hash retires every session bound to another cert. It needs no wire change. New harness scenario s05d. | §5.2 |
| A seed-only attacker can make A re-encrypt the queued plaintext (C1-M2) | **Correct.** Today a seed thief already receives all *future* messages: it can PairInit, the pin accepts a higher id, and `ash send` uses the newest session. The undelivered backlog is the only new exposure. | Automatic re-seal goes **only into a session we initiated ourselves over a local-network route** (policy P2). Otherwise the rows are held as `PEER_RESET_CONFIRM` until the user runs one `raven outbox resend`. A visible notice follows every re-seal. The residual risk goes to the owner in the waiver amendment. | §3 I3, §9.1 |
| An identity fork becomes silent ping-pong (C1-M3) | Correct. | Fork evidence FE1 is recorded: a fresh inbound object under a session the peer signed it no longer has. On FE1, plus a cap of 3 automatic rounds per day, automatic handling stops and a prominent warning is shown. | §9.1, §10 |
| Forced renewals use up generation slots (C1-M4) | **Correct.** `MAX_PREKEY_GENERATIONS = 4` (`prekey_lifecycle.rs:46`). `local_bundle` → `ensure_local_prekey` → `rotate_generation`: any failure kills every LAN link (`lan_dispatch.rs:695-704`, `raven-node/src/lan_direct.rs:319`). | Renewal is allowed only with 2 free slots after pruning. `ensure_local_prekey` keeps serving a still-valid bundle when rotation fails (phase 1). | §4.3, §14.4 |
| The 6 h renewal cap blocks restore and s16 (C1-M5, C2-M4) | Correct. | The age cap is removed. Renewal is idempotent by proof: after renewal the current bundle beats the pinned one, so the same proof is a no-op. Headroom bounds slot use. | §14.4 |
| `abandon_undelivered_outbound` deletes the outstanding row, so late ACKs fail and the per-message cap is dead code (C1-m, C2-M2) | **Correct.** See `indexed_session_store.rs:3180-3198` and `:4097-4103`. | New `retire_outbound_copy`: it deletes only the outbox row and keeps the outstanding row. A persisted `endpoint_reseal_ledger` counts re-seals. The caps are consistent (round cap ≤ message cap). | §9.4, §10 |
| The worker plans with `offered=None` and PairInits to a pinned prekey the peer no longer has (C2-M3) | **Correct.** `load_cached_peer_bundle` returns the *pinned* prekey (`lan_dispatch.rs:1666-1695`). | The reset step always plans from the offer returned by its own probe (replies[0], re-verified and bound to the peer). | §9.3 |
| ash is integrated only through "restart after reply" (C2-M5) | Correct. | ash gets a reset pre-pass on every reachable send. The earlier-rows loop skips rows in retired sessions. The PairInit branch goes through the planner. `SessionRetired` is mapped to a restart. | §11 |
| Inline RSR1 replies are a regression against old senders (C2-M6) | **Correct.** Old A would get `Ok([offer, rsr1])` (`main.rs:683-688`) and record `Sent{NO_ACK_YET}`, which resets refusals (`raven-node/src/outbox.rs:991-994`). SUPERSEDED would then never fire, and ash would stop at `pair_init_lab.rs:1410`. | **Inline replies are removed.** B keeps closing exactly as today. Only a new sender asks, in a dedicated SESSION_QUERY dial. | §6-§8 |
| The worker bookkeeping cannot represent re-seals (C2-M7) | Correct (`outbox.rs:299`, `:885-930`, `:1464`). | New `Outcome::Resealed` (never "finished", never clears routes, triggers a rescan). New `PEER_RESET` arm with an immediate retry, at most once in a row. Status already prefers the live entry. | §12 |
| The debug hooks do not exist (C2-M8) | Correct. | No runtime clock or crash hooks. The crash and clock scenarios run in process with `#[cfg(test)]` faults. The only lab switch is `RAVEN_LAB_SESSION_RESET`, which works only under `cfg!(debug_assertions)`, and a test runs in release. | §18, §21 |
| Minor issues | All checked. | One-line resolutions are in §0.1. | |

### 0.1 Minor items

- **Dead twins and `NO_SESSION` ambiguity.** The re-seal target must be our own local-initiated session, newer than the retired one. A peer-initiated twin is never a target (§9.2).
- **Linkability.** Every `OutboxCarrier` is endpoint-confidential today (`raven-core/src/outbox.rs:479-483`), so there is no custody exposure. Re-sealed copies are additionally filtered to carriers that are confidential to the endpoint, and §19 requires an inner logical id before any custody carrier exists.
- **Version verdict from one close.** The "old build" memo is gone. A close is transient and backs off. The subject always answers PREKEY_STALE with a signed PREKEY_STATUS (§14.3).
- **RLB1 offers as replies.** None are used. Planning reads only the dial's own handshake offer (replies[0]), re-bound to the peer (§9.3).
- **No `confirmed_at`.** A sidecar records it in `confirm_verified_pair_response`. A fallback rule with an explicit bound covers sessions without it (§8.3).
- **History overwrite.** For direction `"in"`, the first body wins and `created_at = min(...)` (§13).
- **Frozen spec.** The receiver's envelope path is unchanged and nothing changes state on receive, so `ATSAM_ENDPOINT_TRANSACTION_V1` needs no amendment. The new spec, version registry and error codes are added, and the freeze manifest is regenerated (§22).
- **RSR1 freshness.** `created_at_ms` is signed but never checked. Replies are bound by the Noise link and by the echo (§6).
- **Defence in depth.** The RSR1 handler calls `peer_is_trusted`. It checks the subject against the local **device** key and the pinned bundle against the local **identity** key, separately. `offered_bundle_hash` is checked (§7, §14.3).
- **RDAP body-less rows.** They now end as a visible failure, `PEER_RESET_NO_BODY` (§15).
- **Per-process memos in ash.** ash keeps no memos. It sends at most one query and one PREKEY_STALE per user send. All backoff lives in the long-lived worker (§8.1, §14.3).
- **Typed errors.** `SessionRetired` maps to `ATSAM_SESSION_REQUIRED` in `map_seal_store_error`, and `AckRejected::Stale` is added in 2b (§10, §14.2).
- **Store guard placement.** A new `refuse_retired_message_lane(tx, ..)` is called right after each of the 5 `validate_outbound_session_and_signer` call sites. Copies are checked explicitly instead of interpreting `OutboundCollision`. A leftover Prepared row is handed off first (§9.4, §10).
- **Keychain and vault restores.** The covered restore shapes are documented and tested (§14.5).
- **Scope.** The work is split into 2a (wipe/reinstall) and 2b (restore), each behind its own gate (§18).

---

## 1. What happens today (verified)

Harness s05 (`scripts/lan_fault_matrix.py:303-322`) runs this sequence:
1. Pair A and B, then deliver `warmup`.
2. Stop B.
3. Delete everything in B's directory **except** files whose names start with `identity`, `device_` or `contacts` (`:309`). So **B's device cert is unchanged**.
4. `ash prekey publish`, then start B.
5. A sends. The result is `QUEUED` with `LAN_DIAL_PEER_CLOSED`, and the message is never delivered.

The causes:

1. **Prekey id reset.**
   - `cmd_prekey_publish_real` uses `highest_signed_prekey_id + 1` (`ash/src/ext.rs:~4012`). `ensure_local_prekey` uses `max(actor highest, published) + 1` (`lan_dispatch.rs:656-665`). After the wipe both give id 1.
   - A's pin refuses id 1 as `PREKEY_ROLLBACK` or `PREKEY_EQUIVOCATION` (`prekey_bundle.rs:259-290`).
   - `cache_peer_bundle` only logs (`lan_dispatch.rs:1170-1185`).
   - `create_initiator_pair_init` → `require_prekey_acceptable_to_pin` refuses any new session (`:1109`) until the pin expires (≤ 30 d) or the contact is removed.
2. **Dead session still selected.**
   - `find_confirmed_peer_session` returns S (`pair_init_lab.rs:626`).
   - B's `handle_indexed_message` finds no candidate and returns `Err` (`lan_dispatch.rs:1456`). The listener closes (`raven-node/src/lan_direct.rs:366-379`). The dialer sees `PEER_CLOSED` (`main.rs:654-680`).
   - The worker retries the same bytes for up to 24 h. Its only escape is SUPERSEDED (3 refusals over 2 min while a newer session exists), which marks the message `failed` (`raven-node/src/outbox.rs:1930-1953`).
3. **Real reinstall with a fresh data dir (not covered by s05).**
   - B issues a new cert with a new X25519 key (`device_cert.rs:282-375`).
   - A's ash compares the presented cert against S's bound digest and returns `ATSAM_SESSION_REQUIRED … nothing was sent` (`pair_init_lab.rs:1033-1052`).
   - If the pin accepts B's new bundle, A's single durable cert slot is overwritten (`lan_dispatch.rs:1143`). Every worker row under S is then `Held(NO_PEER_CERT)` (`outbox.rs:1617-1621`).
   - S is dead on both sides: B cannot ACK under it (`indexed_session_store.rs:4526-4536`).
4. **Restore from an older backup** (locked-file backend; for Keychain and vault see §14.5).
   - B's send and ACK indices roll back, so A refuses them as `Replay` (`prepare_receive_key`, `indexed_session_store.rs:5921-5933`).
   - An older still-valid bundle is refused by A's pin.
   - Nonce reuse is not catastrophic: every seal uses a fresh random 96-bit nonce (`send_message_envelope`, `:2140-2142`), and on LAN both ciphertexts ride Noise to the endpoint.
5. **Mixed versions.**
   - `ReplyCollector::next` treats a close after any reply as a normal end (`main.rs:683-688`). An old dialer that receives an unknown reply frame records "sent, no ACK", which resets its refusal counter (`outbox.rs:991-994`).
   - So **any inline reply from a new receiver regresses old senders**. That is why revision 2 never replies inline.

---

## 2. Goals and non-goals

**Goals**
1. After a single-side loss of session, prekey and/or device-certificate state, A and B converge automatically on a working session, provided the identity key is unchanged. The common LAN case needs no user action. No 30-day wait.
2. Every undelivered outbound message whose body this node holds is either delivered or ends visibly as `expired` or `failed`. Duplicates are bounded: at most 4 copies of one message ever exist. They are deduplicated in the receiver's history and collapsed with a marker in `ash inbox` and chat.
3. Rollback and equivocation protection is unchanged. An attacker who replays any old signed bundle is still refused.
   - Nobody without the contact's key can retire a session, trigger a re-seal, or force a renewal.
   - An attacker who holds *only* the contact's seed and is not on the local network cannot obtain the undelivered backlog without a user action.
4. Works under the HOLD (LAN direct only) and extends when the Internet and p2p carriers open.
5. The change set is as small as the goal allows. Everything is tested, including crash windows, mixed versions, forks and caps.

**Non-goals**
- An identity key that **changed**: that is a new identity (`RAVEN_IDENTITY_CONTINUITY_V2`) and stays refused.
- Recovering what the reset side had already received and ACKed before its own loss.
- The reset side losing its contact book. `link_admission` refuses A until B adds A again.
- Both sides losing their queues at once.
- Peers on old builds: their behaviour is byte-identical to today (§17).
- Re-sealing `SealUnderSession` (RDAP) payloads, because Raven holds no body for them. They end visibly instead (§15).
- Carriage over mailbox, store-and-forward or bridge: RSR1 is never stored or forwarded (§19).
- Any change to the following: the session lifetime, PairInit V1, RVN1, RLB1, the indexed-session profile, the pin rule (`PrekeyStore::publish`), `MAX_PREKEY_GENERATIONS`, or the receiver's envelope path (`ATSAM_ENDPOINT_TRANSACTION_V1` §1).
- Re-sealing after expiry (design Q4). A re-sealed copy keeps the original deadline.
- Local "I was restored" detection.

---

## 3. Security invariants (each has a test in §21)

- **I1 Pin rule unchanged.**
  - Lower id, equal id with other content, or higher id with a `created_at_ms` that is not newer: all still refused.
  - The replay of any earlier bundle is refused.
- **I2 Only the contact's key retires a session.** Retirement needs one of the following.
  - (E1) A SESSION_STATUS that is:
    - signed by the session's bound remote device key;
    - received on a dial whose Noise identity is that key;
    - addressed to our device;
    - echoing the authenticated object digest and message id of an object we hold **outstanding** to that peer in that session.
  - (E2) A certificate for the same device key that:
    - verifies under the contact's identity;
    - was presented on a Noise-bound link;
    - is not lineage-denied;
    - hashes differently from the session's bound digest.
  - (E3, 2b) An ACK under that session refused as `Replay` or `ForwardJumpTooLarge`. That verdict is only reached after the route tag and the outer signature by that key have been checked (`indexed_session_store.rs:4005-4039`).
- **I3 Re-seal never widens the audience beyond what the user approved.**
  - Plaintext is re-encrypted only to the same pinned identity, under a fresh PairInit V1 session.
  - The revocation check (`refuse_if_session_lineage_revoked`) and the PairInit revocation check (`pair_revocation`) both apply.
  - **Automatic** re-seal is limited further: only into a session **we initiated over a LAN route that resolves to local-network addresses only** (`localize_lan_route(route, /*pinned=*/false)`, `raven-core/src/outbox.rs:784`).
  - Anything else waits for `raven outbox resend --contact X`.
  - Residual risk, for the owner to decide (waiver §18): an attacker who holds the contact's seed **and** is on the user's local network can obtain the undelivered backlog. Today such an attacker obtains every future message.
- **I4 Prekey renewal (2b) is forward-only and needs proof.** The subject rotates only when all of the following hold:
  - the carried bundle verifies under its **own identity key**;
  - the bundle is inside its validity window;
  - the bundle beats its current bundle under the pin rule.

  The subject mints strictly above both and never adopts or re-publishes the carried bundle. Renewal requires 2 free generation slots.
- **I5 Strangers learn nothing new.** RSR1 is handled only after link admission (unchanged) and `peer_is_trusted`. The answer concerns only envelopes signed by the asking contact's own key. A non-contact still sees only a closed link.
- **I6 Store-wide failures are never reported as "no session".** A store, keystore or SQLite error closes the link exactly as today. `NO_SESSION` is reported only after a successful candidate lookup. Session-scoped skips such as `ProtectedStateMissing` count as "no session", which is correct (`find_confirmed_sessions_for_peer_at`, `indexed_session_store.rs:3423-3437`).
- **I7 No new crypto.** Ed25519 via `Identity::sign/verify` under a new domain. Existing SHA-256 digests (`bridge::authenticated_object_digest`, `pair_init::prekey_bundle_hash`, `device_certificate_hash`). Existing PairInit and indexed seal.
- **I8 No silent identity confusion.** On fork evidence (FE1) or after 3 automatic rounds in 24 h, automatic re-seal stops and the user is warned. New messages behave as today and are not blocked.
- **I9 The receiver's envelope path is unchanged.** No inline replies, and no state change on a refused envelope. The receiver's query handler is read-only.

---

## 4. Phase 1 (ungated): time-floored monotonic `signed_prekey_id`

### 4.1 Rule (`raven-core/src/prekey_lifecycle.rs`)

```rust
/// 2020-01-01T00:00:00Z. Ids are seconds since then (u32 lasts until 2156).
pub const PREKEY_ID_TIME_EPOCH_MS: u64 = 1_577_836_800_000;

pub fn time_floor_signed_prekey_id(now_ms: u64) -> u32 {
    let secs = now_ms.saturating_sub(PREKEY_ID_TIME_EPOCH_MS) / 1_000;
    u32::try_from(secs).unwrap_or(u32::MAX - 1).max(1)
}

/// Strictly above everything this publisher knows it signed (`actor_highest`,
/// `published`) and above `floor` (a pinned id a contact proved, §14.4), and
/// never below the wall-clock floor.
pub fn next_signed_prekey_id(actor_highest: u32, published: u32, floor: u32, now_ms: u64)
    -> Result<u32, PrekeyLifecycleError>
{
    let above = actor_highest.max(published).max(floor)
        .checked_add(1).ok_or(PrekeyLifecycleError::ResourceLimit)?;
    Ok(above.max(time_floor_signed_prekey_id(now_ms)))
}
```

### 4.2 Call sites

- **`lan_dispatch::ensure_local_prekey` (`lan_dispatch.rs:630-693`).**
  - The body under `PEER_CACHE_LOCK` becomes `fn rotate_local_prekey_locked(data_dir, id, now, floor: Option<(u32, u64)>) -> Result<PrekeyBundle, String>`. It keeps the dry-run publish → `rotate_generation` → publish-and-save order and is reused by §14.4.
  - The id is `next_signed_prekey_id(actor.highest, published_id, floor_id_or_0, now)`.
  - `created_at = max(now, floor_created_at + 1)`.
- **`ash/src/ext.rs::cmd_prekey_publish_real`.** Replace `highest_signed_prekey_id + 1` with `next_signed_prekey_id(highest, PrekeyStore::load_checked(..)?.fetch_valid(own, now).map_or(0, |b| b.signed_prekey_id), 0, now)`.

### 4.3 Rotation-failure fallback (bug fix, same phase)

`ensure_local_prekey` keeps its current contract when no valid own bundle exists. When rotation is merely *due* (inside `PREKEY_ROTATION_LEAD_MS`) but fails, for example on `ResourceLimit`, and `PrekeyStore::fetch_valid(own, now)` still returns a bundle:
- log `raven: prekey rotation failed (<code>); still offering the current prekey` at most once per hour;
- return `Ok(())`.

Before this fix, any rotation failure made every LAN link fail, because `local_bundle` and `encode_local_offer` propagate the error.

### 4.4 Why this is safe and what it fixes

- After a total loss, the first bundle has id ≈ now in seconds and a newer `created_at_ms`. Every earlier bundle of that identity has either a small legacy counter or an earlier time id. A's unchanged pin (I1) **accepts** it as an ordinary rotation, even on an old-build A.
- Replays of old bundles are still refused: a lower id is ROLLBACK, an equal id with other keys is EQUIVOCATION. Minting a higher id requires the identity key.
- A publisher whose clock runs behind fails safe (refused as today). 2b fixes that case with proof (§14.4).
- There is no wire change. `signed_prekey_id` is a non-zero u32 (`pair_init.rs:210`), and the only spec text is "monotonic per identity" (`RAVEN_PREKEY_BUNDLE_V1.md:22`). That spec needs no edit.
- Phase 1 alone fixes the 30-day pin wait: once S expires (≤ 24 h), or as soon as B pairs with A, everything works. B-initiated pairing now works with an old A too, because the pin accepts and so the durable cert is updated.
- Phase 1 does **not** deliver the stuck messages. 2a does.

---

## 5. Evidence that a session is dead; retirement (2a)

### 5.1 E1: signed `SESSION_STATUS` in answer to a query

See §6-§8. A new sealer asks; a new receiver answers read-only.

### 5.2 E2: renewed certificate (`session_reset::note_presented_cert`)

```rust
/// Retire for sending every confirmed session with `peer` whose bound remote
/// certificate is not `presented`. Ok(number retired).
pub fn note_presented_cert(data_dir: &Path, store: &mut IndexedSessionStore,
                           peer: &[u8; 32], presented: &DeviceCertificate, now_ms: u64)
    -> Result<usize, String>;
```

Preconditions, all required:
- `presented.device_ed_pub == *peer && presented.user_ed_pub == *peer`;
- `presented.verify(now)`;
- it was obtained from a Noise-bound offer (the ash probe; the worker's probe through `bound_offer` §9.3, or `load_cached_peer_bundle` right after such a probe);
- `!peer_lineage_denied(data_dir, presented)?`. A denied cert takes today's revocation path. A revoked key re-certified under a new `device_id` is denied through `device_ed_pub` (`RevocationStore::denies_certificate`), so it is never re-paired.

Then for each `key` in `store.find_sendable_sessions_for_peer_at(peer, now)`: if `store.remote_certificate_digest(&key)? != device_certificate_hash(presented)`, call `store.retire_session(&key, peer, PeerCertRenewed, now)`.

E2 has no false positives. A session bound to another cert of the same key cannot be used by B either: B cannot seal or ACK under it (`indexed_session_store.rs:4526-4536`).

### 5.3 E3 (2b only): stale ACK

See §14.2.

### 5.4 What "retired" means

A retired session is never used again to seal, retry or resend a **Message**. That is enforced by the store guard (§10) and by `find_sendable_*`. A retired session still:
- accepts inbound messages and ACKs (the route-tag search over `find_confirmed_*` is unchanged);
- sends ACKs (`enqueue_committed_ack` is allowed);
- is used for the `handle_pair_init` replay check (`lan_dispatch.rs:1357`, unchanged);
- expires and is pruned normally.

Retirement on its own changes nothing on the wire and leaks nothing.

---

## 6. RSR1 v1 wire format (`protocol/RAVEN_SESSION_RESET_V1.md`, normative)

RSR1 is a raw Noise-transport plaintext frame, like RLB1. It is valid **only** on an endpoint-authenticated Raven link: LAN direct, Internet direct (RIH1) or the p2p direct link. It is **never** wrapped in RVN1, stored or forwarded; `carrier_admission::admit_relayable` already refuses it (`carrier_admission.rs:124`).

Request kinds (1 and 3) travel **only alone, in a dedicated dial**. Reply kinds (2 and 4) travel **only as replies** to them.

All integers are big-endian.

```
Header (78 bytes)
  0   4  magic           "RSR1"
  4   1  version         1
  5   1  kind            1 SESSION_QUERY  2 SESSION_STATUS  3 PREKEY_STALE (2b)  4 PREKEY_STATUS (2b)
  6  32  signer_device   Ed25519 device key of the frame's author
 38  32  subject_device  Ed25519 device key of the intended recipient
 70   8  created_at_ms   signer's clock: signed, for logs only, never a validity check
Body (kind-specific)
Trailer
 end-64 64 signature     Ed25519(signer, "rvn1/session-reset/v1\0" || bytes[0 .. end-64])

Kind 1 SESSION_QUERY  (sealer -> receiver)           frame = 146 + n
 78   4  envelope_len    86 ..= RSR1_MAX_FRAME - 146
 82   n  envelope        exact packed RavenEnvelopeV1 of one of the signer's outstanding
                         objects to the subject (env_type 1 Message or 2 Ack)

Kind 2 SESSION_STATUS (receiver -> sealer, reply)     frame = 192
 78   1  status          1 PRESENT  2 NO_SESSION  3 SENDER_STATE_STALE (2b)  4 RECEIVER_STATE_STALE (2b)
 79   1  echoed_env_type
 80  32  echoed_object   bridge::authenticated_object_digest(queried envelope)
112  16  echoed_mid      queried envelope's outer message_id

Kind 3 PREKEY_STALE (2b, initiator -> contact)       frame = 178 + n
 78  32  offered_bundle_hash  pair_init::prekey_bundle_hash(prekey in the subject's RLB1 offer on this link)
110   4  pinned_len           1 ..= 8192
114   n  pinned_bundle        PrekeyBundle JSON (PrekeyBundle::to_json), signed by the SUBJECT's identity

Kind 4 PREKEY_STATUS (2b, reply)                      frame = 179
 78   1  result          1 RENEWED 2 NO_CHANGE_NEEDED 3 GENERATION_CAP 4 CLOCK_BEHIND 5 STALE_OFFER 6 INVALID_PROOF
 79  32  echoed_pinned   prekey_bundle_hash(pinned_bundle)
111   4  current_id      subject's signed_prekey_id after the operation
```

- `RSR1_MAX_FRAME = lan_noise::MAX_TRANSPORT_PLAINTEXT` (65 519). A query carries envelopes of up to 65 373 bytes. ash caps texts at 48 KiB (`MAX_LAN_ENDPOINT_TEXT`), so every real envelope fits. A larger one is simply never queried, and today's behaviour applies.
- **Domain separation.** The signing domain `rvn1/session-reset/v1\0` is not a prefix of any other signing domain, and none of them is a prefix of it. RVN1 envelopes sign over `"RVN1"` (`envelope.rs:8,236-253`); the other domains are `rvn1/pair-init`, `rvn1/pair-response`, `rvn1/prekey`, `rvn1/devcert`, `rvn1/ack` and so on.

**Decoding** (`session_reset::decode(bytes) -> Result<Rsr1Decode, &'static str>`):
- Fewer than 4 bytes, or a magic other than `RSR1` → `NotRsr1`.
- `version != 1` or an unknown `kind` → `Unsupported`. The listener returns `Ok(vec![])`: no reply, no close.
- The following → `Err("RSR1_MALFORMED")` (listener: close; dialer: treated as "no answer"):
  - a wrong length or trailing bytes;
  - a `status` or `result` outside the listed values;
  - an `echoed_env_type` other than 1 or 2;
  - an `envelope_len` or `pinned_len` out of range;
  - invalid JSON.

**Verification** (`session_reset::verify(bytes, &frame, expected_signer, local_device)`), with fixed redacted codes:
1. `signer_device == expected_signer` → else `RSR1_WRONG_SIGNER`.
   - At the listener, `expected_signer` is the Noise or hello-bound key. `dispatch_frame` has already checked that it equals `peer.cert.device_ed_pub` (`lan_dispatch.rs:1625`).
   - At the dialer, `expected_signer` is the dial's `expected_pub`.
2. `subject_device == local device_ed_pub` (from `ensure_local_device_certificate`) → else `RSR1_WRONG_SUBJECT`.
3. The signature verifies → else `RSR1_BAD_SIGNATURE`.

There is no time-window check. Replies cannot be replayed: they are bound to the dial's Noise channel and to the echo of an object that is still outstanding. Requests only cause read-only work (kind 1) or proof-gated, idempotent work (kind 3).

---

## 7. Receiver: answering SESSION_QUERY (`lan_dispatch.rs`, `session_reset.rs`)

New branch at the top of `dispatch_frame`, after the existing identity checks and before RLB1:

```rust
if session_reset::session_reset_live_enabled() && session_reset::is_rsr1(frame) {
    return session_reset::handle_inbound_rsr1(data_dir, identity, peer, noise_ed, frame);
}
```

With the gate off, an RSR1 frame reaches today's `Err("lan frame is not RavenEnvelopeV1")`, byte for byte.

`handle_inbound_rsr1(data_dir, identity, peer: &LanBundle, noise_ed, frame) -> Result<Vec<Vec<u8>>, String>`:
1. `if !peer_is_trusted(data_dir, peer)? { return Err("rsr1 refused: peer is not a local contact".into()) }`. This matches the other handlers (I5).
2. `decode`, then `verify(.., expected_signer = noise_ed, local_device)`. `Unsupported` → `Ok(vec![])`. A kind 2 or 4 arriving as a frame → `Ok(vec![])`. Kind 3 → §14.3, or `Ok(vec![])` when the 2b gate is off.
3. Kind 1:
   - `env = Envelope::unpack(envelope)`; `env_type ∈ {Message, Ack}`;
   - `env.verify(&peer.cert.device_ed_pub)` (the outer signature by the asking contact). On failure → `Err` (close).
   - `env.dest_device_hint ∈ {0, endpoint_device_hint(local device)}` → else `Err`.
4. `store = IndexedSessionStore::open(..)`. Any error → `Err`, which closes as today (I6).
5. `match store.match_inbound_session(&peer.cert.device_ed_pub, envelope, now)?`. This is a new, **read-only** method: for each `find_confirmed_sessions_for_peer_at` candidate, newest first, it derives `derive_route_tag(root, env.created_at, index, env_type, inbound_direction)` exactly as `accept_*_envelope` does (`indexed_session_store.rs:2827-2840`, `:3999-4008`), and returns the first match. A session closed by an early security re-key (Phase 6b R2/R3: retired with `LocalSecurityRekey` more than `EARLY_OLD_ACCEPT_MS` ago, so it takes no new object) matches nothing (Phase 6 review sensing-1).
   - `None` → `NO_SESSION`.
   - `Some(key)`: with the 2b gate on, `store.classify_inbound_index(&key, envelope, now)?` decides (§14.1). Otherwise the answer is `PRESENT`.
6. Reply `vec![encode_signed(identity, &peer.cert.device_ed_pub, now, SessionStatus { status, env.env_type, authenticated_object_digest(&env), env.message_id })]`.
7. Log at most once per peer per hour: `raven-node lan_direct: answered a contact's session check: no session (RAVEN was reset here; the contact sets up a new secure connection)`, or, when the object was sealed in a session this node closed itself after an early security re-key (Phase 6 review re-verify, sensing-1), `raven-node lan_direct: answered a contact's session check: no session (this computer replaced that secure connection with a new one in a security re-key; the contact sends what waited in it again; nothing needs doing here)`. Codes only, no keys.

No state changes (I9). The listeners (`lan_direct.rs:374`, `internet_direct.rs:499`) need no change: they write whatever `dispatch_frame` returns.

**Dial classification** (`raven-node/src/main.rs`):
- `expects_reply`: returns `true` for RSR1 kind 1 and kind 3.
- `is_terminal_reply`: returns `true` for RSR1 kind 2 and kind 4.

Both checks come before the existing RVN1 classification. Without this change a dial still works but waits the 2 s idle timeout.

---

## 8. Sealer: when to query, and applying the answer (`session_reset.rs`)

### 8.1 Trigger

A query is sent only when the gate is on and **a dial that carried at least one Message frame ended in `*_DIAL_PEER_CLOSED`**. The query carries the **first Message frame of that dial**. B processes frames in order and every accepted message produces an ACK, so a close with no reply means that frame was refused. Dials that carried only ACKs never trigger a query.

- **ash:** at most one query per user send (§11).
- **Worker:** at most one query per (peer, session) per attempt. Backoff is kept in memory in a new `AttemptCtx::reset_backoff: Mutex<HashMap<([u8;32],[u8;32]), (Instant, u32)>>`: the first query goes at once, then 1, 4, 16 and 60 minutes. Any decoded answer resets the backoff.

### 8.2 API

```rust
pub fn session_query_frame(identity: &Identity, peer: &[u8; 32], envelope: &[u8], now_ms: u64)
    -> Result<Vec<u8>, String>;

pub enum QueryOutcome {
    Retired { session_id: [u8; 32], cause: SessionRetireCause },
    Transient(&'static str),   // PEER_HAS_SESSION, RESET_TRANSIENT_YOUNG_SESSION, RESET_UNKNOWN_ECHO, ...
    NoAnswer,                  // closed, malformed, or an old peer: never a version verdict
}

/// Under the peer's PeerSendLock.
pub fn apply_query_replies(data_dir: &Path, store: &mut IndexedSessionStore,
    local_device: &[u8; 32], peer: &[u8; 32], queried_envelope: &[u8],
    replies: &[Vec<u8>], now_ms: u64) -> Result<QueryOutcome, String>;
```

### 8.3 `apply_query_replies` steps

1. Take the first frame in `replies[1..]` that decodes as RSR1 kind 2 (`replies[0]` is the handshake offer, `main.rs:616-626`). If there is none → `NoAnswer`.
2. `verify(.., expected_signer = peer, local_device)`.
3. The echo equals `(env_type, authenticated_object_digest(queried), message_id)` → else `Transient("RESET_ECHO_MISMATCH")`.
4. `row = store.outbound_by_digest_for_recipient(&digest, peer)?`.
   - None → `Transient("RESET_UNKNOWN_ECHO")`.
   - Outstanding state `Delivered` or `Read` → `Transient("RESET_ALREADY_DELIVERED")`.
   - `key = record_key_for_session_id(row.session_id)`; its remote device must equal `peer`.
5. Act on the status:
   - `PRESENT` → `Transient("PEER_HAS_SESSION")`. The refusal counts as today.
   - `NO_SESSION`:
     - **Young-responder rule.** If our role in S is Responder, and `confirmed_at_ms` from the sidecar (or, when absent, `head.created_at_ms + MAX_PREKEY_FUTURE_SKEW_MS`) is less than `RESET_NO_SESSION_MIN_AGE_MS` (60 s) before now → `Transient("RESET_TRANSIENT_YOUNG_SESSION")`.
       - Why: as responder we confirmed before the peer did. The peer confirms only once it reads our PairResponse.
       - The worst-case transient window for sessions confirmed by older builds is 6 min.
     - Otherwise `retire_session(key, peer, PeerNoSession, now)` → `Retired`.
       - As initiator, the peer confirmed before it replied (`lan_dispatch.rs:1428-1430`), so `NO_SESSION` is definitive.
   - `SENDER_STATE_STALE` or `RECEIVER_STATE_STALE`: only with the 2b gate on. Retire with `PeerSaysOurSendStale` or `PeerReceiveStale`. With 2b off → `Transient`.

---

## 9. Reset step: policy, target, PairInit, re-seal (`session_reset::run_reset_step`)

One function is shared by ash (pre-pass and restart), the worker, and `raven outbox resend`:

```rust
pub struct ResetEnv<'a> {
    pub data_dir: &'a Path, pub identity: &'a Identity,
    pub local_cert: &'a DeviceCertificate, pub registry: &'a DeviceRegistry,
    pub peer: [u8; 32], pub pinned_contact: bool,
    pub routes: &'a [OutboxRoute],    // the contact's planned routes, preference order
    pub user_confirmed: bool,         // `raven outbox resend`
    pub now_ms: u64,
}
pub trait ResetIo {
    /// Run `f` under this peer's PeerSendLock with an open store. ash already holds
    /// the lock for the whole send (runs f directly); the worker acquires it with
    /// LOCK_WAIT around each call and never across a dial.
    fn locked(&mut self, f: &mut dyn FnMut(&mut IndexedSessionStore) -> Result<(), String>)
        -> Result<(), String>;
    fn dial(&mut self, route: &OutboxRoute, frames: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String>;
}
pub enum ResetStep {
    Nothing,                                       // no retired undelivered rows
    Resealed(ResealReport),
    Held { code: &'static str, rows: usize },      // PEER_RESET_CONFIRM | _LOOP | PEER_IDENTITY_FORK | PEER_PREKEY_RESET | (2b) _WAIT_PREKEY | _CLOCK
    Unreachable(String),                           // probe/PairInit dial failed: caller backs off
}
pub fn run_reset_step(env: &ResetEnv, io: &mut dyn ResetIo) -> Result<ResetStep, String>;
```

### 9.1 Policy (checked in order, under the lock)

1. **Gate.** `session_reset_live_enabled()`; otherwise `Nothing`.
2. `reconcile_resealed_outbound` (§9.5). Then `rows = store.retired_undelivered_messages_for_recipient(peer)`. If empty → `Nothing`.
3. Per-row terminal checks: §9.4 steps 1-5. These give up visibly and need no policy.
4. **P3, fork.** Unless `user_confirmed`: if `peer_reset_state.fork_evidence_at_ms > max(now − 24 h, user_confirmed_at_ms)` → `Held(PEER_IDENTITY_FORK)`.
5. **Target.** `store.reseal_target_for_peer(peer, now)` (§9.2). If found, go to §9.4.
6. **P4, loop cap.** Unless `user_confirmed`: if `store.reset_rounds_since(peer, max(now − 24 h, user_confirmed_at_ms)) >= RESET_MAX_AUTO_ROUNDS_PER_DAY` (3) → `Held(PEER_RESET_LOOP)`.
7. **Cooldown.** If a reset round for this peer started less than 60 s ago and produced no target → `Held(PEER_RESET)`, with backoff.
8. **P2, locality.** Pick the first LAN route `r` with `localize_lan_route(r, false, LOCALIZE_RESOLVE_TIMEOUT).is_ok()`.
   - If there is none: with `user_confirmed`, use `routes[0]`; otherwise `Held(PEER_RESET_CONFIRM)`.
9. PairInit on `r` (§9.3), then re-seal (§9.4).

**Why the caps are consistent.** At most 3 automatic rounds happen in any 24 h, and a message lives at most 24 h. So automatic handling re-seals one message at most 3 times, which equals `RESET_MAX_RESEALS_PER_MESSAGE`. The per-message cap (→ `failed`) can only be reached after a user confirmation. s22 (4 wipes) therefore ends in `PEER_RESET_LOOP`, not `failed`.

### 9.2 Target selection

`reseal_target_for_peer(peer, now)` returns the newest key that meets all of these:
- sendable: confirmed, unexpired, not retired;
- `sidecar.initiated_local = 1`;
- `created_at_ms` greater than the newest `created_at_ms` among retired sessions that still hold undelivered rows to `peer`;
- at least `RESET_TARGET_MIN_REMAINING_MS` (10 min) left.

With `user_confirmed`, any sendable session newer than those retired sessions qualifies.

A session the peer initiated is never an automatic target. That makes the result immune to dead crossed-pair twins. It costs at most one extra PairInit, for example in s05c.

### 9.3 PairInit (`lan_dispatch::pair_with_peer`, extracted from `ash/src/pair_init_lab.rs:625-687`)

1. **Probe.** `replies = io.dial(r, &[])`. Then `offer = session_reset::bound_offer(&replies, &peer, now)`:
   - `replies[0]` must parse as RLB1;
   - `verify_lan_bundle` must pass;
   - `cert.device_ed_pub == peer && cert.user_ed_pub == peer`.

   `dial_session` has already passed that same offer to `cache_peer_bundle` (`raven-node/src/lan_direct.rs:587`). If there is no bound offer → `Unreachable`.
2. **E2 check.** Under the lock, `note_presented_cert(.., &offer.cert, now)`. This also re-checks revocation.
3. **Plan,** under the lock:
   - 2b adds `lan_dispatch::pinned_peer_bundle_refusing(data_dir, &offer, now) -> Result<Option<PrekeyBundle>, String>`, a public variant of `require_prekey_acceptable_to_pin` that returns the pinned bundle on refusal.
   - Not refused → step 4.
   - Refused: in 2a → `Held(PEER_PREKEY_RESET)`; in 2b → §14.3, then back to step 1, once.
4. **PairInit.**
   - `pair_with_peer(data_dir, id, &offer, local_route: bool, reset_round: bool, dial)`:
     1. `create_initiator_pair_init` under the lock;
     2. `wrap_pair_init`;
     3. `io.dial(r, &[init])` without the lock;
     4. `first_pair_response`;
     5. under the lock, `confirm_verified_pair_response`, then `store.mark_session_initiated(&key, &peer, local_route, reset_round, now)`.
   - It returns the key. With `reset_round = true` the round is recorded at creation, so the cooldown and the cap also count failed attempts.
   - ash's ordinary "no session → PairInit" branch uses the same function with `reset_round = false`, recording `local_route`. Its behaviour is unchanged; it only writes the sidecar.

### 9.4 Re-seal, per row (`reseal_retired_outbound`, under the lock)

```rust
pub struct Resealed { pub message_id: [u8;16], pub old_session: [u8;32], pub old_digest: [u8;32], pub new: EndpointOutbound }
pub struct ResealReport { pub resealed: Vec<Resealed>, pub delivered: Vec<[u8;16]>, pub expired: Vec<[u8;16]>,
                          pub capped: Vec<[u8;16]>, pub no_body: Vec<[u8;16]> }
pub fn reseal_retired_outbound(data_dir, identity, local_device: &AuthorizedEndpointDevice<'_>,
    store, peer: &[u8;32], target: &IndexedSessionRecordKey, now_ms) -> Result<ResealReport, String>;
```

Rows are processed in the original send order: envelope `created_at`, then session `created_at_ms`, then `ratchet_index`. For each Message row R in session S (retired), `Prepared` or `Queued`, with outstanding `Sent`:

1. **Already delivered.** If any copy of `(peer, mid)` has outstanding `Delivered` or `Read` (`message_copies_for_recipient`) → `record_outbound_delivered`, then `retire_outbound_copy(S, R.digest)` → `delivered`.
2. **Already re-sealed.** If a live copy exists in a non-retired session, skip it; §9.5 reconciles it. This is checked explicitly; `OutboundCollision` is never interpreted as "already re-sealed".
3. **Body.**
   - Use the staged body bound to `(S, R.digest, mid)` (`load_staged_outbound_body`), or the `out` body in ChatHistory.
   - If neither exists (a `SealUnderSession` row) → `abandon_undelivered_outbound(S, R.digest)`, store only → `no_body`. The worker reports `Failed(PEER_RESET_NO_BODY)` (§15).
4. **Cap.** If `store.reseal_count(peer, mid) >= RESET_MAX_RESEALS_PER_MESSAGE` (3) → `give_up_outbound(.., HISTORY_FAILED)` → `capped`.
5. **Deadline.**
   - `orig = Envelope::unpack(R.immutable_envelope_bytes).expires_at`;
   - `expires = min(orig, target expires_at)`;
   - if `expires <= now + 30 s` → `give_up_outbound(.., HISTORY_EXPIRED)` → `expired`. The deadline is never extended (Q4).
6. **Revocation, once per call.** Run `refuse_if_session_lineage_revoked(local_cert, session_bound_peer_certificate(target))`. On a deny → `abandon_undelivered_to_peer` (today's path) and stop.
7. **Lane free, once per call.** If the target has a leftover Prepared Message row → `retry_endpoint_outbound(target, d, .., cb)`, where `cb` = `ensure_outbound_queued_history` (its own stage) → `Ok`. Without this, the seal below returns `OutboundPending`.
8. `store.bump_reseal_ledger(peer, mid, orig, now)`. It runs in its **own transaction, before the seal**, so a crash can only over-count, which is the safe direction for a cap.
9. `store.reseal_message_envelope(target, body, &mid, local_device, now, expires, now, rng, cb)`. The callback:
   - calls `ensure_outbound_queued_history(data_dir, peer, target_sid, d_new, mid, staged.created_at_ms, Some(body))`, which re-stages under the same mid (`stage_outbound_body_locked` replaces by mid, `chat_history.rs:2138-2149`) and keeps history `queued` on the same row;
   - returns `Ok(*d_new)`. R' is now `Queued`.
10. `store.retire_outbound_copy(S_key, R.digest)`. It deletes the outbox row only and **keeps the outstanding row**, so a late ACK under S still settles it.

**Why mid reuse across sessions is safe.**
- Ids are unique per session (`UNIQUE(session_id, message_id)`) and are checked by `ensure_fresh_outbound_coordinates`, including the historical outstanding row (`indexed_session_store.rs:4565-4610`).
- The AEAD key is per session.
- Relays deduplicate by authenticated digest.
- The receiver deduplicates end to end by `(peer, "in", mid)`.

### 9.5 Crash safety: `reconcile_resealed_outbound(data_dir, store, peer) -> Result<usize, String>`

It runs under the lock at the start of every worker attempt, every ash send and every `run_reset_step`. It is idempotent.

For each `mid` in the ledger for `peer`:
1. **A delivered copy exists.**
   - `retire_outbound_copy` every other undelivered copy;
   - `mark_lan_chat_history_delivery(.., "delivered")`;
   - `clear_staged_outbound_body(mid)`.

   This is the sibling settlement. It also covers ACKs that arrived over the listener (`handle_ack` → `record_inbound_ack_delivery`, `raven-core/src/outbox.rs:412-448`), which leave the stage bound to the other copy.
2. **Old row R in a retired session plus a live copy R' elsewhere.**
   - (a) If the stage is still bound to `(S, R.digest)`, re-stage to `(T, R'.digest)` with the same body and `created_at_ms`.
   - (b) If R' is still `Prepared`, `retry_endpoint_outbound(T, R'.digest, cb = ensure history + Ok)`.
   - (c) `retire_outbound_copy(S, R.digest)`.

| Crash after | Durable state | Repair |
|---|---|---|
| ledger bump | ledger +1, R only | next attempt re-seals (the count is one high: safe) |
| W1: R' committed Prepared | R; R' Prepared; stage → S | reconcile 2a, 2b, 2c |
| W2: callback done | R; R' Queued; stage → T | reconcile 2c |
| W3: R retired | R' only | nothing to do |
| retire, before any re-seal | S retired, rows under S | next attempt re-seals |
| PairInit sent, no response | provisional session (unused; expires) | cooldown, then a new round |

`reconcile_outbound_stage_history` (`lan_dispatch.rs:434`) needs **no change**. Outstanding rows are never deleted by re-seal, so its "no outstanding row → failed" branch is never reached for a re-sealed message.

The worker and ash paths that end in "binding mismatch → give up FAILED" (`raven-node/src/outbox.rs:1641-1658`; `pair_init_lab.rs:1446-1457`) are only reached for rows in non-retired sessions. Rows in retired sessions are filtered out before them (§11, §12), and reconcile runs first.

---

## 10. Store changes (`raven-core/src/indexed_session_store.rs`)

The schema change is additive and is created in `open_with_backend` with `CREATE TABLE IF NOT EXISTS`. The 2a build creates it whatever the gate. **`METADATA_SCHEMA_VERSION` stays 1** (privacy pack PP.13 later raised it to 2, and PP.14 to 3, for a sealed profile's store only: `docs/design/2026-10-at-rest-metadata.md` sections 4.11 and 4.12). Older binaries ignore the new tables; the cascade keeps the sidecar consistent when they prune heads (`prune_expired_sessions` deletes heads by session_id, `:3536`).

```sql
CREATE TABLE IF NOT EXISTS indexed_session_reset (
  session_id        BLOB PRIMARY KEY NOT NULL CHECK(length(session_id) = 32),
  peer_device       BLOB NOT NULL CHECK(length(peer_device) = 32),
  confirmed_at_ms   INTEGER CHECK(confirmed_at_ms IS NULL OR confirmed_at_ms >= 0),
  initiated_local   INTEGER NOT NULL DEFAULT 0 CHECK(initiated_local IN (0, 1)),
  reset_round_at_ms INTEGER CHECK(reset_round_at_ms IS NULL OR reset_round_at_ms >= 0),
  retired_at_ms     INTEGER CHECK(retired_at_ms IS NULL OR retired_at_ms >= 0),
  retire_cause      INTEGER CHECK(retire_cause IS NULL OR retire_cause BETWEEN 1 AND 6),
  CHECK((retired_at_ms IS NULL) = (retire_cause IS NULL)),
  FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS indexed_session_reset_peer ON indexed_session_reset(peer_device);

CREATE TABLE IF NOT EXISTS endpoint_reseal_ledger (      -- survives the prune of the original session
  recipient_device  BLOB NOT NULL CHECK(length(recipient_device) = 32),
  message_id        BLOB NOT NULL CHECK(length(message_id) = 16),
  reseals           INTEGER NOT NULL CHECK(reseals BETWEEN 1 AND 255),
  last_reseal_at_ms INTEGER NOT NULL CHECK(last_reseal_at_ms >= 0),
  expires_at_ms     INTEGER NOT NULL CHECK(expires_at_ms >= 0),   -- original deadline
  notified          INTEGER NOT NULL DEFAULT 0 CHECK(notified IN (0, 1)),
  PRIMARY KEY(recipient_device, message_id)
);

CREATE TABLE IF NOT EXISTS peer_reset_state (
  peer_device          BLOB PRIMARY KEY NOT NULL CHECK(length(peer_device) = 32),
  fork_evidence_at_ms  INTEGER CHECK(fork_evidence_at_ms IS NULL OR fork_evidence_at_ms >= 0),
  user_confirmed_at_ms INTEGER CHECK(user_confirmed_at_ms IS NULL OR user_confirmed_at_ms >= 0)
);
```

```rust
#[repr(u8)] pub enum SessionRetireCause {
    PeerNoSession = 1, PeerCertRenewed = 2,                       // 2a
    PeerSaysOurSendStale = 3, PeerReceiveStale = 4,               // 2b (E1 reasons)
    LocalSawPeerSendStale = 5, LocalReceiveStale = 6,             // 2b (E3)
    LocalSecurityRekey = 7,   // Phase 6b R2 (P6.27): CHECK widened to 1-7 in place
    Other = 0,                // read only: a cause this build does not know
}
// New error; Display: "session was retired after the contact reset it; a newer session is required"
IndexedSessionStoreError::SessionRetired

// sidecar (ungated writes are metadata only)
pub fn retire_session(&mut self, key: &IndexedSessionRecordKey, peer: &[u8;32], cause: SessionRetireCause, now_ms: u64) -> Result<bool, _>; // upsert; idempotent; true if newly retired
pub fn session_reset_info(&self, session_id: &[u8;32]) -> Result<Option<SessionResetInfo>, _>;
pub fn mark_session_initiated(&mut self, key, peer, local_route: bool, reset_round: bool, now_ms: u64) -> Result<(), _>;
pub fn reset_rounds_since(&self, peer: &[u8;32], since_ms: u64) -> Result<usize, _>;
pub fn note_inbound_on_retired(&mut self, session_id: &[u8;32], local_is_initiator: bool, now_ms: u64) -> Result<bool, _>; // FE1
pub fn peer_reset_state(&self, peer) -> Result<PeerResetState, _>;
pub fn confirm_peer_reset(&mut self, peer, now_ms) -> Result<(), _>;   // `raven outbox resend`

// lookups
pub fn find_sendable_sessions_for_peer_at(&mut self, peer, now_ms) -> Result<Vec<IndexedSessionRecordKey>, _>; // confirmed minus retired, same order
pub fn find_sendable_session_for_peer(&mut self, peer) -> Result<Option<IndexedSessionRecordKey>, _>;
pub fn reseal_target_for_peer(&mut self, peer, user_confirmed: bool, now_ms) -> Result<Option<IndexedSessionRecordKey>, _>;
pub fn retired_undelivered_messages_for_recipient(&self, peer) -> Result<Vec<EndpointOutbound>, _>;
pub fn outbound_by_digest_for_recipient(&self, digest, peer) -> Result<Option<(EndpointOutbound, Option<EndpointDeliveryState>)>, _>;
pub fn message_copies_for_recipient(&self, peer, mid) -> Result<Vec<MessageCopy /*session_id, digest?, delivery_state, has_outbox_row*/>, _>;
pub fn live_copy_elsewhere(&self, peer, mid, except_session: &[u8;32]) -> Result<bool, _>;
pub fn inbox_copies(&self, sender, mid) -> Result<usize, _>;                // receiver collapse (§13)

// re-seal
pub fn reseal_message_envelope<R, F>(&mut self, key, text, message_id: &[u8;16], local_device, created_at_ms, expires_at_ms, now_ms, rng, enqueue) -> Result<EndpointOutbound, _>;
pub fn retire_outbound_copy(&mut self, key, object_digest) -> Result<bool, _>; // DELETE endpoint_outbox kind=1 state IN (0,1); keeps outstanding
pub fn bump_reseal_ledger(&mut self, peer, mid, orig_expires_ms, now_ms) -> Result<u8, _>;
pub fn reseal_count(&self, peer, mid) -> Result<u8, _>;
pub fn take_unnotified_reseals(&mut self, peer) -> Result<(usize, u64), _>;

// receiver, read-only
pub fn match_inbound_session(&mut self, peer, packed: &[u8], now_ms) -> Result<Option<IndexedSessionRecordKey>, _>;
pub fn classify_inbound_index(&mut self, key, packed: &[u8], now_ms) -> Result<InboundIndexClass, _>; // 2b
```

Notes on the store changes:

- **Shared seal path.** `send_message_envelope` (`:2083`) and `reseal_message_envelope` share one private `seal_message_inner(.., message_id: Option<[u8;16]>)`. With `Some`, the supplied id replaces `random_nonzero::<16>` (`:2140`); everything else is identical.
- **Guard.** A new `fn refuse_retired_message_lane(tx: &Transaction, session_id: &[u8;32], kind: EndpointOutboundKind) -> Result<(), IndexedSessionStoreError>` returns `SessionRetired` for kind Message when the sidecar row has `retired_at_ms IS NOT NULL`. It is a no-op for ACKs. It is called right after `validate_outbound_session_and_signer` at its five call sites (`:2119`, `:2274`, `:2481`, `:2640`, `:2687`). The free function itself stays unchanged.
- `SessionRetired` is **not** in `is_session_scoped_state_error` (`:4765`).
- **`confirmed_at_ms`.** `confirm_verified_pair_response` (`:4305`) upserts the sidecar row `(session_id, peer_device, confirmed_at_ms = now)` in its own SQLite transaction, for both roles, whatever the gate.
- **FE1.** `note_inbound_on_retired` sets `peer_reset_state.fork_evidence_at_ms = now` when all of these hold:
  - the session is retired with cause `PeerNoSession`;
  - the local role is Initiator;
  - `now >= retired_at + RESET_FORK_GRACE_MS` (60 s);
  - the object was made after the retirement: its envelope's `created_at >= retired_at + RESET_FORK_MADE_AFTER_MS` (the accepted clock skew, 5 min). One made before and delivered late (a friend's custody, an owed ACK) proves nothing: since Phase 6b's early security re-key a contact answers NO_SESSION about a session it closed while its earlier ACKs and messages in it may still be on their way (Phase 6 review sensing-1).

  It is called after a **Committed** (not Duplicate) acceptance in `handle_indexed_message`, in `handle_ack`, and in `outbox::accept_sealed_ack` (`raven-core/src/outbox.rs:150`). The gate must be on.
- **Ledger prune.** `prune_expired_sessions` also runs `DELETE FROM endpoint_reseal_ledger WHERE expires_at_ms + 86400000 <= ?cutoff`.
- **`map_seal_store_error`** (`lan_dispatch.rs:1830`): `SessionRetired` joins the `ATSAM_SESSION_REQUIRED` arm.

---

## 11. `ash send` integration (`ash/src/pair_init_lab.rs`)

**1. Reachable path, after the probe, the lock and `cache_peer_bundle` (`:623`), with the gate on.**
- (a) `note_presented_cert(.., &peer_bundle.cert, now)`.
- (b) `ctx.say_unnotified_reseals(store.take_unnotified_reseals(peer))`.
- (c) **Pre-pass.**
  - Run `run_reset_step(env{routes: [probe route], user_confirmed: false}, AshIo)`. `AshIo::locked` runs inline because `_send_lock` is held; `AshIo::dial` is `ipc_carrier_dial_patient`.
  - `Resealed(r)` → `ctx.say_peer_reset(r.resealed.len())`.
  - `Held{code, rows}` → `ctx.say_reset_held(code, rows)`. That is one line; the new message is **not** blocked.
  - `Unreachable` → nothing.
- (d) Select the session with `find_sendable_peer_session` (`:626`).
  - None → the PairInit branch, which now calls `lan_dispatch::pair_with_peer(.., local_route, reset_round=false, ipc dial)`.
  - A pin refusal in 2b goes through the planner (§9.3 step 3); in 2a it is today's `NOT SENT … PEER_PREKEY_RESET`.

**2. `send_indexed_text`** gains `reset: &mut SendReset { enabled, queried: bool, own_mid: Option<[u8;16]>, held: usize, restart: bool }`.
- **Earlier-rows loop (`:1260-1480`).** Skip a row whose `session_reset_info(row.session_id)` is retired: `held += 1; continue`. Such rows never block and never reach the "binding mismatch → failed" path.
- **Refusal hook.** In the earlier loop's `Err(e)` branch (`:1442-1478`) and in the new message's `Err(e)` branch (`:1550-1590`): when `reset.enabled && !reset.queried && is_peer_refusal(&detail)` and the object is a Message:
  1. Set `reset.queried = true`.
  2. Dial `session_query_frame(id, peer, &bytes)` alone on the same carrier and route. The closure keeps the refused frame in a `RefCell<Option<Vec<u8>>>`; the store call has returned, so no transaction is open.
  3. Call `apply_query_replies` under the held lock.
  4. On `Retired`, set `reset.restart = true` and record `own_mid` if this was the new message. Return `Err(SendStop::PeerReset)`.

  `superseded_row_was_refused` (`:1460`) and `earlier_undelivered_text` still apply when the answer is `Transient` or `NoAnswer`.
- **Store races.** A `SessionRetired` from any store call is treated the same way.
- **`own_mid` handling.** When `reset.own_mid == Some(m)`:
  - in the earlier loop, row `m` reports with the new-message lines: `say_delivered`, `unconfirmed_text`, `queued_text`;
  - the new-message section is **skipped**, because the text is not sealed twice.

**3. Restart** in `run_pair_init_and_send_routes`, at most once per send:
- `run_reset_step` again: it now finds the retired rows, including `own_mid`, and re-seals them;
- `say_peer_reset`;
- `record_key = find_sendable_peer_session`;
- `send_indexed_text(.., reset{enabled, queried: true, own_mid})`.
- If the step returns `Held` or `Unreachable` and `own_mid` is `Some`, return `queued_text(..)` with the hold code. The message is safe in the retired session and the worker continues.

**4. Unreachable path.** `offline_send_target` (`:886`) uses `find_sendable_peer_session`. When every session with the peer is retired → `NOT SENT … (technical: PEER_RESET_UNREACHABLE)`: there is nothing to seal under, and earlier rows stay held.

**5. `raven outbox resend --contact X`.**
- New `OutboxCommands::Resend { contact }` in `cli.rs:477` → `pair_init_lab::resend_after_reset`.
- Steps:
  1. Probe the contact's routes.
  2. Take the lock.
  3. `store.confirm_peer_reset(peer, now)`.
  4. `run_reset_step(env{user_confirmed: true})`.
  5. `outbox_kick(peer)`.
  6. Print `{n} message(s) to {who} were sealed again and handed to raven-node.`
- With the gate off it prints `not available in this build`.

---

## 12. Outbox worker integration (`raven-node/src/outbox.rs`)

1. **Reset step first.** At the start of `attempt_peer_inner`, after contact admission (`:1331-1352`), when the gate is on and the peer has retired undelivered rows:
   - call `run_reset_step` with a `WorkerIo` that uses `PeerSendLock::acquire_within(LOCK_WAIT)` per `locked` call and `ctx.dialer.dial` for dials. Routes come from `plan_object_routes(None, contact, gates)`, filtered to `confidential_to_endpoint()`;
   - map the result:
     - `Resealed` → for each old digest, `report.outcomes[old] = Outcome::Resealed`;
     - `Held{code}` → every due entry in a retired session gets `Outcome::Held(code)`;
     - `Unreachable` → `Outcome::Unreachable{code: dial_error_code(..)}` for those entries.
2. **Missing-cert path (`:1405-1420`).** After the probe, if a session still has no bound cert and `load_cached_peer_bundle(peer)` returns a valid cert for `peer` with a different hash → `note_presented_cert` under the lock. Rows under the retired session become `Held(PEER_RESET)` with `next_due = now`, and the next attempt re-seals them.
3. **Lock A** (`:1449`). Run `reconcile_resealed_outbound` first. For a vanished entry, `finalize_vanished` (`:2136`) first checks `store.live_copy_elsewhere(peer, mid, entry.session_id)` → `Outcome::Resealed`.

   A row in a retired session is never a candidate: `Outcome::Held(PEER_RESET)` once, then the step's hold code. `newest` (`:1557`) becomes `find_sendable_session_for_peer`.
4. **Query after the dial loop, without the lock.** For each session with a Message candidate whose dial ended `PEER_REFUSED`, where the backoff allows: dial `session_query_frame` alone on the same route. Keep `(session_id, queried bytes, replies)`.
5. **Lock B** (`:1838`). Run `apply_query_replies` for each query. On `Retired`, candidates under that session get `Outcome::Held(code::PEER_RESET)`. The existing ACK loop is unchanged in 2a. The early return at `:1833` is unaffected, because queries only follow candidate dials.
6. **Bookkeeping.**
   - New variant `Outcome::Resealed`. `apply()` removes the entry: it does not move it to `done`, does not count a failure, and sets `self.refresh = true` so the next scan adds the new row with `next_due = now`.
   - Its message id is **never** pushed to `finished`, so `clear_object_routes` keeps the route record, which is keyed by mid and shared by the new copy.
   - `apply_outcome` gets a new arm: `Held(PEER_RESET)` sets `next_due = now` without backoff if `entry.last_error != PEER_RESET`; otherwise it backs off as usual, which bounds loops.
   - `status()` already prefers live entries (`:427-441`).
7. **SUPERSEDED** (`:1930-1953`) is unchanged and applies only to non-retired older sessions: old peers, or answers of `PRESENT` / `NoAnswer`.
8. **New `mod code` entries:** `PEER_RESET`, `PEER_RESET_CONFIRM`, `PEER_RESET_LOOP`, `PEER_IDENTITY_FORK`, `PEER_PREKEY_RESET`, `PEER_RESET_NO_BODY`, `RESEAL_CAP`, and for 2b `PEER_RESET_WAIT_PREKEY` and `PEER_RESET_CLOCK`.
9. **Log line** (counts only): `raven-node outbox: contact reset: retired=1 resealed=3 held=0 expired=0`.
10. **Triggers** are unchanged. A reset peer that dials us causes our attempt through `peer_seen` (`lan_direct.rs:344`).

---

## 13. Receiver-visible duplicates and history

- **`ChatHistory::upsert` (`chat_history.rs:548-577`), for direction `"in"` only.**
  - If the existing body is non-empty, keep it. If a new non-empty body differs, keep the first and `eprintln` `raven: chat history: a contact re-used a message id with different text; the first one is kept` (redacted). This is an integrity conflict, as in `ATSAM_ENDPOINT_TRANSACTION_V1`.
  - `created_at_ms = min(existing, new)` when both are > 0. That is today's final value for normal messages, because the poller writes the sender stamp ≤ the receive time; and a re-received copy does not move.
  - Direction `"out"` is unchanged.
- **`ash inbox` (`cli.rs:6606`).** Collapse rows with identical `(sender_device, message_id, plaintext)`, keep the earliest, and append the marker `(received again: the sender re-sent it after a connection reset)`. Rows with the same id and a different body are not collapsed.
- **Chat poller (`ext.rs` `peek_endpoint_inbox_for_contact`).** If `store.inbox_copies(sender, mid) > 1` and an earlier copy exists, print the marker line instead of the body.
- **Bounds.** At most 1 + 3 copies per message (§9.1, §9.4).

---

## 14. Phase 2b: restore from an older backup (own gate)

### 14.1 Receiver classification (read-only)

`classify_inbound_index(key, packed, now)` mirrors `prepare_receive_key` without mutating state (`indexed_session_store.rs:5921-5957`). It uses `message_receive` or `ack_receive` according to `env_type`:
- an exact receipt for the digest exists → `PRESENT`;
- `index < next_index` and the index is not in `skipped_keys` → `SENDER_STATE_STALE`;
- `index − next_index > MAX_FORWARD_JUMP` → `RECEIVER_STATE_STALE`;
- otherwise → `PRESENT`.

### 14.2 E3: stale ACK at the sealer

- **Typed rejection.** `outbox::AckRejected` gains `Stale(StaleKind)`, where `StaleKind` is `PeerSendStale` (store `Replay`) or `LocalReceiveStale` (`ForwardJumpTooLarge`). `accept_sealed_ack` maps them; everything else stays `Refused(String)`.
- **Worker, Lock B.** `Err(AckRejected::Stale(k))` → `retire_session(key, peer, LocalSawPeerSendStale | LocalReceiveStale, now)`. Candidates under that session → `Held(PEER_RESET)`.
- **ash.** `finish_outbound_delivered` returns a string prefixed with `PEER_SESSION_STALE:` for `Stale`. ash retires the session and restarts (§11 step 3).
- **Result.** Both sides of a restored pair converge without any extra notice:
  - the restored side sees its ACKs refused, via queries;
  - the other side sees stale ACKs.

### 14.3 PREKEY_STALE and PREKEY_STATUS

**Sender side.** In `run_reset_step` §9.3 step 3 (and the ash PairInit branch), when the pin refuses the offer:
1. Build kind 3 `{offered_bundle_hash = prekey_bundle_hash(offer.prekey), pinned}`.
2. Dial it alone on the same route.
3. Decode kind 4: `verify`, then `echoed_pinned == hash(pinned)`.
4. Act on the result:
   - `RENEWED` → re-probe (§9.3 step 1, at most once per step) → the offer passes the pin → PairInit;
   - `STALE_OFFER` → re-probe once;
   - `GENERATION_CAP`, `CLOCK_BEHIND`, `INVALID_PROOF` → `Held(PEER_RESET_WAIT_PREKEY | PEER_RESET_CLOCK)`;
   - a close or no answer → `Held(PEER_RESET_WAIT_PREKEY)`, transient.

Limits: ash sends at most one per user send. The worker sends at most one per peer per 10 min (in-memory backoff in `AttemptCtx`).

No reply RLB1 is ever parsed. The renewed bundle arrives through the next dial's own handshake offer, which `dial_session` binds and caches.

**Subject side** (`handle_inbound_rsr1`, kind 3, 2b gate on). It **always** replies with a kind 4:
1. Verify the frame (§6). `pinned = PrekeyBundle::from_json`. Require all of:
   - `pinned.identity_ed25519_pub == local identity key` (checked against `identity.public_key_bytes()`, separately from the subject device check);
   - `pinned.verify(now)`;
   - `pinned.device_id == PRIMARY_DEVICE_ID`.

   Otherwise → `INVALID_PROOF`.
2. `cur = PrekeyStore::fetch_valid(own, now)`. If `offered_bundle_hash != prekey_bundle_hash(cur)` → `STALE_OFFER`.
3. If `cur == pinned`, or the pin rule would accept `cur` over `pinned` (`cur.id > pinned.id && cur.created_at > pinned.created_at`) → `NO_CHANGE_NEEDED`. This makes the operation idempotent per proof.
4. **Headroom.** `actor.prune_expired(now)`. If `actor.status().retained_generations > MAX_PREKEY_GENERATIONS − 2` → `GENERATION_CAP`. One slot always stays free for routine rotation.
5. `created_at = max(now, pinned.created_at + 1, cur.created_at + 1)`. If that is more than `MAX_PREKEY_FUTURE_SKEW_MS − 60 s` ahead of now → `CLOCK_BEHIND`.
6. `rotate_local_prekey_locked(.., floor = Some((max(pinned.id, cur.id), created_at − 1)))`. It runs under `PEER_CACHE_LOCK` and uses the dry-run, then install, then publish order. The new id is `next_signed_prekey_id(actor.highest, cur.id, max(pinned.id, cur.id), now)`.
7. Append `{at_ms, from_id, to_id}` to `prekey_forced_renewals.json`: at most 8 entries, non-secret, atomic write.
   - If another forced renewal happened within `MAX_PREKEY_BUNDLE_LIFETIME_MS + PREKEY_RETENTION_GRACE_MS` (37 d), log the fork warning (§16).
   - `raven doctor` shows the last renewal.
8. Reply `RENEWED` with the new id.

There is **no age cap**. Renewal needs a bundle signed by the subject that beats its current one, so after a renewal only another instance of the identity can produce a new proof (a fork, which is logged). Headroom bounds slot use.

### 14.4 Why this fixes s16

The backup is taken seconds after P1 and is older than P2, which A pins.
1. The restored B offers P1, and A's pin refuses it.
2. A sends PREKEY_STALE carrying P2.
3. B checks that P2 is signed by B and beats P1, has headroom, and renews to P3 with id > P2 and created_at > P2.
4. A re-probes, pins P3, PairInits, and re-seals.

### 14.5 Restore shapes covered

| Backend | Restore | Effect | Covered by |
|---|---|---|---|
| locked-file (harness) | data dir to an older snapshot | ratchets roll back | 2b reasons 3/4 and E3 (s15); 2b PREKEY_STALE (s16) |
| macOS Keychain / Linux vault, same machine | SQLite rolled back; protected state current (`reconcile_metadata` forward-updates, `indexed_session_store.rs:6167-6187`) | sessions keep working; lost receipt rows can make B answer `SENDER_STATE_STALE` for an object it already holds | one re-pair and a deduplicated copy (A's undelivered state is fixed: it finally gets an ACK). Unit test `protected_state_newer_than_metadata_*` |
| Keychain / vault, new machine | protected items missing → `ProtectedStateMissing`, session-scoped | `NO_SESSION` (2a) | `missing_protected_state_answers_no_session` |

No claim of s15-style recovery is made for Keychain installs beyond these tests.

---

## 15. RDAP impact (the RDAP tree of that date)

- **No code or wire change.** `seal_app_payload_under_session` uses `find_sendable_session_for_peer`. When every session is retired it returns `ATSAM_SESSION_REQUIRED: the contact reset its session; a new one is set up the next time it is reachable directly`. `raise_fail_closed` (`team_agents/raven_ipc.py:553-562`) maps that to `AtsamSessionRequired`, never to `AtsamLineageRevoked`. `SessionRetired` from a race maps the same way (§10).
- **Body-less rows already sealed under a retired session** (RDAP's) are abandoned (store only) and end as the worker outcome `failed`, `last_error_code = PEER_RESET_NO_BODY`. That is visible through the existing `OutboxStatus` and `OutboxList` IPC. They are never silently pruned.
- **Documented contract.** RDAP delivers `envelope_b64` itself (`rdap.py:690-703`). Its own end-to-end ACK is the delivery signal, and it resubmits after `AtsamSessionRequired` or after no ACK.
- **`team_agents/selftest.py`.** Add one check next to the existing mappings (~line 330): the message above maps to `AtsamSessionRequired`, and `PEER_RESET_NO_BODY` is not mistaken for `AtsamLineageRevoked`.
- **IPC rule.** No new IPC keys. Only new `last_error_code` values.

---

## 16. UX text (exact; `{who}`, `{until}` and `{preview}` are the existing `SendCtx` helpers)

The prefixes scripts match stay: `status delivered`, `not delivered yet`, `NOT SENT`, `sent, delivery unconfirmed`.

- **Re-seal inside a send** (printed before the usual `status delivered — {who} confirmed receipt`):
  - non-chat: `{who}'s RAVEN no longer had your secure connection (it was reinstalled or restored from a backup). A new secure connection was set up and {n} waiting message(s) were sent again.`
  - chat: `  (new secure connection with {who}: {who}'s RAVEN was reset; {n} waiting message(s) re-sent)`
- **Background re-seal notice** (once, at the next send, chat or `outbox list` for that contact): `Note: {n} message(s) to {who} were sent again under a new secure connection {when}, after {who}'s RAVEN was reinstalled or restored.` `{when}` is on this computer's clock (`today at 14:05`, `yesterday at 09:10`), or `about 3 h ago` when its offset cannot be read; never UTC (cutoff pack CP.6).
- **`PEER_RESET_CONFIRM`:** `{n} earlier message(s) to {who} are on hold: {who}'s RAVEN lost your secure connection, and the new one could not be made on your local network, so RAVEN will not send them again by itself. If {who} confirms they reinstalled or restored RAVEN, run \`raven outbox resend --contact {who}\`; \`raven outbox cancel\` drops one. (technical: PEER_RESET_CONFIRM)`
- **When the contact replaced the connection itself** (Phase 6 review re-verify, sensing-1): the store finds a session the contact answered NO_SESSION about next to a newer sendable one the contact started under the same certificate (`IndexedSessionStore::contact_replaced_retired_session`: what an early security re-key there leaves, Phase 6b R2/R3; also a restore after which it set one up). Then no line says the contact lost the connection or asks whether it was reinstalled. It is no proof of a re-key, so held messages still wait for the person (P2):
  - `PEER_RESET_CONFIRM`: `{n} earlier message(s) to {who} are on hold: {who}'s RAVEN set up a new secure connection with you and no longer takes the older one they were sealed in, as it does after a security re-key or a restore. The new one was not made on your local network, so RAVEN does not send them again by itself until you are both on the same local network. To send them now, run \`raven outbox resend --contact {who}\` (after a re-key, {who}'s \`raven security\` says Raven set up a new secure connection with you); \`raven outbox cancel\` drops one. (technical: PEER_RESET_CONFIRM)`
  - re-seal inside a send, non-chat: `{who}'s RAVEN set up a new secure connection with you and no longer took the older one (as it does after a security re-key or a restore). {n} waiting message(s) were sent again under a new one; nothing needs doing.`; chat: `  (new secure connection with {who}: {who}'s RAVEN replaced the old one; {n} waiting message(s) re-sent)`
  - background re-seal notice: `Note: {n} message(s) to {who} were sent again under a new secure connection {when}, after {who}'s RAVEN replaced the old one (as it does after a security re-key or a restore).`
- **`PEER_RESET_LOOP`:** `{n} earlier message(s) to {who} are on hold: {who}'s RAVEN lost your secure connection {k} times today, so RAVEN stopped re-sending by itself. Ask {who} to run \`raven doctor\`, then run \`raven outbox resend --contact {who}\`. (technical: PEER_RESET_LOOP)`
- **`PEER_IDENTITY_FORK`:** `Warning: {who}'s Raven identity seems to be in use on two computers at once (one said it no longer has your connection while another kept using it). {n} earlier message(s) are on hold and will not be re-sent by themselves. Check with {who} in person or by phone; run \`raven outbox resend --contact {who}\` only if they confirm. (technical: PEER_IDENTITY_FORK)`
- **`PEER_RESET_UNREACHABLE`:** `NOT SENT: {who}'s RAVEN lost your secure connection and {who} cannot be reached right now, so there is no connection to queue this message under. Nothing was queued; send it again when {who} is online. (technical: PEER_RESET_UNREACHABLE)`
- **2b `PEER_RESET_WAIT_PREKEY`:** `not delivered yet: your message{preview} to {who} is queued locally because {who}'s RAVEN was restored from an older backup and has to renew its keys before a new secure connection can be set up. raven-node keeps trying until {until}; you do not need to send it again. (technical: PEER_RESET_WAIT_PREKEY)`
- **Old peer with a pin refusal** (2a, `PEER_PREKEY_RESET`, `NOT SENT`): `NOT SENT: {who}'s RAVEN was reinstalled or restored and offered keys older than the ones you already have for {who}. Newer RAVEN versions sort this out by themselves: ask {who} to update RAVEN. If you have verified {who}'s fingerprint by phone or in person you can instead run \`raven contact remove\` and add {who} again. Nothing was queued. (technical: PEER_PREKEY_RESET …)`
- **Per-message cap** (history `failed`): `it could not be delivered: {who}'s RAVEN lost the secure connection {n} times before confirming it; send it again if you still need it`.
- **Subject-side log and doctor (2b):** `raven: a contact still holds a prekey this computer signed but no longer has (normal after restoring RAVEN from a backup); a newer prekey was published.` When it happens twice within 37 days, add: `If you did not restore or reinstall RAVEN twice, your identity may be in use on another computer: run \`raven doctor\`.`
- **`raven outbox list` legend:**
  - `PEER_RESET`: `the contact's RAVEN lost the secure connection; being sent again under a new one`
  - `PEER_RESET_CONFIRM`: `on hold: waiting for you to confirm (\`raven outbox resend\`)`
  - `PEER_RESET_LOOP`: `on hold: too many connection resets today`
  - `PEER_IDENTITY_FORK`: `on hold: the contact's identity may be in use twice`
  - `PEER_RESET_NO_BODY`: `sealed by another app; it has to send it again`
  - `RESEAL_CAP`: `given up after repeated connection resets`
  - `PEER_RESET_WAIT_PREKEY`: `waiting for the contact to renew its keys`
  - `PEER_RESET_CLOCK`: `the contact's clock is behind; it cannot renew its keys`
- **`PEER_PREKEY_RESET` log text** (`lan_dispatch.rs:1066-1077`): insert `RAVEN asks the contact to renew it automatically when both sides support session reset;` before the existing manual advice.

---

## 17. Version compatibility

| A (sealer) | B (lost state) | Result |
|---|---|---|
| new | new | Full automatic recovery (s05, s05b-d, s17, s18). |
| new | old (or gate off) | B closes on queries as on any unknown frame. That is one `not RavenEnvelopeV1` log line per query, bounded by ash's one-per-send and the worker's backoff of 0/1/4/16/60 min. A falls back to today's behaviour (SUPERSEDED). If B has phase 1, its pin is accepted, so its new cert triggers E2 at A with no wire, and B-initiated pairing works. |
| old | new | **Byte-identical to today on the wire.** B never replies inline; RSR1 replies only answer queries, and old A never sends them. Old A also benefits from B's phase 1 (pin accepts). Scenario s20b checks that B pairing again does not leave old A blocked longer than today. |
| old | old | Unchanged. |

**SQLite.** The tables are additive and `user_version` is not bumped, so a downgrade works. An old binary ignores retirement: it may seal under a retired session again, and B closes as today.

**Lab switches across processes.** The lab switch is read per process. The harness sets it for both ash and raven-node.

---

## 18. Gates and rollout

`raven-core/src/session_reset.rs`:

```rust
pub const SESSION_RESET_PRODUCTION_ENABLED: bool = false;          // phase 2a
pub const SESSION_RESET_RESTORE_PRODUCTION_ENABLED: bool = false;  // phase 2b
const _: () = assert!(!SESSION_RESET_RESTORE_PRODUCTION_ENABLED || SESSION_RESET_PRODUCTION_ENABLED);
/// RAVEN_LAB_SESSION_RESET = 1 (2a) | 2 (2a+2b); debug builds only (pattern of pair_init::lab_test_a_enabled, pair_init.rs:28-37).
fn lab_session_reset_level() -> u8 { if !cfg!(debug_assertions) { return 0 } /* parse env */ }
pub fn session_reset_live_enabled() -> bool { SESSION_RESET_PRODUCTION_ENABLED || lab_session_reset_level() >= 1 }
pub fn session_reset_restore_live_enabled() -> bool {
    session_reset_live_enabled() && (SESSION_RESET_RESTORE_PRODUCTION_ENABLED || lab_session_reset_level() >= 2)
}
```

- The switch is independent of `RAVEN_LAB_TEST_A`, which the harness removes because it opens other carriers.
- **2a gate** covers:
  - RSR1 handling in `dispatch_frame`;
  - queries;
  - E2 retirement;
  - `run_reset_step` in ash, the worker and `outbox resend`;
  - FE1 notes;
  - inbox collapse and the history `"in"` rule.
- **2b gate** covers:
  - status reasons 3 and 4;
  - E3;
  - PREKEY_STALE and PREKEY_STATUS.
- **Always on:** the store tables, the guard (it has no effect while nothing is retired), `confirmed_at_ms` and `initiated_local` metadata, and phase 1.
- `lan_gate.rs::global_production_flags_stay_false` gains asserts for both consts until each flips.
- **New test `session_reset_lab_switch_is_inert_without_debug_assertions`:** when `!cfg!(debug_assertions)`, set the env to `2` and assert that `lab_session_reset_level() == 0`. It runs in the existing release test job.

**Rollout:**
1. **Phase 1 (release N, ungated).** §4 (time-floored ids and the rotation fallback). Record it in the LAN waiver change log.
2. **Phase 2a (release N, gated off).** §5-§13, §15 and §16 (2a parts).
3. **Phase 3 (release N+1).** The owner signs `docs/WAIVER_LAN_DIRECT_SESSION_RESET_AMENDMENT_DRAFT.md`, which records:
   - (1) RSR1 kinds 1 and 2 on LAN links, in dedicated dials only;
   - (2) automatic re-seal of undelivered plaintext into a new session. This deviates from P2a's "exact staged bytes, no new seal" (`docs/WAIVER_LAN_DIRECT_P2A_AMENDMENT_DRAFT.md:32-33`) and is allowed only on E1 or E2 evidence and only into a session we initiated over a local-network route (P2);
   - (3) PairInit started by the worker;
   - (4) the seed-compromise trade-off of I3;
   - (5) the caps in §20.

   Preconditions: the §21.3 matrix, 2a rows, green 5× on macOS and Linux with locked-file backends, plus one manual Keychain run of s05 and s05d on macOS. Then flip `SESSION_RESET_PRODUCTION_ENABLED`.
4. **Phase 4.** Same for 2b: a second amendment covering forced prekey renewal on proof, with the 2b harness rows green. Then flip the restore const.
5. **Carrier gates are unchanged.** RSR1 and re-sealed copies travel only on live direct carriers (`CarrierGates`). Under the HOLD that means LAN.

---

## 19. When more carriers open

- **Internet direct and p2p.** No change to mechanisms. Both listeners call `dispatch_frame`, and the worker's `Dialer` covers them. P2 keeps automatic re-seal local-network-only: remote contacts get `PEER_RESET_CONFIRM` (open question 5).
- **Mailbox and store-and-forward.** Re-sealed copies must only use carriers with `confidential_to_endpoint() == true`.
  - Today every `OutboxCarrier` qualifies (`raven-core/src/outbox.rs:479-483`). The worker filter and a `debug_assert` keep that true when custody carriers are added.
  - Before any custody carrier exists, the logical id must move inside the AEAD payload under a versioned profile, with a fresh outer id per copy. Otherwise a custodian could link the old and new sessions by the clear outer `message_id` (`bridge.rs:65-69`).
  - B cannot fetch envelopes for a session it lost, so a proactive `RETIRED_BEFORE` notice would need a new RSR1 kind with a version bump. That is not in v1.
- **Session renewal (Phase 3 item 4).** Renewal (`raven-core/src/session_renewal.rs`, `raven-node/src/renewal.rs`, behind `SESSION_RENEWAL_PRODUCTION_ENABLED`) starts an ordinary PairInit V1 on a live, endpoint-authenticated link before a session ends. It never retires a session and never re-seals: queued rows keep their session and deadline, and the old and new sessions overlap until the old one expires. It yields to this design's reset step while the contact has rows in retired sessions (`RENEW_RESET_PENDING`), and stops on fork evidence (FE1), a reset loop and a prekey pin refusal. A renewed session made over a local-network route is a re-seal target (§9.2), like any local session.

---

## 20. Constants (`session_reset.rs`) and what they bound

| Constant | Value | Bounds |
|---|---|---|
| `RESET_NO_SESSION_MIN_AGE_MS` | 60 000 | race with a peer-initiated session the peer has not yet confirmed (our role Responder) |
| `RESET_FORK_GRACE_MS` | 60 000 | in-flight traffic around a retirement before FE1 counts |
| `RESET_FORK_HOLD_MS` | 86 400 000 | how long FE1 holds automatic handling (cleared by `outbox resend`) |
| `RESET_MAX_AUTO_ROUNDS_PER_DAY` | 3 | automatic PairInit and re-seal rounds per peer per 24 h (derived from the sidecar) |
| `RESET_MAX_RESEALS_PER_MESSAGE` | 3 | copies: at most 4 of one message ever exist (persisted ledger) |
| `RESET_PAIRINIT_COOLDOWN_MS` | 60 000 | crossed or duplicate rounds; claim slots at the peer (`MAX_ACCEPTED_PREKEY_CLAIMS_PER_INITIATOR` = 32) |
| `RESET_TARGET_MIN_REMAINING_MS` | 600 000 | re-seal targets about to expire |
| `RESET_RESEAL_MIN_REMAINING_MS` | 30 000 | copies that could not be delivered in time (→ `expired`) |
| worker query backoff | 0, 1, 4, 16, 60 min per (peer, session) | dedicated dials and old-peer log lines |
| worker PREKEY_STALE backoff | 10 min per peer | same |
| `RSR1_MAX_FRAME` | `MAX_TRANSPORT_PLAINTEXT` | frame size |
| `RSR1_MAX_PINNED_JSON` | 8 192 | kind 3 size |
| `FORCED_RENEWAL_MIN_FREE_GENERATIONS` | 2 | routine rotation always keeps a slot |
| log interval | 1 h per peer | receiver, subject and worker log lines |

Session renewal (§19) creates its sessions with `reset_round = false`: they never count toward `RESET_MAX_AUTO_ROUNDS_PER_DAY` or `RESET_PAIRINIT_COOLDOWN_MS`. Renewal has its own per-contact re-pair budget (4 rounds per 24 h, 60 s apart, `session_renewal.rs`), and a compile-time check keeps renewal, the reset step and the app channel together below `MAX_ACCEPTED_PREKEY_CLAIMS_PER_INITIATOR`.

Every trigger also needs the contact's key on a Noise-authenticated link. Everything else is already bounded by the existing inbound limits (`max_frames` 64, the 120 s lifetime, per-IP caps; `main.rs:~775`).

---

## 21. Test plan

### 21.1 Phase 1 unit tests

- **`prekey_lifecycle.rs`**
  - `next_signed_prekey_id_takes_max_of_counter_published_floor_and_clock`. It also covers a clock running behind, the same second (+1), and overflow → `ResourceLimit`.
- **`lan_dispatch.rs`**
  - `reinstalled_contact_with_time_ids_is_pinned_and_paired`: fresh dir, same seed, a later second; the pin accepts and `create_initiator_pair_init` succeeds.
  - `legacy_counter_pin_accepts_a_time_id_bundle`.
  - **Security:** `replayed_old_signed_bundle_is_still_refused`.
    - Pin P2, offer P1 → ROLLBACK.
    - P2' with the same id and other keys → EQUIVOCATION.
    - A higher id with an older `created_at` → ROLLBACK.
  - `failed_due_rotation_keeps_serving_the_current_bundle`. Fill the actor to 4 generations, make rotation due, and check that `local_bundle` still returns `Ok` and logs once.
  - Updated: `ensure_local_prekey_never_reuses_a_published_id` (id `> 5 && >= time_floor`) and `concurrent_ensure_local_prekey_rotates_exactly_once`.
  - Kept: `contact_that_reset_its_prekey_counter_stays_reachable_but_gets_no_new_session`, as the old-peer case.
- **`ext.rs`**
  - `prekey_publish_after_state_loss_uses_time_floor`.

### 21.2 Phase 2a unit tests

**`session_reset.rs` (codec)**
- Roundtrip for kinds 1 and 2.
- KAT files `shared-vectors/rvn1/session_reset/rsr1_session_query_001.json` and `rsr1_session_status_001.json`: fixed seeds, exact signing bytes, signature.
- Negatives:
  - wrong magic;
  - version 2 and kind 9 → `Unsupported`;
  - truncated input; one trailing byte;
  - status 0 and status 5;
  - `envelope_len` 85 and too large;
  - a bad signature;
  - signer ≠ expected; subject ≠ local.
- `created_at_ms` years off is still accepted, because it is only informational.
- Domain separation: a PairResponse or ACK signature over the same bytes does not verify.
- `fuzz_smoke.rs`, plus the new target `node/fuzz/fuzz_targets/rsr1_frame.rs`.
- `carrier_admission`: `rsr1_is_refused_custody`.

**`indexed_session_store.rs`**
- `retire_is_idempotent_and_send_side_only`: the sendable list excludes the session; inbound messages and ACKs are still accepted; `enqueue_committed_ack` still works.
- `message_seal_retry_resend_under_retired_session_fail_with_session_retired`: all 5 guard sites; ACKs are unaffected.
- `reseal_keeps_message_id_new_session_new_digest`.
- `reseal_into_session_that_already_has_the_id_is_refused`.
- `retire_outbound_copy_keeps_outstanding_so_a_late_ack_settles`.
- `reseal_ledger_survives_prune_of_the_original_session`.
- `retired_sidecar_cascades_on_raw_head_delete`: simulates an old binary pruning.
- `metadata_schema_version_stays_1`.
- `confirmed_at_written_for_both_roles`.
- `find_sendable_newest_first_matches_confirmed_order`.
- `match_inbound_session_is_read_only` (protected generation and SQLite rows unchanged).
- `missing_protected_state_answers_no_session`.
- `fork_evidence_only_for_initiator_role_after_grace`.

**`lan_dispatch.rs` (dispatch, two in-process dirs)**
- `query_for_lost_session_gets_signed_no_session`. B wiped. The reply verifies under B, and the echo equals the digest and mid. B's store, inbox and history are byte-unchanged.
- `query_for_live_session_gets_present`.
- `envelope_frames_still_close_without_reply_when_gate_on`. The message to a lost session gets `Err` and no frame (I9). The test uses today's exact error string.
- `stranger_query_is_refused_and_gets_no_rsr1` (I5).
- `query_with_foreign_signed_envelope_is_refused` (C's envelope inside A's query).
- `query_store_wide_error_closes_instead_of_no_session` (fault-injected protected backend; I6).
- `unknown_rsr1_version_or_kind_is_dropped_without_closing`.
- `gate_off_rsr1_frame_errors_exactly_as_today`.

**`session_reset.rs` (sealer)**
- `status_retires_only_the_echoed_session`.
- `status_for_delivered_or_unknown_object_is_ignored`.
- `status_signed_by_another_contact_cannot_retire`.
- `young_responder_session_is_transient_initiator_is_definitive`.
- `young_responder_fallback_without_confirmed_at_is_bounded`.
- `presented_cert_renewal_retires_sessions_bound_to_other_certs`.
- **Security:** `revoked_lineage_recertified_under_new_device_id_is_not_retired_or_repaired`.
- `reseal_preserves_order_and_original_deadline`.
- `expired_original_deadline_is_marked_expired_not_resealed`.
- `revoked_target_lineage_is_not_resealed`.
- `bodyless_row_is_abandoned_as_peer_reset_no_body`.
- `reseal_hands_off_a_leftover_prepared_row_first`.
- **Policy:**
  - `automatic_reseal_only_into_own_local_initiated_session`;
  - `peer_initiated_twin_is_never_a_target`;
  - **Security:** `seed_only_impersonator_on_non_local_route_gets_no_plaintext`. A pinned contact routed at `203.0.113.5:7420` must end as `Held(PEER_RESET_CONFIRM)`, with zero re-sealed rows, and no PairInit dial carrying a re-sealed row.
  - `user_confirmed_resend_reseals_over_non_local_route`;
  - `fork_evidence_holds_automatic_reseal_until_confirmed`;
  - `third_round_in_24h_holds_loop_and_does_not_fail_history`;
  - `per_message_cap_only_after_user_confirmation`.
- `late_ack_on_old_session_settles_resealed_sibling_and_vice_versa`.
- **Crash injection.** Add `#[cfg(test)] ResealFault { AfterLedger, AfterW1, AfterW2 }` and the existing `EndpointFaultPoint`, then run `reconcile_resealed_outbound`. Expect exactly one live copy, history never `failed`, and the stage bound to the live copy.
- `reconcile_settles_siblings_after_listener_ack`.
- `seal_app_payload_under_session_reports_session_required_when_all_retired`, plus the `SessionRetired` race mapping.

**`chat_history.rs`**
- `inbound_upsert_keeps_first_body_and_earliest_created_at`.
- `outbound_upsert_unchanged`.

### 21.3 raven-node, ash and RDAP

- **`main.rs` netutil:** `rsr1_query_and_prekey_stale_expect_a_reply`, `rsr1_status_replies_are_terminal`, `old_collector_semantics_unchanged_for_rvn1`.
- **`lan_direct.rs` (duplex Noise):** `listener_answers_session_query`, `stranger_query_sees_only_close`.
- **`outbox.rs`.** `FakeNet` gets:
  - mode `STRICT`, which mirrors the listener: stop at the first dispatch `Err` and return `LAN_DIAL_PEER_CLOSED` when no reply beyond the offer arrived, as `main.rs:654-680` does;
  - a `wipe_bob()` helper: delete B's session store, prekey store and lifecycle files with the same backends, then `ensure_local_prekey`;
  - optionally a fresh cert (`fresh_cert: bool`).

  Tests:
  - `worker_recovers_wiped_peer_without_a_new_send` (query → retire → round → re-seal → deliver);
  - `worker_recovers_fresh_cert_peer_via_e2_without_any_rsr1`;
  - `worker_reset_plans_from_its_own_probe_offer_not_the_pinned_bundle` (C2-M3);
  - `worker_sends_rsr1_only_alone`, asserting on `log` frame counts;
  - `resealed_entries_keep_route_records_and_status_shows_live_copy`;
  - `peer_reset_immediate_retry_happens_once_then_backs_off`;
  - `worker_holds_loop_after_three_rounds`, using sidecar rows with injected timestamps; and that it resumes after a store-level `confirm_peer_reset`;
  - `fork_two_instances_same_seed_hold_and_warn`: two B dirs from one seed, A initiator;
  - `old_peer_refusal_keeps_superseded_rule` (mode `REFUSE`, no answer);
  - `send_lock_not_held_across_reset_dials` (`lock_probe`);
  - `crossed_pairing_during_reset_converges`.
- **`ash/tests/ux_send_chat.rs`** (`Net` already maps a dispatch `Err` to `PEER_CLOSED`, `:758-762`). Add modes `WIPED` and `FRESH_CERT`. Tests:
  - `a_send_to_a_reinstalled_contact_is_delivered_with_the_reset_line`;
  - `a_send_to_a_fresh_cert_contact_pairs_again_without_not_sent`;
  - `send_while_retired_rows_wait_is_not_blocked_and_names_them`;
  - `restarted_send_reports_its_own_message_once`;
  - `unreachable_with_only_retired_sessions_says_not_sent_with_reset_text`;
  - `outbox_resend_releases_held_rows`;
  - `inbox_and_chat_collapse_resent_copies_with_marker`;
  - `gate_off_output_is_byte_identical` (golden).
- **RDAP:** the §15 selftest checks.

### 21.4 Phase 2b unit tests

- `classify_inbound_index_is_read_only_and_matches_accept_verdicts`. Snapshot, then compare with `accept_message_envelope` on a copy.
- `restored_sender_index_reuse_answers_sender_stale`.
- `restored_receiver_far_behind_answers_receiver_stale`.
- `stale_ack_retires_locally_and_reseals` (E3).
- `prekey_stale_with_own_bundle_renews_above_and_peer_pin_accepts`.
- `prekey_stale_repeated_is_no_change_needed`, for idempotence.
- `prekey_stale_with_foreign_expired_or_not_newer_bundle_is_invalid_or_no_change`.
- `prekey_stale_mismatched_offer_hash_is_stale_offer`.
- `forced_renewal_needs_two_free_slots`.
- `routine_rotation_succeeds_after_max_forced_renewals`.
- `forced_renewal_clock_behind_is_reported`.
- `prekey_status_always_answers`.
- `restore_backup_younger_than_six_hours_renews_immediately`.
- `protected_state_newer_than_metadata_*` (Keychain shape, §14.5).
- `second_forced_renewal_within_37_days_logs_fork_warning`.

### 21.5 Real-process harness (`scripts/lan_fault_matrix.py`)

Changes to the harness:
- Add `--old-bin DIR`. Set `RAVEN_LAB_SESSION_RESET=1` for 2a rows and `=2` for 2b rows, for ash and raven-node alike.
- New helper `wipe(node, keep=(...))`, which takes the keep-set per scenario.
- Every row asserts:
  - exactly-once in the receiver's inbox;
  - at most one marked duplicate;
  - no `failed` or `expired` sender rows unless the row says otherwise;
  - no panics in either node log.
- Clock and crash scenarios are covered in process (§21.2-21.3), so the harness needs no hooks.

| id | Steps | Pass |
|---|---|---|
| s05 (2a) | as today (keeps `device_*`) | the following `ash send` prints the reset line and `status delivered`; B's log has the session-check line once; A has no `PEER_PREKEY_RESET` |
| s05b | warmup; stop B; A sends q1-q3 (queued); wipe B; publish; start B; `a.ash('outbox','retry')` | q1-q3 delivered once, in order, within 60 s; `outbox list` all `delivered` |
| s05c | as s05b, but B sends `bob-first` before any action by A | `bob-first` delivered; q1-q3 delivered with no new send from A (through `peer_seen`) |
| s05d (E2) | as s05, but also delete `device_registry.json` and `device_x25519.*` (new cert) | `status delivered` on the following send; A's log has no `NO_PEER_CERT` hold; no RSR1 needed (A's log has no session-check query) |
| s17 | B queues for A while A is stopped; wipe A (keep identity, contacts); start A; `b.ash('outbox','retry')` | B's queued messages delivered once |
| s18 | wipe B; A and B send at the same time ×5 | all delivered once; sessions per side ≤ 4 |
| s19 | `--old-bin` for B; wipe B; A sends | same outcome as an old/old run (QUEUED); A not `failed` earlier than today; B's log shows at most one unknown-frame line per send |
| s20 | `--old-bin` for A; wipe B; A sends | outcome identical to an old/old run (byte-compare the status word); no crash |
| s20b | `--old-bin` for A; wipe B; B sends to A (B pairs again); A sends twice | A's second send is `status delivered`, no later than in an old/old run |
| s22 | wipe B 4×, A sends after each | sends 1-3 print the reset line; send 4 prints `PEER_RESET_LOOP`, history not `failed`; `a.ash('outbox','resend','--contact','@bob')` → delivered |
| s15 (2b) | warmup + m1; stop B, snapshot B; start; m2, m3 delivered; B sends b1; stop B; restore the snapshot; start; A sends m4; B sends b2 | all delivered; A's history has b1 and b2 once; at most one marked duplicate at either inbox |
| s16 (2b) | B init + publish P1; snapshot; B `prekey publish` (P2); pair (A pins P2) + warmup; stop B; restore; start; A sends | `status delivered` within one send or ≤ 60 s through the worker; B's log has the renewal line; A's pinned id > P2 |

---

## 22. Change list by file

**raven-core**
- `src/prekey_lifecycle.rs` (P1): `PREKEY_ID_TIME_EPOCH_MS`, `time_floor_signed_prekey_id`, `next_signed_prekey_id`.
- `src/lan_dispatch.rs`:
  - (P1) `ensure_local_prekey` → `rotate_local_prekey_locked`, time-floored ids, rotation fallback.
  - (2a) `dispatch_frame` RSR1 branch.
  - (2a) `pair_with_peer` (extracted from ash).
  - (2a) `find_sendable_peer_session`.
  - (2a) `seal_app_payload_under_session` uses sendable sessions.
  - (2a) `map_seal_store_error` + `SessionRetired`.
  - (2a) FE1 notes in `handle_indexed_message` and `handle_ack`.
  - (2a) `peer_prekey_policy_error` text.
  - (2b) `pinned_peer_bundle_refusing`, `renew_local_prekey_above`.
- `src/session_reset.rs` (new):
  - gates, constants, codec, sign and verify;
  - `handle_inbound_rsr1`;
  - `session_query_frame`, `apply_query_replies`;
  - `note_presented_cert`, `bound_offer`;
  - `ResetEnv`, `ResetIo`, `run_reset_step`;
  - `reseal_retired_outbound`, `reconcile_resealed_outbound`;
  - (2b) kind 3 and 4 handling, `note_stale_ack`.
- `src/indexed_session_store.rs`:
  - 3 tables;
  - `SessionRetireCause` and `SessionRetired`;
  - the §10 methods;
  - shared `seal_message_inner`;
  - `refuse_retired_message_lane` at 5 sites;
  - `confirmed_at` in `confirm_verified_pair_response`;
  - ledger prune;
  - (2b) `classify_inbound_index`.
- `src/outbox.rs`: FE1 note in `accept_sealed_ack`; (2b) `AckRejected::Stale`.
- `src/chat_history.rs`: the `"in"` upsert rule.
- `src/lan_gate.rs`: flag asserts and the release lab-switch test.
- `src/lib.rs`: exports.
- `tests/fuzz_smoke.rs`; `node/fuzz/fuzz_targets/rsr1_frame.rs`.

**raven-node**
- `src/main.rs`: RSR1 in `expects_reply` and `is_terminal_reply`.
- `src/outbox.rs`:
  - `WorkerIo`, reset step, queries, Lock B apply;
  - `Outcome::Resealed`, `PEER_RESET` arm, codes;
  - sendable `newest`;
  - missing-cert E2;
  - `AttemptCtx` backoff maps;
  - `FakeNet` `STRICT` mode, `wipe_bob`, tests.

**ash**
- `src/pair_init_lab.rs`: pre-pass; `SendReset`; refusal hook and restart; `own_mid`; the PairInit branch → `pair_with_peer`; sendable lookups; `resend_after_reset`.
- `src/ext.rs`: (P1) time-floored publish; `say_peer_reset`, `say_reset_held`, `say_unnotified_reseals`; texts; chat poller marker.
- `src/cli.rs`: `OutboxCommands::Resend`; inbox collapse; legend; `cmd_doctor` lines (fork evidence and held rows per contact; last forced renewal).
- `tests/ux_send_chat.rs`: new modes and tests.

**RDAP**
- `team_agents/selftest.py`: the mapping checks.

**Docs and protocol**
- `protocol/RAVEN_SESSION_RESET_V1.md` (new, normative §6-§8, §14.3; informative note that `ATSAM_ENDPOINT_TRANSACTION_V1` is unchanged because the receiver's envelope path is untouched).
- `protocol/PROTOCOL_VERSIONS.md` (RSR1 v1).
- `protocol/RAVEN_ERROR_CODES_V1.md` (§23).
- `docs/PROTOCOL_FREEZE_HASHES_V1.md`, regenerated with `scripts/freeze_protocol_hashes.sh`.
- `docs/WAIVER_LAN_DIRECT_SESSION_RESET_AMENDMENT_DRAFT.md`.
- `shared-vectors/rvn1/session_reset/*.json`.
- `scripts/lan_fault_matrix.py` (§21.5).

`RAVEN_PREKEY_BUNDLE_V1.md`, `RAVEN_PREKEY_LIFECYCLE_V1.md` and `ATSAM_ENDPOINT_TRANSACTION_V1.md` are **not** edited.

---

## 23. Error and status codes (stable strings)

| Code | Where | Meaning |
|---|---|---|
| `PEER_RESET` | outbox | session retired; re-seal pending (transitional) |
| `PEER_RESET_CONFIRM` | outbox, ash | held: no local-network route for automatic re-seal; needs `outbox resend` |
| `PEER_RESET_LOOP` | outbox, ash | held: 3 automatic rounds in 24 h |
| `PEER_IDENTITY_FORK` | outbox, ash, doctor | held: fork evidence FE1 |
| `PEER_PREKEY_RESET` | outbox, ash (existing prefix) | pin refuses the contact's bundle; no renewal possible (old peer or 2b off) |
| `PEER_RESET_UNREACHABLE` | ash | NOT SENT: every session retired and the contact is unreachable |
| `PEER_RESET_NO_BODY` | outbox (`failed`) | body-less (RDAP) row in a retired session |
| `RESEAL_CAP` | outbox (`failed`), history `failed` | per-message re-seal cap |
| `PEER_RESET_WAIT_PREKEY`, `PEER_RESET_CLOCK` | outbox, ash (2b) | waiting for the contact to renew its prekey; its clock is behind |
| `PEER_SESSION_STALE` | internal ash prefix (2b) | ACK refused as `Replay` or `ForwardJumpTooLarge` |
| `SessionRetired` → `ATSAM_SESSION_REQUIRED: the contact reset its session; …` | store, IPC `SealUnderSession` | no sendable session |
| `RSR1_MALFORMED`, `RSR1_WRONG_SIGNER`, `RSR1_WRONG_SUBJECT`, `RSR1_BAD_SIGNATURE`, `RESET_ECHO_MISMATCH`, `RESET_UNKNOWN_ECHO`, `RESET_ALREADY_DELIVERED`, `RESET_TRANSIENT_YOUNG_SESSION`, `PEER_HAS_SESSION` | debug log only | notice or answer ignored, or transient |
| `PREKEY_RENEWED_FOR_CONTACT`, `PREKEY_GENERATION_CAP`, `PREKEY_RENEWAL_CLOCK_BEHIND`, `PREKEY_STALE_OFFER`, `PREKEY_INVALID_PROOF` | subject log (2b) | outcome of PREKEY_STALE |


## Open questions

- Automatic re-seal policy (I3/P2), an owner decision. Default: re-seal automatically only into a session we initiated over a local-network LAN route, and otherwise hold for `raven outbox resend`. Residual risk: an attacker who holds the contact's seed and is on the same local network gets the undelivered backlog; today the same attacker gets every future message. Alternatives: always ask (most conservative, but s05 then needs a user action) or always automatic (weakens the backlog protection).
- Caps: 3 automatic rounds per contact per 24 h and 3 re-seals per message (at most 4 copies). Are these acceptable, given that a 4th reinstall in one day needs one `raven outbox resend`?
- PEER_IDENTITY_FORK only holds the old backlog and warns; new messages still flow as today. Should a suspected fork also block new sends to that contact until the user confirms?
- Should Phase 2b (restore from an older backup: stale-state reasons, stale-ACK retirement, forced prekey renewal on proof) ship in the HOLD era, or wait until 2a has field data? It needs a second waiver amendment.
- When Internet direct or p2p open, should automatic re-seal extend to verified (pinned) contacts reached over those carriers, or stay local-network-only with confirmation for remote contacts?
- RSR1 frames are Ed25519-signed even though they only ride Noise-authenticated links (64 bytes and one verify per frame). The point is that ash checks daemon-relayed replies without trusting the daemon's link binding. Confirm, or drop the signatures in favour of Noise-only authentication.
- Inbox: collapse identical re-sent copies with a marker (chosen), or show every copy?
- RDAP: is reporting PEER_RESET_NO_BODY through the existing OutboxStatus/OutboxList IPC enough, or should SealUnderSession callers get a push or a dedicated field?
- Phase 3 precondition: is one manual macOS Keychain run of s05 and s05d enough on top of the locked-file harness matrix, or is a Linux vault run also required?
