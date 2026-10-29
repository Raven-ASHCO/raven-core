# Friend Custody V1, revision 2: encrypted store-and-forward through a friend's node ("via a friend")

| | |
|---|---|
| **Status** | Design for implementation, revision 2. It resolves both critiques of revision 1. It is not normative until `protocol/RAVEN_FRIEND_CUSTODY_V1.md` (new) has been reviewed. It changes no frozen byte. |
| **Date** | 2026-10-15 |
| **Tree read** | the Raven tree of that date (`feature/reliability-and-mesh`) (staged fixes) and the RDAP tree of that date. Every `file:line` below was re-checked in this tree. |
| **Extends** | `docs/design/2026-10-transports-internet-mesh-bridge.md` §2.6, §4.4, §4.7 and §4.8. It reduces P2b/P4 there to **one custody hop through a mutual friend**. |
| **Owner constraints** | The LAN-only HOLD stays in place. Reliability must hold in every scenario. Security must not be weakened. Everything must be tested. No new crypto. Smallest change set that reaches the goal. |

Paths use this shorthand: `core/` = `node/crates/raven-core/src/`, `rn/` = `node/crates/raven-node/src/`, `ash/` = `node/crates/ash/src/`, `proto/` = `protocol/`.

---

## 0. Summary

**Mechanism.** Each step reuses an existing primitive.

1. **RFC1 frames.** These are versioned custody frames inside the **existing** authenticated Raven link (Noise XX, signed bind, RLB1, contact-gated responder).
   - They carry **RSO1 Store Object V1 records** (`core/store_object.rs`, `proto/RAVEN_STORE_OBJECT_V1.md` §3) holding the exact sealed envelope.
   - Fetch pagination uses the frozen Mailbox V1 page token (`proto/RAVEN_MAILBOX_TRANSPORT_V1.md` §2).
   - There is no new port, handshake or crypto.
2. **Custodian (Carol).** Carol keeps sealed RVNA1 `0x03` messages and ACKs and nothing else. A DEPOSIT is accepted only if all of these hold:
   - the depositor is a pinned contact and is the envelope's **outer signer**;
   - the recipient is a pinned contact of Carol;
   - the hop fields have their canonical outbound values;
   - the custody gate is open **for that link's carrier and source**.

   Each object is bound to `(recipient, store_tag)`, and only the link-authenticated recipient can FETCH it or RELEASE it. RELEASE hides the object for that recipient. The payload is deleted at TTL only (errata rule 9 unchanged).
3. **Sender (Alice).** The outbox worker adds a custody phase. It hands the **exact staged bytes** to the contact's chosen custodians (at most 2) when both of these hold:
   - direct delivery failed, or no direct route exists;
   - the message is at least 60 s old.

   Which custodians already hold a message is saved in the message's route record (`custodians_held`), not inferred from `unsent`. A deposit is FORWARDED. It is never delivered.
4. **Recipient (Bob).** A supervised fetcher presents Bob's inbound mailbox store tags and pages through his objects with a cursor. Each object goes through a sender-agnostic relayed ingest, which:
   - uses **exactly the session that the tag names**;
   - checks the outer signature cheaply before any protected load;
   - reuses `accept_message_envelope` / `accept_ack_envelope` unchanged.
5. **Durable owed ACKs.** Bob's sealed ACK for a relayed message is written to a durable SQLite table before the object is released. That table has no eviction and pushes back when full. The worker then pushes the ACK to Alice directly, or leaves it with Bob's custodians for Alice. The same table makes today's in-memory F8 path crash-safe.

**Gates.**
- `FRIEND_CUSTODY_PRODUCTION_ENABLED=false` and `FRIEND_CUSTODY_WAN_ENABLED=false` (new `core/custody_gate.rs`).
- Debug lab unlock: `RAVEN_LAB_TEST_A=1`. WAN custody in the lab also needs `RAVEN_LAB_CUSTODY_WAN=1`.
- Both ends enforce the gates per link.
- Under the HOLD, custody runs over LAN links from local-network addresses only.

**Honest limit.** Custody only works within an existing session, and sessions this node initiates last 24 h (`core/lan_dispatch.rs:1929`). A first contact through a friend needs a sealed asynchronous PairInit, which is deferred (§13).

---

## 1. Changes from revision 1 (resolution of every critique issue)

| # | Critique issue (severity) | Resolution | Section |
|---|---|---|---|
| A1 | RELEASE authority was a bearer tag that co-custodians also hold (major) | DEPOSIT carries `recipient[32]`. FETCH and RELEASE match on `recipient == link peer` **and** the tag. RELEASE never deletes in V1 (it only hides the object for its recipient), so the payload goes only at TTL. Tests: a co-custodian FETCH returns 0 objects and a co-custodian RELEASE releases 0. | §5, §6.5 |
| A2 | Global dedup on `authenticated_object_digest`, no signer check, hop fields not checked (major) | **Verified:** `signing_bytes` zeroes `dest_device_hint`, `hop_limit` and `replication_budget` (`core/envelope.rs:236-250`). `admit_relayable` checks none of them (`core/carrier_admission.rs:120-170`). `DeviceHintMismatch` fires before the route check (`core/indexed_session_store.rs:2833` vs `:2842`). **Fix:** DEPOSIT requires `env.verify(link_peer)` and the canonical values `hint=0`, `hop=8`, `budget=2` (`core/indexed_session_store.rs:105-106`, `:4434`). The custody digest is SHA-256 of the exact bytes (Conformance §2.2). The same digest under a different tag or recipient is refused as `CONFLICT` and never overwritten. The fetcher drops objects whose hop fields are not canonical. | §6.4, §8.2 |
| A3 | WAN split enforced only by requesters (major) | **Verified:** `dispatch_frame` has no carrier or source argument (`core/lan_dispatch.rs:1618`), and `internet_direct` and p2p call it the same way (`rn/internet_direct.rs:499`, p2p through `serve_inbound_on` at `rn/p2p.rs:532`). **Fix:** new `dispatch_frame_on(.., InboundLink{carrier, source})`. Carol replies `HOLD` unless `custody_link_allowed(...)`. LAN custody needs a local-network source while WAN is off. §14 F2 is corrected accordingly. | §6.1, §14 |
| A4 | Per-tag cap shared by all depositors (major) | The cap is now per **(depositor, recipient)**, plus per-depositor and node caps. Over-quota deposits are refused, never evicted. Junk under a known tag fails Bob's cheap signature pre-check, so it costs no protected load. | §6.3, §8.2 |
| A5 / B4 | FETCH head-of-line starvation (major ×2) | FETCH carries the Mailbox V1 cursor (`has_after‖after_token`). Rows are sorted by page token. The fetcher resumes from its saved cursor across rounds, and peers in a per-peer backoff are left out of FETCH. Test f6. | §5, §8.1 |
| A6 / B3 | Owed-ACK duplicate path skips the callback; eviction loses ACKs (major ×2) | **Verified:** a Queued intent returns early with no callback (`core/indexed_session_store.rs:2297-2304`). **Fix:** relayed ingest calls `record_owed_ack` explicitly when the callback did not run. The new SQLite table never evicts. Ingest checks capacity first and returns `Retry(OWED_ACK_FULL)`, which is back-pressure and releases nothing. Rows are rebuilt from the store only after corruption, and rebuilt rows are push-only. | §9 |
| A7 / B5 | `unsent` gating is not crash-safe, kills redundancy, and has no rule for ACKs (major ×2) | **Verified:** `unsent` is cleared before the dial and restored after it (`rn/outbox.rs:1738-1751`, `:1875-1887`). **Fix:** `ObjectRoutes.custodians_held` is persisted only after `STORED`/`DUPLICATE`, and eligibility is per custodian. `unsent` keeps its UI and cancel meaning only. ACKs get their own rule (§7.2). | §7 |
| B1 | The custody phase never sees objects with no direct route (major) | **Verified:** `routes.is_empty()` leads to `Held` and `continue` before `capture` (`rn/outbox.rs:1587-1612`, ACKs `:1611-1615`). **Fix:** a message or ACK that can use custody is captured even with `routes=[]`. A `Deposited` branch comes before the `routes_left == 0 → Held` mapping (`:1957`). Tests w10-w13. | §7.3 |
| B2 | ACK eligibility contradicts the data model; F8 ACKs have no session (major) | ACK rule is independent of `ObjectRoutes`. New read-only `outbound_session_for_object(digest)`. A Prepared ACK row that was handed to a custodian becomes Queued through the owed-ACK callback and maps to `AckSent`. | §7.2, §9 |
| B6 | The custodian cannot enforce WAN (major) | Same fix as A3. | §6.1 |
| A-min | Fetch day span too wide; padding claim false | Days are `[day(now−MAX_CUSTODY_VALIDITY_MS), day(now+5 min)]` ∩ the session window, so at most 3. Padding is removed, because with recipient binding Carol knows the recipient anyway. | §4 |
| A-min / B-min | Error classification | `FromTheFuture` and not-yet-valid errors are Retry. `EndpointNotCurrentlyValid` is Refused only once `expires_at ≤ now`. `Replay` is Refused. `ForwardJumpTooLarge` is Retry. Any error not listed defaults to Retry, which never releases. `NO_PEER_CERT` triggers a per-peer backoff. | §8.3 |
| A-min | Iterating candidate sessions with a single certificate | Ingest uses only the session the tag names (`hint.record_key`) and loads that session's bound certificate. | §8.2 |
| A-min | Unenforceable per-dial rule; reply ops sent as requests | The per-dial rule is dropped and a per-fetcher rate limit is used instead. Any op ≥ `0x80` received as a request gets `UNSUPPORTED`. | §5, §6.3 |
| A-min | IPC dials become a custody channel | `LanDial`, `InternetDial` and `P2pDial` refuse RFC1 frames unless the lab unlock is on (`CUSTODY_IPC_REFUSED`). | §10 |
| A-min | `PEER_CLOSED` treated as unsupported; free deposits | 3 strikes within 1 h park the custodian for 1 h. An in-memory attempt counter is charged on **every** DEPOSIT. | §6.3, §7.3 |
| A-min | Incomplete disclosure | §11 now lists the recipient field, ACK timing, release timing, cross-custodian linkability and ciphertext held until TTL after release. | §11 |
| A-min (a-e) | Factual fixes | (a) p2p inbound already goes through `serve_inbound_on`, which calls `peer_seen` at `rn/internet_direct.rs:466`. (b) The revocation helper `identity_denies_device_lineage` (`core/lan_dispatch.rs:1798`) becomes `pub(crate)`, called with the same registry choice per object type. (c) F8 durable writes go through `spawn_blocking`. (d) Re-pair companion: the smaller-key side **dials**. (e) `IN_CUSTODY` and `CONTACT_NOT_VERIFIED` are registered as new codes. | various |
| B-min | RELEASE-as-delete needs an amendment | V1 is TTL-only and has a `released_at_ms` column. Bytes of released rows count toward the caps until expiry, and §6.3 states the throughput this implies. | §6 |
| B-min (a) | Re-noting can widen custody | `record_object_routes(.., custody: Option<bool>)` keeps the existing `custody` and `custodians_held`. Only the send's **own** message gets `Some`. Test w14. | §7.1 |
| B-min (b) | `set_node_flag` forces AUTO off | **Verified:** `ash/cli.rs:5677`. A dedicated `set_node_custody` leaves `auto_policy` untouched. | §10 |
| B-min (e,f,g) | busy_timeout; 2 s idle wait; DUPLICATE on PURGED | Stores open with `open_private_data_dir_sqlite` and `busy_timeout(10 s)`. The collector waits the `first` duration while terminal RFC1 replies are still outstanding. Tombstones are gone: purge deletes the row, and a re-deposit after purge stores again. | §6.2, §5 |
| B-min | Reuse RSO1, Mailbox V1 token, signer check | Adopted. | §5 |
| B-min | Fetcher steady-state cost | Head listing reads metadata only. Tags are cached per (session, day). The interval adapts from 60 s up to 10 min. | §8.1 |
| B-min | Missing tests | Rows 1-12 of that critique are added (§16). | §16 |
| B-min | Scope | `--carrier custody`, `Status.custody` and the per-custodian user status are deferred. `OutboxItem.in_custody` and `raven node custody on|off|status` stay. No new IPC request: `OutboxKick` also kicks the fetcher. | §10, §17 |
| new | A LAN-only contact's send derives `choice=Lan` | **Found while verifying:** a contact with one LAN route goes through `ext::run_send_secure` with `SendCtx.choice=None`, and `OutboxHandoff::new` derives `Lan` from it (`ash/pair_init_lab.rs:757-775`, `ash/ext.rs:1306`). Revision 1's rule `custody = (choice == Auto)` would therefore never fire under the HOLD. **Fix:** a new `SendCtx.custody_ok` is true unless the user passed an explicit `--carrier lan|internet|p2p`. The gate is checked by the worker at use time, not by ash. | §7.1 |

---

## 2. Current state, verified in this tree

| Fact | Where | Consequence |
|---|---|---|
| LAN gate is on. Internet and p2p are off. The lab unlock is debug-only. | `core/lan_gate.rs`, `core/internet_gate.rs`, `core/p2p_gate.rs:14`, `core/pair_init.rs:29` | Custody needs its own gate and must work over LAN alone. |
| Links are request/response. The dialer writes all its frames, then collects replies. The listener dispatches one frame at a time. | `rn/lan_direct.rs:513-541` (`exchange_frames`), `:353-389` (serve loop); collector `rn/main.rs:545`, `:556`, `:492`, `:585` | Carol never pushes. The collector must learn RFC1. |
| Responder link admission is contacts only. An unverified contact is accepted from a local-network source only. Internet links get no source. | `core/lan_dispatch.rs:586-610`; `rn/lan_direct.rs:283-292`; `rn/internet_direct.rs:422-427` | Custody adds a per-op **pinned** check plus a per-link carrier and source check. |
| `dispatch_frame` order is RLB1, then the PairInit sniff, then RVN1. An unknown frame gives `Err` and the link closes. There is no carrier or source argument. | `core/lan_dispatch.rs:1618-1662` | New `dispatch_frame_on`. Old nodes close on RFC1. |
| Receive selects sessions by the **link peer**, tried newest first. | `core/lan_dispatch.rs:1440-1488`, `:1556-1610` | A relayed object on a direct link is still refused. Relayed objects use their own entry point. |
| The route tag is checked before the certificate, signature and AEAD. A **non-zero wrong hint** fails earlier. | `core/indexed_session_store.rs:2826-2846` | Carol must refuse non-canonical hop fields (A2). |
| Object digests zero the mutable fields. `admit_relayable` does not check them and does not verify the signer. | `core/bridge.rs:70-76`, `core/envelope.rs:236-250`, `core/carrier_admission.rs:120-170` | Signer check, canonical-field check and SHA-256 of the exact bytes at Carol (A2). |
| Outbound envelopes are canonical: hint 0, hop 8, budget 2. The store re-validates this on resend. | `core/indexed_session_store.rs:105-106`, `:4434`, `:4718-4730` | Honest objects always pass the canonical check. |
| Mailbox and store tag derivation is frozen, with a vector. | `core/atsam_indexed_session.rs:335-348`; `proto/ATSAM_INDEXED_SESSION_PROFILE_V1.md` §6; `shared-vectors/rvn1/atsam/indexed_session_v1_subkeys_001.json` (`mailbox_tag_hex`, `store_tag_hex`) | No new derivation. |
| RSO1 codec, vectors and fuzz target exist. The RSO1 decoder is strict (trailing bytes, flags, message_id match, lifetime within envelope). | `core/store_object.rs:55-185`, `shared-vectors/rvn1/store/`, `node/fuzz/fuzz_targets/store_object.rs` | DEPOSIT and FETCH_ITEM carry RSO1. |
| Mailbox V1 page token: `SHA-256("raven/offline-mailbox/page-token/v1" ‖ packed RSO1)`, rows sorted by it. | `proto/RAVEN_MAILBOX_TRANSPORT_V1.md` §2 | Reused as the FETCH cursor. |
| Store Object deletion is TTL-only. Early deletion needs an object-bound token. | errata rule 9 (`proto/SECURITY_ERRATA_RVN1_2026-08-13.md:65-72`); `proto/RAVEN_STORE_OBJECT_V1.md` §4 | V1 RELEASE hides only. |
| Carrier Conformance: the digest is SHA-256 of the exact bytes, computed by the carrier. The same digest with different bytes is quarantined. | `proto/RAVEN_CARRIER_CONFORMANCE_V1.md:133-147`, §5.3 | Carol's custody digest follows this. |
| One prepared ACK per session. A second one gets `OutboundPending`. A Queued intent returns the existing row **without** calling the callback. | `core/indexed_session_store.rs:2297-2304`, `:2334-2337` | Owed ACKs are recorded explicitly (A6). |
| The F8 owed ACK is in memory only, evicts the earliest-expiring entry, and has no session id. | `rn/outbox.rs:291-298`, `:415`, `:652-694`, caps `:99-100` | Durable table, session resolved later (B2). |
| Worker: empty route plan gives `Held` before `capture`. `unsent` is cleared before the dial and restored after it. Outcome mapping falls back to `Held` when `routes_left == 0`. | `rn/outbox.rs:1587-1615`, `:1738-1751`, `:1875-1887`, `:1910-1965` | Fixed in §7.3 (B1, B5). |
| `record_object_routes` keeps only `unsent` from the old record. `note()` re-records earlier rows with the current send's choice. | `core/outbox.rs:630-665`; `ash/pair_init_lab.rs:792-822`, `:1287-1292` | New fields are carried over and never set when an earlier row is re-noted (B-min a). |
| The route-record file is "hints only": 256 entries at most, earliest-expiring evicted, an unreadable file is replaced, and `clear_peer_routes` keeps only `unsent` records. | `core/outbox.rs:518-627`, `:711-726` | If custody fields are lost, deposits stop (fail closed). `clear_peer_routes` must also keep records with custody fields. |
| A contact with only a LAN route sends with `choice=None`, which derives `Lan`. | `ash/cli.rs:6735-6744`, `ash/ext.rs:1306`, `ash/pair_init_lab.rs:757-775` | Custody permission comes from the explicit flag (§7.1). |
| `set_node_flag` sets `auto_policy=false`. | `ash/cli.rs:5669-5686` | Dedicated setter. |
| `NodePolicy.bridge` and `.store` default to true (AUTO). Unknown fields are ignored. | `core/node_policy.rs:8-60` | New `custody` field, default false, outside AUTO. |
| IPC `LanDial` forwards any frames. Windows shares the handler. | `rn/ipc_server.rs:565-596`, `:720`; `rn/ipc_server_windows.rs:19` (`serve_one`) | Refuse RFC1 frames outside the lab. |
| `endpoint_outbox` stores the sealed envelope bytes in clear, with `session_id` and `object_digest`. | `core/indexed_session_store.rs:1760-1782` | Read-only queries for F8 session resolution and corruption rebuild. |
| Session heads carry `created_at_ms` and `expires_at_ms` in SQLite metadata. | `core/indexed_session_store.rs:1683-1700`, `:3320-3340` | The fetcher schedule reads metadata only. |
| RDAP uses only `SealUnderSession` and ships no dial client. | `team_agents/raven_ipc.py`, `team_agents/raven_bind.py:4` | **No RDAP change.** |

---

## 3. Goals and non-goals

**Goals.**
- **G1. One hop, never decrypted.** One-hop custody through a mutual pinned friend, who never decrypts. It must work under the LAN-only HOLD.
- **G2. Authenticated custody ops.** DEPOSIT, FETCH and RELEASE run over the existing Noise link, between pinned contacts, with the gate checked per link.
- **G3. Addressing.** Custody is addressed by the recipient's rotating mailbox store tag (current and previous day) and bound to the recipient's identity.
- **G4. Relayed ingest.** Relayed objects go through the existing endpoint transaction, under the single session the tag names.
- **G5. "Via a friend" carrier.** The sender's outbox gains this carrier: custodians are chosen per contact, and each message's record says whether custody is allowed and which custodians already hold it.
- **G6. ACK return.** The ACK comes back directly or through a custodian. Delivery happens only on a verified ACK.
- **G7. Bounds and safety.** Quotas per (depositor, recipient) and per depositor, TTL, dedup, crash safety on all three roles, opt-in.
- **G8. Wire hygiene.** A versioned wire with strict decoders, vectors and fuzzing.

**Non-goals.**
- **N1. Multi-hop.** No multi-hop, spray, RHW1, inventory push or Carol-initiated delivery. This stays true of RFC1's own ops. **Superseded in part (Phase 5, §20):** a two-custodian handoff (A -> F1 -> F2 -> B, RFC1 ops 0x07/0x08 with the RHW1 record) is specified in its companion [`protocol/RAVEN_CUSTODY_HANDOFF_V1.md`](../../protocol/RAVEN_CUSTODY_HANDOFF_V1.md), behind its own gate; spray, inventory push and Carol-initiated delivery stay out.
- **N2. No pairing through a friend.** No PairInit or PairResponse through custody, so no first contact or re-pairing that way (§13).
- **N3. Carol never dials.** Carol dials nobody for custody. Reverse-direction links do not carry custody.
- **N4. No metadata hiding.** No sealed sender. Nothing is hidden from Carol about who talks to whom (§11).
- **N5. Lab bridge untouched.** `bridge_run`, `forward_queue`, `message_router` and `EnqueueSealed` are not fixed or used.
- **N6. Session model unchanged.** No longer sessions, no ratchet, no iOS.
- **N7. No SealUnderSession rows.** Rows with no local body (RDAP M2) are not carried.
- **N8. Swarm mailbox stays separate.** No integration with the swarm `/raven/offline-mailbox/1.0.0`. RSO1 and the page token keep that path open.
- **N9. No custody receipts or early deletion.** No Carol-signed `custody_sig`, no early payload deletion, no deletion by ACK.
- **N10. No custodian advertising.** Custodians are not advertised in cards (a later `cust=` key). **Superseded (Phase 3, §19):** custodians are now advertised inside authenticated RRH1 links only (0x06 CUSTODY_OFFER, 0x07 CUSTODIAN_TAG, pair-blinded), still never in cards.
- **N11. Single recipient key.** One recipient key per object; multi-device fan-out is not handled.
- **N12. Deferred CLI and IPC.** `--carrier custody`, `IpcResponse::Status.custody` and `raven custody status/fetch`.

---

## 4. Roles, trust, opt-in, addressing

### 4.1 Who has to do what

**Preconditions.**
- Alice↔Carol and Bob↔Carol are mutual **pinned** contacts.
- Alice↔Bob are mutual pinned contacts with a confirmed, unexpired session.

**Carol (custodian).**
- Turned on with `raven node custody on`, which sets `NodePolicy.custody=true`.
- Default false. AUTO never sets it, and `fail_closed()` sets it false.
- `off` refuses new deposits, but FETCH and RELEASE are still served until held objects expire.
- `off --purge` deletes every row.

**Alice (sender).**
- Runs `raven contact set-addr --tag bob --custodian @carol`, which writes the contact row field `"custodians": ["<carol pub hex>"]`. At most 2 custodians per contact.
- Meaning: traffic between me and this contact may be left with these friends, and I fetch my mail from this contact there.

**Bob (recipient).**
- Runs `raven contact set-addr --tag alice --custodian @carol`.
- Both sides must list Carol. A mismatch is a documented limit (S21), and the CLI prints the matching command for the other side.

**Validation when the list is set.** Each custodian must be:
- an existing pinned contact;
- different from the contact being configured;
- different from the local key;
- unique in the list;
- one of at most 2.

**Validation at use time.** The worker and the fetcher re-check `contact_admission` (Allowed and pinned). A custodian that fails is skipped with `CUSTODIAN_NOT_USABLE`.

**Verified-only rule.** `core/outbox.rs::custody_allowed_for_contact(pinned) -> bool { pinned }` sits next to `carrier_allowed_for_contact` (`:740`). It is applied:
- by Carol to the link peer (every op) and to the recipient (DEPOSIT);
- by Alice and Bob to the peer and to the custodian.

### 4.2 Addressing (frozen derivation, no new crypto)

```text
day_epoch      = floor(unix_ms / 86_400_000)
mailbox_tag[d] = HMAC-SHA256(K_route[d], "rvn1/mailbox" || u64_be(day_epoch) || u64_be(d))[:16]
store_tag[d]   = SHA-256("raven/relay-tag/v1" || mailbox_tag[d])[:16]   (= derive_mailbox_tags(..).1)
```

**Deposit tag.** Computed from:
- the sender's **outbound** direction of the session the object was sealed under;
- `day_epoch = day(envelope.created_at)`, which is the signed field, so the tag is deterministic per object (re-deposit gives DUPLICATE).

The same rule applies to ACKs deposited by their sender.

**Fetch tags (per custodian C).** Built as follows:
- For every pinned, unblocked contact P whose `custodians` list contains C, and every live session head with P:
  - take the **inbound** direction;
  - take every day in `[day(now − MAX_CUSTODY_VALIDITY_MS), day(now + MAX_ENDPOINT_FUTURE_SKEW_MS)] ∩ [day(head.created_at_ms), day(head.expires_at_ms)]`.
- That gives at most 3 days, usually 2: the profile §6 "current and previous day within the skew window".
- Coverage argument: Alice's validity is at most 24 h (`core/outbox.rs:36-52`) and skew is at most 5 min. So `day(created) ∈ [day(now−24 h), day(now+5 min)]` for any object Bob can still accept.

**Recipient binding.** DEPOSIT also carries `recipient[32]`, the recipient's contact key (the device Ed25519, as everywhere in the contact book).
- Carol returns an object only to a link-authenticated fetcher equal to `recipient` that also presents its tag.
- The tag still matters for three things:
  - Bob maps it locally to exactly one session (the hint);
  - Carol returns only objects for sessions Bob can process;
  - it keeps Store Object V1 §4 semantics ("claimant presents store_tag").
- There is no padding. Carol learns the recipient from the deposit anyway (§11).

**New `IndexedSessionStore` methods** (`core/indexed_session_store.rs`; all read-only, no schema change):

```rust
pub enum MailboxDirection { Inbound, Outbound }
pub struct SessionHeadMeta { pub key: IndexedSessionRecordKey, pub session_id: [u8; 32],
                             pub peer_device: [u8; 32], pub created_at_ms: u64, pub expires_at_ms: u64 }
/// Unexpired heads from SQLite metadata only (no protected load), like head_expires_at_ms (:3320).
pub fn live_session_heads(&self, local_device: &[u8; 32], now_ms: u64) -> Result<Vec<SessionHeadMeta>, IndexedSessionStoreError>;
/// Store-facing tags of one Confirmed, unexpired session (one protected load). Refuses Provisional/expired.
pub fn mailbox_store_tags(&mut self, key: &IndexedSessionRecordKey, dir: MailboxDirection,
                          day_epochs: &[u64]) -> Result<Vec<[u8; 16]>, IndexedSessionStoreError>;
/// Outbound store tag for one exact outbox object of this session (day from its signed created_at).
pub fn outbound_store_tag_for_object(&mut self, key: &IndexedSessionRecordKey, packed: &[u8])
    -> Result<[u8; 16], IndexedSessionStoreError>;
/// session_id of an ACK row in endpoint_outbox (kind = 2) by its object_digest (F8 owed ACKs).
pub fn outbound_session_for_object(&self, object_digest: &[u8; 32]) -> Result<Option<[u8; 32]>, IndexedSessionStoreError>;
/// Queued, unexpired ACK rows (session_id, object_digest, recipient, bytes, expires_at): corruption rebuild only.
pub fn live_queued_ack_rows(&self, now_ms: u64) -> Result<Vec<QueuedAckRow>, IndexedSessionStoreError>;
/// hint == OUTBOUND_DEST_DEVICE_HINT, hop == OUTBOUND_HOP_LIMIT, budget == OUTBOUND_REPLICATION_BUDGET,
/// flags == OUTBOUND_FLAGS, empty ratchet header. Pure.
pub fn canonical_outbound_fields(env: &Envelope) -> bool;
```

Tags are cached **in memory only** by the fetcher and the worker, keyed by (record-key digest, day, direction). Entries are dropped when the session expires. They are never written to disk.

---

## 5. Wire: RFC1 custody frames, version 1

**Framing.** Each RFC1 frame is exactly one Noise transport plaintext (at most `MAX_TRANSPORT_PLAINTEXT` = 65,519 bytes). It is sent on an authenticated Raven link after the RLB1 exchange. All integers are big-endian.

**Byte classes** (Conformance §2.1):
- RFC1 = `carrier_control_bytes`;
- RSO1 = `carrier_record_bytes`;
- the envelope inside is the `endpoint_object_bytes`.

They are demultiplexed on the link channel by magic, exactly as `RLB1` is today.

```text
header (14 bytes, same layout in every future version):
  magic "RFC1" (4) | version u8 = 0x01 | op u8 (requests < 0x80, replies >= 0x80) | req_id [u8; 8] (random, echoed)

requests (dialer -> listener)
  0x01 DEPOSIT  recipient[32] || rso1_len u32 || rso1[rso1_len]
                frame length == 50 + rso1_len; rso1_len in [59 + 86, MAX_RFC1_RSO1]
  0x02 FETCH    tag_count u8 (1..=32) || store_tag[16] x tag_count
                || has_after u8 (0|1) || after_token[32] (all zero iff has_after = 0) || max_items u8 (1..=16)
                frame length == 49 + 16 * tag_count
  0x03 RELEASE  count u8 (1..=32) || custody_digest[32] x count
                frame length == 15 + 32 * count

replies (listener -> dialer), one terminal reply per request, in request order
  0x81 DEPOSIT_RESULT  code u8 || custody_digest[32] (zero if the object could not be parsed)   47 B, terminal
  0x82 FETCH_ITEM      rso1_len u32 || rso1                                                       non-terminal
  0x83 FETCH_END       code u8 || returned u8 || has_next u8 || next_token[32] (zero iff has_next=0)  49 B, terminal
  0x84 RELEASE_RESULT  code u8 || released u8                                                    16 B, terminal
  0xFE UNSUPPORTED     max_version u8                                                            15 B, terminal
                       (unknown version, unknown op, or any op >= 0x80 received as a request)

MAX_RFC1_RSO1      = MAX_TRANSPORT_PLAINTEXT - 50 = 65,469   (DEPOSIT bound; a FETCH_ITEM then always fits)
MAX_RFC1_ENVELOPE  = MAX_RFC1_RSO1 - 59 = 65,410
const assert: largest LAN send (MAX_LAN_ENDPOINT_TEXT 48 KiB + 26 + 16 + 86 + 64 = 49,344 B) <= MAX_RFC1_ENVELOPE
custody_digest     = SHA-256(packed envelope inside the RSO1)            (Conformance §2.2 object_digest)
page_token         = SHA-256("raven/offline-mailbox/page-token/v1" || rso1) (Mailbox V1 §2, reused verbatim)
```

**RSO1 inside RFC1** is stricter than Store Object V1:
- `StoreObject::unpack` succeeds;
- `flags == 0` (no `custody_sig`);
- `created_at_ms == env.created_at`;
- `expires_at_ms == env.expires_at`;
- `packed_envelope.len() <= MAX_RFC1_ENVELOPE`.

The RSO1 `store_tag` is the custody tag.

**Codes (u8)**

| Code | Name | Requester action | Registry string |
|---:|---|---|---|
| 0 | OK / STORED | held by this custodian | `IN_CUSTODY` (new, status) |
| 1 | DUPLICATE | same as STORED | `IN_CUSTODY` |
| 2 | POLICY_DENIED (custody off) | park custodian 1 h | `POLICY_DENIED` (existing) |
| 3 | HOLD (gate closed for this link) | park custodian 1 h | `CUSTODY_HOLD` (new) |
| 4 | NOT_VERIFIED (link peer not pinned) | park until explicit retry | `CONTACT_NOT_VERIFIED` (register) |
| 5 | REFUSED_OBJECT (admission, canonical fields, signer) | never again for this object at this custodian | `CUSTODY_REFUSED` (new) |
| 6 | EXPIRED | never again for this object | `ENVELOPE_EXPIRED` (existing) |
| 7 | STORE_FULL (node cap) | back off | `STORE_FULL` (existing) |
| 8 | QUOTA (depositor or pair cap) | back off | `CUSTODY_QUOTA` (new) |
| 9 | RATE_LIMITED | back off | `RATE_LIMITED` (existing) |
| 10 | PERSISTENCE | back off | `CUSTODY_UNAVAILABLE` (new) |
| 11 | MALFORMED | never again for these bytes | `CUSTODY_MALFORMED` (new) |
| 12 | RECIPIENT_NOT_ACCEPTED | park (custodian, recipient) 1 h | `CUSTODY_RECIPIENT_REFUSED` (new) |
| 13 | CONFLICT (digest held under another tag or recipient) | never again for this object | `CUSTODY_CONFLICT` (new) |
| other | unknown | handled as 10 | – |

Local-only codes, also registered: `CUSTODY_UNSUPPORTED`, `CUSTODIAN_NOT_USABLE`, `OWED_ACK_FULL`, `CUSTODY_IPC_REFUSED`.

**Strict decoding** (`core/friend_custody.rs::Rfc1::decode`):
- A frame shorter than 14 bytes or with the wrong magic is `Err`, and the link closes.
- `version != 1`, an unknown op, or an op ≥ `0x80` gets `UNSUPPORTED`, echoing `req_id`.
- A length that is not exact, a count out of range, `has_after ∉ {0,1}`, or a non-zero `after_token` with `has_after = 0` gets `MALFORMED`. So does an RSO1 that breaks the rules above.
- Repeated tags or digests are deduped silently.
- **Requester side:** a reply with an unknown op, a `req_id` it never sent, or a missing terminal reply fails that RFC1 request. The failure is transient.

**Collector** (`rn/main.rs`):
- `expects_reply(frame)` is true for RFC1 requests (`:545`).
- `is_terminal_reply` is true for `0x81/0x83/0x84/0xFE` (`:556`).
- `ReplyCollector` records whether the dial carries RFC1. While `seen < expected`, `idle_wait()` returns `waits.first`. It still returns `idle` for endpoint dials, so their behaviour is unchanged.

**Budgets:**
- Custody dials never mix RFC1 and endpoint frames.
- A worker custody dial has at most 16 DEPOSITs.
- A fetcher dial has at most one RELEASE and one FETCH.
- A FETCH page is at most 16 objects and at most 128 KiB of RSO1, always at least one object if any match. That is about 175 KiB of base64 plus the RLB1 offer, under `DIAL_REPLY_B64_BUDGET` ≈ 255 KiB (`rn/main.rs:492-497`), and at most 19 replies against `MAX_DIAL_REPLIES` = 64.

**Compatibility:**
- **Old listeners.** An old listener fails `Envelope::unpack` on RFC1 and closes (`core/lan_dispatch.rs:1653-1655`). The requester sees `*_DIAL_PEER_CLOSED` after an accepted link. That counts as a **strike** (§7.3), not an immediate verdict.
- **Old requesters.** They never send RFC1.
- **Future versions.** v2+ keep the 14-byte header, so a v1 listener can always reply `UNSUPPORTED`.
- No existing frame, envelope, PairInit, RLB1, RSO1 or IPC byte changes.

**Vectors** (new `shared-vectors/rvn1/custody/`, hex plus decoded fields):
- `rfc1_deposit_001`, `rfc1_fetch_001` (with cursor), `rfc1_fetch_nocursor_001`, `rfc1_release_001`, `rfc1_replies_001`;
- negatives: `rfc1_neg_trailing_001`, `rfc1_neg_tagcount0_001`, `rfc1_neg_tagcount33_001`, `rfc1_neg_after_nonzero_001`, `rfc1_neg_rso1_flags_001`, `rfc1_neg_rso1_created_mismatch_001`, `rfc1_neg_replyop_as_request_001` (expects `UNSUPPORTED`), `rfc1_neg_version2_001` (expects `UNSUPPORTED`).

Tags reuse `atsam/indexed_session_v1_subkeys_001.json`, and page tokens reuse the Mailbox V1 definition. Add a row to `proto/PROTOCOL_VERSIONS.md` and regenerate `docs/PROTOCOL_FREEZE_HASHES_V1.md` once the spec is frozen.

---

## 6. Custodian (Carol)

### 6.1 Entry point and the per-link gate

`core/lan_dispatch.rs`:

```rust
pub struct InboundLink { pub carrier: OutboxCarrier, pub source: Option<std::net::IpAddr> }
pub fn dispatch_frame_on(data_dir: &Path, identity: &Identity, peer: &LanBundle, noise_ed: &[u8; 32],
                         frame: &[u8], link: InboundLink) -> Result<Vec<Vec<u8>>, String>;
/// Unchanged signature for existing callers and tests: InboundLink { carrier: Lan, source: None }
/// (RFC1 then gets HOLD unless WAN custody is live).
pub fn dispatch_frame(...) -> Result<Vec<Vec<u8>>, String>;
```

After the identity checks and the RLB1 branch, and before `classify_packed_envelope`:
`if friend_custody::is_rfc1(frame) { return friend_custody::handle_frame(data_dir, identity, noise_ed, &link, frame, now_ms()); }`

**Callers:**
- `rn/lan_direct.rs:374` passes `InboundLink { carrier: Lan, source }` (the `source` it already has).
- `rn/internet_direct.rs:499` passes `InboundLink { carrier: link.carrier, source: None }`. This covers p2p through `serve_inbound_on`.

**`handle_frame` sequence.** Nothing before step 6 touches the disk.

1. Parse the header. Short frame or bad magic: `Err`. Unknown version or op: `UNSUPPORTED`.
   - Lab only: `RAVEN_LAB_CUSTODY_PRETEND_OLD=1` returns `Err` here.
2. If `!custody_link_allowed(CustodyGates::current(), CarrierGates::current(), link.carrier, link.source)`, reply HOLD (the op's terminal reply carrying code 3).
3. `contact_admission(noise_ed)` must be `Allowed(c)` with `c.pinned`. Otherwise reply `NOT_VERIFIED`. An unreadable book gives `PERSISTENCE`.
4. Strict body decode, else `MALFORMED`.
5. Op-specific checks (§6.4, §6.5).
6. Store work.

### 6.2 Storage

**File and lifecycle.** The store lives in `<data_dir>/friend_custody.sqlite`.
- Opened with `paths::open_private_data_dir_sqlite` (0600, Windows ACL) and `busy_timeout(10 s)`.
- Created **lazily** by the first DEPOSIT that passes step 5. FETCH and RELEASE without the file answer empty.
- Identity preflight and first-install proof never see it.
- A newer `user_version` is refused (no custody, `PERSISTENCE`). An integrity failure renames the file to `friend_custody.sqlite.corrupt-<ms>` and starts empty. Only ciphertext copies are lost; senders keep retrying.

```sql
PRAGMA auto_vacuum=INCREMENTAL;   -- before the first table
PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA user_version=1;
CREATE TABLE IF NOT EXISTS custody_objects_v1 (
  object_digest  BLOB PRIMARY KEY NOT NULL CHECK(length(object_digest)=32), -- SHA-256(envelope)
  recipient      BLOB NOT NULL CHECK(length(recipient)=32),
  depositor      BLOB NOT NULL CHECK(length(depositor)=32),                 -- link peer == outer signer
  store_tag      BLOB NOT NULL CHECK(length(store_tag)=16),
  page_token     BLOB NOT NULL CHECK(length(page_token)=32),
  rso1           BLOB NOT NULL,
  bytes          INTEGER NOT NULL,
  admitted_at_ms INTEGER NOT NULL,
  expires_at_ms  INTEGER NOT NULL,                                          -- = envelope expires_at
  released_at_ms INTEGER                                                    -- NULL until the recipient RELEASEs
);
CREATE INDEX IF NOT EXISTS idx_custody_fetch ON custody_objects_v1(recipient, page_token);
CREATE INDEX IF NOT EXISTS idx_custody_pair  ON custody_objects_v1(depositor, recipient);
CREATE INDEX IF NOT EXISTS idx_custody_exp   ON custody_objects_v1(expires_at_ms);
```

**No tombstones are needed.** `admit_relayable` bounds `expires_at ≤ now + MAX_CUSTODY_VALIDITY_MS`, so custody end equals the envelope expiry. After that, any re-deposit is refused `EXPIRED`.

**Why not `ForwardQueue`.** The bridge hands every pending row to any subscriber. A separate file whose rows leave only through a recipient-bound fetch keeps "no fanout" a structural property.

### 6.3 Limits (constants in `core/friend_custody.rs`; guesses, to be tuned with the harness)

| Resource | Limit | Reply |
|---|---:|---|
| Node rows / bytes (held **and** released-but-unexpired rows) | 4,096 / 64 MiB | `STORE_FULL` |
| Per depositor rows / bytes | 512 / 16 MiB | `QUOTA` |
| Per (depositor, recipient) rows | 128 | `QUOTA` |
| DEPOSIT frames per depositor per 60 s (in memory, **every** outcome) | 120 | `RATE_LIMITED` (no disk) |
| Stored bytes per depositor per 60 s (from the table, `admitted_at_ms ≥ now−60 s`) | 2 MiB | `RATE_LIMITED` |
| FETCH per fetcher per 60 s (in memory) | 30 | `FETCH_END code=9` |
| Tags per FETCH; RELEASE digests per frame | 32; 32 | `MALFORMED` above |
| Page | `min(max_items,16)` objects, ≤ 128 KiB RSO1, ≥ 1 if any | `has_next=1` |

**Rules:**
- When a limit is reached, the deposit is **refused**. Nothing is ever evicted.
- In-memory windows live in a `static Mutex<HashMap<[u8;32], Window>>` in `friend_custody`. The listener dispatches on blocking threads of one process, so a mutex is enough. The windows reset on restart, which is acceptable for a throttle.

**Throughput this implies (TTL-only):**
- One pair can have at most 128 objects in flight at one custodian over a rolling 24 h. ACKs travel in the reverse pair (Bob as depositor, Alice as recipient), which is a separate bucket.
- A second custodian doubles this.
- Disclosed in `raven node custody on` and in the waiver.

### 6.4 DEPOSIT (`friend_custody::deposit`)

1. `load_policy(data_dir).custody` must be true, re-read per frame. A corrupt policy file fails closed. Otherwise `POLICY_DENIED`.
2. Charge the attempt window. If over the limit, `RATE_LIMITED`.
3. RFC1 RSO1 rules (§5). Otherwise `MALFORMED`.
4. `admit_relayable(envelope, now)`:
   - `Expired` gives `EXPIRED`;
   - every other refusal gives `REFUSED_OBJECT`. That includes `PairingMaterial`, `NotSealedIndexed` (the demo cipher too, except under `unsafe-demo-crypto`), `Flags`, `RatchetHeader`, `FromTheFuture` and `ValidityTooLong`.
5. `canonical_outbound_fields(&env)`. Otherwise `REFUSED_OBJECT`.
6. `env.verify(noise_ed)`: the depositor must be the outer signer. Otherwise `REFUSED_OBJECT`. This is one existing Ed25519 verify.
7. Recipient checks. Otherwise `RECIPIENT_NOT_ACCEPTED`. The recipient must:
   - differ from `noise_ed`;
   - differ from Carol's own key;
   - pass `contact_admission(recipient)` as `Allowed`;
   - be pinned.
8. One `IMMEDIATE` transaction:
   - delete at most 64 rows with `expires_at_ms ≤ now`;
   - look up `object_digest`. Same `(store_tag, recipient)` gives `DUPLICATE`. A different tag or recipient gives `CONFLICT`: no overwrite, no resurrection, and a fixed-code log line;
   - check node, depositor and pair caps, then the stored-bytes window;
   - insert with `expires_at_ms = env.expires_at`, `page_token` and `released_at_ms = NULL`;
   - commit.
9. Reply `STORED` **only after commit** (`synchronous=FULL`). A SQLite error gives `PERSISTENCE`.

Errata rule 6 holds: pre-admission checks are reads only, and a row is written only after admission and quota checks. Conformance §5.3 holds: the digest is SHA-256 of the exact bytes, so "same digest, different bytes" cannot happen, and a different custody identity gives CONFLICT.

### 6.5 FETCH and RELEASE

These are served while custody is off, so held objects can drain. The gate and pinned checks still apply.

**FETCH(tags, after, max_items)** from F:
- Charge the fetch window.
- If there is no file, reply `FETCH_END{OK,0,0}`.
- Otherwise run a read-only:

```sql
SELECT rso1, page_token FROM custody_objects_v1
 WHERE recipient = :F AND released_at_ms IS NULL AND expires_at_ms > :now
   AND store_tag IN (:tags) AND (:has_after = 0 OR page_token > :after)
 ORDER BY page_token LIMIT 17
```
- Apply the page limits. Reply one `FETCH_ITEM` per row, then `FETCH_END{OK, n, has_next, last token if has_next}`.
- Rows are returned again until RELEASE (at-least-once). A lost reply or a fetcher crash loses nothing.

**RELEASE(digests)** from F:
- `UPDATE ... SET released_at_ms = now WHERE object_digest IN (...) AND recipient = F AND released_at_ms IS NULL`.
- Reply `RELEASE_RESULT{OK, changed}`.
- A digest of another recipient's row, an unknown digest, or an already-released one changes nothing. Only the count reveals anything.

**Authority.** Only the object's recipient, authenticated on the link and pinned, can see or release it. RELEASE **never deletes**: the payload stays until `expires_at_ms`. This is within errata rule 9 and Store Object V1 §4 as written, so **no amendment is needed** for F1. Payload deletion on RELEASE is open question Q1. The wire would not change.

**Update (privacy pack PP.17, behind this gate).** Q1 is answered: RELEASE deletes. The
custodian deletes each released row (payload, recipient, depositor, sizes, times) and keeps only
the object digest and its expiry hour (`custody_released_v1`) for dedup until expiry; a re-deposit
of a released digest is `DUPLICATE`, FETCH after RELEASE returns nothing, and in a sealed profile
the open rows' digest and parties are keyed and their payload and times sealed
(`docs/design/2026-10-at-rest-metadata.md` sections 4.15 and 7.4). The spec text is the unsigned
[`SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md`](../SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md);
the custody gate stays false until the Protocol owner signs it. The wire does not change.

### 6.6 Maintenance, purge, logging

**`friend_custody::maintain(data_dir, now)`.** Added to the `run_durable_prune` closure (`rn/lan_direct.rs:503-508`, every 10 min), and only if the file exists. It:
- deletes expired rows;
- deletes rows whose depositor **or** recipient is no longer a current, unblocked, pinned contact (contact book read once);
- runs `PRAGMA incremental_vacuum`.

**Purge.** `raven node custody off --purge` deletes all rows in one transaction. The CLI opens the file directly; SQLite arbitrates with the running service.

**Logs.** Counts and fixed codes only: no key, tag, digest or message id (the `rn/outbox.rs` rule).

---

## 7. Sender (Alice): "via a friend" in the outbox worker

### 7.1 Data model

**Contact row.** `custodians: Vec<String>`, with `#[serde(default, skip_serializing_if = "Vec::is_empty")]`, in:
- `ash/cli.rs:1015` `Contact`;
- `ash/ext.rs:908` `LocalContactRow` (kept through device-sync round trips, **not** in `SyncContact`, because it is a local choice);
- `core/outbox.rs:858` `ContactRouteRow`.

`ContactRoutes` (`:849`) gains `custodians: Vec<[u8;32]>`: valid hex only, deduped, at most 2, the contact itself excluded.

**Per-message record (`core/outbox.rs:531` `ObjectRoutes`).**

```rust
/// This send allowed custody: no explicit `--carrier lan|internet|p2p`. The gate is the worker's check.
#[serde(default, skip_serializing_if = "is_false")] pub custody: bool,
/// Custodians (hex) that answered STORED/DUPLICATE for this object. Written only after the answer.
#[serde(default, skip_serializing_if = "Vec::is_empty")] pub custodians_held: Vec<String>,
```

**Record functions:**
- **`record_object_routes`** gains `custody: Option<bool>`:
  - for an **existing** record, keep its `unsent`, `custody`, `custodians_held` and (G4) its carrier `choice`; the re-noted routes are kept only where that choice allows them;
  - for a **new** record, `custody = custody.unwrap_or(false)`.
- **New `add_object_custodians(data_dir, mid, &[[u8;32]], now)`**: idempotent union.
- **`clear_peer_routes` (`:711`)** keeps every record of the peer and clears only its routes (G4). It no longer keeps only the records with `unsent || custody || !custodians_held.is_empty()`: an `auto` record dropped there fell to the no-record LAN-only plan.
- **Losing the hints file** (unreadable or evicted) stops further deposits for those objects. This fails narrow and never widens.

**ash side:**
- `SendCtx` (`ash/ext.rs:1190-1201`) gains `custody_ok: bool`, set by every user-send call site. `cmd_send_cli` → `run_send` (`ash/cli.rs:6725`) passes `custody_ok = (parsed carrier == Auto)`, which is also the default when `--carrier` is absent. It reaches all three entry points:
  - `run_send_secure` (`ext.rs:2242`);
  - `run_send_secure_on` (`:2267`);
  - `run_send_secure_routes` (`:2299`).
- The menu and chat send (`ash/cli.rs:6196`) pass `true`. Live chat (`ash send --chat`) does so since G4: `true` unless `--carrier lan`, through `cmd_chat_session`'s `custody_ok`.
- `OutboxHandoff` (`ash/pair_init_lab.rs:739`) gains `custody_ok` and `own: Cell<Option<[u8;16]>>`, set when this send stages its own message.
- `record()` passes `Some(custody_ok)` only for `own`, and `None` for every earlier row it re-notes (`:1287`).
- ash does **not** evaluate the custody gate. The worker does, so lab runs do not need the env var in the ash process.

### 7.2 Eligibility (pure functions in `core/outbox.rs`, unit-tested)

```rust
pub const CUSTODY_AFTER_MS: u64 = 60_000;           // lab override RAVEN_LAB_CUSTODY_AFTER_MS (debug + lab A only)
pub const CUSTODY_MIN_REMAINING_MS: u64 = 60_000;
pub fn custody_eligible_message(gate_live: bool, record_custody: bool, peer_pinned: bool,
    age_ms: u64, remaining_ms: u64, direct_failed_or_no_route: bool, size_ok: bool) -> bool;
pub fn custody_eligible_ack(gate_live: bool, peer_pinned: bool, remaining_ms: u64,
    push_failed_or_no_route: bool, origin: OwedOrigin, size_ok: bool) -> bool;   // origin != Rebuilt
```

**A message** may go to custodian C only when all of these hold:
- the gate is live;
- the record exists with `custody`;
- the recipient is pinned;
- age ≥ `CUSTODY_AFTER_MS`;
- at least 60 s of validity remain;
- the size is within `MAX_RFC1_ENVELOPE`;
- a direct attempt in **this** attempt failed, or no direct route exists. Objects only deferred by the frame cap do not qualify;
- no verified ACK has arrived (the row is live);
- C is in `contact.custodians`, usable, not in `custodians_held`, not refused-for-this-object, and not parked.

`unsent` plays **no** part. A message written but never ACKed qualifies once a later direct attempt fails.

**An ACK** (an owed ACK, or a Prepared ACK row) may go to C only when all of these hold:
- the gate is live;
- the peer is pinned;
- its direct push failed, or `ack_routes` is empty;
- origin is not `Rebuilt`;
- at least 60 s of validity remain;
- C is listed in **this node's** contact row for that peer, is usable, and is not already in the owed entry's `held_by`.

ACKs have no `ObjectRoutes` record, and none is consulted.

**A usable custodian** (`core/outbox.rs::custodian_routes(data_dir, c, carrier_gates, custody_gates) -> Result<Vec<(OutboxRoute, OutboxRoute)>, &'static str>`):
- `contact_admission(c)` is Allowed and pinned;
- `c` is neither the local key nor the peer;
- the routes are `plan_object_routes(any-Auto record, with_learned_routes_where(c, keep), gates)` filtered by `custody_route_allowed` (§14), where `keep` is the caller's on-link filter (the worker's `ctx.on_link`, and the same netwatch check in the fetcher), so a learned address on none of this computer's networks is not dialled; hide-IP (the row's or the node policy's) drops Internet direct routes, as in every other planner;
- LAN routes are localized with `localize_lan_route(route, pinned = custody_gates.wan, ..)`, so only local-network addresses are allowed while WAN custody is off;
- no routes left gives `CUSTODIAN_NOT_USABLE`.

### 7.3 Changes in `attempt_peer_inner` (`rn/outbox.rs:1307`)

**`Candidate` (`:1212`) gains:**
- `held_why: Option<&'static str>`;
- `custody_new: Vec<[u8;32]>`;
- `custody_dialed: bool`;
- `custody_refusal: Option<&'static str>`.

**1. Candidate building, under the lock (`:1561-1735`).**
- Messages: when `routes.is_empty()`, compute `why` as today. Then:
  - if `custody_possible` holds, **do not `continue`**. `custody_possible` is a cheap check: gate live, record custody, pinned, some listed custodian neither held nor parked. Instead set `held_why = Some(why)`, keep `routes = []`, and fall through to the cert, history and `capture` steps;
  - otherwise insert `Held(why)` as today.
- Prepared ACK rows with empty `ack_routes` (`:1611`) get the same treatment, with `custody_eligible_ack`.

**2. Direct dial loop (`:1752-1810`).** Unchanged. Candidates with `routes = []` are in no batch.

**3. Custody phase, without the lock.** New, after the direct loop and before the second lock.
- **Objects:** message candidates with `sent.is_none()` passing `custody_eligible_message`, plus Prepared ACK candidates and owed ACKs (`owed` minus `acks_sent`) passing `custody_eligible_ack`.
- **For each custodian C**, in contact order, at most 2:
  - skip it if `custody::parked(C, peer)`;
  - plan `custodian_routes(C)`;
  - build at most 16 `DEPOSIT` frames.
- **Each frame:**
  - recipient = peer;
  - RSO1 = `{store_tag, message_id, created, expires, flags 0, envelope}`;
  - the tag comes from `store.outbound_store_tag_for_object(key, bytes)`, cached per (session, day). Owed ACKs with no session use `outbound_session_for_object` and then `record_key_for_session_id`. If the tag cannot be computed, the object is skipped this time with `STORE`.
- **Dial** with `ctx.dialer.dial(data_dir, route, hex(C), frames)`, trying C's routes in order until one returns `Ok`.
- **Results:** set `custody_dialed = true` whenever frames were written, which means `Ok`, or `PEER_CLOSED` after frames were sent. Match `DEPOSIT_RESULT` by `req_id`:
  - `STORED` / `DUPLICATE`: push C to `custody_new`. After a STORED, call `custody::note_deposit(C)` so the fetcher polls C for the returning ACK;
  - `REFUSED_OBJECT`, `EXPIRED`, `MALFORMED`, `CONFLICT`: mark the object refused at C (`Entry.custody_refused`, in memory);
  - `POLICY_DENIED`, `HOLD`: park C for 1 h;
  - `NOT_VERIFIED`: park C until an explicit `raven outbox retry`;
  - `RECIPIENT_NOT_ACCEPTED`: park (C, peer) for 1 h;
  - `STORE_FULL`, `QUOTA`, `RATE_LIMITED`, `PERSISTENCE`, an unknown code, or a missing reply: short park with `retry_delay`.
- **Dial errors** go through `dial_error_code`. A `PEER_CLOSED` after an accepted link adds a **strike**. 3 strikes within 1 h park C for 1 h as `CUSTODY_UNSUPPORTED`.
- **Park map.** It lives in `rn/custody.rs`, is shared with the fetcher, is held in memory, and is cleared by an explicit `OutboxKick`.

**4. Under the second lock (`:1812+`).**
- Messages with non-empty `custody_new`:
  - if `pending` (Prepared), call `store.retry_endpoint_outbound(&key, &digest, &local_device, wall, &mut |d,_| Ok(*d))`. This is the handoff: the row becomes Queued, delivery state Sent;
  - then `add_object_custodians(mid, &custody_new)`.
- Prepared ACK candidates deposited: `retry_endpoint_outbound` with the callback `|d, bytes| OwedAcks::record(peer, Some(sid), d, bytes, exp, Origin::Prepared, &custody_new)`. That makes the row Queued plus a durable owed entry.
- Owed ACKs deposited: `OwedAcks::add_held(digest, C)`.
- `unsent` restore (`:1875`): `written = sent.is_some() || refused-after-read || custody_dialed`.
- Outcome mapping, with a new branch evaluated **before** the `(_, None)` arm (`:1916`). Let `held = record.custodians_held.len() + custody_new.len()`:
  - `(Message, None)` with `held > 0` gives `Outcome::Deposited { held }`;
  - `(Message, Some(c))`, not delivered, gives `Sent{..}` as today, with the entry's `in_custody = held`;
  - `(Message, None)` with `held == 0` and `routes.is_empty()` gives `Held(custody_refusal.or(held_why))`;
  - `(Ack, None)` with `custody_new` non-empty gives `AckSent { carrier: <custodian route carrier> }`;
  - everything else is unchanged.
- **A deposit never yields `Delivered`.** Only an ACK accepted by `accept_sealed_ack` or `accept_ack_envelope` does (§8, §9).

**5. `Outcome::Deposited { held: u8 }`** (`:953`, `apply_outcome` `:978`):
- state becomes `Sent` (FORWARDED);
- `last_error` becomes `IN_CUSTODY`;
- `in_custody = held`;
- normal backoff applies, so direct retries continue up to 10 min apart, and `peer_seen` still triggers.

**6. Restart.** `Entry.in_custody` is rebuilt from `custodians_held` at scan.
- A crash after STORED but before `add_object_custodians` re-deposits, and C answers `DUPLICATE`, so there is still exactly one row.
- With C up and D down, the object goes to C. When D comes back it also goes to D, because D is not in `custodians_held`. That is the redundancy S7 relies on.

**Visibility.** `OutboxItem` (`core/ipc.rs:175`) gains `#[serde(default, skip_serializing_if = "is_zero")] in_custody: u8`.

---

## 8. Recipient (Bob): fetcher and relayed ingest

### 8.1 Fetcher task: `rn/custody.rs` (new)

```rust
pub async fn run_fetcher(data_dir: PathBuf) -> Result<(), String>; // supervised "custody_fetch" in Commands::Service (rn/main.rs:3801)
pub(crate) fn peer_seen(peer: &[u8; 32]);       // a custodian linked to us: fetch now if its last round failed (≤ 1/min per custodian)
pub(crate) fn kick();                           // listener_up, OutboxKick
pub(crate) fn note_deposit(custodian: &[u8; 32]); // worker deposited there: poll at the base interval
pub(crate) fn parked(c: &[u8; 32], peer: &[u8; 32]) -> Option<&'static str>; pub(crate) fn park(...);
```

**Wiring:**
- `wait_service_end` (`rn/main.rs:3200`) gets a new handle.
- `custody::peer_seen` goes next to `outbox::peer_seen` at `rn/lan_direct.rs:344` and `rn/internet_direct.rs:466`. The second also covers p2p.
- `custody::kick` goes next to `outbox::listener_up` at `rn/lan_direct.rs:441`, `rn/internet_direct.rs:565` and `rn/p2p.rs:1310`, and in the `OutboxKick` handler (`rn/ipc_server.rs:407-419`).
- `Dialer` and `NetDialer` become `pub(crate)`.
- If the gate is closed for the life of the process, `run_fetcher` awaits `pending()`.

**Targets:**
- The union of `custodians` over pinned, unblocked contacts, where each custodian is itself pinned, unblocked and not self.
- For each custodian C, the peers are the contacts listing C, minus peers in a per-peer backoff:
  - `NO_PEER_CERT`: 5 s doubling to 10 min;
  - `OWED_ACK_FULL`: until the worker reports the owed table below 75 %;
  - `CONTACTS_UNREADABLE`.

**Tags.**
- Read `live_session_heads` (metadata only, cached 5 min, re-read on `kick` or `peer_seen`).
- Compute the days per §4.2 and look up the tag cache. A cache miss costs one `mailbox_store_tags` protected load per session per day. A Provisional result is cached as negative for 10 min.
- Keep a reverse map `tag → RelayHint { record_key, peer_device, store_tag }` for the round.
- Sort the tags and cut them into chunks of 32.

**One trigger.** At most `MAX_PAGES_PER_TRIGGER = 8` dials per custodian.
1. Frames: `[RELEASE(pending_release[C][..32]) if any, FETCH(chunk, cursor[C][chunk_digest], 16)]`. The cursor is `None` unless saved.
2. Parse the replies (skip the RLB1 offer and any non-RFC1 frame).
   - A `RELEASE_RESULT{OK}` removes the sent digests from the pending list.
   - Each `FETCH_ITEM` must pass the RFC1 RSO1 rules, and its `store_tag` must be in this chunk. Otherwise drop it silently: no ingest, no release.
   - Compute `custody_digest` locally (Conformance §2.2 rule 1). Run `ingest_relayed_object` (§8.2) on the blocking pool.
   - A page comes in page-token order, which says nothing about when its objects were written. They are ingested in order of their creation time, each at its own receive time (`taken_at`), so the inbox lists them in the order the contact wrote them (cutoff pack CP.14, s97).
3. Classify each outcome:
   - Accepted, Duplicate or Refused: push the digest to `pending_release[C]` (cap 256);
   - `Retry(Item)`: keep it unreleased;
   - `Retry(Peer)`: add the peer to the per-peer backoff;
   - `Retry(Store)`: stop the trigger and back off the fetcher.
   - After `MessageAccepted` or `AckAccepted`, call `outbox::kick(Some(peer), false)`.
4. `FETCH_END`:
   - `has_next = 1`: save `cursor = next_token` and continue while pages remain;
   - `has_next = 0`: clear the cursor and move to the next chunk;
   - a non-OK code is classified as in §7.3 (park or backoff C).
5. If releases are still pending at the end, send one RELEASE-only dial.

**Fairness.** When a trigger stops at the page cap with `has_next=1`, the next trigger **resumes from the saved cursor**. Every object is therefore visited within ⌈N/128⌉ triggers, and objects stuck in Retry cannot starve later ones or other peers.

**Schedule (per custodian, in memory, rebuilt at start):**
- base interval 60 s (lab: `RAVEN_LAB_CUSTODY_FETCH_MS`);
- after 3 consecutive empty `FETCH_END`s (0 items, no next page), the interval doubles up to 10 min;
- it resets on `kick`, `note_deposit(C)`, or while any own outbox entry to a peer listing C is `IN_CUSTODY`, because an ACK is expected;
- `peer_seen(C)` (C linked in) makes C due now only when C's last round reached nothing (it is back); a C that answered keeps its next time and its empty-round count. Field E2 night: two friends that each fetch from the other woke each other's fetch with every fetch link, and neither left the 60 s base (about 2 links a minute per friend all night);
- an RRH1 from C that changed its routes, or a LAN beacon find of C at a new address, makes C due now, its empty-round count kept; one that lands while a trigger is dialling C makes C due again when that trigger ends, if the trigger reached nothing;
- a lab base interval scales the 10 min cap to ten base intervals;
- failures use `retry_delay` (5 s doubling to 10 min, ±50 %);
- a parked C is skipped.

**Crash safety.** Pending releases and cursors live in memory. If they are lost, the next trigger re-fetches, gets Duplicate, and releases again.

**A custodian that moved (cutoff pack F8, CP.14).** Carol comes back on another address while she holds Bob's mail, and Bob may never have sent her an RRH1. While custody is live and noise pins (M0) are on, her route-hints announcer tells the verified contacts she holds unreleased objects for (`friend_custody::held_recipients`, newest deposit first, at most 64), ahead of the contacts whose RRH1 is live, and only those with a noise pin: every try of an announce link is an identity-bearing dial. Bob's listener calls `peer_seen(C)` (a fetch from her failed meanwhile), his RRH1 receiver too once her new LAN port is stored, and `custodian_routes` plans that learned route after the saved one, so he fetches at once. Harness: s96 and s97. It ships with the route-hints and custody gates; it does not cover Bob moving as well (the Phase 3 beacon).

### 8.2 Relayed ingest: `core/relayed_ingest.rs` (new)

```rust
pub struct RelayHint { pub record_key: IndexedSessionRecordKey, pub peer_device: [u8; 32], pub store_tag: [u8; 16] }
pub enum RetryScope { Item, Peer, Store }
pub enum RelayedOutcome {
    MessageAccepted { peer: [u8; 32], message_id: [u8; 16], duplicate: bool },
    AckAccepted     { peer: [u8; 32], acked_message_id: [u8; 16] },
    Refused(&'static str),            // permanent for this recipient: release (hide) it
    Retry(RetryScope, &'static str),  // keep it; no history, no ACK
}
pub fn ingest_relayed_object(data_dir: &Path, identity: &Identity, rso1: &StoreObject,
                             hint: &RelayHint, now_ms: u64) -> RelayedOutcome;
```

The order follows errata rule 5: size → strict decode → TTL → route/session → device/cert + outer auth → AEAD → commit → ACK outbox.

1. **Size and strict decode.** RFC1 RSO1 rules, and `rso1.store_tag == hint.store_tag`. Otherwise `Refused(CUSTODY_MALFORMED)`.
2. **`admit_relayable(env, now)`:**
   - `Expired` gives `Refused(ENVELOPE_EXPIRED)`;
   - `FromTheFuture` gives `Retry(Item, CLOCK)`, because Bob's clock may be behind;
   - anything else gives `Refused(CUSTODY_REFUSED)`. PairInit never enters.
3. **`canonical_outbound_fields(&env)`.** Otherwise `Refused(CUSTODY_REFUSED)`.
4. **`contact_admission(hint.peer_device)`** must be `Allowed` and pinned. Otherwise:
   - `Refused(SENDER_NOT_CONTACT | SENDER_BLOCKED | CONTACT_NOT_VERIFIED)`;
   - an unreadable book gives `Retry(Store, CONTACTS_UNREADABLE)`.
5. **`env.verify(&hint.peer_device)`**, a cheap pre-check before any protected load. Otherwise `Refused(OUTER_SIGNATURE_INVALID)`. Junk from another depositor under a known tag ends here.
6. **Message only, owed-ACK room.** `OwedAcks::has_room(peer)`:
   - false gives `Retry(Peer, OWED_ACK_FULL)`, which is back-pressure: the object stays at Carol;
   - an error gives `Retry(Store, OWED_ACKS_UNAVAILABLE)`.
7. **Certificate.** Open the store. `cert = session_bound_peer_certificate(data_dir, store, &hint.record_key, &peer)` (`core/lan_dispatch.rs:1743`):
   - `None` gives `Retry(Peer, NO_PEER_CERT)`;
   - `Err` gives `Retry(Store, STORE)`.
8. **Message.** `revoked = lan_dispatch::sender_lineage_revoked(data_dir, &local_registry, &cert)`. This wraps `identity_denies_device_lineage` (`:1798`, made `pub(crate)`) with exactly the arguments `handle_indexed_message` uses (`:1460-1465`). Then call the extracted `lan_dispatch::accept_message_under(data_dir, identity, &cert, revoked, &[hint.record_key.clone()], packed, now, AckSink::Owed { peer, session_id })` (§8.4). It:
   - runs `accept_message_envelope` on that **single** session (a `RouteTagMismatch` there is final);
   - persists history (fail closed, giving `Retry(Item, HISTORY)`);
   - runs `enqueue_committed_ack` with the callback `|d, bytes| OwedAcks::record(peer, Some(sid), d, bytes, exp, Origin::Relayed, &[]).map(|_| *d).map_err(|_| ())`;
   - if the call returned a row but **the callback did not run** (Queued intent, `:2297-2304`), calls `OwedAcks::record(.., row.immutable_envelope_bytes, ..)` explicitly. A failure there gives `Retry(Item, OWED_ACK_WRITE)`.

   The result is `MessageAccepted` only once the ACK is durably owed.
9. **ACK.** `denied = peer_lineage_denied(data_dir, &cert)` (`core/outbox.rs:113`, the registry choice `handle_ack` uses). Then `store.accept_ack_envelope(&hint.record_key, packed, &cert, denied, now)` (typed errors), then `record_outbound_delivered(data_dir, store, peer, session_id, acked)` (`core/outbox.rs:174`; it settles Prepared rows and updates history, like `handle_ack` `:1592-1604`). The result is `AckAccepted`.
10. **Typed error classification** (§8.3).

Ingest without a hint, for a future push carrier, is a non-goal.

### 8.3 Error classification (`IndexedSessionStoreError` → outcome)

| Outcome | Errors |
|---|---|
| **Refused** (release) | `AuthenticationFailed`, `OuterSignatureInvalid`, `DeviceBindingMismatch`, `InvalidDeviceCertificate`, `RevokedDevice`, `LogicalMessageConflict`, `InvalidIndexedMessage`, `InvalidEndpointEnvelope`, `EndpointTypeMismatch`, `InvalidEndpointPayload`, `DeviceHintMismatch`, `RouteTagMismatch` (single hinted session), `Replay`, `SessionNotConfirmed`, `BindingConflict`, `IndexExhausted`; `EndpointNotCurrentlyValid` **only if** `env.expires_at ≤ now` |
| **Retry(Item)** | `EndpointNotCurrentlyValid` otherwise (clock behind, or before session start); `ForwardJumpTooLarge` (shrinks once earlier objects are accepted); `OutboundPending`; `OutboundQueueHandoff` (the ACK row stays Prepared, and the worker pushes or deposits it); history failure; **any error not listed here** |
| **Retry(Store)** | `Sqlite`, `ProtectedStore`, keychain/vault errors, `CorruptProtectedState`, `CorruptEndpointState` |

Retry objects are never released and are retried on later triggers. The cursor keeps them from blocking others, and the TTL bounds them.

### 8.4 Refactor in `core/lan_dispatch.rs` (link behaviour unchanged)

Extract the body of `handle_indexed_message` (`:1440-1554`):

```rust
pub(crate) enum AckSink<'a> { ReplyOnLink, Owed { peer: &'a [u8; 32], session_id_out: &'a mut Option<[u8; 32]> } }
pub(crate) enum IngestError { Store(IndexedSessionStoreError), History(String), Other(String) }
pub(crate) struct MessageAccept { pub session_id: [u8; 32], pub message_id: [u8; 16], pub duplicate: bool,
                                  pub ack: EndpointOutbound, pub callback_ran: bool }
pub(crate) fn accept_message_under(data_dir: &Path, identity: &Identity, sender_cert: &DeviceCertificate,
    sender_revoked: bool, candidates: &[IndexedSessionRecordKey], packed: &[u8], now: u64,
    sink: AckSink<'_>) -> Result<MessageAccept, IngestError>;
pub(crate) fn sender_lineage_revoked(data_dir: &Path, local_registry: &DeviceRegistry,
    cert: &DeviceCertificate) -> Result<bool, String>;
```

- `handle_indexed_message` becomes a wrapper. It passes the link peer's cert, all candidates newest first and `ReplyOnLink` (callback `|d,_| Ok(*d)`), and maps errors to the same redacted strings.
- `handle_ack` is unchanged: relayed ACKs reuse the `core/outbox.rs` functions.
- Every existing `lan_dispatch` test must pass unchanged.

---

## 9. ACK return and the durable owed-ACK table

**New `core/owed_acks.rs`**, file `<data_dir>/owed_acks.sqlite`:
- created lazily;
- opened with `open_private_data_dir_sqlite`, `busy_timeout(10 s)`, WAL, `synchronous=FULL`, `user_version=1`.

```sql
CREATE TABLE IF NOT EXISTS owed_acks_v1 (
  ack_digest BLOB PRIMARY KEY NOT NULL CHECK(length(ack_digest)=32),  -- authenticated_object_digest (store key)
  peer BLOB NOT NULL CHECK(length(peer)=32),
  session_id BLOB CHECK(session_id IS NULL OR length(session_id)=32),  -- NULL for F8 (resolved when depositing)
  bytes BLOB NOT NULL,                                                 -- exact sealed ACK envelope
  expires_at_ms INTEGER NOT NULL,
  origin INTEGER NOT NULL,                                             -- 0 link (F8) 1 relayed 2 prepared 3 rebuilt
  recorded_at_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS owed_ack_held_v1 (ack_digest BLOB NOT NULL, custodian BLOB NOT NULL,
  PRIMARY KEY (ack_digest, custodian));
```

**API:**
- `record(peer, session_id, digest, bytes, expires, origin, held) -> Result<(), OwedError>`:
  - idempotent;
  - fills a NULL `session_id`;
  - `OwedError::Full` when the peer has 256 entries or the table has 2,048. It **never evicts**.
- `has_room(peer)`, `list(now)` (also deletes expired entries), `clear(digests)`, `add_held(digest, c)`, `drop_peer(peer)`.

**Corruption.** On an integrity failure or a newer `user_version`:
- rename the file to `owed_acks.sqlite.corrupt-<ms>`;
- create a new one;
- rebuild from `live_queued_ack_rows(now)` with `origin = Rebuilt`.

Rebuilt entries are **push-only**: they are never deposited, so ACKs already written on links do not use up a custodian's quota. Pushing an already-delivered ACK is a no-op at the receiver (`RAVEN_ACK_V1` §4).

**Worker integration:**
- `UnsentAck` (`rn/outbox.rs:291`) gains `session_id: Option<[u8;32]>`, `held_by: Vec<[u8;32]>` and `origin`.
- At every scan the worker merges `OwedAcks::list` into `unsent_acks`. Durable entries are never evicted from memory: `MAX_UNSENT_ACKS*` rise to 2,048 total and 256 per peer for durable entries. F8 entries whose durable write failed keep today's eviction rule.
- At the end of `attempt_peer`, still on the blocking pool, `OwedAcks::clear(&report.acks_done)` runs, covering ACKs written directly, expired, or owed to a non-contact.
- An owed ACK that was deposited **stays** owed until it is written directly or expires. Direct pushes continue with backoff, so a reachable Alice gets it sooner.

**F8 durability.** `note_unsent_replies` (`:415`) keeps its in-memory insert and adds `tokio::task::spawn_blocking(move || OwedAcks::record(.., None, .., Origin::Link, &[]))`. Nothing blocks the async listener (`rn/lan_direct.rs:384`, `rn/internet_direct.rs:506`).

**Path back to Alice.** Bob's worker:
1. pushes the owed ACK over Alice's direct routes (`ack_routes`, `:1365-1383`);
2. if that fails, deposits it at **Bob's** custodians for Alice (§7.2), under the tag for Bob's outbound direction and `day(ack.created_at)`, which equals Alice's inbound tag.

Alice's fetcher ingests it on the ACK path (§8.2 step 9), so the history reads "delivered". Alice's worker then sees `outbound_already_delivered` in `settle_locally` (`:1972`) and clears the record.

---

## 10. Delivery state, CLI, IPC

**Delivery state** (`proto/RAVEN_DELIVERY_STATE_V1.md`):
- deposit `STORED` = `FORWARDED` (store `Sent`), with status `IN_CUSTODY`;
- `DELIVERED_TO_DEVICE` only after a verified ACK, by any path;
- history labels are unchanged.

**CLI (`ash/cli.rs`):**
- `raven node custody on|off|status [--purge]`:
  - uses a **new** `set_node_custody(data_dir, on)`, which loads, sets `.custody` and saves. It leaves `auto_policy`, `bridge`, `store` and `relay` untouched;
  - on an unreadable file it refuses with a repair hint rather than rewriting the file from `fail_closed()`;
  - `on` prints the scope: sealed objects of verified contacts only, ≤ 128 per pair per day, held ≤ 24 h, unreadable by this node, visible metadata;
  - `on` warns when the gate is closed (`CUSTODY_HOLD` text) and when the LAN listener is loopback-only;
  - `status` reads `friend_custody.sqlite` directly and prints counts only: rows, bytes, released, depositors, recipients.
- `raven contact set-addr --tag T --custodian @C [--custodian @D]` and `--clear-custodians`. The set-time validation is in §4.1. The command prints the matching command to give to the other side.
- `raven contact show` lists custodians and flags any that are not usable.
- `raven outbox status/list`: "held by N friend(s), not delivered yet" when `in_custody > 0`
  (Phase 3 P3.C4: "held by N friend(s) until {until}, not delivered yet", the envelope's expiry in
  local time; an expired row says "time ran out: {who} didn't collect it from the friend who held
  it before it expired {when}").
- `raven send`, when queued with custodians and a live gate: "queued; raven-node keeps trying and leaves a sealed copy with @carol if Bob stays unreachable".

**IPC (`core/ipc.rs`, additive):**
- `OutboxItem.in_custody` (serde default).
- **No new request.** `OutboxKick` also calls `custody::kick()`.
- `LanDial`, `InternetDial` and `P2pDial` handlers (`rn/ipc_server.rs:565`, `:611`, `:657`, shared with Windows through `serve_one`) answer `Error{code:"CUSTODY_IPC_REFUSED"}` if any frame `is_rfc1`, unless `lab_test_a_enabled()`.
- The `IPC_FORBIDDEN_FIELD` denylist is unaffected.
- RDAP is unchanged.

**Mixed versions.**
- An older ash or raven-node that rewrites `contacts.json`, `outbox_routes.json` or `node_policy.json` drops the new fields. Custody then stops, which fails closed.
- An older daemon ignores unknown record fields.

---

## 11. Security analysis

**No new crypto.** The design uses only existing primitives:
- the frozen mailbox and store tag derivation (with its vector);
- SHA-256 of exact bytes (Conformance §2.2);
- the Mailbox V1 page token;
- the existing `Envelope::verify` Ed25519 check;
- the Noise XX link with signed bind;
- the endpoint transaction (route tag, certificate binding, outer signature, RVNA1 `0x03` AEAD, inner ACK signature, atomic commit).

Nothing new is signed or encrypted.

| Threat | Result |
|---|---|
| A stranger, a blocked key, or an unpinned contact uses custody | Link admission refuses before identity is revealed (`core/lan_dispatch.rs:586`). An unpinned contact gets `NOT_VERIFIED` on every op. |
| A co-custodian or third contact knows the pair's tag | FETCH and RELEASE match `recipient == link peer`, so they get 0 objects and release 0 (A1). |
| Pre-deposit poisoning: a third party deposits a copy of Alice's object first, or mutates the hint or hop fields | Signer equals depositor, canonical fields are enforced, and the digest is SHA-256 of the exact bytes. Another depositor is refused with `REFUSED_OBJECT`. The same object under another tag or recipient gets `CONFLICT` with no overwrite (A2). |
| Junk deposited under a known tag to waste Bob's keychain | Charged to (junk depositor, Bob) quotas. Bob's cheap `env.verify(peer)` refuses it before any protected load (A4). |
| A contact floods Carol | Per-attempt and per-byte rates, pair, depositor and node caps. Refuse, never evict. Rows are purged when the contact is removed or unpinned. |
| WAN or forwarded-port custody while the HOLD is on | Carol checks carrier and source per link. A LAN link needs a local-network source (A3). |
| Local IPC client fabricating custody ops | Dial IPC refuses RFC1 outside the lab. |
| Carol reads, tampers with, forges or replays | Sealed. Bob's route tag, certificate, signature and AEAD refuse tampering, and nothing is committed or ACKed. A replay is an endpoint Duplicate, which only re-queues the existing ACK. |
| Carol drops, withholds or fakes delivery | This is an availability issue only. Alice keeps retrying directly, and up to 2 custodians give redundancy. Only a verified ACK delivers (errata rule 4). |
| PairInit or RLB1 leaks into custody | `admit_relayable` refuses `PairingMaterial` at deposit and again at ingest. The harness byte-scans Carol's files (C11). |
| Downgrade to the unauthenticated bridge | No code path leads from custody to `bridge_run` or `forward_queue`. |

**What Carol learns** (stated in the waiver and in `raven node custody on`):
- depositor and **recipient** identities, explicitly (the cost of A1);
- size, time, `message_id` and expiry of each object;
- the daily store tag, which links the pair's traffic within a day;
- when the recipient fetches and **releases**, so she knows it received the object;
- Bob's ACK deposit right after his fetch, which tells her Bob processed the message and when;
- that she can verify outer signatures against her contacts' keys (no new information, because the depositor is the signer).

**Other observers and exposures:**
- Two colluding custodians of the same pair can link objects by digest, and each sees the pair's tags.
- **Ciphertext stays at Carol until TTL (≤ 24 h), even after release.** Indexed sessions have no forward secrecy within a session (waiver §4.1). Anyone who later obtains Alice's or Bob's session state within that window can open Carol's copies, which is the same exposure as a recording of LAN traffic.
- `friend_custody.sqlite` (0600 / ACL) holds ciphertext, tags, keys and timestamps.
- `owed_acks.sqlite` holds sealed ACKs only.

**Errata compliance:**

| Rule | How it is met |
|---|---|
| 2 | Only objects staged under a confirmed session are deposited. Bob ingests only under the hinted confirmed session. |
| 3 | ACK bodies stay sealed. Carol never parses them. |
| 4 | Only verified ACKs deliver. `STORED` = FORWARDED. |
| 5 | The ingest order is §8.2. The ACK is durably owed before release. A duplicate re-queues the existing ACK. |
| 6 | Carol writes only after admission. The dedup key is SHA-256 of the exact bytes. |
| 8 | Single cooperative hop. Hop fields are pinned to canonical values and never rewritten. No budget claim is made. |
| 9 | Polling uses rotating mailbox tags. Deletion is TTL-only. RELEASE hides and never deletes. ACKs never delete. **No amendment is needed.** |

---

## 12. Reliability scenarios (all automated unless marked physical)

The C11-C17 names in this table and in §14 are this design's harness names, which were never built (§16.4); the custody harness that exists is listed in §19.6.

| # | Scenario | Expected |
|---|---|---|
| S1 | A, B and C all online | Direct delivery. No custody file at C (C15). |
| S2 | B offline (A and C up), then B and C (A away), then A and C | Deposit; B fetches, commits and releases; B deposits the ACK; A fetches it and shows delivered (C11). |
| S3 | C offline when A sends | Direct and custody both back off. The object is deposited when C returns, if still eligible. |
| S4 | C restarts holding objects | Objects persist (`synchronous=FULL`) and B fetches them (C12a). |
| S5 | B crashes after ingest, before RELEASE | Re-fetch gives Duplicate; history and ACK are idempotent; one inbox row (C12b). |
| S6 | A crashes between the deposit result and `add_object_custodians` | Re-deposit gives `DUPLICATE`; one row at C (C12c). |
| S7 | Two custodians, D down, then D up | Held at C, then also at D. B fetches from both and gets one inbox row (C16). |
| S8 | Message expires before B fetches | Custody expires; A records expired (unchanged semantics). |
| S9 | ACK expires before A fetches it | A shows expired although B got it. **Known limit** (§13). |
| S10 | C runs an old build | 3 `PEER_CLOSED` strikes give `CUSTODY_UNSUPPORTED` for 1 h; direct retries continue (C14). |
| S11 | Custody off or gate closed at C | `POLICY_DENIED` or `HOLD` shown in `raven outbox status`. |
| S12 | C full, over quota or rate-limited | Backoff; the second custodian is used; per-pair isolation holds (C13). |
| S13 | B removed or blocked A | Bob refuses and releases. No history, no ACK. |
| S14 | A blocked by C | `LINK_NOT_ACCEPTED`; custodian skipped. |
| S15 | Lost reply after commit (DEPOSIT or FETCH) | `DUPLICATE` on retry; objects come back until released. |
| S16 | Out-of-order arrival (message 2 direct, message 1 later via C) | Accepted within the skip window (`MAX_SKIPPED_KEYS=256`). |
| S17 | ±5 min skew around midnight | The day range includes `day(now+5 min)`. |
| S18 | Custodian disk error | `PERSISTENCE`, backoff; nothing claimed. |
| S19 | `owed_acks.sqlite` corrupt | Quarantine plus push-only rebuild. |
| S20 | Session older than 24 h with no direct meeting | Custody cannot help: `ATSAM_SESSION_REQUIRED` at send. |
| S21 | Only A lists C (B lists nothing) | `IN_CUSTODY`, then expired. Documented; the CLI prints the reciprocal command. |
| S22 | B's clock 10 min behind | `FromTheFuture` / not-yet-valid gives Retry, not release. Accepted once the clock is inside the window. |
| S23 | More than 256 relayed messages from A while A is offline | Owed table full gives `OWED_ACK_FULL` back-pressure. Objects stay at C. Every ACK eventually reaches A as the table drains. |
| S24 | Co-custodian D fetches or releases at C with A↔B's tag | 0 objects, 0 released; B's delivery unaffected (C13). |
| S25 | A's only route to B is blocked (`LINK_NOT_ACCEPTED`) or B has no LAN address | The message is captured with `routes=[]` and deposited (w10, w11). |

---

## 13. Session window and first contact through a friend (deferred)

**Implemented (Phase 3):** the proactive re-pair below is implemented as session renewal (`raven-core/src/session_renewal.rs`, `raven-node/src/renewal.rs`, behind `SESSION_RENEWAL_PRODUCTION_ENABLED`; any-network plan Phase 3 item 4). The rule was refined: instead of "the smaller key re-pairs", the side that did not start the newest session renews below 12 h left, so the initiator alternates and each side holds about one responder claim per contact; the other side renews below 10 h as a fallback; after a lapse (within 14 days) the smaller key goes first and the other side 10 minutes later. It runs on every live, endpoint-authenticated link, shares one re-pair budget per contact (4 a day, 60 s apart), resends a PairInit whose PairResponse was lost byte for byte, never re-seals or retires, and yields to the session-reset step. Sealed asynchronous PairInit stays deferred. The 24 h session and envelope limits below are unchanged.

**The limit.**
- Sessions this node initiates last 24 h (`core/lan_dispatch.rs:1929`). Envelope validity is at most min(session end, 24 h).
- PairInit V1 is signed but not encrypted, and carries addresses and trust material (`proto/RAVEN_PAIR_INIT_V1.md` §7). It may never enter custody.
- So custody delivers only within 24 h of the pair's last direct pairing.

**Recommended small companion (separate PR, optional): proactive re-pair.**
- Trigger: the worker sees an authenticated link with a contact (`peer_seen`, or its own successful dial), and the newest confirmed session with that contact expires within 12 h.
- Rule: the side with the lexicographically **smaller** Ed25519 key re-pairs.
- Mechanism: it **dials** and runs `create_initiator_pair_init` (`core/lan_dispatch.rs:1935`) over its own dial. A listener cannot start a PairInit on a link the peer opened (`rn/lan_direct.rs:353-389`), so the dialing side has to start it.
- Crossed pairings are already tolerated (`core/indexed_session_store.rs:3370-3381`).
- Effect: custody stays useful for 24 h after the pair's **last meeting**.

**Deferred: sealed asynchronous PairInit (transports Q3).** This needs a new spec and an external review before any code is written. It is a new construction, even though it uses existing suite-1 primitives. Its requirements:
- encryption to the responder's signed prekey;
- a pre-session mailbox namespace;
- one-time-prekey claim semantics under reordering (`proto/RAVEN_PREKEY_LIFECYCLE_V1.md` §6);
- a PairResponse return path.

Until then, `raven send` to a contact with no session says "first contact needs a direct link".

---

## 14. Gates and rollout

**New `core/custody_gate.rs`** (pattern of `core/p2p_gate.rs`):

```rust
pub const FRIEND_CUSTODY_PRODUCTION_ENABLED: bool = false;
pub const FRIEND_CUSTODY_WAN_ENABLED: bool = false;
const _: () = assert!(!FRIEND_CUSTODY_WAN_ENABLED || FRIEND_CUSTODY_PRODUCTION_ENABLED);
pub const CUSTODY_HOLD: &str = "CUSTODY_HOLD: friend custody is lab-only (debug RAVEN_LAB_TEST_A=1); \
    FRIEND_CUSTODY_PRODUCTION_ENABLED=false";
#[derive(Clone, Copy)] pub struct CustodyGates { pub live: bool, pub wan: bool }
impl CustodyGates { pub fn current() -> Self {
    let lab = crate::pair_init::lab_test_a_enabled();
    Self { live: FRIEND_CUSTODY_PRODUCTION_ENABLED || lab,
           wan: FRIEND_CUSTODY_WAN_ENABLED || (lab && env_flag("RAVEN_LAB_CUSTODY_WAN")) } } }
/// Custodian side, per inbound link.
pub fn custody_link_allowed(g: CustodyGates, c: CarrierGates, carrier: OutboxCarrier, source: Option<IpAddr>) -> bool {
    g.live && c.allows(carrier) && match carrier {
        OutboxCarrier::Lan => g.wan || source.is_some_and(crate::outbox::is_local_network_ip),
        OutboxCarrier::Internet | OutboxCarrier::P2p => g.wan,
    }
}
/// Requester side, per planned custodian route (LAN routes then localized with pinned = g.wan).
pub fn custody_route_allowed(g: CustodyGates, c: CarrierGates, route: &OutboxRoute) -> bool;
```

`CarrierGates::current()` is a new helper that reads `lan_direct_live_enabled`, `internet_direct_live_enabled` and `p2p_live_enabled`.

**Tests in this file assert:**
- both flags are false;
- the lab-free gate is closed;
- the generic `live_enabled` tripwires stay closed;
- the HOLD text names the flag and the unlock.

**Every entry point checks the gate:**
- Carol's `handle_frame` (`HOLD`, no disk);
- the worker's custody phase;
- the fetcher;
- `raven node custody on` (saves and warns).

**Phases:**
- **F0, merge (gates false).** All code and tests land. CI runs the unit tests and the custody harness (built as s30 and, for Phase 3, s30p/s30w/s30r and C32-C34, §19.6; the C11-C17 names below were never built) under the lab unlock on ubuntu, macos and windows.
- **F1, owner GO for LAN.** Prerequisites:
  1. `proto/RAVEN_FRIEND_CUSTODY_V1.md` frozen, with its vectors and a `PROTOCOL_VERSIONS.md` row;
  2. notes in `RAVEN_STORE_OBJECT_V1.md` §3/§4 (RFC1 carries unsigned RSO1, TTL-only kept) and `RAVEN_BRIDGE_V1.md` (friend custody is separate);
  3. new codes in `RAVEN_ERROR_CODES_V1.md`;
  4. a custody waiver in the LAN waiver's shape (drafted in Phase 3 as one record for LAN and WAN: [`docs/WAIVER_FRIEND_CUSTODY_DRAFT.md`](../WAIVER_FRIEND_CUSTODY_DRAFT.md), unsigned). Scope: RFC1 over LAN links from local-network sources between mutual pinned contacts' services; RVNA1 `0x03` messages and sealed ACKs only; live use of profile §6 mailbox tags. Residual risks: §11 and S9;
  5. physical rows R-FC1 and R-FC2.

  Then flip `FRIEND_CUSTODY_PRODUCTION_ENABLED`.
- **F2, after the Internet or p2p gates open.** No new code path is needed: both ends are carrier-aware already, and C17 exercises WAN custody under the lab. What is required:
  - the Internet and p2p waivers name RFC1 custody in scope (`docs/WAIVER_INTERNET_DIRECT_DRAFT.md:56` currently excludes it);
  - a physical WAN row;
  - flipping `FRIEND_CUSTODY_WAN_ENABLED`.

  An always-on VPS friend then becomes a natural custodian.

---

## 15. Lab knobs (debug builds **and** `RAVEN_LAB_TEST_A=1` only; ignored otherwise)

| Knob | Effect |
|---|---|
| `RAVEN_LAB_CUSTODY_AFTER_MS` | Overrides `CUSTODY_AFTER_MS` (harness uses 0). |
| `RAVEN_LAB_CUSTODY_FETCH_MS` | Fetch base interval. |
| `RAVEN_LAB_CUSTODY_FORWARD_MS` | Custody handoff (Phase 5): the forwarder's interval while forward rows are pending (default 60 s). |
| `RAVEN_LAB_CUSTODY_WAN=1` | WAN custody in the lab. |
| `RAVEN_LAB_CUSTODY_PRETEND_OLD=1` | Carol closes on RFC1, like an old build. |
| `RAVEN_LAB_CUSTODY_FAULT` | `after_ingest_before_release` (Bob aborts); `after_deposit_before_record` (Alice aborts after STORED, before `add_object_custodians`); `before_custody_dial` (Alice aborts after the unsent clear). |

---

## 16. Test plan

### 16.1 Unit tests in `raven-core`

**`friend_custody.rs`, codec:**
- round trip for every op;
- every negative vector;
- `has_after=0` with a non-zero token is refused;
- reply op sent as a request gives `UNSUPPORTED` echoing `req_id`;
- RSO1 with flags ≠ 0, `created` or `expires` ≠ envelope, or an envelope over `MAX_RFC1_ENVELOPE` gives `MALFORMED`;
- shared vectors decode and encode byte-exact;
- the 48 KiB LAN-send size assert.

**`friend_custody.rs`, DEPOSIT** (two lab identities plus Carol, built with existing test helpers). Each refusal below creates **no row and no file**:
- PairInit- or PairResponse-wrapped, `flags`, ratchet header, expired, validity too long, future `created_at`;
- demo cipher, under `#[cfg(not(feature="unsafe-demo-crypto"))]`, with a separate cfg'd test that the lab feature admits it;
- non-canonical hint, hop or budget;
- signed by someone else (a third party re-deposits Alice's signed object) gives `REFUSED_OBJECT`;
- recipient: self, Carol, not a contact, unpinned or blocked gives `RECIPIENT_NOT_ACCEPTED`;
- same bytes twice gives `DUPLICATE`, charging only the attempt counter;
- same envelope under a different tag or recipient gives `CONFLICT` and the stored row is unchanged.

**Gate, policy, link:**
- `live=false` gives `HOLD` and no file;
- `custody_link_allowed`: Lan with a local source passes; Lan with a public source or `None` and `wan=false` gives HOLD; Internet or P2p with `wan=false` gives HOLD; `wan=true` passes;
- policy off gives `POLICY_DENIED`, while FETCH and RELEASE are still served;
- unpinned link peer gives `NOT_VERIFIED`.

**Quotas and rates:**
- node, depositor and pair caps;
- D at its (D, Bob) cap does not affect (Alice, Bob);
- the attempt window counts DUPLICATE and refusals;
- the bytes window.

**FETCH:**
- recipient binding: D presenting Bob's tags gets 0 objects;
- only the requested tags, unexpired, unreleased rows;
- sorted by page token, with a correct cursor;
- 16 objects / 128 KiB, at least 1, `has_next`;
- a row that expires mid-paging keeps the cursor stable;
- fetch rate limit;
- no file gives `FETCH_END{OK,0,0}`.

**RELEASE:**
- only the recipient's rows; D, Alice or an unknown digest gives 0;
- a released row is no longer returned, but its payload stays until expiry and still counts in the caps.

**Crash and persistence:**
- deposit, drop, reopen, fetch: identical bytes;
- `PRAGMA synchronous` = FULL, `busy_timeout` set;
- 0600 on unix; ACL test on Windows (`#[cfg(windows)]`, reusing the `win_acl` helpers);
- newer `user_version` refused;
- corrupt file quarantined.

**`maintain`:**
- expiry deletes the row;
- an unpinned or removed depositor **or** recipient is purged;
- `purge_all`.

**`relayed_ingest.rs`:**
- message committed once, history written, owed row holds the exact ACK bytes, store ACK row Queued, so the lane is free for the next message;
- **duplicate path:** the object was first accepted over a link (callback `Ok`), then arrives via custody; the result is Duplicate and `OwedAcks` holds the ACK (A6);
- relayed ACK delivers A's outbound row: history delivered, staged body cleared;
- refusals, each with zero history and zero ACKs:
  - sender not a contact, blocked, unpinned or lineage-revoked;
  - expired;
  - tampered body (AEAD);
  - outer signature flipped (refused at the pre-check, with no protected load: assert through a store fault hook that is never reached);
  - PairInit-wrapped;
  - wrong `store_tag` vs hint;
  - non-canonical fields;
  - a hint naming another session of the same peer gives `Refused(ROUTE_TAG_MISMATCH)`;
- retries:
  - clock 10 min behind gives `Retry(Item)`, then success after the clock advances (S22);
  - `ForwardJumpTooLarge` gives Retry;
  - history fault gives Retry and no ACK; the next ingest gives Duplicate, history and ACK;
  - owed write fault gives Retry and the Prepared row is visible to the worker scan;
  - `OutboundPending` gives Retry;
  - `NO_PEER_CERT` gives `Retry(Peer)`;
  - owed table full gives `Retry(Peer, OWED_ACK_FULL)` **before** `accept_message_envelope` (the receipt count is unchanged).

**`owed_acks.rs`:**
- idempotent;
- per-peer and total caps give `Full` and never evict;
- expiry;
- `add_held`;
- a NULL session filled in later;
- quarantine plus rebuild marks entries `Rebuilt`;
- survives reopen.

**`indexed_session_store.rs`:**
- `mailbox_store_tags` equals `indexed_session_v1_subkeys_001.json` in both directions;
- B's inbound tag equals A's outbound tag for the same session and day;
- Provisional or expired sessions are refused;
- `live_session_heads` needs no protected load (a backend fault hook stays untouched);
- `outbound_store_tag_for_object` uses the signed `created_at` day;
- `outbound_session_for_object`;
- `live_queued_ack_rows`;
- `canonical_outbound_fields` is true for every outbound object the store produces.

**`outbox.rs` (core):**
- `ObjectRoutes` serde: old files parse, defaults are not serialized;
- `record_object_routes` keeps `custody` and `custodians_held` on re-record, and **re-noting an earlier `--carrier lan` row never gains custody** (B-min a);
- `clear_peer_routes` keeps records with custody fields;
- `add_object_custodians` is idempotent;
- `contact_routes` parses `custodians`: invalid hex dropped, at most 2, self excluded;
- `custody_eligible_message` and `custody_eligible_ack` truth tables;
- `custodian_routes` respects gates and locality.

**`lan_dispatch.rs`:**
- RFC1 never reaches the RVN1 path;
- `dispatch_frame` (old signature) answers RFC1 with HOLD;
- every existing `handle_indexed_message` and `handle_ack` test passes unchanged after the extraction.

**`custody_gate.rs`:** flags false, generic gates closed, HOLD text.

### 16.2 Unit tests in `raven-node`

**netutil (`rn/main.rs`):**
- `expects_reply` and `is_terminal_reply` for every RFC1 op;
- the collector ends after `FETCH_END` and `RELEASE_RESULT`, not after `FETCH_ITEM`;
- while RFC1 terminals are outstanding it uses the `first` wait (simulated slow fsync of 3 s between replies, nothing lost);
- a full page fits the reply budget.

**Worker (`rn/outbox.rs`).** `FakeNet` (`:2348`) is extended to **`FakeMesh`**. It routes each dial by `expected` to B's or C's real `dispatch_frame_on` (Lan, loopback source), each with a mode: UP, DOWN, REFUSE, OLD (Err on RFC1), FULL.

| Test | Expectation |
|---|---|
| w1 | B DOWN, C UP, lab `AFTER=0`: the dial to C carries DEPOSITs with recipient B and B's inbound tag. Entry is `Sent`/`IN_CUSTODY`, the store row is Queued, `custodians_held=[C]`. With B UP: direct delivery and no dial to C. |
| w2 | An explicit `--carrier lan` record (`custody=false`), or no record, never deposits. |
| w3 | Custodian unpinned, removed or blocked: no dial, `CUSTODIAN_NOT_USABLE`. |
| w4 | C OLD: 3 strikes give `CUSTODY_UNSUPPORTED` parked 1 h. C FULL gives backoff. With two custodians, the second is used. |
| w5 | Restart after STORED (fault `after_deposit_before_record`): re-deposit gives `DUPLICATE`; C holds one row. |
| w6 | `STORED` never yields `Delivered`; only an ingested ACK does. |
| w7 | Owed ACK durable: kill after relayed ingest, restart; the ACK is pushed directly (A UP) or deposited at C (A DOWN). |
| w8 | The send lock is never held across a custody dial (reuse `lock_probe`). |
| w9 | Message written to B with no ACK; later B DOWN: deposited on that later attempt (A7). |
| w10 | **B has no LAN address:** `routes=[]`, captured and deposited (B1). |
| w11 | **Every route to B blocked** (`LINK_NOT_ACCEPTED`): deposited; outcome `Deposited`, not `Held`. |
| w12 | **Prepared ACK with empty `ack_routes`:** deposited; row Queued; owed entry `origin=Prepared, held_by=[C]`; outcome `AckSent`. |
| w13 | **F8 owed ACK** (session NULL): resolved through `outbound_session_for_object` and deposited with the correct tag. |
| w14 | C UP and D DOWN: held at C. D UP later: held at D too (`custodians_held=[C,D]`). |
| w15 | Fault `before_custody_dial` after the unsent clear: on restart exactly one deposit happens, and `unsent` reads true only if nothing was written. |
| w16 | Owed ACK origin `Rebuilt` is pushed but never deposited. |

**Fetcher (`rn/custody.rs`):**

| Test | Expectation |
|---|---|
| f1 | Tags only for sessions with peers listing C; at most 3 days per session; none for other peers; no padding. |
| f2 | Objects ingested; RELEASE goes in the next dial; a Retry object is not released. |
| f3 | `has_next` paging continues up to 8 pages, then resumes from the saved cursor on the next trigger. |
| f4 | Object with an unrequested tag, broken RSO1 rules or non-canonical fields: ignored, not released. |
| f5 | Unreachable custodian backs off; `peer_seen` at most once per minute; gate closed means no dial; empty streak stretches the interval to 10 min; `note_deposit` resets it. |
| f6 | **Starvation:** 20 Retry objects (peer P1) sorted before 1 good object from P2; the good one is ingested within the same trigger or the next (cursor). Then P1 in `NO_PEER_CERT` backoff is left out of FETCH (A5/B4). |
| f7 | **Back-pressure:** 300 relayed messages from A, A offline: `OWED_ACK_FULL` is hit, objects stay at C, and as owed entries drain all 300 ACKs are eventually deposited (S23). |

**Link (`rn/lan_direct.rs`, `rn/internet_direct.rs`):**
- RFC1 on a LAN link with the gate closed gets a HOLD reply, and the link stays usable for the next frame;
- RFC1 on an `internet_direct` inbound link (lab, WAN off) gets HOLD and no file is created; on a LAN link it is served (A3/B6).

**IPC (`rn/ipc_server.rs`):** `LanDial` with an RFC1 frame and the lab off gives `CUSTODY_IPC_REFUSED`; with the lab on it is forwarded.

### 16.3 ash tests

- `set_node_custody` keeps `auto_policy`, `bridge` and `store` (B-min b).
- `contact set-addr --custodian` validation: unpinned, self, the contact itself, more than 2.
- `custodians` survives Contact and LocalContactRow round trips and is not exported in `SyncContact`.
- A send with no `--carrier` to a LAN-only contact records `custody=true`. An explicit `--carrier lan` records `false`.

### 16.4 Real-process harness (`node/crates/raven-node/tests/carrier_matrix.rs`, `#[ignore]`, all 3 OS)

**Retired names.** The cases C11-C17 below were planned but never built under these names, and those numbers now belong to Phases 0-2 (C11-C13 network change, C14-C16 the p2p carrier, C17 the LAN port change). Their coverage is in the fault matrix's s30 family and s125 and in carrier_matrix C32-C34 (§19.6); the list below stays as the design's record of what custody must prove.

All `raven-node` processes run with `RAVEN_LAB_TEST_A=1` (debug), `RAVEN_LAB_CUSTODY_AFTER_MS=0` and `RAVEN_LAB_CUSTODY_FETCH_MS=1000`. They synchronize on log lines, as the existing scenarios do.

- **C11 (core).** A, B and C are services on loopback, all pinned contacts. A and B pair (one message each way). Both set custodian @C; C turns custody on.
  1. Stop B; A sends; `outbox status` reaches `IN_CUSTODY`.
  2. Stop A; start B. B's inbox has the message **exactly once**, and B's ACK is held at C.
  3. Stop B; start A. A shows `delivered`.

  Then assert on C's `friend_custody.sqlite` and its WAL/SHM:
  - no `RVPI1`, `RVPR1` or `RLB1` magic, no plaintext, no `rvn1…` address;
  - both rows have `released_at_ms` set;
  - C's stderr has no 64-hex string.
- **C12 (crash).**
  - (a) SIGKILL C after the deposit, restart it, B fetches.
  - (b) B with `after_ingest_before_release`: one inbox row, and the ACK still reaches A.
  - (c) A with `after_deposit_before_record`: restart gives one row at C and status `IN_CUSTODY`.
  - (d) A with `before_custody_dial`: restart gives exactly one deposit.
- **C13 (refusals and abuse).**
  - Stranger S gives `LINK_NOT_ACCEPTED`. Unpinned U gives `NOT_VERIFIED`. C custody off gives `POLICY_DENIED`.
  - A PairInit-wrapped deposit, crafted and sent through lab IPC `LanDial`, gives `REFUSED_OBJECT`.
  - Co-custodian D, a pinned contact of C and knowing the A↔B tags, gets 0 from FETCH and releases 0.
  - D re-deposits A's captured object and gets `REFUSED_OBJECT`.
  - D floods (D, B) until `QUOTA` while A's next deposit is still `STORED`.
  - A random-tag FETCH returns 0.
- **C14 (old custodian).** C has `PRETEND_OLD=1`. A gets `CUSTODY_UNSUPPORTED` after 3 strikes. When B returns, delivery is direct.
- **C15 (direct wins).** B is up the whole time. Delivery is direct and C's custody file does not exist.
- **C16 (two custodians).** C down, D up: the object is held at D. Later C up: also held at C. B fetches from both; one inbox row.
- **C17 (WAN split).** C runs a lab Internet listener, and A's contact for C has only an Internet route.
  - Without `RAVEN_LAB_CUSTODY_WAN`: A's worker skips C (`CUSTODIAN_NOT_USABLE`), and a crafted lab `InternetDial` DEPOSIT to C gets `HOLD`, with no file.
  - With `RAVEN_LAB_CUSTODY_WAN=1` on all nodes: C11 passes over Internet links.
- **S21 row (config mismatch).** Only A lists C. Status reads `IN_CUSTODY`, then `expired`, and the reciprocal hint was printed.

### 16.5 Fuzz

- New `node/fuzz/fuzz_targets/rfc1_decode.rs`: decode never panics, and an accepted frame re-encodes byte-identical.
- The existing `store_object.rs` target covers RSO1.

### 16.6 Physical rows (owner-run, recorded under `node/proof_artifacts/`)

- **R-FC1.** An always-on custodian (Linux desktop) on a home LAN. Laptop A sends at T1. Laptop B is off and joins at T2 while A is away. A rejoins at T3. Mixed macOS and Windows.
- **R-FC2.** Same as R-FC1, with the custodian power-cycled between deposit and fetch.

---

## 17. Change list and effort (estimates are guesses)

| Area | Files / functions | Effort |
|---|---|---:|
| Gate | new `core/custody_gate.rs` (`CustodyGates`, `custody_link_allowed`, `custody_route_allowed`), `CarrierGates::current`; export in `core/lib.rs` | 0.5 d |
| RFC1 codec, custodian store, handler | new `core/friend_custody.rs` (`is_rfc1`, `Rfc1::{encode,decode}`, `CustodyStore::{open_lazy,deposit,fetch,release,maintain,purge_all,counts}`, rate windows, `handle_frame`) | 4 d |
| Link context | `core/lan_dispatch.rs::{InboundLink, dispatch_frame_on}`; callers `rn/lan_direct.rs:374`, `rn/internet_direct.rs:499`; maintenance hook `rn/lan_direct.rs:503` | 0.5 d |
| Session-store queries | `core/indexed_session_store.rs`: `live_session_heads`, `mailbox_store_tags`, `outbound_store_tag_for_object`, `outbound_session_for_object`, `live_queued_ack_rows`, `canonical_outbound_fields` | 1 d |
| Relayed ingest and extraction | new `core/relayed_ingest.rs`; `core/lan_dispatch.rs::{accept_message_under, sender_lineage_revoked}` (`identity_denies_device_lineage` becomes `pub(crate)`) | 3 d |
| Owed ACKs | new `core/owed_acks.rs`; F8 hook via `spawn_blocking` | 1.5 d |
| Outbox core | `core/outbox.rs`: `ObjectRoutes.{custody,custodians_held}`, `record_object_routes(.., custody: Option<bool>)`, `add_object_custodians`, `clear_peer_routes`, `ContactRoutes.custodians`, `custody_allowed_for_contact`, eligibility fns, `custodian_routes` | 1.5 d |
| Policy | `core/node_policy.rs`: `custody: bool` (default false, `skip_serializing_if`, false in `fail_closed`) | 0.25 d |
| Worker | `rn/outbox.rs`: capture with `routes=[]`, custody phase, `Outcome::Deposited`, Candidate/Entry/UnsentAck fields, owed merge and clear, unsent restore, strikes | 4 d |
| Fetcher | new `rn/custody.rs` (schedule, cursor, park map, hooks); `rn/main.rs` spawn and `wait_service_end`; `peer_seen`/`kick` hooks | 3 d |
| Collector and IPC | `rn/main.rs` `expects_reply`, `is_terminal_reply`, RFC1 wait; `rn/ipc_server.rs` RFC1 refusal and OutboxKick fetch kick; `core/ipc.rs` `OutboxItem.in_custody` | 0.75 d |
| CLI | `ash/cli.rs` (`node custody on|off|status [--purge]`, `set_node_custody`, `contact set-addr --custodian/--clear-custodians`, status texts, `run_send` custody_ok); `ash/ext.rs` (`SendCtx.custody_ok`, `LocalContactRow.custodians`); `ash/pair_init_lab.rs` (`OutboxHandoff.custody_ok/own`) | 1.5 d |
| Spec, vectors, docs, waiver | new `proto/RAVEN_FRIEND_CUSTODY_V1.md`; `shared-vectors/rvn1/custody/*`; notes in `RAVEN_STORE_OBJECT_V1.md`, `RAVEN_BRIDGE_V1.md`, `RAVEN_ERROR_CODES_V1.md`, `RAVEN_DELIVERY_STATE_V1.md`, `PROTOCOL_VERSIONS.md`; `docs/WAIVER_FRIEND_CUSTODY_LAN_DRAFT.md`; cross-reference in the transports design | 2.5 d |
| Tests | §16 plus harness C11-C17 and fuzz | 4-5 d (beyond unit tests written with each item) |
| **Total** | | **~24-30 d** |

**Untouched:**
- `rn/bridge_run.rs`, `core/forward_queue.rs`, `core/message_router.rs`, `core/bridge.rs`, `EnqueueSealed`;
- the PairInit, RLB1, RSO1 and envelope codecs;
- every frozen vector;
- the session-store schema;
- RDAP.

**Deferred** (follow-up PRs):
- `--carrier custody`;
- `IpcResponse::Status.custody`;
- `raven custody status/fetch`;
- custodian advertising in cards;
- the proactive re-pair companion;
- sealed async PairInit;
- payload deletion on RELEASE (Q1).

---

## 18. Open questions for the owner

Returned separately: Q1-Q11.

## Open questions

- Q1. Should RELEASE delete the payload early? Under V1 deletion is TTL-only: RELEASE only hides an object for its recipient, so errata rule 9 needs no amendment. A later errata amendment could treat 'link-authenticated, pinned recipient of this exact custody digest' as the object-bound deletion authorization. The wire would not change, and Carol would get capacity back sooner.
- Q2. Is it acceptable that the DEPOSIT carries the recipient key explicitly? This is what stops co-custodian theft and early deletion. Carol could already infer the recipient from fetch correlation. The alternative is a per-custodian tag derivation, which needs spec and crypto review.
- Q3. Should custody stay verified-only? Today the depositor, the recipient and the custodian must all be pinned contacts, and Carol only holds mail for recipients that are her own pinned contacts.
- Q4. Is CUSTODY_AFTER = 60 s right? It is the minimum message age before a deposit, and a deposit also requires that a direct attempt failed in the same pass or that no direct route exists.
- Q5. Are the quota guesses acceptable? Node: 4,096 objects / 64 MiB. Per depositor: 512 / 16 MiB. Per (depositor, recipient) pair: 128, held until TTL. Rates: 120 DEPOSIT frames and 2 MiB stored per 60 s; 30 FETCHes per 60 s. Because deletion is TTL-only, one pair is limited to about 128 messages per custodian per rolling 24 h.
- Q6. The owed-ACK table caps at 256 per peer and 2,048 in total, and never evicts. When a peer's cap is full, new relayed messages from that peer wait at the custodian. Are these caps acceptable?
- Q7. **Answered (Phase 3):** yes, as session renewal, with the alternating rule and a 10 h fallback instead of "the smaller key dials" (§13). Should the proactive re-pair companion ship as a separate PR? In it, the side with the lexicographically smaller key dials when the newest session expires within 12 h, so custody stays useful for 24 h after the pair's last meeting. The sealed asynchronous PairInit stays deferred until an external review.
- Q8. Is the WAN split right? Custody over Internet or p2p would need FRIEND_CUSTODY_WAN_ENABLED plus amendments to the Internet and p2p waivers; the Internet draft currently excludes custody. Under the HOLD, LAN custody requires a local-network source address, even for pinned contacts.
- Q9. Is it acceptable to ship the durable F8 owed-ACK table (a new owed_acks.sqlite) in the same PR? It changes how the existing in-memory F8 ACK path behaves on restart.
- Q10. Is the S9 limit acceptable to disclose? If Bob's ACK expires before Alice fetches it, Alice shows 'expired' although Bob received the message. Fixing that would need longer sessions or read receipts.
- Q11. Should both sides have to list the same custodian? This design requires it: Alice lists Carol for Bob, and Bob lists Carol for Alice. The alternative is for Bob to fetch from every pinned contact that runs custody, which means more dials and more metadata to every custodian.

---

## 19. Over the internet (Phase 3)

Phase 3 item 3 of the any-network plan (component C9) takes custody beyond
the local network. RFC1 bytes and version are unchanged
([`RAVEN_FRIEND_CUSTODY_V1.md`](../../protocol/RAVEN_FRIEND_CUSTODY_V1.md)
§2, §3, §6, §8 and §10 carry the rule changes); both gates stay `false`.

### 19.1 The recipient-mailbox model

- A node that holds mail for its friends (`raven node custody on`, asked
  y/N on a terminal, `--yes` in scripts, or the follow-up to the relay offer,
  which asks with the same consent text) announces it in RRH1 to its verified
  contacts: 0x06 CUSTODY_OFFER, with a WAN bit (reachable over the internet
  while WAN custody is live) and a REACHABLE bit
  ([`RAVEN_ROUTE_HINTS_V1.md`](../../protocol/RAVEN_ROUTE_HINTS_V1.md) §12),
  and only while some carrier can serve custody (`raven lan off` with WAN
  custody held sends no offer: `custody_gate::offer_flags`).
- A user who says yes to "Use friends as mailboxes?" (`raven custody use
  on`, asked once) picks at most 2 **home custodians** among the verified
  friends who offer: WAN-capable first (while WAN custody is live), then
  reachable, then most recently heard; picks stay while offered, and `raven
  custody home @x` always wins (`raven-core/src/custody_home.rs`).
- The recipient announces its home custodians to each sender as 0x07
  CUSTODIAN_TAG (a pair-blinded SHA-256 tag and a flags byte), so only the
  pair can match them; the sender deposits there when it also has an offer
  from that custodian and its own mailbox consent. Static `--custodian` lists
  (§4) keep working.
- The recipient fetches from its home custodians with the inbound tags of
  every live session with a pinned contact, from a dropped one for about
  97 h (`DRAIN_MS`: the 72 h RRH1 TTL it announces, during which a sender
  that missed the change may still deposit there, plus the custody validity
  limit and an hour), and from the custodians it listed. Removing or blocking
  a contact forgets it as a home custodian (`custody_home::forget` and the
  policy's `custody_home`). Mail friends see when the recipient checks in and,
  from the size of each FETCH, about how many live sessions it has; the
  mailbox question says so.
- A changed custody offer makes everything waiting due once (at most once per
  minimum retry, keeping the backoff; a change inside that window is kicked
  once it has passed; `outbox::custodians_changed` in raven-node), so a
  custodian that turns WAN on is used without waiting out a long backoff.

### 19.2 Budgets

- The custodian caps of §6.3 are unchanged: 4,096 rows and 64 MiB per node,
  512 rows and 16 MiB per depositor, 128 per pair, and the per-minute rates.
- New requester budgets (RFC1 §10, informative): at most 16 deposits and
  512 KiB per dial; at most 4 fetch pages per trigger while the custodian's
  last path was relayed, 8 otherwise, which fits a friend relay's
  `RelayLimits::friends` (2 MiB per circuit per 5 minutes). Fetch tags beyond
  one FETCH rotate, so every tag is visited in turn.
- `raven outbox hand-off`: a 10-minute window that skips the 60 s wait before
  a deposit (`CUSTODY_AFTER_MS`), for a sender about to leave.

### 19.3 Expiry

An object lives until its envelope's `expires_at`, at most
min(created + 24 h, session end) plus the 5 min clock-skew allowance
(`MAX_CUSTODY_VALIDITY_MS`). There is no extension. Session renewal (§13) is
the remedy for a pair that meets less than once a day; S9 (an ACK that
expires before the sender fetches it) stays a disclosed limit.

### 19.4 Over the internet: the gates

- RFC1 runs over p2p links (`/raven/link/1.0.0`, direct, hole-punched or
  relayed) only while `FRIEND_CUSTODY_WAN_ENABLED` is set (debug:
  `RAVEN_LAB_CUSTODY_WAN=1`); otherwise an Internet or p2p link gets `HOLD`
  and nothing is written. A compile-time tripwire refuses WAN custody without
  `FRIEND_CUSTODY_PRODUCTION_ENABLED` and `P2P_PRODUCTION_ENABLED`.
- Learned custody (offers and tags) rides route hints, so it is live only
  while route hints are (`custody_hints_live`).
- Internet direct (7422) stays off (decision D5); a custody route over it
  would also need its gate.
- Paperwork: [`docs/WAIVER_FRIEND_CUSTODY_DRAFT.md`](../WAIVER_FRIEND_CUSTODY_DRAFT.md)
  and the Phase 3 amendment of [`docs/WAIVER_P2P_RELAY_DRAFT.md`](../WAIVER_P2P_RELAY_DRAFT.md)
  (§10), both unsigned. The flips are owner actions: custody after real row
  R11g, WAN custody after R10 and R10b and only once P2P is live.

### 19.5 A friend relay and a custodian on one node

Allowed, with separate consents, keys (the relay key on 7427 versus the
profile identity), ports and quotas. The Phase 2 relay-offer question asks a
custody follow-up only while custody is off. The relay kit has no Raven
identity and can never be a custodian.

### 19.6 The custody harness as built

| Name | Where | What it proves |
|---|---|---|
| s30 | `scripts/lan_fault_matrix.py` (`RAVEN_FAULT_CUSTODY=1`) | deposit, fetch and ACK through a friend on the LAN, exactly once, with and without route hints |
| s30p | same, also `RAVEN_FAULT_P2P=1` and `RAVEN_FAULT_HINTS=1` | via a friend over p2p: announced custodians, no `--custodian`, deposits over `p2p_dial` |
| s30w | same | WAN custody needs both switches: `CUSTODIAN_NOT_OFFERING`, a crafted deposit gets `HOLD`, no store file; with the switch, held after the WAN bit is learned |
| s30r | same, also `RAVEN_FAULT_FRIEND=1` | a friend relay and a custodian on one node |
| s125 | same | a RELEASE deletes the object (the errata rule 9 amendment draft) |
| C32 | `node/crates/raven-node/tests/carrier_matrix.rs` | custody over relay circuits, message and ACK, with a byte scan of the custodian's files |
| C33 | same | the WAN gates and refusals: `HOLD` with no file, hide-IP keeps deposits relayed, strangers and unverified contacts get no RFC1 answer, an old custodian's three strikes |
| C34 | same | a friend relay and a custodian on one node |
| `custody` | `node/scripts/netns_nat_dcutr.sh` (Linux, advisory) | deposit, fetch and ACK through a public custodian between two symmetric NATs, with no packet between A's and B's networks |

The wan script `node/scripts/wan_two_network_test.sh` has the arms the real
rows use: `custodian on|off`, `mailbox on`, `wait-held TAG [SECS]`,
`hand-off TAG` and `custody-status`, and `report` adds counts-only custody
lines ([`docs/P3_REAL_ROWS_CHECKLIST.md`](../P3_REAL_ROWS_CHECKLIST.md)
section 5: R10, R10b, R10r, R11g).

## 20. Multi-hop: custody handoff (Phase 5)

Friend custody needs a friend both ends verified. Custody handoff lets Alice
and Bob use a friend each: Alice leaves a sealed message with her friend F1,
who passes it on to Bob's friend F2, from whom Bob collects it with the
ordinary RFC1 FETCH; Bob's ACK comes back F2 -> F1 the mirrored way.

- **Wire.** [`protocol/RAVEN_CUSTODY_HANDOFF_V1.md`](../../protocol/RAVEN_CUSTODY_HANDOFF_V1.md):
  RFC1 ops 0x07 HANDOFF (an RHW1 record: FORWARD from the signer to F1 naming
  F2's key, DELIVER from F1 to F2) and 0x08 TAGS (Bob registers his own store
  tags at F2), codes 14-16; the RRH1 CUSTODIAN_TAG flag bit 0
  `HANDOFF_INBOX` ([`RAVEN_ROUTE_HINTS_V1.md`](../../protocol/RAVEN_ROUTE_HINTS_V1.md)
  §4). At most two custodians on any path, by construction (FORWARD only from
  the outer signer, DELIVER terminal). The spec's §5 says who learns what.
- **Gate.** `CUSTODY_HANDOFF_PRODUCTION_ENABLED = false` on top of the custody
  gate; debug `RAVEN_LAB_CUSTODY_HANDOFF=1` with the lab unlock. With it
  closed every listener answers 0x07/0x08 `UNSUPPORTED` and every sender's
  plan is exactly Phase 3's.
- **Next hops need a pinned key.** RRH1 custodian tags are pair-blinded
  (RRH1 §12.1), so Alice can name F2 only when F2 is one of her own pinned
  contacts; pinning it by key alone (no route) is enough, and she never
  dials it. A far friend Alice has never pinned cannot be used.
- **Consent.** One node policy flag, `custody_handoff`, off by default and
  never set by AUTO, covering both custodian roles; it works only while
  `custody` is on.
- **CLI (ash).**
  - `raven node custody handoff on|off`: changes only that flag. `on` prints
    what each role learns (passing on: who sent it and which friend it goes
    to, never the final recipient; holding: the recipient and the friend who
    brought it, not the sender), a note while custody is off, and
    `HANDOFF_HOLD` while the gate is closed. `off` refuses new handoffs at
    once; rows already taken on are still passed on or kept until they
    expire.
  - `raven node custody status` adds, while handoff is on, the store holds
    anything or the gate is open, one counts-only line from
    `custody_handoff.sqlite`:
    `handoff on  passing on: N waiting, N handed on, N refused, N bytes;
    registered tags: N`. `raven node custody off --purge` empties that store
    too.
  - `raven contact show NAME`: the contact's mail friends it announced
    (marked when they also take mail another friend passes on), the ones you
    listed, and how it can be reached while away (direct, a mail friend you
    share, two friends in a row, or nobody), with each way's time limit.
  - `raven doctor`: an `offline_delivery:` line with counts only
    (`verified_contacts=N direct=N mutual_friend=N two_friends=N none=N`),
    one line per way with its time limit, and a next step when some contact
    has none. It reads the files only: raven-node's transient parks (an
    hour or a day) are not shown.
- **At rest.** `custody_handoff.sqlite` (forward rows and tag registrations),
  sealed through the at-rest API and registered in
  [`2026-10-at-rest-metadata.md`](2026-10-at-rest-metadata.md) §7.6.
- **Harness.**

| Name | Where | What it proves |
|---|---|---|
| C54 | `node/crates/raven-node/tests/carrier_matrix.rs` | the two-hop chain, message and ACK, exactly once with A and B never online together; no file of F1's (sealed ones opened) or its log names B, none of F2's names A, neither holds the text |
| C55 | same | a closed link gate (`HOLD`) and an old custodian (`RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1`, `UNSUPPORTED`): a mutual custodian's plain deposit still holds the message, no forward row, no tag, no strike, and plain custody at the old one stays usable |
| s68-s71 | `scripts/lan_fault_matrix.py` (`RAVEN_FAULT_HANDOFF=1`) | s68 the chain with timings and the byte scan; s69 F2 away when F1 takes it, handed on when F2 is back; s70 a new session's tags registered late (TAG_UNKNOWN, then delivered); s71 as C55 |
| s97b | same | the chain past 24 h (one LabClock): both friends drop their copies, the sender's outbox says when time ran out |
| s30 | same, with `RAVEN_FAULT_CUSTODY=1` | with the handoff gate on, a custodian both list gets a plain DEPOSIT and no HANDOFF frame is sent |

- **Release path.** [`docs/WAIVER_FRIEND_CUSTODY_HANDOFF_DRAFT.md`](../WAIVER_FRIEND_CUSTODY_HANDOFF_DRAFT.md)
  (unsigned; LAN only, after the custody LAN flip), real rows R28 (LAN mule)
  and R29 (WAN chain, for a later internet amendment) in
  [`docs/P5_REAL_ROWS_CHECKLIST.md`](../P5_REAL_ROWS_CHECKLIST.md).
