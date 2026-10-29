# RDAP tasks over the Raven node: app channel v1 (revision 2)

| | |
|---|---|
| **Status** | Design for implementation, revision 2 (answers both reviews). Built; **switched on in release builds in October 2026** (P4, below: `APP_CHANNEL_PRODUCTION_ENABLED = true`, macOS included after the owner's Q6 decision of 2026-10-29), not independently reviewed. Subordinate to the RVN1 HOLD (`docs/THREAT_MODEL.md`, `protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`) and to ADR 0004. |
| **Date** | 2026-10-15 |
| **Baselines** | Raven: the Raven tree of that date (`feature/reliability-and-mesh`) (staged). RDAP: the RDAP tree of that date. Line numbers refer to these trees; re-check them before editing. |
| **Risk class** | R3 under ADR 0004 D6. Architect #1, Crypto ATSAM #3 and Identity AuthZ #15 must ack; no self-merge. **P0 touches the live LAN receive path, so it is R3 too.** `AppSubmit` and `AgentSign` need the ADR 0004 D4 review that `SealUnderSession` had. |
| **New gate** | `raven_core::app_gate`: `APP_CHANNEL_PRODUCTION_ENABLED = false`, `APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED = false`. The lab unlock is debug-only `RAVEN_LAB_TEST_A=1` (`core/pair_init.rs:29-37`). |
| **Carrier gates** | Unchanged. LAN direct is live; Internet direct and p2p stay held. The app channel adds no carrier. |

Path shorthand:

- `core/` = `node/crates/raven-core/src/`
- `rn/` = `node/crates/raven-node/src/`
- `ash/` = `node/crates/ash/src/`
- `ta/` = RDAP `team_agents/`
- `rdap.py` = RDAP `rdap.py`

---

## 0. Decisions on one page

1. **What carries a task.** A task or answer is an ordinary indexed-session `Message` envelope sealed with ATSAM by `IndexedSessionStore::send_message_envelope`, exactly like chat.
   - Envelope, route tags, mailbox tags, StoreObjectV1, carrier and link admission, bridge and forward queue are all unchanged.
   - No new crypto.
2. **Inner frame** (inside the AEAD plaintext): `RVNAPP/1 <content-type> <app-id>\n<body>`.
   - The content-type registry is compiled in: `a2a-request/1` and `a2a-response/1`. `test/1` is lab-only.
   - The receiver classifies each plaintext as `Chat`, `App` or `ReservedInvalid`.
   - App frames never reach chat history or chat UIs.
3. **Receive-side admission happens before commit (spec step 7).** `accept_message_envelope` gains an application-policy callback that runs after AEAD open and text validation, before the commit.
   - When the policy defers (gate closed, unregistered type, malformed reserved frame, inbox full, app store unreadable), nothing is committed: no receipt, no inbox row, no ACK intent, no ratchet advance.
   - `dispatch_frame` returns `Ok(vec![])`, so the link stays open.
   - The sender's retry, with the same bytes, is a fresh accept.
4. **Every committed app row ends in the app inbox.**
   - The ACK path ingests it and only then sends the ACK.
   - A sweep over `pending_endpoint_ack_intents()` and the expiry archive ingest any committed app row that is not yet in the inbox.
   - So even an ACK sent early (a future intent sweep) cannot lose a payload: the endpoint inbox row stays durable until it is ingested.
5. **Sender: `AppSubmit`** (daemon-side, idempotent on `(peer, client_ref)`):
   - **Order:** admission, then the session ensure, then the per-peer lock, then a re-check of dedup and caps under the lock, then the lineage check, then the seal.
   - **Pairing:** the daemon pairs only when no usable session exists (no proactive re-pair). The pairing budget of 4 PairInits per peer per 24 h is saved to disk.
   - **Dials** take explicit deadlines.
   - **Delivery:** the outbox worker owns retries, ACK checks, expiry and revocation.
   - **Resend** reuses the `app_id` and runs the whole path again.
6. **Receiver ops.**
   - `AppInboxPage`: paged long-poll. Contact, block and lineage are checked again for every item served.
   - `AppInboxAck`: removes the item and writes a tombstone.
   - **Consumer binding:** one consumer per node, saved in the store, with explicit takeover.
   - `OutboxStatus` reports app objects with `kind:"app"`.
7. **Identity (ADR 0004 D3).**
   - RDAP's principal is the node's RVN1.
   - A bound home holds no seed and can never create one.
   - **AgentSign:** RDAP signs through `AgentSign`, a typed op for one context, `raven.a2a.delegation.v2`. The daemon builds RDAP's exact canonical bytes.
   - **Prefix check:** `Identity::sign` and `Identity::verify` refuse that prefix everywhere else, so AgentSign can never produce a Raven-format signature.
8. **A bound home is raven-only for tasks.**
   - The raven channel is the only task path, for both sending and receiving.
   - HTTP JSON-RPC task POSTs, the git relay task path, the mesh mailbox and HTTP request signing are all off in a bound home.
   - So ADR invariant 3 holds by construction, and no AgentSign HTTP or card context is needed.
9. **RDAP channel.**
   - Requests and answers carry the same `raven.*` delegation metadata as HTTP.
   - `TaskLedger` (extracted from `GitRelay.claim_task`, same files) gives exactly-once execution.
   - **Bob's `raven_answers` table:**
     - Saves the brain result before signing.
     - Records whether the answer was delivered, and resends or re-signs it while it is still valid.
     - Serves re-requests.
   - **Confidential brain mode:** the raven worker runs the brain with nothing written to git-synced paths.
10. **Rollout.**
    - P0 makes receivers app-safe. It is always on and R3.
    - P1 adds the node channel, P2 the identity bridge and P3 the RDAP channel, all behind the gate.
    - P4 is the owner's flip: LAN only, and on macOS only after the Q6 decision.

---

## 1. How each review finding is resolved

A = first critique, B = second critique.

| ID | Finding | Resolution (section) |
|---|---|---|
| B1 (blocker) | The brain writes task text into git (`ta/llm.py:180-202` EchoBrain writes `.team/outputs/<slug>.md`, `log_event`, `set_task`; tools `write_file`, `log_event`, `remember_fact`, `board_set_task`, `run_command`, `git_commit`, `ta/tools.py:432-495`; shared paths in `ta/memory.py:56-70`). `rdap say` also posts the whole task text to TeamChat (`rdap.py:1516`) and results (`:1580`). | Confidential run mode (§11.7): EchoBrain writes nothing, the LLM brain gets a read-only tool view, the worker never calls `log_event`, `sync` or `commit`, and bound-home `say`/`do` never post task or answer text. Tested by PY-25, PY-26 and LAB S1 (`git status` clean, no marker in `git log -p`). |
| A1 | Soft refusal after commit leaves an ACK intent pending, which contradicts `ATSAM_ENDPOINT_TRANSACTION_V1` §1 step 7 and §4. | Pre-commit policy callback (option a, §7.1). The ingest sweep and archive ingest (§7.3) mean any committed app row, even one ACKed by a future sweep, reaches the app inbox. CORE-3, CORE-6. |
| A2 | The dedup/resend path bypasses admission, lineage and the lock. | `dedup()` returns a decision. A resend runs the full path and is re-decided under the lock. Records that failed for lineage reasons are never resendable (§8.3). RN-8. |
| A3 | Unknown content types and no item TTL allow a capacity squat. | Compiled registry (`test/1` lab-only), per-(sender, content type) caps, 7-day item TTL, unknown types deferred (§5.3, §7.4). CORE-5, CORE-8. |
| A4, B14 | Receive-side G5 gap. Tasks and answers share one cap. | Each served item is re-checked for contact, block and RVDR1 lineage using the stored session-bound cert; a failure tombstones the item (G5.2(5)) (§7.5). Caps are per content type. RN-15. |
| A5 | A transient AgentSign failure loses a finished result. The rate bucket can be drained remotely. | The brain result is saved to `raven_answers` before signing and signing is retried (§11.5). Separate task and answer buckets; REJECTED replies limited to 1 per sender per 60 s (§4.2, §11.5). PY-12a, RN-21. |
| A6 | Daemon PairInit can exhaust the responder's quota (`MAX_ACCEPTED_PREKEY_CLAIMS_PER_INITIATOR = 32`, `core/prekey_lifecycle.rs:52`). | No proactive re-pair. A PairInit only when there is no usable session. Saved budget of 4 per peer per 24 h; probes do not count; `peer_seen` never resets it (§8.2). **Partly rebutted:** a responder's `ResourceLimit` cannot be mapped to its own code, because the responder says nothing on the wire (`ash/pair_init_lab.rs:640-645`: "it says nothing on the wire, so the dial ends in a silent close"); the budget is the protection. RN-5. |
| A7, B2 | Answer TTL unspecified (RDAP default 600 s, `ta/raven_identity.py:43`). Nothing tracks answer delivery. | Task TTL defaults to 4 h; answer TTL is 24 h, as the relay uses (`ta/relay.py:420`). `raven_answers` tracks delivery, resends and re-signs, and serves re-requests. Answers are checked for freshness at the node's receive time (§11.4-§11.6). PY-13..16, LAB S12. |
| A8, B3 | HTTP contradictions; no AgentSign context for HTTP signing. | Bound homes are raven-only for tasks. `sign_http_request` raises for node-backed identities. HTTP task POST returns 403. Relay and mesh task workers are off (§4.4, §11.8). PY-24. |
| A9 | macOS UID-only gives decrypted content and identity-key use to any same-user process (daemon-owned-secrets §3.0, §3.1, Q6). | **Decided 2026-10-29 (owner, Q6): accepted as a documented residual.** `APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED = true`: any process of the same macOS user can use the app channel (read the RDAP task and answer content it carries, send RDAP tasks as this identity) without a Keychain dialog; ordinary Raven messages are not exposed through it; a stronger peer check (code-signing identity, daemon-owned-secrets §4.4) is future work. Recorded in `docs/THREAT_MODEL.md` §3.16. RN-13. |
| A10, B7 | The claimed 2 s cost of a soft refusal is wrong. | Restated: up to 30 s per attempt when the deferred frame is the only one expecting a reply (`rn/main.rs:584-587`, `:628-634`). Bounded by the worker backoff. C7c and C7d measure it (§7.6). |
| A11, B15 | Domain separation rests on a hand-kept list; the JWS card context accepts too much. | Card context removed. Structural check: `Identity::verify` refuses, and `Identity::sign` asserts against, the AgentSign prefix; AgentSign signs through a private chokepoint (§4.2). CORE-11. |
| A12 | Orphan answers are unbounded and shown. | An answer with no matching `(task_id, peer)` row is acked `rejected` and not stored (§11.6). PY-18b. |
| A13 | Resend, TTL and retry inconsistencies. | Body kept until the task is final or 7 days. `ttl_ms` floor equals `APP_MIN_ENVELOPE_MS`, refused with `APP_BAD_TTL`. Retries run in the worker and on every rdap invocation, and the UX text says so (§8.1, §11.3, §11.9). |
| A14, B11 | Identity residuals: `peers.json`, the old seed, missed `load_or_create` sites (`ta/client.py:511`, `ta/__main__.py:96`, `:103`, `ta/server.py:639`). | `peers.json` keys are checked for equality with node contact pins on every use. Bind retires the old seed and writes a bound marker that `load_or_create` refuses. `NodeConfig.raven_bind`. `cmd_start` rewritten (§4.4). PY-3. |
| A15 | Inbound metadata is taken from the link bundle. | `ingest` takes the session-bound certificate (`session_bound_peer_certificate`), never a `LanBundle` (§7.3). CORE-13. |
| A16 | Orphan tolerance could hide history errors. | Orphan only when the stage is absent, `set_delivery_persisted` returns `Ok(false)`, and no app record exists; `Err` propagates (§8.5). CORE-10. |
| A17 | P0 changes live LAN semantics. | P0 is R3 and recorded in the LAN waiver amendment; residual documented; RDAP warns about non-ACKed tasks; 4 h default TTL (§14, §5.5). |
| A18, B13 | The ledger lock is per channel, so a false `interrupted` is possible. | **Rebutted with construction:** a bound home runs only the raven task channel (relay, mesh and HTTP executor off, §11.8), and an unbound home never runs the raven worker, so two channels can never claim on one home. A `completed` branch is added, and the cached answer is looked up before the expiry check (§11.5). |
| A19 | Metadata reaches git; app inbox write amplification. | No TeamChat notices for raven tasks. SQLite with one sealed row per item (§10). |
| B4 | The lease expires during brain runs; restart semantics undefined. | Consumer binding saved to disk, one per node, with explicit `takeover` (§7.5). RN-14. |
| B5 | Session-ensure budgets cannot be enforced; the worst case exceeds the client timeout; FakeNet does not cache the bundle; the PairInit gate exists only in ash. | `Dialer::dial` gains a `deadline`. The probe reply is parsed and the bundle cached explicitly. `live_pair_init_outbound_ready` moves to core. `pair_over_dial` is shared with ash. RDAP timeout is 90 s, above the daemon maximum of about 80 s plus the seal (§8.1). RN-7c, RN-23. |
| B6 | No reconcile for app records. | `reconcile_app_outbound` runs at preflight and on every prune, before sessions are destroyed. `status_anywhere` consults app records (§8.6). RN-19. |
| B8 | Chat bookkeeping is coupled to the app store. | Order is stage, then history row, then app record; app-store errors fall through to the existing chat behaviour (§8.5). RN-22. |
| B9 | `resolve_outbox_mid` keeps `kind == "message"` only (`ash/ext.rs:2650-2654`). | Accept `app`; label app objects in status and cancel (§8.7). ASH-6. |
| B10 | Composer guard placement. | Guard in `run_pair_init_and_send_routes` (`ash/pair_init_lab.rs:477`) plus a pre-check in `deliver_routes` next to `ash/ext.rs:2386` (§5.5). ASH-4. |
| B12 | UX wording conflicts with HOLD guards. | The raven channel says only "atsam_rvn1 (NON-RELEASE / HOLD)", never "confidential". `refuse_confidential_claim` and its selftest (`ta/selftest.py:171`) stay unchanged (§11.9). |
| B16 | Scope and nits. | Ops are named as IPC v2 forerunners (§9.4). Card AgentSign is dropped. Separate body check allows an empty body. The pairing budget does not depend on `peer_seen`. In-flight cap re-checked under the lock. **Long-poll kept:** it matches IPC v2 `InboxPage.wait_ms` (daemon-owned-secrets §4.4) and costs about 40 lines (a generation counter polled every 250 ms). |

---

## 2. Facts relied on (verified in code)

| Fact | Evidence |
|---|---|
| `accept_message_envelope` opens the AEAD, checks `valid_endpoint_text`, then increments the generation and commits. A refusal before the increment commits nothing (the transaction is dropped). The duplicate check by object digest happens **before** the AEAD open. | `core/indexed_session_store.rs:2781-2970` (text check `:2919`; duplicate `:2878-2893`) |
| The spec puts the application policy at step 7, before commit. Only committed intents may be ACKed. | `protocol/ATSAM_ENDPOINT_TRANSACTION_V1.md` §1 steps 7-9, §4 |
| `pending_endpoint_ack_intents()` is public; the only `enqueue_committed_ack` caller is `handle_indexed_message`. | `core/indexed_session_store.rs:3748`; `core/lan_dispatch.rs:1539` |
| Receive path: persist history, then ACK; a storage error returns `Err` and closes the link. | `core/lan_dispatch.rs:1440-1555`; `rn/lan_direct.rs:370-379` |
| A skipped receive key allows a later retry of a deferred index; at most 256 are held. | `core/indexed_session_store.rs:83` |
| Expiry archive writes endpoint inbox rows into chat history before roots are destroyed. | `core/lan_dispatch.rs:490-524`, `:1258-1272` |
| Text policy: non-empty, no C0 except TAB/LF/CR, no DEL, private helper. | `core/indexed_session_store.rs:156-169` |
| One prepared Message per session lane. The handoff callback runs after the commit; a failed handoff leaves the row Prepared. | `:2125-2138`, `:2212-2231` |
| The worker never dials or abandons a row with no local body (`NO_LOCAL_BODY`). Prepared rows are dialled only if they have a body. | `rn/outbox.rs:1236-1282`, `:2020-2025`, `:1632-1667` |
| `raven send` gives up body-less earlier rows; `mark_outbound_undelivered` then fails with no stage and no history row. | `ash/pair_init_lab.rs:1260-1460`, `:1675-1679`; `core/outbox.rs:276-322`; `core/lan_dispatch.rs:226-248` |
| ACK bookkeeping: the worker uses `accept_sealed_ack` then `record_outbound_delivered` then `record_inbound_ack_delivery`; ash uses `finish_outbound_delivered`. | `rn/outbox.rs:1893-1897`; `core/outbox.rs:174-189`, `:212-267`, `:412-449` |
| `finalize_vanished` resolves only staged chat; `status_anywhere` falls back to history. | `rn/outbox.rs:2136-2193`, `:498-528` |
| `Dialer::dial` has no deadline; NetDialer uses 45 s; ReplyCollector first wait is 30 s when a reply is expected. | `rn/outbox.rs:1088-1145`, `:89`; `rn/main.rs:584-587`, `:628-634` |
| FakeNet ignores dispatch errors and continues. | `rn/outbox.rs:2397-2402` |
| ash pairing: probe, parse offer, `cache_peer_bundle`, `create_initiator_pair_init`, `wrap_pair_init`, dial, `first_pair_response`, `confirm_verified_pair_response`; the gate is `trace_delivery::live_pair_init_outbound_ready`. | `ash/pair_init_lab.rs:421-430`, `:477-687`; `ash/trace_delivery.rs:14-22` |
| Per-initiator claim quota is 32; claims are retained up to the PairInit lifetime. | `core/prekey_lifecycle.rs:47-55`, `:1101-1109` |
| Worker backoff runs 5 s to 10 min with jitter; 16 frames per dial. | `core/outbox.rs:1074-1082`; `rn/outbox.rs:91` |
| ash queue cap: `MAX_QUEUED_PER_PEER = 32`. | `ash/pair_init_lab.rs:55`, `:1494-1505` |
| Chat surfaces read the endpoint inbox directly. | `ash/cli.rs:6597` (`cmd_endpoint_inbox`); `ash/ext.rs:3207` (`peek_endpoint_inbox_for_contact`), `:3166` (cursor tombstone) |
| IPC: one request per connection, no handler timeout, `Ping` inline, other ops on the blocking pool. | `rn/ipc_server.rs:712-772` |
| RDAP signing formats: `lp` is a 2-byte big-endian length, so delegation bytes start `00 17 "raven.a2a.delegation.v2"`. | `protocol/reference/raven_protocol/_canon.py`; `ta/raven_identity.py:40-44`, `:530-553` |
| Relay exactly-once: `RelayOutcomeStore` (`processing`/`completed`), `claim_task`, worker lock; relay replies use a 24 h TTL. | `ta/relay.py:103-284`, `:404-421`, `:645-652` |
| `verify_delegation` rejects `now >= expires_at` and has no injectable clock. | `ta/raven_identity.py:605-700` |
| Bound homes today: `cmd_start` refuses without a seed; `ask`, `say`, `replies`, `do` and the entry points call `load_or_create`. | `rdap.py:1060-1081`, `:201`, `:1512`, `:1658`, `:1898`, `:2573`; `ta/server.py:639`; `ta/__main__.py:96`, `:103`; `ta/client.py:511` |
| G5.2(5): a revoked lineage must fail the bound data plane closed, including task acceptance. | `docs/adr/0004-appendix-g5-raven-rdap-revoke.md` G5.2 |
| macOS: any new op that returns content or uses identity keys needs more than a UID check, or it is weaker than today (Q6 open). | `docs/design/2026-10-daemon-owned-secrets.md` §3.0, §3.1, Q6 |

---

## 3. End-to-end flow

```
Alice RDAP                Alice raven-node                         Bob raven-node                    Bob RDAP worker
 AgentSign(task stmt) -> sig (node RVN1)
 AppSubmit(Bob, a2a-request/1, body, client_ref=rdap-task:<tid>)
 -------------------------> admission -> usable session? else probe+PairInit (budget)
                            PeerSendLock; re-check; lineage; seal "RVNAPP/1 a2a-request/1 <app_id>\n<json>"
                            app_outbox[queued]; route record; kick
 <- {mid, queued} ---------
                            worker dial ----- sealed Message --------> accept: route tag ok, AEAD ok,
                                                                        POLICY(classify, gate, registry, caps)
                                                                        defer -> nothing committed, Ok([])
                                                                        accept -> commit -> ingest app_inbox
                            <---------------- sealed ACK ---------------  ACK only after ingest
                            app_outbox[delivered]
 OutboxStatus(mid) -> kind=app, delivered                                                  <- AppInboxPage(consumer, a2a-request/1, wait)
                                                                        recheck contact/block/lineage per item
                                                                                            transport binding; delegation verify
                                                                                            ledger.claim -> confidential brain.run
                                                                                            raven_answers[unsigned] -> AgentSign -> body
                                                                        <- AppSubmit(Alice, a2a-response/1, rdap-ans:<sig>:1)
                                                                                            <- AppInboxAck(done)
                            <---- same path in reverse; Bob's worker retries; raven_answers tracks delivery
 <- AppInboxPage(a2a-response/1)
 verify (freshness at node receipt time); raven_tasks[answered]; AppInboxAck(done)
```

---

## 4. Identity model

### 4.1 Decision

- **One principal: the node's RVN1.** In a bound home, RDAP's `address`/`public_key` are the node's user identity. Every RDAP signature is made by raven-node through `AgentSign`. A bound home holds no seed and cannot create one.
- **Two trust planes over one key.**
  - The transport plane is the Raven contact plus the session-bound certificate, enforced by the node.
  - The delegation plane is `verify_delegation` against `peers.json`, enforced by RDAP.
  - In a bound home, `peers.json` is an **authorisation list** ("which contacts are teammates"). Its keys are checked for equality with the node's contact pins on every use, so it is never a second identity root (ADR 0004 D3):
    - The node refuses `AgentSign` to a recipient that is not a contact.
    - The node refuses `AppSubmit` with `NOT_A_CONTACT` when `peer_identity_hex` is not a contact key.
    - On receipt, RDAP requires `peers[meta.sender] == item.sender_identity_hex`, where `item.sender_identity_hex` comes from a contact-admitted, session-bound certificate.
- **Rejected alternative:** keep RDAP's seed and add a node-signed binding certificate. That is the deferred `USER_AGENT_DEVICE` follow-on (D3); it needs a new signed record and creates a second pin namespace.

### 4.2 `AgentSign`: one typed context, structurally separated

**Statement fields (one context only)** for `raven.a2a.delegation.v2`:

- `sender`, `recipient`, `task_id`, `kind` (`task` | `answer`)
- `issued_at`, `expires_at` (unix seconds)
- `payload_sha256_hex`, `nonce_hex`

The daemon builds `lp(ctx)‖lp(sender)‖lp(recipient)‖lp(task_id)‖lp(kind)‖lp(dec(issued_at))‖lp(dec(expires_at))‖lp(digest32)‖lp(nonce16)`. That is byte-identical to `ta/raven_identity.py:530-553`. The daemon never sees the text, only its digest.

**Validation** (fail closed, cheapest first):

1. The gate is live.
2. `context` is exactly the constant.
3. `sender` equals the node's own address.
4. `recipient` is the `encode_address` of a current, unblocked contact's `pub_hex`.
5. `issued_at` is within ±60 s of now.
6. `0 < expires_at - issued_at ≤ 86400`.
7. `task_id` is 1-128 characters of `[A-Za-z0-9._:-]`.
8. `kind` is valid, and the hex lengths are exact (64 and 32).

**Rate limits**, as two token buckets per daemon:

- `kind=task` (locally initiated): 60 per minute.
- `kind=answer`: 30 per minute per recipient and 120 per minute in total.

A teammate flooding tasks can only drain Bob's answer bucket for that teammate. It never touches Bob's own `ask`.

**Structural domain separation (replaces the hand-kept list):**

- New `core/agent_sign.rs` defines `AGENT_DELEGATION_PREFIX = [0x00, 0x17] ‖ b"raven.a2a.delegation.v2"` and an opaque `AgentDelegationBytes` that only `agent_sign::build` can construct. It always starts with the prefix.
- `Identity::sign_agent_delegation(&self, b: &AgentDelegationBytes) -> [u8; 64]` is `pub(crate)`. It is the only path that signs prefixed bytes.
- `Identity::sign` gains `debug_assert!(!msg.starts_with(&AGENT_DELEGATION_PREFIX))`. Every test that signs any Raven object therefore proves its format cannot carry the prefix.
- `Identity::verify` returns `false` for any `msg` that starts with the prefix. This is release behaviour: no Raven verifier built on it can accept an AgentSign signature, whatever its format.
- `core/internet.rs:176` (the only direct `VerifyingKey` user) gets the same prefix refusal.
- Test CORE-11 asserts that no signing input in `shared-vectors/rvn1/**` starts with the prefix. It also asserts the reverse: RDAP's verifier rebuilds bytes that start with the prefix, so no Raven signature can verify as a delegation.

**Response:** `{signer_address, signer_pub_hex, signature_b64}`. RDAP re-verifies locally with its own builder against the bound public key; if they disagree it fails closed, which catches canonicalisation drift.

**Logging:** counts only, never field values.

### 4.3 Authorisation boundary (corrected rationale)

- **Linux and Windows.** UID peer credentials or the per-user pipe ACL equal the platform boundary (daemon-owned-secrets §3.0). A same-user process can already read the keys and stores. `AppSubmit` equals `SealUnderSession`, which is already UID-only. `AgentSign` and `AppInboxPage` add nothing that same-user code lacks.
- **macOS.** That argument does **not** hold. Node keys and stores sit behind Keychain code-identity ACLs. A UID-only `AppInboxPage` returns decrypted content, and `AgentSign` uses the identity key, without the dialog a foreign process would face today.
  - **Decision:** `app_channel_live_enabled()` is false on macOS in non-lab builds until the owner either accepts Q6 (UID-only for the RDAP client) as a documented residual in the ADR 0004 amendment, or the code-identity tier (daemon-owned-secrets §4.4) lands.
  - The debug lab unlock still works, because the lab uses throwaway identities.

```rust
// core/app_gate.rs
pub const APP_CHANNEL_PRODUCTION_ENABLED: bool = false;
/// Owner decision on daemon-owned-secrets Q6 (UID-only IPC for RDAP on macOS).
pub const APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED: bool = false;
pub fn app_channel_live_enabled() -> bool {
    let platform_ok = !cfg!(target_os = "macos") || APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED;
    (APP_CHANNEL_PRODUCTION_ENABLED && platform_ok) || crate::pair_init::lab_test_a_enabled()
}
pub fn content_type_registered(ct: &str) -> bool {
    matches!(ct, "a2a-request/1" | "a2a-response/1")
        || (ct == "test/1" && crate::pair_init::lab_test_a_enabled())
}
```

### 4.4 RDAP identity loading and bound mode

**New `ta/node_identity.py`:**

```python
class NodeIdentity:
    """RDAP principal = the bound raven-node RVN1 (ADR 0004 D3). Holds no private key."""
    is_node_backed = True
    # address, public_hex, public_bytes, display_address, fingerprint, identity_card()
    def sign_delegation_statement(self, fields: dict) -> bytes   # AgentSign + local re-verify

def load_agent_identity(st: dict, repo: Path):
    """bound -> NodeIdentity(data_dir=st['raven_bind'].get('data_dir') or default_raven_data_dir());
       unbound -> RavenIdentity.load_or_create(keys_dir) (unchanged behaviour)."""
```

**Bound marker.**

- `raven-bind --from-node` (and the first bound-mode use of a home bound before this change) writes `.team/keys/BOUND_TO_RAVEN_NODE`. It is 0600 JSON holding `address`, `public_key`, `data_dir` and `consumer_id = "rdap:" + 16 random hex`.
- `RavenIdentity.load_or_create` refuses when the marker exists: "this keys dir is bound to raven-node <addr>; it signs only through the node (ADR 0004 D3)".
- This single check covers every caller:
  - `rdap.py:201`, `:1512`, `:1658`, `:1898`, `:2573`
  - `ta/server.py:639`
  - `ta/__main__.py:96`, `:103`
  - `ta/client.py:511`
- The `rdap.py` call sites switch to `load_agent_identity`. The standalone entry points (`python -m team_agents id/send/serve`, `client.py main`) simply fail closed on a bound keys dir.

**Old seed.** At bind, an existing `.team/keys/device_ed25519.seed` whose address differs from the node's is moved to `.team/keys/retired/device_ed25519.<addr8>.seed` (0600, never read). The command prints:

> retired RDAP-only identity rvn1…; teammates who trusted it should remove it from peers.json or add it to their revocations file

Nothing is deleted.

**Node-backed signing.**

- `sign_delegation` (`ta/raven_identity.py:556`) checks `getattr(identity, 'is_node_backed', False)`. When set, it builds the same fields, calls `identity.sign_delegation_statement`, verifies locally, and returns the same dict.
- `sign_http_request` raises `ValueError("a raven-node bound home never signs HTTP task requests (ADR 0004 invariant 3)")`.
- `NodeIdentity` has no `jwk_private`, so card signing is impossible by construction.

**`NodeConfig.raven_bind`** (`data_dir`, `consumer_id`, `address`, `public_key`) is set by `cmd_start`. `build_app` builds `NodeIdentity` from it. `cmd_start` (`rdap.py:1060-1081`):

- Drops the "no local seed" refusal for bound homes.
- Instead requires `Status.capabilities ∋ "app_channel"`; otherwise it exits with "the raven channel is unavailable on this raven-node (APP_CHANNEL_HOLD or not running); a bound home has nothing else to serve".

If the node cannot be reached in a bound home, every signing call fails closed with "raven-node is not running; a bound home signs only through it". There is never a fallback to a seed.

### 4.5 Identity key vs device key; revocation (G5)

- `AppSubmit` takes the contact's identity key. The daemon resolves the device from the contact book and requires `cert.user_ed_pub == identity` on the session-bound certificate. Under today's LAN rule (`core/lan_dispatch.rs:89-94`) they are the same key. If more than one device matches, the answer is `APP_MULTI_DEVICE_UNSUPPORTED`.
- **Lineage revocation (RVDR1), enforced by the node:**
  - At submit: `ATSAM_LINEAGE_REVOKED`, nothing sealed.
  - In the worker: `failed(PEER_REVOKED)`.
  - At page time: the item is tombstoned (§7.5).
  - RDAP treats each as a hard deny and never reports success (G5.5).
  - A record that failed for lineage reasons is never resendable (§8.3).
- **Address deny** (RDAP `revocations_file`) is enforced by RDAP: it does not send to, and silently refuses tasks from, a denied address. Neither side edits the other's lists (G5.2(3), (4), (7)).

---

## 5. Inner wire format: `RVNAPP/1`

New lab spec `protocol/RAVEN_APP_PAYLOAD_V1.md`, listed under "Draft / not production wire" in `PROTOCOL_VERSIONS.md`. The frame lives inside the ATSAM AEAD plaintext of an indexed-session Message. It is not an envelope change.

### 5.1 Grammar

```
APP_FRAME    = MAGIC SP CONTENT_TYPE SP APP_ID LF BODY
MAGIC        = "RVNAPP/1"
CONTENT_TYPE = LOWER *30( LOWER / DIGIT / "." / "+" / "-" ) "/" NZDIGIT *2DIGIT   ; <= 36 chars
APP_ID       = 32 LOWHEX                                                       ; 16 random bytes from the sender node
BODY         = UTF-8; every char is TAB, LF, CR or >= U+0020 and != U+007F; may be empty
```

| Constant (`core/app_channel.rs`) | Value |
|---|---|
| `APP_FRAME_MAGIC` / `APP_RESERVED_PREFIX` | `"RVNAPP/1"` / `"RVNAPP/"` |
| `MAX_APP_HEADER_BYTES` | 128 (the real maximum is 79) |
| `MAX_APP_FRAME_BYTES` | `MAX_LAN_ENDPOINT_TEXT` = 49152 (`core/lan_noise.rs:28`) |
| `MAX_APP_BODY_BYTES` | 49024, enforced on the body alone; const assert `MAX_APP_BODY_BYTES + MAX_APP_HEADER_BYTES <= MAX_APP_FRAME_BYTES` |

`app_body_text_ok(&[u8]) -> bool` is a new public helper with the same character rules as `valid_endpoint_text` but allowing empty. The private helper is not exported. The whole frame is never empty and still passes `valid_endpoint_text` at seal and accept.

### 5.2 Classification

`app_channel::classify(plaintext) -> PayloadClass`:

| Plaintext | Class | Effect |
|---|---|---|
| Does not start with `RVNAPP/` | `Chat` | Unchanged behaviour |
| Starts with `RVNAPP/1 ` and parses strictly | `App(AppFrame{content_type, app_id, body})` | §7 |
| Any other `RVNAPP/` text | `ReservedInvalid` | Deferred (never committed, never shown) |

### 5.3 Content-type registry (compiled, node policy)

| Token | Owner | Body | Allowed |
|---|---|---|---|
| `a2a-request/1` | RDAP | A2A JSON-RPC `SendMessage` request (§6.1) | Gate live |
| `a2a-response/1` | RDAP | A2A JSON-RPC response with a `Task` (§6.2) | Gate live |
| `test/1` | Raven lab | Vectors and harness | Lab unlock only |

- The sender refuses an unregistered type with `APP_BAD_CONTENT_TYPE`.
- The receiver defers it.
- Splitting requests from responses gives them separate caps, so a home that runs no worker and fills up with tasks still accepts answers.

### 5.4 `app_id`

- Generated once per app outbox record and reused for `resend:true`.
- The receiver deduplicates on `(sender_device, message_id)` and on `(sender_device, app_id)`, so a resend after a lost ACK and an envelope expiry never stores a second item.

### 5.5 Compatibility and residuals

- **Old receivers (before P0)** show an app frame as chat text starting `RVNAPP/1`. Only the recipient sees it.
  - RDAP limits this with explicit opt-in: a teammate gets the raven channel only through `rdap trust … --via raven`.
  - There is no signed capability registry (`RAVEN_CAPABILITIES_V1` §1). The residual is documented.
- **P0+ receivers in release builds** (gate closed) defer every app frame.
  - A sender cannot tell "gate closed" from "offline".
  - RDAP's 4 h default TTL bounds the wait.
  - `rdap ask` prints a hint when a task stays `sent` with no ACK for 2 minutes: "bob's node has not confirmed it; if bob's raven-node has no raven channel it never will".
- **Chat from pre-P0 senders** that happens to start with `RVNAPP/` is deferred and never ACKed; the sender sees `expired`. This is documented in RAVEN_APP_PAYLOAD_V1 §compat and the LAN waiver amendment.
- **Composer guard.**
  - `run_pair_init_and_send_routes` (`ash/pair_init_lab.rs:477`, the funnel for every send path) refuses text starting with `RVNAPP/`: "NOT SENT: messages may not start with the reserved prefix RVNAPP/".
  - `deliver_routes` repeats the check next to the empty-text check (`ash/ext.rs:2386`) for an early exit.
- **Future versions:** `RVNAPP/2` is `ReservedInvalid` on v1 nodes and is deferred. A version bump needs negotiation, which is out of scope.

### 5.6 What carriers and relays see

A standard sealed Message envelope: route tag, mailbox tag, StoreObject. Content type and `app_id` are inside the AEAD. Size is visible (padding is a non-goal). The outer device signature names the sender to hops (existing waiver risk 6).

### 5.7 Vectors

`shared-vectors/rvn1/app_payload/` holds `valid_*.json` and `negative_*.json`. Negative cases:

- Bad magic, uppercase hex, missing LF.
- Oversize body (49025 bytes); a 49024-byte body is valid.
- NUL, DEL, ESC.
- Empty or uppercase content type, version `0` or `1000`.
- Header longer than 128 bytes.

Rust (`core/app_channel.rs` tests) and Python (`ta/selftest.py`) both run them.

---

## 6. A2A payload profile

### 6.1 Request (`a2a-request/1`)

```json
{"jsonrpc":"2.0","id":"<task_id 32hex>","method":"SendMessage",
 "params":{"message":{"messageId":"<task_id>","role":"ROLE_USER","parts":[{"text":"<task text>"}],
   "metadata":{"raven.sender":"rvn1…A","raven.recipient":"rvn1…B","raven.task_id":"<task_id>","raven.kind":"task",
     "raven.issued_at":"1760500000","raven.expires_at":"1760514400","raven.nonce":"<32hex>",
     "raven.algorithm":"ed25519","raven.context":"raven.a2a.delegation.v2","raven.signature":"<b64>"}}}}
```

- Metadata is identical to the HTTP path (`ta/client.py:419-433`). The message is built with the `a2a.types` protobufs and `json_format.MessageToDict`.
- Profile rules: exactly one text part, and `messageId == raven.task_id == id`.

### 6.2 Response (`a2a-response/1`)

```json
{"jsonrpc":"2.0","id":"<task_id>","result":{"task":{"id":"<task_id>","contextId":"<task_id>",
  "status":{"state":"TASK_STATE_COMPLETED"},
  "artifacts":[{"artifactId":"result","name":"result","parts":[{"text":"<answer>"}],
     "metadata":{"raven.sender":"rvn1…B","raven.recipient":"rvn1…A","raven.task_id":"<task_id>","raven.kind":"answer","…":"…"}}]}}}
```

`state` is one of:

| State | When |
|---|---|
| `TASK_STATE_COMPLETED` | Normal answer |
| `TASK_STATE_FAILED` | Brain error, interrupted run, or "already executed via another channel" |
| `TASK_STATE_REJECTED` | Expired, or invalid delegation from a known teammate |

The artifact text, including any failure reason, is always delegation-signed. `state` is node-authenticated transport metadata and drives the UX only.

### 6.3 Canonical printable JSON

```python
_ESC = {c: f'\\u{c:04x}' for c in range(0x7f, 0xa0)}   # DEL + C1; C0 is escaped by json.dumps
body = json.dumps(obj, ensure_ascii=False, separators=(',', ':'), allow_nan=False).translate(_ESC)
body.encode('utf-8')   # strict; a lone surrogate -> "task text contains invalid Unicode"
```

The receiver parses with an `object_pairs_hook` that rejects duplicate keys, and applies the bound `MAX_APP_BODY_BYTES`.

### 6.4 Size budget

- **Task:** if the complete body is larger than 49024 bytes, the send is refused with `RAVEN_PAYLOAD_TOO_LARGE`. Nothing is signed or stored. That is about 44 KiB of ASCII text.
- **Answer:** `fit_answer_to_frame(text, state, meta_template)` binary-searches the longest prefix plus the suffix `"\n[raven answer truncated to the channel limit]"` that fits, **before** signing. A cached reply from another channel that does not fit is truncated and re-signed (§11.5).

---

## 7. Receiver node

### 7.1 Store API: application policy before commit (`core/indexed_session_store.rs`)

```rust
pub enum InboundPolicy { Accept, Defer(&'static str /* counter name */) }

pub fn accept_message_envelope_with_policy(
    &mut self, key: &IndexedSessionRecordKey, packed_envelope: &[u8],
    sender_certificate: &DeviceCertificate, sender_revoked: bool, now_ms: u64,
    policy: &mut dyn FnMut(&[u8]) -> InboundPolicy,
) -> Result<EndpointAcceptance, IndexedSessionStoreError>
```

- **Where the hook runs.** The body is today's `accept_message_envelope`, with one addition right after `valid_endpoint_text(&plaintext)` (`:2919`) and before `state.generation` is incremented: `if let InboundPolicy::Defer(_) = policy(&plaintext) { return Err(ApplicationDeferred) }`.
- **Nothing persists.** The immediate transaction is dropped. The in-memory candidate receive key is discarded and the `state` copy is never written. So there is no receipt, no inbox row, no ACK intent and no ratchet change.
- **Old entry point.** `accept_message_envelope` becomes a wrapper that passes `|_| InboundPolicy::Accept`.
- **New error.** `IndexedSessionStoreError::ApplicationDeferred`, whose `redacted_display` is `"APP_DEFERRED"`.
- **Retry.** The sender re-sends the exact bytes. Because nothing was committed, the duplicate-by-digest check misses and the full path runs again. If later indices were accepted in the meantime, the deferred index uses the skipped key, of which at most 256 are held (`:83`). App objects in flight are capped at 16 per peer, so the bound is not reached in normal use. Beyond it the object can never be accepted, and the sender sees `expired`.
- **Spec note.** Add to `ATSAM_ENDPOINT_TRANSACTION_V1.md` §1 step 7: "the application policy may defer; a deferred object commits nothing and is accepted later as a fresh object with the same bytes."

### 7.2 Policy and delivery (`core/lan_dispatch.rs`)

In `handle_indexed_message` (`:1440-1555`), unpack `env = Envelope::unpack(packed)` once for `created_at` and `expires_at`, then build the policy closure:

```rust
let mut policy = |pt: &[u8]| match app_channel::classify(pt) {
    PayloadClass::Chat => InboundPolicy::Accept,
    PayloadClass::ReservedInvalid => InboundPolicy::Defer("app_reserved_invalid"),
    PayloadClass::App(f) if !app_gate::app_channel_live_enabled() => InboundPolicy::Defer("app_gate_closed"),
    PayloadClass::App(f) if !app_gate::content_type_registered(&f.content_type) => InboundPolicy::Defer("app_type_unregistered"),
    PayloadClass::App(f) => match AppStore::admit(dd, &peer_device, &f.content_type, &f.app_id, f.body.len()) {
        Ok(Admit::Fits | Admit::AlreadyHave) => InboundPolicy::Accept,      // AlreadyHave: present or tombstoned
        Ok(Admit::Full) => InboundPolicy::Defer("app_inbox_full"),
        Err(_) => InboundPolicy::Defer("app_store_unavailable"),            // fail closed: commit nothing
    },
};
```

`AppStore::admit` reads **metadata only** (counts, sizes, id lookups). It needs no keystore access, so no Keychain round trip happens inside the session-store transaction. Lock order is session-store transaction, then `app_channel.sqlite3` (read). The reverse nesting never occurs.

**The candidates loop.** `ApplicationDeferred` ends the loop like any non-`RouteTagMismatch` result, because the route tag matched. It maps to `return Ok(Vec::new())` **before** `map_err`, so the link stays open.

**After commit:**

```rust
fn deliver_committed(dd, sessions, key, message_id, created_at_ms, received_at_ms, plaintext) -> Result<bool, String> {
    match app_channel::classify(plaintext) {
        PayloadClass::Chat => { persist_lan_chat_history(...)?; Ok(true) }   // unchanged, incl. Err semantics
        PayloadClass::App(frame) => {
            let (dev, cert) = session_bound_remote(dd, sessions, key)?;        // never the link bundle
            match AppStore::ingest(dd, &cert, message_id, created_at_ms, received_at_ms, &frame) {
                Ok(()) => Ok(true),     // inserted, already present, or tombstoned
                Err(_) => Ok(false),    // I/O or keystore: no ACK now; the row stays durable in the endpoint inbox
            }
        }
        PayloadClass::ReservedInvalid => Ok(false), // unreachable after policy; defensive
    }
}
```

- **Wiring.** The `Committed` branch calls it with the committed plaintext. The `Duplicate` branch calls it with `load_endpoint_inbox(...)` plaintext and `row.created_at_ms`. If it returns `false`, return `Ok(vec![])` before `enqueue_committed_ack`.
- **`session_bound_remote`.** Uses `session_bound_peer_certificate(dd, sessions, key, remote_device_of(key))`. For direct carriers this equals `peer.cert` (accept enforces the digest equality at `:2862-2868`). Relayed carriers later must pass the session-bound certificate the same way (CORE-13).
- **Ingest never refuses for capacity.** Capacity is decided only before commit, so a committed row is always admitted. Overshoot is bounded by concurrent accepts.

### 7.3 Every committed app row reaches the app inbox

`app_channel::ingest_pending_committed(dd)`:

- Iterates `pending_endpoint_ack_intents()`. That is metadata only and usually empty, because a normal path ACKs only after ingest.
- For each intent it runs `load_endpoint_inbox(key, digest)` and `classify`. App rows are passed to `ingest`; chat rows are left to the existing paths.
- It runs:
  - In `maintain_lan_durable_state` (listener preflight).
  - In every service prune (`prune_lan_durable_state`, `:1258`), before sessions are destroyed.
  - At worker start.

`archive_expired_inbox_to_history` (`:490`) sends `App` rows to `ingest` instead of chat history. Tombstoned rows are skipped. `ReservedInvalid` rows cannot exist. An ingest error fails the prune for that pass, as a chat history error does today, so roots are not destroyed and the prune retries.

Result:

- A committed app payload is either ACKed after ingest, or remains durable in the endpoint inbox until a sweep or the archive ingests it.
- If a future spec-conformant ACK sweep ACKs a pending intent early, the payload still lands in the app inbox. CORE-6 proves this.
- Tombstone retention (8 days) exceeds the maximum session lifetime (7 days, `core/prekey_lifecycle.rs:55`), so the archive cannot resurrect an acked item.

### 7.4 App inbox limits

| Constant | Value |
|---|---|
| `APP_INBOX_MAX_ITEMS` | 128 |
| `APP_INBOX_MAX_BODY_BYTES` | 4 MiB |
| `APP_INBOX_MAX_PER_SENDER_TYPE` | 16 per `(sender_device, content_type)` |
| `APP_INBOX_ITEM_TTL_MS` | 7 days from `received_at` (expires to a tombstone with disposition `expired`) |
| `APP_TOMBSTONE_RETENTION_MS` | 8 days |
| `APP_TOMBSTONE_MAX` | 8192; the oldest is evicted first. A resurrection after eviction is harmless because RDAP's ledger deduplicates by signature |

- Only admitted contacts reach the policy (`peer_is_trusted`, `:1446`), and only after a route-tag-matched ATSAM accept.
- `ingest` and `ack` bump `app_channel::GENERATION: AtomicU64`, a process-global static in core that the long-poll watches.

### 7.5 `AppInboxPage` re-checks and consumer binding

**Re-check per item served (G5.2(5)).** Each row stores the session-bound sender certificate inside its sealed plaintext. When the row is decrypted for serving:

| Check | Failure → tombstone disposition |
|---|---|
| `contact_admission(dd, &cert.user_ed_pub)` is `Allowed` | `NotContact` → `not_contact`; `Blocked` → `blocked` |
| `RevocationStore::load_checked(dd)?.denies_certificate(&cert)` (`core/device_sync.rs:494`) is false | `revoked` |
| Contact book unreadable | The whole page fails with `CONTACTS_UNREADABLE` (fail closed; items kept) |
| `expires_at_ms <= now` | `expired` |

**Consumer binding (replaces the lease).** One row in `app_consumer`, saved to disk:

- The first `AppInboxPage` with an unbound node binds its `consumer`.
- Any other consumer gets `APP_CONSUMER_BUSY` naming the bound consumer's 8-character prefix, across daemon restarts.
- `takeover:true` rebinds. It is used only by explicit user commands: `rdap raven-bind --from-node … --takeover` and `raven lab app-consumer --takeover`.
- `AppInboxAck` requires the bound consumer.
- Unacked items are re-served to the bound consumer. After a crash, RDAP's ledger answers `interrupted` instead of re-running.

**Long-poll.**

- `dispatch` routes `AppInboxPage` to an async handler: a blocking page read, then, if empty and `wait_ms > 0`, poll `GENERATION` every 250 ms up to `wait_ms ≤ 20 000`, then re-read.
- `Ping` stays inline (`rn/ipc_server.rs:719`).
- Each long-poll holds one of the 64 IPC slots; RDAP uses 2.

### 7.6 Cost of a deferral (corrected)

- **Dialler side.** If the deferred app frame is the only frame in the dial that expects a reply, the dialler waits `ReplyCollector.first` = 30 s and records `Sent / NO_ACK_YET` (`rn/main.rs:584-587`, `:628-634`). Otherwise it waits at most the 2 s idle wait after the last reply.
- **Receiver side.** Each such attempt holds one inbound link for up to 30 s.
- **Bound.** The worker backoff (5 s doubling to 10 min, ±50 % jitter) gives about 150 attempts over a 24 h envelope; RDAP's 4 h default TTL gives about 30.
- **When space frees up.** Space freed by `AppInboxAck` is noticed at the sender's next backoff slot (at most 10 min). The receiver does not signal it, which would need a wire change.
- Chat frames in the same dial are never affected (RN-20, C7c).

### 7.7 Chat surfaces must not show app frames

| Surface | Change |
|---|---|
| `ash inbox` (`cmd_endpoint_inbox`, `ash/cli.rs:6597`) | Skip rows where `classify != Chat`; print a dim "N agent payload(s) for RDAP not shown" |
| Chat poller (`peek_endpoint_inbox_for_contact`, `ash/ext.rs:3207`) | For non-chat rows, advance the cursor, do not print, do not `persist_lan_chat_history` |
| Receive path / expiry archive | §7.2, §7.3 |
| Sender's own history | `AppSubmit` never writes history |

---

## 8. Sender node: `AppSubmit`

### 8.1 Algorithm (`rn/app_channel.rs::app_submit`, blocking pool)

```rust
gate()?;                                                      // APP_CHANNEL_HOLD
let identity = parse_hex32(&req.peer_identity_hex)?;          // APP_BAD_IDENTITY
let ct = ContentType::parse_registered(&req.content_type)?;   // APP_BAD_CONTENT_TYPE (syntax or unregistered)
let cref = ClientRef::parse(&req.client_ref)?;                // APP_BAD_CLIENT_REF: 1..96 of [A-Za-z0-9._:-]
let body = b64(&req.body_b64)?;                               // IPC_BAD_B64
check_body(&body)?;                                           // APP_PAYLOAD_TOO_LARGE / APP_PAYLOAD_INVALID (app_body_text_ok)
let ttl = req.ttl_ms.unwrap_or(4 * HOUR);                     // APP_BAD_TTL unless APP_MIN_ENVELOPE_MS(10 min) <= ttl <= 24 h
let ctx = outbox::attempt_ctx().ok_or(OUTBOX_WORKER_OFF)?;
let digest = sha256(&body);
let mut decision = AppStore::dedup(dd, &identity, &cref, &digest, &ct, req.resend)?;   // §8.3, read only
if let Decision::Return(r) = decision { return r }            // Duplicate / Conflict / LineageRefused
let device = resolve_device(dd, &identity)?;                  // NOT_A_CONTACT / CONTACT_BLOCKED / CONTACTS_UNREADABLE / APP_MULTI_DEVICE_UNSUPPORTED
precheck_inflight(dd, &device)?;                              // APP_QUEUE_FULL (16)
let routes = outbox::peer_plan(..).auto_dial(..);             // the worker's resolver: learned routes, on-link filter, route memory, connected first, hide-IP, gates, verified rule, localize
let need = session_need(dd, &device, now)?;                   // §8.2
let probed = if need.pair { pair_budget_open(..)?; Some(probe(&ctx, &device, &routes, started)?) } else { None }
                                                              // APP_PAIR_BUDGET (no dial) / APP_PEER_UNREACHABLE / NO_ROUTE / LINK_NOT_ACCEPTED / WRONG_IDENTITY
let _lock = PeerSendLock::acquire_within(dd, &device, 5s)?;   // SEND_IN_PROGRESS
decision = AppStore::dedup(dd, &identity, &cref, &digest, &ct, req.resend)?;          // re-decide under the lock
if let Decision::Return(r) = decision { return r }
recheck_inflight(dd, &device)?;                               // APP_QUEUE_FULL
let key = ensure_session_locked(&ctx, &device, probed)?;      // §8.2: re-check session; else PairInit within budget
clear_orphan_prepared(dd, &mut store, &device)?;              // §8.4
let peer_cert = session_bound_peer_certificate(..)?.ok_or(ATSAM_SESSION_REQUIRED)?;
refuse_if_session_lineage_revoked(dd, &local_cert, &peer_cert)?;   // ATSAM_LINEAGE_REVOKED, before any seal crypto
let expires = envelope_expires_at(now, session_expires)?.min(now + ttl);
if expires < now + APP_MIN_ENVELOPE_MS { return Err(ATSAM_SESSION_REQUIRED) }   // session ended during the op
let (app_id, seq) = match decision { Decision::Fresh => (random16(), 0), Decision::Resend { app_id, seq } => (app_id, seq + 1) };
let frame = encode_app_frame(&ct, &app_id, &body)?;
let mut recorded = false;
let res = store.send_message_envelope(&key, &frame, &local_device, now, expires, now, &mut OsRng, &mut |d, bytes| {
    let env = Envelope::unpack(bytes).ok_or(())?;
    AppStore::put_outbound(dd, AppOutRecord::queued(&identity, &device, &cref, &ct, app_id, digest,
        env.message_id, session_id, *d, now, env.expires_at, seq)).map_err(|_| ())?;
    recorded = true; Ok(*d)                                   // handed to the outbox queue: the worker dials
});
match res {
    Ok(_) => {}
    Err(OutboundPending) => return Err(APP_LANE_BUSY),
    Err(LocalDeviceUnauthorized | RevokedDevice) => return Err(ATSAM_LINEAGE_REVOKED),
    Err(OutboundQueueHandoff) if !recorded => { give_up_prepared_orphan(..)?; return Err(APP_STORE) }  // never on the wire
    Err(e) => return Err(map_seal_store_error(e)),
}
record_object_routes(dd, &mid, &device, CarrierChoice::Auto, &[], expires, now);   // choice only: the worker re-plans through the same resolver at every attempt
set_object_unsent(dd, &mid, true, now);
drop(_lock); outbox::kick(Some(&device), true);
Ok(AppSubmitResult { message_id_hex, app_id_hex, state: "queued", expires_at_ms: expires, duplicate: false, attempt_seq: seq })
```

The worst case is about 80 s plus the seal: route resolution and the probes take 30 s together (`APP_PROBE_BUDGET`, counted from the start of `resolve()`: LAN name resolution of at most 15 s inside that; each probe 10 s at most; the last planned route always keeps 10 s), three lock waits of 5 s at most (the submit's, and `pair_with_peer`'s two), and a 35 s PairInit dial. That stays under the 90 s client timeouts of ash `lab app-submit` and RDAP's `app_submit`; two const asserts in `rn/app_channel.rs` keep it so. If the client gives up while the daemon goes on to seal, the retry with the same `client_ref` returns `duplicate:true` with the same message id (RN-7c).

### 8.2 Session ensure and daemon-side PairInit

**Usable session:** the newest confirmed session for the device (`find_confirmed_sessions_for_peer_at`) with at least `APP_MIN_ENVELOPE_MS = 10 min` left.

- If one exists, there is **no dial and no PairInit**. The envelope gets `min(session end, now + ttl)`.
- There is no proactive re-pair. A seal close to session end may expire; RDAP then resends, and the resend pairs if no usable session remains.

**Shared pairing core** (removes the duplication with ash):

- Move `live_pair_init_outbound_ready()` from `ash/trace_delivery.rs:14` to `core/pair_init_lan_oob.rs`. ash re-exports it, and `AppSubmit` checks it first (`PAIR_INIT_GATE` → `APP_CHANNEL_HOLD`).
- Move `first_pair_response` (`ash/pair_init_lab.rs:421`) to core.
- Add `core::pair_init_lan_oob::pair_over_dial(dd, id, bundle, dial: &mut dyn FnMut(&[Vec<u8>]) -> Result<Vec<Vec<u8>>, String>) -> Result<IndexedSessionRecordKey, PairError>`. It runs `create_initiator_pair_init`, `wrap_pair_init`, `dial([init])`, `first_pair_response` and `confirm_verified_pair_response`.
- ash replaces its inline block (`ash/pair_init_lab.rs:620-680`) with a call to it and keeps its own error wording.

**`Dialer` deadline.** `Dialer::dial(&self, data_dir, route, expected_pub_hex, frames, deadline: Duration)`.

- NetDialer uses `timeout(deadline.min(DIAL_DEADLINE))`.
- The worker passes `DIAL_DEADLINE`.
- `AppSubmit` passes `APP_PROBE_DEADLINE = 10 s` for probes and `APP_PAIR_DEADLINE = 35 s` for the PairInit dial, which must exceed the 30 s first-reply wait.

**Probe.**

- A frame-less dial of every planned route in the worker's order (a connected p2p route first, then the remembered one, then plan order); the first that offers wins, all within `APP_PROBE_BUDGET` (30 s, resolution included; 10 s per probe; a route with under 2 s left is not dialled).
- An offer naming another key fails that route only; the walk goes on.
- No probe while the pairing budget is spent: `APP_PAIR_BUDGET` without a dial (RN-5).
- A walk that found nobody is not repeated for the same routes within 15 s (`APP_PEER_UNREACHABLE` at once, no dial); a changed route list probes at once.
- When every route turned this node away and a p2p route's refusal is part of that, the p2p route is dialled once more after 1 s (`APP_REFUSAL_RECHECK`), inside the same budget. Only a second refusal counts as the contact's (a node re-homing its p2p host or shutting down looks the same once); an offer on that dial wins. The log line shows it as `p2p_dial recheck <code>`.
- Only a connection the contact's own PeerId closed at once counts as a p2p refusal. A relay's answer never does: when the contact's gate turns a circuit away, the relay answers `CONNECTION_FAILED`, the same answer as a failed STOP to a contact that is gone, so a contact reached only through a relay that has not added this node reads `APP_PEER_UNREACHABLE` (retried by RDAP until `deliver_until`), never `LINK_NOT_ACCEPTED` (the diagnosis reads it the same way, `CircuitOutcome::NotOnRelay`; `app_channel::tests::the_probe_maps_refusals_end_to_end`).
- One log line per walk, codes only (`raven-node app: probe lan_dial CLOSED_EARLY, internet_dial CLOSED_EARLY, p2p_dial offer`).
- `AppSubmit` parses the offer from the replies (`parse_peer_offer`), requires `cert.user_ed_pub == identity` or `cert.device_ed_pub == device`, and calls `cache_peer_bundle` **explicitly**, as ash does at `:571-585`. It does not rely on the dialler having cached it, so FakeNet works.
- Probes consume no prekey claims and are not budgeted.

**Pairing budget** (`app_pair_attempts` table, saved to disk):

- At most `APP_AUTO_PAIR_MAX_PER_DAY = 4` PairInit frames per peer device in any 24 h, and at least 60 s apart. Otherwise the answer is `APP_PAIR_BUDGET` with the next allowed time.
- The attempt is recorded **before** the PairInit dial, so a crash still counts.
- `peer_seen` does not reset it.
- 4 is 1/8 of the responder's per-initiator quota of 32, leaving room for `raven send` pairings in the same day.

**Under the lock:** re-check for a usable session (another sender may have paired), then pair if still needed, then continue.

**Errors when no usable session exists:**

| Failure | Code | Retryable |
|---|---|---|
| No route answered the probe, or the routes disagree | `APP_PEER_UNREACHABLE` (nothing sealed) | yes |
| PairInit sent, no PairResponse | `APP_PEER_UNREACHABLE` (budget consumed) | yes |
| Budget exhausted (checked before any dial) | `APP_PAIR_BUDGET` | yes, after the time given |
| Every route refused this node (for p2p: the contact's PeerId closed the connection at once, and again on a second dial about 1 s later within the probe budget; a p2p refusal that is not repeated, or that the budget leaves no room to check, gives `APP_PEER_UNREACHABLE`; so does a circuit the contact's gate turns away, which the relay answers with `CONNECTION_FAILED`) | `LINK_NOT_ACCEPTED` | no |
| Every route offered another key (a key mismatch the carrier rejects inside its dial reads `APP_PEER_UNREACHABLE`, retryable, as before) | `WRONG_IDENTITY` | no |
| Prekey rollback | `PEER_PREKEY_RESET` | no |
| No route / only non-LAN routes for an unverified contact | `NO_ROUTE` / `CONTACT_NOT_VERIFIED` | no |

Carrier planning honours `CarrierGates` (`core/outbox.rs:1011-1069`) and `confidential_to_endpoint()`. Under the HOLD that means LAN only, and local-network addresses only for unverified contacts. It goes through the worker's resolver (`rn/outbox.rs::peer_plan`, shared with the delivery worker and the route-hints announcer): the on-link filter (a learned LAN address on none of this computer's networks is not dialled), the route memory (read, never taught; while learning connectivity is on, Phase 6a, the learned carrier order instead, [`2026-10-learning-connectivity.md`](2026-10-learning-connectivity.md) §2.1), connected first, learned routes and hide-IP.

### 8.3 Dedup and resend decisions (`AppStore::dedup`)

| Existing record for `(peer_identity, client_ref)` | `resend` | Decision |
|---|---|---|
| None | any | `Fresh` |
| Different body digest or content type | any | `Return(APP_CLIENT_REF_CONFLICT)` |
| Same body, any state | false | `Return(duplicate:true, current state)` |
| Same body, `queued`/`sent`/`delivered` | true | `Return(duplicate:true, current state)` (nothing to resend) |
| Same body, `expired` / `failed(other)` / `cancelled` | true | `Resend{app_id, seq}`, which continues through **the full path** (§8.1) |
| Same body, `failed(PEER_REVOKED)` or `failed(ATSAM_LINEAGE_REVOKED)` | true | `Return(ATSAM_LINEAGE_REVOKED)`; nothing sealed (G5.5: re-pair only on a new lineage, with a new task) |

The decision is recomputed under the PeerSendLock. A resend to a contact that is now blocked or removed fails admission with nothing sealed. A resend to a revoked lineage fails the lineage check with nothing sealed.

### 8.4 Orphan Prepared rows

`clear_orphan_prepared` (under the PeerSendLock):

- **What it selects:** every Prepared `Message` row to the device with no stage, no outbound history row and no app record.
- **What it does:** abandons the row via `give_up_outbound(.., HISTORY_FAILED)`, whose `mark_outbound_undelivered` is orphan-tolerant (§8.5), and counts it in `orphan_abandoned`.
- **Why it is safe:**
  - A body-less row is never dialled. The worker holds it as `NO_LOCAL_BODY`, and ash dials only rows it staged.
  - ash stages inside the handoff callback, under the same lock.
  - `SealUnderSession` rows are `Queued`, not `Prepared`, and are never touched.

### 8.5 Bookkeeping edits (`core/outbox.rs`): stage, then history, then app record

**`mark_outbound_undelivered` (`:276`):**

1. Stage present → existing behaviour.
2. Else `ChatHistory::set_delivery_persisted(..)`:
   - `Ok(true)` → done.
   - `Err(e)` → `Err(e)`, unchanged.
   - `Ok(false)` → step 3.
3. `AppStore::mark_outbound_final(dd, mid, delivery)`:
   - `Ok(true)` → done.
   - `Ok(false)` (no record) → **orphan** → `Ok(())` and count it.
   - `Err(_)` → return the existing "chat history row missing" error, so behaviour matches today and the caller retries later.

**`record_inbound_ack_delivery` (`:412`):** same order. Matching stage → history; else the history row if present; else the app record → `delivered`; else the existing `Err`.

**New `finish_app_outbound_delivered(dd, store, key, cert, sid, digest, mid, ack, now)`**, used by ash only if it ever ACK-verifies an app object. It runs `accept_sealed_ack`, then `settle_delivered_outbound`, then marks the app record. It never touches history or the stage.

Chat paths read the app store only when a message has neither a stage nor a history row. A locked or corrupt `app_channel.sqlite3` therefore never changes a chat outcome (RN-22).

### 8.6 Worker edits (`rn/outbox.rs`) and reconcile

- **`LocalBodies::has` (`:1249`):** also true when the message id is in the app-outbound set for that peer (one indexed query per attempt). On an app-store read error, the row stays `NO_LOCAL_BODY` (held, never abandoned).
- **History step (`:1632-1667`):** skipped for app objects.
- **ACK handling:** `record_outbound_delivered` → `record_inbound_ack_delivery` reaches the app branch (§8.5).
- **`finalize_vanished` (`:2136`):** when there is no stage but there is a non-final app record, mark it `expired` if `expires_at <= wall`, else `failed(STORE)`, and return the matching outcome.
- **Kind label:** `Entry` gains `app: bool`, set during scan or merge from the app-outbound set. `Entry::item` reports `kind: "app"` (`:253`).
- **Status:** `status_anywhere` (`:498`) looks in the worker, then the store scan, then **the app record**, then history. `resolve_from_history` resolves `gone` app items from the app record first.
- **`attempt_ctx()`:** a `OnceLock<Arc<AttemptCtx>>` set in `run_worker` (`:2199`), so `AppSubmit` reuses the worker's identity, dialer and gates.

**`app_channel::reconcile_app_outbound(dd, &store, now)`** runs in `maintain_lan_durable_state`, in `prune_lan_durable_state` **before** `prune_expired_sessions`, and at worker start. For each non-final app record with no store row:

| `outstanding_delivery_state` | Record becomes |
|---|---|
| `Delivered` or `Read` | `delivered` |
| Else, `expires_at <= now` | `expired` |
| Else | `failed(STORE)` |

Because it runs before session destruction, a daemon that was down across an expiry reconciles at preflight, while the store still knows (RN-19).

### 8.7 ash edits

- **`ash/pair_init_lab.rs` earlier-rows loop (`:1276`):**
  - Rows with an app record, or any body-less row while the app store is unreadable, are skipped: the worker owns them.
  - Orphans are given up (tolerant).
  - App rows do **not** count toward `MAX_QUEUED_PER_PEER` (`:1494-1505`). They have their own cap of 16, so agent traffic can never make `raven send` refuse.
- **`ash/ext.rs`:**
  - `resolve_outbox_mid` (`:2634`) accepts `kind == "app"`.
  - `raven outbox list/status` labels app objects "agent payload (a2a-request/1)" without a preview.
  - `raven outbox cancel` says "agent payload for bob cancelled" and goes through `give_up_outbound`, so the record becomes `cancelled`.
  - `raven outbox retry` kicks app objects like any other.
- **Lab commands** (debug builds with the gate live only): `raven lab app-submit`, `raven lab app-inbox [--wait-ms N]`, `raven lab app-ack`, `raven lab app-consumer [--takeover]`.

### 8.8 States and `OutboxStatus`

```
queued --carrier wrote it--> sent --verified sealed ACK--> delivered (final)
  \                            \--envelope expiry--> expired
   \--expiry, never written--> expired
   \--revoked lineage (PEER_REVOKED) / superseded session / store--> failed(code)
   \--`raven outbox cancel`--> cancelled
held(code) = live worker label (contact removed/blocked/not verified, lock busy); not stored
expired / failed(non-lineage) / cancelled are resendable (§8.3); delivered is final
```

`OutboxItem` keeps its exact key set; `kind` gains the value `"app"`.

---

## 9. IPC additions

### 9.1 Requests and responses (`core/ipc.rs`; `op` and `ok` are snake_case serde tags)

```rust
// IpcRequest
AppSubmit    { v: u16, peer_identity_hex: String, content_type: String, client_ref: String, body_b64: String,
               #[serde(default)] ttl_ms: Option<u64>, #[serde(default)] resend: bool },
AppInboxPage { v: u16, consumer: String, #[serde(default)] takeover: bool,
               #[serde(default)] content_type: Option<String>, #[serde(default)] after: Option<String>,
               #[serde(default)] limit: Option<u16>, #[serde(default)] wait_ms: Option<u32> },
AppInboxAck  { v: u16, consumer: String, items: Vec<AppInboxRef>, disposition: String },  // "done" | "rejected"
AgentSign    { v: u16, statement: AgentDelegationStatement },

pub struct AgentDelegationStatement { pub context: String, pub sender: String, pub recipient: String,
    pub task_id: String, pub kind: String, pub issued_at: u64, pub expires_at: u64,
    pub payload_sha256_hex: String, pub nonce_hex: String }

// IpcResponse
AppSubmitResult    { v: u16, message_id_hex: String, app_id_hex: String, state: String,
                     expires_at_ms: u64, duplicate: bool, attempt_seq: u32 },
AppInboxPageResult { v: u16, items: Vec<AppInboxItem>, next: Option<String>, more: bool, pending: u32 },
AppInboxAckResult  { v: u16, removed: u32 },
AgentSignResult    { v: u16, signer_address: String, signer_pub_hex: String, signature_b64: String },

pub struct AppInboxRef  { pub sender_device_hex: String, pub message_id_hex: String }
pub struct AppInboxItem { pub sender_identity_hex: String, pub sender_device_hex: String, pub sender_address: String,
    pub sender_verified: bool, pub message_id_hex: String, pub app_id_hex: String, pub content_type: String,
    pub created_at_ms: u64, pub received_at_ms: u64, pub expires_at_ms: u64, pub body_b64: String }
```

Wire examples:

```json
{"op":"app_submit","v":1,"peer_identity_hex":"<64hex>","content_type":"a2a-request/1","client_ref":"rdap-task:<tid>","body_b64":"eyJq…","ttl_ms":14400000}
{"ok":"app_submit_result","v":1,"message_id_hex":"<32hex>","app_id_hex":"<32hex>","state":"queued","expires_at_ms":1760514400000,"duplicate":false,"attempt_seq":0}
{"op":"app_inbox_page","v":1,"consumer":"rdap:9f2c…","content_type":"a2a-request/1","limit":4,"wait_ms":20000}
{"op":"app_inbox_ack","v":1,"consumer":"rdap:9f2c…","items":[{"sender_device_hex":"…","message_id_hex":"…"}],"disposition":"done"}
{"op":"agent_sign","v":1,"statement":{"context":"raven.a2a.delegation.v2","sender":"rvn1…","recipient":"rvn1…","task_id":"…","kind":"task","issued_at":1760500000,"expires_at":1760514400,"payload_sha256_hex":"…","nonce_hex":"…"}}
```

**Paging.**

- `limit` is at most 32; the default is 8.
- Each page carries at most 192 KiB of base64, but always includes the first item.
- `after` is the opaque cursor `"<received_at_ms>.<sender_device_hex>.<message_id_hex>"`.
- `pending` counts unacked, servable items for the filter. `rdap status` and `rdap doctor` use it with `limit:0`.

**Ack.** At most 32 refs. Unknown refs are ignored, so acks are idempotent. Disposition `done` or `rejected` writes a tombstone.

**Decoding.** All four ops join the `decode_request_checked` version match (`core/ipc.rs:311-327`). No key contains a forbidden token. The forbidden-key scan is extended to **responses**. Key-snapshot tests pin the exact key sets.

**Status.** `IpcResponse::Status.capabilities` gains `"app_channel"` when `app_channel_live_enabled() && outbox::is_running()`.

### 9.2 Error codes (added to `protocol/RAVEN_ERROR_CODES_V1.md` §2, with existing node codes now listed)

| Code | Op | Retryable | Meaning |
|---|---|---|---|
| `APP_CHANNEL_HOLD` | all app ops, AgentSign | no | Gate closed (including macOS pending Q6, PairInit gate) |
| `APP_BAD_IDENTITY`, `APP_BAD_CONTENT_TYPE`, `APP_BAD_CLIENT_REF`, `APP_BAD_TTL`, `APP_BAD_CURSOR`, `APP_BAD_CONSUMER` | submit, page, ack | no | Syntax, or type not registered |
| `APP_PAYLOAD_TOO_LARGE`, `APP_PAYLOAD_INVALID` | submit | no | Body over 49024 bytes, or bad characters |
| `APP_CLIENT_REF_CONFLICT` | submit | no | Same `(peer, client_ref)`, different body or type |
| `NOT_A_CONTACT`, `CONTACT_BLOCKED` | submit | no | Admission |
| `CONTACTS_UNREADABLE` | submit, page | yes, after a fix | Fail closed |
| `APP_MULTI_DEVICE_UNSUPPORTED` | submit | no | More than one device for the identity |
| `OUTBOX_WORKER_OFF` | submit | no | Not running under `raven-node service` |
| `APP_QUEUE_FULL` | submit | yes | 16 in flight to the peer |
| `APP_PEER_BACKLOG` | submit | yes, after the peer ACKs | 128+ messages on the session past the peer's newest ACK |
| `SEND_IN_PROGRESS`, `APP_LANE_BUSY` | submit | yes | Lock held / prepared lane |
| `APP_PEER_UNREACHABLE` | submit | yes | No usable session; peer unreachable or no PairResponse; nothing sealed |
| `APP_PAIR_BUDGET` | submit | yes, at the time given in the message | Automatic pairing budget used up |
| `NO_ROUTE`, `CONTACT_NOT_VERIFIED`, `LINK_NOT_ACCEPTED`, `WRONG_IDENTITY`, `PEER_PREKEY_RESET` | submit | no | Route, trust or pairing |
| `ATSAM_SESSION_REQUIRED` | submit | yes, once | Session became unusable during the op |
| `ATSAM_LINEAGE_REVOKED` | submit | **never** | G5 hard deny |
| `APP_STORE` | all app ops | yes | App store I/O or keystore failure |
| `APP_CONSUMER_BUSY` | page, ack | no | Another consumer is bound; use takeover |
| `AGENT_SIGN_FIELDS`, `AGENT_SIGN_SENDER`, `AGENT_SIGN_RECIPIENT_NOT_CONTACT`, `AGENT_SIGN_TIME` | AgentSign | no | Validation |
| `AGENT_SIGN_RATE`, `IDENTITY_UNAVAILABLE` | AgentSign | yes | Bucket empty / identity store locked |

### 9.3 Compatibility and authorisation

- `IPC_VERSION` stays 1; every op is additive. An older daemon answers `IPC_FRAME` (unknown op), which RDAP maps to "raven-node is too old for the raven channel".
- **Authorisation:** UID peer-cred on Unix and the per-user pipe ACL on Windows, exactly as for `SealUnderSession`. Windows reuses `serve_one` and `dispatch`. macOS is gated (§4.3).
- **O6 guard (`scripts/lib/o6_ipc_guard.sh`):** gains an explicit **reviewed allow-list** (`SealUnderSession`, `AppSubmit`, `AgentSign`, `AppInboxPage`). A self-test fails on any other `IpcRequest` variant whose name or fields contain `body`, `payload`, `sign` or `plaintext` (daemon-owned-secrets §4.4).

### 9.4 Relation to IPC v2

- `AppSubmit` is the forerunner of v2 `SubmitMessage` with a `content_type` field.
- `AppInboxPage` is the forerunner of v2 `InboxPage` with `content_type` and `wait_ms` (daemon-owned-secrets §4.4).
- The ADR amendment records that v2 absorbs them rather than adding a second surface.

---

## 10. Storage: `app_channel.sqlite3` (one file, sealed rows)

**Opening.** Opened exactly as `IndexedSessionStore::open` opens its SQLite file: private-file checks (`validate_private_file_metadata`, per-user ACL on Windows), busy timeout 5 s, `synchronous=FULL`, `secure_delete=ON`. Corruption returns `APP_STORE`; the file is never treated as empty.

**Sealed bodies.** Each row's sealed plaintext uses a new `pub(crate) struct DomainProtector { domain: &'static [u8], keys: OperationKeyCache }` in `core/chat_history.rs`:

- Modelled on `PlatformOutboundStageProtector` (`:1521-1580`), without the legacy-AAD fallback.
- Uses the **chat-history key** (no new keystore item) with domain `raven/app-inbox/v1`.
- `prepare()` warms the key before any lock.
- The sealed plaintext embeds the row's identity fields, and `open` checks them against the columns. So swapping blobs between rows or editing columns is detected: that row is quarantined and `app_row_tamper` is counted.

```sql
CREATE TABLE app_inbox(
  sender_device BLOB NOT NULL, message_id BLOB NOT NULL, app_id BLOB NOT NULL,
  sender_identity BLOB NOT NULL, content_type TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL, received_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL,
  body_len INTEGER NOT NULL, cert_hash BLOB NOT NULL,
  sealed BLOB NOT NULL,          -- DomainProtector(seal{ids, content_type, created, cert bytes, body})
  PRIMARY KEY(sender_device, message_id), UNIQUE(sender_device, app_id));
CREATE TABLE app_tombstones(
  sender_device BLOB NOT NULL, message_id BLOB NOT NULL, app_id BLOB NOT NULL,
  disposition TEXT NOT NULL CHECK(disposition IN ('done','rejected','expired','revoked','not_contact','blocked')),
  at_ms INTEGER NOT NULL, PRIMARY KEY(sender_device, message_id));
CREATE INDEX app_tombstones_app ON app_tombstones(sender_device, app_id);
CREATE TABLE app_outbox(
  peer_identity BLOB NOT NULL, client_ref TEXT NOT NULL, peer_device BLOB NOT NULL,
  content_type TEXT NOT NULL, app_id BLOB NOT NULL, body_sha256 BLOB NOT NULL,
  message_id BLOB NOT NULL UNIQUE, session_id BLOB NOT NULL, object_digest BLOB NOT NULL,
  created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('queued','sent','delivered','expired','failed','cancelled')),
  last_error_code TEXT NOT NULL DEFAULT '', attempt_seq INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(peer_identity, client_ref));
CREATE TABLE app_consumer(id INTEGER PRIMARY KEY CHECK(id = 1), consumer TEXT NOT NULL, bound_at_ms INTEGER NOT NULL);
CREATE TABLE app_pair_attempts(peer_device BLOB NOT NULL, at_ms INTEGER NOT NULL);
```

- **Outbox rows** carry no content. Their metadata is comparable to the session store's own clear outbox metadata.
- **Outbox state** is monotonic: `delivered` is final, the same rule as `chat_history::delivery_after`.
- **Outbox capacity:** at most 512 records. Final records are kept 8 days so `client_ref` stays idempotent. At the cap the oldest final record is evicted; a live record is never evicted, and the submit fails with `APP_STORE` instead.
- **Lock order:**
  - Sender: PeerSendLock → session-store transaction. The app store is written in the callback, after commit.
  - Receiver: session-store transaction → app store (read only, for admit). After commit: app store write.
  - Core outbox: history → app store.
  - The app store is never held across a dial or while taking another lock.
- **Crash consistency:**
  - Crash between seal commit and record insert: an orphan Prepared row, cleared by the next submit (§8.4).
  - Crash between commit and ingest: an endpoint row with a pending intent, ingested by the retry, the sweep or the archive (§7.3).
  - SQLite transactions protect each row write.

---

## 11. RDAP channel `raven`

### 11.1 Bound-home policy

A bound home is a **raven-only task plane**:

| Area | Bound-home behaviour |
|---|---|
| Sending (`ask`, `say` with mentions, `do`) | Only via raven |
| Receiving | Only the raven worker runs: no git relay `process_inbox`, no mesh drain (`ta/server.py:766-1016`), no JSON-RPC task route |
| HTTP | `/health`, `/raven/identity` (public) and `/raven/activity` stay; `POST /` answers 403 "this agent takes tasks over the raven channel only (ADR 0004 invariant 3)"; no Agent Card routes, because there is no card signing |
| `--via http\|relay`, `--experimental-plaintext-mailbox` | Refused: "this home is bound to raven-node; tasks travel only over the raven channel. Use an unbound home for HTTP, relay or mailbox tasks." |
| Unbound homes | Unchanged; `--via raven` errors: "bind this home to a raven-node first (rdap raven-bind --from-node …)" |

This removes every cross-channel concern on a bound home.

### 11.2 CLI

| Command | Change |
|---|---|
| `rdap trust raven:<rvn1>:<pub> --name bob --via raven` | Bound homes accept only the ash-pin form and record `channels:["raven"]`, the explicit opt-in (§5.5). The bound-home invite prints the pin and this exact command, but only when the local node reports `app_channel`. |
| `rdap ask "text" --name bob [--wait 90] [--ttl 4h] [--resend <task_id>]` | Raven only in bound homes. TTL defaults to 4 h, range 10 min to 24 h. |
| `rdap say` / `rdap do` | Mentions fan out one raven task per target. **No TeamChat post** of the text, notices or results. A `say` with no mention is ordinary team chat and prints "posted to team chat (git-synced; not part of the raven channel)". |
| `rdap replies` | Raven answers not yet shown, plus tasks that ended `undelivered`, `failed` or `lapsed`. Drains answers itself when the worker lock is free. |
| `rdap status` / `rdap doctor` | Row `channel: raven (atsam_rvn1, NON-RELEASE / HOLD)`, counts per state, node `pending` counts. Doctor checks Ping, the `app_channel` capability, the consumer binding, an AgentSign self-check (a statement to self is refused with `AGENT_SIGN_RECIPIENT_NOT_CONTACT` unless self is a contact; doctor accepts either answer as "reachable"), whether requests are waiting with no worker running, and which brain provider sees task text (§11.7). |
| `rdap raven-bind --from-node <dir> [--takeover]` | Writes the marker, retires the old seed (§4.4), binds the consumer (`AppInboxPage limit:0`, takeover if asked). |

### 11.3 `RavenChannelStore` (`ta/raven_channel.py`, `.team/keys/raven-channel.sqlite3`)

The file is 0600 in the 0700 keys directory, with `secure_delete=ON` and `synchronous=FULL`. Each table holds at most 512 rows; final rows are pruned after 7 days.

```sql
CREATE TABLE raven_tasks(        -- Alice side
  task_id TEXT PRIMARY KEY, peer_name TEXT, peer_address TEXT NOT NULL, peer_identity_hex TEXT NOT NULL,
  client_ref TEXT NOT NULL, rerequests INTEGER NOT NULL DEFAULT 0, node_message_id TEXT, node_state TEXT,
  state TEXT NOT NULL CHECK(state IN ('signed','queued','delivered','undelivered','answered','failed','cancelled','lapsed')),
  last_code TEXT, attempts INTEGER NOT NULL DEFAULT 0, next_try_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,   -- delegation expiry
  body TEXT, body_sha256 TEXT NOT NULL,                       -- exact signed request; NULL once final or after 7 d
  answer_state TEXT, answer_text TEXT, answer_sig_hash TEXT, answered_at INTEGER, shown INTEGER NOT NULL DEFAULT 0);
CREATE TABLE raven_answers(      -- Bob side
  sig_hash TEXT PRIMARY KEY,                                  -- replay_key(task signature) = ledger key
  task_id TEXT NOT NULL, peer_address TEXT NOT NULL, peer_identity_hex TEXT NOT NULL, request_sha256 TEXT NOT NULL,
  answer_state TEXT NOT NULL CHECK(answer_state IN ('completed','failed','rejected')), answer_text TEXT NOT NULL,
  signed INTEGER NOT NULL DEFAULT 0, attempt INTEGER NOT NULL DEFAULT 0, client_ref TEXT, body TEXT, body_expires_at INTEGER,
  node_message_id TEXT, node_state TEXT, next_try_at INTEGER NOT NULL DEFAULT 0, last_code TEXT,
  created_at INTEGER NOT NULL, deliver_until INTEGER NOT NULL, last_rerequest_at INTEGER NOT NULL DEFAULT 0);
```

### 11.4 Sender flow (Alice)

1. **Resolve the teammate.** It must carry `channels:["raven"]`; refuse addresses in `revocations_file`.
2. **Text checks.** Then `task_id = uuid4().hex` and `meta = sign_delegation(NodeIdentity, text, recipient, task_id, kind='task', ttl_seconds=ttl)`, which uses AgentSign and verifies locally.
3. **Build the body (§6.1).** If it is larger than 49024 bytes: `RAVEN_PAYLOAD_TOO_LARGE`, nothing stored.
4. **Insert the row** as `signed`, with `client_ref = "rdap-task:" + task_id`.
5. **`AppSubmit(ttl_ms = (expires_at - now) * 1000)`:**
   - Success → `queued` with the node message id.
   - Retryable code (§9.2) or `IPC_CONNECT` → stay `signed`, with backoff from 5 s to 300 s, ±20 %, until the delegation expires; then `lapsed`.
   - Fatal code → `failed(code)`.
6. **Retries of due `signed` and `undelivered` rows** run in the worker (§11.5) **and** at the start of every `rdap ask`, `replies` and `status`. Each pass is bounded to 10 s and skipped while `rdap start` holds the worker lock.
7. **Node status refresh** (`OutboxStatus`, every 5 s during `--wait`, every 30 s in the worker):
   - `delivered` → `delivered`.
   - `expired`, `failed(other)` or `cancelled` → `undelivered`.
   - A lineage failure → `failed`.
8. **`--wait N`:** poll every second. Drain answers if the worker lock is free. Print "delivered to bob's node" once.
   - Answer COMPLETED → print the verified text and exit 0.
   - FAILED or REJECTED → exit 1.
   - Deadline → exit 3 ("collect later: ./rdap replies").
9. **`--resend <tid>`:**
   - `undelivered`, delegation still valid → `AppSubmit(resend:true, same client_ref)`, so Bob's node deduplicates by `app_id`.
   - `delivered` (or `queued` for more than 10 min) with no answer → **re-request**: the same body under `client_ref = "rdap-task:<tid>:r<n>"`. Bob deduplicates by signature and re-sends or re-signs the cached answer (§11.5), even after the task delegation has expired.

### 11.5 Receiver worker (Bob)

**Threads.** Started in `_start_services` only in a bound home with `app_channel`. Two threads share `.team/keys/raven-channel-worker.lock`, an exclusive file lock held for the life of the process:

- `request-runner`: `page(a2a-request/1, limit=4, wait_ms=20000)`, handles each item, acks it.
- `answer-drainer`: `page(a2a-response/1, limit=8, wait_ms=10000)`; and every 10 s it retries due task submits, refreshes statuses and services `raven_answers`.

Items that `handle` returns `None` for stay unacked, with an in-memory per-item backoff from 5 s to 300 s.

`handle_request(item)`:

1. **Parse.** Strict JSON with duplicate keys refused, then profile checks. On failure: `'rejected'`.
2. **Transport binding.**
   - `meta.sender in peers` and `peers[meta.sender] == item.sender_identity_hex`, and `encode_address(item.sender_identity) == meta.sender`.
   - On failure: `'rejected'`, no reply, and the replay cache and ledger are never touched.
3. **Address deny.** A sender in `revoked` gets `'rejected'` and no reply.
4. **Duplicate or re-request.**
   - `sig_hash = replay_key(meta.signature)`.
   - If `raven_answers[sig_hash]` exists with the same `peer_identity_hex` **and** `request_sha256 == sha256(body)`, these are the exact bytes of a request already verified and handled. Call `service_answer(row, rerequest=True)` (at most once per 10 min per row), then return `'done'`.
   - This lookup runs before the expiry check, so a cached answer is never replaced by a REJECTED.
5. **Verify the delegation:** `verify_delegation(meta, text, peers, required=True, revoked, replay=ledger.replay_cache, expected_recipient=me, expected_task_id=id, expected_kind='task', consume_replay=False)`.
   - On failure from a transport-bound teammate: a best-effort signed REJECTED answer with `client_ref = "rdap-rej:" + item.message_id_hex`, at most 1 per sender per 60 s, untracked. Then `'rejected'`.
6. **Claim:** `state, reply = ledger.claim(signature, expires_at)`.

   | Claim state | Answer row inserted |
   |---|---|
   | `new` | Run the confidential brain (§11.7). Insert `completed` with `fit(answer)`, or `failed` with `"<ExceptionType>: <message>"` |
   | `interrupted` | `failed`: "execution was interrupted before a durable answer; not re-run" |
   | `completed` | From the cached reply: `reply['text']`, and `reply.get('state','completed')` |
   | `replayed` | `failed`: "already executed via another channel" |
   | `expired` | `rejected`: "expired before it could run" |

   - A `RuntimeError` (store full or unavailable) returns `None`: keep the item, fail closed.
   - Insert the `raven_answers` row with `signed=0`, then call `service_answer(row)`. Once it is signed, call `ledger.complete(signature, body_expires_at, reply_dict)`, where `reply_dict` has the relay shape (`ta/relay.py:404-421`) plus `state`, so a cached reply is portable.
   - Return `'done'`. From here the answer row owns delivery.

`service_answer(row, rerequest=False)`:

- **Sign if needed.** If `signed == 0`, or `body_expires_at - now < 10 min`, or this is a re-request with a delivered row: `attempt += 1`, then AgentSign a fresh answer delegation with `expires_at = now + 24 h` and the same text, build and fit the body, and **save** (`signed=1`, `attempt`, `client_ref = f"rdap-ans:{sig_hash[:32]}:{attempt}"`, `body`, `body_expires_at`) **before** submitting. AgentSign failures leave the row and retry later.
- **Submit.** If `node_message_id` is null, call `AppSubmit(client_ref, body, ttl = body_expires_at - now)`. If `node_state` is `expired`, `failed(other)` or `cancelled` and `now < deliver_until`, call `AppSubmit(resend=True)`.
- **Retry handling.**
  - Retryable codes, plus `NO_ROUTE`, `CONTACT_NOT_VERIFIED` and `LINK_NOT_ACCEPTED`: back off from 5 s to 30 min.
  - `NOT_A_CONTACT`, `CONTACT_BLOCKED`, `ATSAM_LINEAGE_REVOKED`: stop, keep the row, log the code.
- **Limits.** `deliver_until = created_at + 24 h`. After that only a re-request (step 4) restarts delivery. Rows are kept 7 days.

**Exactly-once (`ta/ledger.py` `TaskLedger`).**

- `GitRelay.claim_task` and the `RelayOutcomeStore` use (`ta/relay.py:103-284`) move into `TaskLedger(keys_dir)`, using the **same files**: `.team/keys/replay-cache.sqlite3` and `.team/keys/relay-outcomes.sqlite3`.
- `GitRelay` and the mesh drain delegate to it with unchanged behaviour (PY-7). The raven worker uses it.
- Brain execution is serialised by `raven-channel-worker.lock` (one request-runner).
- Cross-channel concurrency cannot occur (§11.1), so no extra lock is added.

| Hop | Idempotency key |
|---|---|
| Node send | `(peer_identity, client_ref)`; resend keeps `app_id` |
| Node receive | `(sender_device, message_id)` and `(sender_device, app_id)`, plus tombstones |
| RDAP execute | Delegation signature (ledger) |
| RDAP answer | `sig_hash` row in `raven_answers` |
| RDAP display | `raven_tasks.task_id` state plus `shown` |

### 11.6 Answer handling (Alice)

`handle_response(item)`:

1. Parse, then the transport binding as in §11.5 step 2. On failure: `'rejected'`.
2. `row = raven_tasks[id]` whose `peer_identity_hex == item.sender_identity_hex`. **If there is none: `'rejected'`, not stored** (count `unsolicited_answer`).
3. `verify_delegation(meta, text, peers, required=True, revoked, expected_recipient=me, expected_task_id=id, expected_kind='answer', consume_replay=False, now=item.received_at_ms // 1000)`.
   - **New parameter `now: int | None = None`** in `verify_delegation`. The default is `time.time()`; existing callers are unchanged.
   - An answer's freshness is judged at the node's authenticated receive time, so an answer that waits in Alice's node inbox while her RDAP is down still verifies.
   - Once-only comes from the task row: a second answer for an answered task is a duplicate.
4. If the row is already `answered`: `'done'`. Otherwise store `answered` (state from the A2A task state, text, sig hash, `answered_at`), then `'done'`. Answers are accepted for `lapsed` tasks too.

### 11.7 Confidential brain mode (fixes B1)

- **Protocol.** `Brain.run(task_text, *, cancel_event=None, confidential: bool = False)` (`ta/llm.py:32-36`). Only the raven worker passes `True`; the HTTP executor and relay are unchanged.
- **EchoBrain with `confidential=True`:**
  - No `.team/outputs` file, no `log_event`, no `set_task`.
  - Returns `f'[echo:{node}] completed task (raven channel: nothing written to the team repo). Task summary: {task_text[:120]}'`.
  - The mission prefix (read-only `_team_goal`) is unchanged.
- **OpenAIBrain with `confidential=True`:**
  - Uses `ConfidentialToolView(toolbox)`. `schemas()` returns only the read-only allow-list `{list_files, read_file, git_status, board_read, read_facts, final_answer}`, and `dispatch()` refuses every other tool with "ERROR: tool disabled for raven-channel tasks".
  - So `write_file`, `run_command`, `git_commit`, `board_set_task`, `log_event`, `remember_fact`, `claim_file` and `release_file` cannot run.
  - It is a per-run wrapper. The process-wide `ToolBox` is not mutated.
- **Worker hygiene.**
  - The raven worker never calls `TeamMemory.log_event`, `TeamChat.post`, `memory.sync`, `commit_team` or `_commit_push` for raven tasks.
  - Local stderr lines only: `raven✓ <task_id[:8]> from <addr[:14]>…` and `raven REJECT <task_id[:8]>: <fixed reason>`.
- **Provider disclosure.** A remote LLM provider still receives the task text: that is Bob's own agent policy, as on HTTP today. `rdap doctor`, `rdap status` and the worker start-up line state "brain <provider> at <host> sees raven task text". Whether to refuse remote providers is open question 3.

### 11.8 Server changes in a bound home (`ta/server.py`)

- **`build_app`:** builds `NodeIdentity` from `config.raven_bind`. The routes are `/health`, `/raven/identity`, `/raven/activity` and `POST /` → 403. There are no `create_agent_card_routes` and no `create_jsonrpc_routes`, so no card signing is ever needed.
- **`_start_services`:** in a bound home, skip the relay and mesh thread (`:766-1016`) and start `RavenChannelWorker`.

### 11.9 Failure and timeout UX

The raven channel never uses the word "confidential" while the HOLD stands. It uses only the D2.1 wording. `refuse_confidential_claim`, the M1 bind strings (`rdap.py:486`, `:2490`, `:2844`, `:2858`) and `ta/selftest.py:171` stay as they are.

| Outcome | Sentence (shortened) | Exit |
|---|---|---|
| `queued` / `sent` | "queued for bob via raven-node (atsam_rvn1, NON-RELEASE / HOLD); raven-node retries until HH:MM" | — |
| `sent` with no ACK for 2 min | "bob's node has not confirmed it yet; if bob's raven-node has no raven channel it never will" | — |
| `delivered` | "delivered to bob's node; waiting for bob's agent" | — |
| Answer COMPLETED | Answer text, "verified answer from bob via raven-node (atsam_rvn1, NON-RELEASE / HOLD)" | 0 |
| FAILED / REJECTED | "bob's agent could not run it: <signed reason>" | 1 |
| Wait deadline | "no answer yet after Ns; task <state>; collect later: ./rdap replies (task 3f2a…)" | 3 |
| `undelivered` | "not delivered before it expired at bob's node; resend while valid: ./rdap ask --resend 3f2a…" | 1 |
| `APP_PEER_UNREACHABLE` / `IPC_CONNECT` | "saved; retried while `rdap start` runs or on your next rdap command, until HH:MM" | 3 if waiting |
| `APP_PAIR_BUDGET` | "automatic pairing with bob is paused until HH:MM; the task is saved" | 3 if waiting |
| `NOT_A_CONTACT` / `AGENT_SIGN_RECIPIENT_NOT_CONTACT` | "bob is not a contact of your raven-node: raven contact add --address … --pub-hex … --verify-fp …" | 1 |
| `LINK_NOT_ACCEPTED` | "bob's node does not accept you; ask bob to add you as a raven contact" | 1 |
| `ATSAM_LINEAGE_REVOKED` | "device lineage revoked; nothing was sent" | 1 |
| `APP_CHANNEL_HOLD` | "the raven channel is not enabled in this build (APP_CHANNEL_HOLD); nothing was sent" | 1 |
| `APP_CONSUMER_BUSY` | "another RDAP home (rdap:9f2c…) is bound to this raven-node; move it here with: rdap raven-bind --from-node … --takeover" | 1 |
| `IPC_FRAME` (unknown op) | "raven-node is too old for the raven channel" | 1 |
| `RAVEN_PAYLOAD_TOO_LARGE` | "task too large for the raven channel (about 44 KiB maximum); nothing was sent" | 1 |

---

## 12. Failure matrix

| # | Scenario | Behaviour | Tests |
|---|---|---|---|
| 1 | Bob's node offline, session exists | `queued`; the worker delivers on backoff, `peer_seen` or `listener_up` | RN-3, C7b, LAB-S3 |
| 2 | Bob offline, no usable session | `APP_PEER_UNREACHABLE`; nothing sealed, no PairInit; RDAP retries until delegation expiry | RN-4, PY-9, LAB-S3 |
| 3 | Bob's RDAP down, node up | Node-level `delivered`; the item waits (up to 7 d); answered when the worker starts | LAB-S4 |
| 4 | Bob's inbox full (per sender and type, global, bytes) | Deferred before commit: no receipt, no intent; chat unaffected; delivered after space frees (at most one backoff slot) | CORE-5, RN-20, C7c |
| 5 | Ingest I/O failure after commit | No ACK; the endpoint row stays durable; retry, sweep or archive ingests it | CORE-6 |
| 6 | Hypothetical ACK sweep of pending intents | Payload still lands in the app inbox | CORE-6 |
| 7 | Alice's node restarts mid-flight | Worker rebuilds from the store; reconcile at preflight | RN-3, RN-19, C7b |
| 8 | Alice's daemon down across session expiry | Reconcile before prune: delivered or expired | RN-19 |
| 9 | RDAP client times out during `AppSubmit` | Retry with the same `client_ref` gives `duplicate`, same message id | RN-7c, PY-8 |
| 10 | ACK lost | Same bytes → `Duplicate` → ingest no-op → ACK; one item | CORE-9 |
| 11 | Bob's RDAP crashes during the brain run | `interrupted` → signed FAILED; the brain ran once | PY-12, LAB-S5 |
| 12 | AgentSign fails after the brain run | Result saved `signed=0`; signing retried; no `interrupted` | PY-12a |
| 13 | Bob's RDAP crashes after the answer row, before or after submit | Same row and `client_ref`; idempotent submit | PY-13 |
| 14 | Alice offline past the answer envelope | Bob resends, then re-signs, within 24 h; Alice's RDAP accepts at node receipt time | PY-14, PY-16, LAB-S12 |
| 15 | Alice re-requests after Bob's answer expired | Same body, new `client_ref`; Bob re-signs the cached answer | PY-15, LAB-S6 |
| 16 | Explicit resend after node `expired` | Same `app_id`; Bob's node deduplicates; ledger prevents re-run | RN-8, PY-15 |
| 17 | Session ends within 10 min | Pairs (budgeted), or `APP_PEER_UNREACHABLE` | RN-6 |
| 18 | PairInit responses lost repeatedly | Stops at 4 per 24 h with `APP_PAIR_BUDGET`; responder quota never reached | RN-5 |
| 19 | Crossed pairing | Both directions delivered | RN-10 |
| 20 | Contact removed or blocked after queueing | Worker `held(code)` until expiry; resend refused | RN-11, RN-8 |
| 21 | Contact blocked or lineage revoked after receipt, before paging | Item tombstoned `blocked`/`revoked`; never served | RN-15 |
| 22 | Bob not Alice's contact / Alice not Bob's | `NOT_A_CONTACT` / `LINK_NOT_ACCEPTED` (a Bob reached only through a relay: `APP_PEER_UNREACHABLE`, retried, §8.2) | RN-11, C7e |
| 23 | Revoked lineage | `ATSAM_LINEAGE_REVOKED`, `failed(PEER_REVOKED)`; never resendable; never a success | RN-12, LAB-S9 |
| 24 | RDAP address deny | No send; inbound rejected silently | PY-17 |
| 25 | Raven contact who is not a teammate | `'rejected'`, no reply | PY-18, LAB-S7 |
| 26 | Forwarded signed task (transport ≠ signer) | Rejected; replay cache untouched | PY-19 |
| 27 | Unsolicited answer | `'rejected'`, not stored | PY-18b |
| 28 | Receiver predates P0 | Shown as chat (residual); avoided by opt-in | doc |
| 29 | Gate closed at receiver | Deferred; sender `expired`; RDAP hint after 2 min | C7d |
| 30 | Gate closed at sender, or macOS before Q6 | `APP_CHANNEL_HOLD` | RN-13, LAB-S8 |
| 31 | Two RDAP homes on one node | `APP_CONSUMER_BUSY` until takeover, across restarts | RN-14, PY-20 |
| 32 | Long brain run while a second home polls | Second home is BUSY throughout; the brain runs once | RN-14, PY-20 |
| 33 | Daemon too old / down | `IPC_FRAME` → "too old" / `IPC_CONNECT` → saved and retried | PY-21, PY-22 |
| 34 | Malformed `RVNAPP/` or unregistered type | Deferred, never chat, never committed | CORE-3, CORE-4 |
| 35 | `raven send` with app objects queued | ash skips app rows; they are not counted toward the queue cap | ASH-3 |
| 36 | Orphan Prepared row (crash, or callback failure) | Cleared under the lock; `raven send` not broken | RN-18, ASH-3 |
| 37 | `raven outbox cancel <mid>` on an app object | `cancelled`; RDAP `undelivered` (resendable) | RN-17, ASH-6 |
| 38 | Corrupt or locked `app_channel.sqlite3` | App ops return `APP_STORE`; receive defers; chat paths unaffected | RN-22, CORE-8 |
| 39 | Tampered row (columns or blob swap) | Open fails; quarantined and counted | CORE-8 |
| 40 | Wall clock steps backwards | Worker `CLOCK` hold (existing); record untouched | RN-16 |
| 41 | Brain tries to write the repo during a raven task | Tool refused; repo unchanged | PY-25, PY-26, LAB-S1 |

---

## 13. Security analysis

- **Confidentiality.** The same ATSAM indexed-session seal as chat, with the waiver's known limits: no forward secrecy inside a 24 h session, no padding, and the outer signature names the sender to hops.
  - **Node at rest:** sealed rows under the chat-history key; metadata in the clear, comparable to the session store's own metadata.
  - **RDAP at rest:** `raven-channel.sqlite3` holds request bodies until the task is final or 7 days, and answer text for 7 days, in a 0600 file. That residual is question 5.
  - **No git leakage:** confidential brain mode plus worker hygiene, tested by PY-25, PY-26 and LAB S1.
- **Authentication and integrity.** Three layers: node (contact admission, session-bound certificate, AEAD, route tag), transport binding (Raven sender = delegation signer), and the RDAP delegation signature under the node identity.
- **Endpoint transaction conformance.** Application policy at step 7; a deferral commits nothing; ACKs only from committed intents and only after ingest; every committed app row is ingested by the ACK path, sweep or archive.
- **Replay and duplication.** ATSAM receipt deduplication; node `(sender, message_id)` and `(sender, app_id)` with tombstones; RDAP ledger and `raven_answers`; answer once-only by task row.
- **AgentSign.**
  - One typed context; the daemon builds the bytes.
  - It cannot produce a Raven-format signature: the prefix is refused by `Identity::verify` in release builds and asserted against in `Identity::sign`.
  - Recipient must be a contact; lifetime, skew and two rate buckets are bounded.
  - No decrypt, no key export, counts-only logging.
  - On macOS, gated until Q6.
- **G5.**
  - Lineage deny is enforced by the node at submit, in the worker and at page time (G5.2(5)), and lineage-failed records are never resent.
  - Address deny is enforced by RDAP.
  - Neither side edits the other's lists.
- **DoS.**
  - Inbox caps per sender per type, plus global caps.
  - Deferral before commit costs the receiver no state.
  - 16 in flight per peer; at most 4 automatic PairInits per peer per day.
  - REJECTED replies at most 1 per sender per minute.
  - Per-recipient answer bucket.
  - App failures never fail `dispatch_frame`, so chat is never blocked.
  - Deferral cost is bounded in §7.6.
- **Downgrade.** Bound homes never use HTTP, relay or mailbox for tasks. Status reports `atsam_rvn1` (D2.1).
- **Unchanged:** ATSAM profile, envelope, PairInit wire, prekey pins (`PEER_PREKEY_RESET`), carrier and link admission, route and mailbox tags, StoreObjectV1, bridge and forward queue (`EnqueueSealed` stays sealed-only), and the unsafe-interim lab body mode, which the app channel never uses.

---

## 14. Rollout and gates

| Phase | Contents | Gate | Exit |
|---|---|---|---|
| **P0: receivers app-safe** (3-4 d, **R3**) | Frame codec and vectors; `classify`; `accept_message_envelope_with_policy` plus `ApplicationDeferred` mapping (the policy defers every App/Reserved frame while the gate is closed); `ash inbox` and chat-poller filters; composer guard; orphan tolerance (§8.5); `live_pair_init_outbound_ready`, `first_pair_response` and `pair_over_dial` moved to core (ash refactored onto them); `Dialer` deadline parameter; spec note in `ATSAM_ENDPOINT_TRANSACTION_V1` §1; LAN waiver amendment (live receive change, `RVNAPP/` residual) | **Always on** | CORE-1..4, ASH-1..4 green; R3 acks |
| **P1: node app channel** (7-9 d) | `app_gate.rs`; `app_channel.sqlite3` and `DomainProtector`; `AppSubmit` (session ensure, budgeted daemon pairing); `AppInboxPage`/`AppInboxAck` (binding, long-poll, page-time re-check); ingest sweep, archive ingest, reconcile; worker and core bookkeeping edits; `OutboxStatus` kind `app`; `Status.app_channel`; ash outbox resolve and labels; lab commands; C7 | `APP_CHANNEL_PRODUCTION_ENABLED=false`; lab unlock | RN-*, C7 green |
| **P2: identity bridge** (3-4 d) | `AgentSign` plus the prefix chokepoints; RDAP `NodeIdentity`, `load_agent_identity`, bound marker, seed retirement, node-backed `sign_delegation`, `sign_http_request` refusal; bound-mode `build_app` and `cmd_start` | Same | CORE-11, RN-21, PY-1..6 |
| **P3: RDAP channel** (7-9 d) | `raven_ipc` ops; `raven_channel.py` (frames, store, sender, worker, answers); `ledger.py`; confidential brain mode; CLI; selftests; `node/scripts/o6_m4_rdap_raven_channel_lab.sh`; docs (RAVEN_APP_PAYLOAD_V1; error codes; ADR 0004 amendment covering D4 review of AppSubmit, AgentSign and AppInboxPage, D3 mechanism = AgentSign, bound homes raven-only, Q6 residual or decision, IPC v2 forerunners; RDAP `docs/rdap-raven-channel.md`; README integration-gap paragraph kept honest) | Same; RDAP feature labelled NON-RELEASE | LAB green; R3 acks recorded |
| **P4: owner flip** | `APP_CHANNEL_PRODUCTION_ENABLED=true`, LAN only while the other gates stay closed. macOS also needs `APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED=true` (Q6) or the code-identity tier. Physical two-device LAN evidence (`BLOCKED_HARDWARE` until then). **Done 2026-10**: switched on together with the carriers of the October 2026 field test (Internet direct, p2p, Tor), so the app channel plans every carrier a send plans, the Tor onion route included (raced as `raven send` races it, so a first session with a friend reachable only over Tor can be set up); Q6 accepted for macOS. RDAP over Raven proven on loopback over LAN and Tor; no physical two-device row yet | Owner GO (given) | Claims remain subordinate to the RVN1 HOLD |
| **Later** | Internet and p2p join automatically when their gates flip (verified contacts only, existing planner). Relayed carriers (mesh, mailbox) **must** call the same policy hook and `deliver_committed` with the session-bound certificate (CORE-13 is the conformance test) | Their own gates | — |

**Effort:** about 4.5 to 5.5 engineer-weeks plus review.

---

## 15. Test plan

### 15.1 Rust: `raven-core`

| ID | Test |
|---|---|
| CORE-1 | Codec: round trip; `shared-vectors/rvn1/app_payload` valid and negative; 49024/49025 body boundary; const assert; `app_body_text_ok` allows empty |
| CORE-2 | `classify`: chat; chat that merely contains `RVNAPP`; valid v1; `RVNAPP/2` and garbage → Reserved |
| CORE-3 | `accept_message_envelope_with_policy`: Defer leaves no receipt, no inbox row, `pending_endpoint_ack_intents()` empty, no generation change. Retrying the same bytes → `Committed`. Deferred index i, then chat i+1 accepted, then retry of i accepted via the skipped key |
| CORE-4 | `lan_dispatch` two-profile tests (pattern of `pair_init_message_ack_dispatch`): app frame → app inbox, not history, ACK returned. Chat unchanged. Reserved, unregistered type, `test/1` without lab, or gate closed → `Ok(vec![])`, no ACK, no history, no intent |
| CORE-5 | Caps: per sender per type, global, bytes → Defer. A sender's tasks fill its cap while its answers are still accepted. After an ack frees space, a retry is stored and ACKed. A chat frame in the same batch is ACKed |
| CORE-6 | Ingest failure after commit (failing protector) → `Ok(vec![])`, intent pending. Then (a) retry → Duplicate → ingest → ACK; (b) `ingest_pending_committed` ingests without a retry; (c) a simulated sweep that runs `enqueue_committed_ack` over every pending intent, followed by the sweep ingest, leaves the item in the app inbox |
| CORE-7 | Expiry archive ingests app rows (not into history) and skips tombstoned rows; an ingest error fails the prune before roots are destroyed |
| CORE-8 | App store: idempotence on `(sender, mid)` and `(sender, app_id)`; tombstones block re-adds; 7 d TTL → `expired` tombstone; page order, cursor and byte budget (first item always present); `pending` count; blob swap and column edit detected; corrupt DB → `APP_STORE`; body bytes absent from the DB file; `admit` reads no keystore |
| CORE-9 | Lost ACK: Duplicate ACKs without a second item; tombstoned → ACK without re-add |
| CORE-10 | `core/outbox.rs` order: stage, history row, app record. Orphan only when the stage is absent, `Ok(false)`, and no record. History `Err` propagates. App-store `Err` falls through to the chat error. Inbound ACK on an app record → delivered with no history file. Undelivered → expired, failed, cancelled |
| CORE-11 | `agent_sign`: bytes equal `shared-vectors/rdap/agent_sign/delegation_v2_*.json` (generated by RDAP `delegation_signing_bytes`); validation table; `Identity::verify` false for prefixed messages; `Identity::sign` debug-asserts; no `shared-vectors/rvn1/**` signing input starts with the prefix; `internet.rs` hello refuses the prefix |
| CORE-12 | IPC: round trip of 4 ops and 4 responses; key snapshots; forbidden-token scan on requests **and** responses; version; unknown op → `IPC_FRAME`; minimal requests decode with defaults |
| CORE-13 | `AppStore::ingest` takes a `DeviceCertificate` (no `LanBundle` overload); the dispatch path passes `session_bound_peer_certificate` |
| CORE-14 | `reconcile_app_outbound`: store says Delivered → delivered; else expired or failed(STORE) |

### 15.2 Rust: `raven-node`

Uses the rig at `rn/outbox.rs:2340-2670`. FakeNet gains:

- `close_on_err: AtomicBool`: stop the batch at the first `Err`, as a real link does (`rn/lan_direct.rs:370-379`).
- `drop_pair_response`.
- A `hang` mode.
- A deadline log.

| ID | Test |
|---|---|
| RN-1 | Happy path with a session: record queued → kick → delivered; Bob has an app item and no history row |
| RN-2 | No session: AppSubmit probes (bundle cached from the reply), pairs in the daemon, delivers; exactly 1 PairInit; budget = 1 |
| RN-3 | Bob down, then up: delivered without a new submit; worker restart rebuilds |
| RN-4 | No session and peer down: `APP_PEER_UNREACHABLE`; nothing sealed; no PairInit; budget unchanged |
| RN-5 | `drop_pair_response`: 4 PairInits, then a 5th refused with `APP_PAIR_BUDGET` with no dial, not even a probe; persists across restart; `peer_seen` does not reset it; responder claims ≤ 4 |
| RN-6 | Session with ≥ 10 min left → no PairInit; < 10 min → pairs |
| RN-7 | (a) Same ref and body → duplicate, same mid. (b) Different body → conflict. (c) The client drops before the response, then a retry → duplicate with the same mid. (d) Concurrent same ref → one seal |
| RN-8 | Resend after expired: same `app_id`, Bob stores one item. Resend after `failed(PEER_REVOKED)` → `ATSAM_LINEAGE_REVOKED`, nothing sealed. Resend to a now-blocked contact → `CONTACT_BLOCKED`, nothing sealed. Resend of a delivered record → duplicate |
| RN-9 | Expiry: record expired; `OutboxStatus` kind `app` |
| RN-10 | Crossed submits from both sides: both delivered |
| RN-11 | Admission codes; contact removed after queueing → held |
| RN-12 | Lineage revoked: `ATSAM_LINEAGE_REVOKED`, nothing sealed; revoked after queueing → `failed(PEER_REVOKED)` |
| RN-13 | Gate closed → `APP_CHANNEL_HOLD` for all ops and AgentSign; `cfg(target_os="macos")` without the lab unlock and without the Q6 const → HOLD |
| RN-14 | Binding: first page binds; second consumer BUSY, also after a daemon restart; takeover; ack requires the binding; a 90 s "brain" (no page or ack) while consumer B polls → B always BUSY; long-poll returns early on arrival and times out empty; `Ping` not blocked |
| RN-15 | Contact blocked, removed, or lineage revoked after receipt → the page serves nothing and tombstones with the right disposition; unreadable contacts → `CONTACTS_UNREADABLE`, items kept |
| RN-16 | Clock step backwards: `CLOCK` hold; record stays `queued` |
| RN-17 | `raven outbox cancel` → `cancelled` |
| RN-18 | Orphan Prepared row (injected failing callback) cleared by the next submit; failing callback → `APP_STORE` and the row abandoned; `raven send` not broken |
| RN-19 | Daemon stopped across session expiry → preflight reconcile marks expired (or delivered when an ACK was committed) before the prune |
| RN-20 | `close_on_err`: one dial carrying a deferred app frame then a chat frame → chat ACKed (proves a deferral never Errs) |
| RN-21 | AgentSign: verifies with the node key; non-contact, sender mismatch, lifetime > 24 h, skew all refused; an answer flood to one recipient leaves the task bucket untouched |
| RN-22 | Locked or corrupt `app_channel.sqlite3`: `raven send`, the worker chat give-ups and ACK bookkeeping all unchanged |
| RN-23 | Deadlines: `hang` mode → probe ≤ 10 s each, resolution + probes ≤ 30 s, PairInit ≤ 35 s, AppSubmit < 90 s; the worker passes 45 s |

### 15.3 ash

| ID | Test |
|---|---|
| ASH-1 | `ash inbox` hides app rows and prints the count |
| ASH-2 | Chat poller advances past app rows without printing or persisting |
| ASH-3 | `raven send` with queued app objects never dials or abandons them; they are not counted toward `MAX_QUEUED_PER_PEER`; an orphan row is given up and the send succeeds |
| ASH-4 | `raven send "RVNAPP/1 x"` is refused by `run_pair_init_and_send_routes` before anything starts, also via the chat composer path |
| ASH-5 | `raven outbox list` labels app rows |
| ASH-6 | `raven outbox status`, `retry` and `cancel <mid prefix>` resolve app objects; cancel prints the app label |

### 15.4 Multi-process harness: `rn/tests/carrier_matrix.rs` C7

`#[ignore]`, lab unlock, real `raven-node service` daemons, and the `raven` lab app commands.

| ID | Scenario |
|---|---|
| C7a | Two nodes on loopback, mutual contacts, **no prior session**: `app-submit` A→B pairs and delivers; B's `app-inbox --wait-ms` shows it; B's `raven inbox` does not; A's `raven outbox status <mid>` shows delivered, kind app |
| C7b | B down; A submits under a session (queued); A restarted, B up → delivered exactly once, no new submit |
| C7c | Fill B's per-sender cap for `test/1`, then A sends chat → chat delivered; the app object stays sent with no ACK; **each attempt's wall time ≤ 35 s**; ack an item on B, then `raven outbox retry` on A → delivered within a bounded wait |
| C7d | B without the lab unlock (gate closed): A's object is never delivered within a bounded wait; B's app inbox and chat history have nothing; per-attempt wall time ≤ 35 s |
| C7e | Stranger S submits to B → `LINK_NOT_ACCEPTED` |
| C7f | Beyond the LAN (RDAP addendum, 2026-10-16): **no prior session**, p2p with no relay; A's book holds a LAN and an Internet address for B (ports that close every connection at once) ahead of B's p2p route, B's book for A is p2p only. `app-submit` A→B probes both dead routes and pairs on p2p (A's log: `raven-node app: probe lan_dial <code>, internet_dial <code>, p2p_dial offer`) and is delivered on `p2p_dial`; B's answer has no probe (B holds the session) and rides A's connection (`p2p_dial`, `reversed`); neither body in `raven inbox`, no PeerId in a log. `scripts/lan_fault_matrix.py` s32b-s32e run RDAP's own `ask` the same ways (Internet direct only, a relay only, the answer reversed, this probe) |

### 15.5 RDAP Python selftest (`ta/selftest.py --unit`, mocked `transact` and the UDS mock daemon at `:419-470`)

| ID | Test |
|---|---|
| PY-1 | Request shapes and exact key sets for 4 ops; no forbidden tokens; error mapping with a retryable flag per code; timeouts (`app_submit` 90 s; page `wait/1000 + 10` s) |
| PY-2 | `NodeIdentity` delegation via a mocked AgentSign verifies under `verify_delegation`; signer mismatch fails closed; tampered bytes caught by local re-verification |
| PY-3 | Bound home: `ask`, `say`, `do`, `replies`, `start`, `python -m team_agents id/send` and `client.py` never create a seed (marker refusal); bind retires the old seed |
| PY-4 | `sign_http_request` raises for `NodeIdentity`; bound `build_app` has no card or JSON-RPC routes and `POST /` → 403 |
| PY-5 | Body builder: DEL and C1 escaped, lone surrogate refused, duplicate keys rejected, size limit, `fit_answer_to_frame` |
| PY-6 | Shared vectors: Python delegation bytes equal the Rust vector file; constants match |
| PY-7 | `TaskLedger` extraction: existing relay and mesh tests unchanged and green |
| PY-8 | Sender crash points (before submit, after submit before recording) → idempotent resubmit; client timeout → duplicate |
| PY-9 | Retryable codes, backoff, delegation-expiry cut-off (`lapsed`); retries also run from `ask`, `replies` and `status` |
| PY-10 | `--wait`: answered → 0; deadline → 3; fatal → 1 |
| PY-11 | Worker happy path: request → brain → answer row → signed → submitted → ack |
| PY-12 | `processing` left behind → `interrupted` signed FAILED; brain not called |
| PY-12a | AgentSign fails after the brain run → row `signed=0`; next pass signs and submits; brain ran once |
| PY-13 | Crash after the row and before or after submit → same `client_ref` and body |
| PY-14 | Answer node `expired` → resend; body delegation under 10 min → re-sign with attempt+1; `NO_ROUTE` and `LINK_NOT_ACCEPTED` keep retrying; stop after `deliver_until` |
| PY-15 | Re-request (new `client_ref`, same body) with an expired task delegation → cached answer re-signed and sent; brain runs once; at most one re-request per 10 min |
| PY-16 | Answer received by the node before expiry and processed after (mocked clock) → accepted (`now=received_at`); received after expiry → rejected |
| PY-17 | Address deny: no send; inbound rejected with no reply |
| PY-18 | Unknown sender: no reply, `rejected` |
| PY-18b | Unsolicited answer (unknown `task_id` or another peer's task) → `rejected`, not stored |
| PY-19 | Transport and delegation mismatch → rejected; replay cache and ledger untouched |
| PY-20 | `APP_CONSUMER_BUSY` message; takeover flag |
| PY-21 | Old daemon (`IPC_FRAME`) |
| PY-22 | Daemon down (`IPC_CONNECT`): task saved, retried later |
| PY-23 | REJECTED rate limit: 10 bad tasks from one teammate in a minute → 1 reply |
| PY-24 | Bound home refuses `--via http`, `--via relay` and the mailbox; unbound home refuses `--via raven` |
| PY-25 | Confidential mode: EchoBrain writes nothing under `TEAM_SHARED_PATHS`; OpenAIBrain view exposes only the read-only tools and refuses the others |
| PY-26 | End to end with mocks: a raven task and answer leave `git status --porcelain` empty, and the marker text appears in no file under `.team/` outside `.team/keys/` |

### 15.6 Two-process lab: `node/scripts/o6_m4_rdap_raven_channel_lab.sh`

Style of `o6_m3`: NON-RELEASE banner, locked-file backends, `RAVEN_LAB_TEST_A=1`, one bring-up retry, `WALL_CLOCK_SEC`, public logs only.

Setup:

- `ash init` A and B, mutual `contact add`.
- Two RDAP homes, each `rdap raven-bind --from-node`.
- `rdap trust <pin> --via raven`.
- B runs `rdap start --provider echo`.

| Scenario | Check |
|---|---|
| S1 GREEN | `rdap ask --name bob --wait 60 "RAVEN_A2A_OK_M4"` exits 0 with the echoed marker and `atsam_rvn1`. There was no prior `ash send`, so `AppSubmit` paired. **Not anywhere else:** B's `ash inbox`, B's chat history, both repos' `git log -p` and `git status --porcelain`, both TeamMemory/TeamChat files, and B's `.team/outputs` contain no marker. A's outbox status is delivered, kind app |
| S3 | B's node down: exit 3; start B → `rdap replies` shows the answer with no new ask |
| S4 | B's RDAP down: node-level delivered; start RDAP → answered |
| S5 | `kill -9` B's RDAP mid-brain (`RDAP_LAB_BRAIN_DELAY=5`, honoured only under `RDAP_SELFTEST=1`); restart → A gets a signed "interrupted" failure; the brain ran once |
| S6 | `rdap ask --resend <tid>` on a delivered task → re-request; no second run; the answer is shown once |
| S7 RED | Carol is a contact of B but not a teammate → no answer, exit 3, B logs a reject |
| S8 RED | A without the lab unlock → `APP_CHANNEL_HOLD`, nothing queued |
| S9 RED | Lineage revoked on A for B → `ATSAM_LINEAGE_REVOKED`, no success |
| S10 | `rdap status` shows `atsam_rvn1 (NON-RELEASE / HOLD)` |
| S11 | No seed in either bound home; retired seed present in `.team/keys/retired/` |
| S12 | A's node down when B's answer is ready → B's worker keeps it queued; A's node up → A's `rdap replies` shows it |
| S13 | Second RDAP home bound to B's node → `APP_CONSUMER_BUSY`; `--takeover` moves it |

CI:

- Run C7 and the PY tests in the existing workflows.
- The lab script runs manually or nightly, like `o6_m3`.
- Extend the `scripts/o6_try_phase_gap_check.sh` inventory with the script and its evidence document.

---

## 16. Change list

**Raven:**

| File | Change |
|---|---|
| `core/app_channel.rs` (new) | Codec, `classify`, `app_body_text_ok`, `AppStore` (admit, ingest, page, ack, dedup, outbound records, reconcile, pair budget, consumer binding), `GENERATION`, `ingest_pending_committed`, `reconcile_app_outbound` |
| `core/app_gate.rs` (new) | Gate constants and content-type registry |
| `core/agent_sign.rs` (new) | Statement, validation, `AGENT_DELEGATION_PREFIX`, `AgentDelegationBytes` |
| `core/identity.rs` | `sign_agent_delegation` (crate-private), `sign` debug-assert, `verify` prefix refusal |
| `core/internet.rs` | Hello verify prefix refusal |
| `core/indexed_session_store.rs` | `accept_message_envelope_with_policy`, `InboundPolicy`, `ApplicationDeferred` |
| `core/lan_dispatch.rs` | Policy closure, `deliver_committed`, archive ingest, sweep and reconcile in maintain/prune |
| `core/chat_history.rs` | `DomainProtector` |
| `core/outbox.rs` | Stage→history→app order, orphan rule, `finish_app_outbound_delivered` |
| `core/pair_init_lan_oob.rs` | `live_pair_init_outbound_ready`, `first_pair_response`, `pair_over_dial` |
| `core/ipc.rs` | Ops and responses, response forbidden-key scan |
| `core/lib.rs` | Exports |
| `rn/app_channel.rs` (new) | `app_submit`, session ensure, page/ack (async long-poll), AgentSign with buckets |
| `rn/ipc_server.rs` (+ Windows dispatch) | Dispatch, Status capability |
| `rn/outbox.rs` | `Dialer` deadline, `LocalBodies`, history skip, `finalize_vanished`, kind app, `status_anywhere`, `attempt_ctx`, reconcile at start, FakeNet modes and tests |
| `ash/pair_init_lab.rs` | Use core pairing; skip app rows; exclude them from the cap; composer guard |
| `ash/trace_delivery.rs` | Re-export the gate |
| `ash/ext.rs` | Composer pre-check, chat-poll filter, `resolve_outbox_mid`, labels |
| `ash/cli.rs` | Inbox filter, lab app commands |
| `rn/tests/carrier_matrix.rs` | C7 |
| `node/scripts/o6_m4_rdap_raven_channel_lab.sh` (new) | Lab script |
| `scripts/lib/o6_ipc_guard.sh` | Allow-list and self-test |
| `protocol/RAVEN_APP_PAYLOAD_V1.md` (new) | Frame spec |
| `protocol/ATSAM_ENDPOINT_TRANSACTION_V1.md` | Step-7 deferral note |
| `protocol/RAVEN_ERROR_CODES_V1.md`, `PROTOCOL_VERSIONS.md` | Codes and draft listing |
| `shared-vectors/rvn1/app_payload/*`, `shared-vectors/rdap/agent_sign/*` (new) | Vectors |
| `docs/adr/0004-…` amendment, `docs/WAIVER_LAN_DIRECT_*` amendment, O6 board | Docs |

**RDAP:**

| File | Change |
|---|---|
| `ta/raven_ipc.py` | `app_submit`, `app_inbox_page`, `app_inbox_ack`, `agent_sign`, `outbox_status`, `status` |
| `ta/node_identity.py` (new) | `NodeIdentity`, `load_agent_identity` |
| `ta/raven_identity.py` | Marker refusal in `load_or_create`; node-backed `sign_delegation`; `sign_http_request` refusal; `verify_delegation(now=…)` |
| `ta/ledger.py` (new) | `TaskLedger` |
| `ta/relay.py` | Use the ledger |
| `ta/raven_channel.py` (new) | Frames, store, sender, worker, answers |
| `ta/llm.py` | `confidential` mode |
| `ta/tools.py` | `ConfidentialToolView` |
| `ta/server.py` | Bound `build_app`, `_start_services`, 403 |
| `ta/config.py` | `NodeConfig.raven_bind` |
| `rdap.py` | `cmd_start`, `cmd_ask`, `cmd_say`, `cmd_do`, `cmd_replies`, `cmd_trust`, `cmd_raven_bind`, `cmd_status`, `cmd_doctor`, `ensure_keys` |
| `ta/selftest.py` | PY tests |
| `docs/rdap-raven-channel.md` (new), `README.md` | Docs |

---

## 17. Non-goals

- **No crypto or wire changes:** no new crypto of any kind, and no change to ATSAM, the envelope, the PairInit wire, prekey or pin rules, route or mailbox tags, StoreObjectV1, carrier or link admission, the bridge, forward queue or message router.
- **No release claims:**
  - No lifting of the RVN1 HOLD, and no production or Release confidentiality claim; the channel is NON-RELEASE until P4 and stays subordinate to the HOLD.
  - No opening of the Internet or p2p gates, and no WAN claim.
  - No use of the word "confidential" in raven-channel UX while the HOLD stands.
- **Out-of-scope features:**
  - Payloads over about 48 KiB (no chunking or attachments), and size padding.
  - Multi-device fan-out.
  - Streaming or intermediate A2A status, A2A cancel over raven, `GetTask`.
  - A node-side pre-seal queue (RDAP retries `AppSubmit`).
  - Automatic node re-seal after `expired` (owner Q4); resends are explicit app-level calls.
  - Proactive re-pair.
- **Identity and IPC follow-ons not done here:** a distinct `USER_AGENT_DEVICE` credential; the macOS code-identity tier and IPC v2; signed capability negotiation.
- **Bound-home restrictions:**
  - HTTP, git relay and mailbox task paths in bound homes, including tasks from unbound teammates (question 2).
  - Agent Card signing in bound homes.
  - Brain write or shell tools for raven tasks (question 9).
- **Left alone:** `SealUnderSession` itself (it stays a lab op, superseded by `AppSubmit`); public or stranger surfaces of any kind.

---

## 18. Open questions

The same list is returned in `open_questions`.


## Open questions

- macOS (daemon-owned-secrets Q6): **decided 2026-10-29**: AppInboxPage and AgentSign are accepted as UID-only on macOS as a documented residual (`APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED = true`, A9, `docs/THREAT_MODEL.md` §3.16); the code-identity IPC tier remains future work.
- Bound homes are raven-only for tasks: no HTTP, git relay or mailbox, for sending or receiving. That means a bound agent cannot exchange tasks with unbound teammates. Is that acceptable, or should bound homes keep accepting signed tasks from unbound teammates, labelled NOT CONFIDENTIAL? (That would bring back the HTTP and relay signing contexts.)
- Remote LLM providers: in confidential mode, Bob's brain still sends Alice's task text to a remote provider (OpenAI, Groq and so on). Is allowing that with a doctor/status warning the right default, or should the raven worker refuse raven tasks unless the brain is local (echo, or ollama on loopback)?
- Defaults to confirm: task TTL 4 h (range 10 min to 24 h); answer TTL and delivery window 24 h; app inbox item TTL 7 d; automatic pairing budget 4 PairInits per peer per 24 h; inbox caps 16 per sender per content type, 128 items and 4 MiB in total; 16 app objects in flight per peer.
- RDAP at rest: raven-channel.sqlite3 keeps request bodies until the task is final (at most 7 d) and answer text for up to 7 d. It is a 0600 file in the 0700 keys directory, not protected by the keystore. Accept that residual, or add a later node-provided key (which needs a new IPC op)?
- P0 changes live LAN receive behaviour in default builds: chat whose text starts with 'RVNAPP/' from a pre-P0 sender is never ACKed and ends 'expired' at the sender. Confirm that handling it through R3 review plus the LAN waiver amendment is enough.
- Old RDAP seed at bind: is moving it to .team/keys/retired/ and printing its address (so teammates can remove or deny it) acceptable, or should the seed stay where it is, unread?
- A receiver running a node older than P0 shows app frames as chat text. The only guard is the explicit 'rdap trust ... --via raven' opt-in, because there is no signed capability registry. Accept this residual until RAVEN_CAPABILITIES_V1 exists?
- Confidential mode turns off every write and shell tool for raven tasks. Should a later owner-approved opt-in allow writes to a non-synced work directory, for example .team/keys/raven-work/?
