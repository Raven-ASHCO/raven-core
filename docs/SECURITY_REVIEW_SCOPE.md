# Security review scope

A package for an independent reviewer of Raven's protocol and code. **No independent review has
happened yet.** An internal review was done in October 2026, and its findings were fixed in
version 0.1.0; it is not a substitute for an independent review, and this page does not depend on
it. This page lists what to review first, where the specs and the code are, what is already known
and published, how to build and test, and what is out of scope. If you are interested in reviewing
Raven, write to security@raven-messager.com.

Good primitives are not a secure system. The questions that matter are how they are put together:
session establishment, key storage, identity verification, recovery, replay handling and the
implementation. The list below starts with what every message depends on, then what protects keys
and identities, then the carriers and features switched on in October 2026.

## 1. What runs in a release build today

Release builds (version 0.1.0) have **direct messaging between two computers on the same local
network**, under a recorded exception to the project's own release rules
([WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md)).
Its exact surface:

- LAN TCP between two `raven-node` services: Noise `XX_25519_ChaChaPoly_BLAKE2s` with the Noise
  static key bound to the Raven identity, then the RLB1 offer;
- session set-up: PairInit V1 / PairResponse, suite 1 (X25519 + ML-KEM-768 + HKDF-SHA-256 +
  Ed25519), accepted only from local contacts;
- the session profile `ATSAM/indexed-session/v1`: RVNA1 `0x03` messages and sealed ACKs;
- key storage in the operating system's keystore, the at-rest sealing of the profile, the contact
  book with pinning and security words, and the local IPC endpoint (Unix socket or Windows named
  pipe) that the command line and the desktop apps use.

Since October 2026 they also have the features the three-machine
[field test](FIELD_TEST_2026_10.md) exercised, switched on by the owner **before** any independent
review ([ROADMAP.md](ROADMAP.md)): Internet direct, the libp2p carrier with hole punching (DCUtR)
and relays run by friends, router port mapping and IPv6 pinholes, public address discovery over
STUN and serverless hole punching, route hints, the Tor onion carrier (Arti in a helper process),
friend custody over the local network and the internet, the 7-day message horizon, groups,
Bluetooth nearby on macOS only, and the app channel for RDAP with AgentSign (UID-only IPC on macOS
too, an accepted residual: [THREAT_MODEL.md](THREAT_MODEL.md) §3.16). Listening for Internet
direct and libp2p, port mapping, relaying, keeping mail and Bluetooth each stay off until the user
turns them on. Two changes made for this release are worth checking against their specs: a contact
card carries and gives no unsigned route (no Internet address, PeerId or relay;
[RAVEN_ROUTE_HINTS_V1](../protocol/RAVEN_ROUTE_HINTS_V1.md) §9.1), and the app channel's receiver
guard ([RAVEN_APP_PAYLOAD_V1](../protocol/RAVEN_APP_PAYLOAD_V1.md) §3.1).

Everything else (sealed letters, custody handoff, relays over WSS and HTTPS proxies, PeerId
rotation, the LAN beacon, learning connectivity, the Phase 6b security features, session reset and
renewal, the hybrid ratchet) is compiled in but held off by `*_PRODUCTION_ENABLED = false` gates; a
release build never reads the `RAVEN_LAB_*` switches that open them in debug builds. CI checks this
(the "lab switches inert in release" and "production flags as pinned" steps).

## 2. Components, in priority order

| # | Component | In release builds? | Specs | Code (`node/crates/...`) |
|---|---|---|---|---|
| 1 | **Hybrid handshake**: PairInit V1, X25519 + ML-KEM-768, the signed transcript and the KDF combiner, prekeys | yes (every carrier) | [RAVEN_PAIR_INIT_V1](../protocol/RAVEN_PAIR_INIT_V1.md), [ATSAM_PRIMITIVE_MAPPING_V1](../protocol/ATSAM_PRIMITIVE_MAPPING_V1.md), [RAVEN_PREKEY_BUNDLE_V1](../protocol/RAVEN_PREKEY_BUNDLE_V1.md), [RAVEN_PREKEY_LIFECYCLE_V1](../protocol/RAVEN_PREKEY_LIFECYCLE_V1.md), [ATSAM_THREAT_ASSUMPTIONS_V1](crypto/ATSAM_THREAT_ASSUMPTIONS_V1.md), [ATSAM_KAT_CONSUMER_MATRIX_V1](crypto/ATSAM_KAT_CONSUMER_MATRIX_V1.md) | `raven-core/src/pair_init.rs`, `atsam_root.rs` (combiner), `atsam_mlkem.rs`, `prekey_bundle.rs`, `prekey_lifecycle.rs`, `pair_init_lan_oob.rs`; lab: `mlkem768_incremental.rs`, `raven-mlkem768-incremental-ffi/` |
| 2 | **Session**: the live indexed-session profile, and the hybrid ratchet (lab) | profile yes; ratchet no | [ATSAM_INDEXED_SESSION_PROFILE_V1](../protocol/ATSAM_INDEXED_SESSION_PROFILE_V1.md), [ATSAM_ENDPOINT_TRANSACTION_V1](../protocol/ATSAM_ENDPOINT_TRANSACTION_V1.md), [ATSAM_HYBRID_RATCHET_V2](../protocol/ATSAM_HYBRID_RATCHET_V2.md), design [ratchet FS/PCS](design/2026-10-ratchet-fs-pcs.md) | `raven-core/src/atsam_indexed_session.rs`, `indexed_session_store.rs`, `lan_dispatch.rs`, `atsam_kdf.rs`; lab: `hybrid_ratchet_v2*.rs`, `hybrid_ratchet_v2_full_braid/`, `full_braid_durable_lab/` (no caller outside tests) |
| 3 | **Envelope and AEAD**: RVN1 envelope, RVNA1 bodies, ACKs, store objects, routing tags | yes | [SPEC.md](../protocol/SPEC.md), [RAVEN_ENVELOPE_V1](../protocol/RAVEN_ENVELOPE_V1.md), [RAVEN_ACK_V1](../protocol/RAVEN_ACK_V1.md), [RAVEN_STORE_OBJECT_V1](../protocol/RAVEN_STORE_OBJECT_V1.md), [RAVEN_ROUTING_TAG_V1](../protocol/RAVEN_ROUTING_TAG_V1.md) | `raven-core/src/envelope.rs`, `ack.rs`, `seal.rs`, `atsam_aead.rs`, `store_object.rs`, `routing_tag.rs`, `canon.rs` |
| 4 | **Replay handling** and the endpoint transaction: dedup, ACK freshness, owed ACKs, crash recovery, relay replay caches | yes | errata rules 4-7 ([SECURITY_ERRATA_RVN1_2026-08-13](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md)), [ATSAM_ENDPOINT_TRANSACTION_V1](../protocol/ATSAM_ENDPOINT_TRANSACTION_V1.md), [THREAT_MODEL](THREAT_MODEL.md) §3.10 | `raven-core/src/indexed_session_store.rs`, `owed_acks.rs`, `arrivals.rs`, `relayed_ingest.rs`, `forward_queue.rs`, `queue.rs`, `clock_skew.rs`, `carrier_admission.rs`; `raven-core/tests/adversarial_atsam.rs` |
| 5 | **At-rest encryption and key storage per OS**: macOS Keychain, Windows DPAPI, Linux Secret Service or a passphrase vault (Argon2id + XChaCha20-Poly1305), the sealed profile metadata, erase | yes | [IDENTITY_SEED_STORAGE.md](IDENTITY_SEED_STORAGE.md), designs [at-rest metadata](design/2026-10-at-rest-metadata.md), [Linux keystore](design/2026-10-linux-keystore.md), [daemon-owned secrets](design/2026-10-daemon-owned-secrets.md), [THREAT_MODEL](THREAT_MODEL.md) §3.6-§3.7a | `raven-core/src/identity_store.rs`, `keystore_select.rs`, `keystore_vault.rs`, `macos_keychain.rs`, `win_acl.rs`, `at_rest.rs`, `privacy.rs`, `chat_history.rs`, `erase.rs`; `raven-node/src/at_rest_boot.rs`; `node/third_party/secret-service-2.0.2-raven-noprompt/`; lab (Lock v2): `local_lock.rs`, `raven_passphrase.rs` |
| 6 | **Identity, fingerprint, security words, pairing**: the address, pinning, the key-change refusal, the LAN Noise binding | yes | [RAVEN_IDENTITY_V1](../protocol/RAVEN_IDENTITY_V1.md), [RAVEN_ADDRESS_V1](../protocol/RAVEN_ADDRESS_V1.md), [RAVEN_SECURITY_WORDS_V1](../protocol/RAVEN_SECURITY_WORDS_V1.md), [SECURITY_WORDS.md](SECURITY_WORDS.md), [RAVEN_IDENTITY_CONTINUITY_V2](../protocol/RAVEN_IDENTITY_CONTINUITY_V2.md) (not approved), [ADR 0003](adr/0003-wire-crypto-identity-bridge-ipc.md) | `raven-core/src/identity.rs`, `address.rs`, `fingerprint.rs`, `security_words.rs`, `contact_book.rs`, `lan_noise.rs`, `lan_rlb1.rs`; `ash/src/cli.rs` (contact add and verify); lab: `lan_noise_pin.rs` |
| 7 | **Device revocation and recovery**: device certificates, revocation records, session reset, lost-state recovery | certificates yes; reset and recovery no | [RAVEN_DEVICE_REVOCATION_V1](../protocol/RAVEN_DEVICE_REVOCATION_V1.md), [RAVEN_SESSION_RESET_V1](../protocol/RAVEN_SESSION_RESET_V1.md), [MULTI_DEVICE_PARTITION_REVOCATION.md](MULTI_DEVICE_PARTITION_REVOCATION.md), designs [lost-state recovery](design/2026-10-lost-state-recovery.md), [per-device keys](design/2026-10-per-device-keys.md), [suite retirement](design/2026-10-suite-retirement.md) | `raven-core/src/device_cert.rs`, `device_revocation.rs`, `device_sync.rs`; lab: `session_reset.rs`, `session_renewal.rs` |
| 8 | **Friend custody** (a friend keeps sealed mail), letters, custody handoff | custody yes (since October 2026, opt-in); letters and handoff no | [RAVEN_FRIEND_CUSTODY_V1](../protocol/RAVEN_FRIEND_CUSTODY_V1.md), [RAVEN_CUSTODY_HANDOFF_V1](../protocol/RAVEN_CUSTODY_HANDOFF_V1.md), [RAVEN_ASYNC_LETTER_V1](../protocol/RAVEN_ASYNC_LETTER_V1.md), design [friend custody](design/2026-10-friend-custody.md), [errata rule 9 amendment draft](SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md), [WAIVER_FRIEND_CUSTODY_DRAFT.md](WAIVER_FRIEND_CUSTODY_DRAFT.md) | `raven-core/src/friend_custody.rs`, `friend_custody/`, `custody_client.rs`, `custody_home.rs`, `custody_handoff.rs`, `custody_gate.rs`, `carrier_admission.rs`, `async_letter.rs`; `raven-node/src/custody.rs`, `letters.rs` |
| 9 | **Tor onion carrier**: the signed onion binding, the Raven link over Tor (its own Noise static), the helper process and its local protocol, the race | yes (since October 2026) | [RAVEN_ONION_CARRIER_V1](../protocol/RAVEN_ONION_CARRIER_V1.md), design [Tor fallback](design/2026-10-tor-fallback.md) | `raven-core/src/onion.rs`, `onion_gate.rs`; `raven-node/src/onion/`, `raven-node/src/bin/raven-tor-helper/`; `node/third_party/saturating-time-0.5.0-raven/` |
| 10 | **Reaching friends on other networks**: Internet direct, the libp2p carrier and friend relays, hole punching, STUN discovery, port mapping, route hints, the card format | yes (since October 2026; listening opt-in) | [RAVEN_ROUTE_HINTS_V1](../protocol/RAVEN_ROUTE_HINTS_V1.md) (§9.1 for cards), [RAVEN_NAT_CONNECTIVITY_V1](../protocol/RAVEN_NAT_CONNECTIVITY_V1.md), [RAVEN_PORT_MAPPING_V1](../protocol/RAVEN_PORT_MAPPING_V1.md), design [auto-reach](design/2026-10-auto-reach.md), [WAIVER_INTERNET_DIRECT_DRAFT.md](WAIVER_INTERNET_DIRECT_DRAFT.md), [WAIVER_P2P_RELAY_DRAFT.md](WAIVER_P2P_RELAY_DRAFT.md) | `raven-node/src/internet_direct.rs`, `p2p.rs`, `friend_relay.rs`, `hints.rs`, `outbox.rs`; `raven-core/src/route_hints.rs`, `stun.rs`, `portmap*.rs`, `outbox.rs` (the planner and the local-network rule); `raven-swarm/`; `ash/src/cli.rs` (cards) |
| 11 | **App channel and AgentSign** (RDAP over Raven): the app frame, the receiver guard, the app store, the IPC ops and the delegation signing chokepoint | yes (since October 2026) | [RAVEN_APP_PAYLOAD_V1](../protocol/RAVEN_APP_PAYLOAD_V1.md), design [app channel](design/2026-10-rdap-app-channel.md), [THREAT_MODEL](THREAT_MODEL.md) §3.16 | `raven-core/src/app_channel.rs`, `app_store.rs`, `agent_sign.rs`, `identity.rs`; `raven-node/src/app_channel.rs`, `ipc_server.rs` |
| 12 | **Groups** and **Bluetooth nearby** (macOS) | yes (since October 2026; nearby opt-in) | [RAVEN_GROUP_V1](../protocol/RAVEN_GROUP_V1.md), [RAVEN_NEARBY_LINK_V1](../protocol/RAVEN_NEARBY_LINK_V1.md) | `raven-core/src/group.rs`, `group/`; `raven-node/src/nearby/`, `raven-node/src/bin/raven-nearby-helper/` |

Also reachable by a peer or another local process, and worth a look with each component: the LAN
listener (`raven-node/src/lan_direct.rs`), the IPC servers (`raven-node/src/ipc_server.rs`,
`ipc_server_windows.rs`, `raven-core/src/ipc.rs`), and every decoder in the fuzz list
([EVIDENCE.md](EVIDENCE.md) §3).

### Questions we would most like answered

1. **Combiner and transcript.** The root is `HKDF-SHA-256(ikm = Z_X || Z_PQ, salt = transcript_hash,
   info = "ATSAM/v1/pair-init" || transcript_hash)` (`atsam_root.rs`), and the transcript hash covers
   the complete signed PairInit wire, ML-KEM ciphertext included
   ([RAVEN_PAIR_INIT_V1](../protocol/RAVEN_PAIR_INIT_V1.md)). Does the code match the spec byte for
   byte, does the transcript bind everything the errata list (identities and devices, both X25519
   keys, both ML-KEM contributions, the suite and the roles), and does the session stay secure if
   either X25519 or ML-KEM-768 holds?
2. **The live session has no ratchet.** Every key of a session is derived from a root kept for the
   session's life (24 hours for sessions this code starts, up to 7 days accepted from older peers).
   Is the stated exposure accurate, and is anything worse than stated?
3. **Endpoint acceptance.** Is the order "strict decode, then authenticate, then AEAD open, then one
   atomic commit, then the ACK" kept on every path, including restarts and storage failures? Can a
   message or an ACK be accepted twice, or an ACK be forged or replayed into a delivery state?
4. **Nonces.** Random 96-bit ChaCha20-Poly1305 nonces, unique per session (enforced in storage),
   index reserved before network handoff. Any path to reuse?
5. **Key storage.** Do the per-OS backends fail closed? What can another local user or process
   read? Does the debug-only `locked-file` backend stay unreachable in release builds?
6. **Security words.** 72 bits from a labelled hash of the key; is the comparison flow safe against
   a man in the middle who can choose keys?
7. **Custody and Tor**: what does a malicious keeper, a malicious Tor relay or a malicious
   friend learn or break beyond what the specs state?
8. **Addresses.** Can anything a stranger or an unverified contact controls (a card field, a
   route hint, a STUN answer, a relay) make a node dial, or reveal its IP address to, a host its
   user did not choose? Release cards carry no unsigned route (§9.1 of the route hints spec).
9. **App channel.** Can a contact get an app payload stored or acted on outside the guard (not
   verified, an unregistered type, over the limits), or obtain a delegation signature that verifies
   as a Raven signature, or the reverse?

## 3. Threat model and what is already known

Read these first. They are public and list the known weaknesses; please do not report them again
unless you find something worse than written.

- [THREAT_MODEL.md](THREAT_MODEL.md), its "Current executable posture" table at the top, and
  [ATSAM_THREAT_ASSUMPTIONS_V1](crypto/ATSAM_THREAT_ASSUMPTIONS_V1.md).
- [SECURITY_ERRATA_RVN1_2026-08-13.md](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md): the errata
  and production hold that followed an earlier implementation audit, with nine processing rules
  and the release gate.
- [WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md)
  §4, the accepted risks of the live LAN path: no forward secrecy and no post-compromise security
  inside a session; no independent review and no formal model; the device key equals the identity
  key; no deniability (everything is signed with the long-term key); revocation is local only;
  metadata (PairInit travels inside Noise on the LAN, but its signature identifies the sender to
  anyone holding candidate public keys); macOS Keychain prompts; no verified Swift parity.
- [THREAT_MODEL.md](THREAT_MODEL.md) "LAN observer and prober": anyone on the network who connects
  to the listener reads its stable Noise static key and can recognise the device on other networks.
- [SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md](SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md):
  what a custodian's computer holds, and the unsigned change to delete on release.
- The Tor design's risks ([design](design/2026-10-tor-fallback.md) §8): reachability is not
  guaranteed, some networks block Tor, Arti has had no dedicated audit, and anyone with a card can
  tell when its owner is online over Tor.
- [SECURITY.md](../SECURITY.md) "Cryptography actually used".

## 4. Build, test, vectors, fuzzers

Install Rust with [rustup](https://rustup.rs); CI uses Rust 1.98.0. Tests must never touch your real
profile or keychain: use the debug-only file-backed test stores.

```sh
cd node
cargo build --release --locked -p ash -p raven-node --features raven-node/tor   # release binaries (macOS: add raven-node/nearby-radio)
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file \
       RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file \
       RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
cargo test --locked -p raven-core -p ash -p raven-node -p raven-client
cargo test --locked -p raven-core --test adversarial_atsam
cargo test --locked -p raven-node --test carrier_matrix -- --ignored --nocapture   # real processes on loopback
RAVEN_LAB_TEST_A=1 RAVEN_LAB_TOR=1 cargo test --locked -p raven-node --bin raven-node -- onion::
cargo build --locked -p raven-node --features tor --bin raven-tor-helper            # the Tor helper
```

Vectors and the Python reference:

```sh
cd protocol/reference && python3 -m pip install -r requirements.txt && python3 -m pytest -q
python3 protocol/reference/generate_rvn1.py && git diff --exit-code -- shared-vectors/rvn1
bash scripts/freeze_protocol_hashes.sh --check
```

Fuzzing (30 targets; [node/fuzz/README.md](../node/fuzz/README.md)):

```sh
cd node && cargo test -p raven-core --test fuzz_smoke                 # stable, every target
cd node/fuzz && cargo +nightly fuzz run pair_init -- -max_total_time=600
```

A debug build with no `RAVEN_LAB_*` variable behaves like a release build. The lab paths open only
in a debug build with `RAVEN_LAB_TEST_A=1` plus the feature's own switch (for example
`RAVEN_LAB_LETTER=1`); a switched-on feature closes in a debug build with its switch set to `0`
(for example `RAVEN_LAB_TOR=0`). What runs in CI, and what is not tested yet:
[EVIDENCE.md](EVIDENCE.md).

Exact dependency versions are in `node/Cargo.lock` (among them `ml-kem` 0.3.2, `snow` 0.9.6,
`libp2p` 0.57.0 and, for the Tor helper, `arti-client` 0.47.0). Vendored and patched upstream code
(SQLite and SQLCipher bindings, a Secret Service client, a time library) is under
`node/third_party/`, with notes (`RAVEN.md`, `RAVEN_DELTA.md`) on what was changed.

## 5. Out of scope

- The lab-only demo cipher (`unsafe-demo-crypto`, `--body-mode unsafe-interim`): it is known to be
  readable by anyone. A way to reach it from a release build **is** in scope.
- The debug-only `locked-file` key backend and the `RAVEN_LAB_*` switches, used as documented. A way
  to open a lab path in a release build **is** in scope.
- The desktop apps' user interface code (separate repositories); their engine, `raven-client`, is in
  this repository and in scope.
- iOS, Android and Swift code: not in this repository. Documents that cite `ios-native/` paths mark
  them OFF-MAIN.
- Third-party code with no Raven-specific impact (Arti and Tor, libp2p, RustCrypto): report
  upstream, and tell us if Raven is affected.
- Social engineering, physical attacks on an unlocked computer, and volumetric flooding that no
  protocol change can mitigate.
- The public STUN servers and the Tor network themselves.

## 6. How to report

Privately, never in a public issue: email security@raven-messager.com with the subject
`[SECURITY] <short description>`, as [SECURITY.md](../SECURITY.md) describes (component, commit,
build and features, reproduction, impact). We credit reviewers who want to be credited.
