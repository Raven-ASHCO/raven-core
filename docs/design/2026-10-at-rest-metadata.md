# At-rest metadata: what a profile stores, and how the privacy pack seals it

| | |
|---|---|
| **Status** | Local-format design, not a wire spec. PP.1 (2026-10-18): the inventory, the rules and the lab switches. PP.3: the at-rest core (`rc/at_rest.rs`, `rc/at_rest/registry.rs`, `privacy::mode`; section 4.1). PP.4: the contact book is sealed (`rc/contact_book.rs`), the migration runs at raven-node's start and at the top of every ash command, and `Status.at_rest` reports it (section 4.2). PP.5: the friend-key files (the peer cache, the block list, the device registry and revocations, the noise pins under their new name, the route hint state, bootstrap, a profile's relay list, the device X25519 secret) are sealed, with the quarantine copies and interrupted writes' temp files (section 4.3). PP.6: the address and activity files (sightings, learned routes, outbox routes, route memory, the chat's read positions, the CLI's alias, nearby and contact-request stores, the relay memory, a profile's friend relay status and key) are sealed, the policy's relay addresses move to a sealed sidecar, and the per-friend send locks are named by a keyed hash (section 4.4); each later step named in the tables adds its part (sections 4.5-4.16: PP.7-PP.18). PP.19 (2026-10-19): this document completed (the final file table, section 6; the column audit, section 7; the migration and downgrade tables, section 8; the registry and the guards, section 11; what the pack does not cover, section 12), fault scenario s120 and `RAVEN_FAULT_PRIVACY=1` (section 4.17), the user's guide (`docs/SAFETY_OFFLINE.md` sections 5-8), the threat rows T3a-T4 (`docs/THREAT_MODEL.md` §3.7a) and the owner-run real row R34 (an unpublished test checklist). PP.21: the terminal app's "Keep chats for", "Delete chat with {name}", "Forget {name}'s address", the one-time notices and the "Locked out of your friends list" chip (section 4.18). PP.22: the terminal app's "Erase Raven from this computer" (section 4.19). PP.23: the terminal app's Lock now completed (`L` on Home, Raven's own login item unloaded for this login session only, the lock recorded, opening the app clears it; section 4.20). PP.24: the terminal app's read markers and the user's own name sealed in `tui_private.rms` (section 4.21). |
| **Plan** | `docs/roadmap/plans/privacy-pack-plan.json` (`designs[0]` and `review.order`, PP.1-PP.24). |
| **Owner policy** | Encrypt everything at rest, addresses and the contact book included; delete old chats automatically (default 30 days; 7 / 30 / 90 days or keep); forget learned addresses after 30 days without contact; real erase; Lock now (roadmap README section 2, rule 7). |
| **Wire** | No wire byte changes. IPC_VERSION stays 1 (one optional `Status.at_rest` field, PP.4). No new crate: HKDF, HMAC, SHA-256, XChaCha20-Poly1305 and zeroize are already raven-core dependencies. |

Paths use this shorthand: `rc/` = `node/crates/raven-core/src/`, `rn/` = `node/crates/raven-node/src/`,
`ash/` = `node/crates/ash/src/`. Symbols, not line numbers, anchor every reference.

## 1. Key hierarchy

```
K_hist   the profile's existing chat-history key ("the chat-history key"; one per profile)
  macOS:   login-keychain generic password, service "app.raven.node.chat-history.v1",
           account = hex(SHA-256("raven/chat-history/v1" || "/" || canonical data dir))
  Linux:   Secret Service item, or the keystore.vault entry keystore_vault::CHAT_HISTORY_KEY_ENTRY
  Windows: chat_history_key.dpapi in the data dir (PP.11): a random K_hist, DPAPI-wrapped for the
           user, entropy = SHA-256("raven/chat-history-key/v1" || "/" || canonical data dir);
           before PP.11 there was none (every blob DPAPI-direct; section 4.9)
  lab:     RAVEN_CHAT_HISTORY_BACKEND=locked-file (tests and debug builds only)
  RULE:    add-only, never rotated, never replaced. The pack writes to the keystore only to create
           K_hist where it does not exist yet (as today) and to delete it in erase.
  |
  +-- meta_key.rmk = "RMK1" || 0x01 || DomainProtector(b"raven/meta-key/v1").protect(dd, payload)
        payload (Zeroizing, canonical JSON): {"v":1, "k_index": 32 bytes, "epochs": [{"e":u32,"k":32 bytes}],
                                              "current": u32}
        Created on the first sealing only, and only in a profile with an identity record. No new
        keychain item: K_meta is wrapped by K_hist.
        |
        +-- K_index = HKDF-SHA256(salt "rvn1/meta/v1", ikm k_index, info "index")      keyed lookups
        +-- K_lock  = HKDF-SHA256(salt "rvn1/meta/v1", ikm k_index, info "lock-name")  per-friend lock names
        +-- per epoch e: K_data[e] = HKDF-SHA256(salt "rvn1/meta/v1", ikm epochs[e].k, info =)
              "meta-file"  RMS1 sealed files (PP.4-PP.6, PP.24)
              "meta-row"   SQLite meta blobs and sealed wire blobs (PP.12-PP.14, PP.17)
              "history"    chat_history.json, magic RVNHIST2 (PP.10)
              "stage"      outbound_body_stage.bin, magic RVNOSTG2 (PP.10)
              "app-row"    app_channel.sqlite3 sealed rows, format tag 0x02 (PP.10)
```

`k_index` is stable for the profile's life (only `raven privacy rotate-meta` replaces it, section
4.16), so a data-key rotation never changes a keyed lookup or a lock name. Data keys rotate by epoch (PP.10): K_hist
never changes. Deleting K_hist (erase, PP.16) makes `meta_key.rmk` unreadable, and with it every
sealed file, row, history, stage and app row: one crypto-erase.

**What is not under these keys:** the identity seed, session roots and chain keys and prekey
secrets (keystore or vault, unchanged), and the files listed as plain by design in section 6.5.

## 2. Formats

**RMS1 sealed file:** `"RMS1" || version 0x01 || kind u8 || epoch u32 BE || nonce[24] || ciphertext || tag[16]`,
XChaCha20-Poly1305 under `K_data[epoch]."meta-file"`, AAD = `"rvn1/meta-seal/v1" || kind || epoch`.
The kind in the AAD stops one sealed file being swapped in for another (a sealed `lan_seen.json` as
`contacts.json`); the epoch names the key (no trial decryption) and lets a rotation find what is
left on an old epoch. Readers always accept plain JSON as well (an old profile, or an older build
wrote it); writers follow the profile mode (section 4).

**Sealed row blob:** `0x01 || epoch u32 BE || nonce[24] || ct || tag`, AAD =
`"rvn1/meta-row/v1" || table || 0x00 || pk || epoch`, where `pk` is the row's primary-key columns
exactly as stored. Random 24-byte nonces: no nonce bookkeeping, no reuse risk at these volumes.

**Epoch data (PP.10):** an epoch body is `epoch u32 BE || nonce[24] || ct || tag[16]`,
XChaCha20-Poly1305 under `K_data[epoch].<use>`, AAD = `domain || epoch` (`at_rest::seal_epoch`):

| Object | Bytes | Use | AAD domain |
|---|---|---|---|
| `chat_history.json` | `"RVNHIST2" ||` body | `history` | `rvn1/history/v2` |
| `outbound_body_stage.bin` | `"RVNOSTG2" ||` body | `stage` | `rvn1/outbound-stage/v2` |
| `app_channel.sqlite3` `app_inbox.sealed` | `0x02 ||` body | `app-row` | `raven/app-inbox/v1` |

A sealed profile's writers always write these; every reader also accepts what K_hist sealed
directly, forever: `"RVNHIST1" || nonce[12] || ct || tag` and `"RVNOSTG1" || ...` (ChaCha20-Poly1305,
AAD SHA-256(domain || "/" || data dir); on Windows `"RKH1"` comes first since PP.11, and a body
without it is an older build's DPAPI-direct one, section 4.9), and app rows with no format byte at
all (`nonce[12] || ct || tag`, on Windows `"RKH1" || nonce[12] || ct || tag` or DPAPI-direct; the
plan's "tag 0x01" was never written). Such a row's random nonce
starts with `0x02` once in 256: a `0x02` row that does not open under its epoch is tried with
K_hist. The vectors are pinned in raven-core (`epoch_formats_are_pinned`,
`epoch_row_format_is_pinned`) and come from the harness's stdlib-only Python reader
(`scripts/lan_fault_matrix.py`, `open_rvnhist2`). The history and stage cap grows by 16 bytes
(4 MiB + 16) so the same serialized budget fits either format.

The data-dir path is not in the RMS1 or row AAD, but `meta_key.rmk` is wrapped under a path-bound
AAD, as every K_hist blob is: moving a profile folder stays unsupported, as it is today.

## 3. Keyed lookups in SQLite: by value type, never by table

`kh = HMAC-SHA256(K_index, "rvn1/meta-index/v1" || type_label || 0x00 || value)`, where
`type_label` names the **value type** (`device-key`, `rvn1-address`, `message-id`, `object-digest`,
`nonce`, `object-bytes`), never the table or the column. Equal values give equal `kh` in every
table, so primary keys, UNIQUE constraints, foreign keys and joins keep their shape. The clear
values move into one sealed `meta` blob per row. Clear time columns stay only where a query needs
them, coarsened (`prune_after_hour`, an insertion `seq`). Where a query compares stored wire bytes
for equality, a keyed digest column (`kh_envelope`, `kh_ack`; value type `object-bytes`) replaces
the comparison.

**Kept clear on purpose (review R20):** random identifiers, or digests of values no file holds
in clear, naming keychain items: the session store's `record_key`, `session_id`,
`binding_digest`, `init_hash` and `generation`. The heads' `init_id` was on this list until
review B-sealed-stores-1: the record key is an unkeyed digest of public values (the constant
profile id, both rvn1 addresses, both device keys) and the `init_id`, so with the `init_id`
clear beside it anyone with the file and a list of candidate friends' public keys could tell
which friend each session is with, who started it and when (to the hour). Since schema 4 the
`init_id` is keyed (`kh_init_id`, value type `nonce`) and kept in the head's `meta`, and the
responder's cached PairResponse that carried it is sealed and named by the keyed value (section
6.1, kind 65); without it the record key is a 2^128 search. Row ids are preserved. **Leakage,
stated honestly:** inside one profile equal values give equal `kh`, so someone with the files but
no keys learns how many sessions, messages and ACKs involve the same unknown friend, and
hour-granular timing; across profiles nothing links.

## 4. Profile mode, the development guard and the lab switches

`privacy.json` (plain, no friend data; PP.3 on) carries `"mode": "plain" | "sealed" |
"unsealed_by_user"` (absent = plain). Only `privacy::migrate_all` moves a profile to sealed: it
flips the mode first, then seals file by file under each file's writer lock.

`privacy::mode` never lets a writer fall back to plaintext: no mode recorded but a `meta_key.rmk`
present (the key is created just before the first sealing) reads as sealed, and so does a
`privacy.json` that cannot be read or parsed, or that names a mode this build does not know
(writers then seal, or fail closed when no key is loaded). Readers accept both forms in every
mode. `privacy::set_mode` keeps every field it does not know, so an older build of the pack never
drops what a newer one recorded.

**Development guard (review R02).** A release build seals on its own. A **debug** build seals only
with `RAVEN_LAB_AT_REST=1` (`lan_gate::at_rest_seal_allowed`), so a debug binary pointed at a real
profile by mistake changes nothing and creates no `meta_key.rmk`. Builds of this pack go only to a
target directory outside the repository (never `node/target`), and no binary of the pack is ever
started without an explicit temporary `--data-dir`.

The pack's lab switches (`lan_gate::PRIVACY_LAB_SWITCHES`), each read only through
`p2p_gate::lab_switch` (a release build never reads one; `lan_gate::tests` proves it in the release
test job, with every switch set):

| Switch | Value | Effect in a debug build | Used from |
|---|---|---|---|
| `RAVEN_LAB_AT_REST` | `1` | may seal a profile (`migrate_all` with its automatic policy) | PP.3 |
| `RAVEN_LAB_ERASE_ROOT` | a folder | `raven erase` refuses any data dir outside it, and every data dir without it | PP.16 |
| `RAVEN_LAB_AT_REST_KEY_FAULT` | `unavailable` | `at_rest::keys_load` fails as an unreadable keystore would (fail-closed node state) | PP.3, PP.4 |
| `RAVEN_LAB_RETENTION_GRACE_MS` | ms | replaces the 7-day grace before the first retention deletion | PP.9 |
| `RAVEN_LAB_LOGIN_ITEM_ROOT` | a folder | stands in for `~/Library/LaunchAgents`, `~/.config/systemd/user` and the scheduled-task list; without it the login-item code refuses to run | PP.15, PP.16 |
| `RAVEN_LAB_LOGIN_ITEM_TOOLS` | a folder | where fake `launchctl` / `systemctl` / `schtasks` live | PP.15, PP.16 |

**Harnesses.** `scripts/lan_fault_matrix.py` (`privacy_env`, `profile_dir_refusal`) and
`node/crates/raven-node/tests/carrier_matrix.rs` (`Profile::env`, `profile_dir`) set
`RAVEN_LAB_AT_REST=1` and `RAVEN_LAB_ERASE_ROOT=<the run's root>` themselves for the processes of
the profiles they create, scrub the caller's values of all six, and refuse a profile folder
outside the run's root, in `~/.raven`, or inside a folder that is already a Raven profile. The
netns scripts unset all six. Outside these two harnesses and unit tests, nothing sets
`RAVEN_LAB_AT_REST` or `RAVEN_LAB_ERASE_ROOT`.

### 4.1 The at-rest core (PP.3)

`rc/at_rest.rs`; nothing outside it calls it until PP.4.

- **Keys.** `at_rest::keys_load(dd)` is the only function that calls the keystore: it reads K_hist
  (minting it exactly as the chat-history path does, only when it creates the key file) and
  unwraps `meta_key.rmk`, or creates it (payload minted and wrapped outside any lock, then
  `.meta_key.lock.sqlite`, re-check, adopt a racing creator's file or write ours). Creation needs
  `MigratePolicy::Auto` to allow sealing (release, or debug with `RAVEN_LAB_AT_REST=1`; unit tests
  pass the test-only `Allow`; read-only tools pass `Never`), a mode other than `unsealed_by_user`
  (`NotSealedMode`) and an identity on record (`identity_store::identity_recorded`: the backend
  marker or the binding, no keystore call and no identity lock; `NoIdentity`), checked before
  anything is created, so a fresh profile stays empty. An existing key file is never replaced, and
  K_hist is never minted for one. One load per profile at a time in a process (a second caller
  finds the cache), then cached per canonical data dir: K_hist, the payload and the file's stamp
  (len, mtime, file id). `at_rest::keys_cached(dd)` never calls the keystore; when another process
  rewrote the key file it unwraps it again with the cached K_hist (one stat per call otherwise).
  `forget_cached_keys` drops both (Phase 6 Lock v2). Debug builds assert that `keys_load` runs on
  a thread that holds no Raven data-dir lock and is inside no store transaction
  (`paths::HeldMark`: held by `DataDirLock`, the chat-history locks, and right after every
  store's `BEGIN`; the guard test `every_store_transaction_is_marked` fails for a new store
  transaction without it).
  `RAVEN_LAB_AT_REST_KEY_FAULT=unavailable` makes every load fail as an unreadable keystore would
  (debug builds; a release build never reads it).
- **Errors.** `KeyUnavailable`, `NoIdentity`, `Tampered { kind }` (kind 0: the key file or a row
  blob), `WrongKind`, `Truncated`, `NewerFormat`, `StaleKeys { epoch }` (the caller's top level
  loads again and retries once; still unknown is tampering), `NotSealedMode`, `Io`, `Json`.
- **Files.** `load_json` / `load_bytes` read RMS1 or plain bytes (`None` when missing; a sealed
  file without loaded keys is `KeyUnavailable`, never empty). `store_json` / `store_bytes` write
  under the file's writer lock: RMS1 when the profile is sealed, otherwise exactly today's bytes
  (`serde_json::to_vec_pretty`, the format of most writers; a writer of another format passes its
  own bytes). `lock_file` holds the writer lock for a read-modify-write. `migrate_file` seals one
  file in place (sealed mode only) and renames only a temp file that opened to exactly the bytes
  it replaces; `unseal_file` is the way back. Only files registered as `Sealed` under the given
  kind are accepted.
- **Registry.** `at_rest::FILES` classifies every file of section 6 (exact names first, then
  patterns where `*` stops at `/`): rule, writer lock and whether erase (PP.16) deletes it. Files
  that had no cross-process writer lock get `.at_rest.<kind name>.lock.sqlite`: `lan_seen`,
  `blocked_pubs`, `revocations` (with `device_revocations_rvdr1.json`), `tui_private`,
  `route_hints_state`, `node_policy_peers`, `bootstrap`, `alias_claims`,
  `nearby_registry`, `contact_inbox`, `relay_memory`, `friend_relay_status`, `friend_relay_key`,
  and since Phase 3 (P3.C2) `lan_meeting`, and since Phase 4 `peer_schedules` (P4.25) and
  `peer_rotation_state` (P4.28), and the desktop apps' `desktop_private` (kind 128). Phase 3's `custody_home.json` (P3.18) is written under the learned
  routes' existing lock `.learned_routes.lock.sqlite`, Phase 5's `prekey_published_local.json`
  (P5.11) under the peer cache's `.lan_peer_cache.lock.sqlite`, `letter_deposits.json`
  (P5.15) under its own `.at_rest.letter_deposits.lock.sqlite`, Phase 6a's `learning.bin`
  (P6.9) under its own `.learning.lock.sqlite`; Phase 6b's `capability_floor.json` (P6.29)
  under its own `.at_rest.capability_floor.lock.sqlite`, `pair_seeds.json` (P6.38) under its own
  `.at_rest.pair_seeds.lock.sqlite`, `updates/state` (P6.44) under its own
  `.at_rest.update_state.lock.sqlite`, and `knock_replays.bin` (Phase 6 review traffic-9) under
  its own `.at_rest.knock_replays.lock.sqlite`.
  The guard test `every_profile_file_name_is_classified` scans the production sources of
  raven-core, raven-node, ash and raven-client (the desktop apps' engine) (test modules, `tests/` and shared-vectors paths excluded;
  fixture readers on a short allow-list with reasons) for file names ending in `.json`, `.sqlite`,
  `.sqlite3`, `.bin`, `.seed`, `.secret`, `.vault`, `.dpapi`, `.rmk` or `.rms`, and fails for any
  name `FILES` does not cover.
- **Formats** (section 2) are pinned by `formats_are_pinned`, whose values come from an
  independent stdlib-only reference (HKDF, HMAC, HChaCha20 and ChaCha20-Poly1305 checked against
  the RFC 8439 and XChaCha20-Poly1305 draft vectors). The wrapped payload is canonical JSON
  `{"v":1,"k_index":"<hex>","epochs":[{"e":1,"k":"<hex>"}],"current":1}`; its key file is
  `"RMK1" || 0x01 || DomainProtector("raven/meta-key/v1")` (on Windows K_hist with the `"RKH1"`
  tag since PP.11; a build before it wrapped it with DPAPI directly, section 4.9).

### 4.2 The contact book, the migration and raven-node's start (PP.4)

- **One reader and writer.** `rc/contact_book.rs` is the only code that reads or writes
  `contacts.json`: `read_plain` / `read_rows` (RMS1 kind 1 or plain JSON; a missing file is the only
  empty book) and `write_rows` (under `.contacts.lock.sqlite`: RMS1 in a sealed profile, exactly
  today's pretty JSON otherwise; `lock` holds the lock for a read-modify-write such as a device-sync
  import). The fourteen readers of the review (raven-core admission, routes, the p2p gate, custody,
  the reach circle, history labels; raven-node's route hints count and agent signatures; ash's
  book, device sync, chat lines and doctor) all go through it. Errors keep today's prefixes
  (`contacts.json: ...`, `contacts.json corrupt: ...`); a sealed book this process cannot open is
  `BookError::Locked` (`contacts.json: locked (...)`), and ash says the UX sentence instead
  ("Raven can't open your friends list: ..."). The readers that defaulted quietly on an unreadable
  book (the sender label written into history, the route hints count, an agent signature's contact
  check, ash's chat and outbox lines, the doctor) now fail their operation (review R23); only the
  name label of a send line stays "unknown".
- **`privacy.json`** (plain, no friend data): `{"v":1, "mode":"sealed", "sealed_since_day":N,
  "kinds":["contacts"], "notices":{"sealing_shown":true, "older_build_wrote_plain":true,
  "older_node_day":N}, "space_deferred_at_ms":..., "space_needed_bytes":...}`; fields this build
  does not know are kept. `kinds` lists the kinds whose files were sealed: a plain file of one of
  them is a downgrade leftover (an older build wrote it), sealed again with the note set.
- **`privacy::migrate_all(dd, now, policy)`** (raven-node; ash and the terminal app call
  `migrate_all_with` and its upgrade interlock): never in mode `unsealed_by_user`; a plain profile
  only when the policy allows sealing (release, or debug with `RAVEN_LAB_AT_REST=1`) and an identity
  is on record (nothing is written otherwise, so a first install stays one); in a sealed profile the
  key is loaded first and the pass is one small read per migrated file once every kind is recorded.
  A pass that would seal asks the interlock (an IPC Status without `at_rest` is an older node:
  nothing is sealed, ash says the restart line at most once a day) and the free-space preflight
  (twice the profile plus 64 MiB; otherwise deferred, recorded, retried at most once an hour). Then
  `keys_load` outside every lock, `.at_rest.lock.sqlite`, the mode recorded as sealed (fsynced),
  each migrated file sealed under its own writer lock (`at_rest::migrate_file`), and the record.
  PP.4 migrates the contact book only (`privacy::MIGRATED`); later steps add their files.
- **ash.** At the top of every command, before any lock: `migrate_all_with` (which loads the key of
  a sealed profile). The one-time sealing notice (and on macOS the keychain-at-start line) goes to
  stderr once; the terminal app's top leaves it for the next command. `raven status` has an
  `at_rest` row (words and counts) under CONTACTS, with the key-unavailable (or key-gone),
  free-space and older-build sentences when they apply; `raven doctor` an `at_rest: state=...
  files=N` line.
- **raven-node** (`rn/at_rest_boot.rs`, at service start and in `raven-node ipc`): a profile that is
  sealed, or that this build seals, gets its key on a thread of its own (a keychain call has no
  timeout and may wait on a dialog). Until the key is loaded and `migrate_all` has run, every read of
  the book in the process refuses (`contact_book::hold`): the listeners start at once and admit
  nobody, exactly the refusal of an unreadable book. Failed tries are retried after 30 s, 1, 2, 4, 8,
  then every 15 minutes, and at once when the user asks (`raven status`: an IPC Status with the
  optional `retry_key`) and the last try ended 30 s ago or more; the terminal app's periodic
  Status never asks (review B-sealed-stores-6: with the app open, a user who pressed Deny saw the
  dialog every 30 s);
  one try at a time. A key file whose K_hist is gone from the keystore (missing, or corrupt: a new
  login keychain, a profile copied to another computer or account, a Windows account whose
  `chat_history_key.dpapi` is gone or no longer unwraps) is `AtRestError::KeyLost`, not the
  transient `KeyUnavailable` (review A-keys-format-4): `key_lost`, tried again only every 15
  minutes and when `raven status` asks, and the commands say `KEY_LOST_TEXT` (put back the keychain
  or the backup, else `raven erase`) instead of "answer the keychain dialog". Readers still take
  it as "not now" (`is_unavailable`): nothing is set aside or called corrupt. The process
  remembers a loss per profile (`at_rest::key_lost`) until a load works. Then the book and the
  block list are cached by file stamp (length, write time, file id; read stat, read, stat), and a
  changed stamp is read again before the next admission. The
  p2p gate and the friend relay add the book's reload generation to their file stamps, so a book
  held at start is read again once the key is here. A plain profile this build does not seal never
  calls the keystore. Log lines: `raven-node at_rest: <state>` once (the harnesses wait for it),
  `sealed N file(s)` after a migration, a rate-limited "the friends list is locked" while the key is
  unavailable.
- **`Status.at_rest`** (`AtRestStatus { state, sealed_files, plain_files, notes }`): `state` is
  `sealed`, `waiting_for_keychain`, `key_unavailable`, `key_lost`, `migrating`, `plain`,
  `unsealed_by_user` or `needs_disk_space`; notes are the fixed tokens
  `older_build_wrote_plain`, `scrub_pending`, `older_node_running`. Every build of the pack sends
  it (that is the interlock's signal); IPC_VERSION stays 1.

### 4.3 The friend-key files (PP.5)

Every file below goes through `rc/at_rest.rs`: RMS1 in a sealed profile, today's bytes otherwise,
and readers accept both. Error texts keep today's words: `... read: ...` when the read may work
later (`AtRestError::is_unavailable`: the key not loaded, an unknown epoch, an I/O error) and
`... corrupt: ...` otherwise. A writer that already holds the file's writer lock for its own
read-modify-write writes with `at_rest::write_held` (taking the lock again would wait on itself).

- **Peer cache** (`rc/lan_dispatch.rs`, `rc/prekey_bundle.rs`): `peer_device_certs.json` (kind 5),
  `prekey_store.json` (6) and `peer_cache.stage.json` (18), all under `.lan_peer_cache.lock.sqlite`.
  The stage+commit dual write works on sealed bytes: the stage is sealed, its replay opens it and
  writes sealed files; `peer_cache.generation` (a number) stays plain. A sealed stage this process
  cannot open yet (its key not loaded) is kept for the next try; one that does not open under this
  profile's key is set aside like an unparsable stage.
- **Block list** (`blocked_pubs.json`, 7): `BlockList::load_checked` opens it on both paths (a
  long-lived process's cache holds the bytes as they are on disk); `save` takes
  `.at_rest.blocked_pubs.lock.sqlite` and still refuses to overwrite a list it cannot read.
- **Devices**: `device_registry.json` (8; its writers hold `.device_registry.lock.sqlite`);
  `device_x25519.secret` (24), written by its one writer under the same lock (so it needs no lock of
  its own); `device_x25519.pub` stays plain; a secret file of exactly 32 bytes is plain whatever it
  starts with. Audit re-confirmed: the secret is read only to derive and check its public key for
  `DeviceCertificate::issue`; it decrypts nothing and takes part in no key agreement.
  `revocations.json` (14) and `device_revocations_rvdr1.json` (25) are written together under the
  new `.at_rest.revocations.lock.sqlite`; `device_sync_seen.json` (15) under
  `.device_sync_seen.lock.sqlite`.
- **Noise pins** (16, `rc/lan_noise_pin.rs`): a sealed profile reads and writes only
  `lan_noise_pins.rms` (review R07). "Unreadable = no pin" holds only for a missing file and a
  corrupt plain one: a sealed file that does not open, or whose key is not loaded, is an error, so
  the dial does not start. The migration moves a plain `lan_noise_pins.json` into the sealed file
  under `.lan_noise_pins.lock.sqlite` (written and checked to open to exactly the merged pins, then
  the plain file deleted, or moved aside and sealed when it did not read in full). Later such a file
  is an older build's (it pins on first use): its pins are taken only for contacts without a sealed
  pin, and where it pins a contact differently the sealed pin stays (counted in
  `notices.older_build_pinned_differently`; the note `older_build_pinned_differently`, cleared with
  the older-build sentence). A newer build's plain file, or a sealed file that does not open, stops
  the merge with both files untouched (counted plain; tried again by the next pass).
- **Route hint state** (`route_hints_state.json`, 17; raven-node's `hints::GEN_STATE_FILE`, written
  under the new cross-process `.at_rest.route_hints_state.lock.sqlite`): an advisory file. Missing,
  or plain bytes that do not parse, read as no state and are replaced as before; a sealed file this
  process cannot open reads as no state, is never written over and is read again next time (once
  the key is loaded): no generation is used meanwhile, and the skip is counted when the file itself
  does not open (a key that is not loaded yet is only late, and is not counted).
- **Bootstrap** (`bootstrap.json`, 20; `.at_rest.bootstrap.lock.sqlite`): a profile is sealed only
  once it has an identity, so a write before it stays plain (a first-install inert file) and the next
  migration seals it. A sealed file that does not open is never moved aside or replaced
  (`BootstrapError::Sealed`); a plain unparsable file moved aside is sealed in place at once in a
  sealed profile.
- **Relay list** (`relay_allow.json`, 21; `.relay_allow.lock.sqlite`): sealed in a sealed profile
  (`raven-node service --relay`, the friend relay's manual list); a dedicated relay folder
  (`is_relay_dir`) has no identity, is never sealed and keeps it plain. Phase 4 P4.26 adds the
  entry column `expires_ms` (a rotating friend's schedule, `raven relay allow --schedule`): it
  lives inside the same file, so it is sealed with it under kind 21 in a profile; no new file,
  kind or lock.
- **The migration** (`privacy::MIGRATED`): the files above in place; then the noise pins move;
  then the quarantine copies (`<file>.corrupt` of the peer cache files, revocations, bootstrap and the
  pins): a plain copy is sealed in place under its file's kind and kept for a manual look (review
  R30); a sealed peer-cache copy that opens under this profile's key to JSON (an older build moved
  a sealed file it could not parse aside) is restored when its file is missing (the stage only beside
  a committed generation, which orders its replay) and deleted otherwise; any other copy is left as
  it is. Every pass in a sealed profile also deletes the `.<name>.tmp.<16 hex>` files of interrupted
  atomic writes older than one hour (the profile and its folders one level down, by the system
  clock): nothing cleaned them before and they may hold plaintext. `privacy.json` `kinds` records
  the noise pins too; `Status.at_rest` counts the migrated files, the pin files and the copies.
- **Advisory-file rule** (`at_rest::load_json_advisory` returns `Missing`, `Loaded`, `CorruptPlain`
  or `Unreadable`): a reader that treats an unreadable file as empty never writes after an at-rest
  error; only a missing file or plain bytes that do not parse may be replaced. A skipped write is
  counted per profile (`at_rest::note_skipped_write`) unless only the key was missing (not loaded
  yet: the file is read again once it is), and `Status.at_rest` carries the note
  `unreadable_file_kept` while the count is above zero. PP.6 uses the same rule for its files.

### 4.4 The address and activity files (PP.6)

The same rules as section 4.3: RMS1 in a sealed profile, today's bytes otherwise, readers accept both,
and `privacy::MIGRATED` seals what is still plain.

- **Advisory files** (an unreadable file reads as empty, as before): `lan_seen.json` (kind 2),
  `learned_routes.json` (3), `route_memory.json` (13), `outbox_routes.json` (4) and the relay memory
  `relay_memory.json` (29). Their writers read under the file's writer lock with
  `at_rest::load_json_for_write`: a missing file or plain bytes that do not parse are replaced as
  before; a sealed file this process cannot open (its key not loaded yet, a changed byte) is never
  written over. The write is skipped and counted (not counted when only the key was late), and
  `outbox::edit_route_file` returns an error instead of silently replacing the file (its callers
  ignore it, as they did every write error). A forget (a contact removed) on such a file is an
  error and leaves it as it is. `lan_seen.json` had only a mutex inside one process: its writers now
  take `.at_rest.lan_seen.lock.sqlite` across processes (`raven contact remove` and the listener),
  and so `raven contact remove`'s best-effort forgetting takes each file's lock.
- **Fail-closed files**: the chat's read positions and clear tombstones `chat_inbox_cursors.json`
  (kind 9; a file that cannot be opened keeps the chat closed with the same sentence and is never
  written over), the CLI's `alias_claims.json` (26; refused, never written over) and
  `nearby_registry.json` (27; a sealed file that does not open is left as it is), and each incoming
  contact request `contact_inbox/<request id>.wire` (28; one that does not open is skipped). The
  exports `contact_request_<id>.wire` / `contact_accept_<id>.wire` / `contact_request_<id>.bin` stay
  plain: they are meant to be handed over.
- **A profile's friend relay** (`friend_relay/`, a folder of a profile with an identity):
  `relay_status.json` (30) and the relay's own libp2p key `relay_key.ed25519` (31; a raw secret: its
  plain file is exactly 32 bytes), under `.at_rest.friend_relay_status.lock.sqlite` /
  `.at_rest.friend_relay_key.lock.sqlite` in the profile. A key that does not open is an error and is
  never replaced (the friend relay tries again later). A dedicated relay folder (`raven-node relay`,
  no identity) keeps both plain, and no lock file is made outside it.
- **The policy's relay addresses** (`node_policy_peers.rms`, kind 19). In a sealed profile
  `p2p_relays` (relays, possibly friends' public addresses) and `relay_external` (this computer's
  own public names) live only in the sealed sidecar; the listen settings stay in the plain
  `node_policy.json`, which raven-node reads at start before any keystore call. `try_load_policy`
  merges the sidecar when this process holds the key (a value still in `node_policy.json`, written
  before sealing or by an older build since, is the newer and wins); `save_policy` writes those
  fields only to the sidecar (removed when they are empty) and, while the sidecar cannot be opened,
  refuses a policy that names relays with a retryable error and keeps the sidecar for one that
  does not. Every writer of either file takes the sidecar's lock in a sealed profile. The migration
  (`node_policy::seal_peers`) writes the sidecar first (checked to open to exactly the values), then
  `node_policy.json` without them; a crash between the two leaves both, and readers see the relays
  once. raven-node's IPC `SetPolicy` (bridge, store, relay) changes `node_policy.json` alone
  (`node_policy::update_settings`), so it works before the key is loaded and never touches the
  sidecar. raven-node's p2p host that started before its key thread loaded the key (the sidecar did
  not open) starts without those relays; the peer gate's next load after the key arrived (its stamp
  includes the book's reload generation) reads them and re-homes the endpoint once with them. An
  older build sees no relays (p2p is gated in release); when it saves the policy it writes none, and
  the sidecar is untouched. The installers still put relay arguments into the login item (plain,
  outside the data dir; removed by erase). Phase 3 (P3.16) adds `custody_home` (the home
  custodians picked by hand with `raven custody home`: contacts' keys in hex, at most 2) to the
  sidecar with the same rules; the consent `custody_use` (`raven custody use on|off`, no friend in
  it) stays in `node_policy.json`. Phase 4 (P4.6) adds `p2p_proxy`, the WSS proxy setting (`auto`
  when empty, `off` or `http://host:port`: the network's proxy is another machine), to the same
  sidecar under the same rules; `save_policy` refuses a proxy setting with a user name or password
  in either mode, so no credential is ever written (they reach the node only at runtime,
  `protocol/RAVEN_WSS_TRANSPORT_V1.md` §8.1).
- **Per-friend send locks.** `PeerSendLock::file_name(dd, peer)` is `at_rest::lock_name` in a sealed
  profile (`.send_<hex(HMAC(K_lock, peer)[0..16])>.lock.sqlite`, from the stable index key: a
  rotation never renames it) and the key in hex otherwise. While an older build's
  `.send_<key hex>.lock.sqlite` exists, a sender takes the keyed lock and then that one (always in
  this order: an older `ash` still running and this build exclude each other) and deletes it when it
  lets both go; this build never creates the hex name in a sealed profile. `raven contact remove`
  deletes the contact's lock files (both names), forgets its M0 pin and its learned routes as
  before, and sets `privacy.json` `rotation_due` (PP.10); so does a change of the block list.

### 4.5 Forgetting addresses (PP.7)

Owner choice "friends' addresses forgotten after 30 days without contact" (cutoff OD-C10 (a): 30
days, day-granular times, no IP in tombstones), in a sealed profile and a plain one alike, with no
gate: only what no dial reads any more leaves the disk.

- **`privacy::forget_stale_addresses(dd, now_ms) -> ForgetReport`** (counts only). raven-node runs it
  after every durable prune (`lan_dispatch::prune_expired_lan_durable_state`, every
  `DURABLE_PRUNE_INTERVAL`) and logs `raven: forgot old addresses: sightings=N learned_routes=N
  route_memory=N outbox_routes=N kept=N` when it removed something; ash runs it at the start of every
  command when no raven-node answers an IPC ping (not running; a node that does not answer is left
  to do it). No keystore call: a sealed file whose key the process has not loaded is left as it is
  for the next pass (`kept`), never written over.
- **`lan_seen.json`**: sightings older than 30 days (`lan_seen::MAX_AGE_MS`) go
  (`lan_seen::prune`); every reader already ignored them.
- **`learned_routes.json`**: written as its readers see it (`learned_routes::prune`: `tidy` turns an
  expired snapshot into a tombstone without its routes, keeps an expired LAN part's IP and port
  until 30 days after it was received and then drops it (Phase 3 P3.C1, OD-C10 (a): a friend met
  weekly is found again; `learned_routes::LAN_KEEP_MS`), and drops a past tombstone, a duplicate
  row and a row stamped in the future). The tombstone of a contact unheard
  for 30 days (`learned_routes::FORGET_AFTER_MS`; heard = the newer of its last stored RRH1 and its
  last authenticated LAN link in `lan_seen.json`) keeps only its key, its carrier, and its
  generation and times rounded down to the day (the generation is the sender's clock in ms): no IP,
  port, relay, relay offer or custodian. A tombstone's generation is never compared with a frame
  (any frame replaces an expired entry), so the rounding changes no merge; the tombstone still goes
  30 days after its (rounded) expiry. Its relay offers going means relay choice no longer keeps a
  reservation on that contact's friend relay (a contact unheard for 30 days). Unreadable sightings
  cut no tombstone.
- **`route_memory.json`**: entries past their 30-minute lease (or stamped in the future) go
  (`route_memory::prune`).
- **`outbox_routes.json`**: the records of messages the outbox no longer holds, and what such
  messages kept once expired (`outbox::forget_finished_object_routes`). The store's prepared and
  queued rows are read after the file and before its lock is taken (no store is opened under the
  lock); every writer records an object only once the store holds it, so a record written after
  that read is never a candidate and a candidate the store no longer holds has left it for good.
  A profile without a session store holds no outbox (none is created). `raven outbox cancel` reads a
  message's evidence before it gives the message up.
- **Not touched**: the contact book's saved addresses (OD-PP-5 (a): the user saved them; sealed),
  the M0 noise pins (keys, removed with the contact) and the relay settings.
- **Rotation**: a pass that removed anything sets `privacy.json` `rotation_due`: older sealed
  versions of these files in freed disk blocks still hold what went until the next data-key
  rotation (PP.10).
- **`raven contact forget-address [NAME] [--tag|--petname|--address] [--yes]`**: clears the
  contact's saved LAN, Internet and p2p routes and relays in the book (sealed write; name, tag,
  pin, Tor address and custody friends stay; field test E3 found an old card's p2p route kept)
  and forgets its sighting, route hints, remembered route and the routes recorded for its waiting
  messages, after "Forget {name}'s saved address? Raven can then reach {name} only after {name}
  connects to you, or after you save a new address. [y/N]" on a terminal (`--yes` for scripts;
  without a terminal it refuses with exit code 2). It sets `rotation_due` too. The terminal
  app's "Forget {name}'s address" (F on the friend's page) takes the same path (PP.21, section
  4.18).

### 4.6 A clear that sticks, and "delete chat" (PP.8)

`/clear-local-history` deleted the friend's history rows but left the session store's
`endpoint_inbox` rows, and two paths wrote them back: the session-expiry archive
(`archive_expired_inbox_to_history`) and, at once, the duplicate path when the friend sent an
accepted object again (its ACK lost). User-invoked, no gate.

- **`privacy::delete_chat(dd, peer, received_up_to_ms) -> ChatDeletion`** (counts only): first
  `IndexedSessionStore::delete_inbox_for_sender` (the friend's chat rows, all or those received at
  or before the bound), then `ChatHistory::delete_for_contact` (every history row of the friend,
  both directions), then `rotation_due` when anything went. Inbox first: a failure in between
  leaves the history, which a second run deletes. No store is created on a profile without one.
- **Tombstones**: one IMMEDIATE transaction moves each deleted row to `endpoint_inbox_deleted`
  (`session_id`, `object_digest`, `sender_device`, `deleted_at_ms`, `max_received_at_ms`; no foreign
  key, additive, `METADATA_SCHEMA_VERSION` unchanged) and deletes it; receipts, ACK intents and
  logical-message rows stay, then a WAL checkpoint (`InboxDeletion::scrubbed`). A re-delivered
  object is still a duplicate: a direct link and a relayed delivery answer it with the same ACK and
  show nothing (`inbox_row_deleted`); a missing row without a tombstone keeps today's error. The
  replay of an acceptance journal treats a tombstoned row as accepted. A row whose acceptance
  journal is still pending, or of a session that cannot be read, is skipped and counted. Agent
  payloads (app channel) are RDAP's and never deleted. `monotonic_received_at_ms` also takes the
  tombstones' floor. `prune_expired_sessions` deletes a session's tombstones before its receipts,
  and orphans an older build's prune left. `delete_inbox_older_than` serves the retention pass
  (PP.9).
- **ash**: `/clear-local-history` saves the chat's cursor tombstone, then deletes up to it (a
  message arriving meanwhile stays to be shown), and prints "cleared: your chat with {name} is
  deleted from this computer." New `raven chats delete --petname NAME [--yes]`: the UX copy's
  question (typed `delete`, also on a Persian keyboard layout; without a terminal it needs
  `--yes`), the count, and the waiting-messages paragraph. Messages still waiting to be sent keep
  their outbox rows and staged bodies; the stage reconcile shows them as waiting again and they
  turn delivered when their ACK comes.

### 4.7 Keeping chats for 7 / 30 / 90 days or always (PP.9)

Owner choice "delete old chats automatically" (OD-PP-4: 7 / 30 / 90 days or keep, default 30 days),
no gate (at-rest data minimisation), the grace of OD-PP-3 (a) for existing profiles.

- **The setting** lives in `privacy.json` (`"chat_keep": "7d" | "30d" | "90d" | "always"`; absent =
  30 days), never in `node_policy.json`, which an older build rewrites without the fields it does not
  know. A word this build does not know (a newer build's) and an unreadable `privacy.json` keep
  everything. `raven chats keep 7d|30d|90d|always` sets it (refused on a profile without an
  identity, where a settings file would make the first `raven init` refuse the profile) and says
  the UX copy's sentence.
- **The clock** (`retention_starts_at_ms`): recorded once by `privacy::migrate_all` of a build that
  may seal (release; a debug build only with `RAVEN_LAB_AT_REST=1`, so a debug binary pointed at a
  real profile deletes no chat either): now for a profile without chats (no history and no outbound
  stage: a new profile), now plus the grace (`RETENTION_GRACE_MS`, 7 days;
  `RAVEN_LAB_RETENTION_GRACE_MS` in a debug build) for one that holds chats, which also gets
  `notices.retention_pending`. Not recorded while an older raven-node holds the migration back.
- **The age** (review R09): `ChatHistoryEntry.stored_at_ms` (new, optional, written only in a sealed
  profile by `ChatHistory::append_persisted` for a new row; an update keeps it) is this computer's
  clock when it first stored the row. Without it (a legacy row, a plain profile) an outbound row
  counts from its own stamp and a received one from its sender's stamp plus
  `MAX_ENDPOINT_ENVELOPE_LIFETIME_MS` (`kept_since_ms`), so nothing goes earlier than the setting
  after it arrived. `ChatHistoryEntry` denies unknown fields, so an older build cannot read a
  history holding the field (it already fails closed on a sealed profile); `raven privacy unseal`
  (PP.18) strips it.
- **`privacy::apply_retention(dd, now_ms) -> RetentionReport`** (counts only; `ran`, `history`,
  `chats`, `inbox`, `staged`, `waiting`): with the cutoff `now - keep`, first
  `IndexedSessionStore::delete_inbox_older_than` (received rows, tombstoned, then the checkpoint:
  `inbox.scrubbed`), so the session-expiry archive cannot bring a row back; then
  `chat_history::clear_finished_staged_older_than` (staged bodies of finished messages, which stay
  only after a crash; the same clear helper as `clear_staged_outbound_body`), so the stage
  reconcile cannot either; then `ChatHistory::delete_older_than`. Messages still waiting to be sent (the store's prepared and queued
  rows) keep their rows and staged bodies and are counted as `waiting`; an outbox that cannot be
  read deletes nothing. A pass that removed anything sets `rotation_due` (PP.10).
- **When it runs**: raven-node after every durable prune (`prune_expired_lan_durable_state`, logged
  `raven: deleted old chats: history=N chats=N inbox=N staged=N waiting=N skipped=N`), ash at the
  start of every command when no raven-node answers. A pass records when anything can go next
  (`retention_next_at_ms`: between an hour and a day ahead; an hour after a failure; cleared by a new
  setting), and the passes before that read no history, so the history key is read at most about
  once a day while nothing is old enough.
- **What people see**: the retention notice (UX copy, once, on stderr of the first command after
  the clock started with a grace; not for a profile that chose "always"); `raven status` says
  "Chats are kept for 30 days (first deletion on {day})." only while the grace runs;
  `raven chats status` gives the setting and the next deletion in local time (CP.6) with how many
  messages in how many chats go then (`privacy::retention_outlook`). The terminal app's row and
  notice are PP.21's (section 4.18: `retention_notice_due`, `take_retention_notice`).

### 4.8 Data-key rotation (PP.10)

No gate (at-rest key management), sealed profiles only: a plain or `unsealed_by_user` profile never
rotates (`mark_rotation_due` is a no-op there and `raven privacy status` says so). The review
replaced "rotate K_hist in the keystore" (R04, R08): **K_hist never changes**; the data moves under
the epoch keys inside `meta_key.rmk`, and a rotation changes the epoch. No keystore call, no
keychain dialog, the same code on every backend (the lab backend included).

- **Formats** (section 2): the migration (`privacy::migrate_all`, its fast path too) moves a
  sealed profile's history, stage and app rows that K_hist sealed directly under the current epoch
  (`ChatHistory::reseal`, `chat_history::reseal_stage` under their locks, `app_store::reseal_rows`
  in one IMMEDIATE transaction plus a checkpoint), with K_hist from the at-rest key cache
  (`at_rest::cached_hist`), so nothing under a lock calls the keystore. An older build of the pack
  that wrote RVNHIST1 into a sealed profile is moved again at the next start. History and stage
  operations warm only what they need before their lock: the at-rest keys in a sealed profile (a
  process that has not loaded them loads them there, outside every lock, never creating a key
  file), K_hist only for a file K_hist sealed.
- **`privacy::rotate_data_key(dd, now_ms) -> RotationReport`**, one pass, every step re-runnable,
  under `.at_rest.lock.sqlite` (2 s wait, else skipped):
  1. When `rotation_due` and no rotation started on this day (`last_rotation_at_ms`): record
     `privacy.json` `"rotation": {"from": e, "started_at_ms": now}` with the due mark cleared (a
     deletion from then on marks the next rotation), then `at_rest::add_epoch` writes
     `meta_key.rmk` with epochs {e, e+1}, current e+1: payload built and wrapped with the cached
     K_hist outside the lock, `.meta_key.lock.sqlite`, the file stamp re-checked (else again from
     the file now there), temp + fsync + rename. Every writer seals under e+1 from its next
     `keys_cached` (which re-reads a key file whose stamp changed).
  2. Re-seal everything not on the current epoch: history, stage, app rows, then every registered
     sealed file (`at_rest::reseal_file` under its writer lock, verified before the rename),
     then the SQLite meta blobs and sealed wire objects of PP.12-PP.14 (sections 4.10-4.12).
  3. The grace: e stays at least `ROTATION_GRACE_MS` (24 h) after the start, so a process that read
     the keys just before step 1 and sealed under e afterwards (an app row is sealed before its
     transaction) loses nothing.
  4. The first pass after the grace re-scans: anything still off the current epoch is re-sealed and
     the pass stops; once a re-scan finds nothing left and nothing it could not re-seal now (a lock
     held, a read failed), `at_rest::drop_old_epochs` writes `meta_key.rmk` with {e+1} only, and
     the record is cleared. An object that opens with no key here (a changed byte) is counted as
     unreadable and does not hold the drop up. `k_index`, every keyed lookup and every lock name
     stay; `raven privacy rotate-meta` (PP.18) is the full re-key.
  A crash at any point (the record written, the epoch added, inside the re-seal per object kind,
  the epoch dropped before the record was cleared) is finished by the next pass
  (`crash_after_each_step_recovers`).
- **When**: raven-node's durable prune (every 10 minutes, `prune_expired_lan_durable_state`, after
  the address forgetting and the retention pass; logged `raven: data key rotation: started=...
  resealed=N dropped=... pending=N unreadable=N`), ash at the start of every command when no
  raven-node answers. So deleted data stops opening with this computer's keys about 24-48 h after
  the deletion.
- **What people see**: `raven privacy status` (PP.18 adds the stores and `--json`): what is
  encrypted, the retention setting, the address rule, and "Deleted chats and forgotten addresses:
  unreadable with this computer's keys 1-2 days after deletion (last key change: ...)", with "the
  old key is still kept for a day or so" while an old epoch is held (`privacy::rotation_state`).
  Hidden, every build, for the owner's real-row check R34: `raven privacy rotate-now [--drop-now]`
  (typed `rotate`, `--yes` for scripts; `--drop-now` ends the grace, so a write sealed under the old
  epoch in that instant would be lost: a check by hand only) and `raven privacy status
  --verify-copy <file>` (only whether a copy opens with the profile's current keys).
- **Older builds**: a build before the pack reads RVNHIST2 as `Corrupt` and fails closed, never
  moving the file aside (its legacy import needs a leading `{`; `rvnhist2_makes_the_snapshot_build_fail_closed_not_move_aside`
  runs the PP.1 snapshot); it quarantines a `0x02` app row; it never opens RVNOSTG2.
- **Honest limit**: older versions of `meta_key.rmk` in freed disk blocks are wrapped by the same
  K_hist, and a copy K_hist sealed directly (RVNHIST1, RVNOSTG1, an untagged app row) opens as long
  as K_hist exists (section 10, limit 1).

### 4.9 Windows: a real K_hist (PP.11)

No gate (at-rest key management). Before PP.11 a Windows profile had no K_hist: history, stage,
app rows and `meta_key.rmk` were each user-scoped DPAPI directly (`CryptProtectData`, entropy the
path-bound scope), so deleting files was no crypto-erase and anyone who can use the user's DPAPI
master key could open freed copies.

- **K_hist** (`rc/chat_history/windows_key.rs`): 32 random bytes in `chat_history_key.dpapi`,
  DPAPI user scope, entropy SHA-256("raven/chat-history-key/v1" || "/" || canonical data dir).
  Created add-only under `.chat_history_key.lock.sqlite` exactly as the keychain item is
  (`init_protected_key`): written whole to an owner-only temp file, fsynced, then hard-linked to
  its name (which fails when the name exists), so it appears complete or not at all and never
  over another one. A file that does not unwrap to 32 bytes for this account is
  `CorruptProtectedKey` and is never replaced. Never rotated (PP.10 rotates the epoch keys).
- **Blobs**: `DomainProtector` and the history and stage protectors seal AEAD under K_hist exactly
  as on macOS and Linux, behind a 4-byte tag: `"RKH1" || nonce[12] || ct || tag[16]`. Every DPAPI
  blob starts with its version `01 00 00 00`, so the forms never meet: a blob without the tag is
  an older build's DPAPI-direct one and still opens with DPAPI, forever. A profile that has no
  K_hist yet loads as `HistKey::Dpapi`: DPAPI-direct blobs open, and a tagged one or a new seal
  uses K_hist once its file exists (read then, never created). An ordinary write outside a sealed
  profile never mints K_hist either (review A-keys-format-2: before the first sealing an older
  raven-node may still share the history and the stage, and the interlock or the free-space
  preflight holds the sealing back): without K_hist it seals DPAPI-direct, which every build reads.
  K_hist is minted by the sealing (`at_rest::create_key_file`) and by the move below, after the
  interlock. A legacy plaintext history stays importable as before (DPAPI gives no integrity
  against same-user processes either way).
- **Eager migration** (review R18: `meta_key.rmk` is never rewritten otherwise, so "on the next
  write" would leave it DPAPI-direct for good): `privacy::migrate_all`, in this order, each step
  leaving files that open either way: create `chat_history_key.dpapi` if missing; in a sealed
  profile (its fast path too) re-wrap `meta_key.rmk` under it (`at_rest::rewrap_key_file`: the
  same payload, temp + fsync, the written copy verified, rename, under `.meta_key.lock.sqlite`;
  every key, keyed lookup and lock name stays), after which PP.10's move puts history, stage and
  app rows under the epoch keys; in a profile that is not sealed (a debug build without the lab
  switch) move history, stage and app rows under K_hist with the tag
  (`windows_key::rewrap_history`, `rewrap_stage`, `app_store::rewrap_dpapi_rows`), not while an
  older raven-node answers (the interlock). Nothing is deleted, and nothing is created in a
  profile with nothing DPAPI-direct. A `raven privacy unseal`ed profile is left as it is (PP.18
  writes DPAPI-direct blobs back for older builds, in a profile without `meta_key.rmk` too:
  review A-keys-format-1). Crash points `WindowsKeyCreated` and
  `WindowsKeyFileRewrapped` are tested.
- **Erase** (PP.16) deletes `chat_history_key.dpapi` first (registered in `at_rest::FILES` as
  already protected, erase: yes): from then on `meta_key.rmk`, and with it every sealed file, row,
  history, stage and app row, opens with nothing this account holds, DPAPI included.
- **Older builds**: an older Windows build reads a tagged blob as a failed DPAPI blob and fails
  closed (`AuthenticationFailed`; the key file `Tampered`); `raven privacy unseal` is the way back.
- **Tests** run on every system through a DPAPI stand-in (`windows_key::ForTests`, test builds
  only) and against real DPAPI in the `rust-windows` CI job: `privacy::windows_key_tests`
  (with the review's `writes_before_the_sealing_stay_readable_to_an_older_build`,
  `unseal_of_a_profile_never_sealed_writes_dpapi_direct_blobs_back` and
  `a_lost_k_hist_is_key_lost_not_a_keychain_wait`).
- **Honest limit**: a copy taken before the migration (DPAPI-direct) still opens for this Windows
  account; only copies taken after it depend on K_hist (section 10, limit 1).

### 4.10 SQLite stores 1: owed ACKs and the app store (PP.12)

No gate (at-rest; the owner's storage choice). The column audit every SQLite step follows is
section 7.

- **The rebuild recipe** (`rc/sqlite_rebuild.rs`, shared with PP.13, PP.14 and PP.17): a dedicated
  connection with `foreign_keys=OFF` and `legacy_alter_table=OFF` set before `BEGIN IMMEDIATE`
  (the bundled SQLite turns foreign keys on, and the pragma is a no-op inside a transaction),
  `temp_store=MEMORY`, `secure_delete=ON`; the version and shape read again inside the
  transaction; per table `CREATE TABLE <t>__new`, the rows copied with their rowids, `DROP`,
  `ALTER TABLE <t>__new RENAME TO <t>`, the indexes created again under their old names; before
  COMMIT every table's row count as expected and `PRAGMA foreign_key_check` empty, else ROLLBACK;
  the `raven_schema(store, version, scrub_pending)` row and `user_version` in the same
  transaction. Then one `VACUUM` and `checkpoint_truncate`: while a reader or a writer is in the
  way `scrub_pending` stays set and the next prune pass finishes it. Free space first (twice the
  store plus 64 MiB): otherwise the move is deferred, the store keeps working as it is, and the
  next pass or open tries again. Tests stop the rebuild before every statement.
- **When**: `privacy::migrate_all` (both of its sealed paths, `move_stores`), the prune passes
  (`privacy::upkeep_stores`: raven-node every 10 minutes, ash when no node answers; they also
  finish a pending scrub) and, as a fallback, the store's open. Only in a sealed profile with its keys loaded: a profile that is not sealed keeps the clear
  schemas, as its files keep today's bytes. ash's upgrade interlock (R11): a store that still has
  to move is left while an older raven-node answers, and the app rows' epoch move waits with it
  (opening the store would move it).
- **Version by shape** (R06): an open reads `user_version`, the `raven_schema` row and the key
  table's columns; a keyed table under another `user_version` (an older process stamped its own
  number) is stamped again (`sqlite_rebuild::restamp`), never migrated twice. The index names are
  kept, so an older build's `CREATE ... IF NOT EXISTS` batch is a no-op on a migrated store and its
  writes fail closed ("table ... has no column named ...").
- **`owed_acks.sqlite`**, schema 1 -> 2 (section 7.1). Every query binds the keyed value
  (`has_room`, `record`, `clear`, `drop_peer`, `add_held`); `list` deletes by
  `prune_after_hour <= hour(now)`, then decides with the exact expiry from each row's `meta`, and
  computes the order (recorded, digest) after opening.
- **An older build's set-aside** (R06): an older build renames a schema-2 store
  `owed_acks.sqlite.corrupt-<ms>` and starts an empty clear one (push-only rows rebuilt from the
  session store). This build, under `.owed_acks_aside.lock.sqlite`, merges every set-aside that
  opens as this profile's schema 2 (every row's sealed values open here): live rows not already
  present come back within the caps, with the custodian marks of ACKs present, and the set-aside is
  deleted. One that does not (another file, a damaged one, an older build's own clear copy) is
  sealed in place (RMS1 kind 64, `owed_acks_aside`, registered with that lock) and counted by
  `raven privacy status` ("Kept encrypted for inspection: ...", `privacy::store_status`). The
  merge runs with every store move pass and after an open that had to move a clear store.
- **`app_channel.sqlite3`**, schema 2 -> 3 (section 7.2): the sender column of `app_inbox`,
  `app_tombstones` and `app_quarantine` becomes `kh_sender`; the sender's identity key, its
  certificate hash and the creation time move into `meta` with the clear sender. (The plan names
  the sender column; the other three name the same sender, so leaving them clear would leave
  `kh_sender` protecting nothing.) The page order and the cursor use `kh_sender`: a total order
  all the same, and the cursor still names the sender in clear (converted at each page). A
  quarantined row keeps its inbox `meta` byte for byte (label `app_inbox`). `app_outbox` and
  `app_pair_attempts` are unchanged (section 7.2, open item).
- **Keys**: a store handle takes the keys this process holds when it opens (one
  `at_rest::keys_cached`, never the keystore); a `meta` that names an epoch the handle lacks (a
  rotation since) is read with the keys held now; a write with keys a rotation has just replaced
  seals under the older epoch, which stays readable through the grace and is sealed again before it
  goes (R04). A sealed profile without its keys loaded: the open fails (`OwedError::KeyUnavailable`,
  `app_store::STORE_KEY_UNAVAILABLE`); nothing is created or set aside, and nothing is read in
  clear. `MetaKeys` now derives each loaded epoch's data keys once (an HKDF per row blob cost more
  than the cipher).
- **Rotation** (PP.10): `privacy::reseal_everything` re-seals both stores' `meta` (and the owed ACK
  bytes) not on the current epoch, one IMMEDIATE transaction per store, then a checkpoint;
  `privacy::rotation_state` counts what is left by first bytes (`owed_acks::rows_off_epoch`,
  `app_store::meta_rows_off_epoch`); a store that cannot be re-sealed now counts as pending, so the
  old epoch waits.
- **The way back** for PP.18: `owed_acks::unseal` and `app_store::unseal`, the same recipe; rows
  whose `meta` does not open here are left out and counted, and the count check expects exactly
  them.
- **Timing** (development Mac, release build): sealing adds about 20-25 µs per owed ACK or app
  item (two AEAD seals with random nonces per row, two opens per listed row). A commit that really
  reaches the disk costs about 5 ms there (SQLite `fullfsync`), so that is far within 10%; with
  macOS's default fsync (about 60 µs a commit) the CPU-bound, list-heavy test mix shows about 1.1x
  for the app store and 1.1-1.3x for owed ACKs. The (ignored, by-hand) timing tests bound the added
  time per item (60 µs).

### 4.11 SQLite stores 2: the session store's heads, resets and session ends (PP.13)

No gate (at-rest; the owner's storage choice). Code: `rc/indexed_session_store/sealed.rs` (the
layout, the schemas of both shapes, the migration both ways, the rotation and status parts) and
the store's own queries in `indexed_session_store.rs`, `reset.rs`, `horizon.rs`, `custody.rs`
and `deleted.rs`. Column targets: section 7.3.

- **Schema 2** in a sealed profile (`METADATA_SCHEMA_VERSION` 1 -> 2, raised on purpose; the
  test that pinned 1 became `metadata_schema_version_is_2_sealed_and_stays_1_plain`, renamed for
  schema 3 by PP.14). A profile that is not sealed keeps schema 1, which every older build
  opens. Six tables change shape:
  `indexed_session_heads`, `indexed_session_reset`, `endpoint_reseal_ledger`,
  `peer_reset_state`, and the cutoff pack's `peer_session_end` and `peer_session_end_erased`.
  Addresses are keyed as `rvn1-address`, device keys as `device-key`, the ledger's message ids
  as `message-id`; every clear value and every time is in the row's sealed `meta` (AAD: the
  table and the primary key as stored), each time exactly as schema 1 holds it. The endpoint
  tables kept their columns in schema 2; PP.14 keys them (schema 3, section 4.12).
- **Kept clear** (review R20): `record_key`, `session_id`, `binding_digest`, `init_hash`,
  `generation`, `init_id`, the constant `profile_id`, `initiated_local`, `retire_cause`, the
  ledger's `reseals` and `notified`. **Coarse clear times**: the heads' `created_hour` (rounded
  down) and `prune_after_hour` (rounded up); the ledger's and the session ends' `prune_after_hour`
  (the instant the row goes, rounded up). The reset table keeps a 0/1 flag where schema 1 tests
  a time for NULL (`confirmed`, `reset_round`, `retired`).
- **Every lookup keeps its behaviour.** A peer lookup binds the keyed device and the hours that
  may still be live (`prune_after_hour > hour(now)`), then opens each candidate's `meta`, drops
  what expired by the exact time, and sorts with the tie-break both nodes share
  (`created_at_ms DESC, init_id DESC`): the SQL orders by `created_hour` at most, never by a
  keyed column (each profile has its own key). `head_expires_at_ms` is still an equality on the
  six identity columns (the four keyed ones bound keyed). The prunes take the hours that may
  have passed (`prune_after_hour <= hour(now) + 1`) and decide with the exact time from `meta`,
  so nothing goes early and nothing late; a `meta` that does not open goes by its hour alone.
  What one UPSERT does in schema 1 (the reset row, the peer state, the ledger, the session end,
  the removal mark) is a read, a change and a write of the row in one IMMEDIATE transaction. The
  metadata-only reads (expiry before the archive, the horizon, custody's heads) open `meta` with
  K_meta: no keychain item, no protected session state.
- **When it moves.** The open reads the version, the `raven_schema` row and the heads' shape
  (R06) and refuses anything newer; every write there (creation, the stamp of a store from
  before versioning, a re-stamp) runs in an IMMEDIATE transaction that reads the version again,
  and an open with nothing to write takes no write lock. A sealed profile's first store is
  created at schema 2. A clear store in a sealed profile moves after the open's
  `recover_all_pending_acceptances` has replayed every journal on schema 1, and not while any
  session's protected state still holds an acceptance, ACK or outbound journal (another instance
  may have staged one since): the move waits for the next open or prune pass. The eager half is
  `privacy::migrate_all` (after it releases the at-rest lock: the open reads each session's
  protected state) and the prune passes (`upkeep_stores`), through a full open; the upgrade
  interlock (R11) holds the move back while an older raven-node answers.
- **The recipe** of section 4.10 (a dedicated connection, foreign keys off before the
  transaction, rowids kept, the heads before their reset rows, index names kept, every table's
  count including the seven endpoint tables that refer to the heads, `foreign_key_check`, then the
  scrub). Too little free space defers the move (the store works in schema 1); any other failure
  fails the open (closed). The way back (`indexed_session_store::unseal`, for PP.18) refuses
  while a journal is pending; the rows that do not open are left out and counted; a head whose
  `meta` does not open goes with every row of its session and its protected state (review
  B-sealed-stores-3, section 4.22; it stopped the way back and the re-key before).
- **Keys**: as section 4.10 (a handle takes the keys at open, re-reads them for a `meta` on an
  epoch it lacks). Without the key a schema-2 store, and the read-only view
  (`SessionMetadataReader`), fail with `MetaKeyUnavailable`; nothing is created.
- **Rotation**: `reseal_rows` re-seals every `meta` not on the current epoch (a metadata-only
  connection, one IMMEDIATE transaction, then a checkpoint); `rows_off_epoch` counts them for
  `rotation_state`; the scrub state joins `raven privacy status`.
- **Tests**: `indexed_session_store::tests::sealed_store` (the populated fixture with a row in
  every table moved with every rowid and the same answers to every read; the cross-node order on
  two profiles; the journal wait; a stop before every statement, both ways; count, disk-full and
  free-space faults; older builds; the key; the byte scan; a rotation; the sealing pass) and the
  schema guard `no_clear_key_address_or_message_id_columns`, which fails for any column of a
  fresh session, owed-ACK, app or custody store whose name says it holds a key, an address, a
  peer, a message id, a digest or a nonce and is neither keyed nor listed with its reason. The
  whole suite also runs on keyed stores: `RAVEN_TEST_SEALED_SESSIONS=keyed` (a sealed profile's
  store from its creation) or `=migrated` (each store created at schema 1 and moved at its first
  open), read by test builds only.

### 4.12 SQLite stores 3: the session store's endpoint tables and the chat cursor (PP.14)

No gate (at-rest; the owner's storage choice). Code: `rc/indexed_session_store/endpoints.rs` (the
endpoint tables' schemas in both shapes, their sealed values, the rows read in either shape, the
inbox order, the migration both ways), the store's queries in `indexed_session_store.rs`,
`deleted.rs`, `reset.rs` and `custody.rs`, and ash's chat cursor (`ext.rs`). Column targets:
section 7.3.

- **Schema 3** in a sealed profile (`METADATA_SCHEMA_VERSION` 2 -> 3, raised on purpose; the test
  that pinned 2 became `metadata_schema_version_is_3_sealed_and_stays_1_plain`, now
  `metadata_schema_version_is_4_sealed_and_stays_1_plain`: section 4.22). The receipts, the
  inbox, the ACK intents, the outstanding messages, the ACK receipts, the outbox and PP.8's
  tombstones hold their message ids, object digests (`source_ack_intent` too), device keys and
  wire nonces as `kh_*` of their value type, in every primary key, UNIQUE constraint and foreign
  key (equal values, equal keys); every clear value and time is in the row's `meta` (AAD: the
  table, the session id and the keyed key columns, as stored). The stored wire objects
  (`endpoint_outbox.immutable_envelope_bytes`, `endpoint_ack_intents.immutable_ack_bytes`) are
  sealed whole (AAD label `<table>.<column>`) with `kh_envelope` / `kh_ack` (`object-bytes`, the
  exact bytes) beside them: the handoff's `... AND immutable_envelope_bytes = ?`, the ACK
  intent's `... WHERE immutable_ack_bytes = ?` and its set-once `IS NULL OR = ?` compare the
  digests (review R20: a random-nonce seal is never equal twice). `endpoint_inbox.sealed_local_row`
  is not sealed again: it is under the session's key, its AAD binds the clear session id, object
  digest, message id and sender device (the reader takes them from `meta`), and a journal's
  replay compares its bytes exactly. Kept clear: `session_id`, `kind`, `state`, `status`,
  `delivery_state`, `ratchet_index`, `session_generation`. Rowids are kept (the prepared and
  waiting messages, the ACK intents and the first copy of an object to a contact are listed by
  rowid).
- **One SQL text, both shapes.** The endpoint SQL is written with the keyed names; `Layout::ep`
  gives the clear names in schema 1 and in a PP.13 build's schema 2 (its endpoint tables clear;
  it works as it is until it moves), and the values are bound in their stored form. Rows are read
  in either shape into the clear values schema 1 holds, so every check after the read is the same
  code; a `meta` that does not open is that row's `CorruptEndpointState` (the inbox listings and
  deletions go on past it, logged; the stamp floor skips it), a key not loaded is store-wide
  (`MetaKeyUnavailable`).
- **The inbox order.** A keyed message id and a sealed time cannot serve the clear pager
  (`received_at_ms, message_id > ?`), so the schema-3 inbox has `seq INTEGER PRIMARY KEY
  AUTOINCREMENT` (its rowid: never used twice, even after the newest row goes) and an index
  `(kh_sender_device, seq)`. `list_endpoint_inbox_for_sender_after(peer, after, limit)` takes an
  `InboxPosition` (`order`: `Seq` in schema 3, `Received` = `(received_at_ms, message_id)` in a
  clear store) and each row carries its own `position`. `resolve_inbox_position` places a
  `Received` position (a cursor saved before the move) in the `Seq` order: the rows after it are
  those stamped after it, which are the sender's newest by `seq` (`monotonic_received_at_ms`
  stamps in insertion order per sender), so it becomes the `seq` just before the oldest of them,
  or the newest `seq` the store has given (`sqlite_sequence`) when there is none: a cleared chat
  stays cleared and every later row is listed once. A `Seq` position in a clear store (moved back
  while a reader held it) goes to the start: nothing is lost, rows already read may be listed
  again (PP.18 places the cursors before it moves the store back). `monotonic_received_at_ms`
  reads the stamp of the sender's newest row by `seq` and of the tombstones at or after it (each
  tombstone keeps the deleted row's `seq`; the move places an older tombstone after the sender's
  newest row stamped before it). The listings that were oldest first by `received_at_ms` take the
  rows by `seq` and sort by the time from `meta`; the retention cut opens each row's `meta`; a
  deletion up to a reader's place takes `seq <= ?`.
- **The chat cursor** (ash): `InboxCursor` is the store's `InboxPosition`. A
  `chat_inbox_cursors.json` entry (RMS1 kind 9 since PP.6) is format 2, `{"seq": n}`, for a
  schema-3 store and keeps format 1, `{"received_at_ms", "message_id_hex"}`, for a clear one (an
  older build opens a plain profile's file). The chat places a format-1 cursor once when it opens
  and saves it in format 2; a position of the newer order sorts after every one of the older, so
  a store that moves while a chat is open moves the chat forward only. "Delete chat" deletes up
  to the cursor's position. The terminal app's read markers (message ids) are unaffected.
- **When it moves**, as section 4.11: the open, after its journal recovery and never while a
  journal is pending, and the eager and prune passes; from schema 1 and from schema 2 in one
  IMMEDIATE transaction (`sealed::migrate_forward`: PP.13's six tables when the heads are clear,
  then `endpoints::move_forward`), every table's count and `foreign_key_check` before the commit,
  then the scrub. `needs_migration` is true below schema 3. The way back (`unseal`, PP.18) moves 3
  (or 2) to 1, recreating exactly the columns older builds create; a receipt whose `meta` does not
  open is left out with the inbox row and the ACK intent that refer to it.
- **Rotation**: every sealed value (each `meta`, and the two sealed wire objects) not on the
  current epoch is sealed again by `reseal_rows` and counted by `rows_off_epoch`.
- **Tests**: `indexed_session_store::tests::sealed_store` adds the move of a PP.13 build's schema-2
  store with every row (`a_schema_2_store_moves_to_3_with_every_row`) and a stop before each of its
  statements, `blob_equality_queries_still_match_after_sealing`, `rowid_order_preserved`,
  `journal_replay_after_migration_matches_sealed_inbox_bytes`,
  `cursor_v1_maps_to_seq_and_nothing_is_shown_twice`,
  `a_cleared_chat_stays_cleared_across_the_migration`,
  `duplicate_after_migration_gets_the_same_ack`, `a_damaged_inbox_meta_is_skipped_not_fatal`,
  the SQL names (`endpoint_sql_names_the_clear_columns_in_a_clear_store`), the clear schema of
  the way back (`clear_endpoint_columns_are_exactly_schema_1`) and the timing test; the byte scan now covers
  the whole file and WAL (no address, device key, message id, object digest or ACK nonce of the
  run) and the schema guard has no PP.14 allowance left. Carrier matrix C87 part 2 reads every
  SQLite store's raw bytes in a copied data dir (WAL and free pages included): no friend key (raw,
  hex, base64), rvn1 address, PeerId, IP address, petname or message id of the run (raw or hex).
  The whole suite runs on keyed stores too (`RAVEN_TEST_SEALED_SESSIONS=keyed|migrated`); six
  tests that write clear columns by hand turn it off for their thread.
- **Timing** (development Mac, release build, `endpoint_timing_within_ten_percent`: 200 messages
  accepted, listed by position and acknowledged, in-memory protected backend): 0.93x to 1.09x
  the clear store's time in five runs, 0 to 150 µs added per message (about 1.5 ms each);
  the test bounds the added time (400 µs per message). The fault-matrix harness opens a sealed
  envelope with the profile's epoch key (`open_row`, checked against raven-core's pinned row
  vector) where s122 replays one.

### 4.13 Lock now v1 (PP.15)

No gate (a local command: nothing changes for anyone who does not type it). Code: `ash/node_control.rs`
(new: the stop step and Raven's own login item), `ash/cli.rs` (`raven lock`, `raven unlock`, the
status and doctor lines, `raven listen`), `ext::ensure_mac_lan_daemon`, `rc/privacy.rs`
(`lock_state`, `set_locked`, `set_unlocked`, `clear_lock_login_item`). Lock v2 (IPC Lock/Unlock that
drops the cached keys, auto-lock on sleep, a Raven passphrase on macOS and Windows) is Phase 6
(P6.40, gate `LOCAL_PROTECTION`).

- **The stop step** is the terminal app's (UXF.7, OD-16), moved out of `tui/node.rs` into
  `node_control.rs`, and the app now runs it from there (through `tui/bridge.rs`), so `raven lock`
  and the app's Lock stop a node the same way: a Status just before; on Unix SIGTERM to the pid it
  reports (the endpoint is per profile); on Windows `taskkill /F` only for a pid this app started
  (the pipe is per user), otherwise the profile's stop advice.
- **Raven's own login item.** The installers create one per OS user, not per profile:
  `~/Library/LaunchAgents/com.raven.raven-node.plist` (label `com.raven.raven-node`, `RunAtLoad`
  and `KeepAlive`), `~/.config/systemd/user/raven-node.service` (always `~/.config`;
  `Restart=on-failure`), the per-user scheduled task `RavenNodeBridge` (at logon, restart count
  999). `node_control::own_login_item` counts it as this profile's only when it runs `raven-node
  service` and its `--data-dir` canonicalizes to this data dir (the plist's `ProgramArguments`,
  the unit's `ExecStart` words with the installer's quoting, the task's XML from `schtasks /Query
  /XML`). Another profile's item, or a file at the same name that someone else wrote, is never
  read further or touched.
- **`raven lock`** (`[y/N]` on a terminal; `--yes` for scripts, and without a terminal it needs
  it). The question depends on the keystore: a passphrase-vault profile is really locked (the next
  start needs the passphrase), with a paragraph when the passphrase is saved in a file (the
  first that is there of: `RAVEN_KEYSTORE_PASSPHRASE_FILE`'s, the systemd credential
  `$CREDENTIALS_DIRECTORY/raven-keystore-passphrase`, the file Raven's own systemd unit hands
  raven-node, from its `Environment="RAVEN_KEYSTORE_PASSPHRASE_FILE=..."` or `LoadCredential=
  raven-keystore-passphrase:...` line, which the user's shell need not name (review D-lock-tui-3),
  and PASSFILE's default; `raven erase` lists the same file as not erased); a keychain or DPAPI
  profile is only stopped, and the text says that anyone logged in as the user can still open the
  chats. The lock is recorded first (`privacy.json` `locked_by_user`), so no send in another
  window starts Raven while it stops. When Raven's own login item runs this profile, the user is
  asked whether to keep Raven stopped at the next login (`--keep-stopped` answers yes for
  scripts; `--yes` alone means no), and either way the item is unloaded for this login session
  (review R16: launchd's KeepAlive starts a killed node again within about 10 s): `launchctl
  bootout gui/<uid>/com.raven.raven-node`, `systemctl --user stop raven-node.service`, `schtasks
  /End /TN RavenNodeBridge`, recorded as `lock_login_item: unloaded`. Then the stop step for
  whatever still runs the profile, and the node must be gone within 5 s (no IPC answer, the
  instance lock free): otherwise the lock is taken back and the user gets the stop advice (or,
  when another process answered after the stop, "Raven is run by a service Raven didn't install,
  so Lock can't stop it: ... Lock your screen or log out."). Only once Raven is gone does a yes
  also turn the item off: `launchctl disable ...` (lasts across logins), `systemctl --user
  disable --now ...`, `schtasks /Change /TN RavenNodeBridge /DISABLE`, recorded as
  `lock_login_item: disabled` (review D-lock-tui-4: an item turned off before a stop that failed
  stayed off, unsaid, so Raven stopped starting at login though nothing was locked). The last
  line says "Raven is stopped until you log in again." only while the item is not recorded as
  off (one an earlier `raven lock` turned off stays off whatever the answer).
- **Auto-start honours Lock.** `ext::ensure_mac_lan_daemon` (the send path; the terminal app's
  start too: opening the app clears only the app's own Lock and asks before it clears one `raven
  lock` set, section 4.20) and
  `raven listen` start no raven-node while `locked_by_user` is set: "Raven is locked. Run `raven
  unlock` to start it again." (the send path: `NOT SENT, nothing queued: ...`). A node that runs
  anyway (started at the next login by an item Lock left on) is used as it is.
  `raven status`'s first line while locked and no node answers: "Raven is locked (stopped). Run
  `raven unlock` to start it again."; `raven doctor`: `lock: locked_by_user=0|1` (and
  `login_item=` while one is recorded).
- **`raven unlock`** clears `locked_by_user` first. When the lock unloaded or disabled Raven's own
  item, it is turned back on and started (`launchctl enable` + `launchctl bootstrap gui/<uid>
  <plist>`, `systemctl --user enable --now`, `schtasks /Change /ENABLE` + `/Run`; only the
  `enable` when a node already answers), and Raven must answer within 20 s; the record is cleared
  once it does. Otherwise Raven starts as a send starts it.
- **The tools** run by absolute path (`/bin/launchctl`; `/usr/bin/systemctl` or `/bin/systemctl`,
  else a PATH lookup; `%SystemRoot%\System32\schtasks.exe`), with no input and no shell. A debug
  build reads and runs none of the real ones: only with `RAVEN_LAB_LOGIN_ITEM_ROOT` (the item's
  file is looked for there; on Windows `RavenNodeBridge.xml`) and `RAVEN_LAB_LOGIN_ITEM_TOOLS`
  (fake tools) set, else `raven lock` refuses (and so does `raven unlock` when it would touch the
  item). A release build never reads them.
- **Installers.** `macos_launchd.sh` runs `launchctl enable` before `bootstrap` (a re-install
  after Lock's `disable` was refused by bootstrap and aborted under `set -e`);
  `windows_service.ps1` enables the task after registering it (CI: a disabled task is enabled by
  a re-install). The Linux installer already enables its unit.
- **Tests**: `node_control::tests` (the stop table, the guard, the item only for this data dir and
  as each installer quotes it, the exact arguments through fake tools, the macOS installer run
  for real in a temp home with fake `cargo`, `install` and `launchctl`), the CLI's
  (`lock_on_macos_always_boots_out_even_on_no`, `lock_disables_and_unlock_reenables_through_the_shims`,
  the texts per profile type, a node that does not stop is not locked, unlock without an item),
  ext's `send_while_locked_does_not_start_the_node`, black-box `cli_failure_paths` (`--yes` and
  the non-terminal refusal, the debug guard, status/doctor/listen while locked), raven-core's
  `privacy::lock_tests`, and fault-matrix s121 (`lock_v1_with_queued_messages`).

### 4.14 Erase this profile (PP.16)

No gate (a local command: nothing changes for anyone who does not type it; OD-PP-8 (a)). Code:
`rc/erase.rs` (new: refusals, the marker, the plan, the deletes), `ash/cli.rs` (`raven erase`, the
refusal at every command's top), `ash/node_control.rs` (`remove_login_item`), `ext::auto_start_refusal`,
raven-node's `main` (the refusal at start), and the marker checks below.

- **Only on a terminal, only typed.** The UX copy's question ends with "Type erase to confirm:";
  the word is read with `read_decision_line` (queued terminal input is dropped first) and taken in
  any case, also typed on a Persian keyboard layout (silent tolerance). An answer that comes within
  300 ms of the prompt (pasted) is refused and the prompt repeats; EOF or any other word cancels.
  Without a terminal: "raven erase needs a terminal: type erase to confirm." Never one key, never
  remote, never from a message.
- **Refusals first (nothing changed).** `erase::refusal`: the folder must be a Raven profile (an
  identity on record, the marker of an unfinished erase, or one of the files only Raven writes:
  `meta_key.rmk`, `privacy.json`, `keystore.vault`, `keystore.backend`, `identity.seed`,
  `chat_history_key.dpapi`, `indexed_sessions.sqlite`, the service log, the socket lock; a file any
  program could name, such as `contacts.json`, is no proof), never the home folder, a folder above
  it or a filesystem root ("This folder doesn't look like a Raven profile, so erase won't touch it:
  {folder}"), and in a debug build strictly inside `RAVEN_LAB_ERASE_ROOT` (canonical paths; no
  switch refuses). There is no list of owner paths in product code.
- **Step 1, the stop.** Raven's own login item for this profile (`node_control::own_login_item`)
  is unloaded for the session, then the stop step; the node must be gone within 5 s (no IPC
  answer, the instance lock free), else "Raven is still running, so erase can't continue: ..."
  with the stop advice and nothing is changed (the item stays, only unloaded for this session).
  Only then the plain marker `erase_in_progress` (fsynced with its folder). A node that answers
  once more is stopped again, or the marker is taken back (nothing was erased yet). Then the item
  is turned off (`launchctl disable`, `systemctl --user disable --now`, `schtasks /Change
  /DISABLE`) and removed (the plist or unit file, then `systemctl --user daemon-reload`; `schtasks
  /Delete /TN RavenNodeBridge /F`): it names the data dir, the listen addresses and the relays. A
  removal that fails keeps the marker (reported; `raven erase` again retries it).
- **The marker closes the profile.** While it exists every entry point of this build except
  `raven erase` refuses with "An erase of this Raven profile did not finish. Run `raven erase` to
  finish it.": every ash command at its top (before the folder is made, a key loaded or anything
  sealed; the terminal app included), the send path's auto-start (`ext::auto_start_refusal`, also
  the app's start), raven-node at start (every command with a data dir, so a login item that
  starts it anyway ends there), and inside raven-core every Raven lock or store opened in the
  folder (`paths::prepare_private_data_dir_sqlite_file`: `DataDirLock`, the chat-history and
  key-init locks, owed ACKs, the app store, custody), the session store, the prekey store,
  `init_protected_key` (K_hist is never minted again) and `at_rest::create_key_file`. So a Raven
  process still open on the profile refuses its next operation and nothing is recreated.
- **Step 2, crypto-erase first** (`erase::plan`, then `execute`). K_hist: the keychain / Secret
  Service item `app.raven.node.chat-history.v1` with this dir's account, Windows'
  `chat_history_key.dpapi`, and the passphrase vault `keystore.vault` (deleted whole: it holds
  K_hist and every other key of the profile, and no passphrase is needed). From then on
  `meta_key.rmk`, and with it every sealed file, SQLite meta blob, the history, the stage and the
  app rows, are unreadable. Then the identity item (`app.raven.node.identity`), every per-session
  item (`app.raven.node.atsam-indexed-session`, account `<ns>:<hex(record_key)>`, rebuilt from the
  store's record keys, which stay clear; then, on macOS and Linux, every keychain or Secret
  Service item of the service whose account starts with `<ns>:`: an item whose head was never
  recorded, and all of them when the store's record keys can't be read; on macOS an
  attribute-only search, which reads no secret, since review C-deletion-erase-1), the prekey item
  (`app.raven.node.prekey-lifecycle`) and the key files of Windows and the lab backends
  (`indexed-session-secrets/`, `prekey-lifecycle-secrets/`, `prekey_lifecycle.protected`). Every
  account is derived from this data dir only. The OS keystore's items are planned only where this
  build's backends use it (not in a unit test, a debug build with a `locked-file` backend, a vault
  profile or on Windows). The macOS deletes and the search go through `macos_keychain::guarded`
  (`keychain_guard_check.sh` allow-lists `erase.rs:keychain_delete_item` and
  `erase.rs:keychain_accounts`); whether a delete of an item another binary created shows a dialog,
  and that the search shows none, is checked in the owner's real row R34.
- **Step 3.** `meta_key.rmk`, `identity.seed`, `device_x25519.secret`, `lab_device_x25519.secret`,
  `relay_key.ed25519` and `friend_relay/relay_key.ed25519` (only while `friend_relay` is a real
  folder, not a link: review C-deletion-erase-2), and an interrupted write's temp copy of one
  (`.<name>.tmp.<16 hex>` beside it), get zeros over their length (fsynced), then go: hygiene only
  (on APFS and SSDs an overwrite lands in new blocks).
- **Step 4, Raven's files only.** Registry-driven: every name and pattern of `at_rest::FILES` with
  `erase: yes` (since PP.16 the relay-folder entries too: in a profile a relay ran in they are
  Raven's; a dedicated relay folder has no identity and is refused) and a quarantine copy of one
  (`<file>.corrupt`, `.corrupt-<n>`, `.corrupt.<n>`) or an interrupted write's temp file beside
  one (`.<file>.tmp.<16 hex>`); inside Raven's own folders (those the registry names files in) the
  same rule (the temp files there since review C-deletion-erase-3: before, they were listed as
  files Raven didn't create). A symbolic link is deleted as a link and never followed: a file is
  deleted only while every folder on its way from the data dir is a real one, so a link put in
  place of a folder after the plan was made is refused and reported (review C-deletion-erase-2).
  A pass then looks again for a file a process finished writing after the marker went down (its
  next write is refused) and deletes it. Raven's folders go once empty.
- **Step 5.** This profile's `raven-node.sock` and `raven-node.sock.lock`, or in the long-path
  fallback only `/tmp/raven-<euid>/raven-<hash>.sock` and its `.lock` (the folder is shared by every
  profile of the user and stays). Then the marker, last, and the folder when it is empty.
  Unknown files stay: "Left in this folder because Raven didn't create them: {n} files ({folder})."
- **Failures** do not stop the run: each is reported ("Erase stopped: {what failed}. Still on
  this computer: {list}. Run `raven erase` again to finish."), the marker stays, and the next run
  makes its plan from what exists. A run in which a conversation key could not be deleted (a
  locked keychain, a denied dialog), or the store's record keys could not be read and no
  namespace pass got through, keeps `indexed_sessions.sqlite` and its `-wal`, `-shm` and
  `-journal` (they name those keys; the list says `indexed_sessions.sqlite`), so the next run
  names the same items and never says Erased while one may be left (review
  C-deletion-erase-1). The result: "Erased: identity, friends, chats, waiting
  messages and {n} keys. Not erased: your shell history and terminal scrollback; Time Machine
  backups and disk snapshots, if any; the passphrase file you made ({path}) [a vault profile
  whose file exists]; files copied elsewhere."
- **Tests**: raven-core `erase::tests` (the plan names every item of profile A and none of B; the
  key root goes before any file; unknown files and the folder stay; the refusals; the debug
  guard; the marker blocks every lock, store, K_hist and the key file; no process mints K_hist
  while a writer thread runs through the erase; a failure part-way reports what is left and a
  rerun finishes; a copy of the sealed folder taken before the erase opens with nothing after;
  only this profile's fallback socket files go; review C-deletion-erase: a conversation key that
  stays keeps its store, WAL included, for the next run, and the namespace pass takes a head-less
  item and nothing of another profile; a damaged store never ends in Erased while its keys may
  stay; a linked `friend_relay` and a link put in place after the plan are not followed; temp
  files in Raven's folders go, a key's with its overwrite),
  `lan_dispatch::tests::b_still_sends_and_receives`
  (in-process), ash's (`paste_guard_and_non_tty_refusal`, `erase_refuses_while_the_node_still_answers`,
  `failed_stop_leaves_the_profile_usable_and_unmarked`, `after_erase_nothing_of_a_remains_in_the_temp_home`
  on all three systems through the shims, `a_login_item_that_stays_keeps_the_erase_open`, the texts,
  ext's `send_during_an_unfinished_erase_does_not_start_the_node`), black-box `cli_failure_paths`
  (`guard_refuses_live_profiles`, `marker_blocks_every_other_entry_point`), `tui_pty_smoke`'s
  `erase_on_a_terminal_takes_the_typed_word` (a real pseudo-terminal), raven-node's
  `cli_robustness::an_unfinished_erase_closes_the_profile`, carrier_matrix C91 and fault scenario
  s117 (both Unix: the word comes through a pseudo-terminal).
- **The terminal app** erases the same way, from Settings (PP.22, section 4.19).

### 4.15 Custody minimisation (PP.17)

Behind the existing `FRIEND_CUSTODY_PRODUCTION_ENABLED` (false) and its lab switches
(`RAVEN_LAB_TEST_A=1`; the fault matrix's `RAVEN_FAULT_CUSTODY=1`): custody does not run in
release, so nothing changes there. The spec text is the unsigned
`docs/SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md` (Approver: Protocol owner); the
frozen `protocol/SECURITY_ERRATA_RVN1_2026-08-13.md` and `protocol/RAVEN_FRIEND_CUSTODY_V1.md` are
unchanged until it is signed, and the custody flip waits for that signature (OD-PP-6). Code:
`rc/friend_custody.rs` (`CustodyStore`), the privacy passes in `rc/privacy.rs`, ash's consent text.
Column targets: section 7.4.

- **RELEASE deletes.** `CustodyStore::release` for the link-authenticated recipient naming exact
  digests: in one IMMEDIATE transaction each matching row is deleted (its payload, recipient,
  depositor, size, store tag, page token and both times) and its digest is written to
  `custody_released_v1` with the hour the object would have expired in (`prune_after_hour`,
  rounded up), then `checkpoint_truncate` (busy: the next maintenance). `secure_delete` (PP.2)
  overwrites the deleted cells and freed pages. A replay of a released digest (any tag) is a
  `DUPLICATE` until that hour has passed, then the deposit's purge or the maintenance drops the
  digest (custody admission refuses the expired envelope anyway); FETCH after RELEASE returns
  nothing; another recipient's digest, an unknown one or one released before changes nothing. In a
  plain profile the same, with the clear digest (the table is additive: version 1 stays, older
  builds never read it).
- **Open rows, schema 2** (a sealed profile; a plain one keeps schema 1): `kh_object_digest`,
  `kh_recipient`, `kh_depositor`, the payload sealed whole (`custody_objects_v1.rso1`, AAD the
  keyed digest), `meta` (the clear digest, both parties, `admitted_at_ms`, `expires_at_ms`), and
  clear `store_tag`, `page_token`, `bytes` and `prune_after_hour`. Every decision keeps its
  answer: FETCH reads the hours not passed and opens `meta` for the hour that may not have (the
  page order and its cursor are the clear page token); the caps count the rows two hours ahead in
  SQL and the edge hour and every row of the depositor (its admission time, for the byte rate)
  from `meta` (a `meta` that does not open counts by its hour, never as recent);
  `held_recipients` (cutoff CP.14) and the maintenance's "still a pinned contact" read the
  parties from `meta` (one per pair). The payload stays the sealed envelope it was on the wire
  (end to end); its clear RSO1 header is inside the sealed blob.
- **Migration.** `user_version` 1 -> 2 and back with the recipe of section 4.10 (both tables in
  one transaction, rowids kept, counts checked, the scrub); version by shape (an older build stamps
  `user_version = 1` after its `CREATE TABLE IF NOT EXISTS` batch, which is a no-op on the moved
  table, its index names kept: `restamp`, and its writes fail closed). An older build's released
  row (payload kept until expiry) becomes a released digest: its row goes in the migration, and in
  a plain profile at the next maintenance. When: `privacy::migrate_all` and the prune passes
  (`move_stores`, the upgrade interlock included), and the store's open. Too little free space
  defers it (the store works in schema 1). Without the profile's key a sealed profile's store
  does not open (custody answers `PERSISTENCE`); nothing is created.
- **The way back** (`unseal`, for PP.18): open objects come back in clear; released digests are
  left out and counted (only their keyed form exists). Rotation: `reseal_rows`,
  `rows_off_epoch`; the scrub joins `raven privacy status`.
- **Consent** (`raven node custody on`): "This computer will hold sealed messages for two of your
  verified friends who both chose you. It can't read them, but it learns who wrote to whom and
  when. Raven envelopes are signed, so a copy is proof that one friend wrote to another. Raven
  deletes each message as soon as it is collected, and at the latest after 24 hours." It is shown
  only while the custody gate is live; while it holds, the hold line is shown instead. Phase 3
  (P3.21, P3.C4) replaced it with `CUSTODIAN_CONSENT` in `node/crates/ash/src/custody_cli.rs`:
  a message stays until the recipient's Raven confirms it collected it (RELEASE), or until it
  expires (at most 24 hours), and while it is held the signed envelope is proof of who wrote to
  whom, when, and how much.
- **The lab replay** for the fault matrix: `ash lab custody-deposit` (hidden; debug builds with
  `RAVEN_LAB_TEST_A=1`, through raven-node's LanDial, which takes RFC1 only in a lab run).
- **Tests**: `friend_custody::tests` (on a plain, a sealed and a migrated store:
  `release_deletes_payload_and_pair_columns_and_keeps_the_digest`,
  `redeposit_after_release_is_a_duplicate_until_expiry`, `fetch_after_release_is_empty`,
  `custody_file_byte_scan_after_release_has_no_friend_key`; the migration with an older build's
  released row, a stop before every statement, the count check, disk-full and free-space faults,
  the older build's refusal and re-stamp, the reverse round trip, the key, a rotation, the edge
  hour, the sealed maintenance), the schema guard (custody's allowances removed), ash's
  `custody_consent_says_signed_and_deleted_once_collected`, and fault scenario s125
  (`custody_release_deletes`, `RAVEN_FAULT_CUSTODY=1`).

### 4.16 The privacy commands (PP.18)

No gate (local, user-invoked, never from a message, an advisory or a remote request). Code:
`rc/privacy/manage.rs` (`report`, `unseal_all`, `seal_now`, `rotate_meta`,
`forget_moved_aside`), the stores' halves (`owed_acks`, `app_store`, `friend_custody` and the
session store's `back_tables` / `forward_tables`, `rekey`), `chat_history::ChatHistory::unseal` and
`unseal_stage`, `app_store::unseal_rows`, `node_policy::unseal_peers`,
`lan_noise_pin::unseal_into_plain`, `at_rest::begin_meta_rotation` and `delete_key_file`; ash's
`raven privacy ...` and `raven doctor`'s `privacy:` line.

- **`raven privacy status`** adds, to PP.10's block: the databases in the "Encrypted on this
  computer" count, a line first while a key change or an unsealing did not finish, the unsealed
  line, the files not encrypted yet, the "older version" note (not consumed here) and the
  plaintext histories an older build moved aside. `--json`: one object, `{"v":1, "mode", "state",
  "files": {"sealed", "plain"}, "stores": [{"file", "user_version", "keyed"}], "chats": {"keep",
  "next_deletion_at_ms"}, "addresses": {"forget_after_days"}, "rotation": {"last_at_ms",
  "old_epoch_held", "due", "old_objects"}, "scrub_pending", "set_aside_stores", "moved_aside",
  "notes", "unfinished": {"unseal", "rotate_meta"}}`: file names, store versions, times and
  counts, never a friend's name, key or address; fields are only added. `raven doctor`:
  `privacy: sealed_files=N plain_files=N keep=30d`.
- **`raven privacy unseal`** (typed `unseal`, `--yes` for scripts; review R12): ash's stop step
  as `raven erase` takes it (Raven's own login item unloaded for the session, SIGTERM to the pid
  Status reports, gone within 5 s, else nothing changes and the stop advice is said), then
  `unseal_all`, every part a no-op once done, so a crash anywhere is finished by running it again:
  the keys are loaded (outside every lock); under the at-rest lock the mode goes to
  `unsealed_by_user` FIRST (no writer seals from then on, no migration runs, and the session
  store's open never moves it forward again); chat cursors saved in the schema-3 order (`{"seq":
  n}`) are placed in the order a build before PP.14 reads (`{"received_at_ms", "message_id_hex"}`
  of the sender's newest row at or before `seq`; the start when there is none) while the store is
  still keyed; every registered sealed file is written back in plain (`unseal_file`; the noise pins
  back to `lan_noise_pins.json`, merged with an older build's plain pins, the sealed pin kept on a
  conflict; the policy's sidecar merged back into `node_policy.json`); the history goes back to
  RVNHIST1 with every `stored_at_ms` dropped, the stage to RVNOSTG1 and the app rows to the
  chat-history key directly, on Windows all three DPAPI-direct (a build before PP.11 knows no
  K_hist and no tag; `windows_key::seal` writes DPAPI-direct in an unsealed profile, so later
  writes stay readable to it); owed ACKs to schema 1, the app store to 2, custody to 1 and, outside
  the at-rest lock (its open replays journals), the session store to 1; `meta_key.rmk` goes last,
  with the records of what was sealed (`kinds`, the rotation records; the sealing notice is due
  again). A history save outside a sealed profile drops `stored_at_ms` whatever the caller. A
  profile without `meta_key.rmk` (never sealed) has only its mode recorded, and on Windows its
  history, stage and app rows that K_hist sealed behind the tag (a debug build's pass without the
  lab switch, or K_hist minted before a sealing that was held back) go back DPAPI-direct with
  K_hist from its file (`windows_key::untag_history`, `untag_stage`, `app_store::untag_rows`; an
  unsealing that stopped after its mode was recorded does it when run again): "This profile was
  not encrypted" only when nothing was written back (review A-keys-format-1).
  Files or rows that do not open with the profile's keys are left as they are and counted. Lock
  files keep their keyed names (an older build creates its own). Every command then says one line,
  "This profile is not encrypted (you ran `raven privacy unseal`). To encrypt it again: `raven
  privacy seal-now`.", and `raven privacy status` says when an unsealing did not finish (the mode
  says unsealed and the key file is still there).
- **`raven privacy seal-now`**: release builds, or debug builds with `RAVEN_LAB_AT_REST=1`; the
  same stop step first (a node running on the unsealed profile holds no at-rest key and could
  neither read nor write it once sealed), then the mode leaves `unsealed_by_user` and
  `migrate_all` runs (files, the stores' forward migrations and scrubs), then `upkeep_stores`;
  not while an older raven-node answers (the upgrade interlock, its restart line); Raven's own login
  item, when it was unloaded, starts Raven again.
- **`raven privacy rotate-meta`** (typed `rotate`): a new `k_index` AND a new epoch, for a profile
  that suspects its keys were copied. The stop step, then: every session-store journal replayed
  under the old keys; under the at-rest lock the keys are read again (review A-keys-format-3: a
  data-key rotation pass in between may have made the next epoch current, which must not pass for
  this command's own), the protected state of each session head whose `meta` does not open goes
  (review B-sealed-stores-3; a failure changes nothing), and the change is recorded in
  `privacy.json` (`meta_rotation`, the new
  epoch one past the newest held); the key file gets the new `k_index` and the new epoch as
  current and KEEPS the old epochs (`begin_meta_rotation`), so the new key is on disk before any
  store uses it and every
  old object still opens; each store is keyed again in one rebuild-recipe transaction (its keyed
  values are primary keys): back to the clear columns and forward under the new keys on a
  connection with `cache_spill=OFF`, so nothing clear is written (`secure_delete` zeroes the freed
  pages before the commit writes them), rowids, the inbox's `seq`, the tombstones' `seq` and the
  inbox counter kept, counts checked, then the scrub; each friend's keyed send-lock file gets its
  new name with both names held, and a keyed lock file no friend in the book has goes unless a
  send holds it; every sealed file, the history, the stage and the app rows are
  sealed again (PP.10's pass); then the old epochs go and the record with them. While the record
  is there the profile is closed: raven-node does not start and ash runs only `rotate-meta`,
  `unseal`, `status` and `erase` (a store may still be keyed under a `k_index` no key file holds);
  PP.10's pass skips it. Running it again finishes it (a store keyed again twice is the same
  store); `unseal` finishes it too. Friend custody's released digests cannot be keyed again and go
  (counted), as on the way back.
- **`raven privacy forget-moved-aside`** (typed `delete`): each
  `chat_history.json.untrusted-plaintext.*` is overwritten with zeros, then deleted.
- **Tests**: `privacy::manage_tests` (`unseal_then_seal_round_trip_on_every_store_and_file`: the
  JSON and secret files byte for byte, the stores' rows, the readers, twice;
  `unseal_is_rerunnable_after_a_crash`, `unseal_is_sticky_until_seal_now`,
  `unseal_refuses_while_a_node_it_cannot_stop_answers`,
  `unseal_strips_stored_at_and_restores_rvnhist1`, `rotate_meta_changes_every_kh_and_keeps_every_lookup`,
  the key change's crash recovery,
  `rotate_meta_changes_k_index_after_a_data_key_rotation_in_its_window`, `status_json_schema`,
  `forget-moved-aside`, the store versions),
  the session store's `rotate_meta_changes_every_kh_and_keeps_every_lookup` (the suite's reads on
  a re-keyed store) and `unseal_places_a_seq_cursor_in_the_received_order`, custody's
  `rekey_keeps_every_open_object_and_lookup`, Windows' `unseal_writes_dpapi_direct_blobs_back`,
  ash's refusal, CLI and text tests, and fault scenario s124 (`downgrade_and_back`,
  `RAVEN_FAULT_PRIVACY_OLD_BIN`).

### 4.17 Harness consolidation, docs and the real row (PP.19)

No code change outside the harness; no gate.

- **Fault matrix** (`scripts/lan_fault_matrix.py`). New **s120 `seal_migrates_an_old_profile`**
  (with `RAVEN_FAULT_PRIVACY_OLD_BIN`, PP.1's snapshot of the build before the pack; M0 noise
  pins and route hints on in both builds): A and B are made and used by the old build (a session,
  sightings, pins, learned routes, two messages each way; A also messages C once and removes her,
  review E-harness-docs-ci-1), A's message to B waits in the old build's outbox; both start this
  build (B first, on his old port): each node seals the whole profile at its start (`raven-node
  at_rest: sealed N file(s)`, then `sealed`), before anything of this build sends no file name
  below either profile names a friend, C included, `raven privacy status --json` says sealed, no
  registered file plain and every SQLite store keyed, the history
  is all there (RVNHIST2), the waiting message arrives exactly once and both ways deliver (the
  session count is recorded: one before and one after in the PP.19 runs, so the migrated session
  carried them). With both nodes stopped, carrier_matrix C87's
  check (`friend_metadata_leaks`: the friend's key in hex, base64 and raw, rvn1 address, PeerId,
  LAN address, petname, tag and the loopback IP in every file, the SQLite stores and sidecars as
  raw bytes with every message id of the run, and no file name naming the key; the lab key
  backends' files left out) finds nothing in either data dir, while the same check over a copy
  of each old profile taken before the switch finds the friend (in the PP.19 runs in eleven and
  nine files: the book, the address files, the session store and its WAL, the pins, the caches,
  an older build's `.send_<key hex>.lock.sqlite`). Those lock names go with the sealing pass at
  the start (review B-sealed-stores-4; before it, only this build's first send to that friend
  deleted one, so a friend removed on the old build kept hers for good, and s120 sent to every
  friend before it looked: review E-harness-docs-ci-1). The same check over A's data dir for C
  finds nothing, and over the copy of A's old profile finds her key in that file name.
- **`RAVEN_FAULT_PRIVACY=1`** runs every privacy scenario: s117 and s120-s125. s120 and s124 also
  run with `RAVEN_FAULT_PRIVACY_OLD_BIN` alone (as s124 did) and fail without it, so a forgotten
  build never reads as a pass. It is a variable of its own (review E-harness-docs-ci-9):
  `RAVEN_FAULT_OLD_BIN` is s04c's pre-RRH1 peer build, and one setting for both builds ran s04c's
  documented command with s120 and s124 against the wrong build (and the other way round). s123
  also runs with `RAVEN_FAULT_OFFLINE=1` and s125 with
  `RAVEN_FAULT_CUSTODY=1`; a scenario two lists name runs once. **s122 joins the default list**
  (5.6 s; with s117 and s121, which were there), and passes without the cutoff gates; s123 and
  s125 pass without their old flags too (5.8 s and 4.5 s) but stay opt-in (the plan names s121
  and s122 for the default list). The registry line in both harnesses names what the pack took.
- **Docs**: this document (sections 6, 8, 11 and 12), the safety guide's sections "If someone
  takes your laptop", "Deleting chats", "Erasing Raven" and "Going back to an older Raven"
  (`scripts/check_safety_offline.sh` checks every command in them against `--help`), the threat
  model's §3.7a, a pointer paragraph in the reachability design, and the real-row checklist R34.
  No LAN waiver amendment: no wire or LAN behaviour changed.

### 4.18 The terminal app 1: keeping chats, deleting a chat, forgetting an address (PP.21)

No gate (user-invoked, as the CLI commands they mirror), no wire change; files under
`node/crates/ash/src/tui/` plus one helper split out of `raven contact forget-address`
(`forget_contact_address`) and raven-core's `privacy::sealing_notice_due` (the sealing notice
read without taking it, as `retention_notice_due` already was).

- **The privacy read** (`StoreJob::LoadPrivacy`, `bridge::chat_keep`, `privacy_notices`,
  `disk_space_needed`): once the identity exists, again whenever raven-node's `Status.at_rest`
  state changes. Before it answers, or when it says not available (no identity on record), every
  part below is hidden: the Settings row, the friend page's C and F (and HELP's lines for them)
  and the notices.
- **Settings, "Keep chats for: 30 days"** (after "Show technical details"): Enter (or Right or
  Left) opens a chooser, 7 days / 30 days / 90 days / Keep, with "Older chats are deleted from
  this computer. Your friends' copies aren't." Enter saves through one store job
  (`privacy::set_chat_keep`) only when the choice changed; never on the render path.
- **The friend page**: "[C] Delete chat with {name}" asks "Delete your chat with {name} on this
  computer? {name} keeps their copy. Type delete to confirm: > _" (any case; the same keys on a
  Persian or Arabic 101 layout are the word; a paste, or an Enter that came with one, clears the
  word; Enter within 300 ms of a paste is ignored), then runs `raven chats delete --yes`'s path
  (`ext::delete_chat_with`, `ext::waiting_messages_to`) as a critical job. The toasts: "Deleted
  your chat with {name} on this computer ({n} messages)." and, while messages to the friend wait,
  "{k} messages to {name} are still waiting to be sent." The conversation is read again from the
  history and the friend's read marker goes. "[F] Forget {name}'s address" asks the CLI's
  question and forgets on Enter (`forget_contact_address`); when part of what Raven learned about
  reaching the friend could not be forgotten (a file that can't be read now, a lock held too
  long), the page says "Raven forgot {name}'s saved address, but couldn't forget everything it
  learned about reaching {name}." with `raven contact forget-address`'s notes in Details, instead
  of the plain toast (review D-lock-tui-8).
- **Home's one-time notices**: the sealing notice (with the keychain sentence on macOS), then
  the retention notice, in the UX copy's words, each with [Enter] OK; only then marked shown
  (`take_sealing_notice`, `take_retention_notice`), so the CLI does not say them again. They wait
  for Home with no other box open and no field that has the keys. The app's start keeps leaving
  them unsaid (`prepare_at_rest` with notices off), and the same top-level pass is the app's
  upgrade interlock: nothing is sealed under an older raven-node before the app's first store job.
- **NET**: while `Status.at_rest` is `key_unavailable`, `key_lost` or `waiting_for_keychain` the
  header chip says "○ Locked out of your friends list" and NET's first row is the key-root
  sentence (for `key_lost` the key-gone one, review A-keys-format-4);
  `needs_disk_space` and `unsealed_by_user` get their UX-copy rows.

### 4.19 The terminal app 2: Erase Raven from this computer (PP.22)

No gate (user-invoked and typed, as `raven erase`), no wire change, no new crate. Files under
`node/crates/ash/src/tui/` plus three small changes in `cli.rs`: `raven erase`'s question split
into its title and paragraph (`ERASE_TITLE`, `ERASE_PARAGRAPH`; the CLI prints them as before),
`erase_passphrase_file` split out of `cmd_erase`, and a `close` hook in `erase_profile` (called
once the marker is down, just before the plan is carried out; `raven erase` passes a no-op); and
`ext::waiting_messages` (`waiting_messages_to` for one friend or, now, for all).

- **The row.** Settings' last row, "Erase Raven from this computer", shown once the privacy read
  answered (section 4.18), as "Keep chats for"; no shortcut anywhere. Enter opens ERASE over the
  whole screen and reads, on the store worker, what goes (`bridge::erase_plan`: section 4.14's
  `erase::refusal` and `erase::plan`, read only; the friends from the book, the waiting messages
  from raven-node's outbox or the store): a refusal (not a Raven profile, the home folder, a debug
  build outside `RAVEN_LAB_ERASE_ROOT`) shows instead of the question and changes nothing.
- **The question.** The UX copy's title "Erase Raven from this computer?" and `raven erase`'s
  paragraph, then "On this computer now:" with "your identity", "{n} friends", "your chats",
  "{k} waiting messages" and "{m} keys in this computer's keychain" (keyring outside macOS; a
  count of none is left out; one sentence in a small window), then "Type erase to confirm: > _".
  The word is taken in any case and from a Persian or Arabic 101 layout's keys (silent tolerance,
  as DEL's); a paste, or an Enter that came with one, clears it; Enter within 300 ms of a paste
  is ignored; any other word does nothing. Esc cancels, also while the erase waits for a job.
- **The erase.** Enter with the word waits until no job is in flight (a send, a save, a read: then
  no worker holds the profile open, and the store worker runs nothing else), then stops the
  background program this app started (`NodeJob::Stop`; on Windows only this app may stop it; it
  is this app's own even where Raven's own login item is set up, so the stop never leaves it to a
  login service: review D-lock-tui-5), then
  runs one critical store job: `bridge::erase` = `erase::refusal`, then cli.rs's `erase_profile`
  (Raven's own login item unloaded, any node stopped and confirmed gone, the marker, the login item
  removed, then the keys first and Raven's files, as in section 4.14). Meanwhile nothing starts by
  itself, the poller's findings are not acted on and no read marker is saved; no key does anything
  once the job runs. Exactly one erase job goes out.
- **Nothing saved after (review R15).** At `erase_profile`'s `close` hook the controller closes:
  every later job refuses ("Raven is being erased from this computer"), every save of
  `tui_state.json` (settings, read markers, a note shown once) is a no-op, the identity is not
  loaded or created again, and the at-rest keys cached in this process are forgotten
  (`at_rest::forget_cached_keys`). The app holds no other handle of the profile (no store stays
  open between jobs; Windows can't delete an open file). The exit saves nothing, so the quit path
  can't make the folder again.
- **The end.** The erase ran: the app leaves the alternate screen, clears the terminal (and its
  scrollback where it can) and prints `raven erase`'s result list (stdout, exit 0); part-way,
  exactly what is left and "Run `raven erase` to finish." (stderr, exit 1; the marker keeps the
  profile closed). Nothing was erased (Raven still runs, or this build can't reach Raven's login
  item): ERASE says why in the CLI's words and the app goes on, the profile as it was.
- **Tests.** Render tests at 80x24 and 60x16 in every look (all glyph sets, mono); the word rules
  (wrong words, case, Persian layout, paste, pasted Enter, the 300 ms guard); Esc; exactly one erase
  job after the jobs in flight and after this app's own stop; the exit plan (only the result list,
  nothing saved); the row hidden while the privacy read says not available; real profiles:
  `stores_closed_before_execute`, `nothing_is_saved_after_erase` (the folder stays gone after every
  save and job), an erase that changed nothing leaves the profile open, the lab erase as `raven
  erase` (one profile of two, a file of the user's left and counted, a part-way stop and its
  rerun); and in a real terminal (`tui_pty_smoke`) the app erases a profile and the folder does
  not exist after it quit.

### 4.20 The terminal app 3: Lock now v1 completed (PP.23)

No gate (user-invoked, as `raven lock`), no wire change, no new crate. Files under
`node/crates/ash/src/tui/` (bridge.rs names the core and CLI items), plus an accessor in
`node_control.rs` (`LoginItem::platform`) and a pty test in `tests/tui_pty_smoke.rs`. It completes
UXF.7's LOCK (the terminal app's design, section 6) with section 4.13's parts; OD-PP-12 is still an
owner call, and this step implements its option (a).

- **`L` on Home** (the friend list or the conversation; in the composer it is a letter) opens LOCK,
  as SET's 'Lock now' and QUIT's `L` do; a Persian or Arabic 101 layout's key works too. HELP over
  Home lists it.
- **Raven's own login item.** The node worker asks `bridge::own_login_item` (section 4.13's
  `node_control::own_login_item`: the installer's item, and only when its `--data-dir` is this
  profile's). This replaces the app's old check, which counted any installed item (a second
  profile was "Managed" by the first one's) and looked under `XDG_CONFIG_HOME` while the
  installer writes `~/.config`. A build that reads no login items (a debug build without
  `RAVEN_LAB_LOGIN_ITEM_ROOT` and `RAVEN_LAB_LOGIN_ITEM_TOOLS`) keeps the older file check, now
  per profile and always under `~/.config`; LOCK's words stay UXF.7's, and its job stops as
  UXF.7 did (a login service is left alone), with the lock recorded around the stop. LOCK's Enter
  waits for the read while it is in flight (review D-lock-tui-6: a LOCK confirmed in the first
  moments after the app opened stopped Raven without recording the lock or unloading the item,
  and launchd started it again); a read that fails counts as none read.
- **LOCK's job** (`NodeJob::Lock`, once the read answered; after a stop already running, also
  where no login item is read): the lock
  recorded first (`bridge::set_locked_by_user`: `privacy.json` `locked_by_user`, so a send in
  another window and `raven listen` start no Raven); when Raven's own item runs this profile, its
  job unloaded for this login session only (`bridge::stop_for_session`: `launchctl bootout`,
  `systemctl --user stop`, `schtasks /End`), recorded as `lock_login_item: unloaded` so `raven
  unlock` loads it again; then the stop step; when Raven still answers after it, the lock is
  taken back. The question then ends with "Raven starts again when you log in. To keep it
  stopped, run `raven lock` in a terminal.", and the last line on the cleared terminal is "Raven
  is stopped until you log in again." (otherwise "Raven is locked." / "Raven is stopped."). When
  a `raven lock` turned that item off (`lock_login_item: disabled`, read with the item), it ends
  instead with "Raven's login item stays off until you run `raven unlock`." and the last line is
  "Raven is locked." / "Raven is stopped." (review D-lock-tui-7). A passphrase-vault profile whose
  passphrase is saved in a file (section 4.13's lookup, through the vault check) gets `raven
  lock`'s paragraph naming the file, its path cut in its middle to one row (review
  D-lock-tui-2).
- **Never a login setting (OD-11, OD-PP-12 (a)).** The app never turns a login item off or on: no
  tui file names `disable_login_item`, `enable_login_item` or `clear_lock_login_item` (testkit's
  scan), and the lab's fake tools record only the unload.
- **Opening the app** is its way to start Raven again after its own Lock: once the identity is
  loaded on the plain terminal, before any start, `bridge::reopen_after_lock` clears a lock the
  app's Lock left; the app then starts Raven as it always does (the profile's receive setting and
  friends decide). A lock `raven lock` set is kept (review E-harness-docs-ci-3): `privacy.json`
  records who set a lock (`lock_by`: `cli` or `app`; a lock without it, which an earlier build of
  the pack wrote, counts as `raven lock`'s, and the app's Lock never turns `raven lock`'s into its
  own), and the app opens UNLOCK ("Raven is locked ... Start Raven again now?"): nothing starts
  Raven until Enter, whose node job clears the lock (`bridge::unlock_from_app`) before the start
  it held; Esc keeps Raven stopped for the session (NET's S asks again; a send says Raven is
  locked). A login item `raven lock` turned off stays off; the privacy read reports it
  (`PrivacyRead.login_item_stays_off`, also when the app opens on a profile that is not locked
  but whose record still says `disabled`: review D-lock-tui-4) and, once Raven runs, Home says
  once (nothing recorded): "Raven is running again. Raven's login item stays off until you run
  `raven unlock`."
- **Tests.** Render tests at 80x24 and 60x16 (Simple, Fancy and ASCII glyphs, colour and mono;
  keychain and vault) with and without the login item's line, the latter cell for cell as
  UXF.7's; Enter sends the job (with or without the unload), Esc nothing; a stop already running
  goes first; the exit lines; `L` on Home and not in the composer; the notice; real profiles with
  lab login items and fake tools: only this profile's item counts, the unload is the only tool
  run, the lock recorded and taken back (a node that still answers), opening the app clears the
  lock before its one start and never turns the item on; and in a real terminal (`tui_pty_smoke`)
  `L`, Enter, "Raven is stopped until you log in again.", then the app opened again clears the
  lock.

### 4.21 The terminal app 4: read markers and the name sealed (PP.24)

No gate (pure at-rest hardening, like PP.4-PP.6), no wire change, no new crate. Files under
`node/crates/ash/src/tui/` only (bridge.rs names the core items); `tui_private.rms` was registered
in `at_rest::FILES` by PP.3 (kind 10, writer lock `.at_rest.tui_private.lock.sqlite`).

- **The split.** `tui_state.json` held, besides the app's settings, `last_read` (per friend key,
  the id of the last message read) and the user's own `display_name`. In a sealed profile the app
  now keeps these two in `tui_private.rms` (`state_file::TuiPrivate`, `{"version":1,
  "display_name":..,"last_read":{..}}` sealed as RMS1 under the profile's at-rest keys, through
  `bridge::store_tui_private` = `at_rest::store_json`). Every other setting (motion, colours,
  symbols, when I quit, receive, the address in the invite, details, the classic menu, the notes
  shown once) stays in `tui_state.json`: the gate reads it on every start, before the identity is
  open, and `state_file::peek` reads only that file (never the sealed one, so nothing that needs a
  key). A profile that is not sealed (a debug build without `RAVEN_LAB_AT_REST=1`, a profile
  without an identity yet) keeps everything in `tui_state.json`, byte for byte as before.
- **Shared with the desktop apps (E1).** The read markers are the desktop engine's too
  (`tui/read_marks.rs`, through raven-client's `messages.mark_read`): `last_read_at` (per friend
  key, the marker's message id and its time) sits beside `last_read` in the same file, so it moves
  and is sealed with it; no new file, and every writer takes `.tui_read_marks.lock.sqlite`.
- **Load** (`state_file::load`, which the app's session now starts from once the identity is
  loaded): `tui_state.json`, then in a sealed profile the sealed file's two fields when it is there
  (until the move below, `tui_state.json` may still hold both). The sealed file opens
  with the keys the process loaded at its start (`bridge::load_tui_private` =
  `at_rest::load_json`; no keystore call). A `tui_private.rms` that cannot be opened (the key
  unavailable, a changed byte, another profile's file) gives no read markers and no name and is
  `LoadNote::Unreadable`: no read-marker save writes over it; a setting the user changes does
  (the rule `tui_state.json` already had).
- **Save** in a sealed profile: `tui_private.rms` first, then `tui_state.json` without the two
  fields. A crash between the two leaves both readable and every read marker in at least one of
  them (the sealed file wins); the next save finishes the move. When the sealed file cannot be
  written (no key loaded) nothing is written and the save fails (the app's "Raven couldn't save
  this setting" toast); there is never a plaintext fallback.
- **The move at every command's top** (review D-lock-tui-1: before it, the two stayed in
  `tui_state.json` until the app happened to save, with no limit for someone who works from the
  CLI, while `raven privacy status` said the friends list was encrypted). Once `migrate_all_with`
  found the profile sealed and loaded its keys (`prepare_at_rest`: every command and the app's
  own start; and `raven privacy seal-now`), `state_file::move_private_now` moves a
  `tui_state.json` that holds a name or read markers as a save would: `tui_private.rms` first,
  only when there is none (one that is there wins, as Load lets it), then `tui_state.json`
  without the two, every other field kept as it is (a newer app's too). What the app loads is the
  same before and after. A `tui_private.rms` that can't be opened, and a `tui_state.json` that
  can't be read or parsed, are left as they are. It also seals in place
  (`at_rest::migrate_file`) a `tui_private.rms` that `unseal` left in plain JSON, which the
  migration after `seal-now` does not seal (it is not one of `MIGRATED`). Until it has run, `raven
  privacy status` (text and `--json`) counts either file under "Not encrypted yet"
  (`state_file::private_files_in_plain`). Without the keys in the process nothing moves.
- **The way back.** `raven privacy unseal` (PP.18) writes `tui_private.rms` back as plain JSON.
  While a profile is not sealed, `tui_state.json`'s own fields win and the sibling is read only
  when they are missing; the next save puts both back into `tui_state.json` and deletes
  `tui_private.rms`, so a build before the pack sees them again.
- **Older apps.** An app before this step reading a sealed profile's `tui_state.json` gets the
  defaults for the two fields: every message shows as unread and there is no name (section 8's
  table). If it saves, the empty fields it writes do not override the sealed file in a sealed
  profile.
- **Tests.** `state_file` with a fake sealed file: the split and its pinned formats, round trips
  sealed and not sealed (the plain file's bytes unchanged, the sealed file never touched), the
  crash between the two writes, an unreadable sealed file and a store that fails, the way back
  after `unseal`; on real sealed profiles: `tui_private.rms` is RMS1 kind 10, `tui_state.json`
  holds no friend key, read marker or name (byte scan), `peek` works and loads no key with none
  loaded, a changed byte is left alone until a setting changes, and `raven privacy unseal`
  followed by a save brings both back into `tui_state.json`. The move (review D-lock-tui-1): with
  the fake, both out of `tui_state.json` and nothing loaded changed, a sealed file that is there
  kept, everything it cannot decide left alone; on real sealed profiles the move at once (none
  without the keys), the plain `tui_private.rms` after `unseal` and `seal-now` sealed in place,
  and the CLI's `the_top_of_a_command_moves_the_apps_read_markers_and_name` (counted as not
  encrypted yet while it can't move, then moved by the next command's top).

### 4.22 Review fixes of the sealed stores (review B-sealed-stores, after PP.20)

No gate (at-rest; the owner's storage choice). Code: `rc/indexed_session_store/sealed.rs`, the
store's queries (`indexed_session_store.rs`, `custody.rs`, `horizon.rs`), `rc/lan_dispatch.rs`,
`rc/outbox.rs`, `rc/privacy.rs`, `rc/privacy/manage.rs`, `rc/at_rest.rs` (kind 65),
`rc/ipc.rs` and `rn/at_rest_boot.rs`.

- **Schema 4: the heads' `init_id` keyed (B-sealed-stores-1).** The clear `record_key` is an
  unkeyed digest of public values and the `init_id`; with the `init_id` clear beside it, anyone
  with the file and a candidate friend's public key could confirm a session with that friend,
  who started it and its hour, and through the clear `session_id` every endpoint row of it
  (section 3). Schema 4 replaces the column with `kh_init_id` (value type `nonce`; the UNIQUE
  index keeps its name, so an older build's batch stays a no-op) and keeps the `init_id` in the
  head's `meta`; lookups by `init_id` bind the keyed value, the SQL orders by `created_hour` at
  most and Rust finishes the tie-break from `meta`. `METADATA_SCHEMA_VERSION` 3 -> 4, raised on
  purpose: the pack's earlier builds refuse it (fail closed), this build moves a schema-2 or -3
  store at its open after its journals (the heads rebuilt in the recipe's transaction, rowids
  kept, each `meta` sealed again with the `init_id` in it; a `meta` that does not open keeps its
  bytes and goes with the prune), the way back writes the clear column again, and the re-key
  writes schema 4. The responder's cached PairResponse held the `init_id` in its name and its
  bytes: section 6.1, kind 65, and below.
- **An unreadable head blocks nothing (B-sealed-stores-2).** The archive before the prune lists
  the heads that open and logs the others once, so the prune, which removes such a head by its
  hour, is reached; without the key it fails (closed). The prune before a PairInit, either way,
  is best effort: housekeeping never stops a new session (without the key the session store
  does not open there either). The inbox listings (`raven inbox`, the paged reader) and a chat
  deletion go past such a head's rows the same way, which stay for its prune (the privacy
  re-verify: `raven inbox` failed as a whole until that hour); without the key they fail
  (closed).
- **Rotate-meta and unseal get past an unreadable head (B-sealed-stores-3).** Before rotate-meta
  records its key change, and before unseal changes the mode, the protected state of every head
  whose `meta` does not open is deleted (a failure, such as a locked keychain, stops the command
  with nothing changed: raven-node still starts the profile, and running it again finishes it;
  the privacy re-verify found the delete inside rotate-meta's re-key, after the record), then
  the rebuild drops the head with every row of its session, counted in `dropped`. A
  rotation record left while the mode says `unsealed_by_user` (an unseal that stopped) makes
  raven-node and ash name `raven privacy unseal`, which finishes it, not rotate-meta, which
  refuses an unsealed profile.
- **An older build's send locks go (B-sealed-stores-4).** `migrate_all` (both arms) and the
  prune passes' `upkeep_stores` delete each `.send_<key hex>.lock.sqlite` (and a `-journal`
  beside none) in a sealed profile with its key loaded, taking the friend's keyed lock first and
  the older one without waiting; one a send holds is left for the next pass and counted as plain
  by `raven privacy status` and `Status.at_rest` (the report lists the pattern, never the name).
  An older name whose friend is not in the book (a contact removed before the upgrade) gets no
  keyed lock file: only one that exists is taken, since nothing would delete a new one. `raven
  privacy rotate-meta` deletes every keyed lock file no friend in the book has under the new
  keys (one left that way by an earlier build, an interrupted run's old names) unless a send
  holds it (the privacy re-verify).
- **The cached PairResponse (B-sealed-stores-5).** In a sealed profile
  `lan_pair_response/<hex(kh_init_id)>`, sealed (RMS1 kind 65, writer lock
  `.at_rest.pair_response.lock.sqlite`); a plain profile keeps `<hex(init_id)>` and plain bytes.
  Every response goes 10 minutes after it was written (`PAIR_RESPONSE_KEEP`), whether its
  session lives or not: a PairInit travels only on a direct dial and is retried only within it,
  so an exact retry comes within minutes; a later one gets no response and the initiator pairs
  again. The responses of a live session used to stay for the session's life (up to 7 days),
  plain, with its exact start and end. In a sealed profile a response still named by its
  `init_id` (an older build's, or one cached before the sealing) goes at once: at the sealing
  pass and at every prune (s120's record-key check found one left by the build before the pack).
- **The keychain retry keeps its backoff (B-sealed-stores-6).** Only `raven status` asks for a try
  at once (`IpcRequest::Status`'s optional `retry_key`, sent only when set, so every other Status
  is the same bytes as before and an older node ignores it), and only once the last try ended
  30 s ago; the terminal app's poll never does.
- **Tests.** `sealed_store`: the byte scan finds no `init_id` in a sealed store;
  `a_schema_3_store_moves_to_4_and_its_init_ids_leave_the_file`,
  `migration_from_schema_3_crash_at_each_statement_recovers`; `lan_dispatch` (real pairings in a
  profile sealed by `migrate_all`): `b1_no_record_key_names_the_friend_in_a_sealed_profile` (no
  16-byte clear value and no file name gives a friend's record key; no file holds an `init_id`),
  `b1_a_response_cached_before_the_sealing_goes_with_it`,
  `b2_an_unreadable_head_stops_no_session_and_the_prune_removes_it`,
  `b3_rotate_meta_and_unseal_get_past_an_unreadable_head`,
  `b5_the_cached_pair_response_is_sealed_and_short_lived`; `privacy`:
  `an_older_builds_send_locks_go_when_the_profile_is_sealed`,
  `an_unseal_that_stopped_during_a_key_change_points_to_unseal`; `ipc`:
  `status_asks_for_a_key_try_only_from_raven_status`; raven-node `at_rest_boot`:
  `the_apps_status_poll_keeps_the_backoff`, `a_slow_answer_counts_from_its_end`; carrier_matrix
  C87 and s120 add the record-key check (no stored record key matches a friend's key with any
  16-byte clear value or file name as the `init_id`).

## 5. Gates

The pack adds **no** `*_PRODUCTION_ENABLED` gate. Every step is either pure at-rest hardening or a
user-invoked local command, which the owner's storage choice approves, or rides an existing gate
that stays false.

| Step | Gate | Why it may be live in release | Old profiles |
|---|---|---|---|
| PP.1 | none (docs, lab switches, harness) | no behaviour change | unchanged |
| PP.2 secure_delete | none | per-connection pragma; file format unchanged | older builds open the files unchanged |
| PP.3 at_rest core | none | no caller yet | nothing written |
| PP.4-PP.6 sealed JSON, keyed lock names | none | pure at-rest; same bytes on the wire, same admission decisions; release seals, debug only with `RAVEN_LAB_AT_REST=1` | migrated at the first start of the new build unless an older node still answers; readers accept plain JSON forever; `raven privacy unseal` is the way back |
| PP.7 forget addresses | none | removes on-disk entries no dial reads any more | nothing a dial uses is removed |
| PP.8 clear that sticks, delete chat | none (user-invoked) | an existing command does what it says; receipts kept | older builds ignore the sidecar table |
| PP.9 retention (default 30 days) | none | at-rest data minimisation | one-time notice and a 7-day grace before the first deletion |
| PP.10-PP.11 rotation, Windows K_hist | none | key management; no keystore write | epoch rotation with a grace of at least 24 h |
| PP.12-PP.14 sealed SQLite | none | at-rest | rebuild recipe, shape-based version detection, reverse migration for `unseal` |
| PP.15 Lock v1, PP.16 erase | none (user-invoked) | typed confirmations, never remote | n/a |
| PP.17 custody minimisation | existing `FRIEND_CUSTODY_PRODUCTION_ENABLED` (false) and its lab switches | custody is off in release | no release change |
| PP.18 privacy command | none (user-invoked) | local | the downgrade path itself |
| PP.21-PP.24 terminal app | none | local UI | older app versions read the plain settings with defaults |

## 6. What a profile writes (final, 2026-10-19)

**How it was derived.** A fresh scan of `rc/`, `rn/` and `ash/` (tests and `shared-vectors`
excluded; re-checked against `at_rest::FILES` for PP.19, which names every entry below and
whose guard fails on a new name, section 11): every `*_FILE` / `*_NAME` constant, every string
literal ending in `.json`, `.sqlite`,
`.sqlite3`, `.bin`, `.seed`, `.secret`, `.vault` or `.dpapi`, every `data_dir.join("...")` and
`join(format!(...))` name, and the SQLite `CREATE TABLE` statements. Names that occur only in
tests or vectors were dropped. "Rule" is one of: an RMS1 kind, keyed SQLite columns, already
protected (keystore or K_hist), or plain with a reason.

### 6.1 Sealed JSON files (RMS1)

| File | Rule | Step | What it holds |
|---|---|---|---|
| `contacts.json` | RMS1 kind 1; Phase 4's `p2p_next` column (P4.27) lives inside it, sealed with the book | PP.4; P4.27 | every friend: petname, tag, rvn1 address, key, pinned, saved LAN / Internet routes, PeerId, relays, custodians; Phase 4: the next epoch's PeerId a rotating friend's card named (`p2p_next`, from `p2pn=`) |
| `lan_seen.json` | kind 2; entries older than 30 days removed (PP.7); a cross-process writer lock (today an in-process `Mutex` only) | PP.6 | friend key, the IP it last came from (an IPv6 link-local one with its zone, this computer's interface name or number: Phase 3 P3.4, inside the same `ip` string), when |
| `learned_routes.json` | kind 3; an expired LAN part keeps its IP and port 30 days after it was received (Phase 3 P3.C1, no new field); tombstones of contacts unheard 30 days keep a generation and a day, no IP (PP.7); Phase 3 P3.18 adds `custodian_tags` (hex), `custodian_tag_flags` and `custody_offer` to the global part, inside the same sealed file, none of them in a tombstone; Phase 4's `nat_class` (P4.24) is part of a live snapshot only (gone with it, never in a tombstone) and written only while the NAT_CLASS gate is live | PP.6; P4.24 | friends' learned LAN ports and addresses (a link-local LAN IP with its zone, P3.4), relays, custodians; since P3.18 which friends offer to hold mail (and how: WAN, reachable) and the tags of the custodians each friend collects from; Phase 4: each friend's NAT mapping classes (four codes and two flags from its RRH1 NAT_CLASS, no address) |
| `outbox_routes.json` | kind 4; finished objects dropped (PP.7); `edit_route_file` never overwrites an unreadable file | PP.6 | who has mail waiting, message ids, the addresses tried; since the cutoff review (FU-3) also `ended`: message id, deadline and three bits per expired object, kept 7 days; with the long message horizon live (Phase 5 P5.6, lab gate) a record stays in `objects` up to 7 days past its envelope's end, and a parked message's is planned until its deadline (written + 7 days); a finished message's is cleared as before; Phase 5 (P5.25): `objects` is decoded entry by entry, and an entry this build cannot parse (a newer build's carrier or choice) is kept inside the same sealed file until its own deadline, under the same cap, clearing and PP.7 rules; a nearby route is never stored (derived live), only a lab `--carrier nearby` choice |
| `peer_device_certs.json`, `prekey_store.json`, `peer_cache.stage.json` | kinds 5, 6, 18 (`peer_cache.generation`, a number, stays plain) | PP.5 | friends' device certificates and cached prekey bundles |
| `blocked_pubs.json` | kind 7 | PP.5 | the block list |
| `device_registry.json`, `revocations.json`, `device_sync_seen.json` | kinds 8, 14, 15 | PP.5 | own and friends' device ids and revocations |
| `chat_inbox_cursors.json` | kind 9; format 2 entries (`seq`) for a schema-3 session store (PP.14, section 4.12) | PP.6 | per-friend activity markers and clear tombstones |
| `tui_state.json` `last_read`, `last_read_at`, `display_name` | moved to `tui_private.rms`, kind 10; the rest stays plain | PP.24 | per-friend read markers (shared with the desktop apps), own display name |
| `desktop_private.rms` (the desktop apps' engine, `node/crates/raven-client`) | kind 128 under `.at_rest.desktop_private.lock.sqlite`; plain JSON until the profile is sealed, then sealed in place by the engine once it holds the key (as `tui_private.rms`); a write without the key fails, never plain; an older engine's name in `desktop_settings.json` moves here; erase removes it | desktop merge review | own display name in the desktop apps |
| `route_memory.json` | kind 13; expired leases dropped (PP.7) | PP.6 | lab route memory per contact |
| `lan_noise_pins.json` (cutoff CP.2) | kind 16 under the NEW name `lan_noise_pins.rms` (R07: an older build rewrites an unreadable `lan_noise_pins.json`); plain pins merged only for contacts without a sealed pin, then the plain file removed | PP.5 | contact key -> keyed digest of its Noise static |
| `route_hints_state.json` (Phase 2, rn `hints::GEN_STATE_FILE`) | kind 17; an advisory file (unreadable reads as no state, and is then never written over) | PP.5 (sealed; the cutoff follow-up re-verify asked for it by PP.6 at the latest) | per-contact digests and sent generations; also the node's own LAN listener address when it is bound to one address (`lan`), and an unkeyed SHA-256 `global` digest over the PeerId, relays and confirmed direct addresses that could be brute-forced: both only inside the sealed file now |
| `node_policy.json` fields `p2p_relays` and `relay_external`; Phase 4's `p2p_proxy` | moved to the sealed sidecar `node_policy_peers.rms`, kind 19 (section 4.4); `p2p_proxy` is written there from the start (P4.6) | PP.6; P4.6 | relay multiaddrs, which may be friends' public addresses; this computer's own public names; the network's proxy host (never its credentials) |
| `node_policy.json` field `custody_home` (Phase 3 P3.16) | in the sealed sidecar `node_policy_peers.rms`, kind 19, with the relays (section 4.4) | P3.16 | the friends picked by hand as home custodians (contact keys) |
| `node_policy.json` field `send_hold` (Phase 6b P6.31, the terminal app's "Pause sending") | in the sealed sidecar `node_policy_peers.rms`, kind 19, with the relays (section 4.4) | P6.31 | the friends the user paused sending to (contact keys, at most 256) |
| `bootstrap.json` | kind 20 once the profile has an identity; plain before (a first-install inert file) | PP.5 | user-entered peers and multiaddrs |
| `relay_allow.json` in a profile with an identity (`raven-node service --relay`, and the friend relay's manual allow-list) | kind 21 | PP.5 | friends' PeerIds with labels (petnames), when a scheduled PeerId expires (`expires_ms`, P4.26) and, for the friend relay, their contact keys |
| `device_x25519.secret` | kind 24 (only its public key is ever derived from it) | PP.5 | a raw X25519 secret |
| `device_revocations_rvdr1.json` | kind 25 | PP.5 | device lineage keys |
| `alias_claims.json`, `nearby_registry.json` | kinds 26, 27 | PP.6 | aliases -> addresses and public keys |
| `contact_inbox/<id>.wire` | kind 28 per file | PP.6 | contact requests received (their addresses and keys) |
| `relay_memory.json` (Phase 2, `relay_select::RELAY_MEMORY_FILE`) | kind 29 (**PP.1 find**) | PP.6 | the relays this node picked or used (often friends' relays): PeerIds, availability and times |
| `friend_relay/relay_status.json` in a profile (Phase 2) | kind 30 (**PP.1 find**); dedicated relay folders stay plain | PP.6 | the friend relay's own PeerId, listen, advertised and UPnP addresses (this computer's public addresses) and counts |
| `friend_relay/relay_key.ed25519` in a profile (Phase 2) | kind 31 (**PP.1 find**); dedicated relay folders stay plain | PP.6 (with the friend relay's other files; PP.5 does not touch the friend relay's start) | the friend relay's own libp2p secret key (whoever copies it can pose as this relay) |
| `lan_meeting.json` (Phase 3 P3.C2, `raven_core::lan_meeting`) | kind 32 under `.at_rest.lan_meeting.lock.sqlite`; plain JSON in a plain profile, sealed by the migration with the rest; written only by ash (`raven lan on --for`, refused in a profile without an identity), removed by `raven lan on` and `raven lan off` (no key needed); raven-node reads it at start and keeps LAN off while a sealed one waits for the key or does not open | P3.C2 | when the LAN window of a meeting ends (`until_ms`): kept after it passed, so `raven lan status` says when listening stopped and a restart keeps LAN off |
| `custody_home.json` (Phase 3 P3.18, `raven_core::custody_home`) | kind 33 under the learned routes' lock `.learned_routes.lock.sqlite`; plain JSON (0600) in a plain profile, sealed by the migration with the rest; written by raven-node (`custody_home::refresh`, only when something changed) and by ash when a contact is removed or blocked (`custody_home::forget`, only when the file names it); a corrupt or unreadable file reads as empty and a sealed one this process cannot open is never written over; a picked friend who is no longer a verified, unblocked contact is dropped at the next refresh, with no drain | P3.18 | the friends picked as home custodians (contact keys, at most 2) and the dropped ones still fetched from, each with the time its drain (about 97 h, `custody_home::DRAIN_MS`) ends (at most 64, `custody_home::MAX_RETIRED`) |
| `peer_schedules.json` (Phase 4 P4.25, `raven_core::peer_rotation`) | kind 66 under `.at_rest.peer_schedules.lock.sqlite`; an advisory file in the `lan_seen.json` pattern (owner only; an unreadable one reads as empty and is never written over); written by raven-node from a pinned contact's RRH1 PEER_SCHEDULE only while the PeerId rotation gate is live (P4.27; a newer RRH1 without one forgets it); at most 8 entries per contact and 1024 contacts, entries behind a contact's clock dropped on every write and by `prune_schedules`, which the 30-day address forget pass runs (`ForgetReport.peer_schedules`; the capability flag stays), a contact removed, blocked or given new addresses has its schedule forgotten with its learned routes (`forget_schedule`) | P4.25; P4.27 | contacts' PeerId rotation schedules, keyed by the contact's device key: their coming libp2p public keys (each a PeerId, so whoever reads them can recognise the contact's node for about 6 months), epoch numbers, flags and when each was received |
| `peer_rotation_state.json` (Phase 4 P4.28, `raven_core::peer_rotation`) | kind 67 under `.at_rest.peer_rotation_state.lock.sqlite`; advisory like `peer_schedules.json` (an unreadable one reads as not ready and is never written over); written by raven-node with each peer gate read, only while the PeerId rotation gate is live: set when the profile's rotation setting is on and every p2p contact can follow, cleared when the setting is off or a contact cannot; erase removes it | P4.28 | when this profile began announcing its coming PeerIds (one Unix time in ms): that its owner turned PeerId rotation on, and roughly when; no PeerId, key or contact. Which key is in use and a rollback stay in raven-node's memory only |
| `prekey_published_local.json` (Phase 5 P5.11, `raven_core::lan_dispatch`) | kind 68 under the peer cache's lock `.lan_peer_cache.lock.sqlite`, written with the prekey store (atomic, owner only); plain JSON in a plain profile, sealed by the migration with the rest; written when this device publishes a bundle of its own (rotation, `ash` lab publish) and once at the first `ensure_local_prekey` that finds no archive (a bundle published before it existed); every write drops bundles past their expiry plus the 7-day grace and keeps at most 4 (the prekey lifecycle's generations); a reader ignores those as well; a sealed file that does not open is never written over and fails the lookup closed; erase removes it | P5.11 | this device's own signed prekey bundles as published (public keys, signed ids, validity times, its own identity key and device id): what a contact already received; no friend, address or private key. Lets an async letter sealed to a generation retired since still find its bundle (`local_published_bundle_by_hash`) |
| `letter_deposits.json` (Phase 5 P5.15, `raven_core::letter_deposits`) | kind 69 under `.at_rest.letter_deposits.lock.sqlite`; an advisory file in the `peer_schedules.json` pattern (owner only; plain JSON in a plain profile, sealed by the migration with the rest; an unreadable one reads as empty and is never written over); written by raven-node only (the worker's letter step and the fetcher's withdraw), only while the letter gate is live; every write drops the letters past their expiry (at most 7 days) and keeps at most 1,024; a letter whose messages all settled, or whose letter session was given up, is withdrawn from its custodians and then forgotten; erase removes it | P5.15 | the RAL1 letters this node left with friends: for each, the contact's device key, the letter session id, the exact letter bytes (ciphertext; its header names both device keys and the times in clear), the message ids or owed-ACK digests it carries, the custodians (friends' keys) that hold it, the last refusal code per custodian and the placement backoff; and the letter sessions given up, until they end. Says which friends carry mail to which contact, and when |
| `learning.bin` (Phase 6a P6.9, `raven_core::learning::store`) | kind 22 under `.learning.lock.sqlite`, sealed from its first write: its writer never writes it in clear, so a profile that is not sealed (or a process without the key) keeps the model in memory only and `migrate_all` has nothing to move; written by raven-node while learning is live (gated) and the user's switch is on (P6.11: at most every 60 s when the model changed, and once at shutdown; IPC `LearningReset` saves it without a contact's rows, or removes it for everyone), and by ash's `raven learning reset` (and the contact edits that forget a contact's routes) only while no raven-node that learns answers for the profile (P6.17: the same sealer, saved without one contact's rows or removed), sealed outside the lock and renamed under it; a file that is a symlink, has a second link, is not 0600, is over 512 KiB or does not open is started over and replaced by the next save; one a newer build wrote is never written over; `raven privacy unseal` deletes it (no clear shape, like the security ledger: an older build never reads it); a plain copy an unseal before that rule left is never read and is replaced, sealed, by the first save after the profile is sealed again; rows not updated for 30 days are dropped on load and before each save; erase removes it, and so does `raven learning off --forget` (P6.17, IPC `LearningReset` first while raven-node runs, then `learning::store::delete` under the lock) | P6.9 | the learning model: per contact, network and carrier a decayed success estimate, costs, round-trip estimates and the last 8 tries; relay, encounter and carry rows. Every contact, network and relay is an HMAC key under a secret kept only inside this file (no public key, network tag, address, PeerId or name), every time rounded down to the hour, no time-of-day field; plaintext `RVNLRN01` and compact JSON v1 |
| `capability_floor.json` (Phase 6b P6.29, `raven_core::capability_floor`) | kind 11 (reserved for it since the pack) under `.at_rest.capability_floor.lock.sqlite`; an advisory file in the `peer_schedules.json` pattern (owner only; plain JSON in a plain profile, sealed by the migration with the rest; an unreadable one reads as empty and is never written over); written by raven-node (the link features a contact's links show) and, while a session profile above 1 exists, the session code, only while `SECURITY_EVENTS` is live; ash lowers a mark only after a security-words match and a typed `accept` (`raven contact verify`) and removes it with the contact; a write only when a mark changes; at most 4,096 contacts (the mark set longest ago goes first); erase removes it | P6.29 | per contact (identity key): the link features its links showed at best (caps bits from 8 up, padding, update exchange, the knock), the lowest session profile a new session may use, what set it and on which day, the downgrades noted since it was last lowered (which features, the best profile a refused offer held, the last day one was noted). Says which features a friend's Raven offered, and roughly when that changed |
| `pair_seeds.json` (Phase 6b P6.38, `raven_core::pair_seed`) | kind 12 (reserved for it since the pack; registered from its first version) under `.at_rest.pair_seeds.lock.sqlite`; an advisory file in the `peer_schedules.json` pattern (owner only; plain JSON in a plain profile, sealed by the migration with the rest; an unreadable one reads as no seeds, so every key comes from the root, and is never written over); written by raven-node only while `PAIR_SEED` is live (a leader's proposal before the RRH1 that carries it, a contact's entry or its absence when its RRH1 arrives) and by ash when a contact is removed (`pair_seed::forget`); a write only when a pair's state changes; a replaced seed goes 2 days after the switch; at most 4,096 contacts (the pair that switched longest ago goes first, back to the root); erase removes it | P6.38 | per contact (identity key): the current pair seed and its generation, the previous one until it goes, a leader's outstanding proposal, when the current one was adopted and the generation the leader last said it uses. With the identity keys these give the keys of the LAN beacon, the link knock and the Bluetooth tokens of that pair: who can recognise whose datagrams and tokens while the seed lasts |
| `knock_replays.bin` (Phase 6 review traffic-9, raven-node's `link_knock`, `raven_core::link_knock::ReplayCache`) | kind 112 (lane 6b's first of 112-119) under `.at_rest.knock_replays.lock.sqlite`; plain bytes (owner only) in a plain profile, sealed by the migration with the rest; read by raven-node at its first knock (one that cannot be read leaves a cache of the process's own and is never written over until it is read); written by raven-node only, while the knock is live, with each new match before message 2 goes out; each nonce goes 3 days after its match, at most 4,096; erase removes it | traffic-9 | the RLK1 knocks this listener matched: each nonce (random, the dialer's) and when it matched. With recorded traffic these say when a contact's knock reached this computer |
| `updates/state` (Phase 6b P6.44, `raven_core::update_state`) | kind 23 (reserved for it since the pack) under `.at_rest.update_state.lock.sqlite`, sealed from its first version (plain JSON, owner only, in a plain profile; sealed by the migration with the rest); its folder `updates/` is 0700. Read and written only while the `ADVISORY` gate is live, by the code that accepts an advisory or a log (an imported file, later a friend's), and never by a build without release keys; a write only when the state changed (an advisory or a longer log taken, a freeze, a rotation, an install recorded). **Not** an advisory file: one that cannot be read, does not parse, holds an advisory or log that does not decode, or carries a later version fails closed (nothing is accepted, the file is left as it is), since an empty state would take an old advisory back. At most one advisory (32 KiB), one log snapshot (58 KiB), 32 key set digests, the last 4 key set rotations with the log snapshots they came with (Phase 6 review: served to friends that missed one) and one freeze's evidence; erase removes it | P6.44 | the release key set this profile trusts now and the digests of those before it; the last key set rotations applied (the Raven project's signed notices and log snapshots, as published); the newest security advisory accepted (the Raven project's signed notice, as published); the longest transparency log accepted (the project's public list of artifact digests and its signed tree head); the build serial last installed and what Raven's own last install or rollback swapped (P6.47: the program folder, the program file names, the two builds' serials and versions); while frozen, the two contradicting advisories or tree heads, when and under which build. Nothing about a contact or a person: which friend passed something on goes only to the security ledger |
| `updates/staged/<build serial>/*` (Phase 6b P6.47, ash's `update_install`) | plain by design (`Rule::Plain`): the Raven project's public release files as published, read and checked against their signed manifest again before every install; folders 0700, files 0600 and never executable; written only by the CLI (`raven update import`) and the terminal app, never by raven-node, while the `RELEASE_BUNDLE` gate is live; at most 2 builds; erase removes them (the erase walk follows the registry's folder patterns) | P6.47 | the release's manifest, log snapshot and advisory (all public and signed) and its programs and documents; that this profile holds a given Raven release. Nothing about a contact or a person |
| `updates/downloads` (Phase 6b P6.49, `raven_core::update_downloads`) | kind 120 (this lane's kinds count up from 120) under `.at_rest.update_downloads.lock.sqlite`; an advisory file in the `peer_schedules.json` pattern (owner only; plain JSON in a plain profile, sealed by the migration with the rest; an unreadable one reads as empty and is never written over; a later format is refused); read and written only while the `MESH_UPDATE` gate is live, by raven-node (offers, progress) and ash (`raven update download`, staging); a write only when a row changed; at most 16 rows of at most 8 friends each, rows of builds the installed one makes moot dropped; erase removes it | P6.49 | per release a pinned contact offered this computer: its manifest digest, build serial, target and size, the friends (device keys) who offered it, when it was first and last offered, whether the person approved it and when, its version once checked, how many of its parts arrived, why it failed. Says which friends hold which Raven release and when they offered it |
| `updates/incoming/<digest>/*` (Phase 6b P6.49, raven-node's `update_exchange`) | plain by design (`Rule::Plain`): the Raven project's public release as published, the manifest and log snapshot checked before the folder is made, each payload chunk checked by its audit path before it is written; folders 0700, files 0600 and never executable; written by raven-node only, while the `MESH_UPDATE` gate is live; at most 256 MiB in all, a folder untouched for 7 days removed, one no row names removed after an hour; ash stages a complete one and removes it; erase removes them | P6.49 | the release's manifest and log snapshot (public, signed), its payload as it arrives (the release's programs and documents), which parts arrived (`chunks`), and `verified` once the whole release checked; that this profile is fetching or holds a given Raven release. Nothing about a contact or a person |
| `updates/quarantine/*` (Phase 6b P6.49, raven-node's `update_exchange`) | plain by design (`Rule::Plain`): what a friend passed on that failed its checks, as received; files 0600, never run, never shown; named `<ms>-<what>-<random>` (the time and what it was: notice, log, manifest, chunk, payload), never the friend; at most 64 MiB, the oldest first, each kept 7 days; written by raven-node only; erase removes them | P6.49 | forged or unlisted Raven notices, logs, manifests and release parts (attacker-chosen bytes, kept as evidence and counted in `Status.updates`); when each arrived. Which friend passed it on is only in the security ledger |
| `lan_pair_response/<name>` in a sealed profile | kind 65, named by the keyed `init_id` (`hex(kh_init_id)`); deleted 10 minutes after it is written (review B-sealed-stores-1, -5; section 4.22) | review fix | a responder's cached PairResponse: the `init_id` that names the friend with the session store's record key, and the session's exact times |
| `<registered file>.corrupt` quarantine copies (`peer_device_certs.json.corrupt`, `prekey_store.json.corrupt`, `peer_cache.stage.json.corrupt`, `revocations.json.corrupt`, `bootstrap.json.corrupt`, `lan_noise_pins.json.corrupt`) and `.<name>.tmp.<hex>` leftovers | sealed in place under the file's kind; temp leftovers older than 1 h deleted by `migrate_all` | PP.5 | plaintext copies of certificates, prekeys, addresses, pins |

Kind 11 is Phase 6b's capability floor (`capability_floor.json`, P6.29), kind 12 its pair seeds
(`pair_seeds.json`, P6.38), 23 its update state (`updates/state`, P6.44) and 112 its knock replay
cache (`knock_replays.bin`, Phase 6 review traffic-9); 22 is Phase 6a's
learning model (`learning.bin`, P6.9); 29-31 are taken by this inventory's finds above; 32 is Phase 3's meeting
time (`lan_meeting.json`, P3.C2); 33 Phase 3's home custodians (`custody_home.json`, P3.18); 34-63
are for Phase 3 and Phase 5; 66 is Phase 4's contacts' PeerId schedules (`peer_schedules.json`,
P4.25; Phase 4 counts up from 66 so it never meets Phase 3's numbers, which count up from 33) and
67 this profile's own PeerId rotation state (`peer_rotation_state.json`, P4.28); Phase 5's letters
and handoff count up from 68 (the Bluetooth nearby work from 80): 68 is this device's own published
prekey bundles (`prekey_published_local.json`, P5.11), 69 the letters left with friends
(`letter_deposits.json`, P5.15); 64 is an `owed_acks.sqlite.corrupt-<ms>` set-aside copy sealed in place (PP.12,
section 4.10); 65 a responder's cached PairResponse (section 4.22); 120 is Phase 6b's update downloads
(`updates/downloads`, P6.49; the updates sub-lane counted up from 120). The desktop apps count up
from 128, a lane of their own: 128 is their copy of the user's own name (`desktop_private.rms`). A
sealed file whose older readers rewrite it when it looks corrupt gets a new name
(the R07 rule).

### 6.2 SQLite stores (keyed columns and sealed meta blobs)

| Store | Rule | Step | What it holds |
|---|---|---|---|
| `owed_acks.sqlite` (`owed_acks_v1`, `owed_ack_held_v1`) | schema 1 -> 2 (section 7.1): `kh_ack_digest`, `kh_peer`, `kh_custodian`, the ACK bytes sealed, `meta`, `prune_after_hour`; an older build's set-aside copy `owed_acks.sqlite.corrupt-<ms>` is merged back, or sealed in place as kind 64 (R06) | PP.12 (done) | peer keys, sealed ACK envelopes, custodians |
| `app_channel.sqlite3` (`app_inbox`, `app_tombstones`, `app_outbox`, `app_consumer`, `app_pair_attempts`, `app_quarantine`) | schema 2 -> 3 (section 7.2): `kh_sender` + `meta` in the inbox, tombstones and quarantine; row bodies under the epoch app-row key (PP.10); `app_outbox` and `app_pair_attempts` still clear (open item, section 7.2) | PP.12 (done) | sender devices of app frames |
| `indexed_sessions.sqlite` heads and reset tables (`indexed_session_heads`, `indexed_session_reset`, `endpoint_reseal_ledger`, `peer_reset_state`) | schema 1 -> 2 (sections 4.11, 7.3): kh addresses, device keys and message ids, meta (every time), `created_hour`, `prune_after_hour`; R20 identifiers kept clear; schema 4: the heads' `init_id` keyed too, `kh_init_id` (section 4.22) | PP.13 (done); review B-sealed-stores-1 (done) | both sides' addresses and device keys, session times; with a clear `init_id`, which friend each session is with |
| `indexed_sessions.sqlite` `peer_session_end`, `peer_session_end_erased` (cutoff CP.6, **not in the plan**) | kh `peer_device` + sealed meta (`ended_at_ms`, `created_to_ms`), `prune_after_hour` for the 30-day prune; moved with PP.13's rebuild | PP.13 (done) | per contact (device key): when its last session ended, and the erase marks of removed contacts |
| `indexed_sessions.sqlite` `peer_session_renewal` (Phase 3 P3.13, session renewal) | additive in schema 1 (clear columns) and 4 (kh `peer_device` + sealed meta with every other value, `prune_after_hour`); no version change; moved by the rebuilds (forward, back, re-key) with rowids kept; a clear table an older build of the pack left in a store it sealed moves at the next open; removing a contact deletes its row. Phase 6b P6.27 keeps the early re-key in the same row (no new table): three more values in the sealed meta of schema 4 (written only when set), three nullable clear columns in schema 1, added to a table an older build made at the next open (`ALTER TABLE ... ADD COLUMN`) | P3.13 (done); P6.27 (done) | per contact (device key): the shared re-pair budget and backoff, the newest session end seen, a kept PairInit (both devices and addresses), and an early re-key after a security event (when it was asked for, why, the last one) |
| `indexed_sessions.sqlite` `endpoint_parked_outbound`, `endpoint_inbound_seen` (Phase 5 P5.4, the long message horizon) | additive in schema 1 (clear columns) and 4 (kh `recipient_device` / `peer_device` and kh `message_id` + sealed meta with every other value; the inbound table also a clear `prune_after_hour`); no version change; moved by the rebuilds (forward, back, re-key) with rowids kept; a clear table an older build of the pack left in a store it sealed moves at the next open; removing a contact deletes its rows | P5.4 (done) | per contact (device key) and message id: messages waiting for a new session until their deadline (when written, the deadline, the last session), and the message ids received, kept for the sender's deadline plus a day |
| `indexed_sessions.sqlite` `indexed_session_letter` (Phase 5 P5.12, letter sessions; P5.14 the kept PairResponse) | additive in schema 1 (clear columns) and 4 (clear `session_id` (R20) and `role`, kh `peer_device` + sealed meta with the device, the kept PairInit or PairResponse and the start, bound to the `session_id`); no version change; the row cascades with its head (no prune hour of its own; removing a contact leaves it until the head expires, like the reset sidecar); moved by the rebuilds (forward, back, re-key) with rowids kept; a clear table an older build of the pack left in a store it sealed moves at the next open; a clear table P5.12 made gains the `pair_response` column at the next open (`ALTER TABLE ... ADD COLUMN`, empty) | P5.12, P5.14 (done) | per session: that it is a letter session, its role (1: started here, 2: accepted from a letter), the other device, for role 1 the exact PairInit (both devices and addresses), for role 2 the exact PairResponse (the responder device; the REPLY letter carries it back, possibly days later) |
| `indexed_sessions.sqlite` endpoint tables (`endpoint_outbox`, `endpoint_inbox`, `endpoint_receipts`, `endpoint_ack_intents`, `endpoint_ack_receipts`, `endpoint_outstanding_messages`, and PP.8's `endpoint_inbox_deleted`) | schema 2 (or 1) -> 3 (sections 4.12, 7.3): kh message ids, digests, devices, nonces; sealed wire blobs; meta; the inbox's insertion `seq`; `kh_envelope` / `kh_ack` replace blob equality; `endpoint_inbox.sealed_local_row` unchanged | PP.14 (done) | who sent what when |
| `friend_custody.sqlite` (`custody_objects_v1`, `custody_released_v1`, on a custodian) | schema 1 -> 2 (sections 4.15, 7.4): `kh_object_digest`, `kh_recipient`, `kh_depositor`, the payload sealed, `meta`, `prune_after_hour`; RELEASE deletes the row and keeps only the released digest (keyed) and its expiry hour; behind FRIEND_CUSTODY | PP.17 (done) | which friends wrote to whom, when |
| `friend_custody.sqlite` `custody_letters_v1` (Phase 5 P5.13, letters held for a contact, on a custodian) | additive in schema 1 (clear columns) and 2 (`kh_letter_digest`, `kh_recipient`, `kh_depositor`, the letter sealed whole (`custody_letters_v1.letter`, AAD the keyed digest), `meta` with the clear digest, both parties and both times, clear `page_token`, `bytes` and `prune_after_hour`); no version change; always in the shape of the objects (a keyed table an older build of the pack left in a clear store is dropped and created clear, only while the objects are clear; a clear one it left in a keyed store moves at the open, review C-2); moved by the rebuilds (forward, back, re-key) with rowids kept and resealed by the data-key rotation; RELEASE deletes the letter and keeps only its keyed digest in `custody_released_v1`; WITHDRAW by the depositor deletes it and keeps nothing; behind FRIEND_CUSTODY and the letter gate | P5.13 (done) | which friends left a letter for whom, when, and its size rounded to 512 bytes |
| `custody_handoff.sqlite` (`custody_forward_v1`, `custody_tags_v1`; Phase 5 P5.19, custody handoff on a custodian) | its own file, schema 1 (clear columns, a plain profile) or 2 (section 7.6: `kh_object_digest`, `kh_next_hop`, `kh_depositor`, `kh_recipient`, the RSO1 sealed whole (`custody_forward_v1.rso1`, AAD both keyed key columns), `meta` with every other value, clear `state`, `bytes`, `conflicted`, `store_tag` of a registration and `prune_after_hour`); created lazily by the first admitted FORWARD or REGISTER, in the shape of the profile's mode; a clear store in a sealed profile moves at its open and in the privacy passes, back at `raven privacy unseal`, keyed anew at `raven privacy rotate-meta`, resealed by the data-key rotation (each move reads the few rows whole and writes the other shape in one transaction, then the scrub); rows go when they expire (forward rows with their object, at most 7 days; tags at most 72 h) and when a party is no longer a pinned contact; a damaged file is moved aside as `custody_handoff.sqlite.corrupt-<ms>` (the store's own shape) and dropped by the prune after 8 days; erase removes both; behind FRIEND_CUSTODY and CUSTODY_HANDOFF | P5.19 | for a first custodian: which friend (the depositor, the object's signer) asked it to hand an object on to which other friend, the object (ciphertext; its RSO1 header names the daily store tag and the times), and how the hand-on went; for a final custodian: which contact registered which inbound store tags, until when, and which tags two contacts claimed |
| `security_events.sqlite` (`sec_counts`, `sec_alerts`, `sec_meta`; Phase 6b P6.23, the security ledger) | born keyed, no clear shape (section 7.7): `kh_subject` (`device-key`) with the clear key only in each row's sealed `meta`; clear `day`, `kind`, `n`, `first_hour`, `last_hour`, `severity`, `state`, `action` (a fixed code), `resolved_hour`; created only while `SECURITY_EVENTS` is live and only in a sealed profile with the key loaded (otherwise no ledger: the events stay in memory); resealed by the data-key rotation, keyed anew at `raven privacy rotate-meta`, deleted by `raven privacy unseal`; counts and resolved alerts go after 30 days, at most 256 open alerts; a damaged file, or one keyed under another key, is moved aside as `security_events.sqlite.corrupt` (one copy, dropped after 30 days and by `raven security clear`); erase removes both; behind SECURITY_EVENTS | P6.23 | per contact, custodian, depositor, relay or update passer: which kinds of security event, how many per day, and the open alerts by the hour; network sources only as a count per kind and day, never an address, a port, a message id or a network tag |
| `queue.sqlite`, `forward_queue.sqlite` (legacy bridge, gated) | `secure_delete` only (PP.2); sealing listed for later (OD-PP-11) | PP.2 | legacy bridge objects |
| `prekey_lifecycle.sqlite` | plain: a lock table only (`prekey_actor_lock`) | - | nothing about friends |

### 6.3 Under the epoch data keys (PP.10)

`chat_history.json` (RVNHIST2), `outbound_body_stage.bin` (RVNOSTG2) and the `app_channel.sqlite3`
inbox rows (format byte 0x02), in a sealed profile (section 4.8). A plain profile keeps them under
K_hist directly, as before the pack; readers accept both forms forever. Rows set aside in
`app_quarantine` stay as they were (they did not open).

### 6.4 Already protected (keystore or K_hist; unchanged by the pack)

The identity seed (the keystore; `identity.seed` holds a DPAPI blob on Windows, and the seed
itself only with the lab `locked-file` backend or in a legacy profile), `keystore.vault` (the
Linux passphrase vault), the per-session secrets (the keystore; `indexed-session-secrets/` holds
`<account>.dpapi` blobs on Windows and `<account>.bin` with the lab backend) and the prekey
secrets (the keystore; `prekey-lifecycle-secrets/` on Windows, `prekey_lifecycle.protected` with
the lab backend), and Windows' K_hist `chat_history_key.dpapi` (DPAPI-wrapped, PP.11, section
4.9). Erase (PP.16) deletes them, K_hist first; prune already deletes per-session items.

### 6.5 Plain by design

| File | Why it stays plain |
|---|---|
| `node_policy.json` (all but `p2p_relays`, `relay_external`, `custody_home` and `p2p_proxy`) | settings the node reads before the keystore; the listen settings stay here (they name at most this computer's own interface, and the node binds before any keystore call); so do Phase 3's on/off settings `lan_off` (P3.2), `lan_verified_only` (P3.C2, read at each LAN link: no friend, address or time in it), the friend-mailbox consent `custody_use` (P3.16, a yes or no), and Phase 4's IPv6 pinhole consent `v6_pinhole` (P4.20: on, off or unset, like `upnp`; no router, address or lease in it) and PeerId rotation setting `peer_rotation` (P4.28: on, off or unset; no contact, PeerId or epoch in it. Which key is in use and a rollback live in raven-node's memory only; when rotation became ready is sealed in `peer_rotation_state.json`, section 6.1). So do Phase 5's nearby consent `nearby` and its background-mail setting `nearby_background_mail` (P5.25: each on, off or unset; no contact, token, Bluetooth address or device name in them), and Phase 6b's settings (P6.21, each read only while its gate is live and omitted while at its default): `security_auto_rekey`, `security_silent_to_strangers` (`automatic`, `on` or `off`), `auto_lock_on_sleep`, `update_carry_for_friends`, `update_serve` (on, off or unset; no contact, key or address in them) and `lan_listen_port` (this computer's own port, read before the keystore to bind, like the listen settings). So does Phase 6a's learning switch `learning` (P6.2, `raven learning on|off`: on, off or unset; nothing learned is in it, the model is `learning.bin`, section 6.1). The meeting time of `raven lan on --for` is not a setting but a record of when a meeting ends: sealed on its own (`lan_meeting.json`, section 6.1) |
| `node_policy.json.bad` | Phase 3 (P3.6): an unreadable `node_policy.json` that `raven lan on` replaced, kept as it was for the user; plain like the file it was; erase removes it |
| `privacy.json`, `meta_key.rmk` | settings and markers; the wrapped key itself |
| `peer_cache.generation` | a number |
| `identity.backend`, `identity.binding`, `keystore.backend` | own identity bookkeeping |
| `device_x25519.pub` (and the lab's `lab_device_x25519.pub`) | a public key |
| `erase_in_progress` | the erase marker (PP.16, section 4.14): no content |
| `desktop_settings.json` (the desktop apps' engine) | the apps' settings that name nobody (receive, motion, what quitting does, lock on sleep); the user's name is in `desktop_private.rms` (section 6.1) and the chat-keeping time in `privacy.json` (`chat_keep`, PP.9); erase removes it |
| `*.lock.sqlite` (and `-wal`, `-shm`, `-journal`) | empty lock databases; the per-friend send lock is named by a keyed hash in a sealed profile (PP.6, section 4.4), and an older build's, named by the friend's key, is deleted there (section 4.22) |
| `raven-node.sock`, `raven-node.sock.lock` | the IPC endpoint |
| `raven-node-service.log`, `raven-node.log`, `raven-node.err` | capped logs, counts and fixed codes only (cutoff pack M3 / CP.8); the legacy `raven-node run` prints received text to stderr and is out of scope |
| `contact_request_<id>.bin`, `contact_request_<id>.wire`, `contact_accept_<id>.wire` | **confirmed by this scan:** exports `raven contact request` / `accept` write for the user to hand over; the `.bin` is ciphertext only and the `.wire` is the request as it travels; erase removes them |
| `mailbox_store.json`, raven-swarm `offline_mailbox_v1.json` | lab / experimental |
| `lab_*` files and folders (`lab_device_x25519.*`, `lab_device_cert.json`, `lab_pair_response.rvpr1`, `lab_endpoint_inbox/`) | lab only |
| `queue.db`, `outbound_body_stage.json`, `prekey_hybrid.secret` | legacy names: read once or deleted, never written by this build |
| dedicated relay folders (no identity: `relay_allow.json`, `relay_status.json`, `relay_key.ed25519`) | no key root exists there |
| `chat_history.json.untrusted-plaintext.<hex>` | only if it ever happened; `raven privacy status` lists it, erase removes it (PP.18) |
| outside the data dir: the login item, shell history, terminal scrollback; the lab clock file (`RAVEN_LAB_CLOCK_FILE`, harness only) | erase removes Raven's own login item; the guide covers the rest (PP.16, PP.19) |

### 6.6 Found by this scan, not in the plan's table

| Find | Added by | Decision recorded here |
|---|---|---|
| `relay_memory.json` | Phase 2 (automatic relay choice) | kind 29, PP.6 |
| `friend_relay/` inside a profile: `relay_status.json`, `relay_key.ed25519` (its allow-list is the profile's `relay_allow.json`, kind 21, sealed by PP.5) | Phase 2 (friend relays) | status kind 30 and key kind 31 (PP.6, which touches the friend relay's start) |
| `route_hints_state.json` clear `lan` address and unkeyed `global` digest | Phase 2; found again by the cutoff follow-up re-verify | sealed (kind 17) by PP.5, which covers both |
| `node_policy.json` `relay_external` (this computer's own public names, e.g. a home DNS name) and `internet_listen` / `p2p_listen` (may name one LAN address) | Phase 1 and 2 | decided by PP.6 as recommended: `relay_external` moved to `node_policy_peers.rms` with `p2p_relays`; the listen settings stay plain (read before the keystore to bind) |
| `outbox_routes.json` `ended` evidence | cutoff review FU-3 | inside kind 4, no change of rule |
| `peer_session_end`, `peer_session_end_erased` | cutoff CP.6 | keyed with the PP.13 tables |
| `lan_noise_pins.json.corrupt` | cutoff CP.2 | the `.corrupt` rule (PP.5); `lan_noise_pins.rms` gets no plain quarantine copy |

### 6.7 Deleting in SQLite (PP.2)

Every connection that can delete runs `paths::harden_sqlite` (`PRAGMA secure_delete=ON`) right
after open: deleted rows, the space a shrinking row leaves and freed pages are overwritten with
zeros. The setting is per connection (the bundled SQLite is not built with
`SQLITE_SECURE_DELETE`); the file format and `user_version` are unchanged. Stores:
`indexed_sessions.sqlite` (the store, and `SessionMetadataReader`, through which removing a
contact deletes its remembered session end), `owed_acks.sqlite`, `friend_custody.sqlite`,
`app_channel.sqlite3` (it had the pragma inline before), and the legacy `queue.sqlite` and
`forward_queue.sqlite`. Lock databases hold nothing and skip it (`DataDirLock`, `*.lock.sqlite`,
and `prekey_lifecycle.sqlite`, a lock table only).

`paths::checkpoint_truncate` (`PRAGMA wal_checkpoint(TRUNCATE)`) then moves what a delete overwrote
into the main file and empties the WAL. It runs at the end of `prune_expired_sessions`, of the
owed-ACK prune (`OwedAcks::list`) and of custody `maintain` and `purge`; the retention, clear and
erase steps add it after their deletes. It returns `busy` while another connection holds an older
read snapshot (raven-node and the ash chat poller keep connections open): nothing fails, the
caller's next prune pass checkpoints again, and `raven privacy status` will say "scrub pending"
(PP.18). It waits at most 250 ms, because a TRUNCATE checkpoint holds the write lock while it
waits for readers.

What this does not cover: it cleans what the filesystem shows (a copied data folder, a later
backup). The old frames of a truncated WAL and the freed pages stay in freed disk blocks until
they are overwritten; only key rotation (PP.10) and full-disk encryption cover those. Pages freed
before a store was first opened by a PP.2 build stay readable on its freelist until the one
`VACUUM` of PP.12-PP.14 (test `pages_freed_before_secure_delete_stay_until_vacuum`). SQLite temp
files (sorts, index builds) can land in the OS temp folder; the migrations of PP.12-PP.14 set
`temp_store=MEMORY`.

## 7. SQLite column audit (PP.12)

Every Raven SQLite store and table (a scan of the `CREATE TABLE` statements of `rc/`, `rn/` and
`ash/` on 2026-10-19, tests excluded) and every column that holds a public key, an rvn1 address,
a message id, an object digest, a wire nonce, a wire object or a time, with its target. PP.13,
PP.14 and PP.17 follow these tables; a later column joins them before it ships.

**Targets.** `kh_<name> (type)`: a keyed lookup (`at_rest::index`, section 3) of that value type,
with the clear value in `meta`. `meta`: into the row's sealed `meta` blob
(`at_rest::seal_row(keys, table, primary key as stored, JSON)`, byte values as hex). `sealed`: the
column itself holds a sealed row blob, AAD label `<table>.<column>`. `clear`: kept, with the
reason. `prune hour`: a clear `prune_after_hour` (the time rounded UP to the hour) that only a
prune compares; every decision reads the exact time from `meta`. Rowids and index names are kept.

### 7.1 `owed_acks.sqlite` (PP.12: done, schema 2)

| Table | Column | Holds | Target |
|---|---|---|---|
| `owed_acks_v1` | `ack_digest` (PK) | object digest | `kh_ack_digest` (`object-digest`) |
| | `peer` | device key | `kh_peer` (`device-key`), index `idx_owed_peer` |
| | `session_id` | random session id (named on the wire) | clear (R20) |
| | `bytes` | the sealed ACK envelope (its clear header names devices) | sealed (`owed_acks_v1.bytes`) |
| | `expires_at_ms` | time | `meta`, prune hour |
| | `origin` | a code 0-3 | `meta` |
| | `recorded_at_ms` | time (the listing order) | `meta` (the order is computed after opening) |
| `owed_ack_held_v1` | `ack_digest` | object digest | `kh_ack_digest` (`object-digest`) |
| | `custodian` | device key | `kh_custodian` (`device-key`) |

### 7.2 `app_channel.sqlite3` (PP.12: the sender tables done, schema 3)

| Table | Column | Holds | Target |
|---|---|---|---|
| `app_inbox` | `sender_device` | device key | `kh_sender` (`device-key`) |
| | `message_id`, `app_id` | random ids (on the wire) | clear (open item below) |
| | `sender_identity` | identity key | `meta` |
| | `cert_hash` | digest of the sender's certificate | `meta` |
| | `created_at_ms` | time, in no query | `meta` |
| | `received_at_ms` | time | clear: the page order and the RDAP cursor compare it exactly; items live 7 days at most |
| | `expires_at_ms` | time | clear: the pending count and the upkeep compare it (open item below) |
| | `content_type`, `body_len` | a protocol word; a size | clear: the caps and the filter |
| | `sealed` | the item | unchanged: the epoch `app-row` key (PP.10) |
| `app_tombstones` | `sender_device` | device key | `kh_sender` |
| | `message_id`, `app_id` | random ids | clear (open item below) |
| | `disposition`, `at_ms` | a word; time | clear: the retention and the cap's order (8 days) |
| `app_quarantine` | as `app_inbox` | | as `app_inbox`; its `meta` is the inbox row's, byte for byte; `quarantined_at_ms` clear (its prune) |
| `app_outbox` | `peer_identity`, `peer_device` | identity key, device key | **open**: `kh_peer_identity`, `kh_peer_device` (`device-key`) |
| | `message_id`, `object_digest` | message id, object digest | **open**: `kh_message_id` (`message-id`), `kh_object_digest` (`object-digest`) |
| | `client_ref`, `body_sha256` | RDAP's own reference (may name a task); digest of the body | **open**: `meta` (a keyed digest where a query compares it) |
| | `session_id` | random session id | clear (R20) |
| | `content_type`, `state`, `last_error_code`, `attempt_seq` | words, codes, a counter | clear |
| | `created_at_ms`, `expires_at_ms`, `updated_at_ms` | times | clear: the retention and the eviction order |
| `app_consumer` | `consumer`, `bound_at_ms` | the local consumer's own name; time | clear: no friend data |
| `app_pair_attempts` | `peer_device` | device key | **open**: `kh_peer_device` |
| | `at_ms` | time | clear: the daily budget and its spacing |

**Open item (not in the plan's steps).** PP.12 names the sender column only, and no later step
touches this store: the outbox's and the pairing budget's friend keys, and the store's message
ids, are still clear. The app channel is gated off in release (`APP_CHANNEL_PRODUCTION_ENABLED =
false`), so no release profile writes this store; the targets above are for the owner and the
PP.20 review. Until they are keyed, `raven privacy status` does not call a schema-3 store keyed
while `app_outbox` or `app_pair_attempts` holds a row (a lab build's app channel wrote it): its
JSON entry says `"keyed": false` with the tables in `"clear_tables"`, and the store is not counted
among the encrypted databases (review E-harness-docs-ci-8). Both tables have to be keyed (a
schema 4) before the app channel's gate flips.

### 7.3 `indexed_sessions.sqlite` (PP.13: heads, bindings, resets, session ends, done, schema 2; PP.14: endpoint tables, done, schema 3; review B-sealed-stores-1: the heads' `init_id`, done, schema 4)

| Table | Column | Holds | Target |
|---|---|---|---|
| `indexed_session_heads` (PP.13) | `record_key`, `binding_digest`, `init_hash`, `session_id`, `generation` | random ids, digests, a counter | clear (R20: naming keychain items, or digests of values no file holds in clear) |
| | `init_id` | random id; the record key is an unkeyed digest of it and of public values, so in clear it names the friend | `kh_init_id` (`nonce`), its UNIQUE index under the same name, the value in `meta` (schema 4, review B-sealed-stores-1); the tie-break (`created_at_ms DESC, init_id DESC`) is finished in Rust from `meta` |
| | `profile_id` | the protocol label `ATSAM/indexed-session/v1` | clear: a constant |
| | `initiator_address`, `responder_address` | rvn1 addresses | `kh_initiator_address`, `kh_responder_address` (`rvn1-address`) |
| | `initiator_device`, `responder_device` | device keys | `kh_initiator_device`, `kh_responder_device` (`device-key`) |
| | `created_at_ms` | time | `meta`, plus a clear `created_hour` (rounded down): the SQL orders by it at most and Rust finishes the order (`created_at_ms DESC, init_id DESC`) from `meta`; the horizon's `created_at_ms <= created_to_ms` moves to Rust |
| | `expires_at_ms` | time | `meta`, prune hour (`expires_at_ms > now` decisions read `meta`) |
| `indexed_session_reset` (PP.13) | `session_id` | random session id | clear (R20) |
| | `peer_device` | device key | `kh_peer_device`, its index kept |
| | `confirmed_at_ms`, `reset_round_at_ms`, `retired_at_ms` | times | `meta`, with a clear 0/1 column each where a query tests `IS NULL` |
| | `initiated_local`, `retire_cause` | a flag, a code (1-7; 7, a local security re-key, since Phase 6b P6.27: a table made with the older 1-6 CHECK is rebuilt in place, rows and rowids kept, before its first such row) | clear |
| `endpoint_reseal_ledger` (PP.13) | `recipient_device`, `message_id` (PK) | device key, message id | `kh_recipient_device`, `kh_message_id` |
| | `reseals`, `notified` | a counter, a flag | clear |
| | `last_reseal_at_ms`, `expires_at_ms` | times | `meta`; a prune hour of the instant the row goes (`expires_at_ms` plus a day) |
| `peer_reset_state` (PP.13) | `peer_device` (PK) | device key | `kh_peer_device` |
| | `fork_evidence_at_ms`, `user_confirmed_at_ms` | times | `meta` |
| `peer_session_end` (cutoff CP.6; PP.13) | `peer_device` (PK) | device key | `kh_peer_device` |
| | `ended_at_ms` | time | `meta`, plus a clear hour for its 30-day prune |
| `peer_session_end_erased` (CP.6; PP.13) | `peer_device` (PK), `created_to_ms` | device key, time | `kh_peer_device`; `meta` (compared in Rust) |
| `peer_session_renewal` (Phase 3 P3.13) | `peer_device` (PK) | device key | `kh_peer_device` |
| | `window_start_ms`, `attempts_in_window`, `last_attempt_at_ms`, `failures`, `last_session_expires_at_ms`, `pending_expires_at_ms` | times, counters | `meta`, plus a clear hour for its prune (the row goes once its kept PairInit expired, the pair's last session ended 14 days ago and its last round is a day old) |
| | `pending_init` | a PairInit as it went on the wire (both devices, both rvn1 addresses) | `meta` |
| | `early_requested_at_ms`, `early_reason`, `last_early_ms` (Phase 6b P6.27) | times, a `SecKind` code | `meta`; they keep the row from the prune while the request (a day) or its 6 h cap lasts |
| `endpoint_parked_outbound` (Phase 5 P5.4) | `recipient_device`, `message_id` (PK) | device key, message id | `kh_recipient_device`, `kh_message_id` |
| | `created_at_ms`, `deadline_ms`, `parked_at_ms`, `send_order` | times, an order | `meta` (no clear time: the worker reads a contact's rows and orders them in Rust) |
| | `from_session` | random session id | `meta` |
| `endpoint_inbound_seen` (Phase 5 P5.4) | `peer_device`, `message_id` (PK) | device key, message id | `kh_peer_device`, `kh_message_id` |
| | `first_seen_ms`, `keep_until_ms` | times | `meta`, plus a clear hour for its prune (the row goes once `keep_until_ms` has passed) |
| `indexed_session_letter` (Phase 5 P5.12) | `session_id` (PK, FK to the head, cascading) | random session id | clear (R20) |
| | `role` | a code (1 or 2) | clear: the provisional cap reads it in the seal's own transaction |
| | `peer_device` | device key | `kh_peer_device` |
| | `pair_init`, `created_at_ms` | a PairInit as it went on the wire (role 1 only: both devices, both rvn1 addresses), a time | `meta` (no clear time: the row goes with its head) |
| | `pair_response` (P5.14) | a PairResponse as this node signed it (role 2 only: the responder device, the session's times) | `meta` |
| `endpoint_receipts` (PP.14) | `session_id`, `session_generation` | random id, counter | clear (R20) |
| | `object_digest`, `message_id`, `sender_device` | digest, message id, device key | `kh_object_digest`, `kh_message_id`, `kh_sender_device` (the UNIQUE constraint keeps its shape) |
| `endpoint_inbox` (PP.14) | `object_digest`, `message_id`, `sender_device` | as above | `kh_*` as above |
| | `created_at_ms`, `received_at_ms` | times | `meta`, plus a clear insertion `seq` (the rowid, `AUTOINCREMENT`) for the reader's place and every `ORDER BY received_at_ms`; the retention cut (`received_at_ms <= ?`) and the per-sender floor (`MAX(received_at_ms)`) read `meta` |
| | `sealed_local_row` | the message, under its session's key | unchanged |
| `endpoint_ack_intents` (PP.14) | `object_digest`, `message_id`, `remote_device` | as above | `kh_*` |
| | `status`, `state` | codes | clear |
| | `immutable_ack_bytes` | the ACK as sent (wire object) | sealed, plus `kh_ack` (`object-bytes`) for its equality check |
| `endpoint_outstanding_messages` (PP.14) | `message_id`, `recipient_device` | message id, device key | `kh_*` |
| | `delivery_state` | a code | clear |
| `endpoint_ack_receipts` (PP.14) | `object_digest`, `outer_message_id`, `acked_message_id`, `remote_device` | digests, message ids, device key | `kh_*` |
| | `ack_nonce` | wire nonce | `kh_ack_nonce` (`nonce`; its UNIQUE keeps its shape) |
| | `status`, `session_generation` | a code, a counter | clear |
| | `created_at_ms` | time | `meta` |
| `endpoint_outbox` (PP.14) | `object_digest`, `message_id`, `recipient_device`, `source_ack_intent` | digests, message id, device key | `kh_*` (`source_ack_intent`: `object-digest`) |
| | `ack_nonce`, `seal_nonce`, `anti_replay_nonce` | wire nonces | `kh_*` (`nonce`; the UNIQUE constraints keep their shape) |
| | `immutable_envelope_bytes` | the envelope as sent (wire object) | sealed, plus `kh_envelope` (`object-bytes`) |
| | `kind`, `state`, `ratchet_index`, `session_generation` | codes, counters | clear; rowids kept (`ORDER BY rowid`) |
| `endpoint_inbox_deleted` (PP.8; PP.14) | `session_id` | random session id | clear (R20) |
| | `object_digest`, `sender_device` | digest, device key | `kh_object_digest`, `kh_sender_device` |
| | `deleted_at_ms`, `max_received_at_ms` | times | `meta`, plus the deleted row's clear `seq` (the floor reads only the tombstones at or after the sender's newest row) |

### 7.4 `friend_custody.sqlite` (PP.17: done, schema 2; behind `FRIEND_CUSTODY_PRODUCTION_ENABLED`)

| Table | Column | Holds | Target |
|---|---|---|---|
| `custody_objects_v1` | `object_digest` (PK) | object digest | `kh_object_digest` (`object-digest`) |
| | `recipient`, `depositor` | device keys | `kh_recipient`, `kh_depositor` (`device-key`; the indexes keep their shape and names) |
| | `store_tag`, `page_token` | the routing tag (the daily store tag) and the page token a fetch names on the wire | clear |
| | `rso1` | the deposited object (wire object) | sealed (`custody_objects_v1.rso1`); deleted at RELEASE |
| | `bytes` | a size | clear: the quota |
| | `admitted_at_ms` | time | `meta` (the byte rate and the held recipients' order read it) |
| | `expires_at_ms` | time | `meta`, prune hour (index `idx_custody_exp`) |
| | `released_at_ms` | time | gone: a RELEASE deletes the row (every row is unreleased); an older build's released row becomes a released digest at the migration or the next maintenance |
| `custody_released_v1` (PP.17, new) | `object_digest` (PK) | object digest (or a released letter's digest, Phase 5 P5.13) | `kh_object_digest`: the only value a released object or letter leaves |
| | `prune_after_hour` | the hour the object would have expired in | clear: the prune; nothing else is kept |
| `custody_letters_v1` (Phase 5 P5.13, new) | `letter_digest` (PK) | letter digest | `kh_letter_digest` (`object-digest`) |
| | `recipient`, `depositor` | device keys | `kh_recipient`, `kh_depositor` (`device-key`; indexes `idx_custody_letters_*`) |
| | `page_token` | the page token a fetch names on the wire | clear |
| | `letter` | the RAL1 letter (its header names both devices, the times and a bundle hash) | sealed (`custody_letters_v1.letter`); deleted at RELEASE or WITHDRAW |
| | `bytes` | a size | clear: the quota |
| | `admitted_at_ms`, `expires_at_ms` | times | `meta`; prune hour |

The plan's target for `released_at_ms` was a clear 0/1 column; RELEASE now deletes the row instead
and writes its digest to `custody_released_v1`, so the open-object table keeps every NOT NULL
constraint and a released object leaves nothing in it (section 4.15). Phase 5's letter table
`custody_letters_v1` (P5.13) follows these rules: keyed parties and digest, the letter sealed, the
deletion at RELEASE (and at the depositor's WITHDRAW). The handoff tables (`custody_forward_v1`,
`custody_tags_v1`) live in their own store, `custody_handoff.sqlite` (Phase 5 P5.19, section
7.6), under the same rules; the schema guard (`no_clear_key_address_or_message_id_columns`, PP.13)
covers that store too.

### 7.5 Stores kept as they are

`queue.sqlite` (`outgoing`: message id, packed envelope, the peer's address, state, time;
`seen_inbound`) and `forward_queue.sqlite` (`forward_queue`, `bridge_seen`,
`forward_objects_v2`, `bridge_seen_objects_v2`, `bridge_peer_rate`): the legacy bridge, gated off;
`secure_delete` only, sealing listed for later (OD-PP-11). `prekey_lifecycle.sqlite`
(`prekey_actor_lock`): a lock table. The `*.lock.sqlite` lock databases: empty. The full-braid
lab's SQLCipher profile: lab only.

### 7.6 `custody_handoff.sqlite` (Phase 5 P5.19: schema 1 or 2 from the start; behind `FRIEND_CUSTODY_PRODUCTION_ENABLED` and `CUSTODY_HANDOFF_PRODUCTION_ENABLED`)

| Table | Column (schema 1) | Holds | Schema 2 |
|---|---|---|---|
| `custody_forward_v1` | `object_digest`, `next_hop` (PK) | object digest, the next custodian's device key | `kh_object_digest` (`object-digest`), `kh_next_hop` (`device-key`) |
| | `depositor` | the depositor's device key (the object's signer) | `kh_depositor` (`device-key`; index `idx_fwd_pair`) |
| | `store_tag` | the daily store tag the object carries | `meta` |
| | `rso1` | the object (wire object) | sealed (`custody_forward_v1.rso1`, AAD the two keyed key columns) |
| | `bytes` | a size | clear: the caps |
| | `state` | pending, handed or refused | clear: the forwarder's index `idx_fwd_due` |
| | `admitted_at_ms`, `expires_at_ms`, `last_code`, `attempts`, `next_try_ms` | times, a reply code, a count | `meta`; prune hour (`idx_fwd_exp`) |
| `custody_tags_v1` | `store_tag` (PK) | the inbound store tag a recipient registered (named on the wire by every DELIVER and FETCH) | clear |
| | `recipient` | the registrant's device key | `kh_recipient` (`device-key`; index `idx_tags_recipient`) |
| | `conflicted` | 0/1: a second recipient claimed the tag | clear |
| | `expires_at_ms`, `registered_at_ms` | times | `meta` (with the clear recipient); prune hour (`idx_tags_exp`) |

The store is new in Phase 5, so no build before it reads it: schema 1 is what a plain profile
keeps (and what `raven privacy unseal` leaves), schema 2 what a sealed profile's store is created
as or moved to. Both tables always share one shape (they are created and moved together; an open
that finds them apart fails closed). Every decision on a schema-2 row reads the exact values from
its `meta`; a `meta` that does not open counts toward the node caps until its prune hour and is
left out (counted) by a move.

### 7.7 `security_events.sqlite` (Phase 6b P6.23: keyed from its first version; behind `SECURITY_EVENTS_PRODUCTION_ENABLED`)

| Table | Column | Holds | At rest |
|---|---|---|---|
| `sec_counts` | `day`, `kind`, `n` | a day number, a `SEC_*` code (`docs/SECURITY_EVENTS.md`), a count | clear |
| | `kh_subject` | the contact, custodian, depositor, relay (`SHA-256("rvn1/sec/relay" \|\| PeerId)`) or update passer | keyed (`device-key`); NULL for network sources (all of them in one count per kind and day), this computer and an update nobody passed on |
| | `meta` | the clear key and its role | sealed (`sec_counts`, AAD `day \|\| kind \|\| kh_subject`); NULL with a NULL subject |
| `sec_alerts` | `id`, `kind`, `n`, `severity`, `state`, `action` | an alert: a code, a count, Notice/Suspicious/Alert, new/seen/resolved, a fixed action code (`REKEY_REQUESTED`, ...; never free text) | clear |
| | `first_hour`, `last_hour`, `resolved_hour` | hours since the epoch | clear (hours only) |
| | `kh_subject`, `meta` | as in `sec_counts` | keyed; `meta` sealed (`sec_alerts`, AAD `kind \|\| kh_subject`) |
| `sec_meta` | `k`, `v` | `key_check` (the keyed digest of a fixed label: a ledger keyed under another key is moved aside), `last_prune_day`, `dropped` (events a full writer queue dropped) | clear |

No IP address, port, message id, network tag, plaintext or stranger key is ever written: a
network-attributed event reaches the file only as its kind's count for the day. The ledger is new in
Phase 6b and has no clear shape: a plain profile (and a debug build without `RAVEN_LAB_AT_REST=1`)
keeps none, a process without the at-rest key writes none (its events stay in memory), and `raven
privacy unseal` deletes it instead of moving it back. At most one write per kind and subject per
minute (`security_ledger::WRITE_INTERVAL_MS`); `secure_delete` zeroes what the prune, the cap and
`raven security clear` delete. The privacy scan test feeds 10,000 random events (addresses, ports,
message ids, network tags) through the classifier and the ledger and finds none of them, and no clear
key, in the file or its WAL.

## 8. Migration and downgrade

### 8.1 Migration: what moves, when, and who moves it

Only a build that may seal does it (release; a debug build only with `RAVEN_LAB_AT_REST=1`), only
in a profile with an identity on record, never in mode `unsealed_by_user`, and never while an
older raven-node answers (the upgrade interlock: ash says the restart line at most once a day).
Readers accept both forms forever; nothing is converted back except by `raven privacy unseal`.

| What | Moves to | When, and by whom | If it cannot move now |
|---|---|---|---|
| The key file | `meta_key.rmk` created (K_hist minted only if missing) | the first sealing pass, before the mode is recorded (section 4.1) | keystore unavailable: nothing is sealed; raven-node admits nobody and retries (30 s, 1, 2, 4, 8, then every 15 min, at once on `raven status`); on Windows writes meanwhile mint no K_hist (review A-keys-format-2) |
| Registered JSON files and secrets | RMS1 under their kind, each under its writer lock | `privacy::migrate_all`: raven-node at its start (before it admits anyone), ash at the top of every command (sections 4.2-4.6) | free space short (twice the profile plus 64 MiB): deferred, retried at most hourly, `raven status` says so |
| Quarantine copies, temp leftovers | sealed in place; temp files older than 1 h deleted | the same pass | as above |
| An older build's plain rewrite (a downgrade leftover) | sealed again, the plain noise pins merged | the same pass; `raven status` says so once | as above |
| History, outbound stage, app rows | the epoch keys (RVNHIST2, RVNOSTG2, 0x02) | the same pass and every rotation pass (section 4.8) | the lock is held: the next pass |
| `owed_acks.sqlite` 1 -> 2, `app_channel.sqlite3` 2 -> 3 | keyed columns, sealed meta | the pass's store moves, the 10-minute upkeep (`upkeep_stores`) and the store's first open (section 4.10) | free space short or a reader in the way: the store keeps working in its clear schema; `scrub_pending` |
| `indexed_sessions.sqlite` 1 -> 2 -> 3 -> 4 | keyed heads, resets, endpoint tables; the heads' `init_id` keyed (schema 4) | as above, after its journals settle (sections 4.11-4.12, 4.22) | as above, and while a journal is pending |
| `friend_custody.sqlite` 1 -> 2 | keyed objects, released digests only | as above (section 4.15; custody is gated) | as above |
| Chat cursors | format 2 (`seq`) for a schema-3 store | with the session store's move (section 4.12) | - |
| Per-friend send locks | keyed names | the sealing pass and every prune pass delete each older name they can take (after the friend's keyed lock; no keyed file is created for a friend not in the book), and the next send to the friend takes both names and deletes the older one (section 4.4; review B-sealed-stores-4); rotate-meta deletes keyed names no friend in the book has | one a send holds stays until a later pass; `raven privacy status` counts it as plain |
| The retention clock | `retention_starts_at_ms` (+7 days and a notice when chats exist) | the first sealing pass (section 4.7) | - |

Scenario s120 runs this table against the build before the pack (section 4.17); carrier_matrix
C90 runs the book's part from plain books.

### 8.2 Downgrade: what an older build does with a sealed profile

| File | Older build reading the new bytes | Result |
|---|---|---|
| `contacts.json` | "contacts.json corrupt"; raven-core readers return an error | fail closed: commands stop, the node admits nobody; nothing is overwritten |
| `blocked_pubs.json` | `BlockList::load_checked` refuses; `save` refuses to overwrite | fail closed (never "nobody is blocked") |
| `lan_seen.json`, `learned_routes.json`, `route_memory.json`, `relay_memory.json` | an unparsable file reads as empty | the older build may write a small plain file (new sightings only); the new build seals it again and says so once |
| `lan_noise_pins.rms` | not opened (new name) | the older build pins on first use into a plain `lan_noise_pins.json`; the new build merges it only for contacts without a sealed pin, keeps the sealed pin where they differ (counted note), then removes the plain file |
| `peer_device_certs.json`, `prekey_store.json`, the stage | the cert and prekey readers fail (`... read`: not UTF-8, or `... corrupt`); a sealed stage is moved to `<file>.corrupt` (it does not parse) | fail closed for links and new sessions; the new build restores a `.corrupt` that opens under the profile's key when the file is missing (the stage beside a committed generation), otherwise seals the file again and deletes the copy |
| `device_registry.json`, `revocations.json`, `device_revocations_rvdr1.json`, `device_sync_seen.json` | the checked loaders fail | fail closed (no device certificate change, no revocation lost, no sync import) |
| `device_x25519.secret` | "expected 32-byte secret" | a new device certificate cannot be issued until the new build returns |
| `route_hints_state.json` | an unreadable state reads as none | the older build may write a plain state; the new build reads it and seals it again (route hints are gated in release) |
| `bootstrap.json` | `load_bootstrap` uses no bootstrap peers; `save_bootstrap` refuses an unreadable file (a sealed file that happens to be UTF-8 is moved aside, never lost) | no bootstrap peers for the older build |
| `relay_allow.json` | unreadable | the relay admits nobody; `raven relay allow/deny` refuse to edit |
| `chat_inbox_cursors.json` | the chat refuses to open | fail closed |
| `outbox_routes.json` | load returns an error; its writers replace an unreadable file | sends fail closed with an error; an older build's plain rewrite is sealed again by the new build |
| `alias_claims.json`, `nearby_registry.json`, `contact_inbox/<id>.wire` | the alias store refuses to write; the nearby store and the inbox read nothing | `raven alias publish` stops; `raven nearby` writes a new plain file (sealed again later); pending requests are not listed |
| `friend_relay/relay_status.json`, `friend_relay/relay_key.ed25519` | the status reads as corrupt; the key is not 32 bytes | the older build's friend relay does not start (friend relays are gated in release); nothing is replaced |
| `.send_<keyed>.lock.sqlite` | never taken (the older build uses `.send_<key hex>.lock.sqlite`) | the new build also takes the older name while it exists, so both still exclude each other |
| `chat_history.json` (RVNHIST2; before PP.10 already a row with `stored_at_ms`, PP.9), stage (RVNOSTG2), app rows (0x02) | `ChatHistoryError::Corrupt` (checked against the PP.1 snapshot: never moved aside, never written over); app rows quarantined | fail closed: no ACK for a received chat, the sender retries |
| `indexed_sessions.sqlite` (schema 2, PP.13; schema 3, PP.14: a PP.13 build refuses it as well; schema 4, review B-sealed-stores-1: the pack's earlier builds refuse it too), `app_channel.sqlite3`, `friend_custody.sqlite` | newer schema refused (`UnsupportedMetadataSchema` for the session store) | fail closed: the older build cannot send or receive; a racing older process may re-stamp `user_version`, so the new build detects the shape (and the older batch is a no-op on the moved tables: the index names are kept) |
| `owed_acks.sqlite` | renamed `owed_acks.sqlite.corrupt-<ms>` and rebuilt empty | owed ACKs delayed until the new build merges the set-aside copy back (PP.12); a copy that does not open as the profile's schema 2 is kept sealed (kind 64) and listed by `raven privacy status` |
| `node_policy.json` | `p2p_relays` and `relay_external` absent (moved) | no relays for the older build's p2p (gated in release anyway); when it saves the policy it writes none and the sidecar stays |
| `node_policy_peers.rms` `p2p_proxy` (Phase 4 P4.6) | an unknown field: ignored; a PP.6 build that rewrites the sidecar (its relays changed) or removes it (its relays cleared) drops it | the proxy setting reads as `auto` again (WSS proxy dials are gated in release); nothing else changes |
| `privacy.json`, `meta_key.rmk`, `tui_private.rms`, `node_policy_peers.rms`, `erase_in_progress`, `chat_history_key.dpapi` | unknown files | ignored |
| `lan_meeting.json` (Phase 3 P3.C2) | an unknown file | ignored: a raven-node before P3.C2 keeps LAN on past the meeting time (`raven lan off` still closes it) |
| `custody_home.json` (Phase 3 P3.18) | an unknown file | ignored: an older build has no home custodians |
| `learned_routes.json` `custodian_tags`, `custodian_tag_flags`, `custody_offer` (Phase 3 P3.18) | unknown fields: ignored, and dropped when the older build rewrites the file | the friends' custody offers and tags are learned again from their next RRH1 |
| `peer_schedules.json` (Phase 4 P4.25) | an unknown file | ignored: an older build never rotates and never reads contacts' schedules (rotation is gated in release anyway) |
| `peer_rotation_state.json` (Phase 4 P4.28) | an unknown file | ignored: an older build never rotates (rotation is gated in release anyway); a newer one after it starts over with one epoch of announcing first |
| `prekey_published_local.json` (Phase 5 P5.11) | an unknown file | ignored: an older build sends and accepts no letters; its rotations are not archived, so a newer build after it refuses a letter sealed to such a generation (`LETTER_UNKNOWN_PREKEY`) until its own next rotation |
| `letter_deposits.json` (Phase 5 P5.15) | an unknown file | ignored: an older build sends no letters; the letters it lists stay with their custodians until they expire (at most 7 days), and a newer build after it withdraws the settled ones |
| `custody_handoff.sqlite` (Phase 5 P5.19) | an unknown file | ignored: an older build serves no handoff ops (it answers them UNSUPPORTED, so friends park handoff there); the rows it holds stay until a newer build prunes them as they expire; a newer schema is refused by this build (fail closed: HANDOFF and TAGS answer PERSISTENCE) |
| `learning.bin` (Phase 6a P6.9) | an unknown file | ignored: an older build has no learning (gated in release anyway) and orders carriers statically; a newer build reads the file again, or keeps the model in memory when its format is newer |
| `security_events.sqlite` (Phase 6b P6.23) | an unknown file | ignored: an older build notes no security events (gated in release anyway); the rows stay until a newer build prunes them; a newer schema is refused by this build and left as it is (its events stay in memory) |
| `pair_seeds.json` (Phase 6b P6.38) | an unknown file | ignored: an older build sends no PAIR_SEED and keeps none (gated in release anyway), so its contacts fall back to the root for it; the seeds stay as they were and a newer build after it goes on from them (its contacts' entries resume, or their absence retires the seed after 2 days) |
| `knock_replays.bin` (Phase 6 review traffic-9) | an unknown file | ignored: an older build keeps its knock replay cache in memory only (the knock is gated in release anyway); a newer build after it reads the file again and drops what is older than 3 days |
| `updates/state` (Phase 6b P6.44) | an unknown file | ignored: an older build takes no advisory or log (gated in release anyway); the state stays as it was, and a newer build after it goes on from it; unknown fields a newer build wrote are dropped when this build writes the state, and a later format version is refused (nothing accepted, the file left as it is) |
| `updates/staged/` (Phase 6b P6.47) | an unknown folder | ignored: an older build installs nothing (gated in release anyway) and its `raven erase` leaves the folder (it reports it as not Raven's); a newer build after it verifies a staged build again in full before it installs it |
| `updates/downloads`, `updates/incoming/`, `updates/quarantine/` (Phase 6b P6.49) | unknown files and folders | ignored: an older build fetches, serves and quarantines nothing (gated in release anyway) and its `raven erase` leaves them (it reports them as not Raven's); a newer build after it goes on from the rows and resumes a download from its bitmap, and verifies a complete one in full again before it stages it |
| `capability_floor.json` (Phase 6b P6.29) | an unknown file | ignored: an older build keeps no capability floor and refuses no session profile (gated in release anyway); the marks stay as they were, and a newer build after it goes on from them; unknown fields a newer build wrote are ignored and dropped when a mark is written again |
| `node_policy.json` `nearby`, `nearby_background_mail` (Phase 5 P5.25) | unknown fields: ignored, and dropped when an older `ash` saves the policy | an older build has no nearby carrier (gated in release anyway); the consent is asked again |
| `node_policy.json` `security_auto_rekey`, `security_silent_to_strangers`, `auto_lock_on_sleep`, `update_carry_for_friends`, `update_serve`, `lan_listen_port` (Phase 6b P6.21) | unknown fields: ignored, and dropped when an older `ash` saves the policy | an older build has none of these features (each is gated in release anyway); the settings go back to their defaults, and a profile that picked a random LAN port listens on the default port again |
| `outbox_routes.json` `choice: "nearby"` (Phase 5 P5.25, lab `--carrier nearby` only) | the whole file does not parse: load returns an error, and its writers replace it | that build fails narrow (LAN only, as for a missing record); a P5.25 build reads every other entry and keeps one it cannot parse |
| `contacts.json` `p2p_next` (Phase 4 P4.27) | an unknown field: ignored, and dropped when an older ash rewrites the book | the friend's next-epoch PeerId is no longer admitted from the card; its route hints' schedule still is (gated in release anyway) |
| `node_policy.json` `lan_verified_only` (Phase 3 P3.C2) | an unknown field: ignored, and dropped when an older `ash` saves the policy | an older raven-node admits unverified contacts on the LAN again |
| `node_policy.json` (a plain profile) and `node_policy_peers.rms` `send_hold` (Phase 6b P6.31) | unknown fields: ignored; an older `ash` that saves the policy drops the plain one, and an older build that saves different relays drops the sidecar's | an older raven-node sends to a paused friend again; the pause is the user's own one-key choice, never a protection Raven relies on |
| `node_policy.json` `custody_use` (and, in a plain profile, `custody_home`), `node_policy_peers.rms` `custody_home` (Phase 3 P3.16) | unknown fields: ignored; an older `ash` that saves the policy drops the plain ones, and an older build that saves different relays drops the sidecar's | custody fails closed: no friend used as a mailbox until `raven custody use on` is answered again; home custodians back to automatic |
| `learned_routes.json` `nat_class` (Phase 4 P4.24) | an unknown field: ignored, and dropped when an older raven-node rewrites the file | the hole-punch policy of a NAT_CLASS build forgets that friend's class until its next RRH1 (gated in release anyway) |
| `node_policy.json` `v6_pinhole` (Phase 4 P4.20) | an unknown field: ignored, and dropped when an older `ash` saves the policy | an older raven-node opens no IPv6 pinhole (pinholes are gated in release anyway); `upnp` keeps its meaning |
| `node_policy.json` `peer_rotation` (Phase 4 P4.28) | an unknown field: ignored, and dropped when an older `ash` saves the policy | an older raven-node keeps the fixed PeerId (rotation is gated in release anyway) |
| `privacy.json` `locked_by_user` (PP.15) | a pack build before PP.15 keeps the field when it writes the file; no older build reads it | an older `ash` starts raven-node on its next send: the lock holds only for this build's commands |
| Windows: `meta_key.rmk`, history, stage and app rows under K_hist (`"RKH1"`, PP.11) | an older Windows build tries DPAPI and fails | fail closed (`AuthenticationFailed`; app rows quarantined) |
| `tui_state.json` (older app) | missing fields take defaults | all messages show unread; no display name |

**The way back:** `raven privacy unseal` (PP.18) stops this profile's node, writes every sealed
file back in today's format, reverses each SQLite migration, deletes `meta_key.rmk` last and sets
mode `unsealed_by_user`; the new build then never seals again until `raven privacy seal-now`.
Scenarios s120 and s124 test the round trip against a snapshot of the build before this pack
(taken in PP.1, kept outside the repository, passed as `RAVEN_FAULT_PRIVACY_OLD_BIN`).

## 9. Numbering

Privacy pack (after the cutoff pack): carrier_matrix C87 (was Phase 6b's C87), C90-C93; fault
scenarios s117 (was Phase 6b's s97), s120-s129; real row R34 (erase, Lock v1 and sealing on real
keystores). Phase 6b moves to s110-s119 (C80-C89 kept); Phase 6a has s100-s109 and C70-C79. The
same registry is in `scripts/lan_fault_matrix.py` and `carrier_matrix.rs`. Taken (PP.19): C87, C90
and C91; s117 and s120-s125; R34 (an unpublished test checklist). C92, C93 and
s126-s129 are free.

## 10. Honest limits

1. Old versions of `meta_key.rmk` in freed disk blocks are wrapped under the never-rotated K_hist:
   someone who recovers raw freed blocks **and** can use this account's keychain, vault
   passphrase or Windows login can recover an old epoch key. Rotation protects against anyone who
   later uses Raven or the keychain normally; only erase, full-disk encryption with TRIM and having
   no backups cover the raw-disk case. On Windows, copies from before PP.11's migration were
   DPAPI-direct and open with the Windows login alone, erase or not.
2. Plaintext written before sealing stays in freed blocks until overwritten. The same holds for
   what SQLite deletes: `secure_delete` and checkpoints clean the files, not the freed disk
   blocks of old WAL frames and pages (section 6.7).
3. Equal values give equal `kh` inside one profile (section 3).
4. No freshness: someone who can write the data folder can put back an older sealed file; such an
   attacker can also replace the Raven binary (out of scope, THREAT_MODEL local-malware row).
5. The advisory-file rule prefers keeping sealed data to working around it: a sealed route hint
   state that does not open (a changed byte) holds route hints back for the profile until the
   file is removed by hand (the skip is counted and `Status.at_rest` says `unreadable_file_kept`);
   sealed noise pins that do not open stop the dials that would check them, as an unreadable pin
   store always did.
   PP.6's address files follow the same rule: one that does not open learns nothing new until it
   is removed by hand, and a removed contact's entries stay in it (sealed).
6. A sealed profile shared with an older build that has never sent to a friend has no older lock
   file to take: if that older `ash` makes one while this build is already sending to the same
   friend, the two may overlap once (the older build cannot know the keyed name). The keyed name
   exists from this build's first send on, and the older name is taken whenever it exists.
7. The app store's outbox, its pairing budget and its message ids still name friends in clear
   (section 7.2, an open item outside the plan's steps); the app channel is gated off in release.
8. A store whose move to its keyed schema waits for free disk space keeps working, and writing,
   in its clear schema until a pass finds the space (section 4.10). The session store's move
   also waits while a journal is pending (section 4.11). An older build that set the
   owed-ACK store aside loses the rows only its deleted WAL held (it deletes the WAL with the
   rename): those owed ACKs are delayed, never wrong (receipts still answer duplicates).
9. The session store keeps clear what names no friend: session ids, codes, counters, the heads'
   `created_hour` and the inbox's insertion `seq` (and the tombstones' copy of it). So the files
   show when sessions began, to the hour, and in what order messages arrived across all friends;
   with equal keys for equal values, how many rows involve the same unknown friend (section 3).
   The record keys name no friend since schema 4: they are digests of public values and the
   `init_id`, which is keyed (review B-sealed-stores-1; before, a clear `init_id` let anyone with
   a candidate friend's public key confirm a session with that friend, its role and its hour).
   A store not yet moved to schema 4 (a pending journal, too little disk space) keeps the
   `init_id` clear until it moves.
10. A store moves at its first open in a sealed profile, by whichever process opens it: ash's
   upgrade interlock (R11) holds back only the eager pass, as for the PP.12 stores, and it tells
   only a build from before the pack apart (its Status has no `at_rest`). A raven-node of an
   older build that still runs (a PP.13 build included, once PP.14 moves its schema-2 store on,
   and the pack's builds before review B-sealed-stores-1, once their schema-3 store moves to 4)
   then cannot use the session store (fail closed) until it is restarted with this build.
11. Lock v1 stops Raven; it locks only a passphrase-vault profile. A keychain or DPAPI profile
   opens again for anyone logged in as the user (every lock text says so; Lock v2 is Phase 6).
   The lock binds this build's own starts: a login item Lock left on starts Raven at the next
   login (the lock is then stale until `raven unlock` or the app clears it), an older build's
   `ash` and a hand-started `raven-node` ignore it, and a service Raven didn't install for this
   profile cannot be stopped by it.
12. Erase removes what this computer's keystore and this folder hold for the profile. A copy of the
   folder made before (a backup, a snapshot, a copy elsewhere) stays sealed under a K_hist that no
   longer exists here, except on Windows, where K_hist's DPAPI-wrapped file is in the folder: a
   copy of the whole folder opens again for anyone who can use the user's Windows login. A
   per-session keychain or Secret Service item whose session head was never recorded (a crash
   between the two writes, which the store otherwise undoes) is found by its account's namespace,
   on macOS since review C-deletion-erase-1. A Raven process of an older
   build ignores the marker, and one of this build that was already inside a write when the marker
   went down finishes that write (the next pass deletes the file). A process still open after the
   erase finished can start a new, empty profile in the same place (it no longer holds any key of
   the old one).
13. Friend custody (PP.17, gated off in release): a released object leaves its keyed digest and
   its expiry hour until that hour has passed, so the store shows how many objects were released
   and roughly when they would have expired, never for whom; the deleted cells are overwritten in
   the file, not in freed disk blocks (section 6.7). The way back (`raven privacy unseal`) cannot
   name the released digests in clear and leaves them out: a replay of a released object within
   its remaining lifetime is then stored again, fetched again and answered by the recipient's
   receipts as a duplicate (`raven privacy rotate-meta`, PP.18, cannot key them again either and
   leaves them out the same way). The open rows still show the clear store tag (a day's tag per
   recipient) and the page token, which the fetch names on the wire.
14. `raven privacy rotate-meta` (PP.18) changes `k_index` and the epoch keys, not K_hist: an old
   copy of `meta_key.rmk` (a backup, a freed block) still opens with K_hist, so the command helps
   against someone who saw the unwrapped keys (a memory dump, a copied key payload), not against
   someone who holds both an old key file and K_hist; only erase does (limit 1). It stops this
   profile's node; a terminal app or command of the same profile still open meanwhile may write
   under the old keys, which the next run of the command keys again. A session head whose `meta`
   does not open (such a write under an epoch the command then dropped, a changed byte) is
   dropped by the command, and by `raven privacy unseal`, with its session's rows and its
   protected state, and counted (review B-sealed-stores-3: it stopped both for good, after
   rotate-meta had closed the profile); the prune passes remove such a head by its hour, and it
   holds up no other session meanwhile (review B-sealed-stores-2). `raven privacy unseal`
   writes the profile's records in plain: what was sealed before stays sealed in freed blocks
   under keys that go with `meta_key.rmk`, and what is written from then on is plain until `raven
   privacy seal-now` (limit 2 then applies to it).

## 11. The registry and the guards

What keeps a later change from writing a friend's data in clear without anyone noticing:

| Guard | Where | What fails it |
|---|---|---|
| The file registry | `at_rest::FILES` (`rc/at_rest/registry.rs`): every file and pattern a profile writes, with its rule (sealed kind, epoch keys, keyed SQLite, already protected, plain with a reason, relay folder, lab), its writer lock and whether erase deletes it | `every_profile_file_name_is_classified`: a file name in the production sources of raven-core, raven-node or ash (`.json`, `.sqlite`, `.sqlite3`, `.bin`, `.seed`, `.secret`, `.vault`, `.dpapi`, `.rmk`, `.rms`) that the registry does not cover |
| Who uses the registry | `migrate_all` and the rotation pass (what to seal), `erase::plan` (what to delete), `unseal_all` (what to write back), `raven privacy status` (sealed and plain files), carrier_matrix C87 (the lab backends' files) | - |
| The SQLite schema guard | `indexed_session_store::tests::sealed_store::no_clear_key_address_or_message_id_columns` | a column of any store (sessions, owed ACKs, the app store, custody, custody handoff, the security ledger) in a sealed profile whose name says address, device, peer, sender, recipient, depositor, custodian, message id, digest or nonce and that is not keyed, unless its list says why (R20's ids, the app store's open item) |
| Version by shape | each store's open (`sqlite_rebuild`, section 4.10) | an older process's `user_version` stamp never migrates a keyed table twice |
| No key load inside a lock or a transaction | `paths::HeldMark`; `every_store_transaction_is_marked` | a debug build's `keys_load` under a Raven lock or inside a store transaction (a keychain dialog would block it); a new store transaction without the mark |
| Formats | `formats_are_pinned`, `epoch_formats_are_pinned`, `epoch_row_format_is_pinned`; the harness's own stdlib reader (`--self-test`, `sealed_book`) | any change of RMS1, the row blob, RVNHIST2, RVNOSTG2 or the app row |
| Keychain calls | `scripts/keychain_guard_check.sh`, `macos_keychain::guarded` | a macOS keychain call outside the allow-list (erase's delete and its attribute-only search are on it) |
| Lab switches | `lan_gate::PRIVACY_LAB_SWITCHES`, the release `*_inert_without_debug_assertions` tests; the harness self-test's lab-switch scan | a switch read in a release build; a `RAVEN_LAB_*` name in the Rust tree that neither harness scrubs |
| Test profiles | `profile_dir_refusal` (fault matrix), `profile_dir` (carrier_matrix) | a profile folder outside the run's root, in `~/.raven`, or inside a Raven profile |
| A copied data dir | carrier_matrix C87, fault scenarios s120 and s125 | any file, SQLite page or WAL frame that names a friend, or a file name that does |

## 12. What the pack does not cover

The honest limits (section 10) describe what the sealing cannot do; these were left out of the
pack on purpose, each with its place:

- **Plain by design** (section 6.5): the settings (`node_policy.json` without its relays,
  `privacy.json`), the logs (counts and fixed codes; the legacy `raven-node run` prints received
  text to stderr), file names, sizes and times, the lock databases, the IPC socket, the contact
  request exports, the paired responses (60 s).
- **Outside the data dir**: Raven's own login item (it names the data dir, the listen addresses
  and the relays; erase removes it), shell history and terminal scrollback (the guide says so),
  backups and snapshots, the OS temp folder (SQLite temp files are kept in memory during the
  migrations only).
- **Gated stores not yet keyed**: the app store's outbox, pairing budget and message ids (section
  7.2, `APP_CHANNEL_PRODUCTION_ENABLED = false`), and the legacy bridge queues `queue.sqlite` and
  `forward_queue.sqlite` (`secure_delete` only, OD-PP-11).
- **Dedicated relay folders** (no identity, so no key root): plain.
- **Lock v2** (a running node that drops its keys, auto-lock on sleep, a Raven passphrase on macOS
  and Windows): Phase 6 (P6.40). Lock v1 stops Raven (section 4.13).
- **The terminal app's files and rows** (`tui_private.rms`, the settings rows, the overlays):
  PP.21-PP.24, after this step (PP.21: section 4.18; PP.22: section 4.19; PP.23: section 4.20;
  PP.24: section 4.21).
- **Real keystores, real login items and real backups**: unit tests and harnesses use the lab
  backends and fake tools; the owner checks them in R34.
