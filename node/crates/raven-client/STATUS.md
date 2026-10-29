# raven-client status

Contract: `desktop/api/API.md` (v1). Every op below is implemented with the CLI's own code; the
words "done", "partial" and "not done" say how much of the contract it meets, and the last section
says what has not been verified.

## Where this stands

All three priority groups are in: (1) crate, C ABI, envelope, `app.info`, `profile.state`,
`identity.*`, `card.*`, `contacts.*`, `settings.*`; (2) security words in raven-core and
`verify.*`; (3) `messages.*`, `node.*`, `events.poll`. Nothing is committed (the lead commits).

Gates, 2026-10-24 (after the merge of `86cd5cd` and the network ops), from `node/` with the
keychain-safe environment: `cargo test -p raven-client` 61 passed (40 unit, 3 contacts_words, 1
delivery, 4 ffi, 3 network, 1 each net_internet, net_p2p, net_custody, net_nearby, 5 privacy);
`cargo test --release -p raven-client --lib network::` with every lab switch set, 6 passed;
`cargo test -p ash` 2954 passed, 0 failed; `cargo clippy -p raven-client -p raven-core -p
raven-node -p raven-swarm -p ash --all-targets` and `-p ash --features engine --all-targets`
(`-D warnings`) and `cargo fmt --all --check` clean; the Linux core 76 and its engine tests 9;
the macOS app 79 without the engine and 83 with the dev engine. Earlier gates (2026-10-22, after
the review of the merge of `feature/reliability-and-mesh`): `cargo build -p raven-client`, `cargo test -p
raven-client` (47 passed: 34 unit, 4 ffi, 3 contacts_words, 1 delivery, 5 privacy; the same
with `RAVEN_LAB_AT_REST=1` in the environment), `cargo test -p raven-core` (1709 passed, 6
ignored), `cargo test -p ash` (2619 passed, 1 ignored: both binaries' unit tests with the
terminal app's, and the CLI's integration suites), `cargo clippy -p raven-client -p raven-core -p
ash --all-targets`, `-p raven-core -p ash --all-targets` and `-p ash --features engine
--all-targets` (all `-D warnings`), `cargo fmt --all --check`, default `cargo build`: all green.
The macOS app's tests on the real engine (`RAVEN_ENGINE=dev swift test`, 81) link
`libraven_client.a`; the Linux app's engine tests (8) run on it too.

## Operations

| op | status | notes |
|---|---|---|
| `app.info` | done | extra `api: 1` |
| `profile.state` | done | opens the profile as the CLI does before every command (below); `new` / `ready` / `locked` (`raven lock`, PP.15) / `unreadable` (+`reason`, `detail`): an unfinished erase or key change (raven-core's sentence, which names the command that finishes it), an identity that can't be read, or a sealed profile whose at-rest key the keystore did not give (asked again now) |
| `identity.create` | done | raven-core `load_or_create_identity` + `ensure_local_prekey` (a prekey failure is an extra `note`, as the CLI's `init` treats it); never over an unreadable store; returns the existing identity if one appeared |
| `identity.me` | done | words (raven-core `security_words`), old code, card (as `raven whoami --card`), invite |
| `card.make` | done | `include_address` uses where raven-node listens (all interfaces → this computer's IPv4); never a loopback address; extra `address_missing` (`not_receiving`, `this_computer_only`, `no_network`) when none can be given |
| `card.parse` | done | the terminal app's paste rules; never the friend's words or code; extras `address`, `already_saved`, `already_verified`; routes only for what the card holds |
| `contacts.list` | done | presence from addresses, waiting messages and this session's touches (15 min); extra `blocked`; `unread` from the read markers the terminal app shares (below) |
| `contacts.add` | done | CLI `add_contact_with_routes`, saved not verified (an existing pin is kept by the CLI); NAME_CLASH also for a name that only looks like a verified friend's |
| `contacts.rename` | done | pin and routes kept |
| `contacts.remove` | done | CLI `contact remove --yes` (also forgets the pinned prekey, as the CLI) |
| `contacts.set_address` | done | CLI `contact set-dial`; Persian, Arabic-Indic and full-width digits folded |
| `verify.check_words` | done | blind: `match` pins through the CLI's save path (the key's own code passed as `verify_fp` once the words matched), `typo` (check word, unknown word, other alphabet; extras `reason`, `position`), `mismatch` (extra `mismatches` count); empty, fewer or more than 10, or a too-short prefix → WORDS_INCOMPLETE; `words` may also be one string |
| `verify.check_old_code` | done | the CLI's one comparator (`security_check`, RAVEN_SECURITY_WORDS_V1.md section 8): 4 or more tokens are words and get `verify.check_words`'s answer; otherwise the CLI's `fingerprint_matches` (separators ignored, case not, only Persian and Arabic-Indic digits folded); pins through the CLI; extras `case_only`, `mismatches` |
| `verify.word_hint` | done | from Raven's list only, after 3 letters (plurals too); extra `known` |
| `messages.history` | done | history rows (both directions) plus this session's sends without a row; `before`, `limit` (default 100, max 1000) |
| `messages.send` | done | returns at once with `sending`; a worker sends one at a time with the CLI's send to a saved friend (no address from `RAVEN_PEER`), starting raven-node first if needed |
| `messages.retry` | done | waiting → `raven outbox retry` (or a retry kick for the friend while raven-node has not listed it yet); never-written → sent again under the same id; ended → a new message (extras `replaces`, `may_arrive_twice`); delivered/sent/sending → unchanged (extra `changed`) |
| `messages.stop` | done | waiting or sent → `raven outbox cancel --yes` (extra `may_have_arrived`); a send still queued in the worker is dropped |
| `messages.details` | done | status/why/what-to-do in the terminal app's words (desktop places instead of keys); `detail` with ids, history, outbox, the CLI's outcome text |
| `messages.mark_read` | done | the terminal app's read marker for the friend (ash `tui/read_marks.rs`: tui_state.json's `last_read` + `last_read_at`, tui_private.rms in a sealed profile) moved to the newest history row up to `id` (default the newest), under the markers' lock, never back; `unread` afterwards; a marker that can't be saved counts for this run (extra `note`) |
| `node.status` | done | the CLI's `classify_node_reach` (a listener bound to an address no longer on this computer does not receive); extras `state` (`listening`, `local_only`, `send_only`, `not_running`, `not_answering`, `starting`), `not_receiving` (`addr_not_here`, `port_in_use`, `lan_off`) and `lab` (carriers on only through a developer build's lab switch) |
| `node.start` | done | the CLI's start (ext.rs) with the program `RAVEN_NODE_BIN`, else next to the app, else the CLI's lookup; listens on the network while `receive` is on, else 127.0.0.1 (free port); `started_by_app` only for the process this engine spawned; refused before the identity exists; Linux vault without a passphrase file → NODE_NOT_RUNNING; `raven lock` → PROFILE_LOCKED; afterwards the at-rest key is loaded if the node sealed the profile |
| `node.stop` | done | the terminal app's stop rules; extras `stop` (`stopped`, `still_running`, `advice`, `managed`, `not_running`, `failed`) and `note` |
| `settings.get` / `settings.set` | done | written once the identity exists, memory before; checked partial updates. `receive`, `reduced_motion`, `when_quit`, `lock_on_sleep`: `desktop_settings.json` (plain, atomic, 0600; registered in raven-core's at-rest registry). `display_name`: `desktop_private.rms` (at-rest kind `DesktopPrivate`: sealed in a sealed profile, plain JSON before; an older engine's name is moved out of `desktop_settings.json`). `keep_chats_days`: the privacy pack's `chat_keep` (`privacy.json`, what `raven chats keep` sets), enforced by its retention pass. `forget_addresses`: always true (PP.7 always forgets); `false` → NOT_AVAILABLE_YET. `lock_on_sleep`: stored and reported, takes effect when the apps offer Lock |
| `events.poll` | done | never blocks; bounded (512) queue with increasing `seq`; `status_ok` heartbeats replace each other; extra `reset` |
| `privacy.state` | done | `encrypted`: raven-core `privacy::mode` is sealed; `locked`: `privacy::lock_state` (`raven lock`); `available: false` until the apps offer the pack's actions |
| `privacy.unlock` | done | clears the lock as `raven unlock` first does and as the terminal app's UNLOCK does (Raven's login item never touched); answers as `profile.state` |
| `privacy.lock` / `encrypt` / `erase` | done | NOT_AVAILABLE_YET naming the CLI command (`raven lock`, `raven privacy seal-now`, `raven erase`), nothing changed |
| `network.status` | done | every way (13) and protection (6) with state, reason, gate, lab switches, setting and whether the running node uses it; listening, port, port mapping, relays, proxy, nearby, carry both ways, bridge/store/relay with honest effects, hide IP, lab switches seen, consent texts (src/network.rs) |
| `network.set` | done | the CLI's commands (`lan_switch`/`lan_open_for`, `cmd_node_internet`, `cmd_node_p2p_with`, `cmd_node_upnp`, `node_proxy_set`, `cmd_nearby`, `custody_on_with`, `custody_use_with`, `handoff_switch`, `relay_offer_with`, `update_policy` for bridge/store/relay with AUTO off, `cmd_node_hide_ip`); checked first: NOT_AVAILABLE_YET for a held way, CONSENT_NEEDED without `agreed`; `applies` now/restart |
| `network.check` | done | `doctor_summary` rows and `doctor_network_lines` (cli.rs, the doctor prints the same), `receiving`, `policy`; `router: true` runs `router_probe` |
| `contacts.routes` / `contacts.set_routes` | done | saved routes, learned routes (counts, PeerId), hide IP, mail friends told/listed, offline delivery class (custody_cli `contact_carriers`); `cmd_contact_set_routes`, `set_custodians_lines` (addresses mapped to the CLI's names), `cmd_contact_hide_ip` |
| `security.status` | done | security_cli `app_read` (no write), the node's counts |
| `lock.state` / `lock.now` / `lock.unlock` | done | lock_cli `node_lock_v2`, `lock_once`, `unlock_once`; NOT_AVAILABLE_YET where the node does not serve Lock v2; PASSPHRASE_WRONG, PASSPHRASE_NEEDED, UNLOCK_WAIT |
| `updates.status` | done | update_install `view(dir, false)`; install stays CLI-only |
| `groups.list` / `groups.get` | done (lab) | raven-core `group::list` / `group::view` after `group::run_pending` (the copies' delivery read in); `available: false` and no store read while the gate is closed (release) |
| `groups.create` / `groups.add` / `groups.remove` / `groups.leave` | done (lab) | raven-core `group::create`, `add_members`, `remove_members`, `leave` (what `raven group` runs); members by friend address (NOT_A_CONTACT, CONTACT_BLOCKED otherwise); then the outbox kick, raven-node started first as a send starts it |
| `groups.history` / `groups.send` / `groups.mark_read` | done (lab) | `group::history` (`before` is a message id), `group::send` (8,192 bytes at most; extra `note` when raven-node could not be asked), `group::mark_read`; events `group_message` and `group_changed` from the watcher's look at groups.json (first look only notes) |

Opening the profile (profile.rs, the engine bridge's `open_profile`): what cli.rs's `run` does
before every command, for an engine that keeps the profile open. Before every operation but
`app.info`, `profile.state`, `events.poll`, `privacy.state`, `privacy.unlock` and
`verify.word_hint`: an unfinished erase (PP.16) or `raven privacy rotate-meta` (PP.18) refuses
it with PROFILE_UNREADABLE and raven-core's sentence, and nothing is written. Once per engine:
the folder made owner-only, the at-rest key loaded and what is still plain sealed (a release
build, or `RAVEN_LAB_AT_REST=1` in a debug build; PP.4), the privacy pack's prune while no
raven-node runs (PP.7, PP.9, PP.10, PP.12), `raven lan off` read. A sealed profile whose key this
process lacks (raven-node sealed it after the app opened it) gets the key loaded again: at the
next operation, at most once a minute after a failed load, and at once on `profile.state` and
after raven-node starts. Without the key the friends list, history and settings fail with
KEYCHAIN_DENIED (raven-core's key text as `detail`). The one-time notices are not shown; they
stay due for the next CLI command.

Events: `status_ok` (each successful Status), `node` (on a change), `send_started`, `state`
(on a change; also `until_ms`), `receipt` (only when the history row became `delivered`/`read`,
which raven-core writes only after verifying the friend's signed receipt, or the send itself
returned after one; always before `state: delivered`; `path`, `ms`), `retry` (attempts grew),
`incoming`, `presence`, `unread` (a friend's count changed: a message came, or the chat was read in
an app). The watcher starts with the first `events.poll`, checks raven-node over IPC about once a
second (history, contacts and the read markers re-read only when their files change) and stops after
30 s without a poll. Its first look only notes what is there.

## Contract additions (extra fields)

- `events.poll`: `reset: true` when events after `after_seq` were dropped from the buffer, or
  `after_seq` is from before this engine started: reload instead of trusting the events.
- `Contact`: `blocked`. `waiting.until_ms` is 0 when not known (raven-node not running).
- `Message` ids: a message sent in this session is `pending-N` from the start and keeps that id
  after its history row appears; history rows otherwise use the message id.
- `NodeStatus`: `state`, `not_receiving`, `lab` (every way a lab switch opened), `lab_switches`,
  `carriers.nearby`; `node.stop`: `stop`, `note`.
- `Message` and `receipt`: `path_kind` (API.md lists every kind); a delivery raven-node's outbox
  made is labelled from its last path to the friend (one fresh Status, once, when it turned
  delivered after the message was written); friends carrying it (`friend`, `handoff`, `letter`,
  from the outbox and the letter book) is kept from when it was seen.
- `card.make`: `address_missing`. `card.parse`: `address`, `already_saved`, `already_verified`.
- `verify.check_words`: `contact` (on match), `reason`, `position`, `mismatches`.
  `verify.check_old_code`: `contact`, `case_only`, `mismatches`. `verify.word_hint`: `known`.
- `messages.retry` / `messages.stop`: `changed`, `replaces`, `may_arrive_twice`,
  `may_have_arrived`. `identity.create`: `note`. `profile.state`: `detail`. `app.info`: `api`.
- Environment: `RAVEN_NODE_BIN` (where the app finds raven-node).

## Deviations from API.md

- `Message.state` of an incoming message is `delivered`.
- `messages.retry` of a message that ended returns a new message (new id) rather than the old one.
- `verify.check_words` maps an unknown word or a word in another alphabet to `typo` (with its
  position), and fewer/more than 10 words or a too-short prefix to WORDS_INCOMPLETE.
- `NOT_SENT_MEET_FIRST` and `TIME_RAN_OUT` are message states only; no op returns them as errors.
- CONTACT_BLOCKED has no unblock op to point to; its message names `raven contact unblock`.

## Changes outside the crate

- `crates/raven-core/src/security_words.rs` + `security_words_v1.txt`: since the merge of
  `feature/reliability-and-mesh` (2026-10-22) the team's SW.1-SW.8 module and its list (a byte
  copy of `protocol/reference/raven_protocol/security_words_v1.txt`, vectors in
  `shared-vectors/rvn1/security_words/`). The engine's only additions to it: `MIN_PREFIX` and
  `fold_digit` public, `ParseError::position()`, and a test that runs the prototype's vectors
  too.
- `crates/ash`: a library target `ash_engine` (`src/lib.rs`, `test = false`), empty unless the new
  `engine` feature is on; then it compiles cli.rs once more and exposes only
  `src/engine_bridge.rs` (a child module of cli.rs, like the terminal app's tui/bridge.rs). The
  binaries are unchanged. cli.rs: the gated `mod engine_bridge;` and a `STDOUT_QUIET` flag
  `print_stdout` honours (set only by the engine). ext.rs: `Cause` / `classify_cause` made
  `pub(super)` (the terminal app branch makes the same change) and `ensure_mac_lan_daemon`'s body
  moved into `ensure_daemon_in` (program, listen address and start record as parameters), which
  `ensure_mac_lan_daemon` calls with the old values. Since the merge it also refuses a start while
  `raven lock` holds the profile or an erase did not finish (the engine explains both), and the
  engine bridge follows the CLI's newer send plan (LAN beacon finds, learned routes standing in for
  a missing LAN address, unrecorded routes), card (PeerId rotation, `p2pn=`) and causes
  (`NameNotFound`, `PinStoreUnreadable`, `LanOff`).
- Since the review of that merge: raven-core's at-rest registry (`at_rest/registry.rs`) lists
  `desktop_settings.json` (plain, with its reason) and `desktop_private.rms` (sealed, the new kind
  `DesktopPrivate = 128`, the desktop apps' own lane; approved by the owner on 2026-10-23), and its file-name guard scans raven-client
  too; `security_words::compare` passes its result through `std::hint::black_box` again (as the
  engine's own module did); the prototype-vector test checks the case counts. The engine bridge
  gained `open_profile`, `closed`, `load_at_rest`, `at_rest_key_missing` (cli.rs `run`'s
  preamble and refusals) and `node_reach` (cli.rs `classify_node_reach`), and its send reads
  `raven lan off` again before planning.
- No new third-party crate, no version change (Cargo.lock only gains `raven-client`).
- Since the merge of `86cd5cd` (2026-10-24): the bridge plans Bluetooth nearby as cli.rs does and
  reports `Carrier::Nearby`; `identity.create` uses `load_or_create_profile_identity` and
  `node.start` listens where `default_service_lan_listen_for` says (the random listen port, P6.36);
  cli.rs's doctor builds its summary rows (`doctor_summary`) and network lines
  (`doctor_network_lines`) as data and prints them unchanged; custody_cli gains
  `contact_carriers` and makes `gather_facts` `pub(super)`; engine_bridge.rs gains the network
  section (thin wrappers and views over the CLI's commands, no question asked, nothing printed).

## Tests

All with `RAVEN_*_BACKEND=locked-file`, `RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1`, throwaway profiles, and
listening on 127.0.0.1 with free ports only.

- raven-core `security_words` (the team's tests plus three): the shared vectors and, read from
  the folder so none is skipped, every file in
  `docs/roadmap/research/prototypes/security-words/vectors` (its list differs from the protocol
  copy only in `#` lines, so its own hash is pinned and its rows must match), the list hash and
  byte copy, list rules, exhaustive check-word guarantees on 64 codes, every word in every typed
  form, `ParseError::position` and `fold_digit`.
- raven-client unit tests: envelope, safety, events, settings, explanations, contacts (pastes,
  names, codes hidden), messages (states, binding, deadlines), node (reach, stop rules).
- `tests/ffi.rs`: the C ABI (NULL, non-UTF-8, bad JSON, unknown op → BAD_REQUEST; never NULL;
  `raven_free(NULL)`), a new profile, privacy state and ops, 8 threads at once.
- `tests/contacts_words.rs`: two profiles; setup settings kept in memory until the identity;
  cards; add (NAME_CLASH, empty name); rename; set_address with Persian digits; words
  incomplete/typo/unknown/mismatch/match typed as people type; the pin in contacts.json; old code
  case-only mismatch and match; words typed into the old-code box checked as words, full-width
  digits not folded, Persian digits folded; settings where each belongs (chat-keeping time in
  privacy.json, the name in its own file, `forget_addresses` refused off); nothing returned holds
  the friend's words or old code.
- `tests/delivery.rs` (the flow in `tests/common/flow.rs`): two real raven-node processes started
  and stopped by the engine; A→B delivered with `receipt` before `state: delivered`, path `LAN
  direct`, friend `in_touch`; B gets `incoming`; with B stopped a send waits, never delivered and
  no receipt; `messages.stop` cancels.
- `tests/privacy.rs` (sets `RAVEN_LAB_AT_REST=1` for itself and its raven-node processes; the
  other binaries strip every privacy lab switch): sealed profiles read and written by the engine
  (friends, history, settings), also after the key left the process and in a new engine; an older
  engine's name moved out of the plain settings; an unfinished erase and an unfinished key change
  close the profile and nothing is written; `raven lock` reads as locked, node.start is
  PROFILE_LOCKED, `privacy.unlock` clears it; the delivery flow on sealed profiles.

- Network (`tests/network.rs`, `net_internet.rs`, `net_p2p.rs`, `net_custody.rs`,
  `net_nearby.rs`, each its own process with its own lab switches; real engines, nodes and the
  `raven` CLI on 127.0.0.1): LAN direct with path_kind `lan`, the network views and
  `network.check`; bridge/store/relay reach the policy `raven doctor` prints, LAN off/on, hide IP;
  every held way `preview` and refused with nothing changed; Internet direct over loopback (the
  node inherits `RAVEN_LAB_TEST_A` and opens the listener; NodeStatus lists the switch); p2p
  relayed through a local `raven-node relay` (C6's way: relay-only listen, cards allowed on the
  relay, path `p2p_relayed`); friend custody (CONSENT_NEEDED, then the recipient offline, a third
  friend holds it, path `friend`, the sender offline, the recipient fetches it); Bluetooth nearby on
  `raven-node nearby-ether` (path `nearby`). Unit test `every_lab_switch_is_inert_in_a_release_build`
  (run with `--release` and every switch set).

## Not verified (honestly)

- Network: real Bluetooth radios (CoreBluetooth through the RavenNearby helper, BlueZ, WinRT),
  real routers (port mapping, `network.check {router: true}` against hardware), WebSocket relays
  and the web proxy, letters and handoff end to end through the engine, Lock v2 and the security
  notices with their gates open, two machines on different networks. A release engine is checked
  at the function level only (a release engine on macOS would reach the Keychain).

- The real macOS Keychain, Windows DPAPI and the Linux Secret Service / passphrase vault: every
  test uses the file-backed stores. In an app, reading the identity and the history may show OS
  keychain prompts for the app's own binary.
- Windows and Linux: built and tested on macOS only (the Windows DLL, `taskkill`, the scheduled
  task check and named-pipe IPC are untested; the Linux path dependency is untested).
- The apps themselves: all three now call the engine (desktop/README.md), but setup, adding a
  friend and messaging through their windows on the real engine have not been tried yet.
- Known issues found while wiring the apps: `identity.create` on an existing identity reads and
  writes the settings separately, so a `settings.set` at the same moment can be lost; on Windows the
  raven-node pipe is per user, not per profile, so an engine on another `RAVEN_DATA_DIR` reaches the
  user's default node (tests use the debug-only `RAVEN_LAB_IPC_PIPE_SUFFIX`); the Rust DLL and
  raven-node.exe need the MSVC runtime, which the Windows installer must provide.
- Internet direct, p2p and friend custody in a release build: held, refused as the CLI refuses
  them (their lab paths are tested above).
- `node.start` with `receive` on (0.0.0.0:7420) was not run: tests never bind that port.
- Login-service detection (launchd, systemd, scheduled task) and the `still_running` / `advice`
  stop outcomes.
- Background deliveries noticed by the watcher (a `receipt` for a message raven-node delivered
  later) are covered by the same code path as the test's, but no test restarts B to see one.
- A panic inside the engine becoming `INTERNAL` is guarded (`catch_unwind` in `call`, `raven_call`
  and the worker threads) but not provoked by a test.
- Two vector inputs in `parse_001.json` were altered by the repository's English-only cleanup (the
  Persian position number 10 and a non-Latin word became an English placeholder); the reference
  Python fails them too. The Rust test puts the removed text back as `\u` escapes before checking
  (only while the placeholder is present).
- Times are relative ("about 22 hours from now"): no time zone database (as the terminal app).
