//! Every file a Raven profile writes, with its at-rest rule, its writer lock
//! and whether `raven erase` (PP.16) deletes it: the PP.1 inventory
//! (docs/design/2026-10-at-rest-metadata.md section 6) as code.
//!
//! The guard test `every_profile_file_name_is_classified` scans the sources
//! of raven-core, raven-node, ash and raven-client for file names (string
//! literals ending in `.json`, `.sqlite`, `.sqlite3`, `.bin`, `.seed`,
//! `.secret`, `.vault`, `.dpapi`, `.rmk` or `.rms`, test code excluded) and
//! fails for any name this table does not cover: a new file is sealed, keyed
//! or explained on arrival.

use super::Kind;

/// What the privacy pack does with a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// RMS1 under this kind once the profile is sealed (PP.4-PP.6, PP.24);
    /// today's bytes before.
    Sealed(Kind),
    /// Under the epoch data keys (PP.10): chat history and the outbound stage.
    EpochSealed,
    /// A SQLite store with keyed lookup columns and sealed meta blobs
    /// (PP.12-PP.14, PP.17).
    KeyedSqlite,
    /// Protected by the keystore or K_hist already; unchanged by the pack.
    AlreadyProtected,
    /// Plain by design, for this reason.
    Plain(&'static str),
    /// A dedicated relay folder's own file: no identity there, so no key root
    /// to seal under.
    RelayDirPlain,
    /// Lab or experimental builds only, for this reason.
    Lab(&'static str),
}

/// One registered file or pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRule {
    /// The path below the data dir (`/`-separated), or a pattern in which `*`
    /// stands for any run of characters other than `/`.
    pub name: &'static str,
    pub rule: Rule,
    /// The writer lock (a `DataDirLock` file in the data dir) every writer of
    /// a sealed file takes: the file's existing lock, or
    /// `.at_rest.<kind name>.lock.sqlite` where it had none.
    pub lock: Option<&'static str>,
    /// `raven erase` (PP.16) deletes it.
    pub erase: bool,
}

const fn sealed(name: &'static str, kind: Kind, lock: &'static str) -> FileRule {
    FileRule {
        name,
        rule: Rule::Sealed(kind),
        lock: Some(lock),
        erase: true,
    }
}

const fn rule(name: &'static str, rule: Rule) -> FileRule {
    FileRule {
        name,
        rule,
        lock: None,
        erase: true,
    }
}

const fn locked(name: &'static str, rule: Rule, lock: &'static str) -> FileRule {
    FileRule {
        name,
        rule,
        lock: Some(lock),
        erase: true,
    }
}

const fn plain(name: &'static str, reason: &'static str) -> FileRule {
    rule(name, Rule::Plain(reason))
}

const fn lab(name: &'static str, reason: &'static str) -> FileRule {
    rule(name, Rule::Lab(reason))
}

const PEER_CACHE_LOCK: &str = ".lan_peer_cache.lock.sqlite";
const REVOCATIONS_LOCK: &str = ".at_rest.revocations.lock.sqlite";
const BOOTSTRAP_LOCK: &str = ".at_rest.bootstrap.lock.sqlite";
const NOISE_PINS_LOCK: &str = ".lan_noise_pins.lock.sqlite";
const LEGACY_BRIDGE: &str =
    "legacy bridge store (gated): secure_delete only, sealing listed for later (OD-PP-11)";
const SQLITE_SIDECAR: &str = "SQLite sidecar: part of the database it is named after";
const ADVISORY_EXPORT: &str =
    "an export the user hands over: ciphertext or the request as it travels";

/// The registry. Exact names are matched before patterns, patterns in order.
pub const FILES: &[FileRule] = &[
    // ── The Tor onion carrier (lab, RAVEN_ONION_CARRIER_V1) ──
    plain(
        crate::onion::SELF_FILE,
        "this node's own onion binding: public (every card and route hint carries it), names \
         no friend; read by `raven whoami --card` without a running node",
    ),
    lab(
        "tor/*",
        "the Tor helper's state (Arti, lab only): its onion service key, guards and directory \
         cache, kept by Arti with owner-only permissions",
    ),
    lab("tor/*/*", "the Tor helper's state (Arti, lab only)"),
    lab("tor/*/*/*", "the Tor helper's state (Arti, lab only)"),
    lab("tor/*/*/*/*", "the Tor helper's state (Arti, lab only)"),
    lab("tor/*/*/*/*/*", "the Tor helper's state (Arti, lab only)"),
    // ── Sealed JSON and secrets (RMS1) ──
    sealed("contacts.json", Kind::Contacts, ".contacts.lock.sqlite"),
    sealed(
        "lan_seen.json",
        Kind::LanSeen,
        crate::lan_seen::LAN_SEEN_LOCK,
    ),
    sealed(
        "learned_routes.json",
        Kind::LearnedRoutes,
        ".learned_routes.lock.sqlite",
    ),
    sealed(
        "outbox_routes.json",
        Kind::OutboxRoutes,
        ".outbox_routes.lock.sqlite",
    ),
    sealed(
        "peer_device_certs.json",
        Kind::PeerDeviceCerts,
        PEER_CACHE_LOCK,
    ),
    sealed("prekey_store.json", Kind::PrekeyStore, PEER_CACHE_LOCK),
    sealed(
        "peer_cache.stage.json",
        Kind::PeerCacheStage,
        PEER_CACHE_LOCK,
    ),
    sealed(
        "blocked_pubs.json",
        Kind::BlockedPubs,
        ".at_rest.blocked_pubs.lock.sqlite",
    ),
    sealed(
        "device_registry.json",
        Kind::DeviceRegistry,
        ".device_registry.lock.sqlite",
    ),
    sealed("revocations.json", Kind::Revocations, REVOCATIONS_LOCK),
    sealed(
        "device_revocations_rvdr1.json",
        Kind::DeviceRevocationsRvdr1,
        REVOCATIONS_LOCK,
    ),
    sealed(
        "device_sync_seen.json",
        Kind::DeviceSyncSeen,
        ".device_sync_seen.lock.sqlite",
    ),
    sealed(
        crate::chat_history::CHAT_INBOX_CURSORS_FILE,
        Kind::ChatInboxCursors,
        crate::chat_history::CHAT_INBOX_CURSORS_LOCK,
    ),
    sealed(
        "tui_private.rms",
        Kind::TuiPrivate,
        ".at_rest.tui_private.lock.sqlite",
    ),
    // The desktop apps' copy of the user's own name (raven-client), as
    // tui_private.rms is the terminal app's: RMS1 in a sealed profile, plain
    // JSON before (the engine seals it in place once the profile is sealed).
    sealed(
        "desktop_private.rms",
        Kind::DesktopPrivate,
        ".at_rest.desktop_private.lock.sqlite",
    ),
    // Groups (docs/design/2026-10-groups.md §6): rosters with member keys,
    // group messages, held frames and intents. RMS1 in a sealed profile.
    sealed(
        crate::group::store::GROUPS_FILE,
        Kind::Groups,
        crate::group::store::GROUPS_LOCK,
    ),
    sealed(
        "route_memory.json",
        Kind::RouteMemory,
        ".route_memory.lock.sqlite",
    ),
    // A new name (review R07): an older build rewrites an unreadable
    // lan_noise_pins.json with fresh trust-on-first-use pins.
    sealed("lan_noise_pins.rms", Kind::NoisePins, NOISE_PINS_LOCK),
    // Holds the node's own LAN listener address (`lan`) and an unkeyed
    // SHA-256 `global` digest (cutoff re-verify): sealed since PP.5.
    sealed(
        "route_hints_state.json",
        Kind::RouteHintsState,
        ".at_rest.route_hints_state.lock.sqlite",
    ),
    // node_policy.json's fields that name other machines, in a sealed
    // profile (PP.6); every writer of either policy file takes its lock.
    sealed(
        crate::node_policy::POLICY_PEERS_FILE,
        Kind::NodePolicyPeers,
        ".at_rest.node_policy_peers.lock.sqlite",
    ),
    // Plain until the profile has an identity (first-install inert), then
    // sealed with the rest.
    sealed("bootstrap.json", Kind::Bootstrap, BOOTSTRAP_LOCK),
    // Sealed in a profile; a dedicated relay folder has no identity, is
    // never sealed and keeps it plain.
    sealed(
        "relay_allow.json",
        Kind::RelayAllow,
        crate::relay_allow::RELAY_ALLOW_LOCK,
    ),
    // Its one writer (`device_cert::load_or_create_device_x25519`) runs under
    // the device registry's lock: the same lock serialises its migration.
    sealed(
        "device_x25519.secret",
        Kind::DeviceXSecret,
        crate::device_cert::DEVICE_REGISTRY_LOCK,
    ),
    sealed(
        crate::alias_record::ALIAS_CLAIMS_FILE,
        Kind::AliasClaims,
        ".at_rest.alias_claims.lock.sqlite",
    ),
    sealed(
        crate::nearby::NEARBY_REGISTRY_FILE,
        Kind::NearbyRegistry,
        ".at_rest.nearby_registry.lock.sqlite",
    ),
    sealed(
        "contact_inbox/*.wire",
        Kind::ContactInbox,
        ".at_rest.contact_inbox.lock.sqlite",
    ),
    sealed(
        crate::relay_select::RELAY_MEMORY_FILE,
        Kind::RelayMemory,
        ".at_rest.relay_memory.lock.sqlite",
    ),
    sealed(
        "friend_relay/relay_status.json",
        Kind::FriendRelayStatus,
        ".at_rest.friend_relay_status.lock.sqlite",
    ),
    sealed(
        "friend_relay/relay_key.ed25519",
        Kind::FriendRelayKey,
        ".at_rest.friend_relay_key.lock.sqlite",
    ),
    // The meeting time (Phase 3 P3.C2): when a meeting's LAN window ends.
    sealed(
        crate::lan_meeting::LAN_MEETING_FILE,
        Kind::LanMeeting,
        crate::lan_meeting::LAN_MEETING_LOCK,
    ),
    // The home custodians (Phase 3 P3.18): written by raven-node under the
    // learned routes' lock, like the offers it is chosen from.
    sealed(
        crate::custody_home::CUSTODY_HOME_FILE,
        Kind::CustodyHome,
        ".learned_routes.lock.sqlite",
    ),
    // Contacts' PeerId rotation schedules (Phase 4 P4.25).
    sealed(
        crate::peer_rotation::PEER_SCHEDULES_FILE,
        Kind::PeerSchedules,
        crate::peer_rotation::PEER_SCHEDULES_LOCK,
    ),
    // Since when this profile announces its own coming PeerIds (P4.28).
    sealed(
        crate::peer_rotation::ROTATION_STATE_FILE,
        Kind::PeerRotationState,
        crate::peer_rotation::ROTATION_STATE_LOCK,
    ),
    // This device's own published prekey bundles (Phase 5 P5.11), kept for
    // letters sealed to a retired generation: written with the prekey store
    // under the peer cache's lock.
    sealed(
        crate::lan_dispatch::PREKEY_PUBLISHED_LOCAL_FILE,
        Kind::PrekeyPublishedLocal,
        PEER_CACHE_LOCK,
    ),
    // The letters this node left with friends (Phase 5 P5.15): raven-node
    // only, under its own lock.
    sealed(
        crate::letter_deposits::LETTER_DEPOSITS_FILE,
        Kind::LetterDeposits,
        crate::letter_deposits::LETTER_DEPOSITS_LOCK,
    ),
    // The learning model (Phase 6a P6.9): written by raven-node, and by
    // `raven learning reset|off --forget` (P6.17) while no raven-node that
    // learns answers; sealed from its first write (never in clear: a profile
    // that is not sealed keeps it in memory), so migrate_all has nothing to
    // move and `raven privacy unseal` deletes it.
    sealed(
        crate::learning::store::LEARNING_FILE,
        Kind::LearningStore,
        crate::learning::store::LEARNING_LOCK,
    ),
    // Each contact's capability high-water mark (Phase 6b P6.29): written
    // by raven-node (link features) and ash (lowered after a words match,
    // forgotten with the contact), under its own lock.
    sealed(
        crate::capability_floor::CAPABILITY_FLOOR_FILE,
        Kind::CapabilityFloor,
        crate::capability_floor::CAPABILITY_FLOOR_LOCK,
    ),
    // Each contact's rotating pair seeds (Phase 6b P6.38): written by
    // raven-node (route hints) and ash (forgotten with the contact), under
    // its own lock; registered from its first version.
    sealed(
        crate::pair_seed::PAIR_SEEDS_FILE,
        Kind::PairSeeds,
        crate::pair_seed::PAIR_SEEDS_LOCK,
    ),
    // The RLK1 link knock's matched nonces (Phase 6 review traffic-9):
    // written by raven-node only, while the knock is live, under its own
    // lock; a knock recorded before a restart stays a replay after it.
    sealed(
        crate::link_knock::KNOCK_REPLAYS_FILE,
        Kind::KnockReplays,
        crate::link_knock::KNOCK_REPLAYS_LOCK,
    ),
    // The update state (Phase 6b P6.44): the release key set, the newest
    // advisory, the log and the freeze evidence, under its own lock; written
    // only while the advisory gate is live.
    sealed(
        crate::update_state::UPDATE_STATE_FILE,
        Kind::UpdateState,
        crate::update_state::UPDATE_STATE_LOCK,
    ),
    // The verified releases waiting to be installed (Phase 6b P6.47):
    // `updates/staged/<build serial>/`, staged by the CLI or the terminal
    // app only (never raven-node), one folder per build.
    plain(
        "updates/staged/*/*",
        "a verified Raven release waiting to be installed (P6.47): the Raven project's signed \
         manifest, log snapshot and advisory and the release's files, as published (owner only, \
         never executable); nothing about a contact or a person; at most 2 builds",
    ),
    // The releases friends offered and the download approvals (Phase 6b
    // P6.49): written by raven-node (offers, progress) and ash (approvals,
    // staging) under their own lock, only while the mesh-update gate is live.
    sealed(
        crate::update_downloads::DOWNLOADS_FILE,
        Kind::UpdateDownloads,
        crate::update_downloads::DOWNLOADS_LOCK,
    ),
    // Downloads from friends (Phase 6b P6.49): `updates/incoming/<digest>/`,
    // written by raven-node only, each chunk checked before it is written.
    plain(
        "updates/incoming/*/*",
        "a Raven release on its way from a friend (P6.49): the Raven project's signed manifest \
         and log snapshot, the payload as checked chunk by chunk and which chunks arrived (owner \
         only, never executable); nothing about a contact or a person; at most 256 MiB, gone \
         after 7 idle days",
    ),
    // What failed its checks (Phase 6b P6.49): kept 7 days, never run or
    // shown, at most 64 MiB.
    plain(
        "updates/quarantine/*",
        "what a friend passed on that failed its checks (P6.49): a forged notice, log, manifest \
         or chunk as received, kept for 7 days at most 64 MiB, counted, never run or shown; its \
         name holds the time and what it was, never the friend",
    ),
    // A responder's cached PairResponse (review B-sealed-stores-1, -5):
    // sealed and named by the keyed init_id in a sealed profile, and gone
    // 10 minutes after it was written, live session or not (one named by
    // its init_id goes at once there).
    sealed(
        "lan_pair_response/*",
        Kind::PairResponse,
        crate::lan_dispatch::PAIR_RESPONSE_LOCK,
    ),
    // Quarantine copies: sealed in place under their file's kind (PP.5).
    sealed(
        "peer_device_certs.json.corrupt",
        Kind::PeerDeviceCerts,
        PEER_CACHE_LOCK,
    ),
    sealed(
        "prekey_store.json.corrupt",
        Kind::PrekeyStore,
        PEER_CACHE_LOCK,
    ),
    sealed(
        "peer_cache.stage.json.corrupt",
        Kind::PeerCacheStage,
        PEER_CACHE_LOCK,
    ),
    sealed(
        "revocations.json.corrupt",
        Kind::Revocations,
        REVOCATIONS_LOCK,
    ),
    sealed("bootstrap.json.corrupt", Kind::Bootstrap, BOOTSTRAP_LOCK),
    sealed(
        "lan_noise_pins.json.corrupt",
        Kind::NoisePins,
        NOISE_PINS_LOCK,
    ),
    plain(
        "lan_noise_pins.json",
        "pins of a plain profile; a sealed profile keeps them in lan_noise_pins.rms, and PP.5 \
         merges this file into it and removes it (R07)",
    ),
    // ── Under the epoch data keys (PP.10) ──
    locked(
        "chat_history.json",
        Rule::EpochSealed,
        ".chat_history.lock.sqlite",
    ),
    locked(
        "outbound_body_stage.bin",
        Rule::EpochSealed,
        ".outbound_body_stage.lock.sqlite",
    ),
    plain(
        "chat_history.json.untrusted-plaintext.*",
        "plaintext history moved aside, never imported; raven privacy status lists it (PP.18)",
    ),
    // ── SQLite stores ──
    rule("owed_acks.sqlite", Rule::KeyedSqlite),
    // A set-aside copy (an older build's of a schema-2 store, review R06):
    // merged back and deleted, or sealed in place when it does not open as
    // the profile's schema 2 (PP.12).
    sealed(
        "owed_acks.sqlite.corrupt-*",
        Kind::OwedAcksAside,
        crate::owed_acks::OWED_ACKS_ASIDE_LOCK,
    ),
    rule("app_channel.sqlite3", Rule::KeyedSqlite),
    rule("indexed_sessions.sqlite", Rule::KeyedSqlite),
    rule("friend_custody.sqlite", Rule::KeyedSqlite),
    // The custody handoff store (Phase 5 P5.19): forward rows and tag
    // registrations, keyed and sealed like friend custody's.
    rule(crate::custody_handoff::HANDOFF_DB_FILE, Rule::KeyedSqlite),
    // A damaged handoff store moved aside: what the store held, in the
    // store's own shape (keyed and sealed in a sealed profile); dropped by
    // the prune once its rows would all have expired (8 days).
    rule("custody_handoff.sqlite.corrupt-*", Rule::KeyedSqlite),
    // The security ledger (Phase 6b P6.23): born keyed (`kh_subject`, the
    // clear key in a sealed `meta`), only in a sealed profile; no clear
    // shape, so `raven privacy unseal` deletes it.
    rule(crate::paths::SECURITY_LEDGER_FILE, Rule::KeyedSqlite),
    // A damaged ledger moved aside: the same keyed rows (one copy, dropped
    // by the prune after 30 days and by `raven security clear`).
    rule("security_events.sqlite.corrupt", Rule::KeyedSqlite),
    plain("queue.sqlite", LEGACY_BRIDGE),
    plain("forward_queue.sqlite", LEGACY_BRIDGE),
    plain(
        "prekey_lifecycle.sqlite",
        "a lock table only (prekey_actor_lock): nothing about friends",
    ),
    // ── Already protected ──
    rule(super::META_KEY_FILE, Rule::AlreadyProtected),
    // Windows' K_hist (PP.11), DPAPI-wrapped: erase deletes it first.
    rule(
        crate::chat_history::WINDOWS_HISTORY_KEY_FILE,
        Rule::AlreadyProtected,
    ),
    rule("identity.seed", Rule::AlreadyProtected),
    rule("keystore.vault", Rule::AlreadyProtected),
    rule("indexed-session-secrets/*.dpapi", Rule::AlreadyProtected),
    rule("prekey-lifecycle-secrets/*.dpapi", Rule::AlreadyProtected),
    lab(
        "indexed-session-secrets/*.bin",
        "the locked-file session backend (debug builds only) keeps per-session secrets unprotected",
    ),
    lab(
        "prekey_lifecycle.protected",
        "the locked-file prekey backend (debug builds only)",
    ),
    // ── Plain by design ──
    locked(
        "privacy.json",
        Rule::Plain(
            "the profile's mode, markers and settings: no friend data, read before the keystore",
        ),
        crate::privacy::PRIVACY_LOCK,
    ),
    plain(
        crate::node_policy::POLICY_FILE,
        "settings the node reads before the keystore; in a sealed profile p2p_relays, \
         relay_external and p2p_proxy (Phase 4) live in node_policy_peers.rms (PP.6)",
    ),
    plain(
        crate::node_policy::POLICY_BAD_FILE,
        "an unreadable node_policy.json that `raven lan on` replaced, kept as it was for the \
         user (Phase 3): plain like the file it was",
    ),
    plain("peer_cache.generation", "a number"),
    plain(
        "identity.backend",
        "own identity bookkeeping (the backend marker)",
    ),
    plain(
        "identity.binding",
        "own identity bookkeeping (a checksum of the public key)",
    ),
    plain("keystore.backend", "own keystore choice"),
    plain("device_x25519.pub", "a public key"),
    plain("erase_in_progress", "the erase marker (PP.16)"),
    plain(
        "tui_state.json",
        "terminal app settings; PP.24 moves last_read and display_name to tui_private.rms",
    ),
    plain(
        "desktop_settings.json",
        "desktop app settings (receive, motion, quit, lock on sleep); the user's name is in \
         desktop_private.rms and the chat-keeping time in privacy.json",
    ),
    plain(
        "desktop_hidden.json",
        "ids of the user's own unsent messages deleted in a desktop app (random ids that name \
         nobody); the chat history row stays until the chat-keeping time ends",
    ),
    plain("raven-node.sock", "the IPC endpoint"),
    plain("raven-node.sock.lock", "the IPC endpoint's instance lock"),
    plain(
        "raven-node-service.log",
        "capped log: counts and fixed codes only (cutoff pack M3, CP.8)",
    ),
    plain(
        "raven-node.log",
        "capped log: counts and fixed codes only (cutoff pack M3, CP.8)",
    ),
    plain(
        "raven-node.err",
        "capped log: counts and fixed codes only (cutoff pack M3, CP.8)",
    ),
    plain("contact_request_*.bin", ADVISORY_EXPORT),
    plain("contact_request_*.wire", ADVISORY_EXPORT),
    plain("contact_accept_*.wire", ADVISORY_EXPORT),
    plain(
        "queue.db",
        "legacy name: read once or deleted, never written by this build",
    ),
    plain(
        "outbound_body_stage.json",
        "legacy plaintext stage: imported once, then deleted",
    ),
    plain(
        "prekey_hybrid.secret",
        "legacy name: read once or deleted, never written by this build",
    ),
    lab("mailbox_store.json", "lab mailbox store"),
    lab(
        "offline_mailbox_v1.json",
        "raven-swarm's experimental offline mailbox",
    ),
    lab(
        "lab_device_x25519.secret",
        "lab-era device key name, renamed to device_x25519.secret on first load",
    ),
    lab("lab_device_x25519.pub", "lab-era device key name"),
    lab("lab_device_cert.json", "lab pairing"),
    lab("lab_pair_response.rvpr1", "lab pairing"),
    lab("lab_endpoint_inbox/*", "lab pairing"),
    // `raven erase` refuses a dedicated relay folder (no identity there); in
    // a profile a relay ran in, they are Raven's like the rest (PP.16).
    rule("relay_status.json", Rule::RelayDirPlain),
    rule("relay_key.ed25519", Rule::RelayDirPlain),
    // ── Patterns ──
    plain(
        ".send_*.lock.sqlite",
        "a per-friend send lock, empty: named by a keyed hash in a sealed profile \
         (at_rest::lock_name, PP.6), by the key in hex in a plain one or by an older build \
         (a sealed profile's passes delete those: review B-sealed-stores-4)",
    ),
    plain(".*.lock.sqlite", "an empty lock database"),
    plain("*.sqlite-wal", SQLITE_SIDECAR),
    plain("*.sqlite-shm", SQLITE_SIDECAR),
    plain("*.sqlite-journal", SQLITE_SIDECAR),
    plain("*.sqlite3-wal", SQLITE_SIDECAR),
    plain("*.sqlite3-shm", SQLITE_SIDECAR),
    plain("*.sqlite3-journal", SQLITE_SIDECAR),
    plain(
        ".*.tmp.*",
        "an interrupted atomic write's temp file; migrate_all deletes leftovers older than 1 h",
    ),
];

/// The registered rule for `name` (a path below the data dir with `/`
/// separators): an exact entry first, then the first pattern that matches.
pub fn rule_for(name: &str) -> Option<&'static FileRule> {
    FILES.iter().find(|rule| rule.name == name).or_else(|| {
        FILES
            .iter()
            .find(|rule| rule.name.contains('*') && glob_match(rule.name, name))
    })
}

/// `*` matches any run of characters other than `/`; everything else
/// matches itself.
pub(crate) fn glob_match(pattern: &str, name: &str) -> bool {
    fn go(pattern: &[u8], name: &[u8]) -> bool {
        match pattern.split_first() {
            None => name.is_empty(),
            Some((b'*', rest)) => {
                let mut taken = 0;
                loop {
                    if go(rest, &name[taken..]) {
                        return true;
                    }
                    if taken == name.len() || name[taken] == b'/' {
                        return false;
                    }
                    taken += 1;
                }
            }
            Some((first, rest)) => name.first() == Some(first) && go(rest, &name[1..]),
        }
    }
    go(pattern.as_bytes(), name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    /// File-name extensions the guard looks for (the PP.1 inventory scan's
    /// list, plus the pack's own `.rmk` and `.rms`).
    const EXTENSIONS: [&str; 10] = [
        ".json", ".sqlite", ".sqlite3", ".bin", ".seed", ".secret", ".vault", ".dpapi", ".rmk",
        ".rms",
    ];

    /// File-name literals in production source that are not profile files:
    /// (source file below `node/crates`, pattern of the literal, reason).
    const NOT_PROFILE_FILES: &[(&str, &str, &str)] = &[
        (
            "raven-core/src/vectors.rs",
            "*/*.json",
            "shared-vectors fixtures, named relative to the vectors folder",
        ),
        (
            "raven-core/src/lan_vectors.rs",
            "*_0*.json",
            "shared-vectors fixtures, named relative to the vectors folder",
        ),
        (
            "raven-core/src/hybrid_ratchet_v2_tr.rs",
            "atsam/*.json",
            "a shared-vectors fixture (full-braid lab)",
        ),
        (
            "raven-core/src/identity_store.rs",
            ".lock.sqlite",
            "the suffix that recognises lock databases, not a file",
        ),
        (
            "raven-core/src/release_sign.rs",
            "entries.bin",
            "the offline release tool's log folder (P6.46), never in a profile",
        ),
    ];

    #[derive(Debug, PartialEq, Eq)]
    enum Tok {
        Str(String, usize),
        Attr(String),
        Comment,
        Open,
        Close,
        Bracket(i32),
        Semi,
        Other,
    }

    /// Rust source to tokens: string literals (with their line), attributes,
    /// comments, braces, brackets and semicolons; char literals and lifetimes
    /// are skipped. A textual lexer, not a parser: enough to find literals
    /// and the extent of test-only items.
    fn lex(src: &str) -> Vec<(Tok, usize, usize)> {
        let b = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        let newlines: Vec<usize> = (0..b.len()).filter(|&at| b[at] == b'\n').collect();
        let line = |at: usize| newlines.partition_point(|&nl| nl < at) + 1;
        let boundary =
            |at: usize| at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_');
        while i < b.len() {
            let c = b[i];
            if b[i..].starts_with(b"//") {
                let end = src[i..].find('\n').map_or(b.len(), |n| i + n);
                out.push((Tok::Comment, i, end));
                i = end;
                continue;
            }
            if b[i..].starts_with(b"/*") {
                let start = i;
                let mut depth = 1;
                i += 2;
                while i < b.len() && depth > 0 {
                    if b[i..].starts_with(b"/*") {
                        depth += 1;
                        i += 2;
                    } else if b[i..].starts_with(b"*/") {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                out.push((Tok::Comment, start, i));
                continue;
            }
            // Raw strings: r"..", r#".."#, br#".."#.
            let raw_at = if c == b'b' && b.get(i + 1) == Some(&b'r') {
                i + 1
            } else {
                i
            };
            if b[raw_at] == b'r' && boundary(i) {
                let hashes = b[raw_at + 1..].iter().take_while(|&&h| h == b'#').count();
                if b.get(raw_at + 1 + hashes) == Some(&b'"') {
                    let start = raw_at + 2 + hashes;
                    let close: Vec<u8> = std::iter::once(b'"')
                        .chain(std::iter::repeat_n(b'#', hashes))
                        .collect();
                    let end = (start..b.len())
                        .find(|&at| b[at..].starts_with(&close))
                        .unwrap_or(b.len());
                    out.push((Tok::Str(src[start..end].to_owned(), line(i)), i, end));
                    i = (end + close.len()).min(b.len());
                    continue;
                }
            }
            if c == b'"' || (c == b'b' && b.get(i + 1) == Some(&b'"') && boundary(i)) {
                let start = if c == b'b' { i + 2 } else { i + 1 };
                let mut at = start;
                while at < b.len() && b[at] != b'"' {
                    at += if b[at] == b'\\' { 2 } else { 1 };
                }
                let end = at.min(b.len());
                out.push((Tok::Str(src[start..end].to_owned(), line(i)), i, end));
                i = end + 1;
                continue;
            }
            if c == b'\'' {
                // A char literal ('x', '\n', '\'', '\u{..}', a multi-byte char)
                // or a lifetime.
                if b.get(i + 1) == Some(&b'\\') {
                    i = (i + 3..b.len())
                        .find(|&at| b[at] == b'\'')
                        .map_or(b.len(), |at| at + 1);
                    continue;
                }
                if let Some(ch) = src[i + 1..].chars().next() {
                    let after = i + 1 + ch.len_utf8();
                    if b.get(after) == Some(&b'\'') {
                        i = after + 1;
                        continue;
                    }
                }
                i += 1;
                continue;
            }
            if c == b'#' && (b[i..].starts_with(b"#[") || b[i..].starts_with(b"#![")) {
                let open = i + b[i..].iter().position(|&x| x == b'[').unwrap_or(0);
                let mut depth = 0;
                let mut at = open;
                while at < b.len() {
                    match b[at] {
                        b'[' => depth += 1,
                        b']' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        b'"' => {
                            at += 1;
                            while at < b.len() && b[at] != b'"' {
                                at += if b[at] == b'\\' { 2 } else { 1 };
                            }
                        }
                        _ => {}
                    }
                    at += 1;
                }
                let end = at.min(b.len().saturating_sub(1));
                out.push((Tok::Attr(src[i..=end].to_owned()), i, end));
                i = end + 1;
                continue;
            }
            let tok = match c {
                b'{' => Tok::Open,
                b'}' => Tok::Close,
                b'(' | b'[' => Tok::Bracket(1),
                b')' | b']' => Tok::Bracket(-1),
                b';' => Tok::Semi,
                _ => Tok::Other,
            };
            if tok != Tok::Other {
                out.push((tok, i, i));
            }
            i += 1;
        }
        out
    }

    /// `#[test]`, `#[cfg(test)]`, `#[cfg(all(test, ..))]`, or `#[cfg(any(..))]`
    /// of `test` and the `test-helpers` feature only.
    fn test_only(attr: &str) -> bool {
        let attr: String = attr.chars().filter(|c| !c.is_whitespace()).collect();
        if attr == "#[test]" {
            return true;
        }
        let Some(pred) = attr
            .strip_prefix("#[cfg(")
            .and_then(|rest| rest.strip_suffix(")]"))
        else {
            return false;
        };
        let elements = |list: &str| -> Vec<String> {
            let mut out = Vec::new();
            let (mut depth, mut current) = (0, String::new());
            for ch in list.chars() {
                match ch {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    ',' if depth == 0 => {
                        out.push(std::mem::take(&mut current));
                        continue;
                    }
                    _ => {}
                }
                current.push(ch);
            }
            if !current.is_empty() {
                out.push(current);
            }
            out
        };
        if pred == "test" {
            return true;
        }
        if let Some(list) = pred.strip_prefix("all(").and_then(|p| p.strip_suffix(')')) {
            return elements(list).iter().any(|e| e == "test");
        }
        if let Some(list) = pred.strip_prefix("any(").and_then(|p| p.strip_suffix(')')) {
            return elements(list)
                .iter()
                .all(|e| e == "test" || e == r#"feature="test-helpers""#);
        }
        false
    }

    /// What [`production`] finds in one source file.
    #[derive(Default)]
    struct Production {
        /// String literals outside test-only items, with their lines.
        literals: Vec<(String, usize)>,
        /// Modules declared test-only (`#[cfg(test)] mod x;`): their files
        /// are not production code.
        test_mods: Vec<String>,
        /// The source with comments and test-only items blanked out (lines
        /// kept).
        code: String,
    }

    fn production(src: &str) -> Production {
        let tokens = lex(src);
        let mut found = Production::default();
        let mut blank = Vec::new();
        let mut n = 0;
        while n < tokens.len() {
            match &tokens[n].0 {
                Tok::Comment => {
                    blank.push((tokens[n].1, tokens[n].2));
                    n += 1;
                }
                Tok::Attr(attr) if test_only(attr) => {
                    // Skip the item: to its `;` at depth 0, or to the `}`
                    // that closes its first `{`, or out of the enclosing block.
                    let start = tokens[n].2 + 1;
                    let (mut braces, mut brackets, mut opened) = (0i32, 0i32, false);
                    let mut end = n + 1;
                    while end < tokens.len() {
                        match tokens[end].0 {
                            Tok::Open => {
                                braces += 1;
                                opened = true;
                            }
                            Tok::Close => {
                                braces -= 1;
                                if braces < 0 || (braces == 0 && opened && brackets == 0) {
                                    break;
                                }
                            }
                            Tok::Bracket(step) => brackets += step,
                            Tok::Semi if braces == 0 && brackets == 0 => break,
                            _ => {}
                        }
                        end += 1;
                    }
                    let item_end = tokens.get(end).map_or(src.len(), |t| t.2 + 1);
                    blank.push((tokens[n].1, item_end));
                    // `[pub(..)] mod name;` (after any further attributes).
                    if let Some(words) = src[start.min(item_end)..item_end]
                        .trim()
                        .strip_suffix(';')
                        .map(|item| item.split_whitespace().collect::<Vec<_>>())
                    {
                        if let [.., "mod", name] = words.as_slice() {
                            found.test_mods.push((*name).to_owned());
                        }
                    }
                    n = end + 1;
                }
                Tok::Str(text, line) => {
                    found.literals.push((text.clone(), *line));
                    n += 1;
                }
                _ => n += 1,
            }
        }
        let mut code = src.as_bytes().to_vec();
        for (from, to) in blank {
            for byte in &mut code[from..to.min(src.len())] {
                if *byte != b'\n' {
                    *byte = b' ';
                }
            }
        }
        found.code = String::from_utf8_lossy(&code).into_owned();
        found
    }

    /// A literal that names a file: one of [`EXTENSIONS`], no whitespace, not
    /// a shared-vectors path. Format placeholders (`{}`, `{id}`) become `*`.
    fn file_name_of(literal: &str) -> Option<String> {
        if !EXTENSIONS.iter().any(|ext| literal.ends_with(ext))
            || literal.chars().any(char::is_whitespace)
            || literal.contains("shared-vectors")
        {
            return None;
        }
        let mut name = String::new();
        let mut in_placeholder = false;
        for ch in literal.chars() {
            match ch {
                '{' => {
                    in_placeholder = true;
                    name.push('*');
                }
                '}' => in_placeholder = false,
                _ if in_placeholder => {}
                _ => name.push(ch),
            }
        }
        Some(name)
    }

    /// Classified: an entry equals the name or, as a pattern, matches it; or
    /// the name is exactly an entry's last path part (code joins
    /// `"{account}.dpapi"` to its folder).
    fn classified(name: &str) -> bool {
        FILES.iter().any(|rule| {
            rule.name == name
                || glob_match(rule.name, name)
                || rule.name.rsplit('/').next() == Some(name)
        })
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name != "tests") {
                    rust_files(&path, out);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && path.file_name().is_some_and(|name| name != "tests.rs")
            {
                out.push(path);
            }
        }
    }

    /// The production source files of `krates` (below `node/crates`), test
    /// modules left out: (`crate/src/file.rs`, what [`production`] found).
    fn production_sources(krates: &[&str]) -> Vec<(String, Production)> {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the crates folder")
            .to_path_buf();
        let mut files = Vec::new();
        for krate in krates {
            rust_files(&crates.join(krate).join("src"), &mut files);
        }
        let sources: Vec<(PathBuf, Production)> = files
            .into_iter()
            .map(|path| {
                let found = production(&std::fs::read_to_string(&path).unwrap());
                (path, found)
            })
            .collect();
        // Files of test-only modules (`#[cfg(test)] mod x;`) are skipped.
        let mut skip = BTreeSet::new();
        for (path, found) in &sources {
            let stem = path.file_stem().unwrap().to_string_lossy();
            let parent = path.parent().unwrap();
            let module_dir = if ["lib", "main", "mod"].contains(&stem.as_ref()) {
                parent.to_path_buf()
            } else {
                parent.join(stem.as_ref())
            };
            for name in &found.test_mods {
                skip.insert(module_dir.join(format!("{name}.rs")));
                skip.insert(module_dir.join(name).join("mod.rs"));
            }
        }
        sources
            .into_iter()
            .filter(|(path, _)| !skip.contains(path))
            .map(|(path, found)| {
                let source = path
                    .strip_prefix(&crates)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                (source, found)
            })
            .collect()
    }

    /// Every file-name literal of the production sources of raven-core,
    /// raven-node, ash and raven-client (the desktop apps' engine): (name,
    /// `crate/src/file.rs`, `crate/src/file.rs:line`).
    fn scan_sources() -> Vec<(String, String, String)> {
        let mut found = Vec::new();
        for (source, production) in
            production_sources(&["raven-core", "raven-node", "ash", "raven-client"])
        {
            for (literal, line) in &production.literals {
                if let Some(name) = file_name_of(literal) {
                    found.push((name, source.clone(), format!("{source}:{line}")));
                }
            }
        }
        found
    }

    /// The registry guard: a new file a profile writes must be classified
    /// here before it can land (sealed kind, keyed columns, or a reason).
    #[test]
    fn every_profile_file_name_is_classified() {
        let found = scan_sources();
        // The scan must see the files it guards (a broken lexer finds nothing).
        for known in [
            "contacts.json",
            "indexed_sessions.sqlite",
            "meta_key.rmk",
            "tui_state.json",
            "desktop_settings.json",
            "desktop_private.rms",
        ] {
            assert!(
                found.iter().any(|(name, _, _)| name == known),
                "the scan no longer finds {known}"
            );
        }
        let excused = |name: &str, source: &str| {
            NOT_PROFILE_FILES
                .iter()
                .any(|(file, pattern, _)| *file == source && glob_match(pattern, name))
        };
        let missing: Vec<String> = found
            .iter()
            .filter(|(name, source, _)| !classified(name) && !excused(name, source))
            .map(|(name, _, at)| format!("{name} ({at})"))
            .collect();
        assert!(
            missing.is_empty(),
            "classify the new file in at_rest::FILES (sealed kind or keyed columns), see \
             docs/design/2026-10-at-rest-metadata.md: {missing:?}"
        );
        // Each allow-list entry still excuses something (no stale reasons).
        for (file, pattern, reason) in NOT_PROFILE_FILES {
            assert!(
                found
                    .iter()
                    .any(|(name, source, _)| source == file && glob_match(pattern, name)),
                "stale allow-list entry {file} {pattern} ({reason})"
            );
        }
    }

    /// The transaction half of `keys_load`'s debug assertion: a mark held
    /// next to every production store transaction
    /// (`paths::HeldMark::transaction`), so a key load inside one panics in a
    /// debug build instead of waiting on a keystore dialog in a transaction.
    #[test]
    fn every_store_transaction_is_marked() {
        let (mut seen, mut unmarked) = (0, Vec::new());
        for (source, production) in production_sources(&["raven-core"]) {
            let lines: Vec<&str> = production.code.lines().collect();
            for (n, line) in lines.iter().enumerate() {
                if ![
                    ".transaction_with_behavior(",
                    ".transaction()",
                    "unchecked_transaction(",
                    "begin_journal_free_tx!(",
                ]
                .iter()
                .any(|call| line.contains(call))
                {
                    continue;
                }
                // The statement: back to its `let`, on to its `;`.
                let start = (0..=n)
                    .rev()
                    .find(|&at| lines[at].contains("let "))
                    .unwrap_or(n);
                if lines[start..=n].iter().any(|l| l.contains('$')) {
                    // Inside a macro: marked where the macro is used.
                    continue;
                }
                let end = (n..lines.len())
                    .find(|&at| lines[at].trim_end().ends_with(';'))
                    .unwrap_or(n);
                seen += 1;
                if !lines
                    .get(end + 1)
                    .is_some_and(|next| next.contains("HeldMark::transaction()"))
                {
                    unmarked.push(format!("{source}:{}", n + 1));
                }
            }
        }
        assert!(seen >= 40, "the scan found only {seen} store transactions");
        assert!(
            unmarked.is_empty(),
            "hold crate::paths::HeldMark::transaction() right after each store transaction \
             begins (at_rest::keys_load must never run inside one): {unmarked:?}"
        );
    }

    #[test]
    fn the_scanner_sees_production_literals_and_skips_test_code() {
        let src = r####"
            //! "doc.json" in a comment
            const A: &str = "new_profile_file.json";
            /* "block.json" */
            fn f<'a>(x: &'a str) -> char { let _ = format!("contact_{}.wire", x); '"' }
            #[cfg(test)]
            const T: [&str; 2] = ["fixture_a.json", "fixture_b.json"];
            const B: &str = r#"raw_"name".sqlite"#;
            #[cfg(all(test, unix))]
            mod e2e;
            #[cfg(any(test, unix))]
            fn both() -> &'static str { "both.secret" }
            #[cfg(test)]
            mod tests {
                fn g() { let _ = "inner_test.json"; let _ = '{'; }
            }
            const C: &str = "after_{id}_tests.rms";
        "####;
        let found = production(src);
        let names: Vec<String> = found
            .literals
            .iter()
            .filter_map(|(text, _)| file_name_of(text))
            .collect();
        assert_eq!(
            names,
            [
                "new_profile_file.json",
                "raw_\"name\".sqlite",
                "both.secret",
                "after_*_tests.rms"
            ]
        );
        assert_eq!(found.test_mods, ["e2e"]);
        assert!(!found.code.contains("doc.json") && !found.code.contains("inner_test"));
        assert!(found.code.contains("new_profile_file.json"));
        assert_eq!(found.code.lines().count(), src.lines().count());
        // What the guard reports: a new name, and a new name of a familiar
        // extension (a pattern's last part matches only itself).
        assert!(!classified("new_profile_file.json"));
        assert!(!classified("new_secret.bin"));
        assert!(classified("*.bin") && classified(".send_*.lock.sqlite"));
        assert!(classified(".contacts.lock.sqlite") && classified("contacts.json"));
    }

    #[test]
    fn patterns_and_lookup() {
        assert!(glob_match(".*.lock.sqlite", ".contacts.lock.sqlite"));
        assert!(!glob_match(".*.lock.sqlite", ".lock.sqlite"));
        assert!(glob_match(
            "contact_inbox/*.wire",
            "contact_inbox/00ff.wire"
        ));
        assert!(!glob_match(
            "contact_inbox/*.wire",
            "contact_inbox/a/b.wire"
        ));
        assert!(!glob_match("*.sqlite-wal", "x/y.sqlite-wal"));
        assert_eq!(
            rule_for(".send_00ab.lock.sqlite").map(|r| r.name),
            Some(".send_*.lock.sqlite")
        );
        assert_eq!(
            rule_for(".contacts.lock.sqlite").map(|r| r.name),
            Some(".*.lock.sqlite")
        );
        assert_eq!(
            rule_for("contacts.json").map(|r| r.rule),
            Some(Rule::Sealed(Kind::Contacts))
        );
        assert!(rule_for("unknown.json").is_none());
    }

    /// Names are unique, every sealed entry names a writer lock (the existing
    /// one, or `.at_rest.<kind name>.lock.sqlite`), and every kind is
    /// registered.
    #[test]
    fn registry_is_consistent() {
        let mut names = BTreeSet::new();
        for rule in FILES {
            assert!(names.insert(rule.name), "{} twice", rule.name);
            if let Rule::Sealed(_) = rule.rule {
                let lock = rule
                    .lock
                    .unwrap_or_else(|| panic!("{} has no writer lock", rule.name));
                assert!(
                    lock.starts_with('.') && lock.ends_with(".lock.sqlite"),
                    "{lock}"
                );
                if let Some(name) = lock
                    .strip_prefix(".at_rest.")
                    .and_then(|rest| rest.strip_suffix(".lock.sqlite"))
                {
                    assert!(
                        Kind::ALL.iter().any(|k| k.name() == name),
                        "{lock} names no kind"
                    );
                }
                assert!(rule.erase, "{} is a profile file", rule.name);
            }
            if let Rule::Plain(reason) | Rule::Lab(reason) = rule.rule {
                assert!(!reason.trim().is_empty(), "{} needs a reason", rule.name);
            }
        }
        for kind in Kind::ALL {
            assert!(
                FILES.iter().any(|rule| rule.rule == Rule::Sealed(kind)),
                "kind {} is not registered",
                kind.code()
            );
        }
        // The plan's existing writer locks are the ones the files' writers take.
        for (file, lock) in [
            ("contacts.json", ".contacts.lock.sqlite"),
            ("learned_routes.json", ".learned_routes.lock.sqlite"),
            ("route_memory.json", ".route_memory.lock.sqlite"),
            ("outbox_routes.json", ".outbox_routes.lock.sqlite"),
            ("peer_device_certs.json", ".lan_peer_cache.lock.sqlite"),
            (
                "device_registry.json",
                crate::device_cert::DEVICE_REGISTRY_LOCK,
            ),
            ("device_sync_seen.json", ".device_sync_seen.lock.sqlite"),
            ("relay_allow.json", ".relay_allow.lock.sqlite"),
            ("chat_inbox_cursors.json", ".chat_inbox_cursors.lock.sqlite"),
            ("lan_seen.json", ".at_rest.lan_seen.lock.sqlite"),
            ("custody_home.json", ".learned_routes.lock.sqlite"),
            ("prekey_published_local.json", ".lan_peer_cache.lock.sqlite"),
            ("learning.bin", ".learning.lock.sqlite"),
        ] {
            assert_eq!(rule_for(file).and_then(|r| r.lock), Some(lock), "{file}");
        }
    }
}
