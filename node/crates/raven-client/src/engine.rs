//! The engine behind `call`: one per profile, shared by every thread of the
//! app (the operations lock what they change), with the caches the
//! operations and the watcher share.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant, SystemTime};

use ash_engine::engine::{self as bridge, ContactView, NodeSlot, ReadMarks};
use raven_core::chat_history::{ChatHistory, ChatHistoryEntry};
use raven_core::identity::Identity;
use raven_core::ipc::{IpcRequest, IpcResponse, OutboxItem, IPC_VERSION, MAX_OUTBOX_LIST};
use serde_json::{json, Map, Value};

use crate::envelope::{self, code, ApiError, Args, OpResult};
use crate::events::EventHub;
use crate::explain::{self, IdentityProblem};
use crate::messages::{MessageBook, SendQueues};
use crate::node::{NodeMemory, WatcherState};
use crate::profile::{self, OpenState};
use crate::safety;
use crate::settings::{self, Settings};

/// A mutex that a thread which panicked holding it does not keep locked.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Milliseconds since the Unix epoch (0 before it).
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A file's size and time: a cache is read again when they change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamp(Option<(u64, Option<SystemTime>)>);

impl Stamp {
    pub(crate) fn of(path: &Path) -> Stamp {
        Stamp(
            std::fs::metadata(path)
                .ok()
                .map(|m| (m.len(), m.modified().ok())),
        )
    }
}

/// raven-node's outbox, as its last `OutboxList` said.
#[derive(Debug, Default)]
pub(crate) struct OutboxSnap {
    /// A node answered.
    pub answered: bool,
    /// Its outbox worker runs (it retries in the background).
    pub worker_running: bool,
    /// Messages (not ACKs), by message id in lower case.
    pub items: HashMap<String, OutboxItem>,
    /// Messages a friend holds as a sealed letter (Phase 5's letter book,
    /// read while letters are live), by message id in lower case.
    pub letters: std::collections::HashSet<String>,
    /// The friends (keys, hex) that hold a sealed copy of a message, by
    /// message id in lower case (`outbox_routes.json`'s `custodians_held`,
    /// read only while a listed message has one).
    pub holders: HashMap<String, Vec<String>>,
}

/// contacts.json's and the block list's stamps.
type ContactStamps = (Stamp, Stamp);
/// The read markers' files' stamps (tui_state.json, tui_private.rms).
type MarkStamps = [Stamp; 2];

#[derive(Default)]
pub(crate) struct Caches {
    history: Option<(Stamp, Arc<Vec<ChatHistoryEntry>>)>,
    contacts: Option<(ContactStamps, Arc<Vec<ContactView>>)>,
    outbox: Option<(Instant, Arc<OutboxSnap>)>,
    marks: Option<(MarkStamps, Arc<ReadMarks>)>,
}

/// What the engine holds of the profile's keys, and Lock v2 as it last
/// learned it ([`Inner::note_locked`]).
#[derive(Default)]
struct Keys {
    /// The identity once loaded, while Lock v2 does not hold the profile.
    identity: Option<Arc<Identity>>,
    /// Lock v2 holds the profile: no key is loaded or kept, and only the
    /// lock's own ops and the node's lifecycle run ([`runs_while_locked`]).
    locked: bool,
    /// An unlock came and the identity was not loaded again yet (the next
    /// operation that needs it, or the watcher's next beat, loads it).
    reload: bool,
}

struct SettingsState {
    value: Settings,
    /// Read from the profile (or found missing) once.
    loaded: bool,
}

pub(crate) struct Inner {
    pub(crate) me: Weak<Inner>,
    /// The profile folder, or why none could be determined.
    pub(crate) data_dir: Result<PathBuf, String>,
    /// What opening the profile did (profile.rs): taken before the profile
    /// is read, never under a data-dir lock.
    pub(crate) open_state: Mutex<OpenState>,
    /// The identity, and Lock v2's hold (never one without the other's
    /// mutex: a lock that comes during a load drops what the load found).
    keys: Mutex<Keys>,
    pub(crate) events: EventHub,
    /// Every change to contacts.json the engine makes goes through it.
    pub(crate) contacts_lock: Mutex<()>,
    /// Starting and stopping raven-node, one at a time.
    pub(crate) node_gate: Mutex<()>,
    pub(crate) node_slot: NodeSlot,
    pub(crate) node: Mutex<NodeMemory>,
    settings: Mutex<SettingsState>,
    pub(crate) caches: Mutex<Caches>,
    pub(crate) book: Mutex<MessageBook>,
    /// The sends waiting for each friend, each friend's on a worker of its
    /// own (messages.rs `enqueue_send`).
    pub(crate) send_queues: Mutex<SendQueues>,
    pub(crate) watcher: Mutex<WatcherState>,
    /// Well-formed words that did not match, per friend, this session.
    pub(crate) mismatches: Mutex<HashMap<String, u32>>,
    /// Read markers `messages.mark_read` set that could not be saved (a
    /// settings file that can't be read): they count in this run.
    pub(crate) marks_unsaved: Mutex<ReadMarks>,
    /// What the watcher last saw of the group store (groups.rs).
    pub(crate) groups: Mutex<crate::groups::GroupWatch>,
    /// The friends `nearby.contact` asked raven-node to advertise for, by
    /// key (hex), until when (`None`: until asked to stop): what
    /// `nearby.status` lists as `advertising_for` (nearby.rs).
    pub(crate) nearby_on: Mutex<HashMap<String, Option<u64>>>,
}

impl Inner {
    pub(crate) fn new(data_dir: Result<PathBuf, String>) -> Arc<Inner> {
        // The CLI code prints what it does on stdout; inside an app that
        // would land in the app's own output.
        bridge::set_quiet();
        // The node runs in this process (iOS, RAVEN_NODE_MODE=embedded).
        #[cfg(feature = "embedded-node")]
        if crate::embedded::mode_on() {
            crate::embedded::install();
        }
        Arc::new_cyclic(|me| Inner {
            me: me.clone(),
            data_dir,
            open_state: Mutex::new(OpenState::default()),
            keys: Mutex::new(Keys::default()),
            events: EventHub::new(),
            contacts_lock: Mutex::new(()),
            node_gate: Mutex::new(()),
            node_slot: NodeSlot::new(),
            node: Mutex::new(NodeMemory::default()),
            settings: Mutex::new(SettingsState {
                value: Settings::default(),
                loaded: false,
            }),
            caches: Mutex::new(Caches::default()),
            book: Mutex::new(MessageBook::default()),
            send_queues: Mutex::new(SendQueues::default()),
            watcher: Mutex::new(WatcherState::default()),
            mismatches: Mutex::new(HashMap::new()),
            marks_unsaved: Mutex::new(ReadMarks::new()),
            groups: Mutex::new(crate::groups::GroupWatch::default()),
            nearby_on: Mutex::new(HashMap::new()),
        })
    }

    /// One request in, one response out. Never panics past `call` (which
    /// catches), never returns a field named like a secret, and every string
    /// in it is sanitised.
    pub(crate) fn handle(&self, text: &str) -> Value {
        let result =
            envelope::parse_request(text).and_then(|req| self.dispatch(&req.op, &Args(&req.args)));
        let mut response = match result {
            Ok(v) => envelope::success(v),
            Err(e) => envelope::failure(&e),
        };
        if let Some(key) = safety::forbidden_field(&response) {
            response = envelope::failure(&ApiError::internal(format!(
                "the engine refused to return a field named {key}"
            )));
        }
        safety::sanitize_strings(&mut response);
        response
    }

    fn dispatch(&self, op: &str, args: &Args) -> OpResult {
        /// An operation that touches the profile.
        type ProfileOp = fn(&Inner, &Args) -> OpResult;
        let run: ProfileOp = match op {
            // What answers without opening the profile: what this build is,
            // the profile's state (it opens the profile itself and says a
            // refusal as its state), the events, the privacy pack's state
            // (file reads), the unlock (it may run on a locked profile) and
            // the word list.
            "app.info" => return Ok(app_info()),
            "profile.state" => return Ok(self.profile_state()),
            "events.poll" => return self.events_poll(args),
            "privacy.state" => return self.privacy_state(),
            "privacy.unlock" => return self.privacy_unlock(),
            "verify.word_hint" => return crate::contacts::word_hint(args),
            // The privacy pack's other actions are the CLI's (and the
            // terminal app's) for now: say so, change nothing.
            "privacy.lock" => return Err(not_in_the_app(op, "raven lock")),
            "privacy.encrypt" => return Err(not_in_the_app(op, "raven privacy seal-now")),
            "privacy.erase" => return Err(not_in_the_app(op, "raven erase")),
            "identity.create" => |me, args| me.identity_create(args),
            "identity.me" => |me, _| me.identity_me(),
            "card.make" => |me, args| me.card_make(args),
            "card.parse" => |me, args| me.card_parse(args),
            "contacts.list" => |me, _| me.contacts_list(),
            "contacts.add" => |me, args| me.contacts_add(args),
            "contacts.rename" => |me, args| me.contacts_rename(args),
            "contacts.remove" => |me, args| me.contacts_remove(args),
            "contacts.set_address" => |me, args| me.contacts_set_address(args),
            // The chat controls (chats.rs; local to this device).
            "contacts.block" => |me, args| me.contacts_block(args),
            "contacts.unblock" => |me, args| me.contacts_unblock(args),
            "contacts.unverify" => |me, args| me.contacts_unverify(args),
            "messages.clear" => |me, args| me.messages_clear(args),
            "groups.clear" => |me, args| me.groups_clear(args),
            "chats.delete" => |me, args| me.chats_delete(args),
            "chats.pin" => |me, args| me.chats_pin(args),
            "chats.list" => |me, _| me.chats_list(),
            "verify.check_words" => |me, args| me.verify_check_words(args),
            "verify.check_old_code" => |me, args| me.verify_check_old_code(args),
            "messages.history" => |me, args| me.messages_history(args),
            "messages.send" => |me, args| me.messages_send(args),
            "messages.retry" => |me, args| me.messages_retry(args),
            "messages.stop" => |me, args| me.messages_stop(args),
            "messages.delete" => |me, args| me.messages_delete(args),
            "messages.details" => |me, args| me.messages_details(args),
            "messages.mark_read" => |me, args| me.messages_mark_read(args),
            "messages.handoff" => |me, args| me.messages_handoff(args),
            "node.status" => |me, _| me.node_status_op(),
            "node.start" => |me, _| me.node_start(),
            "node.stop" => |me, _| me.node_stop(),
            // The app's lifecycle (the embedded node: docs/IOS.md).
            "node.pause" => |me, args| me.node_pause(args),
            "node.resume" => |me, _| me.node_resume(),
            "mail.check" => |me, args| me.mail_check(args),
            "network.path" => |me, args| me.network_path(args),
            "settings.get" => |me, _| Ok(me.settings_view().to_json()),
            "settings.set" => |me, args| me.settings_set(args),
            // Every way to reach friends (network.rs, NETWORK_PARITY.md).
            "network.status" => |me, _| me.network_status(),
            "network.set" => |me, args| me.network_set(args),
            "network.check" => |me, args| me.network_check(args),
            // Bluetooth nearby (nearby.rs; Task 2 design §4).
            "nearby.status" => |me, _| me.nearby_status(),
            "nearby.contact" => |me, args| me.nearby_contact(args),
            "nearby.stop_all" => |me, _| me.nearby_stop_all(),
            "nearby.permission" => |me, _| me.nearby_permission(),
            "contacts.routes" => |me, args| me.contacts_routes(args),
            "contacts.set_routes" => |me, args| me.contacts_set_routes(args),
            "security.status" => |me, _| me.security_status(),
            "lock.state" => |me, _| me.lock_state(),
            "lock.now" => |me, _| me.lock_now(),
            "lock.unlock" => |me, args| me.lock_unlock(args),
            "updates.status" => |me, _| me.updates_status(),
            // Group chats (groups.rs; lab only).
            "groups.list" => |me, _| me.groups_list(),
            "groups.get" => |me, args| me.groups_get(args),
            "groups.create" => |me, args| me.groups_create(args),
            "groups.add" => |me, args| me.groups_add(args),
            "groups.remove" => |me, args| me.groups_remove(args),
            "groups.leave" => |me, args| me.groups_leave(args),
            "groups.history" => |me, args| me.groups_history(args),
            "groups.send" => |me, args| me.groups_send(args),
            "groups.mark_read" => |me, args| me.groups_mark_read(args),
            "lock.passphrase_state" => |me, _| me.lock_passphrase_state(),
            "lock.set_passphrase" => |me, args| me.lock_set_passphrase(args),
            "lock.remove_passphrase" => |me, args| me.lock_remove_passphrase(args),
            other => return Err(ApiError::bad_request(format!("unknown op {other:?}"))),
        };
        // A Raven passphrase profile whose keys this process cannot open
        // yet counts as locked (Lock v2) from the first op on.
        if !self.locked() && self.vault_key_missing() {
            self.note_locked(true);
        }
        // Lock v2 holds the profile: only the lock's own ops and the node's
        // lifecycle run, and the profile is not opened for them (opening
        // loads keys); the cheap refusals still apply.
        if self.locked() {
            if !runs_while_locked(op) {
                return Err(locked_error(op));
            }
            self.refuse_closed()?;
            return run(self, args);
        }
        // Opened as the CLI opens it before every command, and refused as
        // it refuses (profile.rs).
        self.open()?;
        run(self, args)
    }

    // ── Profile and identity ────────────────────────────────────────────────

    pub(crate) fn data_dir(&self) -> Result<&Path, ApiError> {
        self.data_dir.as_deref().map_err(|why| {
            ApiError::new(
                code::PROFILE_UNREADABLE,
                "Raven can't tell which folder to keep its data in. Set RAVEN_DATA_DIR, then \
                 open Raven again.",
                why.clone(),
            )
        })
    }

    /// The identity once loaded (asked for again only after a Lock v2
    /// unlock; none while locked).
    pub(crate) fn cached_identity(&self) -> Option<Arc<Identity>> {
        lock(&self.keys).identity.clone()
    }

    /// The profile's identity: NOT_INITIALIZED before there is one,
    /// KEYCHAIN_DENIED or PROFILE_UNREADABLE when it can't be read,
    /// PROFILE_LOCKED while Lock v2 holds the profile (nothing is loaded
    /// then).
    pub(crate) fn identity(&self) -> Result<Arc<Identity>, ApiError> {
        {
            let keys = lock(&self.keys);
            if keys.locked {
                return Err(locked_error("identity"));
            }
            if let Some(id) = &keys.identity {
                return Ok(Arc::clone(id));
            }
        }
        let dir = self.data_dir()?;
        match bridge::try_load_identity(dir) {
            Ok(Some(id)) => {
                let mut keys = lock(&self.keys);
                // A lock that came during the load: what it found goes.
                if keys.locked {
                    return Err(locked_error("identity"));
                }
                keys.reload = false;
                Ok(Arc::clone(
                    keys.identity.get_or_insert_with(|| Arc::new(id)),
                ))
            }
            Ok(None) => Err(ApiError::of(
                code::NOT_INITIALIZED,
                "this profile has no Raven identity yet",
            )),
            Err(why) => Err(identity_error(&why)),
        }
    }

    /// Keeps `id` as the profile's identity (the first one kept stays),
    /// unless Lock v2 holds the profile: the caller still gets it then, and
    /// nothing is kept.
    pub(crate) fn keep_identity(&self, id: Identity) -> Arc<Identity> {
        let mut keys = lock(&self.keys);
        if keys.locked {
            return Arc::new(id);
        }
        keys.reload = false;
        Arc::clone(keys.identity.get_or_insert_with(|| Arc::new(id)))
    }

    /// The profile has an identity: loaded in this engine, or on record
    /// (raven-core's marker files; no keystore call). Settings are written
    /// into the profile only then.
    pub(crate) fn identity_on_record(&self) -> bool {
        self.cached_identity().is_some()
            || self.data_dir().is_ok_and(|dir| {
                raven_core::identity_store::identity_recorded(dir).unwrap_or(false)
            })
    }

    fn identity_create(&self, args: &Args) -> OpResult {
        let name = args.opt_str("display_name")?.and_then(settings::clean_name);
        let dir = self.data_dir()?.to_path_buf();
        let id = match self.cached_identity() {
            Some(id) => id,
            None => match bridge::try_load_identity(&dir) {
                Ok(Some(id)) => self.keep_identity(id),
                // Never offer to create an identity over one that can't be
                // read: it may be there.
                Err(why) => return Err(identity_error(&why)),
                Ok(None) => {
                    bridge::create_private_data_dir(&dir).map_err(|e| {
                        ApiError::of(code::PROFILE_UNREADABLE, format!("{}: {e}", dir.display()))
                    })?;
                    // As `raven init` and the terminal app's first run: a
                    // profile created now also picks its own LAN port while
                    // that gate is live (Phase 6b P6.36).
                    let (id, _backend) = raven_core::load_or_create_profile_identity(&dir)
                        .map_err(|e| identity_error(&e.redacted_display()))?;
                    self.keep_identity(id)
                }
            },
        };
        // Settings chosen during setup, kept in memory until now.
        let mut chosen = self.settings();
        if name.is_some() {
            chosen.display_name = name;
        }
        // Sealed now where this build seals, as the CLI's next command would
        // seal it: the settings below are written into the sealed profile.
        self.seal_new_profile();
        let mut result = Map::new();
        // The identity's first prekey and device certificate: without them
        // nobody can start a conversation with this profile yet, but the
        // identity stands (the CLI's `init` reports it the same way).
        if let Err(why) = raven_core::ensure_local_prekey(&dir, &id) {
            result.insert("note".into(), format!("prekey: {why}").into());
        }
        self.store_settings(chosen)?;
        let me = crate::identity::me_words(&id);
        result.insert("address".into(), me.address.into());
        result.insert("words".into(), json!(me.words));
        result.insert("old_code".into(), me.old_code.into());
        Ok(Value::Object(result))
    }

    fn identity_me(&self) -> OpResult {
        let id = self.identity()?;
        let dir = self.data_dir()?;
        let me = crate::identity::me_words(&id);
        let card = bridge::card_line(dir, &id, "").unwrap_or_else(|_| bridge::plain_card(&id));
        let mut result = json!({
            "address": me.address,
            "words": me.words,
            "old_code": me.old_code,
            "card": card,
            "invite": me.invite,
        });
        if let Some(name) = self.settings().display_name {
            result["display_name"] = name.into();
        }
        Ok(result)
    }

    // ── Lock v2: what the engine lets go ────────────────────────────────────

    /// Lock v2 holds the profile, as this engine last learned it.
    pub(crate) fn locked(&self) -> bool {
        lock(&self.keys).locked
    }

    /// Lock v2 as the engine just learned it: from `lock.now`, `lock.unlock`
    /// or `lock.state`, or from the node's Status (the watcher's beat, a
    /// node op), so a lock or an unlock made elsewhere (`raven lock`, the
    /// terminal app, a wake from sleep) counts too. Only while the gate is
    /// live in this build: a build with it shut never locks here. A lock
    /// lets go of what this engine holds of the profile's secrets: the
    /// identity, the at-rest keys and the vault's derived key this process
    /// loaded, the cached history (message text), contacts, read markers
    /// and outbox, and every event not read yet; while it holds, no event
    /// is queued ([`EventHub::set_locked`]). An unlock lets them load again
    /// at their next use; `events.poll` then says `reset` once. An unlock
    /// of a node does not unlock this engine while it cannot open the
    /// profile's vault itself ([`Inner::vault_key_missing`]): `lock.unlock`
    /// with the passphrase does.
    pub(crate) fn note_locked(&self, locked: bool) {
        if !crate::network::lock_v2_live() {
            return;
        }
        let locked = locked || self.vault_key_missing();
        // All under the keys' mutex (then the queue's and the caches'), so
        // a lock and an unlock noted at once by two threads end in one
        // state.
        let mut keys = lock(&self.keys);
        let was = keys.locked;
        if locked == was {
            return;
        }
        keys.locked = locked;
        keys.reload = !locked;
        self.events.set_locked(locked);
        if locked {
            keys.identity = None;
            *lock(&self.caches) = Caches::default();
            if let Ok(dir) = self.data_dir() {
                raven_core::at_rest::forget_cached_keys(dir);
                raven_core::keystore_vault::forget_process_key(dir);
            }
        }
    }

    /// A profile with a Raven passphrase whose vault this process cannot
    /// open by itself now: its derived key is not cached here (an unlock
    /// with the passphrase caches it: in this process for an embedded node,
    /// through `lock.unlock` for a raven-node program) and no passphrase
    /// file is configured (a headless setup reads that by itself). Such a
    /// profile counts as locked here whatever the node says: nothing could
    /// load. Only while the gate is live; file reads only, no KDF.
    pub(crate) fn vault_key_missing(&self) -> bool {
        if !crate::network::lock_v2_live() {
            return false;
        }
        let Ok(dir) = self.data_dir() else {
            return false;
        };
        let vault = bridge::has_passphrase(dir).unwrap_or(false)
            || raven_core::raven_passphrase::unfinished(dir).unwrap_or(false);
        vault
            && !raven_core::keystore_vault::process_key_held(dir)
            && !raven_core::keystore_vault::passphrase_file_configured()
    }

    /// After an unlock the identity (and a sealed profile's at-rest key)
    /// loads again: at once from `lock.unlock`, and at the watcher's next
    /// beat when the unlock came from elsewhere. Best effort: a failure is
    /// said by the next operation that needs them.
    pub(crate) fn reload_after_unlock(&self) {
        let due = {
            let keys = lock(&self.keys);
            !keys.locked && keys.reload
        };
        if due && self.identity().is_ok() {
            let _ = self.open_as(crate::profile::KeyLoad::Now);
        }
    }

    /// Puts something into the caches, unless Lock v2 holds the profile
    /// (a read that began before the lock keeps nothing past it).
    fn keep_cached(&self, put: impl FnOnce(&mut Caches)) {
        let keys = lock(&self.keys);
        if !keys.locked {
            put(&mut lock(&self.caches));
        }
    }

    // ── The privacy pack ────────────────────────────────────────────────────
    // profile.rs: profile.state, privacy.state and privacy.unlock.

    // ── Settings ────────────────────────────────────────────────────────────

    /// The settings as the engine keeps them: desktop_settings.json and the
    /// name's own file, read once (settings.rs); in memory only before the
    /// identity exists. The chat-keeping time and `forget_addresses` are the
    /// privacy pack's: [`Inner::settings_view`].
    pub(crate) fn settings(&self) -> Settings {
        let mut state = lock(&self.settings);
        if !state.loaded {
            if let Ok(dir) = self.data_dir() {
                if let settings::Loaded::Read(s) = settings::load(dir) {
                    state.value = s;
                }
                // The name's own file; an older engine's name in
                // desktop_settings.json until it moves (profile.rs).
                if let Ok(Some(name)) = settings::load_name(dir) {
                    state.value.display_name = Some(name);
                }
                state.loaded = true;
            }
        }
        state.value.clone()
    }

    /// The settings are read again at the next use (once the identity
    /// exists: before, they live in memory only).
    pub(crate) fn forget_settings(&self) {
        if self.identity_on_record() {
            lock(&self.settings).loaded = false;
        }
    }

    /// API.md's `Settings`: [`Inner::settings`], with the chat-keeping time
    /// the privacy pack keeps (`privacy.json`, once the identity exists) and
    /// `forget_addresses` as the pack does it (always).
    pub(crate) fn settings_view(&self) -> Settings {
        let mut view = self.settings();
        if let (true, Ok(dir)) = (self.identity_on_record(), self.data_dir()) {
            view.keep_chats_days = raven_core::privacy::chat_keep(dir).days();
        }
        view.forget_addresses = true;
        view
    }

    /// Keeps `next`, and writes it once the identity exists, each part where
    /// it belongs (settings.rs): the name first (sealed in a sealed profile,
    /// where it fails without the key), then the chat-keeping time, then
    /// desktop_settings.json.
    fn store_settings(&self, next: Settings) -> Result<(), ApiError> {
        if let (true, Ok(dir)) = (self.identity_on_record(), self.data_dir()) {
            let failed = |why: String| {
                if bridge::at_rest_key_missing(dir) {
                    let mut e = profile::key_missing_error(dir);
                    e.detail = why;
                    e
                } else {
                    ApiError::new(
                        code::INTERNAL,
                        "Raven couldn't save your settings. Try again; if it keeps happening, \
                         open Details.",
                        why,
                    )
                }
            };
            if settings::load_name(dir).ok() != Some(next.display_name.clone()) {
                settings::save_name(dir, next.display_name.as_deref())
                    .map_err(|e| failed(format!("{}: {e}", settings::PRIVATE_FILE)))?;
            }
            let keep = settings::chat_keep_of(next.keep_chats_days);
            if raven_core::privacy::chat_keep(dir) != keep {
                raven_core::privacy::set_chat_keep(dir, keep)
                    .map_err(|e| failed(format!("privacy.json chat_keep: {e}")))?;
            }
            settings::save(dir, &next)
                .map_err(|e| failed(format!("{}: {e}", settings::FILE_NAME)))?;
        }
        let mut state = lock(&self.settings);
        state.value = next;
        state.loaded = true;
        Ok(())
    }

    fn settings_set(&self, args: &Args) -> OpResult {
        let next = self.settings_view().apply(args)?;
        self.store_settings(next)?;
        Ok(self.settings_view().to_json())
    }

    // ── What the operations and the watcher read ────────────────────────────

    /// The chat history (both directions, in written order), read again only
    /// when its file changed. Needs the identity: reading takes the history's
    /// lock, which creates its file.
    pub(crate) fn history(&self) -> Result<Arc<Vec<ChatHistoryEntry>>, ApiError> {
        self.identity()?;
        let dir = self.data_dir()?;
        let stamp = Stamp::of(&raven_core::chat_history::history_path(dir));
        if let Some((cached, entries)) = &lock(&self.caches).history {
            if *cached == stamp {
                return Ok(Arc::clone(entries));
            }
        }
        let entries = Arc::new(
            ChatHistory::load(dir)
                .map(|h| h.without_group_copies().entries)
                .map_err(|e| history_error(dir, &e.to_string()))?,
        );
        self.keep_cached(|c| c.history = Some((stamp, Arc::clone(&entries))));
        Ok(entries)
    }

    /// Forget the cached history: the next read loads it again.
    pub(crate) fn invalidate_history(&self) {
        lock(&self.caches).history = None;
    }

    /// The saved friends (with their blocked state), read again only when
    /// contacts.json or the block list changed.
    pub(crate) fn contacts(&self) -> Result<Arc<Vec<ContactView>>, ApiError> {
        self.identity()?;
        let dir = self.data_dir()?;
        let stamp = (
            Stamp::of(&bridge::contacts_path(dir)),
            Stamp::of(&raven_core::chat_history::blocked_path(dir)),
        );
        if let Some((cached, contacts)) = &lock(&self.caches).contacts {
            if *cached == stamp {
                return Ok(Arc::clone(contacts));
            }
        }
        let contacts = Arc::new(bridge::contact_views(dir).map_err(|why| {
            if bridge::at_rest_key_missing(dir) {
                let mut e = profile::key_missing_error(dir);
                e.detail = why;
                return e;
            }
            ApiError::new(
                code::PROFILE_UNREADABLE,
                "Your friends list can't be read. Open Details.",
                why,
            )
        })?);
        self.keep_cached(|c| c.contacts = Some((stamp, Arc::clone(&contacts))));
        Ok(contacts)
    }

    pub(crate) fn invalidate_contacts(&self) {
        lock(&self.caches).contacts = None;
    }

    /// raven-node's outbox, asked again when the last answer is older than
    /// `max_age` (an empty snapshot when no node answers).
    pub(crate) fn outbox(&self, max_age: Duration) -> Arc<OutboxSnap> {
        if let Some((at, snap)) = &lock(&self.caches).outbox {
            if at.elapsed() <= max_age {
                return Arc::clone(snap);
            }
        }
        let mut snap = OutboxSnap::default();
        if let (Some(_), Ok(dir)) = (self.cached_identity(), self.data_dir()) {
            let req = IpcRequest::OutboxList {
                v: IPC_VERSION,
                peer_pub_hex: None,
                limit: Some(MAX_OUTBOX_LIST),
            };
            if let Ok(IpcResponse::OutboxListResult {
                worker_running,
                items,
                ..
            }) = bridge::ipc_request_timeout(dir, &req, Duration::from_millis(1000))
            {
                snap.answered = true;
                snap.worker_running = worker_running;
                snap.items = items
                    .into_iter()
                    .filter(|i| i.kind == "message")
                    .map(|i| (i.message_id_hex.to_ascii_lowercase(), i))
                    .collect();
            }
            if raven_core::horizon::letter_live_enabled() {
                snap.letters = letters_held(dir);
            }
            if snap.items.values().any(|i| i.in_custody > 0) {
                snap.holders = copy_holders(dir);
            }
        }
        let snap = Arc::new(snap);
        self.keep_cached(|c| c.outbox = Some((Instant::now(), Arc::clone(&snap))));
        snap
    }

    /// Forget raven-node's last outbox answer: the next read asks again.
    pub(crate) fn invalidate_outbox(&self) {
        lock(&self.caches).outbox = None;
    }

    /// Every friend's read marker, shared with the terminal app
    /// (tui/read_marks.rs in ash): read again only when its files changed,
    /// with this run's markers that could not be saved over them where
    /// later. Reads only.
    pub(crate) fn read_marks(&self) -> ReadMarks {
        let Ok(dir) = self.data_dir() else {
            return ReadMarks::new();
        };
        let stamps = bridge::read_marks_files(dir).map(|path| Stamp::of(&path));
        let cached = match &lock(&self.caches).marks {
            Some((at, marks)) if *at == stamps => Some(Arc::clone(marks)),
            _ => None,
        };
        let saved = cached.unwrap_or_else(|| {
            let marks = Arc::new(bridge::read_marks(dir));
            self.keep_cached(|c| c.marks = Some((stamps, Arc::clone(&marks))));
            marks
        });
        let mut marks = (*saved).clone();
        for (key, mark) in lock(&self.marks_unsaved).iter() {
            let take = marks
                .get(key)
                .is_none_or(|current| bridge::later_read_mark(mark, current, &|_| None));
            if take {
                marks.insert(key.clone(), mark.clone());
            }
        }
        marks
    }

    /// Forget the cached read markers: the next read loads them again.
    pub(crate) fn invalidate_read_marks(&self) {
        lock(&self.caches).marks = None;
    }

    /// The saved friend at `address` (rvn1, as API.md names friends).
    pub(crate) fn contact(&self, address: &str) -> Result<ContactView, ApiError> {
        let want = raven_core::address::from_display(address.trim());
        self.contacts()?
            .iter()
            .find(|c| c.address == want || c.address.eq_ignore_ascii_case(address.trim()))
            .cloned()
            .ok_or_else(|| {
                ApiError::of(
                    code::NOT_A_CONTACT,
                    format!("no saved friend has the address {}", safety::line(address)),
                )
            })
    }

    /// Adds an event now.
    pub(crate) fn emit(&self, kind: &str, fields: Value) {
        let fields = match fields {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        self.events.emit(kind, fields, now_ms());
    }
}

/// `app.info`.
fn app_info() -> Value {
    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        std::env::consts::OS
    };
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "build": build_kind(),
        "platform": platform,
        "api": envelope::VERSION,
    })
}

/// The message ids a friend holds as a sealed letter (the letter book this
/// node keeps, `raven node custody status`'s letters left with friends).
fn letters_held(dir: &Path) -> std::collections::HashSet<String> {
    raven_core::letter_deposits::load(dir, now_ms())
        .map(|book| {
            book.letters
                .iter()
                .filter(|l| !l.held_by.is_empty() && !l.withdraw)
                .flat_map(|l| l.message_ids.iter().map(hex::encode))
                .collect()
        })
        .unwrap_or_default()
}

/// The friends that hold a sealed copy of each queued object, by message id
/// in lower case: `outbox_routes.json`'s `custodians_held` (keys, hex, in
/// the order they took it). Only live records: once a message expires,
/// which friends held it is not kept (review FU-3).
pub(crate) fn copy_holders(dir: &Path) -> HashMap<String, Vec<String>> {
    raven_core::outbox::object_route_records(dir, now_ms())
        .map(|records| {
            records
                .into_iter()
                .filter(|(_, r)| !r.custodians_held.is_empty())
                .map(|(mid, r)| {
                    let keys = r
                        .custodians_held
                        .iter()
                        .map(|k| k.trim().to_ascii_lowercase())
                        .collect();
                    (hex::encode(mid), keys)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What runs while Lock v2 holds the profile: the lock's own ops (a change
/// of the Raven passphrase waits for the unlock), and the node's status and
/// lifecycle (the iPhone app pauses and resumes a locked node; a node that
/// starts follows its own rule: `raven-node` starts a passphrase profile
/// locked, and keeps an embedded node locked across a pause). The ops that
/// need no profile (`app.info`, `profile.state`, `events.poll`, ...) answer
/// before this is asked.
fn runs_while_locked(op: &str) -> bool {
    matches!(
        op,
        "lock.state"
            | "lock.now"
            | "lock.unlock"
            | "lock.passphrase_state"
            | "node.status"
            | "node.start"
            | "node.stop"
            | "node.pause"
            | "node.resume"
    )
}

/// An op refused while Lock v2 holds the profile.
pub(crate) fn locked_error(op: &str) -> ApiError {
    ApiError::of(
        code::PROFILE_LOCKED,
        format!("{op}: Raven is locked (Lock v2); lock.unlock opens it"),
    )
}

/// A privacy-pack action the app does not offer yet. The apps install no
/// `raven` command, so only `detail` names the CLI command that does it.
pub(crate) fn not_in_the_app(op: &str, command: &str) -> ApiError {
    ApiError::new(
        code::NOT_AVAILABLE_YET,
        "This isn't in the Raven app yet. Nothing was changed.",
        format!("{op}: not in the desktop app yet ({command})"),
    )
}

/// `release` or `dev` (debug assertions on: lab switches work there).
pub(crate) fn build_kind() -> &'static str {
    if cfg!(debug_assertions) {
        "dev"
    } else {
        "release"
    }
}

/// The identity store's refusal as an API error.
pub(crate) fn identity_error(why: &str) -> ApiError {
    let (problem, plain) = explain::explain_identity(why);
    let code = match problem {
        IdentityProblem::Keychain => code::KEYCHAIN_DENIED,
        _ => code::PROFILE_UNREADABLE,
    };
    ApiError::new(
        code,
        format!("{} {}", plain.headline, plain.next)
            .trim()
            .to_owned(),
        why,
    )
}

/// A chat history that can't be read, as an API error.
fn history_error(dir: &Path, why: &str) -> ApiError {
    if bridge::at_rest_key_missing(dir) {
        let mut e = profile::key_missing_error(dir);
        e.detail = why.to_owned();
        return e;
    }
    match bridge::classify_cause(why) {
        bridge::Cause::KeychainDenied => ApiError::of(code::KEYCHAIN_DENIED, why),
        bridge::Cause::HistoryLocked => ApiError::new(
            code::INTERNAL,
            "Another Raven program is using your messages right now. Wait a moment, then try \
             again.",
            why,
        ),
        _ => ApiError::new(
            code::PROFILE_UNREADABLE,
            "Your message history can't be read. Open Details.",
            why,
        ),
    }
}
