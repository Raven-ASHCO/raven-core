//! The desktop app's settings, each kept where the rest of Raven keeps it:
//!
//! - `desktop_settings.json` (plain, written atomically and owner-only):
//!   `receive`, `reduced_motion`, `when_quit` and `lock_on_sleep`. Nothing in
//!   it names anyone (raven-core's at-rest registry lists it as plain).
//! - The user's own name: `desktop_private.rms` (raven-core's at-rest file
//!   of kind `DesktopPrivate`), as the terminal app keeps its own in
//!   `tui_private.rms` (privacy pack PP.24): sealed under the profile's
//!   at-rest key once the profile is sealed, plain JSON before. In a sealed
//!   profile a write without the key fails; it never falls back to plain.
//!   The same file keeps, per delivered message of yours (by its history
//!   id), how it travelled and when its receipt came ([`Delivery`]): the
//!   history has no room for either, and the chats show both after a
//!   restart (E1).
//! - How long chats are kept: the privacy pack's own setting
//!   (`privacy.json` `chat_keep`, what `raven chats keep` and the terminal
//!   app set), which its retention pass enforces (PP.9).
//! - Friends' addresses unused for 30 days are always forgotten (PP.7, owner
//!   decision OD-C10 (a)): `forget_addresses` is always on and can't be
//!   turned off.
//! - `lock_on_sleep` is stored and reported; it takes effect when the apps
//!   offer Lock (`privacy.state` `available`).
//!
//! Nothing is written into a profile before its identity exists: raven-core
//! refuses to create an identity in a folder that holds files it does not
//! know (its first-install continuity check), so settings chosen during setup
//! stay in memory until `identity.create` has made the identity.
//!
//! An engine before this split kept the name, the chat-keeping time and
//! `forget_addresses` in `desktop_settings.json`: the name is moved to its
//! own file once the profile's key is loaded ([`move_name_out`]); the other
//! two are read no more.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use raven_core::at_rest::{self, Kind, Migrated};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use ash_engine::engine as bridge;

use crate::envelope::{code, ApiError, Args};
use crate::safety;

pub const FILE_NAME: &str = "desktop_settings.json";
/// The user's own name (raven-core's at-rest registry, kind `DesktopPrivate`).
pub const PRIVATE_FILE: &str = "desktop_private.rms";
/// The longest display name kept (characters).
pub const NAME_MAX_CHARS: usize = 64;

pub const WHEN_QUIT: [&str; 3] = ["keep", "stop_if_started", "ask"];
pub const KEEP_CHATS_DAYS: [u64; 3] = [7, 30, 90];

/// API.md's `Settings`. Defaults are the apps' (the mock's) defaults. Read
/// from `desktop_settings.json` (an older engine's file has every field);
/// written there only as [`Stored`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub display_name: Option<String>,
    /// Receive messages on this computer: a node the app starts listens on
    /// the network; otherwise on this computer only.
    pub receive: bool,
    pub reduced_motion: bool,
    pub when_quit: String,
    /// None keeps chats forever.
    pub keep_chats_days: Option<u64>,
    pub forget_addresses: bool,
    pub lock_on_sleep: bool,
}

/// What `desktop_settings.json` holds: the settings that name nobody.
#[derive(Debug, Serialize)]
struct Stored<'a> {
    receive: bool,
    reduced_motion: bool,
    when_quit: &'a str,
    lock_on_sleep: bool,
}

/// What `desktop_private.rms` holds.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Private {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    /// Delivered messages of yours, by history id (an older engine ignores
    /// it, and drops it the next time it saves the name).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    delivered: BTreeMap<String, Delivery>,
}

/// How one delivered message of yours travelled and when its receipt came,
/// as the engine saw them (E1: the path chips of older messages were gone
/// after a restart, and a message that waited an hour said only
/// "Delivered").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    /// API.md's `path_kind`, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_kind: Option<String>,
    /// When the engine saw its receipt, when it did (Raven's clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_ms: Option<u64>,
}

/// Delivered messages kept at most (those whose receipt came first go).
pub const DELIVERED_MAX: usize = 2000;

impl Default for Settings {
    fn default() -> Self {
        Settings {
            display_name: None,
            receive: true,
            reduced_motion: false,
            when_quit: "keep".into(),
            keep_chats_days: Some(30),
            forget_addresses: true,
            lock_on_sleep: false,
        }
    }
}

/// What a read of the file found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    /// No file yet: the defaults.
    Missing,
    Read(Settings),
    /// The file is there but can't be read: the defaults, and the file is
    /// left as it is until the user changes a setting.
    Unreadable(String),
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

pub fn load(data_dir: &Path) -> Loaded {
    match std::fs::read(path(data_dir)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded::Missing,
        Err(e) => Loaded::Unreadable(e.to_string()),
        Ok(bytes) if bytes.len() > 64 * 1024 => Loaded::Unreadable("file too large".into()),
        Ok(bytes) => match serde_json::from_slice::<Settings>(&bytes) {
            Ok(s) => Loaded::Read(s.normalized()),
            Err(e) => Loaded::Unreadable(e.to_string()),
        },
    }
}

/// Writes the settings that name nobody to `desktop_settings.json` (atomic,
/// 0600): never the name, the chat-keeping time or `forget_addresses`.
/// Only once the identity exists (see the module docs): the caller checks.
pub fn save(data_dir: &Path, settings: &Settings) -> Result<(), String> {
    let stored = Stored {
        receive: settings.receive,
        reduced_motion: settings.reduced_motion,
        when_quit: &settings.when_quit,
        lock_on_sleep: settings.lock_on_sleep,
    };
    let raw = serde_json::to_vec_pretty(&stored).map_err(|e| e.to_string())?;
    raven_core::atomic_write_private(&path(data_dir), &raw)
}

/// `desktop_hidden.json`: the ids of ended messages
/// of yours the person deleted in a desktop app (`messages.delete`), or
/// replaced with Send again. Ids only (random numbers that name nobody);
/// plain, atomic, owner-only. The terminal app reads it too and leaves them
/// out of its chats (ash's tui/hidden.rs holds the file's code, so both apps
/// read it alike). The deleted messages' ids (none when the file is missing
/// or unreadable).
pub fn load_hidden(data_dir: &Path) -> Vec<String> {
    bridge::load_hidden(data_dir)
}

/// Writes the deleted messages' ids, the newest 2000 of them.
pub fn save_hidden(data_dir: &Path, ids: &[String]) -> Result<(), String> {
    bridge::save_hidden(data_dir, ids)
}

pub fn private_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PRIVATE_FILE)
}

/// The user's own name from [`PRIVATE_FILE`] (raven-core's
/// `at_rest::load_json`: RMS1 opened with the key this process loaded, or
/// plain JSON). `Ok(None)`: no file, or no name in it. `Err`: it is there
/// but can't be read now (a sealed one without its key, a changed byte).
pub fn load_name(data_dir: &Path) -> Result<Option<String>, String> {
    let path = private_path(data_dir);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => {}
        // A FIFO or a device here would block the read.
        Ok(_) => return Err(format!("{PRIVATE_FILE} is not a regular file")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    at_rest::load_json::<Private>(data_dir, &path, Kind::DesktopPrivate)
        .map(|private| private.and_then(|p| p.display_name.as_deref().and_then(clean_name)))
        .map_err(|e| e.to_string())
}

/// Writes the user's own name to [`PRIVATE_FILE`] under its writer lock
/// (raven-core's `at_rest::lock_file`), keeping the deliveries it holds:
/// sealed in a sealed profile, where it fails without the key; plain JSON
/// otherwise. None with no file there writes nothing. A file that can't be
/// read is written anew with the name alone, as before deliveries were kept.
pub fn save_name(data_dir: &Path, name: Option<&str>) -> Result<(), String> {
    let path = private_path(data_dir);
    if name.is_none() && std::fs::symlink_metadata(&path).is_err() {
        return Ok(());
    }
    let lock =
        at_rest::lock_file(data_dir, &path, Kind::DesktopPrivate).map_err(|e| e.to_string())?;
    let mut private = match std::fs::symlink_metadata(&path) {
        Ok(_) => lock
            .load_json::<Private>()
            .ok()
            .flatten()
            .unwrap_or_default(),
        Err(_) => Private::default(),
    };
    private.version = 1;
    private.display_name = name.map(str::to_owned);
    lock.store_json(&private).map_err(|e| e.to_string())
}

/// The deliveries [`PRIVATE_FILE`] keeps, by history id: none without the
/// file; `Err` when it is there but can't be read now (a sealed one without
/// its key, a changed byte).
pub fn load_deliveries(data_dir: &Path) -> Result<HashMap<String, Delivery>, String> {
    let path = private_path(data_dir);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Err(format!("{PRIVATE_FILE} is not a regular file")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e.to_string()),
    }
    at_rest::load_json::<Private>(data_dir, &path, Kind::DesktopPrivate)
        .map(|private| {
            private
                .map(|p| p.delivered.into_iter().collect())
                .unwrap_or_default()
        })
        .map_err(|e| e.to_string())
}

/// Writes `deliveries` into [`PRIVATE_FILE`] under its writer lock, keeping
/// the name: only those whose history row is still there (`kept`: the
/// chat-keeping time deletes rows, and their records go with them), at most
/// [`DELIVERED_MAX`]. A file that can't be read is left as it is (`Err`).
pub fn save_deliveries(
    data_dir: &Path,
    deliveries: &HashMap<String, Delivery>,
    kept: &dyn Fn(&str) -> bool,
) -> Result<(), String> {
    let path = private_path(data_dir);
    let lock =
        at_rest::lock_file(data_dir, &path, Kind::DesktopPrivate).map_err(|e| e.to_string())?;
    let mut private = match std::fs::symlink_metadata(&path) {
        Ok(_) => lock
            .load_json::<Private>()
            .map_err(|e| e.to_string())?
            .unwrap_or_default(),
        Err(_) => Private::default(),
    };
    let mut list: Vec<(&String, &Delivery)> =
        deliveries.iter().filter(|(id, _)| kept(id)).collect();
    // The newest receipts stay (one without a time counts as oldest).
    list.sort_by_key(|(id, d)| (std::cmp::Reverse(d.at_ms.unwrap_or(0)), (*id).clone()));
    list.truncate(DELIVERED_MAX);
    private.version = 1;
    private.delivered = list
        .into_iter()
        .map(|(id, d)| (id.clone(), d.clone()))
        .collect();
    lock.store_json(&private).map_err(|e| e.to_string())
}

/// A name an older engine kept in `desktop_settings.json` moves to
/// [`PRIVATE_FILE`] (unless that one has a name already), then leaves the
/// plain file, which is written again without it. Whether it moved. In a
/// sealed profile whose key is not loaded nothing changes (the name would
/// otherwise be lost or written in plain).
pub fn move_name_out(data_dir: &Path) -> Result<bool, String> {
    let Loaded::Read(old) = load(data_dir) else {
        return Ok(false);
    };
    let raw = std::fs::read(path(data_dir)).map_err(|e| e.to_string())?;
    let legacy = serde_json::from_slice::<Map<String, Value>>(&raw)
        .ok()
        .is_some_and(|map| {
            ["display_name", "keep_chats_days", "forget_addresses"]
                .iter()
                .any(|key| map.contains_key(*key))
        });
    if !legacy {
        return Ok(false);
    }
    if let Some(name) = old.display_name.as_deref() {
        if load_name(data_dir)?.is_none() {
            save_name(data_dir, Some(name))?;
        }
    }
    save(data_dir, &old)?;
    Ok(true)
}

/// A sealed profile's [`PRIVATE_FILE`] still in plain JSON (written before
/// the profile was sealed, or by `raven privacy unseal`) is sealed in place
/// with the key this process loaded (raven-core's `at_rest::migrate_file`;
/// as the terminal app does with `tui_private.rms`, review D-lock-tui-1).
/// Whether it was. Nothing (no lock taken) when the profile is not sealed
/// or there is no file.
pub fn seal_private_in_place(data_dir: &Path) -> Result<bool, String> {
    if raven_core::privacy::mode(data_dir) != at_rest::Mode::Sealed
        || std::fs::symlink_metadata(private_path(data_dir)).is_err()
    {
        return Ok(false);
    }
    match at_rest::migrate_file(data_dir, &private_path(data_dir), Kind::DesktopPrivate) {
        Ok(Migrated::Sealed) => Ok(true),
        Ok(_) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

/// The privacy pack's chat-keeping setting for `days` (None: always).
pub fn chat_keep_of(days: Option<u64>) -> raven_core::privacy::ChatKeep {
    use raven_core::privacy::ChatKeep;
    match days {
        Some(7) => ChatKeep::Days7,
        Some(90) => ChatKeep::Days90,
        None => ChatKeep::Always,
        Some(_) => ChatKeep::Days30,
    }
}

impl Settings {
    /// Values outside the contract are put back to the defaults (a file
    /// edited by hand must not reach the app as something it can't show).
    fn normalized(mut self) -> Settings {
        let defaults = Settings::default();
        if !WHEN_QUIT.contains(&self.when_quit.as_str()) {
            self.when_quit = defaults.when_quit;
        }
        if self
            .keep_chats_days
            .is_some_and(|d| !KEEP_CHATS_DAYS.contains(&d))
        {
            self.keep_chats_days = defaults.keep_chats_days;
        }
        self.display_name = self.display_name.as_deref().and_then(clean_name);
        self
    }

    /// API.md's JSON form.
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        if let Some(name) = &self.display_name {
            map.insert("display_name".into(), name.clone().into());
        }
        map.insert("receive".into(), self.receive.into());
        map.insert("reduced_motion".into(), self.reduced_motion.into());
        map.insert("when_quit".into(), self.when_quit.clone().into());
        map.insert(
            "keep_chats_days".into(),
            self.keep_chats_days.map_or(Value::Null, Value::from),
        );
        map.insert("forget_addresses".into(), self.forget_addresses.into());
        map.insert("lock_on_sleep".into(), self.lock_on_sleep.into());
        Value::Object(map)
    }

    /// `settings.set`'s partial update; every field is checked before any is
    /// changed. Unknown fields are ignored.
    pub fn apply(&self, args: &Args) -> Result<Settings, ApiError> {
        let mut next = self.clone();
        if args.has("display_name") {
            next.display_name = args.opt_str("display_name")?.and_then(clean_name);
        }
        if let Some(v) = args.opt_bool("receive")? {
            next.receive = v;
        }
        if let Some(v) = args.opt_bool("reduced_motion")? {
            next.reduced_motion = v;
        }
        if let Some(v) = args.opt_str("when_quit")? {
            if !WHEN_QUIT.contains(&v) {
                return Err(ApiError::bad_request(format!(
                    "when_quit must be one of {WHEN_QUIT:?}"
                )));
            }
            next.when_quit = v.to_owned();
        }
        if args.has("keep_chats_days") {
            next.keep_chats_days = match args.get("keep_chats_days") {
                Some(Value::Null) => None,
                _ => {
                    let days = args.opt_u64("keep_chats_days")?;
                    match days {
                        Some(d) if KEEP_CHATS_DAYS.contains(&d) => Some(d),
                        _ => {
                            return Err(ApiError::bad_request(
                                "keep_chats_days must be 7, 30, 90 or null",
                            ))
                        }
                    }
                }
            };
        }
        if let Some(v) = args.opt_bool("forget_addresses")? {
            // The privacy pack always forgets them (PP.7); no switch.
            if !v {
                return Err(ApiError::new(
                    code::NOT_AVAILABLE_YET,
                    "Raven always forgets a friend's address after 30 days without contact, \
                     and that can't be turned off. Nothing was changed.",
                    "forget_addresses is always on (privacy pack PP.7, OD-C10)",
                ));
            }
            next.forget_addresses = true;
        }
        if let Some(v) = args.opt_bool("lock_on_sleep")? {
            next.lock_on_sleep = v;
        }
        Ok(next)
    }
}

/// A display name as kept: one sanitised line, at most [`NAME_MAX_CHARS`]
/// characters; None when nothing is left.
pub fn clean_name(raw: &str) -> Option<String> {
    let clean: String = safety::line(raw).chars().take(NAME_MAX_CHARS).collect();
    let clean = clean.trim().to_owned();
    (!clean.is_empty()).then_some(clean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn partial_updates_are_checked_first() {
        let s = Settings::default();
        let next = s
            .apply(&Args(&args(json!({
                "display_name": " Studio\u{202E} ", "receive": false, "when_quit": "ask",
                "keep_chats_days": null, "unknown": 1
            }))))
            .unwrap();
        assert_eq!(next.display_name.as_deref(), Some("Studio"));
        assert!(!next.receive);
        assert_eq!(next.when_quit, "ask");
        assert_eq!(next.keep_chats_days, None);
        for bad in [
            json!({"when_quit": "never"}),
            json!({"keep_chats_days": 31}),
            json!({"keep_chats_days": "30"}),
            json!({"receive": "yes"}),
            json!({"display_name": 5}),
        ] {
            assert!(s.apply(&Args(&args(bad.clone()))).is_err(), "{bad}");
        }
        let cleared = next
            .apply(&Args(&args(json!({"display_name": "   "}))))
            .unwrap();
        assert_eq!(cleared.display_name, None);
    }

    #[test]
    fn forget_addresses_cannot_be_turned_off() {
        let s = Settings::default();
        let off = s
            .apply(&Args(&args(json!({"forget_addresses": false}))))
            .unwrap_err();
        assert_eq!(off.code, code::NOT_AVAILABLE_YET);
        assert!(
            s.apply(&Args(&args(json!({"forget_addresses": true}))))
                .unwrap()
                .forget_addresses
        );
        assert_eq!(chat_keep_of(None), raven_core::privacy::ChatKeep::Always);
        assert_eq!(chat_keep_of(Some(7)), raven_core::privacy::ChatKeep::Days7);
        assert_eq!(
            chat_keep_of(Some(30)),
            raven_core::privacy::ChatKeep::Days30
        );
        assert_eq!(
            chat_keep_of(Some(90)),
            raven_core::privacy::ChatKeep::Days90
        );
    }

    #[test]
    fn the_file_round_trips_and_a_bad_one_reads_as_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()), Loaded::Missing);
        let s = Settings {
            display_name: Some("Studio".into()),
            receive: false,
            keep_chats_days: Some(7),
            ..Settings::default()
        };
        save(dir.path(), &s).unwrap();
        // Only what names nobody is in the file.
        let raw = std::fs::read_to_string(path(dir.path())).unwrap();
        assert!(
            !raw.contains("Studio") && !raw.contains("keep_chats_days"),
            "{raw}"
        );
        let back = Settings {
            display_name: None,
            keep_chats_days: Settings::default().keep_chats_days,
            ..s.clone()
        };
        assert_eq!(load(dir.path()), Loaded::Read(back));
        std::fs::write(path(dir.path()), b"{not json").unwrap();
        assert!(matches!(load(dir.path()), Loaded::Unreadable(_)));
        let hand_edited = br#"{"when_quit":"later","keep_chats_days":5}"#;
        std::fs::write(path(dir.path()), hand_edited).unwrap();
        assert_eq!(load(dir.path()), Loaded::Read(Settings::default()));
        assert_eq!(s.to_json()["keep_chats_days"], 7);
        assert_eq!(s.to_json()["display_name"], "Studio");
    }

    /// E1: how a delivered message travelled and when its receipt came stay
    /// after a restart, beside the name (each save keeps the other), only
    /// for rows the history still has.
    #[test]
    fn deliveries_are_kept_beside_the_name() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert_eq!(load_deliveries(d), Ok(HashMap::new()));
        save_name(d, Some("Studio")).unwrap();
        let lan = Delivery {
            path_kind: Some("lan".into()),
            at_ms: Some(5),
        };
        let gone = Delivery {
            path_kind: Some("p2p".into()),
            at_ms: None,
        };
        let all = HashMap::from([("aa".to_owned(), lan.clone()), ("bb".to_owned(), gone)]);
        save_deliveries(d, &all, &|id| id == "aa").unwrap();
        assert_eq!(load_name(d), Ok(Some("Studio".into())));
        assert_eq!(
            load_deliveries(d),
            Ok(HashMap::from([("aa".to_owned(), lan.clone())]))
        );
        save_name(d, Some("Desk")).unwrap();
        assert_eq!(load_deliveries(d).unwrap().len(), 1);
        assert_eq!(load_name(d), Ok(Some("Desk".into())));
        // The newest receipts stay.
        let many: HashMap<String, Delivery> = (0..DELIVERED_MAX as u64 + 3)
            .map(|i| {
                (
                    format!("{i:032x}"),
                    Delivery {
                        path_kind: None,
                        at_ms: Some(i),
                    },
                )
            })
            .collect();
        save_deliveries(d, &many, &|_| true).unwrap();
        let kept = load_deliveries(d).unwrap();
        assert_eq!(kept.len(), DELIVERED_MAX);
        assert!(!kept.contains_key(&format!("{:032x}", 2)));
        assert!(kept.contains_key(&format!("{:032x}", 3)));
        // A file that can't be read is never written over by a delivery.
        std::fs::write(private_path(d), b"{not json").unwrap();
        assert!(load_deliveries(d).is_err());
        assert!(save_deliveries(d, &all, &|_| true).is_err());
        assert_eq!(std::fs::read(private_path(d)).unwrap(), b"{not json");
    }
}
