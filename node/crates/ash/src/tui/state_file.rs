//! The app's own settings and read markers: `<data_dir>/tui_state.json`, and
//! in a sealed profile `<data_dir>/tui_private.rms` (privacy pack PP.24).
//!
//! - [`peek`] is a plain read for the gate and the start-up checks: any
//!   problem gives the defaults, it never writes, and it reads tui_state.json
//!   only (never the sealed file, so never anything that needs a key).
//! - [`load`] adds what a sealed profile keeps in tui_private.rms: the read
//!   markers and the user's own name ([`TuiPrivate`], at_rest kind 10, sealed
//!   under the profile's at-rest keys through bridge.rs). Every other setting
//!   stays in tui_state.json, which the gate reads on every start, before the
//!   identity is open. A profile that is not sealed keeps everything in
//!   tui_state.json exactly as before.
//! - [`TuiState::save`] needs an [`IdentityReady`], so nothing lands in the
//!   profile before its identity does: raven-core refuses to create an
//!   identity over files it does not know (identity_store.rs:280-309,
//!   375-437). In a sealed profile it writes tui_private.rms first, then
//!   tui_state.json without the two fields, so a crash between the two leaves
//!   both readable and no read marker lost.
//! - The read markers are the desktop engine's too (read_marks.rs): every
//!   save takes their lock, reads the files again and keeps a marker saved
//!   meanwhile where it is later than this app's ([`update_marks`] is the
//!   engine's way in).
//! - A file that cannot be read or parsed gives the defaults and is left as it
//!   is until the user changes a setting ([`LoadNote::Unreadable`]); a
//!   tui_private.rms that cannot be opened (the key unavailable, a changed
//!   byte) gives no read markers and no name, under the same rule.
//! - [`move_private_now`] (review D-lock-tui-1) moves what a sealed profile's
//!   tui_state.json still holds of the two (an older app wrote it, or the app
//!   saved it before the profile was sealed) into tui_private.rms at the top
//!   of every command and the app's start, so it no longer waits for the app
//!   to save; it seals a tui_private.rms `raven privacy unseal` left in plain
//!   too. [`private_files_in_plain`] names what is still left for
//!   `raven privacy status`.
//!
//! Every field has a default, and unknown fields are ignored, so files written
//! by older and newer versions of the app still load. An older app reading a
//! sealed profile's tui_state.json shows every message as unread and no name.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};

use super::bridge::{self, TuiPrivateRead};
use super::controller::IdentityReady;
#[cfg(test)]
use super::controller::{self, Controller, IdentityState};
use super::read_marks::{self, ReadAt};
#[cfg(test)]
use super::testkit;

/// The file's name inside the data directory.
pub(super) const FILE_NAME: &str = "tui_state.json";
/// The format [`TuiState::save`] writes.
const STATE_VERSION: u32 = 1;
/// The format of tui_private.rms's JSON.
const PRIVATE_VERSION: u32 = 1;
/// Larger files are not read: the gate reads this file on every start.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// Settings: Motion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum MotionSetting {
    /// Follow the terminal (theme::default_motion).
    #[default]
    Auto,
    Full,
    Reduced,
}

/// Settings: Colors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ColorSetting {
    /// Colour, unless NO_COLOR is set.
    #[default]
    Auto,
    NoColors,
}

/// Settings: Colors' palette, while colours are on. A field of its own
/// (`palette`, omitted while Automatic), so an older app, which knows only
/// `colors`' two values, still reads every file this one writes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PaletteSetting {
    /// The palette for the background the terminal says it has, else the
    /// terminal's own colours (theme::Theme::for_setting).
    #[default]
    Auto,
    Dark,
    Light,
}

impl PaletteSetting {
    fn is_auto(&self) -> bool {
        *self == PaletteSetting::Auto
    }
}

/// Settings: Colors as its row offers it: Automatic, Dark, Light or No
/// colors, kept as `colors` and `palette`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ColorChoice {
    Auto,
    Dark,
    Light,
    NoColors,
}

impl ColorChoice {
    /// Settings' values, in their order.
    pub(super) const ALL: [ColorChoice; 4] = [
        ColorChoice::Auto,
        ColorChoice::Dark,
        ColorChoice::Light,
        ColorChoice::NoColors,
    ];

    /// The choice `state` holds.
    pub(super) fn of(state: &TuiState) -> ColorChoice {
        match (state.colors, state.palette) {
            (ColorSetting::NoColors, _) => ColorChoice::NoColors,
            (ColorSetting::Auto, PaletteSetting::Auto) => ColorChoice::Auto,
            (ColorSetting::Auto, PaletteSetting::Dark) => ColorChoice::Dark,
            (ColorSetting::Auto, PaletteSetting::Light) => ColorChoice::Light,
        }
    }

    /// `state` with this choice: No colors keeps the palette chosen, for
    /// when colours come back.
    pub(super) fn apply(self, state: &mut TuiState) {
        let (colors, palette) = match self {
            ColorChoice::Auto => (ColorSetting::Auto, PaletteSetting::Auto),
            ColorChoice::Dark => (ColorSetting::Auto, PaletteSetting::Dark),
            ColorChoice::Light => (ColorSetting::Auto, PaletteSetting::Light),
            ColorChoice::NoColors => (ColorSetting::NoColors, state.palette),
        };
        state.colors = colors;
        state.palette = palette;
    }
}

/// Settings: Symbols.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SymbolSetting {
    /// Follow the terminal (theme::auto_symbols).
    #[default]
    Auto,
    Ascii,
    Simple,
    Fancy,
}

/// Settings: When I quit (OD-2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OnQuit {
    /// Keep Raven running (recommended): friends can reach you and the outbox
    /// keeps retrying.
    #[default]
    KeepRunning,
    /// Stop Raven if this app started it.
    StopIfStarted,
    /// Ask me.
    Ask,
}

/// Settings: Receive messages on this computer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Receive {
    /// Not asked yet: the receive question comes before the first start.
    #[default]
    Unset,
    On,
    /// The node this app starts listens on this computer only.
    Off,
}

impl SymbolSetting {
    /// Settings' values, in their order.
    pub(super) const ALL: [SymbolSetting; 4] = [
        SymbolSetting::Auto,
        SymbolSetting::Ascii,
        SymbolSetting::Simple,
        SymbolSetting::Fancy,
    ];
}

impl OnQuit {
    /// Settings' values, in their order.
    pub(super) const ALL: [OnQuit; 3] = [OnQuit::KeepRunning, OnQuit::StopIfStarted, OnQuit::Ask];
}

/// The value after `current` in `values` (Right and Enter in Settings), or
/// before it (Left), round and round. A value not listed goes to the first.
pub(super) fn step<T: Copy + PartialEq>(values: &[T], current: T, forward: bool) -> T {
    let Some(at) = values.iter().position(|v| *v == current) else {
        return values[0];
    };
    let len = values.len();
    let next = if forward {
        (at + 1) % len
    } else {
        (at + len - 1) % len
    };
    values[next]
}

/// Everything in tui_state.json. A missing field takes its value from
/// [`TuiState::default`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct TuiState {
    /// The format this was read in; [`TuiState::save`] always writes
    /// [`STATE_VERSION`].
    pub(super) version: u32,
    /// The user's own name, shown only on this computer and never sent
    /// (OD-10). Empty when not given.
    pub(super) display_name: String,
    pub(super) motion: MotionSetting,
    pub(super) colors: ColorSetting,
    /// Colors' palette ([`PaletteSetting`]); omitted while Automatic.
    #[serde(skip_serializing_if = "PaletteSetting::is_auto")]
    pub(super) palette: PaletteSetting,
    pub(super) symbols: SymbolSetting,
    pub(super) on_quit: OnQuit,
    pub(super) receive: Receive,
    /// Share my network address in my invite (OD-5: on).
    pub(super) include_lan_in_card: bool,
    /// Show technical details.
    pub(super) show_details: bool,
    /// Always open the classic menu: read by the gate at the next start.
    pub(super) always_classic: bool,
    /// The firewall note is shown once per profile.
    pub(super) firewall_note_shown: bool,
    /// The honest notes (UXF.9), each shown once per profile: what people
    /// on the network can see once Raven receives there (NOTE), what whoever
    /// runs a hotspot can see (MEET's step 2a), that friends' names stay on
    /// this computer (AF-2), that someone who gets this laptop can read the
    /// chats (the exit line after quitting with receiving on), and that
    /// COPY's invite stays in the terminal's scrollback.
    pub(super) network_note_shown: bool,
    pub(super) hotspot_note_shown: bool,
    pub(super) names_note_shown: bool,
    pub(super) exit_note_shown: bool,
    pub(super) copy_note_shown: bool,
    /// Per friend (`pub_hex`), the id of the last message read. Local only:
    /// no read receipt is ever sent. The desktop engine reads and writes it
    /// too (read_marks.rs).
    pub(super) last_read: BTreeMap<String, String>,
    /// Per friend, the time of the message [`TuiState::last_read`] names
    /// (read_marks.rs), so either app can tell the later of two markers;
    /// omitted from the file while empty.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) last_read_at: BTreeMap<String, ReadAt>,
    /// Lock now v2 (P6.40): lock Raven after this app had no key for these
    /// minutes (0: never, the default; omitted from the file then).
    #[serde(skip_serializing_if = "is_zero")]
    pub(super) idle_lock_minutes: u16,
}

fn is_zero(minutes: &u16) -> bool {
    *minutes == 0
}

impl Default for TuiState {
    fn default() -> TuiState {
        TuiState {
            version: STATE_VERSION,
            display_name: String::new(),
            motion: MotionSetting::default(),
            colors: ColorSetting::default(),
            palette: PaletteSetting::default(),
            symbols: SymbolSetting::default(),
            on_quit: OnQuit::default(),
            receive: Receive::default(),
            include_lan_in_card: true,
            show_details: false,
            always_classic: false,
            firewall_note_shown: false,
            network_note_shown: false,
            hotspot_note_shown: false,
            names_note_shown: false,
            exit_note_shown: false,
            copy_note_shown: false,
            last_read: BTreeMap::new(),
            last_read_at: BTreeMap::new(),
            idle_lock_minutes: 0,
        }
    }
}

/// What a sealed profile keeps in tui_private.rms instead of tui_state.json:
/// the read markers name friends' keys, and the name is the user's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct TuiPrivate {
    /// The format this was read in; a save always writes [`PRIVATE_VERSION`].
    pub(super) version: u32,
    /// [`TuiState::display_name`].
    pub(super) display_name: String,
    /// [`TuiState::last_read`].
    pub(super) last_read: BTreeMap<String, String>,
    /// [`TuiState::last_read_at`].
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) last_read_at: BTreeMap<String, ReadAt>,
}

impl Default for TuiPrivate {
    fn default() -> TuiPrivate {
        TuiPrivate {
            version: PRIVATE_VERSION,
            display_name: String::new(),
            last_read: BTreeMap::new(),
            last_read_at: BTreeMap::new(),
        }
    }
}

impl TuiPrivate {
    fn of(state: &TuiState) -> TuiPrivate {
        TuiPrivate {
            version: PRIVATE_VERSION,
            display_name: state.display_name.clone(),
            last_read: state.last_read.clone(),
            last_read_at: state.last_read_at.clone(),
        }
    }
}

/// tui_state.json in a sealed profile: every setting but the read markers
/// and the name, in [`TuiState`]'s order.
#[derive(Serialize)]
struct PlainSettings {
    version: u32,
    motion: MotionSetting,
    colors: ColorSetting,
    #[serde(skip_serializing_if = "PaletteSetting::is_auto")]
    palette: PaletteSetting,
    symbols: SymbolSetting,
    on_quit: OnQuit,
    receive: Receive,
    include_lan_in_card: bool,
    show_details: bool,
    always_classic: bool,
    firewall_note_shown: bool,
    network_note_shown: bool,
    hotspot_note_shown: bool,
    names_note_shown: bool,
    exit_note_shown: bool,
    copy_note_shown: bool,
    #[serde(skip_serializing_if = "is_zero")]
    idle_lock_minutes: u16,
}

impl PlainSettings {
    fn of(state: &TuiState) -> PlainSettings {
        // Every field named: a new setting fails to compile here until it is
        // placed in one file or the other.
        let TuiState {
            version,
            display_name: _,
            motion,
            colors,
            palette,
            symbols,
            on_quit,
            receive,
            include_lan_in_card,
            show_details,
            always_classic,
            firewall_note_shown,
            network_note_shown,
            hotspot_note_shown,
            names_note_shown,
            exit_note_shown,
            copy_note_shown,
            last_read: _,
            last_read_at: _,
            idle_lock_minutes,
        } = state;
        PlainSettings {
            version: *version,
            motion: *motion,
            colors: *colors,
            palette: *palette,
            symbols: *symbols,
            on_quit: *on_quit,
            receive: *receive,
            include_lan_in_card: *include_lan_in_card,
            show_details: *show_details,
            always_classic: *always_classic,
            firewall_note_shown: *firewall_note_shown,
            network_note_shown: *network_note_shown,
            hotspot_note_shown: *hotspot_note_shown,
            names_note_shown: *names_note_shown,
            exit_note_shown: *exit_note_shown,
            copy_note_shown: *copy_note_shown,
            idle_lock_minutes: *idle_lock_minutes,
        }
    }
}

/// Whether tui_state.json itself holds the read markers or the name: it was
/// written in a profile that is not sealed (or by an older app, or before
/// this profile's first save after it was sealed).
#[derive(Default, Deserialize)]
#[serde(default)]
struct PrivateFields {
    display_name: Option<IgnoredAny>,
    last_read: Option<IgnoredAny>,
    last_read_at: Option<IgnoredAny>,
}

/// Where a sealed profile keeps [`TuiPrivate`]: bridge.rs's tui_private.rms
/// ([`ProfileFile`]), or a test's fake.
pub(super) trait PrivateFile {
    /// Whether the profile is sealed: the read markers and the name are
    /// saved to the sealed file then, and never to tui_state.json.
    fn sealed(&self, data_dir: &Path) -> bool;
    fn load(&self, data_dir: &Path) -> TuiPrivateRead;
    fn store(&self, data_dir: &Path, private: &TuiPrivate) -> Result<(), String>;
    /// Deletes it, when there is one: a profile that is not sealed (any
    /// more) keeps both in tui_state.json again.
    fn remove(&self, data_dir: &Path) -> Result<(), String>;
}

/// The profile's own tui_private.rms (raven-core's at-rest files, through
/// bridge.rs).
pub(super) struct ProfileFile;

impl PrivateFile for ProfileFile {
    fn sealed(&self, data_dir: &Path) -> bool {
        bridge::tui_private_sealed(data_dir)
    }

    fn load(&self, data_dir: &Path) -> TuiPrivateRead {
        bridge::load_tui_private(data_dir)
    }

    fn store(&self, data_dir: &Path, private: &TuiPrivate) -> Result<(), String> {
        bridge::store_tui_private(data_dir, private)
    }

    fn remove(&self, data_dir: &Path) -> Result<(), String> {
        bridge::remove_tui_private(data_dir)
    }
}

/// How [`load`] went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LoadNote {
    /// No file yet: the defaults.
    Missing,
    Loaded,
    /// The file is there but could not be read or parsed (the reason, for
    /// Details): the defaults are in use. Make no automatic save (read
    /// markers, the notes shown once) until the user changes a setting, so a
    /// file the user can still repair is not overwritten behind their back.
    Unreadable(String),
}

/// `<data_dir>/tui_state.json`.
pub(super) fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// The saved settings in tui_state.json, or the defaults on any problem.
/// Only reads: never creates the file or the data directory, and never reads
/// tui_private.rms (in a sealed profile: no read markers and no name).
pub(super) fn peek(data_dir: &Path) -> TuiState {
    read_plain(data_dir).0
}

/// The saved state and how reading it went: tui_state.json, with the read
/// markers and the name from tui_private.rms where the profile keeps them
/// there. Only reads, like [`peek`]; the sealed file opens with the keys this
/// process loaded at its start, with no keystore call.
pub(super) fn load(data_dir: &Path) -> (TuiState, LoadNote) {
    load_with(data_dir, &ProfileFile)
}

/// [`load`] with `file` for tui_private.rms. In a sealed profile the sealed
/// file wins once it is there (until then tui_state.json still holds both,
/// as an older app or a plain profile wrote them); in one that is not
/// sealed, tui_state.json's own fields win, and the sealed file (`raven
/// privacy unseal` writes it back in plain) is read only when they are
/// missing.
fn load_with(data_dir: &Path, file: &dyn PrivateFile) -> (TuiState, LoadNote) {
    let (mut state, mut note, holds_private) = read_plain(data_dir);
    let sealed = file.sealed(data_dir);
    if !sealed && holds_private {
        return (state, note);
    }
    match file.load(data_dir) {
        TuiPrivateRead::Missing => {}
        TuiPrivateRead::Loaded(private) => {
            state.display_name = private.display_name;
            state.last_read = private.last_read;
            state.last_read_at = private.last_read_at;
        }
        TuiPrivateRead::Unreadable(why) => {
            state.display_name.clear();
            state.last_read.clear();
            state.last_read_at.clear();
            if !matches!(note, LoadNote::Unreadable(_)) {
                let path = data_dir.join(bridge::TUI_PRIVATE_FILE);
                note = LoadNote::Unreadable(format!("{}: {why}", path.display()));
            }
        }
    }
    (state, note)
}

/// tui_state.json alone, how reading it went, and whether it holds the read
/// markers or the name itself.
fn read_plain(data_dir: &Path) -> (TuiState, LoadNote, bool) {
    let path = path(data_dir);
    match read_state(&path) {
        Ok(Some((state, holds_private))) => (state, LoadNote::Loaded, holds_private),
        Ok(None) => (TuiState::default(), LoadNote::Missing, false),
        Err(why) => (
            TuiState::default(),
            LoadNote::Unreadable(format!("{}: {why}", path.display())),
            false,
        ),
    }
}

/// The parsed file and whether it holds the read markers or the name, None
/// when there is none.
fn read_state(path: &Path) -> Result<Option<(TuiState, bool)>, String> {
    let Some(bytes) = read_bytes(path)? else {
        return Ok(None);
    };
    let state: TuiState = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let fields: PrivateFields = serde_json::from_slice(&bytes).unwrap_or_default();
    Ok(Some((
        state,
        fields.display_name.is_some()
            || fields.last_read.is_some()
            || fields.last_read_at.is_some(),
    )))
}

/// The file's bytes ([`MAX_FILE_BYTES`] at most, a regular file only), None
/// when there is none.
fn read_bytes(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    // A FIFO or device here would block the gate on its read.
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("larger than {MAX_FILE_BYTES} bytes"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(format!("larger than {MAX_FILE_BYTES} bytes"));
    }
    Ok(Some(bytes))
}

// ── The move at the top of every command (review D-lock-tui-1) ──────────────

/// What tui_state.json still holds of [`TuiPrivate`]: the read markers and
/// the name (not both empty), and the file's other fields as they are,
/// unknown ones too.
struct PlainPrivate {
    private: TuiPrivate,
    rest: serde_json::Map<String, serde_json::Value>,
}

/// tui_state.json's read markers and name, when it holds any: an older app
/// wrote it, or the app saved it while the profile was not sealed. None for
/// a missing file, one that can't be read or parsed (left as it is, as
/// [`load`] leaves it), and one whose two fields are absent or empty.
fn plain_private(data_dir: &Path) -> Option<PlainPrivate> {
    let bytes = read_bytes(&path(data_dir)).ok()??;
    let state: TuiState = serde_json::from_slice(&bytes).ok()?;
    if state.display_name.is_empty() && state.last_read.is_empty() && state.last_read_at.is_empty()
    {
        return None;
    }
    let mut rest: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&bytes).ok()?;
    rest.remove("display_name");
    rest.remove("last_read");
    rest.remove("last_read_at");
    Some(PlainPrivate {
        private: TuiPrivate::of(&state),
        rest,
    })
}

/// Review D-lock-tui-1: a sealed profile's tui_state.json kept the read
/// markers (friends' keys) and the user's name in plain until the app
/// happened to save, with no time limit for someone who works from the CLI.
/// At the top of every command and the app's start (cli.rs, once the
/// migration found the profile sealed and loaded its keys) they move into
/// tui_private.rms as a save moves them: the sealed file first (only when
/// there is none: one that is there wins, as [`load`] lets it win), then
/// tui_state.json without them, its other fields kept as they are, unknown
/// ones too. What the app loads is the same before and after. A
/// tui_private.rms that can't be opened leaves both as they are. Then a
/// tui_private.rms `raven privacy unseal` wrote back in plain is sealed in
/// place (the migration after `raven privacy seal-now` seals only its own
/// files). Whether anything moved; nothing without the keys loaded in this
/// process (no keystore call).
pub(crate) fn move_private_now(data_dir: &Path) -> Result<bool, String> {
    if !bridge::at_rest_keys_loaded(data_dir) {
        return Ok(false);
    }
    let moved = move_private_with(data_dir, &ProfileFile)?;
    let sealed = bridge::seal_tui_private_in_place(data_dir)?;
    Ok(moved || sealed)
}

/// [`move_private_now`]'s move out of tui_state.json, with `file` for
/// tui_private.rms.
fn move_private_with(data_dir: &Path, file: &dyn PrivateFile) -> Result<bool, String> {
    if !file.sealed(data_dir) || plain_private(data_dir).is_none() {
        return Ok(false);
    }
    // Read again under the read markers' lock (read_marks.rs): the desktop
    // engine may be saving one right now.
    let _lock = read_marks::lock(data_dir)?;
    let Some(found) = plain_private(data_dir) else {
        return Ok(false);
    };
    match file.load(data_dir) {
        // The sealed file wins over these copies: they only go.
        TuiPrivateRead::Loaded(_) => {}
        // The sealed file first: until tui_state.json is rewritten both
        // hold them, so a crash between the two loses nothing.
        TuiPrivateRead::Missing => file.store(data_dir, &found.private)?,
        // What to keep is not known: both stay as they are.
        TuiPrivateRead::Unreadable(why) => return Err(why),
    }
    write_plain(data_dir, &found.rest)?;
    Ok(true)
}

/// The app's files a sealed profile still keeps in plain, by name, for
/// `raven privacy status`'s "Not encrypted yet" (review D-lock-tui-1): a
/// tui_state.json that holds read markers or the name, and a
/// tui_private.rms `raven privacy unseal` left in plain. None in a profile
/// that is not sealed. Reads only.
pub(crate) fn private_files_in_plain(data_dir: &Path) -> Vec<&'static str> {
    if !bridge::tui_private_sealed(data_dir) {
        return Vec::new();
    }
    let mut names = Vec::new();
    if plain_private(data_dir).is_some() {
        names.push(FILE_NAME);
    }
    if bridge::tui_private_in_plain(data_dir) {
        names.push(bridge::TUI_PRIVATE_FILE);
    }
    names
}

impl TuiState {
    /// Writes the state to `<data_dir>/tui_state.json`, owner-only (0600),
    /// replacing the old file in one step; in a sealed profile the read
    /// markers and the name go to tui_private.rms first, and tui_state.json
    /// holds the rest. Needs proof that the profile's identity exists.
    pub(super) fn save(&self, data_dir: &Path, ready: &IdentityReady) -> Result<(), String> {
        self.save_with(data_dir, ready, &ProfileFile)
    }

    /// [`TuiState::save`] with `file` for tui_private.rms.
    fn save_with(
        &self,
        data_dir: &Path,
        _ready: &IdentityReady,
        file: &dyn PrivateFile,
    ) -> Result<(), String> {
        // One writer of the read markers at a time (read_marks.rs): a marker
        // the desktop engine saved since this app read them stays where it
        // is later than this app's own.
        let _lock = read_marks::lock(data_dir)?;
        let mut current = TuiState {
            version: STATE_VERSION,
            ..self.clone()
        };
        let saved = load_with(data_dir, file).0.read_marks();
        current.take_later(&saved, &read_marks::no_place);
        write_with(data_dir, &current, file)
    }
}

/// The read markers changed by `change` (whether it changed any) and saved,
/// under their lock (read_marks.rs): read again first, so nothing another
/// app saved meanwhile is lost, and written as [`TuiState::save`] writes. A
/// file that can't be read is left as it is, and its reason comes back.
/// Needs proof that the profile's identity exists, as a save does.
pub(super) fn update_marks(
    data_dir: &Path,
    _ready: &IdentityReady,
    change: impl FnOnce(&mut TuiState) -> bool,
) -> Result<bool, String> {
    update_marks_with(data_dir, &ProfileFile, change)
}

/// [`update_marks`] with `file` for tui_private.rms.
fn update_marks_with(
    data_dir: &Path,
    file: &dyn PrivateFile,
    change: impl FnOnce(&mut TuiState) -> bool,
) -> Result<bool, String> {
    let _lock = read_marks::lock(data_dir)?;
    let (mut state, note) = load_with(data_dir, file);
    if let LoadNote::Unreadable(why) = note {
        return Err(why);
    }
    if !change(&mut state) {
        return Ok(false);
    }
    state.version = STATE_VERSION;
    write_with(data_dir, &state, file)?;
    Ok(true)
}

/// `state` written where it belongs: in a sealed profile the read markers
/// and the name to tui_private.rms, the rest to tui_state.json; otherwise
/// all of it to tui_state.json.
fn write_with(data_dir: &Path, state: &TuiState, file: &dyn PrivateFile) -> Result<(), String> {
    if file.sealed(data_dir) {
        // The sealed file first: until tui_state.json is rewritten without
        // them, both hold the read markers. When it can't be written (the
        // key unavailable) nothing is, and the save fails.
        file.store(data_dir, &TuiPrivate::of(state))?;
        return write_plain(data_dir, &PlainSettings::of(state));
    }
    write_plain(data_dir, state)?;
    // Not sealed (any more): both are in tui_state.json now, and its own
    // fields win over a sealed file left behind ([`load_with`]), so one that
    // can't be deleted now does no harm.
    let _ = file.remove(data_dir);
    Ok(())
}

/// `value` as tui_state.json: pretty JSON and a line break, owner-only
/// (0600), replacing the old file in one step.
fn write_plain<T: Serialize>(data_dir: &Path, value: &T) -> Result<(), String> {
    let path = path(data_dir);
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    raven_core::atomic_write_private(&path, &bytes).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::{Cell, RefCell};

    /// Every entry in `dir`, by name.
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read the profile")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    fn changed() -> TuiState {
        TuiState {
            display_name: "Sam".into(),
            motion: MotionSetting::Reduced,
            colors: ColorSetting::NoColors,
            symbols: SymbolSetting::Ascii,
            on_quit: OnQuit::Ask,
            receive: Receive::Off,
            include_lan_in_card: false,
            show_details: true,
            always_classic: true,
            firewall_note_shown: true,
            network_note_shown: true,
            hotspot_note_shown: true,
            names_note_shown: true,
            exit_note_shown: true,
            copy_note_shown: true,
            last_read: BTreeMap::from([("ab".repeat(32), "msg-7".into())]),
            ..TuiState::default()
        }
    }

    #[test]
    fn defaults_follow_the_owner_decisions() {
        let state = TuiState::default();
        assert_eq!(state.version, 1);
        assert!(
            state.include_lan_in_card,
            "OD-5: the invite carries the address"
        );
        assert_eq!(state.on_quit, OnQuit::KeepRunning, "OD-2");
        assert_eq!(state.receive, Receive::Unset);
        assert!(!state.always_classic && !state.show_details && !state.firewall_note_shown);
        // Every note shown once (UXF.9) is still to show.
        assert!(
            !state.network_note_shown
                && !state.hotspot_note_shown
                && !state.names_note_shown
                && !state.exit_note_shown
                && !state.copy_note_shown
        );
        // The file format, pinned: renaming a field or a value loses users'
        // settings.
        assert_eq!(
            serde_json::to_value(changed()).unwrap(),
            json!({
                "version": 1,
                "display_name": "Sam",
                "motion": "reduced",
                "colors": "no_colors",
                "symbols": "ascii",
                "on_quit": "ask",
                "receive": "off",
                "include_lan_in_card": false,
                "show_details": true,
                "always_classic": true,
                "firewall_note_shown": true,
                "network_note_shown": true,
                "hotspot_note_shown": true,
                "names_note_shown": true,
                "exit_note_shown": true,
                "copy_note_shown": true,
                "last_read": { "ab".repeat(32): "msg-7" },
            })
        );
        assert_eq!(
            serde_json::to_value(TuiState::default()).unwrap(),
            json!({
                "version": 1,
                "display_name": "",
                "motion": "auto",
                "colors": "auto",
                "symbols": "auto",
                "on_quit": "keep_running",
                "receive": "unset",
                "include_lan_in_card": true,
                "show_details": false,
                "always_classic": false,
                "firewall_note_shown": false,
                "network_note_shown": false,
                "hotspot_note_shown": false,
                "names_note_shown": false,
                "exit_note_shown": false,
                "copy_note_shown": false,
                "last_read": {},
            })
        );
        let others = [
            (
                serde_json::to_value(OnQuit::StopIfStarted),
                "stop_if_started",
            ),
            (serde_json::to_value(Receive::On), "on"),
            (serde_json::to_value(MotionSetting::Full), "full"),
            (serde_json::to_value(SymbolSetting::Simple), "simple"),
            (serde_json::to_value(SymbolSetting::Fancy), "fancy"),
        ];
        for (value, want) in others {
            assert_eq!(value.unwrap(), json!(want));
        }
    }

    #[test]
    fn settings_values_step_round_and_round() {
        assert_eq!(
            step(&SymbolSetting::ALL, SymbolSetting::Auto, true),
            SymbolSetting::Ascii
        );
        assert_eq!(
            step(&SymbolSetting::ALL, SymbolSetting::Fancy, true),
            SymbolSetting::Auto
        );
        assert_eq!(
            step(&SymbolSetting::ALL, SymbolSetting::Auto, false),
            SymbolSetting::Fancy
        );
        assert_eq!(step(&OnQuit::ALL, OnQuit::Ask, true), OnQuit::KeepRunning);
        assert_eq!(step(&OnQuit::ALL, OnQuit::KeepRunning, false), OnQuit::Ask);
        assert_eq!(
            step(&ColorChoice::ALL, ColorChoice::Auto, true),
            ColorChoice::Dark
        );
        assert_eq!(
            step(&ColorChoice::ALL, ColorChoice::Auto, false),
            ColorChoice::NoColors
        );
        for forward in [true, false] {
            // A value the list leaves out goes to its first.
            assert_eq!(
                step(&[OnQuit::Ask], OnQuit::KeepRunning, forward),
                OnQuit::Ask
            );
        }
        // The defaults come first.
        assert_eq!(SymbolSetting::ALL[0], SymbolSetting::default());
        assert_eq!(OnQuit::ALL[0], OnQuit::default());
        assert_eq!(ColorChoice::ALL[0], ColorChoice::of(&TuiState::default()));
    }

    #[test]
    fn the_palette_is_a_field_an_older_app_skips() {
        // Automatic writes no `palette`: the file is as it was.
        let auto = serde_json::to_value(TuiState::default()).expect("JSON");
        assert!(auto.get("palette").is_none(), "{auto}");
        // Dark and Light write it, and `colors` keeps one of the two values
        // an older app knows.
        for (choice, palette, word) in [
            (ColorChoice::Dark, PaletteSetting::Dark, "dark"),
            (ColorChoice::Light, PaletteSetting::Light, "light"),
        ] {
            let mut state = TuiState::default();
            choice.apply(&mut state);
            assert_eq!((state.colors, state.palette), (ColorSetting::Auto, palette));
            assert_eq!(ColorChoice::of(&state), choice);
            let json = serde_json::to_value(&state).expect("JSON");
            assert_eq!(json["palette"], word);
            assert_eq!(json["colors"], "auto");
            let back: TuiState = serde_json::from_value(json).expect("read back");
            assert_eq!(back, state);
        }
        // No colors keeps the palette for when colours come back.
        let mut state = TuiState::default();
        ColorChoice::Light.apply(&mut state);
        ColorChoice::NoColors.apply(&mut state);
        assert_eq!(
            (state.colors, state.palette),
            (ColorSetting::NoColors, PaletteSetting::Light)
        );
        assert_eq!(ColorChoice::of(&state), ColorChoice::NoColors);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let ready = controller::identity_ready_for_tests();
        let state = changed();
        state.save(dir.path(), &ready).expect("save");
        assert_eq!(load(dir.path()), (state.clone(), LoadNote::Loaded));
        assert_eq!(peek(dir.path()), state);
        assert_eq!(entries(dir.path()), [read_marks::LOCK, FILE_NAME]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // A save replaces the file, and always writes the current format.
        let older = TuiState {
            version: 0,
            always_classic: false,
            ..state
        };
        older.save(dir.path(), &ready).expect("second save");
        let (back, note) = load(dir.path());
        assert_eq!(note, LoadNote::Loaded);
        assert_eq!(back.version, STATE_VERSION);
        assert!(!back.always_classic);
        assert_eq!(entries(dir.path()), [read_marks::LOCK, FILE_NAME]);
    }

    #[test]
    fn unknown_fields_are_ignored_and_missing_ones_default() {
        let dir = tempfile::tempdir().unwrap();
        let text = r#"{
            "version": 1,
            "always_classic": true,
            "receive": "on",
            "a_future_setting": {"x": [1, 2]},
            "another": null
        }"#;
        std::fs::write(path(dir.path()), text).unwrap();
        let (state, note) = load(dir.path());
        assert_eq!(note, LoadNote::Loaded);
        assert_eq!(
            state,
            TuiState {
                always_classic: true,
                receive: Receive::On,
                ..TuiState::default()
            }
        );
        // Even an empty object: every default, the address share on.
        std::fs::write(path(dir.path()), "{}").unwrap();
        assert_eq!(load(dir.path()), (TuiState::default(), LoadNote::Loaded));
        assert!(peek(dir.path()).include_lan_in_card);
    }

    #[test]
    fn the_notes_shown_once_round_trip_each_on_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let ready = controller::identity_ready_for_tests();
        // A file from before the notes (UXF.9): each is still to show, and
        // nothing else changes.
        std::fs::write(
            path(dir.path()),
            r#"{"version": 1, "receive": "on", "firewall_note_shown": true}"#,
        )
        .unwrap();
        assert_eq!(
            peek(dir.path()),
            TuiState {
                receive: Receive::On,
                firewall_note_shown: true,
                ..TuiState::default()
            }
        );
        // Each flag comes back as saved, the others as they were.
        let flags: [fn(&mut TuiState) -> &mut bool; 5] = [
            |state| &mut state.network_note_shown,
            |state| &mut state.hotspot_note_shown,
            |state| &mut state.names_note_shown,
            |state| &mut state.exit_note_shown,
            |state| &mut state.copy_note_shown,
        ];
        for flag in flags {
            let mut state = TuiState::default();
            *flag(&mut state) = true;
            state.save(dir.path(), &ready).expect("save");
            assert_eq!(load(dir.path()), (state, LoadNote::Loaded));
        }
    }

    #[test]
    fn a_corrupt_file_gives_defaults_and_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let file = path(dir.path());
        let oversize = format!(
            "{{\"display_name\": \"{}\"}}",
            "x".repeat(MAX_FILE_BYTES as usize)
        );
        for text in [
            "{\"always_classic\": tru",
            "",
            "null",
            "\"always_classic\"",
            "{\"always_classic\": \"yes\"}",
            "{\"receive\": \"sometimes\"}",
            "{\"last_read\": [1, 2]}",
            oversize.as_str(),
        ] {
            std::fs::write(&file, text).unwrap();
            let (state, note) = load(dir.path());
            assert_eq!(state, TuiState::default(), "{:.40}", text);
            match note {
                LoadNote::Unreadable(why) => assert!(why.contains(FILE_NAME), "{why}"),
                other => panic!("{:.40}: {other:?}", text),
            }
            assert_eq!(peek(dir.path()), TuiState::default());
            assert_eq!(
                std::fs::read_to_string(&file).unwrap(),
                text,
                "the file changed"
            );
            assert_eq!(entries(dir.path()), [FILE_NAME]);
        }

        // Not a file at all.
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        let (state, note) = load(dir.path());
        assert_eq!(state, TuiState::default());
        assert!(matches!(note, LoadNote::Unreadable(_)), "{note:?}");
        assert!(file.is_dir());
    }

    #[test]
    fn peek_and_load_create_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(peek(dir.path()), TuiState::default());
        assert_eq!(load(dir.path()), (TuiState::default(), LoadNote::Missing));
        assert!(entries(dir.path()).is_empty(), "{:?}", entries(dir.path()));

        // A data directory that does not exist yet stays that way.
        let profile = dir.path().join("not-yet");
        assert_eq!(peek(&profile), TuiState::default());
        assert_eq!(load(&profile), (TuiState::default(), LoadNote::Missing));
        assert!(!profile.exists());
    }

    #[test]
    fn no_state_file_before_the_identity() {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let wizard = Controller::new(dir.path());
        assert!(matches!(wizard.load_identity(), IdentityState::Missing));
        // The gate and the wizard read the settings; that writes nothing.
        assert_eq!(peek(dir.path()), TuiState::default());
        assert!(!path(dir.path()).exists(), "{:?}", entries(dir.path()));

        // The proof that saving needs comes only with the identity.
        let chosen = TuiState {
            display_name: "Sam".into(),
            receive: Receive::On,
            ..TuiState::default()
        };
        assert!(wizard.save_settings(&chosen).is_err());
        assert!(!path(dir.path()).exists(), "{:?}", entries(dir.path()));
        wizard.create_identity().result.expect("create");
        wizard.save_settings(&chosen).expect("save");
        assert_eq!(load(dir.path()), (chosen.clone(), LoadNote::Loaded));
        // The next session gets it by loading the identity.
        let next = Controller::new(dir.path());
        assert!(next.save_settings(&chosen).is_err());
        assert!(matches!(next.load_identity(), IdentityState::Ready { .. }));
        next.save_settings(&chosen).expect("save");
    }

    // ── tui_private.rms (privacy pack PP.24) ──

    /// A fake tui_private.rms: a sealed profile or not, the file as a value
    /// (None: missing; Err: it can't be opened), and how often each part ran.
    struct FakeFile {
        sealed: bool,
        file: RefCell<Option<Result<TuiPrivate, String>>>,
        /// Every store fails with this (the key unavailable).
        refuse: Option<String>,
        loads: Cell<u32>,
        stores: Cell<u32>,
        removes: Cell<u32>,
    }

    impl FakeFile {
        fn new(sealed: bool) -> FakeFile {
            FakeFile {
                sealed,
                file: RefCell::new(None),
                refuse: None,
                loads: Cell::new(0),
                stores: Cell::new(0),
                removes: Cell::new(0),
            }
        }

        fn holding(sealed: bool, private: TuiPrivate) -> FakeFile {
            let fake = FakeFile::new(sealed);
            *fake.file.borrow_mut() = Some(Ok(private));
            fake
        }

        fn held(&self) -> Option<Result<TuiPrivate, String>> {
            self.file.borrow().clone()
        }
    }

    impl PrivateFile for FakeFile {
        fn sealed(&self, _: &Path) -> bool {
            self.sealed
        }

        fn load(&self, _: &Path) -> TuiPrivateRead {
            self.loads.set(self.loads.get() + 1);
            match self.held() {
                None => TuiPrivateRead::Missing,
                Some(Ok(private)) => TuiPrivateRead::Loaded(private),
                Some(Err(why)) => TuiPrivateRead::Unreadable(why),
            }
        }

        fn store(&self, _: &Path, private: &TuiPrivate) -> Result<(), String> {
            self.stores.set(self.stores.get() + 1);
            if let Some(why) = &self.refuse {
                return Err(why.clone());
            }
            *self.file.borrow_mut() = Some(Ok(private.clone()));
            Ok(())
        }

        fn remove(&self, _: &Path) -> Result<(), String> {
            self.removes.set(self.removes.get() + 1);
            *self.file.borrow_mut() = None;
            Ok(())
        }
    }

    /// [`changed`] as the plain file and the sealed one split it.
    fn split(state: &TuiState) -> (TuiState, TuiPrivate) {
        let plain = TuiState {
            display_name: String::new(),
            last_read: BTreeMap::new(),
            ..state.clone()
        };
        (plain, TuiPrivate::of(state))
    }

    /// No friend key, no read marker and not the name in tui_state.json.
    fn assert_plain_names_nobody(dir: &Path, state: &TuiState) {
        let bytes = std::fs::read(path(dir)).expect("tui_state.json");
        let text = String::from_utf8(bytes).expect("text");
        assert!(!state.display_name.is_empty() && !state.last_read.is_empty());
        let mut needles = vec![state.display_name.clone(), "last_read".into()];
        for (friend, message) in &state.last_read {
            needles.push(friend.clone());
            needles.push(message.clone());
        }
        needles.push("display_name".into());
        for needle in needles {
            assert!(!text.contains(&needle), "{needle} in {text}");
        }
    }

    #[test]
    fn a_sealed_profile_keeps_read_markers_and_the_name_in_the_sealed_file() {
        let dir = tempfile::tempdir().unwrap();
        let ready = controller::identity_ready_for_tests();
        let fake = FakeFile::new(true);
        let state = changed();
        state.save_with(dir.path(), &ready, &fake).expect("save");
        let (plain, private) = split(&state);
        assert_eq!(fake.held(), Some(Ok(private.clone())));
        assert_eq!(fake.stores.get(), 1);
        assert_eq!(fake.removes.get(), 0);
        assert_eq!(entries(dir.path()), [read_marks::LOCK, FILE_NAME]);
        assert_plain_names_nobody(dir.path(), &state);
        // Both formats, pinned.
        let text = std::fs::read_to_string(path(dir.path())).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap(),
            json!({
                "version": 1,
                "motion": "reduced",
                "colors": "no_colors",
                "symbols": "ascii",
                "on_quit": "ask",
                "receive": "off",
                "include_lan_in_card": false,
                "show_details": true,
                "always_classic": true,
                "firewall_note_shown": true,
                "network_note_shown": true,
                "hotspot_note_shown": true,
                "names_note_shown": true,
                "exit_note_shown": true,
                "copy_note_shown": true,
            })
        );
        assert!(
            text.starts_with("{\n  \"version\": 1,\n  \"motion\""),
            "{text}"
        );
        assert!(text.ends_with("}\n"));
        assert_eq!(
            serde_json::to_value(&private).unwrap(),
            json!({
                "version": 1,
                "display_name": "Sam",
                "last_read": { "ab".repeat(32): "msg-7" },
            })
        );
        // load merges the two; peek (the gate) reads the plain file alone.
        assert_eq!(
            load_with(dir.path(), &fake),
            (state.clone(), LoadNote::Loaded)
        );
        assert_eq!(peek(dir.path()), plain);

        // The next save: the same split, every change kept.
        let mut next = state.clone();
        next.last_read.insert("cd".repeat(32), "msg-9".into());
        next.display_name = "Samira".into();
        next.motion = MotionSetting::Full;
        next.save_with(dir.path(), &ready, &fake).expect("save");
        assert_eq!(
            load_with(dir.path(), &fake),
            (next.clone(), LoadNote::Loaded)
        );
        assert_eq!(peek(dir.path()), split(&next).0);
        assert_plain_names_nobody(dir.path(), &next);
        assert_eq!(fake.removes.get(), 0);
    }

    #[test]
    fn a_profile_that_is_not_sealed_keeps_everything_in_tui_state_json() {
        let dir = tempfile::tempdir().unwrap();
        let ready = controller::identity_ready_for_tests();
        let fake = FakeFile::new(false);
        let state = changed();
        state.save_with(dir.path(), &ready, &fake).expect("save");
        // Exactly the bytes of the app before the pack, and the sealed file
        // never written or read.
        let mut today = serde_json::to_vec_pretty(&state).unwrap();
        today.push(b'\n');
        assert_eq!(std::fs::read(path(dir.path())).unwrap(), today);
        assert_eq!(
            load_with(dir.path(), &fake),
            (state.clone(), LoadNote::Loaded)
        );
        assert_eq!(peek(dir.path()), state);
        // Read once, by the save (whether `raven privacy unseal` left read
        // markers in it), while tui_state.json held none yet.
        assert_eq!((fake.stores.get(), fake.loads.get()), (0, 1));
        assert_eq!(fake.held(), None);
        assert_eq!(entries(dir.path()), [read_marks::LOCK, FILE_NAME]);
    }

    /// `raven privacy unseal` writes tui_private.rms back in plain and
    /// leaves tui_state.json without the two fields: they are read from it
    /// until the next save puts them back in tui_state.json and deletes it.
    #[test]
    fn after_unseal_the_next_save_takes_both_back_into_tui_state_json() {
        let dir = tempfile::tempdir().unwrap();
        let ready = controller::identity_ready_for_tests();
        let state = changed();
        let sealed = FakeFile::new(true);
        state.save_with(dir.path(), &ready, &sealed).expect("save");
        let unsealed = FakeFile::holding(false, sealed.held().unwrap().unwrap());
        assert_eq!(
            load_with(dir.path(), &unsealed),
            (state.clone(), LoadNote::Loaded)
        );
        state
            .save_with(dir.path(), &ready, &unsealed)
            .expect("save");
        assert_eq!((unsealed.removes.get(), unsealed.held()), (1, None));
        assert_eq!(peek(dir.path()), state);
        assert_eq!(
            load_with(dir.path(), &unsealed),
            (state.clone(), LoadNote::Loaded)
        );

        // A sealed file the delete left behind does no harm: tui_state.json's
        // own fields win while the profile is not sealed.
        let stale = FakeFile::holding(
            false,
            TuiPrivate {
                display_name: "Old".into(),
                ..TuiPrivate::default()
            },
        );
        assert_eq!(load_with(dir.path(), &stale), (state, LoadNote::Loaded));
        assert_eq!(stale.loads.get(), 0);
    }

    #[test]
    fn the_first_sealed_save_moves_both_and_a_crash_between_loses_no_marker() {
        let dir = tempfile::tempdir().unwrap();
        let ready = controller::identity_ready_for_tests();
        // tui_state.json as an older app (or a plain profile) wrote it.
        let older = changed();
        older
            .save_with(dir.path(), &ready, &FakeFile::new(false))
            .expect("save");
        let before = std::fs::read(path(dir.path())).unwrap();
        // Now sealed, and no tui_private.rms yet: tui_state.json's fields.
        let fake = FakeFile::new(true);
        assert_eq!(
            load_with(dir.path(), &fake),
            (older.clone(), LoadNote::Loaded)
        );

        // A save that crashes between its two writes: tui_private.rms is
        // written, tui_state.json is not rewritten yet.
        let mut next = older.clone();
        next.last_read.insert("cd".repeat(32), "msg-9".into());
        fake.store(dir.path(), &TuiPrivate::of(&next))
            .expect("the first write");
        assert_eq!(std::fs::read(path(dir.path())).unwrap(), before);
        // Both readable, every marker there (the sealed file wins).
        assert_eq!(
            load_with(dir.path(), &fake),
            (next.clone(), LoadNote::Loaded)
        );
        assert_eq!(peek(dir.path()), older);

        // The next save finishes the move.
        next.save_with(dir.path(), &ready, &fake).expect("save");
        assert_eq!(
            load_with(dir.path(), &fake),
            (next.clone(), LoadNote::Loaded)
        );
        assert_plain_names_nobody(dir.path(), &next);

        // An older app's save after that (both fields back, empty): the
        // sealed file still wins in a sealed profile.
        TuiState {
            display_name: String::new(),
            last_read: BTreeMap::new(),
            ..next.clone()
        }
        .save_with(dir.path(), &ready, &FakeFile::new(false))
        .expect("save");
        assert_eq!(load_with(dir.path(), &fake), (next, LoadNote::Loaded));
    }

    #[test]
    fn an_unreadable_sealed_file_gives_no_markers_and_a_failed_store_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let ready = controller::identity_ready_for_tests();
        let state = changed();
        state
            .save_with(dir.path(), &ready, &FakeFile::new(true))
            .expect("save");
        let (plain, _) = split(&state);
        let fake = FakeFile::new(true);
        *fake.file.borrow_mut() = Some(Err("sealed data failed authentication (kind 10)".into()));
        let (back, note) = load_with(dir.path(), &fake);
        assert_eq!(back, plain, "no read markers, no name");
        match note {
            LoadNote::Unreadable(why) => {
                assert!(why.contains("tui_private.rms"), "{why}");
                assert!(why.contains("failed authentication"), "{why}");
            }
            other => panic!("{other:?}"),
        }
        // Even beside a tui_state.json that still holds both (before the
        // first sealed save): none from either.
        let older = FakeFile::new(false);
        state.save_with(dir.path(), &ready, &older).expect("save");
        assert_eq!(load_with(dir.path(), &fake).0, plain);

        // The key unavailable: the store fails and nothing is written.
        let before = std::fs::read(path(dir.path())).unwrap();
        let refusing = FakeFile {
            refuse: Some("the at-rest key is unavailable".into()),
            ..FakeFile::new(true)
        };
        let err = changed()
            .save_with(dir.path(), &ready, &refusing)
            .unwrap_err();
        assert!(err.contains("unavailable"), "{err}");
        assert_eq!(std::fs::read(path(dir.path())).unwrap(), before);
        assert_eq!((refusing.stores.get(), refusing.held()), (1, None));
    }

    /// peek, which the gate runs on every start, and the plain read under it
    /// never reach the sealed file or anything else of bridge.rs.
    #[test]
    fn peek_never_calls_the_bridges_sealed_functions() {
        let source = include_str!("state_file.rs");
        for head in ["pub(super) fn peek(", "fn read_plain(", "fn read_state("] {
            let start = source.find(head).expect(head);
            let end = source[start..].find("\n}\n").expect("its end");
            let body = &source[start..start + end];
            for needle in [
                "bridge",
                "load_with",
                "PrivateFile",
                ".sealed(",
                "TuiPrivate",
            ] {
                assert!(!body.contains(needle), "{needle} in {body}");
            }
        }
        assert!(source.contains("    read_plain(data_dir).0\n"));
    }

    /// A profile made and sealed the way Raven does it, its at-rest keys
    /// loaded as a command's top loads them.
    fn sealed_profile() -> (tempfile::TempDir, Controller) {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let controller = Controller::new(dir.path());
        controller.create_identity().result.expect("create");
        raven_core::privacy::migrate_all(
            dir.path(),
            bridge::now_ms(),
            raven_core::at_rest::MigratePolicy::Allow,
        )
        .expect("sealed");
        assert!(bridge::tui_private_sealed(dir.path()));
        (dir, controller)
    }

    /// The real tui_private.rms: RMS1 under the profile's keys, opened by
    /// load and never by peek, which needs no key.
    #[test]
    fn a_sealed_profile_seals_tui_private_and_peek_needs_no_key() {
        let (dir, controller) = sealed_profile();
        let dd = dir.path();
        let state = changed();
        controller.save_settings(&state).expect("saved");
        let sealed = std::fs::read(dd.join(bridge::TUI_PRIVATE_FILE)).expect("tui_private.rms");
        assert!(raven_core::at_rest::is_sealed_as(
            raven_core::at_rest::Kind::TuiPrivate,
            &sealed
        ));
        let text = String::from_utf8_lossy(&sealed);
        assert!(!text.contains("Sam") && !text.contains(&"ab".repeat(32)));
        assert_plain_names_nobody(dd, &state);
        assert_eq!(load(dd), (state.clone(), LoadNote::Loaded));
        let (plain, _) = split(&state);
        assert_eq!(peek(dd), plain);

        // No key in this process: peek is unchanged and loads none; load
        // gives no read markers and no name, and loads none either.
        raven_core::at_rest::forget_cached_keys(dd);
        assert_eq!(peek(dd), plain);
        assert!(raven_core::at_rest::keys_cached(dd).is_err());
        let (back, note) = load(dd);
        assert_eq!(back, plain);
        assert!(matches!(note, LoadNote::Unreadable(_)), "{note:?}");
        assert!(raven_core::at_rest::keys_cached(dd).is_err());
        // Nothing is saved over it then: no read marker save, and a setting
        // the user changes fails (no plaintext fallback).
        assert_eq!(controller.save_read_marks(&state), Ok(false));
        assert!(controller.save_settings(&state).is_err());
        assert_eq!(
            std::fs::read(dd.join(bridge::TUI_PRIVATE_FILE)).unwrap(),
            sealed
        );
        assert_eq!(peek(dd), plain);
        // The keys again: everything back.
        raven_core::at_rest::keys_load_with(dd, raven_core::at_rest::MigratePolicy::Never)
            .expect("the keys");
        assert_eq!(load(dd), (state, LoadNote::Loaded));
    }

    /// A tui_private.rms with a changed byte: no read markers and no name,
    /// left as it is by the saves the user did not ask for, replaced by a
    /// setting the user changes (the tui_state.json rule).
    #[test]
    fn a_tampered_tui_private_is_left_alone_until_the_user_changes_a_setting() {
        let (dir, controller) = sealed_profile();
        let dd = dir.path();
        let state = changed();
        controller.save_settings(&state).expect("saved");
        let file = dd.join(bridge::TUI_PRIVATE_FILE);
        let mut bytes = std::fs::read(&file).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&file, &bytes).unwrap();
        let (plain, _) = split(&state);
        let (back, note) = load(dd);
        assert_eq!(back, plain);
        assert!(matches!(note, LoadNote::Unreadable(_)), "{note:?}");
        assert_eq!(controller.save_read_marks(&state), Ok(false));
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        controller.save_settings(&state).expect("saved");
        assert_eq!(load(dd), (state.clone(), LoadNote::Loaded));
        assert_eq!(controller.save_read_marks(&state), Ok(true));
    }

    // ── The move at the top of every command (review D-lock-tui-1) ──

    /// tui_state.json as an app before PP.24 (or the app in a profile not
    /// sealed yet) wrote it, with a field of a newer app beside: its bytes.
    fn older_tui_state(dir: &Path, state: &TuiState) -> Vec<u8> {
        let mut value = serde_json::to_value(state).unwrap();
        value["a_newer_setting"] = json!({"kept": [1, 2]});
        let mut bytes = serde_json::to_vec_pretty(&value).unwrap();
        bytes.push(b'\n');
        std::fs::write(path(dir), &bytes).unwrap();
        bytes
    }

    #[test]
    fn the_move_takes_both_out_of_tui_state_json_and_changes_nothing_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let state = changed();
        older_tui_state(dir.path(), &state);
        let fake = FakeFile::new(true);
        let before = load_with(dir.path(), &fake);
        assert_eq!(before, (state.clone(), LoadNote::Loaded));
        assert_eq!(move_private_with(dir.path(), &fake), Ok(true));
        // The sealed file first, with both, then tui_state.json without them.
        assert_eq!(fake.stores.get(), 1);
        assert_eq!(fake.held(), Some(Ok(TuiPrivate::of(&state))));
        assert_plain_names_nobody(dir.path(), &state);
        assert_eq!(entries(dir.path()), [read_marks::LOCK, FILE_NAME]);
        // Every other setting stays, a newer app's too; the app loads the
        // same as before.
        let text = std::fs::read_to_string(path(dir.path())).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["a_newer_setting"], json!({"kept": [1, 2]}));
        assert!(text.ends_with("}\n"));
        assert_eq!(peek(dir.path()), split(&state).0);
        assert_eq!(load_with(dir.path(), &fake), before);
        // A second run finds nothing to move and writes nothing.
        let bytes = std::fs::read(path(dir.path())).unwrap();
        assert_eq!(move_private_with(dir.path(), &fake), Ok(false));
        assert_eq!(std::fs::read(path(dir.path())).unwrap(), bytes);
        assert_eq!(fake.stores.get(), 1);
    }

    #[test]
    fn the_move_leaves_a_sealed_file_that_is_there_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let state = changed();
        // The sealed file wins over the plain copies (load_with), so they
        // only go: what the app loads is the same.
        let sealed = TuiPrivate {
            display_name: "Samira".into(),
            last_read: BTreeMap::from([("cd".repeat(32), "msg-9".into())]),
            ..TuiPrivate::default()
        };
        older_tui_state(dir.path(), &state);
        let fake = FakeFile::holding(true, sealed.clone());
        let before = load_with(dir.path(), &fake);
        assert_eq!(before.0.display_name, "Samira");
        assert_eq!(move_private_with(dir.path(), &fake), Ok(true));
        assert_eq!((fake.stores.get(), fake.held()), (0, Some(Ok(sealed))));
        assert_plain_names_nobody(dir.path(), &state);
        assert_eq!(load_with(dir.path(), &fake), before);
    }

    #[test]
    fn the_move_leaves_everything_it_cannot_decide_alone() {
        let dir = tempfile::tempdir().unwrap();
        let state = changed();
        let bytes = older_tui_state(dir.path(), &state);
        let unchanged = |dir: &Path| assert_eq!(std::fs::read(path(dir)).unwrap(), bytes);
        // A sealed file that can't be opened: what to keep is not known.
        let fake = FakeFile::new(true);
        *fake.file.borrow_mut() = Some(Err("sealed data failed authentication (kind 10)".into()));
        let err = move_private_with(dir.path(), &fake).unwrap_err();
        assert!(err.contains("failed authentication"), "{err}");
        unchanged(dir.path());
        assert_eq!(fake.stores.get(), 0);
        // The key unavailable: the store fails, tui_state.json stays whole.
        let refusing = FakeFile {
            refuse: Some("the at-rest key is unavailable".into()),
            ..FakeFile::new(true)
        };
        assert!(move_private_with(dir.path(), &refusing).is_err());
        unchanged(dir.path());
        // A profile that is not sealed keeps both in tui_state.json.
        let plain = FakeFile::new(false);
        assert_eq!(move_private_with(dir.path(), &plain), Ok(false));
        unchanged(dir.path());
        assert_eq!((plain.loads.get(), plain.stores.get()), (0, 0));
        // Nothing to move: no name and no read marker (empty ones too).
        let fake = FakeFile::new(true);
        for text in [
            "{\"version\": 1, \"receive\": \"on\"}".to_owned(),
            serde_json::to_string(&TuiState::default()).unwrap(),
        ] {
            std::fs::write(path(dir.path()), &text).unwrap();
            assert_eq!(move_private_with(dir.path(), &fake), Ok(false));
            assert_eq!(std::fs::read_to_string(path(dir.path())).unwrap(), text);
        }
        // A tui_state.json that can't be parsed is left for the user.
        for text in [
            "{\"display_name\": \"Sam\", \"receive\": \"sometimes\"}",
            "{",
        ] {
            std::fs::write(path(dir.path()), text).unwrap();
            assert_eq!(move_private_with(dir.path(), &fake), Ok(false));
            assert_eq!(std::fs::read_to_string(path(dir.path())).unwrap(), text);
        }
        assert_eq!((fake.loads.get(), fake.stores.get()), (0, 0));
    }

    /// The real files: a sealed profile whose tui_state.json still holds the
    /// read markers and the name (written before the profile was sealed).
    /// The top of a command moves them at once (no save of the app needed);
    /// `raven privacy status` counts the file until then.
    #[test]
    fn a_sealed_profiles_markers_and_name_leave_tui_state_json_at_once() {
        let (dir, _controller) = sealed_profile();
        let dd = dir.path();
        let state = changed();
        older_tui_state(dd, &state);
        assert_eq!(private_files_in_plain(dd), [FILE_NAME]);
        // Without the keys in this process nothing moves.
        raven_core::at_rest::forget_cached_keys(dd);
        let bytes = std::fs::read(path(dd)).unwrap();
        assert_eq!(move_private_now(dd), Ok(false));
        assert_eq!(std::fs::read(path(dd)).unwrap(), bytes);
        assert!(!dd.join(bridge::TUI_PRIVATE_FILE).exists());
        raven_core::at_rest::keys_load_with(dd, raven_core::at_rest::MigratePolicy::Never)
            .expect("the keys");
        assert_eq!(move_private_now(dd), Ok(true));
        let sealed = std::fs::read(dd.join(bridge::TUI_PRIVATE_FILE)).expect("tui_private.rms");
        assert!(raven_core::at_rest::is_sealed_as(
            raven_core::at_rest::Kind::TuiPrivate,
            &sealed
        ));
        assert_plain_names_nobody(dd, &state);
        assert_eq!(load(dd), (state, LoadNote::Loaded));
        assert!(private_files_in_plain(dd).is_empty());
        assert_eq!(move_private_now(dd), Ok(false), "nothing more to move");
    }

    /// `raven privacy unseal`, then `raven privacy seal-now` before the app
    /// saved: tui_private.rms is still the plain JSON unseal wrote, and the
    /// migration seals only its own files. The move seals it in place.
    #[test]
    fn a_tui_private_left_in_plain_after_seal_now_is_sealed_in_place() {
        let (dir, controller) = sealed_profile();
        let dd = dir.path();
        let state = changed();
        controller.save_settings(&state).expect("saved");
        raven_core::privacy::unseal_all(dd, &|| true).expect("unsealed");
        raven_core::privacy::seal_now(
            dd,
            bridge::now_ms(),
            raven_core::at_rest::MigratePolicy::Allow,
            None,
        )
        .expect("sealed again");
        assert!(bridge::tui_private_sealed(dd));
        let file = dd.join(bridge::TUI_PRIVATE_FILE);
        assert!(serde_json::from_slice::<TuiPrivate>(&std::fs::read(&file).unwrap()).is_ok());
        assert_eq!(private_files_in_plain(dd), [bridge::TUI_PRIVATE_FILE]);
        assert_eq!(move_private_now(dd), Ok(true));
        assert!(raven_core::at_rest::is_sealed_as(
            raven_core::at_rest::Kind::TuiPrivate,
            &std::fs::read(&file).unwrap()
        ));
        assert!(private_files_in_plain(dd).is_empty());
        assert_eq!(load(dd), (state, LoadNote::Loaded));
    }

    /// `raven privacy unseal` (PP.18) on a profile the app saved: the read
    /// markers and the name are still there, and the next save takes them
    /// back into tui_state.json, where a build before the pack reads them.
    #[test]
    fn unseal_keeps_the_markers_and_the_next_save_puts_them_back() {
        let (dir, controller) = sealed_profile();
        let dd = dir.path();
        let state = changed();
        controller.save_settings(&state).expect("saved");
        raven_core::privacy::unseal_all(dd, &|| true).expect("unsealed");
        assert!(!bridge::tui_private_sealed(dd));
        let plain_json = std::fs::read(dd.join(bridge::TUI_PRIVATE_FILE)).unwrap();
        assert!(serde_json::from_slice::<TuiPrivate>(&plain_json).is_ok());
        assert_eq!(load(dd), (state.clone(), LoadNote::Loaded));
        controller.save_settings(&state).expect("saved");
        assert!(!dd.join(bridge::TUI_PRIVATE_FILE).exists());
        assert_eq!(peek(dd), state);
        assert_eq!(load(dd), (state, LoadNote::Loaded));
    }
}
