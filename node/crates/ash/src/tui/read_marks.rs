//! The read markers the terminal app and the desktop engine share
//! (engine_bridge.rs, for raven-client): per friend, the newest message read
//! on this computer, so a chat read in one app is read in the other, and the
//! counts survive a restart. Local only: no read receipt is ever sent.
//!
//! - They live where this app always kept them (state_file.rs):
//!   tui_state.json's `last_read` in a profile that is not sealed,
//!   tui_private.rms in a sealed one (privacy pack PP.24). raven-core's
//!   at-rest registry already seals, erases and explains both files; a file
//!   of their own would be one more that names friends, for that registry to
//!   classify first (its guard refuses a profile file it does not know).
//! - `last_read` keeps the message id per friend key, which every version of
//!   this app reads. `last_read_at` adds that message's time ([`ReadAt`]),
//!   used only while its id is `last_read`'s: an older app that moves a
//!   marker drops the field, and its marker (an id only) reads as before.
//! - A marker is only ever replaced by a later one ([`later`]): by the two
//!   messages' places in the history where the reader has both (the
//!   history's written order is the true one: a friend's `created_at_ms` is
//!   their clock), else by their times, a time beating none.
//! - Every write is a read, a merge and a write under one lock across
//!   processes ([`LOCK`]), so two apps that mark at the same moment never
//!   move a marker back. The writes are tui_state.json's and
//!   tui_private.rms's own (atomic, owner-only).
//! - A file that can't be read gives no markers, and a marker save leaves it
//!   as it is (the user may still repair it), as this app's saves always did.
//! - A marker from before (an id only) gets its time once this app finds its
//!   message in the history (app.rs); until then both apps count by its id.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::bridge;
use super::controller::{self, IdentityReady};
use super::state_file::{self, TuiState};
#[cfg(test)]
use super::testkit;

/// The lock every writer of the read markers holds across its read, merge
/// and write: an empty lock database (raven-core's `DataDirLock`), which
/// raven-core's at-rest registry knows as `.*.lock.sqlite`.
pub const LOCK: &str = ".tui_read_marks.lock.sqlite";

/// One friend's read marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadMark {
    /// The history id of the newest message read (either direction).
    pub id: String,
    /// That message's `created_at_ms`; None for a marker an older terminal
    /// app saved (an id only).
    pub at_ms: Option<u64>,
}

/// Every friend's marker, by key (`pub_hex`, lower case).
pub type ReadMarks = BTreeMap<String, ReadMark>;

/// `last_read_at` in the files: the marker's message and its time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ReadAt {
    pub(super) id: String,
    pub(super) at_ms: u64,
}

/// One message of a conversation, as [`unread`] counts it.
#[derive(Debug, Clone, Copy)]
pub struct Row<'a> {
    /// Its history id (empty on some legacy rows and on a send with no row).
    pub id: &'a str,
    /// Yours: never unread.
    pub outgoing: bool,
    pub at_ms: u64,
}

/// Whether `candidate` marks a later message of one conversation than
/// `current`: by their places in it (`place`: a message's index, None when
/// it is not there) when both are there, else by their times, a time beating
/// none. The same message is later only when the candidate brings its time.
/// Anything else (equal times, no way to tell) keeps `current`.
pub fn later(
    candidate: &ReadMark,
    current: &ReadMark,
    place: &dyn Fn(&str) -> Option<usize>,
) -> bool {
    if candidate.id.eq_ignore_ascii_case(&current.id) {
        return candidate.at_ms.is_some() && current.at_ms.is_none();
    }
    if let (Some(a), Some(b)) = (place(&candidate.id), place(&current.id)) {
        return a > b;
    }
    match (candidate.at_ms, current.at_ms) {
        (Some(a), Some(b)) => a > b,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// The friend's messages after the one `mark` names, in history order
/// (`rows`): every one of theirs when there is no marker; when its message is
/// not among them (deleted, or a history read before it came), theirs from
/// after its time. Messages of yours never count.
pub fn unread<'a>(rows: impl IntoIterator<Item = Row<'a>>, mark: Option<&ReadMark>) -> usize {
    let rows: Vec<Row<'a>> = rows.into_iter().collect();
    let theirs = |rows: &[Row<'a>]| rows.iter().filter(|row| !row.outgoing).count();
    let Some(mark) = mark else {
        return theirs(&rows);
    };
    if let Some(at) = rows
        .iter()
        .rposition(|row| row.id.eq_ignore_ascii_case(&mark.id))
    {
        return theirs(&rows[at + 1..]);
    }
    match mark.at_ms {
        Some(ms) => rows
            .iter()
            .filter(|row| !row.outgoing && row.at_ms > ms)
            .count(),
        None => theirs(&rows),
    }
}

impl TuiState {
    /// The friend `key`'s marker (`key` in lower case): `last_read`'s id,
    /// with `last_read_at`'s time while that names the same message.
    pub(super) fn read_mark(&self, key: &str) -> Option<ReadMark> {
        let id = self.last_read.get(key)?;
        let at_ms = self
            .last_read_at
            .get(key)
            .filter(|at| at.id.eq_ignore_ascii_case(id))
            .map(|at| at.at_ms);
        Some(ReadMark {
            id: id.clone(),
            at_ms,
        })
    }

    /// Every friend's marker, each as [`TuiState::read_mark`] reads it.
    pub(super) fn read_marks(&self) -> ReadMarks {
        self.last_read
            .keys()
            .filter_map(|key| Some((key.clone(), self.read_mark(key)?)))
            .collect()
    }

    pub(super) fn set_read_mark(&mut self, key: &str, mark: ReadMark) {
        match mark.at_ms {
            Some(at_ms) => {
                let at = ReadAt {
                    id: mark.id.clone(),
                    at_ms,
                };
                self.last_read_at.insert(key.to_owned(), at);
            }
            None => {
                self.last_read_at.remove(key);
            }
        }
        self.last_read.insert(key.to_owned(), mark.id);
    }

    /// Whether the friend `key` had a marker.
    pub(super) fn remove_read_mark(&mut self, key: &str) -> bool {
        self.last_read_at.remove(key);
        self.last_read.remove(key).is_some()
    }

    /// Takes each of `marks` that is [`later`] than this state's own for the
    /// same friend (`place`: a message's index in the friend's conversation),
    /// and those of friends it has none for. Whether any was taken.
    pub(super) fn take_later(
        &mut self,
        marks: &ReadMarks,
        place: &dyn Fn(&str, &str) -> Option<usize>,
    ) -> bool {
        let mut taken = false;
        for (key, mark) in marks {
            let take = self
                .read_mark(key)
                .is_none_or(|current| later(mark, &current, &|id| place(key, id)));
            if take {
                self.set_read_mark(key, mark.clone());
                taken = true;
            }
        }
        taken
    }
}

/// No place known: [`later`] goes by the times alone.
pub(super) fn no_place(_key: &str, _id: &str) -> Option<usize> {
    None
}

/// The files the markers live in (tui_state.json, and tui_private.rms in a
/// sealed profile): a change to either may be another app's read.
pub fn files(data_dir: &Path) -> [PathBuf; 2] {
    [
        state_file::path(data_dir),
        data_dir.join(bridge::TUI_PRIVATE_FILE),
    ]
}

/// The markers as saved, read as this app reads them at its start
/// (state_file.rs's `load`): only reads, and none on any problem.
pub fn load(data_dir: &Path) -> ReadMarks {
    state_file::load(data_dir).0.read_marks()
}

/// [`LOCK`] in `data_dir`, once another writer lets go (raven-core's wait).
pub(super) fn lock(data_dir: &Path) -> Result<raven_core::DataDirLock, String> {
    raven_core::DataDirLock::acquire(data_dir, LOCK)
}

/// The desktop engine's mark: the friend `key`'s chat read up to `mark`,
/// unless the saved marker is later (`place`: a message's index in that
/// friend's conversation, as the engine's history has it). Whether it was
/// saved. Only once raven-core has the profile's identity on record (nothing
/// lands in a profile before it); a file that can't be read is left as it is
/// and its reason comes back.
#[cfg_attr(not(feature = "engine"), allow(dead_code))]
pub fn mark_read(
    data_dir: &Path,
    key: &str,
    mark: ReadMark,
    place: &dyn Fn(&str) -> Option<usize>,
) -> Result<bool, String> {
    let ready = controller::identity_on_record(data_dir)
        .ok_or_else(|| "this profile has no Raven identity yet".to_owned())?;
    let key = key.to_ascii_lowercase();
    state_file::update_marks(data_dir, &ready, |state| {
        let take = state
            .read_mark(&key)
            .is_none_or(|current| later(&mark, &current, place));
        if take {
            state.set_read_mark(&key, mark);
        }
        take
    })
}

/// Forgets the friend `key`'s marker (their chat was deleted), in the file
/// too: a later save of this app would otherwise take it back from there.
/// Whether there was one.
pub(super) fn forget(data_dir: &Path, ready: &IdentityReady, key: &str) -> Result<bool, String> {
    state_file::update_marks(data_dir, ready, |state| state.remove_read_mark(key))
}

#[cfg(test)]
mod tests {
    use super::state_file::{LoadNote, MotionSetting};
    use super::*;

    fn mark(id: &str, at_ms: Option<u64>) -> ReadMark {
        ReadMark {
            id: id.into(),
            at_ms,
        }
    }

    fn row(id: &str, outgoing: bool, at_ms: u64) -> Row<'_> {
        Row {
            id,
            outgoing,
            at_ms,
        }
    }

    const BOB: &str = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

    #[test]
    fn a_later_marker_wins_and_nothing_moves_back() {
        // The history's order where both are in it, whatever the times say
        // (a friend's clock may be behind).
        let order = ["m1", "m2", "m3"];
        let place = |id: &str| order.iter().position(|m| *m == id);
        let (m2, m3) = (mark("m2", Some(900)), mark("m3", Some(100)));
        assert!(later(&m3, &m2, &place));
        assert!(!later(&m2, &m3, &place));
        // Not both in it: the times; equal times keep the current one.
        let unknown = mark("m9", Some(950));
        assert!(later(&unknown, &m2, &place));
        assert!(!later(&m2, &unknown, &place));
        assert!(!later(&mark("m9", Some(900)), &m2, &place));
        // A time beats none; none never replaces anything.
        let legacy = mark("m7", None);
        assert!(later(&m2, &legacy, &|_| None));
        assert!(!later(&legacy, &m2, &|_| None));
        assert!(!later(&legacy, &mark("m8", None), &|_| None));
        // The same message: later only when it brings its time.
        assert!(later(&mark("M2", Some(900)), &mark("m2", None), &place));
        assert!(!later(&mark("m2", Some(900)), &m2, &place));
        assert!(!later(&mark("m2", None), &m2, &place));
    }

    #[test]
    fn unread_counts_theirs_after_the_marker() {
        let rows = [
            row("m1", false, 10),
            row("m2", true, 20),
            row("m3", false, 30),
            row("m4", false, 40),
        ];
        assert_eq!(unread(rows, None), 3);
        assert_eq!(unread(rows, Some(&mark("m1", None))), 2);
        assert_eq!(unread(rows, Some(&mark("M3", Some(30)))), 1);
        assert_eq!(unread(rows, Some(&mark("m4", Some(40)))), 0);
        // Your own message read: theirs after it.
        assert_eq!(unread(rows, Some(&mark("m2", Some(20)))), 2);
        // Its message is not there: theirs after its time, or all of them.
        assert_eq!(unread(rows, Some(&mark("gone", Some(35)))), 1);
        assert_eq!(unread(rows, Some(&mark("gone", None))), 3);
        // Yours are never unread.
        assert_eq!(unread([row("m5", true, 50)], None), 0);
    }

    #[test]
    fn a_time_counts_only_with_its_own_message() {
        let mut state = TuiState::default();
        state.set_read_mark(BOB, mark("m2", Some(20)));
        assert_eq!(state.read_mark(BOB), Some(mark("m2", Some(20))));
        // An older app moved the marker and kept the time of the one before.
        state.last_read.insert(BOB.into(), "m3".into());
        assert_eq!(state.read_mark(BOB), Some(mark("m3", None)));
        state.set_read_mark(BOB, mark("m4", None));
        assert!(state.last_read_at.is_empty());
        assert!(state.remove_read_mark(BOB));
        assert!(!state.remove_read_mark(BOB));
        assert_eq!(state.read_mark(BOB), None);
    }

    #[test]
    fn marks_from_the_other_app_are_merged_never_backwards() {
        let alice = "a1".repeat(32);
        let mut state = TuiState::default();
        state.set_read_mark(BOB, mark("m3", Some(30)));
        let theirs = ReadMarks::from([
            (BOB.to_owned(), mark("m2", Some(20))),
            (alice.clone(), mark("a1", None)),
        ]);
        assert!(state.take_later(&theirs, &no_place));
        assert_eq!(state.read_mark(BOB), Some(mark("m3", Some(30))), "kept");
        assert_eq!(state.read_mark(&alice), Some(mark("a1", None)), "added");
        let newer = ReadMarks::from([(BOB.to_owned(), mark("m4", Some(40)))]);
        assert!(state.take_later(&newer, &no_place));
        assert_eq!(state.read_mark(BOB), Some(mark("m4", Some(40))));
        assert!(!state.take_later(&newer, &no_place), "nothing new");
    }

    #[test]
    fn two_apps_saving_at_once_keep_the_later_marker() {
        let dir = tempfile::tempdir().unwrap();
        let ready = controller::identity_ready_for_tests();
        // This app read Bob up to m2 and saves a setting; the desktop app
        // marked m3 meanwhile.
        let mut app = TuiState {
            motion: MotionSetting::Reduced,
            ..TuiState::default()
        };
        app.set_read_mark(BOB, mark("m2", Some(20)));
        let mut desktop = TuiState::default();
        desktop.set_read_mark(BOB, mark("m3", Some(30)));
        desktop
            .save(dir.path(), &ready)
            .expect("the desktop's save");
        app.save(dir.path(), &ready).expect("this app's save");
        let (saved, note) = state_file::load(dir.path());
        assert_eq!(note, LoadNote::Loaded);
        assert_eq!(saved.motion, MotionSetting::Reduced);
        assert_eq!(saved.read_mark(BOB), Some(mark("m3", Some(30))));
        // A mark for an older message changes nothing; a newer one does.
        let marks = |id: &str, at_ms| ReadMarks::from([(BOB.to_owned(), mark(id, Some(at_ms)))]);
        let take = |marks: ReadMarks| {
            state_file::update_marks(dir.path(), &ready, |state| {
                state.take_later(&marks, &no_place)
            })
        };
        assert_eq!(take(marks("m1", 10)), Ok(false));
        assert_eq!(take(marks("m4", 40)), Ok(true));
        assert_eq!(load(dir.path()).get(BOB), Some(&mark("m4", Some(40))));
        // Forgetting takes it out of the file too.
        assert_eq!(forget(dir.path(), &ready, BOB), Ok(true));
        assert_eq!(load(dir.path()).get(BOB), None);
        assert_eq!(forget(dir.path(), &ready, BOB), Ok(false));
    }

    #[test]
    fn a_corrupt_file_gives_no_markers_and_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let ready = controller::identity_ready_for_tests();
        let file = state_file::path(dir.path());
        for text in ["{\"last_read\": tru", "{\"last_read_at\": [1]}", "null"] {
            std::fs::write(&file, text).unwrap();
            assert!(load(dir.path()).is_empty());
            let marked = state_file::update_marks(dir.path(), &ready, |state| {
                state.set_read_mark(BOB, mark("m1", Some(1)));
                true
            });
            assert!(
                marked
                    .as_ref()
                    .is_err_and(|why| why.contains(state_file::FILE_NAME)),
                "{marked:?}"
            );
            assert_eq!(std::fs::read_to_string(&file).unwrap(), text, "left alone");
        }
        // Missing: nothing to read, and a mark makes it.
        std::fs::remove_file(&file).unwrap();
        assert!(load(dir.path()).is_empty());
        assert_eq!(
            state_file::update_marks(dir.path(), &ready, |state| {
                state.set_read_mark(BOB, mark("m1", Some(1)));
                true
            }),
            Ok(true)
        );
        assert_eq!(load(dir.path()).get(BOB), Some(&mark("m1", Some(1))));
    }

    #[test]
    fn the_desktop_engine_marks_only_once_the_identity_is_there() {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let place = |_: &str| None;
        let refused = mark_read(dir.path(), BOB, mark("m1", Some(1)), &place);
        assert!(refused.is_err(), "{refused:?}");
        assert!(!state_file::path(dir.path()).exists());
        let wizard = controller::Controller::new(dir.path());
        wizard.create_identity().result.expect("create");
        let upper = BOB.to_ascii_uppercase();
        assert_eq!(
            mark_read(dir.path(), &upper, mark("m2", Some(2)), &place),
            Ok(true)
        );
        assert_eq!(
            mark_read(dir.path(), BOB, mark("m1", Some(1)), &place),
            Ok(false),
            "never back"
        );
        assert_eq!(load(dir.path()).get(BOB), Some(&mark("m2", Some(2))));
        // What every terminal app reads is there, beside the time.
        let text = std::fs::read_to_string(state_file::path(dir.path())).unwrap();
        let file: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(file["last_read"][BOB], "m2");
        assert_eq!(file["last_read_at"][BOB]["at_ms"], 2);
    }
}
