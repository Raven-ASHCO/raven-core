//! Raven's wall clock (cutoff pack CP.3: Phase 5 P5.1 and P5.2).
//!
//! Every wall-clock read in raven-core, raven-node and ash comes through
//! [`now_ms`] or [`now`]: the times Raven stores or signs, validity windows,
//! deadlines, expiry, prune and retry times, and raven-node's wake detector.
//!
//! - **Lab offset.** A debug build with the lab unlock (`RAVEN_LAB_TEST_A=1`)
//!   adds the signed offset in milliseconds held in the file named by
//!   `RAVEN_LAB_CLOCK_FILE`, so a harness can move one profile's ash and
//!   raven-node days ahead or back while they run. The file is read again at
//!   most every [`LAB_CLOCK_REFRESH`]; a missing, unreadable or out-of-range
//!   file (beyond [`LAB_CLOCK_MAX_OFFSET_MS`] either way) is no offset. A jump
//!   ahead looks like a wake from sleep to raven-node's netwatch (intended).
//! - **Release builds** read neither the environment nor the file: their clock
//!   is the system clock.
//! - **Not wall time.** Monotonic timers (`Instant`, tokio, libp2p) never move.
//!   [`system_now`] is the system clock without the offset, only for comparing
//!   with a time the operating system stamped itself (a file's modification
//!   time).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The largest lab offset either way: 400 days.
pub const LAB_CLOCK_MAX_OFFSET_MS: i64 = 400 * 24 * 60 * 60 * 1000;

/// One read of the lab clock file serves this long.
pub const LAB_CLOCK_REFRESH: Duration = Duration::from_millis(200);

/// A longer lab clock file is unreadable (an offset fits in far less).
const LAB_CLOCK_FILE_MAX_BYTES: u64 = 64;

/// Milliseconds since the Unix epoch on Raven's wall clock (0 before 1970).
pub fn now_ms() -> u64 {
    epoch_ms(now())
}

/// Raven's wall clock: the system clock plus the lab offset (a debug build
/// with the lab unlock and `RAVEN_LAB_CLOCK_FILE` only).
pub fn now() -> SystemTime {
    shift(SystemTime::now(), lab_offset_ms())
}

/// The system clock without the lab offset. Only for comparing with a time
/// the operating system stamped itself (a file's modification time), never
/// for a time Raven stores, signs or holds a deadline against: [`now_ms`].
pub fn system_now() -> SystemTime {
    SystemTime::now()
}

/// A time the operating system stamped (a file's modification time) on
/// Raven's clock, to set beside times Raven recorded: moved by the lab offset
/// in force now.
pub fn from_system(stamped: SystemTime) -> SystemTime {
    shift(stamped, lab_offset_ms())
}

fn epoch_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `t` moved by `offset_ms`; unchanged where the result cannot be represented.
fn shift(t: SystemTime, offset_ms: i64) -> SystemTime {
    let by = Duration::from_millis(offset_ms.unsigned_abs());
    if offset_ms >= 0 {
        t.checked_add(by)
    } else {
        t.checked_sub(by)
    }
    .unwrap_or(t)
}

/// The lab offset in force now ([`lab_offset`] over this build and process).
fn lab_offset_ms() -> i64 {
    #[cfg(test)]
    if let Some(offset) = THIS_THREAD.with(std::cell::Cell::get) {
        return offset;
    }
    lab_offset(
        cfg!(debug_assertions),
        crate::pair_init::lab_test_a_enabled,
        || std::env::var_os("RAVEN_LAB_CLOCK_FILE").map(PathBuf::from),
        |path| cached_offset(path, Instant::now()),
    )
}

/// Pure: 0 unless `debug`, then the lab unlock, then a file named (asked in
/// that order, so a release build asks nothing); otherwise what `read` says
/// that file holds.
fn lab_offset(
    debug: bool,
    test_a: impl FnOnce() -> bool,
    file: impl FnOnce() -> Option<PathBuf>,
    read: impl FnOnce(&Path) -> i64,
) -> i64 {
    if !debug || !test_a() {
        return 0;
    }
    file().map_or(0, |path| read(&path))
}

/// The last read of a lab clock file: which file, when, and what it held.
struct LabRead {
    path: PathBuf,
    at: Instant,
    offset: i64,
}

static LAB_READ: Mutex<Option<LabRead>> = Mutex::new(None);

fn cached_offset(path: &Path, now: Instant) -> i64 {
    let mut last = LAB_READ.lock().unwrap_or_else(|e| e.into_inner());
    refresh(&mut last, path, now, read_offset_file)
}

/// `last` while it is the same file and younger than [`LAB_CLOCK_REFRESH`];
/// otherwise `read` again (and remember it).
fn refresh(
    last: &mut Option<LabRead>,
    path: &Path,
    now: Instant,
    read: impl FnOnce(&Path) -> i64,
) -> i64 {
    if let Some(r) = last.as_ref() {
        if r.path == path && now.saturating_duration_since(r.at) < LAB_CLOCK_REFRESH {
            return r.offset;
        }
    }
    let offset = read(path);
    *last = Some(LabRead {
        path: path.to_path_buf(),
        at: now,
        offset,
    });
    offset
}

/// What a lab clock file holds: signed decimal milliseconds (surrounding
/// whitespace allowed), at most [`LAB_CLOCK_MAX_OFFSET_MS`] either way.
/// Anything else is 0: missing, unreadable, too long, not a whole number,
/// out of range.
fn read_offset_file(path: &Path) -> i64 {
    let mut text = String::new();
    let read = std::fs::File::open(path).and_then(|f| {
        f.take(LAB_CLOCK_FILE_MAX_BYTES + 1)
            .read_to_string(&mut text)
    });
    match read {
        Ok(n) if n as u64 <= LAB_CLOCK_FILE_MAX_BYTES => parse_offset(&text).unwrap_or(0),
        _ => 0,
    }
}

fn parse_offset(text: &str) -> Option<i64> {
    text.trim()
        .parse::<i64>()
        .ok()
        .filter(|ms| ms.unsigned_abs() <= LAB_CLOCK_MAX_OFFSET_MS.unsigned_abs())
}

#[cfg(test)]
thread_local! {
    static THIS_THREAD: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
}

/// Tests only: `Some(offset)` puts this thread's clock `offset` ms off the
/// system clock (no lab unlock or file needed); `None` gives it back.
#[cfg(test)]
pub fn set_for_this_thread(offset: Option<i64>) {
    THIS_THREAD.with(|c| c.set(offset));
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: i64 = 24 * 60 * 60 * 1000;
    /// Two reads of the system clock a test compares are never this far apart.
    const SLACK_MS: i64 = 5_000;

    fn system_ms() -> i64 {
        epoch_ms(SystemTime::now()) as i64
    }

    #[test]
    fn lab_offset_applies_in_debug_with_test_a_only() {
        let named = || Some(PathBuf::from("lab/clock"));
        assert_eq!(lab_offset(true, || true, named, |_| 2 * DAY_MS), 2 * DAY_MS);
        assert_eq!(lab_offset(true, || true, named, |_| -DAY_MS), -DAY_MS);
        assert_eq!(
            lab_offset(
                true,
                || false,
                || panic!("named a file without the lab unlock"),
                |_| panic!("read a file without the lab unlock"),
            ),
            0
        );
        assert_eq!(
            lab_offset(
                true,
                || true,
                || None,
                |_| panic!("read with no file named")
            ),
            0
        );
        // This process: exactly what its build and environment say.
        let file = std::env::var_os("RAVEN_LAB_CLOCK_FILE");
        let want = match file {
            Some(f) if cfg!(debug_assertions) && crate::pair_init::lab_test_a_enabled() => {
                read_offset_file(Path::new(&f))
            }
            _ => 0,
        };
        let (before, ours, after) = (system_ms(), now_ms() as i64, system_ms());
        assert!(
            ours - want >= before - SLACK_MS && ours - want <= after + SLACK_MS,
            "now_ms {ours}, system {before}..{after}, lab offset {want}"
        );
    }

    #[test]
    fn unreadable_or_out_of_range_file_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("clock");
        let max = LAB_CLOCK_MAX_OFFSET_MS;
        for (text, offset) in [
            ("0".to_string(), 0),
            ("86400000".into(), DAY_MS),
            ("  -172800000\n".into(), -2 * DAY_MS),
            ("+5".into(), 5),
            (max.to_string(), max),
            ((-max).to_string(), -max),
            ((max + 1).to_string(), 0),
            ((-max - 1).to_string(), 0),
            (i64::MIN.to_string(), 0),
            ("9223372036854775808".into(), 0),
            ("".into(), 0),
            ("soon".into(), 0),
            ("1.5".into(), 0),
            ("1e3".into(), 0),
            ("1 000".into(), 0),
            ("0x10".into(), 0),
        ] {
            std::fs::write(&file, &text).unwrap();
            assert_eq!(read_offset_file(&file), offset, "{text:?}");
        }
        // Too long, though a number: a lab file is never that.
        std::fs::write(&file, format!("{}1", " ".repeat(64))).unwrap();
        assert_eq!(read_offset_file(&file), 0);
        std::fs::write(&file, b"\xff1").unwrap();
        assert_eq!(read_offset_file(&file), 0, "not UTF-8");
        assert_eq!(read_offset_file(&dir.path().join("missing")), 0);
        assert_eq!(read_offset_file(dir.path()), 0, "a directory");
    }

    #[test]
    fn cache_refreshes_within_200ms() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, "1000").unwrap();
        std::fs::write(&b, "-3000").unwrap();
        let reads = std::cell::Cell::new(0);
        let read = |p: &Path| {
            reads.set(reads.get() + 1);
            read_offset_file(p)
        };
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut last = None;
        assert_eq!(refresh(&mut last, &a, t0, read), 1000);
        std::fs::write(&a, "2000").unwrap();
        // Served from the last read for 200 ms, then read again.
        assert_eq!(refresh(&mut last, &a, at(100), read), 1000);
        assert_eq!(refresh(&mut last, &a, at(199), read), 1000);
        assert_eq!(reads.get(), 1);
        assert_eq!(refresh(&mut last, &a, at(200), read), 2000);
        assert_eq!(reads.get(), 2);
        // Another file is read at once, whatever the age.
        assert_eq!(refresh(&mut last, &b, at(201), read), -3000);
        assert_eq!(refresh(&mut last, &a, at(202), read), 2000);
        assert_eq!(reads.get(), 4);
        // The live cache serves the same rule (no other test names this file).
        let c = dir.path().join("c");
        std::fs::write(&c, "7").unwrap();
        assert_eq!(cached_offset(&c, t0), 7);
    }

    /// Runs in both builds. The release test job runs it with the lab unlock
    /// on; it also names a clock file 10 days ahead, and the clock is still
    /// the system clock there. A debug build checks the pure rule only (it
    /// must not change the environment the other tests share).
    #[test]
    fn lab_clock_is_inert_without_debug_assertions() {
        assert_eq!(
            lab_offset(
                false,
                || panic!("release read the lab unlock"),
                || panic!("release read RAVEN_LAB_CLOCK_FILE"),
                |_| panic!("release read a clock file"),
            ),
            0
        );
        if cfg!(debug_assertions) {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("clock");
        std::fs::write(&file, (10 * DAY_MS).to_string()).unwrap();
        // Edition 2021: a plain call. No release test reads these variables.
        std::env::set_var("RAVEN_LAB_TEST_A", "1");
        std::env::set_var("RAVEN_LAB_CLOCK_FILE", &file);
        let (before, ours, after) = (system_ms(), now_ms() as i64, system_ms());
        assert!(
            ours >= before - SLACK_MS && ours <= after + SLACK_MS,
            "now_ms {ours}, system {before}..{after}"
        );
        let wall = epoch_ms(now()) as i64;
        assert!((wall - system_ms()).abs() <= SLACK_MS, "now {wall}");
    }

    /// The override replaces any lab offset this process runs with (the
    /// suite may run on a lab clock), on this thread only.
    #[test]
    fn a_thread_override_moves_only_that_thread() {
        let base = now_ms() as i64;
        set_for_this_thread(Some(-DAY_MS));
        let (system, moved) = (system_ms(), now_ms() as i64);
        let stamped = epoch_ms(from_system(SystemTime::now())) as i64;
        let other = std::thread::spawn(now_ms).join().unwrap() as i64;
        set_for_this_thread(None);
        let back = now_ms() as i64;
        assert!(
            (moved + DAY_MS - system).abs() <= SLACK_MS,
            "{moved} vs {system}"
        );
        assert!((stamped - moved).abs() <= SLACK_MS, "{stamped} vs {moved}");
        assert!((other - base).abs() <= SLACK_MS, "{other} vs {base}");
        assert!((back - base).abs() <= SLACK_MS, "{back} vs {base}");
    }

    /// Regression (raven-node's `pre_epoch_clock_reads_as_zero`): a system
    /// clock set before 1970, or moved there, reads as 0 and never panics.
    #[test]
    fn a_clock_before_1970_reads_as_zero() {
        assert_eq!(epoch_ms(UNIX_EPOCH - Duration::from_secs(5)), 0);
        assert_eq!(epoch_ms(UNIX_EPOCH + Duration::from_millis(1234)), 1234);
        assert_eq!(epoch_ms(shift(UNIX_EPOCH, -1)), 0);
        assert_eq!(shift(UNIX_EPOCH, -1), UNIX_EPOCH - Duration::from_millis(1));
        assert_eq!(shift(UNIX_EPOCH, 1), UNIX_EPOCH + Duration::from_millis(1));
    }

    // ---- P5.2: the source rule ----

    /// Every wall-clock read in raven-core, raven-node and ash goes through
    /// this module: no `SystemTime::now` outside clock.rs, except in test code
    /// (`#[cfg(test)]` and `#[test]` items, test-only module files).
    /// Comments and string literals are not code.
    #[test]
    fn no_wall_clock_reads_outside_clock_rs() {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let this = crates.join("raven-core").join("src").join("clock.rs");
        let mut found = Vec::new();
        let mut scanned = 0;
        for krate in ["raven-core", "raven-node", "ash"] {
            let mut files = Vec::new();
            rs_files(&crates.join(krate).join("src"), &mut files);
            files.sort();
            let codes: Vec<(PathBuf, Vec<char>)> = files
                .into_iter()
                .map(|f| {
                    let text = std::fs::read_to_string(&f)
                        .unwrap_or_else(|e| panic!("{}: {e}", f.display()));
                    (f, code_only(&text))
                })
                .collect();
            // `#[cfg(test)] mod name;` makes name.rs (and name/) test code.
            let mut test_mods = Vec::new();
            for (file, code) in &codes {
                let base = module_dir(file);
                test_mods.extend(test_items(code).1.into_iter().map(|m| base.join(m)));
            }
            for (file, code) in &codes {
                scanned += 1;
                let test_file = test_mods
                    .iter()
                    .any(|m| *file == m.with_extension("rs") || file.starts_with(m));
                if *file == this || test_file {
                    continue;
                }
                for line in wall_clock_reads(code) {
                    let shown = file.strip_prefix(&crates).unwrap_or(file);
                    found.push(format!("{}:{line}", shown.display()));
                }
            }
        }
        assert!(scanned > 100, "only {scanned} files under node/crates");
        assert!(
            found.is_empty(),
            "read the wall clock through raven_core::clock::now_ms (or now; system_now \
             only against an OS-stamped file time):\n{}",
            found.join("\n")
        );
    }

    /// The scanner itself: code is found, test code, comments and literals
    /// are not, and a test-only module declaration names its file.
    #[test]
    fn the_wall_clock_scanner_sees_code_only() {
        let text = r##"
use std::time::SystemTime;
fn real() -> SystemTime { SystemTime::now() }
// SystemTime::now() in a comment
/* SystemTime::now() /* nested */ still a comment */
const S: &str = "SystemTime::now() } {";
const R: &str = r#"SystemTime::now() "} "#;
const C: [char; 3] = ['{', '\'', '"'];
fn life<'a>(x: &'a str) -> &'a str { x }
#[cfg(test)]
mod tests {
    fn t() { let _ = std::time::SystemTime::now(); }
}
#[cfg(all(test, unix))]
fn helper(x: [u8; 2]) { SystemTime::now(); }
#[cfg(any(test, unix))]
fn shared() { SystemTime::now(); }
#[cfg(test)]
mod more;
#[cfg(test)] use std::time::{Duration, Instant};
fn after() { Box::new(SystemTime::now); }
"##;
        let code = code_only(text);
        assert_eq!(wall_clock_reads(&code), [3, 17, 21]);
        assert_eq!(test_items(&code).1, ["more"]);
        assert_eq!(
            wall_clock_reads(&code_only("#![cfg(test)]\nfn f() { SystemTime::now(); }")),
            Vec::<usize>::new()
        );
        assert_eq!(
            module_dir(Path::new("src/a/b.rs")),
            Path::new("src/a/b").to_path_buf()
        );
        assert_eq!(
            module_dir(Path::new("src/a/mod.rs")),
            Path::new("src/a").to_path_buf()
        );
    }

    const NEEDLE: &str = "SystemTime::now";

    /// 1-based lines of `NEEDLE` in `code` outside test items.
    fn wall_clock_reads(code: &[char]) -> Vec<usize> {
        let (tests, _) = test_items(code);
        let needle: Vec<char> = NEEDLE.chars().collect();
        (0..code.len())
            .filter(|&i| code[i..].starts_with(&needle))
            .filter(|&i| !tests.iter().any(|&(from, to)| (from..to).contains(&i)))
            .map(|i| 1 + code[..i].iter().filter(|&&c| c == '\n').count())
            .collect()
    }

    fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// Where `mod name;` in `file` looks for name.rs.
    fn module_dir(file: &Path) -> PathBuf {
        let dir = file.parent().unwrap_or(Path::new(""));
        match file.file_stem().and_then(|s| s.to_str()) {
            Some("mod" | "lib" | "main") | None => dir.to_path_buf(),
            Some(stem) => dir.join(stem),
        }
    }

    /// `text` with comments and the insides of string and char literals
    /// blanked (newlines kept), so braces and words in them are not code.
    fn code_only(text: &str) -> Vec<char> {
        let s: Vec<char> = text.chars().collect();
        let mut out = s.clone();
        let ident = |c: char| c.is_alphanumeric() || c == '_';
        // `r"`, `r#"`, `br##"`...: the number of hashes.
        let raw = |i: usize| -> Option<usize> {
            let hashes = s[i + 1..].iter().take_while(|&&c| c == '#').count();
            let prefix_ok =
                i == 0 || !ident(s[i - 1]) || (s[i - 1] == 'b' && (i < 2 || !ident(s[i - 2])));
            (prefix_ok && s.get(i + 1 + hashes) == Some(&'"')).then_some(hashes)
        };
        let mut i = 0;
        while i < s.len() {
            let start = i;
            match s[i] {
                '/' if s.get(i + 1) == Some(&'/') => {
                    while i < s.len() && s[i] != '\n' {
                        i += 1;
                    }
                }
                '/' if s.get(i + 1) == Some(&'*') => {
                    let mut depth = 0;
                    while i < s.len() {
                        if s[i] == '/' && s.get(i + 1) == Some(&'*') {
                            depth += 1;
                            i += 2;
                        } else if s[i] == '*' && s.get(i + 1) == Some(&'/') {
                            depth -= 1;
                            i += 2;
                            if depth == 0 {
                                break;
                            }
                        } else {
                            i += 1;
                        }
                    }
                }
                '"' => {
                    i += 1;
                    while i < s.len() && s[i] != '"' {
                        i += if s[i] == '\\' { 2 } else { 1 };
                    }
                    i += 1;
                }
                'r' if raw(i).is_some() => {
                    let hashes = raw(i).unwrap_or(0);
                    i += 2 + hashes;
                    while i < s.len() {
                        if s[i] == '"' && (1..=hashes).all(|k| s.get(i + k) == Some(&'#')) {
                            i += 1 + hashes;
                            break;
                        }
                        i += 1;
                    }
                }
                '\'' if s.get(i + 1) == Some(&'\\') => {
                    i += 3;
                    while i < s.len() && s[i] != '\'' {
                        i += 1;
                    }
                    i += 1;
                }
                '\'' if s.get(i + 2) == Some(&'\'') => i += 3,
                // Code, a lifetime or a label included.
                _ => {
                    i += 1;
                    continue;
                }
            }
            let end = i.min(s.len());
            for c in &mut out[start..end] {
                if *c != '\n' {
                    *c = ' ';
                }
            }
            i = end;
        }
        out
    }

    /// The char ranges of test items in `code` (from [`code_only`]), and the
    /// names of the test-only module files they declare (`mod name;`). An
    /// inner `#![cfg(test)]` makes the whole file one test item.
    fn test_items(code: &[char]) -> (Vec<(usize, usize)>, Vec<String>) {
        let (mut ranges, mut mods) = (Vec::new(), Vec::new());
        let mut i = 0;
        while i < code.len() {
            let inner = code.get(i + 1) == Some(&'!');
            let open = i + 1 + usize::from(inner);
            if code[i] != '#' || code.get(open) != Some(&'[') {
                i += 1;
                continue;
            }
            let Some(close) = matching(code, open, '[', ']') else {
                break;
            };
            let attr: String = code[open..=close]
                .iter()
                .filter(|c| !c.is_whitespace())
                .collect();
            if !is_test_attr(&attr) {
                i = close + 1;
                continue;
            }
            if inner {
                return (vec![(0, code.len())], mods);
            }
            let (end, item) = item_after(code, close + 1);
            mods.extend(mod_file(&item));
            ranges.push((i, end));
            i = end;
        }
        (ranges, mods)
    }

    /// `[test]`, `[tokio::test...]`, `[cfg(test)]`, `[cfg(all(.., test, ..))]`
    /// (whitespace removed). `any(test, ..)` and `not(test)` are not test-only.
    fn is_test_attr(attr: &str) -> bool {
        if attr == "[test]" || attr.starts_with("[tokio::test") {
            return true;
        }
        let Some(cfg) = attr
            .strip_prefix("[cfg(")
            .and_then(|a| a.strip_suffix(")]"))
        else {
            return false;
        };
        cfg == "test"
            || cfg
                .strip_prefix("all(")
                .and_then(|a| a.strip_suffix(')'))
                .is_some_and(|args| {
                    let mut depth = 0;
                    args.split(|c| {
                        match c {
                            '(' => depth += 1,
                            ')' => depth -= 1,
                            _ => {}
                        }
                        c == ',' && depth == 0
                    })
                    .any(|a| a == "test")
                })
    }

    /// The index of the bracket closing the one at `open`.
    fn matching(code: &[char], open: usize, l: char, r: char) -> Option<usize> {
        let mut depth = 0;
        for (i, &c) in code.iter().enumerate().skip(open) {
            if c == l {
                depth += 1;
            } else if c == r {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
        }
        None
    }

    /// The item starting at `i` (after more attributes): where it ends (past
    /// its `;` or its block's `}`) and its text.
    fn item_after(code: &[char], mut i: usize) -> (usize, String) {
        loop {
            while code.get(i).is_some_and(|c| c.is_whitespace()) {
                i += 1;
            }
            if code.get(i) == Some(&'#') && code.get(i + 1) == Some(&'[') {
                match matching(code, i + 1, '[', ']') {
                    Some(close) => i = close + 1,
                    None => return (code.len(), String::new()),
                }
            } else {
                break;
            }
        }
        let start = i;
        let mut depth = 0;
        while i < code.len() {
            match code[i] {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                ';' if depth == 0 => return (i + 1, code[start..=i].iter().collect()),
                '{' if depth == 0 => {
                    let end = matching(code, i, '{', '}').unwrap_or(code.len() - 1);
                    return (end + 1, code[start..=end].iter().collect());
                }
                _ => {}
            }
            i += 1;
        }
        (code.len(), String::new())
    }

    /// `name` for an item `[pub..] mod name;`.
    fn mod_file(item: &str) -> Option<String> {
        let words: Vec<&str> = item.trim().strip_suffix(';')?.split_whitespace().collect();
        let at = words.iter().position(|&w| w == "mod")?;
        let name = *words.get(at + 1)?;
        (at + 2 == words.len() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
            .then(|| name.to_string())
    }
}
