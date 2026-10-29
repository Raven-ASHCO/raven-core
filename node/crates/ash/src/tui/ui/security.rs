//! SEC (Phase 6b design A, step P6.31): the open security alerts and
//! warnings, the most severe and the latest first, each with what happened,
//! what Raven did and what the person can do, in security_text.rs's words
//! (the one English table the CLI reads too, through bridge.rs). D shows the
//! chosen one's details, R resolves it, V compares security words with the
//! friend it is about; W or Esc closes. Notices are not listed: one line
//! counts them.
//!
//! No row names an address, a message id or a whole key: a verified
//! friend's key shows as its first 8 hex characters, in the details only
//! (security_cli.rs words them). Every text is shaped by display.rs before
//! it is drawn: names in it are untrusted.

use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::app::{App, SecState};
#[cfg(test)]
use super::app::{Cmd, JobResult, Msg, Overlay, Screen, StoreJob, VerifyStep};
use super::bridge::{self, SecAct, SecKept, SecNotice};
#[cfg(test)]
use super::bridge::{NoticeText, SecurityView};
#[cfg(test)]
use super::controller::Conversations;
#[cfg(test)]
use super::home;
#[cfg(test)]
use super::state_file::Receive;
#[cfg(test)]
use super::workers::PollUpdate;
use super::{cells, display, overlays, widgets, wrap, Look};
#[cfg(test)]
use super::{testkit, theme};

const TITLE: &str = " Security ";
/// SEC's largest size, in cells; smaller in a smaller terminal.
const WIDTH: u16 = 76;
const HEIGHT: u16 = 24;

/// Before the first read answered.
const READING: &str = "Reading Raven's security notices";
const NOTHING_OPEN: &str = "No open security alerts.";
const UNREADABLE: &str = "Raven can't read its security notices right now.";
/// The parts of one notice.
const DID: &str = "What Raven did: ";
const TODO: &str = "What you can do: ";
/// Notice rows sit this far in, under the marker and the mark.
const INDENT: u16 = 4;

/// Draws SEC over the screen: its rows scrolled to keep the chosen notice
/// in view, its keys on the bottom border.
pub(super) fn render(f: &mut Frame, area: Rect, app: &App, sec: SecState) {
    let look = app.look();
    let rect = overlays::centered(area, WIDTH, HEIGHT);
    let mut bar = widgets::key_bar(look, &keys(app, sec), rect.width.saturating_sub(4));
    bar.spans.insert(0, Span::raw(" "));
    bar.spans.push(Span::raw(" "));
    let block = overlays::overlay_block(look)
        .title(Span::styled(TITLE, look.theme.title))
        .title_bottom(bar);
    let inner = block.inner(rect);
    let (rows, chosen) = lines(app, sec, inner.width);
    let top = top_row(chosen, rows.len(), inner.height);
    widgets::clear(f, rect, look);
    f.render_widget(Paragraph::new(rows).block(block).scroll((top, 0)), rect);
}

/// SEC's keys for the notice chosen now, the most needed first (a narrow
/// window cuts the last): V only for one about a saved friend, R and D only
/// while one is open.
fn keys(app: &App, sec: SecState) -> Vec<(&'static str, &'static str)> {
    let mut keys = vec![("Esc", "Close")];
    let chosen = app.notices().get(sec.chosen);
    if chosen.is_some() {
        keys.push(("R", "Resolve"));
    }
    if chosen.is_some_and(|notice| compare_offered(app, notice)) {
        keys.push(("V", "Compare words"));
    }
    if chosen.is_some() {
        keys.push((
            "D",
            if sec.details {
                "Hide details"
            } else {
                "Details"
            },
        ));
    }
    if app.notices().len() > 1 {
        keys.push((app.look().glyphs.up_down, "Choose"));
    }
    keys
}

/// V compares security words with the friend `notice` is about: a saved
/// one, and a notice whose action is to compare them.
fn compare_offered(app: &App, notice: &SecNotice) -> bool {
    notice.text.act == SecAct::CompareWords
        && notice
            .peer
            .as_deref()
            .is_some_and(|peer| app.friend(peer).is_some())
}

/// The first row drawn: the chosen notice's rows (`chosen`: first, end)
/// in view, its start first when they don't all fit.
fn top_row(chosen: (usize, usize), rows: usize, height: u16) -> u16 {
    let height = usize::from(height);
    let max = rows.saturating_sub(height);
    let (start, end) = chosen;
    let top = end.saturating_sub(height).min(start).min(max);
    u16::try_from(top).unwrap_or(u16::MAX)
}

/// SEC's rows at `width` cells, and where the chosen notice's rows are
/// (first, end): the alerts and warnings, then the security notices from
/// the Raven project (P6.45).
pub(super) fn lines(app: &App, sec: SecState, width: u16) -> (Vec<Line<'static>>, (usize, usize)) {
    let look = app.look();
    let Some(read) = app.security() else {
        let text = format!("{READING}{}", look.glyphs.ellipsis);
        return (plain(&text, width), (0, 0));
    };
    let (mut rows, chosen) = alert_lines(app, read, sec, width);
    rows.extend(update_rows(look, &read.updates, width));
    (rows, chosen)
}

/// `text` wrapped at `width` cells, plain.
fn plain(text: &str, width: u16) -> Vec<Line<'static>> {
    wrap(&shaped(text), width, 0)
        .into_iter()
        .map(Line::raw)
        .collect()
}

/// The open alerts and warnings (or why none is listed), and where the
/// chosen one's rows are.
fn alert_lines(
    app: &App,
    read: &bridge::SecurityView,
    sec: SecState,
    width: u16,
) -> (Vec<Line<'static>>, (usize, usize)) {
    let look = app.look();
    let t = &look.theme;
    let plain = |text: &str| plain(text, width);
    match read.kept {
        SecKept::Off => return (plain(bridge::NOT_IN_THIS_VERSION), (0, 0)),
        SecKept::Unsealed => return (plain(bridge::NOT_KEPT_UNSEALED), (0, 0)),
        SecKept::Live => {}
    }
    if read.unreadable.is_some() {
        return (plain(UNREADABLE), (0, 0));
    }
    let mut rows = Vec::new();
    rows.push(Line::styled(summary(&read.notices), t.accent));
    let mut chosen = (0, 0);
    for (i, notice) in read.notices.iter().enumerate() {
        rows.push(Line::default());
        let start = rows.len();
        let here = i == sec.chosen;
        rows.extend(notice_rows(look, notice, here, width));
        if here && sec.details {
            rows.extend(detail_rows(look, notice, width));
        }
        if here {
            chosen = (start, rows.len());
        }
    }
    if read.counted > 0 {
        rows.push(Line::default());
        rows.extend(
            wrap(&bridge::notices_line(read.counted), width, 0)
                .into_iter()
                .map(|row| Line::styled(row, t.secondary)),
        );
    }
    (rows, chosen)
}

/// The security notices from the Raven project (P6.45), under a blank row:
/// raven-core's lines, each a paragraph after a dash, shaped like every
/// other text here (the notice's own text is the project's, sanitized
/// already). Nothing while that gate is shut.
fn update_rows(look: &Look, updates: &[String], width: u16) -> Vec<Line<'static>> {
    if updates.is_empty() {
        return Vec::new();
    }
    let mut rows = vec![Line::default()];
    for text in updates {
        rows.extend(
            wrap(&format!("- {}", shaped(text)), width, 2)
                .into_iter()
                .map(|row| Line::styled(row, look.theme.secondary)),
        );
    }
    rows
}

/// "2 open: 1 alert, 1 warning", or that none is.
fn summary(notices: &[SecNotice]) -> String {
    if notices.is_empty() {
        return NOTHING_OPEN.to_owned();
    }
    let alerts = notices.iter().filter(|notice| notice.alert).count();
    let warnings = notices.len() - alerts;
    let count = |n: usize, one: &str| format!("{n} {one}{}", if n == 1 { "" } else { "s" });
    match (alerts, warnings) {
        (_, 0) => format!("{} open", count(alerts, "alert")),
        (0, _) => format!("{} open", count(warnings, "warning")),
        _ => format!(
            "{} open: {}, {}",
            notices.len(),
            count(alerts, "alert"),
            count(warnings, "warning")
        ),
    }
}

/// One notice: the marker when it is chosen, its mark (the alarm for an
/// alert, a dash for a warning) and what happened with when; then what
/// Raven did and what the person can do, each under the headline.
pub(super) fn notice_rows(
    look: &Look,
    notice: &SecNotice,
    chosen: bool,
    width: u16,
) -> Vec<Line<'static>> {
    let (g, t) = (&look.glyphs, &look.theme);
    let marker = if chosen { g.selected } else { " " };
    let mark = if notice.alert { g.alarm } else { "-" };
    let headline = shaped(&format!("{} ({})", notice.text.headline, notice.when));
    let lead = format!("{marker} {mark} ");
    let mut rows: Vec<Line<'static>> = Vec::new();
    for (i, row) in wrap(&format!("{lead}{headline}"), width, INDENT)
        .into_iter()
        .enumerate()
    {
        let style = if notice.alert {
            t.warn
        } else {
            Default::default()
        };
        let style = if chosen {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        };
        if i == 0 && row.starts_with(&lead) {
            rows.push(Line::from(vec![
                Span::styled(lead.clone(), t.accent),
                Span::styled(row[lead.len()..].to_owned(), style),
            ]));
        } else {
            rows.push(Line::styled(row, style));
        }
    }
    let pad = " ".repeat(usize::from(INDENT));
    for (label, text) in [(DID, &notice.text.did), (TODO, &notice.text.todo)] {
        let hang = INDENT + u16::try_from(cells(label)).unwrap_or(0);
        rows.extend(
            wrap(&format!("{pad}{label}{}", shaped(text)), width, hang)
                .into_iter()
                .map(Line::raw),
        );
    }
    rows
}

/// The chosen notice's details: whom it is about (a key prefix only for a
/// verified friend), how serious, the technical code and Raven's action.
fn detail_rows(look: &Look, notice: &SecNotice, width: u16) -> Vec<Line<'static>> {
    let pad = " ".repeat(usize::from(INDENT));
    notice
        .details
        .iter()
        .flat_map(|(label, value)| {
            let label = format!("{label}: ");
            let hang = INDENT + u16::try_from(cells(&label)).unwrap_or(0);
            wrap(&format!("{pad}{label}{}", shaped(value)), width, hang)
        })
        .map(|row| Line::styled(row, look.theme.secondary))
        .collect()
}

/// `text` as one line of plain characters (names in it are untrusted).
fn shaped(text: &str) -> String {
    display::one_line(text, u16::MAX, "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;

    /// Sara and Rena's keys: a verified friend and one who is not.
    const SARA: u8 = 0x5A;
    const RENA: u8 = 0x7E;

    /// One notice about `peer` (lower-case hex) in `name`'s words.
    fn notice(id: i64, alert: bool, peer: Option<&str>, name: &str) -> SecNotice {
        let prefix = peer.map_or_else(String::new, |peer| peer[..8].to_owned());
        SecNotice {
            id,
            alert,
            peer: peer.map(str::to_owned),
            name: name.to_owned(),
            text: NoticeText {
                headline: format!("Messages from {name} failed Raven's security check"),
                did: "Raven didn't show them. It set up a new secure connection with them by \
                      itself."
                    .into(),
                todo: format!(
                    "Ask {name}, in person or by phone, whether they reinstalled Raven or \
                     restored their computer. Then compare security words."
                ),
                act: SecAct::CompareWords,
            },
            when: "4 times, latest this morning".into(),
            details: vec![
                ("About", format!("{name} (verified friend, key {prefix})")),
                ("How serious", "alert".into()),
                ("Code", "SEC_OBJECT_AUTH_FAIL (40)".into()),
            ],
        }
    }

    /// A read with an alert about Sara, a warning about Rena (a mailbox)
    /// and 3 notices only counted.
    fn read_with_two(sara: &str, rena: &str) -> SecurityView {
        let mut warning = notice(2, false, Some(rena), "Rena");
        warning.text = NoticeText {
            headline: "Mail that came through Rena's computer failed Raven's checks".into(),
            did: "Raven didn't show it. It stopped using Rena as a mailbox for a day.".into(),
            todo: "Tell Rena in person: Rena may not know.".into(),
            act: SecAct::AskThem,
        };
        SecurityView {
            kept: SecKept::Live,
            notices: vec![notice(1, true, Some(sara), "Sara"), warning],
            counted: 3,
            week: vec![(sara.to_owned(), 5)],
            paused: Vec::new(),
            unreadable: None,
            updates: Vec::new(),
        }
    }

    /// Home with Sara (verified) and Rena, and `read` answered.
    fn app_with(size: (u16, u16), read: SecurityView) -> App {
        app_in(testkit::simple_mono(), size, read)
    }

    /// [`app_with`] in `look`.
    fn app_in(look: Look, size: (u16, u16), read: SecurityView) -> App {
        let sara = testkit::saved_as(SARA, "Sara", true, "");
        let rena = testkit::saved_as(RENA, "Rena", false, "");
        let mut app = testkit::home_app_in(
            look,
            size,
            Receive::Off,
            vec![sara, rena],
            Conversations::new(),
        );
        testkit::answer_security(&mut app, read);
        app
    }

    fn keys_of(seed: u8) -> String {
        testkit::saved_as(seed, "x", false, "").pub_hex
    }

    /// No IPv4 or IPv6 address, no 32-hex message id, no hex run longer
    /// than a key prefix (8).
    fn assert_no_address_id_or_key(screen: &str) {
        let mut run = 0;
        for c in screen.chars() {
            run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
            assert!(run <= 8, "a hex run longer than 8 in\n{screen}");
        }
        for word in screen.split(|c: char| c.is_whitespace() || c == '(' || c == ')') {
            let word = word.trim_end_matches(['.', ',', ':']);
            assert!(
                word.parse::<std::net::IpAddr>().is_err()
                    && word.parse::<std::net::SocketAddr>().is_err(),
                "an address `{word}` in\n{screen}"
            );
        }
    }

    /// SEC at 80x24, 60x16 and in the narrowest window: the summary, each
    /// notice with what Raven did and what to do (its action line), the
    /// count of notices, the keys; never an address, an id or a whole key;
    /// a key prefix only in the details of a verified friend.
    #[test]
    fn sec_lists_alerts_with_an_action_line_in_every_size() {
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        for size in testkit::SIZES {
            let mut app = app_with(size, read_with_two(&sara, &rena));
            testkit::press(&mut app, KeyCode::Char('w'));
            assert!(matches!(app.overlays(), [Overlay::Security(_)]), "{size:?}");
            let screen = testkit::render_text(&app);
            assert!(
                screen.contains("2 open: 1 alert, 1 warning"),
                "{size:?}\n{screen}"
            );
            assert!(screen.contains("Messages from Sara failed"), "{screen}");
            assert!(screen.contains("What you can do:"), "{screen}");
            assert!(screen.contains("Esc"), "{screen}");
            assert_no_address_id_or_key(&screen);
            assert!(!screen.contains(&sara[..8]), "no prefix before D");
            // Every notice, rendered alone, has its action line.
            let look = *app.look();
            for notice in app.notices() {
                let rows: Vec<String> = notice_rows(&look, notice, false, size.0 - 8)
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                assert!(
                    rows.iter().any(|row| row.trim_start().starts_with(TODO)),
                    "{rows:#?}"
                );
            }
            // D: the details, with the verified friend's 8-character prefix.
            testkit::press(&mut app, KeyCode::Char('d'));
            let (rows, _) = lines(
                &app,
                SecState {
                    chosen: 0,
                    details: true,
                },
                size.0 - 4,
            );
            let text: Vec<String> = rows.iter().map(ToString::to_string).collect();
            assert!(
                text.iter()
                    .any(|row| row.contains(&format!("key {}", &sara[..8]))),
                "{text:#?}"
            );
            assert_no_address_id_or_key(&testkit::render_text(&app));
            // Down chooses Rena's; it scrolls into view.
            testkit::press(&mut app, KeyCode::Down);
            let screen = testkit::render_text(&app);
            assert!(
                screen.contains("Mail that came through Rena"),
                "{size:?}\n{screen}"
            );
        }
    }

    /// R resolves the chosen notice by its id; V on an alert about a saved
    /// friend opens VF for them; Esc and W close.
    #[test]
    fn sec_resolves_and_compares_words() {
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        let mut app = app_with((80, 24), read_with_two(&sara, &rena));
        testkit::press(&mut app, KeyCode::Char('W'));
        testkit::press(&mut app, KeyCode::Down);
        let cmds = testkit::press(&mut app, KeyCode::Char('r'));
        assert_eq!(
            testkit::store_jobs(&cmds),
            [&StoreJob::ResolveNotice { id: 2 }]
        );
        testkit::press(&mut app, KeyCode::Up);
        testkit::press(&mut app, KeyCode::Char('v'));
        assert!(app.overlays().is_empty());
        assert!(matches!(app.screen(), Screen::Verify(_)));
        let mut app = app_with((80, 24), read_with_two(&sara, &rena));
        testkit::press(&mut app, KeyCode::Char('w'));
        testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Char('w'));
        testkit::press(&mut app, KeyCode::Char('w'));
        assert!(app.overlays().is_empty());
    }

    /// Before a read, with the gate shut, in a profile that keeps none, and
    /// with nothing open, SEC says so in a sentence.
    #[test]
    fn sec_says_why_nothing_is_listed() {
        let sara = keys_of(SARA);
        for (read, says) in [
            (
                SecurityView::default(),
                "Security notices are not part of this version.",
            ),
            (
                SecurityView {
                    kept: SecKept::Unsealed,
                    ..SecurityView::default()
                },
                "This profile is not encrypted",
            ),
            (
                SecurityView {
                    kept: SecKept::Live,
                    counted: 1,
                    ..SecurityView::default()
                },
                NOTHING_OPEN,
            ),
            (
                SecurityView {
                    kept: SecKept::Live,
                    unreadable: Some("disk".into()),
                    ..SecurityView::default()
                },
                UNREADABLE,
            ),
        ] {
            let mut app = app_with((80, 24), read);
            testkit::press(&mut app, KeyCode::Char('w'));
            let screen = testkit::render_text(&app);
            assert!(screen.contains(says), "{says}\n{screen}");
            assert!(!screen.contains(&sara[..8]));
        }
    }

    /// Security notices from the Raven project (P6.45) follow the alerts in
    /// raven-core's words, one paragraph each, with every escape sequence
    /// and bidirectional control of the notice's text gone; alone when no
    /// alert is open.
    #[test]
    fn sec_shows_the_raven_projects_notices() {
        use raven_core::advisory::{Entry, EntryKind, Severity};
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        let entry = |kind, severity, target: &str, arg: &[u8]| Entry {
            kind,
            severity,
            target: target.to_owned(),
            arg: arg.to_vec(),
            text_id: 0,
        };
        let policy = raven_core::suite_policy::Policy::of_entries(
            6,
            0,
            &[
                entry(
                    EntryKind::SuiteStatus,
                    Severity::Broken,
                    raven_core::suite_registry::PAIRINIT_V1_SUITE1,
                    b"",
                ),
                entry(
                    EntryKind::Notice,
                    Severity::Info,
                    "notice",
                    "Update soon\u{1b}[31m please\u{202E}gpj.exe".as_bytes(),
                ),
            ],
            0,
        );
        let mut read = read_with_two(&sara, &rena);
        read.updates = policy.lines(3 * 86_400_000);
        let app = app_with((80, 24), read.clone());
        let sec = SecState::default();
        // The rows, wrapped at 70 cells, read as one run of words.
        let text = |app: &App| -> String {
            lines(app, sec, 70)
                .0
                .iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("\n")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let all = text(&app);
        let at = all
            .find("- Security notices from the Raven project: #6 (issued about 3 days ago).")
            .expect(&all);
        assert!(at > all.find("Sara").unwrap(), "after the alerts\n{all}");
        assert!(all.contains("- Security notice #6: the way Raven starts a new session"));
        assert!(all.contains("- Notice #6 from the Raven project: Update soon please"));
        assert!(
            !all.contains('\u{1b}') && !all.contains('\u{202E}'),
            "{all}"
        );
        assert_no_address_id_or_key(&all);
        // Nothing open: the notices still show.
        let alone = SecurityView {
            kept: SecKept::Live,
            updates: read.updates,
            ..SecurityView::default()
        };
        let all = text(&app_with((80, 24), alone));
        assert!(all.starts_with(NOTHING_OPEN), "{all}");
        assert!(all.contains("Security notices from the Raven project: #6"));
    }

    /// The summary counts alerts and warnings in words.
    #[test]
    fn the_summary_counts_in_words() {
        let one = notice(1, true, None, "Sara");
        let warning = notice(2, false, None, "Rena");
        assert_eq!(summary(&[]), NOTHING_OPEN);
        assert_eq!(summary(std::slice::from_ref(&one)), "1 alert open");
        assert_eq!(
            summary(&[warning.clone(), warning.clone()]),
            "2 warnings open"
        );
        assert_eq!(summary(&[one, warning]), "2 open: 1 alert, 1 warning");
    }

    /// Every look (colours or none, every symbol set, reduced motion) draws
    /// SEC's marks and keys legibly.
    #[test]
    fn sec_reads_in_every_look() {
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        for look in testkit::every_look() {
            for motion in [theme::Motion::Full, theme::Motion::Reduced] {
                let look = Look { motion, ..look };
                let mut app = app_in(look, (80, 24), read_with_two(&sara, &rena));
                testkit::press(&mut app, KeyCode::Char('w'));
                let screen = testkit::render_text(&app);
                let lead = format!(
                    "{} {} Messages from Sara",
                    look.glyphs.selected, look.glyphs.alarm
                );
                assert!(screen.contains(&lead), "{screen}");
            }
        }
    }

    fn type_text(app: &mut App, text: &str) -> Vec<Cmd> {
        let mut cmds = Vec::new();
        for c in text.chars() {
            cmds.extend(testkit::press(app, KeyCode::Char(c)));
        }
        cmds
    }

    /// The front toast's words.
    fn toast(app: &App) -> String {
        app.toast().map(|t| t.text.clone()).unwrap_or_default()
    }

    /// Every toast shown and gone: the next one is on show at once.
    fn drain_toasts(app: &mut App) {
        while app.toast().is_some() {
            testkit::tick(app, std::time::Duration::from_secs(30));
        }
    }

    /// Home at each size: the header chip ('!2' in the render tests' simple
    /// look), the alarm badge over Sara's unverified-style mark, and once
    /// her conversation is open, the banner with what happened and its
    /// keys; never an address, an id or a key.
    #[test]
    fn home_shows_the_chip_the_badge_and_the_banner_in_every_size() {
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        for size in testkit::SIZES {
            let mut app = app_with(size, read_with_two(&sara, &rena));
            let rows = testkit::render(&app, size.0, size.1);
            assert!(rows[0].contains("!2"), "{size:?}: {}", rows[0]);
            let sara_row = rows.iter().find(|row| row.contains("Sara")).expect("Sara");
            let badge = sara_row.split("Sara").nth(1).unwrap_or_default();
            assert!(badge.trim_start().starts_with("!!"), "{sara_row}");
            assert!(
                rows.iter().any(|row| row.contains("W Security")),
                "{size:?}\n{rows:#?}"
            );
            assert_no_address_id_or_key(&testkit::screen_text(&rows));
            // Sara's conversation: the banner.
            testkit::press(&mut app, KeyCode::Enter);
            let screen = testkit::render_text(&app);
            assert!(
                screen.contains("! Messages from Sara"),
                "{size:?}\n{screen}"
            );
            assert!(
                screen.contains("[V] Compare words [D] Details [P] Pause sending"),
                "{size:?}\n{screen}"
            );
            assert_no_address_id_or_key(&screen);
            let friend = app.friend(&sara).expect("Sara").clone();
            let banner: Vec<String> = home::security_banner(&app, &friend, "Sara", 54)
                .iter()
                .map(ToString::to_string)
                .collect();
            assert_eq!(
                banner.join(" "),
                "! Messages from Sara failed Raven's security check (4 times, latest this \
                 morning). [V] Compare words  [D] Details  [P] Pause sending"
            );
        }
        // Nothing open: no chip, no badge, no banner.
        let mut app = app_with(
            (80, 24),
            SecurityView {
                kept: SecKept::Live,
                ..SecurityView::default()
            },
        );
        let rows = testkit::render(&app, 80, 24);
        assert!(!rows[0].contains('!'), "{}", rows[0]);
        testkit::press(&mut app, KeyCode::Enter);
        assert!(!testkit::render_text(&app).contains("Compare words"));
    }

    /// Reduced motion and the mono themes (every glyph set) draw the chip
    /// and the banner legibly: the mark, the count and the words.
    #[test]
    fn chip_and_banner_read_in_every_look() {
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        for look in testkit::every_look() {
            for motion in [theme::Motion::Full, theme::Motion::Reduced] {
                let look = Look { motion, ..look };
                let mut app = app_in(look, (80, 24), read_with_two(&sara, &rena));
                testkit::press(&mut app, KeyCode::Enter);
                let rows = testkit::render(&app, 80, 24);
                let gap = if look.glyphs.alarm.is_ascii() {
                    ""
                } else {
                    " "
                };
                let chip = format!("{}{gap}2", look.glyphs.alarm);
                assert!(rows[0].contains(&chip), "{chip:?}: {}", rows[0]);
                let screen = testkit::screen_text(&rows);
                assert!(
                    screen.contains(&format!("{} Messages from Sara failed", look.glyphs.alarm)),
                    "{screen}"
                );
                assert!(screen.contains("[P] Pause sending"), "{screen}");
            }
        }
        // The chip and banner are bold in both themes: legible without colour.
        for theme in [theme::Theme::color(), theme::Theme::mono()] {
            assert!(theme.warn.add_modifier.contains(Modifier::BOLD));
        }
    }

    /// NET's Security group at each size: the open alerts (W), the strangers
    /// raven-node refused and the sources it refuses for now, the notices
    /// only counted and whom sending is paused to; no address or key in it.
    #[test]
    fn net_has_a_security_group() {
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        for size in testkit::SIZES {
            let mut read = read_with_two(&sara, &rena);
            read.paused = vec![sara.clone()];
            let mut app = app_with(size, read);
            let mut probe = testkit::status(4242, "0.0.0.0:7420");
            probe.security = Some(bridge::SecurityCounts {
                strangers_1h: 37,
                bans: 2,
                alerts_open: 2,
            });
            testkit::send(&mut app, Msg::Poll(PollUpdate::Status(probe)));
            testkit::press(&mut app, KeyCode::Char('n'));
            // The whole panel at this width: a window tall enough for it.
            let seen = testkit::screen_text(&testkit::render(&app, size.0, 120));
            let group = seen
                .split("Security Open alerts")
                .nth(1)
                .and_then(|rest| rest.split("About this Raven").next())
                .unwrap_or_else(|| panic!("{size:?}: no Security group in\n{seen}"));
            for says in [
                ": 2 (press W to see them)",
                "Strangers refused in the last hour: 37 (they learned nothing about you)",
                "Network sources Raven refuses for a while: 2",
                "Also 3 smaller notices, only counted.",
                "Sending paused to: Sara",
            ] {
                assert!(group.contains(says), "{size:?} {says:?} in\n{group}");
            }
            assert_no_address_id_or_key(group);
            assert!(seen.contains("[W] Security"), "{size:?}");
        }
        // The gate shut: one sentence.
        let mut app = app_with((80, 24), SecurityView::default());
        testkit::press(&mut app, KeyCode::Char('n'));
        let seen = testkit::screen_text(&testkit::render(&app, 80, 120));
        assert!(
            seen.contains("Security Security notices are not part of this version."),
            "{seen}"
        );
    }

    /// CI's Security row: how many problems the last 7 days counted, with
    /// V to compare words again (or to verify), W and P among its keys,
    /// and that sending is paused.
    #[test]
    fn the_friend_page_has_a_security_row() {
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        for size in testkit::SIZES {
            let mut read = read_with_two(&sara, &rena);
            read.paused = vec![rena.clone()];
            let mut app = app_with(size, read);
            testkit::press(&mut app, KeyCode::Char('e'));
            let screen = testkit::render_text(&app);
            assert!(
                screen.contains("Security: 5 problems in the last 7 days. [V] Compare words again"),
                "{size:?}\n{screen}"
            );
            assert!(screen.contains("[P] Pause sending"), "{size:?}\n{screen}");
            testkit::press(&mut app, KeyCode::Esc);
            testkit::press(&mut app, KeyCode::Down);
            testkit::press(&mut app, KeyCode::Char('e'));
            let screen = testkit::render_text(&app);
            assert!(
                screen.contains("Security: 1 problem in the last 7 days. [V] Verify"),
                "{size:?}\n{screen}"
            );
            assert!(
                screen.contains(
                    "Sending to Rena is paused: Raven sends them nothing until you resume it."
                ),
                "{size:?}\n{screen}"
            );
            assert!(screen.contains("[P] Resume sending"), "{size:?}\n{screen}");
        }
    }

    /// VF for a verified friend with an open notice checks again at once;
    /// a match goes out as a Recheck (no confirmation code: nothing is
    /// saved). While the older method may be accepted, VF asks for
    /// 'accept' (typed, also on a Persian keyboard); anything else, or
    /// Esc, keeps the newer one. Without a notice, 'Already verified' and
    /// Enter checks again.
    #[test]
    fn vf_checks_a_verified_friend_again() {
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        let words = testkit::me(SARA).words.join(" ");
        let mut app = app_with((80, 24), read_with_two(&sara, &rena));
        drain_toasts(&mut app);
        testkit::press(&mut app, KeyCode::Char('v'));
        let Screen::Verify(vf) = app.screen() else {
            panic!("VF");
        };
        assert_eq!(
            vf.step,
            VerifyStep::Comparing(None),
            "checked again at once"
        );
        type_text(&mut app, &words);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        let jobs = testkit::store_jobs(&cmds);
        assert!(
            matches!(jobs.as_slice(), [StoreJob::Recheck { pub_hex, typed }]
                if *pub_hex == sara && typed.split(' ').count() == 10),
            "{jobs:?}"
        );
        let resolved = |older_method| {
            Msg::Job(JobResult::Rechecked {
                pub_hex: sara.clone(),
                result: Ok(bridge::Resolved {
                    notices: 1,
                    older_method,
                }),
            })
        };
        testkit::send(&mut app, resolved(true));
        assert!(matches!(
            app.screen(),
            Screen::Verify(vf) if matches!(vf.step, VerifyStep::OlderMethod { .. })
        ));
        assert_eq!(
            toast(&app),
            "They match. Resolved 1 security notice about Sara."
        );
        let screen = testkit::render_text(&app);
        assert!(
            screen.contains("Accept the older method for Sara?"),
            "{screen}"
        );
        assert!(screen.contains("Type accept"), "{screen}");
        assert_no_address_id_or_key(screen.split("Accept the older").nth(1).unwrap_or(""));
        // 'accept' on a Persian keyboard: the Latin letters on the same keys.
        let persian = testkit::on_persian_keyboard("accept");
        type_text(&mut app, &persian);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        let jobs = testkit::store_jobs(&cmds);
        assert!(
            matches!(jobs.as_slice(), [StoreJob::AcceptOlderMethod { pub_hex, typed }]
                if *pub_hex == sara && *typed == words),
            "{jobs:?}"
        );
        testkit::send(
            &mut app,
            Msg::Job(JobResult::OlderMethodAccepted {
                pub_hex: sara.clone(),
                result: Ok(true),
            }),
        );
        assert!(matches!(app.screen(), Screen::FriendPage(_)));
        // Again, and Esc keeps the newer method.
        testkit::press(&mut app, KeyCode::Char('v'));
        type_text(&mut app, &words);
        testkit::press(&mut app, KeyCode::Enter);
        testkit::send(&mut app, resolved(true));
        type_text(&mut app, "yes");
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert!(
            testkit::store_jobs(&cmds).is_empty(),
            "only 'accept' accepts"
        );
        assert!(matches!(app.screen(), Screen::FriendPage(_)));
        // Nothing to accept: the friend's page and what was resolved.
        testkit::press(&mut app, KeyCode::Char('v'));
        type_text(&mut app, &words);
        testkit::press(&mut app, KeyCode::Enter);
        testkit::send(&mut app, resolved(false));
        assert!(matches!(app.screen(), Screen::FriendPage(_)));
        // No notice open: 'Already verified', and Enter checks again.
        testkit::answer_security(
            &mut app,
            SecurityView {
                kept: SecKept::Live,
                ..SecurityView::default()
            },
        );
        testkit::press(&mut app, KeyCode::Char('v'));
        assert!(matches!(
            app.screen(),
            Screen::Verify(vf) if vf.step == VerifyStep::AlreadyVerified
        ));
        assert!(testkit::render_text(&app).contains("[Enter] Check again"));
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(
            app.screen(),
            Screen::Verify(vf) if vf.step == VerifyStep::Comparing(None)
        ));
    }

    /// P pauses sending to the highlighted friend and resumes it again,
    /// only through the store job's answer; while paused, Enter in the
    /// composer sends nothing and its hint says how to resume; a friend
    /// with nothing open and no pause gets no P.
    #[test]
    fn pause_sending_round_trip() {
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        let mut app = app_with((80, 24), read_with_two(&sara, &rena));
        let set = |on: bool, paused: bool| {
            Msg::Job(JobResult::SendHoldSet {
                pub_hex: sara.clone(),
                on,
                result: Ok(paused),
            })
        };
        drain_toasts(&mut app);
        let cmds = testkit::press(&mut app, KeyCode::Char('p'));
        assert_eq!(
            testkit::store_jobs(&cmds),
            [&StoreJob::SetSendHold {
                pub_hex: sara.clone(),
                on: true
            }]
        );
        assert!(!app.paused(&sara), "only once it is saved");
        let cmds = testkit::send(&mut app, set(true, true));
        assert!(app.paused(&sara));
        assert!(cmds.contains(&Cmd::Store(StoreJob::LoadSecurity)));
        assert_eq!(
            toast(&app),
            "Sending to Sara is paused. Press P again to resume."
        );
        // The conversation: the banner says so; Enter sends nothing.
        testkit::press(&mut app, KeyCode::Enter);
        type_text(&mut app, "hi");
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert!(testkit::send_job(&cmds).is_none());
        let screen = testkit::render_text(&app);
        assert!(
            screen.contains("Sending to Sara is paused until you resume it."),
            "{screen}"
        );
        assert!(screen.contains("[P] Resume sending"), "{screen}");
        assert!(
            screen.contains("You paused sending to Sara: Enter sends nothing."),
            "{screen}"
        );
        // Back on the list, P resumes.
        drain_toasts(&mut app);
        testkit::press(&mut app, KeyCode::Esc);
        let cmds = testkit::press(&mut app, KeyCode::Char('P'));
        assert_eq!(
            testkit::store_jobs(&cmds),
            [&StoreJob::SetSendHold {
                pub_hex: sara.clone(),
                on: false
            }]
        );
        testkit::send(&mut app, set(false, false));
        assert!(!app.paused(&sara));
        assert_eq!(toast(&app), "Sending to Sara is on again.");
        testkit::press(&mut app, KeyCode::Enter);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert!(testkit::send_job(&cmds).is_some(), "the draft goes now");
        // Rena's warning offers P too; a friend with nothing gets none.
        let mut app = app_with(
            (80, 24),
            SecurityView {
                kept: SecKept::Live,
                ..SecurityView::default()
            },
        );
        assert!(testkit::store_jobs(&testkit::press(&mut app, KeyCode::Char('p'))).is_empty());
        // A pause that could not be saved says so.
        let mut app = app_with((80, 24), read_with_two(&sara, &rena));
        drain_toasts(&mut app);
        testkit::press(&mut app, KeyCode::Char('p'));
        testkit::send(
            &mut app,
            Msg::Job(JobResult::SendHoldSet {
                pub_hex: sara.clone(),
                on: true,
                result: Err("node_policy.json: permission denied".into()),
            }),
        );
        assert!(!app.paused(&sara));
        assert_eq!(toast(&app), "Raven couldn't pause sending to Sara.");
    }

    /// W and P work with a Persian keyboard layout on (input tolerance
    /// only: nothing is shown in another language).
    #[test]
    fn w_and_p_work_on_a_persian_keyboard() {
        let (sara, rena) = (keys_of(SARA), keys_of(RENA));
        let mut app = app_with((80, 24), read_with_two(&sara, &rena));
        testkit::press(&mut app, KeyCode::Char('\u{0635}'));
        assert!(matches!(app.overlays(), [Overlay::Security(_)]));
        testkit::press(&mut app, KeyCode::Char('\u{0635}'));
        assert!(app.overlays().is_empty());
        let cmds = testkit::press(&mut app, KeyCode::Char('\u{062D}'));
        assert!(matches!(
            testkit::store_jobs(&cmds).as_slice(),
            [StoreJob::SetSendHold { on: true, .. }]
        ));
        // D on the highlighted friend opens SEC on their notice.
        testkit::press(&mut app, KeyCode::Char('\u{06CC}'));
        assert!(matches!(app.overlays(), [Overlay::Security(sec)] if sec.chosen == 0));
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Down);
        testkit::press(&mut app, KeyCode::Char('d'));
        assert!(matches!(app.overlays(), [Overlay::Security(sec)] if sec.chosen == 1));
    }
}
