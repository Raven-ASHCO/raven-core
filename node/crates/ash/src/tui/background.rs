//! Colors › Automatic's question (Calm): which palette fits this terminal,
//! from the background colour the terminal itself says it has.
//!
//! - COLORFGBG answers first, where the terminal sets it (theme.rs).
//! - Otherwise the app asks once at start, before the first frame and before
//!   the input thread reads the keys: OSC 11 (`ESC ] 11 ; ? BEL`), then DA1
//!   (`ESC [ c`), which every terminal answers, after OSC 11's answer when
//!   it gives one. The answers are read in raw mode (TerminalGuard is up:
//!   nothing echoes, nothing shows), up to DA1's or for at most 150 ms (500
//!   ms over SSH); what came by then is discarded, so no answer reaches the
//!   app as keys. The terminal's modes are TerminalGuard's throughout:
//!   asking changes none of them.
//! - It asks only while Colors is Automatic, the input and output are a
//!   terminal, NO_COLOR and COLORFGBG say nothing, the terminal has 256
//!   colours or more (else the palettes can't be drawn), and TERM is set and
//!   is neither the Linux console nor `dumb`. Not on Windows: reading an
//!   answer there takes the console's VT input mode, untested here.
//! - `rgb:RRRR/GGGG/BBBB` (1 to 4 hex digits a component) is dark or light
//!   by its relative luminance. Nothing else is guessed: no answer, the
//!   terminal's own colours.

use std::io::Write;
use std::time::{Duration, Instant};

use super::state_file::{ColorSetting, PaletteSetting, TuiState};
use super::theme::{Background, Depth, Rgb, TermEnv};
#[cfg(test)]
use super::theme::{Theme, DARK, LIGHT};

/// OSC 11's question, then DA1's: the end of the answers.
pub(super) const QUESTION: &[u8] = b"\x1b]11;?\x07\x1b[c";
/// How long the answers may take, and over SSH.
const WAIT: Duration = Duration::from_millis(150);
const SSH_WAIT: Duration = Duration::from_millis(500);
/// More than this is not an answer to the two questions.
const MOST: usize = 512;
/// Below this relative luminance a background is dark: where black and
/// white text have the same contrast on it.
const DARK_BELOW: f64 = 0.179;

/// Where the answers come from: the terminal's keys (stdio.rs), or a test's.
pub(super) trait Answers {
    /// Whether something can be read within `within`.
    fn readable(&mut self, within: Duration) -> bool;
    /// What can be read now, into `buf`: how much (0: nothing more).
    fn read(&mut self, buf: &mut [u8]) -> usize;
    /// Drops whatever came and was not read.
    fn discard(&mut self);
}

/// Whether to ask: see the module's rules. `ttys`: the input and the output
/// are a terminal.
pub(super) fn should_ask(settings: &TuiState, env: &TermEnv, ttys: bool) -> bool {
    ttys && !env.windows
        && settings.colors == ColorSetting::Auto
        && settings.palette == PaletteSetting::Auto
        && !env.no_color
        && env.background().is_none()
        && env.depth() != Depth::Ansi
        && !matches!(env.term.as_deref(), None | Some("linux" | "dumb"))
}

/// How long to wait for the answers in a terminal like `env`.
pub(super) fn wait(env: &TermEnv) -> Duration {
    if env.ssh {
        SSH_WAIT
    } else {
        WAIT
    }
}

/// Asks: the questions to `out`, the answers from `answers` until DA1's or
/// for `wait`. The background, or None when the terminal didn't say.
pub(super) fn ask(
    out: &mut impl Write,
    answers: &mut impl Answers,
    wait: Duration,
) -> Option<Background> {
    out.write_all(QUESTION).ok()?;
    out.flush().ok()?;
    let answer = read_answers(answers, wait)?;
    parse_rgb(&answer).map(background_of)
}

/// The answers read until DA1's came, or for `wait`; then what is left is
/// discarded. None without OSC 11's.
fn read_answers(answers: &mut impl Answers, wait: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + wait;
    let mut got = Vec::new();
    loop {
        if da1_answered(&got) {
            break;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || got.len() >= MOST || !answers.readable(left) {
            answers.discard();
            break;
        }
        let mut buf = [0u8; 128];
        let n = answers.read(&mut buf);
        if n == 0 {
            answers.discard();
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    find(&got, b"]11;").is_some().then_some(got)
}

/// Whether `got` holds DA1's answer, `ESC [ ? … c`.
fn da1_answered(got: &[u8]) -> bool {
    find(got, b"\x1b[?").is_some_and(|at| got[at..].contains(&b'c'))
}

/// Where `needle` first is in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The colour in OSC 11's answer, `ESC ] 11 ; rgb:RRRR/GGGG/BBBB` (or
/// `rgba:`, its alpha ignored) ended by BEL or ST; each component 1 to 4
/// hex digits, scaled to 8 bits.
pub(super) fn parse_rgb(answer: &[u8]) -> Option<Rgb> {
    let at = find(answer, b"]11;")? + 4;
    let rest = &answer[at..];
    let end = rest
        .iter()
        .position(|&b| b == 0x07 || b == 0x1b)
        .unwrap_or(rest.len());
    let text = std::str::from_utf8(&rest[..end]).ok()?.trim();
    let spec = text
        .strip_prefix("rgb:")
        .or_else(|| text.strip_prefix("rgba:"))?;
    let mut parts = spec.split('/').map(component);
    let (r, g, b) = (parts.next()??, parts.next()??, parts.next()??);
    Some(Rgb(r, g, b))
}

/// One component, 1 to 4 hex digits, as 8 bits.
fn component(hex: &str) -> Option<u8> {
    if hex.is_empty() || hex.len() > 4 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let value = u32::from_str_radix(hex, 16).ok()?;
    let top = (1u32 << (4 * hex.len())) - 1;
    u8::try_from((value * 255 + top / 2) / top).ok()
}

/// Dark or light, by `rgb`'s relative luminance (sRGB, WCAG).
pub(super) fn background_of(rgb: Rgb) -> Background {
    let linear = |c: u8| {
        let c = f64::from(c) / 255.0;
        if c <= 0.040_45 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    let luminance = 0.2126 * linear(rgb.0) + 0.7152 * linear(rgb.1) + 0.0722 * linear(rgb.2);
    if luminance < DARK_BELOW {
        Background::Dark
    } else {
        Background::Light
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A terminal's answers, a chunk a read; None: nothing more ever comes.
    struct Fake {
        chunks: VecDeque<Vec<u8>>,
        discarded: bool,
        waited: Vec<Duration>,
    }

    impl Fake {
        fn answering(chunks: &[&[u8]]) -> Fake {
            Fake {
                chunks: chunks.iter().map(|c| c.to_vec()).collect(),
                discarded: false,
                waited: Vec::new(),
            }
        }
    }

    impl Answers for Fake {
        fn readable(&mut self, within: Duration) -> bool {
            self.waited.push(within);
            !self.chunks.is_empty()
        }

        fn read(&mut self, buf: &mut [u8]) -> usize {
            let Some(chunk) = self.chunks.pop_front() else {
                return 0;
            };
            buf[..chunk.len()].copy_from_slice(&chunk);
            chunk.len()
        }

        fn discard(&mut self) {
            self.discarded = true;
        }
    }

    #[test]
    fn the_answer_is_read_in_its_forms() {
        let rgb = |answer: &[u8]| parse_rgb(answer);
        assert_eq!(
            rgb(b"\x1b]11;rgb:1c1c/1c1c/1a1a\x07\x1b[?62;22c"),
            Some(Rgb(0x1c, 0x1c, 0x1a))
        );
        // ST in place of BEL, two and one digits a component, rgba.
        assert_eq!(
            rgb(b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\"),
            Some(Rgb(255, 255, 255))
        );
        assert_eq!(
            rgb(b"\x1b]11;rgb:fa/f9/f5\x07"),
            Some(Rgb(0xfa, 0xf9, 0xf5))
        );
        assert_eq!(rgb(b"\x1b]11;rgb:f/0/8\x07"), Some(Rgb(255, 0, 136)));
        assert_eq!(
            rgb(b"\x1b]11;rgba:0000/0000/0000/ffff\x07"),
            Some(Rgb(0, 0, 0))
        );
        assert_eq!(
            rgb(b"\x1b]11;rgb:8080/8080/8080\x07"),
            Some(Rgb(128, 128, 128))
        );
        // Anything else is no answer.
        for bad in [
            &b""[..],
            b"\x1b[?62;22c",
            b"\x1b]11;?\x07",
            b"\x1b]11;rgb:12345/0/0\x07",
            b"\x1b]11;rgb:zz/00/00\x07",
            b"\x1b]11;rgb:00/00\x07",
            b"\x1b]11;#1c1c1a\x07",
            b"\x1b]10;rgb:ffff/ffff/ffff\x07",
        ] {
            assert_eq!(rgb(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn dark_or_light_by_luminance() {
        assert_eq!(background_of(DARK.bg), Background::Dark);
        assert_eq!(background_of(LIGHT.bg), Background::Light);
        assert_eq!(background_of(Rgb(0, 0, 0)), Background::Dark);
        assert_eq!(background_of(Rgb(255, 255, 255)), Background::Light);
        // Solarized's dark and light bases, mid grey.
        assert_eq!(background_of(Rgb(0x00, 0x2b, 0x36)), Background::Dark);
        assert_eq!(background_of(Rgb(0xfd, 0xf6, 0xe3)), Background::Light);
        assert_eq!(background_of(Rgb(0x80, 0x80, 0x80)), Background::Light);
        assert_eq!(background_of(Rgb(0x60, 0x60, 0x60)), Background::Dark);
    }

    #[test]
    fn the_answers_come_in_pieces_until_da1s() {
        let mut fake = Fake::answering(&[b"\x1b]11;rgb:fafa", b"/f9f9/f5f5\x07\x1b[?6", b"2;22c"]);
        let mut out = Vec::new();
        assert_eq!(
            ask(&mut out, &mut fake, Duration::from_secs(5)),
            Some(Background::Light)
        );
        assert_eq!(out, QUESTION);
        assert!(!fake.discarded, "all of it read");
        // DA1 alone: the terminal has no OSC 11; no waiting for more.
        let mut fake = Fake::answering(&[b"\x1b[?1;2c"]);
        assert_eq!(
            ask(&mut Vec::new(), &mut fake, Duration::from_secs(5)),
            None
        );
        assert_eq!(fake.waited.len(), 1);
    }

    #[test]
    fn a_terminal_that_never_answers_times_out_and_leaves_nothing() {
        // Nothing ever comes: one wait of the whole time, then what might
        // have come is discarded, and no palette is guessed.
        let mut fake = Fake::answering(&[]);
        let started = Instant::now();
        assert_eq!(ask(&mut Vec::new(), &mut fake, WAIT), None);
        assert!(fake.discarded);
        assert_eq!(fake.waited.len(), 1);
        assert!(fake.waited[0] <= WAIT);
        assert!(started.elapsed() < Duration::from_secs(5));
        // OSC 11's answer, then silence: it counts, the rest is dropped.
        let mut fake = Fake::answering(&[b"\x1b]11;rgb:0000/0000/0000\x07"]);
        assert_eq!(
            ask(&mut Vec::new(), &mut fake, WAIT),
            Some(Background::Dark)
        );
        assert!(fake.discarded);
        // Half an answer: none.
        let mut fake = Fake::answering(&[b"\x1b]11;rgb:00"]);
        assert_eq!(ask(&mut Vec::new(), &mut fake, WAIT), None);
        // No time at all: nothing read, and the discard still happens.
        let mut fake = Fake::answering(&[b"\x1b]11;rgb:0000/0000/0000\x07\x1b[?1c"]);
        assert_eq!(ask(&mut Vec::new(), &mut fake, Duration::ZERO), None);
        assert!(fake.discarded);
    }

    #[test]
    fn it_asks_only_where_nothing_else_decides() {
        let term = |vars: &[(&str, &str)]| {
            let mut env = TermEnv::default();
            for (name, value) in vars {
                match *name {
                    "TERM" => env.term = Some((*value).into()),
                    "COLORTERM" => env.colorterm = Some((*value).into()),
                    "COLORFGBG" => env.colorfgbg = Some((*value).into()),
                    "NO_COLOR" => env.no_color = true,
                    "SSH" => env.ssh = true,
                    "WINDOWS" => env.windows = true,
                    _ => unreachable!(),
                }
            }
            env
        };
        let auto = TuiState::default();
        let mac = term(&[("TERM", "xterm-256color")]);
        assert!(should_ask(&auto, &mac, true));
        assert_eq!(wait(&mac), WAIT);
        assert_eq!(
            wait(&term(&[("TERM", "xterm-256color"), ("SSH", "")])),
            SSH_WAIT
        );
        // Not a terminal; a palette or No colors chosen.
        assert!(!should_ask(&auto, &mac, false));
        for choice in [
            state_file_choice(PaletteSetting::Dark, ColorSetting::Auto),
            state_file_choice(PaletteSetting::Light, ColorSetting::Auto),
            state_file_choice(PaletteSetting::Auto, ColorSetting::NoColors),
        ] {
            assert!(!should_ask(&choice, &mac, true), "{choice:?}");
        }
        // NO_COLOR, COLORFGBG, 16 colours, the Linux console, dumb, no TERM,
        // Windows.
        for env in [
            term(&[("TERM", "xterm-256color"), ("NO_COLOR", "1")]),
            term(&[("TERM", "xterm-256color"), ("COLORFGBG", "15;0")]),
            term(&[("TERM", "xterm")]),
            term(&[("TERM", "linux"), ("COLORTERM", "truecolor")]),
            term(&[("TERM", "dumb"), ("COLORTERM", "truecolor")]),
            term(&[("COLORTERM", "truecolor")]),
            term(&[("TERM", "xterm-256color"), ("WINDOWS", "")]),
        ] {
            assert!(!should_ask(&auto, &env, true), "{env:?}");
        }
    }

    fn state_file_choice(palette: PaletteSetting, colors: ColorSetting) -> TuiState {
        TuiState {
            colors,
            palette,
            ..TuiState::default()
        }
    }

    #[test]
    fn the_answer_is_automatics_palette_after_colorfgbg() {
        let env = TermEnv {
            term: Some("xterm-256color".into()),
            answered_background: Some(Background::Light),
            ..TermEnv::default()
        };
        assert_eq!(env.background(), Some(Background::Light));
        assert_eq!(
            Theme::for_setting(ColorSetting::Auto, PaletteSetting::Auto, &env),
            Theme::calm(&LIGHT, Depth::Indexed)
        );
        // COLORFGBG says first.
        let both = TermEnv {
            colorfgbg: Some("15;0".into()),
            ..env.clone()
        };
        assert_eq!(both.background(), Some(Background::Dark));
        // Dark and Light as chosen, whatever the terminal answered.
        assert_eq!(
            Theme::for_setting(ColorSetting::Auto, PaletteSetting::Dark, &env),
            Theme::calm(&DARK, Depth::Indexed)
        );
    }
}
