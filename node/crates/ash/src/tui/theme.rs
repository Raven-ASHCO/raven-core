//! Colours, glyph sets and motion for the full screen.
//!
//! The look follows the terminal unless Settings say otherwise:
//!
//! - colours ([`Theme::for_setting`]): the Calm palettes for dark and light
//!   terminals ([`DARK`], [`LIGHT`], desktop/design/tokens.json's
//!   `terminal`), in 24-bit colour where the terminal says it has it, else
//!   the nearest of the 256 colours ([`Theme::calm`]); the terminal's own
//!   colours ([`Theme::color`]) where neither the setting nor the terminal
//!   says which palette fits, or the terminal has 16 colours only; and
//!   [`Theme::mono`] when NO_COLOR is set and not empty (the rule of
//!   cli.rs's `color_enabled_for`) or the setting asks;
//! - glyphs: [`Glyphs::fancy`], [`Glyphs::simple`] for terminals whose fonts
//!   lack braille and ✓, or [`Glyphs::ascii`] where box drawing and `·…●` are
//!   two cells wide ([`auto_symbols`]);
//! - motion: [`Motion::Reduced`] by default on the Linux text console, under
//!   NO_COLOR, with RAVEN_REDUCED_MOTION, with a screen reader and when the
//!   output is not a terminal ([`default_motion`]).
//!
//! Colours never carry meaning alone: every state also has its glyph or word.

use std::ffi::OsString;
use std::time::Duration;

use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;

use super::state_file::{ColorSetting, MotionSetting, PaletteSetting, SymbolSetting};

/// Time between spinner frames (tokens: `terminal.spinner.frameMs`).
const SPINNER_FRAME: Duration = Duration::from_millis(80);
/// Over SSH, where every frame crosses the network: half as many.
const SSH_SPINNER_FRAME: Duration = Duration::from_millis(160);

/// Calm's motion timings (tokens: `terminal`): Delivered types itself a
/// character at a time, and the in-touch marks breathe.
pub(super) const DELIVERED_CHAR: Duration = Duration::from_millis(45);
pub(super) const BREATHE: Duration = Duration::from_millis(1500);

/// WZ-1's welcome timings, in ms from its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WelcomeMs {
    /// The mark's dots assemble over this long.
    pub(super) mark_assemble: u64,
    /// The letters R A V E N on the card's border: one more this often,
    /// from `letters_from`.
    pub(super) letter_every: u64,
    pub(super) letters_from: u64,
    /// 'Welcome to Raven'.
    pub(super) title_at: u64,
    /// The tagline types itself, a character this often.
    pub(super) tagline_from: u64,
    pub(super) tagline_char_every: u64,
    /// The copy, then the keys.
    pub(super) body_at: u64,
    pub(super) keys_at: u64,
}

/// WZ-1 (tokens: `terminal.welcomeMs`): the mark's dots assemble, the
/// letters come one by one, then the title, the tagline typing itself, the
/// copy and the keys.
pub(super) const WELCOME_MS: WelcomeMs = WelcomeMs {
    mark_assemble: 1500,
    letter_every: 100,
    letters_from: 1500,
    title_at: 2100,
    tagline_from: 2200,
    tagline_char_every: 25,
    body_at: 3000,
    keys_at: 3300,
};

/// A 24-bit colour of the Calm palettes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Rgb(pub(super) u8, pub(super) u8, pub(super) u8);

impl Rgb {
    /// `0xRRGGBB`.
    const fn hex(rgb: u32) -> Rgb {
        Rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
    }

    /// Halfway between this colour and `other`.
    fn mix(self, other: Rgb) -> Rgb {
        let half = |a: u8, b: u8| ((u16::from(a) + u16::from(b)) / 2) as u8;
        Rgb(
            half(self.0, other.0),
            half(self.1, other.1),
            half(self.2, other.2),
        )
    }
}

/// One Calm palette (desktop/design/tokens.json, `terminal.dark` and
/// `terminal.light`; a test keeps them equal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Palette {
    pub(super) bg: Rgb,
    pub(super) fg: Rgb,
    pub(super) dim: Rgb,
    pub(super) faint: Rgb,
    pub(super) accent: Rgb,
    pub(super) ok: Rgb,
    pub(super) warn: Rgb,
    pub(super) bad: Rgb,
    pub(super) selection: Rgb,
    pub(super) key: Rgb,
    pub(super) lan: Rgb,
    pub(super) nearby: Rgb,
    pub(super) tor: Rgb,
    pub(super) direct: Rgb,
    pub(super) relay: Rgb,
    pub(super) friend: Rgb,
}

/// For dark terminals.
pub(super) const DARK: Palette = Palette {
    bg: Rgb::hex(0x1C1C1A),
    fg: Rgb::hex(0xECEBE6),
    dim: Rgb::hex(0xA3A29B),
    faint: Rgb::hex(0x4A4945),
    accent: Rgb::hex(0x85B7EB),
    ok: Rgb::hex(0x97C459),
    warn: Rgb::hex(0xEF9F27),
    bad: Rgb::hex(0xF09595),
    selection: Rgb::hex(0x2B2B28),
    key: Rgb::hex(0x34342F),
    lan: Rgb::hex(0x6FA8F0),
    nearby: Rgb::hex(0xA3A3F5),
    tor: Rgb::hex(0xC59AF0),
    direct: Rgb::hex(0x4CC3B8),
    relay: Rgb::hex(0xA2AEBD),
    friend: Rgb::hex(0xEFB451),
};

/// For light terminals.
pub(super) const LIGHT: Palette = Palette {
    bg: Rgb::hex(0xFAF9F5),
    fg: Rgb::hex(0x1F1E1C),
    dim: Rgb::hex(0x6B6A65),
    faint: Rgb::hex(0xC9C7BE),
    accent: Rgb::hex(0x185FA5),
    ok: Rgb::hex(0x3B6D11),
    warn: Rgb::hex(0x925A0C),
    bad: Rgb::hex(0xA32D2D),
    selection: Rgb::hex(0xEEECE4),
    key: Rgb::hex(0xE7E5DC),
    lan: Rgb::hex(0x2F6FDC),
    nearby: Rgb::hex(0x5B5BD6),
    tor: Rgb::hex(0x8E4EC6),
    direct: Rgb::hex(0x12827A),
    relay: Rgb::hex(0x5F6B7A),
    friend: Rgb::hex(0xA86A12),
};

/// How many colours the terminal says it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Depth {
    /// The 16 the terminal's own theme sets: the Calm palettes can't be
    /// drawn, only the terminal's own colours.
    Ansi,
    /// The 256 of xterm: each Calm colour as the nearest of them.
    Indexed,
    /// 24-bit colour.
    True,
}

impl Depth {
    /// `rgb` as this depth draws it: itself, or the nearest of the 256.
    fn color(self, rgb: Rgb) -> Color {
        match self {
            Depth::True => Color::Rgb(rgb.0, rgb.1, rgb.2),
            Depth::Indexed | Depth::Ansi => Color::Indexed(nearest_256(rgb)),
        }
    }
}

/// The nearest of xterm's 256 colours to `rgb`, among the colour cube and
/// the greys (16 to 255): the first 16 are the terminal theme's own, so
/// nothing says what they look like.
pub(super) fn nearest_256(rgb: Rgb) -> u8 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let distance = |a: Rgb| -> u32 {
        let d = |x: u8, y: u8| u32::from(x.abs_diff(y)).pow(2);
        2 * d(a.0, rgb.0) + 4 * d(a.1, rgb.1) + 3 * d(a.2, rgb.2)
    };
    let mut best = (u32::MAX, 16u8);
    for (i, &r) in LEVELS.iter().enumerate() {
        for (j, &g) in LEVELS.iter().enumerate() {
            for (k, &b) in LEVELS.iter().enumerate() {
                let at = distance(Rgb(r, g, b));
                if at < best.0 {
                    // At most 16 + 215: it fits.
                    best = (at, (16 + 36 * i + 6 * j + k) as u8);
                }
            }
        }
    }
    for n in 0u8..24 {
        let v = 8 + 10 * n;
        let at = distance(Rgb(v, v, v));
        if at < best.0 {
            best = (at, 232 + n);
        }
    }
    best.1
}

/// The background the terminal says it has, if it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Background {
    Dark,
    Light,
}

/// The kinds of path a message goes by, each with its colour (tokens:
/// `color.pathRule`): the local network, Bluetooth nearby, Tor, the
/// internet directly (a hole punched, 443), peer-to-peer through relays,
/// a friend holding it, and anything else (the dim colour).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PathKind {
    Lan,
    Nearby,
    /// The Tor onion carrier ('via Tor').
    Tor,
    Direct,
    Relay,
    Friend,
    /// A path this app has no colour for.
    #[cfg_attr(not(test), allow(dead_code))]
    Other,
}

/// Windows code pages (Japanese, Simplified Chinese, Korean, Traditional
/// Chinese) whose console fonts draw box drawing and `·…●` two cells wide.
const CJK_CODE_PAGES: [u32; 4] = [932, 936, 949, 950];
/// Locale languages whose terminals draw the same characters two cells wide.
const CJK_LANGUAGES: [&str; 3] = ["zh", "ja", "ko"];

/// Box drawing in ASCII: `+` corners, `|` sides, `-` top and bottom.
const ASCII_BORDER: border::Set<'static> = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

/// The environment variables the look depends on, read once at startup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct TermEnv {
    /// TERM, when set.
    pub(super) term: Option<String>,
    /// NO_COLOR is set and not empty.
    pub(super) no_color: bool,
    /// RAVEN_REDUCED_MOTION is set, not empty and not `0`: no animation
    /// frames (UXF.10).
    pub(super) reduced_motion: bool,
    /// The values of LC_ALL, LC_CTYPE and LANG that are set and not empty.
    pub(super) locales: Vec<String>,
    /// WT_SESSION is set and not empty: Windows Terminal, not the console host.
    pub(super) wt_session: bool,
    /// SSH_CONNECTION or SSH_TTY is set and not empty.
    pub(super) ssh: bool,
    /// Running on Windows.
    pub(super) windows: bool,
    /// COLORTERM, when set: `truecolor` or `24bit` says 24-bit colour.
    pub(super) colorterm: Option<String>,
    /// COLORFGBG, when set: the terminal's own colours, `fg;bg` as two of
    /// its 16 (rxvt, Konsole, iTerm2 and others set it).
    pub(super) colorfgbg: Option<String>,
    /// The output is not a terminal: nothing animates (no frame is drawn
    /// that nobody sees as motion).
    pub(super) not_a_tty: bool,
    /// The background the terminal answered OSC 11 with at start
    /// (background.rs); None when it was not asked or didn't say.
    pub(super) answered_background: Option<Background>,
}

impl TermEnv {
    /// This process's environment.
    pub(super) fn from_process() -> TermEnv {
        use std::io::IsTerminal;
        TermEnv {
            not_a_tty: !std::io::stdout().is_terminal(),
            ..TermEnv::from_vars(|name| std::env::var_os(name), cfg!(windows))
        }
    }

    /// The environment that `var` reads.
    fn from_vars(var: impl Fn(&str) -> Option<OsString>, windows: bool) -> TermEnv {
        let value = |name: &str| {
            var(name)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string_lossy().into_owned())
        };
        TermEnv {
            term: value("TERM"),
            no_color: value("NO_COLOR").is_some(),
            reduced_motion: value("RAVEN_REDUCED_MOTION").is_some_and(|v| v.trim() != "0"),
            locales: ["LC_ALL", "LC_CTYPE", "LANG"]
                .into_iter()
                .filter_map(value)
                .collect(),
            wt_session: value("WT_SESSION").is_some(),
            ssh: value("SSH_CONNECTION").is_some() || value("SSH_TTY").is_some(),
            windows,
            colorterm: value("COLORTERM"),
            colorfgbg: value("COLORFGBG"),
            not_a_tty: false,
            answered_background: None,
        }
    }

    /// The Linux text console (TERM=linux): few glyphs, slow redraws.
    fn linux_console(&self) -> bool {
        self.term.as_deref() == Some("linux")
    }

    /// How many colours the terminal says it has: 24-bit where COLORTERM
    /// says so, in Windows Terminal, or where TERM names a direct-colour
    /// entry; 256 where TERM says so; the terminal's own 16 otherwise (the
    /// Linux console among them).
    pub(super) fn depth(&self) -> Depth {
        let colorterm = self.colorterm.as_deref().unwrap_or_default();
        let term = self.term.as_deref().unwrap_or_default();
        if colorterm.eq_ignore_ascii_case("truecolor")
            || colorterm.eq_ignore_ascii_case("24bit")
            || (self.windows && self.wt_session)
            || term.ends_with("-direct")
        {
            Depth::True
        } else if term.contains("256color") {
            Depth::Indexed
        } else {
            Depth::Ansi
        }
    }

    /// The background the terminal says it has: COLORFGBG's last field
    /// (one of its 16 colours: black to white but grey are dark), else its
    /// answer to OSC 11 at start (background.rs); None when it says
    /// nothing: then no palette is guessed for it.
    pub(super) fn background(&self) -> Option<Background> {
        self.colorfgbg_background().or(self.answered_background)
    }

    /// The background COLORFGBG says.
    fn colorfgbg_background(&self) -> Option<Background> {
        let bg = self.colorfgbg.as_deref()?.rsplit(';').next()?;
        match bg.trim().parse::<u8>().ok()? {
            0..=6 | 8 => Some(Background::Dark),
            7 | 9..=15 => Some(Background::Light),
            _ => None,
        }
    }
}

/// The styles every screen draws with.
///
/// The Calm palettes ([`Theme::calm`]) paint their own background
/// ([`Theme::base`]), so a palette reads the same in any terminal; the
/// terminal's own colours ([`Theme::color`]) and no colours
/// ([`Theme::mono`]) set foregrounds and attributes only, so the user's own
/// background shows through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Theme {
    /// Things that worked: Delivered, Listening.
    pub(super) ok: Style,
    /// Things that failed: Not delivered, errors.
    pub(super) bad: Style,
    /// Your own name, the open friend's, keys in hints, what is new.
    pub(super) accent: Style,
    /// Less important text: times, help lines, hints.
    pub(super) secondary: Style,
    /// Warnings and waiting. In the terminal's own colours bold, never
    /// yellow (unreadable on light profiles).
    pub(super) warn: Style,
    /// The selected row, which also always has the '>' marker (the bar in
    /// a palette).
    pub(super) selected: Style,
    /// Plain text.
    pub(super) text: Style,
    /// Box borders, rules and what is least important.
    pub(super) faint: Style,
    /// The border of the box that has the keys.
    pub(super) focus: Style,
    /// A box's title, and names.
    pub(super) title: Style,
    /// A key in the hints: a chip where the theme has [`Theme::chips`].
    pub(super) key: Style,
    /// The unread count: a chip in a palette.
    pub(super) unread: Style,
    /// The breathing in-touch mark's quiet half.
    pub(super) breath: Style,
    /// What every cell starts as: the palette's background and text, or
    /// nothing.
    pub(super) base: Style,
    /// Each path kind's colour, in [`PathKind`]'s order but Other (which is
    /// `secondary`).
    pub(super) paths: [Style; 6],
    /// Keys are chips with a background, in place of their brackets.
    pub(super) chips: bool,
    /// The decoration a colour theme adds: the bar before your own lines,
    /// the selection bar. None without colours: there the screen stays
    /// plain text, for screen readers and plain terminals.
    pub(super) decor: bool,
}

impl Theme {
    /// The terminal's own colours: green, red, cyan and magenta only.
    /// Secondary text is the terminal's own colour dimmed, never Gray or
    /// DarkGray: ANSI 37 is nearly invisible on macOS Terminal's white
    /// profile.
    pub(super) const fn color() -> Theme {
        let plain = Style::new().fg(Color::Reset);
        let dim = plain.add_modifier(Modifier::DIM);
        let cyan = Style::new().fg(Color::Cyan);
        let magenta = Style::new().fg(Color::Magenta);
        let bold = plain.add_modifier(Modifier::BOLD);
        Theme {
            ok: Style::new().fg(Color::Green),
            bad: Style::new().fg(Color::Red),
            accent: cyan,
            secondary: dim,
            warn: bold,
            selected: Style::new().add_modifier(Modifier::REVERSED),
            text: plain,
            faint: dim,
            focus: plain,
            title: bold,
            key: cyan,
            unread: cyan,
            breath: Style::new().fg(Color::Green).add_modifier(Modifier::DIM),
            base: Style::new(),
            paths: [cyan, magenta, magenta, cyan, dim, bold],
            chips: false,
            decor: true,
        }
    }

    /// No colours: the terminal's own, with bold, dim and reverse.
    pub(super) const fn mono() -> Theme {
        let plain = Style::new().fg(Color::Reset);
        let bold = plain.add_modifier(Modifier::BOLD);
        Theme {
            ok: plain,
            bad: bold,
            accent: bold,
            secondary: plain.add_modifier(Modifier::DIM),
            warn: bold,
            selected: Style::new().add_modifier(Modifier::REVERSED),
            text: plain,
            faint: plain.add_modifier(Modifier::DIM),
            focus: bold,
            title: bold,
            key: bold,
            unread: bold,
            breath: plain.add_modifier(Modifier::DIM),
            base: Style::new(),
            paths: [plain; 6],
            chips: false,
            decor: false,
        }
    }

    /// A Calm palette at `depth` (24-bit, or the nearest of the 256): its
    /// own background under everything, keys as chips.
    pub(super) fn calm(palette: &Palette, depth: Depth) -> Theme {
        let c = |rgb: Rgb| Style::new().fg(depth.color(rgb));
        let bg = depth.color(palette.bg);
        let text = c(palette.fg);
        Theme {
            ok: c(palette.ok),
            bad: c(palette.bad),
            accent: c(palette.accent),
            secondary: c(palette.dim),
            warn: c(palette.warn),
            selected: Style::new().bg(depth.color(palette.selection)),
            text,
            faint: c(palette.faint),
            focus: c(palette.dim),
            title: text.add_modifier(Modifier::BOLD),
            key: text
                .bg(depth.color(palette.key))
                .add_modifier(Modifier::BOLD),
            unread: Style::new()
                .fg(bg)
                .bg(depth.color(palette.accent))
                .add_modifier(Modifier::BOLD),
            breath: c(palette.ok.mix(palette.bg)),
            base: text.bg(bg),
            paths: [
                c(palette.lan),
                c(palette.nearby),
                c(palette.tor),
                c(palette.direct),
                c(palette.relay),
                c(palette.friend),
            ],
            chips: true,
            decor: true,
        }
    }

    /// The theme Settings ask for in a terminal like `env`:
    ///
    /// - no colours when NO_COLOR asks for it (Settings then show 'set by
    ///   NO_COLOR') or the setting does;
    /// - Dark or Light: that palette, in 24-bit colour where the terminal
    ///   says it has it, else the nearest of the 256;
    /// - Automatic: the palette for the background the terminal says it
    ///   has (COLORFGBG, else its answer to OSC 11 at start), when it has 256
    ///   colours or more; else the terminal's own colours. Raven never
    ///   guesses the background.
    pub(super) fn for_setting(
        colors: ColorSetting,
        palette: PaletteSetting,
        env: &TermEnv,
    ) -> Theme {
        if env.no_color || colors == ColorSetting::NoColors {
            return Theme::mono();
        }
        let depth = env.depth();
        match (palette, env.background()) {
            (PaletteSetting::Dark, _) => Theme::calm(&DARK, depth.max(Depth::Indexed)),
            (PaletteSetting::Light, _) => Theme::calm(&LIGHT, depth.max(Depth::Indexed)),
            (PaletteSetting::Auto, _) if depth == Depth::Ansi => Theme::color(),
            (PaletteSetting::Auto, Some(Background::Dark)) => Theme::calm(&DARK, depth),
            (PaletteSetting::Auto, Some(Background::Light)) => Theme::calm(&LIGHT, depth),
            (PaletteSetting::Auto, None) => Theme::color(),
        }
    }

    /// The colour of a path of `kind`.
    pub(super) fn path(&self, kind: PathKind) -> Style {
        match kind {
            PathKind::Lan => self.paths[0],
            PathKind::Nearby => self.paths[1],
            PathKind::Tor => self.paths[2],
            PathKind::Direct => self.paths[3],
            PathKind::Relay => self.paths[4],
            PathKind::Friend => self.paths[5],
            PathKind::Other => self.secondary,
        }
    }

    /// Whether the theme paints its own background.
    pub(super) fn paints(&self) -> bool {
        self.base.bg.is_some()
    }
}

/// The three glyph sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GlyphSet {
    Fancy,
    Simple,
    Ascii,
}

/// Every mark the screens draw, in one glyph set. The HELP legend explains
/// each one in words, and each is a single cell wide except the two-tick
/// `delivered`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Glyphs {
    /// Node chip: listening on the network.
    pub(super) dot_on: &'static str,
    /// Node chip: receiving on this computer only, or sending only. Friend:
    /// messages waiting.
    pub(super) dot_half: &'static str,
    /// Node chip: not running, or receiving is off. Friend: no recent contact.
    pub(super) dot_off: &'static str,
    /// Friend: no address.
    pub(super) dot_none: &'static str,
    /// Node chip: needs setup, not responding, waiting for permission.
    /// Friend: not verified.
    pub(super) dot_alert: &'static str,
    /// Friend: in touch recently.
    pub(super) dot_recent: &'static str,
    /// A security alert or warning is open (P6.31): the header chip
    /// ('⚠ 2', '!2') and SEC's mark for an alert.
    pub(super) alarm: &'static str,
    /// A friend's badge while a security alert or warning about them is
    /// open (P6.31): Simple's is two cells, so it never reads as the
    /// one-cell 'not verified' mark.
    pub(super) alarm_badge: &'static str,
    /// Sending, and the 'Starting' chip: one frame per spinner tick.
    pub(super) spinner: &'static [&'static str],
    /// Waiting (Raven keeps trying).
    pub(super) tick_waiting: &'static str,
    /// Sent: it left this computer, not confirmed yet.
    pub(super) tick_sent: &'static str,
    /// Delivered: their Raven confirmed it.
    pub(super) tick_delivered: &'static str,
    /// Not delivered, not confirmed or not sent.
    pub(super) tick_failed: &'static str,
    /// In front of the selected row, in every set.
    pub(super) selected: &'static str,
    /// In front of each item of a list in the app's own copy.
    pub(super) bullet: &'static str,
    pub(super) border: border::Set<'static>,
    /// Between the items of a key-hint row: '? Help · Q Quit'.
    pub(super) separator: &'static str,
    /// Between the parts of one label: 'You · just now'.
    pub(super) inline_separator: &'static str,
    /// The end of cut text, and the spinner under reduced motion.
    pub(super) ellipsis: &'static str,
    /// The arrow keys in hints: '↑↓ Choose'.
    pub(super) up_down: &'static str,
    /// In front of a suggestion: '→ turtle'.
    pub(super) arrow: &'static str,
    /// Home's heartbeat: a Status poll the background program answered
    /// (UXF.10).
    pub(super) heart: &'static str,
    /// A friend's waiting mark while Raven tries their messages again: the
    /// retry ring's frames (UXF.10).
    pub(super) ring: [&'static str; 4],
    /// The route line between you and the open friend, one cell a step:
    /// while you are in touch, and dashed otherwise.
    pub(super) route: &'static str,
    pub(super) route_dash: &'static str,
    /// Each end of the route line.
    pub(super) route_end: &'static str,
    /// In front of the selected row where the theme has a selection colour
    /// (the bar; `selected` everywhere else).
    pub(super) bar: &'static str,
    /// In front of each line of your own messages, where the theme has
    /// decoration ([`Theme::decor`]).
    pub(super) own: &'static str,
    /// Around the chosen value in Settings: '‹ Dark ›'.
    pub(super) value_before: &'static str,
    pub(super) value_after: &'static str,
    /// What travels the route line: your message out, theirs in.
    pub(super) route_out: &'static str,
    pub(super) route_in: &'static str,
    /// The footer's activity line, quietest first: 0 to 6 or more messages
    /// in a bucket.
    pub(super) bars: [&'static str; 7],
}

impl Glyphs {
    /// For terminals with good Unicode fonts.
    pub(super) const fn fancy() -> Glyphs {
        Glyphs {
            dot_on: "●",
            dot_half: "◐",
            dot_off: "○",
            dot_none: "✕",
            dot_alert: "!",
            dot_recent: "●",
            alarm: "⚠",
            alarm_badge: "⚠",
            spinner: &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            tick_waiting: "~",
            tick_sent: "✓",
            tick_delivered: "✓✓",
            tick_failed: "✗",
            selected: ">",
            bullet: "•",
            border: border::ROUNDED,
            separator: " · ",
            inline_separator: " · ",
            ellipsis: "…",
            up_down: "↑↓",
            arrow: "→",
            heart: "♥",
            ring: ["◌", "◎", "◉", "◎"],
            route: "─",
            route_dash: "┄",
            route_end: "◉",
            bar: "▌",
            own: "│",
            value_before: "‹",
            value_after: "›",
            route_out: "▸",
            route_in: "◂",
            bars: ["⣀", "⣠", "⣤", "⣴", "⣶", "⣾", "⣿"],
        }
    }

    /// For older terminals (the Windows console host, the Linux text
    /// console): ASCII marks inside plain box drawing.
    pub(super) const fn simple() -> Glyphs {
        Glyphs {
            dot_on: "*",
            dot_half: "~",
            dot_off: "o",
            dot_none: "x",
            dot_alert: "!",
            dot_recent: "*",
            alarm: "!",
            alarm_badge: "!!",
            spinner: &["|", "/", "-", "\\"],
            tick_waiting: "~",
            tick_sent: "v",
            tick_delivered: "vv",
            tick_failed: "x",
            selected: ">",
            bullet: "-",
            border: border::PLAIN,
            separator: "  ",
            inline_separator: " - ",
            ellipsis: "...",
            up_down: "Up/Down",
            arrow: "->",
            heart: "+",
            ring: ["o", "O", "@", "O"],
            route: "-",
            route_dash: "-",
            route_end: "*",
            bar: ">",
            own: "|",
            value_before: "<",
            value_after: ">",
            route_out: ">",
            route_in: "<",
            bars: [".", ":", "-", "=", "+", "*", "#"],
        }
    }

    /// Simple with ASCII borders, for any terminal.
    pub(super) const fn ascii() -> Glyphs {
        Glyphs {
            border: ASCII_BORDER,
            ..Glyphs::simple()
        }
    }

    pub(super) const fn of(set: GlyphSet) -> Glyphs {
        match set {
            GlyphSet::Fancy => Glyphs::fancy(),
            GlyphSet::Simple => Glyphs::simple(),
            GlyphSet::Ascii => Glyphs::ascii(),
        }
    }

    /// The spinner's `frame`th frame; a still ellipsis under reduced motion.
    pub(super) fn spinner_frame(&self, motion: Motion, frame: u64) -> &'static str {
        match motion {
            Motion::Full => {
                // The frame count is a handful, so both casts are lossless.
                self.spinner[(frame % self.spinner.len() as u64) as usize]
            }
            Motion::Reduced => self.ellipsis,
        }
    }
}

/// The glyph set for this terminal:
///
/// - Ascii when a locale (LC_ALL, LC_CTYPE or LANG) is Chinese, Japanese or
///   Korean, or the Windows output code page is 932, 936, 949 or 950: box
///   drawing and `·…●` are East Asian Ambiguous, two cells wide there;
/// - Simple on Windows outside Windows Terminal (the console host's fonts lack
///   braille and ✓, and it has no font fallback) and on the Linux text console;
/// - Fancy otherwise.
pub(super) fn auto_symbols(env: &TermEnv, code_page: Option<u32>) -> GlyphSet {
    let cjk_locale = env.locales.iter().any(|locale| {
        CJK_LANGUAGES
            .iter()
            .any(|&l| locale_language(locale).eq_ignore_ascii_case(l))
    });
    if cjk_locale || code_page.is_some_and(|cp| CJK_CODE_PAGES.contains(&cp)) {
        GlyphSet::Ascii
    } else if (env.windows && !env.wt_session) || env.linux_console() {
        GlyphSet::Simple
    } else {
        GlyphSet::Fancy
    }
}

/// The language of a POSIX locale name, `ja` of `ja_JP.UTF-8`: so `kok_IN`
/// (Konkani) is not taken for Korean.
fn locale_language(locale: &str) -> &str {
    locale
        .split(['_', '.', '@', '-'])
        .next()
        .unwrap_or_default()
}

/// The glyph set Settings ask for: Automatic follows [`auto_symbols`].
pub(super) fn glyph_set(setting: SymbolSetting, env: &TermEnv, code_page: Option<u32>) -> GlyphSet {
    match setting {
        SymbolSetting::Auto => auto_symbols(env, code_page),
        SymbolSetting::Ascii => GlyphSet::Ascii,
        SymbolSetting::Simple => GlyphSet::Simple,
        SymbolSetting::Fancy => GlyphSet::Fancy,
    }
}

/// How much moves on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Motion {
    /// Spinners, the delivered draw-in, blinks, and the live feel's motion
    /// (UXF.10): the Welcome mark's reveal, the heartbeat's pulse, the route
    /// line, the retry ring.
    Full,
    /// No spinners (a still '…'), no draw-ins, blinks or travel: only text
    /// changes (the clock, the ages).
    Reduced,
}

/// Reduced on the Linux text console (slow redraws), under NO_COLOR (a
/// request for a quiet terminal), with RAVEN_REDUCED_MOTION, while a screen
/// reader runs and when the output is not a terminal; Full otherwise.
pub(super) fn default_motion(env: &TermEnv, screen_reader: bool) -> Motion {
    if env.linux_console() || env.no_color || env.reduced_motion || screen_reader || env.not_a_tty {
        Motion::Reduced
    } else {
        Motion::Full
    }
}

/// The motion Settings ask for: Automatic follows [`default_motion`].
pub(super) fn motion(setting: MotionSetting, env: &TermEnv, screen_reader: bool) -> Motion {
    match setting {
        MotionSetting::Auto => default_motion(env, screen_reader),
        MotionSetting::Full => Motion::Full,
        MotionSetting::Reduced => Motion::Reduced,
    }
}

/// Time between spinner frames: 80 ms, or 160 ms over SSH. It is the frame
/// budget of every animation too (anim.rs never draws frames closer).
pub(super) fn spinner_interval(env: &TermEnv) -> Duration {
    if env.ssh {
        SSH_SPINNER_FRAME
    } else {
        SPINNER_FRAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::text::Span;

    /// The environment of a terminal with these variables set.
    fn env(vars: &[(&str, &str)], windows: bool) -> TermEnv {
        TermEnv::from_vars(
            |name| {
                vars.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| OsString::from(v))
            },
            windows,
        )
    }

    /// A macOS or Linux desktop terminal.
    fn desktop() -> TermEnv {
        env(
            &[("TERM", "xterm-256color"), ("LANG", "en_US.UTF-8")],
            false,
        )
    }

    #[test]
    fn environment_is_read_as_the_rules_say() {
        let empty = env(&[], false);
        assert_eq!(empty, TermEnv::default());
        // NO_COLOR counts only when not empty (cli.rs's color_enabled_for).
        assert!(!env(&[("NO_COLOR", "")], false).no_color);
        assert!(env(&[("NO_COLOR", "1")], false).no_color);
        assert!(env(&[("SSH_TTY", "/dev/ttys004")], false).ssh);
        assert!(env(&[("SSH_CONNECTION", "10.0.0.2 52000 10.0.0.1 22")], false).ssh);
        assert!(!env(&[("SSH_TTY", "")], false).ssh);
        assert!(env(&[("RAVEN_REDUCED_MOTION", "1")], false).reduced_motion);
        assert!(!env(&[("RAVEN_REDUCED_MOTION", "")], false).reduced_motion);
        assert!(!env(&[("RAVEN_REDUCED_MOTION", "0")], false).reduced_motion);
        assert!(env(&[("WT_SESSION", "0c5f3a2e")], true).wt_session);
        let all = env(
            &[("LANG", "en_US.UTF-8"), ("LC_ALL", "C"), ("LC_CTYPE", "")],
            false,
        );
        assert_eq!(all.locales, ["C", "en_US.UTF-8"]);
        // The real environment goes through the same reading, and whether
        // the output is a terminal.
        assert_eq!(
            TermEnv {
                not_a_tty: false,
                ..TermEnv::from_process()
            },
            TermEnv::from_vars(|name| std::env::var_os(name), cfg!(windows))
        );
        use std::io::IsTerminal;
        assert_eq!(
            TermEnv::from_process().not_a_tty,
            !std::io::stdout().is_terminal()
        );
    }

    #[test]
    fn no_color_gives_mono_and_reduced_motion() {
        let no_color = TermEnv {
            no_color: true,
            ..desktop()
        };
        assert_eq!(
            Theme::for_setting(ColorSetting::Auto, PaletteSetting::Auto, &no_color),
            Theme::mono()
        );
        assert_eq!(
            Theme::for_setting(ColorSetting::NoColors, PaletteSetting::Auto, &no_color),
            Theme::mono()
        );
        assert_eq!(default_motion(&no_color, false), Motion::Reduced);
        assert_eq!(
            motion(MotionSetting::Auto, &no_color, false),
            Motion::Reduced
        );
        // An explicit setting wins over the default, for motion only.
        assert_eq!(motion(MotionSetting::Full, &no_color, false), Motion::Full);

        let plain = desktop();
        assert_eq!(
            Theme::for_setting(ColorSetting::Auto, PaletteSetting::Auto, &plain),
            Theme::color()
        );
        assert_eq!(
            Theme::for_setting(ColorSetting::NoColors, PaletteSetting::Auto, &plain),
            Theme::mono()
        );
        assert_eq!(default_motion(&plain, false), Motion::Full);
        assert_eq!(
            motion(MotionSetting::Reduced, &plain, false),
            Motion::Reduced
        );
        // A screen reader asks for stillness too.
        assert_eq!(default_motion(&plain, true), Motion::Reduced);
        // So does RAVEN_REDUCED_MOTION (UXF.10), unless Settings say Full.
        let still = TermEnv {
            reduced_motion: true,
            ..desktop()
        };
        assert_eq!(default_motion(&still, false), Motion::Reduced);
        assert_eq!(motion(MotionSetting::Auto, &still, false), Motion::Reduced);
        assert_eq!(motion(MotionSetting::Full, &still, false), Motion::Full);
    }

    #[test]
    fn windows_console_and_linux_console_pick_simple() {
        let conhost = env(&[("LANG", "en_US.UTF-8")], true);
        assert_eq!(auto_symbols(&conhost, Some(437)), GlyphSet::Simple);
        assert_eq!(auto_symbols(&conhost, Some(65001)), GlyphSet::Simple);
        let windows_terminal = env(&[("WT_SESSION", "0c5f3a2e")], true);
        assert_eq!(
            auto_symbols(&windows_terminal, Some(65001)),
            GlyphSet::Fancy
        );
        // So delivered reads ✓✓ in Windows Terminal, vv in the console host.
        let delivered = |env: &TermEnv| Glyphs::of(auto_symbols(env, Some(65001))).tick_delivered;
        assert_eq!(delivered(&windows_terminal), "✓✓");
        assert_eq!(delivered(&conhost), "vv");
        // WT_SESSION means nothing off Windows.
        let elsewhere = env(&[("WT_SESSION", "0c5f3a2e")], false);
        assert_eq!(auto_symbols(&elsewhere, None), GlyphSet::Fancy);

        let linux_console = env(&[("TERM", "linux"), ("LANG", "en_US.UTF-8")], false);
        assert_eq!(auto_symbols(&linux_console, None), GlyphSet::Simple);
        assert_eq!(default_motion(&linux_console, false), Motion::Reduced);

        assert_eq!(auto_symbols(&desktop(), None), GlyphSet::Fancy);
        assert_eq!(auto_symbols(&env(&[], false), None), GlyphSet::Fancy);
    }

    #[test]
    fn cjk_locales_and_code_pages_pick_ascii() {
        for locale in [
            "ja_JP.UTF-8",
            "zh_CN.UTF-8",
            "zh_TW.Big5",
            "ko_KR.eucKR",
            "ja",
            "zh-Hant",
        ] {
            for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
                assert_eq!(
                    auto_symbols(&env(&[(var, locale)], false), None),
                    GlyphSet::Ascii,
                    "{var}={locale}"
                );
            }
        }
        // Any of the three counts: the terminal's widths do not follow LC_ALL.
        let mixed = env(&[("LC_ALL", "C"), ("LANG", "ja_JP.UTF-8")], false);
        assert_eq!(auto_symbols(&mixed, None), GlyphSet::Ascii);
        for locale in ["kok_IN", "en_US.UTF-8", "C.UTF-8", "POSIX", "jv_ID"] {
            assert_eq!(
                auto_symbols(&env(&[("LANG", locale)], false), None),
                GlyphSet::Fancy,
                "LANG={locale}"
            );
        }

        let conhost = env(&[], true);
        for cp in CJK_CODE_PAGES {
            assert_eq!(
                auto_symbols(&conhost, Some(cp)),
                GlyphSet::Ascii,
                "code page {cp}"
            );
        }
        // Ascii comes before Simple.
        let console_ja = env(&[("TERM", "linux"), ("LANG", "ja_JP.UTF-8")], false);
        assert_eq!(auto_symbols(&console_ja, None), GlyphSet::Ascii);
    }

    #[test]
    fn settings_override_the_automatic_set() {
        let ja = env(&[("LANG", "ja_JP.UTF-8")], false);
        assert_eq!(glyph_set(SymbolSetting::Auto, &ja, None), GlyphSet::Ascii);
        assert_eq!(glyph_set(SymbolSetting::Fancy, &ja, None), GlyphSet::Fancy);
        assert_eq!(
            glyph_set(SymbolSetting::Simple, &desktop(), None),
            GlyphSet::Simple
        );
        assert_eq!(
            glyph_set(SymbolSetting::Ascii, &desktop(), None),
            GlyphSet::Ascii
        );
        assert_eq!(Glyphs::of(GlyphSet::Fancy), Glyphs::fancy());
        assert_eq!(Glyphs::of(GlyphSet::Simple), Glyphs::simple());
        assert_eq!(Glyphs::of(GlyphSet::Ascii), Glyphs::ascii());
    }

    #[test]
    fn ssh_halves_the_spinner_rate() {
        assert_eq!(spinner_interval(&desktop()), Duration::from_millis(80));
        let ssh = env(&[("SSH_CONNECTION", "10.0.0.2 52000 10.0.0.1 22")], false);
        assert_eq!(spinner_interval(&ssh), Duration::from_millis(160));
    }

    #[test]
    fn output_that_is_not_a_terminal_never_animates() {
        let piped = TermEnv {
            not_a_tty: true,
            ..desktop()
        };
        assert_eq!(default_motion(&piped, false), Motion::Reduced);
        assert_eq!(motion(MotionSetting::Auto, &piped, false), Motion::Reduced);
        assert_eq!(default_motion(&desktop(), false), Motion::Full);
    }

    #[test]
    fn the_depth_is_what_the_terminal_says() {
        assert_eq!(desktop().depth(), Depth::Indexed);
        assert_eq!(env(&[("TERM", "xterm")], false).depth(), Depth::Ansi);
        assert_eq!(env(&[("TERM", "linux")], false).depth(), Depth::Ansi);
        assert_eq!(env(&[], false).depth(), Depth::Ansi);
        for colorterm in ["truecolor", "24bit", "TrueColor"] {
            let true_color = env(&[("TERM", "xterm"), ("COLORTERM", colorterm)], false);
            assert_eq!(true_color.depth(), Depth::True, "{colorterm}");
        }
        assert_eq!(
            env(&[("TERM", "xterm-256color"), ("COLORTERM", "yes")], false).depth(),
            Depth::Indexed
        );
        assert_eq!(env(&[("TERM", "xterm-direct")], false).depth(), Depth::True);
        assert_eq!(
            env(&[("WT_SESSION", "0c5f3a2e")], true).depth(),
            Depth::True
        );
        assert_eq!(
            env(&[("WT_SESSION", "0c5f3a2e")], false).depth(),
            Depth::Ansi
        );
    }

    #[test]
    fn the_background_is_only_what_colorfgbg_says() {
        let with = |value: &str| env(&[("COLORFGBG", value)], false).background();
        assert_eq!(with("15;0"), Some(Background::Dark));
        assert_eq!(with("7;8"), Some(Background::Dark));
        assert_eq!(with("0;15"), Some(Background::Light));
        assert_eq!(with("0;7"), Some(Background::Light));
        assert_eq!(with("12;default;0"), Some(Background::Dark));
        assert_eq!(with("default;default"), None);
        assert_eq!(with("15;200"), None);
        assert_eq!(with(""), None);
        assert_eq!(desktop().background(), None);
    }

    #[test]
    fn automatic_never_guesses_a_palette() {
        let auto = |vars: &[(&str, &str)]| {
            Theme::for_setting(ColorSetting::Auto, PaletteSetting::Auto, &env(vars, false))
        };
        // Nothing says the background: the terminal's own colours.
        assert_eq!(auto(&[("TERM", "xterm-256color")]), Theme::color());
        assert_eq!(
            auto(&[("TERM", "xterm-256color"), ("COLORTERM", "truecolor")]),
            Theme::color()
        );
        // COLORFGBG says it: that palette, at the terminal's depth.
        assert_eq!(
            auto(&[("TERM", "xterm-256color"), ("COLORFGBG", "15;0")]),
            Theme::calm(&DARK, Depth::Indexed)
        );
        assert_eq!(
            auto(&[
                ("TERM", "xterm-256color"),
                ("COLORTERM", "truecolor"),
                ("COLORFGBG", "0;15")
            ]),
            Theme::calm(&LIGHT, Depth::True)
        );
        // 16 colours only: the terminal's own, whatever it says.
        assert_eq!(
            auto(&[("TERM", "xterm"), ("COLORFGBG", "15;0")]),
            Theme::color()
        );
        // Dark and Light are the palettes, in 256 colours at least.
        let plain = env(&[("TERM", "xterm")], false);
        assert_eq!(
            Theme::for_setting(ColorSetting::Auto, PaletteSetting::Dark, &plain),
            Theme::calm(&DARK, Depth::Indexed)
        );
        assert_eq!(
            Theme::for_setting(ColorSetting::Auto, PaletteSetting::Light, &plain),
            Theme::calm(&LIGHT, Depth::Indexed)
        );
        // No colors and NO_COLOR win over a palette.
        assert_eq!(
            Theme::for_setting(ColorSetting::NoColors, PaletteSetting::Dark, &plain),
            Theme::mono()
        );
        let no_color = env(&[("TERM", "xterm-256color"), ("NO_COLOR", "1")], false);
        assert_eq!(
            Theme::for_setting(ColorSetting::Auto, PaletteSetting::Light, &no_color),
            Theme::mono()
        );
    }

    #[test]
    fn the_palettes_draw_in_24_bit_or_the_nearest_of_256() {
        let dark = Theme::calm(&DARK, Depth::True);
        assert_eq!(dark.ok.fg, Some(Color::Rgb(0x97, 0xC4, 0x59)));
        assert_eq!(dark.base.bg, Some(Color::Rgb(0x1C, 0x1C, 0x1A)));
        assert_eq!(dark.selected.bg, Some(Color::Rgb(0x2B, 0x2B, 0x28)));
        assert_eq!(dark.key.bg, Some(Color::Rgb(0x34, 0x34, 0x2F)));
        assert!(dark.paints() && dark.chips && dark.decor);
        let indexed = Theme::calm(&DARK, Depth::Indexed);
        // #1C1C1A is grey 234 (#1C1C1C); #ECEBE6 grey 255; #85B7EB 110.
        assert_eq!(indexed.base.bg, Some(Color::Indexed(234)));
        assert_eq!(indexed.text.fg, Some(Color::Indexed(255)));
        assert_eq!(indexed.accent.fg, Some(Color::Indexed(110)));
        // Never one of the first 16: those are the terminal theme's own.
        for palette in [DARK, LIGHT] {
            for rgb in palette_colors(&palette) {
                assert!(nearest_256(rgb) >= 16, "{rgb:?}");
            }
        }
        assert_eq!(nearest_256(Rgb(0, 0, 0)), 16);
        assert_eq!(nearest_256(Rgb(255, 255, 255)), 231);
        assert_eq!(nearest_256(Rgb(0x80, 0x80, 0x80)), 244);
        // The terminal's own colours and none paint nothing.
        for theme in [Theme::color(), Theme::mono()] {
            assert!(!theme.paints() && !theme.chips);
        }
        assert!(Theme::color().decor && !Theme::mono().decor);
    }

    #[test]
    fn each_path_kind_has_its_colour() {
        let dark = Theme::calm(&DARK, Depth::True);
        let fg = |kind| dark.path(kind).fg;
        let rgb = |c: Rgb| Some(Color::Rgb(c.0, c.1, c.2));
        assert_eq!(fg(PathKind::Lan), rgb(DARK.lan));
        assert_eq!(fg(PathKind::Nearby), rgb(DARK.nearby));
        assert_eq!(fg(PathKind::Tor), rgb(DARK.tor));
        assert_eq!(fg(PathKind::Direct), rgb(DARK.direct));
        assert_eq!(fg(PathKind::Relay), rgb(DARK.relay));
        assert_eq!(fg(PathKind::Friend), rgb(DARK.friend));
        assert_eq!(fg(PathKind::Other), rgb(DARK.dim));
        let light = Theme::calm(&LIGHT, Depth::True);
        assert_eq!(light.path(PathKind::Lan).fg, rgb(LIGHT.lan));
        assert_eq!(light.path(PathKind::Friend).fg, rgb(LIGHT.friend));
        // No colours: every path as plain text (its words say which).
        for kind in [PathKind::Lan, PathKind::Tor, PathKind::Friend] {
            assert_eq!(Theme::mono().path(kind), Style::new().fg(Color::Reset));
        }
    }

    /// Every colour of `palette`, in tokens.json's order.
    fn palette_colors(palette: &Palette) -> [Rgb; 16] {
        [
            palette.bg,
            palette.fg,
            palette.dim,
            palette.faint,
            palette.accent,
            palette.ok,
            palette.warn,
            palette.bad,
            palette.selection,
            palette.key,
            palette.lan,
            palette.nearby,
            palette.tor,
            palette.direct,
            palette.relay,
            palette.friend,
        ]
    }

    /// The design tokens, from the repository's desktop/ folder; None when
    /// the node workspace is built without it.
    fn tokens() -> Option<serde_json::Value> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../desktop/design/tokens.json"
        );
        let Ok(text) = std::fs::read_to_string(path) else {
            eprintln!("{path} is missing: the palette is not checked against the tokens");
            return None;
        };
        Some(serde_json::from_str(&text).expect("tokens.json is JSON"))
    }

    #[test]
    fn the_palettes_are_the_design_tokens() {
        let Some(tokens) = tokens() else {
            return;
        };
        let terminal = &tokens["terminal"];
        let names = [
            "bg",
            "fg",
            "dim",
            "faint",
            "accent",
            "ok",
            "warn",
            "bad",
            "selection",
            "key",
            "lan",
            "nearby",
            "tor",
            "direct",
            "relay",
            "friend",
        ];
        for (name, palette) in [("dark", DARK), ("light", LIGHT)] {
            let section = terminal[name].as_object().expect("a palette");
            assert_eq!(section.len(), names.len(), "terminal.{name}");
            for (key, rgb) in names.iter().zip(palette_colors(&palette)) {
                let want = section[*key].as_str().expect("a colour");
                let have = format!("#{:02X}{:02X}{:02X}", rgb.0, rgb.1, rgb.2);
                assert_eq!(have, want.to_uppercase(), "terminal.{name}.{key}");
            }
        }
        // The motion: the spinner, the welcome, the draw-ins, the breath.
        let ms = |value: &serde_json::Value| value.as_u64().expect("ms");
        let spinner = &terminal["spinner"];
        assert_eq!(
            Glyphs::fancy().spinner.concat(),
            spinner["frames"].as_str().expect("frames")
        );
        assert_eq!(spinner["reduced"].as_str(), Some(Glyphs::fancy().ellipsis));
        assert_eq!(
            u64::try_from(SPINNER_FRAME.as_millis()).ok(),
            Some(ms(&spinner["frameMs"]))
        );
        let welcome = &terminal["welcomeMs"];
        let w = WELCOME_MS;
        for (key, value) in [
            ("markAssemble", w.mark_assemble),
            ("letterEvery", w.letter_every),
            ("lettersFrom", w.letters_from),
            ("titleAt", w.title_at),
            ("taglineFrom", w.tagline_from),
            ("taglineCharEvery", w.tagline_char_every),
            ("bodyAt", w.body_at),
            ("keysAt", w.keys_at),
        ] {
            assert_eq!(value, ms(&welcome[key]), "terminal.welcomeMs.{key}");
        }
        for (key, value) in [
            ("deliveredCharEvery", DELIVERED_CHAR),
            ("breatheMs", BREATHE),
        ] {
            assert_eq!(
                u64::try_from(value.as_millis()).ok(),
                Some(ms(&terminal[key])),
                "terminal.{key}"
            );
        }
    }

    /// Every style of `theme`, named.
    fn styles(theme: &Theme) -> Vec<(&'static str, Style)> {
        let mut styles = vec![
            ("ok", theme.ok),
            ("bad", theme.bad),
            ("accent", theme.accent),
            ("secondary", theme.secondary),
            ("warn", theme.warn),
            ("selected", theme.selected),
            ("text", theme.text),
            ("faint", theme.faint),
            ("focus", theme.focus),
            ("title", theme.title),
            ("key", theme.key),
            ("unread", theme.unread),
            ("breath", theme.breath),
            ("base", theme.base),
        ];
        styles.extend(theme.paths.iter().map(|style| ("path", *style)));
        styles
    }

    #[test]
    fn palettes_use_their_own_colours_only() {
        for palette in [DARK, LIGHT] {
            for depth in [Depth::True, Depth::Indexed] {
                let theme = Theme::calm(&palette, depth);
                let mut allowed: Vec<Color> = palette_colors(&palette)
                    .into_iter()
                    .map(|rgb| depth.color(rgb))
                    .collect();
                allowed.push(depth.color(palette.ok.mix(palette.bg)));
                for (name, style) in styles(&theme) {
                    for color in [style.fg, style.bg].into_iter().flatten() {
                        assert!(allowed.contains(&color), "{name}: {color:?}");
                    }
                    assert!(
                        (Modifier::BOLD).contains(style.add_modifier),
                        "{name}: {style:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn themes_use_only_safe_colours() {
        let quiet = [
            Color::Gray,
            Color::DarkGray,
            Color::Yellow,
            Color::LightYellow,
        ];
        for (theme, allowed) in [
            (
                Theme::color(),
                &[
                    Color::Reset,
                    Color::Green,
                    Color::Red,
                    Color::Cyan,
                    Color::Magenta,
                ][..],
            ),
            (Theme::mono(), &[Color::Reset][..]),
        ] {
            for (name, style) in styles(&theme) {
                for color in [style.fg, style.bg].into_iter().flatten() {
                    assert!(allowed.contains(&color), "{name}: {color:?}");
                    assert!(!quiet.contains(&color), "{name}: {color:?}");
                }
                assert!(style.bg.is_none(), "{name} sets a background");
                let mods = Modifier::BOLD | Modifier::DIM | Modifier::REVERSED;
                assert!(mods.contains(style.add_modifier), "{name}: {style:?}");
            }
        }
        // Secondary text is the terminal's colour dimmed, in both themes.
        for theme in [Theme::color(), Theme::mono()] {
            assert_eq!(
                theme.secondary,
                Style::new().fg(Color::Reset).add_modifier(Modifier::DIM)
            );
            assert_eq!(
                theme.warn,
                Style::new().fg(Color::Reset).add_modifier(Modifier::BOLD)
            );
            assert_eq!(
                theme.selected,
                Style::new().add_modifier(Modifier::REVERSED)
            );
        }
        assert_eq!(Theme::color().ok.fg, Some(Color::Green));
        assert_eq!(Theme::color().bad.fg, Some(Color::Red));
        assert_eq!(Theme::color().accent.fg, Some(Color::Cyan));
    }

    /// Every mark of `glyphs` that is not part of its border, named.
    fn marks(glyphs: &Glyphs) -> Vec<(String, &'static str)> {
        let mut out: Vec<(String, &'static str)> = [
            ("dot_on", glyphs.dot_on),
            ("dot_half", glyphs.dot_half),
            ("dot_off", glyphs.dot_off),
            ("dot_none", glyphs.dot_none),
            ("dot_alert", glyphs.dot_alert),
            ("dot_recent", glyphs.dot_recent),
            ("alarm", glyphs.alarm),
            ("tick_waiting", glyphs.tick_waiting),
            ("tick_sent", glyphs.tick_sent),
            ("tick_failed", glyphs.tick_failed),
            ("selected", glyphs.selected),
            ("bullet", glyphs.bullet),
            ("route", glyphs.route),
            ("route_dash", glyphs.route_dash),
            ("route_end", glyphs.route_end),
            ("route_out", glyphs.route_out),
            ("route_in", glyphs.route_in),
            ("bar", glyphs.bar),
            ("own", glyphs.own),
            ("value_before", glyphs.value_before),
            ("value_after", glyphs.value_after),
        ]
        .into_iter()
        .map(|(name, mark)| (name.to_owned(), mark))
        .collect();
        for (i, frame) in glyphs.ring.iter().enumerate() {
            out.push((format!("ring[{i}]"), frame));
        }
        for (i, frame) in glyphs.spinner.iter().enumerate() {
            out.push((format!("spinner[{i}]"), frame));
        }
        for (i, bar) in glyphs.bars.iter().enumerate() {
            out.push((format!("bars[{i}]"), bar));
        }
        out
    }

    /// Every string of `glyphs`, named.
    fn every_glyph(glyphs: &Glyphs) -> Vec<(String, &'static str)> {
        let b = glyphs.border;
        let mut out = marks(glyphs);
        out.extend(
            [
                ("tick_delivered", glyphs.tick_delivered),
                ("separator", glyphs.separator),
                ("inline_separator", glyphs.inline_separator),
                ("ellipsis", glyphs.ellipsis),
                ("up_down", glyphs.up_down),
                ("arrow", glyphs.arrow),
                ("heart", glyphs.heart),
                ("alarm_badge", glyphs.alarm_badge),
                ("border", b.top_left),
                ("border", b.top_right),
                ("border", b.bottom_left),
                ("border", b.bottom_right),
                ("border", b.vertical_left),
                ("border", b.vertical_right),
                ("border", b.horizontal_top),
                ("border", b.horizontal_bottom),
            ]
            .map(|(name, text)| (name.to_owned(), text)),
        );
        out
    }

    #[test]
    fn every_mark_is_one_cell_wide() {
        for glyphs in [Glyphs::fancy(), Glyphs::simple(), Glyphs::ascii()] {
            for (name, mark) in marks(&glyphs) {
                assert_eq!(Span::raw(mark).width(), 1, "{name} {mark:?}");
            }
            assert_eq!(Span::raw(glyphs.tick_delivered).width(), 2);
            assert!(glyphs.spinner.len() >= 4);
            // The bars rise: no two are the same.
            let mut bars = glyphs.bars.to_vec();
            bars.dedup();
            assert_eq!(bars.len(), glyphs.bars.len());
            assert_eq!(glyphs.selected, ">");
        }
    }

    #[test]
    fn simple_and_ascii_sets_are_ascii_where_they_should_be() {
        for (name, text) in every_glyph(&Glyphs::ascii()) {
            assert!(
                text.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                "ascii set, {name}: {text:?}"
            );
        }
        let simple = Glyphs::simple();
        for (name, text) in every_glyph(&simple) {
            if name != "border" {
                assert!(text.is_ascii(), "simple set, {name}: {text:?}");
            }
        }
        assert_eq!(simple.border, border::PLAIN);
        assert_eq!(Glyphs::fancy().border, border::ROUNDED);
        assert_eq!(
            Glyphs::ascii(),
            Glyphs {
                border: ASCII_BORDER,
                ..simple
            }
        );
        // The heartbeat in each set (tokens: `terminal.symbols`, ♥ becomes
        // +), and the ring and route line (ASCII: o O @, and > < for what
        // travels).
        assert_eq!(
            [Glyphs::fancy().heart, simple.heart, Glyphs::ascii().heart],
            ["♥", "+", "+"]
        );
        assert_eq!(Glyphs::fancy().ring, ["◌", "◎", "◉", "◎"]);
        assert_eq!(simple.ring, ["o", "O", "@", "O"]);
        assert_eq!(
            [simple.route_out, simple.route_in, simple.route_end],
            [">", "<", "*"]
        );
        assert_eq!(ASCII_BORDER.top_left, "+");
        assert_eq!(ASCII_BORDER.horizontal_top, "-");
        assert_eq!(ASCII_BORDER.vertical_left, "|");
        // The rows the e2e test reads: 'You · just now  ✓✓ Delivered' and
        // 'You - just now  vv Delivered'.
        let fancy = Glyphs::fancy();
        assert_eq!(
            format!(
                "You{}just now  {} Delivered",
                fancy.inline_separator, fancy.tick_delivered
            ),
            "You · just now  ✓✓ Delivered"
        );
        assert_eq!(
            format!(
                "You{}just now  {} Delivered",
                simple.inline_separator, simple.tick_delivered
            ),
            "You - just now  vv Delivered"
        );
    }

    #[test]
    fn reduced_motion_stills_the_spinner() {
        for glyphs in [Glyphs::fancy(), Glyphs::simple(), Glyphs::ascii()] {
            let n = glyphs.spinner.len() as u64;
            assert_eq!(glyphs.spinner_frame(Motion::Full, 0), glyphs.spinner[0]);
            assert_eq!(glyphs.spinner_frame(Motion::Full, n + 1), glyphs.spinner[1]);
            assert_eq!(
                glyphs.spinner_frame(Motion::Full, u64::MAX),
                glyphs.spinner[(u64::MAX % n) as usize]
            );
            for frame in [0, 1, n, u64::MAX] {
                assert_eq!(
                    glyphs.spinner_frame(Motion::Reduced, frame),
                    glyphs.ellipsis
                );
            }
        }
        assert_eq!(Glyphs::fancy().ellipsis, "…");
        assert_eq!(Glyphs::simple().ellipsis, "...");
    }
}
