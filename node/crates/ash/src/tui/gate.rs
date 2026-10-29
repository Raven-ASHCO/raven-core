//! Whether `raven` with no arguments opens the full screen or the classic
//! line menu.
//!
//! [`decide`] is pure: `run_or_classic` (tui/mod.rs) reads the terminal, the
//! environment, tui_state.json and the Windows probes into a [`GateInput`].
//! The classic menu stays the answer wherever the full screen could not work
//! or was not asked for: piped and test runs, TERM=dumb, consoles without VT
//! sequences, the saved 'Always open the classic menu', and Windows with a
//! screen reader running.

/// Whether a capable terminal opens the full screen when nothing else
/// decides: on (OD-14). `RAVEN_UI=classic` and the saved setting opt out.
pub(super) const DEFAULT_ON: bool = true;

/// `RAVEN_UI` value that always opens the classic menu.
const UI_CLASSIC: &str = "classic";
/// `RAVEN_UI` value that opens the full screen wherever it can work.
const UI_TUI: &str = "tui";
/// The TERM of terminals that cannot move the cursor (Emacs shell buffers,
/// some CI logs); cli.rs's colour rule turns colour off for it too.
const TERM_DUMB: &str = "dumb";

/// Everything the decision depends on, read once at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GateInput {
    /// stdin is a terminal (`std::io::IsTerminal`).
    pub(super) stdin_tty: bool,
    /// stdout is a terminal.
    pub(super) stdout_tty: bool,
    /// TERM, when set.
    pub(super) term: Option<String>,
    /// RAVEN_UI, when set.
    pub(super) ui_env: Option<String>,
    /// The saved 'Always open the classic menu' (`TuiState::always_classic`).
    pub(super) saved_classic: bool,
    /// `stdio::windows_console_ok()`: always true off Windows.
    pub(super) windows_console_ok: bool,
    /// `stdio::screen_reader_running()`: always false off Windows.
    pub(super) screen_reader: bool,
    /// [`DEFAULT_ON`]; a field so the tests cover both values.
    pub(super) default_on: bool,
}

/// Which interface a no-argument run opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UiChoice {
    /// The full screen.
    Tui,
    /// The existing line menu, `interactive()` in cli.rs.
    Classic,
}

/// The interface for `input`. The first rule that applies decides:
///
/// 1. `RAVEN_UI=classic`: Classic.
/// 2. stdin or stdout is not a terminal: Classic. Piped runs, the test
///    suites and scripts/ash_menu_smoke.sh keep the line menu.
/// 3. `TERM=dumb`: Classic.
/// 4. A Windows console that cannot show the full screen (legacy conhost,
///    Git Bash's mintty without ConPTY): Classic, whatever TERM says.
/// 5. `RAVEN_UI=tui`: Tui.
/// 6. The saved 'Always open the classic menu': Classic.
/// 7. A screen reader is running (Windows): Classic.
/// 8. Otherwise Tui when `default_on`, else Classic.
///
/// So `RAVEN_UI=tui` overrides the saved setting and the screen reader, but
/// never a terminal the full screen cannot run on. Other `RAVEN_UI` values,
/// an empty one included, count as unset; values are matched exactly, as
/// cli.rs matches `TERM=dumb`.
pub(super) fn decide(input: &GateInput) -> UiChoice {
    let ui = input.ui_env.as_deref();
    if ui == Some(UI_CLASSIC) {
        return UiChoice::Classic;
    }
    if !input.stdin_tty || !input.stdout_tty {
        return UiChoice::Classic;
    }
    if input.term.as_deref() == Some(TERM_DUMB) {
        return UiChoice::Classic;
    }
    if !input.windows_console_ok {
        return UiChoice::Classic;
    }
    if ui == Some(UI_TUI) {
        return UiChoice::Tui;
    }
    if input.saved_classic || input.screen_reader {
        return UiChoice::Classic;
    }
    if input.default_on {
        UiChoice::Tui
    } else {
        UiChoice::Classic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use UiChoice::{Classic, Tui};

    /// An interactive desktop terminal with nothing set and the default off.
    fn capable() -> GateInput {
        GateInput {
            stdin_tty: true,
            stdout_tty: true,
            term: Some("xterm-256color".into()),
            ui_env: None,
            saved_classic: false,
            windows_console_ok: true,
            screen_reader: false,
            default_on: false,
        }
    }

    /// `input` with RAVEN_UI set to `value`.
    fn with_ui(value: &str, input: GateInput) -> GateInput {
        GateInput {
            ui_env: Some(value.into()),
            ..input
        }
    }

    /// [`capable`] with the default on.
    fn default_on() -> GateInput {
        GateInput {
            default_on: true,
            ..capable()
        }
    }

    #[test]
    fn truth_table() {
        let piped_stdin = GateInput {
            stdin_tty: false,
            ..capable()
        };
        let piped_stdout = GateInput {
            stdout_tty: false,
            ..capable()
        };
        let piped_both = GateInput {
            stdin_tty: false,
            stdout_tty: false,
            ..default_on()
        };
        let dumb = GateInput {
            term: Some("dumb".into()),
            ..capable()
        };
        let no_term = GateInput {
            term: None,
            ..default_on()
        };
        // Legacy conhost, or Git Bash/mintty without ConPTY: TERM=xterm is set
        // and both ends look like terminals, but the console probe fails.
        let no_vt_console = GateInput {
            term: Some("xterm".into()),
            windows_console_ok: false,
            ..capable()
        };
        let saved_classic = GateInput {
            saved_classic: true,
            ..default_on()
        };
        let screen_reader = GateInput {
            screen_reader: true,
            ..default_on()
        };
        let both_opt_outs = GateInput {
            saved_classic: true,
            screen_reader: true,
            ..default_on()
        };

        let cases: &[(&str, GateInput, UiChoice)] = &[
            // Nothing set: the default decides.
            ("capable, default off", capable(), Classic),
            ("capable, default on", default_on(), Tui),
            ("TERM unset, default on", no_term.clone(), Tui),
            // RAVEN_UI.
            ("RAVEN_UI=tui, default off", with_ui("tui", capable()), Tui),
            (
                "RAVEN_UI=tui, default on",
                with_ui("tui", default_on()),
                Tui,
            ),
            (
                "RAVEN_UI=classic, default on",
                with_ui("classic", default_on()),
                Classic,
            ),
            (
                "RAVEN_UI=classic, default off",
                with_ui("classic", capable()),
                Classic,
            ),
            (
                "RAVEN_UI junk, default off",
                with_ui("fancy", capable()),
                Classic,
            ),
            (
                "RAVEN_UI junk, default on",
                with_ui("fancy", default_on()),
                Tui,
            ),
            ("RAVEN_UI empty, default on", with_ui("", default_on()), Tui),
            (
                "RAVEN_UI empty, default off",
                with_ui("", capable()),
                Classic,
            ),
            // Exact values only.
            (
                "RAVEN_UI=TUI, default off",
                with_ui("TUI", capable()),
                Classic,
            ),
            (
                "RAVEN_UI=' classic', default on",
                with_ui(" classic", default_on()),
                Tui,
            ),
            // Not a terminal: piped and test runs keep the line menu.
            (
                "stdin piped, RAVEN_UI=tui",
                with_ui("tui", piped_stdin),
                Classic,
            ),
            (
                "stdout piped, RAVEN_UI=tui",
                with_ui("tui", piped_stdout),
                Classic,
            ),
            ("both piped, default on", piped_both.clone(), Classic),
            (
                "both piped, RAVEN_UI=classic",
                with_ui("classic", piped_both),
                Classic,
            ),
            // TERM=dumb.
            (
                "TERM=dumb, RAVEN_UI=tui",
                with_ui("tui", dumb.clone()),
                Classic,
            ),
            (
                "TERM=dumb, default on",
                GateInput {
                    default_on: true,
                    ..dumb
                },
                Classic,
            ),
            (
                "TERM=dumb-ish name, default on",
                GateInput {
                    term: Some("dumb-256color".into()),
                    ..default_on()
                },
                Tui,
            ),
            // A Windows console without VT sequences, whatever TERM says.
            (
                "console probe false, TERM=xterm, RAVEN_UI=tui",
                with_ui("tui", no_vt_console.clone()),
                Classic,
            ),
            (
                "console probe false, TERM=xterm, default on",
                GateInput {
                    default_on: true,
                    ..no_vt_console
                },
                Classic,
            ),
            // The saved setting and the screen reader; RAVEN_UI=tui wins over both.
            ("saved classic, default on", saved_classic.clone(), Classic),
            (
                "saved classic, RAVEN_UI=tui",
                with_ui("tui", saved_classic),
                Tui,
            ),
            ("screen reader, default on", screen_reader.clone(), Classic),
            (
                "screen reader, RAVEN_UI=tui",
                with_ui("tui", screen_reader),
                Tui,
            ),
            (
                "saved classic and screen reader, RAVEN_UI=tui",
                with_ui("tui", both_opt_outs.clone()),
                Tui,
            ),
            (
                "saved classic and screen reader, RAVEN_UI=classic",
                with_ui("classic", both_opt_outs),
                Classic,
            ),
        ];
        assert!(cases.len() >= 20);
        for (name, input, want) in cases {
            assert_eq!(decide(input), *want, "{name}: {input:?}");
        }
    }

    /// Every combination: the full screen only opens when stdin and stdout are
    /// terminals, without TERM=dumb, on a console that takes VT sequences and
    /// never under RAVEN_UI=classic; RAVEN_UI=tui opens it wherever that holds.
    #[test]
    fn every_combination_keeps_the_hard_rules() {
        let uis = [None, Some("classic"), Some("tui"), Some("junk"), Some("")];
        let terms = [None, Some("dumb"), Some("xterm"), Some("linux")];
        let mut checked = 0;
        for bits in 0u32..1 << 6 {
            let bit = |n: u32| bits & (1 << n) != 0;
            for ui in uis {
                for term in terms {
                    let input = GateInput {
                        stdin_tty: bit(0),
                        stdout_tty: bit(1),
                        term: term.map(String::from),
                        ui_env: ui.map(String::from),
                        saved_classic: bit(2),
                        windows_console_ok: bit(3),
                        screen_reader: bit(4),
                        default_on: bit(5),
                    };
                    let can_run = input.stdin_tty
                        && input.stdout_tty
                        && term != Some("dumb")
                        && input.windows_console_ok;
                    let want = match ui {
                        Some("classic") => Classic,
                        _ if !can_run => Classic,
                        Some("tui") => Tui,
                        _ if input.saved_classic || input.screen_reader => Classic,
                        _ if input.default_on => Tui,
                        _ => Classic,
                    };
                    assert_eq!(decide(&input), want, "{input:?}");
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 64 * 5 * 4);
    }

    /// As shipped (OD-14): an interactive no-argument run opens the full
    /// screen, and every way out still gets the classic menu.
    #[test]
    fn shipped_default_opens_the_full_screen() {
        let shipped = GateInput {
            default_on: DEFAULT_ON,
            ..capable()
        };
        assert_eq!(decide(&shipped), Tui);
        assert_eq!(decide(&with_ui("tui", shipped.clone())), Tui);
        let ways_out = [
            with_ui("classic", shipped.clone()),
            GateInput {
                saved_classic: true,
                ..shipped.clone()
            },
            GateInput {
                screen_reader: true,
                ..shipped.clone()
            },
            GateInput {
                stdin_tty: false,
                ..shipped.clone()
            },
            GateInput {
                stdout_tty: false,
                ..shipped.clone()
            },
            GateInput {
                term: Some("dumb".into()),
                ..shipped.clone()
            },
            GateInput {
                windows_console_ok: false,
                ..shipped
            },
        ];
        for input in ways_out {
            assert_eq!(decide(&input), Classic, "{input:?}");
        }
    }
}
