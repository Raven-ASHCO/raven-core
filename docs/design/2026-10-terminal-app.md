# Terminal app: full-screen `raven` with no arguments

| | |
|---|---|
| **Status** | Owner decisions OD-1 to OD-19 taken 2026-10-16 (the recommended option each time). On by default (OD-14). Built on the UX track copy of the feature worktree, uncommitted at time of writing; merged into the feature tree with the checklist in §12. |
| **Scope** | `raven` and `ash` run with no arguments on an interactive terminal. Every subcommand, the piped or `TERM=dumb` line menu, the wire protocol and the IPC are unchanged. |
| **Code** | `node/crates/ash/src/tui/` (all logic), `node/crates/ash/tests/tui_pty_smoke.rs`. Edits to existing files: 4 lines in `crates/ash/Cargo.toml` and the regenerated `Cargo.lock`; in `cli.rs` `mod tui;`, a 3-line hook at the top of both `print_stdout` variants and the no-argument match arm in `run()`; two `pub(super)` keywords in `ext.rs` (`Cause`, `classify_cause`). |
| **Crates** | `ratatui =0.30.2` (default features off, `crossterm`) and `crossterm =0.29.0` (`bracketed-paste`, `events`, `windows`); transitive `indoc 2.0.7` and `litrs 1.0.0` pinned (OD-1). |

## 1. What the app does

`raven` (or `ash`) with no arguments opens a full-screen app in the terminal instead of the numbered
line menu. It covers the everyday tasks of the menu in one place:

- **First run.** A short wizard: what Raven is and where its data lives (WZ-1), an optional name
  that stays on this computer and is never sent (WZ-2, OD-10), whether to receive messages on this
  computer (WZ-3, §5), creating the identity (WZ-4), your security words and old-style code
  (WZ-5), and a last screen that offers to add a friend (WZ-6). A profile Raven can't open shows a
  plain error screen (ERR-ID) that never offers to create a new key.
- **Home.** The friend list with honest status marks, the open conversation with a delivery tick
  under each of your messages, and a composer that always names who it writes to. Two panes from 80
  columns, one pane from 60 to 79; below 60 x 16 a 'window too small' screen (SMALL) offers the
  classic menu.
- **Add a friend.** Share your invite and paste theirs (AF-1), name them (AF-2), check security
  words (VF; `Ctrl+O` takes the old code instead), done (AF-3). A friend becomes *verified* only when
  you type the words (or code) they read to you and they match, plus the 5-character confirmation
  code on screen: the CLI's rules (`add_contact_with_routes`, `security_check`, `new_confirm_code`).
  The friend's words and code are never shown before what you typed matches them (OD-6), typed words
  get no mark against theirs, and after 3 entries that are not theirs VF stops checking
  (`protocol/RAVEN_SECURITY_WORDS_V1.md` section 8). A name that clashes with a verified friend
  shows a warning (NAME-CLASH) instead of saving.
- **Friend page** (CI): rename, edit their address, verify, remove, unblock.
- **Network** (NET): what the background program (raven-node) is doing, where it listens or why
  it doesn't (on this computer only, an address that isn't here, a port another program uses, no
  network at all), the ways to reach friends by what people do (release builds: this Wi-Fi or
  cable, a laptop's hotspot and meeting in person work; Bluetooth, a friend carrying messages and
  the internet read 'Not in this version', never 'On'), its log, and start or stop.
- **Meet without the internet** (MEET, `G` on Home and NET): a guide for two people who meet
  with no internet. It asks who makes a small Wi-Fi (a hotspot) and says how in the system's own
  words (Windows' settings, the Linux `nmcli` command with a copy view, what a Mac may not do),
  shows this computer's addresses (hotspot first) and takes the friend's (saved as CI's `E` saves
  it, then one `raven outbox retry` for the messages waiting for them), and says 'Connected' once
  a message from them arrived, or one of yours was delivered, after `G`. It changes no Wi-Fi,
  firewall or system setting and runs no command.
- **Settings** (SET): §8.
- **Lock now** (LOCK, SET's 'Lock now' and `[L]` in QUIT): stops this profile's background program,
  clears the terminal and quits (§6). A passphrase-vault profile is then locked; on a keychain
  profile Raven is only stopped, and LOCK says so.
- **Leaving a meeting** (UXF.8): while the background program keeps trying messages that haven't
  gone yet, QUIT says so before its question (§6). Toasts on Home say when a friend's waiting
  messages were all delivered, and when several messages from a friend arrive after an hour of
  none (§4).
- **Live feel and the Raven mark** (UXF.10, `docs/design/terminal-app-mockup.html`). Every motion
  reflects something Raven really did; the one exception is the Welcome mark's reveal. WZ-1 shows
  the website's mark in Braille (`docs/design/raven-logo-braille.txt`, `tui/logo.rs`) beside the
  text from 80 x 24 with the Fancy symbols: a row at a time, then the letters R A V E N, then the
  tagline 'Messages straight to your friends. No server.'; elsewhere the card keeps R A V E N on
  its border. Home's header reads `R A V E N · <name>`; on the right a heart (♥, Simple `<3`,
  ASCII `*`) that is bright from each Status poll the background program answered to the next
  whole second, `node ok · <age>` while it listens (any other state: the node chip), and the
  clock with seconds when this computer's time can be read. Under the open friend's name the
  route line `You ●────● <name>` and, once known, how the last delivery went (the send's carrier
  and address, e.g. `LAN direct · 192.168.1.30:7420`, or the carrier and p2p path raven-node's
  outbox recorded, e.g. `p2p · relayed`): your message travels it while its send runs, the
  signed receipt (✓) travels back only once it came, and a friend's message travels in before it
  shows. In the list an in-touch mark breathes with the clock's seconds, a friend's row blinks
  three frames with news, and a waiting mark rings (◐ ◎ ◐) when raven-node's outbox lists another
  attempt. From 20 rows a status row above the keys names the latest event ('Delivered to Ali
  via LAN direct in 1.4 s · receipt signed by Ali', 'Tried Mina again · not reachable yet ·
  keeps trying until …'; otherwise 'Listening on your network · 3 friends · all quiet', shorter
  when the row is narrow) and draws the activity line: your messages and theirs per two minutes
  over the last 48 minutes (`▁▂▃▄▅▆▇`, ASCII `.:-=+*#`), counted from the chat history on this
  computer and never sent anywhere. There is no typing indicator and no online state. Frames:
  12 a second at most (6 over SSH); an idle Home redraws once a second for its clock and ages;
  reduced motion (Settings or `RAVEN_REDUCED_MOTION`) draws no animation frame, only text.
- **Honest notes** (UXF.9). WZ-1 says 'Raven doesn't need the internet. It reaches friends on the
  same network as you: a Wi-Fi, a hotspot, or a cable.' (in place of its old same-network
  sentence). Five notes show once per profile, each remembered in `tui_state.json` as soon as it
  shows (a save the user did not ask for: a file that can't be read is left alone): NOTE, what
  people on the network can see (§5); on MEET's step 2a, the first time a hotspot is made here,
  'Whoever runs the hotspot can see which devices joined, and when.'; AF-2's hint, in place of
  'This name is only on this computer.' on the first friend named: 'Names here stay on this
  computer. Use a nickname if someone may look at this laptop.'; the laptop note under the exit
  line (§6); and COPY's 'Clear this from the terminal afterwards (it stays in the scrollback).'
  None of them says whether the internet works.

Sending reuses the CLI's route planning and secure send (`plan_contact_routes_with`,
`ext::run_send_secure*`). The app adds no new network behaviour, no IPC operation and no gate
change; it never sends `OutboxKick` on its own, only for a send, Retry or Cancel you ask for, and
once when you save a friend's address on MEET while messages wait for them.
`RAVEN_PEER` and `ASH_LAN_DIAL` are ignored in the app (OD-17).

## 2. App or classic menu

The gate (`tui/gate.rs`) decides once, at startup. The first rule that applies wins:

| # | Condition | Opens |
|---|---|---|
| 1 | `RAVEN_UI=classic` | classic menu |
| 2 | stdin or stdout is not a terminal (pipes, tests, CI, `node/scripts/ash_menu_smoke.sh`) | classic menu |
| 3 | `TERM=dumb` (Emacs shell buffers, some CI logs) | classic menu |
| 4 | Windows console without VT sequences: legacy conhost ('Use legacy console', Windows 7/8.1), Git Bash/mintty without ConPTY. Our own probe; TERM is ignored here | classic menu |
| 5 | `RAVEN_UI=tui` | the app |
| 6 | the saved setting 'Always open the classic menu' (`always_classic` in `tui_state.json`) | classic menu |
| 7 | Windows with a screen reader running (`SPI_GETSCREENREADER`) | classic menu |
| 8 | otherwise | the app (`DEFAULT_ON = true`) |

`RAVEN_UI` values are matched exactly (`classic`, `tui`); anything else counts as unset. So
`RAVEN_UI=tui` overrides the saved setting and the screen reader, but never a terminal the app can't
run on.

**Ways back to the classic menu.**

- `RAVEN_UI=classic raven` for one run.
- Settings > 'Always open the classic menu' (saved per profile; OD-9).
- Settings > 'Switch to the classic menu now', and `[C] Classic menu` on Welcome (WZ-1), ERR-ID
  and SMALL, for this run. While a save or a send is still running the switch is refused with a
  note ('Raven is still finishing (saving, or sending a message). Try again in a moment.').
- Before the screen opens Raven prints one plain line: `Opening Raven in full-screen mode. For the
  plain menu: Settings > Classic menu, or start Raven with RAVEN_UI=classic.`

**If the screen can't start** (raw mode, the alternate screen or the first draw fails) the classic
menu runs instead, with one line on stderr. A later draw error (for example after the terminal hung
up) restores the terminal and exits: code 129 after SIGHUP, otherwise 1.

## 3. Keys

Shortcuts are single letters, case-insensitive. Letters typed into a field (composer, name, code,
paste box) are always text, never shortcuts. `?` opens HELP on every screen with keys of its own;
HELP lists that screen's keys and every mark (§4); its 'Not verified' line points to the user guide
`docs/SECURITY_WORDS.md`.

**Everywhere**

| Key | Does |
|---|---|
| `?` | Help, wherever `?` is not text (in the composer only while it is empty) |
| `Q` | Quit (QUIT dialog, §6); Esc on Welcome |
| `Ctrl+C` | Quit dialog; on Add a friend it opens the copy view instead. A second Ctrl+C inside QUIT does nothing: Enter answers it |
| `Ctrl+L` | Redraw the screen |
| `Ctrl+Z` | Not supported: a note says to press Q |
| `Esc` | Back one level, or close an overlay |

**Home**, by focus (`Tab` / `Shift+Tab` cycle the focus while a conversation is open):

| Focus | Keys |
|---|---|
| Friends | `Up`/`Down` or `k`/`j` move the highlight only; `Enter` opens that friend and goes to the composer; `A` add a friend; `V` verify (a verified friend with an open security notice: check again); `E` or `I` friend page; `G` meet without the internet (for the highlighted friend); `N` network; `S` settings; `L` Lock now (LOCK); `W` security notices (SEC); `D` SEC on the highlighted friend's notice; `P` pause or resume sending to them (only while a notice about them is open, or it is paused) |
| Composer | type; `Enter` sends; `Ctrl+J` new line; `Backspace`, `Delete`, `Left`, `Right`, `Home`, `End` edit; `Up`, `Down`, `PgUp`, `PgDn` scroll; `Esc` back to the friends |
| Messages | `Up`/`Down` choose a message; `Enter` shows a clipped message whole, then its details (MSG); `R` retry or send again; `C` stop trying (after confirming); `D` details; `L` Lock now (LOCK); `W` security notices (SEC); `Esc` back |

The highlight in the friend list never changes who the composer writes to: only `Enter` does. A
mouse wheel that the terminal turns into arrow keys therefore can't redirect a message.

**Other screens**

| Screen | Keys |
|---|---|
| Welcome (WZ-1) | `Enter` get started; `C` classic menu; `Q` or `Esc` quit |
| Receive? (WZ-3, RX) | `Y` yes (recommended); `N` not now; `Enter` picks the highlighted answer |
| Ready (WZ-6) | `A` add a friend now; `Enter` open Raven |
| Add a friend (AF-1) | `Tab` switch box; `L` address in my invite on/off; `C` or `Ctrl+C` copy view; `S` show my invite anyway (when it would have no address); `N` how to set up the passphrase file (§7, when needed); `Ctrl+U` empty the paste box; `Enter` continue; `Esc` back |
| Copy view (COPY) | the invite alone on the normal screen, to select and copy; any key returns |
| Verify (VF) | type the words your friend reads out; `Tab` (or `Space`) picks the word suggested; `Enter` check them, then save; `Tab` with no word being typed: later (save as not verified); `Ctrl+O` the old code instead, or back; with the code, `Left`/`Right` spell the group before or after; `Esc` cancel, nothing saved. For a verified friend: `Enter` on 'Already verified' checks again (P6.31; at once while a security notice about them is open); a match resolves their notices, and while their Raven offers an older security method than before, type `accept` and `Enter` to accept it (`Esc`, or anything else, keeps the newer one) |
| Added (AF-3) | `Enter` open the chat; `1` show my invite; `A` add another friend; `Esc` home |
| Friend page (CI) | `R` rename; `E` edit their address; `V` verify (or compare words again); `X` remove; `U` unblock; `W` security notices; `P` pause or resume sending to them (as on Home); `D` details of a failure; `Esc` back |
| Message (MSG) | as its state allows: `R` try now or send again, `C` stop trying, `S` send again anyway (after a warning that they may see it twice); `D` details; `Esc` close |
| Network (NET) | `L` service log; `S` start the background program; `X` stop it; `R` check again; `W` security notices; `G` meet without the internet; `Up`/`Down` scroll; `Esc` back |
| Security (SEC; `W`, or `D` on a friend) | `Up`/`Down` or `k`/`j` choose a notice; `D` its details; `R` resolve it; `V` compare security words with the friend it is about; `W` or `Esc` close |
| Meet (MEET) | `1` I make the hotspot, `2` my friend makes it, `3` we're on the same Wi-Fi already; `A` add a friend; `C` show the Linux command alone to copy (step 2a); `Enter` next, save the friend's address (step 3) or open the chat (step 4); `Up`/`Down` another friend (step 3); `Esc` back to where `G` was pressed |
| Settings (SET) | `Up`/`Down` choose; `Enter` change or open (on 'Lock now': LOCK; on 'Erase Raven from this computer': ERASE); `Right`/`Left` next or previous value; `Esc` back |
| Erase (ERASE) | type `erase`, then `Enter` erase (a paste clears the word); `Esc` cancel (also while it waits for a job); after a refusal, `Esc` or `Enter` close |
| Quit (QUIT) | `Enter` quit as 'When I quit' says; `S` quit and stop, `K` quit and keep (where offered); `L` Lock: stop Raven and quit (LOCK in QUIT's place, once QUIT knows the background program's state); `Esc` stay. While it says messages haven't gone yet (§6): `Enter` or `Esc` stay and wait, `Q` quit anyway |
| Lock (LOCK; `L` on Home's friend list or conversation, SET's 'Lock now', `L` in QUIT) | `Enter` lock (on a keychain profile: stop); `Esc` cancel (also while a send goes first); after a stop that left Raven running, `Esc` close |
| SMALL | `C` classic menu; `Q` quit |

A paste is data only: it never sends, saves or confirms. Bracketed paste is used on Unix; on every
OS a burst of 3 or more keystrokes within 10 ms counts as one paste (Windows delivers every paste as
keystrokes). `Enter` is ignored for 300 ms after a paste.

**Persian keyboard layout** (UXF.4, `tui/keys_fa.rs`). A key arrives as the character its layout
types: with a Persian layout on, the Q key types U+0636, not `q`. Wherever no field takes text, the
app reads such a key as the shortcut on the same key: the 26 letter keys of the Persian standard
layout, the 6 Arabic 101 keys that type another letter, and the number row (Persian U+06F0-U+06F9
and Arabic-Indic U+0660-U+0669 digits read as 0-9, so AF-3's `1` works too). In a field (the
composer; the name on WZ-2, AF-2 and SET; the paste box until it parses, and the rest of a paste in
either box; the words or code on VF and the code on [U]; CI's open field; MEET's address on step 3) no key is read this
way: it types into the field as before. Only unshifted keys are read: `?` (Shift+`/` types U+061F)
and any shortcut that needs Shift still need the Latin layout. HELP says "Shortcuts also work with a
Persian keyboard." Nothing is shown in Persian.

| Keys | Persian standard | Arabic 101, where it differs |
|---|---|---|
| Q W E R T Y U I O P | U+0636 U+0635 U+062B U+0642 U+0641 U+063A U+0639 U+0647 U+062E U+062D | |
| A S D F G H J K L | U+0634 U+0633 U+06CC U+0628 U+0644 U+0627 U+062A U+0646 U+0645 | D: U+064A |
| Z X C V B N M | U+0638 U+0637 U+0632 U+0631 U+0630 U+062F U+067E | Z: U+0626, X: U+0621, C: U+0624, N: U+0649, M: U+0629 |

**Layout check** (what each OS layout types on the letter keys, against that table). macOS was read
on 2026-10-17 (macOS 26.6) with `UCKeyTranslate` from the installed layout data, without selecting
or enabling any layout. Windows and GNOME are still to be checked by the owner.

| Layout | Letter keys as the table | Notes |
|---|---|---|
| macOS "Persian - ISIRI 2901" (macOS's standard Persian layout; it has none named ISIRI 9147) | 26 of 26 | The number row types U+06F0-U+06F9; Shift+`/` types U+061F. Shift+A, S, J and M type U+0624, U+0626, U+0629 and U+0621, which the Arabic 101 entries read as C, Z, M and X; Shift+D types U+064A, read as D. The other shifted letter keys type marks, punctuation or letters outside the table. |
| macOS "Persian" (the older layout) and "Arabic" | 21 of 26 | C, V, B and N type U+0630, U+062F, U+0632 and U+0631, read as B, N, C and V (V opens NET, N opens VF); M types U+0648, no shortcut. Some shifted keys type Arabic 101 letters (Shift+M reads as C). The number row types U+06F0-U+06F9 (Persian) or U+0660-U+0669 (Arabic). |
| macOS "Arabic - PC" (Arabic 101) | 25 of 26 | B types two letters (U+0644 U+0627, read as G and H: no shortcut); `/`, `]`, `'` and `.` type U+0638, U+062F, U+0637 and U+0632, read as Z, N, X and C. The number row types U+0660-U+0669. |
| macOS "Persian - QWERTY" and "Arabic - QWERTY" (phonetic) | 1 of 26 | Letters sit by sound, so the table does not fit (Q types U+0642, read as R; E types U+0639, read as U). Use the Latin layout there. |
| Windows "Persian (Standard)" | not checked yet | owner |
| GNOME "fa" (xkb `ir`) | not checked yet | owner |

On every macOS layout above, Ctrl with a letter key types the control code of that key's Latin
letter, so `Ctrl+C`, `Ctrl+L`, `Ctrl+U` and `Ctrl+J` need no mapping. A key the table reads as
another letter reaches another shortcut of the same screen. Most of those open a screen (Esc goes
back) or ask first; a few act at once, for example `R` sends again a message that never left this
computer, `U` unblocks a blocked friend on CI and `L` turns my address in my invite on or off. On
the phonetic layouts most letter keys do this (E reads as U, M as L); whether the app should do more
there is the owner's call. Mapping Shift+`/` to `?` is a one-line change once Windows and GNOME are
checked.

## 4. What the marks and ticks mean

Symbols depend on the glyph set (§8): **Fancy** / **Simple** (ASCII is Simple with `+ - |`
borders). Colour never carries meaning alone: every state has its mark and its words.

**Friends** (in the list; HELP has the same legend):

| Fancy | Simple | Meaning |
|---|---|---|
| `•` | `*` | In touch: since you opened Raven, a message from them arrived, or one of yours was delivered, in the last 15 minutes. It does not mean they are online now |
| `◐` | `~` | Messages waiting: some of your messages haven't reached them yet |
| `○` | `o` | No recent contact. Raven has no online indicator |
| `✕` | `x` | No address: Raven doesn't know where to reach them |
| `!` | `!` | Not verified: you haven't compared security words yet (also a 'Not verified' header and a banner) |
| `⚠` | `!!` | Security alert (P6.31): a security alert or warning about them is open (over the unread count and 'not verified'; also a banner over their conversation, with `[V] Compare words  [D] Details  [P] Pause sending`); 'paused' while sending to them is paused |

Rows from the first history load never count as 'in touch', and a sender clock that runs ahead is
treated as 'now'.

**This computer** (the chip on Home's header):

| Mark | Words |
|---|---|
| `●` / `*` | Listening on port 7420 (green: the only green on screen). On Home since UXF.10: the heart and `node ok · <age>` while its Status answers; other screens keep the chip |
| `◐` / `~` | Receiving on this computer only (a loopback listener) · Sending only, not receiving |
| spinner | Starting Raven… |
| `○` / `o` | Not running · Starts when you add a friend · Receiving is off · Not receiving (address not here): the address it is set to listen on isn't on this computer now · Not on any network (no address a friend could dial; it takes the place of every chip but the spinner and the `!` ones) |
| `!` | Needs setup: press N (§7) · Not responding: press N · Waiting for permission (a macOS Keychain dialog, KC) |

Left of it, on every screen's header, the security chip (P6.31) while security alerts or warnings
are open: `⚠ 2` (Simple and ASCII `!2`), bold in every theme and still under reduced motion; `W`
opens SEC. The words of every notice are `ash/src/security_text.rs`'s, the table the CLI reads too
(`docs/SECURITY_EVENTS.md`).

Why a running node isn't receiving comes from its Status once the cutoff pack adds the reason
(`lan_bind_error`, CP.5). Until then it comes from the service log of a node Raven started, read
from the moment the node is seen not receiving; a login service's node writes another file, so
its chip stays 'Sending only, not receiving'. NET also says when another program uses the port.
Whether this computer is on any network comes from the cutoff pack's interface reader
(`raven_core::netifs`, CP.4): on none when no interface that is up has an address a friend could
dial; never said when the interfaces can't be read.

**Your messages** (the tick and label under each one):

| Fancy | Simple | Label |
|---|---|---|
| spinner | spinner | `Waiting to send` (behind another send) · `Sending…` · `Connecting…` |
| `◷` | `~` | `Waiting: Raven keeps trying (next try in …)` · `Waiting: goes out with your next message` · `Waiting: not being retried (Raven's background program isn't running)` · `On hold: <reason>` |
| `✓` | `v` | `Sent, not confirmed yet`: it left this computer; their Raven hasn't confirmed it |
| `✓✓` | `vv` | `Delivered`: their Raven confirmed it. Never taken back |
| `✗` | `x` | `Not delivered: it never left this computer. Press R to send it again.` · `Not confirmed: <name> may have it. Press Enter for options.` · `Not sent: <reason>. Press R to try again.` |

What R, C and S offer follows what Raven can prove:

- Waiting or on hold: `R` asks the background program to try now, `C` stops trying (after
  confirming).
- Not sent, or never left this computer: `R` sends the same text again.
- Not confirmed (it may have left): no `R`; MSG offers `S` 'Send again anyway' after a warning that
  your friend may see it twice.
- Sent, not confirmed yet: nothing to do; retyping it would send it twice.

Ticks merge the send's own answer, the outbox (`OutboxList`, polled every 5 s while something is
waiting, else 30 s) and the chat history (reloaded when the file changes). Messages that were
queued while the app was closed count as 'may have it', the conservative reading.

**Meeting toasts** (UXF.8), raised while Home is on screen:

- 'Delivered {n} messages to {name}.' once every message of yours to that friend that was seen
  waiting or on hold in this session has been delivered or has ended, and at least one was
  delivered ({n}: how many were). Messages delivered without waiting never count.
- '{n} new messages from {name} (written while you were apart).' when 3 or more messages from one
  friend arrived within a minute and none had arrived for an hour before the first of them. A
  message that was already there when Raven opened counts as arriving when it was written (one
  written ahead of this computer's clock, as arriving now); messages of the first history load are
  never a burst.

Each of the two shows at most once a minute for one friend; one due sooner is dropped. Noted on
another screen, a toast waits until Home shows again.

## 5. Receiving and the firewall

To get messages, the background program (raven-node) must run and listen on the local network.
Raven asks once per profile: WZ-3 for a new profile, the RX overlay for an existing one, before the
first automatic start (OD-18). The answer is saved in `tui_state.json` and can be changed in
Settings > 'Receive messages on this computer'.

- **Yes (On).** Raven starts raven-node by itself (OD-3) once the identity exists: at launch when at
  least one friend is saved, otherwise as soon as you open Add a friend, so both invites carry an
  address. The node listens on `0.0.0.0:7420`, as `raven send` already does (OD-4);
  `RAVEN_SERVICE_LAN_LISTEN` still overrides it. The header says what is really bound: 'Listening on
  port 7420', or 'Receiving on this computer only' for a loopback listener.
- **Not now (Off).** No automatic start. For this process Raven sets
  `RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0` (only when you have not set it yourself), so a node that a
  send starts listens on this computer only. Friends can't send you messages. Turning receiving on
  later applies the next time Raven opens (at once if no loopback override was set this session);
  turning it off offers to stop a node this app started.
- Raven never starts the node before the identity exists (`raven-node service` would create one),
  never on a passphrase-vault profile without a passphrase file (§7), and never when it can't find
  its own program file (it would otherwise look raven-node up on PATH). NET shows the resolved
  raven-node path.

**Your invite's address** (OD-5). The invite carries `lan=<IP>:<port>` only from a live listener
whose address is not loopback: the bound IP, or this computer's outgoing IPv4 when it listens on
every address. `L` on AF-1 turns it off; the line reads '[L] Include my network address
(<IP>:<port>): On. Anyone you send this to can see it.' Without a usable listener the invite is
shown only after `S`, with the consequence spelled out: your friend can't send you the first
message. An address outside 10/8, 172.16/12 and 192.168/16 gets a note that a VPN may be on.

**Firewall.** The first time this app starts a node that listens beyond this computer, once per
profile, the FW overlay explains the prompt that may follow:

- **Windows:** 'Windows Security Alert': choose Private networks and Allow access, which needs an
  administrator. Closing it makes Windows block friends from reaching this computer (sending still
  works). The overlay shows the `New-NetFirewallRule` command to add later in an administrator
  PowerShell (the same text as the CLI's hint), and never runs it.
- **macOS:** allow raven-node to accept incoming connections. On macOS 15 and later a denied Local
  Network permission makes dials fail with 'no route to host'; the error names System Settings >
  Privacy & Security > Local Network.

Installed login services (`node/scripts/install/*`) listen on `127.0.0.1:7420` by default. NET says so
when it finds a loopback-only node, and how to change it.

**What the network can see** (NOTE, UXF.9). Once per profile, the first time Raven listens on the
network (not on this computer only, and with some network there) while receiving is on, a box in
FW's style says 'What people on this network can see' / 'People on this network can see that this
computer talks to another one, when, and how much. They can't read your messages.' /
`[Enter] OK`. It opens only on Home, NET or SET, with no other box open and no field that has the
keys, so it never takes a key meant for something else (Enter on AF-1, a step of a guide); FW, due
at the same moment, goes over it.

## 6. The background program when you quit

By default raven-node **keeps running** when you quit the app, so friends can reach you and waiting
messages keep trying (OD-2; ADR 0003 says closing the TUI must not stop the node). QUIT says so in
one sentence: '…keeps running while this computer is on and you stay logged in…', and after the app
closes the plain terminal shows `Raven is still running in the background (process <pid>), so
friends can reach you while this computer is on. Open it again with: raven`.

The first time the app quits with receiving on (once per profile, UXF.9), the plain terminal adds,
under that line or the stopped line: 'If someone gets this laptop while you're logged in, they can
read your Raven chats. Lock Raven or your screen when you step away.' It is remembered as shown on
the UI thread before the screen goes, since no worker would finish a save once the app ends. LOCK's
line, a signal and a failure never carry it.

Settings > 'When I quit':

| Value | Enter in QUIT |
|---|---|
| Keep Raven running (recommended) | quits; the node keeps running. `[S]` quits and stops it |
| Stop Raven if this app started it | quits and stops the node when this app started it (otherwise keeps it); `[K]` keeps it |
| Ask me | QUIT offers `[S]` stop and `[K]` keep |

QUIT waits for a message still being sent (Q quits anyway) and, with no way to skip, for identity
creation or a change to the friends being saved.

**Messages that haven't gone yet** (UXF.8). While the background program runs and its outbox
lists messages to saved friends as waiting (`queued`, unless the history or a send's answer already
says they were delivered, written to the friend's computer or ended; held messages don't count),
QUIT says so before its question: '{n} messages to {name} haven't gone yet.' / 'If you leave this
network now, they wait until next time (until {short}).' / `[Enter] Stay and wait   [Q] Quit
anyway`. With messages to several friends it names the one whose message runs out first and adds
'and {k} more' ({k}: the other friends' messages); a time raven-node didn't give comes last, and
with none the '(until …)' is left out. One message reads '1 message to {name} hasn't gone yet.'
and 'it waits'. {short} is UXF.1's `deadline_text`. Enter or Esc stays; Q quits as Enter on the
question would, and under 'Ask me' asks the question. With no background program running, staying
would not send them: QUIT is as before. Q also opens QUIT, so for a second after the warning
appears QUIT takes no key that ends the app (a double or held Q). The same second applies when the
warning goes by itself (the messages left while it showed, and the question is back): an Enter
meant to stay doesn't quit.

Stopping (from QUIT, NET, Settings or LOCK, always after confirmation) is narrow (OD-16):

- **Unix:** `SIGTERM` to the pid this profile's own socket reports, then up to 3 s for it to stop
  answering.
- **Windows:** only a pid this app started that a Status taken just before still reports, through
  `%SystemRoot%\System32\taskkill.exe /F`. Otherwise NET shows the CLI's stop advice. The pipe is
  per Windows account, not per profile, so NET notes that a running node may belong to another
  Raven folder.
- **Never a login-managed service** (`~/Library/LaunchAgents/com.raven.raven-node.plist`,
  `~/.config/systemd/user/raven-node.service`, the `RavenNodeBridge` task): launchd or systemd would
  restart it. QUIT says 'It is set to start when you log in.' The app asks bridge.rs whether Raven's
  own login item runs this profile (node_control.rs's `own_login_item`: the installer's item, and only
  when its `--data-dir` is this profile's, so a second profile is not 'Managed' by the first one's
  item; privacy pack PP.23). Where a build reads no login items (a debug build without the lab
  switches `RAVEN_LAB_LOGIN_ITEM_ROOT` and `RAVEN_LAB_LOGIN_ITEM_TOOLS`), the older check stands in:
  the agent's or unit's file at the places above when it runs this profile (on Windows, any
  installed task). Only LOCK goes further (below).

Settings > 'Start Raven when I log in' only shows whether a login service is installed and how the
installers set one up; the app never writes one (OD-11).

On Windows, when Raven has its own console window (started by a double-click), the exit text ends
with 'Press Enter to close this window.'

**Lock now** (LOCK, UXF.7: Lock now v1, completed by the privacy pack's PP.23). SET's row 'Lock
now', `[L] Lock: stop Raven and quit` in QUIT, and `L` on Home (the friend list or the
conversation; not in the composer, where it is a letter; a Persian layout's key works too) open it.
Its words follow where the profile keeps its keys (the vault check's `uses_vault`):

- Passphrase-vault profile: 'Lock Raven now?' / 'Raven stops. Your chats can't be opened again
  without your passphrase.' / 'Friends can't reach you until you open Raven again.' /
  `[Enter] Lock   [Esc] Cancel`.
- Keychain or DPAPI profile (macOS, Windows, Linux with a keyring; also before the vault check has
  answered): 'Stop Raven now?' / 'Raven stops, and friends can't reach you until you open it
  again.' / 'Your Raven keys stay in this computer's keychain: anyone who can log in as you can
  still open your chats. Lock your screen or log out too.' / `[Enter] Stop   [Esc] Cancel`.

Enter (never right after a paste) waits for a message being sent or a change to the friends being
saved (a send could start the background program again; Esc still cancels), then asks for the same
stop as X on NET (a stop already running serves). Nothing starts by itself meanwhile. When the stop
has answered and this profile's Status says nothing runs, the app leaves the alternate screen,
clears the terminal and its scrollback where the terminal can (`CSI 2 J`, `CSI 3 J`), prints one
line, 'Raven is locked.' or 'Raven is stopped.', and exits 0. Otherwise the app stays, and LOCK
says why, then the stop advice NET shows when the stop rules give one, then 'Lock your screen or
log out.':

- a login service: 'Raven's login service keeps it running, so Lock can't stop it.' (the stop rules
  give no advice here: launchd or the scheduler would start a stopped node again);
- the stop rules leave it to the user (Windows, a node this app did not start): 'Raven can't stop
  its background program from here.' and 'To stop it yourself: …';
- it still answers: 'Raven asked its background program to stop, but it is still running.';
- the stop failed: 'Raven couldn't stop its background program.'

**Lock now completed (PP.23).** Once the app knows whether Raven's own login item runs this
profile (the read above), LOCK's Enter (after a stop already running, if one is) sends one job
that does what `raven lock` does, without its questions:

- the lock is recorded first (`privacy.json` `locked_by_user`, a Raven setting, not a login
  setting), so a send in another window (`raven send` starts Raven when it isn't running) and
  `raven listen` start no Raven;
- when Raven's own login item runs this profile, LOCK's question ends with 'Raven starts again
  when you log in. To keep it stopped, run `raven lock` in a terminal.', and the job unloads it for
  this login session only (`launchctl bootout`, `systemctl --user stop`, `schtasks /End`: launchd
  would start a stopped node again within about 10 s), recorded so `raven unlock` loads it again.
  The app never turns a login item off or on (OD-11; OD-PP-12 option (a), still an owner call):
  `raven lock` asks whether to keep Raven stopped after the next login, the app doesn't;
- then the stop step; when Raven still runs after it, the lock is taken back and LOCK says why.

The last line is 'Raven is stopped until you log in again.' after the item was unloaded, else
'Raven is locked.' or 'Raven is stopped.' as before. When a `raven lock` turned the item off (only
`raven unlock` turns it on again), the question ends with 'Raven's login item stays off until you
run `raven unlock`.' instead, and the last line is 'Raven is locked.' or 'Raven is stopped.'
(review D-lock-tui-7). A passphrase-vault profile whose passphrase is saved in a file gets `raven
lock`'s paragraph 'Your passphrase is saved in a file on this computer ({path}). Anyone who can
read your files can unlock Raven with it. ...' after its body (review D-lock-tui-2). Enter waits
for the read while it is in flight, with the spinner (review D-lock-tui-6: before, a LOCK
confirmed then stopped Raven without recording the lock or unloading the item). Where the build
reads no login items (or the read failed) LOCK's words are UXF.7's, and its job stops as UXF.7 did
(a login service left alone), with the lock recorded around the stop.

Opening the app is its way to start Raven again after its own Lock (LOCK says 'until you open
Raven again'): once the identity is loaded, before anything could start Raven, a lock the app's
Lock left is cleared, and the app starts Raven as it always does. A lock `raven lock` set is kept
(review E-harness-docs-ci-3: `raven lock` promises Raven stays stopped until `raven unlock`, and the
app used to clear it without a word and start Raven): **UNLOCK** opens over Home at once, 'Raven
is locked' / '`raven lock` stopped Raven: friends can't reach you, and sending doesn't start it.' /
'Start Raven again now?' / '[Enter] Start Raven   [Esc] Keep it stopped'. Until it is answered
nothing starts Raven by itself (it closes by itself when Raven runs anyway, started at login by a
login item the lock left on; the lock stays). Enter clears the lock (a node job; `privacy.json` records who set
a lock, `lock_by`), and the start the lock held follows (the one at launch, Add a friend's, or
NET's S). Esc keeps Raven stopped for this session, with a toast 'Raven stays stopped. To start
it, press N, then S, or run `raven unlock`.'; NET's S asks again, and a send says 'Raven is
locked: `raven lock` stopped it.' / 'Press N, then S to start Raven again.' (also when `raven
lock` ran in another window while the app was open). A login item that `raven lock` turned off
stays off (only `raven unlock` turns it on); once Raven runs again Home then says once 'Raven is
running again. Raven's login item stays off until you run `raven unlock`.'

Lock v2 (an IPC Lock that makes raven-node drop its cached keys) is Phase 6.

## 7. Passphrase-vault profiles and the passphrase file

On Linux and other Unix systems without a Secret Service, keys live in a passphrase vault
([`2026-10-linux-keystore.md`](2026-10-linux-keystore.md)).

- **Opening.** The passphrase is asked on the plain terminal, before the full screen opens.
- **First run.** Creating the identity suspends the full screen, prints why a passphrase is needed,
  and asks for it twice; the app comes back afterwards.
- **The background program can't ask** (it runs without a terminal). Unless
  `RAVEN_KEYSTORE_PASSPHRASE_FILE` is set or the systemd credential
  `$CREDENTIALS_DIRECTORY/raven-keystore-passphrase` exists, the app does not start it, the header
  says 'Needs setup: press N', and the PASSFILE screen shows the documented steps
  ([`../INSTALL_Linux.md`](../INSTALL_Linux.md), 'Passphrase vault in practice'):

  ```sh
  ( umask 077; printf '%s\n' 'your passphrase' > ~/.config/raven/keystore-passphrase )
  RAVEN_KEYSTORE_PASSPHRASE_FILE=~/.config/raven/keystore-passphrase raven
  ```

  The first command assumes `~/.config/raven` exists; INSTALL_Linux.md creates it first with
  `mkdir -p ~/.config/raven && chmod 700 ~/.config/raven`.

- The app never writes the passphrase file itself: a passphrase stored in a file is a secret at
  rest (OD-19). A start that fails with 'cannot ask for the passphrase' shows the same screen. Until
  it is set up, sending fails on such a profile in the CLI too.
- When `~/.config/raven/keystore-passphrase` exists already (checked with the vault check, on the
  node worker), PASSFILE adds under the steps (UXF.7): 'Your passphrase is saved in a file on this
  computer (~/.config/raven/keystore-passphrase). Anyone who can read your files can unlock Raven
  with it. If that worries you, delete the file when you are not using Raven (for example before
  you travel), and create it again when you want to send and receive.' At 60 x 16 it gives way to
  the steps.

## 8. Settings and look

Settings are saved per profile in `<data-dir>/tui_state.json` (mode 0600, atomic write), and only
once the identity exists: nothing is written into a profile before that (OD-13). A corrupt file
gives the defaults and is left alone until you change a setting. In a profile the privacy pack
sealed, your name and the read markers (the last message read per friend) are kept in the sealed
`tui_private.rms` instead (privacy pack PP.24; `docs/design/2026-10-at-rest-metadata.md` section
4.21); the other settings stay in `tui_state.json`, which the start-up check reads before the
identity is open.

| Setting | Values |
|---|---|
| Your name (only on this computer) | free text, never sent |
| Motion | Full · Reduced: no spinners or animations |
| Colors | Automatic · No colors (forced by `NO_COLOR`) |
| Symbols | Automatic · ASCII (for any terminal) · Simple (for older terminals) · Fancy |
| When I quit | §6 |
| Receive messages on this computer | §5 |
| Share my network address in my invite | On · Off |
| Show technical details | On · Off |
| Start Raven when I log in | shown only (§6) |
| Switch to the classic menu now | this run |
| Always open the classic menu | On · Off (the gate, rule 6) |
| Lock now | an action: LOCK (§6) |
| Erase Raven from this computer | an action: ERASE, over the whole screen (privacy pack PP.22; `docs/design/2026-10-at-rest-metadata.md` section 4.19); shown once the privacy read answered |

**Automatic choices.**

- Symbols: ASCII when `LC_ALL`, `LC_CTYPE` or `LANG` starts with `zh`, `ja` or `ko`, or the Windows
  output code page is 932, 936, 949 or 950 (box drawing and `·…●` are ambiguous-width there);
  Simple on Windows without `WT_SESSION` and on `TERM=linux`; Fancy otherwise.
- Colours: green, red and cyan only; secondary text is dim, never grey (grey is nearly invisible on
  macOS Terminal's white profile); warnings are bold. `NO_COLOR` gives a mono theme (bold, dim,
  reversed). The selected row always also has a `>` marker.
- Motion: reduced by default with `TERM=linux`, `NO_COLOR`, `RAVEN_REDUCED_MOTION` (set, not `0`) or
  a screen reader. The spinner turns at 12 frames a second, 6 over SSH, and no animation draws
  faster; nothing redraws while nothing changes, but for Home's clock once a second (UXF.10).

The real terminal cursor sits on the focused field, so magnifiers and screen readers can follow it.
Line wrap is off while the screen is up, so a character the terminal draws wider than expected is
clipped at the edge. Every name, message and log line goes through one sanitizer
(`tui/display.rs`): escape sequences, control and bidi-override characters are removed, emoji
sequences are split into single emoji, and long text is clipped.

## 9. How it is built

- One UI thread runs a pure state machine (`app.rs`, `update(msg) -> cmds`) and draws only when
  something changed or an animation frame is due. Worker threads do all identity, store, send, IPC
  and node work through `controller.rs`; every write to `contacts.json` runs on one store worker.
- `bridge.rs` is the only file that names items of `cli.rs`, `ext.rs`, `pair_init_lab.rs`,
  `p2p_cli.rs` and `ipc_client.rs`. Source-scan tests in `testkit.rs` enforce this, forbid exiting
  or prompting calls in `bridge.rs` and `controller.rs`, pin every bridged signature
  (`bridge_api_pins`), keep `unsafe` in `stdio.rs` alone, and hash the few pieces of CLI and
  raven-node logic the app mirrors.
- Output of existing code is captured so nothing draws over the screen: stdout through the
  `print_stdout` hook, stderr through a pipe redirect (close-on-exec on every descriptor involved,
  non-inheritable handles on Windows), armed once per session. Captured text stays in memory (a
  256-line ring) and is shown, sanitized, only under Details.
- The terminal is always restored: a drop guard, a chained panic hook, a signal thread for SIGTERM
  and SIGHUP (Windows close and break) that never force-exits while the identity or the friends are
  being saved, and thread-death guards.

## 10. Safe-run setup

Every scripted or manual check outside the owner's own matrix (§11) runs like this, never against
`~/.raven` or any existing profile:

```sh
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file \
  RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file \
  RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0
D=$(mktemp -d "$SCRATCH/tui-run.XXXX")      # a fresh scratch profile
cd node && cargo build -p ash -p raven-node   # debug: locked-file is refused in release builds
target/debug/raven --data-dir "$D"            # RAVEN_UI=tui forces the app where the gate allows
```

- With this setup the header reads 'Receiving on this computer only', not 'Listening on port 7420'.
  Use port 0 or a high random port; never 7420, 7422 or 7423 on a computer that runs a real node.
- Afterwards stop only the node started for `$D`, by the pid that
  `target/debug/raven --data-dir "$D" status` reports. No other raven-node is touched.
- Owner-run only: real Keychain prompts (macOS without locked-file), release-binary checks,
  two-machine LAN checks, firewall prompts, and the Windows matrix (the Windows pipe is per user,
  so a running node would be shared).

## 11. Tests and platform checks

**Automated** (CI runs all of it on rust-linux, rust-macos and rust-windows):

- `cargo test --locked -p ash --bin raven tui::`: unit and render tests (exact cell text through
  ratatui's TestBackend at 80x24, 60x16 and the Home sizes), the gate truth table for both
  `DEFAULT_ON` values, controller tests on ephemeral profiles with fake IPC daemons, and the source
  scans and drift hashes.
- `tui/e2e_tests.rs` (Unix): two profiles add, verify and message each other through the App and
  the Controller, with fake nodes; no raven-node is ever spawned.
- `crates/ash/tests/tui_pty_smoke.rs` (Unix): the real binary under `script` with `RAVEN_UI=tui` on
  an empty profile opens WZ-1, quits on `q`, and leaves `stty -g` exactly as it was.
- Unchanged byte for byte: `crates/ash/tests/ux_screens.rs`, `cli_failure_paths.rs` and
  `ux_send_chat.rs`, `node/scripts/ash_menu_smoke.sh` and `ash_doctor_send_smoke.ps1`. They run
  with piped stdio, so the gate keeps the classic menu. A harness that drives `raven` under a
  pseudo-terminal and needs the menu must set `RAVEN_UI=classic`.

**Cross-target type-check, recorded 2026-10-16.** From macOS, on a scratch copy of the tree with a
scratch-only stub in `third_party/libsqlite3-sys-raven/build.rs` (`RAVEN_PROBE_TYPECHECK_ONLY`, so
no target C toolchain is needed; never ported to the tree), with an isolated rustup home on
rustc 1.98.0 (the CI pin):

```sh
cargo check --locked -p ash --all-targets --target <target>
```

| Target | Result |
|---|---|
| `x86_64-pc-windows-msvc` | clean: no errors, no warnings |
| `x86_64-pc-windows-gnu` | clean: no errors, no warnings |
| `x86_64-unknown-linux-gnu` | clean: no errors, no warnings |
| `x86_64-unknown-linux-musl` | clean: no errors, no warnings |

This checks types and rustc lints (dead code included) for those targets. It does not link, run
tests or run clippy there; the native CI jobs are the real gate.

**Manual terminal matrix** (owner-run; status as of 2026-10-16: not yet run).

| Terminal | Expected with `raven` and no arguments |
|---|---|
| macOS Terminal.app, white profile and dark profile | the app (Fancy symbols) |
| iTerm2 | the app |
| GNOME Terminal, with a friend whose name is right-to-left | the app; the RTL name does not reorder the other pane |
| Konsole | the app |
| Windows Terminal | the app (Fancy) |
| Windows 10 console host (conhost) | the app (Simple symbols, plain borders) |
| conhost with 'Use legacy console' | classic menu |
| Git Bash / mintty | classic menu |
| tmux over SSH | the app; spinner at 6 frames a second |
| `TERM=linux` text console | the app (Simple symbols, reduced motion) |
| a `ja_JP.UTF-8` locale | the app (ASCII symbols) |
| any terminal with `TERM=dumb`, `RAVEN_UI=classic`, or the saved 'Always open the classic menu' | classic menu |
| Windows with a screen reader running | classic menu (`RAVEN_UI=tui` still opens the app) |

Each run covers: the wizard; adding a friend by paste (on Windows also a keystroke paste of a card
while the share box has focus); verifying; sending to a second machine; resizing (Windows
included); `NO_COLOR`; reduced motion; quitting with the node kept running and with it stopped;
quitting while a message waits for a friend who is away (the warning, then `Q`);
Lock now (whether the terminal's scrollback is gone afterwards, which depends on the terminal);
`kill -TERM <pid>` restoring the terminal; a double-click launch on Windows; with a Persian keyboard
layout on (Windows "Persian (Standard)", GNOME "fa"), Q opening QUIT from Home and letters typed in
the composer staying as typed, recorded in the layout check of §3.

**Scripted here instead** (2026-10-16, macOS, a pseudo-terminal at 80x24, the safe-run setup): see
§13.

## 12. Merge checklist

The app is merged into the feature tree, where `cli.rs` and `ext.rs` keep changing. Anchor on
function names, not line numbers.

1. **Regenerate the lock; never hand-merge it.** Take the feature tree's `Cargo.lock`, keep the 4
   manifest lines in `crates/ash/Cargo.toml` (right after `zeroize`), then:

   ```sh
   cd node
   cargo update -p ash                     # locks the new packages
   cargo update -p indoc --precise 2.0.7
   cargo update -p litrs --precise 1.0.0
   grep -c '^name = "crossterm"' Cargo.lock                              # must print 1
   cargo tree --locked -p ash -d --target all | grep -E '^crossterm '   # must print nothing
   ```

2. **Re-apply the edits to existing files** if they conflict: `mod tui;` after
   `mod trace_delivery;`; `if tui::stdio::divert_stdout(args) { return; }` as the first statement
   of both `print_stdout` variants; `None => tui::run_or_classic(&data_dir),` in `run()`;
   `pub(super)` on `ext::Cause` and `ext::classify_cause`.
3. **`cargo check --locked -p ash`.** Fix every error in `tui/bridge.rs` only: it is the one file
   that names CLI items, and `bridge_api_pins` names every bridged item with its expected type.
4. **Run `cargo test --locked -p ash --bin raven tui::testkit`** and fix any mirror a failing drift
   test names: `bridge_still_mirrors_the_clis_send` (`run_send` in cli.rs → `bridge::send_routes`),
   `errors_words_every_outbox_code_of_raven_node` (raven-node's `mod code` → `tui/errors.rs`),
   `ext_still_prints_the_texts_the_app_reads` ('started raven-node (process', 'may have it
   anyway'), `raven_core_still_words_the_keychain_wait_as_the_app_reads_it`,
   `raven_core_still_says_it_cannot_ask_for_the_passphrase`.
5. **Read the body of every bridged helper that changed** for new stdin reads, prompts or
   `process::exit`: the forbidden-call scan sees only `bridge.rs` and `controller.rs`, not what a
   helper does inside.
6. **Re-run the end-to-end test** (`tui::e2e_tests`), then the full gates, from `node/`:
   `cargo fmt --all`, `cargo clippy --locked -p raven-core -p ash -p raven-node -p raven-swarm
   --all-targets -- -D warnings`, `cargo test --locked -p raven-core -p ash -p raven-node`,
   `scripts/ash_menu_smoke.sh`, `bash scripts/messaging_product_boundary_gate.sh`,
   `bash scripts/sqlcipher_release_feature_audit.sh` and
   `python3 scripts/audit_active_dependencies.py`.
7. **Switch to the cutoff pack's helpers** once they are in the feature tree. Each stand-in here
   says "not known" until then:
   - `bridge::deadline_text` (UXF.1): the clock time from `raven_core::local_time::deadline`
     (CP.6). QUIT's '(until …)' (UXF.8) reads it too. **Done in CP.6**: with this computer's
     offset `short` is 'tomorrow 09:10' and `long` 'tomorrow at 09:10 (about 19 hours from
     now)', `hh_mm` is set; without it, the relative words as before. Under test the offset is
     unknown unless a test sets one (`bridge::with_local_offset`), so every rendered screen
     reads the same in every time zone (`deadlines_name_this_computers_clock_time_when_it_is_known`).
   - `bridge::queue_horizon` (UXF.2): wrap `raven_core::outbox::queue_horizon` (CP.6), reading
     only a session store that already exists; update
     `no_horizon_is_known_before_the_cutoff_packs_read`. **Done in CP.6**: a profile with no
     store (or no secure connection with the friend) gives `Some(None)`, meet first; the test
     is now `the_horizon_is_raven_cores_metadata_read`, and the controller's horizon test
     expects 'meet first'. errors.rs's `needs_meeting` also reads CP.6's NOT SENT once the
     secure connection ended (`SESSION_ENDED_MARK`, pinned in testkit's `EXT_TEXTS`).
   - `bridge::on_any_network` (UXF.5): wrap `raven_core::netifs::read` (CP.4): `Some(true)` when
     an interface that is up has an address that isn't loopback, `Some(false)` when none has,
     `None` when the read fails; update `no_network_state_is_known_before_the_cutoff_packs_reader`.
     **Done in CP.4**, counting only addresses a friend could dial (`netifs::for_friends`): a
     Mac's tunnels and peer-to-peer Wi-Fi always carry an fe80 address. The test is now
     `the_network_state_is_raven_cores_interface_read`.
   - `node.rs` (UXF.5, CP.5): `Probe::of` fills `bind` from Status's `lan_bind_error` and
     `lan_listen_wanted` through `bind_failure`; `reach_of` maps the new
     `NodeReach::ReceiveLocalOnly` to `Reach::LocalOnly`; the tests' `IpcResponse::Status`
     values gain the two fields. **Done in CP.5**: cli.rs's `classify_node_reach` now tells the
     loopback listener itself, so `reach_of` no longer reads `lan_listen` for it (and
     `bridge::listen_is_loopback` is kept for testkit's pin only); the Status's own word wins
     over the service log's in `a_node_view_says_why_it_isnt_receiving_until_it_is`.
   - `errors.rs` (UXF.5, CP.5): `cause_words` gains `Cause::NameNotFound => NAME_NOT_FOUND`
     (which loses its `cfg(test)`), and `a_computer_name_not_found_has_its_words_for_the_merge`
     becomes its `cause_test!` in `test_of`. **Done in CP.5**: the test is now
     `cause_name_not_found` plus `a_computer_name_not_found_has_its_words`; a first message to
     a friend whose name isn't found waits for a meeting (`needs_meeting`), and the cause is a
     connect failure in `delivery.rs` (nothing was written).
   - MEET's step 3 (UXF.6, CP.4): today it shows the one address NET shows (`bridge::egress_v4`,
     or the IP the listener is bound to), with the listener's port, while Raven listens on the
     network. At the merge it lists every address `raven_core::netifs::lan_addresses_for_friends`
     gives, hotspot first, each with the port on its own row: a bridge function wraps it, read
     on the node worker when step 3 opens (never in a draw); update
     `step_3_shows_this_computers_address_as_far_as_it_is_known` and the step 3 render rows in
     `ui/meet.rs`. Later, with the Phase 3 beacon live, 'Looking for {name} on this network…' and
     'Found {name}.' take the place of the typing step. **Done in CP.4**: the node job
     `LanAddresses` reads `bridge::lan_addresses_for_friends` when step 3 opens; step 3 lists
     those the listener takes (`bridge::listener_takes`: 0.0.0.0 takes no IPv6 address), and its
     heading says 'addresses' when there is more than one.
   - `bridge::fold_code_digits` and `bridge::code_has_non_latin_letters` (UXF.3): cli.rs's
     own once CP.8 adds them. **Done in CP.8**: they wrap cli.rs's `fold_digits` and
     `code_has_non_latin_letters` (the CLI's code comparisons fold too, so folding twice
     changes nothing), and VF's keyboard hint is cli.rs's `CODE_KEYBOARD_HINT`
     (`bridge::CODE_KEYBOARD_HINT`), the words `raven contact add --verify-fp`, the guided add
     and `raven contact verify` print for a code typed with Persian letters.

## 13. Verification record (2026-10-16, UX track)

- `cargo fmt --all`; clippy with `-D warnings` on raven-core, ash, raven-node and raven-swarm (and
  the CI variant with `ash/debug-trace-delivery,raven-node/corebluetooth`) with no dead-code
  allowance left in `tui/`.
- `cargo test --locked -p ash`, including the `tui::` tests, the end-to-end test and the pty smoke;
  `node/scripts/ash_menu_smoke.sh` (with a loopback listen address).
- The cross-target type-check in §11.
- A scripted pseudo-terminal run of the shipped default (`DEFAULT_ON = true`, no `RAVEN_UI`; 45
  checks, run twice, all passed):
  an empty profile prints the opening line, enters the alternate screen and shows Welcome; a profile
  with an identity opens Home; `q` (and Enter in QUIT) exits 0 with `stty -g` unchanged and no node
  started. `RAVEN_UI=classic`, `TERM=dumb`, a piped stdout and the saved 'Always open the classic
  menu' each open the classic menu instead, and `RAVEN_UI=tui` overrides the saved setting.
- Not run: the manual terminal matrix (§11), Linux and Windows natively, release binaries, real
  Keychain and firewall prompts, two-machine sends. These are the owner's.

UXF.10 (2026-10-22, live feel): an idle Home in an 80 x 24 pseudo-terminal (`script`, debug build,
a throwaway profile with an identity and no friends, so no background program) used 0.09 to 0.10 s
of CPU over 20 s (about 0.5 %, `ps` and `top` samples between 0.0 % and 0.7 %) with the clock
redrawn once a second; the same with `RAVEN_REDUCED_MOTION=1`.
