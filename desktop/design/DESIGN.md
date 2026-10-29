# Raven desktop apps — design

Three native apps with one design: **macOS** (SwiftUI), **Windows** (WinUI 3, C#) and **Linux**
(GTK 4, Rust). Same screens, same texts (`strings.en.json`), same tokens (`tokens.json`), same honest
motion. Each app looks like it belongs on its system (native window chrome, menus, controls, fonts),
but a user who knows one knows all three.

**Design: Calm** (chosen by the owner on 2026-10-28). The approved prototypes are the visual and motion
reference: `concept-1-calm.html` (the desktop apps) and `concept-1-calm-terminal.html` (the terminal
app), local HTML prototypes that are kept out of the repository (the owner shares them; their Prototype
menu plays the scenes). `tokens.json` (version 2) carries their palette, type ramp, radii,
layout and motion (durations, curves, springs, and the terminal palette); the apps keep their own
behaviour and wording rules, and show only what the engine reports. The earlier concept
(`mockups/desktop-concept.html`) is kept for history.

### Calm at a glance

- **Window:** a sidebar (`sidebar` colour, 272 pt): the mark and **Raven** with the heartbeat ("node ok ·
  now"), **You** (fingerprint), Search, FRIENDS (avatar 36 pt with its presence dot, name, status line,
  the path icon of the last delivery or an unread badge), GROUPS (stacked avatars, members line),
  **Add a friend**, and at the bottom Network (with "n ways on"), Security words, Security, Settings.
- **Chat:** a 66 pt header (avatar, name, Verified / Not verified, status · path; the path pill or
  "{name} holds your mail" and Routes on the right); a 34 pt route line (You ── path ── friend; dashed
  while the friend isn't reachable); day lines ("Today"); bubbles (incoming on `surface` with a shadow;
  yours a gradient `accentFillTop` → `accentFill`; a waiting one is an outline); under each bubble its
  time, the tick (spinner, sent ring, filled delivered check, dashed waiting clock) and the path chip;
  a "new message" pill above the composer; the rounded composer with the round send button and the
  "End-to-end encrypted…" line.
- **Groups:** sender names in their avatar colour, a small avatar beside each bubble, and under yours a
  ring with one arc per member that fills as each confirms ("Delivered to 3 of 5" · "1 held by Sam ·
  1 waiting"); Details lists every member with their state and path chip.
- **Friend away:** the waiting bubble is an outline with "Waiting for {name} · until {time}" and the
  "Held by {friend}" chip; under it the away card (You ── holder ··· friend, Try now, Details, Stop
  trying); the sidebar line says "1 waiting · until Fri 18:00".
- **Network page:** "This computer" card (the mark with its radar rings, listening line, background
  program, heartbeat), Ways to reach friends as cards with a coloured icon, switch, description and state,
  Protections with switches.
- **Settings:** seven sections (General, Appearance, Privacy, Lock, Network, Updates, About) in a
  228 pt list with coloured square icons; the selection glides between them and the section's content
  slides in from the direction of travel; grouped cards of rows (title, description, control on the
  right); springy switches, segmented controls with a sliding thumb, radio rows; the Lock sheet and the
  locked window.

## Principles

1. **Honest.** Never claim more than Raven knows: "Sent, not confirmed yet" until a signed receipt
   arrives; "In touch 5 min ago", not "online"; Preview labels for features off in this release.
2. **Alive, not busy.** Motion only when something real happens (see Honest motion). Idle windows are
   still and cost no CPU beyond a 1-second clock.
3. **Safe by default.** A friend is verified only after the security words match; the friend's words
   are never shown; nothing secret appears on screen; text from friends is sanitised.
4. **One next step.** Every error says what happened and one thing to do; details are one click away.
5. **English only.** Typed input tolerates Persian/Arabic-Indic digits and other keyboard layouts;
   nothing is displayed in another language.

## Screens

| Screen | macOS | Windows | Linux |
|---|---|---|---|
| Install | DMG window: Raven icon, arrow, Applications ("Drag Raven to Applications") | MSIX/installer wizard with the same three steps | Flatpak/AppImage/deb; first run identical |
| Welcome | Window with the Raven mark (fades in), R A V E N wordmark, tagline types itself, three steps, **Get started** | same, Fluent styling | same, libadwaita-like styling |
| Setup | Name (optional) → Receive messages? (with the OS-specific firewall/local-network sentence) → Creating identity (spinner) → Your security words | same | same |
| Main window | Sidebar: search, friends (avatar, presence dot, name, status line, unread badge), Add a friend. Chat: toolbar (name, Verified badge, path pill, heartbeat + "node ok · now"), route line, bubbles with tick text, toast line, composer | NavigationView left pane + chat | `Gtk.Paned` sidebar + chat |
| Message details | Sheet: status, why, what you can do, Try now / Stop trying / Details | ContentDialog | `Adw`-style dialog |
| Add a friend | Sheet with a step strip (Share yours · Paste theirs · Check words); pasted card collapses to a summary | same | same |
| Check words | Sheet: your 10 words (read-aloud highlight, word 10 marked "check"); typed words appear as neutral chips; field completes after 3 letters; result only at the end (match / typo / mismatch); a small secondary link switches to the old code (see Security words) | same | same |
| Network | Panel: This computer (listening chip, background program), Ways to reach friends (Preview labels), About | Settings page | Preferences page |
| Settings | Calm: in the main window, seven sections (General, Appearance, Privacy, Lock, Network, Updates, About) with a gliding selection; privacy choices from the storage policy; Encrypt everything and Erase follow `privacy.state` (see Privacy actions) | Settings page | Preferences window |
| Menu bar / tray | macOS menu bar extra: breathing Raven mark; menu with status, friends, Open, Add a friend, Lock, Quit window, Quit and stop | Notification-area (tray) icon with the same menu | StatusNotifierItem (where supported) with the same menu; otherwise a background-app entry |
| Quit | Dialog explaining what keeps running | same | same |
| Locked | Window showing the mark and **Unlock** (after the privacy pack) | same | same |

## Honest motion

| Motion | Trigger (API event) | Visual |
|---|---|---|
| Heartbeat | `status_ok` | ♥ pulses once (500 ms); "node ok · now" resets |
| Packet out | `send_started` | a small ▸ travels along the route line left to right (800 ms) |
| Receipt back | `receipt` | a ✓ travels back right to left (650 ms); tick text becomes "Delivered" |
| Incoming | `incoming` | ◂ travels in; the bubble slides up and fades in (350 ms); bold for 1.5 s |
| Presence | `presence` | the friend's dot changes colour with a short blink; "in touch" dots breathe slowly (3 s) |
| Retry | `retry` | a ring expands once around the friend's dot (1 s) |
| Node start | `node` (starting) | spinner in the network chip until listening |
| Logo | welcome screen only | the mark fades and scales in once; menu-bar mark (Windows: tray icon) breathes while listening |

| Bubble lift-out | `messages.send` returned | your bubble lifts out of the composer to its place (520 ms, curve `lift`) |
| Check fills | `receipt` | the delivered check fills and pops (450 ms, curve `pop`) with one ripple; the path chip slides in (`chipSlide`) |
| Group ring | `group_changed` / a receipt per member | the member's arc takes its colour (500 ms) |
| Radar | `status_ok` on the Network page | two rings spread around the mark |
| Settings glide | the user picks a section | the selection glides (450 ms, `glide`), the content slides in (`sectionIn`) |
| Switch, segmented control | the user's choice (a switch moves to the engine's answer) | knob springs (`knob`), thumb slides (`thumb`) |
| Lock | the user locks | the shackle closes, the locked window fades in; a wrong passphrase shakes the card |

Reduced motion (system setting or Raven's): none of the above moves; texts still update.

## Security words (owner decision)

10 English words from Raven's own 256-word list: 9 carry the key, word 10 is a check word that
catches a misheard or swapped word. Typing completes after 3 letters. The friend's words are never
shown and there is no per-word right/wrong mark; only the final check says match, "one word doesn't
fit" (read again) or mismatch (do not verify). After three mismatches Check is no longer offered
("Stop here…"). The old letters-and-digits code stays accepted. Full design:
`docs/roadmap/plans/security-words-design.json`.

**Old code (friends with an older Raven).** Under the typed words, a small secondary link "Older Raven?
Use the old code instead" switches the sheet to the old code: the intro talks about the code
(`check.oldCode.intro`), your old code is shown in groups of four as in the security-words design
(`If4x 36FU omFi`, also on the words screen) to read aloud, and the friend's old code goes into one plain field
(no chips, no completion, no per-character marks; spaces and separators are ignored, letter case
matters). The result comes only at the end, from `verify.check_old_code`: match (the friend is saved as
verified, exactly as with the words) or mismatch (compare once more, otherwise do not verify). "Use the
10 words instead" switches back. Mismatches count towards the same limit of three.

## Privacy actions

Settings → Privacy shows "Encrypt everything stored on this computer" and "Erase Raven from this
computer…" from `privacy.state`. While `available` is false (this release) both are disabled and
labelled "Preview, not in this release", like the Preview carriers. When available, the switch shows
`encrypted` and turns encryption on with `privacy.encrypt`; Erase opens a confirmation dialog that
says what is removed and enables **Erase** only after the user types "erase", then calls
`privacy.erase` and returns to the welcome screen. "Lock now" in the menu bar or tray is disabled
while `available` is false.

## Per-platform notes

- **macOS:** SwiftUI app (macOS 13+), menu bar extra (`MenuBarExtra`), sheets for dialogs, DMG built
  with `hdiutil`, signed and notarised (see `node/SIGNING_NOTARIZATION_CHECKLIST.md`). The Local Network
  privacy prompt appears on first listen; the setup screen explains it before it appears.
- **Windows:** WinUI 3 (Windows App SDK) app in C#, Fluent controls, notification-area icon, MSIX or
  installer. raven-node runs as the user's background process; the named pipe is per user.
- **Linux:** GTK 4 app in Rust (gtk4-rs), follows the system light/dark scheme, packaged as
  AppImage/deb/Flatpak. Tray support varies by desktop; when missing, Raven keeps running in the
  background and says so on quit.
