# Tor onion carrier: field test runbook (lab)

Design: [`design/2026-10-tor-fallback.md`](design/2026-10-tor-fallback.md). Carrier:
[`../protocol/RAVEN_ONION_CARRIER_V1.md`](../protocol/RAVEN_ONION_CARRIER_V1.md). Lab only:
debug builds, `RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_TOR=1`. Automated tests never touch the real
Tor network; this run is the real-network check.

## Machines

- **M**: a Mac on a phone hotspot (symmetric carrier NAT, no IPv6).
- **W**: the Windows laptop behind a second router (double NAT), on another network.
- **S**: the Mac Studio, observer only (not a contact of M or W, so no friend relay or custody
  can help).

No port forwards. Fresh test profiles only: never `~/.raven`, never a running node, never the
three-machine kit's profiles or ports (17420-17428).

## 1. Build (once per machine)

macOS (Terminal that has Local Network permission):

```sh
cd <repo>/node
git fetch origin && git checkout feature/tor-fallback && git pull
CARGO_INCREMENTAL=0 cargo build -p raven-node -p ash --features raven-node/tor
ls target/debug/raven-node target/debug/raven target/debug/raven-tor-helper
```

Windows (Developer PowerShell or cmd):

```bat
cd <repo>\node
git fetch origin && git checkout feature/tor-fallback && git pull
set CARGO_INCREMENTAL=0
cargo build -p raven-node -p ash --features raven-node/tor
dir target\debug\raven-node.exe target\debug\raven.exe target\debug\raven-tor-helper.exe
```

`raven-tor-helper` must stay next to `raven-node` (raven-node starts it from its own folder).
It is built with Arti's vanguards (lite, Arti's default; owner decision 2026-10-29): the first
start after this change picks a new set of second-hop relays, nothing to do by hand. Record the
bootstrap and "onion service reachable" times as before: a slower publish than in round 8 is
expected and accepted.

## 2. Environment (every shell that runs raven or raven-node)

macOS:

```sh
export RAVEN_LAB_TEST_A=1 RAVEN_LAB_TOR=1 RAVEN_LAB_HORIZON=1 RAVEN_LAB_ROUTE_HINTS=1
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file \
  RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file
export D=$HOME/raven-tor-test    # the test profile
export PATH=<repo>/node/target/debug:$PATH
```

Windows (cmd):

```bat
set RAVEN_LAB_TEST_A=1
set RAVEN_LAB_TOR=1
set RAVEN_LAB_HORIZON=1
set RAVEN_LAB_ROUTE_HINTS=1
set RAVEN_IDENTITY_BACKEND=locked-file
set RAVEN_SESSION_BACKEND=locked-file
set RAVEN_PREKEY_BACKEND=locked-file
set RAVEN_CHAT_HISTORY_BACKEND=locked-file
set D=%USERPROFILE%\raven-tor-test
set PATH=<repo>\node\target\debug;%PATH%
```

**Combined run with auto-reach** (one branch since the merge of `feature/auto-reach`): use the
S5A set plus the auto-reach and Tor switches on every machine:

```sh
export RAVEN_LAB_TEST_A=1 RAVEN_LAB_HORIZON=1 RAVEN_LAB_PORT_MAP=1 RAVEN_LAB_V6_PINHOLE=1 \
  RAVEN_LAB_NAT_CLASS=1 RAVEN_LAB_ROUTE_HINTS=1 RAVEN_LAB_FRIEND_RELAY=1 RAVEN_LAB_CUSTODY_WAN=1 \
  RAVEN_LAB_STUN_DISCOVERY=1 RAVEN_LAB_SERVERLESS_PUNCH=1 RAVEN_LAB_TOR=1
```

(Windows: one `set NAME=1` per switch.) Start the node as the three-machine kit's S5A does
(its Internet direct and p2p listeners and consents); the Tor helper needs nothing more. Every
send then races the direct paths (LAN, IPv6/IPv4
direct, the STUN-discovered address, punching, a friend relay) against Tor; when nothing direct
works, Tor carries it.

- `RAVEN_LAB_TOR=1` (with `RAVEN_LAB_TEST_A=1`): the Tor helper, the onion service, onion
  dials, `onion=` in cards, the ONION route hint.
- `RAVEN_LAB_HORIZON=1`: a first message to a contact with no session yet waits and the node
  pairs over whatever path works (Tor here), instead of "meet first".
- `RAVEN_LAB_ROUTE_HINTS=1`: friends tell each other new routes (a new onion key, direct
  addresses for moving off Tor).

## 3. First run (each of M and W)

```sh
raven --data-dir "$D" init
raven --data-dir "$D" prekey publish
raven-node service --data-dir "$D" --lan-listen 0.0.0.0:17530 --ble-listen 127.0.0.1:0 \
  2> "$D-node.log" &
```

(Windows: `start /b raven-node service --data-dir "%D%" --lan-listen 0.0.0.0:17530
--ble-listen 127.0.0.1:0 2> "%D%-node.log"`; Windows Defender may ask about the LAN listener:
Tor needs no inbound rule, either answer works.)

Write down the start time, then watch the node log for:

- `raven-node onion: Tor: starting`
- `raven-node onion: Tor: ready (bootstrap N s)`: **record N** (bootstrap time).
- `raven-node onion: Tor: onion service reachable (N s after start)`: **record N**. After it,
  only settled changes are logged: `onion service unreachable for 60 s (Arti: <state>,
  <reason>)` and `onion service reachable again` (Arti's republish "bootstrapping" blips are
  not); **record** each with its time. A line that ends `a friend reached it over Tor before
  Tor said so` (or `reachable again (a friend reached it over Tor)`) means a friend's link came
  in before Arti finished publishing: record it too, and note when Arti's own state followed.
- Self-checks (round 10): `self-check reached our onion service` (two an hour), `self-check
  reached our onion service, whatever Arti: ... says` (Arti's word was wrong for friends), or
  `self-check did not reach our onion service (<reason>)` (every 10 minutes while it fails). An
  outage is now measured: `onion service unreachable for 60 s (self-check failed: ...; Arti:
  ...)`. **Record** each outage line, and from `raven --data-dir "$D" status` the `Tor` row's
  "outages since start" count and the last one's length.
- `descriptor upload round: N of M HSDirs took it`: **record** the rounds where N is less than M
  (and N = 0: every HSDir that needed our descriptor timed out from this uplink).
- or `Tor: blocked on this network (...)` (record it; the node retries by itself);
- or `Tor: could not start on this computer (...)` (record it: the reason in brackets says
  what went wrong on this computer, not the network).

While it starts, the log has one line per bootstrap stage, `raven-node onion: Tor: starting
(15 %, consensus, 4 s)`, and every helper that ended leaves one line of last words:
`raven-node onion: Tor helper ended after 121 s (...): 15 %, stage consensus, ..., answered
7 pings, last 1 s ago`. **Copy these lines** into the field-test notes when a start fails
(states, words and numbers only; no address).

`raven --data-dir "$D" status` shows the same state in its `Tor` row (`starting (45 %)`,
`ready`, `ready (onion service publishing)`, `blocked on this network (...)`,
`could not start on this computer (...)`, `restarting (...)`).

## 4. Cards (once)

```sh
raven --data-dir "$D" whoami --card     # one line; it ends with onion=...
```

Never add `--inet` or `--lan`: a card carries no IP address, only the onion address (which
reveals none, and is signed by the card's own key). Addresses travel only inside encrypted,
authenticated links (route hints), Tor links included.

Send the line to the other machine (chat, AirDrop, a file). On the other machine:

```sh
raven --data-dir "$D" contact add --card '<their line>' --petname friend
raven --data-dir "$D" contact verify friend   # compare the security words aloud, then pin
```

`contact add` says "the card also names their Tor onion service (signed by their key)". A card
whose `onion=` is not signed by its own key is refused.

## 5. Messages

M sends 10 messages to W, one every 30 s; then W sends 10 to M:

```sh
for i in $(seq 1 10); do
  printf 'tor-test M->W %02d %s\n' "$i" "$(date -u +%H:%M:%S)" | raven --data-dir "$D" send --contact friend
  sleep 30
done
```

(Windows: `echo tor-test W->M 01 & ... | raven --data-dir "%D%" send --contact friend`, or type
the line after `raven --data-dir "%D%" send --contact friend`.)

**Tor between two computers on one LAN** (lab): `raven --data-dir "$D" send --contact friend
--carrier onion` sends over Tor only (the friend's signed onion address; its LAN address is
left out, and if it waits in the outbox it is retried over Tor only). It works only in a debug
build with `RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_TOR=1` (anything else refuses it with
ONION_HOLD before dialling), only for a verified contact, and only with `--contact`.

Record for each message: the time `raven send` returned, the time it shows in the other side's
`raven --data-dir "$D" inbox`, and the path (`raven --data-dir "$D" outbox list` while it waits;
`status delivered` lines say `path: via Tor`). Record the **first** message's time separately
(first connection: pairing plus the first rendezvous, 10-30 s expected).

## 6. Robustness

1. Sleep both laptops 5 minutes, wake, send 2 messages each way. Expected in the log:
   `raven-node netwatch: woke from sleep` then `raven-node onion: Tor: restarting (woke from
   sleep)` and `Tor: ready` again. Record the time to delivery.
2. Move M from the hotspot to a Wi-Fi and back once while W sends: expected
   `Tor: restarting (network changed)`; record delivery.
3. Put M and W on the same Wi-Fi: send 2 messages each way. With route hints on, the first may
   still go over Tor; later ones go direct (`same network (LAN)`), because every send races the
   direct paths with a 1.5 s head start.

4. **A stale LAN address** (S15 retest): on M, keep W's old LAN address in the contact (or
   send right after W moved off M's network). Each send should take about as long as the Tor
   path, not 8 s more: the stale LAN probe and Tor's probe race (Tor after 1.5 s).
5. **Background retry over Tor** (S15 retest): stop W's raven-node, send 2 messages from M (they
   queue), start W again. Expected: both arrive within a few minutes without another `raven
   send`; `raven --data-dir "$D" outbox list` on M then says delivered, path via Tor.
6. **Custody over Tor** (S15 retest, with `RAVEN_LAB_CUSTODY_WAN=1` on all three and the
   Windows computer as the third friend): with W reachable only over Tor, messages the third
   friend left at M for W reach W over Tor: W's log says `raven-node custody: fetched
   messages=N ... (onion_dial)`. An idle mail friend is polled over Tor at most every 30
   minutes; a link from it, or mail in the last round, makes the next poll go at once.

**Windows (S15 retest).** Tor should no longer hang at 15 % (`saturating-time` patched for
arti#2726; checked by unit tests and Windows CI, not yet on win-c). If a start still fails, the
log now says which side it is: `Tor: blocked on this network
(...)` (no Tor relay answered, or Tor says offline/filtered/cant_reach_tor) or `Tor: could not
start on this computer (...)` (the helper crashed, hung or said a local error, the clock, or it
got stuck after relays answered), followed by the helper's last words. Copy the `raven-node
onion:` lines of the first two starts into the notes.

## 7. Collect

From each node log: the `Tor:` lines, restarts and their reasons. Check that no onion address
appears in any log:

```sh
grep -c '\.onion' "$D-node.log"      # expected 0
```

Pass: 20/20 delivered over Tor in §5 (the first within 60 s, later ones within 10 s each), and
§6.1-6.3 deliver without a manual restart.

## 8. Stop and clean up

End the test `raven-node` process (macOS: `kill %1` in its shell or `pkill -f "$D"`; Windows:
Task Manager, the `raven-node.exe` whose command line names the test folder); its
`raven-tor-helper` ends with it. The test profile holds the onion key in `$D/tor/`; delete the
whole test profile when done.
