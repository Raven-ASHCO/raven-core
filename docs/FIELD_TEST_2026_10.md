# Field test, October 2026: three computers, real networks

This is a short, sanitized report of a test that ran Raven on three real computers between 25 and
29 October 2026. It says what was tested, what was counted, what failed and what is still open.
The raw notes and logs are not published: they hold addresses, keys and network details. Every
number below was counted from them, and each result says where its number comes from.

**Read this first.** These were **debug builds with lab switches on**. Most of what this report
shows (the Tor onion carrier, public address discovery, hole punching, friends keeping mail,
groups, Bluetooth nearby, the long message horizon) is **switched off in release builds**
(see [ROADMAP.md](ROADMAP.md)). Three computers and one person running the test is a small
sample. This is evidence that the design can work on real networks, not proof that it works
everywhere.

## Setup

| | |
|---|---|
| Computers | a MacBook (Apple silicon), a Mac Studio, a Windows 11 laptop. No Linux computer and no phone took part. |
| People | one person did every step that needs a human (reading security words aloud, moving the laptop to the hotspot, allowing operating system prompts); the other steps were scripted on each computer |
| Builds | debug builds of the code of 25-29 October 2026, rebuilt after each fix round. The last check ran on the final build of 29 October, which is the code published in this repository. |
| Lab switches | `RAVEN_LAB_TEST_A` (the lab unlock) plus, depending on the step: `RAVEN_LAB_STUN_DISCOVERY` and `RAVEN_LAB_SERVERLESS_PUNCH` (public address discovery, hole punching), `RAVEN_LAB_TOR` (the Tor onion carrier), `RAVEN_LAB_GROUPS`, `RAVEN_LAB_NEARBY` and `RAVEN_LAB_NEARBY_ONLY` (Bluetooth nearby), `RAVEN_LAB_HORIZON` (messages wait up to 7 days), `RAVEN_LAB_CUSTODY_WAN` (friends keep mail over the internet), `RAVEN_LAB_ROUTE_HINTS`, `RAVEN_LAB_FRIEND_RELAY`, `RAVEN_LAB_PORT_MAP`, `RAVEN_LAB_V6_PINHOLE`, `RAVEN_LAB_NAT_CLASS`, and a few desktop-app switches (LAN beacon, security events, Lock v2). A release build reads none of them. |
| Identities | each computer had a separate test profile, never a real one. The three were added to each other from contact cards and verified by reading the ten security words aloud. |
| Raven servers | none. Raven runs no server. The test used other people's servers: the Tor network, and two public STUN servers (Cloudflare and Google) that only see which public address asked them, and when. |
| Port forwarding | none was set up for the Tor steps, and no address was typed anywhere. Port forwards to the Mac Studio from an earlier step may still have been on the home router; no counted message used them (every message between the two networks went over Tor, and the MacBook and the Windows laptop had no forward). |

Networks, described by type only:

| Computer | Network | What a probe measured |
|---|---|---|
| MacBook, at home | home Wi-Fi behind the home router (in some steps behind a second router) | NAT mapping endpoint-independent ("easy"), no IPv6 |
| MacBook, away | a phone hotspot on mobile data | NAT mapping **endpoint-dependent** ("hard": a new public port for every destination), no port preservation, no IPv6 |
| Mac Studio | home network by cable | endpoint-independent, no IPv6 |
| Windows laptop | Wi-Fi behind a second router at home (double NAT) | not probed separately |

The home router answered none of UPnP, NAT-PMP or PCP, so no computer could open a port by itself.

## Results

"Exactly once" means the receiver's inbox held each labelled message one time. A message counted
as delivered only if it arrived within the time limit of that step (5 minutes for most steps).

### 1. Night soak on one network

| | |
|---|---|
| What | All three at home: on the home network and on a second router inside it (the Mac Studio was connected to both). Every 15 minutes each computer sent one labelled message to each of the other two, for about 6 hours. A stability soak: no message crossed the internet. |
| Result | **138 / 138 delivered, each exactly once** (6 directions × 23 messages) |
| Path, time | all over LAN direct with signed receipts; 0-4 s per message where the sender logged it |
| Other | no node restart and no lost session all night; the logs showed route-hint chatter (fixed later, see Problems) |
| Source | each sender's send log (delivered, receipt) and each receiver's inbox count |

LAN direct is the one path that release builds also have, but these nodes were debug builds with
lab switches on.

### 2. Different networks (the main result)

The MacBook on the phone hotspot; the Mac Studio and the Windows laptop at home. Cards carried the
key and a signed onion address, never an IP address. Raven raced every direct path against its Tor
onion service.

| Step | Direction | Delivered | Path, time per message (sender's log) |
|---|---|---|---|
| A | Windows laptop → MacBook | 10 / 10 | Tor; five delivered during the send (14-18 s each), five by the background retry, all within 5 minutes |
| A | MacBook → Windows laptop | 10 / 10, each once | Tor |
| B | Mac Studio → MacBook | 10 / 10 | Tor, 11-13 s |
| B | MacBook → Mac Studio | 10 / 10, each once | Tor |
| C (MacBook's Bluetooth off) | Mac Studio ↔ MacBook | 5 / 5 each way | Tor, 19-28 s |
| D (a later build) | Windows laptop → MacBook | 10 / 10 | Tor, 12-17 s |
| D | MacBook → Windows laptop | 10 / 10, each once | Tor |
| D | Mac Studio → MacBook | 10 / 10 | Tor; one slow Tor circuit made 9 wait for the background retry, all 10 within 3 minutes |
| D | MacBook → Mac Studio | 10 / 10, each once | Tor |

Every message in these steps arrived exactly once, within the 5-minute limit, over Tor, with no
port forwarding, no address typed and no Raven server. Over Tor a message took about 11 to 28
seconds. Each message opened its own Tor connection, so later messages were not faster than the
first one.

In the first round with Tor (before step A), Tor did not start on the Windows laptop (a bug, fixed
since): its 10 messages to the MacBook missed the 5-minute limit and arrived only after the MacBook
came home, through a friend's custody. The Mac Studio and the MacBook exchanged messages over Tor
in that round.

Hole punching was tried but **never connected** in this test: the hotspot's NAT is the
endpoint-dependent kind, where Raven does not try to guess ports. Every message between the two
networks went over Tor.

Source: delivered and times from each sender's send log; "each once" from the receiver's inbox
count.

**What happened before the Tor carrier.** The first cross-network attempt in this test ran
without Tor and without public address discovery: **no message crossed** while the MacBook was
away, in any direction between the two networks (0 / 10 from each home computer to the MacBook,
and the MacBook's own sends did not get out either), even with a port forward to the Mac Studio
(nobody outside had learned its public address). They waited in the senders' outboxes
or with a friend at home and were delivered, each once, only after the MacBook came back to the
home network (about 35 to 85 minutes after they were written). That result is why the Tor carrier
and address discovery were built and tested.

### 3. A friend who is away

| Step | What | Result |
|---|---|---|
| MacBook's node stopped | The MacBook, on the hotspot, stopped Raven twice (about 5 minutes, then about 2.5). The Windows laptop sent 5 messages during the first stop, the Mac Studio 5 during the second. | **5 / 5 + 5 / 5** delivered after it came back, each once, by the senders' background retry over Tor. Nothing was sent again by hand. |
| A friend keeps the mail | With the MacBook's node stopped (on the hotspot), the Windows laptop's messages were left as sealed copies with the Mac Studio (a friend both had verified), which could not read them. | 3 / 3 delivered, each once, after the MacBook restarted; in another step (all at home) the keeper handed 3 / 3 over 1 s after the recipient came back. |

Source: senders' outbox status (delivered, attempts, carrier), the keeper's log (held and handed
over), receivers' inbox counts.

Friend custody over Tor was added during the test. The logs show the keeper and the hand-over, but
not always which carrier carried the collection, so this report does not claim custody over Tor
as measured.

### 4. Bluetooth chain

A has internet only (Windows laptop), B is a bridge with network and Bluetooth (Mac Studio), C uses
Bluetooth only (MacBook). C's "Bluetooth only" was a lab switch that turns off every other Raven
path; the computer itself stayed online. Windows was not used for Bluetooth in this test, so it
could only be A.

| Direction | Result |
|---|---|
| A → B → C: A sent 10 while C was out of range; B held them; C came back into range | **10 / 10**, each once; B handed them over 7 s after C was back, all in C's inbox within 11 s |
| C → B → A: C sent 10 over Bluetooth to B; A collected them from B | **10 / 10**, each once |

The A-B link in this step was the home network, not the internet. Source: B's log (held, handed
over), C's and A's inbox counts.

### 5. Groups (lab)

A three-member group with the MacBook (on the hotspot) as admin:

| Check | Result |
|---|---|
| The group appears on every member without an accept step | pass |
| 5 messages from each member | pass: each "delivered to 2 of 2", each received exactly once, in order |
| One member's node stopped 3 minutes while others sent 3 each | pass: 3 / 3 + 3 / 3 arrived after it came back (some through a friend's custody), nothing sent again |
| The terminal app's group view | pass |

A second group in the final check: delivered to 2 of 2. Source: senders' group status, receivers'
group view.

### 6. Adding a new contact while away

A new, throwaway identity on the MacBook (on the hotspot) gave its card to the Windows laptop at
home. The person read the ten security words aloud and the Windows laptop checked them.

- Before the check, sends to it were refused at once and nothing was dialled. Its Tor connections
  were refused because it was not verified yet.
- After the check: 3 / 3 from the new contact arrived over Tor, each once, with nothing done on the
  receiving side.
- Sending to the new contact found a bug: verifying the contact dropped its onion address, so Raven
  did not try Tor until a Tor-only send. Fixed in the final build; checked only briefly since.

### 7. Earlier rounds on one network

Before the internet steps, six rounds of fixes ran with all three on the home network, using the
desktop apps and the terminal app. Messages went over LAN direct in about 1-5 s with signed
receipts; the Windows laptop alone sent 55 messages and all were delivered. No duplicate and no
wrong order was seen in any round.

### Exactly once and in order

No message was lost and none was shown twice in any counted step after the Tor carrier existed.
Two smaller things were seen: a sender's outbox listed some group messages twice (the receiver
dropped the copy; fixed), and a sender left each receipt with a keeper about three times (the
keeper kept one of each; open, minor). Order was checked in the one-network rounds and in the
group steps and was right.

## Problems found

About 60 smaller problems (wording, layout, accessibility, keyboard use, times without a time zone)
were found and fixed in the one-network rounds alone. The larger ones:

| Problem | Status |
|---|---|
| macOS app window blank on most pages | fixed |
| macOS Local Network privacy silently blocked sends from a node started without that permission | the cause is now named in the app and the log; it is an operating system permission |
| A first message to a friend who was away was given up | fixed: it retries while the friend answers; with the lab horizon it waits up to 7 days |
| A friend refused as a stranger right after a start or unlock (the contact book was still loading) | fixed |
| Route-hint messages between two friends about twice a second | fixed: at most once per friend per minute |
| Waiting messages took about 70 s after a friend came back | fixed: any sign of the friend sends what waits |
| "Use the new address" forgot a friend's other routes | fixed |
| Windows: "Access is denied" on the LAN listener after unlock | fixed |
| Across networks without Tor: nothing crossed (see section 2) | led to the Tor carrier and address discovery |
| Tor did not start on Windows (a time library looped on the Windows clock) | fixed (patched dependency) |
| The desktop engine did not know the Tor carrier | fixed |
| Friend custody did not use Tor | Tor added to custody; not measured separately (section 3) |
| A refused LAN connection made every following send to a stopped friend try all paths again (15-23 s each) | fixed and re-tested: later sends queue at once |
| One slow Tor circuit made the next sends leave Tor out | fixed in the final build, not re-tested at volume |
| Verifying a new contact dropped its onion address | fixed in the final build, checked briefly |
| The onion service was **unreachable for 11-24 % of a long idle night** on two computers ("descriptor upload timed out"), each time coming back by itself | **open**. Raven now checks its own onion service and keeps an outage history, so this is visible in `raven status`; the cause is not known yet. |
| The onion service took from about 10 seconds to 9 minutes to become reachable after a start | **open** |
| Senders still dial a friend's old LAN address first after the friend moved to another network | partly fixed (it no longer keeps Tor out); the wasted dial is open |
| In a step without Tor, messages to a computer behind a second router (it can dial out but cannot be dialled) waited 1-2 hours, until Tor was on again | **open**: waiting mail is not yet handed over on the links that computer opens itself |
| macOS: the Bluetooth helper was stopped by the privacy check, then crashed in a debug build | fixed |
| Many "why is it waiting" texts gave LAN advice when Tor was the real path | mostly fixed; some wording open |

## What this test does not show

- Release builds: everything above except LAN direct is switched off in them.
- More people, more networks, other countries, networks that block Tor, enterprise networks.
- Linux, and phones of any kind.
- A long run: the longest continuous node run was about 8 to 9 hours, the longest counted soak 6
  hours.
- An independent security review: nobody outside the project has reviewed the code or the test.
- Signed or notarised packages: every build was a local debug build.

If you can run a similar test on your own computers, please do and send a report
([field test report template](../.github/ISSUE_TEMPLATE/field_test_report.md)). Never post
addresses, network names, onion addresses, cards or security words in it.
