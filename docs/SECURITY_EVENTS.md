# Security events: the local code registry

> **Local codes, not wire.** These numbers name events inside one Raven installation: in memory,
> in its own security ledger and in its own `raven status`. They are never sent to anyone, never
> put in a frame, a route hint, a log line with a key or an address, or any IPC answer other than
> the local `Status`. No `PROTOCOL_VERSIONS` row or freeze hash covers them.
>
> **Status (P6.52, 2026-10-24): built, behind shut gates.** Every kind in the registry but 78 is
> raised by lane 6b's code (P6.21-P6.51), and only while `SECURITY_EVENTS_PRODUCTION_ENABLED` (still
> `false`) is live; the automatic responses run only while `SECURITY_RESPONSES_PRODUCTION_ENABLED`
> (still `false`) is live too. While the first gate is closed nothing is noted or written and
> builds behave byte for byte as before. The registry dates from Phase 6 P6.1 (2026-10-22); the
> paragraphs below say what each step added. None of these events can show that someone is only
> listening: passive listening sends nothing, so nothing here detects it
> ([`THREAT_MODEL.md`](THREAT_MODEL.md) §3.17).
> Since P6.22 the pure core is in `raven-core/src/security_events.rs`: the kinds with these codes
> (a test reads this table), the thresholds, the in-memory aggregator, the stranger penalty box
> and the classifiers. Still nothing raises an event.
> Since P6.23 the ledger is in `raven-core/src/security_ledger.rs`: `security_events.sqlite`, keyed
> and sealed from its first version (`docs/design/2026-10-at-rest-metadata.md` section 7.7), only in
> a sealed profile and only while the events gate is live; at most one write per kind and subject a
> minute; network sources only as a count per kind and day.
> Since P6.24 raven-node raises the link-layer kinds while the events gate is live
> (`raven-node/src/security.rs`): 1 (a tag failure once the peer is known; before that it is 3),
> 2-6 (noted by the accept loop against the source), 8 (the p2p peer gate, by remote IP, never a
> PeerId), 29 (another key at a contact's address, the M0 stop included) and 46 (a relayed p2p link
> that broke inside). Its sink writes the ledger from one thread; network events go in as hourly
> counts, so a stranger's connection costs no write. `Status.security` reports memory-only counts.
> Since P6.25 the session, contact and custody paths raise theirs (`raven-core/src/security_sense.rs`
> and the modules it names): 20-26 and 34 from session-store refusals of a contact's message or
> ACK (on its link, on a dial's ACK, or fetched from a custodian), 25 and 31 from a contact's link
> frames, 27 (a refused key change in the CLI or the terminal app's NAME-CLASH), 28 (a prekey the
> pin refuses), 32 (a PairInit over the claim quota), 33 (the reset loop hold, once per hold),
> 40-42 (a custodian's junk, unrequested items and objects served again after release), 43-44 and
> 48 (a custodian's refusals of a contact's requests; 48 also a forward of ours refused), 47 (a
> bad letter: the custodian's when its signature fails, the sender's when it verified), 49 (a
> failed nearby knock, against the pipe's radio source) and 60 (rollback found by the session
> store, or sealed at-rest bytes that fail authentication). ash writes its events straight into
> the ledger (`DirectSink`) while the gate is live.
> Since P6.26 the first response (R1, only while the responses gate is live too) is the stranger
> penalty box in raven-node (`raven-node/src/security.rs`): one per process, memory only, at most
> 4,096 sources. The listed strike weights count against the source's address from the LAN and
> Internet listeners (2-5, and a source at its own connection cap: 1), the p2p peer gate's inbound
> refusals (8) and the LAN beacon answerer (9: a replay; 10: a query over its source's rate, 1).
> 16 in a minute ban the source for 60 s, doubling up to 1 h; the listeners refuse it save one
> probation connection per 10 s (a contact that authenticates on it clears the source), the p2p
> peer gate refuses it before Noise (a contact it admits on a direct inbound connection clears the
> source too), and the beacon answerer does not answer it. A source on the local network
> (link-local, unique-local, or inside a prefix of this computer's networks) at the LAN listener or
> the beacon answerer is its whole address (every link-local host shares fe80::/64 and every SLAAC
> host one LAN's /64, so one stranger on the Wi-Fi must not get its neighbours banned); any other
> IPv6 source is its /64: at the Internet listener, at the p2p gate, and a global one from outside
> the local network at the LAN listener, which takes dials from anywhere before they authenticate
> (Phase 6 review sensing-2, its re-verify, and sensing-7). Each ban is one 7
> (a day count). The p2p responder's and the nearby pipes' sources are keys, not addresses: they
> are never struck (49 stays a Notice). Loopback is never banned unless the debug switch
> `RAVEN_LAB_SEC_PENALTY_LOOPBACK=1` says so. `Status.security.bans_active` counts the bans.
> Since P6.27 raven-node answers R2 and R3 (the responses gate, and `node_policy.security_auto_rekey`,
> default on): 20 and 22 about a contact, and its third 23 within an hour, note an early re-key
> (`session_renewal::request_early`, at most one per contact per 6 h, within the shared re-pair
> budget of 4 a day); the renewer renews on the next live link (role `early`), retires the older
> sessions for sending (`SessionRetireCause::LocalSecurityRekey` = 7, so the reset step re-seals
> what waited in them; only while the reset step is live, and a session still holding messages is
> retired only when the reset step can re-seal them) and they take the contact's objects for 10
> more minutes; then the contact's SESSION_QUERY about an object sealed in one is answered
> NO_SESSION, so the contact re-seals it, and a custodian's copy of one is released (Phase 6 review
> sensing-1). 60 rotates this computer's
> prekey (`lan_dispatch::rotate_local_prekey_now`) and notes an early re-key for every contact with
> a live session, at most once per 6 h. Each answer writes its alert's action (`REKEY_REQUESTED`,
> `PREKEY_ROTATED`). Only a contact's signature or this disk raises these kinds, so no third party
> can spend the budget; nothing is ever blocked, unpinned or removed (a source scan checks it).
> Since P6.28 raven-node also answers R4-R8 (the responses gate only; each ends by itself and writes
> its alert's action): 1 at Suspicious puts that contact's routes over that carrier last on this
> network for 10 minutes, behind friend custody when custody may carry the message (R4,
> `PATH_DEMOTED`; memory only); 29 at Suspicious forgets the learned LAN address another key answered
> at (`lan_seen` and the learned LAN part; the address saved in the contact book stays) (R5,
> `ADDRESS_FORGOTTEN`); 40, 41 and a custodian's 47 are strikes, the third within a day parks the
> custodian for a day, which only `raven outbox retry` lifts (R6, `CUSTODIAN_PARKED`); a depositor's
> tenth refused object (44) within an hour makes the custodian answer RATE_LIMITED to its deposits
> for an hour (R7, `DEPOSITS_THROTTLED`; memory only; a depositor's own object or letter dated
> further ahead than the clock skew allows is its clock, 34, and never counts: Phase 6 review
> sensing-5); 45 (a relayed dial without a receipt while
> the same contact's came over another path within an hour; Suspicious when more than half of the
> relay's last 10 such dials went that way) and 46 at Suspicious put the relay last in circuit order
> for an hour, never out (R8, `RELAY_DEMOTED`). On a profile that learns (Phase 6a's learning live
> and on) the same events lower the relay's learned term instead, a full failure each, bounded like
> the term, and nothing goes last by hand (P6.28's merge amendment, landed with the main-line
> merge). Nothing new is stored: the per-relay counters, the throttle and the demotions live in
> memory only.
> Since P6.29 30 is raised against each contact's capability high-water mark
> (`raven_core::capability_floor`, R9; recording needs only the events gate): a verified hello's
> caps on Internet direct and p2p, the dialer's RLX1 caps on a LAN listener and the listener's RRH1
> on a LAN dialer raise the mark (the LAN showings only ever raise it); a verified hello without a
> feature seen before is a downgrade at that feature's level (route hints or update exchange a
> Notice, padding or the knock Suspicious), noted at most once a day per contact and feature
> (padding only while it is live on this node: PAD1 needs both sides; Phase 6 review sensing-3);
> the link is never refused. A session profile offered below the contact's floor is an Alert, refused
> only while `SUITE_FLOOR` is live too (`require_profile`; profile 1 is the only one today, so
> nothing is refused yet). Nothing lowers a mark by itself: only `raven contact verify` after a
> security-words match and a typed `accept`, and removing the contact forgets it. The marks are
> sealed at rest (`capability_floor.json`, kind 11).
> Since P6.30 the CLI shows them (`ash/src/security_cli.rs`; the texts are one English table in
> `ash/src/security_text.rs`, for the terminal app too from P6.31): `raven security` lists the open
> alerts and warnings (Alert and Suspicious rows, the most severe first; Notice rows are only
> counted) with what happened, what Raven did (the alert's action code in words) and what to do,
> and marks them seen; each has its own number N, which stays the same while it is open (Phase 6
> review sensing-6: a position would shift as notices are noted, refreshed or resolved);
> `explain N` adds when, the counts per day, whom it is about (a verified friend's key as an
> 8-character prefix only) and the code; `resolve N` closes that one; `clear` deletes
> every row after a typed `clear` (or `--yes`); `--json` is `{"v":1,...}` for each. With the events
> gate shut it says "Security notices are not part of this version." and exits 0; no command
> creates the ledger by reading it. `raven status` has a SECURITY section only while an alert or a
> warning is open (with the strangers the running raven-node refused in the last hour, else that
> count alone as a row), `raven doctor` a `security` row with how many are open and what to do,
> `raven send` one note (on stderr) when the contact has an open Alert, and the send goes ahead. A
> match in `raven contact verify` (the words or the old code; at a terminal a verified contact with
> an open alert or warning is checked again) resolves every open row about that contact; when a
> capability downgrade (Suspicious and up) about it was open, or its floor holds one, the person
> may accept the older method there (the words and a typed `accept`).
>
> Since P6.31 the full-screen terminal app shows the same rows in the same words (read through
> `tui/bridge.rs`, once a minute and after a change; reading never creates the ledger): the header
> chip `⚠ n` (ASCII `!n`) while alerts or warnings are open; the alarm as a friend's badge (over
> the unread count and "not verified"); a banner over the open friend's conversation with the
> headline and `[V] Compare words  [D] Details  [P] Pause sending`; SEC (W on Home, the friend page
> and NET; D on a friend) lists them with what happened, what Raven did, what to do and, on D, the
> details, R resolves one and V compares words; NET has a Security group (open alerts, the
> strangers raven-node refused in the last hour, the sources it refuses for now, the notices only
> counted, whom sending is paused to); the friend page has a Security row (the problems the last 7
> days counted). VF for a verified friend checks again (at once while a notice about them is open,
> else Enter on "Already verified"): a match resolves their rows, and where the older method may be
> accepted it asks for a typed `accept`. "Pause sending" (P, the same key undoes it, never
> automatic) is `node_policy` `send_hold`: raven-node's outbox worker holds everything for that
> contact with the code `SENDING_PAUSED` and the app's composer sends nothing to them until the
> person resumes it.
> Since P6.34 the links pad with PAD1 while link padding is live (`raven-node/src/link.rs`,
> `protocol/RAVEN_LINK_PADDING_V1.md`): a contact's frame that breaks PAD1 on a link that agreed it
> (a bare frame after its first padded one, or a padded frame that breaks a rule) closes the link
> and is 31 about that contact, on its inbound link or on our dial (never before the link knows
> who it is); a LAN dialer that read the listener's first padded frame raises that contact's mark
> for padding (30's high-water mark, as a showing that is never a downgrade by itself).
> Since P6.35 the LAN and Internet direct listeners raise 11 while the link knock is live
> (`raven-node/src/link_knock.rs`, `protocol/RAVEN_LINK_KNOCK_V1.md`): a matched knock nonce seen
> before (a cache of 4,096 nonces kept 3 days, one per process and kept in the profile across
> restarts) is a replay about the network
> source, answered as no match and struck 4 by the penalty box. A dialer that stops before Noise
> message 3 because a contact whose mark shows the knock answered without a proof raises 29 with
> M0's text. Each link's real knock goes to the contact's capability mark: a direct link without
> the knock after one with it is 30 at Suspicious.
> Since P6.38 35 is raised while pair seeds are live (design B §5, `raven_core::pair_seed`,
> `RAVEN_ROUTE_HINTS_V1.md` §14): a contact's LAN beacon query, RLK1 knock or Bluetooth token matched
> only with the pair's static root while this node expects the contact's seed (it sends with a seed
> the contact acked, or as a follower it saw the leader use one). A Notice, only counted, about that
> contact on its link (the beacon and the knock: `DirectLink`; a Bluetooth pipe this node dialled:
> `Dial`); nothing is refused, since the root is the fallback that keeps friends from being locked
> out, and the next link agrees on a new seed.
> Since P6.40 raven-node raises 61 (about this computer) for each wrong Raven passphrase at
> `raven unlock` while Lock v2 is live (`raven-node/src/lock.rs`); each also lengthens the wait
> before the next try (1 s, doubling up to 60 s), and the unlock that ends the lock says how many
> there were.
>
> Since P6.44 the update state raises 70-72, 74 and 76 while the advisory gate is live
> (`raven-core/src/update_state.rs`): an advisory or a log snapshot that fails its check is 70, one
> older than the newest known (the build's compiled floor included) is 71 and is ignored, two
> advisories with one serial (or a broken chain) are 72, an advisory its log does not list is 74,
> and two signed logs that are not prefixes of each other are 76; 72 and 76 freeze the update state
> (both pieces kept as evidence). Each is about the update, "passed on by" the friend who handed it
> over (or none for a file the person imported), and noted after the state file is written. A
> refused bundle's 73-76 go through the same helper (`note_bundle_refusal`) once bundles are read
> (P6.47). Accepting one raises nothing yet (77 is P6.45's).
> Since P6.45 storing an advisory raises 77 (an informational alert, "passed on by" whoever handed
> it over), and its entries apply (`raven-core/src/suite_policy.rs`): a BROKEN suite refuses with
> the local codes `SUITE_BROKEN` and `SUITE_HELD`, which are no events themselves. `raven status`'s
> SECURITY section and the terminal app's SEC overlay show the notices' lines before the alerts.
> Since P6.47 `raven update import` and `raven update install` note a refused release bundle
> through `note_bundle_refusal`: a forged or unsigned manifest, a bad log, payload, chunk or file
> hash is 73, a release or notice its log does not list 74, an older build or one below the
> release floor 75, a split view 76 and a notice in the bundle that fails 70, "passed on by" nobody
> for a file the person imported. `raven update verify` notes nothing.
> Since P6.49 raven-node's update exchange (`raven-node/src/update_exchange.rs`, RUP1) puts what
> friends pass on through the same checks, "passed on by" that friend: a notice or log that fails
> is 70-72, 74 or 76 as above (a forged notice also goes to quarantine and that friend is not
> asked for a day), a forged chunk is 73 and a refused manifest 73-76 (quarantined; that friend is
> not asked for that release again). 78 (`SEC_UPDATE_FLOOD`) is registered, but nothing raises it
> yet: RUP1's quotas answer `RATE_LIMITED` or `BUSY` without an event.

Each code is fixed forever once a build that raises it is released: a code is never reused for
another kind, and a retired kind keeps its number. Ranges:

| Codes | What is attributed | Notes |
|---|---|---|
| 1-19 | A network source (memory only; the ledger keeps one count row per kind and day) | `admission_key(ip)`: v4 /32, v6 /64; never stored |
| 20-39 | A verified contact (its device key) | contact-attributed kinds need the contact's signature |
| 40-59 | A carrier: a custodian, a depositor or a relay | relays as `SHA-256("rvn1/sec/relay" \|\| PeerId bytes)` |
| 60-69 | This computer's own state | |
| 70-79 | Security updates (design D) | "passed on by", never "blamed" |
| 80-92 | Phase 6c (its own plan) | reserved; re-checked when 6c starts |

## Registry

Severity is one of Notice, Suspicious, Alert. "NET row" is the network section of `raven status`
and the terminal app; "friend page" is that friend's page; "banner" is an alert banner. The
responses (R1-R9) are Phase 6b design A's and run only while the responses gate is open.

| Code | Kind | Attribution | Default severity | Alert rule | Automatic response (responses gate) |
|---|---|---|---|---|---|
| 1 | SEC_LINK_TAG_FAIL | Contact path + network | Notice; Suspicious at 2 per contact per 10 min; Alert at 6 per 24 h on one network | NET row; banner at Alert | R4 path demotion |
| 2 | SEC_HANDSHAKE_FAIL | Network | Notice | none | R1 strike 1 |
| 3 | SEC_PREAUTH_MALFORMED | Network | Notice | none | R1 strike 2 |
| 4 | SEC_STRANGER_REFUSED | Network | Notice | NET count | R1 strike 1 |
| 5 | SEC_BLOCKED_REFUSED | Network | Notice | NET count | R1 strike 1 |
| 6 | SEC_UNVERIFIED_REMOTE | Network | Notice | none | none (it is a contact) |
| 7 | SEC_PREAUTH_FLOOD | Network | Suspicious | NET row | R1 ban |
| 8 | SEC_P2P_GATE_REFUSED | Network | Notice | NET count | R1 strike 1 |
| 9 | SEC_BEACON_REPLAY | Network | Suspicious | NET row | R1 strike 4 |
| 10 | SEC_BEACON_FLOOD | Network | Notice | none | R1 strike 1 for a source over its own rate (like a listener's cap refusal; the global limit strikes nobody) |
| 11 | SEC_KNOCK_REPLAY (design B) | Network | Suspicious | NET row | R1 strike 4 |
| 20 | SEC_OBJECT_AUTH_FAIL | Contact | Suspicious; Alert at 3 per 24 h | banner | R2 re-key |
| 21 | SEC_OBJECT_SIG_FAIL | Contact (direct link only) | Suspicious; Alert at 3 per 24 h | banner | none |
| 22 | SEC_OBJECT_REPLAY | Contact | Suspicious; Alert at 3 per 24 h | banner | R2 re-key |
| 23 | SEC_INDEX_JUMP | Contact | Notice | none | R2 when 3 per hour |
| 24 | SEC_SESSION_UNKNOWN | Contact | Notice | none | existing session reset |
| 25 | SEC_BINDING_MISMATCH | Contact | Alert at 1 | banner | none |
| 26 | SEC_REVOKED_DEVICE_USED | Contact | Alert at 1 | banner | none |
| 27 | SEC_KEY_CHANGE_ATTEMPT | Contact (local import) | Alert at 1 | banner | none (pin kept, as today) |
| 28 | SEC_PREKEY_ROLLBACK | Contact | Suspicious | friend page | none |
| 29 | SEC_ADDRESS_IMPOSTOR | Contact + network | Notice; Suspicious at 3 per 24 h | friend page | R5 forget that address |
| 30 | SEC_CAPABILITY_DOWNGRADE | Contact | Notice (route hints, updates); Suspicious (padding, knock); Alert (session profile) | by level | R9 |
| 31 | SEC_CONTACT_MALFORMED | Contact | Notice | none | none |
| 32 | SEC_PAIRINIT_FLOOD | Contact | Suspicious | friend page | none (quota exists) |
| 33 | SEC_RESET_LOOP | Contact | Suspicious | friend page | none (loop hold exists) |
| 34 | SEC_CLOCK_SKEW | Contact | Notice | the "clocks differ" text (cutoff pack M11) | none |
| 35 | SEC_PAIR_SEED_ROOT (design B, pair seeds) | Contact | Notice | none | none (the root is the fallback that keeps friends from being locked out; the next link agrees on a new seed) |
| 40 | SEC_CUSTODIAN_BAD_OBJECT | Carrier (custodian) | Suspicious; Alert at 3 per 24 h | banner | R6 park |
| 41 | SEC_CUSTODIAN_UNREQUESTED | Carrier (custodian) | Suspicious | friend page | R6 strike |
| 42 | SEC_CUSTODIAN_REPLAY | Carrier (custodian) | Notice | none | none |
| 43 | SEC_DEPOSITOR_FLOOD | Contact (as depositor) | Notice | none | existing quotas |
| 44 | SEC_DEPOSITOR_BAD_OBJECT | Contact (as depositor) | Suspicious | friend page | R7 |
| 45 | SEC_RELAY_NO_RECEIPT | Carrier (relay) | Notice; Suspicious at more than half of 10 dials | NET row | R8 |
| 46 | SEC_RELAY_LINK_BROKEN | Carrier (relay) | Suspicious | NET row | R8 |
| 47 | SEC_LETTER_BAD (Phase 5 letters) | Carrier, or Contact when the signature verified | Suspicious | friend page | R6 |
| 48 | SEC_HANDOFF_REFUSED (Phase 5 handoff) | Carrier | Notice | none | none |
| 49 | SEC_KNOCK_FAIL (Phase 5 nearby RNK1) | Network (radio) | Notice | none | none (P6.26: a pipe's key is its contact's, so a stranger replaying a contact's token must not earn that contact a ban) |
| 60 | SEC_LOCAL_ROLLBACK | Local | Alert at 1 | banner | R3 |
| 61 | SEC_UNLOCK_FAILED (design C) | Local | Notice; Suspicious at 5 per 10 min | shown after the next unlock | unlock back-off |
| 70 | SEC_ADVISORY_FORGED | Update (passed on by a contact) | Suspicious | design D | design D |
| 71 | SEC_ADVISORY_ROLLBACK | Update | Notice | design D | design D |
| 72 | SEC_ADVISORY_EQUIVOCATION | Update | Alert | design D | design D |
| 73 | SEC_BUNDLE_FORGED | Update | Suspicious | design D | design D |
| 74 | SEC_UPDATE_UNLOGGED | Update | Suspicious | design D | design D |
| 75 | SEC_BUNDLE_DOWNGRADE | Update | Notice | design D | design D |
| 76 | SEC_LOG_SPLIT_VIEW | Update | Alert | design D | design D |
| 77 | SEC_ADVISORY_APPLIED | Update | informational alert | design D | design D |
| 78 | SEC_UPDATE_FLOOD | Contact | Notice | design D | design D |

Codes not listed (12-19, 36-39, 50-59, 62-69, 79) are unassigned.

## Rules for the code that raises them

- **One table.** The thresholds live in one `THRESHOLDS` table next to the kinds, with a unit test
  that every kind has a row.
- **No wildcard.** The classifiers that map an error to a kind match every variant without a `_`
  arm, so a new error variant does not compile until someone decides whether it is a security event.
- **No telemetry.** Nothing in `security_events`, the ledger or the responses reaches a frame
  encoder, an IPC answer other than the local `Status`, or a log line with a key or an address.
- **What is kept.** No IP address, port, message id, plaintext or stranger key, ever. Subjects are
  contact, custodian or relay keys only; times are hours (alerts) or days (counts); counts and
  resolved alerts are kept 30 days. The ledger is sealed at rest and registered with the at-rest
  registry like every other profile file (`docs/design/2026-10-at-rest-metadata.md`).
- **What the person reads.** English only. Say what happened, what Raven did and what the person can
  do; the harmless explanation first; never accuse a friend; every Alert ends with one concrete,
  reversible action. Alerts that ask to check a friend's key say "compare security words" (the
  security words design, `docs/SECURITY_WORDS.md`), never a digits-only code.
- **No automatic block.** Responses may re-key, demote a path, park a carrier or throttle a network
  source; they never block a contact by themselves.
