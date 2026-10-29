# DRAFT (unsigned): amendment to `WAIVER-LAN-DIRECT-2026-10-07` for Phase 3 (every interface, the LAN beacon, session renewal)

| | |
|---|---|
| **Status** | **DRAFT, not signed.** Nothing here is in force until the owner signs it. Until each flip commit, `LAN_AUTO_LISTEN_PRODUCTION_ENABLED` (`node/crates/raven-core/src/lan_gate.rs`), `LAN_BEACON_PRODUCTION_ENABLED` (`node/crates/raven-core/src/lan_beacon.rs`) and `SESSION_RENEWAL_PRODUCTION_ENABLED` (`node/crates/raven-core/src/session_renewal.rs`) stay `false`; debug builds open them with `RAVEN_LAB_LAN_AUTO=1`, `RAVEN_LAB_LAN_BEACON=1` and `RAVEN_LAB_SESSION_RENEWAL=1`, release builds never read those variables. |
| **Amends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) §2, §4, §5 and §6, next to its [P2a](WAIVER_LAN_DIRECT_P2A_AMENDMENT_DRAFT.md), [session reset](WAIVER_LAN_DIRECT_SESSION_RESET_AMENDMENT_DRAFT.md), [route hints](WAIVER_LAN_DIRECT_ROUTE_HINTS_AMENDMENT_DRAFT.md) and [cutoff](WAIVER_LAN_DIRECT_CUTOFF_AMENDMENT_DRAFT.md) amendments (none is edited) |
| **Not covered** | Friend custody, on the LAN or over the internet: its own draft [`WAIVER_FRIEND_CUSTODY_DRAFT.md`](WAIVER_FRIEND_CUSTODY_DRAFT.md). Everything in §5 below |
| **Decision** | One Phase 3 LAN amendment with three sections, (A) every interface, (B) the beacon, (C) renewal, instead of separate drafts (Phase 3 owner decision "renewal paperwork and scope"). Each section's gate is flipped on its own, in the order of §7 |
| **Design** | the any-network reachability plan (not published) §3 "Phase 3" items 1, 2 and 4 (components C8 and C9), decision D7; plan `docs/roadmap/plans/phase3-design.json` |
| **Wire** | (A) none. (B) [`protocol/RAVEN_LAN_BEACON_V1.md`](../protocol/RAVEN_LAN_BEACON_V1.md) and [`RAVEN_PRIVATE_RENDEZVOUS_V1.md`](../protocol/RAVEN_PRIVATE_RENDEZVOUS_V1.md) revision 4 §5.3a (not yet approved); vectors `shared-vectors/rvn1/lan_beacon/`. (C) none: an ordinary [`RAVEN_PAIR_INIT_V1.md`](../protocol/RAVEN_PAIR_INIT_V1.md) exchange |
| **User docs** | `INSTALL_macOS.md`, `INSTALL_Linux.md`, `INSTALL_Windows.md` ("Local network"); [`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md); [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) §4 |
| **Real rows** | an unpublished test checklist |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-22 |
| **Review by** | Same date as the LAN waiver (2027-01-07) |
| **Withdrawal** | Set the three consts back to `false` (§6) |

## 1. Why an amendment

The LAN waiver covers LAN direct TCP between two `raven-node` services, as the
installers set it up: listening on `127.0.0.1:7420` unless the user names an
address (hold B12 keeps LAN exposure opt-in). Phase 3 changes three things on
that slice: the installers' default listener becomes every local interface,
a new UDP datagram pair finds contacts on a new network, and the daemon
starts PairInit V1 by itself before a session ends. The waiver §6 makes
"extending the slice beyond §2 without a new waiver" a lapse condition, so
each change is written down here.

## 2. What changes on the covered slice (§2 amended)

The carrier (Noise XX bound to the Raven identity, the RLB1 offer), the
session profile (`ATSAM/indexed-session/v1`, RVNA1 `0x03` messages and sealed
ACKs), PairInit V1 and the contact gate are unchanged.

### 2.1 (A) Every interface, `raven lan off|on`, IPv6 zones (`LAN_AUTO_LISTEN_PRODUCTION_ENABLED`)

- **`--lan-listen auto`** listens on `0.0.0.0:7420` and `[::]:7420` (IPv6
  only on the second socket), and closes a connection whose source is not
  local before any byte is sent: local means loopback, RFC 1918, link-local,
  ULA, or on-link by this computer's own interface prefixes. 100.64.0.0/10
  (Tailscale, carrier NAT) is not local; such contacts keep an explicit
  `--lan-listen 0.0.0.0:7420`, which accepts any source (owner decision
  "`auto` listener source rule"). The contact gate still runs after Noise XX
  on every link, as today.
- **The installers** take their default from the installed binary
  (`raven-node lan-default`): `auto` once this gate is open, `127.0.0.1:7420`
  until then; an explicit `RAVEN_LAN_LISTEN` / `-LanListen` always wins. They
  print firewall lines for TCP and UDP 7420 (Windows: `-Profile Private` only)
  and never change the firewall. **This flip lifts hold B12 for `auto` only.**
  With the gate closed `auto` means exactly `0.0.0.0:7420` from any source
  (contacts only), as a bare `raven-node service` does today.
- **Ungated today, recorded here:** `raven lan off|on|status` (saved in
  `node_policy.json`, applied live: no listener, no beacon, no LAN dial),
  meeting mode (`raven lan on --for 1h`), verified-only on the LAN (`raven lan
  verified-only on|off`), a fail-closed read of an unreadable
  `node_policy.json` (LAN off, `raven lan on` rewrites it and keeps the old
  file as `.bad`), and IPv6 link-local zones kept in `lan_seen`, learned
  routes and typed addresses (`[fe80::1%en0]:7420`; a number on Windows).
  They only reduce exposure or fix correctness, so they ship in release
  without a gate (Phase 3 owner decision "gates").

### 2.2 (B) The solicited LAN beacon (`LAN_BEACON_PRODUCTION_ENABLED`)

- **What is sent.** A 160-byte query (a 16-byte nonce and 8
  indistinguishable slots: a 16-byte tag and the encrypted listener port) to
  UDP 7420 at 239.255.74.20 and the IPv4 subnet broadcast, or at
  ff02::8000:7420; a 48-byte answer, bound to the query's nonce and both
  IP addresses, sent to the same group on the arrival interface, never
  unicast. Each carries a random tail (0-31 bytes on a query, 0-15 on an
  answer) and goes out after a random 0-500 ms delay (the Phase 6b amendment
  of the spec, made before the flip). No datagram carries a constant byte, a
  version byte, an identity, a timestamp or a port in the clear (spec §3-§5).
- **Keys.** X25519 static-static over the Montgomery forms of the two pinned
  Ed25519 identity keys, one R2 pairwise root (HKDF-SHA256, salt
  `rvn1/r2-pair/v1`) with the LAN medium byte `0x02` (`0x01` reserved for
  Bluetooth LE nearby), directional keys, then a key per 600 s epoch (spec
  §2). Beacon keys are never a message, session, route, mailbox or ACK key.
- **When.** Only on a need: deliveries or owed ACKs waiting, custody rows
  waiting for their recipients, a user send (IPC `LanLocate`), and one join
  round per network or interface change while such a need or meeting mode
  exists (owner decision OD-C7), naming at most 8 contacts with an
  authenticated inbound LAN link in the last 7 days. Never a periodic
  presence beacon. Never on AWDL/LLW, utun/point-to-point or loopback.
- **Who answers.** A node answers only a querier that its LAN link gate
  would admit (the same `link_admission` check); unverified contacts take
  part on the local network only, and `raven lan verified-only on` keeps them
  out.
- **Limits** (starting values, to be re-checked after R1, R11 and R24): epoch
  600 s, window plus or minus 1, 8 slots; per-contact interval 15 s doubling
  to 10 min; 4 global rounds refilled 1 per 3 s; an answerer answers 1 per
  2 s per source and 10 per second in total; at most 1024 contacts and 8
  interfaces.
- **Results.** A candidate is untrusted, kept in memory for 10 minutes, never
  saved to `contacts.json`, `lan_seen.json` or `learned_routes.json`, never
  forwarded, and dialled first among LAN routes (at most 2). Noise XX and the
  RLB1 bind decide everything after it.

### 2.3 (C) Daemon-started PairInit V1 renewal (`SESSION_RENEWAL_PRODUCTION_ENABLED`)

- **What it is.** On a live, endpoint-authenticated link with a contact (LAN,
  and Internet direct or p2p only while their own gates are open), raven-node
  starts an ordinary PairInit V1 while the newest session with that contact
  still has time left, so a message queued for a contact who then leaves
  keeps almost a day. Today only `ash send` and the gated reset step start a
  PairInit.
- **Who renews.** The side that did not start the newest session, below 12 h
  left; the other side below 10 h (a contact that cannot dial, runs an older
  build or has the gate off). After the last session ended, within 14 days:
  the smaller device key first, the other side 10 minutes later. Whoever
  renews dials. Unverified contacts renew over the local network only.
- **Caps.** One automatic re-pair budget per contact, shared with Phase 5's
  horizon re-pair: 4 rounds per 24 h, 60 s apart, counted durably before the
  PairInit exists; failures back off 30 min, 1 h, 2 h, 4 h; at most 6
  renewals per 10 minutes in total. Renewal, the reset step and the app
  channel's own budget together stay below the responder's 32 claims per
  initiator (a compile-time check). A contact with no route that may carry a
  PairInit costs nothing (`RENEW_NO_ROUTE`).
- **A lost PairResponse.** The pending PairInit is kept and resent byte for
  byte (PairInit V1 §6 makes that idempotent): 2 quick resends 5 s apart,
  then on the next live link until it expires or something newer is
  confirmed. No RSR1 or PairInit change (owner decision "lost PairResponse").
- **What it never does.** It never re-seals and never retires: queued
  messages keep their session and deadline, and the old and new sessions
  overlap until the old one expires (both sides pick the newest the same
  way). It yields to the session-reset step while retired rows wait for a
  re-seal, carries `reset_round = false` (it never counts toward the reset
  step's rounds or cooldown), and stops on fork evidence, a reset loop or a
  prekey pin refusal.
- **Unchanged lifetime and exposure bound.** A session this node starts
  still lasts 24 hours and an envelope never outlives its session; renewal
  makes a new session, it never extends one. Normally two sessions per
  contact overlap (the old one until it expires, the renewed one).

## 3. What does not change

- No new carrier, no TCP port, no change to Noise XX, RLB1, RRH1,
  `RavenEnvelopeV1`, PairInit V1, the indexed-session profile or the ATSAM
  endpoint transaction. The beacon's UDP 7420 socket exists only while its
  gate is open; a node without it binds none.
- Who is admitted is unchanged: the local contact book behind the Noise to
  RLB1 identity bind. Old peers bind no UDP 7420, so their contacts' queries
  go unanswered, and they answer a renewal PairInit as any PairInit.
- With all three gates closed, a release build listens where the installer
  or the user put it, sends no UDP and starts no PairInit by itself.
- Logs carry counts only: no address, key, name or tag.

## 4. Residual risks added (on top of waiver §4)

1. **(A) Active probers read the stable Noise static key** (decision D7).
   Anyone on the same network who connects to TCP 7420 gets the responder's
   Noise static in message 2 before the contact gate runs, and can use it to
   recognise the device on other networks. A passive observer cannot read it.
   Rotation is deferred to Phase 4 with PeerId rotation (D14). Mitigations
   meanwhile: `raven lan off` on untrusted networks, the local-source rule,
   firewall rules for the Private profile only.
2. **(A) Listening on every interface** widens where that probe works: every
   local network the computer joins, IPv6 link-local included, instead of the
   one address a user typed.
3. **(B) A fixed software fingerprint.** UDP 7420 to 239.255.74.20 or
   ff02::8000:7420 with 160- and 48-byte payloads tells an observer that a
   Raven node is on the network (R2 revision 4 §5.3a accepts it; hiding inside
   mDNS stays deferred).
4. **(B) Query and answer timing.** An observer who sees a query and the
   answer that follows within 3 s learns that two devices on this network
   know each other, and when one of them had something to deliver. Nothing
   names them.
5. **(B) No forward secrecy for beacon keys.** They are static-static: who
   later obtains either identity key can recompute past tags and ports from a
   recording and link the two devices to those rounds. Messages stay sealed.
6. **(B) Identity-key reuse.** The Ed25519 identity key is also used, in its
   Montgomery form, for X25519. Under the collapsed device tier (waiver §4.3)
   this is one more use of the same key; the independent crypto review of the
   static bootstrap (R2 §14 item 4) is a precondition of the beacon flip.
7. **(B) R2 revision 4 is not yet approved.** The beacon implements a draft
   revision of Private Rendezvous V1, and Swift parity with the vectors is not
   shown in this tree.
8. **(C) More sessions and more claims.** Renewal keeps a session alive with
   every contact you link to regularly, custodians and relays included: about
   2 PairInits a day per pair and about 1 responder claim per contact. That is
   far below the 32-per-initiator cap, but about 500 continuously linked
   contacts would reach the responder's global cap of 512.
9. **(C) Session state over time.** Each session still ends after 24 h, so
   whoever obtains a device's session state reads at most what its stored
   sessions protect (waiver §4.1); renewal means such state exists for every
   regularly linked contact without a gap, instead of only after a send.

## 5. What stays held

- Friend custody on any carrier (its own draft), route hints (their own
  amendment), Internet direct on 7422 and p2p (their own records).
- A user-facing `raven contact renew` (owner decision: not now).
- The cutoff pack's two gates (`LAN_NOISE_PIN_PRODUCTION_ENABLED`,
  `OFFLINE_LAN_PRODUCTION_ENABLED`) under their own amendment.
- Noise static or PeerId rotation (Phase 4), Bluetooth nearby (Phase 5), mDNS.

## 6. Conditions and rollback (§6 amended)

On top of waiver §6, each section lapses, and its gate MUST be set back to
`false`, if:

- (A) the `auto` listener accepts a non-local source, or an installer
  changes a firewall by itself or binds beyond loopback while this gate is
  closed;
- (B) a beacon datagram carries a constant byte, an identity, a timestamp or
  a port in the clear, a node answers anyone the LAN link gate would not
  admit, candidates are stored or forwarded, or the beacon sends without a
  need (a periodic presence beacon);
- (C) renewal re-seals or retires a message, counts as a reset round,
  exceeds the shared re-pair budget, or extends a session beyond 24 h;
- any of C27-C31, s04 or s80-s85b is disabled, or fails on any of its runners
  for more than one release.

Rollback is the const set back to `false` in its own commit: (A) the
installers fall back to `127.0.0.1:7420` at the next install and `auto` to
`0.0.0.0:7420`; (B) no UDP socket is bound; (C) no PairInit is started by the
daemon, and sessions already made stay valid until they expire.

## 7. Evidence and flip order

Evidence before signature (all open until recorded; none of it replaces the
real rows):

- **carrier_matrix** (`node/crates/raven-node/tests/carrier_matrix.rs`,
  ubuntu, macOS and Windows): C27 `auto` on both families refusing non-local
  sources, C28 `lan off` and `on` live, C29 the beacon over real multicast,
  C30 strangers and old peers, C31 a session renewed near its end with waiting
  messages keeping a day.
- **lan_fault_matrix** (`scripts/lan_fault_matrix.py`, macOS and Linux)
  green 5 times: s04 (with `RAVEN_FAULT_BEACON=1`, no route hints), s80-s84
  (both move, a quiet receiver's DHCP move, the capture has no marker, `lan
  off` and `on`, unverified contacts), s85 and s85b (renewal and its
  fallback); also s86-s89 (meeting mode, the clock hint, hotspot isolation,
  the weekly port).
- **netns** (`node/scripts/netns_nat_dcutr.sh`, Linux, advisory): `lan-move`,
  `lan-ll`, `lan-isolated`, `lan-nonlocal`
  ([`NAT_SOFTWARE_SIM.md`](NAT_SOFTWARE_SIM.md)).
- **Vectors:** `shared-vectors/rvn1/lan_beacon/` recomputed by the Python
  reference (`raven_protocol/lan_beacon.py`) with the same bytes as Rust;
  [`PROTOCOL_FREEZE_HASHES_V1.md`](PROTOCOL_FREEZE_HASHES_V1.md) checked.
- **Release inertness:** the release-mode CI step (`inert`, `production_flag`)
  green.
- **Real rows** (an unpublished test checklist):
  R1, R1b, R11a-f and R21-R24.

Flip order, each in its own reviewed commit, after signature:

1. `LAN_AUTO_LISTEN_PRODUCTION_ENABLED` after signing (section A);
2. `SESSION_RENEWAL_PRODUCTION_ENABLED` after signing (section C); optionally
   with one informative paragraph in `RAVEN_PAIR_INIT_V1.md` §4 on the
   exact-bytes resend, and regenerated freeze hashes;
3. `LAN_BEACON_PRODUCTION_ENABLED` only after R2 revision 4 is approved, the
   crypto review of the static bootstrap (R2 §14 item 4) is done and Swift
   parity with the `lan_beacon` vectors is shown (section B).

## 8. Signature

Not signed.
