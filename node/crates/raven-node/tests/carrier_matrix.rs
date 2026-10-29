//! Portable multi-process carrier harness (transports design 2026-10 §6.4).
//!
//! Real `raven-node service` daemons and the `raven` CLI on loopback, each
//! profile in its own temp data dir with the documented debug lab backends
//! (`locked-file` identity / session / prekey; chat history uses the lab key
//! on Unix and real DPAPI on Windows). Rust instead of bash so the same test
//! runs on ubuntu, macOS and Windows (named-pipe IPC there).
//!
//! - **C1 LAN direct:** A and B on 127.0.0.1, mutual contacts, one `raven
//!   send` each way, each delivered (sealed ACK back) and in the other inbox.
//!   A's `raven status` then has a LAST DELIVERY row for bob, `same network
//!   (LAN)`, with no address or port, and no REACHABILITY section; `raven
//!   doctor` says `reach_class: off` (no p2p host) and counts the last paths.
//! - **C3 contact gating (F4):** stranger S, who has B as a contact but is not
//!   B's contact, dials B. B closes before it identifies itself: S's send fails
//!   with `LINK_NOT_ACCEPTED`, B logs only the key-free reason, and S never
//!   received B's RLB1 (S would have cached B's certificate, since B is S's
//!   contact).
//!
//! - **C2 Internet direct (P1):** A and B with Internet direct listeners (A on
//!   127.0.0.1, B on [::1] when the runner has IPv6 loopback) and contacts that
//!   hold only Internet routes (one imported from a `raven whoami --card`, one
//!   set with `raven contact set-addr`). `raven send --carrier auto` (the
//!   default) reaches each other over Internet direct, names the carrier only in
//!   verbose mode, and a stranger holding B's card is refused before B
//!   identifies itself. Runs under the debug lab unlock (`RAVEN_LAB_TEST_A=1`)
//!   while `INTERNET_DIRECT_PRODUCTION_ENABLED` is false, and without it once
//!   the flag is flipped.
//!
//! - **C4 outbox restart (P2a):** A and B on loopback with a confirmed session.
//!   B goes down, A sends (queued: `raven send` ends at once and says raven-node
//!   keeps trying), A's service is killed, B stays down a few seconds, then
//!   both restart (A first, B on its old port). A's rebuilt outbox delivers the
//!   exact staged bytes with no new `raven send`: `raven outbox status` and the
//!   history say delivered, and B's inbox holds the message exactly once.
//!
//! - **C7f app channel beyond the LAN (RDAP addendum):** C7a's no-session
//!   pairing over p2p, with no relay. A's book holds a LAN and an Internet
//!   address for B ahead of B's p2p route, each a port that closes every
//!   connection at once; B's book for A is p2p only, and A's card names no
//!   address. A's `lab app-submit` probes both dead routes and pairs on p2p
//!   (its probe line `lan_dial <code>, internet_dial <code>, p2p_dial
//!   offer`), the payload is delivered on `p2p_dial` and served by B; B's
//!   answer rides A's connection (`reversed`) with no probe of B's (it holds
//!   the session). Neither body reaches chat, and no log names a PeerId.
//!
//! - **C11 network change (G1):** A's netwatch reads a debug lab event file
//!   instead of the OS (`RAVEN_LAB_NETWATCH_EVENTS`); B's runs the real OS
//!   watcher (if-watch), which must open on every runner. B goes down, A's
//!   queued message backs off for a few attempts, then A's "network" changes:
//!   exactly one `network changed` line, an immediate retry on a fresh backoff
//!   (the next wait is 5-7.5 s again), and delivery exactly once when B is
//!   back. An optional Linux check (`RAVEN_HARNESS_REAL_NETCHANGE=1`, sudo)
//!   adds an address on a dummy interface and expects the real netlink path
//!   to report it; it runs alone (every daemon on the host sees that change),
//!   the other tests wait for it and it for them.
//!
//! - **C6 forced relay (P3):** a dedicated relay R (`raven-node relay`, no
//!   Raven identity) whose allow-list holds A and B; A and B run the service
//!   with the libp2p host on and no listening port at all (`--p2p-listen
//!   relay`, retired since Phase 1 and kept here by the debug
//!   `RAVEN_LAB_P2P_RELAY_ONLY=1`: `host up (listeners=0`, no `retired`
//!   line), so they are reachable ONLY through their reservations on R and
//!   can never hole-punch, and they reach R through a recording TCP proxy in
//!   this test. They pin each other from `raven-card/2` cards (`p2p=` +
//!   `via=`), and A→B (`--carrier p2p`) and B→A (`auto`) are delivered over
//!   the circuit, each exactly once.
//!   Everything the proxy saw (all relayed bytes) holds no PairInit or RLB1
//!   magic, no message text and no Raven identity bytes. A stranger S with
//!   B's card is not on the allow-list: R's peer gate refuses its connection,
//!   so it can neither reserve nor reach B, and its send says to ask the
//!   relay's operator. Once on the allow-list (R's circle), S reaches B's
//!   peer gate and is refused there before B accepts the circuit: B logs
//!   the counts-only gate line, its Raven link never runs, `raven status`
//!   counts the refusal on its `p2p_gate` row, and S's send says B may not
//!   know its PeerId. A contact A added without pinning it is refused by A's
//!   gate too (p2p is for verified contacts only). A→B still works after
//!   all of it, and no log names a PeerId. Every verbose send says
//!   `path=relayed` (no listener, so no upgrade), the default output says so
//!   in words, and `raven status` counts them on its `p2p_paths` row with no
//!   hole punch. Its REACHABILITY section says `behind NAT: contacts reach
//!   you through 1 relay`, no independent check yet (R runs no AutoNAT
//!   server), and R's `relay 1` row its host and port (never a PeerId) and,
//!   within one ping interval, the ping; `raven doctor` says `reach_class:
//!   relayed` and `relay_1: reserved`. Each side's LAST DELIVERY row says
//!   `through a relay`. When R is gone, A's `relay 1` row says `NOT reserved`,
//!   its `what to do` and the doctor's next step say the relay is not
//!   answering (W1), and the doctor says `reach_class: unreachable`; no new
//!   row, line or log names a PeerId or an address. Runs under the debug lab
//!   unlock while `P2P_PRODUCTION_ENABLED` is false.
//!
//! - **C12 network switch, p2p (Phase 0b):** relay R behind a recording proxy;
//!   A listens on a loopback port and its netwatch reads a lab event file; B
//!   is reachable through R only. With B down A queues 3 messages; then the
//!   proxy silences every path open so far (A's old network is gone, nothing
//!   is closed on R's side) and A's network changes: one `network changed`
//!   line ending `, p2p re-homing`, `re-homed (network changed)`, a new
//!   reservation on the SAME relay within 15 s (R holds A's silent one too),
//!   the listen port open again, status `reachability: relayed` (the fresh
//!   endpoint's AutoNAT verdict starts over, its relay holds it). B
//!   comes back: each queued message exactly once. A `wake` line re-homes
//!   again and the next message goes through. A's log names no address or
//!   PeerId, and once R reaps the silent reservation by ping it still counts
//!   A (its newest reservation) and B.
//! - **C13 silent relay path (Phase 0b):** R behind one proxy per node; A runs
//!   the real OS watcher and pings every 2 s with a 1 s timeout (debug
//!   `RAVEN_LAB_P2P_PING`). A's path alone goes silent with no network change:
//!   netwatch's `every relay stopped answering; p2p re-homing`, a re-home and
//!   a new reservation within 30 s, no `network changed` / `woke from sleep` /
//!   `default route moved` line (the outbox backoff is kept), and the next
//!   message is delivered exactly once.
//! - **C14 direct, then reversed (Phase 1 item 4):** A and B listen on
//!   loopback, no relay. A pins B's card naming B's own address; B pins A's
//!   card with `p2p=` only (no address: B can reach A only over a connection
//!   A opened). A→B is `path=direct`; B→A rides A's connection,
//!   `path=reversed`. A restarts (the connection is gone): B's next message
//!   is queued (no address). A sends again (a new connection), and B's
//!   outbox worker delivers the queued message over it: `raven outbox status`
//!   says `carrier p2p_dial` and `path reversed`, B logs `delivered 1
//!   (p2p_dial, reversed)`, and A holds it exactly once.
//! - **C15 true three-node relay (Phase 1 item 8):** a dedicated relay R
//!   behind a recording proxy, whose allow-list holds A and B (R relays only
//!   within its circle). A and B always listen on loopback (TCP and QUIC),
//!   yet publish no address to dial: their cards name only R (one `via=`),
//!   Identify hides listen addresses, and hole punching offers global
//!   addresses only. With no connection between them before the first send
//!   (R: 2 reservations, 0 circuits; A's book holds no LAN or Internet route
//!   for B), A→B twice and B→A are each `path=relayed` and arrive exactly
//!   once, R counts a circuit, the proxy carries more than 2 KiB and no
//!   message text, and no hole punch happens. The C16 spy pinned as B's
//!   contact gets B's Identify naming circuits only and is offered no
//!   candidate (no direct dial); as a stranger in R's circle it is refused
//!   by B's peer gate (no Identify, no DCUtR, no dial; B logs the
//!   counts-only gate line and counts it, and its Raven link never runs).
//!   No log names a PeerId.
//! - **C16 loopback hole punch and R14 (Phase 1 items 3 and 8):** R reached
//!   over QUIC, no proxy; A and B listen on loopback with the debug
//!   `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1`, so their candidate books offer
//!   loopback. Before A and B talk, an in-process libp2p spy (no Raven
//!   filter) probes B through R: as a stranger in R's circle its circuit is
//!   refused by B's peer gate (no Identify, no DCUtR, no candidate, no direct
//!   dial; B logs the counts-only gate line), and the same spy as B's pinned
//!   contact is offered B's 127.0.0.1 candidate and dials it (the positive
//!   control: the gate sits before DCUtR). A pcap cannot show this, since
//!   DCUtR runs inside Noise. Then A→B is `relayed` (or already
//!   `hole_punched`), a `direct connection upgraded (dcutr)` line comes
//!   within 30 s, the next A→B is `path=hole_punched` (A's newest link line
//!   says so), B→A is not `relayed`, each message arrives once, and A's
//!   `p2p_paths` row counts `hole punching 1 ok`. The only CI coverage of
//!   DCUtR plumbing end to end.
//!
//! Route hints (RRH1, `protocol/RAVEN_ROUTE_HINTS_V1.md`) run under their
//! debug switch `RAVEN_LAB_ROUTE_HINTS=1` ([`Profile::with_route_hints`])
//! while `ROUTE_HINTS_PRODUCTION_ENABLED` is false; every other profile
//! runs without it. On loopback nothing confirms a global address, so the
//! direct addresses in these tests are the same-network ones a node tells
//! a contact over a LAN link.
//!
//! - **C17 LAN port change, old peers (RRH1):** both sides on: B comes back
//!   on another port and sends to A; that link tells A the new port, and the
//!   message A queued meanwhile reaches B there within 15 s, with no
//!   `set-addr`. One side on, then neither: a message each way, exactly once,
//!   no dispatcher refusal in either log, no `learned_routes.json`.
//! - **C18 a new relay without new cards (RRH1):** relays R_A, R1, R2 behind
//!   recording proxies; `raven-card/3` cards; B listens nowhere. m1 is
//!   `relayed` through R1; B comes back on R2 only, its announce reaches A
//!   over LAN (A logs one learned relay), and m2 is `relayed` through R2. R1
//!   relays no circuit after the move, A's contacts.json is byte-identical,
//!   and no log names a PeerId.
//! - **C19 hide my IP from one contact (D4):** A, B, C on one relay with
//!   loopback candidates; A hides its IP from B. Over LAN, A's hints give C
//!   its p2p address and B none; A↔C leaves the relay, A↔B stays `relayed`
//!   on 3 sends each way with no DCUtR upgrade, and a contact spy A hides
//!   from gets no Identify.
//! - **C20 a stale hint after the recipient's network change:** B re-homes
//!   on the same relay with a new port (lab netwatch line); C's #1 dials the
//!   stale address and the relay together: `relayed`, once, within 30 s.
//!   B's next LAN link tells C the new address; with the relay gone, #2 is
//!   `direct` to it.
//!
//! Friend relays (any-network plan C6/C7: a profile relays for its verified
//! contacts with a relay key of its own and offers it in its route hints;
//! contacts pick relays from the offers) run under their debug switch
//! `RAVEN_LAB_FRIEND_RELAY=1` with route hints on
//! ([`Profile::with_friend_relays`]) while `FRIEND_RELAY_PRODUCTION_ENABLED`
//! is false. On loopback an operator's relay is offered only at the address
//! it names (`relay_external`, written into node_policy.json); members
//! listen nowhere and set no relay; every profile holds every other's LAN
//! route (the links that carry the offers).
//!
//! - **C21 a friend relay with its own key, picked from its offer:** Bob and
//!   Carol each send Alice one LAN message and within 30 s hold her relay
//!   (`relay_1_source=offer`, reserved); its PeerId is not hers, it counts 2
//!   members and 2 reservations, and Carol and Bob are `relayed` to each
//!   other through it, once each. `raven relay offer off`: it stops within
//!   10 s, Bob's reservation ends, and Carol's next message waits.
//! - **C22 a sleeping relay replaced without new cards:** three operators,
//!   each relay behind a recording proxy; Bob holds 2. X's proxy goes
//!   Blackhole (the cross-OS sleep stand-in): Bob logs `relay replaced`
//!   within 45 s and takes the standby Z, his route hints tell Carol, and
//!   with Y asleep too Carol is `relayed` to Bob through Z although her
//!   contact book is unchanged. X back: no further replacement within 20 s,
//!   and X is Bob's spare.
//! - **C23 a relay that moves is followed through RRH1:** Alice's network
//!   changes (lab netwatch) and her relay starts over on a new port with the
//!   same key; her route hints tell Bob, who holds it beside a relay set by
//!   hand, and he re-reserves at the new address within 30 s with no
//!   reselection; his own hints tell Carol, the relay set by hand stops, and
//!   Carol is `relayed` to Bob through the moved relay, once.
//!
//! The relay kit (docs/RELAY_KIT.md: `raven-node relay` with `--also-tcp`
//! and `--public-host`, `raven relay use`, a relay named by two addresses):
//!
//! - **C24 kit relay, fallback address, graceful stop:** `relay --check`
//!   names ports only; the relay opens TCP+QUIC P1 and TCP P2 and names all
//!   three; `raven relay card` prints TCP P1, TCP P2, QUIC P1, and the
//!   `raven relay use` line only with `--host` (loopback addresses alone
//!   give none); `relay-probe` says reachable, refused, and a different
//!   PeerId. A saves a dead primary and the working P2 (`raven relay use`):
//!   one reservation, on the fallback (`reservations 1/1`), and A↔B are
//!   `relayed`, each once. No PeerId or address in a log. Unix: SIGTERM
//!   stops the relay within 3 s, exit 0, and A sees the reservation end
//!   within 5 s (no SIGTERM on Windows: the check is skipped there).
//! - **C25 an installed kit on 443:** only where `RAVEN_RELAY_KIT_VIA` names
//!   the 443 line of a kit the CI step installed (Linux, systemd,
//!   CAP_NET_BIND_SERVICE): A reserves over 443, B over the main port, A↔B
//!   are `relayed`, and `raven-relay status` counts 2 reservations and a
//!   circuit.
//!
//! Why a contact cannot be reached (any-network plan, Phase 2 item 5: the
//! reason block raven-node adds to a failed p2p dial, `reach: why=…`, and
//! the texts ash makes of it):
//!
//! - **C26 every reason explained:** relay-only A and B on relay R. B
//!   stops: A's send is queued with "bob is offline: bob's relay answered",
//!   `raven status` has a NOT REACHABLE NOW row `offline —`, the doctor
//!   counts `contact_offline=1` and `raven outbox list` says why. B is back:
//!   the worker delivers and the section is gone within 30 s. R is killed:
//!   the send names the relay both use (`is not answering`), the doctor
//!   says W1. B moves to R2, which serves B only: "bob's relay turned you
//!   away" (first or second try). B2 has no relay: both_nat, from B2's card,
//!   with the friend relay command, the relay kit and the port forward; once
//!   A pins carol, who can be reached, the fix names her. No log names a
//!   PeerId, and the reason line names no address.
//! - **C35 no route, LAN only (cutoff study F9):** a lab netwatch file says
//!   `egress none`; A and B hold literal LAN routes and a relay at a dead
//!   TEST-NET address. LAN delivery both ways, once each, every send within
//!   8 s; the outbox keeps the LAN result; `raven status` says W0 and none
//!   of W1 to W3, the doctor `internet_route: none`, and no text suggests a
//!   relay, a VPS, UPnP or a port forward.
//! - **C36 the hotspot host learns its client (cutoff F7):** A has no LAN
//!   route for B (B was added from an invite line); B dials A once, so A
//!   records where B came from and, with M0 on, B's noise pin. Then A
//!   replies, four ways, each on fresh profiles: (1) no switches
//!   (`RAVEN_LAB_OFFLINE=0`): NOT SENT, B "has no reachable lan_dial" (the
//!   gap); (2) route hints on: delivered within 5 s at B's real port, which
//!   B announced (RRH1); (3) `RAVEN_LAB_OFFLINE=1 RAVEN_LAB_NOISE_PIN=1`,
//!   no hints, B listening on the port `RAVEN_LAB_LAN_DEFAULT_PORT` names:
//!   delivered within 5 s at `127.0.0.1:<that port>` (never 7420), and
//!   saved as B's address; (4) as (3) with A's noise pin for B removed
//!   first: NOT SENT as in (1) (no pin, no guess); (5) Phase 3 P3.C5, (3)
//!   with the LAN beacon (`RAVEN_LAB_LAN_BEACON=1`) on a lab bus of the
//!   test's own and B on a port of its own, the default port held by a
//!   listener that counts connections: B's hello asks its beacon for A, A
//!   answers and so finds B's port; A's reply is delivered within 5 s
//!   through that find ("found on your network now", B's real port, not
//!   saved), and the guess was never dialled (0 connections). CP.13's
//!   gateway candidate was not built (OD-C5), so there is no C37 to run
//!   with the beacon.
//! - **C38 a sibling's success wakes the queue (cutoff F5, the study's C43;
//!   `RAVEN_LAB_OFFLINE=1 RAVEN_LAB_NOISE_PIN=1` on every profile,
//!   `RAVEN_LAB_LAN_DEFAULT_PORT` naming a free port):** A, B and C link
//!   once (A pins B's and C's Noise statics). B and C go away and A queues
//!   a message for each, until A's next try for B is a minute or more away.
//!   B comes back on its port and stays silent; C comes back and dials A:
//!   B's message is delivered within 5 s of C's link plus one dial (A logs
//!   "a contact answered on this network; retrying 1 others" once), C's on
//!   A's dial-back, each exactly once.
//! - **C39 a stranger at a friend's address learns nothing (cutoff M0, the
//!   debug switch `RAVEN_LAB_NOISE_PIN=1`):** A and B link once (A pins B's
//!   Noise static). B stops and X, a scripted Noise XX responder with
//!   another identity, takes B's old port: A's send is queued with "something
//!   else answered at bob's address", and X read message 1 only (no message
//!   3, no bind) on every connection. X stops and B comes back on that port
//!   and sends to A: A's queued message reaches B exactly once with no
//!   `raven outbox retry` (B's inbound link cleared the scoped block). With
//!   the gate closed (`RAVEN_LAB_NOISE_PIN=0`) the same X decrypts A's bind
//!   and learns A's Ed25519 key: today's leak, which a raven-node responder
//!   would not keep (hence the scripted X).
//! - **C90 the sealed contact book (privacy pack PP.4):** A and B start from
//!   plain books (their own commands run with `RAVEN_LAB_AT_REST=0`); each
//!   daemon, started with `RAVEN_LAB_AT_REST=1`, seals its book at start
//!   before it admits anyone, and they exchange both ways. B removes A
//!   while B's daemon runs: A's next send is refused at B at once (B's
//!   cached book is read again on the file's change). B adds A back: A's
//!   next send is delivered. Both restart: still delivered both ways. Both
//!   books are RMS1 from the first start on, and `raven status` / `raven
//!   doctor` say so in words and counts only.
//! - **C87 no friend metadata in a copied data dir (privacy pack PP.6 and
//!   PP.14):** A and B exchange over LAN with route hints on, stop, and each
//!   data dir is copied: no file holds the friend's key (hex, base64),
//!   rvn1 address, PeerId, address, petname or IP, and no file name names
//!   the key; the address files are RMS1. Part 2 (PP.14) reads every SQLite
//!   store's raw bytes, its WAL and free pages included: none of those, and
//!   no message id of the run (raw or hex). Part 3 (review
//!   B-sealed-stores-1): no clear 16-byte value or file name, taken as a
//!   session's init_id, gives a record key that names the friend.
//! - **C91 erase one of two profiles (privacy pack PP.16):** A and B
//!   exchange; A runs `raven erase` in a pseudo-terminal with its node
//!   running and Raven's own (lab) login item for it: the node stops, the
//!   item is unloaded, turned off and removed, and the temp root holds
//!   nothing of A; B's node (the same process) and C still exchange both
//!   ways. Unix only (`script`).
//! - **C86 part 1 PAD1 link padding (Phase 6b P6.34; its debug switch
//!   `RAVEN_LAB_LINK_PADDING=1` with `RAVEN_LAB_TEST_A=1`):** every route
//!   goes through a proxy that keeps each connection's directions apart. Two
//!   padding nodes exchange over LAN and Internet direct: after the handshake
//!   every message is a PAD1 bucket plus the tag, but the LAN dialer's bind,
//!   the hellos and a frame-less probe. A padding node and one without (both
//!   ways round): each message once, nothing padded. s115 runs part 1
//!   against an older build.
//! - **C86 part 2 RLK1 link knock (Phase 6b P6.35; its debug switch
//!   `RAVEN_LAB_LINK_KNOCK=1` with `RAVEN_LAB_TEST_A=1`, every node with the
//!   noise pins and security events):** two knocking nodes exchange over LAN
//!   and Internet direct, each message once, every handshake knocked both
//!   ways (message 1 64-95 bytes, message 2 112-143, message 3 71-128); the
//!   listener is then strict (two stranger probes see two statics) and, set
//!   silent to strangers, sends a probe no message 2 while its contact still
//!   gets in. A knocking node and an M0-only node, both ways: each message
//!   once, no pin mismatch, the knocking one stays legacy (its contact's
//!   floor lacks the knock). The impostor rows wait for P6.32.
//! - **C86 part 3 pair seeds (Phase 6b P6.38; its debug switch
//!   `RAVEN_LAB_PAIR_SEED=1` with `RAVEN_LAB_TEST_A=1` and route hints, every
//!   node knocking with the noise pins and security events):** two nodes in
//!   plain profiles exchange over LAN until their RRH1 frames agreed a pair
//!   seed (both `pair_seeds.json` hold the same current seed), and later
//!   messages still arrive once each, every dial knocked with the seed. One
//!   side then loses its seeds (its file removed while it runs): each
//!   message still arrives once (the other's seeded knock falls back to the
//!   root), and the two agree on a seed again.
//! - **C88 notices over RUP1 (Phase 6b P6.51, `carrier_matrix/updates.rs`;
//!   the update gates' debug switches, the test release key set, the
//!   security events' switch):** a notice passed A -> B -> C by itself; a
//!   rolled-back, a forged and an equivocating notice refused by their
//!   event kinds (B freezes on the last), and C freezes on a split view
//!   between two friends' logs. The lab friend that claims a newer notice
//!   than it holds runs `RAVEN_LAB_UPDATE_CLAIM_NEWER=1`.
//! - **C89 releases over RUP1 and the install (P6.51, Unix):** unsigned,
//!   forged and unlogged releases refused from files and over RUP1 (after
//!   each approval), a good one passed A -> B -> C only after each
//!   approval, installed from a temp prefix with the old raven-node kept as
//!   `.prev`, then an older one refused as a downgrade. C87 also runs with
//!   every Phase 6 switch on, after a notice and a release passed.
//!
//! Phase 3 (the LAN listener on every interface, `--lan-listen auto`, and the
//! contact-only LAN beacon, `protocol/RAVEN_LAN_BEACON_V1.md`; their lab
//! switches only, both gates closed):
//!
//! - **C27 `auto` on both families, local sources only:** with
//!   `RAVEN_LAB_LAN_AUTO=1`, `raven lan status` lists `0.0.0.0:P` and
//!   `[::]:P` (IPv6 where the runner has it), A delivers through `127.0.0.1:P`
//!   and `[::1]:P`, and with `RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK=1` a plain
//!   connection on either family is closed before a byte (a counts-only log
//!   line) while A's message waits. Without the unlock, a single `0.0.0.0:P`
//!   for any source, and the waiting message arrives once.
//! - **C28 `raven lan off` and `on` act live:** off closes the port on both
//!   families within 5 s with no restart, A's message waits and B's own send
//!   says LAN_OFF; on opens the same port in the same process, and A's
//!   message arrives once.
//! - **C29 the beacon over real multicast:** `auto` listeners and the beacon
//!   on a free UDP port (never 7420), contacts pinned with no address: A's
//!   send is delivered within 10 s through what its beacon found, its own
//!   query came back (`echo_ok`); again over IPv6 link-local only
//!   (`[fe80::…%zone]`) where the runner has it. Skipped, and the skip
//!   printed, only with `RAVEN_HARNESS_NO_MULTICAST=1`.
//! - **C30 the beacon's safety (a lab bus, 127.0.0.1 only):** a stranger
//!   who holds A as a contact gets no answer (A's `answers_sent` stays 0);
//!   B with the beacon's gate closed is `held`, opens no socket (its lab port
//!   stays free, nothing of it on the bus), and A delivers to B by its saved
//!   route as today.
//!
//! Phase 3 item 4 (session renewal, `raven_core::session_renewal`; its lab
//! switch `RAVEN_LAB_SESSION_RENEWAL=1` only, the gate closed):
//!
//! - **C31 a session near its end is renewed:** A's first send starts an
//!   11 h session (the debug `RAVEN_LAB_SESSION_LIFETIME_MS` on that `raven
//!   send` only). B did not start it, so B renews it after the settle (one
//!   `renewed a session (primary` line, at B); both daemons advertise
//!   `session_renewal`. B goes down: A's queued message gets a deadline
//!   about a day out (`in about N h`, N >= 23, not 11 h) and is delivered
//!   exactly once when B is back on its port; B to A is delivered, and no
//!   second renewal follows.
//!
//! Phase 3 item 3 (friend custody over the internet: custodians announced in
//! route hints, RFC1 over p2p links; the lab unlock plus the WAN custody
//! switch `RAVEN_LAB_CUSTODY_WAN=1`, both custody gates closed):
//!
//! - **C32 custody over relay circuits, message and ACK:** A, B and C on a
//!   relay behind a recording proxy, cards naming only it; C offers to hold
//!   mail, A and B turn friend mailboxes on, nobody names a custodian. B
//!   away: A's message is held by C; A away, B back: once, and B's ACK is
//!   left with C; B away, A back: the ACK through C, delivered. The proxy
//!   carried no RFC1/RSO1/RVPI1/RVPR1/RLB1 magic, text, raw key or tag; C's
//!   store holds no text; the deposit lines say `p2p_dial, relayed`; the
//!   logs hold no PeerId or 64-hex value.
//! - **C33 the WAN gates and the refusals:** C without the WAN switch
//!   (CUSTODIAN_NOT_OFFERING, a crafted lab P2pDial DEPOSIT answered HOLD, no
//!   store file); A hides its IP from C and C restarts with the switch (the
//!   waiting message left over the circuit, then fetched once); a stranger
//!   and an unverified contact get no RFC1 answer (C's peer gate); C as an
//!   old build (`RAVEN_LAB_CUSTODY_PRETEND_OLD=1`): three strikes (A's
//!   counts-only park line), no further link to it, then direct delivery
//!   once B is back.
//! - **C34 a friend relay and a custodian on one node:** the fault
//!   matrix's s30r on three OSes: C's friend relay (its own key) and its
//!   custody; B away, NotOnRelay (`contact_offline`) before the deposit, B
//!   back has it once; the relay status holds counts only.
//!
//! Phase 4, restrictive networks (`protocol/RAVEN_WSS_TRANSPORT_V1.md`, RWS1:
//! a relay's WebSocket/TLS listener and the HTTPS proxy of WSS dials; their
//! lab switches `RAVEN_LAB_WSS` and `RAVEN_LAB_WSS_PROXY` only where a case
//! sets them, both gates closed):
//!
//! - **C40 a WSS relay on loopback ([`RelayOpts::wss`]):** R's `--wss`
//!   listener has a port of its own, which its status file lists in both
//!   forms (`…/tls/ws` and plain) and its up line names (`wss=on`). A reaches
//!   it through a recording proxy that lets only TLS out
//!   ([`ProxyMode::TlsOnly`]): the raw sibling, tried first, is closed there
//!   and A reserves over WSS (IPC `relay_paths` `wss`; `raven status`: `relay
//!   over WSS`); B reserves over the raw sibling on the same port (`tcp`).
//!   A→B and B→A are `relayed`, once each; the proxy saw a TLS record first
//!   and no libp2p protocol name, PeerId or message text in the clear.
//! - **C41 the HTTPS proxy only:** A names R as `/dns4/relay.invalid/tcp/
//!   <P>/tls/ws`, a name only the in-test CONNECT proxy ([`ConnectProxy`])
//!   resolves, with `RAVEN_P2P_PROXY` naming it (the one case that sets a
//!   proxy); R names only a closed port (`--external`), and so do both
//!   cards, so A reaches R through the proxy alone. The proxy is asked
//!   `CONNECT relay.invalid:<P>` (the name, never an address) and carries
//!   TLS only; `raven status` says `relay over WSS through the HTTPS proxy`
//!   and `restricted network (relay only)`; delivery both ways, `relayed`,
//!   once. The proxy goes away: A's reservation ends, 3 messages wait, the
//!   slot retries; the proxy is back on its port: A reserves through it
//!   again and each message arrives exactly once. A's log names no PeerId,
//!   proxy address or relay address or name.
//! - **C42 the WSS gate closed:** `raven-node relay --wss` exits 2 with
//!   WSS_HOLD and starts nothing; a service named a WSS relay address dials
//!   its raw sibling (a high port: tests bind no privileged port, so the
//!   raw-443 convention is the unit tests' part), logs WSS_HOLD once, and
//!   reserves and delivers over raw libp2p: the relay's recording proxy sees
//!   multistream-select from the first byte, no TLS, and the relay lists no
//!   `/tls/` address.
//!
//! Phase 4, router port mapping (`protocol/RAVEN_PORT_MAPPING_V1.md`: NAT-PMP
//! and PCP; their lab switches `RAVEN_LAB_PORT_MAP` and
//! `RAVEN_LAB_V6_PINHOLE` only where a case sets them, both gates closed).
//! The router is raven-core's `FakeGateway` on a loopback UDP socket
//! ([`fake_gw`]), named by `RAVEN_LAB_PORTMAP_GATEWAY`; it reports 127.0.0.1
//! as its external address, where the test forwards the mapped port.
//!
//! - **C43 PCP and NAT-PMP, router and network changes:** B maps TCP and UDP
//!   (an ANNOUNCE first, one nonce per mapping, at least 2 renewals each
//!   within 20 s of 8 s leases); A learns the mapped address through B's
//!   route hints on a relayed first message and, restarted with the relay
//!   gone, reaches B `direct` through the forwarded port (over 2 KiB). A
//!   router restart is followed within 6 s, a lab network change searches
//!   the router again within 15 s, and B's stop deletes both mappings
//!   (Unix). NAT-PMP only maps through NAT-PMP; a CGN external address is
//!   `behind another NAT` and deleted. A silent router (UPnP next) and the
//!   gate closed (Phase 1's UPnP only, 0 datagrams to the fake) start a
//!   real UPnP search: only with `RAVEN_HARNESS_UPNP_SEARCH=1` (CI).
//! - **C44 the IPv6 pinhole's own consent:** B on `[::1]` with a fake PCP
//!   firewall on `[::1]`: nothing asked while `ipv6-pinhole` is unset, the
//!   pinhole open once it is on. Skipped without IPv6 loopback.
//! - **C45 hopeless hole punches are skipped (P4.24):** the C16 topology
//!   (loopback candidates; R over TCP) with the NAT_CLASS lab
//!   (`RAVEN_LAB_NAT_CLASS=1`) and route hints on A and B, each NAT class
//!   forced by `RAVEN_LAB_NAT_CLASS_FORCE`. A first message carries the
//!   RRH1 exchange (each side stores the other's NAT_CLASS); both nodes
//!   then restart, so the next messages need a fresh relayed connection.
//!   `varies` on both: messages 2-3 are `relayed`, both log "hole punch
//!   skipped (both", neither logs an upgrade or "hole punch failed", and
//!   status `nat_mapping.punch_skipped` >= 1. Controls: `stable_kept` on
//!   both hole-punches as C16 does; `varies` on A alone still attempts it.
//! - **C46 PeerId rotation follows contacts and relays (P4.28):** the C15
//!   topology (dedicated R, A and B pinned, loopback candidates, route
//!   hints) with the rotation lab (`RAVEN_LAB_PEER_ROTATION=1`,
//!   `RAVEN_LAB_PEER_EPOCH_S=30`) on A and B. B turns rotation on and R gets
//!   his `raven relay schedule`. With C (no rotation lab) also pinned on B,
//!   B says `waiting: 1 contact` once A's RRH1 said it can follow, and keeps
//!   its card's PeerId. C removed: B announces its coming PeerIds (A stores
//!   them), then at a boundary logs 'network ID rotated', its status PeerId
//!   is the epoch's from the schedule and a second 'reservation accepted'
//!   follows; A hears B rotates and its next message is delivered under the
//!   scheduled PeerId (`peer_epoch=current`). R then denies B's later
//!   PeerIds: at the next boundary 'rotation postponed', a re-home back to
//!   the previous key, A hears it and a third message is delivered. Every
//!   message arrives exactly once; no log of A or B names a PeerId.
//! - **C54 two-hop custody chain (P5.23, handoff design C20):** four daemons
//!   on loopback with the handoff lab (`RAVEN_LAB_CUSTODY_HANDOFF=1`, the
//!   forwarder at 500 ms, route hints). A lists F1 for B, B lists F2 for A;
//!   F1 never pins B, F2 never pins A, and A and B pin the far friend by key
//!   only (RRH1 tags are pair-blinded). With B away A's message is left with
//!   F1 to pass on, F1 hands it to F2; with A away B fetches it from F2 and
//!   his ACK goes F2 -> F1; A, back on a new port, fetches the ACK: exactly
//!   once, delivered, A and B never running together. No file of F1's
//!   (sealed ones opened) or its log holds B's key, none of F2's holds A's,
//!   neither the text; logs are counts only and nobody logs a strike.
//! - **C55 handoff refusals (P5.23, handoff design C21):** F1 behind a closed
//!   link gate (A reaches it over Internet direct with WAN custody, F1
//!   without) answers HOLD; F1 with `RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1`
//!   answers the handoff ops UNSUPPORTED. Each time a plain deposit at a
//!   mutual custodian holds the message, F1 keeps no forward row and no tag,
//!   no strike is logged, and after the UNSUPPORTED F1 still takes a plain
//!   deposit; B has each message exactly once.
//!
//! Phase 5, Bluetooth nearby (`protocol/RAVEN_NEARBY_LINK_V1.md`, RNL1; its
//! lab switch `RAVEN_LAB_NEARBY` with the Lab Test A unlock, the gate
//! closed). Every case runs a `raven-node nearby-ether` hub ([`EtherHub`]:
//! the fake radio, loopback only) and its services on it
//! (`RAVEN_LAB_NEARBY_ETHER`). The contacts meet once on the LAN (nearby
//! admits a verified contact by the certificate an earlier link left, RNL1
//! §0), then their saved LAN addresses become dead loopback ports, with no
//! Internet direct, p2p or LAN beacon: nearby is the only path
//! ([`nearby_meet`]).
//!
//! - **C50 both ways:** `raven nearby enable` on both; 3 messages each way,
//!   each delivered with its sealed receipt over nearby (`carrier
//!   nearby_dial`), each exactly once; `raven status` says the last delivery
//!   went over Bluetooth nearby.
//! - **C51 a stranger in range learns nothing:** while Alice advertises for
//!   Bob (his radio off), a raw radio with no key ([`RawRadio`]) connects to
//!   her service and writes random HELLOs, and later Bob's captured HELLO
//!   (the hub's `hellos`, what a radio observer sees) on a new connection:
//!   0 frames back, no `nearby inbound` line from it; Bob's own knock works.
//! - **C52 adverts rotate and carry no constant:** one lab clock moved 15
//!   min an epoch, Bob's and Dave's radios off: one token per epoch while
//!   Alice advertises for Bob, two once for Dave too (at most 2 rotate), a
//!   new one every epoch, never one for an unverified contact; each advert
//!   one v4 UUID and nothing else, per-token characteristic UUIDs, and no
//!   byte the same in every advert.
//! - **C53 a lost frame mid-message:** the hub loses one frame of a 48 KB
//!   message (`fault drop_after`); the outbox tries again and it arrives
//!   exactly once, the receipt idempotent.
//! - **C56 a Bluetooth-only island (the cutoff study's C44):** netwatch
//!   says no route out, every process counts its name lookups and outbound
//!   connects (`RAVEN_LAB_NET_AUDIT`): a message and receipt each way;
//!   25 h later (lab clock, the horizon on) the ended session is set up
//!   again over nearby and the waiting message arrives once; zero lookups,
//!   zero connects beyond this computer; no constant byte in the adverts.
//!   Variant (cutoff addendum F11d): radios that meet after the user's work
//!   ran out (`RAVEN_LAB_NEARBY_FOREGROUND_MS`) deliver only with nearby
//!   background mail on.
//!
//! Phase 6a, learning connectivity (P6.18; `RAVEN_LAB_LEARNING=1` on the
//! learning side while `LEARNING_PRODUCTION_ENABLED` is false, each
//! profile on a lab network tag of its own, `RAVEN_LAB_NET_TAG`). C70, C72
//! and C73 share one pair ([`black_hole_pair`]): A pins B with a LAN route
//! into TEST-NET-1 on B's port (a black hole) and B's working Internet
//! route (the lab unlock).
//!
//! - **C70 the LAN black hole is learned:** with A's session set up first
//!   (learning held), message 1 pays at most one LAN connect wait (5.5 s)
//!   and goes over the Internet; from message 3 on
//!   `raven send` dials no LAN route (its own dial lines) and the worker's
//!   order (the learning row) is Internet first, each send under 2 s;
//!   `raven learning status` says the LAN did not answer; after `raven
//!   learning reset --yes` message 5 goes LAN first again (one LAN wait
//!   too); each once.
//! - **C71 a learned reply wait:** [`StallProxy`] in front of B's LAN
//!   listener; once warm (5 sends) one link in three gets no reply: that
//!   send gives up in under 10 s (today's wait is 30 s), A's outbox sends
//!   it again, it arrives once, and no send waits 30 s.
//! - **C72 learning off:** C70's pair without the switch: the sends follow
//!   the recorded baseline ([`C72_BASELINE`]), no log line names learning,
//!   no `learning.bin`, no `Status.learning`, no learning line in `raven
//!   doctor`'s report.
//! - **C73 an unreadable or locked store:** a corrupted `learning.bin` is
//!   `reset_after_unreadable` (static order, overwritten by the next
//!   save); with the debug sealer hook `RAVEN_LAB_LEARNING_SEALER=unavailable`
//!   it is `memory_only` and the file's bytes never change.
//! - **C74 relay terms (the p2p lab, two relays as C15):** R1 sleeps (its
//!   proxies hold every connection silent); A's dials to B, each a new
//!   connection, go `path=relayed` through R2, the third in under 5 s; R1
//!   stays in the dial set; nobody's relay choice changes.
//!
//! Internet direct is for verified (pinned) contacts only (owner decision
//! 2026-10-08): C2 also checks that an unverified contact is refused on send
//! (nothing dialled) and by the listener (treated like a stranger).
//!
//! Case numbers, one registry for every phase (Phase 6 P6.1; the same registry
//! is in scripts/lan_fault_matrix.py): Phases 0-1: C1-C16, s01-s38b. Phase 2:
//! C17-C26 (+C7f), C35 (F9), s32b-s32e, s39-s49 (+s48c, s48o). Cutoff pack:
//! C36-C39, s90-s93, s95-s99 (+s90p, s91b, s93b, s96w). Privacy pack: C87,
//! C90-C93, s117, s120-s129. Phase 3: C27-C34, s80-s89 (+s85b). Phase 4:
//! C40-C49 (uses C40-C46), s50-s59 (uses s50-s53). Phase 5: C50-C69 (uses
//! C50-C56; C56 is the cutoff study's), s60-s79 (+b/c variants), plus s94 and
//! s97b inside the cutoff block (registered by CP.1). Phase 6a: C70-C79 (uses
//! C70-C74), s100-s109 (uses s100-s106), real rows L1-L4. Phase 6b: C80-C89
//! (C87 is the privacy pack's), s110-s119 (s117 is the privacy pack's), real
//! rows R30-R35 and R37 (R34 is the privacy pack's; R36 dropped). Phase 6c:
//! C100-C109, s130-s145. The cutoff study's C40-C44 are C35, C36, C37 (not
//! built, OD-C5), C38 and C56 here; C39 is M0's. Phase 6 also holds RIH1/RLX1
//! caps bits 9 (PAD1) and 10 (RUP1), RRH1 entry type 0x08 (T_PAIR_SEED, the
//! next free type in the route hints spec's own range), RLX1 entry type 0x7E
//! (padding), rendezvous medium 0x03 (link knock), the local event codes SEC_*
//! 1-78 (docs/SECURITY_EVENTS.md: local, not wire) and the at-rest kinds 11
//! (capability floor), 12 (pair seeds), 22 (learning store) and 23 (update
//! state) that `at_rest::Kind` reserves, then 96 and up.
//! Taken by the privacy pack (PP.19): C87, C90 and C91 here
//! (C92 and C93 are free; each runs with `--ignored`, C91 on Unix only), s117
//! and s120-s125 in the fault matrix (s117, s121 and s122 by default, all of
//! them with `RAVEN_FAULT_PRIVACY=1`; s120 and s124 need
//! `RAVEN_FAULT_PRIVACY_OLD_BIN`, the build before the pack).
//! Phase 3 (P3.0, P3.C0): its plan steps take C27-C34, s80-s85b and
//! s30p/s30w/s30r, and use s04; its cutoff steps (P3.C1-P3.C8) take s86-s89;
//! C35-C39 and s90-s99 stay the cutoff pack's.
//! Phase 4 (P4.0): C40-C49, s50-s59; real rows R2b, R2c, R8w, R8p, R8m and
//! R25-R27 (the plan's R15-R17; Phase 2 holds R15-R20). Phase 5: C50-C69
//! (C56 stays the cutoff pack's), s60-s79; real rows R28-R29 (the plan's
//! R18-R19) and N1-N12. Taken by multi-hop custody (P5.23): C54, C55 here,
//! s68-s71 and the cutoff addendum's s97b in the fault matrix.
//!
//! Privacy pack (PP.1): a build of the pack seals the profiles its nodes start
//! in, so every profile lies under its test's own temp root ([`profile_dir`]
//! refuses anything else, `~/.raven` and a live profile among them), and every
//! process of a profile gets `RAVEN_LAB_AT_REST=1` and that root as
//! `RAVEN_LAB_ERASE_ROOT` from [`Profile::env`], never the caller's values.
//!
//! Phase 4 (P4.1): no process gets a Phase 4 lab switch or harness value
//! unless its case sets one, nor the caller's proxy settings (`HTTPS_PROXY`,
//! `ALL_PROXY`, `NO_PROXY`, also in lower case); each runs with
//! `RAVEN_P2P_PROXY=off` ([`Profile::env`], [`relay_node_command`]), so the
//! proxy of the computer running the matrix never reaches C1-C16. C41's
//! service alone gets a real one (its in-test proxy).
//!
//! Synchronisation is event driven: the harness reads each daemon's stderr and
//! waits for its own "ipc: listening" / "lan_direct: listen <addr>" lines. Every
//! wait and every child process has a bounded deadline; nothing sleeps to
//! "give it time".
//!
//! `#[ignore]` (spawns processes, needs the `raven` binary):
//!
//! ```text
//! cargo build --locked -p ash -p raven-node
//! cargo test --locked -p raven-node --test carrier_matrix -- --ignored --nocapture
//! ```
//!
//! The harness's own checks (pipe names, the relay guard) run without
//! `--ignored`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};

const NODE: &str = env!("CARGO_BIN_EXE_raven-node");
const READY_TIMEOUT: Duration = Duration::from_secs(120);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const LOG_TIMEOUT: Duration = Duration::from_secs(30);

/// The `raven` CLI: `RAVEN_HARNESS_RAVEN_BIN`, else next to `raven-node`
/// (`cargo build -p ash` puts both in the same target directory).
fn raven_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("RAVEN_HARNESS_RAVEN_BIN") {
        return PathBuf::from(p);
    }
    let node = Path::new(NODE);
    let name = if cfg!(windows) { "raven.exe" } else { "raven" };
    let path = node.with_file_name(name);
    assert!(
        path.is_file(),
        "{} is missing: run `cargo build --locked -p ash -p raven-node` first (or set \
         RAVEN_HARNESS_RAVEN_BIN)",
        path.display()
    );
    path
}

/// Lines of one process's stderr, appended by a reader thread; waiters block
/// on the condition variable until a matching line arrives or time runs out.
#[derive(Default)]
struct Log {
    lines: Mutex<(Vec<String>, bool)>,
    changed: Condvar,
}

impl Log {
    fn follow(self: &Arc<Self>, stream: impl Read + Send + 'static) {
        let log = Arc::clone(self);
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines() {
                let Ok(line) = line else { break };
                log.lines.lock().unwrap().0.push(line);
                log.changed.notify_all();
            }
            log.lines.lock().unwrap().1 = true;
            log.changed.notify_all();
        });
    }

    /// The first line matching `pred` (already seen or arriving within
    /// `timeout`). `None` on timeout or when the stream ended without one.
    fn wait_for(&self, timeout: Duration, pred: impl Fn(&str) -> bool) -> Option<String> {
        let deadline = Instant::now() + timeout;
        let mut guard = self.lines.lock().unwrap();
        loop {
            if let Some(hit) = guard.0.iter().find(|l| pred(l)) {
                return Some(hit.clone());
            }
            let now = Instant::now();
            if guard.1 || now >= deadline {
                return None;
            }
            guard = self.changed.wait_timeout(guard, deadline - now).unwrap().0;
        }
    }

    fn text(&self) -> String {
        self.lines.lock().unwrap().0.join("\n")
    }

    /// How many lines so far contain `needle`.
    fn count(&self, needle: &str) -> usize {
        let guard = self.lines.lock().unwrap();
        guard.0.iter().filter(|l| l.contains(needle)).count()
    }
}

/// One running `raven-node service`; killed when dropped.
struct Service {
    child: Child,
    log: Arc<Log>,
    lan_dial: String,
    /// The bound Internet direct address (empty without `--internet-listen`).
    internet_dial: String,
    /// Listen addresses the libp2p host opened at start (`host up
    /// (listeners=N`); 0 without the host.
    p2p_listeners: u32,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Service {
    /// The LAN listener's address: [`Self::lan_dial`], or for a p2p service
    /// (which does not wait for it) its `lan_direct: listen` line.
    fn lan_listen(&self) -> String {
        if !self.lan_dial.is_empty() {
            return self.lan_dial.clone();
        }
        let line = self
            .log
            .wait_for(READY_TIMEOUT, |l| {
                l.contains("raven-node lan_direct: listen ")
            })
            .unwrap_or_else(|| panic!("no LAN listener:\n{}", self.log.text()));
        line.rsplit(' ').next().unwrap().trim().to_string()
    }

    /// Ask the daemon to stop (SIGTERM, as an OS service manager does) and
    /// wait at most `within` for it to exit; `false` when it still runs
    /// (C43: its router mappings are deleted on the way out).
    #[cfg(unix)]
    fn terminate(&mut self, within: Duration) -> bool {
        let pid = self.child.id().to_string();
        let sent = Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("run kill");
        assert!(sent.success(), "kill -TERM {pid} failed");
        let deadline = Instant::now() + within;
        loop {
            if self.child.try_wait().expect("service wait").is_some() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Output {
    fn all(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

struct Profile {
    name: &'static str,
    dir: PathBuf,
    /// The test's temp root that holds [`Self::dir`] ([`profile_dir`]).
    root: PathBuf,
    /// Its Windows pipe suffix ([`pipe_suffix`]), the same for its daemon
    /// and its CLI.
    pipe_suffix: String,
    address: String,
    pub_hex: String,
    fingerprint: String,
    /// Debug lab unlock for Internet direct (`RAVEN_LAB_TEST_A=1`) on every
    /// process of this profile; the C1 profiles run without it.
    lab_internet: bool,
    /// Route hints (RRH1) on every process of this profile: the debug switch
    /// `RAVEN_LAB_ROUTE_HINTS=1` while `ROUTE_HINTS_PRODUCTION_ENABLED` is
    /// false ([`Profile::with_route_hints`]). Off by default, so C1-C16 run
    /// without hints whatever the caller exported.
    route_hints: bool,
    /// Friend relays (Phase 2) on every process of this profile
    /// ([`Profile::with_friend_relays`]). Off by default.
    friend_relays: bool,
    /// The cutoff pack's noise pins (M0) on every process of this profile:
    /// `RAVEN_LAB_NOISE_PIN=1` (`Some(true)`) or `=0` (`Some(false)`, the
    /// gate closed whatever its const says); `None` leaves the const.
    noise_pin: Option<bool>,
    /// More lab switches for every process of this profile
    /// ([`Profile::with_lab_env`]), set after the ones above.
    lab_env: Vec<(&'static str, String)>,
}

impl Profile {
    /// Every process of this profile gets the same lab environment, including
    /// its own Windows pipe name (debug builds; ignored on Unix, where the IPC
    /// socket already lives in the data dir).
    fn env(&self, cmd: &mut Command) {
        for k in [
            "RAVEN_PREKEY_BACKEND",
            "RAVEN_SESSION_BACKEND",
            "RAVEN_KEYSTORE_PASSPHRASE",
            "RAVEN_KEYSTORE_PASSPHRASE_FILE",
            "RAVEN_KEYSTORE_BACKEND",
            "RAVEN_TRACE_LOG",
            "RAVEN_LAB_TEST_A",
            "RAVEN_DATA_DIR",
            "ASH_DATA_DIR",
            "RAVEN_INTERNET_LISTEN",
            "RAVEN_P2P_LISTEN",
            "RAVEN_P2P_RELAYS",
            "RAVEN_P2P_RELAY",
            "RAVEN_PEER",
            "ASH_LAN_DIAL",
            "RAVEN_VERBOSE",
            "ASH_VERBOSE",
            "RAVEN_LAB_NETWATCH_EVENTS",
            "RAVEN_LAB_NET_TAG",
            "RAVEN_LAB_P2P_PING",
            "RAVEN_LAB_P2P_LOCAL_CANDIDATES",
            "RAVEN_LAB_P2P_RELAY_ONLY",
            "RAVEN_LAB_CUSTODY_AFTER_MS",
            "RAVEN_LAB_CUSTODY_FETCH_MS",
            "RAVEN_LAB_CUSTODY_WAN",
            "RAVEN_LAB_CUSTODY_PRETEND_OLD",
            "RAVEN_LAB_CUSTODY_BASE_OPS_ONLY",
            "RAVEN_LAB_CUSTODY_HANDOFF",
            "RAVEN_LAB_CUSTODY_FORWARD_MS",
            "RAVEN_LAB_ROUTE_HINTS",
            "RAVEN_LAB_HINTS_NO_ANNOUNCE",
            // Friend relays (Phase 2): off in every case unless it sets them.
            "RAVEN_LAB_FRIEND_RELAY",
            "RAVEN_LAB_FRIEND_RELAY_LISTEN",
            "RAVEN_LAB_RELAY_SELECT",
            "RAVEN_LAB_P2P_PROFILE_RELAY",
            // The cutoff pack's (after Phase 2): its two held gates, the
            // default LAN port it guesses, the gateway and the lab clock.
            "RAVEN_LAB_OFFLINE",
            "RAVEN_LAB_NOISE_PIN",
            "RAVEN_LAB_LAN_DEFAULT_PORT",
            "RAVEN_LAB_LAN_GATEWAY",
            "RAVEN_LAB_CLOCK_FILE",
            "RAVEN_SERVICE_LOG_MAX_BYTES",
            // The privacy pack's: two set below for every profile, the
            // other four only where a case sets them.
            "RAVEN_LAB_AT_REST",
            "RAVEN_LAB_ERASE_ROOT",
            "RAVEN_LAB_AT_REST_KEY_FAULT",
            "RAVEN_LAB_RETENTION_GRACE_MS",
            "RAVEN_LAB_LOGIN_ITEM_ROOT",
            "RAVEN_LAB_LOGIN_ITEM_TOOLS",
            // Phase 3 (P3.5): `--lan-listen auto`'s lab unlock and the C27
            // switch, only where a case sets them.
            "RAVEN_LAB_LAN_AUTO",
            "RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK",
            // Phase 3 (P3.8): the LAN beacon's lab unlock, and (P3.10) its
            // port, family and loopback bus, only where a case sets them.
            "RAVEN_LAB_LAN_BEACON",
            "RAVEN_LAB_LAN_BEACON_PORT",
            "RAVEN_LAB_LAN_BEACON_FAMILY",
            "RAVEN_LAB_LAN_BEACON_BUS",
            // Phase 3 (P3.13): session renewal's lab unlock and the shorter
            // session lifetime, only where a case sets them.
            "RAVEN_LAB_SESSION_RENEWAL",
            "RAVEN_LAB_SESSION_LIFETIME_MS",
            // Phase 5 (P5.3): the horizon's and the letters' lab unlocks,
            // only where a case sets them.
            "RAVEN_LAB_HORIZON",
            "RAVEN_LAB_LETTER",
            // Phase 5 (P5.25-P5.28): the nearby carrier's lab unlock, its
            // ether hub, the public-address allowance, the shorter
            // foreground and the network audit, only where a case sets them.
            "RAVEN_LAB_NEARBY",
            "RAVEN_LAB_NEARBY_ETHER",
            "RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR",
            "RAVEN_LAB_NEARBY_FOREGROUND_MS",
            "RAVEN_LAB_NET_AUDIT",
            // Offline mesh carry Phase 0: the Bluetooth-only node (no LAN,
            // Internet direct, p2p or beacon); no case sets it.
            "RAVEN_LAB_NEARBY_ONLY",
            // Phase 5 (P5.29): the BlueZ btvirt test's opt-in; no node reads
            // it.
            "RAVEN_LAB_BLUEZ_BTVIRT",
            // Phase 4 (P4.1): its lab switches and harness values, only where
            // a case sets them, and none of the caller's proxy settings
            // (RAVEN_P2P_PROXY is `off` below, so this computer's own proxy
            // is never used either).
            "RAVEN_LAB_WSS",
            "RAVEN_LAB_WSS_PROXY",
            "RAVEN_P2P_PROXY",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "RAVEN_LAB_PORT_MAP",
            "RAVEN_LAB_V6_PINHOLE",
            "RAVEN_LAB_NAT_CLASS",
            "RAVEN_LAB_NAT_CLASS_FORCE",
            "RAVEN_LAB_PEER_ROTATION",
            "RAVEN_LAB_PEER_EPOCH_S",
            "RAVEN_LAB_PORTMAP_GATEWAY",
            "RAVEN_LAB_PORTMAP_LIFETIME",
            // Auto-reach: its switches and harness values, only where a case
            // sets them (no case asks a public STUN server).
            "RAVEN_LAB_STUN_DISCOVERY",
            "RAVEN_LAB_SERVERLESS_PUNCH",
            "RAVEN_LAB_STUN_SERVERS",
            "RAVEN_LAB_STUN_REFRESH_S",
            "RAVEN_LAB_PUNCH_SLOT_S",
            // Phase 6a (P6.2): learning's lab unlock, its harness timings and
            // the sealer fault (C73), only where a case sets them.
            "RAVEN_LAB_LEARNING",
            "RAVEN_LAB_LEARNING_TUNE",
            "RAVEN_LAB_LEARNING_SEALER",
            // Phase 6b (P6.21): the security gates' lab unlocks, only where
            // a case sets them.
            "RAVEN_LAB_SECURITY_EVENTS",
            "RAVEN_LAB_SECURITY_RESPONSES",
            "RAVEN_LAB_SUITE_FLOOR",
            "RAVEN_LAB_LINK_PADDING",
            "RAVEN_LAB_LINK_KNOCK",
            "RAVEN_LAB_RANDOM_PORT",
            "RAVEN_LAB_PAIR_SEED",
            "RAVEN_LAB_LOCAL_PROTECTION",
            "RAVEN_LAB_ADVISORY",
            "RAVEN_LAB_RELEASE_BUNDLE",
            "RAVEN_LAB_MESH_UPDATE",
            // Phase 6b (P6.26): the penalty box spares loopback, which
            // every profile here talks over.
            "RAVEN_LAB_SEC_PENALTY_LOOPBACK",
            // Phase 6b (P6.44): the lab release key set, only where a case
            // sets it.
            "RAVEN_LAB_RELEASE_KEYS_FILE",
            // Phase 6b (P6.49): the lab download approval and install word,
            // only where a case sets it.
            "RAVEN_LAB_UPDATE_AUTO_APPROVE",
            // Phase 6b (P6.51): the lab friend that claims a newer notice
            // (C88), only where a case sets it.
            "RAVEN_LAB_UPDATE_CLAIM_NEWER",
            // The Tor onion carrier (lab): its switch, the helper path, the
            // loopback helper and the race's head start, only where a case
            // sets them (C95). No case ever reaches the real Tor network.
            "RAVEN_LAB_TOR",
            "RAVEN_TOR_HELPER",
            "RAVEN_LAB_TOR_LOOPBACK",
            "RAVEN_LAB_TOR_HEAD_START_MS",
            "RAVEN_LAB_TOR_LOOPBACK_STALL",
            "RAVEN_LAB_TOR_LOOPBACK_OBSOLETE",
            "RAVEN_LAB_TOR_LOOPBACK_DELAY_MS",
            // Groups' lab unlock; no case sets it.
            "RAVEN_LAB_GROUPS",
        ] {
            cmd.env_remove(k);
        }
        cmd.env("RAVEN_LAB_AT_REST", "1")
            .env("RAVEN_LAB_ERASE_ROOT", &self.root)
            .env("RAVEN_P2P_PROXY", "off");
        // Release builds have these on since 2026-10. Here they stay closed
        // (a debug build's "0") unless a case opens them, as before the
        // switch-on: no case reaches the real Tor network or asks a public
        // STUN server, and each case's route hints, horizon, groups and
        // friend relay are the ones it asks for.
        cmd.env("RAVEN_LAB_TOR", "0")
            .env("RAVEN_LAB_STUN_DISCOVERY", "0")
            .env("RAVEN_LAB_HORIZON", "0")
            .env("RAVEN_LAB_GROUPS", "0");
        if self.lab_internet {
            cmd.env("RAVEN_LAB_TEST_A", "1");
        }
        cmd.env(
            "RAVEN_LAB_ROUTE_HINTS",
            if self.route_hints { "1" } else { "0" },
        );
        if !self.friend_relays {
            cmd.env("RAVEN_LAB_FRIEND_RELAY", "0");
        }
        if let Some(on) = self.noise_pin {
            cmd.env("RAVEN_LAB_NOISE_PIN", if on { "1" } else { "0" });
        }
        for (k, v) in &self.lab_env {
            cmd.env(k, v);
        }
        if self.friend_relays {
            cmd.env("RAVEN_LAB_FRIEND_RELAY", "1")
                .env("RAVEN_LAB_FRIEND_RELAY_LISTEN", "127.0.0.1:0")
                .env("RAVEN_LAB_P2P_LOCAL_CANDIDATES", "1");
        }
        cmd.env("RAVEN_IDENTITY_BACKEND", "locked-file")
            .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
            .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
            .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0")
            .env("RAVEN_LAB_IPC_PIPE_SUFFIX", &self.pipe_suffix)
            .env("NO_COLOR", "1");
    }

    fn raven(&self, args: &[&str], stdin: Option<&str>) -> Output {
        self.raven_with(args, stdin, &[])
    }

    fn raven_with(&self, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(raven_bin());
        self.env(&mut cmd);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.arg("--data-dir").arg(&self.dir).args(args);
        run_bounded(
            cmd,
            stdin,
            COMMAND_TIMEOUT,
            &format!("{} {:?}", self.name, args),
        )
    }

    fn create(root: &Path, name: &'static str) -> Self {
        Self::create_with(root, name, false)
    }

    fn create_with(root: &Path, name: &'static str, lab_internet: bool) -> Self {
        let mut p = Self::new(root, name, lab_internet);
        p.init();
        p
    }

    /// [`Self::create`] whose own processes never seal it
    /// (`RAVEN_LAB_AT_REST=0` for every one of them): its contact book stays
    /// plain until a daemon started with `RAVEN_LAB_AT_REST=1` in its extra
    /// environment seals it at its start (privacy pack PP.4, C90).
    fn create_plain(root: &Path, name: &'static str) -> Self {
        let mut p = Self::new(root, name, false).with_lab_env("RAVEN_LAB_AT_REST", "0");
        p.init();
        p
    }

    /// `raven init` and `raven prekey publish` in this (new) profile.
    fn init(&mut self) {
        let name = self.name;
        std::fs::create_dir_all(&self.dir).unwrap();
        let init = self.raven(&["init"], None);
        assert!(init.ok, "{name} init failed:\n{}", init.all());
        let field = |key: &str| {
            init.stdout
                .lines()
                .find_map(|l| l.trim().strip_prefix(key).map(str::to_string))
                .unwrap_or_else(|| panic!("{name} init printed no {key}:\n{}", init.all()))
        };
        self.address = field("address=");
        self.pub_hex = field("pub_hex=");
        self.fingerprint = field("fingerprint=");
        let publish = self.raven(&["prekey", "publish"], None);
        assert!(publish.ok, "{name} prekey publish:\n{}", publish.all());
    }

    /// This profile's contact book as JSON text, sealed or plain.
    fn book(&self) -> String {
        book_text(&self.dir)
    }

    /// The profile `root/name`, not created yet ([`profile_dir`] checks it).
    fn new(root: &Path, name: &'static str, lab_internet: bool) -> Self {
        Profile {
            name,
            dir: profile_dir(root, name),
            root: root.to_path_buf(),
            pipe_suffix: pipe_suffix(name),
            address: String::new(),
            pub_hex: String::new(),
            fingerprint: String::new(),
            lab_internet,
            route_hints: false,
            friend_relays: false,
            noise_pin: None,
            lab_env: Vec::new(),
        }
    }

    /// Route hints on for every later process of this profile (its `init`
    /// ran without them, which nothing there reads).
    fn with_route_hints(mut self) -> Self {
        self.route_hints = true;
        self
    }

    /// The noise pin gate (M0) open (`true`) or closed for every later
    /// process of this profile (its debug switch `RAVEN_LAB_NOISE_PIN`).
    fn with_noise_pin(mut self, on: bool) -> Self {
        self.noise_pin = Some(on);
        self
    }

    /// `key=value` for every later process of this profile (one of the lab
    /// switches [`Profile::env`] clears first).
    fn with_lab_env(mut self, key: &'static str, value: &str) -> Self {
        self.lab_env.push((key, value.to_string()));
        self
    }

    /// Friend relays on for every later process of this profile: the debug
    /// switch `RAVEN_LAB_FRIEND_RELAY=1` while
    /// `FRIEND_RELAY_PRODUCTION_ENABLED` is false, route hints (offers ride
    /// RRH1), the friend relay on loopback
    /// (`RAVEN_LAB_FRIEND_RELAY_LISTEN=127.0.0.1:0`, which a daemon's own
    /// environment may change) and loopback addresses as candidates and
    /// offer addresses (`RAVEN_LAB_P2P_LOCAL_CANDIDATES=1`).
    fn with_friend_relays(mut self) -> Self {
        self.route_hints = true;
        self.friend_relays = true;
        self
    }

    /// Consent for this profile's friend relay, what `raven relay offer on`
    /// saves, written straight into node_policy.json (no terminal, nothing
    /// asked; an atomic replace the running raven-node reads at its next
    /// look), with the one address it names (`relay_external`) when given.
    fn relay_offer_on(&self, external: Option<&str>) {
        // A sealed profile keeps `relay_external` in node_policy_peers.rms
        // (privacy pack PP.6): this process opens it with the profile's key.
        if self.dir.join(raven_core::at_rest::META_KEY_FILE).exists() {
            load_profile_key(&self.dir);
        }
        let mut policy = raven_core::node_policy::try_load_policy(&self.dir)
            .unwrap_or_else(|e| panic!("{} node_policy.json: {e}", self.name));
        policy.relay_offer = Some(true);
        if let Some(addr) = external {
            policy.relay_external = vec![addr.to_string()];
        }
        raven_core::node_policy::save_policy(&self.dir, &policy)
            .unwrap_or_else(|e| panic!("{} node_policy.json: {e}", self.name));
    }

    /// Start the daemon and wait until its IPC endpoint and LAN listener are up.
    fn start_service(&self) -> Service {
        self.start_service_with(None)
    }

    /// [`Self::start_service`], plus an Internet direct listener on `internet`
    /// (waited for too) when given.
    fn start_service_with(&self, internet: Option<&str>) -> Service {
        self.start_service_on("127.0.0.1:0", internet)
    }

    /// [`Self::start_service_with`] on a chosen LAN listen address (a restart
    /// that must come back on the same port).
    fn start_service_on(&self, lan_listen: &str, internet: Option<&str>) -> Service {
        self.start_service_env(lan_listen, internet, &[])
    }

    /// [`Self::start_service_on`] with extra environment for the daemon only.
    fn start_service_env(
        &self,
        lan_listen: &str,
        internet: Option<&str>,
        extra_env: &[(&str, &str)],
    ) -> Service {
        let mut cmd = Command::new(NODE);
        self.env(&mut cmd);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.arg("service").arg("--data-dir").arg(&self.dir).args([
            "--lan-listen",
            lan_listen,
            "--ble-listen",
            "127.0.0.1:0",
        ]);
        if let Some(addr) = internet {
            cmd.args(["--internet-listen", addr]);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn raven-node service");
        let log = Arc::new(Log::default());
        log.follow(child.stderr.take().unwrap());
        let mut service = Service {
            child,
            log,
            lan_dial: String::new(),
            internet_dial: String::new(),
            p2p_listeners: 0,
        };
        let ipc = service
            .log
            .wait_for(READY_TIMEOUT, |l| l.contains("raven-node ipc: listening"));
        let lan = service.log.wait_for(READY_TIMEOUT, |l| {
            l.contains("raven-node lan_direct: listen ")
        });
        wait_at_rest(&service, self.name);
        let (Some(_), Some(lan)) = (ipc, lan) else {
            panic!(
                "{} service did not come up within {READY_TIMEOUT:?}:\n{}",
                self.name,
                service.log.text()
            );
        };
        service.lan_dial = lan.rsplit(' ').next().unwrap().trim().to_string();
        if internet.is_some() {
            let inet = service.log.wait_for(READY_TIMEOUT, |l| {
                l.contains("raven-node internet_direct: listen ")
            });
            let Some(inet) = inet else {
                panic!(
                    "{} internet listener did not come up within {READY_TIMEOUT:?}:\n{}",
                    self.name,
                    service.log.text()
                );
            };
            service.internet_dial = inet.rsplit(' ').next().unwrap().trim().to_string();
        }
        // The listener line is printed after bind; one positive ping proves the
        // CLI reaches this daemon (on Windows: this profile's own pipe).
        let ping = self.raven(&["ipc-ping"], None);
        assert!(
            ping.ok,
            "{} ipc-ping failed:\n{}\n{}",
            self.name,
            ping.all(),
            service.log.text()
        );
        service
    }

    /// The daemon on `--lan-listen lan_listen` (`auto:<port>`, or an
    /// address) with `extra_env` for it alone (Phase 3: the LAN switches of
    /// C27-C30), waited for as [`Self::start_service`] waits. Its `lan_dial`
    /// is where this computer dials its first socket: an `auto` listener's
    /// `0.0.0.0:P` at `127.0.0.1:P`.
    fn start_service_lan(&self, lan_listen: &str, extra_env: &[(&str, &str)]) -> Service {
        let mut service = self.start_service_env(lan_listen, None, extra_env);
        service.lan_dial = loopback_dial(&service.lan_dial);
        service
    }

    /// Pin `other` as `tag` (its security code), with `lan_dial` as its LAN
    /// route or none at all (Phase 3: the beacon finds it).
    fn pin_contact(&self, other: &Profile, tag: &str, lan_dial: Option<&str>) {
        let mut args = vec![
            "contact",
            "add",
            "--address",
            &other.address,
            "--pub-hex",
            &other.pub_hex,
            "--petname",
            tag,
            "--tag",
            tag,
            "--verify-fp",
            &other.fingerprint,
        ];
        if let Some(dial) = lan_dial {
            args.extend(["--lan-dial", dial]);
        }
        let out = self.raven(&args, None);
        assert!(
            out.ok && out.stdout.contains("pinned      yes"),
            "{} contact add {tag}:\n{}",
            self.name,
            out.all()
        );
    }

    /// [`Self::start_service`] with the libp2p host on, no listening port
    /// (`--p2p-listen relay` under the debug `RAVEN_LAB_P2P_RELAY_ONLY=1`:
    /// the setting is retired everywhere else) and a reservation on
    /// `relay_via`, waited for.
    fn start_service_p2p(&self, relay_via: &str) -> Service {
        self.start_service_p2p_with(relay_via, true)
    }

    fn start_service_p2p_with(&self, relay_via: &str, wait_reservation: bool) -> Service {
        self.start_service_p2p_opts(&P2pStart {
            listen: "relay",
            relay_via,
            wait_reservation,
            env: &[],
        })
    }

    /// The service with the libp2p host on, as `o` says.
    fn start_service_p2p_opts(&self, o: &P2pStart) -> Service {
        let mut cmd = Command::new(NODE);
        self.env(&mut cmd);
        if o.listen == "relay" {
            // The retired no-listener mode, kept only by this debug switch
            // (without it `relay` listens on 0.0.0.0:7423 and [::]:7423).
            cmd.env("RAVEN_LAB_P2P_RELAY_ONLY", "1");
        }
        for (k, v) in o.env {
            cmd.env(k, v);
        }
        cmd.arg("service").arg("--data-dir").arg(&self.dir).args([
            "--lan-listen",
            "127.0.0.1:0",
            "--ble-listen",
            "127.0.0.1:0",
            "--p2p-listen",
            o.listen,
        ]);
        // One relay, or two separated by a space (C74).
        for via in o.relay_via.split(' ').filter(|v| !v.is_empty()) {
            cmd.args(["--p2p-relay", via]);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn raven-node service");
        let log = Arc::new(Log::default());
        log.follow(child.stderr.take().unwrap());
        let mut service = Service {
            child,
            log,
            lan_dial: String::new(),
            internet_dial: String::new(),
            p2p_listeners: 0,
        };
        let up = service
            .log
            .wait_for(READY_TIMEOUT, |l| l.contains("raven-node p2p: host up"));
        let ipc = service
            .log
            .wait_for(READY_TIMEOUT, |l| l.contains("raven-node ipc: listening"));
        wait_at_rest(&service, self.name);
        let (Some(up), Some(_)) = (up, ipc) else {
            panic!(
                "{} p2p service did not come up within {READY_TIMEOUT:?}:\n{}",
                self.name,
                service.log.text()
            );
        };
        service.p2p_listeners = up
            .split_once("(listeners=")
            .and_then(|(_, rest)| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no listener count in {up:?}"));
        if o.wait_reservation {
            let reserved = service.log.wait_for(READY_TIMEOUT, |l| {
                l.contains("raven-node p2p: reservation accepted")
            });
            assert!(
                reserved.is_some(),
                "{} got no reservation on the relay:\n{}",
                self.name,
                service.log.text()
            );
        }
        let ping = self.raven(&["ipc-ping"], None);
        assert!(ping.ok, "{} ipc-ping failed:\n{}", self.name, ping.all());
        service
    }

    /// This profile's `raven-card/2` line naming `relay_via` (`via=`), or
    /// with route hints on and a relay named, its `raven-card/3` (`relay=`).
    fn p2p_card(&self, relay_via: &str) -> String {
        let card = self.raven(&["whoami", "--card", "--via", relay_via], None);
        assert!(
            card.ok,
            "{} whoami --card --via:\n{}",
            self.name,
            card.all()
        );
        let line = card.stdout.trim().to_string();
        assert_eq!(card.stdout.trim_end().lines().count(), 1, "{}", card.stdout);
        let field = if self.route_hints && line.starts_with("raven-card/3 ") {
            " relay=/"
        } else {
            assert!(line.starts_with("raven-card/2 "), "{line}");
            " via=/"
        };
        assert!(
            line.contains(" p2p=12D3KooW") && line.contains(field),
            "{line}"
        );
        line
    }

    /// Pin `card` (verified fingerprint) as `tag`.
    fn add_card(&self, card: &str, tag: &str, fingerprint: &str) {
        let out = self.raven(
            &[
                "contact",
                "add",
                "--card",
                card,
                "--petname",
                tag,
                "--tag",
                tag,
                "--verify-fp",
                fingerprint,
            ],
            None,
        );
        assert!(
            out.ok,
            "{} contact add --card {tag}:\n{}",
            self.name,
            out.all()
        );
        assert!(out.stdout.contains("pinned      yes"), "{}", out.all());
    }

    fn add_contact(&self, other: &Profile, tag: &str, lan_dial: &str) {
        let out = self.raven(
            &[
                "contact",
                "add",
                "--address",
                &other.address,
                "--pub-hex",
                &other.pub_hex,
                "--petname",
                tag,
                "--tag",
                tag,
                "--lan-dial",
                lan_dial,
            ],
            None,
        );
        assert!(out.ok, "{} contact add {tag}:\n{}", self.name, out.all());
    }

    fn send(&self, tag: &str, text: &str) -> Output {
        self.raven(
            &["send", "--contact", &format!("@{tag}")],
            Some(&format!("{text}\n")),
        )
    }

    fn inbox(&self) -> String {
        let out = self.raven(&["inbox"], None);
        assert!(out.ok, "{} inbox:\n{}", self.name, out.all());
        out.stdout
    }
}

/// The Windows pipe suffix of a new profile: `cm-<pid>-<n>-<name>`, where `n`
/// counts the profiles of this test process. Tests run in parallel in one
/// process and may reuse a name (C1 and C7a once both had an "a"): with the
/// name alone the second daemon could not bind the pipe the first holds (the
/// first instance is exclusive), so it never came up, and its test's CLI
/// could reach the other test's daemon. At most 32 of `[A-Za-z0-9_-]`, which
/// `raven_core::ipc::with_lab_pipe_suffix` requires (a 2-letter name with a
/// 10-digit pid and counter is 27).
fn pipe_suffix(name: &str) -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    pipe_suffix_for(
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        name,
    )
}

fn pipe_suffix_for(pid: u32, n: u32, name: &str) -> String {
    format!("cm-{pid}-{n}-{name}")
}

/// Two profiles with the same name in one test process never share a pipe,
/// and every suffix is one the daemon accepts (a refused one leaves the
/// daemon with no pipe at all). Runs without `--ignored`: no process.
#[test]
fn profiles_with_the_same_name_never_share_a_windows_pipe() {
    let (one, two) = (pipe_suffix("a"), pipe_suffix("a"));
    assert_ne!(one, two);
    let longest = pipe_suffix_for(u32::MAX, u32::MAX, "kq");
    for s in [&one, &two, &longest] {
        assert!(
            raven_core::ipc::with_lab_pipe_suffix("pipe".into(), Some(s), true).is_some(),
            "{s}"
        );
    }
}

/// Files that make a folder a Raven profile (its identity bookkeeping and its
/// contact book).
const PROFILE_MARKERS: [&str; 4] = [
    "identity.backend",
    "identity.binding",
    "keystore.backend",
    "contacts.json",
];

/// Privacy pack PP.4: a daemon says `raven-node at_rest: <state>` once its
/// contact book can be read (the at-rest key loaded and what was plain
/// sealed), or once it knows it cannot. Until then it admits nobody, so a
/// case's first send waits for this line, not for luck.
fn wait_at_rest(service: &Service, name: &str) {
    if service
        .log
        .wait_for(READY_TIMEOUT, |l| l.contains("raven-node at_rest: "))
        .is_none()
    {
        panic!(
            "{name}: the daemon never said its at-rest state within {READY_TIMEOUT:?}:\n{}",
            service.log.text()
        );
    }
}

/// A profile's contact book as JSON text (privacy pack PP.4: sealed, RMS1,
/// once a daemon or a command of this build ran there). This test process
/// opens it with the key every process of a profile here uses: on Unix the
/// lab chat-history key of a debug build with the locked-file backends,
/// never a keychain item (without that environment it stops rather than ask
/// the keystore); on Windows this user's DPAPI, which never prompts.
fn book_text(dir: &Path) -> String {
    let raw = std::fs::read(dir.join(raven_core::contact_book::CONTACTS_FILE))
        .unwrap_or_else(|e| panic!("{}: no contact book: {e}", dir.display()));
    if !raven_core::at_rest::is_sealed(&raw) {
        return String::from_utf8(raw).unwrap();
    }
    load_profile_key(dir);
    let plain = raven_core::contact_book::read_plain(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .expect("the book");
    String::from_utf8(plain.to_vec()).unwrap()
}

/// Load `dir`'s at-rest key into this test process (see [`book_text`]):
/// the lab key of a debug build with the locked-file backends, never a
/// keychain item.
fn load_profile_key(dir: &Path) {
    let lab = ["RAVEN_CHAT_HISTORY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
        .iter()
        .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
    assert!(
        cfg!(windows) || (cfg!(debug_assertions) && lab),
        "reading a sealed file needs a debug build and \
         RAVEN_CHAT_HISTORY_BACKEND=locked-file in the harness's own environment"
    );
    raven_core::at_rest::keys_load_with(dir, raven_core::at_rest::MigratePolicy::Never)
        .unwrap_or_else(|e| panic!("{}: the at-rest key: {e}", dir.display()));
}

/// One of a profile's registered files as text, sealed (privacy pack PP.5:
/// the friend-key files are RMS1 once this build ran there) or plain; empty
/// when it is missing. Opened as [`book_text`] opens the book.
fn sealed_text(dir: &Path, name: &str, kind: raven_core::at_rest::Kind) -> String {
    let path = dir.join(name);
    let Ok(raw) = std::fs::read(&path) else {
        return String::new();
    };
    if !raven_core::at_rest::is_sealed(&raw) {
        return String::from_utf8(raw).unwrap();
    }
    load_profile_key(dir);
    let plain = raven_core::at_rest::load_bytes(dir, &path, kind)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .unwrap_or_default();
    String::from_utf8(plain.to_vec()).unwrap()
}

/// The durable peer certificate cache of a profile as text (empty: none).
fn peer_cert_cache(dir: &Path) -> String {
    sealed_text(
        dir,
        "peer_device_certs.json",
        raven_core::at_rest::Kind::PeerDeviceCerts,
    )
}

/// The noise pin file (M0) a profile holds: `lan_noise_pins.rms` once it is
/// sealed (privacy pack PP.5), `lan_noise_pins.json` before.
fn noise_pin_file(dir: &Path) -> PathBuf {
    let sealed = dir.join(raven_core::lan_noise_pin::NOISE_PIN_SEALED_FILE);
    if sealed.exists() {
        sealed
    } else {
        dir.join(raven_core::lan_noise_pin::NOISE_PIN_FILE)
    }
}

/// A profile's noise pins as JSON text, sealed or plain (empty: none).
fn noise_pins_text(dir: &Path) -> String {
    let path = noise_pin_file(dir);
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    sealed_text(dir, &name, raven_core::at_rest::Kind::NoisePins)
}

/// The profile folder `root/name`, which lies under the test's own temp root
/// (privacy pack PP.1); panics otherwise ([`profile_dir_refusal`]).
fn profile_dir(root: &Path, name: &str) -> PathBuf {
    let home =
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
    if let Some(why) = profile_dir_refusal(root, name, &std::env::temp_dir(), home.as_deref()) {
        panic!("refusing profile {name} under {}: {why}", root.display());
    }
    root.join(name)
}

/// Why `root/name` must not be a profile this harness creates, or `None`: a
/// build of the privacy pack seals the profiles its nodes start in, so `root`
/// is an existing folder strictly inside the system temp folder `temp`, is no
/// Raven profile itself (a live one), and lies outside `~/.raven`; `name` is
/// one plain folder name.
fn profile_dir_refusal(
    root: &Path,
    name: &str,
    temp: &Path,
    home: Option<&Path>,
) -> Option<String> {
    let mut parts = Path::new(name).components();
    if !matches!(
        (parts.next(), parts.next()),
        (Some(std::path::Component::Normal(_)), None)
    ) {
        return Some(format!("{name:?} is not one folder name"));
    }
    let Ok(r) = root.canonicalize() else {
        return Some("the root does not exist".into());
    };
    let Ok(t) = temp.canonicalize() else {
        return Some("the temp folder does not exist".into());
    };
    if r == t || !r.starts_with(&t) {
        return Some(format!("not inside the temp folder {}", t.display()));
    }
    if let Some(raven_home) = home.and_then(|h| h.join(".raven").canonicalize().ok()) {
        if r.starts_with(&raven_home) {
            return Some("inside ~/.raven".into());
        }
    }
    if PROFILE_MARKERS.iter().any(|m| r.join(m).exists()) {
        return Some("the root is a Raven profile".into());
    }
    None
}

/// Privacy pack PP.1, runs without `--ignored` (no process): every process
/// of a profile gets `RAVEN_LAB_AT_REST=1` and its test's root as
/// `RAVEN_LAB_ERASE_ROOT`, never the caller's privacy switches (a relay gets
/// none of them), and a profile outside the test's temp root, in `~/.raven`
/// or in a live profile is refused.
#[test]
fn profiles_stay_under_the_test_root_and_get_the_privacy_switches() {
    let root = tempfile::tempdir().unwrap();
    let p = Profile::new(root.path(), "pa", false);
    assert_eq!(p.dir, root.path().join("pa"));
    let mut cmd = Command::new("raven-env-check");
    p.env(&mut cmd);
    let envs: HashMap<String, Option<String>> = cmd
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert_eq!(envs["RAVEN_LAB_AT_REST"].as_deref(), Some("1"));
    assert_eq!(
        envs["RAVEN_LAB_ERASE_ROOT"].as_deref().map(Path::new),
        Some(root.path())
    );
    let others = [
        "RAVEN_LAB_AT_REST_KEY_FAULT",
        "RAVEN_LAB_RETENTION_GRACE_MS",
        "RAVEN_LAB_LOGIN_ITEM_ROOT",
        "RAVEN_LAB_LOGIN_ITEM_TOOLS",
    ];
    for k in others {
        assert_eq!(envs.get(k), Some(&None), "{k} is removed");
    }
    let relay = relay_node_command();
    let removed: Vec<String> = relay
        .get_envs()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    for k in ["RAVEN_LAB_AT_REST", "RAVEN_LAB_ERASE_ROOT"]
        .iter()
        .chain(&others)
    {
        assert!(removed.iter().any(|r| r == k), "relay keeps {k}");
    }

    let t = tempfile::tempdir().unwrap();
    let temp = t.path().join("tmp");
    let home = t.path().join("home");
    let run = temp.join("run");
    let live = temp.join("live");
    for d in [&run, &live, &home.join(".raven").join("x")] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(live.join("identity.backend"), b"locked-file\n").unwrap();
    let refused = |root: &Path, name: &str, home: &Path| {
        profile_dir_refusal(root, name, &temp, Some(home)).is_some()
    };
    assert!(!refused(&run, "a", &home));
    assert!(refused(&run, "../a", &home), "escapes the root");
    assert!(refused(&run, "a/b", &home));
    assert!(refused(&run, "", &home));
    assert!(refused(&temp, "a", &home), "the temp folder itself");
    assert!(refused(&home, "a", &home), "outside the temp folder");
    assert!(refused(&home.join(".raven").join("x"), "a", &home));
    assert!(refused(&live, "a", &home), "a live profile");
    assert!(refused(&temp.join("missing"), "a", &home));
    // ~/.raven inside the temp folder (a home under it): still refused.
    let inner = temp.join("home");
    std::fs::create_dir_all(inner.join(".raven").join("y")).unwrap();
    assert!(refused(&inner.join(".raven").join("y"), "a", &inner));
}

/// Phase 4 P4.1, runs without `--ignored` (no process): no Phase 4 lab
/// switch or harness value and no proxy setting of the caller's reaches a
/// profile's process or a relay, and each runs with `RAVEN_P2P_PROXY=off`,
/// so a developer computer's proxy never reaches C1-C16.
#[test]
fn phase4_switches_and_proxy_settings_reach_no_process() {
    let removed = [
        "RAVEN_LAB_WSS",
        "RAVEN_LAB_WSS_PROXY",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "RAVEN_LAB_PORT_MAP",
        "RAVEN_LAB_V6_PINHOLE",
        "RAVEN_LAB_NAT_CLASS",
        "RAVEN_LAB_NAT_CLASS_FORCE",
        "RAVEN_LAB_PEER_ROTATION",
        "RAVEN_LAB_PEER_EPOCH_S",
        "RAVEN_LAB_PORTMAP_GATEWAY",
        "RAVEN_LAB_PORTMAP_LIFETIME",
        // Auto-reach's, as in Profile::env (STUN discovery is closed there
        // instead: below).
        "RAVEN_LAB_SERVERLESS_PUNCH",
        "RAVEN_LAB_STUN_SERVERS",
        "RAVEN_LAB_STUN_REFRESH_S",
        "RAVEN_LAB_PUNCH_SLOT_S",
    ];
    let root = tempfile::tempdir().unwrap();
    let mut profile = Command::new("raven-env-check");
    Profile::new(root.path(), "pa", false).env(&mut profile);
    for (what, cmd) in [("profile", profile), ("relay", relay_node_command())] {
        let envs: HashMap<String, Option<String>> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        // Windows folds the case of names, so `https_proxy` and
        // `HTTPS_PROXY` are one entry there.
        let get = |k: &str| {
            envs.iter()
                .find(|(n, _)| n.as_str() == k || (cfg!(windows) && n.eq_ignore_ascii_case(k)))
                .map(|(_, v)| v.as_deref())
        };
        for k in removed {
            assert_eq!(get(k), Some(None), "{what} keeps {k}");
        }
        assert_eq!(get("RAVEN_P2P_PROXY"), Some(Some("off")), "{what}");
        // STUN discovery (on in release builds since 2026-10): a profile's
        // processes run with it closed, so no case asks a public server.
        let stun = if what == "profile" {
            Some(Some("0"))
        } else {
            Some(None)
        };
        assert_eq!(get("RAVEN_LAB_STUN_DISCOVERY"), stun, "{what}");
    }
}

/// How [`Profile::start_service_p2p_opts`] runs the libp2p host.
struct P2pStart<'a> {
    /// `--p2p-listen`: `relay` (no listening port; the harness adds the debug
    /// `RAVEN_LAB_P2P_RELAY_ONLY=1` that keeps the retired mode) or an
    /// address.
    listen: &'a str,
    /// `--p2p-relay` (none when empty; two separated by a space give two).
    relay_via: &'a str,
    /// Also wait for the first `reservation accepted` line.
    wait_reservation: bool,
    /// Extra environment for the daemon only.
    env: &'a [(&'a str, &'a str)],
}

/// Run `cmd` with a hard deadline (killed on expiry; the test then fails).
fn run_bounded(mut cmd: Command, stdin: Option<&str>, timeout: Duration, what: &str) -> Output {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        let _ = pipe.write_all(text.as_bytes());
        // Dropping the pipe closes stdin (EOF ends the message).
    }
    let collect = |stream: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = String::new();
            if let Some(mut s) = stream {
                let _ = s.read_to_string(&mut buf);
            }
            buf
        })
    };
    let out = collect(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err = collect(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let child = Arc::new(Mutex::new(child));
    let waiter = Arc::clone(&child);
    // `try_wait` behind the lock lets the timeout path still kill the child.
    std::thread::spawn(move || loop {
        let done = waiter.lock().unwrap().try_wait();
        match done {
            Ok(Some(status)) => {
                let _ = tx.send(status.success());
                return;
            }
            Ok(None) => std::thread::park_timeout(Duration::from_millis(20)),
            Err(_) => {
                let _ = tx.send(false);
                return;
            }
        }
    });
    let ok = match rx.recv_timeout(timeout) {
        Ok(ok) => ok,
        Err(_) => {
            let _ = child.lock().unwrap().kill();
            panic!(
                "{what} did not finish within {timeout:?}:\n{}\n{}",
                out.join().unwrap_or_default(),
                err.join().unwrap_or_default()
            );
        }
    };
    Output {
        ok,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    }
}

/// `[::1]` when this runner has IPv6 loopback, else `127.0.0.1`.
fn second_loopback() -> &'static str {
    if std::net::TcpListener::bind("[::1]:0").is_ok() {
        "[::1]:0"
    } else {
        eprintln!("note: no IPv6 loopback on this runner; C2 uses 127.0.0.1 for both nodes");
        "127.0.0.1:0"
    }
}

/// The Internet direct lab unlock is needed only while the P1 flag is off;
/// after the flip C2 runs the production path unchanged.
fn internet_lab_unlock() -> bool {
    !raven_core::INTERNET_DIRECT_PRODUCTION_ENABLED
}

fn lab_ready() -> bool {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: the lab locked-file backends need a debug build");
        return false;
    }
    true
}

/// The host's network, which every test's daemons watch. Only C11-linux
/// changes it (a dummy interface: every real OS watcher sees it and acts on
/// it, with an outbox retry and a p2p re-home, which C13's "no network
/// change" check and the relay counts of the p2p cases would catch), so it
/// takes this lock for writing and runs alone; every other test holds it for
/// reading, and they still run in parallel.
static HOST_NETWORK: RwLock<()> = RwLock::new(());

fn shared_host_network() -> RwLockReadGuard<'static, ()> {
    HOST_NETWORK.read().unwrap_or_else(PoisonError::into_inner)
}

fn assert_delivered(from: &str, out: &Output) {
    let all = out.all().to_lowercase();
    assert!(
        out.ok && all.contains("status") && all.contains("delivered"),
        "{from} send was not delivered:\n{}",
        out.all()
    );
}

/// C1 + C3 on one runner. One test so the daemons are started once.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c1_lan_direct_both_ways_and_c3_stranger_is_not_accepted() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create(root.path(), "a");
    let b = Profile::create(root.path(), "b");
    let a_svc = a.start_service();
    let b_svc = b.start_service();

    // ── C1: LAN direct, one send each way ────────────────────────────────
    a.add_contact(&b, "bob", &b_svc.lan_dial);
    b.add_contact(&a, "alice", &a_svc.lan_dial);

    let sent = a.send("bob", "c1 hello from a");
    assert_delivered("a→b", &sent);
    // Positive control for C3 below: a contact's RLB1 lands in the durable
    // peer cache of the dialer.
    let a_cache = peer_cert_cache(&a.dir);
    assert!(
        a_cache.contains(&b.pub_hex),
        "a did not cache b's certificate after a delivered send"
    );
    assert!(
        b.inbox().contains("c1 hello from a"),
        "b inbox misses a's message"
    );

    let sent = b.send("alice", "c1 hello from b");
    assert_delivered("b→a", &sent);
    assert!(
        a.inbox().contains("c1 hello from b"),
        "a inbox misses b's message"
    );
    // `raven status` names how the last delivery to each contact travelled:
    // by petname and in words, never an address (raven-node keeps it in
    // memory: since it started). p2p is off, so there is no REACHABILITY
    // section and the doctor says the host does not run.
    let status = a.raven(&["status"], None);
    let last = status_section(&status.stdout, "LAST DELIVERY");
    let row = status_row(last, "bob")
        .unwrap_or_else(|| panic!("no LAST DELIVERY row for bob:\n{}", status.stdout));
    assert!(
        row.starts_with("same network (LAN), ") && row.ends_with(" ago"),
        "{row}"
    );
    let b_port = b_svc.lan_dial.rsplit(':').next().unwrap();
    assert!(
        !last.contains("127.0.0.1") && !last.contains(&format!(":{b_port}")),
        "{last}"
    );
    assert!(
        status.stdout.contains("(since raven-node started)")
            && !status.stdout.contains("REACHABILITY"),
        "{}",
        status.stdout
    );
    let doctor = a.raven(&["doctor"], None);
    assert!(
        doctor
            .stdout
            .contains("  reach_class: off (p2p host not running)"),
        "{}",
        doctor.all()
    );
    let counted: u32 = status_row(&doctor.stdout, "last_paths:")
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap_or_else(|| panic!("no last_paths line:\n{}", doctor.stdout));
    assert!(counted >= 1, "{}", doctor.stdout);

    // ── C3: a stranger learns nothing but "not accepted" ─────────────────
    let s = Profile::create(root.path(), "s");
    let _s_svc = s.start_service();
    s.add_contact(&b, "bob", &b_svc.lan_dial);
    let refused = s.send("bob", "c3 stranger probe");
    assert!(!refused.ok, "stranger send succeeded:\n{}", refused.all());
    assert!(
        !refused.all().to_lowercase().contains("status: delivered"),
        "{}",
        refused.all()
    );
    assert!(
        refused.all().contains("LINK_NOT_ACCEPTED"),
        "the stranger must see only the fixed refusal:\n{}",
        refused.all()
    );
    let reason = b_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| {
            l.contains("lan_direct inbound") && l.contains("not a local contact")
        })
        .unwrap_or_else(|| panic!("b did not log the refusal:\n{}", b_svc.log.text()));
    assert!(
        !reason.contains(&s.pub_hex) && !reason.contains(&s.address),
        "the refusal log names the stranger: {reason}"
    );
    // B is S's contact, so an RLB1 offer from B would have been persisted in
    // S's durable peer cache. It must not be there: S got no bundle.
    let cache = peer_cert_cache(&s.dir);
    assert!(
        !cache.contains(&b.pub_hex),
        "the stranger received b's certificate:\n{cache}"
    );
    assert!(
        !b.inbox().contains("c3 stranger probe"),
        "b accepted the stranger's message"
    );
    // B's contacts still get through after the refusal.
    let again = a.send("bob", "c1 after the stranger");
    assert_delivered("a→b after c3", &again);
    assert!(b.inbox().contains("c1 after the stranger"));
}

/// C7a (app channel, design §15.4; not C7, which is the netns DCUtR gate of
/// transports design §6.4): two services with no prior session. An
/// agent payload handed to Alice's node pairs in the daemon and is delivered;
/// Bob's node serves it to its one consumer and never as chat; a resubmit
/// with the same ref and body is the same object. Lab unlock on both sides.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c7a_app_channel_pairs_delivers_and_stays_out_of_chat() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create_with(root.path(), "ca", true);
    let b = Profile::create_with(root.path(), "cb", true);
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    a.add_contact(&b, "bob", &b_svc.lan_dial);
    b.add_contact(&a, "alice", &a_svc.lan_dial);

    let submit = |body: &str| {
        a.raven(
            &[
                "lab",
                "app-submit",
                "--to",
                "@bob",
                "--ref",
                "c7-task-1",
                "--body",
                body,
            ],
            None,
        )
    };
    let first = submit("c7 agent task");
    assert!(
        first.ok && first.stdout.contains("app payload queued"),
        "submit:\n{}",
        first.all()
    );
    let deadline = Instant::now() + LOG_TIMEOUT;
    let mut served = String::new();
    while Instant::now() < deadline {
        served = b
            .raven(&["lab", "app-inbox", "--wait-ms", "2000"], None)
            .stdout;
        if served.contains("c7 agent task") {
            break;
        }
    }
    assert!(
        served.contains("c7 agent task"),
        "b never served it:\n{served}"
    );
    assert!(
        !b.inbox().contains("c7 agent task"),
        "an agent payload reached chat"
    );
    let again = submit("c7 agent task");
    assert!(
        again.ok && again.stdout.contains("(duplicate)"),
        "resubmit:\n{}",
        again.all()
    );
    let conflict = submit("another body");
    assert!(
        !conflict.ok && conflict.all().contains("APP_CLIENT_REF_CONFLICT"),
        "{}",
        conflict.all()
    );
}

/// A loopback port that accepts every connection and closes it at once,
/// counting them: a route that dials and never answers (C7f).
struct ClosingPort {
    addr: String,
    accepted: Arc<AtomicUsize>,
}

impl ClosingPort {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stream.is_ok() {
                    count.fetch_add(1, Ordering::SeqCst);
                }
                // Dropped here: closed at once.
            }
        });
        ClosingPort { addr, accepted }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// Is `line` AppSubmit's probe walk `lan_dial <code>, …, internet_dial
/// <code>, p2p_dial offer`: every LAN route, then the Internet route, each
/// dialled and failed (not `skipped`), and the offer on p2p last?
fn probe_walked_past_two(line: &str) -> bool {
    let Some((_, walk)) = line.split_once("raven-node app: probe ") else {
        return false;
    };
    let steps: Vec<&str> = walk.trim().split(", ").collect();
    // A failure code; `skipped` was not dialled.
    let failed = |step: &str, carrier: &str| {
        step.strip_prefix(carrier)
            .and_then(|rest| rest.strip_prefix(' '))
            .is_some_and(|code| {
                !code.is_empty() && code != "skipped" && !code.contains(char::is_whitespace)
            })
    };
    let n = steps.len();
    n >= 3
        && steps[n - 1] == "p2p_dial offer"
        && failed(steps[n - 2], "internet_dial")
        && steps[..n - 2].iter().all(|s| failed(s, "lan_dial"))
}

#[test]
fn the_probe_walk_check_reads_the_log_line() {
    let line = "raven-node app: probe lan_dial CLOSED_EARLY, internet_dial DIAL_FAILED, \
                p2p_dial offer";
    assert!(probe_walked_past_two(line));
    assert!(probe_walked_past_two(
        "raven-node app: probe lan_dial A, lan_dial B, internet_dial C, p2p_dial offer"
    ));
    for no in [
        "raven-node app: probe p2p_dial offer",
        "raven-node app: probe lan_dial A, internet_dial B",
        "raven-node app: probe internet_dial A, p2p_dial offer",
        "raven-node app: probe lan_dial A, internet_dial skipped, p2p_dial offer",
        "raven-node app: probe lan_dial A B, internet_dial C, p2p_dial offer",
        "raven-node app: probe lan_dial A, internet_dial B, p2p_dial DIAL_FAILED",
        "raven-node outbox: lan_dial A, internet_dial B, p2p_dial offer",
    ] {
        assert!(!probe_walked_past_two(no), "{no}");
    }
}

/// C7f (app channel beyond the LAN, design §15.4): two services with no
/// prior session, as C7a, but A's book holds a LAN and an Internet address
/// for B ahead of B's p2p route, each a port that closes every connection
/// at once ([`ClosingPort`]); B's book for A is p2p only, and A's card
/// names no address. A's `lab app-submit` probes both dead routes and
/// pairs on p2p (its probe line is the proof; each port also counts a
/// connection), the payload is delivered on `p2p_dial` and served by B.
/// B's answer rides A's connection (`reversed`) with no probe of B's, which
/// holds the session (RN-6). Neither body reaches chat, and no log names a
/// PeerId. Lab unlock on both sides (the app channel needs it while
/// `APP_CHANNEL_PRODUCTION_ENABLED` is false, whatever the p2p flag).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c7f_app_channel_pairs_past_two_dead_routes_and_answers_by_reversal() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create_with(root.path(), "fa", true);
    let b = Profile::create_with(root.path(), "fb", true);
    // No relay: each listens on a loopback port of its own (as C14).
    let start = |p: &Profile, listen: &str| {
        let svc = p.start_service_p2p_opts(&P2pStart {
            listen,
            relay_via: "",
            wait_reservation: false,
            env: &[],
        });
        assert_eq!(svc.p2p_listeners, 2, "{}:\n{}", p.name, svc.log.text());
        svc
    };
    let a_svc = start(&a, "127.0.0.1:0");
    let (b_port, b_svc) = start_p2p_on_own_port(
        &b,
        &P2pStart {
            listen: "",
            relay_via: "",
            wait_reservation: false,
            env: &[],
        },
    );
    // B's card names B's own address; A's has `p2p=` only.
    let status = b.raven(&["status"], None);
    let b_peer = status_row(&status.stdout, "p2p_peer")
        .unwrap_or_else(|| panic!("no p2p_peer row:\n{}", status.stdout))
        .to_string();
    let b_card = b.p2p_card(&format!("/ip4/127.0.0.1/tcp/{b_port}/p2p/{b_peer}"));
    let card = a.raven(&["whoami", "--card"], None);
    assert!(card.ok, "a whoami --card:\n{}", card.all());
    let a_card = card.stdout.trim().to_string();
    assert!(
        a_card.starts_with("raven-card/2 ")
            && a_card.contains(" p2p=12D3KooW")
            && !a_card.contains(" via="),
        "{a_card}"
    );
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    // Two dead routes ahead of p2p in A's book.
    let (lan, inet) = (ClosingPort::start(), ClosingPort::start());
    let set = a.raven(
        &[
            "contact",
            "set-addr",
            "@bob",
            "--lan",
            &lan.addr,
            "--internet",
            &inet.addr,
        ],
        None,
    );
    assert!(set.ok, "a set-addr:\n{}", set.all());
    let clear = b.raven(
        &[
            "contact", "set-addr", "@alice", "--clear", "lan", "--clear", "internet",
        ],
        None,
    );
    assert!(clear.ok, "b set-addr:\n{}", clear.all());

    let submit = |p: &Profile, to: &str, client_ref: &str, body: &str| {
        let started = Instant::now();
        let out = p.raven(
            &[
                "lab",
                "app-submit",
                "--to",
                to,
                "--ref",
                client_ref,
                "--body",
                body,
            ],
            None,
        );
        (out, started.elapsed())
    };
    let served = |p: &Profile, body: &str| {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let inbox = p
                .raven(&["lab", "app-inbox", "--wait-ms", "2000"], None)
                .stdout;
            if inbox.contains(body) || Instant::now() >= deadline {
                return inbox.contains(body);
            }
        }
    };
    let delivered = |p: &Profile, mid: &str| {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let st = p.raven(&["outbox", "status", mid], None);
            if st.ok && st.stdout.contains("state       delivered") {
                return st;
            }
            assert!(
                Instant::now() < deadline,
                "{} {mid} not delivered within 60 s:\n{}",
                p.name,
                st.all()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    };

    // A to B: no session, so A's node probes every route and pairs.
    let (task, took) = submit(&a, "@bob", "c7f-task", "c7f agent task");
    let dialled = (lan.accepted(), inet.accepted());
    assert!(
        task.ok && task.stdout.contains("app payload queued"),
        "submit:\n{}\n{}",
        task.all(),
        a_svc.log.text()
    );
    assert!(took < Duration::from_secs(45), "the submit took {took:?}");
    let probe = a_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| l.contains("raven-node app: probe "))
        .unwrap_or_else(|| panic!("a logged no probe:\n{}", a_svc.log.text()));
    assert!(probe_walked_past_two(&probe), "{probe}");
    assert!(
        dialled.0 >= 1 && dialled.1 >= 1,
        "the dead routes accepted {dialled:?}"
    );
    assert!(served(&b, "c7f agent task"), "b never served the task");
    let st = delivered(&a, &queued_mid(&task)[..8]);
    assert!(st.stdout.contains("carrier     p2p_dial"), "{}", st.all());

    // B to A: B holds the session, so no probe; it rides A's connection.
    let (answer, _) = submit(&b, "@alice", "c7f-answer", "c7f answer");
    assert!(
        answer.ok && answer.stdout.contains("app payload queued"),
        "answer:\n{}\n{}",
        answer.all(),
        b_svc.log.text()
    );
    assert!(served(&a, "c7f answer"), "a never served the answer");
    let st = delivered(&b, &queued_mid(&answer)[..8]);
    for row in ["carrier     p2p_dial", "path        reversed"] {
        assert!(st.stdout.contains(row), "{row}:\n{}", st.all());
    }
    assert_eq!(
        b_svc.log.count("raven-node app: probe "),
        0,
        "b probed:\n{}",
        b_svc.log.text()
    );

    for (p, svc) in [(&a, &a_svc), (&b, &b_svc)] {
        let chat = p.inbox();
        for body in ["c7f agent task", "c7f answer"] {
            assert!(!chat.contains(body), "{} chat holds {body:?}", p.name);
        }
        assert!(
            !svc.log.text().contains("12D3KooW"),
            "{}'s log names a PeerId:\n{}",
            p.name,
            svc.log.text()
        );
    }
}

/// C2: Internet direct between two services whose contacts hold only Internet
/// routes, both ways, plus a stranger refused (lab gate; transports design
/// §6.4 C2, §7.2).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c2_internet_direct_routes_both_ways_and_stranger_is_refused() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create_with(root.path(), "ia", internet_lab_unlock());
    let b = Profile::create_with(root.path(), "ib", internet_lab_unlock());
    let a_svc = a.start_service_with(Some("127.0.0.1:0"));
    let b_svc = b.start_service_with(Some(second_loopback()));
    eprintln!(
        "C2: a internet={} b internet={} (lab unlock: {})",
        a_svc.internet_dial,
        b_svc.internet_dial,
        internet_lab_unlock()
    );
    assert!(
        a_svc.log.text().contains("dial≠WAN"),
        "missing the lab listen claim:\n{}",
        a_svc.log.text()
    );

    // A imports B from B's card (Internet route only, fingerprint pinned).
    let card = b.raven(&["whoami", "--card", "--inet", &b_svc.internet_dial], None);
    assert!(card.ok, "b whoami --card:\n{}", card.all());
    let card_line = card.stdout.trim();
    assert_eq!(card.stdout.trim_end().lines().count(), 1, "{}", card.stdout);
    assert!(card_line.starts_with("raven-card/1 "), "{card_line}");
    let added = a.raven(
        &[
            "contact",
            "add",
            "--card",
            card_line,
            "--petname",
            "bob",
            "--tag",
            "bob",
            "--verify-fp",
            &b.fingerprint,
        ],
        None,
    );
    assert!(added.ok, "a contact add --card:\n{}", added.all());
    assert!(added.stdout.contains("contact saved"), "{}", added.all());
    // B adds A the classic way, then saves A's Internet route with set-addr.
    let added = b.raven(
        &[
            "contact",
            "add",
            "--address",
            &a.address,
            "--pub-hex",
            &a.pub_hex,
            "--petname",
            "alice",
            "--tag",
            "alice",
        ],
        None,
    );
    assert!(added.ok, "b contact add:\n{}", added.all());
    let set = b.raven(
        &[
            "contact",
            "set-addr",
            "@alice",
            "--internet",
            &a_svc.internet_dial,
        ],
        None,
    );
    assert!(set.ok, "b contact set-addr:\n{}", set.all());
    let a_book = a.book();
    assert!(
        a_book.contains(&format!("\"internet_dial\": \"{}\"", b_svc.internet_dial))
            && a_book.contains("\"lan_dial\": \"\""),
        "a's contact for b must hold only the Internet route:\n{a_book}"
    );

    // B has not verified A (no --verify-fp): Internet delivery needs a pinned
    // contact, so B's send is refused at once and nothing is dialled.
    let a_inbox_before = a.inbox();
    let unverified = b.send("alice", "c2 must wait for verification");
    assert!(!unverified.ok, "{}", unverified.all());
    assert!(
        unverified.all().contains(
            "@alice is not verified: Internet delivery needs the fingerprint checked first"
        ),
        "{}",
        unverified.all()
    );
    assert!(
        unverified.all().contains("CONTACT_NOT_VERIFIED")
            && unverified.all().contains("Nothing was dialled")
            && unverified.all().contains("--verify-fp"),
        "{}",
        unverified.all()
    );
    assert_eq!(a.inbox(), a_inbox_before, "nothing reached a");
    assert!(
        !a_svc.log.text().contains("internet_direct inbound"),
        "a saw no Internet dial at all:\n{}",
        a_svc.log.text()
    );
    // B verifies A's fingerprint and pins it (adding again with --verify-fp
    // keeps the petname, tag and routes).
    let pinned = b.raven(
        &[
            "contact",
            "add",
            "--address",
            &a.address,
            "--pub-hex",
            &a.pub_hex,
            "--verify-fp",
            &a.fingerprint,
        ],
        None,
    );
    assert!(pinned.ok, "b pins a:\n{}", pinned.all());
    assert!(
        pinned.stdout.contains("pinned      yes"),
        "{}",
        pinned.all()
    );

    // No LAN route: `--carrier lan` refuses at once, nothing is dialled.
    let lan_only = a.raven(
        &["send", "--contact", "@bob", "--carrier", "lan"],
        Some("c2 must not go out\n"),
    );
    assert!(!lan_only.ok, "{}", lan_only.all());
    assert!(
        lan_only.all().contains("no reachable lan_dial"),
        "{}",
        lan_only.all()
    );

    // Default carrier (auto) → Internet direct; the carrier is not named.
    let sent = a.send("bob", "c2 hello over internet from a");
    assert_delivered("a→b (internet)", &sent);
    assert!(
        !sent.stdout.contains("carrier="),
        "auto must name the carrier only in verbose mode:\n{}",
        sent.all()
    );
    assert!(
        b.inbox().contains("c2 hello over internet from a"),
        "b inbox misses a's Internet message"
    );
    // The other way, verbose: the carrier is named.
    let sent = b.raven_with(
        &["send", "--contact", "@alice"],
        Some("c2 hello over internet from b\n"),
        &[("RAVEN_VERBOSE", "1")],
    );
    assert_delivered("b→a (internet)", &sent);
    assert!(
        sent.stdout.contains("carrier=internet_dial"),
        "verbose send must name the carrier:\n{}",
        sent.all()
    );
    assert!(
        a.inbox().contains("c2 hello over internet from b"),
        "a inbox misses b's Internet message"
    );
    let status = b.raven(&["status"], None);
    assert!(status.ok, "b status:\n{}", status.all());
    let row = status
        .stdout
        .lines()
        .find(|l| l.trim_start().starts_with("internet "))
        .unwrap_or_else(|| panic!("no internet row in status:\n{}", status.stdout));
    assert!(row.contains("YES"), "{row}");

    // ── Stranger: S holds B's card (verified), B does not know S ─────────
    let s = Profile::create_with(root.path(), "is", internet_lab_unlock());
    let _s_svc = s.start_service();
    let added = s.raven(
        &[
            "contact",
            "add",
            "--card",
            card_line,
            "--petname",
            "bob",
            "--tag",
            "bob",
            "--verify-fp",
            &b.fingerprint,
        ],
        None,
    );
    assert!(added.ok, "s contact add --card:\n{}", added.all());
    let refused = s.send("bob", "c2 stranger probe");
    assert!(!refused.ok, "stranger send succeeded:\n{}", refused.all());
    assert!(
        !refused.stdout.to_lowercase().contains("delivered"),
        "{}",
        refused.all()
    );
    assert!(
        refused.all().contains("LINK_NOT_ACCEPTED"),
        "the stranger must see only the fixed refusal:\n{}",
        refused.all()
    );
    let reason = b_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| {
            l.contains("internet_direct inbound") && l.contains("not a local contact")
        })
        .unwrap_or_else(|| panic!("b did not log the refusal:\n{}", b_svc.log.text()));
    let stranger_logged = Instant::now();
    assert!(
        !reason.contains(&s.pub_hex) && !reason.contains(&s.address),
        "the refusal log names the stranger: {reason}"
    );
    let cache = peer_cert_cache(&s.dir);
    assert!(
        !cache.contains(&b.pub_hex),
        "the stranger received b's certificate:\n{cache}"
    );
    assert!(
        !b.inbox().contains("c2 stranger probe"),
        "b accepted the stranger's message"
    );
    // ── Unverified contact: B adds S but never pins it ───────────────────
    // On the Internet listener such a contact is a stranger: S learns nothing
    // but "not accepted" (no hello, no RLB1), and B logs a key-free reason.
    let added = b.raven(
        &[
            "contact",
            "add",
            "--address",
            &s.address,
            "--pub-hex",
            &s.pub_hex,
            "--petname",
            "sam",
            "--tag",
            "sam",
        ],
        None,
    );
    assert!(added.ok, "b contact add s:\n{}", added.all());
    // Peer-caused refusals are logged once per 10 s window: let the stranger's
    // window close so this refusal gets its own line.
    std::thread::sleep(Duration::from_secs(11).saturating_sub(stranger_logged.elapsed()));
    let refused = s.send("bob", "c2 unverified contact probe");
    assert!(!refused.ok, "unverified send succeeded:\n{}", refused.all());
    assert!(
        !refused.stdout.to_lowercase().contains("delivered"),
        "{}",
        refused.all()
    );
    assert!(
        refused.all().contains("LINK_NOT_ACCEPTED"),
        "an unverified contact must see only the fixed refusal:\n{}",
        refused.all()
    );
    let reason = b_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| {
            l.contains("internet_direct inbound") && l.contains("not verified")
        })
        .unwrap_or_else(|| panic!("b did not log the refusal:\n{}", b_svc.log.text()));
    assert!(
        !reason.contains(&s.pub_hex) && !reason.contains(&s.address),
        "the refusal log names the contact: {reason}"
    );
    let cache = peer_cert_cache(&s.dir);
    assert!(
        !cache.contains(&b.pub_hex),
        "the unverified contact received b's certificate:\n{cache}"
    );
    assert!(
        !b.inbox().contains("c2 unverified contact probe"),
        "b accepted the unverified contact's Internet message"
    );
    // A still gets through after the refusals.
    let again = a.send("bob", "c2 after the stranger");
    assert_delivered("a→b after the stranger", &again);
    assert!(b.inbox().contains("c2 after the stranger"));
}

/// Where [`free_loopback_port`] picks: below every OS's ephemeral range
/// (Linux 32768-60999, macOS and Windows 49152-65535), so no socket another
/// case binds to port 0 (its QUIC endpoint, a dial) can take a picked port
/// between the check and the service's own bind; and above the ports Raven
/// itself uses (7420-7427).
const PICK_PORTS: std::ops::Range<u16> = 20_000..30_000;

/// The next port [`free_loopback_port`] tries: spread by process id, then
/// one after the other, so cases running at once never pick the same one.
static NEXT_PICK: AtomicU32 = AtomicU32::new(u32::MAX);

/// A free loopback TCP port for a service that must restart on the same
/// address, from [`PICK_PORTS`].
fn free_loopback_port() -> u16 {
    pick_loopback_port(false)
}

/// [`free_loopback_port`] for a listener that opens TCP and QUIC on the one
/// port: free for UDP too.
fn free_loopback_tcp_udp_port() -> u16 {
    pick_loopback_port(true)
}

fn pick_loopback_port(udp_too: bool) -> u16 {
    pick_port(|port| {
        let tcp = std::net::TcpListener::bind(("127.0.0.1", port)).is_ok();
        tcp && (!udp_too || std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok())
    })
}

/// A port from [`PICK_PORTS`] free for TCP on every address (`0.0.0.0`,
/// and `[::]` where the runner has IPv6) and, with `udp_too`, for UDP on
/// both as well: an `auto` LAN listener's port, or the LAN beacon's lab
/// port (Phase 3, C27-C30). Each bind is let go before the next (a
/// dual-stack `[::]` would collide with the `0.0.0.0` one).
fn free_any_port(udp_too: bool) -> u16 {
    let v6 = has_ipv6_loopback();
    pick_port(|port| {
        let v4_tcp = std::net::TcpListener::bind(("0.0.0.0", port)).is_ok();
        let v6_tcp = !v6 || std::net::TcpListener::bind(("::", port)).is_ok();
        let v4_udp = !udp_too || std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok();
        let v6_udp = !udp_too || !v6 || std::net::UdpSocket::bind(("::", port)).is_ok();
        v4_tcp && v6_tcp && v4_udp && v6_udp
    })
}

/// The next port of [`PICK_PORTS`] that `free` says is free.
fn pick_port(free: impl Fn(u16) -> bool) -> u16 {
    let span = u32::from(PICK_PORTS.end - PICK_PORTS.start);
    let _ = NEXT_PICK.compare_exchange(
        u32::MAX,
        std::process::id().wrapping_mul(7_919) % span,
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
    for _ in 0..span {
        let at = NEXT_PICK.fetch_add(1, Ordering::SeqCst) % span;
        let port = PICK_PORTS.start + u16::try_from(at).unwrap();
        if free(port) {
            return port;
        }
    }
    panic!("no port in {PICK_PORTS:?} was free");
}

/// Whether this runner has IPv6 loopback (an `auto` listener's `[::]`
/// socket opens only then).
fn has_ipv6_loopback() -> bool {
    std::net::TcpListener::bind("[::1]:0").is_ok()
}

/// The ports the harness picks for listeners that keep their port lie
/// outside every OS's ephemeral range, are free for TCP (and UDP when
/// asked) when picked, and are never picked twice by one process: a port
/// from the ephemeral range could have its UDP side taken by another case's
/// QUIC socket on port 0 before the service binds it (the C12 flake).
/// Runs without `--ignored`: it binds loopback ports for an instant only.
#[test]
fn picked_ports_avoid_the_ephemeral_range_and_repeat_never() {
    let picked: Vec<u16> = (0..16)
        .map(|i| {
            if i % 2 == 0 {
                free_loopback_tcp_udp_port()
            } else {
                free_loopback_port()
            }
        })
        .collect();
    for port in &picked {
        assert!(PICK_PORTS.contains(port) && *port < 32_768, "{port}");
    }
    let mut unique = picked.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), picked.len(), "{picked:?}");
}

/// [`Profile::start_service_p2p_opts`] listening on a loopback port of its
/// own ([`free_loopback_tcp_udp_port`]), for a case that needs the port to
/// stay across a restart or a re-home: started again on another port when
/// another program took the TCP or UDP side first (the host comes up with
/// one listener and says the port `is already in use`). The port, and the
/// service with both listeners.
fn start_p2p_on_own_port(p: &Profile, o: &P2pStart) -> (u16, Service) {
    for _ in 0..3 {
        let port = free_loopback_tcp_udp_port();
        let listen = format!("127.0.0.1:{port}");
        let svc = p.start_service_p2p_opts(&P2pStart {
            listen: &listen,
            ..*o
        });
        if svc.p2p_listeners == 2 {
            return (port, svc);
        }
        let log = svc.log.text();
        assert!(log.contains("is already in use"), "{log}");
        eprintln!("note: {} p2p port {port} was taken; another port", p.name);
    }
    panic!("{}: no loopback port stayed free for TCP and UDP", p.name);
}

/// The 8-hex message id a queued send prints (`mid=1a2b3c4d…`).
fn queued_mid(out: &Output) -> String {
    let all = out.all();
    let at = all
        .find("mid=")
        .unwrap_or_else(|| panic!("no mid= in the queued line:\n{all}"));
    all[at + 4..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect()
}

/// C4: a message staged while B is down is delivered by A's background outbox
/// after both services restart, with no new `raven send` (transports design
/// §6.4 C4, P2a).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c4_outbox_delivers_after_a_restart_without_a_new_send() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create(root.path(), "oa");
    let b = Profile::create(root.path(), "ob");
    let b_listen = format!("127.0.0.1:{}", free_loopback_port());
    let a_svc = a.start_service();
    let b_svc = b.start_service_on(&b_listen, None);
    assert_eq!(b_svc.lan_dial, b_listen);
    a.add_contact(&b, "bob", &b_svc.lan_dial);
    b.add_contact(&a, "alice", &a_svc.lan_dial);
    assert_delivered("a→b (session)", &a.send("bob", "c4 first"));

    // B goes down; A's send is queued and handed to raven-node's outbox, and
    // `raven send` ends right away instead of waiting the peer out.
    drop(b_svc);
    let text = "c4 sent while bob was down";
    let started = Instant::now();
    let queued = a.send("bob", text);
    let took = started.elapsed();
    assert!(!queued.ok, "nothing confirmed it yet:\n{}", queued.all());
    assert!(
        queued
            .all()
            .contains("raven-node keeps trying in the background until"),
        "{}",
        queued.all()
    );
    assert!(took < Duration::from_secs(10), "raven send took {took:?}");
    let mid = queued_mid(&queued);
    assert_eq!(mid.len(), 8, "{mid}");
    let status = a.raven(&["outbox", "status", &mid], None);
    assert!(status.ok, "{}", status.all());
    assert!(
        ["state       queued", "state       sent", "state       held"]
            .iter()
            .any(|s| status.stdout.contains(s)),
        "{}",
        status.all()
    );

    // Kill A after staging: the schedule is in memory only, the staged bytes
    // are in A's session store. B stays down for a few seconds (the scenario,
    // not a synchronisation), then A comes back first (its rebuilt outbox
    // tries, finds B down and backs off), then B on its old port.
    drop(a_svc);
    std::thread::sleep(Duration::from_secs(3));
    let a_svc = a.start_service();
    assert!(
        a_svc
            .log
            .wait_for(READY_TIMEOUT, |l| l.contains("raven-node outbox: running"))
            .is_some(),
        "a's outbox did not start:\n{}",
        a_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(2));
    let b_svc = b.start_service_on(&b_listen, None);

    // No new send: A's outbox delivers on its next retry (5 s doubling).
    let deadline = Instant::now() + Duration::from_secs(90);
    let delivered = loop {
        let st = a.raven(&["outbox", "status", &mid], None);
        if st.ok && st.stdout.contains("state       delivered") {
            break st;
        }
        assert!(
            Instant::now() < deadline,
            "not delivered within 90 s:\n{}\n{}\n{}",
            st.all(),
            a_svc.log.text(),
            b_svc.log.text()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    assert!(
        delivered.stdout.contains("history     delivered"),
        "{}",
        delivered.all()
    );
    assert!(
        delivered.stdout.contains("carrier     lan_dial"),
        "{}",
        delivered.all()
    );
    let inbox = b.inbox();
    assert_eq!(
        inbox.matches(text).count(),
        1,
        "exactly once on b:\n{inbox}"
    );
    let list = a.raven(&["outbox", "list"], None);
    assert!(list.ok, "{}", list.all());
    assert!(
        list.stdout.contains("Nothing waiting"),
        "nothing left to retry:\n{}",
        list.all()
    );
    // The next send needs nothing from the outbox and is delivered as usual.
    assert_delivered("a→b after c4", &a.send("bob", "c4 after the restart"));
    assert_eq!(b.inbox().matches(text).count(), 1, "still exactly once");
}

/// One field of `raven outbox status` (`  attempts    4`).
fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|l| l.trim().strip_prefix(key).map(str::trim))
}

fn status_attempts(status: &Output) -> u32 {
    status_field(&status.stdout, "attempts")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// `next try` in seconds (`now` is 0, `in 23 s`, `in 4 min`).
fn status_next_try_secs(status: &Output) -> Option<u64> {
    let v = status_field(&status.stdout, "next try")?;
    if v == "now" {
        return Some(0);
    }
    let v = v.strip_prefix("in ")?;
    if let Some(s) = v.strip_suffix(" s") {
        return s.parse().ok();
    }
    v.strip_suffix(" min")?.parse::<u64>().ok().map(|m| m * 60)
}

/// Append `text` to the file at `path` (a lab netwatch event file).
fn append(path: &Path, text: &str) {
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(text.as_bytes()).unwrap();
}

/// Polls `pred` until it holds (`true`) or `timeout` passed (`false`).
fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if pred() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// `raven outbox status <mid>` once the message has had `at_least` attempts.
fn wait_attempts(p: &Profile, mid: &str, at_least: u32, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        let st = p.raven(&["outbox", "status", mid], None);
        assert!(st.ok, "{}", st.all());
        if status_attempts(&st) >= at_least {
            return st;
        }
        assert!(
            Instant::now() < deadline,
            "fewer than {at_least} attempts within {timeout:?}:\n{}",
            st.all()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// C11: a change of A's network (netwatch, fed by the debug lab event file)
/// retries A's queued message at once on a fresh backoff, and B's netwatch
/// opens the real OS watcher on this runner (transports design §6.4 C11, G1).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c11_network_change_retries_the_outbox_at_once_on_a_fresh_backoff() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create(root.path(), "na");
    let b = Profile::create(root.path(), "nb");
    let net = root.path().join("a-net.txt");
    std::fs::write(&net, "up 192.0.2.10/24\n").unwrap();
    let net_path = net.to_string_lossy().into_owned();
    let b_listen = format!("127.0.0.1:{}", free_loopback_port());
    let a_svc = a.start_service_env(
        "127.0.0.1:0",
        None,
        &[("RAVEN_LAB_NETWATCH_EVENTS", &net_path)],
    );
    let b_svc = b.start_service_on(&b_listen, None);
    assert!(
        a_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l
                .contains("raven-node netwatch: watching (1 network)"))
            .is_some(),
        "a's netwatch read no lab baseline:\n{}",
        a_svc.log.text()
    );
    // B runs the real if-watch backend (netlink, SCDynamicStore or
    // NotifyIpInterfaceChange): it must open on this runner.
    assert!(
        b_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l
                .contains("raven-node netwatch: watching ("))
            .is_some(),
        "b's OS network watcher did not start:\n{}",
        b_svc.log.text()
    );
    a.add_contact(&b, "bob", &b_svc.lan_dial);
    b.add_contact(&a, "alice", &a_svc.lan_dial);
    assert_delivered("a→b (session)", &a.send("bob", "c11 first"));

    // B goes down; A's message is queued and backs off (5 s doubling).
    drop(b_svc);
    let text = "c11 sent while bob was down";
    let queued = a.send("bob", text);
    assert!(!queued.ok, "nothing confirmed it yet:\n{}", queued.all());
    let mid = queued_mid(&queued);
    let status = || {
        let st = a.raven(&["outbox", "status", &mid], None);
        assert!(st.ok, "{}", st.all());
        st
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    let backed_off = loop {
        let st = status();
        if status_attempts(&st) >= 4 {
            break st;
        }
        assert!(
            Instant::now() < deadline,
            "fewer than 4 attempts within 120 s:\n{}\n{}",
            st.all(),
            a_svc.log.text()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let attempts = status_attempts(&backed_off);
    let waiting = status_next_try_secs(&backed_off);
    assert!(
        waiting.is_some_and(|s| s >= 15),
        "after 4 failures the next try is 20-60 s away:\n{}",
        backed_off.all()
    );

    // A's network changes: one decision after the burst quiets (2 s), every
    // contact due within 5 s on a fresh backoff.
    let mut file = std::fs::OpenOptions::new().append(true).open(&net).unwrap();
    file.write_all(b"down 192.0.2.10/24\nup 198.51.100.7/24\n")
        .unwrap();
    drop(file);
    let changed_at = Instant::now();
    let line = a_svc.log.wait_for(Duration::from_secs(10), |l| {
        l.contains("raven-node netwatch: network changed (")
    });
    let Some(line) = line else {
        panic!("no network change within 10 s:\n{}", a_svc.log.text());
    };
    assert!(
        line.contains("network changed (1 new, 1 gone, 1 now): retrying"),
        "{line}"
    );
    let retried = loop {
        let st = status();
        if status_attempts(&st) > attempts && status_next_try_secs(&st).is_some_and(|s| s <= 8) {
            break st;
        }
        assert!(
            changed_at.elapsed() < Duration::from_secs(12),
            "no immediate retry on a fresh backoff within 12 s (was {attempts} attempts, \
             next try {waiting:?} s):\n{}\n{}",
            st.all(),
            a_svc.log.text()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    assert!(status_attempts(&retried) >= 5, "{}", retried.all());

    // B comes back on its old port: A's next (short) retry delivers.
    let b_svc = b.start_service_on(&b_listen, None);
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let st = status();
        if st.stdout.contains("state       delivered") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "not delivered within 40 s of b's return:\n{}\n{}\n{}",
            st.all(),
            a_svc.log.text(),
            b_svc.log.text()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(b.inbox().matches(text).count(), 1, "exactly once on b");
    assert_eq!(
        a_svc
            .log
            .text()
            .matches("raven-node netwatch: network changed")
            .count(),
        1,
        "exactly one acted-on change:\n{}",
        a_svc.log.text()
    );
}

/// G1 on the real netlink path (Linux only, opt-in with
/// `RAVEN_HARNESS_REAL_NETCHANGE=1`; needs passwordless sudo, as on the
/// hosted runners): an address added on a dummy interface is one acted-on
/// change.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c11_a_real_address_change_is_noticed_on_linux() {
    if !lab_ready() {
        return;
    }
    if !cfg!(target_os = "linux")
        || std::env::var("RAVEN_HARNESS_REAL_NETCHANGE").as_deref() != Ok("1")
    {
        eprintln!("skipped: set RAVEN_HARNESS_REAL_NETCHANGE=1 on Linux (uses sudo ip link)");
        return;
    }
    // Alone: the dummy interface is a change for every daemon on this host.
    let _net = HOST_NETWORK.write().unwrap_or_else(PoisonError::into_inner);
    struct Dummy;
    impl Drop for Dummy {
        fn drop(&mut self) {
            let _ = Command::new("sudo")
                .args(["ip", "link", "del", "rvnw0"])
                .status();
        }
    }
    let sudo = |args: &[&str]| {
        let ok = Command::new("sudo")
            .args(args)
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "sudo {args:?} failed");
    };
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create(root.path(), "ra");
    let a_svc = a.start_service();
    assert!(
        a_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l
                .contains("raven-node netwatch: watching ("))
            .is_some(),
        "{}",
        a_svc.log.text()
    );
    let _dummy = Dummy;
    sudo(&["ip", "link", "add", "rvnw0", "type", "dummy"]);
    sudo(&["ip", "addr", "add", "192.0.2.10/24", "dev", "rvnw0"]);
    sudo(&["ip", "link", "set", "rvnw0", "up"]);
    let line = a_svc.log.wait_for(Duration::from_secs(10), |l| {
        l.contains("raven-node netwatch: network changed (")
    });
    assert!(
        line.as_deref()
            .is_some_and(|l| l.contains("network changed (1 new, 0 gone")),
        "{line:?}:\n{}",
        a_svc.log.text()
    );
}

/// The p2p lab unlock is needed only while the P3 flag is off.
fn p2p_lab_unlock() -> bool {
    !raven_core::P2P_PRODUCTION_ENABLED
}

/// The `listen_addrs` of a relay status file.
fn listen_addrs(status: &serde_json::Value) -> Vec<String> {
    status["listen_addrs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// One running `raven-node relay`; killed when dropped.
struct Relay {
    child: Child,
    log: Arc<Log>,
    dir: PathBuf,
    /// `/ip4/127.0.0.1/tcp/<port>/p2p/<relay PeerId>`.
    via: String,
    /// `/ip4/127.0.0.1/udp/<port>/quic-v1/p2p/<relay PeerId>`.
    quic_via: String,
    /// With [`RelayOpts::wss`]: `/ip4/127.0.0.1/tcp/<port>/tls/ws/p2p/<relay
    /// PeerId>`, the two-protocol listener (RWS1 §6), whose port is not
    /// [`Self::via`]'s; empty otherwise.
    wss_via: String,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// How [`Relay::start_with`] runs `raven-node relay`.
struct RelayStart<'a> {
    /// Its folder under the test's root (its own key).
    name: &'a str,
    /// More flags after `--listen 127.0.0.1:0` (or the test's own
    /// `--listen`): `--also-tcp`, `--public-host`, … (C24).
    args: &'a [&'a str],
    /// Phase 4 listeners ([`RelayOpts`]).
    opts: RelayOpts,
}

/// Phase 4 listeners of a [`Relay`].
#[derive(Clone, Copy, Debug, Default)]
struct RelayOpts {
    /// `--wss 127.0.0.1:0` with the WSS gate's lab switch
    /// (`RAVEN_LAB_WSS=1` while `WSS_PRODUCTION_ENABLED` is false): a
    /// two-protocol listener on a port of its own, recorded as
    /// [`Relay::wss_via`] (C40, C41).
    wss: bool,
}

/// The WSS lab switch is needed only while the Phase 4 flag is off; it
/// also needs the lab unlock (`RAVEN_LAB_TEST_A=1`).
fn wss_lab_unlock() -> bool {
    !raven_core::WSS_PRODUCTION_ENABLED
}

/// `raven-node` with a relay's environment: the debug lab unlock while the
/// P3 flag is off, none of the caller's settings, and (proof that the relay
/// needs no keystore) no identity backend at all. `relay`, `relay --check`
/// and `relay-probe` all run this way.
fn relay_node_command() -> Command {
    let mut cmd = Command::new(NODE);
    for k in [
        "RAVEN_LAB_TEST_A",
        "RAVEN_DATA_DIR",
        "ASH_DATA_DIR",
        "RAVEN_LAB_P2P_PING",
        "RAVEN_LAB_P2P_LOCAL_CANDIDATES",
        "RAVEN_LAB_P2P_RELAY_ONLY",
        "RAVEN_LAB_ROUTE_HINTS",
        "RAVEN_LAB_FRIEND_RELAY",
        "RAVEN_LAB_FRIEND_RELAY_LISTEN",
        "RAVEN_LAB_RELAY_SELECT",
        "RAVEN_LAB_P2P_PROFILE_RELAY",
        "RAVEN_LAB_OFFLINE",
        "RAVEN_LAB_NOISE_PIN",
        "RAVEN_LAB_LAN_DEFAULT_PORT",
        "RAVEN_LAB_LAN_GATEWAY",
        "RAVEN_LAB_CLOCK_FILE",
        "RAVEN_SERVICE_LOG_MAX_BYTES",
        "RAVEN_LAB_AT_REST",
        "RAVEN_LAB_ERASE_ROOT",
        "RAVEN_LAB_AT_REST_KEY_FAULT",
        "RAVEN_LAB_RETENTION_GRACE_MS",
        "RAVEN_LAB_LOGIN_ITEM_ROOT",
        "RAVEN_LAB_LOGIN_ITEM_TOOLS",
        // Phase 3 (P3.12): the LAN listener's and the LAN beacon's lab
        // switches; a relay runs neither.
        "RAVEN_LAB_LAN_AUTO",
        "RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK",
        "RAVEN_LAB_LAN_BEACON",
        "RAVEN_LAB_LAN_BEACON_PORT",
        "RAVEN_LAB_LAN_BEACON_FAMILY",
        "RAVEN_LAB_LAN_BEACON_BUS",
        // Phase 3 (P3.13): session renewal's; a relay runs none.
        "RAVEN_LAB_SESSION_RENEWAL",
        "RAVEN_LAB_SESSION_LIFETIME_MS",
        // Phase 5 (P5.3): the horizon's and the letters'; a relay holds no
        // message.
        "RAVEN_LAB_HORIZON",
        "RAVEN_LAB_LETTER",
        // Phase 5 (P5.28): the nearby carrier's; a relay has no radio.
        "RAVEN_LAB_NEARBY",
        "RAVEN_LAB_NEARBY_ETHER",
        "RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR",
        "RAVEN_LAB_NEARBY_FOREGROUND_MS",
        "RAVEN_LAB_NET_AUDIT",
        "RAVEN_LAB_NEARBY_ONLY",
        "RAVEN_LAB_BLUEZ_BTVIRT",
        // Phase 3 (P3.22): friend custody's (the WAN switch among them); a
        // relay holds no mail.
        "RAVEN_LAB_CUSTODY_AFTER_MS",
        "RAVEN_LAB_CUSTODY_FETCH_MS",
        "RAVEN_LAB_CUSTODY_WAN",
        "RAVEN_LAB_CUSTODY_PRETEND_OLD",
        "RAVEN_LAB_CUSTODY_BASE_OPS_ONLY",
        "RAVEN_LAB_CUSTODY_HANDOFF",
        "RAVEN_LAB_CUSTODY_FORWARD_MS",
        "RAVEN_IDENTITY_BACKEND",
        // Phase 4 (P4.1), as in Profile::env.
        "RAVEN_LAB_WSS",
        "RAVEN_LAB_WSS_PROXY",
        "RAVEN_P2P_PROXY",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "RAVEN_LAB_PORT_MAP",
        "RAVEN_LAB_V6_PINHOLE",
        "RAVEN_LAB_NAT_CLASS",
        "RAVEN_LAB_NAT_CLASS_FORCE",
        "RAVEN_LAB_PEER_ROTATION",
        "RAVEN_LAB_PEER_EPOCH_S",
        "RAVEN_LAB_PORTMAP_GATEWAY",
        "RAVEN_LAB_PORTMAP_LIFETIME",
        // Auto-reach's, as in Profile::env.
        "RAVEN_LAB_STUN_DISCOVERY",
        "RAVEN_LAB_SERVERLESS_PUNCH",
        "RAVEN_LAB_STUN_SERVERS",
        "RAVEN_LAB_STUN_REFRESH_S",
        "RAVEN_LAB_PUNCH_SLOT_S",
        // Phase 6a (P6.2): learning's; a relay learns nothing.
        "RAVEN_LAB_LEARNING",
        "RAVEN_LAB_LEARNING_TUNE",
        "RAVEN_LAB_LEARNING_SEALER",
        // Phase 6b (P6.21): the security gates'; a relay opens none.
        "RAVEN_LAB_SECURITY_EVENTS",
        "RAVEN_LAB_SECURITY_RESPONSES",
        "RAVEN_LAB_SUITE_FLOOR",
        "RAVEN_LAB_LINK_PADDING",
        "RAVEN_LAB_LINK_KNOCK",
        "RAVEN_LAB_RANDOM_PORT",
        "RAVEN_LAB_PAIR_SEED",
        "RAVEN_LAB_LOCAL_PROTECTION",
        "RAVEN_LAB_ADVISORY",
        "RAVEN_LAB_RELEASE_BUNDLE",
        "RAVEN_LAB_MESH_UPDATE",
        "RAVEN_LAB_SEC_PENALTY_LOOPBACK",
        "RAVEN_LAB_RELEASE_KEYS_FILE",
        "RAVEN_LAB_UPDATE_AUTO_APPROVE",
        "RAVEN_LAB_UPDATE_CLAIM_NEWER",
    ] {
        cmd.env_remove(k);
    }
    if p2p_lab_unlock() {
        cmd.env("RAVEN_LAB_TEST_A", "1");
    }
    cmd.env("NO_COLOR", "1").env("RAVEN_P2P_PROXY", "off");
    cmd
}

impl Relay {
    fn start(root: &Path) -> Self {
        Self::start_named(root, "relay")
    }

    /// [`Self::start`] in its own folder `root/<name>` (its own key), for a
    /// test with more than one relay (C18).
    fn start_named(root: &Path, name: &str) -> Self {
        Self::start_with(
            root,
            RelayStart {
                name,
                args: &[],
                opts: RelayOpts::default(),
            },
        )
    }

    /// The relay as `o` says, once its status file names a TCP and a QUIC
    /// listen address (and with [`RelayOpts::wss`] a `/tls/ws` one). Without
    /// a `--listen` in `o.args` it listens on `127.0.0.1:0`.
    fn start_with(root: &Path, o: RelayStart) -> Self {
        let dir = profile_dir(root, o.name);
        std::fs::create_dir_all(&dir).unwrap();
        let mut cmd = relay_node_command();
        cmd.arg("relay").arg("--data-dir").arg(&dir);
        if !o.args.contains(&"--listen") {
            cmd.args(["--listen", "127.0.0.1:0"]);
        }
        if o.opts.wss {
            cmd.args(["--wss", "127.0.0.1:0"]);
            if wss_lab_unlock() {
                cmd.env("RAVEN_LAB_TEST_A", "1").env("RAVEN_LAB_WSS", "1");
            }
        }
        cmd.args(o.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut relay = Self::spawn(cmd, dir, READY_TIMEOUT);
        // The WSS listener's port is listed in both forms (`…/tls/ws`, and
        // plain: it takes raw libp2p too); `via` is another TCP port's.
        let wss_port = |s: &serde_json::Value| -> Option<String> {
            listen_addrs(s)
                .into_iter()
                .find_map(|t| Some(t.strip_suffix("/tls/ws")?.rsplit('/').next()?.to_string()))
        };
        let listening = |s: &serde_json::Value, kind: &str| -> Option<String> {
            let wss = wss_port(s).map(|p| format!("/tcp/{p}"));
            listen_addrs(s).into_iter().find(|t| {
                t.contains(kind)
                    && !t.ends_with("/tls/ws")
                    && wss.as_ref().is_none_or(|w| !t.ends_with(w.as_str()))
            })
        };
        let status = relay.wait_status(|s| {
            listening(s, "/tcp/").is_some()
                && listening(s, "/quic-v1").is_some()
                && wss_port(s).is_some() == o.opts.wss
        });
        let peer = status["peer_id"].as_str().unwrap();
        relay.via = format!("{}/p2p/{peer}", listening(&status, "/tcp/").unwrap());
        relay.quic_via = format!("{}/p2p/{peer}", listening(&status, "/quic-v1").unwrap());
        if let Some(port) = wss_port(&status) {
            relay.wss_via = format!("/ip4/127.0.0.1/tcp/{port}/tls/ws/p2p/{peer}");
        }
        relay
    }

    /// Spawn `cmd` (stderr piped) and wait for its `up` line. The guard exists
    /// before the wait, so a relay that never comes up is killed when the
    /// assert unwinds: a bare `Child` is not killed on drop, and the relay
    /// would outlive the test, still listening.
    fn spawn(mut cmd: Command, dir: PathBuf, ready: Duration) -> Self {
        let mut child = cmd.spawn().expect("spawn raven-node relay");
        let log = Arc::new(Log::default());
        log.follow(child.stderr.take().unwrap());
        let relay = Relay {
            child,
            log,
            dir,
            via: String::new(),
            quic_via: String::new(),
            wss_via: String::new(),
        };
        let up = relay
            .log
            .wait_for(ready, |l| l.contains("raven-node relay: up"));
        assert!(up.is_some(), "relay did not come up:\n{}", relay.log.text());
        relay
    }

    /// The relay's status file once `pred` holds (it is rewritten every 2 s).
    fn wait_status(&self, pred: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let raw =
                std::fs::read_to_string(self.dir.join("relay_status.json")).unwrap_or_default();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                if pred(&v) {
                    return v;
                }
            }
            assert!(
                Instant::now() < deadline,
                "relay status never matched:\n{raw}\n{}",
                self.log.text()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// `raven --data-dir <relay dir> relay allow --card <card>`.
    fn allow(&self, as_profile: &Profile, card: &str) {
        self.allow_args(as_profile, &["--card", card]);
    }

    /// `raven --data-dir <relay dir> relay allow <PeerId>` (a peer with no
    /// Raven identity, such as the C15 and C16 spies).
    fn allow_peer(&self, as_profile: &Profile, peer: &str) {
        self.allow_args(as_profile, &[peer]);
    }

    fn allow_args(&self, as_profile: &Profile, args: &[&str]) {
        let out = self.cli(as_profile, &[&["relay", "allow"], args].concat());
        assert!(out.ok, "relay allow:\n{}", out.all());
    }

    /// `raven --data-dir <relay dir> <args>`, with `as_profile`'s
    /// environment.
    fn cli(&self, as_profile: &Profile, args: &[&str]) -> Output {
        let mut cmd = Command::new(raven_bin());
        as_profile.env(&mut cmd);
        cmd.arg("--data-dir").arg(&self.dir).args(args);
        run_bounded(
            cmd,
            None,
            COMMAND_TIMEOUT,
            &format!("relay folder {args:?}"),
        )
    }

    /// Ask the relay to stop (SIGTERM, as systemd and launchd do) and wait at
    /// most `within` for it to exit; `None` when it is still running.
    #[cfg(unix)]
    fn terminate(&mut self, within: Duration) -> Option<std::process::ExitStatus> {
        let pid = self.child.id().to_string();
        let sent = Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("run kill");
        assert!(sent.success(), "kill -TERM {pid} failed");
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().expect("relay wait") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// A relay that never says `up` does not outlive its failed start. The
/// stand-in (silent on stderr) holds a pipe's only write end as its stdout,
/// so the read end sees EOF once it is gone. Runs without `--ignored`.
#[test]
fn a_relay_that_never_comes_up_is_killed() {
    let (mut gone, held) = std::io::pipe().unwrap();
    let mut cmd = if cfg!(windows) {
        let mut cmd = Command::new("ping");
        cmd.args(["-n", "120", "127.0.0.1"]);
        cmd
    } else {
        let mut cmd = Command::new("sleep");
        cmd.arg("120");
        cmd
    };
    cmd.stdin(Stdio::null()).stdout(held).stderr(Stdio::piped());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        Relay::spawn(cmd, path, Duration::from_secs(1))
    }));
    assert!(started.is_err(), "the stand-in never says up");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut gone, &mut std::io::sink());
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(20)).is_ok(),
        "the relay outlived its failed start"
    );
}

/// A TCP proxy in front of one address that records every byte it relays,
/// both directions (capped), for the C6 capture check. [`Self::cut_existing`]
/// silences the paths open so far (C12, C13); [`Self::set_mode`] decides
/// what happens to new ones (C22). [`Self::start_split`] also keeps each
/// connection's two directions apart (C86: message lengths).
struct RecordingProxy {
    addr: std::net::SocketAddr,
    seen: Arc<Mutex<Vec<u8>>>,
    /// [`Self::start_split`]: each connection's bytes from the client and
    /// from the target, in accept order (capped); `None` otherwise.
    split: Option<Arc<Mutex<Vec<SplitLogs>>>>,
    /// Each connection keeps the value it was accepted under; a pump whose
    /// value is stale drops what it reads.
    generation: Arc<AtomicU64>,
    /// The generation of every connection still open (either pump running).
    open: Arc<Mutex<HashMap<u64, u64>>>,
    /// The [`ProxyMode`] new connections get (its `as u8`).
    mode: Arc<AtomicU8>,
    /// Connections accepted so far, whatever their mode, and bytes read
    /// and dropped (on a held or cut connection): C74's dials that still
    /// reach a relay that sleeps.
    accepted: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

/// What a [`RecordingProxy`] does with a new connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyMode {
    /// Pass it on, recorded (the default).
    Forward,
    /// Accept it and hold it open, reading and dropping everything: pings
    /// and handshakes time out as they do towards a computer that went to
    /// sleep, on all three OSes (Windows has no SIGSTOP).
    Blackhole,
    /// Close it at once, like a host that is gone.
    Refuse,
    /// Pass it on, recorded, only when its first byte is a TLS record
    /// (0x16); close any other before a byte is passed on, as a network that
    /// lets only TLS out does (C40: a raw libp2p dial fails, WSS gets
    /// through).
    TlsOnly,
}

const PROXY_RECORD_CAP: usize = 64 << 20;
/// What a split [`RecordingProxy`] keeps of one direction of a connection.
const PROXY_SPLIT_CAP: usize = 4 << 20;
/// One connection through a split [`RecordingProxy`]: what the client sent,
/// what the target sent.
type SplitLogs = [Arc<Mutex<Vec<u8>>>; 2];

impl RecordingProxy {
    fn start(target: std::net::SocketAddr) -> Self {
        Self::start_with(target, false)
    }

    /// [`Self::start`] that keeps each connection's directions apart
    /// ([`Self::messages`]).
    fn start_split(target: std::net::SocketAddr) -> Self {
        Self::start_with(target, true)
    }

    fn start_with(target: std::net::SocketAddr, split: bool) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let split = split.then(|| Arc::new(Mutex::new(Vec::new())));
        let conns = split.clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let generation = Arc::new(AtomicU64::new(0));
        let open = Arc::new(Mutex::new(HashMap::new()));
        let mode = Arc::new(AtomicU8::new(ProxyMode::Forward as u8));
        let accepted = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let record = Arc::clone(&seen);
        let current = Arc::clone(&generation);
        let tracked = Arc::clone(&open);
        let now_mode = Arc::clone(&mode);
        let counted = Arc::clone(&accepted);
        let lost = Arc::clone(&dropped);
        std::thread::spawn(move || {
            for (number, client) in (0u64..).zip(listener.incoming()) {
                let Ok(mut client) = client else { continue };
                counted.fetch_add(1, Ordering::SeqCst);
                let mode = now_mode.load(Ordering::SeqCst);
                if mode == ProxyMode::Refuse as u8 {
                    drop(client);
                    continue;
                }
                if mode == ProxyMode::Blackhole as u8 {
                    let lost = Arc::clone(&lost);
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 16 << 10];
                        while let Ok(n @ 1..) = client.read(&mut buf) {
                            lost.fetch_add(n as u64, Ordering::SeqCst);
                        }
                    });
                    continue;
                }
                if mode == ProxyMode::TlsOnly as u8 {
                    // Dialers speak first; a silent one is closed too.
                    let mut first = [0u8; 1];
                    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
                    if !matches!(client.peek(&mut first), Ok(1) if first[0] == 0x16) {
                        drop(client);
                        continue;
                    }
                    let _ = client.set_read_timeout(None);
                }
                let born = current.load(Ordering::SeqCst);
                let Ok(upstream) = std::net::TcpStream::connect(target) else {
                    continue;
                };
                let (Ok(client2), Ok(upstream2)) = (client.try_clone(), upstream.try_clone())
                else {
                    continue;
                };
                tracked.lock().unwrap().insert(number, born);
                let pumps = Arc::new(AtomicU64::new(2));
                let logs: SplitLogs = Default::default();
                if let Some(conns) = &conns {
                    conns.lock().unwrap().push(logs.clone());
                }
                for ((mut from, mut to), log) in [(client2, upstream2), (upstream, client)]
                    .into_iter()
                    .zip(logs)
                {
                    let split = conns.is_some();
                    let lost = Arc::clone(&lost);
                    let record = Arc::clone(&record);
                    let current = Arc::clone(&current);
                    let tracked = Arc::clone(&tracked);
                    let pumps = Arc::clone(&pumps);
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 16 << 10];
                        loop {
                            match from.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) if current.load(Ordering::SeqCst) != born => {
                                    lost.fetch_add(n as u64, Ordering::SeqCst);
                                }
                                Ok(n) => {
                                    {
                                        let mut seen = record.lock().unwrap();
                                        if seen.len() + n <= PROXY_RECORD_CAP {
                                            seen.extend_from_slice(&buf[..n]);
                                        }
                                    }
                                    if split {
                                        let mut own = log.lock().unwrap();
                                        if own.len() + n <= PROXY_SPLIT_CAP {
                                            own.extend_from_slice(&buf[..n]);
                                        }
                                    }
                                    if to.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        // A cut path stays silent: one side's close is not
                        // passed on (that network is gone). The other pump
                        // keeps both sockets open until its own end closes.
                        if current.load(Ordering::SeqCst) == born {
                            let _ = to.shutdown(std::net::Shutdown::Both);
                        }
                        if pumps.fetch_sub(1, Ordering::SeqCst) == 1 {
                            tracked.lock().unwrap().remove(&number);
                        }
                    });
                }
            }
        });
        RecordingProxy {
            addr,
            seen,
            split,
            generation,
            open,
            mode,
            accepted,
            dropped,
        }
    }

    /// What reached the proxy so far: connections accepted (in any mode)
    /// plus bytes it read and dropped (held or cut connections).
    fn activity(&self) -> u64 {
        self.accepted.load(Ordering::SeqCst) + self.dropped.load(Ordering::SeqCst)
    }

    /// A split proxy's connections so far, each as the lengths of the
    /// `u32_be(len) || message` messages its client sent and the target
    /// sent back (a cut last message left out).
    fn messages(&self) -> Vec<[Vec<usize>; 2]> {
        let lengths = |bytes: &[u8]| {
            let mut out = Vec::new();
            let mut rest = bytes;
            while rest.len() >= 4 {
                let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
                if rest.len() < 4 + n {
                    break;
                }
                out.push(n);
                rest = &rest[4 + n..];
            }
            out
        };
        let conns = self.split.as_ref().expect("a split proxy");
        conns
            .lock()
            .unwrap()
            .iter()
            .map(|[up, down]| [lengths(&up.lock().unwrap()), lengths(&down.lock().unwrap())])
            .collect()
    }

    /// New connections from now on are passed on, held silent or closed
    /// ([`ProxyMode`]). Blackhole and Refuse also silence every connection
    /// open now ([`Self::cut_existing`]): the host behind went to sleep or
    /// away, and nothing tells the other end. Back to Forward, the silenced
    /// ones stay silent; new ones pass.
    fn set_mode(&self, mode: ProxyMode) {
        self.mode.store(mode as u8, Ordering::SeqCst);
        if matches!(mode, ProxyMode::Blackhole | ProxyMode::Refuse) {
            self.cut_existing();
        }
    }

    fn recorded(&self) -> Vec<u8> {
        self.seen.lock().unwrap().clone()
    }

    /// Every connection open now goes silent both ways (bytes read and
    /// dropped, sockets kept open, closes not passed on), like a network that
    /// vanished; new connections pass.
    fn cut_existing(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Cut connections that are still open (until the far end closes).
    fn cut_still_open(&self) -> usize {
        let now = self.generation.load(Ordering::SeqCst);
        let open = self.open.lock().unwrap();
        open.values().filter(|born| **born < now).count()
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// An in-process plain libp2p peer with no Raven filter: the R14 instrument
/// (C15, C16). Being the endpoint, it sees what B sends inside the encrypted
/// circuit, which no packet capture can: Identify, and the DCUtR candidates
/// B offers (a hole-punch dial targets exactly those). Only raven_swarm's
/// re-exports, so no new dependency.
mod spy {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use futures::StreamExt;
    use raven_swarm::host::{identify_config, is_circuit};
    use raven_swarm::libp2p::core::transport::PortUse;
    use raven_swarm::libp2p::core::Endpoint;
    use raven_swarm::libp2p::identity::Keypair;
    use raven_swarm::libp2p::swarm::behaviour::NewExternalAddrCandidate;
    use raven_swarm::libp2p::swarm::dial_opts::DialOpts;
    use raven_swarm::libp2p::swarm::{
        dummy, ConnectionDenied, ConnectionId, DialError, FromSwarm, NetworkBehaviour, SwarmEvent,
        THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
    };
    use raven_swarm::libp2p::{
        dcutr, identify, noise, relay, tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
    };

    pub const CONTACT_SEED: u8 = 0x5a;
    pub const STRANGER_SEED: u8 = 0x5b;

    fn key(seed: u8) -> Keypair {
        Keypair::ed25519_from_bytes([seed; 32]).expect("seed")
    }

    pub fn peer_id(seed: u8) -> String {
        key(seed).public().to_peer_id().to_string()
    }

    /// Every dial to the target that names no circuit (a hole punch's dial:
    /// its addresses are exactly the candidates the target sent), recorded
    /// and then refused, so the spy never connects to B directly.
    struct DialLog {
        target: PeerId,
        seen: Arc<Mutex<Vec<Multiaddr>>>,
    }

    impl NetworkBehaviour for DialLog {
        type ConnectionHandler = dummy::ConnectionHandler;
        type ToSwarm = std::convert::Infallible;

        fn handle_pending_outbound_connection(
            &mut self,
            _: ConnectionId,
            peer: Option<PeerId>,
            addresses: &[Multiaddr],
            _: Endpoint,
        ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
            if peer == Some(self.target)
                && !addresses.is_empty()
                && !addresses.iter().any(is_circuit)
            {
                self.seen.lock().unwrap().extend_from_slice(addresses);
                return Err(ConnectionDenied::new(std::io::Error::other(
                    "recorded, not dialled",
                )));
            }
            Ok(Vec::new())
        }

        fn handle_established_inbound_connection(
            &mut self,
            _: ConnectionId,
            _: PeerId,
            _: &Multiaddr,
            _: &Multiaddr,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn handle_established_outbound_connection(
            &mut self,
            _: ConnectionId,
            _: PeerId,
            _: &Multiaddr,
            _: Endpoint,
            _: PortUse,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn on_swarm_event(&mut self, _: FromSwarm) {}

        fn on_connection_handler_event(
            &mut self,
            _: PeerId,
            _: ConnectionId,
            event: THandlerOutEvent<Self>,
        ) {
            raven_swarm::libp2p::core::util::unreachable(event)
        }

        fn poll(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
            std::task::Poll::Pending
        }
    }

    // The test crate has no libp2p dependency of its own.
    #[derive(NetworkBehaviour)]
    #[behaviour(prelude = "raven_swarm::libp2p::swarm::derive_prelude")]
    struct Spy {
        dials: DialLog,
        relay_client: relay::client::Behaviour,
        dcutr: dcutr::Behaviour,
        identify: identify::Behaviour,
    }

    /// What the spy saw of the target.
    #[derive(Debug, Default)]
    pub struct Report {
        pub established: bool,
        /// Refused or closed (not counting the spy's own refused dials).
        pub closed: bool,
        /// The listen addresses of the target's Identify, if any came.
        pub identify_addrs: Option<Vec<Multiaddr>>,
        /// DCUtR results: "ok" or the error text.
        pub dcutr: Vec<String>,
        /// Hole-punch dial targets (the candidates the target offered).
        pub direct_dials: Vec<Multiaddr>,
    }

    #[derive(Clone, Copy)]
    pub enum Until {
        Closed,
        DirectDial,
        /// This long after the target's Identify (a DCUtR attempt would
        /// have come by then), or at once on a direct dial or a hole punch.
        /// A failed DCUtR attempt does not end it: the target may try again.
        QuietAfterIdentify(Duration),
    }

    /// Dial `target` (a PeerId) through `circuit` as the peer of `seed`, and
    /// report what it learns until `until` or `limit`.
    pub fn probe(seed: u8, circuit: &str, target: &str, until: Until, limit: Duration) -> Report {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("spy runtime")
            .block_on(run(seed, circuit, target, until, limit))
    }

    async fn run(seed: u8, circuit: &str, target: &str, until: Until, limit: Duration) -> Report {
        let target: PeerId = target.parse().expect("target PeerId");
        let circuit: Multiaddr = circuit.parse().expect("circuit address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        // As the endpoint host builds its swarm (raven-swarm host.rs).
        let mut swarm = SwarmBuilder::with_existing_identity(key(seed))
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("tcp")
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .expect("relay client")
            .with_behaviour(|k, relay_client| Spy {
                dials: DialLog { target, seen: log },
                relay_client,
                dcutr: dcutr::Behaviour::new(k.public().to_peer_id()),
                identify: identify::Behaviour::new(identify_config(k, Duration::from_secs(60))),
            })
            .expect("spy behaviour")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();
        // DCUtR runs only when both sides offer a candidate: a loopback port
        // nobody listens on, which B (debug lab rule) may dial and is
        // refused at once.
        let own: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", super::free_loopback_port())
            .parse()
            .unwrap();
        swarm
            .behaviour_mut()
            .dcutr
            .on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                NewExternalAddrCandidate { addr: &own },
            ));
        // A circuit dial needs no reservation of its own.
        swarm
            .dial(DialOpts::peer_id(target).addresses(vec![circuit]).build())
            .expect("spy dial");
        let mut report = Report::default();
        let deadline = tokio::time::Instant::now() + limit;
        let mut quiet_until: Option<tokio::time::Instant> = None;
        loop {
            let stop = quiet_until.map_or(deadline, |q| q.min(deadline));
            let Ok(event) = tokio::time::timeout_at(stop, swarm.select_next_some()).await else {
                break;
            };
            match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target => {
                    report.established = true
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    num_established: 0,
                    ..
                } if peer_id == target => report.closed = true,
                SwarmEvent::OutgoingConnectionError {
                    peer_id: Some(peer),
                    error,
                    ..
                } if peer == target && !matches!(error, DialError::Denied { .. }) => {
                    report.closed = true
                }
                SwarmEvent::Behaviour(SpyEvent::Identify(identify::Event::Received {
                    peer_id,
                    info,
                    ..
                })) if peer_id == target => {
                    report.identify_addrs = Some(info.listen_addrs);
                    if let Until::QuietAfterIdentify(quiet) = until {
                        quiet_until.get_or_insert(tokio::time::Instant::now() + quiet);
                    }
                }
                SwarmEvent::Behaviour(SpyEvent::Dcutr(e)) if e.remote_peer_id == target => {
                    report.dcutr.push(match e.result {
                        Ok(_) => "ok".to_string(),
                        Err(e) => e.to_string(),
                    })
                }
                _ => {}
            }
            report.direct_dials = seen.lock().unwrap().clone();
            let done = match until {
                Until::Closed => report.closed,
                Until::DirectDial => !report.direct_dials.is_empty(),
                Until::QuietAfterIdentify(_) => {
                    !report.direct_dials.is_empty() || report.dcutr.iter().any(|r| r == "ok")
                }
            };
            if done {
                break;
            }
        }
        report.direct_dials = seen.lock().unwrap().clone();
        report
    }
}

/// A [`RecordingProxy`] in front of the relay's TCP address, and the `via`
/// that reaches the relay through it.
fn proxied_via(relay: &Relay) -> (RecordingProxy, String) {
    let (r_tcp, r_peer) = relay.via.split_once("/p2p/").unwrap();
    let r_port: u16 = r_tcp.rsplit('/').next().unwrap().parse().unwrap();
    let proxy = RecordingProxy::start(std::net::SocketAddr::from(([127, 0, 0, 1], r_port)));
    let via = format!("/ip4/127.0.0.1/tcp/{}/p2p/{r_peer}", proxy.addr.port());
    (proxy, via)
}

/// Milliseconds since the Unix epoch (the relay status file's clock).
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The value of the first `raven status` row named `key` (`  p2p_listen
/// /ip4/…`, `  relay 1       OK — …`).
fn status_row<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|l| {
        let rest = l.trim().strip_prefix(key)?;
        rest.starts_with(char::is_whitespace).then(|| rest.trim())
    })
}

/// The rows of one `raven status` section (`REACHABILITY`, `LAST DELIVERY`):
/// from its header line to the next blank line; empty when it is missing.
fn status_section<'a>(status: &'a str, header: &str) -> &'a str {
    let Some(start) = status.find(&format!("{header} \u{2500}")) else {
        return "";
    };
    let rows = status[start..]
        .split_once('\n')
        .map_or("", |(_, rest)| rest);
    rows.split("\n\n").next().unwrap_or("")
}

/// The `path=` token of a verbose `raven send` (`… peer=… path=relayed`).
fn send_path(out: &Output) -> String {
    out.stdout
        .lines()
        .find_map(|l| l.split_once(" path=").map(|(_, p)| p.trim().to_string()))
        .unwrap_or_default()
}

/// `card` with its `p2p=` PeerId replaced by `peer`. A card's `p2p=` is not
/// bound to its Raven key, so a pinned identity-only profile can carry a
/// spy's PeerId (C15, C16).
fn with_p2p(card: &str, peer: &str) -> String {
    let swapped: Vec<String> = card
        .split(' ')
        .map(|t| {
            if t.starts_with("p2p=") {
                format!("p2p={peer}")
            } else {
                t.to_string()
            }
        })
        .collect();
    assert_eq!(
        card.split(' ').filter(|t| t.starts_with("p2p=")).count(),
        1,
        "{card}"
    );
    swapped.join(" ")
}

/// `peer` through the relay at `via` (a circuit address).
fn circuit_to(via: &str, peer: &str) -> String {
    format!("{via}/p2p-circuit/p2p/{peer}")
}

/// One side (`sent` / `received`) of the `p2p_paths` row, per path:
/// `sent: direct 1 · reversed 2 · relayed 3 · hole-punched 0; …`.
fn path_count(row: &str, side: &str) -> HashMap<&'static str, u64> {
    let part = row
        .split(';')
        .find_map(|p| p.trim().strip_prefix(side)?.strip_prefix(':'))
        .unwrap_or_else(|| panic!("no {side} in {row:?}"));
    ["direct", "reversed", "relayed", "hole-punched"]
        .into_iter()
        .map(|path| {
            let n = part
                .split('·')
                .find_map(|kv| kv.trim().strip_prefix(path)?.trim().parse().ok())
                .unwrap_or_else(|| panic!("no {path} in {part:?}"));
            (path, n)
        })
        .collect()
}

/// The p2p host re-reads its peer gate from contacts.json about once a
/// second: wait until `svc` admits `contacts` verified contacts, so a contact
/// pinned a moment ago is not refused below the Raven link.
fn wait_gate(svc: &Service, contacts: usize) {
    let line = format!("raven-node p2p: peer gate reloaded (verified contacts {contacts},");
    assert!(
        svc.log
            .wait_for(LOG_TIMEOUT, |l| l.contains(&line))
            .is_some(),
        "the peer gate never admitted {contacts} contact(s):\n{}",
        svc.log.text()
    );
}

/// C6: A and B reachable only through a relay they reserve on; delivery both
/// ways over the circuit; strangers, unpinned contacts and peers that are not
/// on the relay's allow-list are refused (transports design §6.4 C6, P3).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c6_forced_relay_both_ways_and_strangers_are_refused() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    assert!(
        !relay.dir.join("identity.seed").exists() && !relay.dir.join("identity.backend").exists(),
        "the relay must hold no Raven identity"
    );
    assert!(relay.dir.join("relay_key.ed25519").is_file());
    // A and B reach R through a recording proxy: every relayed byte is seen.
    let (r_tcp, r_peer) = relay.via.split_once("/p2p/").unwrap();
    let r_port: u16 = r_tcp.rsplit('/').next().unwrap().parse().unwrap();
    let proxy = RecordingProxy::start(std::net::SocketAddr::from(([127, 0, 0, 1], r_port)));
    let via = format!("/ip4/127.0.0.1/tcp/{}/p2p/{r_peer}", proxy.addr.port());
    let a = Profile::create_with(root.path(), "pa", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "pb", p2p_lab_unlock());
    let a_card = a.p2p_card(&via);
    let b_card = b.p2p_card(&via);
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    // The relay re-reads its allow-list on its own (no restart).
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    let a_svc = a.start_service_p2p(&via);
    let b_svc = b.start_service_p2p(&via);
    relay.wait_status(|s| s["counts"]["reservations"].as_u64() == Some(2));
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        assert!(
            !svc.log.text().contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{}",
            svc.log.text()
        );
        // The test switch keeps the retired no-listener mode.
        assert_eq!(svc.p2p_listeners, 0, "{name}:\n{}", svc.log.text());
        assert!(
            !svc.log.text().contains("is retired"),
            "{name}:\n{}",
            svc.log.text()
        );
    }
    let status = a.raven(&["status"], None);
    let row = status
        .stdout
        .lines()
        .find(|l| l.trim_start().starts_with("p2p "))
        .unwrap_or_else(|| panic!("no p2p row in status:\n{}", status.stdout));
    // No listener, no AutoNAT server: reachable through the relay only.
    assert!(
        row.contains("YES")
            && row.contains("reachability: relayed")
            && row.contains("reservations 1/1"),
        "{row}"
    );
    // No listening port: the only addresses are circuits through the relay.
    let listen = status
        .stdout
        .lines()
        .find(|l| l.trim_start().starts_with("p2p_listen "))
        .unwrap_or_else(|| panic!("no p2p_listen row:\n{}", status.stdout));
    assert!(
        listen
            .split_whitespace()
            .skip(1)
            .all(|a| a.trim_end_matches(',').contains("/p2p-circuit/")),
        "{listen}"
    );
    // REACHABILITY in words: relayed (no listener, and R runs no AutoNAT
    // server, so nothing checked), R's row names its host and port only.
    let reach = status_section(&status.stdout, "REACHABILITY");
    assert_eq!(
        status_row(reach, "internet"),
        Some("behind NAT: contacts reach you through 1 relay"),
        "{}",
        status.stdout
    );
    assert_eq!(
        status_row(reach, "checks"),
        Some("none yet (only relays started with `raven-node relay --autonat-server` can check)"),
        "{reach}"
    );
    let relay_1 = status_row(reach, "relay 1").unwrap_or_default();
    assert!(
        relay_1.starts_with(&format!(
            "OK \u{2014} 127.0.0.1:{}, reserved for ",
            proxy.addr.port()
        )),
        "{reach}"
    );
    assert_eq!(
        status_row(reach, "what to do"),
        Some("nothing to do: contacts reach you through your relay. Keep it running."),
        "{reach}"
    );
    assert!(!reach.contains("12D3KooW"), "{reach}");
    // The relay's ping shows up on its row (raven-node pings every 15 s).
    let mut relay_1 = String::new();
    assert!(
        wait_until(LOG_TIMEOUT, || {
            let st = a.raven(&["status"], None);
            relay_1 = status_row(status_section(&st.stdout, "REACHABILITY"), "relay 1")
                .unwrap_or_default()
                .to_string();
            relay_1.contains(", ping ") && relay_1.ends_with(" ago")
        }),
        "no ping on the relay row: {relay_1}"
    );
    let doctor = a.raven(&["doctor"], None);
    for want in [
        "  reach_class: relayed (nat=unknown checks_reached=0 checks_failed=0 \
         checks_not_counted=0 upnp=",
        " listening=no relays=1/1)",
        "  relay_1: reserved for_s=",
        "  reach_next_step: nothing to do: contacts reach you through your relay.",
    ] {
        assert!(doctor.stdout.contains(want), "{want}\n{}", doctor.stdout);
    }
    // E-custody-harness-docs-3: A's LAN listener is on loopback, but the
    // relay holds it: only friends on its network cannot reach it, and only
    // directly.
    assert_eq!(
        status_row(&doctor.stdout, "raven-node"),
        Some(
            "running; you can send, but friends on your network cannot reach you directly (it \
             listens on this computer only)"
        ),
        "{}",
        doctor.stdout
    );

    // Each pins the other from the card: p2p= and via= only, no LAN or
    // Internet route, so every send below rides the relay.
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    // With a contact, the next step is that listener's, in the same words
    // (the relay needs nothing).
    let doctor = a.raven(&["doctor"], None);
    assert!(
        status_row(&doctor.stdout, "next step").is_some_and(|s| s.starts_with(
            "friends on your network cannot reach you directly: raven-node listens on this \
             computer only (127.0.0.1:"
        )),
        "{}",
        doctor.stdout
    );
    let a_book = a.book();
    assert!(
        a_book.contains("\"p2p\": \"12D3KooW") && a_book.contains("\"lan_dial\": \"\""),
        "{a_book}"
    );

    let text_ab = "c6 hello over the relay from a";
    let sent = a.raven_with(
        &["send", "--contact", "@bob", "--carrier", "p2p"],
        Some(&format!("{text_ab}\n")),
        &[("RAVEN_VERBOSE", "1")],
    );
    assert_delivered("a→b (p2p)", &sent);
    assert!(
        sent.stdout.contains("carrier=p2p_dial"),
        "verbose send must name the carrier:\n{}",
        sent.all()
    );
    assert_eq!(send_path(&sent), "relayed", "{}", sent.all());
    assert_eq!(b.inbox().matches(text_ab).count(), 1, "exactly once on b");

    // The other way with the default carrier: auto plans p2p last, and it is
    // the only route this contact has.
    let text_ba = "c6 hello over the relay from b";
    let sent = b.raven_with(
        &["send", "--contact", "@alice"],
        Some(&format!("{text_ba}\n")),
        &[("RAVEN_VERBOSE", "1")],
    );
    assert_delivered("b→a (auto → p2p)", &sent);
    assert!(sent.stdout.contains("carrier=p2p_dial"), "{}", sent.all());
    assert_eq!(send_path(&sent), "relayed", "{}", sent.all());
    assert_eq!(a.inbox().matches(text_ba).count(), 1, "exactly once on a");
    // Each side's LAST DELIVERY names the other and says "through a relay",
    // with no PeerId or address.
    for (who, p, peer) in [("a", &a, "bob"), ("b", &b, "alice")] {
        let status = p.raven(&["status"], None);
        let last = status_section(&status.stdout, "LAST DELIVERY");
        let row = status_row(last, peer).unwrap_or_else(|| {
            panic!(
                "no LAST DELIVERY row for {peer} on {who}:\n{}",
                status.stdout
            )
        });
        assert!(row.starts_with("through a relay, "), "{who}: {row}");
        assert!(
            !last.contains("12D3KooW") && !last.contains("127.0.0.1"),
            "{who}: {last}"
        );
    }
    // Both sides counted their links: relayed only, no hole punch (there is
    // no listener to punch from).
    for (who, p) in [("a", &a), ("b", &b)] {
        let status = p.raven(&["status"], None);
        let paths = status_row(&status.stdout, "p2p_paths")
            .unwrap_or_else(|| panic!("no p2p_paths row in {who}'s status:\n{}", status.stdout));
        let (sent, received) = (path_count(paths, "sent"), path_count(paths, "received"));
        assert!(
            sent["relayed"] >= 1 && received["relayed"] >= 1,
            "{who}: {paths}"
        );
        for path in ["direct", "reversed", "hole-punched"] {
            assert_eq!((sent[path], received[path]), (0, 0), "{who}: {paths}");
        }
        assert!(paths.contains("hole punching 0 ok"), "{who}: {paths}");
    }
    for (who, p) in [("a", &a), ("b", &b)] {
        let list = p.raven(&["outbox", "list"], None);
        assert!(
            list.ok && list.stdout.contains("Nothing waiting"),
            "{who}: nothing left to retry:\n{}",
            list.all()
        );
    }
    let counts = relay.wait_status(|s| s["counts"]["reservations"].as_u64() == Some(2));
    let raw = counts.to_string();
    assert!(
        !raw.contains(&a.pub_hex) && !raw.contains(&b.pub_hex) && !raw.contains(text_ab),
        "the relay status holds counts only: {raw}"
    );
    assert!(
        !relay.log.text().contains(&a_card[..40]) && !relay.log.text().contains("c6 hello"),
        "{}",
        relay.log.text()
    );
    // ── Capture: what the relay's network path carried ────────────────────
    // Pairing (PairInit), both RLB1 offers, both messages and their ACKs all
    // crossed the proxy; inside libp2p Noise and the Raven link none of it
    // may be readable, nor may either side's Raven identity.
    let seen = proxy.recorded();
    assert!(seen.len() > 8 << 10, "the proxy saw {} bytes", seen.len());
    let id_bytes = |hex_key: &str| hex::decode(hex_key).unwrap();
    for (what, needle) in [
        ("PairInit magic", b"RVPI1".to_vec()),
        ("PairResponse magic", b"RVPR1".to_vec()),
        ("RLB1 magic", b"RLB1".to_vec()),
        ("RIH1 hello magic", b"RIH1".to_vec()),
        ("message text a→b", text_ab.as_bytes().to_vec()),
        ("message text b→a", text_ba.as_bytes().to_vec()),
        ("a's identity key", id_bytes(&a.pub_hex)),
        ("b's identity key", id_bytes(&b.pub_hex)),
        ("a's key in hex", a.pub_hex.as_bytes().to_vec()),
        ("a's Raven address", a.address.as_bytes().to_vec()),
        ("b's Raven address", b.address.as_bytes().to_vec()),
    ] {
        assert!(
            !contains(&seen, &needle),
            "the relay path carried {what} in clear"
        );
    }

    // ── A peer that is not on the relay's allow-list cannot reserve ───────
    // R's peer gate refuses its connection: the relay protocol never runs.
    let s = Profile::create_with(root.path(), "ps", p2p_lab_unlock());
    let conn_refused =
        |st: &serde_json::Value| st["counts"]["connections_refused"].as_u64().unwrap_or(0);
    let refused_before = conn_refused(&relay.wait_status(|_| true));
    let s_svc = s.start_service_p2p_with(&via, false);
    relay.wait_status(|st| conn_refused(st) > refused_before);
    assert!(
        !s_svc.log.text().contains("reservation accepted"),
        "a peer off the allow-list got a reservation:\n{}",
        s_svc.log.text()
    );
    assert_eq!(
        relay.wait_status(|_| true)["counts"]["reservations"].as_u64(),
        Some(2),
        "still only A and B"
    );

    // ── Stranger: S holds B's card (verified), B does not know S ─────────
    // Not on R's allow-list either: refused at R, it never reaches B.
    s.add_card(&b_card, "bob", &b.fingerprint);
    let refused_before = conn_refused(&relay.wait_status(|_| true));
    let probe = |to: &str, text: &str| {
        let refused = s.raven(
            &["send", "--contact", &format!("@{to}"), "--carrier", "p2p"],
            Some(&format!("{text}\n")),
        );
        assert!(!refused.ok, "stranger send succeeded:\n{}", refused.all());
        assert!(
            refused.all().contains("P2P_UNREACHABLE")
                && !refused.all().contains("LINK_NOT_ACCEPTED"),
            "the stranger must be refused below the Raven link:\n{}",
            refused.all()
        );
        refused.all()
    };
    let relay_hint =
        "the contact's relay refused this node: ask its operator to `raven relay allow`";
    let node_hint = "the contact's node refused the p2p connection at once";
    let out = probe("bob", "c6 stranger probe");
    assert!(!b.inbox().contains("c6 stranger probe"));
    assert!(
        out.contains(relay_hint) && !out.contains(node_hint),
        "the stranger is told the relay refused it:\n{out}"
    );
    relay.wait_status(|st| conn_refused(st) > refused_before);
    // B never saw S: no gate refusal, and its Raven link responder never ran
    // for S (nor ever does below).
    let gate_line =
        "raven-node p2p: refused a connection from a peer that is not a verified contact";
    let responder_line = |l: &str| l.contains("p2p inbound");
    assert!(
        !b_svc.log.text().contains(gate_line) && !b_svc.log.text().lines().any(responder_line),
        "the stranger reached b:\n{}",
        b_svc.log.text()
    );
    let cache = peer_cert_cache(&s.dir);
    assert!(
        !cache.contains(&b.pub_hex),
        "the stranger received b's certificate:\n{cache}"
    );

    // ── A member of R's circle that is not B's contact ───────────────────
    // R serves it; B's peer gate refuses the circuit before B accepts it.
    // R then answers CONNECTION_FAILED, which cannot be told from a contact
    // that is gone: the stranger reads that B is offline, with no hint
    // (review fix C-relay-kit-1; a quick close on a direct dial still
    // gets the node hint).
    let reads_offline = |out: &str| {
        out.contains("why=contact_offline") && !out.contains(node_hint) && !out.contains(relay_hint)
    };
    let s_card = s.p2p_card(&via);
    relay.allow(&s, &s_card);
    relay.wait_status(|st| st["counts"]["allowed_peers"].as_u64() == Some(3));
    let out = probe("bob", "c6 member stranger probe");
    assert!(!b.inbox().contains("c6 member stranger probe"));
    assert!(
        reads_offline(&out),
        "the stranger is told only that b is offline:\n{out}"
    );
    assert!(
        b_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l.contains(gate_line))
            .is_some(),
        "b logged no gate refusal:\n{}",
        b_svc.log.text()
    );
    assert!(
        !b_svc.log.text().lines().any(responder_line) && !b_svc.log.text().contains("12D3KooW"),
        "the stranger reached b's Raven link, or b's log names a PeerId:\n{}",
        b_svc.log.text()
    );
    let cache = peer_cert_cache(&s.dir);
    assert!(
        !cache.contains(&b.pub_hex),
        "the stranger received b's certificate:\n{cache}"
    );
    let status = b.raven(&["status"], None);
    let gate_row = status_row(&status.stdout, "p2p_gate")
        .unwrap_or_else(|| panic!("no p2p_gate row in b's status:\n{}", status.stdout));
    let refused_at_b: u64 = gate_row
        .split_once("refused ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no refusal count in {gate_row:?}"));
    assert!(
        gate_row.starts_with("verified contacts 1, relays 1;") && refused_at_b >= 1,
        "{gate_row}"
    );

    // ── Unpinned: A adds S (from S's card) but never verifies it ──────────
    // A's peer gate refuses S's circuit: the Raven link never runs.
    let added = a.raven(
        &[
            "contact",
            "add",
            "--card",
            &s_card,
            "--petname",
            "sam",
            "--tag",
            "sam",
        ],
        None,
    );
    assert!(added.ok, "a contact add s:\n{}", added.all());
    assert!(added.stdout.contains("pinned      no"), "{}", added.all());
    s.add_card(&a_card, "alice", &a.fingerprint);
    let out = probe("alice", "c6 unverified probe");
    assert!(reads_offline(&out), "{out}");
    assert!(
        a_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l.contains(gate_line))
            .is_some(),
        "a logged no gate refusal:\n{}",
        a_svc.log.text()
    );
    assert!(
        !a_svc.log.text().lines().any(responder_line),
        "the unverified contact reached a's Raven link:\n{}",
        a_svc.log.text()
    );
    assert!(!a.inbox().contains("c6 unverified probe"));
    // And A's own p2p send to the unpinned S is refused before anything is
    // dialled, although S's card gave A a p2p route.
    let unverified = a.raven(
        &["send", "--contact", "@sam", "--carrier", "p2p"],
        Some("c6 must wait for verification\n"),
    );
    assert!(!unverified.ok, "{}", unverified.all());
    assert!(
        unverified.all().contains("CONTACT_NOT_VERIFIED")
            && unverified.all().contains("Nothing was dialled"),
        "{}",
        unverified.all()
    );

    // A still gets through after the refusals, and says how in words.
    let again = a.send("bob", "c6 after the stranger");
    assert_delivered("a→b after the stranger", &again);
    assert!(
        again
            .stdout
            .contains("path: through a relay (it passes only encrypted bytes)")
            && !again.stdout.contains("path="),
        "{}",
        again.all()
    );
    assert_eq!(b.inbox().matches("c6 after the stranger").count(), 1);
    for (name, svc) in [("a", &a_svc), ("b", &b_svc), ("s", &s_svc)] {
        assert!(
            !svc.log.text().contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{}",
            svc.log.text()
        );
    }
    let raw = relay.wait_status(|_| true)["counts"].to_string();
    assert!(
        !raw.contains("12D3KooW"),
        "the relay counts name a PeerId: {raw}"
    );
    drop(s_svc);

    // ── The relay goes away ──────────────────────────────────────────────
    // A's relay row says so, `what to do` and the doctor's next step say to
    // check the relay (W1), and the class becomes unreachable (no listener,
    // no reservation).
    drop(relay);
    let w1 = "your relay is not answering, so contacts outside this network cannot reach you. \
              Check that it runs and lets you in (on the relay's computer: `raven relay \
              status`); raven-node keeps trying.";
    let (mut reach, mut doctor) = (String::new(), String::new());
    let noticed = wait_until(Duration::from_secs(60), || {
        let st = a.raven(&["status"], None);
        reach = status_section(&st.stdout, "REACHABILITY").to_string();
        if !(status_row(&reach, "relay 1").is_some_and(|r| r.starts_with("NOT reserved"))
            && status_row(&reach, "what to do") == Some(w1))
        {
            return false;
        }
        doctor = a.raven(&["doctor"], None).stdout;
        doctor.contains("  reach_class: unreachable (")
            && status_row(&doctor, "next step") == Some(w1)
            && doctor.contains(&format!("  reach_next_step: {w1}"))
    });
    assert!(noticed, "{reach}\n{doctor}");
    let relay_1 = status_row(&reach, "relay 1").unwrap();
    assert!(
        relay_1.contains(&format!("127.0.0.1:{}", proxy.addr.port()))
            && relay_1.contains(" failed)"),
        "{relay_1}"
    );
    let reach_lines: Vec<&str> = doctor
        .lines()
        .filter(|l| {
            [
                "reach_class:",
                "relay_",
                "p2p_gate:",
                "last_paths:",
                "reach_next_step:",
            ]
            .iter()
            .any(|k| l.trim_start().starts_with(k))
        })
        .collect();
    assert!(reach_lines.len() >= 5, "{doctor}");
    for line in reach_lines {
        assert!(
            !line.contains("12D3KooW") && !line.contains("127.0.0.1"),
            "{line}"
        );
    }
    assert!(!reach.contains("12D3KooW"), "{reach}");
    assert!(
        !a_svc.log.text().contains("12D3KooW"),
        "a's log names a PeerId:\n{}",
        a_svc.log.text()
    );
}

/// C12: A's network switches (netwatch fed by the debug lab event file) while
/// its old path to the relay goes silent. The p2p host re-homes on the SAME
/// relay at once (a second reservation while the relay still holds the
/// silent one), its listen port opens again, and the messages A queued while
/// B was down are delivered exactly once when B is back. A wake from sleep
/// then re-homes it again (transports design §6.4 C12, Phase 0b).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c12_network_switch_rehomes_p2p_on_the_same_relay_and_delivers_the_queue() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    let (proxy, via) = proxied_via(&relay);
    let a = Profile::create_with(root.path(), "wa", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "wb", p2p_lab_unlock());
    let a_card = a.p2p_card(&via);
    let b_card = b.p2p_card(&via);
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    let net = root.path().join("a-net.txt");
    std::fs::write(&net, "up 192.0.2.10/24\n").unwrap();
    let net_path = net.to_string_lossy().into_owned();
    // TCP and QUIC on the one loopback port of its own, kept across the
    // re-home.
    let (a_port, a_svc) = start_p2p_on_own_port(
        &a,
        &P2pStart {
            listen: "",
            relay_via: &via,
            wait_reservation: true,
            env: &[("RAVEN_LAB_NETWATCH_EVENTS", &net_path)],
        },
    );
    let b_svc = b.start_service_p2p(&via);
    assert!(
        a_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l
                .contains("raven-node netwatch: watching (1 network)"))
            .is_some(),
        "a's netwatch read no lab baseline:\n{}",
        a_svc.log.text()
    );
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    let warm = a.raven(
        &["send", "--contact", "@bob", "--carrier", "p2p"],
        Some("c12 warm-up\n"),
    );
    assert_delivered("a→b (p2p warm-up)", &warm);

    // B goes down; A queues three messages (p2p is B's only route) and the
    // first one backs off for a few attempts.
    drop(b_svc);
    let texts = ["c12 queued one", "c12 queued two", "c12 queued three"];
    let mids: Vec<String> = texts
        .iter()
        .map(|text| {
            let out = a.send("bob", text);
            assert!(!out.ok, "nothing confirmed it yet:\n{}", out.all());
            queued_mid(&out)
        })
        .collect();
    wait_attempts(&a, &mids[0], 3, Duration::from_secs(120));

    // A's old network vanishes (its path to the relay goes silent, nothing is
    // closed on the relay's side) and a new one comes up.
    let accepted = || a_svc.log.count("raven-node p2p: reservation accepted");
    let accepted_before = accepted();
    proxy.cut_existing();
    append(&net, "down 192.0.2.10/24\nup 198.51.100.7/24\n");
    let switched = Instant::now();
    let line = a_svc
        .log
        .wait_for(Duration::from_secs(10), |l| {
            l.contains("raven-node netwatch: network changed (")
        })
        .unwrap_or_else(|| panic!("no network change within 10 s:\n{}", a_svc.log.text()));
    assert!(
        line.contains("raven-node netwatch: network changed (1 new, 1 gone, 1 now): retrying")
            && line.trim_end().ends_with(", p2p re-homing"),
        "{line}"
    );
    assert!(
        a_svc
            .log
            .wait_for(Duration::from_secs(10), |l| l
                .contains("raven-node p2p: re-homed (network changed)"))
            .is_some(),
        "{}",
        a_svc.log.text()
    );
    // The same relay at once (the ping path would take 20-40 s).
    assert!(
        wait_until(
            Duration::from_secs(15).saturating_sub(switched.elapsed()),
            || accepted() > accepted_before
        ),
        "no new reservation within 15 s of the switch:\n{}",
        a_svc.log.text()
    );
    let mut last = String::new();
    let listen_tcp = format!("/ip4/127.0.0.1/tcp/{a_port}");
    let reopened = wait_until(LOG_TIMEOUT, || {
        last = a.raven(&["status"], None).stdout;
        let row = status_row(&last, "p2p").unwrap_or_default();
        let listen = status_row(&last, "p2p_listen").unwrap_or_default();
        row.contains("reachability: relayed")
            && row.contains("reservations 1/1")
            && listen.split(", ").any(|addr| addr == listen_tcp)
    });
    assert!(
        reopened,
        "not re-homed with its port open:\n{last}\n{}",
        a_svc.log.text()
    );
    assert!(
        !a_svc
            .log
            .text()
            .contains("already in use by another program"),
        "{}",
        a_svc.log.text()
    );

    // B is back: each queued message arrives exactly once.
    let b_svc = b.start_service_p2p(&via);
    let delivered = wait_until(Duration::from_secs(60), || {
        let inbox = b.inbox();
        texts.iter().all(|text| inbox.contains(text))
    });
    assert!(
        delivered,
        "not delivered within 60 s of b's return:\n{}\n{}\n{}",
        a.raven(&["outbox", "list"], None).all(),
        a_svc.log.text(),
        b_svc.log.text()
    );
    let inbox = b.inbox();
    for text in texts {
        assert_eq!(
            inbox.matches(text).count(),
            1,
            "exactly once on b:\n{inbox}"
        );
    }
    let mut list = String::new();
    assert!(
        wait_until(LOG_TIMEOUT, || {
            list = a.raven(&["outbox", "list"], None).all();
            list.contains("Nothing waiting")
        }),
        "nothing left to retry:\n{list}"
    );

    // A wake from sleep re-homes again, on the same relay, and the next
    // message goes through.
    let accepted_before = accepted();
    append(&net, "wake\n");
    let woke = Instant::now();
    let line = a_svc
        .log
        .wait_for(Duration::from_secs(10), |l| {
            l.contains("raven-node netwatch: woke from sleep (")
        })
        .unwrap_or_else(|| panic!("no wake within 10 s:\n{}", a_svc.log.text()));
    assert!(
        line.contains("woke from sleep (0 new, 0 gone, 1 now): retrying")
            && line.trim_end().ends_with(", p2p re-homing"),
        "{line}"
    );
    assert!(
        a_svc
            .log
            .wait_for(Duration::from_secs(10), |l| l
                .contains("raven-node p2p: re-homed (woke from sleep)"))
            .is_some(),
        "{}",
        a_svc.log.text()
    );
    assert!(
        wait_until(
            Duration::from_secs(15).saturating_sub(woke.elapsed()),
            || accepted() > accepted_before
        ),
        "no new reservation within 15 s of the wake:\n{}",
        a_svc.log.text()
    );
    let text = "c12 after the wake";
    let sent = a.raven(
        &["send", "--contact", "@bob", "--carrier", "p2p"],
        Some(&format!("{text}\n")),
    );
    assert_delivered("a→b after the wake", &sent);
    assert_eq!(b.inbox().matches(text).count(), 1, "exactly once on b");

    // Counts only: one acted-on network change, no address, no PeerId.
    let log = a_svc.log.text();
    assert_eq!(
        log.matches("raven-node netwatch: network changed").count(),
        1,
        "{log}"
    );
    for leak in ["192.0.2.10", "198.51.100.7", "12D3KooW"] {
        assert!(!log.contains(leak), "a's log names {leak}:\n{log}");
    }
    // The relay reaps the silent old reservation by ping (it closes the cut
    // connection), and a status it wrote after that still counts A, whose
    // newest reservation holds, and B (it counts peers).
    assert!(
        wait_until(Duration::from_secs(90), || proxy.cut_still_open() == 0),
        "the relay kept the silent connection:\n{}",
        relay.log.text()
    );
    let reaped_ms = unix_ms() + 2_500;
    let status = relay.wait_status(|s| s["updated_at_ms"].as_u64().is_some_and(|t| t >= reaped_ms));
    assert_eq!(
        status["counts"]["reservations"].as_u64(),
        Some(2),
        "{status}"
    );
    drop(b_svc);
}

/// C13: A's path to its relay goes silent with no visible network change
/// (fast lab pings, the OS watcher on). Every relay failing its pings is a
/// path loss: the p2p host re-homes on the same relay without restarting the
/// outbox backoff, and the next message is delivered exactly once
/// (transports design §6.4 C13, Phase 0b).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c13_a_silent_relay_path_rehomes_without_a_network_change() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    // One proxy per node: only A's path is cut.
    let (proxy_a, via_a) = proxied_via(&relay);
    let (_proxy_b, via_b) = proxied_via(&relay);
    let a = Profile::create_with(root.path(), "la", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "lb", p2p_lab_unlock());
    let a_card = a.p2p_card(&via_a);
    let b_card = b.p2p_card(&via_b);
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    let a_svc = a.start_service_p2p_opts(&P2pStart {
        listen: "relay",
        relay_via: &via_a,
        wait_reservation: true,
        env: &[("RAVEN_LAB_P2P_PING", "2,1")],
    });
    let b_svc = b.start_service_p2p(&via_b);
    for line in [
        "raven-node p2p: lab ping every 2s, timeout 1s (debug build)",
        // The OS watcher: a relay loss needs its baseline.
        "raven-node netwatch: watching (",
    ] {
        assert!(
            a_svc
                .log
                .wait_for(LOG_TIMEOUT, |l| l.contains(line))
                .is_some(),
            "{line}:\n{}",
            a_svc.log.text()
        );
    }
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    let warm = a.raven(
        &["send", "--contact", "@bob", "--carrier", "p2p"],
        Some("c13 warm-up\n"),
    );
    assert_delivered("a→b (p2p warm-up)", &warm);

    let accepted = || a_svc.log.count("raven-node p2p: reservation accepted");
    let accepted_before = accepted();
    proxy_a.cut_existing();
    let cut = Instant::now();
    // Two failed pings close the connection (libp2p-ping's second failure
    // waits out its 10 s negotiation timeout), then the 2 s debounce.
    let limit = Duration::from_secs(30);
    for line in [
        "raven-node netwatch: every relay stopped answering; p2p re-homing",
        "raven-node p2p: re-homed (every relay stopped answering)",
    ] {
        assert!(
            a_svc
                .log
                .wait_for(limit.saturating_sub(cut.elapsed()), |l| l.contains(line))
                .is_some(),
            "{line} not within {limit:?}:\n{}",
            a_svc.log.text()
        );
    }
    assert!(
        wait_until(limit.saturating_sub(cut.elapsed()), || accepted()
            > accepted_before),
        "no new reservation within {limit:?}:\n{}",
        a_svc.log.text()
    );

    let text = "c13 after the silent path";
    let sent = a.raven(
        &["send", "--contact", "@bob", "--carrier", "p2p"],
        Some(&format!("{text}\n")),
    );
    assert_delivered("a→b after the path loss", &sent);
    assert_eq!(b.inbox().matches(text).count(), 1, "exactly once on b");
    // A path loss is not a network change: the outbox backoff was kept.
    let log = a_svc.log.text();
    for line in [
        "raven-node netwatch: network changed",
        "raven-node netwatch: woke from sleep",
        "raven-node netwatch: default route moved",
    ] {
        assert!(!log.contains(line), "{line}:\n{log}");
    }
    assert!(!log.contains("12D3KooW"), "{log}");
    drop(b_svc);
}

/// C14: a direct connection, then the same connection reversed, then the
/// outbox worker delivering a queued message over the contact's own new
/// connection (any-network plan §3 Phase 1 item 4, deliberate reversal).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c14_direct_then_reversed_and_the_worker_rides_the_contacts_connection() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create_with(root.path(), "da", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "db", p2p_lab_unlock());
    // No relay: each listens on a loopback port of its own.
    let start = |p: &Profile, listen: &str| {
        let svc = p.start_service_p2p_opts(&P2pStart {
            listen,
            relay_via: "",
            wait_reservation: false,
            env: &[],
        });
        assert_eq!(svc.p2p_listeners, 2, "{}:\n{}", p.name, svc.log.text());
        svc
    };
    let a_svc = start(&a, "127.0.0.1:0");
    let (b_port, b_svc) = start_p2p_on_own_port(
        &b,
        &P2pStart {
            listen: "",
            relay_via: "",
            wait_reservation: false,
            env: &[],
        },
    );
    // B's card names B's own address (a direct via); A's has `p2p=` only.
    let status = b.raven(&["status"], None);
    let b_peer = status_row(&status.stdout, "p2p_peer")
        .unwrap_or_else(|| panic!("no p2p_peer row:\n{}", status.stdout))
        .to_string();
    let b_card = b.p2p_card(&format!("/ip4/127.0.0.1/tcp/{b_port}/p2p/{b_peer}"));
    let card = a.raven(&["whoami", "--card"], None);
    assert!(card.ok, "a whoami --card:\n{}", card.all());
    let a_card = card.stdout.trim().to_string();
    assert!(
        a_card.starts_with("raven-card/2 ")
            && a_card.contains(" p2p=12D3KooW")
            && !a_card.contains(" via="),
        "{a_card}"
    );
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    let verbose = [("RAVEN_VERBOSE", "1")];

    // A dials B's address: its own connection.
    let text_ab = "c14 a to b";
    let sent = a.raven_with(
        &["send", "--contact", "@bob", "--carrier", "p2p"],
        Some(&format!("{text_ab}\n")),
        &verbose,
    );
    assert_delivered("a→b (direct)", &sent);
    assert_eq!(send_path(&sent), "direct", "{}", sent.all());
    assert!(
        a_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l
                .contains("raven-node p2p: link via a direct connection (direct)"))
            .is_some(),
        "{}",
        a_svc.log.text()
    );
    assert_eq!(b.inbox().matches(text_ab).count(), 1, "exactly once on b");

    // B has no address for A: its link rides the connection A opened.
    let text_ba = "c14 b to a";
    let sent = b.raven_with(
        &["send", "--contact", "@alice"],
        Some(&format!("{text_ba}\n")),
        &verbose,
    );
    assert_delivered("b→a (reversed)", &sent);
    assert_eq!(send_path(&sent), "reversed", "{}", sent.all());
    assert!(sent.stdout.contains("carrier=p2p_dial"), "{}", sent.all());
    assert_eq!(a.inbox().matches(text_ba).count(), 1, "exactly once on a");
    let quiet = b.send("alice", "c14 b to a in words");
    assert_delivered("b→a (reversed, default output)", &quiet);
    assert!(
        quiet
            .stdout
            .contains("path: over alice's own connection to you"),
        "{}",
        quiet.all()
    );

    // A goes away (its connection with it): B's next message waits in its
    // outbox, since B knows no address of A's.
    drop(a_svc);
    let text_queued = "c14 b to a while a is away";
    let queued = b.send("alice", text_queued);
    assert!(!queued.ok, "nothing confirmed it yet:\n{}", queued.all());
    assert!(
        queued.all().contains("raven-node keeps trying"),
        "{}",
        queued.all()
    );
    let mid = queued_mid(&queued);
    assert_eq!(mid.len(), 8, "{mid}");
    wait_attempts(&b, &mid, 1, Duration::from_secs(60));

    // A is back (a new port) and writes again: a new connection, which B's
    // worker rides to deliver what waited (the retry makes it due now).
    // Its peer gate admits B from the start (read before `host up`).
    let a_svc = start(&a, "127.0.0.1:0");
    let again = a.send("bob", "c14 a to b again");
    assert_delivered("a→b again", &again);
    let retry = b.raven(&["outbox", "retry", &mid], None);
    assert!(retry.ok, "{}", retry.all());
    let deadline = Instant::now() + Duration::from_secs(90);
    let delivered = loop {
        let st = b.raven(&["outbox", "status", &mid], None);
        if st.ok && st.stdout.contains("state       delivered") {
            break st;
        }
        assert!(
            Instant::now() < deadline,
            "not delivered within 90 s:\n{}\n{}\n{}",
            st.all(),
            a_svc.log.text(),
            b_svc.log.text()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    for row in ["carrier     p2p_dial", "path        reversed"] {
        assert!(
            delivered.stdout.contains(row),
            "{row}:\n{}",
            delivered.all()
        );
    }
    assert!(
        b_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l
                .contains("raven-node outbox: delivered 1 (p2p_dial, reversed)"))
            .is_some(),
        "{}",
        b_svc.log.text()
    );
    assert_eq!(
        a.inbox().matches(text_queued).count(),
        1,
        "exactly once on a"
    );
    let status = b.raven(&["status"], None);
    let paths = status_row(&status.stdout, "p2p_paths")
        .unwrap_or_else(|| panic!("no p2p_paths row:\n{}", status.stdout));
    assert!(path_count(paths, "sent")["reversed"] >= 3, "{paths}");
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        assert!(
            !svc.log.text().contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{}",
            svc.log.text()
        );
    }
}

/// C15: a true three-node relay. A and B always listen, yet every message
/// rides a circuit through a dedicated relay R: B publishes no address a
/// peer could dial (any-network plan §3 Phase 1 item 8). There is no
/// test-only "deny direct" switch, which would hide exactly the filter
/// regressions this test is for.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c15_true_three_node_relay_with_listening_nodes() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    // A and B reach R through a recording proxy: every relayed byte is seen.
    let (proxy, via) = proxied_via(&relay);
    let r_peer = via.rsplit("/p2p/").next().unwrap().to_string();
    let a = Profile::create_with(root.path(), "ta", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "tb", p2p_lab_unlock());
    // Q never runs a service: its card, pinned on B, carries the contact
    // spy's PeerId.
    let q = Profile::create_with(root.path(), "tq", p2p_lab_unlock());
    let contact_spy = spy::peer_id(spy::CONTACT_SEED);
    let stranger_spy = spy::peer_id(spy::STRANGER_SEED);
    let a_card = a.p2p_card(&via);
    let b_card = b.p2p_card(&via);
    // Each card names exactly one via, R (never the node's own PeerId).
    for card in [&a_card, &b_card] {
        let own = card
            .split(' ')
            .find_map(|t| t.strip_prefix("p2p="))
            .unwrap();
        let vias: Vec<&str> = card
            .split(' ')
            .filter_map(|t| t.strip_prefix("via="))
            .collect();
        assert_eq!(vias, [via.as_str()], "{card}");
        assert!(
            vias[0].ends_with(&format!("/p2p/{r_peer}")) && !vias[0].contains(own),
            "{card}"
        );
    }
    let q_card = with_p2p(&q.p2p_card(&via), &contact_spy);
    // Consent by circle: R relays only between peers on its allow-list, so
    // both ends are on it, and both spies (the stranger then reaches B's own
    // peer gate, not only R's).
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    relay.allow_peer(&a, &contact_spy);
    relay.allow_peer(&a, &stranger_spy);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(4));
    let start = |p: &Profile| {
        let svc = p.start_service_p2p_opts(&P2pStart {
            listen: "127.0.0.1:0",
            relay_via: &via,
            wait_reservation: true,
            env: &[],
        });
        // Always listening (TCP and QUIC), with the production candidate rule.
        assert_eq!(svc.p2p_listeners, 2, "{}:\n{}", p.name, svc.log.text());
        assert!(
            !svc.log.text().contains("lab hole punching"),
            "{}:\n{}",
            p.name,
            svc.log.text()
        );
        svc
    };
    let a_svc = start(&a);
    let b_svc = start(&b);
    // Only the reservation connections to R: A has no connection to B yet.
    let st = relay.wait_status(|s| s["counts"]["reservations"].as_u64() == Some(2));
    assert_eq!(st["counts"]["circuits"].as_u64(), Some(0), "{st}");
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    b.add_card(&q_card, "quill", &q.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 2);
    // A's only route to B is R: no LAN or Internet route, one via.
    let book: serde_json::Value = serde_json::from_str(&a.book()).unwrap();
    let bob = book
        .as_array()
        .and_then(|rows| rows.iter().find(|c| c["petname"] == "bob"))
        .unwrap_or_else(|| panic!("no bob in a's book: {book}"));
    let b_route: Vec<&str> = bob["p2p_via"]
        .as_array()
        .map(|v| v.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    assert!(
        bob["lan_dial"] == "" && bob["internet_dial"].as_str().unwrap_or("").is_empty(),
        "{bob}"
    );
    assert!(
        b_route.len() == 1 && b_route[0].ends_with(&format!("/p2p/{r_peer}")),
        "{bob}"
    );
    assert_eq!(
        relay.wait_status(|_| true)["counts"]["circuits"].as_u64(),
        Some(0),
        "a circuit opened before the first send"
    );

    // ── Relayed, never upgraded ──────────────────────────────────────────
    let verbose = [("RAVEN_VERBOSE", "1")];
    let send = |from: &Profile, to: &str, text: &str| {
        let sent = from.raven_with(
            &["send", "--contact", &format!("@{to}"), "--carrier", "p2p"],
            Some(&format!("{text}\n")),
            &verbose,
        );
        assert_delivered(&format!("{} → {to}", from.name), &sent);
        send_path(&sent)
    };
    let bytes0 = proxy.recorded().len();
    let text_ab1 = "c15 a to b one";
    assert_eq!(send(&a, "bob", text_ab1), "relayed", "{}", a_svc.log.text());
    assert_eq!(b.inbox().matches(text_ab1).count(), 1, "exactly once on b");
    relay.wait_status(|s| s["counts"]["circuits"].as_u64().unwrap_or(0) >= 1);
    let grown = proxy.recorded().len() - bytes0;
    assert!(grown > 2 << 10, "the relay path carried only {grown} bytes");

    // The spy as B's pinned contact: B's gate admits it (Identify comes),
    // yet B names only its circuit and offers no candidate to dial, even to
    // a contact: loopback is not a global address. Its DCUtR may report
    // only a failure (no addresses).
    let status = b.raven(&["status"], None);
    let b_peer = status_row(&status.stdout, "p2p_peer")
        .unwrap_or_else(|| panic!("no p2p_peer row:\n{}", status.stdout))
        .to_string();
    let to_b = circuit_to(&via, &b_peer);
    let contact = spy::probe(
        spy::CONTACT_SEED,
        &to_b,
        &b_peer,
        spy::Until::QuietAfterIdentify(Duration::from_secs(5)),
        LOG_TIMEOUT,
    );
    assert!(contact.established, "{contact:?}");
    let addrs = contact
        .identify_addrs
        .as_ref()
        .unwrap_or_else(|| panic!("b's gate sent its contact no Identify: {contact:?}"));
    // Its own address is its circuit through R, and nothing else.
    assert!(
        !addrs.is_empty() && addrs.iter().all(raven_swarm::host::is_circuit),
        "{contact:?}"
    );
    assert!(
        contact.direct_dials.is_empty() && !contact.dcutr.iter().any(|r| r == "ok"),
        "b disclosed a direct address to its contact: {contact:?}"
    );
    let upgrade_line = "direct connection upgraded (dcutr)";
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        assert_eq!(
            svc.log.count(upgrade_line),
            0,
            "{name}:\n{}",
            svc.log.text()
        );
    }

    let text_ab2 = "c15 a to b two";
    let text_ba = "c15 b to a";
    assert_eq!(send(&a, "bob", text_ab2), "relayed", "{}", a_svc.log.text());
    assert_eq!(
        send(&b, "alice", text_ba),
        "relayed",
        "{}",
        b_svc.log.text()
    );
    for (inbox, text) in [
        (b.inbox(), text_ab1),
        (b.inbox(), text_ab2),
        (a.inbox(), text_ba),
    ] {
        assert_eq!(inbox.matches(text).count(), 1, "{text} exactly once");
    }
    for (who, p) in [("a", &a), ("b", &b)] {
        let list = p.raven(&["outbox", "list"], None);
        assert!(
            list.ok && list.stdout.contains("Nothing waiting"),
            "{who}: nothing left to retry:\n{}",
            list.all()
        );
    }

    // ── The spy as a stranger in R's circle ──────────────────────────────
    // B's peer gate refuses the circuit before Identify, DCUtR or B's Raven
    // link: nothing learned, nothing dialled.
    let stranger = spy::probe(
        spy::STRANGER_SEED,
        &to_b,
        &b_peer,
        spy::Until::Closed,
        LOG_TIMEOUT,
    );
    assert!(stranger.closed && !stranger.established, "{stranger:?}");
    assert!(
        stranger.identify_addrs.is_none()
            && stranger.dcutr.is_empty()
            && stranger.direct_dials.is_empty(),
        "the stranger learned something: {stranger:?}"
    );
    let gate_line =
        "raven-node p2p: refused a connection from a peer that is not a verified contact";
    assert!(
        b_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l.contains(gate_line))
            .is_some(),
        "b logged no gate refusal:\n{}",
        b_svc.log.text()
    );
    assert!(
        !b_svc.log.text().lines().any(|l| l.contains("p2p inbound")),
        "a spy reached b's Raven link:\n{}",
        b_svc.log.text()
    );
    let status = b.raven(&["status"], None);
    let gate_row = status_row(&status.stdout, "p2p_gate")
        .unwrap_or_else(|| panic!("no p2p_gate row in b's status:\n{}", status.stdout));
    let refused_at_b: u64 = gate_row
        .split_once("refused ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no refusal count in {gate_row:?}"));
    assert!(
        gate_row.starts_with("verified contacts 2, relays 1;") && refused_at_b >= 1,
        "{gate_row}"
    );

    // ── What the relay path carried, and what the nodes said ─────────────
    // Both sides counted relayed links only, and no hole punch succeeded.
    for (who, p) in [("a", &a), ("b", &b)] {
        let status = p.raven(&["status"], None);
        let paths = status_row(&status.stdout, "p2p_paths")
            .unwrap_or_else(|| panic!("no p2p_paths row in {who}'s status:\n{}", status.stdout));
        let (sent, received) = (path_count(paths, "sent"), path_count(paths, "received"));
        assert!(
            sent["relayed"] >= 1 && received["relayed"] >= 1,
            "{who}: {paths}"
        );
        for path in ["direct", "reversed", "hole-punched"] {
            assert_eq!((sent[path], received[path]), (0, 0), "{who}: {paths}");
        }
        assert!(paths.contains("hole punching 0 ok"), "{who}: {paths}");
    }
    let seen = proxy.recorded();
    for (what, needle) in [
        ("message text a→b", text_ab1.as_bytes().to_vec()),
        ("message text a→b", text_ab2.as_bytes().to_vec()),
        ("message text b→a", text_ba.as_bytes().to_vec()),
        ("RLB1 magic", b"RLB1".to_vec()),
        ("a's identity key", hex::decode(&a.pub_hex).unwrap()),
        ("b's identity key", hex::decode(&b.pub_hex).unwrap()),
        ("a's Raven address", a.address.as_bytes().to_vec()),
        ("b's Raven address", b.address.as_bytes().to_vec()),
    ] {
        assert!(
            !contains(&seen, &needle),
            "the relay path carried {what} in clear"
        );
    }
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        assert_eq!(
            svc.log.count(upgrade_line),
            0,
            "{name}:\n{}",
            svc.log.text()
        );
        assert!(
            !svc.log.text().contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{}",
            svc.log.text()
        );
    }
}

/// C16: hole punching on loopback, labelled, and the R14 stranger with a
/// positive control (any-network plan §3 Phase 1 items 3 and 8). The debug
/// `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1` on A and B lets the candidate book
/// offer their loopback listen addresses; R is reached over QUIC, with no
/// proxy.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c16_lab_hole_punch_on_loopback_and_r14_stranger() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    let via = relay.quic_via.clone();
    assert!(
        via.contains("/udp/") && via.contains("/quic-v1/p2p/"),
        "{via}"
    );
    let a = Profile::create_with(root.path(), "ka", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "kb", p2p_lab_unlock());
    // Q never runs a service: its card, pinned on B, carries the contact
    // spy's PeerId.
    let q = Profile::create_with(root.path(), "kq", p2p_lab_unlock());
    let contact_spy = spy::peer_id(spy::CONTACT_SEED);
    let stranger_spy = spy::peer_id(spy::STRANGER_SEED);
    let a_card = a.p2p_card(&via);
    let b_card = b.p2p_card(&via);
    let q_card = with_p2p(&q.p2p_card(&via), &contact_spy);
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    // Both spies are in R's circle, so the stranger reaches B's own peer
    // gate (R14), not only R's.
    relay.allow_peer(&a, &contact_spy);
    relay.allow_peer(&a, &stranger_spy);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(4));
    let lab = [("RAVEN_LAB_P2P_LOCAL_CANDIDATES", "1")];
    let start = |p: &Profile| {
        let svc = p.start_service_p2p_opts(&P2pStart {
            listen: "127.0.0.1:0",
            relay_via: &via,
            wait_reservation: true,
            env: &lab,
        });
        assert_eq!(svc.p2p_listeners, 2, "{}:\n{}", p.name, svc.log.text());
        assert!(
            svc.log
                .text()
                .contains("raven-node p2p: lab hole punching also offers and dials loopback"),
            "{}:\n{}",
            p.name,
            svc.log.text()
        );
        svc
    };
    let a_svc = start(&a);
    let b_svc = start(&b);
    relay.wait_status(|s| s["counts"]["reservations"].as_u64() == Some(2));
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    b.add_card(&q_card, "quill", &q.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 2);
    let status = b.raven(&["status"], None);
    let b_peer = status_row(&status.stdout, "p2p_peer")
        .unwrap_or_else(|| panic!("no p2p_peer row:\n{}", status.stdout))
        .to_string();
    let to_b = circuit_to(&via, &b_peer);

    // ── R14, before A and B ever talk ─────────────────────────────────────
    // The stranger: R serves it (a member), B's peer gate refuses the
    // circuit: no Identify, no DCUtR, no candidate, no direct dial.
    let stranger = spy::probe(
        spy::STRANGER_SEED,
        &to_b,
        &b_peer,
        spy::Until::Closed,
        LOG_TIMEOUT,
    );
    assert!(stranger.closed && !stranger.established, "{stranger:?}");
    assert!(
        stranger.identify_addrs.is_none()
            && stranger.dcutr.is_empty()
            && stranger.direct_dials.is_empty(),
        "the stranger learned something: {stranger:?}"
    );
    let gate_line =
        "raven-node p2p: refused a connection from a peer that is not a verified contact";
    assert!(
        b_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l.contains(gate_line))
            .is_some(),
        "b logged no gate refusal:\n{}",
        b_svc.log.text()
    );
    // The positive control: the same probe as B's contact is offered B's
    // loopback candidate and dials it, so the stranger's empty result is
    // the gate's doing (it sits before DCUtR), not a broken instrument.
    let contact = spy::probe(
        spy::CONTACT_SEED,
        &to_b,
        &b_peer,
        spy::Until::DirectDial,
        LOG_TIMEOUT,
    );
    assert!(contact.established, "{contact:?}");
    assert!(
        contact
            .direct_dials
            .iter()
            .any(|a| a.to_string().starts_with("/ip4/127.0.0.1/")),
        "the contact was not offered b's loopback candidate: {contact:?}"
    );
    if let Some(addrs) = &contact.identify_addrs {
        // Identify still names circuits only (listen addresses stay hidden).
        assert!(
            addrs.iter().all(raven_swarm::host::is_circuit),
            "{contact:?}"
        );
    }
    assert!(
        !b_svc.log.text().lines().any(|l| l.contains("p2p inbound")),
        "a spy reached b's Raven link:\n{}",
        b_svc.log.text()
    );

    // ── A and B: relayed, then hole-punched ───────────────────────────────
    let verbose = [("RAVEN_VERBOSE", "1")];
    let send = |from: &Profile, to: &str, text: &str| {
        let sent = from.raven_with(
            &["send", "--contact", &format!("@{to}"), "--carrier", "p2p"],
            Some(&format!("{text}\n")),
            &verbose,
        );
        assert_delivered(&format!("{} → {to}", from.name), &sent);
        send_path(&sent)
    };
    let upgrade_line = "raven-node p2p: direct connection upgraded (dcutr)";
    // DCUtR may finish before the link chooses its connection.
    let first = send(&a, "bob", "c16 a to b one");
    assert!(
        first == "relayed" || first == "hole_punched",
        "{first}:\n{}",
        a_svc.log.text()
    );
    assert!(
        wait_until(Duration::from_secs(30), || {
            a_svc.log.count(upgrade_line) + b_svc.log.count(upgrade_line) > 0
        }),
        "no hole punch within 30 s:\n{}\n{}",
        a_svc.log.text(),
        b_svc.log.text()
    );
    let second = send(&a, "bob", "c16 a to b two");
    assert_eq!(second, "hole_punched", "{}", a_svc.log.text());
    let newest_link = a_svc
        .log
        .text()
        .lines()
        .rfind(|l| l.contains("raven-node p2p: link via "))
        .map(str::to_string)
        .unwrap_or_default();
    assert!(
        newest_link.contains("a direct connection (hole_punched)"),
        "{newest_link:?}:\n{}",
        a_svc.log.text()
    );
    let back = send(&b, "alice", "c16 b to a");
    assert_ne!(back, "relayed", "{}", b_svc.log.text());
    for (inbox, text) in [
        (b.inbox(), "c16 a to b one"),
        (b.inbox(), "c16 a to b two"),
        (a.inbox(), "c16 b to a"),
    ] {
        assert_eq!(inbox.matches(text).count(), 1, "{text} exactly once");
    }
    let status = a.raven(&["status"], None);
    let paths = status_row(&status.stdout, "p2p_paths")
        .unwrap_or_else(|| panic!("no p2p_paths row:\n{}", status.stdout));
    assert!(paths.contains("hole punching 1 ok"), "{paths}");
    assert!(path_count(paths, "sent")["hole-punched"] >= 1, "{paths}");
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        assert!(
            !svc.log.text().contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{}",
            svc.log.text()
        );
    }
}

/// What `p` learned from `other`'s route hints: its `learned_routes.json`
/// entry, `None` without one (or without the file).
fn learned_entry(p: &Profile, other: &Profile) -> Option<serde_json::Value> {
    // Sealed (RMS1 kind 3) once this build ran there (privacy pack PP.6).
    let raw = sealed_text(
        &p.dir,
        "learned_routes.json",
        raven_core::at_rest::Kind::LearnedRoutes,
    );
    let all: serde_json::Value = serde_json::from_str(&raw).ok()?;
    all.as_array()?
        .iter()
        .find(|e| {
            e["pub_hex"]
                .as_str()
                .is_some_and(|k| k.eq_ignore_ascii_case(&other.pub_hex))
        })
        .cloned()
}

/// The PeerIds of the relays a learned entry ([`learned_entry`]) names.
fn learned_relays(entry: &serde_json::Value) -> Vec<String> {
    let mut out: Vec<String> = entry["relays"]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(|r| r.as_str()?.rsplit("/p2p/").next().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    out.dedup();
    out
}

/// The direct addresses a learned entry names: global ones and, from LAN
/// links, same-network ones.
fn learned_direct(entry: &serde_json::Value) -> Vec<String> {
    let texts = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut out = texts(&entry["direct"]);
    out.extend(texts(&entry["lan"]["local_direct"]));
    out
}

/// The TCP port of `p`'s p2p listener (its `p2p_listen` status row).
fn p2p_tcp_port(p: &Profile) -> u16 {
    let status = p.raven(&["status"], None);
    let row = status_row(&status.stdout, "p2p_listen")
        .unwrap_or_else(|| panic!("no p2p_listen row:\n{}", status.stdout));
    row.split(", ")
        .find_map(|a| a.strip_prefix("/ip4/127.0.0.1/tcp/")?.parse().ok())
        .unwrap_or_else(|| panic!("no loopback TCP listener in {row:?}"))
}

/// C17 (2) and (3): `a` and `b` (LAN, mutual unverified contacts) send one
/// message each way, each delivered exactly once; neither log has a frame
/// the dispatcher refused, and neither data dir holds `learned_routes.json`
/// (a side without route hints never sends one, so neither side learns).
fn c17_exchange(a: &Profile, b: &Profile, label: &str) {
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    a.add_contact(b, "bob", &b_svc.lan_dial);
    b.add_contact(a, "alice", &a_svc.lan_dial);
    let ab = format!("c17 {label} a to b");
    let ba = format!("c17 {label} b to a");
    assert_delivered(&format!("{label} a→b"), &a.send("bob", &ab));
    assert_delivered(&format!("{label} b→a"), &b.send("alice", &ba));
    assert_eq!(
        b.inbox().matches(ab.as_str()).count(),
        1,
        "{ab} exactly once"
    );
    assert_eq!(
        a.inbox().matches(ba.as_str()).count(),
        1,
        "{ba} exactly once"
    );
    for (p, svc) in [(a, &a_svc), (b, &b_svc)] {
        let log = svc.log.text();
        for bad in ["not RavenEnvelopeV1", "dispatch:"] {
            assert!(
                !log.contains(bad),
                "{label}: {}'s log has {bad:?}:\n{log}",
                p.name
            );
        }
        assert!(
            !p.dir.join("learned_routes.json").exists(),
            "{label}: {} learned route hints",
            p.name
        );
        if !p.route_hints {
            assert!(
                !p.dir.join("route_hints_state.json").exists(),
                "{label}: {} without route hints wrote their state",
                p.name
            );
        }
    }
}

/// C17: route hints (RRH1, protocol/RAVEN_ROUTE_HINTS_V1.md) on LAN, and
/// old-peer safety. The switch is the debug `RAVEN_LAB_ROUTE_HINTS=1` while
/// `ROUTE_HINTS_PRODUCTION_ENABLED` is false. (1) Both sides on: B comes
/// back on another port and sends to A; that link tells A the new port
/// (LAN_PORT), and the message A queued while B was away reaches B there
/// within 15 s, with no `set-addr`. (2) The switch on one side only, then
/// (3) on neither: one message each way, exactly once, no dispatcher
/// refusal in either log, no learned routes ([`c17_exchange`]). The byte
/// level (an empty Noise message 3, hello caps without bit 8) is raven-node's
/// scripted-peer tests; a real pre-RRH1 build is lan_fault_matrix s04c.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c17_rrh1_lan_port_change_and_old_peer_safety() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();

    // ── (1) Both on: a contact back on another port ──────────────────────
    let a = Profile::create(root.path(), "ha").with_route_hints();
    let b = Profile::create(root.path(), "hb").with_route_hints();
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    a.add_contact(&b, "bob", &b_svc.lan_dial);
    b.add_contact(&a, "alice", &a_svc.lan_dial);
    assert_delivered("a→b (warm-up)", &a.send("bob", "c17 warm-up"));
    let old_dial = b_svc.lan_dial.clone();
    drop(b_svc);
    let text = "c17 queued while b moves";
    let queued = a.send("bob", text);
    assert!(!queued.ok, "nothing confirmed it yet:\n{}", queued.all());
    assert!(
        queued.all().contains("raven-node keeps trying"),
        "{}",
        queued.all()
    );
    let b_svc = b.start_service();
    assert_ne!(b_svc.lan_dial, old_dial, "b came back on the same port");
    assert_delivered("b→a (new port)", &b.send("alice", "c17 b is back"));
    let moved = wait_until(Duration::from_secs(15), || b.inbox().contains(text));
    assert!(
        moved,
        "a's queued message did not reach b's new port within 15 s:\n{}\n{}\n{}",
        a.raven(&["outbox", "list"], None).all(),
        a_svc.log.text(),
        b_svc.log.text()
    );
    assert_eq!(b.inbox().matches(text).count(), 1, "exactly once on b");
    let new_port: u64 = b_svc.lan_dial.rsplit(':').next().unwrap().parse().unwrap();
    let learned = learned_entry(&a, &b)
        .unwrap_or_else(|| panic!("a learned nothing from b:\n{}", a_svc.log.text()));
    assert_eq!(
        learned["lan"]["lan_port"].as_u64(),
        Some(new_port),
        "{learned}"
    );
    assert!(
        a_svc
            .log
            .text()
            .contains("raven-node hints: learned a contact's routes ("),
        "{}",
        a_svc.log.text()
    );
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        for line in svc
            .log
            .text()
            .lines()
            .filter(|l| l.contains("raven-node hints"))
        {
            assert!(
                !line.contains("127.0.0.1")
                    && !line.contains(&a.pub_hex)
                    && !line.contains(&b.pub_hex),
                "{name}'s hints line names an address or a key: {line}"
            );
        }
    }
    drop((a_svc, b_svc));

    // ── (2) One side on, (3) neither ─────────────────────────────────────
    let c = Profile::create(root.path(), "hc").with_route_hints();
    let d = Profile::create(root.path(), "hd");
    c17_exchange(&c, &d, "one side on");
    let e = Profile::create(root.path(), "he");
    let f = Profile::create(root.path(), "hf");
    c17_exchange(&e, &f, "both off");
}

/// C18: a contact's new relay is learned through route hints, with no new
/// card. Dedicated relays R_A, R1 and R2, each behind a recording proxy and
/// each allowing A and B; `raven-card/3` cards (relays only): A's names
/// R_A, B's names R1; B listens nowhere, so only its relays reach it. m1
/// A→B is `relayed` through R1, and A learns B's relay from that link. B
/// comes back naming R2 only: its announcer (its relays changed) tells A
/// over LAN (B holds A's LAN route; an announce over p2p would leave a
/// connection m2 could ride), A's log says it learned one relay, and m2 is
/// `relayed` through R2. R1 relays no circuit after
/// the move, A's contacts.json is byte-identical, and no log names a
/// PeerId, nor a route-hints line an address.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c18_a_new_relay_is_learned_without_new_cards() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let r_a = Relay::start_named(root.path(), "relay-a");
    let r1 = Relay::start_named(root.path(), "relay-1");
    let r2 = Relay::start_named(root.path(), "relay-2");
    let (_pa, via_a) = proxied_via(&r_a);
    let (p1, via_1) = proxied_via(&r1);
    let (p2, via_2) = proxied_via(&r2);
    let peer_of = |via: &str| via.rsplit("/p2p/").next().unwrap().to_string();
    let a = Profile::create_with(root.path(), "ra", p2p_lab_unlock()).with_route_hints();
    let b = Profile::create_with(root.path(), "rb", p2p_lab_unlock()).with_route_hints();
    let a_card = a.p2p_card(&via_a);
    let b_card = b.p2p_card(&via_1);
    for card in [&a_card, &b_card] {
        assert!(
            card.starts_with("raven-card/3 ")
                && card.contains(" relay=/")
                && !card.contains(" via="),
            "{card}"
        );
    }
    for relay in [&r_a, &r1, &r2] {
        relay.allow(&a, &a_card);
        relay.allow(&b, &b_card);
        relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    }
    // B listens nowhere (the relay-only lab mode, C6): A reaches it through
    // its relays only. A listening B would also tell A, over LAN, its own
    // loopback address, and m2 would go there directly.
    let start = |p: &Profile, listen: &str, via: &str| {
        p.start_service_p2p_opts(&P2pStart {
            listen,
            relay_via: via,
            wait_reservation: true,
            env: &[],
        })
    };
    let a_svc = start(&a, "127.0.0.1:0", &via_a);
    let b_svc = start(&b, "relay", &via_1);
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    let lan = b.raven(
        &[
            "contact",
            "set-addr",
            "@alice",
            "--lan",
            &a_svc.lan_listen(),
        ],
        None,
    );
    assert!(lan.ok, "{}", lan.all());
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    let book = std::fs::read(a.dir.join("contacts.json")).unwrap();
    let verbose = [("RAVEN_VERBOSE", "1")];
    let send = |text: &str| {
        let sent = a.raven_with(
            &["send", "--contact", "@bob", "--carrier", "p2p"],
            Some(&format!("{text}\n")),
            &verbose,
        );
        assert_delivered(&format!("a→b {text}"), &sent);
        send_path(&sent)
    };

    // ── m1 through R1, the relay B's card names ──────────────────────────
    let bytes = p1.recorded().len();
    assert_eq!(send("c18 m1"), "relayed", "{}", a_svc.log.text());
    let grown = p1.recorded().len() - bytes;
    assert!(grown > 2 << 10, "R1's path carried only {grown} bytes");
    assert_eq!(b.inbox().matches("c18 m1").count(), 1, "exactly once on b");
    let entry = learned_entry(&a, &b)
        .unwrap_or_else(|| panic!("a learned nothing from b:\n{}", a_svc.log.text()));
    assert_eq!(learned_relays(&entry), [peer_of(&via_1)], "{entry}");
    let learned_line = "raven-node hints: learned a contact's routes (relays=1";
    assert_eq!(a_svc.log.count(learned_line), 1, "{}", a_svc.log.text());
    let m1_learned = Instant::now();

    // ── B moves to R2 ────────────────────────────────────────────────────
    drop(b_svc);
    // Route-hints lines are one of each kind per 30 s: B's announce must not
    // fall into the window m1's "learned" line opened.
    std::thread::sleep(Duration::from_secs(31).saturating_sub(m1_learned.elapsed()));
    let b_svc = start(&b, "relay", &via_2);
    assert!(
        wait_until(Duration::from_secs(60), || a_svc.log.count(learned_line)
            >= 2),
        "a never learned b's new relay:\n{}\n{}",
        a_svc.log.text(),
        b_svc.log.text()
    );
    assert!(
        b_svc
            .log
            .text()
            .contains("raven-node hints: routes changed; telling 1 contacts"),
        "{}",
        b_svc.log.text()
    );
    let entry = learned_entry(&a, &b).unwrap();
    assert_eq!(learned_relays(&entry), [peer_of(&via_2)], "{entry}");

    // ── m2 through R2, a relay no card names ─────────────────────────────
    let (r2_bytes, r1_bytes) = (p2.recorded().len(), p1.recorded().len());
    assert_eq!(send("c18 m2"), "relayed", "{}", a_svc.log.text());
    let r2_grew = p2.recorded().len() - r2_bytes;
    assert!(
        r2_grew > 2 << 10,
        "R2's path carried only {r2_grew} bytes (R1's: {})",
        p1.recorded().len() - r1_bytes
    );
    assert_eq!(b.inbox().matches("c18 m2").count(), 1, "exactly once on b");
    // R1 may refuse a circuit to B (A's book still names it), never relay one.
    let after = unix_ms() + 2_500;
    let r1_status = r1.wait_status(|s| s["updated_at_ms"].as_u64().is_some_and(|t| t >= after));
    assert_eq!(
        (
            r1_status["counts"]["circuits"].as_u64(),
            r1_status["counts"]["reservations"].as_u64()
        ),
        (Some(0), Some(0)),
        "{r1_status}"
    );
    assert_eq!(
        std::fs::read(a.dir.join("contacts.json")).unwrap(),
        book,
        "a's contacts.json changed"
    );
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        let log = svc.log.text();
        assert!(
            !log.contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{log}"
        );
        for line in log.lines().filter(|l| l.contains("raven-node hints")) {
            assert!(
                !line.contains("/ip4/") && !line.contains("127.0.0.1"),
                "{name}'s hints line names an address: {line}"
            );
        }
    }
}

/// C19: hiding this node's IP from one contact (D4) keeps that contact on
/// relays while another upgrades. A, B and C on one relay R, with the debug
/// `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1` (loopback candidates, so hole punching
/// and the same-network address can work at all); A runs `raven contact
/// hide-ip bob on`. B and C each hold A's LAN route and send A one LAN
/// message: A's route hints tell C its p2p listen address and B none. A↔C
/// then leaves the relay (`direct`, `reversed` or `hole_punched`), while
/// A↔B stays `relayed` on 3 sends each way with no DCUtR upgrade at B. A
/// contact spy A pins, also hidden, gets no Identify from A over the relay.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c19_hide_my_ip_keeps_one_contact_relayed() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    let via = relay.via.clone();
    let a = Profile::create_with(root.path(), "ia", p2p_lab_unlock()).with_route_hints();
    let b = Profile::create_with(root.path(), "ib", p2p_lab_unlock()).with_route_hints();
    let c = Profile::create_with(root.path(), "ic", p2p_lab_unlock()).with_route_hints();
    // Q never runs a service: its card, pinned (and hidden) on A, carries
    // the contact spy's PeerId.
    let q = Profile::create_with(root.path(), "iq", p2p_lab_unlock());
    let contact_spy = spy::peer_id(spy::CONTACT_SEED);
    let cards: Vec<String> = [&a, &b, &c].iter().map(|p| p.p2p_card(&via)).collect();
    let q_card = with_p2p(&q.p2p_card(&via), &contact_spy);
    for (p, card) in [&a, &b, &c].iter().zip(&cards) {
        relay.allow(p, card);
    }
    relay.allow_peer(&a, &contact_spy);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(4));
    let lab = [("RAVEN_LAB_P2P_LOCAL_CANDIDATES", "1")];
    let start = |p: &Profile| {
        let svc = p.start_service_p2p_opts(&P2pStart {
            listen: "127.0.0.1:0",
            relay_via: &via,
            wait_reservation: true,
            env: &lab,
        });
        assert!(
            svc.log
                .text()
                .contains("raven-node p2p: lab hole punching also offers and dials loopback"),
            "{}:\n{}",
            p.name,
            svc.log.text()
        );
        svc
    };
    let a_svc = start(&a);
    let b_svc = start(&b);
    let c_svc = start(&c);
    a.add_card(&cards[1], "bob", &b.fingerprint);
    a.add_card(&cards[2], "carol", &c.fingerprint);
    a.add_card(&q_card, "quill", &q.fingerprint);
    for who in ["@bob", "@quill"] {
        let hide = a.raven(&["contact", "hide-ip", who, "on"], None);
        assert!(hide.ok, "hide-ip {who}:\n{}", hide.all());
    }
    for p in [&b, &c] {
        p.add_card(&cards[0], "alice", &a.fingerprint);
        let lan = p.raven(
            &[
                "contact",
                "set-addr",
                "@alice",
                "--lan",
                &a_svc.lan_listen(),
            ],
            None,
        );
        assert!(lan.ok, "{}", lan.all());
    }
    wait_gate(&a_svc, 3);
    wait_gate(&b_svc, 1);
    wait_gate(&c_svc, 1);

    // ── What each learned over LAN ───────────────────────────────────────
    for (p, text) in [(&b, "c19 b over lan"), (&c, "c19 c over lan")] {
        let sent = p.raven(
            &["send", "--contact", "@alice", "--carrier", "lan"],
            Some(&format!("{text}\n")),
        );
        assert_delivered(&format!("{} → a (lan)", p.name), &sent);
    }
    let c_learned = learned_entry(&c, &a)
        .unwrap_or_else(|| panic!("c learned nothing from a:\n{}", c_svc.log.text()));
    assert!(!learned_direct(&c_learned).is_empty(), "{c_learned}");
    let b_learned = learned_entry(&b, &a)
        .unwrap_or_else(|| panic!("b learned nothing from a:\n{}", b_svc.log.text()));
    assert!(learned_direct(&b_learned).is_empty(), "{b_learned}");
    assert_eq!(learned_relays(&b_learned).len(), 1, "{b_learned}");

    let verbose = [("RAVEN_VERBOSE", "1")];
    let send = |from: &Profile, to: &str, text: &str| {
        let sent = from.raven_with(
            &["send", "--contact", &format!("@{to}"), "--carrier", "p2p"],
            Some(&format!("{text}\n")),
            &verbose,
        );
        assert_delivered(&format!("{} → {to}", from.name), &sent);
        send_path(&sent)
    };
    let upgrade_line = "direct connection upgraded (dcutr)";

    // ── A↔C leaves the relay ─────────────────────────────────────────────
    let c_to_a = send(&c, "alice", "c19 c to a");
    if c_to_a == "relayed" {
        assert!(
            wait_until(Duration::from_secs(30), || {
                a_svc.log.count(upgrade_line) + c_svc.log.count(upgrade_line) > 0
            }),
            "a↔c neither went direct nor hole-punched within 30 s:\n{}\n{}",
            a_svc.log.text(),
            c_svc.log.text()
        );
    }
    let a_to_c = send(&a, "carol", "c19 a to c");
    assert!(
        ["direct", "reversed", "hole_punched"].contains(&a_to_c.as_str()),
        "a→c travelled {a_to_c:?} (c→a: {c_to_a:?}):\n{}",
        a_svc.log.text()
    );

    // ── A↔B stays relayed ────────────────────────────────────────────────
    for i in 1..=3 {
        assert_eq!(send(&a, "bob", &format!("c19 a to b {i}")), "relayed");
        assert_eq!(send(&b, "alice", &format!("c19 b to a {i}")), "relayed");
    }
    for i in 1..=3 {
        let (ab, ba) = (format!("c19 a to b {i}"), format!("c19 b to a {i}"));
        assert_eq!(b.inbox().matches(ab.as_str()).count(), 1, "{ab}");
        assert_eq!(a.inbox().matches(ba.as_str()).count(), 1, "{ba}");
    }
    for (inbox, text) in [
        (a.inbox(), "c19 c to a"),
        (c.inbox(), "c19 a to c"),
        (a.inbox(), "c19 b over lan"),
        (a.inbox(), "c19 c over lan"),
    ] {
        assert_eq!(inbox.matches(text).count(), 1, "{text} exactly once");
    }
    assert_eq!(b_svc.log.count(upgrade_line), 0, "{}", b_svc.log.text());

    // ── The hidden spy: admitted, told nothing ───────────────────────────
    let status = a.raven(&["status"], None);
    let a_peer = status_row(&status.stdout, "p2p_peer")
        .unwrap_or_else(|| panic!("no p2p_peer row:\n{}", status.stdout))
        .to_string();
    let hidden = spy::probe(
        spy::CONTACT_SEED,
        &circuit_to(&via, &a_peer),
        &a_peer,
        spy::Until::QuietAfterIdentify(Duration::from_secs(5)),
        Duration::from_secs(15),
    );
    assert!(hidden.established, "{hidden:?}");
    assert!(
        hidden.identify_addrs.is_none()
            && !hidden.dcutr.iter().any(|r| r == "ok")
            && hidden.direct_dials.is_empty(),
        "a told a contact it hides its IP from something: {hidden:?}"
    );
    for (name, svc) in [("a", &a_svc), ("b", &b_svc), ("c", &c_svc)] {
        assert!(
            !svc.log.text().contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{}",
            svc.log.text()
        );
    }
}

/// C20: the recipient changes network while the sender holds a stale
/// hint. B listens on a loopback port of its own and reserves on a
/// dedicated relay R; its netwatch reads a lab event file (C12). B holds
/// C's LAN route, and its LAN message tells C (route hints) B's p2p listen
/// address: a same-network address, sent on LAN links only (on loopback
/// nothing confirms a global one). B's network changes: it re-homes on the
/// same relay with a new listen port. C→B #1 dials the stale address
/// (refused at once) and the relay together: `relayed`, exactly once,
/// within 30 s. B's next LAN message tells C the new address; R then stops
/// (and C's relayed connection with it: #2 would ride it), and C→B #2 is
/// `direct` to B's new port, exactly once. Both announcers are held
/// (`RAVEN_LAB_HINTS_NO_ANNOUNCE=1`; links still carry RRH1): otherwise B's
/// announcer tells C the new port within its 10 s settle time, or opens a
/// link #1 rides, before #1 is sent; right before #1 the case checks that C
/// still holds only the stale port and that no announcer ran.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c20_recipient_changes_network_while_the_sender_holds_a_stale_hint() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    let via = relay.via.clone();
    let b = Profile::create_with(root.path(), "sb", p2p_lab_unlock()).with_route_hints();
    let c = Profile::create_with(root.path(), "sc", p2p_lab_unlock()).with_route_hints();
    let b_card = b.p2p_card(&via);
    let c_card = c.p2p_card(&via);
    relay.allow(&b, &b_card);
    relay.allow(&c, &c_card);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    let net = root.path().join("b-net.txt");
    std::fs::write(&net, "up 192.0.2.20/24\n").unwrap();
    let net_path = net.to_string_lossy().into_owned();
    let hold = ("RAVEN_LAB_HINTS_NO_ANNOUNCE", "1");
    let b_svc = b.start_service_p2p_opts(&P2pStart {
        listen: "127.0.0.1:0",
        relay_via: &via,
        wait_reservation: true,
        env: &[("RAVEN_LAB_NETWATCH_EVENTS", &net_path), hold],
    });
    let c_svc = c.start_service_p2p_opts(&P2pStart {
        listen: "127.0.0.1:0",
        relay_via: &via,
        wait_reservation: true,
        env: &[hold],
    });
    assert!(
        b_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l
                .contains("raven-node netwatch: watching (1 network)"))
            .is_some(),
        "b's netwatch read no lab baseline:\n{}",
        b_svc.log.text()
    );
    c.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&c_card, "carol", &c.fingerprint);
    let lan = b.raven(
        &[
            "contact",
            "set-addr",
            "@carol",
            "--lan",
            &c_svc.lan_listen(),
        ],
        None,
    );
    assert!(lan.ok, "{}", lan.all());
    wait_gate(&b_svc, 1);
    wait_gate(&c_svc, 1);
    let b_lan = |text: &str| {
        let sent = b.raven(
            &["send", "--contact", "@carol", "--carrier", "lan"],
            Some(&format!("{text}\n")),
        );
        assert_delivered(&format!("b→c (lan) {text}"), &sent);
    };
    let ports = |entry: &serde_json::Value| -> Vec<u16> {
        learned_direct(entry)
            .iter()
            .filter_map(|d| d.split("/tcp/").nth(1)?.split('/').next()?.parse().ok())
            .collect()
    };
    let old_port = p2p_tcp_port(&b);
    b_lan("c20 b over lan");
    let entry = learned_entry(&c, &b)
        .unwrap_or_else(|| panic!("c learned nothing from b:\n{}", c_svc.log.text()));
    assert_eq!(ports(&entry), [old_port], "{entry}");

    // ── B's network changes: the same relay, a new port ──────────────────
    let accepted = || b_svc.log.count("raven-node p2p: reservation accepted");
    let accepted_before = accepted();
    append(&net, "down 192.0.2.20/24\nup 198.51.100.8/24\n");
    assert!(
        b_svc
            .log
            .wait_for(Duration::from_secs(10), |l| l
                .contains("raven-node p2p: re-homed (network changed)"))
            .is_some(),
        "{}",
        b_svc.log.text()
    );
    assert!(
        wait_until(Duration::from_secs(15), || accepted() > accepted_before),
        "no new reservation within 15 s of the change:\n{}",
        b_svc.log.text()
    );
    let mut new_port = old_port;
    assert!(
        wait_until(LOG_TIMEOUT, || {
            new_port = p2p_tcp_port(&b);
            new_port != old_port
        }),
        "b re-homed on its old port {old_port}"
    );

    // ── #1: the stale address fails at once, the relay carries it ────────
    // The premise: C still holds only B's old port, and no announcer ran.
    let entry = learned_entry(&c, &b).unwrap();
    assert_eq!(
        ports(&entry),
        [old_port],
        "c learned the move early: {entry}"
    );
    for (name, svc) in [("b", &b_svc), ("c", &c_svc)] {
        assert_eq!(
            svc.log.count("raven-node hints: routes changed; telling"),
            0,
            "{name}'s announcer ran:\n{}",
            svc.log.text()
        );
    }
    let verbose = [("RAVEN_VERBOSE", "1")];
    let send = |text: &str| {
        let t = Instant::now();
        let sent = c.raven_with(
            &["send", "--contact", "@bob", "--carrier", "p2p"],
            Some(&format!("{text}\n")),
            &verbose,
        );
        assert_delivered(&format!("c→b {text}"), &sent);
        (send_path(&sent), t.elapsed())
    };
    let (path, took) = send("c20 one");
    assert_eq!(path, "relayed", "{}", c_svc.log.text());
    assert!(took < Duration::from_secs(30), "#1 took {took:?}");
    assert_eq!(b.inbox().matches("c20 one").count(), 1, "exactly once on b");

    // ── B's next LAN link tells C the new address ────────────────────────
    b_lan("c20 b after the move");
    let entry = learned_entry(&c, &b).unwrap();
    assert_eq!(ports(&entry), [new_port], "{entry}");
    let lost = || c_svc.log.count("raven-node p2p: reservation lost");
    let lost_before = lost();
    drop(relay);
    assert!(
        wait_until(LOG_TIMEOUT, || lost() > lost_before),
        "c never noticed the relay was gone:\n{}",
        c_svc.log.text()
    );

    // ── #2: direct to the new port ───────────────────────────────────────
    let (path, _) = send("c20 two");
    assert_eq!(path, "direct", "{}", c_svc.log.text());
    assert_eq!(b.inbox().matches("c20 two").count(), 1, "exactly once on b");
    for text in ["c20 b over lan", "c20 b after the move"] {
        assert_eq!(c.inbox().matches(text).count(), 1, "{text} exactly once");
    }
    let log = b_svc.log.text();
    assert_eq!(
        log.matches("raven-node netwatch: network changed").count(),
        1,
        "{log}"
    );
    for (name, svc) in [("b", &b_svc), ("c", &c_svc)] {
        let log = svc.log.text();
        for leak in ["192.0.2.20", "198.51.100.8", "12D3KooW"] {
            assert!(!log.contains(leak), "{name}'s log names {leak}:\n{log}");
        }
    }
}

// ── Friend relays (Phase 2 items 2-3) ─────────────────────────────────────────

/// The friend relay's own lines start with this (never the profile's relay).
const FRIEND_UP: &str = "raven-node friend relay: up";
const FRIEND_STOPPED: &str = "raven-node friend relay: stopped (";
const RELAY_CHOSEN: &str = "raven-node p2p: relay chosen (offered by a contact";
const RELAY_REPLACED: &str = "raven-node p2p: relay replaced";
const RESERVATION_LOST: &str = "raven-node p2p: reservation lost";

/// One profile of a friend relay test ([`friend_circle`]).
struct FriendSpec<'a> {
    /// Its folder under the test's root.
    name: &'static str,
    /// The petname and tag every other profile gives it.
    tag: &'static str,
    /// An operator: its p2p host listens on loopback, and its friend relay
    /// is off until [`offer_friend_relay`]. Otherwise a member: no listener
    /// (`--p2p-listen relay` under the debug `RAVEN_LAB_P2P_RELAY_ONLY=1`),
    /// so only relays reach it: the ones it picks from offers, and
    /// `relay_via`.
    operator: bool,
    /// A relay set by hand (`--p2p-relay`; none when empty), reserved on
    /// before the circle forms.
    relay_via: &'a str,
    /// More environment for its daemon.
    env: &'a [(&'a str, &'a str)],
}

impl<'a> FriendSpec<'a> {
    fn operator(name: &'static str, tag: &'static str, env: &'a [(&'a str, &'a str)]) -> Self {
        Self {
            name,
            tag,
            operator: true,
            relay_via: "",
            env,
        }
    }

    fn member(name: &'static str, tag: &'static str, env: &'a [(&'a str, &'a str)]) -> Self {
        Self {
            name,
            tag,
            operator: false,
            relay_via: "",
            env,
        }
    }

    /// With a relay set by hand.
    fn via(self, relay_via: &'a str) -> Self {
        Self { relay_via, ..self }
    }
}

/// Profiles as `specs` say, with friend relays on
/// ([`Profile::with_friend_relays`]): created (`before_start` sees them: a
/// dedicated relay's allow-list needs their cards), then started. Everyone
/// pins everyone from the card its running daemon prints (`p2p=`, no relay
/// yet) and holds everyone's LAN route: the LAN links carry route hints,
/// and the relay offers in them. Returned once every peer gate admits every
/// other profile.
fn friend_circle(
    root: &Path,
    specs: &[FriendSpec],
    before_start: impl FnOnce(&[Profile]),
) -> Vec<(Profile, Service)> {
    let profiles: Vec<Profile> = specs
        .iter()
        .map(|s| Profile::create_with(root, s.name, p2p_lab_unlock()).with_friend_relays())
        .collect();
    before_start(&profiles);
    let circle: Vec<(Profile, Service)> = profiles
        .into_iter()
        .zip(specs)
        .map(|(p, s)| {
            let svc = p.start_service_p2p_opts(&P2pStart {
                listen: if s.operator { "127.0.0.1:0" } else { "relay" },
                relay_via: s.relay_via,
                wait_reservation: !s.relay_via.is_empty(),
                env: s.env,
            });
            (p, svc)
        })
        .collect();
    let cards: Vec<String> = circle.iter().map(|(p, _)| running_card(p)).collect();
    for (i, (p, _)) in circle.iter().enumerate() {
        for (j, (other, other_svc)) in circle.iter().enumerate() {
            if i == j {
                continue;
            }
            p.add_card(&cards[j], specs[j].tag, &other.fingerprint);
            let tag = format!("@{}", specs[j].tag);
            let lan = p.raven(
                &[
                    "contact",
                    "set-addr",
                    &tag,
                    "--lan",
                    &other_svc.lan_listen(),
                ],
                None,
            );
            assert!(lan.ok, "{} set-addr {tag}:\n{}", p.name, lan.all());
        }
    }
    for (_, svc) in &circle {
        wait_gate(svc, specs.len() - 1);
    }
    circle
}

/// The card `p`'s running daemon makes `raven whoami --card` print: its
/// PeerId (`p2p=`) and the relays it holds now.
fn running_card(p: &Profile) -> String {
    let out = p.raven(&["whoami", "--card"], None);
    assert!(out.ok, "{} whoami --card:\n{}", p.name, out.all());
    let line = out.stdout.trim().to_string();
    assert!(line.contains(" p2p=12D3KooW"), "{line}");
    line
}

/// The `p2p=` PeerId of a card.
fn card_peer(card: &str) -> &str {
    card.split(' ')
        .find_map(|t| t.strip_prefix("p2p="))
        .unwrap_or_else(|| panic!("no p2p= in {card}"))
}

/// `p`'s friend relay status file (its own key's PeerId, its listen
/// addresses, counts); `Null` while there is none.
fn friend_relay_status(p: &Profile) -> serde_json::Value {
    // Sealed (RMS1 kind 30) in a sealed profile (privacy pack PP.6).
    let raw = sealed_text(
        &p.dir,
        "friend_relay/relay_status.json",
        raven_core::at_rest::Kind::FriendRelayStatus,
    );
    serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null)
}

/// The loopback TCP address (`/ip4/127.0.0.1/tcp/N`) `p`'s friend relay
/// listens on, once a run that started after `ups` up lines is up and its
/// status file names an address other than `old`.
fn friend_relay_tcp(p: &Profile, svc: &Service, ups: usize, old: &str) -> String {
    let mut found = String::new();
    let up = wait_until(READY_TIMEOUT, || {
        if svc.log.count(FRIEND_UP) <= ups {
            return false;
        }
        let st = friend_relay_status(p);
        found = st["listen_addrs"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| a.as_str())
            .find(|a| a.contains("/tcp/") && *a != old)
            .unwrap_or("")
            .to_string();
        st["pid"].as_u64() == Some(u64::from(svc.child.id())) && !found.is_empty()
    });
    assert!(
        up,
        "{}'s friend relay is not up on an address other than {old:?}:\n{}",
        p.name,
        svc.log.text()
    );
    found
}

/// How many verified contacts `p`'s running friend relay is offered to now
/// (`offered to` of `raven relay status`; 0 while it offers nothing).
fn offered_to(p: &Profile) -> u32 {
    let out = p.raven(&["relay", "status"], None);
    status_row(&out.stdout, "offered to")
        .and_then(|row| row.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

/// Turn `p`'s friend relay on, then name the address its members reach it
/// at (`relay_external`: `external(<its TCP listen address>)`; on loopback
/// nothing else makes an address worth offering), and wait until it is
/// offered to `members` contacts. Returns the address named.
fn offer_friend_relay(
    p: &Profile,
    svc: &Service,
    members: u32,
    external: impl FnOnce(&str) -> String,
) -> String {
    let ups = svc.log.count(FRIEND_UP);
    p.relay_offer_on(None);
    let named = external(&friend_relay_tcp(p, svc, ups, ""));
    p.relay_offer_on(Some(&named));
    assert!(
        wait_until(LOG_TIMEOUT, || offered_to(p) >= members),
        "{}'s friend relay is not offered to {members} contacts:\n{}\n{}",
        p.name,
        p.raven(&["relay", "status"], None).all(),
        svc.log.text()
    );
    named
}

/// What `p`'s running raven-node says about relays, as `raven doctor`
/// prints it for scripts (ash has no `status --json`): its key=value facts
/// (`relay_offer=yes friend_relay=up friend_relay_members=2 …
/// relay_1_source=offer`) and each slot's state (`relay_1: reserved …`
/// gives `relay_1` = `reserved`).
fn friend_status(p: &Profile) -> HashMap<String, String> {
    let out = p.raven(&["doctor"], None);
    let mut facts = HashMap::new();
    for line in out.stdout.lines().map(str::trim) {
        if let Some((key, rest)) = line.split_once(": ") {
            let slot = key
                .strip_prefix("relay_")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
            if slot {
                let state = rest.split_whitespace().next().unwrap_or("");
                facts.insert(key.to_string(), state.to_string());
                continue;
            }
        }
        for (key, value) in line.split_whitespace().filter_map(|t| t.split_once('=')) {
            let plain = !key.is_empty()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            if plain {
                facts
                    .entry(key.to_string())
                    .or_insert_with(|| value.to_string());
            }
        }
    }
    facts
}

/// Waits (30 s) until `p` holds one relay slot per `sources` entry, in that
/// order (`manual` or `offer`: its `relay_N_source`), each reserved, and no
/// other.
fn wait_relay_source(p: &Profile, sources: &[&str]) -> bool {
    wait_until(Duration::from_secs(30), || {
        let f = friend_status(p);
        let slot = |n: usize, key: &str| f.get(&format!("relay_{n}{key}")).map(String::as_str);
        slot(sources.len() + 1, "").is_none()
            && sources.iter().enumerate().all(|(i, want)| {
                slot(i + 1, "_source") == Some(*want) && slot(i + 1, "") == Some("reserved")
            })
    })
}

/// The `relay N` rows of `p`'s `raven status`, in slot order (`OK — alice's
/// relay (127.0.0.1:N), reserved for …`).
fn relay_rows(p: &Profile) -> Vec<String> {
    let status = p.raven(&["status"], None);
    (1..=4)
        .map_while(|i| status_row(&status.stdout, &format!("relay {i}")).map(str::to_string))
        .collect()
}

/// The operator's petname a relay row names (`alice` in `OK — alice's relay
/// (…`); empty for a relay set by hand.
fn row_owner(row: &str) -> &str {
    row.split_once("'s relay (")
        .map_or("", |(head, _)| head.rsplit(' ').next().unwrap_or(""))
}

/// A `--carrier lan` message from `p` to `tag`, delivered: the link that
/// carries route hints, and relay offers, both ways.
fn lan_send(p: &Profile, tag: &str, text: &str) {
    let out = p.raven(
        &["send", "--contact", &format!("@{tag}"), "--carrier", "lan"],
        Some(&format!("{text}\n")),
    );
    assert_delivered(&format!("{} to {tag} (lan) {text}", p.name), &out);
}

/// A verbose `--carrier p2p` message from `p` to `tag`, delivered: how it
/// travelled (`path=`).
fn p2p_send(p: &Profile, tag: &str, text: &str) -> String {
    let out = p.raven_with(
        &["send", "--contact", &format!("@{tag}"), "--carrier", "p2p"],
        Some(&format!("{text}\n")),
        &[("RAVEN_VERBOSE", "1")],
    );
    assert_delivered(&format!("{} to {tag} (p2p) {text}", p.name), &out);
    send_path(&out)
}

/// No log names a PeerId, and no friend relay, relay choice or route-hints
/// line names an address (counts and ports only).
fn assert_friend_logs_clean(circle: &[(Profile, Service)]) {
    for (p, svc) in circle {
        let log = svc.log.text();
        assert!(
            !log.contains("12D3KooW"),
            "{}'s log names a PeerId:\n{log}",
            p.name
        );
        for line in log.lines().filter(|l| {
            l.contains("raven-node friend relay")
                || l.contains("raven-node p2p: relay ")
                || l.contains("raven-node hints")
        }) {
            assert!(
                !line.contains("/ip4/") && !line.contains("127.0.0.1"),
                "{}'s line names an address: {line}",
                p.name
            );
        }
    }
}

/// The relay PeerIds `p` learned from `operator`'s offers, and their
/// addresses (its learned_routes.json entry).
fn learned_offers(p: &Profile, operator: &Profile) -> Vec<(String, Vec<String>)> {
    let Some(entry) = learned_entry(p, operator) else {
        return Vec::new();
    };
    entry["offers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|o| {
            let addrs = o["addrs"].as_array().into_iter().flatten();
            (
                o["relay_peer_id"].as_str().unwrap_or("").to_string(),
                addrs
                    .filter_map(|a| a.as_str().map(str::to_string))
                    .collect(),
            )
        })
        .collect()
}

/// A lab netwatch event file under `root` with one network: the daemon
/// reads it instead of the OS (no wake clock either), so nothing on the
/// runner restarts its friend relay, and an appended line moves it.
fn lab_network(root: &Path, name: &str) -> PathBuf {
    let path = root.join(format!("{name}-net.txt"));
    std::fs::write(&path, "up 192.0.2.20/24\n").unwrap();
    path
}

/// C21: Alice relays for her verified contacts with a relay key of her own
/// (any-network plan C6) and offers it in her route hints; Bob and Carol
/// pick it (C7). Alice listens on loopback (a lab network file: no OS event
/// restarts her relay); Bob and Carol listen nowhere and set no relay;
/// everyone pins everyone and holds everyone's LAN route. Alice's relay is
/// turned on (node_policy.json, its loopback address named), Bob and Carol
/// each send her one LAN message (her hints answer with the offer), and
/// within 30 s each holds her relay as `relay 1`, from the offer, reserved.
/// Its PeerId is its own (not Alice's p2p PeerId), and her doctor counts 2
/// members and 2 reservations. A LAN message each way tells Bob and Carol
/// each other's relay (their hints); then Carol -> Bob and Bob -> Carol are
/// `path=relayed`, each exactly once. Alice's log has the friend relay's
/// `up` line; no log names a PeerId, nor a relay or hints line an address.
/// `raven relay offer off`: her relay stops within 10 s, Bob's reservation
/// ends with it, and Carol -> Bob waits in Carol's outbox (p2p only: no
/// other path, nothing delivered). Bob's W1c status row is the diagnosis
/// harness's (C26).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c21_friend_relay_offers_its_own_key_and_contacts_select_it() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let net = lab_network(root.path(), "fa")
        .to_string_lossy()
        .into_owned();
    let lab_net = [("RAVEN_LAB_NETWATCH_EVENTS", net.as_str())];
    let circle = friend_circle(
        root.path(),
        &[
            FriendSpec::operator("fa", "alice", &lab_net),
            FriendSpec::member("fb", "bob", &[]),
            FriendSpec::member("fc", "carol", &[]),
        ],
        |_| {},
    );
    let ((a, a_svc), (b, b_svc), (c, c_svc)) = (&circle[0], &circle[1], &circle[2]);

    // ── The offer, and the relay picked from it ──────────────────────────
    offer_friend_relay(a, a_svc, 2, str::to_string);
    let asked = Instant::now();
    lan_send(b, "alice", "c21 ask from bob");
    lan_send(c, "alice", "c21 ask from carol");
    for (p, svc) in [(b, b_svc), (c, c_svc)] {
        assert!(
            wait_relay_source(p, &["offer"]),
            "{} holds no reserved relay from alice's offer:\n{}\n{}",
            p.name,
            p.raven(&["doctor"], None).stdout,
            svc.log.text()
        );
        let rows = relay_rows(p);
        assert_eq!(row_owner(&rows[0]), "alice", "{rows:?}");
    }
    assert!(asked.elapsed() < Duration::from_secs(30), "{asked:?}");
    let relay_peer = friend_relay_status(a)["peer_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(relay_peer.starts_with("12D3KooW"), "{relay_peer:?}");
    assert_ne!(
        relay_peer,
        card_peer(&running_card(a)),
        "the friend relay runs under alice's p2p PeerId"
    );
    let mut facts = HashMap::new();
    assert!(
        wait_until(LOG_TIMEOUT, || {
            facts = friend_status(a);
            [
                "friend_relay",
                "friend_relay_members",
                "friend_relay_reserved",
            ]
            .map(|k| facts.get(k).map(String::as_str))
                == [Some("up"), Some("2"), Some("2")]
        }),
        "alice's friend relay: {facts:?}"
    );

    // ── Bob and Carol through Alice's relay ──────────────────────────────
    lan_send(b, "carol", "c21 hints from bob");
    lan_send(c, "bob", "c21 hints from carol");
    assert!(
        wait_until(LOG_TIMEOUT, || {
            [(c, b), (b, c)].iter().all(|(x, y)| {
                learned_entry(x, y).is_some_and(|e| learned_relays(&e) == [relay_peer.clone()])
            })
        }),
        "bob and carol did not learn each other's relay"
    );
    assert_eq!(
        p2p_send(c, "bob", "c21 relayed to bob"),
        "relayed",
        "{}",
        c_svc.log.text()
    );
    assert_eq!(
        p2p_send(b, "carol", "c21 relayed to carol"),
        "relayed",
        "{}",
        b_svc.log.text()
    );
    assert_eq!(b.inbox().matches("c21 relayed to bob").count(), 1);
    assert_eq!(c.inbox().matches("c21 relayed to carol").count(), 1);
    assert!(a_svc.log.text().contains(FRIEND_UP), "{}", a_svc.log.text());
    assert_friend_logs_clean(&circle);

    // ── Consent off: the relay stops, nothing goes another way ───────────
    let stopped = || a_svc.log.count(FRIEND_STOPPED);
    let lost = || b_svc.log.count(RESERVATION_LOST);
    let (stopped_before, lost_before) = (stopped(), lost());
    let off = a.raven(&["relay", "offer", "off"], None);
    assert!(off.ok, "{}", off.all());
    assert!(
        wait_until(Duration::from_secs(10), || stopped() > stopped_before),
        "alice's friend relay did not stop within 10 s:\n{}",
        a_svc.log.text()
    );
    assert!(
        wait_until(Duration::from_secs(10), || lost() > lost_before),
        "bob kept his reservation on a stopped relay:\n{}",
        b_svc.log.text()
    );
    let text = "c21 after the relay stopped";
    let queued = c.raven(
        &["send", "--contact", "@bob", "--carrier", "p2p"],
        Some(&format!("{text}\n")),
    );
    assert!(
        !queued.ok && queued.all().contains("raven-node keeps trying"),
        "{}",
        queued.all()
    );
    assert!(
        !wait_until(Duration::from_secs(10), || b.inbox().contains(text)),
        "carol's message reached bob with alice's relay stopped"
    );
    assert_friend_logs_clean(&circle);
}

/// C22: a relay whose operator sleeps is replaced, and the change reaches
/// senders through route hints, with no new card. Operators Alice, Dave and
/// Erin each offer their friend relay behind a recording proxy (the proxy's
/// address named, so every path to it is the proxy's) and read a lab
/// network file; Bob and Carol listen nowhere and pick relays fast
/// (`RAVEN_LAB_RELAY_SELECT=6,4,2`, pings every 2 s with a 1 s timeout).
/// Bob picks 2 of the 3 (X, Y; from his status rows); Z is the standby.
/// X's proxy goes Blackhole (the sleep stand-in: Windows has no SIGSTOP):
/// within 45 s (loss seen within 3 s, 6 s of loss, a selection round every
/// 10 s, and once more if an AutoNAT re-home starts the loss clocks over)
/// Bob logs `relay replaced` and holds Y and Z, and his route
/// hints tell Carol about Z (his announce: no card, no LAN message). Then
/// Y's proxy goes Blackhole too, and Carol -> Bob is `relayed` through Z's
/// proxy, exactly once, although Carol's contact book still names no relay
/// of Bob's (byte-identical). X's proxy back to Forward: no further `relay
/// replaced` within 20 s (a replaced relay is not taken back for 30 min),
/// and X is Bob's spare. Logs stay counts-only. The sender is Carol, not an
/// operator: an operator's own p2p PeerId is no member of its own relay.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c22_a_sleeping_relay_is_replaced_and_the_change_reaches_senders_without_new_cards() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let nets: Vec<String> = ["xa", "xd", "xe"]
        .into_iter()
        .map(|n| lab_network(root.path(), n).to_string_lossy().into_owned())
        .collect();
    let op_env: Vec<[(&str, &str); 1]> = nets
        .iter()
        .map(|n| [("RAVEN_LAB_NETWATCH_EVENTS", n.as_str())])
        .collect();
    let fast = [
        ("RAVEN_LAB_RELAY_SELECT", "6,4,2"),
        ("RAVEN_LAB_P2P_PING", "2,1"),
    ];
    let circle = friend_circle(
        root.path(),
        &[
            FriendSpec::operator("xa", "alice", &op_env[0]),
            FriendSpec::operator("xd", "dave", &op_env[1]),
            FriendSpec::operator("xe", "erin", &op_env[2]),
            FriendSpec::member("xb", "bob", &fast),
            FriendSpec::member("xc", "carol", &fast),
        ],
        |_| {},
    );
    let tags = ["alice", "dave", "erin"];
    let ops = &circle[..3];
    let ((b, b_svc), (c, c_svc)) = (&circle[3], &circle[4]);
    let proxies: Vec<RecordingProxy> = ops
        .iter()
        .map(|(p, svc)| {
            let mut proxy = None;
            offer_friend_relay(p, svc, 4, |tcp| {
                let port: u16 = tcp.rsplit('/').next().unwrap().parse().unwrap();
                let px = RecordingProxy::start(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
                let named = format!("/ip4/127.0.0.1/tcp/{}", px.addr.port());
                proxy = Some(px);
                named
            });
            proxy.unwrap()
        })
        .collect();
    let relay_peer = |i: usize| -> String {
        friend_relay_status(&ops[i].0)["peer_id"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    for (p, from) in [(b, "bob"), (c, "carol")] {
        for tag in tags {
            lan_send(p, tag, &format!("c22 ask from {from} to {tag}"));
        }
    }
    for p in [b, c] {
        assert!(
            wait_relay_source(p, &["offer", "offer"]),
            "{} did not pick 2 offered relays:\n{}",
            p.name,
            p.raven(&["doctor"], None).stdout
        );
    }
    let owner_index = |row: &str| {
        tags.iter()
            .position(|t| *t == row_owner(row))
            .unwrap_or_else(|| panic!("{row}"))
    };
    let picked: Vec<usize> = relay_rows(b).iter().map(|r| owner_index(r)).collect();
    let (x, y) = (picked[0], picked[1]);
    let z = (0..3).find(|i| !picked.contains(i)).unwrap();
    // Bob's relays reach Carol's book of learned routes (a LAN link).
    lan_send(b, "carol", "c22 hints from bob");
    lan_send(c, "bob", "c22 hints from carol");
    assert!(
        wait_until(LOG_TIMEOUT, || learned_entry(c, b)
            .is_some_and(|e| learned_relays(&e).len() == 2)),
        "carol did not learn bob's relays"
    );
    let book = std::fs::read(c.dir.join("contacts.json")).unwrap();
    let holds = |want: [usize; 2]| {
        let rows = relay_rows(b);
        rows.len() == 2
            && rows.iter().all(|r| r.starts_with("OK"))
            && want
                .iter()
                .all(|&i| rows.iter().any(|r| row_owner(r) == tags[i]))
    };

    // ── X sleeps: replaced by Z ──────────────────────────────────────────
    let replaced = || b_svc.log.count(RELAY_REPLACED);
    let before = replaced();
    let slept = Instant::now();
    proxies[x].set_mode(ProxyMode::Blackhole);
    assert!(
        wait_until(Duration::from_secs(45), || replaced() > before),
        "bob did not replace the sleeping relay within 45 s:\n{}",
        b_svc.log.text()
    );
    eprintln!("c22: relay replaced {:?} after X slept", slept.elapsed());
    assert!(
        wait_until(LOG_TIMEOUT, || holds([y, z])),
        "bob does not hold Y and Z: {:?}\n{}",
        relay_rows(b),
        b_svc.log.text()
    );
    // His announce tells Carol (one announce link per contact a minute).
    assert!(
        wait_until(Duration::from_secs(90), || learned_entry(c, b)
            .is_some_and(|e| learned_relays(&e).contains(&relay_peer(z)))),
        "carol never learned bob's new relay:\n{}\n{}",
        b_svc.log.text(),
        c_svc.log.text()
    );

    // ── Y sleeps too: only Z, a relay Carol learned through RRH1 ─────────
    proxies[y].set_mode(ProxyMode::Blackhole);
    let z_bytes = proxies[z].recorded().len();
    assert_eq!(
        p2p_send(c, "bob", "c22 through the standby"),
        "relayed",
        "{}",
        c_svc.log.text()
    );
    let grown = proxies[z].recorded().len() - z_bytes;
    assert!(grown > 2 << 10, "Z's proxy carried only {grown} bytes");
    assert_eq!(b.inbox().matches("c22 through the standby").count(), 1);
    assert_eq!(
        std::fs::read(c.dir.join("contacts.json")).unwrap(),
        book,
        "carol's contact book changed"
    );

    // ── X wakes: no swap back, a spare ───────────────────────────────────
    let before = replaced();
    proxies[x].set_mode(ProxyMode::Forward);
    assert!(
        !wait_until(Duration::from_secs(20), || replaced() > before),
        "bob replaced a relay again after X came back:\n{}",
        b_svc.log.text()
    );
    let mut facts = HashMap::new();
    assert!(
        wait_until(LOG_TIMEOUT, || {
            facts = friend_status(b);
            facts.get("relay_standby").map(String::as_str) == Some("1")
        }),
        "bob counts no spare relay: {facts:?}"
    );
    assert_friend_logs_clean(&circle);
}

/// C23: a friend relay that moves is followed through route hints. Bob
/// listens nowhere and holds a dedicated relay R he set by hand (slot 1)
/// and Alice's friend relay from her offer (slot 2); Carol holds Alice's.
/// Alice's network changes (a line in her lab network file): her friend
/// relay starts over with the same key on a new port, and she names the new
/// address. Her offer changes, so her route hints' generation moves and her
/// announce tells Bob: within 30 s Bob holds the same slot at the new
/// address, reserved, and logs no relay chosen or replaced (no reselection).
/// His own announce tells Carol; R stops; and Carol -> Bob is `relayed`
/// through Alice's relay at its new address, exactly once. The move comes a
/// minute after Alice last told Bob anything (one announce link per contact
/// a minute; a relay does not move twice a minute). Alice's announce goes
/// over whichever route her planner picks for Bob (here LAN, the circle's
/// links), not necessarily through R.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c23_a_relay_that_moves_is_followed_through_rrh1() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    let via = relay.via.clone();
    let net = lab_network(root.path(), "ma");
    let net_path = net.to_string_lossy().into_owned();
    let lab_net = [("RAVEN_LAB_NETWATCH_EVENTS", net_path.as_str())];
    let circle = friend_circle(
        root.path(),
        &[
            FriendSpec::operator("ma", "alice", &lab_net),
            FriendSpec::member("mb", "bob", &[]).via(&via),
            FriendSpec::member("mc", "carol", &[]),
        ],
        |profiles| {
            for p in &profiles[..2] {
                relay.allow(p, &p.p2p_card(&via));
            }
            relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
        },
    );
    let ((a, a_svc), (b, b_svc), (c, c_svc)) = (&circle[0], &circle[1], &circle[2]);
    assert!(
        a_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l
                .contains("raven-node netwatch: watching (1 network)"))
            .is_some(),
        "alice's netwatch read no lab baseline:\n{}",
        a_svc.log.text()
    );
    let old = offer_friend_relay(a, a_svc, 2, str::to_string);
    let key = friend_relay_status(a)["peer_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    lan_send(b, "alice", "c23 ask from bob");
    lan_send(c, "alice", "c23 ask from carol");
    let told = Instant::now();
    assert!(
        wait_relay_source(b, &["manual", "offer"]),
        "bob does not hold R and alice's relay:\n{}",
        b.raven(&["doctor"], None).stdout
    );
    assert!(
        wait_relay_source(c, &["offer"]),
        "carol does not hold alice's relay:\n{}",
        c.raven(&["doctor"], None).stdout
    );
    lan_send(b, "carol", "c23 hints from bob");
    lan_send(c, "bob", "c23 hints from carol");
    assert!(
        wait_until(LOG_TIMEOUT, || learned_entry(c, b)
            .is_some_and(|e| learned_relays(&e).len() == 2)),
        "carol did not learn bob's relays"
    );
    let generation = |p: &Profile| learned_entry(p, a).and_then(|e| e["generation"].as_u64());
    let first_generation = generation(b).expect("bob learned nothing from alice");

    // ── Alice's network changes: the same key, a new port ────────────────
    std::thread::sleep(Duration::from_secs(65).saturating_sub(told.elapsed()));
    let ups = a_svc.log.count(FRIEND_UP);
    let picks = || b_svc.log.count(RELAY_CHOSEN) + b_svc.log.count(RELAY_REPLACED);
    let picks_before = picks();
    let moved = Instant::now();
    append(&net, "down 192.0.2.20/24\nup 198.51.100.8/24\n");
    let new = friend_relay_tcp(a, a_svc, ups, &old);
    a.relay_offer_on(Some(&new));
    assert_eq!(
        friend_relay_status(a)["peer_id"].as_str(),
        Some(key.as_str())
    );
    let new_port = new.rsplit('/').next().unwrap().to_string();
    let at_new = format!("127.0.0.1:{new_port})");
    assert!(
        wait_until(Duration::from_secs(30), || relay_rows(b)
            .iter()
            .any(|r| r.starts_with("OK") && r.contains(&at_new))),
        "bob did not follow alice's relay to its new address within 30 s: {:?}\n{}\n{}",
        relay_rows(b),
        b_svc.log.text(),
        a_svc.log.text()
    );
    eprintln!("c23: followed {:?} after the move", moved.elapsed());
    assert!(
        generation(b).is_some_and(|g| g > first_generation),
        "alice's generation did not move"
    );
    assert!(
        learned_offers(b, a)
            .iter()
            .any(|(peer, addrs)| *peer == key && addrs.contains(&new)),
        "{:?}",
        learned_offers(b, a)
    );
    assert_eq!(picks(), picks_before, "{}", b_svc.log.text());
    assert!(wait_relay_source(b, &["manual", "offer"]));

    // ── Bob tells Carol; R stops; Carol through the moved relay ──────────
    let moved_circuit = format!("/tcp/{new_port}/");
    assert!(
        wait_until(Duration::from_secs(90), || learned_entry(c, b).is_some_and(
            |e| e["relays"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|r| r.as_str().is_some_and(|r| r.contains(&moved_circuit)))
        )),
        "carol never learned bob's moved relay:\n{}",
        b_svc.log.text()
    );
    drop(relay);
    assert_eq!(
        p2p_send(c, "bob", "c23 through the moved relay"),
        "relayed",
        "{}",
        c_svc.log.text()
    );
    assert_eq!(b.inbox().matches("c23 through the moved relay").count(), 1);
    assert!(
        wait_until(LOG_TIMEOUT, || friend_relay_status(a)["counts"]["circuits"]
            .as_u64()
            .is_some_and(|n| n >= 1)),
        "alice's relay counts no circuit: {}",
        friend_relay_status(a)
    );
    assert_friend_logs_clean(&circle);
}

/// `out`'s `via=` lines (stdout), in order, without `via=`.
fn via_lines(out: &Output) -> Vec<String> {
    out.stdout
        .lines()
        .filter_map(|l| l.trim().strip_prefix("via="))
        .map(str::to_string)
        .collect()
}

/// `p`'s card as `raven whoami --card` prints it with no `--via`: the relays
/// `raven relay use` saved (no service needs to run).
fn saved_relays_card(p: &Profile) -> String {
    let out = p.raven(&["whoami", "--card"], None);
    assert!(out.ok, "{} whoami --card:\n{}", p.name, out.all());
    let line = out.stdout.trim().to_string();
    assert!(
        line.starts_with("raven-card/2 ") && line.contains(" p2p=12D3KooW"),
        "{line}"
    );
    line
}

/// `raven relay use <vias>` in `p`'s profile (not a terminal: no question).
fn relay_use(p: &Profile, vias: &[&str]) -> Output {
    let words: Vec<String> = vias.iter().map(|v| format!("via={v}")).collect();
    let args: Vec<&str> = ["relay", "use"]
        .into_iter()
        .chain(words.iter().map(String::as_str))
        .collect();
    let out = p.raven(&args, None);
    assert!(out.ok, "{} relay use:\n{}", p.name, out.all());
    out
}

/// One value `key=N` of a counts line (`reservations=2 circuits=1 …`);
/// `refused_reservations=` is not `reservations=`.
fn counts_value(line: &str, key: &str) -> Option<u64> {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
}

/// C24: the relay kit's relay (transports design §3.5; docs/RELAY_KIT.md)
/// with the kit's flags, on loopback. `raven-node relay --check` with
/// `--listen 127.0.0.1:P1 --also-tcp P2 --public-host 127.0.0.1` passes and
/// names ports only (`P1/tcp`, `P1/udp`, `P2/tcp`). Started with the same
/// flags it opens 3 listeners (its up line says so), lists all three in
/// relay_status.json and names the three public addresses (`advertised`).
/// `raven relay card` prints TCP P1, TCP P2, QUIC P1 and, loopback
/// addresses alone, no `raven relay use` line but the `--host` advice; with
/// `--host 127.0.0.1` the same lines and, on stderr, the `raven relay use`
/// line with the two TCP addresses. `raven-node
/// relay-probe` finds the three reachable, a closed port refused and the
/// TCP P1 address under another PeerId answering as a different one. A
/// saves a dead primary (a closed port) and the working P2 with `raven relay
/// use`, B the P1 line; both are in the relay's circle. A reserves exactly
/// once, on the fallback (one relay, two addresses: `reservations 1/1`), the
/// relay holds 2 reservations, A's card carries both addresses, and A→B and
/// B→A are each `path=relayed` and arrive exactly once. No log names a
/// PeerId, and neither the relay's log nor a p2p line names an address.
/// Unix only: SIGTERM stops the relay gracefully (`stopped (2 connection(s)
/// closed)`, exit 0 within 3 s) and A sees its reservation end within 5 s,
/// not at a ping timeout. Windows has no SIGTERM: a child is stopped there
/// with TerminateProcess, which no process can catch (the Windows logon task
/// stops the relay the same way), so that check does not run there.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c24_relay_kit_listeners_card_fallback_and_graceful_stop() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    // P1 carries TCP and QUIC, P2 TCP only; `closed` stays closed.
    let (p1, p2, closed) = (
        free_loopback_tcp_udp_port(),
        free_loopback_port(),
        free_loopback_port(),
    );
    let (listen, also) = (format!("127.0.0.1:{p1}"), p2.to_string());
    let kit_flags = [
        "--listen",
        listen.as_str(),
        "--also-tcp",
        also.as_str(),
        "--public-host",
        "127.0.0.1",
        "--counts-every",
        "30",
    ];
    let a = Profile::create_with(root.path(), "ka", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "kb", p2p_lab_unlock());

    // ── --check: ports only, nothing created ─────────────────────────────
    let r_dir = profile_dir(root.path(), "kit-relay");
    std::fs::create_dir_all(&r_dir).unwrap();
    let mut check = relay_node_command();
    check
        .arg("relay")
        .arg("--data-dir")
        .arg(&r_dir)
        .args(kit_flags)
        .arg("--check");
    let check = run_bounded(check, None, COMMAND_TIMEOUT, "relay --check");
    assert!(check.ok, "relay --check:\n{}", check.all());
    for want in [
        format!("listen {p1}/tcp ok"),
        format!("listen {p1}/udp ok"),
        format!("listen {p2}/tcp ok"),
    ] {
        assert!(check.stdout.contains(&want), "{want}:\n{}", check.all());
    }
    assert!(!check.all().contains("127.0.0.1"), "{}", check.all());
    assert!(
        !r_dir.join("relay_key.ed25519").exists(),
        "--check created the key"
    );

    // ── Three listeners, three named addresses ───────────────────────────
    let relay = Relay::start_with(
        root.path(),
        RelayStart {
            name: "kit-relay",
            args: &kit_flags,
            opts: RelayOpts::default(),
        },
    );
    let up = relay
        .log
        .wait_for(LOG_TIMEOUT, |l| l.contains("raven-node relay: up"))
        .unwrap();
    assert!(
        up.contains("(listeners=3;") && up.contains(&format!("tcp ports {p1},{p2};")),
        "{up}"
    );
    let named = [
        format!("/ip4/127.0.0.1/tcp/{p1}"),
        format!("/ip4/127.0.0.1/udp/{p1}/quic-v1"),
        format!("/ip4/127.0.0.1/tcp/{p2}"),
    ];
    let strs = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    };
    let st = relay.wait_status(|s| strs(&s["listen_addrs"]).len() == 3);
    let mut listening = strs(&st["listen_addrs"]);
    listening.sort();
    let mut want = named.to_vec();
    want.sort();
    assert_eq!(listening, want, "{st}");
    assert_eq!(strs(&st["advertised"]), named, "{st}");
    let r_peer = st["peer_id"].as_str().unwrap().to_string();
    let line = |addr: &str| format!("{addr}/p2p/{r_peer}");

    // ── The card: TCP P1, TCP P2, QUIC P1, and the line for friends ──────
    // Loopback addresses alone give no line for friends: it asks for --host.
    let card = relay.cli(&a, &["relay", "card"]);
    assert!(card.ok, "relay card:\n{}", card.all());
    let (tcp1, tcp2, quic1) = (line(&named[0]), line(&named[2]), line(&named[1]));
    assert_eq!(
        via_lines(&card),
        [tcp1.clone(), tcp2.clone(), quic1.clone()],
        "{}",
        card.all()
    );
    assert!(
        !card.stderr.contains("raven relay use via=")
            && card.stderr.contains("raven relay card --host"),
        "{}",
        card.all()
    );
    let card = relay.cli(&a, &["relay", "card", "--host", "127.0.0.1"]);
    assert!(card.ok, "relay card --host:\n{}", card.all());
    assert_eq!(
        via_lines(&card),
        [tcp1.clone(), tcp2.clone(), quic1.clone()],
        "{}",
        card.all()
    );
    assert!(
        card.stderr
            .contains(&format!("raven relay use via={tcp1} via={tcp2}")),
        "{}",
        card.all()
    );

    // ── relay-probe (K8): each line from outside ─────────────────────────
    let probe = |vias: &[&str]| {
        let mut cmd = relay_node_command();
        cmd.arg("relay-probe").args(vias);
        run_bounded(cmd, None, COMMAND_TIMEOUT, "relay-probe")
    };
    let all = probe(&[&tcp1, &tcp2, &quic1]);
    assert!(all.ok, "relay-probe:\n{}", all.all());
    for label in [
        format!("tcp/{p1}"),
        format!("tcp/{p2}"),
        format!("quic/{p1}"),
    ] {
        assert!(
            all.stdout
                .contains(&format!("{label}: reachable (answers as the relay")),
            "{label}:\n{}",
            all.all()
        );
    }
    let dead = line(&format!("/ip4/127.0.0.1/tcp/{closed}"));
    let refused = probe(&[&dead]);
    assert!(
        !refused.ok
            && refused
                .stdout
                .contains(&format!("tcp/{closed}: refused or unreachable")),
        "{}",
        refused.all()
    );
    let other_peer = raven_core::p2p_route::peer_id_from_ed25519_public(&[5; 32]);
    let other = probe(&[&format!("{}/p2p/{other_peer}", named[0])]);
    assert!(
        !other.ok && other.stdout.contains("DIFFERENT PeerId"),
        "{}",
        other.all()
    );
    for out in [&all, &refused, &other] {
        assert!(
            !out.all().contains("127.0.0.1") && !out.all().contains("12D3KooW"),
            "relay-probe named an address or a PeerId:\n{}",
            out.all()
        );
    }

    // ── A: dead primary, working fallback; B: the P1 line ────────────────
    let used = relay_use(&a, &[&dead, &tcp2]);
    assert!(
        used.stdout
            .contains("1 relay saved (2 addresses: the second address of the same relay"),
        "{}",
        used.all()
    );
    relay_use(&b, &[&tcp1]);
    let a_card = saved_relays_card(&a);
    let b_card = saved_relays_card(&b);
    let a_vias: Vec<&str> = a_card
        .split(' ')
        .filter_map(|t| t.strip_prefix("via="))
        .collect();
    assert_eq!(a_vias, [dead.as_str(), tcp2.as_str()], "{a_card}");
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    let start = |p: &Profile, wait_reservation: bool| {
        p.start_service_p2p_opts(&P2pStart {
            listen: "127.0.0.1:0",
            relay_via: "",
            wait_reservation,
            env: &[],
        })
    };
    let a_svc = start(&a, false);
    let accepted = "raven-node p2p: reservation accepted";
    assert!(
        a_svc
            .log
            .wait_for(Duration::from_secs(20), |l| l
                .contains(&format!("{accepted} (active=1)")))
            .is_some(),
        "a reserved on no address of the relay within 20 s:\n{}",
        a_svc.log.text()
    );
    let b_svc = start(&b, true);
    relay.wait_status(|s| s["counts"]["reservations"].as_u64() == Some(2));
    let status = a.raven(&["status"], None);
    let p2p_row = status_row(&status.stdout, "p2p")
        .unwrap_or_else(|| panic!("no p2p row in a's status:\n{}", status.stdout));
    assert!(p2p_row.contains("reservations 1/1"), "{p2p_row}");

    // ── Relayed both ways, each exactly once ─────────────────────────────
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    let verbose = [("RAVEN_VERBOSE", "1")];
    let send = |from: &Profile, to: &str, text: &str| {
        let sent = from.raven_with(
            &["send", "--contact", &format!("@{to}"), "--carrier", "p2p"],
            Some(&format!("{text}\n")),
            &verbose,
        );
        assert_delivered(&format!("{} → {to}", from.name), &sent);
        send_path(&sent)
    };
    assert_eq!(
        send(&a, "bob", "c24 a to b"),
        "relayed",
        "{}",
        a_svc.log.text()
    );
    assert_eq!(
        send(&b, "alice", "c24 b to a"),
        "relayed",
        "{}",
        b_svc.log.text()
    );
    assert_eq!(
        b.inbox().matches("c24 a to b").count(),
        1,
        "exactly once on b"
    );
    assert_eq!(
        a.inbox().matches("c24 b to a").count(),
        1,
        "exactly once on a"
    );
    assert_eq!(
        a_svc.log.count(accepted),
        1,
        "a reserved more than once:\n{}",
        a_svc.log.text()
    );

    // ── Counts and ports only ────────────────────────────────────────────
    let relay_log = relay.log.text();
    for leak in ["127.0.0.1", "12D3KooW"] {
        assert!(
            !relay_log.contains(leak),
            "the relay's log names {leak}:\n{relay_log}"
        );
    }
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        let log = svc.log.text();
        assert!(
            !log.contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{log}"
        );
        for l in log.lines().filter(|l| l.contains("raven-node p2p:")) {
            assert!(
                !l.contains("127.0.0.1") && !l.contains("/ip4/"),
                "{name}'s p2p line names an address: {l}"
            );
        }
    }

    // ── A graceful stop (Unix: SIGTERM) ──────────────────────────────────
    #[cfg(unix)]
    {
        let mut relay = relay;
        let lost = || a_svc.log.count("raven-node p2p: reservation lost");
        assert_eq!(lost(), 0, "{}", a_svc.log.text());
        let asked = Instant::now();
        let exit = relay.terminate(Duration::from_secs(3));
        let exit = exit.unwrap_or_else(|| {
            panic!(
                "the relay did not stop within 3 s of SIGTERM:\n{}",
                relay.log.text()
            )
        });
        assert!(exit.success(), "{exit:?}:\n{}", relay.log.text());
        assert!(
            relay
                .log
                .wait_for(LOG_TIMEOUT, |l| l
                    .contains("raven-node relay: stopped (2 connection(s) closed)"))
                .is_some(),
            "{}",
            relay.log.text()
        );
        assert!(
            wait_until(
                Duration::from_secs(5).saturating_sub(asked.elapsed()),
                || { lost() >= 1 }
            ),
            "a did not see its reservation end within 5 s:\n{}",
            a_svc.log.text()
        );
    }
}

/// C25: an installed relay kit (the Linux CI install step: the systemd unit
/// with CAP_NET_BIND_SERVICE on TCP 443; docs/RELAY_KIT.md) takes
/// reservations on its 443 line. Skipped unless `RAVEN_RELAY_KIT_VIA` holds
/// that line (`raven-relay card`'s TCP 443 `via=`); `RAVEN_RELAY_KIT_SUDO=1`
/// runs the kit's wrapper as `sudo -n raven-relay` (else `raven-relay` on
/// PATH). Lab profiles A and B: A saves the 443 line alone with `raven relay
/// use`, B the card's first line (TCP on the main port), both cards are
/// allowed with `raven-relay allow --card`, both reserve, A→B and B→A are
/// `path=relayed` and arrive exactly once, and `raven-relay status` counts 2
/// reservations and at least one circuit.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c25_an_installed_relay_takes_reservations_on_443() {
    let Some(via443) = std::env::var("RAVEN_RELAY_KIT_VIA")
        .ok()
        .map(|v| v.trim().trim_start_matches("via=").to_string())
        .filter(|v| !v.is_empty())
    else {
        eprintln!(
            "skipped: RAVEN_RELAY_KIT_VIA (the TCP 443 line of an installed relay kit) is not \
             set; the Linux CI install step sets it"
        );
        return;
    };
    if !lab_ready() {
        return;
    }
    assert!(via443.contains("/tcp/443/p2p/"), "not a 443 line: {via443}");
    let _net = shared_host_network();
    let sudo = std::env::var("RAVEN_RELAY_KIT_SUDO").is_ok_and(|v| v == "1");
    let kit = |args: &[&str]| {
        let mut cmd = if sudo {
            let mut c = Command::new("sudo");
            c.args(["-n", "raven-relay"]);
            c
        } else {
            Command::new("raven-relay")
        };
        cmd.args(args).env("NO_COLOR", "1");
        let out = run_bounded(cmd, None, COMMAND_TIMEOUT, &format!("raven-relay {args:?}"));
        assert!(out.ok, "raven-relay {args:?}:\n{}", out.all());
        out
    };
    let card = kit(&["card"]);
    let lines = via_lines(&card);
    let main = lines
        .first()
        .filter(|l| l.contains("/tcp/") && !l.contains("/tcp/443/"))
        .unwrap_or_else(|| {
            panic!(
                "the kit's card starts with no main TCP line:\n{}",
                card.all()
            )
        })
        .clone();
    assert!(
        lines.contains(&via443),
        "{via443} is not on the card:\n{}",
        card.all()
    );
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create_with(root.path(), "ia", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "ib", p2p_lab_unlock());
    relay_use(&a, &[&via443]);
    relay_use(&b, &[&main]);
    let a_card = saved_relays_card(&a);
    let b_card = saved_relays_card(&b);
    assert!(a_card.contains(&format!(" via={via443}")), "{a_card}");
    for c in [&a_card, &b_card] {
        kit(&["allow", "--card", c]);
    }
    let start = |p: &Profile| {
        p.start_service_p2p_opts(&P2pStart {
            listen: "127.0.0.1:0",
            relay_via: "",
            wait_reservation: true,
            env: &[],
        })
    };
    let a_svc = start(&a);
    let b_svc = start(&b);
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    let verbose = [("RAVEN_VERBOSE", "1")];
    let send = |from: &Profile, to: &str, text: &str| {
        let sent = from.raven_with(
            &["send", "--contact", &format!("@{to}"), "--carrier", "p2p"],
            Some(&format!("{text}\n")),
            &verbose,
        );
        assert_delivered(&format!("{} → {to}", from.name), &sent);
        send_path(&sent)
    };
    assert_eq!(
        send(&a, "bob", "c25 a to b"),
        "relayed",
        "{}",
        a_svc.log.text()
    );
    assert_eq!(
        send(&b, "alice", "c25 b to a"),
        "relayed",
        "{}",
        b_svc.log.text()
    );
    assert_eq!(
        b.inbox().matches("c25 a to b").count(),
        1,
        "exactly once on b"
    );
    assert_eq!(
        a.inbox().matches("c25 b to a").count(),
        1,
        "exactly once on a"
    );
    // The relay rewrites its status every few seconds.
    let mut last = String::new();
    let counted = wait_until(Duration::from_secs(30), || {
        let status = kit(&["status"]);
        last = status.stdout.clone();
        let row = status_row(&status.stdout, "counts").unwrap_or("");
        counts_value(row, "reservations") == Some(2)
            && counts_value(row, "circuits").is_some_and(|n| n >= 1)
    });
    assert!(
        counted,
        "raven-relay status never counted 2 reservations and a circuit:\n{last}"
    );
}

// ── Why a contact cannot be reached (any-network plan, Phase 2 item 5) ─────

/// The line raven-node logs when a dial found a reason: the reason's token
/// only, never a peer or an address.
const UNREACHABLE_LINE: &str = "raven-node p2p: a contact is unreachable (";

/// A `--carrier p2p` message from `p` to `tag` that is not delivered: what
/// `raven send` printed (queued, or NOT SENT for a first message).
fn undelivered_p2p_send(p: &Profile, tag: &str, text: &str) -> Output {
    let out = p.raven(
        &["send", "--contact", &format!("@{tag}"), "--carrier", "p2p"],
        Some(&format!("{text}\n")),
    );
    assert!(!out.ok, "{} to {tag} was delivered:\n{}", p.name, out.all());
    out
}

/// Up to `tries` undelivered sends from `p` to `tag` (a new message each),
/// until one prints `want`; that send's output. A reason that needs a
/// remembered event (a connection the relay closed at once) may show on
/// the second try only.
fn undelivered_until(p: &Profile, tag: &str, label: &str, tries: u32, want: &str) -> String {
    let mut seen = Vec::new();
    for i in 1..=tries {
        let out = undelivered_p2p_send(p, tag, &format!("{label} try {i}")).all();
        if out.contains(want) {
            eprintln!(
                "note: {} to {tag}: {label}: said on try {i} of {tries}",
                p.name
            );
            return out;
        }
        seen.push(out);
    }
    panic!(
        "{} to {tag}: no send of {tries} said {want:?}:\n{}",
        p.name,
        seen.join("\n----\n")
    );
}

/// The `NOT REACHABLE NOW` section of `p`'s `raven status` (empty when it
/// is gone).
fn not_reachable_now(p: &Profile) -> String {
    let status = p.raven(&["status"], None);
    status_section(&status.stdout, "NOT REACHABLE NOW").to_string()
}

/// Waits ([`LOG_TIMEOUT`]) until `p`'s NOT REACHABLE NOW row for `tag`
/// starts with `want` (a worker's retry or a re-home may replace the row
/// for a moment).
fn wait_not_reachable_row(p: &Profile, tag: &str, want: &str) {
    let mut section = String::new();
    assert!(
        wait_until(LOG_TIMEOUT, || {
            section = not_reachable_now(p);
            status_row(&section, tag).is_some_and(|r| r.starts_with(want))
        }),
        "{}: no NOT REACHABLE NOW row for {tag} starting {want:?}:\n{section}",
        p.name
    );
}

/// C26: every reason a contact cannot be reached is said in the send, the
/// queue, `raven status`, `raven doctor` and `raven outbox list`, and goes
/// once the contact is heard again (any-network plan, Phase 2 item 5).
/// Relay-only profiles (no listener: C6's lab mode), cards with `p2p=` and
/// `via=` only. (a) B stops: contact_offline everywhere. (b) B is back: the
/// worker delivers and the section goes. (c) R is killed: A's send names
/// the relay both use (relay_asleep), doctor says W1. (d) B moves to R2,
/// which A may not use: relay_refused. (e) B2 uses no relay and nobody can
/// be reached: both_nat with the three fixes. (f) A pins carol, who can be
/// reached: the fix names her (her card names a loopback address, which
/// counts only under the debug local-candidates switch; without it the fix
/// stays "nobody"). (g) No log names a PeerId, and the new log line names
/// no address.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c26_unreachable_contacts_are_explained() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let mut relay = Relay::start(root.path());
    let a = Profile::create_with(root.path(), "ua", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "ub", p2p_lab_unlock());
    let a_card = a.p2p_card(&relay.via);
    let b_card = b.p2p_card(&relay.via);
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    let a_svc = a.start_service_p2p(&relay.via);
    let b_svc = b.start_service_p2p(&relay.via);
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);

    // ── (a) delivered both ways; then B is offline ───────────────────────
    assert_eq!(p2p_send(&a, "bob", "c26 a to b"), "relayed");
    assert_eq!(p2p_send(&b, "alice", "c26 b to a"), "relayed");
    assert_eq!(b.inbox().matches("c26 a to b").count(), 1);
    assert_eq!(a.inbox().matches("c26 b to a").count(), 1);
    let b_log_first = Arc::clone(&b_svc.log);
    drop(b_svc);
    // R holds B's reservation no more.
    relay.wait_status(|s| s["counts"]["reservations"].as_u64() == Some(1));
    let offline_text = "c26 while bob is offline";
    let queued = undelivered_p2p_send(&a, "bob", offline_text);
    assert!(
        queued.all().contains(
            "queued locally because bob is offline: bob's relay answered, but bob's computer \
             is not connected to it"
        ),
        "{}",
        queued.all()
    );
    assert!(
        queued
            .all()
            .contains("Nothing to do on your side: it goes out when bob is back online."),
        "{}",
        queued.all()
    );
    let mid = queued_mid(&queued);
    wait_not_reachable_row(
        &a,
        "bob",
        "offline \u{2014} bob's computer is not connected to its relay",
    );
    let doctor = a.raven(&["doctor"], None).stdout;
    assert!(
        doctor.contains("  unreachable_contacts: 1 (raven status names them) contact_offline=1"),
        "{doctor}"
    );
    // The row names the last error once the worker's own first try is done
    // (it is due at once after the send queued it).
    let mut list = String::new();
    assert!(
        wait_until(LOG_TIMEOUT, || {
            list = a.raven(&["outbox", "list"], None).all();
            list.contains("last: NOT_REACHABLE (offline: not connected to their relay)")
        }),
        "{list}"
    );

    // ── (b) B is back: the worker delivers, the section goes ──────────────
    let b_svc = b.start_service_p2p(&relay.via);
    let delivered = wait_until(Duration::from_secs(90), || {
        a.raven(&["outbox", "status", &mid], None)
            .stdout
            .contains("state       delivered")
    });
    assert!(
        delivered,
        "not delivered after bob came back:\n{}\n{}",
        a.raven(&["outbox", "status", &mid], None).all(),
        a_svc.log.text()
    );
    assert_eq!(b.inbox().matches(offline_text).count(), 1, "exactly once");
    let mut section = String::new();
    assert!(
        wait_until(Duration::from_secs(30), || {
            section = not_reachable_now(&a);
            section.is_empty()
        }),
        "NOT REACHABLE NOW is still there:\n{section}"
    );

    // ── (c) R is killed: the relay both use is not answering ─────────────
    let (r_tcp, _) = relay.via.split_once("/p2p/").unwrap();
    let r_port = r_tcp.rsplit('/').next().unwrap().to_string();
    let _ = relay.child.kill();
    let _ = relay.child.wait();
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        assert!(
            svc.log
                .wait_for(Duration::from_secs(60), |l| l
                    .contains("raven-node p2p: reservation lost"))
                .is_some(),
            "{name} never lost its reservation:\n{}",
            svc.log.text()
        );
    }
    let asleep = undelivered_until(
        &a,
        "bob",
        "c26 relay asleep",
        3,
        ", which you and bob both use, is not answering",
    );
    assert!(
        asleep.contains(&format!(
            "your relay at 127.0.0.1:{r_port}, which you and bob"
        )),
        "{asleep}"
    );
    let mut doctor = String::new();
    assert!(
        wait_until(Duration::from_secs(60), || {
            doctor = a.raven(&["doctor"], None).stdout;
            doctor.contains("  reach_class: unreachable (")
                && doctor.contains("  reach_next_step: your relay is not answering, so contacts")
        }),
        "{doctor}"
    );
    wait_not_reachable_row(
        &a,
        "bob",
        &format!(
            "no path \u{2014} your relay at 127.0.0.1:{r_port} is not answering (you both use \
             it)"
        ),
    );

    // ── (d) B moves to R2, which serves B only: A is turned away ─────────
    let relay2 = Relay::start_named(root.path(), "relay2");
    let b_card2 = b.p2p_card(&relay2.via);
    relay2.allow(&b, &b_card2);
    relay2.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(1));
    let b_log_second = Arc::clone(&b_svc.log);
    drop(b_svc);
    let b_svc = b.start_service_p2p(&relay2.via);
    // A holds B's new card: B's relay is R2 now.
    let set = a.raven(&["contact", "set-addr", "@bob", "--via", &relay2.via], None);
    assert!(set.ok, "{}", set.all());
    let refused = undelivered_until(
        &a,
        "bob",
        "c26 turned away",
        2,
        "bob's relay turned you away",
    );
    assert!(
        refused.contains("Ask bob whose relay it is and become that person's verified contact"),
        "{refused}"
    );

    // ── (e) B2 uses no relay, and nobody in A's circle can be reached ────
    let b2 = Profile::create_with(root.path(), "uc", p2p_lab_unlock());
    let b2_svc = b2.start_service_p2p_opts(&P2pStart {
        listen: "relay",
        relay_via: "",
        wait_reservation: false,
        env: &[],
    });
    let b2_card = running_card(&b2);
    assert!(!b2_card.contains(" via="), "{b2_card}");
    a.add_card(&b2_card, "b2", &b2.fingerprint);
    let nat = undelivered_p2p_send(&a, "b2", "c26 to b2").all();
    for words in [
        "you and b2 are both behind NAT",
        "this comes from b2's card",
        "Nobody in your circle can be reached",
        "`raven relay offer on`",
        "docs/RELAY_KIT.md",
        "forward port 7423 (TCP and UDP)",
    ] {
        assert!(nat.contains(words), "{words:?} missing:\n{nat}");
    }

    // ── (f) carol can be reached from the internet: the fix names her ────
    let c = Profile::create_with(root.path(), "ud", p2p_lab_unlock());
    let (c_port, c_svc) = start_p2p_on_own_port(
        &c,
        &P2pStart {
            listen: "",
            relay_via: "",
            wait_reservation: false,
            env: &[],
        },
    );
    let c_peer = card_peer(&running_card(&c)).to_string();
    let c_card = c.p2p_card(&format!("/ip4/127.0.0.1/tcp/{c_port}/p2p/{c_peer}"));
    a.add_card(&c_card, "carol", &c.fingerprint);
    // A loopback (or LAN) address says nothing about the internet: carol
    // is named only under the debug local-candidates switch (one machine).
    let not_global = undelivered_p2p_send(&a, "b2", "c26 to b2, carol on loopback").all();
    assert!(
        not_global.contains("Nobody in your circle") && !not_global.contains("ask carol"),
        "{not_global}"
    );
    let friend = a.raven_with(
        &["send", "--contact", "@b2", "--carrier", "p2p"],
        Some("c26 to b2 with carol\n"),
        &[("RAVEN_LAB_P2P_LOCAL_CANDIDATES", "1")],
    );
    assert!(!friend.ok, "a to b2 was delivered:\n{}", friend.all());
    let friend = friend.all();
    assert!(
        friend.contains("carol can be reached from the internet: ask carol to offer relaying"),
        "{friend}"
    );
    assert!(!friend.contains("Nobody in your circle"), "{friend}");

    // ── (g) no PeerId in any log; the reason line names no address ───────
    let logs = [
        ("a", a_svc.log.text()),
        ("b (first)", b_log_first.text()),
        ("b (second)", b_log_second.text()),
        ("b (third)", b_svc.log.text()),
        ("b2", b2_svc.log.text()),
        ("carol", c_svc.log.text()),
        ("r", relay.log.text()),
        ("r2", relay2.log.text()),
    ];
    for (name, log) in &logs {
        assert!(
            !log.contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{log}"
        );
    }
    let lines: Vec<&str> = logs[0]
        .1
        .lines()
        .filter(|l| l.contains(UNREACHABLE_LINE))
        .collect();
    assert!(!lines.is_empty(), "a logged no reason:\n{}", logs[0].1);
    for line in lines {
        let token = line
            .split_once(UNREACHABLE_LINE)
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(token, _)| token)
            .unwrap_or_default();
        assert!(
            raven_core::reach_diag::Why::parse(token).is_some()
                && !line.contains("127.0.0.1")
                && !line.contains("/ip4/"),
            "{line}"
        );
    }
}

/// C35: no route to the internet (a lab netwatch file says `egress none`)
/// while A and B share a LAN (literal routes on loopback), with the p2p host
/// on and a relay at a TEST-NET address nothing answers (cutoff study F9).
/// LAN delivery works both ways, exactly once, each send ending within 8 s;
/// `raven outbox status` keeps the LAN result; `raven status` says W0 and
/// none of W1 to W3; `raven doctor` says `internet_route: none`; and no
/// send, status, outbox or doctor text suggests a relay, a VPS, UPnP or a
/// port forward.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c35_offline_lan_literal_only() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    // RFC 5737: nothing answers there.
    let dead_via = format!("/ip4/192.0.2.1/tcp/7423/p2p/{}", spy::peer_id(0x35));
    let start = |p: &Profile| {
        let net = root.path().join(format!("{}-net.txt", p.name));
        std::fs::write(&net, "up 192.0.2.35/24\negress none\n").unwrap();
        let net = net.to_str().unwrap().to_string();
        p.start_service_p2p_opts(&P2pStart {
            listen: "127.0.0.1:0",
            relay_via: &dead_via,
            wait_reservation: false,
            env: &[("RAVEN_LAB_NETWATCH_EVENTS", &net)],
        })
    };
    let a = Profile::create_with(root.path(), "na", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "nb", p2p_lab_unlock());
    let a_svc = start(&a);
    let b_svc = start(&b);
    // Pinned from cards naming the dead relay, each with the other's LAN
    // address saved as written.
    a.add_card(&b.p2p_card(&dead_via), "bob", &b.fingerprint);
    b.add_card(&a.p2p_card(&dead_via), "alice", &a.fingerprint);
    for (p, tag, other) in [(&a, "@bob", &b_svc), (&b, "@alice", &a_svc)] {
        let set = p.raven(
            &["contact", "set-addr", tag, "--lan", &other.lan_listen()],
            None,
        );
        assert!(set.ok, "{}", set.all());
    }
    // The relay offer as advice (its command, or asking for it): the
    // `circle` row's "no relay offers" is a fact and stays.
    let forbidden = [
        "relay kit",
        "VPS",
        "Raspberry",
        "forward port",
        "UPnP",
        "raven relay offer",
        "offer relaying",
    ];
    let clean = |what: &str, text: &str| {
        for word in forbidden {
            assert!(!text.contains(word), "{what} says {word:?}:\n{text}");
        }
    };
    let mut texts = Vec::new();
    for (p, tag, other, text) in [
        (&a, "bob", &b, "c35 a to b on the lan"),
        (&b, "alice", &a, "c35 b to a on the lan"),
    ] {
        let started = Instant::now();
        let sent = p.raven_with(
            &["send", "--contact", &format!("@{tag}")],
            Some(&format!("{text}\n")),
            &[("RAVEN_VERBOSE", "1")],
        );
        let took = started.elapsed();
        assert_delivered(&format!("{} to {tag}", p.name), &sent);
        assert!(
            took <= Duration::from_secs(8),
            "{} to {tag} took {took:?}",
            p.name
        );
        assert!(sent.stdout.contains("carrier=lan_dial"), "{}", sent.all());
        clean("send", &sent.all());
        assert_eq!(other.inbox().matches(text).count(), 1, "exactly once");
        texts.push((p, sent));
    }
    for (p, sent) in texts {
        // The verbose detail line: `message 1a2b3c4d… via carrier=lan_dial`.
        let mid: String = sent
            .stdout
            .split_once("message ")
            .map(|(_, rest)| rest.chars().take_while(char::is_ascii_hexdigit).collect())
            .unwrap_or_default();
        assert_eq!(mid.len(), 8, "{}", sent.all());
        let st = p.raven(&["outbox", "status", &mid], None);
        assert!(
            st.ok
                && st.stdout.contains("state       delivered")
                && !st.stdout.contains("NOT_REACHABLE")
                && !st.stdout.contains("  why "),
            "{}",
            st.all()
        );
        clean("outbox status", &st.all());
        let list = p.raven(&["outbox", "list"], None);
        assert!(list.stdout.contains("Nothing waiting"), "{}", list.all());
        clean("outbox list", &list.all());
    }
    let w0 = "this computer has no route to the internet right now: contacts outside this \
              network cannot reach you, and nothing on this computer can change that. People \
              on this network (Wi-Fi, hotspot or cable) still can.";
    for p in [&a, &b] {
        let status = p.raven(&["status"], None);
        let reach = status_section(&status.stdout, "REACHABILITY");
        assert_eq!(
            status_row(reach, "what to do"),
            Some(w0),
            "{}",
            status.stdout
        );
        // W1 (and W1b, W1c), W2, W3: the `circle` row is a fact, no advice.
        for w in [
            "your relay is not answering",
            "relays your contacts offered are not answering",
            "one of your two relays is not answering",
            "you are behind NAT and no relay is in use",
            "so nobody outside this network can reach you. Any one of these fixes it",
        ] {
            assert!(!status.stdout.contains(w), "{w:?}:\n{}", status.stdout);
        }
        clean("status", &status.all());
        let doctor = p.raven(&["doctor"], None);
        assert!(
            doctor.stdout.contains("  internet_route: none"),
            "{}",
            doctor.stdout
        );
        clean("doctor", &doctor.all());
    }
}

/// C36's four replies (module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C36Arm {
    /// (1) Nothing on: the gap this case documents.
    Gap,
    /// (2) Route hints: B announced its port (RRH1).
    RouteHints,
    /// (3) F7: B's last address on the (lab) default port.
    Guess,
    /// (4) F7 with no noise pin for B: no guess.
    NoPin,
    /// (5) Phase 3 P3.C5: (3) with the LAN beacon on a lab bus and B on a
    /// port of its own: what A's beacon found when it answered B's query is
    /// dialled, the guess never.
    Beacon,
}

/// C36: see the module doc. Each arm on its own profiles.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c36_hotspot_host_learns_client() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    for arm in [
        C36Arm::Gap,
        C36Arm::RouteHints,
        C36Arm::Guess,
        C36Arm::NoPin,
        C36Arm::Beacon,
    ] {
        c36_round(arm);
    }
}

fn c36_round(arm: C36Arm) {
    let root = tempfile::tempdir().unwrap();
    let (an, bn) = match arm {
        C36Arm::Gap => ("ha", "hb"),
        C36Arm::RouteHints => ("ia", "ib"),
        C36Arm::Guess => ("ja", "jb"),
        C36Arm::NoPin => ("ka", "kb"),
        C36Arm::Beacon => ("la", "lb"),
    };
    let f7 = matches!(arm, C36Arm::Guess | C36Arm::NoPin | C36Arm::Beacon);
    // F7's default port: a free one, never 7420 (the live node's). In (5)
    // a port that counts every connection (and closes it): the guess.
    let decoy = (arm == C36Arm::Beacon).then(ClosingPort::start);
    let port = decoy.as_ref().map_or_else(free_loopback_port, |d| {
        d.addr.rsplit_once(':').unwrap().1.parse().unwrap()
    });
    assert_ne!(port, 7420);
    let mut a = Profile::create(root.path(), an).with_noise_pin(true);
    let mut b = Profile::create(root.path(), bn).with_noise_pin(true);
    if f7 {
        a = a
            .with_lab_env("RAVEN_LAB_OFFLINE", "1")
            .with_lab_env("RAVEN_LAB_LAN_DEFAULT_PORT", &port.to_string());
    } else {
        // Closed whatever the const says (after CP.16 too).
        a = a.with_lab_env("RAVEN_LAB_OFFLINE", "0");
    }
    if arm == C36Arm::RouteHints {
        a = a.with_route_hints();
        b = b.with_route_hints();
    }
    // (5): the beacon on a bus of the test's own (127.0.0.1 only).
    if arm == C36Arm::Beacon {
        let bus_file = root.path().join("bus.txt");
        std::fs::write(
            &bus_file,
            format!("{}\n", root.path().join("bus").display()),
        )
        .unwrap();
        let bus_file = bus_file.to_str().unwrap().to_string();
        a = a
            .with_lab_env("RAVEN_LAB_LAN_BEACON", "1")
            .with_lab_env("RAVEN_LAB_LAN_BEACON_BUS", &bus_file);
        b = b
            .with_lab_env("RAVEN_LAB_LAN_BEACON", "1")
            .with_lab_env("RAVEN_LAB_LAN_BEACON_BUS", &bus_file);
    }
    let a_svc = a.start_service();
    let b_listen = format!("127.0.0.1:{port}");
    let b_svc = if f7 && arm != C36Arm::Beacon {
        b.start_service_on(&b_listen, None)
    } else {
        b.start_service()
    };
    // A added B from B's invite line: no address to reach B by.
    let invite = format!("raven:{}:{}", b.address, b.pub_hex);
    let added = a.raven(
        &[
            "contact",
            "add",
            "--card",
            &invite,
            "--petname",
            "bob",
            "--tag",
            "bob",
        ],
        None,
    );
    assert!(
        added.ok,
        "{arm:?}: a contact add:
{}",
        added.all()
    );
    b.add_contact(&a, "alice", &a_svc.lan_dial);
    if arm == C36Arm::Beacon {
        // Both beacons run (each starts once its node loaded the profile),
        // so B's hello asks for A, and A, answering, notes where B is.
        let on = |p: &Profile| beacon_json(p)["state"] == "on";
        assert!(
            wait_until(Duration::from_secs(30), || on(&a) && on(&b)),
            "{arm:?}: the beacons are not on: {} {}",
            beacon_json(&a),
            beacon_json(&b)
        );
    }
    let hello = b.send("alice", &format!("c36 hello {arm:?}"));
    assert_delivered(&format!("{arm:?} b→a (b dials once)"), &hello);
    let pinned = || noise_pins_text(&a.dir).contains(&b.pub_hex);
    assert!(
        wait_until(Duration::from_secs(10), pinned),
        "{arm:?}: A has no noise pin for B:
{}",
        a_svc.log.text()
    );
    if arm == C36Arm::RouteHints {
        // B's RRH1 follows A's on that link: wait until A stored it.
        let told = wait_until(Duration::from_secs(10), || {
            learned_entry(&a, &b).is_some_and(|e| e["lan"]["lan_port"].as_u64().is_some())
        });
        assert!(told, "A learned nothing from B:\n{}", a_svc.log.text());
    }
    if arm == C36Arm::NoPin {
        std::fs::remove_file(noise_pin_file(&a.dir)).unwrap();
    }

    let text = format!("c36 reply {arm:?}");
    let started = Instant::now();
    let sent = a.raven_with(
        &["send", "--contact", "@bob"],
        Some(&format!("{text}\n")),
        &[("RAVEN_VERBOSE", "1")],
    );
    let took = started.elapsed();
    let all = sent.all();
    assert!(
        !all.contains("127.0.0.1:7420"),
        "{arm:?}: dialled 7420?\n{all}"
    );
    let book = || a.book();
    match arm {
        C36Arm::Gap | C36Arm::NoPin => {
            assert!(!sent.ok, "{arm:?}: sent?\n{all}");
            assert!(all.contains("has no reachable lan_dial"), "{arm:?}:\n{all}");
            assert_eq!(b.inbox().matches(text.as_str()).count(), 0);
        }
        C36Arm::RouteHints | C36Arm::Guess => {
            assert_delivered(&format!("{arm:?} a→b (the reply)"), &sent);
            assert!(took <= Duration::from_secs(5), "{arm:?}: took {took:?}");
            assert!(sent.stdout.contains("carrier=lan_dial"), "{all}");
            // RRH1 named B's real port; F7 guessed the (lab) default one.
            let reached = if arm == C36Arm::Guess {
                b_listen.clone()
            } else {
                b_svc.lan_dial.clone()
            };
            assert!(
                all.contains(&format!("LAN dial {reached} (learned · bob")),
                "{arm:?}:\n{all}"
            );
            assert!(
                all.contains(&format!("Saved {reached} as their LAN address")),
                "{arm:?}:\n{all}"
            );
            assert!(book().contains(&reached), "{arm:?}:\n{}", book());
            assert_eq!(b.inbox().matches(text.as_str()).count(), 1, "once");
        }
        C36Arm::Beacon => {
            assert_delivered(&format!("{arm:?} a→b (the reply)"), &sent);
            assert!(took <= Duration::from_secs(5), "{arm:?}: took {took:?}");
            assert!(sent.stdout.contains("carrier=lan_dial"), "{all}");
            // The beacon's find, at B's own port, went first; the guess
            // at the default port was never dialled, and a find is never
            // saved.
            assert!(all.contains("found on your network now"), "{arm:?}:\n{all}");
            assert!(all.contains(&b_svc.lan_dial), "{arm:?}:\n{all}");
            assert!(!all.contains(&b_listen), "{arm:?}: guessed?\n{all}");
            assert!(!book().contains(&b_svc.lan_dial), "{arm:?}:\n{}", book());
            assert_eq!(b.inbox().matches(text.as_str()).count(), 1, "once");
            // A found B by answering the query of B's hello.
            let a_beacon = beacon_json(&a);
            assert!(
                a_beacon["answers_sent_10m"].as_u64().unwrap_or(0) >= 1,
                "{arm:?}: A answered no query: {a_beacon}"
            );
        }
    }
    if let Some(decoy) = decoy {
        assert_eq!(
            decoy.accepted(),
            0,
            "{arm:?}: the guessed default port was dialled"
        );
    }
    for line in a_svc.log.text().lines() {
        assert!(!line.contains("127.0.0.1:7420"), "{arm:?}: {line}");
    }
}

/// C38: see the module doc.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c38_outbox_wakes_on_sibling_success() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    // Both gates open, so F7 is live too: its default port is a free one,
    // never 7420 (every contact here has a saved route anyway).
    let guess = free_loopback_port();
    assert_ne!(guess, 7420);
    let lab = |p: Profile| {
        p.with_noise_pin(true)
            .with_lab_env("RAVEN_LAB_OFFLINE", "1")
            .with_lab_env("RAVEN_LAB_LAN_DEFAULT_PORT", &guess.to_string())
    };
    let a = lab(Profile::create(root.path(), "wa"));
    let b = lab(Profile::create(root.path(), "wb"));
    let c = lab(Profile::create(root.path(), "wc"));
    let b_listen = format!("127.0.0.1:{}", free_loopback_port());
    let c_listen = format!("127.0.0.1:{}", free_loopback_port());
    let a_svc = a.start_service();
    let b_svc = b.start_service_on(&b_listen, None);
    let c_svc = c.start_service_on(&c_listen, None);
    a.add_contact(&b, "bob", &b_listen);
    a.add_contact(&c, "carol", &c_listen);
    b.add_contact(&a, "alice", &a_svc.lan_dial);
    c.add_contact(&a, "alice", &a_svc.lan_dial);
    // Linked once: A pins B's and C's Noise statics (M0).
    assert_delivered("c38 a→b", &a.send("bob", "c38 hello bob"));
    assert_delivered("c38 a→c", &a.send("carol", "c38 hello carol"));
    let pinned = || {
        let pins = noise_pins_text(&a.dir);
        pins.contains(&b.pub_hex) && pins.contains(&c.pub_hex)
    };
    assert!(
        wait_until(Duration::from_secs(10), pinned),
        "A has no noise pins for B and C:\n{}",
        a_svc.log.text()
    );

    // Both away: A's messages wait until its next try for B is a minute or
    // more away.
    drop(b_svc);
    drop(c_svc);
    let (to_bob, to_carol) = ("c38 for bob while away", "c38 for carol while away");
    let queued_b = a.send("bob", to_bob);
    assert!(!queued_b.ok, "nothing confirmed it:\n{}", queued_b.all());
    let mid_b = queued_mid(&queued_b);
    let queued_c = a.send("carol", to_carol);
    assert!(!queued_c.ok, "nothing confirmed it:\n{}", queued_c.all());
    let deadline = Instant::now() + Duration::from_secs(420);
    loop {
        let st = a.raven(&["outbox", "status", &mid_b], None);
        assert!(st.ok, "{}", st.all());
        if status_next_try_secs(&st).is_some_and(|s| s >= 60) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "A's next try for B never reached a minute:\n{}\n{}",
            st.all(),
            a_svc.log.text()
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    // B comes back on its port and stays silent: only A's backoff would
    // reach it, a minute or more from now.
    let _b_svc = b.start_service_on(&b_listen, None);
    let before = a.raven(&["outbox", "status", &mid_b], None);
    let left = status_next_try_secs(&before).unwrap_or(0);
    assert!(
        left >= 30 && !before.stdout.contains("state       delivered"),
        "A's next try for B is too close to tell:\n{}",
        before.all()
    );
    // C comes back and dials A.
    let _c_svc = c.start_service_on(&c_listen, None);
    assert_delivered("c38 c→a (C's link)", &c.send("alice", "c38 carol is back"));
    let linked = Instant::now();
    let delivered = wait_until(Duration::from_secs(20), || {
        a.raven(&["outbox", "status", &mid_b], None)
            .stdout
            .contains("state       delivered")
    });
    let took = linked.elapsed();
    assert!(
        delivered,
        "B's message was not delivered after C's link:\n{}\n{}",
        a.raven(&["outbox", "status", &mid_b], None).all(),
        a_svc.log.text()
    );
    // NETWORK_SPREAD (5 s), plus one loopback dial and this poll.
    assert!(
        took <= Duration::from_secs(5 + 3),
        "B's message took {took:?} after C's link (A's own next try was {left} s away)"
    );
    eprintln!("c38: B delivered {took:?} after C's link (A's own next try was {left} s away)");
    let woke = "raven-node outbox: a contact answered on this network; retrying 1 others";
    assert_eq!(a_svc.log.count(woke), 1, "{}", a_svc.log.text());
    let carol_back = wait_until(Duration::from_secs(20), || {
        c.inbox().matches(to_carol).count() == 1
    });
    assert!(
        carol_back,
        "C's message (A's dial-back):\n{}",
        a_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(b.inbox().matches(to_bob).count(), 1, "exactly once on B");
    assert_eq!(c.inbox().matches(to_carol).count(), 1, "exactly once on C");
    for line in a_svc.log.text().lines() {
        assert!(!line.contains("127.0.0.1:7420"), "{line}");
    }
}

/// What X, C39's scripted responder on a friend's old port, got on one
/// connection.
#[derive(Clone, Debug, PartialEq, Eq)]
enum XSaw {
    /// Noise message 1 and then the end: no message 3, no bind.
    MessageOneOnly,
    /// The whole handshake and the dialer's signed bind: its Ed25519 key.
    Bind(String),
    Broken(String),
}

/// C39's X: a Noise XX responder built from `raven_core::lan_noise` with
/// its own identity, answering every connection on `addr` and keeping what
/// each dialer sent. Stopped (and its port freed) when dropped.
struct ScriptedX {
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<XSaw>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ScriptedX {
    /// Bind `addr` (the friend's port; retried for a few seconds while the
    /// friend's listener lets it go) and serve until dropped.
    fn start(addr: &str) -> Self {
        let deadline = Instant::now() + Duration::from_secs(10);
        let listener = loop {
            match std::net::TcpListener::bind(addr) {
                Ok(l) => break l,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => panic!("X could not bind {addr}: {e}"),
            }
        };
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (flag, log) = (stop.clone(), seen.clone());
        let thread = std::thread::spawn(move || {
            let x = raven_core::identity::Identity::from_seed(&[0x39; 32]);
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let saw = Self::answer(stream, &x);
                        log.lock().unwrap().push(saw);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Self {
            stop,
            seen,
            thread: Some(thread),
        }
    }

    /// One `u32_be || payload` frame; `None` at a clean end.
    fn frame(stream: &mut std::net::TcpStream) -> Result<Option<Vec<u8>>, String> {
        let mut len = [0u8; 4];
        match stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.to_string()),
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > raven_core::lan_noise::MAX_NOISE_MSG {
            return Err(format!("frame length {n}"));
        }
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).map_err(|e| e.to_string())?;
        Ok(Some(buf))
    }

    fn answer(mut stream: std::net::TcpStream, x: &raven_core::identity::Identity) -> XSaw {
        use raven_core::lan_noise::{
            build_responder, derive_noise_static, get_remote_static, handshake_read,
            handshake_write, into_transport, transport_decrypt, verify_bind,
        };
        let mut run = || -> Result<XSaw, String> {
            stream.set_nonblocking(false).map_err(|e| e.to_string())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .map_err(|e| e.to_string())?;
            let secret = derive_noise_static(x).map_err(|e| e.to_string())?;
            let mut hs = build_responder(&secret).map_err(|e| e.to_string())?;
            let m1 = Self::frame(&mut stream)?.ok_or("no message 1")?;
            handshake_read(&mut hs, &m1).map_err(|e| e.to_string())?;
            let m2 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
            let mut framed = (m2.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(&m2);
            stream.write_all(&framed).map_err(|e| e.to_string())?;
            let Some(m3) = Self::frame(&mut stream)? else {
                return Ok(XSaw::MessageOneOnly);
            };
            handshake_read(&mut hs, &m3).map_err(|e| e.to_string())?;
            let dialer_static = get_remote_static(&hs).map_err(|e| e.to_string())?;
            let mut t = into_transport(hs).map_err(|e| e.to_string())?;
            let ct = Self::frame(&mut stream)?.ok_or("no bind")?;
            let bind = transport_decrypt(&mut t, &ct).map_err(|e| e.to_string())?;
            let ed = verify_bind(&bind, &dialer_static, None).map_err(|e| e.to_string())?;
            Ok(XSaw::Bind(hex::encode(ed)))
        };
        run().unwrap_or_else(XSaw::Broken)
    }

    fn seen(&self) -> Vec<XSaw> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for ScriptedX {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// C39: see the module doc. Both rounds in one test (the gate open, then
/// closed), each with its own profiles.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c39_a_stranger_at_a_friends_address_learns_nothing() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    for gate in [true, false] {
        c39_round(gate);
    }
}

fn c39_round(gate: bool) {
    let root = tempfile::tempdir().unwrap();
    let (an, bn) = if gate { ("pa", "pb") } else { ("qa", "qb") };
    let a = Profile::create(root.path(), an).with_noise_pin(gate);
    let b = Profile::create(root.path(), bn).with_noise_pin(gate);
    let b_listen = format!("127.0.0.1:{}", free_loopback_port());
    let a_svc = a.start_service();
    let b_svc = b.start_service_on(&b_listen, None);
    a.add_contact(&b, "bob", &b_svc.lan_dial);
    b.add_contact(&a, "alice", &a_svc.lan_dial);
    assert_delivered("a→b (the link that pins)", &a.send("bob", "c39 first"));
    assert_eq!(
        noise_pins_text(&a.dir).contains(&b.pub_hex),
        gate,
        "gate={gate}: A's pin for B"
    );

    // B is gone; X answers at his old address.
    drop(b_svc);
    let x = ScriptedX::start(&b_listen);
    let text = format!("c39 while x answers gate={gate}");
    let started = Instant::now();
    let sent = a.send("bob", &text);
    let took = started.elapsed();
    assert!(!sent.ok, "nothing confirmed it:\n{}", sent.all());
    let saw =
        |pred: &dyn Fn(&[XSaw]) -> bool| wait_until(Duration::from_secs(20), || pred(&x.seen()));
    if !gate {
        // Today: X completes the handshake and reads A's signed bind.
        assert!(
            saw(&|s| s.contains(&XSaw::Bind(a.pub_hex.clone()))),
            "X learned A's key with the gate closed: {:?}\n{}",
            x.seen(),
            sent.all()
        );
        return;
    }
    let all = sent.all();
    assert!(
        all.contains("something else answered at bob's address at 127.0.0.1:")
            && all
                .contains("it is not bob's RAVEN, so RAVEN stopped before telling it who you are")
            && all.contains(
                "It waits until bob connects to you or you change networks; if bob \
                 reinstalled RAVEN, get their new invite and add them again."
            ),
        "{all}"
    );
    assert!(
        all.contains("raven-node keeps trying in the background until"),
        "{all}"
    );
    assert!(took < Duration::from_secs(10), "raven send took {took:?}");
    // raven send's probe and the outbox worker's first try: message 1
    // only, each time.
    assert!(saw(&|s| !s.is_empty()), "X saw no connection");
    std::thread::sleep(Duration::from_secs(2));
    let got = x.seen();
    assert!(
        !got.is_empty() && got.iter().all(|s| *s == XSaw::MessageOneOnly),
        "{got:?}"
    );
    drop(x);

    // B is back at his old address and sends: A's queued message follows,
    // with no `raven outbox retry`.
    let b_svc = b.start_service_on(&b_listen, None);
    assert_eq!(b_svc.lan_dial, b_listen);
    assert_delivered("b→a (bob is back)", &b.send("alice", "c39 bob is back"));
    let arrived = wait_until(Duration::from_secs(60), || {
        b.inbox().matches(text.as_str()).count() >= 1
    });
    assert!(
        arrived,
        "A's queued message did not reach B:\n{}\n{}\n{}",
        a.raven(&["outbox", "list"], None).all(),
        a_svc.log.text(),
        b_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(b.inbox().matches(text.as_str()).count(), 1, "exactly once");
    // Nothing logged about it names the address or a key (counts only).
    for line in a_svc.log.text().lines() {
        let l = line.to_lowercase();
        if l.contains("noise pin") || l.contains("wrong_identity") {
            assert!(
                !line.contains(&b_listen) && !l.contains(&b.pub_hex.to_lowercase()),
                "{line}"
            );
        }
    }
}

/// C90 (privacy pack PP.4): the sealed contact book at work, from a plain
/// fixture to admission, removal, re-adding and a restart (module docs).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c90_sealed_book_admission_and_reload() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create_plain(root.path(), "a");
    let b = Profile::create_plain(root.path(), "b");
    let a_listen = format!("127.0.0.1:{}", free_loopback_port());
    let b_listen = format!("127.0.0.1:{}", free_loopback_port());
    a.add_contact(&b, "bob", &b_listen);
    b.add_contact(&a, "alice", &a_listen);
    let sealed = |p: &Profile| {
        std::fs::read(p.dir.join(raven_core::contact_book::CONTACTS_FILE))
            .unwrap()
            .starts_with(b"RMS1")
    };
    for p in [&a, &b] {
        assert!(!sealed(p), "{}: the fixture is a plain book", p.name);
        assert!(
            !p.dir.join(raven_core::at_rest::META_KEY_FILE).exists(),
            "{}: sealed before its daemon started",
            p.name
        );
    }
    // The daemons seal at their start (their commands never did).
    let start = |p: &Profile, listen: &str| {
        let svc = p.start_service_env(listen, None, &[("RAVEN_LAB_AT_REST", "1")]);
        assert_eq!(svc.lan_dial, listen);
        svc
    };
    let a_svc = start(&a, &a_listen);
    let b_svc = start(&b, &b_listen);
    for (p, svc, other) in [(&a, &a_svc, &b), (&b, &b_svc, &a)] {
        let settled = svc.log.wait_for(LOG_TIMEOUT, |l| {
            l.trim().ends_with(" raven-node at_rest: sealed")
        });
        // The book, and since PP.5 the device registry, the device key and
        // the prekey store `raven init` wrote; since Phase 5 (P5.11) also the
        // archive of the prekey bundles this computer published.
        assert!(
            settled.is_some() && svc.log.count("raven-node at_rest: sealed 5 file(s)") == 1,
            "{}: the daemon did not seal the book at its start:\n{}",
            p.name,
            svc.log.text()
        );
        assert!(sealed(p), "{}: the book is not RMS1", p.name);
        for name in [
            "device_registry.json",
            "device_x25519.secret",
            "prekey_store.json",
            "prekey_published_local.json",
        ] {
            let raw = std::fs::read(p.dir.join(name)).unwrap();
            assert!(raven_core::at_rest::is_sealed(&raw), "{}: {name}", p.name);
        }
        assert!(p.book().contains(&other.pub_hex), "{}", p.name);
    }

    // Both ways.
    assert_delivered("a→b", &a.send("bob", "c90 hello from a"));
    assert!(b.inbox().contains("c90 hello from a"));
    assert_delivered("b→a", &b.send("alice", "c90 hello from b"));
    assert!(a.inbox().contains("c90 hello from b"));
    // Status and doctor say it in words and counts, no names: the five
    // files above, A's certificate, which B's link cached, and (privacy
    // pack PP.6) where A's link came from (lan_seen.json), all sealed.
    for name in ["peer_device_certs.json", "lan_seen.json"] {
        assert!(
            raven_core::at_rest::is_sealed(&std::fs::read(b.dir.join(name)).unwrap()),
            "{name}"
        );
    }
    assert!(peer_cert_cache(&b.dir).contains(&a.pub_hex));
    let status = b.raven(&["status"], None);
    assert_eq!(
        status_row(&status.stdout, "at_rest"),
        Some("encrypted on this computer (7 files)"),
        "{}",
        status.all()
    );
    let doctor = b.raven(&["doctor"], None);
    assert!(
        doctor.stdout.contains("  at_rest: state=sealed files=7\n"),
        "{}",
        doctor.all()
    );

    // B removes A while B's daemon runs: A's next send is refused at once.
    let removed = b.raven(&["contact", "remove", "--petname", "alice", "--yes"], None);
    assert!(removed.ok, "{}", removed.all());
    assert!(sealed(&b) && !b.book().contains(&a.pub_hex));
    let refusals = b_svc.log.count("not a local contact");
    let refused = a.send("bob", "c90 after the removal");
    assert!(
        !refused.ok,
        "delivered to a removed contact:\n{}",
        refused.all()
    );
    assert!(
        !refused.all().to_lowercase().contains("status: delivered"),
        "{}",
        refused.all()
    );
    assert!(
        wait_until(LOG_TIMEOUT, || b_svc.log.count("not a local contact")
            > refusals),
        "B did not refuse A at its link:\n{}",
        b_svc.log.text()
    );
    assert!(!b.inbox().contains("c90 after the removal"));

    // B adds A back: A's next send is delivered.
    b.add_contact(&a, "alice", &a_listen);
    assert!(sealed(&b) && b.book().contains(&a.pub_hex));
    assert_delivered("a→b (added back)", &a.send("bob", "c90 added back"));
    assert!(b.inbox().contains("c90 added back"));

    // Both restart: the key is loaded again at start, nothing is left to
    // seal, and both ways still deliver.
    drop(a_svc);
    drop(b_svc);
    let a_svc = start(&a, &a_listen);
    let b_svc = start(&b, &b_listen);
    for (p, svc) in [(&a, &a_svc), (&b, &b_svc)] {
        let settled = svc.log.wait_for(LOG_TIMEOUT, |l| {
            l.trim().ends_with(" raven-node at_rest: sealed")
        });
        assert!(
            settled.is_some() && svc.log.count("file(s)") == 0,
            "{}:\n{}",
            p.name,
            svc.log.text()
        );
    }
    assert_delivered(
        "a→b (restarted)",
        &a.send("bob", "c90 after the restart (a)"),
    );
    assert!(b.inbox().contains("c90 after the restart (a)"));
    assert_delivered(
        "b→a (restarted)",
        &b.send("alice", "c90 after the restart (b)"),
    );
    assert!(a.inbox().contains("c90 after the restart (b)"));
    for p in [&a, &b] {
        assert!(sealed(p), "{}", p.name);
    }
}

/// Every regular file below `from`, copied to `to` (folders made; sockets
/// and the like left out): a data dir as a taken laptop's copy holds it.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if kind.is_file() {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Every regular file below `dir`, as its path below `dir` with `/`.
fn tree_files(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                let name = path
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((name, path));
            }
        }
    }
    out.sort();
    out
}

/// A SQLite store or one of its sidecars: PP.12-PP.14 seal their rows
/// (C87 part 2 then reads their pages).
fn is_sqlite_file(name: &str) -> bool {
    [
        ".sqlite",
        ".sqlite3",
        ".sqlite-wal",
        ".sqlite-shm",
        ".sqlite-journal",
        ".sqlite3-wal",
        ".sqlite3-shm",
        ".sqlite3-journal",
    ]
    .iter()
    .any(|ext| name.ends_with(ext))
}

/// C87 part 1 (privacy pack PP.6; was Phase 6b's C87): A and B exchange
/// messages over LAN with route hints on (so each learns the other's routes
/// and sighting), stop, and each data dir is copied as a taken laptop's
/// would be. No file that is not a SQLite store holds the friend's key (hex
/// in either case, base64), rvn1 address, PeerId, LAN address (with its
/// port), petname or the loopback IP they used, sealed or plain by design
/// alike, and no file name names the friend's key. The lab key backends'
/// files (debug builds only: a release build keeps those secrets in the
/// keychain) are left out. The address files
/// (sightings, learned routes, route hint state, outbox routes) exist and
/// are RMS1. Part 2 (PP.14): every SQLite store, its WAL and its free pages
/// (the raw bytes, a WAL a stopped daemon left un-checkpointed included)
/// hold none of those either, as text or as bytes, and no message id of the
/// run (from each profile's chat history, raw or hex). Part 3 (review
/// B-sealed-stores-1): no 16-byte clear value of the session store and no
/// file name, taken as a session's init_id, gives a stored record key with
/// the friend's key (the real init_ids do). PP.16 adds the erase part as
/// C91.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c87_at_rest_data_dir_has_no_friend_metadata() {
    c87_run(false);
}

/// C87 again with every Phase 6 lab switch on (Phase 6b P6.51,
/// [`updates::phase6_profile`]), after A and B also passed a security notice
/// and a release over RUP1 ([`updates::exercise_updates`]): the Phase 6
/// files (the update state, the downloads list and the incoming release,
/// the security ledger, the capability floor) bring back no plaintext
/// friend metadata.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c87_with_every_phase6_switch_on_still_has_no_friend_metadata() {
    c87_run(true);
}

fn c87_run(phase6: bool) {
    use base64::Engine as _;
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let keys = phase6.then(|| updates::test_key_set_file(root.path()));
    let profile = |name: &'static str| {
        let p = Profile::create(root.path(), name).with_route_hints();
        match &keys {
            Some(keys) => updates::phase6_profile(p, keys),
            None => p,
        }
    };
    let a = profile("a");
    let b = profile("b");
    let (a_name, b_name) = ("alicezq", "bobzq");
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    if phase6 {
        // RUP1 runs between verified contacts only.
        a.pin_contact(&b, b_name, Some(&b_svc.lan_dial));
        b.pin_contact(&a, a_name, Some(&a_svc.lan_dial));
    } else {
        a.add_contact(&b, b_name, &b_svc.lan_dial);
        b.add_contact(&a, a_name, &a_svc.lan_dial);
    }
    for i in 0..2 {
        assert_delivered("a→b", &a.send(b_name, &format!("c87 from a {i}")));
        assert_delivered("b→a", &b.send(a_name, &format!("c87 from b {i}")));
    }
    let learned = wait_until(Duration::from_secs(15), || {
        learned_entry(&a, &b).is_some() && learned_entry(&b, &a).is_some()
    });
    assert!(
        learned,
        "no learned routes:\n{}\n{}",
        a_svc.log.text(),
        b_svc.log.text()
    );
    if phase6 {
        updates::exercise_updates(&a, &b, a_name, &b_svc);
    }
    let dials = [
        (a.name, a_svc.lan_dial.clone()),
        (b.name, b_svc.lan_dial.clone()),
    ];
    drop(a_svc);
    drop(b_svc);
    let peer_id = |p: &Profile| {
        load_profile_key(&p.dir);
        let id = raven_core::load_identity(&p.dir)
            .unwrap()
            .expect("an identity");
        raven_core::p2p_route::local_peer_id(&id)
    };
    for (p, friend, friend_name) in [(&a, &b, b_name), (&b, &a, a_name)] {
        let friend_dial = &dials.iter().find(|(n, _)| *n == friend.name).unwrap().1;
        let friend_key: [u8; 32] = hex::decode(&friend.pub_hex).unwrap().try_into().unwrap();
        let needles = [
            friend.pub_hex.to_lowercase(),
            friend.pub_hex.to_uppercase(),
            base64::engine::general_purpose::STANDARD.encode(friend_key),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(friend_key),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(friend_key),
            friend.address.clone(),
            peer_id(friend),
            friend_dial.clone(),
            friend_name.to_string(),
            "127.0.0.1".to_string(),
        ];
        let copy = root.path().join(format!("{}-copy", p.name));
        copy_tree(&p.dir, &copy);
        let files = tree_files(&copy);
        // Part 2's needles: the same, as bytes, the key's raw bytes, and every
        // message id of the run in either direction.
        load_profile_key(&p.dir);
        let history = raven_core::chat_history::ChatHistory::load(&p.dir)
            .unwrap_or_else(|e| panic!("{}: the chat history: {e}", p.name));
        let message_ids: Vec<String> = history
            .for_peer(&friend.pub_hex)
            .iter()
            .map(|entry| entry.message_id_hex.to_lowercase())
            .collect();
        assert!(message_ids.len() >= 4, "{}: {message_ids:?}", p.name);
        let mut byte_needles: Vec<Vec<u8>> =
            needles.iter().map(|n| n.as_bytes().to_vec()).collect();
        byte_needles.push(friend_key.to_vec());
        for id in &message_ids {
            byte_needles.push(id.as_bytes().to_vec());
            byte_needles.push(id.to_uppercase().into_bytes());
            byte_needles.push(hex::decode(id).unwrap());
        }
        let mut sqlite_scanned = 0;
        for name in [
            "contacts.json",
            "lan_seen.json",
            "learned_routes.json",
            "route_hints_state.json",
        ] {
            let raw = std::fs::read(copy.join(name))
                .unwrap_or_else(|e| panic!("{}: no {name} ({e})", p.name));
            assert!(
                raven_core::at_rest::is_sealed(&raw),
                "{}: {name} is not RMS1",
                p.name
            );
        }
        // Written only while a message waits (and then sealed too).
        if let Ok(raw) = std::fs::read(copy.join("outbox_routes.json")) {
            assert!(raven_core::at_rest::is_sealed(&raw), "{}", p.name);
        }
        let mut scanned = 0;
        for (name, path) in &files {
            assert!(
                !name.to_lowercase().contains(&friend.pub_hex.to_lowercase()),
                "{}: the file name {name} names the friend's key",
                p.name
            );
            // SQLite files are read as raw bytes (part 2, PP.14). The lab
            // key backends' files stand in for the keystore (debug builds
            // only): a release build keeps those secrets in the keychain, not
            // in the folder.
            let lab_keystore = matches!(
                raven_core::at_rest::rule_for(name).map(|r| r.rule),
                Some(raven_core::at_rest::Rule::Lab(_))
            ) && (name.starts_with("indexed-session-secrets/")
                || name == "prekey_lifecycle.protected");
            if lab_keystore {
                continue;
            }
            if is_sqlite_file(name) {
                let raw = std::fs::read(path).unwrap();
                for needle in &byte_needles {
                    assert!(
                        !raw.windows(needle.len()).any(|w| w == needle.as_slice()),
                        "{}: the SQLite file {name} holds {:?}",
                        p.name,
                        String::from_utf8_lossy(needle)
                    );
                }
                sqlite_scanned += 1;
                continue;
            }
            let raw = std::fs::read(path).unwrap();
            let text = String::from_utf8_lossy(&raw);
            for needle in &needles {
                assert!(
                    !text.contains(needle.as_str()),
                    "{}: {name} holds the friend's {needle:?} ({:?})",
                    p.name,
                    raven_core::at_rest::rule_for(name).map(|r| r.rule)
                );
            }
            scanned += 1;
        }
        assert!(scanned >= 10, "{}: only {scanned} files: {files:?}", p.name);
        assert!(
            files
                .iter()
                .any(|(name, _)| name == raven_core::INDEXED_SESSION_METADATA_FILE),
            "{}: no session store: {files:?}",
            p.name
        );
        assert!(
            sqlite_scanned >= 2,
            "{}: {sqlite_scanned} SQLite files",
            p.name
        );
        // Part 3 (review B-sealed-stores-1): the session store's record key
        // is an unkeyed digest of public values and the init_id. No 16-byte
        // clear value of the copied store and no 32-hex run of a file name,
        // taken as the init_id, names the friend's session; the real
        // init_ids do (the check works).
        use raven_core::indexed_session_store::{init_id_candidates, record_key_names_friend};
        let own_key: [u8; 32] = hex::decode(&p.pub_hex).unwrap().try_into().unwrap();
        let candidates = init_id_candidates(&copy);
        for init_id in &candidates {
            assert!(
                !record_key_names_friend(&copy, &own_key, &friend_key, init_id),
                "{}: {} names the friend's session",
                p.name,
                hex::encode(init_id)
            );
        }
        let real = raven_core::indexed_session_store::SessionMetadataReader::open(&p.dir)
            .unwrap()
            .expect("a session store")
            .init_ids()
            .unwrap();
        assert!(!real.is_empty(), "{}: no session", p.name);
        assert!(
            real.iter().all(|init_id| record_key_names_friend(
                &copy,
                &own_key,
                &friend_key,
                init_id
            )),
            "{}: the record-key check found no session",
            p.name
        );
    }
}

/// `script` on PATH (a pseudo-terminal for `raven erase`, which takes its
/// word only from a terminal), if there is one.
#[cfg(unix)]
fn script_on_path() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("script"))
        .find(|candidate| {
            std::fs::metadata(candidate)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
}

/// Raven's own login item for `dir` as the installer writes it (enough of
/// it for `node_control::own_login_item`), in `items`, and fake
/// `launchctl` / `systemctl` in `tools` that write their arguments to
/// `log`: this system's item file name.
#[cfg(unix)]
fn login_item_fixture(dir: &Path, items: &Path, tools: &Path, log: &Path) -> &'static str {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(items).unwrap();
    std::fs::create_dir_all(tools).unwrap();
    let dir = dir.canonicalize().unwrap().display().to_string();
    let (file, text) = if cfg!(target_os = "macos") {
        (
            "com.raven.raven-node.plist",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n  \
                 <key>Label</key><string>com.raven.raven-node</string>\n  \
                 <key>ProgramArguments</key>\n  <array>\n    \
                 <string>/opt/raven/bin/raven-node</string>\n    <string>service</string>\n    \
                 <string>--data-dir</string>\n    <string>{dir}</string>\n  </array>\n  \
                 <key>KeepAlive</key><true/>\n</dict>\n</plist>\n"
            ),
        )
    } else {
        (
            "raven-node.service",
            format!(
                "[Unit]\nDescription=Raven node\n\n[Service]\nExecStart=\"/opt/raven/bin/\
                 raven-node\" service --data-dir \"{dir}\"\nRestart=on-failure\n"
            ),
        )
    };
    std::fs::write(items.join(file), text).unwrap();
    for name in ["launchctl", "systemctl"] {
        let path = tools.join(name);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$(basename \"$0\") $*\" >> '{}'\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    file
}

/// A child killed and reaped when it goes out of scope, on a failed
/// assert's unwinding too (review E-harness-docs-ci-4): `script` never
/// outlives its test, and with its pseudo-terminal closed what ran under it
/// is hung up.
#[cfg(unix)]
struct KillOnDrop(Child);

#[cfg(unix)]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `raven erase` for `p` in a pseudo-terminal: waits for the question,
/// pauses as a person reading it would, then types `erase`. Whether it
/// ended well, and what the terminal showed.
#[cfg(unix)]
fn erase_on_a_terminal(script: &Path, p: &Profile, env: &[(&str, &Path)]) -> (bool, String) {
    use std::sync::mpsc;
    let snippet = "\"$RAVEN\" --data-dir \"$D\" erase; exit $?";
    let mut cmd = Command::new(script);
    if cfg!(target_os = "linux") {
        cmd.args(["-q", "-e", "-c", snippet, "/dev/null"])
            .env("SHELL", "/bin/sh");
    } else {
        cmd.args(["-q", "/dev/null", "/bin/sh", "-c", snippet]);
    }
    p.env(&mut cmd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut guard = KillOnDrop(
        cmd.env("RAVEN", raven_bin())
            .env("D", &p.dir)
            .env("TERM", "xterm-256color")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn script"),
    );
    let child = &mut guard.0;
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut stdin = child.stdin.take().unwrap();
    let mut screen = Vec::new();
    let take = |screen: &mut Vec<u8>| {
        if let Ok(bytes) = rx.recv_timeout(Duration::from_millis(50)) {
            screen.extend(bytes);
        }
    };
    let started = Instant::now();
    while !String::from_utf8_lossy(&screen).contains("Type erase to confirm:") {
        if child.try_wait().unwrap().is_some() || started.elapsed() > COMMAND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return (false, String::from_utf8_lossy(&screen).into_owned());
        }
        take(&mut screen);
    }
    let reading = Instant::now();
    while reading.elapsed() < Duration::from_millis(1200) {
        take(&mut screen);
    }
    stdin.write_all(b"erase\n").unwrap();
    stdin.flush().unwrap();
    let typed = Instant::now();
    let status = loop {
        take(&mut screen);
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if typed.elapsed() > COMMAND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return (false, String::from_utf8_lossy(&screen).into_owned());
        }
    };
    drop(stdin);
    screen.extend(rx.try_iter().flatten());
    (
        status.success(),
        String::from_utf8_lossy(&screen).into_owned(),
    )
}

/// C91 (privacy pack PP.16; was the erase half of Phase 6b's C87): A and B
/// exchange, and B and C are friends too. A runs `raven erase` in a
/// terminal, with Raven's own login item for A (the lab's) and A's node
/// running: the erase stops A's node, unloads, turns off and removes the
/// item, and afterwards the test's temp root holds nothing of A. B's
/// profile and B's node (the same process) still exchange with C both
/// ways. Unix (a pseudo-terminal through `script`); Windows has none here.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c91_erase_one_of_two_profiles() {
    if !lab_ready() {
        return;
    }
    #[cfg(not(unix))]
    {
        eprintln!("skipped: raven erase needs a terminal (no `script` on this system)");
    }
    #[cfg(unix)]
    {
        let Some(script) = script_on_path() else {
            eprintln!("skipped: `script` is not on PATH");
            return;
        };
        let _net = shared_host_network();
        let root = tempfile::tempdir().unwrap();
        let a = Profile::create(root.path(), "a");
        let b = Profile::create(root.path(), "b");
        let c = Profile::create(root.path(), "c");
        let mut a_svc = a.start_service();
        let mut b_svc = b.start_service();
        let c_svc = c.start_service();
        a.add_contact(&b, "bob", &b_svc.lan_dial);
        b.add_contact(&a, "alice", &a_svc.lan_dial);
        b.add_contact(&c, "carol", &c_svc.lan_dial);
        c.add_contact(&b, "bob", &b_svc.lan_dial);
        assert_delivered("a→b", &a.send("bob", "c91 from a"));
        assert_delivered("b→a", &b.send("alice", "c91 from b"));
        assert!(b.inbox().contains("c91 from a"));
        assert!(a.inbox().contains("c91 from b"));

        let login = root.path().join("login");
        let (items, tools, log) = (
            login.join("items"),
            login.join("tools"),
            login.join("calls.log"),
        );
        let item = login_item_fixture(&a.dir, &items, &tools, &log);
        let (ok, screen) = erase_on_a_terminal(
            &script,
            &a,
            &[
                ("RAVEN_LAB_LOGIN_ITEM_ROOT", &items),
                ("RAVEN_LAB_LOGIN_ITEM_TOOLS", &tools),
            ],
        );
        assert!(
            ok && screen.contains("Erased: identity, friends, chats, waiting messages and "),
            "the erase did not end well:\n{screen}"
        );
        // A's node: stopped by the erase (its own Status pid).
        assert!(
            wait_until(LOG_TIMEOUT, || a_svc.child.try_wait().unwrap().is_some()),
            "A's node still runs:\n{}",
            a_svc.log.text()
        );
        // Nothing of A is left in the temp root: its folder, its item.
        assert!(!a.dir.exists(), "{screen}");
        assert!(!items.join(item).exists());
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        let want = if cfg!(target_os = "macos") {
            vec!["launchctl bootout gui/", "launchctl disable gui/"]
        } else {
            vec![
                "systemctl --user stop raven-node.service",
                "systemctl --user disable --now raven-node.service",
                "systemctl --user daemon-reload",
            ]
        };
        let lines: Vec<&str> = calls.lines().collect();
        assert_eq!(lines.len(), want.len(), "{calls}");
        for (line, want) in lines.iter().zip(&want) {
            assert!(line.starts_with(want), "{calls}");
        }
        for (name, _) in tree_files(root.path()) {
            assert!(
                !name.starts_with("a/") && !name.starts_with("login/items/"),
                "{name} is left"
            );
        }
        // B (the same node process) and C exchange both ways.
        assert!(
            b_svc.child.try_wait().unwrap().is_none(),
            "B's node stopped"
        );
        assert_delivered("b→c", &b.send("carol", "c91 after the erase (b)"));
        assert!(c.inbox().contains("c91 after the erase (b)"));
        assert_delivered("c→b", &c.send("bob", "c91 after the erase (c)"));
        assert!(b.inbox().contains("c91 after the erase (c)"));
        assert!(b.inbox().contains("c91 from a"), "B keeps its own chat");
        assert!(
            b_svc.child.try_wait().unwrap().is_none(),
            "B's node stopped"
        );
    }
}

// ── Phase 6b: PAD1 link padding (C86 part 1) ───────────────────────────────

/// A Noise transport message of a PAD1 frame: one of the four buckets
/// (512, 4,096, 16,384, 65,519) and the 16-byte tag.
fn pad1_message(len: usize) -> bool {
    [512, 4_096, 16_384, 65_519].iter().any(|b| b + 16 == len)
}

/// Which link a [`RecordingProxy`] stands in front of (C86).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C86Link {
    Lan,
    Internet,
}

/// C86: every complete connection a split proxy carried, checked against
/// what PAD1 should do on it. Each is the dialer's messages (m1, m3, then
/// the LAN bind or the hello, then frames) and the listener's (m2, bind or
/// hello, frames). `padded`: both ends pad. A LAN dial that offered PAD1 has
/// a payload in m3 (an empty one is 64 bytes: the static and two tags); a
/// frame-less probe does not, and is never padded. Returns how many
/// connections were padded.
fn c86_check(proxy: &RecordingProxy, link: C86Link, padded: bool, label: &str) -> usize {
    let mut padded_conns = 0;
    for [dialer, listener] in proxy.messages() {
        // A connection that ended inside the handshake carries no frame.
        if dialer.len() < 3 || listener.len() < 2 {
            continue;
        }
        let offered = match link {
            C86Link::Lan => dialer[1] > 64,
            C86Link::Internet => true,
        };
        // After the handshake: the dialer's bind (LAN, bare, 96 bytes) or
        // hello (never padded) comes first, so its frames start at 3; the
        // listener's own bind is padded on LAN, its hello is not.
        let dialer_frames = &dialer[3..];
        let listener_frames = match link {
            C86Link::Lan => &listener[1..],
            C86Link::Internet => &listener[2..],
        };
        if link == C86Link::Lan {
            assert_eq!(dialer[2], 96 + 16, "{label}: the dialer's bind: {dialer:?}");
        }
        if padded && offered {
            assert!(
                dialer_frames
                    .iter()
                    .chain(listener_frames)
                    .all(|&n| pad1_message(n)),
                "{label}: a message between two padding ends is not a bucket: \
                 {dialer:?} {listener:?}"
            );
            padded_conns += 1;
        } else {
            assert!(
                !dialer_frames
                    .iter()
                    .chain(listener_frames)
                    .any(|&n| pad1_message(n)),
                "{label}: a padded message on a link that must not pad: {dialer:?} {listener:?}"
            );
            if link == C86Link::Lan {
                assert_eq!(listener[1], 96 + 16, "{label}: the listener's bind is bare");
            }
        }
    }
    padded_conns
}

/// C86 part 1 (Phase 6b P6.34, design B §2, `protocol/RAVEN_LINK_PADDING_V1.md`;
/// the fault matrix's s115 runs the same against an older build): PAD1
/// between real nodes, under the debug switch `RAVEN_LAB_LINK_PADDING=1`
/// with `RAVEN_LAB_TEST_A=1` while `LINK_PADDING_PRODUCTION_ENABLED` is
/// false. Every contact route goes to the other node's listener through a
/// recording proxy that keeps each connection's two directions apart.
/// (1) A and B both pad: one message each way over LAN and one each way
/// over Internet direct (verified contacts), each exactly once; every
/// message after the handshake on every connection is a bucket plus the
/// tag, but the LAN dialer's bind and the Internet hellos (and a LAN
/// frame-less probe, which offers nothing). (2) C pads and D does not (this
/// build with the switch off, which is what an older build sends), both
/// ways round on both carriers: each message exactly once, no padded
/// message on any connection (the LAN listener's bind stays 96 bytes), and
/// neither log has a link padding refusal or a frame the dispatcher refused.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c86_pad1_between_new_nodes_and_mixed_pairs() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let node = |name: &'static str, pads: bool| {
        let p = Profile::create_with(root.path(), name, true);
        if pads {
            p.with_lab_env("RAVEN_LAB_LINK_PADDING", "1")
        } else {
            p
        }
    };
    let to_proxy = |dial: &str| RecordingProxy::start_split(dial.parse().unwrap());
    let exchange = |a: &Profile, b: &Profile, padded: bool, label: &str| {
        let a_svc = a.start_service_with(Some("127.0.0.1:0"));
        let b_svc = b.start_service_with(Some("127.0.0.1:0"));
        let (a_lan, b_lan) = (to_proxy(&a_svc.lan_dial), to_proxy(&b_svc.lan_dial));
        let (a_inet, b_inet) = (
            to_proxy(&a_svc.internet_dial),
            to_proxy(&b_svc.internet_dial),
        );
        a.pin_contact(b, "bob", Some(&b_lan.addr.to_string()));
        b.pin_contact(a, "alice", Some(&a_lan.addr.to_string()));
        for (p, tag, inet) in [(a, "bob", &b_inet), (b, "alice", &a_inet)] {
            let set = p.raven(
                &[
                    "contact",
                    "set-addr",
                    &format!("@{tag}"),
                    "--internet",
                    &inet.addr.to_string(),
                ],
                None,
            );
            assert!(set.ok, "{label}: {} set-addr:\n{}", p.name, set.all());
        }
        let mut texts = Vec::new();
        for carrier in ["lan", "internet"] {
            for (from, to, tag) in [(a, b, "bob"), (b, a, "alice")] {
                let text = format!("c86 {label} {carrier} {} to {}", from.name, to.name);
                let sent = from.raven(
                    &[
                        "send",
                        "--contact",
                        &format!("@{tag}"),
                        "--carrier",
                        carrier,
                    ],
                    Some(&format!("{text}\n")),
                );
                assert_delivered(&format!("{label} {carrier} {}", from.name), &sent);
                texts.push((to, text));
            }
        }
        for (to, text) in &texts {
            assert_eq!(
                to.inbox().matches(text.as_str()).count(),
                1,
                "{label}: {text} exactly once"
            );
        }
        for (p, svc) in [(a, &a_svc), (b, &b_svc)] {
            let log = svc.log.text();
            for bad in ["link padding", "not RavenEnvelopeV1", "dispatch:"] {
                assert!(
                    !log.contains(bad),
                    "{label}: {}'s log has {bad:?}:\n{log}",
                    p.name
                );
            }
        }
        let lan = c86_check(&a_lan, C86Link::Lan, padded, label)
            + c86_check(&b_lan, C86Link::Lan, padded, label);
        let inet = c86_check(&a_inet, C86Link::Internet, padded, label)
            + c86_check(&b_inet, C86Link::Internet, padded, label);
        eprintln!("C86 {label}: padded connections lan={lan} internet={inet}");
        if padded {
            assert!(lan >= 2 && inet >= 2, "{label}: lan={lan} internet={inet}");
        }
    };

    // ── (1) both pad ─────────────────────────────────────────────────────
    let a = node("pa", true);
    let b = node("pb", true);
    exchange(&a, &b, true, "both pad");

    // ── (2) one side pads, both ways round ───────────────────────────────
    let c = node("pc", true);
    let d = node("pd", false);
    exchange(&c, &d, false, "c pads");
    let e = node("pe", false);
    let f = node("pf", true);
    exchange(&e, &f, false, "f pads");
}

// ── Phase 6b: RLK1 link knock (C86 part 2) ─────────────────────────────────

/// C86 part 2: the handshake of every connection a split proxy carried, as
/// the lengths of messages 1, 2 and 3 (connections that ended before message
/// 3 left out).
fn c86_handshakes(proxy: &RecordingProxy) -> Vec<[usize; 3]> {
    proxy
        .messages()
        .into_iter()
        .filter(|[dialer, listener]| dialer.len() >= 2 && !listener.is_empty())
        .map(|[dialer, listener]| [dialer[0], listener[0], dialer[1]])
        .collect()
}

/// C86 part 2: every handshake through `proxy` has the shape RLK1 gives it
/// (`RAVEN_LINK_KNOCK_V1.md` §6) when the dialer (`dialer_knocks`) and the
/// listener (`listener_knocks`) run the knock, and today's otherwise:
/// message 1 32 bytes or 64-95, message 2 96 or 112-143, message 3 64 or
/// 71-128 (an RLX1 `PAD` entry, no caps: route hints are off here). Returns
/// how many there were.
fn c86_knock_shapes(
    proxy: &RecordingProxy,
    dialer_knocks: bool,
    listener_knocks: bool,
    label: &str,
) -> usize {
    let all = c86_handshakes(proxy);
    for [m1, m2, m3] in &all {
        let ok = if dialer_knocks {
            (64..=95).contains(m1) && (71..=128).contains(m3)
        } else {
            *m1 == 32 && *m3 == 64
        } && if listener_knocks {
            (112..=143).contains(m2)
        } else {
            *m2 == 96
        };
        assert!(ok, "{label}: handshake {m1}/{m2}/{m3}: {all:?}");
    }
    all.len()
}

/// A stranger's Noise XX message 1 (no knock) at the LAN listener `addr`:
/// the static its message 2 carried, or `None` when the listener closed
/// without one.
fn stranger_probe(addr: &str) -> Option<[u8; 32]> {
    use raven_core::lan_noise::{
        build_initiator, derive_noise_static, get_remote_static, handshake_read, handshake_write,
    };
    let stranger = raven_core::Identity::from_seed(&rand::random::<[u8; 32]>());
    let mut hs = build_initiator(&derive_noise_static(&stranger).unwrap()).unwrap();
    let m1 = handshake_write(&mut hs, &[]).unwrap();
    let mut stream =
        std::net::TcpStream::connect(addr).unwrap_or_else(|e| panic!("a probe to {addr}: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(&(m1.len() as u32).to_be_bytes()).unwrap();
    stream.write_all(&m1).unwrap();
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).ok()?;
    let mut m2 = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut m2).ok()?;
    handshake_read(&mut hs, &m2).unwrap();
    Some(get_remote_static(&hs).unwrap())
}

/// `p`'s "Silent to strangers" setting, written straight into
/// node_policy.json (no command sets it yet); the running node reads it at
/// its next connection.
fn set_silent_to_strangers(p: &Profile, mode: raven_core::node_policy::SilentMode) {
    if p.dir.join(raven_core::at_rest::META_KEY_FILE).exists() {
        load_profile_key(&p.dir);
    }
    let mut policy = raven_core::node_policy::try_load_policy(&p.dir)
        .unwrap_or_else(|e| panic!("{} node_policy.json: {e}", p.name));
    policy.security_silent_to_strangers = mode;
    raven_core::node_policy::save_policy(&p.dir, &policy)
        .unwrap_or_else(|e| panic!("{} node_policy.json: {e}", p.name));
}

/// C86 part 2 (Phase 6b P6.35, design B §3, `protocol/RAVEN_LINK_KNOCK_V1.md`;
/// its debug switch `RAVEN_LAB_LINK_KNOCK=1` with `RAVEN_LAB_TEST_A=1` while
/// `LINK_KNOCK_PRODUCTION_ENABLED` is false): the knock between real nodes,
/// each with the noise pins (M0) and security events on (the capability
/// floors that turn a listener strict), every contact route through a
/// recording proxy. (1) A and B both knock: one message each way over LAN
/// and over Internet direct, each exactly once, every handshake knocked
/// both ways (message sizes in RLK1's ranges). Every contact of A has now
/// shown the knock, so A is strict: two stranger probes at A's LAN listener
/// see two different statics. (2) C knocks and D runs M0 only (this build
/// without the switch, what a build with the pins and without the knock
/// sends), both ways on both carriers: each message once, D's pin of C's
/// static still matches (no pin mismatch in either log), and C, whose
/// contact D never knocked, stays legacy: two probes see the same static.
/// (3) A in silent mode: a stranger's probe gets no message 2, and B still
/// reaches A over LAN. The impostor rows (s113 with C83's tampering proxy)
/// wait for P6.32.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c86_knock_mixed_builds_strict_and_silent() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let node = |name: &'static str, knocks: bool| {
        let p = Profile::create_with(root.path(), name, true)
            .with_noise_pin(true)
            .with_lab_env("RAVEN_LAB_SECURITY_EVENTS", "1");
        if knocks {
            p.with_lab_env("RAVEN_LAB_LINK_KNOCK", "1")
        } else {
            p
        }
    };
    let to_proxy = |dial: &str| RecordingProxy::start_split(dial.parse().unwrap());
    // Both services up, every route through a proxy, one message each way
    // on each carrier; returns the services and the four proxies.
    let exchange = |a: &Profile, b: &Profile, label: &str| {
        let a_svc = a.start_service_with(Some("127.0.0.1:0"));
        let b_svc = b.start_service_with(Some("127.0.0.1:0"));
        let (a_lan, b_lan) = (to_proxy(&a_svc.lan_dial), to_proxy(&b_svc.lan_dial));
        let (a_inet, b_inet) = (
            to_proxy(&a_svc.internet_dial),
            to_proxy(&b_svc.internet_dial),
        );
        a.pin_contact(b, "bob", Some(&b_lan.addr.to_string()));
        b.pin_contact(a, "alice", Some(&a_lan.addr.to_string()));
        for (p, tag, inet) in [(a, "bob", &b_inet), (b, "alice", &a_inet)] {
            let set = p.raven(
                &[
                    "contact",
                    "set-addr",
                    &format!("@{tag}"),
                    "--internet",
                    &inet.addr.to_string(),
                ],
                None,
            );
            assert!(set.ok, "{label}: {} set-addr:\n{}", p.name, set.all());
        }
        let mut texts = Vec::new();
        for carrier in ["lan", "internet"] {
            for (from, to, tag) in [(a, b, "bob"), (b, a, "alice")] {
                let text = format!("c86k {label} {carrier} {} to {}", from.name, to.name);
                let sent = from.raven(
                    &[
                        "send",
                        "--contact",
                        &format!("@{tag}"),
                        "--carrier",
                        carrier,
                    ],
                    Some(&format!("{text}\n")),
                );
                assert_delivered(&format!("{label} {carrier} {}", from.name), &sent);
                texts.push((to, text));
            }
        }
        for (to, text) in &texts {
            assert_eq!(
                to.inbox().matches(text.as_str()).count(),
                1,
                "{label}: {text} exactly once"
            );
        }
        for (p, svc) in [(a, &a_svc), (b, &b_svc)] {
            let log = svc.log.text();
            for bad in ["noise pin mismatch", "link knock", "dispatch:"] {
                assert!(
                    !log.contains(bad),
                    "{label}: {}'s log has {bad:?}:\n{log}",
                    p.name
                );
            }
        }
        (a_svc, b_svc, [a_lan, b_lan, a_inet, b_inet])
    };

    // ── (1) both knock; then A is strict ─────────────────────────────────
    let a = node("ka", true);
    let b = node("kb", true);
    let (a_svc, b_svc, [a_lan, b_lan, a_inet, b_inet]) = exchange(&a, &b, "both knock");
    let mut knocked = 0;
    for proxy in [&a_lan, &b_lan, &a_inet, &b_inet] {
        knocked += c86_knock_shapes(proxy, true, true, "both knock");
    }
    assert!(knocked >= 4, "both knock: {knocked} handshakes");
    let strict = wait_until(Duration::from_secs(10), || {
        let (x, y) = (
            stranger_probe(&a_svc.lan_dial),
            stranger_probe(&a_svc.lan_dial),
        );
        x.is_some() && y.is_some() && x != y
    });
    assert!(strict, "A is strict once B's floor shows the knock");

    // ── (3) A silent to strangers; B still gets in ───────────────────────
    set_silent_to_strangers(&a, raven_core::node_policy::SilentMode::On);
    let silent = wait_until(Duration::from_secs(10), || {
        stranger_probe(&a_svc.lan_dial).is_none()
    });
    assert!(silent, "silent: no message 2 for a stranger");
    let text = "c86k silent kb to ka";
    let sent = b.raven(
        &["send", "--contact", "@alice", "--carrier", "lan"],
        Some(&format!("{text}\n")),
    );
    assert_delivered("silent kb", &sent);
    assert_eq!(a.inbox().matches(text).count(), 1, "{text} exactly once");
    drop((a_svc, b_svc));

    // ── (2) a knock build and an M0-only build ───────────────────────────
    let c = node("kc", true);
    let d = node("kd", false);
    let (c_svc, d_svc, [c_lan, d_lan, c_inet, d_inet]) = exchange(&c, &d, "mixed");
    // D dials C (C knocks, D does not): today's message 1, C's answer
    // jittered; C dials D: a knocked message 1, D's plain message 2.
    let at_c = c86_knock_shapes(&c_lan, false, true, "d dials c")
        + c86_knock_shapes(&c_inet, false, true, "d dials c");
    let at_d = c86_knock_shapes(&d_lan, true, false, "c dials d")
        + c86_knock_shapes(&d_inet, true, false, "c dials d");
    assert!(at_c >= 2 && at_d >= 2, "mixed: at c {at_c}, at d {at_d}");
    let (x, y) = (
        stranger_probe(&c_svc.lan_dial),
        stranger_probe(&c_svc.lan_dial),
    );
    assert!(
        x.is_some() && x == y,
        "C waits for D's floor: legacy, its derived static"
    );
    drop((c_svc, d_svc));
}

// ── Phase 6b: pair seeds (C86 part 3) ──────────────────────────────────────

/// `p`'s current pair seed for `peer` as its `pair_seeds.json` holds it (a
/// plain profile): `(generation, seed hex)`.
fn current_seed(p: &Profile, peer: &Profile) -> Option<(u64, String)> {
    let raw = std::fs::read_to_string(p.dir.join("pair_seeds.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let cur = &v["pairs"][peer.pub_hex.to_lowercase()]["current"];
    Some((
        cur["generation"].as_u64()?,
        cur["seed"].as_str()?.to_string(),
    ))
}

/// C86 part 3 (Phase 6b P6.38, design B §5, `protocol/RAVEN_ROUTE_HINTS_V1.md`
/// §14; its debug switch `RAVEN_LAB_PAIR_SEED=1` with `RAVEN_LAB_TEST_A=1`
/// and route hints while `PAIR_SEED_PRODUCTION_ENABLED` is false): pair seeds
/// between real nodes that knock, with the noise pins and security events
/// on, in plain profiles (the test reads `pair_seeds.json`). (1) Messages
/// both ways over LAN until the leader's RRH1 carried its proposal and the
/// follower's the ack: both files hold the same current seed for each
/// other. Later messages still arrive once each; every dial knocked with the
/// seed (one whose knock got no proof would stop before message 3: the
/// contact's floor shows the knock, and knocked links leave no pin). (2) B
/// loses its seeds (its file removed while its node runs): each message
/// still arrives once both ways (A's seeded knock falls back to the root),
/// and the two agree on a seed again.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c86_pair_seeds_rotate_under_the_knock() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let node = |name: &'static str| {
        Profile::create_plain(root.path(), name)
            .with_route_hints()
            .with_noise_pin(true)
            .with_lab_env("RAVEN_LAB_TEST_A", "1")
            .with_lab_env("RAVEN_LAB_SECURITY_EVENTS", "1")
            .with_lab_env("RAVEN_LAB_LINK_KNOCK", "1")
            .with_lab_env("RAVEN_LAB_PAIR_SEED", "1")
    };
    let a = node("sa");
    let b = node("sb");
    let a_svc = a.start_service_with(None);
    let b_svc = b.start_service_with(None);
    a.pin_contact(&b, "bob", Some(&b_svc.lan_dial));
    b.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    let mut n = 0;
    let mut round = |label: &str| {
        for (from, to, tag) in [(&a, &b, "bob"), (&b, &a, "alice")] {
            n += 1;
            let text = format!("c86s {label} {n} {} to {}", from.name, to.name);
            let sent = from.raven(
                &["send", "--contact", &format!("@{tag}"), "--carrier", "lan"],
                Some(&format!("{text}\n")),
            );
            assert_delivered(&format!("{label} {}", from.name), &sent);
            assert_eq!(
                to.inbox().matches(text.as_str()).count(),
                1,
                "{label}: {text} exactly once"
            );
        }
    };
    // ── (1) the seed is agreed, and the knocks use it ────────────────────
    round("agree");
    round("agree");
    let agreed = wait_until(Duration::from_secs(10), || {
        let (x, y) = (current_seed(&a, &b), current_seed(&b, &a));
        x.is_some() && x == y
    });
    assert!(
        agreed,
        "one seed: a {:?}, b {:?}",
        current_seed(&a, &b),
        current_seed(&b, &a)
    );
    let first = current_seed(&a, &b).unwrap();
    round("seeded");
    assert_eq!(
        current_seed(&a, &b),
        Some(first.clone()),
        "no rotation within 7 days"
    );
    // ── (2) B loses its seeds ────────────────────────────────────────────
    std::fs::remove_file(b.dir.join("pair_seeds.json")).unwrap();
    round("lost");
    round("lost");
    let again = wait_until(Duration::from_secs(10), || {
        let (x, y) = (current_seed(&a, &b), current_seed(&b, &a));
        x.is_some() && x == y
    });
    assert!(
        again,
        "a seed again: a {:?}, b {:?}",
        current_seed(&a, &b),
        current_seed(&b, &a)
    );
    for (p, svc) in [(&a, &a_svc), (&b, &b_svc)] {
        let log = svc.log.text();
        for bad in ["noise pin mismatch", "dispatch:"] {
            assert!(!log.contains(bad), "{}'s log has {bad:?}:\n{log}", p.name);
        }
    }
}

// ── Phase 6b: the update harness (C88, C89, C87's Phase 6 run; P6.51) ──────

// The crate root's own folder holds it: a file in `tests/` would be a test
// target of its own.
#[path = "carrier_matrix/updates.rs"]
mod updates;

// ── Phase 3: the LAN listener on every interface and the LAN beacon ─────────

/// Where this computer dials a listener bound to `listen`: an unspecified
/// address (`0.0.0.0:P`, `[::]:P`) becomes its loopback.
fn loopback_dial(listen: &str) -> String {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    match listen.parse::<SocketAddr>() {
        Ok(addr) if addr.ip().is_unspecified() => {
            let ip: IpAddr = if addr.is_ipv6() {
                Ipv6Addr::LOCALHOST.into()
            } else {
                Ipv4Addr::LOCALHOST.into()
            };
            SocketAddr::new(ip, addr.port()).to_string()
        }
        _ => listen.to_string(),
    }
}

/// A plain TCP connection to `addr` that sends nothing: `Some(n)` when the
/// other side closed it within `wait` after `n` bytes (a reset is a close
/// with what came before), `None` while it stayed open.
fn closed_after(addr: &str, wait: Duration) -> Option<usize> {
    let mut stream = std::net::TcpStream::connect(addr)
        .unwrap_or_else(|e| panic!("a plain connection to {addr}: {e}"));
    stream.set_read_timeout(Some(wait)).unwrap();
    let mut buf = [0u8; 256];
    let mut got = 0;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Some(got),
            Ok(n) => got += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return None
            }
            Err(_) => return Some(got),
        }
    }
}

/// Whether something accepts a TCP connection at `addr` now.
fn tcp_open(addr: &str) -> bool {
    addr.parse()
        .ok()
        .and_then(|a| std::net::TcpStream::connect_timeout(&a, Duration::from_secs(1)).ok())
        .is_some()
}

/// The value of `p`'s `raven lan status` row `key` (`raven-node`, `nearby
/// search`).
fn lan_row(p: &Profile, key: &str) -> String {
    let out = p.raven(&["lan", "status"], None);
    assert!(out.ok, "{} lan status:\n{}", p.name, out.all());
    status_row(&out.stdout, key)
        .unwrap_or_else(|| panic!("{}: no `{key}` row:\n{}", p.name, out.stdout))
        .to_string()
}

/// `p`'s daemon's IPC `Status` answer as JSON, asked as `raven` asks (a
/// 4-byte length, then JSON) on its Unix socket, or on Windows its pipe:
/// the per-user name with the profile's lab suffix. For the counts `raven
/// status` does not print (C29, C30).
fn ipc_status(p: &Profile) -> serde_json::Value {
    let req = raven_core::ipc::IpcRequest::status();
    let frame = raven_core::ipc::encode_request(&req).unwrap();
    let endpoint = ipc_endpoint_of(p);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(ipc_transact(&endpoint, &frame));
    });
    let body = rx
        .recv_timeout(COMMAND_TIMEOUT)
        .unwrap_or_else(|_| panic!("{}: no IPC answer within {COMMAND_TIMEOUT:?}", p.name))
        .unwrap_or_else(|e| panic!("{}: IPC: {e}", p.name));
    serde_json::from_slice(&body).unwrap_or_else(|e| panic!("{}: IPC answer: {e}", p.name))
}

/// `p`'s daemon's LAN beacon counts (`Status.lan.beacon`; null without).
fn beacon_json(p: &Profile) -> serde_json::Value {
    ipc_status(p)["lan"]["beacon"].clone()
}

#[cfg(unix)]
fn ipc_endpoint_of(p: &Profile) -> PathBuf {
    raven_core::ipc::default_socket_path(&p.dir)
}

#[cfg(windows)]
fn ipc_endpoint_of(p: &Profile) -> PathBuf {
    let user = raven_core::ipc::windows_user_pipe_name().expect("a per-user pipe name");
    // A lab suffix of this test process is not the profile's.
    let user = match std::env::var(raven_core::ipc::LAB_IPC_PIPE_SUFFIX_ENV) {
        Ok(own) if !own.is_empty() => user.strip_suffix(&format!("-{own}")).unwrap_or(user),
        _ => user,
    };
    let name = raven_core::ipc::with_lab_pipe_suffix(user.to_string(), Some(&p.pipe_suffix), true)
        .expect("a pipe suffix the daemon accepts");
    PathBuf::from(name)
}

#[cfg(not(any(unix, windows)))]
fn ipc_endpoint_of(p: &Profile) -> PathBuf {
    p.dir.clone()
}

/// One framed request on `endpoint` and the answer's JSON body.
fn ipc_transact(endpoint: &Path, frame: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = ipc_connect(endpoint)?;
    stream.write_all(frame)?;
    stream.flush()?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    let n = u32::from_be_bytes(head) as usize;
    if n == 0 || n > raven_core::ipc::MAX_IPC_FRAME {
        return Err(std::io::Error::other("IPC_FRAME"));
    }
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body)?;
    Ok(body)
}

#[cfg(unix)]
fn ipc_connect(endpoint: &Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(endpoint)
}

#[cfg(windows)]
fn ipc_connect(endpoint: &Path) -> std::io::Result<std::fs::File> {
    // ERROR_PIPE_BUSY: the daemon is between two pipe instances.
    const ERROR_PIPE_BUSY: i32 = 231;
    for _ in 0..40 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(endpoint)
        {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            other => return other,
        }
    }
    Err(std::io::Error::other("named pipe busy"))
}

#[cfg(not(any(unix, windows)))]
fn ipc_connect(_endpoint: &Path) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::other("no IPC transport on this system"))
}

/// The service log's line for a connection `auto` closed because its
/// source is not local (counts only).
const NON_LOCAL_LINE: &str =
    "closed a connection from outside the local network before reading it (";

/// C27 (Phase 3 P3.12): `--lan-listen auto:P` with its lab unlock
/// (`RAVEN_LAB_LAN_AUTO=1`; the B12 gate stays closed) binds `0.0.0.0:P`
/// and `[::]:P` (IPv6 where the runner has it): `raven lan status` lists
/// both and says local sources only, A delivers through `127.0.0.1:P` and
/// `[::1]:P`, and a plain connection from a local source stays open (the
/// responder waits for Noise message 1). With the debug
/// `RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK=1` loopback counts as not local: a
/// plain connection on either family is closed before a byte, the log says
/// so with counts only, and A's message waits. Without the unlock `auto:P`
/// is today's single `0.0.0.0:P` for any source, and the waiting message
/// and a new one arrive, each once.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c27_lan_auto_listens_on_both_families_and_refuses_non_local_sources() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create(root.path(), "a");
    let b = Profile::create(root.path(), "b");
    let v6 = has_ipv6_loopback();
    let port = free_any_port(false);
    let auto = format!("auto:{port}");
    let dial4 = format!("127.0.0.1:{port}");
    let dial6 = format!("[::1]:{port}");
    let _a_svc = a.start_service();
    a.pin_contact(&b, "bob", Some(&dial4));
    b.pin_contact(&a, "alice", None);

    // ── auto, its lab unlock on: both families, local sources only ───────
    let b_svc = b.start_service_lan(&auto, &[("RAVEN_LAB_LAN_AUTO", "1")]);
    let both = if v6 {
        format!("0.0.0.0:{port}, [::]:{port}")
    } else {
        eprintln!("note: no IPv6 loopback on this runner; C27 checks IPv4 only");
        format!("0.0.0.0:{port}")
    };
    assert_eq!(
        lan_row(&b, "raven-node"),
        format!("on (listens on {both}; local sources only)")
    );
    assert_delivered("a→b over IPv4", &a.send("bob", "c27 over ipv4"));
    assert!(b.inbox().contains("c27 over ipv4"));
    if v6 {
        let set = a.raven(&["contact", "set-addr", "@bob", "--lan", &dial6], None);
        assert!(set.ok, "{}", set.all());
        assert_delivered("a→b over IPv6", &a.send("bob", "c27 over ipv6"));
        assert!(b.inbox().contains("c27 over ipv6"));
        let set = a.raven(&["contact", "set-addr", "@bob", "--lan", &dial4], None);
        assert!(set.ok, "{}", set.all());
    }
    assert_eq!(
        closed_after(&dial4, Duration::from_secs(2)),
        None,
        "a local source's plain connection waits for Noise"
    );
    drop(b_svc);

    // ── loopback counted as not local: closed before a byte ──────────────
    let b_svc = b.start_service_lan(
        &auto,
        &[
            ("RAVEN_LAB_LAN_AUTO", "1"),
            ("RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK", "1"),
        ],
    );
    let dials: Vec<&str> = if v6 {
        vec![&dial4, &dial6]
    } else {
        vec![&dial4]
    };
    for dial in &dials {
        assert_eq!(
            closed_after(dial, Duration::from_secs(10)),
            Some(0),
            "{dial}: closed before a byte"
        );
    }
    let line = b_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| l.contains(NON_LOCAL_LINE))
        .unwrap_or_else(|| panic!("no counts-only line:\n{}", b_svc.log.text()));
    assert!(line.contains("(1 since start"), "{line}");
    for named in ["127.0.0.1", "::1", &format!(":{port}")] {
        assert!(!line.contains(named), "{line}");
    }
    let refused = a.send("bob", "c27 refused");
    assert!(
        !refused.ok && refused.all().contains("not delivered yet"),
        "{}",
        refused.all()
    );
    assert!(!b.inbox().contains("c27 refused"));
    drop(b_svc);

    // ── no unlock: today's single 0.0.0.0:P, any source ───────────────────
    let b_svc = b.start_service_lan(&auto, &[]);
    assert_eq!(
        lan_row(&b, "raven-node"),
        format!("on (listens on 0.0.0.0:{port})")
    );
    assert_eq!(
        b_svc.log.count("raven-node lan_direct: listen "),
        1,
        "{}",
        b_svc.log.text()
    );
    assert_delivered("a→b, unlock off", &a.send("bob", "c27 unlock off"));
    assert!(
        wait_until(Duration::from_secs(90), || b
            .inbox()
            .contains("c27 refused")),
        "the waiting message did not arrive"
    );
    std::thread::sleep(Duration::from_secs(2));
    let inbox = b.inbox();
    for text in ["c27 over ipv4", "c27 refused", "c27 unlock off"] {
        assert_eq!(inbox.matches(text).count(), 1, "{text}:\n{inbox}");
    }
}

/// C28 (Phase 3 P3.12): `raven lan off` and `raven lan on` act on the
/// running raven-node, with no restart. B listens with `auto:P` (lab
/// unlock): off closes `127.0.0.1:P` and `[::1]:P` within 5 s and
/// `raven lan status` says it is not listening; A's message waits, and
/// B's own send says LAN_OFF. On: the same port, in the same process,
/// accepts again within 10 s, and A's message arrives once with no new
/// send.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c28_lan_off_closes_and_on_reopens_live() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create(root.path(), "a");
    let b = Profile::create(root.path(), "b");
    let port = free_any_port(false);
    let mut dials = vec![format!("127.0.0.1:{port}")];
    if has_ipv6_loopback() {
        dials.push(format!("[::1]:{port}"));
    }
    let a_svc = a.start_service();
    let mut b_svc = b.start_service_lan(&format!("auto:{port}"), &[("RAVEN_LAB_LAN_AUTO", "1")]);
    a.pin_contact(&b, "bob", Some(&dials[0]));
    b.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    assert_delivered("a→b", &a.send("bob", "c28 before"));
    let pid = b_svc.child.id();

    let off = b.raven(&["lan", "off"], None);
    assert!(
        off.ok
            && off
                .stdout
                .contains("The running raven-node turned LAN off now."),
        "{}",
        off.all()
    );
    for dial in &dials {
        assert!(
            wait_until(Duration::from_secs(5), || !tcp_open(dial)),
            "{dial} still accepts after `raven lan off`"
        );
    }
    b_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| {
            l.contains("raven-node lan_direct: off (raven lan off)")
        })
        .unwrap_or_else(|| panic!("no off line:\n{}", b_svc.log.text()));
    assert_eq!(
        lan_row(&b, "raven-node"),
        "off (not listening now; local sources only)"
    );
    let waiting = a.send("bob", "c28 while off");
    assert!(
        !waiting.ok && waiting.all().contains("not delivered yet"),
        "{}",
        waiting.all()
    );
    let own = b.send("alice", "c28 from b while off");
    assert!(!own.ok && own.all().contains("LAN_OFF"), "{}", own.all());

    let on = b.raven(&["lan", "on"], None);
    assert!(
        on.ok
            && on
                .stdout
                .contains("The running raven-node turned LAN on now."),
        "{}",
        on.all()
    );
    for dial in &dials {
        assert!(
            wait_until(Duration::from_secs(10), || tcp_open(dial)),
            "{dial} does not accept again after `raven lan on`"
        );
    }
    assert!(
        b_svc.child.try_wait().unwrap().is_none() && b_svc.child.id() == pid,
        "B's node restarted"
    );
    assert!(
        wait_until(Duration::from_secs(90), || b
            .inbox()
            .contains("c28 while off")),
        "the waiting message did not arrive after `raven lan on`"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(b.inbox().matches("c28 while off").count(), 1);
}

/// C29 (Phase 3 P3.12): the LAN beacon over real multicast. A and B with
/// `auto` listeners (lab unlock), the beacon (`RAVEN_LAB_LAN_BEACON=1`) on
/// a free UDP port (`RAVEN_LAB_LAN_BEACON_PORT`, never 7420), pinned to
/// each other with no address at all. On IPv4, A's send is delivered
/// within 10 s through what its beacon found (`found on your network now`),
/// A's own query came back to it (`echo_ok`) and B answered it. Then the
/// same over IPv6 link-local only (`RAVEN_LAB_LAN_BEACON_FAMILY=v6`): the
/// find is `[fe80::…%zone]`, where the runner has one. Skipped only with
/// `RAVEN_HARNESS_NO_MULTICAST=1` (a runner without multicast), and the
/// skip is printed.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c29_lan_beacon_real_multicast_finds_a_contact_without_an_address() {
    if !lab_ready() {
        return;
    }
    if std::env::var_os("RAVEN_HARNESS_NO_MULTICAST").is_some_and(|v| v == "1") {
        eprintln!(
            "skipped: C29 (the LAN beacon over real multicast): RAVEN_HARNESS_NO_MULTICAST=1"
        );
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    c29_round(root.path(), ("a4", "b4"), None);
    c29_round(root.path(), ("a6", "b6"), Some("v6"));
}

/// One C29 round, on the address `family` the beacon keeps (both: IPv4
/// first, `v6`: IPv6 link-local only).
fn c29_round(root: &Path, names: (&'static str, &'static str), family: Option<&str>) {
    let beacon_port = free_any_port(true).to_string();
    let make = |name: &'static str| {
        let mut p = Profile::new(root, name, false)
            .with_lab_env("RAVEN_LAB_LAN_AUTO", "1")
            .with_lab_env("RAVEN_LAB_LAN_BEACON", "1")
            .with_lab_env("RAVEN_LAB_LAN_BEACON_PORT", &beacon_port);
        if let Some(family) = family {
            p = p.with_lab_env("RAVEN_LAB_LAN_BEACON_FAMILY", family);
        }
        p.init();
        p
    };
    let (a, b) = (make(names.0), make(names.1));
    let _a_svc = a.start_service_lan(&format!("auto:{}", free_any_port(false)), &[]);
    let _b_svc = b.start_service_lan(&format!("auto:{}", free_any_port(false)), &[]);
    a.pin_contact(&b, "bob", None);
    b.pin_contact(&a, "alice", None);
    for p in [&a, &b] {
        if !wait_until(Duration::from_secs(30), || {
            lan_row(p, "LAN search").starts_with("on ")
        }) {
            let row = lan_row(p, "LAN search");
            if family.is_some() && row == "waiting for a local network" {
                eprintln!(
                    "skipped: C29 over IPv6: no interface here has an IPv6 link-local address"
                );
                return;
            }
            panic!(
                "{}: the beacon does not run ({row}); on a runner without multicast set \
                 RAVEN_HARNESS_NO_MULTICAST=1",
                p.name
            );
        }
    }
    let label = family.unwrap_or("v4");
    let started = Instant::now();
    let mut tries = Vec::new();
    let delivered = loop {
        let text = format!("c29 {label} #{}", tries.len() + 1);
        let out = a.send("bob", &text);
        if out.ok {
            break Some((text, out));
        }
        tries.push(out.all());
        if started.elapsed() >= Duration::from_secs(10) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let Some((text, out)) = delivered else {
        panic!(
            "C29 {label}: not delivered within 10 s:\n{}",
            tries.join("\n---\n")
        );
    };
    assert!(
        started.elapsed() <= Duration::from_secs(12),
        "C29 {label}: delivered after {:?}",
        started.elapsed()
    );
    assert_delivered(&format!("a→b over the beacon ({label})"), &out);
    let found = out
        .stdout
        .lines()
        .find(|l| l.contains("(found on your network now"))
        .unwrap_or_else(|| panic!("C29 {label}: no find in the send:\n{}", out.all()));
    if family.is_some() {
        assert!(
            found.contains("[fe80:") && found.contains('%'),
            "C29 {label}: not a link-local find with its zone: {found}"
        );
    }
    assert_eq!(b.inbox().matches(&text).count(), 1, "{text}");
    let beacon = beacon_json(&a);
    assert_eq!(beacon["echo_ok"], true, "C29 {label}: no echo: {beacon}");
    assert!(
        beacon["answered_10m"].as_u64().unwrap_or(0) >= 1,
        "C29 {label}: {beacon}"
    );
    assert!(
        !lan_row(&a, "LAN search").contains("multicast blocked"),
        "C29 {label}"
    );
}

/// C30 (Phase 3 P3.12): the beacon's safety, on a lab bus of the test's own
/// (`RAVEN_LAB_LAN_BEACON_BUS`: 127.0.0.1 only). A stranger S, who holds A
/// as a contact while A does not hold S, looks for A: A answers nothing
/// (`answers_sent` 0) and S finds nothing. B runs with the beacon's gate
/// closed (no `RAVEN_LAB_LAN_BEACON`, as every release build), its lab port
/// and bus named anyway: its beacon is `held`, nothing of B's is on the
/// bus, its lab UDP port is free, and A delivers to B by its saved route
/// as today (no find).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c30_lan_beacon_stranger_and_old_peer_safety() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let bus = root.path().join("bus");
    let bus_file = root.path().join("bus.txt");
    std::fs::write(&bus_file, format!("{}\n", bus.display())).unwrap();
    let bus_file = bus_file.to_str().unwrap().to_string();
    let lab_port = free_any_port(true);
    let make = |name: &'static str, beacon: bool| {
        let mut p = Profile::new(root.path(), name, false)
            .with_lab_env("RAVEN_LAB_LAN_BEACON_BUS", &bus_file)
            .with_lab_env("RAVEN_LAB_LAN_BEACON_PORT", &lab_port.to_string());
        if beacon {
            p = p.with_lab_env("RAVEN_LAB_LAN_BEACON", "1");
        }
        p.init();
        p
    };
    let (a, s, b) = (make("a", true), make("s", true), make("b", false));
    let a_svc = a.start_service();
    let _s_svc = s.start_service();
    let b_svc = b.start_service();
    let on_bus = || {
        std::fs::read_dir(&bus).map_or(0, |d| {
            d.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "port"))
                .count()
        })
    };
    assert!(
        wait_until(Duration::from_secs(30), || on_bus() == 2),
        "A's and S's beacons are not on the bus"
    );

    // ── a stranger's query gets no answer ────────────────────────────────
    s.pin_contact(&a, "alice", None);
    let mut probes = Vec::new();
    for _ in 0..2 {
        // A user send's queries go at most every 2 s.
        std::thread::sleep(Duration::from_millis(2500));
        let probe = s.send("alice", "c30 stranger probe");
        assert!(!probe.ok, "{}", probe.all());
        probes.push(probe.all());
        if beacon_json(&s)["queries_10m"].as_u64().unwrap_or(0) >= 1 {
            break;
        }
    }
    let s_beacon = beacon_json(&s);
    assert!(
        s_beacon["queries_10m"].as_u64().unwrap_or(0) >= 1,
        "S never asked: {s_beacon}\n{}",
        probes.join("\n---\n")
    );
    assert_eq!(s_beacon["answered_10m"], 0, "{s_beacon}");
    let a_beacon = beacon_json(&a);
    assert_eq!(a_beacon["answers_sent_10m"], 0, "{a_beacon}");
    assert!(!a.inbox().contains("c30 stranger probe"));

    // ── the beacon's gate closed on B: nothing opened, today's delivery ──
    assert_eq!(beacon_json(&b)["state"], "held");
    assert_eq!(lan_row(&b, "LAN search"), "held in this build");
    assert_eq!(on_bus(), 2, "B is on the bus with its gate closed");
    assert!(
        std::net::UdpSocket::bind(("0.0.0.0", lab_port)).is_ok(),
        "B holds its lab beacon port {lab_port} with the gate closed"
    );
    a.pin_contact(&b, "bob", Some(&b_svc.lan_dial));
    b.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    std::thread::sleep(Duration::from_millis(1500));
    let sent = a.send("bob", "c30 to a node without the beacon");
    assert_delivered("a→b (gate closed on B)", &sent);
    assert!(
        !sent.all().contains("found on your network now"),
        "{}",
        sent.all()
    );
    assert_eq!(
        b.inbox()
            .matches("c30 to a node without the beacon")
            .count(),
        1
    );
    assert_eq!(beacon_json(&a)["answered_10m"], 0, "nobody answers for B");
}

/// The renewer's log line for a renewal this daemon made (P3.14).
const RENEWED_LINE: &str = "raven-node renewal: renewed a session (";

/// The hours a queued send says its message keeps (`in about N h`, from
/// ash's `until_text`), or `None` when it names none.
fn hours_left(out: &Output) -> Option<u64> {
    let all = out.all();
    let at = all.find("in about ")? + "in about ".len();
    let rest = &all[at..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    rest[digits.len()..]
        .starts_with(" h")
        .then(|| digits.parse().ok())
        .flatten()
}

#[test]
fn hours_left_reads_the_queued_deadline() {
    let out = |stdout: &str| Output {
        ok: false,
        stdout: stdout.into(),
        stderr: String::new(),
    };
    assert_eq!(
        hours_left(&out("expires tomorrow 09:10 (in about 23 h)")),
        Some(23)
    );
    assert_eq!(hours_left(&out("expires in about 11 h")), Some(11));
    assert_eq!(hours_left(&out("expires in about 40 min")), None);
    assert_eq!(hours_left(&out("delivered")), None);
}

/// C31 session renewal (Phase 3 item 4): A's first send makes an 11 h
/// session (debug `RAVEN_LAB_SESSION_LIFETIME_MS` on that `raven send`
/// only). B did not start it, so B renews it after the settle; then B goes
/// down, A's queued message gets a deadline about 24 h out (not 11 h), and is
/// delivered once when B is back on its port.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c31_a_session_near_its_end_is_renewed_and_waiting_messages_keep_a_day() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let make = |name: &'static str| {
        let mut p =
            Profile::new(root.path(), name, false).with_lab_env("RAVEN_LAB_SESSION_RENEWAL", "1");
        p.init();
        p
    };
    let (a, b) = (make("ra"), make("rb"));
    let b_listen = format!("127.0.0.1:{}", free_loopback_port());
    let a_svc = a.start_service();
    let b_svc = b.start_service_on(&b_listen, None);
    assert_eq!(b_svc.lan_dial, b_listen);
    a.add_contact(&b, "bob", &b_svc.lan_dial);
    b.add_contact(&a, "alice", &a_svc.lan_dial);

    // ── an 11 h session, started by A ────────────────────────────────────
    let eleven_hours = (11 * 3_600_000u64).to_string();
    let warmup = a.raven_with(
        &["send", "--contact", "@bob"],
        Some("c31 warmup\n"),
        &[("RAVEN_LAB_SESSION_LIFETIME_MS", &eleven_hours)],
    );
    assert_delivered("a→b (an 11 h session)", &warmup);
    for (p, svc) in [(&a, &a_svc), (&b, &b_svc)] {
        let status = ipc_status(p);
        assert!(
            status["capabilities"]
                .as_array()
                .is_some_and(|c| c.iter().any(|x| x == "session_renewal")),
            "{}: no session_renewal capability: {status}\n{}",
            p.name,
            svc.log.text()
        );
    }

    // ── B renews it (primary: B did not start it) after the settle ───────
    let renewed = b_svc.log.wait_for(Duration::from_secs(90), |l| {
        l.contains("raven-node renewal: renewed a session (primary")
    });
    assert!(
        renewed.is_some(),
        "b did not renew within 90 s:\n{}\n---\n{}",
        b_svc.log.text(),
        a_svc.log.text()
    );
    assert_eq!(b_svc.log.count(RENEWED_LINE), 1, "{}", b_svc.log.text());
    let b_log_before = Arc::clone(&b_svc.log);

    // ── B away: A's message keeps about a day, not the old 11 h ──────────
    drop(b_svc);
    let text = "c31 sent while bob was down";
    let queued = a.send("bob", text);
    assert!(!queued.ok, "nothing confirmed it yet:\n{}", queued.all());
    let hours = hours_left(&queued);
    assert!(
        hours.is_some_and(|h| h >= 23),
        "the queued message keeps {hours:?} h, not a day:\n{}",
        queued.all()
    );
    let mid = queued_mid(&queued);
    assert_eq!(mid.len(), 8, "{mid}");

    // ── B back on its port: delivered once by A's outbox, B answers ──────
    let b_svc = b.start_service_on(&b_listen, None);
    let delivered = wait_until(Duration::from_secs(90), || {
        let st = a.raven(&["outbox", "status", &mid], None);
        st.ok && st.stdout.contains("state       delivered")
    });
    assert!(
        delivered,
        "not delivered within 90 s of b's return:\n{}\n---\n{}",
        a_svc.log.text(),
        b_svc.log.text()
    );
    let inbox = b.inbox();
    assert_eq!(
        inbox.matches(text).count(),
        1,
        "exactly once on b:\n{inbox}"
    );
    assert_delivered("b→a (reply)", &b.send("alice", "c31 reply"));
    assert_eq!(a.inbox().matches("c31 reply").count(), 1);

    // ── no loop: the fresh session needs no renewal on the next links ────
    // (a link is stepped one settle, 15 s, after it; nothing is logged when
    // a session is not due).
    let again = a_svc
        .log
        .wait_for(Duration::from_secs(20), |l| l.contains(RENEWED_LINE));
    let renewals = b_log_before.count(RENEWED_LINE)
        + b_svc.log.count(RENEWED_LINE)
        + a_svc.log.count(RENEWED_LINE);
    assert!(
        again.is_none() && renewals == 1,
        "{renewals} renewals:\n{}\n---\n{}\n---\n{}",
        a_svc.log.text(),
        b_log_before.text(),
        b_svc.log.text()
    );
}

// ── Phase 3 item 3: friend custody over the internet (P3.22) ──────────────

/// A deposit line (`custody: left N with a friend (p2p_dial, relayed)`).
const CUSTODY_LEFT: &str = "raven-node custody: left ";
/// Alice's and Bob's mail friend chosen from Carol's offer.
const MAIL_FRIENDS_ONE: &str = "raven-node custody: mail friends now 1";
/// What a custodian that pretends to be an old build logs for each RFC1
/// link it closes (C33 d).
const OLD_CUSTODIAN_CLOSED: &str = "lan frame is not RavenEnvelopeV1";
/// The depositor's counts-only line when three closed deposit links park a
/// custodian as CUSTODY_UNSUPPORTED (C33 d).
const OLD_CUSTODIAN_PARKED: &str =
    "raven-node custody: a friend closed 3 deposit links within an hour";
/// The p2p peer gate's counts-only refusal of a peer that is not a verified
/// contact.
const GATE_REFUSED: &str =
    "raven-node p2p: refused a connection from a peer that is not a verified contact";

/// The custody environment of C32-C34's daemons: s30's timers (leave a
/// message with a friend at once, fetch every second) and, with `wan`, the
/// WAN custody switch.
fn custody_env(wan: bool) -> Vec<(&'static str, &'static str)> {
    let mut env = vec![
        ("RAVEN_LAB_CUSTODY_AFTER_MS", "0"),
        ("RAVEN_LAB_CUSTODY_FETCH_MS", "1000"),
    ];
    if wan {
        env.push(("RAVEN_LAB_CUSTODY_WAN", "1"));
    }
    env
}

/// A profile of C32 and C33: the p2p lab unlock and route hints (custody
/// rides RRH1) for every process of it.
fn custody_profile(root: &Path, name: &'static str) -> Profile {
    Profile::create_with(root, name, p2p_lab_unlock()).with_route_hints()
}

/// `p`'s daemon listening on loopback with a reservation on `via` and
/// `env` for it alone.
fn start_custody_node(p: &Profile, via: &str, env: &[(&str, &str)]) -> Service {
    p.start_service_p2p_opts(&P2pStart {
        listen: "127.0.0.1:0",
        relay_via: via,
        wait_reservation: true,
        env,
    })
}

/// Carol offers to hold mail (`raven node custody on --yes`); `users` turn
/// friend mailboxes on (`raven custody use on --yes`). Nobody names a
/// custodian.
fn custody_consents(c: &Profile, users: &[&Profile]) {
    let on = c.raven(&["node", "custody", "on", "--yes"], None);
    assert!(
        on.ok && on.stdout.contains("ok friend custody on"),
        "{} node custody on:\n{}",
        c.name,
        on.all()
    );
    for p in users {
        let mailbox = p.raven(&["custody", "use", "on", "--yes"], None);
        assert!(mailbox.ok, "{} custody use on:\n{}", p.name, mailbox.all());
    }
}

/// The custodian tags `p` keeps from `other`'s route hints.
fn learned_custodian_tags(p: &Profile, other: &Profile) -> usize {
    learned_entry(p, other)
        .and_then(|e| e["custodian_tags"].as_array().map(Vec::len))
        .unwrap_or(0)
}

/// The CUSTODY_OFFER flags `p` keeps from `other` (`None`: no offer).
fn learned_custody_offer(p: &Profile, other: &Profile) -> Option<u64> {
    learned_entry(p, other)?["custody_offer"].as_u64()
}

/// Carol's offer reaches Alice and Bob (a p2p message each to her), each
/// picks her as mail friend, then a message each way between them carries
/// her pair-blinded tag, held by both within 60 s.
fn custody_mailbox_ready(
    (a, a_svc): (&Profile, &Service),
    (b, b_svc): (&Profile, &Service),
    label: &str,
) {
    for p in [a, b] {
        p2p_send(p, "carol", &format!("{label} {} to carol", p.name));
    }
    for (p, svc) in [(a, a_svc), (b, b_svc)] {
        assert!(
            svc.log
                .wait_for(Duration::from_secs(90), |l| l.contains(MAIL_FRIENDS_ONE))
                .is_some(),
            "{} picked no mail friend:\n{}",
            p.name,
            svc.log.text()
        );
    }
    p2p_send(a, "bob", &format!("{label} a to b"));
    p2p_send(b, "alice", &format!("{label} b to a"));
    assert!(
        wait_until(Duration::from_secs(60), || {
            learned_custodian_tags(a, b) >= 1 && learned_custodian_tags(b, a) >= 1
        }),
        "the custodian tags did not arrive:\n{}\n{}",
        a_svc.log.text(),
        b_svc.log.text()
    );
}

/// A send from `p` to `tag` that waits in the outbox (its contact is away):
/// its message id.
fn custody_queued_send(p: &Profile, tag: &str, text: &str) -> String {
    let out = p.send(tag, text);
    assert!(
        !out.ok && out.all().contains("not delivered yet"),
        "{} to {tag} was not queued:\n{}",
        p.name,
        out.all()
    );
    queued_mid(&out)
}

/// Waits until `p`'s outbox says a friend holds what waits (`held by N
/// friend`).
fn wait_held_by_a_friend(p: &Profile, svc: &Service, secs: u64) {
    let mut list = String::new();
    assert!(
        wait_until(Duration::from_secs(secs), || {
            list = p.raven(&["outbox", "list"], None).stdout;
            list.contains("held by 1 friend")
        }),
        "{}'s outbox says no friend holds it within {secs} s:\n{list}\n{}",
        p.name,
        svc.log.text()
    );
}

/// The bytes of a custodian's store files (friend_custody.sqlite and its
/// WAL), and their names.
fn custody_store(p: &Profile) -> (Vec<String>, Vec<u8>) {
    let mut names = Vec::new();
    let mut bytes = Vec::new();
    for entry in std::fs::read_dir(&p.dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("friend_custody.sqlite") {
            bytes.extend(std::fs::read(entry.path()).unwrap_or_default());
            names.push(name);
        }
    }
    names.sort();
    (names, bytes)
}

/// A crafted RFC1 DEPOSIT for `recipient` over a lab P2pDial from `from`'s
/// daemon to the owner of `custodian_card` (raven-node takes RFC1 on an IPC
/// dial only in a lab run). Its object is nothing a custodian would store,
/// so only the custodian's gate decides: its code, or `Err` with what came
/// back instead (no link, no RFC1 reply).
fn p2p_custody_deposit(
    from: &Profile,
    custodian: &Profile,
    custodian_card: &str,
    recipient: &Profile,
) -> Result<raven_core::friend_custody::CustodyCode, String> {
    use base64::Engine as _;
    use raven_core::friend_custody::{decode_reply, encode_request, Rfc1Reply, Rfc1Request};
    use raven_core::ipc::{IpcRequest, IpcResponse};
    let mut key = [0u8; 32];
    hex::decode_to_slice(&recipient.pub_hex, &mut key).unwrap();
    let frame = encode_request(
        &[0xD5; 8],
        &Rfc1Request::Deposit {
            recipient: key,
            rso1: vec![0u8; 128],
        },
    );
    let b64 = base64::engine::general_purpose::STANDARD;
    let req = IpcRequest::P2pDial {
        v: raven_core::ipc::IPC_VERSION,
        multiaddr: format!("/p2p/{}", card_peer(custodian_card)),
        expected_pub_hex: custodian.pub_hex.clone(),
        frames_b64: vec![b64.encode(frame)],
    };
    let wire = raven_core::ipc::encode_request(&req).unwrap();
    let endpoint = ipc_endpoint_of(from);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(ipc_transact(&endpoint, &wire));
    });
    let body = rx
        .recv_timeout(COMMAND_TIMEOUT)
        .map_err(|_| format!("{}: no IPC answer within {COMMAND_TIMEOUT:?}", from.name))?
        .map_err(|e| format!("{}: IPC: {e}", from.name))?;
    match serde_json::from_slice::<IpcResponse>(&body) {
        Ok(IpcResponse::P2pDialResult { frames_b64, .. }) => frames_b64
            .iter()
            .filter_map(|f| b64.decode(f).ok())
            .find_map(|reply| match decode_reply(&reply) {
                Ok(([0xD5, ..], Rfc1Reply::DepositResult { code, .. })) => Some(code),
                _ => None,
            })
            .ok_or_else(|| "a dial result with no deposit answer".to_string()),
        Ok(other) => Err(format!("{other:?}")),
        Err(e) => Err(format!("IPC answer: {e}")),
    }
}

/// How many RFC1 links an old-pretending custodian closed: its `p2p
/// inbound` lines, the rate limiter's `(and N more like it …)` counted in.
fn old_custodian_closes(svc: &Service) -> usize {
    svc.log
        .text()
        .lines()
        .filter(|l| l.contains(OLD_CUSTODIAN_CLOSED))
        .map(|l| {
            1 + l
                .split_once("(and ")
                .and_then(|(_, rest)| rest.split(' ').next()?.parse::<usize>().ok())
                .unwrap_or(0)
        })
        .sum()
}

/// Every deposit line in `log` names how the link travelled (`relayed`),
/// and there is at least one.
fn custody_lines_relayed(log: &str) -> Vec<&str> {
    log.lines().filter(|l| l.contains(CUSTODY_LEFT)).collect()
}

/// No log names a PeerId or a 64-hex value (a key, a tag, a digest).
fn assert_custody_logs_counts_only(logs: &[(&str, String)]) {
    for (name, text) in logs {
        assert!(
            !text.contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{text}"
        );
        let hex64 = text
            .split(|c: char| !c.is_ascii_hexdigit())
            .any(|w| w.len() == 64);
        assert!(!hex64, "{name}'s log names a 64-hex value:\n{text}");
    }
}

/// C32 (Phase 3 item 3): friend custody over relay circuits, message and
/// ACK. A dedicated relay R behind a recording proxy; Alice, Bob and Carol
/// listen on loopback, reserve on R and pin each other from cards naming
/// only R (no LAN or Internet route), with route hints and the WAN custody
/// switch. Carol offers to hold mail, Alice and Bob turn friend mailboxes
/// on, and nobody names a custodian: Carol's offer and the pair-blinded
/// tags ride route hints. Bob stops; Alice's message waits and her outbox
/// says `held by 1 friend`. Alice stops, Bob starts: his inbox has it
/// exactly once, and his ACK is left with Carol. Bob stops, Alice starts:
/// she fetches the ACK from Carol and her outbox says delivered. The proxy
/// carried no RFC1, RSO1, RVPI1, RVPR1 or RLB1 magic, no message text, no
/// raw key and no custodian tag in clear; Carol's store holds no text; the
/// deposit lines say `relayed`; no log names a PeerId or a 64-hex value;
/// R's status holds counts only.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c32_custody_over_relay_circuits_message_and_ack() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    let (proxy, via) = proxied_via(&relay);
    let a = custody_profile(root.path(), "ka");
    let b = custody_profile(root.path(), "kb");
    let c = custody_profile(root.path(), "kc");
    let cards: Vec<String> = [&a, &b, &c].iter().map(|p| p.p2p_card(&via)).collect();
    for (p, card) in [&a, &b, &c].iter().zip(&cards) {
        relay.allow(p, card);
    }
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(3));
    let env = custody_env(true);
    let a_svc = start_custody_node(&a, &via, &env);
    let b_svc = start_custody_node(&b, &via, &env);
    let c_svc = start_custody_node(&c, &via, &env);
    for (i, (p, tag)) in [(&a, "alice"), (&b, "bob"), (&c, "carol")]
        .iter()
        .enumerate()
    {
        for (j, other) in [&a, &b, &c].iter().enumerate() {
            if i != j {
                other.add_card(&cards[i], tag, &p.fingerprint);
            }
        }
    }
    for svc in [&a_svc, &b_svc, &c_svc] {
        wait_gate(svc, 2);
    }
    custody_consents(&c, &[&a, &b]);
    custody_mailbox_ready((&a, &a_svc), (&b, &b_svc), "c32");
    let offer = learned_custody_offer(&a, &c);
    assert!(
        offer.is_some_and(|f| f & 0x01 == 0x01),
        "carol's offer lacks the WAN bit: {offer:?}"
    );

    // ── Bob away: Alice's message is left with Carol ──────────────────────
    let text = "c32 left with carol over a circuit";
    drop(b_svc);
    let mid = custody_queued_send(&a, "bob", text);
    wait_held_by_a_friend(&a, &a_svc, 60);
    let a_log = a_svc.log.text();
    drop(a_svc);

    // ── Alice away, Bob back: once; his ACK is left with Carol ────────────
    let b_svc = start_custody_node(&b, &via, &env);
    assert!(
        wait_until(Duration::from_secs(60), || b.inbox().contains(text)),
        "bob did not fetch it within 60 s:\n{}\n{}",
        b_svc.log.text(),
        c_svc.log.text()
    );
    assert!(
        b_svc
            .log
            .wait_for(Duration::from_secs(60), |l| l.contains(CUSTODY_LEFT))
            .is_some(),
        "bob's ACK was not left with carol:\n{}",
        b_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(b.inbox().matches(text).count(), 1, "exactly once on bob");
    let b_log = b_svc.log.text();
    drop(b_svc);

    // ── Bob away, Alice back: the ACK through Carol ───────────────────────
    let a_svc = start_custody_node(&a, &via, &env);
    let acked = a_svc.log.wait_for(Duration::from_secs(60), |l| {
        l.contains("raven-node custody: fetched messages=") && !l.contains(" acks=0 ")
    });
    assert!(
        acked.is_some(),
        "alice fetched no ACK from carol within 60 s:\n{}\n{}",
        a_svc.log.text(),
        c_svc.log.text()
    );
    assert!(
        wait_until(Duration::from_secs(30), || {
            let st = a.raven(&["outbox", "status", &mid], None);
            st.ok && st.stdout.contains("state       delivered")
        }),
        "alice's outbox does not say delivered:\n{}",
        a.raven(&["outbox", "status", &mid], None).all()
    );

    // ── What the relay path, the store and the logs hold ─────────────────
    let seen = proxy.recorded();
    assert!(seen.len() > 8 << 10, "the proxy saw {} bytes", seen.len());
    let key = |p: &Profile| -> [u8; 32] {
        let mut k = [0u8; 32];
        hex::decode_to_slice(&p.pub_hex, &mut k).unwrap();
        k
    };
    let (ka, kb, kc) = (key(&a), key(&b), key(&c));
    let tags = [
        raven_core::route_hints::custodian_tag(&ka, &kb, &kc),
        raven_core::route_hints::custodian_tag(&kb, &ka, &kc),
    ];
    let mut needles: Vec<(&str, Vec<u8>)> = vec![
        ("RFC1 magic", b"RFC1".to_vec()),
        ("RSO1 magic", b"RSO1".to_vec()),
        ("PairInit magic", b"RVPI1".to_vec()),
        ("PairResponse magic", b"RVPR1".to_vec()),
        ("RLB1 magic", b"RLB1".to_vec()),
        ("the message text", text.as_bytes().to_vec()),
        ("a custodian tag", tags[0].to_vec()),
        ("the other custodian tag", tags[1].to_vec()),
    ];
    for (who, k) in [("a", ka), ("b", kb), ("c", kc)] {
        needles.push((who, k.to_vec()));
    }
    for (what, needle) in &needles {
        assert!(
            !contains(&seen, needle),
            "the relay path carried {what} in clear"
        );
    }
    drop(a_svc);
    drop(c_svc);
    let (files, store) = custody_store(&c);
    assert!(!files.is_empty(), "carol has no custody store");
    for needle in [
        text.as_bytes(),
        b"RVPI1".as_slice(),
        b"RVPR1".as_slice(),
        b"RLB1".as_slice(),
    ] {
        assert!(
            !contains(&store, needle),
            "carol's store ({files:?}) holds {:?}",
            String::from_utf8_lossy(needle)
        );
    }
    let lines: Vec<String> = custody_lines_relayed(&a_log)
        .into_iter()
        .chain(custody_lines_relayed(&b_log))
        .map(str::to_string)
        .collect();
    assert!(
        lines.len() >= 2 && lines.iter().all(|l| l.contains("p2p_dial, relayed")),
        "the deposit lines: {lines:?}"
    );
    assert_custody_logs_counts_only(&[("a", a_log), ("b", b_log)]);
    let status = relay.wait_status(|_| true).to_string();
    for (p, card) in [&a, &b, &c].iter().zip(&cards) {
        assert!(
            !status.contains(&p.pub_hex) && !status.contains(card_peer(card)),
            "the relay status names {}: {status}",
            p.name
        );
    }
}

/// C33 (Phase 3 item 3): the WAN custody gates and refusals, one trio on a
/// dedicated relay (every daemon with the lab's loopback candidates, so
/// only hide-IP keeps a link on the relay). (a) Carol without the WAN
/// switch: her offer lacks the WAN bit, Alice's message for the absent Bob
/// says CUSTODIAN_NOT_OFFERING and nothing is left with her; a crafted
/// DEPOSIT over a lab P2pDial is answered HOLD and makes no store file.
/// (c) Alice hides her IP from Carol (`raven contact hide-ip @carol on`);
/// Carol restarts with the switch: her offer gains the WAN bit and the
/// waiting message is left with her within 60 s over the circuit
/// (`p2p_dial, relayed`); Bob back has it exactly once. (b) A stranger S
/// (who pins Carol; she does not know S) and U (pinned by nobody: Carol
/// holds U unverified) get no RFC1 answer at all: Carol's peer gate refuses
/// their links before any identity. (d) Carol restarted as an old build
/// (`RAVEN_LAB_CUSTODY_PRETEND_OLD=1`): she closes every RFC1 link; after
/// three closed deposit links Alice logs that she parked her
/// (CUSTODY_UNSUPPORTED) and leaves her alone (a new message for the absent
/// Bob makes no further link to her), and when Bob returns both waiting
/// messages are delivered directly, exactly once.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c33_wan_custody_gates_and_refusals() {
    use raven_core::friend_custody::CustodyCode;
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    let via = relay.via.clone();
    let a = custody_profile(root.path(), "ga");
    let b = custody_profile(root.path(), "gb");
    let c = custody_profile(root.path(), "gc");
    let s = Profile::create_with(root.path(), "gs", p2p_lab_unlock());
    let u = Profile::create_with(root.path(), "gu", p2p_lab_unlock());
    let cards: Vec<String> = [&a, &b, &c, &s, &u]
        .iter()
        .map(|p| p.p2p_card(&via))
        .collect();
    for (p, card) in [&a, &b, &c, &s, &u].iter().zip(&cards) {
        relay.allow(p, card);
    }
    relay.wait_status(|st| st["counts"]["allowed_peers"].as_u64() == Some(5));
    let with = |extra: &[(&'static str, &'static str)], wan: bool| {
        let mut env = custody_env(wan);
        env.push(("RAVEN_LAB_P2P_LOCAL_CANDIDATES", "1"));
        env.extend_from_slice(extra);
        env
    };
    let wan = with(&[], true);
    let no_wan = with(&[], false);
    let old = with(&[("RAVEN_LAB_CUSTODY_PRETEND_OLD", "1")], true);
    let a_svc = start_custody_node(&a, &via, &wan);
    let b_svc = start_custody_node(&b, &via, &wan);
    let c_svc = start_custody_node(&c, &via, &no_wan);
    for (i, (p, tag)) in [(&a, "alice"), (&b, "bob"), (&c, "carol")]
        .iter()
        .enumerate()
    {
        for (j, other) in [&a, &b, &c].iter().enumerate() {
            if i != j {
                other.add_card(&cards[i], tag, &p.fingerprint);
            }
        }
    }
    for svc in [&a_svc, &b_svc, &c_svc] {
        wait_gate(svc, 2);
    }
    custody_consents(&c, &[&a, &b]);
    custody_mailbox_ready((&a, &a_svc), (&b, &b_svc), "c33");

    // ── (a) Carol without the WAN switch ─────────────────────────────────
    let offer = learned_custody_offer(&a, &c);
    assert_eq!(offer.map(|f| f & 0x01), Some(0), "offer flags {offer:?}");
    let text1 = "c33 waits for a friend who offers";
    drop(b_svc);
    let mid1 = custody_queued_send(&a, "bob", text1);
    assert!(
        wait_until(Duration::from_secs(60), || {
            a.raven(&["outbox", "list"], None)
                .stdout
                .contains("CUSTODIAN_NOT_OFFERING")
        }),
        "no CUSTODIAN_NOT_OFFERING:\n{}\n{}",
        a.raven(&["outbox", "list"], None).all(),
        a_svc.log.text()
    );
    assert_eq!(a_svc.log.count(CUSTODY_LEFT), 0, "{}", a_svc.log.text());
    let crafted = p2p_custody_deposit(&a, &c, &cards[2], &b);
    assert_eq!(crafted, Ok(CustodyCode::Hold), "{}", c_svc.log.text());
    let (files, _) = custody_store(&c);
    assert!(files.is_empty(), "carol made a store: {files:?}");

    // ── (c) hide-IP toward Carol, Carol with the switch ───────────────────
    let hide = a.raven(&["contact", "hide-ip", "@carol", "on"], None);
    assert!(hide.ok, "hide-ip @carol:\n{}", hide.all());
    drop(c_svc);
    let c_svc = start_custody_node(&c, &via, &wan);
    assert!(
        wait_until(Duration::from_secs(60), || {
            learned_custody_offer(&a, &c).is_some_and(|f| f & 0x01 == 0x01)
        }),
        "carol's offer never gained the WAN bit:\n{}",
        c_svc.log.text()
    );
    wait_held_by_a_friend(&a, &a_svc, 60);
    let left = a_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| l.contains(CUSTODY_LEFT))
        .unwrap_or_default();
    assert!(left.contains("(p2p_dial, relayed)"), "{left:?}");
    let b_svc = start_custody_node(&b, &via, &wan);
    assert!(
        wait_until(Duration::from_secs(60), || b.inbox().contains(text1)),
        "bob did not fetch it:\n{}",
        b_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(b.inbox().matches(text1).count(), 1, "exactly once");
    assert!(
        wait_until(Duration::from_secs(60), || {
            a.raven(&["outbox", "status", &mid1], None)
                .stdout
                .contains("state       delivered")
        }),
        "alice's outbox does not say delivered"
    );

    // ── (b) a stranger and an unverified contact get no RFC1 answer ───────
    let s_svc = start_custody_node(&s, &via, &[]);
    let u_svc = start_custody_node(&u, &via, &[]);
    s.add_card(&cards[2], "carol", &c.fingerprint);
    u.add_card(&cards[2], "carol", &c.fingerprint);
    let unverified = c.raven(
        &[
            "contact",
            "add",
            "--card",
            &cards[4],
            "--petname",
            "ursula",
            "--tag",
            "ursula",
        ],
        None,
    );
    assert!(unverified.ok, "{}", unverified.all());
    wait_gate(&s_svc, 1);
    wait_gate(&u_svc, 1);
    let refused_before = c_svc.log.count(GATE_REFUSED);
    for (who, from) in [("the stranger", &s), ("the unverified contact", &u)] {
        let answer = p2p_custody_deposit(from, &c, &cards[2], &a);
        assert!(answer.is_err(), "{who} got an RFC1 answer: {answer:?}");
    }
    assert!(
        wait_until(LOG_TIMEOUT, || c_svc.log.count(GATE_REFUSED)
            > refused_before),
        "carol's gate refused nobody:\n{}",
        c_svc.log.text()
    );
    let (files, store) = custody_store(&c);
    assert!(
        !contains(&store, &hex::decode(&s.pub_hex).unwrap())
            && !contains(&store, &hex::decode(&u.pub_hex).unwrap()),
        "carol's store ({files:?}) names S or U"
    );
    drop(s_svc);
    drop(u_svc);

    // ── (d) an old custodian: three strikes, then direct delivery ─────────
    drop(c_svc);
    let c_svc = start_custody_node(&c, &via, &old);
    drop(b_svc);
    let text2 = "c33 waits past an old custodian";
    let text3 = "c33 after the old custodian is parked";
    let parks = a_svc.log.count(OLD_CUSTODIAN_PARKED);
    custody_queued_send(&a, "bob", text2);
    // Alice's own word that three deposit links were closed and Carol is
    // parked. (Carol's closes do not tell: Alice's fetch dials to her, her
    // mail friend, are closed too, and only deposits strike.)
    assert!(
        wait_until(Duration::from_secs(90), || a_svc
            .log
            .count(OLD_CUSTODIAN_PARKED)
            > parks),
        "alice never parked the old custodian:\n{}\n{}",
        a_svc.log.text(),
        c_svc.log.text()
    );
    // Past the rate limiter's window, then a new message for Bob: Alice
    // leaves Carol alone (parked: no deposit and no fetch), so no further
    // RFC1 link reaches her.
    std::thread::sleep(Duration::from_secs(12));
    let closes = old_custodian_closes(&c_svc);
    let lines = c_svc.log.count(OLD_CUSTODIAN_CLOSED);
    custody_queued_send(&a, "bob", text3);
    std::thread::sleep(Duration::from_secs(20));
    assert_eq!(
        (
            c_svc.log.count(OLD_CUSTODIAN_CLOSED),
            old_custodian_closes(&c_svc)
        ),
        (lines, closes),
        "alice kept dialling the old custodian:\n{}",
        c_svc.log.text()
    );
    assert!(
        !a.raven(&["outbox", "list"], None)
            .stdout
            .contains("held by"),
        "an old custodian holds nothing"
    );
    let b_svc = start_custody_node(&b, &via, &wan);
    assert!(
        wait_until(Duration::from_secs(90), || {
            let inbox = b.inbox();
            inbox.contains(text2) && inbox.contains(text3)
        }),
        "bob did not get both directly:\n{}\n{}",
        a_svc.log.text(),
        b_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(2));
    let inbox = b.inbox();
    assert_eq!(
        (inbox.matches(text2).count(), inbox.matches(text3).count()),
        (1, 1),
        "exactly once"
    );
    assert_custody_logs_counts_only(&[
        ("a", a_svc.log.text()),
        ("b", b_svc.log.text()),
        ("c", c_svc.log.text()),
    ]);
}

/// C34 (Phase 3 item 3, s30r on three OSes): a friend relay and a
/// custodian on one node. Carol runs the Phase 2 friend relay and holds
/// mail; Alice and Bob listen nowhere, pick her relay from its offer and
/// her as mail friend (route hints over LAN links, as C21). Carol's relay
/// PeerId is not her profile's. Bob stops: Alice's circuit to him through
/// Carol's relay finds no reservation (`contact_offline`) before her
/// message is left with Carol; Bob back has it exactly once. Carol's relay
/// status holds counts only.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c34_friend_relay_and_custodian_on_one_node() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let env = custody_env(true);
    let circle = friend_circle(
        root.path(),
        &[
            FriendSpec::operator("rc", "carol", &env),
            FriendSpec::member("ra", "alice", &env),
            FriendSpec::member("rb", "bob", &env),
        ],
        |_| {},
    );
    let mut circle = circle.into_iter();
    let (c, c_svc) = circle.next().unwrap();
    let (a, a_svc) = circle.next().unwrap();
    let (b, b_svc) = circle.next().unwrap();
    custody_consents(&c, &[&a, &b]);
    offer_friend_relay(&c, &c_svc, 2, |tcp| tcp.to_string());
    lan_send(&a, "carol", "c34 a to carol");
    lan_send(&b, "carol", "c34 b to carol");
    assert!(wait_relay_source(&a, &["offer"]), "{}", a_svc.log.text());
    assert!(wait_relay_source(&b, &["offer"]), "{}", b_svc.log.text());
    for (p, svc) in [(&a, &a_svc), (&b, &b_svc)] {
        assert!(
            svc.log
                .wait_for(Duration::from_secs(90), |l| l.contains(MAIL_FRIENDS_ONE))
                .is_some(),
            "{} picked no mail friend:\n{}",
            p.name,
            svc.log.text()
        );
    }
    lan_send(&a, "bob", "c34 a to b");
    lan_send(&b, "alice", "c34 b to a");
    assert!(
        wait_until(Duration::from_secs(60), || {
            learned_custodian_tags(&a, &b) >= 1
                && learned_entry(&a, &b).is_some_and(|e| !learned_relays(&e).is_empty())
        }),
        "alice holds neither bob's tag nor his relay:\n{}",
        a_svc.log.text()
    );
    let relay_peer = friend_relay_status(&c)["peer_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !relay_peer.is_empty() && relay_peer != card_peer(&running_card(&c)),
        "carol's relay key is not its own: {relay_peer:?}"
    );

    // ── Bob away: NotOnRelay, then the deposit with Carol ─────────────────
    let text = "c34 left with the relay operator";
    let peers: Vec<String> = [&a, &b]
        .iter()
        .map(|p| card_peer(&running_card(p)).to_string())
        .collect();
    drop(b_svc);
    custody_queued_send(&a, "bob", text);
    wait_held_by_a_friend(&a, &a_svc, 60);
    let log = a_svc.log.text();
    let offline = log.find("raven-node p2p: a contact is unreachable (contact_offline)");
    let left = log.find(CUSTODY_LEFT);
    assert!(
        matches!((offline, left), (Some(o), Some(l)) if o < l),
        "no NotOnRelay before the deposit:\n{log}"
    );
    let b_svc = b.start_service_p2p_opts(&P2pStart {
        listen: "relay",
        relay_via: "",
        wait_reservation: false,
        env: &env,
    });
    assert!(
        wait_until(Duration::from_secs(60), || b.inbox().contains(text)),
        "bob did not fetch it:\n{}",
        b_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(b.inbox().matches(text).count(), 1, "exactly once");
    let status = friend_relay_status(&c);
    let text_status = status.to_string();
    assert!(status["counts"].is_object(), "{text_status}");
    for (p, peer) in [&a, &b].iter().zip(&peers) {
        assert!(
            !text_status.contains(peer.as_str()) && !text_status.contains(&p.pub_hex),
            "carol's relay status names {}: {text_status}",
            p.name
        );
    }
    assert_custody_logs_counts_only(&[
        ("a", a_svc.log.text()),
        ("b", b_svc.log.text()),
        ("c", c_svc.log.text()),
    ]);
}

// ── Phase 4: restrictive networks (RWS1, C40-C42) ──────────────────────────

/// The relay's name in C41: only [`ConnectProxy`] resolves it (to
/// 127.0.0.1), so a node reaches the relay by it through the proxy alone.
const PROXY_ONLY_NAME: &str = "relay.invalid";

/// `p` with the WSS gate's lab switch for every later process
/// (`RAVEN_LAB_WSS=1` while `WSS_PRODUCTION_ENABLED` is false) and, with
/// `proxy`, its proxy's (`RAVEN_LAB_WSS_PROXY=1` while
/// `WSS_PROXY_PRODUCTION_ENABLED` is false). Each needs the lab unlock, which
/// the profile was created with ([`wss_profile`]).
fn with_wss(mut p: Profile, proxy: bool) -> Profile {
    if wss_lab_unlock() {
        p = p.with_lab_env("RAVEN_LAB_WSS", "1");
    }
    if proxy && !raven_core::WSS_PROXY_PRODUCTION_ENABLED {
        p = p.with_lab_env("RAVEN_LAB_WSS_PROXY", "1");
    }
    p
}

/// A new profile for C40/C41: the lab unlock while the P3 or the WSS flag
/// is off, and [`with_wss`].
fn wss_profile(root: &Path, name: &'static str, proxy: bool) -> Profile {
    let unlock = p2p_lab_unlock() || wss_lab_unlock();
    with_wss(Profile::create_with(root, name, unlock), proxy)
}

/// The TCP port of a multiaddr text (`…/tcp/<port>/…`).
fn tcp_port_of(addr: &str) -> u16 {
    addr.split("/tcp/")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("no TCP port in {addr}"))
}

/// The running raven-node's p2p facts (IPC Status `p2p`).
fn p2p_status(p: &Profile) -> serde_json::Value {
    ipc_status(p)["p2p"].clone()
}

/// An HTTPS (CONNECT) proxy on 127.0.0.1 in this process (C41), as a network
/// that lets only its proxy out has one. It resolves [`PROXY_ONLY_NAME`]
/// itself and nothing else; its log (shared by a restart) has one
/// `CONNECT <target>` line per request and one `tunnel <target> first=<hex>`
/// line per tunnel with the first byte the client sent through it
/// ([`proxy_lines`]). [`Self::stop`] ends it and every tunnel at once (a
/// proxy that went away); a new one may then take its port.
struct ConnectProxy {
    port: u16,
    stopping: Arc<AtomicBool>,
    open: Arc<Mutex<Vec<std::net::TcpStream>>>,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl ConnectProxy {
    /// On `port` (0: any free one), appending to `log`.
    fn start(port: u16, log: Arc<Mutex<Vec<String>>>) -> Self {
        let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stopping = Arc::new(AtomicBool::new(false));
        let open = Arc::new(Mutex::new(Vec::new()));
        let (stop, tracked, lines) = (Arc::clone(&stopping), Arc::clone(&open), Arc::clone(&log));
        let accept = std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let (tracked, lines) = (Arc::clone(&tracked), Arc::clone(&lines));
                        std::thread::spawn(move || connect_tunnel(client, &tracked, &lines));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        ConnectProxy {
            port,
            stopping,
            open,
            accept: Some(accept),
        }
    }

    /// The proxy goes away: no more connections, and every tunnel ends.
    fn stop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        for s in self.open.lock().unwrap().drain(..) {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for ConnectProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

/// One CONNECT request of [`ConnectProxy`]: the head (read a byte at a time,
/// so nothing after it is taken), then a blind tunnel to 127.0.0.1 for
/// [`PROXY_ONLY_NAME`], or 502 for any other target.
fn connect_tunnel(
    mut client: std::net::TcpStream,
    open: &Mutex<Vec<std::net::TcpStream>>,
    log: &Mutex<Vec<String>>,
) {
    let _ = client.set_nonblocking(false);
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8 << 10 || !matches!(client.read(&mut byte), Ok(1)) {
            return;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let target = text
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("CONNECT "))
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_default()
        .to_string();
    log.lock().unwrap().push(format!("CONNECT {target}"));
    let upstream = target
        .rsplit_once(':')
        .filter(|(host, _)| *host == PROXY_ONLY_NAME)
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .and_then(|port| std::net::TcpStream::connect(("127.0.0.1", port)).ok());
    let Some(upstream) = upstream else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .is_err()
    {
        return;
    }
    // The client speaks first (a TLS ClientHello).
    let first = match client.peek(&mut byte) {
        Ok(1) => format!("{:02x}", byte[0]),
        _ => "none".into(),
    };
    log.lock()
        .unwrap()
        .push(format!("tunnel {target} first={first}"));
    let _ = client.set_read_timeout(None);
    let (Ok(c2), Ok(u2)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    {
        let mut open = open.lock().unwrap();
        for s in [&client, &upstream] {
            if let Ok(s) = s.try_clone() {
                open.push(s);
            }
        }
    }
    for (mut from, mut to) in [(c2, upstream), (u2, client)] {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut from, &mut to);
            let _ = to.shutdown(std::net::Shutdown::Both);
        });
    }
}

/// C40: a relay's WSS listener on loopback (Phase 4, RWS1 §6): one port
/// takes WSS and raw libp2p; delivery both ways with A on WSS (behind a
/// network that lets only TLS out) and B on the raw sibling.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c40_wss_relay_on_loopback_both_ways_and_raw_still_works() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start_with(
        root.path(),
        RelayStart {
            name: "relay",
            args: &[],
            opts: RelayOpts { wss: true },
        },
    );
    let up = relay
        .log
        .wait_for(LOG_TIMEOUT, |l| l.contains("raven-node relay: up"))
        .unwrap();
    assert!(up.contains("wss=on (self-signed certificate); "), "{up}");
    let (wss_listen, peer) = relay.wss_via.split_once("/p2p/").unwrap();
    let raw_listen = wss_listen.strip_suffix("/tls/ws").unwrap();
    let wss_port = tcp_port_of(wss_listen);
    assert_ne!(wss_port, tcp_port_of(&relay.via), "a port of its own");
    // The status file lists both forms of the WSS port.
    let status = relay.wait_status(|_| true);
    let addrs = listen_addrs(&status);
    for form in [wss_listen, raw_listen] {
        assert!(addrs.iter().any(|a| a == form), "{form} not in {addrs:?}");
    }
    // relay-probe checks the card's WSS line over WSS (review A-3): wss/<port>
    // reachable, not tcp/<port> refused.
    let mut probe = relay_node_command();
    if wss_lab_unlock() {
        probe.env("RAVEN_LAB_TEST_A", "1").env("RAVEN_LAB_WSS", "1");
    }
    probe.arg("relay-probe").arg(&relay.wss_via);
    let probed = run_bounded(probe, None, COMMAND_TIMEOUT, "relay-probe");
    assert!(probed.ok, "relay-probe:\n{}", probed.all());
    assert!(
        probed
            .stdout
            .contains(&format!("wss/{wss_port}: reachable (answers as the relay")),
        "{}",
        probed.all()
    );
    // A reaches the WSS port through a recording proxy that passes TLS only:
    // its raw sibling is dialled first (RWS1 §2.3) and closed there, the WSS
    // form gets through. B uses the raw sibling on the same port, no proxy.
    let proxy = RecordingProxy::start(std::net::SocketAddr::from(([127, 0, 0, 1], wss_port)));
    proxy.set_mode(ProxyMode::TlsOnly);
    let a_via = format!("/ip4/127.0.0.1/tcp/{}/tls/ws/p2p/{peer}", proxy.addr.port());
    let b_via = format!("{raw_listen}/p2p/{peer}");
    let a = wss_profile(root.path(), "wsa", false);
    let b = wss_profile(root.path(), "wsb", false);
    let a_card = a.p2p_card(&b_via);
    let b_card = b.p2p_card(&b_via);
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    let a_svc = a.start_service_p2p(&a_via);
    let b_svc = b.start_service_p2p(&b_via);
    relay.wait_status(|s| s["counts"]["reservations"].as_u64() == Some(2));
    assert_eq!(p2p_status(&a)["relay_paths"], serde_json::json!(["wss"]));
    assert_eq!(p2p_status(&b)["relay_paths"], serde_json::json!(["tcp"]));
    let status = a.raven(&["status"], None);
    let row = status_row(&status.stdout, "p2p").unwrap_or_default();
    assert!(
        row.contains("reservations 1/1; relay over WSS")
            && !row.contains("through the HTTPS proxy")
            && !row.contains("restricted network"),
        "{row}"
    );

    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    let texts = ["c40 over wss from a", "c40 over raw from b"];
    for ((from, to, tag), text) in [(&a, &b, "bob"), (&b, &a, "alice")].into_iter().zip(texts) {
        let sent = from.raven_with(
            &["send", "--contact", &format!("@{tag}"), "--carrier", "p2p"],
            Some(&format!("{text}\n")),
            &[("RAVEN_VERBOSE", "1")],
        );
        assert_delivered(text, &sent);
        assert_eq!(send_path(&sent), "relayed", "{}", sent.all());
        assert_eq!(to.inbox().matches(text).count(), 1, "exactly once");
    }

    // What the TLS-only path carried: TLS records from the first byte, no
    // libp2p protocol name, PeerId or message text in the clear.
    let seen = proxy.recorded();
    assert_eq!(seen.first(), Some(&0x16), "the first byte is a TLS record");
    for needle in [
        b"/multistream/1.0.0".as_slice(),
        b"/noise",
        b"/yamux",
        b"/libp2p/circuit/relay",
        b"/ipfs/id",
        peer.as_bytes(),
        texts[0].as_bytes(),
        texts[1].as_bytes(),
    ] {
        assert!(
            !contains(&seen, needle),
            "the proxy saw {:?} in the clear",
            String::from_utf8_lossy(needle)
        );
    }
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        assert!(
            !svc.log.text().contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{}",
            svc.log.text()
        );
    }
}

/// C41: a network that lets only its HTTPS proxy out (Phase 4, RWS1 §8-9).
/// A names its relay by a name only the proxy resolves; delivery both ways;
/// the proxy goes away with 3 messages queued and each is delivered exactly
/// once once it is back. The only case with a real RAVEN_P2P_PROXY.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c41_https_proxy_only_path() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    // On loopback A could dial any of R's own addresses, so nothing tells her
    // one: R names only a closed port (`--external`, in Identify too), and so
    // do both cards. A circuit rides the connection its sender already holds
    // to R (B's reservation; A's, through the proxy), as on a network that
    // lets only the proxy out.
    let closed = free_loopback_port();
    let external = format!("/ip4/127.0.0.1/tcp/{closed}");
    let relay = Relay::start_with(
        root.path(),
        RelayStart {
            name: "relay",
            args: &["--external", &external],
            opts: RelayOpts { wss: true },
        },
    );
    let (wss_listen, peer) = relay.wss_via.split_once("/p2p/").unwrap();
    let wss_port = tcp_port_of(wss_listen);
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut proxy = ConnectProxy::start(0, Arc::clone(&log));
    let proxy_port = proxy.port;
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    let a_via = format!("/dns4/{PROXY_ONLY_NAME}/tcp/{wss_port}/tls/ws/p2p/{peer}");
    let card_via = format!("/ip4/127.0.0.1/tcp/{closed}/p2p/{peer}");
    let a = wss_profile(root.path(), "pxa", true);
    let b = wss_profile(root.path(), "pxb", false);
    let a_card = a.p2p_card(&card_via);
    let b_card = b.p2p_card(&card_via);
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    let a_svc = a.start_service_p2p_opts(&P2pStart {
        listen: "relay",
        relay_via: &a_via,
        wait_reservation: true,
        env: &[("RAVEN_P2P_PROXY", &proxy_url)],
    });
    let b_svc = b.start_service_p2p(&relay.via);
    relay.wait_status(|s| s["counts"]["reservations"].as_u64() == Some(2));
    // The proxy got the name, never an address, and only TLS through it.
    let connect = format!("CONNECT {PROXY_ONLY_NAME}:{wss_port}");
    let check_proxy_log = || {
        let connects = proxy_lines(&log, "CONNECT ");
        assert!(
            !connects.is_empty() && connects.iter().all(|l| *l == connect),
            "{connects:?}"
        );
        let tunnels = proxy_lines(&log, "tunnel ");
        assert!(
            !tunnels.is_empty() && tunnels.iter().all(|l| l.ends_with(" first=16")),
            "{tunnels:?}"
        );
    };
    check_proxy_log();
    let mut row = String::new();
    assert!(
        wait_until(LOG_TIMEOUT, || {
            row = status_row(&a.raven(&["status"], None).stdout, "p2p")
                .unwrap_or_default()
                .to_string();
            row.contains("relay over WSS through the HTTPS proxy")
                && row.contains("restricted network (relay only)")
        }),
        "{row}"
    );
    let facts = p2p_status(&a);
    assert_eq!(
        facts["relay_paths"],
        serde_json::json!(["wss-proxy"]),
        "{facts}"
    );
    assert_eq!(facts["restricted"], true, "{facts}");

    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    for (from, to, tag, text) in [
        (&a, &b, "bob", "c41 through the proxy from a"),
        (&b, &a, "alice", "c41 to a behind the proxy"),
    ] {
        let sent = from.raven_with(
            &["send", "--contact", &format!("@{tag}"), "--carrier", "p2p"],
            Some(&format!("{text}\n")),
            &[("RAVEN_VERBOSE", "1")],
        );
        assert_delivered(text, &sent);
        assert_eq!(send_path(&sent), "relayed", "{}", sent.all());
        assert_eq!(to.inbox().matches(text).count(), 1, "exactly once");
    }

    // The proxy goes away: A's reservation ends, 3 messages wait.
    let lost = || a_svc.log.count("raven-node p2p: reservation lost");
    let accepted = || a_svc.log.count("raven-node p2p: reservation accepted");
    let (lost_before, accepted_before) = (lost(), accepted());
    proxy.stop();
    assert!(
        wait_until(Duration::from_secs(60), || lost() > lost_before),
        "the reservation outlived the proxy:\n{}",
        a_svc.log.text()
    );
    let texts = ["c41 queued one", "c41 queued two", "c41 queued three"];
    for text in texts {
        let out = a.send("bob", text);
        assert!(!out.ok, "nothing confirmed it yet:\n{}", out.all());
        queued_mid(&out);
    }
    // A's relay slot tries again, and fails, while the proxy is away.
    let mut doctor = String::new();
    assert!(
        wait_until(Duration::from_secs(60), || {
            doctor = a.raven(&["doctor"], None).stdout;
            doctor.contains("relay_1: retrying")
        }),
        "{doctor}"
    );
    drop(proxy);
    let _proxy = ConnectProxy::start(proxy_port, Arc::clone(&log));
    assert!(
        wait_until(Duration::from_secs(90), || accepted() > accepted_before),
        "no reservation through the proxy once it was back:\n{}",
        a_svc.log.text()
    );
    let delivered = wait_until(Duration::from_secs(120), || {
        let inbox = b.inbox();
        texts.iter().all(|text| inbox.contains(text))
    });
    assert!(
        delivered,
        "not delivered within 120 s of the proxy's return:\n{}\n{}",
        a.raven(&["outbox", "list"], None).all(),
        a_svc.log.text()
    );
    let inbox = b.inbox();
    for text in texts {
        assert_eq!(inbox.matches(text).count(), 1, "exactly once:\n{inbox}");
    }
    let mut list = String::new();
    assert!(
        wait_until(LOG_TIMEOUT, || {
            list = a.raven(&["outbox", "list"], None).all();
            list.contains("Nothing waiting")
        }),
        "nothing left to retry:\n{list}"
    );
    check_proxy_log();
    // A's log names no PeerId, no proxy address and none of the relay's.
    let a_log = a_svc.log.text();
    for leak in [
        "12D3KooW".to_string(),
        PROXY_ONLY_NAME.to_string(),
        format!("127.0.0.1:{proxy_port}"),
        format!("127.0.0.1:{wss_port}"),
        format!("/tcp/{wss_port}"),
    ] {
        assert!(!a_log.contains(&leak), "a's log names {leak}:\n{a_log}");
    }
}

/// [`ConnectProxy`]'s log lines that start with `kind`.
fn proxy_lines(log: &Mutex<Vec<String>>, kind: &str) -> Vec<String> {
    let log = log.lock().unwrap();
    log.iter()
        .filter(|l| l.starts_with(kind))
        .cloned()
        .collect()
}

/// C42: the WSS gate closed (no `RAVEN_LAB_WSS`; Phase 4, RWS1 §7): `relay
/// --wss` is refused, and a service named a WSS relay dials its raw sibling
/// and says WSS_HOLD once. Nothing listens on or dials TLS.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c42_wss_gate_closed_refuses_cleanly() {
    if !lab_ready() {
        return;
    }
    if raven_core::WSS_PRODUCTION_ENABLED {
        eprintln!("skipped: WSS_PRODUCTION_ENABLED is true, so the gate cannot be closed");
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    // `raven-node relay --wss`: exit 2 with WSS_HOLD before anything starts.
    let held = profile_dir(root.path(), "held-relay");
    std::fs::create_dir_all(&held).unwrap();
    let mut cmd = relay_node_command();
    cmd.arg("relay")
        .arg("--data-dir")
        .arg(&held)
        .args(["--listen", "127.0.0.1:0", "--wss", "127.0.0.1:0"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn raven-node relay --wss");
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("relay --wss with the gate closed kept running");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(&format!("relay: {}", raven_core::WSS_HOLD)),
        "{stderr}"
    );
    assert!(!stderr.contains("raven-node relay: up"), "{stderr}");
    assert!(!held.join("relay_status.json").exists());

    // A relay without --wss, behind a recording proxy; A names it by the
    // WSS form of the proxy's port, so the raw sibling is what it dials.
    let relay = Relay::start(root.path());
    let up = relay
        .log
        .wait_for(LOG_TIMEOUT, |l| l.contains("raven-node relay: up"))
        .unwrap();
    assert!(!up.contains("wss="), "{up}");
    let status = relay.wait_status(|_| true);
    assert!(
        listen_addrs(&status).iter().all(|a| !a.contains("/tls/")),
        "{status}"
    );
    let (proxy, raw_via) = proxied_via(&relay);
    let (raw_listen, peer) = raw_via.split_once("/p2p/").unwrap();
    let a_via = format!("{raw_listen}/tls/ws/p2p/{peer}");
    let a = Profile::create_with(root.path(), "hda", p2p_lab_unlock());
    let b = Profile::create_with(root.path(), "hdb", p2p_lab_unlock());
    let a_card = a.p2p_card(&relay.via);
    let b_card = b.p2p_card(&relay.via);
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    let a_svc = a.start_service_p2p(&a_via);
    let b_svc = b.start_service_p2p(&relay.via);
    let held_line = format!("raven-node p2p: {}", raven_core::WSS_HOLD);
    let said = a_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| l.contains(&held_line))
        .unwrap_or_else(|| panic!("no WSS_HOLD line:\n{}", a_svc.log.text()));
    assert!(
        said.ends_with("(1 WSS relay address(es) dialled at their raw TCP form)"),
        "{said}"
    );
    assert_eq!(p2p_status(&a)["relay_paths"], serde_json::json!(["tcp"]));
    let row = status_row(&a.raven(&["status"], None).stdout, "p2p")
        .unwrap_or_default()
        .to_string();
    assert!(
        row.contains("reservations 1/1") && !row.contains("WSS"),
        "{row}"
    );

    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    let text = "c42 over the raw sibling";
    let sent = a.raven_with(
        &["send", "--contact", "@bob", "--carrier", "p2p"],
        Some(&format!("{text}\n")),
        &[("RAVEN_VERBOSE", "1")],
    );
    assert_delivered(text, &sent);
    assert_eq!(send_path(&sent), "relayed", "{}", sent.all());
    assert_eq!(b.inbox().matches(text).count(), 1, "exactly once");
    // Said once per process, however often it dials.
    assert_eq!(a_svc.log.count(&held_line), 1, "{}", a_svc.log.text());
    // Raw libp2p from the first byte (multistream-select's length 19), no
    // TLS record at all.
    let seen = proxy.recorded();
    assert_eq!(seen.first(), Some(&0x13), "raw libp2p, not TLS");
    assert!(contains(&seen, b"/multistream/1.0.0"));
    assert!(
        !a_svc.log.text().contains("12D3KooW"),
        "{}",
        a_svc.log.text()
    );
}

// ── Phase 4: router port mapping (RAVEN_PORT_MAPPING_V1, P4.21) ─────────────

/// The PORT_MAP lab switch is needed only while its flag is off; it also
/// needs the lab unlock (`RAVEN_LAB_TEST_A=1`).
fn port_map_lab_unlock() -> bool {
    !raven_core::portmap_gate::PORT_MAP_PRODUCTION_ENABLED
}

/// The V6_PINHOLE lab switch, likewise.
fn v6_pinhole_lab_unlock() -> bool {
    !raven_core::portmap_gate::V6_PINHOLE_PRODUCTION_ENABLED
}

/// A real UPnP-IGD search (libp2p-upnp's SSDP M-SEARCH to the multicast
/// group of the network the matrix runs on, which its router answers) runs
/// only where `RAVEN_HARNESS_UPNP_SEARCH=1` says that network may see one
/// (the CI runners). C43's silent router and its gate-closed control start
/// one; elsewhere they are skipped, and the skip is printed.
fn upnp_search_allowed(what: &str) -> bool {
    let allowed = std::env::var("RAVEN_HARNESS_UPNP_SEARCH").as_deref() == Ok("1");
    if !allowed {
        eprintln!(
            "note: {what} skipped: it starts a real UPnP search on this network \
             (RAVEN_HARNESS_UPNP_SEARCH=1 runs it)"
        );
    }
    allowed
}

/// A profile for C43/C44: the lab unlock while the P3 or the PORT_MAP flag
/// is off, route hints on, and loopback as a lab address
/// (`RAVEN_LAB_P2P_LOCAL_CANDIDATES=1`: the mapper accepts a loopback
/// client and external address, and route hints carry and keep loopback
/// DIRECT addresses). The PORT_MAP switch goes to each daemon start
/// ([`port_map_env`]), so one profile also runs with the gate closed.
fn port_map_profile(root: &Path, name: &'static str) -> Profile {
    let unlock = p2p_lab_unlock() || port_map_lab_unlock();
    Profile::create_with(root, name, unlock)
        .with_route_hints()
        .with_lab_env("RAVEN_LAB_P2P_LOCAL_CANDIDATES", "1")
}

/// A daemon's port-mapping environment: the router `gateway` names
/// (`RAVEN_LAB_PORTMAP_GATEWAY`), 8 s leases (renewed every 4 s), the
/// PORT_MAP switch when `gate` (and the V6_PINHOLE one with `v6`), and
/// `more`.
fn port_map_env<'a>(
    gateway: &'a str,
    gate: bool,
    v6: bool,
    more: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    let mut env = vec![
        ("RAVEN_LAB_PORTMAP_GATEWAY", gateway),
        ("RAVEN_LAB_PORTMAP_LIFETIME", "8"),
    ];
    if gate && port_map_lab_unlock() {
        env.push(("RAVEN_LAB_PORT_MAP", "1"));
    }
    if v6 && v6_pinhole_lab_unlock() {
        env.push(("RAVEN_LAB_V6_PINHOLE", "1"));
    }
    env.extend_from_slice(more);
    env
}

/// `raven node <args>` (the router consents), which must succeed.
fn node_setting(p: &Profile, args: &[&str]) {
    let out = p.raven(&[&["node"], args].concat(), None);
    assert!(out.ok, "{} raven node {args:?}:\n{}", p.name, out.all());
}

const MAPPED_PCP: &str = "raven-node p2p: router port mapped (PCP, port ";
const MAPPED_NAT_PMP: &str = "raven-node p2p: router port mapped (NAT-PMP, port ";
const ROUTER_RESTARTED: &str = "raven-node p2p: router restarted; port mapped again";
const BEHIND_CGN: &str = "raven-node p2p: router is behind another NAT (carrier NAT): no mapping";
const TRYING_UPNP: &str = "raven-node p2p: no PCP or NAT-PMP answer; trying UPnP";
const NO_UPNP_LAB: &str = "raven-node p2p: no PCP or NAT-PMP answer; UPnP not tried (lab router)";
const NO_ROUTER: &str = "raven-node p2p: no router port mapping found (UPnP, NAT-PMP, PCP)";
const PINHOLE_OPEN: &str = "raven-node p2p: IPv6 pinhole open on the router (PCP)";
const REHOMED: &str = "raven-node p2p: re-homed (network changed)";

/// Phase 4 (P4.21): raven-core's `FakeGateway` (NAT-PMP and PCP, written
/// from the RFCs' field tables) on a UDP socket of its own, and the
/// forwarders a router's mapping is: from the external port it assigns to
/// the node's listen port, TCP and UDP, counting what they carry.
mod fake_gw {
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use raven_core::portmap_fake::{FakeGateway, Mode, SeenReq};

    /// How often the threads look at their stop flag.
    const POLL: Duration = Duration::from_millis(50);
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The router, answering on its own thread; stopped when dropped.
    pub struct Gateway {
        pub addr: SocketAddr,
        fake: Arc<Mutex<FakeGateway>>,
        packets: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Gateway {
        /// On `ip` and a free port; `None` when `ip` cannot be bound (no
        /// IPv6 loopback). Its external IPv4 address is 127.0.0.1, where
        /// the [`Forwarder`]s listen, unless `mode` names another: no test
        /// ever dials a real Internet address.
        pub fn start(ip: IpAddr, mode: Mode) -> Option<Self> {
            let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).ok()?;
            socket.set_read_timeout(Some(POLL)).ok()?;
            let addr = socket.local_addr().ok()?;
            let mut fake = FakeGateway::new(mode, Instant::now());
            fake.reported_v4 = Some(Ipv4Addr::LOCALHOST);
            let fake = Arc::new(Mutex::new(fake));
            let packets = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let (fake, packets, stop) = (fake.clone(), packets.clone(), stop.clone());
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1500];
                    while !stop.load(Ordering::SeqCst) {
                        // A timeout, or an ICMP error of an earlier answer.
                        let Ok((n, src)) = socket.recv_from(&mut buf) else {
                            continue;
                        };
                        packets.fetch_add(1, Ordering::SeqCst);
                        let answer = lock(&fake).reply(&buf[..n], src, Instant::now());
                        if let Some(answer) = answer {
                            let _ = socket.send_to(&answer, src);
                        }
                    }
                })
            };
            Some(Self {
                addr,
                fake,
                packets,
                stop,
                thread: Some(thread),
            })
        }

        /// `RAVEN_LAB_PORTMAP_GATEWAY`'s value naming it.
        pub fn env(&self) -> String {
            self.addr.to_string()
        }

        pub fn with<R>(&self, f: impl FnOnce(&mut FakeGateway) -> R) -> R {
            f(&mut lock(&self.fake))
        }

        /// Every request so far, in order.
        pub fn log(&self) -> Vec<SeenReq> {
            self.with(|g| g.log.clone())
        }

        /// Datagrams received so far, answered or not.
        pub fn packets(&self) -> usize {
            self.packets.load(Ordering::SeqCst)
        }

        /// The router restarts: every mapping is lost and its epoch starts
        /// from 0 again.
        pub fn restart(&self) {
            self.with(|g| {
                g.mappings.clear();
                g.epoch_start = Instant::now();
            });
        }
    }

    impl Drop for Gateway {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// A PCP ANNOUNCE (version 2, opcode 0).
    pub fn is_announce(r: &SeenReq) -> bool {
        r.version == 2 && r.op == 0
    }

    /// A PCP MAP of `proto`: a delete (lifetime 0) when `delete`, else a
    /// request or renewal.
    pub fn is_pcp_map(r: &SeenReq, proto: u8, delete: bool) -> bool {
        r.version == 2 && r.op == 1 && r.proto == Some(proto) && (r.lifetime == 0) == delete
    }

    /// A mapping request of any protocol version (NAT-PMP or PCP MAP).
    pub fn is_mapping(r: &SeenReq) -> bool {
        r.proto.is_some()
    }

    /// TCP and UDP from 127.0.0.1:`port` to `to`, as a router forwards a
    /// mapped external port; stopped when dropped.
    pub struct Forwarder {
        tcp: Arc<AtomicU64>,
        udp: Arc<AtomicU64>,
        stop: Arc<AtomicBool>,
        open: Arc<Mutex<Vec<TcpStream>>>,
        threads: Vec<JoinHandle<()>>,
    }

    impl Forwarder {
        pub fn start(port: u16, to: SocketAddr) -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .unwrap_or_else(|e| panic!("forwarder TCP 127.0.0.1:{port}: {e}"));
            listener.set_nonblocking(true).unwrap();
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
                .unwrap_or_else(|e| panic!("forwarder UDP 127.0.0.1:{port}: {e}"));
            socket.set_read_timeout(Some(POLL)).unwrap();
            let (tcp, udp) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
            let stop = Arc::new(AtomicBool::new(false));
            let open: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
            let accept = {
                let (count, stop, open) = (tcp.clone(), stop.clone(), open.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        let Ok((inbound, _)) = listener.accept() else {
                            std::thread::sleep(POLL);
                            continue;
                        };
                        let _ = inbound.set_nonblocking(false);
                        let Ok(outbound) = TcpStream::connect(to) else {
                            continue;
                        };
                        let (Ok(in2), Ok(out2)) = (inbound.try_clone(), outbound.try_clone())
                        else {
                            continue;
                        };
                        lock(&open).extend([in2, out2]);
                        let (Ok(in3), Ok(out3)) = (inbound.try_clone(), outbound.try_clone())
                        else {
                            continue;
                        };
                        let up = count.clone();
                        std::thread::spawn(move || pipe(in3, out3, &up));
                        let down = count.clone();
                        std::thread::spawn(move || pipe(outbound, inbound, &down));
                    }
                })
            };
            let datagrams = {
                let (count, stop) = (udp.clone(), stop.clone());
                std::thread::spawn(move || {
                    let mut peers: HashMap<SocketAddr, UdpSocket> = HashMap::new();
                    let mut buf = [0u8; 65_536];
                    while !stop.load(Ordering::SeqCst) {
                        let Ok((n, from)) = socket.recv_from(&mut buf) else {
                            continue;
                        };
                        count.fetch_add(n as u64, Ordering::SeqCst);
                        let up = match peers.entry(from) {
                            Entry::Occupied(e) => e.into_mut(),
                            Entry::Vacant(e) => {
                                let Some(up) = upstream(&socket, from, to, &count, &stop) else {
                                    continue;
                                };
                                e.insert(up)
                            }
                        };
                        let _ = up.send(&buf[..n]);
                    }
                })
            };
            Self {
                tcp,
                udp,
                stop,
                open,
                threads: vec![accept, datagrams],
            }
        }

        /// Bytes carried so far, both directions: TCP, then UDP.
        pub fn bytes(&self) -> (u64, u64) {
            (
                self.tcp.load(Ordering::SeqCst),
                self.udp.load(Ordering::SeqCst),
            )
        }
    }

    impl Drop for Forwarder {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            for stream in lock(&self.open).drain(..) {
                let _ = stream.shutdown(Shutdown::Both);
            }
            for thread in self.threads.drain(..) {
                let _ = thread.join();
            }
        }
    }

    /// One way of a forwarded TCP connection, until either side ends.
    fn pipe(mut from: TcpStream, mut to: TcpStream, count: &AtomicU64) {
        let mut buf = [0u8; 16_384];
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    count.fetch_add(n as u64, Ordering::SeqCst);
                    if to.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to.shutdown(Shutdown::Write);
    }

    /// The socket that carries `client`'s datagrams on to `to`, and the
    /// thread that sends the answers back from the forwarder's port.
    fn upstream(
        socket: &UdpSocket,
        client: SocketAddr,
        to: SocketAddr,
        count: &Arc<AtomicU64>,
        stop: &Arc<AtomicBool>,
    ) -> Option<UdpSocket> {
        let up = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
        up.connect(to).ok()?;
        up.set_read_timeout(Some(POLL)).ok()?;
        let (answers, back) = (up.try_clone().ok()?, socket.try_clone().ok()?);
        let (count, stop) = (count.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 65_536];
            while !stop.load(Ordering::SeqCst) {
                if let Ok(n) = answers.recv(&mut buf) {
                    count.fetch_add(n as u64, Ordering::SeqCst);
                    let _ = back.send_to(&buf[..n], client);
                }
            }
        });
        Some(up)
    }
}

/// No log names a PeerId, and no router line an address.
fn assert_port_map_logs_clean(name: &str, log: &str) {
    assert!(
        !log.contains("12D3KooW"),
        "{name}'s log names a PeerId:\n{log}"
    );
    for line in log
        .lines()
        .filter(|l| l.contains("router") || l.contains("pinhole"))
    {
        assert!(
            !line.contains("127.0.0.1") && !line.contains("::1") && !line.contains("100.64."),
            "{name}: a router line names an address: {line}"
        );
    }
}

/// C43's later routers: `p` (its consent saved) started again on loopback
/// with no relay, its port mapping pointed at a new fake router in `mode`,
/// with the PORT_MAP gate open (`gate`) or closed.
fn c43_router(
    p: &Profile,
    mode: raven_core::portmap_fake::Mode,
    gate: bool,
) -> (fake_gw::Gateway, Service) {
    let gw = fake_gw::Gateway::start(std::net::Ipv4Addr::LOCALHOST.into(), mode)
        .expect("a UDP socket on 127.0.0.1");
    let gateway = gw.env();
    let env = port_map_env(&gateway, gate, false, &[]);
    let svc = p.start_service_p2p_opts(&P2pStart {
        listen: "127.0.0.1:0",
        relay_via: "",
        wait_reservation: false,
        env: &env,
    });
    (gw, svc)
}

/// C43 (P4.21; RAVEN_PORT_MAPPING_V1, the PORT_MAP gate's lab switch): B
/// asks a fake PCP router on loopback (`RAVEN_LAB_PORTMAP_GATEWAY`, 8 s
/// leases), which assigns one external port and reports 127.0.0.1, where
/// this test forwards that port (TCP and UDP) to B's listener. B logs
/// `router port mapped (PCP, port <ext> tcp+udp)`; the router saw an
/// ANNOUNCE before the first MAP, then a MAP for TCP and one for UDP, each
/// with a nonce of its own kept by every renewal, for client 127.0.0.1 and
/// B's port, and at least 2 renewals of each within 20 s. A (relay R, as in
/// C15, both allowed) sends to B: the first message is `relayed` (or
/// already `hole_punched`), and its link brings A B's route hints with the
/// mapped address as DIRECT. A restarts with R gone (no connection left to
/// ride, no relay to dial, as the netns hints run does): the next 2
/// messages are `direct` and the forwarder carries more than 2 KiB. The
/// router restarts (every mapping lost, epoch 0): `router restarted; port
/// mapped again` within 6 s. A lab network change re-homes B: the router
/// sees a fresh ANNOUNCE and MAPs within 15 s (the router was searched
/// again). B stops (SIGTERM; Unix): lifetime-0 deletes for both protocols
/// and no mapping left. Then the other routers: NAT-PMP only gives `router
/// port mapped (NAT-PMP`; a CGN address (100.64.0.9) `behind another NAT`,
/// the mappings deleted, and IPC `port_map` `behind_another_nat` with no
/// port. A silent router: `no PCP or NAT-PMP answer; UPnP not tried (lab
/// router)`, no MAP sent, never `trying UPnP` and IPC `port_map` `none`
/// (review E-2: while `RAVEN_LAB_PORTMAP_GATEWAY` names the router, UPnP's
/// search, which would reach the real one, never starts). The gate closed
/// with no lab router named (0 datagrams to the fake router, Phase 1's
/// UPnP line) starts a real UPnP search, so it runs only with
/// `RAVEN_HARNESS_UPNP_SEARCH=1` (CI). No log names a PeerId, and no router
/// line an address.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c43_pcp_and_natpmp_map_the_port_and_follow_router_and_network_changes() {
    use fake_gw::{is_announce, is_mapping, is_pcp_map, TCP, UDP};
    use raven_core::portmap_fake::Mode;
    use std::net::{Ipv4Addr, SocketAddr};
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let ext = free_loopback_tcp_udp_port();
    let gw = fake_gw::Gateway::start(Ipv4Addr::LOCALHOST.into(), Mode::AssignPort(ext))
        .expect("a UDP socket on 127.0.0.1");
    let relay = Relay::start(root.path());
    let via = relay.via.clone();
    let a = port_map_profile(root.path(), "ma");
    let b = port_map_profile(root.path(), "mb");
    node_setting(&b, &["upnp", "on"]);
    let a_card = a.p2p_card(&via);
    let b_card = b.p2p_card(&via);
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    let net = lab_network(root.path(), "mb");
    let net_path = net.to_string_lossy().into_owned();
    let gateway = gw.env();
    let b_env = port_map_env(
        &gateway,
        true,
        false,
        &[("RAVEN_LAB_NETWATCH_EVENTS", &net_path)],
    );
    // Stopped by SIGTERM at the end (Unix only).
    #[cfg_attr(not(unix), allow(unused_mut))]
    let (b_port, mut b_svc) = start_p2p_on_own_port(
        &b,
        &P2pStart {
            listen: "",
            relay_via: &via,
            wait_reservation: true,
            env: &b_env,
        },
    );
    let fwd = fake_gw::Forwarder::start(ext, SocketAddr::from((Ipv4Addr::LOCALHOST, b_port)));

    // ── PCP: mapped, one nonce per mapping, renewed ──────────────────────
    let both = format!("{MAPPED_PCP}{ext} tcp+udp)");
    let mapped_at = Instant::now();
    assert!(
        b_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l.contains(&both))
            .is_some(),
        "no {both:?}:\n{}",
        b_svc.log.text()
    );
    let renewed = wait_until(
        Duration::from_secs(20).saturating_sub(mapped_at.elapsed()),
        || {
            let log = gw.log();
            [TCP, UDP]
                .iter()
                .all(|p| log.iter().filter(|r| is_pcp_map(r, *p, false)).count() >= 3)
        },
    );
    let log = gw.log();
    assert!(
        renewed,
        "fewer than 2 renewals of each mapping within 20 s: {log:?}"
    );
    let first_map = log
        .iter()
        .position(|r| r.version == 2 && r.op == 1)
        .unwrap();
    assert!(
        log[..first_map].iter().any(is_announce),
        "no ANNOUNCE before the first MAP: {log:?}"
    );
    let mut nonces = Vec::new();
    for proto in [TCP, UDP] {
        let maps: Vec<_> = log.iter().filter(|r| is_pcp_map(r, proto, false)).collect();
        assert!(
            maps.iter().all(|r| r.nonce == maps[0].nonce
                && r.nonce.is_some()
                && r.client_ip == Some(Ipv4Addr::LOCALHOST.into())
                && r.internal_port == b_port),
            "{proto}: {maps:?}"
        );
        nonces.push(maps[0].nonce);
    }
    assert_ne!(nonces[0], nonces[1], "TCP and UDP share a nonce");
    let status = p2p_status(&b);
    assert_eq!(status["port_map"]["v4"], "pcp", "{status}");
    assert_eq!(status["port_map"]["v4_port"], u64::from(ext), "{status}");

    // ── A reaches B through the mapping ──────────────────────────────────
    let a_svc = a.start_service_p2p_opts(&P2pStart {
        listen: "127.0.0.1:0",
        relay_via: &via,
        wait_reservation: true,
        env: &[],
    });
    relay.wait_status(|s| s["counts"]["reservations"].as_u64() == Some(2));
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    let first = p2p_send(&a, "bob", "c43 one");
    assert!(
        first == "relayed" || first == "hole_punched",
        "{first}:\n{}",
        a_svc.log.text()
    );
    let mapped_tcp = format!("/ip4/127.0.0.1/tcp/{ext}");
    let learned = wait_until(LOG_TIMEOUT, || {
        learned_entry(&a, &b).is_some_and(|e| {
            learned_direct(&e)
                .iter()
                .any(|d| d == &mapped_tcp || d.starts_with(&format!("{mapped_tcp}/")))
        })
    });
    assert!(
        learned,
        "a never learned b's mapped address: {:?}",
        learned_entry(&a, &b)
    );
    drop(a_svc);
    drop(relay);
    let a_svc = a.start_service_p2p_opts(&P2pStart {
        listen: "127.0.0.1:0",
        relay_via: "",
        wait_reservation: false,
        env: &[],
    });
    // Its peer gate starts from the contact book (no reload line).
    let (tcp0, udp0) = fwd.bytes();
    for text in ["c43 two", "c43 three"] {
        assert_eq!(p2p_send(&a, "bob", text), "direct", "{}", a_svc.log.text());
    }
    let (tcp1, udp1) = fwd.bytes();
    assert!(
        (tcp1 - tcp0) + (udp1 - udp0) > 2048,
        "the forwarded port carried {} TCP and {} UDP bytes",
        tcp1 - tcp0,
        udp1 - udp0
    );
    for text in ["c43 one", "c43 two", "c43 three"] {
        assert_eq!(b.inbox().matches(text).count(), 1, "{text} exactly once");
    }

    // ── The router restarts; the network changes ─────────────────────────
    let restarts = b_svc.log.count(ROUTER_RESTARTED);
    gw.restart();
    assert!(
        wait_until(Duration::from_secs(6), || b_svc.log.count(ROUTER_RESTARTED)
            > restarts),
        "no {ROUTER_RESTARTED:?} within 6 s:\n{}",
        b_svc.log.text()
    );
    let mark = gw.log().len();
    let rehomed = b_svc.log.count(REHOMED);
    append(&net, "down 192.0.2.20/24\nup 198.51.100.8/24\n");
    let fresh = wait_until(Duration::from_secs(15), || {
        let log = gw.log();
        let Some(at) = log[mark..].iter().position(is_announce) else {
            return false;
        };
        let after = &log[mark + at..];
        [TCP, UDP]
            .iter()
            .all(|p| after.iter().any(|r| is_pcp_map(r, *p, false)))
    });
    assert!(
        fresh && b_svc.log.count(REHOMED) > rehomed,
        "no re-home with a fresh ANNOUNCE and MAPs within 15 s: {:?}\n{}",
        &gw.log()[mark..],
        b_svc.log.text()
    );

    // ── B stops: its mappings are deleted ────────────────────────────────
    #[cfg(unix)]
    {
        let mark = gw.log().len();
        assert!(
            b_svc.terminate(Duration::from_secs(20)),
            "b did not stop within 20 s"
        );
        let log = gw.log();
        for proto in [TCP, UDP] {
            assert!(
                log[mark..].iter().any(|r| is_pcp_map(r, proto, true)),
                "no lifetime-0 delete for {proto}: {:?}",
                &log[mark..]
            );
        }
        assert!(gw.with(|g| g.mappings.is_empty()), "a mapping is left");
    }
    assert_port_map_logs_clean("a", &a_svc.log.text());
    assert_port_map_logs_clean("b", &b_svc.log.text());
    drop(b_svc);
    drop(a_svc);
    drop(fwd);
    drop(gw);

    // ── NAT-PMP only ─────────────────────────────────────────────────────
    let (_gw, svc) = c43_router(&b, Mode::NatPmpOnly, true);
    assert!(
        svc.log
            .wait_for(LOG_TIMEOUT, |l| l.contains(MAPPED_NAT_PMP))
            .is_some(),
        "no {MAPPED_NAT_PMP:?}:\n{}",
        svc.log.text()
    );
    assert_port_map_logs_clean("b (NAT-PMP)", &svc.log.text());
    drop(svc);

    // ── A router behind carrier NAT ──────────────────────────────────────
    let cgn = Mode::ExternalIp(Ipv4Addr::new(100, 64, 0, 9).into());
    let (gw, svc) = c43_router(&b, cgn, true);
    assert!(
        svc.log
            .wait_for(LOG_TIMEOUT, |l| l.contains(BEHIND_CGN))
            .is_some(),
        "no {BEHIND_CGN:?}:\n{}",
        svc.log.text()
    );
    let deleted = wait_until(Duration::from_secs(10), || {
        let log = gw.log();
        let asked: Vec<u8> = [TCP, UDP]
            .into_iter()
            .filter(|p| log.iter().any(|r| is_pcp_map(r, *p, false)))
            .collect();
        !asked.is_empty()
            && asked
                .iter()
                .all(|p| log.iter().any(|r| is_pcp_map(r, *p, true)))
            && gw.with(|g| g.mappings.is_empty())
    });
    assert!(deleted, "the CGN mappings were not deleted: {:?}", gw.log());
    let status = p2p_status(&b);
    assert_eq!(status["port_map"]["v4"], "behind_another_nat", "{status}");
    assert_eq!(status["port_map"]["v4_port"], 0, "{status}");
    assert!(!svc.log.text().contains(MAPPED_PCP), "{}", svc.log.text());
    assert_port_map_logs_clean("b (CGN)", &svc.log.text());
    drop(svc);
    drop(gw);

    // ── A silent router: no UPnP while the lab names the router (E-2) ───
    let (gw, svc) = c43_router(&b, Mode::Silent, true);
    assert!(
        svc.log
            .wait_for(LOG_TIMEOUT, |l| l.contains(NO_UPNP_LAB))
            .is_some(),
        "no {NO_UPNP_LAB:?}:\n{}",
        svc.log.text()
    );
    let log = gw.log();
    assert!(
        !log.is_empty() && !log.iter().any(is_mapping),
        "probes only, no MAP: {log:?}"
    );
    assert_eq!(p2p_status(&b)["port_map"]["v4"], "none");
    let text = svc.log.text();
    assert!(!text.contains(TRYING_UPNP), "{text}");
    assert!(!text.contains("raven-node p2p: upnp "), "{text}");
    drop(svc);
    drop(gw);

    // ── The gate closed, no lab router named (a real UPnP search) ───────
    if upnp_search_allowed("C43's gate-closed control") {
        let gw = fake_gw::Gateway::start(Ipv4Addr::LOCALHOST.into(), Mode::Pcp)
            .expect("a UDP socket on 127.0.0.1");
        let svc = b.start_service_p2p_opts(&P2pStart {
            listen: "127.0.0.1:0",
            relay_via: "",
            wait_reservation: false,
            env: &[("RAVEN_LAB_PORTMAP_LIFETIME", "8")],
        });
        let upnp = svc.log.wait_for(Duration::from_secs(60), |l| {
            l.contains("raven-node p2p: upnp ")
        });
        assert!(upnp.is_some(), "no Phase 1 UPnP line:\n{}", svc.log.text());
        assert_eq!(gw.packets(), 0, "the closed gate asked the router");
        let text = svc.log.text();
        for phase4 in [
            MAPPED_PCP,
            TRYING_UPNP,
            NO_UPNP_LAB,
            NO_ROUTER,
            "router port mapping",
        ] {
            assert!(
                !text.contains(phase4),
                "{phase4:?} with the gate closed:\n{text}"
            );
        }
        assert!(
            p2p_status(&b)["port_map"].is_null(),
            "port_map with the gate closed"
        );
    }
}

/// C44 (P4.21; the V6_PINHOLE gate's lab switch): B listens on `[::1]`, and
/// a fake PCP firewall on `[::1]` is its only router (the IPv4 side finds
/// none). With `upnp` on and `ipv6-pinhole` unset nothing reaches the
/// router (IPC `port_map.v6` `not_asked`). With `raven node ipv6-pinhole
/// on` and a restart: `IPv6 pinhole open on the router (PCP)`, every
/// request a PCP one from `::1` for B's port, and `port_map.v6` `open`.
/// Skipped (and said) where the runner has no IPv6 loopback.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c44_pcp_ipv6_pinhole_needs_its_own_consent() {
    use fake_gw::is_announce;
    use raven_core::portmap_fake::Mode;
    use std::net::{IpAddr, Ipv6Addr};
    if !lab_ready() {
        return;
    }
    if !has_ipv6_loopback() {
        eprintln!("note: no IPv6 loopback on this runner; C44 skipped");
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let gw = fake_gw::Gateway::start(Ipv6Addr::LOCALHOST.into(), Mode::Ipv6Firewall)
        .expect("a UDP socket on [::1]");
    let gateway = gw.env();
    let b = port_map_profile(root.path(), "mv6");
    node_setting(&b, &["upnp", "on"]);
    let env = port_map_env(&gateway, true, true, &[]);
    let start = || {
        b.start_service_p2p_opts(&P2pStart {
            listen: "[::1]:0",
            relay_via: "",
            wait_reservation: false,
            env: &env,
        })
    };

    // No pinhole consent: nothing asked.
    let svc = start();
    assert!(
        svc.log
            .wait_for(LOG_TIMEOUT, |l| l.contains(NO_ROUTER))
            .is_some(),
        "the IPv4 side found a router:\n{}",
        svc.log.text()
    );
    // Past the probe's last retry (3.75 s): still nothing.
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(gw.packets(), 0, "asked without consent: {:?}", gw.log());
    assert_eq!(p2p_status(&b)["port_map"]["v6"], "not_asked");
    assert!(!svc.log.text().contains(PINHOLE_OPEN), "{}", svc.log.text());
    drop(svc);

    // Its own consent: the pinhole opens.
    node_setting(&b, &["ipv6-pinhole", "on"]);
    let svc = start();
    assert!(
        svc.log
            .wait_for(LOG_TIMEOUT, |l| l.contains(PINHOLE_OPEN))
            .is_some(),
        "no {PINHOLE_OPEN:?}:\n{}",
        svc.log.text()
    );
    let log = gw.log();
    let one = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert!(log.iter().any(is_announce), "{log:?}");
    assert!(
        log.iter()
            .all(|r| r.version == 2 && r.client_ip == Some(one)),
        "{log:?}"
    );
    let listens = p2p_status(&b)["listen_addrs"].clone();
    let ports: Vec<u16> = listens
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| {
            a.as_str()?
                .strip_prefix("/ip6/::1/")?
                .split('/')
                .nth(1)?
                .parse()
                .ok()
        })
        .collect();
    assert!(
        log.iter()
            .filter(|r| r.op == 1 && r.lifetime > 0)
            .all(|r| ports.contains(&r.internal_port)),
        "{log:?} {listens}"
    );
    assert_eq!(p2p_status(&b)["port_map"]["v6"], "open");
    assert_port_map_logs_clean("b (IPv6)", &svc.log.text());
}

// ── Phase 4: the hole-punch policy (P4.24, C45) ─────────────────────────────

/// The NAT_CLASS lab switch is needed only while its gate is closed.
fn nat_class_lab_unlock() -> bool {
    !raven_core::portmap_gate::NAT_CLASS_PRODUCTION_ENABLED
}

/// A profile for C45: the lab unlock, route hints, loopback candidates (C16)
/// and the NAT_CLASS lab, its class forced to `force` when given.
fn nat_class_profile(root: &Path, name: &'static str, force: Option<&str>) -> Profile {
    let mut p = Profile::create_with(root, name, true)
        .with_route_hints()
        .with_lab_env("RAVEN_LAB_P2P_LOCAL_CANDIDATES", "1");
    if nat_class_lab_unlock() {
        p = p.with_lab_env("RAVEN_LAB_NAT_CLASS", "1");
    }
    if let Some(class) = force {
        p = p.with_lab_env("RAVEN_LAB_NAT_CLASS_FORCE", class);
    }
    p
}

/// What one C45 round saw after the restart.
struct C45Round {
    /// The paths of messages 2 and 3.
    paths: Vec<String>,
    a_log: String,
    b_log: String,
    a_status: serde_json::Value,
}

const C45_SKIPPED: &str = "raven-node p2p: hole punch skipped (both";
const C45_UPGRADED: &str = "raven-node p2p: direct connection upgraded (dcutr)";
const C45_FAILED: &str = "raven-node p2p: hole punch failed";

/// A verbose `--carrier p2p` message from `p` to bob, delivered (else both
/// daemons' logs are shown): how it travelled.
fn c45_send(p: &Profile, text: &str, svcs: [&Service; 2]) -> String {
    let out = p.raven_with(
        &["send", "--contact", "@bob", "--carrier", "p2p"],
        Some(&format!("{text}\n")),
        &[("RAVEN_VERBOSE", "1")],
    );
    let all = out.all().to_lowercase();
    assert!(
        out.ok && all.contains("status") && all.contains("delivered"),
        "{text} was not delivered:\n{}\n--- a:\n{}\n--- b:\n{}",
        out.all(),
        svcs[0].log.text(),
        svcs[1].log.text()
    );
    send_path(&out)
}

/// One C45 round on the relay `via`: A (`a_force`) and B (`b_force`) learn
/// each other's NAT class from the RRH1 of a first message, then restart
/// (a fresh relayed connection, the classes loaded from route hints at the
/// gate's first read) and A sends two more messages; `wait_upgrade`: wait
/// up to 30 s for a hole punch between them.
fn c45_round(
    root: &Path,
    relay: &Relay,
    names: [&'static str; 2],
    forces: [Option<&str>; 2],
    wait_upgrade: bool,
) -> C45Round {
    // TCP: a stopped daemon's connections end at once (a QUIC one would
    // hold its reservation on R until it times out).
    let via = relay.via.clone();
    let a = nat_class_profile(root, names[0], forces[0]);
    let b = nat_class_profile(root, names[1], forces[1]);
    let a_card = a.p2p_card(&via);
    let b_card = b.p2p_card(&via);
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    let start = |p: &Profile| {
        p.start_service_p2p_opts(&P2pStart {
            listen: "127.0.0.1:0",
            relay_via: &via,
            wait_reservation: true,
            env: &[],
        })
    };
    // ── The first run: the RRH1 exchange ─────────────────────────────────
    let (a_svc, b_svc) = (start(&a), start(&b));
    for svc in [&a_svc, &b_svc] {
        assert!(
            svc.log.text().contains(
                "raven-node p2p: lab NAT mapping classes and hole-punch skips (debug build)"
            ),
            "{}",
            svc.log.text()
        );
    }
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    let first = c45_send(&a, &format!("c45 {} one", names[0]), [&a_svc, &b_svc]);
    assert!(first == "relayed" || first == "hole_punched", "{first}");
    let knows = |p: &Profile, other: &Profile| {
        learned_entry(p, other).is_some_and(|e| e["nat_class"].is_object())
    };
    assert!(
        wait_until(LOG_TIMEOUT, || knows(&a, &b) && knows(&b, &a)),
        "the NAT classes were not exchanged:\nA {:?}\nB {:?}\n{}\n{}",
        learned_entry(&a, &b),
        learned_entry(&b, &a),
        a_svc.log.text(),
        b_svc.log.text()
    );
    // (`mut` only where `terminate` exists: the Windows lint, P4.30.)
    #[cfg_attr(not(unix), allow(unused_mut))]
    for mut svc in [a_svc, b_svc] {
        // Closes its connections, so R frees the reservation at once.
        #[cfg(unix)]
        assert!(svc.terminate(Duration::from_secs(10)), "{}", svc.log.text());
        drop(svc);
    }
    // ── After the restart: a fresh relayed connection ────────────────────
    // (The peer gate and the contacts' NAT classes are read at the start.)
    let (a_svc, b_svc) = (start(&a), start(&b));
    let mut paths = vec![c45_send(
        &a,
        &format!("c45 {} two", names[0]),
        [&a_svc, &b_svc],
    )];
    if wait_upgrade {
        assert!(
            wait_until(Duration::from_secs(30), || {
                a_svc.log.count(C45_UPGRADED) + b_svc.log.count(C45_UPGRADED) > 0
            }),
            "no hole punch within 30 s:\n{}\n{}",
            a_svc.log.text(),
            b_svc.log.text()
        );
    } else {
        // Long enough for a hole punch to have started and ended.
        std::thread::sleep(Duration::from_secs(3));
    }
    paths.push(c45_send(
        &a,
        &format!("c45 {} three", names[0]),
        [&a_svc, &b_svc],
    ));
    for text in ["one", "two", "three"] {
        let text = format!("c45 {} {text}", names[0]);
        assert_eq!(b.inbox().matches(&text).count(), 1, "{text} exactly once");
    }
    let a_status = p2p_status(&a);
    let (a_log, b_log) = (a_svc.log.text(), b_svc.log.text());
    for log in [&a_log, &b_log] {
        assert!(!log.contains("12D3KooW"), "a log names a PeerId:\n{log}");
    }
    C45Round {
        paths,
        a_log,
        b_log,
        a_status,
    }
}

/// C45: hopeless hole punches are skipped and stay relayed (Phase 4 P4.24;
/// RAVEN_ROUTE_HINTS_V1 §13.1). See the module doc.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c45_hopeless_hole_punches_are_skipped_and_stay_relayed() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());

    // Both mappings vary: the punch is skipped on both sides.
    let r = c45_round(
        root.path(),
        &relay,
        ["va", "vb"],
        [Some("varies"), Some("varies")],
        false,
    );
    assert_eq!(r.paths, ["relayed", "relayed"], "{}\n{}", r.a_log, r.b_log);
    for (who, log) in [("a", &r.a_log), ("b", &r.b_log)] {
        assert!(log.contains(C45_SKIPPED), "{who} skipped nothing:\n{log}");
        assert!(!log.contains(C45_UPGRADED), "{who} upgraded:\n{log}");
        assert!(!log.contains(C45_FAILED), "{who} tried and failed:\n{log}");
    }
    let nat = &r.a_status["nat_mapping"];
    assert!(
        nat["punch_skipped"].as_u64().is_some_and(|n| n >= 1),
        "{}",
        r.a_status
    );
    assert_eq!(nat["tcp"], "varies", "{}", r.a_status);
    assert_eq!(nat["punch_failed"], 0, "{}", r.a_status);

    // Control: both stable_kept: hole-punched, as C16.
    let r = c45_round(
        root.path(),
        &relay,
        ["ka", "kb"],
        [Some("stable_kept"), Some("stable_kept")],
        true,
    );
    assert_eq!(r.paths[1], "hole_punched", "{}\n{}", r.a_log, r.b_log);
    for log in [&r.a_log, &r.b_log] {
        assert!(!log.contains("hole punch skipped"), "{log}");
    }

    // Varies on A only: B's class is not known to vary, so the punch is
    // attempted.
    let r = c45_round(
        root.path(),
        &relay,
        ["oa", "ob"],
        [Some("varies"), None],
        true,
    );
    for log in [&r.a_log, &r.b_log] {
        assert!(!log.contains("hole punch skipped"), "{log}");
    }
    assert_eq!(
        r.a_status["nat_mapping"]["punch_skipped"], 0,
        "{}",
        r.a_status
    );
}

// ── Phase 4: PeerId rotation (P4.28, C46) ────────────────────────────────────

/// The PeerId rotation lab switch is needed only while the Phase 4 flag is
/// off; it also needs the lab unlock (`RAVEN_LAB_TEST_A=1`).
fn rotation_lab_unlock() -> bool {
    !raven_core::portmap_gate::PEER_ROTATION_PRODUCTION_ENABLED
}

/// The lab epoch of C46, in seconds (`RAVEN_LAB_PEER_EPOCH_S`).
const C46_EPOCH_S: u64 = 30;

/// A profile for C46: the lab unlock, route hints and loopback candidates
/// (C15/C16); with `rotation` the PeerId rotation lab switch and a 30 s
/// epoch (C, which cannot follow, runs without it).
fn rotation_profile(root: &Path, name: &'static str, rotation: bool) -> Profile {
    let mut p = Profile::create_with(root, name, true)
        .with_route_hints()
        .with_lab_env("RAVEN_LAB_P2P_LOCAL_CANDIDATES", "1");
    if rotation {
        if rotation_lab_unlock() {
            p = p.with_lab_env("RAVEN_LAB_PEER_ROTATION", "1");
        }
        p = p.with_lab_env("RAVEN_LAB_PEER_EPOCH_S", &C46_EPOCH_S.to_string());
    }
    p
}

/// A verbose `--carrier p2p` message from `p` to `to`, which receives it
/// (at once, or from the sender's outbox within a minute: a re-home of the
/// receiver may be under way); else both daemons' logs are shown.
fn c46_send(p: &Profile, to: &Profile, text: &str, svcs: [&Service; 2]) {
    let out = p.raven_with(
        &["send", "--contact", "@bob", "--carrier", "p2p"],
        Some(&format!("{text}\n")),
        &[("RAVEN_VERBOSE", "1")],
    );
    let received = wait_until(Duration::from_secs(60), || to.inbox().contains(text));
    assert!(
        out.ok && received,
        "{text} was not delivered:\n{}\n--- a:\n{}\n--- b:\n{}",
        out.all(),
        svcs[0].log.text(),
        svcs[1].log.text()
    );
}

/// The PeerId schedule `p` stores for its one contact (sealed in a lab
/// profile), or `Null`.
fn stored_schedule(p: &Profile) -> serde_json::Value {
    let text = sealed_text(
        &p.dir,
        raven_core::peer_rotation::PEER_SCHEDULES_FILE,
        raven_core::at_rest::Kind::PeerSchedules,
    );
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.as_object()?.values().next().cloned())
        .unwrap_or_default()
}

/// C46: PeerId rotation follows contacts and relays (Phase 4 P4.28;
/// `RAVEN_P2P_PEER_ROTATION_V1.md` §9.1). See the module doc.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c46_peer_id_rotation_follows_contacts_and_relays() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let relay = Relay::start(root.path());
    let via = relay.via.clone();
    let a = rotation_profile(root.path(), "alice", true);
    let b = rotation_profile(root.path(), "bob", true);
    let c = rotation_profile(root.path(), "carol", false);
    let (a_card, b_card, c_card) = (a.p2p_card(&via), b.p2p_card(&via), c.p2p_card(&via));
    let fixed = card_peer(&b_card).to_string();
    relay.allow(&a, &a_card);
    relay.allow(&b, &b_card);
    // Bob turns rotation on and gives R his schedule (a relay that is not
    // his contact admits his coming PeerIds only from it).
    let on = b.raven(&["node", "p2p", "rotate", "on"], None);
    assert!(
        on.ok && on.stdout.contains("peer_rotation=on"),
        "{}",
        on.all()
    );
    let schedule = b.raven(&["relay", "schedule"], None);
    assert!(schedule.ok, "{}", schedule.all());
    let line = schedule.stdout.trim().to_string();
    let entries = raven_core::peer_rotation::parse_relay_schedule(&line).unwrap();
    assert_eq!(entries.len(), 7, "{line}");
    let installed = relay.cli(&b, &["relay", "allow", "--schedule", &line]);
    assert!(installed.ok, "{}", installed.all());

    let start = |p: &Profile| {
        p.start_service_p2p_opts(&P2pStart {
            listen: "127.0.0.1:0",
            relay_via: &via,
            wait_reservation: true,
            env: &[],
        })
    };
    let (a_svc, b_svc) = (start(&a), start(&b));
    assert!(
        b_svc
            .log
            .text()
            .contains("raven-node p2p: lab PeerId rotation (debug build)"),
        "{}",
        b_svc.log.text()
    );
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    b.add_card(&c_card, "carol", &c.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 2);

    // ── Waiting: Carol cannot follow ─────────────────────────────────────
    // The first message carries the RRH1 exchange: Alice says she can
    // follow, Carol never does.
    c46_send(&a, &b, "c46 one", [&a_svc, &b_svc]);
    let rotation_of = |p: &Profile| p2p_status(p)["rotation"].clone();
    assert!(
        wait_until(LOG_TIMEOUT, || {
            let r = rotation_of(&b);
            r["state"] == "waiting" && r["waiting_on"] == 1
        }),
        "Bob does not wait on Carol alone: {}\n{}",
        rotation_of(&b),
        b_svc.log.text()
    );
    let status = b.raven(&["status"], None);
    assert!(
        status.stdout.contains("waiting: 1 contact"),
        "{}",
        status.all()
    );
    assert_eq!(p2p_status(&b)["peer_id"], fixed.as_str(), "no rotation yet");
    assert_eq!(b_svc.log.count("network ID rotated"), 0);

    // ── Starting, then the first rotation ────────────────────────────────
    let removed = b.raven(&["contact", "remove", "--petname", "carol", "--yes"], None);
    assert!(removed.ok, "{}", removed.all());
    assert!(
        b_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l
                .contains("network ID rotation starts at the next epoch"))
            .is_some(),
        "{}",
        b_svc.log.text()
    );
    // Alice hears the coming PeerIds before the first switch. Bob's
    // announcer opens one link per contact at most every 60 s (raven-node
    // hints PER_PEER_MIN, after its 10 s settle), and his last one to Alice
    // may have just gone (P4.30: the 30 s wait failed once in a full run).
    let announce_paced = Duration::from_secs(60) + LOG_TIMEOUT;
    assert!(
        wait_until(announce_paced, || stored_schedule(&a)["entries"]
            .as_array()
            .is_some_and(|e| !e.is_empty())),
        "Alice never heard Bob's coming PeerIds:\n{}\n{}",
        a_svc.log.text(),
        b_svc.log.text()
    );
    let reservations = b_svc.log.count("raven-node p2p: reservation accepted");
    let boundary = Duration::from_secs(3 * C46_EPOCH_S);
    assert!(
        b_svc
            .log
            .wait_for(boundary, |l| l.contains(
                "raven-node p2p: network ID rotated (epoch boundary); re-homing"
            ))
            .is_some(),
        "no rotation within {boundary:?}:\n{}",
        b_svc.log.text()
    );
    assert!(
        wait_until(LOG_TIMEOUT, || b_svc
            .log
            .count("raven-node p2p: reservation accepted")
            > reservations),
        "no reservation under the new network ID:\n{}",
        b_svc.log.text()
    );
    let rotated = p2p_status(&b);
    assert_ne!(rotated["peer_id"], fixed.as_str(), "{rotated}");
    assert_eq!(rotated["rotation"]["state"], "on", "{rotated}");
    let epoch = rotated["rotation"]["epoch"].as_u64().unwrap();
    assert_eq!(
        rotated["peer_id"].as_str().unwrap(),
        entries
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, p)| p.as_str())
            .unwrap_or("not in the schedule R holds"),
    );
    // Alice hears that Bob rotates, then dials him under the scheduled
    // PeerId.
    assert!(
        wait_until(Duration::from_secs(60), || stored_schedule(&a)["rotating"]
            == true),
        "Alice never heard that Bob rotates:\n{}\n{}",
        a_svc.log.text(),
        b_svc.log.text()
    );
    c46_send(&a, &b, "c46 two", [&a_svc, &b_svc]);
    assert!(
        a_svc.log.text().contains("(peer_epoch=current)"),
        "{}",
        a_svc.log.text()
    );

    // ── R refuses the next PeerIds: postponed, and back ──────────────────
    // The epoch in use now, with time to spare before the next boundary (R
    // reads its list every 2 s): only the later PeerIds are denied.
    assert!(
        wait_until(boundary, || rotation_of(&b)["next_change_s"]
            .as_u64()
            .is_some_and(|s| s >= 10)),
        "{}",
        rotation_of(&b)
    );
    let epoch = rotation_of(&b)["epoch"].as_u64().unwrap();
    for (e, peer) in entries.iter().filter(|(e, _)| *e > epoch) {
        let denied = relay.cli(&b, &["relay", "deny", peer]);
        assert!(denied.ok, "deny epoch {e}: {}", denied.all());
    }
    assert!(
        b_svc
            .log
            .wait_for(boundary, |l| l.contains("network ID rotation postponed"))
            .is_some(),
        "no rollback within {boundary:?}:\n{}",
        b_svc.log.text()
    );
    assert!(
        b_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l.contains(
                "raven-node p2p: re-homed (network ID rotation postponed)"
            ))
            .is_some(),
        "{}",
        b_svc.log.text()
    );
    assert!(
        wait_until(LOG_TIMEOUT, || {
            let r = rotation_of(&b);
            r["state"] == "postponed" && r["epoch"] == epoch
        }),
        "{}\n{}",
        rotation_of(&b),
        b_svc.log.text()
    );
    assert!(
        wait_until(Duration::from_secs(60), || stored_schedule(&a)["postponed"]
            == true),
        "Alice never heard of the rollback:\n{}",
        b_svc.log.text()
    );
    c46_send(&a, &b, "c46 three", [&a_svc, &b_svc]);
    for text in ["c46 one", "c46 two", "c46 three"] {
        assert_eq!(b.inbox().matches(text).count(), 1, "{text} exactly once");
    }

    // No log names a PeerId.
    for (who, log) in [("alice", a_svc.log.text()), ("bob", b_svc.log.text())] {
        assert!(
            !log.contains("12D3KooW"),
            "{who}'s log names a PeerId:\n{log}"
        );
    }
}

// ── Phase 5: custody handoff, two friends in a row (P5.23) ────────────────

/// The worker's line for a FORWARD left with a friend (P5.21).
const LEFT_TO_PASS_ON: &str = "with a friend to pass on (";
/// Plain custody's and handoff's strike lines: a custodian that answers a
/// refusal gets neither.
const STRIKE_LINES: [&str; 2] = [
    "deposit links within an hour",
    "handoff links within an hour",
];

/// A profile of C54 and C55 (`root/name`, initialized): the Lab Test A
/// unlock, friend custody's timers (leave a message with a friend at once,
/// fetch every 500 ms), the handoff gate (`RAVEN_LAB_CUSTODY_HANDOFF=1`)
/// with the forwarder's 500 ms interval, and route hints (the friends ride
/// RRH1), for every process of it.
fn handoff_profile(root: &Path, name: &'static str, wan: bool) -> Profile {
    let mut p = Profile::new(root, name, true)
        .with_route_hints()
        .with_lab_env("RAVEN_LAB_CUSTODY_AFTER_MS", "0")
        .with_lab_env("RAVEN_LAB_CUSTODY_FETCH_MS", "500")
        .with_lab_env("RAVEN_LAB_CUSTODY_FORWARD_MS", "500")
        .with_lab_env("RAVEN_LAB_CUSTODY_HANDOFF", "1");
    if wan {
        p = p.with_lab_env("RAVEN_LAB_CUSTODY_WAN", "1");
    }
    p.init();
    p
}

/// Custody and custody handoff on at `f` (`raven node custody on --yes`,
/// then `raven node custody handoff on`).
fn handoff_on(f: &Profile) {
    let on = f.raven(&["node", "custody", "on", "--yes"], None);
    assert!(
        on.ok && on.stdout.contains("ok friend custody on"),
        "{} node custody on:\n{}",
        f.name,
        on.all()
    );
    let handoff = f.raven(&["node", "custody", "handoff", "on"], None);
    assert!(
        handoff.ok,
        "{} node custody handoff on:\n{}",
        f.name,
        handoff.all()
    );
}

/// `p` lists `custodians` for its contact `tag` (`raven contact set-addr
/// --tag T --custodian @C ...`).
fn list_custodians(p: &Profile, tag: &str, custodians: &[&str]) {
    let mut args = vec!["contact", "set-addr", "--tag", tag];
    for c in custodians {
        args.extend(["--custodian", c]);
    }
    let out = p.raven(&args, None);
    assert!(out.ok, "{} {args:?}:\n{}", p.name, out.all());
}

/// The handoff row of `raven node custody status` (P5.22): forward rows
/// waiting, handed on and refused, and registered tags; `None` when the
/// status shows no such row.
fn handoff_row(p: &Profile) -> Option<[u64; 4]> {
    let out = p.raven(&["node", "custody", "status"], None);
    let line = out.stdout.lines().find(|l| l.starts_with("handoff "))?;
    let after = |marker: &str| -> Option<u64> {
        line.split_once(marker)?
            .1
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    };
    Some([
        after("passing on: ")?,
        after("waiting, ")?,
        after("handed on, ")?,
        after("registered tags: ")?,
    ])
}

/// The sealed objects `p` holds as a custodian (`held N sealed
/// object(s)`), 0 when its status shows none.
fn objects_held(p: &Profile) -> u64 {
    let out = p.raven(&["node", "custody", "status"], None);
    out.stdout
        .split_once("held ")
        .and_then(|(_, rest)| rest.split(' ').next()?.parse().ok())
        .unwrap_or(0)
}

/// `p` learned from `other`'s route hints a custodian announced with
/// HANDOFF_INBOX (custodian flag bit 0).
fn announced_inbox(p: &Profile, other: &Profile) -> bool {
    learned_entry(p, other).is_some_and(|e| {
        e["custodian_tag_flags"]
            .as_array()
            .is_some_and(|flags| flags.iter().any(|f| f.as_u64().unwrap_or(0) & 1 == 1))
    })
}

/// Every file below a profile's data dir as (name, bytes); a sealed file
/// (RMS1) carries its plaintext too, opened with the profile's key.
fn profile_bytes(dir: &Path) -> Vec<(String, Vec<u8>)> {
    load_profile_key(dir);
    let keys = raven_core::at_rest::keys_cached(dir)
        .unwrap_or_else(|e| panic!("{}: the at-rest key: {e}", dir.display()));
    tree_files(dir)
        .into_iter()
        .filter_map(|(name, path)| {
            let mut bytes = std::fs::read(&path).ok()?;
            if raven_core::at_rest::is_sealed(&bytes) {
                let plain = raven_core::at_rest::Kind::ALL
                    .into_iter()
                    .find_map(|kind| raven_core::at_rest::open(&keys, kind, &bytes).ok());
                if let Some(plain) = plain {
                    bytes.extend_from_slice(&plain);
                }
            }
            Some((name, bytes))
        })
        .collect()
}

/// The files of `p` (its data dir, sealed ones opened, and its daemon logs)
/// that hold `far`'s public key (raw, or hex in either case) or `text`.
fn files_naming(p: &Profile, logs: &[&Service], far: &Profile, text: &str) -> Vec<String> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(&far.pub_hex, &mut key).unwrap();
    let hex_lower = far.pub_hex.to_lowercase();
    let mut files = profile_bytes(&p.dir);
    for (i, svc) in logs.iter().enumerate() {
        files.push((format!("daemon log {i}"), svc.log.text().into_bytes()));
    }
    files
        .into_iter()
        .filter(|(_, bytes)| {
            contains(bytes, &key)
                || contains(&bytes.to_ascii_lowercase(), hex_lower.as_bytes())
                || contains(bytes, text.as_bytes())
        })
        .map(|(name, _)| name)
        .collect()
}

/// No strike line in any of `logs`.
fn assert_no_strikes(logs: &[(&str, String)]) {
    for (name, text) in logs {
        for strike in STRIKE_LINES {
            assert!(
                !text.contains(strike),
                "{name} logged a strike ({strike}):\n{text}"
            );
        }
    }
}

/// C54 two-hop custody chain (Phase 5 P5.23; handoff design C20): four
/// daemons on loopback with the handoff lab (`handoff_profile`). Alice lists
/// Fred for Bob, Bob lists Gina for Alice; Fred and Gina turn custody and
/// handoff on and know each other, but Fred never pins Bob and Gina never
/// pins Alice. Alice and Bob pin the far friend by key only (no route): an
/// RRH1 custodian tag is pair-blinded, so Alice reads Bob's announced Gina
/// only as one of her own contacts. After a warm-up each registers its
/// session's tags at its own friend, and a message each way carries the
/// friend with HANDOFF_INBOX. Bob stops; Alice's `c54 two hops` is left
/// with Fred to pass on (held by 1 friend), Fred hands it on, Gina holds
/// it. Alice stops, Bob starts on his port and fetches it, exactly once;
/// his ACK goes the mirrored way (FORWARD at Gina, handed on to Fred). Bob
/// stops, Alice starts on a new port, fetches the ACK from Fred and her
/// outbox says delivered. Alice and Bob never run at the same time after
/// the setup. No file of Fred's (sealed ones opened) or his daemon log holds
/// Bob's key, none of Gina's holds Alice's, neither holds the text; the
/// scan finds the key each friend does hold. Logs are counts only and
/// nobody logged a strike.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c54_two_hop_custody_chain() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = handoff_profile(root.path(), "ha", false);
    let b = handoff_profile(root.path(), "hb", false);
    let f1 = handoff_profile(root.path(), "hf", false);
    let f2 = handoff_profile(root.path(), "hg", false);
    let f1_svc = f1.start_service();
    let f2_svc = f2.start_service();
    let a_svc = a.start_service();
    let b_listen = format!("127.0.0.1:{}", free_loopback_port());
    let b_svc = b.start_service_on(&b_listen, None);
    a.pin_contact(&b, "bob", Some(&b_svc.lan_dial));
    a.pin_contact(&f1, "fred", Some(&f1_svc.lan_dial));
    a.pin_contact(&f2, "gina", None);
    b.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    b.pin_contact(&f2, "gina", Some(&f2_svc.lan_dial));
    b.pin_contact(&f1, "fred", None);
    f1.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    f1.pin_contact(&f2, "gina", Some(&f2_svc.lan_dial));
    f2.pin_contact(&b, "bob", Some(&b_svc.lan_dial));
    f2.pin_contact(&f1, "fred", Some(&f1_svc.lan_dial));
    handoff_on(&f1);
    handoff_on(&f2);
    list_custodians(&a, "bob", &["@fred"]);
    list_custodians(&b, "alice", &["@gina"]);

    // ── the session, the tags at each friend, the announcements ─────────
    assert_delivered("a→b (warm-up)", &a.send("bob", "c54 warm-up"));
    assert!(
        wait_until(Duration::from_secs(60), || {
            handoff_row(&f2).is_some_and(|r| r[3] >= 1)
                && handoff_row(&f1).is_some_and(|r| r[3] >= 1)
        }),
        "no tags registered at the friends: {:?} {:?}\n{}\n---\n{}",
        handoff_row(&f1),
        handoff_row(&f2),
        a_svc.log.text(),
        b_svc.log.text()
    );
    let announced = (0..3).any(|i| {
        assert_delivered("b→a", &b.send("alice", &format!("c54 hello {i}")));
        assert_delivered("a→b", &a.send("bob", &format!("c54 hi {i}")));
        wait_until(Duration::from_secs(15), || {
            announced_inbox(&a, &b) && announced_inbox(&b, &a)
        })
    });
    assert!(
        announced,
        "no HANDOFF_INBOX announcement both ways:\n{:?}\n{:?}",
        learned_entry(&a, &b),
        learned_entry(&b, &a)
    );

    // ── Bob away: Fred takes it to pass on, Gina holds it ────────────────
    let b_log1 = b_svc.log.text();
    drop(b_svc);
    let text = "c54 two hops";
    let mid = custody_queued_send(&a, "bob", text);
    wait_held_by_a_friend(&a, &a_svc, 60);
    assert!(
        a_svc
            .log
            .wait_for(LOG_TIMEOUT, |l| l.contains(LEFT_TO_PASS_ON))
            .is_some(),
        "alice left nothing to pass on:\n{}",
        a_svc.log.text()
    );
    assert!(
        wait_until(Duration::from_secs(60), || {
            handoff_row(&f1).is_some_and(|r| r[1] >= 1) && objects_held(&f2) >= 1
        }),
        "fred did not hand it on to gina: {:?}, gina holds {}\n{}\n---\n{}",
        handoff_row(&f1),
        objects_held(&f2),
        f1_svc.log.text(),
        f2_svc.log.text()
    );

    // ── Alice away, Bob back: he fetches it, his ACK goes back ───────────
    let a_log1 = a_svc.log.text();
    drop(a_svc);
    let b_svc = b.start_service_on(&b_listen, None);
    assert!(
        wait_until(Duration::from_secs(60), || b.inbox().contains(text)),
        "bob never fetched it from gina:\n{}\n---\n{}",
        b_svc.log.text(),
        f2_svc.log.text()
    );
    assert!(
        wait_until(Duration::from_secs(90), || {
            handoff_row(&f2).is_some_and(|r| r[1] >= 1) && objects_held(&f1) >= 1
        }),
        "bob's ACK did not go back through gina to fred: {:?}, fred holds {}\n{}\n---\n{}",
        handoff_row(&f2),
        objects_held(&f1),
        b_svc.log.text(),
        f2_svc.log.text()
    );
    assert_eq!(b.inbox().matches(text).count(), 1, "exactly once on bob");
    let b_log2 = b_svc.log.text();
    drop(b_svc);

    // ── Bob away, Alice back on a new port: the ACK from Fred ────────────
    let a_svc = a.start_service();
    let acked = a_svc.log.wait_for(Duration::from_secs(60), |l| {
        l.contains("raven-node custody: fetched messages=") && !l.contains(" acks=0 ")
    });
    assert!(
        acked.is_some(),
        "alice fetched no ACK from fred:\n{}\n---\n{}",
        a_svc.log.text(),
        f1_svc.log.text()
    );
    assert!(
        wait_until(Duration::from_secs(60), || {
            let st = a.raven(&["outbox", "status", &mid], None);
            st.ok && st.stdout.contains("state       delivered")
        }),
        "alice's outbox never said delivered:\n{}",
        a_svc.log.text()
    );

    // ── privacy: neither friend learned the far end ───────────────────────
    let fred_names_bob = files_naming(&f1, &[&f1_svc], &b, text);
    let gina_names_alice = files_naming(&f2, &[&f2_svc], &a, text);
    assert!(
        fred_names_bob.is_empty() && gina_names_alice.is_empty(),
        "fred's files naming bob: {fred_names_bob:?}; gina's naming alice: {gina_names_alice:?}"
    );
    assert!(
        !files_naming(&f1, &[], &a, text).is_empty()
            && !files_naming(&f2, &[], &b, text).is_empty(),
        "the scan does not find the contact each friend does hold"
    );
    let logs = [
        ("alice", format!("{a_log1}\n{}", a_svc.log.text())),
        ("bob", format!("{b_log1}\n{b_log2}")),
        ("fred", f1_svc.log.text()),
        ("gina", f2_svc.log.text()),
    ];
    assert_custody_logs_counts_only(&logs);
    assert_no_strikes(&logs);
}

/// C55 handoff refusals (Phase 5 P5.23; handoff design C21): Alice
/// (`RAVEN_LAB_CUSTODY_WAN=1`) lists Fred and Gina for Bob; Bob lists Gina
/// (pinned by Alice, a mutual custodian) and announces her with
/// HANDOFF_INBOX, so Alice's plan is a FORWARD at Fred (next hop Gina) and a
/// plain DEPOSIT at Gina. Fred pins Alice, Bob and Gina; Alice reaches him
/// over Internet direct only. Bob stops.
/// (a) A closed link gate: Fred runs without WAN custody, so whatever Alice
/// sends him is answered HOLD. `c55 closed` is held by 1 friend (Gina's
/// plain deposit); Fred holds nothing and keeps no forward row.
/// (b) An old custodian: Alice and Fred start again (her parks are in
/// memory), Fred with WAN custody on and `RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1`,
/// so he answers the handoff ops UNSUPPORTED. `c55 old 1` is held by Gina;
/// handoff is parked at Fred only, so `c55 old 2` is left with him as a plain
/// deposit (custody there stays usable). Nobody logs a strike, Fred never
/// keeps a forward row or takes a tag registration (the handoff ops were
/// refused both times), and Bob, back, has each message exactly once.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c55_handoff_refusals() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = handoff_profile(root.path(), "oa", true);
    let b = handoff_profile(root.path(), "ob", false);
    let f1 = handoff_profile(root.path(), "of", false);
    let m = handoff_profile(root.path(), "og", false);
    let f1_svc = f1.start_service_with(Some("127.0.0.1:0"));
    let f1_inet = f1_svc.internet_dial.clone();
    let m_svc = m.start_service();
    let a_svc = a.start_service();
    let b_listen = format!("127.0.0.1:{}", free_loopback_port());
    let b_svc = b.start_service_on(&b_listen, None);
    a.pin_contact(&b, "bob", Some(&b_svc.lan_dial));
    a.pin_contact(&f1, "fred", None);
    let inet = a.raven(
        &["contact", "set-addr", "@fred", "--internet", &f1_inet],
        None,
    );
    assert!(inet.ok, "a contact set-addr fred:\n{}", inet.all());
    a.pin_contact(&m, "gina", Some(&m_svc.lan_dial));
    b.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    b.pin_contact(&m, "gina", Some(&m_svc.lan_dial));
    f1.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    f1.pin_contact(&b, "bob", Some(&b_svc.lan_dial));
    f1.pin_contact(&m, "gina", Some(&m_svc.lan_dial));
    m.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    m.pin_contact(&b, "bob", Some(&b_svc.lan_dial));
    m.pin_contact(&f1, "fred", Some(&f1_svc.lan_dial));
    handoff_on(&f1);
    handoff_on(&m);
    list_custodians(&a, "bob", &["@fred", "@gina"]);
    list_custodians(&b, "alice", &["@gina"]);

    assert_delivered("a→b (warm-up)", &a.send("bob", "c55 warm-up"));
    assert!(
        wait_until(Duration::from_secs(60), || handoff_row(&m)
            .is_some_and(|r| r[3] >= 1)),
        "bob registered no tags at gina: {:?}\n{}",
        handoff_row(&m),
        b_svc.log.text()
    );
    let announced = (0..3).any(|i| {
        assert_delivered("b→a", &b.send("alice", &format!("c55 hello {i}")));
        wait_until(Duration::from_secs(15), || announced_inbox(&a, &b))
    });
    assert!(announced, "{:?}", learned_entry(&a, &b));
    drop(b_svc);

    // ── (a) Fred's link gate closed: HOLD ────────────────────────────────
    custody_queued_send(&a, "bob", "c55 closed");
    wait_held_by_a_friend(&a, &a_svc, 60);
    // A few more passes, so whatever Alice tries at Fred has been answered.
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(objects_held(&f1), 0, "fred holds something");
    assert!(objects_held(&m) >= 1, "gina holds nothing");
    let closed = handoff_row(&f1);
    assert!(
        closed == Some([0, 0, 0, 0]),
        "fred keeps forward rows or took tags: {closed:?}"
    );
    let a_log1 = a_svc.log.text();
    assert!(
        !a_log1.contains(LEFT_TO_PASS_ON),
        "alice left something to pass on with a closed custodian:\n{a_log1}"
    );
    let f1_log1 = f1_svc.log.text();

    // ── (b) Fred an old custodian: UNSUPPORTED ───────────────────────────
    drop(a_svc);
    drop(f1_svc);
    let f1_svc = f1.start_service_env(
        "127.0.0.1:0",
        Some(&f1_inet),
        &[
            ("RAVEN_LAB_CUSTODY_WAN", "1"),
            ("RAVEN_LAB_CUSTODY_BASE_OPS_ONLY", "1"),
        ],
    );
    let a_svc = a.start_service();
    custody_queued_send(&a, "bob", "c55 old 1");
    assert!(
        wait_until(Duration::from_secs(60), || objects_held(&m) >= 2),
        "gina does not hold c55 old 1:\n{}",
        a_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(3));
    let mid = custody_queued_send(&a, "bob", "c55 old 2");
    let held = || {
        let st = a.raven(&["outbox", "status", &mid], None);
        st.stdout.contains("held by")
    };
    assert!(
        wait_until(Duration::from_secs(60), || held() && objects_held(&f1) >= 1),
        "fred took no plain deposit after his UNSUPPORTED (c55 old 2 held: {}):\n{}\n---\n{}",
        held(),
        a_svc.log.text(),
        f1_svc.log.text()
    );
    let old = handoff_row(&f1);
    assert!(
        old == Some([0, 0, 0, 0]),
        "fred keeps forward rows or took tags: {old:?}"
    );

    // ── Bob back: each message once ──────────────────────────────────────
    let b_svc = b.start_service_on(&b_listen, None);
    let texts = ["c55 closed", "c55 old 1", "c55 old 2"];
    assert!(
        wait_until(Duration::from_secs(90), || {
            let inbox = b.inbox();
            texts.iter().all(|t| inbox.contains(t))
        }),
        "bob is missing messages:\n{}\n---\n{}",
        b.inbox(),
        b_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(3));
    let inbox = b.inbox();
    for t in texts {
        assert_eq!(inbox.matches(t).count(), 1, "{t} exactly once:\n{inbox}");
    }
    let logs = [
        ("alice", format!("{a_log1}\n{}", a_svc.log.text())),
        ("bob", b_svc.log.text()),
        ("fred", format!("{f1_log1}\n{}", f1_svc.log.text())),
        ("gina", m_svc.log.text()),
    ];
    assert_custody_logs_counts_only(&logs);
    assert_no_strikes(&logs);
}

// ── Phase 5: Bluetooth nearby over the fake ether (P5.28) ───────────────────

/// The nearby carrier's lab switches: Lab Test A and nearby's own
/// (`NEARBY_PRODUCTION_ENABLED` is false).
fn nearby_lab_env(cmd: &mut Command) {
    cmd.env("RAVEN_LAB_TEST_A", "1")
        .env("RAVEN_LAB_NEARBY", "1");
}

/// A case's fake Bluetooth ether: `raven-node nearby-ether` (debug builds
/// with the nearby lab switch only) on a loopback port of its own, and its
/// control session: a radio's power switch, an armed fault, what went on
/// air and the knock HELLOs a radio observer captured. Killed when dropped.
struct EtherHub {
    child: Child,
    addr: String,
    ctl: std::net::TcpStream,
    reader: BufReader<std::net::TcpStream>,
}

impl EtherHub {
    fn start(extra: &[&str]) -> Self {
        let mut cmd = Command::new(NODE);
        nearby_lab_env(&mut cmd);
        cmd.args(["nearby-ether", "--listen", "127.0.0.1:0", "--print-port"])
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("spawn raven-node nearby-ether");
        let out = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(out).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx.recv_timeout(READY_TIMEOUT).unwrap_or_default();
        let port: u16 = line
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("nearby-ether printed no port: {line:?}"));
        let addr = format!("127.0.0.1:{port}");
        let mut ctl = std::net::TcpStream::connect(&addr).expect("connect to the ether hub");
        ctl.set_read_timeout(Some(COMMAND_TIMEOUT)).unwrap();
        ctl.write_all(b"{\"op\":\"control\"}\n").unwrap();
        let reader = BufReader::new(ctl.try_clone().unwrap());
        EtherHub {
            child,
            addr,
            ctl,
            reader,
        }
    }

    fn ask(&mut self, req: serde_json::Value) -> serde_json::Value {
        self.ctl.write_all(format!("{req}\n").as_bytes()).unwrap();
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("the hub answers");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("hub answer {line:?}: {e}"))
    }

    /// The Bluetooth switch of `svc`'s radio (named by its pid).
    fn power(&mut self, svc: &Service, on: bool) {
        let name = radio_name(svc);
        let got = self.ask(serde_json::json!({"op": "power", "name": name, "on": on}));
        assert_eq!(got["ev"], "ok", "{got}");
    }

    /// Every token that went on air: (radio, the advert as the hub records
    /// it).
    fn adverts(&mut self) -> Vec<(String, serde_json::Value)> {
        let got = self.ask(serde_json::json!({"op": "adverts"}));
        got["records"]
            .as_array()
            .unwrap_or_else(|| panic!("{got}"))
            .iter()
            .map(|r| {
                (
                    r["radio"].as_str().unwrap_or_default().to_string(),
                    r.clone(),
                )
            })
            .collect()
    }
}

impl Drop for EtherHub {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The name `svc`'s radio has on the ether.
fn radio_name(svc: &Service) -> String {
    format!("raven-node-{}", svc.child.id())
}

/// A new profile with the nearby lab switches on `ether` for every process
/// of it; `extra`: more lab switches.
fn nearby_profile(
    root: &Path,
    name: &'static str,
    ether: &EtherHub,
    extra: &[(&'static str, &str)],
) -> Profile {
    let mut p = Profile::new(root, name, true)
        .with_lab_env("RAVEN_LAB_NEARBY", "1")
        .with_lab_env("RAVEN_LAB_NEARBY_ETHER", &ether.addr);
    for (k, v) in extra {
        p = p.with_lab_env(k, v);
    }
    p.init();
    p
}

/// `p`'s `raven nearby status`.
fn nearby_status(p: &Profile) -> String {
    let out = p.raven(&["nearby", "status"], None);
    assert!(out.ok, "{} nearby status:\n{}", p.name, out.all());
    out.stdout
}

/// The `bluetooth` row says the radio is on (the engine runs).
fn radio_on(p: &Profile) -> bool {
    nearby_status(p).lines().any(|l| {
        let mut w = l.split_whitespace();
        w.next() == Some("bluetooth") && w.next() == Some("on")
    })
}

/// Pipes up now (`N connected` in the `in range` row).
fn pipes_up(p: &Profile) -> u32 {
    nearby_status(p)
        .lines()
        .find_map(|l| {
            let (_, rest) = l.split_once(" in range now, ")?;
            rest.split_whitespace().next()?.parse().ok()
        })
        .unwrap_or(0)
}

/// `raven nearby enable` on each, then each radio on.
fn nearby_enable(people: &[&Profile]) {
    for p in people {
        let out = p.raven(&["nearby", "enable"], None);
        assert!(
            out.ok && out.stdout.contains("ok nearby=on"),
            "{} nearby enable:\n{}",
            p.name,
            out.all()
        );
    }
    for p in people {
        assert!(
            wait_until(LOG_TIMEOUT, || radio_on(p)),
            "{}'s radio did not come on:\n{}",
            p.name,
            nearby_status(p)
        );
    }
}

/// The people meet once on the LAN (pinned to each other by their LAN
/// address, one message each way: a session, and each other's device
/// certificate, which nearby admits a contact by: RNL1 §0), then every
/// saved LAN address becomes a dead loopback port; `enable`: then `raven
/// nearby enable` on each. Nothing else is on (no Internet direct, p2p or
/// LAN beacon), so the ether is the only path. Each pins the others under
/// their profile name.
fn nearby_meet(people: &[(&Profile, &Service)], enable: bool) {
    for (p, _) in people {
        for (q, q_svc) in people {
            if p.name != q.name {
                p.pin_contact(q, q.name, Some(&q_svc.lan_dial));
            }
        }
    }
    for (p, _) in people {
        for (q, _) in people {
            if p.name != q.name {
                assert_delivered(
                    &format!("{} to {} on the LAN", p.name, q.name),
                    &p.send(q.name, &format!("meet {} {}", p.name, q.name)),
                );
            }
        }
    }
    for (p, _) in people {
        for (q, _) in people {
            if p.name != q.name {
                let dead = format!("127.0.0.1:{}", free_loopback_port());
                let set = p.raven(
                    &[
                        "contact",
                        "set-addr",
                        &format!("@{}", q.name),
                        "--lan",
                        &dead,
                    ],
                    None,
                );
                assert!(set.ok, "{}", set.all());
            }
        }
    }
    if enable {
        let all: Vec<&Profile> = people.iter().map(|(p, _)| *p).collect();
        nearby_enable(&all);
    }
}

/// `p` sends `text` to `tag` and it is delivered within `within`: at once
/// over a pipe that was up, or queued and then delivered by raven-node's
/// outbox over nearby (`carrier nearby_dial`, the history delivered).
/// Returns `now` or `outbox`.
fn nearby_delivered(p: &Profile, tag: &str, text: &str, within: Duration) -> &'static str {
    let out = p.raven_with(
        &["send", "--contact", &format!("@{tag}")],
        Some(&format!("{text}\n")),
        &[("RAVEN_VERBOSE", "1")],
    );
    let all = out.all();
    if out.ok && all.contains("status delivered") {
        assert!(all.contains("carrier=nearby_dial"), "{all}");
        return "now";
    }
    assert!(
        all.contains("raven-node keeps trying in the background until"),
        "{} send of {text:?} neither delivered nor queued:\n{all}",
        p.name
    );
    let mid = queued_mid(&out);
    let deadline = Instant::now() + within;
    loop {
        let st = p.raven(&["outbox", "status", &mid], None);
        if st.ok && st.stdout.contains("state       delivered") {
            assert!(
                st.stdout.contains("carrier     nearby_dial"),
                "{}",
                st.all()
            );
            assert!(st.stdout.contains("history     delivered"), "{}", st.all());
            return "outbox";
        }
        assert!(
            Instant::now() < deadline,
            "{text:?} not delivered within {within:?}:\n{}",
            st.all()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// A token's bytes with the UUID v4 version and variant bits cleared (RNL1
/// §2: every token sets them).
fn token_bytes(hex_uuid: &str) -> [u8; 16] {
    let mut t = [0u8; 16];
    hex::decode_to_slice(hex_uuid, &mut t).unwrap_or_else(|_| panic!("uuid {hex_uuid:?}"));
    assert_eq!(t[6] >> 4, 4, "v4 bits: {hex_uuid}");
    assert_eq!(t[8] & 0xc0, 0x80, "variant bits: {hex_uuid}");
    t
}

/// No byte (past the v4 bits) is the same in every one of `tokens` (at
/// least 3): adverts carry no constant a radio observer could match.
fn assert_no_constant_bytes(tokens: &[[u8; 16]]) {
    assert!(tokens.len() >= 3, "{} tokens", tokens.len());
    for i in 0..16 {
        let mask = match i {
            6 => 0x0f,
            8 => 0x3f,
            _ => 0xff,
        };
        let first = tokens[0][i] & mask;
        assert!(
            tokens.iter().any(|t| t[i] & mask != first),
            "byte {i} is the same in every advert"
        );
    }
}

/// A lab wall clock for every process of a profile (`RAVEN_LAB_CLOCK_FILE`):
/// the signed offset from the system clock in ms (cutoff pack CP.3).
struct LabClockFile(PathBuf);

impl LabClockFile {
    fn new(root: &Path, name: &str) -> Self {
        let clock = LabClockFile(root.join(name));
        clock.set(0);
        clock
    }

    fn set(&self, ms: i64) {
        let tmp = self.0.with_extension("tmp");
        std::fs::write(&tmp, format!("{ms}\n")).unwrap();
        std::fs::rename(&tmp, &self.0).unwrap();
    }
}

/// C50: Alice and Bob met once on the LAN; their saved LAN addresses are
/// dead now and nothing else is on, so the fake ether is the only path
/// (design step 5.7). `raven nearby enable` on both; Alice sends 3 and Bob
/// 3 back: each delivered with its sealed receipt over nearby (`carrier
/// nearby_dial`, or `carrier=nearby_dial` when a pipe was already up), each
/// exactly once, and each `raven status` says the last delivery went over
/// Bluetooth nearby.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c50_nearby_both_ways_with_no_network_path() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let ether = EtherHub::start(&[]);
    let a = nearby_profile(root.path(), "a50", &ether, &[]);
    let b = nearby_profile(root.path(), "b50", &ether, &[]);
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    nearby_meet(&[(&a, &a_svc), (&b, &b_svc)], true);
    let mut how = Vec::new();
    for i in 1..=3 {
        how.push(nearby_delivered(
            &a,
            "b50",
            &format!("c50 a to b {i}"),
            Duration::from_secs(90),
        ));
    }
    for i in 1..=3 {
        how.push(nearby_delivered(
            &b,
            "a50",
            &format!("c50 b to a {i}"),
            Duration::from_secs(90),
        ));
    }
    eprintln!("c50: {how:?}");
    for i in 1..=3 {
        let to_b = format!("c50 a to b {i}");
        let to_a = format!("c50 b to a {i}");
        assert_eq!(b.inbox().matches(&to_b).count(), 1, "{to_b} exactly once");
        assert_eq!(a.inbox().matches(&to_a).count(), 1, "{to_a} exactly once");
    }
    for (p, svc) in [(&a, &a_svc), (&b, &b_svc)] {
        let status = p.raven(&["status"], None);
        assert!(
            status.stdout.contains("Bluetooth nearby"),
            "{} status:\n{}",
            p.name,
            status.all()
        );
        assert!(
            svc.log.count("(nearby_dial") + usize::from(how.contains(&"now")) >= 1,
            "{}",
            svc.log.text()
        );
        assert!(!svc.log.text().contains("ether-"), "{}", svc.log.text());
    }
}

/// C51: a stranger in radio range learns nothing (RNL1 §5). Bob's radio is
/// off while Alice has a message for him, so she advertises a token only
/// Bob can recognise. S, a raw radio on the ether with no pair key, sees
/// the advert, connects to its service and writes random HELLOs: Alice
/// stays silent (S receives 0 frames). Bob comes back and his knock is
/// answered (the message is delivered); a radio observer captured his HELLO,
/// and S writes it again on a new connection: a replay, again silence. No
/// "nearby inbound" line comes from S's attempts in Alice's log.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c51_stranger_in_radio_range_learns_nothing() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let mut ether = EtherHub::start(&[]);
    let a = nearby_profile(root.path(), "a51", &ether, &[]);
    let b = nearby_profile(root.path(), "b51", &ether, &[]);
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    nearby_meet(&[(&a, &a_svc), (&b, &b_svc)], true);
    ether.power(&b_svc, false);
    let queued = a.send("b51", "c51 for bob");
    assert!(!queued.ok, "{}", queued.all());

    let mut s = RawRadio::join(&ether.addr, "stranger");
    s.put(serde_json::json!({"op": "scan", "on": true}));
    let seen = s
        .wait(LOG_TIMEOUT, |ev| ev["ev"] == "seen")
        .unwrap_or_else(|| panic!("the stranger saw no advert:\n{}", a_svc.log.text()));
    let (at, service) = (
        seen["addr"].as_str().unwrap().to_string(),
        seen["uuids"][0].as_str().unwrap().to_string(),
    );
    s.put(serde_json::json!({"op": "scan", "on": false}));
    s.put(serde_json::json!({"op": "connect", "conn": 1, "addr": at, "service": service}));
    let up = s
        .wait(LOG_TIMEOUT, |ev| {
            ev["ev"] == "connected" || ev["ev"] == "down"
        })
        .unwrap();
    assert_eq!(up["ev"], "connected", "{up}");
    let mut random = Vec::new();
    for _ in 0..2 {
        let mut hello = vec![0x01, 0x01, 0x00];
        hello.extend((0..32).map(|_| rand_byte()));
        s.send(1, &hello);
        random.push(hello);
    }
    // A knock gets an answer within its 5 s deadline, or never.
    let _ = s.wait(Duration::from_secs(7), |ev| ev["ev"] == "frame");
    assert_eq!(s.frames, 0, "the stranger got frames for random HELLOs");
    assert_eq!(a_svc.log.count("nearby inbound"), 0, "{}", a_svc.log.text());

    ether.power(&b_svc, true);
    assert!(
        wait_until(Duration::from_secs(90), || b
            .inbox()
            .contains("c51 for bob")),
        "{}\n{}",
        a_svc.log.text(),
        b_svc.log.text()
    );
    // Bob's knock, as a radio observer captured it (not the stranger's).
    let hellos = ether.ask(serde_json::json!({"op": "hellos"}));
    let captured = hellos["hellos"]
        .as_array()
        .and_then(|h| {
            h.iter()
                .rev()
                .find(|c| !random.contains(&base64_decode(c["b64"].as_str().unwrap())))
                .cloned()
        })
        .unwrap_or_else(|| panic!("no knock of Bob's captured: {hellos}"));
    assert!(pipes_up(&a) >= 1, "{}", nearby_status(&a));
    let inbound_before = a_svc.log.count("nearby inbound");
    let replay = base64_decode(captured["b64"].as_str().unwrap());
    s.put(serde_json::json!({
        "op": "connect", "conn": 3, "addr": at, "service": captured["service"]
    }));
    let up = s
        .wait(LOG_TIMEOUT, |ev| {
            ev["conn"] == 3 && (ev["ev"] == "connected" || ev["ev"] == "down")
        })
        .unwrap();
    assert_eq!(
        up["ev"], "connected",
        "the replay reaches Alice's service: {up}"
    );
    s.send(3, &replay);
    let _ = s.wait(Duration::from_secs(7), |ev| ev["ev"] == "frame");
    assert_eq!(s.frames, 0, "the stranger got frames for a replayed HELLO");
    assert_eq!(
        a_svc.log.count("nearby inbound"),
        inbound_before,
        "{}",
        a_svc.log.text()
    );
    assert_eq!(b.inbox().matches("c51 for bob").count(), 1);
}

/// One byte from the OS clock's low bits mixed with a counter: enough for a
/// HELLO no key made (the test needs noise, not secrecy).
fn rand_byte() -> u8 {
    static N: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let n = N.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    ((n ^ t.rotate_left(17)).wrapping_mul(0xff51_afd7_ed55_8ccd) >> 56) as u8
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_else(|e| panic!("base64 {s:?}: {e}"))
}

/// A raw radio on the ether hub (a stranger's, with no Raven key): the
/// hub's line protocol spoken directly, counting every frame it receives.
struct RawRadio {
    w: std::net::TcpStream,
    lines: std::sync::mpsc::Receiver<serde_json::Value>,
    frames: usize,
}

impl RawRadio {
    fn join(hub: &str, name: &str) -> Self {
        let mut w = std::net::TcpStream::connect(hub).expect("connect to the hub");
        w.write_all(format!("{}\n", serde_json::json!({"op": "hello", "name": name})).as_bytes())
            .unwrap();
        let r = w.try_clone().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(r).lines() {
                let Ok(line) = line else { break };
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    if tx.send(v).is_err() {
                        break;
                    }
                }
            }
        });
        RawRadio {
            w,
            lines,
            frames: 0,
        }
    }

    fn put(&mut self, m: serde_json::Value) {
        self.w.write_all(format!("{m}\n").as_bytes()).unwrap();
    }

    fn send(&mut self, conn: u64, frame: &[u8]) {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(frame);
        self.put(serde_json::json!({"op": "send", "conn": conn, "b64": b64}));
    }

    /// The first event `pred` takes within `timeout` (frames counted on the
    /// way).
    fn wait(
        &mut self,
        timeout: Duration,
        pred: impl Fn(&serde_json::Value) -> bool,
    ) -> Option<serde_json::Value> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let ev = self.lines.recv_timeout(left).ok()?;
            if ev["ev"] == "frame" {
                self.frames += 1;
            }
            if pred(&ev) {
                return Some(ev);
            }
        }
    }
}

/// C52: adverts rotate and carry no constant (RNL1 §2-§3). Alice, Bob,
/// Dave and Carol on one lab clock; Bob's and Dave's radios are off, so
/// nobody connects to what Alice advertises. Alice has a message waiting
/// for Carol, a contact she never verified (no pair key, so never on air:
/// `raven nearby on @carol` is refused too). Epochs 0-1 (the lab clock
/// moved 15 min each time): Alice advertises for Bob alone (`raven nearby
/// on`): exactly one token per epoch, a new one each epoch. Epochs 2-3:
/// for Dave too: exactly two tokens per epoch (at most 2 contacts rotate),
/// Dave's never Bob's. Every advert is exactly one UUID with the v4 bits
/// and nothing else (no name, no manufacturer data), every token is new,
/// each token's characteristic UUID differs, and no byte is the same in
/// every advert.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c52_adverts_rotate_and_carry_no_constant() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let mut ether = EtherHub::start(&[]);
    let clock = LabClockFile::new(root.path(), "lab52.clock");
    let clock_env = [("RAVEN_LAB_CLOCK_FILE", clock.0.to_str().unwrap())];
    let a = nearby_profile(root.path(), "a52", &ether, &clock_env);
    let b = nearby_profile(root.path(), "b52", &ether, &clock_env);
    let d = nearby_profile(root.path(), "d52", &ether, &clock_env);
    let c = nearby_profile(root.path(), "c52", &ether, &clock_env);
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    let d_svc = d.start_service();
    let c_svc = c.start_service();
    nearby_meet(&[(&a, &a_svc), (&b, &b_svc), (&d, &d_svc)], false);
    // Carol: a contact of Alice's she never verified, met on the LAN.
    a.add_contact(&c, "c52", &c_svc.lan_dial);
    c.pin_contact(&a, "a52", Some(&a_svc.lan_dial));
    assert_delivered("a to carol on the LAN", &a.send("c52", "c52 meet"));
    let dead = format!("127.0.0.1:{}", free_loopback_port());
    assert!(
        a.raven(&["contact", "set-addr", "@c52", "--lan", &dead], None)
            .ok
    );
    nearby_enable(&[&a, &b, &d, &c]);
    ether.power(&b_svc, false);
    ether.power(&d_svc, false);
    let refused = a.raven(&["nearby", "on", "@c52"], None);
    assert!(
        !refused.ok && refused.all().contains("not verified"),
        "{}",
        refused.all()
    );
    assert!(!a.send("c52", "c52 waits").ok);
    assert!(a.raven(&["nearby", "on", "@b52"], None).ok);

    let a_radio = radio_name(&a_svc);
    let mut seen = 0usize;
    let mut tokens_of = |ether: &mut EtherHub| -> Vec<String> {
        let records = ether.adverts();
        let new: Vec<String> = records[seen..]
            .iter()
            .filter(|(radio, _)| *radio == a_radio)
            .map(|(_, r)| r["uuids"][0].as_str().unwrap().to_string())
            .collect();
        seen = records.len();
        new
    };
    let mut per_epoch: Vec<Vec<String>> = Vec::new();
    for epoch in 0..4i64 {
        let want = if epoch < 2 { 1 } else { 2 };
        clock.set(epoch * 15 * 60_000);
        let mut fresh: Vec<String> = Vec::new();
        let mut gather = |fresh: &mut Vec<String>, ether: &mut EtherHub| {
            for t in tokens_of(ether) {
                if !per_epoch.iter().flatten().any(|p| *p == t) && !fresh.contains(&t) {
                    fresh.push(t);
                }
            }
        };
        for need in 1..=want {
            if need == 2 {
                // Dave joins once Alice is in this epoch (her new token for
                // Bob is on air), so his token is this epoch's too.
                assert!(a.raven(&["nearby", "on", "@d52"], None).ok);
            }
            assert!(
                wait_until(LOG_TIMEOUT, || {
                    gather(&mut fresh, &mut ether);
                    fresh.len() >= need
                }),
                "epoch {epoch}: Alice's new tokens {fresh:?}:\n{}",
                a_svc.log.text()
            );
        }
        // Three more 5 s slots of the same epoch: nothing else goes on air.
        std::thread::sleep(Duration::from_secs(16));
        gather(&mut fresh, &mut ether);
        assert_eq!(fresh.len(), want, "epoch {epoch}: Alice's tokens {fresh:?}");
        per_epoch.push(fresh);
    }
    for (_, r) in ether.adverts() {
        let keys: Vec<&str> = r.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["radio", "uuids"],
            "an advert holds only its UUID: {r}"
        );
        assert_eq!(r["uuids"].as_array().unwrap().len(), 1, "{r}");
    }
    let tokens: Vec<String> = per_epoch.into_iter().flatten().collect();
    assert_eq!(tokens.len(), 6, "{tokens:?}");
    let mut chars = std::collections::HashSet::new();
    let mut all = Vec::new();
    for t in &tokens {
        let bytes = token_bytes(t);
        let ch = raven_core::nearby_link::char_uuid(&bytes);
        assert_ne!(ch, bytes);
        assert!(chars.insert(ch), "a characteristic UUID twice");
        all.push(bytes);
    }
    assert_no_constant_bytes(&all);
    assert_eq!(c.inbox().matches("c52 waits").count(), 0);
}

/// C53: the radio drops one frame in the middle of a 48 KB message (RNP1
/// §6: the gap resets the pipe; the hub loses the 41st frame after it is
/// armed). The first try fails, raven-node's outbox tries again over a new
/// pipe, and the message is delivered exactly once; Bob's receipt for a
/// copy he already had is the same (idempotent), and his reply comes back.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c53_nearby_drop_mid_message_then_retry() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let mut ether = EtherHub::start(&[]);
    let a = nearby_profile(root.path(), "a53", &ether, &[]);
    let b = nearby_profile(root.path(), "b53", &ether, &[]);
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    nearby_meet(&[(&a, &a_svc), (&b, &b_svc)], true);
    nearby_delivered(&a, "b53", "c53 warm", Duration::from_secs(90));
    let armed = ether.ask(serde_json::json!({"op": "fault", "drop_after": 40}));
    assert_eq!(armed["ev"], "ok", "{armed}");
    let big = format!("c53 big {}", "y".repeat(48 * 1024 - 64));
    let how = nearby_delivered(&a, "b53", &big, Duration::from_secs(120));
    let stats = ether.ask(serde_json::json!({"op": "stats"}));
    assert_eq!(stats["dropped"], true, "the frame was lost: {stats}");
    assert_eq!(
        b.inbox().matches("c53 big").count(),
        1,
        "exactly once ({how})"
    );
    nearby_delivered(&b, "a53", "c53 reply", Duration::from_secs(90));
    assert_eq!(a.inbox().matches("c53 reply").count(), 1);
    assert_eq!(
        b.inbox().matches("c53 big").count(),
        1,
        "still exactly once"
    );
    let list = a.raven(&["outbox", "list"], None);
    assert!(list.stdout.contains("Nothing waiting"), "{}", list.all());
    drop(b_svc);
}

/// C56 (the cutoff study's C44, Bluetooth only): an island with no network
/// at all. Alice and Bob met once on the LAN; now their LAN addresses are
/// dead, netwatch says there is no route out (`egress none`), and only the
/// fake ether is up. Every process counts its name lookups and outbound
/// connects (`RAVEN_LAB_NET_AUDIT`).
/// - A message each way, each with its receipt, over nearby.
/// - 25 h later (one lab clock, the long message horizon on) their session
///   has ended: Alice's message waits (parked) and raven-node sets up a new
///   session over nearby; it arrives exactly once.
/// - Zero name lookups and zero connects beyond this computer, by every
///   ash and raven-node of both; the adverts hold no constant bytes.
/// - Variant (cutoff addendum F11d): the radios meet after the user's work
///   ran out (`RAVEN_LAB_NEARBY_FOREGROUND_MS`): with nearby background
///   mail off, no delivery (nobody advertises: the gap the study found);
///   with it on, the waiting message arrives.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c56_bluetooth_only_island() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let mut ether = EtherHub::start(&[]);
    let clock = LabClockFile::new(root.path(), "lab56.clock");
    let island = |name: &str| {
        let net = root.path().join(format!("{name}-net.txt"));
        std::fs::write(&net, "up 192.0.2.56/24\negress none\n").unwrap();
        let audit = root.path().join(format!("{name}-audit.txt"));
        (net, audit)
    };
    let (a_net, a_audit) = island("a56");
    let (b_net, b_audit) = island("b56");
    let env = |net: &Path, audit: &Path| -> Vec<(&'static str, String)> {
        vec![
            (
                "RAVEN_LAB_CLOCK_FILE",
                clock.0.to_str().unwrap().to_string(),
            ),
            ("RAVEN_LAB_HORIZON", "1".to_string()),
            (
                "RAVEN_LAB_NETWATCH_EVENTS",
                net.to_str().unwrap().to_string(),
            ),
            ("RAVEN_LAB_NET_AUDIT", audit.to_str().unwrap().to_string()),
        ]
    };
    let (a_env, b_env) = (env(&a_net, &a_audit), env(&b_net, &b_audit));
    let a_ref: Vec<(&'static str, &str)> = a_env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let b_ref: Vec<(&'static str, &str)> = b_env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let a = nearby_profile(root.path(), "a56", &ether, &a_ref);
    let b = nearby_profile(root.path(), "b56", &ether, &b_ref);
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    nearby_meet(&[(&a, &a_svc), (&b, &b_svc)], true);
    // The LAN meeting dialled loopback only; from here on, nothing at all.
    let audit = |path: &Path| std::fs::read_to_string(path).unwrap_or_default();
    let before = (audit(&a_audit), audit(&b_audit));
    for text in [&before.0, &before.1] {
        assert!(
            !text.contains("dns") && !text.contains("connect_other"),
            "{text}"
        );
    }
    nearby_delivered(&a, "b56", "c56 island a to b", Duration::from_secs(90));
    nearby_delivered(&b, "a56", "c56 island b to a", Duration::from_secs(90));

    // 25 h on: the session ends while they are apart.
    drop(a_svc);
    drop(b_svc);
    clock.set(25 * 3_600_000);
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    for p in [&a, &b] {
        assert!(
            wait_until(LOG_TIMEOUT, || radio_on(p)),
            "{}",
            nearby_status(p)
        );
    }
    let parked = a.send("b56", "c56 a day later");
    assert!(!parked.ok, "{}", parked.all());
    assert!(
        wait_until(Duration::from_secs(150), || b
            .inbox()
            .contains("c56 a day later")),
        "not re-paired over nearby:\n{}\n{}",
        a_svc.log.text(),
        b_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(b.inbox().matches("c56 a day later").count(), 1);
    let (a_seen, b_seen) = (audit(&a_audit), audit(&b_audit));
    for (who, text) in [("alice", &a_seen), ("bob", &b_seen)] {
        assert_eq!(text.matches("dns").count(), 0, "{who} looked a name up");
        assert_eq!(
            text.matches("connect_other").count(),
            0,
            "{who} connected beyond this computer"
        );
    }
    // Two more epochs of Alice advertising for Bob (his radio off: nobody
    // connects), so the adverts of the run are at least 4 tokens.
    ether.power(&b_svc, false);
    assert!(a.raven(&["nearby", "on", "@b56"], None).ok);
    for k in 1..=2i64 {
        let before = ether.adverts().len();
        clock.set(25 * 3_600_000 + k * 15 * 60_000);
        let a_radio = radio_name(&a_svc);
        assert!(
            wait_until(LOG_TIMEOUT, || ether.adverts()[before..]
                .iter()
                .any(|(radio, _)| *radio == a_radio)),
            "no advert in epoch +{k}:\n{}",
            a_svc.log.text()
        );
    }
    let mut tokens: Vec<[u8; 16]> = Vec::new();
    for (_, r) in ether.adverts() {
        let t = token_bytes(r["uuids"][0].as_str().unwrap());
        if !tokens.contains(&t) {
            tokens.push(t);
        }
    }
    assert!(tokens.len() >= 4, "{} tokens", tokens.len());
    assert_no_constant_bytes(&tokens);

    // Variant: the radios meet after the foreground ran out.
    let c = nearby_profile(
        root.path(),
        "c56",
        &ether,
        &[("RAVEN_LAB_NEARBY_FOREGROUND_MS", "3000")],
    );
    let d = nearby_profile(root.path(), "d56", &ether, &[]);
    let c_svc = c.start_service();
    let d_svc = d.start_service();
    nearby_meet(&[(&c, &c_svc), (&d, &d_svc)], true);
    ether.power(&d_svc, false);
    assert!(!c.send("d56", "c56 later").ok);
    std::thread::sleep(Duration::from_secs(6));
    ether.power(&d_svc, true);
    std::thread::sleep(Duration::from_secs(40));
    assert_eq!(
        d.inbox().matches("c56 later").count(),
        0,
        "delivered with nobody advertising"
    );
    let mut policy = raven_core::node_policy::try_load_policy(&c.dir).unwrap();
    policy.nearby_background_mail = Some(true);
    raven_core::node_policy::save_policy(&c.dir, &policy).unwrap();
    assert!(c.raven(&["nearby", "enable"], None).ok);
    assert!(
        wait_until(Duration::from_secs(90), || d.inbox().contains("c56 later")),
        "background mail did not advertise:\n{}\n{}",
        c_svc.log.text(),
        d_svc.log.text()
    );
    assert_eq!(d.inbox().matches("c56 later").count(), 1);
}

// ── Phase 6a: learning connectivity (P6.18) ──────────────────────────────

/// TEST-NET-1 (RFC 5737): routed nowhere. A LAN dial to it waits out its
/// connect wait (a black hole), or fails at once on a computer with no
/// default route; either way the LAN does not answer.
const BLACK_HOLE_IP: &str = "192.0.2.10";

/// The black-hole LAN wait a send may pay (C70): today's connect wait per
/// address (`learning::wait::STATIC_CONNECT_PER_ADDR`, 5 s) with 0.5 s of
/// slack.
const LAN_WAIT_BOUND: Duration = Duration::from_millis(5_500);

/// Learning connectivity's lab unlock is needed only while its gate is
/// held (`LEARNING_PRODUCTION_ENABLED`).
fn learning_lab_unlock() -> bool {
    !raven_core::learning::LEARNING_PRODUCTION_ENABLED
}

/// A new profile (`raven init` done) with the Internet direct lab unlock, a
/// lab network tag of its own (`RAVEN_LAB_NET_TAG`, the network learning
/// keys what it learns by) and, when `learning`, the learning switch
/// (`RAVEN_LAB_LEARNING=1`) on every process.
fn learning_profile(root: &Path, name: &'static str, learning: bool, tag: &str) -> Profile {
    let mut p =
        Profile::new(root, name, internet_lab_unlock()).with_lab_env("RAVEN_LAB_NET_TAG", tag);
    if learning && learning_lab_unlock() {
        p = p.with_lab_env("RAVEN_LAB_LEARNING", "1");
    }
    p.init();
    p
}

/// One `raven send` with `RAVEN_VERBOSE=1`: its output, how long it took,
/// whether a LAN route was tried and did not answer (the send's own
/// `lan_dial … did not answer …` line: the dial log of the routes it raced,
/// E2 r9: one that had not answered when another did says so too) and the
/// carrier it was delivered on (`carrier=`).
struct Sent {
    out: Output,
    took: Duration,
    lan_failed: bool,
    carrier: String,
}

fn verbose_send(p: &Profile, tag: &str, text: &str) -> Sent {
    let started = Instant::now();
    let out = p.raven_with(
        &["send", "--contact", &format!("@{tag}")],
        Some(&format!("{text}\n")),
        &[("RAVEN_VERBOSE", "1")],
    );
    let took = started.elapsed();
    let all = out.all();
    let lan_failed = all
        .lines()
        .any(|l| l.contains("lan_dial ") && l.contains(" did not answer"));
    let carrier = all
        .split("carrier=")
        .nth(1)
        .and_then(|rest| {
            rest.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
        })
        .unwrap_or_default()
        .to_string();
    Sent {
        out,
        took,
        lan_failed,
        carrier,
    }
}

/// `raven learning status --json`: the running raven-node's report (or one
/// with a `state` only: `held`, `off`, `not_running`).
fn learning_json(p: &Profile) -> serde_json::Value {
    let out = p.raven(&["learning", "status", "--json"], None);
    assert!(out.ok, "{} learning status --json:\n{}", p.name, out.all());
    let line = out.stdout.trim().lines().last().unwrap_or_default();
    serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("{} learning status --json: {e}:\n{}", p.name, out.all()))
}

/// `p`'s learning row for `other` on its current network.
fn learning_row(p: &Profile, other: &Profile) -> Option<serde_json::Value> {
    learning_json(p)["rows"]
        .as_array()?
        .iter()
        .find(|r| {
            r["peer_pub_hex"]
                .as_str()
                .is_some_and(|k| k.eq_ignore_ascii_case(&other.pub_hex))
        })
        .cloned()
}

/// The carrier order `p` uses for `other` on this network (its row; empty
/// without one: nothing learned, the static order).
fn learned_order(p: &Profile, other: &Profile) -> Vec<String> {
    learning_row(p, other)
        .and_then(|r| {
            r["order"].as_array().map(|o| {
                o.iter()
                    .filter_map(|c| c.as_str().map(str::to_string))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// Waits until `p`'s raven-node reports learning `state` (its service
/// reads the switch every 2 s and loads the model then).
fn wait_learning_state(p: &Profile, state: &str) -> bool {
    wait_until(LOG_TIMEOUT, || learning_json(p)["state"] == state)
}

/// C70-C73's pair: A pins B with a LAN route into a black hole
/// ([`BLACK_HOLE_IP`] on B's LAN port) and B's working Internet route
/// (`set-addr --internet`); B pins A. `learning`: A's processes run with
/// the learning switch. `session_first`: before that, one message with
/// learning held (`RAVEN_LAB_LEARNING=0` for that daemon and send) sets up
/// A's session with B, so that a later send's time is its LAN wait plus an
/// ordinary send's, not a first message's pairing too; A's daemon then
/// starts again with learning on, which has learned nothing yet.
struct BlackHolePair {
    a: Profile,
    b: Profile,
    a_svc: Service,
    b_svc: Service,
}

fn black_hole_pair(
    root: &Path,
    names: (&'static str, &'static str),
    learning: bool,
    session_first: bool,
) -> BlackHolePair {
    let tag = format!("{}-net", names.0);
    let a = learning_profile(root, names.0, learning, &tag);
    let b = learning_profile(root, names.1, false, &tag);
    let held = [("RAVEN_LAB_LEARNING", "0")];
    let mut a_svc = if session_first {
        a.start_service_env("127.0.0.1:0", None, &held)
    } else {
        a.start_service()
    };
    let b_svc = b.start_service_with(Some("127.0.0.1:0"));
    let port = b_svc.lan_dial.rsplit(':').next().unwrap();
    a.pin_contact(&b, "bob", Some(&format!("{BLACK_HOLE_IP}:{port}")));
    let set = a.raven(
        &[
            "contact",
            "set-addr",
            "@bob",
            "--internet",
            &b_svc.internet_dial,
        ],
        None,
    );
    assert!(set.ok, "a contact set-addr --internet:\n{}", set.all());
    b.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    if session_first {
        let text = format!("{} session", names.0);
        let out = a.raven_with(
            &["send", "--contact", "@bob"],
            Some(&format!("{text}\n")),
            &held,
        );
        assert_delivered(&text, &out);
        drop(a_svc);
        a_svc = a.start_service();
    }
    if learning && learning_lab_unlock() {
        assert!(
            wait_learning_state(&a, "on"),
            "a's learning never came on:\n{}",
            a_svc.log.text()
        );
    }
    BlackHolePair { a, b, a_svc, b_svc }
}

/// Every text of `texts` is in `p`'s inbox exactly once.
fn assert_exactly_once(p: &Profile, texts: &[String]) {
    let inbox = p.inbox();
    for text in texts {
        assert_eq!(inbox.matches(text.as_str()).count(), 1, "{text}:\n{inbox}");
    }
}

/// C70 (P6.18): A's LAN route to B is a black hole, its Internet route
/// works, learning is on (and A already has a session with B: one message
/// sent while learning was held). Message 1 pays at most one LAN connect
/// wait (since E2 r9 the routes race, so it pays only the stagger) and
/// goes over the Internet; from message 3 on, A's `raven send` (its dial
/// log: no LAN line) and A's worker (its learning row) go Internet first,
/// in under 2 s; `raven learning status` says the LAN did not answer;
/// after `raven learning reset --yes` message 5 goes LAN first again. Every
/// message arrives exactly once.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c70_learning_prefers_internet_where_lan_black_holes() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    // Each service lives to the end of the test (a field left out of the
    // pattern would be dropped, and its daemon killed, at once).
    let BlackHolePair {
        a,
        b,
        a_svc,
        b_svc: _b_svc,
    } = black_hole_pair(root.path(), ("la70", "lb70"), true, true);
    let texts: Vec<String> = (1..=5).map(|i| format!("c70 message {i}")).collect();
    let sent: Vec<Sent> = texts[..4]
        .iter()
        .map(|t| {
            let s = verbose_send(&a, "bob", t);
            assert_delivered(t, &s.out);
            s
        })
        .collect();
    let first = &sent[0];
    assert!(
        first.lan_failed && first.carrier == "internet_dial",
        "message 1 tried the LAN first and went over the Internet:\n{}",
        first.out.all()
    );
    for (i, s) in sent.iter().enumerate().skip(2) {
        assert!(
            !s.lan_failed && s.carrier == "internet_dial",
            "message {} went Internet first with no LAN dial:\n{}\n{}",
            i + 1,
            s.out.all(),
            a_svc.log.text()
        );
        assert!(
            s.took < Duration::from_secs(2),
            "message {} took {:?}:\n{}",
            i + 1,
            s.took,
            s.out.all()
        );
    }
    let took: Vec<Duration> = sent.iter().map(|s| s.took).collect();
    eprintln!("C70: messages 1-4 took {took:?}");
    // Message 1's LAN wait: its time beyond an Internet-first send's.
    let quick = sent[2].took.min(sent[3].took);
    let lan_wait = first.took.saturating_sub(quick);
    assert!(
        lan_wait <= LAN_WAIT_BOUND,
        "message 1 paid {lan_wait:?} of LAN wait ({:?} in all)",
        first.took
    );
    // E2 r9: the send races its routes, so message 1 no longer waits for
    // the black hole; the LAN dial it started still ends in raven-node, and
    // learning sees it fail a few seconds later.
    assert!(
        wait_until(LOG_TIMEOUT, || learned_order(&a, &b)
            == ["internet_dial", "lan_dial"]),
        "the worker's order:\n{}",
        learning_json(&a)
    );
    let status = a.raven(&["learning", "status"], None);
    assert!(
        status.ok && status.stdout.contains("LAN did not answer"),
        "{}",
        status.all()
    );
    let reset = a.raven(&["learning", "reset", "--yes"], None);
    assert!(reset.ok, "learning reset --yes:\n{}", reset.all());
    let fifth = verbose_send(&a, "bob", &texts[4]);
    assert_delivered(&texts[4], &fifth.out);
    assert!(
        fifth.lan_failed && fifth.carrier == "internet_dial",
        "after the reset message 5 went LAN first:\n{}",
        fifth.out.all()
    );
    let lan_wait = fifth.took.saturating_sub(quick);
    assert!(
        lan_wait <= LAN_WAIT_BOUND,
        "message 5 paid {lan_wait:?} of LAN wait ({:?} in all)",
        fifth.took
    );
    assert_exactly_once(&b, &texts);
}

/// What C72 records of a send with learning off: whether the LAN was tried
/// first and failed, and the carrier it went on. Today's order with the
/// lab's route memory (G2, debug `RAVEN_LAB_TEST_A=1`): message 1 waits
/// out the black-holed LAN, the memory then sends the next ones by the
/// Internet first.
const C72_BASELINE: [(bool, &str); 4] = [
    (true, "internet_dial"),
    (false, "internet_dial"),
    (false, "internet_dial"),
    (false, "internet_dial"),
];

/// C72 (P6.18): C70's setup without the learning switch. The sends follow
/// the recorded baseline ([`C72_BASELINE`]); no log line of either daemon
/// names learning or a carry token; no `learning.bin`; IPC `Status` has no
/// `learning`; `raven doctor` has no learning report line (its gate table
/// still lists the held gate) and `raven learning status` says it is held.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c72_learning_off_is_byte_identical() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let BlackHolePair { a, b, a_svc, b_svc } =
        black_hole_pair(root.path(), ("la72", "lb72"), false, false);
    let texts: Vec<String> = (1..=4).map(|i| format!("c72 message {i}")).collect();
    let seen: Vec<(bool, String)> = texts
        .iter()
        .map(|t| {
            let s = verbose_send(&a, "bob", t);
            assert_delivered(t, &s.out);
            (s.lan_failed, s.carrier)
        })
        .collect();
    let want: Vec<(bool, String)> = C72_BASELINE
        .iter()
        .map(|(lan, c)| (*lan, c.to_string()))
        .collect();
    assert_eq!(seen, want, "the dial sequence left the baseline");
    for (name, log) in [("a", &a_svc.log), ("b", &b_svc.log)] {
        let text = log.text();
        assert!(
            !text.lines().any(|l| {
                let l = l.to_ascii_lowercase();
                l.contains("learning") || l.contains("learn:") || l.contains(" carry=")
            }),
            "{name}'s log names learning:\n{text}"
        );
    }
    for p in [&a, &b] {
        assert!(
            !p.dir
                .join(raven_core::learning::store::LEARNING_FILE)
                .exists(),
            "{} wrote learning.bin",
            p.name
        );
        let status = ipc_status(p);
        assert!(
            status
                .get("learning")
                .is_none_or(serde_json::Value::is_null),
            "{}'s Status carries learning: {status}",
            p.name
        );
        // The gate table still names the held gate; the report's lines
        // (`learning: state=…`, `learning_row_<n>: …`) are not there.
        let doctor = p.raven(&["doctor"], None);
        assert!(
            !doctor.stdout.lines().any(|l| {
                let l = l.trim_start();
                l.starts_with("learning:") || l.starts_with("learning_row_")
            }),
            "{}'s doctor:\n{}",
            p.name,
            doctor.stdout
        );
        let held = p.raven(&["learning", "status"], None);
        assert!(
            held.stdout.contains("learning: held in this build"),
            "{}",
            held.all()
        );
    }
    assert_exactly_once(&b, &texts);
}

/// How long C73 waits for raven-node's periodic save
/// (`learning::SAVE_EVERY`, 60 s) to have run.
const SAVE_TICK_WAIT: Duration = Duration::from_secs(80);

/// C73 (P6.18): C70's pair with learning on. (1) A's `learning.bin`, once
/// saved, is corrupted while A is stopped: A starts `reset_after_unreadable`,
/// plans in the static order (its next send tries the LAN first) and its
/// next save overwrites the file (state `on` again). (2) A restarted with
/// the sealer forced unavailable (`RAVEN_LAB_LEARNING_SEALER=unavailable`,
/// a debug-only hook whose release inertness `lan_gate` tests) is
/// `memory_only`: after 3 sends and a save tick the file's bytes are
/// unchanged.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c73_unreadable_store_is_static_and_locked_store_is_memory_only() {
    if !lab_ready() || !learning_lab_unlock() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let BlackHolePair {
        a,
        b,
        mut a_svc,
        b_svc: _b_svc,
    } = black_hole_pair(root.path(), ("la73", "lb73"), true, false);
    let file = a.dir.join(raven_core::learning::store::LEARNING_FILE);
    let mut texts: Vec<String> = Vec::new();
    let mut send = |text: String| {
        let s = verbose_send(&a, "bob", &text);
        assert_delivered(&text, &s.out);
        texts.push(text);
        s
    };
    send("c73 learn 1".into());
    send("c73 learn 2".into());
    assert!(
        wait_until(SAVE_TICK_WAIT, || file.exists()),
        "learning.bin was never saved:\n{}",
        a_svc.log.text()
    );

    // (1) Unreadable: started over, static, overwritten by the next save.
    drop(a_svc);
    let mut bytes = std::fs::read(&file).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&file, &bytes).unwrap();
    a_svc = a.start_service();
    assert!(
        wait_learning_state(&a, "reset_after_unreadable"),
        "{}\n{}",
        learning_json(&a),
        a_svc.log.text()
    );
    assert!(learned_order(&a, &b).is_empty(), "{}", learning_json(&a));
    let after = send("c73 after the corruption".into());
    assert!(
        after.lan_failed,
        "the first send after the corruption went in the static order (LAN first):\n{}",
        after.out.all()
    );
    assert!(
        wait_until(SAVE_TICK_WAIT, || {
            std::fs::read(&file).is_ok_and(|now| now != bytes) && learning_json(&a)["state"] == "on"
        }),
        "the next save did not overwrite the file:\n{}\n{}",
        learning_json(&a),
        a_svc.log.text()
    );

    // (2) The sealer unavailable: memory only, the file untouched.
    drop(a_svc);
    let before = std::fs::read(&file).unwrap();
    let a_svc = a.start_service_env(
        "127.0.0.1:0",
        None,
        &[("RAVEN_LAB_LEARNING_SEALER", "unavailable")],
    );
    assert!(
        wait_learning_state(&a, "memory_only"),
        "{}\n{}",
        learning_json(&a),
        a_svc.log.text()
    );
    for i in 1..=3 {
        send(format!("c73 memory only {i}"));
    }
    std::thread::sleep(SAVE_TICK_WAIT);
    assert_eq!(
        std::fs::read(&file).unwrap(),
        before,
        "a memory-only learning wrote its file"
    );
    let status = a.raven(&["learning", "status"], None);
    assert!(status.stdout.contains("in memory only"), "{}", status.all());
    assert_exactly_once(&b, &texts);
}

/// C71's proxy in front of one LAN listener: every byte passes both ways,
/// and what the listener writes is read as lan_direct's records (a 4-byte
/// big-endian length, then that many bytes). While it stalls, every third
/// link on which the listener starts a fourth record (after Noise message
/// 2, its identity bind and its RLB1 offer: the reply to the dialer's
/// frames; a probe link has no fourth) gets nothing more from it: the
/// frames were delivered, their reply never comes. A stall earlier in the
/// link (the plan's "after the first 64 bytes") would end in the Noise
/// handshake, which no learned wait bounds.
struct StallProxy {
    addr: std::net::SocketAddr,
    stalling: Arc<AtomicBool>,
    replies: Arc<AtomicU64>,
    stalled: Arc<AtomicU64>,
}

impl StallProxy {
    fn start(target: &str) -> Self {
        let target: std::net::SocketAddr = target.parse().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stalling = Arc::new(AtomicBool::new(false));
        let replies = Arc::new(AtomicU64::new(0));
        let stalled = Arc::new(AtomicU64::new(0));
        let (s, r, h) = (
            Arc::clone(&stalling),
            Arc::clone(&replies),
            Arc::clone(&stalled),
        );
        std::thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { continue };
                let Ok(upstream) = std::net::TcpStream::connect(target) else {
                    continue;
                };
                let (Ok(client2), Ok(upstream2)) = (client.try_clone(), upstream.try_clone())
                else {
                    continue;
                };
                std::thread::spawn(move || pump_plain(client2, upstream2));
                let (s, r, h) = (Arc::clone(&s), Arc::clone(&r), Arc::clone(&h));
                std::thread::spawn(move || pump_replies(upstream, client, &s, &r, &h));
            }
        });
        StallProxy {
            addr,
            stalling,
            replies,
            stalled,
        }
    }

    /// From now on every third reply is held (counting from here).
    fn stall_one_in_three(&self) {
        self.replies.store(0, Ordering::SeqCst);
        self.stalling.store(true, Ordering::SeqCst);
    }

    fn stalled(&self) -> u64 {
        self.stalled.load(Ordering::SeqCst)
    }
}

/// Copies `from` into `to` until either ends.
fn pump_plain(mut from: std::net::TcpStream, mut to: std::net::TcpStream) {
    let mut buf = [0u8; 16 << 10];
    while let Ok(n) = from.read(&mut buf) {
        if n == 0 || to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
}

/// [`StallProxy`]'s listener-to-dialer half: passes the first three
/// records, then (once, at the fourth record's first byte) counts a reply
/// and, while stalling, holds every third one.
fn pump_replies(
    mut from: std::net::TcpStream,
    mut to: std::net::TcpStream,
    stalling: &AtomicBool,
    replies: &AtomicU64,
    stalled: &AtomicU64,
) {
    let mut buf = [0u8; 16 << 10];
    let (mut done, mut left, mut head) = (0u32, 0usize, Vec::with_capacity(4));
    let (mut decided, mut held) = (false, false);
    while let Ok(n) = from.read(&mut buf) {
        if n == 0 {
            break;
        }
        if held {
            continue;
        }
        let data = &buf[..n];
        let mut pass = data.len();
        if !decided {
            let mut i = 0;
            while i < data.len() && done < 3 {
                if left == 0 {
                    head.push(data[i]);
                    i += 1;
                    if head.len() == 4 {
                        left = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
                        head.clear();
                        if left == 0 {
                            done += 1;
                        }
                    }
                } else {
                    let take = left.min(data.len() - i);
                    i += take;
                    left -= take;
                    if left == 0 {
                        done += 1;
                    }
                }
            }
            if i < data.len() {
                decided = true;
                let nth = replies.fetch_add(1, Ordering::SeqCst) + 1;
                if stalling.load(Ordering::SeqCst) && nth.is_multiple_of(3) {
                    stalled.fetch_add(1, Ordering::SeqCst);
                    held = true;
                    pass = i;
                }
            }
        }
        if to.write_all(&data[..pass]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
}

/// C71 (P6.18): A reaches B's LAN listener through [`StallProxy`], learning
/// on. After 5 sends A's first-reply wait for B is learned (warm, fresh;
/// `learning::wait`, at least 6 s). Then the proxy holds the reply of one
/// link in three: the stalled send gives up in under 10 s instead of
/// today's 30 s, the message arrives once (A's outbox sends it again and
/// B's receipt comes back), and no send waits 30 s.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c71_learned_reply_wait_after_a_stall() {
    if !lab_ready() || !learning_lab_unlock() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let a = learning_profile(root.path(), "la71", true, "la71-net");
    let b = learning_profile(root.path(), "lb71", false, "la71-net");
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    let proxy = StallProxy::start(&b_svc.lan_dial);
    a.pin_contact(&b, "bob", Some(&proxy.addr.to_string()));
    b.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    assert!(
        wait_learning_state(&a, "on"),
        "a's learning never came on:\n{}",
        a_svc.log.text()
    );
    let mut texts: Vec<String> = Vec::new();
    let mut took: Vec<Duration> = Vec::new();
    for i in 1..=5 {
        let text = format!("c71 warm {i}");
        let s = verbose_send(&a, "bob", &text);
        assert_delivered(&text, &s.out);
        took.push(s.took);
        texts.push(text);
    }
    proxy.stall_one_in_three();
    let mut stalled_text = None;
    for i in 1..=3 {
        let text = format!("c71 stall {i}");
        let s = verbose_send(&a, "bob", &text);
        took.push(s.took);
        if proxy.stalled() == 1 && stalled_text.is_none() {
            assert!(
                s.took < Duration::from_secs(10),
                "the stalled send waited {:?}:\n{}\n{}",
                s.took,
                s.out.all(),
                a_svc.log.text()
            );
            assert!(
                s.out.all().to_lowercase().contains("unconfirmed")
                    || s.out.all().contains("not delivered yet"),
                "{}",
                s.out.all()
            );
            stalled_text = Some(text.clone());
        } else {
            assert_delivered(&text, &s.out);
        }
        texts.push(text);
    }
    let stalled_text = stalled_text.expect("no link was stalled");
    assert!(
        wait_until(Duration::from_secs(90), || {
            a.raven(&["outbox", "list"], None)
                .stdout
                .contains("Nothing waiting")
        }),
        "the stalled message was never confirmed:\n{}\n{}",
        a.raven(&["outbox", "list"], None).all(),
        a_svc.log.text()
    );
    assert!(
        took.iter().all(|t| *t < Duration::from_secs(30)),
        "a send waited 30 s or more: {took:?}"
    );
    assert!(b.inbox().contains(&stalled_text));
    assert_exactly_once(&b, &texts);
}

/// C74 (P6.18, the p2p lab): B reserves on two dedicated relays R1 and R2,
/// its card names both, and A (no relay of its own, learning on) holds it.
/// A reaches R1 through a [`RecordingProxy`] of its own (the card's R1
/// address), B through another; R2 through a third. Both ping every 2 s
/// with a 1 s timeout (`RAVEN_LAB_P2P_PING`, as C13). R1 goes to sleep
/// before the first message (both its proxies hold every connection
/// silent, as SIGSTOP would, on all three OSes). Three dials, each a new
/// connection (between them A's model is saved, `learning::SAVE_EVERY`,
/// and A restarts: no connection is left to ride): each is delivered
/// `path=relayed` through R2, the third in under 5 s; A's model holds
/// relay rows (the term that ranks R2's circuits
/// first; their order inside one dial is P6.15's unit test, libp2p dials
/// two addresses at once); R1 is never dropped from the dial set (each
/// dial still reaches A's R1 proxy); every message arrives exactly once;
/// and nobody's relay choice changes (no `relay replaced` / `relay chosen`
/// line) well inside `REPLACE_AFTER`.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c74_relay_score_orders_circuits() {
    if !lab_ready() || !learning_lab_unlock() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let r1 = Relay::start_named(root.path(), "r1-74");
    let r2 = Relay::start_named(root.path(), "r2-74");
    // A's way to R1 (the card's), B's way to R1, and R2.
    let (p1a, via1a) = proxied_via(&r1);
    let (p1b, via1b) = proxied_via(&r1);
    let (_p2, via2) = proxied_via(&r2);
    let mut a = Profile::new(root.path(), "la74", p2p_lab_unlock())
        .with_lab_env("RAVEN_LAB_LEARNING", "1")
        .with_lab_env("RAVEN_LAB_NET_TAG", "la74-net");
    let mut b = Profile::new(root.path(), "lb74", p2p_lab_unlock());
    a.init();
    b.init();
    let card = b.raven(&["whoami", "--card", "--via", &via1a, "--via", &via2], None);
    assert!(card.ok, "{}", card.all());
    let b_card = card.stdout.trim().to_string();
    assert_eq!(b_card.matches(" via=").count(), 2, "{b_card}");
    for r in [&r1, &r2] {
        r.allow(&b, &b_card);
    }
    let ping = [("RAVEN_LAB_P2P_PING", "2,1")];
    let a_start = P2pStart {
        listen: "127.0.0.1:0",
        relay_via: "",
        wait_reservation: false,
        env: &ping,
    };
    let mut a_svc = a.start_service_p2p_opts(&a_start);
    let a_card = running_card(&a);
    for r in [&r1, &r2] {
        r.allow(&a, &a_card);
        r.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    }
    // B listens nowhere: reachable through its two relays only.
    let vias = format!("{via1b} {via2}");
    let b_svc = b.start_service_p2p_opts(&P2pStart {
        listen: "relay",
        relay_via: &vias,
        wait_reservation: true,
        env: &ping,
    });
    assert!(
        wait_until(READY_TIMEOUT, || {
            b_svc.log.count("raven-node p2p: reservation accepted") >= 2
        }),
        "b did not reserve on both relays:\n{}",
        b_svc.log.text()
    );
    a.add_card(&b_card, "bob", &b.fingerprint);
    b.add_card(&a_card, "alice", &a.fingerprint);
    wait_gate(&a_svc, 1);
    wait_gate(&b_svc, 1);
    assert!(wait_learning_state(&a, "on"), "{}", a_svc.log.text());
    let send = |text: &str| {
        let started = Instant::now();
        let out = a.raven_with(
            &["send", "--contact", "@bob", "--carrier", "p2p"],
            Some(&format!("{text}\n")),
            &[("RAVEN_VERBOSE", "1")],
        );
        (out, started.elapsed())
    };

    let file = a.dir.join(raven_core::learning::store::LEARNING_FILE);
    let saved = || std::fs::metadata(&file).and_then(|m| m.modified()).ok();

    // R1 sleeps.
    p1a.set_mode(ProxyMode::Blackhole);
    p1b.set_mode(ProxyMode::Blackhole);
    let mut texts = Vec::new();
    for i in 1..=3 {
        if i > 1 {
            // What the last dial taught is saved, then A starts again: no
            // connection is left to ride, the next send dials.
            let before = saved();
            assert!(
                wait_until(SAVE_TICK_WAIT, || saved() != before),
                "a's model was not saved:\n{}",
                a_svc.log.text()
            );
            drop(a_svc);
            a_svc = a.start_service_p2p_opts(&a_start);
            assert!(wait_learning_state(&a, "on"), "{}", a_svc.log.text());
        }
        let text = format!("c74 dial {i}");
        let before = p1a.activity();
        let (out, took) = send(&text);
        eprintln!(
            "C74: dial {i} took {took:?}; A's R1 proxy +{}",
            p1a.activity() - before
        );
        assert_delivered(&text, &out);
        assert_eq!(send_path(&out), "relayed", "{}", out.all());
        if i == 3 {
            assert!(
                took < Duration::from_secs(5),
                "dial {i} took {took:?}:\n{}\n{}",
                out.all(),
                a_svc.log.text()
            );
        }
        assert!(
            p1a.activity() > before,
            "dial {i} left R1 out of its dial set:\n{}",
            a_svc.log.text()
        );
        texts.push(text);
    }
    let learned = learning_json(&a);
    assert!(
        learned["relays"].as_u64().unwrap_or(0) >= 1,
        "a's model holds no relay: {learned}"
    );
    for (name, svc) in [("a", &a_svc), ("b", &b_svc)] {
        let log = svc.log.text();
        assert!(
            !log.contains(RELAY_REPLACED) && !log.contains(RELAY_CHOSEN),
            "{name}'s relay choice changed:\n{log}"
        );
        assert!(
            !log.contains("12D3KooW"),
            "{name}'s log names a PeerId:\n{log}"
        );
    }
    assert_exactly_once(&b, &texts);
}

// ── C95: the Tor onion carrier over the loopback helper ─────────────────────

/// The Tor onion profile of `name`: Lab Test A, the Tor switch and the
/// loopback helper sharing `registry` (no Tor network), the long horizon
/// (a first message to a never-paired contact parks and is paired by the
/// node), a short race head start.
fn tor_profile(root: &Path, name: &'static str, registry: &Path) -> Profile {
    let mut p = Profile::new(root, name, true)
        .with_lab_env("RAVEN_LAB_TOR", "1")
        .with_lab_env("RAVEN_LAB_TOR_LOOPBACK", &registry.to_string_lossy())
        .with_lab_env("RAVEN_LAB_TOR_HEAD_START_MS", "200")
        .with_lab_env("RAVEN_LAB_HORIZON", "1");
    p.init();
    p
}

/// `p`'s card once its node signed its onion binding (`onion=` in it).
fn tor_card(p: &Profile, svc: &Service) -> String {
    let mut last = String::new();
    let ok = wait_until(READY_TIMEOUT, || {
        let out = p.raven(&["whoami", "--card"], None);
        last = out.stdout.trim().to_string();
        out.ok && last.contains(" onion=")
    });
    assert!(
        ok,
        "{}: no onion= in its card:\n{last}\n{}",
        p.name,
        svc.log.text()
    );
    last
}

/// `p`'s inbox holds `text` within `within`.
fn wait_inbox(p: &Profile, text: &str, within: Duration) -> bool {
    wait_until(within, || p.inbox().contains(text))
}

/// C95 (Tor onion carrier, lab; docs/design/2026-10-tor-fallback.md §5): A
/// and B run the onion carrier through the loopback helper, which plays the
/// Tor network with loopback ports (automated tests never touch the real
/// one). Their cards carry `onion=` and nothing else that reaches them (no
/// LAN or Internet address, no p2p): the first message each way parks (no
/// session yet), and each node's outbox pairs and delivers over the onion
/// link. Both logs say `Tor: ready`; neither names an onion key or a
/// `.onion` address.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c95_tor_onion_carrier_both_ways_over_the_loopback_helper() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let registry = root.path().join("tor-registry");
    let a = tor_profile(root.path(), "ta", &registry);
    let b = tor_profile(root.path(), "tb", &registry);
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    for (p, svc) in [(&a, &a_svc), (&b, &b_svc)] {
        assert!(
            svc.log
                .wait_for(READY_TIMEOUT, |l| l
                    .contains("raven-node onion: Tor: ready"))
                .is_some(),
            "{}: Tor never ready:\n{}",
            p.name,
            svc.log.text()
        );
    }
    let (card_a, card_b) = (tor_card(&a, &a_svc), tor_card(&b, &b_svc));
    for card in [&card_a, &card_b] {
        assert!(
            !card.contains(" lan=") && !card.contains(" inet="),
            "{card}"
        );
    }
    a.add_card(&card_b, "bob", &b.fingerprint);
    b.add_card(&card_a, "alice", &a.fingerprint);

    let to_bob = "c95 hello over tor";
    let out = a.send("bob", to_bob);
    assert!(
        wait_inbox(&b, to_bob, Duration::from_secs(90)),
        "a→b never arrived:\nsend: {}\nA:\n{}\nB:\n{}",
        out.all(),
        a_svc.log.text(),
        b_svc.log.text()
    );
    let to_alice = "c95 and back over tor";
    let out = b.send("alice", to_alice);
    assert!(
        wait_inbox(&a, to_alice, Duration::from_secs(90)),
        "b→a never arrived:\nsend: {}\nA:\n{}\nB:\n{}",
        out.all(),
        a_svc.log.text(),
        b_svc.log.text()
    );
    // A later message with the session up: delivered over Tor again.
    let again = "c95 second message";
    let _ = a.send("bob", again);
    assert!(wait_inbox(&b, again, Duration::from_secs(60)));

    // States and counts only: no onion key, no `.onion` address in a log.
    for (p, svc) in [(&a, &a_svc), (&b, &b_svc)] {
        let own = raven_core::onion::load_own(&p.dir).expect("own binding");
        let log = svc.log.text();
        assert!(!log.contains(&hex::encode(own.hs_id)), "{}: {log}", p.name);
        assert!(!log.contains(".onion"), "{}: {log}", p.name);
    }
}

/// C98 (Tor onion carrier, lab; E2 r40 P1): a friend added from a card
/// that names only its onion service (no LAN, no Internet address), first
/// unverified and verified afterwards with `contact verify`, is reached
/// over Tor by the first send: the card's onion route is planned at once,
/// not only once the friend dialled in.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c98_a_friend_added_from_an_onion_card_and_verified_later_is_reached_over_tor() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let registry = root.path().join("tor-registry");
    let a = tor_profile(root.path(), "tc", &registry);
    let b = tor_profile(root.path(), "td", &registry);
    let a_svc = a.start_service();
    let b_svc = b.start_service();
    let (card_a, card_b) = (tor_card(&a, &a_svc), tor_card(&b, &b_svc));
    assert!(
        !card_b.contains(" lan=") && !card_b.contains(" inet="),
        "{card_b}"
    );
    // A adds B unverified, then verifies B with B's code.
    let out = a.raven(
        &[
            "contact",
            "add",
            "--card",
            &card_b,
            "--petname",
            "bob",
            "--tag",
            "bob",
        ],
        None,
    );
    assert!(out.ok, "{}", out.all());
    assert!(out.stdout.contains("Tor onion service"), "{}", out.all());
    let out = a.raven(
        &["contact", "verify", "bob", "--check", &b.fingerprint],
        None,
    );
    assert!(out.ok, "contact verify:\n{}", out.all());
    b.add_card(&card_a, "alice", &a.fingerprint);
    let text = "c98 first message after verify";
    let out = a.send("bob", text);
    assert!(
        wait_inbox(&b, text, Duration::from_secs(90)),
        "a→b never arrived over Tor:\nsend: {}\nA:\n{}\nB:\n{}",
        out.all(),
        a_svc.log.text(),
        b_svc.log.text()
    );
    assert!(
        !out.all().contains("no address known"),
        "the onion route was not planned:\n{}",
        out.all()
    );
}

/// C96 (Tor onion carrier, lab; design §3.7): a Tor helper that exits the
/// way Arti exits on an obsolete protocol version (`exit(1)`, Arti #1932)
/// ends only the helper: raven-node keeps answering, says why in its status
/// line and starts the helper again with backoff. The loopback helper plays
/// the exit (`RAVEN_LAB_TOR_LOOPBACK_OBSOLETE=1`); no Tor network.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c96_a_tor_helper_exit_never_ends_raven_node() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let registry = root.path().join("tor-registry");
    let mut a = Profile::new(root.path(), "tx", true)
        .with_lab_env("RAVEN_LAB_TOR", "1")
        .with_lab_env("RAVEN_LAB_TOR_LOOPBACK", &registry.to_string_lossy())
        .with_lab_env("RAVEN_LAB_TOR_LOOPBACK_OBSOLETE", "1");
    a.init();
    let svc = a.start_service();
    let restarting = svc.log.wait_for(READY_TIMEOUT, |l| {
        l.contains("raven-node onion: Tor: restarting (this Tor version is too old for the network")
    });
    assert!(restarting.is_some(), "{}", svc.log.text());
    // Started again (with backoff), and raven-node still answers.
    assert!(
        wait_until(Duration::from_secs(60), || svc
            .log
            .count("raven-node onion: Tor: starting")
            >= 2),
        "{}",
        svc.log.text()
    );
    let ping = a.raven(&["ipc-ping"], None);
    assert!(ping.ok, "{}\n{}", ping.all(), svc.log.text());
    let status = a.raven(&["status"], None);
    assert!(status.stdout.contains("Tor "), "{}", status.all());
}

/// C97 (E2 r38, field K4): Bob's computer is on the LAN but his Raven is
/// stopped: Alice's LAN route (and her Internet direct route to him) is
/// refused at once. The first send dials them, fails and queues; the next
/// two find every route failed lately ("every way to bob failed N s ago")
/// and queue at once without dialling, each well under a second of
/// network time. Back up on the same address, all three arrive exactly
/// once.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c97_a_stopped_raven_on_the_lan_queues_the_next_sends_at_once() {
    if !lab_ready() {
        return;
    }
    let _net = shared_host_network();
    let root = tempfile::tempdir().unwrap();
    let tag = "la97-net";
    let a = learning_profile(root.path(), "la97", false, tag);
    let b = learning_profile(root.path(), "lb97", false, tag);
    let a_svc = a.start_service();
    let b_lan = format!("127.0.0.1:{}", free_loopback_port());
    let b_svc = b.start_service_on(&b_lan, Some("127.0.0.1:0"));
    a.pin_contact(&b, "bob", Some(&b_svc.lan_dial));
    let set = a.raven(
        &[
            "contact",
            "set-addr",
            "@bob",
            "--internet",
            &b_svc.internet_dial,
        ],
        None,
    );
    assert!(set.ok, "a contact set-addr --internet:\n{}", set.all());
    b.pin_contact(&a, "alice", Some(&a_svc.lan_dial));
    let first = a.send("bob", "c97 session");
    assert_delivered("c97 session", &first);
    // Bob's Raven stops; his computer (this one) still refuses at once.
    drop(b_svc);
    let texts: Vec<String> = (1..=3).map(|i| format!("c97 while stopped {i}")).collect();
    let mut took = Vec::new();
    let mut outs = Vec::new();
    for text in &texts {
        let started = Instant::now();
        let out = a.send("bob", text);
        took.push(started.elapsed());
        assert!(
            out.all().contains("not delivered yet"),
            "{text} was not queued:\n{}",
            out.all()
        );
        outs.push(out.all());
    }
    assert!(
        !outs[0].contains("every way to bob failed"),
        "the first send dials:\n{}",
        outs[0]
    );
    for (i, out) in outs.iter().enumerate().skip(1) {
        assert!(
            out.contains("every way to bob failed") && out.contains("not tried again now"),
            "send {} did not queue at once:\n{out}",
            i + 1
        );
    }
    eprintln!("C97: sends while stopped took {took:?}");
    // Bob back on the same LAN address: the outbox delivers each once.
    let _b_svc = b.start_service_on(&b_lan, None);
    assert!(
        wait_until(Duration::from_secs(90), || {
            let inbox = b.inbox();
            texts.iter().all(|t| inbox.matches(t.as_str()).count() == 1)
        }),
        "not every message arrived once:\n{}",
        b.inbox()
    );
    assert_exactly_once(&b, &texts);
}
