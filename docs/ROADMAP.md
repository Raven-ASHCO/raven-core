# Roadmap: from lab features to release

**October 2026: switched on in release builds.** After the three-machine field test the owner
switched on, in release builds, the features that test exercised: Internet direct, the
peer-to-peer carrier and friend relays, route hints, router port mapping and IPv6 pinholes, the
NAT class, public address discovery (STUN), hole punching between friends, the Tor onion carrier,
friend custody over the local network and the internet, the long message horizon, groups,
Bluetooth nearby on macOS only, and the app channel for RDAP (on macOS with UID-only IPC, the
owner's decision Q6). Their gates are now `true`. This was done **before** the items in
their "Still needed" column below (independent review, signed release records, more real-world
rows): those rows stay here as the list of what is still missing for them. In a debug build a
`RAVEN_LAB_*` switch set to `0` closes such a feature again.

Version 0.1.0 (the first version with these features on) also carries the fixes of an internal
review held in October 2026, and two changes made before release: a contact card no longer
carries or gives an Internet address, a PeerId or a relay (nothing signs them; addresses travel
only inside encrypted links between verified friends, [RAVEN_ROUTE_HINTS_V1](../protocol/RAVEN_ROUTE_HINTS_V1.md)
§9.1), and the app channel takes payloads only from verified contacts, of registered types,
within size and rate limits ([RAVEN_APP_PAYLOAD_V1](../protocol/RAVEN_APP_PAYLOAD_V1.md) §3.1).
An internal review is not an independent one.

Release builds had one thing before that: direct messages between two computers on the same local
network. Everything else is a **lab feature**: compiled in, tested in CI, and held off by a constant
in the code (`*_PRODUCTION_ENABLED = false`) that a release build cannot change. In a debug build a
`RAVEN_LAB_*` environment variable opens it, for testing only.

This page lists each lab feature: what it does, the evidence so far, and what is still needed before
its gate could be switched on in release builds. Most features have an unsigned draft release record
in `docs/WAIVER_*_DRAFT.md`, whose "exit conditions", "preconditions" or "evidence before signature"
section lists the details; some have none yet.
There are no dates here and no promises.

Some drafts propose switching a feature on under a written exception instead of waiting for an
**independent security review**; the peer-to-peer draft itself recommends a review. The only signed
exception is the one for LAN direct
([WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md)),
and no independent review has happened yet ([SECURITY_REVIEW_SCOPE.md](SECURITY_REVIEW_SCOPE.md)).
There is nothing to download yet and there are no signed packages (last section).

"Field test" below means the three-computer test of October 2026
([FIELD_TEST_2026_10.md](FIELD_TEST_2026_10.md)); "carrier matrix" means the multi-process loopback
tests in `node/crates/raven-node/tests/carrier_matrix.rs` ([EVIDENCE.md](EVIDENCE.md)).

## Reaching friends on other networks

| Feature and gate | What it does | Evidence so far | Still needed |
|---|---|---|---|
| **Tor onion carrier** `ONION_PRODUCTION_ENABLED` | Every node publishes a Tor onion service and dials its verified friends' services; raced against the direct paths. The baseline that works when nothing direct does. [Spec](../protocol/RAVEN_ONION_CARRIER_V1.md), [design](design/2026-10-tor-fallback.md) | CI tests with a loopback helper on three operating systems; a shared vector for the signed binding; field test: 10 / 10 in every direction between a phone hotspot and a home network, 11-28 s per message | Understand and reduce the onion service outages (11-24 % of a long idle night) and slow starts (up to 9 minutes) seen in the field test; an external review of the carrier and the helper; a decision on the card format (the `onion=` field makes older readers refuse a card); more networks, including ones that block Tor; a release record (none drafted yet) |
| **Public address discovery** `STUN_DISCOVERY_PRODUCTION_ENABLED` | Asks two public STUN servers (Cloudflare, Google) which public address they see; offers it to friends inside encrypted links. [Design](design/2026-10-auto-reach.md) | unit tests of the STUN reader and the NAT classes; field test: found the public address on the home network | the peer-to-peer carrier first (its gate requires it); a fuzz target for the STUN reader; a release record |
| **Hole punching between friends** `SERVERLESS_PUNCH_PRODUCTION_ENABLED` | Two verified friends with "easy" NATs dial each other at moments both compute from their shared secret; no coordinator, no port guessing | unit tests; field test: tried, **never connected** (the hotspot's NAT is the kind it skips) | a measured success between two different networks with easy NATs; the NAT class gate and address discovery first; a release record |
| **Peer-to-peer carrier and friend relays** `P2P_PRODUCTION_ENABLED`, `FRIEND_RELAY_PRODUCTION_ENABLED` | libp2p over TCP and QUIC, Circuit Relay v2, hole punching through a relay (DCUtR); a friend's node can relay for its friends. [Draft](WAIVER_P2P_RELAY_DRAFT.md) | carrier matrix cases for relay circuits, a network switch, a silent relay and a loopback hole punch; NAT simulations in Linux network namespaces (advisory); field test: the friend relay ran but had no public address to offer, so it carried nothing | the namespace NAT simulations green on a streak; real rows with a relay on a third computer and with hotspots; a decision between an independent review and a written exception (the draft recommends a review) |
| **Internet direct** `INTERNET_DIRECT_PRODUCTION_ENABLED` | Direct TCP to a friend's public or forwarded address, verified contacts only. [Draft](WAIVER_INTERNET_DIRECT_DRAFT.md) | carrier matrix C2 on Linux, macOS and Windows | a real row between two computers on different networks with a reachable address; a signed release record |
| **Router port mapping, IPv6 pinholes, NAT class, PeerId rotation** `PORT_MAP_…`, `V6_PINHOLE_…`, `NAT_CLASS_…`, `PEER_ROTATION_PRODUCTION_ENABLED` | Ask the router to open a port (NAT-PMP, PCP); open an IPv6 pinhole; act on the NAT type; rotate libp2p identities. [Draft](WAIVER_PORT_MAP_DRAFT.md) | carrier matrix cases C43-C44, the `portmap_reply` fuzz target, shared vectors (Rust and Python); field test: the home router answered none of UPnP, NAT-PMP or PCP | tests on routers that do answer NAT-PMP or PCP, and with IPv6; the peer-to-peer carrier first |
| **Relays over WSS on TCP 443, HTTPS proxies** `WSS_PRODUCTION_ENABLED`, `WSS_PROXY_PRODUCTION_ENABLED` | For networks that allow only web traffic. [Spec](../protocol/RAVEN_WSS_TRANSPORT_V1.md), [draft](WAIVER_WSS_PROXY_DRAFT.md) | restrictive-network simulation (advisory), the `ws_frame` fuzz target, shared vectors | real rows on such networks; relays to exist; the peer-to-peer carrier first |

## The local network and Bluetooth

| Feature and gate | What it does | Evidence so far | Still needed |
|---|---|---|---|
| **Listen on every network** `LAN_AUTO_LISTEN_PRODUCTION_ENABLED` | Listen on every interface, IPv4 and IPv6, and let in local sources only | carrier matrix C27-C30; fault matrix | the signed LAN amendment ([draft](WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md)) and its real rows |
| **LAN beacon** `LAN_BEACON_PRODUCTION_ENABLED` | Find a friend's address on the same network without typing it. [Spec](../protocol/RAVEN_LAN_BEACON_V1.md) | vectors (Rust and Python), the `lan_beacon_datagram` fuzz target, fault scenarios; on in the field test's desktop-app rounds | the same amendment; a privacy capture on real networks |
| **Cable-only networks and Noise key pinning** `OFFLINE_LAN_…`, `LAN_NOISE_PIN_PRODUCTION_ENABLED` | Count a cable with only link-local addresses as a network; pin each contact's Noise key and stop a dial before identifying itself when another key answers | fault scenarios; the gates are tied together in the code | its own amendment ([draft](WAIVER_LAN_DIRECT_CUTOFF_AMENDMENT_DRAFT.md)) after its review and fixes |
| **Route hints** `ROUTE_HINTS_PRODUCTION_ENABLED` | Friends tell each other their current routes inside encrypted links, so cards need no address (release cards carry none, §9.1). [Spec](../protocol/RAVEN_ROUTE_HINTS_V1.md) | vectors (Rust and Python), two fuzz targets; field test: on throughout; a chatter bug (two messages a second) found and fixed | its amendment ([draft](WAIVER_LAN_DIRECT_ROUTE_HINTS_AMENDMENT_DRAFT.md)) |
| **Session renewal** `SESSION_RENEWAL_PRODUCTION_ENABLED` | Renew a friend's session while you are together, so later messages can wait almost a day | fault scenarios | the LAN amendment above |
| **Learning connectivity** `LEARNING_PRODUCTION_ENABLED` | Try first the route that worked before for that friend on that network; only reorders what is already allowed | a simulator acceptance gate in CI | its real rows and release record ([draft](WAIVER_LEARNING_DRAFT.md)) |
| **Bluetooth nearby** `NEARBY_PRODUCTION_ENABLED` | Messages between laptops with no network at all, verified contacts only. [Spec](../protocol/RAVEN_NEARBY_LINK_V1.md), [guide](NEARBY.md) | fake-radio tests in CI, vectors, the `rnp1_frame` fuzz target, BlueZ on emulated controllers (advisory); field test: a Bluetooth chain 10 / 10 both ways between two Macs | hardware rows for every operating-system pair (range, throughput, background behaviour, privacy capture); Windows has a partial backend and was not used for Bluetooth in the field test; a signed record ([draft](WAIVER_NEARBY_DRAFT.md)) |

## When a friend is offline

| Feature and gate | What it does | Evidence so far | Still needed |
|---|---|---|---|
| **Long message horizon** `LONG_HORIZON_PRODUCTION_ENABLED` | A message waits up to 7 days instead of a day; it is re-sealed into a fresh session when the friend is back | fault scenarios; field test: on for most rounds, waiting messages delivered each once after friends came back | its amendment's evidence ([draft](WAIVER_LAN_DIRECT_HORIZON_AMENDMENT_DRAFT.md)) |
| **Friend custody** `FRIEND_CUSTODY_PRODUCTION_ENABLED` (and its internet switch) | A friend both people verified keeps a sealed copy it cannot read, up to 24 hours. [Spec](../protocol/RAVEN_FRIEND_CUSTODY_V1.md) | carrier matrix C31-C34, fault scenarios, vectors, the `rfc1_frame` fuzz target; field test: keepers held and handed over messages on the home network and for a recipient on the hotspot | the errata amendment on deleting released copies signed ([draft](SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md)); real rows (a keeper on an offline network; over the internet, which needs the peer-to-peer carrier first); a signed record ([draft](WAIVER_FRIEND_CUSTODY_DRAFT.md)); Python parity for its vectors |
| **Custody handoff** `CUSTODY_HANDOFF_PRODUCTION_ENABLED` | Two friends in a row carry a sealed message on local networks | carrier matrix cases C54-C55, fault scenarios, shared vectors | its record ([draft](WAIVER_FRIEND_CUSTODY_HANDOFF_DRAFT.md)) after friend custody |
| **Sealed letters** `ASYNC_LETTER_PRODUCTION_ENABLED` | For a friend away longer than a day: a letter a friend keeps up to 7 days. [Spec](../protocol/RAVEN_ASYNC_LETTER_V1.md) | vectors (Rust and Python), the `ral1_decode` fuzz target; not covered by the field test | the horizon and friend custody first; the letters amendment in the custody draft |
| **Session reset** `SESSION_RESET_PRODUCTION_ENABLED`, `SESSION_RESET_RESTORE_PRODUCTION_ENABLED` | Recover when a friend lost their session state (reinstall with the same key, restore from a backup). [Spec](../protocol/RAVEN_SESSION_RESET_V1.md) | the `rsr1_frame` fuzz target, vectors | its amendment ([draft](WAIVER_LAN_DIRECT_SESSION_RESET_AMENDMENT_DRAFT.md)) |

## Groups and apps

| Feature and gate | What it does | Evidence so far | Still needed |
|---|---|---|---|
| **Groups** `GROUPS_PRODUCTION_ENABLED` | Small groups as pairwise sealed copies, with an admin-signed member list. [Spec](../protocol/RAVEN_GROUP_V1.md) | unit tests, a shared vector; field test: all group checks passed, including a member who was away | the long message horizon first; a fuzz target and Python parity for group frames; review; a release record (none drafted yet) |
| **App channel** `APP_CHANNEL_PRODUCTION_ENABLED` | Lets a local app (RDAP) send its own payloads over Raven sessions, between verified contacts. [Spec](../protocol/RAVEN_APP_PAYLOAD_V1.md) | CI tests (with the lab unlock for the lab type only), tests of the receiver guard (who, what, how big, how often), the `app_frame` fuzz target; RDAP over Raven on loopback over LAN and Tor | a real row between two computers; a stronger check of the calling program on macOS (today UID-only, the owner's decision Q6); a release record |

## Security and privacy features

| Feature and gate | What it does | Evidence so far | Still needed |
|---|---|---|---|
| **Attack sensing and responses** `SECURITY_EVENTS_…`, `SECURITY_RESPONSES_…`, `SUITE_FLOOR_PRODUCTION_ENABLED` | Local security events and fixed responses; refuse cipher suites below a floor. [Guide](SECURITY_EVENTS.md) | unit tests; on in the field test's desktop-app rounds | a false-positive check on real use; a signed amendment ([draft](WAIVER_SECURITY_SENSING_DRAFT.md)) |
| **Traffic-analysis measures** `LINK_PADDING_…`, `LINK_KNOCK_…`, `LISTEN_PORT_RANDOM_…`, `PAIR_SEED_PRODUCTION_ENABLED` | Pad frames to size classes; answer strangers with silence; a random port; rotating pair seeds | vectors (Rust and Python), fuzz targets `pad1_frame` and `rlk1_m1` | real captures; a signed amendment ([draft](WAIVER_TRAFFIC_ANALYSIS_DRAFT.md)) |
| **Lock while running** `LOCAL_PROTECTION_PRODUCTION_ENABLED` | Lock a running profile and drop its keys; auto-lock on sleep; a Raven passphrase | unit tests; field test: lock and unlock worked, messages sent during a lock arrived after unlock | a signed amendment ([draft](WAIVER_LOCAL_PROTECTION_DRAFT.md)) |
| **Security notices and updates** `ADVISORY_…`, `RELEASE_BUNDLE_…`, `MESH_UPDATE_PRODUCTION_ENABLED` | Signed security notices and release bundles, passed between friends even with no internet | vectors (Rust and Python), five fuzz targets | the release key ceremony: no build has release keys yet ([RELEASE_KEY_CEREMONY.md](RELEASE_KEY_CEREMONY.md)); a signed amendment ([draft](WAIVER_SECURITY_UPDATES_DRAFT.md)) |

## The session layer itself

The live session profile has no forward secrecy and no post-compromise security inside a session,
the device key is the identity key, and revocation is local only
([accepted risks](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) §4). The lab hybrid ratchet code
(`ATSAM_HYBRID_RATCHET_V2`, the "Full Braid" lab) is not wired to any carrier. Still needed: a
reviewed ratchet with forward secrecy and post-compromise security
([proposal](design/2026-10-ratchet-fs-pcs.md)), per-device keys
([design](design/2026-10-per-device-keys.md)), identity continuity
([spec, not approved](../protocol/RAVEN_IDENTITY_CONTINUITY_V2.md)), and the release gate of the
[errata](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md).

## Packages

Nothing is packaged yet; every build is a local build.

| Package | Still needed |
|---|---|
| **macOS** | an Apple Developer ID, signing with the hardened runtime, Apple notarisation and stapling ([checklist](SIGNING_NOTARIZATION_CHECKLIST.md)) |
| **Windows** | an Authenticode code-signing certificate, a signed installer |
| **Linux** | packages for the main distributions, published with SHA-256 checksums and a signature |
| **All** | Raven's own release signature (two of three offline keys, a public release log): the [key ceremony](RELEASE_KEY_CEREMONY.md) has not been held; reproducible builds (an advisory CI job compares two builds today) |

## How you can help

Review a spec against its code, run the field test on your own computers, add the missing fuzz
targets and Python parity listed in [EVIDENCE.md](EVIDENCE.md), and report what you find. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
