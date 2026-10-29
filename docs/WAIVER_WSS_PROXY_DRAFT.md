# DRAFT owner waiver: relays over WSS on TCP 443 and HTTPS proxies (Phase 4)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file (the doc comment of `wss_gate.rs` only points at "the WSS/proxy
> waiver"). `WSS_PRODUCTION_ENABLED` and `WSS_PROXY_PRODUCTION_ENABLED` stay
> `false` until the owner signs a final copy (renamed to
> `docs/WAIVER_WSS_PROXY_<date>.md`), the exit conditions in §7 are met, and
> each gate is flipped on its own, in its own reviewed commit (owner decision
> O4-16). Nothing in Phase 4 flips a gate.

| | |
|---|---|
| **Waiver ID** | `WAIVER-WSS-PROXY-<date>` (to be assigned on signature) |
| **Extends** | [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md) (the p2p carrier and the relay role) and its Phase 2 amendment (§9 there: relays on TCP 443 and the relay kit). It can be signed only together with, or after, both. Its §6 extension rule names "relays on 443" as a lapse without a new record; this is that record |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-22 |
| **Review by** | the review-by date of the p2p relay waiver |
| **Withdrawal** | Set `WSS_PROXY_PRODUCTION_ENABLED = false` (proxy dials only) or both flags `false` in `node/crates/raven-core/src/wss_gate.rs`. The const asserts there keep the proxy gate off while WSS is off, and WSS off while `P2P_PRODUCTION_ENABLED` is off |
| **Spec** | [`RAVEN_WSS_TRANSPORT_V1.md`](../protocol/RAVEN_WSS_TRANSPORT_V1.md) (RWS1) |
| **Design** | the any-network reachability plan (not published) §3 "Phase 4" and decision D10; the Phase 4 plan `docs/roadmap/plans/phase45-design.json` (`.designs[0]`, owner decisions O4-1 to O4-8 and O4-16) |
| **User docs** | `INSTALL_macOS.md`, `INSTALL_Linux.md`, `INSTALL_Windows.md` (section "libp2p: relay and hole punching", "Networks that let only web traffic out"); [`RELAY_KIT.md`](RELAY_KIT.md) |
| **Real rows** | an unpublished test checklist: R8w and R8p required, R8m optional |

## 1. Why a waiver is needed

Some networks let only web traffic out: TCP 443, often only through an HTTPS
proxy, sometimes only TLS. Phase 2 put a raw libp2p listener on a relay's TCP
443, which passes a port filter but not a TLS-only gate or a proxy. RWS1 puts
libp2p inside a WebSocket inside TLS on the relay's TCP 443, and lets an
endpoint reach that relay through the network's HTTP CONNECT proxy. It is a
new public listener protocol on the relay, a new outbound path on the
endpoint, and a new source of local settings (proxy sources), on top of a
carrier that is itself only waived (the p2p relay draft). Turning it on is a
scope extension and needs this record.

## 2. Scope (exactly what is covered)

Covered, and only in this combination:

- **the WSS transport** (RWS1 §3-§5): libp2p Noise + Yamux inside a binary
  WebSocket (Raven's own RFC 6455 subset, owner decision O4-1, no new crate)
  inside TLS 1.3 on TCP, with ALPN `http/1.1`, SNI only for a name, no client
  certificate and no session resumption; addresses `.../tcp/<P>/tls/ws/p2p/<relay
  PeerId>` (with `/dns`, `/dns4`, `/dns6` or `/sni/`) in `via=`, card v3
  `relay=`, route hints and the saved relays;
- **the certificate model** (O4-2, RWS1 §4): the client accepts any server
  certificate but verifies the TLS 1.3 handshake signature under the presented
  key; the relay is authenticated by libp2p Noise against the mandatory
  `/p2p/<id>`, and the contact inside by the Raven link. A relay serves either a
  fresh self-signed P-256 certificate made at each start (never stored) or the
  operator's PEM files (`--wss-cert`, `--wss-key`); there is no ACME inside
  Raven;
- **the two-protocol 443 listener** (O4-3, RWS1 §6): `raven-node relay --wss
  <PORT|IP:PORT>` splits each accepted TCP connection by its first byte, `0x16`
  to TLS/WSS and `0x13` to raw libp2p; a raw listener and a WSS listener never
  share a port; the friend relay has no WSS listener in V1;
- **the CONNECT client** (RWS1 §7): an `http://` proxy with no authentication
  or Basic, one CONNECT per WSS relay dial, the relay's name left to the proxy
  to resolve, no User-Agent; raw libp2p TCP is never proxied;
- **proxy sources** (O4-4, O4-5, RWS1 §8): `--p2p-proxy`, then
  `RAVEN_P2P_PROXY`, then `node_policy.json` `p2p_proxy` (`raven node proxy
  auto|off|http://host:port`, never with a user name or password), then
  `HTTPS_PROXY` / an `http://` `ALL_PROXY` with `NO_PROXY`, then the system
  setting (macOS SCDynamicStore, Windows WinHTTP for the current user; Linux
  reads the environment only); `HTTP_PROXY` is never read;
- **restricted mode** (O4-6, RWS1 §9): while a reservation rides a proxied
  WSS connection the endpoint offers no hole-punch or AutoNAT candidates and
  dials no direct contact address;
- **status texts** for what Raven cannot use (PAC/WPAD, NTLM/Negotiate, SOCKS,
  `https://` proxies, a 407 it cannot answer): words only.

Not covered (all remain held): PAC or WPAD evaluation, NTLM, Negotiate or
Kerberos proxy authentication, SOCKS and `https://` proxies, proxying raw
libp2p TCP or QUIC, certificate pinning (`certhash`), any compiled-in, default
or community relay (decision D1 stands: no community relay list), a WSS
listener on the friend relay, ACME inside Raven, censorship resistance (D10:
out of scope; the TLS fingerprint is not a browser's), and a relay behind a
local reverse proxy (unsupported: loopback is exempt from the per-IP limits).

## 3. Holds

| Hold | Status at signature (to fill) | Waived? |
|---|---|---|
| The p2p relay waiver and its Phase 2 amendment are signed | Both unsigned drafts | **Not waived**: this record cannot stand alone |
| Automated gates (§7 list) green on their runners | Built; carrier_matrix C40-C42 and the fault scenarios ran on macOS in this lane; the netns cases are advisory | Not waived |
| Independent review of the public libp2p surface (p2p relay waiver §3.1 hold 3) | The WSS listener, the first-byte demux and the WebSocket subset (about 1,200 lines) join that surface | Follows the owner's decision on hold 3 there |
| Real rows | R8w and R8p pending, owner-run | **Not waived** |

## 4. Residual risks accepted

1. **Accept-any TLS lets an interceptor learn the endpoint's PeerId.** Any
   active TLS interceptor (a TLS-inspecting corporate proxy, or an attacker on
   the path) can terminate TLS and then answer the libp2p Noise handshake as if
   it were the relay. It cannot pass the `/p2p/<id>` check, so the dial fails
   and no Raven byte is sent, but it learns the dialling endpoint's libp2p
   PeerId from the handshake. Raw TCP 7423 (and Phase 2's raw 443) has exactly
   this exposure today. The PeerId is stable unless the user turns PeerId
   rotation on (Phase 4, held by its own gate; §11 of the p2p relay waiver
   draft). It is never a Raven identity.
2. **TLS-inspecting proxies.** A self-signed relay passes port filters,
   TLS-presence gates and plain CONNECT proxies, but fails behind interception;
   that needs an operator certificate for a real domain (`/dns4/<domain>`, SNI
   kept) and a proxy that allows WebSocket upgrades. Many proxies also refuse
   CONNECT to raw IPs or uncategorised domains.
3. **Fingerprint.** rustls with the post-quantum key share sends a large
   ClientHello that does not look like a browser; deep packet inspection can
   single it out (D10: anti-censorship is out of scope).
4. **Enterprise setups that do not work**: NTLM/Negotiate, PAC/WPAD, SOCKS,
   `https://` proxies. The status says why, and the user can name an `http://`
   proxy by hand. Windows turns "Automatically detect settings" (WPAD) on by
   default: raven-node does not count that setting alone (no manual proxy and
   no script URL) as a proxy (Phase 4 review B-2), so it dials directly and
   its status names no proxy. A network that really needs WPAD gets no
   proxy-script hint; its user names an `http://` proxy by hand.
5. **Shared egress IP.** Users behind one proxy share its IP, and the relay's
   per-IP caps (4 reservations, 8 established connections per IP) can lock some
   of them out (plan risk 4).
6. **Proxy credentials** are sent as Basic over plain HTTP to the proxy, and
   live in the process environment, which other programs of the same user can
   read. Raven never writes them to disk; an OS store the user chooses for the
   service's environment may.
7. **Port 443 needs a privilege** on Linux (CAP_NET_BIND_SERVICE, granted by the
   kit unit's `AmbientCapabilities` line) and a Defender Firewall prompt on
   Windows; macOS 10.14+ is believed to allow it without root (to verify in
   R8w).
8. **Timeouts.** The 10 s connection timeout covers proxy connect, CONNECT,
   TLS 1.3 with the post-quantum share, WebSocket, Noise and Yamux; slow
   proxies may need more. Measure in R8p before changing it.
9. **Identify behind a proxy** observes the proxy's IP. Restricted mode stops
   the pointless hole punches when the proxied path is known; a 443-only
   network without a proxy still tries DCUtR and offers the real NAT IP to
   contacts, which D4 allows.
10. **Old peers.** An older raven-node rejects IPC dial strings with `/tls/ws`
    (those messages stay queued with a readable error), a WSS relay saved in
    `p2p_relays` makes an older raven-node refuse its p2p settings after a
    downgrade, and a `raven-card/2` never carries a WSS via (its raw sibling is
    written instead).
11. **Captive portals** fail until the user logs in ("restricted /
    unreachable" only); proxy tunnels with a maximum lifetime cause
    reservation churn, which the re-reserve logic absorbs.

## 5. Compensating controls in place

- Peer authentication never depends on TLS: Noise against `/p2p/<id>`, then
  RIH1 inside the Raven link; the verifier still checks the TLS 1.3
  signature. The custom verifier exists only in `raven-swarm/src/wss/tls.rs`,
  enforced by `the_custom_verifier_is_built_only_in_wss_tls`.
- TLS 1.3 only, no tickets, no resumption, ALPN `http/1.1` on both sides
  (`client_config_is_tls13_only_alpn_http11_no_resumption`,
  `server_config_is_tls13_only_alpn_http11_no_tickets`). The ephemeral
  certificate carries no libp2p extension and no Raven or rcgen strings, and
  is never stored.
- The relay's peer gate, allow-list and limits are the same for raw and WSS
  connections; the first-byte check holds a pending socket at most 10 s,
  bounded by `max_pending_incoming`.
- Proxy credentials only at runtime: `raven node proxy` refuses any `@`,
  `node_policy.json` never holds one, and a proxy URL's `Debug`/`Display`
  redact it (`Zeroizing` in memory). A saved proxy setting is sealed at rest
  with the policy's relay addresses (`node_policy_peers.rms`).
- Logs carry categories and counts only: no proxy URL, host or credential, no
  address, no PeerId (s50 and s51 check the logs for them).
- With the proxy gate closed no dial uses a proxy: `ProxySource::proxy_for`
  answers "direct" before reading the environment or the system (the status
  reads them only to say `held`). With the WSS gate closed, `relay --wss`
  exits 2 with `WSS_HOLD`, and a WSS via is dialled as its raw sibling with
  one `WSS_HOLD` line (C42).
- Fuzz targets `ws_frame` and `proxy_setting`; vectors under
  `shared-vectors/rvn1/wss/` and `p2p/via_001.json` checked by the Python
  reference and the Rust tests.

## 6. Conditions

This waiver lapses, and both flags MUST be set back to `false`, if any of these
happens before it is renewed:

- certificate validation semantics change (the TLS 1.3 signature check is
  dropped, a pin is added, or the custom verifier is built anywhere but
  `wss/tls.rs`);
- proxy credentials are persisted by Raven, or a log line carries a proxy
  host, URL or credential;
- PAC, WPAD, NTLM, Negotiate or SOCKS support is added, or raw libp2p is
  proxied, without a new record;
- a relay is compiled in or set by default, or a community relay list is
  added (D1);
- a raw listener and a WSS listener are allowed to share a port;
- C40-C42, s50 or s51 is disabled, or fails on any of its runners for more
  than one release;
- the p2p relay waiver or its Phase 2 amendment lapses or is withdrawn;
- the review-by date passes without renewal.

## 7. Exit conditions before signature

All open until recorded; none of the software runs replaces the real rows.

- **carrier_matrix** (`node/crates/raven-node/tests/carrier_matrix.rs`,
  `--ignored`, ubuntu, macOS and Windows): C40 a relay's WSS listener on
  loopback, WSS and raw on one port, delivery both ways; C41 a network that
  lets only its HTTPS proxy out (a name only the proxy resolves, an outage
  with 3 queued messages each delivered once); C42 the WSS gate closed
  (`relay --wss` refused, a WSS via dialled as its raw sibling).
- **lan_fault_matrix** (`RAVEN_FAULT_WSS=1`, macOS and Linux): s50
  `proxy_outage_and_return`, s51 `proxy_wants_negotiate`.
- **netns** (`node/scripts/netns_restrictive.sh`, advisory job
  `restrictive-net-linux`, Linux, root): `only443`, `tlsonly`, `proxyonly`,
  each ending "delivered 10/10 both ways"; advisory until its own green
  streak.
- **CI coverage**: the raven-swarm `wss` tests on the macOS and Windows jobs
  too (today only the Linux all-features job runs them; P4.7 open item).
- **Protocol and paperwork**: the RWS1 vectors regenerate unchanged
  (`generate_wss.py`), `scripts/freeze_protocol_hashes.sh --check` green, the
  dependency audit unchanged (no new crate), and `node/Cargo.lock` with no
  new package for Phase 4.
- **Real rows** (an unpublished test checklist,
  with `node/scripts/r8_only_443.sh` / `r8_only_443.ps1`): **R8w** (only TCP 443
  and DNS out; a VPS relay with `--wss 443`; delivered 10/10 both ways,
  relayed, relay transport `wss`) and **R8p** (nothing out but an HTTPS proxy
  set in the system; 10/10 both ways, relay transport `wss-proxy`) on at least
  one OS each, with macOS's non-root 443 bind recorded. **R8m** (a
  TLS-intercepting proxy with an operator certificate) is optional; record the
  result either way.
- **Owner decisions** recorded at signature (the recommended options are the
  ones built): O4-1 (Raven's own WebSocket subset, zero new crates), O4-2
  (accept-any TLS with the handshake signature checked; certbot with a
  restart hook documented), O4-3 (one port, two protocols; the kit units keep
  raw 443 until the WSS flip), O4-4 (proxy policy: `auto` by default, `http://`
  with none or Basic only, credentials at runtime only), O4-5 (WinHTTP on
  Windows), O4-6 (restricted mode), O4-7 (libp2p/dns stays excluded), O4-8
  (the `WSS_PROXY_*` names).

## 8. Frozen specs and files at the flips

1. [`protocol/RAVEN_WSS_TRANSPORT_V1.md`](../protocol/RAVEN_WSS_TRANSPORT_V1.md):
   its status line (production disabled, lab only) and §1 activation; the RWS1
   row of [`protocol/PROTOCOL_VERSIONS.md`](../protocol/PROTOCOL_VERSIONS.md).
2. [`protocol/RAVEN_NAT_CONNECTIVITY_V1.md`](../protocol/RAVEN_NAT_CONNECTIVITY_V1.md)
   §2 (composition: the WSS transport and the two-protocol listener) and §4
   (relay addresses may be `/tls/ws` forms), on top of the p2p relay
   waiver's §8 and §9.6.
3. The relay kit units (`node/scripts/install/relay_common.sh` and the three
   installers) move their raw TCP 443 listener to `--wss 443` in the WSS flip
   commit (O4-3), with `docs/RELAY_KIT.md`.
4. `docs/PROTOCOL_FREEZE_HASHES_V1.md` regenerated with
   `scripts/freeze_protocol_hashes.sh` in the same commit.

## 9. Signature

Not signed.
