# RAVEN Port Mapping Profile V1

**Version:** 1 (a client profile of NAT-PMP, RFC 6886, and PCP, RFC 6887)
**Status:** Draft; **production disabled** (`PORT_MAP_PRODUCTION_ENABLED = false`,
`V6_PINHOLE_PRODUCTION_ENABLED = false`). Lab only: debug builds with `RAVEN_LAB_TEST_A=1` and
`RAVEN_LAB_PORT_MAP=1` (IPv6 pinholes also `RAVEN_LAB_V6_PINHOLE=1`). Release builds read no
switch. Enabling it in production needs the owner-signed port-mapping waiver (real rows R2b and
R2c).
**Audience:** re-implementers of the endpoint's router port mapping.
**Code:** `node/crates/raven-core/src/portmap.rs` (codec and the `MapperCore` state machine),
`portmap_gate.rs` (gates),
`portmap_fake.rs` (the test gateway). **Reference:** `protocol/reference/raven_protocol/portmap.py`.
**Vectors:** `shared-vectors/rvn1/portmap/` (`protocol/reference/generate_portmap.py`).

---

## 1. Scope and gates

Raven asks the router in front of it to forward its libp2p port (TCP and QUIC, default 7423) so
contacts can dial it directly, and on IPv6 to open a pinhole in the router's firewall. This
profile fixes the subset of NAT-PMP and PCP Raven sends and accepts, and how it acts on the
answers. It is not a Raven wire: no Raven peer ever sees these bytes (§13).

| Gate | What it opens | Lab unlock (debug builds) |
|---|---|---|
| `PORT_MAP_PRODUCTION_ENABLED` | NAT-PMP and PCP mapping of the egress IPv4 address | `RAVEN_LAB_TEST_A=1 RAVEN_LAB_PORT_MAP=1` |
| `V6_PINHOLE_PRODUCTION_ENABLED` | PCP MAP pinholes for the egress global IPv6 address (needs the gate above) | also `RAVEN_LAB_V6_PINHOLE=1` |

Both gates sit on the p2p carrier (`P2P_PRODUCTION_ENABLED`). With the gates closed the endpoint
keeps today's UPnP-IGD behaviour byte for byte. The harness switches
`RAVEN_LAB_PORTMAP_GATEWAY` (a fake gateway's `IP:PORT`) and `RAVEN_LAB_PORTMAP_LIFETIME`
(8..=7200 s) are read only in a debug build with the lab unlock. While
`RAVEN_LAB_PORTMAP_GATEWAY` names the router, UPnP-IGD never runs (its SSDP search would reach
the real network's router): not with the gates closed, and not after a silent probe (§6).

## 2. Who Raven talks to

- Only the OS default router of each family, on UDP port 5351 (NAT-PMP and PCP share it), from
  a socket connected to that address: a datagram from any other address or port is never read.
- IPv4: the default gateway; IPv6: the default router's address (PCP only).
- IPv4 only while that router is on the Internet path: the source address toward it must equal
  the egress address (the source address of a connected UDP socket toward a documentation
  address, `route_memory::egress_addrs`). A full-tunnel VPN leaves the LAN router as the default
  gateway while the egress is the tunnel; then nothing is asked, neither NAT-PMP, PCP nor UPnP,
  since a mapping there would publish the address the VPN hides (status `off_path`).
- The default router is looked up again on every network change; a new router starts a new probe
  and a new epoch (§7).

## 3. Opcodes

| Protocol | Sent | Never sent |
|---|---|---|
| PCP (version 2) | ANNOUNCE (0), MAP (1) | PEER (2), any option |
| NAT-PMP (version 0) | external address (0), UDP mapping (1), TCP mapping (2) | — |

## 4. Byte layouts

All integers are big-endian. An IPv4 address in a 16-byte PCP field is `::ffff:a.b.c.d`.

**NAT-PMP (RFC 6886, IPv4 only)**

| Message | Layout | Size |
|---|---|---|
| External address request | `00 00` | 2 B |
| External address response | `00 80 \| result u16 \| SSSoE u32 \| external IPv4` | 12 B |
| Map request | `00 op(1=UDP,2=TCP) \| 00 00 \| internal port u16 \| suggested external port u16 \| lifetime u32` | 12 B |
| Map response | `00 (128+op) \| result u16 \| SSSoE u32 \| internal port u16 \| mapped external port u16 \| lifetime u32` | 16 B |

- SSSoE: seconds since the router's start of epoch.
- Requests ask for a 7200 s lifetime. A delete is lifetime 0 with suggested port 0.
- Result codes: 0 ok, 1 unsupported version, 2 not authorized (refused), 3 network failure,
  4 out of resources, 5 unsupported opcode.

**PCP (RFC 6887)**

```
Request header (24 B)
  0   1  version          2
  1   1  R=0 | opcode     0 ANNOUNCE, 1 MAP
  2   2  reserved         0
  4   4  requested lifetime (s)
  8  16  client IP        must equal the datagram's source address
MAP opcode data (36 B, request and response)
 24  12  mapping nonce    §5
 36   1  protocol         6 TCP, 17 UDP
 37   3  reserved         0
 40   2  internal port
 42   2  suggested (request) / assigned (response) external port
 44  16  suggested (request) / assigned (response) external IP
Response header (24 B)
  0   1  version          2
  1   1  R=1 | opcode
  2   1  reserved
  3   1  result code
  4   4  lifetime (s)     granted; for an error, how long the error lasts
  8   4  epoch time (s)   §7
 12  12  reserved
```

- ANNOUNCE is the 24-byte header with lifetime 0. MAP is 60 B.
- The suggested external IP is `::ffff:0.0.0.0` for IPv4 and `::` for an IPv6 pinhole: Raven
  never asks for a particular address. The suggested external port is the internal port, or 0
  (§8).
- Raven sends no options.

**Reply acceptance.** A reply is read only from the gateway socket and only while a request is
outstanding. Anything else is ignored, like a datagram that never came:

| Reply | Accepted when |
|---|---|
| PCP | 24..=1100 bytes and a multiple of 4; version 2; R=1; the opcode of the request sent. A MAP response carries the 36 bytes of MAP data, except that an error may come with the header alone. Options: one of code 128 or more is skipped; one below 128 is mandatory to process, and since Raven sends none it is unknown and the reply is invalid; an option whose length (padded to 4) overruns the message makes it invalid. |
| NAT-PMP | version 0; opcode 128 + the opcode sent; exactly 12 bytes (external address) or 16 (mapping). |
| NAT-PMP-only router | to a PCP request: version 0, result 1, 8 bytes (12 or 16 accepted), opcode 0 (the RFC 6886 §3.5 figure) or 128 + the PCP opcode (what miniupnpd sends). The router speaks NAT-PMP only (RFC 6887 §9). |

A MAP response belongs to a mapping only when its nonce, protocol and internal port equal the
request's; any other MAP response is ignored.

## 5. Nonce

```
key   = SHA-256("raven/pcp-nonce-key/v1" || raven seed)
nonce = SHA-256(key || gateway IP (16 B, IPv4-mapped) || internal IP (16 B, IPv4-mapped)
                || protocol u8 || be16 internal port)[0..12]
```

The gateway IP is the router asked (the address the client's socket is connected to; an IPv6
router's link-local address without its scope). The nonce is the same for every request of one
internal endpoint behind one router, across restarts, so a renewal or a delete matches the
router's mapping (RFC 6887 §11.1 asks for the same nonce on every refresh). It reveals nothing
about the seed, another profile's nonces differ, and so do another router's (§12).

## 6. Probe, renewal and retransmission

- **Probe.** A PCP ANNOUNCE and a NAT-PMP external address request go out together at 0, 250,
  750 and 1750 ms; the probe ends at 3750 ms. A version-2 answer means PCP. A NAT-PMP-only
  answer (§4) means NAT-PMP at once; a successful NAT-PMP answer with no PCP answer means
  NAT-PMP 250 ms after it (a PCP answer in that time wins). Silence starts UPnP-IGD for IPv4, or
  the optional IGDv2 pinhole path for IPv6 (§11). IPv6 probes with PCP only. Mappings wanted
  during the probe are asked when it ends.
  - **Deviation:** RFC 6887 §8.1.1 retransmits after an initial 3 s, and RFC 6886 §3.1 after
    250 ms doubling up to 9 times. The probe uses the short schedule above for both, so a node
    on a network without a mapping router falls back to UPnP within 4 s. Mapping requests and
    renewals do not deviate.
- **One protocol per family per network:** PCP when it answers, else NAT-PMP, else UPnP.
- **Lifetime.** Every IPv4 mapping asks for 7200 s, and every IPv6 pinhole for 3600 s, so a
  pinhole a node can no longer delete (a crash, a sleep, another network) exposes the listener
  for at most an hour (a lab lifetime below that is kept). Each is renewed at half the granted
  lifetime (millisecond precision), however short the router makes it, so a lease is always
  renewed before it ends (RFC 6887 §11.2.1). The suggested external port is the internal port,
  then the port granted.
- **Renewals and mapping requests** retransmit with RFC 6887 §8.1.1 timing (initial 3 s,
  doubling): sent at 0, 3 and 9 s, given up at 21 s. After that the mapping is kept until its
  lifetime ends, then dropped; it is asked again at that end or after 30 min, whichever comes
  first.
- **NAT-PMP external address.** NAT-PMP mapping answers carry no address: the probe's answer
  gives it, and every renewal also asks for it again (§9).
- **Deletes** (lifetime 0, same nonce, suggested port 0) are sent when Raven no longer wants a
  mapping, on shutdown, and when the router refuses (§8) or turns out not routable (§9): for
  every mapping that may hold a lease, except a refused new request.

## 7. Epoch rule

RFC 6887 §8.5, also applied to NAT-PMP's SSSoE. For each reply with server epoch `curr`,
received `c` whole seconds after the previous reply (whose epoch was `prev`):

```
lost  if  curr + 1 < prev
      or  c + 2 < s - s/16      with s = curr - prev (0 when curr < prev), integer division
      or  s + 2 < c - c/16
```

The first reply from a router is always valid. Only replies that answer something the client
has outstanding count. When the server has lost its state, every wanted mapping is requested
again at once, except those with a request already in flight and those stopped (§8).

## 8. Result codes

| Code | Action |
|---|---|
| SUCCESS (0) | mapped: confirm the external address (§9) |
| CANNOT_PROVIDE_EXTERNAL (11) | retry at once with suggested port 0 (already 0: as NO_RESOURCES) |
| NO_RESOURCES (8), NETWORK_FAILURE (7) | retry after the response's lifetime (at least 60 s), at most 30 min |
| NOT_AUTHORIZED (2), ADDRESS_MISMATCH (12) | refused: stop asking this router (also as the answer to the probe); delete what it granted (§6) |
| UNSUPP_PROTOCOL (9) | drop that protocol, keep the other |
| any other code | refused for that mapping |

NAT-PMP codes map to the same actions: 2 as NOT_AUTHORIZED, 3 as NETWORK_FAILURE, 4 as
NO_RESOURCES, 5 as UNSUPP_PROTOCOL. A PCP answer is matched to its mapping by nonce, protocol and
internal port, a NAT-PMP answer by opcode and internal port; any other answer is ignored, as is
a PCP error without its MAP data. A router that refused, or whose address is not routable (§9),
is not asked again until the next network change; mappings it held are deleted and reported
gone.

## 9. External address

- An external IPv4 address that is not global (CGN 100.64.0.0/10, RFC 1918, link-local,
  documentation and the other ranges `p2p_route::is_global_ipv4` refuses) means the router is
  itself behind another NAT: NonRoutable. Nothing is confirmed, and the mappings are deleted
  (lifetime 0). A lab harness may accept loopback.
- NonRoutable names the class: 100.64.0.0/10 is the provider's carrier-grade NAT (status
  `behind_another_nat`: a relay is required); any other non-global address is another router of
  the same site, a double NAT (status `double_nat`: bridge mode on the outer router, or a port
  forward there, fixes it).
- A changed external address (or port) expires the old confirmation, then confirms the new
  one; with PCP the other mappings are renewed at once to learn theirs.
- A confirmed mapping becomes the listen address `/ip4/EXT/tcp/PORT` or
  `/ip4/EXT/udp/PORT/quic-v1`, and for an IPv6 pinhole `/ip6/ADDR/tcp/PORT` or
  `/ip6/ADDR/udp/PORT/quic-v1`.

## 10. IPv6 pinholes

- Only the egress global IPv6 address of the listen addresses is mapped (it may be a temporary
  address; the pinhole follows listen-address changes). VPN, container and other non-egress
  addresses are never mapped.
- The client IP field and the datagram's source are that address; the suggested external IP is
  `::`. A firewall returns the same address and port.
- Pinholes need `V6_PINHOLE_PRODUCTION_ENABLED` (or its lab switch) and their own consent: an
  existing UPnP yes covers IPv4 mapping only.

## 11. Optional IGDv2 subset

Built only if a real row shows a router with UPnP-IGDv2 and no PCP.

- SSDP ST `urn:schemas-upnp-org:service:WANIPv6FirewallControl:1`.
- SOAP actions: GetFirewallStatus; AddPinhole (RemoteHost "", RemotePort 0, InternalClient = the
  egress IPv6 address, InternalPort = the libp2p port, Protocol 6 or 17, LeaseTime 3600)
  returning a UniqueID; UpdatePinhole(UniqueID, 3600) at half the lease; DeletePinhole(UniqueID).
- Responses are capped at 64 KiB, with no XML entity expansion.

## 12. Privacy

- No request carries a Raven identity, PeerId or contact. Besides the internal address and port
  the router sees on every packet, a PCP request carries the nonce.
- The nonce is a keyed hash (§5): it differs per profile and per router address, so a profile
  that gets the same internal address on two networks still sends other nonces to their
  routers. Two networks whose routers share an address (192.168.1.1 is common) and give the
  same internal address do see the same nonce: the nonce must stay stable across restarts on one
  network (RFC 6887 §11.1), and nothing else the client knows without stored state tells such
  networks apart.
- Logs name the protocol and the port only, never an IP address.
- This codec writes nothing to disk. Port-mapping state a node keeps is sealed at rest like
  every other profile file (`docs/design/2026-10-at-rest-metadata.md`).

## 13. Old-peer safety

Only the router sees these bytes. No Raven wire, card, route hint or IPC format changes with
this profile, and with the gates closed the endpoint behaves exactly as before (UPnP-IGD).

## 14. Vectors

`shared-vectors/rvn1/portmap/`, all `deterministic: true`, generated by
`protocol/reference/generate_portmap.py` (`--check` verifies the files on disk). The replies are
a router's at epoch 3600 s with external IPv4 11.0.2.9; raven-core's `portmap_fake` reproduces
them from the request vectors.

| File | Content |
|---|---|
| `natpmp_extaddr_req_001`, `natpmp_extaddr_resp_001` | NAT-PMP external address request and response |
| `natpmp_map_tcp_req_001`, `natpmp_map_resp_001` | NAT-PMP TCP mapping request and response |
| `pcp_announce_req_001`, `pcp_announce_resp_001` | PCP ANNOUNCE request and response |
| `pcp_map_v4_req_001`, `pcp_map_v4_resp_001` | PCP MAP, IPv4 TCP 7423 from 192.168.1.20 to router 192.168.1.1, nonce from seed `0x51…` |
| `pcp_map_v4_resp_002` | the same response with an optional option (skipped) |
| `pcp_map_v4_delete_001` | PCP MAP delete (lifetime 0) |
| `pcp_map_v6_req_001` | PCP MAP pinhole request, IPv6 UDP, lifetime 3600 s |
| `pcp_reply_natpmp_only_001`, `_002` | NAT-PMP-only answers to a PCP request (opcode 0x81; opcode 0) |
| `pcp_epoch_validity_001` | §7 table: first reply, one and two seconds back, restart, the 1/16 bounds both ways |
| `pcp_nonce_001` | §5 key and nonces, another profile's, and the same endpoint behind another router |
| `negative/*` | wrong opcode, R bit clear, length not a multiple of 4, unknown mandatory option, unknown version, MAP SUCCESS without MAP data, short NAT-PMP response; `expected.error` names the reason |
