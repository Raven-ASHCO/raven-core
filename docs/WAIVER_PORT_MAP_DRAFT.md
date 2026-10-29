# DRAFT owner waiver: router port mapping (NAT-PMP, PCP) and IPv6 pinholes (Phase 4)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file (the doc comment of `portmap_gate.rs` only points at "the
> port-mapping waiver"). `PORT_MAP_PRODUCTION_ENABLED` and
> `V6_PINHOLE_PRODUCTION_ENABLED` stay `false` until the owner signs a final
> copy (renamed to `docs/WAIVER_PORT_MAP_<date>.md`), the exit conditions in §7
> are met, and each gate is flipped on its own, in its own reviewed commit
> (owner decision O4-16). Nothing in Phase 4 flips a gate.

| | |
|---|---|
| **Waiver ID** | `WAIVER-PORT-MAP-<date>` (to be assigned on signature) |
| **Extends** | [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md), whose §2 covers UPnP-IGD (IPv4) after the user's yes and lists "libp2p-upnp has no NAT-PMP or PCP". It can be signed only together with, or after, that record |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-22 |
| **Review by** | the review-by date of the p2p relay waiver |
| **Withdrawal** | Set `V6_PINHOLE_PRODUCTION_ENABLED = false` (pinholes only) or both flags `false` in `node/crates/raven-core/src/portmap_gate.rs`. The const asserts there keep pinholes off while mapping is off, and mapping off while `P2P_PRODUCTION_ENABLED` is off. With both off the endpoint does Phase 1's UPnP-IGD, byte for byte |
| **Spec** | [`RAVEN_PORT_MAPPING_V1.md`](../protocol/RAVEN_PORT_MAPPING_V1.md) (a client profile of RFC 6886 and RFC 6887; not a Raven wire) |
| **Design** | [`design/2026-10-any-network-reachability.md`](design/2026-10-any-network-reachability.md) §3 "Phase 4" and decision D11; the Phase 4 plan `docs/roadmap/plans/phase45-design.json` (`.designs[1]`, owner decisions O4-9 to O4-11 and O4-16) |
| **User docs** | `INSTALL_macOS.md`, `INSTALL_Linux.md`, `INSTALL_Windows.md` (section "Router port mapping") |
| **Real rows** | [`P4_REAL_ROWS_CHECKLIST.md`](P4_REAL_ROWS_CHECKLIST.md): R2b and R2c |

## 1. Why a waiver is needed

Phase 1 maps the p2p port only through UPnP-IGD on IPv4, after the user's yes.
Many routers (some Apple and ISP boxes, OpenWrt with UPnP off) speak only
NAT-PMP or PCP, and on IPv6 the router's firewall, not a NAT, keeps contacts
out. Phase 4 adds an in-tree NAT-PMP and PCP client and PCP IPv6 pinholes.
Each changes state on the user's router, and a pinhole makes the listener
reachable from the whole IPv6 internet. That is a new effect outside this
computer and a scope extension of the p2p carrier's record.

## 2. Scope (exactly what is covered)

Covered, and only in this combination:

- **PORT_MAP: IPv4 mapping** of the endpoint's p2p port (TCP and UDP/QUIC,
  7423 by default; the friend relay keeps Phase 2's UPnP-IGD for 7427) on the
  OS default router only, UDP 5351, from a socket connected to that router: PCP MAP first, then
  NAT-PMP, then UPnP-IGD, one protocol per family per network (O4-11). Only the
  egress IPv4 address is mapped; VPN, container and other non-egress addresses
  never are. Leases of 7200 s, renewed at half; the router is searched again
  on every network change; an epoch reset ("router restarted") maps again.
- **Consent** (O4-11): the existing UPnP answer (`node_policy.json` `upnp`,
  `raven node upnp on|off`, the ask-once question) also covers NAT-PMP and PCP
  for IPv4, because the effect on the router is the same. With the gate open
  the question names all three protocols.
- **V6_PINHOLE: IPv6 pinholes** through PCP MAP for the egress global IPv6
  address only (it may be a temporary address; the pinhole follows it), with
  leases of 3600 s, and **its own consent**: `node_policy.json` `v6_pinhole`,
  asked once after a UPnP yes on a terminal, or `raven node ipv6-pinhole
  on|off`. An existing UPnP yes never implies it. Only PCP pinholes: the
  optional UPnP-IGDv2 WANIPv6FirewallControl path was not built (P4.22 skipped
  by owner decision O4-9, because no real row showed a router with IGDv2 and
  no PCP), so this gate covers PCP pinholes only.
- **"Behind another NAT"**: a router whose external address is private or
  carrier-grade (100.64/10) gets its mappings deleted and the status says a
  relay is required.
- **The deterministic nonce** (RAVEN_PORT_MAPPING_V1 §5): a keyed hash of the
  profile's seed and the internal endpoint, the same across restarts, so a
  renewal or a delete matches the router's mapping (RFC 6887 §11.1). It
  reveals nothing about the seed, and another profile's nonces differ.

Not covered: UPnP-IGDv2 pinholes (not built; a new record if a real row ever
needs them), NAT-PMP or PCP for the friend relay's port, mapping any port but
the endpoint's p2p port, mapping for
another host, port prediction (D13), and any mapping without the user's yes.

`raven doctor --router` is **not** part of this scope: it is an explicit,
user-run, read-only probe (one PCP ANNOUNCE, one NAT-PMP address query, one
SSDP search to the user's own router; it maps nothing and stores nothing),
allowed in release builds by owner decision O4-10.

## 3. Holds

| Hold | Status at signature (to fill) | Waived? |
|---|---|---|
| The p2p relay waiver is signed | Unsigned draft | **Not waived**: this record cannot stand alone |
| Automated gates (§7 list) green on their runners | Built; C43, C44 and s52 ran on macOS in this lane; the netns cases are advisory | Not waived |
| Real rows | R2b and R2c pending, owner-run | **Not waived** |

## 4. Residual risks accepted

1. **Removal is best effort only.** A clean stop sends lifetime-0 deletes for
   every mapping, but a crash, a power loss, a sleep or a network change can
   leave a mapping on the router until its lease ends (up to 7200 s, a pinhole
   up to 3600 s). A router that ties mappings to the source port instead of
   checking the nonce may also refuse a renewal after a restart until the old
   lease expires. This waiver does not promise removal, and the consent text
   must not either (O4-11).
2. **Scannable listener.** An IPv4 mapping and, more so, an IPv6 pinhole make
   the p2p listener reachable from the whole internet. The peer gate refuses
   strangers right after the libp2p handshake, but every scanner learns the
   node's PeerId and that it speaks libp2p. PeerId rotation (Phase 4, its own
   gate, §11 of the p2p relay waiver draft) is recommended together with
   pinholes; it is opt-in.
3. **Routers differ.** PCP and NAT-PMP are implemented inconsistently:
   success without forwarding, odd lifetimes, epochs that reset on WAN
   reconnect. A mapping the router "confirmed" but does not forward makes
   contacts try a dead direct address first, which can cost one connection
   timeout before the circuit. R2b and R2c are the only true proof.
4. **macOS Local Network privacy** can block the launchd agent's PCP and SSDP
   packets to the router, as it can UPnP's; Windows Defender Firewall can still
   block what the router now forwards; a Linux container may have no
   `/proc/net/route`. Each shows "none found" and delivery falls back to
   relays; `raven doctor --router` says when macOS refused the packets.
5. **Carrier-grade NAT**: a mapping on the home router cannot help when the
   router is itself behind another NAT; Raven detects that and deletes.
6. **Router packets** on every network change and renewals at most hourly:
   negligible next to the 15 s relay pings, to be measured with the real rows.

## 5. Compensating controls in place

- Nothing is sent to a router without the user's yes (IPv4) and a separate
  yes (IPv6), and with a gate closed nothing is sent at all beyond Phase 1's
  UPnP (C43's gate-closed case: the fake router receives 0 packets).
- Only the OS default router is asked, from a connected socket; a datagram
  from anyone else is never read. Replies go through a strict decoder
  (vectors under `shared-vectors/rvn1/portmap/`, fuzz target
  `portmap_reply`).
- Logs and IPC name the protocol, ports, renewals and restarts only, never an
  IP address; no request carries a Raven identity, PeerId or contact.
- Port-mapping state lives in memory; nothing about the router or a lease is
  written to disk (`v6_pinhole` is a plain consent in `node_policy.json`, like
  `upnp`; `docs/design/2026-10-at-rest-metadata.md`).
- Harness switches (`RAVEN_LAB_PORTMAP_GATEWAY`, `RAVEN_LAB_PORTMAP_LIFETIME`)
  are read only in a debug build with the lab unlock; tests and the fault
  matrix use a fake gateway on loopback, never the real router.

## 6. Conditions

This waiver lapses, and both flags MUST be set back to `false`, if any of these
happens before it is renewed:

- a mapping or pinhole is requested without the user's consent, an IPv6
  pinhole is implied by the UPnP answer, or the consent text promises
  removal;
- a non-egress address (VPN, container) or a port other than the
  endpoint's p2p port is mapped through NAT-PMP or PCP, or a router other
  than the OS default one is asked;
- a log line, IPC field or stored file carries a router, external or internal
  IP address;
- UPnP-IGDv2 pinholes or port prediction are added without a new record;
- C43, C44 or s52 is disabled, or fails on any of its runners for more than
  one release;
- the p2p relay waiver lapses or is withdrawn;
- the review-by date passes without renewal.

## 7. Exit conditions before signature

All open until recorded; none of the software runs replaces the real rows.

- **carrier_matrix** (`--ignored`, ubuntu, macOS and Windows; the Unix-only
  steps skip themselves on Windows): C43 PCP and NAT-PMP map the port and
  follow router restarts and network changes (lifetime-0 deletes on stop,
  NAT-PMP only, behind another NAT, a silent router, the gate closed); C44 a
  PCP IPv6 pinhole needs its own consent (skipped without IPv6 loopback).
- **lan_fault_matrix** (`RAVEN_FAULT_PORTMAP=1`, macOS and Linux): s52
  `router_restart_remaps`.
- **netns** (`node/scripts/netns_nat_dcutr.sh` with miniupnpd-nftables, owner
  decision O4-15; advisory until each has its green streak): `pcp`, `pcp-cgn`,
  `v6pin` (advisory only).
- **Vectors and fuzzing**: `generate_portmap.py` regenerates
  `shared-vectors/rvn1/portmap/` unchanged; the `portmap_reply` fuzz target
  in the stable smoke.
- **Real rows** ([`P4_REAL_ROWS_CHECKLIST.md`](P4_REAL_ROWS_CHECKLIST.md)):
  **R2b** (a NAT-PMP-only or PCP-only router: direct with no relay, 10/10
  both ways) and **R2c** (IPv6 behind the router's default firewall with a PCP
  pinhole: inbound direct over IPv6), each on every OS the owner can test, plus
  the `raven doctor --router` lines of every router the owner can reach.
- **Evidence note (O4-9)**: P4.22 (UPnP-IGDv2 IPv6 pinholes) was skipped
  because no `raven doctor --router` result or R2c run showed a router with
  `router_ipv6_firewall_control=yes` and `router_pcp=no`. If R2c finds one,
  the IGDv2 step is built first and this draft is amended; until then
  V6_PINHOLE covers PCP pinholes only.
- **Owner decisions** recorded at signature (the recommended options are the
  ones built): O4-9 (sequencing: probe first, PCP/NAT-PMP and PCP pinholes
  lab-gated, IGDv2 only with evidence), O4-10 (`doctor --router` in release as
  a read-only probe), O4-11 (consent and behaviour: the UPnP yes covers IPv4,
  pinholes ask once, PCP then NAT-PMP then UPnP, 7200 s / 3600 s leases,
  best-effort removal), O4-15 (the CI package).

## 8. Frozen specs and files at the flips

1. [`protocol/RAVEN_PORT_MAPPING_V1.md`](../protocol/RAVEN_PORT_MAPPING_V1.md):
   its status line and §1 gate table; its row in
   [`protocol/PROTOCOL_VERSIONS.md`](../protocol/PROTOCOL_VERSIONS.md).
2. The p2p relay waiver's §2 "reachability helpers" sentence ("libp2p-upnp has
   no NAT-PMP or PCP") and the INSTALL guides' "Router port mapping" sections.
3. `docs/PROTOCOL_FREEZE_HASHES_V1.md` regenerated with
   `scripts/freeze_protocol_hashes.sh` in the same commit.

## 9. Signature

Not signed.
