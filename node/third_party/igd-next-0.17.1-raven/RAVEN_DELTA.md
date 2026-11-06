# Raven delta over igd-next 0.17.1

Upstream: crates.io `igd-next` 0.17.1 (MIT, Darius C and Simon Bernier
St-Pierre; sha256 `de7238d487a9aff61f81b5ab41c0a841532a115a398b5fa92a2fadd0885e2581`),
the UPnP-IGD client of `libp2p-upnp` 0.7.0, which `raven-swarm` builds with
feature `p2p-host` (the endpoint and relay hosts of raven-node). Wired through
`[patch.crates-io]` in `node/Cargo.toml`; outside the workspace (`exclude`).
The commit before the patch is the unchanged crates.io copy (without the
`Cargo.lock` it ships).

## Why

STRANGER-UPNP-1 (security review 2026-11, owner decision 1). UPnP-IGD has no
authentication. The async search took the first SSDP answer from anyone on
the network and fetched the description its LOCATION named, on any host;
it read every description and SOAP response whole, without a limit, and
xmltree parsed it by recursion, one stack frame per element level. A
stranger on the LAN could answer first with a description nested a few
thousand levels deep: the stack of the tokio worker overflowed, and a stack
overflow aborts the whole raven-node process (it is no panic). It could also
name itself the gateway, and so the external address (raven-swarm holds that
back since STRANGER-UPNP-2, `VettedUpnp`).

## Change

| File | Change |
|---|---|
| `src/raven_delta.rs` (new) | `set_gateway_lookup(fn() -> Option<Ipv4Addr>)`: set once per process (a later call changes nothing), asked by every `SearchOptions::default()`; `from_gateway`; the size caps and `read_capped`; `xml_shallow`, the nesting scan; the tests |
| `src/common/options.rs` | `SearchOptions::gateway: Option<Ipv4Addr>`, the default router: its default is what the lookup finds, else `None` |
| `src/aio/tokio.rs` | `search_gateway`: with `gateway` `None` it sends no search and fails at once (`NoResponseWithinTimeout`); an answer is taken only when its source address and its LOCATION host are both `gateway` (an IPv4 mapped IPv6 source counts as IPv4), any other is ignored and the search keeps waiting; an SSDP answer longer than 1500 bytes is refused (`InvalidResponse`), not cut; the description and SCPD bodies are read up to 64 KiB, the SOAP body up to 16 KiB, a longer one refused (`InvalidResponse`) before parsing |
| `src/common/parsing.rs` | `parse_control_urls`, `parse_schemas` and `parse_response` refuse (`InvalidResponse`) a document nested deeper than 32 levels or with a DOCTYPE, before xmltree parses it |
| `src/lib.rs` | `mod raven_delta`; `pub use raven_delta::set_gateway_lookup` |
| `Cargo.toml` | description notes the patch; feature `aio_tokio` on by default (libp2p-upnp turns it on anyway) and no dev-dependencies, so `cargo test --locked -p igd-next --lib` runs these tests in the workspace, on the versions Cargo.lock pins (the examples need simplelog: build only `--lib`) |

Raven sets the lookup in `raven-swarm` (`portmap::new_upnp`, before each
libp2p-upnp behaviour is made): `raven_core::gateway::default_gateways()`
with `v4_to_map()`, the IPv4 default router unless it is a global address
(the router NAT-PMP and PCP already ask).

## Limits and why

- **SSDP answer: 1500 bytes**, the receive buffer upstream already had (one
  Ethernet MTU). A real answer is 250 to 500 bytes in one datagram; a longer
  one was cut silently and parsed, and is refused now.
- **Description and SCPD: 64 KiB each.** Real ones are about 2 to 20 KB (a
  router that lists many services and icons): three times the largest.
- **SOAP response: 16 KiB.** Real ones are under 2 KB (an external address,
  a port mapping entry, a UPnP error).
- **Nesting: 32 levels.** Real descriptions nest about 9 levels (root,
  device, deviceList, device, deviceList, device, serviceList, service,
  controlURL), SOAP responses 4. 32 frames of xmltree fit any stack.

The nesting scan (`xml_shallow`, no new dependency) never counts fewer levels
than xml-rs sees: comments, CDATA sections and processing instructions are
skipped whole, quoted attribute values inside a tag too, and every other `<`
that opens no end tag counts as an element. Any other `<!` (a DOCTYPE, whose
internal entities xml-rs would expand into elements) is refused, as is a
construct left open and UTF-16 input (a byte order mark: the scan reads
ASCII bytes, as UTF-8 and the 8 bit encodings xml-rs knows write them).

## Not changed

- The blocking API (`search_gateway`, `Gateway` over attohttpc), which Raven
  never calls, keeps its search and its unbounded reads; it gets the nesting
  check through the shared parsing only. `src/aio/soap.rs` is upstream dead
  code, untouched.
- What a host that can send from the router address (forged UDP source on
  the LAN) still chooses: the port and path of a request to the router
  itself. The description it then reads comes from the router address.
- Upstream `log::debug!` lines name addresses; Raven installs no `log`
  logger for them.

## Tests

`src/raven_delta.rs` (`cargo test --locked -p igd-next --lib`, Raven CI on
Linux and macOS): a description and a SOAP response 100 000 levels deep are
refused on a 256 KiB stack (upstream: stack overflow, abort); 33 levels, a
DOCTYPE and a quoted `/>` are refused, 32 levels and markup inside comments
are not; and against a router and a stranger played on the loopback: an
answer from another address (cfg not Windows: one dual stack socket) or
naming another host (cfg unix: 0.0.0.0 reaches the loopback) is ignored and
the router answer taken; with no router known nothing is taken; an answer
over 1500 bytes, a description over 64 KiB or 33 levels deep is refused and
the next answer taken; a SOAP response over 16 KiB is refused. Each failed on
the unchanged copy.

Drop this fork once an igd-next release bounds its responses and lets the
caller name the router whose answer it takes, and libp2p-upnp moves to it.
