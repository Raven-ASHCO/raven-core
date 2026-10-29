# RAVEN WSS Transport V1 (RWS1)

**Version:** 1 (Raven restrictive-network transport: libp2p over WebSocket over TLS on TCP, with
an optional HTTP CONNECT proxy)
**Status:** Draft; **production disabled** (`WSS_PRODUCTION_ENABLED = false`,
`WSS_PROXY_PRODUCTION_ENABLED = false`). Lab only: debug builds with `RAVEN_LAB_TEST_A=1` and
`RAVEN_LAB_WSS=1` (proxy dials also `RAVEN_LAB_WSS_PROXY=1`). Release builds read no switch.
Enabling it in production needs the owner-signed WSS/proxy waiver (real rows R8w and R8p).
**Audience:** re-implementers of Raven relays and endpoints.
**Code:** `node/crates/raven-core/src/p2p_route.rs` (§2 address grammar, §2.3 dial forms),
`net_proxy.rs` (§8 proxy rules), `ws_frame.rs` (§5 frames), `wss_gate.rs` (gates);
`node/crates/raven-swarm/src/wss/tls.rs` (§4), `wss/ws.rs` (§5 upgrade and byte stream),
`wss/connect.rs` (§7), and the transport with its two-protocol listener in `wss/mod.rs` (§3,
§6); `node/crates/raven-node/src/proxy.rs` (§8.2 sources and OS readers) and `p2p.rs` (the
endpoint's dial forms, names left to the proxy, SNI after resolution, and restricted mode: §2.3,
§7, §9).
**Reference:** `protocol/reference/raven_protocol/via.py` (§2), `websocket.py` (§5), `connect.py`
(§6, §7), `net_proxy.py` (§8).
**Vectors:** `shared-vectors/rvn1/p2p/via_001.json`, `shared-vectors/rvn1/wss/rws1_ws_handshake_001.json`,
`rws1_ws_frames_001.json`, `rws1_connect_request_001.json`, `rws1_connect_reply_001.json`,
`rws1_demux_001.json`, `rws1_proxy_url_001.json`, `rws1_no_proxy_001.json`
(`protocol/reference/generate_wss.py`), §11.

---

## 1. Scope and activation

Some networks let only HTTPS out: TCP 443, often through an HTTPS proxy that may inspect TLS.
RWS1 lets an endpoint reach its relays there: libp2p runs inside a WebSocket inside TLS on a
relay's TCP 443, optionally through the network's HTTP CONNECT proxy. It changes no Raven frame
and no libp2p protocol: the same Noise-authenticated libp2p connection, the same circuits, the
same Raven link inside them.

| Gate | What it opens | Lab unlock (debug builds) |
|---|---|---|
| `WSS_PRODUCTION_ENABLED` | WSS dials of relay addresses (§2.3) and a relay's two-protocol listener (§6). Needs `P2P_PRODUCTION_ENABLED` | `RAVEN_LAB_TEST_A=1 RAVEN_LAB_WSS=1` |
| `WSS_PROXY_PRODUCTION_ENABLED` | WSS dials through an HTTP CONNECT proxy (§7, §8). Needs `WSS_PRODUCTION_ENABLED` | also `RAVEN_LAB_WSS_PROXY=1` |

- The proxy gate is named WSS_PROXY (owner decision O4-8), never to be mistaken for the
  `HTTP_PROXY` environment variable, which Raven does not read.
- No relay or proxy address is compiled in. Proxies come only from local settings (§8), never
  from a peer, a card or RRH1.
- With both gates closed nothing dials or listens on WSS: the §2 grammar reads WSS addresses, the
  dial plan uses their raw siblings, and a plan without WSS addresses is byte for byte the plan of
  a node without RWS1 (§2.3 (d)).

## 2. Address grammar

The one grammar of a relay address or a direct address of a contact, wherever a `via` is read:
`via=` and `relay=` in cards, `--via`, `--p2p-relay`, `raven relay use`, node policy, the contact
book, the outbox and RRH1 RELAY and DIRECT entries.

### 2.1 Grammar

```
via   = host "/tcp/" port [wss] "/p2p/" peer  /  host "/udp/" port "/quic-v1/p2p/" peer
host  = "/ip4/" v4 / "/ip6/" v6 / ("/dns/" | "/dns4/" | "/dns6/") name
wss   = "/tls/ws"  /  "/tls/sni/" name "/ws"
```

- `port` is 1-65535 in plain decimal; `peer` is a canonical Ed25519 PeerId (`12D3KooW…`, 52
  characters); `name` is a DNS name TLS can send as SNI: at most 253 characters, one trailing `.`
  allowed, labels of 1-63 letters, digits and `-`, none starting or ending with `-`, and a last
  label that is not all digits (so never an IPv4 literal). Every `/dns*` host and `/sni/` name
  takes this rule.

### 2.2 Canonical text and refusals

- `/tls/sni/<name>/ws` is only valid after an IP host (a DNS host already is the SNI name), and
  its name is never an IPv4 literal.
- Input `/wss` (the deprecated libp2p alias) is stored as `/tls/ws`.
- Canonical text: IP addresses in their standard text form (IPv6 compressed, lower case), DNS and
  SNI names in lower case, surrounding spaces trimmed. The canonical text is at most 300
  characters: an input whose `/wss` makes it longer as `/tls/ws` is refused.
- Refused:
  - plain `/ws`;
  - `/x-parity-ws`, `/x-parity-wss`, `/certhash`, `/http`, `/https`, `/http-path`, `/noise`, and
    any `/tls` or `/sni` form other than the two above;
  - a WSS suffix on QUIC;
  - a circuit (`p2p-circuit` anywhere).
- Multiaddr codes are the standard ones (tls 448, sni 449, ws 477).
- A relay offer's address and a relay's own external address (host and transport only) take no
  WSS suffix.

### 2.3 Siblings and dial forms

Who listens: only dedicated relays (`raven-node relay`) listen on WSS in V1; friend relays
(`raven-node service --relay`) do not, and endpoints never do. A direct address of a contact
therefore never carries a WSS suffix from a sender of this version. A reader drops such an RRH1
DIRECT entry, and dials a contact's own WSS address from a card at its raw sibling (a) alone:
its WSS form could never answer, and would put the contact's choice of host and SNI name in the
HTTPS proxy's view. Hole punching never offers or dials a WSS form.

- (a) Every WSS listener is a two-protocol port: the same host and port also accept raw libp2p
  TCP (§6). The raw sibling of a WSS address is the same address without `/tls[/sni/N]/ws`.
- (b) TCP 443 relay addresses are siblings by convention: a dialer MAY try `/tcp/443` and
  `/tcp/443/tls/ws` for either form. No other raw port has a WSS sibling.
- (c) The forms a dialer tries for one relay address (`relay_dial_forms`), best first:

| Address | WSS gate closed | Gate live, raw first | Gate live, WSS first |
|---|---|---|---|
| raw TCP 443 | raw | raw, WSS sibling | WSS sibling, raw |
| WSS, any port | raw sibling | raw sibling, WSS | WSS, raw sibling |
| raw TCP on another port, QUIC | itself | itself | itself |

  WSS first when the configured proxy carries it (§7), otherwise raw first.
- (d) The dial plan circuits through each relay address at each of its forms. A relay's first
  form comes before any relay's second form or second address, so a second relay is never cut
  for the first one's fallback; a form named twice is dialled once. With the WSS gate closed a
  WSS address is planned as its raw sibling would be, and a plan without WSS addresses is byte
  for byte the plan of a node without RWS1.
- (e) Restricted (§9): while a reservation rides a proxied WSS connection, the plan holds no
  direct address, only the circuits.

## 3. Stack

1. TCP;
2. [HTTP/1.1 CONNECT tunnel, §7];
3. TLS 1.3 (§4);
4. HTTP/1.1 Upgrade (RFC 6455), then WebSocket binary messages (§5);
5. libp2p multistream-select 1.0 (V1Lazy), libp2p Noise XX, Yamux;
6. `/raven/link/1.0.0`, then Raven Noise (unchanged).

There is no new libp2p protocol id and no Raven frame change.

## 4. TLS

- Client:
  - TLS 1.3 only;
  - ALPN `http/1.1`;
  - SNI = the `/dns*` name or the `/sni/` name; none for an IP literal;
  - no client certificate, no session resumption.
- The client accepts the server certificate without chain, name or expiry validation. The TLS 1.3
  CertificateVerify signature MUST still verify under the presented key.
- Peer authentication is the libp2p Noise PeerId check against `/p2p/<id>` (mandatory in §2),
  then the RIH1 identity bind inside Raven Noise. TLS is a wrapper, not an authenticator.
- Server, one of:
  - (a) an operator PEM chain and key;
  - (b) an ephemeral self-signed certificate: ECDSA P-256, empty subject DN, SAN = the configured
    names or `localhost`, random 128-bit serial, validity now - 1 h to now + 365 d, EKU
    serverAuth, not a CA. It carries no libp2p extension (OID 1.3.6.1.4.1.53594.1.1) and no Raven
    or rcgen strings. It is regenerated at every start and never stored.
- Server: TLS 1.3, ALPN `http/1.1` or none, no session tickets.

## 5. WebSocket

Implementation (owner decision O4-1): a Raven-owned, binary-only subset of RFC 6455, with no new
crate. The frame codec is pure; the handshake head is parsed with httparse and the
`Sec-WebSocket-Accept` SHA-1 is ring's legacy SHA-1, both already in the build.

### 5.1 Upgrade

- Client request, exactly (vectors: the bytes for a Host value and key):
  - `GET / HTTP/1.1`, Host = the SNI name or the IP literal (IPv6 in brackets), with `:port` when
    the port is not 443;
  - `Upgrade: websocket`, `Connection: Upgrade`;
  - `Sec-WebSocket-Key` = 16 random bytes in base64, fresh for each connection,
    `Sec-WebSocket-Version: 13`;
  - no Origin, no Sec-WebSocket-Protocol, no extensions (permessage-deflate is forbidden), no
    User-Agent.
- Server: answers `101` only to `GET / HTTP/1.1` with exactly one Host, an Upgrade that lists
  `websocket` and a Connection that lists `upgrade` (comma-separated tokens, any case), exactly one
  `Sec-WebSocket-Version: 13` and exactly one `Sec-WebSocket-Key` that is padded base64 of 16 bytes
  in its canonical form. Other headers (an Origin, an offered subprotocol or extension) are ignored
  and nothing is selected. The `101` is `HTTP/1.1 101 Switching Protocols`, `Upgrade: websocket`,
  `Connection: Upgrade` and `Sec-WebSocket-Accept` = base64(SHA-1(key ||
  `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)), nothing else (no Server header). Anything else gets
  `HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`, then the
  connection is closed.
- Client: takes only `HTTP/1.1 101` with an Upgrade that lists `websocket`, a Connection that lists
  `upgrade`, exactly one `Sec-WebSocket-Accept` of the right value, and no
  `Sec-WebSocket-Extensions` or `Sec-WebSocket-Protocol`.
- Heads, both ways: at most 8192 bytes through the blank line and at most 32 headers; lines end in
  CRLF only, and the start line comes first. Bytes after a head are the stream's first bytes.

### 5.2 Frames

- Binary messages only; message boundaries carry no meaning. Raven sends each write as one binary
  frame (FIN set) of at most 16384 bytes, and never pings: libp2p's ping keeps proxies and NATs
  awake.
- Client frames are masked with a fresh random key, server frames unmasked. Lengths use their
  minimal form (7, 16 or 64 bits).
- A reader checks each frame head in this order; the first failing check closes with its code:
  1. RSV1-3 set (no extension is ever agreed): 1002;
  2. an opcode other than 0, 1, 2, 8, 9 and 10: 1002;
  3. a control frame (close, ping, pong) without FIN or over 125 bytes: 1002;
  4. a mask bit that does not match the sender's side: 1002;
  5. a length not in its minimal form: 1002;
  6. a frame over 262144 bytes (any 64-bit length above it, the top bit too): 1009.
- A message may come in fragments (a binary frame, then continuations, the last with FIN), with
  control frames between them. A continuation with no message open, or a binary or text frame
  inside a message, closes with 1002; a text frame closes with 1003; a message over 262144 bytes
  closes with 1009.
- A ping is answered with a pong carrying its payload (only the latest unanswered ping needs one).
  A close is answered with a close 1000, and reading ends; a 1-byte close payload closes with 1002.
  A close's reason is ignored. Nothing is sent after a close.
- The stream ending between messages is the end of it; ending inside a frame or a message is an
  error.
- KAT (RFC 6455): key `dGhlIHNhbXBsZSBub25jZQ==` gives `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`. A masked
  binary "Hello" with mask `37fa213d` is `828537fa213d7f9f4d5158`.

## 6. The two-protocol listener

The relay's WSS listener peeks at the first byte:

- 0x16 (a TLS handshake record) leads to §4 and §5;
- 0x13 (the varint 19 that starts `/multistream/1.0.0\n`) leads to raw libp2p, untouched;
- anything else, or nothing within 10 s (or the connection ending first), closes with no reply.

Only the first byte decides; the listener peeks at it and leaves it in place for TLS or libp2p.

The whole upgrade is inside the 10 s connection timeout. A raw listener and a WSS listener never
share a port (SO_REUSEPORT would split the connections between them): the WSS listener is the
raw listener of its port. Its listen addresses are `{host}/tcp/{port}/tls/ws`, TCP only.

## 7. HTTP CONNECT client

- Request: `CONNECT <authority> HTTP/1.1\r\nHost: <authority>\r\n[Proxy-Authorization: Basic
  <b64(user:pass)>\r\n]\r\n`, and nothing else (no User-Agent, no Proxy-Connection). The
  authority and the Basic value are bytes 0x21..0x7e; anything else is refused before a byte is
  sent.
- Authority:
  - `name:port` for a `/dns*` host, which MUST NOT be resolved locally when proxied;
  - `a.b.c.d:port`;
  - `[v6]:port`.
- The proxy's own name (§8.1) goes to the system resolver, so an internal name like
  `proxy.corp` works; its addresses are tried in the resolver's order, and the first that takes
  the connection is used.
- The reply is read as it arrives and decided as soon as its bytes allow, in this order:
  1. the head is everything through the first CRLF CRLF, or all bytes so far when there is none
     yet;
  2. the head starts with `HTTP/1.` (or a prefix of it while shorter), and its lines end with CRLF
     only; otherwise malformed (a bare LF, a CR followed by another byte, or an empty line before
     the status line);
  3. no CRLF CRLF yet: malformed once 8192 bytes are there, otherwise more bytes are needed;
  4. a head over 8192 bytes is malformed;
  5. the status line is `HTTP/1.0` or `HTTP/1.1`, one space, three digits, then nothing or a space
     and a reason phrase; at most 32 header lines, each a token name, `:` at once, then a value;
     the reason phrase and the values hold only HTAB, SP, VCHAR and obs-text (0x80-0xff).
     Otherwise malformed.

  Once decided, more bytes never change the decision.
- Success: any 2xx (HTTP/1.0 too). Bytes after the head are tunnel data and are read before
  anything else from the connection. Content-Length and Transfer-Encoding of a 2xx are ignored.
- 407: report the Proxy-Authenticate schemes, each once in the order offered: every
  comma-separated element (commas inside a quoted string do not count) that starts with a token
  followed by nothing or white space and not `=` (that is an auth-param) names a scheme. Basic,
  Digest, NTLM, Negotiate and Bearer, matched in any case, are reported by these names; any other
  scheme as `other`. Only Basic is supported, and a refused Basic is never retried.
- Other codes: refused (with the code).
- Errors carry fixed texts: no proxy host, URL, port, credential or tunnel target, and no text
  the proxy sent (§9).
- Proxy URL: `http://[user:pass@]host[:port]` (default port 80), §8.1. `https://`, SOCKS, PAC and
  WPAD are unsupported.
- QUIC and raw TCP never go through the proxy.

## 8. Proxy sources

### 8.1 Proxy setting and proxy URL

A proxy setting is trimmed of space, tab, CR and LF. Empty or `auto` (ASCII case-insensitive) is
auto (§8.2), `off` is no proxy, anything else a proxy URL, read in this order:

1. At most 1024 bytes (`too_long`); every byte 0x21..0x7e (`syntax`).
2. PAC or WPAD: the words `pac` or `wpad`, or a text whose part before the first `?` or `#` ends
   in `.pac` or `/wpad.dat` (unsupported, `pac`).
3. An optional `scheme://`, ASCII case-insensitive: `http`; `https` (unsupported, `https`);
   `socks`, `socks4`, `socks4a`, `socks5`, `socks5h` (unsupported, `socks`); anything else
   (`scheme`). Without `://` the text is `[user[:pass]@]host[:port]` and the scheme is http.
4. The authority ends at the first `/`, `?` or `#`; after it only nothing or a single `/`
   (`path`).
5. User part: what precedes the last `@` of the authority, split at its first `:` into user name
   and password, each percent-decoded (`%` and two hex digits). Refused (`userinfo`): an empty user
   part, a bad escape, a `:` in the decoded user name, a control byte (0x00-0x1f, 0x7f) in either.
   The Basic value is base64 (RFC 4648, padded) of the bytes `user ":" password` (RFC 7617).
6. Host (`host`), checked before the port: `[IPv6]` without a zone (an IPv4-mapped address is its
   IPv4 address), or an IPv4 address in dotted-quad form, neither unspecified, broadcast nor
   multicast; else a DNS name, lower-cased: labels of 1-63 letters, digits, `-` and `_`, none
   starting or ending with `-`, at most 253 bytes, one trailing dot allowed, the last label not all
   digits.
7. Port (`port`): `:` and 1-65535 in plain decimal (no sign, no leading zero); none is 80.

Each refusal has a code (the parenthesised words above) and a status kind: the unsupported kind
(`https`, `socks`, `pac`) or `invalid`. A refusal never repeats the text. Shown to the user, a
proxy is `http://host:port` (IPv6 in brackets), with `<redacted>@` before the host when it carries
a user name; the Basic value is kept only in memory and never logged or serialised.

Credentials are never persisted: node_policy `p2p_proxy` refuses any text with an `@` (§9). They
reach the node only at runtime, in `--p2p-proxy`, `RAVEN_P2P_PROXY` or the environment.

### 8.2 Sources

Highest first; the first that names a proxy decides:

1. The explicit setting: `--p2p-proxy`, then `RAVEN_P2P_PROXY`, then node_policy `p2p_proxy`.
   `off` and a URL decide alone, with an empty bypass list (§8.3's always-direct hosts still go
   direct); `auto` reads on.
2. The environment. A variable that is set but empty (after trimming) counts as unset. The first
   of `HTTPS_PROXY`, `https_proxy` decides, usable or not. Otherwise the first of `ALL_PROXY`,
   `all_proxy` decides only when it is a usable http proxy (it often names a SOCKS proxy for other
   programs). The proxy's bypass list is the first of `NO_PROXY`, `no_proxy`. `HTTP_PROXY` is never
   read.
3. The OS: macOS SCDynamicStore (`HTTPSEnable`, `HTTPSProxy`, `HTTPSPort`, `ExceptionsList`,
   `ExcludeSimpleHostnames`); Windows WinHTTP's IE configuration of the user (`lpszProxy`: its
   `https=` entry, else its first entry without `=`, entries separated by `;` or white space, an
   entry read as in §8.1 with its own port or 80; `lpszProxyBypass` is the bypass list); Linux
   none. An HTTPS proxy decides, with the OS bypass list (plus `<local>` for
   ExcludeSimpleHostnames). Otherwise PAC or WPAD set decides as unsupported `pac`.
4. Otherwise an `ALL_PROXY` that is not a usable http proxy decides as unsupported; otherwise
   there is no proxy.

A source that decides with a proxy Raven cannot use gives no proxy and a status kind (§8.1): WSS
dials then go direct, and the status says why.

### 8.3 Bypass list

The hosts a WSS dial reaches directly. Entries are separated by `,`, `;`, space, tab, CR or LF
and are ASCII case-insensitive:

- `*`: every host;
- `<local>`: names without a dot (Windows; macOS ExcludeSimpleHostnames);
- an optional port: `[IPv6]:port`, or `host:port` when the entry has exactly one `:`; the entry
  then applies only to dials to that port, and a port that is not 1-65535 in plain decimal drops
  the entry;
- `address/length`: a CIDR, IPv6, or IPv4 with 1-4 parts (missing parts are 0: macOS
  `169.254/16`); a length in plain decimal up to the family's width; host bits are cleared;
- a text with `*`: a glob over the host's text, `*` matching any run of characters, dots
  included;
- an IP address (IPv6 bare or in brackets);
- a DNS name as in §8.1, a leading and a trailing dot ignored: that name and every name under it,
  on a label boundary (`notexample.com` is not under `example.com`);
- anything else is ignored.

A dial's host is ASCII-lowercased, its brackets and one trailing dot removed. An IP address (an
IPv4-mapped one read as IPv4) matches IP, CIDR and glob entries (the glob on its canonical text);
a name matches domain and glob entries and `<local>`. Loopback (127.0.0.0/8, ::1) and link-local
(169.254.0.0/16, fe80::/10) addresses, `localhost` and names under `.localhost` always go direct.

## 9. Privacy

- What each party sees:
  - the proxy and the network see the relay host or IP, the time and the volume, but not the TLS
    contents;
  - an active TLS interceptor sees libp2p Noise ciphertext only (no worse than raw TCP today);
  - the relay sees the proxy's egress IP instead of the client's.
- Logs: categories and counts only. No proxy URL, host or credentials; no addresses.
- Restricted: while a reservation rides a proxied WSS connection, the endpoint offers no
  hole-punch or AutoNAT candidates and dials no direct contact addresses (§2.3 (e)).
- A proxy setting is local and never sent. A node that stores one keeps it sealed at rest, with
  the policy's relay addresses in `node_policy_peers.rms`
  (`docs/design/2026-10-at-rest-metadata.md`); credentials are never stored (§8.1).

## 10. Old-peer safety

- An older endpoint keeps dialling raw `/tcp/443` and `/tcp/7423` on a relay of this version: its
  TCP 443 listener also takes raw libp2p (§6).
- A newer endpoint falls back from the WSS form to the raw sibling against an older relay
  (§2.3). A TLS ClientHello fails multistream-select at once, so the fallback is quick.
- RRH1 address entries (`RAVEN_ROUTE_HINTS_V1.md` §5.2) are checked one at a time: a receiver
  without this grammar drops a `/tls/ws` RELAY or DIRECT entry alone and keeps the rest of the
  frame. RRH1's frame-level bounds still apply to the whole frame (§5.1: a RELAY value of at
  most 300 bytes, a DIRECT value of at most 120, bytes 0x21..0x7e, at most 4 RELAY and 6 DIRECT
  entries); a sender never writes a value outside them, and §2's 300-character bound keeps every
  stored via a valid RELAY value.
- Contact-book readers drop a via they cannot parse (`ContactP2p::from_fields`).
- `raven-card/2` MUST NOT carry `/tls/ws` vias: a card /2 reader refuses the whole card on a via
  it cannot parse.
- `raven-card/3` readers of this version read `/tls/ws` relays. Since the Phase 2 amendment for
  owner decision O4-14 (2026-10-21, `RAVEN_ROUTE_HINTS_V1.md` §9), a card v3 reader drops a
  `relay=` it cannot parse and keeps the card and its other relays, so a card v3 reader without
  this grammar drops a `/tls/ws` relay alone. A dropped `relay=` still counts toward the limit of
  4, and the relays a reader keeps follow §9 (each names a PeerId other than the card's `p2p`,
  appears once, and they name at most 2 relays). Card v3 readers built before that amendment
  refuse the whole card. `p2pn=` (Phase 4 key rotation) is accepted once, only with `p2p=`, and
  checked like it (`RAVEN_P2P_PEER_ROTATION_V1.md` §5); nothing writes it while rotation is
  production disabled. Card v3 is printed only while route hints
  are live (`ROUTE_HINTS_PRODUCTION_ENABLED = false`).
- New IPC and node_policy fields are `serde(default)` and skipped when empty.

## 11. Vectors

All `deterministic: true`, generated by `protocol/reference/generate_wss.py` (`--check`
verifies the files on disk; it owns `p2p/via_*.json` and `wss/*.json`).

| File | Content |
|---|---|
| `shared-vectors/rvn1/p2p/via_001.json` | §2 and §2.3: accept cases (input, canonical text, PeerId, `is_wss`, TCP port, raw and WSS siblings, dial forms with the gate closed, raw first and WSS first) and reject cases (input and the refusing step) |
| `shared-vectors/rvn1/wss/rws1_ws_handshake_001.json` | §5.1: the RFC 6455 key with its accept value and SHA-1 digest; the client's exact request for three Host values; server cases (a request, whether it gets the 101, and the exact reply: the 101 or the 404) including heads of exactly 8192 bytes and 32 headers and one more; client cases (a reply to the RFC 6455 key's request and whether the client takes it) |
| `shared-vectors/rvn1/wss/rws1_ws_frames_001.json` | §5.2, mask `37fa213d`: binary frames both ways at 0/5/125/126/65535/65536 bytes (heads, whole frames up to 126 bytes, SHA-256 of each); close 1000/1002/1003/1009 and without a code, ping and pong; heads a reader takes, heads it needs more bytes for, heads it refuses with their close codes; frame sequences with the messages they give and how reading ends |
| `shared-vectors/rvn1/wss/rws1_connect_request_001.json` | §7: the exact request for a name, an IPv4 and an `[IPv6]` authority, each without and with the Basic value of `user:pass` |
| `shared-vectors/rvn1/wss/rws1_connect_reply_001.json` | §7: replies and the client's decision: tunnel (with the leftover bytes), auth (with the schemes), refused (with the code), malformed or incomplete; heads of exactly 8192 bytes and 32 headers and one more, early refusals of what is not HTTP, and prefixes that need more bytes |
| `shared-vectors/rvn1/wss/rws1_demux_001.json` | §6: first bytes and what the listener does: tls, raw or refused (0x16, 0x13, plain HTTP, other TLS records, SOCKS, 0x00, nothing) |
| `shared-vectors/rvn1/wss/rws1_proxy_url_001.json` | §8.1 and §8.2: settings (input, whether node policy refuses it as carrying credentials, then auto, off or the URL's host, port, Basic value and redacted text, or the refusal's code and status kind) and Windows proxy strings (input, the entry a WSS dial uses) |
| `shared-vectors/rvn1/wss/rws1_no_proxy_001.json` | §8.3: bypass lists, each with hosts and ports and whether the dial goes direct |

## 12. Out of scope

Censorship circumvention, domain fronting, ECH, TLS fingerprint mimicry, HTTP/2 or HTTP/3
extended CONNECT, WebTransport, ACME inside Raven, reverse-proxy deployment of relays.
