# Raven decoder fuzzing (cargo-fuzz)

Coverage-guided libFuzzer targets for the decoders a remote peer or another
local process can reach. The crate is **outside** the `node/` workspace (its
own `[workspace]` root and `Cargo.lock`), so `libfuzzer-sys` never enters
normal or release builds.

| target | decoder(s) | invariant checked on accepted input |
|---|---|---|
| `envelope` | `Envelope::unpack`, `bridge::decide`, BLE RVN1 check | re-encode is byte-identical |
| `store_object` | RSO1 `StoreObject::unpack` | re-encode is stable |
| `rlb1_offer` | RLB1 LAN offer `decode_offer` | encode → decode round trip |
| `carrier_frames` | Internet/LAN `deframe_prefix`, mock-BLE `ble_frame_decode`, RIH1 hello | length accounting, re-frame identical |
| `pair_init` | PairInit / PairResponse | re-encode is byte-identical |
| `device_cert` | `DeviceCertificate` / `PrekeyBundleJson` JSON + verify | no panic |
| `device_revocation` | `DeviceRevocationV1::decode` | re-encode is byte-identical |
| `ipc_frame` | IPC request / response frames | request round trip |
| `session_and_records` | indexed-session header / signed ACK, RVNA1 header, alias, PeerRecord, contact request/accept | no panic |
| `rsr1_frame` | RSR1 session-reset frames (`session_reset::decode`, `verify`) | a decoded frame carries a full signature; no panic |
| `rfc1_frame` | RFC1 friend-custody request and reply frames (letter ops 0x04-0x06 and handoff ops 0x07-0x08 included), the RSO1 check, letter admission, RHW1 records (`custody_handoff::Rhw1::decode`, `check_rhw1_rso1`) | request and reply round trip (TAGS merge is a fixed point); the terminal-reply classifier agrees with the decoded reply; letter admission agrees with the strict RAL1 header decode; an accepted RHW1 record re-encodes byte for byte, raw and inside HANDOFF |
| `ral1_decode` | RAL1 async letters (`async_letter::decode`, `decode_header`) and both inner kinds (`decode_inner`) | a letter re-encodes byte-identically within 776..=65,288 bytes and its inner length is a multiple of 512; an inner re-encodes byte-identically |
| `app_frame` | RVNAPP/1 app frames (`app_channel::classify`) | a registered frame re-encodes byte-identically |
| `rrh1_frame` | RRH1 route hints, the RLX1 LAN message-3 payload, RELAY_OFFER records | an accepted RELAY_OFFER re-encodes exactly, a frame round trips canonically, validated entries stay within the spec's bounds |
| `rrh1_phase4_tlvs` | RRH1 Phase 4 entries (types 0x21-0x2F, §13 of RAVEN_ROUTE_HINTS_V1.md) appended to a valid frame | none costs the frame or another entry; only the first 5-byte NAT_CLASS is kept, normalized, the other NAT_CLASS entries counted as dropped; canonical round trip |
| `relay_inputs` | relay kit inputs: `via=` lines, `--also-tcp`, `--public-host`, `relay_allow.json`, `relay_status.json` | re-parse and JSON round trips, bounded sizes |
| `reach_tokens` | the diagnosis reason block (`reach_diag::Diag::find`) | a found block renders within its bound, names no address, and reads back the same |
| `portmap_reply` | NAT-PMP and PCP replies from the router (`portmap::decode_reply`) under every combination of outstanding requests; then `portmap::MapperCore::on_datagram` from a mapped state (PCP and NAT-PMP, TCP and UDP mapped) | an accepted reply keeps the version, opcode, length and option rules of RAVEN_PORT_MAPPING_V1.md; nothing is accepted with nothing outstanding; the core sends only requests of the profile, reports only global external addresses, never maps an endpoint twice without an expiry, and nothing stays mapped after its shutdown |
| `proxy_setting` | proxy settings, bypass lists and Windows proxy strings from the environment and the OS (`net_proxy`) | an accepted URL is shown and debug-printed with its credential redacted, and without one reads back the same; a refusal shows no user part; loopback and link-local hosts always go direct |
| `relay_schedule_text` | the relay schedule text a dedicated relay's operator pastes (`peer_rotation::parse_relay_schedule`, RAVEN_P2P_PEER_ROTATION_V1.md) | an accepted text holds 1 to 13 entries, epochs strictly increasing, PeerIds canonical and distinct; its canonical form stays within the bound and reads back the same; a text this raven formats always reads back |
| `ws_frame` | WebSocket frames of RWS1 (`ws_frame::parse_head`, `Reassembly`, `close_code`): what a relay's WSS listener reads before Noise | an accepted head keeps the subset's bounds and re-encodes byte-identically, its shorter prefixes ask for more bytes; every refusal is the close code the subset names; no message is over 262144 bytes |
| `lan_beacon_datagram` | LAN beacon queries and answers (`lan_beacon::match_query`, `open_answer`) against a fixture of 3 contacts' keys (the people of `shared-vectors/rvn1/lan_beacon`) | only a 160-byte query or a 48-byte answer is read; a match names each contact once and its query re-encodes byte for byte; an opened answer carries a port other than 0 and opens in one direction only |
| `rnp1_frame` | nearby pipe frames (`nearby_link::decode`, `PipeState::on_rx_bytes`, `PeripheralKnock::answer`, RAVEN_NEARBY_LINK_V1.md) as one frame and as a length-prefixed frame sequence on a pipe that just came UP, at frame sizes 64, 185 and 512, either role | an accepted frame fits its size and re-encodes byte for byte; a HELLO the fixture answers (the people of `shared-vectors/rvn1/nearby`) gets one CHALLENGE, then silence for the same nonce; delivered bytes fit one DATA payload, credit stays at most 64, and an error or RESET leaves the pipe dead |
| `pad1_frame` | PAD1 link padding (`link_padding::unwrap`, `wrap`, `PadState::on_recv` and `on_send`, RAVEN_LINK_PADDING_V1.md) as one frame, as one inner frame, and as a length-prefixed frame sequence (padded by the peer when the length byte is odd) read by an off, agreed or LAN-dialer side | an accepted frame is a bucket with zero padding and an inner frame that fits and is not RPD1, and re-encodes byte for byte in its smallest bucket; a wrap is the smallest bucket and unwraps to its input, and only an empty, over-65,511-byte or RPD1 input is refused; an off side passes every frame untouched, a bare frame after the peer's first RPD1 frame is refused, and a side sends padded exactly when it wraps |
| `rlk1_m1` | RLK1 link knock (`link_knock::match_m1`, `check_m2`, `ReplayCache`, RLX1 `PAD`, RAVEN_LINK_KNOCK_V1.md) as the raw Noise XX message 1 a listener reads (against the people of `shared-vectors/rvn1/link/rlk1_tags_001.json`, at the vectors' day and both ends of u32), as a message 2 payload and as a message 3 payload | only 64..=95 bytes can match, a match names the knocking contact with the input's ephemeral and nonce and a tag of one of the three days, and is a replay the second time; a proof verifies only at 16..=47 bytes with the real proof first; a padded RLX1 keeps its caps within 64 bytes |
| `rad1_decode` | RAD1 security advisories (`advisory::Advisory::decode`, `verify`), release key sets (`release_keys::KeySet::decode`) and signature blocks (`SigBlock::decode`, `KeySet::verify_sigs`), RAVEN_SECURITY_ADVISORY_V1.md, against the test key set and the rotation's next set | an accepted advisory keeps every bound, kind and severity rule, has no duplicate entry and re-encodes byte for byte; one that verifies names that key set and carries at least its threshold of signatures; an accepted key set re-encodes, lists distinct keys and a threshold that fits; a signature block re-encodes |
| `rtl1_snapshot` | RTL1 transparency log tree heads (`tlog::Sth::decode`, `verify`) and snapshots (`Snapshot::decode`, `check`, `consistency`, `contains`), RAVEN_TRANSPARENCY_LOG_V1.md, against the test key set and the rotation's next set | an accepted tree head re-encodes byte for byte and, when it verifies, names that key set with at least its threshold of signatures; an accepted snapshot holds 1..=1,400 entries, its head's size is its entry count and it re-encodes byte for byte; a checked log lists each of its entries, is SAME as itself and extends each of its prefixes; BAD_ROOT only on a real root mismatch; prefix consistency is symmetric |
| `rrb1_manifest` | RRB1 release manifests (`release_bundle::Manifest::decode`, `verify`, `check_chunk`) and chunk trees (`ChunkTree`, `chunk_root`, `verify_chunk_path`), RAVEN_RELEASE_BUNDLE_V1.md, against the test key set and the rotation's next set | an accepted manifest keeps every bound and re-encodes byte for byte; every path is safe by `std::path` alone (relative, under `bin` or `docs`, 2 or 3 normal components, the join stays inside: the path-traversal property) and no two collide ignoring case or as file and directory; the files tile the payload in order (the overlap property); one that verifies names that key set; each chunk's audit path proves it and no changed chunk |
| `rrbc_container` | RRBC containers (`release_bundle::Container::open`, `verify_bundle`), RAVEN_RELEASE_BUNDLE_V1.md, opened whole and a few bytes at a time, verified against the test key set as a fresh build, an up-to-date build and a build without release keys | opening whole or in pieces gives the same result; an opened container re-encodes byte for byte; a verified bundle is in its log, for the build's target, newer than the installed build and not under its floor, and its files tile a payload whose chunk root is the manifest's |
| `rup1_frame` | RUP1 update exchange frames (`update_exchange::decode`, `decode_for_listener`, `frame_expects_reply`, `frame_is_terminal_reply`, RAVEN_UPDATE_EXCHANGE_V1.md), as a frame and as a body behind a valid version 1 header whose op is the input's first byte | an accepted frame is at most 65,511 bytes, keeps the offer, chunk and path caps and re-encodes byte for byte; the dial classifier agrees with the op's role; a listener serves exactly the accepted requests and HAVEs, refuses anything else only with UNSUPPORTED or MALFORMED echoing the request id, and never answers a reply |

The target bodies live in [`src/lib.rs`](src/lib.rs). The same file is compiled
into `node/crates/raven-core/tests/fuzz_smoke.rs`, which runs every target over
pseudo-random mutations of all `shared-vectors/rvn1` values on **stable** in CI
(`cargo test -p raven-core --test fuzz_smoke`), so a target that no longer
type-checks, or a decoder that panics on a mutated vector, fails the normal
test run. Longer smoke runs:

```bash
cd node
RAVEN_FUZZ_SMOKE_ROUNDS=500 RAVEN_FUZZ_SMOKE_SEED=$RANDOM \
  cargo test -p raven-core --test fuzz_smoke fuzz_smoke_all_targets_random
```

## Real campaigns (nightly)

```bash
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
cd node/fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run envelope -- -max_total_time=600
```

Seed a corpus from the committed vectors (hex values become binary seeds):

```bash
mkdir -p corpus/envelope
python3 - <<'PY'
import hashlib, json, pathlib
out = pathlib.Path("corpus/envelope")
for p in pathlib.Path("../../shared-vectors/rvn1").rglob("*.json"):
    def walk(v):
        if isinstance(v, str) and len(v) >= 8 and len(v) % 2 == 0:
            try:
                b = bytes.fromhex(v)
            except ValueError:
                return
            (out / hashlib.sha1(b).hexdigest()).write_bytes(b)
        elif isinstance(v, dict):
            for x in v.values(): walk(x)
        elif isinstance(v, list):
            for x in v: walk(x)
    walk(json.loads(p.read_text()))
PY
```

A crash reproducer lands in `artifacts/<target>/`; add the input as a
regression case (e.g. a new negative vector or a unit test in the owning
module) together with the fix.
