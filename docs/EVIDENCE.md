# Evidence: what is tested, and how

Raven's security and reliability claims should be no stronger than the evidence behind them. This
page lists that evidence, says how to reproduce it, and lists what has **not** been done. Read it
together with the [threat model](THREAT_MODEL.md), the
[security errata](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md) and the
[roadmap](ROADMAP.md).

Short version: there are many automated tests, shared test vectors checked by two independent
implementations, 30 fuzz targets, CI on three operating systems, and one small field test on three
real computers. There has been **no independent security review**, no signed package, no long soak,
no test with many users and no test on phones.

## 1. Automated tests

Counted on the published tree with `grep` (a count of test **functions**, not of test runs; some
tests loop over many cases, and a few are parametrised):

```sh
cd node
for c in crates/* third_party/raven-sqlcipher-profile-guard; do
  echo "$c $(grep -rE --include='*.rs' '^\s*#\[test\]' $c | wc -l) \
            $(grep -rE --include='*.rs' '^\s*#\[tokio::test' $c | wc -l)"
done
```

| Crate | `#[test]` | `#[tokio::test]` | Of these `#[ignore]` | What it is |
|---|---:|---:|---:|---|
| `raven-core` | 2,671 | 0 | 10 | protocol library: identity, envelopes, PairInit, sessions, storage, every codec |
| `ash` | 1,611 | 0 | 2 | the `raven` command line and terminal app |
| `raven-node` | 940 | 405 | 68 | the background program: carriers, outbox, custody, Tor, nearby |
| `raven-swarm` | 117 | 79 | 0 | libp2p host |
| `raven-client` | 88 | 0 | 0 | the engine the desktop apps call |
| `raven-mlkem768-incremental-ffi` | 5 | 0 | 0 | lab-only FFI |
| `raven-fb-ffi` | 5 | 0 | 0 | lab-only FFI |
| `third_party/raven-sqlcipher-profile-guard` | 9 | 0 | 0 | storage guard |
| **Total** | **5,446** | **484** | **80** | **5,930 test functions** |

67 of the 80 `#[ignore]` tests are the carrier matrix (they start real `raven-node` processes on
loopback); CI runs them with `--ignored` on Linux, macOS and Windows, and the 10,000-message queue
gate the same way. Most of the others are slow or need special hardware (for example BlueZ
emulated controllers) and run by hand or in advisory jobs.

The Python reference implementation (`protocol/reference/`) has **271** `def test_` functions in
37 test files (`cd protocol/reference && python3 -m pytest -q`).

Tests that go beyond single functions:

| Test | Where | What it shows, and its limit |
|---|---|---|
| Carrier matrix (about 59 cases, C1-C56) | `node/crates/raven-node/tests/carrier_matrix.rs` | real `raven-node` processes on loopback: LAN direct, Internet direct, contact gating, outbox restart, relays, custody, nearby with a fake radio. Loopback is not a real network. |
| LAN fault matrix (135 scenario functions) | `scripts/lan_fault_matrix.py` | real processes with one injected fault each: receiver offline, address change, resets, slow and black-holed links, crash during a burst, 20 queued messages in order. Run by hand; CI runs only its self-test. |
| Adversarial session tests | `node/crates/raven-core/tests/adversarial_atsam.rs` | forged, replayed, reordered and tampered inputs to the session layer |
| 10,000-message queue gate | `node/crates/raven-core/tests/reliability_10k.rs` | the store-and-forward queue under load |
| 1,000-node simulation | `node/crates/raven-core/tests/network_sim_1000.rs`, [spec](../protocol/RAVEN_NETWORK_SIMULATION_1000_V1.md) | a deterministic model of routing rules; not a test of real networks or crypto |
| NAT simulations | CI lab workflow (`nat-sim-linux`, `restrictive-net-linux`), [NAT_SOFTWARE_SIM.md](NAT_SOFTWARE_SIM.md) | Linux network namespaces: cone and symmetric NAT, relays, WSS on 443. Advisory (allowed to fail); not a real carrier NAT. |
| Final serverless proof | `scripts/final_serverless_proof.sh`, [FINAL_SERVERLESS_PROOF.md](FINAL_SERVERLESS_PROOF.md) | the whole flow on one machine; uses the lab demo cipher, so it is lab evidence only |

## 2. Shared test vectors

`shared-vectors/` holds **340** deterministic JSON vector files (fixed keys, fixed times, fixed
nonces). The `rvn1/` tree is the current protocol contract; `v1/` and `v2/` are older contracts
kept frozen. Rules: [shared-vectors/VERSIONING.md](../shared-vectors/VERSIONING.md).

- **Two implementations.** The Python reference (`protocol/reference/raven_protocol/`) generates
  most `rvn1/` vectors (`generate_rvn1.py` and its siblings) and asserts that it accepts or rejects
  the same bytes. The Rust tests read the same files (for example
  `node/crates/raven-core/tests/rvn1_strict_vectors.rs` and `raven_core::vectors`) and must agree.
- **Drift check.** CI regenerates `shared-vectors/rvn1` from the Python reference and fails on any
  difference, and `bash scripts/freeze_protocol_hashes.sh --check` fails when a frozen spec or vector
  changes without updating [PROTOCOL_FREEZE_HASHES_V1.md](PROTOCOL_FREEZE_HASHES_V1.md).
- **Negative cases.** `rvn1/negative/` and `rvn1/atsam/negative/` hold malformed and forged inputs
  (weak Ed25519 keys, small-order X25519 points, clock-skew edges, bad signatures) that both
  implementations must reject.
- **Gap.** A few newer families are read by the Rust tests only; the Python reference does not
  cover them yet: `onion/`, `group/`, `custody/` (the friend custody frames), `session_reset/` and
  `app_payload/`.

Run them:

```sh
cd protocol/reference && python3 -m pip install -r requirements.txt && python3 -m pytest -q
python3 protocol/reference/generate_rvn1.py && git diff --exit-code -- shared-vectors/rvn1
bash scripts/freeze_protocol_hashes.sh --check
cd node && cargo test --locked -p raven-core   # with the test-store variables of the README
```

## 3. Fuzzing

30 coverage-guided `cargo-fuzz` targets in `node/fuzz/fuzz_targets/`, one per decoder that a remote
peer or another local process can reach:

`app_frame`, `carrier_frames`, `device_cert`, `device_revocation`, `envelope`, `ipc_frame`,
`lan_beacon_datagram`, `pad1_frame`, `pair_init`, `portmap_reply`, `proxy_setting`, `rad1_decode`,
`ral1_decode`, `reach_tokens`, `relay_inputs`, `relay_schedule_text`, `rfc1_frame`, `rlb1_offer`,
`rlk1_m1`, `rnp1_frame`, `rrb1_manifest`, `rrbc_container`, `rrh1_frame`, `rrh1_phase4_tlvs`,
`rsr1_frame`, `rtl1_snapshot`, `rup1_frame`, `session_and_records`, `store_object`, `ws_frame`.

What each checks (round trips, bounds, no panic) is in [node/fuzz/README.md](../node/fuzz/README.md).

- **Every CI run** compiles the targets and runs each over random mutations of all `rvn1` vectors on
  stable Rust (`cargo test -p raven-core --test fuzz_smoke`).
- **Weekly** (toolchain canary workflow) every target runs for 2 minutes under libFuzzer.
- **By hand**, longer campaigns:

  ```sh
  rustup toolchain install nightly
  cargo +nightly install cargo-fuzz --locked
  cd node/fuzz
  cargo +nightly fuzz list
  cargo +nightly fuzz run envelope -- -max_total_time=600
  ```

- **Not fuzzed yet:** group frames (`raven_core::group`), the onion binding and the Tor helper's
  local protocol (`raven_core::onion`, `raven-node/src/onion/proto.rs`) and the STUN answer reader
  (`raven_core::stun`). Two minutes per target per week is short; no long campaign results are
  published.

## 4. Continuous integration

Workflows in `.github/workflows/`:

| Workflow | Runs on | What it checks |
|---|---|---|
| `raven-b1-always-on.yml` | every push and pull request | secret history scan, the messaging-only product boundary, `cargo fmt`, a smoke test of the `raven` and `raven-node` commands |
| `raven-serverless.yml` | every push and pull request | Linux, macOS and Windows: `clippy -D warnings`, the `raven-core`, `ash`, `raven-node` and `raven-swarm` tests (nearby with a fake radio, the Tor carrier with a loopback helper), the carrier harness, the 10,000-message queue gate, the 1,000-node simulation, vector drift and protocol freeze hashes, a RustSec dependency audit, that every lab switch is inert and every production flag false in a release build, that the demo cipher cannot reach a release build, a Linux release keystore smoke over the passphrase vault, a Windows type-check from Linux, an SBOM. Advisory (allowed to fail): the same smoke over Secret Service, a reproducible-build comparison and a BlueZ nearby test on emulated controllers. The Go and iOS jobs skip: those trees are not in this repository, and the job summary says so. |
| `raven-serverless-lab.yml` | pushes and pull requests that touch `node/`, `protocol/` or `shared-vectors/` | the ML-KEM-768 incremental code (portable, AVX2, NEON), the Full Braid ratchet lab, NAT and restrictive-network simulations in Linux network namespaces (advisory) |
| `raven-toolchain-canary.yml` | weekly | the latest stable Rust (fmt, clippy, tests), the reliability matrix on software paths, a 2-minute fuzz campaign per target |

CI status of the default branch is shown by the badges in the [README](../README.md#evidence) and
on the repository's Actions page. CI uses debug-only file-backed test stores and never touches an
operating system keychain. The `raven-client` tests (88 functions) are not run by these workflows
yet; run them by hand as the README shows.

## 5. Field test on real networks

One test ran on three real computers (two Macs and a Windows laptop) on a home network and a phone
hotspot, with debug builds and lab switches on. Results, numbers and the problems it found:
[FIELD_TEST_2026_10.md](FIELD_TEST_2026_10.md). In short: 138 / 138 messages in a 6-hour soak at
home over LAN direct; 10 / 10 per direction between a phone hotspot and a home network over the Tor
onion carrier; a Bluetooth chain 10 / 10 both ways; all exactly once. Before the Tor carrier existed,
nothing crossed between the two networks. Three computers and one person is a small sample, and most
of the paths used are switched off in release builds.

## 6. Not done yet

- **Independent security review.** Nobody outside the project has reviewed the protocol, the
  cryptography or the code. An internal review is not a substitute. What an auditor would look at:
  [SECURITY_REVIEW_SCOPE.md](SECURITY_REVIEW_SCOPE.md).
- **Formal model** of PairInit, the session state machine or the hybrid ratchet.
- **Signed and notarised packages.** There is nothing to download; every build is a local build.
- **A long soak.** The longest run so far is hours, not weeks.
- **Many users.** The field test had three computers and one person.
- **More networks.** One home network, one mobile network, one country. No enterprise network, no
  network that blocks Tor, no Linux computer in the field test.
- **Phones.** No phone app is in this repository, and none was tested.
- **Long fuzzing campaigns** and fuzz targets for the decoders listed in section 3.
- **Python parity** for the vector families listed in section 2.
