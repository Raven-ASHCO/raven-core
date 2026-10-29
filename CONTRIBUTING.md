# Contributing to Raven

Thank you for helping. A few rules keep Raven safe and reviewable.

## Before you start

- **Security problems:** never in a public issue. Write to security@raven-messager.com
  ([SECURITY.md](SECURITY.md)).
- **Bugs:** open an issue with the commit you tested, the crate or binary, your operating system,
  whether it was a debug or release build (and any `RAVEN_LAB_*` switch you set), the steps, and
  what you expected.
- **Larger changes:** open an issue first, so we can agree on the approach.

## Making a change

1. Fork, branch, change, and add or update tests.
2. Run the checks for what you touched (from `node/`, with the file-backed test stores of the
   README's "Test" section):
   ```sh
   cargo fmt --check
   cargo clippy --locked -p <crate> --all-targets -- -D warnings
   cargo test --locked -p <crate>
   ```
3. Open a pull request that says what changed and why.

## Rules

- **Wire formats are versioned, never edited in place.** A protocol change updates the spec in
  `protocol/`, the vectors in `shared-vectors/` (`python3 protocol/reference/generate_rvn1.py`) and
  the Python reference tests, and regenerates `docs/PROTOCOL_FREEZE_HASHES_V1.md` with
  `bash scripts/freeze_protocol_hashes.sh` in the same pull request.
- **Lab features stay off in release builds** until their release gate is signed. Do not flip a
  `*_PRODUCTION_ENABLED` constant in a feature pull request.
- **New dependencies** need a reason in the pull request and an exact version.
- **No personal data** in code, tests or docs: use sample names (Alice, Bob), documentation
  addresses (192.0.2.x, 2001:db8::) and `example` domains.
- English only in product text, docs and comments.

## Good places to start

Each of these closes a gap listed in [docs/EVIDENCE.md](docs/EVIDENCE.md) or
[docs/ROADMAP.md](docs/ROADMAP.md):

- **Run the field test on your own computers** (debug builds, lab switches as in
  [docs/FIELD_TEST_2026_10.md](docs/FIELD_TEST_2026_10.md)) and file a
  [field test report](.github/ISSUE_TEMPLATE/field_test_report.md). Linux computers, other
  countries, networks that block Tor and enterprise networks are all untested.
- **Review a spec against its code**, for example
  [RAVEN_ONION_CARRIER_V1](protocol/RAVEN_ONION_CARRIER_V1.md) against `raven-node/src/onion/`, or
  [RAVEN_FRIEND_CUSTODY_V1](protocol/RAVEN_FRIEND_CUSTODY_V1.md) against
  `raven-core/src/friend_custody.rs`. A difference is a bug in one of them.
- **Add fuzz targets** for decoders that have none yet: group frames (`raven_core::group`), the
  onion binding and the Tor helper's local protocol (`raven_core::onion`,
  `raven-node/src/onion/proto.rs`), the STUN answer reader (`raven_core::stun`). See
  [node/fuzz/README.md](node/fuzz/README.md).
- **Python parity:** teach the reference in `protocol/reference/` to read the vector families only
  Rust checks today: `shared-vectors/rvn1/onion/`, `group/`, `custody/`, `session_reset/`,
  `app_payload/`.
- **Run `raven-client`'s tests in CI**: no workflow runs them yet.
- **Wording**: the field test found messages that give local-network advice when Tor was the real
  path; plain, accurate status text is always welcome.

## License

By contributing you agree that your contribution is licensed under the GNU Affero General Public
License v3.0 ([LICENSE](LICENSE)). The Raven name and visual assets are covered by
[TRADEMARK.md](TRADEMARK.md) and [ASSET_LICENSE.md](ASSET_LICENSE.md).
