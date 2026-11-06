# RAVEN delta over secret-service 2.0.2 (Task 0B.3 R0)

MIT/Apache-2.0 upstream copyright retained. This fork does **not** change DH parameters, HKDF, AES-CBC, or D-Bus wire types.

## Allowed surface

| File | Change |
|---|---|
| `error.rs` | `Error::PromptRequired` — typed refuse without executing Prompt |
| `collection.rs` | `create_item_no_prompt` — DH session required; prompt path → `PromptRequired`; **add-only** (D-Bus `replace` flag removed from the API and hard-wired to `false`) |
| `item.rs` | DH-only `delete_no_prompt`, `collection_path`, closure-based zeroizing secret read |
| `session.rs` | Redacted `Debug`; `Drop` zeroizes retained keys; zeroizable bigint + KDF/private byte owners; upstream-math compatibility KAT |
| `util.rs` | Zeroizing AES-key borrow/IV owner on success and error |
| `proxy/mod.rs` | Redacted `Debug` plus zeroizing `Drop` for D-Bus secret values |
| `Cargo.toml` | `zeroize` plus pinned `num-bigint-dig 0.9.1`/`zeroize`; description notes Raven pin |
| `Cargo.lock` | left out: upstream's lock is for its own examples; the fork builds in Raven's workspace, whose `node/Cargo.lock` pins `num-bigint-dig 0.9.1` |
| tests | R0 hard-stop proofs under `tests/raven_r0_hard_stop.rs` |

## Explicit non-goals (R0)

- No plain-session fallback for no-prompt APIs.
- No change to upstream `create_item` / `delete` prompt-executing behavior (still present for compatibility).
- No Raven protected-anchor backend rewrite (that is Task R1).
- No workspace-wide crates.io patch. This fork is built and tested standalone in
  R0 and is not in Raven's default dependency graph.
- No R1 normalization policy for provider-reported content type. Exact binary
  bytes are proved in R0; GNOME Keyring's observed `text/plain` is a recorded
  R1 platform hold.

## Re-freeze 2026-08 (authorized drift)

Independent R0 review rejected the caller-controlled `replace: bool`
argument on `create_item_no_prompt` (`true` could destructively overwrite an
existing item). The argument was removed and the D-Bus flag hard-wired to
`false`; a static no-mutation negative test
(`raven_create_item_no_prompt_is_add_only`) now pins this boundary.
`src/collection.rs`, `tests/raven_r0_hard_stop.rs`, this file, and
`RAVEN_PATCH_DIGEST` were re-frozen accordingly. The prior digest values are
superseded; `verify_secret_service_2_0_2_raven_noprompt.sh` asserts the new
frozen digest against the exact file set on every run.

## Re-freeze 2026-11 (provenance only, no source change)

The 2026-11 security review (DEP-5) found that the verifier could not pass
on a clean checkout: it listed `Cargo.lock` as a modified file and froze its
digest, but this fork's `.gitignore` keeps `Cargo.lock` out of git, so no
checkout had one ("missing upstream file: Cargo.lock"), and no CI job ran
the verifier. `Cargo.lock` is now a declared removed file
(`RAVEN_PATCH_MANIFEST` `[removed]`; the verifier refuses one that is
present), its line left `RAVEN_PATCH_DIGEST`, and the verifier's pinned
digest was updated for exactly that. This file and `RAVEN_PATCH_MANIFEST`
changed with it; no source file did. CI now runs the verifier and its
negatives, and `node/scripts/verify_vendored_forks.py` checks this fork
against the crates.io archive with every changed file pinned in
`node/third_party/forks.json`.
