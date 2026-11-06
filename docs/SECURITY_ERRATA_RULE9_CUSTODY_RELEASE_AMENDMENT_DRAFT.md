# Amendment to errata rule 9 for friend custody RELEASE (accepted 2026-11-06, applied)

| | |
|---|---|
| **Status** | **Accepted by the owner on 2026-11-06 (owner decision 4: custody stays on in release); applied the same day.** The owner reads the final text before it is published. This draft had asked for its signature before any custody flip; instead `FRIEND_CUSTODY_PRODUCTION_ENABLED` and `FRIEND_CUSTODY_WAN_ENABLED` (`node/crates/raven-core/src/custody_gate.rs`) were switched on in release builds on 2026-10-29 (commit b783524), so release custodians have deleted on RELEASE since then, before this acceptance. The file keeps its name because many documents link to it. |
| **Amends** | [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md) rule 9 and [`protocol/RAVEN_FRIEND_CUSTODY_V1.md`](../protocol/RAVEN_FRIEND_CUSTODY_V1.md) §6 "Custodian rules". Both frozen files carry the diffs of §2 and §3 since 2026-11-06, with a freeze record entry in [`protocol/PROTOCOL_VERSIONS.md`](../protocol/PROTOCOL_VERSIONS.md) and the freeze hashes regenerated. |
| **Decision** | Owner decision OD-PP-6 (a) of the privacy pack (`docs/roadmap/plans/privacy-pack-plan.json`), which takes Phase 6b's OD6b-15 and the cutoff pack's OD-C11: delete on RELEASE, behind the existing custody gate, with this amendment signed before any custody flip. The flip came first; owner decision 4 of 2026-11-06 accepted the amendment afterwards |
| **Code** | Privacy pack PP.17: `CustodyStore::release` in `node/crates/raven-core/src/friend_custody.rs`; design `docs/design/2026-10-at-rest-metadata.md` sections 4.15 and 7.4, `docs/design/2026-10-friend-custody.md` §6.5 |
| **Wire** | No change: the RELEASE and RELEASE_RESULT frames, their codes, RSO1 and every other byte stay as they are; no version changes |
| **Approver** | Protocol owner: accepted on 2026-11-06 (owner decision 4); the owner reads the final text before publication |
| **Date drafted** | 2026-10-19 |
| **Applying it** | Done on 2026-11-06: the two diffs below went into the frozen files, `docs/PROTOCOL_FREEZE_HASHES_V1.md` was regenerated with `scripts/freeze_protocol_hashes.sh` and checked (`--check`), and this file records the acceptance |
| **Withdrawal** | Revert the two diffs (and the freeze manifest, with a freeze record entry) and turn RELEASE back to hiding only, or set both custody consts `false` |

## 1. Why an amendment

Errata rule 9 says that Store Object V1 deletion is TTL-only: the arrival of a sealed ACK cannot
reveal the acknowledged ID or authorize a custody deletion, and early deletion needs "a future
versioned, object-bound deletion token". Friend Custody V1 was written within that rule: RELEASE
only hides the named objects from their recipient, and the custodian keeps each payload, both
parties, its size and its times until the object expires (up to 24 hours).

On a custodian's laptop that is taken or inspected, those released rows are pure liability: they
show which of its friends wrote to whom, when and how much, for messages that were already
collected (people study measure M12; Phase 6b OD6b-15; cutoff OD-C11). RFC1's RELEASE is already
the object-bound deletion the rule asks for:

- it is sent by the object's recipient, authenticated on the Noise link and a pinned contact of
  the custodian (RFC1 §2 and §6), never by a third party or a co-custodian;
- it names exact object digests (RFC1 §4), and the custodian matches each against the recipient
  the object was deposited for (RFC1 §3: every object is bound to `(recipient, store_tag)`);
- it is not an ACK arrival: it reveals nothing to the custodian that the custodian does not
  already hold (the digest is the custodian's own index of the object).

So the amendment adds no token and no frame: it states that RFC1's RELEASE deletes.

## 2. Errata rule 9: the sentence to add

> RELEASE by the authenticated recipient deletes the object's payload and pair columns; the digest
> is kept until expiry for dedup.

The diff of `protocol/SECURITY_ERRATA_RVN1_2026-08-13.md` (rule 9, its last sentences), applied
on 2026-11-06:

```diff
    mailbox tags. Store Object V1 deletion is TTL-only: sealed ACK arrival
    cannot reveal the acknowledged ID or authorize custody deletion. Early
    deletion requires a future versioned, object-bound deletion token.
+   Friend Custody V1 (RFC1) RELEASE is such an object-bound deletion:
+   RELEASE by the authenticated recipient deletes the object's payload and
+   pair columns; the digest is kept until expiry for dedup.
```

## 3. RAVEN_FRIEND_CUSTODY_V1.md §6 "Custodian rules": the matching sentence

The spec's sections are 1-9; RELEASE is specified in §6 ("RELEASE hides the named objects from that
recipient; the payload is deleted only at TTL"). The diff, applied on 2026-11-06:

```diff
 FETCH returns, in page-token order, the link peer's unreleased, unexpired
 objects under the presented tags, after the cursor: at most `max_items` (≤ 16)
-and 128 KiB, at least one if any matches. RELEASE hides the named objects from
-that recipient; the payload is deleted only at TTL.
+and 128 KiB, at least one if any matches. RELEASE by the authenticated
+recipient deletes the named objects' payload and pair columns (recipient,
+depositor, sizes, times); the digest is kept until expiry for dedup, so a
+DEPOSIT of a released digest is DUPLICATE and FETCH never returns it.
```

No other section changes: §2 (custody off still serves FETCH and RELEASE until held objects
expire), the codes of §5 and the recipient rules of §7 read the same.

## 4. What the code does (PP.17; live in release builds since 2026-10-29)

- `CustodyStore::release`: in one IMMEDIATE transaction each released object's row is deleted
  (payload, recipient, depositor, size, store tag, page token, both times) and its digest is kept
  in `custody_released_v1` with the hour it would have expired in (rounded up), then the WAL is
  checkpointed; `secure_delete` overwrites the deleted cells and freed pages in the file. A replay
  of the digest is `DUPLICATE` until that hour has passed; FETCH after RELEASE returns nothing.
- In a sealed profile the open rows' digest and parties are keyed lookups and their payload and
  times are sealed (`docs/design/2026-10-at-rest-metadata.md` section 7.4).
- Tests: `release_deletes_payload_and_pair_columns_and_keeps_the_digest`,
  `redeposit_after_release_is_a_duplicate_until_expiry`, `fetch_after_release_is_empty`,
  `custody_file_byte_scan_after_release_has_no_friend_key` (raven-core `friend_custody::tests`),
  and the fault matrix's s125 `custody_release_deletes` (`RAVEN_FAULT_CUSTODY=1`).

## 5. Compatibility

Nothing on the wire changes, so every peer keeps working. A recipient cannot tell a custodian that
deletes from one that hides: in both, a released object is never fetched again and a re-deposit
of it is `DUPLICATE`. An older custodian (before PP.17) keeps hiding and deletes at TTL, which
this amendment still allows (it permits early deletion; it does not require a custodian to prove
it). Store Object V1 outside RFC1 stays TTL-only.

## 6. Honest limits

Deleting in SQLite cleans the file, not the freed disk blocks that held it (full-disk encryption
covers those). The digest and its expiry hour stay until expiry. The envelopes are signed, so a
copy that someone made before the RELEASE stays proof of who wrote to whom.
