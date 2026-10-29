# DRAFT owner waiver: friend custody ("via a friend"), on the local network and over the internet

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file. `FRIEND_CUSTODY_PRODUCTION_ENABLED` and `FRIEND_CUSTODY_WAN_ENABLED`
> (`node/crates/raven-core/src/custody_gate.rs`) stay `false` until the owner
> signs a final copy (renamed to `docs/WAIVER_FRIEND_CUSTODY_<date>.md`), its
> preconditions (§7) are met, and each flip is applied as its own reviewed
> commit. Debug builds open custody with the lab unlock `RAVEN_LAB_TEST_A=1`
> and WAN custody with `RAVEN_LAB_CUSTODY_WAN=1` as well; release builds never
> read either.

| | |
|---|---|
| **Waiver ID** | `WAIVER-FRIEND-CUSTODY-<date>` (to be assigned on signature) |
| **Extends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) (its §2 lists mailbox and store-and-forward delivery as not covered) and, for the WAN part, the p2p record [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md) with its Phase 3 amendment (§10 there) |
| **Not covered** | Internet direct on TCP 7422: [`WAIVER_INTERNET_DIRECT_DRAFT.md`](WAIVER_INTERNET_DIRECT_DRAFT.md) is unchanged, 7422 stays off (decision D5), and a custody route over it also needs the Internet direct gate |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-22 |
| **Decision** | Enable friend custody (RFC1 V1) between verified friends in default and release builds, first on the local network, later over p2p links, under this waiver instead of waiting for an independent review |
| **Review by** | `<YYYY-MM-DD>`: at most 3 months after signature |
| **Withdrawal** | Set `FRIEND_CUSTODY_WAN_ENABLED = false`, or both consts `false`, in `node/crates/raven-core/src/custody_gate.rs` |
| **Design** | [`design/2026-10-friend-custody.md`](design/2026-10-friend-custody.md) (revision 2, and §19 "Over the internet"); the any-network reachability plan (not published) §3 Phase 3 item 3 (C9) |
| **Wire** | [`protocol/RAVEN_FRIEND_CUSTODY_V1.md`](../protocol/RAVEN_FRIEND_CUSTODY_V1.md) (RFC1, version byte 1); [`protocol/RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md) §4 and §12 (RRH1 entries 0x06 CUSTODY_OFFER and 0x07 CUSTODIAN_TAG); vectors `shared-vectors/rvn1/custody/` and `shared-vectors/rvn1/route_hints/rrh1_custody_001.json`, `rrh1_custodian_tag_001.json` |
| **Companions** | [`SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md`](SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md) (a RELEASE deletes the object; signed before the first flip); the route hints records (learned custody rides RRH1, so it also needs `ROUTE_HINTS_PRODUCTION_ENABLED`) |
| **User docs** | `INSTALL_macOS.md`, `INSTALL_Linux.md`, `INSTALL_Windows.md` ("Friend mailboxes"); [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) §9 |
| **Real rows** | an unpublished test checklist: R10, R10b, R11g (R10r optional) |

## 1. Why a waiver is needed

[`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md`](../protocol/RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md)
§9.1 forbids a release flag for store-and-forward delivery until all of its
holds pass, and the LAN waiver §2 leaves "mailbox" and "store-and-forward
bridge delivery" outside its scope. Friend custody lets Alice leave a sealed
message for Bob with Carol, a friend both verified, while Bob cannot be
reached, and lets Bob's ACK come back the same way. It needs its own record.

## 2. Scope (exactly what is covered)

Covered, and only in this combination:

- **RFC1 V1 frames** (DEPOSIT, FETCH, RELEASE and their results) between the
  `raven-node` services of mutual **pinned** (verified) contacts, riding the
  existing authenticated Raven link:
  - over **LAN links from a local-network source** once
    `FRIEND_CUSTODY_PRODUCTION_ENABLED` is set;
  - over **p2p links** (`/raven/link/1.0.0`, direct, hole-punched or relayed)
    only once `FRIEND_CUSTODY_WAN_ENABLED` is set as well. A compile-time
    tripwire makes WAN custody impossible unless custody itself and
    `P2P_PRODUCTION_ENABLED` are on.
- **Objects:** RVNA1 `0x03` sealed messages and sealed ACKs only, staged
  under a confirmed session, with canonical hop fields; never pairing
  material (PairInit, PairResponse, RLB1).
- **Discovery:** the RRH1 entries 0x06 CUSTODY_OFFER (WAN and REACHABLE
  bits) and 0x07 CUSTODIAN_TAG (a pair-blinded SHA-256 tag and a flags byte),
  sent only to verified contacts inside authenticated links; never in cards.
  Phase 2's plain 0x05 entry is receive-only.
- **Consent:**
  - holding mail for friends: `raven node custody on` asks y/N on a terminal
    and needs `--yes` in scripts; its text says what the custodian learns;
  - leaving copies with friends and collecting your own mail: one ask-once
    question, `raven custody use on|off`, at most one ask-once prompt per
    `raven status` run (UPnP, relay offer, mailbox, in that order);
  - static `raven contact set-addr --custodian` lists keep working as explicit
    consent.
- **Automatic home custodians inside that consent:** at most 2, among
  verified friends who send CUSTODY_OFFER, WAN-capable first (while WAN
  custody is live), then reachable, then most recently heard; sticky while
  offered; `raven custody home @x` always wins; a dropped one is still
  fetched from for about 97 h (the 72 h its last announcement lives, plus
  the 24 h a copy left there lives, plus an hour).
- **A friend relay and a custodian on one node**, with separate consents,
  keys (the relay key on 7427 versus the profile identity), ports and quotas.
  The relay kit has no Raven identity and can never be a custodian.
- **`raven outbox hand-off`:** a 10-minute window that skips the 60 s wait
  before a deposit.

Not covered (all remain held): custody of anything but RVNA1 `0x03`
messages and ACKs, multi-hop or spray delivery, custodian-initiated delivery,
first contact or re-pairing through a friend (no PairInit in custody), a
sealed asynchronous PairInit, custodian advertising in cards, Internet direct
(7422) as a custody carrier, the swarm offline mailbox
(`/raven/offline-mailbox/1.0.0`), mesh and bridge custody (`RHW1`), Bluetooth
handoff inboxes (Phase 5), and Swift / iOS.

## 3. Holds of umbrella §9.1 waived for this scope

| Hold | Status | Waived? |
|---|---|---|
| 1. Automated gates | Unit tests, RFC1 and RRH1 vectors, fuzz target `rfc1_frame`, carrier_matrix C32-C34, fault matrix s30, s30p, s30w, s30r and s125 green on macOS | Not waived |
| 2. All companions APPROVED | RFC1 and RRH1 §12 are drafts | **Waived for this slice** |
| 3. Independent security review | Not done; the internal adversarial reviews are not independent | **Waived** |
| 4. Physical rows | Open: R10, R10b, R11g | Not waived: each flip waits for its rows (§7) |
| 5. Store-and-forward paths stay lab-gated | Friend custody becomes live | **Waived for this slice only** |

## 4. Residual risks accepted

1. **The custodian learns both identities** (design §11, N4). Carol cannot
   read a deposited object, but learns the depositor and recipient keys, the
   size, time, `message_id` and expiry of each object, the daily store tag
   (which links a pair's traffic within a day), when the recipient collects
   and releases it, and when its ACK follows. Over the internet she also sees
   both IP addresses, or the relay's.
2. **Signed proof of who wrote to whom.** Envelopes are signed with the
   long-term key, so Carol's copy proves that one friend wrote to another
   until it is deleted: on RELEASE (with the errata rule 9 amendment) or at
   expiry, at most 24 h.
3. **The 24-hour limit.** An object lives until its envelope's `expires_at`,
   at most min(created + 24 h, session end) plus the 5 min clock-skew
   allowance; there is no extension. Custody cannot help a pair whose
   session has ended: session renewal (Phase 3 item 4) is the remedy, a
   first contact through a friend stays out of scope.
4. **S9: an ACK that expires before Alice fetches it** makes Alice show
   "expired" although Bob got the message.
5. **Colluding custodians** of the same pair can link objects by digest, and
   each sees the pair's tags. Home custodians see the counts and daily tags
   of every live session of the recipient with a pinned contact (owner
   decision "fetch tag scope"), never identities unless someone deposits.
6. **No forward secrecy inside a session** (LAN waiver §4.1): anyone who later
   obtains Alice's or Bob's session state within the object's lifetime can
   open Carol's copy, as with a recording of LAN traffic.
7. **Availability only.** Carol can drop, withhold or delay; Alice keeps
   retrying directly, and up to 2 custodians give redundancy. Only a verified
   ACK delivers.
8. **Relay and custodian on one node** learn both roles' metadata: the relay
   sees circuits and timing, the custodian identities and sizes.
9. **No independent review** of RFC1, its admission rules or the at-rest
   store, and Swift parity is not verified in this tree.

## 5. Compensating controls in place

- Link admission before identity: strangers, blocked keys and unpinned
  contacts are refused (`NOT_VERIFIED`, `LINK_NOT_ACCEPTED`); FETCH and
  RELEASE match `recipient == link peer`, so a co-custodian gets nothing.
- The depositor must be the envelope's outer signer; canonical hop fields;
  SHA-256 of the exact bytes as the dedup key; pairing material refused at
  deposit and again at ingest.
- Bounded custodians: 4,096 rows and 64 MiB per node, 512 rows and 16 MiB per
  depositor, 128 per pair, 120 deposits, 2 MiB and 30 fetches per minute;
  refuse, never evict. Requester budgets: at most 16 deposits and 512 KiB per
  dial, at most 4 fetch pages per trigger while the custodian's last path was
  relayed (8 otherwise), which fits a friend relay's per-circuit budget.
- The custodian's store and owed ACKs are sealed at rest (the privacy pack's
  at-rest API) and purged when the contact is removed or unpinned.
- Each end checks the gate per link: a LAN link needs a local-network source
  while WAN custody is off; an Internet or p2p link gets `HOLD` and nothing is
  written.
- Logs carry counts only: no address, PeerId, key or name.

## 6. Conditions

This waiver lapses, and the affected flag MUST be set back to `false`, if:

- a critical or high finding on the covered path is confirmed and not fixed;
- custody carries anything but RVNA1 `0x03` messages and sealed ACKs, admits
  an unpinned or blocked peer, or a custodian evicts instead of refusing;
- custody offers or tags travel outside authenticated links or to unverified
  contacts, or appear in cards;
- the WAN tripwire is removed, or `FRIEND_CUSTODY_WAN_ENABLED` is on while
  `P2P_PRODUCTION_ENABLED` is off;
- a custodian or a home-custodian choice works without the user's consent;
- the p2p waiver, its Phase 3 amendment (for the WAN part) or the LAN waiver
  lapses or is withdrawn;
- C32-C34, s30, s30p, s30w, s30r or s125 is disabled or fails on any of its
  runners for more than one release;
- the review-by date passes without renewal.

## 7. Preconditions and flip order

Before signature:

- [`SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md`](SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md)
  signed;
- carrier_matrix C32 (custody over relay circuits, message and ACK, with a
  byte scan), C33 (the WAN gates and refusals) and C34 (a friend relay and a
  custodian on one node) green on ubuntu, macOS and Windows;
- lan_fault_matrix s30 (with and without `RAVEN_FAULT_HINTS=1`), s30p, s30w,
  s30r and s125 green 5 times on macOS and Linux;
- the netns `custody` case (advisory, Linux;
  [`NAT_SOFTWARE_SIM.md`](NAT_SOFTWARE_SIM.md));
- the RRH1 custody vectors re-read by the Python reference
  (`protocol/reference/tests/test_route_hints_custody.py`) and the RFC1
  vectors (`shared-vectors/rvn1/custody/`) green in Rust;
  [`PROTOCOL_FREEZE_HASHES_V1.md`](PROTOCOL_FREEZE_HASHES_V1.md) checked.

Flip order, each in its own reviewed commit, after signature (the flips are
owner actions, not part of the Phase 3 work):

1. `FRIEND_CUSTODY_PRODUCTION_ENABLED` after real row **R11g** (a custodian
   laptop on an offline LAN);
2. `FRIEND_CUSTODY_WAN_ENABLED` after real rows **R10** and **R10b**, and only
   once `P2P_PRODUCTION_ENABLED` is live under its signed waiver.

At the first flip, the RFC1 status line, the RFC1 row of
[`protocol/PROTOCOL_VERSIONS.md`](../protocol/PROTOCOL_VERSIONS.md) and the
freeze hashes are updated in the same commit.

## 7a. Letters (Phase 5b, draft amendment)

> **DRAFT amendment (P5.16). NOT SIGNED, NOT IN FORCE.** Letters are held by
> their own gate, `ASYNC_LETTER_PRODUCTION_ENABLED` (in
> `node/crates/raven-core/src/horizon.rs`), which stays `false`, needs
> `LONG_HORIZON_PRODUCTION_ENABLED` and this waiver's custody gate, and is
> not flipped by signing this file. Debug builds open it with
> `RAVEN_LAB_LETTER=1`, `RAVEN_LAB_HORIZON=1` and the lab unlock.

**Scope.** A custodian that serves the RFC1 letter ops (0x04-0x06, §10 of
[`protocol/RAVEN_FRIEND_CUSTODY_V1.md`](../protocol/RAVEN_FRIEND_CUSTODY_V1.md))
holds sealed RAL1 letters
([`protocol/RAVEN_ASYNC_LETTER_V1.md`](../protocol/RAVEN_ASYNC_LETTER_V1.md))
for two verified friends, under the same admission, consent and at-rest
rules as the base objects. A letter carries a PairInit V1 and up to 16 sealed
messages (LETTER), or a PairResponse and up to 32 sealed ACKs (REPLY), so a
contact who stays away for more than a day still gets a message without a
live session ([`design/2026-10-beyond-24h.md`](design/2026-10-beyond-24h.md)
§4).

**Residual risks accepted in addition to §4:**

1. **Held up to 7 days.** A letter lives until its latest envelope expires,
   at most 7 days (plus the 5 min skew allowance), not 24 h: the custodian's
   metadata (both devices, times, size rounded to 512 bytes, the bundle hash)
   and the depositor's signature over the letter, proof of who wrote to whom,
   last that long unless the recipient's RELEASE or the sender's WITHDRAW
   deletes it first.
2. **A sealed PairInit travels through a third party.** The letter starts a
   session: its PairInit (addresses, trust hashes) is inside the wrap and
   never readable by the custodian, but the custodian holds it, and the
   recipient's claim budget is spent on it (at most 8 letter claims per
   initiator, `LETTER_CLAIM_LIMIT` keeps the letter).
3. **The chain-0 forward secrecy window.** Letters use no one-time prekey:
   anyone who later obtains the recipient's retained signed prekey generation
   (kept until its `destroy_after`, about 37 days at worst) and the letter
   bytes can read the letter's messages (chain indices 0-15 of a provisional
   session), the same window as an ordinary PairInit, with more content in it.
4. **A classical-only wrap.** The RAL1 wrap is X25519 to the signed prekey,
   as the Noise XX links: a future quantum adversary that records a letter
   may open the wrap (the PairInit and the envelope headers); the messages
   stay under the session's hybrid root (X25519 + ML-KEM-768).

**Additional conditions** (with §6): the waiver for letters lapses, and
`ASYNC_LETTER_PRODUCTION_ENABLED` MUST be `false`, if a custodian evicts a
letter instead of refusing it, admits a letter op from an unverified link
peer, serves a letter to anyone but its recipient or withdraws it for anyone
but its depositor, or if s61, s61b, s62, s75 or s76-s76c (lan_fault_matrix,
`RAVEN_FAULT_LETTER=1`) is disabled or fails for more than one release.

**Additional preconditions** (with §7): the RAL1 and RFC1 letter vectors
re-read by the Python reference; s61, s61b and s62 green 5 times on macOS and
Linux; the user texts (`raven node custody on`, "Use friends as mailboxes?")
name letters and their 7 days.

## 8. Signature

Not signed.
