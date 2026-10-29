# Phase 1 real rows R3, R5, R9 and R14 (operator checklist)

**Status:** owner-run, **open**. Needs a third reachable machine as relay R, a
second phone or SIM, and sudo for `tcpdump`. The rows are defined in
[`design/2026-10-any-network-reachability.md`](design/2026-10-any-network-reachability.md)
("Real-world test matrix"); the tool is
`node/scripts/wan_two_network_test.sh` (its three-node mode). The Phase 0 row
R12 is at the end.

## 0. Purpose and honest claim

- Real networks, a debug build and the lab unlock (`RAVEN_LAB_TEST_A=1`, which
  the script sets). `P2P_PRODUCTION_ENABLED` stays `false`; nothing here flips
  a gate.
- Every message rides a **true circuit**: R relays between A and B, the sender
  is not the relay, and each `three send` restarts the sender first, so it has
  no connection to the recipient before the first message. The two-node
  `friend-host` / `friend-use` commands (Phase 2 friend relays) are not this:
  a message between those two machines rides a direct connection or the
  host's own connection (connection reversal).
- Loopback and netns results do not replace these rows: carrier_matrix C15 /
  C16, `three-dry-run` and the netns cases (C7) run on one kernel
  ([`NAT_SOFTWARE_SIM.md`](NAT_SOFTWARE_SIM.md), "Honest claim").
- Mapping to [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md) §7: R3
  (two homes behind consumer NAT, the forward removed, relay on a VPS) covers
  R7b; R5 and R9 (one or both sides on a phone hotspot) cover R8. R14 is the
  stranger privacy row.
- The results are attached to the waiver's signature record (section 6).

## 1. Gear

- R: a small Linux VPS with a public IPv4 (about €5 a month). The Mac Studio
  cannot be both the recipient and an independent relay in R3. For R9 it may
  be the relay: a dedicated relay folder on port 7424 with its own forward.
- Laptop 1, the Mac Studio, an iPhone hotspot, and a second phone or a SIM
  dongle.
- Test profiles only (`RAVEN_WAN_HOME`, default `~/raven-wan-test`), never
  `~/.raven`, `~/raven-try` or a live node.
- A machine that already runs a Raven node (the live one on 7420, say) needs
  other ports for the test node: `RAVEN_WAN_LAN_PORT=7430
  RAVEN_WAN_P2P_PORT=7433` in front of every command on that machine.

## 2. Rehearse once, on one machine

```bash
node/scripts/wan_two_network_test.sh three-dry-run
```

It runs R, A, B and a stranger on loopback in a fresh temp folder and must end
with `DRY RUN OK (loopback, not a WAN claim)`: 3/3 messages delivered with
`path=relayed`, and the stranger refused by B's peer gate.

## 3. One-time setup of R (the VPS)

```bash
sudo apt-get update && sudo apt-get install -y build-essential pkg-config git python3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.98.0
. "$HOME/.cargo/env"
git clone https://github.com/Raven-ASHCO/RAVEN.git raven && cd raven
git checkout <the commit under test>
(cd node && cargo build --locked -p ash -p raven-node)
sudo ufw allow 7423/tcp && sudo ufw allow 7423/udp   # and the provider's firewall
node/scripts/wan_two_network_test.sh vps-relay start <VPS public IP>
```

Keep the printed VIA. It is the QUIC one by default; the relay also listens on
TCP and prints that VIA too. Where a network blocks UDP, give A and B the TCP
VIA (or start the relay with `RAVEN_WAN_RELAY_TRANSPORT=tcp`) and record that.

## 4. Common steps on A and B

1. On each: `node/scripts/wan_two_network_test.sh three setup NAME '<VIA>'`
   (`alice` on A, `bob` on B). It prints the card (its only `via=` is R) and
   the fingerprint, then waits up to 180 s for R to accept the reservation.
2. Meanwhile on R, for **both** cards: `vps-relay allow '<card>' <label>`. R
   relays only between peers on its list (consent by circle), so a sender
   missing from it is refused by R.
3. Compare the fingerprints by voice or in person, then
   `three add '<other card>' <tag> <other fingerprint>` on each side. It
   refuses (exit 2) unless the contact is reached only through relays.
4. On R: `vps-relay status` shows `allow_list 2 peer(s)` and
   `reservations=2`.

## 5. The rows

### R3: home router with the forward removed, relay on the VPS

- Remove the 7422 / 7423 forwards on the home router; UPnP stays off. On R,
  `vps-relay probe <home public IP> 7423` (and 7422) must print `UNREACHABLE`.
- B = the Mac Studio at home; A = laptop 1 on another fixed network or a
  hotspot.
- `three send bob 10` on A, `three send alice 10` on B, `three rate bob 5` on A.
- Pass: 10/10 each way. The first message of every fresh session is
  `path=relayed`, and `vps-relay status` shows `circuits` at least 1 right
  after it (a true circuit). The DCUtR result and rate are recorded.

### R5: laptop on the iPhone hotspot, home node, relay on the VPS

- A = laptop 1 on the iPhone hotspot (always listening); B = the Mac Studio at
  home.
- 10 each way, plus `three rate bob 5` (at least 5 fresh sessions).
- Pass: 10/10 each way; the DCUtR rate recorded.

### R9: both laptops on different phone hotspots

- A and B on two different phone hotspots. R is the VPS, or the Mac Studio's
  dedicated relay: `RAVEN_WAN_RELAY_PORT=7424 node/scripts/wan_two_network_test.sh
  vps-relay start <home public IP>` with a 7424 TCP + UDP forward for the test
  only.
- 10 each way.
- Pass: 10/10 each way.

### R14: a stranger with B's card opens a circuit

- S is a stranger profile on a network that is neither A's nor B's, or the
  `stranger` profile on laptop 1 with A stopped (`three stop`). S holds B's
  card; B does not know S.
- On S: `three stranger '<B card>' <B fingerprint>`. It prints S's card: on R,
  `vps-relay allow '<S card>' stranger`. Only a member of R's circle reaches
  B's own peer gate; a non-member is refused by R, and the script then says
  `R14 INCONCLUSIVE`.
- Note B's `p2p_gate` status row ("refused N connection(s)"; `ash --data-dir
  <B's test profile> status` with the test build's `ash`) before the probe, and
  do not restart B until the probe is done (the count starts over).
- Start both captures (find the interface with `route -n get default` on macOS
  or `ip route show default` on Linux):
  - on B: `sudo tcpdump -ni <wan interface> -w r14-b.pcap host <S public IP>`
  - on S: `sudo tcpdump -ni <interface> -w r14-s.pcap host <B public IP>`
- Press Enter on S: one `--carrier p2p` probe.
- Pass:
  - S prints `R14 probe refused (expected)`: not delivered, no
    `LINK_NOT_ACCEPTED`, no hole punch logged on S;
  - B's `p2p_gate` refused count is one higher and its `node.log` has
    `raven-node p2p: refused a connection from a peer that is not a verified
    contact` (no PeerId);
  - `tcpdump -r r14-b.pcap | wc -l` and `tcpdump -r r14-s.pcap | wc -l` are
    both 0.
- Positive control: capture again while contact A, on S's network, runs
  `three rate bob 2`. If DCUtR upgrades, packets appear, which shows the
  method would catch a disclosed candidate. Record it either way.
- Honest limit: DCUtR's messages travel encrypted end to end inside the
  relayed connection, so a capture shows only that no candidate address was
  **used** (no direct packet either way), plus B's gate count. That no
  candidate was **sent** is proven from inside the circuit by carrier_matrix
  C16 (its spy as a stranger gets no Identify, no DCUtR and dials nothing; as
  a contact it is offered B's loopback candidate) and C15.

## 6. Record each row (both directions)

- Delivered x/10.
- Path counts: direct, reversed, relayed, hole_punched.
- DCUtR upgraded (yes or no) and the rate.
- Median and maximum seconds until the receipt.
- The OS pair and the network types.
- The relay transport (QUIC or TCP).
- Commit hash, date (UTC) and the operator's role.

`three send` prints the delivered count, path counts, median and maximum, and
writes a TSV. Then run `report ROW` on A and B and `vps-relay report ROW` on R.

**Where results go:** `node/proof_artifacts/wan3-<ROW>-<UTC>/` (git-ignored:
`proof_artifacts/` in `.gitignore`), with both `wan-report-*-ROW-*.txt`, the
TSVs, `relay3-report-ROW-*.txt` and, for R14, both pcaps. The folder is
attached to the waiver's signature record. The reports and pcaps hold public
IP addresses: redact them before sharing, for example
`sed -i.bak 's/203\.0\.113\.7/<B-public-IP>/g' wan-report-*.txt`.

## 7. Cleanup

- `three stop` on A, B and S; `vps-relay stop` on R. Delete the test homes
  once the records are saved.
- Restore the Mac Studio forward per D15: a single 7423 TCP + UDP forward, or
  none. Remove any 7424 forward made for R9.

## R12 (Phase 0 exit): network switches

Owner-run on the Macs, in a separate lab profile (never `~/raven-try` or the
live 7420 node), debug build with `RAVEN_LAB_TEST_A=1`. Set it up like R5
(sections 3 and 4: A = laptop 1, B = the Mac Studio, R = the VPS or the Mac
Studio's dedicated relay on 7424), then watch A's `node.log`:

- Switch A from Wi-Fi to the iPhone hotspot and back. Pass: one
  `raven-node netwatch: network changed (… new, … gone, … now)` line ending
  `, p2p re-homing`, then `raven-node p2p: re-homed (network changed)` and
  `reservation accepted` within about 5 s of each switch.
- Queue one: with A offline (Wi-Fi off), `send bob p2p 1` on A (it is
  queued: "not delivered yet"); then join the hotspot. Pass: delivered within
  about 30 s, with no command.
- Close the lid for a minute, then open it. Pass: `raven-node netwatch: woke
  from sleep (…)`.
- Record with `report R12` on A.
