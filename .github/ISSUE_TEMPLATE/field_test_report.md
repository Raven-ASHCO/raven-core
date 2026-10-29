---
name: Field test report
about: You ran Raven on your own computers and networks; tell us what was delivered and what was not
title: "[field test] "
labels: field-test
---

<!--
Thank you for testing on real networks. docs/FIELD_TEST_2026_10.md shows the kind of test and
the numbers that help most.

PRIVACY: describe networks by TYPE only (home Wi-Fi, phone hotspot, office). NEVER post an IP
address, a network name, an onion address, a contact card, a PeerId, security words, keys, user
names or folder paths. Name computers by type ("Windows laptop", "Linux desktop").

Security problems: do NOT post them here. Write to security@raven-messager.com (SECURITY.md).
-->

## Summary

<!-- One or two sentences: what you tested and the main result. -->

## Build

- Commit or tag:
- Build type: <!-- debug or release -->
- Lab switches set: <!-- for example RAVEN_LAB_TEST_A=1 RAVEN_LAB_STUN_DISCOVERY=1 RAVEN_LAB_TOR=1, or "none (release)" -->
- Cargo features: <!-- for example --features raven-node/tor -->

## Computers and networks

| Computer (type and OS) | Network type | NAT type, if you know it | Notes |
|---|---|---|---|
| e.g. MacBook, macOS 26 | phone hotspot | the NAT line of `raven status` or `raven doctor`, without addresses | |
| e.g. Windows laptop, Windows 11 | home Wi-Fi behind a second router | | |
| | | | |

Port forwarding or router changes made for the test: <!-- none, or what kind (no addresses) -->

## Results

Count each message as delivered only if it arrived **exactly once**. Say how long you waited.

| From | To | Sent | Delivered exactly once | Duplicates | Path shown (LAN, Tor, direct, relay, a friend kept it, Bluetooth) | Time per message |
|---|---|---|---|---|---|---|
| | | | | | | |
| | | | | | | |

Time limit used for counting: <!-- for example 5 minutes after the last send -->

## Friends away, restarts, network changes

<!-- Did you stop a node, close a lid, move a laptop to another network? What waited, and when did it arrive? -->

## Problems

<!-- One item per problem: what you did, what you expected, what happened, the exact Raven text (private data removed). -->

- 

## Anything else
