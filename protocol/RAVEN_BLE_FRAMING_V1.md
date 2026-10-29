# RAVEN BLE Framing V1

**Version:** 1 (`rvn1`)  
**Status:** Binding for GATT / mock_ble carriers of `RavenEnvelopeV1`  
**Companions:** [`RAVEN_ENVELOPE_V1.md`](RAVEN_ENVELOPE_V1.md), [`RAVEN_BRIDGE_V1.md`](RAVEN_BRIDGE_V1.md), [`RAVEN_TRANSPORT_INTERFACE_V1.md`](RAVEN_TRANSPORT_INTERFACE_V1.md)

## 1. Invariant

Bluetooth carries the **same** packed `RavenEnvelopeV1` byte stream as LAN/Internet. Relays MUST NOT transcode JSON↔binary or re-seal content. Fragmentation is MTU-only.

**Note (terminal nodes, no RBF1 rule changed).** Terminal-to-terminal nearby delivery uses [`RAVEN_NEARBY_LINK_V1.md`](RAVEN_NEARBY_LINK_V1.md) (draft, production disabled): an RNP1 byte stream beneath Noise on one GATT characteristic, not RBF1 chunks. RBF1 and `mock_ble` stay migration-only for the legacy bridge ([`RAVEN_CARRIER_CONFORMANCE_V1.md`](RAVEN_CARRIER_CONFORMANCE_V1.md) §11.3 item 2).

## 2. Carrier modes

| Mode | Where | Framing |
|------|-------|---------|
| `ble_gatt` | iOS `RavenBleRvn1Carrier` / `BLEMeshEngine` behind `FeatureFlag.ravenEnvelopeV1` | Raw `RVN1…` written to message characteristic; large envelopes split into ordered chunks |
| `mock_ble` | `raven-node` CI / demos | TCP `u32 BE len \|\| RavenEnvelopeV1` (same as LAN) — hardware-free stand-in |

Default MeshEnvelope JSON path remains when the envelope flag is OFF (legacy).

## 3. GATT chunk framing (when MTU < envelope)

Each chunk:

```
magic "RBF1"(4) || version(1=0x01) || flags(1) || msg_id(16)
  || chunk_index_u16_be || chunk_count_u16_be || u16_be(payload_len) || payload
```

| Rule | Value |
|------|-------|
| Max chunk payload | min(ATT_MTU − overhead, 512) |
| Reassembly timeout | 30 s |
| Ordering | `chunk_index` 0..count-1; missing → drop whole message |
| Integrity | Outer envelope signature covers full reassembled body — chunks are not separately signed |

`flags` bit0 = last chunk redundant with `chunk_index == chunk_count-1` (receivers accept either).

## 4. Validation before radio TX

`raven_core::ble_adapter::validate_opaque_rvn1` (or Swift equivalent) MUST succeed before enqueue on BLE. Non-`RVN1` / unpack failure → drop (no panic).

## 5. Background OS limits

iOS/Android background BLE is OS-restricted. Headless CoreBluetooth on desktop is **BLOCKED_HARDWARE** for CI; `mock_ble` is the software substitute.

## 6. Tests

- Rust: `ble_adapter` unit tests  
- iOS: `RavenBleRvn1CarrierTests` (simulator)  
- Bridge: `bridge_v1` cases using `MockBle`
