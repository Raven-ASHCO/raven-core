#!/usr/bin/env python3
# protocol/reference/generate_peer_rotation.py
"""Deterministic generator for the P2P PeerId rotation V1 vectors.

Source of truth: raven_protocol.peer_rotation (Ed25519 from the `cryptography` package,
requirements.txt)  |  Spec: protocol/RAVEN_P2P_PEER_ROTATION_V1.md. Writes
<out>/p2p/epoch_peer_id_001.json, epoch_phase_001.json, relay_schedule_text_001.json and
card_p2pn_001.json (default out: shared-vectors/rvn1). This generator owns those four files only;
other generators write other files under p2p/.

    python3 -I generate_peer_rotation.py            # write the vectors
    python3 -I generate_peer_rotation.py --check    # exit 1 if any file on disk differs
"""
import argparse, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from raven_protocol import address, fingerprint, via  # noqa: E402
from raven_protocol import peer_rotation as pr  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
OWNED = ("p2p/epoch_peer_id_*.json", "p2p/epoch_phase_*.json", "p2p/relay_schedule_text_*.json",
         "p2p/card_p2pn_*.json")
SEED = bytes([0x51]) * 32
SEED_B = bytes([0x52]) * 32
RELAY = via.peer_id_from_ed25519_public(bytes([0x61]) * 32)
SPEC = "RAVEN_P2P_PEER_ROTATION_V1.md"
# 2026-10-22T00:00:00Z
NOW = 1_792_627_200
LAB_EPOCH_S = 600


def vec(name, desc, inputs, expected):
    return {"name": name, "description": desc, "protocol_version": "rvn1", "spec_reference": SPEC,
            "deterministic": True, "inputs": inputs, "expected": expected}


def identity_public(seed):
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def epoch_peer_id_vector():
    epochs = [0, 1, 2, 23, 2**40, 2**64 - 1]
    cases = [{"epoch": e, "epoch_seed_hex": pr.epoch_seed(SEED, e).hex(),
              "ed25519_public_hex": pr.epoch_public(SEED, e).hex(), "peer_id": pr.epoch_peer_id(SEED, e)}
             for e in epochs]
    return vec(
        "PeerId rotation: epoch keys",
        "epoch_seed(e) = SHA-256(\"raven/libp2p-epoch-key/v1\" || be64(e) || raven seed) is the libp2p "
        "Ed25519 secret seed of epoch e; the PeerId is base58(00 24 08 01 12 20 || public key). The legacy "
        "(non-rotating) key SHA-256(\"raven/libp2p-peer-key/v1\" || seed) is listed to show it differs "
        "from every epoch key. own_schedule(active = 23) is the previous epoch, the active one and 6 ahead",
        {"raven_seed_hex": SEED.hex(), "epochs": epochs, "schedule_active": 23},
        {"legacy_seed_hex": pr.legacy_seed(SEED).hex(), "legacy_peer_id": pr.legacy_peer_id(SEED),
         "epochs": cases,
         "own_schedule": [{"epoch": e, "ed25519_public_hex": k.hex()} for e, k in pr.own_schedule(SEED, 23)],
         "own_schedule_at_0": [e for e, _ in pr.own_schedule(SEED, 0)]})


def epoch_phase_vector():
    cases = []
    for seed in (SEED, SEED_B):
        for length in (pr.DEFAULT_EPOCH_S, LAB_EPOCH_S, 1):
            phase = pr.phase_s(seed, length)
            # Around the boundary after NOW: one second before it, at it, and NOW itself.
            boundary = pr.next_boundary_unix(seed, NOW, length)
            times = sorted({0, NOW, boundary - 1, boundary, boundary + length})
            cases.append({
                "raven_seed_hex": seed.hex(), "epoch_len_s": length, "phase_s": phase,
                "times": [{"unix_s": t, "epoch": pr.epoch_at(seed, t, length),
                           "next_boundary_unix": pr.next_boundary_unix(seed, t, length)} for t in times]})
    return vec(
        "PeerId rotation: epoch phase and boundaries",
        "phase = be64(SHA-256(\"raven/libp2p-epoch-phase/v1\" || raven seed)[0..8]) mod L; epoch(t) = "
        "(t + phase) div L; the next boundary after t is (epoch(t) + 1) * L - phase. L is 2419200 s "
        "(28 days, the default), 600 s (a lab length) and 1 s; each case lists t = 0, a fixed now, the "
        "second before the next boundary, the boundary itself and one epoch later",
        {"now_unix": NOW, "default_epoch_s": pr.DEFAULT_EPOCH_S},
        {"cases": cases})



def relay_cases():
    one = pr.format_relay_schedule(SEED, 23, 1)
    full = pr.format_relay_schedule(SEED, 23, 13)
    p23, p24, p25 = (pr.epoch_peer_id(SEED, e) for e in (23, 24, 25))
    accept = [
        (one, "one entry (raven relay schedule --epochs 1)"),
        (pr.format_relay_schedule(SEED, 23, 7), "the default: the active epoch and 6 ahead"),
        (full, "13 entries, the most a text holds"),
        (f"  {one}\n", "surrounding white space is trimmed"),
        (f"{pr.RELAY_SCHEDULE_PREFIX}  23:{p23}   25:{p25}", "runs of spaces between entries; epochs need "
         "not be consecutive"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 0:{pr.epoch_peer_id(SEED, 0)} {2**64 - 1}:"
         f"{pr.epoch_peer_id(SEED, 2**64 - 1)}", "epoch 0 and epoch 2^64 - 1"),
    ]
    over = full + f" 36:{pr.epoch_peer_id(SEED, 36)}"
    reject = [
        ("", pr.PREFIX, "empty"),
        (pr.RELAY_SCHEDULE_PREFIX, pr.EMPTY, "the prefix alone"),
        (f"raven-relay-schedule/2 23:{p23}", pr.VERSION, "another version"),
        (f"raven-card/3 23:{p23}", pr.PREFIX, "another kind of line"),
        (f"Raven-Relay-Schedule/1 23:{p23}", pr.PREFIX, "the prefix is case-sensitive"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 23{p23}", pr.ENTRY, "an entry without ':'"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 023:{p23}", pr.EPOCH, "a leading zero"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} +23:{p23}", pr.EPOCH, "a sign"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} :{p23}", pr.EPOCH, "no epoch"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 18446744073709551616:{p23}", pr.EPOCH, "2^64"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 0x17:{p23}", pr.EPOCH, "hexadecimal"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 23:{p23[:-1]}", pr.PEER_ID, "a PeerId one character short"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 23:{p23.lower()}", pr.PEER_ID, "a PeerId in lower case"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 23:QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N", pr.PEER_ID,
         "a PeerId that is no Ed25519 key"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 23:{p23}:{p24}", pr.PEER_ID, "two PeerIds in one entry"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 24:{p24} 23:{p23}", pr.ORDER, "epochs decreasing"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 23:{p23} 23:{p24}", pr.ORDER, "an epoch twice"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 23:{p23} 24:{p23}", pr.DUPLICATE, "a PeerId twice"),
        (over, pr.TOO_MANY, "14 entries"),
        (f"{pr.RELAY_SCHEDULE_PREFIX}\t23:{p23}", pr.NOT_ONE_LINE, "a tab"),
        (f"{one}\n{one}", pr.NOT_ONE_LINE, "two lines"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 23:{p23} é", pr.NOT_ONE_LINE, "a character outside ASCII"),
        (full + " " * (pr.RELAY_SCHEDULE_MAX_LEN - len(full) + 1) + "x", pr.NOT_ONE_LINE,
         f"longer than {pr.RELAY_SCHEDULE_MAX_LEN} characters"),
        (f"{pr.RELAY_SCHEDULE_PREFIX} 23:{p23} 24:{RELAY} junk", pr.ENTRY, "a trailing word"),
    ]
    return accept, reject


def relay_schedule_vector():
    accept, reject = relay_cases()
    acc = []
    for text, why in accept:
        acc.append({"input": text, "why": why,
                    "entries": [{"epoch": e, "peer_id": p} for e, p in pr.parse_relay_schedule(text)]})
    rej = []
    for text, code, why in reject:
        try:
            pr.parse_relay_schedule(text)
        except pr.RelayScheduleError as e:
            assert e.code == code, (text, e.code, code)
        else:
            raise AssertionError(f"accepted: {text!r}")
        rej.append({"input": text, "error": code, "why": why})
    return vec(
        "PeerId rotation: relay schedule text",
        "raven-relay-schedule/1 followed by 1 to 13 <epoch>:<PeerId> entries (canonical decimal epochs, "
        "strictly increasing; canonical Ed25519 PeerIds, each once); one line of at most "
        f"{pr.RELAY_SCHEDULE_MAX_LEN} plain characters after trimming. format_relay_schedule(seed 0x51, "
        "from, n) gives the first three accept cases. Reject cases name the rule that refused them "
        "(raven_protocol/peer_rotation.py error codes)",
        {"raven_seed_hex": SEED.hex(), "max_entries": pr.MAX_RELAY_SCHEDULE,
         "max_len": pr.RELAY_SCHEDULE_MAX_LEN,
         "format": [{"from": f, "n": n, "text": pr.format_relay_schedule(SEED, f, n)}
                    for f, n in ((23, 1), (23, 7), (23, 13), (23, 0), (23, 99))]},
        {"accept": acc, "reject": rej})


def card_vector():
    length = pr.DEFAULT_EPOCH_S
    e = pr.epoch_at(SEED, NOW, length)
    pub = identity_public(SEED)
    p2p, p2pn = pr.epoch_peer_id(SEED, e), pr.epoch_peer_id(SEED, e + 1)
    relay = f"/ip4/203.0.113.7/tcp/7423/p2p/{RELAY}"
    card = (f"raven-card/3 address={address.encode(pub)} pub_hex={pub.hex()} "
            f"fingerprint={fingerprint.device_fingerprint_v1(pub)} p2p={p2p} p2pn={p2pn} relay={relay}")
    return vec(
        "PeerId rotation: card p2pn=",
        "A raven-card/3 of a profile whose rotation is on: p2p= is the PeerId of the epoch at now, p2pn= "
        "the next epoch's. p2pn= needs p2p=; readers accept the fields in any order; the line stays within "
        "the card v3 bound of 1530 characters (RAVEN_ROUTE_HINTS_V1.md section 9)",
        {"raven_seed_hex": SEED.hex(), "now_unix": NOW, "epoch_len_s": length, "relay": relay},
        {"phase_s": pr.phase_s(SEED, length), "epoch": e, "p2p": p2p, "p2pn": p2pn,
         "legacy_peer_id": pr.legacy_peer_id(SEED), "card": card, "card_len": len(card)})


def build():
    return {
        "p2p/epoch_peer_id_001.json": epoch_peer_id_vector(),
        "p2p/epoch_phase_001.json": epoch_phase_vector(),
        "p2p/relay_schedule_text_001.json": relay_schedule_vector(),
        "p2p/card_p2pn_001.json": card_vector(),
    }


def render(obj):
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def owned_on_disk(base):
    names = set()
    for pattern in OWNED:
        names.update(p.relative_to(base).as_posix() for p in base.glob(pattern))
    return sorted(names)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO_ROOT / "shared-vectors/rvn1"))
    ap.add_argument("--check", action="store_true", help="exit 1 if any file on disk differs")
    args = ap.parse_args()
    base = pathlib.Path(args.out)
    planned = build()
    if args.check:
        drift = [name for name, obj in planned.items()
                 if not (base / name).is_file() or (base / name).read_text(encoding="utf-8") != render(obj)]
        extra = [name for name in owned_on_disk(base) if name not in planned] if base.is_dir() else []
        for name in drift:
            print("DRIFT", base / name)
        for name in extra:
            print("NOT GENERATED", base / name)
        if drift or extra:
            sys.exit(1)
        print(f"PeerId rotation vectors OK ({len(planned)} files)")
        return
    for name, obj in planned.items():
        (base / name).parent.mkdir(parents=True, exist_ok=True)
        (base / name).write_text(render(obj), encoding="utf-8")
    print("wrote", ", ".join(str(base / name) for name in planned))


if __name__ == "__main__":
    main()
