"""RAVEN Onion Carrier V1 §5.1: the Python reference checks the onion link's
Noise static vector (written by Rust under RAVEN_REGEN_SECURITY_VECTORS=1)."""

import json
from pathlib import Path

from raven_protocol import onion_link

REPO = Path(__file__).resolve().parents[3]
RVN1 = REPO / "shared-vectors/rvn1"


def load(path):
    return json.loads((RVN1 / path).read_text(encoding="utf-8"))


def test_onion_static_vector():
    v = load("onion/noise_static_001.json")
    seed = bytes.fromhex(v["inputs"]["device_seed_hex"])
    assert v["inputs"]["hkdf_salt"].encode() == onion_link.ONION_STATIC_SALT
    assert v["inputs"]["hkdf_info"].encode() == onion_link.STATIC_INFO
    assert onion_link.onion_static_public(seed).hex() == v["expected"]["onion_static_pub_hex"]
    assert onion_link.device_static_public(seed).hex() == v["expected"]["device_static_pub_hex"]


def test_onion_static_is_never_the_device_static():
    lan = load("lan/noise_static_001.json")
    seed = bytes.fromhex(lan["inputs"]["device_seed_hex"])
    device = onion_link.device_static_public(seed)
    assert device.hex() == lan["expected"]["noise_static_pub_hex"]
    assert onion_link.onion_static_public(seed) != device
