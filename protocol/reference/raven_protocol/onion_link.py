"""RAVEN Onion Carrier V1 (RAVEN_ONION_CARRIER_V1.md §5.1): the onion link's
own Noise static.

An independent reference for the Rust code
(``raven_core::lan_noise::derive_onion_noise_static``) and the vector
``shared-vectors/rvn1/onion/noise_static_001.json`` (which Rust writes and
:mod:`tests.test_onion_link` checks against this module).

The onion link answers with a static derived from the identity seed under
its own HKDF salt, never the device static that LAN and Internet direct
listeners answer with, so what anyone holding a card reads over Tor cannot
be matched against those listeners.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEVICE_STATIC_SALT = b"rvn1/lan-noise/v1"
ONION_STATIC_SALT = b"rvn1/onion-noise/v1"
STATIC_INFO = b"static-x25519"


def _static_public(seed: bytes, salt: bytes) -> bytes:
    okm = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=STATIC_INFO).derive(seed)
    key = X25519PrivateKey.from_private_bytes(okm).public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def device_static_public(seed: bytes) -> bytes:
    """The device static (LAN, Internet direct, p2p, nearby)."""
    return _static_public(seed, DEVICE_STATIC_SALT)


def onion_static_public(seed: bytes) -> bytes:
    """The onion link's static (§5.1)."""
    return _static_public(seed, ONION_STATIC_SALT)
