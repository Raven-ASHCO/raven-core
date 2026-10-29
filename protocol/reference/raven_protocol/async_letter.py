"""RAVEN Async Letter V1 (RAL1) reference: codec, key schedule, seal/open.

Mirrors ``raven_core::async_letter`` (protocol/RAVEN_ASYNC_LETTER_V1.md). The
Rust code generates the vectors under ``shared-vectors/rvn1/letter``; this
module re-derives them byte for byte. Production disabled: no Raven build
sends or accepts a letter while ASYNC_LETTER_PRODUCTION_ENABLED is false.
"""

from dataclasses import dataclass
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import ed25519_strict, envelope, indexed_session, pair_init

PRODUCTION_ENABLED = False

MAGIC = b"RAL1"
VERSION = 1
FLAGS = 0
KIND_LETTER = 1
KIND_REPLY = 2
HEADER_PREFIX_LEN = 168
HEADER_LEN = 184
TAG_LEN = 16
SIGNATURE_LEN = 64
PAD_BLOCK = 512
MIN_RAL1_INNER = PAD_BLOCK
MAX_RAL1_INNER = 65_024
MIN_RAL1_LEN = HEADER_LEN + MIN_RAL1_INNER + TAG_LEN + SIGNATURE_LEN
MAX_RAL1_LEN = HEADER_LEN + MAX_RAL1_INNER + TAG_LEN + SIGNATURE_LEN
assert (MIN_RAL1_LEN, MAX_RAL1_LEN) == (776, 65_288)

SIGNING_DOMAIN = b"rvn1/async-letter/v1\x00"
SALT_LABEL = b"rvn1/async-letter/v1/salt"
WRAP_LABEL = b"rvn1/async-letter/v1/wrap"
NONCE_LABEL = b"rvn1/async-letter/v1/nonce"
PAGE_TOKEN_DOMAIN = b"raven/custody-letter/page-token/v1"

INNER_VERSION = 1
PAIR_KIND_INIT_V1 = 1
PAIR_KIND_RESPONSE_V1 = 2
PAIR_KIND_INIT_V3_RESERVED = 3
MAX_LETTER_ENVELOPES = 16
MAX_REPLY_ACKS = 32
MIN_ITEM_LEN = envelope.PREFIX_LEN
MAX_ITEM_LEN = MAX_RAL1_INNER
MAX_LETTER_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000
MAX_LETTER_FUTURE_SKEW_MS = 5 * 60 * 1000

ENV_TYPE_MESSAGE = 1
ENV_TYPE_ACK = 2
INDEXED_SEALED_MIN_WIRE_LEN = 26 + 16

# Stable codes, verification steps 1-9 (RAVEN_ASYNC_LETTER_V1.md §6).
MALFORMED = "LETTER_MALFORMED"
WRONG_RECIPIENT = "LETTER_WRONG_RECIPIENT"
EXPIRED = "LETTER_EXPIRED"
TIME = "LETTER_TIME"
NOT_CONTACT = "LETTER_NOT_CONTACT"
BAD_SIGNATURE = "LETTER_BAD_SIGNATURE"
UNKNOWN_PREKEY = "LETTER_UNKNOWN_PREKEY"
UNWRAP = "LETTER_UNWRAP"
INNER = "LETTER_INNER"
BINDING = "LETTER_BINDING"


class LetterError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class Header:
    kind: int
    letter_id: bytes
    sender_device: bytes
    recipient_device: bytes
    created_at_ms: int
    expires_at_ms: int
    wrap_bundle_hash: bytes
    wrap_ephemeral: bytes
    wrap_nonce: bytes
    ct_len: int

    def prefix_bytes(self) -> bytes:
        return (
            MAGIC
            + bytes([VERSION, self.kind])
            + FLAGS.to_bytes(2, "big")
            + self.letter_id
            + self.sender_device
            + self.recipient_device
            + self.created_at_ms.to_bytes(8, "big")
            + self.expires_at_ms.to_bytes(8, "big")
            + self.wrap_bundle_hash
            + self.wrap_ephemeral
        )

    def to_bytes(self) -> bytes:
        return self.prefix_bytes() + self.wrap_nonce + self.ct_len.to_bytes(4, "big")


def x25519_public(secret: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(secret)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def x25519_shared(secret: bytes, public: bytes) -> bytes:
    """X25519 refusing an all-zero output (a small-order peer key)."""
    try:
        shared = X25519PrivateKey.from_private_bytes(secret).exchange(
            X25519PublicKey.from_public_bytes(public)
        )
    except ValueError as error:  # cryptography refuses an all-zero result
        raise LetterError(UNWRAP) from error
    if shared == bytes(32):
        raise LetterError(UNWRAP)
    return shared


def _check_fields(header: Header) -> None:
    inner_len = header.ct_len - TAG_LEN
    if (
        header.letter_id == bytes(16)
        or header.sender_device == bytes(32)
        or header.recipient_device == bytes(32)
        or header.sender_device == header.recipient_device
        or header.wrap_bundle_hash == bytes(32)
        or header.expires_at_ms <= header.created_at_ms
        or not pair_init.is_contributory_x25519(header.wrap_ephemeral)
        or not MIN_RAL1_INNER <= inner_len <= MAX_RAL1_INNER
        or inner_len % PAD_BLOCK
    ):
        raise LetterError(MALFORMED)


def decode_header(letter: bytes) -> Header:
    """Step 1 on the header and the exact total length."""
    if not MIN_RAL1_LEN <= len(letter) <= MAX_RAL1_LEN:
        raise LetterError(MALFORMED)
    if (
        letter[:4] != MAGIC
        or letter[4] != VERSION
        or letter[5] not in (KIND_LETTER, KIND_REPLY)
        or int.from_bytes(letter[6:8], "big") != FLAGS
    ):
        raise LetterError(MALFORMED)
    header = Header(
        kind=letter[5],
        letter_id=letter[8:24],
        sender_device=letter[24:56],
        recipient_device=letter[56:88],
        created_at_ms=int.from_bytes(letter[88:96], "big"),
        expires_at_ms=int.from_bytes(letter[96:104], "big"),
        wrap_bundle_hash=letter[104:136],
        wrap_ephemeral=letter[136:168],
        wrap_nonce=letter[168:180],
        ct_len=int.from_bytes(letter[180:184], "big"),
    )
    _check_fields(header)
    if len(letter) != HEADER_LEN + header.ct_len + SIGNATURE_LEN:
        raise LetterError(MALFORMED)
    return header


def letter_digest(letter: bytes) -> bytes:
    return hashlib.sha256(letter).digest()


def page_token(letter: bytes) -> bytes:
    return hashlib.sha256(PAGE_TOKEN_DOMAIN + letter).digest()


def signing_bytes(unsigned: bytes) -> bytes:
    return SIGNING_DOMAIN + unsigned


def wrap_salt(wrap_bundle_hash: bytes) -> bytes:
    return hashlib.sha256(SALT_LABEL + wrap_bundle_hash).digest()


def wrap_info(header_prefix: bytes) -> bytes:
    if len(header_prefix) != HEADER_PREFIX_LEN:
        raise ValueError("header prefix must be 168 bytes")
    return WRAP_LABEL + b"\x00" + header_prefix


def wrap_okm(dh: bytes, header_prefix: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=wrap_salt(header_prefix[104:136]),
        info=wrap_info(header_prefix),
    ).derive(dh)


def wrap_nonce(k_nonce: bytes, inner: bytes) -> bytes:
    return hmac.new(k_nonce, NONCE_LABEL + b"\x00" + inner, hashlib.sha256).digest()[:12]


def seal(
    sender_seed: bytes,
    ephemeral_secret: bytes,
    *,
    kind: int,
    letter_id: bytes,
    recipient_device: bytes,
    created_at_ms: int,
    expires_at_ms: int,
    wrap_bundle_hash: bytes,
    recipient_signed_prekey: bytes,
    inner: bytes,
) -> bytes:
    if expires_at_ms - created_at_ms > MAX_LETTER_LIFETIME_MS:
        raise ValueError("letter lifetime over 7 days")
    if len(inner) > MAX_RAL1_INNER or len(inner) < MIN_RAL1_INNER or len(inner) % PAD_BLOCK:
        raise ValueError("inner must be a padded RAL1 inner")
    signer = Ed25519PrivateKey.from_private_bytes(sender_seed)
    header = Header(
        kind=kind,
        letter_id=letter_id,
        sender_device=signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        recipient_device=recipient_device,
        created_at_ms=created_at_ms,
        expires_at_ms=expires_at_ms,
        wrap_bundle_hash=wrap_bundle_hash,
        wrap_ephemeral=x25519_public(ephemeral_secret),
        wrap_nonce=bytes(12),
        ct_len=len(inner) + TAG_LEN,
    )
    _check_fields(header)
    okm = wrap_okm(x25519_shared(ephemeral_secret, recipient_signed_prekey), header.prefix_bytes())
    header.wrap_nonce = wrap_nonce(okm[32:], inner)
    aad = header.to_bytes()
    unsigned = aad + ChaCha20Poly1305(okm[:32]).encrypt(header.wrap_nonce, inner, aad)
    return unsigned + signer.sign(signing_bytes(unsigned))


def _envelope_item(kind: int, item: bytes) -> envelope.Envelope:
    env = envelope.unpack(item)
    if env is None:
        raise LetterError(INNER)
    body = env.message_ciphertext
    sealed = (
        len(body) >= INDEXED_SEALED_MIN_WIRE_LEN
        and body[:8] == indexed_session.RVNA1_MAGIC
        and body[8] == indexed_session.RVNA1_PROTO
        and body[9] == indexed_session.RVNA1_SUITE
    )
    if kind == KIND_LETTER:
        shape = env.env_type == ENV_TYPE_MESSAGE
    else:
        shape = env.env_type == ENV_TYPE_ACK and len(body) == indexed_session.ACK_SEALED_WIRE_LEN
    if not sealed or not shape or env.flags != 0 or env.ratchet_header_ciphertext:
        raise LetterError(INNER)
    return env


def _pair_len(kind: int) -> int:
    return pair_init.INIT_WIRE_LEN if kind == KIND_LETTER else pair_init.RESPONSE_WIRE_LEN


def _item_range(kind: int) -> range:
    if kind == KIND_LETTER:
        return range(1, MAX_LETTER_ENVELOPES + 1)
    return range(0, MAX_REPLY_ACKS + 1)


def _decode_pair(kind: int, pair: bytes):
    if kind == KIND_LETTER:
        return pair_init.decode_init(pair)
    return pair_init.decode_response(pair)


def encode_inner(kind: int, pair: bytes, items: list[bytes]) -> bytes:
    """LETTER (kind 1) or REPLY (kind 2) inner with the smallest padding."""
    if len(pair) != _pair_len(kind) or len(items) not in _item_range(kind):
        raise LetterError(INNER)
    try:
        _decode_pair(kind, pair)
    except ValueError as error:
        raise LetterError(INNER) from error
    out = bytearray([INNER_VERSION, kind]) + len(pair).to_bytes(2, "big") + pair
    out.append(len(items))
    for item in items:
        _envelope_item(kind, item)
        out += len(item).to_bytes(4, "big") + item
    unpadded = len(out) + 2
    pad = (PAD_BLOCK - unpadded % PAD_BLOCK) % PAD_BLOCK
    if unpadded + pad > MAX_RAL1_INNER:
        raise LetterError("LETTER_TOO_LARGE")
    out += pad.to_bytes(2, "big") + bytes(pad)
    return bytes(out)


def decode_inner(kind: int, inner: bytes) -> tuple[bytes, list[bytes]]:
    """Step 8: strict inner decode; returns (pair bytes, packed items)."""
    if not MIN_RAL1_INNER <= len(inner) <= MAX_RAL1_INNER or len(inner) % PAD_BLOCK:
        raise LetterError(INNER)
    at = 0

    def take(n: int) -> bytes:
        nonlocal at
        if at + n > len(inner):
            raise LetterError(INNER)
        out = inner[at : at + n]
        at += n
        return out

    if take(1)[0] != INNER_VERSION or take(1)[0] != kind:
        raise LetterError(INNER)
    if int.from_bytes(take(2), "big") != _pair_len(kind):
        raise LetterError(INNER)
    pair = take(_pair_len(kind))
    try:
        _decode_pair(kind, pair)
    except ValueError as error:
        raise LetterError(INNER) from error
    count = take(1)[0]
    if count not in _item_range(kind):
        raise LetterError(INNER)
    items = []
    for _ in range(count):
        length = int.from_bytes(take(4), "big")
        if not MIN_ITEM_LEN <= length <= MAX_ITEM_LEN:
            raise LetterError(INNER)
        item = take(length)
        _envelope_item(kind, item)
        items.append(item)
    pad_len = int.from_bytes(take(2), "big")
    if pad_len >= PAD_BLOCK or any(take(pad_len)) or at != len(inner):
        raise LetterError(INNER)
    return pair, items


def check_bindings(header: Header, pair: bytes, items: list[bytes]):
    """Step 9, the stateless part."""
    if header.kind == KIND_LETTER:
        init = pair_init.decode_init(pair)
        if (
            init.initiator_device_ed_pub != header.sender_device
            or init.responder_device_ed_pub != header.recipient_device
            or init.responder_prekey_bundle_hash != header.wrap_bundle_hash
            or init.one_time_prekey_id != 0
            or init.created_at_ms > header.created_at_ms
            or header.expires_at_ms > init.expires_at_ms
            or header.wrap_ephemeral == init.initiator_ephemeral_x25519_pub
        ):
            raise LetterError(BINDING)
        decoded = init
    else:
        response = pair_init.decode_response(pair)
        if response.responder_device_ed_pub != header.sender_device:
            raise LetterError(BINDING)
        decoded = response
    envelopes = []
    for item in items:
        env = envelope.unpack(item)
        if not envelope.verify(env, header.sender_device) or (
            header.kind == KIND_LETTER and env.expires_at > header.expires_at_ms
        ):
            raise LetterError(BINDING)
        envelopes.append(env)
    return decoded, envelopes


def check_route_tags(root: bytes, kind: int, envelopes: list[envelope.Envelope]) -> None:
    direction = 0 if kind == KIND_LETTER else 1
    for env in envelopes:
        index = int.from_bytes(env.message_ciphertext[10:14], "big")
        tag = indexed_session.derive_route_tag(root, env.created_at, index, env.env_type, direction)
        if tag != env.routing_tag:
            raise LetterError(BINDING)


def open_letter(letter: bytes, local_device: bytes, now_ms: int, is_contact, wrap_dh):
    """Steps 1-9 in order. ``wrap_dh(header)`` returns the signed-prekey DH
    or raises LetterError(UNKNOWN_PREKEY); it runs after the signature."""
    header = decode_header(letter)
    if header.recipient_device != local_device:
        raise LetterError(WRONG_RECIPIENT)
    if now_ms >= header.expires_at_ms:
        raise LetterError(EXPIRED)
    if (
        header.created_at_ms > now_ms + MAX_LETTER_FUTURE_SKEW_MS
        or header.expires_at_ms - header.created_at_ms > MAX_LETTER_LIFETIME_MS
    ):
        raise LetterError(TIME)
    if not is_contact(header.sender_device):
        raise LetterError(NOT_CONTACT)
    split = len(letter) - SIGNATURE_LEN
    if not ed25519_strict.verify(header.sender_device, letter[split:], signing_bytes(letter[:split])):
        raise LetterError(BAD_SIGNATURE)
    okm = wrap_okm(wrap_dh(header), header.prefix_bytes())
    try:
        inner = ChaCha20Poly1305(okm[:32]).decrypt(
            header.wrap_nonce, letter[HEADER_LEN:split], header.to_bytes()
        )
    except Exception as error:  # cryptography.exceptions.InvalidTag
        raise LetterError(UNWRAP) from error
    pair, items = decode_inner(header.kind, inner)
    decoded, envelopes = check_bindings(header, pair, items)
    return header, inner, decoded, envelopes
