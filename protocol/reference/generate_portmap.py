#!/usr/bin/env python3
# protocol/reference/generate_portmap.py
"""Deterministic generator for the Raven Port Mapping Profile V1 vectors (Python standard library only).

Source of truth: raven_protocol.portmap  |  Spec: protocol/RAVEN_PORT_MAPPING_V1.md
Writes <out>/portmap/*.json and <out>/portmap/negative/*.json (default out: shared-vectors/rvn1).
The replies are what a router sends (gateway epoch 3600 s, external IPv4 11.0.2.9); raven-core's
portmap_fake reproduces them from the request vectors.

    python3 -I generate_portmap.py            # write the vectors
    python3 -I generate_portmap.py --check    # exit 1 if any file on disk differs
"""
import argparse, ipaddress, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from raven_protocol import portmap as pm  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SUBDIR = "portmap"
SEED = bytes([0x51]) * 32
OTHER_SEED = bytes([0x52]) * 32
CLIENT_V4 = "192.168.1.20"
CLIENT_V6 = "2001:db8::20"
ROUTER_V4 = "192.168.1.1"
ROUTER_V6 = "fe80::1"
PORT = 7423
EPOCH = 3600
EXTERNAL_V4 = "11.0.2.9"
GATEWAY = {"epoch_s": EPOCH, "external_ipv4": EXTERNAL_V4, "max_lifetime_s": pm.REQUESTED_LIFETIME_S}


def vec(name, desc, inputs, expected):
    return {"name": name, "description": desc, "protocol_version": "rvn1",
            "spec_reference": "RAVEN_PORT_MAPPING_V1.md", "deterministic": True,
            "inputs": inputs, "expected": expected}


def reply_vec(name, desc, reply, sent_pcp_op, sent_natpmp_op, answers=None):
    inputs = {"reply_hex": reply.hex(), "sent_pcp_op": sent_pcp_op, "sent_natpmp_op": sent_natpmp_op}
    if answers:
        inputs["answers"] = answers
        inputs["gateway"] = GATEWAY
    return vec(name, desc, inputs, pm.decode_reply(reply, sent_pcp_op, sent_natpmp_op))


def negative(name, desc, reply, sent_pcp_op, sent_natpmp_op):
    try:
        pm.decode_reply(reply, sent_pcp_op, sent_natpmp_op)
    except pm.ReplyError as e:
        code = e.code
    else:
        raise RuntimeError(f"{name}: the decoder accepted a negative vector")
    return vec(name, desc, {"reply_hex": reply.hex(), "sent_pcp_op": sent_pcp_op,
                            "sent_natpmp_op": sent_natpmp_op}, {"error": code})


def build():
    key = pm.nonce_key(SEED)
    nonce_v4 = pm.pcp_nonce(key, ROUTER_V4, CLIENT_V4, pm.TCP, PORT)
    nonce_v6 = pm.pcp_nonce(key, ROUTER_V6, CLIENT_V6, pm.UDP, PORT)
    any_v4 = pm.unspecified_external(CLIENT_V4)
    out = {}

    out["natpmp_extaddr_req_001.json"] = vec(
        "NAT-PMP external address request", "version 0, opcode 0 (the probe, sent with the PCP ANNOUNCE)",
        {"op": pm.NATPMP_OP_EXTERNAL_ADDR, "client_ip": CLIENT_V4},
        {"request_hex": pm.natpmp_request(pm.NATPMP_OP_EXTERNAL_ADDR).hex()})
    out["natpmp_extaddr_resp_001.json"] = reply_vec(
        "NAT-PMP external address response", "version 0, opcode 128, result, seconds since start of epoch, IPv4",
        pm.natpmp_external_reply(pm.NATPMP_SUCCESS, EPOCH, EXTERNAL_V4), None, pm.NATPMP_OP_EXTERNAL_ADDR,
        "natpmp_extaddr_req_001.json")
    map_req = {"op": pm.NATPMP_OP_MAP_TCP, "internal_port": PORT, "suggested_port": PORT,
               "lifetime": pm.REQUESTED_LIFETIME_S}
    out["natpmp_map_tcp_req_001.json"] = vec(
        "NAT-PMP TCP mapping request", "version 0, opcode 2, reserved, internal port, suggested external port, "
        "lifetime 7200 s", {**map_req, "client_ip": CLIENT_V4},
        {"request_hex": pm.natpmp_request(pm.NATPMP_OP_MAP_TCP, PORT, PORT, pm.REQUESTED_LIFETIME_S).hex()})
    out["natpmp_map_resp_001.json"] = reply_vec(
        "NAT-PMP TCP mapping response", "version 0, opcode 130, result, epoch, internal port, mapped external "
        "port, granted lifetime",
        pm.natpmp_map_reply(pm.NATPMP_OP_MAP_TCP, pm.NATPMP_SUCCESS, EPOCH, PORT, PORT, pm.REQUESTED_LIFETIME_S),
        None, pm.NATPMP_OP_MAP_TCP, "natpmp_map_tcp_req_001.json")

    out["pcp_announce_req_001.json"] = vec(
        "PCP ANNOUNCE request", "the probe: the 24-byte header, opcode 0, lifetime 0, client IPv4 as ::ffff:a.b.c.d",
        {"op": pm.PCP_OP_ANNOUNCE, "lifetime": 0, "client_ip": CLIENT_V4},
        {"request_hex": pm.pcp_request(pm.PCP_OP_ANNOUNCE, 0, CLIENT_V4).hex()})
    out["pcp_announce_resp_001.json"] = reply_vec(
        "PCP ANNOUNCE response", "version 2, R=1, opcode 0, result SUCCESS, lifetime 0, epoch, reserved",
        pm.pcp_reply(pm.PCP_OP_ANNOUNCE, pm.PCP_SUCCESS, 0, EPOCH), pm.PCP_OP_ANNOUNCE, None,
        "pcp_announce_req_001.json")

    def map_vec(name, desc, client, proto, nonce, suggested_port, lifetime):
        m = {"nonce": nonce, "proto": proto, "internal_port": PORT, "suggested_port": suggested_port,
             "suggested_ip": pm.unspecified_external(client)}
        router = ROUTER_V4 if client == CLIENT_V4 else ROUTER_V6
        return vec(name, desc,
                   {"seed_hex": SEED.hex(), "gateway_ip": router, "client_ip": client, "protocol": proto,
                    "internal_port": PORT,
                    "suggested_port": suggested_port, "suggested_ip": str(ipaddress.IPv6Address(m["suggested_ip"])),
                    "lifetime": lifetime, "nonce_hex": nonce.hex()},
                   {"request_hex": pm.pcp_request(pm.PCP_OP_MAP, lifetime, client, m).hex()})

    out["pcp_map_v4_req_001.json"] = map_vec(
        "PCP MAP request, IPv4 TCP", "header + MAP data; nonce from the seed's nonce key, the router and the internal endpoint; "
        "suggested external ::ffff:0.0.0.0", CLIENT_V4, pm.TCP, nonce_v4, PORT, pm.REQUESTED_LIFETIME_S)
    map_resp = pm.pcp_reply(pm.PCP_OP_MAP, pm.PCP_SUCCESS, pm.REQUESTED_LIFETIME_S, EPOCH,
                            pm.map_data(nonce_v4, pm.TCP, PORT, PORT, EXTERNAL_V4))
    out["pcp_map_v4_resp_001.json"] = reply_vec(
        "PCP MAP response, IPv4 TCP", "SUCCESS, granted lifetime, epoch, the request's nonce, protocol and internal "
        "port, the assigned external port and IPv4 (::ffff:a.b.c.d)", map_resp, pm.PCP_OP_MAP, None,
        "pcp_map_v4_req_001.json")
    optional = bytes([0x80, 0, 0, 1, 0x2A, 0, 0, 0])
    out["pcp_map_v4_resp_002.json"] = reply_vec(
        "PCP MAP response with an optional option", "the response of pcp_map_v4_resp_001 followed by option 128 "
        "(optional to process, length 1, padded): skipped, the reply decodes the same", map_resp + optional,
        pm.PCP_OP_MAP, None)
    out["pcp_map_v4_delete_001.json"] = map_vec(
        "PCP MAP delete, IPv4 TCP", "lifetime 0 with the mapping's nonce, protocol and internal port; suggested "
        "external port 0", CLIENT_V4, pm.TCP, nonce_v4, 0, 0)
    out["pcp_map_v6_req_001.json"] = map_vec(
        "PCP MAP request, IPv6 UDP (pinhole)", "client IPv6 as is, suggested external :: and the internal port",
        CLIENT_V6, pm.UDP, nonce_v6, PORT, pm.PINHOLE_LIFETIME_S)

    out["pcp_reply_natpmp_only_001.json"] = reply_vec(
        "NAT-PMP-only router answers a PCP MAP request", "version 0, opcode 128 + 1 (what miniupnpd sends), result 1 "
        "(unsupported version), epoch: the router speaks NAT-PMP only",
        pm.natpmp_unsupported_version(pm.RESPONSE_BIT | pm.PCP_OP_MAP, EPOCH), pm.PCP_OP_MAP, None)
    out["pcp_reply_natpmp_only_002.json"] = reply_vec(
        "NAT-PMP-only router answers the PCP ANNOUNCE probe", "version 0, opcode 0 (the RFC 6886 section 3.5 "
        "figure), result 1, epoch; sent alongside the NAT-PMP address request",
        pm.natpmp_unsupported_version(0, EPOCH), pm.PCP_OP_ANNOUNCE, pm.NATPMP_OP_EXTERNAL_ADDR)

    rows = [
        ("first answer", None, (3600, 0)),
        ("steady clocks", (3600, 0), (3660, 60)),
        ("server one second behind (allowed)", (3600, 0), (3599, 0)),
        ("server two seconds behind", (3600, 0), (3598, 0)),
        ("router restarted", (3600, 0), (5, 60)),
        ("server fast, at the 1/16 bound (valid)", (100, 0), (208, 100)),
        ("server fast beyond the 1/16 bound", (100, 0), (209, 100)),
        ("client fast, at the 1/16 bound (valid)", (100, 0), (200, 108)),
        ("client fast beyond the 1/16 bound", (100, 0), (200, 109)),
        ("a day later", (3600, 0), (90000, 86400)),
    ]
    out["pcp_epoch_validity_001.json"] = vec(
        "Server epoch validity (RFC 6887 section 8.5, also NAT-PMP)",
        "lost when curr + 1 < prev, or c + 2 < s - s/16, or s + 2 < c - c/16 (c: client seconds elapsed, "
        "s: curr - prev or 0; integer division); the first answer is always valid",
        {"cases": [{"case": label, "prev": None if p is None else {"server": p[0], "client_s": p[1]},
                    "curr": {"server": c[0], "client_s": c[1]}} for label, p, c in rows]},
        {"lost": [pm.epoch_lost(p, c) for _, p, c in rows]})

    endpoints = [(ROUTER_V4, CLIENT_V4, pm.TCP, PORT), (ROUTER_V4, CLIENT_V4, pm.UDP, PORT),
                 (ROUTER_V4, CLIENT_V4, pm.TCP, PORT + 1), (ROUTER_V4, "192.168.1.21", pm.TCP, PORT),
                 ("10.0.0.1", CLIENT_V4, pm.TCP, PORT), (ROUTER_V6, CLIENT_V6, pm.UDP, PORT),
                 ("fe80::2", CLIENT_V6, pm.UDP, PORT)]
    other = pm.nonce_key(OTHER_SEED)
    out["pcp_nonce_001.json"] = vec(
        "PCP MAP nonce", "key = SHA-256(domain || seed); nonce = SHA-256(key || gateway IP (16 bytes, IPv4-mapped) "
        "|| internal IP (16 bytes) || protocol || be16 port)[0..12]; another router or another profile's seed "
        "gives other nonces",
        {"seed_hex": SEED.hex(), "other_seed_hex": OTHER_SEED.hex(), "domain_ascii": pm.NONCE_KEY_DOMAIN.decode()},
        {"key_hex": key.hex(), "other_key_hex": other.hex(),
         "cases": [{"gateway_ip": gw, "internal_ip": ip, "protocol": proto, "port": port,
                    "nonce_hex": pm.pcp_nonce(key, gw, ip, proto, port).hex(),
                    "other_profile_nonce_hex": pm.pcp_nonce(other, gw, ip, proto, port).hex()}
                   for gw, ip, proto, port in endpoints]})

    neg = {}
    neg["pcp_wrong_opcode_001.json"] = negative(
        "PCP reply with another opcode", "an ANNOUNCE response (opcode 0) to a MAP request",
        pm.pcp_reply(pm.PCP_OP_ANNOUNCE, pm.PCP_SUCCESS, 0, EPOCH, pm.map_data(nonce_v4, pm.TCP, PORT, PORT,
                                                                                 EXTERNAL_V4)),
        pm.PCP_OP_MAP, None)
    neg["pcp_r_bit_clear_001.json"] = negative(
        "PCP message with the R bit clear", "a request echoed back, not a response",
        bytes([map_resp[0], map_resp[1] & 0x7F]) + map_resp[2:], pm.PCP_OP_MAP, None)
    neg["pcp_len_not_multiple_of_4_001.json"] = negative(
        "PCP reply whose length is not a multiple of 4", "pcp_map_v4_resp_001 plus one byte (61 bytes)",
        map_resp + b"\x00", pm.PCP_OP_MAP, None)
    neg["pcp_unknown_mandatory_option_001.json"] = negative(
        "PCP reply with an unknown mandatory option", "pcp_map_v4_resp_001 followed by option 0x70 (mandatory to "
        "process, length 4): invalid", map_resp + bytes([0x70, 0, 0, 4, 1, 2, 3, 4]), pm.PCP_OP_MAP, None)
    neg["pcp_bad_version_001.json"] = negative(
        "Reply of an unknown version", "version 1 (a pre-RFC PCP server) to a version 2 MAP request",
        bytes([1]) + map_resp[1:], pm.PCP_OP_MAP, None)
    neg["pcp_map_success_without_data_001.json"] = negative(
        "PCP MAP SUCCESS without MAP data", "a 24-byte header-only SUCCESS reply to MAP (only an error may omit "
        "the MAP data)", pm.pcp_reply(pm.PCP_OP_MAP, pm.PCP_SUCCESS, pm.REQUESTED_LIFETIME_S, EPOCH),
        pm.PCP_OP_MAP, None)
    neg["natpmp_short_001.json"] = negative(
        "NAT-PMP mapping response cut short", "15 of the 16 bytes of natpmp_map_resp_001",
        pm.natpmp_map_reply(pm.NATPMP_OP_MAP_TCP, pm.NATPMP_SUCCESS, EPOCH, PORT, PORT,
                            pm.REQUESTED_LIFETIME_S)[:15], None, pm.NATPMP_OP_MAP_TCP)
    return out, neg


def render(obj):
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO_ROOT / "shared-vectors/rvn1"))
    ap.add_argument("--check", action="store_true", help="exit 1 if any file on disk differs")
    args = ap.parse_args()
    base = pathlib.Path(args.out) / SUBDIR
    files, neg = build()
    planned = {**files, **{f"negative/{name}": obj for name, obj in neg.items()}}
    if args.check:
        drift = [name for name, obj in planned.items()
                 if not (base / name).is_file() or (base / name).read_text(encoding="utf-8") != render(obj)]
        extra = sorted(p.relative_to(base).as_posix() for p in base.rglob("*.json")
                       if p.relative_to(base).as_posix() not in planned) if base.is_dir() else []
        for name in drift:
            print("DRIFT", base / name)
        for name in extra:
            print("NOT GENERATED", base / name)
        if drift or extra:
            sys.exit(1)
        print(f"port mapping vectors OK ({len(planned)} files)")
        return
    (base / "negative").mkdir(parents=True, exist_ok=True)
    for name, obj in planned.items():
        (base / name).write_text(render(obj), encoding="utf-8")
    print("wrote", base)


if __name__ == "__main__":
    main()
