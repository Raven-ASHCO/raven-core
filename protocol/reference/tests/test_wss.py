# tests/test_wss.py
"""Raven WSS Transport V1 (RAVEN_WSS_TRANSPORT_V1.md, draft): the via= grammar, the proxy rules, the
WebSocket subset, the CONNECT client, the listener's first-byte check and their vectors."""
import ast, base64, hashlib, json, pathlib, subprocess, sys, tempfile

import pytest

from raven_protocol import connect, net_proxy, via
from raven_protocol import websocket as ws

REF = pathlib.Path(__file__).resolve().parents[1]  # protocol/reference
REPO = REF.parents[1]
VEC = REPO / "shared-vectors/rvn1"
GEN = REF / "generate_wss.py"
R = via.peer_id_from_ed25519_public(bytes([0x52]) * 32)
V4 = "/ip4/203.0.113.7"


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def test_via_vectors_replay():
    v = load("p2p/via_001.json")
    i = v["inputs"]
    assert via.peer_id_from_ed25519_public(bytes.fromhex(i["relay_ed25519_public_hex"])) == i["relay_peer_id"]
    assert via.peer_id_from_ed25519_public(bytes.fromhex(i["contact_ed25519_public_hex"])) == i["contact_peer_id"]
    accept, reject = v["expected"]["accept"], v["expected"]["reject"]
    assert len(accept) >= 10 and len(reject) >= 20
    for case in accept:
        canonical, peer = via.parse_via(case["input"])
        assert (canonical, peer) == (case["canonical"], case["peer_id"]), case["input"]
        assert via.parse_via(canonical) == (canonical, peer)
        assert via.is_wss(canonical) == case["is_wss"]
        assert via.tcp_port(canonical) == case["tcp_port"]
        assert via.raw_sibling(canonical) == case["raw_sibling"]
        assert via.wss_sibling(canonical) == case["wss_sibling"]
        for key, wss_ok, prefer in (("gate_closed", False, False), ("raw_first", True, False),
                                    ("wss_first", True, True)):
            assert via.relay_dial_forms(canonical, wss_ok, prefer) == case["dial_forms"][key], (case["input"], key)
    for case in reject:
        with pytest.raises(via.ViaError) as e:
            via.parse_via(case["input"])
        assert e.value.code == case["error"], case["input"]
    codes = {case["error"] for case in reject}
    assert {via.WSS_SUFFIX, via.QUIC_SUFFIX, via.CIRCUIT, via.TOO_LONG, via.SYNTAX} <= codes


def test_wss_grammar_rules():
    # /wss is stored as /tls/ws; SNI only after an IP host, lower-cased.
    assert via.parse_via(f"{V4}/tcp/443/wss/p2p/{R}")[0] == f"{V4}/tcp/443/tls/ws/p2p/{R}"
    assert via.parse_via(f"{V4}/tcp/443/tls/sni/A.Example/ws/p2p/{R}")[0] == f"{V4}/tcp/443/tls/sni/a.example/ws/p2p/{R}"
    for text, code in ((f"/dns4/a.example/tcp/443/tls/sni/a.example/ws/p2p/{R}", via.WSS_SUFFIX),
                       (f"{V4}/tcp/443/ws/p2p/{R}", via.WSS_SUFFIX),
                       (f"{V4}/udp/443/quic-v1/tls/ws/p2p/{R}", via.QUIC_SUFFIX),
                       (f"{V4}/tcp/443/tls/ws/p2p/{R}/p2p-circuit/p2p/{R}", via.CIRCUIT),
                       (f"{V4}/tcp/443/tls ws/p2p/{R}", via.NOT_MULTIADDR),
                       (f"/ip6/fe80::1%en0/tcp/443/tls/ws/p2p/{R}", via.HOST),
                       (f"{V4}/tcp/+443/tls/ws/p2p/{R}", via.PORT),
                       (f"{V4}/udp/443/p2p/{R}", via.TRANSPORT)):
        with pytest.raises(via.ViaError) as e:
            via.parse_via(text)
        assert e.value.code == code, text
    # Siblings by convention: raw TCP 443 and WSS on any port; QUIC and other raw ports none.
    raw = f"{V4}/tcp/443/p2p/{R}"
    wss = f"{V4}/tcp/443/tls/ws/p2p/{R}"
    assert via.relay_dial_forms(raw, True, False) == [raw, wss]
    assert via.relay_dial_forms(wss, True, True) == [wss, raw]
    assert via.relay_dial_forms(wss, False, True) == [raw]
    quic = f"{V4}/udp/443/quic-v1/p2p/{R}"
    assert via.relay_dial_forms(quic, True, True) == [quic]
    # A host named like a suffix part stays the host.
    assert via.raw_sibling(f"/dns/tls/tcp/443/tls/ws/p2p/{R}") == f"/dns/tls/tcp/443/p2p/{R}"


def test_base58_peer_ids_round_trip_and_are_canonical():
    for seed in (0x00, 0x01, 0x52, 0xFF):
        p = via.peer_id_from_ed25519_public(bytes([seed]) * 32)
        assert p.startswith("12D3KooW") and len(p) == 52
        assert via.normalize_peer_id(f" {p} ") == p
        assert via.b58decode(p) == via.ED25519_PEER_ID_PREFIX + bytes([seed]) * 32
    assert via.b58encode(b"\0\0\1") == "112" and via.b58decode("112") == b"\0\0\1"
    for bad in ("", "12D3KooW", R[:51], R + "x", R.replace("W", "0", 1), "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"):
        with pytest.raises(via.ViaError):
            via.normalize_peer_id(bad)


def test_generator_check_and_byte_identical_runs():
    done = subprocess.run([sys.executable, "-I", str(GEN), "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    with tempfile.TemporaryDirectory() as t1:
        subprocess.run([sys.executable, "-I", str(GEN), "--out", t1], check=True, capture_output=True)
        out = pathlib.Path(t1)
        names = sorted(p.relative_to(out).as_posix() for p in out.rglob("*.json"))
        assert names == ["p2p/via_001.json", "wss/rws1_connect_reply_001.json", "wss/rws1_connect_request_001.json",
                         "wss/rws1_demux_001.json", "wss/rws1_no_proxy_001.json", "wss/rws1_proxy_url_001.json",
                         "wss/rws1_ws_frames_001.json", "wss/rws1_ws_handshake_001.json"]
        for n in names:
            assert (out / n).read_bytes() == (VEC / n).read_bytes(), n
        # Another generator's file under p2p/ is not this one's business; a stray via_ file is.
        (out / "p2p/epoch_peer_id_001.json").write_text("{}\n", encoding="utf-8")
        ok = subprocess.run([sys.executable, "-I", str(GEN), "--out", t1, "--check"], capture_output=True)
        assert ok.returncode == 0
        (out / "p2p/via_002.json").write_text("{}\n", encoding="utf-8")
        bad = subprocess.run([sys.executable, "-I", str(GEN), "--out", t1, "--check"], capture_output=True)
        assert bad.returncode == 1


def test_proxy_url_vectors_replay():
    v = load("wss/rws1_proxy_url_001.json")
    assert v["inputs"]["default_port"] == net_proxy.DEFAULT_PORT == 80
    assert v["inputs"]["max_text_bytes"] == net_proxy.MAX_TEXT
    cases = v["expected"]["settings"]
    assert len(cases) >= 40
    seen = set()
    for case in cases:
        text = case["input"]
        assert net_proxy.has_credentials(text) == case["credentials"], text
        try:
            setting = net_proxy.parse_setting(text)
        except net_proxy.ProxyError as e:
            assert (e.code, e.kind) == (case["error"], case["kind"]), text
            seen.add(e.code)
            continue
        assert "error" not in case, text
        assert setting[0] == case["setting"] and net_proxy.setting_display(setting) == case["display"], text
        if setting[0] == "url":
            u = setting[1]
            assert (u.host, u.port, u.basic) == (case["host"], case["port"], case["basic"]), text
            assert "<redacted>" in u.display() if u.basic else "@" not in u.display()
    assert {"https", "socks", "pac", "syntax", "too_long", "scheme", "userinfo", "host", "port", "path"} <= seen
    for case in v["expected"]["windows"]:
        assert net_proxy.parse_windows_proxy(case["input"]) == case["entry"], case["input"]


def test_no_proxy_vectors_replay():
    v = load("wss/rws1_no_proxy_001.json")
    lists = v["expected"]["lists"]
    assert len(lists) >= 20
    checks = 0
    for case in lists:
        bypass = net_proxy.Bypass.parse(case["list"])
        for check in case["checks"]:
            assert bypass.bypasses(check["host"], check["port"]) == check["bypass"], (case["list"], check)
            checks += 1
    assert checks >= 80


def test_proxy_rules():
    # Basic is base64 of the percent-decoded user:pass; the display never shows it.
    u = net_proxy.parse_proxy_url("http://user:pass@proxy.example:3128")
    assert u.basic == "dXNlcjpwYXNz" and u.display() == "http://<redacted>@proxy.example:3128"
    # Each unsupported kind and each invalid code.
    for text, code, kind in (("https://p.example", "https", "https"), ("socks5h://p.example", "socks", "socks"),
                             ("http://w.example/x.pac", "pac", "pac"), ("http://p.example:0", "port", "invalid")):
        with pytest.raises(net_proxy.ProxyError) as e:
            net_proxy.parse_proxy_url(text)
        assert (e.value.code, e.value.kind) == (code, kind)
    # The leading dot is optional and matching stays on label boundaries.
    for entry in ("example.com", ".example.com", "EXAMPLE.COM."):
        b = net_proxy.Bypass.parse(entry)
        assert b.bypasses("example.com", 443) and b.bypasses("a.example.com", 443)
        assert not b.bypasses("notexample.com", 443)
    # Separate macOS ExceptionsList entries read as one list.
    entries = ["*.local", "169.254/16", "10.0.0.0/8"]
    joined = net_proxy.Bypass.parse(",".join(entries))
    single = net_proxy.Bypass(entries)
    assert (single.all, single.simple_names, single.rules) == (joined.all, joined.simple_names, joined.rules)
    # Windows: the https= entry, else the bare one.
    assert net_proxy.parse_windows_proxy("http=a:1;https=b:2") == "b:2"
    assert net_proxy.parse_windows_proxy("socks=s:1") is None


def ws_payload(case):
    """A vector frame's payload: its bytes, or the i mod 251 pattern of its length."""
    if "payload_hex" in case:
        return bytes.fromhex(case["payload_hex"])
    return bytes(i % 251 for i in range(case["payload_len"]))


def test_ws_handshake_vectors_replay():
    v = load("wss/rws1_ws_handshake_001.json")
    i, e = v["inputs"], v["expected"]
    # RFC 6455 section 1.3, and the digest under the base64.
    assert ws.accept_token(i["key"]) == e["accept"] == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    assert hashlib.sha1(i["key"].encode() + i["guid"].encode()).hexdigest() == e["sha1_hex"]
    assert (i["max_header_block"], i["max_headers"]) == (ws.MAX_HEADER_BLOCK, ws.MAX_HEADERS) == (8192, 32)
    assert e["not_found"].encode() == ws.NOT_FOUND
    for case in e["requests"]:
        assert ws.client_request(case["host"], case["key"]).decode() == case["request"]
        assert ws.check_request(case["request"].encode()) == case["key"]
    accepted = refused = 0
    for case in e["server"]:
        raw = case["request"].encode()
        if case["accepted"]:
            assert ws.check_request(raw) == case["key"], case["why"]
            assert ws.server_response(case["key"]).decode() == case["reply"]
            accepted += 1
        else:
            with pytest.raises(ws.Refused):
                ws.check_request(raw)
            assert case["reply"] == e["not_found"]
            refused += 1
    assert accepted >= 4 and refused >= 20
    for case in e["client"]:
        raw = case["response"].encode()
        if case["accepted"]:
            assert ws.check_response(raw, i["key"]) is None, case["why"]
        else:
            with pytest.raises(ws.Refused):
                ws.check_response(raw, i["key"])
    # The size limits are exact: 8192 bytes and 32 headers pass, one more does not.
    sizes = {len(c["request"]): c["accepted"] for c in e["server"] if len(c["request"]) > 8000}
    assert sizes == {8192: True, 8193: False}


def test_ws_frames_vectors_replay():
    v = load("wss/rws1_ws_frames_001.json")
    i, e = v["inputs"], v["expected"]
    mask = bytes.fromhex(i["mask_hex"])
    assert (i["max_message"], i["max_control"]) == (ws.MAX_MESSAGE, ws.MAX_CONTROL)
    lengths = []
    for case in e["data"]:
        payload = ws_payload(case)
        assert len(payload) == case["payload_len"]
        lengths.append(len(payload))
        for side, key in (("client", mask), ("server", None)):
            f = ws.encode(ws.BINARY, payload, key)
            assert f.hex().startswith(case[side + "_head_hex"]) and len(f) == case[side + "_frame_len"]
            assert hashlib.sha256(f).hexdigest() == case[side + "_frame_sha256"]
            if side + "_frame_hex" in case:
                assert f.hex() == case[side + "_frame_hex"]
            fin, op, m, n, hdr = ws.parse_head(f, key is not None)
            assert (fin, op, m, n, hdr * 2) == (True, ws.BINARY, key, len(payload), len(case[side + "_head_hex"]))
    assert lengths == [0, 5, 125, 126, 65535, 65536]
    assert e["data"][1]["client_frame_hex"] == "828537fa213d7f9f4d5158"
    for case in e["control"]:
        payload = bytes.fromhex(case["payload_hex"])
        assert ws.encode(case["op"], payload, mask).hex() == case["client_frame_hex"]
        assert ws.encode(case["op"], payload).hex() == case["server_frame_hex"]
        if case["op"] == ws.CLOSE:
            assert ws.close_code(payload) == case["close_code"]
    assert {c["close_code"] for c in e["control"] if c["op"] == ws.CLOSE} == {1000, 1002, 1003, 1009, None}
    for case in e["heads"]:
        head = bytes.fromhex(case["head_hex"])
        m = bytes.fromhex(case["mask_hex"]) if case["mask_hex"] else None
        assert ws.parse_head(head, case["expect_masked"]) == (case["fin"], case["op"], m, case["len"], case["hdr_len"])
        assert ws.encode_head(case["fin"], case["op"], case["len"], m) == head
        for cut in range(len(head)):  # every shorter prefix asks for more bytes
            assert ws.parse_head(head[:cut], case["expect_masked"]) is None, (case["why"], cut)
    for case in e["incomplete"]:
        assert ws.parse_head(bytes.fromhex(case["head_hex"]), case["expect_masked"]) is None
    for case in e["reject"]:
        with pytest.raises(ws.WsClose) as err:
            ws.parse_head(bytes.fromhex(case["head_hex"]), case["expect_masked"])
        assert err.value.code == case["close"], case["why"]
    assert {c["close"] for c in e["reject"]} == {ws.PROTOCOL, ws.TOO_BIG}
    outcomes = set()
    for case in e["sequences"]:
        key = mask if case["expect_masked"] else None
        data = b"".join(ws.encode(f["op"], ws_payload(f), key, f["fin"]) for f in case["frames"])
        messages, outcome, code = ws.read_frames(data, case["expect_masked"])
        assert [ws_message_of(m) for m in messages] == case["messages"], case["why"]
        assert (outcome, code) == (case["outcome"], case["code"]), case["why"]
        outcomes.add((outcome, code))
    assert {("end", None), ("close", 1000), ("close", None), ("fail", 1002), ("fail", 1003),
            ("fail", 1009)} <= outcomes


def ws_message_of(m):
    out = {"len": len(m), "sha256": hashlib.sha256(m).hexdigest()}
    if len(m) <= 64:
        out["hex"] = m.hex()
    return out


def test_ws_subset_rules():
    mask = bytes.fromhex("37fa213d")
    # Masking at an offset continues the key where the previous piece stopped.
    data = bytes(range(11))
    whole = ws.apply_mask(data, mask)
    assert ws.apply_mask(data[:3], mask) + ws.apply_mask(data[3:], mask, 3) == whole
    assert ws.apply_mask(whole, mask) == data
    # Lengths take their minimal form, and only that form is read.
    for n, form in ((125, 2), (126, 4), (65535, 4), (65536, 10), (ws.MAX_MESSAGE, 10)):
        head = ws.encode_head(True, ws.BINARY, n)
        assert len(head) == form and ws.parse_head(head, False) == (True, ws.BINARY, None, n, form)
    with pytest.raises(ws.WsClose) as e:
        ws.parse_head(ws.encode_head(True, ws.BINARY, ws.MAX_MESSAGE + 1), False)
    assert e.value.code == ws.TOO_BIG
    # Reassembly: binary then continuations; text 1003; the limit counts the whole message.
    r = ws.Reassembly()
    assert r.push(False, ws.BINARY, b"a" * 200_000) is None and r.open
    with pytest.raises(ws.WsClose) as e:
        r.push(True, ws.CONTINUATION, b"b" * 62_145)
    assert e.value.code == ws.TOO_BIG
    r = ws.Reassembly()
    assert r.push(False, ws.BINARY, b"a" * 200_000) is None
    assert r.push(True, ws.CONTINUATION, b"b" * 62_144) == b"a" * 200_000 + b"b" * 62_144 and not r.open
    for first, code in ((ws.TEXT, ws.UNSUPPORTED_DATA), (ws.CONTINUATION, ws.PROTOCOL), (ws.PING, ws.PROTOCOL)):
        with pytest.raises(ws.WsClose) as e:
            ws.Reassembly().push(True, first, b"")
        assert e.value.code == code
    # Keys: padded base64 of 16 bytes, canonical.
    assert ws.valid_key("dGhlIHNhbXBsZSBub25jZQ==") and ws.valid_key("AAAAAAAAAAAAAAAAAAAAAA==")
    for bad in ("", "dGhlIHNhbXBsZSBub25jZQ", "dGhlIHNhbXBsZSBub25jZR==", "dGhlIHNhbXBsZSBub25jZQ==\n",
                "AQIDBAUGBwgJCgsMDQ4P", "AQIDBAUGBwgJCgsMDQ4PEBE=", "dGhlIHNhbXBsZSBub25jZQ=é"):
        assert not ws.valid_key(bad), bad
    # The request and the 101 carry no Origin, User-Agent, Server, subprotocol or extension.
    head = (ws.client_request("relay.example.org", "dGhlIHNhbXBsZSBub25jZQ==")
            + ws.server_response("dGhlIHNhbXBsZSBub25jZQ==")).lower()
    for name in (b"origin", b"user-agent", b"server", b"sec-websocket-protocol", b"sec-websocket-extensions"):
        assert name + b":" not in head


def reply_of(case):
    """A reply case's bytes: reply (ASCII text) or reply_hex."""
    return bytes.fromhex(case["reply_hex"]) if "reply_hex" in case else case["reply"].encode("ascii")


def test_connect_request_vectors_replay():
    v = load("wss/rws1_connect_request_001.json")
    assert base64.b64encode(v["inputs"]["basic_user_pass"].encode()).decode() == v["inputs"]["basic"]
    cases = v["expected"]["requests"]
    assert len(cases) == 6 and sum(c["basic"] is None for c in cases) == 3
    for case in cases:
        assert connect.connect_request(case["authority"], case["basic"]).decode() == case["request"]
    # Nothing but the request line, Host and the credential: no User-Agent, no Proxy-Connection.
    lines = connect.connect_request("relay.example.org:443", "dXNlcjpwYXNz").split(b"\r\n")
    assert [line.split(b" ")[0] for line in lines] == [b"CONNECT", b"Host:", b"Proxy-Authorization:", b"", b""]


def test_connect_reply_vectors_replay():
    v = load("wss/rws1_connect_reply_001.json")
    assert (v["inputs"]["max_header_block"], v["inputs"]["max_headers"]) == (8192, 32)
    seen = {}
    for case in v["expected"]["replies"]:
        raw, out = reply_of(case), case["outcome"]
        got = connect.parse_reply(raw)
        if out == "incomplete":
            assert got is None, case["why"]
        elif out == "tunnel":
            assert got == (connect.TUNNEL, bytes.fromhex(case["leftover_hex"])), case["why"]
        elif out == "auth":
            assert got == (connect.AUTH, case["schemes"]), case["why"]
        elif out == "refused":
            assert got == (connect.REFUSED, case["code"]), case["why"]
        else:
            assert got == (connect.MALFORMED,), case["why"]
        seen[out] = seen.get(out, 0) + 1
        # Once decided, more bytes never change the decision; before that, nothing is decided.
        for cut in range(0, len(raw), 1 if len(raw) < 1024 else 61):
            part = connect.parse_reply(raw[:cut])
            assert part is None or part[0] == (got or (None,))[0], (case["why"], cut)
    assert set(seen) == {"tunnel", "auth", "refused", "malformed", "incomplete"} and min(seen.values()) >= 5
    by_why = {c["why"]: c for c in v["expected"]["replies"]}
    assert by_why["HTTP/1.0 200 with leftover bytes"]["leftover_hex"] == b"leftover".hex()
    assert by_why["407 offering NTLM, Negotiate and Basic, one header each"]["schemes"] == ["NTLM", "Negotiate", "Basic"]
    assert by_why["403"]["code"] == 403
    for why in ("a head of 8193 bytes", "8192 bytes and no blank line yet", "33 headers"):
        assert by_why[why]["outcome"] == "malformed", why


def test_demux_vectors_replay():
    v = load("wss/rws1_demux_001.json")
    outcomes = [connect.demux(bytes.fromhex(c["first_hex"])) for c in v["expected"]["cases"]]
    assert outcomes == [c["outcome"] for c in v["expected"]["cases"]]
    assert {"tls", "raw", "refused"} == set(outcomes)
    assert connect.demux(b"") == connect.demux(b"G") == "refused"


def test_connect_rules():
    # The schemes: canonical names, other for the rest, each once; auth-params are no schemes.
    assert connect.auth_schemes([b'Basic realm="a,b", NTLM', b"negotiate abc==, basic", b'Kerberos, x = "y"']) == \
        ["Basic", "NTLM", "Negotiate", "other"]
    assert connect.auth_schemes([b'realm="x"', b"", b",", b'"Basic"']) == []
    # A 2xx keeps every byte after the head; the head is the first CRLF CRLF.
    assert connect.parse_reply(b"HTTP/1.1 200 OK\r\n\r\n\r\n\r\n") == (connect.TUNNEL, b"\r\n\r\n")
    # Not HTTP: decided at the first byte that differs; a bare LF or CR at once.
    assert connect.parse_reply(b"X") == (connect.MALFORMED,)
    assert connect.parse_reply(b"HTTP/1.1 200 OK\n") == (connect.MALFORMED,)
    assert connect.parse_reply(b"HTTP/1.1 200 OK\r") is None
    assert connect.parse_reply(b"HTTP/1.1 200 OK\rX") == (connect.MALFORMED,)


def test_new_python_imports_only_stdlib():
    for path in (via.__file__, net_proxy.__file__, ws.__file__, connect.__file__, GEN):
        tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                assert top in sys.stdlib_module_names or top == "raven_protocol", (path, name)
