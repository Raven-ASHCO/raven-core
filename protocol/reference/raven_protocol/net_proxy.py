# protocol/reference/raven_protocol/net_proxy.py
"""Proxy rules for relay dials over WSS (protocol/RAVEN_WSS_TRANSPORT_V1.md sections 7 and 8),
standard library only.

An independent implementation of raven-core's net_proxy: the proxy setting and URL grammar
(parse_setting, parse_proxy_url, the Basic value and the redacted text), has_credentials (the
node policy rule), the bypass list (Bypass) and parse_windows_proxy. Mirrors
node/crates/raven-core/src/net_proxy.rs. Errors carry a code (ProxyError.code) and a status
kind (ProxyError.kind); the vectors record both.
"""
import base64
import ipaddress

DEFAULT_PORT = 80
MAX_TEXT = 1024
SPACE = " \t\r\n"          # what is trimmed and split on (both implementations)
LIST_SEPARATORS = ",;" + SPACE
REDACTED = "<redacted>"

# Unsupported kinds (owner decision O4-4).
HTTPS = "https"
SOCKS = "socks"
PAC = "pac"
# Invalid codes: the rule the text breaks.
SYNTAX = "syntax"        # empty, or a character outside 0x21..0x7e once trimmed
TOO_LONG = "too_long"    # over MAX_TEXT bytes once trimmed
SCHEME = "scheme"        # a scheme other than http, https and socks*
USERINFO = "userinfo"    # empty, a bad % escape, ':' in the user name, a control character
HOST = "host"            # not a DNS name, an IPv4 address of one host or [IPv6]
PORT = "port"            # not 1-65535 in plain decimal
PATH = "path"            # anything after the host and port but one '/'
INVALID = "invalid"      # the status kind of every invalid code
SOCKS_SCHEMES = ("socks", "socks4", "socks4a", "socks5", "socks5h")


class ProxyError(ValueError):
    def __init__(self, code, unsupported=False):
        super().__init__(code)
        self.code = code
        self.kind = code if unsupported else INVALID


def _invalid(code):
    return ProxyError(code)


def _unsupported(kind):
    return ProxyError(kind, unsupported=True)


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def ascii_lower(text):
    return text.translate(_ASCII_LOWER)


class ProxyUrl:
    """An http:// proxy: host (lowercase name or IP text without brackets), port, Basic value."""

    def __init__(self, host, port, basic):
        self.host, self.port, self.basic = host, port, basic

    def display(self):
        cred = f"{REDACTED}@" if self.basic is not None else ""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{cred}{host}:{self.port}"

    def __eq__(self, other):
        return isinstance(other, ProxyUrl) and (self.host, self.port, self.basic) == \
            (other.host, other.port, other.basic)

    def __repr__(self):
        return f"ProxyUrl({self.display()!r})"


def has_credentials(text):
    """Whether a proxy setting carries a user name or password: any '@' (no host has one)."""
    return "@" in text


def parse_setting(text):
    """("auto",), ("off",) or ("url", ProxyUrl); ProxyError otherwise."""
    t = text.strip(SPACE)
    if t == "" or ascii_lower(t) == "auto":
        return ("auto",)
    if ascii_lower(t) == "off":
        return ("off",)
    return ("url", parse_proxy_url(t))


def setting_display(setting):
    return setting[0] if setting[0] != "url" else setting[1].display()


def is_pac(text):
    base = ascii_lower(text)
    for stop in "?#":
        base = base.split(stop, 1)[0]
    return base in ("pac", "wpad") or base.endswith(".pac") or base.endswith("/wpad.dat")


def parse_proxy_url(text):
    t = text.strip(SPACE)
    if len(t.encode("utf-8")) > MAX_TEXT:
        raise _invalid(TOO_LONG)
    if t == "" or not all(0x21 <= ord(c) <= 0x7E for c in t):
        raise _invalid(SYNTAX)
    if is_pac(t):
        raise _unsupported(PAC)
    if "://" in t:
        scheme, rest = t.split("://", 1)
        scheme = ascii_lower(scheme)
        if scheme == "https":
            raise _unsupported(HTTPS)
        if scheme in SOCKS_SCHEMES:
            raise _unsupported(SOCKS)
        if scheme != "http":
            raise _invalid(SCHEME)
    else:
        rest = t
    end = min([i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i >= 0], default=len(rest))
    authority, tail = rest[:end], rest[end:]
    if tail not in ("", "/"):
        raise _invalid(PATH)
    basic = None
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
        basic = basic_value(userinfo)
    host, port = split_host_port(authority)
    return ProxyUrl(host, port, basic)


def percent_decode(text):
    out = bytearray()
    raw = text.encode("ascii")
    i = 0
    while i < len(raw):
        if raw[i] == ord("%"):
            hexpair = raw[i + 1:i + 3]
            if len(hexpair) != 2 or not all(chr(b) in "0123456789abcdefABCDEF" for b in hexpair):
                return None
            out.append(int(hexpair, 16))
            i += 3
        else:
            out.append(raw[i])
            i += 1
    return bytes(out)


def basic_value(userinfo):
    """base64 of user:pass (RFC 7617), each percent-decoded."""
    if userinfo == "":
        raise _invalid(USERINFO)
    user, _, password = userinfo.partition(":")
    user, password = percent_decode(user), percent_decode(password)
    if user is None or password is None or b":" in user \
            or any(b < 0x20 or b == 0x7F for b in user + password):
        raise _invalid(USERINFO)
    return base64.b64encode(user + b":" + password).decode("ascii")


def host_name_ok(name):
    """Labels of 1-63 letters, digits, '-' and '_' (no '-' at either end), at most 253 bytes, one
    trailing dot allowed, and a last label that is not all digits."""
    if name.endswith("."):
        name = name[:-1]
    if not 0 < len(name) <= 253:
        return False
    for label in name.split("."):
        if not 0 < len(label) <= 63 or label.startswith("-") or label.endswith("-"):
            return False
        if not all(c.isascii() and (c.isalnum() or c in "-_") for c in label):
            return False
    last = name.rsplit(".", 1)[-1]
    return not all(c in "0123456789" for c in last)


def single_host(ip):
    if ip.version == 4 and (ip.is_unspecified or ip.is_multicast
                            or ip == ipaddress.IPv4Address("255.255.255.255")):
        raise _invalid(HOST)
    if ip.version == 6 and (ip.is_unspecified or ip.is_multicast):
        raise _invalid(HOST)
    return str(ip)


def canonical_ip(ip):
    """An IPv4-mapped IPv6 address is its IPv4 address."""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def parse_port(text):
    if not text.isascii() or not text.isdigit() or str(int(text)) != text or not 0 < int(text) <= 65535:
        return None
    return int(text)


def split_host_port(text):
    """The canonical host and the port; the host is checked before the port."""
    if text.startswith("["):
        if "]" not in text:
            raise _invalid(HOST)
        inside, after = text[1:].split("]", 1)
        if after != "" and not after.startswith(":"):
            raise _invalid(HOST)
        port = None if after == "" else after[1:]
        if "%" in inside:
            raise _invalid(HOST)
        try:
            ip = ipaddress.IPv6Address(inside)
        except ValueError:
            raise _invalid(HOST) from None
        host = single_host(canonical_ip(ip))
    else:
        host, sep, port = text.partition(":")
        port = port if sep else None
        try:
            host = single_host(ipaddress.IPv4Address(host))
        except ipaddress.AddressValueError:
            lower = ascii_lower(host)
            if not host_name_ok(lower):
                raise _invalid(HOST) from None
            host = lower
    if port is None:
        return host, DEFAULT_PORT
    n = parse_port(port)
    if n is None:
        raise _invalid(PORT)
    return host, n


def ip_of(text):
    """An IP address (no zone), IPv4-mapped IPv6 as IPv4; None otherwise."""
    if "%" in text:
        return None
    try:
        return canonical_ip(ipaddress.ip_address(text))
    except ValueError:
        return None


def masked(ip, length):
    width = 32 if ip.version == 4 else 128
    if length > width:
        return None
    mask = ((1 << width) - 1) ^ ((1 << (width - length)) - 1)
    return ipaddress.ip_address(int(ip) & mask) if ip.version == 4 else ipaddress.IPv6Address(int(ip) & mask)


def network(addr, length):
    if not length.isascii() or not length.isdigit() or str(int(length)) != length or int(length) > 255:
        return None
    length = int(length)
    if ":" in addr:
        if "%" in addr:
            return None
        try:
            ip = ipaddress.IPv6Address(addr)
        except ValueError:
            return None
    else:
        parts = addr.split(".")
        if len(parts) > 4:
            return None
        octets = []
        for part in parts:
            if not part.isascii() or not part.isdigit() or str(int(part)) != part or int(part) > 255:
                return None
            octets.append(int(part))
        octets += [0] * (4 - len(octets))
        ip = ipaddress.IPv4Address(bytes(octets))
    net = masked(ip, length)
    return None if net is None else ("net", net, length)


def glob_match(glob, text):
    """'*' matches any run of characters (dots included); everything else itself."""
    g = t = 0
    star = None
    while t < len(text):
        if g < len(glob) and glob[g] == "*":
            star = (g, t)
            g += 1
        elif g < len(glob) and glob[g] == text[t]:
            g += 1
            t += 1
        elif star is not None:
            sg, st = star
            g, t = sg + 1, st + 1
            star = (sg, st + 1)
        else:
            return False
    return all(c == "*" for c in glob[g:])


def split_entry_port(entry):
    """(host part, port or None); None when the port is not usable."""
    if entry.startswith("["):
        if "]" not in entry:
            return None
        inside, after = entry[1:].split("]", 1)
        if after == "":
            return inside, None
        if not after.startswith(":"):
            return None
        port = parse_port(after[1:])
        return None if port is None else (inside, port)
    if ":" in entry:
        host, port = entry.split(":", 1)
        if ":" not in port:
            n = parse_port(port)
            return None if n is None else (host, n)
    return entry, None


def pattern_of(host):
    if "/" in host:
        addr, length = host.split("/", 1)
        return network(addr, length)
    if "*" in host:
        return ("glob", host)
    ip = ip_of(host)
    if ip is not None:
        return ("ip", ip)
    name = host[1:] if host.startswith(".") else host
    name = name[:-1] if name.endswith(".") else name
    return ("suffix", name) if host_name_ok(name) else None


def always_direct(name, ip):
    if ip is None:
        return name == "localhost" or name.endswith(".localhost")
    if ip.version == 4:
        return ip.is_loopback or ip in ipaddress.IPv4Network("169.254.0.0/16")
    return ip.is_loopback or ip in ipaddress.IPv6Network("fe80::/10")


class Bypass:
    """A bypass list (NO_PROXY, macOS ExceptionsList, Windows ProxyOverride)."""

    def __init__(self, entries=()):
        self.all = False
        self.simple_names = False
        self.rules = []
        for item in entries:
            for entry in split_any(item, LIST_SEPARATORS):
                self.add(entry)

    @classmethod
    def parse(cls, text):
        return cls([text])

    def add(self, entry):
        entry = ascii_lower(entry)
        if entry == "":
            return
        if entry == "*":
            self.all = True
            return
        if entry == "<local>":
            self.simple_names = True
            return
        split = split_entry_port(entry)
        if split is None:
            return
        host, port = split
        pattern = pattern_of(host)
        if pattern is not None:
            self.rules.append((pattern, port))

    def bypasses(self, host, port):
        host = host.strip(SPACE)
        if len(host) >= 2 and host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        host = ascii_lower(host)
        name = host[:-1] if host.endswith(".") else host
        ip = ip_of(name)
        if always_direct(name, ip) or self.all:
            return True
        if self.simple_names and ip is None and name != "" and "." not in name:
            return True
        text = name if ip is None else str(ip)
        for (pattern, only) in self.rules:
            if only is not None and only != port:
                continue
            kind = pattern[0]
            if kind == "suffix":
                domain = pattern[1]
                if ip is None and (name == domain or name.endswith("." + domain)):
                    return True
            elif kind == "glob":
                if glob_match(pattern[1], text):
                    return True
            elif kind == "ip":
                if ip == pattern[1]:
                    return True
            elif kind == "net":
                if ip is not None and ip.version == pattern[1].version and masked(ip, pattern[2]) == pattern[1]:
                    return True
        return False


def split_any(text, separators):
    out, cur = [], []
    for c in text:
        if c in separators:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    out.append("".join(cur))
    return out


def parse_windows_proxy(text):
    """The https= entry of a Windows proxy string, else the first entry without a scheme."""
    bare = None
    for item in split_any(text, ";" + SPACE):
        if "=" in item:
            scheme, entry = item.split("=", 1)
            if ascii_lower(scheme) == "https" and entry != "":
                return entry
        elif item != "" and bare is None:
            bare = item
    return bare
