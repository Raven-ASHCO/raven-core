#!/usr/bin/env python3
"""A tiny lab proxy for the restrictive-network tests (Phase 4, RWS1).

Two modes, standard library only (Python 3.8+), for loopback and Linux
network namespaces; never a proxy for real traffic:

  connect   (default) an HTTP CONNECT proxy, as a company network has one:
            `CONNECT host:port HTTP/1.1`, then a blind tunnel. The proxy
            resolves names itself (`--map NAME=IP` first, then the system
            resolver), so a client behind it needs no DNS. With `--auth
            SCHEMES` every CONNECT is answered `407 Proxy Authentication
            Required` offering those schemes (`Negotiate,NTLM`: a proxy that
            wants a Windows sign-in) and nothing is tunnelled.
  tls-gate  a transparent gate (iptables/nftables REDIRECT to it): a
            connection whose first byte is 0x16 (a TLS record) is passed on
            to where it was going (Linux SO_ORIGINAL_DST, or `--upstream`),
            anything else is closed unanswered, as a network that lets only
            TLS out does.

Every connection gets one line in `--log` (default stderr): what was asked
(`CONNECT name:port`, or the gate's destination), the answer, the first byte
the client sent through the tunnel and the byte counts. Nothing else: no
payload is kept. `--port-file` receives the bound port once listening, and
stdout says `tiny_connect_proxy: listening HOST:PORT`.

Usage:
  tiny_connect_proxy.py --listen 127.0.0.1:0 [--map relay.invalid=127.0.0.1]
                        [--auth Negotiate,NTLM] [--log FILE] [--port-file FILE]
  tiny_connect_proxy.py --mode tls-gate --listen 0.0.0.0:8443 [--upstream HOST:PORT]
  tiny_connect_proxy.py --self-test
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import sys
import threading
import time

HEAD_MAX = 8192
CONNECT_TIMEOUT = 10.0
PEEK_TIMEOUT = 10.0
# Linux <linux/netfilter_ipv4.h>: the destination before a REDIRECT.
SO_ORIGINAL_DST = 80


class Log:
    """One line per event, flushed at once (a killed proxy loses nothing)."""

    def __init__(self, path: str | None) -> None:
        self.lock = threading.Lock()
        self.out = open(path, 'a', buffering=1) if path else sys.stderr

    def line(self, text: str) -> None:
        with self.lock:
            self.out.write(f'{time.time():.3f} {text}\n')
            self.out.flush()


def split_hostport(text: str, any_port: bool = False) -> tuple[str, int]:
    """`any_port`: port 0 too (a listen address: any free port)."""
    host, sep, port = text.rpartition(':')
    if not sep or not port.isdigit() or not (0 if any_port else 1) <= int(port) < 65536:
        raise ValueError(f'not host:port: {text!r}')
    return host.strip('[]'), int(port)


def pump(src: socket.socket, dst: socket.socket, tally: dict, key: str) -> None:
    try:
        while True:
            data = src.recv(16384)
            if not data:
                break
            if key == 'up' and tally['first'] is None:
                tally['first'] = data[0]
            tally[key] += len(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def tunnel(client: socket.socket, upstream: socket.socket, tally: dict) -> None:
    """Both directions until either end closes."""
    up = threading.Thread(target=pump, args=(client, upstream, tally, 'up'), daemon=True)
    up.start()
    pump(upstream, client, tally, 'down')
    up.join(5)


def first_byte(tally: dict) -> str:
    return 'none' if tally['first'] is None else f"{tally['first']:02x}"


def read_head(client: socket.socket) -> tuple[bytes, bytes]:
    """The request head (through the blank line) and any bytes after it."""
    buf = b''
    while b'\r\n\r\n' not in buf:
        if len(buf) > HEAD_MAX:
            raise ValueError('head too long')
        chunk = client.recv(4096)
        if not chunk:
            raise ValueError('closed before the head ended')
        buf += chunk
    head, _, rest = buf.partition(b'\r\n\r\n')
    return head, rest


def resolve(host: str, names: dict) -> str:
    if host.lower() in names:
        return names[host.lower()]
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0]


def handle_connect(client: socket.socket, opts, log: Log) -> None:
    tally = {'first': None, 'up': 0, 'down': 0}
    try:
        client.settimeout(CONNECT_TIMEOUT)
        head, rest = read_head(client)
        line = head.split(b'\r\n', 1)[0].decode('latin-1')
        parts = line.split()
        if len(parts) != 3 or parts[0] != 'CONNECT':
            client.sendall(b'HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n')
            log.line(f'{parts[0] if parts else "?"} refused 405')
            return
        target = parts[1]
        if opts.auth:
            offers = ''.join(f'Proxy-Authenticate: {s}\r\n' for s in opts.auth)
            client.sendall(('HTTP/1.1 407 Proxy Authentication Required\r\n' + offers
                            + 'Content-Length: 0\r\nConnection: close\r\n\r\n').encode())
            log.line(f'CONNECT {target} 407 ({",".join(opts.auth)})')
            return
        try:
            host, port = split_hostport(target)
            upstream = socket.create_connection((resolve(host, opts.names), port),
                                                timeout=CONNECT_TIMEOUT)
        except (OSError, ValueError, IndexError):
            client.sendall(b'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n')
            log.line(f'CONNECT {target} 502')
            return
        upstream.settimeout(None)
        client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        log.line(f'CONNECT {target} 200')
        # The client speaks first (a TLS ClientHello): its first byte is
        # logged before anything else of the tunnel.
        first = rest or client.recv(16384)
        client.settimeout(None)
        if first:
            tally['first'] = first[0]
            tally['up'] += len(first)
            upstream.sendall(first)
        log.line(f'tunnel {target} first={first_byte(tally)}')
        tunnel(client, upstream, tally)
        log.line(f'closed {target} first={first_byte(tally)} up={tally["up"]} '
                 f'down={tally["down"]}')
    except (OSError, ValueError) as e:
        log.line(f'error {type(e).__name__}')
    finally:
        client.close()


def original_dst(client: socket.socket) -> tuple[str, int]:
    raw = client.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port, packed = struct.unpack_from('!2xH4s', raw)
    return socket.inet_ntoa(packed), port


def handle_gate(client: socket.socket, opts, log: Log) -> None:
    tally = {'first': None, 'up': 0, 'down': 0}
    try:
        dst = opts.upstream or original_dst(client)
        client.settimeout(PEEK_TIMEOUT)
        try:
            peeked = client.recv(1, socket.MSG_PEEK)
        except socket.timeout:
            peeked = b''
        if peeked[:1] != b'\x16':
            log.line(f'gate drop {dst[0]}:{dst[1]} first={peeked.hex() or "none"}')
            return
        upstream = socket.create_connection(dst, timeout=CONNECT_TIMEOUT)
        upstream.settimeout(None)
        client.settimeout(None)
        log.line(f'gate pass {dst[0]}:{dst[1]} first=16')
        tunnel(client, upstream, tally)
        log.line(f'gate closed {dst[0]}:{dst[1]} up={tally["up"]} down={tally["down"]}')
    except (OSError, ValueError) as e:
        log.line(f'gate error {type(e).__name__}')
    finally:
        client.close()


def serve(opts, log: Log, ready: threading.Event | None = None,
          bound: list | None = None) -> None:
    host, port = split_hostport(opts.listen, any_port=True)
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    lsock = socket.socket(family, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((host, port))
    lsock.listen(128)
    port = lsock.getsockname()[1]
    if opts.port_file:
        with open(opts.port_file, 'w') as f:
            f.write(f'{port}\n')
    print(f'tiny_connect_proxy: listening {host}:{port}', flush=True)
    if bound is not None:
        bound.append(lsock)
    if ready is not None:
        ready.set()
    handler = handle_gate if opts.mode == 'tls-gate' else handle_connect
    while True:
        try:
            client, _ = lsock.accept()
        except OSError:
            return
        threading.Thread(target=handler, args=(client, opts, log), daemon=True).start()


def parse(argv: list) -> argparse.Namespace:
    p = argparse.ArgumentParser(description='lab CONNECT proxy and TLS-only gate')
    p.add_argument('--listen', default='127.0.0.1:0')
    p.add_argument('--mode', choices=('connect', 'tls-gate'), default='connect')
    p.add_argument('--map', action='append', default=[], metavar='NAME=IP',
                   help='resolve NAME to IP (repeatable; the system resolver otherwise)')
    p.add_argument('--auth', default='', metavar='SCHEMES',
                   help='answer every CONNECT 407 offering these schemes (comma separated)')
    p.add_argument('--upstream', default='', metavar='HOST:PORT',
                   help='tls-gate: pass to this address instead of SO_ORIGINAL_DST')
    p.add_argument('--log', default='', help='append one line per connection here')
    p.add_argument('--port-file', default='', help='write the bound port here')
    p.add_argument('--self-test', action='store_true')
    opts = p.parse_args(argv)
    names = {}
    for item in opts.map:
        name, sep, ip = item.partition('=')
        if not sep:
            p.error(f'--map wants NAME=IP, not {item!r}')
        ipaddress.ip_address(ip)
        names[name.lower()] = ip
    opts.names = names
    opts.auth = [s.strip() for s in opts.auth.split(',') if s.strip()]
    opts.upstream = split_hostport(opts.upstream) if opts.upstream else None
    return opts


def self_test() -> int:
    """CONNECT with a mapped name, 407, and the gate, on loopback."""
    echo = socket.socket()
    echo.bind(('127.0.0.1', 0))
    echo.listen(8)
    echo_port = echo.getsockname()[1]

    def echo_loop() -> None:
        while True:
            try:
                c, _ = echo.accept()
            except OSError:
                return
            data = c.recv(64)
            c.sendall(b'echo:' + data)
            c.close()
    threading.Thread(target=echo_loop, daemon=True).start()

    def start(args: list) -> int:
        opts = parse(args + ['--listen', '127.0.0.1:0'])
        ready, bound = threading.Event(), []
        threading.Thread(target=serve, args=(opts, Log(None), ready, bound),
                         daemon=True).start()
        ready.wait(5)
        return bound[0].getsockname()[1]

    ok = True
    port = start(['--map', 'relay.invalid=127.0.0.1'])
    with socket.create_connection(('127.0.0.1', port), timeout=5) as s:
        s.sendall(f'CONNECT relay.invalid:{echo_port} HTTP/1.1\r\n'
                  f'Host: relay.invalid:{echo_port}\r\n\r\n\x16hi'.encode())
        got = b''
        while b'echo:' not in got or not got.endswith(b'hi'):
            chunk = s.recv(256)
            if not chunk:
                break
            got += chunk
    ok &= got.startswith(b'HTTP/1.1 200 ') and got.endswith(b'echo:\x16hi')
    port = start(['--auth', 'Negotiate,NTLM'])
    with socket.create_connection(('127.0.0.1', port), timeout=5) as s:
        s.sendall(b'CONNECT relay.invalid:443 HTTP/1.1\r\n\r\n')
        got = s.recv(1024)
    ok &= (got.startswith(b'HTTP/1.1 407 ') and b'Proxy-Authenticate: Negotiate\r\n' in got
           and b'Proxy-Authenticate: NTLM\r\n' in got)
    port = start(['--mode', 'tls-gate', '--upstream', f'127.0.0.1:{echo_port}'])
    for first, passes in ((b'\x16tls', True), (b'\x13raw', False)):
        with socket.create_connection(('127.0.0.1', port), timeout=15) as s:
            s.sendall(first)
            try:
                got = s.recv(64)
            except ConnectionResetError:
                got = b''   # closed with the byte unread: a reset
        ok &= (got == b'echo:' + first) == passes and (passes or got == b'')
    print('tiny_connect_proxy self-test:', 'ok' if ok else 'FAILED')
    return 0 if ok else 1


def main(argv: list) -> int:
    opts = parse(argv)
    if opts.self_test:
        return self_test()
    try:
        serve(opts, Log(opts.log or None))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
