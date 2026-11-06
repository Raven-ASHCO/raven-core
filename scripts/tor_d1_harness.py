#!/usr/bin/env python3
"""D1 harness: how long a Raven message takes over Tor, from Send to the
signed receipt (the security and speed report of 5 November 2026, section
7, and the Tor fallback design, docs/design/2026-10-tor-fallback.md).

D1 runs from messages.send accepted to the friend signed receipt verified
and stored by the client, on the monotonic clock. The engine measures it
(the ms of its receipt event); the harness also times that event as
events.wait shows it (D1 ui). D1 peer (the friend node storing the message)
needs a stored time this build does not expose, so that field stays empty.

Two locked file lab profiles on this computer, S (the sender, measured)
and F (the friend), each run their own debug raven-node and their own Tor
helper, on random free 127.0.0.1 ports (never 7420 to 7427 or 17420), in a
new lab folder. They become friends as scripts/lan_fault_matrix.py makes
them: ash init, ash prekey publish, a card that names the onion service
only, ash contact add with --verify-fp both ways. S sends through the
engine (the library behind raven_call) in an engine worker process of its
own. Nothing but Tor reaches F: route hints, friend relays, STUN, port
mapping, the NAT class, punching, nearby, the LAN beacon and WAN custody
are closed with their debug lab switches, and the cards hold no LAN or
Internet address. A run delivered over another carrier is discarded and
counted.

Modes
  dry (the default): the lab loopback Tor helper (raven-node
    tor-loopback-helper, or in process for ER) plays Tor with simulated
    round trips: r per connect (BEGIN to CONNECTED), r/2 each way per byte,
    R for a fresh rendezvous, a circuit dropped after --sim-kept-s without
    use (Arti keeps one 10 min) and a Tor start of --sim-ready-ms. No Tor
    network and no Internet: every socket of the harness processes is
    checked to be on loopback (lsof) after each restart and after each run.
    It refuses to start without lsof and ps, and stops when either fails or
    lsof sees no socket of the lab processes while they run.
  real: real Tor through a debug raven-tor-helper (Arti). It refuses to
    start unless --real-tor is given AND the environment has
    RAVEN_D1_OWNER_OK=1: the owner says yes to each real run first.

Cases (n per arm; --n CASE=N or --n-all N to change)
  AA  A/A first: WC with two base arms, 30 each; their medians must agree
  WL  warm link: a send every 5 s after one discarded priming send, 60
  WC  warm circuit: a send every 60 s (dry 35 s), past WARM_IDLE 20 s and
      the 30 s idle limit of the listener, inside the kept circuit time, 60
  PW  prewarmed, patched arm only: contacts.warm typing 5 s before each WC
      send, 30 (a run whose warm up did not start is discarded; skipped
      with an engine that has no contacts.warm)
  CN  cold, new Tor life: a wake line in the netwatch lab file of S
      restarts its helper; send at once when Tor is ready (at_ready) and
      30 s after it (ready_30s), 30 each
  CI  cold after idle: a send every 11 min (dry: the kept time and 5 s),
      past the 10 min of Arti and GROUP_KEPT, 30 (the keep warm arm, M2,
      is not built yet: skipped)
  ER  embedded resume (the tor-embedded engine, --embedded-engine): pause
      and resume the node in the worker process, then send at once, 30
Arms: base (no Stage A switch) and patched (the Stage A lab switches of
--patched, by default RAVEN_LAB_TOR_WARM and RAVEN_LAB_TOR_HEDGE, read only
with RAVEN_LAB_TEST_A=1 in a debug build; every gate stays false). They
alternate ABAB in blocks of --block runs (10); S restarts for each block and
the first run after a restart is discarded. F keeps base.

Output, in the lab folder
  d1-runs.jsonl    one line per run: case, variant, arm, block, run, minute
                   of day, outcome (ok, queued, failed), carrier, d1_ms,
                   d1_ui_ms, the stage times of each onion dial S made for
                   it (RAVEN_LAB_TOR_STAGES), links opened, the Tor life
                   counter. Durations, counts and fixed words only: no
                   text, keys, onion ids or addresses (each line is checked
                   before it is written, and again when it is analysed).
  d1-analysis.txt  per case, variant and arm: n, the median and p90 with
                   their 95 percent rank intervals, and the claim rule.
                   Failed and queued sends count as over 1 s. Median under
                   1 s only if the 20th of 30 sorted values (37th of 60) is
                   under 1000 ms; p90 under 1 s only if the largest of 30
                   (59th of 60) is.
  A run that ended well removes the profiles, node logs and the Tor
  registry (--keep-lab keeps them).

Usage
  cargo build --locked -p raven-node -p ash -p raven-client      # in node/
  cargo build --locked -p raven-client --features tor-embedded   # for ER
      (copy target/debug/libraven_client.dylib first: this build replaces it)
  python3 -I scripts/tor_d1_harness.py run --bin-dir BIN --lab LAB
      [--engine LIB] [--embedded-engine LIB] [--cases AA,WL,WC,PW,CN,CI,ER]
      [--n CASE=N] [--n-all N] [--block N] [--interval CASE=S]
      [--patched WARM,HEDGE] [--sim-r-ms 100] [--sim-rendezvous-ms 1500]
      [--sim-kept-s 45] [--sim-ready-ms 2000] [--er-pause-s 5]
      [--send-timeout-s S] [--keep-lab]
      (a send with no receipt after --send-timeout-s counts as queued;
      120 s dry, 300 s real)
  python3 -I scripts/tor_d1_harness.py analyze LAB/d1-runs.jsonl [--out FILE]
  python3 -I scripts/tor_d1_harness.py --self-test   # no build, no process
  RAVEN_D1_OWNER_OK=1 python3 -I scripts/tor_d1_harness.py run --real-tor
      --tor-helper BIN/raven-tor-helper ...           # only with the owner yes

BIN is a debug build folder with raven-node, ash and the engine library
(for a dry run with no raven-tor-helper next to raven-node). LAB is a new
short folder (lab-1, lab-2 and so on; the IPC socket path limit), never in
~/.raven, another live profile or a git work tree. Debug binaries and the
lab locked file backends only, never an OS keystore: each binary is checked
to be a debug build before it runs. Python 3.9 or newer, standard library
only.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import ipaddress
import json
import math
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HARNESS_VERSION = 1
SCRIPT = Path(__file__).resolve()

# The ports a lab run never binds: the owner's live raven-node and Raven's
# defaults (7420 to 7427) and 17420.
FORBIDDEN_PORTS = frozenset(range(7420, 7428)) | frozenset({17420})

# ── Cases, arms and the words a record may hold ────────────────────────────

CASE_ORDER = ('AA', 'WL', 'WC', 'PW', 'CN', 'CI', 'ER')
ARMS = ('base', 'patched', 'base_again')
VARIANTS = ('plain', 'at_ready', 'ready_30s', 'keep_warm')
OUTCOMES = ('ok', 'queued', 'failed')
# not_warmed: a PW run whose warm up did not start (contacts.warm answered
# warming false), so it is no prewarmed send.
DISCARDS = ('restart', 'priming', 'carrier', 'not_warmed')
STATES = ('sending', 'sent', 'delivered', 'waiting', 'time_ran_out', 'not_sent_meet_first',
          'failed')
CARRIERS = ('onion', 'lan', 'internet', 'p2p', 'p2p_direct', 'p2p_reversed', 'p2p_relayed',
            'p2p_hole_punched', 'websocket', 'nearby', 'friend', 'handoff', 'letter', 'unknown')
ENDED = ('failed', 'time_ran_out', 'not_sent_meet_first')
PURPOSES = ('check', 'outbox', 'dial')
# raven-node's stage record (src/onion/stages.rs `Record`), durations only.
STAGE_MS = ('prep_ms', 'connect_ms', 'circuit_ms', 'begin_ms', 'noise_ms', 'hello_ms',
            'write_ms', 'receipt_ms')
DIAL_KEYS = ('purpose', 'frames', 'ok') + STAGE_MS + ('total_ms',)
SKIP_WHY = {
    'no_contacts_warm': 'contacts.warm is not in this engine (M3 not built)',
    'no_keep_warm': 'keep warm (M2) is not built',
    'no_embedded_engine': 'no --embedded-engine given',
    'embedded_engine_without_tor': 'the embedded engine has no Tor in process',
}
ABORT_WHY = ('network_outside_loopback', 'interrupted', 'node_ended', 'worker_ended',
             'tor_not_ready', 'setup_failed', 'harness_error', 'loopback_check_failed')

# Tor speed Stage A: its five lab switches (raven-core onion_gate.rs), every
# gate false. W2 (WARM_LINK) changes the wire and needs both ends patched,
# while F keeps base here: only the dialer side ones are allowed.
STAGE_A = {'WARM': 'RAVEN_LAB_TOR_WARM', 'HEDGE': 'RAVEN_LAB_TOR_HEDGE',
           'EARLY': 'RAVEN_LAB_TOR_EARLY', 'OPTIMISTIC': 'RAVEN_LAB_TOR_OPTIMISTIC',
           'WARM_LINK': 'RAVEN_LAB_TOR_WARM_LINK'}
DIALER_SIDE = ('WARM', 'HEDGE', 'EARLY', 'OPTIMISTIC')
DEFAULT_PATCHED = ('WARM', 'HEDGE')

CASES = {
    'AA': {'arms': ('base', 'base_again'), 'variants': ('plain',), 'n': 30,
           'interval': 60.0, 'dry_interval': 35.0},
    'WL': {'arms': ('base', 'patched'), 'variants': ('plain',), 'n': 60,
           'interval': 5.0, 'dry_interval': 5.0},
    'WC': {'arms': ('base', 'patched'), 'variants': ('plain',), 'n': 60,
           'interval': 60.0, 'dry_interval': 35.0},
    'PW': {'arms': ('patched',), 'variants': ('plain',), 'n': 30,
           'interval': 60.0, 'dry_interval': 35.0},
    'CN': {'arms': ('base', 'patched'), 'variants': ('at_ready', 'ready_30s'), 'n': 30,
           'interval': 0.0, 'dry_interval': 0.0},
    'CI': {'arms': ('base', 'patched'), 'variants': ('plain', 'keep_warm'), 'n': 30,
           'interval': 660.0, 'dry_interval': None},
    'ER': {'arms': ('base', 'patched'), 'variants': ('plain',), 'n': 30,
           'interval': 0.0, 'dry_interval': 0.0},
}
SCHEDULED = ('AA', 'WL', 'WC', 'PW', 'CI')
PW_WARM_BEFORE_S = 5.0
CN_AFTER_READY_S = {'at_ready': 0.0, 'ready_30s': 30.0}
# raven-node's own times the cases are placed around.
WARM_IDLE_S = 20.0       # src/onion/warm.rs WARM_IDLE
LISTENER_IDLE_S = 30.0   # the listener ends a link after 30 s without a frame
ARTI_KEPT_S = 600.0      # Arti keeps a circuit 10 min after its last use
# Between the end of one run and the next send, at least.
MIN_GAP_S = 0.5
# A receipt seen this much later than the engine's own D1 came after the
# send job ended (the outbox delivered it): the send counts as queued.
LATE_SLACK_MS = 1000
# A dial record is appended as the dial ends, before the engine sees the
# receipt: a short wait catches one written a moment later.
STAGE_SETTLE_S = 0.3

SIM_DEFAULTS = {'r_ms': 100, 'rendezvous_ms': 1500, 'kept_s': 45.0, 'ready_ms': 2000}
SIM_MAX_MS = 60_000          # the loopback helper caps each of its times there
SIM_KEPT_MAX_S = 3600.0      # and the kept time at an hour

# The lab network the netwatch lab files report (a documentation range).
LAB_NETWORK = '192.0.2.10/24'

# ── Environments ────────────────────────────────────────────────────────────

# The only settings taken from the caller: everything else is set here.
CALLER_KEEP = ('PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'USER', 'LOGNAME')
# Gates on in release builds that could carry a run past Tor or reach the
# Internet: closed in every process ("0" closes a gate whose const is on,
# raven-core pair_init.rs lab_gate).
CLOSED_GATES = ('RAVEN_LAB_ROUTE_HINTS', 'RAVEN_LAB_FRIEND_RELAY', 'RAVEN_LAB_PORT_MAP',
                'RAVEN_LAB_V6_PINHOLE', 'RAVEN_LAB_NAT_CLASS', 'RAVEN_LAB_STUN_DISCOVERY',
                'RAVEN_LAB_SERVERLESS_PUNCH', 'RAVEN_LAB_NEARBY', 'RAVEN_LAB_LAN_BEACON',
                'RAVEN_LAB_CUSTODY_WAN')
# The loopback helper's knobs (src/onion/loopback.rs).
# The release gates those switches close (raven-core), as reviewed: a name
# leaves CLOSED_GATES only with an owner decision (the self test holds both).
CLOSED_GATE_CONSTS = ('ROUTE_HINTS_PRODUCTION_ENABLED', 'FRIEND_RELAY_PRODUCTION_ENABLED',
                      'PORT_MAP_PRODUCTION_ENABLED', 'V6_PINHOLE_PRODUCTION_ENABLED',
                      'NAT_CLASS_PRODUCTION_ENABLED', 'STUN_DISCOVERY_PRODUCTION_ENABLED',
                      'SERVERLESS_PUNCH_PRODUCTION_ENABLED')
LOOPBACK_KNOBS = ('RAVEN_LAB_TOR_LOOPBACK_DELAY_MS', 'RAVEN_LAB_TOR_LOOPBACK_LATENCY_MS',
                  'RAVEN_LAB_TOR_LOOPBACK_RENDEZVOUS_MS', 'RAVEN_LAB_TOR_LOOPBACK_KEPT_MS',
                  'RAVEN_LAB_TOR_LOOPBACK_READY_MS', 'RAVEN_LAB_TOR_LOOPBACK_ONE_CIRCUIT')
LOCKED_FILE = ('RAVEN_IDENTITY_BACKEND', 'RAVEN_SESSION_BACKEND', 'RAVEN_PREKEY_BACKEND',
               'RAVEN_CHAT_HISTORY_BACKEND')
# The tools the dry mode loopback check runs (refused without them).
TOOLS = {'lsof': ('/usr/sbin/lsof', '/usr/bin/lsof', '/bin/lsof'),
         'ps': ('/bin/ps', '/usr/bin/ps')}


class Refused(Exception):
    """The harness will not start (a message for the caller)."""


class Aborted(Exception):
    """A run stopped part way; `why` is one of ABORT_WHY."""

    def __init__(self, why: str, message: str) -> None:
        super().__init__(message)
        self.why = why


def common_env(caller: dict, lab: Path, mode: str, sim: dict | None,
               tor_helper: Path | None = None) -> dict:
    """Every process of a run (ash, raven-node, the engine worker): a few
    of the caller's settings (CALLER_KEEP) and nothing else of theirs, a
    home folder inside the lab, the lab locked file backends, Lab Test A,
    Tor on, the gates of CLOSED_GATES closed, loopback only listeners, no
    proxy, sealed profiles that may be erased only under the lab; in the dry
    mode the loopback Tor helper and its model, in the real mode the named
    debug Tor helper."""
    env = {k: caller[k] for k in CALLER_KEEP if k in caller}
    env.setdefault('PATH', '/usr/bin:/bin')
    env.update({
        'HOME': str(lab / 'home'),
        'NO_COLOR': '1',
        'RAVEN_ALLOW_EPHEMERAL_DATA_DIR': '1',
        'RAVEN_SERVICE_LAN_LISTEN': '127.0.0.1:0',
        'RAVEN_P2P_PROXY': 'off',
        'RAVEN_LAB_AT_REST': '1',
        'RAVEN_LAB_ERASE_ROOT': str(lab),
        'RAVEN_LAB_TEST_A': '1',
        'RAVEN_LAB_TOR': '1',
    })
    env.update({k: 'locked-file' for k in LOCKED_FILE})
    env.update({k: '0' for k in CLOSED_GATES})
    if mode == 'dry':
        if sim is None:
            raise Refused('the dry mode needs its simulated times')
        r = int(sim['r_ms'])
        env.update({
            'RAVEN_LAB_TOR_LOOPBACK': str(lab / 'tor-registry'),
            'RAVEN_LAB_TOR_LOOPBACK_DELAY_MS': str(r),
            'RAVEN_LAB_TOR_LOOPBACK_LATENCY_MS': str(r // 2),
            'RAVEN_LAB_TOR_LOOPBACK_RENDEZVOUS_MS': str(int(sim['rendezvous_ms'])),
            'RAVEN_LAB_TOR_LOOPBACK_KEPT_MS': str(int(sim['kept_s'] * 1000)),
            'RAVEN_LAB_TOR_LOOPBACK_READY_MS': str(int(sim['ready_ms'])),
            'RAVEN_LAB_TOR_LOOPBACK_ONE_CIRCUIT': '1',
        })
    else:
        if tor_helper is None:
            raise Refused('the real mode needs --tor-helper, a debug raven-tor-helper')
        env['RAVEN_TOR_HELPER'] = str(tor_helper)
    return env


def sender_env(common: dict, lab: Path, arm: str, patched: tuple) -> dict:
    """S's raven-node: its stage record file, its netwatch lab file and,
    in the patched arm only, the Stage A lab switches of `patched`."""
    env = dict(common)
    for name in STAGE_A.values():
        env.pop(name, None)
    if arm == 'patched':
        for key in patched:
            env[STAGE_A[key]] = '1'
    env['RAVEN_LAB_TOR_STAGES'] = str(lab / 'raw' / 's-stages.jsonl')
    env['RAVEN_LAB_NETWATCH_EVENTS'] = str(lab / 's.netwatch')
    return env


def friend_env(common: dict, lab: Path) -> dict:
    """F's raven-node: base always, its own netwatch lab file."""
    env = dict(common)
    for name in STAGE_A.values():
        env.pop(name, None)
    env['RAVEN_LAB_NETWATCH_EVENTS'] = str(lab / 'f.netwatch')
    return env


def worker_env(node_env: dict, profile: Path, lab: Path, embedded: bool) -> dict:
    """The engine worker of S: the environment of S's node, its profile and
    a raven-node program that does not exist (the harness starts the nodes;
    a start the engine would make itself fails). `embedded`: the node runs
    in the worker (RAVEN_NODE_MODE=embedded)."""
    env = dict(node_env)
    env['RAVEN_DATA_DIR'] = str(profile)
    env['RAVEN_NODE_BIN'] = str(lab / 'no-node-start')
    if embedded:
        env['RAVEN_NODE_MODE'] = 'embedded'
    else:
        env.pop('RAVEN_NODE_MODE', None)
    return env


def dry_env_refusal(env: dict) -> str:
    """Why `env` could reach the Tor network or the Internet in a dry run,
    or '' (checked before every process start of a dry run)."""
    loop = env.get('RAVEN_LAB_TOR_LOOPBACK', '')
    if not loop or not os.path.isabs(loop):
        return 'the dry mode needs an absolute RAVEN_LAB_TOR_LOOPBACK'
    if 'RAVEN_TOR_HELPER' in env:
        return 'the dry mode never names a Tor helper'
    if env.get('RAVEN_LAB_TEST_A') != '1':
        return 'the lab unlock is missing'
    for key in CLOSED_GATES:
        if env.get(key) != '0':
            return f'{key} is not closed'
    for key in LOOPBACK_KNOBS:
        if key not in env:
            return f'{key} is missing'
    if env.get('RAVEN_P2P_PROXY') != 'off' or env.get('RAVEN_SERVICE_LAN_LISTEN') != '127.0.0.1:0':
        return 'the listeners or the proxy are not the lab ones'
    for key in ('RAVEN_P2P_LISTEN', 'RAVEN_P2P_RELAYS', 'RAVEN_P2P_RELAY',
                'RAVEN_INTERNET_LISTEN', 'HTTPS_PROXY', 'ALL_PROXY'):
        if key in env:
            return f'{key} is set'
    return ''


def stage_a_refusal(env: dict, arm: str, patched: tuple, friend: bool) -> str:
    """Why `env` opens a Stage A gate it should not, or '': only S's
    patched arm sets the switches of `patched`, always with the lab
    unlock; F never sets one."""
    on = {key for key, name in STAGE_A.items() if env.get(name) is not None}
    want = set(patched) if (arm == 'patched' and not friend) else set()
    if on != want:
        return 'the Stage A switches are not those of the arm'
    if on and env.get('RAVEN_LAB_TEST_A') != '1':
        return 'a Stage A switch without the lab unlock'
    if any(env.get(STAGE_A[key]) != '1' for key in on):
        return 'a Stage A switch with another value than 1'
    return ''


def real_mode_refusal(real: bool, env: dict) -> str:
    """The real mode (`real`) starts only with RAVEN_D1_OWNER_OK=1 (exactly
    1) in the environment, beside --real-tor; '' when it may start (or it is
    a dry run)."""
    if not real:
        return ''
    if env.get('RAVEN_D1_OWNER_OK') != '1':
        return ('the real mode needs the owner OK: --real-tor and RAVEN_D1_OWNER_OK=1 in '
                'the environment')
    return ''


def tool(name: str) -> str | None:
    """Where the tool `name` of TOOLS is (the PATH, then its usual places)."""
    found = shutil.which(name)
    if found:
        return found
    return next((p for p in TOOLS[name] if os.path.isfile(p)), None)


def tools_refusal(mode: str, find=tool) -> str:
    """Why this computer cannot check the dry mode loopback rule, or '': it
    needs lsof (each socket of the lab processes) and ps (the processes
    below the nodes, the Tor helpers among them)."""
    if mode != 'dry':
        return ''
    missing = [name for name in sorted(TOOLS) if not find(name)]
    if missing:
        return ('the dry mode needs lsof and ps to check every socket of its processes; '
                'missing: ' + ', '.join(missing))
    return ''


def worker_refusal(env: dict, real: bool) -> str:
    """Why the engine worker must not open the profile of `env`, or '': it
    runs only as a run of this harness starts it, on a lab profile (the
    lab erase root, with the profile and the home folder inside it; the
    four locked file backends; Lab Test A; RAVEN_NODE_BIN at the lab path
    that starts no node) and the Tor of its mode (dry: the loopback helper
    of an absolute RAVEN_LAB_TOR_LOOPBACK and no Tor helper; `real`, as
    the parent passed it on: an absolute RAVEN_TOR_HELPER)."""
    root = env.get('RAVEN_LAB_ERASE_ROOT', '')
    if not root or not os.path.isabs(root):
        return 'the engine worker runs only under a lab folder (RAVEN_LAB_ERASE_ROOT)'
    base = os.path.realpath(root)

    def inside(key: str) -> bool:
        value = env.get(key, '')
        if not value or not os.path.isabs(value):
            return False
        path = os.path.realpath(value)
        return path != base and os.path.commonpath([base, path]) == base

    if not inside('RAVEN_DATA_DIR') or not inside('HOME'):
        return 'the profile and the home folder of the engine worker must be in the lab folder'
    if any(env.get(k) != 'locked-file' for k in LOCKED_FILE):
        return 'the engine worker needs the lab locked file backends'
    if env.get('RAVEN_LAB_TEST_A') != '1':
        return 'the lab unlock is missing'
    node = env.get('RAVEN_NODE_BIN', '')
    if not node or os.path.realpath(node) != os.path.join(base, 'no-node-start'):
        return 'the engine worker never starts a node of its own'
    if real:
        helper = env.get('RAVEN_TOR_HELPER', '')
        if not helper or not os.path.isabs(helper) or 'RAVEN_LAB_TOR_LOOPBACK' in env:
            return 'the real mode needs an absolute RAVEN_TOR_HELPER and no loopback helper'
    else:
        loop = env.get('RAVEN_LAB_TOR_LOOPBACK', '')
        if not loop or not os.path.isabs(loop) or 'RAVEN_TOR_HELPER' in env:
            return 'the dry mode needs an absolute RAVEN_LAB_TOR_LOOPBACK and no Tor helper'
    return ''


def engine_refusal(info) -> str:
    """Why the engine that answered app.info with `info` must not run a lab
    profile, or '': only a debug engine (build dev) may."""
    if not isinstance(info, dict) or info.get('ok') is not True:
        return 'the engine did not answer app.info'
    result = info.get('result')
    if not isinstance(result, dict) or result.get('build') != 'dev':
        return 'not a debug engine'
    return ''


# ── Lab folder, ports, builds ───────────────────────────────────────────────

PROTECTED_HOME = ('.raven', 'raven-try', 'raven-wan-test', 'raven-3m-test', '.lima')
PROTECTED_TREES = (('Developer', '.worktrees', 'raven-features'),
                   ('Developer', 'raven-oss', 'ui'))
PROFILE_MARKERS = ('identity.backend', 'identity.binding', 'keystore.backend', 'contacts.json')


def lab_refusal(lab: Path, home: Path) -> str:
    """Why `lab` must not be this run's lab folder, or ''. It must be new,
    neither the home folder nor above it, nowhere in a live Raven folder
    (~/.raven and the other test homes), in a protected work tree, in a git
    work tree or in a Raven profile."""
    p = Path(os.path.realpath(lab))
    h = Path(os.path.realpath(home))
    if p == h or p in h.parents:
        return 'the lab folder is the home folder or above it'
    for name in PROTECTED_HOME:
        q = h / name
        if p == q or q in p.parents:
            return f'the lab folder is inside ~/{name}'
    for parts in PROTECTED_TREES:
        q = h.joinpath(*parts)
        if p == q or q in p.parents:
            return 'the lab folder is inside a protected work tree'
    if p.exists():
        return 'the lab folder exists already: name a new one'
    for d in p.parents:
        if (d / '.git').exists():
            return 'the lab folder is inside a git work tree'
        if any((d / m).exists() for m in PROFILE_MARKERS):
            return 'the lab folder is inside a Raven profile'
    return ''


def _bind_zero() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def free_port(taken: set, bind=_bind_zero) -> int:
    """A free 127.0.0.1 port that is no FORBIDDEN_PORTS one and not in
    `taken` (which it joins)."""
    for _ in range(500):
        port = bind()
        if port not in FORBIDDEN_PORTS and port not in taken:
            taken.add(port)
            return port
    raise Refused('no free loopback port')


def file_has(path: Path, needles: tuple) -> dict:
    """Which of the byte strings `needles` the file holds (read in chunks)."""
    found = {n: False for n in needles}
    keep = max(len(n) for n in needles) - 1
    tail = b''
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8 << 20)
            if not chunk:
                break
            data = tail + chunk
            for n in needles:
                if not found[n] and n in data:
                    found[n] = True
            tail = data[-keep:] if keep > 0 else b''
    return found


# Strings only a debug build holds: the hidden loopback helper command
# (#[cfg(debug_assertions)] in raven-node), the object paths of a debug
# target folder and the overflow checks of the dev profile.
NODE_DEBUG = b'tor-loopback-helper'
DEBUG_OBJECTS = b'/debug/deps/'
OVERFLOW_CHECK = b'attempt to add with overflow'
WARM_MODEL = (b'RAVEN_LAB_TOR_LOOPBACK_RENDEZVOUS_MS', b'RAVEN_LAB_TOR_LOOPBACK_KEPT_MS')
ARTI_IN_PROCESS = b'tor_hsclient'


def engine_name() -> str:
    if sys.platform == 'darwin':
        return 'libraven_client.dylib'
    if sys.platform.startswith('win'):
        return 'raven_client.dll'
    return 'libraven_client.so'


def build_refusal(bin_dir: Path, mode: str, engine: Path, embedded: Path | None,
                  tor_helper: Path | None) -> str:
    """Why these binaries must not run against lab profiles, or '': each is
    a debug build (a release build refuses the lab backends and would seal
    a profile with a keychain item), the dry mode has the warm circuit
    model and no Tor helper next to raven-node, the embedded engine has Tor
    in process. The engines say their build themselves too (app.info)."""
    node, ash = bin_dir / 'raven-node', bin_dir / 'ash'
    for p in (node, ash, engine):
        if not p.is_file():
            return f'{p.name} is not in the build folder'
    need = {node: (NODE_DEBUG,) + (WARM_MODEL if mode == 'dry' else ()),
            ash: (DEBUG_OBJECTS, OVERFLOW_CHECK),
            engine: (DEBUG_OBJECTS,)}
    if embedded is not None:
        if not embedded.is_file():
            return 'the embedded engine library is missing'
        need[embedded] = (DEBUG_OBJECTS, ARTI_IN_PROCESS) + (WARM_MODEL if mode == 'dry' else ())
    if mode == 'real':
        if tor_helper is None or not tor_helper.is_file():
            return 'the real mode needs --tor-helper, a debug raven-tor-helper'
        need[tor_helper] = (DEBUG_OBJECTS, OVERFLOW_CHECK)
    elif (bin_dir / 'raven-tor-helper').exists():
        return ('the dry mode never has raven-tor-helper next to raven-node: use a build folder '
                'without it')
    for path, needles in need.items():
        found = file_has(path, needles)
        missing = [n for n in needles if not found[n]]
        if missing:
            if NODE_DEBUG in missing or DEBUG_OBJECTS in missing or OVERFLOW_CHECK in missing:
                return f'{path.name} is not a debug build'
            if WARM_MODEL[0] in missing:
                return f'{path.name} has no warm circuit model: build it from this tree'
            if ARTI_IN_PROCESS in missing:
                return f'{path.name} has no Tor in process: build it with --features tor-embedded'
            return f'{path.name} is not a debug build'
    return ''


# ── Records: what a line of d1-runs.jsonl may hold ──────────────────────────


def _int(v, lo: int = 0, hi: int = 10 ** 9) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _version(v) -> bool:
    return _int(v) and v == HARNESS_VERSION


def _ms(v) -> bool:
    return v is None or _int(v)


def _num(v) -> bool:
    return (isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
            and 0 <= v < 1e9)


def _word(words):
    return lambda v: isinstance(v, str) and v in words


def _opt(check):
    return lambda v: v is None or check(v)


def _dial(v) -> bool:
    if not isinstance(v, dict) or set(v) != set(DIAL_KEYS):
        return False
    return (v['purpose'] in PURPOSES and _int(v['frames']) and isinstance(v['ok'], bool)
            and all(_ms(v[k]) for k in STAGE_MS) and _int(v['total_ms']))


def _dials(v) -> bool:
    return isinstance(v, list) and len(v) <= 64 and all(_dial(d) for d in v)


def _words_list(words):
    return lambda v: isinstance(v, list) and len(v) <= 16 and all(
        isinstance(w, str) and w in words for w in v)


def _dict_of(keys, check):
    return lambda v: isinstance(v, dict) and all(
        isinstance(k, str) and k in keys and check(x) for k, x in v.items())


def _sim(v) -> bool:
    return v is None or (isinstance(v, dict) and set(v) == set(SIM_DEFAULTS)
                         and all(_num(x) for x in v.values()))


SCHEMA = {
    'meta': {
        'type': None, 'v': _version, 'mode': _word(('dry', 'real')),
        'cases': _words_list(CASE_ORDER), 'n': _dict_of(CASE_ORDER, _int),
        'block': lambda v: _int(v, 1), 'patched': _words_list(tuple(STAGE_A)),
        'intervals': _dict_of(CASE_ORDER, _num), 'sim': _sim, 'er_pause_s': _num,
        'send_timeout_s': _num, 'minute': lambda v: _int(v, 0, 1439),
    },
    'run': {
        'type': None, 'v': _version, 'mode': _word(('dry', 'real')),
        'case': _word(CASE_ORDER), 'variant': _word(VARIANTS), 'arm': _word(ARMS),
        'block': lambda v: _int(v, 1), 'run': _int, 'seq': lambda v: _int(v, 1),
        'discard': _opt(_word(DISCARDS)), 'minute': lambda v: _int(v, 0, 1439),
        'outcome': _word(OUTCOMES), 'state': _opt(_word(STATES)),
        'carrier': _opt(_word(CARRIERS)), 'd1_ms': _ms, 'd1_ui_ms': _ms, 'd1_peer_ms': _ms,
        'send_call_ms': _ms, 'ready_wait_ms': _ms, 'dials': _dials, 'links_opened': _int,
        'tor_life': _int,
    },
    'skip': {
        'type': None, 'v': _version, 'case': _word(CASE_ORDER),
        'variant': _word(VARIANTS), 'why': _word(tuple(SKIP_WHY)),
    },
    'end': {
        'type': None, 'v': _version, 'runs': _int, 'counted': _int,
        'discards': _dict_of(DISCARDS, _int), 'unattributed_dials': _int,
        'setup_sends': _int, 'loopback_checks': _int, 'loopback_sockets': _int,
        'elapsed_s': _num,
    },
    'abort': {
        'type': None, 'v': _version, 'why': _word(ABORT_WHY),
    },
}
REQUIRED = {
    'meta': set(SCHEMA['meta']),
    'run': set(SCHEMA['run']),
    'skip': set(SCHEMA['skip']),
    'end': set(SCHEMA['end']),
    'abort': set(SCHEMA['abort']),
}


def record_refusal(rec) -> str:
    """Why `rec` must not be a line of a D1 run file, or '': only known
    fields, each a number, a bool, null or one of the fixed words, and a
    run that ended ok has its D1."""
    if not isinstance(rec, dict):
        return 'not an object'
    kind = rec.get('type')
    fields = SCHEMA.get(kind) if isinstance(kind, str) else None
    if fields is None:
        return 'unknown type'
    for key, value in rec.items():
        if key not in fields:
            return f'unknown field {key}'
        check = fields[key]
        if check is not None and not check(value):
            return f'bad value in {key}'
    missing = REQUIRED[kind] - set(rec)
    if missing:
        return 'missing ' + ', '.join(sorted(missing))
    if kind == 'run' and (rec['outcome'] == 'ok') != (rec['d1_ms'] is not None):
        return 'd1_ms belongs to an ok run, and only to one'
    return ''


class Out:
    """d1-runs.jsonl: every record checked before it is written (0600)."""

    def __init__(self, path: Path) -> None:
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)

    def write(self, rec: dict) -> None:
        why = record_refusal(rec)
        if why:
            raise Aborted('harness_error', f'a record failed its check ({why})')
        line = json.dumps(rec, separators=(',', ':'), sort_keys=True) + '\n'
        os.write(self.fd, line.encode())

    def close(self) -> None:
        os.close(self.fd)


def dial_from_stage(obj) -> dict | None:
    """One line of raven-node's stage record as a run's dial entry, or None
    when it is not one (any other field, any other value)."""
    if not isinstance(obj, dict) or set(obj) != set(DIAL_KEYS):
        return None
    dial = {k: obj[k] for k in DIAL_KEYS}
    return dial if _dial(dial) else None


def links_opened(dials: list) -> int:
    """The Raven links a run opened: its dials with a Noise handshake (a
    dial that rode a kept link has none)."""
    return sum(1 for d in dials if d['noise_ms'] is not None)


# ── The claim rule (qci_check.py of the speed review) ───────────────────────


def binom_cdf(k: int, n: int, p: float) -> float:
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(0, k + 1))


def upper_rank(n: int, q: float, conf: float = 0.95) -> int | None:
    """The one sided upper 95 percent rank of the q quantile: the smallest u
    (1 based) with P(Bin(n, q) <= u - 1) >= conf, or None when n is too
    small (no sorted value bounds it)."""
    for u in range(1, n + 1):
        if binom_cdf(u - 1, n, q) >= conf:
            return u
    return None


def rank_interval(n: int, q: float, conf: float = 0.95) -> tuple | None:
    """The tightest two sided rank interval (l, u), 1 based, that holds the
    q quantile with at least `conf`, as qci_check.py finds it; None when n
    is too small."""
    best = None
    for lo in range(1, n + 1):
        for up in range(lo, n + 1):
            cov = binom_cdf(up - 1, n, q) - binom_cdf(lo - 1, n, q)
            if cov >= conf:
                width, mid = up - lo, abs((lo + up) / 2 - n * q)
                if (best is None or width < best[1] - best[0]
                        or (width == best[1] - best[0]
                            and mid < abs((best[0] + best[1]) / 2 - n * q))):
                    best = (lo, up)
                break
    return best


def point_rank(n: int, q: float) -> int:
    """The nearest rank of the q quantile among n sorted values (1 based)."""
    return max(1, math.ceil(q * n))


def claim(values: list, q: float, limit_ms: float = 1000.0) -> tuple:
    """The claim rule for "the q quantile is under `limit_ms`" over `values`
    (failed and queued runs as inf): ('supported' | 'not_supported' |
    'n_too_small', the rank used, its value)."""
    s = sorted(values)
    u = upper_rank(len(s), q)
    if u is None:
        return ('n_too_small', None, None)
    v = s[u - 1]
    return ('supported' if v < limit_ms else 'not_supported', u, v)


# ── Analysis ────────────────────────────────────────────────────────────────


def read_records(paths: list) -> list:
    """Every record of the run files `paths`; a line that is not a D1
    record refuses the whole analysis."""
    out = []
    for path in paths:
        with open(path, encoding='utf-8') as f:
            for no, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    raise Refused(f'{Path(path).name} line {no} is not JSON')
                why = record_refusal(rec)
                if why:
                    raise Refused(f'{Path(path).name} line {no} is not a D1 record ({why})')
                out.append(rec)
    return out


def _fmt(v) -> str:
    if v is None:
        return 'none'
    return str(int(round(v)))


def _dur(v) -> str:
    """A D1 value in words: its ms, or a failed or queued send (inf)."""
    if v is None:
        return 'none'
    if isinstance(v, float) and math.isinf(v):
        return 'failed or queued'
    return f'{int(round(v))} ms'


def _median(values: list):
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    return vals[point_rank(len(vals), 0.5) - 1]


def _claim_words(name: str, values: list, q: float) -> str:
    verdict, rank, value = claim(values, q)
    n = len(values)
    if verdict == 'n_too_small':
        need = upper_rank_min_n(q)
        return f'{name} under 1 s: no claim (n {n} is too small; it needs n {need} or more)'
    word = 'supported' if verdict == 'supported' else 'not supported'
    return f'{name} under 1 s: {word} (rank {rank} of {n} is {_dur(value)})'


def upper_rank_min_n(q: float) -> int:
    n = 1
    while upper_rank(n, q) is None:
        n += 1
    return n


def _interval_words(values: list, q: float) -> str:
    s = sorted(values)
    iv = rank_interval(len(s), q)
    if iv is None:
        return 'n too small'
    lo, up = iv
    return f'ranks {lo} to {up}: {_dur(s[lo - 1])} to {_dur(s[up - 1])}'


def analyze(records: list) -> str:
    """The analysis text of `records` (see the module doc)."""
    metas = [r for r in records if r['type'] == 'meta']
    runs = [r for r in records if r['type'] == 'run']
    skips = [r for r in records if r['type'] == 'skip']
    ends = [r for r in records if r['type'] == 'end']
    aborts = [r for r in records if r['type'] == 'abort']
    lines = [f'D1 analysis, tor_d1_harness {HARNESS_VERSION}']
    modes = sorted({r['mode'] for r in runs} | {m['mode'] for m in metas})
    lines.append('mode ' + (', '.join(modes) if modes else 'none'))
    for m in metas:
        if m['sim']:
            s = m['sim']
            lines.append(f"simulated Tor: r {_fmt(s['r_ms'])} ms, R {_fmt(s['rendezvous_ms'])} ms, "
                         f"circuits kept {s['kept_s']:g} s, Tor start {_fmt(s['ready_ms'])} ms")
        stage_a = ', '.join(STAGE_A[k] for k in m['patched']) or 'none'
        lines.append(f"patched arm: {stage_a}; block {m['block']}")
    discards: dict = {}
    for r in runs:
        if r['discard']:
            discards[r['discard']] = discards.get(r['discard'], 0) + 1
    counted = [r for r in runs if not r['discard']]
    disc_words = ', '.join(f'{k} {v}' for k, v in sorted(discards.items())) or 'none'
    lines.append(f'runs {len(runs)}, counted {len(counted)}, discarded {sum(discards.values())} '
                 f'({disc_words})')
    for e in ends:
        lines.append(f"unattributed dials {e['unattributed_dials']}, setup sends "
                     f"{e['setup_sends']}, {e['elapsed_s']:.0f} s")
        lines.append(f"loopback checks {e['loopback_checks']}: {e['loopback_sockets']} sockets "
                     'seen, none past loopback' if e['loopback_checks'] else
                     'loopback checks: none (a real run)')
    for a in aborts:
        lines.append(f"aborted: {a['why']}")
    lines.append('')
    groups: dict = {}
    for r in runs:
        groups.setdefault((r['case'], r['variant'], r['arm']), []).append(r)

    def order(key):
        return (CASE_ORDER.index(key[0]), VARIANTS.index(key[1]), ARMS.index(key[2]))

    medians = {}
    intervals = {}
    for key in sorted(groups, key=order):
        rs = groups[key]
        kept = [r for r in rs if not r['discard']]
        gone = len(rs) - len(kept)
        d1 = [r['d1_ms'] if r['outcome'] == 'ok' else math.inf for r in kept]
        ui = [r['d1_ui_ms'] if r['outcome'] == 'ok' and r['d1_ui_ms'] is not None else math.inf
              for r in kept]
        n = len(d1)
        count = {o: sum(1 for r in kept if r['outcome'] == o) for o in OUTCOMES}
        lines.append(f'{key[0]} {key[1]} {key[2]}: n {n} (ok {count["ok"]}, queued '
                     f'{count["queued"]}, failed {count["failed"]}), discarded {gone}')
        if n == 0:
            lines.append('  no counted run')
            lines.append('')
            continue
        s, su = sorted(d1), sorted(ui)
        r50, r90 = point_rank(n, 0.5), point_rank(n, 0.9)
        medians[key] = s[r50 - 1]
        intervals[key] = (s, rank_interval(n, 0.5))
        lines.append(f'  D1: median {_dur(s[r50 - 1])} (rank {r50} of {n}), p90 '
                     f'{_dur(s[r90 - 1])} (rank {r90}); D1 ui: median {_dur(su[r50 - 1])}, '
                     f'p90 {_dur(su[r90 - 1])}')
        lines.append(f'  95 percent intervals: median {_interval_words(d1, 0.5)}; p90 '
                     f'{_interval_words(d1, 0.9)}')
        lines.append('  ' + _claim_words('median', d1, 0.5))
        lines.append('  ' + _claim_words('p90', d1, 0.9))
        lines.append('  links opened per run: median '
                     f"{_fmt(_median([r['links_opened'] for r in kept]))}; Tor lives at the last "
                     f"run: {kept[-1]['tor_life']}")
        late = [r['d1_ui_ms'] for r in kept if r['outcome'] == 'queued'
                and r['d1_ui_ms'] is not None]
        if late:
            lines.append(f'  queued sends with a receipt later: {len(late)}, median '
                         f'{_dur(_median(late))} to the receipt')
        waits = [r['ready_wait_ms'] for r in kept if r['ready_wait_ms'] is not None]
        if waits:
            lines.append(f'  wake to Tor ready: median {_dur(_median(waits))}')
        for purpose, label in (('check', 'check dial'), ('dial', 'message dial'),
                               ('outbox', 'outbox dial')):
            ds = [d for r in kept for d in r['dials'] if d['purpose'] == purpose]
            if not ds:
                continue
            parts = []
            for k in STAGE_MS + ('total_ms',):
                med = _median([d[k] for d in ds])
                if med is not None:
                    parts.append(f'{k[:-3]} {_fmt(med)}')
            lines.append(f'  {label} stage medians ms ({len(ds)} dials): ' + ', '.join(parts))
        lines.append('')
    a, b = ('AA', 'plain', 'base'), ('AA', 'plain', 'base_again')
    if a in intervals and b in intervals:
        (sa, ia), (sb, ib) = intervals[a], intervals[b]
        if ia is None or ib is None:
            lines.append(f'A/A: medians {_dur(medians[a])} and {_dur(medians[b])}; n too small '
                         'to judge them against their intervals')
        else:
            inside = (sb[ib[0] - 1] <= medians[a] <= sb[ib[1] - 1]
                      and sa[ia[0] - 1] <= medians[b] <= sa[ia[1] - 1])
            verdict = ('they agree' if inside else 'they differ by more than the interval: fix '
                       'the harness before any A/B')
            lines.append(f'A/A: medians {_dur(medians[a])} and {_dur(medians[b])}; {verdict}')
    for k in skips:
        lines.append(f"skipped: {k['case']} {k['variant']} ({SKIP_WHY[k['why']]})")
    lines.append('')
    lines.append('Claim rule: a quantile is under 1 s only if the sorted value at its one sided '
                 '95 percent upper rank is under 1000 ms (median: 20 of 30, 37 of 60; p90: 30 of '
                 '30, 59 of 60; p90 needs n 29 or more). Failed and queued sends count as over '
                 '1 s and are never dropped; discarded runs (the first after a restart, a '
                 'priming send, another carrier, a prewarm that did not start) are not '
                 'counted.')
    return '\n'.join(lines) + '\n'


# ── Logs and stage files of a running node ──────────────────────────────────

STARTING_RE = re.compile(r'onion: Tor: starting\s*$')
READY_RE = re.compile(r'onion: Tor: ready \(bootstrap')
LISTEN_RE = re.compile(r'lan_direct: listen\S*.*?(\S+:\d+)[ \t]*\n')


class Lives:
    """The Tor helper lives a node log shows from a byte offset on: how
    many started, and whether the last one is ready (counts only). A log
    started afresh (the embedded node's, past 1 MiB) is read from its
    start again."""

    def __init__(self, path: Path, offset: int) -> None:
        self.path, self.offset = path, offset
        self.lives, self.ready, self.buf = 0, False, b''

    def feed(self, data: bytes) -> None:
        self.buf += data
        while b'\n' in self.buf:
            raw, self.buf = self.buf.split(b'\n', 1)
            line = raw.decode('utf-8', 'replace')
            if STARTING_RE.search(line):
                self.lives += 1
                self.ready = False
            elif READY_RE.search(line) and self.lives:
                self.ready = True

    def poll(self) -> tuple:
        try:
            with open(self.path, 'rb') as f:
                if os.fstat(f.fileno()).st_size < self.offset:
                    self.offset, self.buf = 0, b''
                f.seek(self.offset)
                data = f.read()
        except OSError:
            data = b''
        self.offset += len(data)
        self.feed(data)
        return self.lives, self.ready


class Stages:
    """S's stage record file (RAVEN_LAB_TOR_STAGES, appended by each S node
    in turn): the dial lines since the last look."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.offset = path.stat().st_size if path.exists() else 0
        self.unattributed = 0

    def _read(self) -> list:
        try:
            with open(self.path, 'rb') as f:
                f.seek(self.offset)
                data = f.read()
        except OSError:
            return []
        end = data.rfind(b'\n')
        if end < 0:
            return []
        self.offset += end + 1
        dials = []
        for raw in data[:end].split(b'\n'):
            try:
                dial = dial_from_stage(json.loads(raw))
            except ValueError:
                dial = None
            if dial is None:
                raise Aborted('harness_error', 'a stage record line is not one')
            dials.append(dial)
        return dials

    def mark(self) -> None:
        """The lines so far belong to no run (setup, restarts)."""
        self.unattributed += len(self._read())

    def since_mark(self) -> list:
        return self._read()


def node_socket_path(data_dir: Path) -> Path:
    """Where the raven-node of `data_dir` listens (raven_core ipc
    default_socket_path, as scripts/lan_fault_matrix.py computes it)."""
    base = os.path.realpath(data_dir)
    direct = Path(base) / 'raven-node.sock'
    if len(os.fsencode(str(direct))) <= 103:
        return direct
    digest = hashlib.sha256(b'raven/ipc-socket/v1\0' + os.fsencode(base)).hexdigest()[:16]
    return Path(f'/tmp/raven-{os.geteuid()}') / f'raven-{digest}.sock'


# ── Processes: nodes, the engine worker, the loopback check ─────────────────

# The embedded node's log in its profile (raven-node embedded.rs LOG_FILE_NAME).
EMBEDDED_LOG = 'raven-node-service.log'


def open_private(path: Path):
    """`path` opened to append, created 0600 (logs and lab files)."""
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), 'ab')


class Node:
    """One profile's raven-node service, started by this harness."""

    def __init__(self, name: str, profile: Path, node_bin: Path, log_path: Path,
                 lan_port: int, ble_port: int) -> None:
        self.name, self.profile, self.node_bin = name, profile, node_bin
        self.log_path, self.lan_port, self.ble_port = log_path, lan_port, ble_port
        self.proc: subprocess.Popen | None = None
        self.starts = 0
        self.mark = 0

    def start(self, env: dict) -> None:
        self.starts += 1
        with open_private(self.log_path) as log:
            log.write(f'===== d1 start {self.starts}\n'.encode())
        self.mark = self.log_path.stat().st_size
        with open_private(self.log_path) as log:
            self.proc = subprocess.Popen(
                [str(self.node_bin), 'service', '--data-dir', str(self.profile),
                 '--lan-listen', f'127.0.0.1:{self.lan_port}',
                 '--ble-listen', f'127.0.0.1:{self.ble_port}'],
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=env)

    def since_start(self) -> str:
        with open(self.log_path, 'rb') as f:
            f.seek(self.mark)
            return f.read().decode('utf-8', 'replace')

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(10)
        self.proc = None


class Worker:
    """The engine worker of S (this script's engine-worker command): one
    request per line on its stdin, one answer per line on its stdout."""

    def __init__(self, lib: Path, env: dict, log_path: Path, real: bool) -> None:
        self.log = open_private(log_path)
        self.proc = subprocess.Popen(
            [sys.executable, '-I', str(SCRIPT), 'engine-worker', '--lib', str(lib)]
            + (['--real'] if real else []),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, env=env)
        self.buf = b''
        try:
            hello = self._read(120)
        except Aborted:
            hello = {}
        if 'hello' not in hello:
            self.stop()
            raise Aborted('setup_failed', 'the engine worker refused: '
                          + str(hello.get('refused', 'no answer')))

    def _read(self, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        out = self.proc.stdout
        assert out is not None
        while b'\n' not in self.buf:
            left = deadline - time.monotonic()
            if left <= 0:
                raise Aborted('worker_ended', 'the engine worker did not answer in time')
            ready, _, _ = select.select([out], [], [], left)
            if ready:
                chunk = os.read(out.fileno(), 1 << 16)
                if not chunk:
                    raise Aborted('worker_ended', 'the engine worker ended')
                self.buf += chunk
        line, self.buf = self.buf.split(b'\n', 1)
        return json.loads(line)

    def _ask(self, req: dict, timeout: float) -> dict:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write((json.dumps(req) + '\n').encode())
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise Aborted('worker_ended', 'the engine worker ended')
        return self._read(timeout)

    def call(self, op: str, args: dict | None = None, timeout: float = 180) -> dict:
        return self._ask({'cmd': 'call', 'op': op, 'args': args or {}}, timeout)

    def send(self, address: str, text: str, timeout_s: float) -> dict:
        return self._ask({'cmd': 'send', 'address': address, 'text': text,
                          'timeout_s': timeout_s}, timeout_s + 90)

    def idle(self, seconds: float) -> None:
        if seconds > 0:
            self._ask({'cmd': 'idle', 'seconds': seconds}, seconds + 90)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self) -> None:
        if self.proc.poll() is None:
            try:
                self._ask({'cmd': 'quit'}, 60)
            except Aborted:
                pass
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(10)
        for pipe in (self.proc.stdin, self.proc.stdout):
            if pipe is not None:
                pipe.close()
        self.log.close()


def descendants(pids: list) -> list | None:
    """`pids` and every process below them (ps); None when ps fails."""
    ps = tool('ps')
    if not ps:
        return None
    try:
        got = subprocess.run([ps, '-A', '-o', 'pid=,ppid='], capture_output=True, text=True,
                             timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if got.returncode != 0:
        return None
    out = got.stdout
    children: dict = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            children.setdefault(int(parts[1]), []).append(int(parts[0]))
    seen, todo = set(), list(pids)
    while todo:
        p = todo.pop()
        if p in seen:
            continue
        seen.add(p)
        todo.extend(children.get(p, []))
    return sorted(seen)


LOOPBACK_HOSTS = ('127.0.0.1', '[::1]', 'localhost', '::1')


def outside_loopback(lsof_out: str) -> tuple:
    """(sockets, how many of them reach past loopback) of an `lsof -nP -i`
    listing (a wildcard bind counts: it listens on every interface)."""
    seen = bad = 0
    for line in lsof_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        seen += 1
        name = ' '.join(parts[8:])
        name = re.sub(r'\s*\([A-Z_]+\)\s*$', '', name)
        for end in name.split('->'):
            host = end.rsplit(':', 1)[0] if ':' in end else end
            if host not in LOOPBACK_HOSTS:
                bad += 1
                break
    return seen, bad


def loopback_refusal(returncode: int, listing: str, alive: int) -> tuple:
    """The dry mode loopback check of one `lsof -nP -a -p PIDS -i` run over
    `alive` live lab processes: (sockets seen, the ABORT_WHY word or '', the
    message). It stops the run when lsof failed (a nonzero exit: it could
    not list every process), when it saw no socket while lab processes run
    (each raven-node listens: a listing of nothing proves nothing) and when
    a socket reaches past loopback."""
    seen, bad = outside_loopback(listing)
    if returncode != 0:
        return seen, 'loopback_check_failed', 'lsof failed: the loopback check could not run'
    if alive and not seen:
        return seen, 'loopback_check_failed', 'lsof saw no socket of the running lab processes'
    if bad:
        return (seen, 'network_outside_loopback',
                f'{bad} sockets of the lab processes reach past loopback')
    return seen, '', ''


# ── The engine worker (one process per engine) ──────────────────────────────


def receipt_outcome(waited: bool, ui_ms: int, engine_ms: int) -> tuple:
    """A receipt's (outcome, d1_ms). The engine's own time ends where its
    send job ended: a send that waited, or whose receipt showed well after
    that time (LATE_SLACK_MS), was delivered later by the outbox, so the
    time is no D1 and the send counts as queued."""
    if waited or ui_ms > engine_ms + LATE_SLACK_MS:
        return 'queued', None
    return 'ok', engine_ms


def worker_main(lib_path: str, real: bool = False) -> int:
    """`engine-worker --lib LIB [--real]`: the engine of one profile
    (RAVEN_DATA_DIR) through its C ABI. It refuses unless a run of this
    harness started it on a lab profile (worker_refusal; `real`: the parent
    passed the real mode on), then answers app.info and refuses a release
    engine. Commands: call (one engine request), send (a timed send, numbers
    and fixed words only), idle (keep the event watcher going), quit."""
    import ctypes
    proto = os.fdopen(os.dup(1), 'w', buffering=1, encoding='utf-8')
    # Anything the engine itself prints goes to the log, never into the
    # protocol.
    os.dup2(2, 1)

    def reply(obj) -> None:
        proto.write(json.dumps(obj) + '\n')
        proto.flush()

    why = worker_refusal(dict(os.environ), real)
    if why:
        reply({'refused': why})
        return 2
    try:
        lib = ctypes.CDLL(lib_path)
    except OSError:
        reply({'refused': 'the engine library did not load'})
        return 2
    lib.raven_call.restype = ctypes.c_void_p
    lib.raven_call.argtypes = [ctypes.c_char_p]
    lib.raven_free.restype = None
    lib.raven_free.argtypes = [ctypes.c_void_p]

    def call(op: str, args: dict) -> dict:
        raw = lib.raven_call(json.dumps({'v': 1, 'op': op, 'args': args}).encode())
        try:
            text = ctypes.string_at(raw).decode('utf-8', 'replace')
        finally:
            lib.raven_free(raw)
        try:
            return json.loads(text)
        except ValueError:
            return {'ok': False, 'error': {'code': 'INTERNAL'}}

    why = engine_refusal(call('app.info', {}))
    if why:
        reply({'refused': why})
        return 2
    first = call('events.poll', {'after_seq': 0})
    state = {'seq': int((first.get('result') or {}).get('seq', 0) or 0)}

    def drain() -> None:
        for _ in range(64):
            got = call('events.poll', {'after_seq': state['seq']})
            res = got.get('result') or {}
            state['seq'] = int(res.get('seq', state['seq']) or state['seq'])
            if not res.get('events'):
                return

    def wait(timeout_s: float) -> tuple:
        began = time.monotonic()
        got = call('events.wait', {'after_seq': state['seq'],
                                   'timeout_ms': max(1, int(min(25.0, timeout_s) * 1000))})
        at = time.monotonic()
        res = got.get('result') or {}
        state['seq'] = int(res.get('seq', state['seq']) or state['seq'])
        if not res.get('events') and at - began < 0.005:
            # Answered at once with nothing new (a refusal, a locked
            # profile): a short pause, never a busy loop.
            time.sleep(0.05)
        return res, at

    def ms(a: float, b: float) -> int:
        return max(0, int(round((b - a) * 1000)))

    def send(address: str, text: str, timeout_s: float) -> dict:
        drain()
        t0 = time.monotonic()
        got = call('messages.send', {'address': address, 'text': text})
        t1 = time.monotonic()
        out = {'outcome': 'failed', 'state': None, 'carrier': None, 'd1_ms': None,
               'd1_ui_ms': None, 'send_call_ms': ms(t0, t1), 'error': None}
        if not got.get('ok'):
            code = str((got.get('error') or {}).get('code', ''))
            out['error'] = code if re.fullmatch(r'[A-Z_]{1,40}', code) else 'OTHER'
            return out
        message = (got.get('result') or {}).get('message') or {}
        mid = message.get('id')
        st = message.get('state')
        out['state'] = st if st in STATES else None
        queued = st == 'waiting'
        deadline = t1 + timeout_s
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                out['outcome'] = 'queued'
                return out
            res, at = wait(left)
            if res.get('reset'):
                # Events were lost: this run's receipt may be among them,
                # so it counts as queued (over 1 s).
                queued = True
            for ev in res.get('events') or []:
                if ev.get('id') != mid:
                    continue
                kind = ev.get('kind')
                if kind == 'receipt':
                    carrier = ev.get('path_kind') or 'unknown'
                    ui = ms(t1, at)
                    outcome, d1 = receipt_outcome(queued, ui, int(ev.get('ms', 0)))
                    out.update(outcome=outcome, state='delivered', d1_ms=d1, d1_ui_ms=ui,
                               carrier=carrier if carrier in CARRIERS else 'unknown')
                    return out
                if kind == 'state':
                    st = ev.get('state')
                    out['state'] = st if st in STATES else out['state']
                    if st == 'waiting':
                        queued = True
                    if st in ENDED:
                        out['outcome'] = 'failed'
                        return out

    def idle(seconds: float) -> None:
        end = time.monotonic() + seconds
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return
            wait(left)

    reply({'hello': True})
    while True:
        line = sys.stdin.readline()
        if not line:
            return 0
        if not line.strip():
            continue
        req = json.loads(line)
        cmd = req.get('cmd')
        if cmd == 'call':
            reply(call(str(req.get('op')), req.get('args') or {}))
        elif cmd == 'send':
            reply(send(str(req['address']), str(req['text']), float(req['timeout_s'])))
        elif cmd == 'idle':
            idle(float(req['seconds']))
            reply({'ok': True})
        elif cmd == 'quit':
            reply({'ok': True})
            return 0
        else:
            reply({'ok': False})


# ── A run ───────────────────────────────────────────────────────────────────


def abab(arms: tuple, n: int, block: int) -> list:
    """The blocks of a case: [(arm, block number, runs)], the arms in turn
    (A B A B ...) in blocks of `block`, until each arm has `n` runs."""
    left = {a: n for a in arms}
    plan, no = [], 0
    while any(left.values()):
        for a in arms:
            if left[a] > 0:
                count = min(block, left[a])
                left[a] -= count
                no += 1
                plan.append((a, no, count))
    return plan


def timing_refusal(mode: str, intervals: dict, kept_s: float) -> str:
    """Why the case intervals do not make the cases they name, or '': WL
    within WARM_IDLE, WC (and AA, PW) past the listener idle limit and
    within the kept circuit time, CI past it."""
    if intervals['WL'] <= 0 or intervals['WL'] >= WARM_IDLE_S:
        return f'the WL interval must be above 0 and under {WARM_IDLE_S:g} s'
    for case in ('AA', 'WC', 'PW'):
        if not LISTENER_IDLE_S < intervals[case] < kept_s:
            return (f'the {case} interval must be above {LISTENER_IDLE_S:g} s and under the kept '
                    f'circuit time ({kept_s:g} s)')
    if intervals['CI'] <= kept_s:
        return f'the CI interval must be above the kept circuit time ({kept_s:g} s)'
    if mode == 'dry' and kept_s <= LISTENER_IDLE_S:
        return f'--sim-kept-s must be above {LISTENER_IDLE_S:g} s'
    return ''


def minute_of_day() -> int:
    t = time.localtime()
    return t.tm_hour * 60 + t.tm_min


def say(text: str) -> None:
    print(text, flush=True)


class Run:
    """One run of the harness (see the module doc)."""

    def __init__(self, args, caller: dict) -> None:
        self.args = args
        self.caller = caller
        self.mode = 'real' if args.real_tor else 'dry'
        self.lab = Path(os.path.realpath(args.lab))
        self.bin_dir = Path(os.path.realpath(args.bin_dir))
        self.engine = Path(os.path.realpath(args.engine or (self.bin_dir / engine_name())))
        self.embedded = (Path(os.path.realpath(args.embedded_engine))
                         if args.embedded_engine else None)
        self.tor_helper = (Path(os.path.realpath(args.tor_helper))
                           if args.tor_helper else None)
        self.sim = None if self.mode == 'real' else {
            'r_ms': args.sim_r_ms, 'rendezvous_ms': args.sim_rendezvous_ms,
            'kept_s': float(args.sim_kept_s), 'ready_ms': args.sim_ready_ms}
        self.kept_s = ARTI_KEPT_S if self.mode == 'real' else float(args.sim_kept_s)
        self.cases = args.cases
        self.n = dict(args.n)
        self.block = args.block
        self.patched = args.patched
        self.intervals = {}
        for case in CASE_ORDER:
            spec = CASES[case]
            if self.mode == 'real':
                self.intervals[case] = spec['interval']
            elif case == 'CI':
                self.intervals[case] = self.kept_s + 5.0
            else:
                self.intervals[case] = spec['dry_interval']
        self.intervals.update(args.interval)
        self.send_timeout = args.send_timeout_s or (120.0 if self.mode == 'dry' else 300.0)
        self.ready_timeout = 120.0 if self.mode == 'dry' else 900.0
        # The process environments: built only once refusal() let the run
        # start (environments()).
        self.common: dict = {}
        self.out: Out | None = None
        self.s_node: Node | None = None
        self.f_node: Node | None = None
        self.worker: Worker | None = None
        self.worker_embedded = False
        self.arm_env: dict = {}
        self.lives: Lives | None = None
        self.stages: Stages | None = None
        self.f_address = ''
        self.warm_built = False
        self.started_pids: set = set()
        self.lsof_checks = 0
        self.lsof_sockets = 0
        self.seq = 0
        self.setup_sends = 0
        self.prev_start: float | None = None
        self.prev_end: float | None = None
        self.t0 = time.monotonic()

    # The checks before anything starts. The real mode guard goes by the
    # mode itself, whatever set it.
    def refusal(self) -> str:
        why = real_mode_refusal(self.mode == 'real', self.caller)
        if why:
            return why
        why = lab_refusal(self.lab, Path.home())
        if why:
            return why
        why = build_refusal(self.bin_dir, self.mode, self.engine, self.embedded, self.tor_helper)
        if why:
            return why
        why = timing_refusal(self.mode, self.intervals, self.kept_s)
        if why:
            return why
        why = tools_refusal(self.mode)
        if why:
            return why
        if self.sim:
            if not all(0 < self.sim[k] <= SIM_MAX_MS for k in ('r_ms', 'rendezvous_ms',
                                                              'ready_ms')):
                return 'a simulated time is out of range (1 to 60000 ms)'
            if not 0 < self.sim['kept_s'] <= SIM_KEPT_MAX_S:
                return 'the simulated kept time is out of range'
        return ''

    def environments(self) -> None:
        """The environment every process of the run starts from (after
        refusal() let the run start)."""
        self.common = common_env(self.caller, self.lab, self.mode, self.sim, self.tor_helper)

    def guard_env(self, env: dict, arm: str, friend: bool) -> dict:
        if self.mode == 'dry':
            why = dry_env_refusal(env)
            if why:
                raise Aborted('harness_error', f'refusing a process environment: {why}')
        why = stage_a_refusal(env, arm, self.patched, friend)
        if why:
            raise Aborted('harness_error', f'refusing a process environment: {why}')
        return env

    def ash(self, profile: Path, *args: str, timeout: float = 120) -> subprocess.CompletedProcess:
        env = self.guard_env(dict(self.common), 'base', True)
        return subprocess.run([str(self.bin_dir / 'ash'), '--data-dir', str(profile), *args],
                              capture_output=True, text=True, timeout=timeout, env=env,
                              stdin=subprocess.DEVNULL)

    def node_up(self, node: Node) -> None:
        """Wait for `node` to listen, say its at rest state, answer IPC, take
        its lab network view and run a ready Tor."""
        deadline = time.monotonic() + self.ready_timeout
        lives = Lives(node.log_path, node.mark)
        ipc = False
        while True:
            if not node.alive():
                raise Aborted('node_ended', f'the {node.name} node ended while starting')
            text = node.since_start()
            lives.poll()
            up = LISTEN_RE.search(text) and 'raven-node at_rest: ' in text
            if up and not ipc:
                ipc = self.ash(node.profile, 'ipc-ping', timeout=20).returncode == 0
            settled = 'raven-node netwatch: watching (' in text
            if up and ipc and lives.ready and settled:
                return
            if time.monotonic() > deadline:
                raise Aborted('tor_not_ready', f'the {node.name} node did not get ready')
            time.sleep(0.1)

    def check_sender(self) -> None:
        if self.worker is not None and not self.worker.alive():
            raise Aborted('worker_ended', 'the engine worker ended')
        if not self.worker_embedded and self.s_node is not None and not self.s_node.alive():
            raise Aborted('node_ended', 'the S node ended')

    def wait_ready(self, lives_before: int) -> float:
        """Wait for a Tor life of S after `lives_before` to be ready; when."""
        assert self.lives is not None
        deadline = time.monotonic() + self.ready_timeout
        while True:
            lives, ready = self.lives.poll()
            if lives > lives_before and ready:
                return time.monotonic()
            self.check_sender()
            if time.monotonic() > deadline:
                raise Aborted('tor_not_ready', 'Tor did not get ready again')
            time.sleep(0.05)

    def processes(self) -> list:
        out = []
        for node in (self.s_node, self.f_node):
            if node is not None and node.alive():
                out.append(node.proc)
        if self.worker is not None and self.worker.alive():
            out.append(self.worker.proc)
        return out

    def loopback_check(self) -> None:
        """Every process this run started now (and their children, the Tor
        helpers among them) is noted; in a dry run, each of their sockets
        must be on loopback, and a check that cannot run stops the run
        (loopback_refusal)."""
        pids = [p.pid for p in self.processes()]
        if not pids:
            return
        tree = descendants(pids)
        if tree is None:
            if self.mode == 'dry':
                raise Aborted('loopback_check_failed',
                              'ps failed: the loopback check could not run')
            tree = pids
        self.started_pids.update(tree)
        if self.mode != 'dry':
            return
        lsof = tool('lsof')
        if not lsof:
            raise Aborted('loopback_check_failed', 'lsof is gone: the loopback check could not run')
        try:
            got = subprocess.run([lsof, '-nP', '-a', '-p', ','.join(map(str, tree)), '-i'],
                                 capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            raise Aborted('loopback_check_failed', 'lsof failed: the loopback check could not run')
        seen, why, message = loopback_refusal(got.returncode, got.stdout, len(tree))
        self.lsof_checks += 1
        self.lsof_sockets += seen
        if why:
            raise Aborted(why, message)

    def write_netwatch(self, name: str) -> None:
        """A netwatch lab file afresh: one lab network up (a node reads a
        shorter file from its start)."""
        path = self.lab / name
        path.unlink(missing_ok=True)
        with open_private(path) as f:
            f.write(f'up {LAB_NETWORK}\n'.encode())

    def setup(self) -> None:
        lab = self.lab
        lab.mkdir(mode=0o700, parents=False)
        for d in ('home', 'logs', 'raw', 'tor-registry'):
            (lab / d).mkdir(mode=0o700)
        self.out = Out(lab / 'd1-runs.jsonl')
        self.out.write({
            'type': 'meta', 'v': HARNESS_VERSION, 'mode': self.mode, 'cases': list(self.cases),
            'n': {c: self.n[c] for c in self.cases}, 'block': self.block,
            'patched': list(self.patched),
            'intervals': {c: self.intervals[c] for c in self.cases}, 'sim': self.sim,
            'er_pause_s': float(self.args.er_pause_s), 'send_timeout_s': self.send_timeout,
            'minute': minute_of_day()})
        taken: set = set()
        ports = [free_port(taken) for _ in range(4)]
        node_bin = self.bin_dir / 'raven-node'
        self.s_node = Node('S', lab / 's', node_bin, lab / 'logs' / 's.node.log', *ports[:2])
        self.f_node = Node('F', lab / 'f', node_bin, lab / 'logs' / 'f.node.log', *ports[2:])
        self.stages = Stages(lab / 'raw' / 's-stages.jsonl')
        address = {}
        for node in (self.s_node, self.f_node):
            node.profile.mkdir(mode=0o700)
            out = self.ash(node.profile, 'init')
            m = re.search(r'^address=(\S+)', out.stdout, re.M)
            if out.returncode != 0 or not m:
                raise Aborted('setup_failed', f'ash init failed for {node.name}')
            address[node.name] = m.group(1)
            if self.ash(node.profile, 'prekey', 'publish').returncode != 0:
                raise Aborted('setup_failed', f'ash prekey publish failed for {node.name}')
        self.write_netwatch('f.netwatch')
        self.f_node.start(self.guard_env(friend_env(self.common, lab), 'base', True))
        self.start_sender('base', embedded=False, worker=False)
        self.node_up(self.f_node)
        cards, fps = {}, {}
        for node in (self.s_node, self.f_node):
            cards[node.name] = self.onion_card(node)
            m = re.search(r'fingerprint\s+(\S+)', self.ash(node.profile, 'whoami').stdout)
            if not m:
                raise Aborted('setup_failed', f'no fingerprint for {node.name}')
            fps[node.name] = m.group(1)
        for node, other, tag in ((self.s_node, 'F', 'friend'), (self.f_node, 'S', 'sender')):
            r = self.ash(node.profile, 'contact', 'add', '--card', cards[other], '--petname',
                         tag.capitalize(), '--tag', tag, '--verify-fp', fps[other])
            if r.returncode != 0:
                raise Aborted('setup_failed', f'{node.name} could not add {other}')
        self.start_worker('base')
        assert self.worker is not None
        listed = self.worker.call('contacts.list')
        contacts = (listed.get('result') or {}).get('contacts') or []
        if len(contacts) != 1 or contacts[0].get('verified') is not True:
            raise Aborted('setup_failed', 'S does not hold F as one verified contact')
        self.f_address = str(contacts[0].get('address', ''))
        if self.f_address != address['F']:
            raise Aborted('setup_failed', 'the engine names F by another address')
        self.warm_built = self.contacts_warm_built()
        # The first message sets the session up over Tor (PairInit): never
        # a measured run.
        self.stages.mark()
        res = self.worker.send(self.f_address, 'd1 setup', max(self.send_timeout, 180.0))
        self.setup_sends += 1
        if res['state'] != 'delivered' or res['carrier'] != 'onion':
            raise Aborted('setup_failed', 'the first message did not arrive over Tor')
        time.sleep(STAGE_SETTLE_S)
        self.stages.mark()
        self.loopback_check()
        say(f"setup: S and F are friends over Tor only; the first message arrived in "
            f"{res['d1_ms']} ms")

    def onion_card(self, node: Node) -> str:
        deadline = time.monotonic() + 90
        while True:
            out = self.ash(node.profile, 'whoami', '--card').stdout
            card = next((l for l in out.splitlines() if l.startswith('raven-card/')), '')
            if ' onion=' in card:
                for other in (' lan=', ' inet=', ' p2p=', ' via=', ' relay='):
                    if other in card:
                        raise Aborted('setup_failed', 'a card names more than the onion service')
                return card
            if time.monotonic() > deadline:
                raise Aborted('setup_failed', f'no onion service in the card of {node.name}')
            time.sleep(0.5)

    def contacts_warm_built(self) -> bool:
        assert self.worker is not None
        got = self.worker.call('contacts.warm', {'address': self.f_address, 'why': 'typing'})
        err = got.get('error') or {}
        return not (err.get('code') == 'BAD_REQUEST'
                    and str(err.get('detail', '')).startswith('unknown op'))

    def stop_sender(self) -> None:
        if self.worker is not None:
            if self.worker_embedded and self.worker.alive():
                try:
                    self.worker.call('node.stop', timeout=120)
                except Aborted:
                    pass
            self.worker.stop()
            self.worker = None
        if self.s_node is not None:
            self.s_node.stop()

    def start_worker(self, arm: str) -> None:
        assert self.s_node is not None
        env = worker_env(self.arm_env, self.s_node.profile, self.lab, False)
        self.worker = Worker(self.engine, self.guard_env(env, arm, False),
                             self.lab / 'logs' / 's.engine.log', self.mode == 'real')

    def start_sender(self, arm: str, embedded: bool, worker: bool = True) -> None:
        """S for a block: any S before it stopped, then its node (or the
        embedded node in its engine worker) started with the environment of
        `arm`, and its engine worker."""
        self.stop_sender()
        assert self.s_node is not None and self.stages is not None
        self.stages.mark()
        self.arm_env = self.guard_env(sender_env(self.common, self.lab, arm, self.patched), arm,
                                      False)
        self.write_netwatch('s.netwatch')
        self.worker_embedded = embedded
        if embedded:
            assert self.embedded is not None
            log = self.s_node.profile / EMBEDDED_LOG
            offset = log.stat().st_size if log.exists() else 0
            env = worker_env(self.arm_env, self.s_node.profile, self.lab, True)
            self.worker = Worker(self.embedded, self.guard_env(env, arm, False),
                                 self.lab / 'logs' / 's.embedded.log', self.mode == 'real')
            self.worker.call('settings.set', {'receive': False})
            st = self.worker.call('node.start', timeout=240)
            if not st.get('ok') or (st.get('result') or {}).get('embedded') is not True:
                raise Aborted('setup_failed', 'the embedded node did not start in the worker')
            self.lives = Lives(log, offset)
            self.wait_ready(0)
        else:
            self.s_node.start(self.arm_env)
            self.lives = Lives(self.s_node.log_path, self.s_node.mark)
            self.node_up(self.s_node)
            if worker:
                self.start_worker(arm)
        self.stages.mark()
        self.prev_start = self.prev_end = None
        self.loopback_check()

    def idle_until(self, at: float) -> None:
        assert self.worker is not None
        left = at - time.monotonic()
        if left > 0:
            self.worker.idle(left)

    def one_run(self, case: str, variant: str, arm: str, block_no: int, index: int,
                discard: str | None) -> dict:
        assert self.worker is not None and self.lives is not None and self.stages is not None
        now = time.monotonic()
        if case in SCHEDULED and self.prev_start is not None and self.prev_end is not None:
            send_at = max(self.prev_start + self.intervals[case], self.prev_end + MIN_GAP_S)
        else:
            send_at = now if self.prev_end is None else max(now, self.prev_end + MIN_GAP_S)
        ready_wait_ms = None
        if case == 'PW':
            self.idle_until(send_at - PW_WARM_BEFORE_S)
            got = self.worker.call('contacts.warm', {'address': self.f_address, 'why': 'typing'})
            if not got.get('ok'):
                raise Aborted('harness_error', 'contacts.warm was refused')
            if (got.get('result') or {}).get('warming') is not True and discard is None:
                # No warm up started (a shut gate, Tor not ready): no
                # prewarmed send.
                discard = 'not_warmed'
        self.idle_until(send_at)
        if case == 'CN':
            lives, _ = self.lives.poll()
            woke = time.monotonic()
            with open_private(self.lab / 's.netwatch') as f:
                f.write(b'wake\n')
            ready_at = self.wait_ready(lives)
            ready_wait_ms = max(0, int(round((ready_at - woke) * 1000)))
            if CN_AFTER_READY_S[variant]:
                self.worker.idle(CN_AFTER_READY_S[variant])
        if case == 'ER':
            if not self.worker.call('node.pause', timeout=120).get('ok'):
                raise Aborted('harness_error', 'node.pause was refused')
            self.worker.idle(float(self.args.er_pause_s))
            if not self.worker.call('node.resume', timeout=240).get('ok'):
                raise Aborted('harness_error', 'node.resume was refused')
        self.check_sender()
        self.stages.mark()
        self.seq += 1
        start = time.monotonic()
        res = self.worker.send(self.f_address, f'd1 probe {self.seq}', self.send_timeout)
        end = time.monotonic()
        time.sleep(STAGE_SETTLE_S)
        dials = self.stages.since_mark()
        lives, _ = self.lives.poll()
        self.prev_start, self.prev_end = start, end
        # Once more after each run: every socket still on loopback.
        self.loopback_check()
        if discard is None and res['carrier'] is not None and res['carrier'] != 'onion':
            discard = 'carrier'
        rec = {
            'type': 'run', 'v': HARNESS_VERSION, 'mode': self.mode, 'case': case,
            'variant': variant, 'arm': arm, 'block': block_no, 'run': index, 'seq': self.seq,
            'discard': discard, 'minute': minute_of_day(), 'outcome': res['outcome'],
            'state': res['state'], 'carrier': res['carrier'], 'd1_ms': res['d1_ms'],
            'd1_ui_ms': res['d1_ui_ms'], 'd1_peer_ms': None,
            'send_call_ms': res['send_call_ms'], 'ready_wait_ms': ready_wait_ms,
            'dials': dials, 'links_opened': links_opened(dials), 'tor_life': lives,
        }
        assert self.out is not None
        self.out.write(rec)
        if rec['d1_ms'] is not None:
            shown = f"{rec['d1_ms']} ms"
        elif rec['d1_ui_ms'] is not None:
            shown = f"its receipt after {rec['d1_ui_ms']} ms"
        else:
            shown = 'no receipt'
        if res.get('error'):
            shown += f" (the send was refused: {res['error']})"
        say(f"{case} {variant} {arm} block {block_no} run {index}: {rec['outcome']}, {shown}, "
            f"{len(dials)} dials" + (f", discarded ({discard})" if discard else ''))
        return rec

    def skip(self, case: str, variant: str, why: str) -> None:
        assert self.out is not None
        self.out.write({'type': 'skip', 'v': HARNESS_VERSION, 'case': case, 'variant': variant,
                        'why': why})
        say(f'{case} {variant}: skipped ({SKIP_WHY[why]})')

    def measure(self) -> list:
        runs = []
        for case in self.cases:
            spec = CASES[case]
            if case == 'ER' and self.embedded is None:
                self.skip(case, 'plain', 'no_embedded_engine')
                continue
            for variant in spec['variants']:
                if case == 'PW' and not self.warm_built:
                    self.skip(case, variant, 'no_contacts_warm')
                    continue
                if case == 'CI' and variant == 'keep_warm':
                    self.skip(case, variant, 'no_keep_warm')
                    continue
                for arm, block_no, count in abab(spec['arms'], self.n[case], self.block):
                    self.start_sender(arm, embedded=(case == 'ER'))
                    for index in range(count + 1):
                        discard = None
                        if index == 0:
                            discard = 'priming' if case == 'WL' else 'restart'
                        runs.append(self.one_run(case, variant, arm, block_no, index, discard))
        return runs

    def finish(self, runs: list) -> None:
        assert self.out is not None and self.stages is not None
        self.stages.mark()
        discards: dict = {}
        for r in runs:
            if r['discard']:
                discards[r['discard']] = discards.get(r['discard'], 0) + 1
        self.out.write({
            'type': 'end', 'v': HARNESS_VERSION, 'runs': len(runs),
            'counted': sum(1 for r in runs if not r['discard']), 'discards': discards,
            'unattributed_dials': self.stages.unattributed, 'setup_sends': self.setup_sends,
            'loopback_checks': self.lsof_checks, 'loopback_sockets': self.lsof_sockets,
            'elapsed_s': round(time.monotonic() - self.t0, 1)})

    def stop_all(self) -> None:
        try:
            self.stop_sender()
        finally:
            if self.f_node is not None:
                self.f_node.stop()

    def lingering(self) -> int:
        """Processes this run started that are still there (counted, never
        signalled)."""
        ps = tool('ps')
        if not self.started_pids or not ps:
            return 0
        try:
            out = subprocess.run([ps, '-A', '-o', 'pid='], capture_output=True, text=True,
                                 timeout=20).stdout
        except (OSError, subprocess.TimeoutExpired):
            return 0
        alive = {int(x) for x in out.split() if x.isdigit()}
        return len((self.started_pids & alive) - {os.getpid()})

    def tidy(self) -> None:
        """A run that ended well keeps only its records and the analysis."""
        for name in ('s', 'f', 'home', 'tor-registry', 'logs', 'raw'):
            p = self.lab / name
            if p.is_dir():
                shutil.rmtree(p)
        for name in ('s.netwatch', 'f.netwatch'):
            (self.lab / name).unlink(missing_ok=True)
        for profile in ('s', 'f'):
            sock = node_socket_path(self.lab / profile)
            if sock.parent != self.lab / profile:
                # Outside the lab (the socket path limit): the socket of
                # this run's node and its lock, if the node left them.
                if sock.is_socket():
                    sock.unlink()
                lock = sock.with_name(sock.name + '.lock')
                if lock.is_file():
                    lock.unlink()


def parse_counts(items: list, what: str, cast) -> dict:
    out = {}
    for item in items or []:
        for part in item.split(','):
            key, sep, value = part.partition('=')
            key = key.strip().upper()
            if not sep or key not in CASE_ORDER:
                raise Refused(f'{what} takes CASE=VALUE with a case of {", ".join(CASE_ORDER)}')
            try:
                out[key] = cast(value)
            except ValueError:
                raise Refused(f'{what} {key} needs a number')
    return out


def checked_args(args):
    """The run arguments as a Run takes them, or Refused: first of all the
    real mode without its Tor helper, before anything else is looked at or
    built."""
    if args.real_tor and not args.tor_helper:
        raise Refused('the real mode needs --tor-helper, a debug raven-tor-helper')
    cases = [c.strip().upper() for c in args.cases.split(',') if c.strip()]
    if not cases or any(c not in CASE_ORDER for c in cases) or len(set(cases)) != len(cases):
        raise Refused('--cases takes a list of ' + ', '.join(CASE_ORDER))
    args.cases = tuple(c for c in CASE_ORDER if c in cases)
    n = {c: CASES[c]['n'] for c in CASE_ORDER}
    if args.n_all is not None:
        n = {c: args.n_all for c in CASE_ORDER}
    n.update(parse_counts(args.n, '--n', int))
    if any(v < 1 or v > 1000 for v in n.values()):
        raise Refused('--n takes 1 to 1000 runs per arm')
    args.n = n
    args.interval = parse_counts(args.interval, '--interval', float)
    patched = tuple(p.strip().upper() for p in args.patched.split(',') if p.strip())
    if not patched or any(p not in DIALER_SIDE for p in patched):
        raise Refused('--patched takes Stage A switches of ' + ', '.join(DIALER_SIDE)
                      + ' (WARM_LINK needs both ends patched; F keeps base)')
    args.patched = tuple(k for k in DIALER_SIDE if k in patched)
    if args.block < 1:
        raise Refused('--block takes 1 or more')
    if args.send_timeout_s is not None and not 0 < args.send_timeout_s <= 3600:
        raise Refused('--send-timeout-s takes more than 0 and at most 3600 s')
    if not 0 <= args.er_pause_s <= 3600:
        raise Refused('--er-pause-s takes 0 to 3600 s')
    return args


def run_main(args) -> int:
    run = Run(checked_args(args), dict(os.environ))
    why = run.refusal()
    if why:
        raise Refused(why)
    run.environments()
    say(f'D1 harness, {run.mode} mode, lab {run.lab}')
    ok = False
    runs: list = []
    why_aborted = ''
    try:
        run.setup()
        runs = run.measure()
        run.finish(runs)
        ok = True
    except KeyboardInterrupt:
        why_aborted = 'interrupted'
        say('interrupted')
    except Aborted as e:
        why_aborted = e.why
        say(f'aborted: {e}')
    except Exception as e:  # anything else: the record says so, the run stops
        why_aborted = 'harness_error'
        say(f'aborted: the harness failed ({type(e).__name__})')
        raise
    finally:
        if why_aborted and run.out is not None:
            run.out.write({'type': 'abort', 'v': HARNESS_VERSION, 'why': why_aborted})
        run.stop_all()
        left = run.lingering()
        if left:
            say(f'{left} processes this run started are still running')
        if run.out is not None:
            run.out.close()
    path = run.lab / 'd1-runs.jsonl'
    text = analyze(read_records([path]) if path.exists() else [])
    write_private(run.lab / 'd1-analysis.txt', text)
    print(text, end='')
    if ok and not args.keep_lab:
        run.tidy()
        say('the profiles, node logs and the Tor registry are removed; d1-runs.jsonl and '
            'd1-analysis.txt are kept')
    elif not ok:
        say('the lab folder keeps the profiles and logs for a look; remove it when done')
    return 0 if ok else 1


def write_private(path: Path, text: str) -> None:
    """`path` written afresh with `text`, 0600."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(text)
    os.chmod(path, 0o600)


def analyze_main(args) -> int:
    ins = {os.path.realpath(f) for f in args.files}
    if args.out and os.path.realpath(args.out) in ins:
        raise Refused('--out names one of the run files: name another file')
    text = analyze(read_records(args.files))
    if args.out:
        write_private(Path(args.out), text)
    print(text, end='')
    return 0


# ── Self test (no build, no process, no network) ────────────────────────────


PROSE_EXEMPT = re.compile(r"^(--?[A-Za-z0-9][\w-]*|[\w./=:-]*[/_.=:][\w./=:-]*|raven-node|"
                          r"raven-tor-helper|tor-loopback-helper|tor-embedded|raven-client|"
                          r"locked-file|lab-\d+|d1-[a-z.]+)[,.;:)\]]*$")


def prose_refusal(text: str) -> str:
    """Why `text` is not plain prose for the CLI (no apostrophe, no dash; a
    hyphen only inside a flag, a command, a file or a variable name)."""
    for bad in ("'", '\u2019', '\u2013', '\u2014'):
        if bad in text:
            return f'it holds {bad!r}'
    for token in text.split():
        token = token.strip('([')
        if '-' in token and not PROSE_EXEMPT.match(token):
            return f'a hyphen in {token!r}'
    return ''


def message_texts(source: str) -> list:
    """The literal text of every message this script prints, raises or
    refuses with: the arguments of say, print, check, Refused and Aborted,
    the analysis lines, argparse help and what each refusal check returns."""
    import ast
    tree = ast.parse(source)
    nodes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if ((isinstance(f, ast.Name) and f.id in ('say', 'print', 'check', 'Refused',
                                                       'Aborted'))
                    or (isinstance(f, ast.Attribute) and f.attr == 'append'
                        and isinstance(f.value, ast.Name) and f.value.id == 'lines')):
                nodes.extend(node.args)
            nodes.extend(k.value for k in node.keywords if k.arg in ('help', 'description'))
        elif isinstance(node, ast.FunctionDef) and node.name.endswith('refusal'):
            nodes.extend(r.value for r in ast.walk(node)
                         if isinstance(r, ast.Return) and r.value is not None)
    out = []
    for n in nodes:
        out.extend(c.value for c in ast.walk(n)
                   if isinstance(c, ast.Constant) and isinstance(c.value, str))
    return out


def self_test() -> int:
    results = []

    def check(name: str, ok: bool, detail: str = '') -> None:
        results.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f'  {detail}' if detail else ''))

    # The claim rule: qci_check.py's numbers.
    ranks = {(n, q): upper_rank(n, q) for n in (28, 29, 30, 58, 59, 60) for q in (0.5, 0.9, 0.95)}
    ivs = {(n, q): rank_interval(n, q) for n in (30, 60) for q in (0.5, 0.9)}
    check('claim_ranks',
          ranks[(30, 0.5)] == 20 and ranks[(30, 0.9)] == 30 and ranks[(60, 0.5)] == 37
          and ranks[(60, 0.9)] == 59 and ranks[(28, 0.9)] is None and ranks[(29, 0.9)] == 29
          and ranks[(58, 0.95)] is None and ranks[(59, 0.95)] == 59
          and ivs[(30, 0.5)] == (10, 21) and ivs[(30, 0.9)] == (22, 30)
          and ivs[(60, 0.5)] == (22, 38) and ivs[(60, 0.9)] == (50, 59)
          and upper_rank_min_n(0.9) == 29 and upper_rank_min_n(0.95) == 59,
          f'upper 30: {ranks[(30, 0.5)]} {ranks[(30, 0.9)]}, 60: {ranks[(60, 0.5)]} '
          f'{ranks[(60, 0.9)]}; intervals {ivs[(30, 0.5)]} {ivs[(30, 0.9)]} {ivs[(60, 0.5)]} '
          f'{ivs[(60, 0.9)]}')
    under = [500.0] * 20 + [1500.0] * 10
    short = [500.0] * 19 + [1500.0] * 11
    one_failed = [500.0] * 29 + [math.inf]
    all_fast = [400.0] * 30
    sixty = [600.0] * 37 + [2000.0] * 23
    check('claim_rule',
          claim(under, 0.5)[0] == 'supported' and claim(short, 0.5)[0] == 'not_supported'
          and claim(all_fast, 0.9)[0] == 'supported'
          and claim(one_failed, 0.9)[0] == 'not_supported'
          and claim(one_failed, 0.5)[0] == 'supported'
          and claim(all_fast[:28], 0.9)[0] == 'n_too_small'
          and claim(sixty, 0.5)[:2] == ('supported', 37)
          and claim([600.0] * 36 + [2000.0] * 24, 0.5)[0] == 'not_supported',
          'the 20th of 30 and the 37th of 60 for the median, the largest of 30 for p90; a '
          'failed send counts as over 1 s')

    # The records: fixed words and numbers only.
    dial = {'purpose': 'dial', 'frames': 1, 'ok': True, 'prep_ms': 3, 'connect_ms': 1600,
            'circuit_ms': 1500, 'begin_ms': 100, 'noise_ms': 100, 'hello_ms': 101,
            'write_ms': 1, 'receipt_ms': 100, 'total_ms': 1910}
    good = {'type': 'run', 'v': HARNESS_VERSION, 'mode': 'dry', 'case': 'WC',
            'variant': 'plain', 'arm': 'base', 'block': 1, 'run': 1, 'seq': 3,
            'discard': None, 'minute': 600, 'outcome': 'ok', 'state': 'delivered',
            'carrier': 'onion', 'd1_ms': 812, 'd1_ui_ms': 815, 'd1_peer_ms': None,
            'send_call_ms': 20, 'ready_wait_ms': None, 'dials': [dict(dial)],
            'links_opened': 1, 'tor_life': 1}
    bad_cases = [
        dict(good, note='hello'),                                  # an unknown field
        dict(good, carrier='rvn1qexampleaddressnotreal'),          # free text
        dict(good, carrier='192.0.2.1'),                           # an address
        dict(good, state='a' * 56 + '.onion'),                     # an onion id
        dict(good, dials=[dict(dial, peer='198.51.100.7:7420')]),  # inside a dial
        dict(good, dials=[dict(dial, purpose='to friend')]),
        dict(good, d1_ms='812'),                                   # a number as text
        dict(good, d1_ms=True),
        dict(good, outcome='ok', d1_ms=None),                      # ok without its D1
        dict(good, outcome='queued'),                              # queued with a D1
        {k: v for k, v in good.items() if k != 'tor_life'},        # a field missing
        dict(good, type='note'),
    ]
    refused = [bool(record_refusal(b)) for b in bad_cases]
    check('records', record_refusal(good) == '' and all(refused),
          f'good accepted, {sum(refused)} of {len(bad_cases)} bad ones refused')

    # raven-node's stage lines become dial entries; nothing else does.
    stage_text = json.dumps(dict(dial, purpose='check', frames=0, write_ms=None,
                                 receipt_ms=None))
    parsed = dial_from_stage(json.loads(stage_text))
    warm = dict(dial, prep_ms=None, connect_ms=None, circuit_ms=None, begin_ms=None,
                noise_ms=None, hello_ms=None, write_ms=None)
    check('receipts',
          receipt_outcome(False, 1169, 1154) == ('ok', 1154)
          and receipt_outcome(False, 2154, 1154) == ('ok', 1154)
          and receipt_outcome(True, 1169, 1154) == ('queued', None)
          and receipt_outcome(False, 4000, 121) == ('queued', None),
          'a send that waited, or whose receipt came after its job, is queued')
    check('stage_lines',
          parsed is not None and parsed['purpose'] == 'check'
          and dial_from_stage(dict(dial, onion='x')) is None
          and dial_from_stage(dict(dial, total_ms=-1)) is None
          and links_opened([dial, warm, dict(dial, purpose='check')]) == 2,
          'a dial on a kept link opens no link')

    # The real mode guard: the owner OK, and the mode itself.
    with tempfile.TemporaryDirectory() as tmp:
        dry_args = checked_args(parser().parse_args(
            ['run', '--bin-dir', str(Path(tmp) / 'bin'), '--lab', str(Path(tmp) / 'lab-1')]))
        owner = real_mode_refusal(True, {})
        run_dry = Run(dry_args, {})
        dry_why = run_dry.refusal()
        run_dry.mode = 'real'
        forced = run_dry.refusal()
        run_ok = Run(dry_args, {'RAVEN_D1_OWNER_OK': '1'})
        run_ok.mode = 'real'
        forced_ok = run_ok.refusal()
    check('real_guard',
          real_mode_refusal(False, {}) == ''
          and real_mode_refusal(False, {'RAVEN_D1_OWNER_OK': '1'}) == ''
          and owner != ''
          and real_mode_refusal(True, {'RAVEN_D1_OWNER_OK': '0'}) != ''
          and real_mode_refusal(True, {'RAVEN_D1_OWNER_OK': 'yes'}) != ''
          and real_mode_refusal(True, {'RAVEN_D1_OWNER_OK': '1'}) == ''
          and dry_why not in ('', owner) and forced == owner
          and forced_ok not in ('', owner),
          '--real-tor and RAVEN_D1_OWNER_OK=1, both; a run in the real mode asks for the owner '
          'OK whatever set the mode')

    # --real-tor without --tor-helper: refused (exit 2) before any process
    # environment is built.
    built = []
    real_common_env = common_env

    def counted_env(*a, **k):
        built.append(1)
        return real_common_env(*a, **k)

    with tempfile.TemporaryDirectory() as tmp:
        globals()['common_env'] = counted_env
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = main(['run', '--bin-dir', str(Path(tmp) / 'bin'), '--lab',
                           str(Path(tmp) / 'lab-1'), '--real-tor'])
        except Exception as e:  # the old assert: a crash, no refusal
            rc = type(e).__name__
        finally:
            globals()['common_env'] = real_common_env
        nothing_made = not (Path(tmp) / 'lab-1').exists()
    check('real_needs_helper',
          rc == 2 and not built and nothing_made and '--tor-helper' in err.getvalue(),
          f'exit {rc}, environments built {len(built)}')

    # The environments: nothing of the caller beyond CALLER_KEEP, the dry
    # mode on the loopback helper with the gates closed, Stage A only in the
    # patched arm of S.
    lab = Path('/lab/d1')
    caller = {'PATH': '/usr/bin', 'HOME': '/Users/someone', 'RAVEN_DATA_DIR': '/x/.raven',
              'RAVEN_TOR_HELPER': '/x/raven-tor-helper', 'RAVEN_LAB_TOR_WARM': '1',
              'RAVEN_LAB_ROUTE_HINTS': '1', 'RAVEN_P2P_LISTEN': '/ip4/0.0.0.0/tcp/0',
              'HTTPS_PROXY': 'http://192.0.2.1:3128', 'RAVEN_PEER': '192.0.2.5:7420',
              'RAVEN_LAB_TOR_STAGES': '/x/stages', 'RAVEN_KEYSTORE_BACKEND': 'os'}
    common = common_env(caller, lab, 'dry', dict(SIM_DEFAULTS))
    s_base = sender_env(common, lab, 'base', DEFAULT_PATCHED)
    s_patched = sender_env(common, lab, 'patched', DEFAULT_PATCHED)
    f_env = friend_env(common, lab)
    w_env = worker_env(s_patched, lab / 's', lab, True)
    leaked = sorted(k for k, v in common.items() if caller.get(k) == v and k not in CALLER_KEEP)
    envs_ok = all(dry_env_refusal(e) == '' for e in (common, s_base, s_patched, f_env, w_env))
    stage_ok = (stage_a_refusal(s_base, 'base', DEFAULT_PATCHED, False) == ''
                and stage_a_refusal(s_patched, 'patched', DEFAULT_PATCHED, False) == ''
                and stage_a_refusal(f_env, 'base', DEFAULT_PATCHED, True) == ''
                and stage_a_refusal(s_patched, 'base', DEFAULT_PATCHED, False) != ''
                and stage_a_refusal(dict(s_patched, RAVEN_LAB_TEST_A='0'), 'patched',
                                    DEFAULT_PATCHED, False) != ''
                and s_patched['RAVEN_LAB_TOR_WARM'] == '1' == s_patched['RAVEN_LAB_TOR_HEDGE']
                and all(STAGE_A[k] not in s_patched for k in ('EARLY', 'OPTIMISTIC',
                                                               'WARM_LINK'))
                and all(name not in f_env for name in STAGE_A.values()))
    real = common_env(caller, lab, 'real', None, Path('/b/raven-tor-helper'))
    check('environments',
          not leaked and envs_ok and stage_ok and common['HOME'] == '/lab/d1/home'
          and common['RAVEN_LAB_TOR_LOOPBACK'] == '/lab/d1/tor-registry'
          and common['RAVEN_LAB_TOR_LOOPBACK_LATENCY_MS'] == '50'
          and common['RAVEN_LAB_TOR_LOOPBACK_KEPT_MS'] == '45000'
          and w_env['RAVEN_NODE_MODE'] == 'embedded' and w_env['RAVEN_DATA_DIR'] == '/lab/d1/s'
          and s_base.get('RAVEN_LAB_TOR_STAGES') == '/lab/d1/raw/s-stages.jsonl'
          and 'RAVEN_LAB_TOR_STAGES' not in f_env
          and dry_env_refusal(real) != '' and 'RAVEN_LAB_TOR_LOOPBACK' not in real
          and dry_env_refusal(dict(common, RAVEN_LAB_ROUTE_HINTS='1')) != ''
          and dry_env_refusal(dict(common, RAVEN_LAB_TOR_LOOPBACK='rel/dir')) != '',
          f'leaked={leaked}')

    # The engine worker: only on a lab profile as a run starts it, and only
    # with a debug engine.
    w_real = worker_env(sender_env(real, lab, 'base', DEFAULT_PATCHED), lab / 's', lab, False)
    worker_bad = [
        {k: v for k, v in w_env.items() if k != 'RAVEN_LAB_ERASE_ROOT'},
        dict(w_env, RAVEN_LAB_ERASE_ROOT='lab/d1'),
        dict(w_env, RAVEN_DATA_DIR='/x/.raven'),
        dict(w_env, RAVEN_DATA_DIR='/lab/d1'),
        dict(w_env, RAVEN_DATA_DIR='/lab/d1/../x'),
        dict(w_env, HOME='/Users/someone'),
        dict(w_env, RAVEN_IDENTITY_BACKEND='os'),
        {k: v for k, v in w_env.items() if k != 'RAVEN_CHAT_HISTORY_BACKEND'},
        dict(w_env, RAVEN_LAB_TEST_A='0'),
        dict(w_env, RAVEN_NODE_BIN='/b/raven-node'),
        {k: v for k, v in w_env.items() if k != 'RAVEN_NODE_BIN'},
        dict(w_env, RAVEN_LAB_TOR_LOOPBACK='tor-registry'),
        {k: v for k, v in w_env.items() if k != 'RAVEN_LAB_TOR_LOOPBACK'},
        dict(w_env, RAVEN_TOR_HELPER='/b/raven-tor-helper'),
    ]
    worker_refused = [bool(worker_refusal(e, False)) for e in worker_bad]
    worker_ok = (worker_refusal(w_env, False) == '' and worker_refusal(w_real, True) == ''
                 and worker_refusal(w_env, True) != '' and worker_refusal(w_real, False) != ''
                 and worker_refusal(dict(w_real, RAVEN_TOR_HELPER='raven-tor-helper'), True) != ''
                 and all(worker_refused))
    engines = [engine_refusal(info) for info in (
        {'ok': True, 'result': {'build': 'dev', 'version': '0.1.1'}},
        {'ok': True, 'result': {'build': 'release'}},
        {'ok': True, 'result': {'build': 'Dev'}},
        {'ok': True, 'result': None},
        {'ok': False, 'error': {'code': 'INTERNAL'}},
        {'ok': 'true', 'result': {'build': 'dev'}},
        None)]
    check('engine_worker', worker_ok and engines[0] == '' and all(engines[1:]),
          f'{sum(worker_refused)} of {len(worker_bad)} worker environments refused; a release '
          f'engine: {engines[1]}')

    # Ports: never 7420 to 7427 nor 17420.
    offers = iter([7420, 7423, 7427, 17420, 7421, 52001, 52001, 52002])
    taken: set = set()
    got = [free_port(taken, bind=lambda: next(offers)) for _ in range(2)]
    check('ports', got == [52001, 52002], f'picked {got}')

    # The lab folder.
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / 'home'
        (home / '.raven').mkdir(parents=True)
        tree = Path(tmp) / 'tree'
        (tree / '.git').mkdir(parents=True)
        used = Path(tmp) / 'used'
        used.mkdir()
        prof = Path(tmp) / 'prof'
        prof.mkdir()
        (prof / 'contacts.json').write_text('{}')
        refusals = [lab_refusal(p, home) for p in (
            home, Path(tmp), home / '.raven' / 'lab-1', home / 'raven-try' / 'lab-1',
            home / 'Developer' / 'raven-oss' / 'ui' / 'lab-1', tree / 'lab-1', used,
            prof / 'lab-1')]
        fresh = lab_refusal(Path(tmp) / 'scratch' / 'lab-1', home)
    check('lab_folder', all(refusals) and fresh == '',
          f'{sum(bool(r) for r in refusals)} of {len(refusals)} refused, a new one taken')

    # The blocks: ABAB, each arm its n.
    plan = abab(('base', 'patched'), 60, 10)
    small = abab(('base', 'patched'), 3, 2)
    one = abab(('patched',), 5, 2)
    check('blocks',
          [a for a, _, _ in plan] == ['base', 'patched'] * 6
          and all(c == 10 for _, _, c in plan)
          and small == [('base', 1, 2), ('patched', 2, 2), ('base', 3, 1), ('patched', 4, 1)]
          and one == [('patched', 1, 2), ('patched', 2, 2), ('patched', 3, 1)],
          f'{len(plan)} blocks of 10 for n 60')

    # The case timings around raven-node's and Arti's own times.
    dry = {c: (CASES[c]['dry_interval'] if c != 'CI' else 50.0) for c in CASE_ORDER}
    realt = {c: CASES[c]['interval'] for c in CASE_ORDER}
    check('timings',
          timing_refusal('dry', dry, 45.0) == '' and timing_refusal('real', realt, 600.0) == ''
          and timing_refusal('dry', dry, 34.0) != ''
          and timing_refusal('dry', dict(dry, CI=40.0), 45.0) != ''
          and timing_refusal('dry', dict(dry, WL=25.0), 45.0) != ''
          and timing_refusal('dry', dict(dry, WC=25.0), 45.0) != '',
          'WL under WARM_IDLE, WC past the listener and inside the kept time, CI past it')

    # The analysis of a small run file.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'd1-runs.jsonl'
        out = Out(path)
        out.write({'type': 'meta', 'v': HARNESS_VERSION, 'mode': 'dry', 'cases': ['AA', 'WC'],
                   'n': {'AA': 30, 'WC': 30}, 'block': 10, 'patched': ['WARM', 'HEDGE'],
                   'intervals': {'AA': 35.0, 'WC': 35.0}, 'sim': dict(SIM_DEFAULTS),
                   'er_pause_s': 5.0, 'send_timeout_s': 120.0, 'minute': 0})
        seq = 0
        for case, arm, values in (('AA', 'base', [700 + i for i in range(30)]),
                                  ('AA', 'base_again', [705 + i for i in range(30)]),
                                  ('WC', 'base', [900] * 19 + [1200] * 11),
                                  ('WC', 'patched', [400] * 29 + [None])):
            for i, v in enumerate([650] + values):
                seq += 1
                rec = dict(good, case=case, arm=arm, seq=seq, run=i % 11,
                           discard='restart' if i == 0 else None)
                if v is None:
                    rec.update(outcome='failed', state='failed', carrier=None, d1_ms=None,
                               d1_ui_ms=None, dials=[])
                else:
                    rec.update(d1_ms=v, d1_ui_ms=v + 3)
                out.write(rec)
        out.write(dict(good, case='PW', arm='patched', seq=seq + 1, discard='not_warmed'))
        out.write({'type': 'skip', 'v': HARNESS_VERSION, 'case': 'PW', 'variant': 'plain',
                   'why': 'no_contacts_warm'})
        out.close()
        text = analyze(read_records([path]))
        bad_file = Path(tmp) / 'bad.jsonl'
        bad_file.write_text(json.dumps(dict(good, carrier='192.0.2.1')) + '\n')
        try:
            read_records([bad_file])
            bad_refused = False
        except Refused:
            bad_refused = True
    wanted = ('AA plain base: n 30 (ok 30, queued 0, failed 0), discarded 1',
              'median under 1 s: supported (rank 20 of 30 is 719 ms)',
              'p90 under 1 s: supported (rank 30 of 30 is 729 ms)',
              'A/A: medians 714 ms and 719 ms; they agree',
              'WC plain base: n 30',
              'median under 1 s: not supported (rank 20 of 30 is 1200 ms)',
              'WC plain patched: n 30 (ok 29, queued 0, failed 1)',
              'p90 under 1 s: not supported (rank 30 of 30 is failed or queued)',
              'PW plain patched: n 0 (ok 0, queued 0, failed 0), discarded 1',
              'discarded 5 (not_warmed 1, restart 4)',
              'skipped: PW plain')
    missing = [w for w in wanted if w not in text]
    check('analysis', not missing and bad_refused and not prose_refusal(text),
          f'missing={missing}' if missing else 'a file with an address is refused')

    # The node log counts and the loopback check.
    lives = Lives(Path('/nonexistent'), 0)
    lives.feed(b'raven-node onion: Tor: starting\nraven-node onion: Tor: starting (15 %, '
               b'x, 0 s)\nraven-node onion: Tor: ready (bootstrap 2 s)\n')
    first = (lives.lives, lives.ready)
    lives.feed(b'raven-node onion: Tor helper ended after 9 s (woke)\n'
               b'raven-node onion: Tor: starting\n')
    second = (lives.lives, lives.ready)
    lsof_ok = ('COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n'
               'raven-nod 1 u 9u IPv4 0x1 0t0 TCP 127.0.0.1:50001 (LISTEN)\n'
               'raven-nod 1 u 10u IPv4 0x2 0t0 TCP 127.0.0.1:50002->127.0.0.1:50003 '
               '(ESTABLISHED)\n'
               'raven-nod 1 u 11u IPv6 0x3 0t0 TCP [::1]:50004 (LISTEN)\n')
    lsof_bad = (lsof_ok + 'raven-nod 1 u 12u IPv4 0x4 0t0 TCP 127.0.0.1:50005->'
                '198.51.100.7:443 (SYN_SENT)\n'
                'raven-nod 1 u 13u IPv4 0x5 0t0 UDP *:5353\n')
    check('node_logs',
          first == (1, True) and second == (2, False) and outside_loopback(lsof_ok) == (3, 0)
          and outside_loopback(lsof_bad) == (5, 2)
          and ipaddress.ip_interface(LAB_NETWORK) in [
              ipaddress.ip_interface(LAB_NETWORK)]
          and ipaddress.ip_interface(LAB_NETWORK).network.subnet_of(
              ipaddress.ip_network('192.0.2.0/24')),
          'Tor lives counted, sockets past loopback found, the lab network a documentation '
          'range')

    # The loopback check's decision on an lsof listing, and its tools.
    header = lsof_ok.splitlines()[0] + '\n'
    decisions = (loopback_refusal(0, lsof_ok, 3), loopback_refusal(0, lsof_bad, 3),
                 loopback_refusal(1, '', 3), loopback_refusal(1, lsof_ok, 3),
                 loopback_refusal(0, header, 3), loopback_refusal(0, '', 2))
    words = [d[1] for d in decisions]
    tools_ok = (tools_refusal('dry', lambda name: f'/usr/sbin/{name}') == ''
                and tools_refusal('dry', lambda name: None) != ''
                and 'ps' in tools_refusal('dry', lambda name: None if name == 'ps' else '/x')
                and 'lsof' in tools_refusal('dry', lambda name: None if name == 'lsof' else '/x')
                and tools_refusal('real', lambda name: None) == '')
    check('loopback_decision',
          words == ['', 'network_outside_loopback', 'loopback_check_failed',
                    'loopback_check_failed', 'loopback_check_failed', 'loopback_check_failed']
          and decisions[0][0] == 3 and all(w in ABORT_WHY for w in words if w) and tools_ok,
          'past loopback, a failed lsof and no socket while the lab runs all stop the run; '
          'the dry mode needs lsof and ps')

    # The build checks: markers across a chunk boundary.
    with tempfile.TemporaryDirectory() as tmp:
        blob = Path(tmp) / 'blob'
        blob.write_bytes(b'x' * ((8 << 20) - 5) + NODE_DEBUG + b'y' * 100)
        has = file_has(blob, (NODE_DEBUG, OVERFLOW_CHECK))
    check('build_markers', has == {NODE_DEBUG: True, OVERFLOW_CHECK: False},
          'a marker across two chunks is found')

    # The build folder: debug builds with this tree's lab hooks only, and no
    # Tor helper next to raven-node in the dry mode.
    with tempfile.TemporaryDirectory() as tmp:
        b = Path(tmp) / 'bin'
        b.mkdir()

        def put(name: str, data: bytes) -> Path:
            (b / name).write_bytes(b'\0' + data + b'\0')
            return b / name

        node_ok = NODE_DEBUG + b'.' + b'.'.join(WARM_MODEL)
        put('raven-node', node_ok)
        put('ash', DEBUG_OBJECTS + b'.' + OVERFLOW_CHECK)
        engine = put(engine_name(), DEBUG_OBJECTS)
        emb = put('embedded.lib', b'.'.join((DEBUG_OBJECTS, ARTI_IN_PROCESS) + WARM_MODEL))
        helper = Path(tmp) / 'raven-tor-helper'
        helper.write_bytes(DEBUG_OBJECTS + OVERFLOW_CHECK)
        outcome = {'dry': build_refusal(b, 'dry', engine, emb, None),
                   'real': build_refusal(b, 'real', engine, None, helper),
                   'real_no_helper': build_refusal(b, 'real', engine, None, None)}
        put('raven-tor-helper', DEBUG_OBJECTS + OVERFLOW_CHECK)
        outcome['helper_beside'] = build_refusal(b, 'dry', engine, None, None)
        (b / 'raven-tor-helper').unlink()
        for name, data in (('node_release', b'.'.join(WARM_MODEL)),
                           ('node_release_bare', b'release'),
                           ('node_no_model', NODE_DEBUG)):
            put('raven-node', data)
            outcome[name] = build_refusal(b, 'dry', engine, None, None)
        outcome['real_no_model'] = build_refusal(b, 'real', engine, None, helper)
        put('raven-node', node_ok)
        put('ash', DEBUG_OBJECTS)
        outcome['ash_release'] = build_refusal(b, 'dry', engine, None, None)
        put('ash', DEBUG_OBJECTS + b'.' + OVERFLOW_CHECK)
        put('embedded.lib', b'.'.join((DEBUG_OBJECTS,) + WARM_MODEL))
        outcome['embedded_no_tor'] = build_refusal(b, 'dry', engine, emb, None)
        helper.write_bytes(DEBUG_OBJECTS)
        outcome['helper_release'] = build_refusal(b, 'real', engine, None, helper)
        engine.unlink()
        outcome['no_engine'] = build_refusal(b, 'dry', engine, None, None)
    wanted_words = {'dry': '', 'real': '', 'real_no_model': '',
                    'real_no_helper': 'needs --tor-helper',
                    'helper_beside': 'never has raven-tor-helper',
                    'node_release': 'raven-node is not a debug build',
                    'node_release_bare': 'raven-node is not a debug build',
                    'node_no_model': 'raven-node has no warm circuit model',
                    'ash_release': 'ash is not a debug build',
                    'embedded_no_tor': 'has no Tor in process',
                    'helper_release': 'raven-tor-helper is not a debug build',
                    'no_engine': 'is not in the build folder'}
    wrong = sorted(k for k, w in wanted_words.items()
                   if (outcome[k] != '' if not w else w not in outcome[k]))
    check('build_folder', not wrong,
          f'wrong={wrong}' if wrong else f'{len(outcome) - 3} build folders refused, each for '
          'its reason')

    # The words the harness prints.
    messages = message_texts(SCRIPT.read_text(encoding='utf-8'))
    texts = [__doc__ or '', analyze([])] + list(SKIP_WHY.values()) + messages
    prose = [prose_refusal(t) for t in texts]
    check('prose', len(messages) > 100 and not any(prose),
          next((p for p in prose if p), f'{len(messages)} messages, the usage and the analysis'))

    # The gates every process closes: the reviewed set (an owner decision to
    # change), each a release gate that could carry a send past Tor or reach
    # the Internet, and the radios and the custody of mail over the Internet.
    check('closed_gates',
          set(CLOSED_GATES) == {'RAVEN_LAB_ROUTE_HINTS', 'RAVEN_LAB_FRIEND_RELAY',
                                'RAVEN_LAB_PORT_MAP', 'RAVEN_LAB_V6_PINHOLE',
                                'RAVEN_LAB_NAT_CLASS', 'RAVEN_LAB_STUN_DISCOVERY',
                                'RAVEN_LAB_SERVERLESS_PUNCH', 'RAVEN_LAB_NEARBY',
                                'RAVEN_LAB_LAN_BEACON', 'RAVEN_LAB_CUSTODY_WAN'}
          and len(CLOSED_GATES) == len(set(CLOSED_GATES))
          and all(common[k] == '0' for k in CLOSED_GATES),
          f'{len(CLOSED_GATES)} lab switches set to 0 in every process')

    # The Rust tree, when it is next to this script: the stage record's
    # fields, the switch and knob names this harness sets, the release gates
    # it closes, and the node times its cases are placed around.
    crates = SCRIPT.parent.parent / 'node' / 'crates'
    if crates.is_dir():
        stages = (crates / 'raven-node' / 'src' / 'onion' / 'stages.rs').read_text()
        body = stages.split('pub(crate) struct Record {', 1)[-1].split('}', 1)[0]
        fields = set(re.findall(r'pub\(crate\) (\w+):', body))
        names = set()
        for src in crates.rglob('*.rs'):
            names.update(re.findall(r'"(RAVEN_LAB_[A-Z0-9_]+)"', src.read_text(errors='replace')))
        mine = (set(CLOSED_GATES) | set(LOOPBACK_KNOBS) | set(STAGE_A.values())
                | {'RAVEN_LAB_TOR_STAGES', 'RAVEN_LAB_TOR_LOOPBACK', 'RAVEN_LAB_TOR',
                   'RAVEN_LAB_TEST_A', 'RAVEN_LAB_AT_REST', 'RAVEN_LAB_ERASE_ROOT',
                   'RAVEN_LAB_NETWATCH_EVENTS'})
        unknown = sorted(mine - names)
        core = '\n'.join(s.read_text(errors='replace')
                         for s in (crates / 'raven-core' / 'src').rglob('*.rs'))
        gate_names = set(re.findall(r'pub const (\w+_PRODUCTION_ENABLED): bool', core))
        gates_gone = sorted(set(CLOSED_GATE_CONSTS) - gate_names)

        def secs(rel: str, name: str):
            text = (crates / rel).read_text(errors='replace')
            m = re.search(rf'const {name}: Duration = Duration::from_secs\(([0-9 *]+)\);', text)
            if not m:
                return None
            value = 1
            for part in m.group(1).split('*'):
                value *= int(part)
            return float(value)

        times = {'WARM_IDLE': (secs('raven-node/src/onion/warm.rs', 'WARM_IDLE'), WARM_IDLE_S),
                 'IO_TIMEOUT': (secs('raven-node/src/internet_direct.rs', 'IO_TIMEOUT'),
                                LISTENER_IDLE_S),
                 'GROUP_KEPT': (secs('raven-node/src/onion/proto.rs', 'GROUP_KEPT'),
                                ARTI_KEPT_S)}
        moved = sorted(k for k, (rust, here) in times.items() if rust != here)
        check('rust_tree', fields == set(DIAL_KEYS) and not unknown and not gates_gone
              and not moved,
              f'record fields {"match" if fields == set(DIAL_KEYS) else sorted(fields)}; '
              f'unknown names {unknown}; gate names missing {gates_gone}; '
              f'times that moved {moved}')
    else:
        print('SKIP  rust_tree  (no node/crates next to this script)')
    return 0 if all(results) else 1


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='tor_d1_harness.py', description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command')
    r = sub.add_parser('run', help='measure (dry unless --real-tor)')
    r.add_argument('--bin-dir', required=True)
    r.add_argument('--lab', required=True)
    r.add_argument('--engine')
    r.add_argument('--embedded-engine')
    r.add_argument('--cases', default=','.join(CASE_ORDER))
    r.add_argument('--n', action='append', default=[])
    r.add_argument('--n-all', type=int)
    r.add_argument('--block', type=int, default=10)
    r.add_argument('--interval', action='append', default=[])
    r.add_argument('--patched', default=','.join(DEFAULT_PATCHED))
    r.add_argument('--sim-r-ms', type=int, default=SIM_DEFAULTS['r_ms'])
    r.add_argument('--sim-rendezvous-ms', type=int, default=SIM_DEFAULTS['rendezvous_ms'])
    r.add_argument('--sim-kept-s', type=float, default=SIM_DEFAULTS['kept_s'])
    r.add_argument('--sim-ready-ms', type=int, default=SIM_DEFAULTS['ready_ms'])
    r.add_argument('--er-pause-s', type=float, default=5.0)
    r.add_argument('--send-timeout-s', type=float)
    r.add_argument('--keep-lab', action='store_true')
    r.add_argument('--real-tor', action='store_true')
    r.add_argument('--tor-helper')
    a = sub.add_parser('analyze', help='the medians, p90 and the claim rule of run files')
    a.add_argument('files', nargs='+')
    a.add_argument('--out')
    w = sub.add_parser('engine-worker', help='internal: the engine of one profile')
    w.add_argument('--lib', required=True)
    w.add_argument('--real', action='store_true')
    return p


def main(argv: list) -> int:
    if argv == ['--self-test']:
        return self_test()
    p = parser()
    args = p.parse_args(argv)
    try:
        if args.command == 'run':
            return run_main(args)
        if args.command == 'analyze':
            return analyze_main(args)
        if args.command == 'engine-worker':
            return worker_main(args.lib, args.real)
    except Refused as e:
        print(f'refusing: {e}', file=sys.stderr)
        return 2
    p.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
