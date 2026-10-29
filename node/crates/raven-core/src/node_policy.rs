//! Local node policy config (ash writes; raven-node reads). No secrets.
//!
//! `node_policy.json` stays plain: raven-node reads it at start, before any
//! keystore call. Privacy pack PP.6: in a sealed profile the fields that name
//! other machines ([`NodePolicy::p2p_relays`], relay addresses that may be
//! friends' public addresses, [`NodePolicy::relay_external`], this
//! computer's own public names, since Phase 3 P3.16
//! [`NodePolicy::custody_home`], the friends this node collects its mail
//! from, since Phase 4 [`NodePolicy::p2p_proxy`], the network's proxy, and
//! since Phase 6b [`NodePolicy::send_hold`], the friends sending is paused
//! to) live in the sealed sidecar
//! [`POLICY_PEERS_FILE`] (RMS1 kind 19) instead. [`try_load_policy`] merges
//! the sidecar when this process holds the at-rest key (a value still in
//! `node_policy.json`, written before sealing or by an older build since, is
//! the newer and wins); [`save_policy`] writes those fields only to the
//! sidecar and refuses them, retryably, while the key is not loaded;
//! [`seal_peers`] (the migration) moves them over, the sidecar first. A plain
//! profile keeps today's bytes. An older build sees no relays (p2p is gated
//! in release) and, when it saves the policy, writes none: the sidecar stays.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

use crate::at_rest::{self, AtRestError, FileLock, Kind, Mode};
use crate::security_gate::{live, SecGate};

/// The plain policy file in the data dir.
pub const POLICY_FILE: &str = "node_policy.json";
/// The sealed sidecar (privacy pack PP.6): the policy's fields that name
/// other machines, in a sealed profile.
pub const POLICY_PEERS_FILE: &str = "node_policy_peers.rms";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodePolicy {
    /// AUTO: bridge when both radios; user may force on/off.
    #[serde(default = "default_true")]
    pub bridge: bool,
    #[serde(default = "default_true")]
    pub store: bool,
    /// The bridge/BLE message router's same-transport relay (`raven node relay
    /// on|off`). Unrelated to the friend relay ([`Self::relay_offer`]).
    #[serde(default = "default_false")]
    pub relay: bool,
    /// When true, node also acts as chat endpoint (separate from BridgeSubsystem).
    #[serde(default = "default_true")]
    pub endpoint: bool,
    /// AUTO policy marker — ash may set false when user overrides.
    #[serde(default = "default_true")]
    pub auto_policy: bool,
    /// Internet direct listen address (`ip:port`) the service binds when it
    /// starts without `--internet-listen` / `RAVEN_INTERNET_LISTEN` (`raven
    /// node internet on|off`). Empty = off, the default: Internet exposure is
    /// opt-in, like LAN exposure in the installers. Omitted from the file while
    /// empty, so older files and older readers are unaffected.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub internet_listen: String,
    /// libp2p listen setting (`raven node p2p on|off`, P3): a port (every
    /// interface, IPv4 and IPv6, TCP and QUIC) or `IP:PORT`, see
    /// [`crate::p2p_route::normalize_p2p_listen`]. Empty = off, the default.
    /// Read only when the service starts without `--p2p-listen` /
    /// `RAVEN_P2P_LISTEN`. Omitted from the file while empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub p2p_listen: String,
    /// Relays (`/…/p2p/<relay PeerId>` multiaddrs, at most
    /// [`crate::p2p_route::MAX_VIA`]) this node keeps a reservation on. No
    /// relay is compiled in: they come only from here, `--p2p-relay` or
    /// `RAVEN_P2P_RELAYS`. Omitted from the file while empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub p2p_relays: Vec<String>,
    /// HTTPS proxy for relay dials over WSS (Phase 4, RWS1 §8): empty = auto
    /// (the environment, then the system settings), `off`, or
    /// `http://host:port` ([`crate::net_proxy::parse_setting`]). Never
    /// credentials (this file holds no secrets): [`save_policy`] refuses
    /// `user:pass@`, which belongs in `RAVEN_P2P_PROXY` only (the service's
    /// environment; a command line is readable by other local users).
    /// It names another machine, so a sealed profile keeps it in
    /// [`POLICY_PEERS_FILE`] with the relays. Omitted from the file while
    /// empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub p2p_proxy: String,
    /// Router port mapping consent (IPv4) for the p2p port (owner decision
    /// Q8: "ask once at setup"): UPnP-IGD, and NAT-PMP/PCP where the
    /// PORT_MAP gate is open (owner decision O4-11: an existing yes carries
    /// over, the effect on the router is the same). `None` = never asked
    /// (behaves as off: no mapping is attempted), `Some(true)` = on,
    /// `Some(false)` = off. Omitted from the file while unset, so older files
    /// and readers are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upnp: Option<bool>,
    /// An IPv6 pinhole on the router for the p2p port (Phase 4, owner
    /// decision O4-11): its own ask-once question after a [`Self::upnp`]
    /// yes, or `raven node ipv6-pinhole on|off`; asked of the router (PCP)
    /// only where the V6_PINHOLE gate is open. `None` = never asked (off);
    /// a `upnp` yes never implies it. Omitted from the file while unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6_pinhole: Option<bool>,
    /// PeerId rotation (Phase 4, owner decision O4-13: an opt-in privacy
    /// setting, `raven node p2p rotate on|off`): the p2p host uses a new
    /// libp2p key every epoch once every verified contact with a p2p route
    /// can follow it. Acted on only where the PEER_ROTATION gate is open.
    /// `None` = never set (off). A setting like [`Self::v6_pinhole`], so
    /// plain: no contact, PeerId or epoch in it. Omitted from the file while
    /// unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_rotation: Option<bool>,
    /// Auto-reach (`docs/design/2026-10-auto-reach.md` §3.6): ask public STUN
    /// servers which public address they see for this computer (`raven node
    /// stun on|off`). `None` = never set: on wherever the STUN discovery gate
    /// is open (the owner approved the query, 2026-10-28); `Some(false)` =
    /// off. Hide my IP for everyone stops it too ([`Self::stun_allowed`]).
    /// Omitted from the file while unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stun: Option<bool>,
    /// Friend custody (`raven node custody on|off`): hold sealed messages and
    /// ACKs for mutual pinned contacts (`docs/design/2026-10-friend-custody.md`).
    /// Default off; AUTO never sets it; omitted from the file while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub custody: bool,
    /// Multi-hop custody consent (Phase 5, owner decision P5-MH-3): pass
    /// sealed objects on between two friends, and hold forwarded objects for
    /// a friend who registered for them. One flag for both custodian roles.
    /// Effective only together with [`Self::custody`] and where the handoff
    /// gate is open ([`crate::custody_gate::handoff_live`]). Default off;
    /// AUTO never sets it; plain (no friend in it); omitted from the file
    /// while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub custody_handoff: bool,
    /// Friend mailboxes (`raven custody use on|off`, asked once, Phase 3
    /// P3.16): leave sealed copies with the custodians a contact announced,
    /// and collect your own mail from your home custodians. `None` = never
    /// asked (off). AUTO never sets it. Plain (no friend in it). ash writes it
    /// through a setter of its own that keeps the other settings and AUTO. An
    /// older ash that rewrites the file drops it, so custody fails closed to
    /// off. Omitted from the file while unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_use: Option<bool>,
    /// Home custodians picked by hand (`raven custody home @a [@b]`): the
    /// contacts' keys in hex, at most 2. Empty = automatic. It names friends,
    /// so a sealed profile keeps it only in the sealed sidecar
    /// [`POLICY_PEERS_FILE`], like the relays. An older ash that rewrites the
    /// file drops it (a plain profile: back to automatic). Omitted while
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custody_home: Vec<String>,
    /// Hide my IP from every contact (D4, `raven node hide-ip on|off`): route
    /// hints carry no direct address, no hole punching or Identify with
    /// contacts, p2p dials through relays only. LAN links are unaffected.
    /// Omitted from the file while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hide_ip: bool,
    /// Relay for verified contacts with this profile's own relay key (`raven
    /// relay offer on|off`, any-network plan C6; asked once while this
    /// computer is confirmed public). `None` = never asked (off). Unrelated to
    /// the legacy [`Self::relay`] (`raven node relay on|off`: the bridge/BLE
    /// same-transport relay). Omitted from the file while unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_offer: Option<bool>,
    /// Pick relays from the relays contacts offer (C7): `None` = on,
    /// `Some(false)` = only the relays set by hand ([`Self::p2p_relays`]);
    /// see [`Self::relay_auto_on`]. Not [`Self::relay`] either. Omitted from
    /// the file while unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_auto: Option<bool>,
    /// The friend relay's TCP and UDP (QUIC) port; `None` =
    /// [`crate::p2p_route::FRIEND_RELAY_PORT`]. Omitted from the file while
    /// unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_port: Option<u16>,
    /// The friend relay also listens on TCP 443 (contacts whose network lets
    /// only that port out). Omitted from the file while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub relay_also_443: bool,
    /// Addresses friends reach the friend relay at: host and transport with
    /// no `/p2p` (the grammar of [`crate::p2p_route::parse_host_transport`]),
    /// e.g. `/dns4/home.example.net/tcp/7427`. At most
    /// [`MAX_RELAY_EXTERNAL`]. Omitted from the file while empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_external: Vec<String>,
    /// `raven lan off` (Phase 3, D7): no LAN listener, LAN dial or beacon. Omitted while false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lan_off: bool,
    /// `raven lan verified-only on` (Phase 3 P3.C2, cutoff M1): only pinned
    /// (verified) contacts may link on the LAN, inbound or outbound
    /// ([`lan_verified_only`]). A setting like `lan_off`, so plain; read where
    /// it applies, so a change needs no restart. Omitted while false. The
    /// meeting time (`raven lan on --for`) is not here: it says when a
    /// meeting ended, so it is sealed on its own ([`crate::lan_meeting`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lan_verified_only: bool,
    /// The Bluetooth nearby carrier (Phase 5, RNL1; owner decision O5-13:
    /// ask once, `raven nearby enable|disable`): scan for verified contacts
    /// and advertise for the ones with user-started work. Acted on only
    /// where the nearby gate is open
    /// ([`crate::nearby_gate::nearby_live_enabled`]); raven-node creates no
    /// radio object unless it is `Some(true)`. `None` = never asked (off),
    /// and the value [`NodePolicy::fail_closed`] keeps. A setting, so plain:
    /// no contact, token or Bluetooth address in it. Omitted from the file
    /// while unset, so older files and readers are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nearby: Option<bool>,
    /// Nearby also advertises for contacts this node has mail waiting for,
    /// not only for the ones with user-started work (cutoff addendum F11d):
    /// still at most two tokens on air. `None` = off (the default); only the
    /// separate consent `raven nearby background-mail on` turns it on (owner
    /// decision OD-C8, approved 2026-10-28), never `raven nearby enable`.
    /// Acted on only where the nearby gate is open and [`Self::nearby`] is
    /// on. A setting like [`Self::nearby`], so plain. Omitted from the file
    /// while unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nearby_background_mail: Option<bool>,
    /// Learning connectivity (Phase 6a, `raven learning on|off`): reorder
    /// the carriers and routes the static plan allows by this computer's own
    /// delivery outcomes. Acted on only where the learning gate is open
    /// ([`crate::learning::learning_on`]). `None` = on while the gate is
    /// open, `Some(false)` = off (the value [`NodePolicy::fail_closed`]
    /// keeps). A setting, so plain: what was learned lives in its own sealed
    /// store. Omitted from the file while unset, so older files and readers
    /// are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learning: Option<bool>,
    /// Phase 6b R2 (owner default: yes): renew a suspicious session early
    /// on this node's own initiative. Read only while the responses gate is
    /// live ([`Self::security_auto_rekey_on`]). Default on; omitted from the
    /// file while on.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub security_auto_rekey: bool,
    /// Phase 6b RLK1 (OD6b-9): how the LAN and Internet listeners answer a
    /// dialer without a valid knock. Read only while the knock gate is live
    /// ([`Self::silent_to_strangers`]). Default [`SilentMode::Automatic`];
    /// omitted from the file while automatic.
    #[serde(default, skip_serializing_if = "SilentMode::is_automatic")]
    pub security_silent_to_strangers: SilentMode,
    /// Phase 6b Lock v2 (P6.40, OD6b-18): lock on wake from sleep. `None` =
    /// never set: on for a profile with a Raven passphrase that raven-node
    /// cannot read by itself, off otherwise
    /// ([`Self::auto_lock_on_sleep_default`]). Read only while the
    /// local-protection gate is live ([`Self::auto_lock_on_sleep_on`]).
    /// Omitted from the file while unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_lock_on_sleep: Option<bool>,
    /// Phase 6b mesh updates (OD6b-24): also carry verified bundles for
    /// other platforms, for pinned contacts. Read only while the mesh-update
    /// gate is live ([`Self::update_carry_for_friends_on`]). Default off;
    /// omitted from the file while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub update_carry_for_friends: bool,
    /// Phase 6b mesh updates (OD6b-24): serve verified bundles for this
    /// platform to pinned contacts. Read only while the mesh-update gate is
    /// live ([`Self::update_serve_on`]). Default on; omitted from the file
    /// while on.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub update_serve: bool,
    /// Phase 6b (OD6b-10): the LAN listen port this profile picked at
    /// creation (20,000-59,999), in place of
    /// [`crate::paths::DEFAULT_LAN_LISTEN`]'s. This computer's own setting,
    /// so plain (the node binds before any keystore call). Read only while
    /// the random-port gate is live ([`Self::lan_listen_port_chosen`]).
    /// `None` = the default port. Omitted from the file while unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_listen_port: Option<u16>,
    /// Phase 6b design A (P6.31, OD6b-6): "Pause sending to <name> until I
    /// check", the one-key hold the terminal app offers with a security
    /// alert: the contacts' keys in lower-case hex, at most
    /// [`MAX_SEND_HOLD`]. raven-node's outbox worker sends nothing to them
    /// (their messages wait, and their deadline still runs). Only the user
    /// sets or lifts it, never Raven by itself; it is read whatever the
    /// gates, so a hold can always be seen and lifted. It names friends, so
    /// a sealed profile keeps it only in the sealed sidecar
    /// [`POLICY_PEERS_FILE`], like [`Self::custody_home`]. An older ash that
    /// rewrites the file drops it (nothing is held then). Omitted while
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub send_hold: Vec<String>,
}

/// [`NodePolicy::security_silent_to_strangers`] (Phase 6b design B, RLK1):
/// what a listener does with a dialer that sent no valid knock. The knock
/// step defines each mode's exact answer.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SilentMode {
    /// Legacy until every contact's capability floor shows the knock, then
    /// strict on its own; never silent unless the user turns it on.
    #[default]
    Automatic,
    /// Silent to strangers: close without answering message 1.
    On,
    /// Never silent and never strict on its own.
    Off,
}

impl SilentMode {
    /// The default, which the file omits.
    pub fn is_automatic(&self) -> bool {
        *self == SilentMode::Automatic
    }
}

/// [`NodePolicy::relay_external`] holds at most this many addresses.
pub const MAX_RELAY_EXTERNAL: usize = 4;

/// [`NodePolicy::send_hold`] holds at most this many contacts.
pub const MAX_SEND_HOLD: usize = 256;

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn is_true(v: &bool) -> bool {
    *v
}

impl Default for NodePolicy {
    fn default() -> Self {
        Self {
            bridge: true,
            store: true,
            relay: false,
            endpoint: true,
            auto_policy: true,
            internet_listen: String::new(),
            p2p_listen: String::new(),
            p2p_relays: Vec::new(),
            p2p_proxy: String::new(),
            upnp: None,
            v6_pinhole: None,
            peer_rotation: None,
            stun: None,
            custody: false,
            custody_handoff: false,
            custody_use: None,
            custody_home: Vec::new(),
            hide_ip: false,
            relay_offer: None,
            relay_auto: None,
            relay_port: None,
            relay_also_443: false,
            relay_external: Vec::new(),
            lan_off: false,
            lan_verified_only: false,
            nearby: None,
            nearby_background_mail: None,
            learning: None,
            security_auto_rekey: true,
            security_silent_to_strangers: SilentMode::Automatic,
            auto_lock_on_sleep: None,
            update_carry_for_friends: false,
            update_serve: true,
            lan_listen_port: None,
            send_hold: Vec::new(),
        }
    }
}

impl NodePolicy {
    /// May this profile ask public STUN servers for its public address
    /// (auto-reach)? Not when the user turned it off (`raven node stun off`)
    /// or hides its IP from every contact (an address never shared need not
    /// be found). The gate is the caller's
    /// ([`crate::stun_discovery_live_enabled`]).
    pub fn stun_allowed(&self) -> bool {
        self.stun != Some(false) && !self.hide_ip
    }

    /// Applied when `node_policy.json` exists but cannot be read or parsed:
    /// offer no services to other peers (bridge / store / relay off) and drop
    /// the AUTO marker so nothing re-enables them implicitly. The node stays
    /// the user's own chat endpoint, and opens no Internet or libp2p listener,
    /// maps no router port and opens no IPv6 pinhole, shares its IP with no
    /// contact (`hide_ip`), relays for nobody (`relay_offer` unset), uses no
    /// friend as a mailbox (`custody_use` unset, no home custodian), passes
    /// nothing on between friends (`custody_handoff` off) and keeps
    /// off the local network
    /// (`lan_off`, owner decision: no LAN listener, LAN dial or beacon), and
    /// once `raven lan on` turns that on again, links only with verified
    /// contacts there (`lan_verified_only`, the narrower value). Nearby
    /// stays never asked (`nearby` unset: no radio is touched), and learning
    /// is off (`learning`: the static plan only). Phase 6b: it serves no
    /// update to anyone (`update_serve` off) and carries none for friends,
    /// listens on no chosen port (`lan_listen_port` unset), and keeps the
    /// protective defaults: automatic re-key on, silent mode automatic,
    /// auto-lock on sleep as for a new profile. It asks no STUN server
    /// (`stun` off).
    pub fn fail_closed() -> Self {
        Self {
            bridge: false,
            store: false,
            relay: false,
            endpoint: true,
            auto_policy: false,
            internet_listen: String::new(),
            p2p_listen: String::new(),
            p2p_relays: Vec::new(),
            p2p_proxy: String::new(),
            upnp: None,
            v6_pinhole: None,
            peer_rotation: None,
            stun: Some(false),
            custody: false,
            custody_handoff: false,
            custody_use: None,
            custody_home: Vec::new(),
            hide_ip: true,
            relay_offer: None,
            relay_auto: None,
            relay_port: None,
            relay_also_443: false,
            relay_external: Vec::new(),
            lan_off: true,
            lan_verified_only: true,
            nearby: None,
            nearby_background_mail: None,
            learning: Some(false),
            security_auto_rekey: true,
            security_silent_to_strangers: SilentMode::Automatic,
            auto_lock_on_sleep: None,
            update_carry_for_friends: false,
            update_serve: false,
            lan_listen_port: None,
            send_hold: Vec::new(),
        }
    }

    /// Automatic relay choice from contacts' offers: on unless turned off
    /// (`raven relay auto off`).
    pub fn relay_auto_on(&self) -> bool {
        self.relay_auto != Some(false)
    }

    /// R2's early re-key: [`Self::security_auto_rekey`] while the responses
    /// gate is live, else off.
    pub fn security_auto_rekey_on(&self) -> bool {
        live(SecGate::Responses) && self.security_auto_rekey
    }

    /// RLK1's mode: [`Self::security_silent_to_strangers`] while listeners
    /// read knocks (the knock gate, or a security notice's hold on it, under
    /// which listeners still do:
    /// [`live_despite_own_hold`](crate::security_gate::live_despite_own_hold)),
    /// else `None` (no knock: today's handshake).
    pub fn silent_to_strangers(&self) -> Option<SilentMode> {
        crate::security_gate::live_despite_own_hold(SecGate::LinkKnock)
            .then_some(self.security_silent_to_strangers)
    }

    /// Lock v2's lock on wake from sleep: [`Self::auto_lock_on_sleep`]
    /// (unset: [`Self::auto_lock_on_sleep_default`]) while the
    /// local-protection gate is live, else off.
    pub fn auto_lock_on_sleep_on(&self, passphrase_profile: bool, passphrase_file: bool) -> bool {
        let unset = Self::auto_lock_on_sleep_default(passphrase_profile, passphrase_file);
        live(SecGate::LocalProtection) && self.auto_lock_on_sleep.unwrap_or(unset)
    }

    /// [`Self::auto_lock_on_sleep`] while unset (OD6b-18; review
    /// lock-updates-local-3): on for a profile with a Raven passphrase
    /// (`passphrase_profile`), the same rule as a locked start: not when
    /// raven-node reads that passphrase by itself from a file or a systemd
    /// credential (`passphrase_file`, a headless node). Nobody is there to
    /// unlock such a node after a wake (or a clock step that looks like
    /// one), and a passphrase on the same disk gives that lock nothing to
    /// protect; it starts unlocked for the same reason. An explicit setting
    /// still applies.
    pub fn auto_lock_on_sleep_default(passphrase_profile: bool, passphrase_file: bool) -> bool {
        passphrase_profile && !passphrase_file
    }

    /// Serving this platform's verified bundles to pinned contacts:
    /// [`Self::update_serve`] while the mesh-update gate is live, else off.
    pub fn update_serve_on(&self) -> bool {
        live(SecGate::MeshUpdate) && self.update_serve
    }

    /// Carrying other platforms' bundles for pinned contacts:
    /// [`Self::update_carry_for_friends`] while the mesh-update gate is
    /// live, else off.
    pub fn update_carry_for_friends_on(&self) -> bool {
        live(SecGate::MeshUpdate) && self.update_carry_for_friends
    }

    /// Whether sending to `peer` is paused ([`Self::send_hold`]).
    pub fn send_held(&self, peer: &[u8; 32]) -> bool {
        let hex = hex::encode(peer);
        self.send_hold
            .iter()
            .any(|held| held.trim().eq_ignore_ascii_case(&hex))
    }

    /// The LAN listen port this profile picked: [`Self::lan_listen_port`]
    /// while the random-port gate is live, else `None` (the default port).
    /// Port 0 (hand-edited: "any port", which no friend could be told) is
    /// `None` too.
    pub fn lan_listen_port_chosen(&self) -> Option<u16> {
        if live(SecGate::RandomPort) {
            self.lan_listen_port.filter(|&port| port != 0)
        } else {
            None
        }
    }
}

// ── Phase 6b P6.36: a random LAN listen port for new profiles ────────────
//
// Design B §4 (OD6b-10): every profile listening on TCP 7420 is a
// fingerprint anyone on the network can scan for. A profile created while
// the random-port gate is live picks a port of its own instead
// ([`pick_lan_port_for_new_profile`]), and every place that used 7420 as
// this computer's default listens there ([`profile_lan_port`],
// [`crate::paths::profile_lan_listen`]). Cards, route hints and beacon
// answers already carry the port the listener bound. A profile created
// before (or while the gate was shut) keeps 7420 until the user runs `raven
// lan port random` ([`pick_new_lan_port`]).

/// What `raven lan port random` says while the random-port gate is shut
/// (nothing is written).
pub const RANDOM_PORT_HOLD: &str = "RANDOM_PORT_HOLD: a random LAN listen port is lab-only (debug \
    RAVEN_LAB_TEST_A=1 RAVEN_LAB_RANDOM_PORT=1); LISTEN_PORT_RANDOM_PRODUCTION_ENABLED=false \
    (nothing changed)";

/// The range a profile's LAN port is drawn from (design B §4).
pub const RANDOM_LAN_PORTS: std::ops::RangeInclusive<u16> = 20_000..=59_999;

/// Ports inside [`RANDOM_LAN_PORTS`] a profile never picks (each range
/// inclusive): the well-known ports of software often found on the same
/// computer or network, and IANA's dynamic range (49152 and up), where
/// macOS, Windows and the BSDs take the local ports of outgoing
/// connections, so a listener there could find its port taken after a
/// restart.
pub const SKIPPED_LAN_PORTS: [(u16, u16); 13] = [
    (20_000, 20_000), // DNP3, Usermin
    (21_027, 21_027), // Syncthing discovery
    (22_000, 22_000), // Syncthing
    (24_800, 24_800), // Synergy, Barrier, Input Leap
    (25_565, 25_575), // Minecraft and its RCON
    (26_000, 26_000), // Quake
    (27_000, 27_050), // Steam and game servers, MongoDB
    (28_015, 28_017), // RethinkDB, MongoDB web
    (32_400, 32_469), // Plex
    (37_777, 37_777), // network video recorders
    (44_818, 44_818), // EtherNet/IP
    (47_808, 47_808), // BACnet
    (49_152, 59_999), // IANA dynamic range (outgoing connections)
];

/// How many random ports [`pick_lan_port`] tries before it gives up.
const PICK_TRIES: usize = 64;

/// Whether a profile may pick `port`: inside [`RANDOM_LAN_PORTS`], not in
/// [`SKIPPED_LAN_PORTS`], and not one Raven uses itself.
pub fn lan_port_pickable(port: u16) -> bool {
    RANDOM_LAN_PORTS.contains(&port)
        && !SKIPPED_LAN_PORTS
            .iter()
            .any(|&(from, to)| (from..=to).contains(&port))
        && port != crate::paths::DEFAULT_LAN_PORT
        && !crate::paths::RESERVED_RAVEN_PORTS.contains(&port)
}

/// A random pickable port ([`lan_port_pickable`]) other than `avoid` that
/// `free` says nobody holds: `draw` gives ports in [`RANDOM_LAN_PORTS`],
/// and at most [`PICK_TRIES`] are tried (`None` then).
pub fn pick_lan_port(
    mut draw: impl FnMut() -> u16,
    mut free: impl FnMut(u16) -> bool,
    avoid: Option<u16>,
) -> Option<u16> {
    (0..PICK_TRIES)
        .map(|_| draw())
        .find(|&port| lan_port_pickable(port) && Some(port) != avoid && free(port))
}

/// [`pick_lan_port`] with a uniform draw and the bind test the LAN listener
/// would pass: TCP on every IPv4 interface, and on every IPv6 one where
/// this computer has IPv6 (a port taken there counts; no IPv6 at all does
/// not). The sockets close at once.
fn pick_free_lan_port(avoid: Option<u16>) -> Option<u16> {
    use rand::Rng;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
    let mut rng = rand::rngs::OsRng;
    pick_lan_port(
        || rng.gen_range(RANDOM_LAN_PORTS),
        |port| {
            TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok()
                && match TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)) {
                    Ok(_) => true,
                    Err(e) => e.kind() != std::io::ErrorKind::AddrInUse,
                }
        },
        avoid,
    )
}

/// Profile creation (P6.36): while the random-port gate is live, a profile
/// whose identity was just created picks its LAN listen port and saves it
/// in `node_policy.json` (only that field changes; one the file already
/// names is kept). Callers run it only right after creating the identity
/// (`identity_store::load_or_create_profile_identity`), so an existing
/// profile never gets here and keeps the default port. Best effort: with
/// no free port or a policy that cannot be read or written the profile
/// keeps the default port (said on stderr). Returns the profile's port.
pub fn pick_lan_port_for_new_profile(data_dir: &Path) -> Option<u16> {
    if !live(SecGate::RandomPort) {
        return None;
    }
    let Some(port) = pick_free_lan_port(None) else {
        eprintln!("raven: no free random LAN port found; this profile listens on the default port");
        return None;
    };
    match update_policy(data_dir, |policy| {
        if policy.lan_listen_port.is_none() {
            policy.lan_listen_port = Some(port);
        }
    }) {
        Ok(saved) => saved.lan_listen_port_chosen(),
        Err(e) => {
            eprintln!(
                "raven: could not save this profile's LAN port ({e}); it listens on the default \
                 port"
            );
            None
        }
    }
}

/// `raven lan port random` (P6.36): a new random port in place of the
/// profile's current one (the default port when it has none), saved in
/// `node_policy.json` (only that field changes). `Ok(None)` while the
/// random-port gate is shut (nothing is written: the setting would be
/// ignored); an error when no free port was found or the policy cannot be
/// read or written (nothing changed). Returns the new port.
pub fn pick_new_lan_port(data_dir: &Path) -> Result<Option<u16>, PolicyError> {
    if !live(SecGate::RandomPort) {
        return Ok(None);
    }
    let current = try_load_policy(data_dir)?.lan_listen_port;
    let port = pick_free_lan_port(current).ok_or_else(|| {
        PolicyError::Write("no free random LAN port found (nothing changed)".into())
    })?;
    update_policy(data_dir, |policy| policy.lan_listen_port = Some(port))?;
    Ok(Some(port))
}

/// The LAN listen port the profile in `data_dir` picked
/// ([`NodePolicy::lan_listen_port_chosen`]): `None` while the random-port
/// gate is shut, for a profile without one (the default port,
/// [`crate::paths::DEFAULT_LAN_PORT`]) and for a policy that cannot be
/// read. Reads `node_policy.json` alone (the port is a plain setting): no
/// keystore call, nothing written, so raven-node can ask before it binds.
pub fn profile_lan_port(data_dir: &Path) -> Option<u16> {
    if !live(SecGate::RandomPort) {
        return None;
    }
    try_load_plain(data_dir).ok()?.lan_listen_port_chosen()
}

/// Normalise an Internet direct listen address: `ip:port`, `[ipv6]:port`, a
/// bare IP (`0.0.0.0`, `::`, `[::]`), which gets
/// [`crate::paths::DEFAULT_INTERNET_PORT`], or `localhost[:port]`. Empty (after
/// trimming) is `Ok(None)`: no Internet listener. Port 0 (OS-assigned) is kept
/// for tests. Anything else is an error that says what is expected.
pub fn normalize_internet_listen(raw: &str) -> Result<Option<String>, String> {
    use std::net::{IpAddr, SocketAddr};
    let s = raw.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let port = crate::paths::DEFAULT_INTERNET_PORT;
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(Some(addr.to_string()));
    }
    let bare = s
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(s);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(Some(SocketAddr::new(ip, port).to_string()));
    }
    if s.eq_ignore_ascii_case("localhost") {
        return Ok(Some(format!("localhost:{port}")));
    }
    if let Some(p) = s
        .strip_prefix("localhost:")
        .or_else(|| s.strip_prefix("LOCALHOST:"))
    {
        if p.parse::<u16>().is_ok() {
            return Ok(Some(format!("localhost:{p}")));
        }
    }
    Err(format!(
        "Internet listen address must be IP:PORT, e.g. 0.0.0.0:{port} (all IPv4 interfaces), \
         [::]:{port} (IPv6) or 127.0.0.1:{port} (this computer only); got \"{}\"",
        crate::sanitize::sanitize_terminal_line(s)
    ))
}

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("write: {0}")]
    Write(String),
    /// [`NodePolicy::p2p_proxy`] carries a user name or password
    /// ([`crate::net_proxy::has_credentials`]); nothing was written.
    #[error(
        "the proxy setting carries a user name or password, and node_policy.json holds no \
         secrets: give them only in RAVEN_P2P_PROXY, the service's environment (nothing changed)"
    )]
    ProxyCredentials,
}

pub fn policy_path(data_dir: &Path) -> PathBuf {
    data_dir.join(POLICY_FILE)
}

/// [`POLICY_PEERS_FILE`] in `data_dir`.
pub fn policy_peers_path(data_dir: &Path) -> PathBuf {
    data_dir.join(POLICY_PEERS_FILE)
}

/// The policy's fields that name other machines: what the sealed sidecar
/// holds (each omitted while empty).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PolicyPeers {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    p2p_relays: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    relay_external: Vec<String>,
    /// Phase 3 P3.16 ([`NodePolicy::custody_home`]). An older build ignores
    /// it, and drops it only when it saves different relays.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    custody_home: Vec<String>,
    /// Phase 4 (P4.6); an older build's reader ignores it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    p2p_proxy: String,
    /// Phase 6b P6.31 ([`NodePolicy::send_hold`]); an older build's reader
    /// ignores it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    send_hold: Vec<String>,
}

impl PolicyPeers {
    fn of(policy: &NodePolicy) -> Self {
        Self {
            p2p_relays: policy.p2p_relays.clone(),
            relay_external: policy.relay_external.clone(),
            custody_home: policy.custody_home.clone(),
            p2p_proxy: policy.p2p_proxy.clone(),
            send_hold: policy.send_hold.clone(),
        }
    }

    fn is_empty(&self) -> bool {
        self.p2p_relays.is_empty()
            && self.relay_external.is_empty()
            && self.custody_home.is_empty()
            && self.p2p_proxy.is_empty()
            && self.send_hold.is_empty()
    }
}

impl NodePolicy {
    /// This policy without the fields the sidecar holds: what a sealed
    /// profile's `node_policy.json` keeps.
    fn without_peers(&self) -> Self {
        Self {
            p2p_relays: Vec::new(),
            relay_external: Vec::new(),
            custody_home: Vec::new(),
            p2p_proxy: String::new(),
            send_hold: Vec::new(),
            ..self.clone()
        }
    }
}

/// `node_policy.json` alone: missing is [`NodePolicy::default`].
fn try_load_plain(data_dir: &Path) -> Result<NodePolicy, PolicyError> {
    let raw = match std::fs::read_to_string(policy_path(data_dir)) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(NodePolicy::default()),
        Err(e) => return Err(e.into()),
    };
    Ok(serde_json::from_str(&raw)?)
}

/// The sealed sidecar: `None` when there is none.
fn load_peers(data_dir: &Path) -> Result<Option<PolicyPeers>, AtRestError> {
    at_rest::load_json(
        data_dir,
        &policy_peers_path(data_dir),
        Kind::NodePolicyPeers,
    )
}

/// Whether the policy's fields that name other machines can be read now:
/// `false` while a sealed sidecar waits for the at-rest key (raven-node
/// before its key thread has loaded it), or does not open.
pub fn peers_readable(data_dir: &Path) -> bool {
    load_peers(data_dir).is_ok()
}

/// Whether `node_policy.json` itself holds fields that name other machines
/// (a plain profile's, or a sealed profile's not yet moved to the sidecar).
pub fn peers_in_plain(data_dir: &Path) -> bool {
    try_load_plain(data_dir).is_ok_and(|policy| !PolicyPeers::of(&policy).is_empty())
}

/// Missing file → [`NodePolicy::default`]. Unreadable or corrupt → error, so
/// callers that can surface it (status, settings UI) may do so. The sealed
/// sidecar's fields are merged where `node_policy.json` has none, when this
/// process can open it (an unreadable sidecar adds nothing).
pub fn try_load_policy(data_dir: &Path) -> Result<NodePolicy, PolicyError> {
    let mut policy = try_load_plain(data_dir)?;
    if let Ok(Some(stored)) = load_peers(data_dir) {
        if policy.p2p_relays.is_empty() {
            policy.p2p_relays = stored.p2p_relays;
        }
        if policy.relay_external.is_empty() {
            policy.relay_external = stored.relay_external;
        }
        if policy.custody_home.is_empty() {
            policy.custody_home = stored.custody_home;
        }
        if policy.p2p_proxy.is_empty() {
            policy.p2p_proxy = stored.p2p_proxy;
        }
        if policy.send_hold.is_empty() {
            policy.send_hold = stored.send_hold;
        }
    }
    Ok(policy)
}

static CORRUPT_POLICY_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_unusable(e: &PolicyError) {
    if !CORRUPT_POLICY_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "raven: node_policy.json unusable ({e}); bridge/store/relay disabled \
             until the policy is saved again"
        );
    }
}

/// Never fails open: a corrupt or unreadable policy file yields
/// [`NodePolicy::fail_closed`] (warned once per process; raven-node polls this).
pub fn load_policy(data_dir: &Path) -> NodePolicy {
    match try_load_policy(data_dir) {
        Ok(policy) => policy,
        Err(e) => {
            warn_unusable(&e);
            NodePolicy::fail_closed()
        }
    }
}

/// Atomic replace (temp + fsync + rename, owner-only) so a concurrent reader
/// or a crash mid-write never observes a truncated policy. In a sealed
/// profile the fields that name other machines go only to the sealed sidecar
/// (written first; removed when they are empty), under its writer lock; a
/// sidecar this process cannot open (the at-rest key not loaded yet) is kept
/// as it is, and a policy that names relays or home custodians is then
/// refused (try again). A proxy setting that carries a user name or password
/// is refused in either mode ([`PolicyError::ProxyCredentials`]), before
/// anything is written.
pub fn save_policy(data_dir: &Path, policy: &NodePolicy) -> Result<(), PolicyError> {
    if crate::net_proxy::has_credentials(&policy.p2p_proxy) {
        return Err(PolicyError::ProxyCredentials);
    }
    if crate::privacy::mode(data_dir) != Mode::Sealed {
        return write_plain(data_dir, policy);
    }
    let lock = peers_lock(data_dir)?;
    save_held(data_dir, &lock, policy)
}

/// Read the whole policy again, `change` it and save it as
/// [`save_policy`] does, so a question that waited on the user changes
/// only its own field and never writes back an older copy of the others
/// (review D-6: a `raven lan off` made meanwhile stays). In a sealed
/// profile the read and the write happen under the sidecar's writer lock,
/// the one every writer of either policy file takes; a plain profile has
/// no lock (as [`update_settings`]), so only the read-to-write gap is left.
/// An unreadable policy is an error and nothing is written. Returns what
/// was saved.
pub fn update_policy(
    data_dir: &Path,
    change: impl FnOnce(&mut NodePolicy),
) -> Result<NodePolicy, PolicyError> {
    let lock = if crate::privacy::mode(data_dir) == Mode::Sealed {
        Some(peers_lock(data_dir)?)
    } else {
        None
    };
    let mut policy = try_load_policy(data_dir)?;
    change(&mut policy);
    match &lock {
        Some(lock) => save_held(data_dir, lock, &policy)?,
        None => write_plain(data_dir, &policy)?,
    }
    Ok(policy)
}

/// Pause (`on`) or resume sending to `peer` ([`NodePolicy::send_hold`]):
/// only that field changes ([`update_policy`]). A new hold past
/// [`MAX_SEND_HOLD`] is refused and nothing changes; lifting one always
/// works. Returns whether sending to `peer` is paused now.
pub fn set_send_hold(data_dir: &Path, peer: &[u8; 32], on: bool) -> Result<bool, PolicyError> {
    let hex = hex::encode(peer);
    let mut full = false;
    let saved = update_policy(data_dir, |policy| {
        let before = policy.send_hold.len();
        policy
            .send_hold
            .retain(|held| !held.trim().eq_ignore_ascii_case(&hex));
        if !on {
            return;
        }
        if policy.send_hold.len() >= MAX_SEND_HOLD && policy.send_hold.len() == before {
            full = true;
        } else {
            policy.send_hold.push(hex.clone());
        }
    });
    if full {
        return Err(PolicyError::Write(format!(
            "sending is paused to {MAX_SEND_HOLD} contacts already: resume one first (nothing \
             changed)"
        )));
    }
    Ok(saved?.send_held(peer))
}

/// [`save_policy`] in a sealed profile, with the sidecar's writer lock held.
fn save_held(data_dir: &Path, lock: &FileLock, policy: &NodePolicy) -> Result<(), PolicyError> {
    let wanted = PolicyPeers::of(policy);
    match lock.load_json::<PolicyPeers>() {
        Ok(stored)
            if stored.as_ref() == Some(&wanted) || (stored.is_none() && wanted.is_empty()) => {}
        Ok(_) if wanted.is_empty() => remove_peers(data_dir)?,
        Ok(_) => lock
            .store_json(&wanted)
            .map_err(|e| PolicyError::Write(peers_refused(&e)))?,
        Err(_) if wanted.is_empty() => {}
        Err(e) => return Err(PolicyError::Write(peers_refused(&e))),
    }
    write_plain(data_dir, &policy.without_peers())
}

/// Why relay addresses or home custodians could not be saved now (a
/// retryable error).
fn peers_refused(why: &AtRestError) -> String {
    format!(
        "{POLICY_PEERS_FILE} could not be used ({why}): relay and proxy addresses and home \
         custodians are saved only in the encrypted file; try again once Raven can open your \
         keychain (nothing changed)"
    )
}

/// The sidecar's writer lock (the one `at_rest::FILES` names); in a sealed
/// profile every writer of either policy file takes it.
fn peers_lock(data_dir: &Path) -> Result<FileLock, PolicyError> {
    at_rest::lock_file(
        data_dir,
        &policy_peers_path(data_dir),
        Kind::NodePolicyPeers,
    )
    .map_err(|e| PolicyError::Write(e.to_string()))
}

fn remove_peers(data_dir: &Path) -> Result<(), PolicyError> {
    match std::fs::remove_file(policy_peers_path(data_dir)) {
        Ok(()) => {
            crate::paths::sync_dir_best_effort(data_dir);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// `node_policy.json` as `policy` serialises (today's bytes).
fn write_plain(data_dir: &Path, policy: &NodePolicy) -> Result<(), PolicyError> {
    let raw = serde_json::to_string_pretty(policy)?;
    crate::paths::atomic_write_private(&policy_path(data_dir), raw.as_bytes())
        .map_err(PolicyError::Write)
}

/// Change the settings in `node_policy.json` alone and never the sidecar
/// (raven-node's IPC `SetPolicy`: bridge, store, relay), so it works while
/// the at-rest key is not loaded and the relay addresses stay where they
/// are. A file that cannot be read is replaced by
/// [`NodePolicy::fail_closed`] with the change, as `SetPolicy` always did.
/// In a sealed profile it takes the sidecar's writer lock (the migration
/// rewrites `node_policy.json` under it).
pub fn update_settings(
    data_dir: &Path,
    change: impl FnOnce(&mut NodePolicy),
) -> Result<(), PolicyError> {
    let _lock = if crate::privacy::mode(data_dir) == Mode::Sealed {
        Some(peers_lock(data_dir)?)
    } else {
        None
    };
    let mut policy = try_load_plain(data_dir).unwrap_or_else(|e| {
        warn_unusable(&e);
        NodePolicy::fail_closed()
    });
    change(&mut policy);
    write_plain(data_dir, &policy)
}

/// Where `raven lan on` keeps a `node_policy.json` it could not read before it
/// writes a new one in its place (Phase 3 owner decision: an unreadable policy
/// keeps LAN off until `raven lan on` repairs it). Plain, like the file it
/// was; a later repair replaces it.
pub const POLICY_BAD_FILE: &str = "node_policy.json.bad";

/// What [`set_lan_off`] (or [`set_lan_verified_only`]) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanOffSaved {
    /// The setting saved; every other setting kept.
    Saved,
    /// `node_policy.json` could not be read (`why`). `repaired`: it was kept
    /// as [`POLICY_BAD_FILE`] and [`NodePolicy::fail_closed`] with the new
    /// `lan_off` took its place; otherwise nothing was written.
    Unreadable { why: String, repaired: bool },
}

/// `raven lan on|off` (Phase 3, D7): `lan_off` changed in `node_policy.json`
/// alone, every other setting kept and the sealed sidecar never touched, under
/// the lock [`update_settings`] takes. A file that cannot be read is left as it
/// is unless `repair` (`raven lan on`): then it is kept as [`POLICY_BAD_FILE`]
/// and [`NodePolicy::fail_closed`] with this `lan_off` replaces it, so every
/// other setting stays off until the user sets it again. A missing file is the
/// default policy, as everywhere.
pub fn set_lan_off(data_dir: &Path, off: bool, repair: bool) -> Result<LanOffSaved, PolicyError> {
    change_plain(data_dir, repair, |policy| policy.lan_off = off)
}

/// `raven lan verified-only on|off` (Phase 3 P3.C2): `lan_verified_only`
/// changed as [`set_lan_off`] changes `lan_off`, but a file that cannot be read
/// is never repaired here (LAN is off while it cannot be read; `raven lan on`
/// repairs it).
pub fn set_lan_verified_only(data_dir: &Path, on: bool) -> Result<LanOffSaved, PolicyError> {
    change_plain(data_dir, false, |policy| policy.lan_verified_only = on)
}

/// [`set_lan_off`]'s read-change-write of `node_policy.json` alone.
fn change_plain(
    data_dir: &Path,
    repair: bool,
    change: impl FnOnce(&mut NodePolicy),
) -> Result<LanOffSaved, PolicyError> {
    let _lock = if crate::privacy::mode(data_dir) == Mode::Sealed {
        Some(peers_lock(data_dir)?)
    } else {
        None
    };
    let (mut policy, saved) = match try_load_plain(data_dir) {
        Ok(policy) => (policy, LanOffSaved::Saved),
        Err(e) if !repair => {
            return Ok(LanOffSaved::Unreadable {
                why: e.to_string(),
                repaired: false,
            })
        }
        Err(e) => {
            keep_unreadable(data_dir)?;
            let saved = LanOffSaved::Unreadable {
                why: e.to_string(),
                repaired: true,
            };
            (NodePolicy::fail_closed(), saved)
        }
    };
    change(&mut policy);
    write_plain(data_dir, &policy)?;
    Ok(saved)
}

/// `raven lan verified-only` (Phase 3 P3.C2) as `node_policy.json` says it
/// now: only verified (pinned) contacts may link on the LAN. Read where it
/// applies (link admission, a LAN dial, the delivery planners), one small
/// file read, so a change made by ash holds from the next link without a
/// restart. Missing file: off (the default); a file that cannot be read: on
/// (fail closed, as [`NodePolicy::fail_closed`]).
pub fn lan_verified_only(data_dir: &Path) -> bool {
    try_load_plain(data_dir).map_or(true, |policy| policy.lan_verified_only)
}

/// The nearby settings (Phase 5, RNL1): whether the user turned nearby on
/// ([`NodePolicy::nearby`]) and background mail
/// ([`NodePolicy::nearby_background_mail`]), from `node_policy.json` alone
/// (one small file read, never the sealed sidecar). A missing file, an unset
/// setting and a file that cannot be read are all off: nearby touches no
/// radio unless the user said so.
pub fn nearby_settings(data_dir: &Path) -> (bool, bool) {
    try_load_plain(data_dir).map_or((false, false), |p| {
        (
            p.nearby == Some(true),
            p.nearby_background_mail == Some(true),
        )
    })
}

/// [`POLICY_BAD_FILE`]: a copy of the unreadable `node_policy.json` (0600,
/// over an older copy), or, when its bytes cannot be read at all, a second
/// name for the file itself (a hard link: the file stays in place until the
/// new policy replaces it, so a crash never leaves the profile without one).
fn keep_unreadable(data_dir: &Path) -> Result<(), PolicyError> {
    let (path, bad) = (policy_path(data_dir), data_dir.join(POLICY_BAD_FILE));
    match std::fs::read(&path) {
        Ok(bytes) => crate::paths::atomic_write_private(&bad, &bytes).map_err(PolicyError::Write),
        // Gone meanwhile: nothing to keep.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            match std::fs::remove_file(&bad) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            std::fs::hard_link(&path, &bad)?;
            Ok(())
        }
    }
}

/// The migration (`privacy::migrate_all`, a sealed profile with its key
/// loaded): move the fields that name other machines out of
/// `node_policy.json` into the sealed sidecar, the sidecar first (written and
/// checked to open to exactly them), then `node_policy.json` without them. A
/// value in `node_policy.json` replaces the sidecar's (it is the newer:
/// written before sealing, or by an older build since). `true` when
/// something moved; a `node_policy.json` that cannot be read is left alone
/// (its readers fail closed anyway).
pub fn seal_peers(data_dir: &Path) -> Result<bool, AtRestError> {
    // Lock-free first: nothing to move, no lock (and no lock file).
    if !peers_in_plain(data_dir) {
        return Ok(false);
    }
    let path = policy_peers_path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::NodePolicyPeers)?;
    let Ok(plain) = try_load_plain(data_dir) else {
        return Ok(false);
    };
    let found = PolicyPeers::of(&plain);
    if found.is_empty() {
        return Ok(false);
    }
    let mut stored = lock.load_json::<PolicyPeers>()?.unwrap_or_default();
    if !found.p2p_relays.is_empty() {
        stored.p2p_relays = found.p2p_relays;
    }
    if !found.relay_external.is_empty() {
        stored.relay_external = found.relay_external;
    }
    if !found.custody_home.is_empty() {
        stored.custody_home = found.custody_home;
    }
    if !found.p2p_proxy.is_empty() {
        stored.p2p_proxy = found.p2p_proxy;
    }
    if !found.send_hold.is_empty() {
        stored.send_hold = found.send_hold;
    }
    let json = serde_json::to_vec_pretty(&stored).map_err(|e| AtRestError::Json(e.to_string()))?;
    at_rest::seal_verified_held(data_dir, &path, Kind::NodePolicyPeers, &json)?;
    #[cfg(test)]
    crate::privacy::tests::crash_point(crate::privacy::tests::Crash::PolicySidecarWritten)?;
    write_plain(data_dir, &plain.without_peers()).map_err(|e| AtRestError::Io(e.to_string()))?;
    Ok(true)
}

/// The way back (`raven privacy unseal`, PP.18; the profile is no longer
/// sealed and this process holds its key): under the sidecar's writer lock,
/// the sealed sidecar's fields go back into `node_policy.json` where it has
/// none (a value written there since is the newer and stays), then the
/// sidecar goes. `true` when there was one. A sidecar that does not open is
/// an error and is kept, with `node_policy.json` as it was.
pub fn unseal_peers(data_dir: &Path) -> Result<bool, AtRestError> {
    let path = policy_peers_path(data_dir);
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(false);
    }
    let lock = at_rest::lock_file(data_dir, &path, Kind::NodePolicyPeers)?;
    let Some(stored) = lock.load_json::<PolicyPeers>()? else {
        return Ok(false);
    };
    let mut policy = try_load_plain(data_dir).map_err(|e| AtRestError::Io(e.to_string()))?;
    if policy.p2p_relays.is_empty() {
        policy.p2p_relays = stored.p2p_relays;
    }
    if policy.relay_external.is_empty() {
        policy.relay_external = stored.relay_external;
    }
    if policy.custody_home.is_empty() {
        policy.custody_home = stored.custody_home;
    }
    if policy.p2p_proxy.is_empty() {
        policy.p2p_proxy = stored.p2p_proxy;
    }
    if policy.send_hold.is_empty() {
        policy.send_hold = stored.send_hold;
    }
    write_plain(data_dir, &policy).map_err(|e| AtRestError::Io(e.to_string()))?;
    remove_peers(data_dir).map_err(|e| AtRestError::Io(e.to_string()))?;
    Ok(true)
}

/// Safe status snapshot for ash (never includes keys or packed envelopes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeStatusSnapshot {
    pub bridge: bool,
    pub store: bool,
    pub relay: bool,
    pub endpoint: bool,
    pub auto_policy: bool,
    pub transports: Vec<String>,
    pub forward_queue_pending: usize,
    pub forward_queue_total: usize,
    pub capabilities: Vec<String>,
}

impl BridgeStatusSnapshot {
    pub fn from_policy(
        policy: &NodePolicy,
        transports: &[&str],
        pending: usize,
        total: usize,
    ) -> Self {
        let mut caps = Vec::new();
        if transports.iter().any(|t| *t == "ble" || *t == "mock_ble") {
            caps.push("ble".into());
        }
        if transports.iter().any(|t| *t == "lan" || *t == "internet") {
            caps.push("internet".into());
        }
        if policy.relay {
            caps.push("relay".into());
        }
        if policy.store {
            caps.push("store".into());
        }
        if policy.bridge {
            caps.push("bridge".into());
        }
        Self {
            bridge: policy.bridge,
            store: policy.store,
            relay: policy.relay,
            endpoint: policy.endpoint,
            auto_policy: policy.auto_policy,
            transports: transports.iter().map(|s| (*s).to_string()).collect(),
            forward_queue_pending: pending,
            forward_queue_total: total,
            capabilities: caps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_policy() {
        let dir = tempdir().unwrap();
        let p = NodePolicy {
            bridge: false,
            auto_policy: false,
            ..Default::default()
        };
        save_policy(dir.path(), &p).unwrap();
        let loaded = load_policy(dir.path());
        assert!(!loaded.bridge);
        assert!(!loaded.auto_policy);
    }

    #[test]
    fn missing_policy_uses_defaults() {
        let dir = tempdir().unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap(), NodePolicy::default());
        assert_eq!(load_policy(dir.path()), NodePolicy::default());
    }

    #[test]
    fn corrupt_or_truncated_policy_fails_closed() {
        // A torn write (empty / partial JSON) used to fall back to the
        // permissive default (bridge=true, store=true), silently undoing a
        // user's "bridge off".
        let dir = tempdir().unwrap();
        for raw in ["", "{\"bridge\": fal", "not json", "{\"bridge\": \"no\"}"] {
            std::fs::write(policy_path(dir.path()), raw).unwrap();
            assert!(try_load_policy(dir.path()).is_err(), "{raw:?}");
            let loaded = load_policy(dir.path());
            assert_eq!(loaded, NodePolicy::fail_closed(), "{raw:?}");
            assert!(!loaded.bridge && !loaded.store && !loaded.relay);
            assert!(!loaded.auto_policy);
        }
    }

    #[test]
    fn save_replaces_atomically_and_repairs_corrupt_file() {
        let dir = tempdir().unwrap();
        std::fs::write(policy_path(dir.path()), "{\"bridge\": tr").unwrap();
        let p = NodePolicy {
            store: false,
            ..NodePolicy::fail_closed()
        };
        save_policy(dir.path(), &p).unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap(), p);
        // Only the policy file remains: no temp file left behind.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("node_policy.json")]);
    }

    #[test]
    fn internet_listen_is_opt_in_and_old_files_stay_compatible() {
        let dir = tempdir().unwrap();
        // A file written before the field existed loads with it off.
        std::fs::write(
            policy_path(dir.path()),
            r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true}"#,
        )
        .unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap(), NodePolicy::default());
        // Empty is not written at all (older readers see the same keys).
        save_policy(dir.path(), &NodePolicy::default()).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(!raw.contains("internet_listen"), "{raw}");
        let on = NodePolicy {
            internet_listen: "0.0.0.0:7422".into(),
            ..NodePolicy::default()
        };
        save_policy(dir.path(), &on).unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap(), on);
        assert!(NodePolicy::fail_closed().internet_listen.is_empty());
    }

    #[test]
    fn p2p_settings_are_opt_in_and_upnp_has_three_states() {
        let dir = tempdir().unwrap();
        // Older files load with p2p off and UPnP never asked.
        std::fs::write(
            policy_path(dir.path()),
            r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true}"#,
        )
        .unwrap();
        let loaded = try_load_policy(dir.path()).unwrap();
        assert_eq!(loaded, NodePolicy::default());
        assert!(loaded.p2p_listen.is_empty() && loaded.p2p_relays.is_empty());
        assert_eq!(loaded.upnp, None);
        // Unset values are not written at all.
        save_policy(dir.path(), &NodePolicy::default()).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        for key in ["p2p_listen", "p2p_relays", "upnp"] {
            assert!(!raw.contains(key), "{raw}");
        }
        // unset -> on -> off round-trips through node_policy.json.
        for upnp in [Some(true), Some(false), None] {
            let p = NodePolicy {
                p2p_listen: "7423".into(),
                p2p_relays: vec!["/ip4/203.0.113.7/tcp/7423/p2p/x".into()],
                upnp,
                ..NodePolicy::default()
            };
            save_policy(dir.path(), &p).unwrap();
            assert_eq!(try_load_policy(dir.path()).unwrap(), p);
        }
        let fc = NodePolicy::fail_closed();
        assert!(fc.p2p_listen.is_empty() && fc.p2p_relays.is_empty() && fc.upnp.is_none());
        // A wrong type is a corrupt file (fail closed), not "unset".
        std::fs::write(policy_path(dir.path()), r#"{"upnp":"yes"}"#).unwrap();
        assert!(try_load_policy(dir.path()).is_err());
    }

    /// Phase 4 (P4.20, O4-11): the IPv6 pinhole consent has three states of
    /// its own, is omitted while unset (older files and readers are
    /// unaffected), is never implied by `upnp`, and an unreadable policy
    /// leaves it unset.
    #[test]
    fn v6_pinhole_round_trips_is_omitted_when_unset_and_fail_closed_unsets_it() {
        let dir = tempdir().unwrap();
        std::fs::write(
            policy_path(dir.path()),
            r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true,"upnp":true}"#,
        )
        .unwrap();
        let old = try_load_policy(dir.path()).unwrap();
        assert_eq!((old.upnp, old.v6_pinhole), (Some(true), None));
        save_policy(dir.path(), &old).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(!raw.contains("v6_pinhole"), "{raw}");
        for v6_pinhole in [Some(true), Some(false), None] {
            let p = NodePolicy {
                v6_pinhole,
                ..old.clone()
            };
            save_policy(dir.path(), &p).unwrap();
            let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
            assert_eq!(raw.contains("v6_pinhole"), v6_pinhole.is_some(), "{raw}");
            assert_eq!(try_load_policy(dir.path()).unwrap(), p);
        }
        assert_eq!(NodePolicy::default().v6_pinhole, None);
        assert_eq!(NodePolicy::fail_closed().v6_pinhole, None);
        std::fs::write(policy_path(dir.path()), r#"{"v6_pinhole":"yes"}"#).unwrap();
        assert!(try_load_policy(dir.path()).is_err());
    }

    /// Phase 4 (P4.28, O4-13): the PeerId rotation setting is unset by
    /// default and when the policy cannot be read, omitted while unset, and
    /// round-trips both values.
    #[test]
    fn peer_rotation_round_trips_and_is_omitted_when_unset() {
        let dir = tempdir().unwrap();
        let base = NodePolicy::default();
        save_policy(dir.path(), &base).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(!raw.contains("peer_rotation"), "{raw}");
        for peer_rotation in [Some(true), Some(false), None] {
            let p = NodePolicy {
                peer_rotation,
                ..base.clone()
            };
            save_policy(dir.path(), &p).unwrap();
            let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
            assert_eq!(
                raw.contains("peer_rotation"),
                peer_rotation.is_some(),
                "{raw}"
            );
            assert_eq!(try_load_policy(dir.path()).unwrap(), p);
        }
        assert_eq!(NodePolicy::fail_closed().peer_rotation, None);
        std::fs::write(policy_path(dir.path()), r#"{"peer_rotation":"yes"}"#).unwrap();
        assert!(try_load_policy(dir.path()).is_err());
    }

    /// Auto-reach: the STUN setting is unset by default (on), omitted while
    /// unset, round-trips both values, is off when the policy cannot be
    /// read, and hide my IP for everyone stops the queries too.
    #[test]
    fn stun_round_trips_is_on_by_default_and_hide_ip_stops_it() {
        let dir = tempdir().unwrap();
        let base = NodePolicy::default();
        assert_eq!(base.stun, None);
        assert!(base.stun_allowed());
        save_policy(dir.path(), &base).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(!raw.contains("stun"), "{raw}");
        for stun in [Some(true), Some(false), None] {
            let p = NodePolicy {
                stun,
                ..base.clone()
            };
            save_policy(dir.path(), &p).unwrap();
            let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
            assert_eq!(raw.contains("\"stun\""), stun.is_some(), "{raw}");
            assert_eq!(try_load_policy(dir.path()).unwrap(), p);
            assert_eq!(p.stun_allowed(), stun != Some(false));
            let hidden = NodePolicy { hide_ip: true, ..p };
            assert!(!hidden.stun_allowed());
        }
        assert_eq!(NodePolicy::fail_closed().stun, Some(false));
        assert!(!NodePolicy::fail_closed().stun_allowed());
        std::fs::write(policy_path(dir.path()), r#"{"stun":"yes"}"#).unwrap();
        assert!(try_load_policy(dir.path()).is_err());
    }

    /// Phase 5 (P5.25, O5-13; cutoff addendum F11d): the nearby consent and
    /// its background-mail setting are unset by default and when the policy
    /// cannot be read, omitted while unset (a file without them round-trips
    /// to the same bytes), and round-trip every value.
    #[test]
    fn nearby_settings_round_trip_and_are_omitted_when_unset() {
        let dir = tempdir().unwrap();
        let old = r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true,"upnp":true,"lan_off":true}"#;
        std::fs::write(policy_path(dir.path()), old).unwrap();
        let loaded = try_load_policy(dir.path()).unwrap();
        assert_eq!((loaded.nearby, loaded.nearby_background_mail), (None, None));
        save_policy(dir.path(), &loaded).unwrap();
        let first = std::fs::read(policy_path(dir.path())).unwrap();
        let raw = String::from_utf8(first.clone()).unwrap();
        assert!(!raw.contains("nearby"), "{raw}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
            serde_json::from_str::<serde_json::Value>(old).unwrap()
        );
        // Saved again: the very same bytes.
        save_policy(dir.path(), &try_load_policy(dir.path()).unwrap()).unwrap();
        assert_eq!(std::fs::read(policy_path(dir.path())).unwrap(), first);
        for nearby in [Some(true), Some(false), None] {
            for background in [Some(true), Some(false), None] {
                let p = NodePolicy {
                    nearby,
                    nearby_background_mail: background,
                    ..loaded.clone()
                };
                save_policy(dir.path(), &p).unwrap();
                let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
                assert_eq!(raw.contains(r#""nearby":"#), nearby.is_some(), "{raw}");
                assert_eq!(
                    raw.contains("nearby_background_mail"),
                    background.is_some(),
                    "{raw}"
                );
                assert_eq!(try_load_policy(dir.path()).unwrap(), p);
            }
        }
        for p in [NodePolicy::default(), NodePolicy::fail_closed()] {
            assert_eq!((p.nearby, p.nearby_background_mail), (None, None));
        }
        std::fs::write(policy_path(dir.path()), r#"{"nearby":"yes"}"#).unwrap();
        assert!(try_load_policy(dir.path()).is_err());
    }

    /// Phase 6a (P6.2): the learning switch is unset (on while the gate is
    /// open) by default, omitted while unset (a file without it round-trips
    /// to the same bytes, and an older reader still reads one with it),
    /// round-trips every value, and is off when the policy cannot be read.
    #[test]
    fn learning_is_omitted_by_default_and_off_when_failing_closed() {
        let dir = tempdir().unwrap();
        let dd = dir.path();
        let old = r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true,"lan_off":true}"#;
        std::fs::write(policy_path(dd), old).unwrap();
        let loaded = try_load_policy(dd).unwrap();
        assert_eq!(loaded.learning, None);
        save_policy(dd, &loaded).unwrap();
        let first = std::fs::read(policy_path(dd)).unwrap();
        let raw = String::from_utf8(first.clone()).unwrap();
        assert!(!raw.contains("learning"), "{raw}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
            serde_json::from_str::<serde_json::Value>(old).unwrap()
        );
        save_policy(dd, &try_load_policy(dd).unwrap()).unwrap();
        assert_eq!(std::fs::read(policy_path(dd)).unwrap(), first);
        for learning in [Some(true), Some(false), None] {
            let p = NodePolicy {
                learning,
                ..loaded.clone()
            };
            save_policy(dd, &p).unwrap();
            let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
            assert_eq!(raw.contains(r#""learning":"#), learning.is_some(), "{raw}");
            assert_eq!(try_load_policy(dd).unwrap(), p);
            #[derive(Deserialize)]
            struct OlderReader {
                bridge: bool,
            }
            let older: OlderReader = serde_json::from_str(&raw).unwrap();
            assert!(older.bridge);
        }
        assert_eq!(NodePolicy::default().learning, None);
        assert_eq!(NodePolicy::fail_closed().learning, Some(false));
        std::fs::write(policy_path(dd), r#"{"learning":"yes"}"#).unwrap();
        assert!(try_load_policy(dd).is_err());
        assert_eq!(load_policy(dd).learning, Some(false));
    }

    /// The six Phase 6b fields (P6.21), each from a policy without them.
    fn with_6b_field(base: &NodePolicy, i: usize) -> (NodePolicy, &'static str) {
        let mut p = base.clone();
        let name = match i {
            0 => {
                p.security_auto_rekey = false;
                "security_auto_rekey"
            }
            1 => {
                p.security_silent_to_strangers = SilentMode::On;
                "security_silent_to_strangers"
            }
            2 => {
                p.auto_lock_on_sleep = Some(false);
                "auto_lock_on_sleep"
            }
            3 => {
                p.update_carry_for_friends = true;
                "update_carry_for_friends"
            }
            4 => {
                p.update_serve = false;
                "update_serve"
            }
            _ => {
                p.lan_listen_port = Some(43_210);
                "lan_listen_port"
            }
        };
        (p, name)
    }

    /// Phase 6b (P6.21): the six new settings default as the owner decided,
    /// are omitted while at their defaults (an older file round-trips to
    /// the same bytes, and an older reader still reads one with them), each
    /// round-trips a set value, and a value of the wrong type fails closed.
    #[test]
    fn security_settings_are_omitted_by_default_and_round_trip() {
        let dir = tempdir().unwrap();
        let dd = dir.path();
        let old = r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true,"lan_off":true}"#;
        std::fs::write(policy_path(dd), old).unwrap();
        let loaded = try_load_policy(dd).unwrap();
        let d = NodePolicy::default();
        assert!(loaded.security_auto_rekey && d.security_auto_rekey);
        assert_eq!(loaded.security_silent_to_strangers, SilentMode::Automatic);
        assert_eq!(d.security_silent_to_strangers, SilentMode::Automatic);
        assert_eq!(
            (loaded.auto_lock_on_sleep, d.auto_lock_on_sleep),
            (None, None)
        );
        assert!(!loaded.update_carry_for_friends && !d.update_carry_for_friends);
        assert!(loaded.update_serve && d.update_serve);
        assert_eq!((loaded.lan_listen_port, d.lan_listen_port), (None, None));
        save_policy(dd, &loaded).unwrap();
        let first = std::fs::read(policy_path(dd)).unwrap();
        let raw = String::from_utf8(first.clone()).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
            serde_json::from_str::<serde_json::Value>(old).unwrap()
        );
        save_policy(dd, &try_load_policy(dd).unwrap()).unwrap();
        assert_eq!(std::fs::read(policy_path(dd)).unwrap(), first);
        // The default policy writes none of them either.
        save_policy(dd, &d).unwrap();
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        for i in 0..6 {
            let (p, name) = with_6b_field(&loaded, i);
            assert!(!raw.contains(name), "{name}: {raw}");
            save_policy(dd, &p).unwrap();
            let written = std::fs::read_to_string(policy_path(dd)).unwrap();
            assert!(written.contains(&format!("\"{name}\":")), "{written}");
            assert_eq!(try_load_policy(dd).unwrap(), p, "{name}");
            #[derive(Deserialize)]
            struct OlderReader {
                bridge: bool,
            }
            let older: OlderReader = serde_json::from_str(&written).unwrap();
            assert!(older.bridge);
        }
        for (mode, text) in [
            (SilentMode::Automatic, None),
            (
                SilentMode::On,
                Some(r#""security_silent_to_strangers": "on""#),
            ),
            (
                SilentMode::Off,
                Some(r#""security_silent_to_strangers": "off""#),
            ),
        ] {
            let p = NodePolicy {
                security_silent_to_strangers: mode,
                ..loaded.clone()
            };
            save_policy(dd, &p).unwrap();
            let written = std::fs::read_to_string(policy_path(dd)).unwrap();
            match text {
                Some(text) => assert!(written.contains(text), "{written}"),
                None => assert!(!written.contains("security_silent"), "{written}"),
            }
            assert_eq!(try_load_policy(dd).unwrap(), p);
        }
        let fc = NodePolicy::fail_closed();
        assert!(fc.security_auto_rekey);
        assert_eq!(fc.security_silent_to_strangers, SilentMode::Automatic);
        assert_eq!(fc.auto_lock_on_sleep, None);
        assert!(!fc.update_carry_for_friends && !fc.update_serve);
        assert_eq!(fc.lan_listen_port, None);
        for bad in [
            r#"{"security_auto_rekey":"yes"}"#,
            r#"{"security_silent_to_strangers":"loud"}"#,
            r#"{"auto_lock_on_sleep":1}"#,
            r#"{"update_carry_for_friends":"on"}"#,
            r#"{"update_serve":null}"#,
            r#"{"lan_listen_port":70000}"#,
        ] {
            std::fs::write(policy_path(dd), bad).unwrap();
            assert!(try_load_policy(dd).is_err(), "{bad}");
            assert_eq!(load_policy(dd), fc, "{bad}");
        }
    }

    /// Phase 6b (P6.21): each setting is read only while its gate is live.
    /// With the gates shut (every build without the lab unlock, and every
    /// release build) the accessors give today's behaviour whatever the
    /// file says; in a debug build this thread's overrides open them.
    #[test]
    fn security_settings_are_read_only_while_their_gate_is_live() {
        use crate::security_gate::set_lab_for_this_thread;
        let debug = cfg!(debug_assertions);
        let set = NodePolicy {
            security_auto_rekey: true,
            security_silent_to_strangers: SilentMode::On,
            auto_lock_on_sleep: Some(true),
            update_carry_for_friends: true,
            update_serve: true,
            lan_listen_port: Some(43_210),
            ..NodePolicy::default()
        };
        let unset = NodePolicy {
            security_auto_rekey: false,
            security_silent_to_strangers: SilentMode::Off,
            auto_lock_on_sleep: Some(false),
            update_carry_for_friends: false,
            update_serve: false,
            ..NodePolicy::default()
        };
        for g in SecGate::ALL {
            set_lab_for_this_thread(g, Some(false));
        }
        for p in [&set, &unset, &NodePolicy::default()] {
            assert!(!p.security_auto_rekey_on());
            assert_eq!(p.silent_to_strangers(), None);
            assert!(!p.auto_lock_on_sleep_on(true, false));
            assert!(!p.update_serve_on() && !p.update_carry_for_friends_on());
            assert_eq!(p.lan_listen_port_chosen(), None);
        }
        // Responses without events stays shut; mesh needs the bundle and
        // advisory gates below it.
        set_lab_for_this_thread(SecGate::Responses, Some(true));
        assert!(!set.security_auto_rekey_on());
        set_lab_for_this_thread(SecGate::Events, Some(true));
        assert_eq!(set.security_auto_rekey_on(), debug);
        assert!(!unset.security_auto_rekey_on());
        set_lab_for_this_thread(SecGate::LinkKnock, Some(true));
        assert_eq!(set.silent_to_strangers(), debug.then_some(SilentMode::On));
        assert_eq!(
            NodePolicy::default().silent_to_strangers(),
            debug.then_some(SilentMode::Automatic)
        );
        set_lab_for_this_thread(SecGate::LocalProtection, Some(true));
        assert_eq!(set.auto_lock_on_sleep_on(false, false), debug);
        assert!(!unset.auto_lock_on_sleep_on(true, false));
        // Unset: on for a passphrase profile only (OD6b-18).
        assert_eq!(
            NodePolicy::default().auto_lock_on_sleep_on(true, false),
            debug
        );
        assert!(!NodePolicy::default().auto_lock_on_sleep_on(false, false));
        // ...and not for one whose passphrase raven-node reads from a file
        // (a headless node: review lock-updates-local-3), unless it is set.
        assert!(!NodePolicy::default().auto_lock_on_sleep_on(true, true));
        assert_eq!(set.auto_lock_on_sleep_on(true, true), debug);
        set_lab_for_this_thread(SecGate::MeshUpdate, Some(true));
        set_lab_for_this_thread(SecGate::ReleaseBundle, Some(true));
        assert!(!set.update_serve_on() && !set.update_carry_for_friends_on());
        set_lab_for_this_thread(SecGate::Advisory, Some(true));
        assert_eq!(set.update_serve_on(), debug);
        assert_eq!(set.update_carry_for_friends_on(), debug);
        assert!(!unset.update_serve_on() && !unset.update_carry_for_friends_on());
        // The defaults (OD6b-24): serve this platform's bundles, carry no
        // other platform's.
        assert_eq!(NodePolicy::default().update_serve_on(), debug);
        assert!(!NodePolicy::default().update_carry_for_friends_on());
        set_lab_for_this_thread(SecGate::RandomPort, Some(true));
        assert_eq!(set.lan_listen_port_chosen(), debug.then_some(43_210));
        assert_eq!(unset.lan_listen_port_chosen(), None);
        for g in SecGate::ALL {
            set_lab_for_this_thread(g, None);
        }
    }

    #[test]
    fn p2p_proxy_round_trips_and_is_omitted_when_auto() {
        let dir = tempdir().unwrap();
        // A file written before the field existed loads as auto (empty).
        std::fs::write(
            policy_path(dir.path()),
            r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true,"p2p_listen":"7423"}"#,
        )
        .unwrap();
        let old = try_load_policy(dir.path()).unwrap();
        assert!(old.p2p_proxy.is_empty() && old.p2p_listen == "7423");
        assert!(NodePolicy::default().p2p_proxy.is_empty());
        assert!(NodePolicy::fail_closed().p2p_proxy.is_empty());
        // Auto is not written at all (older readers see the same keys).
        save_policy(dir.path(), &old).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(!raw.contains("p2p_proxy"), "{raw}");
        // Off and a proxy URL round-trip, and parse as settings.
        for value in ["off", "http://proxy.example:3128", "[2001:db8::8]:8080"] {
            let p = NodePolicy {
                p2p_proxy: value.into(),
                ..old.clone()
            };
            save_policy(dir.path(), &p).unwrap();
            let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
            assert!(raw.contains(&format!(r#""p2p_proxy": "{value}""#)), "{raw}");
            let loaded = try_load_policy(dir.path()).unwrap();
            assert_eq!(loaded, p);
            assert!(crate::net_proxy::parse_setting(&loaded.p2p_proxy).is_ok());
            // An older reader (no such field) still reads the file.
            #[derive(Deserialize)]
            struct OlderReader {
                bridge: bool,
                p2p_listen: String,
            }
            let older: OlderReader = serde_json::from_str(&raw).unwrap();
            assert!(older.bridge && older.p2p_listen == "7423");
        }
        // A wrong type is a corrupt file (fail closed), not "auto".
        std::fs::write(policy_path(dir.path()), r#"{"p2p_proxy":["off"]}"#).unwrap();
        assert!(try_load_policy(dir.path()).is_err());
        assert!(load_policy(dir.path()).p2p_proxy.is_empty());
    }

    /// node_policy.json holds no secrets: a proxy setting with a user name or
    /// password is refused, plain or sealed, and nothing is written.
    #[test]
    fn policy_refuses_proxy_credentials() {
        let with_credentials = [
            "http://user:pass@proxy.example:3128",
            "user:pass@proxy.example:3128",
            "http://user@proxy.example",
            "https://user:pass@proxy.example",
            "http://us%40er:p%3Ass@proxy.example:3128",
        ];
        let plain = tempdir().unwrap();
        let sealed = crate::contact_book::tests::profile();
        crate::contact_book::tests::seal(sealed.path());
        for dd in [plain.path(), sealed.path()] {
            let base = NodePolicy {
                p2p_relays: vec!["/ip4/198.51.100.7/tcp/7423/p2p/relay".into()],
                ..NodePolicy::default()
            };
            for value in with_credentials {
                // Nothing there yet: nothing is created.
                let _ = std::fs::remove_file(policy_path(dd));
                let _ = std::fs::remove_file(policy_peers_path(dd));
                let p = NodePolicy {
                    p2p_proxy: value.into(),
                    ..base.clone()
                };
                let err = save_policy(dd, &p).unwrap_err();
                assert!(
                    matches!(err, PolicyError::ProxyCredentials),
                    "{value}: {err}"
                );
                assert!(!err.to_string().contains("proxy.example"), "{err}");
                assert!(!policy_path(dd).exists() && !policy_peers_path(dd).exists());
                // A saved policy stays as it was, sidecar included.
                save_policy(dd, &base).unwrap();
                let before = (
                    std::fs::read(policy_path(dd)).unwrap(),
                    std::fs::read(policy_peers_path(dd)).ok(),
                );
                assert!(save_policy(dd, &p).is_err(), "{value}");
                let after = (
                    std::fs::read(policy_path(dd)).unwrap(),
                    std::fs::read(policy_peers_path(dd)).ok(),
                );
                assert_eq!(before, after, "{value}");
                assert_eq!(try_load_policy(dd).unwrap(), base);
            }
            // Without credentials the same proxy saves.
            let ok = NodePolicy {
                p2p_proxy: "http://proxy.example:3128".into(),
                ..base.clone()
            };
            save_policy(dd, &ok).unwrap();
            assert_eq!(try_load_policy(dd).unwrap(), ok);
        }
    }

    /// The proxy setting names another machine: a sealed profile keeps it in
    /// the sealed sidecar with the relays (also when it is the only field
    /// there), the migration moves a plain one there, and the way back
    /// returns it to node_policy.json.
    #[test]
    fn p2p_proxy_is_sealed_with_the_relays() {
        let dir = crate::contact_book::tests::profile();
        let dd = dir.path();
        let proxy_only = NodePolicy {
            p2p_listen: "7423".into(),
            p2p_proxy: "http://proxy.example:3128".into(),
            ..NodePolicy::default()
        };
        // A plain profile writes it into node_policy.json; sealing moves it.
        save_policy(dd, &proxy_only).unwrap();
        assert!(!policy_peers_path(dd).exists());
        assert!(peers_in_plain(dd));
        crate::contact_book::tests::seal(dd);
        let sidecar = std::fs::read(policy_peers_path(dd)).unwrap();
        assert!(at_rest::is_sealed_as(Kind::NodePolicyPeers, &sidecar));
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(
            !raw.contains("p2p_proxy") && !raw.contains("proxy.example"),
            "{raw}"
        );
        assert!(!peers_in_plain(dd));
        assert_eq!(try_load_policy(dd).unwrap(), proxy_only);
        // Saved sealed with relays: neither in node_policy.json.
        let both = NodePolicy {
            p2p_relays: vec!["/ip4/198.51.100.7/tcp/7423/p2p/relay".into()],
            p2p_proxy: "off".into(),
            ..proxy_only.clone()
        };
        save_policy(dd, &both).unwrap();
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(
            !raw.contains("p2p_proxy") && !raw.contains("p2p_relays"),
            "{raw}"
        );
        assert_eq!(try_load_policy(dd).unwrap(), both);
        // The way back (`raven privacy unseal`): into node_policy.json; and
        // the migration's move again.
        assert!(unseal_peers(dd).unwrap());
        assert!(!policy_peers_path(dd).exists());
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(raw.contains(r#""p2p_proxy": "off""#), "{raw}");
        assert_eq!(try_load_plain(dd).unwrap(), both);
        assert!(seal_peers(dd).unwrap());
        assert!(!peers_in_plain(dd));
        assert_eq!(try_load_policy(dd).unwrap(), both);
        // Both cleared (auto, no relays): no sidecar left.
        let cleared = NodePolicy {
            p2p_relays: Vec::new(),
            p2p_proxy: String::new(),
            ..both
        };
        save_policy(dd, &cleared).unwrap();
        assert!(!policy_peers_path(dd).exists());
        assert_eq!(try_load_policy(dd).unwrap(), cleared);
    }

    #[test]
    fn hide_ip_is_off_by_default_omitted_while_off_and_on_when_failing_closed() {
        let dir = tempdir().unwrap();
        // A file written before the field existed loads with it off.
        std::fs::write(
            policy_path(dir.path()),
            r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true,"custody":true}"#,
        )
        .unwrap();
        let old = try_load_policy(dir.path()).unwrap();
        assert!(!old.hide_ip && old.custody);
        assert!(!NodePolicy::default().hide_ip);
        // Off is not written at all (older readers see the same keys).
        save_policy(dir.path(), &NodePolicy::default()).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(!raw.contains("hide_ip"), "{raw}");
        // On round-trips.
        let on = NodePolicy {
            hide_ip: true,
            ..NodePolicy::default()
        };
        save_policy(dir.path(), &on).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(raw.contains(r#""hide_ip": true"#), "{raw}");
        assert_eq!(try_load_policy(dir.path()).unwrap(), on);
        // An unreadable policy shares no IP.
        assert!(NodePolicy::fail_closed().hide_ip);
        std::fs::write(policy_path(dir.path()), r#"{"hide_ip":"yes"}"#).unwrap();
        assert!(try_load_policy(dir.path()).is_err());
        assert!(load_policy(dir.path()).hide_ip);
    }

    const RELAY_OFFER_KEYS: [&str; 5] = [
        "relay_offer",
        "relay_auto",
        "relay_port",
        "relay_also_443",
        "relay_external",
    ];

    #[test]
    fn relay_offer_fields_default_off_round_trip_and_are_omitted_while_unset() {
        let dir = tempdir().unwrap();
        let d = NodePolicy::default();
        assert_eq!(
            (d.relay_offer, d.relay_auto, d.relay_port),
            (None, None, None)
        );
        assert!(!d.relay_also_443 && d.relay_external.is_empty());
        assert!(d.relay_auto_on(), "automatic relay choice is on by default");
        // Unset values are not written at all (older readers see the same keys).
        save_policy(dir.path(), &d).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        for key in RELAY_OFFER_KEYS {
            assert!(!raw.contains(key), "{key}: {raw}");
        }
        // Every value round-trips, and an explicit "no" is kept, not dropped.
        for (offer, auto) in [
            (Some(true), None),
            (Some(false), Some(false)),
            (None, Some(true)),
        ] {
            let p = NodePolicy {
                relay_offer: offer,
                relay_auto: auto,
                relay_port: Some(7428),
                relay_also_443: true,
                relay_external: vec![
                    "/dns4/home.example.net/tcp/7427".into(),
                    "/ip4/203.0.113.7/udp/7427/quic-v1".into(),
                ],
                ..NodePolicy::default()
            };
            save_policy(dir.path(), &p).unwrap();
            assert_eq!(try_load_policy(dir.path()).unwrap(), p);
            assert_eq!(p.relay_auto_on(), auto != Some(false), "{auto:?}");
        }
        // The legacy `relay` (the bridge/BLE same-transport relay) is its own
        // key: consent to relay for contacts neither sets it nor reads it.
        let offer = NodePolicy {
            relay_offer: Some(true),
            ..NodePolicy::default()
        };
        save_policy(dir.path(), &offer).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(raw.contains(r#""relay": false"#), "{raw}");
        assert!(raw.contains(r#""relay_offer": true"#), "{raw}");
        // An older reader (none of these fields) still reads a newer file.
        #[derive(Deserialize)]
        struct OlderReader {
            bridge: bool,
            relay: bool,
        }
        let older: OlderReader = serde_json::from_str(&raw).unwrap();
        assert!(older.bridge && !older.relay);
        // A wrong type is a corrupt file (fail closed), not "unset".
        for raw in [
            r#"{"relay_offer":"yes"}"#,
            r#"{"relay_auto":1}"#,
            r#"{"relay_port":70000}"#,
            r#"{"relay_also_443":"no"}"#,
            r#"{"relay_external":"/ip4/203.0.113.7/tcp/7427"}"#,
        ] {
            std::fs::write(policy_path(dir.path()), raw).unwrap();
            assert!(try_load_policy(dir.path()).is_err(), "{raw}");
        }
    }

    #[test]
    fn an_old_policy_file_reads_relay_offer_unset_and_auto_on() {
        let dir = tempdir().unwrap();
        // Written before the fields existed, with the legacy relay on.
        std::fs::write(
            policy_path(dir.path()),
            r#"{"bridge":true,"store":true,"relay":true,"endpoint":true,"auto_policy":true,"p2p_listen":"7423"}"#,
        )
        .unwrap();
        let old = try_load_policy(dir.path()).unwrap();
        assert!(old.relay, "the legacy relay stays as it was");
        assert_eq!(
            old.relay_offer, None,
            "the legacy relay is no consent to relay for contacts"
        );
        assert_eq!((old.relay_auto, old.relay_port), (None, None));
        assert!(old.relay_auto_on());
        assert!(!old.relay_also_443 && old.relay_external.is_empty());
        // Saved again unchanged, it gains none of the new keys.
        save_policy(dir.path(), &old).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        for key in RELAY_OFFER_KEYS {
            assert!(!raw.contains(key), "{key}: {raw}");
        }
    }

    #[test]
    fn fail_closed_never_offers() {
        let fc = NodePolicy::fail_closed();
        assert_eq!((fc.relay_offer, fc.relay_port), (None, None));
        assert!(!fc.relay_also_443 && fc.relay_external.is_empty());
        // A policy that said yes but cannot be read relays for nobody.
        let dir = tempdir().unwrap();
        std::fs::write(
            policy_path(dir.path()),
            r#"{"relay_offer":true,"relay_also_443":true,"relay_port":"7427"}"#,
        )
        .unwrap();
        assert!(try_load_policy(dir.path()).is_err());
        let loaded = load_policy(dir.path());
        assert_eq!(loaded, fc);
        assert_eq!(loaded.relay_offer, None);
        assert!(!loaded.relay_also_443);
    }

    #[test]
    fn internet_listen_normalises_bare_ips_to_the_default_port() {
        let ok = |s: &str| normalize_internet_listen(s).unwrap();
        assert_eq!(ok(""), None);
        assert_eq!(ok("  "), None);
        assert_eq!(ok("0.0.0.0:7422").as_deref(), Some("0.0.0.0:7422"));
        assert_eq!(ok("0.0.0.0").as_deref(), Some("0.0.0.0:7422"));
        assert_eq!(ok("::").as_deref(), Some("[::]:7422"));
        assert_eq!(ok("[::]").as_deref(), Some("[::]:7422"));
        assert_eq!(ok("[::1]:0").as_deref(), Some("[::1]:0"));
        assert_eq!(ok("127.0.0.1:0").as_deref(), Some("127.0.0.1:0"));
        assert_eq!(ok("localhost").as_deref(), Some("localhost:7422"));
        assert_eq!(ok("localhost:9000").as_deref(), Some("localhost:9000"));
        for bad in [
            "example.com:7422",
            "0.0.0.0:99999",
            "1.2.3.4:x",
            "[::1",
            "on",
        ] {
            assert!(normalize_internet_listen(bad).is_err(), "{bad}");
        }
    }

    /// Phase 3 P3.2: `raven lan off` is off by default, not written while
    /// off, round-trips, and is on when the policy cannot be read.
    #[test]
    fn lan_off_is_off_by_default_omitted_while_off_and_on_when_failing_closed() {
        let dir = tempdir().unwrap();
        // A file written before the field existed loads with it off.
        std::fs::write(
            policy_path(dir.path()),
            r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true,"hide_ip":true}"#,
        )
        .unwrap();
        let old = try_load_policy(dir.path()).unwrap();
        assert!(!old.lan_off && old.hide_ip);
        assert!(!NodePolicy::default().lan_off);
        // Off is not written at all (older readers see the same keys).
        save_policy(dir.path(), &NodePolicy::default()).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(!raw.contains("lan_off"), "{raw}");
        // On round-trips, and an older reader still reads the file.
        let on = NodePolicy {
            lan_off: true,
            ..NodePolicy::default()
        };
        save_policy(dir.path(), &on).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(raw.contains(r#""lan_off": true"#), "{raw}");
        assert_eq!(try_load_policy(dir.path()).unwrap(), on);
        #[derive(Deserialize)]
        struct OlderReader {
            bridge: bool,
        }
        let older: OlderReader = serde_json::from_str(&raw).unwrap();
        assert!(older.bridge);
        // LAN back on: the key goes away.
        save_policy(dir.path(), &NodePolicy::default()).unwrap();
        let raw = std::fs::read_to_string(policy_path(dir.path())).unwrap();
        assert!(!raw.contains("lan_off"), "{raw}");
        // An unreadable policy keeps off the local network (owner decision).
        assert!(NodePolicy::fail_closed().lan_off);
        std::fs::write(policy_path(dir.path()), r#"{"lan_off":"no"}"#).unwrap();
        assert!(try_load_policy(dir.path()).is_err());
        assert!(load_policy(dir.path()).lan_off);
    }

    /// Phase 3 P3.C2 (cutoff M1), `raven lan verified-only`: off by default
    /// and in a file written before the field existed, omitted while off, on
    /// round-trips (an older reader still reads the file), and on while the
    /// file cannot be read ([`lan_verified_only`] and the fail-closed policy).
    #[test]
    fn lan_verified_only_is_off_by_default_omitted_while_off_and_on_when_failing_closed() {
        let dir = tempdir().unwrap();
        let dd = dir.path();
        assert!(!lan_verified_only(dd), "no file: the default");
        std::fs::write(
            policy_path(dd),
            r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true,"lan_off":true}"#,
        )
        .unwrap();
        let old = try_load_policy(dd).unwrap();
        assert!(!old.lan_verified_only && old.lan_off);
        assert!(!lan_verified_only(dd));
        assert!(!NodePolicy::default().lan_verified_only);
        save_policy(dd, &NodePolicy::default()).unwrap();
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(!raw.contains("lan_verified_only"), "{raw}");
        let on = NodePolicy {
            lan_verified_only: true,
            ..NodePolicy::default()
        };
        save_policy(dd, &on).unwrap();
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(raw.contains(r#""lan_verified_only": true"#), "{raw}");
        assert_eq!(try_load_policy(dd).unwrap(), on);
        assert!(lan_verified_only(dd));
        #[derive(Deserialize)]
        struct OlderReader {
            bridge: bool,
        }
        let older: OlderReader = serde_json::from_str(&raw).unwrap();
        assert!(older.bridge);
        // The fail-closed policy is the narrower one.
        assert!(NodePolicy::fail_closed().lan_verified_only);
        std::fs::write(policy_path(dd), r#"{"lan_verified_only":1}"#).unwrap();
        assert!(try_load_policy(dd).is_err());
        assert!(lan_verified_only(dd));
        assert!(load_policy(dd).lan_verified_only);
    }

    /// `raven lan verified-only on|off` changes that setting alone, every
    /// other setting kept, and writes nothing over a file it cannot read
    /// (`raven lan on` repairs that one).
    #[test]
    fn set_lan_verified_only_keeps_every_other_setting_and_never_repairs() {
        let dir = tempdir().unwrap();
        let dd = dir.path();
        let custom = NodePolicy {
            bridge: false,
            hide_ip: true,
            lan_off: true,
            p2p_listen: "7423".into(),
            ..NodePolicy::default()
        };
        save_policy(dd, &custom).unwrap();
        for on in [true, false] {
            assert_eq!(set_lan_verified_only(dd, on).unwrap(), LanOffSaved::Saved);
            assert_eq!(
                try_load_policy(dd).unwrap(),
                NodePolicy {
                    lan_verified_only: on,
                    ..custom.clone()
                }
            );
            assert_eq!(lan_verified_only(dd), on);
        }
        std::fs::write(policy_path(dd), b"{\"bridge\": tru").unwrap();
        match set_lan_verified_only(dd, false).unwrap() {
            LanOffSaved::Unreadable {
                repaired: false, ..
            } => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(
            std::fs::read(policy_path(dd)).unwrap(),
            b"{\"bridge\": tru",
            "nothing written"
        );
        assert!(!dd.join(POLICY_BAD_FILE).exists());
        assert!(lan_verified_only(dd), "fail closed while it cannot be read");
    }

    /// Phase 3 P3.6, `raven lan on|off`: `lan_off` alone changes, every other
    /// setting stays; an unreadable file is left as it is unless the caller
    /// repairs it (`raven lan on`): then its bytes are kept as
    /// node_policy.json.bad and the fail-closed policy with that `lan_off`
    /// takes its place.
    #[test]
    fn set_lan_off_keeps_every_other_setting_and_repairs_only_when_asked() {
        let dir = tempdir().unwrap();
        let dd = dir.path();
        // No file yet: the default policy with the change.
        assert_eq!(set_lan_off(dd, true, false).unwrap(), LanOffSaved::Saved);
        assert_eq!(
            try_load_policy(dd).unwrap(),
            NodePolicy {
                lan_off: true,
                ..NodePolicy::default()
            }
        );
        let custom = NodePolicy {
            bridge: false,
            relay: true,
            auto_policy: false,
            internet_listen: "0.0.0.0:7422".into(),
            p2p_listen: "7423".into(),
            p2p_relays: vec!["/ip4/198.51.100.7/tcp/7423/p2p/relay".into()],
            upnp: Some(false),
            custody: true,
            hide_ip: true,
            relay_offer: Some(true),
            relay_port: Some(7428),
            ..NodePolicy::default()
        };
        save_policy(dd, &custom).unwrap();
        for off in [true, false, true] {
            assert_eq!(set_lan_off(dd, off, false).unwrap(), LanOffSaved::Saved);
            assert_eq!(
                try_load_policy(dd).unwrap(),
                NodePolicy {
                    lan_off: off,
                    ..custom.clone()
                }
            );
        }
        assert!(!dd.join(POLICY_BAD_FILE).exists());

        // Unreadable: nothing written without `repair`.
        let corrupt = b"{\"bridge\": tru".to_vec();
        std::fs::write(policy_path(dd), &corrupt).unwrap();
        match set_lan_off(dd, false, false).unwrap() {
            LanOffSaved::Unreadable {
                why,
                repaired: false,
            } => assert!(!why.is_empty()),
            other => panic!("{other:?}"),
        }
        assert_eq!(std::fs::read(policy_path(dd)).unwrap(), corrupt);
        assert!(!dd.join(POLICY_BAD_FILE).exists());
        // Repaired: the old bytes kept, the fail-closed policy with LAN on.
        assert!(matches!(
            set_lan_off(dd, false, true).unwrap(),
            LanOffSaved::Unreadable { repaired: true, .. }
        ));
        assert_eq!(std::fs::read(dd.join(POLICY_BAD_FILE)).unwrap(), corrupt);
        assert_eq!(
            try_load_policy(dd).unwrap(),
            NodePolicy {
                lan_off: false,
                ..NodePolicy::fail_closed()
            }
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dd.join(POLICY_BAD_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // A later repair keeps the newer bad file.
        std::fs::write(policy_path(dd), b"not json").unwrap();
        set_lan_off(dd, false, true).unwrap();
        assert_eq!(
            std::fs::read(dd.join(POLICY_BAD_FILE)).unwrap(),
            b"not json"
        );
        // The copy is a registered profile file: `raven erase` removes it.
        assert!(crate::at_rest::rule_for(POLICY_BAD_FILE).is_some_and(|rule| rule.erase));
    }

    /// A policy file whose bytes cannot be read at all is kept under the
    /// second name without a copy (a hard link) and replaced; skipped where
    /// the file stays readable (a root test run).
    #[cfg(unix)]
    #[test]
    fn set_lan_off_keeps_a_policy_it_cannot_even_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let dd = dir.path();
        std::fs::write(policy_path(dd), b"{\"bridge\": false}").unwrap();
        std::fs::set_permissions(policy_path(dd), std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(policy_path(dd)).is_ok() {
            return;
        }
        assert!(matches!(
            set_lan_off(dd, false, true).unwrap(),
            LanOffSaved::Unreadable { repaired: true, .. }
        ));
        let bad = dd.join(POLICY_BAD_FILE);
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(&bad).unwrap(), b"{\"bridge\": false}");
        assert_eq!(
            try_load_policy(dd).unwrap(),
            NodePolicy {
                lan_off: false,
                ..NodePolicy::fail_closed()
            }
        );
    }

    /// In a sealed profile `raven lan on|off` writes `node_policy.json` alone:
    /// the relay sidecar keeps its bytes, also through a repair, and its
    /// relays are read back with the new file.
    #[test]
    fn set_lan_off_in_a_sealed_profile_never_touches_the_relay_sidecar() {
        let dir = crate::contact_book::tests::profile();
        let dd = dir.path();
        crate::contact_book::tests::seal(dd);
        let policy = NodePolicy {
            p2p_listen: "7423".into(),
            p2p_relays: vec!["/ip4/198.51.100.7/tcp/7423/p2p/relay".into()],
            ..NodePolicy::default()
        };
        save_policy(dd, &policy).unwrap();
        let sidecar = std::fs::read(policy_peers_path(dd)).unwrap();
        assert_eq!(set_lan_off(dd, true, false).unwrap(), LanOffSaved::Saved);
        assert_eq!(std::fs::read(policy_peers_path(dd)).unwrap(), sidecar);
        assert_eq!(
            try_load_policy(dd).unwrap(),
            NodePolicy {
                lan_off: true,
                ..policy.clone()
            }
        );
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(!raw.contains("p2p_relays"), "{raw}");
        std::fs::write(policy_path(dd), b"not json").unwrap();
        assert!(matches!(
            set_lan_off(dd, false, true).unwrap(),
            LanOffSaved::Unreadable { repaired: true, .. }
        ));
        assert_eq!(std::fs::read(policy_peers_path(dd)).unwrap(), sidecar);
        let repaired = try_load_policy(dd).unwrap();
        assert_eq!(repaired.p2p_relays, policy.p2p_relays);
        assert!(!repaired.lan_off && !repaired.bridge && repaired.hide_ip);
    }

    /// Phase 3 P3.16: the friend-mailbox consent and the home custodians
    /// are unset by default and when failing closed, omitted from the file
    /// while unset, round-trip, and an older file reads them unset.
    #[test]
    fn custody_use_and_home_default_unset_round_trip_and_are_omitted_while_unset() {
        let dir = tempdir().unwrap();
        let dd = dir.path();
        for policy in [NodePolicy::default(), NodePolicy::fail_closed()] {
            assert_eq!(policy.custody_use, None);
            assert!(policy.custody_home.is_empty());
        }
        // A file written before the fields existed.
        std::fs::write(
            policy_path(dd),
            r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true,"custody":true}"#,
        )
        .unwrap();
        let old = try_load_policy(dd).unwrap();
        assert!(old.custody && old.auto_policy);
        assert_eq!((old.custody_use, old.custody_home.len()), (None, 0));
        // Unset is not written at all.
        save_policy(dd, &NodePolicy::default()).unwrap();
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(
            !raw.contains("custody_use") && !raw.contains("custody_home"),
            "{raw}"
        );
        // Set round-trips, and nothing else changes.
        let home = vec!["ab".repeat(32), "cd".repeat(32)];
        for answer in [true, false] {
            let set = NodePolicy {
                custody_use: Some(answer),
                custody_home: home.clone(),
                ..old.clone()
            };
            save_policy(dd, &set).unwrap();
            let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
            assert!(
                raw.contains(&format!(r#""custody_use": {answer}"#)),
                "{raw}"
            );
            assert!(raw.contains(&home[1]), "{raw}");
            let loaded = try_load_policy(dd).unwrap();
            assert_eq!(loaded, set);
            assert!(
                loaded.auto_policy && loaded.custody,
                "the other settings are kept"
            );
        }
        // An unreadable policy uses no friend as a mailbox.
        std::fs::write(policy_path(dd), r#"{"custody_use":"yes"}"#).unwrap();
        assert!(try_load_policy(dd).is_err());
        let closed = load_policy(dd);
        assert_eq!((closed.custody_use, closed.custody_home.len()), (None, 0));
    }

    /// Phase 5 P5.17: multi-hop custody consent is off unless set, omitted
    /// from the file while off (older files and readers see the same keys),
    /// round-trips without touching the other settings, and an unreadable
    /// policy passes nothing on.
    #[test]
    fn custody_handoff_is_off_by_default_omitted_while_off_and_off_when_failing_closed() {
        let dir = tempdir().unwrap();
        let dd = dir.path();
        assert!(!NodePolicy::default().custody_handoff);
        assert!(!NodePolicy::fail_closed().custody_handoff);
        // A file written before the field existed loads with it off.
        std::fs::write(
            policy_path(dd),
            r#"{"bridge":true,"store":true,"relay":false,"endpoint":true,"auto_policy":true,"custody":true}"#,
        )
        .unwrap();
        let old = try_load_policy(dd).unwrap();
        assert!(!old.custody_handoff && old.custody && old.auto_policy);
        // Off is not written at all.
        save_policy(dd, &old).unwrap();
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(!raw.contains("custody_handoff"), "{raw}");
        assert!(raw.contains(r#""custody": true"#), "{raw}");
        // On round-trips, and nothing else changes.
        let on = NodePolicy {
            custody_handoff: true,
            ..old.clone()
        };
        save_policy(dd, &on).unwrap();
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(raw.contains(r#""custody_handoff": true"#), "{raw}");
        let loaded = try_load_policy(dd).unwrap();
        assert_eq!(loaded, on);
        assert_eq!(
            NodePolicy {
                custody_handoff: false,
                ..loaded
            },
            old,
            "the other settings are kept"
        );
        // And off again drops the key.
        save_policy(dd, &old).unwrap();
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(!raw.contains("custody_handoff"), "{raw}");
        assert_eq!(try_load_policy(dd).unwrap(), old);
        // A policy that said yes but cannot be read passes nothing on.
        std::fs::write(
            policy_path(dd),
            r#"{"custody":true,"custody_handoff":"yes"}"#,
        )
        .unwrap();
        assert!(try_load_policy(dd).is_err());
        let closed = load_policy(dd);
        assert!(!closed.custody_handoff && !closed.custody);
        assert_eq!(closed, NodePolicy::fail_closed());
    }

    /// Phase 3 P3.16: the home custodians name friends, so a sealed profile
    /// keeps them only in the sealed sidecar (the migration moves them there,
    /// a save writes them there, a load merges them); `custody_use` stays in
    /// node_policy.json. The way back puts them into node_policy.json again.
    #[test]
    fn custody_home_lives_in_the_sealed_sidecar() {
        let dir = crate::contact_book::tests::profile();
        let dd = dir.path();
        let home = vec!["ab".repeat(32)];
        let policy = NodePolicy {
            custody_use: Some(true),
            custody_home: home.clone(),
            ..NodePolicy::default()
        };
        save_policy(dd, &policy).unwrap();
        assert!(peers_in_plain(dd), "a plain profile keeps them in plain");
        crate::contact_book::tests::seal(dd);
        assert!(!peers_in_plain(dd));
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(raw.contains(r#""custody_use": true"#), "{raw}");
        assert!(
            !raw.contains("custody_home") && !raw.contains(&home[0]),
            "{raw}"
        );
        let sidecar = std::fs::read(policy_peers_path(dd)).unwrap();
        assert!(at_rest::is_sealed(&sidecar));
        assert_eq!(try_load_policy(dd).unwrap(), policy);
        // A save in the sealed profile writes them to the sidecar only.
        let two = NodePolicy {
            custody_home: vec!["ab".repeat(32), "cd".repeat(32)],
            ..policy.clone()
        };
        save_policy(dd, &two).unwrap();
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(!raw.contains("custody_home"), "{raw}");
        assert_eq!(try_load_policy(dd).unwrap(), two);
        // `raven lan off` (node_policy.json alone) keeps them.
        assert_eq!(set_lan_off(dd, true, false).unwrap(), LanOffSaved::Saved);
        assert_eq!(try_load_policy(dd).unwrap().custody_home, two.custody_home);
        // Automatic again: no sidecar left.
        let auto = NodePolicy {
            custody_home: Vec::new(),
            ..try_load_policy(dd).unwrap()
        };
        save_policy(dd, &auto).unwrap();
        assert!(!policy_peers_path(dd).exists());
        assert_eq!(try_load_policy(dd).unwrap(), auto);
        // The way back.
        save_policy(dd, &two).unwrap();
        assert!(unseal_peers(dd).unwrap());
        assert!(!policy_peers_path(dd).exists());
        let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
        assert!(raw.contains(&two.custody_home[1]), "{raw}");
    }

    /// P6.31's "Pause sending": one contact held and lifted again, every
    /// other setting kept; in a sealed profile the keys live only in the
    /// sealed sidecar; the cap refuses a new hold and changes nothing.
    #[test]
    fn send_hold_pauses_one_contact_and_lives_in_the_sealed_sidecar() {
        let sara = [0x5a; 32];
        let rena = [0x7e; 32];
        for sealed in [false, true] {
            let dir = crate::contact_book::tests::profile();
            let dd = dir.path();
            save_policy(
                dd,
                &NodePolicy {
                    lan_off: true,
                    custody_home: vec!["ab".repeat(32)],
                    ..NodePolicy::default()
                },
            )
            .unwrap();
            if sealed {
                crate::contact_book::tests::seal(dd);
            }
            assert!(!load_policy(dd).send_held(&sara));
            assert!(set_send_hold(dd, &sara, true).unwrap());
            assert!(set_send_hold(dd, &sara, true).unwrap(), "twice: kept once");
            let now = try_load_policy(dd).unwrap();
            assert_eq!(now.send_hold, vec![hex::encode(sara)]);
            assert!(now.send_held(&sara) && !now.send_held(&rena));
            assert!(now.lan_off && now.custody_home.len() == 1, "{now:?}");
            let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
            assert_eq!(
                raw.contains(&hex::encode(sara)),
                !sealed,
                "sealed: only in the sidecar\n{raw}"
            );
            assert!(!set_send_hold(dd, &sara, false).unwrap());
            assert!(!set_send_hold(dd, &rena, false).unwrap(), "nothing to lift");
            let now = try_load_policy(dd).unwrap();
            assert!(now.send_hold.is_empty() && now.lan_off, "{now:?}");
            assert!(!std::fs::read_to_string(policy_path(dd))
                .unwrap()
                .contains("send_hold"));
        }
        // The cap: a new hold is refused, an old one can still be lifted.
        let dir = crate::contact_book::tests::profile();
        let dd = dir.path();
        let full = NodePolicy {
            send_hold: (0..MAX_SEND_HOLD).map(|i| format!("{i:064x}")).collect(),
            ..NodePolicy::default()
        };
        save_policy(dd, &full).unwrap();
        assert!(matches!(
            set_send_hold(dd, &sara, true),
            Err(PolicyError::Write(_))
        ));
        assert_eq!(try_load_policy(dd).unwrap(), full);
        let first: [u8; 32] = hex::decode(&full.send_hold[0]).unwrap().try_into().unwrap();
        assert!(!set_send_hold(dd, &first, false).unwrap());
        assert!(set_send_hold(dd, &sara, true).unwrap());
    }

    /// Review D-6: `update_policy` reads the policy again and changes one
    /// field, so what another writer saved meanwhile (`raven lan off`, a
    /// home list in the sealed sidecar) stays; an unreadable policy writes
    /// nothing.
    #[test]
    fn update_policy_changes_one_field_of_what_is_saved_now() {
        for sealed in [false, true] {
            let dir = crate::contact_book::tests::profile();
            let dd = dir.path();
            let home = vec!["ab".repeat(32)];
            save_policy(
                dd,
                &NodePolicy {
                    custody_home: home.clone(),
                    ..NodePolicy::default()
                },
            )
            .unwrap();
            if sealed {
                crate::contact_book::tests::seal(dd);
            }
            // A copy read before a question...
            let stale = try_load_policy(dd).unwrap();
            assert!(!stale.lan_off);
            // ...another writer meanwhile...
            assert_eq!(set_lan_off(dd, true, false).unwrap(), LanOffSaved::Saved);
            // ...and the answer.
            let saved = update_policy(dd, |p| p.custody_use = Some(true)).unwrap();
            let now = try_load_policy(dd).unwrap();
            assert_eq!(now, saved);
            assert_eq!(
                (now.custody_use, now.lan_off, now.custody_home.clone()),
                (Some(true), true, home.clone()),
                "sealed={sealed}"
            );
            assert_eq!(peers_in_plain(dd), !sealed);
            // Unreadable: an error, nothing written.
            std::fs::write(policy_path(dd), b"{not json").unwrap();
            assert!(update_policy(dd, |p| p.custody = true).is_err());
            assert_eq!(std::fs::read(policy_path(dd)).unwrap(), b"{not json");
        }
    }

    /// Phase 6b P6.36: what a profile may pick. Never 7420 or another port
    /// Raven uses, nothing outside 20,000-59,999, no well-known port and
    /// nothing in IANA's dynamic range.
    #[test]
    fn lan_port_pickable_table() {
        for (port, want) in [
            (crate::paths::DEFAULT_LAN_PORT, false),
            (7_421, false),
            (19_999, false),
            (20_000, false),
            (20_001, true),
            (22_000, false),
            (25_570, false),
            (27_017, false),
            (32_400, false),
            (32_470, true),
            (43_210, true),
            (49_151, true),
            (49_152, false),
            (59_999, false),
            (60_000, false),
            (u16::MAX, false),
        ] {
            assert_eq!(lan_port_pickable(port), want, "{port}");
        }
        for &(from, to) in &SKIPPED_LAN_PORTS {
            assert!(
                from <= to && RANDOM_LAN_PORTS.contains(&from),
                "{from}-{to}"
            );
        }
        let pickable = RANDOM_LAN_PORTS.filter(|&p| lan_port_pickable(p)).count();
        assert!(pickable > 28_000, "{pickable}");
    }

    /// P6.36: the pick takes the first drawn port that is pickable, not
    /// `avoid` and free; it never returns 7420, and gives up after
    /// PICK_TRIES draws.
    #[test]
    fn pick_lan_port_skips_what_it_may_not_take() {
        let mut drawn = vec![
            crate::paths::DEFAULT_LAN_PORT,
            27_017,
            43_210,
            43_211,
            43_212,
            43_213,
        ]
        .into_iter();
        let port = pick_lan_port(
            || drawn.next().unwrap(),
            |port| port != 43_211,
            Some(43_210),
        );
        assert_eq!(port, Some(43_212));
        let mut draws = 0;
        assert_eq!(
            pick_lan_port(
                || {
                    draws += 1;
                    43_210
                },
                |_| false,
                None
            ),
            None
        );
        assert_eq!(draws, PICK_TRIES);
        // The real draw and bind test: a free, pickable port.
        for _ in 0..20 {
            let port = pick_free_lan_port(Some(43_210)).expect("a free port");
            assert!(lan_port_pickable(port) && port != 43_210, "{port}");
        }
    }

    /// P6.36: a new profile picks and saves its port only while the gate is
    /// live (no file is written while it is shut); a port the file already
    /// names is kept; the port survives a reload (a restart reads the same
    /// file) and `raven lan port random` moves it and nothing else.
    #[test]
    fn new_profile_port_is_saved_and_kept() {
        use crate::security_gate::set_lab_for_this_thread;
        let dir = tempdir().unwrap();
        let dd = dir.path();
        set_lab_for_this_thread(SecGate::RandomPort, Some(false));
        assert_eq!(pick_lan_port_for_new_profile(dd), None);
        assert_eq!(pick_new_lan_port(dd).unwrap(), None);
        assert!(!policy_path(dd).exists());
        assert_eq!(profile_lan_port(dd), None);
        if cfg!(debug_assertions) {
            set_lab_for_this_thread(SecGate::RandomPort, Some(true));
            let port = pick_lan_port_for_new_profile(dd).expect("a port");
            assert!(lan_port_pickable(port), "{port}");
            assert_eq!(try_load_policy(dd).unwrap().lan_listen_port, Some(port));
            assert_eq!(profile_lan_port(dd), Some(port));
            // Picked again (it never is for one profile): the saved one stays.
            assert_eq!(pick_lan_port_for_new_profile(dd), Some(port));
            assert_eq!(profile_lan_port(dd), Some(port));
            // `raven lan port random`: a new port, only that field.
            update_policy(dd, |p| p.lan_off = true).unwrap();
            let moved = pick_new_lan_port(dd).unwrap().expect("a new port");
            assert!(moved != port && lan_port_pickable(moved), "{moved}");
            let now = try_load_policy(dd).unwrap();
            assert_eq!((now.lan_listen_port, now.lan_off), (Some(moved), true));
            assert_eq!(profile_lan_port(dd), Some(moved));
            // Shut again: the saved port is ignored, nothing is written.
            set_lab_for_this_thread(SecGate::RandomPort, Some(false));
            let before = std::fs::read(policy_path(dd)).unwrap();
            assert_eq!(profile_lan_port(dd), None);
            assert_eq!(pick_new_lan_port(dd).unwrap(), None);
            assert_eq!(std::fs::read(policy_path(dd)).unwrap(), before);
            // An unreadable policy: no port, nothing written.
            set_lab_for_this_thread(SecGate::RandomPort, Some(true));
            std::fs::write(policy_path(dd), b"{not json").unwrap();
            assert_eq!(profile_lan_port(dd), None);
            assert_eq!(pick_lan_port_for_new_profile(dd), None);
            assert!(pick_new_lan_port(dd).is_err());
            assert_eq!(std::fs::read(policy_path(dd)).unwrap(), b"{not json");
            // Port 0 written by hand is no chosen port.
            std::fs::write(policy_path(dd), br#"{"lan_listen_port":0}"#).unwrap();
            assert_eq!(profile_lan_port(dd), None);
        }
        set_lab_for_this_thread(SecGate::RandomPort, None);
    }

    /// P6.36. Runs in both builds: the release test job sets
    /// `RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_RANDOM_PORT=1`, and no new profile
    /// picks a port and none is read (the variables are never read); a
    /// debug build follows exactly the variables.
    #[test]
    fn random_port_lab_switch_is_inert_in_release() {
        let lab = cfg!(debug_assertions)
            && std::env::var("RAVEN_LAB_TEST_A").as_deref() == Ok("1")
            && std::env::var(crate::security_gate::LAB_RANDOM_PORT).as_deref() == Ok("1");
        let want = crate::security_gate::LISTEN_PORT_RANDOM_PRODUCTION_ENABLED || lab;
        assert_eq!(live(SecGate::RandomPort), want);
        let dir = tempdir().unwrap();
        let picked = pick_lan_port_for_new_profile(dir.path());
        assert_eq!(picked.is_some(), want);
        assert_eq!(policy_path(dir.path()).exists(), want);
        assert_eq!(profile_lan_port(dir.path()), picked);
    }

    #[cfg(unix)]
    #[test]
    fn save_tightens_mode_of_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = policy_path(dir.path());
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_policy(dir.path(), &NodePolicy::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
