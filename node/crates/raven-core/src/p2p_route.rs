//! Text rules for libp2p routes (P3, transports design 2026-10 §3.1-§3.2):
//! PeerIds and `via=` multiaddrs in contact cards, the contact book, the
//! outbox and node policy, and a relay's own listen and public addresses.
//! There is one host grammar for all of them.
//!
//! No libp2p dependency: `raven` parses and prints cards with these functions
//! alone, and raven-node re-parses with the real `Multiaddr` before it dials.
//! The grammar is deliberately narrow (one host part, one transport, one
//! terminal `/p2p/<PeerId>`; after TCP only the WebSocket-over-TLS suffix of
//! `protocol/RAVEN_WSS_TRANSPORT_V1.md` §2), so a card cannot smuggle a
//! circuit, a second peer or an unexpected protocol into a route.
//!
//! A PeerId names a libp2p key only, never a Raven identity: every p2p link
//! runs the Raven Noise link with the RIH1 identity bind inside the libp2p
//! stream, and the dialer accepts only the contact's pinned key. A card's
//! `p2p=` value is therefore a reachability hint, never trusted.

use crate::identity::Identity;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zeroize::Zeroizing;

/// libp2p TCP and UDP (QUIC) port of the endpoint service and the relay.
pub const DEFAULT_P2P_PORT: u16 = 7423;
/// TCP and UDP (QUIC) port of the friend relay inside `raven-node service`
/// (any-network plan C6): a port of its own, since it runs under its own
/// relay key, never the profile's PeerId on [`DEFAULT_P2P_PORT`].
pub const FRIEND_RELAY_PORT: u16 = 7427;
/// Relays one node reserves on, and `via=` entries one card carries.
pub const MAX_VIA: usize = 2;
/// Longest multiaddr text accepted anywhere (real ones are far shorter).
pub const MAX_MULTIADDR_CHARS: usize = 300;
/// Domain of the libp2p key derived from a Raven seed: the PeerId is stable
/// per profile but is not the Raven address.
pub const LIBP2P_KEY_DOMAIN: &[u8] = b"raven/libp2p-peer-key/v1";

/// Multihash prefix of an Ed25519 PeerId: identity hash (0x00) of 36 bytes,
/// holding the protobuf `PublicKey { Type: Ed25519 (1), Data: 32 bytes }`.
const ED25519_PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
/// Length of an Ed25519 PeerId in bytes (the multihash prefix plus the key):
/// the binary form RRH1 route hints carry ([`peer_id_bytes`]).
pub const PEER_ID_BYTES: usize = ED25519_PEER_ID_PREFIX.len() + 32;

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    // Base-58 digits, least significant first.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in &bytes[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|d| B58[*d as usize] as char));
    out
}

fn base58_decode(text: &str) -> Option<Vec<u8>> {
    let zeros = text.bytes().take_while(|b| *b == b'1').count();
    // Base-256 digits, least significant first.
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.bytes().skip(zeros) {
        let mut carry = B58.iter().position(|a| *a == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

/// The libp2p Ed25519 secret key seed of this Raven profile:
/// `SHA-256(LIBP2P_KEY_DOMAIN || raven seed)`. Same derivation `raven-swarm`
/// has always used, so PeerIds do not change.
pub fn libp2p_ed25519_seed(id: &Identity) -> Zeroizing<[u8; 32]> {
    let seed = id.seed_zeroizing();
    let mut h = Sha256::new();
    h.update(LIBP2P_KEY_DOMAIN);
    h.update(seed.as_slice());
    Zeroizing::new(h.finalize().into())
}

/// Public half of [`libp2p_ed25519_seed`].
pub fn libp2p_ed25519_public(id: &Identity) -> [u8; 32] {
    let seed = libp2p_ed25519_seed(id);
    ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
}

/// The text form (`12D3KooW…`) of the PeerId of an Ed25519 libp2p key.
pub fn peer_id_from_ed25519_public(public: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(PEER_ID_BYTES);
    bytes.extend_from_slice(&ED25519_PEER_ID_PREFIX);
    bytes.extend_from_slice(public);
    base58_encode(&bytes)
}

/// This profile's own PeerId (what `raven whoami --card` prints as `p2p=`).
pub fn local_peer_id(id: &Identity) -> String {
    peer_id_from_ed25519_public(&libp2p_ed25519_public(id))
}

/// The PeerId this profile is reachable under: the fixed [`local_peer_id`]
/// while rotation is off (`None`), else epoch `e`'s key
/// ([`crate::peer_rotation::epoch_public`], Phase 4 PeerId rotation). Every
/// caller that names this node's own PeerId goes through it.
pub fn active_peer_id(id: &Identity, rotation: Option<u64>) -> String {
    match rotation {
        None => local_peer_id(id),
        Some(epoch) => crate::peer_rotation::epoch_peer_id(id, epoch),
    }
}

/// Strict PeerId parse: only the Ed25519 identity-multihash form Raven nodes
/// and relays use (`12D3KooW…`, 52 characters). Returns the libp2p public key.
pub fn parse_peer_id(text: &str) -> Result<[u8; 32], String> {
    let t = text.trim();
    if t.len() != 52 || !t.starts_with("12D3KooW") {
        return Err("a PeerId looks like 12D3KooW… (52 characters, an Ed25519 libp2p key)".into());
    }
    let bytes = base58_decode(t).ok_or("PeerId is not base58")?;
    if bytes.len() != PEER_ID_BYTES
        || bytes[..ED25519_PEER_ID_PREFIX.len()] != ED25519_PEER_ID_PREFIX
    {
        return Err("PeerId is not an Ed25519 libp2p key".into());
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&bytes[ED25519_PEER_ID_PREFIX.len()..]);
    // Canonical form only: re-encoding must give the same text.
    if peer_id_from_ed25519_public(&public) != t {
        return Err("PeerId is not in canonical form".into());
    }
    Ok(public)
}

/// [`parse_peer_id`], returning the canonical text.
pub fn normalize_peer_id(text: &str) -> Result<String, String> {
    parse_peer_id(text).map(|public| peer_id_from_ed25519_public(&public))
}

/// The binary form of a PeerId (`00 24 08 01 12 20 || ed25519_pub32`, the
/// RRH1 `P2P_ID` value), after the strict [`parse_peer_id`].
pub fn peer_id_bytes(text: &str) -> Result<[u8; PEER_ID_BYTES], String> {
    let public = parse_peer_id(text)?;
    let mut out = [0u8; PEER_ID_BYTES];
    out[..ED25519_PEER_ID_PREFIX.len()].copy_from_slice(&ED25519_PEER_ID_PREFIX);
    out[ED25519_PEER_ID_PREFIX.len()..].copy_from_slice(&public);
    Ok(out)
}

/// The canonical text of a binary PeerId; only the Ed25519 identity-multihash
/// form is accepted (the inverse of [`peer_id_bytes`]).
pub fn peer_id_from_bytes(bytes: &[u8; PEER_ID_BYTES]) -> Result<String, String> {
    let (prefix, public) = bytes.split_at(ED25519_PEER_ID_PREFIX.len());
    if prefix != ED25519_PEER_ID_PREFIX {
        return Err("PeerId is not an Ed25519 libp2p key".into());
    }
    let public: &[u8; 32] = public
        .try_into()
        .map_err(|_| "PeerId is not an Ed25519 libp2p key")?;
    Ok(peer_id_from_ed25519_public(public))
}

/// A DNS name the WSS transport can also send as TLS SNI (RWS1 §2.1, the
/// rule rustls's `ServerName` applies; review A-5): at most 253 characters,
/// one trailing dot allowed, labels of 1-63 letters, digits and `-`, none
/// starting or ending with `-`, and a last label that is not all digits (so
/// never an IPv4 literal).
fn plausible_dns_name(name: &str) -> bool {
    let labels = name.strip_suffix('.').unwrap_or(name);
    !labels.is_empty()
        && name.len() <= 253
        && labels.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && !labels
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
}

fn parse_port(text: &str) -> Result<u16, String> {
    match text.parse::<u16>() {
        Ok(p) if p != 0 && text == p.to_string() => Ok(p),
        _ => Err(format!(
            "port \"{}\" must be 1-65535",
            crate::sanitize::sanitize_terminal_line(text)
        )),
    }
}

/// Why [`parse_host`] refused a host part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostRefusal {
    /// Not an IP address of that family, or not a plausible DNS name.
    Malformed,
    /// An IP address that names no single host (unspecified, multicast,
    /// broadcast).
    NoSingleHost,
}

/// The one host grammar of every route text (`via=`, a relay's own
/// addresses, `--public-host`, `raven relay card --host`): `kind` is `ip4`,
/// `ip6`, `dns`, `dns4` or `dns6`, and `value` an IP address of that family
/// naming a single host, or a plausible DNS name. Canonical text:
/// `/ip6/2001:db8::1`, lowercase names.
fn parse_host(kind: &str, value: &str) -> Result<String, HostRefusal> {
    match kind {
        "ip4" => {
            let ip: Ipv4Addr = value.parse().map_err(|_| HostRefusal::Malformed)?;
            if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                return Err(HostRefusal::NoSingleHost);
            }
            Ok(format!("/ip4/{ip}"))
        }
        "ip6" => {
            let ip: Ipv6Addr = value.parse().map_err(|_| HostRefusal::Malformed)?;
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(HostRefusal::NoSingleHost);
            }
            Ok(format!("/ip6/{ip}"))
        }
        "dns" | "dns4" | "dns6" if plausible_dns_name(value) => {
            Ok(format!("/{kind}/{}", value.to_ascii_lowercase()))
        }
        _ => Err(HostRefusal::Malformed),
    }
}

/// The `/`-separated parts of a route text, once it passed the size and
/// character check every route text gets.
fn multiaddr_parts<'a>(
    t: &'a str,
    shown: &str,
    usage: &dyn Fn() -> String,
) -> Result<Vec<&'a str>, String> {
    if t.len() > MAX_MULTIADDR_CHARS || !t.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "address \"{shown}\" is not a multiaddr (at most {MAX_MULTIADDR_CHARS} plain characters)"
        ));
    }
    let Some(rest) = t.strip_prefix('/') else {
        return Err(usage());
    };
    Ok(rest.split('/').collect())
}

/// The host ([`parse_host`]) and the transport (`tcp/PORT` or
/// `udp/PORT/quic-v1`) that start `parts`: their canonical text, and how
/// many parts they took.
fn host_and_transport(
    parts: &[&str],
    shown: &str,
    usage: &dyn Fn() -> String,
) -> Result<(String, usize), String> {
    let (Some(kind), Some(value)) = (parts.first(), parts.get(1)) else {
        return Err(usage());
    };
    let mut out = parse_host(kind, value).map_err(|e| match e {
        HostRefusal::Malformed => usage(),
        HostRefusal::NoSingleHost => format!("address \"{shown}\" names no single host"),
    })?;
    match (parts.get(2), parts.get(3), parts.get(4)) {
        (Some(&"tcp"), Some(port), _) => {
            out.push_str(&format!("/tcp/{}", parse_port(port)?));
            Ok((out, 4))
        }
        (Some(&"udp"), Some(port), Some(&"quic-v1")) => {
            out.push_str(&format!("/udp/{}/quic-v1", parse_port(port)?));
            Ok((out, 5))
        }
        _ => Err(usage()),
    }
}

/// One parsed `via=` address: `/<ip4|ip6|dns|dns4|dns6>/<host>/<tcp/PORT
/// [/tls/ws | /tls/sni/NAME/ws] | udp/PORT/quic-v1>/p2p/<PeerId>`. A relay's
/// address, or (when the PeerId is the contact's own) a direct address of the
/// contact. Never a circuit. The `/tls…/ws` suffix is WebSocket over TLS
/// (`protocol/RAVEN_WSS_TRANSPORT_V1.md` §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViaAddr {
    /// Canonical text (normalised IP and PeerId, `/wss` stored as `/tls/ws`).
    pub text: String,
    /// The terminal PeerId (the relay, or the contact itself).
    pub peer_id: String,
}

/// The multiaddr names of WebSocket, TLS and their relatives: after a
/// transport, only [`wss_suffix`]'s forms of them are accepted.
const WS_FAMILY: &[&str] = &[
    "tls",
    "ws",
    "wss",
    "sni",
    "certhash",
    "x-parity-ws",
    "x-parity-wss",
    "http",
    "https",
    "http-path",
    "noise",
];

/// An SNI name (RWS1 §2): a plausible DNS name that is not an IPv4 literal
/// (TLS never sends an IP address as SNI).
fn sni_name_ok(name: &str) -> bool {
    plausible_dns_name(name) && name.parse::<Ipv4Addr>().is_err()
}

/// The optional WebSocket-over-TLS suffix after a `via=` address's
/// `/tcp/PORT` (RWS1 §2): `/tls/ws`, or `/tls/sni/<name>/ws` after an IP host
/// (a DNS host already is the SNI name). The deprecated libp2p alias `/wss`
/// is stored as `/tls/ws`. Returns the canonical suffix and how many parts it
/// took (none: `""`, 0). Plain `/ws`, `/certhash`, `/x-parity-ws`, `/https`,
/// `/noise` and every other form are refused.
fn wss_suffix(parts: &[&str], host_is_ip: bool, shown: &str) -> Result<(String, usize), String> {
    match parts {
        ["wss", ..] => Ok(("/tls/ws".into(), 1)),
        ["tls", "ws", ..] => Ok(("/tls/ws".into(), 2)),
        ["tls", "sni", name, "ws", ..] if host_is_ip && sni_name_ok(name) => {
            Ok((format!("/tls/sni/{}/ws", name.to_ascii_lowercase()), 4))
        }
        [first, ..] if WS_FAMILY.contains(first) => Err(format!(
            "address \"{shown}\": after /tcp/PORT only /tls/ws (WebSocket over TLS) is allowed \
             (/tls/sni/NAME/ws only after an IP address)"
        )),
        _ => Ok((String::new(), 0)),
    }
}

/// Strict parse of a `via=` / `--via` / `--p2p-relay` multiaddr.
pub fn parse_via(text: &str) -> Result<ViaAddr, String> {
    let t = text.trim();
    let shown = crate::sanitize::sanitize_terminal_line(t);
    let usage = || {
        format!(
            "address \"{shown}\" must look like /ip4/203.0.113.7/tcp/{DEFAULT_P2P_PORT}/p2p/12D3KooW… \
             (or /ip6/…, /dns4/name/…, …/udp/{DEFAULT_P2P_PORT}/quic-v1/p2p/…, \
             …/tcp/443/tls/ws/p2p/…)"
        )
    };
    let parts = multiaddr_parts(t, &shown, &usage)?;
    let (mut out, mut i) = host_and_transport(&parts, &shown, &usage)?;
    let rest = parts.get(i..).unwrap_or_default();
    if parts.get(2) == Some(&"tcp") {
        let host_is_ip = matches!(parts.first(), Some(&("ip4" | "ip6")));
        let (suffix, took) = wss_suffix(rest, host_is_ip, &shown)?;
        out.push_str(&suffix);
        i += took;
    } else if rest.first().is_some_and(|p| WS_FAMILY.contains(p)) {
        return Err(format!(
            "address \"{shown}\": WebSocket over TLS runs on TCP only (…/tcp/443/tls/ws/p2p/…), \
             never after /udp/PORT/quic-v1"
        ));
    }
    // Terminal peer, and nothing after it.
    match (parts.get(i), parts.get(i + 1), parts.len()) {
        (Some(&"p2p"), Some(peer), n) if n == i + 2 => {
            let peer_id = normalize_peer_id(peer).map_err(|e| format!("address \"{shown}\": {e}"))?;
            out.push_str(&format!("/p2p/{peer_id}"));
            // `/wss` grows by 3 characters as `/tls/ws`: the stored text keeps
            // the bound every reader of a via applies (RRH1 RELAY values).
            if out.len() > MAX_MULTIADDR_CHARS {
                return Err(format!(
                    "address \"{shown}\" is longer than {MAX_MULTIADDR_CHARS} characters once \
                     /wss is written /tls/ws"
                ));
            }
            Ok(ViaAddr { text: out, peer_id })
        }
        _ if parts.contains(&"p2p-circuit") => Err(format!(
            "address \"{shown}\" is a circuit: give the relay's own address (it ends in /p2p/<relay PeerId>)"
        )),
        _ => Err(usage()),
    }
}

impl ViaAddr {
    /// The canonical text's parts after the leading `/`: host kind, host,
    /// then the transport (`tcp`, PORT, [suffix], …).
    fn parts(&self) -> Vec<&str> {
        self.text.split('/').skip(1).collect()
    }

    /// WebSocket over TLS: `…/tcp/PORT/tls[/sni/NAME]/ws/p2p/…` (RWS1 §2).
    pub fn is_wss(&self) -> bool {
        let p = self.parts();
        p.get(2) == Some(&"tcp") && p.get(4) == Some(&"tls")
    }

    /// The TCP port (of the raw or the WSS form); `None` for QUIC.
    pub fn tcp_port(&self) -> Option<u16> {
        let p = self.parts();
        match (p.get(2), p.get(3)) {
            (Some(&"tcp"), Some(port)) => port.parse().ok(),
            _ => None,
        }
    }

    /// The raw libp2p TCP form of a WSS address: the same host, port and
    /// PeerId without `/tls[/sni/NAME]/ws` (every WSS listener also takes raw
    /// libp2p, RWS1 §2.3 (a)). `None` unless [`Self::is_wss`].
    pub fn raw_sibling(&self) -> Option<String> {
        if !self.is_wss() {
            return None;
        }
        let p = self.parts();
        Some(format!(
            "/{}/{}/tcp/{}/p2p/{}",
            p[0], p[1], p[3], self.peer_id
        ))
    }

    /// The WSS form of a raw TCP 443 address: `…/tcp/443/tls/ws/p2p/…` (TCP
    /// 443 relay addresses are siblings by convention, RWS1 §2.3 (b)). `None`
    /// for any other address.
    pub fn wss_sibling(&self) -> Option<String> {
        if self.is_wss() || self.tcp_port() != Some(443) {
            return None;
        }
        let p = self.parts();
        Some(format!(
            "/{}/{}/tcp/443/tls/ws/p2p/{}",
            p[0], p[1], self.peer_id
        ))
    }
}

/// Strict parse of a multiaddr's host and transport alone, with nothing
/// after them (no `/p2p/…`, no WSS suffix): [`parse_via`]'s grammar,
/// `/<ip4|ip6|dns|dns4|dns6>/<host>/<tcp/PORT | udp/PORT/quic-v1>`. Returns
/// the canonical text: a relay's own external address, an address of a
/// relay offer.
pub fn parse_host_transport(text: &str) -> Result<String, String> {
    let t = text.trim();
    let shown = crate::sanitize::sanitize_terminal_line(t);
    let usage = || {
        format!(
            "address \"{shown}\" must look like /ip4/203.0.113.7/tcp/{DEFAULT_P2P_PORT} \
             (or /ip6/…, /dns4/name/…, …/udp/{DEFAULT_P2P_PORT}/quic-v1)"
        )
    };
    let parts = multiaddr_parts(t, &shown, &usage)?;
    let (out, i) = host_and_transport(&parts, &shown, &usage)?;
    if i != parts.len() {
        return Err(format!(
            "address \"{shown}\" must name a host and a transport only (nothing after /tcp/PORT \
             or /udp/PORT/quic-v1, no /p2p/…)"
        ));
    }
    Ok(out)
}

/// The multiaddr host part of a bare host (`raven relay card --host`,
/// `raven-node relay --public-host`), by [`parse_via`]'s host rule: an IPv4
/// or IPv6 literal (`[…]` brackets allowed around IPv6 only) gives
/// `/ip4/…` or `/ip6/…`, anything else must be a plausible DNS name and
/// gives `/dns/<name>`. No unspecified, multicast or broadcast address.
pub fn host_prefix(host: &str) -> Result<String, String> {
    let h = host.trim();
    let (kind, value) = match h.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        Some(v6) => ("ip6", v6),
        None if h.parse::<Ipv4Addr>().is_ok() => ("ip4", h),
        None if h.parse::<Ipv6Addr>().is_ok() => ("ip6", h),
        None => ("dns", h),
    };
    parse_host(kind, value).map_err(|e| {
        let shown = crate::sanitize::sanitize_terminal_line(h);
        match e {
            HostRefusal::Malformed => format!(
                "host \"{shown}\" must be an IP address (203.0.113.7, [2001:db8::7]) or a DNS \
                 name (relay.example.org)"
            ),
            HostRefusal::NoSingleHost => format!("host \"{shown}\" names no single host"),
        }
    })
}

/// The circuit address that reaches `target` through the relay `via`:
/// `<via>/p2p-circuit/p2p/<target>` (transports design §3.1).
pub fn circuit_addr(via: &ViaAddr, target_peer_id: &str) -> String {
    circuit_through(&via.text, target_peer_id)
}

/// RWS1 §2.3: the address forms a dialer tries for one relay address, best
/// first. A WSS address also takes raw libp2p on its port, and a raw TCP 443
/// address is by convention also a WSS port; any other address (QUIC, raw
/// TCP on another port) is dialled as it is. `wss_ok` (the WSS gate is live):
/// otherwise only the raw form. `prefer_wss`: the WSS form first (the
/// configured proxy carries it); otherwise raw first.
pub fn relay_dial_forms(v: &ViaAddr, wss_ok: bool, prefer_wss: bool) -> Vec<String> {
    let (raw, wss) = match (v.raw_sibling(), v.tcp_port()) {
        (Some(raw), _) => (raw, Some(v.text.clone())),
        (None, Some(443)) => (v.text.clone(), v.wss_sibling()),
        _ => return vec![v.text.clone()],
    };
    match (wss.filter(|_| wss_ok), prefer_wss) {
        (Some(w), true) => vec![w, raw],
        (Some(w), false) => vec![raw, w],
        (None, _) => vec![raw],
    }
}

/// The form one direct address of a contact is dialled at: a WSS address at
/// its raw sibling alone, any other address as it is. Endpoints never listen
/// on WSS in V1 (RWS1 §2.3), so a contact's WSS form could never answer, and
/// dialling it would send the contact's host and SNI name to the HTTPS proxy
/// (review A-2); a raw TCP 443 address of a contact has no WSS sibling.
fn direct_dial_form(v: &ViaAddr) -> String {
    v.raw_sibling().unwrap_or_else(|| v.text.clone())
}

/// The circuit that reaches `target_peer_id` through the relay address
/// `form` (a `via` text, or one of its [`relay_dial_forms`]).
fn circuit_through(form: &str, target_peer_id: &str) -> String {
    format!("{form}/p2p-circuit/p2p/{target_peer_id}")
}

/// Longest text [`split_relay_tokens`] reads: a few pasted card lines.
pub const MAX_RELAY_PASTE: usize = 4096;

/// `raven relay use`: the relay addresses a friend pasted (the lines
/// `raven relay card` prints). Tokens are separated by whitespace or commas,
/// each a [`parse_via`] address with or without a leading `via=`.
/// Duplicates are dropped; past [`MAX_VIA`] addresses, or anything else,
/// the whole paste is refused (nothing is skipped).
pub fn split_relay_tokens(text: &str) -> Result<Vec<ViaAddr>, String> {
    if text.len() > MAX_RELAY_PASTE {
        return Err(format!(
            "relay addresses are at most {MAX_RELAY_PASTE} bytes (paste the via= lines of \
             `raven relay card`)"
        ));
    }
    let mut out: Vec<ViaAddr> = Vec::new();
    let tokens = text
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty());
    for token in tokens {
        let via = parse_via(token.strip_prefix("via=").unwrap_or(token))?;
        if !out.contains(&via) {
            out.push(via);
        }
    }
    if out.is_empty() {
        return Err("no relay address given: paste the via= lines of `raven relay card`".into());
    }
    if out.len() > MAX_VIA {
        return Err(format!(
            "at most {MAX_VIA} relay addresses (a card holds {MAX_VIA} via=): use the TCP \
             {DEFAULT_P2P_PORT} and TCP 443 lines of `raven relay card`"
        ));
    }
    Ok(out)
}

/// Relay addresses grouped by relay PeerId, in first-seen order, each group
/// in the given (card) order with duplicates dropped: two `via=` of one
/// relay (TCP 7423 and TCP 443) are one relay with a fallback address.
pub fn group_relays(relays: &[ViaAddr]) -> Vec<(String, Vec<ViaAddr>)> {
    let mut out: Vec<(String, Vec<ViaAddr>)> = Vec::new();
    for via in relays {
        match out.iter_mut().find(|(peer, _)| *peer == via.peer_id) {
            Some((_, addrs)) => {
                if !addrs.contains(via) {
                    addrs.push(via.clone());
                }
            }
            None => out.push((via.peer_id.clone(), vec![via.clone()])),
        }
    }
    out
}

/// How many relays `relays` names ([`group_relays`]), whatever the number
/// of addresses.
pub fn distinct_relays(relays: &[ViaAddr]) -> usize {
    group_relays(relays).len()
}

/// The outbox / IPC route for "reach this PeerId any way we know":
/// `/p2p/<PeerId>`. raven-node then dials the contact's direct `via=`
/// addresses first, then circuits through its relays.
pub fn peer_route(peer_id: &str) -> String {
    format!("/p2p/{peer_id}")
}

/// What a p2p dial string (`OutboxRoute::dial`, IPC `P2pDial.multiaddr`)
/// asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum P2pDialTarget {
    /// `/p2p/<PeerId>`: every way the contact book knows.
    Peer { peer_id: String },
    /// One direct address of the target (`<via>` naming the target itself).
    Direct { peer_id: String, addr: ViaAddr },
    /// One circuit `<relay via>/p2p-circuit/p2p/<target>`.
    Circuit { peer_id: String, relay: ViaAddr },
}

impl P2pDialTarget {
    pub fn peer_id(&self) -> &str {
        match self {
            Self::Peer { peer_id }
            | Self::Direct { peer_id, .. }
            | Self::Circuit { peer_id, .. } => peer_id,
        }
    }
}

/// Strict parse of a p2p dial string; every form ends in the target's PeerId.
pub fn parse_p2p_dial(text: &str) -> Result<P2pDialTarget, String> {
    let t = text.trim();
    if let Some(peer) = t.strip_prefix("/p2p/") {
        if !peer.contains('/') {
            return Ok(P2pDialTarget::Peer {
                peer_id: normalize_peer_id(peer)?,
            });
        }
    }
    if let Some((relay, target)) = t.split_once("/p2p-circuit/p2p/") {
        let relay = parse_via(relay)?;
        let peer_id = normalize_peer_id(target)?;
        if relay.peer_id == peer_id {
            return Err("a circuit through the target itself is not a circuit".into());
        }
        return Ok(P2pDialTarget::Circuit { peer_id, relay });
    }
    let addr = parse_via(t)?;
    Ok(P2pDialTarget::Direct {
        peer_id: addr.peer_id.clone(),
        addr,
    })
}

/// A contact's p2p routes as the contact book stores them: its PeerId and its
/// `via=` addresses, naming at most [`MAX_VIA`] PeerIds (each relay, and the
/// contact itself for its direct addresses) with at most two addresses each:
/// a `raven-card/2` holds [`MAX_VIA`] addresses, a `raven-card/3` up to two of
/// each of two relays. Junk is dropped, never dialled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContactP2p {
    pub peer_id: String,
    pub via: Vec<ViaAddr>,
}

impl ContactP2p {
    /// From the stored fields; `None` when there is no usable PeerId.
    pub fn from_fields(peer_id: &str, via: &[String]) -> Option<Self> {
        use crate::route_hints::{MAX_ADDRS_PER_RELAY, MAX_RELAY_ENTRIES};
        let peer_id = normalize_peer_id(peer_id).ok()?;
        let mut out = Self {
            peer_id,
            via: Vec::new(),
        };
        for v in via {
            if out.via.len() >= MAX_RELAY_ENTRIES {
                break;
            }
            if let Ok(v) = parse_via(v) {
                let same = out.via.iter().filter(|o| o.peer_id == v.peer_id).count();
                let mut named: Vec<&str> = Vec::new();
                for o in &out.via {
                    if !named.contains(&o.peer_id.as_str()) {
                        named.push(&o.peer_id);
                    }
                }
                // A fallback address of a PeerId already named, or a new
                // PeerId while fewer than MAX_VIA are.
                let room = if same == 0 {
                    named.len() < MAX_VIA
                } else {
                    same < MAX_ADDRS_PER_RELAY
                };
                if room && !out.via.contains(&v) {
                    out.via.push(v);
                }
            }
        }
        Some(out)
    }

    /// The addresses to dial, in plan order (transports design §2.3): direct
    /// ones (a `via` that names the contact itself) first, then circuits
    /// through the relays. [`Self::dial_addrs_with`] with the WSS gate
    /// closed: byte for byte what it was before WSS existed.
    pub fn dial_addrs(&self) -> Vec<String> {
        self.dial_addrs_with(false, |_| false, false)
    }

    /// [`Self::dial_addrs`] with RWS1 §2.3's address forms: each relay `via`
    /// becomes a circuit through each of its [`relay_dial_forms`] (`wss_ok`:
    /// the WSS gate is live; `prefer_wss`: that relay's WSS form first), a
    /// direct WSS address its [`direct_dial_form`]. `restricted` (RWS1 §9:
    /// a reservation rides a proxied WSS connection): no direct address.
    /// Deduplicated.
    pub fn dial_addrs_with(
        &self,
        wss_ok: bool,
        prefer_wss: impl Fn(&ViaAddr) -> bool,
        restricted: bool,
    ) -> Vec<String> {
        let direct = self
            .via
            .iter()
            .filter(|v| !restricted && v.peer_id == self.peer_id)
            .map(direct_dial_form);
        let circuits = self
            .via
            .iter()
            .filter(|v| v.peer_id != self.peer_id)
            .flat_map(|v| relay_dial_forms(v, wss_ok, prefer_wss(v)))
            .map(|form| circuit_through(&form, &self.peer_id));
        let mut out: Vec<String> = Vec::new();
        for a in direct.chain(circuits) {
            if !out.contains(&a) {
                out.push(a);
            }
        }
        out
    }
}

/// Addresses one p2p dial tries at most ([`P2pDialSet::dial_addrs`]).
pub const MAX_DIAL_ADDRS: usize = 8;

/// Everything known about reaching a contact's PeerId: its book (`via=`, a
/// card's `p2p=`) and its RRH1 route hints ([`crate::learned_routes`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct P2pDialSet {
    pub peer_id: String,
    /// The contact's own addresses (each ending in its PeerId), in plan
    /// order: learned before the book's, IPv6 before IPv4 within each.
    pub direct: Vec<ViaAddr>,
    /// The relays it is reached through, in plan order: the ones it named
    /// in its route hints (its current reservations) before the book's.
    pub relays: Vec<ViaAddr>,
}

impl P2pDialSet {
    /// `book`: the contact row's PeerId and `via=`; `learned`: its route
    /// hints, used only when they name the book's PeerId (or the book has
    /// none: the book wins). A learned same-LAN address is kept only when
    /// `local_direct_ok` says so (the caller checks
    /// [`crate::learned_routes::LearnedP2p::local_tag`] against this
    /// computer's current network). `hide_ip` (D4) is `Some(own relays)`
    /// when this node hides its IP from the contact: no direct address at
    /// all, and circuits only through the relays the contact names that are
    /// also among `own relays` (the `via=` addresses of the relays this node
    /// itself reserves on, whose operators already see its IP), each at
    /// this node's own addresses for it, never at an address the contact
    /// gives for it: a circuit makes this node dial its relay address
    /// whenever no connection to that relay is up, and an address the
    /// contact names may be the contact's own host. A relay only the
    /// contact names may be the contact's own, which would see this node's
    /// IP: it is left out, so the contact reaches this node through this
    /// node's relays instead. `None` without a PeerId.
    pub fn merge(
        book: Option<&ContactP2p>,
        learned: Option<&crate::learned_routes::LearnedP2p>,
        local_direct_ok: impl Fn(&ViaAddr) -> bool,
        hide_ip: Option<&[ViaAddr]>,
    ) -> Option<Self> {
        let learned_id = learned.and_then(|l| normalize_peer_id(&l.peer_id).ok());
        let peer_id = match (book, &learned_id) {
            (Some(book), _) => book.peer_id.clone(),
            (None, Some(id)) => id.clone(),
            (None, None) => return None,
        };
        let learned = learned.filter(|_| learned_id.as_deref() == Some(peer_id.as_str()));
        let book_via: &[ViaAddr] = book.map_or(&[], |b| b.via.as_slice());
        let own = |v: &&ViaAddr| v.peer_id == peer_id;
        fn v6_first(mut addrs: Vec<&ViaAddr>) -> Vec<&ViaAddr> {
            // Stable: the given order within each family.
            addrs.sort_by_key(|v| !v.text.starts_with("/ip6/"));
            addrs
        }
        let mut direct: Vec<ViaAddr> = Vec::new();
        let mut relays: Vec<ViaAddr> = Vec::new();
        if hide_ip.is_none() {
            let learned_direct = learned.map_or(Vec::new(), |l| {
                l.local_direct
                    .iter()
                    .filter(own)
                    .filter(|v| local_direct_ok(v))
                    .chain(l.direct.iter().filter(own))
                    .collect()
            });
            let book_direct = book_via.iter().filter(own).collect();
            for v in v6_first(learned_direct)
                .into_iter()
                .chain(v6_first(book_direct))
            {
                if !direct.contains(v) {
                    direct.push(v.clone());
                }
            }
        }
        let learned_relays = learned.map_or(&[][..], |l| l.relays.as_slice());
        for v in learned_relays.iter().chain(book_via).filter(|v| !own(v)) {
            // Hiding the IP: only a relay this node holds itself, at the
            // addresses this node names it by.
            let at: Vec<&ViaAddr> = match hide_ip {
                None => vec![v],
                Some(held) => held.iter().filter(|h| h.peer_id == v.peer_id).collect(),
            };
            for a in at {
                if !relays.contains(a) {
                    relays.push(a.clone());
                }
            }
        }
        Some(Self {
            peer_id,
            direct,
            relays,
        })
    }

    /// The direct addresses, each at its [`direct_dial_form`] (the address
    /// itself, or a WSS one's raw sibling), deduplicated.
    fn direct_in_plan_order(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for v in &self.direct {
            let form = direct_dial_form(v);
            if !out.contains(&form) {
                out.push(form);
            }
        }
        out
    }

    /// The circuits, the first address of each relay (in plan order) before
    /// any relay's fallback address, so a second relay is never cut for the
    /// first one's fallback. A relay address counts at each of its
    /// [`relay_dial_forms`] in their order (with the WSS gate closed, one
    /// form: the address itself, or a WSS address's raw sibling); a second
    /// form is a fallback like a second address. Deduplicated.
    fn circuits_in_plan_order(
        &self,
        wss_ok: bool,
        prefer_wss: &dyn Fn(&ViaAddr) -> bool,
    ) -> Vec<String> {
        let mut firsts: Vec<(&str, String)> = Vec::new();
        let mut fallbacks: Vec<String> = Vec::new();
        for r in &self.relays {
            for form in relay_dial_forms(r, wss_ok, prefer_wss(r)) {
                if firsts.iter().any(|(_, f)| *f == form) || fallbacks.contains(&form) {
                    continue;
                }
                if firsts.iter().any(|(peer, _)| *peer == r.peer_id) {
                    fallbacks.push(form);
                } else {
                    firsts.push((r.peer_id.as_str(), form));
                }
            }
        }
        firsts
            .into_iter()
            .map(|(_, form)| form)
            .chain(fallbacks)
            .map(|form| circuit_through(&form, &self.peer_id))
            .collect()
    }

    /// The addresses to dial, in plan order (any-network plan §2.3 steps
    /// 4-5): the first direct address, then the first circuit, then the
    /// other direct addresses, then the other circuits (each relay's first
    /// address before the fallbacks). libp2p dials two addresses at once, so
    /// a stale direct address (the contact moved) never holds back the first
    /// circuit. Deduplicated, at most [`MAX_DIAL_ADDRS`]; when there is more
    /// to dial than that, direct addresses take at most the room the
    /// circuits leave (half the plan, or more with fewer circuits), so stale
    /// direct addresses never cut a relay out of the plan.
    /// [`Self::dial_addrs_with`] with the WSS gate closed: byte for byte the
    /// plan from before WSS existed.
    pub fn dial_addrs(&self) -> Vec<String> {
        self.dial_addrs_with(false, |_| false, false)
    }

    /// [`Self::dial_addrs`] with RWS1 §2.3's address forms: each relay
    /// address at each of its [`relay_dial_forms`] (`wss_ok`: the WSS gate
    /// is live; `prefer_wss`: that relay's WSS form first), each direct WSS
    /// address at its [`direct_dial_form`]. `restricted` (RWS1 §9: a
    /// reservation rides a proxied WSS connection): no direct address, the
    /// circuits only.
    pub fn dial_addrs_with(
        &self,
        wss_ok: bool,
        prefer_wss: impl Fn(&ViaAddr) -> bool,
        restricted: bool,
    ) -> Vec<String> {
        let c = self.circuits_in_plan_order(wss_ok, &prefer_wss);
        let room = MAX_DIAL_ADDRS - c.len().min(MAX_DIAL_ADDRS / 2);
        let mut d = if restricted {
            Vec::new()
        } else {
            self.direct_in_plan_order()
        };
        d.truncate(room);
        let mut out: Vec<String> = d
            .iter()
            .take(1)
            .chain(c.iter().take(1))
            .chain(d.iter().skip(1))
            .chain(c.iter().skip(1))
            .cloned()
            .collect();
        let mut seen = std::collections::HashSet::new();
        out.retain(|a| seen.insert(a.clone()));
        out.truncate(MAX_DIAL_ADDRS);
        out
    }

    /// The PeerIds of its relays, once each, in plan order: what the dial
    /// admits as contact relays (the p2p host's peer gate).
    pub fn relay_peer_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in &self.relays {
            if !out.contains(&r.peer_id) {
                out.push(r.peer_id.clone());
            }
        }
        out
    }
}

// ── Which addresses are globally routable ───────────────────────────────────
// One rule for the libp2p host and its gate (raven-swarm wraps these) and for
// the addresses a contact's RRH1 route hints may name (`route_hints`).

/// Globally routable unicast IPv4 (not private, loopback, link-local,
/// CGNAT 100.64/10, documentation, benchmarking, multicast, reserved,
/// broadcast or unspecified).
pub fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18))
}

/// Globally routable unicast IPv6 (not loopback, unspecified, link-local,
/// unique-local, multicast, documentation 2001:db8::/32 or the local-use
/// NAT64 prefix 64:ff9b:1::/48). An address that carries an IPv4 address a
/// translator forwards to ([`embedded_ipv4`]) is global exactly when that
/// IPv4 address is: otherwise a peer could name a private IPv4 target
/// through a NAT64 or 6to4 gateway.
pub fn is_global_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_ipv4(ip) {
        return is_global_ipv4(v4);
    }
    let s = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001))
}

/// The IPv4 address an IPv4-mapped (::ffff:0:0/96), NAT64 well-known prefix
/// (64:ff9b::/96, RFC 6052) or 6to4 (2002::/16, RFC 3056) address carries.
pub fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = ip.segments();
    let o = ip.octets();
    if s[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

/// [`is_global_ipv4`] / [`is_global_ipv6`].
pub fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_ipv4(v4),
        IpAddr::V6(v6) => is_global_ipv6(v6),
    }
}

/// Normalise a p2p listen setting (`--p2p-listen`, `RAVEN_P2P_LISTEN`,
/// node_policy.json `p2p_listen`). Empty or `off`: `Ok(None)` (no libp2p
/// host). `on` or a bare port: every interface, IPv4 and IPv6, on that port
/// ([`DEFAULT_P2P_PORT`] for `on`). `IP:PORT` / `[IPv6]:PORT`: that address
/// only (port 0 is kept for tests). `relay` is retired: it still parses (as
/// [`P2pListen::RelayOnly`]), so an old node_policy.json or env value is never
/// a config error, but [`P2pListen::effective`] makes it listen on
/// [`DEFAULT_P2P_PORT`] anyway: a node without a listener can never
/// hole-punch.
pub fn normalize_p2p_listen(raw: &str) -> Result<Option<P2pListen>, String> {
    let s = raw.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    if s.eq_ignore_ascii_case("on") {
        return Ok(Some(P2pListen::All(DEFAULT_P2P_PORT)));
    }
    if s.eq_ignore_ascii_case("relay") {
        return Ok(Some(P2pListen::RelayOnly));
    }
    if let Ok(port) = s.parse::<u16>() {
        if s == port.to_string() {
            return Ok(Some(P2pListen::All(port)));
        }
    }
    if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
        return Ok(Some(P2pListen::One(addr)));
    }
    Err(format!(
        "p2p listen must be a port (e.g. {DEFAULT_P2P_PORT}: every interface, IPv4 and IPv6), \
         IP:PORT (e.g. 127.0.0.1:{DEFAULT_P2P_PORT}), \"on\" or \"off\" (\"relay\" is retired: \
         it listens on {DEFAULT_P2P_PORT} anyway); got \"{}\"",
        crate::sanitize::sanitize_terminal_line(s)
    ))
}

/// Log and status text for the retired `relay` listen setting.
pub const RELAY_LISTEN_RETIRED: &str =
    "listen setting \"relay\" is retired (a node without a listener can never hole-punch)";

/// Where the libp2p host listens (TCP and QUIC on each).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P2pListen {
    /// `0.0.0.0` and `::` on this port.
    All(u16),
    /// One address.
    One(std::net::SocketAddr),
    /// No listener: reachable only through relay reservations. Retired: test
    /// only (debug `RAVEN_LAB_P2P_RELAY_ONLY=1`, see [`Self::effective`]).
    RelayOnly,
}

impl P2pListen {
    /// What the host really opens. The retired `RelayOnly` becomes every
    /// interface on [`DEFAULT_P2P_PORT`] (DCUtR needs a listener socket: QUIC
    /// dials as listener only from one, TCP reuses only a listening port),
    /// unless `relay_only_test` (the debug lab switch) keeps it. The `bool`
    /// says the setting was retired.
    pub fn effective(self, relay_only_test: bool) -> (Self, bool) {
        match self {
            Self::RelayOnly if !relay_only_test => (Self::All(DEFAULT_P2P_PORT), true),
            other => (other, false),
        }
    }

    /// The host part of each listen address: `0.0.0.0` and `::`, the one
    /// address, or none.
    fn hosts(&self) -> Vec<String> {
        let ips: Vec<IpAddr> = match self {
            Self::All(_) => vec![Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()],
            Self::One(addr) => vec![addr.ip()],
            Self::RelayOnly => Vec::new(),
        };
        ips.into_iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => format!("/ip4/{v4}"),
                IpAddr::V6(v6) => format!("/ip6/{v6}"),
            })
            .collect()
    }

    /// The listen port (0 for the retired `RelayOnly`).
    fn port(&self) -> u16 {
        match self {
            Self::All(p) => *p,
            Self::One(addr) => addr.port(),
            Self::RelayOnly => 0,
        }
    }

    /// The listen multiaddrs, TCP then QUIC per address.
    pub fn multiaddrs(&self) -> Vec<String> {
        let port = self.port();
        let mut out = Vec::new();
        for host in self.hosts() {
            out.push(format!("{host}/tcp/{port}"));
            out.push(format!("{host}/udp/{port}/quic-v1"));
        }
        out
    }

    /// The WSS listen multiaddrs (RWS1 §6: a relay's two-protocol TCP
    /// listener, which also takes raw libp2p): `{host}/tcp/{port}/tls/ws` per
    /// address, TCP only (WebSocket over TLS never runs on QUIC).
    pub fn wss_multiaddrs(&self) -> Vec<String> {
        let port = self.port();
        self.hosts()
            .iter()
            .map(|host| format!("{host}/tcp/{port}/tls/ws"))
            .collect()
    }

    /// The canonical text saved in node_policy.json.
    pub fn policy_text(&self) -> String {
        match self {
            Self::All(p) => p.to_string(),
            Self::One(addr) => addr.to_string(),
            Self::RelayOnly => "relay".into(),
        }
    }
}

// ── A relay's extra listeners and the addresses it names ────────────────────

/// `raven-node relay --also-tcp LOCAL[:PUBLIC]`: one extra TCP listener,
/// e.g. TCP 443 for networks that let only HTTPS out. Friends reach it on
/// `public`; a router or nftables maps `public` to `local`. `public` is
/// `local` unless given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExtraTcp {
    pub local: u16,
    pub public: u16,
}

/// `--also-tcp` ports one relay listens on at most.
pub const MAX_EXTRA_TCP: usize = 2;

/// Strict parse of one `--also-tcp` value: `PORT` or `LOCAL:PUBLIC`, decimal
/// with no sign or leading zero. Port 0 (tests: any free port) only as
/// `0`: a friend cannot reach a public port nobody named, and a router
/// cannot map one to a port nobody knows.
pub fn parse_extra_tcp(s: &str) -> Result<ExtraTcp, String> {
    let s = s.trim();
    let (l, p) = s.split_once(':').unwrap_or((s, s));
    let port = |t: &str| t.parse::<u16>().ok().filter(|n| t == n.to_string());
    match (port(l), port(p)) {
        (Some(local), Some(public)) if (local == 0) == (public == 0) => {
            Ok(ExtraTcp { local, public })
        }
        _ => Err(format!(
            "--also-tcp must be PORT or LOCAL:PUBLIC (e.g. 443 or 7443:443); got \"{}\"",
            crate::sanitize::sanitize_terminal_line(s)
        )),
    }
}

/// What a relay listens on: TCP and QUIC on `listen` ([`P2pListen::multiaddrs`]),
/// then TCP only on each extra port, on the same IPs. Refused: the retired
/// `relay` setting (a relay must listen), more than [`MAX_EXTRA_TCP`] extra
/// ports, and an extra port that is already a listen port.
pub fn relay_listen_multiaddrs(
    listen: &P2pListen,
    extra: &[ExtraTcp],
) -> Result<Vec<String>, String> {
    if matches!(listen, P2pListen::RelayOnly) {
        return Err("--listen needs a port or IP:PORT (not \"relay\")".into());
    }
    if extra.len() > MAX_EXTRA_TCP {
        return Err(format!("at most {MAX_EXTRA_TCP} --also-tcp ports"));
    }
    let mut seen = vec![listen.port()];
    let mut out = listen.multiaddrs();
    for e in extra {
        if e.local != 0 && seen.contains(&e.local) {
            return Err(format!("--also-tcp {}: already a listen port", e.local));
        }
        seen.push(e.local);
        out.extend(
            listen
                .hosts()
                .iter()
                .map(|host| format!("{host}/tcp/{}", e.local)),
        );
    }
    Ok(out)
}

/// The addresses `raven-node relay --public-host HOST` names for itself (in
/// reservations, and so in `raven relay card`): TCP and QUIC on the listen
/// port, then TCP on each extra port's public port, without duplicates.
/// `host` follows [`host_prefix`]. Fixed ports only: port 0 is refused.
pub fn relay_public_addrs(
    host: &str,
    listen_port: u16,
    extra: &[ExtraTcp],
) -> Result<Vec<String>, String> {
    let host = host_prefix(host)?;
    if listen_port == 0 || extra.iter().any(|e| e.public == 0) {
        return Err("--public-host needs fixed ports (not port 0)".into());
    }
    let mut out = vec![
        format!("{host}/tcp/{listen_port}"),
        format!("{host}/udp/{listen_port}/quic-v1"),
    ];
    for e in extra {
        let addr = format!("{host}/tcp/{}", e.public);
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> String {
        local_peer_id(&Identity::from_seed(&[seed; 32]))
    }

    #[test]
    fn base58_round_trips_and_keeps_leading_zeros() {
        for bytes in [
            vec![],
            vec![0],
            vec![0, 0, 1],
            vec![0xff; 40],
            (0u8..=255).collect::<Vec<_>>(),
        ] {
            assert_eq!(base58_decode(&base58_encode(&bytes)).unwrap(), bytes);
        }
        assert_eq!(base58_encode(&[0, 0, 0x01]), "112");
        assert!(base58_decode("0OIl").is_none());
    }

    #[test]
    fn peer_ids_are_canonical_ed25519_only() {
        let id = Identity::from_seed(&[7; 32]);
        let p = local_peer_id(&id);
        assert!(p.starts_with("12D3KooW") && p.len() == 52, "{p}");
        assert_eq!(parse_peer_id(&p).unwrap(), libp2p_ed25519_public(&id));
        assert_eq!(normalize_peer_id(&format!("  {p} ")).unwrap(), p);
        // Domain separated from the Raven key, stable per seed.
        assert_ne!(libp2p_ed25519_public(&id), id.public_key_bytes());
        assert_eq!(p, peer(7));
        assert_ne!(p, peer(8));
        for bad in [
            "",
            "12D3KooW",
            "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N", // RSA/sha256 form
            &p[..51],
            &format!("{p}x"),
            &p.replace('W', "0"),
        ] {
            assert!(parse_peer_id(bad).is_err(), "{bad}");
        }
        // A one-character change that is still base58 is a different key or
        // not an Ed25519 PeerId at all; never the same one.
        let mut tweaked = p.clone().into_bytes();
        let last = tweaked.len() - 1;
        tweaked[last] = if tweaked[last] == b'z' { b'y' } else { b'z' };
        let tweaked = String::from_utf8(tweaked).unwrap();
        assert_ne!(parse_peer_id(&tweaked).ok(), parse_peer_id(&p).ok());
    }

    #[test]
    fn peer_id_bytes_round_trip_and_refuse_other_key_types() {
        let id = Identity::from_seed(&[0x51; 32]);
        let p = local_peer_id(&id);
        let bytes = peer_id_bytes(&p).unwrap();
        assert_eq!(bytes[..6], ED25519_PEER_ID_PREFIX);
        assert_eq!(bytes[6..], libp2p_ed25519_public(&id));
        assert_eq!(peer_id_from_bytes(&bytes).unwrap(), p);
        assert_eq!(peer_id_bytes(&format!(" {p} ")).unwrap(), bytes);
        // Any other multihash or key type: refused, whichever prefix byte.
        for i in 0..ED25519_PEER_ID_PREFIX.len() {
            let mut other = bytes;
            other[i] ^= 0x01;
            assert!(peer_id_from_bytes(&other).is_err(), "prefix byte {i}");
        }
        assert!(peer_id_from_bytes(&[0; PEER_ID_BYTES]).is_err());
        for bad in ["", "12D3KooW", &p[..51], "not a peer"] {
            assert!(peer_id_bytes(bad).is_err(), "{bad}");
        }
    }

    /// The same table as raven-swarm's
    /// `host::global_addresses_and_what_a_relay_may_name`, whose
    /// `is_global_ip*` are wrappers of these.
    #[test]
    fn global_ip_rule_table() {
        for ip in [
            "8.8.8.8",
            "203.0.114.1",
            "11.0.3.5",
            "2606:4700::1111",
            "2c0f:fff0:a::5",
            "::ffff:8.8.4.4",
            // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) of a global IPv4.
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_global_ip(ip), "{ip}");
        }
        for ip in [
            "10.0.0.1",
            "192.168.1.2",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "203.0.113.7",
            "198.18.0.1",
            "192.0.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "ff02::1",
            "::ffff:192.168.1.1",
            // NAT64 and 6to4 of a private, loopback, CGNAT or unspecified
            // IPv4: as that IPv4 address (a translator would forward there).
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
            "64:ff9b::c0a8:101",
            "64:ff9b::6440:1",
            "2002:c0a8:101::1",
            "2002:a00:1::1",
            "2002:7f00:1::1",
            "2002::1",
            // The local-use NAT64 prefix (RFC 8215) is never global.
            "64:ff9b:1::808:808",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!is_global_ip(ip), "{ip}");
        }
        assert_eq!(
            embedded_ipv4("64:ff9b::808:808".parse().unwrap()),
            Some(Ipv4Addr::new(8, 8, 8, 8))
        );
        assert_eq!(
            embedded_ipv4("2002:c0a8:101::1".parse().unwrap()),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(embedded_ipv4("2606:4700::1111".parse().unwrap()), None);
    }

    #[test]
    fn via_grammar_is_narrow() {
        let r = peer(1);
        let ok = |s: &str| parse_via(s).unwrap();
        let v = ok(&format!("/ip4/203.0.113.7/tcp/7423/p2p/{r}"));
        assert_eq!(v.peer_id, r);
        assert_eq!(v.text, format!("/ip4/203.0.113.7/tcp/7423/p2p/{r}"));
        assert_eq!(
            ok(&format!("/ip6/2001:DB8:0::1/udp/7423/quic-v1/p2p/{r}")).text,
            format!("/ip6/2001:db8::1/udp/7423/quic-v1/p2p/{r}")
        );
        assert_eq!(
            ok(&format!("/dns4/Relay.Example.com/tcp/7423/p2p/{r}")).text,
            format!("/dns4/relay.example.com/tcp/7423/p2p/{r}")
        );
        ok(&format!("/ip4/127.0.0.1/tcp/1/p2p/{r}"));
        // The longest label, digits in labels, a trailing dot.
        ok(&format!(
            "/dns/{}.example.org/tcp/443/tls/ws/p2p/{r}",
            "a".repeat(63)
        ));
        ok(&format!("/dns4/1relay.2example.org/tcp/443/p2p/{r}"));
        ok(&format!("/dns4/relay.example.org./tcp/443/p2p/{r}"));
        ok(&format!("/dns4/r-1.example.org/tcp/443/p2p/{r}"));
        for bad in [
            format!("ip4/203.0.113.7/tcp/7423/p2p/{r}"),
            "/ip4/203.0.113.7/tcp/7423".to_string(),
            format!("/ip4/203.0.113.7/tcp/0/p2p/{r}"),
            format!("/ip4/203.0.113.7/tcp/07423/p2p/{r}"),
            format!("/ip4/0.0.0.0/tcp/7423/p2p/{r}"),
            format!("/ip6/::/tcp/7423/p2p/{r}"),
            format!("/ip4/203.0.113.7/udp/7423/p2p/{r}"),
            format!("/ip4/203.0.113.7/tcp/7423/p2p/{r}/p2p-circuit"),
            format!(
                "/ip4/203.0.113.7/tcp/7423/p2p/{r}/p2p-circuit/p2p/{}",
                peer(2)
            ),
            format!("/ip4/203.0.113.7/tcp/7423/ws/p2p/{r}"),
            format!("/dns4/-bad/tcp/7423/p2p/{r}"),
            format!("/dns4/a..b/tcp/7423/p2p/{r}"),
            // Review A-5: names TLS cannot send as SNI (rustls ServerName).
            format!("/dns4/203.0.113.7/tcp/443/tls/ws/p2p/{r}"),
            format!("/dns4/203.0.113.7/tcp/7423/p2p/{r}"),
            format!("/dns4/relay-.example.org/tcp/443/p2p/{r}"),
            format!("/dns4/relay.-example.org/tcp/443/p2p/{r}"),
            format!("/dns4/relay.123/tcp/443/p2p/{r}"),
            format!("/dns4/relay.123./tcp/443/p2p/{r}"),
            format!("/dns/{}.example.org/tcp/443/tls/ws/p2p/{r}", "a".repeat(64)),
            format!("/dns4/./tcp/7423/p2p/{r}"),
            format!("/dns4/.relay.example.org/tcp/7423/p2p/{r}"),
            format!("/ip4/203.0.113.7/tcp/443/tls/sni/relay-.example.org/ws/p2p/{r}"),
            format!("/ip4/203.0.113.7/tcp/443/tls/sni/relay.123/ws/p2p/{r}"),
            format!("/unix/x/tcp/7423/p2p/{r}"),
            "/ip4/203.0.113.7/tcp/7423/p2p/not-a-peer".to_string(),
            format!("/ip4/203.0.113.7/tcp/7423/p2p/{r} extra"),
            format!("/ip4/203.0.113.7/tcp/7423/p2p/{r}/"),
            "/".repeat(400),
        ] {
            assert!(parse_via(&bad).is_err(), "{bad}");
        }
        let circuit = parse_via(&format!(
            "/ip4/203.0.113.7/tcp/7423/p2p/{r}/p2p-circuit/p2p/{}",
            peer(2)
        ))
        .unwrap_err();
        assert!(circuit.contains("circuit"), "{circuit}");
    }

    #[test]
    fn dial_targets_and_plan_order() {
        let (relay, bob) = (peer(1), peer(2));
        let relay_via = parse_via(&format!("/ip4/198.51.100.1/tcp/7423/p2p/{relay}")).unwrap();
        let direct_via = parse_via(&format!("/ip4/203.0.113.9/tcp/7423/p2p/{bob}")).unwrap();
        assert_eq!(
            parse_p2p_dial(&peer_route(&bob)).unwrap(),
            P2pDialTarget::Peer {
                peer_id: bob.clone()
            }
        );
        let circuit = circuit_addr(&relay_via, &bob);
        assert_eq!(
            parse_p2p_dial(&circuit).unwrap(),
            P2pDialTarget::Circuit {
                peer_id: bob.clone(),
                relay: relay_via.clone()
            }
        );
        assert_eq!(
            parse_p2p_dial(&direct_via.text).unwrap().peer_id(),
            bob.as_str()
        );
        assert!(parse_p2p_dial(&circuit_addr(&relay_via, &relay)).is_err());
        assert!(parse_p2p_dial("/p2p/").is_err());
        assert!(parse_p2p_dial("203.0.113.9:7423").is_err());

        // Direct addresses first, then circuits; at most MAX_VIA, junk dropped.
        let c = ContactP2p::from_fields(
            &bob,
            &[
                relay_via.text.clone(),
                "junk".into(),
                direct_via.text.clone(),
                relay_via.text.clone(),
                format!("/ip4/198.51.100.2/tcp/7423/p2p/{}", peer(3)),
            ],
        )
        .unwrap();
        assert_eq!(c.via.len(), MAX_VIA);
        assert_eq!(c.dial_addrs(), vec![direct_via.text.clone(), circuit]);
        assert!(ContactP2p::from_fields("nope", &[]).is_none());
    }

    /// A `raven-card/3` row: two addresses of each of two relays are kept
    /// (one relay's TCP 7423 and TCP 443 do not use up both relay slots); a
    /// third relay, a third address of one relay and a fifth address are not.
    #[test]
    fn a_book_row_keeps_two_addresses_of_each_of_two_relays() {
        let bob = peer(2);
        let (r1, r2, r3) = (peer(11), peer(12), peer(13));
        let a = |host: &str, port: u16, who: &str| format!("{host}/tcp/{port}/p2p/{who}");
        let rows = [
            a("/ip4/198.51.100.1", 7423, &r1),
            a("/ip4/198.51.100.1", 443, &r1),
            a("/ip4/198.51.100.2", 7423, &r2),
            a("/ip4/198.51.100.3", 7423, &r3),
            a("/ip4/198.51.100.1", 8443, &r1),
            a("/ip4/198.51.100.2", 443, &r2),
        ];
        let c = ContactP2p::from_fields(&bob, &rows).unwrap();
        let texts: Vec<&str> = c.via.iter().map(|v| v.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                rows[0].as_str(),
                rows[1].as_str(),
                rows[2].as_str(),
                rows[5].as_str()
            ]
        );
        assert_eq!(c.dial_addrs().len(), 4);
        // A row of today's size reads as it always did.
        let two = ContactP2p::from_fields(&bob, &rows[..2]).unwrap();
        assert_eq!(two.via.len(), 2);
    }

    fn learned(peer_id: &str) -> crate::learned_routes::LearnedP2p {
        crate::learned_routes::LearnedP2p {
            peer_id: peer_id.to_string(),
            relays: Vec::new(),
            direct: Vec::new(),
            local_direct: Vec::new(),
            local_tag: None,
            proven: true,
        }
    }

    fn at(host: &str, peer_id: &str) -> ViaAddr {
        parse_via(&format!("{host}/tcp/7423/p2p/{peer_id}")).unwrap()
    }

    /// Learned direct addresses before the book's, IPv6 first within each;
    /// the learned relays' circuits before the book's. The first direct
    /// address, then the first circuit, then the rest; deduplicated; at most
    /// MAX_DIAL_ADDRS.
    #[test]
    fn p2p_dial_set_order() {
        let bob = peer(2);
        let (r1, r2, r3) = (peer(11), peer(12), peer(13));
        let book = ContactP2p::from_fields(
            &bob,
            &[
                at("/ip4/198.51.100.1", &r1).text,
                at("/ip4/203.0.113.9", &bob).text,
            ],
        )
        .unwrap();
        let mut hint = learned(&bob);
        hint.direct = vec![
            at("/ip4/11.0.3.5", &bob),
            at("/ip6/2001:4860::5", &bob),
            // Also the book's: dialled once.
            at("/ip4/203.0.113.9", &bob),
        ];
        hint.relays = vec![
            at("/ip4/11.0.2.1", &r2),
            parse_via(&format!("/ip4/11.0.2.1/udp/7423/quic-v1/p2p/{r2}")).unwrap(),
            // Also the book's relay.
            at("/ip4/198.51.100.1", &r1),
        ];
        let set = P2pDialSet::merge(Some(&book), Some(&hint), |_| true, None).unwrap();
        let direct: Vec<&str> = set.direct.iter().map(|v| v.text.as_str()).collect();
        assert_eq!(
            direct,
            [
                hint.direct[1].text.as_str(),
                hint.direct[0].text.as_str(),
                hint.direct[2].text.as_str(),
            ]
        );
        let circuit = |v: &ViaAddr| circuit_addr(v, &bob);
        assert_eq!(
            set.dial_addrs(),
            [
                hint.direct[1].text.clone(),
                circuit(&hint.relays[0]),
                hint.direct[0].text.clone(),
                hint.direct[2].text.clone(),
                // R1 (the book's) before R2's fallback.
                circuit(&hint.relays[2]),
                circuit(&hint.relays[1]),
            ]
        );
        assert_eq!(set.relay_peer_ids(), [r2.clone(), r1.clone()]);

        // At most MAX_DIAL_ADDRS, whatever was learned.
        hint.local_direct = vec![at("/ip4/192.168.7.20", &bob), at("/ip4/192.168.7.21", &bob)];
        hint.relays.push(at("/ip4/11.0.2.3", &r3));
        let set = P2pDialSet::merge(Some(&book), Some(&hint), |_| true, None).unwrap();
        assert_eq!((set.direct.len(), set.relays.len()), (5, 4));
        let addrs = set.dial_addrs();
        assert_eq!(addrs.len(), MAX_DIAL_ADDRS);
        let unique: std::collections::HashSet<&String> = addrs.iter().collect();
        assert_eq!(unique.len(), addrs.len());

        // The book wins: hints naming another PeerId are ignored whole.
        let other = learned(&peer(3));
        let set = P2pDialSet::merge(Some(&book), Some(&other), |_| true, None).unwrap();
        assert_eq!(set.dial_addrs(), book.dial_addrs());
        // No book PeerId: the learned one. Neither, or junk: nothing.
        let set = P2pDialSet::merge(None, Some(&hint), |_| true, None).unwrap();
        assert_eq!(set.peer_id, bob);
        assert_eq!(set.relay_peer_ids(), [r2.clone(), r1.clone(), r3.clone()]);
        assert_eq!(P2pDialSet::merge(None, None, |_| true, None), None);
        assert_eq!(
            P2pDialSet::merge(None, Some(&learned("junk")), |_| true, None),
            None
        );
    }

    /// Hide my IP (D4): no direct address, and circuits only through a
    /// relay this node holds itself, at this node's own addresses for it. A
    /// relay only the contact names (its book `relay=`/`via=` or its route
    /// hints) could be the contact's own, which would see this node's IP: no
    /// circuit through it. An address the contact gives for one of this
    /// node's relays could be the contact's own host, which a circuit makes
    /// this node dial while it holds no connection to that relay: never
    /// used.
    #[test]
    fn hide_ip_keeps_circuits_through_own_relays_only() {
        let (bob, relay, theirs) = (peer(2), peer(11), peer(12));
        let book = ContactP2p::from_fields(
            &bob,
            &[
                at("/ip4/203.0.113.9", &bob).text,
                at("/ip4/198.51.100.1", &relay).text,
            ],
        )
        .unwrap();
        let mut hint = learned(&bob);
        hint.direct = vec![at("/ip6/2001:4860::5", &bob)];
        hint.local_direct = vec![at("/ip4/192.168.7.20", &bob)];
        hint.relays = vec![at("/ip4/11.0.2.7", &theirs)];
        // A relay this node holds too: its circuit only, at this node's own
        // addresses for it (two: its fallback too), never the book's.
        let mine = [
            at("/ip4/11.0.5.1", &relay),
            parse_via(&format!("/ip4/11.0.5.1/tcp/443/p2p/{relay}")).unwrap(),
            at("/ip4/11.0.5.3", &peer(13)),
        ];
        let set = P2pDialSet::merge(Some(&book), Some(&hint), |_| true, Some(&mine)).unwrap();
        assert!(set.direct.is_empty());
        assert_eq!(
            set.dial_addrs(),
            [circuit_addr(&mine[0], &bob), circuit_addr(&mine[1], &bob)]
        );
        assert_eq!(set.relay_peer_ids(), std::slice::from_ref(&relay));
        assert!(
            !set.dial_addrs().iter().any(|a| a.contains("198.51.100.1")),
            "the contact's address for our relay"
        );
        // Holding the relay its hints name: that one, at our address for
        // it, never the hint's (11.0.2.7, which the contact chose).
        let ours = at("/ip4/11.0.6.1", &theirs);
        let set = P2pDialSet::merge(
            Some(&book),
            Some(&hint),
            |_| true,
            Some(std::slice::from_ref(&ours)),
        )
        .unwrap();
        assert_eq!(set.dial_addrs(), [circuit_addr(&ours, &bob)]);
        assert_eq!(set.relay_peer_ids(), std::slice::from_ref(&theirs));
        // No relay in common: nothing to dial, neither the book's relay nor
        // the learned one (both may be the contact's own).
        let set = P2pDialSet::merge(Some(&book), Some(&hint), |_| true, Some(&[])).unwrap();
        assert!(set.dial_addrs().is_empty() && set.relay_peer_ids().is_empty());
        // Shown: everything, as before.
        let set = P2pDialSet::merge(Some(&book), Some(&hint), |_| true, None).unwrap();
        assert_eq!(set.relay_peer_ids(), [theirs, relay]);
        assert_eq!(set.direct.len(), 3);
        // Without a relay there is nothing left to dial.
        let alone = ContactP2p::from_fields(&bob, &[at("/ip4/203.0.113.9", &bob).text]).unwrap();
        hint.relays.clear();
        let set = P2pDialSet::merge(Some(&alone), Some(&hint), |_| true, Some(&mine)).unwrap();
        assert!(set.dial_addrs().is_empty());
    }

    /// A contact with many direct addresses (stale book ones too) and two
    /// relays at two addresses each: every relay keeps a circuit within
    /// MAX_DIAL_ADDRS, and the extra direct addresses (the book's, last in
    /// plan order) are the ones left out.
    #[test]
    fn dial_addrs_keep_every_relay_within_the_cap() {
        let bob = peer(2);
        let (r1, r2) = (peer(11), peer(12));
        let book = ContactP2p::from_fields(
            &bob,
            &[
                at("/ip4/11.0.9.1", &bob).text,
                at("/ip4/11.0.9.2", &bob).text,
            ],
        )
        .unwrap();
        let mut hint = learned(&bob);
        hint.direct = (1..=4)
            .map(|i| at(&format!("/ip4/11.0.3.{i}"), &bob))
            .collect();
        let tcp443 =
            |host: &str, relay: &str| parse_via(&format!("{host}/tcp/443/p2p/{relay}")).unwrap();
        hint.relays = vec![
            at("/ip4/11.0.2.1", &r1),
            tcp443("/ip4/11.0.2.1", &r1),
            at("/ip4/11.0.2.2", &r2),
            tcp443("/ip4/11.0.2.2", &r2),
        ];
        let set = P2pDialSet::merge(Some(&book), Some(&hint), |_| true, None).unwrap();
        assert_eq!((set.direct.len(), set.relays.len()), (6, 4));
        let c = |v: &ViaAddr| circuit_addr(v, &bob);
        let d = |i: usize| hint.direct[i].text.clone();
        assert_eq!(
            set.dial_addrs(),
            [
                d(0),
                c(&hint.relays[0]),
                d(1),
                d(2),
                d(3),
                c(&hint.relays[2]),
                c(&hint.relays[1]),
                c(&hint.relays[3]),
            ]
        );
        // Fewer circuits leave the direct addresses more room.
        hint.relays.truncate(1);
        let set = P2pDialSet::merge(Some(&book), Some(&hint), |_| true, None).unwrap();
        let addrs = set.dial_addrs();
        assert_eq!(addrs.len(), 7);
        assert_eq!(addrs[1], c(&hint.relays[0]));
    }

    /// Same-LAN addresses are used only where the caller says so: here, on
    /// the network they were learned on.
    #[test]
    fn local_direct_only_with_a_matching_network_tag() {
        let bob = peer(2);
        let mut hint = learned(&bob);
        hint.direct = vec![at("/ip4/11.0.3.5", &bob)];
        hint.local_direct = vec![at("/ip4/192.168.7.20", &bob)];
        hint.local_tag = Some("net-a".into());
        let on = |tag: &'static str| {
            let hint = hint.clone();
            let asked = std::cell::RefCell::new(Vec::new());
            let set = P2pDialSet::merge(
                None,
                Some(&hint),
                |v| {
                    asked.borrow_mut().push(v.text.clone());
                    hint.local_tag.as_deref() == Some(tag)
                },
                None,
            )
            .unwrap();
            (set.dial_addrs(), asked.into_inner())
        };
        let (here, asked) = on("net-a");
        assert_eq!(
            here,
            [
                hint.local_direct[0].text.clone(),
                hint.direct[0].text.clone()
            ]
        );
        assert_eq!(
            asked,
            [hint.local_direct[0].text.clone()],
            "global ones are not asked about"
        );
        let (elsewhere, _) = on("net-b");
        assert_eq!(elsewhere, [hint.direct[0].text.clone()]);
    }

    /// libp2p dials two addresses at once: however many direct addresses
    /// are stale, at most one of them is dialled ahead of the first circuit.
    #[test]
    fn a_stale_direct_never_precedes_two_circuits() {
        let bob = peer(2);
        for directs in 0..=6u8 {
            for relays in 0..=4u8 {
                let mut hint = learned(&bob);
                hint.direct = (0..directs)
                    .map(|i| at(&format!("/ip4/11.0.3.{}", i + 1), &bob))
                    .collect();
                hint.relays = (0..relays)
                    .map(|i| at(&format!("/ip4/11.0.2.{}", i + 1), &peer(20 + i)))
                    .collect();
                let set = P2pDialSet::merge(None, Some(&hint), |_| true, None).unwrap();
                let addrs = set.dial_addrs();
                let first_circuit = addrs.iter().position(|a| a.contains("/p2p-circuit/"));
                match first_circuit {
                    Some(i) => assert!(i <= 1, "{directs} {relays}: {addrs:?}"),
                    None => assert_eq!(relays, 0),
                }
                assert_eq!(
                    addrs.len(),
                    usize::from(directs + relays).min(MAX_DIAL_ADDRS)
                );
            }
        }
        let mut hint = learned(&bob);
        hint.direct = (1..=3)
            .map(|i| at(&format!("/ip4/11.0.3.{i}"), &bob))
            .collect();
        hint.relays = vec![
            at("/ip4/11.0.2.1", &peer(20)),
            at("/ip4/11.0.2.2", &peer(21)),
        ];
        let set = P2pDialSet::merge(None, Some(&hint), |_| true, None).unwrap();
        let c = |i: usize| circuit_addr(&hint.relays[i], &bob);
        let d = |i: usize| hint.direct[i].text.clone();
        assert_eq!(set.dial_addrs(), [d(0), c(0), d(1), d(2), c(1)]);
    }

    #[test]
    fn listen_setting_is_opt_in_and_covers_both_families() {
        assert_eq!(normalize_p2p_listen("").unwrap(), None);
        assert_eq!(normalize_p2p_listen(" off ").unwrap(), None);
        assert_eq!(
            normalize_p2p_listen("on").unwrap(),
            Some(P2pListen::All(DEFAULT_P2P_PORT))
        );
        let all = normalize_p2p_listen("7423").unwrap().unwrap();
        assert_eq!(
            all.multiaddrs(),
            vec![
                "/ip4/0.0.0.0/tcp/7423",
                "/ip4/0.0.0.0/udp/7423/quic-v1",
                "/ip6/::/tcp/7423",
                "/ip6/::/udp/7423/quic-v1"
            ]
        );
        assert_eq!(all.policy_text(), "7423");
        let one = normalize_p2p_listen("127.0.0.1:0").unwrap().unwrap();
        assert_eq!(
            one.multiaddrs(),
            vec!["/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/udp/0/quic-v1"]
        );
        assert_eq!(
            normalize_p2p_listen("[::1]:7423")
                .unwrap()
                .unwrap()
                .multiaddrs()[0],
            "/ip6/::1/tcp/7423"
        );
        let relay_only = normalize_p2p_listen("relay").unwrap().unwrap();
        assert!(relay_only.multiaddrs().is_empty());
        assert_eq!(relay_only.policy_text(), "relay");
        // `relay` is retired: it listens on every interface anyway, unless
        // the debug test switch keeps it; everything else passes through.
        assert_eq!(
            relay_only.effective(false),
            (P2pListen::All(DEFAULT_P2P_PORT), true)
        );
        assert_eq!(relay_only.effective(true), (P2pListen::RelayOnly, false));
        for keep in [all, one] {
            assert_eq!(keep.effective(false), (keep, false));
            assert_eq!(keep.effective(true), (keep, false));
        }
        assert!(RELAY_LISTEN_RETIRED.contains("\"relay\" is retired"));
        assert!(normalize_p2p_listen("yes")
            .unwrap_err()
            .contains("\"relay\" is retired"));
        for bad in ["07423", "99999", "host:7423", "yes", "1.2.3.4"] {
            assert!(normalize_p2p_listen(bad).is_err(), "{bad}");
        }
    }

    /// One host grammar: each host is accepted or refused alike by
    /// `parse_via`, `parse_host_transport` and `host_prefix` (which names a
    /// DNS host `/dns/`), with the same canonical text.
    #[test]
    fn parse_host_transport_and_host_prefix_share_parse_via_hosts() {
        let r = peer(1);
        let table: &[(&str, &str, Option<&str>)] = &[
            ("ip4", "203.0.113.7", Some("/ip4/203.0.113.7")),
            ("ip4", "127.0.0.1", Some("/ip4/127.0.0.1")),
            ("ip6", "2001:DB8:0::1", Some("/ip6/2001:db8::1")),
            ("ip6", "::1", Some("/ip6/::1")),
            ("dns", "Relay.Example.org", Some("/dns/relay.example.org")),
            ("dns4", "relay.example.com", Some("/dns4/relay.example.com")),
            ("dns6", "v6.example.net", Some("/dns6/v6.example.net")),
            ("ip4", "0.0.0.0", None),
            ("ip4", "255.255.255.255", None),
            ("ip4", "224.0.0.1", None),
            ("ip6", "::", None),
            ("ip6", "ff02::1", None),
            ("dns", "-bad", None),
            ("dns", "bad-", None),
            ("dns", ".lead", None),
            ("dns", "a..b", None),
            ("dns", "a_b", None),
            ("dns", "x/y", None),
        ];
        for (kind, value, want) in table {
            let via = parse_via(&format!("/{kind}/{value}/tcp/7423/p2p/{r}")).map(|v| v.text);
            let ht = parse_host_transport(&format!("/{kind}/{value}/tcp/7423"));
            let ht_quic = parse_host_transport(&format!("/{kind}/{value}/udp/7423/quic-v1"));
            let prefix = host_prefix(value);
            match want {
                Some(host) => {
                    assert_eq!(via.unwrap(), format!("{host}/tcp/7423/p2p/{r}"), "{value}");
                    assert_eq!(ht.unwrap(), format!("{host}/tcp/7423"), "{value}");
                    assert_eq!(ht_quic.unwrap(), format!("{host}/udp/7423/quic-v1"));
                    let named = host
                        .replacen("/dns4/", "/dns/", 1)
                        .replacen("/dns6/", "/dns/", 1);
                    assert_eq!(prefix.unwrap(), named, "{value}");
                }
                None => {
                    assert!(via.is_err(), "{kind} {value}");
                    assert!(ht.is_err(), "{kind} {value}");
                    assert!(ht_quic.is_err(), "{kind} {value}");
                    assert!(prefix.is_err(), "{value}");
                }
            }
        }
        // An address that names no single host: refused alike, and said so.
        let none = parse_via(&format!("/ip4/0.0.0.0/tcp/7423/p2p/{r}")).unwrap_err();
        assert!(none.contains("names no single host"), "{none}");
        let none = parse_host_transport("/ip4/0.0.0.0/tcp/7423").unwrap_err();
        assert!(none.contains("names no single host"), "{none}");
        assert!(host_prefix("0.0.0.0")
            .unwrap_err()
            .contains("names no single host"));
        // Host and transport only: no PeerId, no circuit, nothing after.
        for bad in [
            format!("/ip4/203.0.113.7/tcp/7423/p2p/{r}"),
            "/ip4/203.0.113.7/tcp/7423/ws".to_string(),
            "/ip4/203.0.113.7/tcp/7423/".to_string(),
            "/ip4/203.0.113.7/tcp/0".to_string(),
            "/ip4/203.0.113.7/udp/7423".to_string(),
            "/ip4/203.0.113.7".to_string(),
            "ip4/203.0.113.7/tcp/7423".to_string(),
            format!("/dns/{}/tcp/7423", "a".repeat(MAX_MULTIADDR_CHARS)),
        ] {
            assert!(parse_host_transport(&bad).is_err(), "{bad}");
        }
        // The canonical text parses to itself.
        let t = parse_host_transport(" /ip6/2001:DB8::7/udp/443/quic-v1 ").unwrap();
        assert_eq!(t, "/ip6/2001:db8::7/udp/443/quic-v1");
        assert_eq!(parse_host_transport(&t).unwrap(), t);
    }

    #[test]
    fn host_prefix_is_strict() {
        assert_eq!(host_prefix("203.0.113.7").unwrap(), "/ip4/203.0.113.7");
        assert_eq!(host_prefix(" 2001:db8::7 ").unwrap(), "/ip6/2001:db8::7");
        assert_eq!(host_prefix("[2001:DB8::7]").unwrap(), "/ip6/2001:db8::7");
        assert_eq!(
            host_prefix("Relay.Example.com").unwrap(),
            "/dns/relay.example.com"
        );
        for bad in [
            "",
            "0.0.0.0",
            "::",
            "[::]",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "/x",
            "/ip4/203.0.113.7",
            "a b",
            "-x",
            "x-",
            "a..b",
            "[203.0.113.7]",
            "[relay.example.com]",
            "[2001:db8::7",
            "2001:db8::7]",
            "relay.example.com:7423",
            "203.0.113.7:7423",
            &"a".repeat(254),
        ] {
            assert!(host_prefix(bad).is_err(), "{bad:?}");
        }
        let shown = host_prefix("bad\u{1b}[31mhost").unwrap_err();
        assert!(!shown.contains('\u{1b}'), "{shown}");
    }

    #[test]
    fn parse_extra_tcp_table() {
        let ok = |s: &str, local: u16, public: u16| {
            assert_eq!(
                parse_extra_tcp(s).unwrap(),
                ExtraTcp { local, public },
                "{s}"
            );
        };
        ok("443", 443, 443);
        ok(" 443 ", 443, 443);
        ok("7443:443", 7443, 443);
        ok("0", 0, 0);
        ok("65535", 65535, 65535);
        for bad in [
            "", ":", "abc", "1:2:3", "70000", "443:0", "0:443", "443:", ":443", "+443", "0443",
            "443:0443", "-1", "4 43",
        ] {
            let e = parse_extra_tcp(bad).unwrap_err();
            assert!(
                e.contains("--also-tcp must be PORT or LOCAL:PUBLIC"),
                "{bad}: {e}"
            );
        }
    }

    #[test]
    fn relay_listen_multiaddrs_adds_tcp_only_extras() {
        let extra = |s: &str| parse_extra_tcp(s).unwrap();
        let all = P2pListen::All(DEFAULT_P2P_PORT);
        assert_eq!(
            relay_listen_multiaddrs(&all, &[extra("443")]).unwrap(),
            [
                "/ip4/0.0.0.0/tcp/7423",
                "/ip4/0.0.0.0/udp/7423/quic-v1",
                "/ip6/::/tcp/7423",
                "/ip6/::/udp/7423/quic-v1",
                "/ip4/0.0.0.0/tcp/443",
                "/ip6/::/tcp/443",
            ]
        );
        // The extra port listens on LOCAL; PUBLIC is only what friends dial.
        assert_eq!(
            relay_listen_multiaddrs(&all, &[extra("7443:443")]).unwrap()[4..],
            ["/ip4/0.0.0.0/tcp/7443", "/ip6/::/tcp/7443"]
        );
        let lab = normalize_p2p_listen("127.0.0.1:0").unwrap().unwrap();
        assert_eq!(
            relay_listen_multiaddrs(&lab, &[extra("0")]).unwrap(),
            [
                "/ip4/127.0.0.1/tcp/0",
                "/ip4/127.0.0.1/udp/0/quic-v1",
                "/ip4/127.0.0.1/tcp/0"
            ]
        );
        assert_eq!(
            relay_listen_multiaddrs(&all, &[]).unwrap(),
            all.multiaddrs()
        );
        assert_eq!(
            relay_listen_multiaddrs(&all, &[extra("443"), extra("8443")])
                .unwrap()
                .len(),
            8
        );
        let dup = relay_listen_multiaddrs(&all, &[extra("7423")]).unwrap_err();
        assert!(dup.contains("already a listen port"), "{dup}");
        assert!(relay_listen_multiaddrs(&all, &[extra("443"), extra("443")]).is_err());
        assert!(relay_listen_multiaddrs(&all, &[extra("1"), extra("2"), extra("3")]).is_err());
        assert!(relay_listen_multiaddrs(&P2pListen::RelayOnly, &[]).is_err());
    }

    #[test]
    fn relay_public_addrs_order_and_port_zero_refused() {
        let extra = |s: &str| parse_extra_tcp(s).unwrap();
        let addrs = relay_public_addrs("relay.example.org", 7423, &[extra("7443:443")]).unwrap();
        assert_eq!(
            addrs,
            [
                "/dns/relay.example.org/tcp/7423",
                "/dns/relay.example.org/udp/7423/quic-v1",
                "/dns/relay.example.org/tcp/443",
            ]
        );
        // Each is a canonical host-and-transport address, a via= with a PeerId.
        for a in &addrs {
            assert_eq!(&parse_host_transport(a).unwrap(), a);
            parse_via(&format!("{a}/p2p/{}", peer(1))).unwrap();
        }
        assert_eq!(
            relay_public_addrs("[2001:db8::7]", 7423, &[]).unwrap(),
            [
                "/ip6/2001:db8::7/tcp/7423",
                "/ip6/2001:db8::7/udp/7423/quic-v1"
            ]
        );
        // A public port already named is named once.
        assert_eq!(
            relay_public_addrs("203.0.113.7", 7423, &[extra("7443:7423")])
                .unwrap()
                .len(),
            2
        );
        for (host, port, extras) in [
            ("203.0.113.7", 0, vec![]),
            ("203.0.113.7", 7423, vec![extra("0")]),
            ("0.0.0.0", 7423, vec![]),
            ("", 7423, vec![]),
            ("a b", 7423, vec![]),
        ] {
            assert!(
                relay_public_addrs(host, port, &extras).is_err(),
                "{host} {port}"
            );
        }
        let zero = relay_public_addrs("203.0.113.7", 0, &[]).unwrap_err();
        assert!(zero.contains("fixed ports"), "{zero}");
    }

    #[test]
    fn split_relay_tokens_accepts_pasted_lines() {
        let (r1, r2) = (peer(11), peer(12));
        let tcp = format!("/ip4/198.51.100.1/tcp/7423/p2p/{r1}");
        let tls = format!("/ip4/198.51.100.1/tcp/443/p2p/{r1}");
        let texts = |vias: Vec<ViaAddr>| vias.into_iter().map(|v| v.text).collect::<Vec<_>>();
        // With or without via=, separated by newlines, spaces or commas.
        for pasted in [
            format!("via={tcp}\nvia={tls}\n"),
            format!("{tcp} {tls}"),
            format!("  via={tcp},{tls}  "),
            format!("via={tcp}\r\n\tvia={tls}, via={tcp}"),
        ] {
            assert_eq!(
                texts(split_relay_tokens(&pasted).unwrap()),
                [tcp.clone(), tls.clone()],
                "{pasted:?}"
            );
        }
        // Canonical text: normalised and deduplicated as parse_via does.
        let upper = format!("/dns4/Relay.Example.com/tcp/7423/p2p/{r2}");
        assert_eq!(
            texts(split_relay_tokens(&format!("{upper} via={upper}")).unwrap()),
            [format!("/dns4/relay.example.com/tcp/7423/p2p/{r2}")]
        );
        // Refused whole: a third address, junk, nothing, too much text.
        let third = format!("/ip4/198.51.100.2/tcp/7423/p2p/{r2}");
        let e = split_relay_tokens(&format!("{tcp} {tls} {third}")).unwrap_err();
        assert!(e.contains("at most 2 relay addresses"), "{e}");
        for bad in [
            format!("{tcp} junk"),
            format!("via= {tcp}"),
            format!("p2p={r1}"),
            format!("{tcp}/p2p-circuit/p2p/{r2}"),
            String::new(),
            " ,\n, ".to_string(),
            format!("{tcp} {}", " ".repeat(MAX_RELAY_PASTE)),
        ] {
            assert!(split_relay_tokens(&bad).is_err(), "{bad:?}");
        }
        // Up to the bound, whitespace is fine.
        let padded = format!("{tcp}{}", " ".repeat(MAX_RELAY_PASTE - tcp.len()));
        assert_eq!(split_relay_tokens(&padded).unwrap().len(), 1);
    }

    #[test]
    fn group_relays_keeps_card_order_and_groups_by_peer() {
        let (r1, r2) = (peer(11), peer(12));
        let v = |host: &str, port: u16, who: &str| {
            parse_via(&format!("{host}/tcp/{port}/p2p/{who}")).unwrap()
        };
        let relays = [
            v("/ip4/198.51.100.2", 7423, &r2),
            v("/ip4/198.51.100.1", 7423, &r1),
            v("/ip4/198.51.100.2", 443, &r2),
            v("/ip4/198.51.100.2", 7423, &r2),
        ];
        let groups = group_relays(&relays);
        assert_eq!(
            groups,
            [
                (r2.clone(), vec![relays[0].clone(), relays[2].clone()]),
                (r1.clone(), vec![relays[1].clone()]),
            ]
        );
        assert_eq!(distinct_relays(&relays), 2);
        assert_eq!(distinct_relays(&relays[..1]), 1);
        assert_eq!(distinct_relays(&[relays[0].clone(), relays[2].clone()]), 1);
        assert!(group_relays(&[]).is_empty());
        assert_eq!(distinct_relays(&[]), 0);
    }

    // ── WebSocket over TLS (RAVEN_WSS_TRANSPORT_V1.md §2) ─────────────────────

    /// RWS1 §2: `/tls/ws` after `/tcp/PORT`, `/tls/sni/NAME/ws` only after an
    /// IP host, `/wss` stored as `/tls/ws`; every other WebSocket or TLS form,
    /// any suffix on QUIC and every circuit refused.
    #[test]
    fn via_grammar_accepts_wss_forms_canonically() {
        let r = peer(1);
        let v4 = "/ip4/203.0.113.7";
        let ok = |s: &str| parse_via(s).unwrap_or_else(|e| panic!("{s}: {e}")).text;
        assert_eq!(
            ok(&format!("{v4}/tcp/443/wss/p2p/{r}")),
            format!("{v4}/tcp/443/tls/ws/p2p/{r}")
        );
        assert_eq!(
            ok(&format!("{v4}/tcp/443/tls/ws/p2p/{r}")),
            format!("{v4}/tcp/443/tls/ws/p2p/{r}")
        );
        assert_eq!(
            ok(&format!(
                "{v4}/tcp/8443/tls/sni/Relay.Example.org/ws/p2p/{r}"
            )),
            format!("{v4}/tcp/8443/tls/sni/relay.example.org/ws/p2p/{r}")
        );
        assert_eq!(
            ok(&format!(
                "/ip6/2001:DB8::7/tcp/443/tls/sni/relay.example.org/ws/p2p/{r}"
            )),
            format!("/ip6/2001:db8::7/tcp/443/tls/sni/relay.example.org/ws/p2p/{r}")
        );
        assert_eq!(
            ok(&format!("/dns4/Relay.Example.org/tcp/443/tls/ws/p2p/{r}")),
            format!("/dns4/relay.example.org/tcp/443/tls/ws/p2p/{r}")
        );
        // The canonical text is a fixed point; the PeerId is the terminal one.
        let t = ok(&format!(" {v4}/tcp/443/wss/p2p/{r} "));
        assert_eq!(ok(&t), t);
        assert_eq!(parse_via(&t).unwrap().peer_id, r);
        // At the bound once /wss is written /tls/ws: kept; one past it: refused.
        // A name of `n` characters in labels of 63 (RWS1 §2.1).
        let long = |n: usize| -> String {
            (1..=n)
                .map(|i| if i % 64 == 0 { '.' } else { 'a' })
                .collect()
        };
        let at_bound = ok(&format!("/dns/{}/tcp/443/wss/p2p/{r}", long(223)));
        assert_eq!(at_bound.len(), MAX_MULTIADDR_CHARS);
        let hash = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g";
        for bad in [
            // A DNS host already is the SNI name; an IP literal or junk is none.
            format!("/dns4/relay.example.org/tcp/443/tls/sni/relay.example.org/ws/p2p/{r}"),
            format!("/dns/relay.example.org/tcp/443/tls/sni/other.example.org/ws/p2p/{r}"),
            format!("{v4}/tcp/443/tls/sni/203.0.113.8/ws/p2p/{r}"),
            format!("{v4}/tcp/443/tls/sni/a..b/ws/p2p/{r}"),
            format!("{v4}/tcp/443/tls/sni/relay.example.org/p2p/{r}"),
            // Plain WebSocket, certhash, the old parity forms and the rest.
            format!("{v4}/tcp/443/ws/p2p/{r}"),
            format!("{v4}/tcp/443/tls/p2p/{r}"),
            format!("{v4}/tcp/443/certhash/{hash}/p2p/{r}"),
            format!("{v4}/tcp/443/tls/ws/certhash/{hash}/p2p/{r}"),
            format!("{v4}/tcp/443/x-parity-ws/%2F/p2p/{r}"),
            format!("{v4}/tcp/443/x-parity-wss/%2F/p2p/{r}"),
            format!("{v4}/tcp/443/https/p2p/{r}"),
            format!("{v4}/tcp/443/http-path/%2F/p2p/{r}"),
            format!("{v4}/tcp/443/tls/http/p2p/{r}"),
            format!("{v4}/tcp/443/noise/p2p/{r}"),
            format!("{v4}/tcp/443/tls/ws/ws/p2p/{r}"),
            format!("{v4}/tcp/443/TLS/ws/p2p/{r}"),
            format!("{v4}/tcp/443/tls/ws"),
            // WebSocket over TLS never runs on QUIC.
            format!("{v4}/udp/443/quic-v1/tls/ws/p2p/{r}"),
            format!("{v4}/udp/443/quic-v1/wss/p2p/{r}"),
            // A circuit through a WSS address is still a circuit.
            format!("{v4}/tcp/443/tls/ws/p2p/{r}/p2p-circuit/p2p/{}", peer(2)),
            format!("{v4}/tcp/443/tls/ws/p2p-circuit/p2p/{r}"),
            // 303 characters once /wss is written /tls/ws.
            format!("/dns/{}/tcp/443/wss/p2p/{r}", long(226)),
        ] {
            assert!(parse_via(&bad).is_err(), "{bad}");
        }
        // via_grammar_is_narrow's plain /ws after TCP 7423 stays a bad case,
        // now with the reason.
        let plain = parse_via(&format!("{v4}/tcp/7423/ws/p2p/{r}")).unwrap_err();
        assert!(plain.contains("only /tls/ws"), "{plain}");
        let quic = parse_via(&format!("{v4}/udp/443/quic-v1/tls/ws/p2p/{r}")).unwrap_err();
        assert!(quic.contains("TCP only"), "{quic}");
        let circuit = parse_via(&format!(
            "{v4}/tcp/443/tls/ws/p2p/{r}/p2p-circuit/p2p/{}",
            peer(2)
        ))
        .unwrap_err();
        assert!(circuit.contains("circuit"), "{circuit}");
        // A relay offer's or a relay's own address takes no suffix.
        assert!(parse_host_transport(&format!("{v4}/tcp/443/tls/ws")).is_err());
        assert!(parse_host_transport(&format!("{v4}/tcp/443/wss")).is_err());
    }

    /// `shared-vectors/rvn1/p2p/via_001.json`, written by the independent
    /// Python grammar (`protocol/reference/generate_wss.py`).
    #[test]
    fn via_vectors_match() {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        let path = p.join("shared-vectors/rvn1/p2p/via_001.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let inputs = &v["inputs"];
        for who in ["relay", "contact"] {
            let public: [u8; 32] = hex::decode(
                inputs[format!("{who}_ed25519_public_hex")]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
            assert_eq!(
                peer_id_from_ed25519_public(&public),
                inputs[format!("{who}_peer_id")]
            );
        }
        assert_eq!(MAX_MULTIADDR_CHARS, inputs["max_multiaddr_chars"]);
        let accept = v["expected"]["accept"].as_array().unwrap();
        let reject = v["expected"]["reject"].as_array().unwrap();
        assert!(accept.len() >= 10 && reject.len() >= 20);
        let text = |x: &serde_json::Value| x.as_str().map(str::to_string);
        for case in accept {
            let input = case["input"].as_str().unwrap();
            let via = parse_via(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(via.text, case["canonical"], "{input}");
            assert_eq!(via.peer_id, case["peer_id"], "{input}");
            assert_eq!(parse_via(&via.text).unwrap(), via, "{input}");
            assert_eq!(via.is_wss(), case["is_wss"], "{input}");
            assert_eq!(
                via.tcp_port().map(u64::from),
                case["tcp_port"].as_u64(),
                "{input}"
            );
            assert_eq!(via.raw_sibling(), text(&case["raw_sibling"]), "{input}");
            assert_eq!(via.wss_sibling(), text(&case["wss_sibling"]), "{input}");
            for (key, wss_ok, prefer_wss) in [
                ("gate_closed", false, false),
                ("raw_first", true, false),
                ("wss_first", true, true),
            ] {
                let want: Vec<String> =
                    serde_json::from_value(case["dial_forms"][key].clone()).unwrap();
                assert_eq!(
                    relay_dial_forms(&via, wss_ok, prefer_wss),
                    want,
                    "{input} {key}"
                );
            }
        }
        for case in reject {
            let input = case["input"].as_str().unwrap();
            let code = case["error"].as_str().unwrap();
            let err = parse_via(input).expect_err(input);
            // The Python grammar's refusal step, as the Rust text says it.
            let says = match code {
                "circuit" => "circuit",
                "wss_suffix" => "only /tls/ws",
                "quic_suffix" => "TCP only",
                "no_single_host" => "names no single host",
                "port" => "1-65535",
                "peer_id" => "PeerId",
                "too_long" => "once /wss is written /tls/ws",
                "not_multiaddr" => "is not a multiaddr",
                "syntax" | "host" | "transport" => "must look like",
                other => panic!("{input}: unknown error code {other}"),
            };
            assert!(err.contains(says), "{input}: {code}: {err}");
        }
    }

    /// RWS1 §2.3: raw TCP 443 is also a WSS port by convention, a WSS port
    /// also takes raw libp2p, everything else is dialled as it is; the WSS
    /// form only while the gate is live, first only when preferred.
    #[test]
    fn relay_dial_forms_table() {
        let r = peer(1);
        let t = |s: &str| format!("{s}/p2p/{r}");
        let v = |s: &str| parse_via(&t(s)).unwrap();
        let every = [(false, false), (false, true), (true, false), (true, true)];
        // Raw 443: [raw, wss] or [wss, raw]; raw only with the gate closed.
        let raw443 = v("/ip4/203.0.113.7/tcp/443");
        let wss443 = t("/ip4/203.0.113.7/tcp/443/tls/ws");
        assert_eq!(
            relay_dial_forms(&raw443, true, false),
            [raw443.text.clone(), wss443.clone()]
        );
        assert_eq!(
            relay_dial_forms(&raw443, true, true),
            [wss443.clone(), raw443.text.clone()]
        );
        for prefer in [false, true] {
            assert_eq!(
                relay_dial_forms(&raw443, false, prefer),
                std::slice::from_ref(&raw443.text)
            );
        }
        // WSS on any port: the WSS form and its raw sibling on that port.
        let wss8443 = v("/dns4/relay.example.org/tcp/8443/tls/ws");
        let raw8443 = t("/dns4/relay.example.org/tcp/8443");
        assert_eq!(
            relay_dial_forms(&wss8443, true, true),
            [wss8443.text.clone(), raw8443.clone()]
        );
        assert_eq!(
            relay_dial_forms(&wss8443, true, false),
            [raw8443.clone(), wss8443.text.clone()]
        );
        assert_eq!(
            relay_dial_forms(&wss8443, false, true),
            std::slice::from_ref(&raw8443)
        );
        let sni = v("/ip6/2001:db8::7/tcp/443/tls/sni/relay.example.org/ws");
        assert_eq!(
            relay_dial_forms(&sni, true, true),
            [sni.text.clone(), t("/ip6/2001:db8::7/tcp/443")]
        );
        // Other raw ports and QUIC: themselves, whatever the gate.
        let raw7423 = v("/ip4/203.0.113.7/tcp/7423");
        let quic = v("/ip4/203.0.113.7/udp/443/quic-v1");
        for (wss_ok, prefer) in every {
            assert_eq!(
                relay_dial_forms(&raw7423, wss_ok, prefer),
                std::slice::from_ref(&raw7423.text)
            );
            assert_eq!(
                relay_dial_forms(&quic, wss_ok, prefer),
                std::slice::from_ref(&quic.text)
            );
        }
        // The helpers.
        assert!(sni.is_wss() && wss8443.is_wss() && !raw443.is_wss() && !quic.is_wss());
        assert_eq!(
            (raw443.tcp_port(), wss8443.tcp_port(), quic.tcp_port()),
            (Some(443), Some(8443), None)
        );
        assert_eq!(raw443.wss_sibling(), Some(wss443.clone()));
        assert_eq!(raw443.raw_sibling(), None);
        assert_eq!(wss8443.raw_sibling(), Some(raw8443.clone()));
        assert_eq!(wss8443.wss_sibling(), None);
        assert_eq!((raw7423.raw_sibling(), raw7423.wss_sibling()), (None, None));
        assert_eq!((quic.raw_sibling(), quic.wss_sibling()), (None, None));
        // A host named like a suffix part is still the host.
        let tls_host = v("/dns/tls/tcp/443/tls/ws");
        assert_eq!(tls_host.raw_sibling(), Some(t("/dns/tls/tcp/443")));
        let ws_host = v("/dns/ws/tcp/443");
        assert!(!ws_host.is_wss());
        assert_eq!(ws_host.wss_sibling(), Some(t("/dns/ws/tcp/443/tls/ws")));
        // Every form is a canonical via of the same relay.
        for via in [
            &raw443, &wss8443, &sni, &raw7423, &quic, &tls_host, &ws_host,
        ] {
            for (wss_ok, prefer) in every {
                for form in relay_dial_forms(via, wss_ok, prefer) {
                    let back = parse_via(&form).unwrap();
                    assert_eq!((back.text, back.peer_id), (form, r.clone()));
                }
            }
        }
    }

    /// [`ContactP2p::dial_addrs`] as it was before RWS1 (a frozen copy).
    fn pre_rws1_contact_plan(c: &ContactP2p) -> Vec<String> {
        let direct = c
            .via
            .iter()
            .filter(|v| v.peer_id == c.peer_id)
            .map(|v| v.text.clone());
        let circuits = c
            .via
            .iter()
            .filter(|v| v.peer_id != c.peer_id)
            .map(|v| circuit_addr(v, &c.peer_id));
        direct.chain(circuits).collect()
    }

    /// [`P2pDialSet::dial_addrs`] as it was before RWS1 (a frozen copy).
    fn pre_rws1_set_plan(s: &P2pDialSet) -> Vec<String> {
        let mut firsts: Vec<&ViaAddr> = Vec::new();
        let mut fallbacks: Vec<&ViaAddr> = Vec::new();
        for r in &s.relays {
            if firsts.iter().any(|f| f.peer_id == r.peer_id) {
                fallbacks.push(r);
            } else {
                firsts.push(r);
            }
        }
        let c: Vec<String> = firsts
            .into_iter()
            .chain(fallbacks)
            .map(|r| circuit_addr(r, &s.peer_id))
            .collect();
        let room = MAX_DIAL_ADDRS - c.len().min(MAX_DIAL_ADDRS / 2);
        let mut d: Vec<String> = s.direct.iter().map(|v| v.text.clone()).collect();
        d.truncate(room);
        let mut out: Vec<String> = d
            .iter()
            .take(1)
            .chain(c.iter().take(1))
            .chain(d.iter().skip(1))
            .chain(c.iter().skip(1))
            .cloned()
            .collect();
        let mut seen = std::collections::HashSet::new();
        out.retain(|a| seen.insert(a.clone()));
        out.truncate(MAX_DIAL_ADDRS);
        out
    }

    /// With the WSS gate closed both planners give, byte for byte, the plan
    /// of the code before RWS1 for every book and hint a pre-WSS raven could
    /// hold (TCP 443 relays included, the WSS siblings by convention), and a
    /// WSS address is dialled as its raw sibling, exactly as if the raw
    /// sibling had been given: no `/tls/` in any plan.
    #[test]
    fn dial_addrs_is_byte_identical_while_the_gate_is_closed() {
        let bob = peer(2);
        let (r1, r2, r3) = (peer(11), peer(12), peer(13));
        let tcp = |host: &str, port: u16, who: &str| format!("{host}/tcp/{port}/p2p/{who}");
        let quic = |host: &str, who: &str| format!("{host}/udp/7423/quic-v1/p2p/{who}");
        let rows: [Vec<String>; 4] = [
            vec![],
            vec![
                tcp("/ip4/198.51.100.1", 7423, &r1),
                tcp("/ip4/203.0.113.9", 7423, &bob),
            ],
            vec![
                tcp("/ip4/198.51.100.1", 443, &r1),
                quic("/ip4/198.51.100.1", &r1),
                tcp("/dns4/relay.example.org", 7423, &r2),
                tcp("/dns4/relay.example.org", 443, &r2),
            ],
            vec![
                tcp("/ip6/2001:db8::9", 443, &bob),
                tcp("/ip4/203.0.113.9", 7423, &bob),
                tcp("/ip4/198.51.100.1", 443, &r1),
            ],
        ];
        let mut hints = vec![learned(&bob), learned(&peer(3))];
        let mut full = learned(&bob);
        full.direct = vec![
            parse_via(&tcp("/ip4/11.0.3.5", 443, &bob)).unwrap(),
            at("/ip6/2001:4860::5", &bob),
        ];
        full.local_direct = vec![at("/ip4/192.168.7.20", &bob)];
        full.relays = vec![
            parse_via(&tcp("/ip4/11.0.2.1", 443, &r2)).unwrap(),
            parse_via(&quic("/ip4/11.0.2.1", &r2)).unwrap(),
            at("/ip4/11.0.2.3", &r3),
        ];
        hints.push(full);
        let mine = [
            at("/ip4/11.0.5.1", &r1),
            parse_via(&tcp("/ip4/11.0.5.1", 443, &r1)).unwrap(),
            at("/ip4/11.0.5.3", &r3),
        ];
        let no_wss = |plan: &[String]| !plan.iter().any(|a| a.contains("/tls/"));
        let mut sets = 0;
        for row in &rows {
            let book = ContactP2p::from_fields(&bob, row).unwrap();
            assert_eq!(book.dial_addrs(), pre_rws1_contact_plan(&book));
            assert_eq!(
                book.dial_addrs_with(false, |_| true, false),
                book.dial_addrs()
            );
            assert!(no_wss(&book.dial_addrs()));
            for hint in &hints {
                for hide in [None, Some(&mine[..])] {
                    let set = P2pDialSet::merge(Some(&book), Some(hint), |_| true, hide).unwrap();
                    assert_eq!(set.dial_addrs(), pre_rws1_set_plan(&set), "{row:?}");
                    assert_eq!(
                        set.dial_addrs_with(false, |_| true, false),
                        set.dial_addrs()
                    );
                    assert!(no_wss(&set.dial_addrs()));
                    sets += 1;
                }
            }
        }
        assert_eq!(sets, rows.len() * 6);
        // WSS addresses (a relay's, and one naming the contact itself) with
        // the gate closed: their raw siblings, as if those had been given.
        let wss = [
            format!("/ip4/198.51.100.1/tcp/443/tls/ws/p2p/{r1}"),
            format!("/ip4/203.0.113.9/tcp/8443/tls/sni/bob.example.org/ws/p2p/{bob}"),
            format!("/dns4/relay.example.org/tcp/443/tls/ws/p2p/{r1}"),
        ];
        let raw = [
            format!("/ip4/198.51.100.1/tcp/443/p2p/{r1}"),
            format!("/ip4/203.0.113.9/tcp/8443/p2p/{bob}"),
            format!("/dns4/relay.example.org/tcp/443/p2p/{r1}"),
        ];
        let wss_book = ContactP2p::from_fields(&bob, &wss).unwrap();
        let raw_book = ContactP2p::from_fields(&bob, &raw).unwrap();
        assert_eq!(wss_book.via.len(), 3);
        assert_eq!(wss_book.dial_addrs(), raw_book.dial_addrs());
        assert!(no_wss(&wss_book.dial_addrs()));
        for hint in &hints {
            let wss_set = P2pDialSet::merge(Some(&wss_book), Some(hint), |_| true, None).unwrap();
            let raw_set = P2pDialSet::merge(Some(&raw_book), Some(hint), |_| true, None).unwrap();
            assert_eq!(wss_set.dial_addrs(), raw_set.dial_addrs());
            assert!(no_wss(&wss_set.dial_addrs()));
        }
    }

    /// RWS1 §9: while a reservation rides a proxied WSS connection the
    /// endpoint dials no direct contact address; the circuits stay, in the
    /// same order.
    #[test]
    fn restricted_mode_skips_direct_entries() {
        let bob = peer(2);
        let (r1, r2) = (peer(11), peer(12));
        let book = ContactP2p::from_fields(
            &bob,
            &[
                format!("/ip4/203.0.113.9/tcp/7423/p2p/{bob}"),
                format!("/ip4/198.51.100.1/tcp/443/p2p/{r1}"),
                format!("/dns4/relay.example.org/tcp/443/tls/ws/p2p/{r1}"),
            ],
        )
        .unwrap();
        let mut hint = learned(&bob);
        hint.direct = vec![at("/ip6/2001:4860::5", &bob)];
        hint.relays = vec![at("/ip4/11.0.2.1", &r2)];
        let set = P2pDialSet::merge(Some(&book), Some(&hint), |_| true, None).unwrap();
        let circuits = |plan: &[String]| -> Vec<String> {
            plan.iter()
                .filter(|a| a.contains("/p2p-circuit/"))
                .cloned()
                .collect()
        };
        for (wss_ok, prefer) in [(false, false), (true, false), (true, true)] {
            let open = book.dial_addrs_with(wss_ok, |_| prefer, false);
            let restricted = book.dial_addrs_with(wss_ok, |_| prefer, true);
            assert!(open.iter().any(|a| !a.contains("/p2p-circuit/")));
            assert!(!restricted.is_empty());
            assert_eq!(restricted, circuits(&open), "{wss_ok} {prefer}");
            let open = set.dial_addrs_with(wss_ok, |_| prefer, false);
            let restricted = set.dial_addrs_with(wss_ok, |_| prefer, true);
            assert!(open.iter().any(|a| !a.contains("/p2p-circuit/")));
            assert!(!restricted.is_empty());
            assert_eq!(restricted, circuits(&open), "{wss_ok} {prefer}");
        }
        // The relays the dial admits do not change.
        assert_eq!(set.relay_peer_ids(), [r2, r1]);
    }

    /// Phase 2's merged plan expands each relay address into its forms: a
    /// relay's first form before any relay's second, a form given twice
    /// dialled once, a contact's own WSS address at its raw sibling while
    /// the gate is closed, and the plan still at most MAX_DIAL_ADDRS.
    #[test]
    fn dial_set_expands_relay_forms_first_forms_before_fallbacks() {
        let bob = peer(2);
        let (r1, r2) = (peer(11), peer(12));
        let c = |s: &str, who: &str| format!("{s}/p2p/{who}/p2p-circuit/p2p/{bob}");
        let book = ContactP2p::from_fields(
            &bob,
            &[
                format!("/ip4/198.51.100.1/tcp/443/p2p/{r1}"),
                format!("/ip4/198.51.100.2/tcp/7423/p2p/{r2}"),
            ],
        )
        .unwrap();
        let set = P2pDialSet::merge(Some(&book), None, |_| true, None).unwrap();
        assert_eq!(
            set.dial_addrs_with(true, |_| false, false),
            [
                c("/ip4/198.51.100.1/tcp/443", &r1),
                c("/ip4/198.51.100.2/tcp/7423", &r2),
                c("/ip4/198.51.100.1/tcp/443/tls/ws", &r1),
            ]
        );
        assert_eq!(
            set.dial_addrs_with(true, |v| v.peer_id == r1, false),
            [
                c("/ip4/198.51.100.1/tcp/443/tls/ws", &r1),
                c("/ip4/198.51.100.2/tcp/7423", &r2),
                c("/ip4/198.51.100.1/tcp/443", &r1),
            ]
        );
        assert_eq!(
            book.dial_addrs_with(true, |_| false, false),
            [
                c("/ip4/198.51.100.1/tcp/443", &r1),
                c("/ip4/198.51.100.1/tcp/443/tls/ws", &r1),
                c("/ip4/198.51.100.2/tcp/7423", &r2),
            ]
        );
        // Both forms of one relay given: each dialled once.
        let both = ContactP2p::from_fields(
            &bob,
            &[
                format!("/ip4/198.51.100.1/tcp/443/p2p/{r1}"),
                format!("/ip4/198.51.100.1/tcp/443/tls/ws/p2p/{r1}"),
            ],
        )
        .unwrap();
        let pair = [
            c("/ip4/198.51.100.1/tcp/443", &r1),
            c("/ip4/198.51.100.1/tcp/443/tls/ws", &r1),
        ];
        let set = P2pDialSet::merge(Some(&both), None, |_| true, None).unwrap();
        assert_eq!(set.dial_addrs_with(true, |_| false, false), pair);
        assert_eq!(both.dial_addrs_with(true, |_| false, false), pair);
        assert_eq!(set.dial_addrs(), pair[..1]);
        assert_eq!(both.dial_addrs(), pair[..1]);
        // A WSS address of the contact itself: its raw sibling alone, gate
        // closed or live (endpoints never listen on WSS; review A-2).
        let own = ContactP2p::from_fields(
            &bob,
            &[format!("/ip4/203.0.113.9/tcp/8443/tls/ws/p2p/{bob}")],
        )
        .unwrap();
        let raw = format!("/ip4/203.0.113.9/tcp/8443/p2p/{bob}");
        let wss = format!("/ip4/203.0.113.9/tcp/8443/tls/ws/p2p/{bob}");
        let set = P2pDialSet::merge(Some(&own), None, |_| true, None).unwrap();
        assert_eq!(set.dial_addrs(), std::slice::from_ref(&raw));
        for prefer in [false, true] {
            for plan in [
                set.dial_addrs_with(true, |_| prefer, false),
                own.dial_addrs_with(true, |_| prefer, false),
            ] {
                assert_eq!(plan, std::slice::from_ref(&raw));
                assert!(!plan.contains(&wss));
            }
        }
        assert_eq!(own.dial_addrs(), [raw]);
        // Two relays on TCP 443 at two hosts each: eight forms, the plan
        // keeps MAX_DIAL_ADDRS with each relay's first form first.
        let wide = ContactP2p::from_fields(
            &bob,
            &[
                format!("/ip4/198.51.100.1/tcp/443/p2p/{r1}"),
                format!("/ip4/198.51.100.3/tcp/443/p2p/{r1}"),
                format!("/ip4/198.51.100.2/tcp/443/p2p/{r2}"),
                format!("/ip4/198.51.100.4/tcp/443/p2p/{r2}"),
            ],
        )
        .unwrap();
        let mut hint = learned(&bob);
        hint.direct = vec![at("/ip4/11.0.3.5", &bob), at("/ip4/11.0.3.6", &bob)];
        let set = P2pDialSet::merge(Some(&wide), Some(&hint), |_| true, None).unwrap();
        let plan = set.dial_addrs_with(true, |_| false, false);
        assert_eq!(plan.len(), MAX_DIAL_ADDRS);
        assert_eq!(plan[0], hint.direct[0].text);
        assert_eq!(plan[1], c("/ip4/198.51.100.1/tcp/443", &r1));
        assert_eq!(plan[2], hint.direct[1].text);
        assert_eq!(plan[3], c("/ip4/198.51.100.2/tcp/443", &r2));
        let unique: std::collections::HashSet<&String> = plan.iter().collect();
        assert_eq!(unique.len(), plan.len());
        assert_eq!(set.relay_peer_ids(), [r1, r2]);
    }

    #[test]
    fn wss_listen_multiaddrs_are_tcp_only() {
        assert_eq!(
            P2pListen::All(443).wss_multiaddrs(),
            ["/ip4/0.0.0.0/tcp/443/tls/ws", "/ip6/::/tcp/443/tls/ws"]
        );
        let one = normalize_p2p_listen("127.0.0.1:0").unwrap().unwrap();
        assert_eq!(one.wss_multiaddrs(), ["/ip4/127.0.0.1/tcp/0/tls/ws"]);
        let v6 = normalize_p2p_listen("[::1]:8443").unwrap().unwrap();
        assert_eq!(v6.wss_multiaddrs(), ["/ip6/::1/tcp/8443/tls/ws"]);
        assert!(P2pListen::RelayOnly.wss_multiaddrs().is_empty());
        for listen in [P2pListen::All(443), one, v6] {
            let wss = listen.wss_multiaddrs();
            assert!(wss
                .iter()
                .all(|a| a.ends_with("/tls/ws") && !a.contains("/udp/")));
            // One per host, on the TCP addresses the raw listener would use.
            let raw_tcp: Vec<String> = listen
                .multiaddrs()
                .into_iter()
                .filter(|a| a.contains("/tcp/"))
                .collect();
            let stripped: Vec<&str> = wss
                .iter()
                .map(|a| a.strip_suffix("/tls/ws").unwrap())
                .collect();
            assert_eq!(stripped, raw_tcp);
        }
    }
}
