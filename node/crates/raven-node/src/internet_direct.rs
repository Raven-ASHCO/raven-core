//! InternetTransport live path: Noise XX + channel-bound RIH1 hello + frames.
//!
//! Every `u32_be`-framed message is a Noise message. After the XX handshake
//! each side sends an encrypted RIH1 hello signed over the handshake hash,
//! its role and its Noise static key (see `raven_core::internet`), so a
//! captured hello cannot authenticate another connection. The dialer's hello
//! comes first, and the listener answers (hello, then RLB1) only a dialer whose
//! hello names a local, unblocked contact: anyone else is disconnected before
//! learning the listener's Raven identity or prekey bundle. The same indexed
//! PairInit / message / sealed-ACK dispatcher as LAN-direct then runs on
//! Noise transport frames (transport auth ≠ E2EE); RLB1 and PairInit never
//! travel in cleartext. Lab-gated: [`raven_core::internet_direct_live_enabled`].
//! Not WAN Proven.
//!
//! Mirrors `lan_direct`: the listener loads the identity once, unauthenticated
//! connections never touch the identity lock / secret store, the pre-auth
//! handshake has its own deadline, and all SQLite / file work runs on the
//! blocking pool.
//!
//! **One implementation, two links ([`RavenLink`]).** The p2p carrier (P3,
//! `crate::p2p`) runs this exact link inside a libp2p `/raven/link/1.0.0`
//! stream: the same XX, RIH1 identity bind, contact gate (verified contacts
//! only, stranger timing parity), RLB1 exchange and `dispatch_frame`, with
//! its own Noise prologue `raven/p2p-link/v1` ([`P2P_LINK`]) so a raw-TCP
//! transcript and a libp2p one can never complete against each other.
//!
//! **Route hints** (RRH1, [`crate::hints`]; route hints live only): each
//! hello sets caps bit 8 ([`raven_core::CAP_LINK_RRH1`]) when this side
//! accepts RRH1. The listener sends its RRH1 right after its RLB1, the dialer
//! its own before its frames, each only when the other's verified hello set
//! the bit. Receivers ignore caps bits they do not know, so older peers see
//! no difference, and an RRH1 is never a reply.
//!
//! **Link padding** (PAD1, [`crate::link`]; link padding live only): each
//! hello sets caps bit 9 ([`raven_core::CAP_LINK_PAD1`]); when both verified
//! hellos carry it, each side pads every frame after the hellos (the hellos
//! never). The p2p and nearby links run this link, so they pad the same way.
//!
//! **Noise pins** (M0, [`crate::lan_direct::NoisePins`]): the same check and
//! record as LAN direct. The prologue differs per link, the static does not,
//! so one pin covers LAN, Internet direct and the p2p inner link (where
//! libp2p already authenticated our PeerId, the stop still keeps our Raven
//! identity back).
//!
//! **The onion link's static** (RAVEN_ONION_CARRIER_V1 §5.1): the onion
//! link answers with a static of its own ([`LinkStatic::Onion`]), never the
//! device static the other links use. Anyone holding a card can open an
//! onion link and read message 2; that key names nothing beyond the onion
//! address the card shows, and no LAN or Internet listener answers with it.
//! Noise pins are not read or written on onion links: Tor authenticates the
//! onion service (whose key the identity signs) and the hello signs the
//! static.

use std::convert::Infallible;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use raven_core::identity::Identity;
use raven_core::internet::{
    frame as pack_inet_frame, hello_caps, pack_hello, unpack_verify_hello, HelloBinding, HelloRole,
    LinkFeatures, CAP_INTERNET, CAP_LINK_PAD1, HELLO_WIRE_LEN, MAX_FRAME_BYTES, MAX_PAYLOAD_BYTES,
    NEARBY_LINK_PROLOGUE, NOISE_PROLOGUE, ONION_LINK_PROLOGUE, P2P_LINK_PROLOGUE,
};
use raven_core::internet_direct_live_enabled;
use raven_core::lan_dispatch::{
    cache_peer_bundle, encode_local_offer, lan_peer_blocked, parse_peer_offer,
    remember_ephemeral_peer, rlb1_matches_noise_identity,
};
use raven_core::lan_noise::{
    build_initiator_with_prologue, build_responder_with_prologue, build_responder_with_static,
    get_remote_static, handshake_hash, handshake_read, handshake_write, into_transport,
    noise_static_public, static_public, LinkStatic,
};
use raven_core::link_knock::DialerStep;
use raven_core::link_padding::PadState;
use raven_core::load_identity_required;
use raven_core::OutboxCarrier;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::learning::DialMeta;
use crate::link::LinkCipher;
use crate::link_knock::{DialKnock, Ear, Knocked};
use crate::netutil::{
    self, AdmissionSlot, DialProgress, InboundLimits, ReplyWait, CONNECT_BUDGET, PEER_CLOSED,
};

const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// The whole dial, below the 45 s IPC cap (see `lan_direct`).
const DIAL_DEADLINE: Duration = Duration::from_secs(40);
/// [`DialProgress::stage`] while the link opens and its Noise handshake runs
/// (no answer of the contact verified yet).
pub(crate) const STAGE_NOISE: &str = "connecting and in the Noise handshake";
const READ_TIMEOUT: &str = "internet frame read timeout";
/// The security events classify these two texts (Phase 6b S2).
const HANDSHAKE_TIMEOUT: &str = raven_core::security_events::INTERNET_HANDSHAKE_TIMEOUT;
const FRAME_LENGTH: &str = raven_core::security_events::INTERNET_FRAME_LENGTH;
/// A nearby link whose Noise key is not the contact its pipe was knocked
/// for ([`serve_inbound_on`]'s `expected_peer`).
pub(crate) const NEARBY_KEY_MISMATCH: &str = "nearby link key differs from the knocked contact";
pub(crate) const HOLD: &str = "INTERNET_DIRECT_HOLD: Internet direct is closed in this process \
    (a debug build with RAVEN_LAB_TEST_A=0 or RAVEN_LAB_NEARBY_ONLY=1, or a security notice); \
    release builds have it on (INTERNET_DIRECT_PRODUCTION_ENABLED=true)";

/// One flavour of the Raven Noise link. Everything but the prologue, the
/// carrier (contact gate, outbox labels) and the gate is shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RavenLink {
    /// Noise prologue (domain separation between links).
    pub prologue: &'static [u8],
    /// The Noise static this link answers and dials with.
    pub noise_static: LinkStatic,
    /// The carrier the contact gate and the outbox use.
    pub carrier: OutboxCarrier,
    /// Log prefix of inbound failures (`<name> inbound …`).
    pub name: &'static str,
    /// Prefix of dial error codes (`<wire>_DIAL_…`).
    pub wire: &'static str,
}

/// Internet direct: raw TCP, prologue `raven/internet/v1`.
pub(crate) const INTERNET_LINK: RavenLink = RavenLink {
    prologue: NOISE_PROLOGUE,
    noise_static: LinkStatic::Device,
    carrier: OutboxCarrier::Internet,
    name: "internet_direct",
    wire: "INTERNET",
};

/// The p2p carrier: inside a libp2p stream, prologue `raven/p2p-link/v1`.
pub(crate) const P2P_LINK: RavenLink = RavenLink {
    prologue: P2P_LINK_PROLOGUE,
    noise_static: LinkStatic::Device,
    carrier: OutboxCarrier::P2p,
    name: "p2p",
    wire: "P2P",
};

/// The Bluetooth LE nearby carrier (Phase 5, RAVEN_NEARBY_LINK_V1 §7): on
/// one channel of an RNP1 pipe ([`crate::nearby`]), prologue
/// `raven/nearby-link/v1`.
pub(crate) const NEARBY_LINK: RavenLink = RavenLink {
    prologue: NEARBY_LINK_PROLOGUE,
    noise_static: LinkStatic::Device,
    carrier: OutboxCarrier::Nearby,
    name: "nearby",
    wire: "NEARBY",
};

/// The Tor onion carrier (lab, RAVEN_ONION_CARRIER_V1 §5): inside a Tor
/// stream to or from an onion service (`crate::onion`), prologue
/// `raven/onion-link/v1`. Tor is only the pipe: this link authenticates the
/// contact exactly as Internet direct does.
pub(crate) const ONION_LINK: RavenLink = RavenLink {
    prologue: ONION_LINK_PROLOGUE,
    noise_static: LinkStatic::Onion,
    carrier: OutboxCarrier::Onion,
    name: "onion",
    wire: "ONION",
};

impl RavenLink {
    /// Noise pins (M0) on this link: the device static's links only. An
    /// onion link's static is not the one a pin records.
    pub(crate) fn noise_pins(&self) -> crate::lan_direct::NoisePins {
        match self.noise_static {
            LinkStatic::Device => crate::lan_direct::NoisePins::current(),
            LinkStatic::Onion => crate::lan_direct::NoisePins { live: false },
        }
    }

    /// This link's gate: the Internet direct flag, the p2p flag, the
    /// nearby flag or the onion flag.
    pub(crate) fn require_live(&self) -> Result<(), String> {
        match self.carrier {
            OutboxCarrier::Onion if raven_core::onion_live_enabled() => Ok(()),
            OutboxCarrier::Onion => Err(raven_core::ONION_HOLD.into()),
            OutboxCarrier::P2p if raven_core::p2p_live_enabled() => Ok(()),
            OutboxCarrier::P2p => Err(raven_core::P2P_HOLD.into()),
            OutboxCarrier::Nearby if raven_core::nearby_live_enabled() => Ok(()),
            OutboxCarrier::Nearby => Err(raven_core::NEARBY_HOLD.into()),
            _ => require_live(),
        }
    }
}

pub(crate) async fn blocking<T, F>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| format!("internet_direct blocking join: {e}"))?
}

const PRODUCTION_LIMITS: InboundLimits = netutil::PRODUCTION_INBOUND;

fn frame_budget_allows(frames_seen: &mut u32, max_frames: u32) -> bool {
    *frames_seen = frames_seen.saturating_add(1);
    *frames_seen <= max_frames
}

static LISTENER_UP: AtomicBool = AtomicBool::new(false);

pub fn listener_is_up() -> bool {
    LISTENER_UP.load(Ordering::Relaxed)
}

struct ListenerGuard;
impl Drop for ListenerGuard {
    fn drop(&mut self) {
        LISTENER_UP.store(false, Ordering::Relaxed);
    }
}

pub(crate) fn parse_pub_hex(s: &str) -> Result<[u8; 32], String> {
    let h = s.trim().to_lowercase();
    if h.len() != 32 * 2 {
        return Err("expected_pub_hex must be 64 hex chars".into());
    }
    let v = hex::decode(&h).map_err(|_| "expected_pub_hex invalid hex".to_string())?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

pub fn looks_like_internet_dial(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.contains(' ') || t.starts_with("rvn1") {
        return false;
    }
    let Some((host, port)) = t.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && port.parse::<u16>().ok().is_some_and(|p| p != 0)
}

fn require_live() -> Result<(), String> {
    if internet_direct_live_enabled() {
        Ok(())
    } else {
        Err(HOLD.into())
    }
}

async fn write_raw<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<(), String> {
    let framed = pack_inet_frame(bytes)?;
    tokio::time::timeout(IO_TIMEOUT, async {
        stream
            .write_all(&framed)
            .await
            .map_err(|e| netutil::io_error_text(&e))?;
        stream
            .flush()
            .await
            .map_err(|e| netutil::io_error_text(&e))?;
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "internet frame write timeout".to_string())?
}

/// One length-prefixed frame, with no deadline of its own (callers bound it).
async fn read_raw_untimed<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| netutil::io_error_text(&e))?;
    let n = u32::from_be_bytes(len_buf) as usize;
    // One Noise message at most: reject before allocating.
    if n == 0 || n > MAX_FRAME_BYTES {
        return Err(FRAME_LENGTH.into());
    }
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| netutil::io_error_text(&e))?;
    Ok(buf)
}

async fn read_raw<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, String> {
    tokio::time::timeout(IO_TIMEOUT, read_raw_untimed(stream))
        .await
        .map_err(|_| READ_TIMEOUT.to_string())?
}

/// One link frame, padded when the link pads ([`LinkCipher::seal`]).
async fn write_inet_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    cipher: &mut LinkCipher,
    payload: &[u8],
) -> Result<(), String> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err("internet payload exceeds Noise transport limit".into());
    }
    let ct = cipher.seal(payload)?;
    write_raw(stream, &ct).await
}

/// One link frame, unpadded when the peer padded it ([`LinkCipher::open`]).
async fn read_inet_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    cipher: &mut LinkCipher,
) -> Result<Vec<u8>, String> {
    let ct = read_raw(stream).await?;
    cipher.open(&ct)
}

/// Wait up to `wait` for the next reply frame and say what happened.
async fn read_reply<S: AsyncRead + Unpin>(
    stream: &mut S,
    cipher: &mut LinkCipher,
    wait: Duration,
) -> ReplyWait {
    let read = async {
        let ct = read_raw_untimed(stream).await?;
        cipher.open(&ct)
    };
    match tokio::time::timeout(wait, read).await {
        Ok(Ok(frame)) => ReplyWait::Frame(frame),
        Ok(Err(why)) => ReplyWait::Closed(why),
        Err(_) => ReplyWait::Idle,
    }
}

/// The peer's verified hello: its caps (bits this build does not know are
/// kept, never refused; only CAP_INTERNET is required) and its key.
fn verify_peer_hello(raw: &[u8], peer: &HelloBinding) -> Result<(u32, [u8; 32]), String> {
    let (caps, pk) = unpack_verify_hello(raw, peer)?;
    if caps & CAP_INTERNET == 0 {
        return Err("internet hello missing CAP_INTERNET".into());
    }
    Ok((caps, pk))
}

/// [`initiator_session_on`] for Internet direct, without link features.
#[cfg(test)]
async fn initiator_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
    expected: &[u8; 32],
) -> Result<([u8; 32], LinkCipher), String> {
    initiator_session_on(
        INTERNET_LINK,
        stream,
        identity,
        expected,
        LinkFeatures::NONE,
        None,
        None,
    )
    .await
    .map(|(pk, _, t, _, _)| (pk, t))
}

/// Dialer side: XX, then exchange hellos bound to this handshake (ours
/// carries the link features in `offers`: [`crate::link::offers`]). With
/// `pinned` (M0) another responder static ends it before message 3. Returns
/// the peer's authenticated Ed25519 key (must equal `expected`), its hello
/// caps, the link's cipher, its static and whether the link carried the
/// knock. The cipher pads every frame after the hellos when both offered
/// PAD1 (P6.34).
///
/// With `knock` (RLK1, P6.35, Internet direct only; [`crate::link_knock`])
/// message 1 carries it, and the listener's proof decides as on LAN
/// (`lan_direct::initiator_session_pinned`): a fresh static of our own, or
/// the pin and the capability floor, or today's handshake; message 3 then
/// carries an RLX1 `PAD` entry, which every listener ignores. The returned
/// knock is `Some(proof)`; `None` without `knock`.
pub(crate) async fn initiator_session_on<S: AsyncRead + AsyncWrite + Unpin>(
    link: RavenLink,
    stream: &mut S,
    identity: &Identity,
    expected: &[u8; 32],
    offers: LinkFeatures,
    pinned: Option<&[u8; 32]>,
    knock: Option<&DialKnock>,
) -> Result<([u8; 32], u32, LinkCipher, [u8; 32], Option<bool>), String> {
    // A security notice that marks a link suite BROKEN (P6.45): no link on
    // any of these carriers, before anything is sent (the root fallback of a
    // seeded knock asks again).
    raven_core::suite_policy::check_link()?;
    let (mut hs, local_static, remote_static, knocked, m3_payload) = match knock {
        None => {
            let secret = link
                .noise_static
                .derive(identity)
                .map_err(|e| e.to_string())?;
            let local_static = noise_static_public(&secret);
            let mut hs =
                build_initiator_with_prologue(&secret, link.prologue).map_err(|e| e.to_string())?;
            drop(secret);
            let m1 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
            write_raw(stream, &m1).await?;
            let m2 = read_raw(stream).await?;
            handshake_read(&mut hs, &m2).map_err(|e| e.to_string())?;
            // As on LAN: neither our static (message 3) nor our signed hello
            // goes to a key that is not the one pinned for this contact.
            let remote_static = get_remote_static(&hs).map_err(|e| e.to_string())?;
            crate::lan_direct::check_noise_pin(identity, pinned, expected, &remote_static)
                .inspect_err(|_| crate::security::address_impostor(expected, link.carrier, None))?;
            (hs, local_static, remote_static, None, Vec::new())
        }
        Some(knock) => {
            let mut dial = knock.begin(identity, Some(link.prologue))?;
            write_raw(stream, dial.m1()).await?;
            let m2 = read_raw(stream).await.map_err(|e| knock.m2_error(e))?;
            let (remote_static, proof) = knock.read_m2(&mut dial, &m2)?;
            let step = knock.step(proof, identity, pinned, expected, &remote_static);
            // A seeded knock without a proof: the caller knocks once more
            // with the pair's root (Phase 6b P6.38) before this is an
            // impostor, or before a pin lets it go on without the knock.
            if knock.unproved(proof, step) {
                return Err(crate::link_knock::KNOCK_SEED_UNPROVED.to_string());
            }
            if matches!(step, DialerStep::StopPin | DialerStep::StopKnock) {
                crate::security::address_impostor(expected, link.carrier, None);
                return Err(crate::lan_direct::NOISE_PIN_MISMATCH.to_string());
            }
            let (hs, local_static) = dial
                .finish(
                    step == DialerStep::Fresh,
                    &m2,
                    &mut crate::link_knock::rng(),
                )
                .map_err(|e| e.to_string())?;
            let padded = crate::link_knock::m3_payload(&[]);
            (hs, local_static, remote_static, Some(proof), padded)
        }
    };
    let m3 = handshake_write(&mut hs, &m3_payload).map_err(|e| e.to_string())?;
    write_raw(stream, &m3).await?;
    let hash = handshake_hash(&hs);
    let mut t = LinkCipher::new(into_transport(hs).map_err(|e| e.to_string())?);
    let ours = HelloBinding {
        role: HelloRole::Initiator,
        handshake_hash: hash,
        noise_static_pub: local_static,
    };
    let hello = pack_hello(identity, hello_caps(offers), &ours);
    if hello.len() != HELLO_WIRE_LEN {
        return Err("hello pack length".into());
    }
    write_inet_frame(stream, &mut t, &hello).await?;
    let theirs = HelloBinding {
        role: HelloRole::Responder,
        handshake_hash: hash,
        noise_static_pub: remote_static,
    };
    // A contact-gated responder closes here, before its own hello, unless our
    // hello names one of its contacts (see `responder_handshake`).
    let raw = read_inet_frame(stream, &mut t)
        .await
        .map_err(netutil::closed_before_peer_identity)?;
    let (caps, pk) = verify_peer_hello(&raw, &theirs)?;
    if pk != *expected {
        // Another identity at this contact's address (S13).
        crate::security::address_impostor(expected, link.carrier, None);
        return Err("internet hello identity mismatch".into());
    }
    // Both hellos through: PAD1 from the next frame on when both offered it.
    t.pad = pad_after_hellos(offers, caps);
    Ok((pk, caps, t, remote_static, knocked))
}

/// Listener side: XX, then verify the dialer's hello (the initiator always
/// sends first) against this handshake. Returns the dialer's authenticated
/// Ed25519 key and hello caps, the link's cipher (not padding: the hellos
/// never are; [`pad_after_hellos`] once ours is written), our own hello (with
/// the link features in `offers`), which is **not** sent yet: the caller
/// decides first whether the dialer may learn who we are
/// ([`raven_core::lan_dispatch::link_peer_admission`]), the dialer's
/// Noise static (its hello signs it) and what the knock showed.
///
/// With `ear` (RLK1, P6.35, Internet direct only) message 1 is read before
/// the responder is built and its knock decides the static and message 2's
/// payload, as on LAN (`lan_direct::responder_handshake`).
async fn responder_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    link: RavenLink,
    stream: &mut S,
    identity: &Identity,
    offers: LinkFeatures,
    ear: Option<&Ear>,
) -> Result<([u8; 32], u32, LinkCipher, Vec<u8>, [u8; 32], Knocked), String> {
    // A security notice that marks a link suite BROKEN (P6.45): no link,
    // before anything is read.
    raven_core::suite_policy::check_link()?;
    let (mut hs, local_static, knocked) = match ear {
        None => {
            let secret = link
                .noise_static
                .derive(identity)
                .map_err(|e| e.to_string())?;
            let local_static = noise_static_public(&secret);
            let mut hs =
                build_responder_with_prologue(&secret, link.prologue).map_err(|e| e.to_string())?;
            drop(secret);
            let m1 = read_raw(stream).await?;
            handshake_read(&mut hs, &m1).map_err(|e| e.to_string())?;
            let m2 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
            write_raw(stream, &m2).await?;
            (hs, local_static, Knocked::Off)
        }
        Some(ear) => {
            let m1 = read_raw(stream).await?;
            let (reply, knocked) = crate::link_knock::hear(ear, &m1).await?;
            let mut hs = build_responder_with_static(&reply.static_secret, Some(link.prologue))
                .map_err(|e| e.to_string())?;
            handshake_read(&mut hs, &m1).map_err(|e| e.to_string())?;
            let m2 = handshake_write(&mut hs, &reply.payload).map_err(|e| e.to_string())?;
            write_raw(stream, &m2).await?;
            (hs, static_public(&reply.static_secret), knocked)
        }
    };
    let m3 = read_raw(stream).await?;
    handshake_read(&mut hs, &m3).map_err(|e| e.to_string())?;
    let remote_static = get_remote_static(&hs).map_err(|e| e.to_string())?;
    let hash = handshake_hash(&hs);
    let mut t = LinkCipher::new(into_transport(hs).map_err(|e| e.to_string())?);
    let theirs = HelloBinding {
        role: HelloRole::Initiator,
        handshake_hash: hash,
        noise_static_pub: remote_static,
    };
    let (caps, pk) = verify_peer_hello(&read_inet_frame(stream, &mut t).await?, &theirs)?;
    let ours = HelloBinding {
        role: HelloRole::Responder,
        handshake_hash: hash,
        noise_static_pub: local_static,
    };
    Ok((
        pk,
        caps,
        t,
        pack_hello(identity, hello_caps(offers), &ours),
        remote_static,
        knocked,
    ))
}

/// PAD1 on a link once both hellos are through (`offers`: what ours
/// carried, `peer_caps`: the peer's verified caps): every later frame
/// padded both ways when both offered it (P6.34), none otherwise.
fn pad_after_hellos(offers: LinkFeatures, peer_caps: u32) -> PadState {
    PadState::agreed(offers.contains(LinkFeatures::PAD1) && peer_caps & CAP_LINK_PAD1 != 0)
}

/// [`responder_handshake`] that answers every dialer (scripted test peers).
#[cfg(test)]
async fn responder_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
) -> Result<([u8; 32], LinkCipher), String> {
    let (pk, _, mut t, ours, _, _) =
        responder_handshake(INTERNET_LINK, stream, identity, LinkFeatures::NONE, None).await?;
    write_inet_frame(stream, &mut t, &ours).await?;
    Ok((pk, t))
}

/// Gate, then serve one inbound session from `source` (the TCP peer's
/// address: whom a replayed knock is about).
async fn handle_inbound<S: AsyncRead + AsyncWrite + Unpin>(
    data_dir: PathBuf,
    identity: Arc<Identity>,
    stream: S,
    limits: InboundLimits,
    slot: &mut AdmissionSlot,
    source: Option<IpAddr>,
) -> Result<(), String> {
    require_live()?;
    serve_inbound_on(
        INTERNET_LINK,
        data_dir,
        identity,
        stream,
        limits,
        slot,
        None,
        None,
        source,
    )
    .await
}

/// [`serve_inbound_on`] for Internet direct.
#[cfg(test)]
async fn serve_inbound<S: AsyncRead + AsyncWrite + Unpin>(
    data_dir: PathBuf,
    identity: Arc<Identity>,
    stream: S,
    limits: InboundLimits,
    slot: &mut AdmissionSlot,
) -> Result<(), String> {
    serve_inbound_on(
        INTERNET_LINK,
        data_dir,
        identity,
        stream,
        limits,
        slot,
        None,
        None,
        None,
    )
    .await
}

/// Serve one inbound Raven link of `link`'s flavour (the caller checked the
/// gate): handshake, contact gate, RLB1, then frames until the peer is done.
/// `link_peer_id`: the libp2p PeerId of a p2p link's connection.
/// `expected_peer`: the contact a nearby pipe was knocked for (RNL1 §7): a
/// dialer that authenticates as anyone else is closed right after the
/// handshake, before the contact gate and before anything identifying is
/// sent. `source`: the TCP peer's address of an Internet direct link (a
/// replayed RLK1 knock is about it; P6.35), `None` on the others, which
/// never read a knock.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_inbound_on<S: AsyncRead + AsyncWrite + Unpin>(
    link: RavenLink,
    data_dir: PathBuf,
    identity: Arc<Identity>,
    mut stream: S,
    limits: InboundLimits,
    slot: &mut AdmissionSlot,
    link_peer_id: Option<String>,
    expected_peer: Option<[u8; 32]>,
    source: Option<IpAddr>,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    // A contact book still held while its key loads (a start, an Unlock)
    // judges nobody: wait for it, else close before the handshake (E1).
    netutil::book_open_within(&data_dir, limits.book_wait).await?;
    // Identity comes from the listener (loaded once): an unauthenticated peer
    // must not be able to trigger identity-lock / secret-store work. The
    // network half of the handshake has its own short deadline; the local
    // blocking work below deliberately does not, so the contact check's time
    // is added back to it.
    let mut deadline = tokio::time::Instant::now() + limits.handshake_deadline;
    let offers = crate::link::offers(link.carrier);
    let rrh1 = offers.contains(LinkFeatures::RRH1);
    // RLK1 (P6.35): Internet direct reads message 1 for a knock while it is
    // live; p2p and nearby never do.
    let ear = (link == INTERNET_LINK)
        .then(|| Ear::of(&data_dir, &identity, source, link.carrier))
        .flatten();
    let (remote_ed, peer_caps, mut transport, our_hello, remote_static, knocked) =
        match tokio::time::timeout_at(
            deadline,
            responder_handshake(link, &mut stream, &identity, offers, ear.as_ref()),
        )
        .await
        {
            Ok(done) => done?,
            Err(_) => return Err(HANDSHAKE_TIMEOUT.into()),
        };
    // A nearby pipe was knocked for one contact (its pair key): the link on
    // it is that contact's or nobody's.
    if expected_peer.is_some_and(|k| k != remote_ed) {
        return Err(NEARBY_KEY_MISMATCH.into());
    }
    // Contact gate before anything identifying leaves this node: a stranger
    // (or a blocked key) that completed XX gets the connection closed and
    // nothing else, not our hello (Raven identity) and not our RLB1
    // (certificate + prekey bundle). An Internet scanner cannot map IP → ID.
    // Internet and p2p also need a *verified* (pinned) contact (owner
    // decision 2026-10-08): an unverified one is treated exactly like a
    // stranger, and every refusal does the same work (one read of each file),
    // so its timing does not tell a scanner whether a key is a contact.
    let gate_started = tokio::time::Instant::now();
    {
        let dd = data_dir.clone();
        let carrier = link.carrier;
        blocking(move || {
            raven_core::lan_dispatch::link_admission(&dd, &remote_ed, carrier, None)
                .map_err(String::from)
        })
        .await?;
    }
    // A contact: what happens on this link from here on is about its path.
    slot.contact_admitted();
    deadline += gate_started.elapsed();
    let offer = tokio::time::timeout_at(deadline, async {
        write_inet_frame(&mut stream, &mut transport, &our_hello).await?;
        transport.pad = pad_after_hellos(offers, peer_caps);
        read_inet_frame(&mut stream, &mut transport).await
    })
    .await;
    let peer_offer = match offer {
        Ok(done) => {
            done.inspect_err(|e| crate::security::inbound_link_error(&remote_ed, link.carrier, e))?
        }
        Err(_) => return Err(HANDSHAKE_TIMEOUT.into()),
    };
    let (peer, local, trusted) = {
        let dd = data_dir.clone();
        let id = identity.clone();
        blocking(move || {
            let peer = parse_peer_offer(&peer_offer)?;
            if !rlb1_matches_noise_identity(&peer, &remote_ed) {
                return Err("rlb1/internet hello identity mismatch".into());
            }
            if lan_peer_blocked(&dd, &peer, &remote_ed)? {
                return Err("blocked peer".into());
            }
            // An offer dated in our future: the contact's clock (CP.7).
            remember_ephemeral_peer(&dd, &peer).inspect_err(|_| {
                crate::clock_notes::offer_refused(&remote_ed, &peer);
            })?;
            let local = encode_local_offer(&dd, &id)?;
            // Fail closed: an unreadable contact book trusts nobody.
            let trusted = raven_core::lan_dispatch::peer_is_trusted(&dd, &peer).unwrap_or(false);
            // Friend custody: a contact's mail may later come from a custodian
            // (best effort; gated, so nothing changes while custody is held).
            if trusted && raven_core::custody_gate::CustodyGates::current().live {
                let _ = raven_core::lan_dispatch::remember_inbound_contact(&dd, &peer);
            }
            Ok((peer, local, trusted))
        })
        .await?
    };
    // Only a local contact leaves the pre-auth caps for a slot a newcomer cannot
    // displace: a bound RLB1 offer proves possession of *a* key, and anyone can
    // self-sign a bundle (see `lan_direct::handle_inbound`).
    if trusted {
        slot.authenticated();
        // M0: its link authenticated its static (before the dial-back),
        // unless its knock matched: then it is a static for this link only.
        if !knocked.fresh_dialer() {
            link.noise_pins()
                .record(&data_dir, &identity, remote_ed, remote_static, None)
                .await;
        }
        // A contact that reaches us is online now: retry what we owe it.
        crate::outbox::peer_seen(&remote_ed);
        crate::custody::peer_seen(&remote_ed);
        // Over Tor: our onion service is reachable (`raven status`).
        if link.carrier == OutboxCarrier::Onion {
            crate::onion::friend_reached_us();
        }
        // Auto-reach (gated): a contact came in over Internet direct from
        // outside, so its listener's public address is confirmed.
        if link.carrier == OutboxCarrier::Internet {
            if let Some(ip) = source {
                crate::autoreach::confirm(
                    crate::autoreach::Reached::Inet,
                    ip,
                    raven_core::p2p_local_candidates_enabled(),
                );
            }
        }
        // A live link with a contact: renew the session soon if it ends
        // within 12 h (gated; a no-op while the renewer does not run).
        crate::renewal::note_live_link(&remote_ed, crate::renewal::LiveLink::Inbound);
        // Why it could not be reached no longer holds.
        crate::delivery_paths::heard(&remote_ed);
        // Learning connectivity (Phase 6a, gated): a p2p link that came
        // over our reservation on a relay counts for that relay.
        if crate::learning::live_on() {
            let via_relay = match (link.carrier, link_peer_id.as_deref()) {
                (raven_core::OutboxCarrier::P2p, Some(peer)) => crate::p2p::inbound_relay(peer),
                _ => None,
            };
            crate::learning::inbound(&remote_ed, link.carrier, via_relay, false);
        }
    }
    write_inet_frame(&mut stream, &mut transport, &local).await?;
    // Route hints (RRH1): only to a dialer whose hello asked for them;
    // one-way, never a reply.
    let keys = crate::hints::LinkKeys::new(remote_ed, &identity);
    let mut hints = crate::hints::LinkCtl::inet(
        &data_dir,
        link.carrier,
        crate::hints::Role::Listener,
        keys,
        rrh1,
        peer_caps,
        link_peer_id,
    )
    .with_knock(knocked.showed(&remote_ed))
    .with_update(crate::update_exchange::UpdateLink::inet(
        &data_dir,
        link.carrier,
        true,
        remote_ed,
        offers.contains(LinkFeatures::RUP1),
        peer_caps,
    ));
    if trusted {
        if let Some(ours) = hints.outgoing().await {
            write_inet_frame(&mut stream, &mut transport, &ours).await?;
            hints.written();
        }
        hints.note_link().await;
        // Its verified hello's link features: its capability floor (P6.29).
        hints.note_features();
    }
    // RUP1 (P6.49): our HAVE, after RRH1, to a pinned contact whose hello
    // set bit 10; one-way, never a reply.
    if let Some(have) = hints.update().outgoing().await {
        write_inet_frame(&mut stream, &mut transport, &have).await?;
    }

    let mut frames_seen = 0u32;
    loop {
        if started.elapsed() > limits.lifetime {
            return Err(format!(
                "{} connection lifetime exceeded",
                link.wire.to_ascii_lowercase()
            ));
        }
        let frame = match read_inet_frame(&mut stream, &mut transport).await {
            Ok(f) => f,
            // The dialer is done (it closes as soon as it has its replies) or
            // went quiet: normal ends, not events worth a log line.
            Err(e) if e == PEER_CLOSED || e == READ_TIMEOUT => break,
            Err(e) => {
                crate::security::inbound_link_error(&remote_ed, link.carrier, &e);
                netutil::log_inbound_failure(
                    &format!("{} inbound read", link.name),
                    format_args!("contact {}: {e}", netutil::link_tag(&remote_ed)),
                );
                break;
            }
        };
        if !frame_budget_allows(&mut frames_seen, limits.max_frames) {
            return Err("internet frame budget exceeded".into());
        }
        if hints.take(&frame).await {
            continue;
        }
        // RUP1 (P6.49): the dialer's HAVE and requests, answered here and
        // never dispatched.
        if let Some(replies) = hints.update().listener_take(&frame).await {
            for reply in &replies {
                write_inet_frame(&mut stream, &mut transport, reply).await?;
            }
            continue;
        }
        // A custody handoff FORWARD left here is handed on at once (P5.21).
        let handoff = raven_core::friend_custody::is_handoff_request(&frame);
        let dd = data_dir.clone();
        let id = identity.clone();
        let peer_c = peer.clone();
        let hello_ed = remote_ed;
        let link_carrier = link.carrier;
        let replies = tokio::task::spawn_blocking(move || {
            if lan_peer_blocked(&dd, &peer_c, &hello_ed)? {
                return Ok(None);
            }
            // The contact's clock as the frame showed it (CP.7).
            let mut clock = None;
            let replies = raven_core::lan_dispatch::dispatch_frame_clocked(
                &dd,
                &id,
                &peer_c,
                &hello_ed,
                &frame,
                raven_core::friend_custody::InboundLink {
                    carrier: link_carrier,
                    source: None,
                },
                &mut clock,
            );
            crate::clock_notes::seen(&hello_ed, clock);
            replies.map(Some)
        })
        .await
        .map_err(|e| format!("dispatch join: {e}"))?
        .map_err(|e| format!("dispatch: {e}"))?
        .ok_or_else(|| "blocked peer".to_string())?;
        if handoff {
            crate::custody::kick_forward();
        }
        for (i, reply) in replies.iter().enumerate() {
            if let Err(e) = write_inet_frame(&mut stream, &mut transport, reply).await {
                // See `lan_direct::handle_inbound`: the outbox pushes the ACK
                // that never left (transports design F8).
                crate::outbox::note_unsent_replies(&remote_ed, &replies[i..]);
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Blocking: loads the identity (the listener keeps it for its lifetime) and
/// readies durable state, one durable pass at a time
/// ([`netutil::durable_pass`]). Shared by the Internet listener and nearby.
pub(crate) fn preflight_link_ready(link: RavenLink, data_dir: &Path) -> Result<Identity, String> {
    link.require_live()?;
    let _pass = netutil::durable_pass();
    let identity = load_identity_required(data_dir).map_err(|e| e.to_string())?;
    raven_core::ensure_local_prekey(data_dir, &identity)?;
    let _ = raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let _ = raven_core::PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    raven_core::maintain_lan_durable_state(data_dir)?;
    Ok(identity)
}

/// Listen on `internet_listen` and dispatch inbound InternetTransport sessions.
pub async fn run_listener(data_dir: PathBuf, internet_listen: String) -> Result<(), String> {
    run_listener_with_limits(data_dir, internet_listen, PRODUCTION_LIMITS).await
}

async fn run_listener_with_limits(
    data_dir: PathBuf,
    internet_listen: String,
    limits: InboundLimits,
) -> Result<(), String> {
    // Each start-up step is retried on its own (see `lan_direct`).
    let identity = Arc::new(
        netutil::retry_until_ok("internet_direct", || {
            let dd = data_dir.clone();
            async move {
                netutil::with_slow_notice(
                    "internet_direct",
                    "local state preflight (identity, sessions, outbound stage)",
                    blocking(move || {
                        preflight_link_ready(INTERNET_LINK, &dd)
                            .map_err(|e| raven_core::disk_space::with_disk_full_note(&dd, e))
                    }),
                )
                .await
            }
        })
        .await,
    );
    let listener = netutil::retry_until_ok("internet_direct", || async {
        TcpListener::bind(&internet_listen)
            .await
            .map_err(|e| format!("internet_direct bind {internet_listen}: {e}"))
    })
    .await;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!("raven-node internet_direct: listen {local}");
    eprintln!("CLAIM: InternetTransport localhost/lab listen — dial≠WAN");
    LISTENER_UP.store(true, Ordering::Relaxed);
    let _up = ListenerGuard;
    crate::outbox::listener_up();
    crate::custody::kick();
    match serve_listener(listener, data_dir, identity, limits).await {}
}

/// Accept and serve inbound sessions for as long as the task lives.
async fn serve_listener(
    listener: TcpListener,
    data_dir: PathBuf,
    identity: Arc<Identity>,
    limits: InboundLimits,
) -> Infallible {
    netutil::serve_connections(
        "internet_direct",
        || listener.accept(),
        limits,
        move |stream, mut slot| {
            let dd = data_dir.clone();
            let id = identity.clone();
            async move {
                let source = stream.peer_addr().ok().map(|a| a.ip());
                handle_inbound(dd, id, stream, limits, &mut slot, source).await
            }
        },
    )
    .await
}

/// Send `frames` and collect the replies into `progress` (see
/// `lan_direct::exchange_frames`). Our RRH1 goes first when the listener's
/// hello asked for it; the listener's is consumed by `hints`, never
/// collected as a reply.
async fn exchange_frames<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut LinkCipher,
    frames: &[Vec<u8>],
    hints: &mut crate::hints::LinkCtl,
    progress: &mut DialProgress,
) -> Result<(), String> {
    progress.stage = "sending frames";
    if let Some(ours) = hints.outgoing().await {
        write_inet_frame(stream, transport, &ours).await?;
        hints.written();
    }
    // RUP1 (P6.49): our HAVE after the hellos and RRH1, when the listener's
    // hello set bit 10; requests only once its HAVE came.
    if let Some(have) = hints.update().outgoing().await {
        write_inet_frame(stream, transport, &have).await?;
    }
    if frames
        .iter()
        .any(|f| raven_core::update_exchange::is_rup1(f))
    {
        read_peer_frames(stream, transport, hints, progress.collector.idle_wait()).await?;
        crate::update_exchange::check_requests(frames, hints.update())?;
    }
    for frame in frames {
        write_inet_frame(stream, transport, frame).await?;
    }
    if frames.is_empty() {
        // The listener's hello said it sends an RRH1 (or a HAVE, RUP1):
        // read them before closing (unread data at close can reset the
        // connection).
        read_peer_frames(stream, transport, hints, progress.collector.idle_wait()).await?;
        return Ok(());
    }
    progress.frames_sent = true;
    progress.collector.mark_frames_sent();
    progress.stage = "waiting for a reply";
    let wait = progress.collector.first_wait();
    let mut more = progress
        .collector
        .first(read_reply_hints(stream, transport, wait, hints).await?)?;
    while more {
        let wait = progress.collector.idle_wait();
        more = progress
            .collector
            .next(read_reply_hints(stream, transport, wait, hints).await?)?;
    }
    Ok(())
}

/// [`read_reply`] that consumes the peer's RRH1 within the same wait (see
/// `lan_direct::read_reply_hints`).
async fn read_reply_hints<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut LinkCipher,
    wait: Duration,
    hints: &mut crate::hints::LinkCtl,
) -> Result<ReplyWait, String> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let got = read_reply(stream, transport, left).await;
        crate::security::dial_reply(&got, hints);
        let ReplyWait::Frame(frame) = &got else {
            return Ok(got);
        };
        // The listener's HAVE (RUP1, P6.49): taken, never a reply.
        if let Some(answer) = hints.update().dialer_take(frame).await {
            if let Some(ours) = answer {
                write_inet_frame(stream, transport, &ours).await?;
            }
            continue;
        }
        if !hints.take(frame).await {
            return Ok(got);
        }
        if hints.flooded() {
            return Ok(ReplyWait::Closed("too many route hint frames".into()));
        }
        if let Some(ours) = hints.outgoing().await {
            write_inet_frame(stream, transport, &ours).await?;
            hints.written();
        }
    }
}

/// Before a dialer closes without frames, or asks the update exchange
/// anything: read what the listener's hello said it sends (its RRH1, its
/// HAVE) while either is still expected, each within `wait` (see
/// `lan_direct::read_peer_frames`). Without either it reads nothing.
async fn read_peer_frames<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut LinkCipher,
    hints: &mut crate::hints::LinkCtl,
    wait: Duration,
) -> Result<(), String> {
    while hints.expects_peer_frame() || hints.update().expects_have() {
        let got = read_reply(stream, transport, wait).await;
        crate::security::dial_reply(&got, hints);
        let ReplyWait::Frame(frame) = got else {
            break;
        };
        if let Some(answer) = hints.update().dialer_take(&frame).await {
            if let Some(ours) = answer {
                write_inet_frame(stream, transport, &ours).await?;
            }
        } else if !hints.take(&frame).await {
            break;
        }
    }
    Ok(())
}

async fn dial_session(
    data_dir: &Path,
    internet_dial: &str,
    expected: &[u8; 32],
    frames: &[Vec<u8>],
    progress: &mut DialProgress,
) -> Result<(), String> {
    // Per address: today's, or learning connectivity's shorter wait.
    let connect = progress.connect.clone();
    let connect = &connect;
    dial_session_on(
        INTERNET_LINK,
        data_dir,
        || async move {
            netutil::connect_dial_within(internet_dial, connect, CONNECT_BUDGET)
                .await
                .map(|(stream, _addr)| stream)
                .map_err(|e| format!("internet connect: {e}"))
        },
        expected,
        frames,
        None,
        progress,
    )
    .await
}

/// The dialer half of a Raven link of `link`'s flavour over the streams
/// `connect` opens (a TCP connection, or a libp2p stream): handshake (retried
/// on a fresh stream while the peer sheds load), RLB1 exchange with the
/// identity checks, then `frames` and their replies into `progress`.
/// `link_peer_id`: the libp2p PeerId a p2p link's stream goes to.
pub(crate) async fn dial_session_on<S, C, CFut>(
    link: RavenLink,
    data_dir: &Path,
    mut connect: C,
    expected: &[u8; 32],
    frames: &[Vec<u8>],
    link_peer_id: Option<String>,
    progress: &mut DialProgress,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: FnMut() -> CFut,
    CFut: std::future::Future<Output = Result<S, String>>,
{
    progress.stage = "loading the local identity";
    let pins = link.noise_pins();
    // RLK1 (P6.35): Internet direct dials knock while it is live.
    let knock_live = link == INTERNET_LINK && crate::link_knock::live();
    let knock_seeds = crate::pair_seed::live();
    let (identity, local, pinned, knock, no_hints) = {
        let dd = data_dir.to_path_buf();
        let contact = *expected;
        blocking(move || {
            let identity = load_identity_required(&dd).map_err(|e| e.to_string())?;
            let local = encode_local_offer(&dd, &identity)?;
            // Before connecting: an unreadable pin store dials nothing.
            let pinned = pins.load(&dd, &contact)?;
            let knock =
                crate::link_knock::for_dial(knock_live, knock_seeds, &dd, &identity, &contact);
            let no_hints = crate::hints::holds_no_hints(&dd, &contact);
            Ok((identity, local, pinned, knock, no_hints))
        })
        .await?
    };
    let offers = crate::link::offers(link.carrier);
    let rrh1 = offers.contains(LinkFeatures::RRH1);
    // We hold none of the contact's route hints (forgotten, or none since
    // our start): ask for its RRH1 on this link (field test E3: after
    // `forget-address` a friend at home stayed on Tor, never told again).
    let offers = offers.with(LinkFeatures::RRH1_ASK, rrh1 && no_hints);
    progress.stage = STAGE_NOISE;
    let (mut stream, (remote_ed, peer_caps, mut transport, remote_static, knocked)) = {
        let (identity, pinned) = (&identity, pinned.as_ref());
        // A knock with the pair's seed that got no proof (or whose listener
        // closed before message 2 every time) is made once more with the
        // pair's root (Phase 6b P6.38): a contact that lost its seed still
        // proves itself; anyone else is stopped there.
        crate::link_knock::dial_attempts(knock.as_ref(), |k| {
            let opened = connect();
            async move {
                let mut stream = opened.await?;
                let session =
                    initiator_session_on(link, &mut stream, identity, expected, offers, pinned, k)
                        .await?;
                Ok((stream, session))
            }
        })
        .await?
    };
    // The peer's hello verified: its static is the contact's. A listener
    // that proved the knock used a static for this link only (RLK1).
    if knocked != Some(true) {
        pins.record(data_dir, &identity, remote_ed, remote_static, pinned)
            .await;
    }
    let keys = crate::hints::LinkKeys::new(remote_ed, &identity);
    drop(identity);
    progress.stage = "exchanging RLB1 offers";
    write_inet_frame(&mut stream, &mut transport, &local).await?;
    let peer_offer = read_inet_frame(&mut stream, &mut transport)
        .await
        .inspect_err(|e| crate::security::dial_link_error(expected, link.carrier, e))?;
    let peer_offer = {
        let dd = data_dir.to_path_buf();
        let expected = *expected;
        blocking(move || {
            let peer = parse_peer_offer(&peer_offer)?;
            if peer.cert.device_ed_pub != expected && peer.cert.user_ed_pub != expected {
                return Err("rlb1 offer identity mismatch".into());
            }
            if !rlb1_matches_noise_identity(&peer, &remote_ed) {
                return Err("rlb1/internet hello identity mismatch".into());
            }
            if lan_peer_blocked(&dd, &peer, &expected)? {
                return Err("blocked peer".into());
            }
            // An offer dated in our future (PREKEY_NOT_YET_VALID) says how
            // far the contact's clock is ahead (CP.7); refused as before.
            cache_peer_bundle(&dd, &peer).inspect_err(|_| {
                crate::clock_notes::offer_refused(&expected, &peer);
            })?;
            Ok(peer_offer)
        })
        .await?
    };
    // The contact's verified offer: a live link (the session renewer; a
    // no-op for its own dials and while it does not run).
    crate::renewal::note_live_link(expected, crate::renewal::LiveLink::Outbound);
    // It is reachable: what waits for it goes now, whatever this dial is for
    // (E1; nothing while the outbox's own attempt for it runs).
    crate::outbox::peer_back(expected);
    progress.collector.begin(peer_offer, frames)?;
    let mut hints = crate::hints::LinkCtl::inet(
        data_dir,
        link.carrier,
        crate::hints::Role::Dialer,
        keys,
        rrh1,
        peer_caps,
        link_peer_id,
    )
    .with_purpose(crate::hints::dial_purpose(frames, false))
    .with_knock(knocked)
    .with_update(crate::update_exchange::UpdateLink::inet(
        data_dir,
        link.carrier,
        false,
        remote_ed,
        offers.contains(LinkFeatures::RUP1),
        peer_caps,
    ));
    hints.note_link().await;
    // Its verified hello's link features: its capability floor (P6.29).
    hints.note_features();
    exchange_frames(&mut stream, &mut transport, frames, &mut hints, progress).await
}

/// Dial `internet_dial` (`host:port`: an IP or a DNS name), complete
/// Noise+RIH1+RLB1, send `frames`, collect replies.
pub async fn dial(
    data_dir: &Path,
    internet_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    dial_with_meta(
        data_dir,
        internet_dial,
        expected_pub_hex,
        frames,
        DialMeta::default(),
    )
    .await
}

/// [`dial`] with the worker's facts about it ([`DialMeta`]: a resend of an
/// object that went silent gives learning no reply-time sample). Its waits
/// are `crate::learning::waits`' (today's while learning is off).
pub(crate) async fn dial_with_meta(
    data_dir: &Path,
    internet_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    meta: DialMeta,
) -> Result<Vec<Vec<u8>>, String> {
    require_live()?;
    require_verified_contact(data_dir, expected_pub_hex).await?;
    require_ip_shown(data_dir, expected_pub_hex).await?;
    dial_unchecked(data_dir, internet_dial, expected_pub_hex, frames, meta).await
}

/// An Internet direct dial to a contact this node hides its IP from (D4).
pub(crate) const INTERNET_HIDDEN: &str = "you hide your IP from this contact: Raven does not \
    connect to it directly over the Internet; nothing was dialled (raven contact hide-ip NAME off)";

/// Hide my IP (D4): no Internet direct dial to a contact this node hides
/// its IP from (its row's or the node policy's `hide_ip`,
/// [`raven_core::outbox::may_share_ip`]), whoever asks: the planners leave
/// such routes out, and this keeps the IPC `InternetDial` op (`raven send
/// --peer HOST:PORT --carrier internet`) from dialling one. Nothing is
/// dialled on refusal.
async fn require_ip_shown(data_dir: &Path, expected_pub_hex: &str) -> Result<(), String> {
    let expected = parse_pub_hex(expected_pub_hex)?;
    let dd = data_dir.to_path_buf();
    let shown = blocking(move || Ok(raven_core::outbox::may_share_ip(&dd, &expected))).await?;
    if shown {
        Ok(())
    } else {
        Err(INTERNET_HIDDEN.to_string())
    }
}

/// Internet delivery is only for a verified (pinned) contact
/// ([`raven_core::carrier_allowed_for_contact`]). `raven send` and the outbox
/// worker refuse before they get here; this keeps the IPC `InternetDial` op
/// from dialling anyone else. Nothing is dialled on refusal.
async fn require_verified_contact(data_dir: &Path, expected_pub_hex: &str) -> Result<(), String> {
    let expected = parse_pub_hex(expected_pub_hex)?;
    let dd = data_dir.to_path_buf();
    let pinned = blocking(move || raven_core::contact_is_pinned(&dd, &expected)).await?;
    if raven_core::carrier_allowed_for_contact(raven_core::OutboxCarrier::Internet, pinned) {
        Ok(())
    } else {
        Err(format!(
            "{}: Internet delivery needs a verified contact (fingerprint pinned); nothing was \
             dialled",
            raven_core::CONTACT_NOT_VERIFIED
        ))
    }
}

async fn dial_unchecked(
    data_dir: &Path,
    internet_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    meta: DialMeta,
) -> Result<Vec<Vec<u8>>, String> {
    if !looks_like_internet_dial(internet_dial) {
        // 7421 is mock BLE's port; Internet direct uses its own (7422).
        return Err(format!(
            "internet_dial must be host:port (e.g. 203.0.113.7:{p} or node.example.com:{p})",
            p = raven_core::paths::DEFAULT_INTERNET_PORT
        ));
    }
    let expected = parse_pub_hex(expected_pub_hex)?;
    let net = crate::learning::net();
    let waits = crate::learning::waits(&expected, raven_core::OutboxCarrier::Internet);
    let mut progress = DialProgress::waiting("INTERNET", &waits);
    progress.collector.set_race(meta.race);
    // A probe's own bound (learning's exploration): it ends here, observed.
    let deadline = meta.deadline(DIAL_DEADLINE);
    let outcome = tokio::time::timeout(
        deadline,
        dial_session(data_dir, internet_dial, &expected, frames, &mut progress),
    )
    .await;
    let timing = progress.timing();
    let expired = progress.expired();
    let dialled = progress.connecting_began();
    let replies = match outcome {
        Ok(Ok(())) => Ok(progress.collector.into_replies()),
        Ok(Err(e)) => Err(e),
        Err(_) => progress.on_deadline("internet", internet_dial, deadline),
    };
    crate::clock_notes::dialled(&expected, frames, &replies);
    // Learning connectivity (Phase 6a, gated): Ok and Err alike, once the
    // dial began connecting (before that nothing was dialled).
    if dialled {
        crate::learning::observe_dial(
            &expected,
            raven_core::OutboxCarrier::Internet,
            Some(raven_core::outbox::DeliveryPath::Direct),
            None,
            frames,
            &replies,
            &timing,
            expired,
            meta,
            net,
        );
    }
    let replies = replies?;
    crate::delivery_paths::note(
        &expected,
        raven_core::OutboxCarrier::Internet,
        Some(raven_core::outbox::DeliveryPath::Direct),
        frames,
        &replies,
    );
    Ok(replies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netutil::{Admission, ReplyWaits};
    use raven_core::envelope::{EnvType, Envelope};
    use raven_core::lan_noise::{
        derive_noise_static, derive_onion_noise_static, transport_encrypt,
    };

    #[test]
    fn hold_without_lab_when_flag_false() {
        // Only meaningful while the P1 flag is off (and without the lab
        // unlock): flipping the flag must not need this test rewritten.
        if raven_core::pair_init::lab_test_a_enabled()
            || raven_core::INTERNET_DIRECT_PRODUCTION_ENABLED
        {
            return;
        }
        assert!(!internet_direct_live_enabled());
        assert_eq!(require_live().unwrap_err(), HOLD);
        assert!(!listener_is_up());
    }

    #[test]
    fn inbound_caps_are_bounded() {
        const {
            assert!(PRODUCTION_LIMITS.max_conns >= PRODUCTION_LIMITS.max_per_ip);
            assert!(PRODUCTION_LIMITS.max_per_ip >= PRODUCTION_LIMITS.max_handshaking_per_ip);
            assert!(PRODUCTION_LIMITS.max_handshaking_per_ip > 0);
            assert!(PRODUCTION_LIMITS.max_frames > 0);
        }
        assert!(PRODUCTION_LIMITS.lifetime.as_secs() >= 30);
        assert!(PRODUCTION_LIMITS.handshake_deadline < PRODUCTION_LIMITS.lifetime);
    }

    #[test]
    fn frame_budget_rejects_after_max() {
        let mut seen = 0u32;
        for _ in 0..3 {
            assert!(frame_budget_allows(&mut seen, 3));
        }
        assert!(!frame_budget_allows(&mut seen, 3));
        assert_eq!(seen, 4);
    }

    /// F9: the example port in the error is the Internet port, never mock
    /// BLE's 7421 (or LAN's 7420).
    #[tokio::test]
    async fn bad_dial_text_names_the_internet_port() {
        let dir = tempfile::tempdir().unwrap();
        let err = dial_unchecked(
            dir.path(),
            "no-port",
            &"ab".repeat(32),
            &[],
            DialMeta::default(),
        )
        .await
        .unwrap_err();
        assert!(err.contains(":7422"), "{err}");
        assert!(!err.contains("7421") && !err.contains("7420"), "{err}");
    }

    #[test]
    fn dial_string_rejects_non_host_port() {
        assert!(looks_like_internet_dial("127.0.0.1:7422"));
        assert!(!looks_like_internet_dial("127.0.0.1:0"));
        assert!(!looks_like_internet_dial("rvn1qabc"));
        assert!(!looks_like_internet_dial(""));
    }

    fn alice() -> Identity {
        Identity::from_seed(&[0x11; 32])
    }
    fn bob() -> Identity {
        Identity::from_seed(&[0x22; 32])
    }
    fn mallory() -> Identity {
        Identity::from_seed(&[0x33; 32])
    }

    #[tokio::test]
    async fn noise_session_authenticates_both_sides_and_encrypts_frames() {
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
        let responder = tokio::spawn(async move {
            let (peer, mut t) = responder_session(&mut listener, &bob()).await.unwrap();
            let got = read_inet_frame(&mut listener, &mut t).await.unwrap();
            write_inet_frame(&mut listener, &mut t, b"pong")
                .await
                .unwrap();
            (peer, got)
        });
        let expected = bob().public_key_bytes();
        let (peer, mut t) = initiator_session(&mut dialer, &alice(), &expected)
            .await
            .unwrap();
        assert_eq!(peer, expected);
        write_inet_frame(&mut dialer, &mut t, b"RLB1 offer")
            .await
            .unwrap();
        assert_eq!(read_inet_frame(&mut dialer, &mut t).await.unwrap(), b"pong");
        let (responder_saw, got) = responder.await.unwrap();
        assert_eq!(responder_saw, alice().public_key_bytes());
        assert_eq!(got, b"RLB1 offer");
    }

    /// A security notice that marks a link suite BROKEN (P6.45): no link
    /// on the Internet, p2p or nearby carriers either, dialler or listener,
    /// each with the text; lifted, they link again.
    #[tokio::test]
    async fn a_broken_link_suite_refuses_every_carrier_with_the_text() {
        use raven_core::advisory::{Entry, EntryKind, Severity};
        use raven_core::security_gate::{self, SecGate};
        use raven_core::suite_policy::{link_refused_text, set_policy_for_this_thread, Policy};
        use raven_core::suite_registry::{NOISE_XX_25519_CHACHAPOLY_BLAKE2S, RIH1_V1};
        security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
        if !security_gate::live(SecGate::Advisory) {
            security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
            return;
        }
        for link in [INTERNET_LINK, P2P_LINK, NEARBY_LINK] {
            for id in [NOISE_XX_25519_CHACHAPOLY_BLAKE2S, RIH1_V1] {
                let broken = Entry {
                    kind: EntryKind::SuiteStatus,
                    severity: Severity::Broken,
                    target: id.to_owned(),
                    arg: Vec::new(),
                    text_id: 0,
                };
                set_policy_for_this_thread(Some(Policy::of_entries(5, 0, &[broken], 0)));
                let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
                let Err(err) = initiator_session_on(
                    link,
                    &mut dialer,
                    &alice(),
                    &bob().public_key_bytes(),
                    LinkFeatures::NONE,
                    None,
                    None,
                )
                .await
                else {
                    panic!("{link:?}: no link");
                };
                assert_eq!(err, link_refused_text(id, 5), "{link:?}");
                let Err(err) =
                    responder_handshake(link, &mut listener, &bob(), LinkFeatures::NONE, None)
                        .await
                else {
                    panic!("{link:?}: a listener takes no link either");
                };
                assert_eq!(err, link_refused_text(id, 5), "{link:?}");
                drop(dialer);
                let mut byte = [0u8; 1];
                assert_eq!(listener.read(&mut byte).await.unwrap(), 0, "{link:?}");
            }
            set_policy_for_this_thread(None);
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
            let responder = tokio::spawn(async move {
                let (pk, _, mut t, ours, _, _) =
                    responder_handshake(link, &mut listener, &bob(), LinkFeatures::NONE, None)
                        .await
                        .unwrap();
                write_inet_frame(&mut listener, &mut t, &ours)
                    .await
                    .unwrap();
                pk
            });
            let (pk, ..) = initiator_session_on(
                link,
                &mut dialer,
                &alice(),
                &bob().public_key_bytes(),
                LinkFeatures::NONE,
                None,
                None,
            )
            .await
            .unwrap();
            assert_eq!(pk, bob().public_key_bytes());
            assert_eq!(responder.await.unwrap(), alice().public_key_bytes());
        }
        // A knocked Internet link (P6.35) is refused the same way, both
        // ends, before anything crosses.
        if let Some(_knock) = knock_on() {
            let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            write_contacts_pinned(b_dir.path(), &[&alice()], true);
            let bob_arc = Arc::new(bob());
            let dial = crate::link_knock::for_dial(
                true,
                false,
                a_dir.path(),
                &alice(),
                &bob().public_key_bytes(),
            )
            .expect("knock keys");
            let broken = Entry {
                kind: EntryKind::SuiteStatus,
                severity: Severity::Broken,
                target: NOISE_XX_25519_CHACHAPOLY_BLAKE2S.to_owned(),
                arg: Vec::new(),
                text_id: 0,
            };
            set_policy_for_this_thread(Some(Policy::of_entries(5, 0, &[broken], 0)));
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
            let Err(err) = initiator_session_on(
                INTERNET_LINK,
                &mut dialer,
                &alice(),
                &bob().public_key_bytes(),
                LinkFeatures::NONE,
                None,
                Some(&dial),
            )
            .await
            else {
                panic!("a knocked dial: no link");
            };
            let text = link_refused_text(NOISE_XX_25519_CHACHAPOLY_BLAKE2S, 5);
            assert_eq!(err, text);
            let ear = Ear::of(b_dir.path(), &bob_arc, None, OutboxCarrier::Internet);
            assert!(ear.is_some());
            let Err(err) = responder_handshake(
                INTERNET_LINK,
                &mut listener,
                &bob(),
                LinkFeatures::NONE,
                ear.as_ref(),
            )
            .await
            else {
                panic!("a listener with the knock takes no link either");
            };
            assert_eq!(err, text);
            drop(dialer);
            let mut byte = [0u8; 1];
            assert_eq!(listener.read(&mut byte).await.unwrap(), 0);
            set_policy_for_this_thread(None);
        }
        security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
    }

    /// RNL1 §7: the nearby link's prologue is its own. A nearby transcript
    /// never completes against Internet direct or p2p (either way round);
    /// nearby against nearby does.
    #[tokio::test]
    async fn nearby_link_transcript_cannot_complete_against_internet_or_p2p() {
        for (dialer_link, listener_link) in [
            (NEARBY_LINK, INTERNET_LINK),
            (NEARBY_LINK, P2P_LINK),
            (INTERNET_LINK, NEARBY_LINK),
            (P2P_LINK, NEARBY_LINK),
        ] {
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
            let responder = tokio::spawn(async move {
                responder_handshake(
                    listener_link,
                    &mut listener,
                    &bob(),
                    LinkFeatures::NONE,
                    None,
                )
                .await
                .map(drop)
            });
            let dialled = initiator_session_on(
                dialer_link,
                &mut dialer,
                &alice(),
                &bob().public_key_bytes(),
                LinkFeatures::NONE,
                None,
                None,
            )
            .await;
            assert!(dialled.is_err(), "{dialer_link:?} -> {listener_link:?}");
            drop(dialer);
            assert!(
                responder.await.unwrap().is_err(),
                "{dialer_link:?} -> {listener_link:?}"
            );
        }
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
        let responder = tokio::spawn(async move {
            let (pk, _, mut t, ours, _, _) =
                responder_handshake(NEARBY_LINK, &mut listener, &bob(), LinkFeatures::NONE, None)
                    .await
                    .unwrap();
            write_inet_frame(&mut listener, &mut t, &ours)
                .await
                .unwrap();
            pk
        });
        let (pk, ..) = initiator_session_on(
            NEARBY_LINK,
            &mut dialer,
            &alice(),
            &bob().public_key_bytes(),
            LinkFeatures::NONE,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(pk, bob().public_key_bytes());
        assert_eq!(responder.await.unwrap(), alice().public_key_bytes());
    }

    /// RAVEN_ONION_CARRIER_V1 §5.1: anyone can open an onion link and read
    /// the responder's static from message 2. It must be the onion link's
    /// own key, never the device static a LAN or Internet listener answers
    /// with; and an onion dialer never shows the device static either. Both
    /// ends still authenticate each other (the hellos sign the statics).
    #[tokio::test]
    async fn onion_link_never_shows_the_device_static() {
        let device = |id: &Identity| noise_static_public(&derive_noise_static(id).unwrap());
        let onion = |id: &Identity| noise_static_public(&derive_onion_noise_static(id).unwrap());

        // A stranger's message 1 and the onion listener's message 2.
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
        let responder = tokio::spawn(async move {
            responder_handshake(ONION_LINK, &mut listener, &bob(), LinkFeatures::NONE, None)
                .await
                .map(drop)
        });
        let stranger = derive_noise_static(&mallory()).unwrap();
        let mut hs = build_initiator_with_prologue(&stranger, ONION_LINK.prologue).unwrap();
        let m1 = handshake_write(&mut hs, &[]).unwrap();
        write_raw(&mut dialer, &m1).await.unwrap();
        let m2 = read_raw(&mut dialer).await.unwrap();
        handshake_read(&mut hs, &m2).unwrap();
        let shown = get_remote_static(&hs).unwrap();
        assert_ne!(
            shown,
            device(&bob()),
            "the device static went out over onion"
        );
        assert_eq!(shown, onion(&bob()));
        drop(dialer);
        assert!(responder.await.unwrap().is_err());

        // Two contacts over onion: authenticated, and neither static is a
        // device static.
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
        let responder = tokio::spawn(async move {
            let (pk, _, mut t, ours, dialer_static, _) =
                responder_handshake(ONION_LINK, &mut listener, &bob(), LinkFeatures::NONE, None)
                    .await
                    .unwrap();
            write_inet_frame(&mut listener, &mut t, &ours)
                .await
                .unwrap();
            (pk, dialer_static)
        });
        let (pk, _, _, listener_static, _) = initiator_session_on(
            ONION_LINK,
            &mut dialer,
            &alice(),
            &bob().public_key_bytes(),
            LinkFeatures::NONE,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(pk, bob().public_key_bytes());
        assert_eq!(listener_static, onion(&bob()));
        let (dialer_pk, dialer_static) = responder.await.unwrap();
        assert_eq!(dialer_pk, alice().public_key_bytes());
        assert_eq!(dialer_static, onion(&alice()));
        assert_ne!(dialer_static, device(&alice()));

        // The other links keep the device static (noise pins cover them).
        for link in [INTERNET_LINK, P2P_LINK, NEARBY_LINK] {
            assert_eq!(link.noise_static, LinkStatic::Device, "{link:?}");
        }
        assert!(!ONION_LINK.noise_pins().live);
    }

    /// RNL1 §7: a nearby responder takes only the key its pipe was knocked
    /// for. Any other key, even a verified contact's, is closed right after
    /// the handshake: no hello (the Raven identity), no RLB1, and before the
    /// contact gate's work.
    #[tokio::test]
    async fn expected_peer_mismatch_closes_before_hello() {
        let resp_dir = tempfile::tempdir().unwrap();
        write_contacts(resp_dir.path(), &[&alice(), &mallory()]);
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let data_dir = resp_dir.path().to_path_buf();
        let server = tokio::spawn(async move {
            let mut slot = test_slot();
            serve_inbound_on(
                NEARBY_LINK,
                data_dir,
                Arc::new(bob()),
                server_side,
                PRODUCTION_LIMITS,
                &mut slot,
                None,
                Some(alice().public_key_bytes()),
                None,
            )
            .await
        });
        let Err(err) = initiator_session_on(
            NEARBY_LINK,
            &mut client,
            &mallory(),
            &bob().public_key_bytes(),
            LinkFeatures::NONE,
            None,
            None,
        )
        .await
        else {
            panic!("no hello for another key")
        };
        assert_eq!(err, netutil::LINK_NOT_ACCEPTED);
        assert_eq!(
            listener_result(server).await.unwrap_err(),
            NEARBY_KEY_MISMATCH
        );
        let mut rest = Vec::new();
        assert_eq!(client.read_to_end(&mut rest).await.unwrap_or(0), 0);
    }

    #[tokio::test]
    async fn dialer_rejects_unexpected_responder_identity() {
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
        let responder = tokio::spawn(async move {
            let _ = responder_session(&mut listener, &mallory()).await;
        });
        let err = initiator_session(&mut dialer, &alice(), &bob().public_key_bytes())
            .await
            .unwrap_err();
        assert_eq!(err, "internet hello identity mismatch");
        drop(dialer);
        responder.await.unwrap();
    }

    /// Phase 6b S13 (P6.24): a hello from another identity at the dialled
    /// address is `SEC_ADDRESS_IMPOSTOR` about the contact dialled; the
    /// dial ends with the same error as before.
    #[tokio::test]
    async fn a_hello_from_another_identity_is_an_address_impostor() {
        use crate::security::tests::Capture;
        use raven_core::security_events::{Attribution, SecKind, Via};
        let Some(capture) = Capture::start() else {
            return;
        };
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
        let responder = tokio::spawn(async move {
            let _ = responder_session(&mut listener, &mallory()).await;
        });
        let err = initiator_session(&mut dialer, &alice(), &bob().public_key_bytes())
            .await
            .unwrap_err();
        assert_eq!(err, "internet hello identity mismatch");
        drop(dialer);
        responder.await.unwrap();
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::AddressImpostor,
                Attribution::Contact {
                    peer: bob().public_key_bytes()
                },
                Via::Dial(OutboxCarrier::Internet)
            )]
        );
    }

    /// Phase 6b S1 (P6.24): Internet direct's reply with a changed
    /// ciphertext is one `SEC_LINK_TAG_FAIL` about the dialled contact's
    /// path; the error is the same as with the gate shut.
    #[tokio::test]
    async fn a_flipped_reply_is_one_tag_failure_about_the_dialled_contact() {
        use crate::security::tests::Capture;
        use raven_core::security_events::{Attribution, SecKind, Via};
        let flipped_dial = || async move {
            let (mut dialer, mut t, mut conn, mut peer_t) = session_pair().await;
            let frames = vec![envelope_frame(EnvType::Message, 21)];
            let server = tokio::spawn(async move {
                let _ = read_inet_frame(&mut conn, &mut peer_t).await;
                let ack = envelope_frame(EnvType::Ack, 22);
                let mut ct = transport_encrypt(&mut peer_t.transport, &ack).unwrap();
                let last = ct.len() - 1;
                ct[last] ^= 0x01;
                write_raw(&mut conn, &ct).await.unwrap();
                conn
            });
            let mut progress = DialProgress::new("INTERNET", FAST);
            progress
                .collector
                .begin(b"offer".to_vec(), &frames)
                .unwrap();
            let err = exchange_frames(&mut dialer, &mut t, &frames, &mut no_hints(), &mut progress)
                .await
                .unwrap_err();
            drop(server.await.unwrap());
            err
        };
        let shut = flipped_dial().await;
        assert!(
            shut.starts_with("INTERNET_DIAL_BAD_REPLY")
                && shut.contains("(noise transport failed)"),
            "{shut}"
        );
        let Some(capture) = Capture::start() else {
            return;
        };
        assert_eq!(flipped_dial().await, shut);
        let bob = bob().public_key_bytes();
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::LinkTagFail,
                Attribution::Contact { peer: bob },
                Via::Dial(OutboxCarrier::Internet)
            )]
        );
        assert!(crate::security::take_excluded_dial(
            &bob,
            OutboxCarrier::Internet
        ));
    }

    /// Phase 6b S1 (P6.24): on the listener, a verified contact's frame after
    /// RLB1 whose ciphertext changed is one `SEC_LINK_TAG_FAIL` about that
    /// contact, and the link closes as before.
    #[tokio::test]
    async fn a_flipped_byte_after_rlb1_is_one_tag_failure_about_the_contact() {
        use crate::security::tests::Capture;
        use raven_core::security_events::{Attribution, SecKind, Via};
        let lab = ["RAVEN_PREKEY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(debug_assertions) && lab) {
            eprintln!("skipped: needs a debug build and RAVEN_IDENTITY_BACKEND=locked-file");
            return;
        }
        let Some(capture) = Capture::start() else {
            return;
        };
        let resp_dir = tempfile::tempdir().unwrap();
        let init_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x9a; 32]));
        let initiator = Identity::from_seed(&[0x9b; 32]);
        write_contacts(resp_dir.path(), &[&initiator]);
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
        let server = tokio::spawn(async move {
            let mut slot = test_slot();
            serve_inbound(data_dir, resp, server_side, PRODUCTION_LIMITS, &mut slot).await
        });
        let (_, mut t) = initiator_session(&mut client, &initiator, &responder.public_key_bytes())
            .await
            .expect("RIH1 session");
        let offer = encode_local_offer(init_dir.path(), &initiator).unwrap();
        write_inet_frame(&mut client, &mut t, &offer).await.unwrap();
        let theirs = read_inet_frame(&mut client, &mut t).await.unwrap();
        assert!(parse_peer_offer(&theirs).is_ok(), "a contact gets our RLB1");
        let mut ct =
            transport_encrypt(&mut t.transport, &envelope_frame(EnvType::Message, 23)).unwrap();
        ct[3] ^= 0x10;
        write_raw(&mut client, &ct).await.unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("the link closes")
            .unwrap();
        assert_eq!(ended, Ok(()), "closed as before");
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::LinkTagFail,
                Attribution::Contact {
                    peer: initiator.public_key_bytes()
                },
                Via::DirectLink(OutboxCarrier::Internet)
            )]
        );
    }

    /// Mallory completes XX with her own static key, then presents a hello
    /// signed by Alice for a different connection. Before the fix the hello
    /// only covered a self-chosen nonce, so the listener accepted it as Alice.
    #[tokio::test]
    async fn listener_rejects_hello_replayed_from_another_connection() {
        let (mut attacker, mut listener) = tokio::io::duplex(1 << 17);
        let responder =
            tokio::spawn(
                async move { responder_session(&mut listener, &bob()).await.map(|r| r.0) },
            );

        let m_secret = derive_noise_static(&mallory()).unwrap();
        let mut hs = build_initiator_with_prologue(&m_secret, NOISE_PROLOGUE).unwrap();
        write_raw(&mut attacker, &handshake_write(&mut hs, &[]).unwrap())
            .await
            .unwrap();
        let m2 = read_raw(&mut attacker).await.unwrap();
        handshake_read(&mut hs, &m2).unwrap();
        write_raw(&mut attacker, &handshake_write(&mut hs, &[]).unwrap())
            .await
            .unwrap();
        let mut t = LinkCipher::new(into_transport(hs).unwrap());
        // Alice's genuine hello from some earlier Alice→Bob connection.
        let captured = pack_hello(
            &alice(),
            CAP_INTERNET,
            &HelloBinding {
                role: HelloRole::Initiator,
                handshake_hash: [0x5a; 32],
                noise_static_pub: noise_static_public(&derive_noise_static(&alice()).unwrap()),
            },
        );
        write_inet_frame(&mut attacker, &mut t, &captured)
            .await
            .unwrap();
        assert_eq!(responder.await.unwrap().unwrap_err(), "hello sig");
    }

    #[tokio::test]
    async fn legacy_cleartext_hello_fails_closed() {
        let (mut old_peer, mut listener) = tokio::io::duplex(1 << 12);
        let mut legacy = b"RIH1".to_vec();
        legacy.resize(116, 0);
        old_peer.write_all(&legacy).await.unwrap();
        let err = responder_session(&mut listener, &bob()).await.unwrap_err();
        assert_eq!(err, "internet frame length");
    }

    #[tokio::test]
    async fn oversized_frame_rejected_before_allocation() {
        let (mut peer, mut listener) = tokio::io::duplex(64);
        peer.write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        assert_eq!(
            read_raw(&mut listener).await.unwrap_err(),
            "internet frame length"
        );
        let (a, _b, _, _) = raven_core::lan_noise::handshake_pair(&alice(), &bob()).unwrap();
        let mut a = LinkCipher::new(a);
        let (mut sink, _keep) = tokio::io::duplex(64);
        assert_eq!(
            write_inet_frame(&mut sink, &mut a, &vec![0u8; MAX_PAYLOAD_BYTES + 1])
                .await
                .unwrap_err(),
            "internet payload exceeds Noise transport limit"
        );
    }

    fn test_slot() -> AdmissionSlot {
        Admission::new(PRODUCTION_LIMITS)
            .try_admit("127.0.0.1".parse().unwrap())
            .expect("slot")
    }

    fn envelope_frame(kind: EnvType, id: u8) -> Vec<u8> {
        Envelope {
            env_type: kind as u8,
            flags: 0,
            message_id: [id; 16],
            routing_tag: [0x44; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at: u64::MAX / 2,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [0x55; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![id; 8],
            // Parsed only (never verified) by the reply classifier.
            sender_authentication: vec![0u8; 64],
        }
        .pack()
    }

    const FAST: ReplyWaits = ReplyWaits {
        first: Duration::from_secs(60),
        idle: Duration::from_secs(60),
    };

    /// A dial without route hints (a gate-off build): nothing is sent or
    /// consumed, so the data dir is never read.
    fn no_hints() -> crate::hints::LinkCtl {
        let keys = crate::hints::LinkKeys::new(bob().public_key_bytes(), &alice());
        crate::hints::LinkCtl::inet(
            Path::new("unused"),
            OutboxCarrier::Internet,
            crate::hints::Role::Dialer,
            keys,
            false,
            CAP_INTERNET,
            None,
        )
    }

    /// Dialer side of a duplex pipe after the full RIH1 session, plus the
    /// listener's side for a scripted peer.
    async fn session_pair() -> (
        tokio::io::DuplexStream,
        LinkCipher,
        tokio::io::DuplexStream,
        LinkCipher,
    ) {
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
        let expected = bob().public_key_bytes();
        let peer = tokio::spawn(async move {
            let (_, t) = responder_session(&mut listener, &bob()).await.unwrap();
            (listener, t)
        });
        let (_, t) = initiator_session(&mut dialer, &alice(), &expected)
            .await
            .unwrap();
        let (listener, peer_t) = peer.await.unwrap();
        (dialer, t, listener, peer_t)
    }

    /// Regression: a peer that kept streaming frames made `dial` buffer them
    /// without bound until the 45 s IPC timeout; it now stops at the shared
    /// one-IPC-response budget and says the frames were delivered.
    #[tokio::test]
    async fn dial_reply_flood_hits_the_budget() {
        let (mut dialer, mut t, mut conn, mut peer_t) = session_pair().await;
        let frames = vec![envelope_frame(EnvType::Message, 1)];
        let server = tokio::spawn(async move {
            let _ = read_inet_frame(&mut conn, &mut peer_t).await;
            for _ in 0..200 {
                if write_inet_frame(&mut conn, &mut peer_t, b"not-terminal")
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let mut progress = DialProgress::new("INTERNET", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let err = exchange_frames(&mut dialer, &mut t, &frames, &mut no_hints(), &mut progress)
            .await
            .unwrap_err();
        assert!(err.starts_with("INTERNET_DIAL_REPLY_OVERFLOW"), "{err}");
        assert!(err.ends_with("(frames were sent)"), "{err}");
        drop(dialer);
        server.abort();
    }

    /// The oversized RLB1 offer itself is also bounded (no frames sent yet).
    #[test]
    fn oversized_peer_offer_is_refused_before_any_frame_is_sent() {
        let mut progress = DialProgress::new("INTERNET", FAST);
        let err = progress
            .collector
            .begin(
                vec![0u8; 400 * 1024],
                &[envelope_frame(EnvType::Message, 1)],
            )
            .unwrap_err();
        assert!(err.starts_with("INTERNET_DIAL_REPLY_OVERFLOW"), "{err}");
        assert!(err.ends_with("(no frames were sent)"), "{err}");
    }

    /// Terminal reply ends the dial at once; the peer stays connected.
    #[tokio::test]
    async fn dial_returns_as_soon_as_the_ack_arrives() {
        let (mut dialer, mut t, mut conn, mut peer_t) = session_pair().await;
        let frames = vec![envelope_frame(EnvType::Message, 2)];
        let ack = envelope_frame(EnvType::Ack, 3);
        let ack_c = ack.clone();
        let server = tokio::spawn(async move {
            let _ = read_inet_frame(&mut conn, &mut peer_t).await.unwrap();
            write_inet_frame(&mut conn, &mut peer_t, &ack_c)
                .await
                .unwrap();
            let _keep = (conn, peer_t);
            std::future::pending::<()>().await;
        });
        let mut progress = DialProgress::new("INTERNET", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(20),
            exchange_frames(&mut dialer, &mut t, &frames, &mut no_hints(), &mut progress),
        )
        .await
        .expect("must not wait for the idle timeout once the ACK is in")
        .unwrap();
        assert_eq!(
            progress.collector.into_replies(),
            vec![b"offer".to_vec(), ack]
        );
        server.abort();
    }

    #[tokio::test]
    async fn peer_closing_without_a_reply_is_an_error() {
        let (mut dialer, mut t, mut conn, mut peer_t) = session_pair().await;
        let frames = vec![envelope_frame(EnvType::Message, 4)];
        let server = tokio::spawn(async move {
            let _ = read_inet_frame(&mut conn, &mut peer_t).await;
            drop(conn);
        });
        let mut progress = DialProgress::new("INTERNET", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let err = exchange_frames(&mut dialer, &mut t, &frames, &mut no_hints(), &mut progress)
            .await
            .unwrap_err();
        assert!(err.starts_with("INTERNET_DIAL_PEER_CLOSED"), "{err}");
        server.await.unwrap();
    }

    /// Regression: `handle_inbound` loaded the identity from the secret store
    /// for every unauthenticated connection and ran SQLite work on the async
    /// workers. The session now takes the listener's identity (the data dir
    /// here has none at all) and a silent peer ends at the handshake deadline.
    #[tokio::test(start_paused = true)]
    async fn silent_connection_ends_at_handshake_deadline_and_frees_slot() {
        let dir = tempfile::tempdir().unwrap();
        let admission = Admission::new(PRODUCTION_LIMITS);
        let ip = "10.1.2.3".parse().unwrap();
        let mut slot = admission.try_admit(ip).unwrap();
        let (_silent_peer, server_side) = tokio::io::duplex(1024);
        let started = tokio::time::Instant::now();
        let err = serve_inbound(
            dir.path().to_path_buf(),
            Arc::new(bob()),
            server_side,
            PRODUCTION_LIMITS,
            &mut slot,
        )
        .await
        .unwrap_err();
        assert_eq!(err, HANDSHAKE_TIMEOUT);
        assert!(started.elapsed() >= PRODUCTION_LIMITS.handshake_deadline);
        assert!(started.elapsed() < PRODUCTION_LIMITS.lifetime);
    }

    /// Verified (pinned) contacts: the only kind the Internet listener answers.
    fn write_contacts(dir: &Path, contacts: &[&Identity]) {
        write_contacts_pinned(dir, contacts, true);
    }

    fn write_contacts_pinned(dir: &Path, contacts: &[&Identity], pinned: bool) {
        let rows: Vec<String> = contacts
            .iter()
            .map(|c| {
                format!(
                    r#"{{"pub_hex":"{}","pinned":{pinned}}}"#,
                    hex::encode(c.public_key_bytes())
                )
            })
            .collect();
        std::fs::write(dir.join("contacts.json"), format!("[{}]", rows.join(","))).unwrap();
    }

    /// Mirrors `lan_direct::only_a_local_contact_earns_a_protected_slot`: an
    /// RLB1 offer proves possession of *a* key only, so just a local contact
    /// leaves the pre-auth caps for a non-displaceable slot.
    #[tokio::test]
    async fn only_a_local_contact_earns_a_protected_slot() {
        let lab = ["RAVEN_PREKEY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(debug_assertions) && lab) {
            eprintln!("skipped: needs a debug build and RAVEN_IDENTITY_BACKEND=locked-file");
            return;
        }
        let ip: std::net::IpAddr = "10.9.8.8".parse().unwrap();
        let resp_dir = tempfile::tempdir().unwrap();
        let init_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x73; 32]));
        let initiator = Identity::from_seed(&[0x74; 32]);
        write_contacts(resp_dir.path(), &[&initiator]);
        let admission = Admission::new(PRODUCTION_LIMITS);
        let mut slot = admission.try_admit(ip).expect("slot");
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
        let server = tokio::spawn(async move {
            serve_inbound(data_dir, resp, server_side, PRODUCTION_LIMITS, &mut slot).await
        });
        let (_, mut t) = initiator_session(&mut client, &initiator, &responder.public_key_bytes())
            .await
            .expect("RIH1 session");
        let offer = encode_local_offer(init_dir.path(), &initiator).unwrap();
        write_inet_frame(&mut client, &mut t, &offer).await.unwrap();
        let theirs = read_inet_frame(&mut client, &mut t).await.unwrap();
        assert!(parse_peer_offer(&theirs).is_ok(), "a contact gets our RLB1");

        let mut held = Vec::new();
        while let Some(s) = admission.try_admit(ip) {
            held.push(s);
        }
        assert_eq!(
            held.len(),
            PRODUCTION_LIMITS.max_handshaking_per_ip,
            "a contact no longer counts as pre-auth"
        );
        drop(held);
        drop(client);
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("handler ends when the dialer hangs up")
            .unwrap()
            .unwrap();
    }

    /// F4: an Internet scanner that completes Noise XX with any key that is not
    /// a local contact (or is blocked) is disconnected right after its hello.
    /// It gets no transport frame at all: no RIH1 hello (Raven identity), no
    /// RLB1 (certificate + prekey bundle), just the fixed `LINK_NOT_ACCEPTED`.
    #[tokio::test]
    async fn stranger_learns_nothing_but_not_accepted() {
        // P3.14: with the session renewer running, no refused key is queued.
        let _renewer = crate::renewal::RunningForTest::set();
        let responder = Arc::new(bob());
        for case in [
            "no contacts.json",
            "other contact",
            "blocked contact",
            "unverified contact",
        ] {
            let resp_dir = tempfile::tempdir().unwrap();
            match case {
                "other contact" => write_contacts(resp_dir.path(), &[&alice()]),
                "blocked contact" => {
                    write_contacts(resp_dir.path(), &[&mallory()]);
                    let mut blocks = raven_core::BlockList::default();
                    blocks.block(&hex::encode(mallory().public_key_bytes()));
                    blocks.save(resp_dir.path()).unwrap();
                }
                // A contact whose fingerprint was never confirmed: LAN would
                // answer it, the Internet listener treats it as a stranger.
                "unverified contact" => {
                    write_contacts_pinned(resp_dir.path(), &[&mallory()], false)
                }
                _ => {}
            }
            let (mut scanner, server_side) = tokio::io::duplex(1 << 18);
            let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
            let server = tokio::spawn(async move {
                let mut slot = test_slot();
                serve_inbound(data_dir, resp, server_side, PRODUCTION_LIMITS, &mut slot).await
            });
            let err = initiator_session(&mut scanner, &mallory(), &bob().public_key_bytes())
                .await
                .err()
                .unwrap_or_else(|| panic!("{case}: a stranger must not get our hello"));
            assert_eq!(err, netutil::LINK_NOT_ACCEPTED, "{case}");
            let refusal = tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("handler ends")
                .unwrap()
                .unwrap_err();
            let want = match case {
                "blocked contact" => raven_core::lan_dispatch::LINK_REFUSED_BLOCKED,
                "unverified contact" => raven_core::lan_dispatch::LINK_REFUSED_NOT_VERIFIED,
                _ => raven_core::lan_dispatch::LINK_REFUSED_NOT_CONTACT,
            };
            assert_eq!(refusal, want, "{case}");
            assert!(!refusal.contains(&hex::encode(mallory().public_key_bytes())));
            assert!(
                !crate::renewal::queued_for_test(&mallory().public_key_bytes()),
                "{case}: no renewal for a refused key"
            );
            let mut rest = Vec::new();
            assert_eq!(scanner.read_to_end(&mut rest).await.unwrap_or(0), 0);
        }
    }

    /// E1 (three machines): the Internet responder (p2p and nearby links
    /// run it too) waits for a contact book held while its key loads, as
    /// the LAN one does: a verified friend is admitted once it opens; still
    /// held after the wait, the link closes before Noise message 2 with the
    /// not-ready refusal (no stranger, no security event), never with the
    /// stranger's LINK_NOT_ACCEPTED.
    #[tokio::test]
    async fn a_held_book_is_waited_for_and_judges_nobody() {
        use crate::at_rest_boot::tests::{answered, key_loading_until_answered};
        let responder = Arc::new(bob());
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path().to_path_buf();
        write_contacts(&dd, &[&alice()]);
        let dial = |limits: InboundLimits| {
            let (data_dir, resp) = (dd.clone(), responder.clone());
            async move {
                let (mut client, server_side) = tokio::io::duplex(1 << 18);
                let server = tokio::spawn(async move {
                    let mut slot = test_slot();
                    serve_inbound(data_dir, resp, server_side, limits, &mut slot).await
                });
                let got = initiator_session(&mut client, &alice(), &bob().public_key_bytes())
                    .await
                    .map(|_| ());
                drop(client);
                let ended = tokio::time::timeout(Duration::from_secs(10), server)
                    .await
                    .expect("handler ends")
                    .unwrap();
                (got, ended)
            }
        };
        let answer = key_loading_until_answered(&dd);
        let opens = {
            let dd = dd.clone();
            tokio::task::spawn_blocking(move || {
                std::thread::sleep(Duration::from_millis(300));
                answered(&dd, answer);
            })
        };
        let (got, _) = dial(PRODUCTION_LIMITS).await;
        assert_eq!(got, Ok(()), "admitted once the book opened");
        opens.await.unwrap();
        let answer = key_loading_until_answered(&dd);
        let (got, ended) = dial(InboundLimits {
            book_wait: Duration::from_millis(200),
            ..PRODUCTION_LIMITS
        })
        .await;
        assert_eq!(got.unwrap_err(), netutil::PEER_CLOSED);
        let refusal = ended.unwrap_err();
        assert_eq!(refusal, raven_core::lan_dispatch::LINK_REFUSED_NOT_READY);
        assert!(raven_core::security_events::classify_link_error(&refusal).is_none());
        tokio::task::spawn_blocking(move || answered(&dd, answer))
            .await
            .unwrap();
    }

    /// P3.14: with the session renewer running, a contact's Raven link queues
    /// the contact for a renewal step at both ends: the listener notes the
    /// dialer (inbound, trusted branch), the dialer the listener after its
    /// verified RLB1 offer (outbound). p2p links run these same two halves
    /// (`serve_inbound_on`, `dial_session_on`).
    #[tokio::test]
    async fn a_contact_link_queues_both_ends_for_renewal() {
        let lab = ["RAVEN_PREKEY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .all(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(debug_assertions) && lab) {
            eprintln!("skipped: needs a debug build and the locked-file backends");
            return;
        }
        let _renewer = crate::renewal::RunningForTest::set();
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let dialer = raven_core::load_or_create_identity(a_dir.path()).unwrap().0;
        let responder = Arc::new(bob());
        write_contacts(b_dir.path(), &[&dialer]);
        write_contacts(a_dir.path(), &[&responder]);
        let (client, server_side) = tokio::io::duplex(1 << 18);
        let (data_dir, resp) = (b_dir.path().to_path_buf(), responder.clone());
        let server = tokio::spawn(async move {
            let mut slot = test_slot();
            serve_inbound(data_dir, resp, server_side, PRODUCTION_LIMITS, &mut slot).await
        });
        let mut stream = Some(client);
        let mut progress = DialProgress::new("INTERNET", FAST);
        tokio::time::timeout(
            Duration::from_secs(20),
            dial_session_on(
                INTERNET_LINK,
                a_dir.path(),
                || {
                    let s = stream.take();
                    async move { s.ok_or_else(|| "one stream only".to_string()) }
                },
                &responder.public_key_bytes(),
                &[],
                None,
                &mut progress,
            ),
        )
        .await
        .expect("the dial ends")
        .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("the listener ends");
        assert!(
            crate::renewal::queued_for_test(&responder.public_key_bytes()),
            "the dialer queued the contact it reached"
        );
        assert!(
            crate::renewal::queued_for_test(&dialer.public_key_bytes()),
            "the listener queued the contact that reached it"
        );
    }

    /// The dial side of the same rule: an Internet dial to a contact that is
    /// not verified is refused before anything is dialled (no listener here:
    /// a dial attempt would fail with a connect error instead).
    #[tokio::test]
    async fn dial_to_an_unverified_contact_is_refused_before_connecting() {
        if !internet_direct_live_enabled() {
            return; // HOLD answers first; covered by the gate tests.
        }
        let dir = tempfile::tempdir().unwrap();
        let expected = hex::encode(bob().public_key_bytes());
        for pinned in [None, Some(false)] {
            if let Some(pinned) = pinned {
                write_contacts_pinned(dir.path(), &[&bob()], pinned);
            }
            let err = dial(dir.path(), "127.0.0.1:9", &expected, &[])
                .await
                .unwrap_err();
            assert!(err.starts_with(raven_core::CONTACT_NOT_VERIFIED), "{err}");
            assert!(err.contains("nothing was dialled"), "{err}");
        }
    }

    /// Hide my IP (D4): an Internet direct dial to a contact this node hides
    /// its IP from (its row, or every contact) is refused before anything is
    /// dialled, whoever asks (the IPC `InternetDial` op included).
    #[tokio::test]
    async fn dial_to_a_contact_hidden_from_is_refused_before_connecting() {
        let dir = tempfile::tempdir().unwrap();
        let expected = hex::encode(bob().public_key_bytes());
        let book = |hide_ip: bool| {
            std::fs::write(
                dir.path().join("contacts.json"),
                format!(r#"[{{"pub_hex":"{expected}","pinned":true,"hide_ip":{hide_ip}}}]"#),
            )
            .unwrap();
        };
        let everyone = |hide_ip: bool| {
            raven_core::node_policy::save_policy(
                dir.path(),
                &raven_core::node_policy::NodePolicy {
                    hide_ip,
                    ..raven_core::node_policy::NodePolicy::default()
                },
            )
            .unwrap();
        };
        book(false);
        everyone(false);
        assert_eq!(require_ip_shown(dir.path(), &expected).await, Ok(()));
        for (row, all) in [(true, false), (false, true)] {
            book(row);
            everyone(all);
            let err = require_ip_shown(dir.path(), &expected).await.unwrap_err();
            assert_eq!(err, INTERNET_HIDDEN, "{row} {all}");
            assert!(err.contains("nothing was dialled"));
            if internet_direct_live_enabled() {
                // The whole dial: refused at once (no listener at :9 here, a
                // dial attempt would fail with a connect error instead).
                let err = dial(dir.path(), "127.0.0.1:9", &expected, &[])
                    .await
                    .unwrap_err();
                assert_eq!(err, INTERNET_HIDDEN);
            }
        }
    }

    /// The refusal is final: the dial path never retries it (a retry would only
    /// repeat the refusal, and a refused send must fail fast).
    #[tokio::test]
    async fn not_accepted_is_not_retried_by_the_handshake_loop() {
        let mut attempts = 0;
        let err = netutil::with_handshake_retries(|| {
            attempts += 1;
            async { Err::<(), _>(netutil::LINK_NOT_ACCEPTED.to_string()) }
        })
        .await
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert_eq!(err, netutil::LINK_NOT_ACCEPTED);
        assert!(!err.contains("closed the connection during the handshake"));
    }

    /// A full RIH1 session with the listener identity but no local state: a
    /// garbage RLB1 offer is refused after the handshake (and the slot stays
    /// a pre-auth slot until then).
    #[tokio::test]
    async fn inbound_session_uses_listener_identity_not_store() {
        let dir = tempfile::tempdir().unwrap();
        write_contacts(dir.path(), &[&alice()]);
        let (mut dialer, server_side) = tokio::io::duplex(1 << 17);
        let responder = Arc::new(bob());
        let expected = responder.public_key_bytes();
        let data_dir = dir.path().to_path_buf();
        let server = tokio::spawn(async move {
            let mut slot = test_slot();
            serve_inbound(
                data_dir,
                responder,
                server_side,
                PRODUCTION_LIMITS,
                &mut slot,
            )
            .await
        });
        let (_, mut t) = initiator_session(&mut dialer, &alice(), &expected)
            .await
            .expect("RIH1 session with the listener's in-memory identity");
        write_inet_frame(&mut dialer, &mut t, b"not-an-rlb1-offer")
            .await
            .unwrap();
        let err = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("inbound session finishes")
            .unwrap()
            .unwrap_err();
        assert!(!err.is_empty());
    }

    // ── Route hints (RRH1) ──────────────────────────────────────────────

    const BOTH: u32 = CAP_INTERNET | raven_core::CAP_LINK_RRH1;

    fn route_hint(generation: u64) -> Vec<u8> {
        raven_core::route_hints::encode(&raven_core::route_hints::RouteHints {
            generation,
            ttl_s: 3600,
            ..Default::default()
        })
    }

    fn keys(peer: &Identity, local: &Identity) -> crate::hints::LinkKeys {
        crate::hints::LinkKeys::new(peer.public_key_bytes(), local)
    }

    /// Each hello sets bit 8 exactly when its side has route hints on, and
    /// each side sees the other's caps.
    #[tokio::test]
    async fn hello_caps_bit_only_when_live() {
        for (dialer_rrh1, listener_rrh1) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
            let responder = tokio::spawn(async move {
                let (_, caps, mut t, ours, _, _) = responder_handshake(
                    INTERNET_LINK,
                    &mut listener,
                    &bob(),
                    LinkFeatures::NONE.with(LinkFeatures::RRH1, listener_rrh1),
                    None,
                )
                .await
                .unwrap();
                write_inet_frame(&mut listener, &mut t, &ours)
                    .await
                    .unwrap();
                caps
            });
            let (_, listener_caps, _, _, _) = initiator_session_on(
                INTERNET_LINK,
                &mut dialer,
                &alice(),
                &bob().public_key_bytes(),
                LinkFeatures::NONE.with(LinkFeatures::RRH1, dialer_rrh1),
                None,
                None,
            )
            .await
            .unwrap();
            let caps = |rrh1| hello_caps(LinkFeatures::NONE.with(LinkFeatures::RRH1, rrh1));
            assert_eq!(listener_caps, caps(listener_rrh1));
            assert_eq!(responder.await.unwrap(), caps(dialer_rrh1));
        }
        assert_eq!(
            hello_caps(LinkFeatures::NONE),
            CAP_INTERNET,
            "gate off: today's hello"
        );
    }

    /// The old-peer property: bits a build does not know are kept, never
    /// refused; only CAP_INTERNET is required.
    #[test]
    fn verify_peer_hello_accepts_unknown_bits() {
        let binding = HelloBinding {
            role: HelloRole::Initiator,
            handshake_hash: [0x5a; 32],
            noise_static_pub: noise_static_public(&derive_noise_static(&alice()).unwrap()),
        };
        let caps = BOTH | 0x0000_0200 | 0x8000_0000;
        let raw = pack_hello(&alice(), caps, &binding);
        assert_eq!(
            verify_peer_hello(&raw, &binding),
            Ok((caps, alice().public_key_bytes()))
        );
        let raw = pack_hello(&alice(), raven_core::CAP_LINK_RRH1, &binding);
        assert_eq!(
            verify_peer_hello(&raw, &binding).unwrap_err(),
            "internet hello missing CAP_INTERNET"
        );
    }

    /// Internet and p2p: the dialer's RRH1 goes before its frames when the
    /// listener's hello asked for it, and not at all otherwise.
    #[tokio::test]
    async fn dialer_sends_rrh1_before_its_frames_when_the_listener_advertised() {
        let dir = tempfile::tempdir().unwrap();
        write_contacts(dir.path(), &[&bob()]);
        for peer_caps in [CAP_INTERNET, BOTH] {
            let (mut dialer, mut t, mut conn, mut peer_t) = session_pair().await;
            let ack = envelope_frame(EnvType::Ack, 21);
            let ack_c = ack.clone();
            let server = tokio::spawn(async move {
                let mut got = Vec::new();
                while let Ok(frame) = read_inet_frame(&mut conn, &mut peer_t).await {
                    if !raven_core::route_hints::is_rrh1(&frame) {
                        write_inet_frame(&mut conn, &mut peer_t, &ack_c)
                            .await
                            .unwrap();
                    }
                    got.push(frame);
                }
                got
            });
            let frames = vec![envelope_frame(EnvType::Message, 20)];
            let mut progress = DialProgress::new("INTERNET", FAST);
            progress
                .collector
                .begin(b"offer".to_vec(), &frames)
                .unwrap();
            let mut hints = crate::hints::LinkCtl::inet(
                dir.path(),
                OutboxCarrier::Internet,
                crate::hints::Role::Dialer,
                keys(&bob(), &alice()),
                true,
                peer_caps,
                None,
            );
            exchange_frames(&mut dialer, &mut t, &frames, &mut hints, &mut progress)
                .await
                .unwrap();
            assert_eq!(
                progress.collector.into_replies(),
                vec![b"offer".to_vec(), ack]
            );
            drop(dialer);
            let got = server.await.unwrap();
            if peer_caps == BOTH {
                assert_eq!(got.len(), 2);
                assert!(
                    raven_core::route_hints::decode(&got[0]).is_some(),
                    "RRH1 first"
                );
                assert_eq!(got[1], frames[0]);
            } else {
                assert_eq!(got, frames, "the listener did not ask");
            }
        }
    }

    /// The listener's RRH1 follows its RLB1, only for a dialer whose hello
    /// set the bit.
    #[tokio::test]
    async fn listener_sends_after_rlb1_only_to_advertising_dialers() {
        if !lab_backend_available() {
            return;
        }
        let _live = crate::hints::LiveForTest::set(true);
        let resp_dir = tempfile::tempdir().unwrap();
        write_contacts(resp_dir.path(), &[&alice()]);
        for (rrh1, want) in [(false, 0), (true, 1)] {
            let (mut client, mut t, server) =
                dial_listener(INTERNET_LINK, resp_dir.path(), &alice(), rrh1, None).await;
            client.shutdown().await.unwrap();
            let mut after = Vec::new();
            while let Ok(frame) = read_inet_frame(&mut client, &mut t).await {
                after.push(frame);
            }
            assert_eq!(after.len(), want, "rrh1={rrh1}");
            assert!(after
                .iter()
                .all(|f| raven_core::route_hints::decode(f).is_some()));
            listener_result(server).await.unwrap();
        }
    }

    /// On a p2p link the frame's P2P_ID must be the connection's PeerId:
    /// otherwise the PeerId, relays and direct addresses are dropped (and
    /// the link stays up).
    #[tokio::test]
    async fn p2p_link_peer_id_mismatch_drops_p2p_entries() {
        if !lab_backend_available() {
            return;
        }
        let _live = crate::hints::LiveForTest::set(true);
        let alice_peer_id = raven_core::p2p_route::local_peer_id(&alice());
        let frame = raven_core::route_hints::encode(&raven_core::route_hints::RouteHints {
            generation: 3,
            ttl_s: 3600,
            p2p_id: Some(raven_core::p2p_route::peer_id_bytes(&alice_peer_id).unwrap()),
            relays: vec![format!(
                "/ip4/11.0.2.1/tcp/7423/p2p/{}",
                raven_core::p2p_route::local_peer_id(&mallory())
            )],
            ..Default::default()
        });
        for (link_peer_id, kept) in [
            (raven_core::p2p_route::local_peer_id(&mallory()), false),
            (alice_peer_id.clone(), true),
        ] {
            let resp_dir = tempfile::tempdir().unwrap();
            write_contacts(resp_dir.path(), &[&alice()]);
            let (mut client, mut t, server) = dial_listener(
                P2P_LINK,
                resp_dir.path(),
                &alice(),
                true,
                Some(link_peer_id),
            )
            .await;
            write_inet_frame(&mut client, &mut t, &frame).await.unwrap();
            client.shutdown().await.unwrap();
            while read_inet_frame(&mut client, &mut t).await.is_ok() {}
            listener_result(server)
                .await
                .expect("consumed, not dispatched");
            if raven_core::route_hints::route_hints_live() {
                let view = raven_core::learned_routes::learned(
                    resp_dir.path(),
                    &alice().public_key_bytes(),
                    crate::now_ms(),
                )
                .unwrap();
                assert_eq!(view.peer_id.is_some(), kept);
                assert_eq!(view.relays.len(), usize::from(kept));
                assert_eq!(view.peer_id_proven, kept);
            }
        }
    }

    /// A dial without frames whose listener's hello said it sends an RRH1
    /// reads it before closing (and sent its own first).
    #[tokio::test]
    async fn a_zero_frame_dial_reads_the_listeners_rrh1_before_closing() {
        let dir = tempfile::tempdir().unwrap();
        write_contacts(dir.path(), &[&bob()]);
        let (mut dialer, mut t, mut conn, mut peer_t) = session_pair().await;
        let server = tokio::spawn(async move {
            write_inet_frame(&mut conn, &mut peer_t, &route_hint(4))
                .await
                .unwrap();
            let mut got = Vec::new();
            while let Ok(frame) = read_inet_frame(&mut conn, &mut peer_t).await {
                got.push(frame);
            }
            got
        });
        let mut progress = DialProgress::new("INTERNET", FAST);
        progress.collector.begin(b"offer".to_vec(), &[]).unwrap();
        let mut hints = crate::hints::LinkCtl::inet(
            dir.path(),
            OutboxCarrier::Internet,
            crate::hints::Role::Dialer,
            keys(&bob(), &alice()),
            true,
            BOTH,
            None,
        );
        exchange_frames(&mut dialer, &mut t, &[], &mut hints, &mut progress)
            .await
            .unwrap();
        assert_eq!(hints.counts(), (true, 1), "ours out, theirs read");
        assert_eq!(progress.collector.into_replies(), vec![b"offer".to_vec()]);
        drop(dialer);
        let got = server.await.unwrap();
        assert_eq!(got.len(), 1);
        assert!(raven_core::route_hints::decode(&got[0]).is_some());
    }

    fn lab_backend_available() -> bool {
        let lab = ["RAVEN_PREKEY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(debug_assertions) && lab) {
            eprintln!("skipped: needs a debug build and RAVEN_IDENTITY_BACKEND=locked-file");
            return false;
        }
        true
    }

    /// A real listener of `link`'s flavour (bob) and a scripted dialer that
    /// completes the hellos (bit 8 when `rrh1`) and the RLB1 exchange.
    /// Returns the dialer's end after the listener's RLB1, and the listener.
    async fn dial_listener(
        link: RavenLink,
        resp_dir: &Path,
        dialer: &Identity,
        rrh1: bool,
        link_peer_id: Option<String>,
    ) -> (
        tokio::io::DuplexStream,
        LinkCipher,
        tokio::task::JoinHandle<Result<(), String>>,
    ) {
        let init_dir = tempfile::tempdir().unwrap();
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let data_dir = resp_dir.to_path_buf();
        let server = tokio::spawn(async move {
            let mut slot = test_slot();
            serve_inbound_on(
                link,
                data_dir,
                Arc::new(bob()),
                server_side,
                PRODUCTION_LIMITS,
                &mut slot,
                link_peer_id,
                None,
                None,
            )
            .await
        });
        let (_, _, mut t, _, _) = initiator_session_on(
            link,
            &mut client,
            dialer,
            &bob().public_key_bytes(),
            LinkFeatures::NONE.with(LinkFeatures::RRH1, rrh1),
            None,
            None,
        )
        .await
        .expect("RIH1 session");
        let offer = encode_local_offer(init_dir.path(), dialer).unwrap();
        write_inet_frame(&mut client, &mut t, &offer).await.unwrap();
        let theirs = read_inet_frame(&mut client, &mut t).await.unwrap();
        assert!(parse_peer_offer(&theirs).is_ok(), "the listener's RLB1");
        (client, t, server)
    }

    async fn listener_result(
        server: tokio::task::JoinHandle<Result<(), String>>,
    ) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("listener ends")
            .unwrap()
    }

    // ── PAD1 link padding (Phase 6b P6.34) ─────────────────────────────

    /// P6.34 on all three flavours of the link (Internet direct, p2p,
    /// nearby), each order: old dialer and old listener (the baseline), old
    /// and new, new and old, new and new. A real listener and a scripted
    /// dialer whose end is tapped: hellos, RLB1 both ways, then the
    /// dialer's RLB1 again. Every message after the hellos is a PAD1 bucket
    /// plus the tag when both hellos carried bit 9, and the baseline's
    /// lengths otherwise; the hellos are never padded.
    #[tokio::test]
    async fn pad1_sizes_on_the_wire_for_each_order_and_link() {
        use crate::link::wire::{is_padded, Tap};
        if !lab_backend_available() {
            return;
        }
        let _hints = crate::hints::LiveForTest::set(false);
        let resp_dir = tempfile::tempdir().unwrap();
        write_contacts(resp_dir.path(), &[&alice()]);
        for link in [INTERNET_LINK, P2P_LINK, NEARBY_LINK] {
            let mut baseline = None;
            for (dialer_new, listener_new) in
                [(false, false), (false, true), (true, false), (true, true)]
            {
                let _pad = crate::link::PaddingForTest::set(listener_new);
                if listener_new && !crate::link::padding_live() {
                    return; // a release build: the gate cannot open
                }
                let init_dir = tempfile::tempdir().unwrap();
                let (client, server_side) = tokio::io::duplex(1 << 18);
                let mut client = Tap::new(client);
                let data_dir = resp_dir.path().to_path_buf();
                let server = tokio::spawn(async move {
                    let mut slot = test_slot();
                    serve_inbound_on(
                        link,
                        data_dir,
                        Arc::new(bob()),
                        server_side,
                        PRODUCTION_LIMITS,
                        &mut slot,
                        None,
                        None,
                        None,
                    )
                    .await
                });
                let offers = LinkFeatures::NONE.with(LinkFeatures::PAD1, dialer_new);
                let (_, caps, mut t, _, _) = initiator_session_on(
                    link,
                    &mut client,
                    &alice(),
                    &bob().public_key_bytes(),
                    offers,
                    None,
                    None,
                )
                .await
                .expect("RIH1 session");
                assert_eq!(caps & CAP_LINK_PAD1 != 0, listener_new, "{link:?}");
                let offer = encode_local_offer(init_dir.path(), &alice()).unwrap();
                write_inet_frame(&mut client, &mut t, &offer).await.unwrap();
                let theirs = read_inet_frame(&mut client, &mut t).await.unwrap();
                assert!(parse_peer_offer(&theirs).is_ok(), "the listener's RLB1");
                write_inet_frame(&mut client, &mut t, &offer).await.unwrap();
                client.shutdown().await.unwrap();
                assert!(read_inet_frame(&mut client, &mut t).await.is_err());
                listener_result(server).await.expect("a clean end");
                let (sent, received) = client.lengths();
                assert_eq!(
                    (sent.len(), received.len()),
                    (5, 3),
                    "{sent:?} {received:?}"
                );
                assert_eq!(
                    (sent[2], received[1]),
                    (HELLO_WIRE_LEN + 16, HELLO_WIRE_LEN + 16)
                );
                let after = (sent[3..].to_vec(), received[2..].to_vec());
                let both = dialer_new && listener_new;
                assert_eq!(t.pad.negotiated(), both, "{link:?}");
                if both {
                    assert!(t.pad.peer_started());
                    assert!(
                        after.0.iter().chain(&after.1).all(|&n| is_padded(n)),
                        "{after:?}"
                    );
                } else if let Some(base) = &baseline {
                    assert_eq!(&after, base, "{link:?} {dialer_new} {listener_new}");
                } else {
                    assert!(!after.0.iter().chain(&after.1).any(|&n| is_padded(n)));
                    baseline = Some(after);
                }
            }
        }
    }

    /// P6.34: a listener that stops padding mid-link (a bare reply after a
    /// padded one) ends the dialer's read, and that is
    /// `SEC_CONTACT_MALFORMED` about the dialled contact; the reply that
    /// came padded is kept.
    #[tokio::test]
    async fn a_listener_that_stops_padding_is_malformed_at_the_dialer() {
        use crate::security::tests::Capture;
        use raven_core::security_events::{Attribution, SecKind, Via};
        let Some(capture) = Capture::start() else {
            return;
        };
        let (mut dialer, mut t, mut conn, mut peer_t) = session_pair().await;
        t.pad = PadState::agreed(true);
        peer_t.pad = PadState::agreed(true);
        let frames = vec![envelope_frame(EnvType::Message, 31)];
        let ack = envelope_frame(EnvType::Ack, 31);
        let server = tokio::spawn(async move {
            let got = read_inet_frame(&mut conn, &mut peer_t).await.unwrap();
            write_inet_frame(&mut conn, &mut peer_t, b"not-terminal")
                .await
                .unwrap();
            peer_t.pad = PadState::OFF;
            write_inet_frame(&mut conn, &mut peer_t, &ack)
                .await
                .unwrap();
            (got, conn)
        });
        let mut progress = DialProgress::new("INTERNET", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        exchange_frames(&mut dialer, &mut t, &frames, &mut no_hints(), &mut progress)
            .await
            .expect("a close after a reply ends the wait");
        assert_eq!(
            progress.collector.into_replies(),
            vec![b"offer".to_vec(), b"not-terminal".to_vec()]
        );
        let (got, _conn) = server.await.unwrap();
        assert_eq!(got, frames[0], "the frame went padded and came out whole");
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::ContactMalformed,
                Attribution::Contact {
                    peer: bob().public_key_bytes()
                },
                Via::Dial(OutboxCarrier::Internet)
            )]
        );
    }

    /// M0 on the Raven link, both prologues: with Bob's noise pin, Mallory
    /// answering ends the dial after message 2 (no message 3, no hello, so
    /// not even our Raven identity on the p2p inner link), never retried;
    /// Bob himself completes and the dial learns his static.
    #[tokio::test]
    async fn a_pinned_dial_stops_before_message_3_on_both_links() {
        let bob_static = noise_static_public(&derive_noise_static(&bob()).unwrap());
        // Alice's pin for Bob, under her own pin key.
        let pin = raven_core::lan_noise_pin::pin_digest(
            &raven_core::lan_noise_pin::PinKey::derive(&alice()),
            &bob().public_key_bytes(),
            &bob_static,
        );
        for link in [INTERNET_LINK, P2P_LINK] {
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
            let peer = tokio::spawn(async move {
                let secret = derive_noise_static(&mallory()).unwrap();
                let mut hs = build_responder_with_prologue(&secret, link.prologue).unwrap();
                let m1 = read_raw(&mut listener).await.unwrap();
                handshake_read(&mut hs, &m1).unwrap();
                let m2 = handshake_write(&mut hs, &[]).unwrap();
                write_raw(&mut listener, &m2).await.unwrap();
                let mut rest = Vec::new();
                let _ = listener.read_to_end(&mut rest).await;
                rest
            });
            let err = initiator_session_on(
                link,
                &mut dialer,
                &alice(),
                &bob().public_key_bytes(),
                LinkFeatures::NONE,
                Some(&pin),
                None,
            )
            .await
            .err();
            assert_eq!(
                err.as_deref(),
                Some(crate::lan_direct::NOISE_PIN_MISMATCH),
                "{link:?}"
            );
            drop(dialer);
            assert!(peer.await.unwrap().is_empty(), "{link:?}: nothing after m2");

            let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
            let peer = tokio::spawn(async move {
                let (pk, _, mut t, ours, _, _) =
                    responder_handshake(link, &mut listener, &bob(), LinkFeatures::NONE, None)
                        .await
                        .unwrap();
                write_inet_frame(&mut listener, &mut t, &ours)
                    .await
                    .unwrap();
                pk
            });
            let (pk, _, _, remote_static, _) = initiator_session_on(
                link,
                &mut dialer,
                &alice(),
                &bob().public_key_bytes(),
                LinkFeatures::NONE,
                Some(&pin),
                None,
            )
            .await
            .unwrap();
            assert_eq!((pk, remote_static), (bob().public_key_bytes(), bob_static));
            assert_eq!(peer.await.unwrap(), alice().public_key_bytes(), "{link:?}");
        }
    }

    // ── RLK1 link knock (P6.35) ─────────────────────────────────────────

    /// The knock open for this thread; `None` in a release build.
    fn knock_on() -> Option<crate::link_knock::KnockForTest> {
        let on = crate::link_knock::KnockForTest::set(true);
        crate::link_knock::live().then_some(on)
    }

    /// Bob's Internet direct listener with `ear` for one connection: its
    /// dialer's key and what the knock showed.
    fn bob_listens(
        mut listener: tokio::io::DuplexStream,
        ear: Option<Ear>,
    ) -> tokio::task::JoinHandle<Result<([u8; 32], Knocked), String>> {
        tokio::spawn(async move {
            let (pk, _, mut t, ours, _, knocked) = responder_handshake(
                INTERNET_LINK,
                &mut listener,
                &bob(),
                LinkFeatures::NONE,
                ear.as_ref(),
            )
            .await?;
            write_inet_frame(&mut listener, &mut t, &ours).await?;
            Ok((pk, knocked))
        })
    }

    /// RLK1 on Internet direct: Alice knocks twice and gets a fresh static
    /// of Bob's each time (never his derived one) with the proof, and both
    /// hellos verify over the fresh statics; without the knock she sees his
    /// derived static (legacy: her floor lacks the knock). A dialer without
    /// the knock (an older build) reaches a strict listener too (its hello
    /// signs the static it got), with a fresh static each time; a p2p or
    /// nearby listener never reads a knock.
    #[tokio::test]
    async fn knocked_internet_dials_get_a_fresh_listener_static() {
        let Some(_knock) = knock_on() else {
            return;
        };
        let (b_dir, a_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write_contacts_pinned(b_dir.path(), &[&alice()], true);
        let bob_arc = Arc::new(bob());
        let bob_static = noise_static_public(&derive_noise_static(&bob()).unwrap());
        let knock = crate::link_knock::for_dial(
            true,
            false,
            a_dir.path(),
            &alice(),
            &bob().public_key_bytes(),
        )
        .unwrap();
        let mut statics = Vec::new();
        for knocking in [true, true, false] {
            let (mut dialer, listener) = tokio::io::duplex(1 << 17);
            let ear = Ear::of(b_dir.path(), &bob_arc, None, OutboxCarrier::Internet);
            let peer = bob_listens(listener, ear);
            let (pk, _, _, remote_static, knocked) = initiator_session_on(
                INTERNET_LINK,
                &mut dialer,
                &alice(),
                &bob().public_key_bytes(),
                LinkFeatures::NONE,
                None,
                knocking.then_some(&knock),
            )
            .await
            .expect("a knocked Internet link");
            let (dialer_pk, heard) = peer.await.unwrap().unwrap();
            assert_eq!(
                (pk, dialer_pk),
                (bob().public_key_bytes(), alice().public_key_bytes())
            );
            if knocking {
                assert_ne!(remote_static, bob_static);
                assert_eq!(knocked, Some(true));
                assert_eq!(heard, Knocked::Contact(alice().public_key_bytes()));
                statics.push(remote_static);
            } else {
                // Alice's floor lacks the knock: Bob stays legacy, and an
                // older dialer sees his derived static.
                assert_eq!((remote_static, knocked), (bob_static, None));
                assert_eq!(heard, Knocked::Stranger);
            }
        }
        assert_ne!(statics[0], statics[1], "a static per connection");
        let empty = tempfile::tempdir().unwrap();
        let mut strangers = Vec::new();
        for _ in 0..2 {
            let (mut dialer, listener) = tokio::io::duplex(1 << 17);
            let ear = Ear::of(empty.path(), &bob_arc, None, OutboxCarrier::Internet);
            let peer = bob_listens(listener, ear);
            let (_, _, _, remote_static, _) = initiator_session_on(
                INTERNET_LINK,
                &mut dialer,
                &alice(),
                &bob().public_key_bytes(),
                LinkFeatures::NONE,
                None,
                None,
            )
            .await
            .expect("strict mode still answers");
            assert_eq!(peer.await.unwrap().unwrap().1, Knocked::Stranger);
            strangers.push(remote_static);
        }
        assert_ne!(
            strangers[0], strangers[1],
            "strict: a fresh static each time"
        );
        assert!(!strangers.contains(&bob_static));
        for carrier in [OutboxCarrier::P2p, OutboxCarrier::Nearby] {
            assert!(Ear::of(b_dir.path(), &bob_arc, None, carrier).is_none());
        }
    }

    /// Phase 6 review (traffic-1): the Internet direct contact gate takes
    /// verified (pinned) contacts alone (owner decision 2026-10-08), so its
    /// knock book holds them alone. Alice in Bob's contact book but not
    /// verified: her knock gets a stranger's answer (strict: no proof; silent:
    /// no message 2), never the proof that would tell her this address is
    /// Bob's before the gate refuses her. Verified, she gets the proof.
    #[tokio::test]
    async fn an_unverified_contacts_knock_gets_no_internet_proof() {
        let Some(_knock) = knock_on() else {
            return;
        };
        let (b_dir, a_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let bob_arc = Arc::new(bob());
        let knock = crate::link_knock::for_dial(
            true,
            false,
            a_dir.path(),
            &alice(),
            &bob().public_key_bytes(),
        )
        .unwrap();
        let source = Some(IpAddr::from([203, 0, 113, 9]));
        // Message 2's proof, or `Err` when none came; and what Bob heard.
        let knock_once = || async {
            let (mut dialer, listener) = tokio::io::duplex(1 << 17);
            let ear = Ear::of(b_dir.path(), &bob_arc, source, OutboxCarrier::Internet);
            let peer = bob_listens(listener, ear);
            let mut dial = knock.begin(&alice(), Some(INTERNET_LINK.prologue)).unwrap();
            write_raw(&mut dialer, dial.m1()).await.unwrap();
            let proof = match read_raw(&mut dialer).await {
                Ok(m2) => Ok(knock.read_m2(&mut dial, &m2).unwrap().1),
                Err(e) => Err(e),
            };
            drop(dialer);
            (proof, peer.await.unwrap())
        };
        write_contacts_pinned(b_dir.path(), &[&alice()], false);
        let gate = raven_core::lan_dispatch::link_admission(
            b_dir.path(),
            &alice().public_key_bytes(),
            OutboxCarrier::Internet,
            None,
        );
        assert!(gate.is_err(), "the gate refuses her on Internet");
        let (proof, _) = knock_once().await;
        assert_eq!(proof, Ok(false), "strict: a stranger's answer");
        let mut policy = raven_core::node_policy::load_policy(b_dir.path());
        policy.security_silent_to_strangers = raven_core::node_policy::SilentMode::On;
        raven_core::node_policy::save_policy(b_dir.path(), &policy).unwrap();
        let (proof, heard) = knock_once().await;
        assert!(proof.is_err(), "silent: no message 2");
        assert_eq!(heard, Err(crate::link_knock::KNOCK_SILENT.to_string()));
        write_contacts_pinned(b_dir.path(), &[&alice()], true);
        let (proof, _) = knock_once().await;
        assert_eq!(proof, Ok(true), "a verified contact gets the proof");
    }

    /// RLK1 on Internet direct: a knocking dialer at a listener without the
    /// knock goes on with its derived static while the contact's floor
    /// lacks the knock, and stops after message 2 once it has it (no pin):
    /// nothing more reaches that listener.
    #[tokio::test]
    async fn a_knocking_internet_dialer_stops_at_a_known_knockers_address_without_a_proof() {
        let Some(_knock) = knock_on() else {
            return;
        };
        let a_dir = tempfile::tempdir().unwrap();
        let bob_static = noise_static_public(&derive_noise_static(&bob()).unwrap());
        let knock = crate::link_knock::for_dial(
            true,
            false,
            a_dir.path(),
            &alice(),
            &bob().public_key_bytes(),
        )
        .unwrap();
        let (mut dialer, listener) = tokio::io::duplex(1 << 17);
        let peer = bob_listens(listener, None);
        let (_, _, _, remote_static, knocked) = initiator_session_on(
            INTERNET_LINK,
            &mut dialer,
            &alice(),
            &bob().public_key_bytes(),
            LinkFeatures::NONE,
            None,
            Some(&knock),
        )
        .await
        .expect("an older listener, no floor: today's link");
        assert_eq!((remote_static, knocked), (bob_static, Some(false)));
        assert_eq!(peer.await.unwrap().unwrap().1, Knocked::Off);
        let knock = knock.with_floor(true);
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
        let peer = tokio::spawn(async move {
            let secret = derive_noise_static(&bob()).unwrap();
            let mut hs = build_responder_with_prologue(&secret, NOISE_PROLOGUE).unwrap();
            let m1 = read_raw(&mut listener).await.unwrap();
            handshake_read(&mut hs, &m1).unwrap();
            let m2 = handshake_write(&mut hs, &[]).unwrap();
            write_raw(&mut listener, &m2).await.unwrap();
            let mut rest = Vec::new();
            let _ = listener.read_to_end(&mut rest).await;
            rest
        });
        let err = initiator_session_on(
            INTERNET_LINK,
            &mut dialer,
            &alice(),
            &bob().public_key_bytes(),
            LinkFeatures::NONE,
            None,
            Some(&knock),
        )
        .await
        .err();
        assert_eq!(err.as_deref(), Some(crate::lan_direct::NOISE_PIN_MISMATCH));
        drop(dialer);
        assert!(peer.await.unwrap().is_empty(), "nothing after message 2");
    }

    /// RUP1 on an Internet direct link (Phase 6b P6.49, spec §2.2), both
    /// halves as p2p and nearby run them: with the update exchange active at
    /// both ends and each pinned at the other, both hellos carry bit 10, the
    /// listener's HAVE follows its RLB1, the dialer's follows the hellos,
    /// and the dialer's request goes only after the listener's HAVE and is
    /// answered. With the gate shut the request is never sent.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn haves_go_both_ways_and_a_request_follows_the_listeners_have() {
        use raven_core::update_exchange::{self as rup1, ErrorCode, Rup1Msg};
        let lab = ["RAVEN_PREKEY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .all(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !lab {
            eprintln!("skipped: needs the locked-file backends");
            return;
        }
        const WAITS: ReplyWaits = ReplyWaits {
            first: Duration::from_secs(10),
            idle: Duration::from_secs(2),
        };
        let _build =
            crate::update_exchange::BuildForTest::set(crate::update_exchange::test_build());
        // Knocked too (RLK1, P6.35): the HAVEs and the request ride a link
        // whose handshake carried the knock both ways.
        for (gate, knocks) in [(true, false), (false, false), (true, true), (false, true)] {
            crate::update_exchange::gates_for_test(Some(gate));
            let _knock = crate::link_knock::KnockForTest::set(knocks);
            if knocks && !crate::link_knock::live() {
                continue;
            }
            let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let dialer = raven_core::load_or_create_identity(a_dir.path()).unwrap().0;
            let responder = Arc::new(Identity::from_seed(
                &[0x4C + u8::from(gate) + 2 * u8::from(knocks); 32],
            ));
            write_contacts(b_dir.path(), &[&dialer]);
            write_contacts(a_dir.path(), &[&responder]);
            if knocks {
                // Silent to strangers: only a dial whose knock matched gets
                // a message 2, so a link at all proves the knock.
                let mut policy = raven_core::node_policy::load_policy(b_dir.path());
                policy.security_silent_to_strangers = raven_core::node_policy::SilentMode::On;
                raven_core::node_policy::save_policy(b_dir.path(), &policy).unwrap();
            }
            let (client, server_side) = tokio::io::duplex(1 << 18);
            let (data_dir, resp) = (b_dir.path().to_path_buf(), responder.clone());
            let server = tokio::spawn(async move {
                let mut slot = test_slot();
                serve_inbound(data_dir, resp, server_side, PRODUCTION_LIMITS, &mut slot).await
            });
            let ask = rup1::encode(&[5, 6, 7, 8], &Rup1Msg::GetLog).unwrap();
            let mut stream = Some(client);
            let mut progress = DialProgress::new("INTERNET", WAITS);
            let got = tokio::time::timeout(
                Duration::from_secs(20),
                dial_session_on(
                    INTERNET_LINK,
                    a_dir.path(),
                    || {
                        let s = stream.take();
                        async move { s.ok_or_else(|| "one stream only".to_string()) }
                    },
                    &responder.public_key_bytes(),
                    std::slice::from_ref(&ask),
                    None,
                    &mut progress,
                ),
            )
            .await
            .expect("the dial ends");
            if gate {
                got.unwrap();
                let replies = progress.collector.into_replies();
                assert_eq!(replies.len(), 2, "the RLB1 offer and one answer");
                assert_eq!(
                    rup1::decode(&replies[1]),
                    Ok(([5, 6, 7, 8], Rup1Msg::Error(ErrorCode::NotFound)))
                );
                assert!(crate::update_exchange::have_seen_for_test(
                    &responder.public_key_bytes()
                ));
            } else {
                assert_eq!(got.unwrap_err(), crate::update_exchange::NOT_SPOKEN);
            }
            let _ = tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("the listener ends");
            assert_eq!(
                crate::update_exchange::have_seen_for_test(&dialer.public_key_bytes()),
                gate,
                "the listener took the dialer's HAVE only with the gate open"
            );
        }
        crate::update_exchange::gates_for_test(None);
    }
}
