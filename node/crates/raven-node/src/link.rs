//! One Raven link's frame cipher (Phase 6b step P6.34, design B §2): the
//! Noise transport of a LAN, Internet direct, p2p or nearby link and PAD1
//! link padding on it (`protocol/RAVEN_LINK_PADDING_V1.md`,
//! [`raven_core::link_padding`]).
//!
//! Every frame a link sends after its handshake goes through
//! [`LinkCipher::seal`] and every frame it reads through
//! [`LinkCipher::open`]; the link code keeps its own framing
//! (`u32_be(len) || message`), limits and deadlines (`lan_direct`'s
//! `write_cipher` / `read_cipher`, `internet_direct`'s `write_inet_frame` /
//! `read_inet_frame`; p2p and nearby run the Internet-direct link).
//!
//! - **Offered** only while link padding is live ([`padding_live`]:
//!   `LINK_PADDING_PRODUCTION_ENABLED`, or a debug build's
//!   `RAVEN_LAB_LINK_PADDING=1` with `RAVEN_LAB_TEST_A=1`). With it shut
//!   every link is [`PadState::OFF`], no hello or message 3 carries bit 9,
//!   and every byte after the handshake is what earlier builds send.
//! - **Internet direct, p2p, nearby:** caps bit 9 in the signed hello
//!   ([`offers`]); when both verified hellos carry it, each side wraps every
//!   frame after the hellos (the hellos never).
//! - **LAN:** the dialer's RLX1 `LINK_CAPS` carries bit 9 only on a dial
//!   that reads (the RRH1 rule, `crate::hints::lan_m3_payload`). The
//!   listener wraps from its bind on; the dialer reads RPD1 from the start
//!   and wraps once the listener's first RPD1 frame arrived, which its
//!   capability floor keeps as `Seen(CAP_LINK_PAD1)`.
//! - **Refusals:** a frame that breaks PAD1 (spec §6, a bare frame after
//!   the peer's first RPD1 one included) ends the link with
//!   [`PAD1_REFUSED`]; once the link knows its contact that is
//!   `SEC_CONTACT_MALFORMED` about it (`crate::security::inbound_link_error`,
//!   `dial_link_error`). A frame a padding side cannot wrap (longer than
//!   65,511 bytes) is never sent bare: [`PAD1_UNSENDABLE`].

use raven_core::internet::LinkFeatures;
use raven_core::lan_noise::{transport_encrypt, NoiseTransport};
use raven_core::link_padding::{Pad1Error, PadState};
use raven_core::security_gate::{self, SecGate};
use raven_core::OutboxCarrier;

use crate::netutil;

/// The start of the error of a frame that broke PAD1 (the code follows):
/// the link ends, and [`is_pad_refusal`] tells the security events.
pub(crate) const PAD1_REFUSED: &str = "link padding refused";
/// The start of the error of a frame this side cannot pad (the code
/// follows): it was not sent.
pub(crate) const PAD1_UNSENDABLE: &str = "link padding: frame cannot be padded, not sent";

/// PAD1 link padding is live in this process (design B, `SecGate::LinkPadding`).
pub(crate) fn padding_live() -> bool {
    security_gate::live(SecGate::LinkPadding)
}

/// Link padding open (`Some(true)`) or shut for the current thread until
/// dropped (`SecGate::LinkPadding`'s lab override; a `#[tokio::test]` runs
/// both ends of a scripted link on that thread). A release build ignores it:
/// a caller checks [`padding_live`] after setting it.
#[cfg(test)]
pub(crate) struct PaddingForTest;

#[cfg(test)]
impl PaddingForTest {
    pub(crate) fn set(on: bool) -> Self {
        security_gate::set_lab_for_this_thread(SecGate::LinkPadding, Some(on));
        Self
    }
}

#[cfg(test)]
impl Drop for PaddingForTest {
    fn drop(&mut self) {
        security_gate::set_lab_for_this_thread(SecGate::LinkPadding, None);
    }
}

/// The link features this side offers on a link of `carrier`: RRH1 while
/// route hints are live on it ([`crate::hints::live_on`]), PAD1 while link
/// padding is ([`padding_live`]), RUP1 while the update exchange is active
/// (Phase 6b P6.49, [`crate::update_exchange::offered`]). A LAN dialer
/// offers them only on a dial that reads.
pub(crate) fn offers(carrier: OutboxCarrier) -> LinkFeatures {
    LinkFeatures::NONE
        .with(LinkFeatures::RRH1, crate::hints::live_on(carrier))
        .with(LinkFeatures::PAD1, padding_live())
        .with(LinkFeatures::RUP1, crate::update_exchange::offered())
}

/// Did a link end because the peer broke PAD1 ([`PAD1_REFUSED`])?
pub(crate) fn is_pad_refusal(error: &str) -> bool {
    error.starts_with(PAD1_REFUSED)
}

fn refused(e: Pad1Error) -> String {
    format!("{PAD1_REFUSED} ({})", e.code())
}

/// The Noise transport of one link and PAD1 on it.
pub(crate) struct LinkCipher {
    pub(crate) transport: NoiseTransport,
    /// PAD1 on this link, this side ([`PadState`]): [`PadState::OFF`] until
    /// the link knows the peer's offer, and for good when either side did
    /// not offer it.
    pub(crate) pad: PadState,
}

/// Never the transport's keys: only what PAD1 does on the link.
impl std::fmt::Debug for LinkCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkCipher")
            .field("pad", &self.pad)
            .finish_non_exhaustive()
    }
}

impl LinkCipher {
    /// A transport fresh from its handshake, without padding yet.
    pub(crate) fn new(transport: NoiseTransport) -> Self {
        Self::with_pad(transport, PadState::OFF)
    }

    /// A transport fresh from its handshake whose PAD1 side is known already
    /// (the LAN dialer's, from its own message 3).
    pub(crate) fn with_pad(transport: NoiseTransport, pad: PadState) -> Self {
        Self { transport, pad }
    }

    /// The Noise transport message of the link frame `frame`: padded first
    /// when this side wraps.
    pub(crate) fn seal(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let wire = self
            .pad
            .on_send(frame)
            .map_err(|e| format!("{PAD1_UNSENDABLE} ({})", e.code()))?;
        transport_encrypt(&mut self.transport, &wire).map_err(|e| e.to_string())
    }

    /// The link frame in the Noise transport message `ct`: decrypted (a tag
    /// that fails is `netutil::LINK_TAG_FAILED`), then unwrapped when the
    /// peer padded it.
    pub(crate) fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>, String> {
        let plain = netutil::decrypt(&mut self.transport, ct)?;
        let inner = self.pad.on_recv(&plain).map_err(refused)?;
        // An unwrapped frame is always shorter than its RPD1 frame.
        if inner.len() == plain.len() {
            return Ok(plain);
        }
        Ok(inner.to_vec())
    }
}

/// What a link puts on the wire, for the tests of every link that pads
/// (P6.34): a stream that records the bytes passing it each way, and the
/// `u32_be(len)`-framed message lengths in them.
#[cfg(test)]
pub(crate) mod wire {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use raven_core::link_padding::PAD1_BUCKETS;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// `inner`, recording what this end writes (`sent`) and reads
    /// (`received`).
    pub(crate) struct Tap<S> {
        inner: S,
        pub(crate) sent: Log,
        pub(crate) received: Log,
    }

    /// Where a [`Tap`] records one direction.
    pub(crate) type Log = Arc<Mutex<Vec<u8>>>;

    impl<S> Tap<S> {
        pub(crate) fn new(inner: S) -> Self {
            Self::with_logs(inner, Log::default(), Log::default())
        }

        /// A tap that records into logs the caller already holds (a stream
        /// handed on by value).
        pub(crate) fn with_logs(inner: S, sent: Log, received: Log) -> Self {
            Self {
                inner,
                sent,
                received,
            }
        }

        /// The message lengths this end wrote and read so far.
        pub(crate) fn lengths(&self) -> (Vec<usize>, Vec<usize>) {
            (
                lengths(&self.sent.lock().unwrap()),
                lengths(&self.received.lock().unwrap()),
            )
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            let done = Pin::new(&mut self.inner).poll_read(cx, buf);
            if let Poll::Ready(Ok(())) = done {
                let fresh = &buf.filled()[before..];
                self.received.lock().unwrap().extend_from_slice(fresh);
            }
            done
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let done = Pin::new(&mut self.inner).poll_write(cx, buf);
            if let Poll::Ready(Ok(n)) = done {
                self.sent.lock().unwrap().extend_from_slice(&buf[..n]);
            }
            done
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// The lengths of the `u32_be(len) || message` messages in `bytes`
    /// (a cut last one left out).
    pub(crate) fn lengths(bytes: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while let Some(head) = rest.get(..4) {
            let n = u32::from_be_bytes(head.try_into().unwrap()) as usize;
            if rest.len() < 4 + n {
                break;
            }
            out.push(n);
            rest = &rest[4 + n..];
        }
        out
    }

    /// A Noise transport message of a padded frame: a bucket and the tag.
    pub(crate) fn is_padded(len: usize) -> bool {
        PAD1_BUCKETS.iter().any(|b| b + 16 == len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::lan_noise::{handshake_pair, MAX_TRANSPORT_PLAINTEXT};
    use raven_core::link_padding::{PAD1_BUCKETS, PAD1_MAX_INNER};
    use raven_core::Identity;

    /// Two ends of one link (XX in memory), each with its PAD1 side.
    fn ciphers(a: PadState, b: PadState) -> (LinkCipher, LinkCipher) {
        let (x, y, _, _) = handshake_pair(
            &Identity::from_seed(&[0xA1; 32]),
            &Identity::from_seed(&[0xB2; 32]),
        )
        .unwrap();
        (LinkCipher::with_pad(x, a), LinkCipher::with_pad(y, b))
    }

    /// Frames of each kind a link carries: an RRH1, an RFC1 request and a
    /// short and a long envelope-like frame.
    fn frames() -> Vec<Vec<u8>> {
        use raven_core::friend_custody::{encode_request, Rfc1Request};
        let rrh1 = raven_core::route_hints::encode(&raven_core::route_hints::RouteHints {
            generation: 7,
            ttl_s: 3600,
            lan_port: Some(7431),
            ..Default::default()
        });
        let rfc1 = encode_request(
            &[0xC0, 0, 0, 0, 0, 0, 0, 1],
            &Rfc1Request::Fetch {
                tags: vec![[0x11; 16]],
                after: None,
                max_items: 4,
            },
        );
        assert!(raven_core::friend_custody::is_rfc1(&rfc1));
        vec![rrh1, rfc1, vec![0x5a; 293], vec![0x6b; 20_000]]
    }

    /// Gate off (both [`PadState::OFF`]): every frame goes out as it is,
    /// one Noise message of its length plus the tag, as before PAD1.
    #[test]
    fn off_is_the_frame_plus_its_tag() {
        let (mut a, mut b) = ciphers(PadState::OFF, PadState::OFF);
        for f in frames() {
            let ct = a.seal(&f).unwrap();
            assert_eq!(ct.len(), f.len() + 16);
            assert_eq!(b.open(&ct).unwrap(), f);
        }
    }

    /// Both offered: every frame is a bucket on the wire, RRH1 and RFC1
    /// included, and comes out as it went in.
    #[test]
    fn agreed_frames_are_buckets_and_unwrap() {
        let (mut a, mut b) = ciphers(PadState::agreed(true), PadState::agreed(true));
        for f in frames() {
            let ct = a.seal(&f).unwrap();
            assert!(PAD1_BUCKETS.contains(&(ct.len() - 16)), "{}", ct.len());
            assert_eq!(b.open(&ct).unwrap(), f);
            let back = b.seal(&f).unwrap();
            assert_eq!(back.len(), ct.len());
            assert_eq!(a.open(&back).unwrap(), f);
        }
        assert!(a.pad.peer_started() && b.pad.peer_started());
    }

    /// The LAN dialer: bare until the listener's first RPD1 frame, padded
    /// after it; the listener reads the dialer's bare bind first.
    #[test]
    fn the_lan_dialer_wraps_after_the_listeners_first_rpd1_frame() {
        let (mut dialer, mut listener) =
            ciphers(PadState::lan_dialer(true), PadState::agreed(true));
        let bind = vec![0x42; 96];
        let ct = dialer.seal(&bind).unwrap();
        assert_eq!(ct.len(), 96 + 16, "the bind is bare");
        assert_eq!(listener.open(&ct).unwrap(), bind);
        let ct = listener.seal(&bind).unwrap();
        assert_eq!(ct.len(), 512 + 16, "the listener's bind is padded");
        assert!(!dialer.pad.negotiated());
        assert_eq!(dialer.open(&ct).unwrap(), bind);
        assert!(dialer.pad.peer_started() && dialer.pad.negotiated());
        let offer = vec![0x52; 2_000];
        let ct = dialer.seal(&offer).unwrap();
        assert_eq!(ct.len(), 4_096 + 16);
        assert_eq!(listener.open(&ct).unwrap(), offer);
        // A listener that never pads: the dialer never does.
        let (mut dialer, mut old) = ciphers(PadState::lan_dialer(true), PadState::OFF);
        for f in frames() {
            let ct = old.seal(&f).unwrap();
            assert_eq!(dialer.open(&ct).unwrap(), f);
            assert_eq!(dialer.seal(&f).unwrap().len(), f.len() + 16);
        }
    }

    /// A peer that stops padding mid-link: its bare frame is refused, and
    /// the error is one the security events recognise.
    #[test]
    fn a_bare_frame_after_rpd1_is_refused() {
        let (mut a, mut b) = ciphers(PadState::agreed(true), PadState::agreed(true));
        let ct = a.seal(b"first").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"first");
        a.pad = PadState::OFF;
        let ct = a.seal(b"second").unwrap();
        let err = b.open(&ct).unwrap_err();
        assert_eq!(err, "link padding refused (UNPADDED)");
        assert!(is_pad_refusal(&err));
        assert!(!is_pad_refusal(netutil::LINK_TAG_FAILED));
        // A malformed RPD1 frame: refused by its rule.
        let (mut a, mut b) = ciphers(PadState::OFF, PadState::agreed(true));
        let mut frame = raven_core::link_padding::wrap(b"inner").unwrap();
        frame[511] = 1;
        let err = b.open(&a.seal(&frame).unwrap()).unwrap_err();
        assert_eq!(err, "link padding refused (NONZERO_PADDING)");
    }

    /// A side that did not offer PAD1 hands an RPD1 frame on as it is (the
    /// link's handling of a frame it does not know closes it, as before).
    #[test]
    fn an_off_side_passes_rpd1_through() {
        let (mut a, mut b) = ciphers(PadState::agreed(true), PadState::OFF);
        let ct = a.seal(b"hello").unwrap();
        let got = b.open(&ct).unwrap();
        assert_eq!(got.len(), 512);
        assert!(got.starts_with(raven_core::link_padding::PAD1_MAGIC));
    }

    /// The longest frame a padded link sends is 65,511 bytes (spec §5); a
    /// longer one (today's links carry up to 65,519) is not sent at all.
    #[test]
    fn a_frame_too_long_to_pad_is_not_sent() {
        let (mut a, mut b) = ciphers(PadState::agreed(true), PadState::agreed(true));
        let max = vec![0x7e; PAD1_MAX_INNER];
        let ct = a.seal(&max).unwrap();
        assert_eq!(ct.len(), MAX_TRANSPORT_PLAINTEXT + 16);
        assert_eq!(b.open(&ct).unwrap(), max);
        let err = a.seal(&vec![0x7e; PAD1_MAX_INNER + 1]).unwrap_err();
        assert_eq!(
            err,
            "link padding: frame cannot be padded, not sent (BAD_LENGTH)"
        );
        assert!(!is_pad_refusal(&err));
        // Unpadded, the same frame goes as before.
        let (mut a, _) = ciphers(PadState::OFF, PadState::OFF);
        assert!(a.seal(&vec![0x7e; MAX_TRANSPORT_PLAINTEXT]).is_ok());
    }

    /// The offer follows the gate: PAD1 only while padding is live (this
    /// thread's lab override), never in a release build.
    #[test]
    fn offers_pad1_only_while_padding_is_live() {
        security_gate::set_lab_for_this_thread(SecGate::LinkPadding, Some(false));
        assert!(!offers(OutboxCarrier::Internet).contains(LinkFeatures::PAD1));
        assert!(!padding_live());
        security_gate::set_lab_for_this_thread(SecGate::LinkPadding, Some(true));
        assert_eq!(padding_live(), cfg!(debug_assertions));
        for carrier in [
            OutboxCarrier::Lan,
            OutboxCarrier::Internet,
            OutboxCarrier::P2p,
            OutboxCarrier::Nearby,
        ] {
            assert_eq!(
                offers(carrier).contains(LinkFeatures::PAD1),
                cfg!(debug_assertions)
            );
        }
        security_gate::set_lab_for_this_thread(SecGate::LinkPadding, None);
    }

    /// `RAVEN_LAB_LINK_PADDING` (with `RAVEN_LAB_TEST_A`) is inert in a
    /// release build: no link offers PAD1 (the release test job sets every
    /// switch and runs this; a debug build returns early).
    #[test]
    fn link_padding_lab_switch_is_inert_in_release() {
        if cfg!(debug_assertions) {
            return;
        }
        const { assert!(!raven_core::security_gate::LINK_PADDING_PRODUCTION_ENABLED) };
        assert!(!padding_live());
        security_gate::set_lab_for_this_thread(SecGate::LinkPadding, Some(true));
        assert!(!padding_live());
        assert!(!offers(OutboxCarrier::Lan).contains(LinkFeatures::PAD1));
        security_gate::set_lab_for_this_thread(SecGate::LinkPadding, None);
    }
}
