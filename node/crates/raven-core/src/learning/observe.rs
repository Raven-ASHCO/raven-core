//! The observation record and its classifier (design "Phase 6a", data model
//! `Observation` and the evidence table of algorithms §2): what one dial
//! taught about one route to one contact.
//!
//! - [`FrameKind::of`] names what a dial carried: nothing (a probe), custody
//!   (RFC1), a message, only ACKs, or control frames (session reset, a
//!   bundle offer, pairing, gossip).
//! - [`evidence`] turns the dial's result into [`Evidence`]: a receipt (E1)
//!   only when a message dial got an ACK back (one is enough), a link (E2)
//!   for any other authenticated dial, silence (E3) when message frames went
//!   out and no ACK came, a weighted failure (E4) by the dial's stable code
//!   or Phase 2 `why=` token ([`weight_m`]), and no evidence at all (E0) for
//!   holds, local errors and a network change during the dial.
//! - [`Observation`] lives in memory only and is never persisted raw: the
//!   model hashes the contact, network tag and relay before keeping
//!   anything, and its `Debug` prints none of them.
//!
//! Pure: no I/O and no clock read (`at_ms` comes from `raven_core::clock` at
//! the caller), integers only.

use crate::envelope::{EnvType, Envelope};
use crate::outbox::{ack_frames, DeliveryPath, OutboxCarrier};
use crate::pair_init_lan_oob::{classify_message_ciphertext, PairInitOobClassify};

/// E1: a message frame answered by an ACK on the authenticated link.
pub const RECEIPT_W_M: u32 = 1_000;
/// E2 (`PROBE_W`): an authenticated link without a message frame. OD6a-2
/// option (a); 0 would be the strict option (b).
pub const PROBE_W_M: u32 = 500;
/// E3: message frames written and no ACK before the reply wait ended.
pub const SILENT_W_M: u32 = 500;
/// E4 for a code with no row: a failure that says nothing more counts in
/// full (conservative).
pub const FULL_FAIL_W_M: u32 = 1_000;
/// The code a failure without a known code is recorded under (the dial
/// codes' own fallback, raven-node `dial_error_code`).
pub const DIAL_FAILED: &str = "DIAL_FAILED";

/// E4, the design table by string value: a stable dial code (raven-node
/// `outbox::code`) or a Phase 2 reason token (`reach_diag::Why::token`), and
/// its failure weight in milli-observations.
pub const FAIL_WEIGHTS: &[(&str, u32)] = &[
    // The contact is absent, not the route.
    ("NOT_LISTENING", 250),
    ("contact_offline", 250),
    // Phase 3 LAN reason: no contact answered the beacon on this network.
    // It cannot tell a contact that is away from a network that keeps
    // devices apart, so it takes the soft row.
    ("lan_no_answer", 250),
    ("CLOSED_EARLY", 500),
    ("PEER_REFUSED", 500),
    ("relay_busy", 500),
    // What the worker records after a silent message dial: the E3 weight.
    ("NO_ACK_YET", SILENT_W_M),
    // NOT_REACHABLE covers the connect and handshake timeouts.
    ("NOT_REACHABLE", FULL_FAIL_W_M),
    (DIAL_FAILED, FULL_FAIL_W_M),
    ("WRONG_IDENTITY", FULL_FAIL_W_M),
    ("LINK_NOT_ACCEPTED", FULL_FAIL_W_M),
    ("relay_asleep", FULL_FAIL_W_M),
    ("relay_refused", FULL_FAIL_W_M),
    ("relay_off", FULL_FAIL_W_M),
    ("not_admitted", FULL_FAIL_W_M),
    ("both_nat", FULL_FAIL_W_M),
    ("no_relay", FULL_FAIL_W_M),
    ("direct_failed", FULL_FAIL_W_M),
    // This computer has no default route: the route from this network
    // (the arm's network bucket) does not exist.
    ("no_route", FULL_FAIL_W_M),
];

/// E0, not evidence: a gate or hold, a lock, a local error or a fate of the
/// object that says nothing about the route ([`weight_m`] is `None`).
pub const NOT_EVIDENCE: &[&str] = &[
    // The design's E0 row ("lock busy": the send lock was held by another
    // attempt, today reported as SEND_IN_PROGRESS).
    "INTERNET_HOLD",
    "P2P_HOLD",
    "P2P_NOT_RUNNING",
    "CONTACT_BLOCKED",
    "SEND_IN_PROGRESS",
    "IPC_BAD_B64",
    "CUSTODY_IPC_REFUSED",
    "NEARBY_NOT_IN_RANGE",
    // In Bluetooth range, but every nearby link (this node's or the
    // contact's) is in use now (Phase 5 review nearby-6): as
    // NEARBY_NOT_IN_RANGE, a moment's capacity, not the route.
    "NEARBY_BUSY",
    "LOCK_BUSY",
    // The nearby carrier's hold and service, as P2P_HOLD and P2P_NOT_RUNNING.
    "NEARBY_HOLD",
    "NEARBY_NOT_RUNNING",
    // Held before any dial: `raven lan verified-only on`, `raven lan off`.
    "CONTACT_NOT_VERIFIED",
    "lan_off",
    // This node's own state: nothing was dialled, or the dial is not the
    // cause (raven-node `outbox::code`).
    "LOCK",
    "PIN_STORE_UNREADABLE",
    "NOT_A_CONTACT",
    "CONTACTS_UNREADABLE",
    "NO_ROUTE",
    "DEFERRED",
    "LOCAL_DEVICE",
    "LOCAL_DEVICE_REVOKED",
    "PEER_REVOKED",
    "NO_PEER_CERT",
    "NO_LOCAL_BODY",
    "HISTORY",
    "CLOCK",
    "STORE",
    "STAGE",
    // The object's fate, decided after a link: session reset, superseded,
    // expired, friend custody status.
    "SUPERSEDED",
    "EXPIRED",
    "PEER_RESET",
    "PEER_RESET_NO_BODY",
    "RESEAL_CAP",
    "IN_CUSTODY",
    "NO_SHARED_CUSTODIAN",
    "CUSTODIAN_NOT_OFFERING",
    "MAILBOX_OFF",
    // Sealed letters (Phase 5 P5.15, `letter_deposits::code`): status only,
    // as the friend custody codes.
    "WAITING_FOR_CARRIER",
    "CARRIER_FULL",
    "NO_SHARED_CARRIER",
    // The user paused sending to the contact (Phase 6b P6.31, "Pause
    // sending"): a hold, nothing was dialled.
    "SENDING_PAUSED",
    // The Tor onion carrier (lab): never ranked or learned; its hold, a
    // helper not ready yet, and a contact's onion service that did not
    // answer over Tor say nothing about the other carriers' routes.
    "ONION_HOLD",
    "ONION_NOT_READY",
    "ONION_UNREACHABLE",
];

/// What a dial carried (design data model), from its frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameKind {
    /// No frame: a probe of the route.
    Probe,
    /// Only ACK envelopes (owed ACKs pushed back).
    AckOnly,
    /// At least one message envelope.
    Message,
    /// At least one friend custody (RFC1) frame.
    Custody,
    /// Anything else: a session reset query (RSR1), a bundle offer (RLB1),
    /// a pairing envelope, gossip or capabilities.
    Control,
}

impl FrameKind {
    /// No frame is a probe; any RFC1 frame is custody (the rule
    /// `delivery_paths` uses); any message envelope that is not a wrapped
    /// PairInit or PairResponse is a message; only ACK envelopes are
    /// AckOnly; anything else is control.
    pub fn of(frames: &[Vec<u8>]) -> Self {
        if frames.is_empty() {
            return Self::Probe;
        }
        if frames.iter().any(|f| crate::friend_custody::is_rfc1(f)) {
            return Self::Custody;
        }
        let mut acks_only = true;
        for frame in frames {
            match Envelope::unpack(frame) {
                Some(env) if env.env_type == EnvType::Message as u8 => {
                    // A pairing exchange rides a message envelope but is
                    // answered by a PairResponse, never an ACK.
                    if matches!(
                        classify_message_ciphertext(&env.message_ciphertext),
                        PairInitOobClassify::NotPairInitOob
                    ) {
                        return Self::Message;
                    }
                    acks_only = false;
                }
                Some(env) if env.env_type == EnvType::Ack as u8 => {}
                _ => acks_only = false,
            }
        }
        if acks_only {
            Self::AckOnly
        } else {
            Self::Control
        }
    }
}

/// What one dial says about its route (design data model).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// E1: message frame(s) and an ACK reply on the authenticated link.
    Receipt,
    /// E2: an authenticated link without a message frame (probe, ACK push,
    /// announce, custody, control, app probe).
    Link,
    /// E3: message frames written, no ACK before the reply wait ended.
    Silent,
    /// E4: the dial failed; `code` is the table's string and `weight_milli`
    /// its weight ([`FAIL_WEIGHTS`], [`FULL_FAIL_W_M`] without a row).
    Fail {
        code: &'static str,
        weight_milli: u32,
    },
    /// E0: not evidence (a gate, a lock, a local error, a network change
    /// during the dial, a nearby contact out of range).
    None,
}

/// What [`Evidence`] does to an arm's success estimate, in
/// milli-observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Weight {
    Success(u32),
    Failure(u32),
}

impl Evidence {
    /// The design's `weight()`: a receipt [`RECEIPT_W_M`], a link
    /// [`PROBE_W_M`], silence [`SILENT_W_M`], a failure its own weight; E0
    /// is `None`.
    pub fn weight(self) -> Option<Weight> {
        match self {
            Self::Receipt => Some(Weight::Success(RECEIPT_W_M)),
            Self::Link => Some(Weight::Success(PROBE_W_M)),
            Self::Silent => Some(Weight::Failure(SILENT_W_M)),
            Self::Fail { weight_milli, .. } => Some(Weight::Failure(weight_milli)),
            Self::None => None,
        }
    }
}

/// The dial's times in ms: `connect_ms` from the start until the peer's
/// offer was read, `reply_ms` from the frames being sent until the first
/// terminal reply, `total_ms` the whole dial.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialTiming {
    pub connect_ms: Option<u32>,
    pub reply_ms: Option<u32>,
    pub total_ms: u32,
}

/// One dial's outcome on one route (design data model). Memory only, never
/// persisted raw; `Debug` prints neither the contact, the network tag nor
/// the relay.
#[derive(Clone, PartialEq, Eq)]
pub struct Observation {
    /// The key the dial expected (hashed before it enters the model).
    pub contact: [u8; 32],
    /// The network tag when the dial started (`None`: the "none" bucket).
    pub net: Option<String>,
    /// The tag at the end differed from `net`: [`Evidence::None`].
    pub net_changed: bool,
    pub carrier: OutboxCarrier,
    pub path: Option<DeliveryPath>,
    /// The relay's PeerId bytes when `path` is relayed.
    pub relay: Option<Vec<u8>>,
    pub kind: FrameKind,
    pub evidence: Evidence,
    pub timing: DialTiming,
    /// A resend of an object that went silent before: no reply-time
    /// sample (Karn).
    pub karn_exclude: bool,
    /// `raven_core::clock::now_ms()` at the caller.
    pub at_ms: u64,
}

impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        /// Stands in for a value `Debug` must not print.
        struct Hidden;
        impl std::fmt::Debug for Hidden {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("..")
            }
        }
        f.debug_struct("Observation")
            .field("contact", &Hidden)
            .field("net", &self.net.as_ref().map(|_| Hidden))
            .field("net_changed", &self.net_changed)
            .field("carrier", &self.carrier)
            .field("path", &self.path)
            .field("relay", &self.relay.as_ref().map(|_| Hidden))
            .field("kind", &self.kind)
            .field("evidence", &self.evidence)
            .field("timing", &self.timing)
            .field("karn_exclude", &self.karn_exclude)
            .field("at_ms", &self.at_ms)
            .finish()
    }
}

/// The table's row for `code`: `Some((code, Some(w)))` a failure of weight
/// `w`, `Some((code, None))` E0, `None` no row.
fn row(code: &str) -> Option<(&'static str, Option<u32>)> {
    if let Some(&(c, w)) = FAIL_WEIGHTS.iter().find(|(c, _)| *c == code) {
        return Some((c, Some(w)));
    }
    NOT_EVIDENCE
        .iter()
        .find(|c| **c == code)
        .map(|&c| (c, None))
}

/// Does the table name `code` (a weight or E0)? Exact string match: a
/// dial code is upper case, a `why=` token lower case.
pub fn known_code(code: &str) -> bool {
    row(code).is_some()
}

/// The failure weight of `code` in milli-observations; `None` is E0 (not
/// evidence). A code without a row is a full failure ([`FULL_FAIL_W_M`]).
pub fn weight_m(code: &str) -> Option<u32> {
    match row(code) {
        Some((_, w)) => w,
        None => Some(FULL_FAIL_W_M),
    }
}

/// The evidence of one dial (design §2).
///
/// - `ok_replies`: `Some(replies)` when the dial returned Ok, including the
///   replies collected so far when the dial's deadline fired after the
///   frames were written.
/// - `frames_sent`: the dial wrote its frames.
/// - `code`: for an Err, the stable dial code (raven-node `dial_error_code`)
///   or the Phase 2 `why=` token when the p2p reason block is present; `None`
///   counts as [`DIAL_FAILED`]. Ignored for an Ok.
/// - `net_changed`: the network tag moved during the dial, so nothing is
///   learned ([`Evidence::None`]).
///
/// A message dial is a receipt when at least one reply is an ACK
/// (`outbox::ack_frames`; the worker checks which message it confirms),
/// silent when its frames went out and no ACK came. Any other Ok dial is a
/// link: custody dials are link evidence for the custodian's route, never
/// a receipt.
pub fn evidence(
    kind: FrameKind,
    ok_replies: Option<&[Vec<u8>]>,
    frames_sent: bool,
    code: Option<&str>,
    net_changed: bool,
) -> Evidence {
    if net_changed {
        return Evidence::None;
    }
    let Some(replies) = ok_replies else {
        return match row(code.unwrap_or(DIAL_FAILED)) {
            Some((code, Some(weight_milli))) => Evidence::Fail { code, weight_milli },
            Some((_, None)) => Evidence::None,
            None => Evidence::Fail {
                code: DIAL_FAILED,
                weight_milli: FULL_FAIL_W_M,
            },
        };
    };
    if kind != FrameKind::Message {
        return Evidence::Link;
    }
    if !ack_frames(replies).is_empty() {
        Evidence::Receipt
    } else if frames_sent {
        Evidence::Silent
    } else {
        // Ok without writing a message frame: only the link is known.
        Evidence::Link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::friend_custody::{encode_request, Rfc1Request};
    use crate::pair_init::{INIT_MAGIC, INIT_WIRE_LEN, RESPONSE_MAGIC, RESPONSE_WIRE_LEN};
    use crate::reach_diag::Why;
    use crate::session_reset::{RSR1_MAGIC, RSR1_VERSION};

    fn env(kind: u8, body: Vec<u8>) -> Vec<u8> {
        Envelope {
            env_type: kind,
            flags: 0,
            message_id: [0x11; 16],
            routing_tag: [0x22; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at: 2,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [0x33; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: body,
            sender_authentication: vec![0u8; 64],
        }
        .pack()
    }

    fn message() -> Vec<u8> {
        env(EnvType::Message as u8, vec![0x44; 32])
    }

    fn ack() -> Vec<u8> {
        env(EnvType::Ack as u8, vec![0x55; 32])
    }

    /// A wrapped PairInit or PairResponse (the classifier sniffs the magic).
    fn pairing(magic: [u8; 8], len: usize) -> Vec<u8> {
        let mut wire = magic.to_vec();
        wire.resize(len, 0);
        env(EnvType::Message as u8, wire)
    }

    fn rfc1() -> Vec<u8> {
        encode_request(
            &[7; 8],
            &Rfc1Request::Release {
                digests: vec![[9; 32]],
            },
        )
    }

    fn rsr1_query() -> Vec<u8> {
        let mut q = RSR1_MAGIC.to_vec();
        q.extend([RSR1_VERSION, 1]);
        q.resize(78, 0);
        q
    }

    #[test]
    fn frame_kind_table() {
        let (m, a) = (message(), ack());
        let gossip = env(EnvType::AliasGossip as u8, vec![1; 8]);
        let caps = env(EnvType::Capabilities as u8, vec![2; 8]);
        let init = pairing(INIT_MAGIC, INIT_WIRE_LEN);
        let response = pairing(RESPONSE_MAGIC, RESPONSE_WIRE_LEN);
        let (custody, query) = (rfc1(), rsr1_query());
        assert!(crate::friend_custody::frame_expects_reply(&custody));
        assert!(crate::session_reset::frame_expects_reply(&query));
        // A pairing body of the wrong length is an ordinary message.
        let short_init = pairing(INIT_MAGIC, INIT_WIRE_LEN - 1);
        let offer = b"RLB1junk".to_vec();
        let rows: Vec<(Vec<Vec<u8>>, FrameKind)> = vec![
            (vec![], FrameKind::Probe),
            (vec![m.clone()], FrameKind::Message),
            (vec![m.clone(), a.clone()], FrameKind::Message),
            (vec![a.clone(), m.clone()], FrameKind::Message),
            (vec![query.clone(), m.clone()], FrameKind::Message),
            (vec![a.clone()], FrameKind::AckOnly),
            (vec![a.clone(), a.clone()], FrameKind::AckOnly),
            (vec![custody.clone()], FrameKind::Custody),
            (vec![m.clone(), custody.clone()], FrameKind::Custody),
            (vec![a.clone(), custody], FrameKind::Custody),
            (vec![query.clone()], FrameKind::Control),
            (vec![a.clone(), query], FrameKind::Control),
            (vec![offer.clone()], FrameKind::Control),
            (vec![gossip], FrameKind::Control),
            (vec![caps], FrameKind::Control),
            (vec![init.clone()], FrameKind::Control),
            (vec![response], FrameKind::Control),
            (vec![init.clone(), a.clone()], FrameKind::Control),
            (vec![init, m.clone()], FrameKind::Message),
            (vec![short_init], FrameKind::Message),
            (vec![vec![]], FrameKind::Control),
            (vec![b"junk".to_vec()], FrameKind::Control),
            (vec![a, offer], FrameKind::Control),
        ];
        for (i, (frames, want)) in rows.iter().enumerate() {
            assert_eq!(FrameKind::of(frames), *want, "row {i}");
        }
    }

    #[test]
    fn evidence_table() {
        use FrameKind::*;
        let with_ack = vec![b"junk".to_vec(), ack()];
        let without_ack = vec![rsr1_query(), message()];
        let none: Vec<Vec<u8>> = vec![];
        let fail = |code: &'static str, weight_milli: u32| Evidence::Fail { code, weight_milli };

        // The rows the design names.
        // Receipt: a message dial with one ACK among its replies.
        assert_eq!(
            evidence(Message, Some(&with_ack), true, None, false),
            Evidence::Receipt
        );
        // Silent: frames written, no ACK; also the deadline after sending
        // (`DialProgress::on_deadline` returns the replies so far).
        assert_eq!(
            evidence(Message, Some(&without_ack), true, None, false),
            Evidence::Silent
        );
        assert_eq!(
            evidence(Message, Some(&none), true, None, false),
            Evidence::Silent
        );
        // Custody is never a receipt, even with an ACK among the replies.
        assert_eq!(
            evidence(Custody, Some(&with_ack), true, None, false),
            Evidence::Link
        );
        assert_eq!(
            evidence(Probe, Some(&none), false, None, false),
            Evidence::Link
        );
        // Failures by code and by `why=` token; E0 codes; a network change.
        assert_eq!(
            evidence(Message, None, true, Some("NOT_LISTENING"), false),
            fail("NOT_LISTENING", 250)
        );
        assert_eq!(
            evidence(Probe, None, false, Some("relay_busy"), false),
            fail("relay_busy", 500)
        );
        assert_eq!(
            evidence(Message, None, false, None, false),
            fail(DIAL_FAILED, 1_000)
        );
        assert_eq!(
            evidence(Message, None, false, Some("P2P_HOLD"), false),
            Evidence::None
        );
        assert_eq!(
            evidence(Message, Some(&with_ack), true, None, true),
            Evidence::None
        );

        // Every combination against the rules written out once more.
        let replies: [Option<&[Vec<u8>]>; 4] =
            [None, Some(&with_ack), Some(&without_ack), Some(&none)];
        let codes = [
            None,
            Some("NOT_REACHABLE"),
            Some("CLOSED_EARLY"),
            Some("contact_offline"),
            Some("INTERNET_HOLD"),
            Some("NEARBY_NOT_IN_RANGE"),
            Some("SOMETHING_NEW"),
        ];
        let mut seen = std::collections::HashSet::new();
        for kind in [Probe, AckOnly, Message, Custody, Control] {
            for ok in replies {
                for sent in [false, true] {
                    for code in codes {
                        for moved in [false, true] {
                            let got = evidence(kind, ok, sent, code, moved);
                            let acked = ok.is_some_and(|r| !ack_frames(r).is_empty());
                            let want = if moved {
                                Evidence::None
                            } else if ok.is_none() {
                                if code.is_some_and(|c| NOT_EVIDENCE.contains(&c)) {
                                    Evidence::None
                                } else {
                                    // No code, or one without a row, is
                                    // recorded as DIAL_FAILED.
                                    let c = code.filter(|c| known_code(c)).unwrap_or(DIAL_FAILED);
                                    fail(c, weight_m(c).unwrap())
                                }
                            } else if kind == Message && acked {
                                Evidence::Receipt
                            } else if kind == Message && sent {
                                Evidence::Silent
                            } else {
                                Evidence::Link
                            };
                            assert_eq!(got, want, "{kind:?} {ok:?} {sent} {code:?} {moved}");
                            // Only a message dial is ever a receipt or silent.
                            if matches!(got, Evidence::Receipt | Evidence::Silent) {
                                assert_eq!(kind, Message);
                            }
                            seen.insert(format!("{got:?}"));
                        }
                    }
                }
            }
        }
        // Every kind of evidence showed up: E0-E3 and four failures
        // (NOT_REACHABLE, CLOSED_EARLY, contact_offline, DIAL_FAILED).
        assert_eq!(seen.len(), 8, "{seen:?}");
    }

    #[test]
    fn weights_follow_the_design_table() {
        assert_eq!(RECEIPT_W_M, 1_000);
        assert_eq!(PROBE_W_M, 500);
        assert_eq!(SILENT_W_M, 500);
        assert_eq!(Evidence::Receipt.weight(), Some(Weight::Success(1_000)));
        assert_eq!(Evidence::Link.weight(), Some(Weight::Success(500)));
        assert_eq!(Evidence::Silent.weight(), Some(Weight::Failure(500)));
        assert_eq!(
            Evidence::Fail {
                code: "CLOSED_EARLY",
                weight_milli: 500
            }
            .weight(),
            Some(Weight::Failure(500))
        );
        assert_eq!(Evidence::None.weight(), None);
        for (codes, w) in [
            (&["NOT_LISTENING", "contact_offline"][..], 250),
            (&["CLOSED_EARLY", "PEER_REFUSED", "relay_busy"][..], 500),
            (
                &[
                    "NOT_REACHABLE",
                    "DIAL_FAILED",
                    "relay_asleep",
                    "relay_refused",
                    "relay_off",
                    "not_admitted",
                    "both_nat",
                    "no_relay",
                    "direct_failed",
                    "WRONG_IDENTITY",
                    "LINK_NOT_ACCEPTED",
                ][..],
                1_000,
            ),
        ] {
            for code in codes {
                assert!(known_code(code), "{code}");
                assert_eq!(weight_m(code), Some(w), "{code}");
            }
        }
        // The rows added since the design: the worker's silent code takes
        // E3's weight; the Phase 3 reasons are below.
        assert_eq!(weight_m("NO_ACK_YET"), Some(SILENT_W_M));
        // No code has two rows, and every weight is a real failure.
        let mut all: Vec<&str> = FAIL_WEIGHTS.iter().map(|(c, _)| *c).collect();
        all.extend(NOT_EVIDENCE);
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n);
        assert!(FAIL_WEIGHTS
            .iter()
            .all(|&(_, w)| (1..=FULL_FAIL_W_M).contains(&w)));
        // Codes are printable ASCII without blanks (they are table keys).
        assert!(all
            .iter()
            .all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_graphic())));
    }

    #[test]
    fn why_tokens_map() {
        for why in Why::ALL {
            let token = why.token();
            assert!(known_code(token), "{token}");
            let want = match why {
                Why::ContactOffline | Why::LanNoAnswer => Some(250),
                Why::RelayBusy => Some(500),
                Why::RelayAsleep
                | Why::RelayRefused
                | Why::RelayOff
                | Why::NotAdmitted
                | Why::BothNat
                | Why::NoRelay
                | Why::DirectFailed
                | Why::NoRoute => Some(FULL_FAIL_W_M),
                Why::LanOff => None,
            };
            assert_eq!(weight_m(token), want, "{token}");
        }
        // Every lower-case row is a token the reason block can carry.
        for (code, _) in FAIL_WEIGHTS {
            if code.bytes().any(|b| b.is_ascii_lowercase()) {
                assert!(Why::parse(code).is_some(), "{code}");
            }
        }
        for code in NOT_EVIDENCE {
            if code.bytes().any(|b| b.is_ascii_lowercase()) {
                assert!(Why::parse(code).is_some(), "{code}");
            }
        }
    }

    #[test]
    fn unknown_code_is_a_full_failure() {
        for code in [
            "SOMETHING_NEW",
            "",
            "not_listening",
            "NOT_LISTENING ",
            "CONTACT_OFFLINE",
            "p2p_hold",
        ] {
            assert!(!known_code(code), "{code:?}");
            assert_eq!(weight_m(code), Some(FULL_FAIL_W_M), "{code:?}");
            assert_eq!(
                evidence(FrameKind::Message, None, true, Some(code), false),
                Evidence::Fail {
                    code: DIAL_FAILED,
                    weight_milli: FULL_FAIL_W_M
                },
                "{code:?}"
            );
        }
    }

    #[test]
    fn not_evidence_list_is_e0() {
        for code in [
            "INTERNET_HOLD",
            "P2P_HOLD",
            "P2P_NOT_RUNNING",
            "CONTACT_BLOCKED",
            "SEND_IN_PROGRESS",
            "IPC_BAD_B64",
            "CUSTODY_IPC_REFUSED",
            "NEARBY_NOT_IN_RANGE",
            "NEARBY_BUSY",
            "LOCK_BUSY",
        ] {
            assert!(NOT_EVIDENCE.contains(&code), "{code}");
        }
        for code in NOT_EVIDENCE {
            assert!(known_code(code), "{code}");
            assert_eq!(weight_m(code), None, "{code}");
            for kind in [FrameKind::Message, FrameKind::Probe, FrameKind::Custody] {
                assert_eq!(
                    evidence(kind, None, true, Some(code), false),
                    Evidence::None,
                    "{code}"
                );
            }
        }
    }

    #[test]
    fn observation_debug_names_no_key_tag_or_relay() {
        let o = Observation {
            contact: [0xAB; 32],
            net: Some("netTAG77".into()),
            net_changed: false,
            carrier: OutboxCarrier::P2p,
            path: Some(DeliveryPath::Relayed),
            relay: Some(vec![0xCD; 38]),
            kind: FrameKind::Message,
            evidence: Evidence::Receipt,
            timing: DialTiming {
                connect_ms: Some(120),
                reply_ms: Some(80),
                total_ms: 230,
            },
            karn_exclude: false,
            at_ms: 1_000,
        };
        let text = format!("{o:?}");
        // The key and relay bytes would print as 171 and 205.
        for secret in ["171", "205", "netTAG77"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        assert!(
            text.contains("Receipt") && text.contains("Relayed"),
            "{text}"
        );
        assert_eq!(o.clone(), o);
    }
}
