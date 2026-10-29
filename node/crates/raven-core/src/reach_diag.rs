//! Why a contact could not be reached: the words of the "nobody reachable in
//! your circle" diagnosis (any-network plan, Phase 2 item 5), shared by
//! raven-node, which decides ([`diagnose`]), and ash, which explains
//! ([`Diag::find`], [`pick_fix`]). Pure, except [`circle_facts`], which reads
//! the profile's files; nothing here names an address, PeerId, key or person.
//!
//! What one failed dial learned, route by route: what a relay answered our
//! circuit request ([`CircuitOutcome`]) and what a direct address did
//! ([`AddrOutcome`]). `raven_swarm::diag` reads both out of libp2p's dial
//! errors, and relay selection and the diagnosis use that one reading.
//!
//! - **The reason block** (`reach: why=<reason>( <key>=<value>)*`,
//!   [`Diag::render`]) is local IPC only: raven-node appends it to a
//!   `P2P_DIAL` error and serves it in `Status.unreachable` and
//!   `OutboxItem.why`. It is registered in `protocol/RAVEN_ERROR_CODES_V1.md`
//!   §2.1 and is never sent to a contact, a relay or a custodian.
//! - **No token may name an address, PeerId, key or person**: a block holds
//!   fixed words, a slot number and ages only, at most [`MAX_RENDERED`]
//!   bytes.
//! - **Only local facts.** `no_route` means this computer has no default
//!   route (no source address for 192.0.2.1 or 2001:db8::1 when it dialled);
//!   it is never a claim that "the internet is down", and nothing here probes
//!   any host.
//! - **Old and new mix**: clients take the last block, skip unknown keys and
//!   values, and read an unknown reason as no reason (today's text).
//! - **Local network reasons (Phase 3):** `lan_off` and `lan_no_answer` come
//!   from raven-node's outbox ([`diagnose_lan`]), not from a p2p dial: they
//!   appear in `Status.unreachable` and `OutboxItem.why` only, never in a
//!   `P2P_DIAL` error.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

use crate::reach::ReachClass;

/// The command that lets a computer reachable from the internet relay for
/// its verified contacts (the friend relay, ash `raven relay offer on`): the
/// `{OFFER}` the diagnosis texts name.
pub const OFFER_CMD: &str = "raven relay offer on";

/// How the diagnosis texts name the relay kit (`{KIT}`): there is no
/// `raven relay kit` command; the kit is installed by its own scripts.
pub const KIT_REF: &str = "the relay kit (docs/RELAY_KIT.md)";

/// The command that ends `raven lan off` ([`Fix::LanOn`]).
pub const LAN_ON_CMD: &str = "raven lan on";

/// The command that uses friends as mailboxes ([`Fix::UseMailbox`]).
pub const MAILBOX_CMD: &str = "raven custody use on";

/// The command an always-on friend runs to hold mail for its friends
/// ([`Fix::AskFriendToHoldMail`]).
pub const HOLD_MAIL_CMD: &str = "raven node custody on";

/// What one relay answered our circuit request (libp2p-relay 0.22's HOP
/// status, read by `raven_swarm::diag`). A relay answers every refusal of
/// its circuit limiter alike, its caps and rates and the membership check
/// of a Raven relay: RESOURCE_LIMIT_EXCEEDED. PERMISSION_DENIED comes only
/// from the destination's answer to the relay (STOP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitOutcome {
    /// NO_RESERVATION or CONNECTION_FAILED: the contact holds no live
    /// reservation on that relay (it is offline, or the relay could not
    /// hand the circuit to it). A contact whose peer gate refuses our
    /// circuit before accepting it (it lacks our current PeerId) also makes
    /// the relay answer CONNECTION_FAILED: the two cannot be told apart, and
    /// both read as offline (a relay's answer is never a quick close).
    NotOnRelay,
    /// PERMISSION_DENIED: the destination refused the circuit.
    Refused,
    /// The peer at that address does not relay (it does not speak the
    /// relay protocol).
    NotARelay,
    /// RESOURCE_LIMIT_EXCEEDED: the relay is full, rate-limits us, or does
    /// not relay for us.
    Busy,
    /// No answer: the relay was not reached or did not answer in time, or
    /// the request's stream failed.
    NoAnswer,
}

/// What a direct address did with our dial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrOutcome {
    /// The host answered and refused the connection: nothing listens there.
    Refused,
    /// No answer, or a failure that says nothing more.
    NoAnswer,
}

/// Why the last p2p dial to a contact failed: one stable token each
/// (`protocol/RAVEN_ERROR_CODES_V1.md` §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Why {
    /// The contact's relay answered NO_RESERVATION or CONNECTION_FAILED: the
    /// contact is not connected to it.
    ContactOffline,
    /// None of the contact's relays answered.
    RelayAsleep,
    /// A relay refused us, or closed our connection within 2 s.
    RelayRefused,
    /// The peer at a relay address does not relay (hop unsupported).
    RelayOff,
    /// A relay answered RESOURCE_LIMIT_EXCEEDED: full, or it does not relay
    /// for us.
    RelayBusy,
    /// The contact's node closed our connection within 2 s (it lacks our
    /// current card).
    NotAdmitted,
    /// No direct address and no relay for the contact, and this node cannot
    /// be reached either.
    BothNat,
    /// The same, but this node can be reached (the contact can write first).
    NoRelay,
    /// The contact's announced direct addresses did not answer, and it has
    /// no relay.
    DirectFailed,
    /// This computer has no default route: only peers on its own networks
    /// can be reached. A local fact, not a claim about the internet.
    NoRoute,
    /// `raven lan off` is in effect (local, Phase 3 `LAN_OFF`): no LAN dial,
    /// listener or beacon, and the contact has no route on another carrier.
    LanOff,
    /// The LAN beacon runs and looked for the contact (a message waits for
    /// it), but its last 2 rounds got no answer although the contact was on
    /// this network in the last 7 days, and the contact has no route on
    /// another carrier: no contact answered on this network (the Wi-Fi may
    /// keep devices apart).
    LanNoAnswer,
}

impl Why {
    /// Every reason, in the order of the registry (new ones are appended).
    pub const ALL: [Why; 12] = [
        Why::ContactOffline,
        Why::RelayAsleep,
        Why::RelayRefused,
        Why::RelayOff,
        Why::RelayBusy,
        Why::NotAdmitted,
        Why::BothNat,
        Why::NoRelay,
        Why::DirectFailed,
        Why::NoRoute,
        Why::LanOff,
        Why::LanNoAnswer,
    ];

    /// The stable token (`why=` in the reason block).
    pub fn token(self) -> &'static str {
        match self {
            Why::ContactOffline => "contact_offline",
            Why::RelayAsleep => "relay_asleep",
            Why::RelayRefused => "relay_refused",
            Why::RelayOff => "relay_off",
            Why::RelayBusy => "relay_busy",
            Why::NotAdmitted => "not_admitted",
            Why::BothNat => "both_nat",
            Why::NoRelay => "no_relay",
            Why::DirectFailed => "direct_failed",
            Why::NoRoute => "no_route",
            Why::LanOff => "lan_off",
            Why::LanNoAnswer => "lan_no_answer",
        }
    }

    /// The exact token; anything else (a newer daemon's reason) is `None`.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|w| w.token() == s)
    }

    /// A reason about the local network ([`diagnose_lan`]), not about a p2p
    /// dial.
    pub fn is_lan(self) -> bool {
        matches!(self, Why::LanOff | Why::LanNoAnswer)
    }

    /// A reason about a relay on the way to the contact: only these name
    /// one of our relay slots.
    fn is_relay(self) -> bool {
        matches!(
            self,
            Why::RelayAsleep | Why::RelayRefused | Why::RelayOff | Why::RelayBusy
        )
    }
}

/// What one failed p2p dial learned (raven-node builds it from the dial's
/// errors).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DialSummary {
    /// A network change, a host stop, or an error other than
    /// P2P_UNREACHABLE: no reason is given.
    pub interrupted: bool,
    /// The contact's node closed our connection at once.
    pub target_closed_at_once: bool,
    /// One per relay tried: our relay slot (1 or 2) when the relay is one of
    /// ours, what it answered, and whether it closed our connection at once.
    pub circuits: Vec<(Option<u8>, CircuitOutcome, bool)>,
    /// One per direct address tried.
    pub direct: Vec<AddrOutcome>,
    /// Our relay slots (1 or 2) whose relay holds our reservation and
    /// answered us (a ping) after the dial began: no answer through one of
    /// them is the contact's silence (its computer asleep or gone without
    /// closing, while the relay still holds its reservation), never the
    /// relay's.
    pub slots_answering: Vec<u8>,
}

/// What this node knows of itself when the dial failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MyFacts {
    /// Its reachability class (`raven status`).
    pub class: ReachClass,
    /// It has no global listen address and no UPnP mapping.
    pub behind_nat: bool,
    /// It hides its IP from this contact (D4), so it gave them no direct
    /// address.
    pub hides_ip_from_them: bool,
    /// It has no default route (raven-node's netwatch reading): only peers
    /// on its own networks can be reached.
    pub no_default_route: bool,
}

impl Default for MyFacts {
    fn default() -> Self {
        Self {
            class: ReachClass::Unknown,
            behind_nat: false,
            hides_ip_from_them: false,
            no_default_route: false,
        }
    }
}

impl MyFacts {
    /// Could the contact open a link to this node (and so write first)?
    pub fn they_can_reach_me(&self) -> bool {
        match self.class {
            ReachClass::Relayed => true,
            ReachClass::Public | ReachClass::Mapped => !self.hides_ip_from_them,
            ReachClass::Unreachable | ReachClass::Unknown => false,
        }
    }
}

/// What this node knows of the contact's routes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TheirFacts {
    /// Its routes come from its card only (no route hints).
    pub from_card_only: bool,
    /// Its last route hints have expired.
    pub hint_expired: bool,
    /// Seconds since this node last heard from it.
    pub heard_s: Option<u64>,
}

/// One diagnosis: the reason and the facts the texts need. Its block is
/// [`Diag::render`]; [`Diag::find`] reads it back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diag {
    pub why: Why,
    /// This node's reachability class at the time.
    pub me: Option<ReachClass>,
    /// Our relay slot (1 or 2) whose answer decided a `relay_*` reason.
    pub relay: Option<u8>,
    /// Seconds since the contact was last heard.
    pub heard_s: Option<u64>,
    /// The contact's route hints had expired (its routes may be old).
    pub stale: bool,
    /// The contact's routes come from its card only.
    pub from_card: bool,
    /// Seconds since raven-node made this diagnosis (a remembered one).
    pub asof_s: Option<u64>,
}

/// Does circuit `c` carry the answer that gave `why`?
fn deciding(why: Why, c: &(Option<u8>, CircuitOutcome, bool)) -> bool {
    match why {
        Why::RelayRefused => c.1 == CircuitOutcome::Refused || c.2,
        Why::RelayOff => c.1 == CircuitOutcome::NotARelay,
        Why::RelayBusy => c.1 == CircuitOutcome::Busy,
        Why::RelayAsleep => c.1 == CircuitOutcome::NoAnswer,
        _ => false,
    }
}

/// The reason for one failed dial, or `None` when it was interrupted. No
/// default route comes first: then no relay or NAT reason can be told.
/// Then the first match: the contact closed us at once, a relay refused or
/// closed us at once, the contact is not on its relay (or did not answer
/// through one of our relays that answered us meanwhile,
/// [`DialSummary::slots_answering`]), a relay does not relay, a relay is
/// busy, no relay answered, the direct addresses failed; with nothing to
/// dial, whether the contact could reach this node.
pub fn diagnose(d: &DialSummary, me: &MyFacts, them: &TheirFacts) -> Option<Diag> {
    if d.interrupted {
        return None;
    }
    let has = |o: CircuitOutcome| d.circuits.iter().any(|c| c.1 == o);
    // No answer through a relay of ours that answered us meanwhile.
    let contact_silent = d.circuits.iter().any(|c| {
        c.1 == CircuitOutcome::NoAnswer && c.0.is_some_and(|s| d.slots_answering.contains(&s))
    });
    let why = if me.no_default_route {
        Why::NoRoute
    } else if d.target_closed_at_once {
        Why::NotAdmitted
    } else if has(CircuitOutcome::Refused) || d.circuits.iter().any(|c| c.2) {
        Why::RelayRefused
    } else if has(CircuitOutcome::NotOnRelay) || contact_silent {
        Why::ContactOffline
    } else if has(CircuitOutcome::NotARelay) {
        Why::RelayOff
    } else if has(CircuitOutcome::Busy) {
        Why::RelayBusy
    } else if !d.circuits.is_empty() {
        // Every relay: no answer.
        Why::RelayAsleep
    } else if !d.direct.is_empty() {
        Why::DirectFailed
    } else if me.they_can_reach_me() || (me.class == ReachClass::Unknown && !me.behind_nat) {
        Why::NoRelay
    } else {
        Why::BothNat
    };
    // Named only when the deciding answer came from one of OUR slots.
    let relay = if why.is_relay() {
        d.circuits
            .iter()
            .find(|c| deciding(why, c))
            .and_then(|c| c.0)
            .filter(|slot| matches!(slot, 1 | 2))
    } else {
        None
    };
    Some(Diag {
        why,
        me: Some(me.class),
        relay,
        heard_s: them.heard_s,
        stale: them.hint_expired
            && matches!(
                why,
                Why::ContactOffline | Why::RelayAsleep | Why::DirectFailed
            ),
        from_card: them.from_card_only && matches!(why, Why::BothNat | Why::NoRelay),
        asof_s: None,
    })
}

/// What raven-node's outbox knows of the local network after an attempt
/// left a message for a contact waiting for a route (Phase 3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LanFacts {
    /// `raven lan off` is in effect.
    pub lan_off: bool,
    /// The LAN beacon asked for the contact in vain: its last 2 rounds got
    /// no answer while a want for it holds, and the contact was on this
    /// network in the last 7 days.
    pub beacon_no_answer: bool,
    /// The attempt planned a route to the contact on another carrier
    /// (Internet direct or p2p): that carrier's reason, if any, is the one.
    pub other_route: bool,
}

/// The local network's reason for a waiting message, or `None` when LAN is
/// not why: `raven lan off` first, then a beacon that got no answer; never
/// while another carrier has a route. Local facts only; `heard` is kept,
/// nothing else is set.
pub fn diagnose_lan(f: &LanFacts, them: &TheirFacts) -> Option<Diag> {
    if f.other_route {
        return None;
    }
    let why = if f.lan_off {
        Why::LanOff
    } else if f.beacon_no_answer {
        Why::LanNoAnswer
    } else {
        return None;
    };
    Some(Diag {
        why,
        me: None,
        relay: None,
        heard_s: them.heard_s,
        stale: false,
        from_card: false,
        asof_s: None,
    })
}

/// The start of every reason block.
pub const REACH_TAG: &str = "reach: why=";
/// A reason block is at most this long, and [`Diag::find`] reads no further.
pub const MAX_RENDERED: usize = 120;

/// The unit an age is written in: seconds under 2 minutes, minutes under 2
/// hours, hours under 2 days, days after that.
fn age_unit(secs: u64) -> (char, u64) {
    match secs {
        0..=119 => ('s', 1),
        120..=7_199 => ('m', 60),
        7_200..=172_799 => ('h', 3_600),
        _ => ('d', 86_400),
    }
}

/// `<n>s|m|h|d`, rounded down.
pub(crate) fn write_age(out: &mut String, secs: u64) {
    let (unit, size) = age_unit(secs);
    let _ = write!(out, "{}{unit}", secs / size);
}

/// An age value, as the seconds its rounded-down form stands for (so a
/// block read and written again is the same); `None` when it is not one.
pub(crate) fn parse_age(v: &str) -> Option<u64> {
    let size = match v.as_bytes().last()? {
        b's' => 1,
        b'm' => 60,
        b'h' => 3_600,
        b'd' => 86_400,
        _ => return None,
    };
    let digits = &v[..v.len() - 1];
    if digits.is_empty() || digits.len() > 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = digits.parse::<u64>().ok()?.checked_mul(size)?;
    let (_, unit) = age_unit(secs);
    Some(secs / unit * unit)
}

impl Diag {
    /// `reach: why=<w>[ me=<class>][ relay=mine<1|2>][ heard=<age>][ stale=1][ src=card][ asof=<age>]`,
    /// with age = `<n>s|m|h|d` (rounded down). Fixed words and numbers only,
    /// at most [`MAX_RENDERED`] bytes.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(MAX_RENDERED);
        out.push_str(REACH_TAG);
        out.push_str(self.why.token());
        if let Some(me) = self.me {
            out.push_str(" me=");
            out.push_str(me.as_str());
        }
        if let Some(slot @ (1 | 2)) = self.relay {
            let _ = write!(out, " relay=mine{slot}");
        }
        if let Some(secs) = self.heard_s {
            out.push_str(" heard=");
            write_age(&mut out, secs);
        }
        if self.stale {
            out.push_str(" stale=1");
        }
        if self.from_card {
            out.push_str(" src=card");
        }
        if let Some(secs) = self.asof_s {
            out.push_str(" asof=");
            write_age(&mut out, secs);
        }
        out
    }

    /// The LAST block in `raw` (a multi-route failure joins several texts
    /// with "; "). It reads up to ';', ')', a line end or [`MAX_RENDERED`]
    /// bytes (on a char boundary). Unknown keys, and values a key does not
    /// take, are skipped. An unknown or missing `why` gives `None`, so a
    /// newer daemon gets today's text.
    pub fn find(raw: &str) -> Option<Self> {
        let start = raw.rfind(REACH_TAG)?;
        let tail = &raw[start..];
        let mut end = tail.len().min(MAX_RENDERED);
        while !tail.is_char_boundary(end) {
            end -= 1;
        }
        let block = tail[..end]
            .split([';', ')', '\n', '\r'])
            .next()
            .unwrap_or_default();
        let mut words = block.get(REACH_TAG.len()..)?.split(' ');
        let why = Why::parse(words.next()?)?;
        let mut d = Diag {
            why,
            me: None,
            relay: None,
            heard_s: None,
            stale: false,
            from_card: false,
            asof_s: None,
        };
        for (key, value) in words.filter_map(|w| w.split_once('=')) {
            match (key, value) {
                ("me", v) => {
                    if let Some(class) = ReachClass::ALL.into_iter().find(|c| c.as_str() == v) {
                        d.me = Some(class);
                    }
                }
                ("relay", "mine1") => d.relay = Some(1),
                ("relay", "mine2") => d.relay = Some(2),
                ("heard", v) => d.heard_s = parse_age(v).or(d.heard_s),
                ("stale", "1") => d.stale = true,
                ("src", "card") => d.from_card = true,
                ("asof", v) => d.asof_s = parse_age(v).or(d.asof_s),
                _ => {}
            }
        }
        Some(d)
    }
}

/// What the user can do about one reason. ash words each one; a section of
/// several reasons shows the one with the highest [`Fix::priority`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fix {
    /// Nothing on your side: it goes out when the contact is back online.
    WaitUntilOnline,
    /// Nothing: raven-node tries again by itself.
    RetryLater,
    /// Nothing: it goes out when the contact next sends you a message.
    TheyWriteFirst,
    /// The contact needs a new relay.
    TheyNeedNewRelay,
    /// Send the contact your card again.
    ResendCard,
    /// Ask whoever runs the relay to wake that computer.
    WakeRelay,
    /// Become the relay owner's verified contact.
    AskRelayOwner,
    /// This computer can be reached: offer relaying ([`OFFER_CMD`]).
    OfferRelaying,
    /// Ask this contact (device key), who offers relaying or can be reached
    /// from the internet, to relay for you.
    AskFriend([u8; 32]),
    /// Nobody in the circle can be reached: a friend's relay offer, the
    /// relay kit ([`KIT_REF`]) or a port forward fixes it.
    NobodyReachable,
    /// This computer has no default route: only people on the same network
    /// can be reached, and nothing on this computer changes that. Never an
    /// internet-side fix.
    LocalOnly,
    /// `raven lan off` is in effect: [`LAN_ON_CMD`] turns the local network
    /// back on (Phase 3).
    LanOn,
    /// The contact is offline and no friend can hold mail for it, because
    /// friend mailboxes are off here: [`MAILBOX_CMD`] (Phase 3 custody).
    UseMailbox,
    /// The contact is offline and no friend holds mail for it although
    /// friend mailboxes are on: ask an always-on friend you both verified to
    /// run [`HOLD_MAIL_CMD`] (Phase 3 custody).
    AskFriendToHoldMail,
    /// The circle is not known (the contact book cannot be read).
    Generic,
}

impl Fix {
    /// Which fix a section shows when its rows differ: the highest. The
    /// mailbox fixes rank just above waiting; `raven lan on` ranks above
    /// everything, LocalOnly included (with no route to the internet the
    /// local network is the one way left).
    pub fn priority(self) -> u8 {
        match self {
            Fix::Generic | Fix::WaitUntilOnline => 0,
            Fix::RetryLater => 1,
            Fix::AskFriendToHoldMail => 2,
            Fix::UseMailbox => 3,
            Fix::TheyWriteFirst => 4,
            Fix::TheyNeedNewRelay => 5,
            Fix::ResendCard => 6,
            Fix::WakeRelay => 7,
            Fix::AskRelayOwner => 8,
            Fix::OfferRelaying => 9,
            Fix::AskFriend(_) => 10,
            Fix::NobodyReachable => 11,
            Fix::LocalOnly => 12,
            Fix::LanOn => 13,
        }
    }
}

/// The user's circle, as far as a fix needs it ([`circle_facts`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CircleFacts {
    /// The contact book was read (`false`: nothing below is known).
    pub known: bool,
    /// Verified contacts that offer this node relaying (device keys).
    pub offers: Vec<[u8; 32]>,
    /// Verified contacts that can be reached from the internet directly.
    pub reachable: Vec<[u8; 32]>,
    /// Offered relays automatic choice holds.
    pub offers_in_use: u8,
    /// Verified contacts with a p2p PeerId.
    pub p2p_contacts: u32,
    /// Whether a friend could hold mail for the one contact a fix is picked
    /// for ([`mail_path`]); the caller sets it per contact.
    pub mail: MailPath,
}

/// Whether a friend could hold mail for one offline contact (friend
/// custody, Phase 3), as far as a fix needs it ([`mail_path`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MailPath {
    /// No mailbox fix: learned custody is not live here, a friend can
    /// already take mail for the contact, the user said no to mailboxes, or
    /// it is not known.
    #[default]
    NoFix,
    /// Friend mailboxes are off here (`raven custody use` never answered).
    MailboxOff,
    /// Friend mailboxes are on, but no friend can take mail for the contact.
    NoFriend,
}

/// [`MailPath`] for `peer`, with `local` this node's key, from the
/// profile's files: nothing unless learned custody is live
/// ([`crate::custody_gate::custody_hints_live`]); a friend that may take
/// mail for `peer` ([`crate::custody_client::deposit_custodians`]) needs
/// no fix; else friend mailboxes never answered is [`MailPath::MailboxOff`]
/// and on is [`MailPath::NoFriend`]. Off by the user's choice, or an
/// unreadable policy, gives no fix.
pub fn mail_path(data_dir: &Path, local: &[u8; 32], peer: &[u8; 32], now_ms: u64) -> MailPath {
    if !crate::custody_gate::custody_hints_live() {
        return MailPath::NoFix;
    }
    if !crate::custody_client::deposit_custodians(data_dir, local, peer, now_ms).is_empty() {
        return MailPath::NoFix;
    }
    match crate::node_policy::try_load_policy(data_dir).map(|p| p.custody_use) {
        Ok(None) => MailPath::MailboxOff,
        Ok(Some(true)) => MailPath::NoFriend,
        Ok(Some(false)) | Err(_) => MailPath::NoFix,
    }
}

/// What to do about `d`. `me_confirmed_public`: two independent checks
/// confirm this computer is public (D2: only then is offering relaying
/// suggested); `relaying_for_contacts`: it relays for its contacts already.
/// An offline contact (`contact_offline`, `direct_failed`, `lan_no_answer`)
/// gets a mailbox fix when no friend can hold mail for it
/// ([`CircleFacts::mail`]), else waiting.
pub fn pick_fix(
    d: &Diag,
    me_confirmed_public: bool,
    relaying_for_contacts: bool,
    circle: &CircleFacts,
) -> Fix {
    match d.why {
        Why::NoRoute => Fix::LocalOnly,
        Why::LanOff => Fix::LanOn,
        // An offline contact: a friend's mailbox when none can take it yet.
        Why::ContactOffline | Why::DirectFailed | Why::LanNoAnswer => match circle.mail {
            MailPath::MailboxOff => Fix::UseMailbox,
            MailPath::NoFriend => Fix::AskFriendToHoldMail,
            MailPath::NoFix => Fix::WaitUntilOnline,
        },
        Why::RelayBusy => Fix::RetryLater,
        Why::RelayOff => Fix::TheyNeedNewRelay,
        Why::NotAdmitted => Fix::ResendCard,
        Why::RelayAsleep => Fix::WakeRelay,
        Why::RelayRefused => Fix::AskRelayOwner,
        Why::NoRelay if me_confirmed_public && !relaying_for_contacts => Fix::OfferRelaying,
        Why::NoRelay => Fix::TheyWriteFirst,
        Why::BothNat if !circle.known => Fix::Generic,
        Why::BothNat => circle
            .offers
            .first()
            .or(circle.reachable.first())
            .map_or(Fix::NobodyReachable, |k| Fix::AskFriend(*k)),
    }
}

/// [`CircleFacts::offers`] and [`CircleFacts::reachable`] hold at most this
/// many contacts each.
pub const MAX_CIRCLE: usize = 4;

/// One `contacts.json` row, as far as the circle needs it.
#[derive(Deserialize)]
struct BookRow {
    #[serde(default)]
    pub_hex: String,
    #[serde(default)]
    pinned: bool,
    #[serde(default)]
    p2p: String,
    #[serde(default)]
    p2p_via: Vec<String>,
}

/// The circle, from the profile's files: verified (pinned) and unblocked
/// contacts only, in book order (several rows of one key are verified only
/// if all are, as the peer gate reads them), at most [`MAX_CIRCLE`] per
/// list:
/// - `offers`: they offer relaying ([`crate::learned_routes::offers`], an
///   unexpired snapshot only);
/// - `reachable`: a direct p2p address their unexpired route hints name
///   ([`crate::learned_routes`]: global ones only); when those name a
///   PeerId they decide, else a card `via=` naming their own PeerId counts
///   when its host is a DNS name or a global IP (a LAN or loopback address
///   says nothing about the internet; the debug
///   `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1` admits any IP, for one-machine
///   harnesses). Contacts known through route hints come first, then
///   card-only ones.
///
/// `offers_in_use` counts offered relays automatic choice holds
/// ([`crate::relay_select::load_memory`]); `p2p_contacts` the contacts with a
/// PeerId (the book's or a learned one). No contact book is an empty
/// circle; an unreadable or corrupt book or block list gives `Err`, and
/// callers then use `known: false`.
pub fn circle_facts(data_dir: &Path, now_ms: u64) -> Result<CircleFacts, String> {
    circle_facts_with(
        data_dir,
        now_ms,
        crate::p2p_gate::p2p_local_candidates_enabled(),
    )
}

/// [`circle_facts`]; `lab_local`: a card's direct `via=` on any IP counts.
fn circle_facts_with(data_dir: &Path, now_ms: u64, lab_local: bool) -> Result<CircleFacts, String> {
    let rows: Vec<BookRow> = crate::contact_book::read_rows(data_dir)?.unwrap_or_default();
    let blocks = crate::chat_history::BlockList::load_checked(data_dir)?;
    // (key hex, key, verified, the book's PeerId and via=), in book order.
    type Entry = (String, [u8; 32], bool, Option<crate::p2p_route::ContactP2p>);
    let mut book: Vec<Entry> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    for row in &rows {
        let hex = row.pub_hex.trim().to_ascii_lowercase();
        let Some(key) = hex::decode(&hex)
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
        else {
            continue;
        };
        let p2p = crate::p2p_route::ContactP2p::from_fields(&row.p2p, &row.p2p_via);
        match at.get(&hex) {
            Some(&i) => {
                let entry = &mut book[i];
                entry.2 &= row.pinned;
                if entry.3.is_none() {
                    entry.3 = p2p;
                }
            }
            None => {
                at.insert(hex.clone(), book.len());
                book.push((hex, key, row.pinned, p2p));
            }
        }
    }
    book.retain(|(hex, _, verified, _)| *verified && !blocks.is_blocked(hex));

    let learned: HashMap<String, crate::learned_routes::LearnedP2p> =
        crate::learned_routes::learned_p2p(data_dir, now_ms)
            .into_iter()
            .map(|(hex, p2p)| (hex.to_ascii_lowercase(), p2p))
            .collect();
    let mut offered: HashMap<String, Vec<String>> = HashMap::new();
    for (operator, _, offer, expires_at_ms) in crate::learned_routes::offers(data_dir, now_ms) {
        if expires_at_ms > now_ms {
            offered
                .entry(operator.to_ascii_lowercase())
                .or_default()
                .push(offer.relay_peer_id);
        }
    }
    let held: HashSet<String> = if offered.is_empty() {
        HashSet::new()
    } else {
        crate::relay_select::load_memory(data_dir)
            .selected
            .into_iter()
            .collect()
    };

    let mut facts = CircleFacts {
        known: true,
        ..CircleFacts::default()
    };
    let mut in_use: HashSet<&str> = HashSet::new();
    let (mut by_hint, mut by_card) = (Vec::new(), Vec::new());
    for (hex, key, _, card) in &book {
        let hint = learned.get(hex);
        if hint.is_some() || card.is_some() {
            facts.p2p_contacts = facts.p2p_contacts.saturating_add(1);
        }
        if let Some(relays) = offered.get(hex) {
            if facts.offers.len() < MAX_CIRCLE {
                facts.offers.push(*key);
            }
            in_use.extend(
                relays
                    .iter()
                    .filter(|r| held.contains(*r))
                    .map(String::as_str),
            );
        }
        match hint {
            Some(hint) if !hint.direct.is_empty() => by_hint.push(*key),
            Some(_) => {}
            None => {
                if card.as_ref().is_some_and(|c| {
                    c.via.iter().any(|v| {
                        v.peer_id == c.peer_id
                            && crate::route_hints::relay_host_usable(v, lab_local, false)
                    })
                }) {
                    by_card.push(*key);
                }
            }
        }
    }
    facts.reachable = by_hint
        .into_iter()
        .chain(by_card)
        .take(MAX_CIRCLE)
        .collect();
    facts.offers_in_use = u8::try_from(in_use.len()).unwrap_or(u8::MAX);
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain value: copied, compared and printed.
    fn plain<T: Copy + Eq + std::fmt::Debug>(v: T) -> String {
        let copy = v;
        assert_eq!(copy, v);
        format!("{v:?}")
    }

    #[test]
    fn outcomes_are_copy_eq_and_debug_printable() {
        let circuits = [
            CircuitOutcome::NotOnRelay,
            CircuitOutcome::Refused,
            CircuitOutcome::NotARelay,
            CircuitOutcome::Busy,
            CircuitOutcome::NoAnswer,
        ];
        assert_eq!(
            circuits.map(plain),
            ["NotOnRelay", "Refused", "NotARelay", "Busy", "NoAnswer"]
        );
        for (i, a) in circuits.iter().enumerate() {
            for (j, b) in circuits.iter().enumerate() {
                assert_eq!(i == j, a == b);
            }
        }
        assert_eq!(
            [AddrOutcome::Refused, AddrOutcome::NoAnswer].map(plain),
            ["Refused", "NoAnswer"]
        );
        assert_ne!(AddrOutcome::Refused, AddrOutcome::NoAnswer);
    }

    /// `{OFFER}` names the command ash builds, word for word; `{KIT}` names
    /// the kit's guide (no `raven relay kit` command exists).
    #[test]
    fn the_offer_command_is_the_friend_relays() {
        assert_eq!(OFFER_CMD, "raven relay offer on");
        assert_eq!(KIT_REF, "the relay kit (docs/RELAY_KIT.md)");
        assert!(!KIT_REF.contains("raven relay kit"));
    }

    use CircuitOutcome::{Busy, NoAnswer, NotARelay, NotOnRelay, Refused};

    fn circuits(c: &[(Option<u8>, CircuitOutcome, bool)]) -> DialSummary {
        DialSummary {
            circuits: c.to_vec(),
            ..DialSummary::default()
        }
    }

    fn me(class: ReachClass) -> MyFacts {
        MyFacts {
            class,
            ..MyFacts::default()
        }
    }

    fn why(d: &DialSummary, m: &MyFacts) -> Option<Why> {
        diagnose(d, m, &TheirFacts::default()).map(|d| d.why)
    }

    /// Every dial shape that is not "nothing to dial".
    fn dial_shapes() -> Vec<DialSummary> {
        let mut all: Vec<DialSummary> = [NotOnRelay, Refused, NotARelay, Busy, NoAnswer]
            .into_iter()
            .flat_map(|o| {
                [
                    circuits(&[(None, o, false)]),
                    circuits(&[(Some(1), o, false), (None, NoAnswer, false)]),
                    circuits(&[(Some(2), o, true)]),
                ]
            })
            .collect();
        all.push(DialSummary {
            direct: vec![AddrOutcome::Refused, AddrOutcome::NoAnswer],
            ..DialSummary::default()
        });
        all.push(DialSummary {
            target_closed_at_once: true,
            ..circuits(&[(Some(1), NotOnRelay, false)])
        });
        all.push(DialSummary::default());
        all
    }

    /// A relay of ours that holds our reservation and answered us during
    /// the dial is up: no answer through it is the contact's (a computer
    /// asleep while the relay still holds its reservation), so the reason is
    /// `contact_offline` and names no relay slot, never `relay_asleep`
    /// ("check your relay"). A slot that did not answer, or a contact's own
    /// relay (no slot), keeps `relay_asleep`.
    #[test]
    fn no_answer_through_a_relay_that_answered_us_is_the_contact_s() {
        let unknown = me(ReachClass::Unknown);
        let with = |c: &[(Option<u8>, CircuitOutcome, bool)], answering: &[u8]| DialSummary {
            slots_answering: answering.to_vec(),
            ..circuits(c)
        };
        for (d, want) in [
            (
                with(&[(Some(1), NoAnswer, false)], &[1]),
                Why::ContactOffline,
            ),
            (
                with(&[(Some(1), NoAnswer, false), (None, NoAnswer, false)], &[1]),
                Why::ContactOffline,
            ),
            (
                with(
                    &[(Some(1), NoAnswer, false), (Some(2), NoAnswer, false)],
                    &[2],
                ),
                Why::ContactOffline,
            ),
            // Not this dial's slot, or no answer from it: the relay's.
            (with(&[(Some(1), NoAnswer, false)], &[2]), Why::RelayAsleep),
            (with(&[(Some(1), NoAnswer, false)], &[]), Why::RelayAsleep),
            (with(&[(None, NoAnswer, false)], &[1]), Why::RelayAsleep),
            // A specific answer elsewhere keeps its order.
            (
                with(&[(Some(1), NoAnswer, false), (None, Refused, false)], &[1]),
                Why::RelayRefused,
            ),
            (with(&[(Some(1), Busy, false)], &[1]), Why::RelayBusy),
        ] {
            let got = diagnose(&d, &unknown, &TheirFacts::default()).unwrap();
            assert_eq!(got.why, want, "{d:?}");
            if want == Why::ContactOffline {
                assert_eq!(got.relay, None, "{d:?}");
            }
        }
        let asleep = diagnose(
            &with(&[(Some(1), NoAnswer, false)], &[]),
            &unknown,
            &TheirFacts::default(),
        )
        .unwrap();
        assert_eq!((asleep.why, asleep.relay), (Why::RelayAsleep, Some(1)));
        // No route still comes first.
        let offline = MyFacts {
            no_default_route: true,
            ..unknown
        };
        assert_eq!(
            why(&with(&[(Some(1), NoAnswer, false)], &[1]), &offline),
            Some(Why::NoRoute)
        );
    }

    #[test]
    fn diagnose_table() {
        use ReachClass::*;
        let unknown = me(Unknown);
        // Relay answers.
        assert_eq!(
            why(
                &circuits(&[(None, NotOnRelay, false), (Some(1), NotOnRelay, false)]),
                &unknown
            ),
            Some(Why::ContactOffline)
        );
        assert_eq!(
            why(
                &circuits(&[(None, NotOnRelay, false), (None, NoAnswer, false)]),
                &unknown
            ),
            Some(Why::ContactOffline)
        );
        for refused in [
            circuits(&[(None, NotOnRelay, false), (None, Refused, false)]),
            circuits(&[(None, NotOnRelay, false), (None, NoAnswer, true)]),
            circuits(&[(Some(2), Busy, true)]),
        ] {
            assert_eq!(why(&refused, &unknown), Some(Why::RelayRefused));
        }
        assert_eq!(
            why(
                &circuits(&[(None, NotARelay, false), (None, NoAnswer, false)]),
                &unknown
            ),
            Some(Why::RelayOff)
        );
        assert_eq!(
            why(
                &circuits(&[(None, Busy, false), (None, NoAnswer, false)]),
                &unknown
            ),
            Some(Why::RelayBusy)
        );
        assert_eq!(
            why(
                &circuits(&[(None, NoAnswer, false), (Some(1), NoAnswer, false)]),
                &unknown
            ),
            Some(Why::RelayAsleep)
        );
        // The contact closing us beats everything (but no route).
        for d in dial_shapes() {
            let closed = DialSummary {
                target_closed_at_once: true,
                ..d
            };
            assert_eq!(why(&closed, &unknown), Some(Why::NotAdmitted));
        }
        // Direct addresses only.
        let direct = DialSummary {
            direct: vec![AddrOutcome::NoAnswer, AddrOutcome::Refused],
            ..DialSummary::default()
        };
        assert_eq!(why(&direct, &me(Public)), Some(Why::DirectFailed));
        // Nothing to dial: can the contact reach this node?
        let nothing = DialSummary::default();
        let hiding = |class| MyFacts {
            class,
            hides_ip_from_them: true,
            ..MyFacts::default()
        };
        let nat = |class| MyFacts {
            class,
            behind_nat: true,
            ..MyFacts::default()
        };
        for (facts, want) in [
            (me(Relayed), Why::NoRelay),
            (hiding(Relayed), Why::NoRelay),
            (me(Public), Why::NoRelay),
            (me(Mapped), Why::NoRelay),
            (hiding(Public), Why::BothNat),
            (hiding(Mapped), Why::BothNat),
            (me(Unreachable), Why::BothNat),
            (nat(Unreachable), Why::BothNat),
            (nat(Unknown), Why::BothNat),
            (me(Unknown), Why::NoRelay),
        ] {
            assert_eq!(why(&nothing, &facts), Some(want), "{facts:?}");
        }
        // Interrupted: no reason at all, whatever else is known.
        for d in dial_shapes() {
            let cut = DialSummary {
                interrupted: true,
                ..d
            };
            for facts in [
                me(Public),
                MyFacts {
                    no_default_route: true,
                    ..nat(Unreachable)
                },
            ] {
                assert_eq!(why(&cut, &facts), None);
            }
        }
        // No default route: `no_route` with every dial shape and class, and
        // it never names a relay slot, `stale` or `src`; `heard` stays.
        let them = TheirFacts {
            from_card_only: true,
            hint_expired: true,
            heard_s: Some(3 * 3_600),
        };
        for d in dial_shapes() {
            for class in ReachClass::ALL {
                for behind_nat in [false, true] {
                    let facts = MyFacts {
                        class,
                        behind_nat,
                        hides_ip_from_them: behind_nat,
                        no_default_route: true,
                    };
                    let got = diagnose(&d, &facts, &them).expect("a reason");
                    assert_eq!(
                        got,
                        Diag {
                            why: Why::NoRoute,
                            me: Some(class),
                            relay: None,
                            heard_s: Some(3 * 3_600),
                            stale: false,
                            from_card: false,
                            asof_s: None,
                        },
                        "{d:?}"
                    );
                }
            }
        }
        // The local network (Phase 3, raven-node's outbox): `raven lan off`
        // first, then a beacon that got no answer; never while another
        // carrier has a route, and nothing when LAN is not why. Only `heard`
        // is kept.
        let lan = |lan_off, beacon_no_answer, other_route| LanFacts {
            lan_off,
            beacon_no_answer,
            other_route,
        };
        for (f, want) in [
            (lan(true, false, false), Some(Why::LanOff)),
            (lan(true, true, false), Some(Why::LanOff)),
            (lan(false, true, false), Some(Why::LanNoAnswer)),
            (lan(false, false, false), None),
            (lan(true, false, true), None),
            (lan(true, true, true), None),
            (lan(false, true, true), None),
            (LanFacts::default(), None),
        ] {
            let got = diagnose_lan(&f, &them);
            assert_eq!(got.as_ref().map(|d| d.why), want, "{f:?}");
            if let Some(d) = got {
                assert!(d.why.is_lan());
                assert_eq!(
                    d,
                    Diag {
                        heard_s: Some(3 * 3_600),
                        me: None,
                        ..diag(d.why)
                    }
                );
            }
            let bare = diagnose_lan(&f, &TheirFacts::default());
            assert!(bare.is_none_or(|d| d.heard_s.is_none()));
        }
        // No p2p dial gives a local network reason.
        for d in dial_shapes() {
            for class in ReachClass::ALL {
                let got = why(&d, &me(class)).unwrap();
                assert!(!got.is_lan(), "{d:?}");
            }
        }
    }

    #[test]
    fn relay_slot_is_named_only_for_our_deciding_relay() {
        let slot = |c: &[(Option<u8>, CircuitOutcome, bool)]| {
            let d = diagnose(
                &circuits(c),
                &me(ReachClass::Unknown),
                &TheirFacts::default(),
            )
            .unwrap();
            (d.why, d.relay)
        };
        assert_eq!(
            slot(&[(Some(1), Refused, false), (None, NotOnRelay, false)]),
            (Why::RelayRefused, Some(1))
        );
        // The deciding answer came from the contact's own relay.
        assert_eq!(
            slot(&[(None, Refused, false), (Some(2), Refused, false)]),
            (Why::RelayRefused, None)
        );
        assert_eq!(
            slot(&[(None, NotOnRelay, false), (Some(2), NoAnswer, true)]),
            (Why::RelayRefused, Some(2))
        );
        assert_eq!(
            slot(&[(None, NoAnswer, false), (Some(2), Busy, false)]),
            (Why::RelayBusy, Some(2))
        );
        assert_eq!(
            slot(&[(Some(1), NoAnswer, false), (None, NotARelay, false)]),
            (Why::RelayOff, None)
        );
        assert_eq!(
            slot(&[(Some(1), NoAnswer, false), (Some(2), NoAnswer, false)]),
            (Why::RelayAsleep, Some(1))
        );
        // Not a relay reason: no slot, even when ours answered.
        assert_eq!(
            slot(&[(Some(1), NotOnRelay, false)]),
            (Why::ContactOffline, None)
        );
        // Only slots 1 and 2 exist.
        assert_eq!(
            slot(&[(Some(3), NoAnswer, false)]),
            (Why::RelayAsleep, None)
        );
        let closed = DialSummary {
            target_closed_at_once: true,
            ..circuits(&[(Some(1), Refused, false)])
        };
        let d = diagnose(&closed, &me(ReachClass::Unknown), &TheirFacts::default()).unwrap();
        assert_eq!((d.why, d.relay), (Why::NotAdmitted, None));
    }

    #[test]
    fn stale_and_src_flags_only_for_their_reasons() {
        let them = TheirFacts {
            from_card_only: true,
            hint_expired: true,
            heard_s: Some(42),
        };
        let mut seen = HashSet::new();
        let mut shapes: Vec<(DialSummary, MyFacts)> = dial_shapes()
            .into_iter()
            .map(|d| (d, me(ReachClass::Unknown)))
            .collect();
        for class in ReachClass::ALL {
            shapes.push((DialSummary::default(), me(class)));
        }
        shapes.push((
            DialSummary::default(),
            MyFacts {
                no_default_route: true,
                ..MyFacts::default()
            },
        ));
        for f in [
            LanFacts {
                lan_off: true,
                ..LanFacts::default()
            },
            LanFacts {
                beacon_no_answer: true,
                ..LanFacts::default()
            },
        ] {
            let got = diagnose_lan(&f, &them).unwrap();
            seen.insert(got.why);
            assert!(!got.stale && !got.from_card && got.relay.is_none());
            assert_eq!((got.heard_s, got.asof_s), (Some(42), None));
        }
        for (d, facts) in &shapes {
            let got = diagnose(d, facts, &them).unwrap();
            seen.insert(got.why);
            assert_eq!(
                got.stale,
                matches!(
                    got.why,
                    Why::ContactOffline | Why::RelayAsleep | Why::DirectFailed
                ),
                "{got:?}"
            );
            assert_eq!(
                got.from_card,
                matches!(got.why, Why::BothNat | Why::NoRelay),
                "{got:?}"
            );
            assert_eq!((got.heard_s, got.asof_s), (Some(42), None));
            // Without those facts, never.
            let bare = diagnose(d, facts, &TheirFacts::default()).unwrap();
            assert!(!bare.stale && !bare.from_card && bare.heard_s.is_none());
        }
        assert_eq!(seen.len(), Why::ALL.len(), "every reason is covered");
    }

    fn diag(why: Why) -> Diag {
        Diag {
            why,
            me: Some(ReachClass::Unknown),
            relay: None,
            heard_s: None,
            stale: false,
            from_card: false,
            asof_s: None,
        }
    }

    /// Circles: unknown, empty, offers only, reachable only, both.
    fn circles() -> Vec<CircleFacts> {
        let known = |offers: Vec<[u8; 32]>, reachable: Vec<[u8; 32]>| CircleFacts {
            known: true,
            offers,
            reachable,
            offers_in_use: 1,
            p2p_contacts: 3,
            mail: MailPath::NoFix,
        };
        vec![
            CircleFacts::default(),
            known(Vec::new(), Vec::new()),
            known(vec![[1; 32], [2; 32]], Vec::new()),
            known(Vec::new(), vec![[3; 32]]),
            known(vec![[4; 32]], vec![[5; 32]]),
        ]
    }

    #[test]
    fn pick_fix_table() {
        let nobody = CircleFacts {
            known: true,
            ..CircleFacts::default()
        };
        for (w, want) in [
            (Why::ContactOffline, Fix::WaitUntilOnline),
            (Why::DirectFailed, Fix::WaitUntilOnline),
            (Why::RelayBusy, Fix::RetryLater),
            (Why::RelayOff, Fix::TheyNeedNewRelay),
            (Why::NotAdmitted, Fix::ResendCard),
            (Why::RelayAsleep, Fix::WakeRelay),
            (Why::RelayRefused, Fix::AskRelayOwner),
        ] {
            for circle in circles() {
                for (public, relaying) in [(false, false), (true, false), (true, true)] {
                    assert_eq!(pick_fix(&diag(w), public, relaying, &circle), want);
                }
            }
        }
        // D2: offering relaying only for a confirmed public node that does
        // not relay yet; Mapped (not confirmed) waits for the contact.
        let no_relay = |class| Diag {
            me: Some(class),
            ..diag(Why::NoRelay)
        };
        assert_eq!(
            pick_fix(&no_relay(ReachClass::Public), true, false, &nobody),
            Fix::OfferRelaying
        );
        assert_eq!(
            pick_fix(&no_relay(ReachClass::Public), true, true, &nobody),
            Fix::TheyWriteFirst
        );
        assert_eq!(
            pick_fix(&no_relay(ReachClass::Mapped), false, false, &nobody),
            Fix::TheyWriteFirst
        );
        assert_eq!(
            pick_fix(&no_relay(ReachClass::Relayed), false, false, &circles()[4]),
            Fix::TheyWriteFirst
        );
        // Both behind NAT: an offering friend first, then a reachable one,
        // else nobody; an unknown circle gives the generic text.
        let both = diag(Why::BothNat);
        let got: Vec<Fix> = circles()
            .iter()
            .map(|c| pick_fix(&both, false, false, c))
            .collect();
        assert_eq!(
            got,
            [
                Fix::Generic,
                Fix::NobodyReachable,
                Fix::AskFriend([1; 32]),
                Fix::AskFriend([3; 32]),
                Fix::AskFriend([4; 32]),
            ]
        );
        // No route: LocalOnly with every circle and every flag.
        for circle in circles() {
            for public in [false, true] {
                for relaying in [false, true] {
                    assert_eq!(
                        pick_fix(&diag(Why::NoRoute), public, relaying, &circle),
                        Fix::LocalOnly
                    );
                }
            }
        }
        // `raven lan off`: LanOn with every circle, flag and mail path.
        for mut circle in circles() {
            for mail in [MailPath::NoFix, MailPath::MailboxOff, MailPath::NoFriend] {
                circle.mail = mail;
                for public in [false, true] {
                    for relaying in [false, true] {
                        assert_eq!(
                            pick_fix(&diag(Why::LanOff), public, relaying, &circle),
                            Fix::LanOn
                        );
                    }
                }
            }
        }
        // An offline contact with no friend to hold its mail: turn
        // mailboxes on, or ask an always-on friend to hold mail; waiting
        // otherwise (and for every reason that is not "offline").
        for w in [Why::ContactOffline, Why::DirectFailed, Why::LanNoAnswer] {
            for mut circle in circles() {
                for (mail, want) in [
                    (MailPath::NoFix, Fix::WaitUntilOnline),
                    (MailPath::MailboxOff, Fix::UseMailbox),
                    (MailPath::NoFriend, Fix::AskFriendToHoldMail),
                ] {
                    circle.mail = mail;
                    for (public, relaying) in [(false, false), (true, false), (true, true)] {
                        assert_eq!(pick_fix(&diag(w), public, relaying, &circle), want);
                    }
                }
            }
        }
        for w in Why::ALL {
            if matches!(
                w,
                Why::ContactOffline | Why::DirectFailed | Why::LanNoAnswer
            ) {
                continue;
            }
            for mail in [MailPath::MailboxOff, MailPath::NoFriend] {
                let circle = CircleFacts {
                    mail,
                    ..nobody.clone()
                };
                let fix = pick_fix(&diag(w), false, false, &circle);
                assert!(
                    !matches!(fix, Fix::UseMailbox | Fix::AskFriendToHoldMail),
                    "{w:?}"
                );
            }
        }
    }

    fn every_fix() -> [Fix; 15] {
        [
            Fix::WaitUntilOnline,
            Fix::RetryLater,
            Fix::AskFriendToHoldMail,
            Fix::UseMailbox,
            Fix::LanOn,
            Fix::TheyWriteFirst,
            Fix::TheyNeedNewRelay,
            Fix::ResendCard,
            Fix::WakeRelay,
            Fix::AskRelayOwner,
            Fix::OfferRelaying,
            Fix::AskFriend([9; 32]),
            Fix::NobodyReachable,
            Fix::LocalOnly,
            Fix::Generic,
        ]
    }

    #[test]
    fn fix_priority_is_total_and_nobody_reachable_wins() {
        let all = every_fix();
        // Distinct, but for the two that need nothing done.
        for a in all {
            for b in all {
                let tie = a.priority() == b.priority();
                let same = a == b
                    || matches!(
                        (a, b),
                        (Fix::Generic, Fix::WaitUntilOnline) | (Fix::WaitUntilOnline, Fix::Generic)
                    );
                assert_eq!(tie, same, "{a:?} {b:?}");
            }
        }
        // Among the internet-side fixes (not the two local ones).
        let best = all
            .into_iter()
            .filter(|f| !matches!(f, Fix::LocalOnly | Fix::LanOn))
            .max_by_key(|f| f.priority());
        assert_eq!(best, Some(Fix::NobodyReachable));
        // The mailbox fixes are worth more than waiting, less than any
        // relay or NAT fix.
        for f in [Fix::UseMailbox, Fix::AskFriendToHoldMail] {
            assert!(f.priority() > Fix::RetryLater.priority());
            assert!(f.priority() < Fix::TheyWriteFirst.priority());
        }
        assert!(Fix::AskFriend([0; 32]).priority() > Fix::OfferRelaying.priority());
        assert_eq!(
            Fix::Generic.priority(),
            Fix::WaitUntilOnline.priority(),
            "neither asks anything"
        );
    }

    /// A section with any `no_route` row shows LocalOnly, unless one says
    /// `raven lan off` (then LanOn: the local network is the one way left).
    #[test]
    fn fix_priority_is_total_and_local_only_wins() {
        let all = every_fix();
        assert!(all
            .iter()
            .filter(|f| !matches!(f, Fix::LocalOnly | Fix::LanOn))
            .all(|f| f.priority() < Fix::LocalOnly.priority()));
        let nobody = CircleFacts {
            known: true,
            ..CircleFacts::default()
        };
        let section: Vec<Fix> = [Why::BothNat, Why::NoRoute, Why::RelayRefused]
            .into_iter()
            .map(|w| pick_fix(&diag(w), false, false, &nobody))
            .collect();
        assert_eq!(
            section.into_iter().max_by_key(|f| f.priority()),
            Some(Fix::LocalOnly)
        );
    }

    /// `raven lan on` beats every other fix: a section with any `lan_off`
    /// row shows it, even with no route to the internet.
    #[test]
    fn lan_on_wins_over_every_fix() {
        assert!(every_fix()
            .iter()
            .filter(|f| **f != Fix::LanOn)
            .all(|f| f.priority() < Fix::LanOn.priority()));
        let mailbox_off = CircleFacts {
            known: true,
            mail: MailPath::MailboxOff,
            ..CircleFacts::default()
        };
        let section: Vec<Fix> = [
            Why::ContactOffline,
            Why::NoRoute,
            Why::LanNoAnswer,
            Why::LanOff,
            Why::BothNat,
        ]
        .into_iter()
        .map(|w| pick_fix(&diag(w), false, false, &mailbox_off))
        .collect();
        assert_eq!(
            section.into_iter().max_by_key(|f| f.priority()),
            Some(Fix::LanOn)
        );
    }

    /// The commands the new fixes name, word for word.
    #[test]
    fn the_local_network_and_mailbox_commands() {
        assert_eq!(LAN_ON_CMD, "raven lan on");
        assert_eq!(MAILBOX_CMD, "raven custody use on");
        assert_eq!(HOLD_MAIL_CMD, "raven node custody on");
    }

    /// A mailbox fix only while learned custody is live: the gates closed
    /// (a release build) give none, whatever the files say; with them
    /// open, a policy that never answered `raven custody use` is
    /// MailboxOff, one that said yes is NoFriend (no friend can take mail
    /// for this contact), one that said no or cannot be read is none.
    #[test]
    fn mail_path_follows_the_gates_and_the_mailbox_answer() {
        use crate::custody_gate::{set_custody_hints_for_this_thread, CustodyGates};
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let (local, peer) = (key(1), key(2));
        let set = |use_: Option<bool>| {
            let p = crate::node_policy::NodePolicy {
                custody_use: use_,
                ..Default::default()
            };
            crate::node_policy::save_policy(dd, &p).unwrap();
        };
        set(None);
        if !cfg!(debug_assertions) {
            // A release build ignores the per-thread overrides below (CI runs
            // `reach_diag::` in release with every lab switch set): the gates
            // hold, so no mail fix whatever the policy says.
            assert_eq!(mail_path(dd, &local, &peer, NOW), MailPath::NoFix);
            set(Some(true));
            assert_eq!(mail_path(dd, &local, &peer, NOW), MailPath::NoFix);
            return;
        }
        set_custody_hints_for_this_thread(Some(false));
        assert_eq!(mail_path(dd, &local, &peer, NOW), MailPath::NoFix);
        set_custody_hints_for_this_thread(Some(true));
        crate::custody_gate::set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        assert_eq!(mail_path(dd, &local, &peer, NOW), MailPath::MailboxOff);
        set(Some(true));
        assert_eq!(mail_path(dd, &local, &peer, NOW), MailPath::NoFriend);
        set(Some(false));
        assert_eq!(mail_path(dd, &local, &peer, NOW), MailPath::NoFix);
        std::fs::write(dd.join("node_policy.json"), b"{not json").unwrap();
        assert_eq!(mail_path(dd, &local, &peer, NOW), MailPath::NoFix);
        set_custody_hints_for_this_thread(None);
        crate::custody_gate::set_custody_gates_for_this_thread(None);
    }

    /// Ages in their written (rounded-down) form.
    const AGES: [u64; 9] = [
        0,
        59,
        119,
        2 * 60,
        119 * 60,
        2 * 3_600,
        47 * 3_600,
        2 * 86_400,
        400 * 86_400,
    ];

    fn every_diag() -> Vec<Diag> {
        let mut out = Vec::new();
        let mes: Vec<Option<ReachClass>> = std::iter::once(None)
            .chain(ReachClass::ALL.map(Some))
            .collect();
        for why in Why::ALL {
            for me in &mes {
                for relay in [None, Some(1), Some(2)] {
                    for (i, heard_s) in std::iter::once(None).chain(AGES.map(Some)).enumerate() {
                        for flags in 0..4u8 {
                            out.push(Diag {
                                why,
                                me: *me,
                                relay,
                                heard_s,
                                stale: flags & 1 != 0,
                                from_card: flags & 2 != 0,
                                asof_s: (i % 3 != 0).then_some(AGES[i % AGES.len()]),
                            });
                        }
                    }
                }
            }
        }
        out
    }

    #[test]
    fn diag_render_find_round_trip_for_every_reason_and_flag() {
        for d in every_diag() {
            let r = d.render();
            assert_eq!(Diag::find(&r), Some(d.clone()), "{r}");
            assert_eq!(Diag::find(&format!("P2P_UNREACHABLE: x; {r}")), Some(d));
        }
        let d = Diag {
            why: Why::BothNat,
            me: Some(ReachClass::Unreachable),
            relay: None,
            heard_s: None,
            stale: false,
            from_card: true,
            asof_s: None,
        };
        assert_eq!(d.render(), "reach: why=both_nat me=unreachable src=card");
        let d = Diag {
            why: Why::RelayAsleep,
            me: Some(ReachClass::Relayed),
            relay: Some(2),
            heard_s: Some(3 * 3_600 + 59),
            stale: true,
            from_card: false,
            asof_s: Some(30),
        };
        assert_eq!(
            d.render(),
            "reach: why=relay_asleep me=relayed relay=mine2 heard=3h stale=1 asof=30s"
        );
        assert_eq!(
            Diag {
                why: Why::NoRoute,
                me: None,
                ..d.clone()
            }
            .render(),
            "reach: why=no_route relay=mine2 heard=3h stale=1 asof=30s"
        );
        // Ages are rounded down, and read back as written.
        for (secs, text, back) in [
            (90, "90s", 90),
            (200, "3m", 180),
            (7_199, "119m", 7_140),
            (3 * 86_400 + 5, "3d", 3 * 86_400),
        ] {
            let d = Diag {
                heard_s: Some(secs),
                ..diag(Why::ContactOffline)
            };
            let r = d.render();
            assert!(r.ends_with(&format!(" heard={text}")), "{r}");
            assert_eq!(Diag::find(&r).unwrap().heard_s, Some(back));
        }
        assert_eq!(
            Diag::find("reach: why=no_route me=unknown"),
            Some(diag(Why::NoRoute))
        );
        // The local network reasons (Phase 3).
        for (why, text) in [
            (Why::LanOff, "reach: why=lan_off"),
            (Why::LanNoAnswer, "reach: why=lan_no_answer heard=5m"),
        ] {
            let d = Diag::find(text).unwrap();
            assert_eq!(d.why, why);
            assert_eq!(d.render(), text);
            assert_eq!(Diag::find(&format!("x; {text}; y")), Some(d));
        }
        assert_eq!(Diag::find("reach: why=LAN_OFF"), None);
    }

    #[test]
    fn find_takes_the_last_block_of_a_joined_multi_route_text() {
        let joined =
            "lan_dial NOT_REACHABLE: nothing listens; reach: why=contact_offline heard=3h; \
                      p2p_dial P2P_UNREACHABLE: the contact is unreachable; reach: why=both_nat \
                      me=unreachable src=card; internet_dial NOT_REACHABLE: no answer";
        let d = Diag::find(joined).unwrap();
        assert_eq!(
            (d.why, d.me, d.from_card, d.heard_s),
            (Why::BothNat, Some(ReachClass::Unreachable), true, None)
        );
        // Inside "(technical: …)": the block ends at ')'.
        let wrapped = "not delivered (technical: ipc P2P_DIAL: P2P_UNREACHABLE: unreachable; \
                       reach: why=relay_asleep relay=mine1) more text me=public";
        let d = Diag::find(wrapped).unwrap();
        assert_eq!((d.why, d.relay, d.me), (Why::RelayAsleep, Some(1), None));
        // A line end ends it too.
        let d = Diag::find("x; reach: why=no_relay\nme=public src=card").unwrap();
        assert_eq!((d.why, d.me, d.from_card), (Why::NoRelay, None, false));
        // The last block decides, even when an earlier one is known.
        assert_eq!(
            Diag::find("reach: why=both_nat; reach: why=gremlins me=public"),
            None
        );
        assert_eq!(Diag::find("P2P_UNREACHABLE: no reason here"), None);
    }

    #[test]
    fn find_ignores_unknown_keys_and_rejects_unknown_reasons() {
        let d =
            Diag::find("reach: why=both_nat future=7 me=unreachable x tag=a=b src=card").unwrap();
        assert_eq!(
            d,
            Diag {
                me: Some(ReachClass::Unreachable),
                from_card: true,
                ..diag(Why::BothNat)
            }
        );
        // Values a key does not take are skipped, never guessed.
        let d = Diag::find(
            "reach: why=relay_busy me=moon relay=mine3 relay=yours heard=3x heard=h \
             heard=99999999999999999999d asof=-5s stale=2 stale=yes src=lan",
        )
        .unwrap();
        assert_eq!(
            d,
            Diag {
                me: None,
                ..diag(Why::RelayBusy)
            }
        );
        // A later valid value wins; a bad one keeps the earlier.
        let d = Diag::find("reach: why=relay_off heard=5m heard=bad me=public me=mapped").unwrap();
        assert_eq!((d.heard_s, d.me), (Some(300), Some(ReachClass::Mapped)));
        for unknown in [
            "reach: why=moon_phase me=public",
            "reach: why=",
            "reach: why= both_nat",
            "reach: why=BOTH_NAT",
            "reach: why=both_nat_v2",
            "reach: me=public why=both_nat",
            "reach:why=both_nat",
        ] {
            assert_eq!(Diag::find(unknown), None, "{unknown}");
        }
    }

    /// No '/' or ':' after the tag, no run of letters and digits long enough
    /// for a key, a PeerId or a hex string (the longest is an age in days),
    /// only lowercase words, digits, '_', '=' and ' ', and at most
    /// [`MAX_RENDERED`] bytes, even with every key at its widest.
    #[test]
    fn rendered_blocks_have_no_slash_colon_long_hex_or_name_and_fit_120_bytes() {
        let mut blocks: Vec<String> = every_diag().iter().map(Diag::render).collect();
        for why in Why::ALL {
            blocks.push(
                Diag {
                    why,
                    me: Some(ReachClass::Unreachable),
                    relay: Some(2),
                    heard_s: Some(u64::MAX),
                    stale: true,
                    from_card: true,
                    asof_s: Some(u64::MAX),
                }
                .render(),
            );
        }
        let widest = blocks.iter().map(String::len).max().unwrap();
        assert!(widest <= MAX_RENDERED, "{widest}");
        for r in &blocks {
            let body = r.strip_prefix(REACH_TAG).expect(r);
            assert!(!body.contains(['/', ':']), "{r}");
            assert!(
                body.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_= ".contains(c)),
                "{r}"
            );
            let longest = body
                .split(|c: char| !c.is_ascii_alphanumeric())
                .map(str::len)
                .max()
                .unwrap_or(0);
            assert!(longest <= 16, "{r}");
            assert!(!r.contains("12D3KooW"));
            assert_eq!(
                Diag::find(r).map(|d| d.render()).as_deref(),
                Some(r.as_str())
            );
        }
    }

    #[test]
    fn find_is_char_boundary_safe_on_non_ascii_input() {
        let wide = [
            format!("{REACH_TAG}both_nat {}", "é".repeat(80)),
            format!("{REACH_TAG}both_nat me={}", "€".repeat(60)),
            format!("{REACH_TAG}both_nat me=public{}", "\u{1F600}".repeat(40)),
            format!("ñ€{REACH_TAG}no_route me=unknown ✓"),
            format!("{REACH_TAG}relay_off heard=3ｈ src=card"),
            "reach: why=no_relay\u{2028}me=public".to_string(),
        ];
        for s in &wide {
            for (i, _) in s.char_indices() {
                let _ = Diag::find(&s[i..]);
                let _ = Diag::find(&s[..i]);
            }
            if let Some(d) = Diag::find(s) {
                assert_eq!(Diag::find(&d.render()), Some(d));
            }
        }
        // The 120-byte cut lands inside a character: the block before it
        // still reads.
        let s = format!("{REACH_TAG}both_nat src=card {}", "é".repeat(60));
        assert!(!s.is_char_boundary(MAX_RENDERED));
        let d = Diag::find(&s).unwrap();
        assert_eq!((d.why, d.from_card), (Why::BothNat, true));
        let d = Diag::find(&format!("ñ€{REACH_TAG}no_route me=unknown ✓")).unwrap();
        assert_eq!(d, diag(Why::NoRoute));
        let d = Diag::find(&format!("{REACH_TAG}relay_off heard=3ｈ src=card")).unwrap();
        assert_eq!((d.why, d.heard_s, d.from_card), (Why::RelayOff, None, true));
    }

    // ── circle_facts ─────────────────────────────────────────────────────

    const MIN: u64 = 60 * 1000;
    const NOW: u64 = 20_000 * 24 * 60 * MIN;

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn pid(seed: u8) -> String {
        crate::p2p_route::local_peer_id(&crate::identity::Identity::from_seed(&[seed; 32]))
    }

    /// A card: the contact's PeerId (seed `n`) and, when `direct`, a
    /// `via=` naming its own PeerId, else one through a relay.
    fn row(n: u8, pinned: bool, direct: bool) -> serde_json::Value {
        let own = pid(n);
        let via = if direct {
            format!("/ip4/11.0.0.{n}/tcp/7423/p2p/{own}")
        } else {
            format!("/ip4/11.0.9.9/tcp/7423/p2p/{}", pid(0xee))
        };
        serde_json::json!({
            "pub_hex": hex::encode(key(n)),
            "petname": format!("contact {n}"),
            "pinned": pinned,
            "p2p": own,
            "p2p_via": [via],
        })
    }

    /// A route hints snapshot from contact `n`: its PeerId, a global direct
    /// address when `direct`, and a friend relay offer when `offer`;
    /// expiring at `expires`.
    fn hint(n: u8, direct: bool, offer: bool, expires: u64) -> serde_json::Value {
        let own = pid(n);
        let mut e = serde_json::json!({
            "pub_hex": hex::encode(key(n)),
            "generation": 1,
            "received_at_ms": NOW - 10 * MIN,
            "expires_at_ms": expires,
            "via": "p2p",
            "peer_id": own,
        });
        if direct {
            e["direct"] = serde_json::json!([format!("/ip4/11.0.3.{n}/tcp/7423/p2p/{own}")]);
        }
        if offer {
            e["offers"] = serde_json::json!([{
                "relay_peer_id": pid(n.wrapping_add(0x80)),
                "addrs": [format!("/ip4/11.0.4.{n}/tcp/7427")],
                "flags": 1,
            }]);
        }
        e
    }

    fn write(dir: &Path, name: &str, v: &serde_json::Value) {
        std::fs::write(dir.join(name), serde_json::to_vec(v).unwrap()).unwrap();
    }

    #[test]
    fn circle_facts_reads_pinned_unblocked_contacts_in_book_order() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        // No book: an empty circle, known.
        assert_eq!(
            circle_facts(dd, NOW),
            Ok(CircleFacts {
                known: true,
                ..CircleFacts::default()
            })
        );
        let live = NOW + 60 * MIN;
        let book = serde_json::json!([
            row(1, true, true),   // card direct
            row(2, false, true),  // not verified
            row(3, true, true),   // blocked
            row(4, true, false),  // live hint with a direct address
            row(5, true, true),   // live hint naming no direct address: not reachable
            row(6, true, false),  // offers (unexpired)
            row(7, true, true),   // offers, expired snapshot: card direct counts, no offer
            row(8, true, true),   // a second row unpinned: not verified
            row(8, false, true),
            row(9, true, true),   // card direct (the 4th card one)
            row(10, true, true),  // card direct (over the cap)
            {"pub_hex": "zz", "pinned": true},
            {"pub_hex": hex::encode(key(11)), "pinned": true}, // no PeerId
        ]);
        write(dd, "contacts.json", &book);
        write(
            dd,
            "blocked_pubs.json",
            &serde_json::json!({ "pub_hex": [hex::encode(key(3))] }),
        );
        write(
            dd,
            crate::learned_routes::LEARNED_ROUTES_FILE,
            &serde_json::json!([
                hint(4, true, false, live),
                hint(5, false, false, live),
                hint(6, false, true, live),
                {
                    "pub_hex": hex::encode(key(7)),
                    "generation": 1,
                    "received_at_ms": NOW - 80 * 60 * MIN,
                    "expires_at_ms": NOW - 8 * 60 * MIN,
                    "via": "p2p",
                    "offers": [{
                        "relay_peer_id": pid(0x87),
                        "addrs": ["/ip4/11.0.4.7/tcp/7427"],
                        "flags": 1,
                    }],
                },
                hint(2, true, true, live),
                hint(3, true, true, live),
            ]),
        );
        let facts = circle_facts(dd, NOW).unwrap();
        assert!(facts.known);
        assert_eq!(facts.offers, [key(6)]);
        // Learned first (4), then card-only in book order, at most 4.
        assert_eq!(facts.reachable, [key(4), key(1), key(7), key(9)]);
        assert_eq!(facts.offers_in_use, 0);
        // 1, 4, 5, 6, 7, 9, 10 have a PeerId (11 has none).
        assert_eq!(facts.p2p_contacts, 7);

        // Automatic choice holds contact 6's offered relay.
        let mem = crate::relay_select::RelayMemory {
            selected: vec![pid(0x86), pid(0x99)],
            ..crate::relay_select::RelayMemory::default()
        };
        crate::relay_select::save_memory(dd, &mem).unwrap();
        assert_eq!(circle_facts(dd, NOW).unwrap().offers_in_use, 1);

        // At most MAX_CIRCLE offers, in book order.
        let many: Vec<serde_json::Value> = (20..27).map(|n| row(n, true, false)).collect();
        write(dd, "contacts.json", &serde_json::Value::Array(many));
        write(
            dd,
            crate::learned_routes::LEARNED_ROUTES_FILE,
            &serde_json::Value::Array((20..27).rev().map(|n| hint(n, false, true, live)).collect()),
        );
        let facts = circle_facts(dd, NOW).unwrap();
        assert_eq!(facts.offers, [key(20), key(21), key(22), key(23)]);
        assert!(facts.reachable.is_empty());
        assert_eq!(facts.p2p_contacts, 7);

        // A corrupt book or block list: Err (callers use known: false).
        std::fs::write(dd.join("contacts.json"), b"{not json").unwrap();
        assert!(circle_facts(dd, NOW).is_err());
        write(dd, "contacts.json", &book);
        std::fs::write(dd.join("blocked_pubs.json"), b"[[").unwrap();
        assert!(circle_facts(dd, NOW).is_err());
    }

    /// A card's (or `contact set-addr --via`'s) direct address makes a
    /// contact "reachable from the internet" only on a global IP or a DNS
    /// name: a LAN, unique-local or loopback address says nothing about the
    /// internet, so the fix never asks that contact to offer relaying. The
    /// debug local-candidates switch (`lab_local`) admits any IP, for the
    /// one-machine harness (carrier_matrix C26 (f)).
    #[test]
    fn a_card_direct_address_counts_only_on_a_global_ip_or_a_name() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let card = |n: u8, host: &str| {
            let own = pid(n);
            serde_json::json!({
                "pub_hex": hex::encode(key(n)),
                "pinned": true,
                "p2p": own,
                "p2p_via": [format!("{host}/tcp/7423/p2p/{own}")],
            })
        };
        write(
            dd,
            "contacts.json",
            &serde_json::json!([
                card(1, "/ip4/192.168.1.20"),
                card(2, "/ip4/127.0.0.1"),
                card(3, "/ip6/fd00::3"),
                card(4, "/ip4/10.0.0.4"),
                card(5, "/ip4/11.0.0.5"),
                card(6, "/dns4/carol.example.org"),
                card(7, "/ip6/2a00:1450::7"),
            ]),
        );
        let facts = circle_facts_with(dd, NOW, false).unwrap();
        assert_eq!(facts.reachable, [key(5), key(6), key(7)]);
        // Every one of them still has a PeerId.
        assert_eq!(facts.p2p_contacts, 7);
        let lab = circle_facts_with(dd, NOW, true).unwrap();
        assert_eq!(lab.reachable, [key(1), key(2), key(3), key(4)]);
        // With nobody else reachable, the fix for both_nat is no friend.
        let only_lan = serde_json::json!([card(1, "/ip4/192.168.1.20")]);
        write(dd, "contacts.json", &only_lan);
        let facts = circle_facts_with(dd, NOW, false).unwrap();
        let d = diag(Why::BothNat);
        assert_eq!(pick_fix(&d, false, false, &facts), Fix::NobodyReachable);
    }
}
