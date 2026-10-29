//! Cards, friends and verification: `card.*`, `contacts.*`, `verify.*`.
//!
//! Every save goes through the CLI's `add_contact_with_routes` (through the
//! engine bridge), so the desktop app, `raven` and `ash` share one contact
//! list and one rule for pinning. Blind entry: nothing here returns a
//! friend's security words or old code, and every error text has the codes
//! of friends not verified taken out.

use std::net::SocketAddr;

use ash_engine::engine::{self as bridge, ContactView, FriendPreview};
use raven_core::security_words::{self, ParseError, Verdict};
use serde_json::{json, Map, Value};

use crate::engine::{lock, Inner};
use crate::envelope::{code, ApiError, Args, OpResult};
use crate::identity::{avatar_index, short_address};
use crate::messages::PresenceInfo;
use crate::node::Reach;
use crate::safety;
use crate::settings;

/// A paste longer than this, or with more lines, holds no invite or card.
const PASTE_MAX_BYTES: usize = 8 * 1024;
const PASTE_MAX_LINES: usize = 32;

/// The words of the CLI's card and invite refusals that mean the address,
/// the key and the code don't belong together (the terminal app's
/// controller.rs `TAMPER_MARKS`).
const TAMPER_MARKS: &[&str] = &[
    "does not belong to its pub_hex",
    "address/pub mismatch",
    "fingerprint does not match its key",
];

/// Labels of the ways to reach a friend (desktop/design/strings.en.json).
const LABEL_LAN: &str = "Local network (Wi-Fi or cable)";
const LABEL_INTERNET: &str = "Internet direct";
const LABEL_P2P: &str = "Peer-to-peer and relays";

/// Why a paste is not a friend to add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PasteProblem {
    NotACard(String),
    Tampered(String),
    OwnInvite,
}

impl PasteProblem {
    fn into_error(self) -> ApiError {
        match self {
            PasteProblem::NotACard(why) => ApiError::of(code::CARD_INVALID, why),
            PasteProblem::Tampered(why) => ApiError::new(
                code::CARD_INVALID,
                "This invite doesn't add up: its address and key don't match. Ask your friend \
                 to send it again.",
                why,
            ),
            PasteProblem::OwnInvite => ApiError::new(
                code::CARD_INVALID,
                "That's your own invite. Paste your friend's instead.",
                "the pasted key is this profile's own",
            ),
        }
    }
}

/// A friend's invite or card from pasted text (the terminal app's
/// controller.rs `parse_friend_paste`): line breaks normalised, then the
/// lines joined with a space, joined with nothing (a line broken inside a
/// word), then each line on its own (a whoami block). Exactly one identity
/// must come out; the user's own is refused.
pub(crate) fn parse_friend_paste(
    text: &str,
    me_pub_hex: &str,
) -> Result<FriendPreview, PasteProblem> {
    if text.len() > PASTE_MAX_BYTES {
        return Err(PasteProblem::NotACard(format!(
            "more than {PASTE_MAX_BYTES} bytes: longer than any invite or card"
        )));
    }
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<String> = text
        .lines()
        .map(|line| line.replace('\t', " ").trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() {
        return Err(PasteProblem::NotACard("nothing was pasted".into()));
    }
    if lines.len() > PASTE_MAX_LINES {
        return Err(PasteProblem::NotACard(format!(
            "more than {PASTE_MAX_LINES} lines: an invite or a card is one line"
        )));
    }
    let mut candidates = vec![lines.join(" "), lines.concat()];
    if lines.len() > 1 {
        candidates.extend(lines);
    }
    candidates.dedup();

    let mut found: Option<FriendPreview> = None;
    let mut tampered: Option<String> = None;
    let mut card_like: Option<String> = None;
    let mut other: Option<String> = None;
    for candidate in &candidates {
        match bridge::parse_card_or_invite(candidate) {
            Ok(friend) => match &found {
                None => found = Some(friend),
                Some(first) if first.pub_hex == friend.pub_hex => {}
                Some(_) => {
                    return Err(PasteProblem::NotACard(
                        "the pasted text holds more than one Raven identity".into(),
                    ))
                }
            },
            Err(why) if TAMPER_MARKS.iter().any(|mark| why.contains(mark)) => {
                tampered.get_or_insert(why);
            }
            Err(why) if bridge::looks_like_card_or_invite(candidate) => {
                card_like.get_or_insert(why);
            }
            Err(why) => {
                other.get_or_insert(why);
            }
        }
    }
    match found {
        Some(friend) if friend.pub_hex.eq_ignore_ascii_case(me_pub_hex.trim()) => {
            Err(PasteProblem::OwnInvite)
        }
        Some(friend) => Ok(friend),
        None => Err(match tampered {
            Some(why) => PasteProblem::Tampered(why),
            None => PasteProblem::NotACard(card_like.or(other).unwrap_or_default()),
        }),
    }
}

/// Look-alike letters and the Latin letter each passes for (the terminal
/// app's controller.rs `CONFUSABLES`).
const CONFUSABLES: &[(char, char)] = &[
    ('\u{0430}', 'a'),
    ('\u{0435}', 'e'),
    ('\u{043E}', 'o'),
    ('\u{0440}', 'p'),
    ('\u{0441}', 'c'),
    ('\u{0443}', 'y'),
    ('\u{0445}', 'x'),
    ('\u{0456}', 'i'),
    ('\u{0458}', 'j'),
    ('\u{03BF}', 'o'),
    ('\u{03B1}', 'a'),
    ('\u{03B5}', 'e'),
    ('\u{03C1}', 'p'),
    ('\u{03BD}', 'v'),
];

fn name_key(name: &str) -> String {
    raven_core::sanitize::sanitize_terminal_line(name.trim()).to_lowercase()
}

fn fold_confusables(name: &str) -> String {
    name.chars()
        .map(|c| {
            CONFUSABLES
                .iter()
                .find(|(from, _)| *from == c)
                .map_or(c, |(_, to)| *to)
        })
        .collect()
}

/// Whether `name` may be given to the friend with key `pub_hex`: not the
/// name of another friend (ignoring case, as the CLI compares petnames), and
/// not one that only looks like a verified friend's (the terminal app's
/// `check_name`).
fn check_name(contacts: &[ContactView], name: &str, pub_hex: &str) -> Result<(), ApiError> {
    let want = name_key(name);
    let folded = fold_confusables(&want);
    for other in contacts
        .iter()
        .filter(|c| !c.pub_hex.eq_ignore_ascii_case(pub_hex.trim()))
    {
        let theirs = name_key(&other.label);
        if theirs == want || (other.pinned && fold_confusables(&theirs) == folded) {
            return Err(ApiError::of(
                code::NAME_CLASH,
                format!(
                    "another friend ({}) already has this name or one that looks the same",
                    short_address(&other.address)
                ),
            ));
        }
    }
    Ok(())
}

/// A name for a friend as given: one clean line, not empty.
fn friend_name(raw: &str) -> Result<String, ApiError> {
    settings::clean_name(raw).ok_or_else(|| {
        ApiError::new(
            code::BAD_REQUEST,
            "Give your friend a name.",
            "the name is empty",
        )
    })
}

/// Digits typed in another script (Persian, Arabic-Indic, full-width) as
/// ASCII; everything else unchanged. For a LAN address only: the old code
/// folds as the CLI folds it (`verify_check_old_code`).
fn fold_digits(text: &str) -> String {
    text.chars().map(security_words::fold_digit).collect()
}

/// The security code of a key given as hex; None when it is not a key.
fn code_of(pub_hex: &str) -> Option<String> {
    let key: [u8; 32] = hex::decode(pub_hex.trim()).ok()?.try_into().ok()?;
    Some(raven_core::fingerprint::device_fingerprint_v1(&key))
}

fn key_of(c: &ContactView) -> Result<[u8; 32], ApiError> {
    hex::decode(c.pub_hex.trim())
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| ApiError::internal("the saved key of this friend does not parse"))
}

/// A refused change to a friend (the CLI's error) as an API error, with the
/// codes of friends not verified (and of `subject`, unless verified now)
/// taken out.
fn contact_error(text: &str, unverified_codes: &[String]) -> ApiError {
    let detail = safety::hide_codes(text, unverified_codes);
    let l = text.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    if text.contains("KEY_CHANGE_REFUSED_WITHOUT_REPIN") {
        ApiError::new(
            code::CARD_INVALID,
            "You verified this person with a different key, so nothing was saved. If they set up \
             Raven again, check with them in person or by phone, remove the old friend, then add \
             them again.",
            detail,
        )
    } else if has(&[
        "is already used by another contact",
        "choose a distinct --petname",
    ]) {
        ApiError::of(code::NAME_CLASH, detail)
    } else if has(&["contacts.json"]) {
        ApiError::new(
            code::PROFILE_UNREADABLE,
            "Your friends list can't be read. Open Details.",
            detail,
        )
    } else if has(&["block list"]) {
        ApiError::new(
            code::PROFILE_UNREADABLE,
            "Your block list can't be read. Open Details.",
            detail,
        )
    } else if has(&[
        "contact not found",
        "no contact matched",
        "not saved on this computer",
    ]) {
        ApiError::of(code::NOT_A_CONTACT, detail)
    } else if TAMPER_MARKS.iter().any(|m| text.contains(m)) || has(&["address must be valid"]) {
        ApiError::of(code::CARD_INVALID, detail)
    } else if has(&["lan_dial must look like host:port"]) {
        ApiError::new(
            code::BAD_REQUEST,
            "That isn't an address Raven can use. It looks like 192.168.1.30:7420.",
            detail,
        )
    } else if has(&["internet address", "not a network address", "p2p:"]) {
        ApiError::new(
            code::CARD_INVALID,
            "The invite has an address Raven can't use. Ask your friend to send it again.",
            detail,
        )
    } else {
        ApiError::new(
            code::INTERNAL,
            "Raven couldn't save this change. Open Details.",
            detail,
        )
    }
}

/// `verify.word_hint`: the Raven word a prefix of at least 3 letters names.
/// It says nothing about a friend's words (it takes no friend); `known` says
/// only whether the text is a Raven word.
pub(crate) fn word_hint(args: &Args) -> OpResult {
    let prefix = args.str("prefix")?;
    let token = prefix.trim();
    let letters = token.chars().filter(|c| c.is_alphabetic()).count();
    let resolved = security_words::resolve(token).ok();
    let mut out = Map::new();
    if let (true, Some(i)) = (letters >= security_words::MIN_PREFIX, resolved) {
        out.insert(
            "word".into(),
            security_words::list_v1()[usize::from(i)].into(),
        );
    }
    out.insert("known".into(), resolved.is_some().into());
    Ok(Value::Object(out))
}

/// The Raven address of a key given as hex; None when it isn't one.
pub(crate) fn address_of_hex(pub_hex: &str) -> Option<String> {
    hex::decode(pub_hex.trim())
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .map(|k| raven_core::encode_address(&k))
}

impl Inner {
    /// One friend in API.md's `Contact` shape, with their unread messages
    /// (`unread`, 0 when not known).
    pub(crate) fn contact_json(
        &self,
        c: &ContactView,
        presence: Option<&PresenceInfo>,
        unread: Option<usize>,
    ) -> Value {
        let mut map = Map::new();
        map.insert("address".into(), c.address.clone().into());
        let name: String = safety::line(&c.label).chars().take(200).collect();
        map.insert("name".into(), name.into());
        map.insert(
            "short_address".into(),
            short_address(&safety::line(&c.address)).into(),
        );
        map.insert("verified".into(), c.pinned.into());
        let presence_word = presence
            .map_or(if has_address(c) { "none" } else { "no_address" }, |p| {
                p.presence
            });
        map.insert("presence".into(), presence_word.into());
        if let Some(p) = presence {
            if let Some(ms) = p.last_contact_ms {
                map.insert("last_contact_ms".into(), ms.into());
            }
            if let Some((count, until)) = p.waiting {
                map.insert(
                    "waiting".into(),
                    json!({"count": count, "until_ms": until.unwrap_or(0)}),
                );
            }
        }
        map.insert("avatar_index".into(), avatar_index(&c.address).into());
        if !c.lan_dial.trim().is_empty() {
            map.insert("lan".into(), safety::line(&c.lan_dial).into());
        }
        map.insert("blocked".into(), c.blocked.into());
        map.insert("unread".into(), unread.unwrap_or(0).into());
        Value::Object(map)
    }

    /// The codes of every saved friend not verified, for [`contact_error`].
    fn unverified_codes(&self, also: &str) -> Vec<String> {
        let mut codes: Vec<String> = self
            .contacts()
            .map(|list| {
                list.iter()
                    .filter(|c| !c.pinned)
                    .filter_map(|c| code_of(&c.pub_hex))
                    .collect()
            })
            .unwrap_or_default();
        codes.extend(code_of(also));
        codes
    }

    /// The saved friend at `address`, as one `Contact`, with presence and
    /// unread count.
    fn contact_result(&self, address: &str) -> OpResult {
        let c = self.contact(address)?;
        let peer = c.pub_hex.to_ascii_lowercase();
        let snap = self.refresh(std::time::Duration::from_millis(1500)).ok();
        let presence = snap.as_ref().and_then(|s| s.presence.get(&peer).cloned());
        let unread = snap.as_ref().and_then(|s| s.unread.get(&peer).copied());
        Ok(json!({"contact": self.contact_json(&c, presence.as_ref(), unread)}))
    }

    pub(crate) fn card_make(&self, args: &Args) -> OpResult {
        let id = self.identity()?;
        let dir = self.data_dir()?;
        let include = args.opt_bool("include_address")?.unwrap_or(false);
        let me = crate::identity::me_words(&id);
        let (lan, why_not) = if include {
            self.card_lan()
        } else {
            (None, None)
        };
        let card = bridge::card_line(dir, &id, lan.as_deref().unwrap_or(""))
            .map_err(|why| ApiError::internal(format!("card: {why}")))?;
        let mut result = json!({"card": card, "invite": me.invite});
        if let Some(lan) = lan {
            result["address_included"] = lan.into();
        }
        if let Some(why) = why_not {
            // Asked for an address, none could be given: why (an extra
            // field): "not_receiving", "this_computer_only", "no_network".
            result["address_missing"] = why.into();
        }
        Ok(result)
    }

    /// The address a card offers for this computer: where raven-node listens
    /// (with every address bound, this computer's own IPv4 address and that
    /// port), never a listener on this computer only (the terminal app's
    /// controller.rs `card_lan`).
    fn card_lan(&self) -> (Option<String>, Option<&'static str>) {
        let Ok(dir) = self.data_dir() else {
            return (None, Some("not_receiving"));
        };
        let probe = crate::node::probe(dir);
        let listen = match (probe.reach, probe.listen.as_deref()) {
            (Reach::Listening, Some(listen)) => listen.to_owned(),
            (Reach::LocalOnly, _) => return (None, Some("this_computer_only")),
            _ => return (None, Some("not_receiving")),
        };
        let Ok(bound) = listen.trim().parse::<SocketAddr>() else {
            return (None, Some("not_receiving"));
        };
        if bound.ip().is_loopback() {
            return (None, Some("this_computer_only"));
        }
        if bound.port() == 0 {
            return (None, Some("not_receiving"));
        }
        if bound.ip().is_unspecified() {
            return match raven_core::route_memory::egress_addrs().0 {
                Some(ip) => (Some(SocketAddr::from((ip, bound.port())).to_string()), None),
                None => (None, Some("no_network")),
            };
        }
        (Some(bound.to_string()), None)
    }

    pub(crate) fn card_parse(&self, args: &Args) -> OpResult {
        let text = args.str("text")?;
        let id = self.identity()?;
        let friend = parse_friend_paste(text, &hex::encode(id.public_key_bytes()))
            .map_err(PasteProblem::into_error)?;
        let mut routes = Vec::new();
        if !friend.lan.is_empty() {
            routes.push(json!({"kind": "lan", "label": LABEL_LAN,
                               "preview": !raven_core::LAN_DIRECT_PRODUCTION_ENABLED}));
        }
        if !friend.internet.is_empty() {
            routes.push(json!({"kind": "internet", "label": LABEL_INTERNET,
                               "preview": !raven_core::INTERNET_DIRECT_PRODUCTION_ENABLED}));
        }
        if friend.p2p.is_some() {
            routes.push(json!({"kind": "p2p", "label": LABEL_P2P,
                               "preview": !raven_core::P2P_PRODUCTION_ENABLED}));
        }
        let saved = self
            .contacts()?
            .iter()
            .find(|c| c.pub_hex.eq_ignore_ascii_case(&friend.pub_hex))
            .map(|c| c.pinned);
        Ok(json!({
            "short_address": short_address(&friend.address),
            "has_address": !routes.is_empty(),
            "routes": routes,
            // Extra fields: the friend's full address (public), and whether
            // they are saved already (and verified).
            "address": friend.address,
            "already_saved": saved.is_some(),
            "already_verified": saved.unwrap_or(false),
            // Route kinds the card named that were left out (no key signs a
            // card's addresses), and the one line to show about them.
            "ignored_routes": friend.ignored_routes,
            "note": bridge::ignored_routes_note(&friend),
        }))
    }

    pub(crate) fn contacts_list(&self) -> OpResult {
        self.identity()?;
        let snap = self.refresh(std::time::Duration::from_millis(1500))?;
        let list: Vec<Value> = snap
            .contacts
            .iter()
            .map(|c| {
                let peer = c.pub_hex.to_ascii_lowercase();
                self.contact_json(c, snap.presence.get(&peer), snap.unread.get(&peer).copied())
            })
            .collect();
        Ok(json!({"contacts": list}))
    }

    pub(crate) fn contacts_add(&self, args: &Args) -> OpResult {
        let text = args.str("text")?;
        let name = friend_name(args.str("name")?)?;
        let id = self.identity()?;
        let dir = self.data_dir()?;
        let friend = parse_friend_paste(text, &hex::encode(id.public_key_bytes()))
            .map_err(PasteProblem::into_error)?;
        {
            let _guard = lock(&self.contacts_lock);
            check_name(&self.contacts()?, &name, &friend.pub_hex)?;
            let codes = self.unverified_codes(&friend.pub_hex);
            // Saved as not verified (an existing pin is kept by the CLI).
            bridge::add_contact_with_routes(
                dir,
                &friend.address,
                &friend.pub_hex,
                &name,
                None,
                &friend.lan,
                &friend.internet,
                friend.p2p.as_ref(),
            )
            .map_err(|e| contact_error(&e, &codes))?;
            // The card's Tor onion binding: the friend can be reached over
            // Tor as soon as they are verified (E2 r40 P1).
            bridge::keep_card_onion(dir, &friend.pub_hex, friend.onion.as_deref())
                .map_err(|e| contact_error(&e, &codes))?;
            self.invalidate_contacts();
        }
        self.contact_result(&friend.address)
    }

    pub(crate) fn contacts_rename(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        let name = friend_name(args.str("name")?)?;
        let dir = self.data_dir()?;
        {
            let _guard = lock(&self.contacts_lock);
            let c = self.contact(address)?;
            check_name(&self.contacts()?, &name, &c.pub_hex)?;
            let codes = self.unverified_codes(&c.pub_hex);
            // No code and no route: the pin and the routes stay.
            bridge::add_contact_with_routes(dir, &c.address, &c.pub_hex, &name, None, "", "", None)
                .map_err(|e| contact_error(&e, &codes))?;
            self.invalidate_contacts();
        }
        self.contact_result(address)
    }

    pub(crate) fn contacts_remove(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        let dir = self.data_dir()?;
        let _guard = lock(&self.contacts_lock);
        let c = self.contact(address)?;
        let codes = self.unverified_codes(&c.pub_hex);
        bridge::remove_contact(dir, &c.address).map_err(|e| contact_error(&e, &codes))?;
        self.invalidate_contacts();
        lock(&self.mismatches).remove(&c.pub_hex.to_ascii_lowercase());
        Ok(json!({}))
    }

    pub(crate) fn contacts_set_address(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        let lan = fold_digits(args.str("lan")?).trim().to_owned();
        let dir = self.data_dir()?;
        {
            let _guard = lock(&self.contacts_lock);
            let c = self.contact(address)?;
            let codes = self.unverified_codes(&c.pub_hex);
            let lan = bridge::parse_lan_dial(&lan).map_err(|e| contact_error(&e, &codes))?;
            bridge::set_contact_lan(dir, &c.address, &lan)
                .map_err(|e| contact_error(&e, &codes))?;
            self.invalidate_contacts();
        }
        self.contact_result(address)
    }

    /// Pins the friend as verified through the CLI's save path: `fp` is the
    /// code the CLI checks against the key's own before it pins.
    fn pin(&self, c: &ContactView, fp: &str) -> Result<(), ApiError> {
        let dir = self.data_dir()?;
        let _guard = lock(&self.contacts_lock);
        let codes = self.unverified_codes(&c.pub_hex);
        bridge::add_contact_with_routes(dir, &c.address, &c.pub_hex, "", Some(fp), "", "", None)
            .map_err(|e| contact_error(&e, &codes))?;
        self.invalidate_contacts();
        Ok(())
    }

    fn note_mismatch(&self, c: &ContactView) -> u32 {
        let mut counts = lock(&self.mismatches);
        let n = counts.entry(c.pub_hex.to_ascii_lowercase()).or_insert(0);
        *n += 1;
        *n
    }

    /// `verify.check_words`: the 10 words the friend read out, typed blind,
    /// against their key. `match` pins them; `typo` (the check word caught a
    /// misheard, swapped or unknown word: read them again) and `mismatch`
    /// (do not verify) change nothing. The friend's words are never returned.
    pub(crate) fn verify_check_words(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        let typed = match args.get("words") {
            Some(Value::Array(items)) => {
                let mut words = Vec::with_capacity(items.len());
                for item in items {
                    let word = item
                        .as_str()
                        .ok_or_else(|| ApiError::bad_request("\"words\" must hold strings"))?;
                    words.push(word.to_owned());
                }
                words.join(" ")
            }
            Some(Value::String(text)) => text.clone(),
            Some(_) => return Err(ApiError::bad_request("\"words\" must be a list of words")),
            None => return Err(ApiError::bad_request("\"words\" is missing")),
        };
        self.identity()?;
        let c = self.contact(address)?;
        self.check_words_of(&c, &typed)
    }

    /// Typed words against `c`'s key: [`Inner::verify_check_words`]'s
    /// answer (also for words typed where the old code goes).
    fn check_words_of(&self, c: &ContactView, typed: &str) -> OpResult {
        let key = key_of(c)?;
        let (result, why) = match security_words::compare(typed, &key) {
            Verdict::Match => ("match", None),
            Verdict::Mismatch => ("mismatch", None),
            Verdict::Invalid(
                e @ (ParseError::Empty
                | ParseError::WrongCount { .. }
                | ParseError::Ambiguous { .. }),
            ) => {
                let detail = match (e, e.position()) {
                    (ParseError::WrongCount { count }, _) => {
                        format!("{count} words typed, 10 needed")
                    }
                    (_, Some(at)) => format!("word {at}: {}", e.status()),
                    _ => e.status().to_owned(),
                };
                return Err(ApiError::of(code::WORDS_INCOMPLETE, detail));
            }
            // Read from the typed text alone: safe to say which word.
            Verdict::Invalid(e) => ("typo", Some(e)),
        };
        let mut out = Map::new();
        out.insert("result".into(), result.into());
        match result {
            "match" => {
                let fp = raven_core::fingerprint::device_fingerprint_v1(&key);
                self.pin(c, &fp)?;
                lock(&self.mismatches).remove(&c.pub_hex.to_ascii_lowercase());
                let contact = self.contact_result(&c.address)?;
                out.insert("contact".into(), contact["contact"].clone());
            }
            "typo" => {
                if let Some(e) = why {
                    out.insert("reason".into(), e.status().into());
                    if let Some(at) = e.position() {
                        out.insert("position".into(), at.into());
                    }
                }
            }
            _ => {
                out.insert("mismatches".into(), self.note_mismatch(c).into());
            }
        }
        Ok(Value::Object(out))
    }

    /// `verify.check_old_code`: the old letters-and-digits code, for friends
    /// with an older Raven, by the CLI's one comparator (cli.rs
    /// `security_check`, RAVEN_SECURITY_WORDS_V1.md section 8): an entry of
    /// 4 or more tokens is security words and is checked as
    /// `verify.check_words` checks them; anything shorter is the old code,
    /// separators ignored, the letters' case not, and only Persian and
    /// Arabic-Indic digits folded (cli.rs's `fingerprint_matches`). `match`
    /// pins through the CLI, which checks the code again.
    pub(crate) fn verify_check_old_code(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        let typed = args.str("code")?;
        self.identity()?;
        let c = self.contact(address)?;
        if security_words::looks_like_words(typed) {
            return self.check_words_of(&c, typed);
        }
        let key = key_of(&c)?;
        let fp = raven_core::fingerprint::device_fingerprint_v1(&key);
        if typed.trim().is_empty() {
            return Err(ApiError::new(
                code::BAD_REQUEST,
                "Type the code your friend reads to you.",
                "the code is empty",
            ));
        }
        if bridge::fingerprint_matches(typed, &fp) {
            self.pin(&c, typed)?;
            let contact = self.contact_result(&c.address)?;
            return Ok(json!({"result": "match", "contact": contact["contact"]}));
        }
        Ok(json!({
            "result": "mismatch",
            // The right letters in the wrong case (the CLI's case hint).
            "case_only": bridge::fingerprint_case_only_mismatch(typed, &fp),
            "mismatches": self.note_mismatch(&c),
        }))
    }
}

fn has_address(c: &ContactView) -> bool {
    [&c.lan_dial, &c.internet_dial, &c.p2p]
        .iter()
        .any(|route| !route.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::identity::Identity;

    fn invite(id: &Identity) -> String {
        format!(
            "raven:{}:{}",
            id.address(),
            hex::encode(id.public_key_bytes())
        )
    }

    #[test]
    fn pastes_parse_and_own_or_tampered_ones_are_refused() {
        let me = Identity::from_seed(&[1; 32]);
        let friend = Identity::from_seed(&[2; 32]);
        let me_hex = hex::encode(me.public_key_bytes());
        let got = parse_friend_paste(&format!("  {}\n", invite(&friend)), &me_hex).unwrap();
        assert_eq!(got.pub_hex, hex::encode(friend.public_key_bytes()));
        // A line a terminal broke in two still parses.
        let line = invite(&friend);
        let (a, b) = line.split_at(30);
        assert!(parse_friend_paste(&format!("{a}\n{b}"), &me_hex).is_ok());
        assert_eq!(
            parse_friend_paste(&invite(&me), &me_hex),
            Err(PasteProblem::OwnInvite)
        );
        // Another key's address with this key.
        let tampered = format!(
            "raven:{}:{}",
            me.address(),
            hex::encode(friend.public_key_bytes())
        );
        assert!(matches!(
            parse_friend_paste(&tampered, &me_hex),
            Err(PasteProblem::Tampered(_))
        ));
        assert!(matches!(
            parse_friend_paste("hello", &me_hex),
            Err(PasteProblem::NotACard(_))
        ));
        assert!(matches!(
            parse_friend_paste("", &me_hex),
            Err(PasteProblem::NotACard(_))
        ));
    }

    fn view(label: &str, key: u8, pinned: bool) -> ContactView {
        let id = Identity::from_seed(&[key; 32]);
        ContactView {
            pub_hex: hex::encode(id.public_key_bytes()),
            address: id.address(),
            label: label.into(),
            petname: label.into(),
            pinned,
            blocked: false,
            lan_dial: String::new(),
            internet_dial: String::new(),
            p2p: String::new(),
        }
    }

    #[test]
    fn names_clash_by_case_and_by_look_alike_letters_of_verified_friends() {
        let list = vec![view("Office", 3, true), view("Desk", 4, false)];
        let new_key = hex::encode(Identity::from_seed(&[9; 32]).public_key_bytes());
        assert!(check_name(&list, "Garden", &new_key).is_ok());
        assert_eq!(
            check_name(&list, "office", &new_key).unwrap_err().code,
            code::NAME_CLASH
        );
        // Cyrillic o in place of the Latin one, against a verified friend.
        assert_eq!(
            check_name(&list, "\u{043E}ffice", &new_key)
                .unwrap_err()
                .code,
            code::NAME_CLASH
        );
        // The same friend may keep their own name.
        assert!(check_name(&list, "Desk", &list[1].pub_hex).is_ok());
    }

    #[test]
    fn contact_errors_never_show_an_unverified_code() {
        let codes = vec!["If4x-36FU-omFi".to_string()];
        let e = contact_error(
            "petname \"x\" is already used by another contact (fp=If4x-36FU-omFi) — choose",
            &codes,
        );
        assert_eq!(e.code, code::NAME_CLASH);
        assert!(!e.detail.contains("If4x"), "{}", e.detail);
    }

    #[test]
    fn word_hints_complete_after_three_letters() {
        let args = |p: &str| {
            let mut m = Map::new();
            m.insert("prefix".into(), p.into());
            m
        };
        assert_eq!(
            word_hint(&Args(&args("tu"))).unwrap(),
            json!({"known": false})
        );
        assert_eq!(
            word_hint(&Args(&args("tur"))).unwrap(),
            json!({"word": "turtle", "known": true})
        );
        assert_eq!(
            word_hint(&Args(&args("TURTLES"))).unwrap(),
            json!({"word": "turtle", "known": true})
        );
        assert_eq!(
            word_hint(&Args(&args("xyz"))).unwrap(),
            json!({"known": false})
        );
    }
}
