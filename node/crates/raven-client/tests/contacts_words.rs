//! Two throwaway profiles, A and B, on two engines in this process: setup,
//! cards, friends, the security words and the old code. No raven-node runs.

mod common;

use common::{all_text, err, ok, raw, short_dir};
use raven_client::Client;
use serde_json::{json, Value};

struct Profile {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    client: Client,
    me: Value,
}

fn profile(name: &str) -> Profile {
    common::lab_env();
    let dir = short_dir();
    let path = dir.path().join("p");
    let client = Client::with_data_dir(&path);
    assert_eq!(ok(&client, "profile.state", json!({}))["state"], "new");
    // Chosen during setup, before the identity: kept in memory only.
    ok(&client, "settings.set", json!({"receive": false}));
    assert!(!path.join("desktop_settings.json").exists());
    let created = ok(&client, "identity.create", json!({"display_name": name}));
    assert_eq!(created["words"].as_array().unwrap().len(), 10);
    assert!(created["old_code"].as_str().unwrap().contains('-'));
    assert_eq!(ok(&client, "profile.state", json!({}))["state"], "ready");
    let me = ok(&client, "identity.me", json!({}));
    assert_eq!(me["address"], created["address"]);
    assert_eq!(me["words"], created["words"]);
    assert_eq!(me["display_name"], name);
    assert!(me["card"].as_str().unwrap().starts_with("raven-card/"));
    assert!(me["invite"].as_str().unwrap().starts_with("raven:rvn1"));
    // Written once the identity exists; the setup choice survived.
    let settings = ok(&client, "settings.get", json!({}));
    assert_eq!(settings["receive"], false);
    assert_eq!(settings["display_name"], name);
    assert!(path.join("desktop_settings.json").exists());
    Profile {
        _dir: dir,
        path,
        client,
        me,
    }
}

fn words(p: &Profile) -> Vec<String> {
    p.me["words"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap().to_owned())
        .collect()
}

/// The friend's words and code never appear in what `seen` returned.
fn assert_blind(seen: &Value, friend: &Profile) {
    let text = all_text(seen);
    let code = friend.me["old_code"].as_str().unwrap();
    assert!(!text.contains(code), "old code leaked: {text}");
    assert!(
        !text.contains(&words(friend).join(" ")),
        "words leaked: {text}"
    );
}

#[test]
fn cards_friends_words_and_old_code() {
    let a = profile("Desk A");
    let b = profile("Desk B");

    // Cards: B's card as A sees it, and refusals.
    let b_card = ok(&b.client, "card.make", json!({"include_address": false}));
    let b_card_text = b_card["card"].as_str().unwrap().to_owned();
    // No node listens, so no address can be included (and it says why).
    let with = ok(&b.client, "card.make", json!({"include_address": true}));
    assert!(with.get("address_included").is_none(), "{with}");
    assert_eq!(with["address_missing"], "not_receiving");
    let parsed = ok(&a.client, "card.parse", json!({"text": b_card_text}));
    assert_eq!(parsed["address"], b.me["address"]);
    assert_eq!(parsed["has_address"], false);
    assert_eq!(parsed["already_saved"], false);
    assert_blind(&parsed, &b);
    assert_eq!(
        err(&a.client, "card.parse", json!({"text": a.me["invite"]})),
        "CARD_INVALID"
    );
    assert_eq!(
        err(&a.client, "card.parse", json!({"text": "hello there"})),
        "CARD_INVALID"
    );
    // A card with a LAN route lists it.
    let lan_card = format!("{b_card_text} lan=192.168.1.20:7420");
    let lan_card = if b_card_text.starts_with("raven-card/1") {
        lan_card
    } else {
        b_card_text.clone()
    };
    let parsed = ok(&a.client, "card.parse", json!({"text": lan_card}));
    if parsed["has_address"] == true {
        assert_eq!(parsed["routes"][0]["kind"], "lan");
        assert_eq!(parsed["routes"][0]["preview"], false);
    }

    // Friends: saved as not verified, each with a name.
    assert_eq!(
        err(
            &a.client,
            "contacts.add",
            json!({"text": b_card_text, "name": "  "})
        ),
        "BAD_REQUEST"
    );
    let added = ok(
        &a.client,
        "contacts.add",
        json!({"text": b.me["invite"], "name": "Friend B\u{202E}"}),
    )["contact"]
        .clone();
    assert_eq!(added["address"], b.me["address"]);
    assert_eq!(added["name"], "Friend B");
    assert_eq!(added["verified"], false);
    assert_eq!(added["presence"], "no_address");
    assert_blind(&added, &b);
    ok(
        &b.client,
        "contacts.add",
        json!({"text": a.me["card"], "name": "Friend A"}),
    );
    // A second friend under the same name (any case) clashes.
    let c = profile("Desk C");
    assert_eq!(
        err(
            &a.client,
            "contacts.add",
            json!({"text": c.me["invite"], "name": "friend b"})
        ),
        "NAME_CLASH"
    );
    let list = ok(&a.client, "contacts.list", json!({}));
    assert_eq!(list["contacts"].as_array().unwrap().len(), 1);
    assert_blind(&list, &b);

    // Rename and address: digits typed in Persian are folded.
    let renamed = ok(
        &a.client,
        "contacts.rename",
        json!({"address": b.me["address"], "name": "Office"}),
    );
    assert_eq!(renamed["contact"]["name"], "Office");
    let moved = ok(
        &a.client,
        "contacts.set_address",
        json!({"address": b.me["address"],
               "lan": "\u{06F1}\u{06F9}\u{06F2}.168.1.30:\u{06F7}\u{06F4}\u{06F2}\u{06F0}"}),
    );
    assert_eq!(moved["contact"]["lan"], "192.168.1.30:7420");
    assert_eq!(moved["contact"]["presence"], "none");
    assert_eq!(
        err(
            &a.client,
            "contacts.set_address",
            json!({"address": b.me["address"], "lan": "not an address"})
        ),
        "BAD_REQUEST"
    );
    assert_eq!(
        err(
            &a.client,
            "contacts.rename",
            json!({"address": c.me["address"], "name": "x"})
        ),
        "NOT_A_CONTACT"
    );

    // Words: incomplete, a typo the check word catches, a mismatch, a match.
    let mut theirs = words(&b);
    let short: Vec<String> = theirs[..9].to_vec();
    assert_eq!(
        err(
            &a.client,
            "verify.check_words",
            json!({"address": b.me["address"], "words": short})
        ),
        "WORDS_INCOMPLETE"
    );
    let mut swapped = theirs.clone();
    swapped.swap(0, 1);
    if swapped != theirs {
        let typo = ok(
            &a.client,
            "verify.check_words",
            json!({"address": b.me["address"], "words": swapped}),
        );
        assert_eq!(typo["result"], "typo", "{typo}");
        assert_blind(&typo, &b);
    }
    let mut unknown = theirs.clone();
    unknown[3] = "xyzzy".into();
    let typo = ok(
        &a.client,
        "verify.check_words",
        json!({"address": b.me["address"], "words": unknown}),
    );
    assert_eq!(
        (typo["result"].as_str(), typo["position"].as_u64()),
        (Some("typo"), Some(4))
    );
    // C's words are 10 valid Raven words, but not B's.
    let wrong = ok(
        &a.client,
        "verify.check_words",
        json!({"address": b.me["address"], "words": words(&c)}),
    );
    assert_eq!(wrong["result"], "mismatch");
    assert_eq!(wrong["mismatches"], 1);
    assert_blind(&wrong, &b);
    assert_eq!(
        ok(&a.client, "contacts.list", json!({}))["contacts"][0]["verified"],
        false
    );
    // Typed as people type: capitals, first three letters, numbers.
    let spoken: Vec<String> = theirs
        .iter_mut()
        .enumerate()
        .map(|(i, w)| {
            if i % 2 == 0 {
                w[..3].to_uppercase()
            } else {
                format!("{}. {w}", i + 1)
            }
        })
        .collect();
    let matched = ok(
        &a.client,
        "verify.check_words",
        json!({"address": b.me["address"], "words": spoken}),
    );
    assert_eq!(matched["result"], "match", "{matched}");
    assert_eq!(matched["contact"]["verified"], true);
    // Pinned the way the CLI pins: contacts.json says so.
    let book: Value =
        serde_json::from_str(&std::fs::read_to_string(a.path.join("contacts.json")).unwrap())
            .unwrap();
    let row = book
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["address"] == b.me["address"])
        .unwrap();
    assert_eq!(row["pinned"], true);
    assert_eq!(row["petname"], "Office");
    assert_eq!(row["lan_dial"], "192.168.1.30:7420");

    // The old code, on B's side: case matters, separators don't.
    let code = a.me["old_code"].as_str().unwrap().to_owned();
    let flipped: String = code
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect();
    let miss = ok(
        &b.client,
        "verify.check_old_code",
        json!({"address": a.me["address"], "code": flipped}),
    );
    assert_eq!(miss["result"], "mismatch");
    assert_eq!(miss["case_only"], true);
    assert_blind(&miss, &a);
    let no_dashes = code.replace('-', " ");
    let hit = ok(
        &b.client,
        "verify.check_old_code",
        json!({"address": a.me["address"], "code": no_dashes}),
    );
    assert_eq!(hit["result"], "match");
    assert_eq!(hit["contact"]["verified"], true);

    // Hints complete from Raven's list only.
    assert_eq!(
        ok(&a.client, "verify.word_hint", json!({"prefix": "tur"}))["word"],
        "turtle"
    );
    assert!(ok(&a.client, "verify.word_hint", json!({"prefix": "tu"}))
        .get("word")
        .is_none());

    // Remove.
    ok(
        &a.client,
        "contacts.remove",
        json!({"address": b.me["address"]}),
    );
    assert!(ok(&a.client, "contacts.list", json!({}))["contacts"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        err(
            &a.client,
            "contacts.remove",
            json!({"address": b.me["address"]})
        ),
        "NOT_A_CONTACT"
    );
}

/// The old-code box takes what the CLI's one comparator takes (cli.rs
/// `security_check`, RAVEN_SECURITY_WORDS_V1.md section 8): 4 or more
/// tokens are words, checked as words; a code folds Persian and
/// Arabic-Indic digits only.
#[test]
fn the_old_code_box_checks_as_the_cli_does() {
    let a = profile("Desk W");
    let b = profile("Desk X");
    ok(
        &b.client,
        "contacts.add",
        json!({"text": a.me["invite"], "name": "Friend W"}),
    );
    let check = |code: &str| {
        ok(
            &b.client,
            "verify.check_old_code",
            json!({"address": a.me["address"], "code": code}),
        )
    };
    let code = a.me["old_code"].as_str().unwrap().to_owned();
    let in_script = |zero: u32| -> String {
        code.chars()
            .map(|c| match c.to_digit(10) {
                Some(d) => char::from_u32(zero + d).unwrap(),
                None => c,
            })
            .collect()
    };
    if code.chars().any(|c| c.is_ascii_digit()) {
        // Full-width digits are not the CLI's: no match.
        let wide = check(&in_script(0xFF10));
        assert_eq!(wide["result"], "mismatch", "{wide}");
        assert_eq!(wide["case_only"], false);
        assert_blind(&wide, &a);
    }
    // A's words with one unknown word: a typo of the words, not a mismatch.
    let mut typo_words = words(&a);
    typo_words[2] = "xyzzy".into();
    let typo = check(&typo_words.join(" "));
    assert_eq!(
        (typo["result"].as_str(), typo["position"].as_u64()),
        (Some("typo"), Some(3)),
        "{typo}"
    );
    // A's 10 words typed into the old-code box: a match, as the CLI says.
    let matched = check(&words(&a).join(" "));
    assert_eq!(matched["result"], "match", "{matched}");
    assert_eq!(matched["contact"]["verified"], true);
    assert_blind(&matched, &a);
    if code.chars().any(|c| c.is_ascii_digit()) {
        // Persian digits are folded.
        let persian = check(&in_script(0x06F0));
        assert_eq!(persian["result"], "match", "{persian}");
    }
}

#[test]
fn settings_are_checked_and_kept() {
    let a = profile("Desk D");
    let set = ok(
        &a.client,
        "settings.set",
        json!({"when_quit": "ask", "keep_chats_days": null, "reduced_motion": true}),
    );
    assert_eq!(set["when_quit"], "ask");
    assert_eq!(set["keep_chats_days"], Value::Null);
    assert_eq!(set["forget_addresses"], true);
    assert_eq!(
        err(&a.client, "settings.set", json!({"keep_chats_days": 12})),
        "BAD_REQUEST"
    );
    // The privacy pack forgets unused addresses; it can't be turned off.
    assert_eq!(
        err(
            &a.client,
            "settings.set",
            json!({"forget_addresses": false})
        ),
        "NOT_AVAILABLE_YET"
    );
    // The chat-keeping time is the pack's own setting (`raven chats keep`),
    // and the name has its own file: desktop_settings.json names nobody.
    assert_eq!(
        raven_core::privacy::chat_keep(&a.path),
        raven_core::privacy::ChatKeep::Always
    );
    let plain = std::fs::read_to_string(a.path.join("desktop_settings.json")).unwrap();
    assert!(
        !plain.contains("Desk D") && !plain.contains("keep_chats"),
        "{plain}"
    );
    let private = std::fs::read_to_string(a.path.join("desktop_private.rms")).unwrap();
    assert!(private.contains("Desk D"), "a plain profile: {private}");
    // A new engine on the same profile reads them back.
    let again = Client::with_data_dir(&a.path);
    let got = ok(&again, "settings.get", json!({}));
    assert_eq!(got["when_quit"], "ask");
    assert_eq!(got["reduced_motion"], true);
    assert_eq!(got["keep_chats_days"], Value::Null);
    assert_eq!(got["display_name"], "Desk D");
    // An engine never answers with a field named like a secret.
    let r = raw(&again, "identity.me", json!({}));
    for bad in ["seed", "private_key", "secret", "plaintext", "recovery"] {
        assert!(
            !all_text(&r).to_lowercase().contains(&format!("{bad} ")),
            "{r}"
        );
    }
}
