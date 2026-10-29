//! The privacy pack's profile rules on the engine, as cli.rs's `run` applies
//! them before every command: sealed profiles (the at-rest key loaded by the
//! engine itself, also when another process sealed the profile), the
//! refusals while an erase or a key change is unfinished, and `raven lock`.
//!
//! This binary seals every profile it makes: it sets the lab switch
//! `RAVEN_LAB_AT_REST=1` (a debug build seals only with it; a release build
//! always seals) for itself and the raven-node processes it starts.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Once;

use common::{err, ok, raw, short_dir};
use raven_client::Client;
use raven_core::identity::Identity;
use serde_json::{json, Value};

/// The lab environment, with sealing on for this whole binary.
fn sealed_lab() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        common::lab_env();
        std::env::set_var(raven_core::lan_gate::LAB_AT_REST, "1");
    });
}

struct Profile {
    _dir: tempfile::TempDir,
    path: PathBuf,
    client: Client,
    me: Value,
}

fn profile(name: &str) -> Profile {
    sealed_lab();
    let dir = short_dir();
    let path = dir.path().join("p");
    let client = Client::with_data_dir(&path);
    assert_eq!(ok(&client, "profile.state", json!({}))["state"], "new");
    ok(&client, "settings.set", json!({"receive": false}));
    ok(&client, "identity.create", json!({"display_name": name}));
    let me = ok(&client, "identity.me", json!({}));
    Profile {
        _dir: dir,
        path,
        client,
        me,
    }
}

fn sealed(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|bytes| bytes.starts_with(b"RMS1"))
}

/// A friend's invite, made from a seed (no profile behind it).
fn invite(seed: u8) -> (String, String) {
    let id = Identity::from_seed(&[seed; 32]);
    let address = id.address();
    (
        format!("raven:{address}:{}", hex::encode(id.public_key_bytes())),
        address,
    )
}

fn names(list: &Value) -> Vec<String> {
    list["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_owned())
        .collect()
}

/// The reviewers' reproduction: a sealed profile's friends list, history
/// and settings, read and written by the engine, also after the key left
/// this process (another process sealed the profile) and in a new engine.
#[test]
fn a_sealed_profile_is_read_and_written_by_the_engine() {
    let a = profile("Desk A");
    // Sealed when the identity was made, as the CLI's next command would.
    assert_eq!(
        raven_core::privacy::mode(&a.path),
        raven_core::at_rest::Mode::Sealed
    );
    let state = ok(&a.client, "privacy.state", json!({}));
    assert_eq!(
        state,
        json!({"available": false, "encrypted": true, "locked": false})
    );
    // The name is sealed in its own file; the plain settings name nobody.
    assert!(sealed(&a.path.join("desktop_private.rms")));
    let plain = std::fs::read_to_string(a.path.join("desktop_settings.json")).unwrap();
    assert!(!plain.contains("Desk A"), "{plain}");
    assert!(!plain.contains("keep_chats_days"), "{plain}");

    let (friend, friend_address) = invite(0x42);
    ok(
        &a.client,
        "contacts.add",
        json!({"text": friend, "name": "Friend F"}),
    );
    assert!(sealed(&a.path.join("contacts.json")));
    assert_eq!(
        names(&ok(&a.client, "contacts.list", json!({}))),
        ["Friend F"]
    );
    let history = ok(
        &a.client,
        "messages.history",
        json!({"address": friend_address, "limit": 10}),
    );
    assert!(
        history["messages"].as_array().unwrap().is_empty(),
        "{history}"
    );

    // The key leaves this process (as for an engine that was open when
    // raven-node sealed the profile): the next operation loads it again.
    raven_core::at_rest::forget_cached_keys(&a.path);
    assert_eq!(
        names(&ok(&a.client, "contacts.list", json!({}))),
        ["Friend F"]
    );
    let (other, _) = invite(0x43);
    ok(
        &a.client,
        "contacts.add",
        json!({"text": other, "name": "Friend G"}),
    );
    ok(
        &a.client,
        "settings.set",
        json!({"display_name": "Desk A2", "keep_chats_days": 90}),
    );

    // A new engine on the same profile (the app opened again).
    raven_core::at_rest::forget_cached_keys(&a.path);
    let again = Client::with_data_dir(&a.path);
    assert_eq!(ok(&again, "profile.state", json!({}))["state"], "ready");
    assert_eq!(
        names(&ok(&again, "contacts.list", json!({}))),
        ["Friend F", "Friend G"]
    );
    let me = ok(&again, "identity.me", json!({}));
    assert_eq!(me["display_name"], "Desk A2");
    assert_eq!(me["address"], a.me["address"]);
    let settings = ok(&again, "settings.get", json!({}));
    assert_eq!(settings["keep_chats_days"], 90);
    assert_eq!(settings["forget_addresses"], true);
    // The chat-keeping time is the privacy pack's own setting.
    assert_eq!(
        raven_core::privacy::chat_keep(&a.path),
        raven_core::privacy::ChatKeep::Days90
    );
    assert!(sealed(&a.path.join("desktop_private.rms")));
    let plain = std::fs::read_to_string(a.path.join("desktop_settings.json")).unwrap();
    assert!(!plain.contains("Desk A2"), "{plain}");
}

/// An older engine's settings file held the name: it moves to the sealed
/// file once the profile's key is loaded, and leaves the plain one.
#[test]
fn an_older_engines_name_leaves_the_plain_settings() {
    let a = profile("Desk M");
    std::fs::write(
        a.path.join("desktop_settings.json"),
        br#"{"display_name":"Old Name","receive":false,"reduced_motion":true,
             "when_quit":"ask","keep_chats_days":7,"forget_addresses":false,
             "lock_on_sleep":false}"#,
    )
    .unwrap();
    std::fs::remove_file(a.path.join("desktop_private.rms")).unwrap();
    raven_core::at_rest::forget_cached_keys(&a.path);
    let again = Client::with_data_dir(&a.path);
    assert_eq!(ok(&again, "profile.state", json!({}))["state"], "ready");
    let settings = ok(&again, "settings.get", json!({}));
    assert_eq!(settings["display_name"], "Old Name");
    assert_eq!(settings["reduced_motion"], true);
    assert_eq!(settings["forget_addresses"], true);
    let plain = std::fs::read_to_string(a.path.join("desktop_settings.json")).unwrap();
    assert!(!plain.contains("Old Name"), "{plain}");
    assert!(!plain.contains("forget_addresses"), "{plain}");
    assert!(sealed(&a.path.join("desktop_private.rms")));
}

/// The ops every app calls after an op was refused: still answered.
fn still_answers(client: &Client) {
    assert_eq!(raw(client, "app.info", json!({}))["ok"], true);
    assert_eq!(
        raw(client, "events.poll", json!({"after_seq": 0}))["ok"],
        true
    );
}

/// cli.rs's `run` closes the profile to everything but `raven erase` while
/// an erase is unfinished, and to everything but the command that finishes
/// it while a `raven privacy rotate-meta` is: so does the engine, and it
/// writes nothing then.
#[test]
fn an_unfinished_erase_or_key_change_closes_the_profile() {
    let a = profile("Desk E");
    let settings_file = a.path.join("desktop_settings.json");

    // An erase that did not finish.
    std::fs::write(a.path.join("erase_in_progress"), b"").unwrap();
    std::fs::remove_file(&settings_file).unwrap();
    let state = ok(&a.client, "profile.state", json!({}));
    assert_eq!(state["state"], "unreadable", "{state}");
    assert_eq!(state["reason"], raven_core::erase::UNFINISHED_TEXT);
    for (op, args) in [
        ("identity.me", json!({})),
        ("contacts.list", json!({})),
        ("settings.get", json!({})),
        ("settings.set", json!({"display_name": "Desk B"})),
        ("node.start", json!({})),
        ("privacy.unlock", json!({})),
    ] {
        assert_eq!(err(&a.client, op, args), "PROFILE_UNREADABLE", "{op}");
    }
    assert!(
        !settings_file.exists(),
        "nothing is written while it is erased"
    );
    still_answers(&a.client);
    std::fs::remove_file(a.path.join("erase_in_progress")).unwrap();
    assert_eq!(ok(&a.client, "profile.state", json!({}))["state"], "ready");

    // A key change (`raven privacy rotate-meta`) that did not finish: its
    // record in privacy.json.
    let privacy_file = a.path.join(raven_core::privacy::PRIVACY_FILE);
    let before = std::fs::read(&privacy_file).unwrap();
    let mut record: Value = serde_json::from_slice(&before).unwrap();
    record["meta_rotation"] = json!({"to": 2, "started_at_ms": 1});
    std::fs::write(&privacy_file, serde_json::to_vec(&record).unwrap()).unwrap();
    let state = ok(&a.client, "profile.state", json!({}));
    assert_eq!(state["state"], "unreadable", "{state}");
    assert_eq!(
        state["reason"],
        raven_core::privacy::META_ROTATION_UNFINISHED_TEXT
    );
    let (friend, _) = invite(0x44);
    assert_eq!(
        err(
            &a.client,
            "contacts.add",
            json!({"text": friend, "name": "F"})
        ),
        "PROFILE_UNREADABLE"
    );
    assert_eq!(
        err(&a.client, "settings.set", json!({"reduced_motion": true})),
        "PROFILE_UNREADABLE"
    );
    assert!(!settings_file.exists());
    still_answers(&a.client);
    std::fs::write(&privacy_file, &before).unwrap();
    assert_eq!(ok(&a.client, "profile.state", json!({}))["state"], "ready");
    assert!(ok(&a.client, "contacts.list", json!({}))["contacts"]
        .as_array()
        .unwrap()
        .is_empty());
}

/// `raven lock` (PP.15): the profile reads as locked, a start is refused as
/// locked, and the app's Unlock clears it as the terminal app's UNLOCK does.
#[test]
fn raven_lock_reads_as_locked_until_the_app_unlocks() {
    let a = profile("Desk L");
    raven_core::privacy::set_locked(&a.path, None).unwrap();
    let state = ok(&a.client, "profile.state", json!({}));
    assert_eq!(state["state"], "locked", "{state}");
    assert_eq!(ok(&a.client, "privacy.state", json!({}))["locked"], true);
    assert_eq!(err(&a.client, "node.start", json!({})), "PROFILE_LOCKED");
    let unlocked = ok(&a.client, "privacy.unlock", json!({}));
    assert_eq!(unlocked["state"], "ready", "{unlocked}");
    assert!(!raven_core::privacy::lock_state(&a.path).locked_by_user);
    assert_eq!(ok(&a.client, "privacy.state", json!({}))["locked"], false);
    // The other actions stay the CLI's.
    for op in ["privacy.lock", "privacy.encrypt", "privacy.erase"] {
        assert_eq!(err(&a.client, op, json!({})), "NOT_AVAILABLE_YET", "{op}");
    }
}

/// The delivery flow of tests/delivery.rs on sealed profiles (the engine
/// and both raven-node processes seal): it failed before the engine loaded
/// the at-rest key itself.
#[test]
fn delivered_on_sealed_profiles() {
    sealed_lab();
    common::flow::delivered_only_after_a_signed_receipt(|dir, client| {
        assert!(sealed(&dir.join("contacts.json")));
        assert_eq!(ok(client, "privacy.state", json!({}))["encrypted"], true);
    });
}
