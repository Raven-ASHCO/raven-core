//! Groups with the gate closed (no lab switch in this process, as in a
//! release build): `groups.list` says `available: false` and every other
//! `groups.*` op is NOT_AVAILABLE_YET, with nothing read or written.

mod common;

use raven_client::Client;
use serde_json::json;

use common::{err, ok, short_dir};

#[test]
fn groups_are_not_available_without_the_lab_switches() {
    common::lab_env();
    let dir = short_dir();
    let path = dir.path().join("p");
    let client = Client::with_data_dir(&path);
    ok(&client, "settings.set", json!({"receive": false}));
    ok(&client, "identity.create", json!({"display_name": "Desk"}));
    let list = ok(&client, "groups.list", json!({}));
    assert_eq!(list["available"], false, "{list}");
    assert_eq!(list["groups"], json!([]));
    let group = "00112233445566778899aabbccddeeff";
    for (op, args) in [
        ("groups.get", json!({"group": group})),
        ("groups.create", json!({"name": "x", "members": []})),
        ("groups.add", json!({"group": group, "members": []})),
        ("groups.remove", json!({"group": group, "member": "rvn1x"})),
        ("groups.leave", json!({"group": group})),
        ("groups.history", json!({"group": group})),
        ("groups.send", json!({"group": group, "text": "hi"})),
        ("groups.mark_read", json!({"group": group})),
    ] {
        assert_eq!(err(&client, op, args), "NOT_AVAILABLE_YET", "{op}");
    }
    assert!(!path.join("groups.json").exists());
}
