//! PP.5 tests of the friend-key files: each one migrated, read by its
//! readers and written sealed; the noise pins' new file and an older
//! build's pins; quarantine copies and temp leftovers; the peer cache's
//! downgrade copies; bootstrap before and after the identity; the relay list
//! in a relay folder and in a profile; the byte scan. Profiles are temp
//! folders with an identity marker; keys come from the test build's lab
//! K_hist (never a keychain item).

use super::*;
use crate::at_rest::Advisory;
use crate::bootstrap::{save_bootstrap, try_load_bootstrap, BootstrapConfig};
use crate::chat_history::BlockList;
use crate::contact_book::tests::{profile, seal};
use crate::device_cert::{
    device_x25519_agree, ensure_local_device_certificate, load_device_registry_checked,
    load_or_create_device_x25519, save_device_registry, with_device_registry_lock,
    DeviceCertificate,
};
use crate::device_revocation::DeviceRevocationV1;
use crate::device_sync::{
    import_contact_sync_checked, seal_contact_sync, ContactSyncPlaintext, RevocationRecord,
    RevocationStore,
};
use crate::identity::Identity;
use crate::lan_noise_pin::{
    self, PinKey, NOISE_PIN_CORRUPT_FILE, NOISE_PIN_FILE, NOISE_PIN_SEALED_FILE,
};
use crate::lan_rlb1::LanBundle;
use crate::prekey_bundle::{PrekeyBundle, PrekeyStore, MLKEM768_EK_LEN};
use crate::relay_allow;
use serde_json::{json, Value};
use std::path::PathBuf;

const NOW: u64 = 20_000 * DAY_MS;
const DEVICE: &str = "ash-primary";
const BOB_LAN: &str = "192.168.1.44:7420";
const BOOT_PEER: &str = "192.168.1.77:7420";

fn id(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn hex_of(who: &Identity) -> String {
    hex::encode(who.public_key_bytes())
}

fn peer_id(who: &Identity) -> String {
    crate::p2p_route::local_peer_id(who)
}

/// `who`'s self-certified LAN bundle (certificate and prekey `prekey_id`),
/// valid now.
fn bundle_of(who: &Identity, prekey_id: u32) -> LanBundle {
    let now = crate::clock::now_ms();
    let start = now - 60_000 + u64::from(prekey_id);
    let end = now + 30 * DAY_MS;
    let cert = DeviceCertificate::issue(
        who,
        who.public_key_bytes(),
        [0x42; 32],
        DEVICE,
        start,
        end,
        0,
    )
    .unwrap();
    let prekey = PrekeyBundle {
        identity_ed25519_pub: who.public_key_bytes(),
        device_id: DEVICE.into(),
        x25519_pub: [7; 32],
        mlkem768_ek: vec![3; MLKEM768_EK_LEN],
        signed_prekey_id: prekey_id,
        one_time_prekey_id: 0,
        one_time_x25519_pub: None,
        created_at_ms: start,
        expires_at_ms: end,
        signature: [0; 64],
    }
    .sign(who)
    .unwrap();
    LanBundle { cert, prekey }
}

/// An RVDR1 claim of `owner` retiring `cert`'s lineage.
fn rvdr1_wire(owner: &Identity, cert: &DeviceCertificate) -> Vec<u8> {
    DeviceRevocationV1 {
        identity_address: owner.address(),
        device_id: cert.device_id.as_bytes().to_vec(),
        device_ed_pub: cert.device_ed_pub,
        device_x_pub: cert.device_x_pub,
        device_cert_hash: crate::pair_init::device_certificate_hash(cert).unwrap(),
        issuer_device_id: b"desk".to_vec(),
        issuer_seq: 1,
        revocation_id: [9u8; 16],
        reason_code: 1,
        created_at_ms: 10,
        signature: [0u8; 64],
    }
    .sign(owner)
    .unwrap()
    .encode()
    .unwrap()
}

/// The people of [`write_friend_files`]: me, Bob (a verified contact: his
/// certificate, prekey, noise pin, relay entry, route state, revoked phone)
/// and Eve (blocked).
struct Friends {
    me: Identity,
    bob: Identity,
    eve: Identity,
    bob_phone: DeviceCertificate,
}

/// A device sync blob of this computer's own device, issued at `at`.
fn sync_blob(me: &Identity, at: u64) -> Vec<u8> {
    seal_contact_sync(
        me,
        &ContactSyncPlaintext {
            schema: 1,
            from_device_id: DEVICE.into(),
            contacts: Vec::new(),
            issued_at_ms: at,
        },
    )
    .unwrap()
}

/// Every PP.5 file of a profile, written by its own writer (today's bytes
/// in a plain profile, sealed in a sealed one): the book with Bob, this
/// computer's device certificate and X25519 key, Bob's bundle through the
/// peer cache's dual write, the block list (Eve), Bob's revoked phone (a
/// record and an RVDR1 claim), a device-sync import, the route hint state
/// (as raven-node writes it), bootstrap peers, Bob's PeerId on the relay
/// list and the noise pin of Bob's computer.
fn write_friend_files(dd: &Path) -> Friends {
    let now = crate::clock::now_ms();
    let (me, bob, eve) = (id(0x51), id(0x52), id(0x53));
    let book = json!([{
        "petname": "Bob", "address": crate::encode_address(&bob.public_key_bytes()),
        "pub_hex": hex_of(&bob), "pinned": true,
    }]);
    crate::contact_book::write_rows(dd, book.as_array().unwrap()).unwrap();
    ensure_local_device_certificate(dd, &me, DEVICE).unwrap();
    crate::lan_dispatch::persist_trusted_peer_bundle(dd, &bundle_of(&bob, 1)).unwrap();
    BlockList {
        pub_hex: vec![hex_of(&eve)],
    }
    .save(dd)
    .unwrap();
    let bob_phone = DeviceCertificate::issue(
        &bob,
        id(0x54).public_key_bytes(),
        [0x43; 32],
        "bob-phone",
        1,
        u64::MAX / 2,
        1,
    )
    .unwrap();
    let mut revocations = RevocationStore::default();
    revocations
        .apply(RevocationRecord::issue(&bob, "bob-phone", 1, now, "lost").unwrap())
        .unwrap();
    revocations
        .apply_rvdr1(&bob.public_key_bytes(), &rvdr1_wire(&bob, &bob_phone))
        .unwrap();
    revocations.save(dd).unwrap();
    import_contact_sync_checked(dd, &me, &sync_blob(&me, now - 10_000), now).unwrap();
    at_rest::store_json(
        dd,
        &dd.join(crate::route_hints::ROUTE_HINTS_STATE_FILE),
        Kind::RouteHintsState,
        &json!({
            "generation": now, "global": "ab".repeat(32),
            "contacts": [{"pub_hex": hex_of(&bob), "digest": "cd".repeat(32)}],
            "lan": BOB_LAN,
        }),
    )
    .unwrap();
    let mut boot = BootstrapConfig::default();
    boot.manual_peers.push(BOOT_PEER.into());
    boot.add_custom(format!("/ip4/198.51.100.7/tcp/4001/p2p/{}", peer_id(&bob)));
    save_bootstrap(dd, &boot).unwrap();
    relay_allow::relay_allow_contact(dd, &peer_id(&bob), "bob", &hex_of(&bob)).unwrap();
    lan_noise_pin::record(
        dd,
        &PinKey::derive(&me),
        &bob.public_key_bytes(),
        &[0x61; 32],
    )
    .unwrap();
    Friends {
        me,
        bob,
        eve,
        bob_phone,
    }
}

/// What every reader of the PP.5 files answers, as text.
fn friend_readers(dd: &Path, f: &Friends) -> Vec<String> {
    let now = crate::clock::now_ms();
    let bob = f.bob.public_key_bytes();
    crate::lan_dispatch::forget_ephemeral_peers(dd);
    let path = |name: &str| dd.join(name);
    vec![
        format!(
            "registry {:?}",
            load_device_registry_checked(dd).map(|r| r.certs.keys().cloned().collect::<Vec<_>>())
        ),
        format!("device x {:?}", load_or_create_device_x25519(dd)),
        format!(
            "prekey {:?}",
            PrekeyStore::load_checked(dd)
                .and_then(|s| s.fetch(&bob, now))
                .map(|b| b.map(|b| b.signed_prekey_id))
        ),
        format!(
            "peer cache {:?}",
            crate::lan_dispatch::load_cached_peer_bundle(dd, &bob)
                .map(|b| b.map(|b| (hex::encode(b.cert.user_ed_pub), b.prekey.signed_prekey_id)))
        ),
        format!(
            "blocked {:?}",
            BlockList::load_checked(dd)
                .map(|b| (b.is_blocked(&hex_of(&f.eve)), b.is_blocked(&hex_of(&f.bob))))
        ),
        format!(
            "revoked {:?}",
            RevocationStore::load_checked(dd).map(|s| (
                s.is_revoked(&hex_of(&f.bob), "bob-phone"),
                s.denies_certificate(&f.bob_phone)
            ))
        ),
        format!(
            "sync seen {:?}",
            at_rest::load_json::<Value>(
                dd,
                &path(crate::device_sync::SYNC_SEEN_FILE),
                Kind::DeviceSyncSeen
            )
            .map(|v| v.map(|v| v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())))
        ),
        format!(
            "hints {:?}",
            at_rest::load_json::<Value>(
                dd,
                &path(crate::route_hints::ROUTE_HINTS_STATE_FILE),
                Kind::RouteHintsState
            )
        ),
        format!(
            "bootstrap {:?}",
            try_load_bootstrap(dd).map(|c| c.effective_peers())
        ),
        format!("relay {:?}", relay_allow::load_relay_allow(dd)),
        format!(
            "pin {:?} {:?}",
            lan_noise_pin::load_pin(dd, &bob),
            lan_noise_pin::pinned_count(dd)
        ),
    ]
}

/// The PP.5 files a sealed profile holds sealed (RMS1).
const SEALED_NAMES: [&str; 13] = [
    "contacts.json",
    "peer_device_certs.json",
    "prekey_store.json",
    "blocked_pubs.json",
    "device_registry.json",
    "revocations.json",
    "device_revocations_rvdr1.json",
    "device_sync_seen.json",
    "route_hints_state.json",
    "bootstrap.json",
    "relay_allow.json",
    "device_x25519.secret",
    NOISE_PIN_SEALED_FILE,
];

fn is_rms1(dd: &Path, name: &str) -> bool {
    std::fs::read(dd.join(name)).is_ok_and(|raw| at_rest::is_sealed(&raw))
}

fn assert_all_sealed(dd: &Path, when: &str) {
    for name in SEALED_NAMES {
        assert!(is_rms1(dd, name), "{when}: {name} is not RMS1");
    }
    assert!(!dd.join(NOISE_PIN_FILE).exists(), "{when}: plain pins left");
    // Plain by design: a public key and a number.
    assert_eq!(
        std::fs::read(dd.join("device_x25519.pub")).unwrap().len(),
        32
    );
    let generation = std::fs::read_to_string(dd.join("peer_cache.generation")).unwrap();
    assert!(generation.trim().parse::<u64>().is_ok(), "{generation}");
}

/// Per kind: migrated, read by every reader (the same answers sealed as
/// plain; the peer cache's stage replayed from sealed bytes), and written
/// sealed by every writer.
#[test]
fn friend_key_files_migrate_read_and_write_sealed() {
    let dir = profile();
    let dd = dir.path();
    let f = write_friend_files(dd);
    for name in SEALED_NAMES {
        let plain = if name == NOISE_PIN_SEALED_FILE {
            NOISE_PIN_FILE
        } else {
            name
        };
        assert!(dd.join(plain).exists(), "the fixture has no {plain}");
        assert!(!is_rms1(dd, plain), "{plain} sealed in a plain profile");
    }
    let before = friend_readers(dd, &f);
    assert!(
        before.iter().all(|line| !line.contains("Err")),
        "{before:#?}"
    );
    // An interrupted dual write: a stage of Bob's bundle at a newer
    // generation, left for the next writer to replay.
    let committed: u64 = std::fs::read_to_string(dd.join("peer_cache.generation"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut store = PrekeyStore::default();
    store
        .publish(&bundle_of(&f.bob, 1).prekey, crate::clock::now_ms())
        .unwrap();
    let certs: std::collections::HashMap<String, DeviceCertificate> =
        [(hex_of(&f.bob), bundle_of(&f.bob, 1).cert)].into();
    let stage = json!({
        "generation": committed + 1,
        "certs_json": serde_json::to_string_pretty(&certs).unwrap(),
        "prekey_json": serde_json::to_string_pretty(&store).unwrap(),
    });
    std::fs::write(dd.join("peer_cache.stage.json"), stage.to_string()).unwrap();

    seal(dd);
    assert!(
        is_rms1(dd, "peer_cache.stage.json"),
        "the stage holds sealed bytes"
    );
    assert_all_sealed(dd, "after the migration");
    let report = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!(report.sealed, 0, "idempotent");

    // Every reader, sealed: the same answers (the stage replays from its
    // sealed bytes into sealed files, at its own generation).
    assert_eq!(friend_readers(dd, &f), before);
    assert!(!dd.join("peer_cache.stage.json").exists());
    let replayed: u64 = std::fs::read_to_string(dd.join("peer_cache.generation"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(replayed, committed + 1);
    assert_all_sealed(dd, "after the replay");
    // The block list through a long-lived process's cache too.
    crate::contact_book::enable_process_cache(dd);
    assert!(BlockList::load_checked(dd)
        .unwrap()
        .is_blocked(&hex_of(&f.eve)));

    // Every writer writes sealed.
    let carol = id(0x55);
    let mut blocks = BlockList::load_checked(dd).unwrap();
    blocks.block(&hex_of(&carol));
    blocks.save(dd).unwrap();
    assert!(BlockList::load_checked(dd)
        .unwrap()
        .is_blocked(&hex_of(&carol)));
    with_device_registry_lock(dd, || {
        let mut reg = load_device_registry_checked(dd)?;
        reg.revoke("old-laptop");
        save_device_registry(dd, &reg)
    })
    .unwrap();
    assert!(load_device_registry_checked(dd)
        .unwrap()
        .is_revoked("old-laptop"));
    crate::lan_dispatch::publish_prekey_bundle_checked(
        dd,
        &bundle_of(&f.bob, 2).prekey,
        crate::clock::now_ms(),
    )
    .unwrap();
    crate::lan_dispatch::persist_trusted_peer_bundle(dd, &bundle_of(&f.bob, 3)).unwrap();
    crate::lan_dispatch::forget_ephemeral_peers(dd);
    let cached = crate::lan_dispatch::load_cached_peer_bundle(dd, &f.bob.public_key_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(cached.prekey.signed_prekey_id, 3);
    let mut revocations = RevocationStore::load_checked(dd).unwrap();
    revocations
        .apply(
            RevocationRecord::issue(&f.bob, "bob-tablet", 1, crate::clock::now_ms(), "lost")
                .unwrap(),
        )
        .unwrap();
    revocations.save(dd).unwrap();
    assert!(RevocationStore::load_checked(dd)
        .unwrap()
        .is_revoked(&hex_of(&f.bob), "bob-tablet"));
    let now = crate::clock::now_ms();
    import_contact_sync_checked(dd, &f.me, &sync_blob(&f.me, now - 5_000), now).unwrap();
    assert_eq!(
        import_contact_sync_checked(dd, &f.me, &sync_blob(&f.me, now - 7_000), now).unwrap_err(),
        "SYNC_REPLAY_OR_STALE",
        "the sealed high-water mark is read"
    );
    let mut boot = try_load_bootstrap(dd).unwrap();
    boot.add_custom("/ip4/198.51.100.8/tcp/4001");
    save_bootstrap(dd, &boot).unwrap();
    assert_eq!(try_load_bootstrap(dd).unwrap(), boot);
    relay_allow::relay_allow(dd, &peer_id(&carol), "carol").unwrap();
    assert_eq!(
        relay_allow::load_relay_allow(dd)
            .unwrap()
            .unwrap()
            .peers
            .len(),
        2
    );
    lan_noise_pin::record(
        dd,
        &PinKey::derive(&f.me),
        &carol.public_key_bytes(),
        &[0x62; 32],
    )
    .unwrap();
    assert_eq!(lan_noise_pin::pinned_count(dd), Ok(2));
    // The device key: created sealed (a sealed secret is longer than the
    // plain 32 bytes), read back.
    std::fs::remove_file(dd.join("device_x25519.secret")).unwrap();
    std::fs::remove_file(dd.join("device_x25519.pub")).unwrap();
    let x = load_or_create_device_x25519(dd).unwrap();
    assert!(
        std::fs::read(dd.join("device_x25519.secret"))
            .unwrap()
            .len()
            > 32
    );
    assert_eq!(load_or_create_device_x25519(dd).unwrap(), x);
    assert_all_sealed(dd, "after the writes");
    assert!(!dd.join("peer_cache.stage.json").exists());
}

/// A 32-byte plain secret that happens to start with "RMS1" is plain (a
/// sealed one is longer), for the reader and the migration alike.
#[test]
fn a_plain_raw_secret_is_never_taken_for_a_sealed_one() {
    let dir = profile();
    let dd = dir.path();
    let me = id(0x56);
    let mut secret = [0x11u8; 32];
    secret[..4].copy_from_slice(b"RMS1");
    let public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
    std::fs::write(dd.join("device_x25519.secret"), secret).unwrap();
    std::fs::write(dd.join("device_x25519.pub"), public).unwrap();
    assert!(!at_rest::is_sealed_as(Kind::DeviceXSecret, &secret));
    assert!(at_rest::is_sealed_as(Kind::Contacts, &secret));
    assert_eq!(load_or_create_device_x25519(dd), Ok(public));
    ensure_local_device_certificate(dd, &me, DEVICE).unwrap();
    assert_eq!(status(dd).plain_files, 2, "the registry and the secret");
    seal(dd);
    let sealed = std::fs::read(dd.join("device_x25519.secret")).unwrap();
    assert!(sealed.len() > 32 && at_rest::is_sealed(&sealed));
    assert_eq!(load_or_create_device_x25519(dd), Ok(public));
    // The Private Rendezvous §3.1 agreement reads the sealed secret.
    let peer = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x22u8; 32]));
    let shared = x25519_dalek::StaticSecret::from(secret).diffie_hellman(&peer);
    assert_eq!(
        *device_x25519_agree(dd, peer.as_bytes()).unwrap(),
        shared.to_bytes()
    );
}

/// Review R07: an older build pins on first use into a new plain file; the
/// next migration takes its pins only for contacts without a sealed pin,
/// keeps the sealed pin where they differ (counted), and removes the plain
/// file.
#[test]
fn older_build_pins_do_not_replace_sealed_pins() {
    let dir = profile();
    let dd = dir.path();
    let me = id(0x57);
    let key = PinKey::derive(&me);
    let (bob, carol, dave) = ([0xb0u8; 32], [0xc0u8; 32], [0xd0u8; 32]);
    let digest = |contact: &[u8; 32], s: u8| lan_noise_pin::pin_digest(&key, contact, &[s; 32]);
    // The first sealing moves a plain profile's pins as they are.
    lan_noise_pin::record(dd, &key, &bob, &[1; 32]).unwrap();
    seal(dd);
    assert!(!dd.join(NOISE_PIN_FILE).exists());
    assert!(is_rms1(dd, NOISE_PIN_SEALED_FILE));
    assert_eq!(lan_noise_pin::load_pin(dd, &bob), Ok(Some(digest(&bob, 1))));
    lan_noise_pin::record(dd, &key, &carol, &[3; 32]).unwrap();
    assert!(
        !dd.join(NOISE_PIN_FILE).exists(),
        "sealed mode writes only the sealed file"
    );
    let sealed_before = std::fs::read(dd.join(NOISE_PIN_SEALED_FILE)).unwrap();

    // An older build ran: it never opened the sealed file and pinned Bob's
    // address to whatever answered there, and Dave on first use.
    let older = json!({"v": 2, "pins": [
        {"c": hex::encode(bob), "d": hex::encode(digest(&bob, 2))},
        {"c": hex::encode(dave), "d": hex::encode(digest(&dave, 4))},
    ]});
    std::fs::write(dd.join(NOISE_PIN_FILE), older.to_string()).unwrap();
    // Sealed mode reads only the sealed file meanwhile.
    assert_eq!(lan_noise_pin::load_pin(dd, &bob), Ok(Some(digest(&bob, 1))));
    assert_eq!(lan_noise_pin::load_pin(dd, &dave), Ok(None));
    assert_eq!(status(dd).plain_files, 1);
    let report = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!((report.sealed, report.leftovers), (1, 1));
    assert!(!dd.join(NOISE_PIN_FILE).exists());
    assert_ne!(
        std::fs::read(dd.join(NOISE_PIN_SEALED_FILE)).unwrap(),
        sealed_before
    );
    assert_eq!(
        lan_noise_pin::load_pin(dd, &bob),
        Ok(Some(digest(&bob, 1))),
        "kept"
    );
    assert_eq!(
        lan_noise_pin::load_pin(dd, &carol),
        Ok(Some(digest(&carol, 3)))
    );
    assert_eq!(
        lan_noise_pin::load_pin(dd, &dave),
        Ok(Some(digest(&dave, 4)))
    );
    let st = status(dd);
    assert_eq!((st.older_build_pinned_differently, st.plain_files), (1, 0));
    assert_eq!(
        st.to_ipc(st.state()).notes,
        [
            NOTE_OLDER_BUILD_WROTE_PLAIN,
            NOTE_OLDER_BUILD_PINNED_DIFFERENTLY
        ]
    );
    assert!(take_older_build_note(dd));
    assert_eq!(status(dd).older_build_pinned_differently, 0);

    // A plain file that reads only in part: its good rows are merged and the
    // file kept aside, sealed.
    let partly = format!(
        r#"{{"v":2,"pins":[{{"c":"{}","d":"{}"}},{{"c":"zz"}}]}}"#,
        hex::encode([0xe0u8; 32]),
        hex::encode(digest(&[0xe0; 32], 5))
    );
    std::fs::write(dd.join(NOISE_PIN_FILE), &partly).unwrap();
    migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert!(!dd.join(NOISE_PIN_FILE).exists());
    assert!(is_rms1(dd, NOISE_PIN_CORRUPT_FILE));
    assert_eq!(
        &at_rest::load_bytes(dd, &dd.join(NOISE_PIN_CORRUPT_FILE), Kind::NoisePins)
            .unwrap()
            .unwrap()[..],
        partly.as_bytes()
    );
    assert_eq!(lan_noise_pin::pinned_count(dd), Ok(4));

    // A newer Raven's plain file: never merged, never removed.
    let newer = r#"{"v":3,"pins":[]}"#;
    std::fs::write(dd.join(NOISE_PIN_FILE), newer).unwrap();
    let sealed_now = std::fs::read(dd.join(NOISE_PIN_SEALED_FILE)).unwrap();
    assert_eq!(
        migrate_all(dd, NOW, MigratePolicy::Allow).unwrap().outcome,
        MigrateOutcome::Sealed
    );
    assert_eq!(
        std::fs::read_to_string(dd.join(NOISE_PIN_FILE)).unwrap(),
        newer
    );
    assert_eq!(
        std::fs::read(dd.join(NOISE_PIN_SEALED_FILE)).unwrap(),
        sealed_now
    );
    assert_eq!(status(dd).plain_files, 1);
}

/// "Unreadable = no pin" holds for a missing file and a corrupt plain one
/// only: a sealed pin file that does not open stops the dial (`Err`), and
/// nothing is written over it.
#[test]
fn a_sealed_pin_file_that_does_not_open_is_an_error() {
    let dir = profile();
    let dd = dir.path();
    let key = PinKey::derive(&id(0x58));
    seal(dd);
    lan_noise_pin::record(dd, &key, &[0xb1; 32], &[1; 32]).unwrap();
    let path = dd.join(NOISE_PIN_SEALED_FILE);
    let mut bytes = std::fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    for err in [
        lan_noise_pin::load_pin(dd, &[0xb1; 32]).map(|_| ()),
        lan_noise_pin::pinned_count(dd).map(|_| ()),
        lan_noise_pin::record(dd, &key, &[0xb2; 32], &[2; 32]).map(|_| ()),
        lan_noise_pin::forget(dd, &[0xb1; 32]),
    ] {
        let err = err.unwrap_err();
        assert!(err.starts_with(NOISE_PIN_SEALED_FILE), "{err}");
    }
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(!dd.join(NOISE_PIN_CORRUPT_FILE).exists());
    // Without the key loaded (a process that has not loaded it): the same.
    let other = profile();
    seal(other.path());
    lan_noise_pin::record(other.path(), &key, &[0xb1; 32], &[1; 32]).unwrap();
    at_rest::forget_cached_keys(other.path());
    assert!(lan_noise_pin::load_pin(other.path(), &[0xb1; 32]).is_err());
}

/// Review R30: a quarantine copy in plain holds friend data in clear: it is
/// sealed in place under its file's kind and kept.
#[test]
fn plain_corrupt_copy_is_sealed_in_place() {
    let dir = profile();
    let dd = dir.path();
    seal(dd);
    let bob = hex_of(&id(0x59));
    let copies = [
        (
            "bootstrap.json.corrupt",
            Kind::Bootstrap,
            format!(r#"{{"manual_peers":["{BOOT_PEER}","#),
        ),
        (
            "peer_device_certs.json.corrupt",
            Kind::PeerDeviceCerts,
            format!(r#"{{"{bob}":"#),
        ),
        (
            "prekey_store.json.corrupt",
            Kind::PrekeyStore,
            format!(r#"{{"bundles":{{"{bob}""#),
        ),
        (
            "peer_cache.stage.json.corrupt",
            Kind::PeerCacheStage,
            format!("not a stage {bob}"),
        ),
        (
            "revocations.json.corrupt",
            Kind::Revocations,
            format!(r#"[{{"user_ed_pub_hex":"{bob}""#),
        ),
        (
            NOISE_PIN_CORRUPT_FILE,
            Kind::NoisePins,
            format!(r#"{{"v":2,"pins":[{{"c":"{bob}""#),
        ),
    ];
    for (name, _, text) in &copies {
        std::fs::write(dd.join(name), text).unwrap();
    }
    assert_eq!(status(dd).plain_files, copies.len() as u16);
    let report = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!(report.sealed, copies.len() as u16);
    for (name, kind, text) in &copies {
        assert!(is_rms1(dd, name), "{name}");
        let plain = at_rest::load_bytes(dd, &dd.join(name), *kind)
            .unwrap()
            .unwrap();
        assert_eq!(&plain[..], text.as_bytes(), "{name}");
    }
    // Kept on the next passes (sealed garbage is not a cache to restore).
    for _ in 0..2 {
        migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    }
    for (name, _, _) in &copies {
        assert!(dd.join(name).exists(), "{name}");
    }
    assert!(!dd.join("peer_cache.stage.json").exists());
    assert_eq!(status(dd).plain_files, 0);

    // This build's own quarantine of a corrupt plain bootstrap.json in a
    // sealed profile seals the copy at once.
    std::fs::remove_file(dd.join("bootstrap.json.corrupt")).unwrap();
    std::fs::write(
        dd.join("bootstrap.json"),
        format!("{{\"custom\":[\"{BOOT_PEER}\""),
    )
    .unwrap();
    save_bootstrap(dd, &BootstrapConfig::default()).unwrap();
    assert!(is_rms1(dd, "bootstrap.json") && is_rms1(dd, "bootstrap.json.corrupt"));
}

/// The downgrade copies of the peer cache (an older build moved a sealed
/// file it could not parse to `<file>.corrupt`): one that opens under this
/// profile's key comes back when its file is missing, and goes when the
/// file is there; a sealed copy of another profile is left alone.
#[test]
fn corrupt_peer_cache_copy_is_restored_or_removed() {
    let dir = profile();
    let dd = dir.path();
    let f = write_friend_files(dd);
    seal(dd);
    let certs = dd.join("peer_device_certs.json");
    let prekeys = dd.join("prekey_store.json");
    let sealed_certs = std::fs::read(&certs).unwrap();
    // The older build: certificates moved aside (the file is missing now),
    // prekeys moved aside and rebuilt in plain.
    std::fs::rename(&certs, dd.join("peer_device_certs.json.corrupt")).unwrap();
    let sealed_prekeys = std::fs::read(&prekeys).unwrap();
    std::fs::write(dd.join("prekey_store.json.corrupt"), &sealed_prekeys).unwrap();
    std::fs::write(&prekeys, br#"{"bundles":{}}"#).unwrap();
    // A sealed copy this profile's key does not open (another profile's).
    let stranger = profile();
    write_friend_files(stranger.path());
    seal(stranger.path());
    std::fs::copy(
        stranger.path().join("revocations.json"),
        dd.join("revocations.json.corrupt"),
    )
    .unwrap();
    let report = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!(report.leftovers, 1, "the plain prekey store");
    assert_eq!(std::fs::read(&certs).unwrap(), sealed_certs, "restored");
    assert!(!dd.join("peer_device_certs.json.corrupt").exists());
    assert!(!dd.join("prekey_store.json.corrupt").exists(), "removed");
    assert!(
        is_rms1(dd, "prekey_store.json"),
        "the plain one sealed again"
    );
    assert!(
        dd.join("revocations.json.corrupt").exists(),
        "not ours: kept"
    );
    crate::lan_dispatch::forget_ephemeral_peers(dd);
    assert!(
        crate::lan_dispatch::load_cached_peer_bundle(dd, &f.bob.public_key_bytes())
            .unwrap()
            .is_none(),
        "the older build's empty prekey store is current"
    );

    // A sealed stage moved aside: it comes back beside a committed
    // generation and replays; without one it stays aside.
    for with_generation in [true, false] {
        let stage = json!({"generation": u64::MAX / 2, "certs_json": "{}", "prekey_json": "{}"});
        at_rest::store_json(
            dd,
            &dd.join("peer_cache.stage.json"),
            Kind::PeerCacheStage,
            &stage,
        )
        .unwrap();
        std::fs::rename(
            dd.join("peer_cache.stage.json"),
            dd.join("peer_cache.stage.json.corrupt"),
        )
        .unwrap();
        if !with_generation {
            let _ = std::fs::remove_file(dd.join("peer_cache.generation"));
        }
        migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
        assert_eq!(
            dd.join("peer_cache.stage.json").exists(),
            with_generation,
            "generation {with_generation}"
        );
        assert_eq!(
            dd.join("peer_cache.stage.json.corrupt").exists(),
            !with_generation
        );
        let _ = std::fs::remove_file(dd.join("peer_cache.stage.json"));
        let _ = std::fs::remove_file(dd.join("peer_cache.stage.json.corrupt"));
    }
}

/// Interrupted atomic writes' temp files (`.<name>.tmp.<16 hex>`, possibly
/// plaintext) older than an hour are deleted, in the profile and its
/// folders; young ones (a write in flight) and other names stay.
#[test]
fn stale_temp_files_are_removed() {
    let dir = profile();
    let dd = dir.path();
    seal(dd);
    std::fs::create_dir(dd.join("contact_inbox")).unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
    let stale = [
        ".contacts.json.tmp.0123456789abcdef",
        ".blocked_pubs.json.tmp.fedcba9876543210",
        "contact_inbox/.00ff.wire.tmp.00000000deadbeef",
    ];
    let kept = [
        ".contacts.json.tmp.0123456789abcdee",  // young
        ".bootstrap.json.tmp.ABCDEF0123456789", // not this build's temp name
        "contacts.json.tmp.0123456789abcdef",   // no dot
        ".contacts.json.tmp.0123456789abcde",   // 15 digits
        ".contacts.json.tmp.0123456789abcdef0", // 17 digits
    ];
    for (n, name) in stale.iter().chain(&kept).enumerate() {
        std::fs::write(dd.join(name), b"[{\"petname\":\"Bob\"").unwrap();
        if n < stale.len() || n > stale.len() {
            std::fs::File::options()
                .write(true)
                .open(dd.join(name))
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
    }
    migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    for name in stale {
        assert!(!dd.join(name).exists(), "{name}");
    }
    for name in kept {
        assert!(dd.join(name).exists(), "{name}");
    }
    assert!(is_temp_name(".a.tmp.0123456789abcdef") && !is_temp_name(".tmp.0123456789abcdef"));
    // A plain profile this build does not seal is never touched.
    let plain = profile();
    let leftover = plain.path().join(".contacts.json.tmp.0123456789abcdef");
    std::fs::write(&leftover, b"[").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&leftover)
        .unwrap()
        .set_modified(old)
        .unwrap();
    migrate_all(plain.path(), NOW, MigratePolicy::Never).unwrap();
    assert!(leftover.exists());
}

/// bootstrap.json is a first-install inert file: written before the
/// identity it stays plain (identity creation must still accept the
/// profile), and the migration seals it once there is an identity; readers
/// accept both.
#[test]
fn bootstrap_before_and_after_the_identity() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let mut cfg = BootstrapConfig::default();
    cfg.manual_peers.push(BOOT_PEER.into());
    save_bootstrap(dd, &cfg).unwrap();
    assert!(!is_rms1(dd, "bootstrap.json"));
    assert!(
        crate::identity_store::first_install_allowed(dd),
        "still a first install"
    );
    assert_eq!(
        migrate_all(dd, NOW, MigratePolicy::Allow).unwrap().outcome,
        MigrateOutcome::NoIdentity
    );
    assert!(!is_rms1(dd, "bootstrap.json"));
    // The identity arrives; the next pass seals it.
    std::fs::write(
        dd.join(crate::identity_store::BACKEND_MARKER_NAME),
        b"locked-file\n",
    )
    .unwrap();
    seal(dd);
    assert!(is_rms1(dd, "bootstrap.json"));
    assert_eq!(try_load_bootstrap(dd).unwrap(), cfg);
    // A sealed file this process cannot open is never moved aside or
    // replaced.
    at_rest::forget_cached_keys(dd);
    let sealed = std::fs::read(dd.join("bootstrap.json")).unwrap();
    assert!(matches!(
        try_load_bootstrap(dd),
        Err(crate::bootstrap::BootstrapError::Sealed(_))
    ));
    assert_eq!(
        crate::bootstrap::load_bootstrap(dd),
        BootstrapConfig::fail_closed()
    );
    assert!(save_bootstrap(dd, &BootstrapConfig::default()).is_err());
    assert_eq!(std::fs::read(dd.join("bootstrap.json")).unwrap(), sealed);
    assert!(!dd.join("bootstrap.json.corrupt").exists());
}

/// A dedicated relay folder has no identity and so no key: its allow-list
/// stays plain whatever runs there. A profile's own list (the friend relay,
/// `raven-node service --relay`) is sealed with the profile.
#[test]
fn relay_folder_stays_plain_and_a_profile_relay_list_is_sealed() {
    let relay = tempfile::tempdir().unwrap();
    std::fs::write(relay.path().join(relay_allow::RELAY_KEY_FILE), [7u8; 32]).unwrap();
    assert!(relay_allow::is_relay_dir(relay.path()));
    let bob = peer_id(&id(0x5a));
    relay_allow::relay_allow(relay.path(), &bob, "bob").unwrap();
    assert_eq!(
        migrate_all(relay.path(), NOW, MigratePolicy::Allow)
            .unwrap()
            .outcome,
        MigrateOutcome::NoIdentity
    );
    relay_allow::relay_allow(relay.path(), &peer_id(&id(0x5b)), "carol").unwrap();
    let raw = std::fs::read_to_string(relay.path().join("relay_allow.json")).unwrap();
    assert!(raw.contains(&bob), "plain in a relay folder");
    assert!(!relay.path().join(META_KEY_FILE).exists());

    let dir = profile();
    let dd = dir.path();
    relay_allow::relay_allow(dd, &bob, "bob").unwrap();
    seal(dd);
    assert!(is_rms1(dd, "relay_allow.json"));
    relay_allow::relay_allow(dd, &peer_id(&id(0x5b)), "carol").unwrap();
    assert!(is_rms1(dd, "relay_allow.json"));
    assert_eq!(
        relay_allow::load_relay_allow(dd)
            .unwrap()
            .unwrap()
            .peers
            .len(),
        2
    );
    // Without the key the list cannot be used: the relay admits nobody.
    at_rest::forget_cached_keys(dd);
    assert!(relay_allow::load_relay_allow(dd).is_err());
}

/// After the migration and the writes, no file of the profile names a
/// friend's key, PeerId or address in clear.
#[test]
fn byte_scan_finds_no_friend_key_or_peer_id_in_the_friend_files() {
    let dir = profile();
    let dd = dir.path();
    let f = write_friend_files(dd);
    seal(dd);
    lan_noise_pin::record(
        dd,
        &PinKey::derive(&f.me),
        &id(0x5c).public_key_bytes(),
        &[9; 32],
    )
    .unwrap();
    let mut needles: Vec<Vec<u8>> = Vec::new();
    for who in [&f.bob, &f.eve, &id(0x5c), &id(0x54)] {
        needles.push(hex_of(who).into_bytes());
        needles.push(hex_of(who).to_uppercase().into_bytes());
        needles.push(peer_id(who).into_bytes());
        needles.push(crate::encode_address(&who.public_key_bytes()).into_bytes());
    }
    for text in [BOB_LAN, BOOT_PEER, "198.51.100.7", "bob-phone", "\"bob\""] {
        needles.push(text.as_bytes().to_vec());
    }
    let mut scanned = Vec::new();
    let mut stack = vec![dd.to_path_buf()];
    while let Some(at) = stack.pop() {
        for entry in std::fs::read_dir(&at).unwrap() {
            let path: PathBuf = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            for needle in &needles {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "{} holds {:?}",
                    path.display(),
                    String::from_utf8_lossy(needle)
                );
            }
            scanned.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    for name in SEALED_NAMES {
        assert!(
            scanned.iter().any(|s| s == name),
            "{name} not scanned: {scanned:?}"
        );
    }
}

/// The advisory-file rule: a reader that treats an unreadable file as empty
/// may replace a missing file or plain bytes that do not parse, never a
/// sealed file it could not open.
#[test]
fn advisory_reads_tell_what_may_be_written_over() {
    let dir = profile();
    let dd = dir.path();
    let path = dd.join(crate::route_hints::ROUTE_HINTS_STATE_FILE);
    let read = || at_rest::load_json_advisory::<Value>(dd, &path, Kind::RouteHintsState);
    assert!(matches!(read(), at_rest::Advisory::Missing) && read().writable());
    std::fs::write(&path, b"{not json").unwrap();
    assert!(matches!(read(), at_rest::Advisory::CorruptPlain) && read().writable());
    seal(dd);
    at_rest::store_json(dd, &path, Kind::RouteHintsState, &json!({"generation": 7})).unwrap();
    assert!(is_rms1(dd, crate::route_hints::ROUTE_HINTS_STATE_FILE));
    assert_eq!(read().into_loaded(), Some(json!({"generation": 7})));
    at_rest::forget_cached_keys(dd);
    assert!(matches!(
        read(),
        at_rest::Advisory::Unreadable(AtRestError::KeyUnavailable(_))
    ));
    assert!(!read().writable());
    // Only the key missing: skipped, not counted (read again once loaded).
    let Advisory::Unreadable(why) = read() else {
        unreachable!()
    };
    at_rest::note_skipped_write(dd, &why);
    assert_eq!(at_rest::skipped_writes(dd), 0);
    assert!(!status(dd)
        .to_ipc("sealed")
        .notes
        .contains(&NOTE_UNREADABLE_FILE_KEPT.to_owned()));
    // A file that does not open (a changed byte): kept and counted.
    crate::contact_book::tests::seal(dd);
    let mut bytes = std::fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let Advisory::Unreadable(why) = read() else {
        panic!("a changed byte reads as unreadable")
    };
    assert!(matches!(why, AtRestError::Tampered { .. }), "{why}");
    at_rest::note_skipped_write(dd, &why);
    assert_eq!(at_rest::skipped_writes(dd), 1);
    let st = status(dd);
    assert!(st
        .to_ipc(st.state())
        .notes
        .contains(&NOTE_UNREADABLE_FILE_KEPT.to_owned()));
}
