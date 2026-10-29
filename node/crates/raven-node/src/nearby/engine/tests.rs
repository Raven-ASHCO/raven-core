//! The engine on the in-process ether: in-memory keys and paused time,
//! except the end-to-end test, which runs two real profiles in real time.

use std::path::Path;
use std::sync::atomic::AtomicU64;

use futures::future::ready;
use raven_core::identity::Identity;
use raven_core::nearby_link::{pair_keys, CentralKnock, HELLO_LEN, KIND_CHALLENGE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

use super::*;
use crate::nearby::fake::{Ether, EtherParams, FakeOpts, FakeRadio};
use crate::nearby::radio::EVENT_QUEUE;

/// A minute into a token epoch (the hosts' Raven clock starts here).
const T0: u64 = 2_000_000 * raven_core::nearby_link::EPOCH_MS + 60_000;

fn id(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn key(seed: u8) -> [u8; 32] {
    id(seed).public_key_bytes()
}

/// A host with an in-memory contact book, its own Raven clock, the mail
/// waiting it is told, and the inbound channels it is handed.
struct TestHost {
    me: Identity,
    contacts: Mutex<Vec<[u8; 32]>>,
    generation: AtomicU64,
    clock: AtomicU64,
    work: Mutex<Vec<[u8; 32]>>,
    ups: Mutex<Vec<[u8; 32]>>,
    inbound: mpsc::UnboundedSender<([u8; 32], DuplexStream)>,
    allow_public: bool,
    /// Every pair's seed (Phase 6b), expected of the contact too; `None`:
    /// the root alone.
    seed: Mutex<Option<[u8; 32]>>,
}

impl Host for TestHost {
    fn now_ms(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn stamp(&self) -> KeyStamp {
        (Vec::new(), self.generation.load(Ordering::SeqCst), 0)
    }

    fn load_keys(&self) -> BoxFuture<'static, Result<Vec<(PairKeys, KeyUse)>, String>> {
        use raven_core::nearby_link::pair_keys_from;
        let seed = *lock(&self.seed);
        let me = self.me.public_key_bytes();
        let keys = lock(&self.contacts)
            .iter()
            .filter_map(|p| {
                let root = raven_core::lan_beacon::pair_root(&self.me, p).ok()?;
                Some(match seed {
                    None => vec![(pair_keys(&self.me, p).ok()?, KeyUse::SEND)],
                    Some(seed) => vec![
                        (
                            pair_keys_from(&me, p, &raven_core::pair_seed::pair_key(&root, &seed)),
                            KeyUse::SEND,
                        ),
                        (
                            pair_keys_from(&me, p, &root),
                            KeyUse {
                                send: false,
                                notice: true,
                            },
                        ),
                    ],
                })
            })
            .flatten()
            .collect();
        Box::pin(ready(Ok(keys)))
    }

    fn has_work(&self) -> BoxFuture<'static, Vec<[u8; 32]>> {
        Box::pin(ready(lock(&self.work).clone()))
    }

    fn pipe_up(&self, peer: &[u8; 32]) {
        lock(&self.ups).push(*peer);
    }

    fn inbound(&self, peer: [u8; 32], stream: DuplexStream) {
        let _ = self.inbound.send((peer, stream));
    }

    fn allow_public_address(&self) -> bool {
        self.allow_public
    }
}

/// One node on the ether: its engine and what its host saw.
struct Node {
    key: [u8; 32],
    host: Arc<TestHost>,
    engine: EngineHandle,
    task: JoinHandle<()>,
    inbound: mpsc::UnboundedReceiver<([u8; 32], DuplexStream)>,
}

impl Node {
    fn new(ether: &Ether, seed: u8, contacts: &[u8], opts: FakeOpts) -> Self {
        Self::with(ether, seed, contacts, opts, false)
    }

    fn with(ether: &Ether, seed: u8, contacts: &[u8], opts: FakeOpts, allow_public: bool) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let host = Arc::new(TestHost {
            me: id(seed),
            contacts: Mutex::new(contacts.iter().map(|s| key(*s)).collect()),
            generation: AtomicU64::new(0),
            clock: AtomicU64::new(T0),
            work: Mutex::new(Vec::new()),
            ups: Mutex::new(Vec::new()),
            inbound: tx,
            allow_public,
            seed: Mutex::new(None),
        });
        let (ev_tx, ev_rx) = mpsc::channel(EVENT_QUEUE);
        let radio = ether.radio_with(&format!("node-{seed:02x}"), ev_tx, opts);
        let (engine, task) = spawn(
            Box::new(radio),
            ev_rx,
            Arc::clone(&host) as Arc<dyn Host>,
            key(seed),
            false,
        );
        Self {
            key: key(seed),
            host,
            engine,
            task,
            inbound: rx,
        }
    }

    fn status(&self) -> NearbyStatusInfo {
        self.engine.status()
    }

    /// The contacts change (one refresh tells).
    fn set_contacts(&self, seeds: &[u8]) {
        *lock(&self.host.contacts) = seeds.iter().map(|s| key(*s)).collect();
        self.host.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// The Raven clock moves by `ms` (the lab clock).
    fn advance_clock(&self, ms: u64) {
        self.host.clock.fetch_add(ms, Ordering::SeqCst);
    }
}

/// Wait (in paused time, or up to 20 s of real time) until `cond` holds.
async fn until(what: &str, cond: impl Fn() -> bool) {
    timeout(Duration::from_secs(600), async {
        while !cond() {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for: {what}"));
}

/// The token `adv` advertises for `peer` at the epoch of `ms`.
fn token_out(adv: u8, peer: u8, ms: u64) -> [u8; 16] {
    pair_keys(&id(adv), &key(peer))
        .unwrap()
        .token_out(epoch_of(ms))
}

/// A bare radio on the ether (a stranger, or a scripted contact).
fn bare(ether: &Ether, name: &str) -> (FakeRadio, mpsc::Receiver<RadioEvent>) {
    let (tx, rx) = mpsc::channel(EVENT_QUEUE);
    (ether.radio(name, tx), rx)
}

/// The next event of `rx` that `keep` takes, within `wait`.
async fn next_where(
    rx: &mut mpsc::Receiver<RadioEvent>,
    wait: Duration,
    keep: impl Fn(&RadioEvent) -> bool,
) -> Option<RadioEvent> {
    timeout(wait, async {
        loop {
            match rx.recv().await {
                Some(ev) if keep(&ev) => return Some(ev),
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// `bare` connects to the advertiser of `t` (seen first) as the central.
async fn connect_to(
    radio: &mut FakeRadio,
    rx: &mut mpsc::Receiver<RadioEvent>,
    t: [u8; 16],
) -> ConnId {
    radio.set_scanning(true).unwrap();
    let Some(RadioEvent::Seen { addr, .. }) = next_where(
        rx,
        Duration::from_secs(30),
        |ev| matches!(ev, RadioEvent::Seen { uuids, .. } if uuids.contains(&t)),
    )
    .await
    else {
        panic!("the advert is seen")
    };
    let conn = radio.connect(&addr, t).unwrap();
    let up = next_where(rx, Duration::from_secs(5), |ev| ev.conn() == Some(conn)).await;
    assert!(
        matches!(up, Some(RadioEvent::Connected { .. })),
        "connected: {up:?}"
    );
    conn
}

// ── End to end ──────────────────────────────────────────────────────────────

/// The real responder (no gate check: the engine only runs with it open).
struct Ungated(crate::nearby::NodeHost);

impl Host for Ungated {
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }
    fn stamp(&self) -> KeyStamp {
        self.0.stamp()
    }
    fn load_keys(&self) -> BoxFuture<'static, Result<Vec<(PairKeys, KeyUse)>, String>> {
        self.0.load_keys()
    }
    fn has_work(&self) -> BoxFuture<'static, Vec<[u8; 32]>> {
        self.0.has_work()
    }
    fn pipe_up(&self, peer: &[u8; 32]) {
        self.0.pipe_up(peer);
    }
    fn inbound(&self, peer: [u8; 32], stream: DuplexStream) {
        crate::nearby::serve_inbound(
            self.0.data_dir.clone(),
            Arc::clone(&self.0.identity),
            &self.0.admission,
            peer,
            stream,
        );
    }
    fn allow_public_address(&self) -> bool {
        false
    }
}

/// `identity`'s sealed message `text` under the session `key` (as `raven
/// send` stages it).
fn seal(
    dir: &Path,
    identity: &Identity,
    key: &raven_core::indexed_session_store::IndexedSessionRecordKey,
    text: &str,
) -> Vec<u8> {
    use raven_core::indexed_session_store::{AuthorizedEndpointDevice, IndexedSessionStore};
    let now = raven_core::clock::now_ms();
    let (cert, registry) = raven_core::device_cert::ensure_local_device_certificate(
        dir,
        identity,
        raven_core::paths::PRIMARY_DEVICE_ID,
    )
    .unwrap();
    let device = AuthorizedEndpointDevice::authorize(&cert, identity, &registry, now).unwrap();
    let mut store = IndexedSessionStore::open(dir).unwrap();
    let end = store.session_expires_at(key).unwrap();
    let mut sealed = None;
    let _ = store.send_message_envelope(
        key,
        text,
        &device,
        now,
        (now + 3_600_000).min(end),
        now,
        &mut rand::rngs::OsRng,
        &mut |_digest: &[u8; 32], bytes: &[u8]| {
            sealed = Some(bytes.to_vec());
            Err(())
        },
    );
    sealed.expect("sealed")
}

fn inbox(dir: &Path) -> Vec<String> {
    raven_core::indexed_session_store::IndexedSessionStore::open(dir)
        .unwrap()
        .list_endpoint_inbox()
        .unwrap()
        .into_iter()
        .map(|r| String::from_utf8_lossy(&r.plaintext).into_owned())
        .collect()
}

/// Discovery, knock and pipe between two real profiles, then a sealed
/// message one way with its sealed ACK back, and one the other way: Alice
/// (who advertises for Bob) is the peripheral and dials on channel 1, Bob
/// the central on channel 0. Each responder takes only the key its pipe was
/// knocked for (RNL1 §7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_knock_pipe_then_a_message_and_its_sealed_ack_both_ways() {
    use crate::outbox::test_rig::{contacts, lab_backends, pair};
    if !lab_backends() {
        return;
    }
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice = raven_core::load_or_create_identity(a.path()).unwrap().0;
    let bob = raven_core::load_or_create_identity(b.path()).unwrap().0;
    for (dir, me) in [(a.path(), &alice), (b.path(), &bob)] {
        raven_core::device_cert::ensure_local_device_certificate(
            dir,
            me,
            raven_core::paths::PRIMARY_DEVICE_ID,
        )
        .unwrap();
        raven_core::ensure_local_prekey(dir, me).unwrap();
    }
    let (alice_pub, bob_pub) = (alice.public_key_bytes(), bob.public_key_bytes());
    contacts(a.path(), &bob_pub, "", "", true);
    contacts(b.path(), &alice_pub, "", "", true);
    let a_bundle = raven_core::lan_dispatch::local_bundle(a.path(), &alice).unwrap();
    let b_bundle = raven_core::lan_dispatch::local_bundle(b.path(), &bob).unwrap();
    raven_core::lan_dispatch::cache_peer_bundle(a.path(), &b_bundle).unwrap();
    raven_core::lan_dispatch::cache_peer_bundle(b.path(), &a_bundle).unwrap();
    let key_ab = pair(a.path(), &alice, b.path(), &bob, &a_bundle, &b_bundle);
    let key_ba = pair(b.path(), &bob, a.path(), &alice, &b_bundle, &a_bundle);

    let ether = Ether::new(EtherParams::default());
    let start = |dir: &Path, key_of: &[u8; 32], name: &str| {
        let (tx, rx) = mpsc::channel(EVENT_QUEUE);
        let radio = ether.radio_with(name, tx, FakeOpts::default());
        let me = Arc::new(raven_core::load_identity_required(dir).unwrap());
        assert_eq!(me.public_key_bytes(), *key_of);
        let host = Ungated(crate::nearby::NodeHost {
            data_dir: dir.to_path_buf(),
            identity: Arc::clone(&me),
            admission: crate::netutil::Admission::new(crate::netutil::NEARBY_INBOUND),
        });
        spawn(
            Box::new(radio),
            rx,
            Arc::new(host),
            me.public_key_bytes(),
            false,
        )
    };
    let (alice_engine, _a_task) = start(a.path(), &alice_pub, "alice");
    let (bob_engine, _b_task) = start(b.path(), &bob_pub, "bob");
    until("both engines hold the pair key", || {
        alice_engine.has_keys(&bob_pub) && bob_engine.has_keys(&alice_pub)
    })
    .await;
    assert!(
        matches!(
            alice_engine.pipe_for(bob_pub, Duration::from_secs(1)).await,
            Err(e) if e == NEARBY_NOT_IN_RANGE
        ),
        "not seen: fails at once"
    );
    // Alice has a message for Bob: she advertises; Bob's scan finds her,
    // connects and knocks.
    alice_engine.on(bob_pub, None);
    until("the pipe is up both ways", || {
        alice_engine.has_pipe(&bob_pub) && bob_engine.has_pipe(&alice_pub)
    })
    .await;

    let to_bob = seal(a.path(), &alice, &key_ab, "over the air");
    let replies = crate::nearby::dial_on(&alice_engine, a.path(), &bob_pub, &[to_bob])
        .await
        .expect("delivered over nearby");
    assert_eq!(
        raven_core::outbox::ack_frames(&replies).len(),
        1,
        "a sealed ACK"
    );
    assert_eq!(inbox(b.path()), ["over the air"]);

    let to_alice = seal(b.path(), &bob, &key_ba, "and back");
    let replies = crate::nearby::dial_on(&bob_engine, b.path(), &alice_pub, &[to_alice])
        .await
        .expect("delivered over nearby");
    assert_eq!(
        raven_core::outbox::ack_frames(&replies).len(),
        1,
        "a sealed ACK"
    );
    assert_eq!(inbox(a.path()), ["and back"]);

    let (sa, sb) = (alice_engine.status(), bob_engine.status());
    assert_eq!((sa.pipes, sb.pipes), (1, 1));
    assert!(sa.frames_tx > 0 && sa.frames_rx > 0 && sb.bytes_rx > 0);
    assert_eq!(sb.in_range, 1, "Bob saw Alice's beacon");
    alice_engine.stop();
    bob_engine.stop();
}

// ── Knock and privacy ───────────────────────────────────────────────────────

/// A stranger in radio range that connects to the advertised service gets
/// no frame at all: not for random HELLOs (three, then it is dropped), and
/// not for a valid HELLO recorded and replayed. The contact itself gets its
/// CHALLENGE. Phase 6b (S20): each random HELLO is `SEC_KNOCK_FAIL` about
/// the pipe's radio source; the replay is not one.
#[tokio::test(start_paused = true)]
async fn a_stranger_gets_no_frame_for_random_or_replayed_hellos() {
    let capture = crate::security::tests::Capture::start();
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xA1, &[0xB1], FakeOpts::default());
    until("keys", || alice.engine.has_keys(&key(0xB1))).await;
    alice.engine.on(key(0xB1), None);
    let t = token_out(0xA1, 0xB1, T0);

    let (mut mallory, mut m_rx) = bare(&ether, "mallory");
    let conn = connect_to(&mut mallory, &mut m_rx, t).await;
    for i in 0..3u8 {
        let mut hello = [i; HELLO_LEN];
        hello[0] = raven_core::nearby_link::KIND_HELLO;
        hello[1] = 1;
        mallory.send(conn, &hello).unwrap();
    }
    let answer = next_where(&mut m_rx, Duration::from_secs(10), |ev| {
        ev.conn() == Some(conn) && !matches!(ev, RadioEvent::Seen { .. })
    })
    .await;
    assert_eq!(
        answer,
        Some(RadioEvent::Disconnected { conn }),
        "silence, then dropped after three strikes"
    );

    // Bob's own HELLO is answered; recorded and replayed, it is not.
    let bob_keys = pair_keys(&id(0xB1), &key(0xA1)).unwrap();
    let hello = CentralKnock::new(t, [7; 16]).hello(&bob_keys);
    let (mut bob, mut b_rx) = bare(&ether, "bob");
    let c1 = connect_to(&mut bob, &mut b_rx, t).await;
    bob.send(c1, &hello).unwrap();
    let got = next_where(
        &mut b_rx,
        Duration::from_secs(5),
        |ev| matches!(ev, RadioEvent::Frame { conn, .. } if *conn == c1),
    )
    .await;
    assert!(
        matches!(&got, Some(RadioEvent::Frame { bytes, .. }) if bytes[0] == KIND_CHALLENGE),
        "{got:?}"
    );
    let c2 = connect_to(&mut mallory, &mut m_rx, t).await;
    mallory.send(c2, &hello).unwrap();
    let replayed = next_where(
        &mut m_rx,
        Duration::from_secs(4),
        |ev| matches!(ev, RadioEvent::Frame { conn, .. } if *conn == c2),
    )
    .await;
    assert_eq!(replayed, None, "a replayed HELLO gets silence");
    assert!(alice.status().knock_silenced >= 4);
    assert_eq!(alice.status().pipes, 0);
    if let Some(capture) = capture {
        use raven_core::outbox::OutboxCarrier;
        use raven_core::security_events::{Attribution, SecKind, SourceKey, Via};
        let failed = (
            SecKind::KnockFail,
            Attribution::Network {
                source: SourceKey::of(super::super::admission_ip(&key(0xB1))),
            },
            Via::DirectLink(OutboxCarrier::Nearby),
        );
        let knocks: Vec<_> = capture
            .kinds()
            .into_iter()
            .filter(|(kind, ..)| *kind == SecKind::KnockFail)
            .collect();
        assert_eq!(knocks, vec![failed; 3]);
    }
}

/// RNL1 §4: on a link whose ATT MTU is 23 (20-byte frames) the central sends
/// no HELLO: not one frame crosses, and no pipe comes up.
#[tokio::test(start_paused = true)]
async fn an_att_mtu_of_23_gives_no_hello() {
    let ether = Ether::new(EtherParams {
        mtu_c2p: 23,
        mtu_p2c: 23,
        ..EtherParams::default()
    });
    let alice = Node::new(&ether, 0xA2, &[0xB2], FakeOpts::default());
    let bob = Node::new(&ether, 0xB2, &[0xA2], FakeOpts::default());
    until("keys", || {
        alice.engine.has_keys(&bob.key) && bob.engine.has_keys(&alice.key)
    })
    .await;
    alice.engine.on(bob.key, None);
    until("Bob sees Alice", || bob.status().in_range == 1).await;
    sleep(Duration::from_secs(25)).await;
    assert_eq!(ether.crossed(), 0, "no frame at all");
    assert_eq!((alice.status().pipes, bob.status().pipes), (0, 0));
    assert!(lock(&alice.host.ups).is_empty() && lock(&bob.host.ups).is_empty());
}

/// Only a contact the engine holds a pair key for is ever on air or in the
/// scan table; one that loses its key (blocked, revoked, unverified,
/// removed: [`crate::nearby::load_keys`]) leaves the air and its pipe ends
/// within one refresh.
#[tokio::test(start_paused = true)]
async fn a_contact_that_loses_its_key_leaves_the_air_within_one_refresh() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xA3, &[0xB3], FakeOpts::default());
    let bob = Node::new(&ether, 0xB3, &[0xA3], FakeOpts::default());
    until("keys", || alice.engine.has_keys(&bob.key)).await;
    // Carol has no key here: `nearby on` for her puts nothing on air.
    alice.engine.on(key(0xC3), None);
    sleep(Duration::from_secs(3)).await;
    assert_eq!(alice.status().advertising, 0);
    assert!(ether.adverts().is_empty());
    alice.engine.on(bob.key, None);
    until("pipe", || alice.engine.has_pipe(&bob.key)).await;
    assert!(ether
        .adverts()
        .iter()
        .all(|a| a.uuids == [token_out(0xA3, 0xB3, T0)]));
    alice.set_contacts(&[]);
    sleep(REFRESH_EVERY + Duration::from_secs(2)).await;
    assert!(!alice.engine.has_keys(&bob.key));
    assert!(!alice.engine.has_pipe(&bob.key), "its pipe ended");
    assert_eq!(alice.status().advertising, 0);
    until("Bob's end too", || !bob.engine.has_pipe(&alice.key)).await;
    assert!(alice
        .engine
        .pipe_for(bob.key, Duration::from_secs(1))
        .await
        .is_err());
}

/// The verified-contact rule at its source: a key for each verified,
/// unblocked contact with a valid cached certificate whose lineage is not
/// revoked, and for nobody else.
#[test]
fn load_keys_takes_verified_unblocked_unrevoked_contacts_with_a_certificate() {
    use raven_core::device_cert::DeviceCertificate;
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let me = id(0xA4);
    // Bob: the one. Carol: not verified. Dave: no certificate. Erin:
    // blocked. Frank: his lineage revoked.
    let (bob, carol, dave, erin, frank) = (0xB4, 0xC4, 0xD4, 0xE4, 0xF4);
    let rows: Vec<String> = [
        (bob, true),
        (carol, false),
        (dave, true),
        (erin, true),
        (frank, true),
    ]
    .iter()
    .map(|(s, pinned)| {
        format!(
            r#"{{"pub_hex":"{}","pinned":{pinned}}}"#,
            hex::encode(key(*s))
        )
    })
    .collect();
    std::fs::write(dd.join("contacts.json"), format!("[{}]", rows.join(","))).unwrap();
    let t = raven_core::clock::now_ms();
    let cert = |s: u8| {
        DeviceCertificate::issue(
            &id(s),
            key(s),
            [0x42; 32],
            raven_core::paths::PRIMARY_DEVICE_ID,
            t - 60_000,
            t + 365 * 86_400_000,
            0,
        )
        .unwrap()
    };
    let map: HashMap<String, DeviceCertificate> = [bob, carol, erin, frank]
        .iter()
        .map(|s| (hex::encode(key(*s)), cert(*s)))
        .collect();
    std::fs::write(
        raven_core::lan_dispatch::peer_cert_cache_path(dd),
        serde_json::to_string(&map).unwrap(),
    )
    .unwrap();
    let mut blocks = raven_core::BlockList::default();
    blocks.block(&hex::encode(key(erin)));
    blocks.save(dd).unwrap();
    let revoked = raven_core::RevocationRecord::issue(
        &id(frank),
        raven_core::paths::PRIMARY_DEVICE_ID,
        1,
        t,
        "lost",
    )
    .unwrap();
    let mut store = raven_core::RevocationStore::load_checked(dd).unwrap();
    assert!(store.apply(revoked).unwrap());
    store.save(dd).unwrap();
    let keys = crate::nearby::load_keys(dd, &me, false).unwrap();
    assert_eq!(
        keys.iter().map(|(k, _)| k.peer).collect::<Vec<_>>(),
        [key(bob)]
    );
    assert_eq!(keys[0].1, KeyUse::SEND);
    // An unreadable book names nobody.
    std::fs::write(dd.join("contacts.json"), b"not json").unwrap();
    assert!(crate::nearby::load_keys(dd, &me, false).is_err());
}

// ── Pipes ───────────────────────────────────────────────────────────────────

/// A token epoch ends (the lab clock moves 15 min) while a pipe is up: the
/// pipe lives on, its old service stays published while it does, and the
/// new epoch's token goes on air for the next contact.
#[tokio::test(start_paused = true)]
async fn an_epoch_rollover_keeps_a_live_pipe() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xA5, &[0xB5, 0xC5], FakeOpts::default());
    let mut bob = Node::new(&ether, 0xB5, &[0xA5], FakeOpts::default());
    until("keys", || alice.engine.has_keys(&bob.key)).await;
    alice.engine.on(bob.key, None);
    until("pipe", || {
        alice.engine.has_pipe(&bob.key) && bob.engine.has_pipe(&alice.key)
    })
    .await;
    let pipe = alice
        .engine
        .pipe_for(bob.key, Duration::from_secs(1))
        .await
        .unwrap();
    alice.advance_clock(raven_core::nearby_link::EPOCH_MS);
    bob.advance_clock(raven_core::nearby_link::EPOCH_MS);
    alice.engine.on(key(0xC5), None);
    let next = token_out(0xA5, 0xC5, T0 + raven_core::nearby_link::EPOCH_MS);
    until("the new epoch's token on air", || {
        ether.adverts().iter().any(|a| a.uuids == [next])
    })
    .await;
    sleep(Duration::from_secs(10)).await;
    assert_eq!(ether.links(), 1, "the pipe's link was not cut");
    let mut ours = pipe.open_channel().await.expect("the pipe still carries");
    ours.write_all(b"after the epoch").await.unwrap();
    let (from, mut theirs) = timeout(Duration::from_secs(10), bob.inbound.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, alice.key);
    let mut got = [0u8; 15];
    theirs.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"after the epoch");
}

/// Both sides advertise for each other and connect at once: of the two
/// pipes the one whose central has the lower identity key survives, the
/// other is reset (DUPLICATE); one link stays.
#[tokio::test(start_paused = true)]
async fn duplicate_pipes_collapse_to_one() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xA6, &[0xB6], FakeOpts::default());
    let bob = Node::new(&ether, 0xB6, &[0xA6], FakeOpts::default());
    until("keys", || {
        alice.engine.has_keys(&bob.key) && bob.engine.has_keys(&alice.key)
    })
    .await;
    alice.engine.on(bob.key, None);
    bob.engine.on(alice.key, None);
    until("pipes", || {
        alice.engine.has_pipe(&bob.key) && bob.engine.has_pipe(&alice.key)
    })
    .await;
    until("one link", || ether.links() == 1).await;
    sleep(Duration::from_secs(5)).await;
    assert_eq!(ether.links(), 1);
    let central = alice.key.min(bob.key);
    let a_pipe = alice
        .engine
        .pipe_for(bob.key, Duration::from_secs(1))
        .await
        .unwrap();
    let want = if central == alice.key {
        Role::Central
    } else {
        Role::Peripheral
    };
    assert_eq!(a_pipe.role(), want, "the lower key's central survives");
    assert_eq!((alice.status().pipes, bob.status().pipes), (1, 1));
}

/// P6.38: with pair seeds both sides advertise and knock with the pair's
/// seed, and a pipe comes up with no notice. A contact without its seed
/// (it lost it, or an older build) advertises with the root: this side
/// still finds it with the root's key set and knocks with that set (the
/// fallback: no lockout), and notes `SEC_PAIR_SEED_ROOT`, since it expected
/// the seed.
#[tokio::test(start_paused = true)]
async fn pair_seeds_find_and_knock_with_the_seed_or_fall_back_to_the_root() {
    use raven_core::outbox::OutboxCarrier;
    use raven_core::security_events::{Attribution, SecKind, Via};
    let capture = crate::security::tests::Capture::start();
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xA8, &[0xB8], FakeOpts::default());
    let bob = Node::new(&ether, 0xB8, &[0xA8], FakeOpts::default());
    for node in [&alice, &bob] {
        *lock(&node.host.seed) = Some([0x38; 32]);
        node.host.generation.fetch_add(1, Ordering::SeqCst);
    }
    until("keys", || {
        alice.engine.has_keys(&bob.key) && bob.engine.has_keys(&alice.key)
    })
    .await;
    sleep(Duration::from_secs(6)).await;
    bob.engine
        .foreground(alice.key, crate::nearby::FOREGROUND_TTL);
    bob.engine.want(alice.key);
    until("seeded pipe", || alice.engine.has_pipe(&bob.key)).await;
    if let Some(c) = &capture {
        assert!(
            c.kinds().iter().all(|(k, ..)| *k != SecKind::PairSeedRoot),
            "the seed is no notice"
        );
    }
    sleep(crate::nearby::pipe::PIPE_IDLE + Duration::from_secs(5)).await;
    assert_eq!((alice.status().pipes, bob.status().pipes), (0, 0));

    // Bob lost his seed: the root alone.
    *lock(&bob.host.seed) = None;
    bob.host.generation.fetch_add(1, Ordering::SeqCst);
    sleep(Duration::from_secs(6)).await;
    bob.engine
        .foreground(alice.key, crate::nearby::FOREGROUND_TTL);
    bob.engine.want(alice.key);
    until("root pipe", || alice.engine.has_pipe(&bob.key)).await;
    if let Some(c) = &capture {
        assert!(c.kinds().contains(&(
            SecKind::PairSeedRoot,
            Attribution::Contact { peer: bob.key },
            Via::Dial(OutboxCarrier::Nearby),
        )));
    }
}

/// A pipe with no open channel for 30 s ends (IDLE) and frees its slot; a
/// contact that was only wanted is not advertised for again.
#[tokio::test(start_paused = true)]
async fn the_pipe_idle_reset_frees_the_slot() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xA7, &[0xB7], FakeOpts::default());
    let bob = Node::new(&ether, 0xB7, &[0xA7], FakeOpts::default());
    until("keys", || alice.engine.has_keys(&bob.key)).await;
    alice
        .engine
        .foreground(bob.key, crate::nearby::FOREGROUND_TTL);
    alice.engine.want(bob.key);
    until("pipe", || alice.engine.has_pipe(&bob.key)).await;
    assert_eq!(
        lock(&alice.host.ups).as_slice(),
        [bob.key],
        "the outbox kicked"
    );
    sleep(crate::nearby::pipe::PIPE_IDLE + Duration::from_secs(5)).await;
    assert_eq!((alice.status().pipes, bob.status().pipes), (0, 0));
    assert_eq!(ether.links(), 0);
    assert_eq!(alice.status().advertising, 0, "delivered: no want left");
}

/// A radio that can only be a central (Windows without a working GATT
/// server) advertises nothing, and still receives: it finds the contact
/// that advertises for it, and that contact's channel reaches it.
#[tokio::test(start_paused = true)]
async fn a_central_only_radio_still_receives() {
    let ether = Ether::new(EtherParams::default());
    let mut alice = Node::new(
        &ether,
        0xA8,
        &[0xB8],
        FakeOpts {
            central_only: true,
            ..FakeOpts::default()
        },
    );
    let bob = Node::new(&ether, 0xB8, &[0xA8], FakeOpts::default());
    until("keys", || {
        alice.engine.has_keys(&bob.key) && bob.engine.has_keys(&alice.key)
    })
    .await;
    alice.engine.on(bob.key, None);
    sleep(Duration::from_secs(3)).await;
    assert_eq!(alice.status().advertising, 0);
    assert_eq!(alice.status().roles, ["central"]);
    bob.engine.on(alice.key, None);
    until("pipe", || bob.engine.has_pipe(&alice.key)).await;
    let pipe = bob
        .engine
        .pipe_for(alice.key, Duration::from_secs(1))
        .await
        .unwrap();
    let mut ours = pipe.open_channel().await.unwrap();
    ours.write_all(b"hi").await.unwrap();
    let (from, mut theirs) = timeout(Duration::from_secs(10), alice.inbound.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, bob.key);
    let mut got = [0u8; 2];
    theirs.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hi");
}

// ── Advertising ─────────────────────────────────────────────────────────────

/// RNL1 §3: one token on air, at most two contacts in rotation (the most
/// recent first), 5 s each.
#[tokio::test(start_paused = true)]
async fn at_most_one_token_on_air_and_two_contacts_rotate() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xA9, &[0xB9, 0xC9, 0xD9], FakeOpts::default());
    until("keys", || alice.engine.has_keys(&key(0xD9))).await;
    alice.engine.on(key(0xB9), Some(Duration::from_secs(3_600)));
    alice.engine.on(key(0xC9), Some(Duration::from_secs(7_200)));
    alice
        .engine
        .on(key(0xD9), Some(Duration::from_secs(10_800)));
    let (mut scanner, mut rx) = bare(&ether, "scanner");
    scanner.set_scanning(true).unwrap();
    let mut seen: HashSet<[u8; 16]> = HashSet::new();
    timeout(Duration::from_secs(30), async {
        while let Some(ev) = rx.recv().await {
            if let RadioEvent::Seen { uuids, .. } = ev {
                assert_eq!(uuids.len(), 1, "one token on air");
                seen.insert(uuids[0]);
            }
        }
    })
    .await
    .unwrap_err();
    let rotating: HashSet<[u8; 16]> = [0xC9, 0xD9]
        .iter()
        .map(|s| token_out(0xA9, *s, T0))
        .collect();
    assert_eq!(seen, rotating, "the two most recent, both");
    let status = alice.status();
    assert_eq!((status.advertising, status.rotating), (1, 2));
}

/// User work keeps a contact advertised for while something is queued for
/// it, for 15 min (RNL1 §3 (a)); then advertising stops. Work alone, or a
/// want alone, puts nothing on air.
#[tokio::test(start_paused = true)]
async fn the_foreground_ttl_expires_and_advertising_stops() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xAA, &[0xBA, 0xCA], FakeOpts::default());
    until("keys", || alice.engine.has_keys(&key(0xCA))).await;
    alice
        .engine
        .foreground(key(0xBA), crate::nearby::FOREGROUND_TTL);
    alice.engine.want(key(0xCA));
    sleep(Duration::from_secs(2)).await;
    assert_eq!(alice.status().advertising, 0, "work alone, a want alone");
    alice.engine.want(key(0xBA));
    sleep(Duration::from_secs(2)).await;
    assert_eq!(alice.status().advertising, 1);
    sleep(crate::nearby::FOREGROUND_TTL).await;
    assert_eq!(alice.status().advertising, 0, "the TTL ran out");
    assert_eq!(alice.status().rotating, 0);
}

/// RNL1 §3 (owner decision O5-12): a radio that would advertise from its
/// public address does not advertise, unless a debug lab run allows it.
#[tokio::test(start_paused = true)]
async fn a_public_address_radio_refuses_to_advertise() {
    let ether = Ether::new(EtherParams::default());
    let public = FakeOpts {
        public_address: true,
        ..FakeOpts::default()
    };
    let alice = Node::new(&ether, 0xAB, &[0xBB], public);
    until("keys", || alice.engine.has_keys(&key(0xBB))).await;
    // Offline mesh carry research, Phase 0: an engine that cannot go on the
    // air is no carrier the planners or custody may count.
    assert!(!alice.engine.may_go_on_air());
    alice.engine.on(key(0xBB), None);
    sleep(Duration::from_secs(5)).await;
    assert_eq!(alice.status().advertising, 0);
    assert_eq!(alice.status().address_privacy, "public");
    assert!(ether.adverts().is_empty());
    let lab = Node::with(&ether, 0xAC, &[0xBB], public, true);
    until("keys", || lab.engine.has_keys(&key(0xBB))).await;
    assert!(
        lab.engine.may_go_on_air(),
        "the lab run allows the public address"
    );
    lab.engine.on(key(0xBB), None);
    until("the lab run advertises", || lab.status().advertising == 1).await;
    let random = Node::new(&ether, 0xAA, &[0xBB], FakeOpts::default());
    assert!(
        random.engine.may_go_on_air(),
        "a random address goes on the air"
    );
}

/// Cutoff addendum F11d: with background mail on, a contact something waits
/// for is advertised for with no user work; with it off it is not.
#[tokio::test(start_paused = true)]
async fn background_mail_makes_a_contact_eligible_only_with_the_policy() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xAD, &[0xBD], FakeOpts::default());
    until("keys", || alice.engine.has_keys(&key(0xBD))).await;
    *lock(&alice.host.work) = vec![key(0xBD)];
    sleep(WORK_EVERY + Duration::from_secs(2)).await;
    assert_eq!(alice.status().advertising, 0, "the policy is off");
    alice.engine.set_background_mail(true);
    until("advertised for", || alice.status().advertising == 1).await;
    alice.engine.set_background_mail(false);
    until("not any more", || alice.status().advertising == 0).await;
}

/// F11d: a custodian advertises for the recipients it holds mail for (its
/// host's work: [`crate::nearby::NodeHost`] reads the custody store while
/// custody is live), with background mail on.
#[tokio::test(start_paused = true)]
async fn a_custodian_advertises_for_held_recipients() {
    use raven_core::custody_gate::{set_custody_gates_for_this_thread, CustodyGates};
    let dir = tempfile::tempdir().unwrap();
    let recipient = key(0xBE);
    let now = raven_core::clock::now_ms();
    let mut store = raven_core::friend_custody::CustodyStore::open_or_create(dir.path()).unwrap();
    store
        .deposit(
            &[9; 32],
            &recipient,
            &key(0xCE),
            &[1; 16],
            &[0; 16],
            now + 3_600_000,
            now,
        )
        .unwrap();
    // A letter held for another contact counts only while letters are
    // served (merge I.5).
    let letter_to = key(0xBF);
    store
        .deposit_letter(
            &[8; 32],
            &letter_to,
            &key(0xCE),
            &[8; 900],
            now + 3_600_000,
            now,
        )
        .unwrap();
    drop(store);
    let node_host = crate::nearby::NodeHost {
        data_dir: dir.path().to_path_buf(),
        identity: Arc::new(id(0xAE)),
        admission: crate::netutil::Admission::new(crate::netutil::NEARBY_INBOUND),
    };
    let letters = |on: bool| {
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(on));
        raven_core::horizon::set_lab_letter_for_this_thread(Some(on));
    };
    letters(true);
    set_custody_gates_for_this_thread(Some(CustodyGates {
        live: false,
        wan: false,
    }));
    assert!(node_host.has_work().await.is_empty(), "custody off: nobody");
    set_custody_gates_for_this_thread(Some(CustodyGates {
        live: true,
        wan: false,
    }));
    let with_letters = node_host.has_work().await;
    letters(false);
    let work = node_host.has_work().await;
    set_custody_gates_for_this_thread(None);
    raven_core::horizon::set_lab_horizon_for_this_thread(None);
    raven_core::horizon::set_lab_letter_for_this_thread(None);
    assert_eq!(with_letters, [recipient, letter_to]);
    assert_eq!(work, [recipient]);

    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xAE, &[0xBE], FakeOpts::default());
    *lock(&alice.host.work) = work;
    alice.engine.set_background_mail(true);
    until("advertised for the recipient", || {
        ether
            .adverts()
            .iter()
            .any(|a| a.uuids == [token_out(0xAE, 0xBE, T0)])
    })
    .await;
}

/// F11d: background contacts rotate round-robin per epoch, so with one slot
/// left by user work eight of them each get a slot within eight epochs (two
/// hours), and with both slots free within four.
#[test]
fn rotation_gives_eight_background_contacts_a_slot_in_two_hours() {
    let now = Instant::now();
    let later = now + Duration::from_secs(60);
    let background: Vec<[u8; 32]> = (1..=8u8).map(|s| [s; 32]).collect();
    let all = |_: &[u8; 32]| true;
    let none = HashMap::new();
    for (fg_count, epochs) in [(1usize, 8u64), (0, 4)] {
        let fg: HashMap<[u8; 32], Instant> = (0..fg_count).map(|_| ([0xF0; 32], later)).collect();
        let wants = fg.clone();
        let mut slots: HashSet<[u8; 32]> = HashSet::new();
        for epoch in 1_000..1_000 + epochs {
            let r = rotation(now, epoch, all, &fg, &wants, &none, &background);
            assert_eq!(r.len(), MAX_ROTATION, "always full");
            if fg_count == 1 {
                assert_eq!(r[0], [0xF0; 32], "user work first");
            }
            slots.extend(r.into_iter().filter(|p| background.contains(p)));
        }
        assert_eq!(
            slots.len(),
            8,
            "{fg_count} foreground: every one in {epochs} epochs"
        );
    }
}

/// The rotation's rules: user work counts only while something is queued
/// (and both are fresh), `nearby on` always, the most recent two first; a
/// contact the engine may not use never; background contacts only in the
/// slots left.
#[test]
fn the_rotation_takes_the_most_recent_two() {
    let now = Instant::now();
    let at = |s: u64| now + Duration::from_secs(s);
    let (b, c, d, e) = ([0xB; 32], [0xC; 32], [0xD; 32], [0xE; 32]);
    let fg = HashMap::from([(b, at(100)), (c, at(300)), (d, at(200))]);
    let wants = HashMap::from([(b, at(50)), (c, at(50)), (d, now)]);
    let none = HashMap::new();
    let all = |_: &[u8; 32]| true;
    // d's want ran out: c (newest), then b.
    assert_eq!(rotation(now, 0, all, &fg, &wants, &none, &[e]), [c, b]);
    // `nearby on` without an end is the most recent of all.
    let on = HashMap::from([(e, None)]);
    assert_eq!(rotation(now, 0, all, &fg, &wants, &on, &[]), [e, c]);
    // A contact the engine may not use (no key, a pipe up) is skipped.
    let not_c = |p: &[u8; 32]| *p != c;
    assert_eq!(rotation(now, 0, not_c, &fg, &wants, &none, &[e]), [b, e]);
    assert!(rotation(now, 0, all, &HashMap::new(), &wants, &none, &[]).is_empty());
}

/// `raven nearby disable` (or the service ending): the engine resets every
/// pipe, takes everything off the air and ends; a dial then hears that
/// nearby is not running.
#[tokio::test(start_paused = true)]
async fn stop_resets_every_pipe_and_leaves_the_air() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0xAF, &[0xBF], FakeOpts::default());
    let bob = Node::new(&ether, 0xBF, &[0xAF], FakeOpts::default());
    until("keys", || alice.engine.has_keys(&bob.key)).await;
    alice.engine.on(bob.key, None);
    until("pipe", || bob.engine.has_pipe(&alice.key)).await;
    let Node { engine, task, .. } = alice;
    engine.stop();
    timeout(Duration::from_secs(10), task)
        .await
        .expect("the engine ends")
        .unwrap();
    assert!(!engine.is_running());
    assert!(!engine.has_pipe(&bob.key) && !engine.has_keys(&bob.key));
    until("Bob's end too", || !bob.engine.has_pipe(&key(0xAF))).await;
    assert_eq!(ether.links(), 0);
    assert_eq!(
        engine.pipe_for(bob.key, Duration::from_secs(1)).await.err(),
        Some(NEARBY_NOT_RUNNING.to_string())
    );
}

// ── Review fixes (Phase 5 review, area nearby) ──────────────────────────────

/// Review nearby-1 (owner decision O5-12): a radio that would use its fixed
/// public address does not connect either (a CONNECT_IND carries the
/// initiator's address in the clear, as an advert carries the
/// advertiser's) and does not scan, also for a contact that advertises for
/// it with nothing queued here. A debug lab run that allows the public
/// address connects.
#[tokio::test(start_paused = true)]
async fn a_public_address_radio_neither_connects_nor_scans() {
    let ether = Ether::new(EtherParams::default());
    let public = FakeOpts {
        public_address: true,
        ..FakeOpts::default()
    };
    let alice = Node::new(&ether, 0x11, &[0x12], public);
    until("keys", || alice.engine.has_keys(&key(0x12))).await;
    let t = token_out(0x12, 0x11, T0);
    let (mut bob, mut b_rx) = bare(&ether, "bob");
    bob.set_services(&[t], Some(t)).unwrap();
    let connected = |ev: &RadioEvent| matches!(ev, RadioEvent::Connected { .. });
    let got = next_where(&mut b_rx, Duration::from_secs(90), connected).await;
    assert_eq!(got, None, "no connect from a public address");
    assert!(ether.hellos().is_empty(), "no knock");
    let status = alice.status();
    assert_eq!(status.address_privacy, "public");
    assert_eq!((status.advertising, status.in_range), (0, 0), "no scan");
    assert_eq!(
        alice
            .engine
            .pipe_for(key(0x12), Duration::from_secs(1))
            .await
            .err()
            .as_deref(),
        Some(NEARBY_NOT_IN_RANGE),
        "a dial does not connect either"
    );
    let lab = Node::with(&ether, 0x13, &[0x12], public, true);
    until("keys", || lab.engine.has_keys(&key(0x12))).await;
    let t2 = token_out(0x12, 0x13, T0);
    bob.set_services(&[t2], Some(t2)).unwrap();
    let got = next_where(&mut b_rx, Duration::from_secs(60), connected).await;
    assert!(got.is_some(), "the lab run connects");
    until("its HELLO", || ether.hellos().iter().any(|(s, _)| *s == t2)).await;
}

/// Review nearby-4: a token recorded near a contact and played back
/// elsewhere by someone without the pair key (no CHALLENGE that verifies)
/// makes this node connect [`TOKEN_STRIKES`] times, not twice a scan cycle
/// for as long as the token can match: not again in the next epoch either.
/// Once the token can no longer match, the contact's new token links on
/// its first sighting; so does another contact meanwhile.
#[tokio::test(start_paused = true)]
async fn a_replayed_token_gets_at_most_two_connects() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0x41, &[0x42, 0x43], FakeOpts::default());
    until("keys", || alice.engine.has_keys(&key(0x43))).await;
    // Recorded near Bob (a public UUID), replayed here by Eve, who has no
    // key.
    let t = token_out(0x42, 0x41, T0);
    let (mut eve, mut e_rx) = bare(&ether, "eve");
    eve.set_services(&[t], Some(t)).unwrap();
    let connects = |rx: &mut mpsc::Receiver<RadioEvent>| {
        let mut n = 0;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, RadioEvent::Connected { .. }) {
                n += 1;
            }
        }
        n
    };
    sleep(Duration::from_secs(600)).await;
    assert_eq!(
        connects(&mut e_rx),
        usize::from(TOKEN_STRIKES),
        "in ten minutes"
    );
    // The next epoch: the token still matches, and is still not dialled.
    alice.advance_clock(raven_core::nearby_link::EPOCH_MS);
    sleep(Duration::from_secs(120)).await;
    assert_eq!(connects(&mut e_rx), 0, "the next epoch");
    // A genuine contact meanwhile links on its first sighting.
    let carol = Node::new(&ether, 0x43, &[0x41], FakeOpts::default());
    carol.advance_clock(raven_core::nearby_link::EPOCH_MS);
    until("Carol's keys", || carol.engine.has_keys(&alice.key)).await;
    carol.engine.on(alice.key, None);
    until("Carol's pipe", || alice.engine.has_pipe(&carol.key)).await;
    // Two epochs on, the replayed token cannot match; Bob's new one links.
    eve.set_services(&[], None).unwrap();
    alice.advance_clock(raven_core::nearby_link::EPOCH_MS);
    let bob = Node::new(&ether, 0x42, &[0x41], FakeOpts::default());
    bob.advance_clock(2 * raven_core::nearby_link::EPOCH_MS);
    until("Bob's keys", || bob.engine.has_keys(&alice.key)).await;
    bob.engine.on(alice.key, None);
    until("Bob's pipe", || alice.engine.has_pipe(&bob.key)).await;
}

/// Review nearby-4: a success forgets a failed knock, so two transient
/// failures of a contact's token far apart never stop this node from
/// connecting to it.
#[tokio::test(start_paused = true)]
async fn a_successful_knock_forgets_a_failed_one() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0x51, &[0x52], FakeOpts::default());
    let bob = Node::new(&ether, 0x52, &[0x51], FakeOpts::default());
    until("keys", || {
        alice.engine.has_keys(&bob.key) && bob.engine.has_keys(&alice.key)
    })
    .await;
    for round in 0..2 {
        // The next frame on the ether (Alice's HELLO) is lost: that knock
        // fails; the next one, after CONNECT_GAP, brings the pipe up.
        ether.arm_faults(Some(0), None);
        bob.engine.on(alice.key, None);
        until("the pipe", || alice.engine.has_pipe(&bob.key)).await;
        assert!(ether.fault_stats().1, "round {round}: a HELLO was lost");
        bob.engine.off(alice.key);
        // The pipe idles out; nothing is on air for Alice any more.
        until("the pipe ends", || !alice.engine.has_pipe(&bob.key)).await;
    }
}

/// Review nearby-5: a stranger's subscription to this node's service for
/// Bob (a peripheral knock for Bob that anyone in range can start) neither
/// holds back this node's own connect to Bob, whom it sees, nor fails a
/// dial to Bob at the stranger's deadline.
#[tokio::test(start_paused = true)]
async fn a_strangers_knock_neither_blocks_nor_fails_a_dial() {
    let ether = Ether::new(EtherParams::default());
    let alice = Node::new(&ether, 0x21, &[0x22], FakeOpts::default());
    let bob_key = key(0x22);
    until("keys", || alice.engine.has_keys(&bob_key)).await;
    alice.engine.on(bob_key, None);
    let t_ab = token_out(0x21, 0x22, T0);
    let (mut mallory, mut m_rx) = bare(&ether, "mallory");
    let _held = connect_to(&mut mallory, &mut m_rx, t_ab).await;
    let since = Instant::now();
    // Alice stops advertising (the stranger's service stays while its
    // knock lives), so Bob cannot connect to her: only her own connect can
    // bring the pipe up.
    alice.engine.off(bob_key);
    until("nothing on air", || alice.status().advertising == 0).await;
    let dial = {
        let engine = alice.engine.clone();
        tokio::spawn(async move { engine.pipe_for(bob_key, Duration::from_secs(12)).await })
    };
    let bob = Node::new(&ether, 0x22, &[0x21], FakeOpts::default());
    until("Bob's keys", || bob.engine.has_keys(&alice.key)).await;
    bob.engine.on(alice.key, None);
    let pipe = timeout(Duration::from_secs(12), dial)
        .await
        .expect("the dial ends")
        .unwrap();
    assert!(pipe.is_ok(), "{:?}", pipe.err());
    assert!(
        since.elapsed() < KNOCK_DEADLINE,
        "up before the stranger's knock ran out: {:?}",
        since.elapsed()
    );
    assert_eq!(alice.status().in_range, 1);
}

/// Review nearby-6 (RNL1 §8): many contacts seen at once never bring more
/// than [`MAX_PIPES`] pipes up, also when three are up already and eight
/// more come into range together; the cap is reached.
#[tokio::test(start_paused = true)]
async fn many_contacts_at_once_never_exceed_the_pipe_cap() {
    let ether = Ether::new(EtherParams {
        latency: Duration::from_millis(30),
        ..EtherParams::default()
    });
    let seeds: Vec<u8> = (0x31..=0x3B).collect();
    let alice = Node::new(&ether, 0x30, &seeds, FakeOpts::default());
    let others: Vec<Node> = seeds
        .iter()
        .map(|s| Node::new(&ether, *s, &[0x30], FakeOpts::default()))
        .collect();
    until("keys", || {
        seeds.iter().all(|s| alice.engine.has_keys(&key(*s)))
            && others.iter().all(|n| n.engine.has_keys(&key(0x30)))
    })
    .await;
    // Three first.
    for n in &others[..3] {
        n.engine.on(alice.key, None);
    }
    until("three pipes", || alice.status().pipes == 3).await;
    // Then eight at once.
    for n in &others[3..] {
        n.engine.on(alice.key, None);
    }
    assert_eq!(
        most_pipes(&alice, Duration::from_secs(10)).await as usize,
        MAX_PIPES,
        "at most {MAX_PIPES}, and the cap is reached"
    );
    // From none: all eleven at once.
    for n in &others {
        n.engine.off(alice.key);
    }
    until("every pipe idled out", || alice.status().pipes == 0).await;
    for n in &others {
        n.engine.on(alice.key, None);
    }
    assert_eq!(
        most_pipes(&alice, Duration::from_secs(10)).await as usize,
        MAX_PIPES
    );
}

/// The most pipes `node` has up at once, looked at every 50 ms for `span`.
async fn most_pipes(node: &Node, span: Duration) -> u32 {
    let mut most = 0;
    let end = Instant::now() + span;
    while Instant::now() < end {
        sleep(Duration::from_millis(50)).await;
        most = most.max(node.status().pipes);
    }
    most
}

/// Re-verify of review nearby-6: a dial to a contact in range while this
/// node's pipe cap is taken only by knocks still under way failed at once
/// with NEARBY_NOT_IN_RANGE, which is not what happened. It fails
/// NEARBY_BUSY now; a contact that is not seen is still not in range.
#[tokio::test(start_paused = true)]
async fn a_dial_while_the_knocks_fill_the_cap_is_busy_not_out_of_range() {
    let ether = Ether::new(EtherParams::default());
    let contacts = [0x62, 0x63, 0x64, 0x65, 0x66, 0x67];
    let alice = Node::new(&ether, 0x61, &contacts, FakeOpts::default());
    let bob = Node::new(&ether, 0x66, &[0x61], FakeOpts::default());
    until("keys", || {
        contacts.iter().all(|s| alice.engine.has_keys(&key(*s))) && bob.engine.has_keys(&alice.key)
    })
    .await;
    // Something in Alice's rotation keeps her scanning without a pause.
    alice.engine.on(key(0x67), None);
    // Four contacts' tokens played back by radios that never answer: four
    // knocks of Alice's under way fill her cap until their deadline.
    let mut eves = Vec::new();
    for s in &contacts[..4] {
        let t = token_out(*s, 0x61, T0);
        let (mut eve, rx) = bare(&ether, &format!("eve-{s:02x}"));
        eve.set_services(&[t], Some(t)).unwrap();
        eves.push((eve, rx));
    }
    until("four HELLOs", || ether.hellos().len() >= 4).await;
    let since = Instant::now();
    // Bob comes into range: seen, not dialled.
    bob.engine.on(alice.key, None);
    until("Bob seen", || alice.status().in_range == 5).await;
    let err = alice
        .engine
        .pipe_for(bob.key, Duration::from_secs(1))
        .await
        .err();
    assert!(since.elapsed() < KNOCK_DEADLINE, "{:?}", since.elapsed());
    assert_eq!(err.as_deref(), Some(NEARBY_BUSY));
    let unseen = alice
        .engine
        .pipe_for(key(0x67), Duration::from_secs(1))
        .await
        .err();
    assert_eq!(unseen.as_deref(), Some(NEARBY_NOT_IN_RANGE));
}

/// Re-verify of review nearby-4/nearby-6: a contact whose pipes are all
/// taken stayed silent to a HELLO that verified, and that silence counted
/// against its token here: two knocks and the token was barred while it
/// could match, so the contact was not reached once it had room again. It
/// answers now and resets the pipe with LIMIT (it never holds more than
/// MAX_PIPES), the knock is no strike, a dial meanwhile is busy, and the
/// first knock after a pipe frees up stays.
#[tokio::test(start_paused = true)]
async fn a_full_contact_answers_so_its_token_is_not_barred() {
    let ether = Ether::new(EtherParams::default());
    let others: [u8; 4] = [0x73, 0x74, 0x75, 0x76];
    let mut book = vec![0x71];
    book.extend(others);
    let bob = Node::new(&ether, 0x72, &book, FakeOpts::default());
    let alice = Node::new(&ether, 0x71, &[0x72], FakeOpts::default());
    let nodes: Vec<Node> = others
        .iter()
        .map(|s| Node::new(&ether, *s, &[0x72], FakeOpts::default()))
        .collect();
    until("keys", || {
        book.iter().all(|s| bob.engine.has_keys(&key(*s)))
            && alice.engine.has_keys(&bob.key)
            && nodes.iter().all(|n| n.engine.has_keys(&bob.key))
    })
    .await;
    // Bob's four pipes, each with a channel open (never idle).
    let mut held = Vec::new();
    for n in &nodes {
        bob.engine.on(n.key, None);
        until("a pipe to Bob", || n.engine.has_pipe(&bob.key)).await;
        let pipe = n
            .engine
            .pipe_for(bob.key, Duration::from_secs(30))
            .await
            .expect("a pipe to Bob");
        held.push((pipe.open_channel().await.expect("a channel"), pipe));
        bob.engine.off(n.key);
    }
    assert_eq!(bob.status().pipes, 4);
    // Bob advertises for Alice: her knocks verify, and Bob resets each
    // pipe at once. A dial of hers meanwhile is busy.
    bob.engine.on(alice.key, None);
    let mut busy = false;
    let end = Instant::now() + Duration::from_secs(60);
    while Instant::now() < end {
        let got = alice.engine.pipe_for(bob.key, Duration::from_secs(1)).await;
        busy |= got.err().as_deref() == Some(NEARBY_BUSY);
        assert!(bob.status().pipes <= 4, "never more than MAX_PIPES");
        sleep(Duration::from_millis(500)).await;
    }
    assert!(busy, "a dial while Bob is full says so");
    assert!(!bob.engine.has_pipe(&alice.key));
    // One of Bob's contacts goes: Alice's next knock gets the pipe.
    nodes[0].set_contacts(&[]);
    until("Alice's pipe at Bob", || bob.engine.has_pipe(&alice.key)).await;
    assert!(bob.status().pipes <= 4);
}
