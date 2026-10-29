//! Tests of the onion carrier's service task, status and dial.

use super::*;

/// E2 r38: `raven status` reads "reachable" off this line
/// (`raven_core::onion::status_line_says_reachable`): only a ready Tor with
/// its onion service reachable, with or without its outage history.
#[test]
fn status_lines_and_the_reachable_reading_agree() {
    use raven_core::onion::status_line_says_reachable as reachable;
    let now = Instant::now();
    let mut s = Status {
        phase: Phase::Ready,
        ..Status::default()
    };
    assert!(!reachable(&status_line(&s, now)), "publishing");
    s.service_reachable = Some(true);
    assert!(reachable(&status_line(&s, now)));
    s.outages.began(now);
    s.outages.ended(now + Duration::from_secs(60));
    assert!(reachable(&status_line(&s, now + Duration::from_secs(120))));
    s.service_reachable = Some(false);
    assert!(!reachable(&status_line(&s, now)));
    s.service_reachable = None;
    assert!(!reachable(&status_line(&s, now)), "publishing with history");
    for phase in [
        Phase::Off,
        Phase::NotBuilt,
        Phase::Starting,
        Phase::Blocked,
        Phase::CantStart,
        Phase::Restarting,
    ] {
        let s = Status {
            phase,
            service_reachable: Some(true),
            ..Status::default()
        };
        assert!(!reachable(&status_line(&s, now)), "{phase:?}");
    }
}

#[test]
fn status_lines_say_states_only() {
    let now = Instant::now();
    let mut s = Status::default();
    assert_eq!(status_line(&s, now), "Tor: off");
    s.phase = Phase::NotBuilt;
    assert_eq!(status_line(&s, now), "Tor: not built in this raven");
    s.phase = Phase::Starting;
    s.pct = 45;
    assert_eq!(status_line(&s, now), "Tor: starting (45 %)");
    s.tor_says = Some("offline");
    assert_eq!(
        status_line(&s, now),
        "Tor: starting (45 %, Tor says: offline)"
    );
    s.phase = Phase::Ready;
    assert_eq!(
        status_line(&s, now),
        "Tor: ready (onion service publishing)"
    );
    s.service_reachable = Some(true);
    assert_eq!(status_line(&s, now), "Tor: ready");
    s.service_reachable = Some(false);
    s.service_why = Some("Arti: degraded_unreachable, descriptor upload failed".into());
    assert_eq!(
        status_line(&s, now),
        "Tor: ready, onion service unreachable (Arti: degraded_unreachable, descriptor upload \
         failed)"
    );
    // Round 9: the outage going on (how long, and how many since start),
    // and once it is over, the last one stays readable.
    let min = |m: u64| Duration::from_secs(m * 60);
    s.outages.began(now);
    s.service_why = Some("self-check failed: no descriptor; Arti: running".into());
    assert_eq!(
        status_line(&s, now + min(12)),
        "Tor: ready, onion service unreachable for 12 min (self-check failed: no descriptor; \
         Arti: running; onion service outages since start: 1)"
    );
    s.outages.ended(now + min(16));
    s.service_reachable = Some(true);
    s.service_why = None;
    assert_eq!(
        status_line(&s, now + min(41)),
        "Tor: ready (onion service outages since start: 1, the last lasted 16 min and ended 25 \
         min ago)"
    );
    s.service_reachable = None;
    assert_eq!(
        status_line(&s, now + min(41)),
        "Tor: ready (onion service publishing; onion service outages since start: 1, the last \
         lasted 16 min and ended 25 min ago)"
    );
    s.outages = Outages::default();
    s.phase = Phase::Blocked;
    s.why = Some("no Tor relay answered".into());
    s.retry_at = Some(now + Duration::from_secs(30));
    assert_eq!(
        status_line(&s, now),
        "Tor: blocked on this network (no Tor relay answered; retrying in 30 s)"
    );
    s.phase = Phase::CantStart;
    s.why = Some("stuck at 15 % after Tor relays answered".into());
    assert_eq!(
        status_line(&s, now),
        "Tor: could not start on this computer (stuck at 15 % after Tor relays answered; \
         retrying in 30 s)"
    );
    s.phase = Phase::Restarting;
    s.why = Some(End::Woke.words().into());
    s.retry_at = None;
    assert_eq!(status_line(&s, now), "Tor: restarting (woke from sleep)");
    s.retry_at = Some(now + Duration::from_secs(600));
    assert_eq!(
        status_line(&s, now),
        "Tor: restarting (woke from sleep; retrying in 10 min)"
    );
}

#[test]
fn the_helper_is_found_next_to_raven_node_or_by_a_lab_switch() {
    let exe = PathBuf::from("/opt/raven/raven-node");
    let helper = PathBuf::from(format!(
        "/opt/raven/{HELPER_EXECUTABLE}{}",
        std::env::consts::EXE_SUFFIX
    ));
    let all = |_: &Path| true;
    let only = |p: PathBuf| move |q: &Path| q == p;
    // Release: only the helper next to raven-node, whatever the variables say.
    assert_eq!(
        Launcher::find_with(false, None, None, Some(exe.clone()), only(helper.clone())),
        Some(Launcher::Exe(helper.clone()))
    );
    assert_eq!(
        Launcher::find_with(
            false,
            Some("/tmp/reg".into()),
            Some("/tmp/other".into()),
            Some(exe.clone()),
            only(helper.clone())
        ),
        Some(Launcher::Exe(helper.clone()))
    );
    assert_eq!(
        Launcher::find_with(false, None, None, Some(exe.clone()), |_| false),
        None
    );
    // Debug: the loopback registry first (absolute only), then the variable.
    assert_eq!(
        Launcher::find_with(true, Some("/tmp/reg".into()), None, Some(exe.clone()), all),
        Some(Launcher::Loopback {
            exe: exe.clone(),
            dir: "/tmp/reg".into()
        })
    );
    assert_eq!(
        Launcher::find_with(
            true,
            Some("reg".into()),
            None,
            Some(exe.clone()),
            only(helper.clone())
        ),
        Some(Launcher::Exe(helper.clone()))
    );
    assert_eq!(
        Launcher::find_with(true, None, Some("/x/helper".into()), Some(exe.clone()), all),
        Some(Launcher::Exe("/x/helper".into()))
    );
    // A relative or missing helper path is no helper.
    assert_eq!(
        Launcher::find_with(true, None, Some("helper".into()), Some(exe.clone()), all),
        None
    );
}

#[tokio::test]
async fn line_reader_bounds_lines_and_ends_cleanly() {
    let long = "x".repeat(proto::MAX_LINE + 10);
    let text = format!("one\n{long}\ntwo\r\nthree");
    let mut r = LineReader::new(Box::pin(std::io::Cursor::new(text.into_bytes())));
    assert_eq!(r.next_line().await.as_deref(), Some("one"));
    // The over-long line is skipped whole.
    assert_eq!(r.next_line().await.as_deref(), Some("two"));
    // A last line without a newline is not a line.
    assert_eq!(r.next_line().await, None);
}

#[test]
fn arti_obsolete_words_are_recognised() {
    assert!(says_obsolete(
        "Shutting down because of unsupported software version."
    ));
    assert!(!says_obsolete("bootstrap 45 %"));
}

// ── End to end over the loopback helper (no Tor network) ────────────────────

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

/// One node's onion side in this process: its forward listener (serving
/// its profile) and its loopback helper on in-memory pipes; the helper's
/// connect address and onion key once it said them.
struct Side {
    connect: SocketAddr,
    hs_id: [u8; 32],
    forward: SocketAddr,
    token: [u8; proto::TOKEN_LEN],
    _tasks: Vec<AbortOnDrop>,
    _stdin: Pin<Box<dyn AsyncWrite + Send>>,
}

async fn side(dir: &Path, registry: &Path) -> Side {
    let identity = Arc::new(raven_core::load_identity_required(dir).unwrap());
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let forward = listener.local_addr().unwrap();
    let token: [u8; proto::TOKEN_LEN] = rand::random();
    let serving = tokio::spawn(serve_forward(
        listener,
        Arc::new(std::sync::Mutex::new(token)),
        dir.to_path_buf(),
        identity,
    ));
    let (to_helper, helper_in) = tokio::io::duplex(64 * 1024);
    let (helper_out, from_helper) = tokio::io::duplex(64 * 1024);
    let registry = registry.to_path_buf();
    let helper = tokio::spawn(async move {
        let _ = loopback::serve(
            Box::pin(helper_in),
            Box::pin(helper_out),
            registry,
            loopback::Knobs::default(),
        )
        .await;
    });
    let mut stdin: Pin<Box<dyn AsyncWrite + Send>> = Box::pin(to_helper);
    let config = proto::Config {
        v: proto::PROTO_VERSION,
        state_dir: dir.join(TOR_DIR).to_string_lossy().into_owned(),
        token: hex::encode(token),
        forward: forward.to_string(),
        port: raven_core::onion::ONION_VIRTUAL_PORT,
        fresh_state: false,
    };
    stdin
        .write_all(proto::line(&config).as_bytes())
        .await
        .unwrap();
    let mut events = LineReader::new(Box::pin(from_helper));
    let (mut connect, mut hs_id) = (None, None);
    while connect.is_none() || hs_id.is_none() {
        let line = tokio::time::timeout(Duration::from_secs(10), events.next_line())
            .await
            .expect("helper events")
            .expect("helper line");
        match serde_json::from_str::<Event>(&line).unwrap() {
            Event::Ready { connect: c } => connect = Some(c.parse().unwrap()),
            Event::Onion { hs_id: h } => hs_id = proto::parse_hs_id(&h),
            _ => {}
        }
    }
    Side {
        connect: connect.unwrap(),
        hs_id: hs_id.unwrap(),
        forward,
        token,
        _tasks: vec![
            AbortOnDrop(serving.abort_handle()),
            AbortOnDrop(helper.abort_handle()),
        ],
        _stdin: stdin,
    }
}

/// Two real profiles exchange a sealed message and its sealed ACK each way
/// over the onion carrier: the onion link (prologue raven/onion-link/v1,
/// the same handshake and contact gate as Internet direct) through the
/// loopback helper's "onion services". Then: an onion key nobody runs is
/// ONION_UNREACHABLE, and a local connection to the forward port without the
/// helper's token gets no Raven byte. Lab run only (RAVEN_LAB_TEST_A=1 with
/// RAVEN_LAB_TOR=1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_profiles_exchange_messages_and_acks_over_the_onion_link() {
    use crate::outbox::test_rig::{contacts, lab_backends, pair};
    if !lab_backends() || !raven_core::onion_live_enabled() {
        eprintln!("skipped: needs RAVEN_LAB_TEST_A=1 RAVEN_LAB_TOR=1 (debug)");
        return;
    }
    let _one_at_a_time = LAB_ONION.lock().await;
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let registry = tempfile::tempdir().unwrap();
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

    let side_a = side(a.path(), registry.path()).await;
    let side_b = side(b.path(), registry.path()).await;
    assert_ne!(side_a.hs_id, side_b.hs_id);
    // This process dials through Alice's helper (the shared registry is
    // "the Tor network": any helper reaches any registered service).
    *live_lock() = Some(Live {
        token: side_a.token,
        connect: Some(side_a.connect),
        binding: None,
    });

    // Field test round 8: Bob's node just restarted and his service is not
    // reachable yet when Alice dials; it is a second later. The helper's
    // second try (a fresh descriptor, fresh circuits) delivers within the
    // same dial.
    let entry = registry.path().join(hex::encode(side_b.hs_id));
    let published = std::fs::read_to_string(&entry).unwrap();
    std::fs::remove_file(&entry).unwrap();
    let back_up = {
        let entry = entry.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            std::fs::write(&entry, published).unwrap();
        })
    };
    let to_bob = seal(a.path(), &alice, &key_ab, "over Tor");
    let friend_links = FRIEND_LINKS.load(std::sync::atomic::Ordering::Relaxed);
    let t = std::time::Instant::now();
    let replies = dial_with_meta(
        a.path(),
        &raven_core::onion::dial_for(&side_b.hs_id),
        &hex::encode(bob_pub),
        &[to_bob],
        DialMeta::default(),
    )
    .await
    .expect("delivered over the onion link, by the helper's second try");
    back_up.await.unwrap();
    assert!(t.elapsed() < Duration::from_secs(15), "{:?}", t.elapsed());
    // Bob's side counted Alice's authenticated link as proof that his onion
    // service is reachable (`friend_reached_us`).
    assert!(FRIEND_LINKS.load(std::sync::atomic::Ordering::Relaxed) > friend_links);
    assert_eq!(
        raven_core::outbox::ack_frames(&replies).len(),
        1,
        "a sealed ACK"
    );
    assert_eq!(inbox(b.path()), ["over Tor"]);

    let to_alice = seal(b.path(), &bob, &key_ba, "and back over Tor");
    let replies = dial_with_meta(
        b.path(),
        &raven_core::onion::dial_for(&side_a.hs_id),
        &hex::encode(alice_pub),
        &[to_alice],
        DialMeta::default(),
    )
    .await
    .expect("delivered over the onion link");
    assert_eq!(
        raven_core::outbox::ack_frames(&replies).len(),
        1,
        "a sealed ACK"
    );
    assert_eq!(inbox(a.path()), ["and back over Tor"]);

    // An onion key nobody runs: the helper says unreachable.
    let nobody = Identity::from_seed(&[0x5a; 32]).public_key_bytes();
    let err = dial_with_meta(
        a.path(),
        &raven_core::onion::dial_for(&nobody),
        &hex::encode(bob_pub),
        &[],
        DialMeta::default(),
    )
    .await
    .unwrap_err();
    assert!(err.starts_with("ONION_UNREACHABLE"), "{err}");
    assert!(
        !err.contains(&hex::encode(nobody)),
        "no onion key in errors: {err}"
    );

    // Another local program without the token: closed, no Raven byte.
    let mut stranger = TcpStream::connect(side_b.forward).await.unwrap();
    stranger
        .write_all(&[0u8; proto::FORWARD_HEADER_LEN])
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let got = tokio::time::timeout(Duration::from_secs(5), stranger.read(&mut buf))
        .await
        .expect("closed in time");
    assert!(matches!(got, Ok(0) | Err(_)), "{got:?}");

    *live_lock() = None;
}

/// The lab onion tests share this process's helper state ([`live_lock`]):
/// one at a time.
static LAB_ONION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Two verified friends, each with an onion side (forward listener and
/// loopback helper); this process dials through Alice's helper.
struct Friends {
    a: tempfile::TempDir,
    _b: tempfile::TempDir,
    _registry: tempfile::TempDir,
    alice: Identity,
    bob_pub: [u8; 32],
    key_ab: raven_core::indexed_session_store::IndexedSessionRecordKey,
    side_a: Side,
    side_b: Side,
}

impl Friends {
    /// `None` (skipped) outside a lab run.
    async fn new() -> Option<Self> {
        use crate::outbox::test_rig::{contacts, lab_backends, pair};
        if !lab_backends() || !raven_core::onion_live_enabled() {
            eprintln!("skipped: needs RAVEN_LAB_TEST_A=1 RAVEN_LAB_TOR=1 (debug)");
            return None;
        }
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let registry = tempfile::tempdir().unwrap();
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
        let side_a = side(a.path(), registry.path()).await;
        let side_b = side(b.path(), registry.path()).await;
        *live_lock() = Some(Live {
            token: side_a.token,
            connect: Some(side_a.connect),
            binding: None,
        });
        Some(Self {
            a,
            _b: b,
            _registry: registry,
            alice,
            bob_pub,
            key_ab,
            side_a,
            side_b,
        })
    }

    /// Alice dials Bob's onion service with one sealed message.
    async fn alice_dials_bob(&self, text: &str) -> Result<Vec<Vec<u8>>, String> {
        let sealed = seal(self.a.path(), &self.alice, &self.key_ab, text);
        dial_with_meta(
            self.a.path(),
            &raven_core::onion::dial_for(&self.side_b.hs_id),
            &hex::encode(self.bob_pub),
            &[sealed],
            DialMeta::default(),
        )
        .await
    }

    /// A Tor stream to Bob's onion service through Alice's helper (a new
    /// "circuit" each), opened and then left silent.
    async fn silent_stream_to_bob(&self) -> TcpStream {
        let mut s = TcpStream::connect(self.side_a.connect).await.unwrap();
        s.write_all(&proto::encode_connect(
            &self.side_a.token,
            &self.side_b.hs_id,
            raven_core::onion::ONION_VIRTUAL_PORT,
        ))
        .await
        .unwrap();
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.unwrap();
        let mut reason = vec![0u8; usize::from(head[1])];
        s.read_exact(&mut reason).await.unwrap();
        assert_eq!(head[0], 0, "the stream opened");
        s
    }
}

impl Drop for Friends {
    fn drop(&mut self) {
        *live_lock() = None;
    }
}

/// Security review 2026-10-29 #1: anyone holding a card opened 8 silent Tor
/// streams to a friend's onion service and every inbound onion slot was
/// theirs (one fixed source for all onion links); the friend's dial failed
/// until they let go. Now the slots are counted per circuit and a full
/// listener displaces a silent link of the busiest circuit: a friend gets
/// in while a stranger holds 16 silent streams.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_tor_streams_of_a_stranger_cannot_lock_a_friend_out() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::new().await else {
        return;
    };
    let mut held = Vec::new();
    for _ in 0..16 {
        held.push(f.silent_stream_to_bob().await);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let replies = f
        .alice_dials_bob("over Tor, past a stranger's streams")
        .await
        .expect("a friend is not locked out by silent streams");
    assert_eq!(raven_core::outbox::ack_frames(&replies).len(), 1);
    drop(held);
}

/// Security review 2026-10-29 #1: the streams of one rendezvous circuit
/// (the helper's circuit number) count against that circuit's own caps: a
/// third pre-auth link on one circuit is closed at once, and a friend on
/// another circuit gets in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_circuit_cannot_take_every_onion_slot() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::new().await else {
        return;
    };
    let mut held = Vec::new();
    for _ in 0..8 {
        let mut s = TcpStream::connect(f.side_b.forward).await.unwrap();
        s.write_all(&proto::encode_forward(&f.side_b.token, 7))
            .await
            .unwrap();
        held.push(s);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Past the circuit's pre-auth cap (2): closed without a byte.
    let mut closed = 0;
    for s in held.iter_mut() {
        let mut buf = [0u8; 8];
        if let Ok(Ok(0) | Err(_)) =
            tokio::time::timeout(Duration::from_millis(200), s.read(&mut buf)).await
        {
            closed += 1;
        }
    }
    assert_eq!(closed, 6, "one circuit keeps at most 2 pre-auth links");
    let replies = f
        .alice_dials_bob("over Tor, past one busy circuit")
        .await
        .expect("a friend on another circuit gets in");
    assert_eq!(raven_core::outbox::ack_frames(&replies).len(), 1);
}

/// Security review 2026-10-29 #1: a local program without the helper's
/// token held admission slots while the forward listener waited for the
/// token. Now the token comes before any slot: 40 bare local connections
/// (more than the pre-token cap) do not keep a friend out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_connections_without_the_token_take_no_onion_slot() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::new().await else {
        return;
    };
    let mut held = Vec::new();
    for _ in 0..(PRE_TOKEN_MAX + 8) {
        held.push(TcpStream::connect(f.side_b.forward).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let replies = f
        .alice_dials_bob("over Tor, past local strangers")
        .await
        .expect("a friend is not locked out by tokenless local connections");
    assert_eq!(raven_core::outbox::ack_frames(&replies).len(), 1);
    drop(held);
}

/// The pre-token queue is bounded: one past [`PRE_TOKEN_MAX`] closes the
/// oldest waiting connection, and a connection that leaves frees its place.
#[tokio::test]
async fn the_pre_token_queue_closes_its_oldest_when_full() {
    let pre = PreToken::default();
    let (first, first_kicked) = pre.enter();
    let mut rest = Vec::new();
    for _ in 1..PRE_TOKEN_MAX {
        rest.push(pre.enter());
    }
    assert_eq!(pre.len(), PRE_TOKEN_MAX);
    let _newcomer = pre.enter();
    assert_eq!(pre.len(), PRE_TOKEN_MAX);
    tokio::time::timeout(Duration::from_millis(100), first_kicked.notified())
        .await
        .expect("the oldest was told to close");
    pre.leave(first);
    pre.leave(rest[0].0);
    assert_eq!(pre.len(), PRE_TOKEN_MAX - 1);
}

/// An admitted onion link that sends nothing gives its slot back after
/// [`FIRST_MESSAGE_WAIT`] (here a short wait), not after the whole 30 s
/// handshake deadline; a dialer that speaks passes.
#[tokio::test]
async fn a_silent_onion_stream_is_closed_before_the_handshake_deadline() {
    assert!(FIRST_MESSAGE_WAIT < raven_core::onion::ONION_HANDSHAKE_DEADLINE / 2);
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let mut silent = TcpStream::connect(addr).await.unwrap();
    let (theirs, _) = listener.accept().await.unwrap();
    let err = first_message_within(&theirs, Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(err.contains("Noise message 1"), "{err}");
    silent.write_all(b"x").await.unwrap();
    first_message_within(&theirs, Duration::from_millis(500))
        .await
        .expect("a byte arrived");
    // Not consumed: the handshake still reads it.
    let mut one = [0u8; 1];
    let mut theirs = theirs;
    theirs.read_exact(&mut one).await.unwrap();
    assert_eq!(&one, b"x");
}

// ── The supervisor's watchdogs and last words (fake helper, paused clock) ───

/// How the fake helper behaves after its config line.
#[derive(Clone, Copy)]
enum Fake {
    /// Reaches Tor relays, stops at 15 % fetching the consensus, answers
    /// pings (field test S15 on Windows, Arti #2726).
    StuckAnswering,
    /// Stops at 15 % and answers nothing (a hung helper).
    StuckSilent,
    /// No relay ever answers; Tor says it cannot reach the network.
    NoRelay,
    /// Says a local error, then exits.
    LocalError,
    /// Bootstrapped far enough that its onion service is publishing
    /// (Arti: bootstrapping), and answers pings.
    Publishing,
}

async fn fake_helper(fake: Fake, input: tokio::io::DuplexStream, output: tokio::io::DuplexStream) {
    let mut lines = LineReader::new(Box::pin(input));
    let mut out: Pin<Box<dyn AsyncWrite + Send>> = Box::pin(output);
    let say = |ev: Event| proto::line(&ev);
    if lines.next_line().await.is_none() {
        return;
    }
    let first = match fake {
        Fake::NoRelay => say(Event::Progress {
            pct: 0,
            blocked: Some("Can't reach the Tor network".into()),
            stage: Some("stuck".into()),
        }),
        Fake::LocalError => say(Event::Error {
            what: "Tor client not created: folder permissions".into(),
            local: true,
        }),
        Fake::Publishing => {
            let hs_id = Identity::from_seed(&[0x36; 32]).public_key_bytes();
            let onion = say(Event::Onion {
                hs_id: hex::encode(hs_id),
            });
            let service = say(Event::Service {
                state: "bootstrapping".into(),
                reason: None,
            });
            format!("{onion}{service}")
        }
        Fake::StuckAnswering | Fake::StuckSilent => say(Event::Progress {
            pct: 15,
            blocked: None,
            stage: Some("consensus".into()),
        }),
    };
    if out.write_all(first.as_bytes()).await.is_err() || matches!(fake, Fake::LocalError) {
        return;
    }
    while let Some(line) = lines.next_line().await {
        let command = serde_json::from_str::<proto::Command>(&line);
        if let (Fake::Publishing, Ok(proto::Command::SelfCheck { n })) = (fake, &command) {
            // Our own service, reached as a friend would.
            let answer = say(Event::SelfCheck {
                n: *n,
                reached: true,
                reason: None,
            });
            if out.write_all(answer.as_bytes()).await.is_err() {
                return;
            }
        }
        if let (
            Fake::StuckAnswering | Fake::NoRelay | Fake::Publishing,
            Ok(proto::Command::Ping { n }),
        ) = (fake, command)
        {
            if out
                .write_all(say(Event::Pong { n }).as_bytes())
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

fn fake_proc(fake: Fake) -> Proc {
    let (to_helper, helper_in) = tokio::io::duplex(64 * 1024);
    let (helper_out, from_helper) = tokio::io::duplex(64 * 1024);
    let helper = tokio::spawn(fake_helper(fake, helper_in, helper_out));
    let (kill, killed) = tokio::sync::oneshot::channel::<()>();
    let abort = helper.abort_handle();
    let done = async move {
        tokio::select! {
            _ = helper => {}
            _ = killed => abort.abort(),
        }
    };
    Proc {
        stdin: Box::pin(to_helper),
        stdout: Box::pin(from_helper),
        stderr: None,
        done: Box::pin(done),
        kill: Some(kill),
    }
}

async fn one_life(fake: Fake) -> (End, Blame, Duration, String) {
    let dir = tempfile::tempdir().unwrap();
    let identity = Arc::new(Identity::from_seed(&[0x33; 32]));
    let config = proto::Config {
        v: proto::PROTO_VERSION,
        state_dir: dir.path().join(TOR_DIR).to_string_lossy().into_owned(),
        token: "00".repeat(proto::TOKEN_LEN),
        forward: "127.0.0.1:9".into(),
        port: raven_core::onion::ONION_VIRTUAL_PORT,
        fresh_state: false,
    };
    let started = tokio::time::Instant::now();
    let mut restarts = Restarts::default();
    let (end, life) = run_once(
        fake_proc(fake),
        &config,
        &mut restarts,
        dir.path(),
        &identity,
    )
    .await;
    let ran = started.elapsed();
    let summary = life.summary(end, now_for_watchdogs());
    (end, life.blame(end), ran, summary)
}

/// Field test S15 (win-c): a start stuck at 15 % after Tor relays answered
/// is not "blocked on this network": it ends at the early stall window (not
/// 45 s), blamed on this computer, and the helper's last words say where.
#[tokio::test(start_paused = true)]
async fn a_start_stuck_after_relays_answered_is_this_computers_problem() {
    let (end, blame, ran, summary) = one_life(Fake::StuckAnswering).await;
    assert_eq!(end, End::ProgressStall);
    assert!(
        ran >= watch::STALL_EARLY && ran < watch::STALL_EARLY + Duration::from_secs(3),
        "{ran:?}"
    );
    assert_eq!(
        blame,
        Blame::ThisComputer("stuck at 15 % after Tor relays answered".into())
    );
    assert!(summary.contains("15 %, stage consensus"), "{summary}");
    assert!(!summary.contains("answered 0 pings"), "{summary}");
}

#[tokio::test(start_paused = true)]
async fn a_silent_helper_is_hung_on_this_computer() {
    let (end, blame, ran, _) = one_life(Fake::StuckSilent).await;
    assert_eq!(end, End::Unresponsive);
    assert!(
        ran >= watch::PING_DEAD && ran < watch::PING_DEAD + Duration::from_secs(3),
        "{ran:?}"
    );
    assert_eq!(
        blame,
        Blame::ThisComputer("the Tor helper hung at 15 %".into())
    );
}

#[tokio::test(start_paused = true)]
async fn no_relay_answering_is_the_network() {
    let (end, blame, _, summary) = one_life(Fake::NoRelay).await;
    assert_eq!(end, End::ProgressStall);
    assert_eq!(blame, Blame::Network("Tor says: cant_reach_tor".into()));
    assert!(summary.contains("Tor says cant_reach_tor"), "{summary}");
}

#[tokio::test(start_paused = true)]
async fn a_local_error_says_why_tor_could_not_start_here() {
    let (end, blame, ran, summary) = one_life(Fake::LocalError).await;
    assert_eq!(end, End::Exited);
    assert!(ran < Duration::from_secs(10), "{ran:?}");
    assert_eq!(
        blame,
        Blame::ThisComputer("Tor client not created: folder permissions".into())
    );
    assert!(
        summary.contains("helper error (this computer): Tor client not created"),
        "{summary}"
    );
}

#[test]
fn a_panic_on_stderr_is_recognised() {
    assert!(says_panicked(
        "thread 'tokio-runtime-worker' panicked at src/x.rs:1:2:"
    ));
    assert!(!says_panicked("bootstrap 45 %"));
}

/// A friend's authenticated incoming Tor link proves our onion service
/// reachable for `raven status` while Arti still says "bootstrapping"
/// (field test round 8).
#[tokio::test(start_paused = true)]
async fn a_friends_tor_link_makes_status_say_reachable_before_arti_does() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Arc::new(Identity::from_seed(&[0x35; 32]));
    let config = proto::Config {
        v: proto::PROTO_VERSION,
        state_dir: dir.path().join(TOR_DIR).to_string_lossy().into_owned(),
        token: "00".repeat(proto::TOKEN_LEN),
        forward: "127.0.0.1:9".into(),
        port: raven_core::onion::ONION_VIRTUAL_PORT,
        fresh_state: false,
    };
    let data_dir = dir.path().to_path_buf();
    let life = tokio::spawn(async move {
        let mut restarts = Restarts::default();
        run_once(
            fake_proc(Fake::Publishing),
            &config,
            &mut restarts,
            &data_dir,
            &identity,
        )
        .await
    });
    tokio::time::sleep(Duration::from_secs(5)).await;
    friend_reached_us();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(status().service_reachable, Some(true));
    life.abort();
}

/// Round 9: Arti said "degraded_unreachable" while friends could reach the
/// service. A self-check measures it: after the first one (three minutes
/// after the service was launched) the status says reachable although
/// Arti still says "bootstrapping".
#[tokio::test(start_paused = true)]
async fn a_self_check_that_reaches_the_service_makes_status_say_reachable() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Arc::new(Identity::from_seed(&[0x37; 32]));
    let config = proto::Config {
        v: proto::PROTO_VERSION,
        state_dir: dir.path().join(TOR_DIR).to_string_lossy().into_owned(),
        token: "00".repeat(proto::TOKEN_LEN),
        forward: "127.0.0.1:9".into(),
        port: raven_core::onion::ONION_VIRTUAL_PORT,
        fresh_state: false,
    };
    let data_dir = dir.path().to_path_buf();
    let links = FRIEND_LINKS.load(std::sync::atomic::Ordering::Relaxed);
    let life = tokio::spawn(async move {
        let mut restarts = Restarts::default();
        run_once(
            fake_proc(Fake::Publishing),
            &config,
            &mut restarts,
            &data_dir,
            &identity,
        )
        .await
    });
    tokio::time::sleep(watch::SELF_CHECK_FIRST + Duration::from_secs(5)).await;
    let status = status();
    life.abort();
    // (Another test's friend link would prove it too: only count this one
    // when none came meanwhile.)
    if FRIEND_LINKS.load(std::sync::atomic::Ordering::Relaxed) == links {
        assert_eq!(status.service_reachable, Some(true));
    }
}

/// A helper that reads its config line, keeps the token and ends at once.
struct TokenRecorder(Arc<std::sync::Mutex<Vec<String>>>);

impl Spawn for TokenRecorder {
    fn spawn(&self) -> Result<Proc, String> {
        let (to_helper, helper_in) = tokio::io::duplex(64 * 1024);
        let (helper_out, from_helper) = tokio::io::duplex(64 * 1024);
        let seen = Arc::clone(&self.0);
        let done = async move {
            let mut lines = LineReader::new(Box::pin(helper_in));
            if let Some(line) = lines.next_line().await {
                if let Ok(c) = serde_json::from_str::<proto::Config>(&line) {
                    seen.lock().unwrap().push(c.token);
                }
            }
            drop(helper_out);
        };
        Ok(Proc {
            stdin: Box::pin(to_helper),
            stdout: Box::pin(from_helper),
            stderr: None,
            done: Box::pin(done),
            kill: None,
        })
    }
}

/// Security review 2026-10-29 #11 (spec §6: "32 random bytes per helper
/// life"): the token was made once per run and every restarted helper got
/// the same one. Now each life gets a fresh token, and the forward
/// listener checks the current one.
#[tokio::test(start_paused = true)]
async fn every_helper_life_gets_a_fresh_token() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Arc::new(Identity::from_seed(&[0x38; 32]));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let first = [0x11u8; proto::TOKEN_LEN];
    let current = Arc::new(std::sync::Mutex::new(first));
    let config = proto::Config {
        v: proto::PROTO_VERSION,
        state_dir: dir.path().join(TOR_DIR).to_string_lossy().into_owned(),
        token: hex::encode(first),
        forward: "127.0.0.1:9".into(),
        port: raven_core::onion::ONION_VIRTUAL_PORT,
        fresh_state: false,
    };
    let task = tokio::spawn(supervise(
        Arc::new(TokenRecorder(Arc::clone(&seen))),
        config,
        Arc::clone(&current),
        dir.path().to_path_buf(),
        identity,
    ));
    tokio::time::sleep(Duration::from_secs(900)).await;
    task.abort();
    let tokens = seen.lock().unwrap().clone();
    assert!(tokens.len() >= 2, "{tokens:?}");
    assert_eq!(tokens[0], hex::encode(first));
    let distinct: std::collections::HashSet<&String> = tokens.iter().collect();
    assert_eq!(distinct.len(), tokens.len(), "a fresh token per life");
    let now = *current.lock().unwrap();
    assert!(tokens.contains(&hex::encode(now)));
}
