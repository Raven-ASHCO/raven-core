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
pub(super) fn seal(
    dir: &Path,
    identity: &Identity,
    key: &raven_core::indexed_session_store::IndexedSessionRecordKey,
    text: &str,
) -> Vec<u8> {
    seal_as(dir, identity, key, text, false)
}

/// [`seal`], and `queued`: handed to the outbox as `raven send` hands it,
/// so the session takes a next message behind it (one prepared message per
/// lane). Unqueued, the message stays prepared.
fn seal_as(
    dir: &Path,
    identity: &Identity,
    key: &raven_core::indexed_session_store::IndexedSessionRecordKey,
    text: &str,
    queued: bool,
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
        &mut |digest: &[u8; 32], bytes: &[u8]| {
            sealed = Some(bytes.to_vec());
            if queued {
                Ok(*digest)
            } else {
                Err(())
            }
        },
    );
    sealed.expect("sealed")
}

pub(super) fn inbox(dir: &Path) -> Vec<String> {
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
pub(super) struct Side {
    pub(super) connect: SocketAddr,
    pub(super) hs_id: [u8; 32],
    forward: SocketAddr,
    pub(super) token: [u8; proto::TOKEN_LEN],
    _tasks: Vec<AbortOnDrop>,
    _stdin: Pin<Box<dyn AsyncWrite + Send>>,
}

pub(super) async fn side(dir: &Path, registry: &Path) -> Side {
    side_with(dir, registry, loopback::Knobs::default()).await
}

/// [`side`] with its loopback helper's `knobs` (with `knobs.memory`, its
/// forward listener in memory too: [`serve_forward_in_memory`]).
async fn side_with(dir: &Path, registry: &Path, knobs: loopback::Knobs) -> Side {
    let identity = Arc::new(raven_core::load_identity_required(dir).unwrap());
    let token: [u8; proto::TOKEN_LEN] = rand::random();
    let (forward, serving) = if knobs.memory {
        let listener = memnet::Listener::bind();
        let forward = listener.local_addr();
        let serving = tokio::spawn(serve_forward_in_memory(
            listener,
            token,
            dir.to_path_buf(),
            identity,
        ));
        (forward, serving.abort_handle())
    } else {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let forward = listener.local_addr().unwrap();
        let serving = tokio::spawn(serve_forward(
            Intake::Tcp(listener),
            Arc::new(std::sync::Mutex::new(token)),
            dir.to_path_buf(),
            identity,
        ));
        (forward, serving.abort_handle())
    };
    let (to_helper, helper_in) = tokio::io::duplex(64 * 1024);
    let (helper_out, from_helper) = tokio::io::duplex(64 * 1024);
    let registry = registry.to_path_buf();
    let helper = tokio::spawn(async move {
        let _ = loopback::serve(Box::pin(helper_in), Box::pin(helper_out), registry, knobs).await;
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
    // Keep reading what the helper says next (its service state, pongs):
    // with its stdout dropped, the helper's next event fails to write, it
    // ends, and its connect port and its "descriptor" go with it, so a dial
    // through it reads ONION_NOT_READY and a dial to it "no descriptor"
    // (the lab onion tests failed so, now and then).
    let draining = tokio::spawn(async move { while events.next_line().await.is_some() {} });
    Side {
        connect: connect.unwrap(),
        hs_id: hs_id.unwrap(),
        forward,
        token,
        _tasks: vec![
            AbortOnDrop(serving),
            AbortOnDrop(helper.abort_handle()),
            AbortOnDrop(draining.abort_handle()),
        ],
        _stdin: stdin,
    }
}

/// [`serve_forward`] on a listener in memory ([`memnet`], for a test on the
/// paused clock): the helper's header before any slot, a slot per circuit
/// in this helper life, then the Raven link listener of the onion carrier
/// under the onion limits, as there. Not the parts that need a TCP stream
/// (the loopback source check, and the wait for Noise message 1 by a peek,
/// which takes no byte and no time of its own), nor a token that changes.
async fn serve_forward_in_memory(
    mut listener: memnet::Listener,
    token: [u8; proto::TOKEN_LEN],
    data_dir: PathBuf,
    identity: Arc<Identity>,
) {
    let limits = netutil::ONION_INBOUND;
    let admission = Admission::for_circuits(limits);
    let life = admission.new_life();
    while let Ok(stream) = listener.accept().await {
        let (dd, id) = (data_dir.clone(), identity.clone());
        let admission = Arc::clone(&admission);
        tokio::spawn(async move {
            let Ok((stream, circuit)) = check_token(stream, &token).await else {
                return;
            };
            let Ok(mut slot) = admission.admit_in_life(circuit_source(circuit), life) else {
                return;
            };
            let displaced = slot.displaced();
            let work = async move {
                ONION_LINK.require_live()?;
                internet_direct::serve_inbound_on(
                    ONION_LINK, dd, id, stream, limits, &mut slot, None, None, None,
                )
                .await
            };
            tokio::select! {
                _ = tokio::time::timeout(limits.lifetime, work) => {}
                () = displaced.notified() => {}
            }
        });
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
        connect: Some(Route::Port(side_a.connect)),
        binding: None,
        channel: None,
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

    // Another local program without the token: closed, no Raven byte
    // (version 4: raven-node's random challenge, nothing more).
    let mut stranger = TcpStream::connect(side_b.forward).await.unwrap();
    stranger
        .write_all(&[0u8; channel::FORWARD_HELLO_LEN])
        .await
        .unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stranger.read_to_end(&mut got))
        .await
        .expect("closed in time");
    assert!(got.len() <= channel::NONCE_LEN, "{} bytes", got.len());

    *live_lock() = None;
}

/// This process's onion state is shared: the helper state ([`live_lock`],
/// which the lab onion tests set and a helper life ([`run_once`],
/// [`supervise`]) changes on Ready and at its end) and the status
/// ([`status`], which a helper life writes and some tests read back). Every
/// test that sets or runs either takes this lock: one at a time, or one
/// test's helper life clears the connect address or the status another is
/// about to use.
pub(super) static LAB_ONION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    /// With the knobs' `memory`: both sides are in memory, and no real
    /// socket is dialled on this thread while they live.
    _memory_only: Option<memnet::MemoryOnly>,
}

impl Friends {
    /// `None` (skipped) outside a lab run.
    async fn new() -> Option<Self> {
        Self::with(loopback::Knobs::default()).await
    }

    /// [`Self::new`] with Alice's loopback helper's `knobs` (the one this
    /// process dials through). With `alice_knobs.memory`, Bob's side is in
    /// memory too: a test on the paused clock
    /// (`#[tokio::test(start_paused = true)]`, a current thread runtime)
    /// then times its sends in the model's round trips alone.
    async fn with(alice_knobs: loopback::Knobs) -> Option<Self> {
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
        let memory = alice_knobs.memory;
        let memory_only = memory.then(memnet::MemoryOnly::new);
        let side_a = side_with(a.path(), registry.path(), alice_knobs).await;
        let bob_knobs = loopback::Knobs {
            memory,
            ..loopback::Knobs::default()
        };
        let side_b = side_with(b.path(), registry.path(), bob_knobs).await;
        *live_lock() = Some(Live {
            token: side_a.token,
            connect: Some(Route::Port(side_a.connect)),
            binding: None,
            channel: None,
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
            _memory_only: memory_only,
        })
    }

    /// Alice dials Bob's onion service with one sealed message.
    async fn alice_dials_bob(&self, text: &str) -> Result<Vec<Vec<u8>>, String> {
        let sealed = seal(self.a.path(), &self.alice, &self.key_ab, text);
        self.alice_redials_bob(&sealed).await
    }

    /// Alice dials Bob's onion service with `sealed` (again: Bob answers
    /// a copy with the same ACK).
    async fn alice_redials_bob(&self, sealed: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        dial_with_meta(
            self.a.path(),
            &raven_core::onion::dial_for(&self.side_b.hs_id),
            &hex::encode(self.bob_pub),
            &[sealed.to_vec()],
            DialMeta::default(),
        )
        .await
    }

    /// A Tor stream to Bob's onion service through Alice's helper (a new
    /// "circuit" each), opened and then left silent.
    async fn silent_stream_to_bob(&self) -> TcpStream {
        let mut s = TcpStream::connect(self.side_a.connect).await.unwrap();
        let keys = channel::Keys::new(&self.side_a.token);
        let proof = channel::node_connect(&mut s, &keys).await.unwrap();
        s.write_all(&proto::encode_connect(
            &proof,
            &self.side_b.hs_id,
            raven_core::onion::ONION_VIRTUAL_PORT,
            0,
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

/// Inbound onion slots are counted per circuit, and a full listener
/// displaces a silent link of the busiest circuit: a friend gets in while a
/// stranger who holds the card keeps 16 silent Tor streams open to the onion
/// service.
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

/// The streams of one rendezvous circuit
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
        let keys = channel::Keys::new(&f.side_b.token);
        channel::helper_forward(&mut s, &keys, 7).await.unwrap();
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

/// Audit T6: the rendezvous circuit Alice's helper shares by default to
/// Bob is dead (Bob's network path vanished and no DESTROY came back). The
/// first dial pays for it once: its first try times out and the helper's
/// fresh try (a new isolation group) starts at once, with no pause, and
/// delivers. The dials after it reuse that fresh group at once. Before,
/// each of them met the dead circuit again (in the field: a 10 s timeout,
/// a 2 s pause and a whole new rendezvous per dial).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_dead_shared_circuit_later_dials_reuse_the_fresh_one() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let stale = Duration::from_secs(3);
    let Some(f) = Friends::with(loopback::Knobs {
        stale,
        count: true,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    // One message, dialled three times (Bob answers each copy with its ACK).
    let sealed = seal(f.a.path(), &f.alice, &f.key_ab, "past a dead circuit");
    let mut took = Vec::new();
    for _ in 0..3 {
        let began = Instant::now();
        let replies = f.alice_redials_bob(&sealed).await.expect("delivered");
        took.push(began.elapsed());
        assert_eq!(raven_core::outbox::ack_frames(&replies).len(), 1);
    }
    let counts = loopback::Counts::read(&f.a.path().join(TOR_DIR));
    eprintln!("three dials past a dead shared circuit: {took:?}, {counts:?}");
    assert!(took[0] >= stale, "{took:?} {counts:?}");
    assert!(
        took[0] < stale + proto::CONNECT_RETRY_PAUSE,
        "the fresh try waited after the timeout: {took:?} {counts:?}"
    );
    for t in &took[1..] {
        assert!(
            *t < stale,
            "a later dial met the dead circuit: {took:?} {counts:?}"
        );
    }
    assert_eq!(
        counts,
        loopback::Counts {
            connects: 3,
            tries: 4,
            stale: 1
        },
        "{took:?}"
    );
}

/// The stage record (speed groundwork, D1): each onion dial keeps one
/// record of durations, its steps split where the time goes. Over a
/// loopback Tor whose every connect takes `delay` and whose every byte
/// arrives `latency` later (one round trip r = 2 x latency): the connect
/// is at least `delay`, and Noise, the hellos and the receipt are one round
/// trip each (never two), the frame write only local work. The connect's
/// two parts add up to it. A send's check (no frames) has no write and no
/// receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tor_dial_timeline_splits_stream_link_and_receipt() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let (delay, latency) = (Duration::from_millis(900), Duration::from_millis(200));
    let Some(f) = Friends::with(loopback::Knobs {
        delay,
        latency,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    let ((), records) = stages::caught(async {
        let replies = f
            .alice_dials_bob("timed over Tor")
            .await
            .expect("delivered");
        assert_eq!(raven_core::outbox::ack_frames(&replies).len(), 1);
        let check = dial_with_meta(
            f.a.path(),
            &raven_core::onion::dial_for(&f.side_b.hs_id),
            &hex::encode(f.bob_pub),
            &[],
            DialMeta {
                send_check: true,
                ..DialMeta::default()
            },
        )
        .await
        .expect("the check answered");
        assert!(!check.is_empty(), "the friend's offer");
    })
    .await;
    eprintln!("stage records: {records:?}");
    assert_eq!(records.len(), 2, "one record per dial: {records:?}");
    let ms = |d: Duration| u32::try_from(d.as_millis()).unwrap();
    let (r, delay, slack) = (2 * ms(latency), ms(delay), 350);
    // One round trip, give or take local work, never two.
    let one_trip = |step: &str, got: Option<u32>| {
        let got = got.unwrap_or_else(|| panic!("no {step}: {records:?}"));
        assert!(
            (r..r + slack).contains(&got),
            "{step} {got} ms, r {r}: {records:?}"
        );
    };
    let (sent, checked) = (&records[0], &records[1]);
    assert_eq!(
        (sent.purpose, sent.frames, sent.ok),
        (stages::Purpose::Dial, 1, true)
    );
    assert_eq!(
        (checked.purpose, checked.frames, checked.ok),
        (stages::Purpose::Check, 0, true)
    );
    for record in [sent, checked] {
        let connect = record.connect_ms.expect("connect");
        assert!(
            (delay..delay + slack).contains(&connect),
            "connect: {record:?}"
        );
        assert_eq!(
            record.circuit_ms.zip(record.begin_ms).map(|(c, b)| c + b),
            Some(connect),
            "{record:?}"
        );
        one_trip("noise", record.noise_ms);
        one_trip("hello", record.hello_ms);
    }
    one_trip("receipt", sent.receipt_ms);
    assert!(sent.write_ms.expect("write") < slack, "{sent:?}");
    assert_eq!(
        (checked.write_ms, checked.receipt_ms),
        (None, None),
        "{checked:?}"
    );
}

/// Tor as a helper that is still starting says it ([`Phase::Starting`],
/// no connect port yet) until the guard goes; then as it was.
struct TorStarting;

impl TorStarting {
    fn now(f: &Friends) -> Self {
        *live_lock() = Some(Live {
            token: f.side_a.token,
            connect: None,
            binding: None,
            channel: None,
        });
        update_status(|s| s.phase = Phase::Starting);
        TorStarting
    }
}

impl Drop for TorStarting {
    fn drop(&mut self) {
        update_status(|s| *s = Status::default());
    }
}

/// The helper becomes ready after `after`, as the supervisor marks it
/// (its connect port, then the phase).
fn ready_after(after: Duration, connect: SocketAddr) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(after).await;
        if let Some(live) = live_lock().as_mut() {
            live.connect = Some(Route::Port(connect));
        }
        update_status(|s| s.phase = Phase::Ready);
    })
}

/// A send while Tor is still starting (the iPhone app back from the
/// background, audit T7): the onion dial waits for Tor to be ready, a
/// moment later, instead of failing at once with ONION_NOT_READY (the
/// message then waited for the outbox's next try).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_while_tor_starts_waits_until_it_is_ready() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::new().await else {
        return;
    };
    let _starting = TorStarting::now(&f);
    let ready = ready_after(Duration::from_millis(1500), f.side_a.connect);
    let began = Instant::now();
    let replies = f
        .alice_dials_bob("written while Tor starts")
        .await
        .expect("the dial waits for Tor");
    assert!(
        began.elapsed() >= Duration::from_millis(1400),
        "{:?}",
        began.elapsed()
    );
    assert_eq!(raven_core::outbox::ack_frames(&replies).len(), 1);
    ready.await.unwrap();
}

/// The wait has its bounds: a Tor still not ready when the dial's own
/// deadline comes is ONION_NOT_READY then, and a Tor that is not starting
/// (blocked on this network) is ONION_NOT_READY at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_waits_for_a_starting_tor_only_within_its_deadline() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::new().await else {
        return;
    };
    let _starting = TorStarting::now(&f);
    let sealed = seal(f.a.path(), &f.alice, &f.key_ab, "never sent");
    let (route, bob) = (
        raven_core::onion::dial_for(&f.side_b.hs_id),
        hex::encode(f.bob_pub),
    );
    let dial = |within: Duration| {
        dial_with_meta(
            f.a.path(),
            &route,
            &bob,
            std::slice::from_ref(&sealed),
            DialMeta {
                within: Some(within),
                ..DialMeta::default()
            },
        )
    };
    let began = Instant::now();
    let err = dial(Duration::from_millis(800)).await.unwrap_err();
    assert!(err.starts_with("ONION_NOT_READY"), "{err}");
    let took = began.elapsed();
    assert!(took >= Duration::from_millis(700), "{took:?}");
    assert!(took < Duration::from_secs(3), "{took:?}");

    update_status(|s| s.phase = Phase::Blocked);
    let began = Instant::now();
    let err = dial(Duration::from_secs(20)).await.unwrap_err();
    assert!(err.starts_with("ONION_NOT_READY"), "{err}");
    assert!(
        began.elapsed() < Duration::from_millis(500),
        "{:?}",
        began.elapsed()
    );
}

/// The helper's token comes before any admission slot: 40 bare local
/// connections without it (more than the pre-token cap) do not keep a
/// friend out.
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
    /// Ready (bootstrapped, a connect port) and its onion service launched
    /// while Arti still says "bootstrapping" (field test round 9); answers
    /// pings and self-checks. Its life outlasts the first self-check: a
    /// helper that never says Ready is ended as stalled first.
    ReadyPublishing,
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
        Fake::Publishing | Fake::ReadyPublishing => {
            let hs_id = Identity::from_seed(&[0x36; 32]).public_key_bytes();
            let ready = if matches!(fake, Fake::ReadyPublishing) {
                say(Event::Ready {
                    connect: "127.0.0.1:9".into(),
                })
            } else {
                String::new()
            };
            let onion = say(Event::Onion {
                hs_id: hex::encode(hs_id),
            });
            let service = say(Event::Service {
                state: "bootstrapping".into(),
                reason: None,
            });
            format!("{ready}{onion}{service}")
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
        if let (Fake::Publishing | Fake::ReadyPublishing, Ok(proto::Command::SelfCheck { n })) =
            (fake, &command)
        {
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
            Fake::StuckAnswering | Fake::NoRelay | Fake::Publishing | Fake::ReadyPublishing,
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
    let _one_at_a_time = LAB_ONION.lock().await;
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

/// Wait, in real time and without letting the paused clock run, until a
/// helper life has launched its onion service (its binding saved on the
/// blocking pool, the status published): a sleep here would let the clock
/// jump past what the test measures while the binding is being written.
async fn wait_launched() {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !status_lock().as_ref().is_some_and(|s| s.published) {
        assert!(
            std::time::Instant::now() < deadline,
            "the binding was never saved"
        );
        tokio::task::yield_now().await;
    }
}

/// A friend's authenticated incoming Tor link proves our onion service
/// reachable for `raven status` while Arti still says "bootstrapping"
/// (field test round 8).
#[tokio::test(start_paused = true)]
async fn a_friends_tor_link_makes_status_say_reachable_before_arti_does() {
    let _one_at_a_time = LAB_ONION.lock().await;
    // Another test's helper life may have left the status published.
    update_status(|s| *s = Status::default());
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
    wait_launched().await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    friend_reached_us();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(status().service_reachable, Some(true));
    life.abort();
}

/// Round 9: Arti said "degraded_unreachable" while friends could reach the
/// service. A self-check measures it: after the first one (three minutes
/// after the service was launched) the status says reachable although
/// Arti still says "bootstrapping". (The helper is Ready: one that never
/// says Ready is ended as stalled two minutes after its start, before any
/// self-check; the test passed only when the paused clock raced past the
/// launch.)
#[tokio::test(start_paused = true)]
async fn a_self_check_that_reaches_the_service_makes_status_say_reachable() {
    let _one_at_a_time = LAB_ONION.lock().await;
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
    // Another test's helper life may have left the status published.
    update_status(|s| *s = Status::default());
    let life = tokio::spawn(async move {
        let mut restarts = Restarts::default();
        run_once(
            fake_proc(Fake::ReadyPublishing),
            &config,
            &mut restarts,
            &data_dir,
            &identity,
        )
        .await
    });
    wait_launched().await;
    tokio::time::sleep(watch::SELF_CHECK_FIRST + Duration::from_secs(5)).await;
    let status = status();
    life.abort();
    // Its Ready set this process's "Tor is ready" flag: no later test sees it.
    raven_core::onion_gate::set_onion_ready(false);
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

/// Each helper life gets a fresh token (spec §6: "32 random bytes per
/// helper life"), not one per run, and the forward listener checks the
/// current one.
#[tokio::test(start_paused = true)]
async fn every_helper_life_gets_a_fresh_token() {
    let _one_at_a_time = LAB_ONION.lock().await;
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

// ── Tor off: too old for the Tor network, mobile data (owner 2026-10-30) ───

/// A helper that says Arti's "too old" words on stderr, as the helper (and
/// the in-process helper) does when the Tor network requires a protocol it
/// lacks, then ends; how many were started.
struct TooOldHelper(Arc<std::sync::atomic::AtomicUsize>);

impl Spawn for TooOldHelper {
    fn spawn(&self) -> Result<Proc, String> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (to_helper, helper_in) = tokio::io::duplex(64 * 1024);
        let (helper_out, from_helper) = tokio::io::duplex(64 * 1024);
        let (mut err_in, err_out) = tokio::io::duplex(1024);
        let done = async move {
            let mut lines = LineReader::new(Box::pin(helper_in));
            let _ = lines.next_line().await;
            let words = format!("{}\n", arti_words());
            let _ = err_in.write_all(words.as_bytes()).await;
            drop(err_in);
            drop(helper_out);
        };
        Ok(Proc {
            stdin: Box::pin(to_helper),
            stdout: Box::pin(from_helper),
            stderr: Some(Box::pin(err_out)),
            done: Box::pin(done),
            kill: None,
        })
    }
}

/// The words a too-old helper says (the Arti helper's [`arti::OBSOLETE_WORDS`]
/// where it is built).
fn arti_words() -> &'static str {
    #[cfg(feature = "tor-embedded")]
    {
        arti::OBSOLETE_WORDS
    }
    #[cfg(not(feature = "tor-embedded"))]
    {
        "Shutting down because of unsupported software version."
    }
}

/// A helper that reads its config line and then stays (answers pings, says
/// nothing else); how many were started and how many ended.
struct Quiet(
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
);

impl Spawn for Quiet {
    fn spawn(&self) -> Result<Proc, String> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let ended = Arc::clone(&self.1);
        let (to_helper, helper_in) = tokio::io::duplex(64 * 1024);
        let (helper_out, from_helper) = tokio::io::duplex(64 * 1024);
        let helper = tokio::spawn(fake_helper(Fake::Publishing, helper_in, helper_out));
        let (kill, killed) = tokio::sync::oneshot::channel::<()>();
        let abort = helper.abort_handle();
        let done = async move {
            tokio::select! {
                _ = helper => {}
                _ = killed => abort.abort(),
            }
            ended.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        };
        Ok(Proc {
            stdin: Box::pin(to_helper),
            stdout: Box::pin(from_helper),
            stderr: None,
            done: Box::pin(done),
            kill: Some(kill),
        })
    }
}

fn test_config(dir: &Path) -> proto::Config {
    proto::Config {
        v: proto::PROTO_VERSION,
        state_dir: dir.join(TOR_DIR).to_string_lossy().into_owned(),
        token: "00".repeat(proto::TOKEN_LEN),
        forward: "127.0.0.1:9".into(),
        port: raven_core::onion::ONION_VIRTUAL_PORT,
        fresh_state: false,
    }
}

/// Owner decision 2026-10-30: when the Tor network requires a protocol
/// this Tor lacks, Tor turns off ("update Raven") instead of the process
/// ending, and is never started again in this run.
#[tokio::test(start_paused = true)]
async fn a_tor_too_old_for_the_network_turns_tor_off_for_good() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task = tokio::spawn(supervise(
        Arc::new(TooOldHelper(Arc::clone(&starts))),
        test_config(dir.path()),
        Arc::new(Mutex::new([0u8; proto::TOKEN_LEN])),
        dir.path().to_path_buf(),
        Arc::new(Identity::from_seed(&[0x3a; 32])),
    ));
    tokio::time::sleep(Duration::from_secs(3600)).await;
    let line = status_line(&status(), Instant::now());
    task.abort();
    assert_eq!(starts.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        line,
        "Tor: off: this version is too old for the Tor network; update Raven"
    );
    assert!(!raven_core::onion_gate::onion_usable_now());
}

/// Owner decision 2026-10-30: Tor runs on mobile data unless the profile
/// says Tor on Wi-Fi only; then no helper runs while the app says the
/// device is on mobile data, a running one ends when it moves there, and
/// one starts again on Wi-Fi.
#[tokio::test(start_paused = true)]
async fn tor_on_wifi_only_keeps_tor_off_on_mobile_data() {
    use raven_core::net_path::{self, PathKind};
    use std::sync::atomic::Ordering::SeqCst;
    let _one_at_a_time = LAB_ONION.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let mut policy = raven_core::node_policy::NodePolicy {
        tor_wifi_only: true,
        ..Default::default()
    };
    raven_core::node_policy::save_policy(dir.path(), &policy).unwrap();
    let (starts, ended) = (
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    );
    net_path::set(PathKind::Cellular);
    let task = tokio::spawn(supervise(
        Arc::new(Quiet(Arc::clone(&starts), Arc::clone(&ended))),
        test_config(dir.path()),
        Arc::new(Mutex::new([0u8; proto::TOKEN_LEN])),
        dir.path().to_path_buf(),
        Arc::new(Identity::from_seed(&[0x3b; 32])),
    ));
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(starts.load(SeqCst), 0, "no Tor on mobile data");
    assert_eq!(
        status_line(&status(), Instant::now()),
        "Tor: off on mobile data (the setting uses Tor on Wi-Fi only)"
    );
    // Wi-Fi: Tor starts.
    net_path::set(PathKind::Wifi);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(starts.load(SeqCst), 1);
    assert_eq!(ended.load(SeqCst), 0);
    // Mobile data again: that life ends, no other starts.
    net_path::set(PathKind::Cellular);
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(ended.load(SeqCst), 1);
    assert_eq!(starts.load(SeqCst), 1);
    assert!(status_line(&status(), Instant::now()).starts_with("Tor: off on mobile data"));
    // The setting off: Tor runs on mobile data too (the default).
    policy.tor_wifi_only = false;
    raven_core::node_policy::save_policy(dir.path(), &policy).unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(starts.load(SeqCst), 2);
    task.abort();
    net_path::set(PathKind::Unknown);
}

/// Raven's arti-client patch (third_party/arti-client-0.47.0-raven): the
/// path a consensus requiring a missing protocol takes tells the helper
/// instead of ending the process. Without the patch this test process
/// would exit with 1 here.
#[cfg(feature = "tor-embedded")]
#[tokio::test]
async fn the_arti_patch_tells_the_helper_instead_of_exiting() {
    let life = arti::watch_too_old();
    let runtime = tor_rtcompat::PreferredRuntime::current().unwrap();
    arti_client::raven_delta::simulate_unsupported_software(&runtime).await;
    assert!(life.said.load(std::sync::atomic::Ordering::Acquire));
}

/// Tor is on in release builds (since 2026-10): raven-node's Status carries
/// its line, and so its start percentage, without a lab switch (the apps'
/// progress bar reads it from the engine's `network.status`).
#[test]
fn the_status_line_needs_no_lab_switch() {
    const { assert!(raven_core::ONION_PRODUCTION_ENABLED) };
    if raven_core::onion_live_enabled() {
        let line = status_text().expect("the gate is open: Status has the Tor line");
        assert!(line.starts_with("Tor: "), "{line}");
    } else {
        assert_eq!(status_text(), None);
    }
    let s = Status {
        phase: Phase::Starting,
        pct: 37,
        ..Status::default()
    };
    assert_eq!(status_line(&s, Instant::now()), "Tor: starting (37 %)");
}

// ── A ready helper whose onion service stays unreachable (paused clock) ─────

/// The fake helper `ReadyUnreachable` (its own here, beside [`Fake`]): Ready,
/// its onion service launched while Arti says "degraded_unreachable"; it
/// answers every ping and fails every self-check ("rendezvous failed"). Tor
/// itself works here; our onion service does not (stale introduction
/// points, uploads that keep failing).
fn ready_unreachable_proc() -> Proc {
    let (to_helper, helper_in) = tokio::io::duplex(64 * 1024);
    let (helper_out, from_helper) = tokio::io::duplex(64 * 1024);
    let helper = tokio::spawn(async move {
        let mut lines = LineReader::new(Box::pin(helper_in));
        let mut out: Pin<Box<dyn AsyncWrite + Send>> = Box::pin(helper_out);
        let say = |ev: Event| proto::line(&ev);
        if lines.next_line().await.is_none() {
            return;
        }
        let hs_id = Identity::from_seed(&[0x3e; 32]).public_key_bytes();
        let first = [
            say(Event::Ready {
                connect: "127.0.0.1:9".into(),
            }),
            say(Event::Onion {
                hs_id: hex::encode(hs_id),
            }),
            say(Event::Service {
                state: "degraded_unreachable".into(),
                reason: Some("descriptor upload timed out".into()),
            }),
        ]
        .concat();
        if out.write_all(first.as_bytes()).await.is_err() {
            return;
        }
        while let Some(line) = lines.next_line().await {
            let answer = match serde_json::from_str::<proto::Command>(&line) {
                Ok(proto::Command::Ping { n }) => say(Event::Pong { n }),
                Ok(proto::Command::SelfCheck { n }) => say(Event::SelfCheck {
                    n,
                    reached: false,
                    reason: Some("rendezvous failed".into()),
                }),
                _ => continue,
            };
            if out.write_all(answer.as_bytes()).await.is_err() {
                return;
            }
        }
    });
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

/// One helper life of `proc` under the paused clock, given up after an
/// hour: how it ended (`None`: it did not), how long it ran, and the
/// restart policy it left.
async fn one_hour_of(proc: Proc, seed: u8) -> (Option<(End, Life)>, Duration, Restarts) {
    let dir = tempfile::tempdir().unwrap();
    let identity = Arc::new(Identity::from_seed(&[seed; 32]));
    let mut restarts = Restarts::default();
    let started = tokio::time::Instant::now();
    let ended = tokio::time::timeout(
        Duration::from_secs(3600),
        run_once(
            proc,
            &test_config(dir.path()),
            &mut restarts,
            dir.path(),
            &identity,
        ),
    )
    .await
    .ok();
    let ran = started.elapsed();
    // Its Ready set this process's "Tor is ready" flag: no later test sees it.
    raven_core::onion_gate::set_onion_ready(false);
    (ended, ran, restarts)
}

/// A ready helper whose onion service stays unreachable while Tor answers
/// every ping: before, nothing ended its life until the next network change
/// (friends fell back to custody or waited). Now it is started again once it
/// was ready 12 min with two self-checks failed in a row, within 15 min of
/// ready, at once and blaming nobody; not again within the repair gap.
#[tokio::test(start_paused = true)]
async fn a_ready_helper_whose_onion_service_stays_unreachable_is_started_again() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let links = FRIEND_LINKS.load(std::sync::atomic::Ordering::Relaxed);
    let (ended, ran, mut restarts) = one_hour_of(ready_unreachable_proc(), 0x3c).await;
    let (end, life) = ended.expect("the stuck service ended the helper's life within an hour");
    eprintln!("a stuck onion service: its helper life ended after {ran:?}");
    assert_eq!(end, End::Unreachable);
    let blame = life.blame(end);
    assert_eq!(blame, Blame::Restart);
    // (Another test's friend link proves the service reachable and holds
    // the repair back for a while: only time it when none came meanwhile.)
    if FRIEND_LINKS.load(std::sync::atomic::Ordering::Relaxed) == links {
        assert!(
            ran >= watch::REPAIR_MIN_READY && ran < Duration::from_secs(15 * 60),
            "{ran:?}"
        );
    }
    assert!(!restarts.may_repair(now_for_watchdogs()), "the gap holds");
    let next = restarts.ended(end, ran, &blame);
    assert_eq!((next.wait, next.fresh_state), (Duration::ZERO, false));
    assert!(life
        .summary(end, now_for_watchdogs())
        .contains("(our onion service stayed unreachable)"));
}

/// The repair never ends a ready helper whose self-checks reach its onion
/// service, however long Arti says "bootstrapping" (round 9: Arti's word
/// alone is no outage).
#[tokio::test(start_paused = true)]
async fn a_ready_helper_whose_self_checks_reach_the_service_is_kept() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let (ended, ran, restarts) = one_hour_of(fake_proc(Fake::ReadyPublishing), 0x3d).await;
    if let Some((end, _)) = ended {
        panic!("ended after {ran:?}: {end:?}");
    }
    assert!(restarts.may_repair(now_for_watchdogs()), "no repair");
}

// ── W1: kept links (Tor speed Stage A, speed design M1) ────────────────────

/// One Tor round trip in the W1, M5 and M8 tests that time a send: a
/// loopback connect takes it, and every byte arrives half of it later.
/// Those tests run the loopback Tor model in memory on tokio's paused clock
/// (`Knobs::memory`, [`memnet`]): local work takes no time there, and only
/// the model's timers and the code's own waits move the clock. So a send
/// takes its round trips (and timeouts) exactly, whatever the load on the
/// computer (on the wall clock, CPU load stretched a send of 7 round trips
/// to 8 in a full run).
const R: Duration = Duration::from_millis(1000);

/// What may come on top of a time of whole round trips and timeouts on the
/// paused clock: timers end on a whole millisecond. Far less than the
/// model's smallest step (a byte's latency, r/2), so one round trip more or
/// less, or a timeout waited out, never passes for it.
const TICK: Duration = Duration::from_millis(5);

/// `took` is `want` on the paused clock ([`TICK`]).
fn about(took: Duration, want: Duration) -> bool {
    took >= want && took < want + TICK
}

/// A pool of one test's own, with `limits` and its own gate switch (open):
/// no other test's lock, network change or helper end empties it.
fn test_pool(
    limits: warm::Limits,
) -> (
    &'static warm::WarmPool,
    &'static std::sync::atomic::AtomicBool,
) {
    let (pool, gate, _hedge) = test_pool_with_hedge(limits);
    (pool, gate)
}

/// [`test_pool`] with its own hedge gate switch too (shut).
fn test_pool_with_hedge(
    limits: warm::Limits,
) -> (
    &'static warm::WarmPool,
    &'static std::sync::atomic::AtomicBool,
    &'static std::sync::atomic::AtomicBool,
) {
    let switch = |on: bool| -> &'static std::sync::atomic::AtomicBool {
        Box::leak(Box::new(std::sync::atomic::AtomicBool::new(on)))
    };
    let (gate, hedge) = (switch(true), switch(false));
    let pool: &'static warm::WarmPool = Box::leak(Box::new(warm::WarmPool::new(
        limits,
        warm::Gate::Switch(gate),
        warm::Gate::Switch(hedge),
    )));
    (pool, gate, hedge)
}

/// Waits until `ok` holds, at most `within` (on the paused clock, if the
/// test runs on it).
async fn until(what: &str, within: Duration, ok: impl Fn() -> bool) {
    let end = tokio::time::Instant::now() + within;
    while !ok() {
        assert!(tokio::time::Instant::now() < end, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

impl Friends {
    /// The Tor streams Alice's helper connected so far.
    fn connects(&self) -> u64 {
        loopback::Counts::read(&self.a.path().join(TOR_DIR)).connects
    }

    /// A program's dial of `frames` to Bob (none: a send's check), as
    /// `ipc_server` asks it, with the kept links of `pool` and the reply
    /// `waits`.
    async fn program_dials(
        &self,
        pool: &'static warm::WarmPool,
        waits: ReplyWaits,
        frames: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, String> {
        dial_with_pool(
            pool,
            waits,
            self.a.path(),
            &raven_core::onion::dial_for(&self.side_b.hs_id),
            &hex::encode(self.bob_pub),
            frames,
            DialMeta {
                send_check: frames.is_empty(),
                warm: true,
                ..DialMeta::default()
            },
        )
        .await
    }

    /// A program's send of `text` to Bob, as the app's engine makes it: its
    /// check, then its message (sealed first, local work outside the time
    /// taken, and queued so the next send can seal its own). How many ACKs
    /// came, and how long the check and the message took (on the paused
    /// clock, if the test runs on it).
    async fn program_sends(&self, pool: &'static warm::WarmPool, text: &str) -> (usize, Duration) {
        let sealed = seal_as(self.a.path(), &self.alice, &self.key_ab, text, true);
        let began = tokio::time::Instant::now();
        let check = self
            .program_dials(pool, ONION_WAITS, &[])
            .await
            .expect("the check answered");
        assert!(!check.is_empty(), "the friend's offer");
        let replies = self
            .program_dials(pool, ONION_WAITS, &[sealed])
            .await
            .expect("delivered");
        let took = began.elapsed();
        (raven_core::outbox::ack_frames(&replies).len(), took)
    }
}

/// W1 (speed design M1): with the warm gate open, a program's first send
/// over Tor (its check, then its message) costs 4 round trips and one Tor
/// stream, as the message rides its check's link; its next send within
/// WARM_IDLE costs 1 round trip and no stream, its check answered from the
/// kept link. On loopback Tor whose connect takes one round trip r and
/// whose every byte arrives r/2 later (in memory, on the paused clock: [`R`]).
#[tokio::test(start_paused = true)]
async fn a_send_after_the_check_rides_the_checks_link() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(loopback::Knobs {
        delay: R,
        latency: R / 2,
        count: true,
        memory: true,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    let (pool, _gate) = test_pool(warm::LIMITS);
    let (acks, first) = f.program_sends(pool, "first, on one link").await;
    assert_eq!(acks, 1);
    assert_eq!(f.connects(), 1, "one Tor stream: {first:?}");
    assert!(about(first, 4 * R), "a first send took {first:?}, r {R:?}");
    assert_eq!(pool.len(), 1, "its link is kept");
    let (acks, second) = f.program_sends(pool, "second, within WARM_IDLE").await;
    assert_eq!(acks, 1);
    eprintln!("a first send {first:?}, a warm send {second:?}, r {R:?}");
    assert_eq!(f.connects(), 1, "no other Tor stream: {second:?}");
    assert!(about(second, R), "a warm send took {second:?}, r {R:?}");
    assert_eq!(
        inbox(f._b.path()),
        ["first, on one link", "second, within WARM_IDLE"]
    );
    pool.flush();
}

/// With the warm gate shut nothing changes: each send is a check of 3
/// round trips and a message link of 4, two Tor streams, and no link is
/// kept.
#[tokio::test(start_paused = true)]
async fn with_the_warm_gate_shut_a_send_opens_two_links_as_before() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(loopback::Knobs {
        delay: R,
        latency: R / 2,
        count: true,
        memory: true,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    let (pool, gate) = test_pool(warm::LIMITS);
    gate.store(false, std::sync::atomic::Ordering::SeqCst);
    for (n, text) in (1..).zip(["one", "two"]) {
        let (acks, took) = f.program_sends(pool, text).await;
        eprintln!("a send with the gate shut {took:?}, r {R:?}");
        assert_eq!(acks, 1);
        assert_eq!(f.connects(), 2 * n, "{took:?}");
        assert!(about(took, 7 * R), "a send took {took:?}, r {R:?}");
        assert_eq!(pool.len(), 0, "nothing kept");
    }
}

/// A kept link closes once its friend is blocked or no longer verified, or
/// the warm gate is held (a security notice holds it: raven-core
/// `speed_gates_need_the_carrier_their_switch_and_no_hold`); the keeper
/// looks every sweep. And a batch for a friend blocked a moment ago, before
/// any sweep, does not ride the kept link: nothing is sent and no stream
/// opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blocked_or_unpinned_contact_or_a_held_gate_closes_the_kept_link() {
    use crate::outbox::test_rig::contacts;
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(loopback::Knobs {
        count: true,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    let block = |on: bool| {
        let mut blocks = raven_core::BlockList::default();
        if on {
            blocks.block(&hex::encode(f.bob_pub));
        }
        blocks.save(f.a.path()).unwrap();
    };
    let (pool, gate) = test_pool(warm::Limits {
        sweep: Duration::from_millis(50),
        ..warm::LIMITS
    });
    for case in ["blocked", "unpinned", "held"] {
        assert_eq!(f.program_sends(pool, case).await.0, 1, "{case}");
        assert_eq!(pool.len(), 1, "{case}: kept");
        match case {
            "blocked" => block(true),
            "unpinned" => contacts(f.a.path(), &f.bob_pub, "", "", false),
            _ => gate.store(false, std::sync::atomic::Ordering::SeqCst),
        }
        until(
            &format!("{case}: the keeper closes the kept link"),
            Duration::from_secs(5),
            || pool.len() == 0,
        )
        .await;
        match case {
            "blocked" => block(false),
            "unpinned" => contacts(f.a.path(), &f.bob_pub, "", "", true),
            _ => gate.store(true, std::sync::atomic::Ordering::SeqCst),
        }
    }
    let (pool, _gate) = test_pool(warm::Limits {
        sweep: Duration::from_secs(600),
        ..warm::LIMITS
    });
    assert_eq!(f.program_sends(pool, "kept").await.0, 1);
    assert_eq!(pool.len(), 1);
    let connects = f.connects();
    block(true);
    let sealed = seal_as(f.a.path(), &f.alice, &f.key_ab, "after the block", true);
    let err = f
        .program_dials(pool, ONION_WAITS, &[sealed])
        .await
        .unwrap_err();
    block(false);
    assert!(err.contains("blocked peer"), "{err}");
    assert_eq!(pool.len(), 0, "the kept link is closed");
    assert_eq!(f.connects(), connects, "and no stream opened");
    assert!(!inbox(f._b.path()).contains(&"after the block".to_string()));
}

/// A batch whose reply wait ran out never leaves its link kept: not a fresh
/// link (its read may have stopped part way through a frame), nor a kept
/// one (its reply may still come, and would be taken for the next batch's).
/// The resend then opens a fresh link and gets exactly one ACK, and Bob
/// holds the message once.
#[tokio::test(start_paused = true)]
async fn a_batch_that_timed_out_never_returns_its_link() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(loopback::Knobs {
        latency: R / 2,
        count: true,
        memory: true,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    let (pool, _gate) = test_pool(warm::LIMITS);
    // Longer than nothing, shorter than the round trip the ACK takes.
    let short = ReplyWaits {
        first: R / 3,
        ..ONION_WAITS
    };
    let acks = |replies: &[Vec<u8>]| raven_core::outbox::ack_frames(replies).len();
    let sealed = seal(f.a.path(), &f.alice, &f.key_ab, "late");
    let replies = f
        .program_dials(pool, short, std::slice::from_ref(&sealed))
        .await
        .expect("the link opened");
    assert_eq!(acks(&replies), 0, "no ACK within the wait");
    assert_eq!(f.connects(), 1);
    assert_eq!(pool.len(), 0, "a fresh link whose wait ran out is not kept");
    let check = f
        .program_dials(pool, ONION_WAITS, &[])
        .await
        .expect("the check answered");
    assert!(!check.is_empty());
    assert_eq!(
        (f.connects(), pool.len()),
        (2, 1),
        "the check's link is kept"
    );
    let replies = f
        .program_dials(pool, short, std::slice::from_ref(&sealed))
        .await
        .expect("the batch ended");
    assert_eq!(acks(&replies), 0, "no ACK within the wait");
    assert_eq!(f.connects(), 2, "it rode the kept link");
    assert_eq!(pool.len(), 0, "a kept link whose wait ran out is closed");
    let replies = f
        .program_dials(pool, ONION_WAITS, &[sealed])
        .await
        .expect("delivered");
    assert_eq!(acks(&replies), 1, "exactly one ACK");
    assert_eq!(f.connects(), 3, "on a fresh link");
    assert_eq!(inbox(f._b.path()), ["late"], "Bob holds it once");
    pool.flush();
}

/// Every kept link closes at a flush, and the next send opens a fresh link.
/// The process's pool is flushed ([`warm::flush`]) at a network change and
/// at the end of the onion task here, at a lock (the lock tests), at the
/// end of a helper life and at the embedded node's pause.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pool_drops_every_link_on_a_flush() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(loopback::Knobs {
        count: true,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    let (pool, _gate) = test_pool(warm::LIMITS);
    assert_eq!(f.program_sends(pool, "before the flush").await.0, 1);
    assert_eq!((f.connects(), pool.len()), (1, 1));
    pool.flush();
    assert_eq!(pool.len(), 0);
    assert_eq!(f.program_sends(pool, "after the flush").await.0, 1);
    assert_eq!((f.connects(), pool.len()), (2, 1), "a fresh link");
    pool.flush();
    // No helper is live now: the network change restarts none.
    drop(f);
    let count = warm::flushes_for_test;
    let before = count(warm::Flush::NetworkChanged);
    network_changed(false);
    assert!(
        count(warm::Flush::NetworkChanged) > before,
        "network change"
    );
    let before = count(warm::Flush::TorEnded);
    drop(LiveGuard);
    assert!(
        count(warm::Flush::TorEnded) > before,
        "the onion task's end"
    );
}

/// A kept link carries a batch only within its limits, scaled down here:
/// idle past `idle` or older than `age`, the keeper closes it, and the next
/// send opens a fresh link; one that carried `frames` frames is not kept.
#[tokio::test(start_paused = true)]
async fn a_link_idle_old_or_full_is_retired_not_reused() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(loopback::Knobs {
        count: true,
        memory: true,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    let sweep = Duration::from_millis(50);
    for (case, limits) in [
        (
            "idle",
            warm::Limits {
                idle: Duration::from_millis(700),
                sweep,
                ..warm::LIMITS
            },
        ),
        (
            "old",
            warm::Limits {
                age: Duration::from_millis(1500),
                sweep,
                ..warm::LIMITS
            },
        ),
    ] {
        let (pool, _gate) = test_pool(limits);
        let connects = f.connects();
        assert_eq!(f.program_sends(pool, case).await.0, 1, "{case}");
        assert_eq!(pool.len(), 1, "{case}: kept");
        until(
            &format!("{case}: the keeper closes the kept link"),
            Duration::from_secs(5),
            || pool.len() == 0,
        )
        .await;
        assert_eq!(f.program_sends(pool, case).await.0, 1, "{case}");
        assert_eq!(f.connects(), connects + 2, "{case}: a fresh link");
        pool.flush();
    }
    let (pool, _gate) = test_pool(warm::Limits {
        frames: 1,
        ..warm::LIMITS
    });
    for text in ["full", "full again"] {
        assert_eq!(f.program_sends(pool, text).await.0, 1);
        assert_eq!(pool.len(), 0, "a link that carried its frames is not kept");
    }
}

// ── M5: hedges and fresh first (Tor speed Stage A, speed design M5) ────────

/// A fresh rendezvous in the M5 tests: the first try in an isolation group
/// pays it before its connect (descriptor, introduction, rendezvous).
const RENDEZVOUS: Duration = Duration::from_millis(2000);
/// What a BEGIN on a dead circuit waits before Arti gives up on it (the Arti
/// helper's stream connect timeout).
const BEGIN_TIMEOUT: Duration = Duration::from_secs(6);

/// Loopback Tor for the M5 tests: a connect takes one round trip r ([`R`])
/// and every byte arrives r/2 later, a fresh group pays [`RENDEZVOUS`]
/// first, and the default isolation group's circuit to Bob is dead (a try
/// in it waits [`BEGIN_TIMEOUT`] and ends "tor timeout"), as is every
/// circuit built before a rise of `kill`.
fn dead_circuit_knobs(kill: Option<&'static std::sync::atomic::AtomicU64>) -> loopback::Knobs {
    loopback::Knobs {
        delay: R,
        latency: R / 2,
        stale: BEGIN_TIMEOUT,
        rendezvous: RENDEZVOUS,
        kill,
        count: true,
        memory: true,
        ..loopback::Knobs::default()
    }
}

impl Friends {
    /// The counts of Alice's helper.
    fn counts(&self) -> loopback::Counts {
        loopback::Counts::read(&self.a.path().join(TOR_DIR))
    }
}

/// With the hedge and warm gates shut nothing changes: a send to a friend
/// whose circuit is dead costs Arti's BEGIN timeout, a rendezvous and its
/// 7 round trips (a check of 3 on the fresh circuit, a message link of 4),
/// 6 s + R + 7r: two Tor streams, three tries, one on the dead circuit.
#[tokio::test(start_paused = true)]
async fn with_the_hedge_gate_shut_a_dead_circuit_costs_its_timeout_as_before() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(dead_circuit_knobs(None)).await else {
        return;
    };
    let (pool, gate, _hedge) = test_pool_with_hedge(warm::LIMITS);
    gate.store(false, std::sync::atomic::Ordering::SeqCst);
    let (acks, took) = f
        .program_sends(pool, "past a dead circuit, gates shut")
        .await;
    let want = BEGIN_TIMEOUT + RENDEZVOUS + 7 * R;
    eprintln!(
        "gates shut: {took:?} (6 s + R + 7r = {want:?}), {:?}",
        f.counts()
    );
    assert_eq!(acks, 1);
    assert!(about(took, want), "took {took:?}, want about {want:?}");
    assert_eq!(
        f.counts(),
        loopback::Counts {
            connects: 2,
            tries: 3,
            stale: 1
        }
    );
    assert_eq!(pool.len(), 0, "nothing kept");
}

/// M5 with W1: the helper hedges a first try that has no stream after
/// CONNECT_HEDGE_AFTER (2 s) with a fresh one beside it, so a dead circuit
/// costs 2 s, not Arti's 6 s BEGIN timeout; the check's link is kept and
/// the message rides it: 2 s + R + 4r in all (6 s + R + 7r with the gates
/// shut), one Tor stream and two tries.
#[tokio::test(start_paused = true)]
async fn a_dead_circuit_costs_two_seconds_with_the_hedge_gate_open() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(dead_circuit_knobs(None)).await else {
        return;
    };
    let (pool, _gate, hedge) = test_pool_with_hedge(warm::LIMITS);
    hedge.store(true, std::sync::atomic::Ordering::SeqCst);
    let (acks, took) = f.program_sends(pool, "past a dead circuit, hedged").await;
    let want = proto::CONNECT_HEDGE_AFTER + RENDEZVOUS + 4 * R;
    eprintln!(
        "hedged: {took:?} (2 s + R + 4r = {want:?}), {:?}",
        f.counts()
    );
    assert_eq!(acks, 1);
    assert!(about(took, want), "took {took:?}, want about {want:?}");
    assert_eq!(
        f.counts(),
        loopback::Counts {
            connects: 1,
            tries: 2,
            stale: 1
        }
    );
    assert_eq!(inbox(f._b.path()), ["past a dead circuit, hedged"]);
    pool.flush();
}

/// M5, fresh first (W4): once a link to Bob failed where the helper cannot
/// see it (here a batch on the kept link whose circuit died with no word,
/// left unanswered), the next connect goes in a new isolation group at once:
/// a rendezvous and 4 round trips, no try on the dead circuit and no 2 s
/// hedge wait. Bob holds the message once (the copy on the dead circuit
/// never reached him).
#[tokio::test(start_paused = true)]
async fn after_a_failed_link_the_next_connect_goes_fresh_first() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let kill: &'static std::sync::atomic::AtomicU64 =
        Box::leak(Box::new(std::sync::atomic::AtomicU64::new(0)));
    let Some(f) = Friends::with(dead_circuit_knobs(Some(kill))).await else {
        return;
    };
    let (pool, _gate, hedge) = test_pool_with_hedge(warm::LIMITS);
    hedge.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(f.program_sends(pool, "before the kill").await.0, 1);
    assert_eq!(pool.len(), 1, "the link is kept");
    let before = f.counts();
    loopback::kill_circuits(kill);
    let sealed = seal_as(f.a.path(), &f.alice, &f.key_ab, "after the kill", true);
    let short = ReplyWaits {
        first: R,
        ..ONION_WAITS
    };
    let replies = f
        .program_dials(pool, short, std::slice::from_ref(&sealed))
        .await
        .expect("written on the kept link");
    assert!(
        raven_core::outbox::ack_frames(&replies).is_empty(),
        "no ACK"
    );
    assert_eq!(pool.len(), 0, "the silent link is not kept");
    assert_eq!(f.counts(), before, "it rode the kept link");
    let began = tokio::time::Instant::now();
    let replies = f
        .program_dials(pool, ONION_WAITS, &[sealed])
        .await
        .expect("delivered");
    let took = began.elapsed();
    let want = RENDEZVOUS + 4 * R;
    eprintln!(
        "fresh first: {took:?} (R + 4r = {want:?}), {:?}",
        f.counts()
    );
    assert_eq!(raven_core::outbox::ack_frames(&replies).len(), 1);
    assert!(about(took, want), "took {took:?}, want about {want:?}");
    assert_eq!(
        f.counts(),
        loopback::Counts {
            connects: before.connects + 1,
            tries: before.tries + 1,
            stale: before.stale
        },
        "one try, in a new group"
    );
    assert_eq!(inbox(f._b.path()), ["before the kill", "after the kill"]);
    pool.flush();
}

/// A helper refuses a connect request with a flag it does not know (here
/// bit 1, kept for the keep-warm probe): never served as if it were clear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connect_with_an_unknown_flag_is_refused() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(loopback::Knobs {
        count: true,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    let mut s = TcpStream::connect(f.side_a.connect).await.unwrap();
    let keys = channel::Keys::new(&f.side_a.token);
    let proof = channel::node_connect(&mut s, &keys).await.unwrap();
    s.write_all(&proto::encode_connect(
        &proof,
        &f.side_b.hs_id,
        raven_core::onion::ONION_VIRTUAL_PORT,
        1 << 1,
    ))
    .await
    .unwrap();
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await.unwrap();
    let mut reason = vec![0u8; usize::from(head[1])];
    s.read_exact(&mut reason).await.unwrap();
    assert_eq!(
        ConnectReply::decode(head[0], &reason),
        ConnectReply::Failed(proto::UNKNOWN_FLAGS.into())
    );
    assert_eq!(f.counts().tries, 0, "no try made");
}

// ── M8: batches pipelined on a kept link (Tor speed Stage A, speed design M8)

impl Friends {
    /// The messages the ACKs in `replies` confirm, as Alice opens them (the
    /// ACK check `raven send` and the outbox share).
    fn acked(&self, replies: &[Vec<u8>]) -> Vec<[u8; 16]> {
        let peer =
            raven_core::lan_dispatch::parse_peer_offer(&replies[0]).expect("the offer comes first");
        let mut store =
            raven_core::indexed_session_store::IndexedSessionStore::open(self.a.path()).unwrap();
        raven_core::outbox::ack_frames(replies)
            .into_iter()
            .map(|ack| {
                raven_core::outbox::accept_sealed_ack(
                    self.a.path(),
                    &mut store,
                    &self.key_ab,
                    &peer.cert,
                    ack,
                    OutboxCarrier::Onion,
                )
                .unwrap_or_else(|e| panic!("an ACK Alice accepts: {e:?}"))
            })
            .collect()
    }
}

/// The id of the sealed message `sealed`.
fn message_id(sealed: &[u8]) -> [u8; 16] {
    raven_core::envelope::Envelope::unpack(sealed)
        .expect("an envelope")
        .message_id
}

/// M8: three sends at once to a friend with a kept link share it, each
/// batch written as it comes and answered about one round trip later (not
/// one round trip after the batch before it), each with the ACK of its own
/// message (the listener answers frame after frame, so replies go to the
/// batches first in, first out): no other Tor stream, and Bob holds each
/// message once.
#[tokio::test(start_paused = true)]
async fn three_quick_sends_share_one_warm_link_and_each_gets_its_receipt() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(loopback::Knobs {
        delay: R,
        latency: R / 2,
        count: true,
        memory: true,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    let (pool, _gate) = test_pool(warm::LIMITS);
    assert_eq!(f.program_sends(pool, "before the burst").await.0, 1);
    assert_eq!((f.connects(), pool.len()), (1, 1), "a kept link");
    let texts = ["one", "two", "three"];
    let sealed: Vec<Vec<u8>> = texts
        .iter()
        .map(|text| seal_as(f.a.path(), &f.alice, &f.key_ab, text, true))
        .collect();
    let (f, began) = (&f, tokio::time::Instant::now());
    let send = |sealed: &Vec<u8>| {
        let sealed = sealed.clone();
        async move {
            let replies = f.program_dials(pool, ONION_WAITS, &[sealed]).await;
            (replies, began.elapsed())
        }
    };
    let (a, b, c) = tokio::join!(send(&sealed[0]), send(&sealed[1]), send(&sealed[2]));
    let took: Vec<Duration> = [&a, &b, &c].iter().map(|(_, took)| *took).collect();
    eprintln!("a burst of three: {took:?}, r {R:?}");
    for ((replies, took), sealed) in [a, b, c].into_iter().zip(&sealed) {
        let replies = replies.expect("delivered");
        assert_eq!(f.acked(&replies), [message_id(sealed)], "its own ACK");
        assert!(about(took, R), "took {took:?}, r {R:?}");
    }
    assert_eq!(f.connects(), 1, "no other Tor stream");
    let mut held = inbox(f._b.path());
    held.sort();
    assert_eq!(held, ["before the burst", "one", "three", "two"]);
    pool.flush();
}

/// M8: when the count of replies drifts (a batch on the kept link stops
/// waiting before its ACK came, with another batch behind it), the link is
/// closed: the batch that stopped ends with no ACK (unconfirmed: its retry
/// gets a duplicate ACK), the one behind it goes again on a fresh link and
/// gets its own ACK, never the other's.
#[tokio::test(start_paused = true)]
async fn a_reply_count_drift_ends_unconfirmed_never_misattributed() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let Some(f) = Friends::with(loopback::Knobs {
        delay: R,
        latency: R / 2,
        count: true,
        memory: true,
        ..loopback::Knobs::default()
    })
    .await
    else {
        return;
    };
    let (pool, _gate) = test_pool(warm::LIMITS);
    assert_eq!(f.program_sends(pool, "before the drift").await.0, 1);
    let first = seal_as(f.a.path(), &f.alice, &f.key_ab, "stops waiting", true);
    let second = seal_as(f.a.path(), &f.alice, &f.key_ab, "behind it", true);
    let short = ReplyWaits {
        first: R / 3,
        ..ONION_WAITS
    };
    let f = &f;
    let stops = async {
        f.program_dials(pool, short, std::slice::from_ref(&first))
            .await
    };
    let behind = async {
        tokio::time::sleep(Duration::from_millis(150)).await;
        f.program_dials(pool, ONION_WAITS, std::slice::from_ref(&second))
            .await
    };
    let (stopped, behind) = tokio::join!(stops, behind);
    let stopped = stopped.expect("its frame was written");
    assert!(f.acked(&stopped).is_empty(), "no ACK: unconfirmed");
    let behind = behind.expect("delivered");
    assert_eq!(f.acked(&behind), [message_id(&second)], "its own ACK");
    assert_eq!(pool.len(), 1, "the fresh link is kept");
    let mut held = inbox(f._b.path());
    held.sort();
    assert_eq!(held, ["before the drift", "behind it", "stops waiting"]);
    pool.flush();
}

/// M5, the batch hedge: a batch on a kept link whose circuit died with no
/// word gets no reply; after max(2 s, 3 x the link's last round trip) it
/// goes again on a fresh link (fresh first: a new isolation group at once)
/// instead of waiting out its 30 s first-reply wait, and Bob, who never got
/// the first copy, answers the copy: one ACK, its own, and Bob holds the
/// message once. (With the hedge gate shut a kept link's batch waits out its
/// wait as before: `a_batch_that_timed_out_never_returns_its_link`.)
#[tokio::test(start_paused = true)]
async fn a_silent_pooled_link_is_hedged_and_the_copy_is_acked_once() {
    let _one_at_a_time = LAB_ONION.lock().await;
    let kill: &'static std::sync::atomic::AtomicU64 =
        Box::leak(Box::new(std::sync::atomic::AtomicU64::new(0)));
    let Some(f) = Friends::with(dead_circuit_knobs(Some(kill))).await else {
        return;
    };
    let (pool, _gate, hedge) = test_pool_with_hedge(warm::LIMITS);
    hedge.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(f.program_sends(pool, "before the kill").await.0, 1);
    assert_eq!(
        pool.len(),
        1,
        "the link is kept, its last batch one round trip"
    );
    loopback::kill_circuits(kill);
    let sealed = seal_as(f.a.path(), &f.alice, &f.key_ab, "after the kill", true);
    let began = tokio::time::Instant::now();
    let check = f
        .program_dials(pool, ONION_WAITS, &[])
        .await
        .expect("the check answered from the kept link");
    assert!(!check.is_empty());
    let replies = f
        .program_dials(pool, ONION_WAITS, std::slice::from_ref(&sealed))
        .await
        .expect("delivered");
    let took = began.elapsed();
    // The hedge after 3 x r, then a rendezvous and a link of 4 round trips.
    let want = 3 * R + RENDEZVOUS + 4 * R;
    eprintln!(
        "hedged batch: {took:?} (3r + R + 4r = {want:?}), {:?}",
        f.counts()
    );
    assert_eq!(f.acked(&replies), [message_id(&sealed)], "one ACK, its own");
    assert!(about(took, want), "took {took:?}, want about {want:?}");
    assert_eq!(inbox(f._b.path()), ["before the kill", "after the kill"]);
    pool.flush();
}
