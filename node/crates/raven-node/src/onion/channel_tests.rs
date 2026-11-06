//! Tests of the helper channel (security review 2026-11, TOR-4): who can
//! reach the streams between raven-node and its Tor helper, and what a
//! program that is not one of them learns or gets. On tokio's paused clock,
//! the loopback helper and its streams in memory (`memnet`).

use super::*;
use crate::onion::memnet;
use std::sync::atomic::Ordering::SeqCst;

/// The longest a peer of the helper channel may say nothing before it is
/// closed (the other side answers at once).
const SHORT_WAIT: Duration = Duration::from_secs(2);

/// One loopback helper life in memory: its connect address, its onion key
/// and its token; its "onion service" forwards into a listener of the test
/// that only holds every stream.
struct Helper {
    connect: SocketAddr,
    hs_id: [u8; 32],
    token: [u8; proto::TOKEN_LEN],
    state: tempfile::TempDir,
    _registry: tempfile::TempDir,
    _tasks: Vec<AbortOnDrop>,
    _stdin: Pin<Box<dyn AsyncWrite + Send>>,
}

impl Helper {
    async fn start(knobs: loopback::Knobs) -> Self {
        let (state, registry) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut forward = memnet::Listener::bind();
        let forward_addr = forward.local_addr();
        let holding = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok(stream) = forward.accept().await {
                held.push(stream);
            }
        });
        let token = fresh_token();
        let (to_helper, helper_in) = tokio::io::duplex(64 * 1024);
        let (helper_out, from_helper) = tokio::io::duplex(64 * 1024);
        let dir = registry.path().to_path_buf();
        let helper = tokio::spawn(async move {
            let _ = loopback::serve(Box::pin(helper_in), Box::pin(helper_out), dir, knobs).await;
        });
        let mut stdin: Pin<Box<dyn AsyncWrite + Send>> = Box::pin(to_helper);
        let config = proto::Config {
            v: proto::PROTO_VERSION,
            state_dir: state.path().to_string_lossy().into_owned(),
            token: hex::encode(token),
            forward: forward_addr.to_string(),
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
            let line = events.next_line().await.expect("a helper event");
            match serde_json::from_str::<Event>(&line).unwrap() {
                Event::Ready { connect: c } => connect = Some(c.parse().unwrap()),
                Event::Onion { hs_id: h } => hs_id = proto::parse_hs_id(&h),
                _ => {}
            }
        }
        let draining = tokio::spawn(async move { while events.next_line().await.is_some() {} });
        Self {
            connect: connect.unwrap(),
            hs_id: hs_id.unwrap(),
            token,
            state,
            _registry: registry,
            _tasks: vec![
                AbortOnDrop(holding.abort_handle()),
                AbortOnDrop(helper.abort_handle()),
                AbortOnDrop(draining.abort_handle()),
            ],
            _stdin: stdin,
        }
    }
}

fn in_memory() -> loopback::Knobs {
    loopback::Knobs {
        memory: true,
        ..loopback::Knobs::default()
    }
}

/// `needle` appears in `hay`.
fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A local program that connects to the helper's connect port and says
/// nothing is closed within the short wait (TOR-4 (a): before, each one held
/// a task and a socket for as long as it liked).
#[tokio::test(start_paused = true)]
async fn a_connection_to_the_helper_that_says_nothing_is_closed_within_the_wait() {
    let _memory = memnet::MemoryOnly::new();
    let helper = Helper::start(in_memory()).await;
    let mut silent = memnet::connect(helper.connect).await.unwrap();
    let began = tokio::time::Instant::now();
    let mut buf = [0u8; 8];
    let got = tokio::time::timeout(Duration::from_secs(60), silent.read(&mut buf)).await;
    assert!(
        matches!(got, Ok(Ok(0)) | Ok(Err(_))),
        "not closed within 60 s: {got:?}"
    );
    assert!(began.elapsed() <= SHORT_WAIT, "{:?}", began.elapsed());
}

/// The helper's connect port holds at most 32 connections that still owe
/// raven-node's hello: one more closes the oldest, as raven-node's forward
/// listener does (TOR-4 (a): no cap before).
#[tokio::test(start_paused = true)]
async fn the_helpers_connect_port_keeps_at_most_32_waiting_connections() {
    let _memory = memnet::MemoryOnly::new();
    let helper = Helper::start(in_memory()).await;
    let mut oldest = memnet::connect(helper.connect).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1)).await;
    let mut rest = Vec::new();
    for _ in 0..32 {
        rest.push(memnet::connect(helper.connect).await.unwrap());
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let mut buf = [0u8; 8];
    let got = tokio::time::timeout(Duration::from_millis(500), oldest.read(&mut buf)).await;
    assert!(
        matches!(got, Ok(Ok(0)) | Ok(Err(_))),
        "the oldest stays open past the cap: {got:?}"
    );
    let newest = rest.last_mut().unwrap();
    let got = tokio::time::timeout(Duration::from_millis(500), newest.read(&mut buf)).await;
    assert!(got.is_err(), "the newest still waits: {got:?}");
}

/// raven-node's forward listener closes a local connection that does not
/// answer its hello within the short wait (it waited 10 s before).
#[tokio::test(start_paused = true)]
async fn the_forward_listener_drops_a_silent_connection_within_the_wait() {
    let (_peer, theirs) = tokio::io::duplex(1024);
    let token = fresh_token();
    let began = tokio::time::Instant::now();
    let got = check_token(theirs, &token).await;
    assert!(got.is_err());
    assert!(began.elapsed() <= SHORT_WAIT, "{:?}", began.elapsed());
}

/// A program that holds the address raven-node dials for its helper (TOR-4
/// (c): the port of a helper that just ended) and answers raven-node's
/// challenge with a whole hello whose proof is not the helper's learns
/// neither the helper life's token nor the friend's onion key: raven-node
/// checks the proof first and closes the stream at once, with nothing
/// after its challenge (no proof of its own, no request).
#[tokio::test(start_paused = true)]
async fn a_program_in_the_helpers_place_learns_neither_token_nor_onion_key() {
    let _memory = memnet::MemoryOnly::new();
    let mut squatter = memnet::Listener::bind();
    let addr = squatter.local_addr();
    let listening = tokio::spawn(async move {
        let mut stream = squatter.accept().await.unwrap();
        let mut challenge = [0u8; channel::NONCE_LEN];
        stream.read_exact(&mut challenge).await.unwrap();
        stream
            .write_all(&[0x5a; channel::CONNECT_HELLO_LEN])
            .await
            .unwrap();
        let began = tokio::time::Instant::now();
        let mut rest = Vec::new();
        let ended = tokio::time::timeout(SHORT_WAIT * 3, stream.read_to_end(&mut rest)).await;
        (rest, ended.is_ok(), began.elapsed())
    });
    let (token, hs_id) = (fresh_token(), [0xa5u8; 32]);
    let dialled = connect_via_helper(Route::Port(addr), token, hs_id, 0).await;
    assert!(dialled.is_err());
    let (rest, closed, after) = listening.await.unwrap();
    assert!(!holds(&rest, &token), "the token reached a stranger");
    assert!(!holds(&rest, &hs_id), "the onion key reached a stranger");
    assert!(closed, "raven-node kept the stream open");
    assert!(after < SHORT_WAIT, "closed only after {after:?}");
    assert!(rest.is_empty(), "{} bytes after the challenge", rest.len());
}

/// A program that copied one whole exchange between raven-node and its
/// helper cannot play raven-node's part again: the helper's nonce is new on
/// every stream, so the copy is refused before its request is read, and no
/// Tor stream opens for it.
#[tokio::test(start_paused = true)]
async fn a_copied_connect_cannot_be_played_again() {
    let _memory = memnet::MemoryOnly::new();
    let helper = Helper::start(loopback::Knobs {
        count: true,
        ..in_memory()
    })
    .await;
    // Between raven-node and its helper: copies one exchange both ways and
    // keeps what raven-node wrote.
    let mut relay = memnet::Listener::bind();
    let relay_addr = relay.local_addr();
    let to_helper = helper.connect;
    let written = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&written);
    let relaying = tokio::spawn(async move {
        let node = relay.accept().await.unwrap();
        let theirs = memnet::connect(to_helper).await.unwrap();
        let (mut node_read, mut node_write) = tokio::io::split(node);
        let (mut helper_read, mut helper_write) = tokio::io::split(theirs);
        let up = async move {
            let mut buf = [0u8; 4096];
            while let Ok(n) = node_read.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                keep.lock().unwrap().extend_from_slice(&buf[..n]);
                if helper_write.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        };
        let down = tokio::io::copy(&mut helper_read, &mut node_write);
        let _ = tokio::join!(up, down);
    });
    let _relaying = AbortOnDrop(relaying.abort_handle());
    let _opened = connect_via_helper(Route::Port(relay_addr), helper.token, helper.hs_id, 0)
        .await
        .expect("one exchange through the copier");
    let copied = written.lock().unwrap().clone();
    assert_eq!(loopback::Counts::read(helper.state.path()).connects, 1);
    let mut again = memnet::connect(helper.connect).await.unwrap();
    again.write_all(&copied).await.unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(60), again.read_to_end(&mut got)).await;
    assert_eq!(
        loopback::Counts::read(helper.state.path()).connects,
        1,
        "the copy opened a Tor stream"
    );
}

/// A helper that answers the config line as one of another version does
/// (an error on this computer, then it ends); how many were started.
struct OtherVersion(Arc<std::sync::atomic::AtomicUsize>);

impl Spawn for OtherVersion {
    fn spawn(&self) -> Result<Proc, String> {
        self.0.fetch_add(1, SeqCst);
        let (to_helper, helper_in) = tokio::io::duplex(64 * 1024);
        let (mut helper_out, from_helper) = tokio::io::duplex(64 * 1024);
        let done = async move {
            let mut lines = LineReader::new(Box::pin(helper_in));
            let _ = lines.next_line().await;
            let refused = proto::line(&Event::Error {
                what: "unknown protocol version".into(),
                local: true,
            });
            let _ = helper_out.write_all(refused.as_bytes()).await;
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

/// raven-node and its helper ship together and speak one version of the
/// local protocol: a helper of another version refuses the config line,
/// and raven-node says so in words a person can act on.
#[tokio::test(start_paused = true)]
async fn a_helper_of_another_version_is_refused_with_a_clear_error() {
    let _one_at_a_time = super::tests::LAB_ONION.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = proto::Config {
        v: proto::PROTO_VERSION,
        state_dir: dir.path().join(TOR_DIR).to_string_lossy().into_owned(),
        token: hex::encode(fresh_token()),
        forward: "127.0.0.1:9".into(),
        port: raven_core::onion::ONION_VIRTUAL_PORT,
        fresh_state: false,
    };
    let task = tokio::spawn(supervise(
        Arc::new(OtherVersion(Arc::clone(&starts))),
        config,
        Arc::new(Mutex::new([0u8; proto::TOKEN_LEN])),
        dir.path().to_path_buf(),
        Arc::new(Identity::from_seed(&[0x3c; 32])),
    ));
    // Within the first restart wait (5 s): the first life's words.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let seen = status();
    task.abort();
    update_status(|s| *s = Status::default());
    assert!(starts.load(SeqCst) >= 1);
    assert_eq!(seen.phase, Phase::CantStart);
    assert_eq!(
        seen.why.as_deref(),
        Some("the Tor helper is from another version of Raven; install Raven again")
    );
}

// ── The channel (macOS, Linux) ──────────────────────────────────────────────

/// The channel has no name and no port another program could open, and its
/// helper end goes to the helper process alone: another program raven-node
/// starts gets no copy of it (every descriptor of raven-node is closed on
/// exec), and one started as the helper ([`channel::pair::inherit`]) has
/// it.
#[cfg(unix)]
#[tokio::test]
async fn another_program_gets_no_copy_of_the_channel() {
    use std::os::fd::AsRawFd;
    let (_node_end, helper_end) = channel::pair::new_channel().unwrap();
    let fd = helper_end.as_raw_fd();
    // A shell that copies `fd` (a copy fails when it is not open there).
    let probe = |fd: i32| {
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(copies(fd))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd
    };
    // The probe itself fails for a number that is not open, whatever it
    // is: 9 and 8 included, the numbers it copies into.
    for closed in [9, 8] {
        let mut cmd = probe(closed);
        // SAFETY: close alone, in the child between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                libc::close(closed);
                Ok(())
            });
        }
        let status = cmd.status().await.unwrap();
        assert!(!status.success(), "the probe found {closed} open");
    }
    let other = probe(fd).status().await.unwrap();
    assert!(!other.success(), "another program got the channel");
    let mut helper = probe(fd);
    channel::pair::inherit(&mut helper, &helper_end);
    let helper = helper.status().await.unwrap();
    assert!(helper.success(), "the helper did not get its end");
}

/// A shell line that copies `fd` into another number, so it fails when
/// `fd` is not open (a copy of a number onto itself, `exec 9<&9`, passes
/// with 9 closed).
#[cfg(unix)]
fn copies(fd: i32) -> String {
    let into = if fd == 9 { 8 } else { 9 };
    format!("exec {into}<&{fd}")
}

/// What makes [`child_loopback_helper`] the loopback helper of a test: its
/// registry directory.
#[cfg(unix)]
const CHILD_ENV: &str = "RAVEN_TEST_ONION_CHILD_REGISTRY";

/// No test of its own (nothing without [`CHILD_ENV`]): in a process that
/// [`ChildHelper`] started, the loopback helper on its stdin and stdout and
/// its inherited end of the channel, as `raven-node tor-loopback-helper`
/// runs it ([`loopback::run_cli`]).
#[cfg(unix)]
#[test]
fn child_loopback_helper() {
    let Some(registry) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let code = runtime.block_on(loopback::run_cli(PathBuf::from(registry)));
    std::process::exit(code);
}

/// Starts the loopback helper as a process of its own, as raven-node's
/// [`Launcher`] does (a library test has no raven-node program to start:
/// this test program again, running [`child_loopback_helper`]).
#[cfg(unix)]
struct ChildHelper(PathBuf);

#[cfg(unix)]
impl ChildHelper {
    fn command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "onion::channel_tests::child_loopback_helper",
            "--quiet",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, &self.0)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
        cmd
    }
}

#[cfg(unix)]
impl Spawn for ChildHelper {
    fn spawn(&self) -> Result<Proc, String> {
        start(self.command())
    }

    fn on_channel(&self) -> bool {
        true
    }

    fn spawn_on(&self, end: std::os::unix::net::UnixStream) -> Result<(Proc, String), String> {
        start_inheriting(self.command(), end)
    }
}

/// Two real profiles. Alice's onion side runs as raven-node runs it
/// ([`run_with`]: her helper started by `helper` with its end of a channel
/// of its own, her forward streams taken from it); Bob's runs in this
/// process on loopback ports ([`super::tests::side`]). A sealed message
/// goes each way: Alice's out through her helper's channel, Bob's in
/// through it. Lab run only.
#[cfg(unix)]
async fn a_message_each_way_on_alices_channel(helper: impl FnOnce(&Path) -> Arc<dyn Spawn>) {
    use super::tests::{inbox, seal, side};
    use crate::outbox::test_rig::{contacts, lab_backends, pair};
    if !lab_backends() || !raven_core::onion_live_enabled() {
        eprintln!("skipped: needs RAVEN_LAB_TEST_A=1 RAVEN_LAB_TOR=1 (debug)");
        return;
    }
    let _one_at_a_time = super::tests::LAB_ONION.lock().await;
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

    let side_b = side(b.path(), registry.path()).await;
    let alice_side = tokio::spawn(run_with(a.path().to_path_buf(), helper(registry.path())));
    let _alice_side = AbortOnDrop(alice_side.abort_handle());
    // Ready on her helper's channel, her onion key said.
    let began = Instant::now();
    let alice_hs = loop {
        let on_channel = live_lock()
            .as_ref()
            .is_some_and(|live| matches!(live.connect, Some(Route::Channel(_))));
        if let (true, Some(binding)) = (on_channel, own_binding()) {
            break binding.hs_id;
        }
        assert!(
            began.elapsed() < Duration::from_secs(30),
            "Alice's helper is not ready on its channel: {:?}",
            status().phase
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    // Alice to Bob: her connect stream over her helper's channel.
    let to_bob = seal(a.path(), &alice, &key_ab, "out over the channel");
    let replies = dial_with_meta(
        a.path(),
        &raven_core::onion::dial_for(&side_b.hs_id),
        &hex::encode(bob_pub),
        &[to_bob],
        DialMeta::default(),
    )
    .await
    .expect("delivered from Alice through her helper's channel");
    assert_eq!(raven_core::outbox::ack_frames(&replies).len(), 1);
    assert_eq!(inbox(b.path()), ["out over the channel"]);

    // Bob to Alice, through Bob's helper: her forward stream over her
    // helper's channel.
    let alices = live_lock().replace(Live {
        token: side_b.token,
        connect: Some(Route::Port(side_b.connect)),
        binding: None,
        channel: None,
    });
    let to_alice = seal(b.path(), &bob, &key_ba, "in over the channel");
    let replies = dial_with_meta(
        b.path(),
        &raven_core::onion::dial_for(&alice_hs),
        &hex::encode(alice_pub),
        &[to_alice],
        DialMeta::default(),
    )
    .await;
    *live_lock() = alices;
    let replies = replies.expect("delivered to Alice through her helper's channel");
    assert_eq!(raven_core::outbox::ack_frames(&replies).len(), 1);
    assert_eq!(inbox(a.path()), ["in over the channel"]);
}

/// raven-node starts its helper as a process (here the loopback helper)
/// with its end of the channel inherited, and every onion stream both ways
/// rides that channel.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_helper_process_reaches_raven_node_on_its_channel() {
    a_message_each_way_on_alices_channel(|registry| Arc::new(ChildHelper(registry.to_path_buf())))
        .await;
}

/// The helper inside raven-node's process (the iOS app, here the loopback
/// helper) is handed its end of the channel, and every onion stream both
/// ways rides it.
#[cfg(all(unix, feature = "tor-embedded"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_helper_in_this_process_is_handed_its_channel() {
    a_message_each_way_on_alices_channel(|registry| {
        Arc::new(InProcess::Loopback(registry.to_path_buf()))
    })
    .await;
}
