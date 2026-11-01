//! The embedded node (docs/IOS.md) end to end, with no raven-node program:
//! every engine runs its node inside its own process (`RAVEN_NODE_MODE=
//! embedded`; `RAVEN_NODE_BIN` names a program that does not exist, so a
//! start that spawned would fail). One node runs per process, so the
//! friends are engines in processes of their own: this test binary started
//! again as [`embedded_peer_process`], driven over its stdin and stdout one
//! request per line.
//!
//! A (this process), B and C (the peers), on 127.0.0.1 with free ports and
//! file-backed secret stores: friends verified by their words; a message
//! each way with its signed receipt; with `tor-embedded`, Tor in A's process
//! (the in-process loopback helper: no Tor network) ready; A paused (as the
//! app going to the background): its listener closed, a start refused, B's
//! message left with C; A's mail check (as iOS background refresh) fetches
//! it from C within its budget while A stays paused; A resumed, and B's
//! next message delivered directly; A paused keeping Bluetooth nearby (the
//! small background node) and resumed again.
//!
//! A send whose turn comes while A is paused (and then locked by Lock v2)
//! waits and goes after the resume (and the unlock).
//!
//! `tor_in_process_bootstraps` (ignored: it needs the Tor network) runs
//! real Arti in an engine's process until Tor is ready.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use raven_client::Client;
use serde_json::{json, Value};

/// The peer process's profile folder.
const PEER_DIR_ENV: &str = "RAVEN_TEST_EMBEDDED_PEER_DIR";
/// Marks a response line on the peer's stdout (the test harness prints too).
const MARK: &str = "@@raven-response ";

/// One engine: this process's own, or a peer process's.
trait Engine {
    fn call(&self, request: &str) -> String;
}

impl Engine for Client {
    fn call(&self, request: &str) -> String {
        Client::call(self, request)
    }
}

/// This process's engine, shared with another thread of the test.
impl Engine for std::sync::Arc<Client> {
    fn call(&self, request: &str) -> String {
        Client::call(self, request)
    }
}

/// A peer process: [`embedded_peer_process`] on a profile of its own.
struct Remote {
    child: Child,
    io: Mutex<(ChildStdin, BufReader<ChildStdout>)>,
}

impl Remote {
    fn spawn(dir: &Path, extra_env: &[(&str, &str)]) -> Remote {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "embedded_peer_process",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PEER_DIR_ENV, dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("start the peer process");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Remote {
            child,
            io: Mutex::new((stdin, stdout)),
        }
    }
}

impl Engine for Remote {
    fn call(&self, request: &str) -> String {
        let mut io = self.io.lock().unwrap();
        writeln!(io.0, "{request}").expect("write to the peer");
        io.0.flush().unwrap();
        let mut line = String::new();
        loop {
            line.clear();
            let n = io.1.read_line(&mut line).expect("read from the peer");
            assert!(n > 0, "the peer process ended");
            // The harness's own words may come first on the line.
            if let Some(at) = line.find(MARK) {
                return line[at + MARK.len()..].trim_end().to_owned();
            }
        }
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        // Its stdin closes: it stops its node and exits.
        if let Ok(mut io) = self.io.lock() {
            let _ = writeln!(io.0);
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
    }
}

/// One friend: a profile and its engine.
struct Peer {
    name: String,
    path: PathBuf,
    engine: Box<dyn Engine>,
    me: Value,
}

impl Peer {
    fn new(name: &str, path: PathBuf, engine: Box<dyn Engine>) -> Peer {
        let mut p = Peer {
            name: name.into(),
            path,
            engine,
            me: Value::Null,
        };
        p.ok("settings.set", json!({"receive": false}));
        p.ok("identity.create", json!({"display_name": name}));
        p.me = p.ok("identity.me", json!({}));
        p
    }

    fn raw(&self, op: &str, args: Value) -> Value {
        let request = json!({"v": 1, "op": op, "args": args}).to_string();
        let response = self.engine.call(&request);
        serde_json::from_str(&response)
            .unwrap_or_else(|e| panic!("{}: {op}: not JSON ({e}): {response}", self.name))
    }

    fn ok(&self, op: &str, args: Value) -> Value {
        let r = self.raw(op, args);
        assert_eq!(
            r["ok"],
            true,
            "{}: {op} failed: {r}\n{}",
            self.name,
            self.log()
        );
        r["result"].clone()
    }

    fn err(&self, op: &str, args: Value) -> Value {
        let r = self.raw(op, args);
        assert_eq!(
            r["ok"], false,
            "{}: {op} should have failed: {r}",
            self.name
        );
        r["error"].clone()
    }

    fn address(&self) -> String {
        self.me["address"].as_str().unwrap().to_owned()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.path.join("raven-node-service.log")).unwrap_or_default()
    }

    fn befriend(&self, other: &Peer) {
        self.ok(
            "contacts.add",
            json!({"text": other.me["invite"], "name": format!("Friend {}", other.name)}),
        );
        let checked = self.ok(
            "verify.check_words",
            json!({"address": other.address(), "words": other.me["words"]}),
        );
        assert_eq!(checked["result"], "match", "{checked}");
    }

    /// `node.start`: where it listens.
    fn start(&self) -> String {
        let st = self.ok("node.start", json!({}));
        assert_eq!(st["running"], true, "{}: {st}", self.name);
        assert_eq!(st["embedded"], true, "{}: {st}", self.name);
        st["listening"].as_str().unwrap().to_owned()
    }

    fn set_lan(&self, friend: &Peer, lan: &str) {
        self.ok(
            "contacts.set_address",
            json!({"address": friend.address(), "lan": lan}),
        );
    }

    fn send(&self, friend: &Peer, text: &str) -> String {
        let sent = self.ok(
            "messages.send",
            json!({"address": friend.address(), "text": text}),
        );
        sent["message"]["id"].as_str().unwrap().to_owned()
    }

    /// The message `id` to `friend` once its state is one of `ends`.
    fn wait_state(&self, friend: &Peer, id: &str, ends: &[&str], limit: Duration) -> Value {
        let deadline = Instant::now() + limit;
        let mut after = 0;
        loop {
            // Polling keeps the engine's watcher running.
            let batch = self.ok("events.poll", json!({"after_seq": after}));
            after = batch["seq"].as_u64().unwrap();
            let history = self.ok(
                "messages.history",
                json!({"address": friend.address(), "limit": 50}),
            );
            let mine = history["messages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["id"] == id)
                .cloned();
            if let Some(m) = &mine {
                if ends.contains(&m["state"].as_str().unwrap_or("")) {
                    return m.clone();
                }
            }
            assert!(
                Instant::now() < deadline,
                "{}: {id} stayed {mine:?}\n{}",
                self.name,
                self.log()
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    fn has_incoming(&self, friend: &Peer, text: &str) -> bool {
        let history = self.ok(
            "messages.history",
            json!({"address": friend.address(), "limit": 50}),
        );
        history["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["direction"] == "in" && m["text"] == text)
    }

    fn wait_incoming(&self, friend: &Peer, text: &str, limit: Duration) {
        let deadline = Instant::now() + limit;
        while !self.has_incoming(friend, text) {
            assert!(
                Instant::now() < deadline,
                "{}: {text:?} from {} never came\n{}",
                self.name,
                friend.name,
                self.log()
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    fn carrier(&self, id: &str) -> Value {
        let status = self.ok("network.status", json!({}));
        status["carriers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("no {id} in {status}"))
    }
}

/// One test at a time: each runs its node in this process (one per
/// process) and sets the process's lab switches.
static SERIAL: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Names the scenario a process of its own runs ([`in_own_process`]).
const OWN_PROCESS_ENV: &str = "RAVEN_TEST_EMBEDDED_OWN_PROCESS";

/// Runs the scenario `name` (an ignored test of this binary) in a process
/// of its own, one at a time: the node, its custody fetcher's and Tor's
/// state are the process's (one node per process), so no scenario leaves
/// them to the next.
fn in_own_process(name: &str) {
    let _one = one_at_a_time();
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(OWN_PROCESS_ENV, name)
        .status()
        .expect("start the scenario's process");
    assert!(status.success(), "{name} failed: its output is above");
}

/// This process runs the scenario `name` ([`in_own_process`]); nothing
/// else runs one (`--ignored` alone does not).
fn own_process(name: &str) -> bool {
    let mine = std::env::var(OWN_PROCESS_ENV).is_ok_and(|v| v == name);
    if mine && !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch");
        return false;
    }
    mine
}

/// This process as an embedded engine with no raven-node program to find.
fn embedded_env() {
    common::lab_env();
    std::env::set_var(raven_client::NODE_MODE_ENV, "embedded");
    std::env::set_var(raven_client::NODE_PROGRAM_ENV, "/nonexistent/raven-node");
}

/// A peer of [`embedded_engines_end_to_end`]: an engine on the profile in
/// [`PEER_DIR_ENV`] serving one request per stdin line (nothing without
/// it). It takes its environment from the test that started it.
#[test]
#[ignore = "a peer process the embedded tests start"]
fn embedded_peer_process() {
    let Some(dir) = std::env::var_os(PEER_DIR_ENV) else {
        return;
    };
    let client = Client::with_data_dir(PathBuf::from(dir));
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            break;
        }
        let response = client.call(&line);
        let _ = writeln!(out, "{MARK}{response}");
        let _ = out.flush();
    }
    let _ = client.call(r#"{"v":1,"op":"node.stop"}"#);
}

#[test]
fn embedded_engines_end_to_end() {
    let _one = one_at_a_time();
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch");
        return;
    }
    embedded_env();
    // Custody's lab knobs (as tests/net_custody.rs): a copy is left with
    // the friend at once, and a running node collects every second.
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    std::env::set_var("RAVEN_LAB_CUSTODY_AFTER_MS", "0");
    std::env::set_var("RAVEN_LAB_CUSTODY_FETCH_MS", "1000");

    // No Tor for the peers (its gate is open in this build: they would
    // reach the real Tor network); A's below runs on the loopback helper.
    std::env::set_var("RAVEN_LAB_TOR", "0");
    let root = common::short_dir();
    let dir = |n: &str| root.path().join(n);
    // The peers first: they take this environment as it is now (no Tor).
    let b = Peer::new("B", dir("b"), Box::new(Remote::spawn(&dir("b"), &[])));
    let c = Peer::new("C", dir("c"), Box::new(Remote::spawn(&dir("c"), &[])));
    // Tor in this process only, on the in-process loopback helper (no Tor
    // network), where the engine is built with it.
    let tor = cfg!(feature = "tor-embedded");
    let registry = root.path().join("tor-registry");
    if tor {
        std::fs::create_dir_all(&registry).unwrap();
        std::env::set_var("RAVEN_LAB_TOR", "1");
        std::env::set_var("RAVEN_LAB_TOR_LOOPBACK", &registry);
    }
    let a = Peer::new("A", dir("a"), Box::new(Client::with_data_dir(dir("a"))));
    for (x, y) in [(&a, &b), (&a, &c), (&b, &a), (&b, &c), (&c, &a), (&c, &b)] {
        x.befriend(y);
    }
    // C carries for friends.
    c.ok(
        "network.set",
        json!({"carry_for_friends": true, "agreed": true}),
    );

    // Every node runs in its engine's process: no program was started.
    let (la, lb, lc) = (a.start(), b.start(), c.start());
    let st = a.ok("node.status", json!({}));
    assert_eq!(st["pid"], std::process::id(), "{st}");
    assert_eq!(st["started_by_app"], true, "{st}");
    assert!(
        a.log().contains("raven-node ipc: listening in process"),
        "{}",
        a.log()
    );
    for (x, y, l) in [
        (&a, &b, &lb),
        (&a, &c, &lc),
        (&b, &a, &la),
        (&b, &c, &lc),
        (&c, &a, &la),
        (&c, &b, &lb),
    ] {
        x.set_lan(y, l);
    }
    for (x, y) in [(&a, &b), (&b, &a)] {
        x.ok(
            "contacts.set_routes",
            json!({"address": y.address(), "custodians": [c.address()]}),
        );
    }

    // A message each way, delivered with a signed receipt.
    let id = a.send(&b, "hello from A");
    let m = a.wait_state(&b, &id, &["delivered", "failed"], Duration::from_secs(90));
    assert_eq!(m["state"], "delivered", "{m}");
    b.wait_incoming(&a, "hello from A", Duration::from_secs(30));
    let id = b.send(&a, "hello from B");
    let m = b.wait_state(&a, &id, &["delivered", "failed"], Duration::from_secs(90));
    assert_eq!(m["state"], "delivered", "{m}");
    a.wait_incoming(&b, "hello from B", Duration::from_secs(30));

    // Tor inside A's process: its helper ready (no helper program).
    if tor {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let t = a.carrier("tor");
            if t["running"] == true {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Tor never ready: {t}\n{}",
                a.log()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        assert!(a.log().contains("onion: Tor: ready"), "{}", a.log());

        // Tor on Wi-Fi only: off while the app says mobile data, back on
        // Wi-Fi (owner decision 2026-10-30; the default is Tor on both).
        let set = a.ok("network.set", json!({"tor_wifi_only": true}));
        assert_eq!(set["status"]["tor_wifi_only"], true, "{set}");
        let path = a.ok("network.path", json!({"type": "cellular"}));
        assert_eq!(path["path"], "cellular", "{path}");
        let tor_phase = |a: &Peer| a.ok("network.status", json!({}))["tor"]["phase"].clone();
        let deadline = Instant::now() + Duration::from_secs(30);
        while tor_phase(&a) != "off_mobile_data" {
            assert!(Instant::now() < deadline, "Tor still on: {}", a.log());
            std::thread::sleep(Duration::from_millis(300));
        }
        a.ok("network.path", json!({"type": "wifi"}));
        let deadline = Instant::now() + Duration::from_secs(60);
        while a.carrier("tor")["running"] != true {
            assert!(Instant::now() < deadline, "Tor never back: {}", a.log());
            std::thread::sleep(Duration::from_millis(300));
        }
        a.ok("network.set", json!({"tor_wifi_only": false}));
    }
    let bad = a.err("network.path", json!({"type": "5g"}));
    assert_eq!(bad["code"], "BAD_REQUEST", "{bad}");

    // The app goes to the background: A pauses.
    let paused = a.ok("node.pause", json!({}));
    assert_eq!(paused["was_running"], true, "{paused}");
    assert_eq!(paused["running"], false, "{paused}");
    assert_eq!(paused["state"], "paused", "{paused}");
    let refused = a.err("node.start", json!({}));
    assert!(
        refused["detail"].as_str().unwrap().contains("PAUSED"),
        "{refused}"
    );
    // A's listener is closed: B's message is left with C.
    let id = b.send(&a, "while you were away");
    let m = b.wait_state(
        &a,
        &id,
        &["waiting", "sent", "delivered", "failed"],
        Duration::from_secs(60),
    );
    assert_ne!(m["state"], "delivered", "{m}");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let net = c.ok("network.status", json!({}));
        if net["carry"]["carry_for_friends"]["held_messages"]
            .as_i64()
            .unwrap_or(0)
            >= 1
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "C holds nothing: {net}\n{}",
            b.log()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(!a.has_incoming(&b, "while you were away"));

    // iOS background refresh: one bounded fetch from friends, A stays
    // paused.
    let began = Instant::now();
    let check = a.ok("mail.check", json!({"budget_ms": 25000}));
    let took = began.elapsed();
    assert!(took < Duration::from_secs(25), "{took:?} {check}");
    assert_eq!(check["custody"], "on", "{check}");
    assert_eq!(check["started_node"], true, "{check}");
    assert_eq!(check["completed"], true, "{check}\n{}", a.log());
    // Who it asked, by name: the friend A listed for B.
    assert_eq!(
        check["names"],
        json!([format!("Friend {}", c.name)]),
        "{check}"
    );
    assert!(check["new_messages"].as_u64().unwrap() >= 1, "{check}");
    assert!(a.has_incoming(&b, "while you were away"), "{}", a.log());
    let st = a.ok("node.status", json!({}));
    assert_eq!(st["state"], "paused", "{st}");
    assert_eq!(st["running"], false, "{st}");

    // The app is open again: A resumes (on a new free port here; a phone
    // keeps its profile's port) and B reaches it directly.
    let resumed = a.ok("node.resume", json!({}));
    assert_eq!(resumed["running"], true, "{resumed}");
    let la = resumed["listening"].as_str().unwrap().to_owned();
    b.set_lan(&a, &la);
    let id = b.send(&a, "welcome back");
    let m = b.wait_state(&a, &id, &["delivered", "failed"], Duration::from_secs(90));
    assert_eq!(m["state"], "delivered", "{m}\n{}", b.log());
    a.wait_incoming(&b, "welcome back", Duration::from_secs(30));

    // Bluetooth kept in the background (Task 2 Phase B): the small node
    // that keeps nearby runs while the pause holds (a start meanwhile finds
    // it and starts no full node), and the next resume brings the full node
    // back.
    let bad = a.err("node.pause", json!({"nearby": "sometimes"}));
    assert_eq!(bad["code"], "BAD_REQUEST", "{bad}");
    let kept = a.ok("node.pause", json!({"nearby": "keep"}));
    assert_eq!(kept["was_running"], true, "{kept}");
    assert_eq!(kept["nearby"], "kept", "{kept}");
    assert_eq!(kept["state"], "background", "{kept}");
    assert_eq!(kept["paused"], true, "{kept}");
    let started = a.ok("node.start", json!({}));
    assert_eq!(started["state"], "background", "{started}");
    let near = a.ok("nearby.status", json!({}));
    assert_eq!(near["background"], "background", "{near}");
    let resumed = a.ok("node.resume", json!({}));
    assert_eq!(resumed["running"], true, "{resumed}");
    assert_eq!(resumed["paused"], false, "{resumed}");
    let plain = a.ok("node.pause", json!({}));
    assert_eq!(plain["nearby"], "stopped", "{plain}");
    assert_eq!(plain["state"], "paused", "{plain}");
    let near = a.ok("nearby.status", json!({}));
    assert_eq!(near["background"], "foreground_only", "{near}");
    a.ok("node.resume", json!({}));

    let stopped = a.ok("node.stop", json!({}));
    assert_eq!(stopped["stop"], "stopped", "{stopped}");
    assert_eq!(stopped["running"], false, "{stopped}");
}

/// A and B on the local network, nothing else (no Tor, no custody): A in
/// this process, B a peer process; friends, nodes started, a first message
/// A to B delivered. `lab`: more lab switches, set for both.
fn two_on_lan(root: &Path, lab: &[&str]) -> (Peer, Peer) {
    embedded_env();
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    // No Tor anywhere: its gate is open in this build.
    std::env::set_var("RAVEN_LAB_TOR", "0");
    std::env::remove_var("RAVEN_LAB_TOR_LOOPBACK");
    for switch in lab {
        std::env::set_var(switch, "1");
    }
    let dir = |n: &str| root.join(n);
    let b = Peer::new("B", dir("b"), Box::new(Remote::spawn(&dir("b"), &[])));
    let a = Peer::new("A", dir("a"), Box::new(Client::with_data_dir(dir("a"))));
    a.befriend(&b);
    b.befriend(&a);
    let (la, lb) = (a.start(), b.start());
    a.set_lan(&b, &lb);
    b.set_lan(&a, &la);
    let id = a.send(&b, "hello before the pause");
    let m = a.wait_state(&b, &id, &["delivered", "failed"], Duration::from_secs(90));
    assert_eq!(m["state"], "delivered", "{m}");
    (a, b)
}

/// Stops this process's node when the test ends, failed or not: the next
/// test starts one of its own.
struct StopsNode<'a>(&'a Peer);

impl Drop for StopsNode<'_> {
    fn drop(&mut self) {
        let _ = self.0.raw("node.stop", json!({}));
    }
}

/// The message `id` to `friend`, as `messages.history` shows it now.
fn message(a: &Peer, friend: &Peer, id: &str) -> Value {
    let history = a.ok(
        "messages.history",
        json!({"address": friend.address(), "limit": 50}),
    );
    history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == id)
        .cloned()
        .unwrap_or(Value::Null)
}

/// The iPhone app leaves the foreground with a send still queued (audit
/// T4): the send's turn comes while `node.pause` holds the node. It is not
/// refused ("Not sent" with PAUSED in its details, nothing dialled): it
/// stays Sending, nothing is written for it, and it goes out once
/// `node.resume` starts the node again.
#[test]
fn a_send_whose_turn_comes_while_paused_goes_out_after_the_resume() {
    in_own_process("send_while_paused");
}

#[test]
#[ignore = "run in a process of its own by a_send_whose_turn_comes_while_paused_goes_out_after_the_resume"]
fn send_while_paused() {
    if !own_process("send_while_paused") {
        return;
    }
    let root = common::short_dir();
    let (a, b) = two_on_lan(root.path(), &[]);
    let _stops = StopsNode(&a);

    a.ok("node.pause", json!({}));
    let id = a.send(&b, "written as the app left");
    // Its turn came at once, while paused; give a refusal time to show.
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        let m = message(&a, &b, &id);
        assert_eq!(m["state"], "sending", "{m}\n{}", a.log());
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(!b.has_incoming(&a, "written as the app left"));

    a.ok("node.resume", json!({}));
    let m = a.wait_state(&b, &id, &["delivered", "failed"], Duration::from_secs(90));
    assert_eq!(m["state"], "delivered", "{m}\n{}", a.log());
    b.wait_incoming(&a, "written as the app left", Duration::from_secs(30));
}

/// The same with Lock v2 (the iPhone app's lock set to "now", audit T4):
/// a send held back by the pause is still held when the node starts again
/// locked (it is not refused as locked: "Not sent"), and it goes out after
/// the unlock.
#[test]
fn a_send_held_by_the_pause_and_the_lock_goes_out_after_the_unlock() {
    in_own_process("send_held_by_pause_and_lock");
}

#[test]
#[ignore = "run in a process of its own by a_send_held_by_the_pause_and_the_lock_goes_out_after_the_unlock"]
fn send_held_by_pause_and_lock() {
    if !own_process("send_held_by_pause_and_lock") {
        return;
    }
    let root = common::short_dir();
    let lock_switch = raven_core::security_gate::LAB_LOCAL_PROTECTION;
    struct Unset(&'static str);
    impl Drop for Unset {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }
    let _unset = Unset(lock_switch);
    let (a, b) = two_on_lan(root.path(), &[lock_switch]);
    let _stops = StopsNode(&a);

    a.ok("node.pause", json!({}));
    let id = a.send(&b, "written as the lock came down");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(message(&a, &b, &id)["state"], "sending");
    // The app locks (Lock v2) in the background, then comes back: the
    // node starts locked, and the send's turn comes again while locked.
    assert_eq!(a.ok("lock.now", json!({}))["locked"], true);
    let st = a.ok("node.resume", json!({}));
    assert_eq!(st["running"], true, "{st}");
    std::thread::sleep(Duration::from_secs(2));
    assert!(!b.has_incoming(&a, "written as the lock came down"));

    assert_eq!(a.ok("lock.unlock", json!({}))["locked"], false);
    let m = a.wait_state(&b, &id, &["delivered", "failed"], Duration::from_secs(90));
    assert_eq!(m["state"], "delivered", "{m}\n{}", a.log());
    b.wait_incoming(&a, "written as the lock came down", Duration::from_secs(30));
}

/// A mail check on opening while a mail friend does not answer (audit T9:
/// the iPhone app checks when it opens): it waits out its budget, and
/// meanwhile a send goes at once and the node can pause at once. Neither
/// waits for the check (it held the engine's node gate and the node's
/// turn for all of its 20 s).
#[test]
fn a_mail_check_holds_up_no_send_and_no_pause() {
    in_own_process("mail_check_beside_a_send_and_a_pause");
}

#[test]
#[ignore = "run in a process of its own by a_mail_check_holds_up_no_send_and_no_pause"]
fn mail_check_beside_a_send_and_a_pause() {
    if !own_process("mail_check_beside_a_send_and_a_pause") {
        return;
    }
    embedded_env();
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    std::env::set_var("RAVEN_LAB_TOR", "0");
    std::env::remove_var("RAVEN_LAB_TOR_LOOPBACK");
    let root = common::short_dir();
    let dir = |n: &str| root.path().join(n);
    let b = Peer::new("B", dir("b"), Box::new(Remote::spawn(&dir("b"), &[])));
    // C holds A's mail; its node never runs, and A's saved address for it
    // takes connections but never answers.
    let c = Peer::new("C", dir("c"), Box::new(Client::with_data_dir(dir("c"))));
    let shared = std::sync::Arc::new(Client::with_data_dir(dir("a")));
    let a = Peer::new("A", dir("a"), Box::new(std::sync::Arc::clone(&shared)));
    let _stops = StopsNode(&a);
    a.befriend(&b);
    b.befriend(&a);
    a.befriend(&c);
    let (la, lb) = (a.start(), b.start());
    a.set_lan(&b, &lb);
    b.set_lan(&a, &la);
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    a.set_lan(&c, &silent.local_addr().unwrap().to_string());
    a.ok(
        "contacts.set_routes",
        json!({"address": b.address(), "custodians": [c.address()]}),
    );
    let id = a.send(&b, "hello before the check");
    let m = a.wait_state(&b, &id, &["delivered", "failed"], Duration::from_secs(90));
    assert_eq!(m["state"], "delivered", "{m}");

    let began = Instant::now();
    let checking = std::thread::spawn(move || {
        let r = shared.call(r#"{"v":1,"op":"mail.check","args":{"budget_ms":20000}}"#);
        (began.elapsed(), r)
    });
    std::thread::sleep(Duration::from_secs(1));
    let sent_at = Instant::now();
    let id = a.send(&b, "written while mail is checked");
    let m = a.wait_state(&b, &id, &["delivered", "failed"], Duration::from_secs(90));
    let send_took = sent_at.elapsed();
    assert_eq!(m["state"], "delivered", "{m}");
    let paused_at = Instant::now();
    a.ok("node.pause", json!({}));
    let pause_took = paused_at.elapsed();
    let still_checking = !checking.is_finished();
    let (check_took, check) = checking.join().unwrap();
    eprintln!("send {send_took:?}, pause {pause_took:?}, check {check_took:?}: {check}");
    assert!(
        check_took >= Duration::from_secs(15),
        "the check did not wait for its mail friend: {check_took:?} {check}"
    );
    assert!(
        send_took < Duration::from_secs(8),
        "the send waited for the mail check: {send_took:?} (check {check_took:?})"
    );
    assert!(
        still_checking && pause_took < Duration::from_secs(9),
        "the pause waited for the mail check: {pause_took:?} (check {check_took:?})"
    );
    drop(silent);
    a.ok("node.resume", json!({}));
}

/// Real Arti inside an engine's process (feature `tor-embedded`) until Tor
/// is ready. Needs the Tor network: run it by name with `--ignored`.
#[test]
#[ignore = "needs the Tor network"]
fn tor_in_process_bootstraps() {
    if !cfg!(feature = "tor-embedded") || !cfg!(debug_assertions) {
        eprintln!("skipped: needs a debug engine built with tor-embedded");
        return;
    }
    embedded_env();
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    std::env::set_var("RAVEN_LAB_TOR", "1");
    std::env::remove_var("RAVEN_LAB_TOR_LOOPBACK");
    let root = common::short_dir();
    let a = Peer::new(
        "A",
        root.path().join("a"),
        Box::new(Client::with_data_dir(root.path().join("a"))),
    );
    a.start();
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        let t = a.carrier("tor");
        if t["running"] == true {
            eprintln!("Tor ready in process: {t}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Tor never ready: {t}\n{}",
            a.log()
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    // Pausing ends Tor in process; resuming starts it again.
    a.ok("node.pause", json!({}));
    assert!(
        a.log().contains("embedded node ended (stopped)"),
        "{}",
        a.log()
    );
    a.ok("node.resume", json!({}));
    a.ok("node.stop", json!({}));
}
