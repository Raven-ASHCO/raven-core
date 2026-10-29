//! Custody handoff in raven-node (Phase 5 P5.21) over real profile folders:
//! Alice and Bob (a direct session), F1 (Alice's friend, listed by her for
//! Bob) and F2 (Bob's friend, listed by him for Alice), each a pinned contact
//! of the next (A-F1, F1-F2, F2-B), F1 and F2 with custody and custody
//! handoff on. Every frame goes to the real handlers. Bob announced F2 to
//! Alice with `HANDOFF_INBOX`, Alice F1 to Bob. The gates open through this
//! thread's debug overrides, which release builds ignore: these tests return
//! early there.
//!
//! - worker h1-h9 (handoff spec §3.5), and the review fixes h10-h12,
//! - forwarder fw1-fw7 (§3.2), and fw8,
//! - registration rg1-rg4 (§3.6), and rg5-rg6,
//! - the whole chain: a message and its ACK through two friends.

use super::*;
use crate::outbox::test_rig::{lab_backends, lan, pair, test_ctx};
use crate::outbox::{
    attempt_peer, scan_store, AttemptCtx, Dialer, Entry, Outcome, PeerReport, UnsentAck,
};
use raven_core::custody_gate::{
    set_carrier_gates_for_this_thread, set_custody_gates_for_this_thread,
    set_custody_hints_for_this_thread, set_handoff_gate_for_this_thread,
};
use raven_core::custody_handoff::HandoffUsage;
use raven_core::device_cert::ensure_local_device_certificate;
use raven_core::envelope::Envelope;
use raven_core::friend_custody::{
    set_lab_base_ops_only_for_this_thread, CustodyStore, InboundLink,
};
use raven_core::indexed_session_store::{
    AuthorizedEndpointDevice, IndexedSessionRecordKey, IndexedSessionStore,
};
use raven_core::lan_dispatch::{cache_peer_bundle, dispatch_frame_on, local_bundle};
use raven_core::outbox::{
    object_route_records, record_object_routes, CarrierChoice, CarrierGates, OutboxCarrier,
    PeerSendLock,
};
use raven_core::owed_acks::OwedAcks;
use raven_core::paths::PRIMARY_DEVICE_ID;
use raven_core::route_hints::{custodian_tag, CUSTODIAN_FLAG_HANDOFF_INBOX};
use raven_core::LanBundle;
use std::sync::atomic::{AtomicUsize, Ordering};

const DAY: u64 = 24 * 60 * 60 * 1000;
const A: usize = 0;
const B: usize = 1;
const F1: usize = 2;
const F2: usize = 3;
/// A third friend Bob may announce (never dialled: a key only).
const F3: usize = 4;

fn now() -> u64 {
    raven_core::clock::now_ms()
}

/// Custody live (no WAN), riding route hints, the LAN carrier open and the
/// handoff gate `handoff` on this thread; the letters held, whatever
/// `RAVEN_LAB_LETTER` the suite runs with (with them a fetch pass also asks
/// for letters, one more dial); cleared on drop.
struct Gates {
    _lan: crate::lan_direct::LanSwitchUntouched,
}

impl Gates {
    fn on(handoff: bool) -> Self {
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        set_custody_hints_for_this_thread(Some(true));
        set_carrier_gates_for_this_thread(Some(CarrierGates {
            lan: true,
            internet: false,
            p2p: false,
            nearby: false,
            onion: false,
        }));
        set_handoff_gate_for_this_thread(Some(handoff));
        raven_core::horizon::set_lab_letter_for_this_thread(Some(false));
        Self {
            _lan: crate::lan_direct::lan_switch_untouched(),
        }
    }
}

impl Drop for Gates {
    fn drop(&mut self) {
        set_handoff_gate_for_this_thread(None);
        set_carrier_gates_for_this_thread(None);
        set_custody_hints_for_this_thread(None);
        set_custody_gates_for_this_thread(None);
        set_lab_base_ops_only_for_this_thread(None);
        raven_core::horizon::set_lab_letter_for_this_thread(None);
    }
}

struct Node {
    hex: String,
    dir: PathBuf,
    id: Identity,
}

struct Caller {
    dir: PathBuf,
    bundle: LanBundle,
    key: [u8; 32],
}

/// Everybody's listener, in process: a dial reaches the node it expects
/// (unless it is down, or closes every link) and hands every frame to its
/// real dispatcher, as the caller whose data dir dials.
struct Net {
    nodes: Vec<Node>,
    callers: Vec<Caller>,
    down: Mutex<HashSet<String>>,
    closing: Mutex<HashSet<String>>,
    /// (the data dir whose send lock is checked, its peer) per dial.
    lock_probe: Mutex<Option<(PathBuf, [u8; 32])>>,
    probed: AtomicUsize,
    held_dials: AtomicUsize,
    /// (caller dir, node dialled, its RFC1 request ops) per dial.
    log: Mutex<Vec<(PathBuf, String, Vec<u8>)>>,
}

impl Dialer for Net {
    fn dial(
        &self,
        data_dir: &Path,
        _route: &OutboxRoute,
        expected: &str,
        frames: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, String> {
        if let Some((dir, peer)) = self.lock_probe.lock().unwrap().clone() {
            self.probed.fetch_add(1, Ordering::SeqCst);
            if PeerSendLock::acquire_within(&dir, &peer, Duration::ZERO).is_err() {
                self.held_dials.fetch_add(1, Ordering::SeqCst);
            }
        }
        let ops = frames
            .iter()
            .filter(|f| raven_core::friend_custody::is_rfc1(f))
            .map(|f| f[5])
            .collect();
        self.log
            .lock()
            .unwrap()
            .push((data_dir.to_path_buf(), expected.to_string(), ops));
        if self.down.lock().unwrap().contains(expected) {
            return Err("lan connect: cannot connect (Connection refused)".into());
        }
        if self.closing.lock().unwrap().contains(expected) {
            return Err(
                "LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying".into(),
            );
        }
        let node = self
            .nodes
            .iter()
            .find(|n| n.hex == expected)
            .ok_or("lan connect: cannot connect (Connection refused)")?;
        let caller = self
            .callers
            .iter()
            .find(|c| c.dir == data_dir)
            .ok_or("unknown caller")?;
        let mut replies = vec![raven_core::encode_local_offer(&node.dir, &node.id)?];
        for frame in frames {
            let link = InboundLink {
                carrier: OutboxCarrier::Lan,
                source: Some("192.168.1.40".parse().unwrap()),
            };
            if let Ok(more) = dispatch_frame_on(
                &node.dir,
                &node.id,
                &caller.bundle,
                &caller.key,
                frame,
                link,
            ) {
                replies.extend(more);
            }
        }
        Ok(replies)
    }
}

/// Alice, Bob, F1 and F2 (and F3's key): see the module.
struct World {
    dirs: Vec<tempfile::TempDir>,
    ids: Vec<Arc<Identity>>,
    keys: Vec<[u8; 32]>,
    key: IndexedSessionRecordKey,
    net: Arc<Net>,
}

fn contact(key: &[u8; 32], lan: &str, custodians: &[[u8; 32]]) -> serde_json::Value {
    serde_json::json!({
        "petname": hex::encode(&key[..4]),
        "pub_hex": hex::encode(key),
        "pinned": true,
        "lan_dial": lan,
        "custodians": custodians.iter().map(hex::encode).collect::<Vec<_>>(),
    })
}

fn write_contacts(dir: &Path, rows: &[serde_json::Value]) {
    std::fs::write(
        dir.join("contacts.json"),
        serde_json::Value::Array(rows.to_vec()).to_string(),
    )
    .unwrap();
}

/// Where each node listens (the routes the books hold; the net ignores
/// them).
fn lan_of(n: usize) -> &'static str {
    [
        "127.0.0.1:8",
        "127.0.0.1:9",
        "192.168.1.50:7420",
        "192.168.1.51:7420",
        "192.168.1.52:7420",
    ][n]
}

impl World {
    fn new(seed: u8) -> Self {
        let ids: Vec<Arc<Identity>> = (0..5u8)
            .map(|n| Arc::new(Identity::from_seed(&[seed.wrapping_add(n); 32])))
            .collect();
        let dirs: Vec<tempfile::TempDir> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
        for (dir, who) in dirs.iter().zip(&ids) {
            ensure_local_device_certificate(dir.path(), who, PRIMARY_DEVICE_ID).unwrap();
            raven_core::ensure_local_prekey(dir.path(), who).unwrap();
        }
        let keys: Vec<[u8; 32]> = ids.iter().map(|i| i.public_key_bytes()).collect();
        let row = |n: usize, custodians: &[usize]| {
            let cs: Vec<[u8; 32]> = custodians.iter().map(|c| keys[*c]).collect();
            contact(&keys[n], lan_of(n), &cs)
        };
        write_contacts(
            dirs[A].path(),
            &[row(B, &[F1]), row(F1, &[]), row(F2, &[]), row(F3, &[])],
        );
        write_contacts(dirs[B].path(), &[row(A, &[F2]), row(F2, &[]), row(F1, &[])]);
        write_contacts(dirs[F1].path(), &[row(A, &[]), row(F2, &[]), row(F3, &[])]);
        write_contacts(dirs[F2].path(), &[row(B, &[]), row(F1, &[])]);
        for n in [F1, F2] {
            handoff_policy(dirs[n].path(), true);
        }
        let bundles: Vec<LanBundle> = (0..4)
            .map(|n| local_bundle(dirs[n].path(), &ids[n]).unwrap())
            .collect();
        cache_peer_bundle(dirs[A].path(), &bundles[B]).unwrap();
        cache_peer_bundle(dirs[B].path(), &bundles[A]).unwrap();
        let key = pair(
            dirs[A].path(),
            &ids[A],
            dirs[B].path(),
            &ids[B],
            &bundles[A],
            &bundles[B],
        );
        let net = Arc::new(Net {
            nodes: (0..4)
                .map(|n| Node {
                    hex: hex::encode(keys[n]),
                    dir: dirs[n].path().to_path_buf(),
                    id: Identity::from_seed(&[seed.wrapping_add(n as u8); 32]),
                })
                .collect(),
            callers: (0..4)
                .map(|n| Caller {
                    dir: dirs[n].path().to_path_buf(),
                    bundle: bundles[n].clone(),
                    key: keys[n],
                })
                .collect(),
            down: Mutex::new([hex::encode(keys[A]), hex::encode(keys[B])].into()),
            closing: Mutex::new(HashSet::new()),
            lock_probe: Mutex::new(None),
            probed: AtomicUsize::new(0),
            held_dials: AtomicUsize::new(0),
            log: Mutex::new(Vec::new()),
        });
        let w = Self {
            dirs,
            ids,
            keys,
            key,
            net,
        };
        // Bob announced F2 to Alice with HANDOFF_INBOX, Alice F1 to Bob.
        w.told(A, B, &[(F2, CUSTODIAN_FLAG_HANDOFF_INBOX)]);
        w.told(B, A, &[(F1, CUSTODIAN_FLAG_HANDOFF_INBOX)]);
        w
    }

    fn dir(&self, n: usize) -> &Path {
        self.dirs[n].path()
    }

    /// `to`'s learned snapshot of `from`: the custodians `from` announced
    /// to it (pair-blinded tags) with their flags.
    fn told(&self, to: usize, from: usize, custodians: &[(usize, u8)]) {
        let t = now();
        let tags: Vec<String> = custodians
            .iter()
            .map(|(c, _)| {
                hex::encode(custodian_tag(
                    &self.keys[from],
                    &self.keys[to],
                    &self.keys[*c],
                ))
            })
            .collect();
        let flags: Vec<u8> = custodians.iter().map(|(_, f)| *f).collect();
        let rows = serde_json::json!([{
            "pub_hex": hex::encode(self.keys[from]),
            "generation": t,
            "received_at_ms": t,
            "expires_at_ms": t + 600_000,
            "via": "lan",
            "custodian_tags": tags,
            "custodian_tag_flags": flags,
        }]);
        std::fs::write(
            self.dir(to)
                .join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
            rows.to_string(),
        )
        .unwrap();
    }

    /// `to` also holds `from`'s own snapshot offering custody (RRH1
    /// CUSTODY_OFFER: `from` holds mail for `to`), next to what is there.
    fn offers(&self, to: usize, from: usize) {
        let path = self
            .dir(to)
            .join(raven_core::learned_routes::LEARNED_ROUTES_FILE);
        let mut rows: Vec<serde_json::Value> = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let t = now();
        rows.push(serde_json::json!({
            "pub_hex": hex::encode(self.keys[from]),
            "generation": t,
            "received_at_ms": t,
            "expires_at_ms": t + 600_000,
            "via": "lan",
            "custody_offer": 0,
        }));
        std::fs::write(&path, serde_json::Value::Array(rows).to_string()).unwrap();
    }

    /// F1 knows Bob too (a plain DEPOSIT there names him as the recipient,
    /// which F1 takes only for a contact of its own).
    fn f1_knows_bob(&self) {
        let row = |n: usize| contact(&self.keys[n], lan_of(n), &[]);
        write_contacts(self.dir(F1), &[row(A), row(B), row(F2), row(F3)]);
    }

    /// No announcement at all at `to`.
    fn untold(&self, to: usize) {
        let _ = std::fs::remove_file(
            self.dir(to)
                .join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
        );
    }

    fn ctx(&self, n: usize) -> AttemptCtx {
        test_ctx(self.dir(n), Arc::clone(&self.ids[n]), self.net.clone())
    }

    /// Alice's `raven send` while Bob is down, two minutes ago (the direct
    /// path had its chance), valid for `ttl` ms from then: staged in the
    /// direct session, its route record allowing custody.
    fn stage(&self, text: &str, ttl: u64) -> [u8; 16] {
        let created = now() - 120_000;
        let a = self.dir(A).to_path_buf();
        let (cert, registry) =
            ensure_local_device_certificate(&a, &self.ids[A], PRIMARY_DEVICE_ID).unwrap();
        let device =
            AuthorizedEndpointDevice::authorize(&cert, &self.ids[A], &registry, created).unwrap();
        let mut store = IndexedSessionStore::open(&a).unwrap();
        let session = store.session_id_for_record_key(&self.key).unwrap();
        let end = store.session_expires_at(&self.key).unwrap();
        let mut staged = None;
        let bob = self.keys[B];
        store
            .send_message_envelope(
                &self.key,
                text,
                &device,
                created,
                (created + ttl).min(end),
                created,
                &mut rand::rngs::OsRng,
                &mut |digest: &[u8; 32], bytes: &[u8]| {
                    let env = Envelope::unpack(bytes).unwrap();
                    raven_core::ensure_outbound_queued_history(
                        &a,
                        &bob,
                        &session,
                        digest,
                        &env.message_id,
                        created,
                        Some(text),
                    )
                    .unwrap();
                    staged = Some(env.message_id);
                    Ok(*digest)
                },
            )
            .unwrap();
        let mid = staged.unwrap();
        record_object_routes(
            &a,
            &mid,
            &bob,
            CarrierChoice::Auto,
            &[lan("127.0.0.1:9")],
            now() + DAY,
            now(),
        )
        .unwrap();
        raven_core::outbox::set_object_custody(&a, &mid, now()).unwrap();
        mid
    }

    fn due_of(&self, n: usize, peer: usize) -> Vec<Entry> {
        let t = Instant::now();
        scan_store(self.dir(n))
            .unwrap()
            .iter()
            .map(|r| Entry::from_row(r, t))
            .filter(|e| e.recipient == self.keys[peer])
            .collect()
    }

    /// One worker attempt of Alice's for Bob.
    fn attempt(&self) -> PeerReport {
        attempt_peer(&self.ctx(A), &self.keys[B], &self.due_of(A, B), &[])
    }

    /// One worker attempt of Bob's for Alice, with the ACKs he owes her.
    fn bob_attempt(&self) -> PeerReport {
        let (mut owed, _) = OwedAcks::open(self.dir(B)).unwrap();
        let acks: Vec<([u8; 32], UnsentAck)> = owed
            .list(now())
            .unwrap()
            .into_iter()
            .map(|o| {
                (
                    o.ack_digest,
                    UnsentAck {
                        peer: o.peer,
                        bytes: o.bytes,
                        expires_at_ms: o.expires_at_ms,
                        failures: 0,
                        next_due: Instant::now(),
                        durable: true,
                        session_id: o.session_id,
                        held_by: o.held_by,
                        may_deposit: o.origin.may_deposit(),
                    },
                )
            })
            .collect();
        attempt_peer(&self.ctx(B), &self.keys[A], &self.due_of(B, A), &acks)
    }

    /// One fetch pass of node `n` on `shared` at `at`, through the net.
    fn fetch(&self, n: usize, shared: &Mutex<Shared>, at: Instant) -> bool {
        self.fetch_at(n, shared, at, now())
    }

    /// [`Self::fetch`] with the wall clock at `wall` (ms).
    fn fetch_at(&self, n: usize, shared: &Mutex<Shared>, at: Instant, wall: u64) -> bool {
        let dir = self.dir(n);
        let mut dial = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            self.net
                .dial(dir, route, expected, frames)
                .map(|replies| (replies, Some(DeliveryPath::Direct)))
        };
        let mut home_changed = |_: usize| {};
        let mut io = PassIo {
            dial: &mut dial,
            want: &|_| {},
            finds: &|_| Vec::new(),
            find_failed: &|_, _| {},
            home_changed: &mut home_changed,
            lan: true,
            kick: &|_| {},
        };
        fetch_pass_with(shared, dir, &self.ids[n], at, wall, &mut io)
    }

    /// One forward pass of custodian `n` on `shared` at `at` / `wall`.
    fn forward(&self, n: usize, shared: &Mutex<Shared>, at: Instant, wall: u64) -> ForwardPass {
        self.forward_io(n, shared, at, wall, true, &|_| {})
    }

    /// [`Self::forward`] with the LAN carrier's gate `lan` and the LAN
    /// beacon's `want`.
    fn forward_io(
        &self,
        n: usize,
        shared: &Mutex<Shared>,
        at: Instant,
        wall: u64,
        lan: bool,
        want: &dyn Fn(&[u8; 32]),
    ) -> ForwardPass {
        let dir = self.dir(n);
        let mut dial = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            self.net
                .dial(dir, route, expected, frames)
                .map(|replies| (replies, Some(DeliveryPath::Direct)))
        };
        let mut home_changed = |_: usize| {};
        let mut io = PassIo {
            dial: &mut dial,
            want,
            finds: &|_| Vec::new(),
            find_failed: &|_, _| {},
            home_changed: &mut home_changed,
            lan,
            kick: &|_| {},
        };
        forward_pass_with(shared, dir, at, wall, &mut io)
    }

    /// What custodian `n`'s handoff store holds (all zero: no store).
    fn handoff_usage(&self, n: usize) -> HandoffUsage {
        HandoffStore::open_existing(self.dir(n))
            .unwrap()
            .map(|s| s.usage().unwrap())
            .unwrap_or_default()
    }

    /// The pending forward rows custodian `n` holds, as (next hop, tries).
    fn forward_rows(&self, n: usize, wall: u64) -> Vec<([u8; 32], u32)> {
        HandoffStore::open_existing(self.dir(n))
            .unwrap()
            .map(|s| {
                s.forward_due_for(wall, 64, &|_| true)
                    .unwrap()
                    .into_iter()
                    .map(|r| (r.next_hop, r.attempts))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Base-ops objects custodian `n` holds (RFC1 DEPOSIT or DELIVER).
    fn objects_at(&self, n: usize) -> i64 {
        CustodyStore::open_existing(self.dir(n))
            .unwrap()
            .map_or(0, |s| s.usage().unwrap().0)
    }

    /// The RFC1 request ops of every dial from `from` to `to` so far.
    fn ops(&self, from: usize, to: usize) -> Vec<Vec<u8>> {
        let to = hex::encode(self.keys[to]);
        self.net
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|(dir, node, _)| dir == self.dir(from) && *node == to)
            .map(|(_, _, ops)| ops.clone())
            .collect()
    }

    fn history(&self, mid: &[u8; 16]) -> Option<String> {
        raven_core::ChatHistory::load(self.dir(A))
            .unwrap()
            .entries
            .into_iter()
            .find(|e| e.direction == "out" && e.message_id_hex == hex::encode(mid))
            .map(|e| e.delivery)
    }

    fn bob_inbox(&self) -> Vec<String> {
        IndexedSessionStore::open(self.dir(B))
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .into_iter()
            .map(|r| String::from_utf8_lossy(&r.plaintext).into_owned())
            .collect()
    }

    fn held_by(&self, mid: &[u8; 16]) -> Vec<String> {
        object_route_records(self.dir(A), now()).unwrap()[mid]
            .custodians_held
            .clone()
    }
}

/// Custody (and custody handoff when `handoff`) offered by the node at
/// `dir`.
fn handoff_policy(dir: &Path, handoff: bool) {
    raven_core::save_policy(
        dir,
        &raven_core::NodePolicy {
            custody: true,
            custody_handoff: handoff,
            ..Default::default()
        },
    )
    .unwrap();
}

/// The one outcome of a report.
fn only(report: &PeerReport) -> Outcome {
    assert_eq!(report.outcomes.len(), 1, "{:?}", report.outcomes);
    report.outcomes.values().next().unwrap().clone()
}

const HANDOFF: u8 = 0x07;
const TAGS: u8 = 0x08;
const DEPOSIT: u8 = 0x01;
const FETCH: u8 = 0x02;
const HOUR_MS: u64 = 3_600_000;
/// Far enough on that every custodian is due again.
const LATER: Duration = Duration::from_secs(3_600);

// ── The worker (h1-h9) ─────────────────────────────────────────────────────

/// h1 (with h8, h9): Bob down and F1 not in Bob's announced set {F2}: F1's
/// dial carries HANDOFF/FORWARD with next hop F2 and no DEPOSIT; the object
/// is held by F1 (Deposited, custodians_held = [F1]), never delivered; the
/// send lock is free during every dial; the next attempt files nothing again.
#[test]
fn h1_a_message_goes_to_f1_as_a_forward_to_f2() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0x11);
    let mid = w.stage("two friends", DAY);
    *w.net.lock_probe.lock().unwrap() = Some((w.dir(A).to_path_buf(), w.keys[B]));
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    assert_eq!(w.held_by(&mid), vec![hex::encode(w.keys[F1])]);
    assert_eq!(w.ops(A, F1), vec![vec![HANDOFF]]);
    assert_eq!(w.forward_rows(F1, now()), vec![(w.keys[F2], 0)]);
    assert_eq!(w.objects_at(F1), 0, "no DEPOSIT at F1");
    // h9: held is not delivered.
    assert_eq!(w.history(&mid).as_deref(), Some("queued"));
    // h8: never under the send lock.
    assert!(w.net.probed.load(Ordering::SeqCst) >= 2);
    assert_eq!(w.net.held_dials.load(Ordering::SeqCst), 0);
    // Not filed again.
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    assert_eq!(w.ops(A, F1).len(), 1);
    assert_eq!(w.forward_rows(F1, now()).len(), 1);
}

/// h2: F1 is in Bob's announced set: a DEPOSIT only, no HANDOFF.
#[test]
fn h2_an_announced_custodian_gets_a_deposit_only() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0x21);
    w.f1_knows_bob();
    w.told(A, B, &[(F1, 0), (F2, CUSTODIAN_FLAG_HANDOFF_INBOX)]);
    w.stage("announced", DAY);
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    assert_eq!(w.ops(A, F1), vec![vec![DEPOSIT]]);
    assert_eq!(w.objects_at(F1), 1);
    assert_eq!(w.handoff_usage(F1), HandoffUsage::default());
}

/// h3: no announcement from Bob: Phase 3's DEPOSIT.
#[test]
fn h3_no_announcement_is_phase_3() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0x31);
    w.f1_knows_bob();
    w.untold(A);
    w.stage("phase 3", DAY);
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    assert_eq!(w.ops(A, F1), vec![vec![DEPOSIT]]);
    assert_eq!(w.objects_at(F1), 1);
}

/// h4: F1 has no handoff ops (UNSUPPORTED): handoff is parked at F1, plain
/// custody to F1 is not (no plain park, no strike), and the next attempt
/// leaves the object there with a DEPOSIT.
#[test]
fn h4_unsupported_parks_handoff_only() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0x41);
    w.f1_knows_bob();
    let (f1, bob) = (w.keys[F1], w.keys[B]);
    w.stage("old friend", DAY);
    set_lab_base_ops_only_for_this_thread(Some(true));
    let report = w.attempt();
    assert!(
        !matches!(only(&report), Outcome::Deposited { .. }),
        "{report:?}"
    );
    assert_eq!(w.ops(A, F1), vec![vec![HANDOFF]]);
    assert!(handoff_parked(&f1, None));
    assert_eq!(parked(&f1, Some(&bob)), None, "plain custody stays usable");
    assert!(!lock().strikes.contains_key(&f1));
    assert_eq!(crate::letters::handoff_supported(&f1, now()), Some(false));
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    assert_eq!(w.ops(A, F1)[1], vec![DEPOSIT]);
    assert_eq!(w.objects_at(F1), 1);
}

/// h5: F1 does not know F2 (NEXT_HOP_UNKNOWN): the pair (F1, F2) is parked
/// and the next attempt forwards to the next announced inbox, F3.
#[test]
fn h5_next_hop_unknown_moves_on_to_the_next_inbox() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0x51);
    let (f1, f2, f3) = (w.keys[F1], w.keys[F2], w.keys[F3]);
    write_contacts(
        w.dir(F1),
        &[contact(&w.keys[A], "", &[]), contact(&f3, lan_of(F3), &[])],
    );
    let inbox = CUSTODIAN_FLAG_HANDOFF_INBOX;
    w.told(A, B, &[(F2, inbox), (F3, inbox)]);
    w.stage("next hop", DAY);
    let first = w.attempt();
    assert!(!matches!(only(&first), Outcome::Deposited { .. }));
    assert!(handoff_parked(&f1, Some(&f2)));
    assert!(!handoff_parked(&f1, None), "the pair only");
    assert_eq!(w.handoff_usage(F1), HandoffUsage::default());
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    assert_eq!(w.forward_rows(F1, now()), vec![(f3, 0)]);
}

/// h6: the handoff gate closed: never a HANDOFF, Phase 3's DEPOSIT.
#[test]
fn h6_gate_off_never_hands_off() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(false);
    let w = World::new(0x61);
    w.f1_knows_bob();
    w.stage("gate off", DAY);
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    assert_eq!(w.ops(A, F1), vec![vec![DEPOSIT]]);
    assert!(!w
        .dir(F1)
        .join(raven_core::custody_handoff::HANDOFF_DB_FILE)
        .exists());
}

/// h10, review handoff-4: a plain DEPOSIT F2 refused for Alice
/// (RECIPIENT_NOT_ACCEPTED: F2 never pins Alice, by design; say Bob's owed
/// ACK to her in its last 2 h, which is not forwarded) parks (F2, Alice)
/// for Bob's deposits only. Bob still fetches Alice's mail at F2 and
/// registers his tags from her there: exactly the mail F2 holds for him,
/// DELIVERed by F1. With the handoff gate closed nothing reaches Bob that
/// way, and the pair park keeps Alice's tags out of his fetch there, as in
/// Phase 3.
#[test]
fn h10_a_refused_deposit_never_stops_the_fetch_there() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0xf1);
    let (alice, f2) = (w.keys[A], w.keys[F2]);
    let t0 = Instant::now();
    let sb = Mutex::default();
    lock_of(&sb).park_for_code(&f2, &alice, CustodyCode::RecipientNotAccepted, t0);
    assert_eq!(
        lock_of(&sb).parked(&f2, Some(&alice), t0),
        Some("CUSTODY_RECIPIENT_REFUSED"),
        "the depositor's park stands"
    );
    w.fetch(B, &sb, t0);
    let ops = w.ops(B, F2);
    assert_eq!(ops.len(), 1, "{ops:?}");
    assert!(ops[0].contains(&TAGS) && ops[0].contains(&FETCH), "{ops:?}");
    assert!(w.handoff_usage(F2).tags >= 2);
    // The gate closed: Phase 3's pair park, no dial for Alice's mail.
    let w = World::new(0xf6);
    set_handoff_gate_for_this_thread(Some(false));
    let sb = Mutex::default();
    lock_of(&sb).park_for_code(
        &w.keys[F2],
        &w.keys[A],
        CustodyCode::RecipientNotAccepted,
        t0,
    );
    w.fetch(B, &sb, t0);
    assert!(w.ops(B, F2).is_empty(), "{:?}", w.ops(B, F2));
}

/// h11, review handoff-5: Alice pins F2 (Bob's friend) to name it as the
/// next hop, here with an address; F2 offers her nothing (it does not pin
/// her). Her fetcher never dials F2 for Bob's mail, although Bob named it:
/// each dial would show F2 her identity. Once F2 does offer her custody
/// (its own snapshot), F2 is a custodian she fetches from for Bob, as P5.14
/// has it.
#[test]
fn h11_a_far_friend_that_offers_nothing_is_never_dialled() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0xfb);
    let t0 = Instant::now();
    let sa = Mutex::default();
    w.fetch(A, &sa, t0);
    assert!(!w.ops(A, F1).is_empty(), "her own friend");
    assert!(w.ops(A, F2).is_empty(), "{:?}", w.ops(A, F2));
    w.fetch(A, &sa, t0 + LATER);
    assert!(w.ops(A, F2).is_empty(), "{:?}", w.ops(A, F2));
    // F2 offers Alice custody: fetched from for Bob.
    w.offers(A, F2);
    w.fetch(A, &sa, t0 + LATER * 2);
    assert_eq!(w.ops(A, F2).len(), 1, "{:?}", w.ops(A, F2));
}

/// h12, review handoff-3: a message F1 holds only to pass on is recorded as
/// such (its route record's `custody_forwarded`, the attempt's report and
/// the outbox item), so once its time runs out its row says that delivery
/// was not confirmed: Bob may have collected it from F2 while his receipt
/// had no way back. A plain DEPOSIT (F1 in Bob's announced set) is not.
#[test]
fn h12_a_hold_to_pass_on_is_recorded_as_such() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0x01);
    let mid = w.stage("passed on", DAY);
    let report = w.attempt();
    assert_eq!(only(&report), Outcome::Deposited { held: 1 });
    let digest = *report.outcomes.keys().next().unwrap();
    assert!(report.custody_forwarded.contains(&digest));
    assert!(object_route_records(w.dir(A), now()).unwrap()[&mid].custody_forwarded);
    // The next attempt (nothing new filed) still reports it.
    let report = w.attempt();
    assert_eq!(only(&report), Outcome::Deposited { held: 1 });
    assert!(report.custody_forwarded.contains(&digest));
    // F1 announced by Bob: a plain DEPOSIT, held for Bob himself.
    let w = World::new(0x06);
    w.f1_knows_bob();
    w.told(A, B, &[(F1, 0), (F2, CUSTODIAN_FLAG_HANDOFF_INBOX)]);
    let mid = w.stage("deposited", DAY);
    let report = w.attempt();
    assert_eq!(only(&report), Outcome::Deposited { held: 1 });
    assert!(report.custody_forwarded.is_empty());
    assert!(!object_route_records(w.dir(A), now()).unwrap()[&mid].custody_forwarded);
}

/// Cutoff addendum: an object with less than 2 h of validity left is not
/// forwarded (it would expire on the way); it keeps its other paths, here
/// the plain DEPOSIT at F1.
#[test]
fn h_a_short_lived_object_is_not_forwarded() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0x71);
    w.f1_knows_bob();
    // Created two minutes ago, valid for two hours: under 2 h left.
    w.stage("short", 2 * 60 * 60 * 1000);
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    assert_eq!(w.ops(A, F1), vec![vec![DEPOSIT]]);
    assert_eq!(w.handoff_usage(F1), HandoffUsage::default());
}

/// The whole chain (h7, h9, fw1, rg1): Alice's message goes A -> F1 -> F2
/// -> B and its ACK B -> F2 -> F1 -> A, each FORWARD planned from the other
/// side's announcement, each DELIVER after the recipient registered its
/// tags on its fetch dial; the message is delivered only once the ACK is
/// fetched, and each custodian hands each object on exactly once.
#[test]
fn a_message_and_its_ack_travel_through_two_friends() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0x81);
    let (f1, f2) = (w.keys[F1], w.keys[F2]);
    let mid = w.stage("carried twice", DAY);
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    // Bob's fetch pass registers his tags at F2 (TAGS ahead of FETCH).
    let (sb, s1, s2, sa) = (
        Mutex::default(),
        Mutex::default(),
        Mutex::default(),
        Mutex::default(),
    );
    let t0 = Instant::now();
    w.fetch(B, &sb, t0);
    assert!(w.ops(B, F2)[0].starts_with(&[TAGS]), "{:?}", w.ops(B, F2));
    assert!(lock_of(&sb).inbox_ok(&f2, t0), "F2 answered OK");
    // F1 hands it on: one dial of one DELIVER, STORED, marked handed.
    let pass = w.forward(F1, &s1, t0, now());
    assert_eq!((pass.dials, pass.handed, pass.kept), (1, 1, 0));
    assert_eq!(w.ops(F1, F2), vec![vec![HANDOFF]]);
    assert_eq!(w.handoff_usage(F1).handed, 1);
    assert_eq!(w.objects_at(F2), 1, "held for Bob");
    // Bob's next pass takes it; no TAGS again (registered).
    w.fetch(B, &sb, t0 + LATER);
    assert_eq!(w.bob_inbox(), vec!["carried twice".to_string()]);
    assert!(w.ops(B, F2)[1..].iter().all(|ops| !ops.contains(&TAGS)));
    assert_eq!(w.history(&mid).as_deref(), Some("queued"), "h9: no ACK yet");
    // h7: Bob owes the ACK; it takes the mirrored path, FORWARD at F2 to F1.
    let back = w.bob_attempt();
    assert_eq!(back.acks_failed.len(), 1, "still owed: pushes go on");
    assert!(w.ops(B, F2).iter().any(|ops| ops == &vec![HANDOFF]));
    assert_eq!(w.forward_rows(F2, now()), vec![(f1, 0)]);
    // Alice registers at F1, F2 hands the ACK on, Alice fetches it.
    w.fetch(A, &sa, t0);
    let pass = w.forward(F2, &s2, t0, now());
    assert_eq!((pass.dials, pass.handed), (1, 1));
    w.fetch(A, &sa, t0 + LATER);
    assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
    // fw1: a re-FORWARD is DUPLICATE and nothing is sent again.
    let pass = w.forward(F1, &s1, t0 + LATER, now());
    assert_eq!(pass.dials, 0);
    assert_eq!(w.ops(F1, F2).len(), 1);
}

// ── The forwarder (fw2-fw7) ────────────────────────────────────────────────

/// A FORWARD from Alice at F1 (her worker's attempt), then F1's shared.
fn forwarded(seed: u8) -> (World, Mutex<Shared>) {
    let w = World::new(seed);
    w.stage("for the forwarder", DAY);
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    assert_eq!(w.forward_rows(F1, now()).len(), 1);
    (w, Mutex::default())
}

/// fw2 (and fw4, fw7): TAG_UNKNOWN (Bob has not registered) backs off 60 s
/// doubling (±50 %), the row is not sent before; Bob's registration and a
/// trigger (F2 seen, a network change) send it at once.
#[test]
fn fw2_tag_unknown_backs_off_then_delivers_once_registered() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let (w, s1) = forwarded(0x91);
    let f2 = w.keys[F2];
    let (t0, wall) = (Instant::now(), now());
    let pass = w.forward(F1, &s1, t0, wall);
    assert_eq!((pass.dials, pass.handed, pass.kept), (1, 0, 1));
    let next_try = |at: u64| {
        HandoffStore::open_existing(w.dir(F1))
            .unwrap()
            .unwrap()
            .forward_due(at, 8)
            .unwrap()
            .len()
    };
    assert_eq!(next_try(wall + 29_000), 0, "not before 30 s");
    assert_eq!(next_try(wall + 90_000), 1, "due by 90 s");
    // Not due: the next pass sends nothing.
    let pass = w.forward(F1, &s1, t0 + LATER, wall + 1_000);
    assert_eq!(pass.dials, 0);
    // Due again: TAG_UNKNOWN again, now 60-180 s.
    let pass = w.forward(F1, &s1, t0 + LATER * 2, wall + 91_000);
    assert_eq!((pass.dials, pass.kept), (1, 1));
    assert_eq!(next_try(wall + 91_000 + 59_000), 0);
    assert_eq!(next_try(wall + 91_000 + 180_000), 1);
    assert_eq!(w.forward_rows(F1, wall)[0].1, 2, "two tries");
    // Bob registers; fw4: F2 seen makes the row due at once.
    w.fetch(B, &Mutex::default(), Instant::now());
    let t3 = t0 + LATER * 3;
    assert_eq!(w.forward(F1, &s1, t3, wall + 92_000).dials, 0, "backed off");
    assert!(lock_of(&s1).seen_for_handoff(&f2, t3));
    let pass = w.forward(F1, &s1, t3, wall + 92_000);
    assert_eq!((pass.dials, pass.handed, pass.kept), (1, 1, 0));
    assert_eq!(w.objects_at(F2), 1);
}

/// fw7: a network change makes every row due at once.
#[test]
fn fw7_a_network_change_makes_rows_due() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let (w, s1) = forwarded(0x92);
    let (t0, wall) = (Instant::now(), now());
    assert_eq!(w.forward(F1, &s1, t0, wall).kept, 1, "TAG_UNKNOWN");
    w.fetch(B, &Mutex::default(), Instant::now());
    let t1 = t0 + LATER;
    assert_eq!(w.forward(F1, &s1, t1, wall + 1_000).dials, 0);
    lock_of(&s1).network_changed(t1);
    let pass = w.forward(F1, &s1, t1, wall + 1_000);
    assert_eq!((pass.dials, pass.handed), (1, 1));
}

/// fw9 (review cross-3): before it dials a next hop the forwarder asks the
/// LAN beacon to look for it (its LAN address may have changed), as the
/// fetch pass does for a due custodian: once per pass, not while the LAN
/// carrier's gate is closed, and not for a hop whose retry wait runs.
#[test]
fn fw9_the_forwarder_asks_the_lan_beacon_for_the_next_hop() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let (w, s1) = forwarded(0x96);
    let f2 = w.keys[F2];
    let wanted: Mutex<Vec<[u8; 32]>> = Mutex::default();
    let want = |hop: &[u8; 32]| wanted.lock().unwrap().push(*hop);
    let (t0, wall) = (Instant::now(), now());
    // The LAN carrier's gate closed: dialled, never wanted.
    let pass = w.forward_io(F1, &s1, t0, wall, false, &want);
    assert_eq!((pass.dials, pass.kept), (1, 1), "TAG_UNKNOWN");
    assert!(wanted.lock().unwrap().is_empty());
    // Open: wanted once, then dialled.
    let t1 = t0 + LATER;
    lock_of(&s1).network_changed(t1);
    let pass = w.forward_io(F1, &s1, t1, wall + 1_000, true, &want);
    assert_eq!(pass.dials, 1);
    assert_eq!(*wanted.lock().unwrap(), [f2]);
    // The hop's retry wait runs: neither wanted nor dialled.
    let t2 = t1 + LATER;
    {
        let mut s = lock_of(&s1);
        s.forward_failed(&f2, t2);
        s.forward_all = true;
        s.forward_next = Some(t2);
    }
    let pass = w.forward_io(F1, &s1, t2, wall + 2_000, true, &want);
    assert_eq!(pass.dials, 0);
    assert_eq!(*wanted.lock().unwrap(), [f2], "no second want");
}

/// fw3: three links F2 closed park handoff at F2 for an hour; plain
/// custody's strikes and parks stay empty.
#[test]
fn fw3_three_closed_links_park_handoff_at_the_next_hop_only() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let (w, s1) = forwarded(0x93);
    let f2 = w.keys[F2];
    w.net.closing.lock().unwrap().insert(hex::encode(f2));
    let (t0, wall) = (Instant::now(), now());
    let minute = Duration::from_secs(60);
    for i in 0..3u32 {
        let at = t0 + minute * i;
        lock_of(&s1).network_changed(at);
        assert_eq!(w.forward(F1, &s1, at, wall).dials, 1, "{i}");
    }
    let last = t0 + minute * 2;
    let s = lock_of(&s1);
    assert!(s.handoff_parked(&f2, None, last));
    assert!(!s.handoff_parked(&f2, None, last + PARK_HOUR));
    assert_eq!(s.handoff_parked[&f2].1, "CUSTODY_HANDOFF_UNSUPPORTED");
    assert!(s.strikes.is_empty() && s.parked.is_empty());
    drop(s);
    lock_of(&s1).network_changed(last);
    assert_eq!(w.forward(F1, &s1, last, wall).dials, 0, "parked");
    assert_eq!(w.forward_rows(F1, wall).len(), 1, "the row waits");
}

/// fw5: the handoff gate closed: no dial and no file, even with rows.
#[test]
fn fw5_gate_closed_means_no_dial_and_no_file() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0x94);
    set_handoff_gate_for_this_thread(Some(false));
    let shared = Mutex::default();
    assert_eq!(
        w.forward(F2, &shared, Instant::now(), now()),
        ForwardPass::default()
    );
    assert!(!w
        .dir(F2)
        .join(raven_core::custody_handoff::HANDOFF_DB_FILE)
        .exists());
    set_handoff_gate_for_this_thread(Some(true));
    let (w, s1) = forwarded(0x95);
    set_handoff_gate_for_this_thread(Some(false));
    assert_eq!(w.forward(F1, &s1, Instant::now(), now()).dials, 0);
    assert!(w
        .net
        .log
        .lock()
        .unwrap()
        .iter()
        .all(|(dir, _, _)| dir != w.dir(F1)));
}

/// fw6: Alice unpinned at F1 since her FORWARD: the row is dropped, not
/// sent.
#[test]
fn fw6_a_depositor_unpinned_since_has_its_row_dropped() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let (w, s1) = forwarded(0x96);
    write_contacts(w.dir(F1), &[contact(&w.keys[F2], lan_of(F2), &[])]);
    let pass = w.forward(F1, &s1, Instant::now(), now());
    assert_eq!((pass.dials, pass.dropped, pass.kept), (0, 1, 0));
    assert_eq!(w.handoff_usage(F1).pending, 0);
    assert!(w.ops(F1, F2).is_empty());
}

/// fw8, review handoff-2: F1's contact book is held (raven-node's start in a
/// profile it seals, until the key is loaded) or its block list is
/// corrupt: every contact would read as gone, so the forwarder drops no row
/// and sends none, and looks again after its interval. Readable again, the
/// row goes on.
#[test]
fn fw8_an_unreadable_book_drops_and_sends_nothing() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let (w, s1) = forwarded(0x0b);
    let f1 = w.dir(F1).to_path_buf();
    let t0 = Instant::now();
    lock_of(&s1).network_changed(t0);
    raven_core::contact_book::hold(&f1, "the at-rest key is loading");
    let pass = w.forward(F1, &s1, t0, now());
    assert_eq!((pass.dials, pass.dropped), (0, 0));
    assert_eq!(w.forward_rows(F1, now()).len(), 1, "the row waits");
    assert!(lock_of(&s1).forward_next.is_some_and(|t| t > t0));
    raven_core::contact_book::enable_process_cache(&f1);
    let blocked = raven_core::chat_history::blocked_path(&f1);
    std::fs::write(&blocked, b"{ not a block list").unwrap();
    let t1 = t0 + LATER;
    let pass = w.forward(F1, &s1, t1, now());
    assert_eq!((pass.dials, pass.dropped), (0, 0));
    assert_eq!(w.forward_rows(F1, now()).len(), 1, "the row waits");
    // Readable: sent (TAG_UNKNOWN: Bob has not registered yet), kept.
    std::fs::remove_file(&blocked).unwrap();
    let pass = w.forward(F1, &s1, t1 + LATER, now());
    assert_eq!((pass.dials, pass.dropped, pass.kept), (1, 0, 1));
}

/// An inbound HANDOFF kicks the forwarder: every row due now, its next look
/// now (the process-wide one; the gate on this thread).
#[test]
fn kick_forward_makes_the_forwarder_due() {
    let _g = Gates::on(true);
    kick_forward();
    let s = lock();
    assert!(s.forward_all);
    assert!(s.forward_next.is_some_and(|t| t <= Instant::now()));
}

// ── Registration (rg1-rg4) ─────────────────────────────────────────────────

/// rg1 (with rg3): the first pass registers Bob's tags at F2, once; a
/// registration close to its end is sent again; a contact that linked (a
/// new session) has its new tags registered at once at a custodian that is
/// not due, and only then.
#[test]
fn rg1_tags_are_registered_once_and_again_when_due() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0xa1);
    let (alice, f2) = (w.keys[A], w.keys[F2]);
    let sb = Mutex::default();
    let t0 = Instant::now();
    w.fetch(B, &sb, t0);
    assert_eq!(w.ops(B, F2).len(), 1);
    assert_eq!(w.ops(B, F2)[0][0], TAGS);
    // Yesterday (when the session is that old), today and tomorrow.
    assert!((2..=3).contains(&w.handoff_usage(F2).tags));
    w.fetch(B, &sb, t0 + LATER);
    assert!(!w.ops(B, F2)[1].contains(&TAGS));
    // Close to its end with a later expiry wanted: registered again.
    let soon = now() + 60_000;
    for held in lock_of(&sb)
        .states
        .get_mut(&f2)
        .unwrap()
        .0
        .registered
        .values_mut()
    {
        held.expiry = soon;
    }
    w.fetch(B, &sb, t0 + LATER * 2);
    assert_eq!(w.ops(B, F2)[2][0], TAGS);
    // rg3: new tags (a new session's) and F2 not due: nothing until Alice
    // links in.
    lock_of(&sb)
        .states
        .get_mut(&f2)
        .unwrap()
        .0
        .registered
        .clear();
    let t3 = t0 + LATER * 2 + Duration::from_secs(1);
    w.fetch(B, &sb, t3);
    assert_eq!(w.ops(B, F2).len(), 3, "not due");
    lock_of(&sb).seen_for_handoff(&alice, t3);
    w.fetch(B, &sb, t3);
    assert_eq!(w.ops(B, F2).len(), 4);
    assert_eq!(w.ops(B, F2)[3][0], TAGS);
}

/// rg2: F2 without the handoff ops (UNSUPPORTED) or with handoff off
/// (POLICY_DENIED): handoff parked there, no inbox, so the route hints carry
/// no HANDOFF_INBOX for it; the fetch itself goes on.
#[test]
fn rg2_unsupported_or_policy_denied_clears_the_inbox() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0xa2);
    let f2 = w.keys[F2];
    let sb = Mutex::default();
    let t0 = Instant::now();
    assert!(w.fetch(B, &sb, t0), "the inbox came");
    assert!(lock_of(&sb).inbox_ok(&f2, t0));
    handoff_policy(w.dir(F2), false);
    lock_of(&sb)
        .states
        .get_mut(&f2)
        .unwrap()
        .0
        .registered
        .clear();
    let t1 = t0 + LATER;
    assert!(w.fetch(B, &sb, t1), "and went");
    let s = lock_of(&sb);
    assert!(!s.inbox_ok(&f2, t1));
    assert!(s.handoff_parked(&f2, None, t1));
    assert_eq!(
        s.handoff_parked[&f2].1,
        CustodyCode::PolicyDenied.registry()
    );
    assert!(!s.parked.contains_key(&f2), "plain custody stays");
    drop(s);
    // Parked (for an hour): the next pass sends no TAGS, the FETCH still
    // goes.
    w.fetch(B, &sb, t1 + Duration::from_secs(120));
    let last = w.ops(B, F2).last().unwrap().clone();
    assert!(
        !last.contains(&TAGS) && !last.is_empty(),
        "{:?}",
        w.ops(B, F2)
    );

    // UNSUPPORTED: parked for a day, the capability cache knows it too.
    let w = World::new(0xa3);
    let f2 = w.keys[F2];
    set_lab_base_ops_only_for_this_thread(Some(true));
    let sb = Mutex::default();
    assert!(!w.fetch(B, &sb, t0), "never an inbox");
    let s = lock_of(&sb);
    assert_eq!(s.handoff_parked[&f2].1, "CUSTODY_HANDOFF_UNSUPPORTED");
    assert!(s.handoff_parked(&f2, None, t0 + LATER * 23));
    assert!(!s.inbox_ok(&f2, t0));
    assert_eq!(crate::letters::handoff_supported(&f2, now()), Some(false));
}

/// rg5, review handoff-1: F2 no longer takes Bob (it unpinned him: its
/// FETCH answers NOT_VERIFIED, and no TAGS frame is due): F2's
/// HANDOFF_INBOX ends at once. (Bob's own record of what he registered
/// there kept it fresh for a day, so Alice went on forwarding to a friend
/// that turns Bob away.)
#[test]
fn rg5_a_refused_fetch_ends_the_inbox_at_once() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let w = World::new(0x16);
    let f2 = w.keys[F2];
    let sb = Mutex::default();
    let t0 = Instant::now();
    assert!(w.fetch(B, &sb, t0), "the inbox came");
    write_contacts(w.dir(F2), &[contact(&w.keys[F1], lan_of(F1), &[])]);
    let t1 = t0 + LATER;
    assert!(w.fetch(B, &sb, t1), "and went");
    let last = w.ops(B, F2).last().unwrap().clone();
    assert!(!last.contains(&TAGS) && last.contains(&FETCH), "{last:?}");
    assert!(!lock_of(&sb).inbox_ok(&f2, t1));
}

/// rg6, review handoff-1: F2 lost Bob's registrations (custody turned off
/// and on with --purge): nothing tells Bob (FETCH works by tag), and F1's
/// DELIVER of Alice's message gets TAG_UNKNOWN. Once F2's OK for them is
/// 6 h old Bob registers his tags again, and F1 hands the row on. (They
/// were registered again only near their own expiry: up to two days.)
#[test]
fn rg6_lost_registrations_are_registered_again_within_six_hours() {
    if !lab_backends() {
        return;
    }
    let _g = Gates::on(true);
    let (w, s1) = forwarded(0x1b);
    let sb = Mutex::default();
    let t0 = Instant::now();
    w.fetch(B, &sb, t0);
    assert!(w.handoff_usage(F2).tags >= 2);
    HandoffStore::open_existing(w.dir(F2))
        .unwrap()
        .unwrap()
        .purge()
        .unwrap();
    assert_eq!(w.handoff_usage(F2).tags, 0);
    // Bob's next pass: F2 confirmed his tags just now, none is sent.
    w.fetch(B, &sb, t0 + LATER);
    assert!(!w.ops(B, F2).last().unwrap().contains(&TAGS));
    let pass = w.forward(F1, &s1, t0, now());
    assert_eq!(
        (pass.dials, pass.handed, pass.kept),
        (1, 0, 1),
        "TAG_UNKNOWN"
    );
    // Seven hours on (Bob's wall clock): all his tags again (one day's new
    // tag alone, should the day have turned meanwhile, would be one).
    w.fetch_at(B, &sb, t0 + LATER * 2, now() + 7 * HOUR_MS);
    let last = w.ops(B, F2).last().unwrap().clone();
    assert!(last.contains(&TAGS), "{:?}", w.ops(B, F2));
    assert!(w.handoff_usage(F2).tags >= 2);
    // F1's row (a trigger makes it due at once) now reaches Bob's friend.
    let t1 = t0 + LATER;
    lock_of(&s1).network_changed(t1);
    let pass = w.forward(F1, &s1, t1, now());
    assert_eq!((pass.dials, pass.handed, pass.kept), (1, 1, 0));
    assert_eq!(w.objects_at(F2), 1);
}

/// rg2/rg4 on the bookkeeping alone: every TAGS frame answered OK makes the
/// inbox fresh, and only that keeps it fresh (review handoff-1: a round
/// that only fetched, from a custodian that may hold none of the tags any
/// more, no longer does; the tags go again every 6 h); a refused round
/// (the FETCH answered POLICY_DENIED, HOLD or NOT_VERIFIED) ends it at
/// once; TAGS POLICY_DENIED / HOLD park for an hour, UNSUPPORTED for a
/// day; conflicts are counted (a counts-only line) and change nothing else.
#[test]
fn rg4_registration_answers_and_conflicts() {
    use raven_core::custody_client::FetchReport;
    let mut s = Shared::default();
    let (c, t0) = ([0xC9; 32], Instant::now());
    let ok = FetchReport {
        tags_ok: true,
        ..Default::default()
    };
    assert!(note_registration(&mut s, &c, &ok, t0), "came");
    assert!(!note_registration(&mut s, &c, &ok, t0), "no change");
    // Answering with nothing to register: fresh still, but no fresher.
    let t1 = t0 + Duration::from_secs(20 * 3_600);
    let quiet = FetchReport::default();
    assert!(!note_registration(&mut s, &c, &quiet, t1));
    assert!(s.inbox_ok(&c, t1));
    // It ages out 24 h after the last TAGS OK, whatever answered since.
    let t2 = t0 + INBOX_FRESH;
    assert!(!s.inbox_ok(&c, t2), "kept fresh by a round without TAGS");
    assert!(!note_registration(&mut s, &c, &quiet, t2));
    // Conflicts: counted, the inbox follows the codes only.
    let conflicts = FetchReport {
        tags_ok: true,
        tag_conflicts: 2,
        ..Default::default()
    };
    assert!(note_registration(&mut s, &c, &conflicts, t2));
    // The FETCH refused (custody off there, this node no longer verified,
    // its link gate closed): the inbox ends now, and handoff is not parked
    // (the plain park follows the FETCH's code).
    for code in [
        CustodyCode::PolicyDenied,
        CustodyCode::Hold,
        CustodyCode::NotVerified,
    ] {
        let mut s = Shared::default();
        s.inbox_ok.insert(c, t0);
        let refused = FetchReport {
            custodian_code: Some(code),
            ..Default::default()
        };
        assert!(note_registration(&mut s, &c, &refused, t0), "{code:?}");
        assert!(!s.inbox_ok(&c, t0));
        assert!(!s.handoff_parked(&c, None, t0));
    }
    for (code, for_) in [
        (CustodyCode::PolicyDenied, PARK_HOUR),
        (CustodyCode::Hold, PARK_HOUR),
    ] {
        let mut s = Shared::default();
        s.inbox_ok.insert(c, t0);
        let refused = FetchReport {
            tags_code: Some(code),
            ..Default::default()
        };
        assert!(note_registration(&mut s, &c, &refused, t0));
        assert!(s.handoff_parked(&c, None, t0 + for_ - Duration::from_secs(1)));
        assert!(!s.handoff_parked(&c, None, t0 + for_));
    }
    let mut s = Shared::default();
    let unsupported = FetchReport {
        tags_unsupported: true,
        ..Default::default()
    };
    assert!(!note_registration(&mut s, &c, &unsupported, t0));
    assert!(s.handoff_parked(&c, None, t0 + PARK_DAY - Duration::from_secs(1)));
    // A RATE_LIMITED answer parks nothing and keeps the inbox.
    s.handoff_parked.clear();
    s.inbox_ok.insert(c, t0);
    let busy = FetchReport {
        tags_code: Some(CustodyCode::RateLimited),
        ..Default::default()
    };
    assert!(!note_registration(&mut s, &c, &busy, t0));
    assert!(!s.handoff_parked(&c, None, t0));
    assert!(s.inbox_ok(&c, t0));
}

/// The handoff parks and strikes stay apart from plain custody's; a plain
/// park of the whole custodian holds handoffs, a plain pair park does not;
/// the TAG_UNKNOWN delay doubles from 60 s to 10 min within ±50 %.
#[test]
fn handoff_parks_and_delays() {
    let _g = Gates::on(true);
    let mut s = Shared::default();
    let (c, h, p, t0) = ([0xCA; 32], [0xCB; 32], [0xCC; 32], Instant::now());
    assert!(!s.handoff_parked(&c, Some(&h), t0));
    s.park_for_code(&c, &p, CustodyCode::RecipientNotAccepted, t0);
    assert!(!s.handoff_parked(&c, Some(&h), t0), "a plain pair park");
    s.park_for_code(&c, &p, CustodyCode::Hold, t0);
    assert!(
        s.handoff_parked(&c, None, t0),
        "a plain park of the custodian"
    );
    let mut s = Shared::default();
    s.park_handoff_pair(&c, &h, PARK_DAY, t0);
    assert!(s.handoff_parked(&c, Some(&h), t0));
    assert!(!s.handoff_parked(&c, None, t0));
    assert!(!s.handoff_parked(&c, Some(&p), t0));
    assert!(s.parked(&c, None, t0).is_none(), "plain custody untouched");
    for _ in 0..2 {
        assert!(!s.strike_handoff(&c, t0));
    }
    assert!(s.strike_handoff(&c, t0));
    assert!(s.handoff_parked(&c, None, t0));
    assert!(s.strikes.is_empty() && s.parked.is_empty());
    // A kick clears plain parks, not handoff ones, and makes rows due.
    s.kick(t0);
    assert!(s.handoff_parked(&c, None, t0));
    assert!(s.forward_all && s.forward_next == Some(t0));
    for (attempts, (lo, hi)) in [
        (0u32, (30, 90)),
        (1, (60, 180)),
        (2, (120, 360)),
        (4, (300, 600)),
        (9, (300, 600)),
    ] {
        let low = tag_unknown_delay(attempts, 0.0);
        let high = tag_unknown_delay(attempts, 1.0);
        assert_eq!(
            (low, high),
            (Duration::from_secs(lo), Duration::from_secs(hi)),
            "{attempts}"
        );
    }
    assert_eq!(tag_unknown_delay(0, 0.5), TAG_UNKNOWN_FIRST);
}

/// The forwarder's next look counts in the fetcher's sleep: due at once
/// after a kick, at most the interval while rows wait. With the handoff gate
/// closed a kick or a network change schedules no look (no forward pass
/// would take it: the fetcher would wake every 200 ms).
#[test]
fn next_wait_counts_the_forwarder() {
    let t0 = Instant::now();
    {
        let _g = Gates::on(false);
        let mut s = Shared::default();
        s.kick(t0);
        s.network_changed(t0);
        assert_eq!(s.forward_next, None);
        assert_eq!(s.next_wait(t0, BASE_INTERVAL), BASE_INTERVAL);
    }
    let _g = Gates::on(true);
    let mut s = Shared::default();
    assert_eq!(s.next_wait(t0, BASE_INTERVAL), BASE_INTERVAL);
    s.forward_next = Some(t0 + Duration::from_secs(5));
    assert_eq!(s.next_wait(t0, BASE_INTERVAL), Duration::from_secs(5));
    s.forward_everything(t0);
    assert_eq!(s.next_wait(t0, BASE_INTERVAL), Duration::from_millis(200));
}
