//! The worker's letter step, direct completion and the fetcher's letter
//! round (P5.15) over real profile folders: Alice (this node) and Bob, who
//! met once (a direct session and each other's bundle), and Carol (and
//! Dave), friends both list as custodians, every frame to their real
//! handlers. The gates open through this thread's debug overrides, which
//! release builds ignore: these tests return early there.

use super::*;
use crate::outbox::test_rig::{lab_backends, lan, pair, test_ctx};
use crate::outbox::{attempt_peer, scan_store, Dialer};
use raven_core::async_letter::{seal, Ral1Kind, SealInput};
use raven_core::custody_gate::{
    set_carrier_gates_for_this_thread, set_custody_gates_for_this_thread, CustodyGates,
};
use raven_core::device_cert::ensure_local_device_certificate;
use raven_core::envelope::Envelope;
use raven_core::friend_custody::{
    set_lab_base_ops_only_for_this_thread, CustodyStore, InboundLink,
};
use raven_core::horizon::{set_lab_horizon_for_this_thread, set_lab_letter_for_this_thread};
use raven_core::indexed_session_store::AuthorizedEndpointDevice;
use raven_core::lan_dispatch::{cache_peer_bundle, dispatch_frame_on, local_bundle};
use raven_core::outbox::{object_route_records, record_object_routes, CarrierChoice, CarrierGates};
use raven_core::owed_acks::OwedAcks;
use raven_core::pair_init::{decode_init, prekey_bundle_hash};
use raven_core::paths::PRIMARY_DEVICE_ID;
use raven_core::{classify_packed_envelope, LanBundle, PairInitOobClassify};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub(crate) const DAY: u64 = 24 * 60 * 60 * 1000;

fn now() -> u64 {
    raven_core::clock::now_ms()
}

/// The letter gate open on this thread (custody live, the horizon and
/// letter switches, LAN for custody routes); closed again on drop.
pub(crate) struct LettersOn {
    _lan: crate::lan_direct::LanSwitchUntouched,
}

impl LettersOn {
    pub(crate) fn new() -> Self {
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        set_carrier_gates_for_this_thread(Some(CarrierGates {
            lan: true,
            internet: false,
            p2p: false,
            nearby: false,
            onion: false,
        }));
        set_lab_horizon_for_this_thread(Some(true));
        set_lab_letter_for_this_thread(Some(true));
        Self {
            _lan: crate::lan_direct::lan_switch_untouched(),
        }
    }
}

impl Drop for LettersOn {
    fn drop(&mut self) {
        set_lab_letter_for_this_thread(None);
        set_lab_horizon_for_this_thread(None);
        set_carrier_gates_for_this_thread(None);
        set_custody_gates_for_this_thread(None);
        set_lab_base_ops_only_for_this_thread(None);
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
/// (Bob only while he is up) and hands every frame to its real dispatcher,
/// as the caller whose data dir dials.
pub(crate) struct LetterNet {
    nodes: Vec<Node>,
    callers: Vec<Caller>,
    bob_hex: String,
    pub(crate) bob_down: AtomicBool,
    /// Bob answers a letter session's PairInit with nothing (an older peer,
    /// a rotated bundle); a link PairInit he answers.
    pub(crate) old_bob: AtomicBool,
    /// (the data dir whose send lock is checked, its peer) per dial.
    pub(crate) lock_probe: Mutex<Option<(PathBuf, [u8; 32])>>,
    pub(crate) probed: AtomicUsize,
    pub(crate) held_dials: AtomicUsize,
    /// (the node dialled, its RFC1 request ops) per dial.
    pub(crate) log: Mutex<Vec<(String, Vec<u8>)>>,
}

/// A PairInit of a letter session (longer than a link's 24 h).
fn is_letter_pair_init(frame: &[u8]) -> bool {
    match classify_packed_envelope(frame) {
        PairInitOobClassify::PairInit(wire) => {
            decode_init(&wire).is_ok_and(|init| init.expires_at_ms - init.created_at_ms > DAY)
        }
        _ => false,
    }
}

impl Dialer for LetterNet {
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
        self.log.lock().unwrap().push((expected.to_string(), ops));
        if expected == self.bob_hex && self.bob_down.load(Ordering::SeqCst) {
            return Err("lan connect: cannot connect (Connection refused)".into());
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
            if expected == self.bob_hex
                && self.old_bob.load(Ordering::SeqCst)
                && is_letter_pair_init(frame)
            {
                continue;
            }
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

/// Alice, Bob, Carol (and Dave): see the module.
pub(crate) struct World {
    pub(crate) a: tempfile::TempDir,
    pub(crate) b: tempfile::TempDir,
    pub(crate) c: tempfile::TempDir,
    pub(crate) d: tempfile::TempDir,
    pub(crate) alice: Arc<Identity>,
    pub(crate) bob: Arc<Identity>,
    pub(crate) alice_pub: [u8; 32],
    pub(crate) bob_pub: [u8; 32],
    pub(crate) carol_pub: [u8; 32],
    pub(crate) dave_pub: [u8; 32],
    pub(crate) a_bundle: LanBundle,
    pub(crate) b_bundle: LanBundle,
    /// Alice's direct session with Bob (`None`: they never paired).
    pub(crate) key: Option<IndexedSessionRecordKey>,
    pub(crate) net: Arc<LetterNet>,
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

impl World {
    /// The world; both Carol and Dave are custodians when `dave`, Carol
    /// alone otherwise; Alice and Bob share a direct session when
    /// `paired`.
    pub(crate) fn new(seed: u8, dave: bool, paired: bool) -> Self {
        let id = |n: u8| Identity::from_seed(&[seed.wrapping_add(n); 32]);
        let (alice, bob, carol, dave_id) = (id(0), id(1), id(2), id(3));
        let dirs: Vec<tempfile::TempDir> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
        for (dir, who) in dirs.iter().zip([&alice, &bob, &carol, &dave_id]) {
            ensure_local_device_certificate(dir.path(), who, PRIMARY_DEVICE_ID).unwrap();
            raven_core::ensure_local_prekey(dir.path(), who).unwrap();
        }
        let mut dirs = dirs.into_iter();
        let (a, b, c, d) = (
            dirs.next().unwrap(),
            dirs.next().unwrap(),
            dirs.next().unwrap(),
            dirs.next().unwrap(),
        );
        let (alice_pub, bob_pub) = (alice.public_key_bytes(), bob.public_key_bytes());
        let (carol_pub, dave_pub) = (carol.public_key_bytes(), dave_id.public_key_bytes());
        let custodians: Vec<[u8; 32]> = if dave {
            vec![carol_pub, dave_pub]
        } else {
            vec![carol_pub]
        };
        let friends = |rows: &mut Vec<serde_json::Value>| {
            rows.push(contact(&carol_pub, "192.168.1.50:7420", &[]));
            rows.push(contact(&dave_pub, "192.168.1.51:7420", &[]));
        };
        let mut rows = vec![contact(&bob_pub, "127.0.0.1:9", &custodians)];
        friends(&mut rows);
        write_contacts(a.path(), &rows);
        let mut rows = vec![contact(&alice_pub, "127.0.0.1:8", &custodians)];
        friends(&mut rows);
        write_contacts(b.path(), &rows);
        for dir in [c.path(), d.path()] {
            write_contacts(
                dir,
                &[contact(&alice_pub, "", &[]), contact(&bob_pub, "", &[])],
            );
            raven_core::save_policy(
                dir,
                &raven_core::NodePolicy {
                    custody: true,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        let a_bundle = local_bundle(a.path(), &alice).unwrap();
        let b_bundle = local_bundle(b.path(), &bob).unwrap();
        cache_peer_bundle(a.path(), &b_bundle).unwrap();
        cache_peer_bundle(b.path(), &a_bundle).unwrap();
        let key = paired.then(|| pair(a.path(), &alice, b.path(), &bob, &a_bundle, &b_bundle));
        let net = Arc::new(LetterNet {
            nodes: vec![
                Node {
                    hex: hex::encode(bob_pub),
                    dir: b.path().to_path_buf(),
                    id: Identity::from_seed(&[seed.wrapping_add(1); 32]),
                },
                Node {
                    hex: hex::encode(carol_pub),
                    dir: c.path().to_path_buf(),
                    id: carol,
                },
                Node {
                    hex: hex::encode(dave_pub),
                    dir: d.path().to_path_buf(),
                    id: dave_id,
                },
            ],
            callers: vec![
                Caller {
                    dir: a.path().to_path_buf(),
                    bundle: a_bundle.clone(),
                    key: alice_pub,
                },
                Caller {
                    dir: b.path().to_path_buf(),
                    bundle: b_bundle.clone(),
                    key: bob_pub,
                },
            ],
            bob_hex: hex::encode(bob_pub),
            bob_down: AtomicBool::new(true),
            old_bob: AtomicBool::new(false),
            lock_probe: Mutex::new(None),
            probed: AtomicUsize::new(0),
            held_dials: AtomicUsize::new(0),
            log: Mutex::new(Vec::new()),
        });
        Self {
            a,
            b,
            c,
            d,
            alice: Arc::new(alice),
            bob: Arc::new(bob),
            alice_pub,
            bob_pub,
            carol_pub,
            dave_pub,
            a_bundle,
            b_bundle,
            key,
            net,
        }
    }

    pub(crate) fn ctx(&self) -> AttemptCtx {
        test_ctx(self.a.path(), Arc::clone(&self.alice), self.net.clone())
    }

    fn bob_ctx(&self) -> AttemptCtx {
        test_ctx(self.b.path(), Arc::clone(&self.bob), self.net.clone())
    }

    /// Every custodian serves letters, as the cache believes now.
    pub(crate) fn letters_known(&self) {
        for c in [self.carol_pub, self.dave_pub] {
            note_letters(&c, true, now());
        }
    }

    /// `raven send` while Bob is down, two minutes ago (the direct path had
    /// its chance): staged in the direct session (history `queued`), handed
    /// to the outbox queue, its route record allowing custody.
    pub(crate) fn stage(&self, text: &str) -> [u8; 16] {
        self.stage_at(text, now() - 120_000)
    }

    /// [`Self::stage`] written at `created` (Raven's clock).
    pub(crate) fn stage_at(&self, text: &str, created: u64) -> [u8; 16] {
        let key = self.key.clone().expect("a direct session");
        let (cert, registry) =
            ensure_local_device_certificate(self.a.path(), &self.alice, PRIMARY_DEVICE_ID).unwrap();
        let device =
            AuthorizedEndpointDevice::authorize(&cert, &self.alice, &registry, created).unwrap();
        let mut store = IndexedSessionStore::open(self.a.path()).unwrap();
        let session = store.session_id_for_record_key(&key).unwrap();
        let end = store.session_expires_at(&key).unwrap();
        let mut staged = None;
        let (a_dir, bob) = (self.a.path().to_path_buf(), self.bob_pub);
        store
            .send_message_envelope(
                &key,
                text,
                &device,
                created,
                (created + DAY).min(end),
                created,
                &mut rand::rngs::OsRng,
                &mut |digest: &[u8; 32], bytes: &[u8]| {
                    let env = Envelope::unpack(bytes).unwrap();
                    raven_core::ensure_outbound_queued_history(
                        &a_dir,
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
            self.a.path(),
            &mid,
            &self.bob_pub,
            CarrierChoice::Auto,
            &[lan("127.0.0.1:9")],
            now() + DAY,
            now(),
        )
        .unwrap();
        raven_core::outbox::set_object_custody(self.a.path(), &mid, now()).unwrap();
        mid
    }

    pub(crate) fn due_of(dir: &Path) -> Vec<Entry> {
        let t = tokio::time::Instant::now();
        scan_store(dir)
            .unwrap()
            .iter()
            .map(|r| Entry::from_row(r, t))
            .collect()
    }

    /// One worker attempt of Alice's for Bob, over everything tracked.
    pub(crate) fn attempt(&self) -> PeerReport {
        attempt_peer(
            &self.ctx(),
            &self.bob_pub,
            &Self::due_of(self.a.path()),
            &[],
        )
    }

    /// One worker attempt of Bob's for Alice, with the ACKs he owes her.
    pub(crate) fn bob_attempt(&self) -> PeerReport {
        let (mut owed, _) = OwedAcks::open(self.b.path()).unwrap();
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
                        next_due: tokio::time::Instant::now(),
                        durable: true,
                        session_id: o.session_id,
                        held_by: o.held_by,
                        may_deposit: o.origin.may_deposit(),
                    },
                )
            })
            .collect();
        let due: Vec<Entry> = Self::due_of(self.b.path())
            .into_iter()
            .filter(|e| e.recipient == self.alice_pub)
            .collect();
        attempt_peer(&self.bob_ctx(), &self.alice_pub, &due, &acks)
    }

    /// A dial to `custodian` from `dir` through the net.
    fn dial_from<'a>(
        &'a self,
        dir: &'a Path,
        custodian: [u8; 32],
    ) -> impl FnMut(&[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> + 'a {
        move |frames: &[Vec<u8>]| {
            self.net.dial(
                dir,
                &lan("192.168.1.50:7420"),
                &hex::encode(custodian),
                frames,
            )
        }
    }

    /// Bob's (or Alice's) letter fetch at `custodian`, as the fetcher runs it.
    pub(crate) fn fetch(&self, bob: bool, custodian: [u8; 32]) -> LetterFetchReport {
        let (dir, who) = if bob {
            (self.b.path(), &self.bob)
        } else {
            (self.a.path(), &self.alice)
        };
        let mut dial = self.dial_from(dir, custodian);
        fetch_at(dir, who, &custodian, now(), 4, &mut dial).expect("the letter gate is open")
    }

    /// Letters `custodian` holds now.
    pub(crate) fn held_at(&self, custodian: [u8; 32]) -> i64 {
        let dir = if custodian == self.carol_pub {
            self.c.path()
        } else {
            self.d.path()
        };
        CustodyStore::open_existing(dir)
            .unwrap()
            .map_or(0, |s| s.letter_usage().unwrap().0)
    }

    /// Base-ops objects `custodian` holds now.
    pub(crate) fn objects_at(&self, custodian: [u8; 32]) -> i64 {
        let dir = if custodian == self.carol_pub {
            self.c.path()
        } else {
            self.d.path()
        };
        CustodyStore::open_existing(dir)
            .unwrap()
            .map_or(0, |s| s.usage().unwrap().0)
    }

    pub(crate) fn book(&self, bob: bool) -> LetterBook {
        let dir = if bob { self.b.path() } else { self.a.path() };
        letter_deposits::load(dir, now()).unwrap()
    }

    pub(crate) fn history(&self, mid: &[u8; 16]) -> Option<String> {
        raven_core::ChatHistory::load(self.a.path())
            .unwrap()
            .entries
            .into_iter()
            .find(|e| e.direction == "out" && e.message_id_hex == hex::encode(mid))
            .map(|e| e.delivery)
    }

    pub(crate) fn bob_inbox(&self) -> Vec<String> {
        IndexedSessionStore::open(self.b.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .into_iter()
            .map(|r| String::from_utf8_lossy(&r.plaintext).into_owned())
            .collect()
    }

    pub(crate) fn alice_inbox(&self) -> Vec<String> {
        IndexedSessionStore::open(self.a.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .into_iter()
            .map(|r| String::from_utf8_lossy(&r.plaintext).into_owned())
            .collect()
    }

    /// The sessions holding a copy of `mid` to Bob, with whether each is a
    /// letter session Alice started.
    fn copies(&self, mid: &[u8; 16]) -> Vec<([u8; 32], bool)> {
        let store = IndexedSessionStore::open(self.a.path()).unwrap();
        store
            .message_copies_for_recipient(&self.bob_pub, mid)
            .unwrap()
            .into_iter()
            .filter(|c| c.has_outbox_row)
            .map(|c| {
                let letter =
                    store.letter_role(&c.session_id).unwrap() == Some(LetterRole::Initiator);
                (c.session_id, letter)
            })
            .collect()
    }

    /// A letter Bob seals for Alice in a new letter session of his, with
    /// one message, left with `custodian` (they never paired).
    pub(crate) fn bob_letter_for_alice(&self, text: &str, custodian: [u8; 32]) {
        let b = self.b.path();
        let (init, key) =
            raven_core::lan_dispatch::create_letter_pair_init(b, &self.bob, &self.a_bundle)
                .unwrap();
        let (cert, registry) =
            ensure_local_device_certificate(b, &self.bob, PRIMARY_DEVICE_ID).unwrap();
        let t = now();
        let device = AuthorizedEndpointDevice::authorize(&cert, &self.bob, &registry, t).unwrap();
        let mut store = IndexedSessionStore::open(b).unwrap();
        let mut packed = None;
        store
            .send_message_envelope(
                &key,
                text,
                &device,
                t,
                t + 2 * DAY,
                t,
                &mut rand::rngs::OsRng,
                &mut |d: &[u8; 32], bytes: &[u8]| {
                    packed = Some(bytes.to_vec());
                    Ok(*d)
                },
            )
            .unwrap();
        let inner =
            raven_core::async_letter::encode_letter_inner(&raven_core::async_letter::LetterInner {
                pair_init: raven_core::pair_init::encode_init(&init).unwrap(),
                envelopes: vec![packed.unwrap()],
            })
            .unwrap();
        let letter = seal_to(&self.bob, &self.a_bundle, &inner, t, t + 2 * DAY);
        self.leave(b, custodian, &self.alice_pub, vec![letter]);
    }

    /// Leave `letters` for `recipient` with `custodian`, from `dir`.
    pub(crate) fn leave(
        &self,
        dir: &Path,
        custodian: [u8; 32],
        recipient: &[u8; 32],
        letters: Vec<Vec<u8>>,
    ) {
        let items: Vec<raven_core::custody_client::LetterDeposit> = letters
            .into_iter()
            .map(|letter| raven_core::custody_client::LetterDeposit {
                recipient: *recipient,
                letter,
            })
            .collect();
        let mut dial = self.dial_from(dir, custodian);
        let mut caps = CapabilityCache::default();
        for chunk in items.chunks(16) {
            let answers = deposit_letters(&custodian, chunk, &mut caps, now(), &mut dial).unwrap();
            assert!(answers.iter().all(|a| a.is_some_and(LetterAnswer::held)));
        }
    }

    /// `custodian` full for letters from Alice to Bob (its per-pair cap):
    /// letters Alice sealed to nothing in particular.
    fn fill(&self, custodian: [u8; 32]) {
        let t = now();
        let letters = (0..raven_core::friend_custody::MAX_PAIR_LETTERS)
            .map(|_| seal_to(&self.alice, &self.b_bundle, &[0u8; 512], t, t + DAY))
            .collect();
        self.leave(self.a.path(), custodian, &self.bob_pub, letters);
    }
}

/// `inner` sealed and signed by `from` to `to`'s signed prekey.
fn seal_to(from: &Identity, to: &LanBundle, inner: &[u8], created: u64, expires: u64) -> Vec<u8> {
    use rand::RngCore;
    let (mut eph, mut letter_id) = ([0u8; 32], [0u8; 16]);
    rand::rngs::OsRng.fill_bytes(&mut eph);
    rand::rngs::OsRng.fill_bytes(&mut letter_id);
    seal(
        from,
        &eph,
        &SealInput {
            kind: Ral1Kind::Letter,
            letter_id,
            recipient_device: to.cert.device_ed_pub,
            created_at_ms: created,
            expires_at_ms: expires,
            wrap_bundle_hash: prekey_bundle_hash(&to.prekey).unwrap(),
            recipient_signed_prekey: to.prekey.x25519_pub,
            inner,
        },
    )
    .unwrap()
}

fn only(report: &PeerReport) -> Outcome {
    assert_eq!(report.outcomes.len(), 1, "{:?}", report.outcomes);
    report.outcomes.values().next().unwrap().clone()
}

/// A message the direct path could not carry moves into a letter session
/// once: its direct copy goes, its new copy is sealed into a letter that
/// Carol (who serves letters) now holds, recorded in the book and in the
/// route record ("left with Carol"). The next attempt moves nothing again:
/// the copy waits for its letter (in custody), one letter at Carol. Bob's
/// fetch takes it.
#[test]
fn letter_deposit_moves_message_once_and_records_custodians() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x51, false, true);
    w.letters_known();
    let mid = w.stage("by letter");
    let direct = w.copies(&mid);
    assert_eq!(direct.len(), 1);
    assert!(!direct[0].1, "the copy is in the direct session");
    let report = w.attempt();
    assert_eq!(only(&report), Outcome::Resealed);
    assert!(report.rescan);
    let copies = w.copies(&mid);
    assert_eq!(copies.len(), 1, "moved, not copied: {copies:?}");
    assert!(copies[0].1, "now in a letter session");
    let book = w.book(false);
    assert_eq!(book.letters.len(), 1);
    let row = &book.letters[0];
    assert_eq!(
        (row.kind, row.message_ids.clone(), row.held_by.clone()),
        (DepositKind::Letter, vec![mid], vec![w.carol_pub])
    );
    let records = object_route_records(w.a.path(), now()).unwrap();
    assert_eq!(
        records[&mid].custodians_held,
        vec![hex::encode(w.carol_pub)]
    );
    assert_eq!(w.held_at(w.carol_pub), 1);
    assert_eq!(w.objects_at(w.carol_pub), 0, "no base deposit");
    // The letter copy waits for its letter: nothing moves or is left again.
    let report = w.attempt();
    assert_eq!(only(&report), Outcome::Deposited { held: 1 });
    assert_eq!(w.book(false).letters.len(), 1);
    assert_eq!(w.held_at(w.carol_pub), 1);
    assert_eq!(w.history(&mid).as_deref(), Some("queued"));
    // Bob takes it from Carol.
    let fetched = w.fetch(true, w.carol_pub);
    assert_eq!((fetched.letters, fetched.accepted), (1, 1));
    assert_eq!(w.bob_inbox(), vec!["by letter".to_string()]);
}

/// A custodian with the base ops only (an older build): the fetcher's
/// FETCH_LETTERS learns it, and the worker leaves the message with it as
/// before, moving nothing (no letter session, no letter).
#[test]
fn old_custodian_falls_back_without_move() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    set_lab_base_ops_only_for_this_thread(Some(true));
    let w = World::new(0x55, false, true);
    let mid = w.stage("by the base deposit");
    let report = w.fetch(false, w.carol_pub);
    assert!(report.unsupported);
    assert_eq!(letters_supported(&w.carol_pub, now()), Some(false));
    let report = w.attempt();
    assert_eq!(only(&report), Outcome::Deposited { held: 1 });
    assert_eq!(w.objects_at(w.carol_pub), 1);
    assert_eq!(w.held_at(w.carol_pub), 0);
    assert!(w.book(false).letters.is_empty());
    let copies = w.copies(&mid);
    assert_eq!(copies.len(), 1);
    assert!(!copies[0].1, "still in the direct session");
}

/// Bob turns out to be reachable while the message waits in its letter:
/// the letter session's exact PairInit is replayed, his PairResponse
/// confirms it, and the message goes out in the same attempt and is
/// delivered once. The letter is then withdrawn from Carol.
#[test]
fn letter_session_completed_directly_via_pairinit_replay() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x59, false, true);
    w.letters_known();
    let mid = w.stage("completed directly");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    assert_eq!(w.held_at(w.carol_pub), 1);
    w.net.bob_down.store(false, Ordering::SeqCst);
    let report = w.attempt();
    assert!(
        matches!(only(&report), Outcome::Delivered { .. }),
        "{:?}",
        report.outcomes
    );
    assert_eq!(w.bob_inbox(), vec!["completed directly".to_string()]);
    assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
    // The next attempt withdraws the settled letter.
    w.attempt();
    assert_eq!(w.held_at(w.carol_pub), 0);
    assert!(w.book(false).letters.is_empty());
}

/// Bob is reachable but gives no PairResponse for the letter session (an
/// older peer, a rotated bundle): its copies are parked again and the
/// horizon's synchronous re-pair seals them into a new session at once; the
/// next attempt delivers. The letter session is given up and its letter
/// withdrawn.
#[test]
fn failed_direct_completion_falls_back_to_sync_reseal() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x5d, false, true);
    w.letters_known();
    let mid = w.stage("re-paired instead");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    w.net.bob_down.store(false, Ordering::SeqCst);
    w.net.old_bob.store(true, Ordering::SeqCst);
    let report = w.attempt();
    assert_eq!(only(&report), Outcome::Resealed, "{:?}", report.outcomes);
    assert!(report.rescan);
    let copies = w.copies(&mid);
    assert_eq!(copies.len(), 1);
    assert!(!copies[0].1, "re-sealed into a link session");
    let book = w.book(false);
    assert!(book.letters.iter().all(|row| row.withdraw));
    assert_eq!(book.abandoned.len(), 1);
    let report = w.attempt();
    assert!(
        report
            .outcomes
            .values()
            .any(|o| matches!(o, Outcome::Delivered { .. })),
        "{:?}",
        report.outcomes
    );
    assert_eq!(w.bob_inbox(), vec!["re-paired instead".to_string()]);
    assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
    assert_eq!(
        w.held_at(w.carol_pub),
        0,
        "the given-up letter was withdrawn"
    );
}

/// Bob takes the letter and owes its ACK on a letter session he accepted:
/// his worker leaves a REPLY letter (the kept PairResponse and the ACK)
/// with Carol, never the base deposit, and only once. Alice's fetch takes
/// it: her letter session is confirmed and the message delivered.
#[test]
fn reply_letter_built_for_owed_acks_of_letter_sessions() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x61, false, true);
    w.letters_known();
    let mid = w.stage("answered by letter");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    assert_eq!(w.fetch(true, w.carol_pub).accepted, 1);
    w.bob_attempt();
    let book = w.book(true);
    assert_eq!(book.letters.len(), 1);
    let reply = &book.letters[0];
    assert_eq!(
        (reply.kind, reply.acks.len(), reply.held_by.clone()),
        (DepositKind::Reply, 1, vec![w.carol_pub])
    );
    assert_eq!(w.objects_at(w.carol_pub), 0, "no base deposit of the ACK");
    // Not again.
    w.bob_attempt();
    assert_eq!(w.book(true).letters.len(), 1);
    let fetched = w.fetch(false, w.carol_pub);
    assert_eq!((fetched.replies, fetched.acks), (1, 1));
    assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
}

/// Alice's letter is left with Carol and Dave. Bob takes it from Carol
/// (released there) and his REPLY delivers the message; the copy Dave still
/// holds is then withdrawn and the letter forgotten: the fetcher withdraws
/// at the custodian the REPLY came from, the worker at the others.
#[test]
fn withdraw_after_delivery() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x65, true, true);
    w.letters_known();
    let mid = w.stage("withdrawn after");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    assert_eq!((w.held_at(w.carol_pub), w.held_at(w.dave_pub)), (1, 1));
    assert_eq!(w.fetch(true, w.carol_pub).accepted, 1);
    assert_eq!(w.held_at(w.carol_pub), 0, "Bob released it there");
    w.bob_attempt();
    let fetched = w.fetch(false, w.carol_pub);
    assert_eq!(fetched.replies, 1);
    assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
    // The fetcher's withdraw at Carol: nothing left there; Dave's copy waits
    // for the worker.
    let store = IndexedSessionStore::open(w.a.path()).unwrap();
    let mut dial = w.dial_from(w.a.path(), w.carol_pub);
    let withdrawn = withdraw_settled(
        w.a.path(),
        &store,
        &w.bob_pub,
        Some(&w.carol_pub),
        now(),
        &mut |_: &[u8; 32], frames: &[Vec<u8>]| dial(frames),
    );
    assert_eq!(withdrawn, 0);
    let book = w.book(false);
    assert_eq!(book.letters.len(), 1);
    assert_eq!(book.letters[0].held_by, vec![w.dave_pub]);
    assert!(book.letters[0].withdraw);
    // Dave holds Alice's letter and Bob's REPLY; the worker withdraws hers.
    assert_eq!(w.held_at(w.dave_pub), 2);
    w.attempt();
    assert!(w.book(false).letters.is_empty());
    assert_eq!(w.held_at(w.dave_pub), 1, "only Bob's REPLY is left there");
}

/// Every dial of the letter step (the deposit, the PairInit replay, the
/// withdraw) runs without the contact's send lock.
#[test]
fn send_lock_not_held_across_letter_dials() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x69, false, true);
    w.letters_known();
    w.stage("no lock across dials");
    *w.net.lock_probe.lock().unwrap() = Some((w.a.path().to_path_buf(), w.bob_pub));
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    w.net.bob_down.store(false, Ordering::SeqCst);
    assert!(matches!(only(&w.attempt()), Outcome::Delivered { .. }));
    w.attempt();
    assert_eq!(w.held_at(w.carol_pub), 0, "withdrawn");
    assert!(w.net.probed.load(Ordering::SeqCst) >= 4);
    assert_eq!(w.net.held_dials.load(Ordering::SeqCst), 0);
}

/// Carol and Dave are both full for Alice's letters to Bob (32 each): the
/// letter stays in the book unplaced, its message in the letter session
/// (nothing lost), the status says CARRIER_FULL, and placement waits an
/// hour before both are asked again.
#[test]
fn every_custodian_full_keeps_the_letter_and_retries() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x6d, true, true);
    w.letters_known();
    w.fill(w.carol_pub);
    w.fill(w.dave_pub);
    let mid = w.stage("kept while full");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    let book = w.book(false);
    assert_eq!(book.letters.len(), 1);
    let row = book.letters[0].clone();
    assert!(row.held_by.is_empty());
    assert_eq!(row.waiting_code(), Some(CARRIER_FULL));
    assert_eq!(row.refused.len(), 2);
    let copies = w.copies(&mid);
    assert!(
        copies.len() == 1 && copies[0].1,
        "kept in the letter session"
    );
    assert!(row.next_try_ms >= now() + 59 * 60 * 1000);
    let report = w.attempt();
    assert_eq!(only(&report), Outcome::Held(CARRIER_FULL));
    // No new offer before the hour is up ...
    let deposits = |w: &World| {
        w.net
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, ops)| ops.contains(&raven_core::friend_custody::OP_DEPOSIT_LETTER))
            .count()
    };
    let before = deposits(&w);
    let capable = vec![(w.carol_pub, None), (w.dave_pub, None)];
    let ctx = w.ctx();
    let mut dial_for =
        |c: &[u8; 32], o: Option<u8>, frames: &[Vec<u8>]| match worker_dial(&ctx, *c, o) {
            Some(mut dial) => dial(frames),
            None => Err("no route".into()),
        };
    place(
        w.a.path(),
        &w.bob_pub,
        &capable,
        now() + 30 * 60 * 1000,
        &mut dial_for,
    );
    assert_eq!(deposits(&w), before);
    // ... then both again, still full: two hours next.
    let later = row.next_try_ms;
    place(w.a.path(), &w.bob_pub, &capable, later, &mut dial_for);
    assert_eq!(deposits(&w), before + 2);
    let row = w.book(false).letters[0].clone();
    assert!(row.held_by.is_empty());
    assert_eq!(row.next_try_ms, later + 2 * 60 * 60 * 1000);
    assert_eq!(w.history(&mid).as_deref(), Some("queued"));
}

/// A letter Carol refused for space is offered again at once after Alice's
/// fetcher released a letter there (room was made meanwhile), not an hour
/// later.
#[test]
fn a_release_triggers_placement() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x71, false, true);
    w.letters_known();
    w.fill(w.carol_pub);
    w.stage("placed after a release");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    assert!(w.book(false).letters[0].held_by.is_empty());
    // Room at Carol: one of the filler letters is withdrawn.
    let filler = {
        let store = CustodyStore::open_existing(w.c.path()).unwrap().unwrap();
        let page = store.fetch_letters(&w.bob_pub, None, 1, now()).unwrap();
        raven_core::async_letter::letter_digest(&page.items[0])
    };
    let mut dial = w.dial_from(w.a.path(), w.carol_pub);
    let mut caps = CapabilityCache::default();
    withdraw_letters(&w.carol_pub, &[filler], &mut caps, now(), &mut dial).unwrap();
    // Bob left a letter for Alice there; Alice's fetch takes it and
    // releases it: placement is due at once.
    w.bob_letter_for_alice("from Bob", w.carol_pub);
    let fetched = w.fetch(false, w.carol_pub);
    assert!(fetched.released >= 1, "{fetched:?}");
    assert!(w.book(false).letters[0].next_try_ms <= now());
    let report = w.attempt();
    assert_eq!(only(&report), Outcome::Deposited { held: 1 });
    assert_eq!(w.book(false).letters[0].held_by, vec![w.carol_pub]);
}

/// Bob took the letter (his session is the letter's), but before his REPLY
/// reaches Alice he is reachable directly, after his cached PairResponse is
/// gone: the replay is answered with the PairResponse his letter row keeps,
/// the message goes out again and is delivered, once in his inbox.
#[test]
fn moved_messages_still_deliver_on_direct_return() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x75, false, true);
    w.letters_known();
    let mid = w.stage("delivered on return");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    assert_eq!(w.fetch(true, w.carol_pub).accepted, 1);
    let _ = std::fs::remove_dir_all(w.b.path().join("lan_pair_response"));
    w.net.bob_down.store(false, Ordering::SeqCst);
    let report = w.attempt();
    assert!(
        matches!(only(&report), Outcome::Delivered { .. }),
        "{:?}",
        report.outcomes
    );
    assert_eq!(w.bob_inbox(), vec!["delivered on return".to_string()]);
    assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
}

// ── Phase 5 review fixes (letters) ─────────────────────────────────────────

/// Review letters-1: an UNSUPPORTED is believed for 24 h from when the
/// custodian said it, however often the cache is read meanwhile (each fetch
/// pass reads it): it is not written back with a fresh time.
#[test]
fn an_unsupported_answer_lapses_a_day_after_it_was_given() {
    let c = [0xE7u8; 32];
    let t0 = 1_900_000_000_000u64;
    let ((), _) = with_caps(&c, t0, |caps| {
        caps.note(
            &c,
            raven_core::custody_client::CustodianCapability::Letters,
            false,
            t0,
        )
    });
    let mut t = t0;
    while t + 10 * 60 * 1000 < t0 + DAY {
        t += 10 * 60 * 1000;
        let ((), fresh) = with_caps(&c, t, |_| ());
        assert!(!fresh);
    }
    assert_eq!(letters_supported(&c, t0 + DAY - 1), Some(false));
    assert_eq!(letters_supported(&c, t0 + DAY), None, "lapsed");
    // A real answer is kept with its own time.
    let ((), fresh) = with_caps(&c, t0 + DAY, |caps| {
        caps.note(
            &c,
            raven_core::custody_client::CustodianCapability::Letters,
            true,
            t0 + DAY,
        )
    });
    assert!(fresh);
    assert_eq!(letters_supported(&c, t0 + 2 * DAY - 1), Some(true));
}

/// Review letters-1: Carol answered Alice's FETCH_LETTERS UNSUPPORTED (an
/// older build), then upgraded, and Bob left a letter for Alice there.
/// Alice's fetcher, running all along, makes no dial while the answer is
/// believed, and asks Carol again once it lapsed: Bob's letter is taken.
#[test]
fn an_upgraded_custodian_is_asked_again_after_a_day() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0xB1, false, false);
    let fetch = |at: u64| {
        let mut dial = w.dial_from(w.a.path(), w.carol_pub);
        fetch_at(w.a.path(), &w.alice, &w.carol_pub, at, 4, &mut dial).unwrap()
    };
    set_lab_base_ops_only_for_this_thread(Some(true));
    let t0 = now();
    assert!(fetch(t0).unsupported);
    set_lab_base_ops_only_for_this_thread(Some(false));
    w.bob_letter_for_alice("waits at Carol", w.carol_pub);
    // A fetch pass every 10 minutes for the rest of the day: no dial.
    let mut at = t0;
    while at + 10 * 60 * 1000 < t0 + DAY {
        at += 10 * 60 * 1000;
        assert_eq!(fetch(at).dials, 0);
    }
    assert_eq!(w.held_at(w.carol_pub), 1);
    let later = fetch(t0 + DAY + 60 * 60 * 1000);
    assert!(later.dials >= 1, "{later:?}");
    assert_eq!((later.letters, later.accepted), (1, 1), "{later:?}");
    assert_eq!(w.alice_inbox(), vec!["waits at Carol".to_string()]);
    assert_eq!(
        letters_supported(&w.carol_pub, t0 + DAY + 60 * 60 * 1000),
        Some(true)
    );
}

/// Review letters-2: Carol holds Alice's letter, then stops serving
/// letters (an older build). Once Alice learns it, Carol is no longer
/// listed as holding the letter and the message does not show it carried;
/// with no custodian serving letters, its copy is parked again (not left
/// waiting for a carrier), and it goes when Bob is reachable.
#[test]
fn a_custodian_that_stops_serving_letters_leaves_its_letters() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0xB5, false, true);
    w.letters_known();
    let mid = w.stage("held then stranded");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    assert_eq!(w.held_at(w.carol_pub), 1);
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 1 });
    set_lab_base_ops_only_for_this_thread(Some(true));
    // Alice's fetcher learns it (Bob, in this one process, shares the
    // cache: he asks nothing more and takes nothing there).
    assert!(w.fetch(false, w.carol_pub).unsupported);
    assert_eq!(w.fetch(true, w.carol_pub).letters, 0);
    let book = w.book(false);
    assert!(
        book.letters.iter().all(|row| row.held_by.is_empty()),
        "{:?}",
        book.letters
            .iter()
            .map(|r| r.held_by.len())
            .collect::<Vec<_>>()
    );
    let report = w.attempt();
    assert_eq!(only(&report), Outcome::Parked, "{:?}", report.outcomes);
    assert!(w.copies(&mid).is_empty(), "no longer in the letter session");
    let book = w.book(false);
    assert!(book.letters.iter().all(|row| row.withdraw));
    assert_eq!(book.abandoned.len(), 1);
    // Bob is reachable: the horizon re-pairs and the message goes.
    w.net.bob_down.store(false, Ordering::SeqCst);
    for _ in 0..3 {
        w.attempt();
    }
    assert_eq!(w.bob_inbox(), vec!["held then stranded".to_string()]);
    assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
}

/// Review letters-2: Carol stops serving letters after Alice's cache
/// learned she does. The message moves into a letter session, Carol
/// answers its letter UNSUPPORTED; on the next attempt the copy is parked
/// again rather than shown waiting for a carrier that cannot come, and
/// nothing is offered to Carol again.
#[test]
fn messages_moved_for_a_custodian_without_letters_are_parked_again() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0xB9, false, true);
    w.letters_known();
    set_lab_base_ops_only_for_this_thread(Some(true));
    let mid = w.stage("stranded");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    assert_eq!(letters_supported(&w.carol_pub, now()), Some(false));
    let second = w.attempt();
    assert_eq!(only(&second), Outcome::Parked, "{:?}", second.outcomes);
    assert!(
        w.copies(&mid).is_empty(),
        "parked, not in the letter session"
    );
    let third = w.attempt();
    assert!(
        third
            .outcomes
            .values()
            .all(|o| *o != Outcome::Held(WAITING_FOR_CARRIER)),
        "{:?}",
        third.outcomes
    );
    assert_eq!(w.held_at(w.carol_pub), 0);
    w.net.bob_down.store(false, Ordering::SeqCst);
    for _ in 0..3 {
        w.attempt();
    }
    assert_eq!(w.bob_inbox(), vec!["stranded".to_string()]);
}

/// Review letters-3: a build moved the message into the letter session and
/// stopped before its letter was recorded (a kill, or a book write that
/// failed: the two stores are not written together). The next attempt
/// seals the copy into a letter of its own, Carol holds it and Bob takes it.
#[test]
fn copies_left_without_a_letter_are_lettered_on_the_next_attempt() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0xBD, false, true);
    w.letters_known();
    let mid = w.stage("between two writes");
    let direct = DirectCopy {
        message_id: mid,
        session_id: w.copies(&mid)[0].0,
    };
    {
        let mut store = IndexedSessionStore::open(w.a.path()).unwrap();
        let built = build_letters(
            w.a.path(),
            &w.alice,
            &mut store,
            &w.bob_pub,
            &[direct],
            now(),
        )
        .unwrap();
        assert_eq!(built.moved, vec![mid]);
    }
    // The letter's record is lost.
    std::fs::remove_file(w.a.path().join(letter_deposits::LETTER_DEPOSITS_FILE)).unwrap();
    assert!(w.copies(&mid)[0].1, "in the letter session");
    let report = w.attempt();
    assert_eq!(
        only(&report),
        Outcome::Deposited { held: 1 },
        "{:?}",
        report.outcomes
    );
    let book = w.book(false);
    assert_eq!(book.letters.len(), 1);
    assert_eq!(book.letters[0].message_ids, vec![mid]);
    assert_eq!(w.held_at(w.carol_pub), 1);
    // Not again.
    w.attempt();
    assert_eq!(w.book(false).letters.len(), 1);
    let fetched = w.fetch(true, w.carol_pub);
    assert_eq!(fetched.accepted, 1, "{fetched:?}");
    assert_eq!(w.bob_inbox(), vec!["between two writes".to_string()]);
}

/// Re-verify of review 5a-1/cross-4: a message cancelled after the worker
/// left its letter with Carol, a letter that carries another message too.
/// The cancel (as `raven outbox cancel` does it under the send lock: the
/// outbox copy given up, then `letter_deposits::cancel_message`) marks the
/// letter to be withdrawn and says a friend holds it. The next attempt
/// withdraws it from Carol and leaves a new letter with the other message
/// only: Bob's fetch brings him that one alone.
#[test]
fn a_cancelled_message_leaves_its_letter() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0xE7, false, true);
    w.letters_known();
    let keep = w.stage("keep me");
    let gone = w.stage("cancel me");
    w.attempt();
    let book = w.book(false);
    assert_eq!(book.letters.len(), 1);
    assert_eq!(book.letters[0].message_ids, vec![keep, gone]);
    assert_eq!(w.held_at(w.carol_pub), 1);
    {
        let a = w.a.path();
        let _lock = PeerSendLock::acquire_within(a, &w.bob_pub, LOCK_WAIT).unwrap();
        let mut store = IndexedSessionStore::open(a).unwrap();
        let row = store
            .awaiting_ack_endpoint_outbound_for_recipient(Some(&w.bob_pub))
            .unwrap()
            .into_iter()
            .chain(
                store
                    .pending_endpoint_outbound_for_recipient(Some(&w.bob_pub))
                    .unwrap(),
            )
            .find(|r| r.message_id == gone)
            .expect("its copy in the letter session");
        let key = store
            .record_key_for_session_id(&row.session_id)
            .unwrap()
            .unwrap();
        raven_core::outbox::give_up_outbound(
            a,
            &mut store,
            &key,
            &w.bob_pub,
            &row.session_id,
            &row.object_digest,
            &gone,
            raven_core::outbox::HISTORY_CANCELLED,
        )
        .unwrap();
        assert_eq!(
            letter_deposits::cancel_message(a, &w.bob_pub, &gone, now()).unwrap(),
            letter_deposits::CancelledLetters {
                withdrawn: 1,
                with_friend: true
            }
        );
    }
    w.attempt();
    let book = w.book(false);
    assert_eq!(book.letters.len(), 1, "{:?}", book.letters);
    let row = &book.letters[0];
    assert_eq!(
        (row.message_ids.clone(), row.held_by.clone(), row.withdraw),
        (vec![keep], vec![w.carol_pub], false)
    );
    assert_eq!(w.held_at(w.carol_pub), 1, "the old letter left Carol");
    w.fetch(true, w.carol_pub);
    assert_eq!(w.bob_inbox(), vec!["keep me".to_string()]);
    assert_eq!(w.history(&gone).as_deref(), Some("cancelled"));
}

/// Review letters-4: messages that fill two letters in one build: each
/// letter is written a millisecond after the one before, and Bob's inbox
/// has them in send order.
#[test]
fn the_letters_of_one_build_reach_the_inbox_in_send_order() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0xD5, false, true);
    w.letters_known();
    let texts: Vec<String> = (0..6)
        .map(|i| format!("m{i}:{}", "y".repeat(20_000)))
        .collect();
    for text in &texts {
        w.stage(text);
    }
    w.attempt();
    let book = w.book(false);
    assert_eq!(book.letters.len(), 2);
    assert_eq!(
        book.letters[1].created_at_ms,
        book.letters[0].created_at_ms + 1
    );
    let fetched = w.fetch(true, w.carol_pub);
    assert_eq!(fetched.accepted, 2, "{fetched:?}");
    assert_eq!(w.bob_inbox(), texts);
}

/// A WITHDRAW_LETTERS answer of PERSISTENCE (the custodian's store was busy)
/// once, then the real handler.
fn persistence_once<'a>(
    w: &'a World,
    custodian: [u8; 32],
    refused: &'a AtomicBool,
) -> impl FnMut(&[u8; 32], &[Vec<u8>]) -> Replies + 'a {
    let mut real = w.dial_from(w.a.path(), custodian);
    move |_: &[u8; 32], frames: &[Vec<u8>]| {
        if refused.swap(true, Ordering::SeqCst) {
            return real(frames);
        }
        Ok(frames
            .iter()
            .map(|frame| {
                let id: [u8; 8] = frame[6..14].try_into().unwrap();
                raven_core::friend_custody::encode_reply(
                    &id,
                    &raven_core::friend_custody::Rfc1Reply::WithdrawResult {
                        code: CustodyCode::Persistence,
                        withdrawn: 0,
                    },
                )
            })
            .collect())
    }
}

/// Review letters-8: a settled letter's WITHDRAW refused (PERSISTENCE)
/// keeps the row with its holder, marked to be withdrawn; the next
/// withdraw, served OK, clears it there and forgets it.
#[test]
fn a_refused_withdraw_keeps_the_letter_until_it_is_served() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0xD9, false, true);
    w.letters_known();
    let mid = w.stage("withdrawn on the second try");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    // Delivered directly: the letter at Carol is settled.
    w.net.bob_down.store(false, Ordering::SeqCst);
    assert!(matches!(only(&w.attempt()), Outcome::Delivered { .. }));
    assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
    assert_eq!(w.held_at(w.carol_pub), 1);
    let refused = AtomicBool::new(false);
    let mut dial = persistence_once(&w, w.carol_pub, &refused);
    let store = IndexedSessionStore::open(w.a.path()).unwrap();
    withdraw_settled(w.a.path(), &store, &w.bob_pub, None, now(), &mut dial);
    let book = w.book(false);
    assert_eq!(book.letters.len(), 1, "kept after a refusal");
    assert_eq!(book.letters[0].held_by, vec![w.carol_pub]);
    assert!(book.letters[0].withdraw);
    assert_eq!(w.held_at(w.carol_pub), 1);
    let withdrawn = withdraw_settled(w.a.path(), &store, &w.bob_pub, None, now(), &mut dial);
    assert_eq!(withdrawn, 1);
    assert_eq!(w.held_at(w.carol_pub), 0);
    assert!(w.book(false).letters.is_empty());
}

/// Alice's letter left with Carol only (Dave not known to serve letters
/// yet); Bob takes it and his REPLY delivers the message. Dave serves
/// letters from then on. The letter's digest.
fn settled_letter_held_by_carol(w: &World) -> [u8; 32] {
    note_letters(&w.carol_pub, true, now());
    let mid = w.stage("settled by a reply");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    let book = w.book(false);
    assert_eq!(book.letters[0].held_by, vec![w.carol_pub]);
    assert_eq!(w.fetch(true, w.carol_pub).accepted, 1);
    w.bob_attempt();
    assert_eq!(w.fetch(false, w.carol_pub).replies, 1);
    assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
    note_letters(&w.dave_pub, true, now());
    book.letters[0].digest
}

/// Review letters-9: the settled letter could not be withdrawn from Carol
/// (unreachable): it is never offered to Dave, who serves letters.
#[test]
fn a_settled_letter_is_never_placed_again() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0xDD, true, true);
    settled_letter_held_by_carol(&w);
    let store = IndexedSessionStore::open(w.a.path()).unwrap();
    withdraw_settled(
        w.a.path(),
        &store,
        &w.bob_pub,
        None,
        now(),
        &mut |_: &[u8; 32], _: &[Vec<u8>]| Err("custody dial deadline".to_string()),
    );
    let book = w.book(false);
    assert_eq!(book.letters[0].held_by, vec![w.carol_pub]);
    assert!(book.letters[0].withdraw);
    let ctx = w.ctx();
    let mut dial_for =
        |c: &[u8; 32], o: Option<u8>, frames: &[Vec<u8>]| match worker_dial(&ctx, *c, o) {
            Some(mut dial) => dial(frames),
            None => Err("no route".into()),
        };
    let placed = place(
        w.a.path(),
        &w.bob_pub,
        &[(w.dave_pub, None)],
        now(),
        &mut dial_for,
    );
    assert!(placed.is_empty());
    assert_eq!(w.held_at(w.dave_pub), 0, "never offered to Dave");
}

/// Review letters-9: the fetcher withdraws the settled letter at Carol and
/// forgets it while the worker's deposit of it at Dave is in flight. Dave's
/// STORED answer is not thrown away: the letter keeps a row for Dave,
/// marked to be withdrawn, and the next withdraw leaves Dave with nothing.
#[test]
fn a_letter_forgotten_during_its_deposit_is_still_withdrawn() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0xE1, true, true);
    let digest = settled_letter_held_by_carol(&w);
    let store = IndexedSessionStore::open(w.a.path()).unwrap();
    let mut to_carol = w.dial_from(w.a.path(), w.carol_pub);
    let mut to_dave = w.dial_from(w.a.path(), w.dave_pub);
    let mut raced = false;
    let mut dial_for = |_: &[u8; 32], _: Option<u8>, frames: &[Vec<u8>]| {
        if !std::mem::replace(&mut raced, true) {
            // The fetcher, meanwhile: withdrawn at Carol, forgotten.
            withdraw_settled(
                w.a.path(),
                &store,
                &w.bob_pub,
                Some(&w.carol_pub),
                now(),
                &mut |_: &[u8; 32], frames: &[Vec<u8>]| to_carol(frames),
            );
            assert!(w.book(false).letters.is_empty());
        }
        to_dave(frames)
    };
    place(
        w.a.path(),
        &w.bob_pub,
        &[(w.dave_pub, None)],
        now(),
        &mut dial_for,
    );
    assert!(raced);
    assert_eq!(w.held_at(w.dave_pub), 1, "Dave took it meanwhile");
    let book = w.book(false);
    assert_eq!(book.letters.len(), 1, "tracked again");
    assert_eq!(
        (
            book.letters[0].digest,
            book.letters[0].held_by.clone(),
            book.letters[0].withdraw
        ),
        (digest, vec![w.dave_pub], true)
    );
    let mut to_dave = w.dial_from(w.a.path(), w.dave_pub);
    withdraw_settled(
        w.a.path(),
        &store,
        &w.bob_pub,
        None,
        now(),
        &mut |_: &[u8; 32], frames: &[Vec<u8>]| to_dave(frames),
    );
    assert_eq!(w.held_at(w.dave_pub), 0, "withdrawn from Dave");
    assert!(w.book(false).letters.is_empty());
}

/// Review cross-6: with the letter gate closed the fetcher's letter steps
/// do nothing: the deposit book names nobody to withdraw from a custodian
/// that holds a letter, and the letter round dials nothing. CI runs this in
/// release with every lab switch set, where no thread override applies and
/// the gate is the build's own: it fails if a release build ever opens it.
#[test]
fn the_letter_steps_do_nothing_with_the_letter_gate_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (peer, carol) = ([0xB7; 32], [0xC7; 32]);
    let wall = now();
    let mut row = letter_deposits::LetterDeposit::new(
        DepositKind::Letter,
        peer,
        [0x5e; 32],
        vec![0x4c; 900],
        wall,
        wall + DAY,
        vec![[0x1d; 16]],
        Vec::new(),
    );
    row.held_by.push(carol);
    letter_deposits::update(dir.path(), wall, |book| book.letters.push(row)).unwrap();
    if cfg!(debug_assertions) {
        // Open, the book names the peer: what the closed gate hides.
        let _on = LettersOn::new();
        assert_eq!(letter_peers_at(dir.path(), &carol, wall), [peer]);
    }
    set_lab_letter_for_this_thread(Some(false));
    let peers = letter_peers_at(dir.path(), &carol, wall);
    let dials = AtomicUsize::new(0);
    let mut dial = |_: &[Vec<u8>]| -> Result<Vec<Vec<u8>>, String> {
        dials.fetch_add(1, Ordering::SeqCst);
        Err("no dial with the gate closed".into())
    };
    let me = Identity::from_seed(&[0x7a; 32]);
    let fetched = fetch_at(dir.path(), &me, &carol, wall, 4, &mut dial).is_some();
    set_lab_letter_for_this_thread(None);
    assert!(peers.is_empty(), "nobody");
    assert!(!fetched, "no letter round");
    assert_eq!(dials.load(Ordering::SeqCst), 0);
}
