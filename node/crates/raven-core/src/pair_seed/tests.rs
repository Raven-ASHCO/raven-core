//! Pair seeds: the KDF's known answers (`shared-vectors/rvn1/pair_seed/
//! kdf_001.json`, written only under `RAVEN_REGEN_SECURITY_VECTORS=1` and
//! checked by the Python reference), the entry codec, the leader/follower
//! state machine (propose, ack, switch, the previous seed's retirement, the
//! root fallback), a property test that no ordering of sends, losses,
//! crashes and clock steps ever leaves a key one side sends with outside
//! what the other accepts, and the file.

use std::collections::VecDeque;

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use serde_json::{json, Value};

use super::*;
use crate::lan_beacon::{medium_key, MEDIUM_BLE, MEDIUM_LAN};
use crate::link_knock::MEDIUM_LINK;

const REGEN: &str = "RAVEN_REGEN_SECURITY_VECTORS";

/// RFC 8032 section 7.1 tests 1 and 2 (the beacon vectors' alice and bob).
const ALICE: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const BOB: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

/// 2026-10-23 12:00 UTC.
const T0: u64 = 1_792_756_800_000;
const HOUR_MS: u64 = 60 * 60 * 1000;

fn id(seed: &str) -> Identity {
    Identity::from_seed(&hex::decode(seed).unwrap().try_into().unwrap())
}

fn counting(first: u8) -> [u8; 32] {
    std::array::from_fn(|i| first.wrapping_add(i as u8))
}

fn rvn1_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors/rvn1")
}

/// Assert that the committed vector `file` (under shared-vectors/rvn1)
/// equals `expected`; write it first under `RAVEN_REGEN_SECURITY_VECTORS=1`.
fn assert_vector(file: &str, expected: &Value) {
    let path = rvn1_dir().join(file);
    if std::env::var(REGEN).as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(expected).unwrap() + "\n",
        )
        .unwrap();
    }
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
    let stored: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(&stored, expected, "{file}");
}

/// KAT (W-B4): K_pair of two seeds of the alice/bob pair, the three medium
/// keys made from it, and the leader. The root is the beacon vectors'
/// (`lan_beacon/lbcn_pair_keys_001.json`).
#[test]
fn kdf_known_answer_vector() {
    let (alice, bob) = (id(ALICE), id(BOB));
    let (a, b) = (alice.public_key_bytes(), bob.public_key_bytes());
    let root = pair_root(&alice, &b).unwrap();
    assert_eq!(*root, *pair_root(&bob, &a).unwrap());
    assert_eq!(
        hex::encode(*root),
        "4a7b4e88f966358051ad5a45a0374f88f37627182cce69a27860717269c504a1"
    );
    // Bob's key is the smaller one: Bob leads.
    assert!(is_leader(&b, &a) && !is_leader(&a, &b));
    let gens: Vec<Value> = [(1u32, counting(0x01)), (2, counting(0xa0))]
        .into_iter()
        .map(|(generation, seed)| {
            let k = pair_key(&root, &seed);
            assert_ne!(*k, *root);
            json!({
                "generation": generation,
                "seed_hex": hex::encode(seed),
                "k_pair_hex": hex::encode(*k),
                "k_ble_hex": hex::encode(*medium_key(&k, MEDIUM_BLE)),
                "k_lan_hex": hex::encode(*medium_key(&k, MEDIUM_LAN)),
                "k_link_hex": hex::encode(*medium_key(&k, MEDIUM_LINK)),
            })
        })
        .collect();
    assert_ne!(gens[0]["k_pair_hex"], gens[1]["k_pair_hex"]);
    assert_vector(
        "pair_seed/kdf_001.json",
        &json!({
            "name": "Pair seed KDF (design B W-B4)",
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": "RAVEN_ROUTE_HINTS_V1 §14: K_pair = HKDF-SHA256(salt K_root, ikm \
                            seed, info 'rvn1/pair-seed/v1', 32 bytes), K_root the R2 pairwise \
                            root of the two Ed25519 identity keys (shared-vectors/rvn1/\
                            lan_beacon/lbcn_pair_keys_001.json); K_pair takes K_root's place in \
                            K_medium = HKDF-Expand-SHA256(PRK, info 'medium' || medium, 32 \
                            bytes): 0x01 Bluetooth LE, 0x02 LAN beacon, 0x03 link knock. The \
                            leader is the numerically smaller identity key",
            "inputs": {
                "alice_seed_hex": ALICE,
                "bob_seed_hex": BOB,
                "kdf_info": "rvn1/pair-seed/v1",
                "seeds": gens.iter().map(|g| json!({
                    "generation": g["generation"],
                    "seed_hex": g["seed_hex"],
                })).collect::<Vec<_>>(),
            },
            "expected": {
                "alice_pub_hex": hex::encode(a),
                "bob_pub_hex": hex::encode(b),
                "k_root_hex": hex::encode(*root),
                "leader": "bob",
                "generations": gens,
            },
        }),
    );
}

/// The entry is 40 bytes: generation, seed, acked generation; generation 0
/// and an all-zero seed are refused, and so is any other length.
#[test]
fn entry_codec() {
    let e = SeedEntry {
        generation: 7,
        seed: Zeroizing::new(counting(0x40)),
        acked: 6,
    };
    let bytes = e.to_bytes();
    assert_eq!(bytes.len(), ENTRY_LEN);
    assert_eq!(&bytes[..4], &[0, 0, 0, 7]);
    assert_eq!(&bytes[4..36], &counting(0x40));
    assert_eq!(&bytes[36..], &[0, 0, 0, 6]);
    assert_eq!(SeedEntry::from_bytes(&bytes), Some(e.clone()));
    assert!(SeedEntry::from_bytes(&bytes[..39]).is_none());
    assert!(SeedEntry::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_none());
    let mut zero_gen = bytes;
    zero_gen[..4].fill(0);
    assert!(SeedEntry::from_bytes(&zero_gen).is_none());
    let mut zero_seed = bytes;
    zero_seed[4..36].fill(0);
    assert!(SeedEntry::from_bytes(&zero_seed).is_none());
    // acked may be anything, 0 included.
    let mut none_acked = bytes;
    none_acked[36..].fill(0);
    assert_eq!(SeedEntry::from_bytes(&none_acked).unwrap().acked, 0);
    assert!(!format!("{e:?}").contains("40"), "Debug shows no seed");
}

/// The two sides of the model: their stored states.
struct Pair {
    leader: PairState,
    follower: PairState,
}

impl Pair {
    fn new() -> Self {
        Self {
            leader: PairState::default(),
            follower: PairState::default(),
        }
    }

    /// The leader's RRH1 entry (a proposal made and stored first).
    fn leader_sends(&mut self, now: u64, seed: [u8; 32]) -> Option<SeedEntry> {
        self.leader.propose(true, now, || seed);
        self.leader.entry(true)
    }

    fn follower_sends(&mut self, now: u64) -> Option<SeedEntry> {
        self.follower
            .propose(false, now, || unreachable!("a follower never proposes"));
        self.follower.entry(false)
    }

    /// The seed `from` sends with is one `to` accepts (or the root, which
    /// every side accepts).
    fn sends_ok(from: &PairState, to: &PairState, now: u64) -> bool {
        from.send_seed()
            .is_none_or(|s| to.accepted(now).contains(&s))
    }

    fn no_lockout(&self, now: u64) -> bool {
        Self::sends_ok(&self.leader, &self.follower, now)
            && Self::sends_ok(&self.follower, &self.leader, now)
    }
}

/// Propose, ack, switch: the follower adopts the leader's proposal at once
/// (the leader accepts it as its proposal meanwhile), the leader switches on
/// the ack, the follower retires the old seed 2 days after it sees the
/// leader use the new one, and the next proposal waits 7 days.
#[test]
fn propose_ack_switch_and_retire() {
    let mut p = Pair::new();
    // A new pair: the leader proposes generation 1 at once.
    let offer = p.leader_sends(T0, counting(1)).unwrap();
    assert_eq!((offer.generation, offer.acked), (1, 0));
    assert!(p.leader.send_seed().is_none(), "the root until acked");
    // A follower without a seed offers nothing.
    assert!(p.follower_sends(T0).is_none());
    p.follower.incoming(false, Some(&offer), T0);
    assert_eq!(p.follower.send_seed().unwrap().generation, 1);
    assert!(p.no_lockout(T0), "the leader accepts its proposal");
    let ack = p.follower_sends(T0).unwrap();
    assert_eq!((ack.generation, ack.acked), (1, 1));
    p.leader.incoming(true, Some(&ack), T0 + 1);
    assert_eq!(p.leader.send_seed().unwrap().generation, 1);
    assert!(p.leader.proposed.is_none() && p.leader.previous.is_none());
    assert!(p.no_lockout(T0 + 1));
    // Nothing new before 7 days.
    let again = p.leader_sends(T0 + ROTATE_MS - 2, counting(2)).unwrap();
    assert_eq!((again.generation, again.acked), (1, 1));
    p.follower.incoming(false, Some(&again), T0 + ROTATE_MS - 2);
    assert_eq!(p.follower.peer_acked, 1);
    // Day 7: generation 2.
    let t7 = T0 + ROTATE_MS + 1;
    let offer = p.leader_sends(t7, counting(2)).unwrap();
    assert_eq!((offer.generation, offer.acked), (2, 1));
    p.follower.incoming(false, Some(&offer), t7);
    assert_eq!(p.follower.send_seed().unwrap().generation, 2);
    assert_eq!(p.follower.previous.as_ref().unwrap().generation, 1);
    assert_eq!(p.follower.retire_at_ms, None, "the leader still uses 1");
    assert!(p.no_lockout(t7));
    let ack = p.follower_sends(t7).unwrap();
    p.leader.incoming(true, Some(&ack), t7 + 10);
    assert_eq!(p.leader.send_seed().unwrap().generation, 2);
    assert_eq!(p.leader.retire_at_ms, Some(t7 + 10 + RETIRE_MS));
    // The follower sees the leader use 2: its 1 goes 2 days later.
    let seen = p.leader_sends(t7 + 20, counting(3)).unwrap();
    p.follower.incoming(false, Some(&seen), t7 + 20);
    assert_eq!(p.follower.retire_at_ms, Some(t7 + 20 + RETIRE_MS));
    assert_eq!(p.follower.accepted(t7 + 20 + RETIRE_MS - 1).len(), 2);
    assert_eq!(p.follower.accepted(t7 + 20 + RETIRE_MS).len(), 1);
    p.follower.prune(t7 + 20 + RETIRE_MS);
    p.leader.prune(t7 + 20 + RETIRE_MS);
    assert!(p.follower.previous.is_none() && p.leader.previous.is_none());
    assert!(p.no_lockout(t7 + 20 + RETIRE_MS));
}

/// A lost ack (the follower crashed after it stored the proposal, or its
/// RRH1 never arrived): both keep working, the follower with the new seed
/// (the leader's proposal), the leader with the root; the leader offers the
/// same proposal again and never a second one, and switches when an ack
/// finally comes.
#[test]
fn a_lost_ack_keeps_both_working() {
    let mut p = Pair::new();
    let offer = p.leader_sends(T0, counting(1)).unwrap();
    p.follower.incoming(false, Some(&offer), T0);
    let _lost = p.follower_sends(T0);
    for day in 1..=20 {
        let now = T0 + day * DAY_MS;
        let again = p.leader_sends(now, counting(day as u8 + 1)).unwrap();
        assert_eq!(again, offer, "the same proposal, day {day}");
        assert!(p.no_lockout(now));
        let roots = roots_from(&[9; 32], &[1; 32], &[2; 32], Some(&p.leader), now);
        assert_eq!(roots.accept.len(), 2, "the proposal and the root");
        assert!(roots.is_root(roots.send) && !roots.root_notice);
    }
    let ack = p.follower_sends(T0 + 21 * DAY_MS).unwrap();
    p.leader.incoming(true, Some(&ack), T0 + 21 * DAY_MS);
    assert_eq!(p.leader.send_seed(), p.follower.send_seed());
    // An ack of another seed, or one that does not ack, switches nothing.
    let mut q = Pair::new();
    let offer = q.leader_sends(T0, counting(1)).unwrap();
    let mut wrong = offer.clone();
    wrong.acked = offer.generation;
    wrong.seed = Zeroizing::new(counting(5));
    q.leader.incoming(true, Some(&wrong), T0);
    let mut unacked = offer.clone();
    unacked.acked = 0;
    q.leader.incoming(true, Some(&unacked), T0);
    assert!(q.leader.current.is_none() && q.leader.proposed.is_some());
}

/// A contact whose RRH1 carries no entry has no seed (its gate is shut, an
/// older build, or it lost its seeds): this side keeps its seed as the
/// previous one for 2 days and sends with the root; a match with the root
/// is a Notice only while this side expects the contact to use a seed.
#[test]
fn no_entry_falls_back_to_the_root() {
    let mut p = Pair::new();
    let offer = p.leader_sends(T0, counting(1)).unwrap();
    p.follower.incoming(false, Some(&offer), T0);
    let ack = p.follower_sends(T0).unwrap();
    p.leader.incoming(true, Some(&ack), T0);
    let seen = p.leader_sends(T0, counting(2)).unwrap();
    p.follower.incoming(false, Some(&seen), T0);
    assert!(p.leader.root_is_notice(true) && p.follower.root_is_notice(false));
    // The follower's next RRH1 has no entry.
    p.leader.incoming(true, None, T0 + HOUR_MS);
    assert!(p.leader.send_seed().is_none(), "the root now");
    assert_eq!(
        p.leader.accepted(T0 + HOUR_MS).len(),
        1,
        "the old seed, 2 days"
    );
    assert!(!p.leader.root_is_notice(true));
    assert!(p.no_lockout(T0 + HOUR_MS));
    // The leader proposes again at once; the follower adopts and acks.
    let offer = p.leader_sends(T0 + 2 * HOUR_MS, counting(9)).unwrap();
    assert_eq!(offer.generation, 2, "never a generation used before");
    p.follower.incoming(false, Some(&offer), T0 + 2 * HOUR_MS);
    assert!(p.no_lockout(T0 + 2 * HOUR_MS));
    // The leader's RRH1 without an entry: the follower uses the root too.
    let mut f = PairState::default();
    f.incoming(false, Some(&offer), T0);
    f.incoming(false, None, T0 + 1);
    assert!(f.send_seed().is_none() && f.peer_acked == 0);
    assert_eq!(f.accepted(T0 + 1).len(), 1);
    assert!(f.accepted(T0 + 1 + RETIRE_MS).is_empty());
    // It comes back with the same seed: adopted again.
    f.incoming(false, Some(&offer), T0 + 2);
    assert_eq!(f.send_seed().unwrap().generation, offer.generation);
    assert_eq!(f.accepted(T0 + 2).len(), 1, "no duplicate");
}

/// The keys a matcher tries: the current seed's K_pair, then the proposal
/// or the previous one, the root last (at most three), sending with the
/// current one or else the root.
#[test]
fn roots_order_and_send_key() {
    let (alice, bob) = (id(ALICE), id(BOB));
    let b = bob.public_key_bytes();
    let root = pair_root(&alice, &b).unwrap();
    let plain = roots(&alice, &b, None, T0).unwrap();
    assert_eq!(plain.accept.len(), 1);
    assert_eq!(plain.send_key(), &*root);
    assert!(!plain.notice_at(0));
    // Alice follows Bob.
    let mut s = PairState::default();
    s.incoming(false, Some(&entry(1, 1, 1)), T0);
    let r = roots(&alice, &b, Some(&s), T0).unwrap();
    assert_eq!(r.accept.len(), 2);
    assert_eq!(*r.accept[0], *pair_key(&root, &counting(1)));
    assert_eq!(r.send, 0);
    assert_eq!(*r.accept[1], *root);
    assert!(r.notice_at(1) && !r.notice_at(0));
    s.incoming(false, Some(&entry(2, 2, 1)), T0 + 1);
    let r = roots(&alice, &b, Some(&s), T0 + 1).unwrap();
    assert_eq!(r.accept.len(), 3);
    assert_eq!(*r.accept[0], *pair_key(&root, &counting(2)));
    assert_eq!(*r.accept[1], *pair_key(&root, &counting(1)));
    assert_eq!(*r.accept[2], *root);
    assert!(format!("{r:?}").contains("keys: 3"));
}

fn entry(generation: u32, seed: u8, acked: u32) -> SeedEntry {
    SeedEntry {
        generation,
        seed: Zeroizing::new(counting(seed)),
        acked,
    }
}

/// Acceptance (design B §5): no ordering of sends, losses (a receiver that
/// crashed before it stored, a sender that crashed after it stored and
/// before it sent), in-order late deliveries and clock steps of up to 10
/// days ever leaves the seed one side sends with outside what the other
/// accepts; and once the links work again, both end on the same seed.
#[test]
fn no_lockout_in_any_crash_ordering() {
    for run in 0..400u64 {
        let mut rng = StdRng::seed_from_u64(0x5053_3138 ^ run);
        let mut p = Pair::new();
        let mut now = T0;
        let mut to_f: VecDeque<Option<SeedEntry>> = VecDeque::new();
        let mut to_l: VecDeque<Option<SeedEntry>> = VecDeque::new();
        for step in 0..300 {
            match rng.gen_range(0..10) {
                0 | 1 => {
                    let mut seed = [0u8; 32];
                    rng.fill_bytes(&mut seed);
                    to_f.push_back(p.leader_sends(now, seed));
                }
                2 | 3 => to_l.push_back(p.follower_sends(now)),
                4 | 5 => {
                    if let Some(e) = to_f.pop_front() {
                        p.follower.incoming(false, e.as_ref(), now);
                    }
                }
                6 | 7 => {
                    if let Some(e) = to_l.pop_front() {
                        p.leader.incoming(true, e.as_ref(), now);
                    }
                }
                8 => {
                    // Lost: a crash on either side of the link.
                    if rng.gen_bool(0.5) {
                        to_f.pop_front();
                    } else {
                        to_l.pop_front();
                    }
                }
                _ => {
                    now += match rng.gen_range(0..4) {
                        0 => rng.gen_range(0..HOUR_MS),
                        1 => rng.gen_range(0..DAY_MS),
                        2 => rng.gen_range(0..3 * DAY_MS),
                        _ => rng.gen_range(0..10 * DAY_MS),
                    };
                }
            }
            p.leader.prune(now);
            p.follower.prune(now);
            assert!(
                p.no_lockout(now),
                "run {run} step {step}: leader {:?} follower {:?}",
                p.leader,
                p.follower
            );
            assert!(p.leader.accepted(now).len() <= 3 && p.follower.accepted(now).len() <= 2);
        }
        // The links work again: two clean round trips agree.
        to_f.clear();
        to_l.clear();
        for _ in 0..2 {
            let e = p.leader_sends(now, counting(0x77));
            p.follower.incoming(false, e.as_ref(), now);
            let e = p.follower_sends(now);
            p.leader.incoming(true, e.as_ref(), now);
            assert!(p.no_lockout(now));
        }
        assert!(p.leader.send_seed().is_some(), "run {run}");
        assert_eq!(p.leader.send_seed(), p.follower.send_seed(), "run {run}");
    }
}

/// The file: two profiles run the exchange through their own files; a
/// follower's adoption is stored before its ack is made; forget removes a
/// contact's seeds; the file is plain JSON (0600) in a plain profile,
/// registered as at-rest kind 12.
#[test]
fn two_profiles_through_their_files() {
    let (la, fo) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, bob) = (id(ALICE), id(BOB));
    let (a, b) = (alice.public_key_bytes(), bob.public_key_bytes());
    // Bob leads.
    assert!(outgoing(fo.path(), &a, &b, T0, || unreachable!()).is_none());
    let offer = outgoing(la.path(), &b, &a, T0, || counting(1)).unwrap();
    assert_eq!(offer.generation, 1);
    // Stored before it went out: offered again, the same.
    assert_eq!(
        outgoing(la.path(), &b, &a, T0 + 1, || counting(2)),
        Some(offer.clone())
    );
    incoming(fo.path(), &a, &b, Some(&offer), T0).unwrap();
    assert_eq!(state(fo.path(), &b).unwrap().current.unwrap().generation, 1);
    let ack = outgoing(fo.path(), &a, &b, T0, || unreachable!()).unwrap();
    incoming(la.path(), &b, &a, Some(&ack), T0).unwrap();
    let book_l = SeedBook::load(la.path(), true, T0);
    let book_f = SeedBook::load(fo.path(), true, T0);
    let (rl, rf) = (
        book_l.roots(&bob, &a).unwrap(),
        book_f.roots(&alice, &b).unwrap(),
    );
    assert_eq!(rl.send_key(), rf.send_key(), "both send with K_pair(1)");
    assert_eq!(
        *rl.send_key(),
        *pair_key(&pair_root(&bob, &a).unwrap(), &counting(1))
    );
    // While the gate is shut the book is empty: the root.
    let shut = SeedBook::load(la.path(), false, T0);
    assert!(shut.state(&a).is_none());
    assert_eq!(shut.roots(&bob, &a).unwrap().accept.len(), 1);
    // Plain JSON, owner only, names the contact by its key; no seed in a
    // log-shaped Debug.
    let raw = std::fs::read_to_string(la.path().join(PAIR_SEEDS_FILE)).unwrap();
    assert!(raw.contains(&hex::encode(a)) && raw.contains(&hex::encode(counting(1))));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(la.path().join(PAIR_SEEDS_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(!format!("{:?}", state(la.path(), &a).unwrap()).contains(&hex::encode(counting(1))));
    assert_eq!(
        crate::at_rest::rule_for(PAIR_SEEDS_FILE).map(|r| r.rule),
        Some(crate::at_rest::Rule::Sealed(Kind::PairSeeds))
    );
    // Forget: gone, and no write for a contact it does not name.
    forget(la.path(), &a).unwrap();
    assert!(state(la.path(), &a).is_none());
    forget(la.path(), &[7; 32]).unwrap();
    // A file this process cannot read is never written over, and offers
    // nothing.
    std::fs::write(
        fo.path().join(PAIR_SEEDS_FILE),
        b"RMS1\x01\x0c\x00\x00\x00\x01garbage-that-is-not-a-sealed-file",
    )
    .unwrap();
    assert!(outgoing(fo.path(), &a, &b, T0, || unreachable!()).is_none());
    assert!(incoming(fo.path(), &a, &b, Some(&offer), T0).is_err());
    assert!(SeedBook::load(fo.path(), true, T0).state(&b).is_none());
}

/// The live check is the gate's (it sits on route hints): shut in a release
/// build whatever the variables say.
#[test]
fn live_follows_the_gate() {
    const { assert!(!crate::security_gate::PAIR_SEED_PRODUCTION_ENABLED) };
    crate::security_gate::set_lab_for_this_thread(SecGate::PairSeed, Some(false));
    assert!(!live());
    crate::security_gate::set_lab_for_this_thread(SecGate::PairSeed, Some(true));
    assert_eq!(
        live(),
        cfg!(debug_assertions) && crate::route_hints::route_hints_live()
    );
    crate::security_gate::set_lab_for_this_thread(SecGate::PairSeed, None);
}

/// The seeded K_pair replaces the root for every medium: a beacon query, a
/// knock and a Bluetooth token made with the current seed match a receiver
/// that holds that seed, never one with the root alone; a sender without a
/// seed (the root) still matches a receiver that has one (its last key).
#[test]
fn seeded_keys_match_and_the_root_stays_the_fallback() {
    use crate::lan_beacon::{build_query, match_query, pair_keys_from, PairKeys};
    use crate::link_knock::{knock_keys_from, m1_payload_with, match_m1, KnockKeys};
    use std::net::{IpAddr, Ipv4Addr};
    let (alice, bob) = (id(ALICE), id(BOB));
    let (a, b) = (alice.public_key_bytes(), bob.public_key_bytes());
    let root = pair_root(&alice, &b).unwrap();
    let mut seeded = PairState::default();
    seeded.incoming(false, Some(&entry(1, 0x11, 1)), T0);
    // Alice (follower) and Bob (leader, switched) with the same seed.
    let ra = roots_from(&root, &a, &b, Some(&seeded), T0);
    let mut lead = PairState::default();
    lead.propose(true, T0, || counting(0x11));
    lead.incoming(true, Some(&entry(1, 0x11, 1)), T0);
    let rb = roots_from(&root, &b, &a, Some(&lead), T0);
    assert_eq!(ra.send_key(), rb.send_key());
    assert_ne!(ra.send_key(), &*root);
    let plain = roots_from(&root, &b, &a, None, T0);
    let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    let epoch = 2_833_333;
    let mut rng = StdRng::seed_from_u64(38);
    // The beacon: Bob's book of Alice's keys.
    let bob_book = |r: &PairRoots| -> Vec<PairKeys> {
        r.accept.iter().map(|k| pair_keys_from(&b, &a, k)).collect()
    };
    let q = build_query(
        &mut rng,
        epoch,
        src,
        7531,
        &[&pair_keys_from(&a, &b, ra.send_key())],
    );
    assert_eq!(match_query(&q, src, epoch, &bob_book(&rb)), vec![(0, 7531)]);
    assert!(match_query(&q, src, epoch, &bob_book(&plain)).is_empty());
    // Alice without a seed asks with the root: Bob matches his last key, a
    // Notice since he expects a seed.
    let q = build_query(
        &mut rng,
        epoch,
        src,
        7531,
        &[&pair_keys_from(&a, &b, &root)],
    );
    let hits = match_query(&q, src, epoch, &bob_book(&rb));
    assert_eq!(hits, vec![(1, 7531)]);
    assert!(rb.notice_at(hits[0].0));
    assert_eq!(
        match_query(&q, src, epoch, &bob_book(&plain)),
        vec![(0, 7531)]
    );
    assert!(!plain.notice_at(0));
    // The knock: Bob listens with Alice's key sets.
    let day = crate::link_knock::day_of(T0);
    let e = [0x42; 32];
    let knock_book = |r: &PairRoots| -> Vec<KnockKeys> {
        r.accept
            .iter()
            .map(|k| knock_keys_from(&b, &a, k))
            .collect()
    };
    let m1 = |r: &[u8; 32]| {
        [
            e.as_slice(),
            &m1_payload_with(&knock_keys_from(&a, &b, r), day, &e, &[7; 16], &[]),
        ]
        .concat()
    };
    assert_eq!(
        match_m1(&knock_book(&rb), &m1(ra.send_key()), day)
            .unwrap()
            .index,
        0
    );
    assert!(match_m1(&knock_book(&plain), &m1(ra.send_key()), day).is_none());
    let fallback = match_m1(&knock_book(&rb), &m1(&root), day).unwrap();
    assert!(rb.is_root(fallback.index) && fallback.peer == a);
    // Bluetooth: the seeded token is not the root's.
    use crate::nearby_link::pair_keys_from as ble_keys;
    let seeded_ble = ble_keys(&a, &b, ra.send_key());
    let root_ble = ble_keys(&a, &b, &root);
    assert_ne!(seeded_ble.token_out(5), root_ble.token_out(5));
    assert_eq!(
        root_ble.token_out(5),
        crate::nearby_link::pair_keys(&alice, &b)
            .unwrap()
            .token_out(5)
    );
    assert_eq!(
        seeded_ble.token_out(5),
        ble_keys(&b, &a, rb.send_key()).token_in(5)
    );
}
