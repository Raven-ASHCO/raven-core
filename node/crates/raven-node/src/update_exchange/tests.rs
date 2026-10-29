//! The update exchange in raven-node (step P6.49): three profiles in one
//! process (A -> B -> C), their links as HAVE frames taken both ways and
//! their follow-up dials answered by the other profile's listener code
//! ([`Node::listener_frame`]), with notices and releases signed by the
//! published test keys. The link code's part (bit 10, HAVE after RLB1 and
//! RRH1, requests only after the listener's HAVE) is tested in
//! `lan_direct` and `internet_direct`.

use super::*;

/// What the exchange does with its gate shut (both builds): no bit 10, no
/// HAVE, nothing taken from a link, no status.
#[test]
fn with_the_gate_shut_nothing_is_offered_sent_or_taken() {
    for g in [
        security_gate::SecGate::Advisory,
        security_gate::SecGate::ReleaseBundle,
        security_gate::SecGate::MeshUpdate,
    ] {
        security_gate::set_lab_for_this_thread(g, Some(false));
    }
    assert!(!active());
    assert!(!offered());
    assert!(!crate::link::offers(OutboxCarrier::Internet)
        .contains(raven_core::internet::LinkFeatures::RUP1));
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(status(dir.path()), None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let have = rup1::encode(&NO_REQ_ID, &Rup1Msg::Have(Have::nothing())).unwrap();
        let get_log = rup1::encode(&[1, 2, 3, 4], &Rup1Msg::GetLog).unwrap();
        let mut listener = UpdateLink::lan_listener(
            dir.path(),
            [7; 32],
            &raven_core::route_hints::rlx1_payload(CAP_LINK_RUP1),
        );
        assert_eq!(listener.outgoing().await, None, "no HAVE");
        // A RUP1 frame is not this exchange's while it is shut: the link
        // handles it as it always did.
        assert_eq!(listener.listener_take(&get_log).await, None);
        let mut dialer = UpdateLink::inet(
            dir.path(),
            OutboxCarrier::Internet,
            false,
            [7; 32],
            false,
            raven_core::internet::hello_caps(raven_core::internet::LinkFeatures::RUP1),
        );
        assert_eq!(dialer.outgoing().await, None);
        assert_eq!(dialer.dialer_take(&have).await, None);
        assert!(
            check_requests(&[get_log], &dialer).is_err(),
            "nothing is asked"
        );
        assert!(check_requests(&[b"not RUP1".to_vec()], &dialer).is_ok());
    });
    for g in [
        security_gate::SecGate::Advisory,
        security_gate::SecGate::ReleaseBundle,
        security_gate::SecGate::MeshUpdate,
    ] {
        security_gate::set_lab_for_this_thread(g, None);
    }
}

/// Runs in both builds: the release test job sets Lab Test A and the
/// switch, and a release build still never claims a newer notice; a debug
/// build reads the variable only with Lab Test A.
#[test]
fn the_newer_claim_is_inert_without_debug_assertions() {
    if !cfg!(debug_assertions) {
        // Edition 2021: plain calls. No other release test reads these.
        std::env::set_var("RAVEN_LAB_TEST_A", "1");
        std::env::set_var(LAB_CLAIM_NEWER, "1");
        assert!(!lab_claim_newer());
        set_lab_claim_newer_for_this_thread(Some(true));
        assert!(!lab_claim_newer());
        set_lab_claim_newer_for_this_thread(None);
        return;
    }
    set_lab_claim_newer_for_this_thread(Some(true));
    assert!(lab_claim_newer());
    set_lab_claim_newer_for_this_thread(Some(false));
    assert!(!lab_claim_newer());
    set_lab_claim_newer_for_this_thread(None);
    assert_eq!(
        lab_claim_newer(),
        raven_core::pair_init::lab_test_a_enabled()
            && std::env::var(LAB_CLAIM_NEWER)
                .is_ok_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes")),
        "the variable, only with Lab Test A"
    );
}

/// The serving quotas (spec §7) on their own.
#[test]
fn quotas_count_requests_a_minute_and_bytes_a_day() {
    let t = Instant::now();
    let mut q = Quota::default();
    for _ in 0..SERVE_REQUESTS_PER_MINUTE {
        assert!(q.admit_request(t));
    }
    assert!(!q.admit_request(t + Duration::from_secs(59)));
    assert!(q.admit_request(t + MINUTE), "a minute later");
    assert!(q.admit_bytes(SERVE_BYTES_PER_DAY - 10, t));
    assert!(!q.admit_bytes(11, t + Duration::from_secs(3_600)));
    assert!(q.admit_bytes(10, t + Duration::from_secs(3_600)));
    assert!(q.admit_bytes(SERVE_BYTES_PER_DAY, t + DAY), "a day later");
}

#[cfg(debug_assertions)]
mod with_the_gate {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use raven_core::advisory::{Advisory, AdvisoryDraft, Entry, EntryKind};
    use raven_core::release_bundle::{FileMode, ManifestDraft, PackFile, THIS_TARGET};
    use raven_core::release_keys::test_keys::{key_set, signers};
    use raven_core::release_sign::sha256;
    use raven_core::security_gate::SecGate;
    use raven_core::tlog::{LogEntry, SthDraft};
    use raven_core::update_downloads::{
        incoming_dir, set_lab_auto_approve_for_this_thread, Downloads,
    };
    use raven_core::update_state::{STAGED_ADVISORY, STAGED_DIR};

    use super::*;

    const T0: u64 = 1_792_800_000_000;
    const DAY_MS: u64 = 86_400_000;
    const GATES: [SecGate; 3] = [
        SecGate::Advisory,
        SecGate::ReleaseBundle,
        SecGate::MeshUpdate,
    ];

    /// The update gates open for this thread, the lab auto-approval as
    /// asked and no newer claim (whatever the variables say); all back when
    /// dropped.
    struct Gates;

    impl Gates {
        fn open(auto_approve: bool) -> Gates {
            for g in GATES {
                security_gate::set_lab_for_this_thread(g, Some(true));
            }
            set_lab_auto_approve_for_this_thread(Some(auto_approve));
            set_lab_claim_newer_for_this_thread(Some(false));
            Gates
        }
    }

    impl Drop for Gates {
        fn drop(&mut self) {
            for g in GATES {
                security_gate::set_lab_for_this_thread(g, None);
            }
            set_lab_auto_approve_for_this_thread(None);
            set_lab_claim_newer_for_this_thread(None);
        }
    }

    /// The Raven project as the tests publish it (one growing log after the
    /// key set at entry 0, its head signed by keys 0 and 1).
    struct Project {
        log: Vec<LogEntry>,
        prev: [u8; 32],
    }

    impl Project {
        fn new() -> Self {
            Project {
                log: vec![LogEntry {
                    kind: EntryType::KeySet,
                    digest: key_set().digest(),
                    logged_at_ms: T0,
                }],
                prev: [0; 32],
            }
        }

        fn list(&mut self, kind: EntryType, digest: [u8; 32]) {
            let at = self.log.len() as u64;
            self.log.push(LogEntry {
                kind,
                digest,
                logged_at_ms: T0 + at * DAY_MS,
            });
        }

        fn snapshot(&self) -> Snapshot {
            let [a, b, _] = signers();
            let sth = SthDraft::of_entries(
                &self.log,
                T0 + self.log.len() as u64 * DAY_MS,
                key_set().digest(),
            )
            .sign(&[(0, &a), (1, &b)])
            .unwrap();
            Snapshot::new(self.log.clone(), sth).unwrap()
        }

        /// Advisory `serial` after the last one (`chain`: it names it), listed.
        fn advisory(&mut self, serial: u64, issued_day: u64, chain: bool) -> Advisory {
            self.advisory_with(serial, issued_day, chain, Vec::new())
        }

        /// [`Project::advisory`] with these entries.
        fn advisory_with(
            &mut self,
            serial: u64,
            issued_day: u64,
            chain: bool,
            entries: Vec<Entry>,
        ) -> Advisory {
            let [a, _, c] = signers();
            let advisory = AdvisoryDraft {
                serial,
                issued_at_ms: T0 + issued_day * DAY_MS,
                key_set_digest: key_set().digest(),
                prev_digest: if chain { self.prev } else { [0; 32] },
                entries,
            }
            .sign(&[(0, &a), (2, &c)])
            .unwrap();
            self.prev = advisory.digest();
            self.list(EntryType::Advisory, advisory.digest());
            advisory
        }

        /// A release for this computer with a `chunks`-chunk program and a
        /// document, signed and listed.
        fn release(&mut self, serial: u64, chunks: u64) -> Parts {
            let program: Vec<u8> = (0..chunks * u64::from(CHUNK_SIZE) - 1_000)
                .map(|j| (j % 251) as u8)
                .collect();
            let docs = b"Raven, the release notes.\n".to_vec();
            let mut draft = ManifestDraft {
                build_serial: serial,
                created_at_ms: T0 + serial * DAY_MS,
                key_set_digest: key_set().digest(),
                version: format!("1.{serial}.0"),
                target: THIS_TARGET.to_owned(),
                source_commit: [0xC0; 20],
                toolchain: "1.98.0".to_owned(),
                min_advisory_serial: 0,
                chunk_size: 0,
                payload_len: 0,
                payload_chunk_root: [0; 32],
                payload_sha256: [0; 32],
                files: Vec::new(),
                notes: "Faster links.".to_owned(),
            };
            let files = [
                ("bin/raven-node", FileMode::Executable, &program),
                ("docs/README.txt", FileMode::Regular, &docs),
            ];
            let pack: Vec<PackFile<'_>> = files
                .iter()
                .map(|(path, mode, bytes)| PackFile {
                    path,
                    mode: *mode,
                    bytes,
                    rebuild_sha256: sha256(bytes),
                })
                .collect();
            let payload = draft.fill_payload(&pack);
            let [a, b, _] = signers();
            let manifest = draft.sign(&[(0, &a), (1, &b)]).unwrap();
            self.list(EntryType::Manifest, manifest.digest());
            Parts {
                manifest,
                snapshot: self.snapshot(),
                advisory: None,
                payload,
            }
        }
    }

    /// One profile: its folder, its device key, its exchange's memory and
    /// the build reading its update state (the test keys, serial 1).
    struct Peer {
        dir: tempfile::TempDir,
        key: [u8; 32],
        shared: Mutex<Shared>,
        build: Build,
    }

    impl Peer {
        fn new(seed: u8) -> Peer {
            Peer {
                dir: tempfile::tempdir().unwrap(),
                key: [seed; 32],
                shared: Mutex::default(),
                build: Build {
                    key_set: Some(key_set()),
                    serial: 1,
                    floor: (0, [0; 32]),
                },
            }
        }

        fn dd(&self) -> &Path {
            self.dir.path()
        }

        fn node(&self) -> Node<'_> {
            Node::new(self.dd(), &self.build, &self.shared)
        }

        /// Its contact book: these friends, pinned (or not).
        fn befriend(&self, friends: &[(&Peer, bool)]) {
            let rows: Vec<String> = friends
                .iter()
                .map(|(f, pinned)| {
                    format!(
                        r#"{{"pub_hex":"{}","pinned":{pinned}}}"#,
                        hex::encode(f.key)
                    )
                })
                .collect();
            std::fs::write(
                self.dd().join("contacts.json"),
                format!("[{}]", rows.join(",")),
            )
            .unwrap();
        }

        fn state(&self) -> UpdateState {
            update_state::load_with(self.dd(), &self.build).unwrap()
        }

        fn rows(&self) -> Downloads {
            downloads::load(self.dd()).unwrap()
        }

        /// A notice imported from a file (`raven update import`).
        fn import_advisory(&self, advisory: &Advisory, log: &Snapshot) {
            update_state::accept_advisory_with(
                self.dd(),
                &self.build,
                advisory.bytes(),
                &log.encode(),
                Origin::IMPORTED,
            )
            .unwrap();
        }

        /// A release imported and staged as `raven update import` does it
        /// (the log first, then `updates/staged/<serial>/`).
        fn stage(&self, parts: &Parts) {
            update_state::accept_log_with(
                self.dd(),
                &self.build,
                &parts.snapshot.encode(),
                Origin::IMPORTED,
            )
            .unwrap();
            let dir = self
                .dd()
                .join(STAGED_DIR)
                .join(parts.manifest.build_serial.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(STAGED_MANIFEST), parts.manifest.bytes()).unwrap();
            std::fs::write(dir.join(STAGED_SNAPSHOT), parts.snapshot.encode()).unwrap();
            if let Some(advisory) = &parts.advisory {
                std::fs::write(dir.join(STAGED_ADVISORY), advisory.bytes()).unwrap();
            }
            for (i, f) in parts.manifest.files.iter().enumerate() {
                std::fs::write(
                    dir.join(update_state::staged_file_name(i, &f.path)),
                    &parts.payload[f.range()],
                )
                .unwrap();
            }
        }

        /// Its HAVE for `to` (none unless `to` is a pinned contact).
        fn have_for(&self, to: &Peer, carrier: OutboxCarrier) -> Option<Have> {
            let frame = self.node().have_frame(&to.key, carrier)?;
            match rup1::decode(&frame) {
                Ok((_, Rup1Msg::Have(have))) => Some(have),
                other => panic!("not a HAVE: {other:?}"),
            }
        }
    }

    /// A link `dialer` -> `listener` (spec §2.2): the listener's HAVE, then
    /// the dialer's, each taken by the other side. Whether each side now has
    /// something to fetch.
    fn link(dialer: &Peer, listener: &Peer, now: Instant) -> (bool, bool) {
        let carrier = OutboxCarrier::Lan;
        let mut work = (false, false);
        if let Some(have) = listener.have_for(dialer, carrier) {
            work.0 = dialer.node().take_have(&listener.key, have, now);
        }
        if let Some(have) = dialer.have_for(listener, carrier) {
            work.1 = listener.node().take_have(&dialer.key, have, now);
        }
        work
    }

    /// What a follow-up dial meets: the other profiles' listeners, some
    /// unreachable, one that flips a byte of every chunk, one whose link
    /// drops after some frames.
    struct Net<'a> {
        peers: Vec<&'a Peer>,
        from: &'a Peer,
        now: Instant,
        down: Vec<[u8; 32]>,
        forger: Option<[u8; 32]>,
        /// (friend, frames of its replies that arrive before the drop).
        cut: Option<([u8; 32], usize)>,
        dials: Vec<[u8; 32]>,
        chunks_served: AtomicUsize,
    }

    impl<'a> Net<'a> {
        fn new(from: &'a Peer, peers: &[&'a Peer], now: Instant) -> Self {
            Net {
                peers: peers.to_vec(),
                from,
                now,
                down: Vec::new(),
                forger: None,
                cut: None,
                dials: Vec::new(),
                chunks_served: AtomicUsize::new(0),
            }
        }

        fn dial(
            &mut self,
            peer: &[u8; 32],
            frames: &[Vec<u8>],
            _bundle: bool,
        ) -> Result<(Vec<Vec<u8>>, OutboxCarrier), String> {
            self.dials.push(*peer);
            if self.down.contains(peer) {
                return Err("no route".into());
            }
            let target = self
                .peers
                .iter()
                .find(|p| p.key == *peer)
                .ok_or("no such peer")?;
            // The listener's RLB1 offer comes first in a dial's replies.
            let mut replies = vec![b"RLB1 offer".to_vec()];
            for frame in frames {
                let (answers, _) = target.node().listener_frame(
                    &self.from.key,
                    OutboxCarrier::Lan,
                    frame,
                    false,
                    self.now,
                );
                for mut answer in answers {
                    if let Ok((id, Rup1Msg::Chunk(mut chunk))) = rup1::decode(&answer) {
                        self.chunks_served.fetch_add(1, Ordering::Relaxed);
                        if self.forger == Some(*peer) {
                            chunk.bytes[0] ^= 1;
                            answer = rup1::encode(&id, &Rup1Msg::Chunk(chunk)).unwrap();
                        }
                    }
                    replies.push(answer);
                }
            }
            if let Some((who, keep)) = self.cut {
                if who == *peer {
                    // The link dropped: what arrived before is the answer.
                    replies.truncate(keep + 1);
                    self.cut = None;
                    self.down.push(who);
                }
            }
            Ok((replies, OutboxCarrier::Lan))
        }
    }

    fn pass(peer: &Peer, net: &mut Net<'_>) -> PassReport {
        let now = net.now;
        peer.node().pass(now, &mut |p, f, b| net.dial(p, f, b))
    }

    /// Every file below `dir`, relative, `/`-separated.
    fn files_below(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut todo = vec![PathBuf::new()];
        while let Some(rel) = todo.pop() {
            for entry in std::fs::read_dir(dir.join(&rel)).unwrap().flatten() {
                let rel = rel.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    todo.push(rel);
                } else {
                    out.push(PathBuf::from(rel.to_string_lossy().replace('\\', "/")));
                }
            }
        }
        out
    }

    /// The payload a folder holds, read back.
    fn incoming_payload(peer: &Peer, digest: &[u8; 32]) -> Vec<u8> {
        std::fs::read(incoming_dir(peer.dd(), digest).join(INCOMING_PAYLOAD)).unwrap()
    }

    /// An older build sets no bit 10 (spec §9): no HAVE goes to it and
    /// nothing is asked of it, whichever end of the link it is; a pinned
    /// peer that set bit 10 gets our HAVE.
    #[test]
    fn an_old_peer_never_gets_a_rup1_frame() {
        use raven_core::internet::{hello_caps, LinkFeatures};
        let _gates = Gates::open(false);
        let _build = BuildForTest::set(test_build());
        let me = Peer::new(0x01);
        let old = Peer::new(0x02);
        me.befriend(&[(&old, true)]);
        let ask = rup1::encode(&[1, 2, 3, 4], &Rup1Msg::GetLog).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let old_hello = hello_caps(LinkFeatures::RRH1.with(LinkFeatures::PAD1, true));
            for listener in [true, false] {
                let mut link = UpdateLink::inet(
                    me.dd(),
                    OutboxCarrier::Internet,
                    listener,
                    old.key,
                    true,
                    old_hello,
                );
                assert_eq!(link.outgoing().await, None, "listener {listener}");
                assert!(!link.may_ask() && !link.expects_have());
                assert!(check_requests(std::slice::from_ref(&ask), &link).is_err());
            }
            // LAN: an old dialer's message 3 lacks bit 10; an old listener
            // sends no HAVE, so a new dialer asks nothing.
            let mut listener = UpdateLink::lan_listener(
                me.dd(),
                old.key,
                &raven_core::route_hints::rlx1_payload(raven_core::CAP_LINK_RRH1),
            );
            assert_eq!(listener.outgoing().await, None);
            let dialer = UpdateLink::lan_dialer(me.dd(), old.key, true);
            assert!(dialer.expects_have() && !dialer.may_ask());
            assert!(check_requests(std::slice::from_ref(&ask), &dialer).is_err());
            let mut new = UpdateLink::inet(
                me.dd(),
                OutboxCarrier::Internet,
                true,
                old.key,
                true,
                hello_caps(LinkFeatures::RUP1),
            );
            let have = new.outgoing().await.expect("our HAVE");
            assert!(matches!(rup1::decode(&have), Ok((_, Rup1Msg::Have(_)))));
        });
    }

    #[test]
    fn a_notice_goes_from_a_to_b_to_c_by_itself() {
        let _gates = Gates::open(false);
        let (a, b, c) = (Peer::new(0xA1), Peer::new(0xB1), Peer::new(0xC1));
        a.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true), (&c, true)]);
        c.befriend(&[(&b, true)]);
        let mut project = Project::new();
        let notice = project.advisory(1, 1, true);
        a.import_advisory(&notice, &project.snapshot());
        let now = Instant::now();
        // B dials A (to deliver a message, say): A's HAVE shows a notice B
        // lacks, so B has work; A has none from B's empty HAVE.
        assert_eq!(link(&b, &a, now), (true, false));
        let mut net = Net::new(&b, &[&a], now);
        let report = pass(&b, &mut net);
        assert_eq!((report.dials, report.notices), (1, 1));
        assert_eq!(b.state().advisory().map(|n| n.serial), Some(1));
        assert_eq!(b.state().log().unwrap().entries().len(), 2);
        // Nothing more to ask A for.
        assert_eq!(pass(&b, &mut net).dials, 0);
        // C links with B later: B offers it onward, C takes it.
        let b_have = b.have_for(&c, OutboxCarrier::Lan).unwrap();
        assert_eq!((b_have.adv_serial, b_have.log_size), (1, 2));
        assert_eq!(link(&c, &b, now), (true, false));
        let mut net = Net::new(&c, &[&b], now);
        assert_eq!(pass(&c, &mut net).notices, 1);
        assert_eq!(
            c.state().advisory().map(|n| n.digest()),
            Some(notice.digest())
        );
        let status = c.node().status().unwrap();
        assert_eq!((status.advisory_serial, status.log_size), (1, 2));
        assert!(!status.frozen);
        // A longer log alone travels too.
        project.list(EntryType::Manifest, [0x55; 32]);
        let longer = project.snapshot();
        update_state::accept_log_with(a.dd(), &a.build, &longer.encode(), Origin::IMPORTED)
            .unwrap();
        assert_eq!(link(&b, &a, now), (true, false));
        let mut net = Net::new(&b, &[&a], now);
        assert_eq!(pass(&b, &mut net).notices, 1);
        assert_eq!(b.state().log().unwrap().entries().len(), 3);
    }

    /// The lab dry run of the suite retirement procedure (step P6.50,
    /// `docs/design/2026-10-suite-retirement.md` §6.3): a notice signed by the
    /// test keys that marks `pairinit/1/1` DEPRECATED goes A -> B -> C over
    /// RUP1. Every profile shows the warning, and nothing else changes: no
    /// link, PairInit, session or feature refused, no release floor, no
    /// text, no contact touched, no floor written, V1 still chosen.
    #[test]
    fn a_deprecated_pairinit_notice_only_warns_at_every_hop() {
        use raven_core::advisory::Severity;
        use raven_core::capability_floor::{self, CAPABILITY_FLOOR_FILE};
        use raven_core::suite_policy::{self, Policy, Status, V1Sessions};
        use raven_core::suite_registry::{FEATURES, PAIRINIT_V1_SUITE1, SUITES};
        let _gates = Gates::open(false);
        let (a, b, c) = (Peer::new(0xA9), Peer::new(0xB9), Peer::new(0xC9));
        a.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true), (&c, true)]);
        c.befriend(&[(&b, true)]);
        let peers = [&a, &b, &c];
        let book = |p: &Peer| std::fs::read(p.dd().join("contacts.json")).unwrap();
        let books: Vec<Vec<u8>> = peers.iter().map(|p| book(p)).collect();
        let mut project = Project::new();
        let deprecated = Entry {
            kind: EntryKind::SuiteStatus,
            severity: Severity::Deprecated,
            target: PAIRINIT_V1_SUITE1.to_owned(),
            arg: Vec::new(),
            text_id: 0,
        };
        let notice = project.advisory_with(1, 1, true, vec![deprecated]);
        a.import_advisory(&notice, &project.snapshot());
        let now = Instant::now();
        assert_eq!(link(&b, &a, now), (true, false));
        assert_eq!(pass(&b, &mut Net::new(&b, &[&a], now)).notices, 1);
        assert_eq!(link(&c, &b, now), (true, false));
        assert_eq!(pass(&c, &mut Net::new(&c, &[&b], now)).notices, 1);
        for (peer, before) in peers.into_iter().zip(&books) {
            let state = peer.state();
            assert_eq!(state.advisory().map(|n| n.digest()), Some(notice.digest()));
            let policy = Policy::of_state(&state);
            assert_eq!(
                policy.lines(T0 + 4 * DAY_MS),
                [
                    "Security notices from the Raven project: #1 (issued about 3 days ago).",
                    "Security notice #1: an older security method is being retired \
                     (pairinit/1/1). Raven still uses it for now; update Raven when a newer \
                     version is out."
                ]
            );
            for suite in SUITES {
                let status = policy.status(suite.id);
                if suite.id == PAIRINIT_V1_SUITE1 {
                    assert_eq!(status, Status::Deprecated);
                } else {
                    assert_eq!(status, Status::Allowed, "{}", suite.id);
                }
            }
            assert!(FEATURES.iter().all(|f| policy.allows(f.id)));
            assert_eq!(policy.broken_link_suite(), None);
            assert!(policy.pair_init_allowed() && policy.session_allowed());
            assert!(!policy.below_release_floor() && policy.notice.is_none() && !policy.frozen);
            assert_eq!(policy.profile_status(1), Status::Deprecated);
            assert_eq!(policy.profile_refusal(1), None);
            assert_eq!(policy.v1_sessions(None), V1Sessions::Go);
            // Every consult point under it lets everything through.
            suite_policy::set_policy_for_this_thread(Some(policy));
            assert_eq!(suite_policy::check_link(), Ok(()));
            assert_eq!(suite_policy::check_pair_init(), Ok(()));
            assert!(suite_policy::session_allowed());
            assert!(FEATURES.iter().all(|f| suite_policy::hold_allows(f.id)));
            assert_eq!(suite_policy::v1_sessions(None), V1Sessions::Go);
            suite_policy::set_policy_for_this_thread(None);
            // Nothing about contacts: the book as it was, no floor, V1 still
            // the session profile.
            assert_eq!(&book(peer), before);
            assert!(!peer.dd().join(CAPABILITY_FLOOR_FILE).exists());
            let via = Via::Dial(OutboxCarrier::Lan);
            assert_eq!(
                capability_floor::require_profile(peer.dd(), &[0x5E; 32], &[1], via),
                Ok(1)
            );
            for path in files_below(peer.dd()) {
                let name = path.to_string_lossy();
                assert!(
                    name.starts_with("updates/")
                        || name.starts_with(".at_rest.")
                        || name == "contacts.json",
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn a_release_goes_from_a_to_b_to_c_with_the_lab_approval() {
        let _gates = Gates::open(true);
        let (a, b, c) = (Peer::new(0xA2), Peer::new(0xB2), Peer::new(0xC2));
        a.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true), (&c, true)]);
        c.befriend(&[(&b, true)]);
        let mut project = Project::new();
        let release = project.release(5, 20);
        let digest = release.manifest.digest();
        a.stage(&release);
        let now = Instant::now();
        // A's HAVE offers the staged release; B (build 1) has a row for it,
        // approved by the lab switch, and work to do.
        let offer = &a.have_for(&b, OutboxCarrier::Lan).unwrap().offers[0];
        assert_eq!((offer.build_serial, offer.manifest_digest), (5, digest));
        assert!(link(&b, &a, now).0);
        assert_eq!(b.rows().row(&digest).unwrap().state, RowState::Approved);
        let mut net = Net::new(&b, &[&a], now);
        let report = pass(&b, &mut net);
        // A's log first (it lists the release), then the manifest, then 20
        // chunks at most 16 a dial.
        assert_eq!(
            (report.notices, report.chunks, report.completed),
            (1, 20, 1)
        );
        assert_eq!(report.dials, 4, "{:?}", net.dials);
        let row = b.rows().row(&digest).unwrap().clone();
        assert_eq!(row.state, RowState::Complete);
        assert_eq!(
            (row.version.as_deref(), row.chunks_have, row.chunks_total),
            (Some("1.5.0"), 20, 20)
        );
        assert_eq!(incoming_payload(&b, &digest), release.payload);
        assert!(incoming_dir(b.dd(), &digest)
            .join(INCOMING_VERIFIED)
            .exists());
        assert_eq!(b.node().status().unwrap().ready, 1);
        // B now serves it to C, which downloads it from B.
        let offers = b.have_for(&c, OutboxCarrier::Lan).unwrap().offers;
        assert_eq!(
            offers.iter().map(|o| o.manifest_digest).collect::<Vec<_>>(),
            vec![digest]
        );
        assert!(link(&c, &b, now).0);
        let mut net = Net::new(&c, &[&b], now);
        assert_eq!(pass(&c, &mut net).completed, 1);
        assert_eq!(incoming_payload(&c, &digest), release.payload);
        assert_eq!(c.rows().row(&digest).unwrap().state, RowState::Complete);
        // The exchange wrote nothing outside `updates/` (besides the locks
        // its sealed files take): no program, nothing run.
        for peer in [&b, &c] {
            for path in files_below(peer.dd()) {
                let name = path.to_string_lossy();
                assert!(
                    name.starts_with("updates/")
                        || name.starts_with(".at_rest.")
                        || name == "contacts.json",
                    "{name}"
                );
            }
        }
        // Bluetooth carries notices only: no offers there.
        assert!(b
            .have_for(&c, OutboxCarrier::Nearby)
            .unwrap()
            .offers
            .is_empty());
    }

    #[test]
    fn a_release_waits_for_the_download_approval() {
        let _gates = Gates::open(false);
        let (a, b) = (Peer::new(0xA3), Peer::new(0xB3));
        a.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true)]);
        let mut project = Project::new();
        let release = project.release(5, 2);
        let digest = release.manifest.digest();
        a.stage(&release);
        let now = Instant::now();
        // Offered, not approved: only A's log is fetched (it lists the
        // release), nothing of the release.
        link(&b, &a, now);
        let row = b.rows().row(&digest).unwrap().clone();
        assert_eq!(
            (row.state, row.from.clone()),
            (RowState::Offered, vec![a.key])
        );
        assert_eq!(b.node().status().unwrap().offers, 1);
        let mut net = Net::new(&b, &[&a], now);
        let report = pass(&b, &mut net);
        assert_eq!((report.dials, report.notices, report.chunks), (1, 1, 0));
        assert!(!incoming_dir(b.dd(), &digest).exists());
        // The person approves (`raven update download`): fetched.
        downloads::approve(b.dd(), &hex::encode(digest)[..8], T0)
            .unwrap()
            .unwrap();
        assert_eq!(pass(&b, &mut net).completed, 1);
        // An offer of an older build than this one is no row.
        let old = project.release(1, 1);
        let (c, d) = (Peer::new(0xC3), Peer::new(0xD3));
        c.befriend(&[(&d, true)]);
        d.befriend(&[(&c, true)]);
        c.stage(&old);
        link(&d, &c, now);
        assert!(
            d.rows().rows.is_empty(),
            "build 1 is not newer than build 1"
        );
    }

    #[test]
    fn a_forged_chunk_is_refused_and_fetched_from_the_other_friend() {
        let _gates = Gates::open(true);
        let (a, d, b) = (Peer::new(0xA4), Peer::new(0xD4), Peer::new(0xB4));
        a.befriend(&[(&b, true)]);
        d.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true), (&d, true)]);
        let mut project = Project::new();
        let release = project.release(5, 40);
        let digest = release.manifest.digest();
        a.stage(&release);
        d.stage(&release);
        let now = Instant::now();
        link(&b, &d, now);
        link(&b, &a, now);
        // A offered it last, so A is asked first (the manifest), then D (16
        // chunks), then A again: its chunks arrive with a byte changed.
        assert_eq!(b.rows().row(&digest).unwrap().from, vec![a.key, d.key]);
        let mut net = Net::new(&b, &[&a, &d], now);
        net.forger = Some(a.key);
        let report = pass(&b, &mut net);
        assert_eq!(report.completed, 1, "{:?}", net.dials);
        assert_eq!(incoming_payload(&b, &digest), release.payload);
        assert_eq!(
            b.node().forged_counts(),
            (0, 1),
            "one forged chunk, then A is left out"
        );
        assert_eq!(b.node().status().unwrap().quarantined, 1);
        // D's log first (A's is the same then), A's manifest, D's chunks,
        // A's forged ones, then D's only.
        assert_eq!(&net.dials[..4], &[d.key, a.key, d.key, a.key]);
        assert!(
            net.dials[4..].iter().all(|p| *p == d.key),
            "{:?}",
            net.dials
        );
        assert!(lock(&b.shared).bad_copy(&a.key, &digest, now));
    }

    #[test]
    fn a_dropped_link_resumes_from_what_arrived_with_the_other_friend() {
        let _gates = Gates::open(true);
        let (a, d, b) = (Peer::new(0xA5), Peer::new(0xD5), Peer::new(0xB5));
        a.befriend(&[(&b, true)]);
        d.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true), (&d, true)]);
        let mut project = Project::new();
        let release = project.release(5, 12);
        let digest = release.manifest.digest();
        a.stage(&release);
        d.stage(&release);
        let now = Instant::now();
        link(&b, &a, now);
        // Only A is known yet. Its log and the manifest come; the link of
        // the first chunk dial drops after 5 chunks, and A stays
        // unreachable.
        let mut net = Net::new(&b, &[&a, &d], now);
        let mut calls = 0;
        let report = b.node().pass(now, &mut |p, f, bundle| {
            calls += 1;
            if calls == 3 {
                net.cut = Some((*p, 5));
            }
            net.dial(p, f, bundle)
        });
        assert_eq!((report.chunks, report.completed), (5, 0), "{:?}", net.dials);
        let row = b.rows().row(&digest).unwrap().clone();
        assert_eq!(
            (row.state, row.chunks_have, row.chunks_total),
            (RowState::Downloading, 5, 12)
        );
        // raven-node restarts (its memory is gone, the folder stays); D
        // offers the same release; A is still unreachable.
        let b = Peer {
            shared: Mutex::default(),
            ..b
        };
        link(&b, &d, now);
        assert_eq!(b.rows().row(&digest).unwrap().from, vec![d.key, a.key]);
        let mut net = Net::new(&b, &[&a, &d], now + Duration::from_secs(120));
        net.down.push(a.key);
        let report = pass(&b, &mut net);
        assert_eq!(
            (report.chunks, report.completed),
            (7, 1),
            "only what was missing"
        );
        assert_eq!(net.chunks_served.load(Ordering::Relaxed), 7);
        assert_eq!(incoming_payload(&b, &digest), release.payload);
    }

    #[test]
    fn serving_answers_busy_rate_limited_and_policy_denied() {
        let _gates = Gates::open(false);
        let (a, b, stranger) = (Peer::new(0xA6), Peer::new(0xB6), Peer::new(0x5E));
        a.befriend(&[(&b, true), (&stranger, false)]);
        let mut project = Project::new();
        let notice = project.advisory(1, 1, true);
        a.import_advisory(&notice, &project.snapshot());
        let release = project.release(5, 3);
        let digest = release.manifest.digest();
        a.stage(&release);
        let now = Instant::now();
        let node = a.node();
        let ask = |from: &Peer, msg: &Rup1Msg, carrier: OutboxCarrier, at: Instant| {
            let frame = rup1::encode(&[9, 9, 9, 9], msg).unwrap();
            node.listener_frame(&from.key, carrier, &frame, false, at)
                .0
                .into_iter()
                .map(|f| rup1::decode(&f).unwrap().1)
                .collect::<Vec<_>>()
        };
        let lan = OutboxCarrier::Lan;
        // An unverified contact (or a stranger): POLICY_DENIED, and no HAVE.
        assert_eq!(
            ask(&stranger, &Rup1Msg::GetLog, lan, now),
            vec![Rup1Msg::Error(ErrorCode::PolicyDenied)]
        );
        assert!(a.have_for(&stranger, lan).is_none());
        // Bluetooth: notices yes, releases no.
        assert!(matches!(
            ask(&b, &Rup1Msg::GetAdvisory, OutboxCarrier::Nearby, now)[..],
            [Rup1Msg::Advisory { .. }]
        ));
        assert_eq!(
            ask(
                &b,
                &Rup1Msg::GetManifest {
                    manifest_digest: digest
                },
                OutboxCarrier::Nearby,
                now
            ),
            vec![Rup1Msg::Error(ErrorCode::PolicyDenied)]
        );
        // Six requests a minute; the seventh is RATE_LIMITED (the two above
        // counted).
        for _ in 0..4 {
            assert!(matches!(
                ask(&b, &Rup1Msg::GetLog, lan, now)[..],
                [Rup1Msg::Log { .. }]
            ));
        }
        assert_eq!(
            ask(&b, &Rup1Msg::GetLog, lan, now),
            vec![Rup1Msg::Error(ErrorCode::RateLimited)]
        );
        let later = now + MINUTE;
        // Two at a time overall: a third is BUSY.
        lock(&a.shared).serving = SERVE_AT_ONCE;
        assert_eq!(
            ask(&b, &Rup1Msg::GetLog, lan, later),
            vec![Rup1Msg::Error(ErrorCode::Busy)]
        );
        lock(&a.shared).serving = 0;
        // 128 MiB a day: past it, CHUNKS_END says RATE_LIMITED after what fit.
        let chunk = |first, count| Rup1Msg::GetChunks {
            manifest_digest: digest,
            first,
            count,
        };
        lock(&a.shared).quotas.get_mut(&b.key).unwrap().day_bytes =
            SERVE_BYTES_PER_DAY - u64::from(CHUNK_SIZE);
        let got = ask(&b, &chunk(0, 3), lan, later);
        assert!(matches!(got[0], Rup1Msg::Chunk(_)), "{got:?}");
        assert_eq!(
            got[1],
            Rup1Msg::ChunksEnd {
                stopped: Some(ErrorCode::RateLimited),
                sent: 1
            }
        );
        // What it does not hold: NOT_FOUND.
        let other = Rup1Msg::GetManifest {
            manifest_digest: [0x77; 32],
        };
        assert_eq!(
            ask(&b, &other, lan, later),
            vec![Rup1Msg::Error(ErrorCode::NotFound)]
        );
        assert_eq!(
            ask(&b, &chunk(9, 1), lan, later),
            vec![Rup1Msg::Error(ErrorCode::NotFound)],
            "past the last chunk"
        );
        // A malformed request and an unknown op get their refusals; a reply
        // op gets nothing.
        let bad = [
            &rup1::RUP1_MAGIC[..],
            &[1, rup1::OP_GET_CHUNKS, 1, 2, 3, 4],
            &[0; 3],
        ]
        .concat();
        let (got, _) = node.listener_frame(&b.key, lan, &bad, false, later + MINUTE);
        assert_eq!(
            rup1::decode(&got[0]).unwrap().1,
            Rup1Msg::Error(ErrorCode::Malformed)
        );
        let reply = rup1::encode(&[1; 4], &Rup1Msg::Error(ErrorCode::Busy)).unwrap();
        assert!(node
            .listener_frame(&b.key, lan, &reply, false, later)
            .0
            .is_empty());
        // Serving off in the policy: releases are denied, notices still go.
        let mut policy = raven_core::node_policy::load_policy(a.dd());
        policy.update_serve = false;
        raven_core::node_policy::save_policy(a.dd(), &policy).unwrap();
        let day = later + DAY;
        assert_eq!(
            ask(&b, &chunk(0, 1), lan, day),
            vec![Rup1Msg::Error(ErrorCode::PolicyDenied)]
        );
        assert!(a.have_for(&b, lan).unwrap().offers.is_empty());
    }

    #[test]
    fn equivocating_notices_and_a_split_log_freeze_the_state() {
        let _gates = Gates::open(false);
        let (a, d, b) = (Peer::new(0xA7), Peer::new(0xD7), Peer::new(0xB7));
        a.befriend(&[(&b, true)]);
        d.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true), (&d, true)]);
        // One log lists two different notices #1: the project signed both
        // (a stolen key pair, say).
        let mut project = Project::new();
        let first = project.advisory(1, 1, false);
        let other = project.advisory(1, 2, false);
        let log = project.snapshot();
        a.import_advisory(&first, &log);
        d.import_advisory(&other, &log);
        let now = Instant::now();
        link(&b, &a, now);
        let mut net = Net::new(&b, &[&a, &d], now);
        assert_eq!(pass(&b, &mut net).notices, 1);
        assert!(b.state().frozen().is_none());
        // D's HAVE names another #1: fetched, and the state freezes.
        assert!(link(&b, &d, now).0);
        pass(&b, &mut net);
        let state = b.state();
        let evidence = state.frozen().expect("frozen");
        assert_eq!(evidence.reason, update_state::FreezeReason::Equivocation);
        assert!(b.node().status().unwrap().frozen);
        // Frozen: no download is asked for, whatever is offered.
        let release = project.release(5, 1);
        a.stage(&release);
        link(&b, &a, now);
        assert!(b.rows().rows.is_empty());

        // A split view: two signed logs of one size that differ.
        let (e, f, g) = (Peer::new(0xE7), Peer::new(0xF7), Peer::new(0x97));
        e.befriend(&[(&g, true)]);
        f.befriend(&[(&g, true)]);
        g.befriend(&[(&e, true), (&f, true)]);
        let mut left = Project::new();
        left.list(EntryType::Manifest, [1; 32]);
        let mut right = Project::new();
        right.list(EntryType::Manifest, [2; 32]);
        for (peer, project) in [(&e, &left), (&f, &right)] {
            update_state::accept_log_with(
                peer.dd(),
                &peer.build,
                &project.snapshot().encode(),
                Origin::IMPORTED,
            )
            .unwrap();
        }
        link(&g, &e, now);
        let mut net = Net::new(&g, &[&e, &f], now);
        assert_eq!(pass(&g, &mut net).notices, 1);
        assert!(link(&g, &f, now).0, "same size, another root");
        pass(&g, &mut net);
        assert_eq!(
            g.state().frozen().map(|e| e.reason),
            Some(update_state::FreezeReason::SplitView)
        );
    }

    /// The lab's friend stuck on notice #1 that claims #2 (P6.51, C88): B,
    /// which holds #2, asks it because the digest differs and is answered
    /// with #1, which its update state refuses as a rollback. Nothing is
    /// stored, frozen or quarantined, and that friend is not parked.
    #[test]
    fn a_friend_claiming_a_newer_notice_hands_over_a_rollback_that_is_refused() {
        let _gates = Gates::open(false);
        let (a, f, b) = (Peer::new(0xAA), Peer::new(0xFA), Peer::new(0xBA));
        a.befriend(&[(&b, true)]);
        f.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true), (&f, true)]);
        let mut project = Project::new();
        let first = project.advisory(1, 1, true);
        let second = project.advisory(2, 2, true);
        let log = project.snapshot();
        f.import_advisory(&first, &log);
        a.import_advisory(&second, &log);
        let now = Instant::now();
        link(&b, &a, now);
        let mut net = Net::new(&b, &[&a, &f], now);
        assert_eq!(pass(&b, &mut net).notices, 1);
        assert_eq!(b.state().advisory().map(|a| a.serial), Some(2));
        set_lab_claim_newer_for_this_thread(Some(true));
        let claim = f.have_for(&b, OutboxCarrier::Lan).expect("F's HAVE");
        assert_eq!(
            (claim.adv_serial, claim.adv_digest),
            (2, first.digest()),
            "the next serial, the digest of the one it holds"
        );
        assert!(link(&b, &f, now).0, "B asks: same serial, another digest");
        set_lab_claim_newer_for_this_thread(Some(false));
        let report = pass(&b, &mut net);
        assert_eq!((report.dials, report.notices), (1, 0));
        let state = b.state();
        assert_eq!(state.advisory().map(|a| a.digest()), Some(second.digest()));
        assert!(state.frozen().is_none());
        assert_eq!(b.node().forged_counts(), (0, 0));
        assert_eq!(b.node().status().unwrap().quarantined, 0);
        assert!(!lock(&b.shared).parked(&f.key, now));
    }

    #[test]
    fn a_forged_notice_goes_to_quarantine_and_its_friend_waits_a_day() {
        let _gates = Gates::open(false);
        let (a, b) = (Peer::new(0xA8), Peer::new(0xB8));
        a.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true)]);
        let mut project = Project::new();
        let notice = project.advisory(1, 1, true);
        a.import_advisory(&notice, &project.snapshot());
        let now = Instant::now();
        link(&b, &a, now);
        // A's reply is changed on the way: one byte of the notice.
        let mut net = Net::new(&b, &[&a], now);
        let report = b.node().pass(now, &mut |p, frames, bundle| {
            let (mut replies, carrier) = net.dial(p, frames, bundle)?;
            if let Some(last) = replies.last_mut() {
                let n = last.len();
                last[n - 120] ^= 1;
            }
            Ok((replies, carrier))
        });
        assert_eq!((report.dials, report.notices), (1, 0));
        assert!(b.state().advisory().is_none());
        assert_eq!(b.node().forged_counts(), (1, 0));
        assert_eq!(b.node().status().unwrap().quarantined, 1);
        // Within the day A is not asked again, whatever its HAVE says.
        link(&b, &a, now + Duration::from_secs(3_600));
        lock(&b.shared).fetched.clear();
        let mut net = Net::new(&b, &[&a], now + Duration::from_secs(3_600));
        assert_eq!(pass(&b, &mut net).dials, 0);
        // A day later it is.
        link(&b, &a, now + DAY);
        let mut net = Net::new(&b, &[&a], now + DAY);
        assert_eq!(pass(&b, &mut net).notices, 1);
    }

    #[test]
    fn storage_is_capped_and_pruned() {
        let _gates = Gates::open(false);
        let p = Peer::new(0xA9);
        let wall = T0;
        // Quarantine: at most 64 MiB, oldest first, 7 days.
        let big = vec![0u8; (MAX_QUARANTINE_BYTES / 2) as usize];
        assert!(quarantine(p.dd(), "chunk", &big, wall));
        assert!(quarantine(p.dd(), "chunk", &big, wall + 1));
        assert!(quarantine(p.dd(), "chunk", &big, wall + 2));
        let items = quarantine_items(p.dd());
        assert_eq!(
            items.iter().map(|i| i.1).collect::<Vec<_>>(),
            vec![wall + 1, wall + 2]
        );
        assert!(!quarantine(
            p.dd(),
            "payload",
            &vec![0; MAX_QUARANTINE_BYTES as usize + 1],
            wall
        ));
        for (path, ..) in &items {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            assert!(name.contains("-chunk-") && !name.contains('.'), "{name}");
        }
        prune_quarantine(p.dd(), wall + QUARANTINE_AGE_MS + 1, 0);
        assert_eq!(quarantine_items(p.dd()).len(), 1);
        prune_quarantine(p.dd(), wall + QUARANTINE_AGE_MS + 2, 0);
        assert!(quarantine_items(p.dd()).is_empty());
        // Incoming: a folder no row names goes after an hour, one untouched
        // for 7 days goes whatever its row.
        let orphan = incoming_dir(p.dd(), &[0xEE; 32]);
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::write(orphan.join(INCOMING_CHUNKS), [0]).unwrap();
        let touched = touched_ms(&orphan);
        prune_incoming(p.dd(), touched + ORPHAN_AGE_MS - 1, None);
        assert!(orphan.exists());
        prune_incoming(p.dd(), touched + ORPHAN_AGE_MS, None);
        assert!(!orphan.exists());
        let digest = [0xDD; 32];
        downloads::change(p.dd(), |rows| {
            rows.note_offer(
                &[1; 32],
                &Offer {
                    build_serial: 9,
                    target: THIS_TARGET.into(),
                    manifest_digest: digest,
                    payload_len: 10,
                },
                T0,
            )
        })
        .unwrap();
        let kept = incoming_dir(p.dd(), &digest);
        std::fs::create_dir_all(&kept).unwrap();
        std::fs::write(kept.join(INCOMING_CHUNKS), [0]).unwrap();
        let touched = touched_ms(&kept);
        prune_incoming(p.dd(), touched + ORPHAN_AGE_MS, None);
        assert!(kept.exists(), "its row names it");
        prune_incoming(p.dd(), touched + INCOMING_IDLE_MS, None);
        assert!(!kept.exists(), "7 idle days");
    }

    /// Phase 6 review updates-protocol-2: while frozen nothing is asked of
    /// a friend (no advisory lifts a freeze), so a friend whose HAVE claims
    /// a newer notice is neither dialled nor blamed.
    #[test]
    fn a_frozen_node_asks_its_friends_nothing() {
        let _gates = Gates::open(false);
        let (a, d, f, b) = (
            Peer::new(0xA0),
            Peer::new(0xD0),
            Peer::new(0xF0),
            Peer::new(0xB0),
        );
        for p in [&a, &d, &f] {
            p.befriend(&[(&b, true)]);
        }
        b.befriend(&[(&a, true), (&d, true), (&f, true)]);
        let mut project = Project::new();
        let first = project.advisory(1, 1, false);
        let other = project.advisory(1, 2, false);
        let later = project.advisory(2, 3, true);
        let log = project.snapshot();
        a.import_advisory(&first, &log);
        d.import_advisory(&other, &log);
        f.import_advisory(&later, &log);
        let now = Instant::now();
        link(&b, &a, now);
        pass(&b, &mut Net::new(&b, &[&a], now));
        link(&b, &d, now);
        pass(&b, &mut Net::new(&b, &[&d], now));
        assert!(b.state().frozen().is_some(), "two notices #1: frozen");
        // F claims #2: nothing is due, nothing is asked.
        assert!(!link(&b, &f, now).0, "no work while frozen");
        lock(&b.shared).due.push(f.key);
        let report = pass(&b, &mut Net::new(&b, &[&f], now));
        assert_eq!((report.dials, report.notices), (0, 0));
        assert_eq!(b.node().forged_counts(), (0, 0));
        assert_eq!(b.node().status().unwrap().quarantined, 0);
        let s = lock(&b.shared);
        assert!(!s.parked(&f.key, now) && !s.notice_parked.contains_key(&f.key));
    }

    /// The notices of a project that rotated its keys: #1 under the test
    /// set, #2 naming the next set (signed by the test set, with a log the
    /// test set signs), #3 under the next set (its log signed by it).
    fn rotated_project() -> [(Advisory, Snapshot); 3] {
        use raven_core::advisory::Severity;
        use raven_core::release_keys::test_keys::{key_set_of, signer};
        let current = key_set();
        let next = key_set_of(2, &[0x22, 0x33, 0x44]);
        let sign = |set: &raven_core::release_keys::KeySet,
                    seeds: [u8; 2],
                    serial: u64,
                    prev: [u8; 32],
                    entries: Vec<Entry>| {
            AdvisoryDraft {
                serial,
                issued_at_ms: T0 + serial * DAY_MS,
                key_set_digest: set.digest(),
                prev_digest: prev,
                entries,
            }
            .sign(&[(0, &signer(seeds[0])), (1, &signer(seeds[1]))])
            .unwrap()
        };
        let snapshot =
            |log: &[LogEntry], set: &raven_core::release_keys::KeySet, seeds: [u8; 2]| {
                let sth = SthDraft::of_entries(log, T0 + log.len() as u64 * DAY_MS, set.digest())
                    .sign(&[(0, &signer(seeds[0])), (1, &signer(seeds[1]))])
                    .unwrap();
                Snapshot::new(log.to_vec(), sth).unwrap()
            };
        let mut log = vec![LogEntry {
            kind: EntryType::KeySet,
            digest: current.digest(),
            logged_at_ms: T0,
        }];
        let list = |log: &mut Vec<LogEntry>, digest| {
            let at = log.len() as u64;
            log.push(LogEntry {
                kind: EntryType::Advisory,
                digest,
                logged_at_ms: T0 + at * DAY_MS,
            });
        };
        let one = sign(&current, [0x11, 0x22], 1, [0; 32], Vec::new());
        list(&mut log, one.digest());
        let s1 = snapshot(&log, &current, [0x11, 0x22]);
        let rotate = Entry {
            kind: EntryKind::KeySet,
            severity: Severity::Info,
            target: "keys".to_owned(),
            arg: next.encode(),
            text_id: 0,
        };
        let two = sign(&current, [0x11, 0x22], 2, one.digest(), vec![rotate]);
        list(&mut log, two.digest());
        let s2 = snapshot(&log, &current, [0x11, 0x22]);
        let three = sign(&next, [0x22, 0x33], 3, two.digest(), Vec::new());
        list(&mut log, three.digest());
        let s3 = snapshot(&log, &next, [0x22, 0x33]);
        [(one, s1), (two, s2), (three, s3)]
    }

    /// Phase 6 review updates-protocol-3: C missed the rotation its friend A
    /// took. A's newest notice and log are under a key set C never trusted:
    /// nothing is forged, nobody is blamed, and C asks A for the rotation
    /// away from its own set (GET_ROTATION), then takes A's newest notice.
    /// A friend that kept no rotation answers NOT_FOUND: C stays where it
    /// is, and (re-verify) counts that friend's notice as forged, since it
    /// cannot tell it from one under a key set a friend made up.
    #[test]
    fn a_node_that_missed_a_rotation_catches_up_without_blaming_its_friend() {
        let _gates = Gates::open(false);
        let [(one, s1), (two, s2), (three, s3)] = rotated_project();
        let (a, c) = (Peer::new(0xA3), Peer::new(0xC3));
        a.befriend(&[(&c, true)]);
        c.befriend(&[(&a, true)]);
        for (notice, log) in [(&one, &s1), (&two, &s2), (&three, &s3)] {
            a.import_advisory(notice, log);
        }
        c.import_advisory(&one, &s1);
        let now = Instant::now();
        assert!(link(&c, &a, now).0);
        let mut net = Net::new(&c, &[&a], now);
        let report = pass(&c, &mut net);
        assert_eq!((report.dials, report.notices), (2, 2), "{:?}", net.dials);
        let state = c.state();
        assert_eq!(state.advisory().map(|n| n.digest()), Some(three.digest()));
        assert_eq!(
            state.key_set().map(|k| k.digest()),
            Some(raven_core::release_keys::test_keys::key_set_of(2, &[0x22, 0x33, 0x44]).digest())
        );
        assert_eq!(c.node().forged_counts(), (0, 0));
        assert_eq!(c.node().status().unwrap().quarantined, 0);
        assert!(!lock(&c.shared).notice_parked.contains_key(&a.key));
        // Nothing more to ask.
        assert_eq!(pass(&c, &mut net).dials, 0);

        // B never took the rotation itself (a build that trusts the next set
        // from the start), so it kept none to give. D asked for the rotation
        // and got none: to D that notice is one no key set it can reach
        // signed, as a made-up one is (re-verify): forged, quarantined, and
        // B is not asked again for a day.
        let (b, d) = (Peer::new(0xB3), Peer::new(0xD3));
        let b = Peer {
            build: Build {
                key_set: Some(raven_core::release_keys::test_keys::key_set_of(
                    2,
                    &[0x22, 0x33, 0x44],
                )),
                ..b.build.clone()
            },
            ..b
        };
        b.befriend(&[(&d, true)]);
        d.befriend(&[(&b, true)]);
        b.import_advisory(&three, &s3);
        d.import_advisory(&one, &s1);
        assert!(link(&d, &b, now).0);
        let mut net = Net::new(&d, &[&b], now);
        let report = pass(&d, &mut net);
        assert_eq!((report.dials, report.notices), (2, 0), "{:?}", net.dials);
        assert_eq!(d.state().advisory().map(|n| n.serial), Some(1));
        assert_eq!(d.node().forged_counts(), (1, 0));
        assert_eq!(d.node().status().unwrap().quarantined, 1);
        assert!(lock(&d.shared).notice_parked.contains_key(&b.key));
        link(&d, &b, now);
        assert_eq!(pass(&d, &mut net).dials, 0, "not asked again for a day");
    }

    /// A notice and its log under a key set made of these test seeds
    /// (2 of 3), listed in a log of that set's own.
    fn notice_under(seeds: [u8; 3], serial: u64) -> (Advisory, Snapshot) {
        use raven_core::release_keys::test_keys::{key_set_of, signer};
        let set = key_set_of(2, &seeds);
        let notice = AdvisoryDraft {
            serial,
            issued_at_ms: T0 + serial * DAY_MS,
            key_set_digest: set.digest(),
            prev_digest: [0x5A; 32],
            entries: Vec::new(),
        }
        .sign(&[(0, &signer(seeds[0])), (1, &signer(seeds[1]))])
        .unwrap();
        let log = vec![
            LogEntry {
                kind: EntryType::KeySet,
                digest: set.digest(),
                logged_at_ms: T0,
            },
            LogEntry {
                kind: EntryType::Advisory,
                digest: notice.digest(),
                logged_at_ms: T0 + DAY_MS,
            },
        ];
        let sth = SthDraft::of_entries(&log, T0 + 2 * DAY_MS, set.digest())
            .sign(&[(0, &signer(seeds[0])), (1, &signer(seeds[1]))])
            .unwrap();
        (notice, Snapshot::new(log, sth).unwrap())
    }

    /// A friend running a build that trusts `seeds`' key set, holding a
    /// notice signed by it.
    fn friend_under(seed: u8, seeds: [u8; 3]) -> Peer {
        use raven_core::release_keys::test_keys::key_set_of;
        let peer = Peer::new(seed);
        let peer = Peer {
            build: Build {
                key_set: Some(key_set_of(2, &seeds)),
                ..peer.build.clone()
            },
            ..peer
        };
        let (notice, log) = notice_under(seeds, 2);
        peer.import_advisory(&notice, &log);
        peer
    }

    /// Phase 6 review re-verify (updates-protocol-3): a pinned friend that
    /// serves notices under a key set it made up, link after link, each
    /// HAVE claiming a newer notice. B asks once, asks for the rotation
    /// once (none comes), and counts the notice as forged: quarantined,
    /// SEC_ADVISORY_FORGED about that friend, and not asked again for a day
    /// whatever it claims. A friend that drops every catch-up dial spends
    /// its catch-ups of the day ([`MAX_CATCH_UPS_PER_DAY`]); after that its
    /// notice is forged too.
    #[test]
    fn a_friend_that_invents_a_key_set_is_asked_twice_and_counted_forged() {
        use raven_core::security_events::{Attribution, SecKind, Via};
        let _gates = Gates::open(false);
        let Some(capture) = crate::security::tests::Capture::start() else {
            return;
        };
        let b = Peer::new(0xB7);
        let m = friend_under(0x37, [0x66, 0x77, 0x88]);
        b.befriend(&[(&m, true)]);
        m.befriend(&[(&b, true)]);
        let mut project = Project::new();
        b.import_advisory(&project.advisory(1, 1, true), &project.snapshot());
        let t0 = Instant::now();
        let mut dials = 0;
        // The flood: a link every 11 minutes for a day, each HAVE claiming
        // a notice B does not have.
        for i in 0..131u64 {
            let at = t0 + Duration::from_secs(i * 660);
            link(&b, &m, at);
            dials += pass(&b, &mut Net::new(&b, &[&m], at)).dials;
        }
        assert!(t0 + Duration::from_secs(130 * 660) < t0 + FORGED_PARK);
        assert_eq!(dials, 2, "the notice, then the rotation with it again");
        assert_eq!(b.node().forged_counts(), (1, 0));
        assert_eq!(b.node().status().unwrap().quarantined, 1);
        assert_eq!(b.state().advisory().map(|n| n.serial), Some(1));
        let forged: Vec<_> = capture
            .kinds()
            .into_iter()
            .filter(|(kind, _, _)| *kind == SecKind::AdvisoryForged)
            .collect();
        assert_eq!(
            forged,
            [(
                SecKind::AdvisoryForged,
                Attribution::Update {
                    passed_by: Some(m.key)
                },
                Via::Dial(OutboxCarrier::Lan)
            )]
        );
        // A day on, it is asked again (twice), and forged again.
        let later = t0 + FORGED_PARK + Duration::from_secs(60);
        link(&b, &m, later);
        assert_eq!(pass(&b, &mut Net::new(&b, &[&m], later)).dials, 2);
        assert_eq!(b.node().forged_counts(), (2, 0));

        // One that drops every catch-up dial: four tries a day, then forged.
        let c = Peer::new(0xC7);
        let n = friend_under(0x38, [0x55, 0x99, 0xAA]);
        c.befriend(&[(&n, true)]);
        n.befriend(&[(&c, true)]);
        c.import_advisory(&project.advisory(2, 2, true), &project.snapshot());
        let (mut notices, mut catch_ups) = (0, 0);
        for i in 0..131u64 {
            let at = t0 + Duration::from_secs(i * 660);
            link(&c, &n, at);
            let mut net = Net::new(&c, &[&n], at);
            c.node().pass(at, &mut |p, frames, bundle| {
                let rotation = frames
                    .iter()
                    .any(|f| matches!(rup1::decode(f), Ok((_, Rup1Msg::GetRotation { .. }))));
                if rotation {
                    catch_ups += 1;
                    return Err("the link dropped".into());
                }
                notices += 1;
                net.dial(p, frames, bundle)
            });
        }
        assert_eq!(
            (notices, catch_ups),
            (
                MAX_CATCH_UPS_PER_DAY as usize + 1,
                MAX_CATCH_UPS_PER_DAY as usize
            ),
            "a notice dial before each catch-up, and one after the last"
        );
        assert_eq!(c.node().forged_counts(), (1, 0));
        assert!(lock(&c.shared).notice_parked.contains_key(&n.key));
    }

    /// Phase 6 review updates-protocol-4: a security notice's hold on
    /// release bundles stops bundles between friends, not notices (a node
    /// without an uplink gets the notice that lifts the hold only this
    /// way). A hold on the exchange itself still stops everything.
    #[test]
    fn a_hold_on_release_bundles_keeps_notices_passing() {
        use raven_core::advisory::Severity;
        use raven_core::suite_policy::{self, Policy};
        use raven_core::suite_registry::{FEATURE_MESH_UPDATE, FEATURE_RELEASE_BUNDLE};
        let _gates = Gates::open(false);
        let _build = BuildForTest::set(test_build());
        let hold = |feature: &str| {
            let advisory = AdvisoryDraft {
                serial: 9,
                issued_at_ms: T0,
                key_set_digest: key_set().digest(),
                prev_digest: [9; 32],
                entries: vec![Entry {
                    kind: EntryKind::FeatureHold,
                    severity: Severity::Broken,
                    target: feature.to_owned(),
                    arg: Vec::new(),
                    text_id: 0,
                }],
            }
            .assemble(&Default::default())
            .unwrap();
            Policy::of_advisory(&advisory, 1)
        };
        let (a, b) = (Peer::new(0xA4), Peer::new(0xB4));
        a.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true)]);
        let mut project = Project::new();
        let notice = project.advisory(1, 1, true);
        a.import_advisory(&notice, &project.snapshot());
        let release = project.release(5, 2);
        let digest = release.manifest.digest();
        a.stage(&release);
        assert!(active() && rup1::live());
        assert_eq!(a.have_for(&b, OutboxCarrier::Lan).unwrap().offers.len(), 1);
        suite_policy::set_policy_for_this_thread(Some(hold(FEATURE_RELEASE_BUNDLE)));
        assert!(!rup1::live(), "bundles held");
        assert!(rup1::notices_live() && active() && offered());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut listener = UpdateLink::lan_listener(
                a.dd(),
                b.key,
                &raven_core::route_hints::rlx1_payload(CAP_LINK_RUP1),
            );
            assert!(listener.outgoing().await.is_some(), "a HAVE still goes");
        });
        // Its HAVE offers nothing; B gets the notice all the same.
        assert!(a
            .have_for(&b, OutboxCarrier::Lan)
            .unwrap()
            .offers
            .is_empty());
        let now = Instant::now();
        assert_eq!(link(&b, &a, now), (true, false));
        assert!(b.rows().rows.is_empty(), "no download row");
        let report = pass(&b, &mut Net::new(&b, &[&a], now));
        assert_eq!((report.dials, report.notices), (1, 1));
        assert_eq!(b.state().advisory().map(|n| n.serial), Some(1));
        let ask = rup1::encode(
            &[7; 4],
            &Rup1Msg::GetManifest {
                manifest_digest: digest,
            },
        )
        .unwrap();
        let (got, _) = a
            .node()
            .listener_frame(&b.key, OutboxCarrier::Lan, &ask, false, now);
        assert_eq!(
            rup1::decode(&got[0]).unwrap().1,
            Rup1Msg::Error(ErrorCode::PolicyDenied)
        );
        // A hold on the exchange itself stops notices too.
        suite_policy::set_policy_for_this_thread(Some(hold(FEATURE_MESH_UPDATE)));
        assert!(!rup1::notices_live() && !active() && !offered());
        suite_policy::set_policy_for_this_thread(None);
    }

    /// Phase 6 review updates-protocol-5: every chunk is in but the check
    /// never finished (raven-node stopped in between): the next pass checks
    /// it, with no dial. And a complete download whose folder went (7 idle
    /// days) is offered again, unless its build was staged.
    #[test]
    fn a_complete_download_whose_check_did_not_finish_is_checked_without_a_dial() {
        let _gates = Gates::open(true);
        let (a, b) = (Peer::new(0xA5), Peer::new(0xB5));
        a.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true)]);
        let mut project = Project::new();
        let release = project.release(5, 3);
        let digest = release.manifest.digest();
        a.stage(&release);
        let now = Instant::now();
        link(&b, &a, now);
        assert_eq!(pass(&b, &mut Net::new(&b, &[&a], now)).completed, 1);
        let folder = incoming_dir(b.dd(), &digest);
        // As raven-node left it when it stopped after the last chunk.
        std::fs::remove_file(folder.join(INCOMING_VERIFIED)).unwrap();
        downloads::change(b.dd(), |rows| {
            rows.row_mut(&digest).unwrap().state = RowState::Downloading;
        })
        .unwrap();
        let b = Peer {
            shared: Mutex::default(),
            ..b
        };
        let mut net = Net::new(&b, &[&a], now);
        let report = pass(&b, &mut net);
        assert_eq!((report.dials, report.completed), (0, 1), "{:?}", net.dials);
        assert_eq!(b.rows().row(&digest).unwrap().state, RowState::Complete);
        assert!(folder.join(INCOMING_VERIFIED).exists());
        assert_eq!(incoming_payload(&b, &digest), release.payload);
        // Its folder goes (7 idle days): offered again, nothing staged.
        std::fs::remove_dir_all(&folder).unwrap();
        b.node().prune(raven_core::clock::now_ms());
        let row = b.rows().row(&digest).unwrap().clone();
        assert_eq!((row.state, row.chunks_have), (RowState::Offered, 0));
        // Staged by the CLI or the app before its folder went: staged.
        downloads::change(b.dd(), |rows| {
            rows.row_mut(&digest).unwrap().state = RowState::Complete;
        })
        .unwrap();
        std::fs::create_dir_all(b.dd().join(STAGED_DIR).join("5")).unwrap();
        b.node().prune(raven_core::clock::now_ms());
        assert_eq!(b.rows().row(&digest).unwrap().state, RowState::Staged);
    }

    /// Phase 6 review updates-protocol-6 and -7: A answers GET_MANIFEST with
    /// the real manifest and an older, validly signed log that does not
    /// list it. That is A's bad copy, not the release's: A is left out, E
    /// serves it, and the row then shows the verified manifest's build and
    /// size, not the claims of the HAVE that created it.
    #[test]
    fn a_friend_sending_an_older_log_with_its_manifest_is_left_out() {
        let _gates = Gates::open(true);
        let (a, e, b) = (Peer::new(0xA6), Peer::new(0xE6), Peer::new(0xB6));
        a.befriend(&[(&b, true)]);
        e.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true), (&e, true)]);
        let mut project = Project::new();
        let older = project.snapshot();
        update_state::accept_log_with(b.dd(), &b.build, &older.encode(), Origin::IMPORTED).unwrap();
        let release = project.release(5, 3);
        let digest = release.manifest.digest();
        a.stage(&release);
        e.stage(&release);
        let now = Instant::now();
        // A's HAVE claims build 999 and another size for this digest.
        let claim = Have {
            offers: vec![Offer {
                build_serial: 999,
                target: THIS_TARGET.into(),
                manifest_digest: digest,
                payload_len: 7,
            }],
            ..Have::nothing()
        };
        assert!(b.node().take_have(&a.key, claim, now));
        assert_eq!(b.rows().row(&digest).unwrap().build_serial, 999);
        link(&b, &e, now);
        link(&b, &a, now);
        assert_eq!(b.rows().row(&digest).unwrap().from, vec![a.key, e.key]);
        // The notices are not fetched first here: B's log is the older one
        // when the manifests come.
        lock(&b.shared).due.clear();
        let mut net = Net::new(&b, &[&a, &e], now);
        let report = b.node().pass(now, &mut |p, frames, bundle| {
            let (mut replies, carrier) = net.dial(p, frames, bundle)?;
            if *p == a.key {
                for reply in &mut replies {
                    if let Ok((id, Rup1Msg::Manifest { manifest, .. })) = rup1::decode(reply) {
                        *reply = rup1::encode(
                            &id,
                            &Rup1Msg::Manifest {
                                manifest,
                                snapshot: older.encode(),
                            },
                        )
                        .unwrap();
                    }
                }
            }
            Ok((replies, carrier))
        });
        assert_eq!(report.completed, 1, "{:?}", net.dials);
        let row = b.rows().row(&digest).unwrap().clone();
        assert_eq!(
            (row.state, row.failed.as_deref()),
            (RowState::Complete, None)
        );
        assert_eq!(
            (row.build_serial, row.payload_len),
            (5, release.manifest.payload_len)
        );
        assert_eq!(incoming_payload(&b, &digest), release.payload);
        assert!(lock(&b.shared).bad_copy(&a.key, &digest, now));
        assert!(!lock(&b.shared).bad_copy(&e.key, &digest, now));

        // Re-verify: no one else to ask. Build 7 is in the project's log,
        // which B does not have yet, and A alone offers it, with its older
        // log. No log here lists it: not used, A's copy held back, nothing
        // of the release itself quarantined, and the row says no log lists
        // it (not that it failed its checks).
        let newer = project.release(7, 2);
        let newer_digest = newer.manifest.digest();
        a.stage(&newer);
        let quarantined = |what: &str| {
            std::fs::read_dir(b.dd().join(QUARANTINE_DIR))
                .map(|list| {
                    list.flatten()
                        .filter(|f| f.file_name().to_string_lossy().contains(what))
                        .count()
                })
                .unwrap_or(0)
        };
        let manifests_before = quarantined("-manifest-");
        // A waits 30 s after a dial that gave nothing.
        let later = now + Duration::from_secs(120);
        link(&b, &a, later);
        lock(&b.shared).due.clear();
        let mut net = Net::new(&b, &[&a, &e], later);
        let mut stale = |p: &[u8; 32], frames: &[Vec<u8>], bundle: bool| {
            let (mut replies, carrier) = net.dial(p, frames, bundle)?;
            if *p == a.key {
                for reply in &mut replies {
                    if let Ok((id, Rup1Msg::Manifest { manifest, .. })) = rup1::decode(reply) {
                        *reply = rup1::encode(
                            &id,
                            &Rup1Msg::Manifest {
                                manifest,
                                snapshot: older.encode(),
                            },
                        )
                        .unwrap();
                    }
                }
            }
            Ok((replies, carrier))
        };
        b.node().pass(later, &mut stale);
        let row = b.rows().row(&newer_digest).unwrap().clone();
        assert_eq!(
            (row.state, row.failed.as_deref()),
            (RowState::Failed, Some(downloads::FAILED_NOT_LOGGED)),
            "{:?}",
            net.dials
        );
        assert!(lock(&b.shared).bad_copy(&a.key, &newer_digest, later));
        assert_eq!(
            quarantined("-manifest-"),
            manifests_before,
            "the release is not what failed"
        );
        // With nobody to ask and no log that lists it, it stays so.
        let mut net = Net::new(&b, &[&a, &e], later + Duration::from_secs(60));
        assert_eq!(pass(&b, &mut net).dials, 0);
        assert_eq!(b.rows().row(&newer_digest).unwrap().state, RowState::Failed);
        // A notice brings the project's newer log: approved again by itself.
        update_state::accept_log_with(
            b.dd(),
            &b.build,
            &project.snapshot().encode(),
            Origin::IMPORTED,
        )
        .unwrap();
        let mut net = Net::new(&b, &[&a, &e], later + Duration::from_secs(90));
        pass(&b, &mut net);
        assert_eq!(
            b.rows().row(&newer_digest).unwrap().state,
            RowState::Approved
        );
        // E offers it too: B takes it from E.
        e.stage(&newer);
        let then = later + Duration::from_secs(120);
        link(&b, &e, then);
        lock(&b.shared).due.clear();
        let mut net = Net::new(&b, &[&a, &e], then);
        let report = pass(&b, &mut net);
        assert_eq!(report.completed, 1, "{:?}", net.dials);
        assert_eq!(
            b.rows().row(&newer_digest).unwrap().state,
            RowState::Complete
        );

        // A release no log lists at all, offered by one friend alone: the
        // same honest refusal, and it stays so while no log lists it.
        let unlisted = Project::new().release(9, 2);
        let unlisted = Parts {
            snapshot: project.snapshot(),
            ..unlisted
        };
        let unlisted_digest = unlisted.manifest.digest();
        let f = Peer::new(0xF6);
        f.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true), (&e, true), (&f, true)]);
        f.stage(&unlisted);
        let after = then + Duration::from_secs(60);
        link(&b, &f, after);
        lock(&b.shared).due.clear();
        let mut net = Net::new(&b, &[&a, &e, &f], after);
        pass(&b, &mut net);
        let row = b.rows().row(&unlisted_digest).unwrap().clone();
        assert_eq!(
            (row.state, row.failed.as_deref()),
            (RowState::Failed, Some(downloads::FAILED_NOT_LOGGED)),
            "{:?}",
            net.dials
        );
    }

    #[test]
    fn a_download_without_room_fails_and_says_so() {
        let _gates = Gates::open(true);
        let (a, b) = (Peer::new(0xAA), Peer::new(0xBA));
        a.befriend(&[(&b, true)]);
        b.befriend(&[(&a, true)]);
        let mut project = Project::new();
        let release = project.release(5, 2);
        let digest = release.manifest.digest();
        a.stage(&release);
        // Something else fills incoming/ (a sparse file).
        let other = incoming_dir(b.dd(), &[0x11; 32]);
        std::fs::create_dir_all(&other).unwrap();
        std::fs::File::create(other.join(INCOMING_PAYLOAD))
            .unwrap()
            .set_len(MAX_INCOMING_BYTES)
            .unwrap();
        // ... with a complete row, so it is no orphan.
        downloads::change(b.dd(), |rows| {
            rows.note_offer(
                &a.key,
                &Offer {
                    build_serial: 7,
                    target: THIS_TARGET.into(),
                    manifest_digest: [0x11; 32],
                    payload_len: MAX_INCOMING_BYTES,
                },
                raven_core::clock::now_ms(),
            );
            rows.row_mut(&[0x11; 32]).unwrap().state = RowState::Complete;
        })
        .unwrap();
        let now = Instant::now();
        link(&b, &a, now);
        let mut net = Net::new(&b, &[&a], now);
        let report = pass(&b, &mut net);
        assert_eq!(report.completed, 0);
        let row = b.rows().row(&digest).unwrap().clone();
        assert_eq!(
            (row.state, row.failed.as_deref()),
            (RowState::Failed, Some("NO_ROOM"))
        );
    }
}
