//! `raven update download` and the staging of friends' downloads (step
//! P6.49), with a release signed by the published test keys: debug builds
//! only (the test keys are not in a release build).

#[cfg(debug_assertions)]
mod with_the_gate {
    use raven_core::release_bundle::{FileMode, ManifestDraft, PackFile, THIS_TARGET};
    use raven_core::release_keys::test_keys::{key_set, signers};
    use raven_core::tlog::{LogEntry, SthDraft};
    use raven_core::update_downloads::{incoming_dir, set_lab_auto_approve_for_this_thread};
    use raven_core::update_exchange::Offer;

    use super::super::*;

    const T0: u64 = 1_792_800_000_000;
    const GATES: [SecGate; 3] = [
        SecGate::Advisory,
        SecGate::ReleaseBundle,
        SecGate::MeshUpdate,
    ];
    const SARA: [u8; 32] = [0x5A; 32];

    struct Gates;

    impl Gates {
        /// The gates open and the person approving (the lab auto-approval
        /// off whatever the variables say).
        fn open() -> Gates {
            for g in GATES {
                security_gate::set_lab_for_this_thread(g, Some(true));
            }
            set_lab_auto_approve_for_this_thread(Some(false));
            Gates
        }
    }

    impl Drop for Gates {
        fn drop(&mut self) {
            for g in GATES {
                security_gate::set_lab_for_this_thread(g, None);
            }
            set_lab_auto_approve_for_this_thread(None);
        }
    }

    fn build(serial: u64) -> Build {
        Build {
            key_set: Some(key_set()),
            serial,
            floor: (0, [0; 32]),
        }
    }

    /// A release of `serial` for this computer, signed and listed in a log
    /// of its own (after the key set).
    fn release(serial: u64) -> Parts {
        let program = b"#!/bin/sh\necho pong\n".to_vec();
        let mut draft = ManifestDraft {
            build_serial: serial,
            created_at_ms: T0,
            key_set_digest: key_set().digest(),
            version: "1.5.0".to_owned(),
            target: THIS_TARGET.to_owned(),
            source_commit: [0xC0; 20],
            toolchain: "1.98.0".to_owned(),
            min_advisory_serial: 0,
            chunk_size: 0,
            payload_len: 0,
            payload_chunk_root: [0; 32],
            payload_sha256: [0; 32],
            files: Vec::new(),
            notes: String::new(),
        };
        let payload = draft.fill_payload(&[PackFile {
            path: "bin/raven-node",
            mode: FileMode::Executable,
            bytes: &program,
            rebuild_sha256: sha256(&program),
        }]);
        let [a, b, _] = signers();
        let manifest = draft.sign(&[(0, &a), (1, &b)]).unwrap();
        let log = vec![
            LogEntry {
                kind: EntryType::KeySet,
                digest: key_set().digest(),
                logged_at_ms: T0,
            },
            LogEntry {
                kind: EntryType::Manifest,
                digest: manifest.digest(),
                logged_at_ms: T0 + 1,
            },
        ];
        let sth = SthDraft::of_entries(&log, T0 + 2, key_set().digest())
            .sign(&[(0, &a), (1, &b)])
            .unwrap();
        Parts {
            manifest,
            snapshot: Snapshot::new(log, sth).unwrap(),
            advisory: None,
            payload,
        }
    }

    /// A profile whose contacts name Sara.
    fn profile() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","address":"rvn1sara","petname":"Sara","pinned":true}}]"#,
                hex::encode(SARA)
            ),
        )
        .unwrap();
        dir
    }

    /// Sara's offer of `parts`, noted as raven-node notes it.
    fn offered(dd: &Path, parts: &Parts) {
        let offer = Offer {
            build_serial: parts.manifest.build_serial,
            target: parts.manifest.target.clone(),
            manifest_digest: parts.manifest.digest(),
            payload_len: parts.manifest.payload_len,
        };
        downloads::change(dd, |rows| rows.note_offer(&SARA, &offer, T0)).unwrap();
    }

    /// raven-node's complete download of `parts`, as it leaves it.
    fn downloaded(dd: &Path, parts: &Parts) {
        let digest = parts.manifest.digest();
        let dir = incoming_dir(dd, &digest);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(INCOMING_MANIFEST), parts.manifest.bytes()).unwrap();
        std::fs::write(dir.join(INCOMING_SNAPSHOT), parts.snapshot.encode()).unwrap();
        std::fs::write(dir.join(INCOMING_PAYLOAD), &parts.payload).unwrap();
        std::fs::write(dir.join(INCOMING_VERIFIED), b"").unwrap();
        downloads::change(dd, |rows| {
            let row = rows.row_mut(&digest).unwrap();
            row.state = RowState::Complete;
            row.version = Some(parts.manifest.version.clone());
        })
        .unwrap();
    }

    #[test]
    fn an_offer_names_the_friend_and_asks_before_anything_is_fetched() {
        let _gates = Gates::open();
        let dir = profile();
        let parts = release(5);
        offered(dir.path(), &parts);
        let (row, lines) = first_offer(dir.path()).expect("an offer waits");
        assert_eq!(row.state, RowState::Offered);
        assert_eq!(
            lines,
            vec![
                "Sara has a Raven update (build 5) for this computer (1 kB).".to_owned(),
                "Raven checks that it is signed by the Raven project keys and listed in the \
                 public release log before it keeps any of it; installing it is a separate step."
                    .to_owned(),
                "Download it from Sara?".to_owned(),
            ]
        );
        let status = download_lines(dir.path());
        let code = &hex::encode(parts.manifest.digest())[..8];
        assert_eq!(
            status,
            vec![format!(
                "Sara has a Raven update (build 5) for this computer (1 kB): raven update \
                 download {code}"
            )]
        );
        // Never a key.
        assert!(!lines.join(" ").contains(&hex::encode(SARA)[..16]));
        // Approved: raven-node is told (none runs here) and the row says so.
        let said = approve(dir.path(), code).unwrap();
        assert!(
            said[0].contains("once its background program runs"),
            "{said:?}"
        );
        assert_eq!(said.last().map(String::as_str), Some(NEVER_WITHOUT_ASKING));
        assert_eq!(
            downloads::load(dir.path()).unwrap().rows[0].state,
            RowState::Approved
        );
        assert!(approve(dir.path(), code)
            .unwrap_err()
            .contains("approved already"));
        assert!(approve(dir.path(), "ffff")
            .unwrap_err()
            .contains("No update offer"));
        assert_eq!(
            download_lines(dir.path()),
            vec!["Downloading a Raven update (build 5) from Sara.".to_owned()]
        );
        assert!(first_offer(dir.path()).is_none());
    }

    #[test]
    fn a_complete_download_is_staged_like_an_import_and_then_installable() {
        let _gates = Gates::open();
        let dir = profile();
        let parts = release(5);
        let digest = parts.manifest.digest();
        offered(dir.path(), &parts);
        downloaded(dir.path(), &parts);
        assert_eq!(
            download_lines(dir.path()),
            vec![
                "Raven 1.5.0 (build 5) from Sara is downloaded and checked: raven update install"
                    .to_owned()
            ]
        );
        let build = build(1);
        assert!(stage_downloads(dir.path(), &build).is_empty());
        let staged = staged_builds(dir.path());
        assert_eq!(staged.iter().map(|s| s.serial).collect::<Vec<_>>(), vec![5]);
        assert!(
            !incoming_dir(dir.path(), &digest).exists(),
            "its folder went"
        );
        assert_eq!(
            downloads::load(dir.path()).unwrap().rows[0].state,
            RowState::Staged
        );
        assert!(download_lines(dir.path()).is_empty());
        // The staged build is what `raven update install` offers.
        let lines = update_lines(dir.path(), &build);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Raven 1.5.0 (build 5) is ready to install")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_download_that_no_longer_checks_fails_and_is_not_staged() {
        let _gates = Gates::open();
        let dir = profile();
        let parts = release(5);
        offered(dir.path(), &parts);
        downloaded(dir.path(), &parts);
        // The payload changed on the disk since raven-node checked it.
        let digest = parts.manifest.digest();
        let payload = incoming_dir(dir.path(), &digest).join(INCOMING_PAYLOAD);
        let mut bytes = std::fs::read(&payload).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&payload, bytes).unwrap();
        let said = stage_downloads(dir.path(), &build(1));
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(staged_builds(dir.path()).is_empty());
        let row = downloads::load(dir.path()).unwrap().rows[0].clone();
        assert_eq!(row.state, RowState::Failed);
        assert_eq!(row.failed.as_deref(), Some(downloads::FAILED_NOT_STAGED));
        // raven-node checked it whole when it came: what changed since is on
        // this computer, never the friend's doing (Phase 6 review
        // updates-protocol-7).
        let line = &download_lines(dir.path())[0];
        assert!(
            line.contains("this computer can no longer install it"),
            "{line}"
        );
        assert!(
            !line.contains("may not know") && !line.contains("passed on"),
            "{line}"
        );
    }

    /// Phase 6 review updates-protocol-7: failures caused on this computer
    /// name no fault of the friend's; one of the friend's copy still does.
    #[test]
    fn a_failure_on_this_computer_does_not_blame_the_friend() {
        let _gates = Gates::open();
        let dir = profile();
        let parts = release(5);
        let digest = parts.manifest.digest();
        offered(dir.path(), &parts);
        let fail = |code: &str| {
            downloads::change(dir.path(), |rows| {
                let row = rows.row_mut(&digest).unwrap();
                row.state = RowState::Failed;
                row.failed = Some(code.to_owned());
            })
            .unwrap();
            download_lines(dir.path()).remove(0)
        };
        let code = &hex::encode(digest)[..8];
        let no_room = fail(downloads::FAILED_NO_ROOM);
        assert_eq!(
            no_room,
            format!(
                "Raven had no room on this computer to download a Raven update (build 5) from \
                 Sara: install an update it downloaded before (raven update install), then \
                 approve this one again: raven update download {code}"
            )
        );
        for local in [downloads::FAILED_NOT_STAGED, "REFUSED"] {
            let line = fail(local);
            assert!(!line.contains("failed its checks"), "{line}");
        }
        let forged = fail("BAD_CHUNK_ROOT");
        assert_eq!(
            forged,
            "Sara passed on a Raven update (build 5) that failed its checks (BAD_CHUNK_ROOT). \
             Raven ignored it; Sara may not know."
        );
        // Re-verify (updates-protocol-6): no log listed it, which is no
        // proof against the release.
        let not_logged = fail(downloads::FAILED_NOT_LOGGED);
        assert!(!not_logged.contains("failed its checks"), "{not_logged}");
        assert!(
            not_logged.starts_with(
                "Sara offered a Raven update (build 5), but no Raven release log lists it"
            ),
            "{not_logged}"
        );
        assert!(not_logged.contains("tries again by itself"), "{not_logged}");
    }

    /// A complete download that cannot be read right now (the disk) stays
    /// as it is, for the next try: not failed, its folder kept.
    #[test]
    fn a_download_that_cannot_be_read_now_is_kept_for_later() {
        let _gates = Gates::open();
        let dir = profile();
        let parts = release(5);
        let digest = parts.manifest.digest();
        offered(dir.path(), &parts);
        downloaded(dir.path(), &parts);
        let folder = incoming_dir(dir.path(), &digest);
        let payload = folder.join(INCOMING_PAYLOAD);
        std::fs::remove_file(&payload).unwrap();
        std::fs::create_dir(&payload).unwrap();
        let said = stage_downloads(dir.path(), &build(1));
        assert_eq!(said.len(), 1, "{said:?}");
        let row = downloads::load(dir.path()).unwrap().rows[0].clone();
        assert_eq!((row.state, row.failed), (RowState::Complete, None));
        assert!(folder.join(INCOMING_MANIFEST).exists(), "its folder stays");
        assert!(staged_builds(dir.path()).is_empty());
        // Readable again: staged.
        std::fs::remove_dir(&payload).unwrap();
        std::fs::write(&payload, &parts.payload).unwrap();
        assert!(stage_downloads(dir.path(), &build(1)).is_empty());
        assert_eq!(
            downloads::load(dir.path()).unwrap().rows[0].state,
            RowState::Staged
        );
    }

    #[test]
    fn the_lab_switch_types_the_install_word_in_a_debug_build_only() {
        let _gates = Gates::open();
        set_lab_auto_approve_for_this_thread(Some(true));
        assert!(super::super::super::ask_typed(&[], INSTALL_WORD));
        assert!(ask_yes(&[]));
        set_lab_auto_approve_for_this_thread(Some(false));
        // Tests run without a terminal: nothing is approved.
        assert!(!ask_yes(&[]));
    }

    #[test]
    fn downloads_are_off_while_the_mesh_update_gate_is_shut() {
        let _gates = Gates::open();
        security_gate::set_lab_for_this_thread(SecGate::MeshUpdate, Some(false));
        let dir = profile();
        assert_eq!(
            cmd_download(dir.path(), None).unwrap_err(),
            FRIENDS_OFF_TEXT
        );
        assert_eq!(approve(dir.path(), "00").unwrap_err(), FRIENDS_OFF_TEXT);
        assert!(download_lines(dir.path()).is_empty());
        assert!(first_offer(dir.path()).is_none());
        assert!(stage_downloads(dir.path(), &build(1)).is_empty());
    }
}
