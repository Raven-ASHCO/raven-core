//! `raven update` (step P6.47): a temp profile and a temp prefix with fake
//! programs (shell scripts that note every run and answer `ping` or not),
//! bundles signed with the published test keys, and a mock file system with
//! Windows' rules. Everything opens the gates for its own thread, so a
//! debug build only (the test keys are not in a release build).

use super::*;

/// What the CLI's words are, in every build.
#[test]
fn sizes_and_build_names_read_as_people_say_them() {
    assert_eq!(size_text(1), "1 kB");
    assert_eq!(size_text(2_170), "3 kB");
    assert_eq!(size_text(34_100_000), "34.1 MB");
    assert_eq!(build_name("1.5.0", 5), "Raven 1.5.0 (build 5)");
    assert_eq!(build_name("0.1.0", 0), "Raven 0.1.0 (a development build)");
    assert_eq!(staged_name(1, "bin/raven-node"), "1-raven-node");
    assert_eq!(staged_name(2, "docs/en/README.txt"), "2-README.txt");
    assert!(package_managed(Path::new(
        "/opt/homebrew/Cellar/raven/1.4.2/bin"
    )));
    assert!(package_managed(Path::new("/nix/store/abc-raven/bin")));
    assert!(!package_managed(Path::new("/opt/raven/bin")));
}

/// The node an install started from the terminal app's process is the
/// app's own only where the one it replaced was, or none ran (review
/// lock-updates-local-7), as the app's own start decides; a node a login
/// item started, or none, is nobody's.
#[test]
fn the_node_an_install_started_is_the_apps_only_in_place_of_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let host = |started_by_app, ran: Option<bool>, started| LiveHost {
        data_dir: dir.path(),
        started_by_app,
        env: None,
        item: None,
        before: ran.map(|ran| Before {
            ran,
            ..Before::default()
        }),
        started,
    };
    assert_eq!(
        host(Some(4242), Some(true), Some(4243)).adopted(),
        Some(4243)
    );
    assert_eq!(host(None, Some(false), Some(4243)).adopted(), Some(4243));
    assert_eq!(host(None, Some(true), Some(4243)).adopted(), None);
    assert_eq!(host(Some(4242), Some(true), None).adopted(), None);
    assert_eq!(host(None, None, None).adopted(), None);
}

/// `raven update ...` parses as the help says.
#[test]
fn update_commands_parse() {
    use super::super::{Cli, Commands, UpdateCommands};
    use clap::Parser;
    let parse = |args: &[&str]| {
        Cli::try_parse_from(std::iter::once("raven").chain(args.iter().copied())).map(|cli| cli.cmd)
    };
    assert!(matches!(
        parse(&["update"]),
        Ok(Some(Commands::Update { cmd: None }))
    ));
    assert!(matches!(
        parse(&["update", "import", "r.rrb", "--allow-downgrade"]),
        Ok(Some(Commands::Update {
            cmd: Some(UpdateCommands::Import {
                allow_downgrade: true,
                log: None,
                ..
            })
        }))
    ));
    assert!(matches!(
        parse(&["update", "verify", "7.rad1", "--log", "snapshot.rtl1"]),
        Ok(Some(Commands::Update {
            cmd: Some(UpdateCommands::Verify { log: Some(_), .. })
        }))
    ));
    assert!(matches!(
        parse(&["update", "download"]),
        Ok(Some(Commands::Update {
            cmd: Some(UpdateCommands::Download { offer: None })
        }))
    ));
    assert!(matches!(
        parse(&["update", "download", "3f2a91c0"]),
        Ok(Some(Commands::Update {
            cmd: Some(UpdateCommands::Download { offer: Some(_) })
        }))
    ));
    assert!(parse(&["update", "download", "--yes"]).is_err());
    assert!(matches!(
        parse(&["update", "install"]),
        Ok(Some(Commands::Update {
            cmd: Some(UpdateCommands::Install {
                allow_downgrade: false
            })
        }))
    ));
    assert!(matches!(
        parse(&["update", "rollback"]),
        Ok(Some(Commands::Update {
            cmd: Some(UpdateCommands::Rollback)
        }))
    ));
    // Nothing installs without asking: there is no --yes.
    assert!(parse(&["update", "install", "--yes"]).is_err());
}

#[cfg(debug_assertions)]
mod with_the_gate {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::rc::Rc;

    use raven_core::advisory::{AdvisoryDraft, Entry, EntryKind, Severity};
    use raven_core::release_bundle::{ManifestDraft, PackFile, THIS_TARGET};
    use raven_core::release_keys::test_keys::{key_set, signers};
    use raven_core::tlog::{LogEntry, SthDraft};

    use super::*;

    /// 2026-10-24T00:00:00Z.
    const T0: u64 = 1_792_800_000_000;
    const DAY_MS: u64 = 86_400_000;

    /// The update gates open for this thread (debug builds), shut again
    /// when dropped.
    struct Gates;

    impl Gates {
        fn open() -> Gates {
            security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
            security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, Some(true));
            Gates
        }
    }

    impl Drop for Gates {
        fn drop(&mut self) {
            security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
            security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, None);
        }
    }

    /// A build that trusts the test key set, at `serial`.
    fn build(serial: u64) -> Build {
        Build {
            key_set: Some(key_set()),
            serial,
            floor: (0, [0; 32]),
        }
    }

    fn floor_entry(serial: u64) -> Entry {
        Entry {
            kind: EntryKind::ReleaseFloor,
            severity: Severity::Deprecated,
            target: "raven".to_owned(),
            arg: serial.to_be_bytes().to_vec(),
            text_id: 0,
        }
    }

    /// The Raven project as the tests publish it: one growing log (after
    /// the key set at entry 0), its head signed by keys 0 and 1.
    struct Project {
        log: Vec<LogEntry>,
        advisories: u64,
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
                advisories: 0,
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

        /// The next advisory with these entries, listed.
        fn advisory(&mut self, entries: Vec<Entry>) -> Advisory {
            self.advisories += 1;
            let [a, _, c] = signers();
            let advisory = AdvisoryDraft {
                serial: self.advisories,
                issued_at_ms: T0 + self.advisories * DAY_MS,
                key_set_digest: key_set().digest(),
                prev_digest: self.prev,
                entries,
            }
            .sign(&[(0, &a), (2, &c)])
            .unwrap();
            self.prev = advisory.digest();
            self.list(EntryType::Advisory, advisory.digest());
            advisory
        }

        /// A release of these files for this computer, signed by keys 0 and
        /// 1 and listed: the bundle's parts.
        fn release(
            &mut self,
            serial: u64,
            version: &str,
            files: &[(&str, FileMode, Vec<u8>)],
            notes: &str,
            advisory: Option<Advisory>,
        ) -> Parts {
            let mut draft = ManifestDraft {
                build_serial: serial,
                created_at_ms: T0 + serial * DAY_MS,
                key_set_digest: key_set().digest(),
                version: version.to_owned(),
                target: THIS_TARGET.to_owned(),
                source_commit: [0xC0; 20],
                toolchain: "1.98.0".to_owned(),
                min_advisory_serial: 0,
                chunk_size: 0,
                payload_len: 0,
                payload_chunk_root: [0; 32],
                payload_sha256: [0; 32],
                files: Vec::new(),
                notes: notes.to_owned(),
            };
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
                advisory,
                payload,
            }
        }
    }

    /// A shell script that notes each run (its path and arguments) in
    /// `record` and answers `ping` with `pong`, or fails.
    fn program(tag: &str, record: &Path, answers: bool) -> Vec<u8> {
        let answer = if answers { "echo pong" } else { "exit 1" };
        format!(
            "#!/bin/sh\n# {tag}\necho \"$0 $*\" >> '{}'\n{answer}\n",
            record.display()
        )
        .into_bytes()
    }

    /// The release's files: raven, raven-node (answering or not) and a
    /// document.
    fn release_files(
        record: &Path,
        version: &str,
        answers: bool,
    ) -> Vec<(&'static str, FileMode, Vec<u8>)> {
        vec![
            (
                "bin/raven",
                FileMode::Executable,
                program(&format!("raven {version}"), record, true),
            ),
            (
                "bin/raven-node",
                FileMode::Executable,
                program(&format!("raven-node {version}"), record, answers),
            ),
            (
                "docs/README.txt",
                FileMode::Regular,
                b"Raven, the release notes.\n".to_vec(),
            ),
        ]
    }

    /// A temp profile, a temp prefix holding the installed (old) programs,
    /// and the file every program run is noted in.
    struct World {
        profile: tempfile::TempDir,
        prefix: tempfile::TempDir,
        record: PathBuf,
        _gates: Gates,
    }

    impl World {
        fn new() -> World {
            let gates = Gates::open();
            let profile = tempfile::tempdir().unwrap();
            let prefix = tempfile::tempdir().unwrap();
            let record = profile.path().join("runs.txt");
            let world = World {
                profile,
                prefix,
                record,
                _gates: gates,
            };
            for name in ["raven", "raven-node"] {
                world.put(name, &program(&format!("{name} old"), &world.record, true));
            }
            world
        }

        fn dd(&self) -> &Path {
            self.profile.path()
        }

        fn dir(&self) -> PathBuf {
            std::fs::canonicalize(self.prefix.path()).unwrap()
        }

        fn put(&self, name: &str, bytes: &[u8]) {
            let path = self.prefix.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }

        fn read(&self, name: &str) -> String {
            String::from_utf8(std::fs::read(self.prefix.path().join(name)).unwrap()).unwrap()
        }

        fn names(&self) -> BTreeSet<String> {
            std::fs::read_dir(self.prefix.path())
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        }

        fn runs(&self) -> Vec<String> {
            std::fs::read_to_string(&self.record)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        /// Write the bundle as a file and import it.
        fn import(
            &self,
            build: &Build,
            parts: &Parts,
            allow_downgrade: bool,
        ) -> Result<Vec<String>, String> {
            let file = self.dd().join("release.rrb");
            std::fs::write(&file, parts.encode()).unwrap();
            import(
                self.dd(),
                build,
                &FileArgs {
                    file,
                    log: None,
                    allow_downgrade,
                },
            )
        }

        fn ctx<'a>(&'a self, build: &'a Build, fs: &'a dyn InstallFs) -> Ctx<'a> {
            Ctx {
                data_dir: self.dd(),
                build,
                fs,
                rules: Rules::Unix,
                place: Place { dir: self.dir() },
                version: "1.4.0",
                node_program: NODE_PROGRAM.to_owned(),
                health_wait: Duration::from_millis(10),
            }
        }
    }

    /// The node as the tests see it: a stop notes what had run until then;
    /// a start runs the folder's raven-node with `ping` and keeps whether it
    /// answered.
    struct FakeHost {
        dir: PathBuf,
        record: PathBuf,
        events: Vec<String>,
        /// What had run when the node was first stopped.
        runs_at_first_stop: Option<Vec<String>>,
        answered: bool,
        stop_fails: bool,
        /// Lock v2 holds it ([`NodeHost::locked`]).
        locked: bool,
    }

    impl FakeHost {
        fn new(world: &World) -> FakeHost {
            FakeHost {
                dir: world.dir(),
                record: world.record.clone(),
                events: Vec::new(),
                runs_at_first_stop: None,
                answered: false,
                stop_fails: false,
                locked: false,
            }
        }
    }

    impl NodeHost for FakeHost {
        fn stop(&mut self) -> Result<(), String> {
            self.events.push("stop".to_owned());
            if self.runs_at_first_stop.is_none() {
                self.runs_at_first_stop = Some(
                    std::fs::read_to_string(&self.record)
                        .unwrap_or_default()
                        .lines()
                        .map(str::to_owned)
                        .collect(),
                );
            }
            if self.stop_fails {
                return Err("Raven is still running, so it can't be updated.".to_owned());
            }
            Ok(())
        }

        fn start(&mut self) -> Result<(), String> {
            self.events.push("start".to_owned());
            let out = std::process::Command::new(self.dir.join(NODE_PROGRAM))
                .arg("ping")
                .output()
                .map_err(|e| e.to_string())?;
            self.answered = out.status.success() && out.stdout.starts_with(b"pong");
            Ok(())
        }

        fn healthy(&mut self, _wait: Duration) -> bool {
            self.events.push("ping".to_owned());
            self.answered
        }

        fn locked(&mut self) -> bool {
            self.locked
        }
    }

    fn mode(path: &Path) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            0
        }
    }

    // ── import, staging, verify ─────────────────────────────────────────────

    #[test]
    fn a_bundle_is_verified_staged_and_hashed_again_and_two_builds_stay() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            "",
            None,
        );
        let lines = world.import(&b, &parts, false).unwrap();
        assert!(
            lines[0].starts_with("Raven 1.5.0 (build 5) for this computer"),
            "{lines:?}"
        );
        assert!(
            lines[1].contains("signed by 2 of the 3 Raven project keys"),
            "{lines:?}"
        );
        assert!(lines[1].contains("entry 2 of 2"), "{lines:?}");
        assert!(lines.iter().any(|l| l == NEVER_WITHOUT_ASKING));
        let staged = world.dd().join(STAGED_DIR).join("5");
        let names: BTreeSet<String> = std::fs::read_dir(&staged)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "0-raven",
                "1-raven-node",
                "2-README.txt",
                MANIFEST_NAME,
                SNAPSHOT_NAME
            ]
            .map(str::to_owned)
            .into()
        );
        // Owner only, never executable, nothing run.
        assert_eq!(mode(&staged), 0o700);
        assert_eq!(mode(&world.dd().join(STAGED_DIR)), 0o700);
        for name in &names {
            assert_eq!(mode(&staged.join(name)), 0o600, "{name}");
        }
        assert!(world.runs().is_empty());
        // The log came along into the update state.
        let state = update_state::load_with(world.dd(), &b).unwrap();
        assert_eq!(state.log_entries().len(), 2);
        // Two more builds: the oldest goes.
        for (serial, version) in [(6, "1.6.0"), (7, "1.7.0")] {
            let parts = project.release(
                serial,
                version,
                &release_files(&world.record, version, true),
                "",
                None,
            );
            world.import(&b, &parts, false).unwrap();
        }
        let serials: Vec<u64> = staged_builds(world.dd()).iter().map(|s| s.serial).collect();
        assert_eq!(serials, [7, 6]);
        // Verify keeps nothing and says so.
        let parts = project.release(
            8,
            "1.8.0",
            &release_files(&world.record, "1.8.0", true),
            "",
            None,
        );
        let file = world.dd().join("eight.rrb");
        std::fs::write(&file, parts.encode()).unwrap();
        let args = FileArgs {
            file,
            log: None,
            allow_downgrade: false,
        };
        let said = verify(world.dd(), &b, &args).unwrap();
        assert!(
            said[0].contains("Raven 1.8.0 (build 8)")
                && said.last().unwrap().contains("Nothing was kept")
        );
        assert_eq!(staged_builds(world.dd()).len(), 2);
        // The status says what waits.
        let status = update_lines(world.dd(), &b);
        assert!(
            status.iter().any(|l| l
                == "Updates: Raven 1.7.0 (build 7) is ready to install (raven update install)."),
            "{status:?}"
        );
        assert_eq!(
            net_row(world.dd(), &b).as_deref(),
            Some("1.7.0 ready to install")
        );
    }

    #[test]
    fn forged_and_foreign_files_are_refused_and_nothing_is_staged() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let mut parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            "",
            None,
        );
        parts.payload[10] ^= 1;
        let refused = world.import(&b, &parts, false).unwrap_err();
        assert!(
            refused.contains("failed its check (BAD_CHUNK_ROOT)"),
            "{refused}"
        );
        assert!(staged_builds(world.dd()).is_empty());
        // Not an update file at all.
        let other = world.dd().join("notes.txt");
        std::fs::write(&other, b"hello").unwrap();
        let args = FileArgs {
            file: other,
            log: None,
            allow_downgrade: false,
        };
        assert!(import(world.dd(), &b, &args)
            .unwrap_err()
            .contains("is not a Raven update file"));
        // A build without release keys checks nothing.
        let no_keys = Build {
            key_set: None,
            ..build(3)
        };
        let parts = project.release(
            6,
            "1.6.0",
            &release_files(&world.record, "1.6.0", true),
            "",
            None,
        );
        assert_eq!(
            world.import(&no_keys, &parts, false).unwrap_err(),
            update_state::NO_RELEASE_KEYS_TEXT
        );
        assert!(staged_builds(world.dd()).is_empty());
        assert!(world.runs().is_empty());
    }

    #[test]
    fn a_shut_gate_does_nothing_and_says_so() {
        let profile = tempfile::tempdir().unwrap();
        security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
        security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, Some(false));
        let mut project = Project::new();
        let record = profile.path().join("runs.txt");
        let parts = project.release(5, "1.5.0", &release_files(&record, "1.5.0", true), "", None);
        let file = profile.path().join("release.rrb");
        std::fs::write(&file, parts.encode()).unwrap();
        let args = FileArgs {
            file,
            log: None,
            allow_downgrade: false,
        };
        let b = build(3);
        assert_eq!(import(profile.path(), &b, &args).unwrap_err(), OFF_TEXT);
        assert!(update_lines(profile.path(), &b).is_empty());
        assert_eq!(net_row(profile.path(), &b), None);
        let fs = RealFs;
        let ctx = Ctx {
            data_dir: profile.path(),
            build: &b,
            fs: &fs,
            rules: Rules::Unix,
            place: Place {
                dir: profile.path().to_path_buf(),
            },
            version: "1.4.0",
            node_program: NODE_PROGRAM.to_owned(),
            health_wait: Duration::from_millis(10),
        };
        assert!(matches!(prepare(&ctx, InstallArgs::default()), Err(e) if e == OFF_TEXT));
        security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(false));
        assert_eq!(import(profile.path(), &b, &args).unwrap_err(), OFF_TEXT);
        assert!(!profile.path().join(update_state::UPDATES_DIR).exists());
        security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
        security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, None);
    }

    /// Every file below `dir`, as `/`-separated names.
    fn files_below(dir: &Path) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(folder) = stack.pop() {
            for entry in std::fs::read_dir(&folder).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let name = path.strip_prefix(dir).unwrap().to_string_lossy();
                    out.insert(name.replace('\\', "/"));
                }
            }
        }
        out
    }

    /// Importing writes below `updates/` only (the state, its lock beside
    /// the profile's other locks, the staged build).
    #[test]
    fn an_import_writes_only_below_updates() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            "",
            None,
        );
        let file = world.dd().join("release.rrb");
        std::fs::write(&file, parts.encode()).unwrap();
        let before = files_below(world.dd());
        world.import(&b, &parts, false).unwrap();
        let new: Vec<String> = files_below(world.dd())
            .difference(&before)
            .cloned()
            .collect();
        assert!(!new.is_empty());
        for name in &new {
            assert!(
                name.starts_with("updates/")
                    || name == update_state::UPDATE_STATE_LOCK
                    || name.starts_with(&format!("{}-", update_state::UPDATE_STATE_LOCK)),
                "{name}"
            );
        }
        assert!(
            new.iter().any(|n| n.starts_with("updates/staged/5/")),
            "{new:?}"
        );
    }

    #[test]
    fn a_notice_and_a_log_import_on_their_own() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let notice = project.advisory(vec![floor_entry(4)]);
        let folder = world.dd().join("release-log");
        std::fs::create_dir_all(folder.join("advisories")).unwrap();
        let rad1 = folder.join("advisories/1.rad1");
        std::fs::write(&rad1, notice.bytes()).unwrap();
        // Without a snapshot nearby, it says how to give one.
        let args = FileArgs {
            file: rad1.clone(),
            log: None,
            allow_downgrade: false,
        };
        assert!(import(world.dd(), &b, &args)
            .unwrap_err()
            .contains("--log FILE"));
        std::fs::write(folder.join(LOG_SNAPSHOT_NAME), project.snapshot().encode()).unwrap();
        let lines = verify(world.dd(), &b, &args).unwrap();
        assert!(
            lines[0].starts_with("Security notice #1 checks"),
            "{lines:?}"
        );
        assert_eq!(
            update_state::load_with(world.dd(), &b)
                .unwrap()
                .release_floor(),
            0
        );
        let lines = import(world.dd(), &b, &args).unwrap();
        assert!(
            lines[0].starts_with("Security notice #1 from the Raven project is checked"),
            "{lines:?}"
        );
        let state = update_state::load_with(world.dd(), &b).unwrap();
        assert_eq!(state.release_floor(), 4);
        assert_eq!(
            import(world.dd(), &b, &args).unwrap(),
            ["Raven has this security notice already."]
        );
        // The log on its own: the same one, then a longer one.
        let log = FileArgs {
            file: folder.join(LOG_SNAPSHOT_NAME),
            log: None,
            allow_downgrade: false,
        };
        assert_eq!(
            import(world.dd(), &b, &log).unwrap(),
            ["Raven has this release log (or a newer one) already."]
        );
        project.list(EntryType::Other(9), [9; 32]);
        std::fs::write(folder.join(LOG_SNAPSHOT_NAME), project.snapshot().encode()).unwrap();
        assert!(import(world.dd(), &b, &log).unwrap()[0].contains("up to date with this one"));
        assert_eq!(
            update_state::load_with(world.dd(), &b)
                .unwrap()
                .log_entries()
                .len(),
            3
        );
    }

    #[test]
    fn a_split_view_freezes_and_nothing_installs() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            "",
            None,
        );
        world.import(&b, &parts, false).unwrap();
        // Another history: the same start, another artifact after it.
        let mut other = Project::new();
        other.list(EntryType::Manifest, [7; 32]);
        let file = world.dd().join("other.rtl1");
        std::fs::write(&file, other.snapshot().encode()).unwrap();
        let args = FileArgs {
            file: file.clone(),
            log: None,
            allow_downgrade: false,
        };
        // Verify freezes nothing; import does.
        let said = verify(world.dd(), &b, &args);
        assert!(
            said.as_ref()
                .is_err_and(|e| e.contains("would stop updates")),
            "{said:?}"
        );
        assert_eq!(
            import(world.dd(), &b, &args).unwrap_err(),
            raven_core::suite_policy::FROZEN_TEXT
        );
        let fs = RealFs;
        let ctx = world.ctx(&b, &fs);
        assert_eq!(
            prepare(&ctx, InstallArgs::default()).err().as_deref(),
            Some(raven_core::suite_policy::FROZEN_TEXT)
        );
        let parts = project.release(
            6,
            "1.6.0",
            &release_files(&world.record, "1.6.0", true),
            "",
            None,
        );
        assert_eq!(
            world.import(&b, &parts, false).unwrap_err(),
            raven_core::suite_policy::FROZEN_TEXT
        );
    }

    #[test]
    fn a_staged_file_changed_on_disk_is_refused_at_install() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            "",
            None,
        );
        world.import(&b, &parts, false).unwrap();
        let staged = world.dd().join(STAGED_DIR).join("5/1-raven-node");
        let mut bytes = std::fs::read(&staged).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&staged, bytes).unwrap();
        let fs = RealFs;
        let ctx = world.ctx(&b, &fs);
        let refused = prepare(&ctx, InstallArgs::default()).err().unwrap();
        assert!(refused.contains("failed its check"), "{refused}");
        // The terminal app's expected build: another one is refused.
        std::fs::remove_dir_all(world.dd().join(STAGED_DIR)).unwrap();
        world.import(&b, &parts, false).unwrap();
        let args = InstallArgs {
            allow_downgrade: false,
            expect_serial: Some(6),
        };
        assert!(prepare(&ctx, args)
            .err()
            .unwrap()
            .contains("changed meanwhile"));
    }

    // ── install ─────────────────────────────────────────────────────────────

    /// A good install: shown, confirmed with `install`, swapped with the
    /// old programs kept as `.prev`, the node stopped before and started
    /// after; nothing from the bundle ran before the swap.
    #[cfg(unix)]
    #[test]
    fn a_good_install_swaps_keeps_prev_and_runs_nothing_before_the_swap() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let notes = "Fixes a test problem.\x1b[2J Update soon.";
        let parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            notes,
            None,
        );
        world.import(&b, &parts, false).unwrap();
        let before = world.names();
        let fs = RealFs;
        let ctx = world.ctx(&b, &fs);
        let mut host = FakeHost::new(&world);
        let mut shown = Vec::new();
        let end = install(
            &ctx,
            InstallArgs::default(),
            &mut host,
            &mut |lines, word| {
                shown = lines.to_vec();
                word == INSTALL_WORD
            },
        )
        .unwrap();
        // What was shown: version, size, signers, log place, the folder, the
        // notes sanitized.
        let all = shown.join("\n");
        assert!(
            all.contains("Raven 1.5.0 (build 5) is ready to install"),
            "{all}"
        );
        assert!(
            all.contains("signed by 2 of the 3 Raven project keys"),
            "{all}"
        );
        assert!(
            all.contains("listed in the public release log (entry 2 of 2)"),
            "{all}"
        );
        assert!(all.contains(&shown_dir(&world)), "{all}");
        assert!(all.contains("What's new: Fixes a test problem."), "{all}");
        assert!(!all.contains('\x1b'), "{all}");
        assert!(all.contains(NEVER_WITHOUT_ASKING));
        let End::Done(lines) = end else {
            panic!("{end:?}")
        };
        assert_eq!(lines[0], "Raven 1.5.0 (build 5) is installed and running.");
        assert!(
            lines[1].starts_with("Raven 1.4.0 (build 3) is kept"),
            "{lines:?}"
        );
        // The swap: new programs in place (executable), the old ones kept,
        // the document not among the programs, no leftovers.
        assert!(world.read("raven-node").contains("raven-node 1.5.0"));
        assert!(world.read("raven").contains("raven 1.5.0"));
        assert!(world.read("raven-node.prev").contains("raven-node old"));
        assert!(world.read("raven.prev").contains("raven old"));
        assert_eq!(mode(&world.dir().join("raven-node")), 0o755);
        let mut after = before.clone();
        after.insert("raven.prev".to_owned());
        after.insert("raven-node.prev".to_owned());
        assert_eq!(world.names(), after);
        // The node stopped first, nothing of the bundle had run then, and
        // only the installed raven-node ran after the swap.
        assert_eq!(host.events, ["stop", "start", "ping"]);
        assert_eq!(host.runs_at_first_stop, Some(Vec::new()));
        let node = world.dir().join("raven-node");
        assert_eq!(world.runs(), [format!("{} ping", node.display())]);
        // Recorded: the installed build, and what rollback swaps back.
        let state = update_state::load_with(world.dd(), &b).unwrap();
        assert_eq!(state.installed_serial(), 5);
        let record = state.install_record().unwrap();
        assert_eq!(record.files, ["raven", "raven-node"]);
        assert_eq!(
            (record.prev_serial, record.prev_version.as_str()),
            (3, "1.4.0")
        );
        assert_eq!(record.dir, world.dir().to_string_lossy());
        // Nothing newer waits now.
        assert_eq!(
            prepare(&ctx, InstallArgs::default()).err().as_deref(),
            Some(NOTHING_WAITING)
        );
        let status = update_lines(world.dd(), &b);
        assert!(
            status.contains(&"This Raven: Raven 1.5.0 (build 5).".to_owned()),
            "{status:?}"
        );
        assert!(
            status.contains(
                &"Raven 1.4.0 (build 3) is kept to go back to (raven update rollback).".to_owned()
            ),
            "{status:?}"
        );
    }

    #[cfg(unix)]
    fn shown_dir(world: &World) -> String {
        shown(&world.dir())
    }

    #[cfg(unix)]
    #[test]
    fn a_build_that_fails_the_health_check_rolls_back() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", false),
            "",
            None,
        );
        world.import(&b, &parts, false).unwrap();
        let before = world.names();
        let fs = RealFs;
        let ctx = world.ctx(&b, &fs);
        let mut host = FakeHost::new(&world);
        let end = install(&ctx, InstallArgs::default(), &mut host, &mut |_, _| true).unwrap();
        let End::RolledBack(lines) = end else {
            panic!("{end:?}")
        };
        assert_eq!(
            lines[0],
            "Raven 1.5.0 (build 5) didn't start, so Raven went back to Raven 1.4.0 (build 3). \
             Nothing was lost."
        );
        // The old programs are back, nothing new is left, and the old node
        // ran again.
        assert_eq!(world.names(), before);
        assert!(world.read("raven-node").contains("raven-node old"));
        assert!(world.read("raven").contains("raven old"));
        assert_eq!(
            host.events,
            ["stop", "start", "ping", "stop", "start", "ping"]
        );
        assert!(host.answered, "the old node answers again");
        let state = update_state::load_with(world.dd(), &b).unwrap();
        assert_eq!(state.installed_serial(), 3);
        assert_eq!(state.install_record(), None);
        // A stop that fails changes nothing at all.
        let mut stuck = FakeHost::new(&world);
        stuck.stop_fails = true;
        let refused =
            install(&ctx, InstallArgs::default(), &mut stuck, &mut |_, _| true).unwrap_err();
        assert!(refused.contains("still running"), "{refused}");
        assert_eq!(world.names(), before);
        assert_eq!(stuck.events, ["stop"]);
    }

    /// A failed install after a good one leaves everything as it was: the
    /// `.prev` of the good one too, so a rollback still goes back.
    #[cfg(unix)]
    #[test]
    fn a_failed_install_keeps_the_way_back_of_the_one_before() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let good = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            "",
            None,
        );
        world.import(&b, &good, false).unwrap();
        let fs = RealFs;
        let ctx = world.ctx(&b, &fs);
        let mut host = FakeHost::new(&world);
        assert!(matches!(
            install(&ctx, InstallArgs::default(), &mut host, &mut |_, _| true).unwrap(),
            End::Done(_)
        ));
        let after_good = world.names();
        let bad = project.release(
            6,
            "1.6.0",
            &release_files(&world.record, "1.6.0", false),
            "",
            None,
        );
        world.import(&b, &bad, false).unwrap();
        let end = install(&ctx, InstallArgs::default(), &mut host, &mut |_, _| true).unwrap();
        assert!(matches!(end, End::RolledBack(_)), "{end:?}");
        assert_eq!(world.names(), after_good);
        assert!(world.read("raven-node").contains("raven-node 1.5.0"));
        assert!(world.read("raven-node.prev").contains("raven-node old"));
        let state = update_state::load_with(world.dd(), &b).unwrap();
        assert_eq!(state.installed_serial(), 5);
        assert_eq!(state.install_record().unwrap().prev_serial, 3);
        assert!(matches!(
            rollback(&ctx, &mut host, &mut |_, _| true).unwrap(),
            End::Done(_)
        ));
        assert!(world.read("raven-node").contains("raven-node old"));
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_prefix_prints_the_steps_and_changes_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            "",
            None,
        );
        world.import(&b, &parts, false).unwrap();
        let before = world.names();
        std::fs::set_permissions(world.prefix.path(), std::fs::Permissions::from_mode(0o555))
            .unwrap();
        let fs = RealFs;
        let ctx = world.ctx(&b, &fs);
        if fs.dir_writable(&ctx.place.dir) {
            // Root writes anywhere: nothing to show here.
            std::fs::set_permissions(world.prefix.path(), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            return;
        }
        let mut host = FakeHost::new(&world);
        let mut asked = false;
        let end = install(&ctx, InstallArgs::default(), &mut host, &mut |_, _| {
            asked = true;
            true
        })
        .unwrap();
        std::fs::set_permissions(world.prefix.path(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let End::Manual(lines) = end else {
            panic!("{end:?}")
        };
        assert!(
            lines[0].starts_with(&format!(
                "Raven can't replace its own programs in {}: this user can't change that folder.",
                shown_dir(&world)
            )),
            "{lines:?}"
        );
        let staged = world.dd().join(STAGED_DIR).join("5");
        let copy = format!(
            "       {}  ->  {}",
            shown(&staged.join("1-raven-node")),
            shown(&world.dir().join("raven-node"))
        );
        assert!(lines.contains(&copy), "{lines:?}");
        assert!(lines
            .iter()
            .any(|l| l.contains("never asks for an administrator's rights")));
        assert!(!asked && host.events.is_empty());
        assert_eq!(world.names(), before);
        assert!(world.runs().is_empty());
    }

    #[test]
    fn a_folder_without_ravens_programs_or_with_links_is_not_swapped() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            "",
            None,
        );
        world.import(&b, &parts, false).unwrap();
        std::fs::remove_file(world.prefix.path().join("raven-node")).unwrap();
        let fs = RealFs;
        let ctx = world.ctx(&b, &fs);
        let Ok(Prepared::Manual(lines)) = prepare(&ctx, InstallArgs::default()) else {
            panic!("manual steps")
        };
        assert!(
            lines[0].contains("doesn't hold Raven's programs"),
            "{lines:?}"
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                world.dd().join("elsewhere"),
                world.prefix.path().join("raven-node"),
            )
            .unwrap();
            assert!(matches!(
                prepare(&ctx, InstallArgs::default()),
                Ok(Prepared::Manual(_))
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_downgrade_needs_allow_downgrade_and_the_floor_holds_even_then() {
        let world = World::new();
        let b = build(5);
        let mut project = Project::new();
        let older = project.release(
            4,
            "1.4.5",
            &release_files(&world.record, "1.4.5", true),
            "",
            None,
        );
        let refused = world.import(&b, &older, false).unwrap_err();
        assert!(
            refused.contains("is not newer than the Raven you have (build 5)"),
            "{refused}"
        );
        assert!(refused.contains("--allow-downgrade"), "{refused}");
        assert!(staged_builds(world.dd()).is_empty());
        let lines = world.import(&b, &older, true).unwrap();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("raven update install --allow-downgrade")),
            "{lines:?}"
        );
        let fs = RealFs;
        let ctx = world.ctx(&b, &fs);
        let mut host = FakeHost::new(&world);
        // Without the flag nothing is chosen.
        assert_eq!(
            install(&ctx, InstallArgs::default(), &mut host, &mut |_, _| true).unwrap_err(),
            NOTHING_WAITING
        );
        // With it the word is `downgrade`, and `install` does not do.
        let args = InstallArgs {
            allow_downgrade: true,
            expect_serial: None,
        };
        let mut words = Vec::new();
        let cancelled = install(&ctx, args, &mut host, &mut |lines, word| {
            words.push(word.to_owned());
            assert!(lines
                .iter()
                .any(|l| l.contains("Raven would go back to an older version")));
            false
        })
        .unwrap_err();
        assert!(cancelled.starts_with("cancelled"), "{cancelled}");
        assert_eq!(words, [DOWNGRADE_WORD]);
        assert!(host.events.is_empty());
        let end = install(&ctx, args, &mut host, &mut |_, word| word == DOWNGRADE_WORD).unwrap();
        assert!(matches!(end, End::Done(_)), "{end:?}");
        assert!(world.read("raven-node").contains("raven-node 1.4.5"));
        // A release under a security notice's floor is refused even so.
        let notice = project.advisory(vec![floor_entry(4)]);
        let under = project.release(
            3,
            "1.3.0",
            &release_files(&world.record, "1.3.0", true),
            "",
            Some(notice),
        );
        let refused = world.import(&build(4), &under, true).unwrap_err();
        assert!(
            refused.contains("has a known security problem"),
            "{refused}"
        );
        assert!(refused.contains("build 4 or later"), "{refused}");
    }

    // ── rollback ────────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn rollback_swaps_back_warns_under_the_floor_and_can_return() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let fs = RealFs;
        let ctx = world.ctx(&b, &fs);
        let mut host = FakeHost::new(&world);
        assert_eq!(
            rollback(&ctx, &mut host, &mut |_, _| true).unwrap_err(),
            NOTHING_TO_GO_BACK
        );
        // Release 5 carries a notice whose floor (4) is above build 3.
        let notice = project.advisory(vec![floor_entry(4)]);
        let parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            "",
            Some(notice),
        );
        world.import(&b, &parts, false).unwrap();
        assert!(matches!(
            install(&ctx, InstallArgs::default(), &mut host, &mut |_, _| true).unwrap(),
            End::Done(_)
        ));
        let mut shown = Vec::new();
        let mut word = String::new();
        let end = rollback(&ctx, &mut host, &mut |lines, w| {
            shown = lines.to_vec();
            word = w.to_owned();
            true
        })
        .unwrap();
        assert_eq!(word, ROLLBACK_WORD);
        assert!(
            shown[0].starts_with("Raven will go back to Raven 1.4.0 (build 3)"),
            "{shown:?}"
        );
        assert!(
            shown.iter().any(|l| l
                .starts_with("Warning: Raven 1.4.0 (build 3) has a known security problem")
                && l.contains("build 4 or later")),
            "{shown:?}"
        );
        assert!(matches!(end, End::Done(_)), "{end:?}");
        assert!(world.read("raven-node").contains("raven-node old"));
        assert!(world.read("raven-node.prev").contains("raven-node 1.5.0"));
        let state = update_state::load_with(world.dd(), &b).unwrap();
        assert_eq!(state.installed_serial(), 3);
        assert_eq!(state.install_record().unwrap().prev_serial, 5);
        // And back again: no warning now.
        let end = rollback(&ctx, &mut host, &mut |lines, _| {
            assert!(!lines.iter().any(|l| l.starts_with("Warning")), "{lines:?}");
            true
        })
        .unwrap();
        assert!(matches!(end, End::Done(_)));
        assert!(world.read("raven-node").contains("raven-node 1.5.0"));
        // Cancelled: nothing changes.
        let names = world.names();
        assert!(rollback(&ctx, &mut host, &mut |_, _| false)
            .unwrap_err()
            .starts_with("cancelled"));
        assert_eq!(world.names(), names);
        assert!(world.read("raven-node").contains("raven-node 1.5.0"));
    }

    /// Review lock-updates-local-6 (re-verify): a node Lock v2 holds is not
    /// updated. A restart would start a keychain profile's node unlocked,
    /// and where no login item starts it, on the default address (a locked
    /// node tells none). Install and rollback refuse before the question,
    /// with nothing stopped or changed; unlocked, they go on.
    #[cfg(unix)]
    #[test]
    fn a_locked_node_is_not_updated_until_it_is_unlocked() {
        let world = World::new();
        let b = build(3);
        let mut project = Project::new();
        let parts = project.release(
            5,
            "1.5.0",
            &release_files(&world.record, "1.5.0", true),
            "",
            None,
        );
        world.import(&b, &parts, false).unwrap();
        let fs = RealFs;
        let ctx = world.ctx(&b, &fs);
        let mut host = FakeHost::new(&world);
        host.locked = true;
        let names = world.names();
        let mut asked = false;
        let refused = install(&ctx, InstallArgs::default(), &mut host, &mut |_, _| {
            asked = true;
            true
        })
        .unwrap_err();
        assert_eq!(refused, LOCKED_INSTALL_TEXT);
        assert!(!asked, "refused before the question");
        assert!(host.events.is_empty(), "nothing stopped: {:?}", host.events);
        assert_eq!(world.names(), names);
        host.locked = false;
        assert!(matches!(
            install(&ctx, InstallArgs::default(), &mut host, &mut |_, _| true).unwrap(),
            End::Done(_)
        ));
        host.locked = true;
        host.events.clear();
        assert_eq!(
            rollback(&ctx, &mut host, &mut |_, _| true).unwrap_err(),
            LOCKED_ROLLBACK_TEXT
        );
        assert!(host.events.is_empty(), "nothing stopped: {:?}", host.events);
        assert!(world.read("raven-node").contains("raven-node 1.5.0"));
        host.locked = false;
        assert!(matches!(
            rollback(&ctx, &mut host, &mut |_, _| true).unwrap(),
            End::Done(_)
        ));
        assert!(world.read("raven-node").contains("raven-node old"));
    }

    // ── Windows' rules on a mock file system ────────────────────────────────

    /// A program folder in memory with Windows' rules: a file in use (a
    /// running program) can be renamed, but not replaced or deleted.
    #[derive(Default)]
    struct MockFs {
        files: RefCell<BTreeMap<PathBuf, (Vec<u8>, bool)>>,
        /// Symbolic links and what they point at (they exist, are no file).
        links: RefCell<BTreeMap<PathBuf, PathBuf>>,
        ops: RefCell<Vec<String>>,
        /// The node started from the folder runs its raven-node program.
        running: Rc<RefCell<Option<PathBuf>>>,
        /// This user can't create files in the folder.
        read_only: std::cell::Cell<bool>,
    }

    impl MockFs {
        fn link(&self, path: &Path, target: &Path) {
            self.links
                .borrow_mut()
                .insert(path.to_path_buf(), target.to_path_buf());
        }

        fn put(&self, path: &Path, bytes: &[u8], in_use: bool) {
            self.files
                .borrow_mut()
                .insert(path.to_path_buf(), (bytes.to_vec(), in_use));
        }

        fn bytes(&self, path: &Path) -> Option<Vec<u8>> {
            self.files.borrow().get(path).map(|(b, _)| b.clone())
        }

        fn in_use(&self, path: &Path) -> bool {
            self.files.borrow().get(path).is_some_and(|(_, used)| *used)
                || self.running.borrow().as_deref() == Some(path)
        }

        fn names(&self) -> Vec<String> {
            self.files
                .borrow()
                .keys()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect()
        }
    }

    fn denied(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, what.to_owned())
    }

    impl InstallFs for MockFs {
        fn dir_writable(&self, _dir: &Path) -> bool {
            !self.read_only.get()
        }

        fn is_file(&self, path: &Path) -> bool {
            self.files.borrow().contains_key(path)
        }

        fn exists(&self, path: &Path) -> bool {
            self.files.borrow().contains_key(path) || self.links.borrow().contains_key(path)
        }

        fn write_new(&self, path: &Path, bytes: &[u8], _mode: FileMode) -> io::Result<()> {
            if self.exists(path) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "exists"));
            }
            self.ops
                .borrow_mut()
                .push(format!("write {}", path.display()));
            self.put(path, bytes, false);
            Ok(())
        }

        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            if self.links.borrow().contains_key(from) || self.links.borrow().contains_key(to) {
                return Err(denied("the swap never moves or replaces a link"));
            }
            if !self.exists(from) {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no file"));
            }
            if self.exists(to) && self.in_use(to) {
                return Err(denied("a running program can't be replaced"));
            }
            self.ops
                .borrow_mut()
                .push(format!("rename {} {}", from.display(), to.display()));
            let moved = self.files.borrow_mut().remove(from).unwrap();
            let used = moved.1 || self.running.borrow().as_deref() == Some(from);
            if self.running.borrow().as_deref() == Some(from) {
                *self.running.borrow_mut() = Some(to.to_path_buf());
            }
            self.files
                .borrow_mut()
                .insert(to.to_path_buf(), (moved.0, used));
            Ok(())
        }

        fn remove(&self, path: &Path) -> io::Result<()> {
            if self.links.borrow().contains_key(path) {
                return Err(denied("the swap never removes a link"));
            }
            if self.in_use(path) {
                return Err(denied("a running program can't be deleted"));
            }
            self.ops
                .borrow_mut()
                .push(format!("remove {}", path.display()));
            self.files
                .borrow_mut()
                .remove(path)
                .map(|_| ())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no file"))
        }

        fn sync_dir(&self, _dir: &Path) {}
    }

    /// The node on the mock folder: it "runs" raven-node.exe (the file
    /// stays in use until it stops) and answers when that program says so.
    struct MockHost {
        dir: PathBuf,
        /// `raven-node`, or `raven-node.exe` on Windows.
        node: String,
        running: Rc<RefCell<Option<PathBuf>>>,
        fs_files: Rc<RefCell<Option<Vec<u8>>>>,
        good: Vec<u8>,
        events: Vec<String>,
    }

    impl NodeHost for MockHost {
        fn stop(&mut self) -> Result<(), String> {
            self.events.push("stop".to_owned());
            *self.running.borrow_mut() = None;
            Ok(())
        }

        fn start(&mut self) -> Result<(), String> {
            self.events.push("start".to_owned());
            *self.running.borrow_mut() = Some(self.dir.join(&self.node));
            Ok(())
        }

        fn healthy(&mut self, _wait: Duration) -> bool {
            self.fs_files.borrow().as_deref() == Some(&self.good[..])
        }
    }

    /// A Windows install on the mock folder: `ash.exe` runs the install and
    /// an old `raven-node.exe.prev` is still in use; `good` says whether the
    /// new raven-node answers.
    fn windows_install(good: bool) -> (MockFs, End, Vec<String>) {
        let _gates = Gates::open();
        let profile = tempfile::tempdir().unwrap();
        let b = build(3);
        let mut project = Project::new();
        let node_bytes: Vec<u8> = if good {
            b"node new good".to_vec()
        } else {
            b"node new bad".to_vec()
        };
        let files = vec![
            ("bin/ash.exe", FileMode::Executable, b"ash new".to_vec()),
            ("bin/raven-node.exe", FileMode::Executable, node_bytes),
            (
                "bin/raven-swarm.exe",
                FileMode::Executable,
                b"swarm new".to_vec(),
            ),
        ];
        let parts = project.release(5, "1.5.0", &files, "", None);
        let file = profile.path().join("release.rrb");
        std::fs::write(&file, parts.encode()).unwrap();
        import(
            profile.path(),
            &b,
            &FileArgs {
                file,
                log: None,
                allow_downgrade: false,
            },
        )
        .unwrap();
        let dir = PathBuf::from("/mock/Raven");
        let fs = MockFs::default();
        fs.put(&dir.join("ash.exe"), b"ash old", true);
        fs.put(&dir.join("raven-node.exe"), b"node old", false);
        fs.put(&dir.join("raven-node.exe.prev"), b"node older", true);
        let current = Rc::new(RefCell::new(None));
        let ctx = Ctx {
            data_dir: profile.path(),
            build: &b,
            fs: &fs,
            rules: Rules::Windows,
            place: Place { dir: dir.clone() },
            version: "1.4.0",
            node_program: "raven-node.exe".to_owned(),
            health_wait: Duration::from_millis(10),
        };
        // The health check reads what raven-node.exe holds when it runs.
        let mut host = MockHost {
            dir: dir.clone(),
            node: "raven-node.exe".to_owned(),
            running: Rc::clone(&fs.running),
            fs_files: Rc::clone(&current),
            good: b"node new good".to_vec(),
            events: Vec::new(),
        };
        struct Watch<'a> {
            host: &'a mut MockHost,
            fs: &'a MockFs,
            current: Rc<RefCell<Option<Vec<u8>>>>,
        }
        impl NodeHost for Watch<'_> {
            fn stop(&mut self) -> Result<(), String> {
                self.host.stop()
            }
            fn start(&mut self) -> Result<(), String> {
                *self.current.borrow_mut() = self.fs.bytes(&self.host.dir.join("raven-node.exe"));
                self.host.start()
            }
            fn healthy(&mut self, wait: Duration) -> bool {
                self.host.healthy(wait)
            }
        }
        let mut watch = Watch {
            host: &mut host,
            fs: &fs,
            current,
        };
        let end = install(&ctx, InstallArgs::default(), &mut watch, &mut |_, _| true).unwrap();
        let events = host.events.clone();
        drop(ctx);
        (fs, end, events)
    }

    // ── The installers' layouts (P6.52's finding) ───────────────────────────

    /// What a mock folder holds before an install: a program file (`in
    /// use`: running), or a link.
    enum Have {
        File(&'static [u8], bool),
        Link(&'static str),
    }

    /// The new release's command-line program, as every layout test ships it.
    const CLI_NEW: &[u8] = b"cli new";

    /// An install on the mock folder `/mock/Raven` that holds `have`, under
    /// `rules`, of a release that names its programs as the build scripts do
    /// (`bin/ash`, `bin/raven-node`, `bin/raven-swarm`; `exe` the system's
    /// suffix), whose raven-node answers. Also the manual steps the same
    /// folder gets when it is read-only.
    fn layout_install(rules: Rules, exe: &str, have: &[(&str, Have)]) -> LayoutRun {
        let gates = Gates::open();
        let profile = tempfile::tempdir().unwrap();
        let b = build(3);
        let mut project = Project::new();
        let name = |n: &str| format!("{n}{exe}");
        let files = [
            (
                format!("bin/{}", name("ash")),
                FileMode::Executable,
                CLI_NEW.to_vec(),
            ),
            (
                format!("bin/{}", name("raven-node")),
                FileMode::Executable,
                b"node new good".to_vec(),
            ),
            (
                format!("bin/{}", name("raven-swarm")),
                FileMode::Executable,
                b"swarm new".to_vec(),
            ),
        ];
        let refs: Vec<(&str, FileMode, Vec<u8>)> = files
            .iter()
            .map(|(path, mode, bytes)| (path.as_str(), *mode, bytes.clone()))
            .collect();
        let parts = project.release(5, "1.5.0", &refs, "", None);
        let file = profile.path().join("release.rrb");
        std::fs::write(&file, parts.encode()).unwrap();
        import(
            profile.path(),
            &b,
            &FileArgs {
                file,
                log: None,
                allow_downgrade: false,
            },
        )
        .unwrap();
        let dir = PathBuf::from("/mock/Raven");
        let fs = MockFs::default();
        for (n, what) in have {
            match what {
                Have::File(bytes, in_use) => fs.put(&dir.join(n), bytes, *in_use),
                Have::Link(target) => fs.link(&dir.join(n), &dir.join(target)),
            }
        }
        let node = name("raven-node");
        let ctx = Ctx {
            data_dir: profile.path(),
            build: &b,
            fs: &fs,
            rules,
            place: Place { dir: dir.clone() },
            version: "1.4.0",
            node_program: node.clone(),
            health_wait: Duration::from_millis(10),
        };
        fs.read_only.set(true);
        let manual = match prepare(&ctx, InstallArgs::default()).unwrap() {
            Prepared::Manual(lines) => lines,
            Prepared::Ready(_) => panic!("a read-only folder is not swapped"),
        };
        fs.read_only.set(false);
        let mut host = MockHost {
            dir: dir.clone(),
            node,
            running: Rc::clone(&fs.running),
            fs_files: Rc::new(RefCell::new(Some(b"node new good".to_vec()))),
            good: b"node new good".to_vec(),
            events: Vec::new(),
        };
        let end = install(&ctx, InstallArgs::default(), &mut host, &mut |_, _| true).unwrap();
        let record = update_state::load_with(profile.path(), &b)
            .unwrap()
            .install_record()
            .map(|r| r.files.clone());
        let back = match end {
            End::Done(_) => Some(rollback(&ctx, &mut host, &mut |_, _| true).unwrap()),
            _ => None,
        };
        let after_rollback = fs.files.borrow().clone();
        drop(ctx);
        LayoutRun {
            fs,
            end,
            manual,
            record,
            back,
            after_rollback,
            staged: profile.path().join(STAGED_DIR).join("5"),
            _profile: profile,
            _gates: gates,
        }
    }

    struct LayoutRun {
        fs: MockFs,
        end: End,
        /// The manual steps of the same folder, read-only.
        manual: Vec<String>,
        /// The install record's program files (what rollback exchanges).
        record: Option<Vec<String>>,
        /// The rollback right after a good install, and the folder then.
        back: Option<End>,
        after_rollback: BTreeMap<PathBuf, (Vec<u8>, bool)>,
        staged: PathBuf,
        _profile: tempfile::TempDir,
        _gates: Gates,
    }

    impl LayoutRun {
        fn link(&self, name: &str) -> Option<PathBuf> {
            self.fs
                .links
                .borrow()
                .get(&Path::new("/mock/Raven").join(name))
                .cloned()
        }

        fn rolled_back(&self, name: &str) -> Option<Vec<u8>> {
            self.after_rollback
                .get(&Path::new("/mock/Raven").join(name))
                .map(|(b, _)| b.clone())
        }

        /// The manual step that copies the staged program `staged_name`
        /// over the folder's `name`.
        fn copies(&self, staged_name: &str, name: &str) -> bool {
            let line = format!(
                "       {}  ->  {}",
                shown(&self.staged.join(staged_name)),
                shown(&Path::new("/mock/Raven").join(name))
            );
            self.manual.contains(&line)
        }
    }

    /// macOS and Linux (the installers): `raven` with `ash -> raven` beside
    /// it. The release's `bin/ash` replaces `raven`, the link stays and
    /// names the new program, and rollback puts `raven` back. Before the fix
    /// the link made the swap refuse the folder (manual steps only).
    #[test]
    fn a_release_ash_replaces_the_installed_raven_and_the_ash_link_stays() {
        let run = layout_install(
            Rules::Unix,
            "",
            &[
                ("raven", Have::File(b"cli old", false)),
                ("ash", Have::Link("raven")),
                ("raven-node", Have::File(b"node old", false)),
            ],
        );
        assert!(matches!(run.end, End::Done(_)), "{:?}", run.end);
        assert_eq!(
            run.record.as_deref(),
            Some(
                &[
                    "raven".to_owned(),
                    "raven-node".to_owned(),
                    "raven-swarm".to_owned()
                ][..]
            )
        );
        assert_eq!(run.link("ash"), Some(PathBuf::from("/mock/Raven/raven")));
        assert_eq!(run.rolled_back("raven").as_deref(), Some(&b"cli old"[..]));
        assert_eq!(run.rolled_back("raven.prev").as_deref(), Some(CLI_NEW));
        assert_eq!(
            run.rolled_back("raven-node").as_deref(),
            Some(&b"node old"[..])
        );
        assert_eq!(run.rolled_back("ash"), None, "no file named ash, ever");
        assert!(matches!(run.back, Some(End::Done(_))), "{:?}", run.back);
        assert!(run.copies("0-ash", "raven"), "{:?}", run.manual);
        assert!(!run.copies("0-ash", "ash"), "{:?}", run.manual);
        assert!(run.copies("1-raven-node", "raven-node"), "{:?}", run.manual);
    }

    /// Linux where the installer made no `ash` link (another `ash` shell is
    /// on the system): `raven` is replaced and no `ash` is added. Before the
    /// fix the swap added `ash` and left `raven` old.
    #[test]
    fn linux_without_the_ash_link_replaces_raven_and_adds_no_ash() {
        let run = layout_install(
            Rules::Unix,
            "",
            &[
                ("raven", Have::File(b"cli old", false)),
                ("raven-node", Have::File(b"node old", false)),
            ],
        );
        assert!(matches!(run.end, End::Done(_)), "{:?}", run.end);
        assert_eq!(
            run.record.as_deref(),
            Some(
                &[
                    "raven".to_owned(),
                    "raven-node".to_owned(),
                    "raven-swarm".to_owned()
                ][..]
            )
        );
        let mut names = run.fs.names();
        names.sort();
        // After the rollback: the old programs back, the new ones kept.
        assert!(
            !names.iter().any(|n| n == "ash" || n == "ash.prev"),
            "{names:?}"
        );
        assert_eq!(run.rolled_back("raven").as_deref(), Some(&b"cli old"[..]));
        assert_eq!(run.rolled_back("raven.prev").as_deref(), Some(CLI_NEW));
        assert!(run.copies("0-ash", "raven"), "{:?}", run.manual);
        assert!(!run.copies("0-ash", "ash"), "{:?}", run.manual);
    }

    /// Windows: `raven.exe` and `ash.exe` are two copies (the running one in
    /// use): both are replaced by the release's `ash.exe`, the running one
    /// renamed, never written over or deleted. Before the fix only `ash.exe`
    /// was.
    #[test]
    fn windows_replaces_both_copies_of_the_command_line_program() {
        let run = layout_install(
            Rules::Windows,
            ".exe",
            &[
                ("raven.exe", Have::File(b"cli old", true)),
                ("ash.exe", Have::File(b"cli old", false)),
                ("raven-node.exe", Have::File(b"node old", false)),
            ],
        );
        assert!(matches!(run.end, End::Done(_)), "{:?}", run.end);
        assert_eq!(
            run.record.as_deref(),
            Some(
                &[
                    "raven.exe".to_owned(),
                    "ash.exe".to_owned(),
                    "raven-node.exe".to_owned(),
                    "raven-swarm.exe".to_owned()
                ][..]
            )
        );
        // Rolled back: both copies old again, the new ones kept.
        for cli in ["raven.exe", "ash.exe"] {
            assert_eq!(
                run.rolled_back(cli).as_deref(),
                Some(&b"cli old"[..]),
                "{cli}"
            );
            let prev = format!("{cli}.prev");
            assert_eq!(run.rolled_back(&prev).as_deref(), Some(CLI_NEW), "{cli}");
        }
        let ops = run.fs.ops.borrow();
        assert!(
            !ops.iter().any(|op| op == "remove /mock/Raven/raven.exe"),
            "{ops:?}"
        );
        assert!(run.copies("0-ash.exe", "raven.exe"), "{:?}", run.manual);
        assert!(run.copies("0-ash.exe", "ash.exe"), "{:?}", run.manual);
    }

    /// The tarball's layout (`ash`, with `raven -> ash`) still has `ash`
    /// replaced in place and its link kept; a folder whose command-line
    /// program is only a link (someone else's) is refused as before.
    #[test]
    fn the_tarball_layout_keeps_its_link_and_a_linked_cli_alone_is_refused() {
        let run = layout_install(
            Rules::Unix,
            "",
            &[
                ("ash", Have::File(b"cli old", false)),
                ("raven", Have::Link("ash")),
                ("raven-node", Have::File(b"node old", false)),
            ],
        );
        assert!(matches!(run.end, End::Done(_)), "{:?}", run.end);
        assert_eq!(
            run.record.as_deref(),
            Some(
                &[
                    "ash".to_owned(),
                    "raven-node".to_owned(),
                    "raven-swarm".to_owned()
                ][..]
            )
        );
        assert_eq!(run.link("raven"), Some(PathBuf::from("/mock/Raven/ash")));
        assert_eq!(run.rolled_back("ash").as_deref(), Some(&b"cli old"[..]));
        let fs = MockFs::default();
        let dir = Path::new("/mock/Raven");
        fs.link(&dir.join("ash"), Path::new("/usr/bin/busybox"));
        fs.put(&dir.join("raven-node"), b"node old", false);
        let manifest_of = |run: &LayoutRun| Staged::read(&run.staged, 5).unwrap().manifest;
        let manifest = manifest_of(&run);
        assert_eq!(
            plan_swap(
                &fs,
                &Place {
                    dir: dir.to_path_buf()
                },
                &manifest,
                "raven-node"
            ),
            Err(NotHere::NotRavens)
        );
    }

    #[test]
    fn windows_renames_running_programs_and_never_replaces_or_deletes_them() {
        let (fs, end, events) = windows_install(true);
        assert!(matches!(end, End::Done(_)), "{end:?}");
        assert_eq!(events, ["stop", "start"]);
        let dir = PathBuf::from("/mock/Raven");
        assert_eq!(fs.bytes(&dir.join("ash.exe")).unwrap(), b"ash new");
        assert_eq!(
            fs.bytes(&dir.join("raven-node.exe")).unwrap(),
            b"node new good"
        );
        assert_eq!(
            fs.bytes(&dir.join("raven-swarm.exe")).unwrap(),
            b"swarm new"
        );
        // The running ash.exe was renamed to .prev, never written over.
        assert_eq!(fs.bytes(&dir.join("ash.exe.prev")).unwrap(), b"ash old");
        assert!(fs.in_use(&dir.join("ash.exe.prev")));
        assert_eq!(
            fs.bytes(&dir.join("raven-node.exe.prev")).unwrap(),
            b"node old"
        );
        // The older .prev still in use was renamed aside, and stays there.
        assert_eq!(
            fs.bytes(&dir.join("raven-node.exe.prev.raven-old"))
                .unwrap(),
            b"node older"
        );
        let ops = fs.ops.borrow();
        assert!(
            !ops.contains(&"remove /mock/Raven/ash.exe".to_owned()),
            "{ops:?}"
        );
        assert_eq!(
            fs.names(),
            [
                "ash.exe",
                "ash.exe.prev",
                "raven-node.exe",
                "raven-node.exe.prev",
                "raven-node.exe.prev.raven-old",
                "raven-swarm.exe",
            ]
        );
    }

    #[test]
    fn windows_rolls_back_with_the_failed_node_still_running() {
        let (fs, end, events) = windows_install(false);
        let End::RolledBack(lines) = end else {
            panic!("{end:?}")
        };
        assert!(
            lines[0].contains("didn't start, so Raven went back"),
            "{lines:?}"
        );
        assert_eq!(events, ["stop", "start", "stop", "start"]);
        let dir = PathBuf::from("/mock/Raven");
        assert_eq!(fs.bytes(&dir.join("ash.exe")).unwrap(), b"ash old");
        assert_eq!(fs.bytes(&dir.join("raven-node.exe")).unwrap(), b"node old");
        // The program the release added is gone; the running ash.exe never
        // was deleted or replaced; the older .prev is back in its place.
        assert!(!fs.exists(&dir.join("raven-swarm.exe")));
        assert!(fs.in_use(&dir.join("ash.exe")));
        assert_eq!(
            fs.bytes(&dir.join("raven-node.exe.prev")).unwrap(),
            b"node older"
        );
        assert_eq!(
            fs.names(),
            ["ash.exe", "raven-node.exe", "raven-node.exe.prev"]
        );
    }

    #[test]
    fn windows_exchange_moves_a_running_program_without_replacing_it() {
        let fs = MockFs::default();
        let dir = PathBuf::from("/mock/Raven");
        fs.put(&dir.join("ash.exe"), b"ash new", true);
        fs.put(&dir.join("ash.exe.prev"), b"ash old", false);
        fs.put(&dir.join("raven-swarm.exe"), b"swarm new", false);
        let names = vec!["ash.exe".to_owned(), "raven-swarm.exe".to_owned()];
        exchange_all(&fs, &dir, &names).unwrap();
        assert_eq!(fs.bytes(&dir.join("ash.exe")).unwrap(), b"ash old");
        assert_eq!(fs.bytes(&dir.join("ash.exe.prev")).unwrap(), b"ash new");
        assert!(fs.in_use(&dir.join("ash.exe.prev")));
        assert_eq!(
            fs.bytes(&dir.join("raven-swarm.exe.prev")).unwrap(),
            b"swarm new"
        );
        exchange_all(&fs, &dir, &names).unwrap();
        assert_eq!(fs.bytes(&dir.join("ash.exe")).unwrap(), b"ash new");
        assert_eq!(
            fs.bytes(&dir.join("raven-swarm.exe")).unwrap(),
            b"swarm new"
        );
        assert!(!fs.ops.borrow().iter().any(|op| op.starts_with("remove")));
    }
}
