//! PP.15 tests: the stop step (its table, moved here from the terminal
//! app), Raven's own login item (only the installer's item, only for this
//! data dir, as each installer writes it), the debug guard, the exact
//! arguments each action runs (fake tools that record them; no real login
//! item is ever read or changed) and the macOS installer's enable before
//! bootstrap.

use super::*;
use raven_core::ipc::IPC_VERSION;

/// The installers' item for a `raven-node service --data-dir <dir>` run.
pub(crate) fn fixture(platform: Platform, dir: &Path) -> String {
    let dir = dir.display().to_string();
    match platform {
        // macos_launchd.sh's plist (an empty line where no Internet or p2p
        // flag was asked for).
        Platform::MacOs => format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.raven.raven-node</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/raven/bin/raven-node</string>
    <string>service</string>
    <string>--data-dir</string>
    <string>{}</string>
    <string>--lan-listen</string>
    <string>127.0.0.1:7420</string>
    <string>--ble-listen</string>
    <string>127.0.0.1:7421</string>

    <string>--timeout-secs</string>
    <string>0</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#,
            dir.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        ),
        // linux_systemd_user.sh's unit (sd_quote).
        Platform::Linux => format!(
            "[Unit]\nDescription=RAVEN raven-node service (bridge + IPC)\n\n[Service]\n\
             Type=simple\nExecStart=\"/opt/raven/bin/raven-node\" service --data-dir \
             \"{}\" --lan-listen \"127.0.0.1:7420\" --ble-listen 127.0.0.1:7421 --timeout-secs \
             0\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n",
            dir.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('%', "%%")
                .replace('$', "$$")
        ),
        // What `schtasks /Query /XML` prints for windows_service.ps1's task.
        Platform::Windows => format!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Task version=\"1.4\">\n  \
             <Actions Context=\"Author\">\n    <Exec>\n      \
             <Command>C:\\Raven\\bin\\raven-node.exe</Command>\n      \
             <Arguments>service --data-dir \"{}\" --lan-listen 127.0.0.1:7420 --ble-listen \
             127.0.0.1:7421 --timeout-secs 0</Arguments>\n    </Exec>\n  </Actions>\n</Task>\n",
            dir.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        ),
    }
}

/// The same file names, written by someone else for this data dir: another
/// label, another program, a service that is not `raven-node service`.
fn foreign(platform: Platform, dir: &Path) -> Vec<String> {
    let ours = fixture(platform, dir);
    match platform {
        Platform::MacOs => vec![
            ours.replace(
                "<string>com.raven.raven-node</string>",
                "<string>org.example.sync</string>",
            ),
            ours.replace("/bin/raven-node<", "/bin/other-node<"),
            ours.replace("<string>service</string>", "<string>relay</string>"),
        ],
        Platform::Linux => vec![
            ours.replace("/bin/raven-node\"", "/bin/other\""),
            ours.replace("\" service --data-dir", "\" relay --data-dir"),
            ours.replace("ExecStart=", "ExecStartPre="),
        ],
        Platform::Windows => vec![
            ours.replace("raven-node.exe</Command>", "other.exe</Command>"),
            ours.replace("<Arguments>service ", "<Arguments>relay "),
        ],
    }
}

const ALL: [Platform; 3] = [Platform::MacOs, Platform::Linux, Platform::Windows];

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn stop_plan_table() {
    use StopPlan::{Advise, Managed, NotRunning, TaskKill, Terminate};
    let table = [
        // windows, managed, running, status pid, started by app -> plan
        (false, false, true, Some(42), None, Terminate(42)),
        (false, false, true, Some(42), Some(42), Terminate(42)),
        (false, false, true, None, None, Advise(None)),
        (false, true, true, Some(42), Some(42), Managed),
        (false, false, false, None, Some(42), NotRunning),
        (true, false, true, Some(42), Some(42), TaskKill(42)),
        // Windows: a pid this app did not start, or no longer reported.
        (true, false, true, Some(42), None, Advise(Some(42))),
        (true, false, true, Some(43), Some(42), Advise(Some(43))),
        (true, false, true, None, Some(42), Advise(None)),
        (true, true, true, Some(42), Some(42), Managed),
        (true, false, false, None, Some(42), NotRunning),
    ];
    for (windows, managed, running, pid, ours, want) in table {
        assert_eq!(
            stop_plan(windows, managed, running, pid, ours),
            want,
            "windows {windows}, managed {managed}, running {running}, pid {pid:?}, ours {ours:?}"
        );
    }
}

#[test]
fn a_status_says_whether_a_node_runs_and_its_pid() {
    let status = |pid| {
        Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: Vec::new(),
            p2p: None,
            pid,
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        })
    };
    assert_eq!(running_pid(&status(Some(42))), (true, Some(42)));
    assert_eq!(running_pid(&status(None)), (true, None));
    assert_eq!(
        running_pid(&Err("raven-node is not running; start it".into())),
        (false, None)
    );
    // Took the request and never answered: it runs.
    assert_eq!(
        running_pid(&Err("timed out waiting for raven-node".into())),
        (true, None)
    );
}

#[test]
fn stopping_a_profile_with_no_node_stops_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(stop(dir.path()), (StopOutcome::NotRunning, None));
    assert!(node_gone(dir.path()));
    assert_eq!(wait_gone(dir.path(), Duration::ZERO), Gone::Yes);
    assert!(!node_answers(dir.path()));
}

#[test]
fn windows_tools_run_by_absolute_path_only() {
    let root = std::env::temp_dir();
    assert_eq!(
        system_tool(Some(root.as_os_str()), "taskkill.exe"),
        Some(root.join("System32").join("taskkill.exe"))
    );
    assert_eq!(
        system_tool(Some(OsStr::new("Windows")), "taskkill.exe"),
        None
    );
    assert_eq!(system_tool(Some(OsStr::new("")), "schtasks.exe"), None);
    assert_eq!(system_tool(None, "schtasks.exe"), None);
}

#[cfg(unix)]
#[test]
fn kill_term_signals_one_process_only() {
    use std::os::unix::process::ExitStatusExt;
    // 0 is our own process group; u32::MAX would be kill(-1): everything.
    for pid in [0, u32::MAX, 1 << 31] {
        assert_eq!(
            kill_term(pid).map_err(|e| e.kind()),
            Err(io::ErrorKind::InvalidInput),
            "pid {pid}"
        );
    }
    let mut child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    kill_term(child.id()).expect("kill_term");
    assert_eq!(child.wait().expect("wait").signal(), Some(15));
}

#[test]
fn guard_refuses_without_lab_root_in_debug() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, tools) = (tmp.path().join("items"), tmp.path().join("tools"));
    let home = tmp.path().join("home");
    let text = |p: &Path| Some(p.display().to_string());
    // An absolute SystemRoot on the host the test runs on.
    let system_root = if cfg!(windows) {
        "C:\\Windows"
    } else {
        "/windows"
    };
    let resolve = |debug: bool, root: Option<String>, tools: Option<String>, platform| {
        LoginEnv::resolve(
            debug,
            root,
            tools,
            platform,
            Some(home.clone().into_os_string()),
            Some(OsString::from(system_root)),
            501,
        )
    };
    // A debug build without both switches (or with a relative one) refuses.
    for (r, t) in [
        (None, None),
        (text(&root), None),
        (None, text(&tools)),
        (Some("items".to_owned()), text(&tools)),
        (text(&root), Some("tools".to_owned())),
    ] {
        assert_eq!(
            resolve(true, r.clone(), t.clone(), Platform::MacOs),
            Err(LAB_GUARD_TEXT.to_owned()),
            "{r:?} {t:?}"
        );
    }
    // With both: only the lab folder and the fake tool.
    for platform in ALL {
        assert_eq!(
            resolve(true, text(&root), text(&tools), platform),
            Ok(LoginEnv {
                platform,
                folder: Some(root.clone()),
                tool: tools.join(platform.tool_name()),
                uid: 501,
            })
        );
    }
    // A release build never uses the lab folders: the real places.
    let mac = resolve(false, text(&root), text(&tools), Platform::MacOs).unwrap();
    assert_eq!(mac.folder, Some(home.join("Library/LaunchAgents")));
    assert_eq!(mac.tool, PathBuf::from("/bin/launchctl"));
    let linux = resolve(false, text(&root), text(&tools), Platform::Linux).unwrap();
    assert_eq!(linux.folder, Some(home.join(".config/systemd/user")));
    assert!(linux.tool.ends_with("systemctl"), "{:?}", linux.tool);
    let windows = resolve(false, None, None, Platform::Windows).unwrap();
    assert_eq!(windows.folder, None);
    assert_eq!(
        windows.tool,
        Path::new(system_root).join("System32").join("schtasks.exe")
    );
    // No absolute home or SystemRoot: nothing to act on.
    assert!(LoginEnv::resolve(false, None, None, Platform::MacOs, None, None, 501).is_err());
    assert!(LoginEnv::resolve(
        false,
        None,
        None,
        Platform::Linux,
        Some("rel".into()),
        None,
        501
    )
    .is_err());
    assert!(LoginEnv::resolve(false, None, None, Platform::Windows, None, None, 501).is_err());
    // This test process: a debug build refuses unless both switches are set.
    if cfg!(debug_assertions) {
        let set = [LAB_LOGIN_ITEM_ROOT, LAB_LOGIN_ITEM_TOOLS]
            .iter()
            .all(|name| {
                raven_core::p2p_gate::lab_switch(name).is_some_and(|v| Path::new(&v).is_absolute())
            });
        if !set {
            assert_eq!(LoginEnv::current(), Err(LAB_GUARD_TEXT.to_owned()));
        }
    }
}

/// Phase 6 review (traffic-5): the address Raven's own login item gives
/// raven-node's LAN listener, as each installer writes it: what `raven lan
/// port random` reads to tell whether the service keeps its own port. Only
/// this profile's item counts.
#[test]
fn own_item_lan_listen_reads_the_installers_address() {
    let tmp = tempfile::tempdir().unwrap();
    let this = tmp.path().join("profile");
    let other = tmp.path().join("profile-2");
    std::fs::create_dir_all(&this).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    for platform in ALL {
        let root = tmp.path().join(format!("listen-{platform:?}"));
        std::fs::create_dir_all(&root).unwrap();
        let env = LoginEnv::lab(platform, &root, &tmp.path().join("tools"), 501);
        let file = root.join(platform.item_file());
        assert_eq!(
            own_item_lan_listen(&env, &this),
            None,
            "{platform:?}: no item"
        );
        write(&file, &fixture(platform, &this));
        assert_eq!(
            own_item_lan_listen(&env, &this).as_deref(),
            Some("127.0.0.1:7420"),
            "{platform:?}"
        );
        for listen in ["auto:43210", "auto"] {
            write(
                &file,
                &fixture(platform, &this).replace("127.0.0.1:7420", listen),
            );
            assert_eq!(
                own_item_lan_listen(&env, &this).as_deref(),
                Some(listen),
                "{platform:?}"
            );
        }
        write(&file, &fixture(platform, &other));
        assert_eq!(
            own_item_lan_listen(&env, &this),
            None,
            "{platform:?}: another profile's"
        );
        for text in foreign(platform, &this) {
            write(&file, &text);
            assert_eq!(
                own_item_lan_listen(&env, &this),
                None,
                "{platform:?}: {text}"
            );
        }
    }
}

#[test]
fn own_login_item_matches_only_this_data_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let this = tmp.path().join("profile");
    let other = tmp.path().join("profile-2");
    std::fs::create_dir_all(&this).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    for platform in ALL {
        let root = tmp.path().join(format!("items-{platform:?}"));
        std::fs::create_dir_all(&root).unwrap();
        let env = LoginEnv::lab(platform, &root, &tmp.path().join("tools"), 501);
        let file = root.join(platform.item_file());
        assert_eq!(own_login_item(&env, &this), None, "{platform:?}: no item");

        // Another profile's item: never this profile's.
        write(&file, &fixture(platform, &other));
        assert_eq!(own_login_item(&env, &this), None, "{platform:?}");
        assert!(own_login_item(&env, &other).is_some(), "{platform:?}");

        // This profile's, by any spelling of its folder.
        write(&file, &fixture(platform, &this));
        let want = Some(LoginItem {
            platform,
            file: Some(file.clone()),
        });
        assert_eq!(own_login_item(&env, &this), want, "{platform:?}");
        let spelled = other.join("..").join("profile");
        assert_eq!(own_login_item(&env, &spelled), want, "{platform:?}");

        // Someone else's file at the installer's name, for this data dir.
        for text in foreign(platform, &this) {
            write(&file, &text);
            assert_eq!(own_login_item(&env, &this), None, "{platform:?}: {text}");
        }
    }
}

#[test]
fn item_for_another_data_dir_is_foreign() {
    let tmp = tempfile::tempdir().unwrap();
    let this = tmp.path().join("prof");
    std::fs::create_dir_all(this.join("sub")).unwrap();
    std::fs::create_dir_all(tmp.path().join("prof2")).unwrap();
    for platform in ALL {
        let root = tmp.path().join(format!("items-{platform:?}"));
        let env = LoginEnv::lab(platform, &root, &tmp.path().join("tools"), 501);
        let file = root.join(platform.item_file());
        // A name that starts the same, a folder inside it, its parent, and
        // a folder that does not exist (nothing to canonicalize).
        for dir in [
            tmp.path().join("prof2"),
            this.join("sub"),
            tmp.path().to_path_buf(),
            tmp.path().join("gone"),
        ] {
            write(&file, &fixture(platform, &dir));
            assert_eq!(own_login_item(&env, &this), None, "{platform:?} {dir:?}");
        }
        // An item the size cap refuses.
        write(
            &file,
            &format!(
                "{}{}",
                fixture(platform, &this),
                " ".repeat(MAX_ITEM_BYTES as usize)
            ),
        );
        assert_eq!(own_login_item(&env, &this), None, "{platform:?}: too big");
    }
}

#[test]
fn item_files_parse_as_the_installers_quote_them() {
    // Each installer's quoting, with every character it escapes.
    let odd = Path::new("/srv/my \"raven\" 100% $HOME & <x>");
    for platform in [Platform::MacOs, Platform::Linux] {
        assert_eq!(
            item_data_dir(platform, &fixture(platform, odd)).as_deref(),
            Some(odd.to_str().unwrap()),
            "{platform:?}"
        );
    }
    let win = Path::new("C:\\Raven data & co\\.raven");
    assert_eq!(
        item_data_dir(Platform::Windows, &fixture(Platform::Windows, win)).as_deref(),
        Some(win.to_str().unwrap())
    );
    // The scheduler may write the quotes as entities, and the file as UTF-16.
    let quoted = fixture(Platform::Windows, win)
        .replace("\"C:", "&quot;C:")
        .replace("\\.raven\" --lan", "\\.raven&quot; --lan");
    let mut utf16 = vec![0xFF, 0xFE];
    utf16.extend(quoted.encode_utf16().flat_map(u16::to_le_bytes));
    assert_eq!(
        item_data_dir(Platform::Windows, &decode_text(&utf16)).as_deref(),
        Some(win.to_str().unwrap())
    );
    // Words: systemd's escapes inside and outside quotes; an unterminated
    // quote is no command line.
    assert_eq!(
        systemd_words(r#"  "/a b/raven-node"  service --data-dir "x\"y" z\ w "#),
        Some(args(&[
            "/a b/raven-node",
            "service",
            "--data-dir",
            "x\"y",
            "z w"
        ]))
    );
    assert_eq!(systemd_words("\"open"), None);
    assert_eq!(windows_words("a \"b c\" d"), Some(args(&["a", "b c", "d"])));
    assert_eq!(windows_words("a \"b"), None);
    assert_eq!(decode_text(b"\xEF\xBB\xBFplain"), "plain");
}

/// Review D-lock-tui-3: the passphrase file Raven's own unit hands
/// raven-node, as linux_systemd_user.sh writes it (`Environment=` with
/// sd_quote, or `LoadCredential=` with
/// RAVEN_SYSTEMD_LOAD_CREDENTIAL=1).
#[test]
fn the_unit_names_the_passphrase_file_it_hands_raven_node() {
    let unit = fixture(Platform::Linux, Path::new("/home/sam/.raven"));
    let with = |lines: &[&str]| {
        unit.replace(
            "Restart=on-failure\n",
            &format!("Restart=on-failure\n{}\n", lines.join("\n")),
        )
    };
    assert_eq!(unit_passphrase_file(&unit), None);
    let env = "Environment=\"RAVEN_KEYSTORE_PASSPHRASE_FILE=/srv/keys/pass\"";
    let credential = "LoadCredential=raven-keystore-passphrase:/srv/keys/cred";
    assert_eq!(
        unit_passphrase_file(&with(&[env])),
        Some(PathBuf::from("/srv/keys/pass"))
    );
    assert_eq!(
        unit_passphrase_file(&with(&[credential])),
        Some(PathBuf::from("/srv/keys/cred"))
    );
    // Both: the variable, which raven-node reads first.
    assert_eq!(
        unit_passphrase_file(&with(&[credential, env])),
        Some(PathBuf::from("/srv/keys/pass"))
    );
    // sd_quote's escapes, beside another assignment on the same line.
    assert_eq!(
        unit_passphrase_file(&with(&[
            "Environment=\"LANG=C\" \"RAVEN_KEYSTORE_PASSPHRASE_FILE=/srv/my keys/100%% pass\""
        ])),
        Some(PathBuf::from("/srv/my keys/100% pass"))
    );
    // Not the passphrase file: another variable, another credential, a
    // relative path.
    for line in [
        "Environment=\"RAVEN_DATA_DIR=/srv/keys/pass\"",
        "LoadCredential=another:/srv/keys/cred",
        "Environment=\"RAVEN_KEYSTORE_PASSPHRASE_FILE=keys/pass\"",
        "LoadCredential=raven-keystore-passphrase:keys/cred",
    ] {
        assert_eq!(unit_passphrase_file(&with(&[line])), None, "{line}");
    }
    // Only Raven's own unit is read: a launch agent or a task names none.
    let tmp = tempfile::tempdir().unwrap();
    let this = tmp.path().join("profile");
    std::fs::create_dir_all(&this).unwrap();
    for platform in ALL {
        let root = tmp.path().join(format!("{platform:?}"));
        let text = fixture(platform, &this).replace(
            "Restart=on-failure\n",
            &format!("Restart=on-failure\n{env}\n"),
        );
        write(&root.join(platform.item_file()), &text);
        let env = LoginEnv::lab(platform, &root, &root, 501);
        let item = own_login_item(&env, &this).expect("this profile's item");
        let want = (platform == Platform::Linux).then(|| PathBuf::from("/srv/keys/pass"));
        assert_eq!(item_passphrase_file(&item), want, "{platform:?}");
    }
}

/// Fake `launchctl`, `systemctl` and `schtasks.exe` in `dir`/tools that
/// append their name and arguments to `dir`/calls.log; with `fail`, they
/// also exit 3 and say so on stderr.
#[cfg(unix)]
pub(crate) fn shims(dir: &Path, fail: bool) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let tools = dir.join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let log = dir.join("calls.log");
    for name in ["launchctl", "systemctl", "schtasks.exe"] {
        let path = tools.join(name);
        let tail = if fail {
            "echo 'Boot-out failed: 3: No such process' >&2\nexit 3\n"
        } else {
            ""
        };
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$(basename \"$0\") $*\" >> '{}'\n{tail}",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (tools, log)
}

/// What the fake tools recorded, one run per line.
#[cfg(unix)]
pub(crate) fn calls(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[cfg(unix)]
#[test]
fn each_action_runs_these_arguments_and_a_failure_says_why() {
    let tmp = tempfile::tempdir().unwrap();
    let this = tmp.path().join("profile");
    std::fs::create_dir_all(&this).unwrap();
    for platform in ALL {
        let dir = tmp.path().join(format!("{platform:?}"));
        let (tools, log) = shims(&dir, false);
        let root = dir.join("items");
        write(&root.join(platform.item_file()), &fixture(platform, &this));
        let env = LoginEnv::lab(platform, &root, &tools, 501);
        let item = own_login_item(&env, &this).expect("this profile's item");
        stop_for_session(&env, &item).unwrap();
        disable_login_item(&env, &item).unwrap();
        enable_login_item(&env, &item, true).unwrap();
        enable_login_item(&env, &item, false).unwrap();
        let plist = root.join(LAUNCH_AGENT_FILE);
        let want: Vec<String> = match platform {
            Platform::MacOs => vec![
                "launchctl bootout gui/501/com.raven.raven-node".into(),
                "launchctl disable gui/501/com.raven.raven-node".into(),
                "launchctl enable gui/501/com.raven.raven-node".into(),
                format!("launchctl bootstrap gui/501 {}", plist.display()),
                "launchctl enable gui/501/com.raven.raven-node".into(),
            ],
            Platform::Linux => vec![
                "systemctl --user stop raven-node.service".into(),
                "systemctl --user disable --now raven-node.service".into(),
                "systemctl --user enable --now raven-node.service".into(),
                "systemctl --user enable raven-node.service".into(),
            ],
            Platform::Windows => vec![
                "schtasks.exe /End /TN RavenNodeBridge".into(),
                "schtasks.exe /Change /TN RavenNodeBridge /DISABLE".into(),
                "schtasks.exe /Change /TN RavenNodeBridge /ENABLE".into(),
                "schtasks.exe /Run /TN RavenNodeBridge".into(),
                "schtasks.exe /Change /TN RavenNodeBridge /ENABLE".into(),
            ],
        };
        assert_eq!(calls(&log), want, "{platform:?}");

        // A tool that fails: its own words, and the next run is not made.
        let failing = dir.join("failing");
        let (bad_tools, bad_log) = shims(&failing, true);
        let bad = LoginEnv::lab(platform, &root, &bad_tools, 501);
        let err = enable_login_item(&bad, &item, true).unwrap_err();
        assert!(err.contains("Boot-out failed: 3: No such process"), "{err}");
        assert!(err.starts_with(platform.tool_name()), "{err}");
        assert_eq!(
            calls(&bad_log).len(),
            1,
            "{platform:?}: stops at the first failure"
        );
    }
    // A tool that is not there.
    let env = LoginEnv::lab(
        Platform::Linux,
        tmp.path(),
        &tmp.path().join("no-tools"),
        501,
    );
    let item = LoginItem {
        platform: Platform::Linux,
        file: None,
    };
    let err = stop_for_session(&env, &item).unwrap_err();
    assert!(
        err.starts_with("systemctl --user stop raven-node.service: "),
        "{err}"
    );
}

/// The macOS installer turns the agent back on before it loads it: a
/// re-install after `raven lock` disabled it would otherwise be refused by
/// `bootstrap` and abort under `set -e`. The installer runs for real in a
/// temp home with fake `cargo`, `install` and `launchctl` first on PATH (and
/// a check that they are the ones found), so nothing real is built, copied
/// or loaded; the plist it writes is this profile's own login item.
#[cfg(unix)]
#[test]
fn installer_enables_before_bootstrap() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let (shim_dir, log) = shims(tmp.path(), false);
    for (name, body) in [
        ("cargo", "exit 0\n".to_owned()),
        // install -m 755 SRC DST: DST becomes a program that does nothing.
        (
            "install",
            "for last; do :; done\nprintf '#!/bin/sh\\nexit 0\\n' > \"$last\"\nchmod 755 \
             \"$last\"\n"
                .to_owned(),
        ),
    ] {
        let path = shim_dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let home = tmp.path().join("home");
    let data = tmp.path().join("profile");
    std::fs::create_dir_all(&home).unwrap();
    let path = format!("{}:/usr/bin:/bin", shim_dir.display());
    let found = |tool: &str| {
        let out = Command::new("/bin/sh")
            .args(["-c", &format!("command -v {tool}")])
            .env_clear()
            .env("PATH", &path)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    for tool in ["launchctl", "cargo", "install"] {
        assert_eq!(
            found(tool),
            shim_dir.join(tool).display().to_string(),
            "the fake {tool} must be the one the installer runs"
        );
    }
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/install/macos_launchd.sh");
    let bash = ["/bin/bash", "/usr/bin/bash"]
        .into_iter()
        .find(|b| Path::new(b).is_file())
        .expect("bash");
    let out = Command::new(bash)
        .arg(&script)
        .env_clear()
        .env("PATH", &path)
        .env("HOME", &home)
        .env("RAVEN_DATA_DIR", &data)
        .env("RAVEN_BIN_DIR", tmp.path().join("bin"))
        // The Bluetooth helper app (installed by default since 2026-10)
        // needs a real build and codesign: not here. The Tor helper is
        // "installed" by the fake `install` like the other binaries.
        .env("RAVEN_INSTALL_NEARBY_HELPER", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let uid = current_uid();
    let plist = home.join("Library/LaunchAgents").join(LAUNCH_AGENT_FILE);
    assert_eq!(
        calls(&log),
        [
            format!("launchctl bootout gui/{uid}/com.raven.raven-node"),
            format!("launchctl enable gui/{uid}/com.raven.raven-node"),
            format!("launchctl bootstrap gui/{uid} {}", plist.display()),
        ]
    );
    // 2026-10: the Tor onion carrier's helper goes next to raven-node.
    assert!(
        tmp.path().join("bin/raven-tor-helper").is_file(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let env = LoginEnv::lab(
        Platform::MacOs,
        &home.join("Library/LaunchAgents"),
        &shim_dir,
        uid,
    );
    assert!(
        own_login_item(&env, &data).is_some(),
        "the installer's item"
    );
    assert_eq!(own_login_item(&env, tmp.path()), None);
}
