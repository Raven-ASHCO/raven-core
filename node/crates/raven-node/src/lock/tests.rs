//! Lock v2's tests (P6.40): the back-off, the wrong-passphrase path against a
//! real vault (cheap KDF parameters), and a real LAN listener that a lock
//! closes and an unlock opens again.

use std::sync::Arc;

use raven_core::keystore_vault::{
    KdfBounds, KdfParams, KeyCache, PassphrasePurpose, PassphraseSource,
};
use raven_core::security_gate::set_lab_for_this_thread;

use super::*;

/// The gate open on this thread for the guard's life.
struct GateOpen;

impl GateOpen {
    fn new() -> Self {
        set_lab_for_this_thread(SecGate::LocalProtection, Some(true));
        GateOpen
    }
}

impl Drop for GateOpen {
    fn drop(&mut self) {
        set_lab_for_this_thread(SecGate::LocalProtection, None);
    }
}

/// A current-thread runtime: the test's tasks run on its thread, where its
/// lock lives (and a std guard it holds is never held across another
/// thread's await).
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

const PARAMS: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};
const BOUNDS: KdfBounds = KdfBounds {
    min_m_kib: 8,
    max_m_kib: 1 << 20,
    min_t: 1,
    max_t: 10,
    min_p: 1,
    max_p: 4,
};
const PASSPHRASE: &str = "correct horse battery";

struct Fixed(&'static str);

impl PassphraseSource for Fixed {
    fn passphrase(
        &self,
        _purpose: PassphrasePurpose,
        _vault_path: &Path,
    ) -> Result<SecretBytes, VaultError> {
        Ok(SecretBytes::new(self.0.as_bytes().to_vec()))
    }
}

fn test_vault(dir: &Path, passphrase: &'static str) -> Vault {
    Vault::with_options(
        dir,
        PARAMS,
        BOUNDS,
        Arc::new(Fixed(passphrase)),
        Arc::new(KeyCache::default()),
    )
}

/// A profile with a Raven passphrase: its keys in a vault (one entry
/// here), and the marker that says so.
fn passphrase_profile_in(dir: &Path) {
    test_vault(dir, PASSPHRASE).put("probe", b"x").unwrap();
    std::fs::write(
        dir.join(raven_core::keystore_select::KEYSTORE_MARKER_NAME),
        "passphrase-vault\n",
    )
    .unwrap();
}

fn secret(text: &str) -> Option<SecretBytes> {
    Some(SecretBytes::new(text.as_bytes().to_vec()))
}

/// Waits (at most 60 s) until `ok`.
async fn wait_until(what: &str, ok: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !ok() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn check(dir: &Path, passphrase: &[u8]) -> Result<(), VaultError> {
    test_vault(dir, "unused").verify_passphrase(passphrase)
}

#[test]
fn a_wrong_passphrase_waits_one_second_doubling_to_sixty() {
    let waits: Vec<u64> = (1..=9).map(|n| delay(n).as_secs()).collect();
    assert_eq!(waits, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
    assert_eq!(delay(u32::MAX), BACKOFF_MAX);
    let t = Instant::now();
    let mut backoff = Backoff::default();
    assert_eq!(backoff.wait_left(t), None);
    backoff.wrong(t);
    assert_eq!(backoff.wait_left(t), Some(Duration::from_secs(1)));
    assert_eq!(backoff.wait_left(t + Duration::from_secs(1)), None);
    backoff.wrong(t + Duration::from_secs(1));
    assert_eq!(
        backoff.wait_left(t + Duration::from_millis(1500)),
        Some(Duration::from_millis(1500))
    );
    assert_eq!(whole_secs(Duration::from_millis(1500)), 2);
    assert_eq!(whole_secs(Duration::from_secs(3)), 3);
    assert_eq!(backoff.opened(), 2, "said once by the unlock");
    assert_eq!(backoff.opened(), 0);
    assert_eq!(backoff.wait_left(t), None, "an unlock starts it over");
}

/// Gate shut: `Lock` and `Unlock` are refused (raven lock then stops Raven,
/// v1), nothing locks and `Status.locked` is absent.
#[test]
fn with_the_gate_shut_nothing_locks() {
    let _state = crate::lan_direct::listener_state_test_lock();
    set_lab_for_this_thread(SecGate::LocalProtection, Some(false));
    let dir = tempfile::tempdir().unwrap();
    runtime().block_on(async {
        assert_eq!(lock(dir.path()).await, Err(Held));
        assert_eq!(unlock(dir.path(), None).await, Err(UnlockError::Held));
    });
    assert!(!is_locked());
    assert_eq!(status(), None);
    assert!(!raven_core::local_lock::engaged(dir.path()));
    set_lab_for_this_thread(SecGate::LocalProtection, None);
}

/// A passphrase profile: no unlock without the passphrase; a wrong one is
/// refused and the next try waits (1 s, then 2 s); the right one unlocks and
/// says how many wrong ones came. Nothing in any answer holds the
/// passphrase.
#[test]
fn wrong_passphrases_back_off_and_the_unlock_counts_them() {
    let _state = crate::lan_direct::listener_state_test_lock();
    let _gate = GateOpen::new();
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    passphrase_profile_in(dd);
    assert!(passphrase_profile(dd));
    runtime().block_on(async {
        assert_eq!(status(), Some(false));
        let locked = lock(dd).await.unwrap();
        assert_eq!(
            locked,
            LockReply {
                locked: true,
                passphrase: true,
                failed_unlocks: 0
            }
        );
        assert!(is_locked());
        assert_eq!(status(), Some(true));
        assert!(raven_core::local_lock::engaged(dd));
        assert_eq!(lock(dd).await.unwrap(), locked, "locked already: the same");
        assert_eq!(
            unlock_with(dd, None, check).await,
            Err(UnlockError::Required)
        );
        assert_eq!(
            unlock_with(dd, secret("not it at all"), check).await,
            Err(UnlockError::Wrong)
        );
        assert_eq!(
            unlock_with(dd, secret(PASSPHRASE), check).await,
            Err(UnlockError::Wait(1)),
            "even the right one waits"
        );
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            unlock_with(dd, secret("still wrong"), check).await,
            Err(UnlockError::Wrong)
        );
        assert_eq!(
            unlock_with(dd, secret(PASSPHRASE), check).await,
            Err(UnlockError::Wait(2))
        );
        assert!(is_locked(), "nothing unlocked it");
        // The 2 s are not waited out here.
        state().backoff.not_before = None;
        let opened = unlock_with(dd, secret(PASSPHRASE), check).await.unwrap();
        assert_eq!(
            opened,
            LockReply {
                locked: false,
                passphrase: true,
                failed_unlocks: 2
            }
        );
        assert!(!is_locked());
        assert!(!raven_core::local_lock::engaged(dd));
        let again = unlock_with(dd, secret("anything"), check).await.unwrap();
        assert_eq!(again.failed_unlocks, 0, "said once");
        assert!(!again.locked);
        // A wrong passphrase in a new lock starts at 1 s again.
        lock(dd).await.unwrap();
        assert_eq!(
            unlock_with(dd, secret("wrong"), check).await,
            Err(UnlockError::Wrong)
        );
        assert_eq!(
            unlock_with(dd, secret(PASSPHRASE), check).await,
            Err(UnlockError::Wait(1))
        );
        state().backoff.not_before = None;
        assert!(unlock_with(dd, secret(PASSPHRASE), check).await.is_ok());
    });
    // Every error is a fixed text: none can carry the passphrase.
    let words = format!(
        "{:?} {:?} {:?} {:?}",
        UnlockError::Wrong,
        UnlockError::Required,
        UnlockError::Wait(1),
        UnlockError::Held
    );
    assert!(!words.contains(PASSPHRASE));
}

/// A profile without a Raven passphrase (keychain, DPAPI or the desktop
/// keyring; here the lab file backends) resumes without one.
#[test]
fn a_keychain_profile_resumes_without_a_passphrase() {
    let _state = crate::lan_direct::listener_state_test_lock();
    let _gate = GateOpen::new();
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    assert!(!passphrase_profile(dd));
    runtime().block_on(async {
        let locked = lock(dd).await.unwrap();
        assert!(locked.locked && !locked.passphrase);
        let opened = unlock_with(dd, None, |_, _| panic!("no vault is asked"))
            .await
            .unwrap();
        assert_eq!(
            opened,
            LockReply {
                locked: false,
                passphrase: false,
                failed_unlocks: 0
            }
        );
    });
}

/// The service's LAN listener under `supervise_unlocked` with a sealed
/// profile: a lock closes it (a dial is refused), ends the link it held,
/// drops its identity (no `Arc` of it is left), the at-rest keys and the
/// decrypted book, and no key of the profile loads while locked; the unlock
/// starts it again with the identity and the keys back.
#[test]
fn a_lock_drops_the_keys_and_closes_the_listener_and_an_unlock_restarts_it() {
    if !crate::outbox::test_rig::lab_backends() {
        return;
    }
    let _state = crate::lan_direct::listener_state_test_lock();
    let _lan = crate::lan_direct::lan_switch_untouched();
    let _cleared = crate::lan_direct::ListenerStateForTest;
    let _gate = GateOpen::new();
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path().to_path_buf();
    raven_core::load_or_create_identity(&dd).unwrap();
    raven_core::privacy::migrate_all(
        &dd,
        crate::now_ms(),
        raven_core::at_rest::MigratePolicy::Allow,
    )
    .unwrap();
    assert!(raven_core::at_rest::keys_cached(&dd).is_ok());
    raven_core::contact_book::enable_process_cache(&dd);
    let _ = raven_core::contact_book::read_plain(&dd);
    runtime().block_on(async {
        use tokio::io::AsyncReadExt;
        let data_lan = dd.clone();
        let listener = tokio::spawn(crate::supervise_unlocked("lan_direct", None, move || {
            crate::lan_direct::run_listener(data_lan.clone(), "127.0.0.1:0".into())
        }));
        wait_until("listening", crate::lan_direct::listener_is_up).await;
        let addr = crate::lan_direct::listener_addr().unwrap();
        let identity = crate::lan_direct::listener_identity().expect("its identity");
        let weak = Arc::downgrade(&identity);
        drop(identity);
        // An open (not yet authenticated) link holds the identity too.
        let mut link = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        lock(&dd).await.unwrap();
        wait_until("the listener stops", || {
            !crate::lan_direct::listener_is_up()
        })
        .await;
        let mut byte = [0u8; 1];
        let ended = tokio::time::timeout(Duration::from_secs(5), link.read(&mut byte))
            .await
            .expect("the link ends at once");
        assert!(matches!(ended, Ok(0) | Err(_)), "{ended:?}");
        wait_until("no Arc<Identity> is left", || weak.strong_count() == 0).await;
        assert!(crate::lan_direct::listener_identity().is_none());
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "a dial is refused"
        );
        assert!(
            raven_core::at_rest::keys_cached(&dd).is_err(),
            "no at-rest key"
        );
        assert!(!raven_core::contact_book::holds_plaintext(&dd));
        assert!(raven_core::contact_book::read_plain(&dd).is_err(), "held");
        let Err(refused) = raven_core::load_identity_required(&dd) else {
            panic!("an identity loaded while locked");
        };
        assert!(
            refused
                .to_string()
                .contains(raven_core::local_lock::LOCKED_REFUSAL),
            "{refused}"
        );
        assert!(raven_core::at_rest::keys_load(&dd).is_err());
        // It stays down while locked.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!crate::lan_direct::listener_is_up());

        unlock(&dd, None).await.unwrap();
        wait_until("listening again", crate::lan_direct::listener_is_up).await;
        assert!(crate::lan_direct::listener_identity().is_some());
        wait_until("the at-rest key is back", || {
            raven_core::at_rest::keys_cached(&dd).is_ok()
        })
        .await;
        wait_until("the book opens", || {
            raven_core::contact_book::read_plain(&dd).is_ok()
        })
        .await;
        listener.abort();
        let _ = listener.await;
    });
}

/// Service start: a profile with a Raven passphrase and an identity, whose
/// passphrase this process cannot read by itself, starts locked (no key
/// loads until the unlock); one without an identity yet, and a keychain
/// profile, start as before.
#[test]
fn a_passphrase_profile_starts_locked_and_a_keychain_one_does_not() {
    let _state = crate::lan_direct::listener_state_test_lock();
    let _gate = GateOpen::new();
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    passphrase_profile_in(dd);
    assert!(!start(dd), "no identity yet: a first install");
    assert!(!is_locked());
    std::fs::write(dd.join("identity.backend"), "passphrase-vault\n").unwrap();
    if raven_core::keystore_vault::passphrase_file_configured() {
        // This environment hands raven-node a passphrase file.
        return;
    }
    assert!(start(dd));
    assert!(is_locked() && raven_core::local_lock::engaged(dd));
    assert_eq!(status(), Some(true));
    runtime().block_on(async {
        assert_eq!(
            unlock_with(dd, secret("not it"), check).await,
            Err(UnlockError::Wrong)
        );
        state().backoff.not_before = None;
        assert!(
            !unlock_with(dd, secret(PASSPHRASE), check)
                .await
                .unwrap()
                .locked
        );
    });
    assert!(!raven_core::local_lock::engaged(dd));
    let keychain = tempfile::tempdir().unwrap();
    std::fs::write(keychain.path().join("identity.backend"), "locked-file\n").unwrap();
    assert!(!start(keychain.path()));
    assert!(!is_locked());
}

/// A wake locks a passphrase profile while 'Lock Raven when the computer
/// sleeps' is unset only when this process cannot read the passphrase by
/// itself (review lock-updates-local-3): a headless node that reads it from
/// a file or credential stays unlocked (nobody is there to unlock it, and a
/// clock step reads as a wake); set on, it locks anyway. An unfinished
/// switch of the passphrase counts as a passphrase profile (review
/// lock-updates-local-4); a keychain profile never locks by default.
#[test]
fn a_wake_locks_a_headless_passphrase_node_only_when_set_to() {
    let _gate = GateOpen::new();
    let debug = cfg!(debug_assertions);
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    passphrase_profile_in(dd);
    assert_eq!(locks_on_wake(dd, false), debug, "no file: it locks");
    assert!(!locks_on_wake(dd, true), "a headless node stays unlocked");
    raven_core::node_policy::update_policy(dd, |policy| {
        policy.auto_lock_on_sleep = Some(true);
    })
    .unwrap();
    assert_eq!(locks_on_wake(dd, true), debug, "set on: it locks");

    let keychain = tempfile::tempdir().unwrap();
    assert!(!passphrase_profile(keychain.path()));
    assert!(!locks_on_wake(keychain.path(), false));
    // Halfway through a switch: the identity reads the vault.
    std::fs::write(
        keychain.path().join("identity.backend"),
        "passphrase-vault\n",
    )
    .unwrap();
    assert!(passphrase_profile(keychain.path()));
    assert_eq!(locks_on_wake(keychain.path(), false), debug);
}

/// Release builds (the CI job that sets every lab switch): the gate stays
/// shut whatever `RAVEN_LAB_LOCAL_PROTECTION` says, so nothing locks and
/// `Status.locked` is absent. A debug build returns at once.
#[test]
fn lock_v2_lab_switch_is_inert_in_release() {
    if cfg!(debug_assertions) {
        return;
    }
    assert!(!live());
    assert_eq!(status(), None);
    let dir = tempfile::tempdir().unwrap();
    assert!(!start(dir.path()));
    runtime().block_on(async {
        assert_eq!(lock(dir.path()).await, Err(Held));
        assert_eq!(unlock(dir.path(), None).await, Err(UnlockError::Held));
    });
    assert!(!is_locked());
}
