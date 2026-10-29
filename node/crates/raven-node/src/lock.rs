//! Lock v2 (Phase 6 P6.40, gate `LOCAL_PROTECTION`; design C §6 and its
//! P6b-C remainder; owner decision OD6b-18).
//!
//! IPC `Lock` makes raven-node drop every key it holds and stop its network
//! work until `Unlock`:
//! - no key of the profile loads in this process again until then
//!   ([`raven_core::local_lock`]);
//! - its network tasks stop (main.rs `supervise_unlocked`, on [`subscribe`]):
//!   the LAN, Internet and p2p listeners (a dial is refused), every inbound
//!   link ([`until_locked`]), the Phase 3 beacon, the outbox worker, the
//!   custody fetcher, the renewer, nearby, route hints, the friend relay, the
//!   bridge, the meeting watcher and the expiry pruner, each with the
//!   `Arc<Identity>` it held; the p2p host and the friend relay say goodbye
//!   to their relays first;
//! - the secrets it cached go: the LAN listener's identity, the at-rest keys
//!   (`at_rest::forget_cached_keys`), the decrypted contact book and block
//!   list (`contact_book::hold`), the passphrase vault's derived key
//!   (`keystore_vault::forget_process_key`) and learning connectivity's
//!   model with its secret (saved first: `learning::save_for_lock`; nothing
//!   loads it while locked). The history and session keys are never kept
//!   past one operation (`OperationKeyCache`);
//! - IPC answers only `Ping`, `Status` (`locked: true`, every other field
//!   empty), `Lock` and `Unlock` (`LOCKED` to anything else, ipc_server.rs).
//!
//! `Unlock` of a profile with a Raven passphrase (its keys in the passphrase
//! vault) needs it: it is checked against the vault and never logged. A
//! wrong one is answered `UNLOCK_WRONG_PASSPHRASE`, and the next try waits
//! 1 s, doubling to 60 s (`UNLOCK_WAIT` before then); each is noted as
//! `SEC_UNLOCK_FAILED` (local, while the security-events gate is live), and
//! their count is said once by the unlock that ends the lock. A keychain,
//! DPAPI or desktop-keyring profile resumes without one: anyone who can log
//! in as the user can open those keys anyway, and ash says so. Queued
//! messages wait; on unlock every task starts again as at service start and
//! the outbox tries all it holds at once.
//!
//! Auto-lock on wake from sleep ([`woke_from_sleep`], netwatch's wake clock
//! or a lab `wake` line) per `node_policy.auto_lock_on_sleep` (default on for
//! passphrase profiles whose passphrase this process cannot read by itself,
//! OD6b-18); the terminal app locks after its idle minutes. A passphrase
//! profile whose passphrase this process cannot read by itself (no
//! passphrase file or credential: always so on macOS and Windows) starts
//! locked ([`start`]); one that reads it (a headless node) neither starts
//! locked nor locks on a wake by default, since nobody is there to unlock
//! it.
//!
//! Gate shut (every release build): nothing here runs, `Status.locked` is
//! absent and `Lock`/`Unlock` answer `LOCK_V2_HELD` (`raven lock` then stops
//! Raven: Lock now v1). The lock lives in this process: a restart of a
//! keychain profile's node is unlocked (its keys were open to the user's
//! login all along), a passphrase profile's starts locked again.

use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::sync::OnceLock;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use raven_core::ipc::SecretBytes;
use raven_core::keystore_vault::{Vault, VaultError};
use raven_core::security_events::{Attribution, SecEvent, SecKind, Via};
use raven_core::security_gate::{self, SecGate};
use tokio::sync::watch;

/// The wait after the first wrong passphrase; it doubles with each.
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
/// The longest wait between two tries.
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// For this long after an unlock every task is starting again at once (as
/// at service start): a start-up step that fails then is tried again soon
/// and quietly ([`settling`]).
const SETTLE: Duration = Duration::from_secs(5);
/// How long a lock waits for the p2p host and the friend relay to close
/// their connections (a relay then frees their reservations at once).
#[cfg(not(test))]
const DRAIN: Duration = Duration::from_millis(1500);

/// What `Lock` and `Unlock` answer (`IpcResponse::LockState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LockReply {
    pub(crate) locked: bool,
    pub(crate) passphrase: bool,
    pub(crate) failed_unlocks: u32,
}

/// Why `Unlock` did not unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnlockError {
    /// The local-protection gate is shut.
    Held,
    /// A wrong passphrase came less than the back-off ago: whole seconds
    /// left (at least 1).
    Wait(u64),
    /// The passphrase does not open the vault.
    Wrong,
    /// This profile has a Raven passphrase and none came.
    Required,
    /// The vault could not be read (its words, never the passphrase).
    Failed(String),
}

/// `Lock` to a node whose gate is shut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Held;

/// Wrong passphrases and the wait they impose.
#[derive(Debug, Default)]
struct Backoff {
    /// Wrong in a row.
    wrong: u32,
    /// No try before this.
    not_before: Option<Instant>,
    /// Wrong since the last unlock (said once by the next).
    since_unlock: u32,
}

impl Backoff {
    /// How long the next try must still wait.
    fn wait_left(&self, now: Instant) -> Option<Duration> {
        self.not_before
            .map(|at| at.saturating_duration_since(now))
            .filter(|left| !left.is_zero())
    }

    /// A wrong passphrase at `now`.
    fn wrong(&mut self, now: Instant) {
        self.wrong = self.wrong.saturating_add(1);
        self.since_unlock = self.since_unlock.saturating_add(1);
        self.not_before = Some(now + delay(self.wrong));
    }

    /// The lock ended: how many wrong ones it saw.
    fn opened(&mut self) -> u32 {
        std::mem::take(self).since_unlock
    }
}

/// The wait after the `wrong`-th wrong passphrase in a row: 1 s doubling to
/// 60 s.
fn delay(wrong: u32) -> Duration {
    let doublings = wrong.saturating_sub(1).min(16);
    (BACKOFF_FIRST * 2u32.pow(doublings)).min(BACKOFF_MAX)
}

/// Whole seconds of `left`, rounded up (at least 1).
fn whole_secs(left: Duration) -> u64 {
    left.as_secs() + u64::from(left.subsec_nanos() > 0)
}

#[derive(Default)]
struct State {
    /// The profile this process serves ([`start`]).
    data_dir: Option<PathBuf>,
    backoff: Backoff,
    /// The last unlock.
    unlocked_at: Option<Instant>,
}

/// The lock's state and the switch every network task watches: one per
/// process (raven-node serves one profile).
#[cfg(not(test))]
fn shared() -> &'static (Mutex<State>, watch::Sender<bool>) {
    static SHARED: OnceLock<(Mutex<State>, watch::Sender<bool>)> = OnceLock::new();
    SHARED.get_or_init(|| (Mutex::default(), watch::Sender::new(false)))
}

/// Tests: one per test thread (a test's runtime runs its tasks on its own
/// thread), so a test that locks never locks another test's node.
#[cfg(test)]
fn shared() -> &'static (Mutex<State>, watch::Sender<bool>) {
    thread_local! {
        static SHARED: &'static (Mutex<State>, watch::Sender<bool>) =
            Box::leak(Box::new((Mutex::default(), watch::Sender::new(false))));
    }
    SHARED.with(|shared| *shared)
}

fn state() -> MutexGuard<'static, State> {
    shared()
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The lock switch every network task watches.
fn switch() -> &'static watch::Sender<bool> {
    &shared().1
}

/// One lock or unlock at a time.
fn turn() -> &'static tokio::sync::Mutex<()> {
    static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &TURN
}

/// The local-protection gate.
pub(crate) fn live() -> bool {
    security_gate::live(SecGate::LocalProtection)
}

/// raven-node is locked now.
pub(crate) fn is_locked() -> bool {
    *switch().borrow()
}

/// The lock switch, for a task that runs only while unlocked.
pub(crate) fn subscribe() -> watch::Receiver<bool> {
    switch().subscribe()
}

/// Resolves once raven-node is locked (at once while it is): an inbound
/// link ends then.
pub(crate) async fn until_locked() {
    let mut locked = subscribe();
    if locked.wait_for(|locked| *locked).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// raven-node was unlocked less than `window` ago.
pub(crate) fn unlocked_within(window: Duration) -> bool {
    state().unlocked_at.is_some_and(|at| at.elapsed() < window)
}

/// The few seconds after an unlock in which the tasks start again, all at
/// once: a start-up step that fails then is tried again soon with no line,
/// and logged only if it still fails after them (E1: on Windows the LAN
/// listener's first try met "Access is denied" and said so, then started a
/// second later).
pub(crate) fn settling() -> bool {
    unlocked_within(SETTLE)
}

/// Tests: raven-node was unlocked `ago` (this test thread's lock).
#[cfg(test)]
pub(crate) fn unlocked_for_test(ago: Duration) {
    state().unlocked_at = Instant::now().checked_sub(ago);
}

/// `Status.locked`: absent while the gate is shut.
pub(crate) fn status() -> Option<bool> {
    live().then(is_locked)
}

/// Whether `Unlock` needs this profile's Raven passphrase: its keys are in
/// the vault, or a switch to or from it stopped halfway (the identity reads
/// the vault: review lock-updates-local-4). A marker that cannot be read
/// counts as one (fail closed).
pub(crate) fn passphrase_profile(data_dir: &Path) -> bool {
    raven_core::keystore_select::has_passphrase(data_dir).unwrap_or(true)
        || raven_core::raven_passphrase::unfinished(data_dir).unwrap_or(true)
}

/// Service start, before the identity preflight and any task: the profile
/// this process serves. With the gate live, a passphrase profile with an
/// identity whose passphrase this process cannot read by itself starts
/// locked (`true`): nothing loads a key until `Unlock`.
pub(crate) fn start(data_dir: &Path) -> bool {
    state().data_dir = Some(data_dir.to_path_buf());
    let locked = live()
        && passphrase_profile(data_dir)
        && raven_core::identity_store::identity_recorded(data_dir).unwrap_or(false)
        && !raven_core::keystore_vault::passphrase_file_configured();
    if locked {
        drop_secrets(data_dir);
        eprintln!(
            "raven-node lock: locked at start: this profile's Raven passphrase opens it (raven \
             unlock)"
        );
    }
    locked
}

/// IPC `Lock`: drop every secret and stop the network work. Locked already:
/// the same answer.
pub(crate) async fn lock(data_dir: &Path) -> Result<LockReply, Held> {
    if !live() {
        return Err(Held);
    }
    let _turn = turn().lock().await;
    if !is_locked() {
        // Goodbyes first, while the hosts still run: their relays free
        // the reservations at once (as at a stop). Tests never stop the
        // hosts of other tests (they are process-wide).
        #[cfg(not(test))]
        tokio::join!(
            crate::p2p::shutdown(DRAIN),
            crate::friend_relay::shutdown(DRAIN)
        );
        // Learning connectivity (Phase 6a) saves what it learned while the
        // key is here, and lets its model go once the keys went.
        crate::learning::save_for_lock().await;
        drop_secrets(data_dir);
        crate::learning::let_go();
        eprintln!("raven-node lock: locked");
    }
    Ok(LockReply {
        locked: true,
        passphrase: passphrase_profile(data_dir),
        failed_unlocks: 0,
    })
}

/// No key loads again, the tasks stop (and their links end), the caches go.
fn drop_secrets(data_dir: &Path) {
    raven_core::local_lock::engage(data_dir);
    switch().send_replace(true);
    crate::lan_direct::forget_listener_identity();
    crate::at_rest_boot::lock(data_dir);
    raven_core::keystore_vault::forget_process_key(data_dir);
}

/// IPC `Unlock` with the production vault.
pub(crate) async fn unlock(
    data_dir: &Path,
    passphrase: Option<SecretBytes>,
) -> Result<LockReply, UnlockError> {
    unlock_with(data_dir, passphrase, |dd, pass| {
        Vault::for_data_dir(dd).verify_passphrase(pass)
    })
    .await
}

/// [`unlock`] with the vault check passed in (tests use cheap KDF
/// parameters). Not locked: the state as it is.
pub(crate) async fn unlock_with<V>(
    data_dir: &Path,
    passphrase: Option<SecretBytes>,
    verify: V,
) -> Result<LockReply, UnlockError>
where
    V: FnOnce(&Path, &[u8]) -> Result<(), VaultError> + Send + 'static,
{
    if !live() {
        return Err(UnlockError::Held);
    }
    let _turn = turn().lock().await;
    let has_passphrase = passphrase_profile(data_dir);
    let reply = |failed_unlocks| LockReply {
        locked: false,
        passphrase: has_passphrase,
        failed_unlocks,
    };
    if !is_locked() {
        return Ok(reply(0));
    }
    if has_passphrase {
        let Some(passphrase) = passphrase else {
            return Err(UnlockError::Required);
        };
        if let Some(left) = state().backoff.wait_left(Instant::now()) {
            return Err(UnlockError::Wait(whole_secs(left)));
        }
        let dd = data_dir.to_path_buf();
        // Argon2id: off the runtime.
        let checked = tokio::task::spawn_blocking(move || verify(&dd, &passphrase))
            .await
            .map_err(|e| UnlockError::Failed(format!("the check ended abnormally: {e}")))?;
        match checked {
            Ok(()) => {}
            Err(VaultError::WrongPassphraseOrTampered) => {
                state().backoff.wrong(Instant::now());
                crate::security::note(SecEvent::new(
                    SecKind::UnlockFailed,
                    Attribution::Local,
                    Via::Local,
                    crate::now_ms(),
                ));
                eprintln!("raven-node lock: a wrong passphrase");
                return Err(UnlockError::Wrong);
            }
            Err(e) => return Err(UnlockError::Failed(e.to_string())),
        }
    }
    let failed = state().backoff.opened();
    restore(data_dir);
    eprintln!("raven-node lock: unlocked");
    Ok(reply(failed))
}

/// Keys load again, the tasks start again as at service start, and the
/// outbox tries everything it holds once its worker runs.
fn restore(data_dir: &Path) {
    raven_core::local_lock::release(data_dir);
    crate::at_rest_boot::unlock(data_dir);
    crate::outbox::after_unlock();
    state().unlocked_at = Some(Instant::now());
    switch().send_replace(false);
}

/// netwatch: this computer woke from sleep. Locks when the gate is live,
/// raven-node is not locked and the profile's setting says so (OD6b-18:
/// on by default for a passphrase profile).
pub(crate) fn woke_from_sleep() {
    if !live() || is_locked() {
        return;
    }
    let Some(data_dir) = state().data_dir.clone() else {
        return;
    };
    if !locks_on_wake(
        &data_dir,
        raven_core::keystore_vault::passphrase_file_configured(),
    ) {
        return;
    }
    eprintln!("raven-node lock: this computer woke from sleep; locking (auto-lock on sleep)");
    tokio::spawn(async move {
        let _ = lock(&data_dir).await;
    });
}

/// Whether a wake locks this profile: its `auto_lock_on_sleep`, which
/// while unset follows [`start`]'s rule (review lock-updates-local-3): on
/// for a passphrase profile unless this process reads the passphrase by
/// itself (`passphrase_file`), as a headless node does.
fn locks_on_wake(data_dir: &Path, passphrase_file: bool) -> bool {
    raven_core::node_policy::try_load_policy(data_dir).is_ok_and(|policy| {
        policy.auto_lock_on_sleep_on(passphrase_profile(data_dir), passphrase_file)
    })
}

#[cfg(test)]
mod tests;
