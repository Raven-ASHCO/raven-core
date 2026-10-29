//! The Raven passphrase (Phase 6 P6.40, gate `LOCAL_PROTECTION`; design C
//! §6, owner decision OD6b-18): on macOS a profile's keys leave the login
//! keychain for the passphrase vault ([`crate::keystore_vault`]), so that a
//! Lock v2 lock holds against anyone who can log in as the user, and come
//! back again. A vault profile changes its passphrase (GNU/Linux vault
//! profiles too).
//!
//! What moves are the keychain items `raven erase` deletes (PP.16), each as
//! the vault entry the vault backends read: the identity seed
//! ([`keystore_vault::IDENTITY_SEED_ENTRY`]), the history key K_root
//! ([`keystore_vault::CHAT_HISTORY_KEY_ENTRY`]; K_meta is wrapped by it and
//! stays as it is), every conversation's secret
//! (`indexed-session/<record key>`) and the prekey state
//! (`prekey-lifecycle/<account>`).
//!
//! The order keeps an interruption safe, with no journal: [`set`] copies
//! every item into a new vault and reads it back, then the identity's marker
//! and binding say "passphrase-vault", then `keystore.backend` does (every
//! other store), and only then do the keychain items go. [`remove`] copies
//! the vault's entries back and reads them back, then `keystore.backend`
//! goes, then the identity's marker and binding say "keychain", and only
//! then is the vault overwritten and deleted. Between the two marker writes
//! both copies are whole, so either command finishes from there
//! ([`unfinished`]: the identity opens only with the passphrase then, so the
//! profile counts as one with a passphrase, and both commands are offered);
//! a vault no marker names is a stray copy, replaced by the next [`set`].
//!
//! Not here: Windows (DPAPI files) and GNU/Linux desktop-keyring profiles
//! are refused with what to do instead; so are the debug lab's file
//! backends (they never read the keychain). The caller holds raven-node
//! locked (Lock v2) or stopped while this runs, so it writes no key
//! meanwhile.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::identity_store::IdentityStoreBackend;
use crate::keystore_vault::{
    self, PassphrasePurpose, PassphraseSource, Vault, VaultError, CHAT_HISTORY_KEY_ENTRY,
    IDENTITY_SEED_ENTRY, PREKEY_ENTRY_PREFIX, SESSION_ENTRY_PREFIX,
};
use crate::security_gate::{self, SecGate};

/// Why a Raven passphrase cannot be changed here (the user's words).
pub const NOT_IN_THIS_VERSION: &str = "A Raven passphrase is not part of this version of Raven.";
/// The lab's file backends (debug builds).
pub const LAB_FILES: &str = "This profile keeps its keys in the lab's files \
     (RAVEN_*_BACKEND=locked-file): a Raven passphrase does not apply to it.";
/// Windows keeps the keys in files only the user's account opens (DPAPI).
pub const NOT_ON_WINDOWS: &str = "A Raven passphrase is not available on Windows yet. Your \
     Raven keys are protected by your Windows account.";
/// A GNU/Linux profile with its keys in the desktop keyring.
pub const KEYRING_PROFILE: &str = "This profile keeps its keys in your desktop keyring. A \
     Raven passphrase is chosen when a profile is made (RAVEN_KEYSTORE_BACKEND=vault).";
/// [`set`] on a profile that has one.
pub const ALREADY_SET: &str = "This profile already has a Raven passphrase.";
/// [`change`] or [`remove`] on a profile without one.
pub const NONE_SET: &str = "This profile has no Raven passphrase.";
/// A passphrase that does not open the vault.
pub const WRONG: &str = "That passphrase is not right.";

/// What Settings and `raven passphrase` offer for this profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offer {
    /// No Raven passphrase: one can be set.
    Set,
    /// A Raven passphrase (macOS): change or remove it.
    ChangeOrRemove,
    /// A vault profile of another system: its passphrase can change.
    Change,
    /// Nothing, and why (the user's words).
    No(&'static str),
}

impl Offer {
    /// The profile has a Raven passphrase.
    pub fn has_passphrase(&self) -> bool {
        matches!(self, Offer::ChangeOrRemove | Offer::Change)
    }
}

/// Why a change of the Raven passphrase did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassError {
    /// The passphrase given does not open the vault ([`WRONG`]).
    Wrong,
    /// Not on this profile, build or system, or not now (the user's words).
    Refused(String),
    /// A keystore or file step failed (its words; never a secret).
    Failed(String),
}

impl std::fmt::Display for PassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassError::Wrong => f.write_str(WRONG),
            PassError::Refused(why) | PassError::Failed(why) => f.write_str(why),
        }
    }
}

impl From<VaultError> for PassError {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::WrongPassphraseOrTampered => PassError::Wrong,
            other => PassError::Failed(other.to_string()),
        }
    }
}

/// What [`set`] or [`remove`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Moved {
    /// Keys that moved.
    pub keys: usize,
    /// Keys that stayed behind where they were because their delete failed
    /// (what each is, never its name).
    pub left: Vec<String>,
}

/// The debug lab's file backends are asked for (never in a release build).
fn lab_file_backends() -> bool {
    cfg!(debug_assertions)
        && [
            "RAVEN_IDENTITY_BACKEND",
            "RAVEN_SESSION_BACKEND",
            "RAVEN_PREKEY_BACKEND",
            "RAVEN_CHAT_HISTORY_BACKEND",
        ]
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|v| v == "locked-file"))
}

/// What this build offers for this profile's Raven passphrase.
pub fn offer(data_dir: &Path) -> Offer {
    if !security_gate::live(SecGate::LocalProtection) {
        return Offer::No(NOT_IN_THIS_VERSION);
    }
    if lab_file_backends() {
        return Offer::No(LAB_FILES);
    }
    offer_on_this_system(data_dir)
}

#[cfg(target_os = "macos")]
fn offer_on_this_system(data_dir: &Path) -> Offer {
    if crate::keystore_select::has_passphrase(data_dir).unwrap_or(false)
        || unfinished(data_dir).unwrap_or(false)
    {
        Offer::ChangeOrRemove
    } else {
        Offer::Set
    }
}

#[cfg(windows)]
fn offer_on_this_system(_data_dir: &Path) -> Offer {
    Offer::No(NOT_ON_WINDOWS)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn offer_on_this_system(data_dir: &Path) -> Offer {
    if crate::keystore_select::has_passphrase(data_dir).unwrap_or(false) {
        Offer::Change
    } else {
        Offer::No(KEYRING_PROFILE)
    }
}

#[cfg(not(any(unix, windows)))]
fn offer_on_this_system(_data_dir: &Path) -> Offer {
    Offer::No(NOT_IN_THIS_VERSION)
}

/// A new passphrase's rules: at least
/// [`keystore_vault::MIN_NEW_PASSPHRASE_CHARS`] characters, at most
/// [`keystore_vault::MAX_PASSPHRASE_BYTES`] bytes, UTF-8, no control
/// characters (it is typed).
pub fn check_new(passphrase: &[u8]) -> Result<(), PassError> {
    let refused = |why: String| Err(PassError::Refused(why));
    let Ok(text) = std::str::from_utf8(passphrase) else {
        return refused("Use letters, digits and punctuation only.".into());
    };
    if text.chars().any(char::is_control) {
        return refused("Use letters, digits and punctuation only.".into());
    }
    if text.chars().count() < keystore_vault::MIN_NEW_PASSPHRASE_CHARS {
        return refused(format!(
            "Use at least {} characters.",
            keystore_vault::MIN_NEW_PASSPHRASE_CHARS
        ));
    }
    if passphrase.len() > keystore_vault::MAX_PASSPHRASE_BYTES {
        return refused(format!(
            "Use at most {} characters.",
            keystore_vault::MAX_PASSPHRASE_BYTES
        ));
    }
    Ok(())
}

/// The passphrase just typed, for both purposes (creating the vault, and
/// opening it to finish an earlier try).
struct Given(Zeroizing<Vec<u8>>);

impl PassphraseSource for Given {
    fn passphrase(
        &self,
        _purpose: PassphrasePurpose,
        _vault_path: &Path,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Ok(self.0.clone())
    }
}

fn given(passphrase: &[u8]) -> Arc<dyn PassphraseSource> {
    Arc::new(Given(Zeroizing::new(passphrase.to_vec())))
}

/// Set a Raven passphrase: the profile's keys move from the login keychain
/// into a new vault that `new` opens.
pub fn set(data_dir: &Path, new: &[u8]) -> Result<Moved, PassError> {
    let vault = Vault::for_data_dir_with(data_dir, given(new));
    set_offered(data_dir, &offer(data_dir), new, &platform::Keychain, &vault)
}

/// [`set`] with what [`offer`] said, its keychain and vault passed in.
pub(crate) fn set_offered(
    data_dir: &Path,
    offer: &Offer,
    new: &[u8],
    login: &dyn LoginStore,
    vault: &Vault,
) -> Result<Moved, PassError> {
    match offer {
        Offer::Set => {}
        // A set or remove that stopped between its markers: `new` (the
        // passphrase it was started with) finishes it as a set.
        Offer::ChangeOrRemove if halfway(data_dir)? => {}
        Offer::No(why) => return Err(PassError::Refused((*why).into())),
        _ => return Err(PassError::Refused(ALREADY_SET.into())),
    }
    set_with(data_dir, new, login, vault)
}

/// Change the Raven passphrase from `current` to `new`.
pub fn change(data_dir: &Path, current: &[u8], new: &[u8]) -> Result<(), PassError> {
    match offer(data_dir) {
        Offer::ChangeOrRemove | Offer::Change => {}
        Offer::No(why) => return Err(PassError::Refused(why.into())),
        Offer::Set => return Err(PassError::Refused(NONE_SET.into())),
    }
    let vault = Vault::for_data_dir_with(data_dir, given(current));
    change_with(&vault, current, new)
}

/// Remove the Raven passphrase (`current` opens the vault): the keys move
/// back into the login keychain.
pub fn remove(data_dir: &Path, current: &[u8]) -> Result<Moved, PassError> {
    let vault = Vault::for_data_dir_with(data_dir, given(current));
    remove_offered(
        data_dir,
        &offer(data_dir),
        current,
        &platform::Keychain,
        &vault,
    )
}

/// [`remove`] with what [`offer`] said, its keychain and vault passed in.
pub(crate) fn remove_offered(
    data_dir: &Path,
    offer: &Offer,
    current: &[u8],
    login: &dyn LoginStore,
    vault: &Vault,
) -> Result<Moved, PassError> {
    match offer {
        Offer::ChangeOrRemove => {}
        Offer::No(why) => return Err(PassError::Refused((*why).into())),
        Offer::Change => return Err(PassError::Refused(KEYRING_PROFILE.into())),
        Offer::Set => return Err(PassError::Refused(NONE_SET.into())),
    }
    remove_with(data_dir, current, login, vault)
}

/// Whether `passphrase` opens this profile's vault, checked before a
/// change holds raven-node locked (review lock-updates-local-1): a typo in
/// the current passphrase then changes nothing and never reaches raven-node
/// as a wrong unlock. No vault: [`PassError::Failed`]. Nothing is cached
/// (the change itself opens the vault again).
pub fn check_opens(data_dir: &Path, passphrase: &[u8]) -> Result<(), PassError> {
    let vault = Vault::with_options(
        data_dir,
        keystore_vault::KdfParams::DEFAULT,
        keystore_vault::PRODUCTION_BOUNDS,
        given(passphrase),
        Arc::new(keystore_vault::KeyCache::default()),
    );
    vault.verify_passphrase(passphrase)?;
    Ok(())
}

/// A [`set`] or [`remove`] stopped between its two markers (review
/// lock-updates-local-4): the identity reads the vault, so it opens only
/// with the Raven passphrase, while every other store still reads the
/// keychain. Such a profile counts as one with a passphrase (Lock v2 asks
/// for it, [`offer`] offers change or remove), and `set` with the
/// passphrase it was started with or `remove` finishes it. A marker that
/// cannot be read: its error.
pub fn unfinished(data_dir: &Path) -> Result<bool, String> {
    halfway(data_dir).map_err(|e| e.to_string())
}

// ── The keys and where each lives ───────────────────────────────────────────

/// Which key an item holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Identity,
    HistKey,
    Session,
    Prekey,
}

impl Kind {
    fn words(self) -> &'static str {
        match self {
            Kind::Identity => "the identity key",
            Kind::HistKey => "the chat-history key",
            Kind::Session => "a conversation key",
            Kind::Prekey => "the key-exchange keys",
        }
    }
}

/// One key: its login keychain item and its vault entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Item {
    pub(crate) kind: Kind,
    pub(crate) service: &'static str,
    pub(crate) account: String,
    pub(crate) entry: String,
}

/// The login keystore's generic passwords (the macOS keychain; tests: a
/// map).
pub(crate) trait LoginStore {
    fn get(&self, item: &Item) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    /// Add or replace.
    fn put(&self, item: &Item, value: &[u8]) -> Result<(), String>;
    /// `Ok(true)` when it was there.
    fn delete(&self, item: &Item) -> Result<bool, String>;
    /// The account of every item of `service` (attributes only).
    fn accounts(&self, kind: Kind, service: &'static str) -> Result<Vec<String>, String>;
}

fn identity_item(data_dir: &Path) -> Item {
    let (service, account) = crate::identity_store::keychain_item(data_dir);
    Item {
        kind: Kind::Identity,
        service,
        account,
        entry: IDENTITY_SEED_ENTRY.into(),
    }
}

fn hist_item(data_dir: &Path) -> Item {
    let (service, account) = crate::chat_history::history_key_item(data_dir);
    Item {
        kind: Kind::HistKey,
        service,
        account,
        entry: CHAT_HISTORY_KEY_ENTRY.into(),
    }
}

fn prekey_item(data_dir: &Path) -> Item {
    let (service, account) = crate::prekey_lifecycle::erase_item(data_dir);
    let entry = format!("{PREKEY_ENTRY_PREFIX}{account}");
    Item {
        kind: Kind::Prekey,
        service,
        account,
        entry,
    }
}

/// A conversation's item from its record key's hex (the session store's
/// keychain account is `<namespace>:<hex>`, its vault entry
/// `indexed-session/<hex>`).
fn session_item(data_dir: &Path, record_hex: &str) -> Option<Item> {
    let well_formed = record_hex.len() == 64
        && record_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !well_formed {
        return None;
    }
    let (service, namespace) = crate::indexed_session_store::erase_namespace(data_dir);
    Some(Item {
        kind: Kind::Session,
        service,
        account: format!("{namespace}:{record_hex}"),
        entry: format!("{SESSION_ENTRY_PREFIX}{record_hex}"),
    })
}

/// Every key of this profile in the login keychain: the identity, the
/// history key, each conversation the session store lists and each item in
/// its namespace (one a session start left without a head too), the prekey
/// state.
fn login_items(data_dir: &Path, login: &dyn LoginStore) -> Result<Vec<Item>, PassError> {
    let mut items = vec![identity_item(data_dir), hist_item(data_dir)];
    let (service, namespace) = crate::indexed_session_store::erase_namespace(data_dir);
    let prefix = format!("{namespace}:");
    let mut records = BTreeSet::new();
    for key in crate::indexed_session_store::erase_record_keys(data_dir).map_err(|e| {
        PassError::Failed(format!("the conversation keys could not be listed ({e})"))
    })? {
        records.insert(hex::encode(key));
    }
    for account in login
        .accounts(Kind::Session, service)
        .map_err(PassError::Failed)?
    {
        if let Some(record) = account.strip_prefix(&prefix) {
            records.insert(record.to_owned());
        }
    }
    items.extend(records.iter().filter_map(|hex| session_item(data_dir, hex)));
    items.push(prekey_item(data_dir));
    Ok(items)
}

/// The keychain item a vault entry came from; `None`: an entry no key of
/// this profile has.
fn item_of_entry(data_dir: &Path, entry: &str) -> Option<Item> {
    if entry == IDENTITY_SEED_ENTRY {
        return Some(identity_item(data_dir));
    }
    if entry == CHAT_HISTORY_KEY_ENTRY {
        return Some(hist_item(data_dir));
    }
    if let Some(hex) = entry.strip_prefix(SESSION_ENTRY_PREFIX) {
        return session_item(data_dir, hex);
    }
    let prekey = prekey_item(data_dir);
    (entry == prekey.entry).then_some(prekey)
}

/// The identity seed and the history key are 32 bytes.
fn well_sized(item: &Item, value: &[u8]) -> Result<(), PassError> {
    if matches!(item.kind, Kind::Identity | Kind::HistKey) && value.len() != 32 {
        return Err(PassError::Failed(format!(
            "{} is damaged (not 32 bytes)",
            item.kind.words()
        )));
    }
    Ok(())
}

fn seed_of(value: &[u8]) -> Result<Zeroizing<[u8; 32]>, PassError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    if value.len() != 32 {
        return Err(PassError::Failed("the identity key is damaged".into()));
    }
    seed.copy_from_slice(value);
    Ok(seed)
}

fn identity_backend(data_dir: &Path) -> Result<Option<IdentityStoreBackend>, PassError> {
    crate::identity_store::recorded_identity_backend(data_dir)
        .map_err(|e| PassError::Failed(e.redacted_display()))
}

fn has_passphrase(data_dir: &Path) -> Result<bool, PassError> {
    crate::keystore_select::has_passphrase(data_dir).map_err(PassError::Failed)
}

/// Between the two marker writes of a [`set`] or [`remove`] that stopped:
/// the identity reads the vault, every other store the keychain, and both
/// copies are whole.
fn halfway(data_dir: &Path) -> Result<bool, PassError> {
    Ok(
        identity_backend(data_dir)? == Some(IdentityStoreBackend::PassphraseVault)
            && !has_passphrase(data_dir)?,
    )
}

/// The vault file overwritten and deleted, and its key forgotten here.
fn remove_vault_file(data_dir: &Path) -> Result<(), PassError> {
    keystore_vault::forget_process_key(data_dir);
    crate::erase::remove_file(&data_dir.join(keystore_vault::VAULT_FILE_NAME), true)
        .map(|_| ())
        .map_err(|e| PassError::Failed(format!("the old vault could not be removed ({e})")))
}

fn rebind(
    data_dir: &Path,
    backend: IdentityStoreBackend,
    seed: &[u8; 32],
) -> Result<(), PassError> {
    crate::identity_store::rebind_backend(data_dir, backend, seed)
        .map_err(|e| PassError::Failed(e.redacted_display()))
}

/// [`set`] with its keychain and vault passed in.
pub(crate) fn set_with(
    data_dir: &Path,
    new: &[u8],
    login: &dyn LoginStore,
    vault: &Vault,
) -> Result<Moved, PassError> {
    if has_passphrase(data_dir)? {
        return Err(PassError::Refused(ALREADY_SET.into()));
    }
    if halfway(data_dir)? {
        // A set or remove stopped between its markers: the vault is whole.
        vault.verify_passphrase(new)?;
        return finish_set(data_dir, login, vault);
    }
    check_new(new)?;
    // A vault no marker names is a copy an earlier try left: not in use.
    remove_vault_file(data_dir)?;
    let mut copied = Vec::new();
    for item in login_items(data_dir, login)? {
        let Some(value) = login.get(&item).map_err(PassError::Failed)? else {
            if item.kind == Kind::Identity {
                return Err(PassError::Refused(
                    "This profile has no identity in the keychain yet.".into(),
                ));
            }
            continue;
        };
        well_sized(&item, &value)?;
        vault.put(&item.entry, &value)?;
        copied.push((item, value));
    }
    for (item, value) in &copied {
        let back = vault.get(&item.entry)?;
        if back.as_deref().map(|b| &b[..]) != Some(&value[..]) {
            return Err(PassError::Failed(format!(
                "{} did not read back from the vault",
                item.kind.words()
            )));
        }
    }
    let identity = copied
        .iter()
        .find(|(item, _)| item.kind == Kind::Identity)
        .ok_or_else(|| PassError::Failed("the identity key was not copied".into()))?;
    let seed = seed_of(&identity.1)?;
    rebind(data_dir, IdentityStoreBackend::PassphraseVault, &seed)?;
    finish_set(data_dir, login, vault)
}

/// The vault holds every key and the identity reads it: every other store
/// reads it from now on, and the keychain items go.
fn finish_set(data_dir: &Path, login: &dyn LoginStore, vault: &Vault) -> Result<Moved, PassError> {
    crate::keystore_select::switch_marker(data_dir, true).map_err(PassError::Failed)?;
    let mut moved = Moved::default();
    for entry in vault.entry_names()? {
        let Some(item) = item_of_entry(data_dir, &entry) else {
            continue;
        };
        moved.keys += 1;
        if let Err(e) = login.delete(&item) {
            moved.left.push(format!(
                "{} ({})",
                item.kind.words(),
                crate::sanitize::sanitize_terminal_line(&e)
            ));
        }
    }
    Ok(moved)
}

/// [`change`] with its vault passed in.
pub(crate) fn change_with(vault: &Vault, current: &[u8], new: &[u8]) -> Result<(), PassError> {
    check_new(new)?;
    vault.verify_passphrase(current)?;
    let new = Given(Zeroizing::new(new.to_vec()));
    vault.change_passphrase(&new)?;
    Ok(())
}

/// [`remove`] with its keychain and vault passed in.
pub(crate) fn remove_with(
    data_dir: &Path,
    current: &[u8],
    login: &dyn LoginStore,
    vault: &Vault,
) -> Result<Moved, PassError> {
    let halfway = halfway(data_dir)?;
    if !halfway && !has_passphrase(data_dir)? {
        return Err(PassError::Refused(NONE_SET.into()));
    }
    vault.verify_passphrase(current)?;
    let mut moved = Moved::default();
    let mut seed = None;
    let mut items = Vec::new();
    for entry in vault.entry_names()? {
        items.push(item_of_entry(data_dir, &entry).ok_or_else(|| {
            PassError::Failed(
                "the vault holds a key this version does not know; nothing was changed".into(),
            )
        })?);
    }
    for item in items {
        let entry = &item.entry;
        let value = vault
            .get(entry)?
            .ok_or_else(|| PassError::Failed("the vault changed meanwhile; try again".into()))?;
        well_sized(&item, &value)?;
        login.put(&item, &value).map_err(PassError::Failed)?;
        let back = login.get(&item).map_err(PassError::Failed)?;
        if back.as_deref().map(|b| &b[..]) != Some(&value[..]) {
            return Err(PassError::Failed(format!(
                "{} did not read back from the keychain",
                item.kind.words()
            )));
        }
        if item.kind == Kind::Identity {
            seed = Some(seed_of(&value)?);
        }
        moved.keys += 1;
    }
    let seed = seed.ok_or_else(|| {
        PassError::Failed("the vault holds no identity key; nothing was changed".into())
    })?;
    crate::keystore_select::switch_marker(data_dir, false).map_err(PassError::Failed)?;
    rebind(data_dir, IdentityStoreBackend::MacosKeychain, &seed)?;
    if let Err(e) = remove_vault_file(data_dir) {
        moved.left.push(format!("the passphrase vault ({e})"));
    }
    Ok(moved)
}

// ── The login keychain (macOS) ──────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::{Item, Kind, LoginStore};
    use crate::macos_keychain::{guarded, KeychainWhat};
    use zeroize::Zeroizing;

    /// errSecItemNotFound: the only status that proves no such item.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;

    fn what(kind: Kind) -> KeychainWhat {
        match kind {
            Kind::Identity => KeychainWhat::IdentitySeed,
            Kind::HistKey => KeychainWhat::ChatHistoryKey,
            Kind::Session => KeychainWhat::SessionSecret,
            Kind::Prekey => KeychainWhat::PrekeyState,
        }
    }

    /// The user's login keychain, each call inside the access-dialog guard.
    pub(super) struct Keychain;

    impl LoginStore for Keychain {
        fn get(&self, item: &Item) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            use security_framework::passwords::get_generic_password;
            match guarded(what(item.kind), || {
                get_generic_password(item.service, &item.account)
            }) {
                Ok(value) => Ok(Some(Zeroizing::new(value))),
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
                Err(e) => Err(format!("keychain read failed: {e}")),
            }
        }

        fn put(&self, item: &Item, value: &[u8]) -> Result<(), String> {
            use security_framework::passwords::set_generic_password;
            guarded(what(item.kind), || {
                set_generic_password(item.service, &item.account, value)
            })
            .map_err(|e| format!("keychain update failed: {e}"))
        }

        fn delete(&self, item: &Item) -> Result<bool, String> {
            use security_framework::passwords::delete_generic_password;
            match guarded(what(item.kind), || {
                delete_generic_password(item.service, &item.account)
            }) {
                Ok(()) => Ok(true),
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
                Err(e) => Err(format!("keychain delete failed: {e}")),
            }
        }

        fn accounts(&self, kind: Kind, service: &'static str) -> Result<Vec<String>, String> {
            use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
            // kSecAttrAccount's key in a search result's attributes.
            const ACCOUNT: &str = "acct";
            match guarded(what(kind), || {
                ItemSearchOptions::new()
                    .class(ItemClass::generic_password())
                    .service(service)
                    .load_attributes(true)
                    .limit(Limit::All)
                    .search()
            }) {
                Ok(found) => Ok(found
                    .iter()
                    .filter_map(|item| item.simplify_dict()?.remove(ACCOUNT))
                    .collect()),
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(Vec::new()),
                Err(e) => Err(format!("keychain search failed: {e}")),
            }
        }
    }
}

/// No login keychain to move keys out of here ([`offer`] refuses first).
#[cfg(not(target_os = "macos"))]
mod platform {
    use super::{Item, Kind, LoginStore};
    use zeroize::Zeroizing;

    pub(super) struct Keychain;

    const NONE: &str = "there is no login keychain to move keys to or from on this system";

    impl LoginStore for Keychain {
        fn get(&self, _item: &Item) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Err(NONE.into())
        }

        fn put(&self, _item: &Item, _value: &[u8]) -> Result<(), String> {
            Err(NONE.into())
        }

        fn delete(&self, _item: &Item) -> Result<bool, String> {
            Err(NONE.into())
        }

        fn accounts(&self, _kind: Kind, _service: &'static str) -> Result<Vec<String>, String> {
            Err(NONE.into())
        }
    }
}

#[cfg(test)]
mod tests;
