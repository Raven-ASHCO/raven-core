//! The Raven passphrase's tests (P6.40): the switch to the vault and back
//! against a keychain that is a map (never the real one) and a vault with
//! cheap KDF parameters; an interruption between the markers; the rules
//! for a new passphrase; and what each build and system offers.

// The switch's helpers serve the macOS tests only (the switch runs on
// macOS; see the marker note below).
#[cfg(target_os = "macos")]
use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::sync::Mutex;

use super::*;
#[cfg(target_os = "macos")]
use crate::keystore_vault::{KdfBounds, KdfParams, KeyCache};

#[cfg(target_os = "macos")]
const PARAMS: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};
#[cfg(target_os = "macos")]
const BOUNDS: KdfBounds = KdfBounds {
    min_m_kib: 8,
    max_m_kib: 1 << 20,
    min_t: 1,
    max_t: 10,
    min_p: 1,
    max_p: 4,
};
const FIRST: &[u8] = b"correct horse battery";
#[cfg(target_os = "macos")]
const SECOND: &[u8] = b"staple and more staples";

/// A login keychain in memory: (service, account) to value.
#[cfg(target_os = "macos")]
#[derive(Default)]
struct MapKeychain {
    items: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    /// Deletes fail (a keychain that refuses).
    refuse_deletes: bool,
}

#[cfg(target_os = "macos")]
impl MapKeychain {
    fn with(items: &[(&Item, &[u8])]) -> Self {
        let keychain = MapKeychain::default();
        for (item, value) in items {
            keychain.put(item, value).unwrap();
        }
        keychain
    }

    fn holds(&self, item: &Item) -> Option<Vec<u8>> {
        self.items
            .lock()
            .unwrap()
            .get(&(item.service.to_owned(), item.account.clone()))
            .cloned()
    }

    fn len(&self) -> usize {
        self.items.lock().unwrap().len()
    }
}

#[cfg(target_os = "macos")]
impl LoginStore for MapKeychain {
    fn get(&self, item: &Item) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        Ok(self.holds(item).map(Zeroizing::new))
    }

    fn put(&self, item: &Item, value: &[u8]) -> Result<(), String> {
        self.items.lock().unwrap().insert(
            (item.service.to_owned(), item.account.clone()),
            value.to_vec(),
        );
        Ok(())
    }

    fn delete(&self, item: &Item) -> Result<bool, String> {
        if self.refuse_deletes {
            return Err("the keychain said no".into());
        }
        Ok(self
            .items
            .lock()
            .unwrap()
            .remove(&(item.service.to_owned(), item.account.clone()))
            .is_some())
    }

    fn accounts(&self, _kind: Kind, service: &'static str) -> Result<Vec<String>, String> {
        Ok(self
            .items
            .lock()
            .unwrap()
            .keys()
            .filter(|(s, _)| s == service)
            .map(|(_, account)| account.clone())
            .collect())
    }
}

#[cfg(target_os = "macos")]
fn vault(dir: &Path, passphrase: &[u8]) -> Vault {
    Vault::with_options(
        dir,
        PARAMS,
        BOUNDS,
        given(passphrase),
        Arc::new(KeyCache::default()),
    )
}

/// A keychain profile of the identity `seed`: its marker and binding, and
/// in the keychain its identity, history key, two conversations (one the
/// session store never listed) and its prekey state.
#[cfg(target_os = "macos")]
struct Profile {
    dir: tempfile::TempDir,
    seed: [u8; 32],
    items: Vec<(Item, Vec<u8>)>,
}

#[cfg(target_os = "macos")]
impl Profile {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let seed = [0x5a; 32];
        crate::identity_store::rebind_backend(dd, IdentityStoreBackend::MacosKeychain, &seed)
            .unwrap();
        let items = vec![
            (identity_item(dd), seed.to_vec()),
            (hist_item(dd), vec![0x11; 32]),
            (session_item(dd, &"ab".repeat(32)).unwrap(), vec![0x22; 48]),
            (session_item(dd, &"0c".repeat(32)).unwrap(), vec![0x33; 40]),
            (prekey_item(dd), vec![0x44; 300]),
        ];
        Profile { dir, seed, items }
    }

    fn dd(&self) -> &Path {
        self.dir.path()
    }

    fn keychain(&self) -> MapKeychain {
        let refs: Vec<(&Item, &[u8])> = self.items.iter().map(|(i, v)| (i, &v[..])).collect();
        MapKeychain::with(&refs)
    }

    fn identity_marker(&self) -> Option<IdentityStoreBackend> {
        crate::identity_store::recorded_identity_backend(self.dd()).unwrap()
    }
}

/// The marker files: macOS reads the keystore marker only; other systems
/// read a vault file too (`recorded_backend`), so the switch runs on macOS.
#[cfg(target_os = "macos")]
#[test]
fn set_moves_every_key_into_the_vault_and_remove_brings_them_back() {
    let profile = Profile::new();
    let dd = profile.dd();
    let keychain = profile.keychain();
    assert!(!has_passphrase(dd).unwrap());

    let moved = set_with(dd, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    assert_eq!(moved.keys, 5);
    assert!(moved.left.is_empty());
    assert_eq!(keychain.len(), 0, "nothing stays in the keychain");
    assert!(has_passphrase(dd).unwrap(), "every store reads the vault");
    assert_eq!(
        profile.identity_marker(),
        Some(IdentityStoreBackend::PassphraseVault)
    );
    // The vault holds each key as its backend reads it, for that
    // passphrase only.
    let opened = vault(dd, FIRST);
    for (item, value) in &profile.items {
        assert_eq!(
            opened.get(&item.entry).unwrap().as_deref(),
            Some(value),
            "{item:?}"
        );
    }
    assert!(matches!(
        vault(dd, b"not the passphrase").verify_passphrase(b"not the passphrase"),
        Err(VaultError::WrongPassphraseOrTampered)
    ));
    // The identity binding now names the vault: the identity loads from it.
    crate::identity_store::rebind_backend(dd, IdentityStoreBackend::PassphraseVault, &profile.seed)
        .unwrap();
    assert!(matches!(
        crate::identity_store::rebind_backend(
            dd,
            IdentityStoreBackend::PassphraseVault,
            &[0x01; 32]
        ),
        Err(crate::identity_store::IdentityStoreError::Continuity(_))
    ));
    assert_eq!(
        set_with(dd, FIRST, &keychain, &vault(dd, FIRST)),
        Err(PassError::Refused(ALREADY_SET.into()))
    );

    // Change: the old passphrase opens it no more.
    assert_eq!(
        change_with(&vault(dd, b"wrong one!"), b"wrong one!", SECOND),
        Err(PassError::Wrong)
    );
    change_with(&vault(dd, FIRST), FIRST, SECOND).unwrap();
    assert!(matches!(
        vault(dd, FIRST).verify_passphrase(FIRST),
        Err(VaultError::WrongPassphraseOrTampered)
    ));
    assert_eq!(
        vault(dd, SECOND)
            .get(IDENTITY_SEED_ENTRY)
            .unwrap()
            .as_deref(),
        Some(&profile.seed.to_vec())
    );

    // Remove: a wrong passphrase changes nothing.
    assert_eq!(
        remove_with(dd, FIRST, &keychain, &vault(dd, FIRST)),
        Err(PassError::Wrong)
    );
    assert!(has_passphrase(dd).unwrap());
    let back = remove_with(dd, SECOND, &keychain, &vault(dd, SECOND)).unwrap();
    assert_eq!(back.keys, 5);
    assert!(back.left.is_empty());
    for (item, value) in &profile.items {
        assert_eq!(keychain.holds(item).as_ref(), Some(value), "{item:?}");
    }
    assert!(!has_passphrase(dd).unwrap());
    assert_eq!(
        profile.identity_marker(),
        Some(IdentityStoreBackend::MacosKeychain)
    );
    assert!(
        !dd.join(keystore_vault::VAULT_FILE_NAME).exists(),
        "the vault is gone"
    );
    assert_eq!(
        remove_with(dd, SECOND, &keychain, &vault(dd, SECOND)),
        Err(PassError::Refused(NONE_SET.into()))
    );
}

/// A set that stopped between its two markers (the identity reads the
/// vault, every other store the keychain): both copies are whole, and
/// either command finishes it. A stray vault no marker names is replaced.
#[cfg(target_os = "macos")]
#[test]
fn an_interrupted_switch_is_finished_by_either_command() {
    let profile = Profile::new();
    let dd = profile.dd();
    let keychain = profile.keychain();
    // A stray vault under another passphrase (an earlier try).
    vault(dd, b"an older try").put("stray", b"x").unwrap();
    let moved = set_with(dd, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    assert_eq!(moved.keys, 5, "the stray vault was replaced");
    // Back to the keychain, then halfway again: the identity marker says
    // the vault (with both copies whole).
    remove_with(dd, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    let whole = vault(dd, FIRST);
    for (item, value) in &profile.items {
        whole.put(&item.entry, value).unwrap();
    }
    crate::identity_store::rebind_backend(dd, IdentityStoreBackend::PassphraseVault, &profile.seed)
        .unwrap();
    assert!(halfway(dd).unwrap());
    // `set` finishes it: a wrong passphrase first changes nothing.
    assert_eq!(
        set_with(
            dd,
            b"something else",
            &keychain,
            &vault(dd, b"something else")
        ),
        Err(PassError::Wrong)
    );
    assert!(halfway(dd).unwrap());
    let moved = set_with(dd, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    assert_eq!(moved.keys, 5);
    assert!(has_passphrase(dd).unwrap() && !halfway(dd).unwrap());
    assert_eq!(keychain.len(), 0);

    // Halfway once more; `remove` finishes the other way.
    remove_with(dd, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    let whole = vault(dd, FIRST);
    for (item, value) in &profile.items {
        whole.put(&item.entry, value).unwrap();
    }
    crate::identity_store::rebind_backend(dd, IdentityStoreBackend::PassphraseVault, &profile.seed)
        .unwrap();
    remove_with(dd, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    assert!(!halfway(dd).unwrap() && !has_passphrase(dd).unwrap());
    assert_eq!(
        profile.identity_marker(),
        Some(IdentityStoreBackend::MacosKeychain)
    );
}

/// A switch that stopped between its markers (here a remove whose
/// `keystore.backend` went before the identity's marker moved: the identity
/// reads the vault, every other store the keychain, both copies whole) is
/// offered change or remove, the remove that is offered finishes it, and so
/// does a set with the passphrase it was started with (review
/// lock-updates-local-4: it was offered only a set, and a remove was
/// refused as "no passphrase").
#[cfg(target_os = "macos")]
#[test]
fn an_unfinished_switch_is_offered_and_finished_by_remove_or_set() {
    let profile = Profile::new();
    let dd = profile.dd();
    let keychain = profile.keychain();
    let halfway_again = || {
        for (item, value) in &profile.items {
            keychain.put(item, value).unwrap();
        }
        crate::keystore_select::switch_marker(dd, false).unwrap();
        assert!(unfinished(dd).unwrap());
    };
    set_with(dd, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    assert!(!unfinished(dd).unwrap());
    halfway_again();
    // The identity opens only with the passphrase: change or remove.
    let offered = offer_on_this_system(dd);
    assert_eq!(offered, Offer::ChangeOrRemove);
    assert_eq!(
        remove_offered(dd, &offered, SECOND, &keychain, &vault(dd, SECOND)),
        Err(PassError::Wrong)
    );
    let back = remove_offered(dd, &offered, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    assert_eq!(back.keys, 5);
    assert!(!unfinished(dd).unwrap() && !has_passphrase(dd).unwrap());
    assert_eq!(
        profile.identity_marker(),
        Some(IdentityStoreBackend::MacosKeychain)
    );
    assert_eq!(offer_on_this_system(dd), Offer::Set);

    // The same state, finished the other way: a set with the passphrase
    // the vault opens with.
    set_with(dd, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    halfway_again();
    let offered = offer_on_this_system(dd);
    assert_eq!(
        set_offered(dd, &offered, SECOND, &keychain, &vault(dd, SECOND)),
        Err(PassError::Wrong)
    );
    let moved = set_offered(dd, &offered, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    assert_eq!(moved.keys, 5);
    assert!(has_passphrase(dd).unwrap() && !unfinished(dd).unwrap());
    assert_eq!(keychain.len(), 0);
    // A whole passphrase profile is offered no set.
    assert_eq!(
        set_offered(
            dd,
            &offer_on_this_system(dd),
            FIRST,
            &keychain,
            &vault(dd, FIRST)
        ),
        Err(PassError::Refused(ALREADY_SET.into()))
    );
}

/// A keychain item that will not go is said (what it is, never its name);
/// the switch stands. No identity in the keychain: nothing happens.
#[cfg(target_os = "macos")]
#[test]
fn a_key_left_behind_is_said_and_no_identity_changes_nothing() {
    let profile = Profile::new();
    let dd = profile.dd();
    let mut keychain = profile.keychain();
    keychain.refuse_deletes = true;
    let moved = set_with(dd, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    assert_eq!(moved.left.len(), 5);
    assert!(moved
        .left
        .iter()
        .all(|left| !left.contains(&profile.items[2].0.account)));
    assert!(has_passphrase(dd).unwrap());

    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(
        set_with(
            empty.path(),
            FIRST,
            &MapKeychain::default(),
            &vault(empty.path(), FIRST)
        ),
        Err(PassError::Refused(_))
    ));
    assert!(!has_passphrase(empty.path()).unwrap());
}

/// A vault entry no key of this profile has: `remove` changes nothing.
#[cfg(target_os = "macos")]
#[test]
fn remove_refuses_a_vault_entry_it_does_not_know() {
    let profile = Profile::new();
    let dd = profile.dd();
    let keychain = profile.keychain();
    set_with(dd, FIRST, &keychain, &vault(dd, FIRST)).unwrap();
    vault(dd, FIRST).put("something-else", b"?").unwrap();
    assert!(matches!(
        remove_with(dd, FIRST, &keychain, &vault(dd, FIRST)),
        Err(PassError::Failed(_))
    ));
    assert!(has_passphrase(dd).unwrap(), "still the vault");
}

#[test]
fn a_new_passphrase_has_at_least_eight_characters_and_no_controls() {
    assert!(check_new(b"seven77").is_err());
    assert!(check_new("ab\u{7}cdefgh".as_bytes()).is_err());
    assert!(check_new(&[0xff; 12]).is_err());
    assert!(check_new(&[b'a'; keystore_vault::MAX_PASSPHRASE_BYTES + 1]).is_err());
    assert!(check_new(b"eight888").is_ok());
    assert!(check_new("pässwörter".as_bytes()).is_ok());
}

/// Entries map back to the keys they came from, and nothing else does.
#[test]
fn every_vault_entry_names_its_keychain_item() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    for item in [
        identity_item(dd),
        hist_item(dd),
        session_item(dd, &"9f".repeat(32)).unwrap(),
        prekey_item(dd),
    ] {
        assert_eq!(item_of_entry(dd, &item.entry), Some(item));
    }
    assert_eq!(item_of_entry(dd, "indexed-session/xyz"), None);
    assert_eq!(item_of_entry(dd, "prekey-lifecycle/00"), None);
    assert_eq!(item_of_entry(dd, "probe"), None);
    assert!(
        session_item(dd, &"AB".repeat(32)).is_none(),
        "lower-case hex only"
    );
}

/// With the gate shut nothing is offered; the lab's file backends are
/// refused; macOS offers set, then change or remove.
#[test]
fn what_is_offered_follows_the_gate_the_lab_and_the_system() {
    use crate::security_gate::set_lab_for_this_thread;
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    set_lab_for_this_thread(SecGate::LocalProtection, Some(false));
    assert_eq!(offer(dd), Offer::No(NOT_IN_THIS_VERSION));
    assert_eq!(
        set(dd, FIRST),
        Err(PassError::Refused(NOT_IN_THIS_VERSION.into()))
    );
    set_lab_for_this_thread(SecGate::LocalProtection, Some(true));
    if lab_file_backends() {
        assert_eq!(offer(dd), Offer::No(LAB_FILES));
        assert_eq!(remove(dd, FIRST), Err(PassError::Refused(LAB_FILES.into())));
    }
    let here = offer_on_this_system(dd);
    if cfg!(target_os = "macos") {
        assert_eq!(here, Offer::Set);
        crate::keystore_select::switch_marker(dd, true).unwrap();
        assert_eq!(offer_on_this_system(dd), Offer::ChangeOrRemove);
        crate::keystore_select::switch_marker(dd, false).unwrap();
        assert_eq!(offer_on_this_system(dd), Offer::Set);
    } else if cfg!(windows) {
        assert_eq!(here, Offer::No(NOT_ON_WINDOWS));
    } else {
        assert_eq!(here, Offer::No(KEYRING_PROFILE));
    }
    set_lab_for_this_thread(SecGate::LocalProtection, None);
}
