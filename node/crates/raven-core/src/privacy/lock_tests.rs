//! PP.15 tests: the lock `raven lock` records in `privacy.json`
//! ([`lock_state`], [`set_locked`], [`set_unlocked`],
//! [`clear_lock_login_item`]). It needs an identity, keeps every other
//! field, never weakens a disabled login item, reads an unknown word as
//! disabled, and an unlock writes nothing when nothing is locked.

use super::*;
use crate::contact_book::tests::profile;

#[test]
fn lock_is_recorded_and_cleared_keeping_every_other_field() {
    let dir = profile();
    let dd = dir.path();
    assert_eq!(lock_state(dd), LockState::default());
    set_chat_keep(dd, ChatKeep::Days90).unwrap();

    set_locked(dd, None).unwrap();
    assert_eq!(
        lock_state(dd),
        LockState {
            locked_by_user: true,
            login_item: None,
            by_app: false,
        }
    );
    assert_eq!(chat_keep(dd), ChatKeep::Days90, "other fields are kept");

    set_locked(dd, Some(LockedItem::Unloaded)).unwrap();
    assert_eq!(lock_state(dd).login_item, Some(LockedItem::Unloaded));
    set_locked(dd, Some(LockedItem::Disabled)).unwrap();
    assert_eq!(lock_state(dd).login_item, Some(LockedItem::Disabled));
    // A second lock that only unloads the item: it is still off.
    set_locked(dd, Some(LockedItem::Unloaded)).unwrap();
    set_locked(dd, None).unwrap();
    assert_eq!(lock_state(dd).login_item, Some(LockedItem::Disabled));

    set_unlocked(dd).unwrap();
    assert_eq!(
        lock_state(dd),
        LockState {
            locked_by_user: false,
            login_item: Some(LockedItem::Disabled),
            by_app: false,
        },
        "the item stays recorded until unlock turned it back on"
    );
    clear_lock_login_item(dd).unwrap();
    assert_eq!(lock_state(dd), LockState::default());
    assert_eq!(chat_keep(dd), ChatKeep::Days90);
    let raw = std::fs::read_to_string(dd.join(PRIVACY_FILE)).unwrap();
    assert!(!raw.contains("locked_by_user"), "{raw}");
    assert!(!raw.contains("lock_login_item"), "{raw}");
    assert!(!raw.contains("lock_by"), "{raw}");
}

/// Review E-harness-docs-ci-3: who set the lock. The full-screen app's Lock
/// is its own (opening the app clears it); `raven lock` is the CLI's, and
/// the app's Lock never turns one into its own, while `raven lock` over the
/// app's makes it the CLI's. A lock that names nobody (an older build of
/// the pack set it) counts as `raven lock`'s. An unlock forgets who.
#[test]
fn the_lock_says_who_set_it() {
    let dir = profile();
    let dd = dir.path();
    let by_app = |dd: &Path| lock_state(dd).by_app;
    set_locked_by_app(dd, None).unwrap();
    assert!(lock_state(dd).locked_by_user && by_app(dd));
    set_locked_by_app(dd, Some(LockedItem::Unloaded)).unwrap();
    assert!(by_app(dd));
    assert_eq!(lock_state(dd).login_item, Some(LockedItem::Unloaded));
    // `raven lock` over the app's: the CLI's now.
    set_locked(dd, None).unwrap();
    assert!(!by_app(dd));
    // The app's Lock over `raven lock`'s: still the CLI's.
    set_locked_by_app(dd, Some(LockedItem::Unloaded)).unwrap();
    assert!(lock_state(dd).locked_by_user && !by_app(dd));
    // Unlocked: nobody's; the next app Lock is the app's again.
    set_unlocked(dd).unwrap();
    assert!(!lock_state(dd).locked_by_user && !by_app(dd));
    let raw = std::fs::read_to_string(dd.join(PRIVACY_FILE)).unwrap();
    assert!(!raw.contains("lock_by"), "{raw}");
    set_locked_by_app(dd, None).unwrap();
    assert!(by_app(dd));
    // An older build of the pack's lock: no `lock_by`, the CLI's.
    std::fs::write(dd.join(PRIVACY_FILE), br#"{"v":1,"locked_by_user":true}"#).unwrap();
    assert_eq!(
        lock_state(dd),
        LockState {
            locked_by_user: true,
            login_item: None,
            by_app: false,
        }
    );
    set_locked_by_app(dd, None).unwrap();
    assert!(!by_app(dd), "the app's Lock never makes it its own");
}

#[test]
fn a_profile_without_identity_is_never_locked_and_unlocking_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let err = set_locked(dd, None).unwrap_err();
    assert!(err.contains("no identity"), "{err}");
    set_unlocked(dd).unwrap();
    clear_lock_login_item(dd).unwrap();
    assert_eq!(
        std::fs::read_dir(dd).unwrap().count(),
        0,
        "nothing written: the first `raven init` must still be allowed"
    );
    assert!(crate::identity_store::first_install_allowed(dd));
}

#[test]
fn an_unknown_item_word_reads_as_disabled_and_an_unreadable_file_as_unlocked() {
    let dir = profile();
    let dd = dir.path();
    std::fs::write(
        dd.join(PRIVACY_FILE),
        br#"{"v":1,"locked_by_user":true,"lock_login_item":"paused","later":7}"#,
    )
    .unwrap();
    assert_eq!(
        lock_state(dd),
        LockState {
            locked_by_user: true,
            login_item: Some(LockedItem::Disabled),
            by_app: false,
        }
    );
    set_unlocked(dd).unwrap();
    let raw = std::fs::read_to_string(dd.join(PRIVACY_FILE)).unwrap();
    assert!(
        raw.contains("\"later\": 7"),
        "a newer build's field is kept: {raw}"
    );

    std::fs::write(dd.join(PRIVACY_FILE), b"{not json").unwrap();
    assert_eq!(lock_state(dd), LockState::default());
    assert!(
        set_locked(dd, None).is_err(),
        "never replaces a file it can't read"
    );
}
