//! The generic-password calls Raven's secret stores make on Apple systems
//! (the identity seed, session and prekey secrets, the chat-history key,
//! Lock v2's items): one name for each, two keychains behind them.
//!
//! **macOS** keeps what it always did: `security-framework`'s
//! `passwords::*`, which are `SecItem*` calls without
//! `kSecUseDataProtectionKeychain`, so they reach the login keychain (the
//! legacy file-based keychain, with its per-program access lists and
//! dialogs; `crate::macos_keychain`). The add-only creates in
//! `identity_store` and `chat_history` go through the legacy
//! `SecKeychain` API itself, which exists on macOS only.
//!
//! **iOS** has only the data-protection keychain, inside the app's own
//! keychain access group. Every item Raven adds there is:
//! - `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: readable while the
//!   phone is locked once it was unlocked after a restart (the node works
//!   while the app runs in the background, a background refresh included),
//!   and never in a backup restored to another device;
//! - `kSecAttrSynchronizable = false`: never in iCloud Keychain.
//!
//! Reads, updates and deletes name the item by service and account; an
//! update changes the value only, so an item keeps the protection it was
//! added with. Errors keep Apple's `OSStatus` (`errSecItemNotFound`
//! -25300, `errSecDuplicateItem` -25299, `errSecInteractionNotAllowed`
//! -25308 while the phone was not unlocked since it started), as the
//! macOS calls give it.

#[cfg(target_os = "macos")]
pub(crate) use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

#[cfg(target_os = "ios")]
pub(crate) use ios::{
    add_generic_password, delete_generic_password, get_generic_password, set_generic_password,
};

#[cfg(target_os = "ios")]
mod ios {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::{CFGetTypeID, CFRelease, CFTypeRef};
    use core_foundation_sys::data::CFDataRef;
    use core_foundation_sys::string::CFStringRef;
    use security_framework::base::{Error, Result};
    use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    use security_framework_sys::base::{errSecDuplicateItem, errSecParam, errSecSuccess};
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecReturnData, kSecValueData,
    };

    // The attribute key itself; security-framework-sys binds only its
    // values (the Security framework is linked already).
    extern "C" {
        static kSecAttrAccessible: CFStringRef;
    }
    use security_framework_sys::keychain_item::{
        SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
    };

    fn key(k: CFStringRef) -> CFString {
        // SAFETY: a Security framework constant: a valid, immortal CFString.
        unsafe { CFString::wrap_under_get_rule(k) }
    }

    fn check(status: i32) -> Result<()> {
        if status == errSecSuccess {
            Ok(())
        } else {
            Err(Error::from_code(status))
        }
    }

    /// The item: class, service, account, and never a synchronized one.
    fn query(service: &str, account: &str) -> Vec<(CFString, CFType)> {
        vec![
            (
                key(unsafe { kSecClass }),
                key(unsafe { kSecClassGenericPassword }).into_CFType(),
            ),
            (
                key(unsafe { kSecAttrService }),
                CFString::new(service).into_CFType(),
            ),
            (
                key(unsafe { kSecAttrAccount }),
                CFString::new(account).into_CFType(),
            ),
            (
                key(unsafe { kSecAttrSynchronizable }),
                CFBoolean::false_value().into_CFType(),
            ),
        ]
    }

    /// Add-only: `errSecDuplicateItem` when the item exists.
    pub(crate) fn add_generic_password(service: &str, account: &str, value: &[u8]) -> Result<()> {
        let mut attrs = query(service, account);
        attrs.push((
            key(unsafe { kSecAttrAccessible }),
            key(unsafe { kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly }).into_CFType(),
        ));
        attrs.push((
            key(unsafe { kSecValueData }),
            CFData::from_buffer(value).into_CFType(),
        ));
        let attrs = CFDictionary::from_CFType_pairs(&attrs);
        // SAFETY: a valid dictionary; no result is asked for.
        check(unsafe { SecItemAdd(attrs.as_concrete_TypeRef(), std::ptr::null_mut()) })
    }

    /// Add, or update the value of the existing item (its protection
    /// stays the one it was added with).
    pub(crate) fn set_generic_password(service: &str, account: &str, value: &[u8]) -> Result<()> {
        match add_generic_password(service, account, value) {
            Err(e) if e.code() == errSecDuplicateItem => {
                let found = CFDictionary::from_CFType_pairs(&query(service, account));
                let change = CFDictionary::from_CFType_pairs(&[(
                    key(unsafe { kSecValueData }),
                    CFData::from_buffer(value).into_CFType(),
                )]);
                // SAFETY: two valid dictionaries.
                check(unsafe {
                    SecItemUpdate(found.as_concrete_TypeRef(), change.as_concrete_TypeRef())
                })
            }
            other => other,
        }
    }

    /// The item's value; `errSecItemNotFound` when there is none.
    pub(crate) fn get_generic_password(service: &str, account: &str) -> Result<Vec<u8>> {
        let mut q = query(service, account);
        q.push((
            key(unsafe { kSecReturnData }),
            CFBoolean::true_value().into_CFType(),
        ));
        let q = CFDictionary::from_CFType_pairs(&q);
        let mut found: CFTypeRef = std::ptr::null();
        // SAFETY: a valid dictionary; `found` receives a +1 reference.
        check(unsafe { SecItemCopyMatching(q.as_concrete_TypeRef(), &mut found) })?;
        if found.is_null() {
            return Err(Error::from_code(errSecParam));
        }
        // SAFETY: `found` is a live CF object we own (create rule).
        if unsafe { CFGetTypeID(found) } != CFData::type_id() {
            unsafe { CFRelease(found) };
            return Err(Error::from_code(errSecParam));
        }
        let data = unsafe { CFData::wrap_under_create_rule(found as CFDataRef) };
        Ok(data.bytes().to_vec())
    }

    /// Removes the item; `errSecItemNotFound` when there is none.
    pub(crate) fn delete_generic_password(service: &str, account: &str) -> Result<()> {
        let q = CFDictionary::from_CFType_pairs(&query(service, account));
        // SAFETY: a valid dictionary.
        check(unsafe { SecItemDelete(q.as_concrete_TypeRef()) })
    }
}

/// On the iOS Simulator (`xcrun simctl spawn`; docs/IOS.md section 10):
/// the data-protection keychain as Raven's stores use it.
#[cfg(all(test, target_os = "ios"))]
mod tests {
    use super::*;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};

    const NOT_FOUND: i32 = -25_300;
    const DUPLICATE: i32 = -25_299;

    /// Added once (add-only), read, updated in place, deleted; its
    /// protection is after-first-unlock, this device only, and it is never
    /// synchronized, before and after the update.
    #[test]
    fn an_item_is_added_once_read_updated_and_deleted() {
        let service = "app.raven.test.keychain";
        let account = format!("t-{}", std::process::id());
        let _ = delete_generic_password(service, &account);
        add_generic_password(service, &account, b"one").unwrap();
        assert_eq!(
            add_generic_password(service, &account, b"two")
                .unwrap_err()
                .code(),
            DUPLICATE
        );
        assert_eq!(get_generic_password(service, &account).unwrap(), b"one");
        let protection = || {
            let found = ItemSearchOptions::new()
                .class(ItemClass::generic_password())
                .service(service)
                .account(&account)
                .load_attributes(true)
                .limit(Limit::All)
                .search()
                .unwrap();
            assert_eq!(found.len(), 1);
            found[0].simplify_dict().unwrap()
        };
        let attrs = protection();
        // kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly is "cku".
        assert_eq!(
            attrs.get("pdmn").map(String::as_str),
            Some("cku"),
            "{attrs:?}"
        );
        set_generic_password(service, &account, b"three").unwrap();
        assert_eq!(get_generic_password(service, &account).unwrap(), b"three");
        let attrs = protection();
        assert_eq!(
            attrs.get("pdmn").map(String::as_str),
            Some("cku"),
            "{attrs:?}"
        );
        delete_generic_password(service, &account).unwrap();
        assert_eq!(
            get_generic_password(service, &account).unwrap_err().code(),
            NOT_FOUND
        );
    }

    /// A new profile's identity seed goes to the iOS keychain (marker
    /// `ios-keychain`), loads again, and is gone after the cleanup.
    #[test]
    fn the_identity_lives_in_the_ios_keychain() {
        assert!(std::env::var_os("RAVEN_IDENTITY_BACKEND").is_none());
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("p");
        let (id, backend) = crate::identity_store::load_or_create_identity(&profile).unwrap();
        assert_eq!(
            backend,
            crate::identity_store::IdentityStoreBackend::IosKeychain
        );
        assert_eq!(
            std::fs::read_to_string(profile.join("identity.backend")).unwrap(),
            "ios-keychain\n"
        );
        assert!(!profile.join("identity.seed").exists());
        let again = crate::identity_store::load_identity(&profile)
            .unwrap()
            .unwrap();
        assert_eq!(again.public_key_bytes(), id.public_key_bytes());
        crate::identity_store::test_cleanup(&profile);
    }
}
