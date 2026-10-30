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
    accounts, add_generic_password, delete_generic_password, get_generic_password,
    set_generic_password,
};

#[cfg(target_os = "ios")]
mod ios {
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use core_foundation_sys::array::CFArrayRef;
    use core_foundation_sys::base::{CFGetTypeID, CFRelease, CFTypeRef};
    use core_foundation_sys::data::CFDataRef;
    use core_foundation_sys::string::CFStringRef;
    use security_framework::base::{Error, Result};
    use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    use security_framework_sys::base::{
        errSecDuplicateItem, errSecItemNotFound, errSecParam, errSecSuccess,
    };
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecMatchLimit, kSecMatchLimitAll, kSecReturnAttributes,
        kSecReturnData, kSecValueData,
    };
    use security_framework_sys::keychain_item::{
        SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
    };

    // The attribute key itself; security-framework-sys binds only its
    // values (the Security framework is linked already).
    extern "C" {
        static kSecAttrAccessible: CFStringRef;
    }

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

    /// The items of `service` (of `account`, when given), never a
    /// synchronized one.
    fn query(service: &str, account: Option<&str>) -> Vec<(CFString, CFType)> {
        let mut q = vec![
            (
                key(unsafe { kSecClass }),
                key(unsafe { kSecClassGenericPassword }).into_CFType(),
            ),
            (
                key(unsafe { kSecAttrService }),
                CFString::new(service).into_CFType(),
            ),
            (
                key(unsafe { kSecAttrSynchronizable }),
                CFBoolean::false_value().into_CFType(),
            ),
        ];
        if let Some(account) = account {
            q.push((
                key(unsafe { kSecAttrAccount }),
                CFString::new(account).into_CFType(),
            ));
        }
        q
    }

    /// Runs a copy query: its result as a +1 reference (`None`: no match).
    fn copy_matching(q: &[(CFString, CFType)]) -> Result<Option<CFTypeRef>> {
        let q = CFDictionary::from_CFType_pairs(q);
        let mut found: CFTypeRef = std::ptr::null();
        // SAFETY: a valid dictionary; `found` receives a +1 reference.
        let status = unsafe { SecItemCopyMatching(q.as_concrete_TypeRef(), &mut found) };
        if status == errSecItemNotFound {
            return Ok(None);
        }
        check(status)?;
        Ok((!found.is_null()).then_some(found))
    }

    /// Add-only: `errSecDuplicateItem` when the item exists.
    pub(crate) fn add_generic_password(service: &str, account: &str, value: &[u8]) -> Result<()> {
        let mut attrs = query(service, Some(account));
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
                let found = CFDictionary::from_CFType_pairs(&query(service, Some(account)));
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
        let mut q = query(service, Some(account));
        q.push((
            key(unsafe { kSecReturnData }),
            CFBoolean::true_value().into_CFType(),
        ));
        let found = copy_matching(&q)?.ok_or_else(|| Error::from_code(errSecItemNotFound))?;
        // SAFETY: `found` is a live CF object we own (create rule).
        if unsafe { CFGetTypeID(found) } != CFData::type_id() {
            unsafe { CFRelease(found) };
            return Err(Error::from_code(errSecParam));
        }
        let data = unsafe { CFData::wrap_under_create_rule(found as CFDataRef) };
        // An empty value has no byte pointer to read.
        if data.is_empty() {
            return Ok(Vec::new());
        }
        Ok(data.bytes().to_vec())
    }

    /// Removes the item; `errSecItemNotFound` when there is none.
    pub(crate) fn delete_generic_password(service: &str, account: &str) -> Result<()> {
        let q = CFDictionary::from_CFType_pairs(&query(service, Some(account)));
        // SAFETY: a valid dictionary.
        check(unsafe { SecItemDelete(q.as_concrete_TypeRef()) })
    }

    /// The attributes of every item of `service` (of `account`, when
    /// given). No value is read.
    fn attributes(
        service: &str,
        account: Option<&str>,
    ) -> Result<Vec<CFDictionary<CFString, CFType>>> {
        let mut q = query(service, account);
        q.push((
            key(unsafe { kSecReturnAttributes }),
            CFBoolean::true_value().into_CFType(),
        ));
        q.push((
            key(unsafe { kSecMatchLimit }),
            key(unsafe { kSecMatchLimitAll }).into_CFType(),
        ));
        let Some(found) = copy_matching(&q)? else {
            return Ok(Vec::new());
        };
        // SAFETY: `found` is a live CF object we own (create rule).
        if unsafe { CFGetTypeID(found) } != CFArray::<CFType>::type_id() {
            unsafe { CFRelease(found) };
            return Err(Error::from_code(errSecParam));
        }
        let items: CFArray<CFType> =
            unsafe { CFArray::wrap_under_create_rule(found as CFArrayRef) };
        Ok(items
            .iter()
            .filter_map(|item| item.downcast::<CFDictionary>())
            // SAFETY: a dictionary the array holds (get rule: retained here).
            .map(|d| unsafe {
                CFDictionary::<CFString, CFType>::wrap_under_get_rule(d.as_concrete_TypeRef())
            })
            .collect())
    }

    /// The account of every item of `service` (for erase). Attributes
    /// only: no secret is read.
    pub(crate) fn accounts(service: &str) -> Result<Vec<String>> {
        Ok(attributes(service, None)?
            .iter()
            .filter_map(|attrs| {
                attrs
                    .find(key(unsafe { kSecAttrAccount }))
                    .and_then(|v| v.downcast::<CFString>())
                    .map(|s| s.to_string())
            })
            .collect())
    }

    /// One item's protection class (`kSecAttrAccessible`'s value, such as
    /// "cku") and whether it is synchronized, as the keychain reports them.
    #[cfg(test)]
    pub(crate) fn protection(service: &str, account: &str) -> Result<(String, bool)> {
        let all = attributes(service, Some(account))?;
        let attrs = all
            .first()
            .ok_or_else(|| Error::from_code(errSecItemNotFound))?;
        let class = attrs
            .find(key(unsafe { kSecAttrAccessible }))
            .and_then(|v| v.downcast::<CFString>())
            .map(|s| s.to_string())
            .unwrap_or_default();
        let synced = attrs
            .find(key(unsafe { kSecAttrSynchronizable }))
            .and_then(|v| v.downcast::<CFBoolean>())
            .is_some_and(bool::from);
        Ok((class, synced))
    }
}

/// On the iOS Simulator (`xcrun simctl spawn`; docs/IOS.md section 10):
/// the data-protection keychain as Raven's stores use it.
#[cfg(all(test, target_os = "ios"))]
mod tests {
    use super::*;

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
        // kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly is "cku".
        let cku = || (String::from("cku"), false);
        assert_eq!(ios::protection(service, &account).unwrap(), cku());
        assert!(accounts(service).unwrap().contains(&account));
        set_generic_password(service, &account, b"three").unwrap();
        assert_eq!(get_generic_password(service, &account).unwrap(), b"three");
        assert_eq!(ios::protection(service, &account).unwrap(), cku());
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
