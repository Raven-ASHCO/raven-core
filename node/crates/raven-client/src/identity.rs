//! This profile's own public identity: address, security words, old code and
//! invite. Public material only.

use raven_core::identity::Identity;

/// What `identity.create` and `identity.me` show of the user's own key.
pub(crate) struct MeWords {
    pub address: String,
    /// The 10 security words (raven_core::security_words v1).
    pub words: Vec<String>,
    /// The old letters-and-digits code (`device_fingerprint_v1`).
    pub old_code: String,
    /// `raven:<address>:<pub_hex>`, as `ash whoami` prints it.
    pub invite: String,
}

pub(crate) fn me_words(id: &Identity) -> MeWords {
    let key = id.public_key_bytes();
    let address = id.address();
    MeWords {
        words: raven_core::security_words::words_v1(&key)
            .iter()
            .map(|w| (*w).to_owned())
            .collect(),
        old_code: raven_core::fingerprint::device_fingerprint_v1(&key),
        invite: format!("raven:{address}:{}", hex::encode(key)),
        address,
    }
}

/// An address shortened for display: its first 8 and last 5 characters
/// (the apps' mock does the same).
pub(crate) fn short_address(address: &str) -> String {
    let chars: Vec<char> = address.chars().collect();
    if chars.len() <= 16 {
        return address.to_owned();
    }
    let head: String = chars[..8].iter().collect();
    let tail: String = chars[chars.len() - 5..].iter().collect();
    format!("{head}\u{2026}{tail}")
}

/// Which of the 5 avatar colours a friend gets: the sum of the address's
/// bytes modulo 5 (the apps' `avatarIndex`, so a friend keeps their colour
/// from the mock to the engine).
pub(crate) fn avatar_index(address: &str) -> u64 {
    address
        .bytes()
        .fold(0u64, |acc, b| (acc + u64::from(b)) % 5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_identity_shows_words_code_and_invite_only() {
        let id = Identity::from_seed(&[0x31; 32]);
        let me = me_words(&id);
        assert_eq!(me.words.len(), 10);
        assert!(raven_core::security_words::looks_like_words(
            &me.words.join(" ")
        ));
        assert_eq!(
            raven_core::security_words::compare(&me.words.join(" "), &id.public_key_bytes()),
            raven_core::security_words::Verdict::Match
        );
        assert!(me.invite.starts_with(&format!("raven:{}:", me.address)));
        assert!(!me.invite.contains(&hex::encode([0x31u8; 32])));
    }

    #[test]
    fn short_addresses_and_avatars() {
        assert_eq!(
            short_address("rvn1qtnu9xwlc92xuxjx4fpjtjdgawyazdw46tdnu8kt"),
            "rvn1qtnu\u{2026}nu8kt"
        );
        assert_eq!(short_address("short"), "short");
        assert_eq!(avatar_index("ab"), (97 + 98) % 5);
    }
}
