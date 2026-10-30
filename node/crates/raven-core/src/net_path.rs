//! The kind of network this device uses now, as the app that runs the node
//! reports it (iOS: `NWPathMonitor`'s interface type; docs/IOS.md). The node
//! cannot tell mobile data from Wi-Fi by itself on a phone, so the app says
//! it, and the profile's `tor_wifi_only` setting then keeps Tor off on
//! mobile data. Nothing reports it on a desktop: it stays
//! [`PathKind::Unknown`] there, and Tor follows its other settings only.
//!
//! Process-wide: the app's engine and its embedded node share one process.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// What kind of network carries this device's traffic now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    /// Nobody said (a desktop, or before the app's first report).
    Unknown,
    Wifi,
    Wired,
    /// Mobile data (cellular).
    Cellular,
    /// Another interface (a VPN alone, a loopback-only path).
    Other,
    /// No usable network at all.
    Offline,
}

impl PathKind {
    pub fn word(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Wifi => "wifi",
            Self::Wired => "wired",
            Self::Cellular => "cellular",
            Self::Other => "other",
            Self::Offline => "offline",
        }
    }

    pub fn parse(word: &str) -> Option<Self> {
        Some(match word.trim() {
            "unknown" => Self::Unknown,
            "wifi" => Self::Wifi,
            "wired" => Self::Wired,
            "cellular" => Self::Cellular,
            "other" => Self::Other,
            "offline" => Self::Offline,
            _ => return None,
        })
    }

    fn code(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Wifi => 1,
            Self::Wired => 2,
            Self::Cellular => 3,
            Self::Other => 4,
            Self::Offline => 5,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Wifi,
            2 => Self::Wired,
            3 => Self::Cellular,
            4 => Self::Other,
            5 => Self::Offline,
            _ => Self::Unknown,
        }
    }
}

static PATH: AtomicU8 = AtomicU8::new(0);
static CHANGES: AtomicU64 = AtomicU64::new(0);

/// The app's report: this device uses `kind` now. Whether it changed.
pub fn set(kind: PathKind) -> bool {
    let changed = PATH.swap(kind.code(), Ordering::AcqRel) != kind.code();
    if changed {
        CHANGES.fetch_add(1, Ordering::AcqRel);
    }
    changed
}

/// The kind of network the app last reported.
pub fn current() -> PathKind {
    PathKind::from_code(PATH.load(Ordering::Acquire))
}

/// How many times the reported kind changed in this process (a waiter
/// compares it to notice a change).
pub fn changes() -> u64 {
    CHANGES.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_round_trip_and_unknown_words_are_refused() {
        for kind in [
            PathKind::Unknown,
            PathKind::Wifi,
            PathKind::Wired,
            PathKind::Cellular,
            PathKind::Other,
            PathKind::Offline,
        ] {
            assert_eq!(PathKind::parse(kind.word()), Some(kind));
            assert_eq!(PathKind::from_code(kind.code()), kind);
        }
        assert_eq!(PathKind::parse("5g"), None);
    }
}
