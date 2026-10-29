//! The suite and protocol-version registry (`protocol/RAVEN_SECURITY_ADVISORY_V1.md`
//! §4; `docs/roadmap/plans/phase6-design.json` step P6.41, design D §7 and §8;
//! owner decision OD6b-29): the ids a RAD1 advisory names.
//!
//! - **Suites** ([`SUITES`]): every negotiable cryptographic suite and wire
//!   protocol version, with where it is consulted. A `SUITE_STATUS` entry
//!   marks one INFO, DEPRECATED (warn) or BROKEN (refuse; no local
//!   override, OD6b-21).
//! - **Feature holds** ([`FEATURES`]): `feature/<gate>` for every
//!   `*_PRODUCTION_ENABLED` gate of raven-core. A `FEATURE_HOLD` entry can
//!   only close the feature (BROKEN) or warn (DEPRECATED), never open it.
//!
//! An id not in this build's registry (a suite added later) keeps the
//! advisory valid and is not enforced: this build has nothing to refuse.
//! Ids are RAD1 targets ([`crate::advisory::target_well_formed`]) and never
//! change meaning: a new version of a suite gets a new id.
//!
//! Data only. The consult points are [`crate::suite_policy`]'s (P6.45).

/// Where a suite is consulted (design D §7), and so what BROKEN means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// Before every link handshake (LAN direct, Internet direct, p2p,
    /// nearby): BROKEN means no link, so no contact can be reached until
    /// Raven is updated (the text says so).
    Link,
    /// Creating and accepting a PairInit: BROKEN means no new session of
    /// that version, either way.
    PairInit,
    /// Sealing and accepting on an indexed session: BROKEN retires the
    /// existing sessions of that version (re-sealed under the next profile
    /// when there is one, otherwise held with an explanation).
    Session,
    /// The wire module's own live check: BROKEN turns the feature off.
    Module,
}

/// A registered suite or protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suite {
    pub id: &'static str,
    pub layer: Layer,
    /// [`Layer::Module`] only: the name of the gate whose feature the
    /// module is (BROKEN turns that feature off).
    pub gate: Option<&'static str>,
}

/// The LAN and Internet link handshake (`lan_noise::NOISE_PATTERN`).
pub const NOISE_XX_25519_CHACHAPOLY_BLAKE2S: &str = "noise/xx-25519-chachapoly-blake2s";
/// The signed Internet hello, version 1 (RAVEN_TRANSPORT_INTERFACE_V1).
pub const RIH1_V1: &str = "rih1/1";
/// The LAN bind and offer, version 1 (`lan_rlb1`).
pub const RLB1_V1: &str = "rlb1/1";
/// PairInit version 1 with its suite 1 (X25519 + ML-KEM-768, `pair_init`).
pub const PAIRINIT_V1_SUITE1: &str = "pairinit/1/1";
/// The ATSAM indexed session V1 (ATSAM_INDEXED_SESSION_PROFILE_V1).
pub const ATSAM_INDEXED_SESSION_V1: &str = "atsam/indexed-session/v1";
/// The RVNA1 sealed body, header version 3 (`atsam_indexed_session`).
pub const RVNA1_V3: &str = "rvna1/3";
/// Route hints (RAVEN_ROUTE_HINTS_V1).
pub const RRH1_V1: &str = "rrh1/1";
/// Friend custody (RAVEN_FRIEND_CUSTODY_V1).
pub const RFC1_V1: &str = "rfc1/1";
/// Session reset (RAVEN_SESSION_RESET_V1).
pub const RSR1_V1: &str = "rsr1/1";
/// Async letters (RAVEN_ASYNC_LETTER_V1).
pub const RAL1_V1: &str = "ral1/1";
/// Custody handoff (RAVEN_CUSTODY_HANDOFF_V1).
pub const RHW1_V1: &str = "rhw1/1";
/// The Bluetooth LE nearby link (RAVEN_NEARBY_LINK_V1).
pub const RNL1_V1: &str = "rnl1/1";
/// Link padding (RAVEN_LINK_PADDING_V1).
pub const PAD1_V1: &str = "pad1/1";
/// The link knock (RAVEN_LINK_KNOCK_V1).
pub const RLK1_V1: &str = "rlk1/1";
/// The update exchange between friends (RAVEN_UPDATE_EXCHANGE_V1).
pub const RUP1_V1: &str = "rup1/1";

/// Every registered suite and protocol version (design D §7).
pub const SUITES: &[Suite] = &[
    Suite {
        id: NOISE_XX_25519_CHACHAPOLY_BLAKE2S,
        layer: Layer::Link,
        gate: None,
    },
    Suite {
        id: RIH1_V1,
        layer: Layer::Link,
        gate: None,
    },
    Suite {
        id: RLB1_V1,
        layer: Layer::Link,
        gate: None,
    },
    Suite {
        id: PAIRINIT_V1_SUITE1,
        layer: Layer::PairInit,
        gate: None,
    },
    Suite {
        id: ATSAM_INDEXED_SESSION_V1,
        layer: Layer::Session,
        gate: None,
    },
    Suite {
        id: RVNA1_V3,
        layer: Layer::Session,
        gate: None,
    },
    Suite {
        id: RRH1_V1,
        layer: Layer::Module,
        gate: Some("ROUTE_HINTS_PRODUCTION_ENABLED"),
    },
    Suite {
        id: RFC1_V1,
        layer: Layer::Module,
        gate: Some("FRIEND_CUSTODY_PRODUCTION_ENABLED"),
    },
    Suite {
        id: RSR1_V1,
        layer: Layer::Module,
        gate: Some("SESSION_RESET_PRODUCTION_ENABLED"),
    },
    Suite {
        id: RAL1_V1,
        layer: Layer::Module,
        gate: Some("ASYNC_LETTER_PRODUCTION_ENABLED"),
    },
    Suite {
        id: RHW1_V1,
        layer: Layer::Module,
        gate: Some("CUSTODY_HANDOFF_PRODUCTION_ENABLED"),
    },
    Suite {
        id: RNL1_V1,
        layer: Layer::Module,
        gate: Some("NEARBY_PRODUCTION_ENABLED"),
    },
    Suite {
        id: PAD1_V1,
        layer: Layer::Module,
        gate: Some("LINK_PADDING_PRODUCTION_ENABLED"),
    },
    Suite {
        id: RLK1_V1,
        layer: Layer::Module,
        gate: Some("LINK_KNOCK_PRODUCTION_ENABLED"),
    },
    Suite {
        id: RUP1_V1,
        layer: Layer::Module,
        gate: Some("MESH_UPDATE_PRODUCTION_ENABLED"),
    },
];

/// A feature a `FEATURE_HOLD` entry can close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feature {
    /// `feature/<gate>`: the gate's name without `_PRODUCTION_ENABLED`,
    /// lower case, `_` written `-`.
    pub id: &'static str,
    /// The gate constant's name.
    pub gate: &'static str,
    /// The gate constant's value in this build.
    pub production: bool,
}

impl Feature {
    /// Does a BROKEN hold close this feature? Every one but
    /// `feature/advisory`: a hold on advisories would also stop the
    /// advisory that lifts it (such an entry is shown, never enforced).
    pub fn holdable(&self) -> bool {
        self.id != FEATURE_ADVISORY
    }
}

macro_rules! features {
    ($($name:ident = $id:literal => $module:ident :: $gate:ident),* $(,)?) => {
        $(
            #[doc = concat!("`", $id, "`: [`", stringify!($gate), "`](crate::",
                stringify!($module), "::", stringify!($gate), ").")]
            pub const $name: &str = $id;
        )*

        /// Every gate of raven-core, as a feature a hold can name.
        pub const FEATURES: &[Feature] = &[
            $(Feature {
                id: $name,
                gate: stringify!($gate),
                production: crate::$module::$gate,
            }),*
        ];
    };
}

features! {
    FEATURE_ADVISORY = "feature/advisory" => security_gate::ADVISORY_PRODUCTION_ENABLED,
    FEATURE_APP_CHANNEL = "feature/app-channel" => app_channel::APP_CHANNEL_PRODUCTION_ENABLED,
    FEATURE_ASYNC_LETTER = "feature/async-letter" => horizon::ASYNC_LETTER_PRODUCTION_ENABLED,
    FEATURE_CUSTODY_HANDOFF =
        "feature/custody-handoff" => custody_gate::CUSTODY_HANDOFF_PRODUCTION_ENABLED,
    FEATURE_FRIEND_CUSTODY =
        "feature/friend-custody" => custody_gate::FRIEND_CUSTODY_PRODUCTION_ENABLED,
    FEATURE_FRIEND_RELAY = "feature/friend-relay" => p2p_gate::FRIEND_RELAY_PRODUCTION_ENABLED,
    FEATURE_GROUPS = "feature/groups" => group::GROUPS_PRODUCTION_ENABLED,
    FEATURE_INDEXED_SESSION_STORE = "feature/indexed-session-store"
        => indexed_session_store::INDEXED_SESSION_STORE_PRODUCTION_ENABLED,
    FEATURE_INTERNET_DIRECT =
        "feature/internet-direct" => internet_gate::INTERNET_DIRECT_PRODUCTION_ENABLED,
    FEATURE_LAN_AUTO_LISTEN =
        "feature/lan-auto-listen" => lan_gate::LAN_AUTO_LISTEN_PRODUCTION_ENABLED,
    FEATURE_LAN_BEACON = "feature/lan-beacon" => lan_beacon::LAN_BEACON_PRODUCTION_ENABLED,
    FEATURE_LAN_DIRECT = "feature/lan-direct" => lan_gate::LAN_DIRECT_PRODUCTION_ENABLED,
    FEATURE_LAN_NOISE_PIN = "feature/lan-noise-pin" => lan_gate::LAN_NOISE_PIN_PRODUCTION_ENABLED,
    FEATURE_LEARNING = "feature/learning" => learning::LEARNING_PRODUCTION_ENABLED,
    FEATURE_LINK_KNOCK = "feature/link-knock" => security_gate::LINK_KNOCK_PRODUCTION_ENABLED,
    FEATURE_LINK_PADDING =
        "feature/link-padding" => security_gate::LINK_PADDING_PRODUCTION_ENABLED,
    FEATURE_LISTEN_PORT_RANDOM =
        "feature/listen-port-random" => security_gate::LISTEN_PORT_RANDOM_PRODUCTION_ENABLED,
    FEATURE_LOCAL_PROTECTION =
        "feature/local-protection" => security_gate::LOCAL_PROTECTION_PRODUCTION_ENABLED,
    FEATURE_LONG_HORIZON = "feature/long-horizon" => horizon::LONG_HORIZON_PRODUCTION_ENABLED,
    FEATURE_MESH_UPDATE = "feature/mesh-update" => security_gate::MESH_UPDATE_PRODUCTION_ENABLED,
    FEATURE_NAT_CLASS = "feature/nat-class" => portmap_gate::NAT_CLASS_PRODUCTION_ENABLED,
    FEATURE_NEARBY = "feature/nearby" => nearby_gate::NEARBY_PRODUCTION_ENABLED,
    FEATURE_OFFLINE_LAN = "feature/offline-lan" => lan_gate::OFFLINE_LAN_PRODUCTION_ENABLED,
    FEATURE_ONION = "feature/onion" => onion_gate::ONION_PRODUCTION_ENABLED,
    FEATURE_P2P = "feature/p2p" => p2p_gate::P2P_PRODUCTION_ENABLED,
    FEATURE_PAIR_SEED = "feature/pair-seed" => security_gate::PAIR_SEED_PRODUCTION_ENABLED,
    FEATURE_PEER_ROTATION =
        "feature/peer-rotation" => portmap_gate::PEER_ROTATION_PRODUCTION_ENABLED,
    FEATURE_PORT_MAP = "feature/port-map" => portmap_gate::PORT_MAP_PRODUCTION_ENABLED,
    FEATURE_PREKEY_LIFECYCLE =
        "feature/prekey-lifecycle" => prekey_lifecycle::PREKEY_LIFECYCLE_PRODUCTION_ENABLED,
    FEATURE_RELEASE_BUNDLE =
        "feature/release-bundle" => security_gate::RELEASE_BUNDLE_PRODUCTION_ENABLED,
    FEATURE_ROUTE_HINTS = "feature/route-hints" => route_hints::ROUTE_HINTS_PRODUCTION_ENABLED,
    FEATURE_SECURITY_EVENTS =
        "feature/security-events" => security_gate::SECURITY_EVENTS_PRODUCTION_ENABLED,
    FEATURE_SECURITY_RESPONSES =
        "feature/security-responses" => security_gate::SECURITY_RESPONSES_PRODUCTION_ENABLED,
    FEATURE_SERVERLESS_PUNCH =
        "feature/serverless-punch" => portmap_gate::SERVERLESS_PUNCH_PRODUCTION_ENABLED,
    FEATURE_SESSION_RENEWAL =
        "feature/session-renewal" => session_renewal::SESSION_RENEWAL_PRODUCTION_ENABLED,
    FEATURE_SESSION_RESET =
        "feature/session-reset" => session_reset::SESSION_RESET_PRODUCTION_ENABLED,
    FEATURE_SESSION_RESET_RESTORE = "feature/session-reset-restore"
        => session_reset::SESSION_RESET_RESTORE_PRODUCTION_ENABLED,
    FEATURE_STUN_DISCOVERY =
        "feature/stun-discovery" => portmap_gate::STUN_DISCOVERY_PRODUCTION_ENABLED,
    FEATURE_SUITE_FLOOR = "feature/suite-floor" => security_gate::SUITE_FLOOR_PRODUCTION_ENABLED,
    FEATURE_V6_PINHOLE = "feature/v6-pinhole" => portmap_gate::V6_PINHOLE_PRODUCTION_ENABLED,
    FEATURE_WSS = "feature/wss" => wss_gate::WSS_PRODUCTION_ENABLED,
    FEATURE_WSS_PROXY = "feature/wss-proxy" => wss_gate::WSS_PROXY_PRODUCTION_ENABLED,
}

/// The registered suite with this id.
pub fn suite(id: &str) -> Option<&'static Suite> {
    SUITES.iter().find(|s| s.id == id)
}

/// The feature with this `feature/<gate>` id.
pub fn feature(id: &str) -> Option<&'static Feature> {
    FEATURES.iter().find(|f| f.id == id)
}

/// The feature of the gate constant named `gate`.
pub fn feature_for_gate(gate: &str) -> Option<&'static Feature> {
    FEATURES.iter().find(|f| f.gate == gate)
}

#[cfg(test)]
mod tests;
