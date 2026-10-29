//! LAN production gates.
//!
//! LAN direct dial: independent of the four global `PRODUCTION_ENABLED`
//! tripwires. Flipped only after the two-node LAN script is green.
//!
//! The cutoff pack's two held gates, [`OFFLINE_LAN_PRODUCTION_ENABLED`] and
//! [`LAN_NOISE_PIN_PRODUCTION_ENABLED`]: a release build follows the const
//! alone; a debug build opens or closes each with its lab switch
//! ([`gate_live`]). Every behaviour behind them is a pure inner function that
//! takes `live: bool`, so its gate-closed tests stay valid after the flip.
//!
//! Phase 3 (D7) adds [`LAN_AUTO_LISTEN_PRODUCTION_ENABLED`] (`--lan-listen
//! auto`; debug `RAVEN_LAB_LAN_AUTO`, and [`lab_lan_source_deny_loopback`]
//! for the harness) and the user's `raven lan off` for this process
//! ([`set_lan_user_off`], ungated): [`lan_usable_now`] is the LAN carrier
//! gate with that switch applied. The LAN beacon's gate,
//! [`crate::lan_beacon::LAN_BEACON_PRODUCTION_ENABLED`] (debug
//! `RAVEN_LAB_LAN_BEACON`), sits with its codec in `lan_beacon`; the tests
//! here hold it false with the others.
//!
//! Phase 5's horizon gates, [`crate::horizon::LONG_HORIZON_PRODUCTION_ENABLED`]
//! (debug `RAVEN_LAB_HORIZON`) and
//! [`crate::horizon::ASYNC_LETTER_PRODUCTION_ENABLED`] (debug
//! `RAVEN_LAB_LETTER`), sit with their constants in `horizon`, and its
//! multi-hop custody gate,
//! [`crate::custody_gate::CUSTODY_HANDOFF_PRODUCTION_ENABLED`] (debug
//! `RAVEN_LAB_CUSTODY_HANDOFF`), in `custody_gate`. So does the Bluetooth
//! nearby carrier's, [`crate::nearby_gate::NEARBY_PRODUCTION_ENABLED`] (debug
//! `RAVEN_LAB_NEARBY`), in `nearby_gate`.
//!
//! The release set (2026-10): LAN direct, plus the features that passed the
//! October 2026 three-machine field test (Internet direct, p2p and the friend
//! relay, friend custody over LAN and the internet, the long horizon, route
//! hints, port mapping, the NAT class, STUN discovery, serverless punching,
//! the Tor onion carrier, groups, and Bluetooth nearby on macOS), switched
//! on and not independently reviewed. A debug build closes each again with
//! its switch set to "0" ([`crate::pair_init::lab_gate`],
//! [`crate::pair_init::test_a_gate`], [`gate_switch`]). The tests here pin
//! that set and hold every other gate false.
//!
//! The privacy pack adds no gate; its debug-only lab switches are named here
//! ([`PRIVACY_LAB_SWITCHES`]) with the one rule a release build follows
//! without them ([`at_rest_seal_allowed`]).
//!
//! Phase 6a's learning gate, [`crate::learning::LEARNING_PRODUCTION_ENABLED`]
//! (debug `RAVEN_LAB_LEARNING`, with `RAVEN_LAB_LEARNING_TUNE`), sits with
//! its switches in `learning`; the tests here hold it false with the others
//! and prove its switches and [`lab_sealer_unavailable`] inert in release.
//!
//! Phase 6b's eleven gates (security events and responses, the suite floor,
//! padding, the knock, the random port, pair seeds, Lock v2, advisories,
//! bundles and mesh updates) sit with their switches in `security_gate`
//! ([`crate::security_gate::live`]); the tests here hold them false with the
//! others and prove their switches inert in release.

/// Hard enable for the terminal↔terminal LAN slice. Global PairInit / session
/// / prekey / ATSAM production flags stay false.
pub const LAN_DIRECT_PRODUCTION_ENABLED: bool = true;

/// Phase 3 item 1 (D7): `--lan-listen auto` = every interface, IPv4+IPv6, local sources only.
/// false until the Phase 3 LAN amendment (hold B12) is signed; until then `auto` == 0.0.0.0:<port>.
pub const LAN_AUTO_LISTEN_PRODUCTION_ENABLED: bool = false;

/// `--lan-listen auto` is live: [`LAN_AUTO_LISTEN_PRODUCTION_ENABLED`], or in a
/// debug build `RAVEN_LAB_LAN_AUTO=1` (a release build never reads it);
/// unless a security notice holds it (P6.45, close-only).
pub fn lan_auto_live() -> bool {
    (LAN_AUTO_LISTEN_PRODUCTION_ENABLED
        || crate::p2p_gate::lab_flag(cfg!(debug_assertions), || {
            std::env::var("RAVEN_LAB_LAN_AUTO").ok()
        }))
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_LAN_AUTO_LISTEN)
}

/// Debug only (Phase 3, harness case C27): `RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK=1`
/// makes a live `auto` LAN listener count a loopback source as not local, so
/// a one-computer harness can watch the local-source rule close a
/// connection. A release build never reads the variable.
pub fn lab_lan_source_deny_loopback() -> bool {
    crate::p2p_gate::lab_flag(cfg!(debug_assertions), || {
        std::env::var("RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK").ok()
    })
}

/// Local refusal / status code (RAVEN_ERROR_CODES_V1 §2): `raven lan off` is
/// in effect, so no LAN listener, LAN dial or beacon.
pub const LAN_OFF: &str = "LAN_OFF";

/// Local refusal code (RAVEN_ERROR_CODES_V1 §2): `raven lan verified-only on`
/// (Phase 3 P3.C2, cutoff M1) is in effect and the contact is not verified
/// (pinned), so it gets no LAN link either way: not admitted, not dialled.
/// The setting is `lan_verified_only` in node_policy.json
/// ([`crate::node_policy::lan_verified_only`]).
pub const LAN_VERIFIED_ONLY: &str = "LAN_VERIFIED_ONLY";

static LAN_USER_OFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `raven lan off` for this process: raven-node sets it together with its LAN listener from
/// node_policy at start and on IPC SetLan; ash sets it from node_policy before any send or plan.
pub fn set_lan_user_off(off: bool) {
    LAN_USER_OFF.store(off, std::sync::atomic::Ordering::Relaxed)
}

/// Whether `raven lan off` is in effect for this process ([`set_lan_user_off`]).
pub fn lan_user_off() -> bool {
    LAN_USER_OFF.load(std::sync::atomic::Ordering::Relaxed)
}

/// The LAN carrier may be used now: gate live AND not turned off by the user.
pub fn lan_usable_now() -> bool {
    lan_direct_live_enabled() && !lan_user_off()
}

/// Module test lock for [`LAN_USER_OFF`] (one switch per process): a test
/// that sets it holds the lock for writing ([`lan_user_off_for_test`]); a
/// test that needs the LAN carrier as the build sets it (friend custody over
/// LAN links reads [`lan_usable_now`]) holds it for reading
/// ([`lan_user_switch_untouched`]), so neither sees the other's switch. A
/// thread takes it at most once at a time: a second read on the same thread
/// can deadlock behind a waiting writer.
#[cfg(test)]
static LAN_USER_OFF_TEST_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// Test-only: `raven lan off` set to `off` while the guard lives, under the
/// module test lock; dropping it turns the switch back off.
#[cfg(test)]
pub(crate) fn lan_user_off_for_test(off: bool) -> LanUserOffForTest {
    let lock = LAN_USER_OFF_TEST_LOCK
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_lan_user_off(off);
    LanUserOffForTest { _lock: lock }
}

/// [`lan_user_off_for_test`]'s guard.
#[cfg(test)]
pub(crate) struct LanUserOffForTest {
    _lock: std::sync::RwLockWriteGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for LanUserOffForTest {
    fn drop(&mut self) {
        set_lan_user_off(false);
    }
}

/// Test-only: no test changes `raven lan off` while the guard lives.
#[cfg(test)]
pub(crate) fn lan_user_switch_untouched() -> std::sync::RwLockReadGuard<'static, ()> {
    LAN_USER_OFF_TEST_LOCK
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Cutoff pack: F1 (queue for an unverified contact whose saved name does not resolve, and
/// dial one whose name also resolves outside the local network at its local address),
/// F5 (wake waiting contacts when the network proves itself), F6 (link-local-only
/// networks count) and F7 (lan_seen without a saved route). The owner approved
/// (2026-10-16) setting it true only after the pack is green and its adversarial review
/// and fixes are clean (CP.16). Nothing else may ride this gate.
pub const OFFLINE_LAN_PRODUCTION_ENABLED: bool = false;

/// M0: each contact's Noise static is pinned (as a digest), and a dial stops before Noise
/// message 3 (so before our static and signed identity bind) when another key answers.
/// Same owner approval and condition (CP.16).
pub const LAN_NOISE_PIN_PRODUCTION_ENABLED: bool = false;

// offline_lan_needs_noise_pin: F5 and F7 dial sooner or at more addresses, so
// they are never live in release without M0.
const _: () = assert!(!OFFLINE_LAN_PRODUCTION_ENABLED || LAN_NOISE_PIN_PRODUCTION_ENABLED);

/// Live LAN-direct path: compile-time slice gate or debug `RAVEN_LAB_TEST_A=1`,
/// unless a security notice holds it (P6.45, close-only) or a debug lab run
/// carries over nearby alone ([`crate::nearby_gate::nearby_only`]; raven-node
/// then also keeps its LAN switch off, so its LAN listener never binds).
pub fn lan_direct_live_enabled() -> bool {
    crate::nearby_gate::unless_nearby_only(
        (LAN_DIRECT_PRODUCTION_ENABLED || crate::pair_init::lab_test_a_enabled())
            && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_LAN_DIRECT),
    )
}

/// F1, F5, F6 and F7 are live: [`OFFLINE_LAN_PRODUCTION_ENABLED`], or in a
/// debug build `RAVEN_LAB_OFFLINE` ([`gate_live`]); unless a security notice
/// holds them, or holds M0, which they sit on (P6.45: never live without
/// M0's own hold allowing it, as `offline_lan_needs_noise_pin` says).
pub fn offline_lan_live() -> bool {
    gate_live(OFFLINE_LAN_PRODUCTION_ENABLED, "RAVEN_LAB_OFFLINE")
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_OFFLINE_LAN)
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_LAN_NOISE_PIN)
}

/// M0 is live: [`LAN_NOISE_PIN_PRODUCTION_ENABLED`], or in a debug build
/// `RAVEN_LAB_NOISE_PIN` ([`gate_live`]); unless a security notice holds it
/// (P6.45, close-only).
pub fn lan_noise_pin_live() -> bool {
    gate_live(LAN_NOISE_PIN_PRODUCTION_ENABLED, "RAVEN_LAB_NOISE_PIN")
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_LAN_NOISE_PIN)
}

/// Release: exactly the const (the variable is never read). Debug: "1" opens a closed
/// gate and "0" closes an open one, so the gate-closed paths and the scenarios that
/// document pre-flip behaviour stay testable after CP.16 flips the consts.
fn gate_live(production: bool, var: &str) -> bool {
    gate_switch(cfg!(debug_assertions), production, || {
        std::env::var(var).ok()
    })
}

/// [`gate_live`] with the build passed in; `value` (the variable) is not
/// called in a release build. Shared by the gates switched on in 2026-10
/// whose switch needs no Lab Test A unlock (route hints, the friend relay).
pub(crate) fn gate_switch(
    debug: bool,
    production: bool,
    value: impl FnOnce() -> Option<String>,
) -> bool {
    if !debug {
        return production;
    }
    match value().as_deref() {
        Some("1") => true,
        Some("0") => false,
        _ => production,
    }
}

/// Debug-only port used instead of 7420 wherever the cutoff pack guesses the default LAN
/// port (F4, F7), so no test ever dials the developer's own node on 7420:
/// `RAVEN_LAB_LAN_DEFAULT_PORT`, a port 1-65535. Release builds never read the variable.
pub fn lab_default_lan_port() -> Option<u16> {
    crate::p2p_gate::lab_value(
        cfg!(debug_assertions),
        || std::env::var("RAVEN_LAB_LAN_DEFAULT_PORT").ok(),
        parse_lab_port,
    )
}

/// A port 1-65535 (surrounding blanks ignored); anything else is `None`.
fn parse_lab_port(v: &str) -> Option<u16> {
    v.trim().parse::<u16>().ok().filter(|&port| port != 0)
}

// ── Privacy pack lab switches (PP.1) ─────────────────────────────────────
//
// The privacy pack adds no gate (docs/design/2026-10-at-rest-metadata.md):
// its steps are live in release. These debug-only switches keep a debug
// build away from real profiles and make the harness fast; each is read
// through [`crate::p2p_gate::lab_switch`], so a release build never reads
// one. Nothing reads them before the steps named here.

/// `=1`: a debug build may seal a profile (`privacy::migrate_all` with its
/// automatic policy, PP.3 on). See [`at_rest_seal_allowed`].
pub const LAB_AT_REST: &str = "RAVEN_LAB_AT_REST";
/// `=<dir>`: in a debug build `raven erase` (PP.16) refuses every data dir
/// that is not under this directory, and every data dir without it.
pub const LAB_ERASE_ROOT: &str = "RAVEN_LAB_ERASE_ROOT";
/// `=unavailable`: the at-rest key load (PP.3) fails as an unreadable
/// keystore would, without a real keychain (the node's fail-closed state).
pub const LAB_AT_REST_KEY_FAULT: &str = "RAVEN_LAB_AT_REST_KEY_FAULT";
/// `=<ms>`: replaces the 7-day grace before the first retention deletion of
/// an existing profile (PP.9), for the harness.
pub const LAB_RETENTION_GRACE_MS: &str = "RAVEN_LAB_RETENTION_GRACE_MS";
/// `=<dir>`: stands in for `~/Library/LaunchAgents`, `~/.config/systemd/user`
/// and the scheduled-task list (PP.15, PP.16); without it a debug build's
/// login-item code refuses to run, so no test touches the real login item.
pub const LAB_LOGIN_ITEM_ROOT: &str = "RAVEN_LAB_LOGIN_ITEM_ROOT";
/// `=<dir>`: where the fake `launchctl` / `systemctl` / `schtasks` the
/// login-item code runs in a debug build live (PP.15, PP.16).
pub const LAB_LOGIN_ITEM_TOOLS: &str = "RAVEN_LAB_LOGIN_ITEM_TOOLS";

/// Every privacy pack lab switch (the harnesses scrub and set these).
pub const PRIVACY_LAB_SWITCHES: [&str; 6] = [
    LAB_AT_REST,
    LAB_ERASE_ROOT,
    LAB_AT_REST_KEY_FAULT,
    LAB_RETENTION_GRACE_MS,
    LAB_LOGIN_ITEM_ROOT,
    LAB_LOGIN_ITEM_TOOLS,
];

/// Whether this build may seal a profile on its own (review R02): a release
/// build always may; a debug build only with [`LAB_AT_REST`]`=1`, so a debug
/// binary pointed at a live profile by mistake seals nothing (and creates no
/// `meta_key.rmk`). Unit tests pass an explicit policy instead.
pub fn at_rest_seal_allowed() -> bool {
    seal_allowed(cfg!(debug_assertions), || {
        crate::p2p_gate::lab_switch(LAB_AT_REST)
    })
}

/// [`at_rest_seal_allowed`] with the build passed in; `value` (the switch)
/// is not called in a release build.
fn seal_allowed(debug: bool, value: impl FnOnce() -> Option<String>) -> bool {
    !debug || value().as_deref() == Some("1")
}

/// Debug only (Phase 6a, harness case C73):
/// `RAVEN_LAB_LEARNING_SEALER=unavailable` makes the learning store's sealer
/// fail as an unreadable keystore would, so learning runs memory-only and
/// the store's file is left as it is. A release build never reads it.
pub fn lab_sealer_unavailable() -> bool {
    crate::p2p_gate::lab_value(
        cfg!(debug_assertions),
        || std::env::var(crate::learning::LAB_LEARNING_SEALER).ok(),
        parse_sealer_fault,
    )
    .is_some()
}

/// [`lab_sealer_unavailable`]'s value: exactly `unavailable`.
fn parse_sealer_fault(v: &str) -> Option<()> {
    (v == "unavailable").then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The release set, in one place (2026-10): LAN direct, plus exactly the
    /// features that passed the October 2026 three-machine field test,
    /// switched on and not independently reviewed; everything else held.
    #[test]
    fn release_gates_are_the_field_tested_set() {
        const {
            // On since the LAN slice.
            assert!(LAN_DIRECT_PRODUCTION_ENABLED);
            // Switched on 2026-10 (the field test's S15 switches and, for
            // Bluetooth, S14's): Internet direct, p2p, the friend relay,
            // friend custody over LAN and the internet, the long message
            // horizon, route hints, port mapping and IPv6 pinholes, the NAT
            // class, STUN discovery, serverless punching, the Tor onion
            // carrier, groups, and Bluetooth nearby on macOS; and the app
            // channel (RDAP over Raven), macOS included (owner decision Q6).
            assert!(crate::INTERNET_DIRECT_PRODUCTION_ENABLED);
            assert!(crate::P2P_PRODUCTION_ENABLED);
            assert!(crate::FRIEND_RELAY_PRODUCTION_ENABLED);
            assert!(crate::custody_gate::FRIEND_CUSTODY_PRODUCTION_ENABLED);
            assert!(crate::custody_gate::FRIEND_CUSTODY_WAN_ENABLED);
            assert!(crate::horizon::LONG_HORIZON_PRODUCTION_ENABLED);
            assert!(crate::route_hints::ROUTE_HINTS_PRODUCTION_ENABLED);
            assert!(crate::portmap_gate::PORT_MAP_PRODUCTION_ENABLED);
            assert!(crate::portmap_gate::V6_PINHOLE_PRODUCTION_ENABLED);
            assert!(crate::portmap_gate::NAT_CLASS_PRODUCTION_ENABLED);
            assert!(crate::portmap_gate::STUN_DISCOVERY_PRODUCTION_ENABLED);
            assert!(crate::portmap_gate::SERVERLESS_PUNCH_PRODUCTION_ENABLED);
            assert!(crate::ONION_PRODUCTION_ENABLED);
            assert!(crate::group::GROUPS_PRODUCTION_ENABLED);
            assert!(crate::NEARBY_PRODUCTION_ENABLED == cfg!(target_os = "macos"));
            assert!(crate::app_channel::APP_CHANNEL_PRODUCTION_ENABLED);
            assert!(crate::app_channel::APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED);

            // Held: the four generic PairInit tripwires (the legacy contact
            // request), whatever the carriers do.
            assert!(!crate::pair_init::PRODUCTION_ENABLED);
            assert!(!crate::INDEXED_SESSION_STORE_PRODUCTION_ENABLED);
            assert!(!crate::PREKEY_LIFECYCLE_PRODUCTION_ENABLED);
            assert!(!crate::atsam_indexed_session::PRODUCTION_ENABLED);
            assert!(!crate::session_reset::SESSION_RESET_PRODUCTION_ENABLED);
            assert!(!crate::session_reset::SESSION_RESET_RESTORE_PRODUCTION_ENABLED);
            // Phase 3 item 4: no daemon-started renewal PairInit before the
            // Phase 3 LAN amendment's renewal section is signed.
            assert!(!crate::session_renewal::SESSION_RENEWAL_PRODUCTION_ENABLED);
            // The cutoff pack's two held gates (CP.16 moves exactly these two
            // into their own test when the owner-approved flip lands).
            assert!(!OFFLINE_LAN_PRODUCTION_ENABLED);
            assert!(!LAN_NOISE_PIN_PRODUCTION_ENABLED);
            // Phase 3 (hold B12): `--lan-listen auto` stays 0.0.0.0:<port>.
            assert!(!LAN_AUTO_LISTEN_PRODUCTION_ENABLED);
            // Phase 3 item 2: no LAN beacon before R2 revision 4, the crypto
            // review and the Swift vectors.
            assert!(!crate::lan_beacon::LAN_BEACON_PRODUCTION_ENABLED);
            // Phase 5 (P5.3): no sealed letter before the letter waiver.
            assert!(!crate::horizon::ASYNC_LETTER_PRODUCTION_ENABLED);
            // Phase 5 (P5.17): no multi-hop custody before its own waiver.
            assert!(!crate::custody_gate::CUSTODY_HANDOFF_PRODUCTION_ENABLED);
            // Phase 4 (P4.1): relays over WSS and through an HTTPS proxy, and
            // PeerId rotation.
            assert!(!crate::wss_gate::WSS_PRODUCTION_ENABLED);
            assert!(!crate::wss_gate::WSS_PROXY_PRODUCTION_ENABLED);
            assert!(!crate::portmap_gate::PEER_ROTATION_PRODUCTION_ENABLED);
            // Phase 6a (P6.2): no learned order, wait or relay term before
            // the learning waiver.
            assert!(!crate::learning::LEARNING_PRODUCTION_ENABLED);
            // Phase 6b (P6.21): security events and responses, the suite
            // floor, padding, the knock, the random port, pair seeds, Lock
            // v2, advisories, release bundles and mesh updates, each before
            // its own waiver (OD6b-1).
            assert!(!crate::security_gate::SECURITY_EVENTS_PRODUCTION_ENABLED);
            assert!(!crate::security_gate::SECURITY_RESPONSES_PRODUCTION_ENABLED);
            assert!(!crate::security_gate::SUITE_FLOOR_PRODUCTION_ENABLED);
            assert!(!crate::security_gate::LINK_PADDING_PRODUCTION_ENABLED);
            assert!(!crate::security_gate::LINK_KNOCK_PRODUCTION_ENABLED);
            assert!(!crate::security_gate::LISTEN_PORT_RANDOM_PRODUCTION_ENABLED);
            assert!(!crate::security_gate::PAIR_SEED_PRODUCTION_ENABLED);
            assert!(!crate::security_gate::LOCAL_PROTECTION_PRODUCTION_ENABLED);
            assert!(!crate::security_gate::ADVISORY_PRODUCTION_ENABLED);
            assert!(!crate::security_gate::RELEASE_BUNDLE_PRODUCTION_ENABLED);
            assert!(!crate::security_gate::MESH_UPDATE_PRODUCTION_ENABLED);
        }
    }

    /// Runs in both builds: every switched-on gate is live as a release
    /// build runs it (no `RAVEN_LAB_*` variable needed, the Lab Test A unlock
    /// included), and every held one stays shut, unless this process's
    /// environment says otherwise in a debug build. The release test job
    /// sets every lab switch and reaches the first branch.
    #[test]
    fn switched_on_gates_are_live_without_any_lab_switch() {
        let lab_free = !cfg!(debug_assertions)
            || std::env::vars_os().all(|(k, _)| !k.to_string_lossy().starts_with("RAVEN_LAB_"));
        if !lab_free {
            return;
        }
        assert!(crate::internet_direct_live_enabled());
        assert!(crate::p2p_live_enabled());
        assert!(crate::p2p_gate::friend_relay_live_enabled());
        assert!(crate::p2p_gate::relay_offers_live());
        assert_eq!(
            crate::custody_gate::CustodyGates::current(),
            crate::custody_gate::CustodyGates {
                live: true,
                wan: true
            }
        );
        assert!(crate::horizon::horizon_live_enabled());
        assert!(crate::route_hints::route_hints_live());
        assert!(crate::portmap_gate::port_map_live_enabled());
        assert!(crate::portmap_gate::v6_pinhole_live_enabled());
        assert!(crate::portmap_gate::nat_class_live_enabled());
        assert!(crate::portmap_gate::stun_discovery_live_enabled());
        assert!(crate::portmap_gate::serverless_punch_live_enabled());
        assert!(crate::onion_live_enabled());
        assert!(crate::group::group_live_enabled());
        assert!(crate::app_channel::app_channel_live_enabled());
        assert_eq!(
            crate::nearby_live_enabled(),
            cfg!(target_os = "macos"),
            "Bluetooth nearby: macOS only"
        );
        // Held.
        assert!(!crate::pair_init::live_enabled());
        assert!(!crate::horizon::letter_live_enabled());
        assert!(!crate::custody_gate::handoff_live());
        assert!(!crate::wss_gate::wss_live_enabled());
        assert!(!crate::portmap_gate::peer_rotation_live_enabled());
        assert!(!crate::lan_beacon::lan_beacon_live());
        assert!(!offline_lan_live());
        assert!(!lan_noise_pin_live());
        assert!(!lan_auto_live());
        assert!(!crate::learning::learning_live());
    }

    /// Phase 5 P5.3. Runs in both builds: the release test job sets
    /// `RAVEN_LAB_TEST_A=1`, `RAVEN_LAB_HORIZON=1` and `RAVEN_LAB_LETTER=1`,
    /// and the horizon and receiver dedup stay at their consts (on since
    /// 2026-10) and the letters closed (the variables are never read); a
    /// debug build follows exactly the variables.
    #[test]
    fn horizon_and_letter_lab_switches_are_inert_without_debug_assertions() {
        use crate::horizon::{
            horizon_live_enabled, letter_live_enabled, receiver_dedup_live,
            ASYNC_LETTER_PRODUCTION_ENABLED, LAB_HORIZON, LAB_LETTER,
            LONG_HORIZON_PRODUCTION_ENABLED,
        };
        use crate::pair_init::{lab_switch_value, lab_test_a_enabled};
        use crate::session_reset::{session_reset_live_enabled, SESSION_RESET_PRODUCTION_ENABLED};
        if !cfg!(debug_assertions) {
            // Edition 2021: plain calls. No release test reads these
            // variables.
            std::env::set_var("RAVEN_LAB_TEST_A", "1");
            std::env::set_var(LAB_HORIZON, "1");
            std::env::set_var(LAB_LETTER, "1");
            assert_eq!(horizon_live_enabled(), LONG_HORIZON_PRODUCTION_ENABLED);
            assert_eq!(
                letter_live_enabled(),
                ASYNC_LETTER_PRODUCTION_ENABLED
                    && crate::custody_gate::FRIEND_CUSTODY_PRODUCTION_ENABLED
            );
            assert_eq!(
                receiver_dedup_live(),
                SESSION_RESET_PRODUCTION_ENABLED || LONG_HORIZON_PRODUCTION_ENABLED
            );
            return;
        }
        let switch = |name: &str| {
            lab_switch_value(
                true,
                lab_test_a_enabled(),
                std::env::var(name).ok().as_deref(),
            )
        };
        let horizon = crate::pair_init::lab_gate_value(
            true,
            LONG_HORIZON_PRODUCTION_ENABLED,
            lab_test_a_enabled(),
            std::env::var(LAB_HORIZON).ok().as_deref(),
        );
        assert_eq!(horizon_live_enabled(), horizon);
        assert_eq!(
            letter_live_enabled(),
            horizon
                && crate::custody_gate::CustodyGates::current().live
                && (ASYNC_LETTER_PRODUCTION_ENABLED || switch(LAB_LETTER))
        );
        assert_eq!(
            receiver_dedup_live(),
            session_reset_live_enabled() || horizon
        );
    }

    /// Phase 3 P3.2. Runs in both builds: the release test job sets
    /// `RAVEN_LAB_LAN_AUTO=1` and `--lan-listen auto` stays closed (the
    /// variable is never read); a debug build follows exactly the variable.
    #[test]
    fn lan_auto_lab_switch_is_inert_without_debug_assertions() {
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No other test reads this variable.
            std::env::set_var("RAVEN_LAB_LAN_AUTO", "1");
            assert_eq!(lan_auto_live(), LAN_AUTO_LISTEN_PRODUCTION_ENABLED);
            return;
        }
        let set = std::env::var("RAVEN_LAB_LAN_AUTO").ok();
        assert_eq!(
            lan_auto_live(),
            LAN_AUTO_LISTEN_PRODUCTION_ENABLED || set.as_deref() == Some("1")
        );
    }

    /// Phase 3 P3.8. Runs in both builds: the release test job sets
    /// `RAVEN_LAB_LAN_BEACON=1` and the beacon stays closed (the variable is
    /// never read); a debug build follows exactly the variable.
    #[test]
    fn lan_beacon_lab_switch_is_inert_without_debug_assertions() {
        use crate::lan_beacon::{lan_beacon_live, LAN_BEACON_PRODUCTION_ENABLED};
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No other test reads this variable.
            std::env::set_var("RAVEN_LAB_LAN_BEACON", "1");
            assert_eq!(lan_beacon_live(), LAN_BEACON_PRODUCTION_ENABLED);
            return;
        }
        let set = std::env::var("RAVEN_LAB_LAN_BEACON").ok();
        assert_eq!(
            lan_beacon_live(),
            LAN_BEACON_PRODUCTION_ENABLED || set.as_deref() == Some("1")
        );
    }

    /// Phase 3 P3.13. Runs in both builds: the release test job sets
    /// `RAVEN_LAB_SESSION_RENEWAL=1` and `RAVEN_LAB_SESSION_LIFETIME_MS=60000`,
    /// and renewal stays closed and sessions this node starts last a day (the
    /// variables are never read); a debug build follows exactly the variables.
    #[test]
    fn session_renewal_lab_switch_is_inert_without_debug_assertions() {
        use crate::lan_dispatch::{initiator_session_lifetime_ms, LAN_SESSION_LIFETIME_MS};
        use crate::session_renewal::{
            session_renewal_live_enabled, SESSION_RENEWAL_PRODUCTION_ENABLED,
        };
        if !cfg!(debug_assertions) {
            // Edition 2021: plain calls. No other test reads these variables.
            std::env::set_var("RAVEN_LAB_SESSION_RENEWAL", "1");
            std::env::set_var("RAVEN_LAB_SESSION_LIFETIME_MS", "60000");
            assert_eq!(
                session_renewal_live_enabled(),
                SESSION_RENEWAL_PRODUCTION_ENABLED
            );
            assert_eq!(initiator_session_lifetime_ms(), LAN_SESSION_LIFETIME_MS);
            return;
        }
        let set = std::env::var("RAVEN_LAB_SESSION_RENEWAL").ok();
        assert_eq!(
            session_renewal_live_enabled(),
            SESSION_RENEWAL_PRODUCTION_ENABLED || set.as_deref() == Some("1")
        );
        if std::env::var("RAVEN_LAB_SESSION_LIFETIME_MS").is_err() {
            assert_eq!(initiator_session_lifetime_ms(), LAN_SESSION_LIFETIME_MS);
        }
    }

    /// Phase 3 P3.5. Runs in both builds: the release test job sets
    /// `RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK=1` and loopback stays local (the
    /// variable is never read); a debug build follows exactly the variable.
    #[test]
    fn lan_source_deny_loopback_switch_is_inert_without_debug_assertions() {
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No other test reads this variable.
            std::env::set_var("RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK", "1");
            assert!(!lab_lan_source_deny_loopback());
            return;
        }
        let set = std::env::var("RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK").ok();
        assert_eq!(lab_lan_source_deny_loopback(), set.as_deref() == Some("1"));
    }

    /// `raven lan off` closes the LAN carrier for this process and nothing
    /// else; turning it back on restores the gate as the build sets it.
    #[test]
    fn lan_usable_now_follows_the_user_switch() {
        {
            let _off = lan_user_off_for_test(true);
            assert!(lan_user_off());
            assert!(!lan_usable_now());
            // Only the user's switch: the slice gate itself is untouched.
            assert!(lan_direct_live_enabled());
            set_lan_user_off(false);
            assert!(!lan_user_off());
            assert_eq!(lan_usable_now(), lan_direct_live_enabled());
            set_lan_user_off(true);
        }
        // Dropping the guard cleared the switch.
        let _untouched = lan_user_switch_untouched();
        assert!(!lan_user_off());
        assert_eq!(lan_usable_now(), lan_direct_live_enabled());
    }

    /// Flip-proof: neither the const nor the build decides what is asserted.
    /// The release test job sets each variable to "1" and to "0" and the gate
    /// still equals its const (the switches are inert there); a debug build
    /// follows the variable ("1" opens, "0" closes, anything else is the
    /// const), checked through [`gate_switch`] without touching the process
    /// environment, and the live functions read exactly what is set.
    #[test]
    fn cutoff_gate_switches_are_inert_in_release_and_follow_the_const() {
        let gates = [
            (
                offline_lan_live as fn() -> bool,
                OFFLINE_LAN_PRODUCTION_ENABLED,
                "RAVEN_LAB_OFFLINE",
            ),
            (
                lan_noise_pin_live,
                LAN_NOISE_PIN_PRODUCTION_ENABLED,
                "RAVEN_LAB_NOISE_PIN",
            ),
        ];
        for production in [false, true] {
            for value in [
                None,
                Some(""),
                Some("0"),
                Some("1"),
                Some("true"),
                Some(" 1"),
            ] {
                let read = || value.map(str::to_owned);
                assert_eq!(
                    gate_switch(false, production, read),
                    production,
                    "{value:?}"
                );
                let debug = match value {
                    Some("1") => true,
                    Some("0") => false,
                    _ => production,
                };
                assert_eq!(gate_switch(true, production, read), debug, "{value:?}");
            }
            assert_eq!(
                gate_switch(false, production, || panic!("release read the variable")),
                production
            );
        }
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No other test reads these variables.
            for (live, production, var) in gates {
                for value in ["1", "0"] {
                    std::env::set_var(var, value);
                    assert_eq!(live(), production, "{var}={value}");
                }
            }
            std::env::set_var("RAVEN_LAB_LAN_DEFAULT_PORT", "17420");
            assert_eq!(lab_default_lan_port(), None);
            return;
        }
        for (live, production, var) in gates {
            let debug = match std::env::var(var).ok().as_deref() {
                Some("1") => true,
                Some("0") => false,
                _ => production,
            };
            assert_eq!(live(), debug, "{var}");
        }
        let port = std::env::var("RAVEN_LAB_LAN_DEFAULT_PORT").ok();
        assert_eq!(
            lab_default_lan_port(),
            port.as_deref().and_then(parse_lab_port)
        );
    }

    /// The debug "0" switch closes a gate whose const is true, so the
    /// gate-closed paths stay testable after the flip; an unset variable
    /// leaves the const.
    #[test]
    fn debug_zero_closes_an_open_gate() {
        let unset = "RAVEN_TEST_CUTOFF_GATE_NEVER_SET";
        assert!(std::env::var_os(unset).is_none());
        assert!(gate_live(true, unset));
        assert!(!gate_live(false, unset));
        assert!(!gate_switch(true, true, || Some("0".into())));
        assert!(gate_switch(true, false, || Some("1".into())));
        assert!(gate_switch(false, true, || Some("0".into())));
    }

    #[test]
    fn lab_default_lan_port_parses_a_port_only() {
        for (text, port) in [
            ("1", Some(1)),
            ("7420", Some(7420)),
            (" 17420 ", Some(17420)),
            ("65535", Some(65535)),
            ("0", None),
            ("65536", None),
            ("-1", None),
            ("", None),
            ("127.0.0.1:7420", None),
        ] {
            assert_eq!(parse_lab_port(text), port, "{text:?}");
        }
        let unread = || -> Option<String> { panic!("release read the variable") };
        assert_eq!(
            crate::p2p_gate::lab_value(false, unread, parse_lab_port),
            None
        );
        assert_eq!(
            crate::p2p_gate::lab_value(true, || Some("9".into()), parse_lab_port),
            Some(9)
        );
    }

    /// Runs in both builds: the release test job proves that the route-hints
    /// lab switch is inert there (the variable is set to "1" and to "0" and
    /// the gate stays at its const, on since 2026-10); a debug build follows
    /// exactly the variable ("1" opens, "0" closes, else the const).
    #[test]
    fn route_hints_lab_switch_is_inert_without_debug_assertions() {
        use crate::route_hints::{
            route_hints_live, route_hints_live_on, ROUTE_HINTS_PRODUCTION_ENABLED,
        };
        for value in [None, Some(""), Some("0"), Some("1"), Some("true")] {
            let read = || value.map(str::to_owned);
            assert!(!crate::p2p_gate::lab_flag(false, read), "{value:?}");
            assert_eq!(
                crate::p2p_gate::lab_flag(true, read),
                value == Some("1"),
                "{value:?}"
            );
            assert_eq!(
                gate_switch(false, ROUTE_HINTS_PRODUCTION_ENABLED, read),
                ROUTE_HINTS_PRODUCTION_ENABLED
            );
        }
        if !cfg!(debug_assertions) {
            for value in ["1", "0"] {
                // Edition 2021: a plain call. No other test reads this variable.
                std::env::set_var("RAVEN_LAB_ROUTE_HINTS", value);
                assert_eq!(route_hints_live(), ROUTE_HINTS_PRODUCTION_ENABLED);
                for carrier in [
                    crate::OutboxCarrier::Lan,
                    crate::OutboxCarrier::Internet,
                    crate::OutboxCarrier::P2p,
                ] {
                    assert_eq!(
                        route_hints_live_on(carrier),
                        ROUTE_HINTS_PRODUCTION_ENABLED,
                        "{carrier:?}"
                    );
                }
            }
            std::env::set_var("RAVEN_LAB_ROUTE_HINTS", "1");
            return;
        }
        let set = std::env::var("RAVEN_LAB_ROUTE_HINTS").ok();
        assert_eq!(
            route_hints_live(),
            gate_switch(true, ROUTE_HINTS_PRODUCTION_ENABLED, || set.clone())
        );
    }

    /// Phase 6a P6.2. Runs in both builds: the release test job sets every
    /// learning lab switch to a value that would act in a debug build and
    /// learning stays shut, untuned and sealed as usual (the variables are
    /// never read); a debug build follows exactly the variables.
    #[test]
    fn learning_lab_switches_are_inert_without_debug_assertions() {
        use crate::learning::{
            lab_tune, learning_live, parse_tune, LAB_LEARNING, LAB_LEARNING_SEALER,
            LAB_LEARNING_TUNE, LEARNING_PRODUCTION_ENABLED,
        };
        use crate::p2p_gate::{lab_flag, lab_value};
        let unread = || -> Option<String> { panic!("release read the variable") };
        assert!(!lab_flag(false, unread));
        assert_eq!(lab_value(false, unread, parse_tune), None);
        assert_eq!(lab_value(false, unread, parse_sealer_fault), None);
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("1"),
            Some("1,1,1"),
            Some("unavailable"),
            Some(" unavailable"),
            Some("Unavailable"),
        ] {
            let read = || value.map(str::to_owned);
            assert!(!lab_flag(false, read), "{value:?}");
            assert_eq!(lab_value(false, read, parse_tune), None, "{value:?}");
            assert_eq!(
                lab_value(false, read, parse_sealer_fault),
                None,
                "{value:?}"
            );
            assert_eq!(lab_flag(true, read), value == Some("1"), "{value:?}");
            assert_eq!(
                lab_value(true, read, parse_tune).is_some(),
                value == Some("1,1,1"),
                "{value:?}"
            );
            assert_eq!(
                lab_value(true, read, parse_sealer_fault).is_some(),
                value == Some("unavailable"),
                "{value:?}"
            );
        }
        if !cfg!(debug_assertions) {
            // Edition 2021: plain calls. No other test sets these variables.
            std::env::set_var(LAB_LEARNING, "1");
            std::env::set_var(LAB_LEARNING_TUNE, "1,1,1");
            std::env::set_var(LAB_LEARNING_SEALER, "unavailable");
            assert!(!learning_live());
            assert!(lab_tune().is_none());
            assert!(!lab_sealer_unavailable());
            return;
        }
        let set = |name: &str| std::env::var(name).ok();
        assert_eq!(
            learning_live(),
            LEARNING_PRODUCTION_ENABLED || set(LAB_LEARNING).as_deref() == Some("1")
        );
        assert_eq!(
            lab_tune(),
            set(LAB_LEARNING_TUNE).as_deref().and_then(parse_tune)
        );
        assert_eq!(
            lab_sealer_unavailable(),
            set(LAB_LEARNING_SEALER).as_deref() == Some("unavailable")
        );
    }

    /// Phase 6b P6.21. Runs in both builds: the release test job sets the
    /// Lab Test A unlock, every security lab switch and every thread
    /// override, and each gate stays at its const (no variable or override
    /// is read); a debug build follows exactly the variables (this thread
    /// sets no override) and what each gate sits on.
    #[test]
    fn security_lab_switches_are_inert_without_debug_assertions() {
        use crate::security_gate::{
            live, set_lab_for_this_thread, Requires, SecGate, SECURITY_LAB_SWITCHES,
        };
        if !cfg!(debug_assertions) {
            // Edition 2021: plain calls. No release test reads these
            // variables (RAVEN_LAB_TEST_A is set by the release job too).
            std::env::set_var("RAVEN_LAB_TEST_A", "1");
            for name in SECURITY_LAB_SWITCHES {
                std::env::set_var(name, "1");
            }
            for g in SecGate::ALL {
                set_lab_for_this_thread(g, Some(true));
            }
            for g in SecGate::ALL {
                assert_eq!(live(g), g.production(), "{g:?}");
                assert!(!live(g), "{g:?}");
            }
            for g in SecGate::ALL {
                set_lab_for_this_thread(g, None);
            }
            return;
        }
        fn expect(g: SecGate) -> bool {
            let own = g.production()
                || (crate::pair_init::lab_test_a_enabled()
                    && std::env::var(g.lab_switch()).ok().as_deref() == Some("1"));
            own && match g.requires() {
                Requires::Nothing => true,
                Requires::Gate(below) => expect(below),
                Requires::RouteHints => crate::route_hints::route_hints_live(),
            }
        }
        for g in SecGate::ALL {
            assert_eq!(live(g), expect(g), "{g:?}");
        }
        if std::env::var("RAVEN_LAB_TEST_A").is_err() {
            assert!(SecGate::ALL.iter().all(|g| !live(*g)), "no Lab Test A");
        }
    }

    /// Phase 6b P6.26. Runs in both builds: the release test job sets
    /// `RAVEN_LAB_SEC_PENALTY_LOOPBACK=1` and loopback stays exempt from the
    /// penalty box (the variable is never read); a debug build follows
    /// exactly the variable.
    #[test]
    fn penalty_loopback_switch_is_inert_without_debug_assertions() {
        use crate::security_gate::{lab_penalty_loopback, LAB_SEC_PENALTY_LOOPBACK};
        assert_eq!(LAB_SEC_PENALTY_LOOPBACK, "RAVEN_LAB_SEC_PENALTY_LOOPBACK");
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No release test reads this variable.
            std::env::set_var(LAB_SEC_PENALTY_LOOPBACK, "1");
            assert!(!lab_penalty_loopback());
            return;
        }
        let set = std::env::var(LAB_SEC_PENALTY_LOOPBACK).ok();
        assert_eq!(lab_penalty_loopback(), set.as_deref() == Some("1"));
    }

    /// Privacy pack PP.1. Runs in both builds: the release test job sets
    /// every privacy pack switch to a value that would act in a debug build
    /// and none is read (`lab_switch` is `None`); a debug build reads exactly
    /// what is set (blank is unset).
    #[test]
    fn privacy_lab_switches_are_inert_without_debug_assertions() {
        use crate::p2p_gate::{lab_switch, lab_switch_text, lab_value};
        for value in [
            None,
            Some(""),
            Some("  "),
            Some("0"),
            Some("1"),
            Some("/tmp/x"),
        ] {
            let read = || value.map(str::to_owned);
            assert_eq!(lab_value(false, read, lab_switch_text), None, "{value:?}");
            let debug = value.filter(|v| !v.trim().is_empty()).map(str::to_owned);
            assert_eq!(lab_value(true, read, lab_switch_text), debug, "{value:?}");
        }
        let unread = || -> Option<String> { panic!("release read the variable") };
        assert_eq!(lab_value(false, unread, lab_switch_text), None);
        let mut names = PRIVACY_LAB_SWITCHES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), PRIVACY_LAB_SWITCHES.len());
        assert!(names.iter().all(|n| n.starts_with("RAVEN_LAB_")));
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No other test sets these variables.
            for (name, value) in [
                (LAB_AT_REST, "1"),
                (LAB_ERASE_ROOT, "/tmp/raven-lab-erase-root"),
                (LAB_AT_REST_KEY_FAULT, "unavailable"),
                (LAB_RETENTION_GRACE_MS, "1"),
                (LAB_LOGIN_ITEM_ROOT, "/tmp/raven-lab-login-items"),
                (LAB_LOGIN_ITEM_TOOLS, "/tmp/raven-lab-login-tools"),
            ] {
                std::env::set_var(name, value);
                assert_eq!(lab_switch(name), None, "{name}={value}");
            }
            return;
        }
        for name in PRIVACY_LAB_SWITCHES {
            let set = std::env::var(name).ok();
            assert_eq!(
                lab_switch(name),
                set.filter(|v| !v.trim().is_empty()),
                "{name}"
            );
        }
    }

    /// Privacy pack PP.1 (review R02), the inverse of the usual inert test:
    /// a release build seals without `RAVEN_LAB_AT_REST` and never reads it.
    #[test]
    fn release_seals_without_the_lab_switch() {
        assert!(seal_allowed(false, || panic!("release read the variable")));
        if !cfg!(debug_assertions) {
            assert!(at_rest_seal_allowed());
        }
    }

    /// Privacy pack PP.1 (review R02): a debug build seals only with exactly
    /// `RAVEN_LAB_AT_REST=1`, so a debug binary run against a real profile
    /// by mistake seals nothing.
    #[test]
    fn debug_without_switch_never_seals() {
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some(" 1"),
            Some("yes"),
        ] {
            assert!(
                !seal_allowed(true, || value.map(str::to_owned)),
                "{value:?}"
            );
        }
        assert!(seal_allowed(true, || Some("1".into())));
        if cfg!(debug_assertions) {
            let set = std::env::var(LAB_AT_REST).ok();
            assert_eq!(at_rest_seal_allowed(), set.as_deref() == Some("1"));
        }
    }

    #[test]
    fn lan_gate_const_is_independent() {
        const {
            assert!(LAN_DIRECT_PRODUCTION_ENABLED);
        }
        assert!(lan_direct_live_enabled());
    }

    #[test]
    fn lan_gate_does_not_open_generic_live_enabled() {
        if crate::pair_init::lab_test_a_enabled() {
            return;
        }
        assert!(!crate::pair_init::live_enabled());
        assert!(!crate::indexed_session_store::live_enabled());
        assert!(!crate::prekey_lifecycle::live_enabled());
        assert!(!crate::atsam_indexed_session::live_enabled());
    }
}
