//! RAVEN protocol core (`rvn1`).
//!
//! Wire formats match `protocol/` + `shared-vectors/rvn1/`.
//! Content sealing: authenticated ChaCha20-Poly1305 interim path with clear hooks for
//! full ATSAM hybrid+ratchet (see `protocol/ATSAM_PRIMITIVE_MAPPING_V1.md`).

pub mod ack;
pub mod address;
pub mod advisory;
pub mod agent_sign;
pub mod alias_record;
pub mod app_channel;
pub mod app_store;
pub mod arrivals;
pub mod async_letter;
pub mod at_rest;
pub mod atsam_aead;
pub mod atsam_indexed_session;
pub mod atsam_kdf;
pub mod atsam_mlkem;
pub mod atsam_root;
pub mod bech32m;
pub mod ble_adapter;
pub mod bootstrap;
pub mod bridge;
pub mod canon;
pub mod capability_floor;
pub mod carrier_admission;
pub mod chat_history;
pub mod clock;
pub mod clock_skew;
pub mod contact_book;
pub mod contact_request;
pub mod custody_client;
pub mod custody_gate;
pub mod custody_handoff;
pub mod custody_home;
pub mod device_cert;
pub mod device_revocation;
pub mod device_revocation_conformance;
pub mod device_sync;
pub mod discovery;
pub mod discovery_resolver;
pub mod disk_space;
pub mod envelope;
pub mod erase;
pub mod fingerprint;
pub mod forward_queue;
pub mod friend_custody;
#[cfg(feature = "full-braid-durable-lab")]
pub mod full_braid_durable_lab;
pub mod gateway;
pub mod group;
pub mod horizon;
#[cfg(feature = "full-braid-lab")]
pub mod hybrid_ratchet_v2;
#[cfg(feature = "full-braid-lab")]
pub mod hybrid_ratchet_v2_full_braid;
#[cfg(feature = "full-braid-lab")]
pub mod hybrid_ratchet_v2_state;
#[cfg(feature = "full-braid-lab")]
pub mod hybrid_ratchet_v2_tr;
pub mod identity;
pub mod identity_store;
pub mod indexed_session_store;
pub mod internet;
pub mod internet_gate;
pub mod introduction;
pub mod ipc;
pub mod keystore_select;
pub mod keystore_vault;
pub mod lab_audit;
pub mod lan_beacon;
pub mod lan_dispatch;
pub mod lan_gate;
pub mod lan_meeting;
pub mod lan_noise;
pub mod lan_noise_pin;
pub mod lan_rlb1;
pub mod lan_seen;
pub mod lan_vectors;
pub mod learned_routes;
pub mod learning;
pub mod letter_deposits;
pub mod link_knock;
pub mod link_padding;
pub mod local_lock;
pub mod local_time;
pub mod macos_keychain;
pub mod message_router;
pub mod messaging_path;
#[cfg(feature = "mlkem768-incremental-lab")]
pub mod mlkem768_incremental;
pub mod nearby;
pub mod nearby_gate;
pub mod nearby_link;
pub mod net_proxy;
pub mod netifs;
pub mod node_policy;
pub mod onion;
pub mod onion_gate;
pub mod outbox;
pub mod owed_acks;
pub mod p2p_gate;
pub mod p2p_route;
pub mod pair_init;
pub mod pair_init_lan_oob;
pub mod pair_seed;
pub mod paths;
pub mod peer_rotation;
pub mod portmap;
/// The test gateway for port mapping: raven-core's own tests and the
/// `test-helpers` feature only, never a release build.
#[cfg(any(test, feature = "test-helpers"))]
#[doc(hidden)]
pub mod portmap_fake;
pub mod portmap_gate;
pub mod prekey_bundle;
pub mod prekey_lifecycle;
pub mod privacy;
pub mod profile_record;
pub mod punch;
pub mod queue;
pub mod raven_passphrase;
pub mod reach;
pub mod reach_diag;
pub mod records;
pub mod relay_allow;
pub mod relay_select;
pub mod relayed_ingest;
pub mod release_bundle;
pub mod release_keys;
pub mod release_sign;
pub mod route_hints;
pub mod route_memory;
pub mod routing_tag;
pub mod sanitize;
pub mod seal;
pub mod security_events;
pub mod security_gate;
pub mod security_ledger;
pub mod security_sense;
pub mod security_words;
pub mod session_renewal;
pub mod session_reset;
pub mod sqlite_rebuild;
pub mod store_object;
pub mod stun;
pub mod suite_policy;
pub mod suite_registry;
pub mod tlog;
pub mod transport;
pub mod update_downloads;
pub mod update_exchange;
pub mod update_state;
pub mod vectors;
/// Owner-only DACLs behind the private file helpers in [`paths`] (Windows).
#[cfg(windows)]
mod win_acl;
pub mod ws_frame;
pub mod wss_gate;

pub use address::{decode_address, encode_address, from_display, to_display};
pub use alias_record::{normalize_alias, AliasClaimStore, AliasPublishQuota, AliasRecord};
pub use atsam_aead::{build_aad_v1, build_aad_v2, seal_rvna1_v2, unseal_rvna1_v2};
pub use atsam_mlkem::{
    begin_hybrid_initiation, respond_hybrid_root, HybridKeypair, PendingHybridInitiation,
};
pub use atsam_root::{derive_root, transcript_hash, x25519_shared_checked};
pub use ble_adapter::{
    ble_frame_decode, ble_frame_encode, select_ble_adapter, select_ble_adapter_from_env,
    validate_opaque_rvn1, BleAdapterKind,
};
pub use bootstrap::{
    bootstrap_path, load_bootstrap, save_bootstrap, BootstrapConfig, BootstrapError,
};
pub use bridge::{
    authenticated_object_digest, classify_multi_role, decide as bridge_decide, prepare_forward,
    split_replication, BridgeAction, BridgeRole, DropReason, EnvelopeIdentity,
    MultiRoleDisposition,
};
pub use chat_history::{
    blocked_path, clear_staged_outbound_body, history_path, list_staged_outbound_bodies,
    load_staged_outbound_body, outbound_body_stage_path, stage_outbound_body, BlockList,
    ChatHistory, ChatHistoryEntry, ChatHistoryError, OutboundStageSendGuard, StagedOutboundBody,
};
pub use contact_request::{
    ContactAcceptOutcome, ContactAcceptV1, ContactBinding, ContactRequestInbox,
    ContactRequestInner, PendingContactRequest, RavenContactRequestV1,
};
pub use device_cert::{
    device_registry_path, ensure_local_device_certificate, load_device_registry,
    load_device_registry_checked, save_device_registry, with_device_registry_lock,
    DeviceCertificate, DeviceRegistry, DEVICE_REGISTRY_LOCK,
};
pub use device_sync::{
    derive_device_sync_key, import_contact_sync, partition_lag_allows_stale_auth,
    revocation_store_path, seal_contact_sync, unseal_contact_sync, ContactSyncPlaintext,
    RevocationRecord, RevocationStore, SyncContact,
};
pub use discovery::{alias_hint_key, DiscoveryStore, PeerRecord, NAT_STATUS};
pub use discovery_resolver::{
    result_model_schema_keys, DiscoveryContext, DiscoveryResolver, DiscoveryResult, DiscoveryScope,
    DiscoverySource, LocalContactRow, VerificationState,
};
pub use envelope::{EnvType, Envelope};
pub use forward_queue::{
    ForwardItem, ForwardQueue, ForwardState, PeerRateDecision, MAX_FORWARD_QUEUE,
    MAX_PER_PEER_ENQUEUES_PER_WINDOW, MAX_PER_PEER_PENDING,
};
pub use identity::Identity;
pub use identity_store::{
    backend_consistency, identity_usable, load_identity, load_identity_required,
    load_or_create_identity, load_or_create_profile_identity, store_status,
    IdentityBackendConsistency, IdentityStoreBackend, IdentityStoreError, IdentityStoreStatus,
    IdentityUsable, BACKEND_MARKER_NAME, SEED_FILE_NAME,
};
pub use indexed_session_store::{
    endpoint_device_hint, AuthorizedEndpointDevice, EndpointAcceptance, EndpointAckAcceptance,
    EndpointAckIntent, EndpointAckIntentState, EndpointDeliveryState, EndpointInboxListing,
    EndpointInboxRow, EndpointOutbound, EndpointOutboundKind, EndpointOutboxState, InboxOrder,
    InboxPosition, IndexedSessionBinding, IndexedSessionRecordKey, IndexedSessionStore,
    IndexedSessionStoreError, LocalRole, RatchetLane, SessionLifecycle,
    INDEXED_SESSION_METADATA_FILE, INDEXED_SESSION_STORE_PRODUCTION_ENABLED,
    MAX_ENDPOINT_ENVELOPE_LIFETIME_MS, MAX_ENDPOINT_FUTURE_SKEW_MS, MAX_ENDPOINT_TEXT_BYTES,
    MAX_FORWARD_JUMP, MAX_SKIPPED_KEYS,
};
pub use internet::{
    bits_to_caps, caps_to_bits, deframe_prefix, frame, opaque_store_tag, pack_hello,
    unpack_verify_hello, CAP_BLE, CAP_BRIDGE, CAP_INTERNET, CAP_LINK_PAD1, CAP_LINK_RRH1,
    CAP_LINK_RUP1, CAP_RELAY, CAP_STORE, HELLO_WIRE_LEN, INTERNET_PROTO_ID, MAX_FRAME_BYTES,
};
pub use internet_gate::{internet_direct_live_enabled, INTERNET_DIRECT_PRODUCTION_ENABLED};
pub use introduction::{IntroductionInbox, RavenIntroductionV1};
pub use ipc::{
    decode_request, decode_response, default_ipc_endpoint, default_pipe_name, default_socket_path,
    encode_request, encode_response, ipc_endpoint, IpcEndpoint, IpcRequest, IpcResponse,
    IPC_VERSION, MAX_IPC_FRAME, WINDOWS_NAMED_PIPE,
};
pub use lan_beacon::lan_beacon_live;
pub use lan_dispatch::{
    cache_peer_bundle, create_initiator_pair_init, dispatch_frame, encode_local_offer,
    ensure_local_prekey, ensure_outbound_queued_history,
    ensure_outbound_queued_history_under_send_guard, find_confirmed_peer_session, lan_peer_blocked,
    load_cached_peer_bundle, local_bundle, local_published_bundle_by_hash,
    maintain_lan_durable_state, mark_lan_chat_history_delivery, parse_peer_offer, peer_is_trusted,
    persist_lan_chat_history, persist_trusted_peer_bundle, publish_local_prekey_bundle_checked,
    publish_prekey_bundle_checked, reconcile_outbound_stage_history,
    refuse_if_session_lineage_revoked, remember_ephemeral_peer, rlb1_matches_noise_identity,
    seal_app_payload_under_session, with_prekey_store_lock, wrap_pair_init, ATSAM_LINEAGE_REVOKED,
    ATSAM_SESSION_REQUIRED,
};
pub use lan_gate::{
    lan_auto_live, lan_direct_live_enabled, lan_noise_pin_live, lan_usable_now, lan_user_off,
    offline_lan_live, set_lan_user_off, LAN_DIRECT_PRODUCTION_ENABLED, LAN_OFF, LAN_VERIFIED_ONLY,
};
pub use lan_rlb1::{
    decode_offer as decode_rlb1_offer, encode_offer as encode_rlb1_offer, LanBundle,
};
pub use message_router::{InboundEnvelope, MessageRouter, RouterOutcome};
pub use messaging_path::{
    assert_no_silent_fastapi, path_from_raven_envelope_flag, resolve_terminal_messaging_path,
    MessagingPath, ENV_FORCE_LEGACY_LABEL, ENV_SERVERLESS_RVN1,
};
pub use nearby_gate::{
    nearby_live_enabled, nearby_only, NEARBY_HOLD, NEARBY_ONLY_NOTE, NEARBY_PRODUCTION_ENABLED,
};
pub use node_policy::{load_policy, policy_path, save_policy, BridgeStatusSnapshot, NodePolicy};
pub use onion_gate::{onion_live_enabled, ONION_HOLD, ONION_PRODUCTION_ENABLED};
pub use outbox::{
    carrier_allowed_for_contact, contact_is_pinned, envelope_expires_at, DeliveryPath,
    OutboxCarrier, OutboxRoute, PeerSendLock, CONTACT_NOT_VERIFIED, ENVELOPE_VALIDITY_MS,
};
pub use p2p_gate::{
    friend_relay_live_enabled, lab_friend_relay_listen, lab_relay_select, p2p_live_enabled,
    p2p_local_candidates_enabled, p2p_profile_relay_test_enabled, p2p_relay_only_test_enabled,
    relay_offers_live, FRIEND_RELAY_HOLD, FRIEND_RELAY_PRODUCTION_ENABLED, P2P_HOLD,
    P2P_PRODUCTION_ENABLED,
};
pub use pair_init::{
    confirmation_tag, decode_init, decode_response as decode_pair_response,
    derive_provisional_root, device_certificate_hash, encode_init,
    encode_response as encode_pair_response, init_hash, init_signing_bytes, lab_test_a_enabled,
    live_enabled as pair_init_live_enabled, prekey_bundle_hash, response_signing_bytes, session_id,
    transcript_hash as pair_transcript_hash, verify_init, verify_response, PairInit, PairInitError,
    PairInitTrust, PairResponse, INIT_WIRE_LEN, PRODUCTION_ENABLED as PAIR_INIT_PRODUCTION_ENABLED,
    RESPONSE_WIRE_LEN,
};
pub use pair_init_lan_oob::{
    classify_message_ciphertext, classify_packed_envelope, wrap_oob_wire, PairInitOobClassify,
    PairInitOobKind, FLAG_PAIR_INIT_OOB,
};
pub use paths::{
    atomic_write_private, default_raven_data_dir, resolve_raven_data_dir, DataDirLock,
    DEFAULT_BLE_LISTEN, DEFAULT_LAN_LISTEN, LAN_LISTEN_AUTO, PRIMARY_DEVICE_ID,
};
pub use portmap_gate::{
    nat_class_live_enabled, peer_rotation_live_enabled, port_map_live_enabled,
    serverless_punch_live_enabled, stun_discovery_live_enabled, v6_pinhole_live_enabled,
    NAT_CLASS_HOLD, NAT_CLASS_PRODUCTION_ENABLED, PEER_ROTATION_HOLD,
    PEER_ROTATION_PRODUCTION_ENABLED, PORT_MAP_HOLD, PORT_MAP_PRODUCTION_ENABLED,
    SERVERLESS_PUNCH_HOLD, SERVERLESS_PUNCH_PRODUCTION_ENABLED, STUN_DISCOVERY_HOLD,
    STUN_DISCOVERY_PRODUCTION_ENABLED, V6_PINHOLE_HOLD, V6_PINHOLE_PRODUCTION_ENABLED,
};
pub use prekey_bundle::{PrekeyBundle, PrekeyBundleJson, PrekeyStore, MLKEM768_EK_LEN};
pub use prekey_lifecycle::{
    CompleteClaimOutcome, OneTimePrekeyPrivate, PrekeyClaim, PrekeyClaimOutcome,
    PrekeyGenerationPrivate, PrekeyLifecycleActor, PrekeyLifecycleError, PrekeyLifecycleStatus,
    PrekeyPruneOutcome, MAX_ACCEPTED_PREKEY_CLAIMS, MAX_BUNDLES_PER_GENERATION,
    MAX_PAIR_INIT_LIFETIME_MS, MAX_PREKEY_BUNDLE_LIFETIME_MS, MAX_PREKEY_FUTURE_SKEW_MS,
    MAX_PREKEY_GENERATIONS, MAX_PROTECTED_PREKEY_STATE_BYTES, PREKEY_LIFECYCLE_LOCK_FILE,
    PREKEY_LIFECYCLE_PRODUCTION_ENABLED, PREKEY_RETENTION_GRACE_MS, PREKEY_ROOT_HANDOFF_TIMEOUT_MS,
};
pub use profile_record::{ProfileStore, RavenProfileRecordV1};
pub use queue::{DeliveryState, OutgoingQueue, QueueItem};
pub use sanitize::{had_dangerous_controls, sanitize_terminal_text, strip_ansi, strip_bidi};
pub use seal::{
    classify_sealed_body, derive_pairwise_key, parse_rvna1_header, rvna1_wire_plausible,
    seal_message, unseal_message, Rvna1Header, SealClass, ATSAM_PROTO_V1, ATSAM_PROTO_V2,
    SEAL_MAGIC_RVNA1, SEAL_MAGIC_RVNA1_STUB, STUB_PROTO,
};
pub use store_object::{
    mailbox_tag, mailbox_tags_with_overlap, store_tag_from_mailbox, StoreMailbox, StoreObject,
};
pub use transport::{
    plan_paths, prefer_transport, select_path, NodeCapability, PathChoice, PathContext,
    TransportKind, TransportPreference,
};
pub use wss_gate::{
    wss_live_enabled, wss_proxy_live_enabled, WSS_HOLD, WSS_PRODUCTION_ENABLED, WSS_PROXY_HOLD,
    WSS_PROXY_PRODUCTION_ENABLED,
};
