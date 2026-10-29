//! Proxy sources for relay dials over WSS (`protocol/RAVEN_WSS_TRANSPORT_V1.md`
//! §8): which HTTPS proxy, if any, a WSS dial goes through. The WSS transport
//! asks through [`ProxyLookup`]; the p2p host asks [`ProxySource::applies`]
//! to order dial forms and to keep a name unresolved for the proxy.
//!
//! - **Rules:** [`net_proxy::effective`] (pure, raven-core): the explicit
//!   setting, then the environment (`HTTPS_PROXY`, an `http://` `ALL_PROXY`,
//!   with `NO_PROXY`), then the system settings ([`system_proxy`]).
//!   `HTTP_PROXY` is never read.
//! - **System settings:** macOS: the dynamic store's proxies
//!   (SCDynamicStoreCopyProxies: `HTTPSEnable`, `HTTPSProxy`, `HTTPSPort`,
//!   `ExceptionsList`, `ExcludeSimpleHostnames`); PAC or auto-discovery
//!   without an HTTPS proxy is `unsupported: pac`. Windows: WinHTTP's IE
//!   configuration of the current user (the logon task runs as the user, so
//!   these are the user's settings), each string freed with GlobalFree.
//!   Linux and the rest: none; a service names its proxy with
//!   `--p2p-proxy`, `Environment=` or `~/.config/environment.d`.
//! - **Cache:** a decision is kept [`CACHE_TTL`]; [`ProxySource::invalidate`]
//!   drops it. Every p2p endpoint generation does, so a re-home after a
//!   network change reads the settings again.
//! - **Gate:** while [`raven_core::wss_proxy_live_enabled`] is false,
//!   [`ProxyLookup::proxy_for`] and [`ProxySource::applies`] answer "direct"
//!   without reading anything. [`ProxySource::status_word`] then says `held`
//!   when a source names a proxy.
//! - **Privacy:** nothing is stored or logged. The status word names a
//!   source or a kind, never a host or a credential; a credential lives only
//!   in memory ([`net_proxy::ProxyUrl`]).

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use raven_core::net_proxy::{self, Effective, ProxySetting, ProxyUrl, Source, SystemProxy};
use raven_swarm::wss::{Host, ProxyEndpoint, ProxyLookup};

/// How long a decision ([`ProxySource::effective`]) is kept before the
/// environment and the system settings are read again.
pub(crate) const CACHE_TTL: Duration = Duration::from_secs(30);

type EnvReader = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;
type SystemReader = Box<dyn Fn() -> SystemProxy + Send + Sync>;

/// The proxy of the WSS dials of one p2p host: its explicit setting
/// (`--p2p-proxy`, `RAVEN_P2P_PROXY`, node policy `p2p_proxy`; `auto` reads
/// the environment and the system) and the last decision, kept
/// [`CACHE_TTL`].
pub(crate) struct ProxySource {
    explicit: Mutex<ProxySetting>,
    cache: Mutex<Option<(Instant, Effective)>>,
    env: EnvReader,
    system: SystemReader,
    /// The proxy gate ([`raven_core::wss_proxy_live_enabled`]; a test may
    /// open it, [`Self::with_gate`]).
    gate: fn() -> bool,
}

impl ProxySource {
    /// Reads this process's environment and this computer's settings
    /// ([`system_proxy`]).
    pub(crate) fn new(explicit: ProxySetting) -> Self {
        Self::with_readers(explicit, |name| std::env::var(name).ok(), system_proxy)
    }

    /// The same with other readers (tests).
    pub(crate) fn with_readers(
        explicit: ProxySetting,
        env: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
        system: impl Fn() -> SystemProxy + Send + Sync + 'static,
    ) -> Self {
        Self {
            explicit: Mutex::new(explicit),
            cache: Mutex::new(None),
            env: Box::new(env),
            system: Box::new(system),
            gate: raven_core::wss_proxy_live_enabled,
        }
    }

    /// The same behind another gate (tests: the p2p host's proxied paths
    /// whatever this build's gate says).
    #[cfg(test)]
    pub(crate) fn with_gate(self, gate: fn() -> bool) -> Self {
        Self { gate, ..self }
    }

    /// Drop the kept decision: the next question reads the sources again.
    pub(crate) fn invalidate(&self) {
        *lock(&self.cache) = None;
    }

    /// Take another explicit setting (node policy's, once its sealed sidecar
    /// opens) and drop the kept decision.
    pub(crate) fn set_explicit(&self, explicit: ProxySetting) {
        *lock(&self.explicit) = explicit;
        self.invalidate();
    }

    /// The decision ([`net_proxy::effective`]), read again once the kept one
    /// is [`CACHE_TTL`] old. Reads even while the proxy gate is closed.
    // `raven node proxy` (P4.16) shows it; tests until then.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective(&self) -> Effective {
        self.effective_at(Instant::now())
    }

    fn effective_at(&self, now: Instant) -> Effective {
        let mut cache = lock(&self.cache);
        if let Some((at, kept)) = cache.as_ref() {
            if now.saturating_duration_since(*at) < CACHE_TTL {
                return kept.clone();
            }
        }
        let explicit = lock(&self.explicit).clone();
        let fresh = net_proxy::effective(&explicit, |name| (self.env)(name), || (self.system)());
        *cache = Some((now, fresh.clone()));
        fresh
    }

    /// The proxy of a WSS dial to `host` at `port`: none while the gate
    /// (`live`) is closed, without reading anything; otherwise the
    /// decision's, unless the host bypasses it.
    fn proxy_url_for(&self, live: bool, host: &Host, port: u16, now: Instant) -> Option<ProxyUrl> {
        if !live {
            return None;
        }
        self.effective_at(now)
            .proxy_for(&host_text(host), port)
            .cloned()
    }

    /// Whether a WSS dial to `host` at `port` goes through the proxy: the
    /// p2p host then orders the proxied form first and leaves a `/dns*` name
    /// for the proxy to resolve (RWS1 §7). False while the proxy gate is
    /// closed.
    pub(crate) fn applies(&self, host: &Host, port: u16) -> bool {
        let live = (self.gate)();
        self.proxy_url_for(live, host, port, Instant::now())
            .is_some()
    }

    /// The proxy word of the p2p status (IPC `P2pStatusInfo.proxy`), fixed
    /// words only:
    /// - `held`: the proxy gate is closed and a source names a proxy (usable
    ///   or not); WSS dials go direct;
    /// - `setting`, `env` or `system`: where the proxy WSS dials use comes
    ///   from;
    /// - `unsupported: <kind>`: the deciding source names a proxy Raven
    ///   cannot use (`https`, `socks`, `pac` or `invalid`); dials go direct;
    /// - empty: no proxy (none named, or `off`).
    pub(crate) fn status_word(&self) -> String {
        self.status_word_at((self.gate)(), Instant::now())
    }

    fn status_word_at(&self, live: bool, now: Instant) -> String {
        let decided = self.effective_at(now);
        let named = decided.proxy.is_some() || decided.unsupported.is_some();
        if !live {
            return if named { "held".into() } else { String::new() };
        }
        if let Some(kind) = &decided.unsupported {
            return format!("unsupported: {kind}");
        }
        if decided.proxy.is_none() {
            return String::new();
        }
        match decided.source {
            Source::Setting => "setting",
            Source::Env => "env",
            Source::System => "system",
            Source::None => "",
        }
        .into()
    }
}

impl ProxyLookup for ProxySource {
    /// None while [`raven_core::wss_proxy_live_enabled`] is false.
    fn proxy_for(&self, host: &Host, port: u16) -> Option<ProxyEndpoint> {
        let live = (self.gate)();
        self.proxy_url_for(live, host, port, Instant::now())
            .as_ref()
            .map(ProxyEndpoint::from)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Where an explicit setting from node_policy.json says it came from.
pub(crate) const POLICY_SOURCE: &str = "node_policy.json";

/// The explicit setting `text` of `source` (RWS1 §8.2, source 1):
/// [`net_proxy::parse_setting`]. `RAVEN_P2P_PROXY` may carry a user name
/// and password, and `--p2p-proxy` still takes them (with
/// [`ARGV_CREDENTIALS_NOTE`]); node_policy.json ([`POLICY_SOURCE`]) never
/// does (it holds no secrets, §8.1). An error names the source and the
/// rule, never the text.
pub(crate) fn parse_explicit(text: &str, source: &str) -> Result<ProxySetting, String> {
    if source == POLICY_SOURCE && net_proxy::has_credentials(text) {
        return Err(format!(
            "{source}: the proxy setting carries a user name or password, which \
             node_policy.json never holds: give them only in RAVEN_P2P_PROXY (the service's \
             environment)"
        ));
    }
    net_proxy::parse_setting(text).map_err(|e| format!("{source}: {e}"))
}

/// Printed once at start when `--p2p-proxy` carries a user name or password
/// (review B-7): a process's arguments are readable by every local account
/// (`ps`, `/proc/<pid>/cmdline`), its environment only by its own user.
/// Never repeats the setting.
pub(crate) const ARGV_CREDENTIALS_NOTE: &str =
    "raven-node p2p: --p2p-proxy carries a user name or password, which other local users can \
     read in the process list: give them only in RAVEN_P2P_PROXY (the service's environment)";

/// [`ARGV_CREDENTIALS_NOTE`] for the explicit setting `text` of `source`,
/// when it is `--p2p-proxy` with a user name or password.
pub(crate) fn argv_credentials_note(text: &str, source: &str) -> Option<&'static str> {
    (source == "--p2p-proxy" && net_proxy::has_credentials(text)).then_some(ARGV_CREDENTIALS_NOTE)
}

/// A dial's host as the bypass list reads it: a name, or an IP address
/// (IPv6 without brackets).
fn host_text(host: &Host) -> String {
    match host {
        Host::Ip(ip) => ip.to_string(),
        Host::Name(name) => name.clone(),
    }
}

/// This computer's proxy settings (macOS and Windows; none elsewhere).
#[cfg(target_os = "macos")]
fn system_proxy() -> SystemProxy {
    macos::read()
}

/// This computer's proxy settings (macOS and Windows; none elsewhere).
#[cfg(windows)]
fn system_proxy() -> SystemProxy {
    windows::read()
}

/// This computer's proxy settings: none on Linux and the rest (the
/// environment only).
#[cfg(not(any(target_os = "macos", windows)))]
fn system_proxy() -> SystemProxy {
    SystemProxy::default()
}

/// WinHTTP's IE configuration of the user as [`SystemProxy`]: the
/// `https=` entry of `lpszProxy`, else its bare one
/// ([`net_proxy::parse_windows_proxy`], with its own port);
/// `lpszProxyBypass` as the bypass list; an auto-config URL as PAC/WPAD.
/// `fAutoDetect` alone ("Automatically detect settings") is not counted
/// (review B-2): Windows turns it on by default, and with no manual proxy
/// and no script URL dials go direct and work, so it must not make the
/// status say `unsupported: pac` (or `held`) and send the user to a proxy.
#[cfg_attr(not(windows), allow(dead_code))]
fn from_windows(
    _auto_detect: bool,
    auto_config_url: Option<&str>,
    proxy: Option<&str>,
    bypass: Option<&str>,
) -> SystemProxy {
    let entry = proxy.and_then(net_proxy::parse_windows_proxy);
    SystemProxy {
        https_enabled: entry.is_some(),
        host: entry.unwrap_or_default(),
        port: 0,
        exceptions: bypass.map(str::to_owned).into_iter().collect(),
        exclude_simple: false,
        pac_or_wpad: auto_config_url.is_some_and(|url| !url.trim().is_empty()),
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use raven_core::net_proxy::SystemProxy;
    use system_configuration::core_foundation::array::CFArray;
    use system_configuration::core_foundation::base::{CFType, TCFType};
    use system_configuration::core_foundation::boolean::CFBoolean;
    use system_configuration::core_foundation::dictionary::CFDictionary;
    use system_configuration::core_foundation::number::CFNumber;
    use system_configuration::core_foundation::string::CFString;
    use system_configuration::dynamic_store::SCDynamicStoreBuilder;

    /// The proxies of the current network services
    /// (SCDynamicStoreCopyProxies). No store or no settings: none.
    pub(super) fn read() -> SystemProxy {
        let Some(store) = SCDynamicStoreBuilder::new("raven-node").build() else {
            return SystemProxy::default();
        };
        store
            .get_proxies()
            .map_or_else(SystemProxy::default, |proxies| from_dict(&proxies))
    }

    /// The keys a WSS dial needs; a missing or mistyped value counts as
    /// unset.
    pub(super) fn from_dict(proxies: &CFDictionary<CFString, CFType>) -> SystemProxy {
        let value = |key: &'static str| {
            proxies
                .find(CFString::from_static_string(key))
                .map(|v| v.clone())
        };
        let number = |key| value(key).and_then(|v| v.downcast::<CFNumber>()?.to_i64());
        let flag = |key| {
            value(key).is_some_and(|v| match v.downcast::<CFBoolean>() {
                Some(b) => bool::from(b),
                None => v
                    .downcast::<CFNumber>()
                    .and_then(|n| n.to_i64())
                    .is_some_and(|n| n != 0),
            })
        };
        let exceptions = value("ExceptionsList")
            .and_then(|v| v.downcast::<CFArray>())
            .map(|list| {
                list.iter()
                    .filter_map(|item| {
                        // SAFETY: a property list's array holds CF objects;
                        // the get rule retains this one while it is read.
                        let item = unsafe { CFType::wrap_under_get_rule(*item) };
                        item.downcast::<CFString>().map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        SystemProxy {
            https_enabled: flag("HTTPSEnable"),
            host: value("HTTPSProxy")
                .and_then(|v| v.downcast::<CFString>())
                .map(|s| s.to_string())
                .unwrap_or_default(),
            port: number("HTTPSPort")
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(0),
            exceptions,
            exclude_simple: flag("ExcludeSimpleHostnames"),
            pac_or_wpad: flag("ProxyAutoConfigEnable") || flag("ProxyAutoDiscoveryEnable"),
        }
    }
}

#[cfg(windows)]
mod windows {
    use raven_core::net_proxy::SystemProxy;
    use windows_sys::core::PWSTR;
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::Networking::WinHttp::{
        WinHttpGetIEProxyConfigForCurrentUser, WINHTTP_CURRENT_USER_IE_PROXY_CONFIG,
    };

    /// The current user's IE proxy settings (WinHttpGetIEProxyConfigForCurrentUser).
    /// A failed read: none.
    pub(super) fn read() -> SystemProxy {
        let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG {
            fAutoDetect: 0,
            lpszAutoConfigUrl: std::ptr::null_mut(),
            lpszProxy: std::ptr::null_mut(),
            lpszProxyBypass: std::ptr::null_mut(),
        };
        // SAFETY: `config` is a valid, writable structure; WinHTTP fills it
        // and leaves the null pointers of the strings it does not set.
        let ok = unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut config) } != 0;
        // SAFETY: each pointer is null or a string WinHTTP allocated for this
        // call, taken (and freed) once, whatever the result.
        let (auto_config_url, proxy, bypass) = unsafe {
            (
                take(config.lpszAutoConfigUrl),
                take(config.lpszProxy),
                take(config.lpszProxyBypass),
            )
        };
        if !ok {
            return SystemProxy::default();
        }
        super::from_windows(
            config.fAutoDetect != 0,
            auto_config_url.as_deref(),
            proxy.as_deref(),
            bypass.as_deref(),
        )
    }

    /// The text of a string WinHTTP returned, which is then freed
    /// (GlobalFree). Null: none.
    ///
    /// # Safety
    /// `p` is null or a NUL-terminated UTF-16 string allocated with
    /// GlobalAlloc, not used after this call.
    pub(super) unsafe fn take(p: PWSTR) -> Option<String> {
        if p.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
        GlobalFree(p.cast());
        Some(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// The readers' state: the environment and the system settings the
    /// source sees, and how often it read the system.
    #[derive(Clone, Default)]
    struct Readers {
        env: Arc<Mutex<HashMap<String, String>>>,
        system: Arc<Mutex<SystemProxy>>,
        system_reads: Arc<AtomicUsize>,
        env_reads: Arc<AtomicUsize>,
    }

    impl Readers {
        fn source(&self, explicit: ProxySetting) -> ProxySource {
            let (env, env_reads) = (self.env.clone(), self.env_reads.clone());
            let (system, system_reads) = (self.system.clone(), self.system_reads.clone());
            ProxySource::with_readers(
                explicit,
                move |name| {
                    env_reads.fetch_add(1, Ordering::SeqCst);
                    lock(&env).get(name).cloned()
                },
                move || {
                    system_reads.fetch_add(1, Ordering::SeqCst);
                    lock(&system).clone()
                },
            )
        }

        fn set_env(&self, name: &str, value: &str) {
            lock(&self.env).insert(name.into(), value.into());
        }

        fn set_system(&self, system: SystemProxy) {
            *lock(&self.system) = system;
        }

        fn system_reads(&self) -> usize {
            self.system_reads.load(Ordering::SeqCst)
        }

        fn env_reads(&self) -> usize {
            self.env_reads.load(Ordering::SeqCst)
        }
    }

    fn name(host: &str) -> Host {
        Host::Name(host.into())
    }

    fn ip(text: &str) -> Host {
        Host::Ip(text.parse::<IpAddr>().unwrap())
    }

    fn setting(text: &str) -> ProxySetting {
        net_proxy::parse_setting(text).unwrap()
    }

    fn system_https(host: &str, port: u16, exceptions: &[&str]) -> SystemProxy {
        SystemProxy {
            https_enabled: true,
            host: host.into(),
            port,
            exceptions: exceptions.iter().map(|e| (*e).to_owned()).collect(),
            ..SystemProxy::default()
        }
    }

    /// The `host:port` of the proxy a live dial uses.
    fn live_proxy(source: &ProxySource, host: &Host, port: u16, now: Instant) -> Option<String> {
        source
            .proxy_url_for(true, host, port, now)
            .map(|url| ProxyEndpoint::from(&url).addr)
    }

    /// Precedence (RWS1 §8.2) through the source: an explicit URL or `off`
    /// decides alone, without reading the environment or the system; `auto`
    /// takes `HTTPS_PROXY` (with `NO_PROXY`) before the system, and the
    /// system's HTTPS proxy (with its exceptions) when the environment names
    /// none; PAC alone is `unsupported: pac`. A decision is kept
    /// [`CACHE_TTL`]: changes within it are not seen, a read at its end or
    /// after [`ProxySource::invalidate`] sees them.
    #[test]
    fn proxy_source_precedence_and_ttl() {
        let t0 = Instant::now();
        let relay = name("relay.example");

        // An explicit URL: the environment and the system are never read.
        let readers = Readers::default();
        readers.set_env("HTTPS_PROXY", "http://env.example:8080");
        readers.set_system(system_https("system.example", 3128, &[]));
        let explicit = readers.source(setting("http://user:pw@proxy.example:3128"));
        let decided = explicit.effective_at(t0);
        assert_eq!(decided.source, Source::Setting);
        assert!(decided.proxy.as_ref().unwrap().has_credentials());
        let endpoint = explicit
            .proxy_url_for(true, &relay, 443, t0)
            .map(|url| ProxyEndpoint::from(&url))
            .unwrap();
        assert_eq!(endpoint.addr, "proxy.example:3128");
        assert!(endpoint.basic.is_some());
        // Loopback and link-local go direct even with an explicit proxy.
        assert_eq!(live_proxy(&explicit, &ip("127.0.0.1"), 443, t0), None);
        assert_eq!(live_proxy(&explicit, &ip("fe80::1"), 443, t0), None);
        assert_eq!(explicit.status_word_at(true, t0), "setting");
        assert_eq!((readers.env_reads(), readers.system_reads()), (0, 0));

        // `off`: no proxy, nothing read, an empty word.
        let off = readers.source(ProxySetting::Off);
        assert_eq!(live_proxy(&off, &relay, 443, t0), None);
        assert_eq!(off.status_word_at(true, t0), "");
        assert_eq!(off.status_word_at(false, t0), "");
        assert_eq!((readers.env_reads(), readers.system_reads()), (0, 0));

        // `auto`: the environment first, with its bypass list; the system is
        // not read.
        let readers = Readers::default();
        readers.set_env("HTTPS_PROXY", "http://env.example:8080");
        readers.set_env("NO_PROXY", ".corp.example");
        readers.set_system(system_https("system.example", 3128, &[]));
        let auto = readers.source(ProxySetting::Auto);
        assert_eq!(
            live_proxy(&auto, &relay, 443, t0).as_deref(),
            Some("env.example:8080")
        );
        assert_eq!(
            live_proxy(&auto, &name("relay.corp.example"), 443, t0),
            None
        );
        assert_eq!(auto.status_word_at(true, t0), "env");
        assert_eq!(readers.system_reads(), 0);

        // `auto` with nothing in the environment: the system, with its
        // exceptions and simple names; read once and kept.
        let readers = Readers::default();
        let mut system = system_https("system.example", 3128, &["*.local", "169.254/16"]);
        system.exclude_simple = true;
        readers.set_system(system);
        let auto = readers.source(ProxySetting::Auto);
        assert_eq!(
            live_proxy(&auto, &relay, 443, t0).as_deref(),
            Some("system.example:3128")
        );
        assert_eq!(live_proxy(&auto, &name("printer.local"), 443, t0), None);
        assert_eq!(live_proxy(&auto, &name("intranet"), 443, t0), None);
        assert_eq!(auto.status_word_at(true, t0), "system");
        assert_eq!(readers.system_reads(), 1);

        // Within the TTL a change is not seen; at its end it is.
        readers.set_env("HTTPS_PROXY", "http://env.example:8080");
        let almost = t0 + CACHE_TTL - Duration::from_millis(1);
        assert_eq!(
            live_proxy(&auto, &relay, 443, almost).as_deref(),
            Some("system.example:3128")
        );
        assert_eq!(readers.system_reads(), 1);
        let t1 = t0 + CACHE_TTL;
        assert_eq!(
            live_proxy(&auto, &relay, 443, t1).as_deref(),
            Some("env.example:8080")
        );
        assert_eq!(auto.status_word_at(true, t1), "env");
        // A clock that reads earlier than the kept decision keeps it.
        assert_eq!(
            live_proxy(&auto, &relay, 443, t0).as_deref(),
            Some("env.example:8080")
        );

        // invalidate(): the next question reads again at once.
        readers.set_env("HTTPS_PROXY", "");
        readers.set_system(SystemProxy {
            pac_or_wpad: true,
            ..SystemProxy::default()
        });
        assert_eq!(auto.status_word_at(true, t1), "env");
        let reads = readers.system_reads();
        auto.invalidate();
        assert_eq!(live_proxy(&auto, &relay, 443, t1), None);
        assert_eq!(readers.system_reads(), reads + 1);
        // PAC without an HTTPS proxy: unsupported, dials go direct.
        assert_eq!(auto.status_word_at(true, t1), "unsupported: pac");
        assert_eq!(auto.status_word_at(false, t1), "held");

        // An unusable environment proxy decides as unsupported.
        let readers = Readers::default();
        readers.set_env("https_proxy", "socks5://socks.example:1080");
        let auto = readers.source(ProxySetting::Auto);
        assert_eq!(live_proxy(&auto, &relay, 443, t0), None);
        assert_eq!(auto.status_word_at(true, t0), "unsupported: socks");

        // Nothing anywhere: no proxy, an empty word, gate or not.
        let auto = Readers::default().source(ProxySetting::Auto);
        assert_eq!(live_proxy(&auto, &relay, 443, t0), None);
        assert_eq!(auto.status_word_at(true, t0), "");
        assert_eq!(auto.status_word_at(false, t0), "");
    }

    /// While the proxy gate is closed, every WSS dial goes direct and the
    /// lookup reads nothing; the status word says `held` when a source names
    /// a proxy. Through the real gate the answer follows
    /// `raven_core::wss_proxy_live_enabled` (closed in the default run).
    #[test]
    fn proxy_for_is_none_while_the_proxy_gate_is_closed() {
        let t0 = Instant::now();
        let relay = name("relay.example");
        let readers = Readers::default();
        readers.set_env("HTTPS_PROXY", "http://env.example:8080");
        readers.set_system(system_https("system.example", 3128, &[]));
        let auto = readers.source(ProxySetting::Auto);
        assert_eq!(auto.proxy_url_for(false, &relay, 443, t0), None);
        assert_eq!(auto.proxy_url_for(false, &ip("203.0.113.7"), 443, t0), None);
        assert_eq!((readers.env_reads(), readers.system_reads()), (0, 0));
        assert_eq!(auto.status_word_at(false, t0), "held");

        let explicit = readers.source(setting("http://proxy.example:3128"));
        let live = raven_core::wss_proxy_live_enabled();
        let endpoint = ProxyLookup::proxy_for(&explicit, &relay, 443);
        assert_eq!(endpoint.is_some(), live);
        if let Some(endpoint) = endpoint {
            assert_eq!(endpoint.addr, "proxy.example:3128");
        }
        assert_eq!(explicit.applies(&relay, 443), live);
        assert_eq!(explicit.applies(&ip("203.0.113.7"), 443), live);
        assert_eq!(
            explicit.status_word(),
            if live { "setting" } else { "held" }
        );
        // Loopback never goes through a proxy, gate or not.
        assert!(!explicit.applies(&ip("127.0.0.1"), 443));
        assert!(ProxyLookup::proxy_for(&explicit, &ip("::1"), 443).is_none());
    }

    /// The explicit setting of each source (RWS1 §8.2): the flag and the
    /// environment may carry a user name and password, node_policy.json
    /// never; an error names the source and the rule, never the text. A
    /// setting taken later (node policy's, once its sealed sidecar opens)
    /// drops the kept decision. A source behind an open test gate answers
    /// as a live one.
    #[test]
    fn explicit_settings_parse_per_source_and_can_be_replaced() {
        let secret = "http://user:hunter2@proxy.example:3128";
        for source in ["--p2p-proxy", "RAVEN_P2P_PROXY"] {
            let ProxySetting::Url(url) = parse_explicit(secret, source).unwrap() else {
                panic!("{source}: a proxy URL");
            };
            assert!(url.has_credentials());
        }
        let err = parse_explicit(secret, POLICY_SOURCE).unwrap_err();
        assert!(err.starts_with("node_policy.json: "), "{err}");
        assert!(
            !err.contains("hunter2") && !err.contains("proxy.example"),
            "{err}"
        );
        assert_eq!(
            parse_explicit(" Auto ", POLICY_SOURCE),
            Ok(ProxySetting::Auto)
        );
        assert_eq!(parse_explicit("off", "--p2p-proxy"), Ok(ProxySetting::Off));
        assert_eq!(
            parse_explicit("", "RAVEN_P2P_PROXY"),
            Ok(ProxySetting::Auto)
        );
        for (bad, source) in [
            ("socks5://proxy.example:1080", "--p2p-proxy"),
            ("https://pw@proxy.example", "RAVEN_P2P_PROXY"),
            ("http://proxy.example:99999", POLICY_SOURCE),
        ] {
            let err = parse_explicit(bad, source).unwrap_err();
            assert!(err.starts_with(&format!("{source}: ")), "{err}");
            assert!(
                !err.contains("proxy.example") && !err.contains("pw@"),
                "{err}"
            );
        }

        let t0 = Instant::now();
        let relay = name("relay.example");
        let readers = Readers::default();
        readers.set_env("HTTPS_PROXY", "http://env.example:8080");
        let source = readers.source(ProxySetting::Auto);
        let via = |s: &ProxySource| live_proxy(s, &relay, 443, t0);
        assert_eq!(via(&source).as_deref(), Some("env.example:8080"));
        source.set_explicit(setting("http://proxy.example:3128"));
        assert_eq!(via(&source).as_deref(), Some("proxy.example:3128"));
        source.set_explicit(ProxySetting::Off);
        assert_eq!(via(&source), None);

        let open = readers
            .source(setting("http://proxy.example:3128"))
            .with_gate(|| true);
        assert!(open.applies(&relay, 443));
        assert!(!open.applies(&ip("127.0.0.1"), 443));
        assert_eq!(open.status_word(), "setting");
        let shut = readers
            .source(setting("http://proxy.example:3128"))
            .with_gate(|| false);
        assert!(!shut.applies(&relay, 443));
        assert!(ProxyLookup::proxy_for(&shut, &relay, 443).is_none());
        assert_eq!(shut.status_word(), "held");
    }

    /// WinHTTP's IE settings as [`SystemProxy`], on every OS (the reader
    /// itself runs only on Windows): the `https=` entry, else the bare one,
    /// with its own port; the bypass string; a script URL as PAC, and
    /// auto-detect alone as nothing.
    #[test]
    fn windows_settings_map_to_a_system_proxy() {
        let both = from_windows(
            false,
            None,
            Some("http=web.example:80;https=secure.example:8443"),
            Some("<local>;*.corp.example"),
        );
        assert_eq!(
            both,
            SystemProxy {
                https_enabled: true,
                host: "secure.example:8443".into(),
                port: 0,
                exceptions: vec!["<local>;*.corp.example".into()],
                exclude_simple: false,
                pac_or_wpad: false,
            }
        );
        let decided = net_proxy::effective(&ProxySetting::Auto, |_| None, || both.clone());
        assert_eq!(decided.source, Source::System);
        let proxy = decided.proxy_for("relay.example", 443).unwrap();
        assert_eq!((proxy.host(), proxy.port()), ("secure.example", 8443));
        assert!(decided.proxy_for("intranet", 443).is_none());
        assert!(decided.proxy_for("relay.corp.example", 443).is_none());

        let bare = from_windows(false, None, Some("proxy.example"), None);
        assert_eq!(
            (bare.https_enabled, bare.host.as_str()),
            (true, "proxy.example")
        );
        assert!(bare.exceptions.is_empty());
        let decided = net_proxy::effective(&ProxySetting::Auto, |_| None, || bare);
        assert_eq!(decided.proxy.unwrap().port(), net_proxy::DEFAULT_PROXY_PORT);

        // Only other schemes: no HTTPS proxy.
        let socks = from_windows(false, None, Some("socks=socks.example:1080"), None);
        assert!(!socks.https_enabled && socks.host.is_empty());

        for auto_detect in [false, true] {
            let pac = from_windows(
                auto_detect,
                Some("http://wpad.example/proxy.pac"),
                None,
                None,
            );
            assert!(pac.pac_or_wpad && !pac.https_enabled);
            let decided = net_proxy::effective(&ProxySetting::Auto, |_| None, || pac);
            assert_eq!(decided.unsupported.as_deref(), Some("pac"));
        }
        // Review B-2: "Automatically detect settings" alone (on by default)
        // is no proxy: dials go direct, and the status word is empty, gate
        // or not, never `unsupported: pac` or `held`.
        let detect = from_windows(true, None, None, None);
        assert_eq!(detect, SystemProxy::default());
        let auto = ProxySource::with_readers(ProxySetting::Auto, |_| None, move || detect.clone());
        let now = Instant::now();
        assert_eq!(auto.effective_at(now).unsupported, None);
        assert_eq!(auto.status_word_at(true, now), "");
        assert_eq!(auto.status_word_at(false, now), "");
        // With a manual proxy it is that proxy, as before.
        let manual = from_windows(true, None, Some("proxy.example:3128"), None);
        assert!(manual.https_enabled && !manual.pac_or_wpad);
        assert_eq!(
            from_windows(false, Some("  "), None, None),
            SystemProxy::default()
        );
        assert_eq!(
            from_windows(false, None, None, None),
            SystemProxy::default()
        );
    }

    /// The real macOS settings read twice without a panic, and whatever
    /// they hold decides something; nothing is printed (they may name a real
    /// network's proxy).
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_proxy_reads_without_panicking() {
        for _ in 0..2 {
            let system = system_proxy();
            let decided = net_proxy::effective(&ProxySetting::Auto, |_| None, || system);
            assert!(decided.proxy.is_none() || decided.source == Source::System);
        }
    }

    /// The dynamic store's keys as [`SystemProxy`]: numbers or booleans for
    /// the flags, a port in range, the string entries of ExceptionsList;
    /// anything missing or of another type is unset.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_proxy_keys_map_to_a_system_proxy() {
        use system_configuration::core_foundation::array::CFArray;
        use system_configuration::core_foundation::base::{CFType, TCFType};
        use system_configuration::core_foundation::boolean::CFBoolean;
        use system_configuration::core_foundation::dictionary::CFDictionary;
        use system_configuration::core_foundation::number::CFNumber;
        use system_configuration::core_foundation::string::CFString;

        let dict = |pairs: &[(&str, CFType)]| {
            let pairs: Vec<(CFString, CFType)> = pairs
                .iter()
                .map(|(k, v)| (CFString::new(k), v.clone()))
                .collect();
            CFDictionary::from_CFType_pairs(&pairs)
        };
        let n = |v: i64| CFNumber::from(v).as_CFType();
        let s = |v: &str| CFString::new(v).as_CFType();
        let exceptions = CFArray::from_CFTypes(&[s("*.local"), n(7), s("169.254/16")]);

        let full = macos::from_dict(&dict(&[
            ("HTTPSEnable", n(1)),
            ("HTTPSProxy", s("proxy.example")),
            ("HTTPSPort", n(3128)),
            ("ExceptionsList", exceptions.as_CFType()),
            (
                "ExcludeSimpleHostnames",
                CFBoolean::true_value().as_CFType(),
            ),
            ("ProxyAutoConfigEnable", n(0)),
        ]));
        assert_eq!(
            full,
            SystemProxy {
                https_enabled: true,
                host: "proxy.example".into(),
                port: 3128,
                exceptions: vec!["*.local".into(), "169.254/16".into()],
                exclude_simple: true,
                pac_or_wpad: false,
            }
        );

        let disabled = macos::from_dict(&dict(&[
            ("HTTPSEnable", n(0)),
            ("HTTPSProxy", s("proxy.example")),
            ("HTTPSPort", n(70000)),
            ("ProxyAutoDiscoveryEnable", n(1)),
        ]));
        assert!(!disabled.https_enabled && disabled.pac_or_wpad);
        assert_eq!(disabled.port, 0);
        let decided = net_proxy::effective(&ProxySetting::Auto, |_| None, || disabled);
        assert_eq!(decided.unsupported.as_deref(), Some("pac"));

        let mistyped = macos::from_dict(&dict(&[
            ("HTTPSEnable", s("1")),
            ("HTTPSProxy", n(1)),
            ("ExceptionsList", s("*.local")),
            (
                "ProxyAutoConfigEnable",
                CFBoolean::false_value().as_CFType(),
            ),
        ]));
        assert_eq!(mistyped, SystemProxy::default());
        assert_eq!(macos::from_dict(&dict(&[])), SystemProxy::default());
    }

    /// The real WinHTTP settings read twice without a panic; a string
    /// WinHTTP would return is read and freed, and null is none.
    #[cfg(windows)]
    #[test]
    fn windows_winhttp_reads_without_panicking() {
        #[link(name = "kernel32")]
        extern "system" {
            fn GlobalAlloc(flags: u32, bytes: usize) -> *mut core::ffi::c_void;
        }
        for _ in 0..2 {
            let system = system_proxy();
            let decided = net_proxy::effective(&ProxySetting::Auto, |_| None, || system);
            assert!(decided.proxy.is_none() || decided.source == Source::System);
        }
        let text: Vec<u16> = "https=proxy.example:3128\0".encode_utf16().collect();
        // SAFETY: a fixed block (GMEM_FIXED, 0) large enough for `text`,
        // filled before `take` reads and frees it.
        let p = unsafe {
            let p = GlobalAlloc(0, text.len() * 2).cast::<u16>();
            assert!(!p.is_null());
            std::ptr::copy_nonoverlapping(text.as_ptr(), p, text.len());
            p
        };
        // SAFETY: `p` is a NUL-terminated GlobalAlloc string, not used again.
        let taken = unsafe { windows::take(p) };
        assert_eq!(taken.as_deref(), Some("https=proxy.example:3128"));
        // SAFETY: null is allowed.
        assert_eq!(unsafe { windows::take(std::ptr::null_mut()) }, None);
    }
}
