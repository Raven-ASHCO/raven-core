//! Proxy rules for relay dials over WSS (`protocol/RAVEN_WSS_TRANSPORT_V1.md`
//! §7, §8): the proxy setting and its URL grammar, the bypass list, and which
//! source decides. Pure: no OS call and no environment read of its own;
//! raven-node fills [`SystemProxy`] per OS and hands [`effective`] the
//! environment as a closure.
//!
//! - [`parse_setting`]: `auto` (or empty), `off`, or an `http://` proxy
//!   ([`parse_proxy_url`]); `https://`, SOCKS and PAC/WPAD are
//!   [`ProxyError::Unsupported`] (owner decision O4-4).
//! - [`ProxyUrl`] keeps a Basic credential only in memory, in a
//!   [`Zeroizing`] string: its `Debug` and `Display` redact it and it has no
//!   `Serialize`. Node policy refuses a setting that carries one
//!   ([`has_credentials`]).
//! - [`Bypass`]: `NO_PROXY`, macOS ExceptionsList and Windows ProxyOverride
//!   entries; loopback and link-local hosts always bypass.
//! - [`effective`]: the explicit setting, then the environment
//!   ([`ENV_HTTPS_PROXY`], an `http://` [`ENV_ALL_PROXY`], with
//!   [`ENV_NO_PROXY`]), then the system settings. `HTTP_PROXY` is never read.
//!
//! Nothing here dials; the dials sit behind [`crate::wss_gate`]. Vectors:
//! `shared-vectors/rvn1/wss/rws1_proxy_url_001.json` and
//! `rws1_no_proxy_001.json` (`protocol/reference/generate_wss.py`).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use zeroize::Zeroizing;

/// Port of an `http://` proxy that names none (Go's httpproxy rule).
pub const DEFAULT_PROXY_PORT: u16 = 80;
/// Longest proxy setting accepted, in bytes once trimmed.
pub const MAX_PROXY_TEXT: usize = 1024;
/// The environment variables that name the proxy of a WSS dial, highest
/// first (RWS1 §8). A set but empty variable counts as unset.
pub const ENV_HTTPS_PROXY: [&str; 2] = ["HTTPS_PROXY", "https_proxy"];
/// Read after [`ENV_HTTPS_PROXY`], and used only when it names an `http://`
/// proxy: it often names a SOCKS proxy for other programs.
pub const ENV_ALL_PROXY: [&str; 2] = ["ALL_PROXY", "all_proxy"];
/// The bypass list of a proxy from the environment ([`Bypass::parse`]).
pub const ENV_NO_PROXY: [&str; 2] = ["NO_PROXY", "no_proxy"];

/// What a status line says for a text [`ProxyError::Invalid`] refused.
pub const INVALID: &str = "invalid";

/// The white space Raven trims from a setting and splits lists on: space,
/// tab, CR and LF (the same set in the Python reference).
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Why [`parse_proxy_url`] refused a text. Each message is fixed: none
/// repeats the text, which may carry a password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// A proxy Raven does not use (owner decision O4-4): `"https"` (an
    /// HTTPS proxy), `"socks"` or `"pac"` (PAC or WPAD).
    Unsupported(&'static str),
    /// Not a proxy setting. The code names the rule it breaks: `"syntax"`,
    /// `"too_long"`, `"scheme"`, `"userinfo"`, `"host"`, `"port"` or
    /// `"path"`.
    Invalid(&'static str),
}

impl ProxyError {
    /// The code the vectors record.
    pub fn code(self) -> &'static str {
        match self {
            Self::Unsupported(code) | Self::Invalid(code) => code,
        }
    }

    /// What a status line says: the unsupported kind, or [`INVALID`].
    pub fn kind(self) -> &'static str {
        match self {
            Self::Unsupported(kind) => kind,
            Self::Invalid(_) => INVALID,
        }
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported("https") => f.write_str(
                "https:// proxies are not supported: Raven dials through an http:// proxy \
                 (HTTP CONNECT)",
            ),
            Self::Unsupported("socks") => {
                f.write_str("SOCKS proxies are not supported: Raven dials through an http:// proxy")
            }
            Self::Unsupported("pac") => f.write_str(
                "automatic proxy configuration (PAC, WPAD) is not supported: give the proxy as \
                 http://host:port",
            ),
            Self::Unsupported(kind) => write!(f, "{kind} proxies are not supported"),
            Self::Invalid(code) => write!(
                f,
                "not a proxy setting ({code}): use auto, off or http://host:port"
            ),
        }
    }
}

impl std::error::Error for ProxyError {}

/// An `http://` proxy: its host (a lowercase DNS name, or an IP address
/// without brackets), its port and, only in memory, a Basic credential.
/// `Debug` and `Display` redact the credential; there is no `Serialize`.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyUrl {
    host: String,
    port: u16,
    basic: Option<Zeroizing<String>>,
}

impl ProxyUrl {
    /// The proxy's host: a lowercase DNS name or an IP address (no brackets).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The proxy's TCP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The `Proxy-Authorization: Basic` value (base64 of `user:pass`, RFC
    /// 7617), when the URL carried a user name.
    pub fn basic(&self) -> Option<&str> {
        self.basic.as_deref().map(String::as_str)
    }

    /// Whether the URL carried a user name (and maybe a password).
    pub fn has_credentials(&self) -> bool {
        self.basic.is_some()
    }
}

impl fmt::Display for ProxyUrl {
    /// `http://host:port`, `http://[v6]:port`; `<redacted>@` before the host
    /// when there is a credential.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("http://")?;
        if self.basic.is_some() {
            f.write_str("<redacted>@")?;
        }
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Debug for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyUrl")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("basic", &self.basic.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The proxy setting (`--p2p-proxy`, `RAVEN_P2P_PROXY`, node policy
/// `p2p_proxy`): [`parse_setting`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ProxySetting {
    /// The environment, then the system settings ([`effective`]).
    #[default]
    Auto,
    /// No proxy: WSS dials go direct.
    Off,
    /// This proxy, whatever the environment and the system say.
    Url(ProxyUrl),
}

impl fmt::Display for ProxySetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Off => f.write_str("off"),
            Self::Url(url) => fmt::Display::fmt(url, f),
        }
    }
}

/// A proxy setting: empty or `auto` (any case) is [`ProxySetting::Auto`],
/// `off` is [`ProxySetting::Off`], anything else a proxy URL
/// ([`parse_proxy_url`]). Surrounding white space is ignored.
pub fn parse_setting(text: &str) -> Result<ProxySetting, ProxyError> {
    let t = text.trim_matches(is_space);
    if t.is_empty() || t.eq_ignore_ascii_case("auto") {
        Ok(ProxySetting::Auto)
    } else if t.eq_ignore_ascii_case("off") {
        Ok(ProxySetting::Off)
    } else {
        parse_proxy_url(t).map(ProxySetting::Url)
    }
}

/// Whether a proxy setting carries a user name or password (`user[:pass]@`):
/// any `@`, since no host has one. Node policy refuses such a setting, as
/// `node_policy.json` holds no secrets.
pub fn has_credentials(text: &str) -> bool {
    text.contains('@')
}

/// A proxy URL (RWS1 §7): `http://[user[:pass]@]host[:port][/]`, the scheme
/// optional and any case. The host is a DNS name or an IPv4 address naming
/// one host, or `[IPv6]`; the port 1-65535 in plain decimal, default
/// [`DEFAULT_PROXY_PORT`]. The user name and password are percent-decoded
/// into the Basic value; the last `@` ends them. `https://`, `socks*://` and
/// PAC/WPAD texts are [`ProxyError::Unsupported`].
pub fn parse_proxy_url(text: &str) -> Result<ProxyUrl, ProxyError> {
    use ProxyError::{Invalid, Unsupported};
    let t = text.trim_matches(is_space);
    if t.len() > MAX_PROXY_TEXT {
        return Err(Invalid("too_long"));
    }
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Invalid("syntax"));
    }
    if is_pac(t) {
        return Err(Unsupported("pac"));
    }
    let rest = match t.split_once("://") {
        Some((scheme, rest)) => match scheme.to_ascii_lowercase().as_str() {
            "http" => rest,
            "https" => return Err(Unsupported("https")),
            "socks" | "socks4" | "socks4a" | "socks5" | "socks5h" => {
                return Err(Unsupported("socks"))
            }
            _ => return Err(Invalid("scheme")),
        },
        None => t,
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if !tail.is_empty() && tail != "/" {
        return Err(Invalid("path"));
    }
    let (basic, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (Some(basic_value(userinfo)?), host_port),
        None => (None, authority),
    };
    let (host, port) = split_host_port(host_port)?;
    Ok(ProxyUrl { host, port, basic })
}

/// A PAC or WPAD text: the words `pac` or `wpad`, or a URL ending in `.pac`
/// or `/wpad.dat` (before any `?` or `#`).
fn is_pac(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let base = lower.split(['?', '#']).next().unwrap_or_default();
    matches!(base, "pac" | "wpad") || base.ends_with(".pac") || base.ends_with("/wpad.dat")
}

/// The Basic value of a URL's user part: base64 of `user:pass` (RFC 7617),
/// each percent-decoded. Refused: an empty user part, a bad `%` escape, a
/// `:` in the user name, a control character.
fn basic_value(userinfo: &str) -> Result<Zeroizing<String>, ProxyError> {
    const BAD: ProxyError = ProxyError::Invalid("userinfo");
    if userinfo.is_empty() {
        return Err(BAD);
    }
    let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let user = percent_decode(user).ok_or(BAD)?;
    let pass = percent_decode(pass).ok_or(BAD)?;
    if user.contains(&b':') || user.iter().chain(pass.iter()).any(u8::is_ascii_control) {
        return Err(BAD);
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(user.len() + 1 + pass.len()));
    plain.extend_from_slice(&user);
    plain.push(b':');
    plain.extend_from_slice(&pass);
    Ok(Zeroizing::new(STANDARD.encode(plain.as_slice())))
}

/// `%XX` (two hex digits) decoded; `None` on a bad escape.
fn percent_decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let b = text.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// `host[:port]` or `[v6][:port]`: the canonical host and the port. The host
/// is checked before the port.
fn split_host_port(text: &str) -> Result<(String, u16), ProxyError> {
    const HOST: ProxyError = ProxyError::Invalid("host");
    let (host, port) = match text.strip_prefix('[') {
        Some(rest) => {
            let (inside, after) = rest.split_once(']').ok_or(HOST)?;
            let port = match after {
                "" => None,
                _ => Some(after.strip_prefix(':').ok_or(HOST)?),
            };
            (bracketed_host(inside)?, port)
        }
        None => match text.split_once(':') {
            Some((host, port)) => (plain_host(host)?, Some(port)),
            None => (plain_host(text)?, None),
        },
    };
    let port = match port {
        None => DEFAULT_PROXY_PORT,
        Some(p) => parse_port(p).ok_or(ProxyError::Invalid("port"))?,
    };
    Ok((host, port))
}

/// The address inside `[…]`: IPv6 (an IPv4-mapped one is its IPv4 address),
/// no zone.
fn bracketed_host(inside: &str) -> Result<String, ProxyError> {
    match inside.parse::<Ipv6Addr>() {
        Ok(ip) if !inside.contains('%') => single_host(IpAddr::V6(ip).to_canonical()),
        _ => Err(ProxyError::Invalid("host")),
    }
}

/// An IPv4 address or a DNS name (lowercased).
fn plain_host(host: &str) -> Result<String, ProxyError> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return single_host(IpAddr::V4(ip));
    }
    let lower = host.to_ascii_lowercase();
    if host_name_ok(&lower) {
        Ok(lower)
    } else {
        Err(ProxyError::Invalid("host"))
    }
}

/// The text of an IP address that names one host (not unspecified,
/// broadcast or multicast).
fn single_host(ip: IpAddr) -> Result<String, ProxyError> {
    let one = match ip {
        IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast()),
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast()),
    };
    if one {
        Ok(ip.to_string())
    } else {
        Err(ProxyError::Invalid("host"))
    }
}

/// A DNS name (one trailing dot allowed): labels of 1-63 letters, digits, `-`
/// and `_`, none starting or ending with `-`, at most 253 bytes, and a last
/// label that is not all digits (that would be an IPv4 address, or a short
/// form of one).
fn host_name_ok(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        && !name
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
}

/// 1-65535 in plain decimal (no sign, no leading zero).
fn parse_port(text: &str) -> Option<u16> {
    match text.parse::<u16>() {
        Ok(p) if p != 0 && text == p.to_string() => Some(p),
        _ => None,
    }
}

/// The hosts a WSS dial reaches directly, never through the proxy (RWS1
/// §8): `NO_PROXY`, macOS ExceptionsList or Windows ProxyOverride entries.
/// Loopback and link-local hosts always bypass, even an empty list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bypass {
    all: bool,
    simple_names: bool,
    rules: Vec<(Pattern, Option<u16>)>,
}

/// One bypass entry without its port.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Pattern {
    /// A domain and every name under it (lowercase, no leading or trailing
    /// dot).
    Suffix(String),
    /// A `*` glob over the host's text (lowercase).
    Glob(String),
    /// One IP address.
    Ip(IpAddr),
    /// An IP network: its address with the host bits cleared, and its prefix
    /// length.
    Net(IpAddr, u8),
}

impl Bypass {
    /// A list of entries separated by `,`, `;` or white space (`NO_PROXY`,
    /// Windows ProxyOverride). Each entry, any case:
    /// - `*`: every host;
    /// - `<local>`: names without a dot (Windows; macOS ExcludeSimpleHostnames);
    /// - a domain, with or without a leading dot: it and every name under it
    ///   (on a label boundary);
    /// - a glob with `*` (any run of characters) over the host's text;
    /// - an IP address (IPv6 bare or in brackets);
    /// - a CIDR, also the macOS short form `169.254/16`;
    /// - each but the first two with an optional `:port` (`[v6]:port`), then
    ///   only for dials to that port.
    ///
    /// An entry that fits none of these is ignored.
    pub fn parse(list: &str) -> Self {
        Self::from_entries([list])
    }

    /// The same from separate entries (macOS ExceptionsList); each may
    /// itself be a list.
    pub fn from_entries<I>(entries: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut out = Self::default();
        for list in entries {
            for entry in list
                .as_ref()
                .split(|c: char| c == ',' || c == ';' || is_space(c))
            {
                out.add(entry);
            }
        }
        out
    }

    /// Names without a dot bypass too (macOS ExcludeSimpleHostnames).
    pub fn with_simple_names(mut self) -> Self {
        self.simple_names = true;
        self
    }

    fn add(&mut self, entry: &str) {
        let entry = entry.to_ascii_lowercase();
        match entry.as_str() {
            "" => {}
            "*" => self.all = true,
            "<local>" => self.simple_names = true,
            _ => {
                if let Some((host, port)) = split_entry_port(&entry) {
                    if let Some(pattern) = pattern_of(host) {
                        self.rules.push((pattern, port));
                    }
                }
            }
        }
    }

    /// Whether a WSS dial to `host` (a DNS name or an IP address, IPv6 with
    /// or without brackets) on `port` goes direct. Case and one trailing dot
    /// are ignored; an IPv4-mapped IPv6 address is its IPv4 address.
    pub fn bypasses(&self, host: &str, port: u16) -> bool {
        let host = host.trim_matches(is_space);
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host)
            .to_ascii_lowercase();
        let name = host.strip_suffix('.').unwrap_or(&host);
        let ip = ip_of(name);
        if always_direct(name, ip) || self.all {
            return true;
        }
        if self.simple_names && ip.is_none() && !name.is_empty() && !name.contains('.') {
            return true;
        }
        let text = ip.map_or_else(|| name.to_owned(), |ip| ip.to_string());
        self.rules.iter().any(|(pattern, only)| {
            only.is_none_or(|p| p == port)
                && match pattern {
                    Pattern::Suffix(domain) => {
                        ip.is_none()
                            && (name == domain
                                || name
                                    .strip_suffix(domain.as_str())
                                    .is_some_and(|under| under.ends_with('.')))
                    }
                    Pattern::Glob(glob) => glob_match(glob.as_bytes(), text.as_bytes()),
                    Pattern::Ip(addr) => ip == Some(*addr),
                    Pattern::Net(net, len) => ip.is_some_and(|ip| masked(ip, *len) == Some(*net)),
                }
        })
    }
}

/// An entry's host part and its optional port (`host:port`, `[v6]:port`); a
/// bare IPv6 address (two or more `:`) has none. `None`: no usable port.
fn split_entry_port(entry: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = entry.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        return match after {
            "" => Some((inside, None)),
            _ => Some((inside, Some(parse_port(after.strip_prefix(':')?)?))),
        };
    }
    match entry.split_once(':') {
        Some((host, port)) if !port.contains(':') => Some((host, Some(parse_port(port)?))),
        _ => Some((entry, None)),
    }
}

/// The pattern of an entry's host part; `None` when it fits no form.
fn pattern_of(host: &str) -> Option<Pattern> {
    if let Some((addr, len)) = host.split_once('/') {
        return network(addr, len);
    }
    if host.contains('*') {
        return Some(Pattern::Glob(host.to_owned()));
    }
    if let Some(ip) = ip_of(host) {
        return Some(Pattern::Ip(ip));
    }
    let name = host.strip_prefix('.').unwrap_or(host);
    let name = name.strip_suffix('.').unwrap_or(name);
    host_name_ok(name).then(|| Pattern::Suffix(name.to_owned()))
}

/// `addr/len`: an IPv6 network, or an IPv4 one whose address may have 1-4
/// parts (the missing ones are 0: macOS `169.254/16`).
fn network(addr: &str, len: &str) -> Option<Pattern> {
    let len: u8 = len.parse().ok().filter(|n: &u8| len == n.to_string())?;
    let ip = if addr.contains(':') {
        IpAddr::V6(addr.parse().ok()?)
    } else {
        let parts: Vec<&str> = addr.split('.').collect();
        if parts.len() > 4 {
            return None;
        }
        let mut octets = [0u8; 4];
        for (octet, part) in octets.iter_mut().zip(&parts) {
            *octet = part.parse().ok().filter(|n: &u8| *part == n.to_string())?;
        }
        IpAddr::V4(Ipv4Addr::from(octets))
    };
    Some(Pattern::Net(masked(ip, len)?, len))
}

/// `ip` with the bits past `len` cleared; `None` past the family's width.
fn masked(ip: IpAddr, len: u8) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(v4) if len <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            Some(IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask)))
        }
        IpAddr::V6(v6) if len <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            Some(IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask)))
        }
        _ => None,
    }
}

/// An IP address (no zone); an IPv4-mapped IPv6 address is its IPv4 one.
fn ip_of(text: &str) -> Option<IpAddr> {
    if text.contains('%') {
        return None;
    }
    text.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// Loopback and link-local addresses, `localhost` and names under it.
fn always_direct(name: &str, ip: Option<IpAddr>) -> bool {
    match ip {
        Some(IpAddr::V4(v4)) => v4.is_loopback() || v4.is_link_local(),
        Some(IpAddr::V6(v6)) => v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80,
        None => name == "localhost" || name.ends_with(".localhost"),
    }
}

/// `*` matches any run of characters (dots included); everything else
/// itself.
fn glob_match(glob: &[u8], text: &[u8]) -> bool {
    let (mut g, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if g < glob.len() && glob[g] == b'*' {
            star = Some((g, t));
            g += 1;
        } else if g < glob.len() && glob[g] == text[t] {
            g += 1;
            t += 1;
        } else if let Some((sg, st)) = star {
            g = sg + 1;
            t = st + 1;
            star = Some((sg, st + 1));
        } else {
            return false;
        }
    }
    glob[g..].iter().all(|&b| b == b'*')
}

/// The entry of a Windows proxy string (WinHTTP `lpszProxy`, the
/// ProxyServer value) that a WSS dial uses: the `https=` entry, else the
/// first entry without a scheme (it serves every scheme the string does not
/// name). Entries are separated by `;` or white space; `http=`, `socks=` and
/// others are ignored. The entry goes into [`SystemProxy::host`] with port 0.
pub fn parse_windows_proxy(text: &str) -> Option<String> {
    let mut bare = None;
    for item in text.split(|c: char| c == ';' || is_space(c)) {
        match item.split_once('=') {
            Some((scheme, entry)) => {
                if scheme.eq_ignore_ascii_case("https") && !entry.is_empty() {
                    return Some(entry.to_owned());
                }
            }
            None if !item.is_empty() && bare.is_none() => bare = Some(item.to_owned()),
            None => {}
        }
    }
    bare
}

/// The OS proxy settings, as raven-node reads them (macOS SCDynamicStore,
/// Windows WinHTTP's IE configuration; Linux has none). Plain data.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemProxy {
    /// An HTTPS proxy is set and on (macOS `HTTPSEnable`; Windows: an entry
    /// [`parse_windows_proxy`] found).
    pub https_enabled: bool,
    /// Its host (macOS `HTTPSProxy`); with [`Self::port`] 0, a whole
    /// `host[:port]` entry as [`parse_windows_proxy`] returns it.
    pub host: String,
    /// Its port (macOS `HTTPSPort`); 0: the entry's own, else
    /// [`DEFAULT_PROXY_PORT`].
    pub port: u16,
    /// Bypass entries (macOS `ExceptionsList`; Windows `lpszProxyBypass`, a
    /// `;` list): [`Bypass::from_entries`].
    pub exceptions: Vec<String>,
    /// macOS `ExcludeSimpleHostnames`: names without a dot bypass, like
    /// Windows `<local>`.
    pub exclude_simple: bool,
    /// PAC or WPAD is set (macOS `ProxyAutoConfigEnable` /
    /// `ProxyAutoDiscoveryEnable`; Windows `fAutoDetect` /
    /// `lpszAutoConfigUrl`). Used only to say why there is no proxy.
    pub pac_or_wpad: bool,
}

impl SystemProxy {
    fn url(&self) -> Result<ProxyUrl, ProxyError> {
        let host = self.host.trim_matches(is_space);
        if self.port == 0 {
            return parse_proxy_url(host);
        }
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if bare.contains(':') {
            parse_proxy_url(&format!("[{bare}]:{}", self.port))
        } else {
            parse_proxy_url(&format!("{bare}:{}", self.port))
        }
    }

    fn bypass(&self) -> Bypass {
        let bypass = Bypass::from_entries(&self.exceptions);
        if self.exclude_simple {
            bypass.with_simple_names()
        } else {
            bypass
        }
    }
}

/// Where the effective proxy came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The explicit setting (`--p2p-proxy`, `RAVEN_P2P_PROXY`, node policy).
    Setting,
    /// The environment ([`ENV_HTTPS_PROXY`], [`ENV_ALL_PROXY`]).
    Env,
    /// The OS settings ([`SystemProxy`]).
    System,
    /// Nowhere: no proxy is set.
    None,
}

/// The proxy WSS dials use, as [`effective`] decided it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effective {
    /// The proxy; `None`: WSS dials go direct.
    pub proxy: Option<ProxyUrl>,
    /// The hosts that go direct even with a proxy.
    pub bypass: Bypass,
    /// The source that decided.
    pub source: Source,
    /// The source named a proxy Raven cannot use: its [`ProxyError::kind`]
    /// (`https`, `socks`, `pac` or [`INVALID`]), for a status line. Dials
    /// then go direct.
    pub unsupported: Option<String>,
}

impl Effective {
    fn proxied(url: ProxyUrl, bypass: Bypass, source: Source) -> Self {
        Self {
            proxy: Some(url),
            bypass,
            source,
            unsupported: None,
        }
    }

    fn direct(source: Source, unsupported: Option<&str>) -> Self {
        Self {
            proxy: None,
            bypass: Bypass::default(),
            source,
            unsupported: unsupported.map(str::to_owned),
        }
    }

    /// The proxy a WSS dial to `host` on `port` goes through: `None` without
    /// one, or when the host bypasses it ([`Bypass::bypasses`]).
    pub fn proxy_for(&self, host: &str, port: u16) -> Option<&ProxyUrl> {
        let proxy = self.proxy.as_ref()?;
        (!self.bypass.bypasses(host, port)).then_some(proxy)
    }
}

/// The proxy WSS dials use (RWS1 §8), highest source first:
/// 1. `explicit`: [`ProxySetting::Off`] or a URL decides alone (with no
///    bypass list but loopback and link-local); [`ProxySetting::Auto`] reads
///    on;
/// 2. the environment (`env`, `None` or empty when unset): the first of
///    [`ENV_HTTPS_PROXY`] decides, usable or not; then the first of
///    [`ENV_ALL_PROXY`], only when it is a usable `http://` proxy. Either
///    takes the first of [`ENV_NO_PROXY`] as its bypass list;
/// 3. `system` (called only when it is needed): an HTTPS proxy, with its
///    exceptions; else PAC/WPAD, reported as `pac`.
///
/// A source that names a proxy Raven cannot use decides with no proxy and
/// says why ([`Effective::unsupported`]); an `ALL_PROXY` that is not
/// `http://` says so only when the system names nothing either.
pub fn effective(
    explicit: &ProxySetting,
    env: impl Fn(&str) -> Option<String>,
    system: impl FnOnce() -> SystemProxy,
) -> Effective {
    match explicit {
        ProxySetting::Off => return Effective::direct(Source::Setting, None),
        ProxySetting::Url(url) => {
            return Effective::proxied(url.clone(), Bypass::default(), Source::Setting)
        }
        ProxySetting::Auto => {}
    }
    let first = |names: &[&str]| {
        names
            .iter()
            .find_map(|&name| env(name).filter(|v| !v.trim_matches(is_space).is_empty()))
    };
    let no_proxy = || Bypass::parse(&first(&ENV_NO_PROXY).unwrap_or_default());
    if let Some(value) = first(&ENV_HTTPS_PROXY) {
        return match parse_proxy_url(&value) {
            Ok(url) => Effective::proxied(url, no_proxy(), Source::Env),
            Err(e) => Effective::direct(Source::Env, Some(e.kind())),
        };
    }
    let all_refused = match first(&ENV_ALL_PROXY).map(|value| parse_proxy_url(&value)) {
        Some(Ok(url)) => return Effective::proxied(url, no_proxy(), Source::Env),
        Some(Err(e)) => Some(e),
        None => None,
    };
    let sys = system();
    if sys.https_enabled && !sys.host.trim_matches(is_space).is_empty() {
        return match sys.url() {
            Ok(url) => Effective::proxied(url, sys.bypass(), Source::System),
            Err(e) => Effective::direct(Source::System, Some(e.kind())),
        };
    }
    if sys.pac_or_wpad {
        return Effective::direct(Source::System, Some("pac"));
    }
    match all_refused {
        Some(e) => Effective::direct(Source::Env, Some(e.kind())),
        None => Effective::direct(Source::None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::cell::Cell;
    use std::collections::HashMap;

    fn vector(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared-vectors/rvn1/wss")
            .join(name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
        serde_json::from_str(&raw).unwrap()
    }

    fn url(text: &str) -> ProxyUrl {
        parse_proxy_url(text).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    /// The proxy setting and URL grammar against
    /// `shared-vectors/rvn1/wss/rws1_proxy_url_001.json` (the Python
    /// reference): auto/off, default port 80, a bare `host:port`,
    /// percent-decoded user parts and their Basic value, the redacted text;
    /// `https`, `socks` and PAC unsupported; every refusal code; the policy's
    /// credentials rule; Windows proxy strings.
    #[test]
    fn proxy_url_table() {
        let v = vector("rws1_proxy_url_001.json");
        assert_eq!(v["inputs"]["default_port"], u64::from(DEFAULT_PROXY_PORT));
        assert_eq!(v["inputs"]["max_text_bytes"], MAX_PROXY_TEXT as u64);
        let cases = v["expected"]["settings"].as_array().unwrap();
        assert!(cases.len() >= 40, "{}", cases.len());
        let mut codes = std::collections::BTreeSet::new();
        for case in cases {
            let input = case["input"].as_str().unwrap();
            assert_eq!(
                has_credentials(input),
                case["credentials"].as_bool().unwrap(),
                "{input}"
            );
            match parse_setting(input) {
                Ok(setting) => {
                    assert!(case.get("error").is_none(), "{input}: accepted");
                    assert_eq!(setting.to_string(), case["display"], "{input}");
                    match setting {
                        ProxySetting::Auto => assert_eq!(case["setting"], "auto", "{input}"),
                        ProxySetting::Off => assert_eq!(case["setting"], "off", "{input}"),
                        ProxySetting::Url(u) => {
                            assert_eq!(case["setting"], "url", "{input}");
                            assert_eq!(u.host(), case["host"], "{input}");
                            assert_eq!(u64::from(u.port()), case["port"], "{input}");
                            assert_eq!(u.basic(), case["basic"].as_str(), "{input}");
                            assert_eq!(u.has_credentials(), case["basic"].is_string());
                            // The canonical text without a credential reads back the same.
                            if !u.has_credentials() {
                                assert_eq!(url(&u.to_string()), u, "{input}");
                            }
                        }
                    }
                }
                Err(e) => {
                    assert_eq!(e.code(), case["error"], "{input}");
                    assert_eq!(e.kind(), case["kind"], "{input}");
                    codes.insert(e.code());
                }
            }
        }
        for code in [
            "https", "socks", "pac", "syntax", "too_long", "scheme", "userinfo", "host", "port",
            "path",
        ] {
            assert!(codes.contains(code), "no vector refuses with {code}");
        }
        let windows = v["expected"]["windows"].as_array().unwrap();
        assert!(windows.len() >= 8);
        for case in windows {
            let input = case["input"].as_str().unwrap();
            assert_eq!(
                parse_windows_proxy(input).as_deref(),
                case["entry"].as_str(),
                "{input}"
            );
        }
    }

    /// Bypass lists against `shared-vectors/rvn1/wss/rws1_no_proxy_001.json`:
    /// `*`, a domain with and without a leading dot on label boundaries
    /// (`notexample.com` is not under `example.com`), globs, IP addresses,
    /// CIDRs with the macOS short form (`169.254/16`), `:port`, `<local>`,
    /// separators, ignored entries, and loopback and link-local hosts that
    /// always bypass.
    #[test]
    fn no_proxy_table() {
        let v = vector("rws1_no_proxy_001.json");
        let lists = v["expected"]["lists"].as_array().unwrap();
        assert!(lists.len() >= 20, "{}", lists.len());
        let mut checks = 0;
        for case in lists {
            let list = case["list"].as_str().unwrap();
            let bypass = Bypass::parse(list);
            for check in case["checks"].as_array().unwrap() {
                let host = check["host"].as_str().unwrap();
                let port = u16::try_from(check["port"].as_u64().unwrap()).unwrap();
                assert_eq!(
                    bypass.bypasses(host, port),
                    check["bypass"].as_bool().unwrap(),
                    "{list:?}: {host} port {port}"
                );
                checks += 1;
            }
        }
        assert!(checks >= 80, "{checks}");
        // The separate entries of macOS ExceptionsList read as one list.
        let entries = ["*.local", "169.254/16", "10.0.0.0/8", ".example.com"];
        assert_eq!(
            Bypass::from_entries(entries),
            Bypass::parse(&entries.join(","))
        );
    }

    struct Env(HashMap<&'static str, &'static str>);

    impl Env {
        fn of(pairs: &[(&'static str, &'static str)]) -> Self {
            Self(pairs.iter().copied().collect())
        }

        fn get(&self, name: &str) -> Option<String> {
            self.0.get(name).map(|v| (*v).to_owned())
        }
    }

    fn macos_proxy() -> SystemProxy {
        SystemProxy {
            https_enabled: true,
            host: "sys.example".into(),
            port: 8080,
            exceptions: vec!["*.local".into(), "169.254/16".into(), "corp.example".into()],
            exclude_simple: true,
            pac_or_wpad: false,
        }
    }

    /// Which source decides: an explicit URL or `off` decides alone (neither
    /// the environment nor the system is asked); then `HTTPS_PROXY` before
    /// `https_proxy`, usable or not; an `http://` `ALL_PROXY`; the system
    /// (asked once, and only then), with its exceptions; PAC; an
    /// `ALL_PROXY` Raven cannot use; nothing.
    #[test]
    fn precedence_explicit_env_system_off() {
        let asked = Cell::new(0);
        let system = |sys: SystemProxy| {
            let asked = &asked;
            move || {
                asked.set(asked.get() + 1);
                sys
            }
        };
        let full = Env::of(&[
            ("HTTPS_PROXY", "http://env.example:3128"),
            ("https_proxy", "http://lower.example:3128"),
            ("ALL_PROXY", "http://all.example:3128"),
            ("NO_PROXY", ".corp.example"),
        ]);
        let explicit = ProxySetting::Url(url("http://set.example:8000"));

        // 1. The explicit setting decides alone.
        let e = effective(&explicit, |n| full.get(n), system(macos_proxy()));
        assert_eq!(e.source, Source::Setting);
        assert_eq!(e.proxy, Some(url("http://set.example:8000")));
        assert_eq!(e.bypass, Bypass::default());
        assert_eq!(e.proxy_for("relay.corp.example", 443), e.proxy.as_ref());
        assert_eq!(e.proxy_for("127.0.0.1", 443), None, "loopback is direct");
        let off = effective(&ProxySetting::Off, |n| full.get(n), system(macos_proxy()));
        assert_eq!(off, Effective::direct(Source::Setting, None));
        assert_eq!(off.proxy_for("relay.example.org", 443), None);
        assert_eq!(asked.get(), 0, "the system is not asked");

        // 2. The environment: HTTPS_PROXY first, with NO_PROXY.
        let auto = ProxySetting::Auto;
        let e = effective(&auto, |n| full.get(n), system(macos_proxy()));
        assert_eq!(
            (e.source, e.proxy.clone()),
            (Source::Env, Some(url("env.example:3128")))
        );
        assert_eq!(e.proxy_for("relay.corp.example", 443), None);
        assert_eq!(e.proxy_for("relay.example.org", 443), e.proxy.as_ref());
        let lower = Env::of(&[
            ("HTTPS_PROXY", "  "),
            ("https_proxy", "http://lower.example:3128"),
            ("no_proxy", "relay.example.org"),
        ]);
        let e = effective(&auto, |n| lower.get(n), system(macos_proxy()));
        assert_eq!(e.proxy, Some(url("lower.example:3128")), "empty is unset");
        assert!(e.bypass.bypasses("relay.example.org", 443));
        // An HTTPS_PROXY Raven cannot use decides too: direct, with why.
        for (value, kind) in [
            ("socks5://127.0.0.1:1080", "socks"),
            ("https://env.example", "https"),
            ("http://env.example:0", INVALID),
        ] {
            let env = Env::of(&[("HTTPS_PROXY", value), ("ALL_PROXY", "all.example:3128")]);
            let e = effective(&auto, |n| env.get(n), system(macos_proxy()));
            assert_eq!(e, Effective::direct(Source::Env, Some(kind)), "{value}");
        }
        // ALL_PROXY when it is http://.
        let all = Env::of(&[("all_proxy", "all.example:3128"), ("NO_PROXY", "*")]);
        let e = effective(&auto, |n| all.get(n), system(macos_proxy()));
        assert_eq!(
            (e.source, e.proxy.clone()),
            (Source::Env, Some(url("http://all.example:3128")))
        );
        assert_eq!(e.proxy_for("relay.example.org", 443), None, "NO_PROXY=*");
        assert_eq!(asked.get(), 0, "the environment decided");

        // 3. The system, asked once: its proxy and exceptions.
        let socks_all = Env::of(&[("ALL_PROXY", "socks5h://127.0.0.1:9050")]);
        let e = effective(&auto, |n| socks_all.get(n), system(macos_proxy()));
        assert_eq!(asked.get(), 1);
        assert_eq!(
            (e.source, e.proxy.clone(), e.unsupported.clone()),
            (Source::System, Some(url("sys.example:8080")), None)
        );
        for (host, direct) in [
            ("printer.local", true),
            ("intranet", true),
            ("relay.corp.example", true),
            ("169.254.1.2", true),
            ("relay.example.org", false),
            ("203.0.113.7", false),
        ] {
            assert_eq!(e.proxy_for(host, 443).is_none(), direct, "{host}");
        }
        // PAC with no HTTPS proxy: reported, direct.
        let pac = SystemProxy {
            pac_or_wpad: true,
            ..SystemProxy::default()
        };
        let none = Env::of(&[]);
        let e = effective(&auto, |n| none.get(n), system(pac.clone()));
        assert_eq!(e, Effective::direct(Source::System, Some("pac")));
        // An HTTPS proxy wins over PAC.
        let both = SystemProxy {
            pac_or_wpad: true,
            ..macos_proxy()
        };
        let e = effective(&auto, |n| none.get(n), system(both));
        assert_eq!(e.proxy, Some(url("sys.example:8080")));
        // A system proxy that does not parse: reported.
        let bad = SystemProxy {
            host: "https://sys.example".into(),
            port: 0,
            ..macos_proxy()
        };
        let e = effective(&auto, |n| none.get(n), system(bad));
        assert_eq!(e, Effective::direct(Source::System, Some("https")));
        // HTTPSEnable off: no proxy, the host is ignored.
        let disabled = SystemProxy {
            https_enabled: false,
            ..macos_proxy()
        };
        let e = effective(&auto, |n| none.get(n), system(disabled));
        assert_eq!(e, Effective::direct(Source::None, None));
        // An ALL_PROXY Raven cannot use, and nothing from the system.
        let e = effective(&auto, |n| socks_all.get(n), system(SystemProxy::default()));
        assert_eq!(e, Effective::direct(Source::Env, Some("socks")));
        // HTTP_PROXY is never read.
        let http_only = Env::of(&[("HTTP_PROXY", "http://env.example:3128")]);
        let e = effective(&auto, |n| http_only.get(n), system(SystemProxy::default()));
        assert_eq!(e, Effective::direct(Source::None, None));
        assert_eq!(asked.get(), 7);
    }

    /// Windows proxy strings: the `https=` entry, else the first bare one;
    /// `http=` and `socks=` alone give none; `;` or white space separate
    /// entries; an entry may carry `http://`. The entry and the bypass
    /// string go through SystemProxy into the effective proxy.
    #[test]
    fn windows_proxy_string_parsing() {
        let entry = |s: &str| parse_windows_proxy(s);
        assert_eq!(
            entry("http=a.example:1;https=b.example:2").as_deref(),
            Some("b.example:2")
        );
        assert_eq!(entry("b.example:2").as_deref(), Some("b.example:2"));
        assert_eq!(
            entry("http=a.example:1;b.example:2;c.example:3").as_deref(),
            Some("b.example:2")
        );
        assert_eq!(
            entry("b.example:2;HTTPS=c.example:3").as_deref(),
            Some("c.example:3")
        );
        assert_eq!(
            entry(" http=a.example:1  https=b.example:2 ").as_deref(),
            Some("b.example:2")
        );
        assert_eq!(
            entry("https=http://b.example:2").as_deref(),
            Some("http://b.example:2")
        );
        assert_eq!(
            entry("https=;socks=s.example:1080;c.example:3").as_deref(),
            Some("c.example:3")
        );
        for none in [
            "",
            ";;",
            "socks=s.example:1080",
            "http=a.example:1",
            "https=",
        ] {
            assert_eq!(entry(none), None, "{none:?}");
        }
        let sys = SystemProxy {
            https_enabled: true,
            host: entry("http=a.example:1;https=b.example:2").unwrap(),
            port: 0,
            exceptions: vec!["*.corp.example;10.*;<local>".into()],
            exclude_simple: false,
            pac_or_wpad: false,
        };
        let e = effective(&ProxySetting::Auto, |_| None, || sys);
        assert_eq!(e.source, Source::System);
        assert_eq!(e.proxy, Some(url("b.example:2")));
        for (host, direct) in [
            ("intranet", true),
            ("relay.corp.example", true),
            ("10.1.2.3", true),
            ("relay.example.org", false),
        ] {
            assert_eq!(e.proxy_for(host, 443).is_none(), direct, "{host}");
        }
        // macOS: a host and a port, IPv6 with or without brackets.
        for host in ["2001:db8::8", "[2001:db8::8]"] {
            let sys = SystemProxy {
                https_enabled: true,
                host: host.into(),
                port: 3128,
                ..SystemProxy::default()
            };
            assert_eq!(sys.url(), Ok(url("[2001:db8::8]:3128")), "{host}");
        }
    }

    // `Serialize` would make this ambiguous, so the test would not compile
    // (the static_assertions `assert_not_impl_any!` trick).
    trait NotSerialize<A> {
        fn check() {}
    }
    impl<T: ?Sized> NotSerialize<()> for T {}
    #[allow(dead_code)]
    struct IsSerialize;
    impl<T: ?Sized + serde::Serialize> NotSerialize<IsSerialize> for T {}

    /// The Basic value appears in no `Debug` or `Display` text of the URL,
    /// the setting or the effective proxy, nor in a refusal's message; none
    /// of them implements `Serialize` (a compile-time check).
    #[test]
    fn credentials_are_redacted_in_debug_and_display_and_never_serialized() {
        let _ = <ProxyUrl as NotSerialize<_>>::check;
        let _ = <ProxySetting as NotSerialize<_>>::check;
        let _ = <Effective as NotSerialize<_>>::check;
        let text = "http://raven-user:s3cret-pass@proxy.example:3128";
        let ProxySetting::Url(u) = parse_setting(text).unwrap() else {
            panic!("not a URL");
        };
        let basic = u.basic().unwrap().to_owned();
        assert_eq!(basic, STANDARD.encode("raven-user:s3cret-pass"));
        let e = effective(
            &ProxySetting::Url(u.clone()),
            |_| None,
            SystemProxy::default,
        );
        let shown = [
            format!("{u}"),
            format!("{u:?}"),
            format!("{u:#?}"),
            format!("{}", ProxySetting::Url(u.clone())),
            format!("{:?}", ProxySetting::Url(u.clone())),
            format!("{e:?}"),
        ];
        for s in &shown {
            for secret in ["raven-user", "s3cret", &basic] {
                assert!(!s.contains(secret), "{secret} in {s}");
            }
            assert!(
                s.contains("proxy.example") && s.contains("<redacted>"),
                "{s}"
            );
        }
        assert_eq!(shown[0], "http://<redacted>@proxy.example:3128");
        // Refusals never repeat the text.
        for bad in [
            "https://raven-user:s3cret@proxy.example",
            "http://raven-user:s3cret@proxy.example:0",
            "http://raven-user:s3%zzcret@proxy.example",
        ] {
            let err = parse_setting(bad).unwrap_err();
            for s in [err.to_string(), format!("{err:?}")] {
                assert!(!s.contains("s3cret") && !s.contains("raven-user"), "{s}");
            }
        }
        // A setting that carries a credential is the policy's to refuse.
        assert!(has_credentials(text) && !has_credentials("http://proxy.example:3128"));
    }

    /// An entry's port limits it to dials to that port; a bad port drops the
    /// entry.
    #[test]
    fn bypass_ports_and_ignored_entries() {
        let b = Bypass::parse("relay.example.org:443,[2001:db8::7]:443,10.0.0.0/8:7423");
        assert!(b.bypasses("relay.example.org", 443));
        assert!(!b.bypasses("relay.example.org", 8443));
        assert!(b.bypasses("[2001:db8::7]", 443) && !b.bypasses("2001:db8::7", 80));
        assert!(b.bypasses("10.9.9.9", 7423) && !b.bypasses("10.9.9.9", 443));
        let ignored = Bypass::parse("example.com:abc [::1 :443 10.0.0.0/33 -bad- 1.2.3.4/x");
        assert_eq!(ignored, Bypass::default());
        assert!(!ignored.bypasses("example.com", 443));
    }
}
