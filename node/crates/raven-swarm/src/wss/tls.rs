//! The TLS layer of RWS1 (§4): TLS 1.3 only, ALPN `http/1.1`, no session
//! resumption, on the aws-lc-rs provider that rustls is already built with
//! for libp2p-quic (this graph has no rustls `ring` or `tls12` feature). The
//! configs name the provider instead of relying on a process-wide default.
//!
//! **TLS is a wrapper, not an authenticator.** It is there so that a
//! restrictive network lets the connection through. libp2p Noise
//! authenticates the relay PeerId named by the dialled address
//! (`/p2p/<id>`), exactly as on raw TCP, and Raven Noise authenticates the
//! contact inside that. So the client accepts any server certificate (no
//! chain, name or expiry check), but the TLS 1.3 handshake signature must
//! still verify under the presented certificate's key (`OuterTlsOnly`, which
//! stays private to this file). TLS 1.2 is refused on both sides.
//!
//! A relay serves either an operator's PEM chain and key
//! ([`operator_server_tls`]) or a self-signed certificate made at each start
//! and never stored ([`ephemeral_server_tls`]): ECDSA P-256, an empty
//! subject, the configured names or `localhost`, a random 128-bit serial,
//! valid from an hour ago for 365 days, serverAuth, not a CA. It carries no
//! libp2p extension and no Raven or rcgen string, so the certificate does
//! not name the software behind it.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use rand::RngCore;
use rcgen::{
    CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, KeyPair, SerialNumber,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::NoServerSessionStorage;
use rustls::{
    ClientConfig, DigitallySignedStruct, PeerIncompatible, ServerConfig, SignatureScheme,
};
use zeroize::Zeroizing;

/// The one ALPN protocol both sides name (RWS1 §4): HTTP/1.1, which the
/// WebSocket upgrade runs on.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// An ephemeral certificate is valid from this long before it is made, for
/// a peer or middlebox whose clock runs a little behind ...
const EPHEMERAL_BACKDATE: time::Duration = time::Duration::hours(1);
/// ... until this long after it is made.
const EPHEMERAL_LIFETIME: time::Duration = time::Duration::days(365);

/// The largest operator PEM file read (a long chain is a few tens of KB).
const PEM_FILE_MAX: u64 = 1 << 20;

/// The provider of every config here: aws-lc-rs, the one rustls is built with.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The client's certificate check: none, except that the TLS 1.3 handshake
/// signature must verify under the key of the certificate the server sent
/// (so the server holds that key). Who the relay is, is libp2p Noise's
/// check (module docs).
#[derive(Debug)]
struct OuterTlsOnly(Arc<CryptoProvider>);

impl ServerCertVerifier for OuterTlsOnly {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Unreachable with a TLS 1.3-only config; refused all the same.
        Err(rustls::Error::PeerIncompatible(
            PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The client config of every WSS dial (RWS1 §4): TLS 1.3 only, ALPN
/// `http/1.1`, no client certificate, any server certificate (module docs),
/// and no session resumption: a ticket presented on the next dial would
/// link the two. SNI is the `ServerName` the caller dials: the `/dns*` or
/// `/sni/` name, or an IP address, for which rustls sends none.
pub fn client_tls() -> Arc<ClientConfig> {
    let provider = provider();
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the aws-lc-rs provider supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(OuterTlsOnly(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    config.resumption = Resumption::disabled();
    Arc::new(config)
}

/// A relay's server config with a fresh self-signed certificate (RWS1 §4
/// (b); module docs): `names` become its subjectAltNames (an IP literal an
/// IP SAN), `localhost` when there are none. Made at each relay start; the
/// certificate and its key live in memory only.
pub fn ephemeral_server_tls(names: &[String]) -> Result<Arc<ServerConfig>, String> {
    let (cert, key) = ephemeral_certificate(names)?;
    server_tls(vec![cert], key)
}

fn ephemeral_certificate(
    names: &[String],
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("certificate key: {e}"))?;
    let names = if names.is_empty() {
        vec!["localhost".to_string()]
    } else {
        names.to_vec()
    };
    let mut params = CertificateParams::new(names).map_err(|e| format!("certificate name: {e}"))?;
    // Never rcgen's default subject (CN "rcgen self signed cert").
    params.distinguished_name = DistinguishedName::new();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - EPHEMERAL_BACKDATE;
    params.not_after = now + EPHEMERAL_LIFETIME;
    // rcgen's default serial is a hash of the public key; this one is random.
    params.serial_number = Some(SerialNumber::from_slice(&random_serial()));
    params.is_ca = IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("certificate: {e}"))?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok((cert.der().clone(), key))
}

/// 128 random bits for a certificate serial (RFC 5280: a positive INTEGER
/// of at most 20 octets; rcgen adds the leading zero octet when needed).
fn random_serial() -> [u8; 16] {
    let mut serial = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut serial);
    serial
}

/// A relay's server config from the operator's own certificate (RWS1 §4
/// (a)): `chain_pem` holds the chain, leaf first, as PEM CERTIFICATE blocks;
/// `key_pem` its private key (PKCS#8, PKCS#1 or SEC1 PEM). A key that is not
/// the leaf's is refused. On unix, a key file its group or every user can
/// read is still used, with a warning on stderr.
pub fn operator_server_tls(chain_pem: &Path, key_pem: &Path) -> Result<Arc<ServerConfig>, String> {
    let chain_bytes = read_pem_file(chain_pem).map_err(|e| format!("certificate chain: {e}"))?;
    let chain = CertificateDer::pem_slice_iter(&chain_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate chain: {e}"))?;
    if chain.is_empty() {
        return Err("certificate chain: no CERTIFICATE block".into());
    }
    if let Some(warning) = key_file_warning(key_pem) {
        eprintln!("{warning}");
    }
    let key_bytes = read_pem_file(key_pem).map_err(|e| format!("private key: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| format!("private key: {e}"))?;
    server_tls(chain, key)
}

/// Reads a PEM file of at most [`PEM_FILE_MAX`] bytes into memory that is
/// wiped when dropped (it may hold the private key). The buffer is sized
/// from the file's length first, so reading does not reallocate it and
/// leave an unwiped copy behind.
fn read_pem_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let size = file
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0)
        .min(PEM_FILE_MAX);
    let mut bytes = Zeroizing::new(Vec::with_capacity(size as usize + 1));
    file.take(PEM_FILE_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > PEM_FILE_MAX {
        return Err(format!("larger than {PEM_FILE_MAX} bytes"));
    }
    Ok(bytes)
}

/// The warning for a private key file that its group or every user can read
/// (unix mode bits 0o044), or `None` (also when the file cannot be read; the
/// load that follows says why). A warning, not a refusal: the key only wraps
/// the connection (module docs).
#[cfg(unix)]
fn key_file_warning(key_pem: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(key_pem).ok()?.permissions().mode() & 0o777;
    let who = if mode & 0o004 != 0 {
        "every user"
    } else if mode & 0o040 != 0 {
        "its group"
    } else {
        return None;
    };
    Some(format!(
        "warning: the WSS private key file can be read by {who} (mode {mode:04o}); \
         restrict it with chmod 600"
    ))
}

#[cfg(not(unix))]
fn key_file_warning(_key_pem: &Path) -> Option<String> {
    None
}

/// TLS 1.3 only, no client certificate, ALPN `http/1.1` (a client that
/// offers no ALPN is served too), and no session tickets or session cache:
/// nothing a client could present to link two of its connections.
fn server_tls(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, String> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS 1.3: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("certificate and key: {e}"))?;
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use rcgen::Certificate;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use rustls::{CertificateError, ClientConnection, Connection, HandshakeKind, ServerConnection};
    use time::{Duration, OffsetDateTime};

    use super::*;

    /// Which side refused a handshake, and why.
    #[derive(Debug)]
    enum Refused {
        Client(rustls::Error),
        Server(rustls::Error),
    }

    /// Moves every queued TLS byte from `from` to `to`, which processes it:
    /// `to`'s error is returned. `Ok(true)` when anything moved.
    fn flow(from: &mut Connection, to: &mut Connection) -> Result<bool, rustls::Error> {
        let mut moved = false;
        while from.wants_write() {
            let mut bytes = Vec::new();
            from.write_tls(&mut bytes).unwrap();
            let mut rest = &bytes[..];
            while !rest.is_empty() {
                to.read_tls(&mut rest).unwrap();
            }
            to.process_new_packets()?;
            moved = true;
        }
        Ok(moved)
    }

    /// A whole handshake in memory, then whatever follows it (session
    /// tickets) until both sides are quiet. Returns (client, server).
    fn connect(
        client: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
        name: &str,
    ) -> Result<(Connection, Connection), Refused> {
        let name = ServerName::try_from(name).unwrap().to_owned();
        let mut c = Connection::Client(ClientConnection::new(client, name).unwrap());
        let mut s = Connection::Server(ServerConnection::new(server).unwrap());
        for _ in 0..16 {
            let up = flow(&mut c, &mut s).map_err(Refused::Server)?;
            let down = flow(&mut s, &mut c).map_err(Refused::Client)?;
            if !up && !down {
                assert!(
                    !c.is_handshaking() && !s.is_handshaking(),
                    "handshake stalled"
                );
                return Ok((c, s));
            }
        }
        panic!("the handshake did not settle");
    }

    /// A self-signed P-256 test certificate (rcgen's defaults otherwise).
    fn certificate(
        names: &[&str],
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> (Certificate, KeyPair) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let mut params = CertificateParams::new(names).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;
        (params.self_signed(&key).unwrap(), key)
    }

    fn key_der(key: &KeyPair) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
    }

    /// Serves one fixed certificate and signing key, matched or not.
    #[derive(Debug)]
    struct Serve(Arc<CertifiedKey>);

    impl ResolvesServerCert for Serve {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// A TLS 1.3 server that presents `cert` and signs with `signer`.
    fn server_presenting(cert: &Certificate, signer: &KeyPair) -> Arc<ServerConfig> {
        let signer = provider()
            .key_provider
            .load_private_key(key_der(signer))
            .unwrap();
        let certified = CertifiedKey::new(vec![cert.der().clone()], signer);
        let config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Serve(Arc::new(certified))));
        Arc::new(config)
    }

    /// A server with rustls's defaults, which do issue TLS 1.3 tickets
    /// (unlike [`server_tls`]).
    fn ticketing_server() -> Arc<ServerConfig> {
        let now = OffsetDateTime::now_utc();
        let (cert, key) = certificate(
            &["relay.example"],
            now - Duration::hours(1),
            now + Duration::days(1),
        );
        let config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der(&key))
            .unwrap();
        assert!(config.send_tls13_tickets > 0);
        Arc::new(config)
    }

    /// [`client_tls`], keeping session tickets (the resumption controls).
    fn resuming_client() -> Arc<ClientConfig> {
        let mut config = (*client_tls()).clone();
        config.resumption = Resumption::in_memory_sessions(8);
        Arc::new(config)
    }

    #[test]
    fn outer_tls_accepts_any_certificate_but_rejects_a_bad_handshake_signature() {
        // Self-signed, for another name, expired in 2002: accepted, since
        // the server signs the handshake with that certificate's key.
        let long_ago = OffsetDateTime::from_unix_timestamp(978_307_200).unwrap();
        let (cert, key) = certificate(
            &["elsewhere.example"],
            long_ago,
            long_ago + Duration::days(365),
        );
        let (client, _) = connect(
            client_tls(),
            server_presenting(&cert, &key),
            "relay.example",
        )
        .expect("any certificate is accepted");
        assert_eq!(
            client.peer_certificates().unwrap(),
            &[cert.der().clone()][..]
        );

        // The same certificate, the handshake signed by another key: the
        // CertificateVerify signature does not verify under the presented
        // key, and the client refuses.
        let (_, other) = certificate(&["elsewhere.example"], long_ago, long_ago);
        match connect(
            client_tls(),
            server_presenting(&cert, &other),
            "relay.example",
        )
        .map(|_| ())
        {
            Err(Refused::Client(rustls::Error::InvalidCertificate(
                CertificateError::BadSignature,
            ))) => {}
            other => panic!("expected a bad handshake signature, got {other:?}"),
        }
    }

    /// One TLS record: content type, record version 1.2, length, body.
    fn record(kind: u8, body: &[u8]) -> Vec<u8> {
        [&[kind, 3, 3][..], &with_len16(body)].concat()
    }

    /// One handshake message: type, 24-bit length, body.
    fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        [&[kind][..], &len[1..], body].concat()
    }

    fn with_len16(body: &[u8]) -> Vec<u8> {
        let len = u16::try_from(body.len()).unwrap().to_be_bytes();
        [&len[..], body].concat()
    }

    fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
        [&kind.to_be_bytes()[..], &with_len16(body)].concat()
    }

    /// A ClientHello that offers TLS 1.2 only: legacy version 1.2 and,
    /// with `versions`, a supported_versions extension listing 1.2 alone.
    fn tls12_client_hello(versions: bool) -> Vec<u8> {
        let mut extensions = [
            // supported_groups: secp256r1
            extension(0x000a, &with_len16(&[0x00, 0x17])),
            // ec_point_formats: uncompressed
            extension(0x000b, &[1, 0]),
            // signature_algorithms: ecdsa_secp256r1_sha256
            extension(0x000d, &with_len16(&[0x04, 0x03])),
        ]
        .concat();
        if versions {
            extensions.extend(extension(0x002b, &[2, 3, 3]));
        }
        let mut body = vec![3, 3];
        body.extend([7u8; 32]);
        body.push(0);
        // ECDHE-ECDSA and ECDHE-RSA with AES-128-GCM: TLS 1.2 suites only.
        body.extend(with_len16(&[0xc0, 0x2b, 0xc0, 0x2f]));
        body.extend([1, 0]);
        body.extend(with_len16(&extensions));
        record(0x16, &handshake_message(1, &body))
    }

    /// A ServerHello that picks TLS 1.2 (no supported_versions extension).
    fn tls12_server_hello() -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([9u8; 32]);
        body.push(0);
        body.extend([0xc0, 0x2b, 0]);
        body.extend(with_len16(&[]));
        record(0x16, &handshake_message(2, &body))
    }

    #[test]
    fn tls12_is_refused() {
        // The client, answered by a TLS 1.2 server.
        let name = ServerName::try_from("relay.example").unwrap().to_owned();
        let mut client = ClientConnection::new(client_tls(), name).unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let reply = tls12_server_hello();
        client.read_tls(&mut &reply[..]).unwrap();
        assert_eq!(
            client.process_new_packets().unwrap_err(),
            rustls::Error::PeerIncompatible(
                PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig
            )
        );

        // The server (ephemeral and operator configs share server_tls),
        // offered TLS 1.2 alone with and without supported_versions.
        for (versions, why) in [
            (false, PeerIncompatible::SupportedVersionsExtensionRequired),
            (true, PeerIncompatible::Tls12NotOfferedOrEnabled),
        ] {
            let mut server = ServerConnection::new(ephemeral_server_tls(&[]).unwrap()).unwrap();
            let hello = tls12_client_hello(versions);
            server.read_tls(&mut &hello[..]).unwrap();
            assert_eq!(
                server.process_new_packets().unwrap_err(),
                rustls::Error::PeerIncompatible(why)
            );
        }
    }

    /// Big-endian reads off the front of a byte slice.
    struct Bytes<'a>(&'a [u8]);

    impl<'a> Bytes<'a> {
        fn take(&mut self, n: usize) -> &'a [u8] {
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            head
        }

        fn u8(&mut self) -> u8 {
            self.take(1)[0]
        }

        fn u16(&mut self) -> u16 {
            let b = self.take(2);
            u16::from_be_bytes([b[0], b[1]])
        }
    }

    /// The cipher suites and the extensions (type, body) of the ClientHello
    /// a fresh client connection sends.
    fn client_hello_of(config: Arc<ClientConfig>, name: &str) -> (Vec<u16>, Vec<(u16, Vec<u8>)>) {
        let name = ServerName::try_from(name).unwrap().to_owned();
        let mut conn = ClientConnection::new(config, name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        let mut rec = Bytes(&out);
        assert_eq!(rec.u8(), 0x16, "a handshake record");
        rec.take(2);
        let len = usize::from(rec.u16());
        let mut msg = Bytes(rec.take(len));
        assert_eq!(msg.u8(), 1, "a ClientHello");
        msg.take(3 + 2 + 32); // length, legacy_version, random
        let n = usize::from(msg.u8());
        msg.take(n); // legacy_session_id
        let n = usize::from(msg.u16());
        let suites = msg
            .take(n)
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let n = usize::from(msg.u8());
        msg.take(n); // compression methods
        let n = usize::from(msg.u16());
        let mut list = Bytes(msg.take(n));
        let mut extensions = Vec::new();
        while !list.0.is_empty() {
            let kind = list.u16();
            let n = usize::from(list.u16());
            extensions.push((kind, list.take(n).to_vec()));
        }
        (suites, extensions)
    }

    #[test]
    fn client_config_is_tls13_only_alpn_http11_no_resumption() {
        let config = client_tls();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(
            !config.client_auth_cert_resolver.has_certs(),
            "no client certificate"
        );

        let (suites, extensions) = client_hello_of(config.clone(), "relay.example");
        assert!(
            suites.iter().all(|s| s >> 8 == 0x13),
            "TLS 1.3 suites only: {suites:04x?}"
        );
        let find = |kind: u16| {
            extensions
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, body)| body.clone())
        };
        assert_eq!(
            find(0x002b),
            Some(vec![2, 3, 4]),
            "supported_versions: 1.3 alone"
        );
        assert_eq!(
            find(0x0010),
            Some([&[0, 9, 8][..], b"http/1.1"].concat()),
            "ALPN: http/1.1 alone"
        );
        assert!(find(0x0000).is_some(), "SNI for a name");
        // No session_ticket, pre_shared_key or early_data.
        for kind in [0x0023, 0x0029, 0x002a] {
            assert_eq!(find(kind), None, "extension {kind:#06x}");
        }
        // An IP literal sends no SNI (RWS1 §4).
        let (_, extensions) = client_hello_of(config.clone(), "192.0.2.7");
        assert!(extensions.iter().all(|(kind, _)| *kind != 0x0000));

        // Two dials in a row never resume, even against a server that
        // issues tickets; the same server does resume a client that keeps
        // them (the control, which shows the check can fail).
        let server = ticketing_server();
        for (client, kind) in [
            (config, HandshakeKind::Full),
            (resuming_client(), HandshakeKind::Resumed),
        ] {
            connect(client.clone(), server.clone(), "relay.example").unwrap();
            let (second, _) = connect(client, server.clone(), "relay.example").unwrap();
            assert_eq!(second.handshake_kind(), Some(kind));
        }
    }

    #[test]
    fn server_config_is_tls13_only_alpn_http11_no_tickets() {
        let server = ephemeral_server_tls(&[]).unwrap();
        assert_eq!(server.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert_eq!(server.send_tls13_tickets, 0);

        // A client that keeps tickets (and resumes with a server that issues
        // them, client_config_is_tls13_only_alpn_http11_no_resumption) gets
        // none to resume with.
        let keeps = resuming_client();
        let (first, _) = connect(keeps.clone(), server.clone(), "localhost").unwrap();
        assert_eq!(first.alpn_protocol(), Some(ALPN_HTTP11));
        let (again, _) = connect(keeps, server.clone(), "localhost").unwrap();
        assert_eq!(
            again.handshake_kind(),
            Some(HandshakeKind::Full),
            "no ticket issued"
        );

        // A client that offers no ALPN is served; one that offers h2 first
        // gets http/1.1.
        for (offer, chosen) in [
            (vec![], None),
            (
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                Some(ALPN_HTTP11),
            ),
        ] {
            let mut config = (*client_tls()).clone();
            config.alpn_protocols = offer;
            let (client, _) = connect(Arc::new(config), server.clone(), "localhost").unwrap();
            assert_eq!(client.alpn_protocol(), chosen);
        }
        // One that offers ALPN without http/1.1 is refused by the server.
        let mut config = (*client_tls()).clone();
        config.alpn_protocols = vec![b"h2".to_vec()];
        match connect(Arc::new(config), server, "localhost").map(|_| ()) {
            Err(Refused::Server(rustls::Error::NoApplicationProtocol)) => {}
            other => panic!("expected the server to refuse h2 alone, got {other:?}"),
        }
    }

    /// One DER element: (tag, contents, what follows). DER lengths only.
    fn tlv(input: &[u8]) -> (u8, &[u8], &[u8]) {
        let mut b = Bytes(input);
        let tag = b.u8();
        let len = match b.u8() {
            n @ 0..=0x7f => usize::from(n),
            0x81 => usize::from(b.u8()),
            0x82 => usize::from(b.u16()),
            n => panic!("DER length form {n:#04x}"),
        };
        let contents = b.take(len);
        (tag, contents, b.0)
    }

    /// The elements of a constructed value's contents.
    fn items(mut input: &[u8]) -> Vec<(u8, &[u8])> {
        let mut out = Vec::new();
        while !input.is_empty() {
            let (tag, contents, rest) = tlv(input);
            out.push((tag, contents));
            input = rest;
        }
        out
    }

    /// The DER contents of an OBJECT IDENTIFIER, from its dotted form.
    fn oid(dotted: &str) -> Vec<u8> {
        let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
        let mut out = Vec::new();
        for arc in std::iter::once(arcs[0] * 40 + arcs[1]).chain(arcs[2..].iter().copied()) {
            let mut digits = vec![(arc & 0x7f) as u8];
            let mut rest = arc >> 7;
            while rest > 0 {
                digits.push((rest & 0x7f) as u8 | 0x80);
                rest >>= 7;
            }
            out.extend(digits.iter().rev());
        }
        out
    }

    /// A UTCTime or GeneralizedTime.
    fn time_of((tag, text): (u8, &[u8])) -> OffsetDateTime {
        let text = std::str::from_utf8(text).unwrap();
        let (year, rest) = match tag {
            0x17 => {
                let yy: i32 = text[..2].parse().unwrap();
                (if yy < 50 { 2000 + yy } else { 1900 + yy }, &text[2..])
            }
            0x18 => (text[..4].parse().unwrap(), &text[4..]),
            other => panic!("time tag {other:#04x}"),
        };
        assert!(
            rest.len() == 11 && rest.ends_with('Z'),
            "MMDDHHMMSSZ: {text}"
        );
        let n = |i: usize| -> u8 { rest[i..i + 2].parse().unwrap() };
        time::Date::from_calendar_date(year, time::Month::try_from(n(0)).unwrap(), n(2))
            .unwrap()
            .with_hms(n(4), n(6), n(8))
            .unwrap()
            .assume_utc()
    }

    /// The parts of an X.509 v3 certificate this module cares about.
    struct X509 {
        serial: Vec<u8>,
        signature: Vec<u8>,
        issuer: Vec<u8>,
        validity: (OffsetDateTime, OffsetDateTime),
        subject: Vec<u8>,
        key_algorithm: Vec<Vec<u8>>,
        public_key: Vec<u8>,
        /// (OID, critical, extnValue contents)
        extensions: Vec<(Vec<u8>, bool, Vec<u8>)>,
    }

    fn parse(der: &[u8]) -> X509 {
        let (tag, certificate, rest) = tlv(der);
        assert!(tag == 0x30 && rest.is_empty());
        let parts = items(certificate);
        assert_eq!(
            parts.len(),
            3,
            "tbsCertificate, signatureAlgorithm, signature"
        );
        let tbs = items(parts[0].1);
        assert_eq!(tbs.len(), 8, "version to extensions, no unique IDs");
        assert_eq!(tbs[0], (0xa0, &[2, 1, 2][..]), "X.509 v3");
        assert_eq!(tbs[1].0, 0x02);
        let algorithm = |(tag, contents): (u8, &[u8])| {
            assert_eq!(tag, 0x30);
            let fields = items(contents);
            assert_eq!(fields[0].0, 0x06);
            fields[0].1.to_vec()
        };
        assert_eq!(algorithm(parts[1]), algorithm(tbs[2]));
        assert_eq!(
            [tbs[3].0, tbs[4].0, tbs[5].0, tbs[6].0, tbs[7].0],
            [0x30, 0x30, 0x30, 0x30, 0xa3],
            "issuer, validity, subject, key, [3] extensions"
        );
        let validity = items(tbs[4].1);
        let key = items(tbs[6].1);
        assert_eq!((key[0].0, key[1].0), (0x30, 0x03));
        let (tag, list, rest) = tlv(tbs[7].1);
        assert!(tag == 0x30 && rest.is_empty());
        let extensions = items(list)
            .into_iter()
            .map(|(tag, extension)| {
                assert_eq!(tag, 0x30);
                let fields = items(extension);
                let critical = fields.len() == 3 && fields[1] == (0x01, &[0xff][..]);
                let (value_tag, value) = fields[fields.len() - 1];
                assert_eq!((fields[0].0, value_tag), (0x06, 0x04));
                (fields[0].1.to_vec(), critical, value.to_vec())
            })
            .collect();
        X509 {
            serial: tbs[1].1.to_vec(),
            signature: algorithm(tbs[2]),
            issuer: tbs[3].1.to_vec(),
            validity: (time_of(validity[0]), time_of(validity[1])),
            subject: tbs[5].1.to_vec(),
            key_algorithm: items(key[0].1)
                .into_iter()
                .map(|(tag, o)| {
                    assert_eq!(tag, 0x06);
                    o.to_vec()
                })
                .collect(),
            public_key: key[1].1.to_vec(),
            extensions,
        }
    }

    /// The certificate a fresh ephemeral relay config presents to a client.
    fn ephemeral_presented(names: &[String]) -> Vec<u8> {
        let server = ephemeral_server_tls(names).unwrap();
        let (client, _) = connect(client_tls(), server, "relay.example").unwrap();
        let chain = client.peer_certificates().unwrap();
        assert_eq!(chain.len(), 1, "the leaf alone");
        chain[0].to_vec()
    }

    #[test]
    fn ephemeral_certificate_profile() {
        let names = ["relay.example".to_string(), "192.0.2.7".to_string()];
        let before = OffsetDateTime::now_utc();
        let der = ephemeral_presented(&names);
        let after = OffsetDateTime::now_utc();
        let cert = parse(&der);

        assert_eq!(
            cert.signature,
            oid("1.2.840.10045.4.3.2"),
            "ecdsa-with-SHA256"
        );
        assert_eq!(
            cert.key_algorithm,
            vec![oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")],
            "an EC key on P-256"
        );
        assert_eq!(
            cert.public_key.len(),
            66,
            "a BIT STRING of one uncompressed point"
        );
        assert_eq!(&cert.public_key[..2], &[0, 4]);
        assert!(
            cert.issuer.is_empty() && cert.subject.is_empty(),
            "empty DN"
        );

        // A positive INTEGER of at most 128 bits, not rcgen's 20-octet
        // public-key hash; another start gets another serial and key.
        assert_eq!(cert.serial[0] & 0x80, 0, "positive");
        let magnitude = match cert.serial.as_slice() {
            [0, rest @ ..] if !rest.is_empty() => rest,
            all => all,
        };
        assert!(magnitude.len() <= 16 && magnitude.iter().any(|b| *b != 0));
        let other = parse(&ephemeral_presented(&names));
        assert_ne!(other.serial, cert.serial);
        assert_ne!(other.public_key, cert.public_key);

        // Valid from an hour before it was made for 365 days (UTCTime
        // drops the fraction of a second).
        let second = Duration::seconds(1);
        let (not_before, not_after) = cert.validity;
        let back = EPHEMERAL_BACKDATE;
        assert!(before - back - second <= not_before && not_before <= after - back);
        let year = EPHEMERAL_LIFETIME;
        assert_eq!(year, Duration::days(365));
        assert!(before + year - second <= not_after && not_after <= after + year);

        let ids: BTreeSet<Vec<u8>> = cert
            .extensions
            .iter()
            .map(|(id, _, _)| id.clone())
            .collect();
        let expected: BTreeSet<Vec<u8>> = ["2.5.29.17", "2.5.29.14", "2.5.29.37", "2.5.29.19"]
            .map(oid)
            .into_iter()
            .collect();
        assert_eq!(
            ids, expected,
            "SAN, subject key id, EKU and basic constraints alone"
        );
        let value = |id: &str| {
            let (_, critical, value) = cert
                .extensions
                .iter()
                .find(|(o, _, _)| *o == oid(id))
                .unwrap();
            let (tag, contents, rest) = tlv(value);
            assert!(tag == 0x30 && rest.is_empty());
            (*critical, contents.to_vec())
        };
        let (_, san) = value("2.5.29.17");
        assert_eq!(
            items(&san),
            vec![(0x82, &b"relay.example"[..]), (0x87, &[192, 0, 2, 7][..])],
            "dNSName and iPAddress"
        );
        let (_, eku) = value("2.5.29.37");
        assert_eq!(
            items(&eku),
            vec![(0x06, &oid("1.3.6.1.5.5.7.3.1")[..])],
            "serverAuth"
        );
        let (critical, constraints) = value("2.5.29.19");
        assert!(critical);
        let constraints = items(&constraints);
        assert!(
            constraints.is_empty() || constraints == [(0x01, &[0][..])],
            "cA false, no path length: {constraints:?}"
        );

        // Nothing names the software: no Raven or rcgen string, and not
        // libp2p's TLS certificate extension.
        for word in [&b"rcgen"[..], &b"raven"[..]] {
            assert!(!der
                .windows(word.len())
                .any(|w| w.eq_ignore_ascii_case(word)));
        }
        let libp2p = oid("1.3.6.1.4.1.53594.1.1");
        assert!(!der.windows(libp2p.len()).any(|w| w == libp2p));

        // No names: localhost.
        let cert = parse(&ephemeral_presented(&[]));
        let san = cert
            .extensions
            .iter()
            .find(|(o, _, _)| *o == oid("2.5.29.17"))
            .unwrap();
        let (_, list, _) = tlv(&san.2);
        assert_eq!(items(list), vec![(0x82, &b"localhost"[..])]);
    }

    #[cfg(unix)]
    #[test]
    fn operator_cert_loads_pem_and_warns_on_world_readable_key() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let now = OffsetDateTime::now_utc();
        let valid = (now - Duration::hours(1), now + Duration::days(90));
        let (leaf, key) = certificate(&["relay.example"], valid.0, valid.1);
        let (issuer, _) = certificate(&["issuer.example"], valid.0, valid.1);
        let chain = dir.path().join("chain.pem");
        std::fs::write(&chain, leaf.pem() + &issuer.pem()).unwrap();
        let write_key = |name: &str, key: &KeyPair| {
            let path = dir.path().join(name);
            std::fs::write(&path, key.serialize_pem()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            path
        };
        let key_pem = write_key("key.pem", &key);

        assert_eq!(key_file_warning(&key_pem), None);
        let server = operator_server_tls(&chain, &key_pem).unwrap();
        let (client, _) = connect(client_tls(), server, "relay.example").unwrap();
        assert_eq!(
            client.peer_certificates().unwrap(),
            &[leaf.der().clone(), issuer.der().clone()][..],
            "the whole chain, leaf first"
        );

        for (mode, who) in [
            (0o644, "every user"),
            (0o604, "every user"),
            (0o640, "its group"),
        ] {
            std::fs::set_permissions(&key_pem, std::fs::Permissions::from_mode(mode)).unwrap();
            let warning = key_file_warning(&key_pem).expect("a warning");
            assert!(warning.contains(who), "{warning}");
            assert!(warning.contains(&format!("(mode {mode:04o})")), "{warning}");
            assert!(
                operator_server_tls(&chain, &key_pem).is_ok(),
                "a warning, not a refusal"
            );
        }
        std::fs::set_permissions(&key_pem, std::fs::Permissions::from_mode(0o600)).unwrap();

        let (_, stranger) = certificate(&["relay.example"], valid.0, valid.1);
        let stranger = write_key("stranger.pem", &stranger);
        let refusals = [
            (&chain, &stranger, "certificate and key: "),
            (
                &key_pem,
                &key_pem,
                "certificate chain: no CERTIFICATE block",
            ),
            (&chain, &chain, "private key: "),
        ];
        for (chain_pem, key_pem, why) in refusals {
            let err = operator_server_tls(chain_pem, key_pem).unwrap_err();
            assert!(err.starts_with(why), "{err}");
        }
        let missing = dir.path().join("missing.pem");
        let err = operator_server_tls(&missing, &key_pem).unwrap_err();
        assert!(err.starts_with("certificate chain: "), "{err}");
    }

    /// The custom verifier is built here and nowhere else: no other Raven
    /// source makes a TLS config that skips certificate checks.
    #[test]
    fn the_custom_verifier_is_built_only_in_wss_tls() {
        fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().into_owned();
                let kind = entry.file_type().unwrap();
                if kind.is_dir() && !name.starts_with('.') && name != "target" {
                    rust_files(&entry.path(), out);
                } else if kind.is_file() && name.ends_with(".rs") {
                    out.push(entry.path());
                }
            }
        }

        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let node = manifest.join("../..");
        let mut files = Vec::new();
        for dir in ["crates", "fuzz"] {
            if node.join(dir).is_dir() {
                rust_files(&node.join(dir), &mut files);
            }
        }
        assert!(files.len() > 100, "the scan found the sources");
        let users: Vec<PathBuf> = files
            .iter()
            .filter(|f| {
                std::fs::read_to_string(f)
                    .unwrap()
                    .contains("with_custom_certificate_verifier")
            })
            .map(|f| f.canonicalize().unwrap())
            .collect();
        let this = manifest.join("src/wss/tls.rs").canonicalize().unwrap();
        assert_eq!(users, vec![this]);
    }
}
