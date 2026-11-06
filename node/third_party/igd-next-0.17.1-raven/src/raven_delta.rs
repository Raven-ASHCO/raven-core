//! The Raven patch of igd-next 0.17.1 (`RAVEN_DELTA.md`, STRANGER-UPNP-1).
//!
//! UPnP-IGD has no authentication. Upstream took the first SSDP answer from
//! anyone on the network, fetched the description its LOCATION named and
//! parsed every response whole, however large or deep; xmltree builds its
//! tree with one stack frame per level, so a deeply nested description from
//! a stranger on the LAN aborted the program (a stack overflow is no panic).
//! Here:
//!
//! - the async search (`aio::tokio::search_gateway`) takes an answer only
//!   when it comes from `SearchOptions::gateway`, the IPv4 default router,
//!   and its LOCATION names that same address; any other answer is ignored
//!   and the search keeps waiting. With no router known it sends no search
//!   and fails at once (`NoResponseWithinTimeout`);
//! - the async client refuses (`InvalidResponse`) an SSDP answer longer
//!   than its 1500 byte buffer instead of cutting it, and a description or
//!   SOAP body longer than [`MAX_DESCRIPTION`] or [`MAX_SOAP_RESPONSE`],
//!   before any of it is parsed;
//! - every XML document, in the async and the blocking API alike, is
//!   refused (`InvalidResponse`) before xmltree parses it when its elements
//!   nest deeper than [`MAX_XML_DEPTH`] or it declares a document type.

use std::io;
use std::net::Ipv4Addr;
#[cfg(feature = "aio_tokio")]
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use crate::errors::SearchError;
#[cfg(feature = "aio_tokio")]
use crate::RequestError;

/// The largest device or service description (SCPD) read: 64 KiB. Real
/// ones are about 2 to 20 KB (a router listing many services and icons),
/// so this is three times the largest, and it bounds what a router can make
/// the client hold.
#[cfg(feature = "aio_tokio")]
pub(crate) const MAX_DESCRIPTION: usize = 64 * 1024;

/// The largest SOAP control response read: 16 KiB. Real ones are under
/// 2 KB (an external address, a port mapping entry or a UPnP error).
#[cfg(feature = "aio_tokio")]
pub(crate) const MAX_SOAP_RESPONSE: usize = 16 * 1024;

/// The deepest element nesting parsed. Real IGD descriptions nest about 9
/// levels (root, device, deviceList, device, deviceList, device,
/// serviceList, service, controlURL) and SOAP responses 4; 32 frames of
/// xmltree fit any stack.
pub(crate) const MAX_XML_DEPTH: usize = 32;

static GATEWAY_LOOKUP: OnceLock<fn() -> Option<Ipv4Addr>> = OnceLock::new();

/// Raven: sets, once per process, how `SearchOptions::default()` finds the
/// IPv4 default router, the only address whose search answer is taken. It
/// is asked again for every default (a network change moves the router).
/// A later call changes nothing and returns false. Without a lookup the
/// default is `None`, and a search takes no answer.
pub fn set_gateway_lookup(lookup: fn() -> Option<Ipv4Addr>) -> bool {
    GATEWAY_LOOKUP.set(lookup).is_ok()
}

/// The default of `SearchOptions::gateway`: what the lookup finds.
pub(crate) fn default_gateway() -> Option<Ipv4Addr> {
    GATEWAY_LOOKUP.get().and_then(|lookup| lookup())
}

/// Is this the default router's answer: sent from `gateway`, with its
/// LOCATION on `gateway` too? An IPv4 address that a dual stack socket
/// reports as IPv4 mapped IPv6 counts as itself.
#[cfg(feature = "aio_tokio")]
pub(crate) fn from_gateway(gateway: Ipv4Addr, from: &SocketAddr, location: &SocketAddr) -> bool {
    let gateway = IpAddr::V4(gateway);
    from.ip().to_canonical() == gateway && location.ip().to_canonical() == gateway
}

/// A body read up to `cap` bytes; a longer one fails with http-body-util's
/// `LengthLimitError` before the rest is read.
#[cfg(feature = "aio_tokio")]
pub(crate) async fn read_capped(
    body: hyper::body::Incoming,
    cap: usize,
) -> Result<bytes::Bytes, Box<dyn std::error::Error + Send + Sync>> {
    use http_body_util::BodyExt;
    Ok(http_body_util::Limited::new(body, cap).collect().await?.to_bytes())
}

/// A capped description that could not be read: the transport error as
/// upstream reports it, or (a longer body) refused.
#[cfg(feature = "aio_tokio")]
pub(crate) fn search_body_error(err: Box<dyn std::error::Error + Send + Sync>) -> SearchError {
    match err.downcast::<hyper::Error>() {
        Ok(err) => SearchError::HyperError(*err),
        Err(_) => SearchError::InvalidResponse,
    }
}

/// A capped SOAP response that could not be read: the transport error as
/// upstream reports it, or (a longer body) refused.
#[cfg(feature = "aio_tokio")]
pub(crate) fn request_body_error(err: Box<dyn std::error::Error + Send + Sync>) -> RequestError {
    match err.downcast::<hyper::Error>() {
        Ok(err) => RequestError::HyperError(*err),
        Err(_) => RequestError::InvalidResponse(format!("a response longer than {MAX_SOAP_RESPONSE} bytes")),
    }
}

/// A description read whole for xmltree, refused (`InvalidResponse`) when
/// it is not [`xml_shallow`].
pub(crate) fn shallow_xml<R: io::Read>(mut xml: R) -> Result<Vec<u8>, SearchError> {
    let mut bytes = Vec::new();
    xml.read_to_end(&mut bytes)?;
    if xml_shallow(&bytes) {
        Ok(bytes)
    } else {
        Err(SearchError::InvalidResponse)
    }
}

/// Does `xml` nest its elements at most [`MAX_XML_DEPTH`] deep, with no
/// document type declaration? A byte scan before xmltree parses it, made
/// to never count fewer levels than the parser sees: a comment, a CDATA
/// section or a processing instruction is skipped whole, and a quoted
/// attribute value inside a tag; every other `<` that opens no end tag
/// counts as an element (a self closing one too, while it is checked).
/// Refused as well: any other `<!` (a DOCTYPE, whose entities could expand
/// to elements), a construct left open, and UTF-16 (a byte order mark; the
/// scan reads ASCII bytes, as UTF-8 and the 8 bit encodings xml-rs knows
/// write them).
pub(crate) fn xml_shallow(xml: &[u8]) -> bool {
    if xml.starts_with(&[0xFE, 0xFF]) || xml.starts_with(&[0xFF, 0xFE]) {
        return false;
    }
    let mut depth = 0usize;
    let mut at = 0;
    while let Some(open) = find(xml, at, b"<") {
        let rest = &xml[open + 1..];
        let end = if rest.starts_with(b"!--") {
            find(xml, open + 4, b"-->").map(|end| end + 3)
        } else if rest.starts_with(b"![CDATA[") {
            find(xml, open + 9, b"]]>").map(|end| end + 3)
        } else if rest.starts_with(b"?") {
            find(xml, open + 2, b"?>").map(|end| end + 2)
        } else if rest.starts_with(b"!") {
            return false;
        } else if rest.starts_with(b"/") {
            depth = depth.saturating_sub(1);
            find(xml, open + 2, b">").map(|end| end + 1)
        } else {
            depth += 1;
            if depth > MAX_XML_DEPTH {
                return false;
            }
            tag_end(xml, open + 1).map(|(end, self_closing)| {
                if self_closing {
                    depth -= 1;
                }
                end
            })
        };
        match end {
            Some(end) => at = end,
            None => return false,
        }
    }
    true
}

/// The first index of `needle` in `xml` at or after `from`.
fn find(xml: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    xml.get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| from + at)
}

/// Just past the `>` that ends the start tag whose name begins at `from`
/// (quoted attribute values skipped), and whether it ends with `/>`.
fn tag_end(xml: &[u8], from: usize) -> Option<(usize, bool)> {
    let mut quote = None;
    for (offset, &byte) in xml.get(from..)?.iter().enumerate() {
        match quote {
            Some(open) if byte == open => quote = None,
            Some(_) => {}
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            None if byte == b'>' => {
                let at = from + offset;
                return Some((at + 1, at > from && xml[at - 1] == b'/'));
            }
            None => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::parsing::{parse_control_urls, parse_response, parse_schemas};
    use crate::RequestError;

    /// A minimal IGD description whose elements nest exactly `depth` deep
    /// (9 or more): the vendor elements that make the depth sit in `device`.
    pub(super) fn description(depth: usize) -> String {
        let vendor = depth - 2;
        format!(
            r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<serviceList>
<service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<SCPDURL>/scpd.xml</SCPDURL>
<controlURL>/ctl</controlURL>
</service>
</serviceList>
{}{}
</device>
</root>
"#,
            "<x>".repeat(vendor),
            "</x>".repeat(vendor)
        )
    }

    fn refused(text: &str) -> bool {
        matches!(parse_control_urls(text.as_bytes()), Err(SearchError::InvalidResponse))
    }

    /// On a small stack, as a tokio worker has a bounded one.
    fn on_a_small_stack(work: impl FnOnce() -> bool + Send + 'static) -> bool {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(work)
            .expect("a thread")
            .join()
            .expect("no panic")
    }

    /// Upstream: xmltree recursed once per level until the stack overflowed,
    /// which aborts the whole program.
    #[test]
    fn a_deeply_nested_description_is_refused_not_a_stack_overflow() {
        let deep = "<a>".repeat(100_000);
        assert!(on_a_small_stack(move || {
            matches!(parse_control_urls(deep.as_bytes()), Err(SearchError::InvalidResponse))
                && matches!(parse_schemas(deep.as_bytes()), Err(SearchError::InvalidResponse))
        }));
    }

    #[test]
    fn a_deeply_nested_soap_response_is_refused_not_a_stack_overflow() {
        let deep = format!(
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>{}"#,
            "<a>".repeat(100_000)
        );
        assert!(on_a_small_stack(move || matches!(
            parse_response(deep, "GetExternalIPAddressResponse"),
            Err(RequestError::InvalidResponse(_))
        )));
    }

    #[test]
    fn nesting_deeper_than_32_levels_is_refused() {
        let urls = parse_control_urls(description(MAX_XML_DEPTH).as_bytes()).expect("32 levels are parsed");
        assert_eq!(urls, ("/scpd.xml".to_string(), "/ctl".to_string()));
        assert!(refused(&description(MAX_XML_DEPTH + 1)), "33 levels were parsed");
        // A self closing element counts while it is open.
        assert!(refused(&description(MAX_XML_DEPTH).replacen("</x>", "<z/></x>", 1)));
        assert!(!refused(
            &description(MAX_XML_DEPTH - 1).replacen("</x>", "<z/></x>", 1)
        ));
    }

    #[test]
    fn a_document_type_declaration_is_refused() {
        let text = description(9).replacen("<root", "<!DOCTYPE root [<!ENTITY e \"x\">]>\n<root", 1);
        assert!(refused(&text), "a DOCTYPE was parsed");
    }

    #[test]
    fn the_scan_counts_levels_as_the_parser_does() {
        // A quoted "/>" or ">" ends no tag: these 33 levels stay 33.
        let quoted = description(MAX_XML_DEPTH + 1).replace("<x>", r#"<x a="/>" b='>'>"#);
        assert!(refused(&quoted), "a quoted end of tag was taken for one");
        // Markup in a comment, a CDATA section or a processing instruction
        // is no element.
        let markup = "<y>".repeat(50);
        let skipped = description(MAX_XML_DEPTH).replacen(
            "<deviceType>",
            &format!("<!-- {markup} --><![CDATA[{markup}]]><?raven {markup}?><deviceType>"),
            1,
        );
        assert!(!refused(&skipped));
        // A construct left open, and UTF-16, are refused.
        assert!(!xml_shallow(b"<root><!-- open"));
        assert!(!xml_shallow(b"<root a=\"open>"));
        assert!(!xml_shallow(&[0xFF, 0xFE, b'<', 0, b'a', 0, b'>', 0]));
    }

    #[test]
    fn the_lookup_sets_the_default_router_once() {
        let router = Ipv4Addr::new(192, 0, 2, 1);
        assert!(set_gateway_lookup(|| Some(Ipv4Addr::new(192, 0, 2, 1))));
        assert_eq!(crate::SearchOptions::default().gateway, Some(router));
        assert!(!set_gateway_lookup(|| None), "a second lookup was taken");
        assert_eq!(crate::SearchOptions::default().gateway, Some(router));
    }

    #[cfg(feature = "aio_tokio")]
    #[test]
    fn only_the_router_answers() {
        let router = Ipv4Addr::new(192, 0, 2, 1);
        let at = |ip: &str| -> SocketAddr { format!("{ip}:5000").parse().expect("an address") };
        assert!(from_gateway(router, &at("192.0.2.1"), &at("192.0.2.1")));
        assert!(from_gateway(router, &at("[::ffff:192.0.2.1]"), &at("192.0.2.1")));
        assert!(!from_gateway(router, &at("192.0.2.66"), &at("192.0.2.1")));
        assert!(!from_gateway(router, &at("192.0.2.1"), &at("192.0.2.66")));
        assert!(!from_gateway(router, &at("[2001:db8::1]"), &at("192.0.2.1")));
    }

    /// The async search and client against a router and a stranger played on
    /// the loopback (nothing leaves this computer).
    #[cfg(feature = "aio_tokio")]
    mod search {
        use super::description;
        use crate::aio::tokio::{search_gateway, Tokio};
        use crate::aio::Gateway;
        use crate::raven_delta::{MAX_DESCRIPTION, MAX_SOAP_RESPONSE, MAX_XML_DEPTH};
        use crate::{GetExternalIpError, RequestError, SearchError, SearchOptions};
        use std::future::Future;
        use std::io::{Read, Write};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
        use std::time::Duration;

        const LO: Ipv4Addr = Ipv4Addr::LOCALHOST;
        const SCPD: &str = r#"<?xml version="1.0"?><scpd xmlns="urn:schemas-upnp-org:service-1-0"><actionList><action><name>GetExternalIPAddress</name><argumentList/></action></actionList></scpd>"#;

        fn block_on<F: Future>(work: F) -> F::Output {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime")
                .block_on(work)
        }

        /// A GetExternalIPAddress response naming 203.0.113.9, `padding`
        /// long in a comment.
        fn soap(padding: usize) -> String {
            format!(
                r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><!-- {} --><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>203.0.113.9</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"#,
                "p".repeat(padding)
            )
        }

        /// A router web server on 127.0.0.1: `description` for a GET, the
        /// SCPD at /scpd.xml, `soap` for a POST. Its port.
        fn web(description: String, soap: String) -> u16 {
            let listener = TcpListener::bind((LO, 0)).expect("a listener");
            let port = listener.local_addr().expect("its address").port();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    let head = read_request(&mut stream);
                    let body = if head.starts_with("POST") {
                        soap.as_str()
                    } else if head.contains(" /scpd.xml ") {
                        SCPD
                    } else {
                        description.as_str()
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            });
            port
        }

        /// Reads one request whole; its head.
        fn read_request(stream: &mut TcpStream) -> String {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => break,
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let length = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; length];
            let _ = stream.read_exact(&mut body);
            head
        }

        /// An SSDP answer naming `location`.
        fn answer(location: &str) -> Vec<u8> {
            format!(
                "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nEXT:\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: {location}\r\n\r\n"
            )
            .into_bytes()
        }

        fn at(ip: &str, port: u16) -> String {
            format!("http://{ip}:{port}/desc")
        }

        /// The multicast group, played on `group`: it waits for the M-SEARCH,
        /// then sends each answer from a socket on its address, in order.
        fn ssdp(group: IpAddr, answers: Vec<(IpAddr, Vec<u8>)>) -> SocketAddr {
            let socket = UdpSocket::bind((group, 0)).expect("a group socket");
            let addr = socket.local_addr().expect("its address");
            std::thread::spawn(move || {
                let mut search = [0u8; 2048];
                let Ok((_, searcher)) = socket.recv_from(&mut search) else {
                    return;
                };
                for (from, answer) in answers {
                    let to: SocketAddr = match from {
                        IpAddr::V4(_) => (LO, searcher.port()).into(),
                        IpAddr::V6(_) => (Ipv6Addr::LOCALHOST, searcher.port()).into(),
                    };
                    let sender = UdpSocket::bind((from, 0)).expect("a sender");
                    sender.send_to(&answer, to).expect("an answer sent");
                }
            });
            addr
        }

        fn search(bind: IpAddr, group: SocketAddr, gateway: Option<Ipv4Addr>) -> Result<Gateway<Tokio>, SearchError> {
            block_on(search_gateway(SearchOptions {
                bind_addr: (bind, 0).into(),
                broadcast_address: group,
                timeout: Some(Duration::from_secs(5)),
                single_search_timeout: Some(Duration::from_secs(5)),
                gateway,
            }))
        }

        /// A router answers, one service: found, and its external address read.
        #[test]
        fn the_routers_answer_is_taken() {
            let router = web(description(9), soap(1));
            let group = ssdp(LO.into(), vec![(LO.into(), answer(&at("127.0.0.1", router)))]);
            let gateway = search(LO.into(), group, Some(LO)).expect("the router answered");
            assert_eq!(gateway.addr, SocketAddr::from((LO, router)));
            assert_eq!(
                (gateway.control_url.as_str(), gateway.control_schema_url.as_str()),
                ("/ctl", "/scpd.xml")
            );
            let external = block_on(gateway.get_external_ip()).expect("an external address");
            assert_eq!(external, IpAddr::from([203, 0, 113, 9]));
        }

        /// STRANGER-UPNP-1: another host on the network answers first.
        #[cfg(not(windows))] // one socket for IPv4 and IPv6
        #[test]
        fn an_answer_from_another_address_is_ignored() {
            if UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).is_err() {
                eprintln!("note: skipped: this host has no IPv6 loopback");
                return;
            }
            let stranger = web(description(9), soap(1));
            let router = web(description(9), soap(1));
            let group = ssdp(
                Ipv6Addr::LOCALHOST.into(),
                vec![
                    (Ipv6Addr::LOCALHOST.into(), answer(&at("127.0.0.1", stranger))),
                    (LO.into(), answer(&at("127.0.0.1", router))),
                ],
            );
            let gateway = search(Ipv6Addr::UNSPECIFIED.into(), group, Some(LO)).expect("the router answered");
            assert_eq!(gateway.addr.port(), router, "the answer of the stranger was taken");
        }

        /// An answer from the router address whose LOCATION names another
        /// host (0.0.0.0 reaches the loopback, as another host would be
        /// reached).
        #[cfg(unix)]
        #[test]
        fn an_answer_naming_another_host_is_ignored() {
            let stranger = web(description(9), soap(1));
            let router = web(description(9), soap(1));
            let group = ssdp(
                LO.into(),
                vec![
                    (LO.into(), answer(&at("0.0.0.0", stranger))),
                    (LO.into(), answer(&at("127.0.0.1", router))),
                ],
            );
            let gateway = search(LO.into(), group, Some(LO)).expect("the router answered");
            assert_eq!(gateway.addr.port(), router, "a LOCATION on another host was taken");
        }

        #[test]
        fn without_a_known_router_no_answer_is_taken() {
            let router = web(description(9), soap(1));
            let group = ssdp(LO.into(), vec![(LO.into(), answer(&at("127.0.0.1", router)))]);
            let result = search(LO.into(), group, None);
            assert!(
                matches!(result, Err(SearchError::NoResponseWithinTimeout)),
                "{result:?}"
            );
        }

        #[test]
        fn an_oversized_search_answer_is_refused() {
            let cut = web(description(9), soap(1));
            let router = web(description(9), soap(1));
            let mut long = answer(&at("127.0.0.1", cut));
            long.truncate(long.len() - 2);
            long.extend_from_slice(format!("X-PAD: {}\r\n\r\n", "p".repeat(1600)).as_bytes());
            let group = ssdp(
                LO.into(),
                vec![(LO.into(), long), (LO.into(), answer(&at("127.0.0.1", router)))],
            );
            let gateway = search(LO.into(), group, Some(LO)).expect("the second answer");
            assert_eq!(
                gateway.addr.port(),
                router,
                "an answer over 1500 bytes was cut and taken"
            );
        }

        #[test]
        fn an_oversized_description_is_refused() {
            let padded = description(9).replacen(
                "<deviceType>",
                &format!("<!-- {} --><deviceType>", "p".repeat(MAX_DESCRIPTION)),
                1,
            );
            let big = web(padded, soap(1));
            let router = web(description(9), soap(1));
            let group = ssdp(
                LO.into(),
                vec![
                    (LO.into(), answer(&at("127.0.0.1", big))),
                    (LO.into(), answer(&at("127.0.0.1", router))),
                ],
            );
            let gateway = search(LO.into(), group, Some(LO)).expect("the second answer");
            assert_eq!(gateway.addr.port(), router, "a description over 64 KiB was taken");
        }

        #[test]
        fn a_deeply_nested_description_is_refused_in_a_search() {
            let deep = web(description(MAX_XML_DEPTH + 1), soap(1));
            let router = web(description(9), soap(1));
            let group = ssdp(
                LO.into(),
                vec![
                    (LO.into(), answer(&at("127.0.0.1", deep))),
                    (LO.into(), answer(&at("127.0.0.1", router))),
                ],
            );
            let gateway = search(LO.into(), group, Some(LO)).expect("the second answer");
            assert_eq!(gateway.addr.port(), router, "a description 33 levels deep was taken");
        }

        #[test]
        fn an_oversized_control_response_is_refused() {
            let router = web(description(9), soap(MAX_SOAP_RESPONSE));
            let gateway = Gateway {
                addr: (LO, router).into(),
                root_url: "/desc".into(),
                control_url: "/ctl".into(),
                control_schema_url: "/scpd.xml".into(),
                control_schema: Default::default(),
                provider: Tokio,
            };
            let result = block_on(gateway.get_external_ip());
            assert!(
                matches!(
                    result,
                    Err(GetExternalIpError::RequestError(RequestError::InvalidResponse(_)))
                ),
                "{result:?}"
            );
        }
    }
}
