//! The Linux Bluetooth management socket's READ_INFO, for the BlueZ backend
//! ([`super::bluez`]; Nearby design step 5.8): the one fact BlueZ's D-Bus API
//! does not give, whether the adapter advertises from a private address.
//! libc only.
//!
//! - [`read_info`] opens `AF_BLUETOOTH`/`SOCK_RAW`/`BTPROTO_HCI` bound to
//!   `HCI_CHANNEL_CONTROL`, sends `MGMT_OP_READ_INFO` (0x0004) for the
//!   adapter's index and reads the answer. `current_settings` bit 13
//!   (`PRIVACY`) means the adapter advertises from a resolvable private
//!   address (BlueZ sets it with `Privacy = device` in main.conf).
//! - The kernel lets a process without `CAP_NET_ADMIN` send READ_INFO on the
//!   control channel (it is one of the management API's untrusted commands);
//!   that this holds on each distribution is a verify item of the nearby
//!   runbook. Whatever fails is "unknown", which the backend counts as the
//!   public address (owner decision O5-12: never advertise from it).
//! - The answer's address and names are parsed past, never kept.

// Only the BlueZ backend (glibc Linux, feature `nearby-radio`) opens the
// socket; the parser is also built for the tests on every platform.
#![cfg_attr(
    not(all(target_os = "linux", target_env = "gnu", feature = "nearby-radio")),
    allow(dead_code)
)]

/// The management command that reads an adapter's settings.
pub(crate) const MGMT_OP_READ_INFO: u16 = 0x0004;
/// A command finished: `opcode`, `status`, return parameters.
const MGMT_EV_CMD_COMPLETE: u16 = 0x0001;
/// A command failed: `opcode`, `status`.
const MGMT_EV_CMD_STATUS: u16 = 0x0002;
/// Every management packet starts with `code`, `index` and `length`, each a
/// little-endian u16.
const MGMT_HEADER: usize = 6;
/// READ_INFO's return parameters: address 6, version 1, manufacturer 2,
/// supported settings 4, current settings 4, class 3, name 249, short
/// name 11.
pub(crate) const READ_INFO_LEN: usize = 280;

/// `current_settings` / `supported_settings` bits (the management API).
pub(crate) const SETTING_LE: u32 = 1 << 9;
pub(crate) const SETTING_PRIVACY: u32 = 1 << 13;

/// What READ_INFO says about an adapter (its address and names are not
/// kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadInfo {
    /// The controller's HCI version.
    pub(crate) version: u8,
    /// The controller's company identifier (0x05F1, the Linux Foundation,
    /// for BlueZ's emulated controllers such as btvirt).
    pub(crate) manufacturer: u16,
    pub(crate) supported: u32,
    pub(crate) current: u32,
}

impl ReadInfo {
    /// The adapter advertises from a resolvable private address. A static
    /// random address is as stable as the public one, so it does not count.
    pub(crate) fn privacy(&self) -> bool {
        self.current & SETTING_PRIVACY != 0
    }

    /// The controller speaks Bluetooth LE.
    pub(crate) fn le(&self) -> bool {
        self.supported & SETTING_LE != 0
    }
}

/// READ_INFO's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    Info(ReadInfo),
    /// The kernel refused the command with this management status (0x14:
    /// permission denied, 0x11: invalid index).
    Refused(u8),
}

/// The READ_INFO command for adapter `index` (`hci<index>`).
pub(crate) fn read_info_request(index: u16) -> [u8; MGMT_HEADER] {
    let mut req = [0u8; MGMT_HEADER];
    req[..2].copy_from_slice(&MGMT_OP_READ_INFO.to_le_bytes());
    req[2..4].copy_from_slice(&index.to_le_bytes());
    // No parameters: length 0.
    req
}

/// One packet read from the control channel: READ_INFO's answer for
/// `index`, or `None` for anything else (another event, another adapter or
/// command, a short or inconsistent packet).
pub(crate) fn parse_read_info(packet: &[u8], index: u16) -> Option<Answer> {
    let u16_at = |at: usize| -> Option<u16> {
        Some(u16::from_le_bytes(packet.get(at..at + 2)?.try_into().ok()?))
    };
    let u32_at = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(packet.get(at..at + 4)?.try_into().ok()?))
    };
    let code = u16_at(0)?;
    if u16_at(2)? != index {
        return None;
    }
    let len = usize::from(u16_at(4)?);
    if packet.len() != MGMT_HEADER + len || len < 3 || u16_at(MGMT_HEADER)? != MGMT_OP_READ_INFO {
        return None;
    }
    let status = *packet.get(MGMT_HEADER + 2)?;
    match code {
        MGMT_EV_CMD_STATUS => Some(Answer::Refused(status)),
        MGMT_EV_CMD_COMPLETE if status != 0 => Some(Answer::Refused(status)),
        MGMT_EV_CMD_COMPLETE if len == 3 + READ_INFO_LEN => {
            let info = MGMT_HEADER + 3;
            Some(Answer::Info(ReadInfo {
                version: *packet.get(info + 6)?,
                manufacturer: u16_at(info + 7)?,
                supported: u32_at(info + 9)?,
                current: u32_at(info + 13)?,
            }))
        }
        _ => None,
    }
}

/// The index of a BlueZ adapter path (`/org/bluez/hci3` is 3).
pub(crate) fn adapter_index(path: &str) -> Option<u16> {
    let n = path.strip_prefix("/org/bluez/hci")?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) || (n.len() > 1 && n.starts_with('0'))
    {
        return None;
    }
    n.parse().ok()
}

#[cfg(all(target_os = "linux", target_env = "gnu", feature = "nearby-radio"))]
mod socket {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::{parse_read_info, read_info_request, Answer, ReadInfo};

    const BTPROTO_HCI: libc::c_int = 1;
    const HCI_DEV_NONE: u16 = 0xffff;
    const HCI_CHANNEL_CONTROL: u16 = 3;
    /// Packets read before giving up (other events may come first).
    const READS: usize = 16;

    /// `struct sockaddr_hci`.
    #[repr(C)]
    struct SockaddrHci {
        family: libc::sa_family_t,
        dev: u16,
        channel: u16,
    }

    /// READ_INFO for adapter `index`; `None` when it cannot be read (no
    /// Bluetooth in the kernel, refused, no answer within half a second).
    pub(crate) fn read_info(index: u16) -> Option<ReadInfo> {
        // SAFETY: socket(2) with constant arguments; the result is checked
        // and owned at once.
        let raw = unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                BTPROTO_HCI,
            )
        };
        if raw < 0 {
            return None;
        }
        // SAFETY: `raw` is a descriptor socket(2) just returned to us.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let addr = SockaddrHci {
            family: libc::sa_family_t::try_from(libc::AF_BLUETOOTH).ok()?,
            dev: HCI_DEV_NONE,
            channel: HCI_CHANNEL_CONTROL,
        };
        let addr_len = libc::socklen_t::try_from(std::mem::size_of::<SockaddrHci>()).ok()?;
        // SAFETY: bind(2) with a pointer to a live `sockaddr_hci` and its
        // size.
        let bound = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                addr_len,
            )
        };
        if bound < 0 {
            return None;
        }
        let wait = libc::timeval {
            tv_sec: 0,
            tv_usec: 500_000,
        };
        let wait_len = libc::socklen_t::try_from(std::mem::size_of::<libc::timeval>()).ok()?;
        // SAFETY: setsockopt(2) with a pointer to a live `timeval` and its
        // size.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const wait).cast::<libc::c_void>(),
                wait_len,
            );
        }
        let req = read_info_request(index);
        // SAFETY: write(2) of `req`'s bytes on the descriptor owned above.
        let wrote = unsafe { libc::write(fd.as_raw_fd(), req.as_ptr().cast(), req.len()) };
        if usize::try_from(wrote).ok() != Some(req.len()) {
            return None;
        }
        let mut buf = [0u8; 512];
        for _ in 0..READS {
            // SAFETY: read(2) into `buf`, at most its length.
            let got = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            let got = usize::try_from(got).ok().filter(|n| *n > 0)?;
            match parse_read_info(&buf[..got], index) {
                Some(Answer::Info(info)) => return Some(info),
                Some(Answer::Refused(_)) => return None,
                None => {}
            }
        }
        None
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu", feature = "nearby-radio"))]
pub(crate) use socket::read_info;

#[cfg(test)]
mod tests {
    use super::*;

    const SETTING_POWERED: u32 = 1 << 0;
    const SETTING_ADVERTISING: u32 = 1 << 10;
    const SETTING_STATIC_ADDRESS: u32 = 1 << 15;

    /// A READ_INFO answer for hci0 as the kernel sends it on the control
    /// channel (the management API's layout; the address is a documentation
    /// placeholder): CMD_COMPLETE, index 0, length 283, opcode 0x0004,
    /// status 0, address, HCI version 0x0b (5.2), manufacturer 0x0002,
    /// supported 0x0001bfff, current 0x00002ad1 (powered, bondable, SSP,
    /// BR/EDR, LE, secure connections, privacy), class 0x0c010c, name
    /// "raven-lab", short name empty.
    fn captured(current: u32) -> Vec<u8> {
        let mut p = hex::decode(concat!(
            "0100",
            "0000",
            "1b01", // CMD_COMPLETE, hci0, 283 bytes
            "0400",
            "00",           // READ_INFO, success
            "665544332211", // the address (placeholder, little-endian)
            "0b",
            "0200",     // HCI 5.2, manufacturer 2
            "ffbf0100", // supported settings
        ))
        .unwrap();
        p.extend_from_slice(&current.to_le_bytes());
        p.extend_from_slice(&[0x0c, 0x01, 0x0c]);
        let mut name = [0u8; 249];
        name[..9].copy_from_slice(b"raven-lab");
        p.extend_from_slice(&name);
        p.extend_from_slice(&[0u8; 11]);
        p
    }

    /// P5.29: READ_INFO's answer gives the privacy bit (and LE support);
    /// another adapter's or another command's packet is not it.
    #[test]
    fn read_info_answer_parses_from_the_wire_bytes() {
        let on = captured(0x0000_2ad1);
        assert_eq!(on.len(), MGMT_HEADER + 3 + READ_INFO_LEN);
        let Some(Answer::Info(info)) = parse_read_info(&on, 0) else {
            panic!("no READ_INFO answer");
        };
        assert_eq!(
            info,
            ReadInfo {
                version: 0x0b,
                manufacturer: 0x0002,
                supported: 0x0001_bfff,
                current: 0x0000_2ad1,
            }
        );
        assert!(info.privacy() && info.le());
        assert_ne!(info.current & SETTING_POWERED, 0);
        assert_eq!(info.current & SETTING_ADVERTISING, 0);

        // Privacy = device off: the public address (or a static random one,
        // just as stable) is used.
        let Some(Answer::Info(off)) = parse_read_info(&captured(0x0000_8ad1), 0) else {
            panic!("no READ_INFO answer");
        };
        assert!(!off.privacy());
        assert_ne!(off.current & SETTING_STATIC_ADDRESS, 0);

        assert_eq!(parse_read_info(&on, 1), None, "another adapter");
        let mut other_op = on.clone();
        other_op[MGMT_HEADER] = 0x05;
        assert_eq!(parse_read_info(&other_op, 0), None, "another command");
        assert_eq!(parse_read_info(&on[..on.len() - 1], 0), None, "short");
        assert_eq!(parse_read_info(&on[..4], 0), None, "no header");
        // An event that is not a command's answer (INDEX_ADDED, 0x0004).
        assert_eq!(
            parse_read_info(&hex::decode("040000000000").unwrap(), 0),
            None
        );
    }

    /// A refused READ_INFO (CMD_STATUS, or CMD_COMPLETE with a status) is
    /// "unknown" for the backend, which then counts the address as public.
    #[test]
    fn a_refused_read_info_is_reported_as_refused() {
        // CMD_STATUS, hci0, 3 bytes: READ_INFO, 0x14 permission denied.
        let status = hex::decode("020000000300040014").unwrap();
        assert_eq!(parse_read_info(&status, 0), Some(Answer::Refused(0x14)));
        // CMD_COMPLETE with 0x11 invalid index and no parameters.
        let complete = hex::decode("010001000300040011").unwrap();
        assert_eq!(parse_read_info(&complete, 1), Some(Answer::Refused(0x11)));
    }

    #[test]
    fn the_request_and_adapter_indexes() {
        assert_eq!(read_info_request(0), [0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            read_info_request(0x0102),
            [0x04, 0x00, 0x02, 0x01, 0x00, 0x00]
        );
        assert_eq!(adapter_index("/org/bluez/hci0"), Some(0));
        assert_eq!(adapter_index("/org/bluez/hci12"), Some(12));
        for bad in [
            "/org/bluez/hci",
            "/org/bluez/hci01",
            "/org/bluez/hci0/dev_AA",
            "/org/bluez/hcix",
            "/org/bluez",
        ] {
            assert_eq!(adapter_index(bad), None, "{bad}");
        }
    }
}
