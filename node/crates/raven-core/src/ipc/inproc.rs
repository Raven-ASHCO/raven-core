//! In-process IPC endpoints: the local IPC of a raven-node that runs inside
//! the caller's own process (raven-node's `embedded` host; docs/IOS.md).
//!
//! The protocol is unchanged: the same length-prefixed JSON frames
//! ([`super::encode_request`], [`super::decode_response`]) on a connected
//! `AF_UNIX` stream, served by the same server code (the peer-credential
//! check included). Only the rendezvous differs: instead of a socket file in
//! the profile (or under `/tmp`), a connect makes a socket pair
//! ([`UnixStream::pair`]) and hands one end to the node registered for that
//! profile in this process.
//!
//! Why not the socket file on iOS: an app's container path is 80 to 90
//! bytes before the profile's own folder, so `<profile>/raven-node.sock`
//! does not fit `sun_path` (103 bytes), and the short fallback under `/tmp`
//! cannot be created inside the app sandbox. A pair also leaves nothing on
//! disk for another program to find, and nothing stale after the system
//! suspends or ends the app.
//!
//! One endpoint per profile per process: a second registration for the same
//! profile is refused (the node's instance lock refuses a second node too).
//!
//! Either end may be closed before the other writes: a program that gives
//! up waiting hangs up before the node's answer, a node that stops closes
//! under a program's request. That write is an error (`BrokenPipe`), never
//! SIGPIPE: both ends are told so where the system can say it per socket
//! (Apple systems; std does it for the sockets it opens, not for a pair),
//! since the process a pair lives in is an app whose `main` may not be Rust
//! ([`crate::sigpipe`]).

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Hands the server end of a new connection to the node; gives it back
/// when the node takes no more (it is stopping, or its queue is full).
pub type Acceptor = Box<dyn Fn(UnixStream) -> Result<(), UnixStream> + Send + Sync>;

struct Entry {
    dir: PathBuf,
    id: u64,
    accept: Acceptor,
}

static ENDPOINTS: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// Set by a process whose nodes all run embedded (an iOS app, or an engine
/// told to run its node in process): a profile with no endpoint registered
/// has no node, and no socket file is ever tried.
static EMBEDDED_ONLY: AtomicBool = AtomicBool::new(false);

fn endpoints() -> MutexGuard<'static, Vec<Entry>> {
    ENDPOINTS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The one spelling a profile is keyed by (as the socket path's).
fn key(data_dir: &Path) -> PathBuf {
    super::normalized_data_dir(data_dir)
}

/// Keeps an endpoint registered; dropping it unregisters (the node stopped).
#[derive(Debug)]
pub struct Registration {
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        endpoints().retain(|e| e.id != self.id);
    }
}

/// Registers the endpoint of the node serving `data_dir` in this process.
/// `Err` when one is registered already.
pub fn register(data_dir: &Path, accept: Acceptor) -> Result<Registration, String> {
    let dir = key(data_dir);
    let mut all = endpoints();
    if all.iter().any(|e| e.dir == dir) {
        return Err(format!(
            "an embedded raven-node already serves {} in this process",
            data_dir.display()
        ));
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    all.push(Entry { dir, id, accept });
    Ok(Registration { id })
}

/// Whether a node serving `data_dir` is registered in this process.
pub fn is_registered(data_dir: &Path) -> bool {
    let dir = key(data_dir);
    endpoints().iter().any(|e| e.dir == dir)
}

/// Every IPC client of this process connects in process only from now on
/// ([`connect`]): set once, by a host whose nodes all run embedded.
pub fn set_embedded_only() {
    EMBEDDED_ONLY.store(true, Ordering::Relaxed);
}

/// Whether [`set_embedded_only`] was called.
pub fn embedded_only() -> bool {
    EMBEDDED_ONLY.load(Ordering::Relaxed)
}

/// A connection to the node registered for `data_dir`. `None`: none is
/// registered and this process may still use the socket file (the caller
/// connects as before). With [`embedded_only`] an unregistered profile is
/// `NotFound` (no node runs), and a node that takes no more connections
/// is `ConnectionRefused` (it is stopping) or `WouldBlock` (busy): the same
/// kinds a socket connect gives, so callers read them the same way.
pub fn connect(data_dir: &Path) -> Option<io::Result<UnixStream>> {
    let dir = key(data_dir);
    let all = endpoints();
    let Some(entry) = all.iter().find(|e| e.dir == dir) else {
        return embedded_only().then(|| {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no embedded raven-node runs for this profile",
            ))
        });
    };
    let pair = UnixStream::pair().and_then(|(client, server)| {
        no_sigpipe(&client)?;
        no_sigpipe(&server)?;
        Ok((client, server))
    });
    let (client, server) = match pair {
        Ok(pair) => pair,
        Err(e) => return Some(Err(e)),
    };
    Some(match (entry.accept)(server) {
        Ok(()) => Ok(client),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "the embedded raven-node takes no more connections now",
        )),
    })
}

/// No SIGPIPE from a write to `sock` once its peer is closed (the module's
/// words above).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn no_sigpipe(sock: &UnixStream) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let on: libc::c_int = 1;
    // SAFETY: an int option on an open socket.
    let set = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if set == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Elsewhere no socket can say it: the process ignores SIGPIPE (a Rust
/// program from its start, an app through [`crate::sigpipe`]).
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn no_sigpipe(_sock: &UnixStream) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;

    /// A write to an end whose peer is closed is an error in a process
    /// where SIGPIPE has its default action (an app whose `main` is not
    /// Rust), never the signal that ends it. Either end: the node answers a
    /// program that hung up; a program asks a node that closed.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_write_to_a_closed_end_is_an_error_not_a_signal() {
        crate::sigpipe::testing::run_child(module_path!(), "closed_end_child");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn closed_end_child() {
        if !crate::sigpipe::testing::child_with_default(module_path!(), "closed_end_child") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("s");
        let (tx, rx) = mpsc::channel::<UnixStream>();
        let tx = Mutex::new(tx);
        let _reg = register(
            &profile,
            Box::new(move |s| tx.lock().unwrap().send(s).map_err(|mpsc::SendError(s)| s)),
        )
        .unwrap();

        let client = connect(&profile).expect("registered").unwrap();
        let mut server = rx.recv().unwrap();
        drop(client);
        let err = server.write_all(b"answer").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        let mut client = connect(&profile).expect("registered").unwrap();
        drop(rx.recv().unwrap());
        let err = client.write_all(b"request").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        // The signal's action was the default all along.
        assert_eq!(crate::sigpipe::testing::action(), libc::SIG_DFL);
    }

    /// A connect reaches the registered acceptor with a working pair; a
    /// second registration for the same profile (any spelling) is refused;
    /// dropping the registration removes it.
    #[test]
    fn a_registered_profile_gets_a_connected_pair() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("p");
        let (tx, rx) = mpsc::channel::<UnixStream>();
        let tx = Mutex::new(tx);
        let reg = register(
            &profile,
            Box::new(move |s| tx.lock().unwrap().send(s).map_err(|mpsc::SendError(s)| s)),
        )
        .unwrap();
        assert!(is_registered(&profile));
        assert!(is_registered(&profile.join(".")));
        assert!(register(&profile.join("."), Box::new(|_| Ok(()))).is_err());

        let mut client = connect(&profile).expect("registered").unwrap();
        let mut server = rx.recv().unwrap();
        client.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        server.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");

        drop(reg);
        assert!(!is_registered(&profile));
        // Not embedded-only: an unregistered profile falls back to the
        // socket file (None). (The embedded-only answer is tested in the
        // engine's own process, where the flag is set for good.)
        if !embedded_only() {
            assert!(connect(&profile).is_none());
        }
    }

    /// An acceptor that gives the stream back (the node is stopping) is a
    /// transient refusal, never a hang.
    #[test]
    fn a_node_that_takes_no_more_is_a_transient_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("q");
        let _reg = register(&profile, Box::new(Err)).unwrap();
        let err = connect(&profile).expect("registered").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }
}
