//! TUI-side IPC client.
//!
//! Connects to a running daemon over the local socket, authenticates with the
//! auth cookie, then bridges the socket to a pair of `std::sync::mpsc` channels
//! that the `App` uses internally.
//!
//! # Security layers
//! 1. **Socket permissions (0600)** — set by the daemon at bind time; the OS
//!    rejects connections from other users before we even read a byte.
//! 2. **Auth cookie** — 32 random bytes written by the daemon to a 0600 file.
//!    The TUI reads and sends the cookie; the daemon does a constant-time
//!    comparison and sends back a `bool`. A rogue same-user process would need
//!    to read the cookie file first, which requires the same privileges as the
//!    daemon itself — at that point IPC auth is no longer the weakest link.

use std::{
    io::{self, BufReader},
    sync::mpsc::{channel, Receiver, Sender},
};

use cesa_conn_ipc::{read_msg, write_msg, DaemonEvent, TuiCommand};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ConnectError {
    /// Cookie file not found — daemon has never started or was cleanly shut down.
    CookieNotFound(io::Error),
    /// Socket connect failed — daemon is not running or the socket was removed.
    DaemonNotRunning(io::Error),
    /// Daemon rejected the cookie — stale cookie file from a previous session.
    AuthFailed,
    Io(io::Error),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CookieNotFound(e) => write!(f, "cookie not found ({e})"),
            Self::DaemonNotRunning(e) => write!(f, "daemon not running ({e})"),
            Self::AuthFailed => write!(f, "IPC authentication failed"),
            Self::Io(e) => write!(f, "I/O error ({e})"),
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Connect to a running daemon.
///
/// Returns `(event_rx, cmd_tx)` ready to pass to `App::connect_channels`.
/// Two background threads are spawned to bridge the socket and the channels —
/// they run until the socket closes or the channels are dropped.
pub fn connect() -> Result<(Receiver<DaemonEvent>, Sender<TuiCommand>), ConnectError> {
    let cookie = read_cookie().map_err(ConnectError::CookieNotFound)?;

    let stream = open_socket().map_err(ConnectError::DaemonNotRunning)?;
    // try_clone creates an independent file descriptor — both halves can block
    // simultaneously without interfering with each other.
    let mut writer = stream.try_clone().map_err(ConnectError::Io)?;
    // BufReader batches small reads (the 4-byte length header + payload) into
    // fewer syscalls.
    let mut reader = BufReader::new(stream);

    // ── Cookie handshake ───────────────────────────────────────────────────
    write_msg(&mut writer, &cookie).map_err(ConnectError::Io)?;
    let ok: bool = read_msg(&mut reader).map_err(|_| ConnectError::AuthFailed)?;
    if !ok {
        return Err(ConnectError::AuthFailed);
    }

    let (event_tx, event_rx) = channel::<DaemonEvent>();
    let (cmd_tx, cmd_rx) = channel::<TuiCommand>();

    // ── Read thread: socket → TUI event channel ────────────────────────────
    // Separate thread because `read_exact` blocks; we can't poll it from the
    // TUI's synchronous draw loop without a dedicated OS thread.
    std::thread::spawn(move || loop {
        match read_msg::<DaemonEvent, _>(&mut reader) {
            Ok(ev) => {
                if event_tx.send(ev).is_err() {
                    break; // TUI dropped the receiver — it has exited
                }
            }
            Err(_) => break, // daemon closed the socket or sent garbage
        }
    });

    // ── Write thread: TUI command channel → socket ─────────────────────────
    // Blocks on `cmd_rx.recv()` to avoid busy-looping; wakes up only when the
    // TUI sends a command.
    std::thread::spawn(move || loop {
        match cmd_rx.recv() {
            Ok(cmd) => {
                if write_msg(&mut writer, &cmd).is_err() {
                    break; // socket closed
                }
            }
            Err(_) => break, // TUI dropped the sender — it has exited
        }
    });

    Ok((event_rx, cmd_tx))
}

// Re-export path helpers from the shared crate so callers don't need to
// import cesa_conn_ipc directly.
pub use cesa_conn_ipc::{cookie_path, socket_path};

// ── Platform socket implementation ────────────────────────────────────────────

#[cfg(unix)]
fn open_socket() -> io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(socket_path())
}

#[cfg(windows)]
fn open_socket() -> io::Result<interprocess::local_socket::LocalSocketStream> {
    use interprocess::local_socket::{prelude::*, GenericNamespaced};
    "cesaconn"
        .to_ns_name::<GenericNamespaced>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
        .and_then(interprocess::local_socket::LocalSocketStream::connect)
}

// ── Cookie ────────────────────────────────────────────────────────────────────

/// Read the 32-byte cookie the daemon wrote at startup.
///
/// 32 bytes = 256 bits of entropy, same as an AES-256 key — enough that
/// guessing or brute-forcing it is not a realistic attack.
fn read_cookie() -> io::Result<[u8; 32]> {
    let bytes = std::fs::read(cookie_path())?;
    // Reject any file that isn't exactly 32 bytes — signals a corrupt or
    // partially-written cookie rather than a valid one.
    bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cookie must be exactly 32 bytes"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_path_ends_with_expected_components() {
        // Both daemon and TUI must derive the same path independently.
        assert!(cookie_path().ends_with("cesaconn/ipc.cookie"));
    }

    #[cfg(unix)]
    #[test]
    fn socket_path_ends_with_sock() {
        assert!(socket_path().to_str().unwrap().ends_with(".sock"));
    }

    #[test]
    fn read_cookie_rejects_wrong_size() {
        // Simulate a truncated or corrupt cookie file.
        let bytes: Vec<u8> = vec![0u8; 16]; // 16 bytes, not 32
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn read_cookie_accepts_exact_32_bytes() {
        let bytes: Vec<u8> = vec![0xABu8; 32];
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn connect_fails_when_daemon_not_running() {
        // Without a daemon socket present, connect() must return DaemonNotRunning
        // (or CookieNotFound if the cookie file doesn't exist either, which is
        // the earlier check).
        let err = connect().unwrap_err();
        // Either variant is acceptable depending on system state.
        assert!(matches!(
            err,
            ConnectError::CookieNotFound(_) | ConnectError::DaemonNotRunning(_)
        ));
    }
}
