//! Shared IPC types and wire framing used by both the daemon and TUI.
//!
//! Transport is a local socket (Unix socket / Windows named pipe).
//! Every message is framed as: [4-byte LE length][bincode payload].
//! Both sides use `write_msg` / `read_msg` to stay in sync.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

// ── TUI → Daemon ──────────────────────────────────────────────────────────────

/// Commands sent from the TUI process to the daemon process.
#[derive(Debug, Serialize, Deserialize)]
pub enum TuiCommand {
    /// Ask the daemon to initiate a TCP handshake with this address.
    Connect { addr: std::net::SocketAddr },
    /// Remove addr from the trusted list and close its connection.
    Disconnect { addr: std::net::SocketAddr },
    /// Derive and store the authentication key from the given passphrase.
    /// The daemon derives the key; the plaintext passphrase is never stored.
    SetAuthKey { passphrase: String },
    /// Derive and store the data encryption key from the given passphrase.
    SetDataKey { passphrase: String },
    /// Update a runtime configuration value.
    SetConfig { key: ConfigKey, value: String },
}

/// Identifies which configuration field a `SetConfig` command targets.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConfigKey {
    ListenAddress,
    ListenPort,
    /// How many seconds UDP presence broadcasts are sent before stopping.
    UdpBroadcastDuration,
}

// ── Daemon → TUI ──────────────────────────────────────────────────────────────

/// Events pushed from the daemon to every connected TUI session.
#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonEvent {
    /// TCP handshake succeeded — device is trusted and the session is live.
    DeviceConnected { addr: std::net::SocketAddr },
    /// Connection attempt is in progress (dial sent, waiting for response).
    DeviceConnecting { addr: std::net::SocketAddr },
    /// Device was disconnected or removed from the trusted list.
    DeviceDisconnected { addr: std::net::SocketAddr },
    /// The daemon successfully derived and stored a key from a passphrase.
    KeyConfigured { is_auth: bool },
    /// Structured log line for the TUI Logs tab.
    Log { message: String },
}

// ── Socket paths ──────────────────────────────────────────────────────────────

/// Where the daemon writes the 32-byte auth cookie (permissions: 0600).
///
/// Uses the XDG data directory so the file survives reboots but is
/// user-private. The daemon deletes the file on clean shutdown.
pub fn cookie_path() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("cesaconn")
        .join("ipc.cookie")
}

/// The local socket the daemon binds and the TUI connects to.
///
/// On Linux/macOS uses `$XDG_RUNTIME_DIR` (tmpfs, auto-cleaned on logout).
/// Falls back to the system temp directory if XDG is not available.
#[cfg(unix)]
pub fn socket_path() -> std::path::PathBuf {
    dirs::runtime_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("cesaconn.sock")
}

/// Named pipe path used on Windows.
#[cfg(windows)]
pub fn socket_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"\\.\pipe\cesaconn")
}

// ── Wire framing ──────────────────────────────────────────────────────────────

/// Serialize `msg` and write it as a length-prefixed frame.
///
/// Length-prefix framing is used instead of newlines because bincode
/// produces arbitrary binary output that may contain 0x0A bytes.
pub fn write_msg<T: Serialize, W: Write>(w: &mut W, msg: &T) -> io::Result<()> {
    let bytes = bincode::serialize(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // 4-byte LE length header keeps the framing simple and allocation-free on the read side.
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(&bytes)?;
    w.flush()
}

/// Read one length-prefixed frame and deserialize it into `T`.
///
/// The 4 MiB cap prevents a corrupt or malicious frame from exhausting
/// heap memory before we even attempt deserialization.
pub fn read_msg<T: for<'de> Deserialize<'de>, R: Read>(r: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 4 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3232)
    }

    // Helpers to write then read back through an in-memory buffer.
    fn roundtrip<T>(msg: &T) -> Vec<u8>
    where
        T: Serialize,
    {
        let mut buf = Vec::new();
        write_msg(&mut buf, msg).expect("write_msg failed");
        buf
    }

    #[test]
    fn tui_command_connect_roundtrip() {
        let addr = test_addr();
        let buf = roundtrip(&TuiCommand::Connect { addr });
        let decoded: TuiCommand = read_msg(&mut Cursor::new(&buf)).unwrap();
        let TuiCommand::Connect { addr: decoded_addr } = decoded else {
            panic!("wrong variant");
        };
        assert_eq!(decoded_addr, addr);
    }

    #[test]
    fn tui_command_set_auth_key_roundtrip() {
        let buf = roundtrip(&TuiCommand::SetAuthKey { passphrase: "s3cr3t".into() });
        let decoded: TuiCommand = read_msg(&mut Cursor::new(&buf)).unwrap();
        let TuiCommand::SetAuthKey { passphrase } = decoded else {
            panic!("wrong variant");
        };
        assert_eq!(passphrase, "s3cr3t");
    }

    #[test]
    fn tui_command_set_config_roundtrip() {
        let buf = roundtrip(&TuiCommand::SetConfig {
            key: ConfigKey::ListenPort,
            value: "4444".into(),
        });
        let decoded: TuiCommand = read_msg(&mut Cursor::new(&buf)).unwrap();
        let TuiCommand::SetConfig { key, value } = decoded else {
            panic!("wrong variant");
        };
        assert!(matches!(key, ConfigKey::ListenPort));
        assert_eq!(value, "4444");
    }

    #[test]
    fn daemon_event_device_connected_roundtrip() {
        let addr = test_addr();
        let buf = roundtrip(&DaemonEvent::DeviceConnected { addr });
        let decoded: DaemonEvent = read_msg(&mut Cursor::new(&buf)).unwrap();
        let DaemonEvent::DeviceConnected { addr: decoded_addr } = decoded else {
            panic!("wrong variant");
        };
        assert_eq!(decoded_addr, addr);
    }

    #[test]
    fn daemon_event_key_configured_roundtrip() {
        for is_auth in [true, false] {
            let buf = roundtrip(&DaemonEvent::KeyConfigured { is_auth });
            let decoded: DaemonEvent = read_msg(&mut Cursor::new(&buf)).unwrap();
            let DaemonEvent::KeyConfigured { is_auth: decoded_flag } = decoded else {
                panic!("wrong variant");
            };
            assert_eq!(decoded_flag, is_auth);
        }
    }

    #[test]
    fn daemon_event_log_roundtrip() {
        let msg = "[ INFO] test log line".to_string();
        let buf = roundtrip(&DaemonEvent::Log { message: msg.clone() });
        let decoded: DaemonEvent = read_msg(&mut Cursor::new(&buf)).unwrap();
        let DaemonEvent::Log { message } = decoded else {
            panic!("wrong variant");
        };
        assert_eq!(message, msg);
    }

    #[test]
    fn empty_log_message_roundtrip() {
        let buf = roundtrip(&DaemonEvent::Log { message: String::new() });
        let decoded: DaemonEvent = read_msg(&mut Cursor::new(&buf)).unwrap();
        let DaemonEvent::Log { message } = decoded else {
            panic!("wrong variant");
        };
        assert!(message.is_empty());
    }

    #[test]
    fn rejects_oversized_frame() {
        // Forge a frame header claiming 5 MiB payload — should be rejected before allocation.
        let mut buf = (5u32 * 1024 * 1024).to_le_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 16]); // small body so read_exact doesn't stall
        let result: io::Result<DaemonEvent> = read_msg(&mut Cursor::new(&buf));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn partial_frame_returns_error() {
        // Write a valid frame then truncate it — simulates a dropped connection mid-send.
        let mut buf = roundtrip(&DaemonEvent::Log { message: "hi".into() });
        buf.truncate(buf.len() - 1);
        let result: io::Result<DaemonEvent> = read_msg(&mut Cursor::new(&buf));
        assert!(result.is_err());
    }

    #[test]
    fn multiple_messages_in_sequence() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &DaemonEvent::Log { message: "first".into() }).unwrap();
        write_msg(&mut buf, &DaemonEvent::Log { message: "second".into() }).unwrap();

        let mut cursor = Cursor::new(&buf);
        let first: DaemonEvent = read_msg(&mut cursor).unwrap();
        let second: DaemonEvent = read_msg(&mut cursor).unwrap();

        let DaemonEvent::Log { message: m1 } = first else { panic!() };
        let DaemonEvent::Log { message: m2 } = second else { panic!() };
        assert_eq!(m1, "first");
        assert_eq!(m2, "second");
    }

    #[test]
    fn cookie_path_ends_with_expected_components() {
        let path = cookie_path();
        assert!(path.ends_with("cesaconn/ipc.cookie"));
    }

    #[cfg(unix)]
    #[test]
    fn socket_path_ends_with_sock() {
        let path = socket_path();
        assert!(path.to_str().unwrap().ends_with(".sock"));
    }
}
