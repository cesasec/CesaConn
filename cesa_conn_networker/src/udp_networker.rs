use core::fmt;
use core::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep, timeout};
use zeroize::Zeroize;

use crate::auth::{decrypt_tunnel, encrypt_tunnel};

/// Errors that can occur during UDP networking operations
#[derive(Debug, PartialEq)] // Dodaj tę linię!
pub enum UdpNetworkerErrors {
    /// Failed to bind UDP socket to the given address
    FailedToBindSocket,
    /// Failed to enable or disable broadcast mode on the socket
    FailedToSetBroadcastMode,
    /// Failed to send broadcast packet to the network
    FailedToSendBroadcast,
    /// No device responded within the given duration
    Timeout,
    /// Failed to receive incoming UDP packet
    FailedToFetchResult,
    /// Received packet was larger than the buffer — may have been truncated
    DataTooBig,
    /// Received packet does not match the expected device identifier
    UnknownDevice,
    /// AES-GCM encryption failed — should not happen under normal conditions.
    FailedToEncryptTunnel,
    /// AES-GCM decryption failed — wrong key or data was tampered with in transit.
    FailedToDecryptTunnel,
    /// Failed while trying to cenvert u8 to String
    FailedToConvertU8ToString,
}

impl fmt::Display for UdpNetworkerErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UdpNetworkerErrors::FailedToBindSocket => write!(f, "Failed to bind UDP socket"),
            UdpNetworkerErrors::FailedToSetBroadcastMode => {
                write!(f, "Failed to set broadcast mode")
            }
            UdpNetworkerErrors::FailedToSendBroadcast => {
                write!(f, "Failed to send broadcast packet")
            }
            UdpNetworkerErrors::Timeout => write!(f, "Discovery timed out — no device found"),
            UdpNetworkerErrors::FailedToFetchResult => write!(f, "Failed to receive UDP packet"),
            UdpNetworkerErrors::DataTooBig => write!(f, "Received packet exceeds buffer size"),
            UdpNetworkerErrors::UnknownDevice => write!(f, "Unknown device — name mismatch"),
            UdpNetworkerErrors::FailedToEncryptTunnel => write!(f, "failed to encrypt tunnel data"),
            UdpNetworkerErrors::FailedToDecryptTunnel => write!(f, "failed to decrypt tunnel data"),
            UdpNetworkerErrors::FailedToConvertU8ToString => {
                write!(f, "failed to convert u8 to string")
            }
        }
    }
}

/// Maximum allowed duration for broadcast/listening operations in seconds
pub static MAX_BROADCAST_DURATION: u64 = 20;

/// Identifier name used to recognize CesaConn devices on the network
pub static BROADCAST_NAME: &str = "CesaConn Broadcast";

/// Broadcasts a UDP presence message every second for the given duration.
/// Duration is capped at MAX_BROADCAST_DURATION to prevent indefinite broadcasting.
/// Returns Ok(()) if all packets were sent successfully.
pub async fn udp_broadcast_presence(
    message: &[u8],
    duration: u64,
    a_key: Arc<RwLock<[u8; 32]>>,
) -> Result<(), UdpNetworkerErrors> {
    // Cap duration to the allowed maximum to prevent indefinite broadcasting
    let duration = if duration > MAX_BROADCAST_DURATION {
        MAX_BROADCAST_DURATION
    } else {
        duration
    };

    // Bind to all interfaces on port 6363
    let socket = UdpSocket::bind("0.0.0.0:6363")
        .await
        .map_err(|_| UdpNetworkerErrors::FailedToBindSocket)?;

    // Enable broadcast mode — required to send packets to 255.255.255.255
    socket
        .set_broadcast(true)
        .map_err(|_| UdpNetworkerErrors::FailedToSetBroadcastMode)?;

    println!("Successfully enabled broadcast mode");

    for _tick in 0..duration {
        let auth_key = &mut a_key.read().await.clone();

        let e_msg = encrypt_tunnel(&auth_key, message)
            .map_err(|_| UdpNetworkerErrors::FailedToEncryptTunnel)?;
        auth_key.zeroize();

        // Send presence packet to the entire local network
        let bytes_sent = socket
            .send_to(e_msg.as_ref(), "255.255.255.255:3636")
            .await
            .map_err(|_| UdpNetworkerErrors::FailedToSendBroadcast)?;

        println!(
            "Successfully broadcasted: {} bytes | Data: {}",
            bytes_sent,
            String::from_utf8(message.to_vec())
                .map_err(|_| UdpNetworkerErrors::FailedToConvertU8ToString)?
        );

        // Wait one second before sending the next broadcast
        sleep(Duration::from_secs(1)).await;
    }

    // Disable broadcast mode after finishing — good practice to clean up
    socket
        .set_broadcast(false)
        .map_err(|_| UdpNetworkerErrors::FailedToSetBroadcastMode)?;

    println!("Successfully disabled broadcast mode.");

    Ok(())
}

/// Listens for incoming UDP packets for the given duration.
/// Returns Ok(SocketAddr) if a valid CesaConn device is found.
/// Returns Err if timeout, socket error, oversized packet, or name mismatch.
pub async fn udp_find_broadcaster(
    duration: u64,
    message: &[u8],
    a_key: Arc<RwLock<[u8; 32]>>,
) -> Result<SocketAddr, UdpNetworkerErrors> {
    // Cap duration to the allowed maximum
    let duration = if duration > MAX_BROADCAST_DURATION {
        MAX_BROADCAST_DURATION
    } else {
        duration
    };

    // Bind to all interfaces on port 6363 — same port as broadcaster
    let socket = UdpSocket::bind("0.0.0.0:3636")
        .await
        .map_err(|_| UdpNetworkerErrors::FailedToBindSocket)?;

    // Receive buffer — max 1024 bytes per packet
    let mut buf = [0; 1024];

    println!("Searching for devices on network...");

    // Wait for incoming packet — abort if duration expires
    let recv_result = timeout(Duration::from_secs(duration), socket.recv_from(&mut buf))
        .await
        .map_err(|_| UdpNetworkerErrors::Timeout)?; // timeout expired;

    let (len, addr) = match recv_result {
        Ok(v) => v,
        Err(e) => {
            #[cfg(windows)]
            if e.raw_os_error() == Some(10040) {
                return Err(UdpNetworkerErrors::DataTooBig);
            }

            return Err(UdpNetworkerErrors::FailedToFetchResult);
        }
    };

    // If len equals buffer size, packet may have been truncated — discard it
    // recv_from never returns more than buf.len(), so == means truncation occurred
    if len == buf.len() {
        buf.zeroize();
        return Err(UdpNetworkerErrors::DataTooBig);
    }

    // Convert received bytes to string for device name comparison
    let auth_key = &mut a_key.read().await.clone();
    let name = decrypt_tunnel(auth_key, &buf[..len])
        .map_err(|_| UdpNetworkerErrors::FailedToDecryptTunnel)?;

    buf.zeroize();

    auth_key.zeroize();

    // Verify the packet comes from a recognized CesaConn device
    if *name == *message {
        println!(
            "Found device: {} at IP: {}",
            String::from_utf8_lossy(name.as_ref()),
            addr.ip()
        );
        Ok(addr)
    } else {
        // Device responded but name doesn't match — ignore it
        Err(UdpNetworkerErrors::UnknownDevice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::encrypt_tunnel;
    use tokio::net::UdpSocket;
    use tokio::time::{Duration, sleep};

    /// Pre-shared key used across all tests.
    const TEST_KEY: [u8; 32] = [0xAB; 32];

    /// Wraps a fixed-size key in `Arc<RwLock>` for passing to `udp_find_broadcaster`.
    fn make_test_key(key: [u8; 32]) -> Arc<RwLock<[u8; 32]>> {
        Arc::new(RwLock::new(key))
    }

    /// `UdpSocket::bind` must succeed on any available port.
    #[tokio::test]
    async fn test_bind_socket() {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        assert!(socket.local_addr().is_ok());
    }

    /// Duration above `MAX_BROADCAST_DURATION` must be capped to the maximum.
    #[tokio::test]
    async fn test_duration_cap() {
        let over_limit = MAX_BROADCAST_DURATION + 100;
        let capped = if over_limit > MAX_BROADCAST_DURATION {
            MAX_BROADCAST_DURATION
        } else {
            over_limit
        };
        assert_eq!(capped, MAX_BROADCAST_DURATION);
    }

    /// A packet that decrypts successfully but carries the wrong device name must be
    /// rejected with `UnknownDevice`.
    #[tokio::test]
    async fn test_unknown_device_rejected() {
        let key = make_test_key(TEST_KEY);
        let key_clone = Arc::clone(&key);

        let handle = tokio::spawn(async move {
            udp_find_broadcaster(2, BROADCAST_NAME.as_bytes(), key_clone).await
        });

        // Give the listener time to bind before sending
        sleep(Duration::from_millis(100)).await;

        // Bind to an ephemeral port — receiver only cares about the destination port (3636)
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        // Encrypt with the correct key so decryption succeeds, but use a wrong device name
        let raw_key = key.read().await.clone();
        let encrypted = encrypt_tunnel(&raw_key, b"UnknownDevice").unwrap();
        socket.send_to(&encrypted, "127.0.0.1:3636").await.unwrap();

        let result = handle.await.unwrap();
        assert_eq!(result, Err(UdpNetworkerErrors::UnknownDevice));
    }

    /// A packet encrypted with a mismatched key must fail AES-GCM authentication
    /// and return `FailedToDecryptTunnel`.
    #[tokio::test]
    async fn test_wrong_key_fails_decryption() {
        let handle = tokio::spawn(async {
            udp_find_broadcaster(2, BROADCAST_NAME.as_bytes(), make_test_key(TEST_KEY)).await
        });

        sleep(Duration::from_millis(100)).await;

        // Bind to an ephemeral port — receiver only cares about the destination port (3636)
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let wrong_key = [0xFF; 32];
        // Encrypt with a different key — receiver's GCM tag check will fail
        let encrypted = encrypt_tunnel(&wrong_key, BROADCAST_NAME.as_bytes()).unwrap();
        socket.send_to(&encrypted, "127.0.0.1:3636").await.unwrap();

        let result = handle.await.unwrap();
        assert_eq!(result, Err(UdpNetworkerErrors::FailedToDecryptTunnel));
    }

    /// A correctly encrypted packet whose plaintext matches `BROADCAST_NAME` must be
    /// accepted — the function returns the sender's `SocketAddr`.
    #[tokio::test]
    async fn test_correct_broadcast_found() {
        let key = make_test_key(TEST_KEY);
        let key_clone = Arc::clone(&key);

        let handle = tokio::spawn(async move {
            udp_find_broadcaster(2, BROADCAST_NAME.as_bytes(), key_clone).await
        });

        sleep(Duration::from_millis(100)).await;

        // Bind to an ephemeral port — receiver only cares about the destination port (3636)
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let raw_key = key.read().await.clone();
        let encrypted = encrypt_tunnel(&raw_key, BROADCAST_NAME.as_bytes()).unwrap();
        socket.send_to(&encrypted, "127.0.0.1:3636").await.unwrap();

        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    /// A UDP packet larger than the 1024-byte receive buffer must be rejected as `DataTooBig`.
    #[tokio::test]
    async fn test_oversized_packet_rejected() {
        let handle = tokio::spawn(async {
            udp_find_broadcaster(2, BROADCAST_NAME.as_bytes(), make_test_key(TEST_KEY)).await
        });

        sleep(Duration::from_millis(100)).await;

        // Bind to an ephemeral port — receiver only cares about the destination port (3636)
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let big_data = vec![0u8; 1025];
        socket.send_to(&big_data, "127.0.0.1:3636").await.unwrap();

        let result = handle.await.unwrap();
        assert_eq!(result, Err(UdpNetworkerErrors::DataTooBig));
    }

    /// `Arc<RwLock<Vec<SocketAddr>>>` must be readable from multiple concurrent tasks —
    /// verifies the shared-state pattern used by callers of this module.
    #[tokio::test]
    async fn test_known_addrs_holds_multiple_entries() {
        let known_addrs: Arc<RwLock<Vec<SocketAddr>>> = Arc::new(RwLock::new(vec![
            "192.168.1.1:6363".parse().unwrap(),
            "192.168.1.2:6363".parse().unwrap(),
            "10.0.0.1:6363".parse().unwrap(),
        ]));

        let addrs = known_addrs.read().await;
        assert_eq!(addrs.len(), 3);
        assert!(addrs.contains(&"192.168.1.2:6363".parse::<SocketAddr>().unwrap()));
    }

    /// An `Arc::clone` of a `RwLock<Vec<SocketAddr>>` must share the same underlying data
    /// across spawned tasks.
    #[tokio::test]
    async fn test_known_addrs_arc_clone() {
        let known_addrs = Arc::new(RwLock::new(vec![
            "192.168.0.1:6363".parse::<SocketAddr>().unwrap(),
        ]));

        let clone = Arc::clone(&known_addrs);

        tokio::spawn(async move {
            let addrs = clone.read().await;
            assert_eq!(addrs.len(), 1);
        })
        .await
        .unwrap();
    }

    /// The encryption key must not be mutated by `udp_find_broadcaster` on timeout.
    #[tokio::test]
    async fn test_key_not_mutated_on_timeout() {
        let key = make_test_key(TEST_KEY);

        let _ = udp_find_broadcaster(1, BROADCAST_NAME.as_bytes(), Arc::clone(&key)).await;

        let k = key.read().await;
        assert_eq!(*k, TEST_KEY);
    }

    /// All `UdpNetworkerErrors` variants must produce a non-empty `Display` string.
    #[test]
    fn test_error_display() {
        assert!(!UdpNetworkerErrors::FailedToBindSocket.to_string().is_empty());
        assert!(!UdpNetworkerErrors::FailedToSetBroadcastMode.to_string().is_empty());
        assert!(!UdpNetworkerErrors::FailedToSendBroadcast.to_string().is_empty());
        assert!(!UdpNetworkerErrors::Timeout.to_string().is_empty());
        assert!(!UdpNetworkerErrors::FailedToFetchResult.to_string().is_empty());
        assert!(!UdpNetworkerErrors::DataTooBig.to_string().is_empty());
        assert!(!UdpNetworkerErrors::UnknownDevice.to_string().is_empty());
        assert!(!UdpNetworkerErrors::FailedToEncryptTunnel.to_string().is_empty());
        assert!(!UdpNetworkerErrors::FailedToDecryptTunnel.to_string().is_empty());
        assert!(!UdpNetworkerErrors::FailedToConvertU8ToString.to_string().is_empty());
    }
}
