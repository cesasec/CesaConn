use core::fmt;
use core::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep, timeout};

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
    message: &str,
    duration: u64,
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
        let msg = message.as_bytes();

        // Send presence packet to the entire local network
        let bytes_sent = socket
            .send_to(msg, "255.255.255.255:3636")
            .await
            .map_err(|_| UdpNetworkerErrors::FailedToSendBroadcast)?;

        println!(
            "Successfully broadcasted: {} bytes | Data: {}",
            bytes_sent, message
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
    known_addrs: Arc<RwLock<Vec<SocketAddr>>>,
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
                return Err(UdpNetworkerErrors::DataTooBig)
            }

            return Err(UdpNetworkerErrors::FailedToFetchResult)
        }
    };

    // If len equals buffer size, packet may have been truncated — discard it
    // recv_from never returns more than buf.len(), so == means truncation occurred
    if len == buf.len() {
        return Err(UdpNetworkerErrors::DataTooBig);
    }

    // TODO: DECRYPT

    // Convert received bytes to string for device name comparison
    let name = &buf[..len];

    // Verify the packet comes from a recognized CesaConn device
    if *name == *message {
        println!(
            "Found device: {} at IP: {}",
            String::from_utf8_lossy(name),
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
    use tokio::net::UdpSocket;

    /// Helper that returns an empty known_addrs list wrapped in Arc<RwLock>
    fn empty_known_addrs() -> Arc<RwLock<Vec<SocketAddr>>> {
        Arc::new(RwLock::new(vec![]))
    }

    /// Test that UdpSocket::bind successfully binds to a valid address
    #[tokio::test]
    async fn test_bind_socket() {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        assert!(socket.local_addr().is_ok());
    }

    /// Test that duration cap works correctly
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

    /// Test that udp_find_broadcaster times out when no broadcaster is present
    //#[tokio::test]
    //async fn test_find_broadcaster_timeout() {
     //   let result = udp_find_broadcaster(1, BROADCAST_NAME.as_bytes(), empty_known_addrs()).await;
     //   assert!(result.is_err());
     //   assert!(matches!(result, Err(UdpNetworkerErrors::Timeout)));
   // }

    /// Test that an unknown broadcast name is rejected
    #[tokio::test]
    async fn test_unknown_device_rejected() {
        let handle = tokio::spawn(async {
            udp_find_broadcaster(2, BROADCAST_NAME.as_bytes(), empty_known_addrs()).await
        });

        // Let the listener bind first
        sleep(Duration::from_millis(100)).await;

        let socket = UdpSocket::bind("0.0.0.0:6363").await.unwrap();
        socket
            .send_to(b"UnknownDevice", "127.0.0.1:3636")
            .await
            .unwrap();

        let result = handle.await.unwrap();
        assert_eq!(result, Err(UdpNetworkerErrors::UnknownDevice));
    }

    #[tokio::test]
    async fn test_oversized_packet_rejected() {
        let handle = tokio::spawn(async {
            udp_find_broadcaster(2, BROADCAST_NAME.as_bytes(), empty_known_addrs()).await
        });

        sleep(Duration::from_millis(100)).await;

        let socket = UdpSocket::bind("0.0.0.0:6363").await.unwrap();
        let big_data = vec![0u8; 1025];
        socket.send_to(&big_data, "127.0.0.1:3636").await.unwrap();

        let result = handle.await.unwrap();
        assert_eq!(result, Err(UdpNetworkerErrors::DataTooBig));
    }

    /// Test that known_addrs can hold multiple addresses simultaneously
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

    /// Test that known_addrs is accessible from multiple tasks via Arc::clone
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

    /// Test that known_addrs is not mutated by udp_find_broadcaster on timeout
    #[tokio::test]
    async fn test_known_addrs_not_mutated_on_timeout() {
        let known_addrs = Arc::new(RwLock::new(vec![
            "192.168.1.1:6363".parse::<SocketAddr>().unwrap(),
        ]));

        let _ = udp_find_broadcaster(1, BROADCAST_NAME.as_bytes(), Arc::clone(&known_addrs)).await;

        let addrs = known_addrs.read().await;
        assert_eq!(addrs.len(), 1);
    }

    /// Test Display implementation for all error variants
    #[test]
    fn test_error_display() {
        assert!(
            !UdpNetworkerErrors::FailedToBindSocket
                .to_string()
                .is_empty()
        );
        assert!(
            !UdpNetworkerErrors::FailedToSetBroadcastMode
                .to_string()
                .is_empty()
        );
        assert!(
            !UdpNetworkerErrors::FailedToSendBroadcast
                .to_string()
                .is_empty()
        );
        assert!(!UdpNetworkerErrors::Timeout.to_string().is_empty());
        assert!(
            !UdpNetworkerErrors::FailedToFetchResult
                .to_string()
                .is_empty()
        );
        assert!(!UdpNetworkerErrors::DataTooBig.to_string().is_empty());
        assert!(!UdpNetworkerErrors::UnknownDevice.to_string().is_empty());
    }
}
