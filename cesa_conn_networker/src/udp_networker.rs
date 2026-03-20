
use tokio::net::{UdpSocket};
use tokio::time::{sleep, timeout, Duration};

use core::net::SocketAddr;

#[derive(Debug)]
pub enum UdpNetworkerErrors {
    FailedToBindSocket
}

/// Maximum allowed duration for broadcast/listening operations in seconds
pub static MAX_BROADCAST_DURATION: u64 = 20;

/// Identifier name used to recognize CesaConn devices on the network
pub static BROADCAST_NAME: &str = "CesaConn Brodcast";

/// Broadcasts a UDP presence message every second for the given duration.
/// Duration is capped at MAX_BROADCAST_DURATION to prevent indefinite broadcasting.
pub async fn udp_broadcast_presence(message: &str, duration: u64) {

    // Cap duration to the allowed maximum
    let duration = if duration > MAX_BROADCAST_DURATION { MAX_BROADCAST_DURATION } else { duration };
    let socket = UdpSocket::bind("0.0.0.0:6363").await.unwrap();

    // Enable broadcast mode — required for sending to 255.255.255.255
    match socket.set_broadcast(true) {
        Ok(_) => println!("Succesfully enabled broadcast mode."),
        Err(e) => eprintln!("Failed to enable broadcast mode! | Error: {}", e),
    };

    for _tick in 0..duration {

        let msg = message.as_bytes();

        // Send broadcast packet to the local network
        match socket.send_to(msg, "255.255.255.255:6363").await {
            Ok(msg) => println!("Succesfully broadcasted: {} bytes | Data: {}", msg, message),
            Err(e) => eprintln!("Failed to broadcast presence: {}", e),
        }

        // Wait one second before the next broadcast
        sleep(Duration::from_secs(1)).await;
    };

    // Disable broadcast mode after the loop finishes
    match socket.set_broadcast(false) {
        Ok(_) => println!("Succefully disabled broadcast mode."),
        Err(e) => eprintln!("Failed disable broadcast mode! | Error: {}", e),
    };
}

/// Listens for incoming UDP packets for the given duration.
/// Returns Some(SocketAddr) if a valid CesaConn device is found,
/// or None on timeout, socket error, oversized packet, or name mismatch.
pub async fn udp_find_broadcaster(duration: u64, message: &str) -> Option<SocketAddr> {

    // Cap duration to the allowed maximum
    let duration = if duration > MAX_BROADCAST_DURATION { MAX_BROADCAST_DURATION } else { duration };

    let socket = UdpSocket::bind("0.0.0.0:6363").await.unwrap();
    let mut buf = [0; 1024]; // Receive buffer — max 1024 bytes

    println!("Searching for devices on network...");

    // Wait for an incoming packet, abort if duration expires
    let result = timeout(
        Duration::from_secs(duration),
        socket.recv_from(&mut buf)
    ).await;

    match result {
        Ok(Ok((len, addr))) => {

            // If len equals buffer size, the packet may have been truncated — discard it
            if len == buf.len() {
                eprintln!("Too big broadcast data!");
                return None
            }

            let name = String::from_utf8_lossy(&buf[..len]);

            // Verify the packet comes from a CesaConn device
            if name.starts_with(&message) {
                println!("Found device: {} at IP: {}", name, addr.ip());
                Some(addr)
            } else {
                eprintln!("Found unknown device: {} from {}", name, addr);
                None
            }
        }
        Ok(Err(e)) => {
            eprintln!("Socket error: {}", e);
            None
        }
        Err(_) => {
            // No device responded within the given duration
            eprintln!("Timeout: Didnt find any device in 5 seconds!");
            None
        }
    }
}


#[cfg(test)]
mod tests {

    use super::*;
    use tokio::net::UdpSocket;

    /// Test that UdpSocket::bind successfully binds to a valid address
    #[tokio::test]
    async fn test_bind_socket() {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap(); // port 0 = OS picks random port
        assert!(socket.local_addr().is_ok());
    }

    /// Test that duration cap works — duration above MAX should be capped
    #[tokio::test]
    async fn test_duration_cap() {
        let over_limit = MAX_BROADCAST_DURATION + 100;
        let capped = if over_limit > MAX_BROADCAST_DURATION { MAX_BROADCAST_DURATION } else { over_limit };
        assert_eq!(capped, MAX_BROADCAST_DURATION);
    }

    /// Test that udp_find_broadcaster times out when no broadcaster is present
    #[tokio::test]
    async fn test_find_broadcaster_timeout() {
        // No broadcaster running — should timeout and return None
        let result = udp_find_broadcaster(1, BROADCAST_NAME).await;
        assert!(result.is_none());
    }

    /// Test full broadcast + discovery loop
    /// Spawns a broadcaster and a finder at the same time
    #[tokio::test]
    async fn test_broadcast_and_find() {

        // Spawn broadcaster in background
        tokio::spawn(async {
            udp_broadcast_presence(BROADCAST_NAME, 3).await;
        });

        // Give broadcaster a moment to start
        sleep(Duration::from_millis(100)).await;

        // Try to find the broadcaster
        let result = udp_find_broadcaster(3, BROADCAST_NAME).await;

        assert!(result.is_some());
    }

    /// Test that unknown broadcast name is rejected
    #[tokio::test]
    async fn test_unknown_device_rejected() {

        // Broadcast with wrong name
        tokio::spawn(async {
            let socket = UdpSocket::bind("0.0.0.0:6363").await.unwrap();
            socket.set_broadcast(true).unwrap();
            socket.send_to(b"UnknownDevice", "255.255.255.255:6363").await.unwrap();
        });

        sleep(Duration::from_millis(100)).await;

        // Finder should reject unknown device
        let result = udp_find_broadcaster(1, BROADCAST_NAME).await;
        assert!(result.is_none());
    }

    /// Test that oversized packet is rejected
    #[tokio::test]
    async fn test_oversized_packet_rejected() {

        tokio::spawn(async {
            let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            socket.set_broadcast(true).unwrap();

            // Send packet larger than buffer (1024 bytes)
            let big_data = vec![0u8; 1025];
            socket.send_to(&big_data, "255.255.255.255:6363").await.unwrap();
        });

        sleep(Duration::from_millis(100)).await;

        let result = udp_find_broadcaster(1, BROADCAST_NAME).await;
        assert!(result.is_none());
    }
}