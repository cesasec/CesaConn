
use tokio::net::{UdpSocket};
use tokio::time::{sleep, timeout, Duration};
use core::net::SocketAddr;

/// Maximum allowed duration for broadcast/listening operations in seconds
pub static MAX_BROADCAST_DURATION: u64 = 20;

/// Identifier name used to recognize CesaConn devices on the network
pub static BROADCAST_NAME: &str = "CesaConn Brodcast";

/// Binds a UDP socket to the given address and returns it.
/// Panics if binding fails — intentional, as the app cannot function without a socket.
pub async fn bind_socket(addr: &str) -> UdpSocket {
    match UdpSocket::bind(addr).await {
        Ok(s) => {
            println!("Succesfully binded socket.");
            s
        },
        Err(e) => {
            panic!("Failed to bind socket! | Error: {}", e)
        }
    }
}

/// Broadcasts a UDP presence message every second for the given duration.
/// Duration is capped at MAX_BROADCAST_DURATION to prevent indefinite broadcasting.
pub async fn udp_broadcast_presence(message: &str, duration: u64) {

    // Cap duration to the allowed maximum
    let duration = if duration > MAX_BROADCAST_DURATION { MAX_BROADCAST_DURATION } else { duration };
    let socket = bind_socket("0.0.0.0:6363").await;

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

    let socket = bind_socket("0.0.0.0:6363").await;
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
