use core::net::SocketAddr;
use std::fmt;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

use crate::auth::{auth_incoming, decrypt_tunnel};

/// Identifies what kind of data is being sent in a packet.
/// Encoded as a single byte at the start of the init header.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ActionType {
    Default = 0x00,
    Debug = 0x01,
    ClipboardSync = 0x02,
}

impl ActionType {
    /// Converts a raw byte to an ActionType, returns None for unknown values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::Debug),
            0x02 => Some(Self::ClipboardSync),
            _ => None,
        }
    }
}

/// All errors that can occur in the TCP networker.
#[derive(Debug, PartialEq)]
pub enum TcpNetworkerErrors {
    /// `listener.accept()` failed — OS-level socket error.
    FailedToAcceptConnection,
    /// Stream closed or errored before all expected bytes were read.
    FailedToReadFromStream,
    /// ECDH + pre-shared key authentication failed or returned an error.
    FailedToAuthenticate,
    /// AES-GCM decryption of tunnel data failed — wrong key or tampered data.
    FailedToDecryptTunnel,
}

impl fmt::Display for TcpNetworkerErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpNetworkerErrors::FailedToAcceptConnection => {
                write!(f, "failed to accept connection")
            }
            TcpNetworkerErrors::FailedToReadFromStream => write!(f, "failed to read from stream"),
            TcpNetworkerErrors::FailedToAuthenticate => write!(f, "authentication failed"),
            TcpNetworkerErrors::FailedToDecryptTunnel => write!(f, "failed to decrypt tunnel data"),
        }
    }
}

// TODO : Auth
/// Handles a single incoming TCP connection after it has been accepted.
///
/// Steps:
///   1. Authenticate the connection using ECDH + pre-shared key (see auth_incoming)
///   2. Read and decrypt the 37-byte init header using the session key (shared_key)
///      - init_buf[0]    = action type (see ActionType)
///      - init_buf[1..9] = data payload size as big-endian u64
///   3. Read and decrypt the data packet (size declared in the init header)
///      - Outer encryption: session key (shared_key) — unique per connection
///      - Inner encryption: data key (d_key) — static, extra layer of protection
///   4. Dispatch to the appropriate handler based on action type
pub async fn recv_handler(
    listener: Arc<RwLock<TcpListener>>,
    incoming_connection: (TcpStream, SocketAddr),
    a_key: Arc<RwLock<[u8; 32]>>,
    d_key: Arc<RwLock<[u8; 32]>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    cancellation_token: Arc<RwLock<CancellationToken>>,
) -> Result<(), TcpNetworkerErrors> {
    let mut connection = incoming_connection.0;
    let connection_mut = &mut connection;

    // Run the ECDH + pre-shared key handshake — derives shared_key for this session
    let (auth_result, shared_key) = auth_incoming(
        a_key,
        trusted_addrs,
        (connection_mut, incoming_connection.1),
    )
    .await
    .map_err(|_| TcpNetworkerErrors::FailedToAuthenticate)?;

    if !auth_result {
        println!(
            "Authentication failed for connection from {}",
            incoming_connection.1
        );
        return Ok(()); // Just close the connection by returning
    }

    // Read the encrypted init header (37 bytes = 12 nonce + 9 plaintext + 16 GCM tag)
    let e_init_buf = &mut [0u8; 37];

    connection_mut
        .read_exact(e_init_buf)
        .await
        .map_err(|_| TcpNetworkerErrors::FailedToReadFromStream)?;

    // Decrypt the init header using the session key
    let init_buf = decrypt_tunnel(&shared_key, e_init_buf)
        .map_err(|_| TcpNetworkerErrors::FailedToDecryptTunnel)?;

    // Extract the payload size from bytes 1..9 (big-endian u64)
    let size_bytes = &mut [0u8; 8];
    size_bytes.copy_from_slice(&init_buf[1..9]);

    let size = u64::from_be_bytes(*size_bytes);

    // Read the encrypted data packet — size was declared in the init header
    let e_t_data_buf = &mut vec![0u8; size as usize];

    connection_mut
        .read_exact(e_t_data_buf)
        .await
        .map_err(|_| TcpNetworkerErrors::FailedToReadFromStream)?;

    // Decrypt outer layer with session key — result is still encrypted with d_key
    let e_data_buf = decrypt_tunnel(&shared_key, e_t_data_buf)
        .map_err(|_| TcpNetworkerErrors::FailedToDecryptTunnel)?;

    // Decrypt inner layer with the static data key, then wipe it from memory
    let data_key = &mut d_key.read().await.clone();

    let data_buf = decrypt_tunnel(data_key, e_data_buf.as_ref())
        .map_err(|_| TcpNetworkerErrors::FailedToDecryptTunnel)?;

    Zeroize::zeroize(data_key);

    // Dispatch to the appropriate handler based on the action type byte
    match ActionType::from_u8(init_buf[0]) {
        Some(ActionType::Default) => {
            println!("default");
            // Handle default action
        }
        Some(ActionType::Debug) => {
            println!(
                "Received debug action | size: {} | offset: {} | data: {}",
                size,
                init_buf[0],
                String::from_utf8_lossy(&data_buf)
            );
            // Handle debug action
        }
        Some(ActionType::ClipboardSync) => {
            println!(
                "Received clipboard sync action with size {}: {:?}",
                size, init_buf[0]
            );
            // Handle clipboard sync action
        }
        None => {
            println!("Received unknown action type: {}", init_buf[0]);
            // Handle unknown action type
        }
    }

    Ok(())
}

/// Accepts connections in a loop and spawns a `recv_handler` task for each one.
/// Stops when the cancellation token is cancelled.
///
/// Each connection runs in its own task so they don't block each other.
/// If the token is cancelled while a handler is running, the handler is dropped.
pub async fn recv(
    listener: Arc<RwLock<TcpListener>>,
    addr: &str,
    a_key: Arc<RwLock<[u8; 32]>>,
    d_key: Arc<RwLock<[u8; 32]>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    cancellation_token: Arc<RwLock<CancellationToken>>,
) -> Result<(), TcpNetworkerErrors> {
    println!("Listening on: {addr}");

    loop {
        let cancellation_token_clone = Arc::clone(&cancellation_token);

        let cloned_token = cancellation_token.read().await.clone();

        // Clone Arcs so the spawned task owns its own references
        let listener_clone = Arc::clone(&listener);
        let a_key_clone = Arc::clone(&a_key);
        let d_key_clone = Arc::clone(&d_key);
        let trusted_addrs_clone = Arc::clone(&trusted_addrs);

        let guard = listener.read().await;
        let incoming_connection = select! {
            _ = cloned_token.cancelled() => {
                println!("Quitting...");
                break;
            },
            result = guard.accept() => {
                result.map_err(|_| TcpNetworkerErrors::FailedToAcceptConnection)?
            }
        };

        tokio::spawn(async move {
            select! {
                // Abort the handler if the token is cancelled mid-connection
                _ = cloned_token.cancelled() => {
                // The token was cancelled
                println!("Quitting...");
                },
                _ = recv_handler(listener_clone, incoming_connection, a_key_clone, d_key_clone, trusted_addrs_clone, cancellation_token_clone) => {
                    println!("Passed connection to handler");
                }
            }
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::encrypt_tunnel;
    use cesa_conn_crypto::ecdh::{
        calculate_public_key, calculate_shared_key, generate_private_key, hash_key,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    const TEST_A_KEY: [u8; 32] = [0xAB; 32]; // pre-shared auth key
    const TEST_D_KEY: [u8; 32] = [0xCD; 32]; // data encryption key

    /// Spins up a TCP listener and returns (listener, client_stream, peer_addr).
    async fn setup_tcp_pair() -> (TcpListener, TcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let peer_addr = client.peer_addr().unwrap();
        (listener, client, peer_addr)
    }

    fn make_state(
        a_key: [u8; 32],
        d_key: [u8; 32],
        trusted: Vec<SocketAddr>,
    ) -> (
        Arc<RwLock<[u8; 32]>>,
        Arc<RwLock<[u8; 32]>>,
        Arc<RwLock<Vec<SocketAddr>>>,
        Arc<RwLock<CancellationToken>>,
    ) {
        (
            Arc::new(RwLock::new(a_key)),
            Arc::new(RwLock::new(d_key)),
            Arc::new(RwLock::new(trusted)),
            Arc::new(RwLock::new(CancellationToken::new())),
        )
    }

    /// Performs the full client-side auth handshake and returns the shared_key_hash.
    async fn client_auth(stream: &mut TcpStream, auth_key: [u8; 32]) -> [u8; 32] {
        let client_priv = generate_private_key();
        let client_pub = calculate_public_key(&client_priv);

        stream.write_all(&client_pub).await.unwrap();

        let server_pub = &mut [0u8; 32];
        stream.read_exact(server_pub).await.unwrap();

        let shared = calculate_shared_key(&client_priv, server_pub);
        let shared_hash = hash_key(&shared);

        // Send encrypted auth key to server
        let payload = encrypt_tunnel(&shared_hash, &auth_key).unwrap();
        stream.write_all(&payload).await.unwrap();

        // Read server's confirmation payload (60 bytes) and verify it
        let recv_buf = &mut [0u8; 60];
        stream.read_exact(recv_buf).await.unwrap();

        let recv_nonce: [u8; 12] = recv_buf[0..12].try_into().unwrap();
        let recv_plaintext =
            cesa_conn_crypto::aes::decrypt(&shared_hash, &recv_buf[12..], &recv_nonce).unwrap();

        let confirmed = recv_plaintext == auth_key;
        stream
            .write_all(&[if confirmed { 0x01 } else { 0x00 }])
            .await
            .unwrap();

        shared_hash
    }

    /// Connection from an untrusted address must be rejected — recv_handler returns Ok(())
    /// without reading any data.
    #[tokio::test]
    async fn test_recv_handler_untrusted_addr_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        let (a_key, d_key, trusted, token) = make_state(TEST_A_KEY, TEST_D_KEY, vec![]); // empty trusted list
        let listener_arc = Arc::new(RwLock::new(TcpListener::bind("127.0.0.1:0").await.unwrap()));

        drop(client); // not needed — server rejects before reading anything

        let result = recv_handler(
            listener_arc,
            (server, peer_addr),
            a_key,
            d_key,
            trusted,
            token,
        )
        .await;

        // Untrusted address returns Ok(()) — graceful rejection, not an error
        assert!(result.is_ok());
    }

    /// Stream closes during auth — must return FailedToAuthenticate.
    #[tokio::test]
    async fn test_recv_handler_stream_closes_during_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        let (a_key, d_key, trusted, token) = make_state(TEST_A_KEY, TEST_D_KEY, vec![peer_addr]);
        let listener_arc = Arc::new(RwLock::new(TcpListener::bind("127.0.0.1:0").await.unwrap()));

        drop(client); // close immediately — auth read_exact will fail

        let result = recv_handler(
            listener_arc,
            (server, peer_addr),
            a_key,
            d_key,
            trusted,
            token,
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            TcpNetworkerErrors::FailedToAuthenticate
        );
    }

    /// Full happy path — auth succeeds, init header and data packet are read and decrypted.
    #[tokio::test]
    async fn test_recv_handler_full_happy_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        let (a_key, d_key, trusted, token) = make_state(TEST_A_KEY, TEST_D_KEY, vec![peer_addr]);
        let listener_arc = Arc::new(RwLock::new(TcpListener::bind("127.0.0.1:0").await.unwrap()));

        let client_task = tokio::spawn(async move {
            // Complete the auth handshake and get the shared session key
            let shared_hash = client_auth(&mut client, TEST_A_KEY).await;

            // Build a 9-byte plaintext init header:
            // [0] = action type (Debug = 0x01)
            // [1..9] = data size as big-endian u64
            let payload = b"hello!!"; // 7 bytes
            // Double-encrypt the payload: inner = d_key, outer = shared_hash
            let inner = encrypt_tunnel(&TEST_D_KEY, payload).unwrap();
            let outer = encrypt_tunnel(&shared_hash, &inner).unwrap();

            let data_size = outer.len() as u64;
            let mut init_plaintext = [0u8; 9];
            init_plaintext[0] = 0x01; // Debug
            init_plaintext[1..9].copy_from_slice(&data_size.to_be_bytes());

            // Encrypt and send the init header
            let init_packet = encrypt_tunnel(&shared_hash, &init_plaintext).unwrap();
            client.write_all(&init_packet).await.unwrap();

            // Send the double-encrypted data packet
            client.write_all(&outer).await.unwrap();
        });

        let result = recv_handler(
            listener_arc,
            (server, peer_addr),
            a_key,
            d_key,
            trusted,
            token,
        )
        .await;
        client_task.await.unwrap();

        assert!(result.is_ok());
    }

    /// All known byte values must map to the correct ActionType variant.
    #[test]
    fn test_action_type_from_u8_known() {
        assert_eq!(ActionType::from_u8(0x00), Some(ActionType::Default));
        assert_eq!(ActionType::from_u8(0x01), Some(ActionType::Debug));
        assert_eq!(ActionType::from_u8(0x02), Some(ActionType::ClipboardSync));
    }

    /// Unknown byte values must return None — not panic or guess.
    #[test]
    fn test_action_type_from_u8_unknown() {
        assert_eq!(ActionType::from_u8(0x03), None);
        assert_eq!(ActionType::from_u8(0xFF), None);
    }

    /// Wire discriminants must match the documented values — if these change,
    /// it breaks the protocol with existing clients.
    #[test]
    fn test_action_type_discriminants() {
        assert_eq!(ActionType::Default as u8, 0x00);
        assert_eq!(ActionType::Debug as u8, 0x01);
        assert_eq!(ActionType::ClipboardSync as u8, 0x02);
    }

    #[test]
    fn test_error_display_accept() {
        assert_eq!(
            TcpNetworkerErrors::FailedToAcceptConnection.to_string(),
            "failed to accept connection"
        );
    }

    #[test]
    fn test_error_display_read() {
        assert_eq!(
            TcpNetworkerErrors::FailedToReadFromStream.to_string(),
            "failed to read from stream"
        );
    }

    #[test]
    fn test_error_display_auth() {
        assert_eq!(
            TcpNetworkerErrors::FailedToAuthenticate.to_string(),
            "authentication failed"
        );
    }

    #[test]
    fn test_error_display_decrypt() {
        assert_eq!(
            TcpNetworkerErrors::FailedToDecryptTunnel.to_string(),
            "failed to decrypt tunnel data"
        );
    }
}
