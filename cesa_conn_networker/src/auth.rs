use cesa_conn_crypto::aes::{decrypt, encrypt};
use cesa_conn_crypto::ecdh::{
    calculate_public_key, calculate_shared_key, generate_private_key, hash_key,
};
use core::net::SocketAddr;
use std::fmt;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::{io::AsyncReadExt, net::TcpStream, sync::RwLock};
use zeroize::Zeroize;

/// All errors that can occur during authentication.
#[derive(Debug, PartialEq)]
pub enum AuthErrors {
    /// The TCP stream ended or errored before we could read all expected bytes.
    FailedToReadFromStream,
    /// AES-GCM decryption failed — wrong shared secret or tampered data.
    FailedToDecrypt,
    /// The TCP stream errored while sending data to the client.
    FailedToWriteToStream,
    /// Failed to encrypt the authentication key.
    FailedToEncrypt,
}

impl fmt::Display for AuthErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthErrors::FailedToReadFromStream => {
                write!(f, "failed to read authentication key from stream")
            }
            AuthErrors::FailedToDecrypt => write!(f, "failed to decrypt authentication key"),
            AuthErrors::FailedToWriteToStream => write!(f, "failed to write to stream"),
            AuthErrors::FailedToEncrypt => write!(f, "failed to encrypt authentication key"),
        }
    }
}

/// Authenticates an incoming TCP connection using ECDH key exchange + pre-shared key verification.
///
/// Handshake sequence:
///   1. Client → Server: client's X25519 ephemeral public key (32 bytes)
///   2. Server → Client: server's X25519 ephemeral public key (32 bytes)
///   3. Client → Server: nonce (12 bytes) + AES-256-GCM ciphertext (48 bytes) = 60 bytes total
///      - Client encrypts the pre-shared key using SHA-256(ECDH shared secret) as the AES key
///   4. Server → Client: nonce (12 bytes) + AES-256-GCM ciphertext (48 bytes) = 60 bytes total
///      - Server encrypts the same pre-shared key back so the client can verify the server knows it too
///   5. Client → Server: 1 confirmation byte (non-zero = client verified server's response)
///
/// Both sides prove they know the pre-shared key, so neither can impersonate the other.
///
/// Returns (authenticated, server_public_key, shared_key_hash).
/// The caller should use shared_key_hash as the session encryption key for all further communication.
pub async fn auth_incoming(
    key: Arc<RwLock<[u8; 32]>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    incoming_connection: (&mut TcpStream, SocketAddr),
) -> Result<(bool, [u8; 32], [u8; 32]), AuthErrors> {
    // Step 1: IP allowlist check — reject unknown peers before doing any crypto work
    if !trusted_addrs.read().await.contains(&incoming_connection.1) {
        println!(
            "Received connection from untrusted address: {}",
            incoming_connection.1
        );
        return Ok((false, [0u8; 32], [0u8; 32]));
    }

    println!(
        "Received connection from trusted address: {}",
        incoming_connection.1
    );

    // Step 2: Read the client's X25519 ephemeral public key (always exactly 32 bytes)
    let their_pub_key = &mut [0u8; 32];

    incoming_connection
        .0
        .read_exact(their_pub_key)
        .await
        .map_err(|_| AuthErrors::FailedToReadFromStream)?;

    // An all-zero public key is cryptographically invalid — reject it
    if their_pub_key == &[0u8; 32] {
        println!(
            "Received invalid public key from address: {}",
            incoming_connection.1
        );
        return Ok((false, [0u8; 32], [0u8; 32]));
    }

    // Step 3: Generate our ephemeral keypair and derive the shared secret
    // private_key is marked &mut so we can zeroize it from memory after use
    let private_key = &mut generate_private_key();
    let public_key = calculate_public_key(&private_key);
    let shared_key = &mut calculate_shared_key(&private_key, their_pub_key);

    // Hash the raw ECDH output before using it as an AES key — raw shared secrets
    // are not uniformly distributed and must not be used directly
    let shared_key_hash = hash_key(&shared_key);

    // Wipe private key and raw shared secret from memory immediately — they're no longer needed
    Zeroize::zeroize(private_key);
    Zeroize::zeroize(shared_key);

    // Step 3b: Send our public key to the client so they can compute the same shared secret
    incoming_connection
        .0
        .write_all(&public_key)
        .await
        .map_err(|_| AuthErrors::FailedToWriteToStream)?;

    // Step 4: Read the client's encrypted pre-shared key
    // Layout: [ nonce (12 bytes) | AES-GCM ciphertext (48 bytes) ] = 60 bytes total
    // Ciphertext = encrypt(pre_shared_key[32 bytes]) → 32 + 16 (GCM tag) = 48 bytes
    let e_key_buf = &mut [0u8; 60];
    let nonce = &mut [0u8; 12];

    incoming_connection
        .0
        .read_exact(e_key_buf)
        .await
        .map_err(|_| AuthErrors::FailedToReadFromStream)?;

    nonce.copy_from_slice(&e_key_buf[0..12]);

    // Step 5: Decrypt using the derived shared key — GCM will also verify integrity,
    // so any tampering or wrong key causes an error here
    let key_buf = &mut decrypt(&shared_key_hash, &e_key_buf[12..60], nonce)
        .map_err(|_| AuthErrors::FailedToDecrypt)?;

    // Wipe the encrypted buffer and nonce — plaintext key is now in key_buf
    Zeroize::zeroize(e_key_buf);
    Zeroize::zeroize(nonce);

    // Step 6: Compare decrypted key against the expected pre-shared key
    if key_buf != key.read().await.as_ref() {
        println!(
            "Authentication failed for address: {}",
            incoming_connection.1
        );
        return Ok((false, [0u8; 32], [0u8; 32]));
    }

    // Wipe the decrypted key now that comparison is done
    Zeroize::zeroize(key_buf);

    // Step 7: Encrypt our pre-shared key and send it back so the client can verify
    // we know the same key — mutual authentication
    let e_key = &mut encrypt(&shared_key_hash, key.read().await.as_ref())
        .map_err(|_| AuthErrors::FailedToEncrypt)?;

    // Pack nonce + ciphertext into a single 60-byte buffer before sending
    let send_buf = &mut [0u8; 60];
    send_buf[0..12].copy_from_slice(&e_key.1);  // nonce
    send_buf[12..60].copy_from_slice(&e_key.0); // ciphertext

    incoming_connection
        .0
        .write_all(send_buf)
        .await
        .map_err(|_| AuthErrors::FailedToWriteToStream)?;

    // Wipe sensitive data — key material no longer needed
    Zeroize::zeroize(send_buf);
    Zeroize::zeroize(&mut e_key.0);
    Zeroize::zeroize(&mut e_key.1);

    // Step 8: Read 1-byte confirmation from client — non-zero means they decrypted
    // our response successfully and confirmed they know the pre-shared key
    let buf = &mut [0u8];

    incoming_connection
        .0
        .read_exact(buf)
        .await
        .map_err(|_| AuthErrors::FailedToReadFromStream)?;

    if buf != &[1u8] {
        println!(
            "Client rejected our key confirmation, authentication failed for address: {}",
            incoming_connection.1
        );
        return Ok((false, [0u8; 32], [0u8; 32]));
    }

    println!(
        "Authentication successful for address: {}",
        incoming_connection.1
    );

    // Return the server's public key so the caller can send it to the client,
    // and the shared_key_hash for use as the session encryption key
    Ok((true, public_key, shared_key_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesa_conn_crypto::aes::{decrypt, encrypt};
    use cesa_conn_crypto::ecdh::{
        calculate_public_key, calculate_shared_key, generate_private_key, hash_key,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    const TEST_KEY: [u8; 32] = [0xAB; 32];

    /// Spins up a TCP listener, connects a client, returns (server_stream, client_stream, peer_addr)
    async fn setup_tcp_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();
        (server, client, peer_addr)
    }

    fn make_shared_state(
        key: [u8; 32],
        trusted: Vec<SocketAddr>,
    ) -> (Arc<RwLock<[u8; 32]>>, Arc<RwLock<Vec<SocketAddr>>>) {
        (Arc::new(RwLock::new(key)), Arc::new(RwLock::new(trusted)))
    }

    /// Connection from an address not in the trusted list must be rejected immediately.
    #[tokio::test]
    async fn test_untrusted_addr_rejected() {
        let (mut server, _client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![]);

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap(), (false, [0u8; 32], [0u8; 32]));
    }

    /// An all-zero public key is invalid and must be rejected after reading.
    #[tokio::test]
    async fn test_zero_pubkey_rejected() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        client.write_all(&[0u8; 32]).await.unwrap();

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap(), (false, [0u8; 32], [0u8; 32]));
    }

    /// Stream closing before sending a full public key must return FailedToReadFromStream.
    #[tokio::test]
    async fn test_incomplete_pubkey_returns_error() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        client.write_all(&[0xAB; 10]).await.unwrap();
        drop(client); // close stream early

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap_err(), AuthErrors::FailedToReadFromStream);
    }

    /// Stream closing after pubkey exchange but before sending the full 60-byte encrypted payload
    /// must return FailedToReadFromStream.
    /// Client reads server pubkey first to avoid a race where the server's write fails instead.
    #[tokio::test]
    async fn test_incomplete_encrypted_payload_returns_error() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let client_task = tokio::spawn(async move {
            let client_priv = generate_private_key();
            let client_pub = calculate_public_key(&client_priv);

            // Send our pubkey so server can proceed to send its own
            client.write_all(&client_pub).await.unwrap();

            // Read server's pubkey so the server's write_all doesn't fail
            client.read_exact(&mut [0u8; 32]).await.unwrap();

            // Send only 20 of the required 60 bytes then close
            client.write_all(&[0xAB; 20]).await.unwrap();
            drop(client);
        });

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        client_task.await.unwrap();

        assert_eq!(result.unwrap_err(), AuthErrors::FailedToReadFromStream);
    }

    /// Sending garbage bytes as the encrypted payload must fail decryption (GCM tag mismatch).
    #[tokio::test]
    async fn test_invalid_ciphertext_returns_decrypt_error() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let client_priv = generate_private_key();
        let client_pub = calculate_public_key(&client_priv);

        client.write_all(&client_pub).await.unwrap();
        client.write_all(&[0xDE; 60]).await.unwrap(); // random garbage

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap_err(), AuthErrors::FailedToDecrypt);
    }

    /// Simulates the full client side of the handshake.
    /// Returns true if the server's key confirmation matched, false otherwise.
    async fn run_client(mut stream: TcpStream, auth_key: [u8; 32]) -> bool {
        let client_priv = generate_private_key();
        let client_pub = calculate_public_key(&client_priv);

        // Step 1: send our public key
        stream.write_all(&client_pub).await.unwrap();

        // Step 2: read server's public key
        let server_pub = &mut [0u8; 32];
        stream.read_exact(server_pub).await.unwrap();

        // Step 3: derive shared secret and encrypt our copy of the auth key
        let shared = calculate_shared_key(&client_priv, server_pub);
        let shared_hash = hash_key(&shared);
        let (ciphertext, nonce) = encrypt(&shared_hash, &auth_key).unwrap();

        // Send nonce (12 bytes) followed by ciphertext (48 bytes)
        stream.write_all(&nonce).await.unwrap();
        stream.write_all(&ciphertext).await.unwrap();

        // Step 4: read server's encrypted key back (60 bytes: nonce + ciphertext)
        // If server rejected us (wrong key), it closes the connection here — read_exact will error
        let recv_buf = &mut [0u8; 60];
        if stream.read_exact(recv_buf).await.is_err() {
            return false;
        }

        let recv_nonce: [u8; 12] = recv_buf[0..12].try_into().unwrap();
        let recv_plaintext = match decrypt(&shared_hash, &recv_buf[12..60], &recv_nonce) {
            Ok(p) => p,
            Err(_) => return false, // server sent something we can't decrypt
        };

        // Step 5: send 1-byte confirmation — 0x01 = verified, 0x00 = rejected
        let confirmed = recv_plaintext == auth_key;
        let confirm_byte: u8 = if confirmed { 0x01 } else { 0x00 };
        stream.write_all(&[confirm_byte]).await.unwrap();

        confirmed
    }

    /// Correct pre-shared key and trusted address must result in successful authentication
    /// on both sides — server returns true, client confirms the server's response.
    /// Also verifies the returned public key and shared key hash are valid (non-zero).
    #[tokio::test]
    async fn test_correct_key_auth_success() {
        let (mut server, client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        // Server and client must run concurrently — both block waiting for the other
        let client_task = tokio::spawn(run_client(client, TEST_KEY));
        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        let client_confirmed = client_task.await.unwrap();

        let (authenticated, pub_key, shared_key_hash) = result.unwrap();
        assert!(authenticated);
        assert!(client_confirmed);
        // Both returned values must be non-zero — zeros would mean the ECDH failed silently
        assert_ne!(pub_key, [0u8; 32]);
        assert_ne!(shared_key_hash, [0u8; 32]);
    }

    /// Wrong pre-shared key — server rejects during key comparison and returns early.
    /// The server stream (owned by the test) is dropped after auth_incoming returns,
    /// which closes the connection and lets the client detect rejection via read error.
    #[tokio::test]
    async fn test_wrong_key_server_rejects() {
        let (mut server, client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let wrong_key = [0xFFu8; 32];
        let client_task = tokio::spawn(timeout(Duration::from_secs(5), run_client(client, wrong_key)));
        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;

        // Drop server stream explicitly so the client's read_exact gets an EOF
        drop(server);

        let client_confirmed = client_task.await.unwrap().unwrap();

        assert_eq!(result.unwrap(), (false, [0u8; 32], [0u8; 32]));
        assert!(!client_confirmed);
    }

    /// Client sends the correct key but then rejects the server's confirmation (sends 0x00).
    /// Server should return false after reading the zero confirmation byte.
    #[tokio::test]
    async fn test_client_rejects_server_confirmation() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let client_task = tokio::spawn(async move {
            let client_priv = generate_private_key();
            let client_pub = calculate_public_key(&client_priv);

            client.write_all(&client_pub).await.unwrap();

            let server_pub = &mut [0u8; 32];
            client.read_exact(server_pub).await.unwrap();

            let shared = calculate_shared_key(&client_priv, server_pub);
            let shared_hash = hash_key(&shared);
            let (ciphertext, nonce) = encrypt(&shared_hash, &TEST_KEY).unwrap();
            client.write_all(&nonce).await.unwrap();
            client.write_all(&ciphertext).await.unwrap();

            // Read and discard server's confirmation payload
            let _ = client.read_exact(&mut [0u8; 60]).await;

            // Send 0x00 — client rejects
            client.write_all(&[0x00u8]).await.unwrap();
        });

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        client_task.await.unwrap();

        assert_eq!(result.unwrap(), (false, [0u8; 32], [0u8; 32]));
    }

    /// Client completes the full handshake correctly but closes the connection instead of
    /// sending the confirmation byte — server must return FailedToReadFromStream.
    #[tokio::test]
    async fn test_confirmation_byte_missing() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let client_task = tokio::spawn(async move {
            let client_priv = generate_private_key();
            let client_pub = calculate_public_key(&client_priv);

            client.write_all(&client_pub).await.unwrap();

            let server_pub = &mut [0u8; 32];
            client.read_exact(server_pub).await.unwrap();

            let shared = calculate_shared_key(&client_priv, server_pub);
            let shared_hash = hash_key(&shared);
            let (ciphertext, nonce) = encrypt(&shared_hash, &TEST_KEY).unwrap();
            client.write_all(&nonce).await.unwrap();
            client.write_all(&ciphertext).await.unwrap();

            // Read server's confirmation payload so its write_all doesn't fail
            client.read_exact(&mut [0u8; 60]).await.unwrap();

            // Close without sending the confirmation byte
            drop(client);
        });

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        client_task.await.unwrap();

        assert_eq!(result.unwrap_err(), AuthErrors::FailedToReadFromStream);
    }

    /// Each successful auth must produce a different shared key because ephemeral keys are
    /// generated fresh per connection.
    #[tokio::test]
    async fn test_shared_key_unique_per_session() {
        let (mut server1, client1, peer_addr1) = setup_tcp_pair().await;
        let (mut server2, client2, peer_addr2) = setup_tcp_pair().await;
        let (key1, trusted1) = make_shared_state(TEST_KEY, vec![peer_addr1]);
        let (key2, trusted2) = make_shared_state(TEST_KEY, vec![peer_addr2]);

        let t1 = tokio::spawn(run_client(client1, TEST_KEY));
        let t2 = tokio::spawn(run_client(client2, TEST_KEY));

        let r1 = auth_incoming(key1, trusted1, (&mut server1, peer_addr1)).await;
        let r2 = auth_incoming(key2, trusted2, (&mut server2, peer_addr2)).await;

        t1.await.unwrap();
        t2.await.unwrap();

        let (_, _, hash1) = r1.unwrap();
        let (_, _, hash2) = r2.unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_error_display_read() {
        assert_eq!(
            AuthErrors::FailedToReadFromStream.to_string(),
            "failed to read authentication key from stream"
        );
    }

    #[test]
    fn test_error_display_decrypt() {
        assert_eq!(
            AuthErrors::FailedToDecrypt.to_string(),
            "failed to decrypt authentication key"
        );
    }

    #[test]
    fn test_error_display_write() {
        assert_eq!(
            AuthErrors::FailedToWriteToStream.to_string(),
            "failed to write to stream"
        );
    }

    #[test]
    fn test_error_display_encrypt() {
        assert_eq!(
            AuthErrors::FailedToEncrypt.to_string(),
            "failed to encrypt authentication key"
        );
    }
}
