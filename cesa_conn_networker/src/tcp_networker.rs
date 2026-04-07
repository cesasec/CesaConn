use core::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub enum TcpNetworkerErrors {
    FailedToBindSocket,
    FailedToAcceptConnection,
}

pub static DEFAULT_ADDR: &str = "127.0.0.1:6969";
pub static AUTH_BUFFER_SIZE: usize = 1024;
pub static BUFFER_SIZE: usize = 4096;

// TODO : Auth
pub async fn recv_handler(
    listener: Arc<RwLock<TcpListener>>,
    incoming_connection: (TcpStream, SocketAddr),
    a_key: Arc<RwLock<[u8; 32]>>,
    d_key: Arc<RwLock<[u8; 32]>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    cancellation_token: Arc<RwLock<CancellationToken>>,
) {
}

// TODO : Auth
pub async fn connect_handler(
    connection: (TcpStream, SocketAddr),
    a_key: Arc<RwLock<[u8; 32]>>,
    d_key: Arc<RwLock<[u8; 32]>>,
    trusted_addrs: &mut Vec<u8>,
) {

    //logic here
}

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

        if cloned_token.is_cancelled() {
            println!("Quitting...");
            break;
        }

        let listener_clone = Arc::clone(&listener);
        let a_key_clone = Arc::clone(&a_key);
        let d_key_clone = Arc::clone(&d_key);
        let trusted_addrs_clone = Arc::clone(&trusted_addrs);

        let incoming_connection = listener
            .read()
            .await
            .accept()
            .await
            .map_err(|_| TcpNetworkerErrors::FailedToAcceptConnection)?;

        tokio::spawn(async move {
            select! {
                _ = cloned_token.cancelled() => {
                // The token was cancelled
                println!("Quitting...");
                5
                },
                _ = recv_handler(listener_clone, incoming_connection, a_key_clone, d_key_clone, trusted_addrs_clone, cancellation_token_clone) => {
                    println!("Passed connection to handler");
                    99
                }
            }
        });
    }

    Ok(())
}

pub async fn connect(addr: &str) {}
