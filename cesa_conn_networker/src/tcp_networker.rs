use core::net::SocketAddr;
use std::sync::Arc;
use tokio::select;
use tokio::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};
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
    listener: Arc<Mutex<TcpListener>>,
    incoming_connection: (TcpStream, SocketAddr),
    key: Arc<Mutex<[u8; 32]>>,
    trusted_addrs: Arc<Mutex<Vec<SocketAddr>>>,
    cancellation_token: Arc<Mutex<CancellationToken>>,
) {

    
}

// TODO : Auth
pub async fn connect_handler(
    connection: (TcpStream, SocketAddr),
    key: &mut [u8; 32],
    trusted_addrs: &mut Vec<u8>,
) {

    //logic here
}

pub async fn recv(
    listener: Arc<Mutex<TcpListener>>,
    addr: &str,
    key: Arc<Mutex<[u8; 32]>>,
    trusted_addrs: Arc<Mutex<Vec<SocketAddr>>>,
    cancellation_token: Arc<Mutex<CancellationToken>>,
) -> Result<(), TcpNetworkerErrors> {

    println!("Listening on: {addr}");

    loop {
        let listener_clone = Arc::clone(&listener);
        let key_clone = Arc::clone(&key);
        let trusted_addrs_clone = Arc::clone(&trusted_addrs);
        let cancellation_token_clone = Arc::clone(&cancellation_token);

        let cloned_token = cancellation_token.lock().await.clone();

        let incoming_connection = listener
            .lock()
            .await
            .accept()
            .await
            .map_err(|_| TcpNetworkerErrors::FailedToAcceptConnection)?;

        let join_handle = tokio::spawn(async move {
            select! {
                _ = cloned_token.cancelled() => {
                // The token was cancelled
                println!("Cancelled");
                5
                },
                _ = recv_handler(listener_clone, incoming_connection, key_clone, trusted_addrs_clone, cancellation_token_clone) => {
                    println!("Finished");
                    99
                }
            }
        });
    }

    Ok(())
}

pub async fn connect(addr: &str) {
   
}
