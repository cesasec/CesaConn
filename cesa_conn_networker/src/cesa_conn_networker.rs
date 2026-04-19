/* TODO NOW: 
IMPORTANT:

TCP CONNECTIVITY
AUTH

---------------

CLIPBOARD SYNC
FOLDER SYNC

*/


/* TODO AFTER POC:

IMPORTANT:

GET RID OF STORING KEYS IN RAM

---------------

 */



mod udp_networker;
mod tcp_networker;
mod auth;
use std::{env, net::SocketAddr, sync::Arc};
use tracing_subscriber::EnvFilter;

use cesa_conn_crypto::{pswd_manager::derive_key};
use tokio::{net::{TcpListener}, sync::RwLock};
use tokio_util::sync::CancellationToken;

use crate::{tcp_networker::{ActionType, connect, recv}, udp_networker::{BROADCAST_NAME, udp_broadcast_presence, udp_find_broadcaster}};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("cesa_conn=debug".parse().unwrap()))
        .init();

    let args: Vec<String> = env::args().collect();

    match args[1].as_str() {
        "servertest" => {
            let test_psw = "password".as_bytes();
            let mut salt = [0u8; 32];
            salt[0..test_psw.len()].copy_from_slice(test_psw);
            let a_key = Arc::new(RwLock::new(derive_key(test_psw, salt).unwrap()));

            let a_key_clone = a_key.clone();

            udp_broadcast_presence(BROADCAST_NAME.as_bytes(), 10, a_key_clone).await.unwrap();

            let listener = Arc::new(RwLock::new(TcpListener::bind("0.0.0.0:3232").await.unwrap()));
            let trusted_addrs = Arc::new(RwLock::new(Vec::new()));

            let incoming_addr = udp_find_broadcaster(10, BROADCAST_NAME.as_bytes(), a_key.clone()).await.unwrap();
            let write_g = trusted_addrs.write();

            write_g.await.push(incoming_addr);

            let cancellation_token = Arc::new(RwLock::new(CancellationToken::new()));

            recv(listener, a_key.clone(), a_key.clone(), trusted_addrs, cancellation_token).await.unwrap();
        }

        "clienttest" => {
            let test_psw = "password".as_bytes();
            let mut salt = [0u8; 32];
            salt[0..test_psw.len()].copy_from_slice(test_psw);
            let a_key = Arc::new(RwLock::new(derive_key(test_psw, salt).unwrap()));

            let a_key_clone = a_key.clone();

            let trusted_addrs = Arc::new(RwLock::new(Vec::new()));

            let incoming_addr = udp_find_broadcaster(10, BROADCAST_NAME.as_bytes(), a_key.clone()).await.unwrap();
            let write_g = trusted_addrs.write();
            udp_broadcast_presence(BROADCAST_NAME.as_bytes(), 10, a_key_clone).await.unwrap();

            write_g.await.push(incoming_addr);

            let cancellation_token = Arc::new(RwLock::new(CancellationToken::new()));

            let message = "test message";

            let connect_addr = SocketAddr::new(incoming_addr.ip(), 3232);

            let action_type = ActionType::Debug;

            connect(a_key.clone(), a_key.clone(), trusted_addrs, cancellation_token, connect_addr, action_type, message.as_bytes().to_vec()).await.unwrap();

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
        _ => {}
    }
}