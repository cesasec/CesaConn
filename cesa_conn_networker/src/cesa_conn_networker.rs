
mod udp_networker;
mod tcp_networker;

#[tokio::main]
async fn main() {
    let addr = udp_networker::udp_find_broadcaster(21, udp_networker::BROADCAST_NAME).await;

    if addr.is_none() {
        eprintln!("Fail!");
    } else {
        println!("Ip: {}", addr.unwrap().ip());
    }
}