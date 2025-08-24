use quic::Dialer;
use sia::{public_key, rhp::Host, types::v2::{NetAddress, Protocol}};
use tokio::time::sleep;
use core::time::Duration;


#[tokio::main]
async fn main() {
    let host_key = public_key!("ed25519:36c8b07e61548a57e16dfabdfcc07dc157974a75010ab1684643d933e83fa7b1");

    let mut dialer = Dialer::new();
    dialer.set_hosts(vec![
        Host{
            public_key: host_key,
            addresses: vec![
                NetAddress{
                    protocol: Protocol::QUIC,
                    address: "6r4b0vj1ai55fobdvauvpg3to5bpeijl045b2q268fcj7q1vkuog.sia.host:9984".into(),
                },
            ],
        }
    ]).await;

    let prices = dialer.host_prices(host_key, false).await.expect("Failed to get host prices");
    // check that they are cached
    let prices2 = dialer.host_prices(host_key, false).await.expect("Failed to get host prices");
    assert_eq!(prices, prices2);
    sleep(Duration::from_secs(2)).await; // ensure the signature changes
    let prices3 = dialer.host_prices(host_key, true).await.expect("Failed to get host prices");
    assert_ne!(prices2, prices3);
}