use std::io::{BufRead, Cursor, stdin};
use std::time::Instant;

use indexd::{AppMetadata, Builder, DownloadOptions, UploadOptions};
use rand::Rng;

const APP_META: AppMetadata = AppMetadata {
    id: indexd::app_id!("5c0b1af28e6ac76395b2087ea987297b9c496f90d2ab3e3d3d07980ae4c43633"),
    name: "My Example App",
    description: "My Example App Description",
    service_url: "https://myexampleapp.com",
    logo_url: None,
    callback_url: None,
};

#[tokio::main]
async fn main() {
    env_logger::init();

    // authorize the app to access the user's storage
    let builder =
        Builder::new("https://app.sia.storage", APP_META).expect("failed to create builder");

    let builder = builder
        .request_connection()
        .await
        .expect("failed to request connection");
    println!(
        "Visit the following URL to authorize the application: {}",
        builder.response_url()
    );

    let builder = builder
        .wait_for_approval()
        .await
        .expect("failed to wait for approval");
    println!("Connection approved!");

    println!("Enter recovery phrase:");
    let phrase = stdin()
        .lock()
        .lines()
        .next()
        .expect("failed to read recovery phrase")
        .expect("failed to read recovery phrase");

    let sdk = builder
        .register(&phrase)
        .await
        .expect("failed to register app");
    println!("App registered successfully!");

    let mut data = vec![0u8; 1024 * 1024]; // 1 MiB
    rand::rng().fill_bytes(&mut data);

    // upload the data to the network
    println!("Uploading random data...");
    let start = Instant::now();
    let obj = sdk
        .upload(
            Cursor::new(data),
            UploadOptions {
                data_shards: 25,
                parity_shards: 25,
                ..Default::default()
            },
        )
        .await
        .expect("failed to upload object");
    let duration = start.elapsed();
    println!(
        "Object uploaded ID: {}\tSize: {} bytes\tElapsed: {:?}",
        obj.id(),
        obj.size(),
        duration
    );

    // pin the object to ensure it remains available on the network.
    sdk.pin_object(&obj).await.expect("object to be pinned");
    println!("Object pinned successfully!");

    // download the object back from the network
    println!("Downloading object...");
    let start = Instant::now();
    let mut downloaded_data = Vec::new();
    sdk.download(&mut downloaded_data, &obj, DownloadOptions::default())
        .await
        .expect("failed to download object");
    let duration = start.elapsed();
    println!(
        "Object downloaded ID: {}\tSize: {} bytes\tElapsed: {:?}",
        obj.id(),
        downloaded_data.len(),
        duration,
    );
}
