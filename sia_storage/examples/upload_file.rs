use std::env;
use std::path::PathBuf;

use sia_storage::{AppKey, AppMetadata, Builder, Object, UploadOptions, app_id, encoded_size};
use tokio::fs::File;
use tokio::io::BufReader;

const APP_META: AppMetadata = AppMetadata {
    id: app_id!("c0000000000000000000000000000000000000000000000000000000000000de"),
    name: "Sialo",
    description: "Sialo file upload",
    service_url: "https://sialo.app",
    logo_url: None,
    callback_url: None,
};

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: upload_file <indexer_url> <app_key_hex> <file_path>");
        std::process::exit(1);
    }

    let indexer_url = &args[1];
    let app_key_hex = &args[2];
    let file_path = PathBuf::from(&args[3]);

    let key_bytes = hex::decode(app_key_hex).expect("invalid hex key");
    let app_key = AppKey::import(
        <[u8; 32]>::try_from(key_bytes.as_slice()).expect("key must be 32 bytes"),
    );

    let file_size = std::fs::metadata(&file_path).expect("cannot stat file").len();
    let opts = UploadOptions::default();
    let on_network = encoded_size(file_size, opts.data_shards, opts.parity_shards);

    fn fmt_size(n: u64) -> String {
        if n >= 1_073_741_824 { format!("{:.2} GiB", n as f64 / 1_073_741_824.0) }
        else if n >= 1_048_576 { format!("{:.2} MiB", n as f64 / 1_048_576.0) }
        else if n >= 1024 { format!("{:.1} KiB", n as f64 / 1024.0) }
        else { format!("{n} B") }
    }

    eprintln!("File:       {}", file_path.display());
    eprintln!("Size:       {} ({} bytes)", fmt_size(file_size), file_size);
    eprintln!("On-network: {} ({:.1}x with {}/{} erasure coding)",
        fmt_size(on_network), on_network as f64 / file_size.max(1) as f64,
        opts.data_shards, opts.parity_shards);

    eprintln!("Connecting to {}...", indexer_url);
    let builder = Builder::new(indexer_url, APP_META).expect("invalid URL");
    let sdk = builder
        .connected(&app_key)
        .await
        .expect("connection failed")
        .expect("app key not recognized");

    let file = File::open(&file_path).await.expect("cannot open file");
    let reader = BufReader::new(file);

    eprintln!("Uploading...");
    let obj = sdk
        .upload(Object::default(), reader, opts)
        .await
        .expect("upload failed");

    println!("Uploaded. Pinning...");
    sdk.pin_object(&obj).await.expect("pin failed");

    println!("Object ID: {}", obj.id());
    println!("Size: {} bytes", obj.size());
}
