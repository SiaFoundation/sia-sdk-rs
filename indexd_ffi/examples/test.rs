use std::time::{Duration, SystemTime};

use indexd_ffi::{AppMeta, SDK};
use log::info;

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let sdk = SDK::new(
        "https://app.indexd.zeus.sia.dev".into(),
        [26u8; 32].to_vec(),
    )
    .expect("expected sdk init");

    if !sdk.connect().await.expect("sdk connected") {
        let req = sdk
            .request_app_connection(AppMeta {
                name: "Test App".into(),
                description: "An example app using indexd-ffi".into(),
                service_url: "https://example.com".into(),
                logo_url: None,
                callback_url: None,
            })
            .await
            .expect("requested connection");
        info!("please approve the app by visiting: {}", req.response_url);
        if !sdk
            .wait_for_connect(&req)
            .await
            .expect("waited for connect")
        {
            panic!("app not approved");
        }
    }

    info!("connected");

    let encryption_key: [u8; 32] = rand::random();
    let writer = sdk
        .upload(encryption_key.to_vec(), 1, 3, None)
        .await
        .expect("writer");
    let data = vec![1u8; 1 << 22];

    writer.write(data.as_ref()).await.expect("data written");
    info!("chunk written");
    let object = writer.finalize().await.expect("upload to complete");
    assert_eq!(
        object.slabs[0].length as usize,
        data.len(),
        "length mismatch"
    );
    info!("upload complete, got {} slabs", object.slabs.len());

    let reader = sdk
        .download(&object, encryption_key.to_vec())
        .await
        .expect("reader init");

    let mut read_data = Vec::with_capacity(data.len());
    loop {
        let chunk = reader.read_chunk().await.expect("read chunk");
        if chunk.is_empty() {
            break;
        }
        read_data.extend_from_slice(&chunk);
    }

    if data != read_data {
        println!("{:?} ({})", &data[..100], data.len());
        println!("{:?} ({})", &read_data[..100], read_data.len());
        panic!("data mismatch"); // not using assert_eq to avoid printing huge data
    }
    info!("download complete, data matches original");

    info!("sharing object");

    let share_url = sdk
        .object_share_url(
            object.key,
            encryption_key.to_vec(),
            SystemTime::now() + Duration::from_secs(600),
        )
        .expect("share url");
    info!("share url: {}", share_url);

    info!("downloading shared object");

    let reader = sdk
        .download_shared(share_url)
        .await
        .expect("download shared");
    let mut read_data = Vec::with_capacity(data.len());
    loop {
        let chunk = reader.read_chunk().await.expect("read chunk");
        if chunk.is_empty() {
            break;
        }
        read_data.extend_from_slice(&chunk);
    }
    if data != read_data {
        println!("{:?} ({})", &data[..100], data.len());
        println!("{:?} ({})", &read_data[..100], read_data.len());
        panic!("data mismatch"); // not using assert_eq to avoid printing huge data
    }
    info!("download complete, data matches original");
}
