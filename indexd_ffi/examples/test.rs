use indexd_ffi::{AppMeta, PinnedSector, SDK, SlabPinParams};
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

    let slab_pin_params = SlabPinParams {
        encryption_key: vec![255; 32],
        min_shards: 1,
        sectors: vec![
            PinnedSector {
                host_key:
                    "ed25519:eb5172fb6e1644d9308ca55caf1ffcafccd4ff1542918daeb69b024ed602409e"
                        .to_string(),
                root: "afd1e5b79601efcbfb7283fc7a79bad6964607e373942856c2521b0218aab6e9"
                    .to_string(),
            },
            PinnedSector {
                host_key:
                    "ed25519:bb362c9c3b0dfbff5375b61d7bac949d063bf796e7c3a7ea1d3f68184b445033"
                        .to_string(),
                root: "bfd1e5b79601efcbfb7283fc7a79bad6964607e373942856c2521b0218aab6e9"
                    .to_string(),
            },
            PinnedSector {
                host_key:
                    "ed25519:f54367610e7917b51e9a731bba11f68a4570415e3518901d6e89c6912e1b2278"
                        .to_string(),
                root: "cfd1e5b79601efcbfb7283fc7a79bad6964607e373942856c2521b0218aab6e9"
                    .to_string(),
            },
        ],
    };
    let slab_id = sdk
        .pin_slab(slab_pin_params)
        .await
        .expect("failed to pin slab");
    info!("Pinned slab: {}", slab_id.clone());

    let slab = sdk
        .slab(slab_id.clone())
        .await
        .expect("failed to get slab");
    if slab.id != slab_id.clone() {
        panic!("slab id mismatch");
    }

    sdk.unpin_slab(slab_id.clone())
        .await
        .expect("failed to unpin slab");
    info!("Unpinned slab: {}", slab_id);

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
    info!("done");
}
