use indexd_ffi::SDK;
use log::info;

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let sdk = SDK::new("https://app.indexd.zeus.sia.dev".into(), [1u8; 32].to_vec())
        .expect("expected sdk init");

    if !sdk.connect().await.expect("sdk connected") {
        panic!("oops")
    }

    let writer = sdk.upload([1u8; 32].to_vec(), 1, 3).await.expect("writer");
    let data = vec![1u8; 1024];
    writer.write(data.as_ref()).await.expect("data written");
    let slabs = writer.finalize().await.expect("upload to complete");

    let reader = sdk.download(slabs.as_ref()).await.expect("reader init");

    let read_data = reader.read_chunk().await.expect("read chunk");

    assert_eq!(read_data, data);
    info!("done");
}
