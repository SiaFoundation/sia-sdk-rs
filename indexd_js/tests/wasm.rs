use indexd_sdk::*;
use sia::rhp::HostSettings;
use wasm_bindgen_test::*;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_get_host_settings() {
    let val =
        get_host_settings("6r4b0vj1ai55fobdvauvpg3to5bpeijl045b2q268fcj7q1vkuog.sia.host:9984")
            .await
            .expect("Failed to get host settings");

    let settings: HostSettings =
        serde_wasm_bindgen::from_value(val).expect("Failed to deserialize settings");
    assert_eq!(settings.accepting_contracts, true);
}
