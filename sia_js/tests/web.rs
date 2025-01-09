//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use hex;
use sia_js::Seed;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn test_seed_derive_key() {
    const PHRASE: &str =
        "wealth salon venue abstract blossom hollow south over accuse bunker guide saddle";

    let test_cases = vec![
        (0, hex::decode("e313a1aa2dbe411b5335ced5592e87cb002f47a874e27e9cb90eab285c675e366d29b52b7b312fb5e4f657afd0105d3d6dcc5c326131a033597501d25612789f").unwrap()),
        (1, hex::decode("0a909bf1d36c876cb776b81e19c8b4a1351c644e329db3be07f6dfce59b75f4d3fa53cfea6763b07cc4202a0ba36574d99fa6ca3f807dbff2f2266c4d0a0a76d").unwrap()),
        (2, hex::decode("866b40a6ee117ab8e65ee0772ca4e463e98edbf0793beae08a784745e7f10554294324450371bb263bc02c4536a04afa355ca490ef6481fd682dfd44bdb0f464").unwrap()),
        (3, hex::decode("f713e2a9cc2415d7069d136c73dd3a67c5f2a63cc04f1106b980d6d6cd816f6bf710d69b256ae23f4b28d1f02f714fed04ea2c9268598835713eec36697bf179").unwrap()),
        (4, hex::decode("433b5bf2c3ec44895af7299148ba38deaa7324c5146821fcef407708abc211bcb12b2a480977ffdc4c3801752b0e2bee06219311b7bdce80189be961f47d7ac9").unwrap()),
        (5, hex::decode("48a4765ece4d7e6b12f4f8b20caaca4b2249654ada2b9d0d31d855517244b1ed8850f06b52e7ce6b5ea061ac6b69f3febb3fc96e58c590c975300fb20f317dcc").unwrap()),
        (6, hex::decode("2de36d94f299ab39511e9eb3fe0cf5cc989b25e2943ca9c3a87ac592831791d76b0ee63d4be3b5296fe3961150b6bc3dd5f0acc56235fb8a62143a7eb73bdaa7").unwrap()),
        (7, hex::decode("ecbd64189b9429583ad62173035cf3680238e5d90727220f55d466e88dc631b70299cbd2b777df0e62099f3f5f913692d022a3faabd461a2933754ec3aa35c21").unwrap()),
        (8, hex::decode("5e836458fccb204dfe0e300c66ca2c47ad7efe9f835cda99d1a3cf22cf642634d53903b6ba22cf84adcae25f3d27d90323017ff793115b559df26fc0a4450cf4").unwrap()),
        (9, hex::decode("9abd3e40d6d3b10d36966cec65861d7f08c6aa7f2d2845b0e9f10e15cc9e9f28eb63b79a7719c1a8323fe2d3da06d121ccbda1342d9f0913860f5e0817af1390").unwrap()),
        (4294967295, hex::decode("71945cbc310c189f01fe8727a0060c007528aa0fd4812e4c5c7aa8b0e518906fc7dcf5e7623152e310ed440b8abf02e02fbead45553f13b3e8a7bea78a16d1b8").unwrap()),
    ];
    let seed = Seed::new(PHRASE.to_string()).expect("valid seed phrase");
    for (i, expected) in test_cases {
        let expected_pk = format!("ed25519:{}", hex::encode(expected[32..].as_ref()));

        let sk = seed.private_key(i);
        let pk = sk.public_key();

        assert_eq!(pk, expected_pk, "public key");
    }
}
