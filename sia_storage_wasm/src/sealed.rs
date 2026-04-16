use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(transparent)]
pub struct SealedObject(pub sia_storage::SealedObject);

// Override tsify's broken `export type SealedObject = SealedObject;`
// with the actual interface shape.
#[wasm_bindgen(typescript_custom_section)]
const _: &str = r#"
export interface SealedObject {
    encryptedDataKey: string;
    slabs: Slab[];
    dataSignature: string;
    encryptedMetadataKey?: string;
    encryptedMetadata?: string;
    metadataSignature: string;
    createdAt: string;
    updatedAt: string;
}
"#;
