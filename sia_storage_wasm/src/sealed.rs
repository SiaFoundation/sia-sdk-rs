use wasm_bindgen::prelude::*;

// The shape is given here rather than derived, because tsify resolves a
// transparent newtype to its inner type's name and emits the self referential
// `export type SealedObject = SealedObject;`.
#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct SealedObject(
    #[tsify(type = "{
    encryptedDataKey: string;
    slabs: Slab[];
    dataSignature: string;
    encryptedMetadataKey?: string;
    encryptedMetadata?: string;
    metadataSignature: string;
    createdAt: string;
    updatedAt: string;
}")]
    pub sia_storage::SealedObject,
);
