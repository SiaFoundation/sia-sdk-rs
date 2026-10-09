//! Encode/decode a whole object, data key included.
//!
//! This is not a storage format. It carries the key in the clear, so anything
//! persisted or sent anywhere should be sealed with `sia_object_seal_json`
//! instead.
use sia_core::encoding::{self, SiaDecodable, SiaEncodable};
use sia_storage::{DateTime, EncryptionKey, Object, Slab, Utc};

/// Encodes `obj` for [decode].
pub(crate) fn encode(obj: &Object) -> encoding::Result<Vec<u8>> {
    let key = obj.data_key();
    let slabs = obj.slabs();
    let len = key.encoded_length() + slabs.encoded_length() + obj.metadata.encoded_length() + 8 + 8; // + created_at as microseconds + updated_at as microseconds

    let mut w = Vec::with_capacity(len);
    key.encode(&mut w)?;
    slabs.encode(&mut w)?;
    obj.metadata.encode(&mut w)?;
    obj.created_at.timestamp_micros().encode(&mut w)?;
    obj.updated_at.timestamp_micros().encode(&mut w)?;
    Ok(w)
}

/// Rebuilds the object [encode] produced.
pub(crate) fn decode(mut r: &[u8]) -> encoding::Result<Object> {
    let data_key = EncryptionKey::decode(&mut r)?;
    let slabs = Vec::<Slab>::decode(&mut r)?;
    let metadata = Vec::<u8>::decode(&mut r)?;
    let micros = |us: i64| {
        DateTime::<Utc>::from_timestamp_micros(us)
            .ok_or_else(|| encoding::Error::InvalidValue(format!("invalid timestamp: {us}")))
    };
    let created_at = micros(i64::decode(&mut r)?)?;
    let updated_at = micros(i64::decode(&mut r)?)?;

    let mut obj = Object::less_safe_new(data_key, slabs, Some(metadata));
    obj.created_at = created_at;
    obj.updated_at = updated_at;
    Ok(obj)
}
