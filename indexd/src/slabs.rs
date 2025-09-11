use serde::{Deserialize, Serialize};

use serde_with::base64::Base64;
use serde_with::serde_as;
use sia::encoding::{SiaEncodable, SiaEncode};
use sia::encryption::EncryptionKey;
use sia::signing::PublicKey;
use sia::types::Hash256;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
/// A Sector is a unit of data stored on the Sia network. It can be referenced by its Merkle root.
pub struct Sector {
    pub root: Hash256,
    pub host_key: PublicKey,
}

/// A Slab is an erasure-coded collection of sectors. The sectors can be downloaded and
/// used to recover the original data.
#[derive(Debug, Clone, PartialEq)]
pub struct Slab {
    pub encryption_key: EncryptionKey,
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
    pub offset: usize,
    pub length: usize,
}

impl Slab {
    /// creates a unique identifier for the resulting slab to be referenced by hashing
    /// its contents, excluding the host key, length, and offset.
    pub fn digest(&self) -> Hash256 {
        let mut state = blake2b_simd::Params::new().hash_length(32).to_state();

        (self.min_shards as u64).encode(&mut state).unwrap();
        self.encryption_key.encode(&mut state).unwrap();
        self.sectors.iter().for_each(|sector| {
            sector.root.encode(&mut state).unwrap();
        });
        state.finalize().into()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, SiaEncode)]
#[serde(rename_all = "camelCase")]
pub struct SlabSlice {
    #[serde(rename = "slabID")]
    pub slab_id: Hash256,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PinnedSlab {
    pub id: Hash256,
    pub encryption_key: EncryptionKey,
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Object {
    pub key: Hash256,
    pub slabs: Vec<SlabSlice>,

    // base64-encoded arbitrary metadata
    #[serde_as(as = "Base64")]
    pub meta: Vec<u8>,

    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,

    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

impl Object {
    pub fn new(slabs: Vec<SlabSlice>, meta: Option<Vec<u8>>) -> Self {
        Self {
            key: Self::object_key_from_slabs(&slabs),
            slabs,
            meta: meta.unwrap_or_default(),

            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    /// creates a unique identifier for the object by hashing the list of slabs
    /// its made up of.
    fn object_key_from_slabs(slabs: &[SlabSlice]) -> Hash256 {
        let mut state = blake2b_simd::Params::new().hash_length(32).to_state();
        for slab in slabs {
            slab.encode(&mut state)
                .expect("encoding slabs shouldn't fail");
        }
        state.finalize().into()
    }

    /// validate_object checks that the integrity of the object is intact.
    pub fn validate_object(&self) -> Result<(), &'static str> {
        if self.key != Self::object_key_from_slabs(&self.slabs) {
            return Err("object key does not match slabs");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedSlab {
    pub id: Hash256,
    pub encryption_key: EncryptionKey,
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedObject {
    pub key: String,
    pub slabs: Vec<SharedSlab>,
    pub meta: Option<Vec<u8>>,
}

impl SharedObject {
    pub fn size(&self) -> u64 {
        self.slabs
            .iter()
            .fold(0_u64, |v, s| v + s.length as u64)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sia::hash_256;

    /// tests Slab.digest against a reference digest
    #[test]
    fn test_slab_digest() {
        let s = Slab {
            min_shards: 1,
            encryption_key: [
                152, 138, 169, 77, 22, 195, 154, 192, 91, 139, 241, 61, 75, 225, 38, 124, 225, 31,
                187, 165, 80, 215, 75, 121, 115, 204, 235, 9, 90, 248, 68, 92,
            ]
            .into(),
            sectors: vec![
                Sector {
                    root: hash_256!(
                        "fb0a42cce246d6bb9716eb0e97579a1d0d5c2bb34d7234e9ae271d4fd8201b24"
                    ),
                    host_key: PublicKey::new(rand::random()), // host key is not included in the digest
                },
                Sector {
                    root: hash_256!(
                        "8125994daee38e1fbaf7a26c7935420ce055202f7175eae98d291ebe80f2b00e"
                    ),
                    host_key: PublicKey::new(rand::random()), // host key is not included in the digest
                },
                Sector {
                    root: hash_256!(
                        "54ee41b57b9439868b119b8fe1c6c602bd6b35e27d31400c5bb85912b60c9f0a"
                    ),
                    host_key: PublicKey::new(rand::random()), // host key is not included in the digest
                },
            ],
            // length and offset are not included in the digest
            length: 100,
            offset: 100,
        };

        assert_eq!(
            s.digest().to_string(),
            "d1aea84f8682d7ae17b6c1f14dc344eb70b9328ee913a76fc241559657b06284"
        )
    }

    #[test]
    fn test_object_validation() {
        let slabs = vec![
            SlabSlice {
                slab_id: hash_256!(
                    "d1aea84f8682d7ae17b6c1f14dc344eb70b9328ee913a76fc241559657b06284"
                ),
                offset: 0,
                length: 100,
            },
            SlabSlice {
                slab_id: hash_256!(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
                offset: 0,
                length: 100,
            },
        ];
        let meta = b"hello world".to_vec();

        let mut obj = Object::new(slabs.clone(), Some(meta));
        obj.validate_object().expect("object should be valid");
        assert_eq!(
            obj.key,
            hash_256!("369cbab41f56f89ddc5adb417a5b9600137c7533adf91ab203cba96bcbce5b89")
        );

        // without the metadata the key should be the same
        let obj2 = Object::new(slabs.clone(), None);
        obj2.validate_object().expect("object should be valid");
        assert_eq!(obj.key, obj2.key);

        // tamper with obj to break validation
        obj.slabs = vec![];
        assert!(obj.validate_object().is_err());
    }
}
