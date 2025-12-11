use chrono::{DateTime, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use serde_with::base64::Base64;
use serde_with::{DefaultOnNull, serde_as};
use sia::blake2::{Blake2b256, Digest};
use sia::encoding::{self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use sia::encryption::{CipherReader, CipherWriter, EncryptionKey};
use sia::signing::{PrivateKey, PublicKey, Signature};
use sia::types::Hash256;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::object_encryption::{
    DecryptError, open_data_key, open_metadata, open_metadata_key, seal_data_key, seal_metadata,
    seal_metadata_key,
};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
/// A Sector is a unit of data stored on the Sia network. It can be referenced by its Merkle root.
pub struct Sector {
    pub root: Hash256,
    pub host_key: PublicKey,
}

/// A Slab is an erasure-coded collection of sectors. The sectors can be downloaded and
/// used to recover the original data.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Slab {
    pub encryption_key: EncryptionKey,
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
    pub offset: u32,
    pub length: u32,
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

impl SiaEncodable for Slab {
    fn encode<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.encryption_key.encode(w)?;
        self.min_shards.encode(w)?;
        self.sectors.encode(w)?;
        let combined: u64 = (self.offset as u64) << 32 | (self.length as u64);
        combined.encode(w)?;
        Ok(())
    }
}

impl SiaDecodable for Slab {
    fn decode<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        let encryption_key = EncryptionKey::decode(r)?;
        let min_shards = u8::decode(r)?;
        let sectors = Vec::<Sector>::decode(r)?;
        let combined = u64::decode(r)?;

        Ok(Self {
            encryption_key,
            min_shards,
            sectors,
            offset: (combined >> 32) as u32,
            length: combined as u32,
        })
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PinnedSlab {
    pub id: Hash256,
    pub encryption_key: EncryptionKey,
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
}

#[derive(Debug, Error)]
pub enum SealedObjectError {
    #[error("decryption error: {0}")]
    Decryption(#[from] DecryptError),
    #[error("sealed object ID does not match contents")]
    ContentsMismatch,
    #[error("encoding error: {0}")]
    Encoding(#[from] encoding::Error),
    #[error("invalid signature")]
    InvalidSignature,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SealedObject {
    #[serde_as(as = "Base64")]
    pub encrypted_data_key: Vec<u8>,
    pub slabs: Vec<Slab>,
    pub data_signature: Signature,

    #[serde(default)]
    #[serde_as(as = "DefaultOnNull<Base64>")]
    pub encrypted_metadata_key: Vec<u8>,
    #[serde(default)]
    #[serde_as(as = "DefaultOnNull<Base64>")]
    pub encrypted_metadata: Vec<u8>,
    pub metadata_signature: Signature,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SiaDecodable for SealedObject {
    fn decode<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        let encrypted_data_key = Vec::<u8>::decode(r)?;
        let slabs = Vec::<Slab>::decode(r)?;
        let data_signature = Signature::decode(r)?;
        let encrypted_metadata_key = Vec::<u8>::decode(r)?;
        let encrypted_metadata = Vec::<u8>::decode(r)?;
        let metadata_signature = Signature::decode(r)?;
        let created_at = DateTime::<Utc>::decode(r)?;
        let updated_at = DateTime::<Utc>::decode(r)?;

        Ok(Self {
            encrypted_data_key,
            slabs,
            data_signature,
            encrypted_metadata_key,
            encrypted_metadata,
            metadata_signature,
            created_at,
            updated_at,
        })
    }
}

impl SealedObject {
    fn data_sig_hash(object_id: &Hash256, encrypted_data_key: &[u8]) -> Hash256 {
        let mut state = Blake2b256::default();
        object_id.encode(&mut state).unwrap();
        state.update(encrypted_data_key);
        state.finalize().into()
    }

    fn meta_sig_hash(
        object_id: &Hash256,
        encrypted_meta_key: &[u8],
        encrypted_metadata: &[u8],
    ) -> Hash256 {
        let mut state = Blake2b256::default();
        object_id.encode(&mut state).unwrap();
        state.update(encrypted_meta_key);
        state.update(encrypted_metadata);
        state.finalize().into()
    }

    fn verify_signatures(
        &self,
        app_key: &PublicKey,
        object_id: &Hash256,
    ) -> Result<(), SealedObjectError> {
        let data_sig_hash = Self::data_sig_hash(object_id, &self.encrypted_data_key);
        let meta_sig_hash = Self::meta_sig_hash(
            object_id,
            &self.encrypted_metadata_key,
            &self.encrypted_metadata,
        );

        if !app_key.verify(data_sig_hash.as_ref(), &self.data_signature) {
            return Err(SealedObjectError::InvalidSignature);
        }

        if !app_key.verify(meta_sig_hash.as_ref(), &self.metadata_signature) {
            return Err(SealedObjectError::InvalidSignature);
        }

        Ok(())
    }

    pub fn id(&self) -> Hash256 {
        object_id(&self.slabs)
    }

    pub fn open(self, app_key: &PrivateKey) -> Result<Object, SealedObjectError> {
        // verify signatures first
        let object_id = self.id();
        self.verify_signatures(&app_key.public_key(), &object_id)?;

        // decrypt data key and metadata
        let data_key = open_data_key(app_key, &object_id, &self.encrypted_data_key)?;
        let metadata = if !self.encrypted_metadata.is_empty() {
            let metadata_key =
                open_metadata_key(app_key, &object_id, &self.encrypted_metadata_key)?;
            open_metadata(&metadata_key, &object_id, &self.encrypted_metadata)?
        } else {
            Vec::new()
        };

        Ok(Object {
            data_key,
            slabs: self.slabs,
            metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// An ObjectEvent represents an object and whether it was deleted or not.
#[serde_as]
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectEvent {
    pub key: Hash256,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
    pub object: Option<Object>,
}

// An Object represents a file stored on the Sia network, consisting of multiple slabs and
// associated metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct Object {
    data_key: EncryptionKey, // not public to avoid accidental exposure

    pub slabs: Vec<Slab>,
    pub metadata: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Object {
    /// Returns the total size of the object by summing the lengths of its slabs.
    pub fn size(&self) -> u64 {
        self.slabs.iter().fold(0_u64, |v, s| v + s.length as u64)
    }

    /// Returns a reader that encrypts data on-the-fly using the object's encryption key.
    pub fn reader<R: AsyncRead + Unpin>(&self, r: R, offset: usize) -> CipherReader<R> {
        CipherReader::new(r, self.data_key.clone(), offset)
    }

    /// Returns a writer that encrypts data on-the-fly using the object's encryption key.
    pub fn writer<W: AsyncWrite + Unpin>(&self, w: W, offset: usize) -> CipherWriter<W> {
        CipherWriter::new(w, self.data_key.clone(), offset)
    }

    /// Returns the object's encryption key.
    ///
    /// Be careful when using this function to avoid accidental exposure.
    pub(crate) fn data_key(&self) -> &EncryptionKey {
        &self.data_key
    }
}

impl Default for Object {
    fn default() -> Self {
        let mut data_key: [u8; 32] = [0; 32];
        OsRng.try_fill_bytes(&mut data_key).unwrap();
        let mut meta_key: [u8; 32] = [0; 32];
        OsRng.try_fill_bytes(&mut meta_key).unwrap();
        Object {
            data_key: EncryptionKey::from(data_key),
            slabs: Vec::new(),
            metadata: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl Object {
    pub fn id(&self) -> Hash256 {
        object_id(&self.slabs)
    }

    pub fn seal(&self, app_key: &PrivateKey) -> SealedObject {
        let object_id = self.id();

        // encypt data key and create data signature
        let encrypted_data_key = seal_data_key(app_key, &object_id, &self.data_key);
        let data_signature = {
            let sig_hash = SealedObject::data_sig_hash(&object_id, &encrypted_data_key);
            app_key.sign(sig_hash.as_ref())
        };

        // encrypt metadata key and metadata, if present, and create metadata signature
        let (encrypted_metadata_key, encrypted_metadata) = if !self.metadata.is_empty() {
            let metadata_key = EncryptionKey::from(rand::random::<[u8; 32]>());
            let encrypted_metadata_key = seal_metadata_key(app_key, &object_id, &metadata_key);
            let encrypted_metadata = seal_metadata(&metadata_key, &object_id, &self.metadata);
            (encrypted_metadata_key, encrypted_metadata)
        } else {
            (Vec::new(), Vec::new())
        };

        let metadata_signature = {
            let sig_hash = SealedObject::meta_sig_hash(
                &object_id,
                &encrypted_metadata_key,
                &encrypted_metadata,
            );
            app_key.sign(sig_hash.as_ref())
        };

        SealedObject {
            encrypted_data_key,
            encrypted_metadata_key,
            slabs: self.slabs.clone(),
            encrypted_metadata,
            data_signature,
            metadata_signature,

            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// A SharedObject is an object that can be shared with others. It contains the encryption key
/// needed to decrypt the data, as well as the slabs that make up the object.
///
/// It has no public fields to avoid corruption of the internal state.
#[derive(Debug, Clone, PartialEq)]
pub struct SharedObject {
    data_key: EncryptionKey,
    slabs: Vec<Slab>,
}

impl SharedObject {
    pub fn new(encryption_key: EncryptionKey, slabs: Vec<Slab>) -> Self {
        SharedObject {
            data_key: encryption_key,
            slabs,
        }
    }

    pub fn slabs(&self) -> &Vec<Slab> {
        &self.slabs
    }

    /// Computes the total size of the object by summing the lengths of its slabs.
    pub fn size(&self) -> u64 {
        self.slabs.iter().fold(0_u64, |v, s| v + s.length as u64)
    }

    /// Returns a writer that decrypts data on-the-fly using the object's encryption key.
    pub fn writer<W: AsyncWrite + Unpin>(&self, w: W, offset: usize) -> CipherWriter<W> {
        CipherWriter::new(w, self.data_key.clone(), offset)
    }

    /// Converts the SharedObject into an Object that can be saved to an indexer.
    /// The slabs must be pinned before the object can be saved.
    pub fn object(&self) -> Object {
        Object {
            data_key: self.data_key.clone(),
            slabs: self.slabs.clone(),
            metadata: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl From<SharedObject> for Object {
    fn from(val: SharedObject) -> Self {
        Object {
            data_key: val.data_key,
            slabs: val.slabs.clone(),
            metadata: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

pub(crate) fn object_id(slabs: &[Slab]) -> Hash256 {
    let mut state = Blake2b256::default();
    for slab in slabs.iter() {
        let slab_id = slab.digest();
        slab_id
            .encode(&mut state)
            .expect("hashing slab_id shouldn't fail");
        ((slab.offset as u64) << 32 | slab.length as u64)
            .encode(&mut state)
            .expect("hashing slab offset/length shouldn't fail");
    }
    state.finalize().into()
}

#[cfg(test)]
mod test {
    use super::*;
    use sia::hash_256;

    #[test]
    fn test_object_id() {
        let slabs = vec![Slab {
            encryption_key: [0u8; 32].into(),
            min_shards: 1,
            sectors: vec![Sector {
                root: Hash256::new([1u8; 32]),
                host_key: PublicKey::new([2u8; 32]),
            }],
            offset: 10,
            length: 100,
        }];

        let id = object_id(&slabs);
        assert_eq!(
            id.to_string(),
            "1b13d5dd22605af0573cae7fe9242c1ee83727c29798308b2b170864677b46d0"
        );
    }

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
    fn test_object_roundtrip() {
        let slabs = vec![
            Slab {
                encryption_key: rand::random::<[u8; 32]>().into(),
                min_shards: 2,
                sectors: vec![],
                offset: 0,
                length: 100,
            },
            Slab {
                encryption_key: rand::random::<[u8; 32]>().into(),
                min_shards: 2,
                sectors: vec![],
                offset: 0,
                length: 100,
            },
        ];
        let meta = b"hello, world!".to_vec();

        let mut obj = Object::default();
        obj.slabs = slabs.clone();
        obj.metadata = meta.clone();

        let seed: [u8; 32] = rand::random();
        let private_key = PrivateKey::from_seed(&seed);

        let sealed = obj.seal(&private_key);
        let opened = sealed.open(&private_key).expect("should open");

        assert_eq!(opened.slabs, slabs);
        assert_eq!(opened.metadata, meta);
    }

    /// tests that the SealedObject struct is compatible with the Go implementation
    /// by deserializing a reference object
    #[test]
    fn test_sealed_object_golden() {
        let mut seed = [0u8; 32];
        hex::decode_to_slice(
            "9593edfd90ef2da9973af3bca88afdf54b6e7ff66ff6c749505734b9cf6b8aec",
            &mut seed,
        )
        .expect("hex");
        let app_key = PrivateKey::from_seed(&seed);

        let mut expected_object_key = [0u8; 32];
        hex::decode_to_slice(
            "cd280dd064e3c2d4259579bf0deda2492962c130ee8d7d2e11f1daca3e5cc579",
            &mut expected_object_key,
        )
        .expect("hex");
        let expected_object_key = EncryptionKey::from(expected_object_key);

        let expected_metadata = hex::decode("b9d615255cc17596e3870c3adf5e11c1da0dd78e30f29c6b6d223949c7d91492db55cdc6e04ce65b5b1fea4ccc953e883d5bf23e9c893ecb5221e7315f16e7f95dfc70f0ed1ee1306e8733a22a5faf1b139f01f0f77ae00d71fe3bbefa4b65aca80f749e4788ace89beaa79ac651aedc54cba7066264df9db54c22c1e17cea1a").expect("hex");

        let sealed_data = hex::decode("48000000000000009ea15c148ee957bc6daf0df3ab475e33ee94e4ce9f82394c9673495d551c38d294a9333578e74d69fdc4e53ef7ed550515c24e779b9116820c8785676a53d067e778ad7c938d9c5d020000000000000029a43531bca66317343214d5089c92c31cb6b8049c7499a97133f1355caa9788000000000000000000881300000a0000000dc9764287f16caf8b0486ca817958a4e5ec92937459c60d333006f19d7e3a8d0000000000000000000010000020000000a8000000000000000987b2f8e137b456f7dad872d4debec79100d981e62c952e04b8178f375362d61757c3fd014db35feb0ca4e47c5269e09f6bf0d750baa317f9aacf10dc743b4e0a0eed0871aa247de3ff7589795d080c1711de4a9cc54ddf29cc8618cf0a529073243b7dfe0ae21f429e1f790fda1e21363b86845ca5dcd74019b752ef2ce9fd352d1de8a8e5e8d81e34c8a8cc9e4cdc6345cfc609ac75c5174ff6d338f5de5d41ae56364318f144d5b2e3a118074a298cd563ee7ea2f0ab3870413f56a72dd55de48df4d9450d4c40ffb958dc7b61346fcb73d791668712fd78da5221e8fea1930f3fbfe409650e00096e88f1ffffff00096e88f1ffffff").expect("hex");
        let sealed = SealedObject::decode(&mut &sealed_data[..]).expect("decode");
        let opened = sealed.open(&app_key).expect("open");

        assert_eq!(opened.data_key, expected_object_key);
        assert_eq!(opened.slabs.len(), 2);
        assert_eq!(opened.metadata, expected_metadata);
    }
}
