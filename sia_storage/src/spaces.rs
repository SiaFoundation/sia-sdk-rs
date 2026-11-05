//! Shared spaces, which several accounts read and write together.

use std::fmt;

use blake2b_simd::Params;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::{DefaultOnNull, serde_as};
use sia_core::encoding::SiaEncodable;
use sia_core::signing::{PrivateKey, PublicKey, Signature};
use sia_core::types::Hash256;

use crate::encryption::EncryptionKey;
use crate::object_encryption::{DecryptError, derive_encryption_key, open_metadata, seal_metadata};
use crate::slabs::{Base64OrBytes, SealedObject, SealedObjectSummary};
use crate::{AppKey, app_client};

/// A shared space's key. It identifies the space to the indexer and decrypts
/// what is stored in it. Every member holds one, obtained from their
/// [`Space`].
#[derive(Clone)]
pub struct SpaceKey(pub(crate) PrivateKey);

impl SpaceKey {
    /// The key `app_key` wraps a space key under; indexd's `DeriveMemberKey`.
    fn member_key(app_key: &AppKey, space_key: &PublicKey) -> EncryptionKey {
        derive_encryption_key(app_key.0.as_ref(), space_key.as_ref(), b"memberKey")
    }

    /// Derives a key used to encrypt the space's name and metadata.
    fn cipher_key(&self) -> EncryptionKey {
        derive_encryption_key(
            self.0.as_ref(),
            self.public_key().as_ref(),
            b"spaceMetadata",
        )
    }

    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        SpaceKey(PrivateKey::from_seed(&seed))
    }

    /// Unwraps a key the indexer returned under `space_key` for the member
    /// holding `app_key`.
    pub(crate) fn import(
        app_key: &AppKey,
        space_key: &PublicKey,
        wrapped: &[u8],
    ) -> Result<Self, DecryptError> {
        let key = open_metadata(&Self::member_key(app_key, space_key), wrapped)?;
        let key: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| DecryptError::KeyLength)?;
        Ok(Self::from_seed(key))
    }

    /// Wraps the key for the member holding `app_key`, as the indexer stores
    /// it.
    pub(crate) fn export(&self, app_key: &AppKey) -> Vec<u8> {
        seal_metadata(
            &Self::member_key(app_key, &self.public_key()),
            &self.0.as_ref()[..32],
        )
    }

    /// The public key that identifies the space.
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }
}

impl fmt::Debug for SpaceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SpaceKey").field(&self.public_key()).finish()
    }
}

/// What a member may do in a space. Each level includes the ones before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpacePermission {
    /// List, fetch, and download objects.
    Read,
    /// Upload and pin objects.
    Write,
    /// Delete objects.
    Delete,
    /// Manage members and the space's name and metadata.
    Admin,
    /// Delete the space. Held by its creator and never granted to anyone else.
    Owner,
}

/// Options for creating a shared space.
#[derive(Clone, Default)]
pub struct SpaceOptions {
    /// The space's name, visible to its members.
    pub name: String,
    /// Application-defined metadata, visible to its members.
    pub metadata: Vec<u8>,
}

/// A shared space: a store one account owns and invites other accounts into,
/// so an application's users can read and write the same objects without
/// sharing app keys.
///
/// Members keep their own app keys. The space has its own [`SpaceKey`], which
/// every member receives and which decrypts everything in it. The indexer
/// never learns that key, so a space's name, metadata, and objects are
/// private to its members, and every object records which member wrote it.
/// Storage is charged to the owner; transfers to the member making them.
///
/// Members join at a [`SpacePermission`] level the owner can change or
/// revoke. A `Space` is one member's view of a space: its details, their
/// permission, and the key that opens it for uploads, downloads, listing,
/// and deletes.
#[derive(Debug, Clone)]
pub struct Space {
    /// The key that opens the space.
    pub key: SpaceKey,
    /// The app account that created the space and pays for its storage.
    pub owner: PublicKey,
    pub name: String,
    /// Application-defined metadata.
    pub metadata: Vec<u8>,
    /// What this member may do in the space.
    pub permission: SpacePermission,
    pub object_count: u64,
    /// The total size of the objects, in bytes.
    pub object_size: u64,
    /// Bytes stored before redundancy.
    pub pinned_data: u64,
    /// Bytes stored on the network, including redundancy.
    pub pinned_size: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Errors returned by the shared space operations.
#[derive(Debug, thiserror::Error)]
pub enum SpaceError {
    /// The indexer request failed.
    #[error("app error: {0}")]
    Api(#[from] app_client::Error),

    /// The space's name or metadata fail verification, so they are not what a
    /// member set.
    #[error("invalid space signature")]
    InvalidSignature,

    /// The indexer returned a space other than the one requested.
    #[error("indexer returned a mismatched space")]
    KeyMismatch,

    /// The space could not be decrypted with this app key.
    #[error("decryption error: {0}")]
    Decryption(#[from] DecryptError),

    /// The space's name is not valid UTF-8.
    #[error("space name is not valid UTF-8")]
    InvalidName,
}

/// The hash the space key signs over a space's identity, name, and metadata.
/// The indexer verifies it on create and update; members verify it on read.
pub(crate) fn space_sig_hash(
    key: &PublicKey,
    owner: &PublicKey,
    encrypted_name: &[u8],
    encrypted_metadata: &[u8],
) -> Hash256 {
    let mut state = Params::new().hash_length(32).to_state();
    // length-prefixed string and byte slices, raw fixed-size keys
    "indexd/space/v1".to_string().encode(&mut state).unwrap();
    key.encode(&mut state).unwrap();
    owner.encode(&mut state).unwrap();
    encrypted_name.encode(&mut state).unwrap();
    encrypted_metadata.encode(&mut state).unwrap();
    state.finalize().into()
}

/// The body of a request to create a space.
#[serde_as]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AddSpaceRequest {
    pub key: PublicKey,
    #[serde_as(as = "Base64")]
    pub encrypted_key: Vec<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "Base64")]
    pub encrypted_name: Vec<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "Base64")]
    pub encrypted_metadata: Vec<u8>,
    pub signature: Signature,
}

impl AddSpaceRequest {
    /// Builds the request that creates `space`, owned by the account holding
    /// `app_key`.
    pub(crate) fn new(app_key: &AppKey, space: &SpaceKey, name: &str, metadata: &[u8]) -> Self {
        let key = space.public_key();
        let owner = app_key.public_key();
        let encrypted_key = space.export(app_key);
        let cipher_key = space.cipher_key();
        let encrypted_name = if name.is_empty() {
            Vec::new()
        } else {
            seal_metadata(&cipher_key, name.as_bytes())
        };
        let encrypted_metadata = if metadata.is_empty() {
            Vec::new()
        } else {
            seal_metadata(&cipher_key, metadata)
        };
        let sig_hash = space_sig_hash(&key, &owner, &encrypted_name, &encrypted_metadata);
        Self {
            key,
            encrypted_key,
            encrypted_name,
            encrypted_metadata,
            signature: space.0.sign(sig_hash.as_ref()),
        }
    }
}

/// A space as the indexer returns it to a member.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SpaceResponse {
    pub key: PublicKey,
    pub owner: PublicKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "DefaultOnNull<Base64OrBytes>")]
    pub encrypted_name: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "DefaultOnNull<Base64OrBytes>")]
    pub encrypted_metadata: Vec<u8>,
    #[serde_as(as = "Base64OrBytes")]
    pub encrypted_key: Vec<u8>,
    pub permission: SpacePermission,
    pub signature: Signature,
    pub object_count: u64,
    pub object_size: u64,
    pub pinned_data: u64,
    pub pinned_size: u64,
    #[serde(with = "sia_core::types::null_as_zero_time")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "sia_core::types::null_as_zero_time")]
    pub updated_at: DateTime<Utc>,
}

impl SpaceResponse {
    /// Verifies and decrypts the space for the member holding `app_key`.
    pub(crate) fn open(self, app_key: &AppKey) -> Result<Space, SpaceError> {
        let sig_hash = space_sig_hash(
            &self.key,
            &self.owner,
            &self.encrypted_name,
            &self.encrypted_metadata,
        );
        if !self.key.verify(sig_hash.as_ref(), &self.signature) {
            return Err(SpaceError::InvalidSignature);
        }
        let key = SpaceKey::import(app_key, &self.key, &self.encrypted_key)?;
        if key.public_key() != self.key {
            return Err(SpaceError::KeyMismatch);
        }
        let cipher_key = key.cipher_key();
        let name = if self.encrypted_name.is_empty() {
            String::new()
        } else {
            String::from_utf8(open_metadata(&cipher_key, &self.encrypted_name)?)
                .map_err(|_| SpaceError::InvalidName)?
        };
        let metadata = if self.encrypted_metadata.is_empty() {
            Vec::new()
        } else {
            open_metadata(&cipher_key, &self.encrypted_metadata)?
        };
        Ok(Space {
            key,
            owner: self.owner,
            name,
            metadata,
            permission: self.permission,
            object_count: self.object_count,
            object_size: self.object_size,
            pinned_data: self.pinned_data,
            pinned_size: self.pinned_size,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A space object as the indexer returns it, with the member that wrote it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SealedSpaceObject {
    pub key: Hash256,
    pub account: PublicKey,
    #[serde(flatten)]
    pub object: SealedObject,
}

/// A space object listed without its slabs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SealedSpaceObjectSummary {
    pub key: Hash256,
    pub account: PublicKey,
    #[serde(flatten)]
    pub object: SealedObjectSummary,
}

/// A change to a space object: the current object, or a tombstone once it is
/// deleted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SealedSpaceObjectEvent {
    #[serde(rename = "key")]
    pub id: Hash256,
    pub deleted: bool,
    #[serde(with = "sia_core::types::null_as_zero_time")]
    pub updated_at: DateTime<Utc>,
    pub object: Option<SealedSpaceObject>,
}

/// A [`SealedSpaceObjectEvent`] listed without the object's slabs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SealedSpaceObjectEventSummary {
    #[serde(rename = "key")]
    pub id: Hash256,
    pub deleted: bool,
    #[serde(with = "sia_core::types::null_as_zero_time")]
    pub updated_at: DateTime<Utc>,
    pub object: Option<SealedSpaceObjectSummary>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the record the indexer would return for `req` to its owner.
    fn owner_response(app_key: &AppKey, req: &AddSpaceRequest) -> SpaceResponse {
        SpaceResponse {
            key: req.key,
            owner: app_key.public_key(),
            encrypted_name: req.encrypted_name.clone(),
            encrypted_metadata: req.encrypted_metadata.clone(),
            encrypted_key: req.encrypted_key.clone(),
            permission: SpacePermission::Owner,
            signature: req.signature.clone(),
            object_count: 0,
            object_size: 0,
            pinned_data: 0,
            pinned_size: 0,
            created_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            updated_at: DateTime::from_timestamp(1_700_000_100, 0).unwrap(),
        }
    }

    // The vector from indexd's `TestSpaceWrappingKeyVectors`: a 64-byte app
    // key and a space key whose bytes are 32..64.
    #[sia_core_derive::cross_target_test]
    fn test_derive_member_key_golden() {
        let app_key: [u8; 64] = hex::decode(
            "b3383d90bf82c4c9bfa445a9d6090977dc9333d302309bd002ba9407c42674b4581010a63b0682cc447cd970fdb8b7d634e1e6fec0631a310e53069c7e1b61d9",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let app_key = AppKey(PrivateKey::from(app_key));
        let space_key = PublicKey::new(std::array::from_fn(|i| i as u8 + 32));

        let member_key = SpaceKey::member_key(&app_key, &space_key);
        assert_eq!(
            hex::encode(member_key.as_ref()),
            "ca79c8a13a7a20b1abf272f670af2c829d2a310c363ad0c2d576b164786436b8",
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_wrap_roundtrip() {
        let app_key = AppKey::import([1u8; 32]);
        let space = SpaceKey::from_seed([2u8; 32]);

        let wrapped = space.export(&app_key);
        assert_eq!(wrapped.len(), 72, "indexd accepts exactly 72 bytes");
        let unwrapped =
            SpaceKey::import(&app_key, &space.public_key(), &wrapped).expect("should unwrap");
        assert_eq!(unwrapped.0.as_ref(), space.0.as_ref());

        // another account must not unwrap it
        assert!(matches!(
            SpaceKey::import(&AppKey::import([3u8; 32]), &space.public_key(), &wrapped),
            Err(DecryptError::Decryption)
        ));
    }

    #[sia_core_derive::cross_target_test]
    fn test_add_space_request_opens_as_space() {
        let app_key = AppKey::import([1u8; 32]);
        let space = SpaceKey::from_seed([2u8; 32]);
        let req = AddSpaceRequest::new(&app_key, &space, "photos", br#"{"color":"blue"}"#);
        assert_eq!(req.key, space.public_key());

        let opened = owner_response(&app_key, &req)
            .open(&app_key)
            .expect("should open");
        assert_eq!(opened.key.0.as_ref(), space.0.as_ref());
        assert_eq!(opened.owner, app_key.public_key());
        assert_eq!(opened.name, "photos");
        assert_eq!(opened.metadata, br#"{"color":"blue"}"#);
        assert_eq!(opened.permission, SpacePermission::Owner);

        // a name swapped by the indexer fails the signature check before
        // anything is decrypted
        let mut tampered = req.clone();
        tampered.encrypted_name =
            AddSpaceRequest::new(&app_key, &space, "videos", b"").encrypted_name;
        assert!(matches!(
            owner_response(&app_key, &tampered).open(&app_key),
            Err(SpaceError::InvalidSignature)
        ));

        // the signature does not cover the wrapped key, so some other key
        // wrapped for the member is caught by re-deriving the public key
        let mut swapped = req.clone();
        swapped.encrypted_key = seal_metadata(
            &SpaceKey::member_key(&app_key, &space.public_key()),
            &[9u8; 32],
        );
        assert!(matches!(
            owner_response(&app_key, &swapped).open(&app_key),
            Err(SpaceError::KeyMismatch)
        ));

        // only the member the key was wrapped for can unwrap it
        let other = AppKey::import([3u8; 32]);
        assert!(matches!(
            owner_response(&app_key, &req).open(&other),
            Err(SpaceError::Decryption(_))
        ));
    }

    #[sia_core_derive::cross_target_test]
    fn test_empty_name_and_metadata_are_omitted() {
        let app_key = AppKey::import([1u8; 32]);
        let space = SpaceKey::from_seed([2u8; 32]);
        let req = AddSpaceRequest::new(&app_key, &space, "", b"");
        assert!(req.encrypted_name.is_empty());
        assert!(req.encrypted_metadata.is_empty());

        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("encryptedName").is_none());
        assert!(json.get("encryptedMetadata").is_none());

        let opened = owner_response(&app_key, &req)
            .open(&app_key)
            .expect("should open");
        assert_eq!(opened.name, "");
        assert!(opened.metadata.is_empty());
    }

    #[sia_core_derive::cross_target_test]
    fn test_permission_wire_format_and_order() {
        use SpacePermission::*;

        for (permission, name) in [
            (Read, "read"),
            (Write, "write"),
            (Delete, "delete"),
            (Admin, "admin"),
            (Owner, "owner"),
        ] {
            let json = serde_json::to_string(&permission).unwrap();
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(
                serde_json::from_str::<SpacePermission>(&json).unwrap(),
                permission
            );
        }
        assert!(serde_json::from_str::<SpacePermission>("\"root\"").is_err());

        // each level includes the ones before it
        assert!(Read < Write && Write < Delete && Delete < Admin && Admin < Owner);
    }
}
