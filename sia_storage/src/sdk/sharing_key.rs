//! Operations on a [`SharingKey`]. A descendant of the `sdk` module so it can
//! reach [`Sdk`]'s private fields.

use sia_core::signing::PrivateKey;
use sia_core::types::Hash256;

use crate::sharing::{SharedObjectRequest, SharingKey, derive_sharing_seed};
use crate::{AppKey, Error, Object, Sdk};

/// Operations on a sharing key. Each takes the [`Sdk`] whose account owns the
/// key, since the app key is what re-derives the sharing key from its nonce and
/// authorizes the request.
///
/// The aggregate fields are a snapshot from when the key was fetched, so
/// re-read the key with [`Sdk::sharing_key`] after mutating it to see updated
/// totals.
impl SharingKey {
    /// Returns the seed a recipient needs to read the key's objects. It is the
    /// whole credential; pair it with the indexer's url in
    /// [`SharedSdk::connect`](crate::SharedSdk::connect).
    ///
    /// Errors if the record's nonce does not derive its
    /// [`public_key`](SharingKey::public_key).
    pub fn seed(&self, sdk: &Sdk) -> Result<[u8; 32], Error> {
        let seed = derive_sharing_seed(&sdk.app_key.0, &self.nonce);
        if PrivateKey::from_seed(&seed).public_key() != self.public_key {
            return Err(Error::App(
                "sharing key nonce does not derive its public key".into(),
            ));
        }
        Ok(seed)
    }

    /// Attaches objects the account owns to the key, re-sealing their
    /// encryption keys under the sharing key so recipients can decrypt them.
    ///
    /// Attaching an object that is already attached replaces its re-sealed
    /// keys, so a call that fails partway can be retried with the same objects.
    pub async fn add_objects(&self, sdk: &Sdk, objects: &[Object]) -> Result<(), Error> {
        let sharing_key = PrivateKey::from_seed(&self.seed(sdk)?);
        for object in objects {
            let req = SharedObjectRequest::new(object, &sharing_key);
            sdk.api_client
                .add_shared_object(&sdk.app_key.0, &self.public_key, &req)
                .await
                .map_err(|e| Error::App(format!("{e:?}")))?;
        }
        Ok(())
    }

    /// Lists and decrypts the objects attached to the key.
    pub async fn objects(&self, sdk: &Sdk, offset: u64, limit: u64) -> Result<Vec<Object>, Error> {
        let sharing_key = AppKey(PrivateKey::from_seed(&self.seed(sdk)?));
        let sealed = sdk
            .api_client
            .sharing_key_objects(&sdk.app_key.0, &self.public_key, offset, limit)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        sealed
            .into_iter()
            .map(|s| s.open(&sharing_key).map_err(Error::from))
            .collect()
    }

    /// Detaches objects from the key.
    ///
    /// Detaching an object that is not attached is an error, so a call that
    /// fails partway cannot simply be retried with the same keys. Re-read the
    /// attachments with [`Self::objects`] and retry with what remains.
    pub async fn delete_objects(&self, sdk: &Sdk, object_keys: &[Hash256]) -> Result<(), Error> {
        for object_key in object_keys {
            sdk.api_client
                .delete_shared_object(&sdk.app_key.0, &self.public_key, object_key)
                .await
                .map_err(|e| Error::App(format!("{e:?}")))?;
        }
        Ok(())
    }

    /// Deletes the key along with all of its object attachments, revoking
    /// recipients' access to the indexer.
    ///
    /// Account tokens already issued stay valid until they expire, so a download
    /// already in flight can keep reading from hosts for up to five more
    /// minutes.
    pub async fn delete(&self, sdk: &Sdk) -> Result<(), Error> {
        sdk.api_client
            .delete_sharing_key(&sdk.app_key.0, &self.public_key)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }
}
