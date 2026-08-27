//! Owner-side operations on a [`SharingKey`]. A descendant of the `sdk` module
//! so it can reach [`Sdk`]'s private fields.

use sia_core::types::Hash256;

use crate::sharing::{SharedObjectRequest, SharingError, SharingKey};
use crate::{Object, Sdk, app_client};

impl Sdk {
    /// Attaches an object the account owns to `key`, re-sealing its encryption
    /// keys under the sharing key so recipients can decrypt it.
    ///
    /// Attaching an object already attached to `key` replaces its re-sealed
    /// keys, so a failed call can be retried with the same object.
    pub async fn share_object(
        &self,
        key: &SharingKey,
        object: &Object,
    ) -> Result<(), SharingError> {
        let req = SharedObjectRequest::new(object, &key.0);
        self.api_client
            .add_shared_object(&self.app_key.0, &key.public_key(), &req)
            .await?;
        Ok(())
    }

    /// Lists and decrypts the objects attached to `key`.
    pub async fn shared_objects(
        &self,
        key: &SharingKey,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<Object>, SharingError> {
        let sealed = self
            .api_client
            .sharing_key_objects(&self.app_key.0, &key.public_key(), offset, limit)
            .await?;
        sealed
            .into_iter()
            .map(|s| s.open_with(&key.0).map_err(SharingError::from))
            .collect()
    }

    /// Detaches `object_id` from `key`.
    pub async fn unshare_object(
        &self,
        key: &SharingKey,
        object_id: &Hash256,
    ) -> Result<(), SharingError> {
        self.api_client
            .delete_shared_object(&self.app_key.0, &key.public_key(), object_id)
            .await
            .map_err(|e| match e {
                app_client::Error::NotFound(_) => SharingError::ObjectNotAttached,
                e => SharingError::Api(e),
            })
    }

    /// Deletes `key` along with all of its object attachments, revoking
    /// recipients' access to the indexer.
    ///
    /// Account tokens already issued stay valid until they expire, so a download
    /// already in flight can keep reading from hosts for up to five more
    /// minutes.
    pub async fn revoke_sharing_key(&self, key: &SharingKey) -> Result<(), SharingError> {
        self.api_client
            .delete_sharing_key(&self.app_key.0, &key.public_key())
            .await?;
        Ok(())
    }
}
