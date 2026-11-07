//! A member's access to one shared space.

#[cfg(feature = "fs")]
use std::path::Path;
use std::sync::Arc;

use sia_core::types::Hash256;
use tokio::io::AsyncRead;

use crate::app_client::{self, PinTarget};
use crate::hosts::Hosts;
use crate::sdk::pin_sealed_object;
use crate::spaces::{SpaceError, SpaceKey, UpdateSpaceRequest};
use crate::task::AbortOnDropHandle;
use crate::upload::{PackedUpload, upload_object};
use crate::{
    AppKey, Download, DownloadError, DownloadOptions, Error, Object, ObjectEvent,
    ObjectEventSummary, ObjectsCursor, PackedUploadOptions, Space, SpaceOptions, UploadError,
    UploadOptions,
};

/// A shared space opened by one of its members. It reads and writes the
/// space's objects, renames the space, and deletes it, each as far as the
/// member's [`SpacePermission`](crate::SpacePermission) allows.
///
/// Obtain one with [`Sdk::shared_space`](crate::Sdk::shared_space).
#[derive(Clone)]
pub struct SharedSpace {
    key: SpaceKey,
    app_key: Arc<AppKey>,
    api_client: app_client::Client,
    hosts: Hosts,
    _refresh_task: Arc<AbortOnDropHandle<()>>,
}

impl SharedSpace {
    pub(crate) fn new(
        key: SpaceKey,
        app_key: Arc<AppKey>,
        api_client: app_client::Client,
        hosts: Hosts,
        refresh_task: Arc<AbortOnDropHandle<()>>,
    ) -> Self {
        Self {
            key,
            app_key,
            api_client,
            hosts,
            _refresh_task: refresh_task,
        }
    }

    fn target(&self) -> PinTarget {
        PinTarget::Space(self.key.public_key())
    }

    /// The key that identifies and opens the space.
    pub fn key(&self) -> &SpaceKey {
        &self.key
    }

    /// Fetches the space's current name, metadata, figures, and this member's
    /// permission.
    pub async fn space(&self) -> Result<Space, SpaceError> {
        let key = self.key.public_key();
        self.api_client
            .space(&self.app_key, &key)
            .await?
            .open(&self.app_key, &key)
    }

    /// Replaces the space's name and metadata. Requires admin permission.
    pub async fn update(&self, options: SpaceOptions) -> Result<(), SpaceError> {
        let owner = self.space().await?.owner;
        let req = UpdateSpaceRequest::new(&self.key, &owner, &options.name, &options.metadata);
        self.api_client
            .update_space(&self.app_key, &self.key.public_key(), &req)
            .await?;
        Ok(())
    }

    /// Deletes the space and everything in it. Only the owner may
    /// delete a space.
    pub async fn delete(&self) -> Result<(), SpaceError> {
        self.api_client
            .delete_space(&self.app_key, &self.key.public_key())
            .await?;
        Ok(())
    }

    /// Reads until EOF and uploads all slabs into the space. Behaves like
    /// [`Sdk::upload`](crate::Sdk::upload), with the slabs pinned to the
    /// space as they are uploaded. The caller must pin the object with
    /// [`SharedSpace::pin_object`] afterwards. Requires write permission.
    pub async fn upload<R: AsyncRead + Unpin + 'static>(
        &self,
        object: Object,
        reader: R,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        upload_object(
            self.hosts.clone(),
            self.api_client.clone(),
            self.app_key.clone(),
            self.target(),
            object,
            reader,
            options,
        )
        .await
    }

    /// Uploads the file at `path` into the space. Behaves like
    /// [`upload`](Self::upload) otherwise.
    #[cfg(feature = "fs")]
    pub async fn upload_path<P: AsRef<Path>>(
        &self,
        object: Object,
        path: P,
        options: UploadOptions,
    ) -> Result<Object, UploadError> {
        let file = tokio::fs::File::open(path).await?;
        self.upload(object, file, options).await
    }

    /// Creates a packed upload into the space. Behaves like
    /// [`Sdk::upload_packed`](crate::Sdk::upload_packed), with the slabs
    /// pinned to the space.
    pub fn upload_packed(&self, options: PackedUploadOptions) -> Result<PackedUpload, UploadError> {
        PackedUpload::new(
            self.hosts.clone(),
            self.api_client.clone(),
            self.app_key.clone(),
            self.target(),
            options,
        )
    }

    /// Returns a [`Download`] handle that streams an object's data, paid for
    /// by this member's account. Behaves like
    /// [`Sdk::download`](crate::Sdk::download).
    pub fn download(
        &self,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<Download, DownloadError> {
        Download::new(object, self.hosts.clone(), self.app_key.clone(), options)
    }

    /// Pins an object to the space, pinning any of its slabs that are not
    /// already pinned. Requires write permission.
    pub async fn pin_object(&self, object: &Object) -> Result<(), Error> {
        let sealed = object.seal_with(&self.key.0);
        pin_sealed_object(&self.api_client, &self.app_key, self.target(), &sealed).await
    }

    /// Retrieves an object from the space by its id.
    pub async fn object(&self, id: &Hash256) -> Result<Object, Error> {
        let sealed = self
            .api_client
            .space_object(&self.app_key, &self.key.public_key(), id)
            .await?;
        let actual = sealed.id();
        if actual != *id {
            return Err(Error::App(format!(
                "indexer returned object {actual} but {id} was requested"
            )));
        }
        Ok(sealed.open_with(&self.key.0)?)
    }

    /// Retrieves a list of the space's object events. This can be used to
    /// synchronize local state with the indexer. Use
    /// [`SharedSpace::object_event_summaries`] to leave out the objects' slabs.
    pub async fn object_events(
        &self,
        cursor: Option<ObjectsCursor>,
        limit: Option<usize>,
    ) -> Result<Vec<ObjectEvent>, Error> {
        let events = self
            .api_client
            .space_objects(&self.app_key, &self.key.public_key(), cursor, limit)
            .await?;
        events
            .into_iter()
            .map(|event| {
                Ok(ObjectEvent {
                    id: event.id,
                    deleted: event.deleted,
                    updated_at: event.updated_at,
                    object: event
                        .object
                        .map(|sealed| sealed.open_with(&self.key.0))
                        .transpose()?,
                })
            })
            .collect()
    }

    /// Retrieves a list of the space's object events without the objects'
    /// slabs, which makes the response a small fraction of the size of
    /// [`SharedSpace::object_events`]. Fetch the full object with
    /// [`SharedSpace::object`] to download it.
    pub async fn object_event_summaries(
        &self,
        cursor: Option<ObjectsCursor>,
        limit: Option<usize>,
    ) -> Result<Vec<ObjectEventSummary>, Error> {
        let events = self
            .api_client
            .space_object_summaries(&self.app_key, &self.key.public_key(), cursor, limit)
            .await?;
        events
            .into_iter()
            .map(|event| {
                Ok(ObjectEventSummary {
                    id: event.id,
                    deleted: event.deleted,
                    updated_at: event.updated_at,
                    object: event
                        .object
                        .map(|sealed| sealed.open_with(&self.key.0, &event.id))
                        .transpose()?,
                })
            })
            .collect()
    }

    /// Deletes an object from the space. Requires delete permission.
    pub async fn delete_object(&self, id: &Hash256) -> Result<(), Error> {
        self.api_client
            .delete_space_object(&self.app_key, &self.key.public_key(), id)
            .await
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockNetwork;
    use crate::slabs::SlabVersion::V0;
    use crate::{AppApiError, Sector, Slab, SpacePermission};
    use reqwest::StatusCode;
    use sia_core::signing::PublicKey;
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;

    /// An object whose slab is pinned nowhere, so pinning it to a space has
    /// to pin the slab first.
    fn unpinned_object() -> Object {
        Object {
            data_key: [9u8; 32].into(),
            slabs: vec![Slab {
                version: V0,
                encryption_key: [1u8; 32].into(),
                min_shards: 1,
                sectors: vec![Sector {
                    root: Hash256::new([2u8; 32]),
                    host_key: PublicKey::new([3u8; 32]),
                }],
                offset: 0,
                length: 256,
            }],
            metadata: b"notes.txt".to_vec(),
            ..Default::default()
        }
    }

    /// Whether an error is the indexer refusing for lack of permission.
    fn is_forbidden(err: &SpaceError) -> bool {
        matches!(
            err,
            SpaceError::Api(AppApiError::Api(StatusCode::FORBIDDEN, _))
        )
    }

    #[sia_core_derive::cross_target_test]
    async fn test_shared_space_objects() {
        let network = MockNetwork::new();
        let sdk = network
            .sdk(AppKey::import(rand::random()))
            .await
            .expect("sdk creation failed");
        let created = sdk
            .create_space(SpaceOptions {
                name: "photos".to_string(),
                ..Default::default()
            })
            .await
            .expect("create failed");
        let space = sdk.shared_space(created.key.clone());
        assert_eq!(space.key().public_key(), created.key.public_key());

        let object = unpinned_object();
        space.pin_object(&object).await.expect("pin failed");

        let fetched = space.object(&object.id()).await.expect("fetch failed");
        assert_eq!(fetched, object);
        assert!(space.object(&Hash256::new([7u8; 32])).await.is_err());

        let events = space.object_events(None, None).await.expect("list failed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].object, Some(object.clone()));

        let summaries = space
            .object_event_summaries(None, None)
            .await
            .expect("summary list failed");
        assert_eq!(summaries.len(), 1);
        let summary = summaries[0].object.as_ref().expect("summary missing");
        assert_eq!(summary.id, object.id());
        assert_eq!(summary.metadata, object.metadata);
        assert_eq!(summary.size, object.size());

        let record = space.space().await.expect("space failed");
        assert_eq!(record.object_count, 1);
        assert_eq!(record.permission, SpacePermission::Owner);

        space
            .delete_object(&object.id())
            .await
            .expect("delete failed");
        let events = space.object_events(None, None).await.expect("list failed");
        assert_eq!(events.len(), 1);
        assert!(events[0].deleted && events[0].object.is_none());
    }

    #[sia_core_derive::cross_target_test]
    async fn test_shared_space_update_and_delete() {
        let network = MockNetwork::new();
        let owner = network
            .sdk(AppKey::import(rand::random()))
            .await
            .expect("sdk creation failed");
        let other = network
            .sdk(AppKey::import(rand::random()))
            .await
            .expect("second sdk creation failed");
        let created = owner
            .create_space(SpaceOptions {
                name: "photos".to_string(),
                ..Default::default()
            })
            .await
            .expect("create failed");
        let space = owner.shared_space(created.key.clone());
        let outsider = other.shared_space(created.key.clone());

        // a non-member can neither read nor change the space
        assert!(is_forbidden(&outsider.space().await.unwrap_err()));
        assert!(outsider.object_events(None, None).await.is_err());
        let rename = SpaceOptions {
            name: "team".to_string(),
            metadata: b"{}".to_vec(),
        };
        assert!(is_forbidden(
            &outsider.update(rename.clone()).await.unwrap_err()
        ));
        assert!(is_forbidden(&outsider.delete().await.unwrap_err()));

        space.update(rename).await.expect("update failed");
        let record = space.space().await.expect("space failed");
        assert_eq!(record.name, "team");
        assert_eq!(record.metadata, b"{}");
        assert_eq!(
            owner.spaces(None, None).await.expect("list failed")[0].name,
            "team"
        );

        space.delete().await.expect("delete failed");
        assert!(
            owner
                .spaces(None, None)
                .await
                .expect("list failed")
                .is_empty()
        );
        assert!(space.space().await.is_err());
    }

    #[sia_core_derive::cross_target_test]
    async fn test_shared_space_upload_download() {
        let network = MockNetwork::new();
        network.add_hosts(40);
        let sdk = network
            .sdk(AppKey::import(rand::random()))
            .await
            .expect("sdk creation failed");
        let created = sdk
            .create_space(SpaceOptions::default())
            .await
            .expect("create failed");
        let space = sdk.shared_space(created.key.clone());

        let data: Vec<u8> = (0..(1 << 20)).map(|i| i as u8).collect();
        let object = space
            .upload(
                Object::new(Some(b"metadata".to_vec())),
                Cursor::new(data.clone()),
                UploadOptions::default(),
            )
            .await
            .expect("upload failed");
        let mut packed = space
            .upload_packed(PackedUploadOptions::default())
            .expect("packed upload failed");
        packed
            .add(Cursor::new(data.clone()))
            .await
            .expect("add failed");
        let packed = packed.finalize().await.expect("finalize failed");
        assert_eq!(packed.len(), 1);

        // the slabs were pinned to the space, not the account, so the objects
        // pin without the slab fallback
        assert_eq!(network.pinned_slabs(), 0);
        space.pin_object(&object).await.expect("pin failed");
        space.pin_object(&packed[0]).await.expect("pin failed");
        assert_eq!(network.pinned_slabs(), 0);
        assert_eq!(space.space().await.expect("space failed").object_count, 2);

        for object in [&object, &packed[0]] {
            let fetched = space.object(&object.id()).await.expect("fetch failed");
            let mut reader = space
                .download(&fetched, DownloadOptions::default())
                .expect("download failed");
            let mut downloaded = Vec::new();
            reader
                .read_to_end(&mut downloaded)
                .await
                .expect("read failed");
            assert_eq!(downloaded, data);
        }
    }
}
