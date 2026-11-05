//! A member's access to one shared space.

use std::sync::Arc;

use sia_core::types::Hash256;

use crate::app_client::{self, PinTarget};
use crate::sdk::pin_sealed_object;
use crate::spaces::{SpaceError, SpaceKey, UpdateSpaceRequest};
use crate::{
    AppKey, Error, Object, ObjectEvent, ObjectEventSummary, ObjectsCursor, Space, SpaceOptions,
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
}

impl SharedSpace {
    pub(crate) fn new(key: SpaceKey, app_key: Arc<AppKey>, api_client: app_client::Client) -> Self {
        Self {
            key,
            app_key,
            api_client,
        }
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

    /// Pins an object to the space, pinning any of its slabs that are not
    /// already pinned. Requires write permission.
    pub async fn pin_object(&self, object: &Object) -> Result<(), Error> {
        let sealed = object.seal_with(&self.key.0);
        pin_sealed_object(
            &self.api_client,
            &self.app_key,
            PinTarget::Space(self.key.public_key()),
            &sealed,
        )
        .await
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
    ///
    /// # Arguments
    /// * `cursor` - An optional cursor to continue from a previous call.
    /// * `limit` - An optional limit on the number of events to retrieve.
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
    ///
    /// # Arguments
    /// * `cursor` - An optional cursor to continue from a previous call.
    /// * `limit` - An optional limit on the number of events to retrieve.
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
}
