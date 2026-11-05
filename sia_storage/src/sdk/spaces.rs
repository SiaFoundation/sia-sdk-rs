//! The `Sdk` shared space methods. A descendant of the `sdk` module so they
//! can reach [`Sdk`]'s private fields.

use sia_core::signing::PublicKey;

use crate::spaces::{AddSpaceRequest, SpaceError, SpaceKey};
use crate::{Sdk, Space, SpaceOptions};

impl Sdk {
    /// Creates a shared space owned by the account, with the account as its
    /// only member.
    pub async fn create_space(&self, options: SpaceOptions) -> Result<Space, SpaceError> {
        let key = SpaceKey::from_seed(rand::random());
        let req = AddSpaceRequest::new(&self.app_key, &key, &options.name, &options.metadata);
        self.api_client.add_space(&self.app_key, &req).await?;
        self.space(&key.public_key()).await
    }

    /// Lists the spaces the account owns or has joined, newest first. Omit
    /// `offset` or `limit` to use the indexer's default paging.
    pub async fn spaces(
        &self,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<Space>, SpaceError> {
        self.api_client
            .spaces(&self.app_key, offset, limit)
            .await?
            .into_iter()
            .map(|record| record.open(&self.app_key))
            .collect()
    }

    /// Fetches the indexer's current record of the space identified by `key`.
    async fn space(&self, key: &PublicKey) -> Result<Space, SpaceError> {
        let record = self.api_client.space(&self.app_key, key).await?;
        if record.key != *key {
            return Err(SpaceError::KeyMismatch);
        }
        record.open(&self.app_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockNetwork;
    use crate::sdk::test::random_seed;
    use crate::{AppKey, SpacePermission};

    #[sia_core_derive::cross_target_test]
    async fn test_create_and_list_spaces() {
        let network = MockNetwork::new();
        let sdk = network
            .sdk(AppKey::import(random_seed()))
            .await
            .expect("sdk creation failed");
        let other = network
            .sdk(AppKey::import(random_seed()))
            .await
            .expect("second sdk creation failed");

        let space = sdk
            .create_space(SpaceOptions {
                name: "photos".to_string(),
                metadata: br#"{"color":"blue"}"#.to_vec(),
            })
            .await
            .expect("create failed");
        assert_eq!(space.name, "photos");
        assert_eq!(space.metadata, br#"{"color":"blue"}"#);
        assert_eq!(space.owner, sdk.app_key().public_key());
        assert_eq!(space.permission, SpacePermission::Owner);
        assert_eq!(space.object_count, 0);

        let second = sdk
            .create_space(SpaceOptions::default())
            .await
            .expect("second create failed");
        assert_eq!(second.name, "");
        assert!(second.metadata.is_empty());

        // listing returns the same key the owner stored, not just its public half
        let listed = sdk.spaces(None, None).await.expect("list failed");
        assert_eq!(listed.len(), 2);
        let found = listed
            .iter()
            .find(|s| s.key.public_key() == space.key.public_key())
            .expect("created space not listed");
        assert_eq!(found.key.0.as_ref(), space.key.0.as_ref());
        assert_eq!(found.name, "photos");
        assert!(
            listed
                .iter()
                .any(|s| s.key.public_key() == second.key.public_key())
        );
        assert_eq!(
            sdk.spaces(None, Some(1)).await.expect("list failed").len(),
            1
        );
        assert_eq!(
            sdk.spaces(Some(1), None).await.expect("list failed").len(),
            1
        );

        // a space is listed only for its members
        assert!(
            other
                .spaces(None, None)
                .await
                .expect("list failed")
                .is_empty()
        );
    }
}
