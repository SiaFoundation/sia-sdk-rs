use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::URL_SAFE;
use base64::prelude::*;
use chrono::{DateTime, Utc};
use reqwest::Method;
use sia_core::rhp4::{AccountToken, SECTOR_SIZE};
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;

use super::{
    Error, KeyResponse, PinObjectError, RegisterAppResponse, SHARE_URL_SCHEME, SealedObjectEvent,
    SharedHost, SlabPinParams, Url, sign,
};
use crate::encryption::EncryptionKey;
use crate::hosts::Host;
use crate::sharing::{KeyRequest, SharedObjectRequest, SharingKey};
use crate::slabs::Slab;
use crate::time::Duration;
use crate::{
    Account, App, AppMetadata, HostQuery, KeyStats, Object, ObjectsCursor, PinnedSlab, SealedObject,
};

const MOCK_AUTHORITY: &str = "mock.indexd";

#[derive(Debug)]
struct StoredObject {
    /// `None` once the object has been deleted. The tombstone is retained so
    /// [`Client::objects`] reports the deletion, matching the indexer.
    sealed: Option<SealedObject>,
    updated_at: DateTime<Utc>,
}

/// A sharing key and the objects attached to it.
#[derive(Debug)]
struct StoredSharingKey {
    key: SharingKey,
    description: String,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    attached: HashMap<Hash256, SealedObject>,
}

#[derive(Debug, Default)]
struct State {
    hosts: Vec<Host>,
    objects: HashMap<Hash256, StoredObject>,
    slabs: HashMap<Hash256, PinnedSlab>,
    user_secret: Hash256,
    pin_slabs_calls: usize,
    pin_slabs_failures: usize,
    sharing_keys: HashMap<PublicKey, StoredSharingKey>,
}

/// An in-memory stand-in for the indexer API.
///
/// Only the behaviour the SDK depends on is modelled: objects are stored as the
/// [`SealedObject`] they were pinned with, so `seal`/`open` still round-trips,
/// and [`Client::hosts`] honours `offset`/`limit` so the SDK's paged host
/// refresh terminates. Other [`HostQuery`] filters are ignored.
#[derive(Clone, Default)]
pub(crate) struct Client {
    state: Arc<RwLock<State>>,
}

impl Client {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Appends to the host list returned by [`Client::hosts`].
    pub(crate) fn add_hosts(&self, hosts: Vec<Host>) {
        self.state.write().unwrap().hosts.extend(hosts);
    }

    /// Returns the number of slabs currently pinned.
    pub(crate) fn pinned_slabs(&self) -> usize {
        self.state.read().unwrap().slabs.len()
    }

    /// Makes the next `failures` calls to [`Client::pin_slabs`] fail with an
    /// [`Error::Api`] before they resume succeeding.
    pub(crate) fn set_pin_slabs_failures(&self, failures: usize) {
        self.state.write().unwrap().pin_slabs_failures = failures;
    }

    /// Returns the number of times [`Client::pin_slabs`] has been called,
    /// including the calls made to fail.
    pub(crate) fn pin_slabs_calls(&self) -> usize {
        self.state.read().unwrap().pin_slabs_calls
    }

    pub(crate) async fn check_app_authenticated(&self, _: &PrivateKey) -> Result<bool, Error> {
        Ok(true)
    }

    pub(crate) async fn request_app_connection(
        &self,
        _: &PrivateKey,
        _: &AppMetadata,
    ) -> Result<RegisterAppResponse, Error> {
        let base = format!("{SHARE_URL_SCHEME}://{MOCK_AUTHORITY}/auth/connect/mock");
        Ok(RegisterAppResponse {
            response_url: base.clone(),
            status_url: format!("{base}/status"),
            register_url: format!("{base}/register"),
            expiration: Utc::now() + Duration::from_secs(600),
        })
    }

    pub(crate) async fn request_app_connection_pre_authorized(
        &self,
        ephemeral_key: &PrivateKey,
        opts: &AppMetadata,
        _: &PrivateKey,
    ) -> Result<RegisterAppResponse, Error> {
        self.request_app_connection(ephemeral_key, opts).await
    }

    pub(crate) async fn check_request_status(
        &self,
        _: &PrivateKey,
        _: Url,
    ) -> Result<Option<Hash256>, Error> {
        Ok(Some(self.state.read().unwrap().user_secret))
    }

    pub(crate) async fn register_app(
        &self,
        _: &PrivateKey,
        _: &PrivateKey,
        _: Url,
    ) -> Result<(), Error> {
        Ok(())
    }

    pub(crate) async fn hosts(&self, _: &PrivateKey, query: HostQuery) -> Result<Vec<Host>, Error> {
        let state = self.state.read().unwrap();
        let offset = query.offset.unwrap_or(0) as usize;
        let limit = query.limit.map_or(usize::MAX, |l| l as usize);
        Ok(state
            .hosts
            .iter()
            .skip(offset)
            .take(limit)
            .map(|h| Host {
                public_key: h.public_key,
                addresses: h.addresses.clone(),
                country_code: h.country_code.clone(),
                latitude: h.latitude,
                longitude: h.longitude,
                good_for_upload: h.good_for_upload,
            })
            .collect())
    }

    pub(crate) async fn object(
        &self,
        _: &PrivateKey,
        key: &Hash256,
    ) -> Result<SealedObject, Error> {
        self.state
            .read()
            .unwrap()
            .objects
            .get(key)
            .and_then(|o| o.sealed.clone())
            .ok_or_else(|| Error::Api(format!("object {key} not found")))
    }

    pub(crate) async fn objects(
        &self,
        _: &PrivateKey,
        cursor: Option<ObjectsCursor>,
        limit: Option<usize>,
    ) -> Result<Vec<SealedObjectEvent>, Error> {
        let state = self.state.read().unwrap();
        let mut events: Vec<SealedObjectEvent> = state
            .objects
            .iter()
            .map(|(id, stored)| SealedObjectEvent {
                id: *id,
                deleted: stored.sealed.is_none(),
                updated_at: stored.updated_at,
                object: stored.sealed.clone(),
            })
            .collect();
        // Hash256 is not Ord; order by its raw bytes so the cursor has a
        // total order to compare against.
        let sort_key = |e: &SealedObjectEvent| (e.updated_at, *AsRef::<[u8; 32]>::as_ref(&e.id));
        events.sort_by_key(sort_key);
        if let Some(ObjectsCursor { after, id }) = cursor {
            let cursor = (after, *AsRef::<[u8; 32]>::as_ref(&id));
            events.retain(|e| sort_key(e) > cursor);
        }
        events.truncate(limit.unwrap_or(usize::MAX));
        Ok(events)
    }

    pub(crate) async fn pin_object(
        &self,
        _: &PrivateKey,
        object: &SealedObject,
    ) -> Result<(), PinObjectError> {
        let mut state = self.state.write().unwrap();
        if object
            .slabs
            .iter()
            .any(|slab| !state.slabs.contains_key(&slab.digest()))
        {
            return Err(PinObjectError::UnpinnedSlab);
        }
        state.objects.insert(
            object.id(),
            StoredObject {
                sealed: Some(object.clone()),
                updated_at: Utc::now(),
            },
        );
        Ok(())
    }

    pub(crate) async fn delete_object(&self, _: &PrivateKey, key: &Hash256) -> Result<(), Error> {
        let mut state = self.state.write().unwrap();
        match state.objects.get_mut(key) {
            Some(stored) => {
                stored.sealed = None;
                stored.updated_at = Utc::now();
                Ok(())
            }
            None => Err(Error::Api(format!("object {key} not found"))),
        }
    }

    pub(crate) async fn slab(
        &self,
        _: &PrivateKey,
        slab_id: &Hash256,
    ) -> Result<PinnedSlab, Error> {
        self.state
            .read()
            .unwrap()
            .slabs
            .get(slab_id)
            .map(|s| PinnedSlab {
                version: s.version,
                id: s.id,
                encryption_key: s.encryption_key.clone(),
                min_shards: s.min_shards,
                sectors: s.sectors.clone(),
            })
            .ok_or_else(|| Error::Api(format!("slab {slab_id} not found")))
    }

    pub(crate) async fn pin_slabs(
        &self,
        _: &PrivateKey,
        slabs: &[SlabPinParams],
    ) -> Result<Vec<Hash256>, Error> {
        let mut state = self.state.write().unwrap();
        state.pin_slabs_calls += 1;
        if state.pin_slabs_failures > 0 {
            state.pin_slabs_failures -= 1;
            return Err(Error::Api("temporary pin failure".to_string()));
        }
        Ok(slabs
            .iter()
            .map(|params| {
                let id = slab_id(params);
                state.slabs.insert(
                    id,
                    PinnedSlab {
                        version: params.version,
                        id,
                        encryption_key: params.encryption_key.clone(),
                        min_shards: params.min_shards,
                        sectors: params.sectors.clone(),
                    },
                );
                id
            })
            .collect())
    }

    pub(crate) async fn prune_slabs(&self, _: &PrivateKey) -> Result<(), Error> {
        let mut state = self.state.write().unwrap();
        let referenced: HashSet<Hash256> = state
            .objects
            .values()
            .filter_map(|o| o.sealed.as_ref())
            .flat_map(|sealed| sealed.slabs.iter().map(|s| s.digest()))
            .collect();
        state.slabs.retain(|id, _| referenced.contains(id));
        Ok(())
    }

    pub(crate) async fn account(&self, app_key: &PrivateKey) -> Result<Account, Error> {
        let state = self.state.read().unwrap();
        let pinned_size: u64 = state
            .slabs
            .values()
            .map(|s| (s.sectors.len() * SECTOR_SIZE) as u64)
            .sum();
        let pinned_data: u64 = state
            .slabs
            .values()
            .map(|s| (s.min_shards as usize * SECTOR_SIZE) as u64)
            .sum();
        Ok(Account {
            account_key: app_key.public_key(),
            max_pinned_data: u64::MAX,
            remaining_storage: u64::MAX - pinned_data,
            pinned_data,
            pinned_size,
            ready: true,
            app: App {
                id: Hash256::default(),
                name: "mock".to_string(),
                description: "mock indexer".to_string(),
                logo_url: None,
                service_url: None,
            },
            last_used: Utc::now(),
        })
    }

    pub(crate) fn shared_object_url(
        &self,
        app_key: &PrivateKey,
        object: &Object,
        valid_until: DateTime<Utc>,
    ) -> Result<Url, Error> {
        let mut url: Url = format!(
            "{SHARE_URL_SCHEME}://{MOCK_AUTHORITY}/objects/{}/shared",
            object.id()
        )
        .parse()?;

        let params = sign(app_key, &url, Method::GET, None, valid_until);
        url.set_fragment(Some(
            format!(
                "encryption_key={}",
                URL_SAFE.encode(object.data_key.as_ref())
            )
            .as_str(),
        ));

        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            pairs.append_pair(key, value.as_str());
        }

        Ok(pairs.finish().to_owned())
    }

    pub(crate) async fn shared_object(&self, share_url: Url) -> Result<Object, Error> {
        if share_url.scheme() != SHARE_URL_SCHEME {
            return Err(Error::Format(format!(
                "invalid url scheme: expected {SHARE_URL_SCHEME}"
            )));
        }
        let data_key = match share_url.fragment() {
            Some(fragment) => {
                let fragment = fragment
                    .strip_prefix("encryption_key=")
                    .ok_or(Error::Format("missing encryption_key".into()))?;
                let mut out = [0u8; 32];
                match URL_SAFE.decode_slice(fragment, &mut out) {
                    Ok(32) => Ok(EncryptionKey::from(out)),
                    _ => Err(Error::Format(
                        "encryption key must be 32 bytes, base64url-encoded".into(),
                    )),
                }
            }
            None => Err(Error::Format("missing encryption_key".into())),
        }?;

        // ../objects/:id/shared
        let id: Hash256 = share_url
            .path_segments()
            .and_then(|segments| segments.rev().nth(1).map(str::to_string))
            .ok_or(Error::Format("invalid share url format".into()))?
            .parse()
            .map_err(|_| Error::Format("invalid object id".into()))?;

        let sealed = self
            .state
            .read()
            .unwrap()
            .objects
            .get(&id)
            .and_then(|o| o.sealed.clone())
            .ok_or_else(|| Error::Api(format!("object {id} not found")))?;

        Ok(Object {
            data_key,
            slabs: sealed.slabs,
            ..Default::default()
        })
    }

    /// Records a sharing key. It must echo the submitted public key and nonce:
    /// `create_sharing_key` verifies the response against the nonce it generated.
    pub(crate) async fn add_sharing_key(
        &self,
        _: &PrivateKey,
        req: &KeyRequest,
    ) -> Result<KeyResponse, Error> {
        let mut state = self.state.write().unwrap();
        if state.sharing_keys.contains_key(&req.public_key) {
            return Err(Error::Api("sharing key already exists".into()));
        }
        let stored = StoredSharingKey {
            key: SharingKey {
                public_key: req.public_key,
                nonce: req.nonce,
            },
            description: req.description.clone(),
            expires_at: req.expires_at,
            created_at: Utc::now(),
            attached: HashMap::new(),
        };
        let response = stored.response();
        state.sharing_keys.insert(req.public_key, stored);
        Ok(response)
    }

    pub(crate) async fn sharing_keys(
        &self,
        _: &PrivateKey,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<KeyResponse>, Error> {
        let state = self.state.read().unwrap();
        let mut keys: Vec<_> = state.sharing_keys.values().collect();
        // Newest first, matching indexd, with the key's bytes breaking ties.
        keys.sort_by_key(|k| (k.created_at, k.key.public_key.as_ref().to_vec()));
        keys.reverse();
        Ok(keys
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(StoredSharingKey::response)
            .collect())
    }

    pub(crate) async fn sharing_key(
        &self,
        _: &PrivateKey,
        public_key: &PublicKey,
    ) -> Result<KeyResponse, Error> {
        let state = self.state.read().unwrap();
        state
            .sharing_keys
            .get(public_key)
            .map(StoredSharingKey::response)
            .ok_or_else(|| Error::Api(format!("sharing key {public_key} not found")))
    }

    pub(crate) async fn delete_sharing_key(
        &self,
        _: &PrivateKey,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        let mut state = self.state.write().unwrap();
        if state.sharing_keys.remove(public_key).is_none() {
            return Err(Error::Api(format!("sharing key {public_key} not found")));
        }
        Ok(())
    }

    pub(crate) async fn add_shared_object(
        &self,
        _: &PrivateKey,
        sharing_key: &PublicKey,
        req: &SharedObjectRequest,
    ) -> Result<(), Error> {
        let now = Utc::now();
        let mut state = self.state.write().unwrap();
        let slabs = state
            .objects
            .get(&req.object_id)
            .and_then(|o| o.sealed.as_ref())
            .ok_or_else(|| Error::Api(format!("object {} not found", req.object_id)))?
            .slabs
            .clone();
        let stored = state
            .sharing_keys
            .get_mut(sharing_key)
            .ok_or_else(|| Error::Api(format!("sharing key {sharing_key} not found")))?;
        // The request carries the object's keys re-sealed under the sharing
        // key, so store those rather than the account-sealed originals.
        stored.attached.insert(
            req.object_id,
            SealedObject {
                slabs,
                created_at: now,
                updated_at: now,
                encrypted_data_key: req.encrypted_data_key.clone(),
                data_signature: req.data_signature.clone(),
                encrypted_metadata_key: req.encrypted_metadata_key.clone(),
                encrypted_metadata: req.encrypted_metadata.clone(),
                metadata_signature: req.metadata_signature.clone(),
            },
        );
        Ok(())
    }

    pub(crate) async fn sharing_key_objects(
        &self,
        _: &PrivateKey,
        sharing_key: &PublicKey,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<SealedObject>, Error> {
        let state = self.state.read().unwrap();
        state
            .sharing_keys
            .get(sharing_key)
            .map(|stored| stored.page(offset, limit))
            .ok_or_else(|| Error::Api(format!("sharing key {sharing_key} not found")))
    }

    /// Authenticates a `/shared` request the way the indexer does, by the public
    /// half of the key it is signed with.
    fn shared<'a>(
        state: &'a State,
        sharing_key: &PrivateKey,
    ) -> Result<&'a StoredSharingKey, Error> {
        let public_key = sharing_key.public_key();
        state
            .sharing_keys
            .get(&public_key)
            .ok_or_else(|| Error::Api(format!("sharing key {public_key} not found")))
    }

    pub(crate) async fn shared_stats(&self, sharing_key: &PrivateKey) -> Result<KeyStats, Error> {
        let state = self.state.read().unwrap();
        let record = Self::shared(&state, sharing_key)?.response();
        Ok(record.stats)
    }

    pub(crate) async fn shared_objects(
        &self,
        sharing_key: &PrivateKey,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<SealedObject>, Error> {
        let state = self.state.read().unwrap();
        Ok(Self::shared(&state, sharing_key)?.page(offset, limit))
    }

    pub(crate) async fn shared_object_by_id(
        &self,
        sharing_key: &PrivateKey,
        key: &Hash256,
    ) -> Result<SealedObject, Error> {
        let state = self.state.read().unwrap();
        Self::shared(&state, sharing_key)?
            .attached
            .get(key)
            .cloned()
            .ok_or_else(|| Error::Api(format!("object {key} not found")))
    }

    /// Signs every token with one stand-in account key. Nothing in the SDK
    /// inspects which account paid, only that a token is present and unexpired.
    pub(crate) async fn shared_hosts(
        &self,
        sharing_key: &PrivateKey,
        query: HostQuery,
    ) -> Result<Vec<SharedHost>, Error> {
        let state = self.state.read().unwrap();
        Self::shared(&state, sharing_key)?;
        let account_key = PrivateKey::from_seed(&[7u8; 32]);
        let offset = query.offset.unwrap_or(0) as usize;
        let limit = query.limit.map_or(usize::MAX, |l| l as usize);
        Ok(state
            .hosts
            .iter()
            .skip(offset)
            .take(limit)
            .map(|h| SharedHost {
                token: AccountToken::new(&account_key, h.public_key),
                host: h.clone(),
            })
            .collect())
    }

    pub(crate) async fn delete_shared_object(
        &self,
        _: &PrivateKey,
        sharing_key: &PublicKey,
        object_key: &Hash256,
    ) -> Result<(), Error> {
        let mut state = self.state.write().unwrap();
        let stored = state
            .sharing_keys
            .get_mut(sharing_key)
            .ok_or_else(|| Error::Api(format!("sharing key {sharing_key} not found")))?;
        if stored.attached.remove(object_key).is_none() {
            return Err(Error::Api(format!("object {object_key} is not attached")));
        }
        Ok(())
    }
}

/// Derives a slab's id the same way the indexer does, from the fields covered
/// by [`Slab::digest`]. `offset` and `length` are outside the digest.
fn slab_id(params: &SlabPinParams) -> Hash256 {
    Slab {
        version: params.version,
        encryption_key: params.encryption_key.clone(),
        min_shards: params.min_shards,
        sectors: params.sectors.clone(),
        offset: 0,
        length: 0,
    }
    .digest()
}

impl StoredSharingKey {
    /// Builds the record the sharing key API returns, with counts derived from
    /// what is currently attached.
    fn response(&self) -> KeyResponse {
        let object_size: u64 = self
            .attached
            .values()
            .flat_map(|o| o.slabs.iter())
            .map(|s| s.length as u64)
            .sum();
        KeyResponse {
            key: self.key,
            account: PublicKey::new([0u8; 32]),
            description: self.description.clone(),
            stats: KeyStats {
                object_count: self.attached.len() as u64,
                object_size,
                pinned_data: object_size,
                pinned_size: object_size,
                expires_at: self.expires_at,
                created_at: self.created_at,
                updated_at: self.created_at,
            },
        }
    }

    /// Returns a stable page of the attached objects, ordered by id.
    fn page(&self, offset: u64, limit: u64) -> Vec<SealedObject> {
        let mut ids: Vec<_> = self.attached.keys().copied().collect();
        ids.sort_by_key(|id| *AsRef::<[u8; 32]>::as_ref(id));
        ids.into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .filter_map(|id| self.attached.get(&id).cloned())
            .collect()
    }
}
