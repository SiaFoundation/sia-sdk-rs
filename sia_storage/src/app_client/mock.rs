use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::URL_SAFE;
use base64::prelude::*;
use chrono::{DateTime, Utc};
use reqwest::Method;
use sia_core::rhp4::SECTOR_SIZE;
use sia_core::signing::PrivateKey;
use sia_core::types::Hash256;

use super::{
    Error, RegisterAppResponse, SHARE_URL_SCHEME, SealedObjectEvent, SlabPinParams, Url, sign,
};
use crate::encryption::EncryptionKey;
use crate::hosts::Host;
use crate::slabs::Slab;
use crate::time::Duration;
use crate::{
    Account, App, AppMetadata, HostQuery, Object, ObjectsCursor, PinnedSlab, SealedObject,
};

const MOCK_AUTHORITY: &str = "mock.indexd";

#[derive(Debug)]
struct StoredObject {
    /// `None` once the object has been deleted. The tombstone is retained so
    /// [`Client::objects`] reports the deletion, matching the indexer.
    sealed: Option<SealedObject>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
struct State {
    hosts: Vec<Host>,
    objects: HashMap<Hash256, StoredObject>,
    slabs: HashMap<Hash256, PinnedSlab>,
    user_secret: Hash256,
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
    ) -> Result<(), Error> {
        let mut state = self.state.write().unwrap();
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
