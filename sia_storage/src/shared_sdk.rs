use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use log::warn;
use sia_core::rhp4::AccountToken;
use sia_core::signing::PublicKey;
use sia_core::types::Hash256;

use crate::app_client::IntoUrl;
use crate::hosts::{Host, Hosts};
use crate::rhp4::Client;
use crate::task::AbortOnDropHandle;
use crate::time::{Duration, sleep};
use crate::tokens::AccountTokenSource;
use crate::{
    BuilderError, Download, DownloadError, DownloadOptions, Error, HostQuery, KeyStats, Object,
    SharingKey, app_client,
};

/// Refresh the token cache this long before the earliest token expires.
const REFRESH_MARGIN_SECS: i64 = 60;
/// Never refresh more often than this, even if tokens are near expiry.
const MIN_REFRESH_SECS: u64 = 30;
/// Refresh at least this often, regardless of the tokens' claimed validity.
const MAX_REFRESH_SECS: u64 = 4 * 60;
/// Stop refreshing only after this many consecutive unauthorized responses. A
/// single 401 can be transient clock skew, so one is not enough to conclude the
/// sharing key was revoked.
const MAX_AUTH_FAILURES: u32 = 3;

/// A read-only SDK for downloading the objects a sharing key grants access to.
///
/// Unlike [Sdk](crate::Sdk), a `SharedSdk` authenticates with a sharing key
/// rather than an app key and cannot upload, pin, or delete. Downloads are paid
/// for with server-signed account tokens drawn from the sharing key owner's
/// account; the tokens are refreshed automatically before they expire.
#[derive(Clone)]
pub struct SharedSdk {
    sharing_key: Arc<SharingKey>,
    api_client: app_client::Client,
    hosts: Hosts,
    tokens: Arc<RwLock<HashMap<PublicKey, AccountToken>>>,
    refresh_task: Arc<AbortOnDropHandle<()>>,
}

impl SharedSdk {
    /// Fetches usable hosts and their account tokens, replacing the host set
    /// and the token cache. Returns the earliest token expiry so the caller can
    /// schedule the next refresh before it.
    async fn refresh(
        sharing_key: &SharingKey,
        api_client: &app_client::Client,
        hosts: &Hosts,
        tokens: &RwLock<HashMap<PublicKey, AccountToken>>,
    ) -> Result<Option<DateTime<Utc>>, app_client::Error> {
        const PAGE_SIZE: usize = 100;
        let mut shared = Vec::new();
        for offset in (0..).step_by(PAGE_SIZE) {
            let page = api_client
                .shared_hosts(
                    &sharing_key.0,
                    HostQuery {
                        offset: Some(offset),
                        limit: Some(PAGE_SIZE as u64),
                        ..Default::default()
                    },
                )
                .await?;
            let done = page.len() < PAGE_SIZE;
            shared.extend(page);
            if done {
                break;
            }
        }

        let mut host_list = Vec::with_capacity(shared.len());
        let mut token_map = HashMap::with_capacity(shared.len());
        let mut earliest: Option<DateTime<Utc>> = None;
        for h in shared {
            let expiry = h.token.valid_until;
            earliest = Some(earliest.map_or(expiry, |e| e.min(expiry)));
            token_map.insert(h.host.public_key, h.token);
            host_list.push(h.host);
        }

        hosts.update(host_list, true);
        *tokens.write().unwrap() = token_map;
        Ok(earliest)
    }

    /// Connects to `indexer_url` as the recipient of the sharing key derived
    /// from `seed`.
    ///
    /// `seed` is the credential the key's owner hands out; how it reaches the
    /// recipient is up to the caller.
    pub async fn connect<U: IntoUrl>(indexer_url: U, seed: [u8; 32]) -> Result<Self, BuilderError> {
        let api_client = app_client::Client::new(indexer_url)?;
        Self::new(api_client, SharingKey::import(seed)).await
    }

    /// Connects as the recipient of a sharing key. Seeds the host list and token
    /// cache and spawns a task that refreshes them before the tokens expire.
    pub(crate) async fn new(
        api_client: app_client::Client,
        sharing_key: SharingKey,
    ) -> Result<Self, BuilderError> {
        let sharing_key = Arc::new(sharing_key);
        let hosts = Hosts::new(Client::new());
        let tokens = Arc::new(RwLock::new(HashMap::new()));
        let earliest = Self::refresh(&sharing_key, &api_client, &hosts, &tokens).await?;
        let refresh_task = Self::spawn_refresh_task(
            sharing_key.clone(),
            api_client.clone(),
            hosts.clone(),
            tokens.clone(),
            earliest,
        );
        Ok(Self {
            sharing_key,
            api_client,
            hosts,
            tokens,
            refresh_task: Arc::new(refresh_task),
        })
    }

    /// Computes how long to wait before the next refresh, aiming to replace the
    /// tokens [`REFRESH_MARGIN_SECS`] before the earliest one expires.
    fn refresh_delay(earliest: Option<DateTime<Utc>>) -> Duration {
        let Some(earliest) = earliest else {
            return Duration::from_secs(MIN_REFRESH_SECS);
        };
        let secs = earliest
            .signed_duration_since(Utc::now())
            .num_seconds()
            .saturating_sub(REFRESH_MARGIN_SECS)
            .clamp(MIN_REFRESH_SECS as i64, MAX_REFRESH_SECS as i64) as u64;
        Duration::from_secs(secs)
    }

    /// Applies a refresh outcome to the loop's state, returning the next
    /// earliest expiry to pace from, or [`ControlFlow::Break`] when the sharing
    /// key is no longer accepted. Only [`MAX_AUTH_FAILURES`] consecutive
    /// unauthorized responses count as revocation, since a single 401 can be
    /// transient clock skew; every other error is transient and retried.
    fn apply_refresh(
        result: Result<Option<DateTime<Utc>>, app_client::Error>,
        auth_failures: &mut u32,
    ) -> ControlFlow<(), Option<DateTime<Utc>>> {
        match result {
            Ok(next) => {
                *auth_failures = 0;
                ControlFlow::Continue(next)
            }
            Err(app_client::Error::Unauthorized(err)) => {
                *auth_failures += 1;
                if *auth_failures >= MAX_AUTH_FAILURES {
                    warn!(
                        "shared key unauthorized {} times, stopping refresh: {err}",
                        *auth_failures
                    );
                    ControlFlow::Break(())
                } else {
                    warn!(
                        "shared hosts unauthorized ({}/{MAX_AUTH_FAILURES}), retrying: {err}",
                        *auth_failures
                    );
                    ControlFlow::Continue(None)
                }
            }
            Err(err) => {
                warn!("failed to refresh shared hosts, retrying: {err}");
                *auth_failures = 0;
                ControlFlow::Continue(None)
            }
        }
    }

    /// Spawns a background task that refreshes the hosts and tokens, pacing
    /// itself off the tokens' expiry.
    fn spawn_refresh_task(
        sharing_key: Arc<SharingKey>,
        api_client: app_client::Client,
        hosts: Hosts,
        tokens: Arc<RwLock<HashMap<PublicKey, AccountToken>>>,
        initial_earliest: Option<DateTime<Utc>>,
    ) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(maybe_spawn!(async move {
            let mut earliest = initial_earliest;
            let mut auth_failures = 0;
            loop {
                sleep(Self::refresh_delay(earliest)).await;
                let result = Self::refresh(&sharing_key, &api_client, &hosts, &tokens).await;
                match Self::apply_refresh(result, &mut auth_failures) {
                    ControlFlow::Continue(next) => earliest = next,
                    ControlFlow::Break(()) => break,
                }
            }
        }))
    }

    /// Fetches the sharing key's stats from the indexer.
    pub async fn stats(&self) -> Result<KeyStats, Error> {
        self.api_client
            .shared_stats(&self.sharing_key.0)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))
    }

    /// Retrieves and decrypts a single object the sharing key grants access to.
    pub async fn object(&self, key: &Hash256) -> Result<Object, Error> {
        let sealed = self
            .api_client
            .shared_object_by_id(&self.sharing_key.0, key)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(sealed.open_with(&self.sharing_key.0)?)
    }

    /// Lists and decrypts a page of the objects the sharing key grants access
    /// to. Omit `offset` or `limit` to use the indexer's default paging.
    pub async fn objects(
        &self,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<Object>, Error> {
        let sealed = self
            .api_client
            .shared_objects(&self.sharing_key.0, offset, limit)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        sealed
            .into_iter()
            .map(|s| s.open_with(&self.sharing_key.0).map_err(Error::from))
            .collect()
    }

    /// Retrieves the hosts serving this key's objects from the indexer,
    /// matching the provided query. Mirrors [`Sdk::hosts`](crate::Sdk::hosts)
    /// but is scoped to the sharing key.
    pub async fn hosts(&self, query: HostQuery) -> Result<Vec<Host>, Error> {
        let shared = self
            .api_client
            .shared_hosts(&self.sharing_key.0, query)
            .await
            .map_err(|e| Error::App(format!("{e:?}")))?;
        Ok(shared.into_iter().map(|h| h.host).collect())
    }

    /// Returns a [Download] handle that streams a shared object's data, paying
    /// hosts with the cached account tokens.
    ///
    /// The handle keeps the token refresh task alive on its own, so it stays
    /// usable for downloads longer than a token's validity even if this
    /// `SharedSdk` is dropped first.
    pub fn download(
        &self,
        object: &Object,
        options: DownloadOptions,
    ) -> Result<Download, DownloadError> {
        Download::new(
            object,
            self.hosts.clone(),
            AccountTokenSource::Shared {
                tokens: self.tokens.clone(),
                _refresh: self.refresh_task.clone(),
            },
            options,
        )
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::app_client::SharedHost;
    use crate::hosts::Host;
    use crate::slabs::SlabVersion::V0;
    use crate::slabs::{Sector, Slab};
    use httptest::http::{Response, StatusCode};
    use httptest::matchers::*;
    use httptest::{Expectation, Server};
    use sia_core::signing::PrivateKey;

    #[test]
    fn test_apply_refresh_tolerates_transient_errors() {
        let mut failures = 2;

        // A non-auth error (e.g. a 404 during a redeploy) is transient and
        // clears the streak.
        assert!(matches!(
            SharedSdk::apply_refresh(
                Err(app_client::Error::NotFound("route".into())),
                &mut failures
            ),
            ControlFlow::Continue(None)
        ));
        assert_eq!(failures, 0);

        // Only MAX_AUTH_FAILURES consecutive 401s stop the loop.
        for _ in 0..MAX_AUTH_FAILURES - 1 {
            assert!(matches!(
                SharedSdk::apply_refresh(
                    Err(app_client::Error::Unauthorized("skew".into())),
                    &mut failures
                ),
                ControlFlow::Continue(None)
            ));
        }
        assert!(matches!(
            SharedSdk::apply_refresh(
                Err(app_client::Error::Unauthorized("revoked".into())),
                &mut failures
            ),
            ControlFlow::Break(())
        ));

        // A success clears the streak.
        assert!(matches!(
            SharedSdk::apply_refresh(Ok(None), &mut failures),
            ControlFlow::Continue(None)
        ));
        assert_eq!(failures, 0);
    }

    #[tokio::test]
    async fn test_recipient_flow() {
        let sharing_seed = [7u8; 32];
        let sharing_key = PrivateKey::from_seed(&sharing_seed);

        // A host and its account token, returned by GET /shared/hosts.
        let host = Host {
            public_key: PublicKey::new([3u8; 32]),
            addresses: vec![],
            country_code: "US".to_string(),
            latitude: 0.0,
            longitude: 0.0,
            good_for_upload: true,
        };
        let token = AccountToken::new(&PrivateKey::from_seed(&[8u8; 32]), host.public_key);
        let hosts_body = serde_json::to_string(&vec![SharedHost {
            host: host.clone(),
            token: token.clone(),
        }])
        .unwrap();

        // An object sealed with the sharing key (as the owner re-seals it for
        // sharing), returned by GET /shared/objects/:id.
        let object = Object {
            data_key: [9u8; 32].into(),
            slabs: vec![Slab {
                version: V0,
                encryption_key: [1u8; 32].into(),
                min_shards: 1,
                sectors: vec![Sector {
                    root: Hash256::new([2u8; 32]),
                    host_key: host.public_key,
                }],
                offset: 0,
                length: 256,
            }],
            ..Default::default()
        };
        let object_id = object.id();
        let object_body = serde_json::to_string(&object.seal_with(&sharing_key)).unwrap();

        let stats = KeyStats {
            object_count: 1,
            object_size: 256,
            pinned_data: 256,
            pinned_size: 768,
            expires_at: None,
            created_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            updated_at: DateTime::from_timestamp(1_700_000_100, 0).unwrap(),
        };
        let stats_body = serde_json::to_string(&stats).unwrap();

        let server = Server::run();
        // GET /shared/hosts may be re-requested by the refresh task, so allow 1+.
        server.expect(
            Expectation::matching(request::method_path("GET", "/shared/hosts"))
                .times(1..)
                .respond_with(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(hosts_body)
                        .unwrap(),
                ),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/shared")).respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(stats_body)
                    .unwrap(),
            ),
        );
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/shared/objects/{object_id}"),
            ))
            .times(1..)
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(object_body)
                    .unwrap(),
            ),
        );

        let sdk = SharedSdk::connect(format!("http://{}", server.addr()), sharing_seed)
            .await
            .expect("failed to build shared sdk");

        {
            let cache = sdk.tokens.read().unwrap();
            assert_eq!(cache.len(), 1);
            assert_eq!(cache.get(&host.public_key), Some(&token));
        }

        assert_eq!(sdk.stats().await.unwrap(), stats);

        let hosts = sdk.hosts(HostQuery::default()).await.unwrap();
        assert_eq!(hosts, vec![host.clone()]);

        let fetched = sdk.object(&object_id).await.unwrap();
        assert_eq!(fetched.data_key, object.data_key);
        assert_eq!(fetched.slabs(), object.slabs());

        assert!(sdk.download(&object, DownloadOptions::default()).is_ok());
    }
}
