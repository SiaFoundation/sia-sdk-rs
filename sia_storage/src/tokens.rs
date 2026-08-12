use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use sia_core::rhp4::AccountToken;
use sia_core::signing::PublicKey;

use crate::AppKey;
use crate::hosts::RPCError;
use crate::task::AbortOnDropHandle;

/// Supplies the RHP4 [`AccountToken`] used to pay a host for a sector read.
#[derive(Clone)]
pub(crate) enum AccountTokenSource {
    /// Owner mode: mint a fresh token per read from the account key.
    Mint(Arc<AppKey>),
    /// Shared mode: serve a server-signed token from the cached
    /// `GET /shared/hosts` response, keyed by host.
    Shared {
        tokens: Arc<RwLock<HashMap<PublicKey, AccountToken>>>,
        /// Keeps the [`SharedSdk`](crate::SharedSdk) refresh task alive for as
        /// long as any download can still read from the cache.
        _refresh: Arc<AbortOnDropHandle<()>>,
    },
}

impl AccountTokenSource {
    pub(crate) fn token(&self, host: PublicKey) -> Result<AccountToken, RPCError> {
        match self {
            Self::Mint(key) => Ok(AccountToken::new(&key.0, host)),
            Self::Shared { tokens, .. } => tokens
                .read()
                .unwrap()
                .get(&host)
                .filter(|token| token.valid_until > Utc::now())
                .cloned()
                .ok_or(RPCError::NoToken(host)),
        }
    }
}

impl From<Arc<AppKey>> for AccountTokenSource {
    fn from(key: Arc<AppKey>) -> Self {
        Self::Mint(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sia_core::signing::PrivateKey;

    #[tokio::test]
    async fn test_shared_token_lookup() {
        let host = PublicKey::new([1u8; 32]);
        let missing = PublicKey::new([2u8; 32]);
        let token = AccountToken::new(&PrivateKey::from_seed(&[3u8; 32]), host);

        let mut map = HashMap::new();
        map.insert(host, token.clone());
        let source = AccountTokenSource::Shared {
            tokens: Arc::new(RwLock::new(map)),
            _refresh: Arc::new(AbortOnDropHandle::new(maybe_spawn!(
                std::future::pending::<()>()
            ))),
        };

        assert_eq!(source.token(host).unwrap(), token);
        assert!(matches!(source.token(missing), Err(RPCError::NoToken(pk)) if pk == missing));
    }

    #[tokio::test]
    async fn test_expired_shared_token_is_absent() {
        let host = PublicKey::new([1u8; 32]);
        let mut expired = AccountToken::new(&PrivateKey::from_seed(&[3u8; 32]), host);
        expired.valid_until = Utc::now() - chrono::Duration::seconds(1);

        let mut map = HashMap::new();
        map.insert(host, expired);
        let source = AccountTokenSource::Shared {
            tokens: Arc::new(RwLock::new(map)),
            _refresh: Arc::new(AbortOnDropHandle::new(maybe_spawn!(
                std::future::pending::<()>()
            ))),
        };

        assert!(matches!(source.token(host), Err(RPCError::NoToken(pk)) if pk == host));
    }

    #[test]
    fn test_mint_token_matches_host() {
        let key: Arc<AppKey> = Arc::new(AppKey(PrivateKey::from_seed(&[4u8; 32])));
        let host = PublicKey::new([5u8; 32]);
        let source = AccountTokenSource::Mint(key.clone());

        let token = source.token(host).unwrap();
        assert_eq!(token.host_key, host);
        assert_eq!(token.account, key.0.public_key());
    }
}
