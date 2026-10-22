use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use sia_core::rhp4::HostPrices;
use sia_core::signing::PublicKey;
use tokio::sync::watch;

use crate::task::AbortOnDropHandle;

type PriceOutcome = Result<HostPrices, crate::rhp4::Error>;

/// A price RPC running on its own task. Waiters hold the `Arc`; dropping
/// the last one aborts the task.
pub(super) struct PriceFetch {
    pub(super) outcome: watch::Receiver<Option<PriceOutcome>>,
    pub(super) _task: AbortOnDropHandle<()>,
}

pub(super) enum PriceEntry {
    Cached(HostPrices),
    Fetching(Weak<PriceFetch>),
}

/// Caches each host's price table and serializes concurrent fetches for
/// the same host behind a single RPC.
#[derive(Clone, Default)]
pub(super) struct PriceCache {
    pub(super) entries: Arc<Mutex<HashMap<PublicKey, PriceEntry>>>,
}
