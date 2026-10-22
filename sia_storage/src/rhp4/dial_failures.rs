#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use std::collections::HashMap;

use crate::time::{Duration, Instant};

/// How long Chrome counts a failed WebTransport handshake against every new
/// connection the browser makes.
pub(crate) const DIAL_FAILURE_BACKOFF: Duration = Duration::from_secs(5 * 60);

/// Addresses whose WebTransport handshake was refused, and when.
#[derive(Debug, Default)]
pub(crate) struct DialFailures {
    refused_at: HashMap<String, Instant>,
}

impl DialFailures {
    /// Also forgets every record whose backoff is over, so addresses that are
    /// never dialed again do not stay for the life of the page.
    pub(crate) fn record(&mut self, address: &str, now: Instant) {
        self.refused_at.retain(|_, refused_at| {
            now.saturating_duration_since(*refused_at) < DIAL_FAILURE_BACKOFF
        });
        self.refused_at.insert(address.to_string(), now);
    }

    /// Whether `address` refused a handshake within [`DIAL_FAILURE_BACKOFF`]
    /// of `now`. Forgets the address once that has passed.
    pub(crate) fn in_backoff(&mut self, address: &str, now: Instant) -> bool {
        let Some(refused_at) = self.refused_at.get(address) else {
            return false;
        };
        if now.saturating_duration_since(*refused_at) >= DIAL_FAILURE_BACKOFF {
            self.refused_at.remove(address);
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_that_never_refused_may_be_dialed() {
        let mut failures = DialFailures::default();
        assert!(!failures.in_backoff("a:9984", Instant::now()));
    }

    #[test]
    fn a_refused_address_waits_out_the_backoff_and_others_do_not() {
        let mut failures = DialFailures::default();
        let refused = Instant::now();
        failures.record("a:9984", refused);

        let later = refused + Duration::from_secs(60);
        assert!(failures.in_backoff("a:9984", later));
        assert!(!failures.in_backoff("b:9984", later));
    }

    #[test]
    fn a_refused_address_may_be_dialed_again_once_the_backoff_is_over() {
        let mut failures = DialFailures::default();
        let refused = Instant::now();
        failures.record("a:9984", refused);

        assert!(!failures.in_backoff("a:9984", refused + DIAL_FAILURE_BACKOFF));
        assert!(failures.refused_at.is_empty());
    }

    #[test]
    fn recording_a_refusal_forgets_the_expired_ones() {
        let mut failures = DialFailures::default();
        let first = Instant::now();
        failures.record("a:9984", first);
        failures.record("b:9984", first + DIAL_FAILURE_BACKOFF);

        assert_eq!(failures.refused_at.len(), 1);
        assert!(failures.refused_at.contains_key("b:9984"));
    }

    #[test]
    fn a_second_refusal_restarts_the_backoff() {
        let mut failures = DialFailures::default();
        let first = Instant::now();
        failures.record("a:9984", first);
        let second = first + DIAL_FAILURE_BACKOFF;
        failures.record("a:9984", second);

        assert!(failures.in_backoff("a:9984", second + Duration::from_secs(1)));
    }
}
