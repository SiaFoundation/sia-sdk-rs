use std::sync::Mutex;

use log::debug;

use crate::time::Duration;

const CONGESTION_THRESHOLD: f64 = 1.5;

/// Ratio charged for a failed attempt, and the per-sample cap. Capping at
/// 2*CONGESTION_THRESHOLD means over a quarter of a window must be congested before the
/// mean can cross CONGESTION_THRESHOLD, so a few slow hosts can't force a back-off on
/// their own.
const FAILURE_RATIO: f64 = 2.0 * CONGESTION_THRESHOLD;

const MIN_WINDOW: usize = 16;

#[derive(Debug)]
struct State {
    limit: usize,
    floor: usize,
    cap: usize,
    /// Doubling growth until the first congestion signal, additive after.
    slow_start: bool,
    /// Completions to drop after a back-off: the cohort still in flight was
    /// started under the old limit, so counting it would cascade the limit
    /// down to the floor.
    skip: usize,
    completions: usize,
    scale: usize,
    ratio_sum: f64,
}

impl State {
    /// Completions before the next decision. Slow start uses a small fixed
    /// probe so the exponential climb reaches the ceiling in a few steps;
    /// steady state scales with the limit to keep the congestion mean stable.
    fn window(&self) -> usize {
        if self.slow_start {
            MIN_WINDOW
        } else {
            (self.limit * self.scale).max(MIN_WINDOW)
        }
    }
}

/// AIMD controller for a transfer pipeline's inflight limit.
///
/// The congestion signal is per-host-relative: each completed RPC reports
/// its observed pace over the host's own expected pace. One host slower
/// than itself is a host problem (scoring and racing handle that); many
/// distinct hosts slower than their own baselines at once share one cause
/// — the client's pipe. Windows are completion-counted, so there are no
/// clocks or background tasks and it works on wasm.
#[derive(Debug)]
pub(crate) struct InflightController {
    state: Mutex<State>,
}

impl InflightController {
    pub(crate) fn new(initial: usize, floor: usize, cap: usize, scale: usize) -> Self {
        let floor = floor.min(cap);
        let limit = initial.clamp(floor, cap);
        let scale = scale.max(1);
        Self {
            state: Mutex::new(State {
                limit,
                floor,
                cap,
                slow_start: true,
                skip: 0,
                completions: 0,
                scale,
                ratio_sum: 0.0,
            }),
        }
    }

    /// The current inflight limit.
    pub(crate) fn limit(&self) -> usize {
        self.state.lock().unwrap().limit
    }

    /// Records a completed transfer and returns the resulting change to the
    /// limit (non-zero only when this completion closes a window). `expected`
    /// is the host's own predicted duration, fetched before the RPC so it
    /// excludes the transfer being measured, or `None` if the host has no
    /// baseline yet; `elapsed` is the actual duration; `ok` is whether the
    /// RPC succeeded.
    pub(crate) fn record(&self, expected: Option<Duration>, elapsed: Duration, ok: bool) -> isize {
        let ratio = if ok {
            expected.map(|e| elapsed.as_secs_f64() / e.as_secs_f64())
        } else {
            Some(FAILURE_RATIO)
        };
        let mut state = self.state.lock().unwrap();
        if state.skip > 0 {
            state.skip -= 1;
            return 0;
        }
        state.completions += 1;
        // A completion with no host baseline contributes a neutral 1.0, so
        // the mean spans the whole window rather than only sampled
        // completions — otherwise a couple of failures could declare
        // congestion alone before any baselines exist.
        state.ratio_sum += ratio.map_or(1.0, |r| r.min(FAILURE_RATIO));
        if state.completions < state.window() {
            return 0;
        }

        let old = state.limit;
        let congested = state.ratio_sum / state.completions as f64 > CONGESTION_THRESHOLD;
        if congested {
            state.limit = (state.limit / 2).max(state.floor);
            state.slow_start = false;
            // Drop the in-flight cohort (bounded by the old limit) before
            // the next window so its stragglers can't trigger a second
            // back-off.
            state.skip = old * state.scale;
        } else if state.slow_start {
            state.limit = (state.limit * 2).min(state.cap);
        } else {
            state.limit = (state.limit + 1).min(state.cap);
        }
        state.completions = 0;
        state.ratio_sum = 0.0;
        let delta = state.limit as isize - old as isize;
        if delta != 0 {
            debug!("AIMD limit changed {} ({delta:+})", state.limit);
        }
        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    /// Drives `n` successful completions at the given pace ratio (`None` =
    /// the host has no baseline yet). A ratio `r` is synthesized as an
    /// `r`-second transfer against a 1-second baseline.
    fn drive(c: &InflightController, n: usize, ratio: Option<f64>) {
        for _ in 0..n {
            match ratio {
                Some(r) => {
                    c.record(
                        Some(Duration::from_secs(1)),
                        Duration::from_secs_f64(r),
                        true,
                    );
                }
                None => {
                    c.record(None, Duration::ZERO, true);
                }
            }
        }
    }

    /// Drives `n` failed completions (each contributes [`FAILURE_RATIO`]).
    fn fail(c: &InflightController, n: usize) {
        for _ in 0..n {
            c.record(None, Duration::ZERO, false);
        }
    }

    /// The current window length: limit-scaled with the MIN_WINDOW floor.
    fn window(c: &InflightController, scale: usize) -> usize {
        (c.limit() * scale).max(MIN_WINDOW)
    }

    #[sia_core_derive::cross_target_test]
    fn test_slow_start_doubles_until_cap() {
        // Slow start probes with a fixed MIN_WINDOW per step and doubles on
        // every clean window until it clamps at the cap.
        let c = InflightController::new(8, 2, 100, 1);
        assert_eq!(c.limit(), 8);
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 16, "clean window in slow start doubles");
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 32);
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 64, "step closes after MIN_WINDOW, not the limit");
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 100, "growth clamps at the cap");
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 100);
    }

    #[sia_core_derive::cross_target_test]
    fn test_slow_start_window_ignores_scale() {
        // Download fan-out (scale 10) must not lengthen the slow-start
        // probe: a doubling still closes after MIN_WINDOW completions, not
        // limit * scale.
        let c = InflightController::new(8, 1, 100, 10);
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(
            c.limit(),
            16,
            "slow-start probe stays MIN_WINDOW under fan-out"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_congestion_halves_then_additive_growth() {
        let c = InflightController::new(16, 2, 100, 1);
        drive(&c, 16, Some(2.0));
        assert_eq!(c.limit(), 8, "congested window halves the limit");
        // the old 16-deep cohort drains as stragglers; even congested
        // ratios must not trigger a second back-off
        drive(&c, 16, Some(3.0));
        assert_eq!(c.limit(), 8, "old cohort must not back off again");
        drive(&c, window(&c, 1), Some(1.0));
        assert_eq!(
            c.limit(),
            9,
            "clean window after congestion grows additively"
        );
        drive(&c, window(&c, 1), Some(1.0));
        assert_eq!(c.limit(), 10);
    }

    #[sia_core_derive::cross_target_test]
    fn test_back_off_skip_scales_with_fanout() {
        // scale 10 (download): a back-off halves 16 -> 8, and the in-flight
        // cohort is old_limit * scale = 160 sampled reads, so the skip must
        // drop that many before the next window opens.
        let c = InflightController::new(16, 1, 100, 10);
        drive(&c, MIN_WINDOW, Some(2.0)); // slow-start probe → back-off
        assert_eq!(c.limit(), 8, "congested probe halves the limit");
        drive(&c, 160, Some(3.0));
        assert_eq!(c.limit(), 8, "scaled cohort must not back off again");
        drive(&c, window(&c, 10), Some(1.0));
        assert_eq!(c.limit(), 9, "clean window after the cohort drains grows");
    }

    #[sia_core_derive::cross_target_test]
    fn test_back_off_clamps_at_floor() {
        let c = InflightController::new(4, 2, 100, 1);
        drive(&c, window(&c, 1), Some(3.0));
        assert_eq!(c.limit(), 2);
        drive(&c, 4, Some(3.0)); // old cohort drains
        drive(&c, window(&c, 1), Some(3.0));
        assert_eq!(c.limit(), 2, "back-off never goes below the floor");
    }

    #[sia_core_derive::cross_target_test]
    fn test_minority_of_bad_hosts_cannot_back_off() {
        // 4 failures + 12 clean in a 16-wide window:
        // mean = (4*3.0 + 12*1.0) / 16 = 1.5, not above CONGESTION_THRESHOLD. A quarter
        // of a window misbehaving must not shrink the limit.
        let c = InflightController::new(8, 2, 100, 1);
        fail(&c, 4);
        drive(&c, 12, Some(1.0));
        assert_eq!(c.limit(), 16, "minority slow samples must not back off");
    }

    #[sia_core_derive::cross_target_test]
    fn test_min_window_protects_small_limits() {
        // At a small limit the window stays MIN_WINDOW long, so a few
        // failures can't dominate the mean: 3 failures + 13 clean =
        // (3*3.0 + 13*1.0) / 16 ≈ 1.4, below CONGESTION_THRESHOLD.
        let c = InflightController::new(2, 2, 100, 1);
        fail(&c, 3);
        drive(&c, 13, Some(1.0));
        assert_eq!(
            c.limit(),
            4,
            "a few failures must not back off a small limit"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_sparse_baselines_neutralize_failures() {
        // Early-transfer shape: successes have no baseline yet (neutral
        // 1.0). The failures must not dominate the mean:
        // 2 failures + 14 baseline-less = (2*3.0 + 14*1.0) / 16 = 1.25 < CONGESTION_THRESHOLD.
        let c = InflightController::new(8, 2, 100, 1);
        fail(&c, 2);
        drive(&c, 14, None);
        assert_eq!(
            c.limit(),
            16,
            "failures among baseline-less successes must not back off"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_unsampled_completions_count_toward_window() {
        // Completions without a baseline close windows but carry no
        // congestion evidence; the window is treated as clean.
        let c = InflightController::new(4, 2, 100, 1);
        drive(&c, window(&c, 1), None);
        assert_eq!(c.limit(), 8, "baseline-free window grows");
    }

    #[sia_core_derive::cross_target_test]
    fn test_sample_cap_bounds_outliers() {
        // One absurd outlier among otherwise clean samples is capped to
        // FAILURE_RATIO and cannot drag the mean over CONGESTION_THRESHOLD by itself.
        let c = InflightController::new(8, 2, 100, 1);
        drive(&c, 1, Some(1_000.0));
        drive(&c, 15, Some(1.0));
        assert_eq!(c.limit(), 16, "capped outlier must not back off");
    }

    #[sia_core_derive::cross_target_test]
    fn test_initial_clamped_to_bounds() {
        // Initial is clamped into [floor, cap].
        assert_eq!(InflightController::new(8, 2, 4, 1).limit(), 4);
        assert_eq!(InflightController::new(1, 2, 100, 1).limit(), 2);
        // degenerate cap below floor: cap wins
        assert_eq!(InflightController::new(8, 2, 1, 1).limit(), 1);
    }
}
