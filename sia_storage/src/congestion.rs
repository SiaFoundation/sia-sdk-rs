use std::sync::Mutex;

use log::debug;

use crate::time::Duration;

const CONGESTION_THRESHOLD: f64 = 1.5;
const FAILURE_RATIO: f64 = 2.0 * CONGESTION_THRESHOLD;
const MIN_WINDOW: usize = 16;
/// Cap on the steady window so the controller keeps evaluating congestion at
/// high limits instead of going open-loop at `limit * scale`.
const MAX_WINDOW: usize = 1024;
/// Consecutive congested windows required to back off.
const CONGEST_CONFIRM: usize = 2;
/// Clean additive windows before re-probing upward (raising ssthresh) to retest
/// higher concurrency after the pipe clears.
const REPROBE_AFTER: usize = 4;

#[derive(Debug)]
struct State {
    limit: usize,
    floor: usize,
    cap: usize,
    scale: usize,
    /// Multiplicative growth below, additive at/above; reset to the knee on back-off.
    ssthresh: usize,
    strikes: usize,
    /// Clean additive windows since the last congestion or re-probe.
    clean_run: usize,
    /// Completions to drop after a back-off so the stale cohort can't re-trigger one.
    skip: usize,
    completions: usize,
    ratio_sum: f64,
}

impl State {
    fn window(&self) -> usize {
        if self.limit < self.ssthresh {
            MIN_WINDOW
        } else {
            (self.limit * self.scale).clamp(MIN_WINDOW, MAX_WINDOW)
        }
    }
}

/// AIMD controller for a pipeline's inflight limit. The congestion signal is
/// per-host-relative pace. Many distinct hosts slow at once means the client's
/// pipe is the bottleneck.
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
                scale,
                ssthresh: cap,
                strikes: 0,
                clean_run: 0,
                skip: 0,
                completions: 0,
                ratio_sum: 0.0,
            }),
        }
    }

    pub(crate) fn limit(&self) -> usize {
        self.state.lock().unwrap().limit
    }

    pub(crate) fn cap(&self) -> usize {
        self.state.lock().unwrap().cap
    }

    /// Records a completed transfer and returns the change to the limit.
    /// `expected` is the host's own predicted duration (`None` if unsampled);
    /// `elapsed` is the actual duration.
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
        // unsampled -> neutral 1.0, so failures alone can't declare congestion
        state.ratio_sum += ratio.map_or(1.0, |r| r.min(FAILURE_RATIO));
        if state.completions < state.window() {
            return 0;
        }

        let old = state.limit;
        let congested = state.ratio_sum / state.completions as f64 > CONGESTION_THRESHOLD;
        state.completions = 0;
        state.ratio_sum = 0.0;

        if congested {
            state.clean_run = 0;
            state.strikes += 1;
            if state.strikes < CONGEST_CONFIRM {
                return 0;
            }
            state.strikes = 0;
            state.ssthresh = (old * 3 / 4).max(state.floor);
            state.limit = (old / 2).max(state.floor);
            state.skip = old * state.scale;
        } else {
            state.strikes = 0;
            if state.limit < state.ssthresh {
                state.limit = (state.limit * 2).min(state.ssthresh);
            } else {
                // sustained clean operation: re-probe upward in case the pipe
                // opened up since the back-off, so growth goes multiplicative again
                state.clean_run += 1;
                if state.clean_run >= REPROBE_AFTER && state.ssthresh < state.cap {
                    state.clean_run = 0;
                    state.ssthresh = (state.ssthresh * 2).min(state.cap);
                }
                state.limit = (state.limit + 1).min(state.cap);
            }
        }

        let delta = state.limit as isize - old as isize;
        if delta != 0 {
            debug!(
                "AIMD limit {old} -> {} ({delta:+}) ss={}",
                state.limit, state.ssthresh
            );
        }
        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    /// Drives `n` successful completions at the given pace ratio (`None` = the
    /// host has no baseline yet), synthesizing ratio `r` as an `r`-second
    /// transfer against a 1-second baseline.
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

    fn window(c: &InflightController, scale: usize) -> usize {
        (c.limit() * scale).max(MIN_WINDOW)
    }

    #[sia_core_derive::cross_target_test]
    fn test_slow_start_doubles_until_cap() {
        let c = InflightController::new(8, 2, 100, 1);
        assert_eq!(c.limit(), 8);
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 16, "clean window doubles");
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 32);
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 64);
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 100, "doubling clamps at the cap");
    }

    #[sia_core_derive::cross_target_test]
    fn test_slow_start_window_ignores_scale() {
        let c = InflightController::new(8, 1, 100, 10);
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(
            c.limit(),
            16,
            "slow-start probe stays MIN_WINDOW under fan-out"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_transient_congestion_holds_then_resumes() {
        let c = InflightController::new(8, 2, 100, 1);
        drive(&c, MIN_WINDOW, Some(2.0));
        assert_eq!(c.limit(), 8, "a single congested window holds the limit");
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 16, "a clean window clears the strike and grows");
    }

    #[sia_core_derive::cross_target_test]
    fn test_sustained_congestion_backs_off() {
        let c = InflightController::new(16, 2, 100, 1);
        drive(&c, MIN_WINDOW, Some(2.0));
        assert_eq!(c.limit(), 16);
        drive(&c, MIN_WINDOW, Some(2.0));
        assert_eq!(c.limit(), 8, "confirmed congestion halves the limit");
    }

    #[sia_core_derive::cross_target_test]
    fn test_fast_recovery_reprobes_to_ssthresh() {
        let c = InflightController::new(64, 1, 1000, 1);
        drive(&c, MIN_WINDOW, Some(2.0));
        drive(&c, MIN_WINDOW, Some(2.0)); // back off: 64 -> ss=48, limit=32, skip=64
        assert_eq!(c.limit(), 32);
        drive(&c, 64, Some(1.0)); // drain the stale cohort
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(c.limit(), 48, "recovery doubles back to the knee, not +1");
        drive(&c, window(&c, 1), Some(1.0));
        assert_eq!(c.limit(), 49, "at/above the knee it probes additively");
    }

    #[sia_core_derive::cross_target_test]
    fn test_reprobe_raises_ssthresh_when_clear() {
        // after a back-off pins ssthresh low, sustained clean additive windows
        // re-probe upward so growth goes multiplicative again
        let c = InflightController::new(64, 1, 10_000, 1);
        drive(&c, MIN_WINDOW, Some(2.0));
        drive(&c, MIN_WINDOW, Some(2.0)); // back off: 64 -> ss=48, limit=32, skip=64
        drive(&c, 64, Some(1.0)); // drain the stale cohort
        drive(&c, MIN_WINDOW, Some(1.0)); // recovery doubles 32 -> ss 48
        assert_eq!(c.limit(), 48);
        // REPROBE_AFTER clean additive windows bump ssthresh (48 -> 96)
        for _ in 0..REPROBE_AFTER {
            drive(&c, window(&c, 1), Some(1.0));
        }
        let before = c.limit();
        drive(&c, MIN_WINDOW, Some(1.0));
        assert!(
            c.limit() > before + 1,
            "re-probe resumed multiplicative growth, got {} from {before}",
            c.limit()
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_back_off_skip_scales_with_fanout() {
        let c = InflightController::new(16, 1, 100, 10);
        drive(&c, MIN_WINDOW, Some(2.0));
        drive(&c, MIN_WINDOW, Some(2.0));
        assert_eq!(c.limit(), 8);
        drive(&c, 160, Some(3.0)); // cohort = old_limit * scale = 160
        assert_eq!(c.limit(), 8, "scaled cohort must not back off again");
        drive(&c, MIN_WINDOW, Some(1.0));
        assert_eq!(
            c.limit(),
            12,
            "clean window after the cohort drains re-probes"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_steady_window_capped() {
        // at a high limit the steady window is capped at MAX_WINDOW instead of
        // limit*scale, so the controller keeps evaluating instead of going open-loop
        let c = InflightController::new(256, 1, 10_000, 10);
        drive(&c, MIN_WINDOW, Some(2.0));
        drive(&c, MIN_WINDOW, Some(2.0)); // back off: 256 -> ss=192, limit=128, skip=2560
        assert_eq!(c.limit(), 128);
        drive(&c, 2560, Some(1.0)); // drain skip (old 256 * scale 10)
        drive(&c, MIN_WINDOW, Some(1.0)); // recovery doubles 128 -> ss 192
        assert_eq!(c.limit(), 192);
        drive(&c, MAX_WINDOW - 1, Some(1.0));
        assert_eq!(c.limit(), 192, "one short of the capped window holds");
        drive(&c, 1, Some(1.0));
        assert_eq!(
            c.limit(),
            193,
            "decision closes at MAX_WINDOW, not limit*scale"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_back_off_clamps_at_floor() {
        let c = InflightController::new(4, 2, 100, 1);
        drive(&c, 4096, Some(3.0));
        assert_eq!(c.limit(), 2, "back-off never goes below the floor");
    }

    #[sia_core_derive::cross_target_test]
    fn test_minority_of_bad_hosts_cannot_back_off() {
        // mean = (4*3.0 + 12*1.0) / 16 = 1.5, not above threshold
        let c = InflightController::new(8, 2, 100, 1);
        fail(&c, 4);
        drive(&c, 12, Some(1.0));
        assert_eq!(c.limit(), 16, "minority slow samples must not back off");
    }

    #[sia_core_derive::cross_target_test]
    fn test_min_window_protects_small_limits() {
        // mean = (3*3.0 + 13*1.0) / 16 ≈ 1.4, below threshold
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
        // mean = (2*3.0 + 14*1.0) / 16 = 1.25, below threshold
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
        let c = InflightController::new(4, 2, 100, 1);
        drive(&c, MIN_WINDOW, None);
        assert_eq!(c.limit(), 8, "baseline-free window grows");
    }

    #[sia_core_derive::cross_target_test]
    fn test_sample_cap_bounds_outliers() {
        // one 1000x outlier capped to FAILURE_RATIO: (3.0 + 15*1.0) / 16 < threshold
        let c = InflightController::new(8, 2, 100, 1);
        drive(&c, 1, Some(1_000.0));
        drive(&c, 15, Some(1.0));
        assert_eq!(c.limit(), 16, "capped outlier must not back off");
    }

    #[sia_core_derive::cross_target_test]
    fn test_initial_clamped_to_bounds() {
        assert_eq!(InflightController::new(8, 2, 4, 1).limit(), 4);
        assert_eq!(InflightController::new(1, 2, 100, 1).limit(), 2);
        assert_eq!(
            InflightController::new(8, 2, 1, 1).limit(),
            1,
            "cap below floor: cap wins"
        );
    }
}
