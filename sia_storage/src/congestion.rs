use std::sync::Mutex;

use log::debug;

use crate::time::Duration;

/// Completions per decision while probing. The steady window scales with the
/// limit, clamped, so the goodput estimate stays stable without going open-loop.
const MIN_WINDOW: usize = 16;
const MAX_WINDOW: usize = 1024;
/// While probing, keep climbing unless goodput *drops* by more than this.
///
/// Demanding a positive gain per step stalls the climb: throughput per step is
/// measured with far more noise than the gain being looked for, so a step that
/// paid off often looks like one that didn't. Flat goodput means the step was
/// harmless, and harmless steps are worth keeping — the depth only needs to
/// stop where throughput actually degrades.
const RISE_MARGIN: f64 = -0.1;
/// In steady state, goodput must fall more than this below its smoothed peak to
/// count as real congestion and trigger a back-off.
const DECLINE_MARGIN: f64 = 0.25;
/// Smoothing factor for the steady-state goodput baseline.
const EMA_ALPHA: f64 = 0.2;
/// Consecutive adverse windows required before acting, so one noisy window can
/// neither settle the limit low nor back it off.
const CONFIRM: usize = 2;
/// Healthy steady windows between upward probes, so a settled limit climbs again
/// when capacity frees up (e.g. a concurrent transfer finishes).
const PROBE_INTERVAL: usize = 8;
/// Factor to climb by per step. Four rather than two so a download reaches a
/// deep working point within its own lifetime.
const CLIMB: usize = 4;

/// Generation-stamped token: taken at dispatch via [`InflightController::sample`]
/// and returned to [`InflightController::record`]. A completion stamped with a
/// superseded generation was dispatched under an old limit and is discarded.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SamplePermit {
    generation: u64,
}

#[derive(Debug)]
struct State {
    limit: usize,
    floor: usize,
    cap: usize,
    scale: usize,
    /// Doubling while goodput climbs; holds once a doubling stops raising it.
    probing: bool,
    completions: usize,
    successes: usize,
    elapsed_sum: f64,
    /// Goodput of the previous decided window, or 0 for no baseline yet
    /// (bootstrap / re-probe). A decided window has a success, so it is never 0.
    prev_goodput: f64,
    prev_limit: usize,
    goodput_ema: f64,
    strikes: usize,
    steady_run: usize,
    /// Bumped on every limit change; stamps in-flight samples so a completion
    /// from a superseded limit is discarded.
    generation: u64,
}

impl State {
    fn window(&self) -> usize {
        if self.probing {
            MIN_WINDOW
        } else {
            (self.limit * self.scale).clamp(MIN_WINDOW, MAX_WINDOW)
        }
    }

    /// Halves the limit and probes upward again from there.
    fn back_off(&mut self, old: usize) {
        self.limit = (old / 2).max(self.floor);
        self.strikes = 0;
        self.probing = true;
        self.prev_goodput = 0.0;
        self.steady_run = 0;
    }

    /// Commits the new limit, superseding in-flight samples if it moved.
    fn apply_limit(&mut self, old: usize, goodput: f64) -> isize {
        self.prev_limit = old;
        let delta = self.limit as isize - old as isize;
        if delta != 0 {
            self.generation += 1;
            debug!(
                "AIMD limit {old} -> {} ({delta:+}) goodput {goodput:.0}",
                self.limit
            );
        }
        delta
    }
}

/// Controller for a pipeline's inflight limit. The signal is goodput estimated
/// via Little's law (`successes * limit / Σ latency`). The limit doubles while
/// raising it raises goodput and backs off only when it declines.
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
                probing: true,
                completions: 0,
                successes: 0,
                elapsed_sum: 0.0,
                prev_goodput: 0.0,
                prev_limit: limit,
                goodput_ema: 0.0,
                strikes: 0,
                steady_run: 0,
                generation: 0,
            }),
        }
    }

    pub(crate) fn limit(&self) -> usize {
        self.state.lock().unwrap().limit
    }

    pub(crate) fn cap(&self) -> usize {
        self.state.lock().unwrap().cap
    }

    /// Issues a permit stamped with the current generation. Take one at dispatch
    /// and hand it back to [`Self::record`] on completion.
    pub(crate) fn sample(&self) -> SamplePermit {
        SamplePermit {
            generation: self.state.lock().unwrap().generation,
        }
    }

    /// Records a completed operation and returns the change to the limit.
    /// `permit` is the token from [`Self::sample`] at dispatch. A completion
    /// from a superseded limit is discarded.
    pub(crate) fn record(&self, permit: SamplePermit, elapsed: Duration, ok: bool) -> isize {
        let mut state = self.state.lock().unwrap();
        if permit.generation != state.generation {
            return 0;
        }
        state.completions += 1;
        if ok {
            state.successes += 1;
        }
        state.elapsed_sum += elapsed.as_secs_f64();
        if state.completions < state.window() {
            return 0;
        }

        let old = state.limit;
        let (successes, window_elapsed) = (state.successes, state.elapsed_sum);
        state.completions = 0;
        state.successes = 0;
        state.elapsed_sum = 0.0;

        // Nothing succeeded: back off without waiting out the strikes. Must come
        // before the baseline below, which reads a stored 0 as "no baseline" and climbs.
        if successes == 0 {
            state.back_off(old);
            return state.apply_limit(old, 0.0);
        }
        if window_elapsed <= 0.0 {
            // too fast to measure
            return 0;
        }

        // throughput ≈ inflight / latency
        let goodput = successes as f64 * old as f64 / window_elapsed;

        let adverse = state.prev_goodput > 0.0 && {
            if state.probing {
                // each doubling has to keep paying off
                goodput < state.prev_goodput * (1.0 + RISE_MARGIN)
            } else {
                // once settled, only a drop at an unchanged limit counts
                old == state.prev_limit && goodput < state.goodput_ema * (1.0 - DECLINE_MARGIN)
            }
        };

        if adverse && state.strikes + 1 < CONFIRM {
            state.strikes += 1;
            return 0;
        }
        state.strikes = 0;

        let doubled = (old * CLIMB).min(state.cap);
        if !adverse && state.probing {
            // no baseline yet, or still paying off: climb
            state.limit = doubled;
            state.prev_goodput = goodput;
        } else if !adverse {
            // settled and healthy
            state.goodput_ema = EMA_ALPHA * goodput + (1.0 - EMA_ALPHA) * state.goodput_ema;
            state.steady_run += 1;
            // periodically probe upward in case capacity has freed up
            if state.steady_run >= PROBE_INTERVAL && old < state.cap {
                state.steady_run = 0;
                state.probing = true;
                state.limit = doubled;
            }
            state.prev_goodput = goodput;
        } else if state.probing {
            // the last doubling did not pay off: settle below it
            state.limit = state.prev_limit.clamp(state.floor, state.cap);
            state.probing = false;
            state.goodput_ema = goodput;
            state.prev_goodput = goodput;
            state.steady_run = 0;
        } else {
            // sustained decline at a settled limit
            state.back_off(old);
        }
        state.apply_limit(old, goodput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(c: &InflightController, secs: f64) -> usize {
        let start = c.limit();
        let mut n = 0;
        while c.limit() == start && n < 100_000 {
            c.record(c.sample(), Duration::from_secs_f64(secs), true);
            n += 1;
        }
        c.limit()
    }

    /// Latency flat below `sat`, growing ∝ limit above it, so goodput plateaus at `sat`.
    fn step_saturating(c: &InflightController, sat: usize, base: f64) -> usize {
        let secs = base * (c.limit() as f64 / sat as f64).max(1.0);
        step(c, secs)
    }

    #[sia_core_derive::cross_target_test]
    fn test_climbs_while_goodput_rises() {
        let c = InflightController::new(8, 2, 1000, 1);
        assert_eq!(step(&c, 1.0), 16);
        assert_eq!(step(&c, 1.0), 32);
        assert_eq!(step(&c, 1.0), 64);
        assert_eq!(step(&c, 1.0), 128);
    }

    #[sia_core_derive::cross_target_test]
    fn test_settles_at_saturation() {
        let c = InflightController::new(8, 2, 1000, 1);
        assert_eq!(step_saturating(&c, 64, 1.0), 16);
        assert_eq!(step_saturating(&c, 64, 1.0), 32);
        assert_eq!(step_saturating(&c, 64, 1.0), 64);
        assert_eq!(
            step_saturating(&c, 64, 1.0),
            128,
            "probes one step past saturation"
        );
        assert_eq!(
            step_saturating(&c, 64, 1.0),
            64,
            "settles at the last climbing level"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_all_failures_back_off() {
        // with no baseline yet
        let c = InflightController::new(8, 2, 1000, 1);
        let mut trace = vec![c.limit()];
        for _ in 0..10 {
            for _ in 0..MIN_WINDOW {
                c.record(c.sample(), Duration::from_secs(1), false);
            }
            trace.push(c.limit());
        }
        assert!(
            trace.windows(2).all(|w| w[1] <= w[0]),
            "limit must never climb while everything fails: {trace:?}"
        );
        assert_eq!(c.limit(), 2, "should reach the floor: {trace:?}");

        // and from a settled, healthy limit
        let c = InflightController::new(8, 2, 1000, 1);
        for _ in 0..5 {
            step_saturating(&c, 64, 1.0);
        }
        assert_eq!(c.limit(), 64);
        let mut trace = vec![c.limit()];
        for _ in 0..10 {
            let window = c.state.lock().unwrap().window();
            for _ in 0..window {
                c.record(c.sample(), Duration::from_secs(1), false);
            }
            trace.push(c.limit());
        }
        assert!(
            trace.windows(2).all(|w| w[1] <= w[0]),
            "limit must never climb while everything fails: {trace:?}"
        );
        assert_eq!(c.limit(), 2, "should reach the floor: {trace:?}");
    }

    #[sia_core_derive::cross_target_test]
    fn test_recovers_after_a_failing_window() {
        let c = InflightController::new(8, 2, 1000, 1);
        for _ in 0..5 {
            step_saturating(&c, 64, 1.0);
        }
        assert_eq!(c.limit(), 64);

        // a settled controller samples a full `limit * scale` window
        let window = c.state.lock().unwrap().window();
        for _ in 0..window {
            c.record(c.sample(), Duration::from_secs(1), false);
        }
        assert_eq!(c.limit(), 32, "one bad window halves the limit");

        assert!(
            step(&c, 1.0) > 32,
            "should climb again once operations succeed"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_steady_holds_through_high_latency() {
        let c = InflightController::new(8, 2, 1000, 1);
        for _ in 0..5 {
            step_saturating(&c, 64, 1.0);
        }
        assert_eq!(c.limit(), 64);
        let mut min_limit = c.limit();
        for _ in 0..30 {
            min_limit = min_limit.min(step_saturating(&c, 64, 1.0));
        }
        assert!(
            min_limit >= 64,
            "must not back off below saturation, got {min_limit}"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_steady_probes_upward() {
        let c = InflightController::new(8, 2, 1000, 1);
        for _ in 0..5 {
            step_saturating(&c, 64, 1.0);
        }
        assert_eq!(c.limit(), 64);
        assert!(
            step(&c, 1.0) > 64,
            "steady state probes upward to reclaim capacity"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_backs_off_on_goodput_decline() {
        let c = InflightController::new(8, 2, 1000, 1);
        for _ in 0..5 {
            step_saturating(&c, 64, 1.0);
        }
        assert_eq!(c.limit(), 64);
        // latency 4x at the same limit -> goodput 1/4
        let after = step(&c, 4.0);
        assert!(
            after < 64,
            "a sustained goodput drop backs off, got {after}"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_failures_lower_goodput() {
        let c = InflightController::new(8, 2, 1000, 1);
        step(&c, 1.0);
        let start = c.limit();
        let mut backed_off = false;
        for _ in 0..(MIN_WINDOW * (CONFIRM + 1)) {
            c.record(c.sample(), Duration::from_secs(1), false);
            if c.limit() < start {
                backed_off = true;
                break;
            }
        }
        assert!(backed_off, "sustained failures must back off");
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
