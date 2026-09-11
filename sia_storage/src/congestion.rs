use std::collections::VecDeque;
use std::sync::Mutex;

use log::debug;
use sia_core::signing::PublicKey;

use crate::time::Duration;

/// Completions per decision while probing. The steady window scales with the
/// limit, clamped, so the goodput estimate stays stable without going open-loop.
const MIN_WINDOW: usize = 16;
const MAX_WINDOW: usize = 1024;
/// While probing, keep climbing unless goodput *drops* by more than this. Per
/// step the measurement is noisier than the gain being looked for, so requiring
/// a gain stalls the climb early.
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
/// Factor to climb by per step.
const CLIMB: usize = 2;
/// Outstanding timeout strikes before backing off. One is just a bad host; this
/// many different peers is the pipeline. Strikes decay as windows finish, so
/// reaching this takes timeouts arriving faster than they are worked off.
const TIMEOUT_STRIKES: usize = 8;

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
    /// Hosts holding a timeout strike, oldest first. One entry per host, so an
    /// unreachable peer cannot spend them all.
    timeout_hosts: VecDeque<PublicKey>,
}

impl State {
    fn window(&self) -> usize {
        if self.probing {
            MIN_WINDOW
        } else {
            (self.limit * self.scale).clamp(MIN_WINDOW, MAX_WINDOW)
        }
    }

    /// Ages out half the timeout strikes. Rounded up so the last one clears.
    fn decay_timeouts(&mut self) {
        let drop = self.timeout_hosts.len().div_ceil(2);
        self.timeout_hosts.drain(..drop);
    }

    /// Halves the limit and probes upward again from there.
    fn back_off(&mut self, old: usize) {
        self.limit = (old / 2).max(self.floor);
        self.strikes = 0;
        self.probing = true;
        self.prev_goodput = 0.0;
        self.steady_run = 0;
    }

    /// Backs off and stays there, for a window that gave no goodput to judge.
    /// `back_off` alone leaves no baseline, which reads as "climb".
    fn settle_back(&mut self, old: usize) -> isize {
        self.back_off(old);
        self.probing = false;
        self.apply_limit(old, 0.0)
    }

    /// Commits the new limit, superseding in-flight samples if it moved.
    fn apply_limit(&mut self, old: usize, goodput: f64) -> isize {
        self.prev_limit = old;
        let delta = self.limit as isize - old as isize;
        if delta != 0 {
            // `generation` discards old-limit samples still in flight; this
            // drops those already counted.
            self.completions = 0;
            self.successes = 0;
            self.elapsed_sum = 0.0;
            self.timeout_hosts.clear();
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
                timeout_hosts: VecDeque::new(),
            }),
        }
    }

    pub(crate) fn limit(&self) -> usize {
        self.state.lock().unwrap().limit
    }

    pub(crate) fn cap(&self) -> usize {
        self.state.lock().unwrap().cap
    }

    /// Reports that an operation hit its deadline. A read that could not move in
    /// 60s is evidence goodput cannot give: on a saturated link the measurement
    /// reads flat, which [`RISE_MARGIN`] treats as permission to climb.
    ///
    /// `permit` is the token from [`Self::sample`] at dispatch, so the cohort
    /// stranded by a back-off cannot drive another one. Repeats from one `host`
    /// count once: an unreachable peer says nothing about the pipeline.
    pub(crate) fn record_timeout(&self, permit: SamplePermit, host: PublicKey) {
        let mut state = self.state.lock().unwrap();
        if permit.generation != state.generation || state.limit <= state.floor {
            return;
        }
        if !state.timeout_hosts.contains(&host) {
            state.timeout_hosts.push_back(host);
        }
        if state.timeout_hosts.len() < TIMEOUT_STRIKES {
            return;
        }
        let old = state.limit;
        state.settle_back(old);
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
            return state.settle_back(old);
        }

        // Decay timeouts once per window if the window made some progress.
        state.decay_timeouts();

        if window_elapsed <= 0.0 {
            // too fast to measure
            return 0;
        }

        // throughput ≈ inflight / latency
        let goodput = successes as f64 * old as f64 / window_elapsed;

        let adverse = state.prev_goodput > 0.0 && {
            if state.probing {
                // climb until a step makes throughput worse
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

        let climbed = (old * CLIMB).min(state.cap);
        if !adverse && state.probing {
            // no baseline yet, or not yet hurting: climb
            state.limit = climbed;
            state.prev_goodput = goodput;
        } else if !adverse {
            // settled and healthy
            state.goodput_ema = if state.prev_goodput > 0.0 {
                EMA_ALPHA * goodput + (1.0 - EMA_ALPHA) * state.goodput_ema
            } else {
                // no baseline: the EMA still describes the limit backed off from
                goodput
            };
            state.steady_run += 1;
            // periodically probe upward in case capacity has freed up
            if state.steady_run >= PROBE_INTERVAL && old < state.cap {
                state.steady_run = 0;
                state.probing = true;
                state.limit = climbed;
            }
            state.prev_goodput = goodput;
        } else if state.probing {
            // the last step cost throughput: settle below it
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

    fn host(i: usize) -> PublicKey {
        PublicKey::new([i as u8; 32])
    }

    /// Enough distinct hosts timing out to count as congestion.
    fn timeouts(c: &InflightController) {
        for i in 0..TIMEOUT_STRIKES {
            c.record_timeout(c.sample(), host(i));
        }
    }

    /// Drives the limit to the ceiling on a link that saturates at `sat`.
    fn climb_to_cap(c: &InflightController, sat: usize) -> usize {
        for _ in 0..20 {
            step_saturating(c, sat, 1.0);
            if c.limit() == c.cap() {
                break;
            }
        }
        c.limit()
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
    fn test_timeout_backs_off_without_a_window() {
        let c = InflightController::new(8, 2, 1000, 1);
        let settled = climb_to_cap(&c, 64);

        // too few hosts is not congestion
        let permit = c.sample();
        for i in 0..TIMEOUT_STRIKES - 1 {
            c.record_timeout(permit, host(i));
        }
        assert_eq!(c.limit(), settled, "backed off before the evidence was in");

        // enough of them is, and no window has to fill first
        c.record_timeout(permit, host(TIMEOUT_STRIKES - 1));
        assert_eq!(c.limit(), settled / 2);

        // the cohort stranded by that back-off must not drive another
        for i in 0..100 {
            c.record_timeout(permit, host(i));
        }
        assert_eq!(c.limit(), settled / 2, "stranded cohort backed off again");

        // but reads dispatched since are fresh evidence, at the same limit
        timeouts(&c);
        assert_eq!(
            c.limit(),
            settled / 4,
            "congestion at a settled limit must still bite"
        );
    }

    // A timeout back-off must not leave the controller bootstrapping.
    #[sia_core_derive::cross_target_test]
    fn test_timeout_settles_instead_of_reprobing() {
        let c = InflightController::new(8, 2, 1000, 1);
        let settled = climb_to_cap(&c, 64);
        timeouts(&c);
        let after = c.limit();

        // one healthy window is not enough to send it back up
        let window = |c: &InflightController| {
            let n = c.state.lock().unwrap().window();
            for _ in 0..n {
                c.record(c.sample(), Duration::from_secs(1), true);
            }
        };
        window(&c);
        assert_eq!(c.limit(), after, "must not climb on the very next window");

        // but PROBE_INTERVAL of them is
        for _ in 0..PROBE_INTERVAL {
            window(&c);
        }
        assert!(
            c.limit() > after,
            "should probe again once settled and healthy"
        );
        assert!(settled > after);
    }

    #[sia_core_derive::cross_target_test]
    fn test_timeout_back_off_starts_a_fresh_window() {
        let c = InflightController::new(8, 2, 1000, 1);
        climb_to_cap(&c, 64);

        // a partial window, measured at the deep limit
        for _ in 0..8 {
            c.record(c.sample(), Duration::from_secs(10), true);
        }
        assert!(c.state.lock().unwrap().completions > 0);

        // averaging these into the window that judges the new limit would mix
        // two regimes
        timeouts(&c);
        let state = c.state.lock().unwrap();
        assert_eq!(state.completions, 0, "stale completions carried over");
        assert_eq!(state.successes, 0, "stale successes carried over");
        assert_eq!(state.elapsed_sum, 0.0, "stale latency carried over");
    }

    // One unreachable peer strands a read per chunk, so its timeouts arrive in
    // bulk. That is a bad host, not a saturated pipeline.
    #[sia_core_derive::cross_target_test]
    fn test_one_bad_host_is_not_congestion() {
        let c = InflightController::new(8, 2, 1000, 1);
        let settled = climb_to_cap(&c, 64);

        let permit = c.sample();
        for _ in 0..TIMEOUT_STRIKES * 4 {
            c.record_timeout(permit, host(1));
        }
        assert_eq!(
            c.limit(),
            settled,
            "one unreachable peer backed off the pipeline"
        );
    }

    // A window deciding does not mean the timeouts stopped, so strikes decay
    // rather than clear.
    #[sia_core_derive::cross_target_test]
    fn test_sustained_timeouts_outrun_the_decay() {
        let c = InflightController::new(64, 2, 64, 1);

        let mut h = 0;
        for _ in 0..4 {
            // just under the threshold, so only the decay decides
            for _ in 0..TIMEOUT_STRIKES - 1 {
                c.record_timeout(c.sample(), host(h));
                h += 1;
            }
            if c.limit() < 64 {
                return;
            }
            let n = c.state.lock().unwrap().window();
            for _ in 0..n {
                c.record(c.sample(), Duration::from_secs(1), true);
            }
        }
        panic!("sustained timeouts never backed the limit off");
    }

    // Settling leaves no baseline, but the EMA still describes the old, higher
    // limit. Blending into it reads as a decline and backs off again.
    #[sia_core_derive::cross_target_test]
    fn test_settling_does_not_cascade() {
        let c = InflightController::new(8, 2, 1000, 1);
        climb_to_cap(&c, 64);

        // settled: the EMA describes the throughput at this limit
        {
            let mut state = c.state.lock().unwrap();
            state.probing = false;
            state.goodput_ema = state.limit as f64;
            state.prev_goodput = state.limit as f64;
        }

        timeouts(&c);
        let after = c.limit();

        // healthy windows at the new limit, where goodput is honestly lower
        let mut lowest = after;
        for _ in 0..6 {
            lowest = lowest.min(step(&c, 1.0));
        }
        assert!(lowest >= after, "cascaded from {after} down to {lowest}");
    }

    // Pinned at the cap the limit never moves, so nothing else resets the
    // strikes: a lifetime tally would halve a healthy download on strays alone.
    #[sia_core_derive::cross_target_test]
    fn test_timeouts_do_not_accumulate_across_healthy_windows() {
        let c = InflightController::new(64, 2, 64, 1);

        for i in 0..TIMEOUT_STRIKES * 4 {
            c.record_timeout(c.sample(), host(i));
            // checked every iteration: a back-off climbs back to the cap
            // within a few windows, so the final limit alone would hide it
            assert_eq!(
                c.limit(),
                64,
                "stray timeouts halved a healthy pipeline after {} of them",
                i + 1
            );
            // a full window of healthy work in between
            let n = c.state.lock().unwrap().window();
            for _ in 0..n {
                c.record(c.sample(), Duration::from_secs(1), true);
            }
        }
    }

    #[sia_core_derive::cross_target_test]
    fn test_timeout_does_not_go_below_the_floor() {
        let c = InflightController::new(8, 4, 1000, 1);
        for _ in 0..20 {
            timeouts(&c);
            step_saturating(&c, 1, 1.0);
        }
        assert!(c.limit() >= 4, "floor holds, got {}", c.limit());
    }

    // Saturation reads as flat goodput, which is not a reason to stop.
    #[sia_core_derive::cross_target_test]
    fn test_climbs_through_saturation() {
        let c = InflightController::new(8, 2, 1000, 1);
        assert_eq!(
            climb_to_cap(&c, 64),
            1000,
            "flat goodput is not a reason to stop"
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
        let mut trace = vec![climb_to_cap(&c, 64)];
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
        let settled = climb_to_cap(&c, 64);

        let window = c.state.lock().unwrap().window();
        for _ in 0..window {
            c.record(c.sample(), Duration::from_secs(1), false);
        }
        let after = c.limit();
        assert_eq!(after, settled / 2, "one bad window halves the limit");

        // settled, so it must not double straight back. Same latency model as
        // `step_saturating`, or the baseline it leaves reads as a decline.
        let (window, secs) = {
            let state = c.state.lock().unwrap();
            (state.window(), (state.limit as f64 / 64.0).max(1.0))
        };
        for _ in 0..window {
            c.record(c.sample(), Duration::from_secs_f64(secs), true);
        }
        assert_eq!(c.limit(), after, "climbed back on the very next window");

        assert!(
            step_saturating(&c, 64, 1.0) > after,
            "should climb again once operations succeed"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_steady_holds_through_high_latency() {
        let c = InflightController::new(8, 2, 1000, 1);
        let settled = climb_to_cap(&c, 64);
        let mut min_limit = settled;
        for _ in 0..10 {
            min_limit = min_limit.min(step_saturating(&c, 64, 1.0));
        }
        assert!(
            min_limit >= settled,
            "high latency at flat goodput must not back off, got {min_limit}"
        );
    }

    // After backing off, healthy work has to be able to win the depth back.
    #[sia_core_derive::cross_target_test]
    fn test_climbs_again_after_backing_off() {
        let c = InflightController::new(8, 2, 1000, 1);
        let settled = climb_to_cap(&c, 64);
        let backed_off = step(&c, settled as f64 / 64.0 * 4.0);
        assert!(backed_off < settled);

        step_saturating(&c, 64, 1.0);
        assert!(
            c.limit() > backed_off,
            "should climb again once goodput returns, stuck at {backed_off}"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_backs_off_on_goodput_decline() {
        let c = InflightController::new(8, 2, 1000, 1);
        let settled = climb_to_cap(&c, 64);
        // four times the latency it saturated at, so goodput quarters
        let saturated = settled as f64 / 64.0;
        let after = step(&c, saturated * 4.0);
        assert!(
            after < settled,
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
