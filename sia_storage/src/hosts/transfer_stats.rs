//! Aggregate throughput of the sector RPCs the SDK runs.
//!
//! Applications display an average transfer speed, which is a property of
//! the connection rather than of any one transfer: total bytes over the
//! time the connection was busy, counted once no matter how many RPCs were
//! sharing it. Summing per-RPC durations would multiply-count concurrency;
//! measuring wall clock end to end would let queueing and packing gaps drag
//! the number down.
//!
//! Per direction the tracker keeps a count of in-flight RPCs and the
//! instant the current busy stretch began. The stretch closes when the last
//! RPC of that direction finishes, so accumulated active time is the union
//! of the in-flight spans and not their sum. Nothing is reconstructed from
//! completion timestamps, so out-of-order completions and idle gaps both
//! fall out correctly.
//!
//! This is a different quantity from the moving averages in
//! [`super::metrics::RPCAverage`], which answer how fast a typical host is
//! and drive race timeouts. With twenty concurrent sector RPCs each moving
//! 1 MB/s, those averages read 1 MB/s while this reads 20 MB/s. Both are
//! wanted, for different questions.

use std::sync::{Arc, Mutex};

use crate::time::{Duration, Instant, sleep};

/// How often the suspension watcher wakes to check whether the process was
/// scheduled.
const SUSPENSION_INTERVAL: Duration = Duration::from_secs(1);

/// Lateness above which a gap is attributed to the process being frozen
/// rather than to scheduler jitter. Jitter is milliseconds; a freeze is
/// seconds, so the two separate cleanly anywhere in between.
const SUSPENSION_THRESHOLD: Duration = Duration::from_millis(500);

/// Cumulative transfer totals since the SDK was created. The counters only
/// grow, so sampling them periodically and dividing the deltas gives the
/// speed over any window.
///
/// The active durations include a stretch still in progress at the moment
/// of the read. Without that, a sustained transfer would report climbing
/// bytes against an active time frozen at whenever the last RPC briefly
/// drained, and read as absurdly fast.
///
/// Rate, smoothing, windowing and persistence are left to the caller. These
/// are measurements, not a display.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransferStats {
    /// Bytes written to hosts by RPCs that completed successfully.
    pub uploaded_bytes: u64,
    /// Time at least one upload RPC was in flight.
    pub upload_active: Duration,
    /// Bytes read from hosts by RPCs that completed successfully.
    pub downloaded_bytes: u64,
    /// Time at least one download RPC was in flight.
    pub download_active: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Upload,
    Download,
}

/// Counters for one direction. Every field is guarded by the tracker's
/// mutex; the instants come from the caller so a tick and a read agree on
/// what "now" is.
#[derive(Debug, Default)]
struct DirectionStats {
    inflight: usize,
    /// Start of the stretch currently being counted. `Some` exactly while
    /// `inflight` is non-zero.
    active_since: Option<Instant>,
    active: Duration,
    bytes: u64,
}

impl DirectionStats {
    fn enter(&mut self, now: Instant) {
        if self.inflight == 0 {
            self.active_since = Some(now);
        }
        self.inflight += 1;
    }

    fn exit(&mut self, now: Instant, bytes: u64) {
        self.bytes += bytes;
        self.inflight = self.inflight.saturating_sub(1);
        if self.inflight == 0
            && let Some(since) = self.active_since.take()
        {
            self.active += now.saturating_duration_since(since);
        }
    }

    fn totals(&self, now: Instant) -> (u64, Duration) {
        let open = self
            .active_since
            .map(|since| now.saturating_duration_since(since))
            .unwrap_or_default();
        (self.bytes, self.active + open)
    }

    /// Takes `drift` out of the stretch in progress by moving its start
    /// forward, so a span that covers a frozen stretch is credited only
    /// with the part the process was awake for.
    ///
    /// Moving the start is exact where subtracting from the accumulated
    /// total is not: the frozen stretch is usually inside a span that has
    /// not closed yet, so there is nothing accumulated to subtract from.
    fn discount(&mut self, drift: Duration, now: Instant) {
        let Some(since) = self.active_since else {
            return;
        };
        let shift = drift.min(now.saturating_duration_since(since));
        self.active_since = Some(since + shift);
    }
}

#[derive(Debug, Default)]
struct Inner {
    upload: DirectionStats,
    download: DirectionStats,
    /// Last moment the process is known to have been running, from either
    /// a watcher tick or a read. `None` until the watcher starts: without
    /// one, a long gap between reads is unexplained rather than evidence
    /// of a freeze.
    last_seen: Option<Instant>,
}

impl Inner {
    fn stats_mut(&mut self, direction: Direction) -> &mut DirectionStats {
        match direction {
            Direction::Upload => &mut self.upload,
            Direction::Download => &mut self.download,
        }
    }

    /// Takes any stretch since the last sign of life that the process was
    /// not scheduled for out of the spans in progress.
    fn check_suspension(&mut self, now: Instant) {
        let Some(last_seen) = self.last_seen.replace(now) else {
            return;
        };
        let drift = now
            .saturating_duration_since(last_seen)
            .saturating_sub(SUSPENSION_INTERVAL);
        if drift <= SUSPENSION_THRESHOLD {
            return;
        }
        self.upload.discount(drift, now);
        self.download.discount(drift, now);
    }
}

/// Shared handle to the counters. Cloning shares them, so every clone of
/// [`super::Hosts`] feeds one set of totals for the whole SDK.
#[derive(Clone, Default)]
pub(crate) struct TransferTracker(Arc<Mutex<Inner>>);

impl TransferTracker {
    /// Counts an upload RPC as in flight until the returned span is
    /// dropped.
    pub fn upload(&self) -> TransferSpan {
        self.span(Direction::Upload)
    }

    /// Counts a download RPC as in flight until the returned span is
    /// dropped.
    pub fn download(&self) -> TransferSpan {
        self.span(Direction::Download)
    }

    fn span(&self, direction: Direction) -> TransferSpan {
        self.0
            .lock()
            .unwrap()
            .stats_mut(direction)
            .enter(Instant::now());
        TransferSpan {
            tracker: self.clone(),
            direction,
            bytes: 0,
        }
    }

    /// Reads the totals, discounting any suspension the watcher has not
    /// caught yet. Doing that here as well as on the tick keeps the totals
    /// from stepping backwards: a caller polling in the second after a
    /// resume would otherwise see the frozen stretch as transfer time and
    /// then see it taken away.
    pub fn stats(&self) -> TransferStats {
        let now = Instant::now();
        let mut inner = self.0.lock().unwrap();
        inner.check_suspension(now);
        let (uploaded_bytes, upload_active) = inner.upload.totals(now);
        let (downloaded_bytes, download_active) = inner.download.totals(now);
        TransferStats {
            uploaded_bytes,
            upload_active,
            downloaded_bytes,
            download_active,
        }
    }

    /// Watches for stretches where the process was not scheduled and keeps
    /// them out of the active totals. Runs until dropped.
    ///
    /// A process can be frozen for seconds at a time while the machine
    /// stays awake and the clock keeps advancing: an operating system
    /// suspending a backgrounded application, a throttled container, a
    /// stopped debugger. A span open across one of those would count the
    /// whole stretch as time spent transferring. The watcher measures its
    /// own lateness to find them: a tick that arrives far later than its
    /// interval means nothing was scheduled in between, so no RPC made
    /// progress then either.
    ///
    /// A freeze that straddles the start or end of a span is off by at most
    /// one interval.
    ///
    /// The one thing this cannot resolve: a socket can keep filling kernel
    /// buffers while the process is frozen, so part of that stretch did
    /// move bytes. Discounting all of it charges those bytes to less time
    /// and reads slightly fast. That is the better default for a speed
    /// figure, because what limited the transfer then was the operating
    /// system rather than the connection.
    pub async fn watch_suspension(self) {
        self.0.lock().unwrap().last_seen = Some(Instant::now());
        loop {
            sleep(SUSPENSION_INTERVAL).await;
            let now = Instant::now();
            self.0.lock().unwrap().check_suspension(now);
        }
    }
}

/// Holds one sector RPC's slot in the in-flight count for as long as it is
/// alive. Releasing on drop rather than on return is what makes a raced or
/// timed-out RPC, whose future is dropped mid-await, still close its span.
pub(crate) struct TransferSpan {
    tracker: TransferTracker,
    direction: Direction,
    bytes: u64,
}

impl TransferSpan {
    /// Credits the bytes the RPC moved. Call it only on success: a failed
    /// or cancelled RPC occupied the connection, which the span counts
    /// either way, but landed no data.
    pub fn transferred(&mut self, bytes: u64) {
        self.bytes = bytes;
    }
}

impl Drop for TransferSpan {
    fn drop(&mut self) {
        let now = Instant::now();
        self.tracker
            .0
            .lock()
            .unwrap()
            .stats_mut(self.direction)
            .exit(now, self.bytes);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // The instants are supplied by the caller, so these tests lay spans out
    // on a timeline from a fixed origin rather than sleeping.

    #[sia_core_derive::cross_target_test]
    fn test_overlapping_rpcs_count_their_shared_time_once() {
        let t = Instant::now();
        let mut stats = DirectionStats::default();

        stats.enter(t);
        stats.enter(t + Duration::from_secs(1));
        stats.exit(t + Duration::from_secs(2), 4);
        stats.exit(t + Duration::from_secs(3), 4);

        let (bytes, active) = stats.totals(t + Duration::from_secs(5));
        assert_eq!(bytes, 8);
        assert_eq!(
            active,
            Duration::from_secs(3),
            "two RPCs spanning 3s together should count 3s, not the 4s they sum to"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_idle_time_between_rpcs_is_not_counted() {
        let t = Instant::now();
        let mut stats = DirectionStats::default();

        stats.enter(t);
        stats.exit(t + Duration::from_secs(1), 1);
        stats.enter(t + Duration::from_secs(3));
        stats.exit(t + Duration::from_secs(4), 1);

        let (_, active) = stats.totals(t + Duration::from_secs(4));
        assert_eq!(active, Duration::from_secs(2));
    }

    #[sia_core_derive::cross_target_test]
    fn test_totals_include_an_rpc_still_running() {
        let t = Instant::now();
        let mut stats = DirectionStats::default();

        stats.enter(t);

        let (bytes, active) = stats.totals(t + Duration::from_secs(2));
        assert_eq!(bytes, 0, "bytes are credited when the RPC completes");
        assert_eq!(active, Duration::from_secs(2));
    }

    #[sia_core_derive::cross_target_test]
    fn test_a_failed_rpc_counts_its_time_but_no_bytes() {
        let t = Instant::now();
        let mut stats = DirectionStats::default();

        stats.enter(t);
        stats.exit(t + Duration::from_secs(1), 0);

        let (bytes, active) = stats.totals(t + Duration::from_secs(1));
        assert_eq!(bytes, 0);
        assert_eq!(
            active,
            Duration::from_secs(1),
            "a failed RPC held the connection for a second"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_suspended_time_is_removed_from_the_running_rpc() {
        let t = Instant::now();
        let mut stats = DirectionStats::default();

        stats.enter(t);
        stats.discount(Duration::from_secs(3), t + Duration::from_secs(5));
        stats.exit(t + Duration::from_secs(5), 10);

        let (_, active) = stats.totals(t + Duration::from_secs(5));
        assert_eq!(
            active,
            Duration::from_secs(2),
            "5s span with 3s of it frozen leaves 2s of transfer"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_suspended_time_does_not_go_negative() {
        let t = Instant::now();
        let mut stats = DirectionStats::default();

        stats.enter(t);
        stats.exit(t + Duration::from_secs(10), 10);
        stats.enter(t + Duration::from_secs(20));
        stats.discount(Duration::from_secs(30), t + Duration::from_secs(21));

        let (_, active) = stats.totals(t + Duration::from_secs(21));
        assert_eq!(
            active,
            Duration::from_secs(10),
            "drift longer than the running RPC should not eat the earlier total"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_suspension_while_idle_changes_nothing() {
        let t = Instant::now();
        let mut stats = DirectionStats::default();

        stats.enter(t);
        stats.exit(t + Duration::from_secs(1), 5);
        stats.discount(Duration::from_secs(60), t + Duration::from_secs(61));

        let (bytes, active) = stats.totals(t + Duration::from_secs(61));
        assert_eq!(bytes, 5);
        assert_eq!(active, Duration::from_secs(1));
    }

    #[sia_core_derive::cross_target_test]
    fn test_a_freeze_is_discounted_before_the_watcher_next_ticks() {
        let t = Instant::now();
        let mut inner = Inner {
            last_seen: Some(t),
            ..Default::default()
        };

        inner.upload.enter(t);
        // A read a minute later, with nothing scheduled in between.
        inner.check_suspension(t + Duration::from_secs(60));

        let (_, active) = inner.upload.totals(t + Duration::from_secs(60));
        assert_eq!(
            active, SUSPENSION_INTERVAL,
            "all but one interval of the frozen minute should be discounted"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_scheduler_jitter_is_not_mistaken_for_a_freeze() {
        let t = Instant::now();
        let mut inner = Inner {
            last_seen: Some(t),
            ..Default::default()
        };

        inner.upload.enter(t);
        let late = SUSPENSION_INTERVAL + SUSPENSION_THRESHOLD;
        inner.check_suspension(t + late);

        let (_, active) = inner.upload.totals(t + late);
        assert_eq!(active, late, "a tick merely running late transferred data");
    }

    #[sia_core_derive::cross_target_test]
    fn test_a_gap_is_ignored_until_the_watcher_is_running() {
        let t = Instant::now();
        let mut inner = Inner::default();

        inner.upload.enter(t);
        inner.check_suspension(t + Duration::from_secs(60));

        let (_, active) = inner.upload.totals(t + Duration::from_secs(60));
        assert_eq!(
            active,
            Duration::from_secs(60),
            "with no watcher there is nothing to say the process was frozen"
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_uploads_and_downloads_are_tracked_separately() {
        let tracker = TransferTracker::default();
        {
            let mut span = tracker.upload();
            span.transferred(7);
        }
        let stats = tracker.stats();
        assert_eq!(stats.uploaded_bytes, 7);
        assert_eq!(stats.downloaded_bytes, 0);
        assert_eq!(stats.download_active, Duration::ZERO);
    }

    #[sia_core_derive::cross_target_test]
    fn test_dropping_a_span_without_bytes_closes_it() {
        let tracker = TransferTracker::default();
        drop(tracker.download());

        let stats = tracker.stats();
        assert_eq!(stats.downloaded_bytes, 0);
        let first = tracker.stats().download_active;
        let second = tracker.stats().download_active;
        assert_eq!(
            first, second,
            "a closed span should stop the active time from growing"
        );
    }
}
