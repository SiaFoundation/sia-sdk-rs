//! Platform compatibility layer for native and WASM targets.
//!
//! Import time types via `crate::time::` and task types via `crate::task::`.
//! Do not import from `std::time`, `tokio::time`, `web_time`, or
//! `tokio_util::task` directly in other modules.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(not(target_arch = "wasm32"))]
use tokio::task::{JoinError, JoinHandle, JoinSet};

#[cfg(target_arch = "wasm32")]
use futures_util::stream::FuturesUnordered;
#[cfg(target_arch = "wasm32")]
use futures_util::StreamExt;
#[cfg(target_arch = "wasm32")]
use tokio::sync::oneshot;

#[cfg(target_arch = "wasm32")]
mod wasm_time;

/// Unified time types for native and WASM targets.
pub mod time {
    pub use web_time::{Duration, Instant};

    #[cfg(not(target_arch = "wasm32"))]
    pub use tokio::time::{error::Elapsed, sleep, timeout};

    #[cfg(target_arch = "wasm32")]
    pub use super::wasm_time::{Elapsed, sleep, timeout};
}

/// Error from a spawned task. On native, wraps JoinError (task panicked or
/// was cancelled). On WASM, tasks run inline via FuturesUnordered and cannot
/// fail independently, so this error is never produced.
#[cfg(not(target_arch = "wasm32"))]
pub struct TaskError(JoinError);

#[cfg(target_arch = "wasm32")]
pub struct TaskError;

impl fmt::Display for TaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(not(target_arch = "wasm32"))]
        return self.0.fmt(f);
        #[cfg(target_arch = "wasm32")]
        write!(f, "task error (unreachable on WASM)")
    }
}

impl fmt::Debug for TaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(not(target_arch = "wasm32"))]
        return self.0.fmt(f);
        #[cfg(target_arch = "wasm32")]
        write!(f, "TaskError")
    }
}

impl std::error::Error for TaskError {}

#[cfg(not(target_arch = "wasm32"))]
impl From<JoinError> for TaskError {
    fn from(e: JoinError) -> Self {
        TaskError(e)
    }
}

/// Cross-platform concurrent task runner.
///
/// On native: wraps `tokio::task::JoinSet` (spawns tasks on the runtime).
/// On WASM: wraps `FuturesUnordered` (polls futures inline, no LocalSet
/// needed). This eliminates `run_local` which blocked the JS event loop
/// and prevented setTimeout-based timeouts from firing.
#[cfg(not(target_arch = "wasm32"))]
pub struct TaskSet<T>(JoinSet<T>);

#[cfg(target_arch = "wasm32")]
pub struct TaskSet<T>(FuturesUnordered<Pin<Box<dyn Future<Output = T>>>>);

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + 'static> TaskSet<T> {
    pub fn new() -> Self {
        Self(JoinSet::new())
    }

    pub fn spawn<F>(&mut self, fut: F)
    where
        F: Future<Output = T> + Send + 'static,
    {
        self.0.spawn(fut);
    }

    pub async fn join_next(&mut self) -> Option<Result<T, TaskError>> {
        self.0.join_next().await.map(|r| r.map_err(TaskError))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(target_arch = "wasm32")]
impl<T> TaskSet<T> {
    pub fn new() -> Self {
        Self(FuturesUnordered::new())
    }

    pub fn spawn<F>(&mut self, fut: F)
    where
        F: Future<Output = T> + 'static,
    {
        self.0.push(Box::pin(fut));
    }

    pub async fn join_next(&mut self) -> Option<Result<T, TaskError>> {
        self.0.next().await.map(Ok)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// A handle to a spawned background task that aborts on drop (native)
/// or discards the result (WASM). Awaiting yields the task's result.
#[cfg(not(target_arch = "wasm32"))]
pub struct AbortOnDropHandle<T>(JoinHandle<T>);

#[cfg(not(target_arch = "wasm32"))]
impl<T> Drop for AbortOnDropHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<T> AbortOnDropHandle<T> {
    pub fn new(handle: JoinHandle<T>) -> Self {
        Self(handle)
    }

    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<T> Future for AbortOnDropHandle<T> {
    type Output = Result<T, TaskError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|r| r.map_err(TaskError))
    }
}

#[cfg(target_arch = "wasm32")]
pub struct AbortOnDropHandle<T>(oneshot::Receiver<T>);

#[cfg(target_arch = "wasm32")]
impl<T> AbortOnDropHandle<T> {
    pub fn new(rx: oneshot::Receiver<T>) -> Self {
        Self(rx)
    }

    pub fn is_finished(&self) -> bool {
        // If the sender was dropped (task completed), the channel is closed.
        // oneshot::Receiver doesn't expose is_closed, so we can't check
        // without consuming. Conservatively return false.
        false
    }
}

#[cfg(target_arch = "wasm32")]
impl<T> Future for AbortOnDropHandle<T> {
    type Output = Result<T, TaskError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.0).poll(cx) {
            Poll::Ready(Ok(val)) => Poll::Ready(Ok(val)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(TaskError)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Unified task types for cross-platform use.
pub mod task {
    pub use super::{AbortOnDropHandle, TaskError, TaskSet};
}

/// Run a blocking computation on `spawn_blocking` on native, or inline on WASM.
/// Must be called from an async context. The expression must return a type that
/// implements `Send + 'static` on native.
///
/// ```ignore
/// let result = maybe_spawn_blocking!(expensive_computation())?;
/// ```
macro_rules! maybe_spawn_blocking {
    ($body:expr) => {{
        #[cfg(not(target_arch = "wasm32"))]
        {
            tokio::task::spawn_blocking(move || $body)
                .await
                .map_err(crate::compat::TaskError::from)?
        }
        #[cfg(target_arch = "wasm32")]
        {
            $body
        }
    }};
}

/// Spawn a future on a [`TaskSet`]. Uses `JoinSet::spawn` on native
/// (requires `Send`) and pushes to `FuturesUnordered` on WASM.
///
/// ```ignore
/// let mut set = TaskSet::new();
/// task_set_spawn!(set, async move { do_work().await });
/// ```
macro_rules! task_set_spawn {
    ($set:expr, $fut:expr) => {{
        $set.spawn($fut);
    }};
}

/// Spawn a future as a standalone task. Uses `tokio::spawn` on native
/// (requires `Send`) and `tokio::task::spawn_local` on WASM.
///
/// ```ignore
/// let handle = maybe_spawn!(async move { do_work().await });
/// ```
macro_rules! maybe_spawn {
    ($fut:expr) => {{
        #[cfg(not(target_arch = "wasm32"))]
        {
            tokio::spawn($fut)
        }
        #[cfg(target_arch = "wasm32")]
        {
            let (tx, rx) = tokio::sync::oneshot::channel();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = tx.send($fut.await);
            });
            rx
        }
    }};
}

/// Dual-target test macro. All test functions must be `async fn`.
/// Uses `#[tokio::test]` on native and `#[wasm_bindgen_test]` on WASM.
///
/// Can only be invoked once per scope (module) because it emits a
/// `use wasm_bindgen_test::*;` import.
#[cfg(test)]
macro_rules! cross_target_tests {
    ($($test_fn:item)*) => {
        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::*;

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_test_configure!(run_in_browser);

        $(
            #[cfg(target_arch = "wasm32")]
            #[wasm_bindgen_test]
            $test_fn

            #[cfg(not(target_arch = "wasm32"))]
            #[tokio::test]
            $test_fn
        )*
    };
}

/// Run an async block inside a `tokio::task::LocalSet` on WASM, or directly
/// on native. Assumes a tokio runtime is already active (e.g. inside
/// `#[tokio::main]`, `#[tokio::test]`, or after `Runtime::enter()`).
#[cfg(all(test, target_arch = "wasm32"))]
pub(crate) async fn run_local<F: Future>(f: F) -> F::Output {
    tokio::task::LocalSet::new().run_until(f).await
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) async fn run_local<F: Future>(f: F) -> F::Output {
    f.await
}
