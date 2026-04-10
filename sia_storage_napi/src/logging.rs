use std::sync::{Mutex, Once};

use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;

static LOGGER: Mutex<Option<ThreadsafeFunction<String, ErrorStrategy::Fatal>>> = Mutex::new(None);
static LOGGER_SET: Once = Once::new();

static FORWARDER: ForwardLogger = ForwardLogger;

struct ForwardLogger;

impl log::Log for ForwardLogger {
    fn enabled(&self, meta: &log::Metadata) -> bool {
        for target in ["indexd", "app_client", "sia_storage_napi"] {
            if meta.target().contains(target) {
                return true;
            }
        }
        false
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if let Some(logger) = { LOGGER.lock().unwrap().clone() } {
            let msg = format!("[{}] {}", record.level(), record.args());
            logger.call(msg, ThreadsafeFunctionCallMode::NonBlocking);
        }
    }

    fn flush(&self) {}
}

/// Sets a logging callback to receive log messages from the SDK.
///
/// The callback receives formatted log messages as strings.
/// `level` should be one of: "error", "warn", "info", "debug", "trace".
#[napi]
pub fn set_logger(callback: ThreadsafeFunction<String, ErrorStrategy::Fatal>, level: String) {
    LOGGER_SET.call_once(|| {
        log::set_logger(&FORWARDER).unwrap();
    });
    LOGGER.lock().unwrap().replace(callback);
    if let Ok(level) = level.parse::<log::LevelFilter>() {
        log::set_max_level(level);
    }
}
