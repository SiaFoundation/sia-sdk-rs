use std::sync::{Arc, Mutex, Once};

use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;

type LogFn = ThreadsafeFunction<String, (), String, napi::Status, false, true>;

static LOGGER: Mutex<Option<Arc<LogFn>>> = Mutex::new(None);
static LOGGER_SET: Once = Once::new();

static FORWARDER: ForwardLogger = ForwardLogger;

struct ForwardLogger;

impl log::Log for ForwardLogger {
    fn enabled(&self, _meta: &log::Metadata) -> bool {
        true
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
pub fn set_logger(callback: LogFn, level: String) {
    LOGGER_SET.call_once(|| {
        log::set_logger(&FORWARDER).unwrap();
    });
    LOGGER.lock().unwrap().replace(Arc::new(callback));
    if let Ok(level) = level.parse::<log::LevelFilter>() {
        log::set_max_level(level);
    }
}
