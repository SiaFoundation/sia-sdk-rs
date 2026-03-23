use std::sync::{Arc, Mutex, Once};

static LOGGER: Mutex<Option<Arc<dyn Logger>>> = Mutex::new(None);
static LOGGER_SET: Once = Once::new();

static FORWARDER: ForwardLogger = ForwardLogger;

struct ForwardLogger;

impl log::Log for ForwardLogger {
    fn enabled(&self, meta: &log::Metadata) -> bool {
        for target in ["indexd", "app_client", "indexd_ffi"] {
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
            let msg = format!("{}", record.args());
            match record.level() {
                log::Level::Error => logger.error(msg),
                log::Level::Warn => logger.warn(msg),
                log::Level::Info => logger.info(msg),
                log::Level::Debug => logger.debug(msg),
                log::Level::Trace => logger.debug(msg),
            }
        }
    }

    fn flush(&self) {}
}

/// Sets a foreign logger to receive log messages from the SDK.
#[uniffi::export]
pub fn set_logger(logger: Arc<dyn Logger>, level: String) {
    LOGGER_SET.call_once(|| {
        // lazy init the logger
        log::set_logger(&FORWARDER).unwrap();
    });
    LOGGER.lock().unwrap().replace(logger.clone());
    if let Ok(level) = level.parse::<log::LevelFilter>() {
        log::set_max_level(level);
    }
}

#[uniffi::export(with_foreign)]
pub trait Logger: Send + Sync {
    fn info(&self, msg: String);
    fn warn(&self, msg: String);
    fn error(&self, msg: String);
    fn debug(&self, msg: String);
}
