use std::sync::{Arc, Mutex};

static LOG_CALLBACK: Mutex<Option<Arc<dyn Logger>>> = Mutex::new(None);
static LOGGER: CallbackLogger = CallbackLogger;

static INIT: std::sync::Once = std::sync::Once::new();

#[uniffi::export(with_foreign)]
pub trait Logger: Send + Sync {
    fn debug(&self, msg: String);
    fn info(&self, msg: String);
    fn warn(&self, msg: String);
    fn error(&self, msg: String);
}


#[uniffi::export]
pub fn set_log_callback(callback: Arc<dyn Logger>) {
    let log = callback.clone();
    let mut cb = LOG_CALLBACK.lock().unwrap();
    *cb = Some(callback);
    
    INIT.call_once(|| {
        log.debug("log initialized".into());
        init_logger();
    });
    log.debug("log callback set".into());
}

struct CallbackLogger;

impl log::Log for CallbackLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if let Some(callback) = LOG_CALLBACK.lock().unwrap().as_ref() {
            let msg = format!("{}", record.args());
            match record.level() {
                log::Level::Debug => callback.debug(msg),
                log::Level::Info => callback.info(msg),
                log::Level::Warn => callback.warn(msg),
                log::Level::Error => callback.error(msg),
                _ => {}
            }
        }
    }

    fn flush(&self) {}
}

fn init_logger() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Debug);
}