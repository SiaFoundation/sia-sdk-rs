use std::cell::RefCell;
use std::sync::Once;

use js_sys::Function;
use wasm_bindgen::prelude::*;

thread_local! {
    static LOGGER: RefCell<Option<Function>> = const { RefCell::new(None) };
}

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
        LOGGER.with(|l| {
            if let Some(logger) = l.borrow().as_ref() {
                let msg = format!("[{}] {}", record.level(), record.args());
                let _ = logger.call1(&JsValue::NULL, &JsValue::from_str(&msg));
            }
        });
    }

    fn flush(&self) {}
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "(message: string) => void")]
    pub type LogCallback;

    #[wasm_bindgen(
        typescript_type = "\"off\" | \"error\" | \"warn\" | \"info\" | \"debug\" | \"trace\""
    )]
    pub type LogLevel;
}

/// Sets a logging callback to receive log messages from the SDK.
///
/// The callback receives formatted log messages as strings.
/// `level` should be one of: "off", "error", "warn", "info", "debug", "trace".
#[wasm_bindgen(js_name = "setLogger")]
pub fn set_logger(callback: LogCallback, level: LogLevel) {
    LOGGER_SET.call_once(|| {
        log::set_logger(&FORWARDER).unwrap();
    });
    let callback: Function = callback.unchecked_into();
    LOGGER.with(|l| l.borrow_mut().replace(callback));
    if let Some(level) = JsValue::from(level).as_string()
        && let Ok(filter) = level.parse::<log::LevelFilter>()
    {
        log::set_max_level(filter);
    }
}
