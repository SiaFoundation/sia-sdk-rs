use std::io;

use futures_util::future::{Either, Ready, ready};
use futures_util::stream::{AndThen, IntoAsyncRead as StreamIntoAsyncRead, MapErr, TryStreamExt};
use js_sys::Uint8Array;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_streams::readable::{IntoAsyncRead, IntoStream, ReadableStream};

fn js_err_message(e: &JsValue) -> String {
    if let Some(err) = e.dyn_ref::<js_sys::Error>() {
        let message: String = err.message().into();
        if message.is_empty() {
            return "JavaScript error with no message".to_string();
        }
        return message;
    }
    e.as_string().unwrap_or_else(|| format!("{e:?}"))
}

fn js_err_to_io(e: JsValue) -> io::Error {
    io::Error::other(js_err_message(&e))
}

fn chunk_to_vec(value: JsValue) -> Ready<io::Result<Vec<u8>>> {
    ready(
        value
            .dyn_into::<Uint8Array>()
            .map(|a| a.to_vec())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ReadableStream chunk is not a Uint8Array",
                )
            }),
    )
}

type DefaultReader = StreamIntoAsyncRead<
    AndThen<
        MapErr<IntoStream<'static>, fn(JsValue) -> io::Error>,
        Ready<io::Result<Vec<u8>>>,
        fn(JsValue) -> Ready<io::Result<Vec<u8>>>,
    >,
>;

/// `AsyncRead` over a JS `ReadableStream`.
///
/// Prefers a BYOB (byte) reader for zero-copy reads, falling back to a default
/// reader with a copy per chunk when the source isn't a byte stream. The
/// fallback is required on Safari — `File.stream()` and `Blob.stream()` return
/// default streams there, so without it uploads fail with "already locked to
/// a reader, or not a readable byte stream".
///
/// https://github.com/MattiasBuelens/wasm-streams/issues/19#issuecomment-1447294077
pub(crate) type JsStreamReader = Either<IntoAsyncRead<'static>, DefaultReader>;

pub(crate) fn js_stream_reader(source: web_sys::ReadableStream) -> JsStreamReader {
    let stream = ReadableStream::from_raw(source);
    match stream.try_into_async_read() {
        Ok(reader) => Either::Left(reader),
        Err((_, stream)) => Either::Right(
            stream
                .into_stream()
                .map_err(js_err_to_io as fn(JsValue) -> io::Error)
                .and_then(chunk_to_vec as fn(JsValue) -> Ready<io::Result<Vec<u8>>>)
                .into_async_read(),
        ),
    }
}
