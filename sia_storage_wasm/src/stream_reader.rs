use std::io;

use futures_util::future::Either;
use futures_util::stream::{IntoAsyncRead as StreamIntoAsyncRead, MapErr, MapOk, TryStreamExt};
use js_sys::Uint8Array;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_streams::readable::{IntoAsyncRead, IntoStream, ReadableStream};

fn chunk_to_vec(value: JsValue) -> Vec<u8> {
    value.unchecked_into::<Uint8Array>().to_vec()
}

fn js_err_to_io(e: JsValue) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

type DefaultReader = StreamIntoAsyncRead<
    MapErr<MapOk<IntoStream<'static>, fn(JsValue) -> Vec<u8>>, fn(JsValue) -> io::Error>,
>;

/// `AsyncRead` over a JS `ReadableStream`.
///
/// Left variant is a BYOB (byte) reader, used when the source is a byte
/// stream for zero-copy reads. Right variant falls back to a default reader
/// with a copy per chunk — Safari's `File.stream()` / `Blob.stream()` are
/// default streams, so without the fallback any upload from a browser file
/// on Safari fails with "already locked to a reader, or not a readable byte
/// stream".
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
                .map_ok(chunk_to_vec as fn(JsValue) -> Vec<u8>)
                .map_err(js_err_to_io as fn(JsValue) -> io::Error)
                .into_async_read(),
        ),
    }
}
