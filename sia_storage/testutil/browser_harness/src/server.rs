//! The control API, a minimal HTTP/1.1 server. The tests call it from the
//! test page the browser opens, so every response allows any origin.
//!
//! - `POST /hosts` with a list of [`HostSpec`] replaces every host and
//!   returns the new hosts as [`FakeHost`](browser_harness::FakeHost)s.
//! - `PUT /hosts/<i>` with a [`HostSpec`] changes host `i`.
//! - `GET /stats` returns each host's
//!   [`HostStats`](browser_harness::HostStats).

use std::sync::Arc;

use browser_harness::HostSpec;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use wtransport::Identity;

use crate::host::Host;

type Error = Box<dyn std::error::Error + Send + Sync>;

pub async fn serve(listener: TcpListener, identity: Identity) -> std::io::Result<()> {
    let hosts = Arc::new(Mutex::new(Vec::new()));
    let identity = Arc::new(identity);
    loop {
        let (stream, _) = listener.accept().await?;
        let (hosts, identity) = (hosts.clone(), identity.clone());
        tokio::spawn(async move {
            if let Err(e) = respond(stream, &hosts, &identity).await {
                eprintln!("control request failed: {e}");
            }
        });
    }
}

async fn respond(
    stream: TcpStream,
    hosts: &Mutex<Vec<Host>>,
    identity: &Identity,
) -> Result<(), Error> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let mut words = line.split(' ');
    let (Some(method), Some(path)) = (words.next(), words.next()) else {
        return Err(format!("bad request line {line:?}").into());
    };
    let mut length = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await?;
        match header.trim_end().split_once(':') {
            Some((name, value)) if name.eq_ignore_ascii_case("content-length") => {
                length = value.trim().parse()?;
            }
            Some(_) => {}
            None => break,
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;

    let (status, body) = match route(method, path, &body, hosts, identity).await {
        Ok(body) => ("200 OK", body.to_string()),
        Err(e) => ("400 Bad Request", e.to_string()),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, PUT\r\n\
         Access-Control-Allow-Headers: *\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    reader.into_inner().write_all(response.as_bytes()).await?;
    Ok(())
}

async fn route(
    method: &str,
    path: &str,
    body: &[u8],
    hosts: &Mutex<Vec<Host>>,
    identity: &Identity,
) -> Result<Value, Error> {
    match (method, path.strip_prefix("/hosts/")) {
        // CORS preflight
        ("OPTIONS", _) => Ok(Value::Null),
        ("POST", _) if path == "/hosts" => {
            let specs: Vec<HostSpec> = serde_json::from_slice(body)?;
            let mut hosts = hosts.lock().await;
            for host in hosts.drain(..) {
                host.stop().await;
            }
            for spec in specs {
                hosts.push(Host::start(spec, identity)?);
            }
            Ok(serde_json::to_value(
                hosts.iter().map(|h| &h.info).collect::<Vec<_>>(),
            )?)
        }
        ("PUT", Some(index)) => {
            let index: usize = index.parse()?;
            let hosts = hosts.lock().await;
            let host = hosts.get(index).ok_or(format!("no host {index}"))?;
            host.set(serde_json::from_slice(body)?);
            Ok(Value::Null)
        }
        ("GET", _) if path == "/stats" => {
            let hosts = hosts.lock().await;
            Ok(serde_json::to_value(
                hosts.iter().map(Host::stats).collect::<Vec<_>>(),
            )?)
        }
        _ => Err(format!("no route for {method} {path}").into()),
    }
}
