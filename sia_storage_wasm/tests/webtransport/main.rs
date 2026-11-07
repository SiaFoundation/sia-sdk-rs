//! Starts fake WebTransport hosts for the ordinary wasm-pack browser tests.

#![cfg(not(target_arch = "wasm32"))]

mod fixtures;
mod host;
mod sector;
mod server;

use std::error::Error;
use std::ffi::OsString;
use std::path::Path;

use base64::Engine;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PublicKeyData};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::process::Command;
use wtransport::Identity;
use wtransport::tls::{Certificate, CertificateChain, PrivateKey};

#[tokio::test]
async fn browsers() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let dir = dir.path();
    // The hosts share one certificate, signed by a CA made for this run.
    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca.self_signed(&ca_key)?;
    let ca_pem = dir.join("ca.pem");
    std::fs::write(&ca_pem, ca_cert.pem())?;
    let key = KeyPair::generate()?;
    let cert = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?
        .signed_by(&key, &Issuer::new(ca, ca_key))?;
    let spki = base64::engine::general_purpose::STANDARD
        .encode(Sha256::digest(key.subject_public_key_info()));
    let profile = dir.join("firefox");
    firefox_profile(&profile, &ca_pem).await?;
    let webdriver = dir.join("webdriver.json");
    std::fs::write(
        &webdriver,
        serde_json::json!({
            // Chrome applies the SPKI list to WebTransport only with QUIC
            // forced on. `--webtransport-developer-mode` would also skip the
            // certificate check, but it turns off Chrome's penalty for failed
            // handshakes, which several tests depend on.
            "goog:chromeOptions": {
                "args": [
                    format!("--ignore-certificate-errors-spki-list={spki}"),
                    "--origin-to-force-quic-on=*",
                ]
            },
            // Firefox ignores `acceptInsecureCerts` for WebTransport, so the
            // CA goes into a profile made for the run.
            "moz:firefoxOptions": {
                "args": ["-profile", profile.to_str().ok_or("temp dir is not UTF-8")?],
                // Firefox turns HTTP/3 off, and with it WebTransport, once
                // it trusts a root it did not ship with.
                "prefs": { "network.http.http3.disable_when_third_party_roots_found": false },
            },
        })
        .to_string(),
    )?;
    let identity = Identity::new(
        CertificateChain::new(vec![
            Certificate::from_der(cert.der().to_vec())?,
            Certificate::from_der(ca_cert.der().to_vec())?,
        ]),
        PrivateKey::from_der_pkcs8(key.serialize_der()),
    );

    let listener = TcpListener::bind(fixtures::CONTROL_ADDR).await?;
    // Safari uses macOS certificate trust; wasm-bindgen-test does not pass
    // webdriver.json capabilities to Safari.
    #[cfg(target_os = "macos")]
    let ci = std::env::var_os("CI").is_some();
    #[cfg(target_os = "macos")]
    if !Command::new(if ci { "sudo" } else { "security" })
        .args(ci.then_some("-n"))
        .args(ci.then_some("security"))
        .arg("add-trusted-cert")
        .args(ci.then_some("-d"))
        .args(["-r", "trustRoot", "-p", "ssl", "-s", "127.0.0.1"])
        .arg(&ca_pem)
        .status()
        .await?
        .success()
    {
        return Err("could not trust the test CA for Safari".into());
    }
    let result = tokio::select! {
        result = server::serve(listener, identity) => {
            Err(format!("fake host server stopped: {result:?}").into())
        }
        result = async {
            let status = Command::new("wasm-pack")
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .args(["test", "--release", "--headless", "--chrome", "--firefox"])
                .args(cfg!(target_os = "macos").then_some("--safari"))
                .env("WASM_BINDGEN_USE_BROWSER", "1")
                .env("WASM_BINDGEN_TEST_TIMEOUT", "600")
                .env("WASM_BINDGEN_TEST_WEBDRIVER_JSON", &webdriver)
                .status()
                .await?;
            if !status.success() {
                return Err(format!("wasm-pack test failed: {status}").into());
            }
            Ok(())
        } => result,
    };
    #[cfg(target_os = "macos")]
    if !ci
        && !tokio::time::timeout(
            std::time::Duration::from_secs(60),
            Command::new("security")
                .arg("remove-trusted-cert")
                .arg(&ca_pem)
                .kill_on_drop(true)
                .status(),
        )
        .await
        .map_err(|_| "timed out removing the Safari test CA")??
        .success()
    {
        return Err("could not remove the Safari test CA".into());
    }
    result
}

/// Makes a Firefox profile whose certificate store trusts the CA in
/// `ca_pem`.
async fn firefox_profile(profile: &Path, ca_pem: &Path) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(profile)?;
    let mut db = OsString::from("sql:");
    db.push(profile);
    let mut create = Command::new("certutil");
    create.args(["-N", "--empty-password", "-d"]).arg(&db);
    let mut add_ca = Command::new("certutil");
    add_ca
        .args(["-A", "-n", "browser_harness", "-t", "C,,", "-i"])
        .arg(ca_pem)
        .arg("-d")
        .arg(&db);
    for mut certutil in [create, add_ca] {
        let status = certutil
            .status()
            .await
            .map_err(|e| format!("running certutil: {e}"))?;
        if !status.success() {
            return Err(format!("certutil exited with {status}").into());
        }
    }
    Ok(())
}
