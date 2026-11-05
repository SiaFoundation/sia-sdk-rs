//! Runs the `sia_storage` browser tests (see `sia_storage/tests/browser.rs`):
//! starts the fake hosts and their control API, then runs each test with
//! `wasm-pack test` in a fresh headless browser, so no test inherits the
//! failed handshakes Chrome counted during another. It needs Chrome, Firefox
//! and NSS `certutil` (`libnss3-tools` on Debian and Ubuntu).
//!
//! ```sh
//! cargo run -p browser_harness [-- <test name filter>...]
//! ```

mod host;
mod sector;
mod server;

use std::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use base64::Engine;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PublicKeyData};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::process::Command;
use wtransport::Identity;
use wtransport::tls::{Certificate, CertificateChain, PrivateKey};

#[derive(Clone, Copy)]
enum Browser {
    Chrome,
    Firefox,
}

impl Browser {
    const ALL: [Self; 2] = [Self::Chrome, Self::Firefox];

    fn name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
        }
    }

    /// The browsers `test` runs in: the one a module in its path is named
    /// after, or all of them.
    fn for_test(test: &str) -> Vec<Self> {
        let named: Vec<Self> = Self::ALL
            .into_iter()
            .filter(|browser| test.split("::").any(|part| part == browser.name()))
            .collect();
        if named.is_empty() {
            Self::ALL.to_vec()
        } else {
            named
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let filters: Vec<String> = std::env::args().skip(1).collect();
    let dir = tempfile::tempdir()?;
    run(dir.path(), &filters).await
}

async fn run(dir: &Path, filters: &[String]) -> Result<(), Box<dyn Error>> {
    // The hosts share one certificate, signed by a CA made for this run.
    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_pem = dir.join("ca.pem");
    std::fs::write(&ca_pem, ca.self_signed(&ca_key)?.pem())?;
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
        CertificateChain::single(Certificate::from_der(cert.der().to_vec())?),
        PrivateKey::from_der_pkcs8(key.serialize_der()),
    );

    let listener = TcpListener::bind(browser_harness::CONTROL_ADDR).await?;
    let failed = tokio::select! {
        result = server::serve(listener, identity) => {
            Err(format!("control API stopped: {result:?}").into())
        }
        failed = run_tests(&webdriver, filters) => failed,
    }?;
    if !failed.is_empty() {
        return Err(format!("failed: {}", failed.join(", ")).into());
    }
    Ok(())
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

/// Runs each test whose name contains one of `filters`, or every test if
/// there are none, and returns those that failed with their browser.
async fn run_tests(webdriver: &Path, filters: &[String]) -> Result<Vec<String>, Box<dyn Error>> {
    let list = wasm_pack_test(webdriver, Browser::Chrome)
        .arg("--list")
        .output()
        .await
        .map_err(|e| format!("running wasm-pack: {e}"))?;
    if !list.status.success() {
        return Err(format!(
            "listing the tests failed:\n{}",
            String::from_utf8_lossy(&list.stderr)
        )
        .into());
    }
    let tests: Vec<String> = String::from_utf8(list.stdout)?
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .filter(|name| filters.is_empty() || filters.iter().any(|f| name.contains(f.as_str())))
        .map(String::from)
        .collect();
    if tests.is_empty() {
        return Err(format!("no browser tests match {filters:?}").into());
    }

    let mut failed = Vec::new();
    for test in tests {
        for browser in Browser::for_test(&test) {
            println!("=== {test} in {}", browser.name());
            if !wasm_pack_test(webdriver, browser)
                .args([&test, "--exact"])
                .status()
                .await
                .map_err(|e| format!("running wasm-pack: {e}"))?
                .success()
            {
                failed.push(format!("{test} in {}", browser.name()));
            }
        }
    }
    Ok(failed)
}

/// `wasm-pack test` of the `sia_storage` browser tests in a headless
/// `browser`. Arguments added after it go to the test runner.
fn wasm_pack_test(webdriver: &Path, browser: Browser) -> Command {
    let sia_storage: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", ".."].iter().collect();
    let mut command = Command::new("wasm-pack");
    command
        .current_dir(sia_storage)
        .args([
            "test",
            "--release",
            "--headless",
            &format!("--{}", browser.name()),
        ])
        .args(["--", "--test", "browser", "--features", "mock", "--"])
        .env("WASM_BINDGEN_USE_BROWSER", "1")
        .env("WASM_BINDGEN_TEST_TIMEOUT", "600")
        .env("WASM_BINDGEN_TEST_WEBDRIVER_JSON", webdriver);
    command
}
