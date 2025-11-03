use rustls::ClientConfig;

#[cfg(target_os = "android")]
pub fn tls_config() -> ClientConfig {
    use rustls::RootCertStore;
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.to_vec());
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[cfg(not(target_os = "android"))]
pub fn tls_config() -> ClientConfig {
    use rustls_platform_verifier::ConfigVerifierExt; // adds with_platform_verifier()
    // Uses platform trust store on non-Android OSes.
    ClientConfig::with_platform_verifier().expect("failed to create tls config")
}