#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use std::collections::HashMap;
    use std::future::pending;
    use std::sync::{LazyLock, Mutex};

    use crate::rhp4::Client;

    struct Detach(tokio::runtime::Id);

    impl Drop for Detach {
        fn drop(&mut self) {
            RHP_CLIENTS.lock().unwrap().remove(&self.0);
        }
    }

    static RHP_CLIENTS: LazyLock<Mutex<HashMap<tokio::runtime::Id, Client>>> =
        LazyLock::new(Default::default);

    pub(crate) fn default_client() -> Client {
        let id = tokio::runtime::Handle::current().id();
        let mut clients = RHP_CLIENTS.lock().unwrap();
        if let Some(client) = clients.get(&id) {
            return client.clone();
        }
        let client = Client::new();
        clients.insert(id, client.clone());
        drop(clients);

        // Spawn outside the lock: on a runtime that is shutting down, tokio
        // drops the task immediately, running Detach::drop on this thread.
        let detach = Detach(id);
        tokio::spawn(async move {
            let _detach = detach;
            pending::<()>().await;
        });
        client
    }

    #[cfg(test)]
    mod native_tests {
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use ed25519_dalek::SigningKey;
        use sia_core::encoding::SiaEncodable;
        use sia_core::rhp4::protocol::{Error as RHP4Error, RPCError};
        use sia_core::signing::PublicKey;
        use sia_core::types::SPECIFIER_SIZE;
        use sia_core::types::v2::{NetAddress, Protocol};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::runtime::{Builder, Id, Runtime};

        use super::*;
        use crate::rhp4::{Error, HostEndpoint, Transport};
        use crate::time::{Duration, timeout};

        /// A siamux host that answers every RPC with an error. It runs on its
        /// own runtime so it outlives the client runtimes under test.
        struct Server {
            _runtime: Runtime,
            addr: SocketAddr,
            public_key: PublicKey,
            accepted: Arc<AtomicUsize>,
        }

        impl Server {
            fn start() -> Self {
                let runtime = Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .unwrap();
                let key = SigningKey::from_bytes(&rand::random());
                let public_key = PublicKey::new(key.verifying_key().to_bytes());
                let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
                let addr = listener.local_addr().unwrap();
                let accepted = Arc::new(AtomicUsize::new(0));

                let count = accepted.clone();
                runtime.spawn(async move {
                    while let Ok((conn, _)) = listener.accept().await {
                        count.fetch_add(1, Ordering::SeqCst);
                        let key = key.clone();
                        tokio::spawn(async move {
                            let mux = sia_mux::accept(conn, &key).await.unwrap();
                            while let Ok(mut stream) = mux.accept_stream().await {
                                tokio::spawn(async move {
                                    let mut specifier = [0u8; SPECIFIER_SIZE];
                                    stream.read_exact(&mut specifier).await.unwrap();
                                    let mut resp = Vec::new();
                                    true.encode(&mut resp).unwrap();
                                    RPCError {
                                        code: 1,
                                        description: "pool test".to_string(),
                                    }
                                    .encode(&mut resp)
                                    .unwrap();
                                    stream.write_all(&resp).await.unwrap();
                                    stream.close().unwrap();
                                });
                            }
                        });
                    }
                });

                Self {
                    _runtime: runtime,
                    addr,
                    public_key,
                    accepted,
                }
            }

            fn endpoint(&self) -> HostEndpoint {
                HostEndpoint {
                    public_key: self.public_key,
                    addresses: vec![NetAddress {
                        protocol: Protocol::SiaMux,
                        address: self.addr.to_string(),
                    }],
                }
            }

            fn accepted(&self) -> usize {
                self.accepted.load(Ordering::SeqCst)
            }
        }

        fn registered(id: Id) -> bool {
            RHP_CLIENTS.lock().unwrap().contains_key(&id)
        }

        /// Runs a settings RPC through the runtime's pooled real transport and
        /// asserts it reached the server.
        fn rpc(runtime: &Runtime, host: &HostEndpoint) {
            let err = runtime
                .block_on(async {
                    timeout(
                        Duration::from_secs(5),
                        default_client().host_prices(host, Duration::from_secs(5)),
                    )
                    .await
                })
                .expect("rpc hung")
                .expect_err("server always answers with an error");
            assert!(matches!(err, Error::Rpc(RHP4Error::RPC(_))), "{err}");
        }

        fn assert_detaches_on_shutdown(a: Runtime, b: Runtime) {
            let server = Server::start();
            let host = server.endpoint();
            let id_a = a.handle().id();
            let id_b = b.handle().id();
            assert_ne!(id_a, id_b);

            rpc(&a, &host);
            assert_eq!(server.accepted(), 1);
            assert!(registered(id_a));
            // the pooled connection is reused within the runtime
            rpc(&a, &host);
            assert_eq!(server.accepted(), 1);

            drop(a);
            assert!(!registered(id_a));

            // the next runtime dials fresh instead of inheriting a connection
            // whose driver tasks died with the first
            rpc(&b, &host);
            assert_eq!(server.accepted(), 2);
            assert!(registered(id_b));

            drop(b);
            assert!(!registered(id_b));
        }

        #[test]
        fn test_current_thread_runtime_detaches_on_shutdown() {
            let build = || Builder::new_current_thread().enable_all().build().unwrap();
            assert_detaches_on_shutdown(build(), build());
        }

        #[test]
        fn test_multi_thread_runtime_detaches_on_shutdown() {
            let build = || Builder::new_multi_thread().enable_all().build().unwrap();
            assert_detaches_on_shutdown(build(), build());
        }

        /// A handle that outlives its runtime can still enter it, but tokio
        /// drops anything spawned there immediately.
        #[test]
        fn test_default_client_after_shutdown_does_not_deadlock() {
            let runtime = Builder::new_current_thread().enable_all().build().unwrap();
            let handle = runtime.handle().clone();
            let id = handle.id();
            drop(runtime);

            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                handle.block_on(async { default_client() });
                tx.send(()).unwrap();
            });
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .expect("default_client deadlocked");
            assert!(!registered(id));
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use crate::rhp4::Client;

    std::thread_local! {
        static RHP_CLIENT: Client = Client::new();
    }

    pub(crate) fn default_client() -> Client {
        RHP_CLIENT.with(|client| client.clone())
    }

    #[cfg(test)]
    mod wasm_tests {
        use wasm_bindgen_test::wasm_bindgen_test;

        use super::*;

        #[wasm_bindgen_test]
        fn test_default_client_initializes() {
            let _ = default_client();
            let _ = default_client();
        }
    }
}

pub(crate) use imp::default_client;
