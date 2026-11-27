//! An embedded iroh relay whose admission is the caller's.

use std::{
    ffi::{c_char, c_void},
    net::SocketAddr,
    sync::Arc,
};

use iroh::PublicKey;
use iroh_relay::server::{
    Access, AccessControl, CertConfig, ClientRequest, ConnectionId, RelayConfig, RelayService,
    Server, ServerConfig, TlsConfig,
};
use tokio::sync::Mutex;

use crate::op::{Outcome, RunOnce, detach, guard, handle, key, spawn, text, wi_callback};

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct wi_relay_access {
    context: *mut c_void,
    on_connect: Option<unsafe extern "C" fn(*mut c_void, *const u8, u64) -> bool>,
    on_disconnect: Option<unsafe extern "C" fn(*mut c_void, *const u8, u64)>,
    release: Option<unsafe extern "C" fn(*mut c_void)>,
}

#[derive(Debug)]
struct CallerAccess {
    context: usize,
    #[allow(clippy::type_complexity)]
    on_connect: Option<unsafe extern "C" fn(*mut c_void, *const u8, u64) -> bool>,
    on_disconnect: Option<unsafe extern "C" fn(*mut c_void, *const u8, u64)>,
    release: Option<unsafe extern "C" fn(*mut c_void)>,
}

impl Drop for CallerAccess {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            unsafe { release(self.context as *mut c_void) };
        }
    }
}

fn connection_number(id: ConnectionId) -> u64 {
    id.to_string().parse().expect("ConnectionId displays its number")
}

impl AccessControl for CallerAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let Some(on_connect) = self.on_connect else {
            return Access::Allow;
        };
        let key = *request.endpoint_id().as_bytes();
        let number = connection_number(request.connection_id());
        if unsafe { on_connect(self.context as *mut c_void, key.as_ptr(), number) } {
            Access::Allow
        } else {
            Access::Deny { reason: None }
        }
    }

    fn on_disconnect(&self, endpoint_id: PublicKey, connection_id: ConnectionId) {
        if let Some(on_disconnect) = self.on_disconnect {
            let key = *endpoint_id.as_bytes();
            let number = connection_number(connection_id);
            unsafe { on_disconnect(self.context as *mut c_void, key.as_ptr(), number) };
        }
    }
}

#[allow(non_camel_case_types)]
pub struct wi_relay {
    server: Arc<Mutex<Option<Server>>>,
    shutdown: RunOnce<Result<(), String>>,
    service: RelayService,
    metrics: Arc<iroh_relay::server::Metrics>,
    address: Option<SocketAddr>,
}

impl Drop for wi_relay {
    fn drop(&mut self) {
        let server = self.server.clone();
        detach(async move {
            if let Some(server) = server.lock().await.take() {
                let _ = server.shutdown().await;
            }
        });
    }
}

fn tls(address: SocketAddr, cert: &str, key: &str) -> Result<TlsConfig, String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let chain = CertificateDer::pem_slice_iter(cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate chain: {e}"))?;
    if chain.is_empty() {
        return Err("certificate chain: no certificate".into());
    }
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).map_err(|e| format!("key: {e}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())?;
    Ok(TlsConfig::new(
        address,
        CertConfig::Manual {
            server_config: config,
        },
    ))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relay_spawn(
    address: *const c_char,
    cert_chain_pem: *const c_char,
    key_pem: *const c_char,
    access: wi_relay_access,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let access = CallerAccess {
        context: access.context as usize,
        on_connect: access.on_connect,
        on_disconnect: access.on_disconnect,
        release: access.release,
    };
    let address = unsafe { text(address) };
    let pem = unsafe { (text(cert_chain_pem), text(key_pem)) };
    spawn(callback, context, async move {
        let address: SocketAddr = match address.as_deref().map(str::parse) {
            Some(Ok(address)) => address,
            Some(Err(e)) => return Outcome::Error(format!("address {}: {e}", address.unwrap_or_default())),
            None => return Outcome::Error("no address".into()),
        };
        let mut relay = match pem {
            (None, None) => RelayConfig::new(address),
            (Some(cert), Some(key)) => {
                // iroh serves only its captive-portal check on the plain listener once TLS is on.
                let mut relay = RelayConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
                match tls(address, &cert, &key) {
                    Ok(config) => relay.tls = Some(config),
                    Err(e) => return Outcome::Error(e),
                }
                relay
            }
            _ => return Outcome::Error("a certificate chain needs its key, and a key its chain".into()),
        };
        relay.access = Arc::new(access);
        let tls = relay.tls.is_some();
        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        match Server::spawn(config).await {
            Ok(server) => {
                let service = server
                    .relay_service()
                    .expect("a relay server has a relay service")
                    .clone();
                Outcome::Handle(handle(wi_relay {
                    metrics: server.metrics().server.clone(),
                    address: if tls { server.https_addr() } else { server.http_addr() },
                    service,
                    server: Arc::new(Mutex::new(Some(server))),
                    shutdown: RunOnce::new(),
                }))
            }
            Err(e) => Outcome::error(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relay_address(relay: *const wi_relay, out: *mut c_char, capacity: usize) -> usize {
    let relay = unsafe { &*relay };
    guard(0, || {
        let Some(address) = relay.address else {
            return 0;
        };
        let text = address.to_string();
        if text.len() + 1 > capacity {
            return 0;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(text.as_ptr() as *const c_char, out, text.len());
            *out.add(text.len()) = 0;
        }
        text.len()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relay_traffic(relay: *const wi_relay, sent: *mut u64, received: *mut u64) {
    let relay = unsafe { &*relay };
    guard((), || unsafe {
        *sent = relay.metrics.bytes_sent.get();
        *received = relay.metrics.bytes_recv.get();
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relay_disconnect(relay: *const wi_relay, public_key: *const u8) -> bool {
    let relay = unsafe { &*relay };
    let key = unsafe { key(public_key) };
    guard(false, || {
        let Ok(key) = PublicKey::from_bytes(&key) else {
            return false;
        };
        relay.service.clients().disconnect(key, None)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relay_shutdown(
    relay: *const wi_relay,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let this = unsafe { &*relay };
    let server = this.server.clone();
    let shutdown = this.shutdown.run(Err("panic in wuhu_iroh".into()), || async move {
        let Some(server) = server.lock().await.take() else {
            return Ok(());
        };
        server.shutdown().await.map_err(|e| e.to_string())
    });
    spawn(callback, context, async move {
        match shutdown.await {
            Ok(()) => Outcome::Ok,
            Err(e) => Outcome::Error(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relay_free(relay: *mut wi_relay) {
    guard((), || drop(unsafe { Box::from_raw(relay) }))
}
