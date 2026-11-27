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

use crate::op::{Outcome, guard, handle, key, runtime, spawn, text, wi_callback};

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
    service: RelayService,
    http: Option<SocketAddr>,
    https: Option<SocketAddr>,
}

impl Drop for wi_relay {
    fn drop(&mut self) {
        let server = self.server.clone();
        runtime().spawn(async move {
            if let Some(server) = server.lock().await.take() {
                let _ = server.shutdown().await;
            }
        });
    }
}

fn tls(address: SocketAddr, cert: &str, key: &str) -> Result<TlsConfig, String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("certificate {cert}: {e}"))?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("key {key}: {e}"))?;
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
    http_address: *const c_char,
    tls_address: *const c_char,
    cert_pem_path: *const c_char,
    key_pem_path: *const c_char,
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
    let http = unsafe { text(http_address) };
    let tls_parts = unsafe { (text(tls_address), text(cert_pem_path), text(key_pem_path)) };
    spawn(callback, context, async move {
        let parse = |text: Option<String>| -> Result<SocketAddr, String> {
            let text = text.ok_or("no address")?;
            text.parse().map_err(|e| format!("address {text}: {e}"))
        };
        let mut relay = match parse(http) {
            Ok(address) => RelayConfig::new(address),
            Err(e) => return Outcome::Error(e),
        };
        relay.access = Arc::new(access);
        if let (Some(address), Some(cert), Some(key)) = tls_parts {
            match parse(Some(address)).and_then(|address| tls(address, &cert, &key)) {
                Ok(config) => relay.tls = Some(config),
                Err(e) => return Outcome::Error(e),
            }
        }
        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        match Server::spawn(config).await {
            Ok(server) => {
                let service = server
                    .relay_service()
                    .expect("a relay server has a relay service")
                    .clone();
                Outcome::Handle(handle(wi_relay {
                    http: server.http_addr(),
                    https: server.https_addr(),
                    service,
                    server: Arc::new(Mutex::new(Some(server))),
                }))
            }
            Err(e) => Outcome::error(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relay_address(
    relay: *const wi_relay,
    tls: bool,
    out: *mut c_char,
    capacity: usize,
) -> usize {
    let relay = unsafe { &*relay };
    guard(0, || {
        let Some(address) = (if tls { relay.https } else { relay.http }) else {
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
    let server = unsafe { &*relay }.server.clone();
    spawn(callback, context, async move {
        let Some(server) = server.lock().await.take() else {
            return Outcome::Ok;
        };
        match server.shutdown().await {
            Ok(()) => Outcome::Ok,
            Err(e) => Outcome::error(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_relay_free(relay: *mut wi_relay) {
    guard((), || drop(unsafe { Box::from_raw(relay) }))
}
