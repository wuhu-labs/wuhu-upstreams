//! The two halves of a bidirectional QUIC stream.

use std::{ffi::c_void, sync::Arc};

use iroh::endpoint::{ReadError, RecvStream, SendStream, VarInt, WriteError};
use tokio::sync::Mutex;

use crate::op::{Outcome, guard, runtime, spawn, wi_callback};

struct Send {
    stream: SendStream,
    closed: bool,
}

impl Drop for Send {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.stream.reset(VarInt::from_u32(0));
        }
    }
}

pub struct SendHandle(Arc<Mutex<Send>>);

impl SendHandle {
    pub fn new(stream: SendStream) -> Self {
        SendHandle(Arc::new(Mutex::new(Send {
            stream,
            closed: false,
        })))
    }
}

pub struct RecvHandle(Arc<Mutex<RecvStream>>);

impl RecvHandle {
    pub fn new(stream: RecvStream) -> Self {
        RecvHandle(Arc::new(Mutex::new(stream)))
    }
}

fn var_int(code: u64) -> VarInt {
    VarInt::from_u64(code).unwrap_or(VarInt::MAX)
}

fn write_outcome(error: WriteError) -> Outcome {
    match error {
        WriteError::Stopped(code) => Outcome::Stopped(code.into_inner()),
        WriteError::ConnectionLost(e) => Outcome::Closed(e.to_string()),
        other => Outcome::error(other),
    }
}

#[allow(non_camel_case_types)]
pub type wi_send = SendHandle;
#[allow(non_camel_case_types)]
pub type wi_recv = RecvHandle;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_send_write(
    send: *const wi_send,
    bytes: *const u8,
    len: usize,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let send = unsafe { &*send }.0.clone();
    let bytes = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec()
    };
    spawn(callback, context, async move {
        let mut send = send.lock().await;
        match send.stream.write_chunk(bytes.into()).await {
            Ok(()) => Outcome::Ok,
            Err(e) => write_outcome(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_send_finish(send: *const wi_send) -> bool {
    let send = unsafe { &*send };
    guard(false, || {
        let Ok(mut send) = send.0.try_lock() else {
            return false;
        };
        send.closed = true;
        send.stream.finish().is_ok()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_send_reset(send: *const wi_send, code: u64) {
    let send = unsafe { &*send }.0.clone();
    guard((), || {
        runtime().spawn(async move {
            let mut send = send.lock().await;
            send.closed = true;
            let _ = send.stream.reset(var_int(code));
        });
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_send_free(send: *mut wi_send) {
    guard((), || drop(unsafe { Box::from_raw(send) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_recv_read(
    recv: *const wi_recv,
    max: usize,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let recv = unsafe { &*recv }.0.clone();
    spawn(callback, context, async move {
        let mut recv = recv.lock().await;
        let mut bytes = vec![0; max.max(1)];
        match recv.read(&mut bytes).await {
            Ok(Some(count)) => {
                bytes.truncate(count);
                Outcome::Bytes(bytes)
            }
            Ok(None) => Outcome::Finished,
            Err(ReadError::Reset(code)) => Outcome::Reset(code.into_inner()),
            Err(ReadError::ConnectionLost(e)) => Outcome::Closed(e.to_string()),
            Err(e) => Outcome::error(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_recv_stop(recv: *const wi_recv, code: u64) {
    let recv = unsafe { &*recv }.0.clone();
    guard((), || {
        runtime().spawn(async move {
            let _ = recv.lock().await.stop(var_int(code));
        });
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_recv_free(recv: *mut wi_recv) {
    guard((), || drop(unsafe { Box::from_raw(recv) }))
}
