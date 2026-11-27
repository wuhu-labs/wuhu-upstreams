//! The two halves of a bidirectional QUIC stream.

use std::{
    ffi::c_void,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use futures_util::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use iroh::endpoint::{ReadError, RecvStream, SendStream, StoppedError, VarInt, WriteError};
use tokio::sync::Mutex;

use crate::op::{Outcome, detach, guard, spawn, wi_callback, wi_status};

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

#[derive(Clone)]
enum Stop {
    Stopped(u64),
    Ended,
    Lost(String),
}

struct SendState {
    stream: Mutex<Send>,
    /// Writes submitted and not yet replied to, counted before they are spawned, so a finish
    /// between a write's call and its first poll still sees it.
    writes: AtomicUsize,
    stopped: Shared<BoxFuture<'static, Stop>>,
}

pub struct SendHandle(Arc<SendState>);

impl SendHandle {
    pub fn new(stream: SendStream) -> Self {
        let stopped = stream.stopped();
        let stopped = async move {
            match stopped.await {
                Ok(Some(code)) => Stop::Stopped(code.into_inner()),
                Ok(None) => Stop::Ended,
                Err(StoppedError::ConnectionLost(e)) => Stop::Lost(e.to_string()),
                Err(e) => Stop::Lost(e.to_string()),
            }
        }
        .boxed()
        .shared();
        SendHandle(Arc::new(SendState {
            stream: Mutex::new(Send {
                stream,
                closed: false,
            }),
            writes: AtomicUsize::new(0),
            stopped,
        }))
    }
}

struct PendingWrite(Arc<SendState>);

impl Drop for PendingWrite {
    fn drop(&mut self) {
        self.0.writes.fetch_sub(1, Ordering::SeqCst);
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
    let state = unsafe { &*send }.0.clone();
    let bytes = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec()
    };
    state.writes.fetch_add(1, Ordering::SeqCst);
    let pending = PendingWrite(state.clone());
    spawn(callback, context, async move {
        let _pending = pending;
        let mut send = state.stream.lock().await;
        match send.stream.write_chunk(bytes.into()).await {
            Ok(()) => Outcome::Ok,
            Err(e) => write_outcome(e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_send_finish(send: *const wi_send) -> wi_status {
    let state = &unsafe { &*send }.0;
    guard(wi_status::WI_ERROR, || {
        if state.writes.load(Ordering::SeqCst) > 0 {
            return wi_status::WI_ERROR;
        }
        let Ok(mut send) = state.stream.try_lock() else {
            return wi_status::WI_CLOSED;
        };
        if send.closed {
            return wi_status::WI_CLOSED;
        }
        send.closed = true;
        match send.stream.finish() {
            Ok(()) => wi_status::WI_OK,
            Err(_) => wi_status::WI_CLOSED,
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_send_reset(send: *const wi_send, code: u64) {
    let state = unsafe { &*send }.0.clone();
    guard((), || {
        detach(async move {
            let mut send = state.stream.lock().await;
            send.closed = true;
            let _ = send.stream.reset(var_int(code));
        });
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_send_stopped(
    send: *const wi_send,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let stopped = unsafe { &*send }.0.stopped.clone();
    spawn(callback, context, async move {
        match stopped.await {
            Stop::Stopped(code) => Outcome::Stopped(code),
            Stop::Ended => Outcome::Finished,
            Stop::Lost(reason) => Outcome::Closed(reason),
        }
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
        if max == 0 {
            return Outcome::Error("max is 0".into());
        }
        let mut recv = recv.lock().await;
        let mut bytes = vec![0; max];
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
        detach(async move {
            let _ = recv.lock().await.stop(var_int(code));
        });
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_recv_free(recv: *mut wi_recv) {
    guard((), || drop(unsafe { Box::from_raw(recv) }))
}
