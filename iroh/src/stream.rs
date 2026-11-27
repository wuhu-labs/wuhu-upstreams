//! The two halves of a bidirectional QUIC stream.

use std::{
    ffi::c_void,
    future::poll_fn,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
};

use iroh::endpoint::{ReadError, RecvStream, SendStream, StoppedError, VarInt, WriteError};
use tokio::sync::{Mutex, watch};

use crate::op::{Outcome, detach, guard, spawn, spawn_holding, wi_callback, wi_status};

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

/// The send half. `stream` is only ever locked for a synchronous step, never across an await, so
/// a reset, a finish or a stop watcher reaches it while a write waits on flow control.
struct SendState {
    stream: std::sync::Mutex<Send>,
    writer: Mutex<()>,
    /// Writes from their call to the return of their callback.
    writes: AtomicUsize,
    /// Our own reset's code, set once noq took it. noq wakes no stop watcher for a local reset
    /// and, once the reset is acknowledged, reports the stream like an acknowledged finish.
    reset: watch::Sender<Option<u64>>,
}

impl SendState {
    fn lock(&self) -> std::sync::MutexGuard<'_, Send> {
        self.stream.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub struct SendHandle(Arc<SendState>);

impl SendHandle {
    pub fn new(stream: SendStream) -> Self {
        SendHandle(Arc::new(SendState {
            stream: std::sync::Mutex::new(Send {
                stream,
                closed: false,
            }),
            writer: Mutex::new(()),
            writes: AtomicUsize::new(0),
            reset: watch::Sender::new(None),
        }))
    }
}

struct PendingWrite(Arc<SendState>);

impl PendingWrite {
    fn new(state: &Arc<SendState>) -> Self {
        state.writes.fetch_add(1, Ordering::SeqCst);
        PendingWrite(state.clone())
    }
}

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
    let pending = PendingWrite::new(&state);
    let bytes = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec()
    };
    spawn_holding(pending, callback, context, async move {
        let _writer = state.writer.lock().await;
        let mut resets = state.reset.subscribe();
        let mut written = 0;
        let write = poll_fn(|cx| {
            while written < bytes.len() {
                let mut send = state.lock();
                match Pin::new(&mut send.stream).poll_write(cx, &bytes[written..]) {
                    Poll::Ready(Ok(count)) => written += count,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Poll::Ready(Ok(()))
        });
        let written = tokio::select! {
            biased;
            _ = resets.wait_for(Option::is_some) => None,
            written = write => Some(written),
        };
        // A write that our reset woke sees only a closed stream.
        let reset = *state.reset.borrow();
        match (written, reset) {
            (Some(Ok(())), _) => Outcome::Ok,
            (_, Some(code)) => Outcome::Reset(code),
            (Some(Err(e)), None) => write_outcome(e),
            (None, None) => unreachable!("only a reset ends the wait"),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_send_finish(send: *const wi_send) -> wi_status {
    let state = &unsafe { &*send }.0;
    guard(wi_status::WI_ERROR, || {
        let mut send = state.lock();
        if state.writes.load(Ordering::SeqCst) > 0 {
            return wi_status::WI_ERROR;
        }
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
    let state = &unsafe { &*send }.0;
    guard((), || {
        let mut send = state.lock();
        send.closed = true;
        if send.stream.reset(var_int(code)).is_ok() {
            state.reset.send_replace(Some(code));
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_send_stopped(
    send: *const wi_send,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let state = unsafe { &*send }.0.clone();
    spawn(callback, context, async move {
        let mut reset = state.reset.subscribe();
        let stopped = {
            let send = state.lock();
            if let Some(code) = *reset.borrow_and_update() {
                return Outcome::Reset(code);
            }
            // noq keeps this watcher's entry until the stream finishes, is stopped or the
            // connection ends: a stream waited on and then reset locally holds it until then.
            send.stream.stopped()
        };
        tokio::select! {
            biased;
            code = reset.wait_for(Option::is_some) => Outcome::Reset(code.map_or(0, |c| c.unwrap_or(0))),
            stop = stopped => match stop {
                Ok(Some(code)) => Outcome::Stopped(code.into_inner()),
                Ok(None) => Outcome::Finished,
                Err(StoppedError::ConnectionLost(e)) => Outcome::Closed(e.to_string()),
                Err(e) => Outcome::Closed(e.to_string()),
            },
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
