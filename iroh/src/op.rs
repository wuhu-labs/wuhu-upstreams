//! Operations, results and the runtime behind every asynchronous call of `wuhu_iroh.h`.

use std::{
    collections::HashMap,
    ffi::{CString, c_char, c_void},
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use futures_util::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use tokio::{runtime::Runtime, task::AbortHandle};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types, dead_code)]
pub enum wi_status {
    WI_OK = 0,
    WI_FINISHED = 1,
    WI_RESET = 2,
    WI_STOPPED = 3,
    WI_CLOSED = 4,
    WI_CANCELLED = 5,
    WI_ERROR = 6,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct wi_result {
    status: wi_status,
    code: u64,
    handles: [*mut c_void; 2],
    bytes: *const u8,
    len: usize,
    message: *const c_char,
}

#[allow(non_camel_case_types)]
pub type wi_callback = Option<unsafe extern "C" fn(*mut c_void, *const wi_result)>;

/// What an operation ends with. Handles are raw `Box` pointers handed to the caller.
pub enum Outcome {
    Ok,
    Handle(usize),
    Handles(usize, usize),
    Keyed(usize, [u8; 32]),
    Bytes(Vec<u8>),
    Finished,
    Reset(u64),
    Stopped(u64),
    Closed(String),
    ClosedWith(u64, String),
    Error(String),
    Cancelled,
}

impl Outcome {
    pub fn error(error: impl std::fmt::Display) -> Self {
        Outcome::Error(format!("{error:#}"))
    }
}

pub fn handle<T>(value: T) -> usize {
    Box::into_raw(Box::new(value)) as usize
}

struct Reply {
    callback: wi_callback,
    context: usize,
    done: bool,
}

impl Reply {
    fn send(mut self, outcome: Outcome) {
        self.done = true;
        deliver(self.callback, self.context, outcome);
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        if !self.done {
            deliver(self.callback, self.context, Outcome::Cancelled);
        }
    }
}

fn deliver(callback: wi_callback, context: usize, outcome: Outcome) {
    let Some(callback) = callback else { return };
    let mut result = wi_result {
        status: wi_status::WI_OK,
        code: 0,
        handles: [ptr::null_mut(); 2],
        bytes: ptr::null(),
        len: 0,
        message: ptr::null(),
    };
    let mut message = None;
    let (bytes, outcome) = match outcome {
        Outcome::Bytes(bytes) => (bytes, Outcome::Ok),
        Outcome::Keyed(handle, key) => (key.to_vec(), Outcome::Handle(handle)),
        other => (Vec::new(), other),
    };
    if !bytes.is_empty() {
        result.bytes = bytes.as_ptr();
        result.len = bytes.len();
    }
    match outcome {
        Outcome::Ok => {}
        Outcome::Handle(a) => result.handles[0] = a as *mut c_void,
        Outcome::Handles(a, b) => result.handles = [a as *mut c_void, b as *mut c_void],
        Outcome::Keyed(..) | Outcome::Bytes(_) => unreachable!(),
        Outcome::Finished => result.status = wi_status::WI_FINISHED,
        Outcome::Reset(code) => {
            result.status = wi_status::WI_RESET;
            result.code = code;
        }
        Outcome::Stopped(code) => {
            result.status = wi_status::WI_STOPPED;
            result.code = code;
        }
        Outcome::Closed(text) => {
            result.status = wi_status::WI_CLOSED;
            message = Some(text);
        }
        Outcome::ClosedWith(code, text) => {
            result.status = wi_status::WI_CLOSED;
            result.code = code;
            message = Some(text);
        }
        Outcome::Error(text) => {
            result.status = wi_status::WI_ERROR;
            message = Some(text);
        }
        Outcome::Cancelled => result.status = wi_status::WI_CANCELLED,
    }
    let message = message.map(|m| CString::new(m.replace('\0', " ")).expect("no NUL"));
    if let Some(m) = &message {
        result.message = m.as_ptr();
    }
    unsafe { callback(context as *mut c_void, &result) };
}

static OPERATIONS: OnceLock<Mutex<HashMap<u64, AbortHandle>>> = OnceLock::new();
static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);

fn operations() -> &'static Mutex<HashMap<u64, AbortHandle>> {
    OPERATIONS.get_or_init(Default::default)
}

pub fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("wuhu-iroh")
            .build()
            .expect("tokio runtime")
    })
}

/// Runs `work` on the runtime and reports its outcome exactly once.
pub fn spawn(
    callback: wi_callback,
    context: *mut c_void,
    work: impl Future<Output = Outcome> + Send + 'static,
) -> u64 {
    let id = NEXT_OPERATION.fetch_add(1, Ordering::Relaxed);
    let reply = Reply {
        callback,
        context: context as usize,
        done: false,
    };
    let mut registry = operations().lock().unwrap_or_else(|e| e.into_inner());
    let task = runtime().spawn(async move {
        let outcome = AssertUnwindSafe(work)
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Outcome::Error("panic in wuhu_iroh".into()));
        operations()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        reply.send(outcome);
    });
    registry.insert(id, task.abort_handle());
    id
}

/// Runs a synchronous entry point, turning a panic into `fallback`.
pub fn guard<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(fallback)
}

#[unsafe(no_mangle)]
pub extern "C" fn wi_cancel(operation: u64) {
    guard((), || {
        let task = operations()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&operation);
        if let Some(task) = task {
            task.abort();
        }
    })
}

/// Copies `text` into a NUL-terminated C buffer of `N` bytes, truncating at a char boundary.
pub fn fill<const N: usize>(out: &mut [c_char; N], text: &str) {
    let mut end = text.len().min(N - 1);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    for (slot, byte) in out.iter_mut().zip(text.as_bytes()[..end].iter()) {
        *slot = *byte as c_char;
    }
    out[end] = 0;
}

pub unsafe fn key(bytes: *const u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(bytes, key.as_mut_ptr(), 32) };
    key
}

pub unsafe fn text(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_log_to_stderr(filter: *const c_char) {
    let filter = unsafe { text(filter) }.unwrap_or_else(|| "warn".into());
    guard((), || {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .try_init();
    })
}

/// Work that runs to its end once on the runtime, however many callers wait on it and whether or
/// not they are cancelled: a cancelled `wi_cancel` drops only its own wait.
pub struct RunOnce<T: Clone + Send + Sync + 'static>(Mutex<Option<Shared<BoxFuture<'static, T>>>>);

impl<T: Clone + Send + Sync + 'static> RunOnce<T> {
    pub fn new() -> Self {
        RunOnce(Mutex::new(None))
    }

    /// The work's outcome; the first call starts `work`, later calls wait for that same run.
    pub fn run<F: Future<Output = T> + Send + 'static>(
        &self,
        panicked: T,
        work: impl FnOnce() -> F,
    ) -> Shared<BoxFuture<'static, T>> {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        slot.get_or_insert_with(|| {
            let task = runtime().spawn(work());
            async move { task.await.unwrap_or(panicked) }.boxed().shared()
        })
        .clone()
    }
}
