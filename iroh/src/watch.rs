//! Cursors over a feed of changes; every cursor sees each change made after it.

use std::{ffi::c_void, sync::Arc};

use futures_util::{StreamExt, stream::BoxStream};
use tokio::sync::Mutex;

use crate::op::{Outcome, guard, spawn, wi_callback};

#[allow(non_camel_case_types)]
pub struct wi_watch(Arc<Mutex<BoxStream<'static, ()>>>);

impl wi_watch {
    pub fn new(changes: BoxStream<'static, ()>) -> Self {
        wi_watch(Arc::new(Mutex::new(changes)))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_watch_next(
    watch: *const wi_watch,
    callback: wi_callback,
    context: *mut c_void,
) -> u64 {
    let changes = unsafe { &*watch }.0.clone();
    spawn(callback, context, async move {
        match changes.lock().await.next().await {
            Some(()) => Outcome::Ok,
            None => Outcome::Closed("closed".into()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wi_watch_free(watch: *mut wi_watch) {
    guard((), || drop(unsafe { Box::from_raw(watch) }))
}
