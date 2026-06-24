//! # Submodule: Win32EventStream
//!
//! The submodule contains two main structures: `Win32EventStream` and `Win32EventNotification`.
//! These types are used to interface with the Win32 API for event-driven asynchronous programming.
//!
//! `Win32EventStream` represents a stream of events coming from a specific Win32 event.
//! It encapsulates a `Win32EventNotification` object (the Win32 event notification object),
//! an `AtomicWaker` (used to wake up the stream when new events are ready to be processed),
//! and an `AtomicBool` (indicating whether the event is ready or not).
//!
//! An instance of `Win32EventStream` can be created with a given Win32 event handle,
//! and can be polled to check if new events are ready.
//!
//! The `Win32EventStream` struct implements the `Stream` trait, making it possible to use
//! it with async/await syntax and within other futures, streams or async functions.
//!
//! `Win32EventNotification` encapsulates a Win32 event and provides a mechanism to register
//! a callback function that is called when the event is signaled. It maintains the Win32 event handle,
//! the wait object handle, and a pointer to the callback function. It also implements the `Drop` trait
//! to ensure proper cleanup of its resources when it goes out of scope.
//!
//! This submodule provides an abstraction over the Win32 event handling mechanism, providing a Rust-friendly,
//! safe, and idiomatic way to work with Win32 events in an asynchronous context.
//! This can be especially useful in scenarios involving network I/O, inter-process communication,
//! or any other situation where you need to wait for an event to occur without blocking your application.
use futures::{stream::FusedStream, task::AtomicWaker, Stream};
use std::{
    ffi::c_void,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use windows::{
    core::Result,
    Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        System::Threading::{
            RegisterWaitForSingleObject, ResetEvent, UnregisterWaitEx, INFINITE,
            WT_EXECUTEINWAITTHREAD,
        },
    },
};

/// A stream that resolves when a Win32 event is signaled.
pub struct Win32EventStream {
    #[allow(dead_code)]
    /// The Win32 event notification object.
    notif: Win32EventNotification,
    /// An atomic waker for waking the future.
    waker: Arc<AtomicWaker>,
    /// An atomic boolean indicating whether the event is ready.
    ready: Arc<AtomicBool>,
}

impl Win32EventStream {
    /// Create a new `Win32EventStream` instance with the specified event handle.
    pub fn new(event_handle: HANDLE) -> Result<Self> {
        let waker = Arc::new(AtomicWaker::new());
        let ready = Arc::new(AtomicBool::new(false));

        // Extract the raw pointer value from HANDLE to make it Send-safe
        // We store it as usize since that's Send, and reconstruct HANDLE when needed
        let event_handle_raw = event_handle.0 as usize;

        Ok(Self {
            waker: waker.clone(),
            ready: ready.clone(),
            notif: Win32EventNotification::new(
                event_handle,
                Box::new(move |_| {
                    ready.store(true, Ordering::SeqCst);
                    waker.wake();
                    // Reconstruct HANDLE from the raw value
                    let handle = HANDLE(event_handle_raw as *mut c_void);
                    let _ = unsafe { ResetEvent(handle) };
                }),
            )?,
        })
    }
}

impl Stream for Win32EventStream {
    type Item = Result<()>;

    /// Polls the stream to check if the event is ready.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = Pin::into_inner(self);

        // Register the waker *before* checking readiness. The callback always stores `true` into
        // `ready` and only then calls `waker.wake()`. By registering first and re-checking, a
        // signal that fires between the check and the registration cannot be lost: either we
        // observe `ready == true` here, or the callback's `wake()` targets the waker we just
        // registered. (The previous order — check then register — could sleep forever if the
        // event was signaled in the gap between the two.)
        this.waker.register(cx.waker());

        if this.ready.swap(false, Ordering::SeqCst) {
            // The Win32 event was signaled; clear the flag and report readiness.
            Poll::Ready(Some(Ok(())))
        } else {
            Poll::Pending
        }
    }
}

impl FusedStream for Win32EventStream {
    fn is_terminated(&self) -> bool {
        false
    }
}

/// Win32 event notifications
struct Win32EventNotification {
    win32_event: HANDLE,               // The Win32 event handle.
    wait_object: HANDLE,               // The wait object handle.
    callback: *mut Win32EventCallback, // A pointer to the Win32 event callback function.
}

/// Implementing the Debug trait for the Win32EventNotification struct.
impl std::fmt::Debug for Win32EventNotification {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Win32EventNotification: {:?}", self.wait_object)
    }
}

type Win32EventCallback = Box<dyn Fn(bool) + Send>; // A type alias for the Win32 event callback function.

impl Win32EventNotification {
    /// Register for Win32 event notifications.
    fn new(win32_event: HANDLE, cb: Win32EventCallback) -> Result<Self> {
        // Defining the global callback function for the Win32 event.
        unsafe extern "system" fn global_callback(caller_context: *mut c_void, time_out: bool) {
            (**(caller_context as *mut Win32EventCallback))(time_out)
        }

        let callback = Box::into_raw(Box::new(cb)); // Creating a raw pointer to the callback function.
        let mut wait_object: HANDLE = HANDLE(std::ptr::null_mut());

        // Registering for Win32 event notifications.
        let rc = unsafe {
            RegisterWaitForSingleObject(
                &mut wait_object,
                win32_event,
                Some(global_callback),
                Some(callback as *const c_void),
                INFINITE,
                WT_EXECUTEINWAITTHREAD,
            )
        };

        // Check if the registration was successful.
        match rc {
            Ok(_) => Ok(Self {
                callback,
                win32_event,
                wait_object,
            }),
            Err(e) => {
                drop(unsafe { Box::from_raw(callback) }); // Dropping the callback function.
                Err(e)
            }
        }
    }
}

impl Drop for Win32EventNotification {
    /// Implementing the Drop trait for the Win32EventNotification struct.
    fn drop(&mut self) {
        // Deregister the wait and *block until any in-flight callback has finished*. Passing
        // `INVALID_HANDLE_VALUE` as the completion event makes `UnregisterWaitEx` wait for
        // outstanding callbacks to complete before returning. Only once that succeeds is it
        // safe to free the callback box and close the event.
        //
        // Passing the event handle itself (as the original code did) merely asks the OS to
        // signal that event on completion *without* waiting; tearing down a registered wait
        // while it is still pending is explicitly undefined per the
        // `RegisterWaitForSingleObject` documentation.
        match unsafe { UnregisterWaitEx(self.wait_object, Some(INVALID_HANDLE_VALUE)) } {
            Ok(()) => {
                // The wait is gone and no callback can be running, so the boxed callback can be
                // dropped and the event handle closed safely.
                drop(unsafe { Box::from_raw(self.callback) });
                let _ = unsafe { CloseHandle(self.win32_event) };
            }
            Err(_e) => {
                // Deregistration failed, so we cannot prove that the wait is gone or that no
                // callback is (or will later be) running. Freeing the callback box or closing
                // the event here would risk a use-after-free of the callback and a
                // use-after-close of the event handle (the callback also touches the event via
                // `ResetEvent`). A leak is strictly preferable to undefined behavior, so we
                // deliberately leak both the callback allocation and the event handle on this
                // (expected-to-be-unreachable) path.
                //log::error!("error deregistering notification: {_e}");
            }
        }
    }
}

/// # Safety
/// `Win32EventNotification` is safe to send between threads because it does not
/// encompass any thread-specific data (like `std::rc::Rc` or `std::cell::RefCell`)
/// and does not provide mutable access to its data across different threads
/// (like `std::sync::Arc`).
/// The Windows API functions that we're using (`RegisterWaitForSingleObject`,
/// `UnregisterWaitEx`, and `CloseHandle`) are all thread-safe as per the
/// Windows API documentation. Our struct only contains raw pointers and handles
/// that are essentially IDs which can be freely copied and are not tied to a
/// specific thread. As such, it's safe to implement Send for this type.
unsafe impl Send for Win32EventNotification {}
