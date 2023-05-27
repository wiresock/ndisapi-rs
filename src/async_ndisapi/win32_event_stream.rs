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
        Foundation::{CloseHandle, GetLastError, BOOLEAN, HANDLE},
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

        Ok(Self {
            waker: waker.clone(),
            ready: ready.clone(),
            notif: Win32EventNotification::new(
                event_handle,
                Box::new(move |_| {
                    ready.store(true, Ordering::SeqCst);
                    waker.wake();
                    unsafe { ResetEvent(event_handle) };
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

        if this.ready.swap(false, Ordering::Relaxed) {
            // The Win32 event is ready, so we clear the ready flag and wake the waker, if present.
            // Then we reset the event to non-signaled state.
            // We signal readiness by returning `Poll::Ready`.
            Poll::Ready(Some(Ok(())))
        } else {
            // The Win32 event is not ready, so we register the waker and return `Poll::Pending`.
            this.waker.register(cx.waker());
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

type Win32EventCallback = Box<dyn Fn(BOOLEAN) + Send>; // A type alias for the Win32 event callback function.

impl Win32EventNotification {
    /// Register for Win32 event notifications.
    fn new(win32_event: HANDLE, cb: Win32EventCallback) -> Result<Self> {
        // Defining the global callback function for the Win32 event.
        unsafe extern "system" fn global_callback(caller_context: *mut c_void, time_out: BOOLEAN) {
            (**(caller_context as *mut Win32EventCallback))(time_out)
        }

        let callback = Box::into_raw(Box::new(cb)); // Creating a raw pointer to the callback function.
        let mut wait_object: HANDLE = HANDLE(0isize);

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
        if rc.as_bool() {
            Ok(Self {
                callback,
                win32_event,
                wait_object,
            })
        } else {
            drop(unsafe { Box::from_raw(callback) }); // Dropping the callback function.
            Err(unsafe { GetLastError() }.into())
        }
    }
}

impl Drop for Win32EventNotification {
    /// Implementing the Drop trait for the Win32EventNotification struct.
    fn drop(&mut self) {
        unsafe {
            // Deregistering the wait object.
            if !UnregisterWaitEx(self.wait_object, self.win32_event).as_bool() {
                //log::error!("error deregistering notification: {}", GetLastError);
            }
            drop(Box::from_raw(self.callback)); // Dropping the callback function.
        }

        unsafe {
            // Closing the handle to the event.
            CloseHandle(self.win32_event);
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
