use windows::{
    core::{InParam, Result, PCWSTR},
    Win32::Foundation::CloseHandle,
    Win32::Foundation::{GetLastError, HANDLE},
    Win32::Storage::FileSystem::{
        CreateFileW, FILE_ACCESS_FLAGS, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    },
};

// Submodules
mod baseapi;
mod defs;
mod fastio;
mod filters;
mod io;
mod statics;

pub use crate::driver::*;

pub struct Ndisapi {
    driver_handle: HANDLE,
}

impl Drop for Ndisapi {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.driver_handle);
        }
    }
}

impl Ndisapi {
    /// Initializes new Ndisapi instance opening the NDIS filter driver
    pub fn new<P>(filename: P) -> Result<Self>
    where
        P: Into<InParam<PCWSTR>>,
    {
        if let Ok(handle) = unsafe {
            CreateFileW(
                filename,
                FILE_ACCESS_FLAGS(0u32),
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        } {
            Ok(Self {
                driver_handle: handle,
            })
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }
}
