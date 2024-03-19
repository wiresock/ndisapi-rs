//! # Module: NDISAPI
//!
//! This module provides a high-level interface to the NDISAPI Rust library for communicating with the Windows Packet Filter driver.
//! It includes the definition and implementation of the `Ndisapi` struct, which represents the main entry point to interact with the driver.
//!
//! The NDISAPI module also contains submodules for various aspects of the NDISAPI functionality, such as:
//! - base_api: Basic API operations
//! - defs: Definitions of constants, structures, and enumerations
//! - fastio_api: Fast I/O operations
//! - filters_api: Filter management and manipulation
//! - io_api: Basic I/O operations
//! - static_api: Static and Registry related methods for the NDISAPI
//!
//! For a detailed description of each submodule and the `Ndisapi` struct, refer to their respective documentation within the module.

// Imports required dependencies
use windows::{
    core::{Result, PCWSTR},
    Win32::Foundation::CloseHandle,
    Win32::Foundation::HANDLE,
    Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
};

// Submodules
mod base_api;
mod defs;
mod fastio_api;
mod filters_api;
mod io_api;
mod static_api;

// Re-exports the `driver` submodule
pub use crate::driver::*;

// Re-export already public members in `defs.rs`
pub use crate::ndisapi::defs::{NetworkAdapterInfo, Version};

// Re-export already public members in `fastio_api.rs`
pub use crate::ndisapi::fastio_api::{IntermediateBufferArray, IntermediateBufferArrayMut};

/// The `Ndisapi` struct represents an instance of the NDIS filter driver that provides access to network adapters and packets.
///
/// This struct is used to communicate with the NDIS filter driver and access its functionalities. It contains a single field, `driver_handle`,
/// which represents a handle to the driver. This handle is used to perform operations such as reading and writing packets, setting filters, and
/// getting information about network adapters.
///
/// To use `Ndisapi`, you should first create an instance of the struct by calling the `Ndisapi::new()` function. This will return a `Result`
/// that contains an instance of `Ndisapi` if the operation was successful, or an error if it failed. Once you have an instance of `Ndisapi`,
/// you can call its methods to perform various network-related operations.
///
/// For example, you can use the `Ndisapi::read_packets()` method to read packets from the network adapter, or the `Ndisapi::send_packets_to_adapter()`
/// method to write packets to the network adapter. You can also use the `Ndisapi::set_packet_filter_table()` method to set a filter that specifies which
/// packets should be captured or dropped.
#[derive(Debug, Clone)]
pub struct Ndisapi {
    // Represents a handle to the NDIS filter driver.
    driver_handle: HANDLE,
    // Stores the driver registry key for parameters
    registry_key: Vec<u16>,
}

// Implements the Drop trait for the `Ndisapi` struct
impl Drop for Ndisapi {
    // Provides a custom implementation for the `drop` method
    fn drop(&mut self) {
        // Closes the driver_handle when the `Ndisapi` instance goes out of scope
        let _ = unsafe { CloseHandle(self.driver_handle) };
    }
}

// Implements additional methods for the `Ndisapi` struct
impl Ndisapi {
    /// Initializes new Ndisapi instance opening the NDIS filter driver
    ///
    /// # Arguments
    ///
    /// * `driver_name` - The name of the file representing the NDIS filter driver.
    ///
    /// # Returns
    ///
    /// * `Result<Self>` - A Result containing the Ndisapi instance if successful, or an error if not.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ndisapi::Ndisapi;
    /// let ndisapi = Ndisapi::new("NDISRD").unwrap();
    /// ```
    pub fn new(driver_name: &str) -> Result<Self> {
        // Create the filename and driver parameters registry path
        let filename = format!(r"\\.\{driver_name}");
        let registry_key = format!(r"SYSTEM\CurrentControlSet\Services\{driver_name}\Parameters");
        let mut filename: Vec<u16> = filename.encode_utf16().collect();
        let mut registry_key: Vec<u16> = registry_key.encode_utf16().collect();
        filename.push(0);
        registry_key.push(0);

        // Attempts to create a file handle for the NDIS filter driver
        match unsafe {
            CreateFileW(
                PCWSTR::from_raw(filename.as_ptr()),
                0u32,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        } {
            Ok(driver_handle) => Ok(Self {
                driver_handle,
                registry_key,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn get_driver_registry_key(&self) -> PCWSTR {
        PCWSTR::from_raw(self.registry_key.as_ptr())
    }
}
