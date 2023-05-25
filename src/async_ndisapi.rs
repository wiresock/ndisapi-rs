//! # Module: ASYNC NDISAPI
//!
//! This module contains the `NdisapiAdapter` struct, an abstraction for a network adapter that is controlled via the
//! Windows Packet Filter NDISAPI interface.
//!
//! `NdisapiAdapter` provides asynchronous methods for managing and interacting with the network adapter. This includes
//! reading and writing Ethernet packets, and adjusting adapter settings. This is achieved through the use of `async` functions,
//! which allow these operations to be performed without blocking the rest of your application.
//!
//! With the help of the NDISAPI, `NdisapiAdapter` can directly interact with the network adapter at a low level, offering finer
//! control and efficiency compared to the traditional sockets-based networking. This makes it particularly suited to tasks such as
//! packet sniffing and injection, implementing custom protocols, or interacting with the adapter in unusual ways that may not be
//! supported by the standard networking stack.
use crate::ndisapi::{self, EthPacket, FilterFlags};
use futures::StreamExt;
use std::sync::Arc;
use windows::{
    core::Result,
    Win32::{
        Foundation::{GetLastError, HANDLE, WIN32_ERROR},
        System::Threading::CreateEventW,
    },
};

use self::win32_event_stream::Win32EventStream;

// Submodules
mod win32_event_stream;

/// The struct NdisapiAdapter represents a network adapter with its associated driver and relevant handles.
pub struct NdisapiAdapter {
    /// The network driver for the adapter.
    driver: Arc<ndisapi::Ndisapi>,
    /// The handle of the network adapter.
    adapter_handle: HANDLE,
    /// A stream that resolves when a Win32 event is signaled.
    notif: Win32EventStream,
}

impl NdisapiAdapter {
    /// Constructs a new `NdisapiAdapter`.
    ///
    /// This function takes a network driver and the handle of the network adapter as arguments.
    /// It then creates a Win32 event and sets it for packet capture for the specified adapter.
    /// Finally, it creates a new `NdisapiAdapter` with the driver, adapter handle, and a
    /// `Win32EventStream` created with the event handle.
    ///
    /// # Arguments
    ///
    /// * `driver` - An `Arc<ndisapi::Ndisapi>` that represents the network driver for the adapter.
    /// * `adapter_handle` - A `HANDLE` that represents the handle of the network adapter.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the FFI call to `CreateEventW`
    /// and the potential for a null or invalid adapter handle. The caller should ensure that
    /// the passed network driver and the adapter handle are properly initialized and safe
    /// to use in this context.
    ///
    /// # Errors
    ///
    /// Returns an error if the Win32 event creation fails, or if setting the packet capture event for
    /// the adapter fails, or if creating the `Win32EventStream` fails.
    ///
    /// # Returns
    ///
    /// Returns an `Ok(Self)` if the `NdisapiAdapter` is successfully created, where `Self` is
    /// the newly created `NdisapiAdapter`.
    pub fn new(
        driver: Arc<ndisapi::Ndisapi>, // The network driver for the adapter.
        adapter_handle: HANDLE,        // The handle of the network adapter.
    ) -> Result<Self> {
        let event_handle = unsafe {
            // Creating a Win32 event without a name. The event is manual-reset and initially non-signaled.
            CreateEventW(None, true, false, None)?
        };

        // Setting the event for packet capture for the specified adapter.
        driver.set_packet_event(adapter_handle, event_handle)?;

        Ok(Self {
            adapter_handle,
            driver,
            notif: Win32EventStream::new(event_handle)?, // Creating a new Win32EventStream with the event handle.
        })
    }

    /// Sets the operating mode for the network adapter.
    ///
    /// This function takes a set of `FilterFlags` as an argument which represent the desired
    /// operating mode, and applies them to the network adapter.
    ///
    /// # Arguments
    ///
    /// * `flags` - `FilterFlags` that represent the desired operating mode for the network adapter.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to set the operating mode for the network adapter.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the operating mode was successfully set for the network adapter.
    pub fn set_adapter_mode(&self, flags: FilterFlags) -> Result<()> {
        self.driver.set_adapter_mode(self.adapter_handle, flags)?;
        Ok(())
    }

    /// Reads a packet from the network adapter asynchronously and returns it as an `EthPacket`.
    ///
    /// This function initializes an `EthRequest` with the provided `EthPacket` and the handle to the adapter.
    /// Then it attempts to read a packet from the network adapter. If the read operation fails,
    /// the function awaits the next event from the `Win32EventStream` before attempting the read operation again.
    ///
    /// # Arguments
    ///
    /// * `packet` - An `EthPacket` which will be filled with the data from the network adapter.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the FFI calls to `driver.read_packet(&request)`
    /// and the call to `GetLastError()`. Ensure the passed `EthPacket` is properly initialized
    /// and safe to use in this context.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to read a packet from the network adapter, or if the
    /// await operation on the event stream fails. The specific error returned in the first case is the
    /// last error occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns an `Ok(EthPacket)` if the packet is successfully read from the network adapter,
    /// where `EthPacket` is the original packet filled with the data from the network adapter.
    pub async fn read_packet(&mut self, packet: EthPacket) -> Result<EthPacket> {
        let driver = self.driver.clone();

        // Initialize EthPacket to pass to driver API.
        let mut request = ndisapi::EthRequest {
            adapter_handle: self.adapter_handle,
            packet,
        };

        // First try to read packet
        if unsafe { driver.read_packet(&mut request) }.is_ok() {
            return Ok(packet);
        }

        // Wait for packet event
        match self.notif.next().await {
            Some(result) => match result {
                Ok(_) => {
                    if unsafe { driver.read_packet(&mut request) }.is_ok() {
                        Ok(packet)
                    } else {
                        Err(unsafe { GetLastError() }.into())
                    }
                }
                Err(e) => Err(e),
            },
            None => {
                // The stream is exhausted. This should never happen in our case.
                Err(WIN32_ERROR(0u32).into())
            }
        }
    }

    /// Reads a number of packets from the network adapter asynchronously and returns the number of packets read.
    ///
    /// This function initializes an `EthMRequest` with the provided array of `EthPacket`s and the handle to the adapter.
    /// Then it attempts to read packets from the network adapter. If the read operation fails, the function awaits a packet event
    /// before attempting the read operation again.
    ///
    /// # Arguments
    ///
    /// * `packets` - A slice of `EthPacket`s which will be filled with the data from the network adapter.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the FFI calls to `driver.read_packets(&mut request)` and the call to `GetLastError()`.
    /// Ensure the passed `EthPacket`s are properly initialized and safe to use in this context.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The compile-time constant representing the maximum size of the `EthMRequest`.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to read packets from the network adapter, or if the await operation on the packet event fails.
    /// The specific error returned in the first case is the last error occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns an `Ok(usize)` if the packets are successfully read from the network adapter, where `usize` is the number of packets read.
    pub async fn read_packets<const N: usize>(&mut self, packets: &[EthPacket]) -> Result<usize> {
        let driver = self.driver.clone();

        // Initialize EthMPacket to pass to driver API.
        let mut request = ndisapi::EthMRequest::<N>::new(self.adapter_handle);

        // Push packets to request
        request.push_slice(packets)?;

        // first try to read packets
        if unsafe { driver.read_packets(&mut request) }.is_ok() {
            return Ok(request.get_packet_success() as usize);
        }

        // Wait for packet event
        match self.notif.next().await {
            Some(result) => match result {
                Ok(_) => {
                    if unsafe { driver.read_packets(&mut request) }.ok().is_some() {
                        Ok(request.get_packet_success() as usize)
                    } else {
                        Err(unsafe { GetLastError() }.into())
                    }
                }
                Err(e) => Err(e),
            },
            None => {
                // The stream is exhausted. This should never happen in our case.
                Err(WIN32_ERROR(0u32).into())
            }
        }
    }

    /// Sends an Ethernet packet to the network adapter.
    ///
    /// This function takes an `EthPacket` as an argument and passes it to the network adapter.
    /// This is achieved by creating an `EthRequest` structure which contains the `EthPacket`
    /// and the handle to the adapter, and then passing this request to the driver API.
    ///
    /// # Arguments
    ///
    /// * `packet` - An `EthPacket` that represents the Ethernet packet to be sent.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe due to the FFI call to `self.driver.send_packet_to_adapter(&request)`
    /// and the call to `GetLastError()`. Caller should ensure that the passed `EthPacket` is properly
    /// initialized and safe to use in this context.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to send the packet to the network adapter. The specific error
    /// returned is the last error occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packet was successfully sent to the network adapter.
    pub fn send_packet_to_adapter(&self, packet: EthPacket) -> Result<()> {
        // Initialize EthPacket to pass to driver API.
        let request = ndisapi::EthRequest {
            adapter_handle: self.adapter_handle,
            packet,
        };

        // Try to send packet to the network adapter.
        if unsafe { self.driver.send_packet_to_adapter(&request) }.is_ok() {
            Ok(())
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    /// Sends a number of packets to the network adapter synchronously and returns the number of packets sent.
    ///
    /// This function initializes an `EthMRequest` with the provided array of `EthPacket`s and the handle to the adapter.
    /// Then it attempts to send packets to the network adapter.
    ///
    /// # Arguments
    ///
    /// * `packets` - A slice of `EthPacket`s which will be sent to the network adapter.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the FFI calls to `self.driver.send_packets_to_adapter(&request)`
    /// and the call to `GetLastError()`. Ensure the passed `EthPacket`s are properly initialized and safe to use in this context.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The compile-time constant representing the maximum size of the `EthMRequest`.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to send packets to the network adapter.
    /// The specific error returned is the last error occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns an `Ok(usize)` if the packets are successfully sent to the network adapter,
    /// where `usize` is the number of packets sent.
    pub fn send_packets_to_adapter<const N: usize>(
        &mut self,
        packets: &[EthPacket],
    ) -> Result<usize> {
        // Initialize EthMPacket to pass to driver API.
        let mut request = ndisapi::EthMRequest::<N>::new(self.adapter_handle);

        for packet in packets {
            request.push(*packet)?;
        }

        // Try to send packets to the network adapter.
        if unsafe { self.driver.send_packets_to_adapter(&request) }.is_ok() {
            Ok(request.get_packet_success() as usize)
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    /// Sends an Ethernet packet upwards the network stack to the Microsoft TCP/IP protocol driver.
    ///
    /// This function takes an `EthPacket` as an argument and sends it upwards the network stack.
    /// This is accomplished by creating an `EthRequest` structure which contains the `EthPacket`
    /// and the handle to the adapter, and then passing this request to the driver API.
    ///
    /// # Arguments
    ///
    /// * `packet` - An `EthPacket` that represents the Ethernet packet to be sent.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe due to the FFI call to `self.driver.send_packet_to_mstcp(&request)`
    /// and the call to `GetLastError()`. Ensure that the passed `EthPacket` is properly initialized
    /// and safe to use in this context.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to send the packet upwards the network stack. The specific error
    /// returned is the last error occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packet was successfully sent upwards the network stack.
    pub fn send_packet_to_mstcp(&self, packet: EthPacket) -> Result<()> {
        // Initialize EthPacket to pass to driver API.
        let request = ndisapi::EthRequest {
            adapter_handle: self.adapter_handle,
            packet,
        };

        // Try to send packet upwards the network stack.
        if unsafe { self.driver.send_packet_to_mstcp(&request) }.is_ok() {
            Ok(())
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    /// Sends a number of packets upwards the network stack synchronously and returns the number of packets sent.
    ///
    /// This function initializes an `EthMRequest` with the provided array of `EthPacket`s and the handle to the adapter.
    /// Then it attempts to send packets to the network stack.
    ///
    /// # Arguments
    ///
    /// * `packets` - A slice of `EthPacket`s which will be sent upwards the network stack.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the FFI calls to `self.driver.send_packets_to_mstcp(&request)`
    /// and the call to `GetLastError()`. Ensure the passed `EthPacket`s are properly initialized and safe to use in this context.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The compile-time constant representing the maximum size of the `EthMRequest`.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to send packets to the network stack.
    /// The specific error returned is the last error occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns an `Ok(usize)` if the packets are successfully sent to the network stack,
    /// where `usize` is the number of packets sent.
    pub fn send_packets_to_mstcp<const N: usize>(
        &mut self,
        packets: &[EthPacket],
    ) -> Result<usize> {
        // Initialize EthMPacket to pass to driver API.
        let mut request = ndisapi::EthMRequest::<N>::new(self.adapter_handle);

        for packet in packets {
            request.push(*packet)?;
        }

        // Try to send packets upwards the network stack.
        if unsafe { self.driver.send_packets_to_mstcp(&request) }.is_ok() {
            Ok(request.get_packet_success() as usize)
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }
}

// Implementing the Drop trait for the NdisapiAdapter struct.
impl Drop for NdisapiAdapter {
    /// The drop method will be called automatically when the NdisapiAdapter object goes out of scope.
    fn drop(&mut self) {
        // Setting the operating mode for the specified adapter to default.
        _ = self
            .driver
            .set_adapter_mode(self.adapter_handle, FilterFlags::from_bits_truncate(0));

        // Setting the packet event for the specified adapter to NULL.
        _ = self
            .driver
            .set_packet_event(self.adapter_handle, HANDLE(0isize));
    }
}
