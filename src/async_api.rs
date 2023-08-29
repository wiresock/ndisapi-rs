//! # Module: ASYNC NDISAPI
//!
//! This module contains the `AsyncNdisapiAdapter` struct, an abstraction for a network adapter that is controlled via the
//! Windows Packet Filter NDISAPI interface.
//!
//! `AsyncNdisapiAdapter` provides asynchronous methods for managing and interacting with the network adapter. This includes
//! reading and writing Ethernet packets, and adjusting adapter settings. This is achieved through the use of `async` functions,
//! which allow these operations to be performed without blocking the rest of your application.
//!
//! With the help of the NDISAPI, `AsyncNdisapiAdapter` can directly interact with the network adapter at a low level, offering finer
//! control and efficiency compared to the traditional sockets-based networking. This makes it particularly suited to tasks such as
//! packet sniffing and injection, implementing custom protocols, or interacting with the adapter in unusual ways that may not be
//! supported by the standard networking stack.
use crate::{
    ndisapi::{self, FilterFlags},
    IntermediateBuffer,
};
use futures::StreamExt;
use std::sync::Arc;
use windows::{
    core::Result,
    Win32::{
        Foundation::{HANDLE, WIN32_ERROR},
        System::Threading::CreateEventW,
    },
};

use self::win32_event_stream::Win32EventStream;

// Submodules
mod win32_event_stream;

/// The struct AsyncNdisapiAdapter represents a network adapter with its associated driver and relevant handles.
pub struct AsyncNdisapiAdapter {
    /// The network driver for the adapter.
    driver: Arc<ndisapi::Ndisapi>,
    /// The handle of the network adapter.
    adapter_handle: HANDLE,
    /// A stream that resolves when a Win32 event is signaled.
    notif: Win32EventStream,
}

impl AsyncNdisapiAdapter {
    /// Constructs a new `AsyncNdisapiAdapter`.
    ///
    /// This function takes a network driver and the handle of the network adapter as arguments.
    /// It then creates a Win32 event and sets it for packet capture for the specified adapter.
    /// Finally, it creates a new `AsyncNdisapiAdapter` with the driver, adapter handle, and a
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
    /// Returns an `Ok(Self)` if the `AsyncNdisapiAdapter` is successfully created, where `Self` is
    /// the newly created `AsyncNdisapiAdapter`.
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

    /// Asynchronously reads a packet from the network adapter, filling the provided `IntermediateBuffer`.
    ///
    /// This function initializes an `EthRequest` with the handle to the adapter and the provided `IntermediateBuffer`.
    /// Then it tries to read a packet from the network adapter. If the initial read operation fails,
    /// the function awaits the next event from the `Win32EventStream` before retrying the read operation.
    ///
    /// # Arguments
    ///
    /// * `packet` - An `IntermediateBuffer` which will be filled with the data from the network adapter if a packet is successfully read.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the FFI call to `GetLastError()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to read a packet from the network adapter, or if the
    /// await operation on the event stream fails. In case of driver failure, the specific error returned is the
    /// last occurred error, retrieved via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packet is successfully read from the network adapter.
    pub async fn read_packet(&mut self, packet: &mut IntermediateBuffer) -> Result<()> {
        let driver = self.driver.clone();

        // Initialize EthPacket to pass to driver API
        let mut request = ndisapi::EthRequest::new(self.adapter_handle);
        request.set_packet(packet);

        // First try to read packet
        if driver.read_packet(&mut request).is_ok() {
            return Ok(());
        }

        // Wait for packet event
        match self.notif.next().await {
            Some(result) => match result {
                Ok(_) => match driver.read_packet(&mut request) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            None => {
                // The stream is exhausted. This should never happen in our case.
                Err(WIN32_ERROR(0u32).into())
            }
        }
    }

    /// Asynchronously reads a number of packets from the network adapter and returns the number of packets successfully read.
    ///
    /// This function creates an `EthMRequest` with the provided `IntermediateBuffer`s and the handle to the adapter.
    /// It then attempts to read packets from the network adapter. If the initial read operation fails,
    /// the function waits for a packet event before retrying the read operation.
    ///
    /// # Arguments
    ///
    /// * `packets` - An iterator over `&mut IntermediateBuffer` which will be filled with the data from the network adapter if packets are successfully read.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the FFI call to `GetLastError()`.
    ///
    /// # Type Parameters
    ///
    /// * `N`: A compile-time constant representing the maximum size of the `EthMRequest`.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to read packets from the network adapter, or if the await operation on the packet event fails.
    /// In case of driver failure, the specific error returned is the last occurred error, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(usize)` if packets are successfully read from the network adapter, where `usize` is the number of packets read.
    pub async fn read_packets<'a, const N: usize, I>(&mut self, packets: I) -> Result<usize>
    where
        I: Iterator<Item = &'a mut IntermediateBuffer>,
    {
        let driver = self.driver.clone();

        // Initialize EthMPacket to pass to driver API.
        let mut request = ndisapi::EthMRequest::<N>::from_iter(self.adapter_handle, packets);

        // first try to read packets
        if driver.read_packets(&mut request).is_ok() {
            return Ok(request.get_packet_success() as usize);
        }

        // Wait for packet event
        match self.notif.next().await {
            Some(result) => match result {
                Ok(_) => match driver.read_packets(&mut request) {
                    Ok(_) => Ok(request.get_packet_success() as usize),
                    Err(err) => Err(err),
                },
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
    /// This function takes an `IntermediateBuffer` as an argument, wraps it into an `EthPacket`,
    /// and sends it to the network adapter. This is accomplished by creating an `EthRequest`
    /// structure, which includes the `EthPacket` and the handle to the adapter. This request
    /// is then passed to the driver API for transmission.
    ///
    /// # Arguments
    ///
    /// * `packet` - An `IntermediateBuffer` that will be encapsulated in an `EthPacket`
    /// representing the Ethernet packet to be sent.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the FFI call to `GetLastError()`.
    /// Ensure that the `IntermediateBuffer` passed as argument is properly initialized
    /// and safe to use in this context.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver fails to send the packet to the network adapter.
    /// The specific error returned is the last occurred error, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packet is successfully sent to the network adapter.
    pub fn send_packet_to_adapter(&self, packet: &mut IntermediateBuffer) -> Result<()> {
        // Initialize EthPacket to pass to driver API.
        let mut request = ndisapi::EthRequest::new(self.adapter_handle);
        request.set_packet(packet);

        // Try to send packet to the network adapter.
        self.driver.send_packet_to_adapter(&request)
    }

    /// Sends a specified number of Ethernet packets to the network adapter synchronously.
    ///
    /// This function initializes an `EthMRequest` object using an iterator over `IntermediateBuffer` objects and the handle to the network adapter.
    /// It then attempts to send these packets to the network adapter. If the sending process fails, an error is returned.
    ///
    /// # Arguments
    ///
    /// * `packets` - An iterator over mutable references to `IntermediateBuffer` objects that contain the Ethernet packets to be sent to the network adapter.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the Foreign Function Interface (FFI) call to `GetLastError()`. Ensure that the input `IntermediateBuffer` objects are properly initialized and safe to use in this context.
    ///
    /// # Type Parameters
    ///
    /// * `N`: A compile-time constant that determines the maximum size of the `EthMRequest` object.
    /// * `I`: The type of the iterator over `IntermediateBuffer` objects.
    ///
    /// # Errors
    ///
    /// This function returns an error if the driver fails to send packets to the network adapter.
    /// The specific error returned is the last error occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// On successful operation, this function returns an `Ok(usize)` that represents the number of packets successfully sent to the network adapter. If the operation fails, an error is returned.
    pub fn send_packets_to_adapter<'a, const N: usize, I>(&mut self, packets: I) -> Result<usize>
    where
        I: Iterator<Item = &'a mut IntermediateBuffer>,
    {
        // Initialize EthMPacket to pass to driver API.
        let request = ndisapi::EthMRequest::<N>::from_iter(self.adapter_handle, packets);

        // Try to send packets to the network adapter.
        match self.driver.send_packets_to_adapter(&request) {
            Ok(_) => Ok(request.get_packet_success() as usize),
            Err(err) => Err(err),
        }
    }

    /// Sends an Ethernet packet upwards through the network stack to the Microsoft TCP/IP protocol driver.
    ///
    /// This function creates an `EthRequest` object with the `EthPacket` to be sent and the handle to the network adapter.
    /// This `EthRequest` is then passed to the driver API to send the packet upwards through the network stack.
    ///
    /// # Arguments
    ///
    /// * `packet` - A mutable reference to an `IntermediateBuffer` that represents the Ethernet packet to be sent.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe due to the Foreign Function Interface (FFI) call to `GetLastError()`. Ensure that the input `IntermediateBuffer` is properly initialized and safe to use in this context.
    ///
    /// # Errors
    ///
    /// This function returns an error if the driver fails to send the packet upwards through the network stack. The specific error returned is the last error that occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// On successful operation, this function returns `Ok(())`. If the operation fails, an error is returned.
    pub fn send_packet_to_mstcp(&self, packet: &mut IntermediateBuffer) -> Result<()> {
        // Initialize EthPacket to pass to driver API.
        let mut request = ndisapi::EthRequest::new(self.adapter_handle);
        request.set_packet(packet);

        // Try to send packet upwards the network stack.
        self.driver.send_packet_to_mstcp(&request)
    }

    /// Sends a sequence of Ethernet packets upwards through the network stack to the Microsoft TCP/IP protocol driver synchronously.
    ///
    /// This function creates an `EthMRequest` object with the provided iterator over `IntermediateBuffer`s and the handle to the network adapter.
    /// It then tries to send these packets upwards through the network stack.
    ///
    /// # Arguments
    ///
    /// * `packets` - An iterator over mutable references to `IntermediateBuffer`s representing the Ethernet packets to be sent.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe due to the Foreign Function Interface (FFI) call to `GetLastError()`. Ensure that the input `IntermediateBuffer`s are properly initialized and safe to use in this context.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The compile-time constant specifying the maximum size of the `EthMRequest`.
    /// * `I`: The type of the iterator over `IntermediateBuffer` objects.
    ///
    /// # Errors
    ///
    /// This function returns an error if the driver fails to send the packets upwards through the network stack. The specific error returned is the last error that occurred, obtained via a call to `GetLastError()`.
    ///
    /// # Returns
    ///
    /// On successful operation, this function returns `Ok(usize)`, where `usize` is the number of packets sent. If the operation fails, an error is returned.
    pub fn send_packets_to_mstcp<'a, const N: usize, I>(&mut self, packets: I) -> Result<usize>
    where
        I: Iterator<Item = &'a mut IntermediateBuffer>,
    {
        // Initialize EthMPacket to pass to driver API.
        let request = ndisapi::EthMRequest::<N>::from_iter(self.adapter_handle, packets);

        // Try to send packets upwards the network stack.
        match self.driver.send_packets_to_mstcp(&request) {
            Ok(_) => Ok(request.get_packet_success() as usize),
            Err(err) => Err(err),
        }
    }
}

// Implementing the Drop trait for the AsyncNdisapiAdapter struct.
impl Drop for AsyncNdisapiAdapter {
    /// The drop method will be called automatically when the AsyncNdisapiAdapter object goes out of scope.
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
