//! # Submodule: I/O functions
//!
//! This submodule defines a set of functions that interact with the NDIS filter driver.
//! These functions include clearing the packet queue associated with a network adapter,
//! retrieving the number of packets currently queued in the packet queue, reading single
//! or multiple network packets from the NDIS filter driver, and sending single or multiple
//! network packets to the NDIS filter driver to be passed down or up the network stack.
//! This submodule also provides a function to set a Win32 event to be signaled by the
//! NDIS filter when packets are available for read on a network adapter.
//!

use std::mem::size_of;

use windows::{core::Result, Win32::Foundation::HANDLE, Win32::System::IO::DeviceIoControl};

use super::Ndisapi;
use crate::driver::*;

impl Ndisapi {
    /// This function clears the packet queue associated with the specified network adapter
    /// handle in the NDIS filter driver.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle: HANDLE`: The handle of the network adapter whose packet queue
    ///   should be flushed.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn flush_adapter_packet_queue(&self, adapter_handle: HANDLE) -> Result<()> {
        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE,
                Some(&adapter_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
                None,
                0,
                None,
                None,
            )
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This function retrieves the number of packets currently queued in the packet queue associated with the
    /// specified network adapter handle in the NDIS filter driver.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle: HANDLE`: The handle of the network adapter whose packet queue size should be queried.
    ///
    /// # Returns
    ///
    /// * `Result<u32>`: If successful, returns `Ok(queue_size)` where `queue_size` is the number of packets in the
    ///   adapter's packet queue. Otherwise, returns an error.
    pub fn get_adapter_packet_queue_size(&self, adapter_handle: HANDLE) -> Result<u32> {
        let mut queue_size = 0u32;

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_ADAPTER_QUEUE_SIZE,
                Some(&adapter_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
                Some(&mut queue_size as *mut u32 as *mut std::ffi::c_void),
                size_of::<u32>() as u32,
                None,
                None,
            )
        } {
            Ok(_) => Ok(queue_size),
            Err(e) => Err(e),
        }
    }

    /// This function retrieves a single network packet from the NDIS filter driver associated with
    /// the specified `EthRequestMut`.
    ///
    /// # Arguments
    ///
    /// * `packet: &mut EthRequestMut`: A mutable reference to the `EthRequestMut` structure that will be filled with
    ///   the retrieved packet data.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn read_packet(&self, packet: &mut EthRequestMut) -> Result<()> {
        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_READ_PACKET,
                Some(packet as *const EthRequestMut as *const std::ffi::c_void),
                size_of::<EthRequestMut>() as u32,
                None,
                0u32,
                None,
                None,
            )
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This function retrieves a block of network packets from the NDIS filter driver associated with
    /// the specified `EthMRequestMut<N>`.
    ///
    /// # Arguments
    ///
    /// * `packets: &mut EthMRequestMut<N>`: A mutable reference to the `EthMRequestMut<N>` structure that will be filled with
    ///   the retrieved packet data.
    ///
    /// # Returns
    ///
    /// * `Result<usize>`: If successful, returns `Ok(packet_count)` where `packet_count` is the number of packets read
    ///   into `EthMRequestMut<N>`. Otherwise, returns an error.
    pub fn read_packets<const N: usize>(&self, packets: &mut EthMRequestMut<N>) -> Result<usize> {
        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_READ_PACKETS,
                Some(packets as *const EthMRequestMut<N> as *const std::ffi::c_void),
                size_of::<EthMRequestMut<N>>() as u32,
                Some(packets as *mut EthMRequestMut<N> as *mut std::ffi::c_void),
                size_of::<EthMRequestMut<N>>() as u32,
                None,
                None,
            )
        } {
            Ok(_) => Ok(packets.get_packet_success() as usize),
            Err(e) => Err(e),
        }
    }

    /// This function sends a single network packet to the NDIS filter driver associated with
    /// the specified `EthRequest`, which will then be passed down the network stack.
    ///
    /// # Arguments
    ///
    /// * `packet: &EthRequest`: A reference to the `EthRequest` structure containing the packet data to be sent.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn send_packet_to_adapter(&self, packet: &EthRequest) -> Result<()> {
        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER,
                Some(packet as *const EthRequest as *const std::ffi::c_void),
                size_of::<EthRequest>() as u32,
                None,
                0,
                None,
                None,
            )
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This function sends a single network packet to the NDIS filter driver associated with
    /// the specified `EthRequest`, which will then be passed down the network stack to the Microsoft TCP/IP stack.
    ///
    /// # Arguments
    ///
    /// * `packet: &EthRequest`: A reference to the `EthRequest` structure containing the packet data to be sent.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn send_packet_to_mstcp(&self, packet: &EthRequest) -> Result<()> {
        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKET_TO_MSTCP,
                Some(packet as *const EthRequest as *const std::ffi::c_void),
                size_of::<EthRequest>() as u32,
                None,
                0,
                None,
                None,
            )
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This function sends a block of network packets to the NDIS filter driver associated with
    /// the specified `EthMRequest<N>`, which will then be passed down the network stack.
    ///
    /// # Arguments
    ///
    /// * `packets: &EthMRequest<N>`: A reference to the `EthMRequest<N>` structure containing the packet data to be sent.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn send_packets_to_adapter<const N: usize>(&self, packets: &EthMRequest<N>) -> Result<()> {
        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER,
                Some(packets as *const EthMRequest<N> as *const std::ffi::c_void),
                size_of::<EthMRequest<N>>() as u32,
                None,
                0,
                None,
                None,
            )
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This function sends a block of network packets to the NDIS filter driver associated with
    /// the specified `EthMRequest<N>`, which will then be passed up the network stack to the Microsoft TCP/IP stack.
    ///
    /// # Arguments
    ///
    /// * `packets: &EthMRequest<N>`: A reference to the `EthMRequest<N>` structure containing the packet data to be sent.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn send_packets_to_mstcp<const N: usize>(&self, packets: &EthMRequest<N>) -> Result<()> {
        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP,
                Some(packets as *const EthMRequest<N> as *const std::ffi::c_void),
                size_of::<EthMRequest<N>>() as u32,
                None,
                0,
                None,
                None,
            )
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This function sets a Win32 event to be signaled by the NDIS filter when it has queued packets available for read
    /// on the specified network adapter.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle: HANDLE`: The handle of the network adapter to associate the event with.
    /// * `event_handle: HANDLE`: The handle of the Win32 event to be signaled when queued packets are available.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn set_packet_event(&self, adapter_handle: HANDLE, event_handle: HANDLE) -> Result<()> {
        let adapter_event = AdapterEvent {
            adapter_handle,
            event_handle,
        };

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_EVENT,
                Some(&adapter_event as *const AdapterEvent as *const std::ffi::c_void),
                size_of::<AdapterEvent>() as u32,
                None,
                0,
                None,
                None,
            )
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
