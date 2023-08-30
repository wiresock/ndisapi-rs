//! # Submodule: Fast I/O operations
//!
//! This submodule  offers methods to interact with the NDIS filter driver, allowing users to
//! initialize the fast I/O mechanism, add a secondary fast I/O shared memory sections, and forward
//! packets to the driver or to the target network interface or protocol layer. The methods in this
//! submodule are designed to be highly flexible, allowing for parameterization by the size of the shared
//! memory section or the number of packets to send. This submodule is part of the larger NDISAPI module,
//! which provides a high-level API for the Windows Packet Filter on Windows.
//!

use std::mem::size_of;

use windows::{core::Result, Win32::System::IO::DeviceIoControl};

use super::Ndisapi;
use crate::driver::*;

impl Ndisapi {
    /// This function adds a secondary Fast I/O shared memory section to the NDIS filter driver,
    /// allowing faster communication between user-mode applications and the driver.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The size of the Fast I/O shared memory section.
    ///
    /// # Arguments
    ///
    /// * `fast_io_section`: A mutable reference to a `FastIoSection<N>` object representing
    ///   the shared memory section to be added.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn add_secondary_fast_io<const N: usize>(
        &self,
        fast_io_section: &mut FastIoSection<N>,
    ) -> Result<()> {
        let params = InitializeFastIoParams::<N> {
            header_ptr: fast_io_section as *mut FastIoSection<N>,
            data_size: N as u32,
        };

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION,
                Some(&params as *const InitializeFastIoParams<N> as *const std::ffi::c_void),
                size_of::<InitializeFastIoParams<N>>() as u32,
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

    /// This function initializes the fast I/O mechanism for the NDIS filter driver and
    /// submits the initial shared memory section for faster communication between
    /// user-mode applications and the driver.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The size of the Fast I/O shared memory section.
    ///
    /// # Arguments
    ///
    /// * `fast_io_section`: A mutable reference to a `FastIoSection<N>` object representing
    ///   the shared memory section to be submitted.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn initialize_fast_io<const N: usize>(
        &self,
        fast_io_section: &mut FastIoSection<N>,
    ) -> Result<()> {
        let params = InitializeFastIoParams::<N> {
            header_ptr: fast_io_section as *mut FastIoSection<N>,
            data_size: N as u32,
        };

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_INITIALIZE_FAST_IO,
                Some(&params as *const InitializeFastIoParams<N> as *const std::ffi::c_void),
                size_of::<InitializeFastIoParams<N>>() as u32,
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

    /// This function retrieves queued packets from the NDIS filter driver without considering
    /// the network interface. It reads packets in an unsorted manner and stores them in the
    /// provided buffer.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The number of packets to read.
    ///
    /// # Arguments
    ///
    /// * `packets`: A mutable reference to an array of `IntermediateBuffer` objects, where the
    ///   read packets will be stored.
    ///
    /// # Returns
    ///
    /// * `Result<usize>`: If successful, returns `Ok(usize)` with the number of packets read.
    ///   Otherwise, returns an error.
    pub fn read_packets_unsorted<const N: usize>(
        &self,
        packets: &mut [IntermediateBuffer; N],
    ) -> Result<usize> {
        let mut request = UnsortedReadSendRequest::<N> {
            packets: packets as *mut [IntermediateBuffer; N],
            packets_num: N as u32,
        };

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_READ_PACKETS_UNSORTED,
                Some(&request as *const UnsortedReadSendRequest<N> as *const std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                Some(&mut request as *mut UnsortedReadSendRequest<N> as *mut std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                None,
                None,
            )
        } {
            Ok(_) => Ok(request.packets_num as usize),
            Err(e) => Err(e),
        }
    }

    /// This function forwards packets to the NDIS filter driver in an unsorted manner, which then
    /// sends them to the target network interface. The target adapter handle should be set in the
    /// `IntermediateBuffer.header.adapter_handle` field.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The number of packets to send.
    ///
    /// # Arguments
    ///
    /// * `packets`: A mutable reference to an array of `IntermediateBuffer` objects, which contain
    ///   the packets to be sent.
    /// * `packets_num`: The number of packets to send from the array.
    ///
    /// # Returns
    ///
    /// * `Result<usize>`: If successful, returns `Ok(usize)` with the number of packets sent.
    ///   Otherwise, returns an error.
    pub fn send_packets_to_adapters_unsorted<const N: usize>(
        &self,
        packets: &mut [IntermediateBuffer; N],
        packets_num: usize,
    ) -> Result<usize> {
        let mut request = UnsortedReadSendRequest::<N> {
            packets: packets as *mut [IntermediateBuffer; N],
            packets_num: packets_num as u32,
        };

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED,
                Some(&request as *const UnsortedReadSendRequest<N> as *const std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                Some(&mut request as *mut UnsortedReadSendRequest<N> as *mut std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                None,
                None,
            )
        } {
            Ok(_) => Ok(request.packets_num as usize),
            Err(e) => Err(e),
        }
    }

    /// This function forwards packets to the NDIS filter driver in an unsorted manner, which then
    /// sends them to the target protocols layer (MSTCP). The target adapter handle (to be indicated
    /// from) should be set in the `IntermediateBuffer.header.adapter_handle` field.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The number of packets to send.
    ///
    /// # Arguments
    ///
    /// * `packets`: A mutable reference to an array of `IntermediateBuffer` objects, which contain
    ///   the packets to be sent.
    /// * `packets_num`: The number of packets to send from the array.
    ///
    /// # Returns
    ///
    /// * `Result<usize>`: If successful, returns `Ok(usize)` with the number of packets sent.
    ///   Otherwise, returns an error.
    pub fn send_packets_to_mstcp_unsorted<const N: usize>(
        &self,
        packets: &mut [IntermediateBuffer; N],
        packets_num: usize,
    ) -> Result<usize> {
        let mut request = UnsortedReadSendRequest::<N> {
            packets: packets as *mut [IntermediateBuffer; N],
            packets_num: packets_num as u32,
        };

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED,
                Some(&request as *const UnsortedReadSendRequest<N> as *const std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                Some(&mut request as *mut UnsortedReadSendRequest<N> as *mut std::ffi::c_void),
                size_of::<UnsortedReadSendRequest<N>>() as u32,
                None,
                None,
            )
        } {
            Ok(_) => Ok(request.packets_num as usize),
            Err(e) => Err(e),
        }
    }
}
