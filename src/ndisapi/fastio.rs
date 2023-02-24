use std::mem::size_of;

use windows::{core::Result, Win32::Foundation::GetLastError, Win32::System::IO::DeviceIoControl};

use super::Ndisapi;
use crate::driver::*;

impl Ndisapi {
    /// Adds Secondary Fast I/O shared memory section
    pub fn add_secondary_fast_io<const N: usize>(
        &self,
        fast_io_section: &mut FastIoSection<N>,
    ) -> Result<()> {
        let params = InitializeFastIoParams::<N> {
            header_ptr: fast_io_section as *mut FastIoSection<N>,
            data_size: N as u32,
        };

        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// Initializes the fast i/o and submits the initial shared memory section into the NDIS filter driver
    pub fn initialize_fast_io<const N: usize>(
        &self,
        fast_io_section: &mut FastIoSection<N>,
    ) -> Result<()> {
        let params = InitializeFastIoParams::<N> {
            header_ptr: fast_io_section as *mut FastIoSection<N>,
            data_size: N as u32,
        };

        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// Reads the bunch of queued packets from the device NDIS filter driver (regardless of the network interface)
    pub fn read_packets_unsorted<const N: usize>(
        &self,
        packets: &mut [IntermediateBuffer; N],
    ) -> Result<usize> {
        let mut request = UnsortedReadSendRequest::<N> {
            packets: packets as *mut [IntermediateBuffer; N],
            packets_num: N as u32,
        };

        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(request.packets_num as usize)
        }
    }

    /// Sends the bunch of packets to the device NDIS filter driver to forward to the network interface. Please note that target
    /// adapter handle should be set in the IntermediateBuffer.header.adapter_handle
    pub fn send_packets_to_adapters_unsorted<const N: usize>(
        &self,
        packets: &mut [IntermediateBuffer; N],
        packets_num: usize,
    ) -> Result<usize> {
        let mut request = UnsortedReadSendRequest::<N> {
            packets: packets as *mut [IntermediateBuffer; N],
            packets_num: packets_num as u32,
        };

        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(request.packets_num as usize)
        }
    }

    /// Sends the bunch of packets to the device NDIS filter driver to forward to the protocols layer(mstcp). Please note that target
    /// adapter handle (to be indicated from) should be set in the IntermediateBuffer.header.adapter_handle
    pub fn send_packets_to_mstcp_unsorted<const N: usize>(
        &self,
        packets: &mut [IntermediateBuffer; N],
        packets_num: usize,
    ) -> Result<usize> {
        let mut request = UnsortedReadSendRequest::<N> {
            packets: packets as *mut [IntermediateBuffer; N],
            packets_num: packets_num as u32,
        };

        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(request.packets_num as usize)
        }
    }
}
