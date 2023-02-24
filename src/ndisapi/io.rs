use std::mem::size_of;

use windows::{
    core::Result,
    Win32::Foundation::{GetLastError, HANDLE},
    Win32::System::IO::DeviceIoControl,
};

use super::Ndisapi;
use crate::driver::*;

impl Ndisapi {
    /// Flushes the packet queue in the NDIS filter driver for the requested interface.
    pub fn flush_adapter_packet_queue(&self, adapter_handle: HANDLE) -> Result<()> {
        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// Queries the adapter packet queue size for the given adapter handle
    pub fn get_adapter_packet_queue_size(&self, adapter_handle: HANDLE) -> Result<u32> {
        let mut queue_size = 0u32;

        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(queue_size)
        }
    }

    /// Reads the the single packet (IntermediateBuffer) from the driver
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthRequest.packet may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn read_packet(&self, packet: &mut EthRequest) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_READ_PACKET,
                Some(packet as *const EthRequest as *const std::ffi::c_void),
                size_of::<EthRequest>() as u32,
                Some(packet as *mut EthRequest as *mut std::ffi::c_void),
                size_of::<EthRequest>() as u32,
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

    /// Reads the block of packets (IntermediateBuffer) from the driver
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthMRequest<N>.packets may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn read_packets<const N: usize>(
        &self,
        packets: &mut EthMRequest<N>,
    ) -> Result<usize> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_READ_PACKETS,
                Some(packets as *const EthMRequest<N> as *const std::ffi::c_void),
                size_of::<EthMRequest<N>>() as u32,
                Some(packets as *mut EthMRequest<N> as *mut std::ffi::c_void),
                size_of::<EthMRequest<N>>() as u32,
                None,
                None,
            )
        };

        if result.as_bool() {
            Ok(packets.get_packet_success() as usize)
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    /// Writes the single packet (IntermediateBuffer) to the driver to be indicated downwards the network stack
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthRequest.packet may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn send_packet_to_adapter(&self, packet: &EthRequest) -> Result<()> {
        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// Writes the single packet (IntermediateBuffer) to the driver to be indicated downwards the network stack
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthRequest.packet may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn send_packet_to_mstcp(&self, packet: &EthRequest) -> Result<()> {
        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// Writes the block of packets (IntermediateBuffer) to the driver to be indicated downwards the network stack
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthMRequest<N>.packets may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn send_packets_to_adapter<const N: usize>(
        &self,
        packets: &EthMRequest<N>,
    ) -> Result<()> {
        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// Writes the block of packets (IntermediateBuffer) to the driver to be indicated upwards the network stack
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthMRequest<N>.packets may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn send_packets_to_mstcp<const N: usize>(
        &self,
        packets: &EthMRequest<N>,
    ) -> Result<()> {
        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// Associates the specified Win32 event with specified network interface.
    /// This even will be signalled by the NDIS filter when it has queued packets available for read.
    pub fn set_packet_event(&self, adapter_handle: HANDLE, event_handle: HANDLE) -> Result<()> {
        let adapter_event = AdapterEvent {
            adapter_handle,
            event_handle,
        };

        let result = unsafe {
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
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }
}
