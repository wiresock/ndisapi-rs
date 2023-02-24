use std::mem::size_of;

use windows::{core::Result, Win32::Foundation::GetLastError, Win32::System::IO::DeviceIoControl};

use super::Ndisapi;
use crate::driver::*;

impl Ndisapi {
    /// Queries static filter table from the NDIS filter driver
    pub fn get_packet_filter_table<const N: usize>(
        &self,
        filter_table: &mut StaticFilterTable<N>,
    ) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_PACKET_FILTERS,
                None,
                0,
                Some(filter_table as *mut StaticFilterTable<N> as *mut std::ffi::c_void),
                size_of::<StaticFilterTable<N>>() as u32,
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

    /// Queries static filter table from the NDIS filter driver and resets the filter statistics
    pub fn get_packet_filter_table_reset_stats<const N: usize>(
        &self,
        filter_table: &mut StaticFilterTable<N>,
    ) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS,
                None,
                0,
                Some(filter_table as *mut StaticFilterTable<N> as *mut std::ffi::c_void),
                size_of::<StaticFilterTable<N>>() as u32,
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

    /// Queries static filter table size from the NDIS filter driver
    pub fn get_packet_filter_table_size(&self) -> Result<usize> {
        let mut size = 0u32;

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE,
                None,
                0,
                Some(&mut size as *mut u32 as *mut std::ffi::c_void),
                size_of::<u32>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(size as usize)
        }
    }

    /// Removes static filter table from the NDIS filter driver
    pub fn reset_packet_filter_table(&self) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_RESET_PACKET_FILTERS,
                None,
                0,
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

    /// Loads static filter table into the NDIS filter driver
    pub fn set_packet_filter_table<const N: usize>(
        &self,
        filter_table: &StaticFilterTable<N>,
    ) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_PACKET_FILTERS,
                Some(filter_table as *const StaticFilterTable<N> as *const std::ffi::c_void),
                size_of::<StaticFilterTable<N>>() as u32,
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
