//! # Submodule: Static filter functions
//!
//! This submodule provides methods for controlling the NDIS filter driver, including retrieving and setting
//! the static filter table, resetting the filter statistics, and resetting the static filter table. These
//! methods are parameterized by the size of the static filter table. The submodule is part of a larger module
//! (NDISAPI) that provides high-level API for the Windows packet Filter on Windows.
//!

use std::mem::size_of;

use windows::{core::Result, Win32::System::IO::DeviceIoControl};

use super::Ndisapi;
use crate::driver::*;

impl Ndisapi {
    /// This function retrieves the static filter table from the NDIS filter driver and stores it in
    /// the provided `filter_table` argument.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The size of the static filter table.
    ///
    /// # Arguments
    ///
    /// * `filter_table`: A mutable reference to a `StaticFilterTable<N>` object, which will store the
    ///   queried static filter table.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn get_packet_filter_table<const N: usize>(
        &self,
        filter_table: &mut StaticFilterTable<N>,
    ) -> Result<()> {
        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This function retrieves the static filter table from the NDIS filter driver, stores it in
    /// the provided `filter_table` argument, and resets the filter statistics.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The size of the static filter table.
    ///
    /// # Arguments
    ///
    /// * `filter_table`: A mutable reference to a `StaticFilterTable<N>` object, which will store the
    ///   queried static filter table.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn get_packet_filter_table_reset_stats<const N: usize>(
        &self,
        filter_table: &mut StaticFilterTable<N>,
    ) -> Result<()> {
        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This function retrieves the size of the static filter table from the NDIS filter driver.
    ///
    /// # Returns
    ///
    /// * `Result<usize>`: If successful, returns the size of the static filter table as `Ok(usize)`.
    ///   Otherwise, returns an error.
    pub fn get_packet_filter_table_size(&self) -> Result<usize> {
        let mut size = 0u32;

        match unsafe {
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
        } {
            Ok(_) => Ok(size as usize),
            Err(e) => Err(e),
        }
    }

    /// This function resets the static filter table in the NDIS filter driver, effectively
    /// removing all filters from the table.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn reset_packet_filter_table(&self) -> Result<()> {
        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This function takes a static filter table and sets it as the current filter table
    /// in the NDIS filter driver.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The number of filters in the static filter table.
    ///
    /// # Arguments
    ///
    /// * `filter_table: &StaticFilterTable<N>`: A reference to the static filter table to be loaded.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn set_packet_filter_table<const N: usize>(
        &self,
        filter_table: &StaticFilterTable<N>,
    ) -> Result<()> {
        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
