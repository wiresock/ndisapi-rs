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

    /// Adds a single static filter to the front (highest priority) of the static packet filter
    /// list in the NDIS filter driver.
    ///
    /// # Arguments
    ///
    /// * `filter`: A reference to the [`StaticFilter`] to be added.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn add_packet_filter_front(&self, filter: &StaticFilter) -> Result<()> {
        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_ADD_PACKET_FILTER_FRONT,
                Some(filter as *const StaticFilter as *const std::ffi::c_void),
                size_of::<StaticFilter>() as u32,
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

    /// Adds a single static filter to the back (lowest priority) of the static packet filter
    /// list in the NDIS filter driver.
    ///
    /// # Arguments
    ///
    /// * `filter`: A reference to the [`StaticFilter`] to be added.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn add_packet_filter_back(&self, filter: &StaticFilter) -> Result<()> {
        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_ADD_PACKET_FILTER_BACK,
                Some(filter as *const StaticFilter as *const std::ffi::c_void),
                size_of::<StaticFilter>() as u32,
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

    /// Inserts a single static filter at the specified zero-based position in the static
    /// packet filter list in the NDIS filter driver.
    ///
    /// # Arguments
    ///
    /// * `filter`: A reference to the [`StaticFilter`] to be inserted.
    /// * `position`: The zero-based position at which to insert the filter. Lower positions have
    ///   higher priority because filters are processed in ascending order.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn insert_packet_filter(&self, filter: &StaticFilter, position: u32) -> Result<()> {
        let driver_data = StaticFilterWithPosition::new(*filter, position);

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_INSERT_FILTER_BY_INDEX,
                Some(&driver_data as *const StaticFilterWithPosition as *const std::ffi::c_void),
                size_of::<StaticFilterWithPosition>() as u32,
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

    /// Removes the static filter at the given zero-based index from the static packet filter
    /// list in the NDIS filter driver.
    ///
    /// # Arguments
    ///
    /// * `filter_index`: The zero-based index of the filter to remove.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn remove_packet_filter(&self, filter_index: u32) -> Result<()> {
        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_REMOVE_FILTER_BY_INDEX,
                Some(&filter_index as *const u32 as *const std::ffi::c_void),
                size_of::<u32>() as u32,
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

    /// Sets the state of the packet filter cache in the NDIS filter driver.
    ///
    /// The packet filter cache is used to improve performance by caching packet filter lookups.
    /// Disabling it may be useful for debugging or when the most up-to-date filter information
    /// is required.
    ///
    /// # Arguments
    ///
    /// * `state`: `true` to enable the packet filter cache, `false` to disable it.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn set_packet_filter_cache_state(&self, state: bool) -> Result<()> {
        let state: u32 = state as u32;

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_FILTER_CACHE_STATE,
                Some(&state as *const u32 as *const std::ffi::c_void),
                size_of::<u32>() as u32,
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

    /// Enables the packet filter cache in the NDIS filter driver.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn enable_packet_filter_cache(&self) -> Result<()> {
        self.set_packet_filter_cache_state(true)
    }

    /// Disables the packet filter cache in the NDIS filter driver.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn disable_packet_filter_cache(&self) -> Result<()> {
        self.set_packet_filter_cache_state(false)
    }

    /// Sets the state of the packet fragment cache in the NDIS filter driver.
    ///
    /// The packet fragment cache caches packet fragments to improve packet processing
    /// performance. Disabling it may be useful for debugging or in scenarios where caching
    /// is not desirable.
    ///
    /// # Arguments
    ///
    /// * `state`: `true` to enable the packet fragment cache, `false` to disable it.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn set_packet_fragment_cache_state(&self, state: bool) -> Result<()> {
        let state: u32 = state as u32;

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_FRAGMENT_CACHE_STATE,
                Some(&state as *const u32 as *const std::ffi::c_void),
                size_of::<u32>() as u32,
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

    /// Enables the packet fragment cache in the NDIS filter driver.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn enable_packet_fragment_cache(&self) -> Result<()> {
        self.set_packet_fragment_cache_state(true)
    }

    /// Disables the packet fragment cache in the NDIS filter driver.
    ///
    /// # Returns
    ///
    /// * `Result<()>`: If successful, returns `Ok(())`. Otherwise, returns an error.
    pub fn disable_packet_fragment_cache(&self) -> Result<()> {
        self.set_packet_fragment_cache_state(false)
    }
}
