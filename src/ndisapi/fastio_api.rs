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

/// `IntermediateBufferArrayMut` is a struct that holds an array of mutable references to `IntermediateBuffer` objects.
/// It also keeps track of the number of initialized elements in the array.
pub struct IntermediateBufferArrayMut<'a, const N: usize> {
    pub array: [Option<&'a mut IntermediateBuffer>; N],
    pub initialized_count: usize,
}

impl<'a, const N: usize> IntermediateBufferArrayMut<'a, N> {
    /// Constructs a new `IntermediateBufferArrayMut` from an iterator over mutable references to `IntermediateBuffer` objects.
    /// The iterator is consumed up to `N` items and the number of initialized elements is tracked.
    pub fn new(iter: impl Iterator<Item = &'a mut IntermediateBuffer>) -> Self {
        const ARRAY_REPEAT_VALUE: Option<&mut IntermediateBuffer> = None;
        let mut array = [ARRAY_REPEAT_VALUE; N];
        let mut initialized_count = 0;
        for (i, item) in iter.enumerate().take(N) {
            array[i] = Some(item);
            initialized_count += 1;
        }
        Self {
            array,
            initialized_count,
        }
    }

    /// Returns the number of initialized elements in the array.
    pub fn get_packet_number(&self) -> usize {
        self.initialized_count
    }
}

/// Converts the `IntermediateBufferArrayMut` into an array of mutable references to `IntermediateBuffer` objects.
impl<'a, const N: usize> From<IntermediateBufferArrayMut<'a, N>>
    for [Option<&'a mut IntermediateBuffer>; N]
{
    fn from(val: IntermediateBufferArrayMut<'a, N>) -> Self {
        val.array
    }
}

/// Provides a default value for `IntermediateBufferArrayMut`.
/// The default value is an array of `None` with a size of `N` and an initialized count of 0.
impl<'a, const N: usize> Default for IntermediateBufferArrayMut<'a, N> {
    fn default() -> Self {
        const ARRAY_REPEAT_VALUE: Option<&mut IntermediateBuffer> = None;
        Self {
            array: [ARRAY_REPEAT_VALUE; N],
            initialized_count: 0,
        }
    }
}

/// Extends the `IntermediateBufferArrayMut` with an iterator over mutable references to `IntermediateBuffer` objects.
/// The iterator is consumed up to `N` items and the number of initialized elements is tracked.
impl<'a, const N: usize> Extend<&'a mut IntermediateBuffer> for IntermediateBufferArrayMut<'a, N> {
    fn extend<T: IntoIterator<Item = &'a mut IntermediateBuffer>>(&mut self, iter: T) {
        for item in iter {
            if self.initialized_count >= N {
                break;
            }
            self.array[self.initialized_count] = Some(item);
            self.initialized_count += 1;
        }
    }
}

/// `IntermediateBufferArray` is a struct that holds an array of references to `IntermediateBuffer` objects.
/// It also keeps track of the number of initialized elements in the array.
pub struct IntermediateBufferArray<'a, const N: usize> {
    pub array: [Option<&'a IntermediateBuffer>; N],
    pub initialized_count: usize,
}

impl<'a, const N: usize> IntermediateBufferArray<'a, N> {
    /// Constructs a new `IntermediateBufferArray` from an iterator over references to `IntermediateBuffer` objects.
    /// The iterator is consumed up to `N` items and the number of initialized elements is tracked.
    pub fn new(iter: impl Iterator<Item = &'a IntermediateBuffer>) -> Self {
        const ARRAY_REPEAT_VALUE: Option<&IntermediateBuffer> = None;
        let mut array = [ARRAY_REPEAT_VALUE; N];
        let mut initialized_count = 0;
        for (i, item) in iter.enumerate().take(N) {
            array[i] = Some(item);
            initialized_count += 1;
        }
        Self {
            array,
            initialized_count,
        }
    }

    /// Returns the number of initialized elements in the array.
    pub fn get_packet_number(&self) -> usize {
        self.initialized_count
    }
}

/// Converts the `IntermediateBufferArray` into an array of mutable references to `IntermediateBuffer` objects.
impl<'a, const N: usize> From<IntermediateBufferArray<'a, N>>
    for [Option<&'a IntermediateBuffer>; N]
{
    fn from(val: IntermediateBufferArray<'a, N>) -> Self {
        val.array
    }
}

/// Provides a default value for `IntermediateBufferArray`.
/// The default value is an array of `None` with a size of `N` and an initialized count of 0.
impl<'a, const N: usize> Default for IntermediateBufferArray<'a, N> {
    fn default() -> Self {
        const ARRAY_REPEAT_VALUE: Option<&IntermediateBuffer> = None;
        Self {
            array: [ARRAY_REPEAT_VALUE; N],
            initialized_count: 0,
        }
    }
}

/// Extends the `IntermediateBufferArray` with an iterator over references to `IntermediateBuffer` objects.
/// The iterator is consumed up to `N` items and the number of initialized elements is tracked.
impl<'a, const N: usize> Extend<&'a IntermediateBuffer> for IntermediateBufferArray<'a, N> {
    fn extend<T: IntoIterator<Item = &'a IntermediateBuffer>>(&mut self, iter: T) {
        for item in iter {
            if self.initialized_count >= N {
                break;
            }
            self.array[self.initialized_count] = Some(item);
            self.initialized_count += 1;
        }
    }
}

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

    /// This function is used to read packets from the NDIS filter driver. It does not consider
    /// the network interface and reads packets in an unsorted manner. The packets are stored
    /// in the provided buffer.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The number of packets to read.
    ///
    /// # Arguments
    ///
    /// * `packets`: A reference to an array of `Option<&mut IntermediateBuffer>` objects, where the
    ///   read packets will be stored. Each `Option<&mut IntermediateBuffer>` represents a slot for a packet.
    ///
    /// # Returns
    ///
    /// * `Result<usize>`: If successful, returns `Ok(usize)` with the number of packets read.
    ///   Otherwise, returns an error.
    ///
    /// # Safety
    ///
    /// This function performs a device I/O control operation, which is unsafe as it can cause
    /// undefined behavior if not used correctly. The caller must ensure that the `packets` array
    /// is valid and that `N` does not exceed the size of the array.
    pub fn read_packets_unsorted<const N: usize>(
        &self,
        packets: &[Option<&mut IntermediateBuffer>; N],
    ) -> Result<usize> {
        let mut request = UnsortedReadRequest::<N> {
            packets: Some(packets),
            packets_num: N as u32,
        };

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_READ_PACKETS_UNSORTED,
                Some(&request as *const UnsortedReadRequest<N> as *const std::ffi::c_void),
                size_of::<UnsortedReadRequest<N>>() as u32,
                Some(&mut request as *mut UnsortedReadRequest<N> as *mut std::ffi::c_void),
                size_of::<UnsortedReadRequest<N>>() as u32,
                None,
                None,
            )
        } {
            Ok(_) => Ok(request.packets_num as usize),
            Err(e) => Err(e),
        }
    }

    /// This function is used to send packets to the network adapters. It does not consider
    /// the order of the packets and sends them in an unsorted manner. The packets are taken
    /// from the provided buffer.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The number of packets to send.
    ///
    /// # Arguments
    ///
    /// * `packets`: A reference to an array of `Option<&IntermediateBuffer>` objects, which contain
    ///   the packets to be sent. Each `Option<&IntermediateBuffer>` represents a slot for a packet.
    /// * `packets_num`: The number of packets to send from the array.
    ///
    /// # Returns
    ///
    /// * `Result<usize>`: If successful, returns `Ok(usize)` with the number of packets sent.
    ///   Otherwise, returns an error.
    ///
    /// # Safety
    ///
    /// This function performs a device I/O control operation, which is unsafe as it can cause
    /// undefined behavior if not used correctly. The caller must ensure that the `packets` array
    /// is valid and that `N` does not exceed the size of the array.
    pub fn send_packets_to_adapters_unsorted<const N: usize>(
        &self,
        packets: &[Option<&IntermediateBuffer>; N],
        packets_num: usize,
    ) -> Result<usize> {
        let mut request = UnsortedSendRequest::<N> {
            packets: Some(packets),
            packets_num: packets_num as u32,
        };

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED,
                Some(&request as *const UnsortedSendRequest<N> as *const std::ffi::c_void),
                size_of::<UnsortedSendRequest<N>>() as u32,
                Some(&mut request as *mut UnsortedSendRequest<N> as *mut std::ffi::c_void),
                size_of::<UnsortedReadRequest<N>>() as u32,
                None,
                None,
            )
        } {
            Ok(_) => Ok(request.packets_num as usize),
            Err(e) => Err(e),
        }
    }

    /// This function is used to send packets to the Microsoft TCP/IP protocol driver. It does not consider
    /// the order of the packets and sends them in an unsorted manner. The packets are taken
    /// from the provided buffer.
    ///
    /// # Type Parameters
    ///
    /// * `N`: The number of packets to send.
    ///
    /// # Arguments
    ///
    /// * `packets`: A reference to an array of `Option<&IntermediateBuffer>` objects, which contain
    ///   the packets to be sent. Each `Option<&IntermediateBuffer>` represents a slot for a packet.
    /// * `packets_num`: The number of packets to send from the array.
    ///
    /// # Returns
    ///
    /// * `Result<usize>`: If successful, returns `Ok(usize)` with the number of packets sent.
    ///   Otherwise, returns an error.
    ///
    /// # Safety
    ///
    /// This function performs a device I/O control operation, which is unsafe as it can cause
    /// undefined behavior if not used correctly. The caller must ensure that the `packets` array
    /// is valid and that `N` does not exceed the size of the array.
    pub fn send_packets_to_mstcp_unsorted<const N: usize>(
        &self,
        packets: &[Option<&IntermediateBuffer>; N],
        packets_num: usize,
    ) -> Result<usize> {
        let mut request = UnsortedSendRequest::<N> {
            packets: Some(packets),
            packets_num: packets_num as u32,
        };

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED,
                Some(&request as *const UnsortedSendRequest<N> as *const std::ffi::c_void),
                size_of::<UnsortedSendRequest<N>>() as u32,
                Some(&mut request as *mut UnsortedSendRequest<N> as *mut std::ffi::c_void),
                size_of::<UnsortedSendRequest<N>>() as u32,
                None,
                None,
            )
        } {
            Ok(_) => Ok(request.packets_num as usize),
            Err(e) => Err(e),
        }
    }
}
