//! # Submodule: Fast I/O Structures
//!
//! This submodule provides Rust equivalents of several structures related to Fast I/O operations
//! for the NDISAPI Rust library used in communicating with the Windows Packet Filter driver.
//!
//! The structures in this submodule are related to Fast I/O sections, which include headers and packet data,
//! and are involved in read and write operations.
//!
//! For a detailed description of each structure, refer to their respective documentation within the
//! submodule.

use super::base::*;

/// This structure contains the fields that make up the FastIoWriteUnion when accessed separately.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct FastIoWriteUnionStruct {
    /// The number of packets
    pub number_of_packets: u16,
    /// Flag indicating whether a write operation is in progress
    pub write_in_progress_flag: u16,
}

/// This union represents a combined 32-bit field containing both the number of packets and a flag
/// indicating whether a write operation is in progress. It provides the option to access the fields individually
/// through the `split` field or the combined 32-bit value through the `join` field.
///
/// Rust equivalent for _FAST_IO_WRITE_UNION
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union FastIoWriteUnion {
    /// Separate access to the number of packets and write in progress flag
    pub split: FastIoWriteUnionStruct,
    /// Combined 32-bit representation of the number of packets and write in progress flag
    pub join: u32,
}

impl Default for FastIoWriteUnion {
    /// Initializes a new `FastIoWriteUnion` with default values for both the `join` field and the fields in the `split` structure.
    fn default() -> Self {
        FastIoWriteUnion { join: 0 }
    }
}

/// This structure is used as the header for the FastIoSection structure, containing the FastIoWriteUnion
/// and a flag indicating whether a read operation is in progress.
///
/// Rust equivalent for _FAST_IO_SECTION_HEADER
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct FastIoSectionHeader {
    /// Union containing the number of packets and write in progress flag
    pub fast_io_write_union: FastIoWriteUnion,
    /// Flag indicating whether a read operation is in progress
    pub read_in_progress_flag: u32,
}

/// This structure represents a Fast I/O section, which includes a FastIoSectionHeader and an array of IntermediateBuffer
/// structures. It is used to store information about packet data and the state of read and write operations.
///
/// Rust equivalent for _FAST_IO_SECTION
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct FastIoSection<const N: usize> {
    /// Header containing the FastIoWriteUnion and read in progress flag
    pub fast_io_header: FastIoSectionHeader,
    /// Array of IntermediateBuffer structures for packet data
    pub fast_io_packets: [IntermediateBuffer; N],
}

impl<const N: usize> Default for FastIoSection<N> {
    // Initializes a new `FastIoSection<N>` with default values for its fields.
    // SAFETY: This structure is filled by information by NDIS filter driver.
    // Zero-initialized FastIoSection<N> is completely valid and ignored by the code.
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// A Rust struct that represents the parameters for fast I/O initialization.
///
/// Rust equivalent for _INITIALIZE_FAST_IO_PARAMS.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct InitializeFastIoParams<const N: usize> {
    /// header_ptr: A mutable pointer to a FastIoSection of size N.
    pub header_ptr: *mut FastIoSection<N>,
    /// data_size: A u32 representing the data size of the Fast I/O section.
    pub data_size: u32,
}

/// A Rust struct that represents an unsorted read request.
///
/// Rust equivalent for _UNSORTED_READ_SEND_REQUEST.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct UnsortedSendRequest<'a, const N: usize> {
    /// packets: A pointer to an array of Option<&IntermediateBuffer> of size N.
    pub packets: Option<&'a [Option<&'a IntermediateBuffer>; N]>,
    /// packets_num: A u32 representing the number of packets in the request.
    pub packets_num: u32,
}

/// A Rust struct that represents an unsorted read/send request.
///
/// Rust equivalent for _UNSORTED_READ_SEND_REQUEST.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct UnsortedReadRequest<'a, const N: usize> {
    /// packets: A pointer to an array of Option<&mut IntermediateBuffer> of size N.
    pub packets: Option<&'a [Option<&'a mut IntermediateBuffer>; N]>,
    /// packets_num: A u32 representing the number of packets in the request.
    pub packets_num: u32,
}
