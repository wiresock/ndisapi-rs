//! # Submodule: Basic NDISAPI Structures
//!
//! This submodule provides Rust equivalents of several structures used in the NDISAPI Rust library
//! for communicating with the Windows Packet Filter driver.
//!
//! The structures in this submodule are related to network adapters, Ethernet packets, adapter events,
//! and Remote Access Service (RAS) links.
//!
//! For a detailed description of each structure, refer to their respective documentation within the
//! submodule.

// Import required external crates and types
use std::mem::size_of;
use windows::{
    core::Result,
    Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE},
};

use super::constants::*;

/// The `TcpAdapterList` structure is the Rust equivalent of the
/// [_TCP_AdapterList](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_tcp_adapterlist/)
/// structure in the Windows Packet Filter documentation. It represents a list of network adapters,
/// along with their properties, such as adapter names, handles, medium types, current addresses, and MTUs.
///
/// # Fields
///
/// * `adapter_count`: A 32-bit unsigned integer representing the total number of adapters in the list.
/// * `adapter_name_list`: An array of arrays, with each inner array containing `ADAPTER_NAME_SIZE` bytes,
///   representing the adapter names in the list.
/// * `adapter_handle`: An array of `HANDLE` values, representing the handles of the adapters in the list.
/// * `adapter_medium_list`: An array of 32-bit unsigned integers, representing the medium types of the
///   adapters in the list.
/// * `current_address`: An array of arrays, with each inner array containing `ETHER_ADDR_LENGTH` bytes,
///   representing the current addresses of the adapters in the list.
/// * `mtu`: An array of 16-bit unsigned integers, representing the Maximum Transmission Units (MTUs) of the
///   adapters in the list.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct TcpAdapterList {
    pub adapter_count: u32,
    pub adapter_name_list: [[u8; ADAPTER_NAME_SIZE]; ADAPTER_LIST_SIZE],
    pub adapter_handle: [HANDLE; ADAPTER_LIST_SIZE],
    pub adapter_medium_list: [u32; ADAPTER_LIST_SIZE],
    pub current_address: [[u8; ETHER_ADDR_LENGTH]; ADAPTER_LIST_SIZE],
    pub mtu: [u16; ADAPTER_LIST_SIZE],
}

/// The `ListEntry` structure is the Rust equivalent of the
/// [_LIST_ENTRY](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry)
/// structure in the Windows API. It represents a doubly-linked list entry, containing forward and backward
/// pointers to adjacent list entries.
///
/// # Fields
///
/// * `flink`: A mutable raw pointer to the next `ListEntry` in the list (forward link).
/// * `blink`: A mutable raw pointer to the previous `ListEntry` in the list (backward link).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

/// The `IntermediateBufferHeaderUnion` structure is the Rust equivalent of the union
/// used for `INTERMEDIATE_BUFFER` in the driver API. It represents a union between a
/// `HANDLE` and a `ListEntry`, providing a way to access either of them based on the context.
///
/// # Fields
///
/// * `adapter_handle`: A `HANDLE` representing the adapter handle.
/// * `list_entry`: A `ListEntry` structure representing a doubly-linked list entry.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union IntermediateBufferHeaderUnion {
    pub adapter_handle: HANDLE,
    pub list_entry: ListEntry,
}

/// Provides a default implementation for the `IntermediateBufferHeaderUnion` structure.
///
/// # Safety
///
/// This implementation is safe because the union contains either a `HANDLE` or a `ListEntry`.
/// The `ListEntry` is a union of raw pointers, which can be safely zeroed as long as they are not dereferenced.
/// The `HANDLE` is a wrapper around an `isize`, which can also be safely zeroed.
impl Default for IntermediateBufferHeaderUnion {
    fn default() -> Self {
        // SAFETY: This union contains either a `HANDLE` or a `ListEntry`
        // ListEntry: is an union of raw pointers which can be safely zeroed(as long as you not dereference it)
        // HANDLE: is just an `isize` wrapper which can also be zeroed
        unsafe { core::mem::zeroed() }
    }
}

/// The `IntermediateBuffer` structure represents an intermediate buffer that stores packet data along with some
/// additional information. This structure is used internally by the packet filter driver.
///
/// Rust equivalent for [_INTERMEDIATE_BUFFER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_intermediate_buffer/).
///
/// # Fields
/// * `header`: An `IntermediateBufferHeaderUnion` which is a union of `HANDLE` and `ListEntry`.
/// * `device_flags`: A `DirectionFlags` value that indicates the direction of the packet (send or receive).
/// * `length`: A `u32` representing the length of the packet data.
/// * `flags`: A `u32` value containing various flags related to the packet.
/// * `vlan_8021q`: A `u32` value representing the VLAN tag (802.1Q) associated with the packet.
/// * `filter_id`: A `u32` value identifying the filter that processed the packet.
/// * `reserved`: A reserved `[u32; 4usize]` array for future use.
/// * `buffer`: A `Buffer` structure containing the actual packet data.
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct IntermediateBuffer {
    pub header: IntermediateBufferHeaderUnion,
    pub device_flags: DirectionFlags,
    pub length: u32,
    pub flags: u32,
    pub vlan_8021q: u32,
    pub filter_id: u32,
    pub reserved: [u32; 4usize],
    pub buffer: Buffer,
}

/// This structure represents the buffer used for storing the actual packet data.
///
/// A wrapper around an array of bytes with a size of `MAX_ETHER_FRAME`.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Buffer(pub [u8; MAX_ETHER_FRAME]);

impl Default for Buffer {
    fn default() -> Self {
        Self([0; MAX_ETHER_FRAME])
    }
}

/// IntermediateBuffer implementation
impl IntermediateBuffer {
    /// Creates a new `IntermediateBuffer` with default values.
    ///
    /// # Returns
    /// A new `IntermediateBuffer` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets the `DirectionFlags` value associated with the `IntermediateBuffer`.
    ///
    /// # Returns
    /// The `DirectionFlags` value indicating the direction of the packet (send or receive).
    pub fn get_device_flags(&self) -> DirectionFlags {
        self.device_flags
    }

    /// Gets the length of the packet data stored in the `IntermediateBuffer`.
    ///
    /// # Returns
    /// A `u32` value representing the length of the packet data.
    pub fn get_length(&self) -> u32 {
        self.length
    }

    /// Sets the length of the packet data stored in the `IntermediateBuffer`.
    ///
    /// # Arguments
    /// * `length`: A `u32` value representing the new length of the packet data.
    pub fn set_length(&mut self, length: u32) {
        self.length = length
    }
}

/// This structure is used to define the mode of an adapter with a specified handle and filter flags.
///
/// A Rust equivalent for the [_ADAPTER_MODE](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/adapter_mode/) structure.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct AdapterMode {
    /// A `HANDLE` representing the adapter handle.
    pub adapter_handle: HANDLE,
    /// `FilterFlags` representing the filter flags associated with the adapter mode.
    pub flags: FilterFlags,
}

/// This structure represents an Ethernet packet with a pointer to an `IntermediateBuffer`.
///
/// A Rust equivalent for the [_NDISRD_ETH_Packet](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ndisrd_eth_packet/) structure.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthPacket {
    /// A raw pointer to an `IntermediateBuffer` representing the buffer for this Ethernet packet.
    pub buffer: *mut IntermediateBuffer,
}

impl EthPacket {
    /// Returns a mutable reference to the `IntermediateBuffer` pointed to by the `EthPacket`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because `EthPacket.buffer` may not be initialized or may point to
    /// invalid memory.
    pub unsafe fn get_buffer_mut(&mut self) -> &mut IntermediateBuffer {
        &mut *self.buffer
    }

    /// Returns a reference to the `IntermediateBuffer` pointed to by the `EthPacket`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because `EthPacket.buffer` may not be initialized or may point to
    /// invalid memory.
    pub unsafe fn get_buffer(&self) -> &IntermediateBuffer {
        &*self.buffer
    }
}

/// This structure represents a request for an Ethernet packet, containing an adapter handle and an `EthPacket`.
///
/// A Rust equivalent for the [_ETH_REQUEST](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_request/) structure.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthRequest {
    /// A handle to the network adapter associated with this request.
    pub adapter_handle: HANDLE,
    /// An `EthPacket` representing the Ethernet packet for this request.
    pub packet: EthPacket,
}

/// This structure represents a multiple Ethernet packets request, containing an adapter handle, packet number, packet success, and an array of `EthPacket`.
///
/// A Rust equivalent for the [_ETH_M_REQUEST](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_m_request/) structure.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthMRequest<const N: usize> {
    /// A handle to the network adapter associated with this request.
    adapter_handle: HANDLE,
    /// The number of packets in the `packets` array.
    packet_number: u32,
    /// The number of successfully processed packets.
    packet_success: u32,
    /// An array of `EthPacket` representing the Ethernet packets for this request.
    packets: [EthPacket; N],
}

impl<const N: usize> EthMRequest<N> {
    /// Creates a new `EthMRequest` with the specified adapter handle.
    pub fn new(adapter_handle: HANDLE) -> Self {
        Self {
            adapter_handle,
            packet_number: 0,
            packet_success: 0,
            packets: [EthPacket {
                buffer: core::ptr::null_mut(),
            }; N],
        }
    }

    /// Returns an `EthPacket` at the specified index if the index is within the valid range.
    pub fn at(&self, index: usize) -> Option<EthPacket> {
        if index < self.packet_number as usize {
            Some(self.packets[index])
        } else {
            None
        }
    }

    /// Returns the number of packets in the `packets` array.
    pub fn get_packet_number(&self) -> u32 {
        self.packet_number
    }

    /// Sets the number of packets in the `packets` array.
    pub fn set_packet_number(&mut self, number: u32) {
        self.packet_number = number;
    }

    /// Resets the packet number to 0.
    pub fn reset(&mut self) {
        self.set_packet_number(0);
    }

    /// Returns the number of successfully processed packets.
    pub fn get_packet_success(&self) -> u32 {
        self.packet_success
    }

    /// Pushes an `EthPacket` to the `packets` array if there's available space, returning an error if the array is full.
    pub fn push(&mut self, packet: EthPacket) -> Result<()> {
        if (self.packet_number as usize) < N {
            self.packets[self.packet_number as usize] = packet;
            self.packet_number += 1;
            Ok(())
        } else {
            Err(ERROR_INVALID_PARAMETER.into())
        }
    }
}

/// This structure represents an adapter event, containing an adapter handle and an event handle.
///
/// A Rust equivalent for the [_ADAPTER_EVENT](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/adapter_event/) structure.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AdapterEvent {
    /// A handle to the network adapter associated with this event.
    pub adapter_handle: HANDLE,
    /// A handle to the event associated with this adapter.
    pub event_handle: HANDLE,
}

/// This structure is used to make queries or set parameters on a network adapter.
///
/// A Rust equivalent for the [_PACKET_OID_DATA](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_packet_oid_data/) structure.
#[repr(C, packed)]
pub struct PacketOidData<T> {
    /// A handle to the network adapter associated with this query or parameter setting.
    pub adapter_handle: HANDLE,
    /// The OID (Object Identifier) that represents the query or parameter to be set.
    pub oid: u32,
    /// The length of the data in bytes.
    pub length: u32,
    /// The data associated with the query or parameter.
    pub data: T,
}

impl<T> PacketOidData<T> {
    /// Creates a new PacketOidData instance.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle` - A handle to the network adapter associated with this query or parameter setting.
    /// * `oid` - The OID (Object Identifier) that represents the query or parameter to be set.
    /// * `data` - The data associated with the query or parameter.
    pub fn new(adapter_handle: HANDLE, oid: u32, data: T) -> Self {
        Self {
            adapter_handle,
            oid,
            length: size_of::<T>() as u32,
            data,
        }
    }
}

/// This structure contains information about a RAS (Remote Access Service) link.
///
/// A Rust equivalent for the [_RAS_LINK_INFO](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ras_link_info/) structure.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RasLinkInformation {
    /// The link speed in bits per second.
    link_speed: u32,
    /// The maximum total size, in bytes.
    maximum_total_size: u32,
    /// The remote MAC address.
    remote_address: [u8; ETHER_ADDR_LENGTH],
    /// The local MAC address.
    local_address: [u8; ETHER_ADDR_LENGTH],
    /// The length of the protocol buffer, in bytes.
    protocol_buffer_length: u32,
    /// The buffer containing information about the RAS-managed protocols.
    protocol_buffer: [u8; RAS_LINK_BUFFER_LENGTH],
}

impl RasLinkInformation {
    /// Returns the link speed in bits per second.
    pub fn get_link_speed(&self) -> u32 {
        self.link_speed
    }

    /// Returns the maximum total size.
    pub fn get_maximum_total_size(&self) -> u32 {
        self.maximum_total_size
    }

    /// Returns the remote MAC address.
    pub fn get_remote_address(&self) -> &[u8; ETHER_ADDR_LENGTH] {
        &self.remote_address
    }

    /// Returns the local MAC address.
    pub fn get_local_address(&self) -> &[u8; ETHER_ADDR_LENGTH] {
        &self.local_address
    }

    /// Returns the length of the protocol buffer, in bytes.
    pub fn get_protocol_buffer_length(&self) -> usize {
        self.protocol_buffer_length as usize
    }

    /// Returns the buffer containing information about the RAS-managed protocols.
    pub fn get_protocol_buffer(&self) -> &[u8; RAS_LINK_BUFFER_LENGTH] {
        &self.protocol_buffer
    }
}

/// This structure is a container for RAS (Remote Access Service) link information structures.
///
/// A Rust equivalent for the [_RAS_LINKS](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ras_links/) structure.
/// Note that this struct may be too large to be allocated on the stack in Rust and may result in a stack overflow.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RasLinks {
    /// The number of RAS links in the array.
    number_of_links: u32,
    /// The array of RAS link information structures.
    pub ras_links: [RasLinkInformation; RAS_LINKS_MAX],
}

impl Default for RasLinks {
    /// Returns a zero-initialized instance of `RasLinks`.
    ///
    /// # Safety
    ///
    /// This structure is filled by the information by NDIS filter driver when passed as a memory buffer
    /// along with IOCTL_NDISRD_GET_RAS_LINKS. It is safe to be zeroed because contains only values and arrays that
    /// can be default initialized with zeroes.
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl RasLinks {
    /// Returns the number of RAS links in the array.
    pub fn get_number_of_links(&self) -> usize {
        self.number_of_links as usize
    }
}
