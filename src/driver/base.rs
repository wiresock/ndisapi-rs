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
    Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_INVALID_PARAMETER, HANDLE},
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
/// links to adjacent list entries.
///
/// # Fields
///
/// * `flink`: A usize representing the memory address of the next `ListEntry` in the list (forward link).
/// * `blink`: A usize representing the memory address of the previous `ListEntry` in the list (backward link).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ListEntry {
    pub flink: usize,
    pub blink: usize,
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

    /// Returns a reference to the data stored in the buffer.
    ///
    /// This method returns a reference to the data stored in the buffer as a slice of bytes.
    /// The length of the slice is determined by the `length` field of the `buffer` struct.
    pub fn get_data(&self) -> &[u8] {
        &self.buffer.0[..self.length as usize]
    }

    /// Returns a mutable reference to the data stored in the buffer.
    ///
    /// This method returns a mutable reference to the data stored in the buffer as a slice of bytes.
    /// The length of the slice is determined by the `length` field of the `buffer` struct.
    pub fn get_data_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.0[..self.length as usize]
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

/// This structure represents an Ethernet packet with an optional mutable reference to an `IntermediateBuffer`.
///
/// A Rust equivalent for the [_NDISRD_ETH_Packet](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ndisrd_eth_packet/) structure.
///
/// The `buffer` field is an optional mutable reference to an `IntermediateBuffer`. This design allows for flexibility
/// when manipulating Ethernet packets, as a packet may not always have a buffer associated with it.
/// This structure is particularly useful when the packet data needs to be modified.
#[repr(C)]
pub struct EthPacketMut<'a> {
    /// An optional mutable reference to an `IntermediateBuffer` representing the buffer for this Ethernet packet.
    pub buffer: Option<&'a mut IntermediateBuffer>,
}

/// This structure represents an Ethernet packet with an optional reference to an `IntermediateBuffer`.
///
/// A Rust equivalent for the [_NDISRD_ETH_Packet](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ndisrd_eth_packet/) structure.
///
/// The `buffer` field is an optional reference to an `IntermediateBuffer`. This design allows for flexibility
/// when manipulating Ethernet packets, as a packet may not always have a buffer associated with it.
/// This structure is particularly useful when the packet data needs to be read but not modified.
#[repr(C)]
pub struct EthPacket<'a> {
    /// An optional reference to an `IntermediateBuffer` representing the buffer for this Ethernet packet.
    pub buffer: Option<&'a IntermediateBuffer>,
}

/// Implements the `Into` trait for `EthPacketMut`.
///
/// This implementation facilitates the conversion of an `EthPacketMut` into an `Option<&'a mut IntermediateBuffer>`.
/// This conversion is useful when there is a need to directly manipulate the buffer of a packet. By implementing `Into` for `EthPacketMut`,
/// we provide a convenient and idiomatic way to perform this transformation.
impl<'a> From<EthPacketMut<'a>> for Option<&'a mut IntermediateBuffer> {
    fn from(val: EthPacketMut<'a>) -> Self {
        val.buffer
    }
}

/// Implements the `AsRef` trait for `EthPacketMut`.
///
/// This implementation facilitates the conversion of an `EthPacketMut` into a reference to an `Option<&'a mut IntermediateBuffer>`.
/// This conversion is useful when there is a need to directly access the buffer of a packet. By implementing `AsRef` for `EthPacketMut`,
/// we provide a convenient and idiomatic way to perform this transformation.
impl<'a> AsRef<Option<&'a mut IntermediateBuffer>> for EthPacketMut<'a> {
    fn as_ref(&self) -> &Option<&'a mut IntermediateBuffer> {
        &self.buffer
    }
}

/// Implements the `AsMut` trait for `EthPacketMut`.
///
/// This implementation facilitates the conversion of an `EthPacketMut` into a mutable reference to an `Option<&'a mut IntermediateBuffer>`.
/// This conversion is useful when there is a need to directly manipulate the buffer of a packet. By implementing `AsMut` for `EthPacketMut`,
/// we provide a convenient and idiomatic way to perform this transformation.
impl<'a> AsMut<Option<&'a mut IntermediateBuffer>> for EthPacketMut<'a> {
    fn as_mut(&mut self) -> &mut Option<&'a mut IntermediateBuffer> {
        &mut self.buffer
    }
}

/// Implements the `Default` trait for `EthPacketMut`.
///
/// This implementation allows for the creation of an "empty" `EthPacketMut`, i.e., a packet without a buffer. This is useful when
/// initializing a variable of type `EthPacketMut` without immediately associating a buffer with it.
impl<'a> Default for EthPacketMut<'a> {
    fn default() -> Self {
        EthPacketMut { buffer: None }
    }
}

/// Implements the `Into` trait for `EthPacket`.
///
/// This implementation facilitates the conversion of an `EthPacket` into an `Option<&'a IntermediateBuffer>`.
/// This conversion is useful when there is a need to directly manipulate the buffer of a packet. By implementing `Into` for `EthPacket`,
/// we provide a convenient and idiomatic way to perform this transformation.
impl<'a> From<EthPacket<'a>> for Option<&'a IntermediateBuffer> {
    fn from(val: EthPacket<'a>) -> Self {
        val.buffer
    }
}

/// Implements the `AsRef` trait for `EthPacket`.
///
/// This implementation facilitates the conversion of an `EthPacket` into a reference to an `Option<&'a IntermediateBuffer>`.
/// This conversion is useful when there is a need to directly access the buffer of a packet. By implementing `AsRef` for `EthPacket`,
/// we provide a convenient and idiomatic way to perform this transformation.
impl<'a> AsRef<Option<&'a IntermediateBuffer>> for EthPacket<'a> {
    fn as_ref(&self) -> &Option<&'a IntermediateBuffer> {
        &self.buffer
    }
}

/// Implements the `Default` trait for `EthPacket`.
///
/// This implementation allows for the creation of an "empty" `EthPacket`, i.e., a packet without a buffer. This is useful when
/// initializing a variable of type `EthPacket` without immediately associating a buffer with it.
impl<'a> Default for EthPacket<'a> {
    fn default() -> Self {
        EthPacket { buffer: None }
    }
}

/// This structure represents a request for an Ethernet packet, containing a network adapter handle and an `EthPacketMut`.
///
/// A Rust equivalent for the [_ETH_REQUEST](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_request/) structure.
///
/// `adapter_handle` is a handle to the network adapter associated with this request. The `packet` field is an `EthPacketMut` that represents the Ethernet packet for this request.
#[repr(C)]
pub struct EthRequestMut<'a> {
    /// A handle to the network adapter associated with this request.
    pub adapter_handle: HANDLE,
    /// An `EthPacketMut` representing the Ethernet packet for this request.
    pub packet: EthPacketMut<'a>,
}

/// This structure represents a request for an Ethernet packet, containing a network adapter handle and an `EthPacket`.
///
/// A Rust equivalent for the [_ETH_REQUEST](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_request/) structure.
///
/// `adapter_handle` is a handle to the network adapter associated with this request. The `packet` field is an `EthPacket` that represents the Ethernet packet for this request.
#[repr(C)]
pub struct EthRequest<'a> {
    /// A handle to the network adapter associated with this request.
    pub adapter_handle: HANDLE,
    /// An `EthPacket` representing the Ethernet packet for this request.
    pub packet: EthPacket<'a>,
}

/// Provides methods for manipulating the `EthPacketMut` within an `EthRequestMut`.
impl<'a> EthRequestMut<'a> {
    /// Creates a new `EthRequestMut` with the specified adapter handle and an empty `EthPacketMut`.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle` - A handle to the network adapter to be associated with this request.
    ///
    /// # Returns
    ///
    /// * A new `EthRequestMut` instance with the specified adapter handle and an empty `EthPacketMut`.
    pub fn new(adapter_handle: HANDLE) -> Self {
        Self {
            adapter_handle,
            packet: EthPacketMut { buffer: None },
        }
    }

    /// Takes the `EthPacketMut` out from the `EthRequestMut`, replacing it with `None`.
    ///
    /// This is useful when you want to use the packet's buffer elsewhere, while ensuring that the `EthRequestMut` no longer has access to it.
    pub fn take_packet(&mut self) -> Option<&'a mut IntermediateBuffer> {
        self.packet.buffer.take()
    }

    /// Sets the `EthPacketMut` for the `EthRequestMut` using a mutable reference to an `IntermediateBuffer`.
    ///
    /// This method allows you to associate a new buffer with the `EthRequestMut`. This is useful when you have a buffer that you want to send with the `EthRequestMut`.
    pub fn set_packet(&mut self, buffer: &'a mut IntermediateBuffer) {
        self.packet = EthPacketMut {
            buffer: Some(buffer),
        };
    }
}

/// Provides methods for manipulating the `EthPacket` within an `EthRequest`.
impl<'a> EthRequest<'a> {
    /// Creates a new `EthRequest` with the specified adapter handle and an empty `EthPacket`.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle` - A handle to the network adapter to be associated with this request.
    ///
    /// # Returns
    ///
    /// * A new `EthRequest` instance with the specified adapter handle and an empty `EthPacket`.
    pub fn new(adapter_handle: HANDLE) -> Self {
        Self {
            adapter_handle,
            packet: EthPacket { buffer: None },
        }
    }

    /// Takes the `EthPacket` out from the `EthRequest`, replacing it with `None`.
    ///
    /// This is useful when you want to use the packet's buffer elsewhere, while ensuring that the `EthRequest` no longer has access to it.
    pub fn take_packet(&mut self) -> Option<&'a IntermediateBuffer> {
        self.packet.buffer.take()
    }

    /// Sets the `EthPacket` for the `EthRequest` using a reference to an `IntermediateBuffer`.
    ///
    /// This method allows you to associate a new buffer with the `EthRequest`. This is useful when you have a buffer that you want to send with the `EthRequest`.
    pub fn set_packet(&mut self, buffer: &'a IntermediateBuffer) {
        self.packet = EthPacket {
            buffer: Some(buffer),
        };
    }
}

/// This structure represents a request for multiple Ethernet packets, containing a network adapter handle, packet number, packet success count, and an array of `EthPacketMut` instances.
///
/// A Rust equivalent for the [_ETH_M_REQUEST](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_m_request/) structure.
///
/// `adapter_handle` is a handle to the network adapter associated with this request. `packet_number` is the number of packets in the `packets` array. `packet_success` is the number of packets that have been successfully processed. `packets` is an array of `EthPacketMut` instances representing the Ethernet packets for this request.
#[repr(C)]
pub struct EthMRequestMut<'a, const N: usize> {
    /// A handle to the network adapter associated with this request.
    adapter_handle: HANDLE,
    /// The number of packets in the `packets` array.
    packet_number: u32,
    /// The number of successfully processed packets.
    packet_success: u32,
    /// An array of `EthPacketMut` representing the Ethernet packets for this request.
    packets: [EthPacketMut<'a>; N],
}

/// This structure represents a request for multiple Ethernet packets, containing a network adapter handle, packet number, packet success count, and an array of `EthPacket` instances.
///
/// A Rust equivalent for the [_ETH_M_REQUEST](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_m_request/) structure.
///
/// `adapter_handle` is a handle to the network adapter associated with this request. `packet_number` is the number of packets in the `packets` array. `packet_success` is the number of packets that have been successfully processed. `packets` is an array of `EthPacket` instances representing the Ethernet packets for this request.
#[repr(C)]
pub struct EthMRequest<'a, const N: usize> {
    /// A handle to the network adapter associated with this request.
    adapter_handle: HANDLE,
    /// The number of packets in the `packets` array.
    packet_number: u32,
    /// The number of successfully processed packets.
    packet_success: u32,
    /// An array of `EthPacket` representing the Ethernet packets for this request.
    packets: [EthPacket<'a>; N],
}

/// Provides methods for manipulating the `EthPacketMut` instances within an `EthMRequestMut`.
impl<'a, const N: usize> EthMRequestMut<'a, N> {
    /// Creates a new `EthMRequestMut` with the specified adapter handle.
    ///
    /// All packets in the request are initialized to empty.
    pub fn new(adapter_handle: HANDLE) -> Self {
        let packets = [(); N].map(|_| EthPacketMut { buffer: None });
        Self {
            adapter_handle,
            packet_number: 0,
            packet_success: 0,
            packets,
        }
    }

    /// Creates a new `EthMRequestMut` from an iterator over `&mut IntermediateBuffer`.
    ///
    /// This constructor will attempt to consume up to `N` items from the iterator to initialize the `packets` array.
    /// If the iterator contains fewer than `N` items, the remaining entries in the `packets` array will be left as `None`.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle`: A handle to the network adapter associated with this request.
    /// * `iter`: An iterator over mutable references to `IntermediateBuffer`.
    ///
    /// # Returns
    ///
    /// A new `EthMRequestMut`.
    pub fn from_iter(
        adapter_handle: HANDLE,
        iter: impl Iterator<Item = &'a mut IntermediateBuffer>,
    ) -> Self {
        let mut packets = [(); N].map(|_| EthPacketMut { buffer: None });
        let mut packet_number = 0;

        for (buffer, packet) in iter.zip(packets.iter_mut()) {
            packet.buffer = Some(buffer);
            packet_number += 1;
        }

        Self {
            adapter_handle,
            packet_number,
            packet_success: 0,
            packets,
        }
    }

    /// Returns an iterator that yields `Some(IntermediateBuffer)` for each non-empty buffer in `packets`, in order,
    /// up to `packet_success`.
    ///
    /// This method is used to drain the successful packets from the request. It iterates over the packets in the request,
    /// and for each packet that has a buffer (i.e., is not empty), it decreases the packet number and removes the buffer from the packet.
    /// The removed buffer (which is a mutable reference to an `IntermediateBuffer`) is then yielded by the iterator.
    /// This process continues until either all packets have been inspected or a number of packets equal to `packet_success` have been drained.
    ///
    /// # Returns
    ///
    /// An iterator over `Option<&'a mut IntermediateBuffer>`. Each `Some(IntermediateBuffer)` item in the iterator represents a successfully processed packet.
    pub fn drain_success(&mut self) -> impl Iterator<Item = &'a mut IntermediateBuffer> + '_ {
        self.packets
            .iter_mut()
            .take(self.packet_success as usize)
            .filter_map(|packet| {
                if packet.buffer.is_some() {
                    self.packet_number -= 1;
                    packet.buffer.take()
                } else {
                    None
                }
            })
    }

    /// Returns an iterator that yields `Some(IntermediateBuffer)` for each non-empty buffer in `packets`.
    ///
    /// This method is used to drain the packets from the request. It iterates over the packets in the request,
    /// and for each packet that has a buffer (i.e., is not empty), it decreases the packet number and removes the buffer from the packet.
    /// The removed buffer (which is a mutable reference to an `IntermediateBuffer`) is then yielded by the iterator.
    ///
    /// # Returns
    ///
    /// An iterator over `Option<&'a mut IntermediateBuffer>`. Each `Some(IntermediateBuffer)` item in the iterator represents a packet.
    pub fn drain(&mut self) -> impl Iterator<Item = &'a mut IntermediateBuffer> + '_ {
        self.packets.iter_mut().filter_map(|packet| {
            if packet.buffer.is_some() {
                self.packet_number -= 1;
                packet.buffer.take()
            } else {
                None
            }
        })
    }

    /// Sets the `IntermediateBuffer` for the `EthPacketMut` at the specified index.
    ///
    /// This method is used to associate a mutable reference to an `IntermediateBuffer` with an `EthPacketMut` at a specific index in the `packets` array.
    /// If the index is valid (i.e., less than `N`), the method sets the `buffer` field of the `EthPacketMut` at the specified index to `Some(buffer)`,
    /// where `buffer` is a mutable reference to an `IntermediateBuffer`.
    ///
    /// # Arguments
    ///
    /// * `index`: A `usize` representing the index at which to set the `IntermediateBuffer`.
    /// * `buffer`: A mutable reference to an `IntermediateBuffer` to be associated with the `EthPacketMut`.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the index is valid and the `IntermediateBuffer` has been successfully set.
    /// * `Err(ERROR_INVALID_PARAMETER.into())` if the index is not valid.
    fn set_packet(&mut self, index: usize, buffer: &'a mut IntermediateBuffer) -> Result<()> {
        if index < N {
            self.packets[index].buffer = Some(buffer);
            Ok(())
        } else {
            Err(ERROR_INVALID_PARAMETER.into())
        }
    }

    /// Returns the number of packets in the `packets` array.
    ///
    /// This method is used to get the total number of packets currently stored in the `packets` array.
    /// The `packets` array is used to store the packets that are to be sent or received.
    ///
    /// # Returns
    /// A `u32` value representing the total number of packets in the `packets` array.
    pub fn get_packet_number(&self) -> u32 {
        self.packet_number
    }

    /// Erases all `EthPacketMut` instances within the `packets` array and releases all references.
    ///
    /// This method is used to reset the state of the `EthMRequest` instance. It iterates over the `packets` array,
    /// setting each `buffer` field to `None`, effectively releasing all references to `IntermediateBuffer` instances.
    /// It also resets the `packet_number` and `packet_success` counters to 0.
    pub fn reset(&mut self) {
        for packet in self.packets.iter_mut() {
            packet.buffer = None;
        }
        self.packet_number = 0;
        self.packet_success = 0;
    }

    /// Returns the number of successfully processed packets.
    ///
    /// This method is used to get the total number of packets that have been successfully processed.
    /// The `packet_success` field is incremented each time a packet is successfully processed.
    ///
    /// # Returns
    /// A `u32` value representing the total number of successfully processed packets.
    pub fn get_packet_success(&self) -> u32 {
        self.packet_success
    }

    /// Adds an `IntermediateBuffer` to the `packets` array if there's available space.
    ///
    /// This method is used to add a new packet to the `packets` array. It first checks if the current number of packets
    /// is less than the maximum allowed (`N`). If there is space available, it finds the first empty slot in the `packets`
    /// array and inserts the new packet there, incrementing the `packet_number` counter. If the `packets` array is full,
    /// it returns an `Err` with `ERROR_BUFFER_OVERFLOW`.
    ///
    /// # Arguments
    ///
    /// * `packet`: A mutable reference to an `IntermediateBuffer` representing the new packet to be added.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the packet was successfully added.
    /// * `Err(ERROR_BUFFER_OVERFLOW.into())` if the `packets` array is full.
    pub fn push(&mut self, packet: &'a mut IntermediateBuffer) -> Result<()> {
        if (self.packet_number as usize) < N {
            if let Some(index) = self.first_empty_packet() {
                self.packets[index] = EthPacketMut {
                    buffer: Some(packet),
                };
                self.packet_number += 1;
                Ok(())
            } else {
                Err(ERROR_BUFFER_OVERFLOW.into())
            }
        } else {
            Err(ERROR_BUFFER_OVERFLOW.into())
        }
    }

    /// Returns the index of the first `EthPacketMut` which contains `None`.
    ///
    /// This method is used to find the first empty slot in the `packets` array. It iterates over the `packets` array,
    /// and for each `EthPacketMut` that does not have a buffer (i.e., its `buffer` field is `None`), it returns the index of that packet.
    /// If all `EthPacketMut` instances in the `packets` array have a buffer, this method returns `None`.
    ///
    /// # Returns
    /// An `Option<usize>` that is `Some(index)` if an empty `EthPacketMut` is found, where `index` is the index of the empty packet.
    /// If no empty `EthPacketMut` is found, it returns `None`.
    fn first_empty_packet(&self) -> Option<usize> {
        self.packets
            .iter()
            .position(|packet| packet.buffer.is_none())
    }

    /// Consumes packets from an Iterator, moving them into `self`.
    ///
    /// This method is used to add packets from an iterator to the `packets` array. It iterates over the packets provided by the iterator,
    /// and for each packet, it checks if there is space available in the `packets` array. If there is space available, it finds the first empty slot
    /// in the `packets` array and inserts the new packet there, incrementing the `packet_number` counter. If the `packets` array is full,
    /// it returns an `Err` with `ERROR_BUFFER_OVERFLOW`.
    ///
    /// # Arguments
    ///
    /// * `packets`: An iterator that yields mutable references to `IntermediateBuffer` instances.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if all packets from the iterator were successfully added.
    /// * `Err(ERROR_BUFFER_OVERFLOW.into())` if the `packets` array is full.
    pub fn append<I>(&mut self, packets: I) -> Result<()>
    where
        I: Iterator<Item = &'a mut IntermediateBuffer>,
    {
        for buffer in packets {
            if self.packet_number as usize >= N {
                return Err(ERROR_BUFFER_OVERFLOW.into());
            }

            if let Some(empty_slot) = self.first_empty_packet() {
                self.set_packet(empty_slot, buffer)?;
                self.packet_number += 1;
            } else {
                return Err(ERROR_BUFFER_OVERFLOW.into());
            }
        }

        Ok(())
    }
}

/// Provides methods for manipulating the `EthPacket` instances within an `EthMRequest`.
impl<'a, const N: usize> EthMRequest<'a, N> {
    /// Creates a new `EthMRequest` with the specified adapter handle.
    ///
    /// All packets in the request are initialized to empty.
    pub fn new(adapter_handle: HANDLE) -> Self {
        let packets = [(); N].map(|_| EthPacket { buffer: None });
        Self {
            adapter_handle,
            packet_number: 0,
            packet_success: 0,
            packets,
        }
    }

    /// Creates a new `EthMRequest` from an iterator over `&IntermediateBuffer`.
    ///
    /// This constructor will attempt to consume up to `N` items from the iterator to initialize the `packets` array.
    /// If the iterator contains fewer than `N` items, the remaining entries in the `packets` array will be left as `None`.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle`: A handle to the network adapter associated with this request.
    /// * `iter`: An iterator over references to `IntermediateBuffer`.
    ///
    /// # Returns
    ///
    /// A new `EthMRequest`.
    pub fn from_iter(
        adapter_handle: HANDLE,
        iter: impl Iterator<Item = &'a IntermediateBuffer>,
    ) -> Self {
        let mut packets = [(); N].map(|_| EthPacket { buffer: None });
        let mut packet_number = 0;

        for (buffer, packet) in iter.zip(packets.iter_mut()) {
            packet.buffer = Some(buffer);
            packet_number += 1;
        }

        Self {
            adapter_handle,
            packet_number,
            packet_success: 0,
            packets,
        }
    }

    /// Returns an iterator that yields `Some(IntermediateBuffer)` for each non-empty buffer in `packets`, in order,
    /// up to `packet_success`.
    ///
    /// This method is used to drain the successful packets from the request. It iterates over the packets in the request,
    /// and for each packet that has a buffer (i.e., is not empty), it decreases the packet number and removes the buffer from the packet.
    /// The removed buffer (which is a mutable reference to an `IntermediateBuffer`) is then yielded by the iterator.
    /// This process continues until either all packets have been inspected or a number of packets equal to `packet_success` have been drained.
    ///
    /// # Returns
    ///
    /// An iterator over `Option<&'a IntermediateBuffer>`. Each `Some(IntermediateBuffer)` item in the iterator represents a successfully processed packet.
    pub fn drain_success(&mut self) -> impl Iterator<Item = &'a IntermediateBuffer> + '_ {
        self.packets
            .iter_mut()
            .take(self.packet_success as usize)
            .filter_map(|packet| {
                if packet.buffer.is_some() {
                    self.packet_number -= 1;
                    packet.buffer.take()
                } else {
                    None
                }
            })
    }

    /// Returns an iterator that yields `Some(IntermediateBuffer)` for each non-empty buffer in `packets`.
    ///
    /// This method is used to drain the packets from the request. It iterates over the packets in the request,
    /// and for each packet that has a buffer (i.e., is not empty), it decreases the packet number and removes the buffer from the packet.
    /// The removed buffer (which is a mutable reference to an `IntermediateBuffer`) is then yielded by the iterator.
    ///
    /// # Returns
    ///
    /// An iterator over `Option<&'a IntermediateBuffer>`. Each `Some(IntermediateBuffer)` item in the iterator represents a packet.
    pub fn drain(&mut self) -> impl Iterator<Item = &'a IntermediateBuffer> + '_ {
        self.packets.iter_mut().filter_map(|packet| {
            if packet.buffer.is_some() {
                self.packet_number -= 1;
                packet.buffer.take()
            } else {
                None
            }
        })
    }

    /// Sets the `IntermediateBuffer` for the `EthPacket` at the specified index.
    ///
    /// This method is used to associate a reference to an `IntermediateBuffer` with an `EthPacket` at a specific index in the `packets` array.
    /// If the index is valid (i.e., less than `N`), the method sets the `buffer` field of the `EthPacket` at the specified index to `Some(buffer)`,
    /// where `buffer` is a reference to an `IntermediateBuffer`.
    ///
    /// # Arguments
    ///
    /// * `index`: A `usize` representing the index at which to set the `IntermediateBuffer`.
    /// * `buffer`: A reference to an `IntermediateBuffer` to be associated with the `EthPacket`.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the index is valid and the `IntermediateBuffer` has been successfully set.
    /// * `Err(ERROR_INVALID_PARAMETER.into())` if the index is not valid.
    fn set_packet(&mut self, index: usize, buffer: &'a IntermediateBuffer) -> Result<()> {
        if index < N {
            self.packets[index].buffer = Some(buffer);
            Ok(())
        } else {
            Err(ERROR_INVALID_PARAMETER.into())
        }
    }

    /// Returns the number of packets in the `packets` array.
    ///
    /// This method is used to get the total number of packets currently stored in the `packets` array.
    /// The `packets` array is used to store the packets that are to be sent or received.
    ///
    /// # Returns
    /// A `u32` value representing the total number of packets in the `packets` array.
    pub fn get_packet_number(&self) -> u32 {
        self.packet_number
    }

    /// Erases all `EthPacketMut` instances within the `packets` array and releases all references.
    ///
    /// This method is used to reset the state of the `EthMRequest` instance. It iterates over the `packets` array,
    /// setting each `buffer` field to `None`, effectively releasing all references to `IntermediateBuffer` instances.
    /// It also resets the `packet_number` and `packet_success` counters to 0.
    pub fn reset(&mut self) {
        for packet in self.packets.iter_mut() {
            packet.buffer = None;
        }
        self.packet_number = 0;
        self.packet_success = 0;
    }

    /// Returns the number of successfully processed packets.
    ///
    /// This method is used to get the total number of packets that have been successfully processed.
    /// The `packet_success` field is incremented each time a packet is successfully processed.
    ///
    /// # Returns
    /// A `u32` value representing the total number of successfully processed packets.
    pub fn get_packet_success(&self) -> u32 {
        self.packet_success
    }

    /// Adds an `IntermediateBuffer` to the `packets` array if there's available space.
    ///
    /// This method is used to add a new packet to the `packets` array. It first checks if the current number of packets
    /// is less than the maximum allowed (`N`). If there is space available, it finds the first empty slot in the `packets`
    /// array and inserts the new packet there, incrementing the `packet_number` counter. If the `packets` array is full,
    /// it returns an `Err` with `ERROR_BUFFER_OVERFLOW`.
    ///
    /// # Arguments
    ///
    /// * `packet`: A mutable reference to an `IntermediateBuffer` representing the new packet to be added.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the packet was successfully added.
    /// * `Err(ERROR_BUFFER_OVERFLOW.into())` if the `packets` array is full.
    pub fn push(&mut self, packet: &'a IntermediateBuffer) -> Result<()> {
        if (self.packet_number as usize) < N {
            if let Some(index) = self.first_empty_packet() {
                self.packets[index] = EthPacket {
                    buffer: Some(packet),
                };
                self.packet_number += 1;
                Ok(())
            } else {
                Err(ERROR_BUFFER_OVERFLOW.into())
            }
        } else {
            Err(ERROR_BUFFER_OVERFLOW.into())
        }
    }

    /// Returns the index of the first `EthPacketMut` which contains `None`.
    ///
    /// This method is used to find the first empty slot in the `packets` array. It iterates over the `packets` array,
    /// and for each `EthPacketMut` that does not have a buffer (i.e., its `buffer` field is `None`), it returns the index of that packet.
    /// If all `EthPacketMut` instances in the `packets` array have a buffer, this method returns `None`.
    ///
    /// # Returns
    /// An `Option<usize>` that is `Some(index)` if an empty `EthPacketMut` is found, where `index` is the index of the empty packet.
    /// If no empty `EthPacketMut` is found, it returns `None`.
    fn first_empty_packet(&self) -> Option<usize> {
        self.packets
            .iter()
            .position(|packet| packet.buffer.is_none())
    }

    /// Consumes packets from an Iterator, moving them into `self`.
    ///
    /// This method is used to add packets from an iterator to the `packets` array. It iterates over the packets provided by the iterator,
    /// and for each packet, it checks if there is space available in the `packets` array. If there is space available, it finds the first empty slot
    /// in the `packets` array and inserts the new packet there, incrementing the `packet_number` counter. If the `packets` array is full,
    /// it returns an `Err` with `ERROR_BUFFER_OVERFLOW`.
    ///
    /// # Arguments
    ///
    /// * `packets`: An iterator that yields mutable references to `IntermediateBuffer` instances.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if all packets from the iterator were successfully added.
    /// * `Err(ERROR_BUFFER_OVERFLOW.into())` if the `packets` array is full.
    pub fn append<I>(&mut self, packets: I) -> Result<()>
    where
        I: Iterator<Item = &'a IntermediateBuffer>,
    {
        for buffer in packets {
            if self.packet_number as usize >= N {
                return Err(ERROR_BUFFER_OVERFLOW.into());
            }

            if let Some(empty_slot) = self.first_empty_packet() {
                self.set_packet(empty_slot, buffer)?;
                self.packet_number += 1;
            } else {
                return Err(ERROR_BUFFER_OVERFLOW.into());
            }
        }

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_ethpacket() {
        assert_eq!(
            std::mem::size_of::<*mut IntermediateBuffer>(),
            std::mem::size_of::<EthPacket>()
        );
    }

    #[test]
    fn size_of_ethrequest() {
        assert_eq!(
            std::mem::size_of::<EthPacket>() + std::mem::size_of::<HANDLE>(),
            std::mem::size_of::<EthRequest>()
        );
    }

    #[test]
    fn size_of_ethmrequest() {
        assert_eq!(
            std::mem::size_of::<EthPacket>()
                + std::mem::size_of::<HANDLE>()
                + 2 * std::mem::size_of::<u32>(),
            std::mem::size_of::<EthMRequest<1>>()
        );
    }
}
