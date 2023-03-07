use bitflags::bitflags;
use std::mem::size_of;
use windows::{
    core::w,
    core::Result,
    Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE},
    Win32::Networking::WinSock::IN6_ADDR,
    Win32::Networking::WinSock::IN_ADDR,
};

pub const NDISRD_DRIVER_NAME: ::windows::core::PCWSTR = w!("\\\\.\\NDISRD");
pub const ADAPTER_NAME_SIZE: usize = 256;
pub const ADAPTER_LIST_SIZE: usize = 32;
pub const ETHER_ADDR_LENGTH: usize = 6;
pub const MAX_ETHER_FRAME: usize = 1514; // 9014usize bytes if driver was built with the JUMBO_FRAME_SUPPORTED
pub const RAS_LINK_BUFFER_LENGTH: usize = 2048;
pub const RAS_LINKS_MAX: usize = 256;
pub const IP_SUBNET_V4_TYPE: u32 = 1;
pub const IP_RANGE_V4_TYPE: u32 = 2;
pub const IP_SUBNET_V6_TYPE: u32 = 1;
pub const IP_RANGE_V6_TYPE: u32 = 2;
pub const ETH_802_3: u32 = 1;
pub const IPV4: u32 = 1;
pub const IPV6: u32 = 2;
pub const TCPUDP: u32 = 1;
pub const ICMP: u32 = 2;
pub const FILTER_PACKET_PASS: u32 = 1;
pub const FILTER_PACKET_DROP: u32 = 2;
pub const FILTER_PACKET_REDIRECT: u32 = 3;
pub const FILTER_PACKET_PASS_RDR: u32 = 4;
pub const FILTER_PACKET_DROP_RDR: u32 = 5;

bitflags! {
    #[derive(Default)]
    pub struct FilterFlags: u32 {
        const MSTCP_FLAG_SENT_TUNNEL = 1;
        const MSTCP_FLAG_RECV_TUNNEL = 2;
        const MSTCP_FLAG_SENT_LISTEN = 4;
        const MSTCP_FLAG_RECV_LISTEN = 8;
        const MSTCP_FLAG_FILTER_DIRECT = 16;
        const MSTCP_FLAG_LOOPBACK_FILTER = 32;
        const MSTCP_FLAG_LOOPBACK_BLOCK = 64;
        const MSTCP_FLAG_SENT_RECEIVE_TUNNEL = Self::MSTCP_FLAG_SENT_TUNNEL.bits | Self::MSTCP_FLAG_RECV_TUNNEL.bits;
        const MSTCP_FLAG_SENT_RECEIVE_LISTEN = Self::MSTCP_FLAG_SENT_LISTEN.bits | Self::MSTCP_FLAG_RECV_LISTEN.bits;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct DirectionFlags: u32 {
        const PACKET_FLAG_ON_SEND = 1;
        const PACKET_FLAG_ON_RECEIVE = 2;
        const PACKET_FLAG_ON_SEND_RECEIVE = Self::PACKET_FLAG_ON_SEND.bits | Self::PACKET_FLAG_ON_RECEIVE.bits;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct Eth802_3FilterFlags: u32 {
        const ETH_802_3_SRC_ADDRESS = 1;
        const ETH_802_3_DEST_ADDRESS = 2;
        const ETH_802_3_PROTOCOL = 4;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct IpV4FilterFlags: u32 {
        const IP_V4_FILTER_SRC_ADDRESS = 1;
        const IP_V4_FILTER_DEST_ADDRESS = 2;
        const IP_V4_FILTER_PROTOCOL = 4;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct IpV6FilterFlags: u32 {
        const IP_V6_FILTER_SRC_ADDRESS = 1;
        const IP_V6_FILTER_DEST_ADDRESS = 2;
        const IP_V6_FILTER_PROTOCOL = 4;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct TcpUdpFilterFlags: u32 {
        const TCPUDP_SRC_PORT = 1;
        const TCPUDP_DEST_PORT = 2;
        const TCPUDP_TCP_FLAGS = 4;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct IcmpFilterFlags: u32 {
        const ICMP_TYPE = 1;
        const ICMP_CODE = 2;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct FilterLayerFlags: u32 {
        const DATA_LINK_LAYER_VALID = 1;
        const NETWORK_LAYER_VALID = 2;
        const TRANSPORT_LAYER_VALID = 4;
    }
}

/// TcpAdapterList
/// * Rust equivalent for [_TCP_AdapterList](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_tcp_adapterlist/)
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

/// ListEntry
/// * Rust equivalent for [_LIST_ENTRY](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

/// IntermediateBufferHeaderUnion
/// * Rust equivalent for HANDLE and LIST_ENTRY union used for INTERMEDIATE_BUFFER
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union IntermediateBufferHeaderUnion {
    pub adapter_handle: HANDLE,
    pub list_entry: ListEntry,
}

impl Default for IntermediateBufferHeaderUnion {
    fn default() -> Self {
        // SAFETY: This union contains either a `HANDLE` or a `ListEntry`
        // ListEntry: is an union of raw pointers which can be safely zeroed(as long as you not dereference it)
        // HANDLE: is just an `isize` wrapper which can also be zeroed
        unsafe { core::mem::zeroed() }
    }
}

/// IntermediateBuffer
/// * Rust equivalent for [_INTERMEDIATE_BUFFER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_intermediate_buffer/)
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

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Buffer(pub [u8; MAX_ETHER_FRAME]);

impl Default for Buffer {
    fn default() -> Self {
        Self([0; MAX_ETHER_FRAME])
    }
}

impl IntermediateBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_device_flags(&self) -> DirectionFlags {
        self.device_flags
    }

    pub fn get_length(&self) -> u32 {
        self.length
    }

    pub fn set_length(&mut self, length: u32) {
        self.length = length
    }
}

/// AdapterMode
/// * Rust equivalent for [_ADAPTER_MODE](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/adapter_mode/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct AdapterMode {
    pub adapter_handle: HANDLE,
    pub flags: FilterFlags,
}

/// EthPacket
/// * Rust equivalent for [_NDISRD_ETH_Packet](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ndisrd_eth_packet/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthPacket {
    pub buffer: *mut IntermediateBuffer,
}

impl EthPacket {
    /// Returns the mutable reference to the IntermediateBuffer pointed to by the EthPacket
    ///
    /// # Safety
    ///
    /// This function is unsafe becasue EthPacket.buffer may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn get_buffer_mut(&mut self) -> &mut IntermediateBuffer {
        &mut *self.buffer
    }

    /// Returns the reference to the IntermediateBuffer pointed to by the EthPacket
    ///
    /// # Safety
    ///
    /// This function is unsafe because EthPacket.buffer may not be initilized or point to
    /// the invalid memory.
    pub unsafe fn get_buffer(&self) -> &IntermediateBuffer {
        &mut *self.buffer
    }
}

/// EthRequest
/// * Rust equivalent for [_ETH_REQUEST](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_request/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthRequest {
    pub adapter_handle: HANDLE,
    pub packet: EthPacket,
}

/// EthMRequest
/// * Rust equivalent for [_ETH_M_REQUEST](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_m_request/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthMRequest<const N: usize> {
    adapter_handle: HANDLE,
    packet_number: u32,
    packet_success: u32,
    packets: [EthPacket; N],
}

impl<const N: usize> EthMRequest<N> {
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

    pub fn at(&self, index: usize) -> Option<EthPacket> {
        if index < self.packet_number as usize {
            Some(self.packets[index])
        } else {
            None
        }
    }

    pub fn get_packet_number(&self) -> u32 {
        self.packet_number
    }

    pub fn set_packet_number(&mut self, number: u32) {
        self.packet_number = number;
    }

    pub fn reset(&mut self) {
        self.set_packet_number(0);
    }

    pub fn get_packet_success(&self) -> u32 {
        self.packet_success
    }

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

/// AdapterEvent
/// * Rust equivalent for [_ADAPTER_EVENT](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/adapter_event/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AdapterEvent {
    pub adapter_handle: HANDLE,
    pub event_handle: HANDLE,
}

/// PacketOidData
/// * Rust equivalent for [_PACKET_OID_DATA](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_packet_oid_data/)
#[repr(C, packed)]
pub struct PacketOidData<T> {
    pub adapter_handle: HANDLE,
    pub oid: u32,
    pub length: u32,
    pub data: T,
}

impl<T> PacketOidData<T> {
    pub fn new(adapter_handle: HANDLE, oid: u32, data: T) -> Self {
        Self {
            adapter_handle,
            oid,
            length: size_of::<T>() as u32,
            data,
        }
    }
}

/// RasLinkInformation
/// * Rust equivalent for [_RAS_LINK_INFO](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ras_link_info/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RasLinkInformation {
    link_speed: u32,
    maximum_total_size: u32,
    remote_address: [u8; ETHER_ADDR_LENGTH],
    local_address: [u8; ETHER_ADDR_LENGTH],
    protocol_buffer_length: u32,
    protocol_buffer: [u8; RAS_LINK_BUFFER_LENGTH],
}

impl RasLinkInformation {
    pub fn get_link_speed(&self) -> u32 {
        self.link_speed
    }

    pub fn get_maximum_total_size(&self) -> u32 {
        self.maximum_total_size
    }

    pub fn get_remote_address(&self) -> &[u8; ETHER_ADDR_LENGTH] {
        &self.remote_address
    }

    pub fn get_local_address(&self) -> &[u8; ETHER_ADDR_LENGTH] {
        &self.local_address
    }

    pub fn get_protocol_buffer_length(&self) -> usize {
        self.protocol_buffer_length as usize
    }

    pub fn get_protocol_buffer(&self) -> &[u8; RAS_LINK_BUFFER_LENGTH] {
        &self.protocol_buffer
    }
}

/// RasLinks
/// * Rust equivalent for [_RAS_LINKS](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ras_links/)
/// This struct is too large to be allocated on the stack in Rust and may result in stack overflow
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RasLinks {
    number_of_links: u32,
    pub ras_links: [RasLinkInformation; RAS_LINKS_MAX],
}

impl Default for RasLinks {
    fn default() -> Self {
        // SAFETY: This structure is filled by the information by NDIS filter driver when passed as a memory buffer
        // along with IOCTL_NDISRD_GET_RAS_LINKS. It is safe to be zeroed because contains only values and arrays that
        // can be default initialized with zeroes
        unsafe { std::mem::zeroed() }
    }
}

impl RasLinks {
    pub fn get_number_of_links(&self) -> usize {
        self.number_of_links as usize
    }
}

/// Eth802_3Filter
/// * Rust equivalent for [_ETH_802_3_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_802_3_filter/)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Eth8023Filter {
    pub valid_fields: Eth802_3FilterFlags,
    pub src_address: [u8; ETHER_ADDR_LENGTH],
    pub dest_address: [u8; ETHER_ADDR_LENGTH],
    pub protocol: u16,
    pub padding: u16,
}

impl Default for Eth8023Filter {
    fn default() -> Self {
        // SAFETY: It is safe to be zeroed because contains only values and arrays that
        // can be default initialized with zeroes
        unsafe { std::mem::zeroed() }
    }
}

/// IpSubnetV4
/// * Rust equivalent for [_IP_SUBNET_V4](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_subnet_v4/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpSubnetV4 {
    pub ip: IN_ADDR,
    pub ip_mask: IN_ADDR,
}

/// IpRangeV4
/// * Rust equivalent for [_IP_RANGE_V4](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_range_v4/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpRangeV4 {
    pub start_ip: IN_ADDR,
    pub end_ip: IN_ADDR,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union IpAddressV4Union {
    pub ip_subnet: IpSubnetV4,
    pub ip_range: IpRangeV4,
}

impl Default for IpAddressV4Union {
    fn default() -> Self {
        // SAFETY: This union contains either a `IpSubnetV4` or a `IpRangeV4`
        // IpSubnetV4: when zeroed is equivalent to 0.0.0.0/0
        // IpRangeV4: when zeroed is equivalent to 0.0.0.0 - 0.0.0.0
        unsafe { std::mem::zeroed() }
    }
}

/// IpAddressV4
/// * Rust equivalent for [_IP_ADDRESS_V4](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_address_v4/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpAddressV4 {
    pub address_type: u32, // IP_SUBNET_V4_TYPE or IP_RANGE_V4_TYPE
    pub address: IpAddressV4Union,
}

/// IpV4Filter
/// * Rust equivalent for [_IP_V4_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_v4_filter/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpV4Filter {
    pub valid_fields: IpV4FilterFlags,
    pub src_address: IpAddressV4,
    pub dest_address: IpAddressV4,
    pub protocol: u8,
    pub padding: [u8; 3usize],
}

/// IpSubnetV6
/// * Rust equivalent for [_IP_ADDRESS_V6](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_address_v6/)
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct IpSubnetV6 {
    pub ip: IN6_ADDR,
    pub ip_mask: IN6_ADDR,
}

/// IpRangeV6
/// * Rust equivalent for [_IP_RANGE_V6](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_range_v6/)
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct IpRangeV6 {
    pub start_ip: IN6_ADDR,
    pub end_ip: IN6_ADDR,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union IpAddressV6Union {
    pub ip_subnet: IpSubnetV6,
    pub ip_range: IpRangeV6,
}

impl Default for IpAddressV6Union {
    fn default() -> Self {
        // SAFETY: This union contains either a `IpSubnetV6` or a `IpRangeV6`
        // IpSubnetV6: when zeroed is equivalent to ::/0
        // IpRangeV6: when zeroed is equivalent to :: - ::
        unsafe { std::mem::zeroed() }
    }
}

/// IpAddressV6
/// * Rust equivalent for [_IP_ADDRESS_V6](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_address_v6/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpAddressV6 {
    pub address_type: u32, // IP_SUBNET_V6_TYPE or IP_RANGE_V6_TYPE
    pub address: IpAddressV6Union,
}

/// IpV6Filter
/// * Rust equivalent for [_IP_V6_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_v6_filter/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpV6Filter {
    pub valid_fields: IpV6FilterFlags,
    pub src_address: IpAddressV6,
    pub dest_address: IpAddressV6,
    pub protocol: u8,
    pub padding: [u8; 3usize],
}

/// PortRange
/// * Rust equivalent for [_PORT_RANGE](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_port_range/)
#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct PortRange {
    pub start_range: u16,
    pub end_range: u16,
}

///
/// * Rust equivalent for [_TCPUDP_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_tcpudp_filter/)
#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct TcpUdpFilter {
    pub valid_fields: TcpUdpFilterFlags,
    pub source_port: PortRange,
    pub dest_port: PortRange,
    pub tcp_flags: u8,
    pub padding: [u8; 3usize],
}

/// ByteRange
/// * Rust equivalent for _BYTE_RANGE
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct ByteRange {
    pub start_range: u8,
    pub end_range: u8,
}

/// IcmpFilter
/// * Rust equivalent for _ICMP_FILTER
#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct IcmpFilter {
    pub valid_fields: IcmpFilterFlags,
    pub type_range: ByteRange,
    pub code_range: ByteRange,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union DataLinkLayerFilterUnion {
    pub eth_8023_filter: Eth8023Filter,
}

impl Default for DataLinkLayerFilterUnion {
    fn default() -> Self {
        // SAFETY: This union contains either a `Eth8023Filter`
        // Eth8023Filter: when zeroed is meaningless and ignored by code
        unsafe { std::mem::zeroed() }
    }
}

/// DataLinkLayerFilter
/// * Rust equivalent for [_DATA_LINK_LAYER_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/data_link_layer_filter/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct DataLinkLayerFilter {
    pub union_selector: u32, // ETH_802_3 for Eth8023Filter
    pub data_link_layer: DataLinkLayerFilterUnion,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union NetworkLayerFilterUnion {
    pub ipv4: IpV4Filter,
    pub ipv6: IpV6Filter,
}

impl Default for NetworkLayerFilterUnion {
    fn default() -> Self {
        // SAFETY: This union contains either a `IpV4Filter` or `IpV6Filter'
        // IpV4Filter: when zeroed is meaningless and ignored by code
        // IpV6Filter: when zeroed is meaningless and ignored by code
        unsafe { std::mem::zeroed() }
    }
}

/// NetworkLayerFilter
/// * Rust equivalent for [_NETWORK_LAYER_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_network_layer_filter/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct NetworkLayerFilter {
    pub union_selector: u32, // IPV4 for IpV4Filter, IPV6 for IpV6Filter
    pub network_layer: NetworkLayerFilterUnion,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union TransportLayerFilterUnion {
    pub tcp_udp: TcpUdpFilter,
    pub icmp: IcmpFilter,
}

impl Default for TransportLayerFilterUnion {
    fn default() -> Self {
        // SAFETY: This union contains either a `TcpUdpFilter` or `IcmpFilter'
        // TcpUdpFilter: when zeroed is meaningless and ignored by code
        // IcmpFilter: when zeroed is meaningless and ignored by code
        unsafe { std::mem::zeroed() }
    }
}

/// TransportLayerFilter
/// * Rust equivalent for [_TRANSPORT_LAYER_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_transport_layer_filter/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct TransportLayerFilter {
    pub union_selector: u32, // TCPUDP for TcpUdpFilter, ICMP for IcmpFilter
    pub transport_layer: TransportLayerFilterUnion,
}

/// StaticFilter
/// * Rust equivalent for [_STATIC_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_static_filter/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct StaticFilter {
    pub adapter_handle: u64, // Adapter handle extended to 64 bit size for structure compatibility across x64 and x86
    pub direction_flags: DirectionFlags, // PACKET_FLAG_ON_SEND or/and PACKET_FLAG_ON_RECEIVE
    pub filter_action: u32,  // FILTER_PACKET_XXX
    pub valid_fields: FilterLayerFlags, // Specifies which of the fields below contain valid values and should be matched against the packet
    pub last_reset: u32, // Time of the last counters reset (in seconds passed since 1 Jan 1980)
    pub packets_in: u64, // Incoming packets passed through this filter
    pub bytes_in: u64,   // Incoming bytes passed through this filter
    pub packets_out: u64, // Outgoing packets passed through this filter
    pub bytes_out: u64,  // Outgoing bytes passed through this filter
    pub data_link_filter: DataLinkLayerFilter,
    pub network_filter: NetworkLayerFilter,
    pub transport_filter: TransportLayerFilter,
}

/// StaticFilterTable
/// * Rust equivalent to the [_STATIC_FILTER_TABLE](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_static_filter_table/)
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct StaticFilterTable<const N: usize> {
    pub table_size: u32,
    pub padding: u32,
    pub static_filters: [StaticFilter; N],
}

impl<const N: usize> StaticFilterTable<N> {
    pub fn new() -> Self {
        Self {
            table_size: N as u32,
            padding: 0u32,
            static_filters: [StaticFilter::default(); N],
        }
    }
}

impl<const N: usize> Default for StaticFilterTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct FastIoWriteUnionStruct {
    pub number_of_packets: u16,
    pub write_in_progress_flag: u16,
}

/// FastIoWriteUnion
/// * Rust equivalent for _FAST_IO_WRITE_UNION
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union FastIoWriteUnion {
    pub split: FastIoWriteUnionStruct,
    pub join: u32,
}

impl Default for FastIoWriteUnion {
    fn default() -> Self {
        FastIoWriteUnion { join: 0 }
    }
}

/// FastIoSectionHeader
/// * Rust equivalent for _FAST_IO_SECTION_HEADER
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct FastIoSectionHeader {
    pub fast_io_write_union: FastIoWriteUnion,
    pub read_in_progress_flag: u32,
}

/// FastIoSection
/// * Rust equivalent for _FAST_IO_SECTION
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct FastIoSection<const N: usize> {
    pub fast_io_header: FastIoSectionHeader,
    pub fast_io_packets: [IntermediateBuffer; N],
}

impl<const N: usize> Default for FastIoSection<N> {
    fn default() -> Self {
        // SAFETY: This structure is filled by information by NDIS filter driver
        // Zero initialized FastIoSection<N> is completely valid and ignored by the code
        unsafe { std::mem::zeroed() }
    }
}

/// InitializeFastIoParams
/// * Rust equivalent for _INITIALIZE_FAST_IO_PARAMS
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct InitializeFastIoParams<const N: usize> {
    pub header_ptr: *mut FastIoSection<N>,
    pub data_size: u32,
}

/// UnsortedReadSendRequest
/// * Rust equivalent for _UNSORTED_READ_SEND_REQUEST
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct UnsortedReadSendRequest<const N: usize> {
    pub packets: *mut [IntermediateBuffer; N],
    pub packets_num: u32,
}

// Device and ioctl codes
const FILE_DEVICE_NDISRD: u32 = 0x00008300;
const NDISRD_IOCTL_INDEX: u32 = 0x830;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const IOCTL_NDISRD_GET_VERSION: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_GET_TCPIP_INTERFACES: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 1,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 2,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SEND_PACKET_TO_MSTCP: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 3,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_READ_PACKET: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 4,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SET_ADAPTER_MODE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 5,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 6,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SET_EVENT: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 7,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_NDIS_SET_REQUEST: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 8,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_NDIS_GET_REQUEST: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 9,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SET_WAN_EVENT: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 10,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SET_ADAPTER_EVENT: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 11,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_ADAPTER_QUEUE_SIZE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 12,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_GET_ADAPTER_MODE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 13,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SET_PACKET_FILTERS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 14,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_RESET_PACKET_FILTERS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 15,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 16,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_GET_PACKET_FILTERS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 17,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 18,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_GET_RAS_LINKS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 19,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 20,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 21,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_READ_PACKETS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 22,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 23,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_INITIALIZE_FAST_IO: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 24,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_READ_PACKETS_UNSORTED: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 25,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 26,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 27,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 28,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
