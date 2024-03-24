//! # Submodule: Basic NDISAPI static filter definitions
//!
//! This submodule contains various structures used for static filters in the NDISAPI Rust library.
//!
//! The `filters` submodule provides a Rust interface for configuring static filters for the Windows Packet
//! Filter driver. It contains structures for specifying filter conditions and actions for various protocols,
//! including Ethernet 802.3, IPv4, IPv6, TCP, UDP, and ICMP. These structures allow users to define complex
//! filtering rules based on multiple packet fields and layers.
//!
//! # Structures
//!
//! * [`Eth8023Filter`] - Represents a static filter for Ethernet 802.3 frames.
//! * [`IpV4Filter`] - Represents a static filter for IPv4 packets.
//! * [`IpV6Filter`] - Represents a static filter for IPv6 packets.
//! * [`TcpUdpFilter`] - Represents a static filter for TCP and UDP packets.
//! * [`IcmpFilter`] - Represents a static filter for ICMP packets.
//! * [`StaticFilter`] - Represents a single static filter entry that combines filter conditions for various
//! layers and the filter action to be taken.
//! * [`StaticFilterTable`] - Represents a table of static filters, used for managing multiple static filter entries.

// Import required external crates and types
use windows::{Win32::Networking::WinSock::IN6_ADDR, Win32::Networking::WinSock::IN_ADDR};

use super::constants::*;

/// This structure is used to define an Ethernet 802.3 filter based on various fields like source and destination addresses, and protocol.
///
/// A Rust equivalent for the [_ETH_802_3_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_eth_802_3_filter/) structure.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Eth8023Filter {
    /// A bitmask indicating which fields in the filter are valid.
    pub valid_fields: Eth802_3FilterFlags,
    /// The source address to filter on.
    pub src_address: [u8; ETHER_ADDR_LENGTH],
    /// The destination address to filter on.
    pub dest_address: [u8; ETHER_ADDR_LENGTH],
    /// The protocol (Ethertype) to filter on.
    pub protocol: u16,
    /// Padding to align the structure.
    pub padding: u16,
}

/// Creates a new `Eth8023Filter` instance.
///
/// # Arguments
///
/// * `valid_fields` - A bitmask indicating which fields in the filter are valid.
/// * `src_address` - The source address to filter on.
/// * `dest_address` - The destination address to filter on.
/// * `protocol` - The protocol (Ethertype) to filter on.
///
/// # Returns
///
/// * A new `Eth8023Filter` instance.
impl Eth8023Filter {
    pub fn new(
        valid_fields: Eth802_3FilterFlags,
        src_address: [u8; ETHER_ADDR_LENGTH],
        dest_address: [u8; ETHER_ADDR_LENGTH],
        protocol: u16,
    ) -> Self {
        Self {
            valid_fields,
            src_address,
            dest_address,
            protocol,
            padding: 0, // padding is usually set to 0
        }
    }
}

impl Default for Eth8023Filter {
    /// Returns a zero-initialized instance of `Eth8023Filter`.
    ///
    /// # Safety
    ///
    /// It is safe to zero-initialize this structure because it contains only values and arrays that
    /// can be default initialized with zeroes.
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// This structure is used to represent an IPv4 subnet based on an IP address and a subnet mask.
///
/// A Rust equivalent for the [_IP_SUBNET_V4](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_subnet_v4/) structure.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpSubnetV4 {
    /// The IPv4 address.
    pub ip: IN_ADDR,
    /// The subnet mask.
    pub ip_mask: IN_ADDR,
}

/// Creates a new `IpSubnetV4` instance.
///
/// # Arguments
///
/// * `ip` - The IPv4 address.
/// * `ip_mask` - The subnet mask.
///
/// # Returns
///
/// * A new `IpSubnetV4` instance.
impl IpSubnetV4 {
    pub fn new(ip: IN_ADDR, ip_mask: IN_ADDR) -> Self {
        Self { ip, ip_mask }
    }
}

/// This structure is used to represent an IPv4 address range based on a start and end IP address.
///
/// A Rust equivalent for the [_IP_RANGE_V4](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_range_v4/) structure.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpRangeV4 {
    /// The start of the IPv4 address range.
    pub start_ip: IN_ADDR,
    /// The end of the IPv4 address range.
    pub end_ip: IN_ADDR,
}

/// Creates a new `IpRangeV4` instance.
///
/// # Arguments
///
/// * `start_ip` - The start of the IPv4 address range.
/// * `end_ip` - The end of the IPv4 address range.
///
/// # Returns
///
/// * A new `IpRangeV4` instance.
impl IpRangeV4 {
    pub fn new(start_ip: IN_ADDR, end_ip: IN_ADDR) -> Self {
        Self { start_ip, end_ip }
    }
}

/// A Rust union representing either an IPv4 subnet (IpSubnetV4) or an IPv4 address range (IpRangeV4).
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union IpAddressV4Union {
    /// The IPv4 subnet representation.
    pub ip_subnet: IpSubnetV4,
    /// The IPv4 address range representation.
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

/// Represents an IPv4 address in a format used by the packet filtering mechanism.
///
/// A Rust equivalent for [_IP_ADDRESS_V4](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_address_v4/).
///
/// The `address_type` field indicates whether the address is a subnet or a range.
/// The `address` field contains the actual IPv4 address information in a union format.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpAddressV4 {
    pub address_type: u32, // IP_SUBNET_V4_TYPE or IP_RANGE_V4_TYPE
    pub address: IpAddressV4Union,
}

/// Creates a new `IpAddressV4` instance.
///
/// # Arguments
///
/// * `address_type` - Indicates whether the address is a subnet or a range.
/// * `address` - Contains the actual IPv4 address information in a union format.
///
/// # Returns
///
/// * A new `IpAddressV4` instance.
impl IpAddressV4 {
    pub fn new(address_type: u32, address: IpAddressV4Union) -> Self {
        Self {
            address_type,
            address,
        }
    }
}

/// Represents an IPv4 filter used by the packet filtering mechanism.
///
/// A Rust equivalent for [_IP_V4_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_v4_filter/).
///
/// The `valid_fields` field specifies which fields in the filter structure are used for filtering.
/// The `src_address` field contains the source IPv4 address information.
/// The `dest_address` field contains the destination IPv4 address information.
/// The `protocol` field represents the IP protocol number.
/// The `padding` field is used for alignment purposes.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpV4Filter {
    pub valid_fields: IpV4FilterFlags,
    pub src_address: IpAddressV4,
    pub dest_address: IpAddressV4,
    pub protocol: u8,
    pub padding: [u8; 3usize],
}

/// Creates a new `IpV4Filter` instance.
///
/// # Arguments
///
/// * `valid_fields` - Specifies which fields in the filter structure are used for filtering.
/// * `src_address` - Contains the source IPv4 address information.
/// * `dest_address` - Contains the destination IPv4 address information.
/// * `protocol` - Represents the IP protocol number.
///
/// # Returns
///
/// * A new `IpV4Filter` instance.
impl IpV4Filter {
    pub fn new(
        valid_fields: IpV4FilterFlags,
        src_address: IpAddressV4,
        dest_address: IpAddressV4,
        protocol: u8,
    ) -> Self {
        Self {
            valid_fields,
            src_address,
            dest_address,
            protocol,
            padding: [0; 3], // padding is usually set to 0
        }
    }
}

/// Represents an IPv6 subnet used by the packet filtering mechanism.
///
/// A Rust equivalent for [_IP_SUBNET_V6](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_subnet_v6/).
///
/// The `ip` field contains the IPv6 address.
/// The `ip_mask` field contains the subnet mask.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct IpSubnetV6 {
    pub ip: IN6_ADDR,
    pub ip_mask: IN6_ADDR,
}

/// Creates a new `IpSubnetV6` instance.
///
/// # Arguments
///
/// * `ip` - The IPv6 address.
/// * `ip_mask` - The subnet mask.
///
/// # Returns
///
/// * A new `IpSubnetV6` instance.
impl IpSubnetV6 {
    pub fn new(ip: IN6_ADDR, ip_mask: IN6_ADDR) -> Self {
        Self { ip, ip_mask }
    }
}

/// Represents an IPv6 address range used by the packet filtering mechanism.
///
/// A Rust equivalent for [_IP_RANGE_V6](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_range_v6/).
///
/// The `start_ip` field contains the starting IPv6 address of the range.
/// The `end_ip` field contains the ending IPv6 address of the range.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct IpRangeV6 {
    pub start_ip: IN6_ADDR,
    pub end_ip: IN6_ADDR,
}

/// Creates a new `IpRangeV6` instance.
///
/// # Arguments
///
/// * `start_ip` - The start of the IPv6 address range.
/// * `end_ip` - The end of the IPv6 address range.
///
/// # Returns
///
/// * A new `IpRangeV6` instance.
impl IpRangeV6 {
    pub fn new(start_ip: IN6_ADDR, end_ip: IN6_ADDR) -> Self {
        Self { start_ip, end_ip }
    }
}

/// This structure is used to store information about a particular address space
/// for packet filtering purposes.
///
/// A Rust union that represents either an IPv6 subnet or an IPv6 address range.
///
/// The `ip_subnet` field contains the IPv6 subnet if the address space is a subnet.
/// The `ip_range` field contains the IPv6 address range if the address space is a range.
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

/// This structure is used to store information about an IPv6 address for packet filtering purposes.
///
/// Rust equivalent for [_IP_ADDRESS_V6](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_address_v6/).
///
/// The `address_type` field indicates whether the address is a subnet (IP_SUBNET_V6_TYPE) or a range (IP_RANGE_V6_TYPE).
/// The `address` field contains the specific IPv6 address data, either a subnet or an address range, depending on the `address_type`.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpAddressV6 {
    pub address_type: u32, // IP_SUBNET_V6_TYPE or IP_RANGE_V6_TYPE
    pub address: IpAddressV6Union,
}

/// Creates a new `IpAddressV6` instance.
///
/// # Arguments
///
/// * `address_type` - Indicates whether the address is a subnet or a range.
/// * `address` - Contains the specific IPv6 address data, either a subnet or an address range, depending on the `address_type`.
///
/// # Returns
///
/// * A new `IpAddressV6` instance.
impl IpAddressV6 {
    pub fn new(address_type: u32, address: IpAddressV6Union) -> Self {
        Self {
            address_type,
            address,
        }
    }
}

/// This structure is used to define packet filtering rules for IPv6 packets.
///
/// Rust equivalent for [_IP_V6_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_ip_v6_filter/).
///
/// The `valid_fields` field contains flags that specify which fields of the filter are active.
/// The `src_address` and `dest_address` fields store information about the source and destination IPv6 addresses respectively.
/// The `protocol` field represents the protocol used in the packet (e.g., TCP, UDP).
/// The `padding` field is reserved for padding to ensure the correct alignment of the structure.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct IpV6Filter {
    pub valid_fields: IpV6FilterFlags,
    pub src_address: IpAddressV6,
    pub dest_address: IpAddressV6,
    pub protocol: u8,
    pub padding: [u8; 3usize],
}

/// Creates a new `IpV6Filter` instance.
///
/// # Arguments
///
/// * `valid_fields` - Specifies which fields in the filter structure are used for filtering.
/// * `src_address` - Contains the source IPv6 address information.
/// * `dest_address` - Contains the destination IPv6 address information.
/// * `protocol` - Represents the IP protocol number.
///
/// # Returns
///
/// * A new `IpV6Filter` instance.
impl IpV6Filter {
    pub fn new(
        valid_fields: IpV6FilterFlags,
        src_address: IpAddressV6,
        dest_address: IpAddressV6,
        protocol: u8,
    ) -> Self {
        Self {
            valid_fields,
            src_address,
            dest_address,
            protocol,
            padding: [0; 3], // padding is usually set to 0
        }
    }
}

/// This structure is used to define a range of port numbers for packet filtering rules.
///
/// Rust equivalent for [_PORT_RANGE](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_port_range/).
///
/// The `start_range` field represents the starting port number in the range.
/// The `end_range` field represents the ending port number in the range.
#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct PortRange {
    pub start_range: u16,
    pub end_range: u16,
}

/// Creates a new `PortRange` instance.
///
/// # Arguments
///
/// * `start_range` - The start of the port range.
/// * `end_range` - The end of the port range.
///
/// # Returns
///
/// * A new `PortRange` instance.
impl PortRange {
    pub fn new(start_range: u16, end_range: u16) -> Self {
        Self {
            start_range,
            end_range,
        }
    }
}

/// This structure is used to define filtering rules for TCP and UDP packets.
///
/// Rust equivalent for [_TCPUDP_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_tcpudp_filter/).
///
/// The `valid_fields` field specifies which fields in the structure are valid for filtering.
/// The `source_port` field represents the range of source port numbers to filter.
/// The `dest_port` field represents the range of destination port numbers to filter.
/// The `tcp_flags` field is used to filter TCP packets based on their flags.
/// The `padding` field ensures proper alignment of the structure.
#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct TcpUdpFilter {
    pub valid_fields: TcpUdpFilterFlags,
    pub source_port: PortRange,
    pub dest_port: PortRange,
    pub tcp_flags: u8,
    pub padding: [u8; 3usize],
}

/// Creates a new `TcpUdpFilter` instance.
///
/// # Arguments
///
/// * `valid_fields` - Specifies which fields in the filter structure are valid for filtering.
/// * `source_port` - Represents the range of source port numbers to filter.
/// * `dest_port` - Represents the range of destination port numbers to filter.
/// * `tcp_flags` - Used to filter TCP packets based on their flags.
///
/// # Returns
///
/// * A new `TcpUdpFilter` instance.
impl TcpUdpFilter {
    pub fn new(
        valid_fields: TcpUdpFilterFlags,
        source_port: PortRange,
        dest_port: PortRange,
        tcp_flags: u8,
    ) -> Self {
        Self {
            valid_fields,
            source_port,
            dest_port,
            tcp_flags,
            padding: [0; 3], // padding is usually set to 0
        }
    }
}

/// A Rust struct that represents a range of byte values.
///
/// Rust equivalent for _BYTE_RANGE. This structure can be used to define
/// filtering rules based on byte ranges, such as ICMP type or code ranges.
///
/// The `start_range` field represents the start of the byte range.
/// The `end_range` field represents the end of the byte range.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct ByteRange {
    pub start_range: u8,
    pub end_range: u8,
}

/// Creates a new `ByteRange` instance.
///
/// # Arguments
///
/// * `start_range` - The start of the byte range.
/// * `end_range` - The end of the byte range.
///
/// # Returns
///
/// * A new `ByteRange` instance.
impl ByteRange {
    pub fn new(start_range: u8, end_range: u8) -> Self {
        Self {
            start_range,
            end_range,
        }
    }
}

/// A Rust struct that represents an ICMP filter.
///
/// Rust equivalent for _ICMP_FILTER. This structure can be used to define
/// filtering rules for ICMP packets based on ICMP type and code ranges.
///
/// The `valid_fields` field specifies which fields in the filter are valid for filtering.
/// The `type_range` field represents a range of ICMP types for filtering.
/// The `code_range` field represents a range of ICMP codes for filtering.
#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct IcmpFilter {
    pub valid_fields: IcmpFilterFlags,
    pub type_range: ByteRange,
    pub code_range: ByteRange,
}

/// Creates a new `IcmpFilter` instance.
///
/// # Arguments
///
/// * `valid_fields` - Specifies which fields in the filter are valid for filtering.
/// * `type_range` - Represents a range of ICMP types for filtering.
/// * `code_range` - Represents a range of ICMP codes for filtering.
///
/// # Returns
///
/// * A new `IcmpFilter` instance.
impl IcmpFilter {
    pub fn new(
        valid_fields: IcmpFilterFlags,
        type_range: ByteRange,
        code_range: ByteRange,
    ) -> Self {
        Self {
            valid_fields,
            type_range,
            code_range,
        }
    }
}

/// A Rust union that holds an `Eth8023Filter`.
///
/// This union can be extended to include other data link layer filters if needed.
/// Currently, it only contains an `Eth8023Filter` for filtering Ethernet/802.3 packets.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union DataLinkLayerFilterUnion {
    pub eth_8023_filter: Eth8023Filter,
}

impl Default for DataLinkLayerFilterUnion {
    fn default() -> Self {
        // SAFETY: This union contains an `Eth8023Filter`
        // Eth8023Filter: when zeroed is meaningless and ignored by code
        unsafe { std::mem::zeroed() }
    }
}

/// A Rust struct that represents a data link layer filter.
///
/// Rust equivalent for [_DATA_LINK_LAYER_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/data_link_layer_filter/)
/// This struct can be used to filter packets at the data link layer (e.g., Ethernet/802.3) by specifying the filter type in `union_selector`.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct DataLinkLayerFilter {
    pub union_selector: u32, // ETH_802_3 for Eth8023Filter
    pub data_link_layer: DataLinkLayerFilterUnion,
}

/// Creates a new `DataLinkLayerFilter` instance.
///
/// # Arguments
///
/// * `union_selector` - Specifies the filter type (e.g., ETH_802_3 for Eth8023Filter).
/// * `data_link_layer` - Contains the actual data link layer filter information in a union format.
///
/// # Returns
///
/// * A new `DataLinkLayerFilter` instance.
impl DataLinkLayerFilter {
    pub fn new(union_selector: u32, data_link_layer: DataLinkLayerFilterUnion) -> Self {
        Self {
            union_selector,
            data_link_layer,
        }
    }
}

/// A Rust union that holds either an `IpV4Filter` or an `IpV6Filter`.
///
/// This union can be used to filter packets at the network layer by specifying the appropriate filter type (IPv4 or IPv6).
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

/// A Rust struct that represents a network layer filter.
///
/// Rust equivalent for [_NETWORK_LAYER_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_network_layer_filter/).
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct NetworkLayerFilter {
    /// union_selector: A field that determines the type of the network layer filter.
    /// Set to IPV4 for IpV4Filter, and IPV6 for IpV6Filter.
    pub union_selector: u32,
    /// network_layer: A union that holds either an IpV4Filter or an IpV6Filter,
    /// depending on the value of the union_selector field.
    pub network_layer: NetworkLayerFilterUnion,
}

/// Creates a new `NetworkLayerFilter` instance.
///
/// # Arguments
///
/// * `union_selector` - A field that determines the type of the network layer filter.
/// * `network_layer` - A union that holds either an IpV4Filter or an IpV6Filter.
///
/// # Returns
///
/// * A new `NetworkLayerFilter` instance.
impl NetworkLayerFilter {
    pub fn new(union_selector: u32, network_layer: NetworkLayerFilterUnion) -> Self {
        Self {
            union_selector,
            network_layer,
        }
    }
}

/// A Rust union that represents a transport layer filter.
///
/// Holds either a `TcpUdpFilter` or an `IcmpFilter`.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union TransportLayerFilterUnion {
    /// tcp_udp: A TcpUdpFilter struct that represents a TCP/UDP filter.
    pub tcp_udp: TcpUdpFilter,
    /// icmp: An IcmpFilter struct that represents an ICMP filter.
    pub icmp: IcmpFilter,
}

impl Default for TransportLayerFilterUnion {
    fn default() -> Self {
        // SAFETY: This union contains either a `TcpUdpFilter` or an `IcmpFilter`
        // TcpUdpFilter: when zeroed is meaningless and ignored by code
        // IcmpFilter: when zeroed is meaningless and ignored by code
        unsafe { std::mem::zeroed() }
    }
}

/// A Rust struct that represents a transport layer filter.
///
/// Rust equivalent for [_TRANSPORT_LAYER_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_transport_layer_filter/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct TransportLayerFilter {
    /// union_selector: A u32 flag that selects the appropriate filter.
    /// Use TCPUDP for TcpUdpFilter and ICMP for IcmpFilter.
    pub union_selector: u32,
    /// transport_layer: A TransportLayerFilterUnion that holds either a `TcpUdpFilter` or an `IcmpFilter`.
    pub transport_layer: TransportLayerFilterUnion,
}

/// Creates a new `TransportLayerFilter` instance.
///
/// # Arguments
///
/// * `union_selector` - A u32 flag that selects the appropriate filter. Use TCPUDP for TcpUdpFilter and ICMP for IcmpFilter.
/// * `transport_layer` - A TransportLayerFilterUnion that holds either a `TcpUdpFilter` or an `IcmpFilter`.
///
/// # Returns
///
/// * A new `TransportLayerFilter` instance.
impl TransportLayerFilter {
    pub fn new(union_selector: u32, transport_layer: TransportLayerFilterUnion) -> Self {
        Self {
            union_selector,
            transport_layer,
        }
    }
}

/// This structure is used to define a single static filter rule for packet filtering. Each rule can specify filtering criteria at
/// the data link, network, and transport layers. The structure also includes counters for incoming and outgoing packets and bytes
/// that match the filter rule.
///
/// * Rust equivalent for [_STATIC_FILTER](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_static_filter/)
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct StaticFilter {
    /// Adapter handle extended to 64 bit size for structure compatibility across x64 and x86 architectures
    pub adapter_handle: u64,
    /// PACKET_FLAG_ON_SEND or/and PACKET_FLAG_ON_RECEIVE to specify the direction of packets to match
    pub direction_flags: DirectionFlags,
    /// FILTER_PACKET_XXX to define the action to take when a packet matches the filter
    pub filter_action: u32,
    /// Specifies which of the fields below contain valid values and should be matched against the packet
    pub valid_fields: FilterLayerFlags,
    /// Time of the last counters reset (in seconds passed since 1 Jan 1980)
    pub last_reset: u32,
    /// Incoming packets passed through this filter
    pub packets_in: u64,
    /// Incoming bytes passed through this filter
    pub bytes_in: u64,
    /// Outgoing packets passed through this filter
    pub packets_out: u64,
    /// Outgoing bytes passed through this filter
    pub bytes_out: u64,
    /// Filter criteria for the data link layer (e.g., Ethernet)
    pub data_link_filter: DataLinkLayerFilter,
    /// Filter criteria for the network layer (e.g., IPv4, IPv6)
    pub network_filter: NetworkLayerFilter,
    /// Filter criteria for the transport layer (e.g., TCP, UDP, ICMP)
    pub transport_filter: TransportLayerFilter,
}

/// Creates a new `StaticFilter` instance.
///
/// # Arguments
///
/// * `adapter_handle` - Adapter handle extended to 64 bit size for structure compatibility across x64 and x86 architectures.
/// * `direction_flags` - PACKET_FLAG_ON_SEND or/and PACKET_FLAG_ON_RECEIVE to specify the direction of packets to match.
/// * `filter_action` - FILTER_PACKET_XXX to define the action to take when a packet matches the filter.
/// * `valid_fields` - Specifies which of the fields below contain valid values and should be matched against the packet.
/// * `data_link_filter` - Filter criteria for the data link layer (e.g., Ethernet).
/// * `network_filter` - Filter criteria for the network layer (e.g., IPv4, IPv6).
/// * `transport_filter` - Filter criteria for the transport layer (e.g., TCP, UDP, ICMP).
///
/// # Returns
///
/// * A new `StaticFilter` instance.
impl StaticFilter {
    pub fn new(
        adapter_handle: u64,
        direction_flags: DirectionFlags,
        filter_action: u32,
        valid_fields: FilterLayerFlags,
        data_link_filter: DataLinkLayerFilter,
        network_filter: NetworkLayerFilter,
        transport_filter: TransportLayerFilter,
    ) -> Self {
        Self {
            adapter_handle,
            direction_flags,
            filter_action,
            valid_fields,
            last_reset: 0,  // last_reset is usually set to 0
            packets_in: 0,  // packets_in is usually set to 0
            bytes_in: 0,    // bytes_in is usually set to 0
            packets_out: 0, // packets_out is usually set to 0
            bytes_out: 0,   // bytes_out is usually set to 0
            data_link_filter,
            network_filter,
            transport_filter,
        }
    }
}

/// This structure represents an array of static filter rules, each of which is defined by a `StaticFilter` structure.
/// It is used to manage multiple filter rules for packet filtering in a table format.
///
/// * Rust equivalent to the [_STATIC_FILTER_TABLE](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_static_filter_table/)
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct StaticFilterTable<const N: usize> {
    /// The number of elements in the static_filters array
    pub table_size: u32,
    /// Padding to ensure correct memory alignment
    pub padding: u32,
    /// Array of static filter rules
    pub static_filters: [StaticFilter; N],
}

impl<const N: usize> StaticFilterTable<N> {
    /// Creates a new `StaticFilterTable` with the specified number of elements.
    pub fn new() -> Self {
        Self {
            table_size: N as u32,
            padding: 0u32,
            static_filters: [StaticFilter::default(); N],
        }
    }

    /// Creates a new `StaticFilterTable` with the specified static filters.
    pub fn from_filters(static_filters: [StaticFilter; N]) -> Self {
        Self {
            table_size: N as u32,
            padding: 0u32,
            static_filters,
        }
    }
}

impl<const N: usize> Default for StaticFilterTable<N> {
    /// Initializes a new `StaticFilterTable` with the specified number of elements and default values for each element.
    fn default() -> Self {
        Self::new()
    }
}
