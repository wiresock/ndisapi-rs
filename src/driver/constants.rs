//! # Submodule: Basic NDISAPI Constants and flags
//!
//! This submodule contains various constants and bitflag structures for the NDISAPI Rust library.
//!
//! The NDISAPI library provides a Rust interface for interacting with the Windows Packet Filter
//! driver. This module contains various constants and bitflag structures used to configure the
//! packet filtering mechanism, specify filtering options for different protocols, and define
//! the conditions for filtering at specific layers.

// Import required external crates and types
use bitflags::bitflags;

/// ADAPTER_NAME_SIZE is the maximum length for the adapter name.
pub const ADAPTER_NAME_SIZE: usize = 256;

/// ADAPTER_LIST_SIZE is the maximum number of adapters in the adapter list.
pub const ADAPTER_LIST_SIZE: usize = 32;

/// ETHER_ADDR_LENGTH is the length of an Ethernet address in bytes.
pub const ETHER_ADDR_LENGTH: usize = 6;

/// MAX_ETHER_FRAME is the maximum size of an Ethernet frame in bytes. If the driver was built with
/// the JUMBO_FRAME_SUPPORTED option, this value would be 9014 bytes instead.
pub const MAX_ETHER_FRAME: usize = 1514;

/// RAS_LINK_BUFFER_LENGTH is the length of the RAS link buffer in bytes.
pub const RAS_LINK_BUFFER_LENGTH: usize = 2048;

/// RAS_LINKS_MAX is the maximum number of RAS links.
pub const RAS_LINKS_MAX: usize = 256;

/// Constant representing the IPv4 subnet type.
pub const IP_SUBNET_V4_TYPE: u32 = 1;
/// Constant representing the IPv4 address range type.
pub const IP_RANGE_V4_TYPE: u32 = 2;

/// Constant representing the IPv6 subnet type.
pub const IP_SUBNET_V6_TYPE: u32 = 1;
/// Constant representing the IPv6 address range type.
pub const IP_RANGE_V6_TYPE: u32 = 2;

/// ETH_802_3 is a constant representing the 802.3 Ethernet standard.
pub const ETH_802_3: u32 = 1;

/// Constant representing the IPv4 network protocols.
pub const IPV4: u32 = 1;
/// Constant representing the IPv6 network protocols.
pub const IPV6: u32 = 2;

/// Constant representing the TCP or UDP protocols.
pub const TCPUDP: u32 = 1;
/// Constant representing the ICMP protocol.
pub const ICMP: u32 = 2;

/// Allows a packet to pass through the filter without any modification.
pub const FILTER_PACKET_PASS: u32 = 1;
/// Drops the packet and prevents it from reaching the destination.
pub const FILTER_PACKET_DROP: u32 = 2;
/// Redirects the packet for processing in user-mode.
pub const FILTER_PACKET_REDIRECT: u32 = 3;
/// Allows the packet to pass through the filter and redirects a copy of it for processing by user-mode application.
pub const FILTER_PACKET_PASS_RDR: u32 = 4;
/// Drops the packet and and redirects a copy of it for processing by user-mode application.
pub const FILTER_PACKET_DROP_RDR: u32 = 5;

// Define bitflag structures for filter flags, direction flags, and various protocol-specific filter flags
bitflags! {
    /// FilterFlags represent various flags used for packet filtering.
    ///
    /// These flags are used to configure the behavior of the packet filtering mechanism in different scenarios.
    #[derive(Default, Clone, Copy, Debug, PartialEq)]
    pub struct FilterFlags: u32 {
        /// MSTCP_FLAG_SENT_TUNNEL: Queue all packets sent from TCP/IP to network interface. Original packet is dropped.
        const MSTCP_FLAG_SENT_TUNNEL = 1;

        /// MSTCP_FLAG_RECV_TUNNEL: Queue all packets indicated by network interface to TCP/IP. Original packet is dropped.
        const MSTCP_FLAG_RECV_TUNNEL = 2;

        /// MSTCP_FLAG_SENT_LISTEN: Queue all packets sent from TCP/IP to network interface. Original packet goes ahead.
        const MSTCP_FLAG_SENT_LISTEN = 4;

        /// MSTCP_FLAG_RECV_LISTEN: Queue all packets indicated by network interface to TCP/IP. Original packet goes ahead.
        const MSTCP_FLAG_RECV_LISTEN = 8;

        /// MSTCP_FLAG_FILTER_DIRECT: In promiscuous mode, the TCP/IP stack receives all packets in the Ethernet segment
        /// and replies with various ICMP packets. To prevent this, set this flag. All packets with destination MAC different
        /// from FF-FF-FF-FF-FF-FF and network interface current MAC will never reach TCP/IP.
        const MSTCP_FLAG_FILTER_DIRECT = 16;

        /// MSTCP_FLAG_LOOPBACK_FILTER: If not set, loopback packets are silently passed over. Otherwise, these packets are
        /// passed for further processing (queued for redirecting to the application if not dropped by the MSTCP_FLAG_LOOPBACK_BLOCK below).
        const MSTCP_FLAG_LOOPBACK_FILTER = 32;

        /// MSTCP_FLAG_LOOPBACK_BLOCK: If set, loopback packets (with exception to broadcast/multicast) are silently dropped.
        const MSTCP_FLAG_LOOPBACK_BLOCK = 64;

        /// MSTCP_FLAG_SENT_RECEIVE_TUNNEL: Combination of MSTCP_FLAG_SENT_TUNNEL and MSTCP_FLAG_RECV_TUNNEL.
        const MSTCP_FLAG_SENT_RECEIVE_TUNNEL = Self::MSTCP_FLAG_SENT_TUNNEL.bits() | Self::MSTCP_FLAG_RECV_TUNNEL.bits();

        /// MSTCP_FLAG_SENT_RECEIVE_LISTEN: Combination of MSTCP_FLAG_SENT_LISTEN and MSTCP_FLAG_RECV_LISTEN.
        const MSTCP_FLAG_SENT_RECEIVE_LISTEN = Self::MSTCP_FLAG_SENT_LISTEN.bits() | Self::MSTCP_FLAG_RECV_LISTEN.bits();
    }
}

bitflags! {
    /// DirectionFlags represent various direction flags for packet processing.
    ///
    /// These flags are used to specify the direction of packets that the filter should act upon and
    /// to specify the packet direction in IntermediateBuffer.
    #[derive(Default, Clone, Copy, Debug, PartialEq)]
    pub struct DirectionFlags: u32 {
        /// PACKET_FLAG_ON_SEND: Indicates an outgoing packet. In the context of filters, the filter should act on packets being sent from the system.
        const PACKET_FLAG_ON_SEND = 1;

        /// PACKET_FLAG_ON_RECEIVE: Indicates an incoming packet. In the context of filters, the filter should act on packets being received by the system.
        const PACKET_FLAG_ON_RECEIVE = 2;

        /// PACKET_FLAG_ON_SEND_RECEIVE: Filter should act on both sent and received packets.
        const PACKET_FLAG_ON_SEND_RECEIVE = Self::PACKET_FLAG_ON_SEND.bits() | Self::PACKET_FLAG_ON_RECEIVE.bits();
    }
}

bitflags! {
    /// Eth802_3FilterFlags represent various filtering options for Ethernet 802.3 frames.
    ///
    /// These flags are used to specify which fields of an Ethernet 802.3 frame the filter should
    /// consider when determining whether to process the packet.
    #[derive(Default, Clone, Copy, Debug, PartialEq)]
    pub struct Eth802_3FilterFlags: u32 {
        /// ETH_802_3_SRC_ADDRESS: Filter based on the source MAC address of the Ethernet 802.3 frame.
        const ETH_802_3_SRC_ADDRESS = 1;

        /// ETH_802_3_DEST_ADDRESS: Filter based on the destination MAC address of the Ethernet 802.3 frame.
        const ETH_802_3_DEST_ADDRESS = 2;

        /// ETH_802_3_PROTOCOL: Filter based on the protocol field (EtherType) of the Ethernet 802.3 frame.
        const ETH_802_3_PROTOCOL = 4;
    }
}

bitflags! {
    /// IpV4FilterFlags represent various filtering options for IPv4 packets.
    ///
    /// These flags are used to specify which fields of an IPv4 packet the filter should
    /// consider when determining whether to process the packet.
    #[derive(Default, Clone, Copy, Debug, PartialEq)]
    pub struct IpV4FilterFlags: u32 {
        /// IP_V4_FILTER_SRC_ADDRESS: Filter based on the source IP address of the IPv4 packet.
        const IP_V4_FILTER_SRC_ADDRESS = 1;

        /// IP_V4_FILTER_DEST_ADDRESS: Filter based on the destination IP address of the IPv4 packet.
        const IP_V4_FILTER_DEST_ADDRESS = 2;

        /// IP_V4_FILTER_PROTOCOL: Filter based on the protocol field of the IPv4 packet (e.g., TCP, UDP, ICMP).
        const IP_V4_FILTER_PROTOCOL = 4;
    }
}

bitflags! {
    /// IpV6FilterFlags represent various filtering options for IPv6 packets.
    ///
    /// These flags are used to specify which fields of an IPv6 packet the filter should
    /// consider when determining whether to process the packet.
    #[derive(Default, Clone, Copy, Debug, PartialEq)]
    pub struct IpV6FilterFlags: u32 {
        /// IP_V6_FILTER_SRC_ADDRESS: Filter based on the source IP address of the IPv6 packet.
        const IP_V6_FILTER_SRC_ADDRESS = 1;

        /// IP_V6_FILTER_DEST_ADDRESS: Filter based on the destination IP address of the IPv6 packet.
        const IP_V6_FILTER_DEST_ADDRESS = 2;

        /// IP_V6_FILTER_PROTOCOL: Filter based on the protocol field of the IPv6 packet (e.g., TCP, UDP, ICMPv6).
        const IP_V6_FILTER_PROTOCOL = 4;
    }
}

bitflags! {
    /// TcpUdpFilterFlags represent various filtering options for TCP and UDP packets.
    ///
    /// These flags are used to specify which fields of a TCP or UDP packet the filter should
    /// consider when determining whether to process the packet.
    #[derive(Default, Clone, Copy, Debug, PartialEq)]
    pub struct TcpUdpFilterFlags: u32 {
        /// TCPUDP_SRC_PORT: Filter based on the source port of the TCP or UDP packet.
        const TCPUDP_SRC_PORT = 1;

        /// TCPUDP_DEST_PORT: Filter based on the destination port of the TCP or UDP packet.
        const TCPUDP_DEST_PORT = 2;

        /// TCPUDP_TCP_FLAGS: Filter based on the TCP flags of a TCP packet. This flag is ignored for UDP packets.
        const TCPUDP_TCP_FLAGS = 4;
    }
}

bitflags! {
    /// IcmpFilterFlags represent various filtering options for ICMP packets.
    ///
    /// These flags are used to specify which fields of an ICMP packet the filter should
    /// consider when determining whether to process the packet.
    #[derive(Default, Clone, Copy, Debug, PartialEq)]
    pub struct IcmpFilterFlags: u32 {
        /// ICMP_TYPE: Filter based on the ICMP type of the ICMP packet.
        const ICMP_TYPE = 1;

        /// ICMP_CODE: Filter based on the ICMP code of the ICMP packet.
        const ICMP_CODE = 2;
    }
}

bitflags! {
    /// FilterLayerFlags represent the validation flags for various filter layers.
    ///
    /// These flags are used to specify which layers of a packet the filter should consider
    /// when determining whether to process the packet. They are typically used in conjunction
    /// with other filter flags to define the conditions for filtering at specific layers.
    #[derive(Default, Clone, Copy, Debug, PartialEq)]
    pub struct FilterLayerFlags: u32 {
        /// DATA_LINK_LAYER_VALID: Indicates that the Data Link Layer filter fields are valid and should be considered in the filtering process.
        const DATA_LINK_LAYER_VALID = 1;

        /// NETWORK_LAYER_VALID: Indicates that the Network Layer filter fields are valid and should be considered in the filtering process.
        const NETWORK_LAYER_VALID = 2;

        /// TRANSPORT_LAYER_VALID: Indicates that the Transport Layer filter fields are valid and should be considered in the filtering process.
        const TRANSPORT_LAYER_VALID = 4;
    }
}
