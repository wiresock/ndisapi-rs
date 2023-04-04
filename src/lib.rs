//! The NDISAPI crate is a Rust library that provides functionality for capturing and filtering network packets
//! on Windows operating systems. The crate contains three main modules: driver, ndisapi, and net.
//!
//! The driver module provides low-level functionality for interacting with Windows device drivers, and is used
//! by the ndisapi module to capture and filter network packets.
//!
//! The ndisapi module contains the main functionality for capturing and filtering network packets.
//! This includes various structs and enums for representing packet data and filter settings, as well as a Ndisapi
//! struct for interacting with the driver and performing packet capture and filtering operations.
//!
//! The net module contains a MacAddress struct for representing and manipulating MAC addresses.

mod driver;
mod ndisapi;
mod net;

pub use crate::ndisapi::{
    DirectionFlags, Eth802_3FilterFlags, EthMRequest, EthPacket, EthRequest, FastIoSection,
    FastIoSectionHeader, FilterFlags, FilterLayerFlags, IcmpFilterFlags, IntermediateBuffer,
    IpV4FilterFlags, IpV6FilterFlags, Ndisapi, PacketOidData, RasLinks, StaticFilterTable,
    TcpUdpFilterFlags, UnsortedReadSendRequest, ETHER_ADDR_LENGTH, ETH_802_3, FILTER_PACKET_DROP,
    FILTER_PACKET_DROP_RDR, FILTER_PACKET_PASS, FILTER_PACKET_PASS_RDR, FILTER_PACKET_REDIRECT,
    ICMP, IPV4, IPV6, IP_RANGE_V4_TYPE, IP_RANGE_V6_TYPE, IP_SUBNET_V4_TYPE, IP_SUBNET_V6_TYPE,
    TCPUDP,
};

pub use net::MacAddress;
