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

mod async_api;
mod driver;
mod ndisapi;
mod netlib;

pub use crate::ndisapi::{
    DirectionFlags, Eth802_3FilterFlags, EthMRequest, EthPacket, EthRequest, FastIoSection,
    FastIoSectionHeader, FilterFlags, FilterLayerFlags, IcmpFilterFlags, IntermediateBuffer,
    IpV4FilterFlags, IpV6FilterFlags, Ndisapi, NetworkAdapterInfo, PacketOidData, RasLinks,
    StaticFilterTable, TcpUdpFilterFlags, UnsortedReadSendRequest, Version, ETHER_ADDR_LENGTH,
    ETH_802_3, FILTER_PACKET_DROP, FILTER_PACKET_DROP_RDR, FILTER_PACKET_PASS,
    FILTER_PACKET_PASS_RDR, FILTER_PACKET_REDIRECT, ICMP, IPV4, IPV6, IP_RANGE_V4_TYPE,
    IP_RANGE_V6_TYPE, IP_SUBNET_V4_TYPE, IP_SUBNET_V6_TYPE, TCPUDP,
};

pub use crate::async_api::AsyncNdisapiAdapter;

pub use crate::netlib::ip_helper::{
    guid_wrapper::GuidWrapper, if_luid::IfLuid, ip_gateway_info::IpGatewayInfo,
    network_adapter_info::IphlpNetworkAdapterInfo, sockaddr_storage::SockAddrStorage,
};

pub use netlib::net::MacAddress;
