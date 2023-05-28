//! # Module: NETLIB
//!
//! This module provides a set of networking utilities and helpers for Rust.
//!
//! # Submodules
//!
//! * [`ip_helper`] - Provides a set of helpers for working with the Windows IP Helper API.
//! This includes types for working with network adapter information, IP gateway information, and
//! socket address storage.
//!
//! * [`net`] - Provides a set of networking utilities for Rust. This includes a type for
//! representing MAC addresses.

// Submodules
pub mod ip_helper;
pub mod net;

// Re-exports
pub use crate::netlib::ip_helper::{
    guid_wrapper::GuidWrapper, if_luid::IfLuid, ip_gateway_info::IpGatewayInfo,
    network_adapter_info::IphlpNetworkAdapterInfo, sockaddr_storage::SockAddrStorage,
};
pub use net::MacAddress;
