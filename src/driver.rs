//! # Module: DRIVER
//!
//! This module provides a low-level interface used by NDISAPI module for communicating
//! with the Windows Packet Filter driver.
//!
//! The submodules in this module contain various structures, functions, and constants
//! required to communicate with the driver and perform operations such as setting packet filters,
//! reading packets, and sending packets to the adapter or MSTCP stack.
//!
//! # Submodules
//!
//! * [`constants`] - Provides various constants and bitflag structures used to configure the
//! packet filtering mechanism, specify filtering options for different protocols, and define
//! the conditions for filtering at specific layers.
//!
//! * [`base`] - Provides Rust equivalents of several structures used in the NDISAPI Rust library
//! for communicating with the Windows Packet Filter driver. he structures in this submodule are related
//! to network adapters, Ethernet packets, adapter events, and Remote Access Service (RAS) links.
//!
//! * [`ioctl`] - Provides a collection of constants for IOCTL (Input/Output Control) codes and
//! the `ctl_code` function used to generate these codes. IOCTL codes are used to communicate
//! with the Windows Packet Filter driver to perform various operations.
//!
//! * [`filters`] - Provides structures for specifying filter conditions and actions for various protocols,
//! including Ethernet 802.3, IPv4, IPv6, TCP, UDP, and ICMP. These structures allow users to define complex
//! filtering rules based on multiple packet fields and layers.
//!
//! * [`fastio`] - Provides Rust equivalents of several structures related to Fast I/O operations
//! for the NDISAPI Rust library used in communicating with the Windows Packet Filter driver.
//! The structures in this submodule are related to Fast I/O sections, which include headers and packet data,
//! and are involved in read and write operations.
//!

// Submodules
pub mod base;
pub mod constants;
pub mod fastio;
pub mod filters;
pub mod ioctl;

pub use self::base::*;
pub use self::constants::*;
pub use self::fastio::*;
pub use self::filters::*;
pub use self::ioctl::*;
