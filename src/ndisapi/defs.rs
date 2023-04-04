//! # Submodule: High-level NDISAPI Types
//!
//! This submodule provides high-level NDISAPI definitions of constants, structures, and enumerations
//!

// Required imports for the submodule
use std::fmt::{Display, Formatter, Result};
use windows::Win32::Foundation::HANDLE;

/// Represents the version information for the NDIS filter driver.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub revision: u32,
}

impl Display for Version {
    /// Formats the version information for display purposes.
    ///
    /// # Arguments
    ///
    /// * `f`: A mutable reference to a `Formatter` object.
    ///
    /// # Returns
    ///
    /// * `Result` - A formatting Result.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.revision)
    }
}

/// Represents information about a network adapter.
pub struct NetworkAdapterInfo {
    name: String,
    handle: HANDLE,
    medium: u32,
    hw_address: [u8; 6],
    mtu: u16,
}

impl NetworkAdapterInfo {
    /// Creates a new `NetworkAdapterInfo` object with the specified properties.
    ///
    /// # Arguments
    ///
    /// * `name`: A `String` representing the name of the network adapter.
    /// * `handle`: A `HANDLE` to the network adapter.
    /// * `medium`: A `u32` value representing the network adapter medium.
    /// * `hw_address`: A `[u8; 6]` array representing the hardware address of the network adapter.
    /// * `mtu`: A `u16` value representing the maximum transmission unit (MTU) of the network adapter.
    ///
    /// # Returns
    ///
    /// * `NetworkAdapterInfo` - A new instance of `NetworkAdapterInfo`.
    pub fn new(name: String, handle: HANDLE, medium: u32, hw_address: [u8; 6], mtu: u16) -> Self {
        Self {
            name,
            handle,
            medium,
            hw_address,
            mtu,
        }
    }

    /// Returns the name of the network adapter.
    ///
    /// # Returns
    ///
    /// * `&str` - A reference to the name of the network adapter.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the handle of the network adapter.
    ///
    /// # Returns
    ///
    /// * `HANDLE` - The handle of the network adapter.
    pub fn get_handle(&self) -> HANDLE {
        self.handle
    }

    /// Returns the medium of the network adapter.
    ///
    /// # Returns
    ///
    /// * `u32` - The medium of the network adapter.
    pub fn get_medium(&self) -> u32 {
        self.medium
    }

    /// Returns the hardware address of the network adapter.
    ///
    /// # Returns
    ///
    /// * `&[u8; 6]` - A reference to the hardware address of the network adapter.
    pub fn get_hw_address(&self) -> &[u8; 6] {
        &self.hw_address
    }

    /// Returns the maximum transmission unit (MTU) of the network adapter.
    ///
    /// # Returns
    ///
    /// * `u16` - The MTU of the network adapter.
    pub fn get_mtu(&self) -> u16 {
        self.mtu
    }
}
