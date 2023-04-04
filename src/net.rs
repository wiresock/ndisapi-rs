/// This module provides a type for a MAC address, represented as a 6-byte array of unsigned
/// integers. It implements `Display` and `Debug` traits for displaying a MAC address in the
/// standard colon-separated format.
///
/// # Example
///
/// ```
/// use ndisapi::MacAddress;
///
/// let mac = MacAddress::from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]).unwrap();
/// assert_eq!(format!("{}", mac), "12:34:56:78:9A:BC");
/// assert_eq!(format!("{:?}", mac), "12:34:56:78:9A:BC");
/// ```
use crate::driver::ETHER_ADDR_LENGTH;
use std::fmt::{Debug, Display, Formatter, Result};

/// A MAC address represented as a 6-byte array of unsigned integers.
#[derive(Default)]
pub struct MacAddress([u8; ETHER_ADDR_LENGTH]);

impl Display for MacAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl Debug for MacAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl MacAddress {
    /// Creates a new `MacAddress` instance from a slice of bytes.
    ///
    /// # Arguments
    ///
    /// * `slice` - A slice of bytes representing a MAC address.
    ///
    /// # Returns
    ///
    /// An `Option` containing a `MacAddress` instance if the slice has a length of `ETHER_ADDR_LENGTH`
    /// bytes, `None` otherwise.
    pub fn from_slice(slice: &[u8]) -> Option<MacAddress> {
        let mut mac_address = MacAddress::default();
        if slice.len() < ETHER_ADDR_LENGTH {
            None
        } else {
            mac_address.0.copy_from_slice(slice);
            Some(mac_address)
        }
    }

    /// Returns a reference to the internal byte array of the `MacAddress` instance.
    pub fn get(&self) -> &[u8; 6] {
        &self.0
    }

    /// Returns a mutable reference to the internal byte array of the `MacAddress` instance.
    pub fn get_mut(&mut self) -> &mut [u8; 6] {
        &mut self.0
    }
}
