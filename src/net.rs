use crate::driver::ETHER_ADDR_LENGTH;
use std::fmt::{Debug, Display, Formatter, Result};

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
    pub fn from_slice(slice: &[u8]) -> Option<MacAddress> {
        let mut mac_address = MacAddress::default();
        if slice.len() < ETHER_ADDR_LENGTH {
            None
        } else {
            mac_address.0.copy_from_slice(slice);
            Some(mac_address)
        }
    }

    pub fn get(&self) -> &[u8; 6] {
        &self.0
    }

    pub fn get_mut(&mut self) -> &mut [u8; 6] {
        &mut self.0
    }
}
