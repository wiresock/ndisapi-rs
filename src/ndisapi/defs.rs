use std::fmt::{Display, Formatter, Result};
use windows::Win32::Foundation::HANDLE;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub revision: u32,
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.revision)
    }
}

pub struct NetworkAdapterInfo {
    name: String,
    handle: HANDLE,
    medium: u32,
    hw_address: [u8; 6],
    mtu: u16,
}

impl NetworkAdapterInfo {
    pub fn new(name: String, handle: HANDLE, medium: u32, hw_address: [u8; 6], mtu: u16) -> Self {
        Self {
            name,
            handle,
            medium,
            hw_address,
            mtu,
        }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_handle(&self) -> HANDLE {
        self.handle
    }

    pub fn get_medium(&self) -> u32 {
        self.medium
    }

    pub fn get_hw_address(&self) -> &[u8; 6] {
        &self.hw_address
    }

    pub fn get_mtu(&self) -> u16 {
        self.mtu
    }
}
