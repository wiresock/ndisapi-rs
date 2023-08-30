use crate::IphlpNetworkAdapterInfo;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows::Win32::NetworkManagement::IpHelper::{CreateIpNetEntry2, DeleteIpNetEntry2};
use windows::Win32::Networking::WinSock::NlnsPermanent;
use windows::Win32::{
    Foundation::ERROR_OBJECT_ALREADY_EXISTS,
    NetworkManagement::IpHelper::MIB_IPNET_ROW2,
    Networking::WinSock::{AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0},
};

use super::util::{set_is_router, set_is_unreachable};

impl IphlpNetworkAdapterInfo {
    /// Adds an IPv4 NDP entry for the network interface.
    ///
    /// # Arguments
    ///
    /// * `address`: Ipv4Addr
    /// * `hw_address`: [u8; 6] hardware address
    ///
    /// # Returns
    ///
    /// * `Option<MIB_IPNET_ROW2>`: Some with a MIB_IPNET_ROW2 if successful, None otherwise.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to create an IP Net entry.
    /// The caller should ensure that the provided IPv4 address and hardware address are valid and
    /// that the network interface is properly configured before calling this function.
    pub fn add_ndp_entry_ipv4(
        &self,
        address: Ipv4Addr,
        hw_address: [u8; 6],
    ) -> Option<MIB_IPNET_ROW2> {
        let mut net_row = unsafe { std::mem::zeroed::<MIB_IPNET_ROW2>() };

        net_row.Address.si_family = AF_INET;
        net_row.Address.Ipv4.sin_family = AF_INET;
        net_row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from(address);
        net_row.InterfaceIndex = self.if_index;
        net_row.InterfaceLuid = self.luid.into();
        net_row.PhysicalAddress.copy_from_slice(&hw_address);
        net_row.PhysicalAddressLength = 6;
        net_row.State = NlnsPermanent;
        unsafe {
            set_is_router(&mut net_row, true);
            set_is_unreachable(&mut net_row, true);
        }

        match unsafe { CreateIpNetEntry2(&net_row) } {
            Ok(_) => Some(net_row),
            Err(err) => {
                if err == ERROR_OBJECT_ALREADY_EXISTS.into() {
                    Some(net_row)
                } else {
                    None
                }
            }
        }
    }

    /// Adds an IPv6 NDP entry for the network interface.
    ///
    /// # Arguments
    ///
    /// * `address`: Ipv6Addr
    /// * `hw_address`: [u8; 6] hardware address
    ///
    /// # Returns
    ///
    /// * `Option<MIB_IPNET_ROW2>`: Some with a MIB_IPNET_ROW2 if successful, None otherwise.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to create an IP Net entry.
    /// The caller should ensure that the provided IPv6 address and hardware address are valid and
    /// that the network interface is properly configured before calling this function.
    pub fn add_ndp_entry_ipv6(
        &self,
        address: Ipv6Addr,
        hw_address: [u8; 6],
    ) -> Option<MIB_IPNET_ROW2> {
        let mut net_row = unsafe { std::mem::zeroed::<MIB_IPNET_ROW2>() };

        net_row.Address.si_family = AF_INET6;
        net_row.Address.Ipv6.sin6_family = AF_INET6;
        net_row.Address.Ipv6.sin6_addr = IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: address.octets(),
            },
        };
        net_row.InterfaceIndex = self.ipv6_if_index;
        net_row.InterfaceLuid = self.luid.into();
        net_row.PhysicalAddress.copy_from_slice(&hw_address);
        net_row.PhysicalAddressLength = 6;
        net_row.State = NlnsPermanent;
        unsafe {
            set_is_router(&mut net_row, true);
            set_is_unreachable(&mut net_row, true);
        }

        match unsafe { CreateIpNetEntry2(&net_row) } {
            Ok(_) => Some(net_row),
            Err(err) => {
                if err == ERROR_OBJECT_ALREADY_EXISTS.into() {
                    Some(net_row)
                } else {
                    None
                }
            }
        }
    }

    /// Removes an NDP entry by a MIB_IPNET_ROW2 reference.
    ///
    /// # Arguments
    ///
    /// * `address`: A reference to MIB_IPNET_ROW2
    ///
    /// # Returns
    ///
    /// * `bool`: `true` if successful, `false` otherwise.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to delete an IP Net entry.
    /// The caller should ensure that the provided MIB_IPNET_ROW2 reference is valid
    /// and points to an existing NDP entry before calling this function.
    pub fn delete_ndp_entry(address: &MIB_IPNET_ROW2) -> bool {
        unsafe { DeleteIpNetEntry2(address) }.is_ok()
    }
}
