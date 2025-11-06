use crate::IfLuid;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_TABLE,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;
use windows::Win32::{
    Foundation::ERROR_OBJECT_ALREADY_EXISTS,
    NetworkManagement::IpHelper::{
        CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, InitializeUnicastIpAddressEntry,
        MIB_UNICASTIPADDRESS_ROW,
    },
    Networking::WinSock::{
        IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual, AF_INET, AF_INET6,
        IN6_ADDR, IN6_ADDR_0,
    },
};

use crate::IphlpNetworkAdapterInfo;

impl IphlpNetworkAdapterInfo {
    /// Adds an IPv4 unicast address to the network interface.
    ///
    /// This function creates a new `MIB_UNICASTIPADDRESS_ROW` with the provided IPv4 address
    /// and prefix length, and then calls the `CreateUnicastIpAddressEntry` Windows API function
    /// to add the unicast address to the network interface. On success, it returns
    /// `Some(MIB_UNICASTIPADDRESS_ROW)`; otherwise, it sets the last error and returns `None`.
    ///
    /// # Arguments
    ///
    /// * `address` - The IPv4 address to assign to the network interface.
    /// * `prefix_length` - The subnet prefix length for the IPv4 address.
    ///
    /// # Returns
    ///
    /// * `Option<MIB_UNICASTIPADDRESS_ROW>` - Returns `Some(MIB_UNICASTIPADDRESS_ROW)` if the
    ///   unicast address is successfully added to the network interface, or `None` if the
    ///   operation fails.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls (`InitializeUnicastIpAddressEntry` and
    /// `CreateUnicastIpAddressEntry`). The function takes care of initializing the
    /// `MIB_UNICASTIPADDRESS_ROW` struct and ensuring that the arguments and struct fields
    /// are properly set before making the API calls. However, any changes to this function or
    /// the underlying Windows APIs could introduce potential safety issues. Ensure that you
    /// understand the risks and consequences of using unsafe code before modifying this
    /// function or its dependencies.
    pub fn add_unicast_address_ipv4(
        &self,
        address: std::net::Ipv4Addr,
        prefix_length: u8,
    ) -> Option<MIB_UNICASTIPADDRESS_ROW> {
        let mut address_row = MIB_UNICASTIPADDRESS_ROW::default(); // Create a new MIB_UNICASTIPADDRESS_ROW
        unsafe { InitializeUnicastIpAddressEntry(&mut address_row) };

        address_row.Address.Ipv4.sin_family = AF_INET;
        address_row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.octets());
        address_row.Address.si_family = AF_INET;

        address_row.InterfaceIndex = self.if_index;
        address_row.InterfaceLuid = self.luid.into();

        address_row.PrefixOrigin = IpPrefixOriginManual;
        address_row.SuffixOrigin = IpSuffixOriginManual;
        address_row.OnLinkPrefixLength = prefix_length;
        address_row.DadState = IpDadStatePreferred;

        // Call the CreateUnicastIpAddressEntry function (you need to implement this function)
        match unsafe { CreateUnicastIpAddressEntry(&address_row).ok() } {
            Ok(_) => Some(address_row),
            Err(err) => {
                if err == ERROR_OBJECT_ALREADY_EXISTS.into() {
                    Some(address_row)
                } else {
                    None
                }
            }
        }
    }

    /// Adds an IPv6 unicast address to the network interface.
    ///
    /// This function creates a new `MIB_UNICASTIPADDRESS_ROW` with the provided IPv6 address
    /// and prefix length, and then calls the `CreateUnicastIpAddressEntry` Windows API function
    /// to add the unicast address to the network interface. On success, it returns
    /// `Some(MIB_UNICASTIPADDRESS_ROW)`; otherwise, it sets the last error and returns `None`.
    ///
    /// # Arguments
    ///
    /// * `address` - The IPv6 address to assign to the network interface.
    /// * `prefix_length` - The subnet prefix length for the IPv6 address.
    ///
    /// # Returns
    ///
    /// * `Option<MIB_UNICASTIPADDRESS_ROW>` - Returns `Some(MIB_UNICASTIPADDRESS_ROW)` if the
    ///   unicast address is successfully added to the network interface, or `None` if the
    ///   operation fails.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls (`InitializeUnicastIpAddressEntry` and
    /// `CreateUnicastIpAddressEntry`). The function takes care of initializing the
    /// `MIB_UNICASTIPADDRESS_ROW` struct and ensuring that the arguments and struct fields
    /// are properly set before making the API calls. However, any changes to this function or
    /// the underlying Windows APIs could introduce potential safety issues. Ensure that you
    /// understand the risks and consequences of using unsafe code before modifying this
    /// function or its dependencies.
    pub fn add_unicast_address_ipv6(
        &self,
        address: std::net::Ipv6Addr,
        prefix_length: u8,
    ) -> Option<MIB_UNICASTIPADDRESS_ROW> {
        let mut address_row = MIB_UNICASTIPADDRESS_ROW::default(); // Create a new MIB_UNICASTIPADDRESS_ROW
        unsafe { InitializeUnicastIpAddressEntry(&mut address_row) };

        address_row.Address.Ipv6.sin6_family = AF_INET6;
        address_row.Address.Ipv6.sin6_addr = IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: address.octets(),
            },
        };
        address_row.Address.si_family = AF_INET6;

        address_row.InterfaceIndex = self.ipv6_if_index;
        address_row.InterfaceLuid = self.luid.into();

        address_row.PrefixOrigin = IpPrefixOriginManual;
        address_row.SuffixOrigin = IpSuffixOriginManual;
        address_row.OnLinkPrefixLength = prefix_length;
        address_row.DadState = IpDadStatePreferred;

        match unsafe { CreateUnicastIpAddressEntry(&address_row) }.ok() {
            Ok(_) => Some(address_row),
            Err(err) => {
                if err == ERROR_OBJECT_ALREADY_EXISTS.into() {
                    Some(address_row)
                } else {
                    None
                }
            }
        }
    }

    /// Removes a unicast IP address from the network adapter using a reference to a `MIB_UNICASTIPADDRESS_ROW`.
    ///
    /// This function calls the `DeleteUnicastIpAddressEntry` Windows API function to remove the
    /// unicast IP address from the network adapter. On success, it returns `true`; otherwise,
    /// it sets the last error and returns `false`.
    ///
    /// # Arguments
    ///
    /// * `address` - A reference to a `MIB_UNICASTIPADDRESS_ROW`.
    ///
    /// # Returns
    ///
    /// * `bool` - Returns `true` if the unicast IP address is successfully removed from the
    ///   network adapter, or `false` if the operation fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls the `DeleteUnicastIpAddressEntry`
    /// Windows API function, which is an unsafe operation due to the use of raw pointers.
    /// The caller must ensure that the provided `address` reference is valid and correctly
    /// initialized to avoid any undefined behavior.
    pub fn delete_unicast_address(address: &MIB_UNICASTIPADDRESS_ROW) -> bool {
        unsafe { DeleteUnicastIpAddressEntry(address) }.is_ok()
    }

    /// Removes all unicast addresses associated with the network interface.
    ///
    /// # Returns
    ///
    /// * `bool`: true if successful, false otherwise.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to get and delete unicast IP addresses.
    /// The caller should ensure that the network interface is properly configured before calling this function.
    pub fn reset_unicast_addresses(&self) -> bool {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();

        match unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) }.ok() {
            Ok(_) => {
                for i in 0..unsafe { (*table).NumEntries } {
                    let entry = unsafe { &mut (*table).Table[i as usize] };
                    if IfLuid::from(entry.InterfaceLuid) == self.luid {
                        let _ = unsafe { DeleteUnicastIpAddressEntry(entry) };
                    }
                }
                unsafe { FreeMibTable(table as *mut _) };
                true
            }
            Err(_) => false,
        }
    }

    /// Removes the specified IPv4 address from the network interface.
    ///
    /// # Arguments
    ///
    /// * `address`: Ipv4Addr to remove
    ///
    /// # Returns
    ///
    /// * `bool`: true if successful, false otherwise.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to get and delete unicast IP address entries.
    /// The caller should ensure that the provided IPv4 address is valid and
    /// that the network interface is properly configured before calling this function.
    pub fn delete_unicast_address_ipv4(&self, address: Ipv4Addr) -> bool {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();

        match unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) }.ok() {
            Ok(_) => {
                for i in 0..unsafe { (*table).NumEntries } {
                    let entry = unsafe { &(*table).Table[i as usize] };

                    if IfLuid::from(entry.InterfaceLuid) == self.luid
                        && Ipv4Addr::from(
                            unsafe { entry.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
                        ) == address
                    {
                        let _ = unsafe { DeleteUnicastIpAddressEntry(entry) };
                    }
                }

                unsafe { FreeMibTable(table as *mut _) };
                true
            }
            Err(_) => false,
        }
    }

    /// Removes the specified IPv6 address from the network interface.
    ///
    /// # Arguments
    ///
    /// * `address`: Ipv6Addr to remove
    ///
    /// # Returns
    ///
    /// * `bool`: true if successful, false otherwise.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to get and delete unicast IP address entries.
    /// The caller should ensure that the provided IPv6 address is valid and
    /// that the network interface is properly configured before calling this function.
    pub fn delete_unicast_address_ipv6(&self, address: Ipv6Addr) -> bool {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();

        match unsafe { GetUnicastIpAddressTable(AF_INET6, &mut table) }.ok() {
            Ok(_) => {
                for i in 0..unsafe { (*table).NumEntries } {
                    let entry = unsafe { &(*table).Table[i as usize] };

                    if IfLuid::from(entry.InterfaceLuid) == self.luid
                        && Ipv6Addr::from(unsafe { entry.Address.Ipv6.sin6_addr.u.Byte }) == address
                    {
                        let _ = unsafe { DeleteUnicastIpAddressEntry(entry) };
                    }
                }

                unsafe { FreeMibTable(table as *mut _) };
                true
            }
            Err(_) => false,
        }
    }

    /// Gets unicast addresses with their prefix lengths from the Windows IP Helper API.
    pub(crate) fn get_unicast_addresses_with_prefix(&self) -> Vec<(std::net::IpAddr, u8)> {
        use std::net::IpAddr;
        let mut addresses_with_prefix = Vec::new();

        // Get the unicast IP address table from Windows
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();

        match unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) }.ok() {
            Ok(_) => {
                let num_entries = unsafe { (*table).NumEntries };

                // Iterate through all entries in the table
                for i in 0..num_entries {
                    let entry_ptr = unsafe { (*table).Table.as_ptr().add(i as usize) };
                    let entry = unsafe { &*entry_ptr };

                    // Check if this entry belongs to our adapter
                    if IfLuid::from(entry.InterfaceLuid) == self.luid {
                        let prefix_length = entry.OnLinkPrefixLength;

                        // Convert the address based on address family
                        match unsafe { entry.Address.si_family } {
                            AF_INET => {
                                // IPv4 address
                                let ipv4_bytes = unsafe { entry.Address.Ipv4.sin_addr.S_un.S_addr }
                                    .to_ne_bytes();
                                let ipv4_addr = std::net::Ipv4Addr::from(ipv4_bytes);
                                addresses_with_prefix.push((IpAddr::V4(ipv4_addr), prefix_length));
                            }
                            AF_INET6 => {
                                // IPv6 address
                                let ipv6_bytes = unsafe { entry.Address.Ipv6.sin6_addr.u.Byte };
                                let ipv6_addr = std::net::Ipv6Addr::from(ipv6_bytes);
                                addresses_with_prefix.push((IpAddr::V6(ipv6_addr), prefix_length));
                            }
                            _ => {
                                // Unknown address family, skip
                                continue;
                            }
                        }
                    }
                }

                // Free the table memory
                unsafe { FreeMibTable(table as *mut _) };
            }
            Err(_) => {
                // Failed to get unicast address table, return empty vector
            }
        }

        addresses_with_prefix
    }
}
