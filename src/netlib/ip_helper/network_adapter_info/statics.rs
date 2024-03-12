use crate::{IfLuid, IphlpNetworkAdapterInfo, MacAddress};
use windows::Win32::Foundation::{SetLastError, ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetIfTable2, GAA_FLAG_INCLUDE_ALL_INTERFACES,
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    IF_TYPE_SOFTWARE_LOOPBACK,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::AF_UNSPEC;
use windows::Win32::{
    Foundation::WIN32_ERROR,
    NetworkManagement::IpHelper::{IP_ADAPTER_ADDRESSES_LH, MIB_IF_TABLE2},
};

impl IphlpNetworkAdapterInfo {
    /// Returns a list of network interfaces which:
    /// 1. Have at least one unicast address assigned
    /// 2. Operational (IfOperStatusUp)
    /// 3. Not software loopback
    ///
    /// # Returns
    ///
    /// * `Vec<IphlpNetworkAdapterInfo>`: A vector of `IphlpNetworkAdapterInfo` objects.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to get the network interface information.
    /// The caller should ensure that the returned `IphlpNetworkAdapterInfo` objects are not used
    /// after the corresponding network interfaces have been removed or disabled.
    pub fn get_external_network_connections() -> Vec<IphlpNetworkAdapterInfo> {
        let mut ret_val = Vec::new();
        let mut dw_size = 0;
        let mut mib_table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();

        // Query detailed information on available network interfaces
        let error_code = unsafe { GetIfTable2(&mut mib_table) };
        if error_code.is_err() {
            return ret_val;
        }

        let error_code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_INCLUDE_GATEWAYS
                    | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                None,
                None,
                &mut dw_size,
            )
        };

        // Get available unicast addresses
        if WIN32_ERROR(error_code) == ERROR_BUFFER_OVERFLOW && dw_size != 0 {
            loop {
                let mut ip_address_info = vec![0u8; dw_size as usize];

                let error_code = unsafe {
                    GetAdaptersAddresses(
                        AF_UNSPEC.0 as u32,
                        GAA_FLAG_SKIP_ANYCAST
                            | GAA_FLAG_SKIP_MULTICAST
                            | GAA_FLAG_INCLUDE_GATEWAYS
                            | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                        None,
                        Some(ip_address_info.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                        &mut dw_size,
                    )
                };

                if WIN32_ERROR(error_code) == NO_ERROR {
                    let mut current_address =
                        ip_address_info.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

                    while !current_address.is_null() {
                        let current = unsafe { &*current_address };

                        if current.FirstUnicastAddress.is_null()
                            || current.OperStatus != IfOperStatusUp
                            || current.IfType == IF_TYPE_SOFTWARE_LOOPBACK
                        {
                            current_address = current.Next;
                            continue;
                        }

                        // Lookup advanced information on the network interface
                        for i in 0..unsafe { (*mib_table).NumEntries } {
                            let table_ptr = unsafe { (*mib_table).Table.as_ptr() };
                            let entry_ptr = unsafe { table_ptr.add(i as usize) };
                            if IfLuid::from(unsafe { (*entry_ptr).InterfaceLuid })
                                == IfLuid::from(current.Luid)
                            {
                                ret_val.push(unsafe {
                                    IphlpNetworkAdapterInfo::new(current, entry_ptr)
                                });
                                break;
                            }
                        }

                        current_address = current.Next;
                    }

                    break;
                }
                // In case of insufficient buffer size we try to recover by reallocating buffer
                if WIN32_ERROR(error_code) != ERROR_BUFFER_OVERFLOW {
                    unsafe { SetLastError(WIN32_ERROR(error_code)) };
                    break;
                }
            }
        } else {
            // GetAdaptersAddresses has failed with status different from ERROR_BUFFER_OVERFLOW when obtaining required buffer size
            if WIN32_ERROR(error_code) != NO_ERROR {
                unsafe { SetLastError(WIN32_ERROR(error_code)) };
            }
        }

        // Free interface table
        unsafe { FreeMibTable(mib_table as *const core::ffi::c_void) };

        ret_val
    }

    /// Finds a network interface by the provided LUID.
    ///
    /// # Arguments
    ///
    /// * `luid` - An `IfLuid` to look up.
    ///
    /// # Returns
    ///
    /// * `Option<IphlpNetworkAdapterInfo>` - An optional `IphlpNetworkAdapterInfo` class instance.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to get the network interface information.
    /// The caller should ensure that the returned `IphlpNetworkAdapterInfo` objects are not used
    /// after the corresponding network interfaces have been removed or disabled.
    pub fn get_connection_by_luid(luid: IfLuid) -> Option<IphlpNetworkAdapterInfo> {
        let mut dw_size = 0;
        let mut mib_table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();

        // Query detailed information on available network interfaces
        if unsafe { GetIfTable2(&mut mib_table) }.is_err() {
            return None;
        }

        // Get available unicast addresses
        let error_code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_INCLUDE_GATEWAYS
                    | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                None,
                None,
                &mut dw_size,
            )
        };

        if WIN32_ERROR(error_code) == ERROR_BUFFER_OVERFLOW && dw_size != 0 {
            loop {
                let mut ip_address_info = vec![0u8; dw_size as usize];

                let error_code = unsafe {
                    GetAdaptersAddresses(
                        AF_UNSPEC.0 as u32,
                        GAA_FLAG_SKIP_ANYCAST
                            | GAA_FLAG_SKIP_MULTICAST
                            | GAA_FLAG_INCLUDE_GATEWAYS
                            | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                        None,
                        Some(ip_address_info.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                        &mut dw_size,
                    )
                };

                if WIN32_ERROR(error_code) == NO_ERROR {
                    let mut current_address =
                        ip_address_info.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

                    while !current_address.is_null() {
                        let current = unsafe { &*current_address };

                        if IfLuid::from(current.Luid) != luid {
                            current_address = current.Next;
                            continue;
                        }

                        // Lookup advanced information on the network interface
                        for i in 0..unsafe { (*mib_table).NumEntries } {
                            let table_ptr = unsafe { (*mib_table).Table.as_ptr() };
                            let entry_ptr = unsafe { table_ptr.add(i as usize) };
                            if IfLuid::from(unsafe { (*entry_ptr).InterfaceLuid }) == luid {
                                let result =
                                    unsafe { IphlpNetworkAdapterInfo::new(current, entry_ptr) };
                                unsafe { FreeMibTable(mib_table as *const core::ffi::c_void) };
                                return Some(result);
                            }
                        }

                        current_address = current.Next;
                    }

                    break;
                }
                // In case of insufficient buffer size, we try to recover by reallocating the buffer
                if WIN32_ERROR(error_code) != ERROR_BUFFER_OVERFLOW {
                    unsafe { SetLastError(WIN32_ERROR(error_code)) };
                    break;
                }
            }
        } else {
            // GetAdaptersAddresses has failed with a status different from ERROR_BUFFER_OVERFLOW when obtaining the required buffer size
            if WIN32_ERROR(error_code) != NO_ERROR {
                unsafe { SetLastError(WIN32_ERROR(error_code)) };
            }
        }

        // Free interface table
        unsafe { FreeMibTable(mib_table as *const core::ffi::c_void) };

        None
    }

    /// Finds network interface by provided hardware address.
    ///
    /// # Arguments
    ///
    /// * `address` - A `MacAddress` to lookup.
    ///
    /// # Returns
    ///
    /// * `Option<IphlpNetworkAdapterInfo>` - An optional `IphlpNetworkAdapterInfo` object.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to get the network interface information.
    /// The caller should ensure that the returned `IphlpNetworkAdapterInfo` objects are not used
    /// after the corresponding network interfaces have been removed or disabled.
    pub fn get_connection_by_hw_address(address: &MacAddress) -> Option<IphlpNetworkAdapterInfo> {
        let mut dw_size = 0;
        let mut mib_table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();

        // Query detailed information on available network interfaces
        if unsafe { GetIfTable2(&mut mib_table) }.is_err() {
            return None;
        }

        // Get available unicast addresses
        let error_code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_INCLUDE_GATEWAYS
                    | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                None,
                None,
                &mut dw_size,
            )
        };

        if WIN32_ERROR(error_code) == ERROR_BUFFER_OVERFLOW && dw_size != 0 {
            loop {
                let mut ip_address_info = vec![0u8; dw_size as usize];

                let error_code = unsafe {
                    GetAdaptersAddresses(
                        AF_UNSPEC.0 as u32,
                        GAA_FLAG_SKIP_ANYCAST
                            | GAA_FLAG_SKIP_MULTICAST
                            | GAA_FLAG_INCLUDE_GATEWAYS
                            | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                        None,
                        Some(ip_address_info.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                        &mut dw_size,
                    )
                };

                if WIN32_ERROR(error_code) == NO_ERROR {
                    let mut current_address =
                        ip_address_info.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

                    while !current_address.is_null() {
                        let current = unsafe { &*current_address };

                        if MacAddress::from_slice(&current.PhysicalAddress).unwrap_or_default()
                            != *address
                        {
                            current_address = current.Next;
                            continue;
                        }

                        // Lookup advanced information on the network interface
                        for i in 0..unsafe { (*mib_table).NumEntries } {
                            let table_ptr = unsafe { (*mib_table).Table.as_ptr() };
                            let entry_ptr = unsafe { table_ptr.add(i as usize) };
                            if IfLuid::from(unsafe { (*mib_table).Table[i as usize].InterfaceLuid })
                                == IfLuid::from(current.Luid)
                            {
                                let result =
                                    unsafe { IphlpNetworkAdapterInfo::new(current, entry_ptr) };
                                unsafe { FreeMibTable(mib_table as *const core::ffi::c_void) };
                                return Some(result);
                            }
                        }

                        current_address = current.Next;
                    }

                    break;
                }
                // In case of insufficient buffer size we try to recover by reallocating buffer
                if WIN32_ERROR(error_code) != ERROR_BUFFER_OVERFLOW {
                    unsafe { SetLastError(WIN32_ERROR(error_code)) };
                    break;
                }
            }
        } else {
            // GetAdaptersAddresses has failed with status different from ERROR_BUFFER_OVERFLOW when obtaining required buffer size
            if WIN32_ERROR(error_code) != NO_ERROR {
                unsafe { SetLastError(WIN32_ERROR(error_code)) };
            }
        }

        // Free interface table
        unsafe { FreeMibTable(mib_table as *const core::ffi::c_void) };

        None
    }

    /// Finds network interface by provided GUID.
    ///
    /// # Arguments
    ///
    /// * `guid` - A `&str` containing the GUID to lookup.
    ///
    /// # Returns
    ///
    /// * `Option<IphlpNetworkAdapterInfo>` - An optional `IphlpNetworkAdapterInfo` object.
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to get the network interface information.
    /// The caller should ensure that the returned `IphlpNetworkAdapterInfo` objects are not used
    /// after the corresponding network interfaces have been removed or disabled.
    pub fn get_connection_by_guid(guid: &str) -> Option<IphlpNetworkAdapterInfo> {
        let mut dw_size = 0;
        let mut mib_table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();

        // Query detailed information on available network interfaces
        if unsafe { GetIfTable2(&mut mib_table) }.is_err() {
            return None;
        }

        // Get available unicast addresses
        let error_code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_INCLUDE_GATEWAYS
                    | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                None,
                None,
                &mut dw_size,
            )
        };

        if WIN32_ERROR(error_code) == ERROR_BUFFER_OVERFLOW && dw_size != 0 {
            loop {
                let mut ip_address_info = vec![0u8; dw_size as usize];

                let error_code = unsafe {
                    GetAdaptersAddresses(
                        AF_UNSPEC.0 as u32,
                        GAA_FLAG_SKIP_ANYCAST
                            | GAA_FLAG_SKIP_MULTICAST
                            | GAA_FLAG_INCLUDE_GATEWAYS
                            | GAA_FLAG_INCLUDE_ALL_INTERFACES,
                        None,
                        Some(ip_address_info.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                        &mut dw_size,
                    )
                };

                if WIN32_ERROR(error_code) == NO_ERROR {
                    let mut current_address =
                        ip_address_info.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

                    while !current_address.is_null() {
                        let current = unsafe { &*current_address };

                        let adapter_name = unsafe { current.AdapterName.to_string() }
                            .unwrap_or_default()
                            .to_uppercase();

                        if !adapter_name.contains(guid) {
                            current_address = current.Next;
                            continue;
                        }

                        // Lookup advanced information on the network interface
                        for i in 0..unsafe { (*mib_table).NumEntries } {
                            let table_ptr = unsafe { (*mib_table).Table.as_ptr() };
                            let entry_ptr = unsafe { table_ptr.add(i as usize) };
                            if IfLuid::from(unsafe { (*mib_table).Table[i as usize].InterfaceLuid })
                                == IfLuid::from(current.Luid)
                            {
                                let result =
                                    unsafe { IphlpNetworkAdapterInfo::new(current, entry_ptr) };
                                unsafe { FreeMibTable(mib_table as *const core::ffi::c_void) };
                                return Some(result);
                            }
                        }

                        current_address = current.Next;
                    }

                    break;
                }
                // In case of insufficient buffer size we try to recover by reallocating buffer
                if WIN32_ERROR(error_code) != ERROR_BUFFER_OVERFLOW {
                    unsafe { SetLastError(WIN32_ERROR(error_code)) };
                    break;
                }
            }
        } else {
            // GetAdaptersAddresses has failed with status different from ERROR_BUFFER_OVERFLOW when obtaining required buffer size
            if WIN32_ERROR(error_code) != NO_ERROR {
                unsafe { SetLastError(WIN32_ERROR(error_code)) };
            }
        }

        // Free interface table
        unsafe { FreeMibTable(mib_table as *const core::ffi::c_void) };

        None
    }
}
