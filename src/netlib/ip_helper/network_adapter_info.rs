use crate::{GuidWrapper, IfLuid, IpGatewayInfo, MacAddress, SockAddrStorage};
use std::net::IpAddr;
use windows::{
    core::{w, Result, PCWSTR},
    Win32::{
        NetworkManagement::{
            IpHelper::{
                ResolveIpNetEntry2, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
                IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2, MIB_IPNET_ROW2,
            },
            Ndis::{NDIS_MEDIUM, NDIS_PHYSICAL_MEDIUM},
        },
        Networking::WinSock::{AF_INET, AF_INET6},
        System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_SZ,
        },
    },
};

// Submodules
pub mod address;
pub mod gateway;
pub mod getters;
pub mod ndp;
pub mod routing;
pub mod statics;
pub mod util;

/// Represents information about a network adapter.
///
/// This struct provides an easy-to-use and safe interface for working with network adapter
/// information, such as IP addresses, DNS server addresses, gateway addresses, and more.
#[derive(Debug, Clone)]
pub struct IphlpNetworkAdapterInfo {
    /// The index of the IPv4 interface.
    if_index: u32,
    /// The interface index for the IPv6 IP address. This member is zero if IPv6 is not available on the interface.
    ipv6_if_index: u32,
    /// Contains the name of the adapter. Unlike an adapter's friendly name, the adapter name specified in `adapter_name_` is permanent and cannot be modified by the user.
    adapter_name: String,
    /// Contains the name of the underlying hardware adapter.
    true_adapter_name: GuidWrapper,
    /// A description for the adapter.
    description: String,
    /// A user-friendly name for the adapter.
    friendly_name: String,
    /// List of IP unicast addresses for the adapter.
    unicast_address_list: Vec<IpAddr>,
    /// List of DNS server addresses for the adapter.
    dns_server_address_list: Vec<IpAddr>,
    /// List of gateways for the adapter.
    gateway_address_list: Vec<IpGatewayInfo>,
    /// The Media Access Control (MAC) address for the adapter.
    physical_address: MacAddress,
    /// The maximum transmission unit (MTU) size, in bytes.
    mtu: u16,
    /// The interface type as defined by the Internet Assigned Names Authority (IANA).
    /// Possible values for the interface type are listed in the `Ipifcons.h` header file.
    if_type: u32,
    /// The current speed in bits per second of the transmit link for the adapter.
    transmit_link_speed: u64,
    /// The current speed in bits per second of the receive link for the adapter.
    receive_link_speed: u64,
    /// The interface LUID for the adapter address.
    luid: IfLuid,
    /// The NDIS media type for the interface. This member can be one of the values from the `NDIS_MEDIUM`
    /// enumeration type defined in the `Ntddndis.h` header file.
    media_type: NDIS_MEDIUM,
    /// The NDIS physical medium type. This member can be one of the values from the `NDIS_PHYSICAL_MEDIUM`
    /// enumeration type defined in the `Ntddndis.h` header file.
    physical_medium_type: NDIS_PHYSICAL_MEDIUM,
    /// If `physical_medium_type_` is `NdisPhysicalMediumUnspecified` (virtual network interface on top of the real one),
    /// this one may contain real physical media.
    true_medium_type: NDIS_PHYSICAL_MEDIUM,
    /// NDISWANIP associated MAC address.
    ndis_wan_ip_link: MacAddress,
    /// NDISWANIPV6 associated MAC address.
    ndis_wan_ipv6_link: MacAddress,
}

impl IphlpNetworkAdapterInfo {
    /// Constructs a new `IphlpNetworkAdapterInfo` instance from raw pointers to `IP_ADAPTER_ADDRESSES_LH`
    /// and `MIB_IF_ROW2` structures.
    ///
    /// This method is marked as `unsafe` because it dereferences raw pointers, which can lead
    /// to undefined behavior if not used correctly.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `address` and `if_row` are valid pointers to
    /// `IP_ADAPTER_ADDRESSES_LH` and `MIB_IF_ROW2` structures, respectively, and that the
    /// structures remain valid for the duration of the method call.
    ///
    /// # Arguments
    ///
    /// * `address` - A pointer to an `IP_ADAPTER_ADDRESSES_LH` structure containing information
    ///   about the network adapter.
    /// * `if_row` - A pointer to a `MIB_IF_ROW2` structure containing information about the
    ///   network interface.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use my_crate::IphlpNetworkAdapterInfo;
    /// use my_crate::{IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2};
    ///
    /// unsafe {
    ///     let address = /* ... */;
    ///     let if_row = /* ... */;
    ///
    ///     let network_adapter_info = IphlpNetworkAdapterInfo::new(address, if_row);
    /// }
    ///
    pub unsafe fn new(address: *const IP_ADAPTER_ADDRESSES_LH, if_row: *const MIB_IF_ROW2) -> Self {
        let address = unsafe { &*address };

        let mut unicast_address_list = Vec::new();
        let mut unicast_address = address.FirstUnicastAddress;
        while !unicast_address.is_null() {
            unicast_address_list.push(
                SockAddrStorage::from_sockaddr(unsafe { *(*unicast_address).Address.lpSockaddr })
                    .into(),
            );
            unicast_address = unsafe { (*unicast_address).Next };
        }

        let mut dns_server_address_list = Vec::new();
        let mut dns_address = address.FirstDnsServerAddress;
        while !dns_address.is_null() {
            dns_server_address_list.push(
                SockAddrStorage::from_sockaddr(unsafe { *(*dns_address).Address.lpSockaddr })
                    .into(),
            );
            dns_address = unsafe { (*dns_address).Next };
        }

        let mut gateway_address_list = Vec::new();
        let mut gateway_address = address.FirstGatewayAddress;
        while !gateway_address.is_null() {
            gateway_address_list.push(IpGatewayInfo::new(
                SockAddrStorage::from_sockaddr(unsafe { *(*gateway_address).Address.lpSockaddr })
                    .into(),
                None,
            ));
            gateway_address = unsafe { (*gateway_address).Next };
        }

        let mut result = Self {
            if_index: unsafe { address.Anonymous1.Anonymous.IfIndex },
            ipv6_if_index: address.Ipv6IfIndex,
            adapter_name: unsafe { address.AdapterName.to_string() }.unwrap_or_default(),
            description: unsafe { address.Description.to_string() }.unwrap_or_default(),
            friendly_name: unsafe { address.FriendlyName.to_string() }.unwrap_or_default(),
            physical_address: MacAddress::from_slice(&address.PhysicalAddress).unwrap_or_default(),
            mtu: address.Mtu as u16,
            if_type: address.IfType,
            transmit_link_speed: address.TransmitLinkSpeed,
            receive_link_speed: address.ReceiveLinkSpeed,
            luid: IfLuid::new(&address.Luid),
            media_type: (*if_row).MediaType,
            physical_medium_type: (*if_row).PhysicalMediumType,
            unicast_address_list,
            dns_server_address_list,
            gateway_address_list,
            true_adapter_name: GuidWrapper::new(),
            true_medium_type: NDIS_PHYSICAL_MEDIUM::default(),
            ndis_wan_ip_link: MacAddress::default(),
            ndis_wan_ipv6_link: MacAddress::default(),
        };

        // For each ethernet of wi-fi interface initialize the gateway hardware address list by resolving
        // the hardware addresses for each gateway IP address in the list.
        if address.IfType == IF_TYPE_ETHERNET_CSMACD || address.IfType == IF_TYPE_IEEE80211 {
            result.initialize_gateway_hw_address_list();
        }

        result
    }

    /// Initializes the gateway hardware address list by resolving the hardware addresses
    /// for each gateway IP address in the list.
    ///
    /// This function iterates over the `gateway_address_list` and resolves the hardware addresses
    /// by updating the `MIB_IPNET_ROW2` structure and calling the `ResolveIpNetEntry2` function.
    /// If successful, the hardware address is assigned to the `hardware_address` field of the
    /// corresponding `Address` structure.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code blocks due to the use of FFI calls to the WinAPI, direct memory access,
    /// and pointer casting. Make sure that the data structures are properly initialized and that the
    /// WinAPI functions are used correctly to ensure memory safety.
    ///
    unsafe fn initialize_gateway_hw_address_list(&mut self) {
        if !self.gateway_address_list.is_empty() {
            // check if the address list is empty
            for address in &mut self.gateway_address_list {
                // iterate through each address in the list
                let mut row: MIB_IPNET_ROW2 = unsafe { std::mem::zeroed() }; // create a new row object with default values

                // assign values to new row object
                row.Address.si_family = if address.ip_address.is_ipv4() {
                    AF_INET
                } else {
                    AF_INET6
                }; // assign si_family value
                row.InterfaceLuid = self.luid.into(); // assign InterfaceLuid value

                // match against address family and assign to proper field in row
                match address.ip_address {
                    IpAddr::V4(ip_address) => {
                        // for IPv4 addresses
                        row.Address.Ipv4.sin_addr = ip_address.into();
                    }
                    IpAddr::V6(ip_address) => {
                        // for IPv6 addresses
                        row.Address.Ipv6.sin6_addr = ip_address.into();
                    }
                }

                // resolve IP address to MAC address using the current row and store it in the address object
                if unsafe { ResolveIpNetEntry2(&mut row, None) }.is_ok() {
                    address.hardware_address =
                        MacAddress::from_slice(&row.PhysicalAddress).unwrap_or_default();
                }
            }
        }
    }

    /// Sets the friendly name of the network adapter.
    ///
    /// This function sets the friendly name of the network adapter by updating the Windows registry.
    /// The registry key for the adapter is located at:
    /// `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{adapter_name}\Connection`.
    ///
    /// # Arguments
    ///
    /// * `friendly_name` - A string or any type that can be converted into a `String` representing the friendly name of the adapter.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the friendly name is set successfully. Returns an `Err` containing the error code if there is a failure.
    ///
    // This function sets the friendly name of a network adapter and updates the registry accordingly
    pub fn set_friendly_name(&mut self, friendly_name: impl Into<String>) -> Result<()> {
        self.friendly_name = friendly_name.into(); // set the friendly name of the adapter to the input value

        // create the registry key path for the adapter's connection settings
        let friendly_name_key = format!(
        "SYSTEM\\CurrentControlSet\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{}\\Connection",
        &self.adapter_name
    );

        // Convert the string to UTF16 array and get a pointer to it as PCWSTR
        let mut friendly_name_key = friendly_name_key.encode_utf16().collect::<Vec<u16>>();
        friendly_name_key.push(0); // add null terminator to end of key string

        let mut hkey = HKEY::default();

        // open the registry key for the adapter's connection settings with write access
        let mut result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE, // handle to a pre-defined registry key
                PCWSTR::from_raw(friendly_name_key.as_ptr()), // registry key path as a PCWSTR pointer
                0,                                            // reserved (ignored)
                KEY_WRITE,                                    // desired security access level
                &mut hkey, // pointer to a variable to receive the handle to the opened key
            )
        };

        if result.is_ok() {
            // if the key was successfully opened
            // set the AdapterName registry value to the friendly name of the adapter
            result = unsafe {
                RegSetValueExW(
                    hkey,                                // handle to an open registry key
                    w!("Name"),                          // name of the value to be set
                    0,                                   // reserved (ignored)
                    REG_SZ,                              // data type of the value
                    Some(self.friendly_name.as_bytes()), // pointer to the buffer containing the value's data
                )
            };

            _ = unsafe {
                RegCloseKey(hkey) // close the registry key handle
            };
        }

        result
    }

    /// Checks if IP address information in the provided network_adapter_info is different
    /// from the current one.
    ///
    /// # Arguments
    ///
    /// * `rhs`: IphlpNetworkAdapterInfo to compare to
    /// * `check_gateway`: If true, also checks the gateway information
    ///
    /// # Returns
    ///
    /// * `bool`: true if provided IphlpNetworkAdapterInfo contains the same IP addresses, false otherwise
    pub fn is_same_address_info(&self, rhs: &IphlpNetworkAdapterInfo, check_gateway: bool) -> bool {
        if self.unicast_address_list.len() != rhs.unicast_address_list.len() {
            return false;
        }

        if check_gateway && self.gateway_address_list.len() != rhs.gateway_address_list.len() {
            return false;
        }

        // Check if any of the unicast addresses have changed
        let ret_val = rhs
            .unicast_address_list
            .iter()
            .all(|address| self.unicast_address_list.contains(address));

        if !ret_val {
            return ret_val;
        }

        // Check if any of the gateways have changed
        if check_gateway {
            rhs.gateway_address_list
                .iter()
                .all(|address| self.gateway_address_list.contains(address))
        } else {
            ret_val
        }
    }

    /// Resets the adapter's addresses and routes.
    ///
    /// # Returns
    ///
    /// * `bool`: true if successful, false otherwise.
    pub fn reset_adapter(&self) -> bool {
        self.reset_unicast_addresses() && self.reset_adapter_routes()
    }
}
