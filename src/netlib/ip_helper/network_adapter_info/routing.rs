use crate::{IfLuid, IphlpNetworkAdapterInfo};
use ipnetwork::IpNetwork;
use std::collections::VecDeque;
use windows::Win32::NetworkManagement::IpHelper::{
    DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;
use windows::Win32::{
    Foundation::ERROR_OBJECT_ALREADY_EXISTS,
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    },
    Networking::WinSock::{
        NlroManual, AF_INET, AF_INET6, IN6_ADDR, IN_ADDR, MIB_IPPROTO_NT_STATIC,
    },
};

impl IphlpNetworkAdapterInfo {
    /// Configures IPv4 network interface routes (Wireguard AllowedIps parameter).
    ///
    /// # Arguments
    ///
    /// * `ips`: Vec of IpNetwork (Ipv4Network or Ipv6Network) subnets to configure
    ///
    /// # Returns
    ///
    /// * `VecDeque<MIB_IPFORWARD_ROW2>`: VecDeque of MIB_IPFORWARD_ROW2 on success
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to initialize and create IP forward entries.
    /// The caller should ensure that the provided IPv4/IPv6 subnets are valid and
    /// that the network interface is properly configured before calling this function.
    pub fn add_routes_ipv4(&self, ips: Vec<IpNetwork>) -> VecDeque<MIB_IPFORWARD_ROW2> {
        let mut ret_val = VecDeque::new();

        for ip in ips {
            if let IpNetwork::V4(subnet_v4) = ip {
                let mut forward_row = MIB_IPFORWARD_ROW2::default();
                unsafe { InitializeIpForwardEntry(&mut forward_row) };

                forward_row.InterfaceIndex = self.if_index;
                forward_row.InterfaceLuid = self.luid.into();
                forward_row.DestinationPrefix.Prefix.si_family = AF_INET;
                forward_row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
                forward_row
                    .DestinationPrefix
                    .Prefix
                    .Ipv4
                    .sin_addr
                    .S_un
                    .S_addr = u32::from_ne_bytes(subnet_v4.ip().octets());
                forward_row.DestinationPrefix.PrefixLength = subnet_v4.prefix();
                forward_row.NextHop.si_family = AF_INET;
                forward_row.NextHop.Ipv4.sin_family = AF_INET;
                forward_row.NextHop.Ipv4.sin_addr = IN_ADDR::default();
                forward_row.SitePrefixLength = 0;
                forward_row.Metric = 0;
                forward_row.Protocol = MIB_IPPROTO_NT_STATIC;
                forward_row.Origin = NlroManual;

                match unsafe { CreateIpForwardEntry2(&forward_row) }.ok() {
                    Ok(_) => ret_val.push_back(forward_row),
                    Err(err) => {
                        if err == ERROR_OBJECT_ALREADY_EXISTS.into() {
                            ret_val.push_back(forward_row);
                        }
                    }
                }
            }
        }

        ret_val
    }

    /// Configures IPv6 network interface routes (Wireguard AllowedIps parameter).
    ///
    /// # Arguments
    ///
    /// * `ips`: Vec of IpNetwork (Ipv4Network or Ipv6Network) subnets to configure
    ///
    /// # Returns
    ///
    /// * `VecDeque<MIB_IPFORWARD_ROW2>`: VecDeque of MIB_IPFORWARD_ROW2 on success
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to initialize and create IP forward entries.
    /// The caller should ensure that the provided IPv4/IPv6 subnets are valid and
    /// that the network interface is properly configured before calling this function.
    pub fn add_routes_ipv6(&self, ips: Vec<IpNetwork>) -> VecDeque<MIB_IPFORWARD_ROW2> {
        let mut return_value = VecDeque::new();

        for ip in ips {
            if let IpNetwork::V6(subnet_v6) = ip {
                let mut forward_row = MIB_IPFORWARD_ROW2::default();
                unsafe { InitializeIpForwardEntry(&mut forward_row) };

                forward_row.InterfaceIndex = self.ipv6_if_index;
                forward_row.InterfaceLuid = self.luid.into();
                forward_row.DestinationPrefix.Prefix.si_family = AF_INET6;
                forward_row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
                forward_row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte =
                    subnet_v6.ip().octets();
                forward_row.DestinationPrefix.PrefixLength = subnet_v6.prefix();
                forward_row.NextHop.si_family = AF_INET6;
                forward_row.NextHop.Ipv6.sin6_family = AF_INET6;
                forward_row.NextHop.Ipv6.sin6_addr = IN6_ADDR::default();
                forward_row.SitePrefixLength = 0;
                forward_row.Metric = 0;
                forward_row.Protocol = MIB_IPPROTO_NT_STATIC;
                forward_row.Origin = NlroManual;

                match unsafe { CreateIpForwardEntry2(&forward_row) }.ok() {
                    Ok(_) => return_value.push_back(forward_row),
                    Err(err) => {
                        if err == ERROR_OBJECT_ALREADY_EXISTS.into() {
                            return_value.push_back(forward_row);
                        }
                    }
                }
            }
        }

        return_value
    }

    /// Deletes routing table entry by MIB_IPFORWARD_ROW2 reference.
    ///
    /// # Arguments
    ///
    /// * `address`: Reference to MIB_IPFORWARD_ROW2
    ///
    /// # Returns
    ///
    /// * `bool`: `true` if successful, `false` otherwise
    ///
    /// # Safety
    ///
    /// This function uses an unsafe Windows API call to delete IP forward entries.
    /// The caller should ensure that the provided MIB_IPFORWARD_ROW2 reference is valid before calling this function.
    pub fn delete_route(address: &MIB_IPFORWARD_ROW2) -> bool {
        unsafe { DeleteIpForwardEntry2(address) }.is_ok()
    }

    /// Deletes routing table entries by MIB_IPFORWARD_ROW2 references.
    ///
    /// # Arguments
    ///
    /// * `addresses`: Vec of MIB_IPFORWARD_ROW2 references
    ///
    /// # Returns
    ///
    /// * `bool`: `true` if successful, `false` otherwise
    ///
    /// # Safety
    ///
    /// This function uses an unsafe Windows API call to delete IP forward entries.
    /// The caller should ensure that the provided MIB_IPFORWARD_ROW2 reference is valid before calling this function.
    pub fn delete_routes(addresses: &mut [MIB_IPFORWARD_ROW2]) -> bool {
        let mut status = true;

        for address in addresses.iter() {
            status = unsafe { DeleteIpForwardEntry2(address) }.is_ok()
        }

        status
    }

    /// Removes all routing table entries associated with the network interface.
    ///
    /// # Returns
    ///
    /// * `bool`: `true` if successful, `false` otherwise
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to get the IP forward table, delete IP forward entries,
    /// and free the MIB table. The caller should ensure that the network interface is properly configured
    /// before calling this function.
    pub fn reset_adapter_routes(&self) -> bool {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();

        match unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) }.ok() {
            Ok(_) => {
                let num_entries = unsafe { (*table).NumEntries };

                for i in 0..num_entries {
                    let entry = unsafe { &mut (*table).Table[i as usize] };

                    if IfLuid::from(entry.InterfaceLuid) == self.luid {
                        let _ = unsafe { DeleteIpForwardEntry2(entry) };
                    }
                }

                unsafe { FreeMibTable(table as *mut _) };
                true
            }
            Err(_) => false,
        }
    }
}
