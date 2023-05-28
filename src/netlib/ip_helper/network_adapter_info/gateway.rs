use crate::IphlpNetworkAdapterInfo;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows::Win32::{
    Foundation::{SetLastError, ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS, NO_ERROR},
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    },
    Networking::WinSock::{
        NlroManual, AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, MIB_IPPROTO_NT_STATIC,
    },
};

impl IphlpNetworkAdapterInfo {
    /// Adds a default IPv4 gateway to the network interface.
    ///
    /// # Arguments
    ///
    /// * `address`: Default gateway IPv4 address
    ///
    /// # Returns
    ///
    /// * `Option<MIB_IPFORWARD_ROW2>`: Some(MIB_IPFORWARD_ROW2) on success, None on failure
    ///
    /// # Safety
    ///
    /// This function calls unsafe Windows API functions (`InitializeIpForwardEntry`, `SetLastError`, and
    /// `CreateIpForwardEntry2`). Make sure to handle errors and exceptions properly when using this function.
    pub fn add_default_gateway_ipv4(&self, address: Ipv4Addr) -> Option<MIB_IPFORWARD_ROW2> {
        let mut forward_row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut forward_row) };

        forward_row.InterfaceIndex = self.if_index;
        forward_row.InterfaceLuid = self.luid.into();
        forward_row.DestinationPrefix.Prefix.si_family = AF_INET;
        forward_row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
        forward_row.NextHop.si_family = AF_INET;
        forward_row.NextHop.Ipv4.sin_family = AF_INET;
        forward_row.NextHop.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.octets());
        forward_row.SitePrefixLength = 0;
        forward_row.Metric = 1;
        forward_row.Protocol = MIB_IPPROTO_NT_STATIC;
        forward_row.Origin = NlroManual;

        unsafe { SetLastError(ERROR_SUCCESS) };

        let error_code = unsafe { CreateIpForwardEntry2(&forward_row) };

        if error_code == NO_ERROR || error_code == ERROR_OBJECT_ALREADY_EXISTS {
            Some(forward_row)
        } else {
            unsafe { SetLastError(error_code) };
            None
        }
    }

    /// Adds a default IPv6 gateway to the network interface.
    ///
    /// # Arguments
    ///
    /// * `address`: Default gateway IPv6 address
    ///
    /// # Returns
    ///
    /// * `Option<MIB_IPFORWARD_ROW2>`: Some(MIB_IPFORWARD_ROW2) on success, None on failure
    ///
    /// # Safety
    ///
    /// This function uses FFI to interact with the Windows API, specifically the `InitializeIpForwardEntry`,
    /// `CreateIpForwardEntry2`, and `SetLastError` functions. It is the caller's responsibility to ensure that
    /// the library containing these functions is properly loaded and the FFI definitions are correct.
    pub fn add_default_gateway_ipv6(&self, address: Ipv6Addr) -> Option<MIB_IPFORWARD_ROW2> {
        let mut forward_row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut forward_row) };

        forward_row.InterfaceIndex = self.ipv6_if_index;
        forward_row.InterfaceLuid = self.luid.into();
        forward_row.DestinationPrefix.Prefix.si_family = AF_INET6;
        forward_row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
        forward_row.NextHop.si_family = AF_INET6;
        forward_row.NextHop.Ipv6.sin6_family = AF_INET6;
        forward_row.NextHop.Ipv6.sin6_addr = IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: address.octets(),
            },
        };
        forward_row.SitePrefixLength = 0;
        forward_row.Metric = 1;
        forward_row.Protocol = MIB_IPPROTO_NT_STATIC;
        forward_row.Origin = NlroManual;

        unsafe { SetLastError(ERROR_SUCCESS) };

        let error_code = unsafe { CreateIpForwardEntry2(&forward_row) };

        if error_code == NO_ERROR || error_code == ERROR_OBJECT_ALREADY_EXISTS {
            Some(forward_row)
        } else {
            unsafe { SetLastError(error_code) };
            None
        }
    }

    /// Configures the network interface as a default IPv4 gateway with the specified metric.
    ///
    /// # Arguments
    ///
    /// * `metric`: Network metric (priority), defaults to 0
    ///
    /// # Returns
    ///
    /// * `Option<MIB_IPFORWARD_ROW2>`: Some(MIB_IPFORWARD_ROW2) on success, None on failure
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to initialize and create IP forward entries.
    /// The caller should ensure that the provided metric is a valid network metric and
    /// that the network interface is properly configured before calling this function.
    pub fn assign_default_gateway_ipv4(&self, metric: u32) -> Option<MIB_IPFORWARD_ROW2> {
        let mut forward_row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut forward_row) };

        forward_row.InterfaceIndex = self.if_index;
        forward_row.InterfaceLuid = self.luid.into();
        forward_row.DestinationPrefix.Prefix.si_family = AF_INET;
        forward_row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
        forward_row.NextHop.si_family = AF_INET;
        forward_row.NextHop.Ipv4.sin_family = AF_INET;
        forward_row.NextHop.Ipv4.sin_addr.S_un.S_addr = 0;
        forward_row.SitePrefixLength = 0;
        forward_row.Metric = metric;
        forward_row.Protocol = MIB_IPPROTO_NT_STATIC;
        forward_row.Origin = NlroManual;

        unsafe { SetLastError(ERROR_SUCCESS) };

        let error_code = unsafe { CreateIpForwardEntry2(&forward_row) };

        if error_code == NO_ERROR || error_code == ERROR_OBJECT_ALREADY_EXISTS {
            Some(forward_row)
        } else {
            unsafe { SetLastError(error_code) };
            None
        }
    }

    /// Configures the network interface as a default IPv6 gateway with the specified metric.
    ///
    /// # Arguments
    ///
    /// * `metric`: Network metric (priority), defaults to 0
    ///
    /// # Returns
    ///
    /// * `Option<MIB_IPFORWARD_ROW2>`: Some(MIB_IPFORWARD_ROW2) on success, None on failure
    ///
    /// # Safety
    ///
    /// This function uses unsafe Windows API calls to initialize and create IP forward entries.
    /// The caller should ensure that the provided metric is a valid network metric and
    /// that the network interface is properly configured before calling this function.
    pub fn assign_default_gateway_ipv6(&self, metric: u32) -> Option<MIB_IPFORWARD_ROW2> {
        let mut forward_row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut forward_row) };

        forward_row.InterfaceIndex = self.ipv6_if_index;
        forward_row.InterfaceLuid = self.luid.into();
        forward_row.DestinationPrefix.Prefix.si_family = AF_INET6;
        forward_row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
        forward_row.NextHop.si_family = AF_INET6;
        forward_row.NextHop.Ipv6.sin6_family = AF_INET6;
        forward_row.NextHop.Ipv6.sin6_addr = IN6_ADDR::default();
        forward_row.SitePrefixLength = 0;
        forward_row.Metric = metric;
        forward_row.Protocol = MIB_IPPROTO_NT_STATIC;
        forward_row.Origin = NlroManual;

        let error_code = unsafe { CreateIpForwardEntry2(&forward_row) };

        if error_code == NO_ERROR || error_code == ERROR_OBJECT_ALREADY_EXISTS {
            Some(forward_row)
        } else {
            unsafe { SetLastError(error_code) };
            None
        }
    }
}
