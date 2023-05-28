use crate::{GuidWrapper, IfLuid, IpGatewayInfo, IphlpNetworkAdapterInfo, MacAddress};
use std::net::IpAddr;
use windows::Win32::NetworkManagement::Ndis::{NDIS_MEDIUM, NDIS_PHYSICAL_MEDIUM};

impl IphlpNetworkAdapterInfo {
    /// Returns the index of the IPv4 interface.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let if_index = adapter_info.if_index();
    /// ```
    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    /// Returns the interface index for the IPv6 IP address.
    /// This member is zero if IPv6 is not available on the interface.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let ipv6_if_index = adapter_info.ipv6_if_index();
    /// ```
    pub fn ipv6_if_index(&self) -> u32 {
        self.ipv6_if_index
    }

    /// Returns a reference to the name of the adapter.
    /// Unlike an adapter's friendly name, the adapter name specified in `adapter_name_`
    /// is permanent and cannot be modified by the user.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let adapter_name = adapter_info.adapter_name();
    /// ```
    pub fn adapter_name(&self) -> &String {
        &self.adapter_name
    }

    /// Returns a reference to the name of the underlying hardware adapter.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let true_adapter_name = adapter_info.true_adapter_name();
    /// ```
    pub fn true_adapter_name(&self) -> &GuidWrapper {
        &self.true_adapter_name
    }

    /// Returns a reference to the description for the adapter.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let description = adapter_info.description();
    /// ```
    pub fn description(&self) -> &String {
        &self.description
    }

    /// Returns a reference to the user-friendly name for the adapter.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let friendly_name = adapter_info.friendly_name();
    /// ```
    pub fn friendly_name(&self) -> &String {
        &self.friendly_name
    }

    /// Returns a reference to the list of IP unicast addresses for the adapter.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let unicast_address_list = adapter_info.unicast_address_list();
    /// ```
    pub fn unicast_address_list(&self) -> &Vec<IpAddr> {
        &self.unicast_address_list
    }

    /// Returns a reference to the list of DNS server addresses for the adapter.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let dns_server_address_list = adapter_info.dns_server_address_list();
    /// ```
    pub fn dns_server_address_list(&self) -> &Vec<IpAddr> {
        &self.dns_server_address_list
    }

    /// Returns a reference to the list of gateways for the adapter.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let gateway_address_list = adapter_info.gateway_address_list();
    /// ```
    pub fn gateway_address_list(&self) -> &Vec<IpGatewayInfo> {
        &self.gateway_address_list
    }

    /// Returns a reference to the Media Access Control (MAC) address for the adapter.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let physical_address = adapter_info.physical_address();
    /// ```
    pub fn physical_address(&self) -> &MacAddress {
        &self.physical_address
    }

    /// Returns the maximum transmission unit (MTU) size, in bytes.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mtu = adapter_info.mtu();
    /// ```
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Returns the interface type as defined by the Internet Assigned Names Authority (IANA).
    /// Possible values for the interface type are listed in the `Ipifcons.h` header file.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let if_type = adapter_info.if_type();
    /// ```
    pub fn if_type(&self) -> u32 {
        self.if_type
    }

    /// Returns the current speed in bits per second of the transmit link for the adapter.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let transmit_link_speed = adapter_info.transmit_link_speed();
    /// ```
    pub fn transmit_link_speed(&self) -> u64 {
        self.transmit_link_speed
    }

    /// Returns the current speed in bits per second of the receive link for the adapter.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let receive_link_speed = adapter_info.receive_link_speed();
    /// ```
    pub fn receive_link_speed(&self) -> u64 {
        self.receive_link_speed
    }

    /// Returns the interface LUID for the adapter address.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let luid = adapter_info.luid();
    /// ```
    pub fn luid(&self) -> &IfLuid {
        &self.luid
    }

    /// Returns the NDIS media type for the interface.
    /// This member can be one of the values from the `NDIS_MEDIUM`
    /// enumeration type defined in the `Ntddndis.h` header file.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let media_type = adapter_info.media_type();
    /// ```
    pub fn media_type(&self) -> &NDIS_MEDIUM {
        &self.media_type
    }

    /// Returns the NDIS physical medium type.
    /// This member can be one of the values from the `NDIS_PHYSICAL_MEDIUM`
    /// enumeration type defined in the `Ntddndis.h` header file.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let physical_medium_type = adapter_info.physical_medium_type();
    /// ```
    pub fn physical_medium_type(&self) -> &NDIS_PHYSICAL_MEDIUM {
        &self.physical_medium_type
    }

    /// If `physical_medium_type_` is `NdisPhysicalMediumUnspecified` (virtual network interface on top of the real one),
    /// this one may contain real physical media.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let true_medium_type = adapter_info.true_medium_type();
    /// ```
    pub fn true_medium_type(&self) -> &NDIS_PHYSICAL_MEDIUM {
        &self.true_medium_type
    }

    /// Returns the NDISWANIP associated MAC address.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let ndis_wan_ip_link = adapter_info.ndis_wan_ip_link();
    /// ```
    pub fn ndis_wan_ip_link(&self) -> &MacAddress {
        &self.ndis_wan_ip_link
    }

    /// Returns the NDISWANIPV6 associated MAC address.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let ndis_wan_ipv6_link = adapter_info.ndis_wan_ipv6_link();
    /// ```
    pub fn ndis_wan_ipv6_link(&self) -> &MacAddress {
        &self.ndis_wan_ipv6_link
    }
}
