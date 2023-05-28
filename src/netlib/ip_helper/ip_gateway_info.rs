use crate::MacAddress;
use std::net::IpAddr;

/// Represents network gateway information, storing IP address and hardware (MAC) address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpGatewayInfo {
    pub ip_address: IpAddr,
    pub hardware_address: MacAddress,
}

impl IpGatewayInfo {
    /// Constructs `IpGatewayInfo` from a `SockAddrStorage` and an optional `MacAddress`.
    ///
    /// # Arguments
    ///
    /// * `ip_address_info` - A `SockAddrStorage` representing the IP address.
    /// * `hardware_address` - An optional `MacAddress` representing the hardware (MAC) address.
    ///
    /// # Returns
    ///
    /// A new `IpGatewayInfo` instance.
    pub fn new(ip_address: IpAddr, hardware_address: Option<MacAddress>) -> IpGatewayInfo {
        IpGatewayInfo {
            ip_address,
            hardware_address: hardware_address
                .unwrap_or_else(|| MacAddress::from_slice(&[0; 6]).unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    // Test the IpGatewayInfo::new method with a given MacAddress
    #[test]
    fn test_new_with_mac_address() {
        let ip_address = IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap());
        let mac_address = MacAddress::from_slice(&[0, 1, 2, 3, 4, 5]).unwrap();

        let ip_gateway_info = IpGatewayInfo::new(ip_address, Some(mac_address));

        assert_eq!(
            ip_gateway_info,
            IpGatewayInfo {
                ip_address,
                hardware_address: MacAddress::from_slice(&[0, 1, 2, 3, 4, 5]).unwrap(),
            }
        );
    }

    // Test the IpGatewayInfo::new method with no MacAddress (default to zeros)
    #[test]
    fn test_new_without_mac_address() {
        let ip_address = IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap());

        let ip_gateway_info = IpGatewayInfo::new(ip_address, None);

        assert_eq!(
            ip_gateway_info,
            IpGatewayInfo {
                ip_address,
                hardware_address: MacAddress::from_slice(&[0; 6]).unwrap(),
            }
        );
    }
}
