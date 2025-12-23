//! This module provides a convenient way to work with IP endpoints in the Windows environment.
//! It defines an `SockAddrStorage` struct which can be constructed from various socket address types
//! provided by the Windows API and can be converted to `std::net::SocketAddr`.
//!
//! # Examples
//!
//! ```
//! use ndisapi::SockAddrStorage;
//! use std::net::Ipv4Addr;
//!
//! let ipv4_addr = Ipv4Addr::new(192, 168, 0, 1);
//! let ip_info = SockAddrStorage::from_ipv4_addr(ipv4_addr);
//! let socket_addr = ip_info.to_socket_addr().unwrap();
//! assert_eq!(socket_addr.ip(), ipv4_addr);
//! ```

use std::mem::MaybeUninit;
use std::{
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_STORAGE,
};

/// The `SockAddrStorage` struct represents a socket address for IPv4 or IPv6 addresses.
/// It can be created from various Windows socket address types and can be converted
/// to a `std::net::SocketAddr`.
#[derive(Clone, Copy, Debug)]
pub struct SockAddrStorage(pub SOCKADDR_STORAGE);

impl PartialEq for SockAddrStorage {
    fn eq(&self, other: &Self) -> bool {
        // Compare based on the socket address contents
        if self.0.ss_family != other.0.ss_family {
            return false;
        }

        match self.0.ss_family {
            AF_INET => {
                let self_addr: &SOCKADDR_IN = unsafe { &*(self as *const _ as *const SOCKADDR_IN) };
                let other_addr: &SOCKADDR_IN =
                    unsafe { &*(other as *const _ as *const SOCKADDR_IN) };
                unsafe {
                    self_addr.sin_port == other_addr.sin_port
                        && self_addr.sin_addr.S_un.S_addr == other_addr.sin_addr.S_un.S_addr
                }
            }
            AF_INET6 => {
                let self_addr: &SOCKADDR_IN6 =
                    unsafe { &*(self as *const _ as *const SOCKADDR_IN6) };
                let other_addr: &SOCKADDR_IN6 =
                    unsafe { &*(other as *const _ as *const SOCKADDR_IN6) };
                unsafe {
                    self_addr.sin6_port == other_addr.sin6_port
                        && self_addr.sin6_addr.u.Byte == other_addr.sin6_addr.u.Byte
                        && self_addr.sin6_flowinfo == other_addr.sin6_flowinfo
                        && self_addr.Anonymous.sin6_scope_id == other_addr.Anonymous.sin6_scope_id
                }
            }
            _ => {
                // For unknown address families, compare the raw bytes
                unsafe {
                    std::slice::from_raw_parts(
                        self as *const _ as *const u8,
                        std::mem::size_of::<SOCKADDR_STORAGE>(),
                    ) == std::slice::from_raw_parts(
                        other as *const _ as *const u8,
                        std::mem::size_of::<SOCKADDR_STORAGE>(),
                    )
                }
            }
        }
    }
}

impl Eq for SockAddrStorage {}

impl SockAddrStorage {
    /// Constructs a new `SockAddrStorage` with all fields set to zero.
    pub fn new() -> Self {
        SockAddrStorage(unsafe { std::mem::zeroed() })
    }

    /// Constructs a new `SockAddrStorage` instance from a string representation of an IPv4 or IPv6 address.
    ///
    /// # Arguments
    ///
    /// * `ip_address` - A string representation of an IPv4 or IPv6 address.
    ///
    /// # Returns
    ///
    /// A `Result` containing a new `SockAddrStorage` instance, or an error if the input string is not a valid IP address.
    pub fn from_ip_string(ip_address: &str) -> Result<Self, std::net::AddrParseError> {
        let ip_addr: IpAddr = ip_address.parse()?;
        let socket_addr = SocketAddr::new(ip_addr, 0);
        let sockaddr_storage = Self::socket_addr_to_sockaddr_storage(&socket_addr);

        Ok(Self(sockaddr_storage))
    }

    /// Converts a `SocketAddr` to a `SOCKADDR_STORAGE` structure.
    ///
    /// # Arguments
    ///
    /// * `socket_addr` - A `SocketAddr` reference.
    ///
    /// # Returns
    ///
    /// A `SOCKADDR_STORAGE` structure.
    fn socket_addr_to_sockaddr_storage(socket_addr: &SocketAddr) -> SOCKADDR_STORAGE {
        let mut sockaddr_storage: SOCKADDR_STORAGE = unsafe { mem::zeroed() };

        match socket_addr {
            SocketAddr::V4(addr_v4) => {
                let ipv4_addr: Ipv4Addr = *addr_v4.ip();
                let sockaddr_in: SOCKADDR_IN = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from(ipv4_addr).to_le(),
                        },
                    },
                    sin_zero: [0; 8],
                };

                unsafe {
                    *(&mut sockaddr_storage as *mut _ as *mut SOCKADDR_IN) = sockaddr_in;
                }
            }
            SocketAddr::V6(addr_v6) => {
                let ipv6_addr: Ipv6Addr = *addr_v6.ip();
                let sockaddr_in6: SOCKADDR_IN6 = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: 0,
                    sin6_flowinfo: addr_v6.flowinfo(),
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: ipv6_addr.octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 {
                        sin6_scope_id: addr_v6.scope_id(),
                    },
                };

                unsafe {
                    *(&mut sockaddr_storage as *mut _ as *mut SOCKADDR_IN6) = sockaddr_in6;
                }
            }
        }

        sockaddr_storage
    }

    /// Constructs a new `SockAddrStorage` from a `SOCKADDR` struct.
    ///
    /// # Safety
    ///
    /// This function uses `MaybeUninit` to safely create an uninitialized
    /// `SOCKADDR_STORAGE` instance, and then it copies the `SOCKADDR` contents
    /// into the `SOCKADDR_STORAGE` without overlapping.
    /// Before constructing the `SockAddrStorage`, it ensures that the contents
    /// are valid using the `assume_init()` method.
    pub fn from_sockaddr(address: SOCKADDR) -> Self {
        // Create a `MaybeUninit` instance for `SOCKADDR_STORAGE`.
        let mut storage: MaybeUninit<SOCKADDR_STORAGE> = MaybeUninit::uninit();

        // Get pointers to the `SOCKADDR` and `SOCKADDR_STORAGE` instances.
        let src_ptr = &address as *const _ as *const u8;
        let dst_ptr = storage.as_mut_ptr() as *mut u8;

        // Copy the `SOCKADDR` contents into the `SOCKADDR_STORAGE` without overlapping.
        // # Safety: The source and destination pointers are non-overlapping, and
        // the size of the `SOCKADDR` struct is known at compile-time.
        unsafe {
            std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, std::mem::size_of::<SOCKADDR>());
        }

        // Ensure that the contents are valid before constructing the `SockAddrStorage`.
        // # Safety: `storage` has been properly initialized by the `copy_nonoverlapping`
        // function above, so it's safe to call `assume_init()`.
        let storage = unsafe { storage.assume_init() };

        SockAddrStorage(storage)
    }

    /// Constructs a new `SockAddrStorage` from a `SOCKADDR_IN` struct.
    ///
    /// # Safety
    ///
    /// This function uses `MaybeUninit` to safely create an uninitialized
    /// `SOCKADDR_STORAGE` instance, and then it copies the `SOCKADDR_IN` contents
    /// into the `SOCKADDR_STORAGE` without overlapping.
    /// Before constructing the `SockAddrStorage`, it ensures that the contents
    /// are valid using the `assume_init()` method.
    pub fn from_sockaddr_in(address: SOCKADDR_IN) -> Self {
        // Create a `MaybeUninit` instance for `SOCKADDR_STORAGE`.
        let mut storage: MaybeUninit<SOCKADDR_STORAGE> = MaybeUninit::uninit();

        // Get pointers to the `SOCKADDR_IN` and `SOCKADDR_STORAGE` instances.
        let src_ptr = &address as *const _ as *const u8;
        let dst_ptr = storage.as_mut_ptr() as *mut u8;

        // Copy the `SOCKADDR_IN` contents into the `SOCKADDR_STORAGE` without overlapping.
        // # Safety: The source and destination pointers are non-overlapping, and
        // the size of the `SOCKADDR_IN` struct is known at compile-time.
        unsafe {
            std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, std::mem::size_of::<SOCKADDR_IN>());
        }

        // Ensure that the contents are valid before constructing the `SockAddrStorage`.
        // # Safety: `storage` has been properly initialized by the `copy_nonoverlapping`
        // function above, so it's safe to call `assume_init()`.
        let storage = unsafe { storage.assume_init() };

        SockAddrStorage(storage)
    }

    /// Constructs a new `SockAddrStorage` from a `SOCKADDR_IN6` struct.
    ///
    /// # Safety
    ///
    /// This function uses `MaybeUninit` to safely create an uninitialized
    /// `SOCKADDR_STORAGE` instance, and then it copies the `SOCKADDR_IN6` contents
    /// into the `SOCKADDR_STORAGE` without overlapping.
    /// Before constructing the `SockAddrStorage`, it ensures that the contents
    /// are valid using the `assume_init()` method.
    pub fn from_sockaddr_in6(address: SOCKADDR_IN6) -> Self {
        // Create a `MaybeUninit` instance for `SOCKADDR_STORAGE`.
        let mut storage: MaybeUninit<SOCKADDR_STORAGE> = MaybeUninit::uninit();

        // Get pointers to the `SOCKADDR_IN6` and `SOCKADDR_STORAGE` instances.
        let src_ptr = &address as *const _ as *const u8;
        let dst_ptr = storage.as_mut_ptr() as *mut u8;

        // Copy the `SOCKADDR_IN6` contents into the `SOCKADDR_STORAGE` without overlapping.
        // # Safety: The source and destination pointers are non-overlapping, and
        // the size of the `SOCKADDR_IN6` struct is known at compile-time.
        unsafe {
            std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, std::mem::size_of::<SOCKADDR_IN6>());
        }

        // Ensure that the contents are valid before constructing the `SockAddrStorage`.
        // # Safety: `storage` has been properly initialized by the `copy_nonoverlapping`
        // function above, so it's safe to call `assume_init()`.
        let storage = unsafe { storage.assume_init() };

        SockAddrStorage(storage)
    }

    /// Constructs a new `SockAddrStorage` from an `Ipv4Addr` object.
    pub fn from_ipv4_addr(address: Ipv4Addr) -> Self {
        let in_addr = IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from(address).to_be(),
            },
        };
        let sockaddr = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: in_addr,
            sin_zero: [0; 8],
        };
        SockAddrStorage::from_sockaddr_in(sockaddr)
    }

    /// Constructs a new `SockAddrStorage` from an `Ipv6Addr` object.
    pub fn from_ipv6_addr(address: Ipv6Addr) -> Self {
        let in6_addr = IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: address.octets(),
            },
        };
        let sockaddr = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: in6_addr,
            Anonymous: SOCKADDR_IN6_0 {
                sin6_scope_id: 0u32,
            },
        };
        SockAddrStorage::from_sockaddr_in6(sockaddr)
    }

    /// Converts the `SockAddrStorage` to a `std::net::SocketAddr` if it contains a valid IPv4 or IPv6 address.
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self.0.ss_family {
            AF_INET => {
                let addr_in: &SOCKADDR_IN = unsafe { &*(self as *const _ as *const SOCKADDR_IN) };
                let ip = Ipv4Addr::from(unsafe { addr_in.sin_addr.S_un.S_addr.to_be() });
                let port = u16::from_be(addr_in.sin_port);
                Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            AF_INET6 => {
                let addr_in6: &SOCKADDR_IN6 =
                    unsafe { &*(self as *const _ as *const SOCKADDR_IN6) };
                let ip = Ipv6Addr::from(unsafe { addr_in6.sin6_addr.u.Byte });
                let port = u16::from_be(addr_in6.sin6_port);
                let flowinfo = addr_in6.sin6_flowinfo;
                let scope_id = unsafe { addr_in6.Anonymous.sin6_scope_id };
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip, port, flowinfo, scope_id,
                )))
            }
            _ => None,
        }
    }

    /// Converts the `SockAddrStorage` to a `String` representation of the IP address and port.
    pub fn to_string(&self) -> Option<String> {
        self.to_socket_addr()
            .map(|socket_addr| socket_addr.to_string())
    }

    /// Converts the `SockAddrStorage` to a wide `String` representation of the IP address and port.
    pub fn to_wide_string(&self) -> Option<String> {
        self.to_socket_addr().map(|socket_addr| {
            let socket_addr_str = socket_addr.to_string();
            let wide_socket_addr_str: Vec<u16> = socket_addr_str.encode_utf16().collect();
            String::from_utf16_lossy(&wide_socket_addr_str)
        })
    }
}

// This block of code defines a default implementation for the SockAddrStorage struct.
// It returns an instance of Self by calling the new method which is also part of the SockAddrStorage struct.
impl Default for SockAddrStorage {
    // This function specifies the behaviour of the default method.
    // In this case, it simply returns an instance of Self by invoking the new method.
    fn default() -> Self {
        Self::new()
    }
}

// Implement the `From` trait to convert an `SockAddrStorage` instance into an `IpAddr`.
impl From<SockAddrStorage> for IpAddr {
    fn from(ip_address_info: SockAddrStorage) -> Self {
        // Extract the `SOCKADDR_STORAGE` from the `SockAddrStorage`.
        let sockaddr_storage = ip_address_info.0;
        // Get the address family (IPv4 or IPv6) as a `c_short`.
        let addr_family = sockaddr_storage.ss_family;

        // Match the address family to determine whether it's an IPv4 or IPv6 address.
        match addr_family {
            // For IPv4 addresses:
            AF_INET => {
                // Cast the `SOCKADDR_STORAGE` as a `SOCKADDR_IN` (IPv4) structure.
                let sockaddr_in: SOCKADDR_IN =
                    unsafe { std::ptr::read(&sockaddr_storage as *const _ as *const SOCKADDR_IN) };
                // Extract the IPv4 address from the `SOCKADDR_IN` structure and convert it to an `Ipv4Addr`.
                let ipv4_address =
                    Ipv4Addr::from(unsafe { sockaddr_in.sin_addr.S_un.S_addr.to_be() });
                // Return the `IpAddr` variant for IPv4 addresses.
                IpAddr::V4(ipv4_address)
            }
            // For IPv6 addresses:
            AF_INET6 => {
                // Cast the `SOCKADDR_STORAGE` as a `SOCKADDR_IN6` (IPv6) structure.
                let sockaddr_in6: SOCKADDR_IN6 =
                    unsafe { std::ptr::read(&sockaddr_storage as *const _ as *const SOCKADDR_IN6) };
                // Extract the IPv6 address from the `SOCKADDR_IN6` structure and convert it to an `Ipv6Addr`.
                let ipv6_address = Ipv6Addr::from(unsafe { sockaddr_in6.sin6_addr.u.Byte });
                // Return the `IpAddr` variant for IPv6 addresses.
                IpAddr::V6(ipv6_address)
            }
            // If the address family is not supported, panic.
            _ => panic!("Unsupported address family"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Networking::WinSock::ADDRESS_FAMILY;

    #[test]
    fn test_new() {
        let ip_address_info = SockAddrStorage::new();
        assert_eq!(ip_address_info.0.ss_family, ADDRESS_FAMILY(0));
    }

    #[test]
    fn test_from_sockaddr() {
        let ipv4_addr = Ipv4Addr::new(127, 0, 0, 1);
        let sockaddr = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from(ipv4_addr).to_be(),
                },
            },
            sin_zero: [0; 8],
        };
        let sockaddr = unsafe { std::mem::transmute::<SOCKADDR_IN, SOCKADDR>(sockaddr) };
        let ip_address_info = SockAddrStorage::from_sockaddr(sockaddr);

        assert_eq!(ip_address_info.0.ss_family, AF_INET);
    }

    #[test]
    fn test_from_sockaddr_in() {
        let ipv4_addr = Ipv4Addr::new(127, 0, 0, 1);
        let sockaddr = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from(ipv4_addr).to_be(),
                },
            },
            sin_zero: [0; 8],
        };
        let ip_address_info = SockAddrStorage::from_sockaddr_in(sockaddr);

        assert_eq!(ip_address_info.0.ss_family, AF_INET);
    }

    #[test]
    fn test_from_sockaddr_in6() {
        let ipv6_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let sockaddr = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: ipv6_addr.octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 {
                sin6_scope_id: 0u32,
            },
        };
        let ip_address_info = SockAddrStorage::from_sockaddr_in6(sockaddr);

        assert_eq!(ip_address_info.0.ss_family, AF_INET6);
    }

    #[test]
    fn test_from_ipv4_addr() {
        let ipv4_addr = Ipv4Addr::new(127, 0, 0, 1);
        let ip_address_info = SockAddrStorage::from_ipv4_addr(ipv4_addr);

        match ip_address_info.to_socket_addr().unwrap() {
            SocketAddr::V4(socket_addr_v4) => {
                assert_eq!(*socket_addr_v4.ip(), ipv4_addr);
                assert_eq!(socket_addr_v4.port(), 0);
            }
            _ => panic!("Expected SocketAddr::V4"),
        }
    }

    #[test]
    fn test_from_ipv6_addr() {
        let ipv6_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let ip_address_info = SockAddrStorage::from_ipv6_addr(ipv6_addr);

        match ip_address_info.to_socket_addr().unwrap() {
            SocketAddr::V6(socket_addr_v6) => {
                assert_eq!(*socket_addr_v6.ip(), ipv6_addr);
                assert_eq!(socket_addr_v6.port(), 0);
                assert_eq!(socket_addr_v6.flowinfo(), 0);
                assert_eq!(socket_addr_v6.scope_id(), 0);
            }
            _ => panic!("Expected SocketAddr::V6"),
        }
    }

    #[test]
    fn test_to_socket_addr() {
        let ipv4_addr = Ipv4Addr::new(127, 0, 0, 1);
        let ip_address_info = SockAddrStorage::from_ipv4_addr(ipv4_addr);
        let socket_addr = ip_address_info.to_socket_addr().unwrap();
        assert_eq!(socket_addr, SocketAddr::V4(SocketAddrV4::new(ipv4_addr, 0)));

        let ipv6_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let ip_address_info = SockAddrStorage::from_ipv6_addr(ipv6_addr);
        let socket_addr = ip_address_info.to_socket_addr().unwrap();
        assert_eq!(
            socket_addr,
            SocketAddr::V6(SocketAddrV6::new(ipv6_addr, 0, 0, 0))
        );
    }

    #[test]
    fn test_to_string() {
        let ipv4_addr = Ipv4Addr::new(127, 0, 0, 1);
        let ip_address_info = SockAddrStorage::from_ipv4_addr(ipv4_addr);
        let ip_string = ip_address_info.to_string().unwrap();
        assert_eq!(ip_string, "127.0.0.1:0");

        let ipv6_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let ip_address_info = SockAddrStorage::from_ipv6_addr(ipv6_addr);
        let ip_string = ip_address_info.to_string().unwrap();
        assert_eq!(ip_string, "[::1]:0");
    }

    #[test]
    fn test_to_wide_string() {
        let ipv4_addr = Ipv4Addr::new(127, 0, 0, 1);
        let ip_address_info = SockAddrStorage::from_ipv4_addr(ipv4_addr);
        let ip_wide_string = ip_address_info.to_wide_string().unwrap();
        assert_eq!(ip_wide_string, "127.0.0.1:0");

        let ipv6_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let ip_address_info = SockAddrStorage::from_ipv6_addr(ipv6_addr);
        let ip_wide_string = ip_address_info.to_wide_string().unwrap();
        assert_eq!(ip_wide_string, "[::1]:0");
    }

    #[test]
    fn test_ip_address_info_to_ip_addr() {
        // Test IPv4 address conversion
        let ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let sockaddr_in = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: unsafe { mem::transmute(ipv4) },
            sin_zero: [0; 8],
        };
        let ip_address_info = SockAddrStorage::from_sockaddr_in(sockaddr_in);
        let ip_addr: IpAddr = ip_address_info.into();
        assert_eq!(ip_addr, IpAddr::V4(ipv4));

        // Test IPv6 address conversion
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let sockaddr_in6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: unsafe { mem::transmute(ipv6) },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        };
        let ip_address_info = SockAddrStorage::from_sockaddr_in6(sockaddr_in6);
        let ip_addr: IpAddr = ip_address_info.into();
        assert_eq!(ip_addr, IpAddr::V6(ipv6));
    }
}
