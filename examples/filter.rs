/// This example demonstrates the basic usage of the `set_packet_filter_table` API, showcasing different filter scenarios:
///
/// 1. Redirect only DNS packets for user mode processing.
/// 2. Redirect only HTTP (TCP port 80) packets for user mode processing.
/// 3. Drop all ICMP packets and redirect all other packets to user mode (default behavior).
/// 4. Block access to http://www.ntkernel.com, while allowing all other packets to pass without user mode processing.
/// 5. Redirect only ARP/RARP packets to user mode, and pass all other packets without processing.
/// 6. Redirect only outgoing ICMP ping request packets to user mode. Pass all others.
use clap::Parser;
use ndisapi::{
    ByteRange, DataLinkLayerFilter, DataLinkLayerFilterUnion, DirectionFlags, Eth8023Filter,
    Eth802_3FilterFlags, EthRequest, EthRequestMut, FilterFlags, FilterLayerFlags, IcmpFilter,
    IcmpFilterFlags, IntermediateBuffer, IpAddressV4, IpAddressV4Union, IpAddressV6, IpSubnetV4,
    IpV4Filter, IpV4FilterFlags, IpV6Filter, IpV6FilterFlags, Ndisapi, NetworkLayerFilter,
    NetworkLayerFilterUnion, PortRange, StaticFilter, StaticFilterTable, TcpUdpFilter,
    TcpUdpFilterFlags, TransportLayerFilter, TransportLayerFilterUnion, ETHER_ADDR_LENGTH,
    ETH_802_3, FILTER_PACKET_DROP, FILTER_PACKET_PASS, FILTER_PACKET_REDIRECT, ICMP, IPV4, IPV6,
    IP_SUBNET_V4_TYPE, TCPUDP,
};
use smoltcp::wire::{
    ArpPacket, EthernetFrame, EthernetProtocol, Icmpv4Packet, Icmpv6Packet, IpProtocol, Ipv4Packet,
    Ipv6Packet, TcpPacket, UdpPacket,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use windows::{
    core::Result,
    Win32::Foundation::{CloseHandle, HANDLE},
    Win32::Networking::WinSock::{IN_ADDR, IN_ADDR_0, IN_ADDR_0_0},
    Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent, WaitForSingleObject},
};

#[derive(Parser)]
struct Cli {
    /// Network interface index (please use listadapters example to determine the right one)
    #[clap(short, long)]
    interface_index: usize,
    /// Filter set to apply the selected network interface. The following sets are supported:
    /// 1 - Redirect only IPv4 DNS packets for processing in user mode.
    /// 2 - Redirect only HTTP(TCP port 80) packets for processing in user mode. Both IPv4 and IPv6 protocols.
    /// 3 - Drop all IPv4 ICMP packets. Redirect all other packets to user mode (default behaviour).
    /// 4 - Block IPv4 access to https://www.ntkernel.com. Pass all other packets without processing in user mode.
    /// 5 - Redirect only ARP/RARP packets to user mode. Pass all others.
    /// 6 - Redirect only outgoing ICMP ping request packets to user mode. Pass all others.
    #[clap(short, long, verbatim_doc_comment)]
    filter: usize,
}

// Reverse Addr Res packet
const ETH_P_RARP: u16 = 0x8035;
// Address Resolution packet
const ETH_P_ARP: u16 = 0x0806;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

const DNS_PORT: u16 = 53;
const HTTP_PORT: u16 = 80;

/// Sets up a packet filter table for IPv4 DNS packets.
///
/// This function configures a packet filter table with three filters:
///
/// 1. Outgoing DNS requests filter: This filter redirects outgoing UDP packets with destination port 53 (DNS) for processing in user mode. It applies to all network adapters.
///
/// 2. Incoming DNS responses filter: This filter redirects incoming UDP packets with source port 53 (DNS) for processing in user mode. It applies to all network adapters.
///
/// 3. Default pass filter: This filter passes all packets that are not matched by the previous filters without processing in user mode. It applies to all network adapters.
///
/// After setting up the filter table, this function applies it to the network interface using the `set_packet_filter_table` method of the `Ndisapi` object.
///
/// # Arguments
///
/// * `ndisapi` - A reference to the `Ndisapi` object that represents the network interface.
///
/// # Returns
///
/// This function returns a `Result` that indicates whether the operation succeeded or failed. If the operation succeeded, the `Result` contains `()`. If the operation failed, the `Result` contains an error.
///
/// # Examples
///
///
fn load_ipv4_dns_filters(ndisapi: &Ndisapi) -> Result<()> {
    let filter_table = StaticFilterTable::<3>::from_filters([
        // 1. Outgoing DNS requests filter: REDIRECT OUT UDP packets with destination PORT 53
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV4,
                NetworkLayerFilterUnion {
                    ipv4: IpV4Filter::new(
                        IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                        IpAddressV4::default(),
                        IpAddressV4::default(),
                        IPPROTO_UDP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_DEST_PORT,
                        PortRange::default(),
                        PortRange::new(DNS_PORT, DNS_PORT),
                        0u8,
                    ),
                },
            ),
        ),
        // 2. Incoming DNS responses filter: REDIRECT IN UDP packets with source PORT 53
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV4,
                NetworkLayerFilterUnion {
                    ipv4: IpV4Filter::new(
                        IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                        IpAddressV4::default(),
                        IpAddressV4::default(),
                        IPPROTO_UDP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_SRC_PORT,
                        PortRange::new(DNS_PORT, DNS_PORT),
                        PortRange::default(),
                        0u8,
                    ),
                },
            ),
        ),
        // 3. Pass all packets (skipped by previous filters) without processing in user mode
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_PASS,
            FilterLayerFlags::empty(),
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::default(),
            TransportLayerFilter::default(),
        ),
    ]);

    ndisapi.set_packet_filter_table(&filter_table)
}

/// Sets up a packet filter table for HTTP packets over IPv4 and IPv6.
///
/// This function configures a packet filter table with five filters:
///
/// 1. Outgoing HTTP requests filter (IPv4): This filter redirects outgoing TCP packets with destination port 80 (HTTP) for processing in user mode. It applies to all network adapters.
///
/// 2. Incoming HTTP responses filter (IPv4): This filter redirects incoming TCP packets with source port 80 (HTTP) for processing in user mode. It applies to all network adapters.
///
/// 3. Outgoing HTTP requests filter (IPv6): This filter redirects outgoing TCP packets with destination port 80 (HTTP) for processing in user mode. It applies to all network adapters.
///
/// 4. Incoming HTTP responses filter (IPv6): This filter redirects incoming TCP packets with source port 80 (HTTP) for processing in user mode. It applies to all network adapters.
///
/// 5. Default pass filter: This filter passes all packets that are not matched by the previous filters without processing in user mode. It applies to all network adapters.
///
/// After setting up the filter table, this function applies it to the network interface using the `set_packet_filter_table` method of the `Ndisapi` object.
///
/// # Arguments
///
/// * `ndisapi` - A reference to the `Ndisapi` object that represents the network interface.
///
/// # Returns
///
/// This function returns a `Result` that indicates whether the operation succeeded or failed. If the operation succeeded, the `Result` contains `()`. If the operation failed, the `Result` contains an error.
///
/// # Examples
///
///
fn load_http_ipv4v6_filters(ndisapi: &Ndisapi) -> Result<()> {
    let filter_table = StaticFilterTable::<5>::from_filters([
        // 1. Outgoing HTTP requests filter: REDIRECT OUT TCP packets with destination PORT 80 IPv4
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV4,
                NetworkLayerFilterUnion {
                    ipv4: IpV4Filter::new(
                        IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                        IpAddressV4::default(),
                        IpAddressV4::default(),
                        IPPROTO_TCP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_DEST_PORT,
                        PortRange::default(),
                        PortRange::new(HTTP_PORT, HTTP_PORT),
                        0u8,
                    ),
                },
            ),
        ),
        // 2. Incoming HTTP responses filter: REDIRECT IN TCP packets with source PORT 80 IPv4
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV4,
                NetworkLayerFilterUnion {
                    ipv4: IpV4Filter::new(
                        IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                        IpAddressV4::default(),
                        IpAddressV4::default(),
                        IPPROTO_TCP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_SRC_PORT,
                        PortRange::new(HTTP_PORT, HTTP_PORT),
                        PortRange::default(),
                        0u8,
                    ),
                },
            ),
        ),
        // 3. Outgoing HTTP requests filter: REDIRECT OUT TCP packets with destination PORT 80 IPv6
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV6,
                NetworkLayerFilterUnion {
                    ipv6: IpV6Filter::new(
                        IpV6FilterFlags::IP_V6_FILTER_PROTOCOL,
                        IpAddressV6::default(),
                        IpAddressV6::default(),
                        IPPROTO_TCP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_DEST_PORT,
                        PortRange::default(),
                        PortRange::new(HTTP_PORT, HTTP_PORT),
                        0u8,
                    ),
                },
            ),
        ),
        // 4. Incoming HTTP responses filter: REDIRECT IN TCP packets with source PORT 80 IPv6
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV6,
                NetworkLayerFilterUnion {
                    ipv6: IpV6Filter::new(
                        IpV6FilterFlags::IP_V6_FILTER_PROTOCOL,
                        IpAddressV6::default(),
                        IpAddressV6::default(),
                        IPPROTO_TCP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_SRC_PORT,
                        PortRange::new(HTTP_PORT, HTTP_PORT),
                        PortRange::default(),
                        0u8,
                    ),
                },
            ),
        ),
        // 5. Pass all packets (skipped by previous filters) without processing in user mode
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_PASS,
            FilterLayerFlags::empty(),
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::default(),
            TransportLayerFilter::default(),
        ),
    ]);

    ndisapi.set_packet_filter_table(&filter_table)
}

/// Sets up a packet filter table to drop all ICMP packets.
///
/// This function configures a packet filter table with a single filter:
///
/// 1. Block all ICMP packets: This filter drops all ICMP packets, both incoming and outgoing. It applies to all network adapters.
///
/// After setting up the filter table, this function applies it to the network interface using the `set_packet_filter_table` method of the `Ndisapi` object.
///
/// # Arguments
///
/// * `ndisapi` - A reference to the `Ndisapi` object that represents the network interface.
///
/// # Returns
///
/// This function returns a `Result` that indicates whether the operation succeeded or failed. If the operation succeeded, the `Result` contains `()`. If the operation failed, the `Result` contains an error.
///
/// # Examples
///
///
fn load_icmpv4_drop_filters(ndisapi: &Ndisapi) -> Result<()> {
    let filter_table = StaticFilterTable::<1>::from_filters([
        // 1. Block all ICMP packets
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_SEND | DirectionFlags::PACKET_FLAG_ON_RECEIVE,
            FILTER_PACKET_DROP,
            FilterLayerFlags::NETWORK_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV4,
                NetworkLayerFilterUnion {
                    ipv4: IpV4Filter::new(
                        IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                        IpAddressV4::default(),
                        IpAddressV4::default(),
                        IPPROTO_ICMP,
                    ),
                },
            ),
            TransportLayerFilter::default(),
        ),
    ]);

    ndisapi.set_packet_filter_table(&filter_table)
}

/// Sets up a packet filter table to block access to https://www.ntkernel.com over IPv4.
///
/// This function configures a packet filter table with two filters:
///
/// 1. Outgoing HTTP requests filter: This filter drops outgoing TCP packets with destination IP 95.179.146.125 and destination port 443 (https://www.ntkernel.com). It applies to all network adapters.
///
/// 2. Default pass filter: This filter passes all packets that are not matched by the previous filter without processing in user mode. It applies to all network adapters.
///
/// After setting up the filter table, this function applies it to the network interface using the `set_packet_filter_table` method of the `Ndisapi` object.
///
/// # Arguments
///
/// * `ndisapi` - A reference to the `Ndisapi` object that represents the network interface.
///
/// # Returns
///
/// This function returns a `Result` that indicates whether the operation succeeded or failed. If the operation succeeded, the `Result` contains `()`. If the operation failed, the `Result` contains an error.
///
/// # Examples
///
///
fn load_block_ntkernel_https_filters(ndisapi: &Ndisapi) -> Result<()> {
    let filter_table = StaticFilterTable::<2>::from_filters([
        // 1. Outgoing HTTP requests filter: DROP OUT TCP packets with destination IP 95.179.146.125 PORT 443 (https://www.ntkernel.com)
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_DROP,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV4,
                NetworkLayerFilterUnion {
                    ipv4: IpV4Filter::new(
                        IpV4FilterFlags::IP_V4_FILTER_PROTOCOL
                            | IpV4FilterFlags::IP_V4_FILTER_DEST_ADDRESS,
                        IpAddressV4::new(
                            IP_SUBNET_V4_TYPE,
                            IpAddressV4Union {
                                ip_subnet: IpSubnetV4::new(
                                    IN_ADDR {
                                        S_un: IN_ADDR_0 {
                                            S_un_b: IN_ADDR_0_0 {
                                                s_b1: 95,
                                                s_b2: 179,
                                                s_b3: 146,
                                                s_b4: 125,
                                            },
                                        },
                                    },
                                    IN_ADDR {
                                        S_un: IN_ADDR_0 {
                                            S_un_b: IN_ADDR_0_0 {
                                                s_b1: 255,
                                                s_b2: 255,
                                                s_b3: 255,
                                                s_b4: 255,
                                            },
                                        },
                                    },
                                ),
                            },
                        ),
                        IpAddressV4::default(),
                        IPPROTO_TCP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                TCPUDP,
                TransportLayerFilterUnion {
                    tcp_udp: TcpUdpFilter::new(
                        TcpUdpFilterFlags::TCPUDP_DEST_PORT,
                        PortRange::default(),
                        PortRange::new(443, 443),
                        0u8,
                    ),
                },
            ),
        ),
        // 2. Pass all packets (skipped by previous filters) without processing in user mode
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_PASS,
            FilterLayerFlags::empty(),
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::default(),
            TransportLayerFilter::default(),
        ),
    ]);

    ndisapi.set_packet_filter_table(&filter_table)
}

/// Sets up a packet filter table to redirect ARP and RARP packets for user mode processing.
///
/// This function configures a packet filter table with three filters:
///
/// 1. ARP packets filter: This filter redirects all ARP packets for processing in user mode. It applies to all network adapters.
///
/// 2. RARP packets filter: This filter redirects all RARP packets for processing in user mode. It applies to all network adapters.
///
/// 3. Default pass filter: This filter passes all packets that are not matched by the previous filters without processing in user mode. It applies to all network adapters.
///
/// After setting up the filter table, this function applies it to the network interface using the `set_packet_filter_table` method of the `Ndisapi` object.
///
/// # Arguments
///
/// * `ndisapi` - A reference to the `Ndisapi` object that represents the network interface.
///
/// # Returns
///
/// This function returns a `Result` that indicates whether the operation succeeded or failed. If the operation succeeded, the `Result` contains `()`. If the operation failed, the `Result` contains an error.
///
/// # Examples
///
///
fn load_redirect_arp_filters(ndisapi: &Ndisapi) -> Result<()> {
    let filter_table = StaticFilterTable::<3>::from_filters([
        // 1. Redirects all ARP packets to be processed by user mode application
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_SEND_RECEIVE,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::DATA_LINK_LAYER_VALID,
            DataLinkLayerFilter::new(
                ETH_802_3,
                DataLinkLayerFilterUnion {
                    eth_8023_filter: Eth8023Filter::new(
                        Eth802_3FilterFlags::ETH_802_3_PROTOCOL,
                        [0; ETHER_ADDR_LENGTH],
                        [0; ETHER_ADDR_LENGTH],
                        ETH_P_ARP,
                    ),
                },
            ),
            NetworkLayerFilter::default(),
            TransportLayerFilter::default(),
        ),
        // 2. Redirects all RARP packets to be processed by user mode application
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_SEND_RECEIVE,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::DATA_LINK_LAYER_VALID,
            DataLinkLayerFilter::new(
                ETH_802_3,
                DataLinkLayerFilterUnion {
                    eth_8023_filter: Eth8023Filter::new(
                        Eth802_3FilterFlags::ETH_802_3_PROTOCOL,
                        [0; ETHER_ADDR_LENGTH],
                        [0; ETHER_ADDR_LENGTH],
                        ETH_P_RARP,
                    ),
                },
            ),
            NetworkLayerFilter::default(),
            TransportLayerFilter::default(),
        ),
        // 3. Pass all packets (skipped by previous filters) without processing in user mode
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_PASS,
            FilterLayerFlags::empty(),
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::default(),
            TransportLayerFilter::default(),
        ),
    ]);

    ndisapi.set_packet_filter_table(&filter_table)
}

/// Sets up a packet filter table to redirect outgoing ICMP ping request packets for user mode processing.
///
/// This function configures a packet filter table with two filters:
///
/// 1. Outgoing ICMP ping requests filter: This filter redirects outgoing ICMP ping request packets for processing in user mode. It applies to all network adapters.
///
/// 2. Default pass filter: This filter passes all packets that are not matched by the previous filter without processing in user mode. It applies to all network adapters.
///
/// After setting up the filter table, this function applies it to the network interface using the `set_packet_filter_table` method of the `Ndisapi` object.
///
/// # Arguments
///
/// * `ndisapi` - A reference to the `Ndisapi` object that represents the network interface.
///
/// # Returns
///
/// This function returns a `Result` that indicates whether the operation succeeded or failed. If the operation succeeded, the `Result` contains `()`. If the operation failed, the `Result` contains an error.
///
/// # Examples
///
///
fn load_redirect_icmp_req_filters(ndisapi: &Ndisapi) -> Result<()> {
    let filter_table = StaticFilterTable::<2>::from_filters([
        // 1. Redirects all outgoing ICMP ping request packets to be processed by user mode application
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(
                IPV4,
                NetworkLayerFilterUnion {
                    ipv4: IpV4Filter::new(
                        IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                        IpAddressV4::default(),
                        IpAddressV4::default(),
                        IPPROTO_ICMP,
                    ),
                },
            ),
            TransportLayerFilter::new(
                ICMP,
                TransportLayerFilterUnion {
                    icmp: IcmpFilter::new(
                        IcmpFilterFlags::ICMP_TYPE,
                        ByteRange::new(8, 8),
                        ByteRange::default(),
                    ),
                },
            ),
        ),
        // 2. Pass all packets (skipped by previous filters) without processing in user mode
        StaticFilter::new(
            0, // applied to all adapters
            DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_PASS,
            FilterLayerFlags::empty(),
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::default(),
            TransportLayerFilter::default(),
        ),
    ]);

    ndisapi.set_packet_filter_table(&filter_table)
}

/// Entry point of the application.
///
/// This function parses the command line arguments, initializes the Ndisapi driver, sets up the packet filter table based on the selected filter set, and starts the packet processing loop.
///
/// The packet processing loop reads packets from the network interface, prints some information about each packet, and then re-injects the packets back into the network stack.
///
/// The loop continues until the user presses Ctrl-C.
///
/// # Arguments
///
/// None.
///
/// # Returns
///
/// This function returns a `Result` that indicates whether the operation succeeded or failed. If the operation succeeded, the `Result` contains `()`. If the operation failed, the `Result` contains an error.
///
/// # Examples
///
///
fn main() -> Result<()> {
    // Parse command line arguments
    let Cli {
        mut interface_index,
        filter,
    } = Cli::parse();

    // Adjust the interface index to be zero-based
    interface_index -= 1;

    // Initialize the Ndisapi driver
    let driver =
        Ndisapi::new("NDISRD").expect("WinpkFilter driver is not installed or failed to load!");

    // Print the version of the WinpkFilter driver
    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    // Get the list of network interfaces that are bound to TCP/IP
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    // Check if the selected interface index is valid
    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beyond the number of available interfaces");
    }

    // Print the name of the selected network interface
    println!("Using interface {}s", adapters[interface_index].get_name());

    // Set up the packet filter table based on the selected filter set
    let filter_set_result = match filter {
        1 => load_ipv4_dns_filters(&driver),
        2 => load_http_ipv4v6_filters(&driver),
        3 => load_icmpv4_drop_filters(&driver),
        4 => load_block_ntkernel_https_filters(&driver),
        5 => load_redirect_arp_filters(&driver),
        6 => load_redirect_icmp_req_filters(&driver),
        _ => panic!("Filter set is not available"),
    };

    // Check if the packet filter table was set up successfully
    match filter_set_result {
        Ok(_) => println!("Successfully loaded static filters into the driver."),
        Err(err) => panic!("Failed to load static filter into the driver. Error code: {err}"),
    }

    // Create a Win32 event for packet arrival notification
    let event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?;
    }

    // Set up a Ctrl-C handler to terminate the packet processing loop
    let terminate: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let ctrlc_pressed = terminate.clone();
    ctrlc::set_handler(move || {
        println!("Ctrl-C was pressed. Terminating...");
        // Set the atomic flag to exit the loop
        ctrlc_pressed.store(true, Ordering::SeqCst);
        // Signal the event to release the loop if there are no packets in the queue
        let _ = unsafe { SetEvent(event) };
    })
    .expect("Error setting Ctrl-C handler");

    // Set the event within the driver for packet arrival notification
    driver.set_packet_event(adapters[interface_index].get_handle(), event)?;

    // Put the network interface into tunnel mode
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
    )?;

    // Allocate a single IntermediateBuffer on the stack for packet reading
    let mut packet = IntermediateBuffer::default();

    // Start the packet processing loop
    while !terminate.load(Ordering::SeqCst) {
        // Wait for a packet to arrive
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }
        loop {
            // Initialize an EthRequestMut to pass to the driver API
            let mut read_request = EthRequestMut::new(adapters[interface_index].get_handle());

            // Set the packet buffer
            read_request.set_packet(&mut packet);

            // Read a packet from the network interface
            if driver.read_packet(&mut read_request).ok().is_none() {
                // No more packets in the queue, break the loop
                break;
            }

            // Get the direction of the packet
            let direction_flags = packet.get_device_flags();

            // Print packet information
            if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                println!("\nMSTCP --> Interface ({} bytes)\n", packet.get_length());
            } else {
                println!("\nInterface --> MSTCP ({} bytes)\n", packet.get_length());
            }

            // Print some information about the packet
            print_packet_info(&packet);

            // Initialize an EthRequest to pass to the driver API
            let mut write_request = EthRequest::new(adapters[interface_index].get_handle());

            // Set the packet buffer
            write_request.set_packet(&packet);

            // Re-inject the packet back into the network stack
            if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                // Send the packet to the network interface
                match driver.send_packet_to_adapter(&write_request) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
                };
            } else {
                // Send the packet to the TCP/IP stack
                match driver.send_packet_to_mstcp(&write_request) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
                }
            }
        }

        // Reset the event to continue waiting for packets to arrive
        let _ = unsafe { ResetEvent(event) };
    }

    // Put the network interface back into default mode
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::default(),
    )?;

    // Close the event handle
    let _ = unsafe { CloseHandle(event) };

    // Return success
    Ok(())
}

/// Print detailed information about a network packet.
///
/// This function takes an `IntermediateBuffer` containing a network packet and prints various
/// details about the packet, such as Ethernet, IPv4, IPv6, ICMPv4, ICMPv6, UDP, and TCP information.
///
/// # Arguments
///
/// * `packet` - A reference to an `IntermediateBuffer` containing the network packet.
///
/// # Examples
///
/// ```no_run
/// let packet: IntermediateBuffer = ...;
/// print_packet_info(&packet);
/// ```
fn print_packet_info(packet: &IntermediateBuffer) {
    let eth_hdr = EthernetFrame::new_unchecked(packet.get_data());
    match eth_hdr.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new_unchecked(eth_hdr.payload());
            println!(
                "  Ipv4 {:?} => {:?}",
                ipv4_packet.src_addr(),
                ipv4_packet.dst_addr()
            );
            match ipv4_packet.next_header() {
                IpProtocol::Icmp => {
                    let icmp_packet = Icmpv4Packet::new_unchecked(ipv4_packet.payload());
                    println!(
                        "ICMPv4: Type: {:?} Code: {:?}",
                        icmp_packet.msg_type(),
                        icmp_packet.msg_code()
                    );
                }
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
                    println!(
                        "   TCP {:?} -> {:?}",
                        tcp_packet.src_port(),
                        tcp_packet.dst_port()
                    );
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
                    println!(
                        "   UDP {:?} -> {:?}",
                        udp_packet.src_port(),
                        udp_packet.dst_port()
                    );
                }
                _ => {
                    println!("Unknown IPv4 packet: {:?}", ipv4_packet);
                }
            }
        }
        EthernetProtocol::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new_unchecked(eth_hdr.payload());
            println!(
                "  Ipv6 {:?} => {:?}",
                ipv6_packet.src_addr(),
                ipv6_packet.dst_addr()
            );
            match ipv6_packet.next_header() {
                IpProtocol::Icmpv6 => {
                    let icmpv6_packet = Icmpv6Packet::new_unchecked(ipv6_packet.payload());
                    println!(
                        "ICMPv6 packet: Type: {:?} Code: {:?}",
                        icmpv6_packet.msg_type(),
                        icmpv6_packet.msg_code()
                    );
                }
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv6_packet.payload());
                    println!(
                        "   TCP {:?} -> {:?}",
                        tcp_packet.src_port(),
                        tcp_packet.dst_port()
                    );
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv6_packet.payload());
                    println!(
                        "   UDP {:?} -> {:?}",
                        udp_packet.src_port(),
                        udp_packet.dst_port()
                    );
                }
                _ => {
                    println!("Unknown IPv6 packet: {:?}", ipv6_packet);
                }
            }
        }
        EthernetProtocol::Arp => {
            let arp_packet = ArpPacket::new_unchecked(eth_hdr.payload());
            println!("ARP packet: {:?}", arp_packet);
        }
        EthernetProtocol::Unknown(_) => {
            println!("Unknown Ethernet packet: {:?}", eth_hdr);
        }
    }
}
