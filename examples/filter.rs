use clap::Parser;
use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, *};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use windows::{
    core::Result,
    Win32::Foundation::HANDLE,
    Win32::Networking::WinSock::{IN_ADDR, IN_ADDR_0, IN_ADDR_0_0},
    Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject},
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

fn load_ipv4_dns_filters(ndisapi: &ndisapi::Ndisapi) -> Result<()> {
    let mut filter_table = ndisapi::StaticFilterTable::<3>::default();
    //**************************************************************************************
    // 1. Outgoing DNS requests filter: REDIRECT OUT UDP packets with destination PORT 53
    // Common values
    filter_table.static_filters[0].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[0].valid_fields = ndisapi::FilterLayerFlags::NETWORK_LAYER_VALID
        | ndisapi::FilterLayerFlags::TRANSPORT_LAYER_VALID;
    filter_table.static_filters[0].filter_action = ndisapi::FILTER_PACKET_REDIRECT;
    filter_table.static_filters[0].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND;

    // Network layer filter
    filter_table.static_filters[0].network_filter.union_selector = ndisapi::IPV4;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .valid_fields = ndisapi::IpV4FilterFlags::IP_V4_FILTER_PROTOCOL;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .protocol = IPPROTO_UDP;

    // Transport layer filter
    filter_table.static_filters[0]
        .transport_filter
        .union_selector = ndisapi::TCPUDP;
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .tcp_udp
        .valid_fields = ndisapi::TcpUdpFilterFlags::TCPUDP_DEST_PORT;
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .tcp_udp
        .dest_port
        .start_range = DNS_PORT; // DNS
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .tcp_udp
        .dest_port
        .end_range = DNS_PORT;

    //****************************************************************************************
    // 2. Incoming DNS responses filter: REDIRECT IN UDP packets with source PORT 53
    // Common values
    filter_table.static_filters[1].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[1].valid_fields = ndisapi::FilterLayerFlags::NETWORK_LAYER_VALID
        | ndisapi::FilterLayerFlags::TRANSPORT_LAYER_VALID;
    filter_table.static_filters[1].filter_action = ndisapi::FILTER_PACKET_REDIRECT;
    filter_table.static_filters[1].direction_flags =
        ndisapi::DirectionFlags::PACKET_FLAG_ON_RECEIVE;

    // Network layer filter
    filter_table.static_filters[1].network_filter.union_selector = ndisapi::IPV4;
    filter_table.static_filters[1]
        .network_filter
        .network_layer
        .ipv4
        .valid_fields = ndisapi::IpV4FilterFlags::IP_V4_FILTER_PROTOCOL;
    filter_table.static_filters[1]
        .network_filter
        .network_layer
        .ipv4
        .protocol = IPPROTO_UDP;

    // Transport layer filter
    filter_table.static_filters[1]
        .transport_filter
        .union_selector = ndisapi::TCPUDP;
    filter_table.static_filters[1]
        .transport_filter
        .transport_layer
        .tcp_udp
        .valid_fields = ndisapi::TcpUdpFilterFlags::TCPUDP_SRC_PORT;
    filter_table.static_filters[1]
        .transport_filter
        .transport_layer
        .tcp_udp
        .source_port
        .start_range = DNS_PORT;
    filter_table.static_filters[1]
        .transport_filter
        .transport_layer
        .tcp_udp
        .source_port
        .end_range = DNS_PORT;

    //***************************************************************************************
    // 3. Pass all packets (skipped by previous filters) without processing in user mode
    // Common values
    filter_table.static_filters[2].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[2].valid_fields = ndisapi::FilterLayerFlags::empty();
    filter_table.static_filters[2].filter_action = ndisapi::FILTER_PACKET_PASS;
    filter_table.static_filters[2].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_RECEIVE
        | ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND;

    ndisapi.set_packet_filter_table(&filter_table)
}

fn load_http_ipv4v6_filters(ndisapi: &ndisapi::Ndisapi) -> Result<()> {
    let mut filter_table = ndisapi::StaticFilterTable::<5>::default();
    //**************************************************************************************
    // 1. Outgoing HTTP requests filter: REDIRECT OUT TCP packets with destination PORT 80 IPv4
    // Common values
    filter_table.static_filters[0].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[0].valid_fields = ndisapi::FilterLayerFlags::NETWORK_LAYER_VALID
        | ndisapi::FilterLayerFlags::TRANSPORT_LAYER_VALID;
    filter_table.static_filters[0].filter_action = ndisapi::FILTER_PACKET_REDIRECT;
    filter_table.static_filters[0].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND;

    // Network layer filter
    filter_table.static_filters[0].network_filter.union_selector = ndisapi::IPV4;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .valid_fields = ndisapi::IpV4FilterFlags::IP_V4_FILTER_PROTOCOL;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .protocol = IPPROTO_TCP;

    // Transport layer filter
    filter_table.static_filters[0]
        .transport_filter
        .union_selector = ndisapi::TCPUDP;
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .tcp_udp
        .valid_fields = ndisapi::TcpUdpFilterFlags::TCPUDP_DEST_PORT;
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .tcp_udp
        .dest_port
        .start_range = HTTP_PORT; // HTTP
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .tcp_udp
        .dest_port
        .end_range = HTTP_PORT;

    //****************************************************************************************
    // 2. Incoming HTTP responses filter: REDIRECT IN TCP packets with source PORT 80 IPv4
    // Common values
    filter_table.static_filters[1].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[1].valid_fields = ndisapi::FilterLayerFlags::NETWORK_LAYER_VALID
        | ndisapi::FilterLayerFlags::TRANSPORT_LAYER_VALID;
    filter_table.static_filters[1].filter_action = ndisapi::FILTER_PACKET_REDIRECT;
    filter_table.static_filters[1].direction_flags =
        ndisapi::DirectionFlags::PACKET_FLAG_ON_RECEIVE;

    // Network layer filter
    filter_table.static_filters[1].network_filter.union_selector = ndisapi::IPV4;
    filter_table.static_filters[1]
        .network_filter
        .network_layer
        .ipv4
        .valid_fields = ndisapi::IpV4FilterFlags::IP_V4_FILTER_PROTOCOL;
    filter_table.static_filters[1]
        .network_filter
        .network_layer
        .ipv4
        .protocol = IPPROTO_TCP;

    // Transport layer filter
    filter_table.static_filters[1]
        .transport_filter
        .union_selector = ndisapi::TCPUDP;
    filter_table.static_filters[1]
        .transport_filter
        .transport_layer
        .tcp_udp
        .valid_fields = ndisapi::TcpUdpFilterFlags::TCPUDP_SRC_PORT;
    filter_table.static_filters[1]
        .transport_filter
        .transport_layer
        .tcp_udp
        .source_port
        .start_range = HTTP_PORT; // HTTP
    filter_table.static_filters[1]
        .transport_filter
        .transport_layer
        .tcp_udp
        .source_port
        .end_range = HTTP_PORT;

    //****************************************************************************************
    // 3. Outgoing HTTP requests filter: REDIRECT OUT TCP packets with destination PORT 80 IPv6
    // Common values
    filter_table.static_filters[2].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[2].valid_fields = ndisapi::FilterLayerFlags::NETWORK_LAYER_VALID
        | ndisapi::FilterLayerFlags::TRANSPORT_LAYER_VALID;
    filter_table.static_filters[2].filter_action = ndisapi::FILTER_PACKET_REDIRECT;
    filter_table.static_filters[2].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND;

    // Network layer filter
    filter_table.static_filters[2].network_filter.union_selector = ndisapi::IPV6;
    filter_table.static_filters[2]
        .network_filter
        .network_layer
        .ipv6
        .valid_fields = ndisapi::IpV6FilterFlags::IP_V6_FILTER_PROTOCOL;
    filter_table.static_filters[2]
        .network_filter
        .network_layer
        .ipv6
        .protocol = IPPROTO_TCP;

    // Transport layer filter
    filter_table.static_filters[2]
        .transport_filter
        .union_selector = ndisapi::TCPUDP;
    filter_table.static_filters[2]
        .transport_filter
        .transport_layer
        .tcp_udp
        .valid_fields = ndisapi::TcpUdpFilterFlags::TCPUDP_DEST_PORT;
    filter_table.static_filters[2]
        .transport_filter
        .transport_layer
        .tcp_udp
        .dest_port
        .start_range = HTTP_PORT; // HTTP
    filter_table.static_filters[2]
        .transport_filter
        .transport_layer
        .tcp_udp
        .dest_port
        .end_range = HTTP_PORT;

    //****************************************************************************************
    // 4. Incoming HTTP responses filter: REDIRECT IN TCP packets with source PORT 80 IPv6
    // Common values
    filter_table.static_filters[3].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[3].valid_fields = ndisapi::FilterLayerFlags::NETWORK_LAYER_VALID
        | ndisapi::FilterLayerFlags::TRANSPORT_LAYER_VALID;
    filter_table.static_filters[3].filter_action = ndisapi::FILTER_PACKET_REDIRECT;
    filter_table.static_filters[3].direction_flags =
        ndisapi::DirectionFlags::PACKET_FLAG_ON_RECEIVE;

    // Network layer filter
    filter_table.static_filters[3].network_filter.union_selector = ndisapi::IPV6;
    filter_table.static_filters[3]
        .network_filter
        .network_layer
        .ipv6
        .valid_fields = ndisapi::IpV6FilterFlags::IP_V6_FILTER_PROTOCOL;
    filter_table.static_filters[3]
        .network_filter
        .network_layer
        .ipv6
        .protocol = IPPROTO_TCP;

    // Transport layer filter
    filter_table.static_filters[3]
        .transport_filter
        .union_selector = ndisapi::TCPUDP;
    filter_table.static_filters[3]
        .transport_filter
        .transport_layer
        .tcp_udp
        .valid_fields = ndisapi::TcpUdpFilterFlags::TCPUDP_SRC_PORT;
    filter_table.static_filters[3]
        .transport_filter
        .transport_layer
        .tcp_udp
        .source_port
        .end_range = HTTP_PORT; // HTTP
    filter_table.static_filters[3]
        .transport_filter
        .transport_layer
        .tcp_udp
        .source_port
        .end_range = HTTP_PORT;

    //***************************************************************************************
    // 5. Pass all packets (skipped by previous filters) without processing in user mode
    // Common values
    filter_table.static_filters[4].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[4].valid_fields = ndisapi::FilterLayerFlags::empty();
    filter_table.static_filters[4].filter_action = ndisapi::FILTER_PACKET_PASS;
    filter_table.static_filters[4].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_RECEIVE
        | ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND;

    ndisapi.set_packet_filter_table(&filter_table)
}

fn load_icmpv4_drop_filters(ndisapi: &ndisapi::Ndisapi) -> Result<()> {
    let mut filter_table = ndisapi::StaticFilterTable::<1>::default();
    //**************************************************************************************
    // 1. Block all ICMP packets
    // Common values
    filter_table.static_filters[0].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[0].valid_fields = ndisapi::FilterLayerFlags::NETWORK_LAYER_VALID;
    filter_table.static_filters[0].filter_action = ndisapi::FILTER_PACKET_DROP;
    filter_table.static_filters[0].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND
        | ndisapi::DirectionFlags::PACKET_FLAG_ON_RECEIVE;

    // Network layer filter
    filter_table.static_filters[0].network_filter.union_selector = ndisapi::IPV4;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .valid_fields = ndisapi::IpV4FilterFlags::IP_V4_FILTER_PROTOCOL;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .protocol = IPPROTO_ICMP;

    ndisapi.set_packet_filter_table(&filter_table)
}

fn load_block_ntkernel_https_filters(ndisapi: &ndisapi::Ndisapi) -> Result<()> {
    let mut filter_table = ndisapi::StaticFilterTable::<2>::default();

    //**************************************************************************************
    // 1. Outgoing HTTP requests filter: DROP OUT TCP packets with destination IP 95.179.146.125 PORT 443 (https://www.ntkernel.com)
    // Common values
    filter_table.static_filters[0].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[0].valid_fields = ndisapi::FilterLayerFlags::NETWORK_LAYER_VALID
        | ndisapi::FilterLayerFlags::TRANSPORT_LAYER_VALID;
    filter_table.static_filters[0].filter_action = ndisapi::FILTER_PACKET_DROP;
    filter_table.static_filters[0].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND;

    // Network layer filter
    let address = IN_ADDR {
        S_un: IN_ADDR_0 {
            S_un_b: IN_ADDR_0_0 {
                s_b1: 95,
                s_b2: 179,
                s_b3: 146,
                s_b4: 125,
            },
        },
    };

    let mask = IN_ADDR {
        S_un: IN_ADDR_0 {
            S_un_b: IN_ADDR_0_0 {
                s_b1: 255,
                s_b2: 255,
                s_b3: 255,
                s_b4: 255,
            },
        },
    };

    filter_table.static_filters[0].network_filter.union_selector = ndisapi::IPV4;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .valid_fields = ndisapi::IpV4FilterFlags::IP_V4_FILTER_PROTOCOL
        | ndisapi::IpV4FilterFlags::IP_V4_FILTER_DEST_ADDRESS;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .dest_address
        .address_type = ndisapi::IP_SUBNET_V4_TYPE;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .dest_address
        .address
        .ip_subnet
        .ip = address; // IP address
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .dest_address
        .address
        .ip_subnet
        .ip_mask = mask; // network mask
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .protocol = IPPROTO_TCP;

    // Transport layer filter
    filter_table.static_filters[0]
        .transport_filter
        .union_selector = ndisapi::TCPUDP;
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .tcp_udp
        .valid_fields = ndisapi::TcpUdpFilterFlags::TCPUDP_DEST_PORT;
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .tcp_udp
        .dest_port
        .start_range = 443; // HTTPS
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .tcp_udp
        .dest_port
        .end_range = 443;

    //***************************************************************************************
    // 2. Pass all packets (skipped by previous filters) without processing in user mode
    // Common values
    filter_table.static_filters[1].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[1].valid_fields = ndisapi::FilterLayerFlags::empty();
    filter_table.static_filters[1].filter_action = ndisapi::FILTER_PACKET_PASS;
    filter_table.static_filters[1].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_RECEIVE
        | ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND;

    ndisapi.set_packet_filter_table(&filter_table)
}

fn load_redirect_arp_filters(ndisapi: &ndisapi::Ndisapi) -> Result<()> {
    let mut filter_table = ndisapi::StaticFilterTable::<3>::default();

    //**************************************************************************************
    // 1. Redirects all ARP packets to be processes by user mode application
    // Common values
    filter_table.static_filters[0].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[0].valid_fields = ndisapi::FilterLayerFlags::DATA_LINK_LAYER_VALID;
    filter_table.static_filters[0].filter_action = ndisapi::FILTER_PACKET_REDIRECT;
    filter_table.static_filters[0].direction_flags =
        ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND_RECEIVE;
    filter_table.static_filters[0]
        .data_link_filter
        .union_selector = ndisapi::ETH_802_3;
    filter_table.static_filters[0]
        .data_link_filter
        .data_link_layer
        .eth_8023_filter
        .valid_fields = ndisapi::Eth802_3FilterFlags::ETH_802_3_PROTOCOL;
    filter_table.static_filters[0]
        .data_link_filter
        .data_link_layer
        .eth_8023_filter
        .protocol = ETH_P_ARP;

    //**************************************************************************************
    // 2. Redirects all RARP packets to be processes by user mode application
    // Common values
    filter_table.static_filters[1].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[1].valid_fields = ndisapi::FilterLayerFlags::DATA_LINK_LAYER_VALID;
    filter_table.static_filters[1].filter_action = ndisapi::FILTER_PACKET_REDIRECT;
    filter_table.static_filters[1].direction_flags =
        ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND_RECEIVE;
    filter_table.static_filters[1]
        .data_link_filter
        .union_selector = ndisapi::ETH_802_3;
    filter_table.static_filters[1]
        .data_link_filter
        .data_link_layer
        .eth_8023_filter
        .valid_fields = ndisapi::Eth802_3FilterFlags::ETH_802_3_PROTOCOL;
    filter_table.static_filters[1]
        .data_link_filter
        .data_link_layer
        .eth_8023_filter
        .protocol = ETH_P_RARP;

    //***************************************************************************************
    // 3. Pass all packets (skipped by previous filters) without processing in user mode
    // Common values
    filter_table.static_filters[2].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[2].valid_fields = ndisapi::FilterLayerFlags::empty();
    filter_table.static_filters[2].filter_action = ndisapi::FILTER_PACKET_PASS;
    filter_table.static_filters[2].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_RECEIVE
        | ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND;

    ndisapi.set_packet_filter_table(&filter_table)
}

fn load_redirect_icmp_req_filters(ndisapi: &ndisapi::Ndisapi) -> Result<()> {
    let mut filter_table = ndisapi::StaticFilterTable::<2>::default();

    //**************************************************************************************
    // 1. Redirects all ARP packets to be processes by user mode application
    // Common values
    filter_table.static_filters[0].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[0].valid_fields = ndisapi::FilterLayerFlags::NETWORK_LAYER_VALID
        | ndisapi::FilterLayerFlags::TRANSPORT_LAYER_VALID;
    filter_table.static_filters[0].filter_action = ndisapi::FILTER_PACKET_REDIRECT;
    filter_table.static_filters[0].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND;

    filter_table.static_filters[0].network_filter.union_selector = ndisapi::IPV4;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .valid_fields = ndisapi::IpV4FilterFlags::IP_V4_FILTER_PROTOCOL;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .dest_address
        .address_type = ndisapi::IP_SUBNET_V4_TYPE;
    filter_table.static_filters[0]
        .network_filter
        .network_layer
        .ipv4
        .protocol = IPPROTO_ICMP;

    // Transport layer filter
    filter_table.static_filters[0]
        .transport_filter
        .union_selector = ndisapi::ICMP;
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .icmp
        .valid_fields = ndisapi::IcmpFilterFlags::ICMP_TYPE;
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .icmp
        .type_range
        .start_range = 8; // ICMP PING REQUEST
    filter_table.static_filters[0]
        .transport_filter
        .transport_layer
        .icmp
        .type_range
        .end_range = 8;

    //***************************************************************************************
    // 2. Pass all packets (skipped by previous filters) without processing in user mode
    // Common values
    filter_table.static_filters[1].adapter_handle = 0; // applied to all adapters
    filter_table.static_filters[1].valid_fields = ndisapi::FilterLayerFlags::empty();
    filter_table.static_filters[1].filter_action = ndisapi::FILTER_PACKET_PASS;
    filter_table.static_filters[1].direction_flags = ndisapi::DirectionFlags::PACKET_FLAG_ON_RECEIVE
        | ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND;

    ndisapi.set_packet_filter_table(&filter_table)
}

fn main() -> Result<()> {
    let Cli {
        mut interface_index,
        filter,
    } = Cli::parse();

    interface_index -= 1;

    let driver = ndisapi::Ndisapi::new("NDISRD")
        .expect("WinpkFilter driver is not installed or failed to load!");

    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    let adapters = driver.get_tcpip_bound_adapters_info()?;

    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beoynd the number of available interfaces");
    }

    println!("Using interface {}s", adapters[interface_index].get_name());

    let filter_set_result = match filter {
        1 => load_ipv4_dns_filters(&driver),
        2 => load_http_ipv4v6_filters(&driver),
        3 => load_icmpv4_drop_filters(&driver),
        4 => load_block_ntkernel_https_filters(&driver),
        5 => load_redirect_arp_filters(&driver),
        6 => load_redirect_icmp_req_filters(&driver),
        _ => panic!("Filter set is not availbale"),
    };

    match filter_set_result {
        Ok(_) => println!("Succesfully loaded static filters into the driver."),
        Err(err) => panic!("Failed to load static filter into the driver. Error code: {err}"),
    }

    // Create Win32 event
    let event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?;
    }

    let terminate: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let ctrlc_pressed = terminate.clone();
    ctrlc::set_handler(move || {
        println!("Ctrl-C was pressed. Terminating...");
        // set atomic flag to exit the loop
        ctrlc_pressed.store(true, Ordering::SeqCst);
        // signal an event to release the loop if there are no packets in the queue
        unsafe {
            SetEvent(event);
        }
    })
    .expect("Error setting Ctrl-C handler");

    // Set the event within the driver
    driver.set_packet_event(adapters[interface_index].get_handle(), event)?;

    // Put network interface into the tunnel mode
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        ndisapi::FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
    )?;

    // Allocate single IntermediateBuffer on the stack
    let mut ib = ndisapi::IntermediateBuffer::default();

    // Initialize EthPacket to pass to driver API
    let mut packet = ndisapi::EthRequest {
        adapter_handle: adapters[interface_index].get_handle(),
        packet: ndisapi::EthPacket {
            buffer: &mut ib as *mut ndisapi::IntermediateBuffer,
        },
    };

    while !terminate.load(Ordering::SeqCst) {
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }
        while unsafe { driver.read_packet(&mut packet) }.ok().is_some() {
            // Print packet information
            if ib.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
                println!("\nMSTCP --> Interface ({} bytes)\n", ib.get_length());
            } else {
                println!("\nInterface --> MSTCP ({} bytes)\n", ib.get_length());
            }

            // Print some informations about the sliced packet
            print_packet_info(&mut ib);

            // Re-inject the packet back into the network stack
            if ib.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
                match unsafe { driver.send_packet_to_adapter(&packet) } {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
                };
            } else {
                match unsafe { driver.send_packet_to_mstcp(&packet) } {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
                }
            }
        }
    }

    Ok(())
}

/// Print detailed information about a network packet.
///
/// This function takes an `IntermediateBuffer` containing a network packet and prints various
/// details about the packet, such as Ethernet, IPv4, IPv6, ICMPv4, ICMPv6, UDP, and TCP information.
///
/// # Arguments
///
/// * `packet` - A mutable reference to an `ndisapi::IntermediateBuffer` containing the network packet.
///
/// # Examples
///
/// ```no_run
/// let mut packet: ndisapi::IntermediateBuffer = ...;
/// print_packet_info(&mut packet);
/// ```
fn print_packet_info(packet: &mut ndisapi::IntermediateBuffer) {
    // Attempt to create a SlicedPacket from the Ethernet frame.
    match SlicedPacket::from_ethernet(&packet.buffer.0) {
        // If there's an error, print it.
        Err(value) => println!("Err {value:?}"),

        // If successful, proceed with printing packet information.
        Ok(value) => {
            // Print Ethernet information if available.
            if let Some(Ethernet2(value)) = value.link {
                println!(
                    " Ethernet {} => {}",
                    ndisapi::MacAddress::from_slice(&value.source()[..]).unwrap(),
                    ndisapi::MacAddress::from_slice(&value.destination()[..]).unwrap(),
                );
            }

            // Print IP information if available.
            match value.ip {
                Some(Ipv4(value, extensions)) => {
                    println!(
                        "  Ipv4 {:?} => {:?}",
                        value.source_addr(),
                        value.destination_addr()
                    );
                    if !extensions.is_empty() {
                        println!("    {extensions:?}");
                    }
                }
                Some(Ipv6(value, extensions)) => {
                    println!(
                        "  Ipv6 {:?} => {:?}",
                        value.source_addr(),
                        value.destination_addr()
                    );
                    if !extensions.is_empty() {
                        println!("    {extensions:?}");
                    }
                }
                None => {}
            }

            // Print transport layer information if available.
            match value.transport {
                Some(Icmpv4(value)) => println!(" Icmpv4 {value:?}"),
                Some(Icmpv6(value)) => println!(" Icmpv6 {value:?}"),
                Some(Udp(value)) => println!(
                    "   UDP {:?} -> {:?}",
                    value.source_port(),
                    value.destination_port()
                ),
                Some(Tcp(value)) => {
                    println!(
                        "   TCP {:?} -> {:?}",
                        value.source_port(),
                        value.destination_port()
                    );
                }
                Some(Unknown(ip_protocol)) => {
                    println!("  Unknown Protocol (ip protocol number {ip_protocol:?})")
                }
                None => {}
            }
        }
    }
}
