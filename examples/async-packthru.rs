/// This module provides functionality for asynchronously reading packets from a network adapter, processing them, and logging them.
///
/// # Dependencies
///
/// This module depends on the following external crates:
/// * `clap`: For parsing command line arguments.
/// * `ndisapi`: For interacting with the network adapter.
/// * `smoltcp`: For parsing network packets.
/// * `std`: For various standard library features.
/// * `tokio`: For asynchronous programming.
/// * `windows`: For interacting with the Windows API.
/// * `crossterm`: For terminal manipulation.
/// * `prettytable`: For creating formatted tables.
///
/// # Constants
///
/// This module defines the following constants:
/// * `PACKET_NUMBER`: The number of packets to read from the adapter at a time.
///
/// # Structs
///
/// This module defines the following structs:
/// * `PacketInfo`: Represents the information contained in a network packet headers.
///
/// # Functions
///
/// This module defines the following functions:
/// * `main`: The main function of the program.
/// * `main_async`: Asynchronously reads packets from an adapter, processes them, and logs them.
/// * `async_loop`: Asynchronously reads packets from an adapter, processes them, and re-injects them back into the network stack.
/// * `process_packet_logs`: Asynchronously processes packet logs received from a channel.
/// * `update_display`: Asynchronously updates the terminal display with packet information every second.
///
/// Note: The specific behavior of each function is documented in the function's own documentation comment.
use clap::Parser;
use crossterm::{
    cursor::MoveTo,
    execute,
    terminal::{Clear, ClearType},
};
use ndisapi::{AsyncNdisapiAdapter, DirectionFlags, FilterFlags, IntermediateBuffer, Ndisapi};
use prettytable::{row, Table};
use smoltcp::wire::{
    ArpPacket, EthernetFrame, EthernetProtocol, Icmpv4Message, Icmpv4Packet, Icmpv6Message,
    Icmpv6Packet, IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
};
use std::{collections::HashMap, fmt, sync::Arc};
use tokio::{
    sync::{
        mpsc::{self, Receiver},
        oneshot, Mutex,
    },
    time::{self, Duration},
};
use windows::core::Result;

const PACKET_NUMBER: usize = 510;

/// `PacketInfo` is a struct that represents the information contained in a network packet headers.
///
/// # Fields
/// * `ethertype`: The Ethernet protocol type of the packet. This field is of type `EthernetProtocol`.
/// * `src_addr`: The source IP address of the packet. This field is an `Option` that contains an `IpAddress`.
/// * `dst_addr`: The destination IP address of the packet. This field is an `Option` that contains an `IpAddress`.
/// * `protocol`: The protocol used by the packet (e.g., TCP, UDP, ICMP). This field is an `Option` that contains an `IpProtocol`.
/// * `src_port`: The source port number used by the packet. This field is an `Option` that contains a `u16`.
/// * `dst_port`: The destination port number used by the packet. This field is an `Option` that contains a `u16`.
/// * `icmp_v4_type`: The type of ICMPv4 message, if applicable. This field is an `Option` that contains an `Icmpv4Message`.
/// * `icmp_v6_type`: The type of ICMPv6 message, if applicable. This field is an `Option` that contains an `Icmpv6Message`.
/// * `icmp_code`: The ICMP code, if applicable. This field is an `Option` that contains a `u8`.
#[derive(Hash, Eq, PartialEq, Debug)]
struct PacketInfo {
    ethertype: EthernetProtocol,
    src_addr: Option<IpAddress>,
    dst_addr: Option<IpAddress>,
    protocol: Option<IpProtocol>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    icmp_v4_type: Option<Icmpv4Message>,
    icmp_v6_type: Option<Icmpv6Message>,
    icmp_code: Option<u8>,
}

/// Provides a default value for the `PacketInfo` struct.
///
/// # Returns
///
/// * A `PacketInfo` struct with the following default values:
///     * `ethertype`: `EthernetProtocol::Unknown(0)`. This represents an unknown or unsupported Ethernet protocol.
///     * `src_addr`: `None`. This indicates that the source IP address is not known or not applicable.
///     * `dst_addr`: `None`. This indicates that the destination IP address is not known or not applicable.
///     * `protocol`: `None`. This indicates that the protocol is not known or not applicable.
///     * `src_port`: `None`. This indicates that the source port is not known or not applicable.
///     * `dst_port`: `None`. This indicates that the destination port is not known or not applicable.
///     * `icmp_v4_type`: `None`. This indicates that the ICMPv4 message type is not known or not applicable.
///     * `icmp_v6_type`: `None`. This indicates that the ICMPv6 message type is not known or not applicable.
///     * `icmp_code`: `None`. This indicates that the ICMP code is not known or not applicable.
impl Default for PacketInfo {
    fn default() -> Self {
        PacketInfo {
            ethertype: EthernetProtocol::Unknown(0), // or any other default value you want
            src_addr: None,
            dst_addr: None,
            protocol: None,
            src_port: None,
            dst_port: None,
            icmp_v4_type: None,
            icmp_v6_type: None,
            icmp_code: None,
        }
    }
}

impl PacketInfo {
    /// Handles an IPv4 packet encapsulated in an Ethernet frame.
    ///
    /// # Arguments
    ///
    /// * `eth_hdr`: A reference to an `EthernetFrame` that encapsulates the IPv4 packet.
    ///
    /// # Returns
    ///
    /// * A `PacketInfo` struct that contains the parsed information from the IPv4 packet.
    ///
    /// # Behavior
    ///
    /// This function first creates an `Ipv4Packet` from the payload of the Ethernet frame.
    /// It then checks the protocol of the IPv4 packet and handles the packet accordingly:
    /// * If the protocol is ICMP, it creates an `Icmpv4Packet` from the payload of the IPv4 packet and sets the relevant fields in the `PacketInfo`.
    /// * If the protocol is TCP, it creates a `TcpPacket` from the payload of the IPv4 packet and sets the relevant fields in the `PacketInfo`.
    /// * If the protocol is UDP, it creates a `UdpPacket` from the payload of the IPv4 packet and sets the relevant fields in the `PacketInfo`.
    /// * For any other protocol, it sets the `protocol` field in the `PacketInfo` to the protocol of the IPv4 packet and leaves all other fields at their default values.
    fn handle_ipv4_packet(eth_hdr: &EthernetFrame<&[u8]>) -> PacketInfo {
        let ipv4_packet = Ipv4Packet::new_unchecked(eth_hdr.payload());
        match ipv4_packet.next_header() {
            IpProtocol::Icmp => {
                let icmp_packet = Icmpv4Packet::new_unchecked(ipv4_packet.payload());
                PacketInfo {
                    ethertype: EthernetProtocol::Ipv4,
                    src_addr: Some(IpAddress::Ipv4(ipv4_packet.src_addr())),
                    dst_addr: Some(IpAddress::Ipv4(ipv4_packet.dst_addr())),
                    protocol: Some(IpProtocol::Icmp),
                    src_port: None,
                    dst_port: None,
                    icmp_v4_type: Some(icmp_packet.msg_type()),
                    icmp_v6_type: None,
                    icmp_code: Some(icmp_packet.msg_code()),
                }
            }
            IpProtocol::Tcp => {
                let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
                PacketInfo {
                    ethertype: EthernetProtocol::Ipv4,
                    src_addr: Some(IpAddress::Ipv4(ipv4_packet.src_addr())),
                    dst_addr: Some(IpAddress::Ipv4(ipv4_packet.dst_addr())),
                    protocol: Some(IpProtocol::Tcp),
                    src_port: Some(tcp_packet.src_port()),
                    dst_port: Some(tcp_packet.dst_port()),
                    icmp_v4_type: None,
                    icmp_v6_type: None,
                    icmp_code: None,
                }
            }
            IpProtocol::Udp => {
                let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
                PacketInfo {
                    ethertype: EthernetProtocol::Ipv4,
                    src_addr: Some(IpAddress::Ipv4(ipv4_packet.src_addr())),
                    dst_addr: Some(IpAddress::Ipv4(ipv4_packet.dst_addr())),
                    protocol: Some(IpProtocol::Udp),
                    src_port: Some(udp_packet.src_port()),
                    dst_port: Some(udp_packet.dst_port()),
                    icmp_v4_type: None,
                    icmp_v6_type: None,
                    icmp_code: None,
                }
            }
            _ => PacketInfo {
                ethertype: EthernetProtocol::Ipv4,
                src_addr: Some(IpAddress::Ipv4(ipv4_packet.src_addr())),
                dst_addr: Some(IpAddress::Ipv4(ipv4_packet.dst_addr())),
                protocol: Some(ipv4_packet.next_header()),
                src_port: None,
                dst_port: None,
                icmp_v4_type: None,
                icmp_v6_type: None,
                icmp_code: None,
            },
        }
    }

    /// Handles an IPv6 packet encapsulated in an Ethernet frame.
    ///
    /// # Arguments
    ///
    /// * `eth_hdr`: A reference to an `EthernetFrame` that encapsulates the IPv6 packet.
    ///
    /// # Returns
    ///
    /// * A `PacketInfo` struct that contains the parsed information from the IPv6 packet.
    ///
    /// # Behavior
    ///
    /// This function first creates an `Ipv6Packet` from the payload of the Ethernet frame.
    /// It then checks the next header field of the IPv6 packet and handles the packet accordingly:
    /// * If the next header is ICMPv6, it creates an `Icmpv6Packet` from the payload of the IPv6 packet and sets the relevant fields in the `PacketInfo`.
    /// * If the next header is TCP, it creates a `TcpPacket` from the payload of the IPv6 packet and sets the relevant fields in the `PacketInfo`.
    /// * If the next header is UDP, it creates a `UdpPacket` from the payload of the IPv6 packet and sets the relevant fields in the `PacketInfo`.
    /// * For any other next header, it sets the `protocol` field in the `PacketInfo` to the next header of the IPv6 packet and leaves all other fields at their default values.
    fn handle_ipv6_packet(eth_hdr: &EthernetFrame<&[u8]>) -> PacketInfo {
        let ipv6_packet = Ipv6Packet::new_unchecked(eth_hdr.payload());
        match ipv6_packet.next_header() {
            IpProtocol::Icmpv6 => {
                let icmp_packet = Icmpv6Packet::new_unchecked(ipv6_packet.payload());
                PacketInfo {
                    ethertype: EthernetProtocol::Ipv6,
                    src_addr: Some(IpAddress::Ipv6(ipv6_packet.src_addr())),
                    dst_addr: Some(IpAddress::Ipv6(ipv6_packet.dst_addr())),
                    protocol: Some(IpProtocol::Icmpv6),
                    src_port: None,
                    dst_port: None,
                    icmp_v4_type: None,
                    icmp_v6_type: Some(icmp_packet.msg_type()),
                    icmp_code: Some(icmp_packet.msg_code()),
                }
            }
            IpProtocol::Tcp => {
                let tcp_packet = TcpPacket::new_unchecked(ipv6_packet.payload());
                PacketInfo {
                    ethertype: EthernetProtocol::Ipv6,
                    src_addr: Some(IpAddress::Ipv6(ipv6_packet.src_addr())),
                    dst_addr: Some(IpAddress::Ipv6(ipv6_packet.dst_addr())),
                    protocol: Some(IpProtocol::Tcp),
                    src_port: Some(tcp_packet.src_port()),
                    dst_port: Some(tcp_packet.dst_port()),
                    icmp_v4_type: None,
                    icmp_v6_type: None,
                    icmp_code: None,
                }
            }
            IpProtocol::Udp => {
                let udp_packet = UdpPacket::new_unchecked(ipv6_packet.payload());
                PacketInfo {
                    ethertype: EthernetProtocol::Ipv6,
                    src_addr: Some(IpAddress::Ipv6(ipv6_packet.src_addr())),
                    dst_addr: Some(IpAddress::Ipv6(ipv6_packet.dst_addr())),
                    protocol: Some(IpProtocol::Udp),
                    src_port: Some(udp_packet.src_port()),
                    dst_port: Some(udp_packet.dst_port()),
                    icmp_v4_type: None,
                    icmp_v6_type: None,
                    icmp_code: None,
                }
            }
            _ => PacketInfo {
                ethertype: EthernetProtocol::Ipv6,
                src_addr: Some(IpAddress::Ipv6(ipv6_packet.src_addr())),
                dst_addr: Some(IpAddress::Ipv6(ipv6_packet.dst_addr())),
                protocol: Some(ipv6_packet.next_header()),
                src_port: None,
                dst_port: None,
                icmp_v4_type: None,
                icmp_v6_type: None,
                icmp_code: None,
            },
        }
    }

    /// Handles an ARP packet encapsulated in an Ethernet frame.
    ///
    /// # Arguments
    ///
    /// * `eth_hdr`: A reference to an `EthernetFrame` that encapsulates the ARP packet.
    ///
    /// # Returns
    ///
    /// * A `PacketInfo` struct that contains the parsed information from the ARP packet.
    ///
    /// # Behavior
    ///
    /// This function first creates an `ArpPacket` from the payload of the Ethernet frame.
    /// It then creates a `PacketInfo` with the `ethertype` field set to `EthernetProtocol::Arp`,
    /// the `src_addr` field set to the source protocol address from the ARP packet,
    /// and the `dst_addr` field set to the target protocol address from the ARP packet.
    /// All other fields are set to `None` because they are not applicable to ARP packets.
    fn handle_arp_packet(eth_hdr: &EthernetFrame<&[u8]>) -> PacketInfo {
        let arp_packet = ArpPacket::new_unchecked(eth_hdr.payload());
        
        // Convert slices to fixed-size arrays
        let src_bytes: [u8; 4] = arp_packet
            .source_protocol_addr()
            .try_into()
            .unwrap_or([0u8; 4]);
        let dst_bytes: [u8; 4] = arp_packet
            .target_protocol_addr()
            .try_into()
            .unwrap_or([0u8; 4]);
        
        PacketInfo {
            ethertype: EthernetProtocol::Arp,
            src_addr: Some(IpAddress::Ipv4(Ipv4Address::from_octets(src_bytes))),
            dst_addr: Some(IpAddress::Ipv4(Ipv4Address::from_octets(dst_bytes))),
            protocol: None,
            src_port: None,
            dst_port: None,
            icmp_v4_type: None,
            icmp_v6_type: None,
            icmp_code: None,
        }
    }

    /// Creates a new `PacketInfo` from an `IntermediateBuffer`.
    ///
    /// # Arguments
    ///
    /// * `packet`: A reference to an `IntermediateBuffer` that contains the packet data.
    ///
    /// # Returns
    ///
    /// * A `PacketInfo` struct that contains the parsed information from the packet.
    ///
    /// # Behavior
    ///
    /// This function first creates an `EthernetFrame` from the data in the `IntermediateBuffer`.
    /// It then checks the ethertype of the Ethernet frame and handles the packet accordingly:
    /// * If the ethertype is IPv4, it calls `handle_ipv4_packet` to handle the packet.
    /// * If the ethertype is IPv6, it calls `handle_ipv6_packet` to handle the packet.
    /// * If the ethertype is ARP, it calls `handle_arp_packet` to handle the packet.
    /// * For any other ethertype, it creates a `PacketInfo` with the `ethertype` field set to the ethertype of the Ethernet frame and all other fields set to their default values.
    pub fn new(packet: &IntermediateBuffer) -> Self {
        let eth_hdr = EthernetFrame::new_unchecked(packet.get_data());
        match eth_hdr.ethertype() {
            EthernetProtocol::Ipv4 => Self::handle_ipv4_packet(&eth_hdr),
            EthernetProtocol::Ipv6 => Self::handle_ipv6_packet(&eth_hdr),
            EthernetProtocol::Arp => Self::handle_arp_packet(&eth_hdr),
            _ => {
                // Handle other ethertypes here
                PacketInfo {
                    ethertype: eth_hdr.ethertype(),
                    ..PacketInfo::default()
                }
            }
        }
    }
}

/// Implementation of the `Display` trait for `PacketInfo`.
///
/// This implementation provides a human-readable representation of a `PacketInfo` instance. It includes the
/// Ethernet type, source and destination IP addresses, and protocol of the packet. If applicable, it also includes
/// the source and destination port numbers, and the ICMP type and code.
///
/// # Example
///
/// ```rust
/// let packet_info = PacketInfo {
///     ethertype: EthernetProtocol::Ipv4,
///     src_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
///     dst_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
///     protocol: IpProtocol::Tcp,
///     src_port: Some(12345),
///     dst_port: Some(80),
///     icmp_type: None,
///     icmp_code: None,
/// };
///
/// println!("{}", packet_info);
/// ```
///
/// This will output:
///
/// ```text
/// Ethertype: Ipv4
/// Source Address: 192.168.1.1
/// Destination Address: 192.168.1.2
/// Protocol: Tcp
/// Source Port: 12345
/// Destination Port: 80
/// ```
impl fmt::Display for PacketInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Ethertype: {:?}\nSource Address: {:?}\nDestination Address: {:?}\nProtocol: {:?}\n",
            self.ethertype, self.src_addr, self.dst_addr, self.protocol
        )?;

        if let Some(src_port) = self.src_port {
            writeln!(f, "Source Port: {}", src_port)?;
        }

        if let Some(dst_port) = self.dst_port {
            writeln!(f, "Destination Port: {}", dst_port)?;
        }

        if let Some(icmp_v4_type) = self.icmp_v4_type {
            writeln!(f, "ICMPv4 Type: {:?}", icmp_v4_type)?;
        }

        if let Some(icmp_v6_type) = self.icmp_v6_type {
            writeln!(f, "ICMPv6 Type: {:?}", icmp_v6_type)?;
        }

        if let Some(icmp_code) = self.icmp_code {
            writeln!(f, "ICMP Code: {:?}", icmp_code)?;
        }

        Ok(())
    }
}

/// Asynchronously reads packets from an adapter, processes them, and re-injects them back into the network stack.
///
/// # Arguments
///
/// * `adapter`: A mutable reference to an `AsyncNdisapiAdapter` that represents the network adapter.
/// * `tx`: A `mpsc::Sender` that is used to send `PacketInfo` structs to another part of the program.
///
/// # Returns
///
/// * A `Result` that indicates whether the function succeeded or failed. The function returns `Ok(())` if it succeeded and `Err(e)` if it failed, where `e` is the error that occurred.
///
/// # Behavior
///
/// This function first sets the adapter mode to `MSTCP_FLAG_SENT_RECEIVE_TUNNEL` to capture both sent and received packets.
/// It then enters a loop where it does the following on each iteration:
/// * Reads packets from the adapter into a vector of `IntermediateBuffer`s.
/// * For each packet read, it creates a `PacketInfo` from the packet data and sends it to the `tx` channel.
/// * It partitions the packets into two collections: one for packets that were sent and one for packets that were received.
/// * It re-injects the sent packets back into the adapter and the received packets back into the MSTCP.
async fn async_loop(adapter: &mut AsyncNdisapiAdapter, tx: mpsc::Sender<PacketInfo>) -> Result<()> {
    // Set the adapter mode to MSTCP_FLAG_SENT_RECEIVE_TUNNEL.
    adapter.set_adapter_mode(FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)?;

    // Initialize a vector of IntermediateBuffers, `ibs`, to store network packet data.
    // Each IntermediateBuffer is heap-allocated, providing a structure to handle raw packet data.
    let mut packets: Vec<IntermediateBuffer> = vec![Default::default(); PACKET_NUMBER];

    loop {
        // Read packets from the adapter.
        let packets_read = match adapter.read_packets::<PACKET_NUMBER>(&mut packets).await {
            Ok(packets_read) => {
                if packets_read == 0 {
                    println!("No packets read. Continue reading.");
                    continue;
                } else {
                    packets_read
                }
            }
            Err(_) => {
                continue;
            }
        };

        for packet in packets[0..packets_read].iter() {
            // Get packet information as a string.
            let packet_info = PacketInfo::new(packet);

            // Send packet information to the tx channel.
            tx.send(packet_info).await.unwrap();
        }

        // Partition the iterator into two collections based on the device flag.
        let (send_packets, receive_packets): (Vec<_>, Vec<_>) = packets[0..packets_read]
            .iter()
            .partition(|ib| ib.get_device_flags() == DirectionFlags::PACKET_FLAG_ON_SEND);

        // Re-inject packets back into the network stack
        match adapter.send_packets_to_adapter::<PACKET_NUMBER>(send_packets) {
            Ok(_) => {}
            Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
        }

        match adapter.send_packets_to_mstcp::<PACKET_NUMBER>(receive_packets) {
            Ok(_) => {}
            Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
        }
    }
}

/// Asynchronously updates the terminal display with packet information every second.
///
/// # Arguments
///
/// * `shared_table`: An `Arc<Mutex<HashMap<PacketInfo, u32>>>` that represents a shared `HashMap` mapping `PacketInfo` structs to counts.
///
/// # Behavior
///
/// This function does the following:
/// * Sets up a one-second interval timer.
/// * Enters a loop where it does the following on each iteration:
///     * Waits for the interval timer to tick.
///     * Locks the `shared_table` to access the `HashMap`.
///     * Clears the terminal.
///     * Creates a new table with columns for the protocol, source, destination, and count.
///     * Sorts the entries in the `HashMap` by count in descending order and takes the top 10 entries.
///     * For each entry, it formats the source and destination as strings, adds a row to the table with the protocol, source, destination, and count, and then prints the table.
///
/// Note: This function does not return. It continues to update the display until the program is terminated.
async fn update_display(shared_table: Arc<Mutex<HashMap<PacketInfo, u32>>>) {
    let mut interval = time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;
        let packet_info_table = shared_table.lock().await;

        // Clear the terminal
        execute!(std::io::stdout(), Clear(ClearType::All), MoveTo(0, 0)).unwrap();

        // Create and populate the table
        let mut table = Table::new();
        table.add_row(row!["Protocol", "Source", "Destination", "Count"]);

        let mut counts: Vec<_> = packet_info_table
            .iter()
            .map(|(pi, &count)| (pi, count))
            .collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        let top_entries = &counts[..std::cmp::min(10, counts.len())];

        for (packet_info, count) in top_entries {
            let src = format!(
                "{}:{}",
                packet_info
                    .src_addr
                    .unwrap_or(IpAddress::Ipv4(Ipv4Address::new(0, 0, 0, 0))),
                packet_info.src_port.unwrap_or_default()
            );
            let dst = format!(
                "{}:{}",
                packet_info
                    .dst_addr
                    .unwrap_or(IpAddress::Ipv4(Ipv4Address::new(0, 0, 0, 0))),
                packet_info.dst_port.unwrap_or_default()
            );
            table.add_row(row![
                packet_info.protocol.unwrap_or(IpProtocol::Unknown(0)),
                src,
                dst,
                count.to_string()
            ]);
        }

        // Print the table
        table.printstd();
    }
}

/// Asynchronously processes packet logs received from a channel.
///
/// # Arguments
///
/// * `log_rx`: A mutable reference to a `Receiver<PacketInfo>` that receives `PacketInfo` structs from a channel.
///
/// # Behavior
///
/// This function does the following:
/// * Creates a shared `HashMap` that maps `PacketInfo` structs to counts.
/// * Spawns a new task that updates the display with the contents of the `HashMap`.
/// * Enters a loop where it does the following on each iteration:
///     * Waits for a `PacketInfo` struct from the `log_rx` channel.
///     * If it receives a `PacketInfo` struct, it increments the count for that `PacketInfo` in the `HashMap`.
///
/// Note: This function does not return. It continues to process packet logs until the program is terminated.
async fn process_packet_logs(mut log_rx: Receiver<PacketInfo>) {
    let packet_info_table = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(update_display(packet_info_table.clone()));

    loop {
        if let Some(log_message) = log_rx.recv().await {
            let mut table = packet_info_table.lock().await;
            *table.entry(log_message).or_insert(0) += 1;
        }
    }
}

/// Asynchronously reads packets from an adapter, processes them, and logs them.
///
/// # Arguments
///
/// * `adapter`: A mutable reference to an `AsyncNdisapiAdapter` that represents the network adapter.
///
/// # Behavior
///
/// This function does the following:
/// * Prompts the user to press ENTER to exit.
/// * Initializes a `oneshot` channel for communication between this function and a spawned thread that waits for the user to press ENTER.
/// * Initializes a `mpsc` channel for logging. The transmitter end of the channel is passed to the `async_loop` function, which sends `PacketInfo` structs to the receiver end of the channel.
/// * Spawns a new thread that waits for the user to press ENTER and sends a message through the `oneshot` channel when the user does so.
/// * Spawns a new thread that receives `PacketInfo` structs from the `mpsc` channel and logs them.
/// * Calls the `async_loop` function to read packets from the adapter and process them.
/// * Waits for either the `async_loop` function to return a result or the thread that waits for the user to press ENTER to receive a message. If the latter happens, it prints "Shutting down..." and returns.
/// * Prints any errors that may have occurred during the program's execution.
async fn main_async(adapter: &mut AsyncNdisapiAdapter) {
    // Prompts the user to press ENTER to exit.
    println!("Press ENTER to exit");

    // Initializes a channel for communication between this function and a spawned thread.
    // `tx` is the transmitter and `rx` is the receiver end of the channel.
    let (tx, rx) = oneshot::channel::<()>();

    // Initializes a channel for logging.
    // `log_tx` is the transmitter and `log_rx` is the receiver end of the channel.
    let (log_tx, log_rx) = mpsc::channel::<PacketInfo>(PACKET_NUMBER * 100);

    // Spawns a new thread using Tokio's runtime, that waits for the user to press ENTER.
    tokio::spawn(async move {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();

        // Sends a message through the channel when the user presses ENTER.
        let _ = tx.send(());
    });

    // Waits for either the server to return a result or the thread with `rx` to receive a message.
    // This is achieved by using the select! macro which polls multiple futures and blocks until one of them is ready.
    let result = tokio::select! {
        // The async_loop function reads from the adapter and processes the packets.
        result = async_loop(adapter, log_tx) => result,
        _ = process_packet_logs(log_rx) => Ok(()),
        // If the receiver end of the channel receives a message, the program prints "Shutting down..." and returns Ok(()).
        _ = rx => {
            println!("Shutting down...");
            Ok(()) // Thread returns Ok() if it receives the message successfully.
        }
    };

    // Prints any errors that may have occurred during the program's execution.
    if let Err(e) = result {
        eprintln!("Server error: {}", e);
    }
}

/// A struct representing the command line arguments.
#[derive(Parser)]
struct Cli {
    /// Network interface index (please use listadapters example to determine the right one)
    #[clap(short, long)]
    interface_index: usize,
}

/// The main function of the program.
///
/// # Behavior
///
/// This function does the following:
/// * Parses command line arguments to get the interface index.
/// * Decrements the interface index to match zero-based index.
/// * Creates a new `Ndisapi` driver instance.
/// * Prints the detected version of the Windows Packet Filter.
/// * Gets a list of TCP/IP bound adapters in the system.
/// * Checks if the selected interface index is within the range of available interfaces. If not, it panics.
/// * Prints the name of the selected interface.
/// * Creates a new instance of `AsyncNdisapiAdapter` with the selected interface.
/// * Executes the `main_async` function using the previously defined adapter.
///
/// # Returns
///
/// * A `Result` that indicates whether the function succeeded or failed. The function returns `Ok(())` if it succeeded and `Err(e)` if it failed, where `e` is the error that occurred.
#[tokio::main]
async fn main() -> Result<()> {
    // Parsing command line arguments.
    let Cli {
        mut interface_index,
    } = Cli::parse();

    // Decrement interface index to match zero-based index.
    interface_index -= 1;

    // Create a new Ndisapi driver instance.
    let driver = Arc::new(
        Ndisapi::new("NDISRD").expect("WinpkFilter driver is not installed or failed to load!"),
    );

    // Print the detected version of the Windows Packet Filter.
    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    // Get a list of TCP/IP bound adapters in the system.
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    // Check if the selected interface index is within the range of available interfaces.
    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beyond the number of available interfaces");
    }

    // Print the name of the selected interface.
    println!("Using interface {}", adapters[interface_index].get_name(),);

    // Create a new instance of AsyncNdisapiAdapter with the selected interface.
    let mut adapter =
        AsyncNdisapiAdapter::new(Arc::clone(&driver), adapters[interface_index].get_handle())
            .unwrap();

    // Execute the main_async function using the previously defined adapter.
    main_async(&mut adapter).await;
    Ok(())
}
