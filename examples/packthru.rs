/// This example demonstrates the fundamental usage of active filtering modes in packet processing. By selecting a
/// network interface and configuring it to operate in a filtering mode, both sent and received packets are queued.
/// The example registers a Win32 event through the `set_packet_event` function and enters a waiting state
/// for incoming packets. As packets are received, their content is decoded and printed on the console screen, offering
/// a real-time visualization of network traffic. This example resembles the `passthru` utility but employs bulk
/// packet sending and receiving to optimize performance.
use clap::Parser;
use ndisapi_rs::{DirectionFlags, EthMRequest, FilterFlags, IntermediateBuffer, Ndisapi};
use smoltcp::wire::{
    ArpPacket, EthernetFrame, EthernetProtocol, Icmpv4Packet, Icmpv6Packet, IpProtocol, Ipv4Packet,
    Ipv6Packet, TcpPacket, UdpPacket,
};
use windows::{
    core::Result,
    Win32::Foundation::HANDLE,
    Win32::{
        Foundation::CloseHandle,
        System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
    },
};

#[derive(Parser)]
struct Cli {
    /// Network interface index (please use listadapters example to determine the right one)
    #[clap(short, long)]
    interface_index: usize,
    /// Number of packets to read from the specified network interface
    #[clap(short, long)]
    packets_number: usize,
}

const PACKET_NUMBER: usize = 256;

fn main() -> Result<()> {
    // Parse command line arguments.
    let Cli {
        mut interface_index,
        mut packets_number,
    } = Cli::parse();

    // Decrement the interface index since it's zero-based.
    interface_index -= 1;

    // Initialize the NDISAPI driver.
    let driver =
        Ndisapi::new("NDISRD").expect("WinpkFilter driver is not installed or failed to load!");

    // Print the detected Windows Packet Filter version.
    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    // Get a list of TCP/IP bound adapters.
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    // Validate the user-specified interface index.
    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beyond the number of available interfaces");
    }

    // Print the selected interface and number of packets to process.
    println!(
        "Using interface {} with {} packets",
        adapters[interface_index].get_name(),
        packets_number
    );

    // Create a Win32 event.
    let event: HANDLE = unsafe { CreateEventW(None, true, false, None)? };

    // Set the event within the driver.
    driver.set_packet_event(adapters[interface_index].get_handle(), event)?;

    // Put the network interface into tunnel mode.
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
    )?;

    // Initialize a container to store IntermediateBuffers allocated on the heap.
    let mut ibs: Vec<IntermediateBuffer> = vec![Default::default(); PACKET_NUMBER];

    // Initialize containers to read/write IntermediateBuffers from/to the driver.
    let mut to_read =
        EthMRequest::from_iter(adapters[interface_index].get_handle(), ibs.iter_mut());
    let mut to_mstcp: EthMRequest<PACKET_NUMBER> =
        EthMRequest::new(adapters[interface_index].get_handle());
    let mut to_adapter: EthMRequest<PACKET_NUMBER> =
        EthMRequest::new(adapters[interface_index].get_handle());

    // Main loop: Process packets until the specified number of packets is reached.
    while packets_number > 0 {
        // Wait for the event to be signaled.
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }

        // Read packets from the driver.
        let mut packets_read: usize;
        while {
            packets_read = driver
                .read_packets::<PACKET_NUMBER>(&mut to_read)
                .unwrap_or(0usize);
            packets_read > 0
        } {
            // Decrement the packets counter.
            packets_number = packets_number.saturating_sub(packets_read);

            // Process each packet.
            for (i, packet) in to_read.drain_success().enumerate() {
                let direction_flags = packet.get_device_flags();

                // Print packet direction and remaining packets.
                if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                    println!(
                        "\nMSTCP --> Interface ({} bytes) remaining packets {}\n",
                        packet.get_length(),
                        packets_number + (packets_read - i)
                    );
                } else {
                    println!(
                        "\nInterface --> MSTCP ({} bytes) remaining packets {}\n",
                        packet.get_length(),
                        packets_number + (packets_read - i)
                    );
                }

                // Print packet information
                print_packet_info(packet);

                if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                    to_adapter.push(packet)?;
                } else {
                    to_mstcp.push(packet)?;
                }
            }

            // Re-inject packets back into the network stack
            if to_adapter.get_packet_number() > 0 {
                match driver.send_packets_to_adapter::<PACKET_NUMBER>(&to_adapter) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
                }
            }

            if !to_mstcp.get_packet_number() > 0 {
                match driver.send_packets_to_mstcp::<PACKET_NUMBER>(&to_mstcp) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
                };
            }

            match to_read.append(to_mstcp.drain().chain(to_adapter.drain())) {
                Ok(_) => {}
                Err(err) => println!("Error consuming processed packets. Error code = {err}"),
            }

            if packets_number == 0 {
                println!("Filtering complete\n");
                break;
            }
        }

        unsafe {
            ResetEvent(event); // Reset the event to continue waiting for packets to arrive.
        }
    }

    // Put the network interface into default mode.
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::default(),
    )?;

    unsafe {
        CloseHandle(event); // Close the event handle.
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
/// * `packet` - A mutable reference to an `IntermediateBuffer` containing the network packet.
///
/// # Examples
///
/// ```no_run
/// let mut packet: IntermediateBuffer = ...;
/// print_packet_info(&mut packet);
/// ```
fn print_packet_info(packet: &mut IntermediateBuffer) {
    let mut eth_hdr = EthernetFrame::new_unchecked(packet.get_data_mut());
    match eth_hdr.ethertype() {
        EthernetProtocol::Ipv4 => {
            let mut ipv4_packet = Ipv4Packet::new_unchecked(eth_hdr.payload_mut());
            println!(
                "  Ipv4 {:?} => {:?}",
                ipv4_packet.src_addr(),
                ipv4_packet.dst_addr()
            );
            match ipv4_packet.next_header() {
                IpProtocol::Icmp => {
                    let icmp_packet = Icmpv4Packet::new_unchecked(ipv4_packet.payload_mut());
                    println!(
                        "ICMPv4: Type: {:?} Code: {:?}",
                        icmp_packet.msg_type(),
                        icmp_packet.msg_code()
                    );
                }
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload_mut());
                    println!(
                        "   TCP {:?} -> {:?}",
                        tcp_packet.src_port(),
                        tcp_packet.dst_port()
                    );
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload_mut());
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
            let mut ipv6_packet = Ipv6Packet::new_unchecked(eth_hdr.payload_mut());
            println!(
                "  Ipv6 {:?} => {:?}",
                ipv6_packet.src_addr(),
                ipv6_packet.dst_addr()
            );
            match ipv6_packet.next_header() {
                IpProtocol::Icmpv6 => {
                    let icmpv6_packet = Icmpv6Packet::new_unchecked(ipv6_packet.payload_mut());
                    println!(
                        "ICMPv6 packet: Type: {:?} Code: {:?}",
                        icmpv6_packet.msg_type(),
                        icmpv6_packet.msg_code()
                    );
                }
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv6_packet.payload_mut());
                    println!(
                        "   TCP {:?} -> {:?}",
                        tcp_packet.src_port(),
                        tcp_packet.dst_port()
                    );
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv6_packet.payload_mut());
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
            let arp_packet = ArpPacket::new_unchecked(eth_hdr.payload_mut());
            println!("ARP packet: {:?}", arp_packet);
        }
        EthernetProtocol::Unknown(_) => {
            println!("Unknown Ethernet packet: {:?}", eth_hdr);
        }
    }
}
