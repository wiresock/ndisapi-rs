/// This example demonstrates the essential usage of active filtering modes for packet processing. It selects a
/// network interface and sets it into a filtering mode, where both sent and received packets are queued. The example
/// registers a Win32 event using the `Ndisapi::set_packet_event` function, and enters a waiting state for incoming packets.
/// Upon receiving a packet, its content is decoded and displayed on the console screen, providing a real-time view of
/// the network traffic.
use clap::Parser;
use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, *};
use windows::{
    core::Result,
    Win32::Foundation::HANDLE,
    Win32::System::Threading::{CreateEventW, WaitForSingleObject},
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

fn main() -> Result<()> {
    let Cli {
        mut interface_index,
        mut packets_number,
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

    println!(
        "Using interface {} with {} packets",
        adapters[interface_index].get_name(),
        packets_number
    );

    // Create Win32 event
    let event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?;
    }

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

    while packets_number > 0 {
        unsafe {
            WaitForSingleObject(event, u32::MAX);
        }
        while unsafe { driver.read_packet(&mut packet) }.ok().is_some() {
            // Print packet information
            if ib.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
                println!(
                    "\nMSTCP --> Interface ({} bytes) remaining packets {}\n",
                    ib.get_length(),
                    packets_number
                );
            } else {
                println!(
                    "\nInterface --> MSTCP ({} bytes) remaining packets {}\n",
                    ib.get_length(),
                    packets_number
                );
            }

            // Decrement packets counter
            packets_number -= 1;

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

            if packets_number == 0 {
                println!("Filtering complete\n");
                break;
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
