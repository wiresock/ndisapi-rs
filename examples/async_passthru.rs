use clap::Parser;
use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, *};
use ndisapi::NdisapiAdapter;
use std::sync::Arc;
use tokio::sync::oneshot;
use windows::{
    core::Result,
};

/// This async function reads from the given NdisapiAdapter and handles the packets accordingly.
async fn async_loop(adapter: &mut NdisapiAdapter) -> Result<()> {
    // Set the adapter mode to MSTCP_FLAG_SENT_RECEIVE_TUNNEL.
    adapter.set_adapter_mode(ndisapi::FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)?;

    // Allocate single IntermediateBuffer on the stack.
    let mut ib = ndisapi::IntermediateBuffer::default();

    // Initialize EthPacket to pass to driver API.
    let packet = ndisapi::EthPacket {
        buffer: &mut ib as *mut ndisapi::IntermediateBuffer,
    };

    loop {
        // Read a packet from the adapter.
        let result = adapter.read_packet(packet).await;
        if let Err(_) = result {
            continue;
        }

        // Print packet information.
        if ib.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
            println!("\nMSTCP --> Interface ({} bytes)\n", ib.get_length(),);
        } else {
            println!("\nInterface --> MSTCP ({} bytes)\n", ib.get_length(),);
        }

        // Print some information about the sliced packet.
        print_packet_info(&mut ib);

        // Re-inject the packet back into the network stack.
        if ib.get_device_flags() == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND {
            match adapter.send_packet_to_adapter(packet) {
                Ok(_) => {}
                Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
            };
        } else {
            match adapter.send_packet_to_mstcp(packet) {
                Ok(_) => {}
                Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
            }
        }
    }
}

/// This async function runs the main logic of the program.
async fn main_async(adapter: &mut NdisapiAdapter) {
    // Prompts the user to press ENTER to exit.
    println!("Press ENTER to exit");

    // Initializes a channel for communication between this function and a spawned thread.
    // `tx` is the transmitter and `rx` is the receiver end of the channel.
    let (tx, rx) = oneshot::channel::<()>();

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
        result = async_loop(adapter) => result,
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

// The main function of the program.
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
        ndisapi::Ndisapi::new("NDISRD")
            .expect("WinpkFilter driver is not installed or failed to load!"),
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

    // Create a new instance of NdisapiAdapter with the selected interface.
    let mut adapter =
        NdisapiAdapter::new(Arc::clone(&driver), adapters[interface_index].get_handle()).unwrap();

    // Execute the main_async function using the previously defined adapter.
    main_async(&mut adapter).await;
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
