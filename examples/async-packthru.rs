use clap::Parser;
use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, *};
use ndisapi_rs::{Ndisapi, AsyncNdisapiAdapter, IntermediateBuffer, FilterFlags, DirectionFlags, MacAddress};
use std::sync::Arc;
use tokio::sync::oneshot;
use windows::core::Result;

const PACKET_NUMBER: usize = 256;

/// This async function reads from the given AsyncNdisapiAdapter and handles the packets accordingly.
///
/// It sets the adapter mode to MSTCP_FLAG_SENT_RECEIVE_TUNNEL for intercepting packets sent and received by MSTCP.
/// It initializes a vector of IntermediateBuffers to store network packet data. Each IntermediateBuffer
/// provides a structure to handle raw packet data.
///
/// The function then enters a loop where it reads packets from the adapter.
/// If no packets are read, it prints a message and continues to the next iteration of the loop.
/// If an error occurs during reading, it simply continues to the next iteration of the loop.
///
/// When packets are successfully read, it partitions the packets into two collections based on whether
/// they are to be sent or received. The partitioning is done based on the `DirectionFlags` of the packet.
///
/// For each packet, it prints information about the packet and its direction.
/// After printing the packet info, it sends the packets back to the adapter or upwards to the MSTCP, depending on their direction.
/// If any error occurs during sending, it logs the error and continues.
///
/// # Arguments
///
/// * `adapter` - A mutable reference to the `AsyncNdisapiAdapter`.
///
/// # Returns
///
/// This function returns `Result<()>`. If any operation fails, it returns an `Err` variant with the error information.
/// If all operations succeed, it returns an `Ok` variant with unit `()`.
///
/// # Errors
///
/// This function may return an error if any operation on the `AsyncNdisapiAdapter` fails, such as setting the adapter mode,
/// reading packets, or sending packets.
///
async fn async_loop(adapter: &mut AsyncNdisapiAdapter) -> Result<()> {
    // Set the adapter mode to MSTCP_FLAG_SENT_RECEIVE_TUNNEL.
    adapter.set_adapter_mode(FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)?;

    // Initialize a vector of IntermediateBuffers, `ibs`, to store network packet data.
    // Each IntermediateBuffer is heap-allocated, providing a structure to handle raw packet data.
    let mut ibs: Vec<IntermediateBuffer> = vec![Default::default(); PACKET_NUMBER];

    loop {
        // Read packets from the adapter.
        let packets_read = match adapter
            .read_packets::<PACKET_NUMBER, _>(ibs.iter_mut())
            .await
        {
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

        println!("=======================================================================================================");

        for ib in ibs[0..packets_read].iter_mut() {
            // Print packet information.
            if ib.get_device_flags() == DirectionFlags::PACKET_FLAG_ON_SEND {
                println!("\nMSTCP --> Interface ({} bytes)\n", ib.get_length(),);
            } else {
                println!("\nInterface --> MSTCP ({} bytes)\n", ib.get_length(),);
            }

            // Print some information about the sliced packet.
            print_packet_info(ib);
        }

        // Partition the iterator into two collections based on the device flag.
        let (send_packets, receive_packets): (Vec<_>, Vec<_>) = ibs[0..packets_read]
            .iter_mut()
            .partition(|ib| ib.get_device_flags() == DirectionFlags::PACKET_FLAG_ON_SEND);

        // Re-inject packets back into the network stack
        match adapter.send_packets_to_adapter::<PACKET_NUMBER, _>(send_packets.into_iter()) {
            Ok(_) => {}
            Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
        }

        match adapter.send_packets_to_mstcp::<PACKET_NUMBER, _>(receive_packets.into_iter()) {
            Ok(_) => {}
            Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
        }
    }
}

/// This async function runs the main logic of the program.
async fn main_async(adapter: &mut AsyncNdisapiAdapter) {
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
        Ndisapi::new("NDISRD")
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

    // Create a new instance of AsyncNdisapiAdapter with the selected interface.
    let mut adapter =
        AsyncNdisapiAdapter::new(Arc::clone(&driver), adapters[interface_index].get_handle())
            .unwrap();

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
/// * `packet` - A mutable reference to an `IntermediateBuffer` containing the network packet.
///
/// # Examples
///
/// ```no_run
/// let mut packet: IntermediateBuffer = ...;
/// print_packet_info(&mut packet);
/// ```
fn print_packet_info(packet: &mut IntermediateBuffer) {
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
                    MacAddress::from_slice(&value.source()[..]).unwrap(),
                    MacAddress::from_slice(&value.destination()[..]).unwrap(),
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
