use std::{
    mem::{self, size_of},
    ptr::write_bytes,
};

use ndisapi::{MacAddress, Ndisapi};
use windows::core::Result;

const OID_802_3_CURRENT_ADDRESS: u32 = 0x01010102;

fn main() -> Result<()> {
    let driver = ndisapi::Ndisapi::new(ndisapi::NDISRD_DRIVER_NAME)
        .expect("WinpkFilter driver is not installed or failed to load!");

    println!(
        "Detected Windows Packet Filter version {}",
        driver.get_version()?
    );

    let adapters = driver.get_tcpip_bound_adapters_info()?;

    for (index, adapter) in adapters.iter().enumerate() {
        // Display the information about each network interface provided by the get_tcpip_bound_adapters_info
        let network_interface_name = match Ndisapi::get_friendly_adapter_name(adapter.get_name()) {
            Ok(interface_name) => interface_name,
            Err(err) => format!(r#"UNKNOWN NETWORK INTERFACE Error code: {err}"#),
        };
        println!(
            "{}. {}\n\t{}",
            index + 1,
            network_interface_name,
            adapter.get_name(),
        );
        println!("\t Medium: {}", adapter.get_medium());
        println!(
            "\t MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            adapter.get_hw_address()[0],
            adapter.get_hw_address()[1],
            adapter.get_hw_address()[2],
            adapter.get_hw_address()[3],
            adapter.get_hw_address()[4],
            adapter.get_hw_address()[5]
        );
        println!("\t MTU: {}", adapter.get_mtu());
        println!(
            "\t FilterFlags: {:?}",
            driver.get_adapter_mode(adapter.get_handle()).unwrap()
        );

        // Query hardware packet filter for the adapter using built wrapper for ndis_get_request
        match driver.get_hw_packet_filter(adapter.get_handle()) {
            Err(err) => println!(
                "Getting OID_GEN_CURRENT_PACKET_FILTER Error: {}",
                err.message().to_string_lossy()
            ),
            Ok(current_packet_filter) => {
                println!("\t OID_GEN_CURRENT_PACKET_FILTER: 0x{current_packet_filter:08X}")
            }
        }

        // Query MAC address of the network adapter using ndis_get_request directly
        let mut current_address_request = ndisapi::PacketOidData::new(
            adapter.get_handle(),
            OID_802_3_CURRENT_ADDRESS,
            ndisapi::MacAddress::default(),
        );
        if let Err(err) = driver.ndis_get_request::<_>(&mut current_address_request) {
            println!(
                "Getting OID_802_3_CURRENT_ADDRESS Error: {}",
                err.message().to_string_lossy()
            )
        } else {
            println!(
                "\t OID_802_3_CURRENT_ADDRESS: {}",
                current_address_request.data
            )
        }

        if Ndisapi::is_ndiswan_ip(adapter.get_name())
            || Ndisapi::is_ndiswan_ipv6(adapter.get_name())
        {
            let mut ras_links_vec: Vec<ndisapi::RasLinks> = Vec::with_capacity(1);
            // SAFETY: ndisapi::RasLinks is too large to allocate memory on the stack and results in a stackoverflow error
            // Here is the workaround get a raw pointer to the vector with capacity to hold one ndisapi::RasLinks structure,
            // zero initialize the vector allocated memory and then set a vector length to one
            unsafe {
                write_bytes::<u8>(
                    mem::transmute(ras_links_vec.as_mut_ptr()),
                    0,
                    size_of::<ndisapi::RasLinks>(),
                );
                ras_links_vec.set_len(1)
            };
            let ras_links = &mut ras_links_vec[0];

            if let Ok(()) = driver.get_ras_links(adapter.get_handle(), ras_links) {
                println!(
                    "Number of active WAN links: {}",
                    ras_links.get_number_of_links()
                );

                for k in 0..ras_links.get_number_of_links() {
                    println!(
                        "\t{}) LinkSpeed = {} MTU = {}",
                        k,
                        ras_links.ras_links[k].get_link_speed(),
                        ras_links.ras_links[k].get_maximum_total_size()
                    );

                    let local_mac_address =
                        MacAddress::from_slice(ras_links.ras_links[k].get_local_address()).unwrap();
                    let remote_mac_address =
                        MacAddress::from_slice(ras_links.ras_links[k].get_remote_address())
                            .unwrap();

                    println!("\t\tLocal MAC:\t {local_mac_address}");

                    println!("\t\tRemote MAC:\t {remote_mac_address}");

                    if Ndisapi::is_ndiswan_ip(adapter.get_name()) {
                        // Windows Vista and later offsets are used
                        println!(
                            "\t\tIP address:\t {}.{}.{}.{} mask {}.{}.{}.{}",
                            ras_links.ras_links[k].get_protocol_buffer()[584],
                            ras_links.ras_links[k].get_protocol_buffer()[585],
                            ras_links.ras_links[k].get_protocol_buffer()[586],
                            ras_links.ras_links[k].get_protocol_buffer()[587],
                            ras_links.ras_links[k].get_protocol_buffer()[588],
                            ras_links.ras_links[k].get_protocol_buffer()[589],
                            ras_links.ras_links[k].get_protocol_buffer()[590],
                            ras_links.ras_links[k].get_protocol_buffer()[591],
                        );
                    } else {
                        // IP v.6
                        println!(
                            "\t\tIPv6 address (without prefix):\t {:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}",
                            ras_links.ras_links[k].get_protocol_buffer()[588],
                            ras_links.ras_links[k].get_protocol_buffer()[589],
                            ras_links.ras_links[k].get_protocol_buffer()[590],
                            ras_links.ras_links[k].get_protocol_buffer()[591],
                            ras_links.ras_links[k].get_protocol_buffer()[592],
                            ras_links.ras_links[k].get_protocol_buffer()[593],
                            ras_links.ras_links[k].get_protocol_buffer()[594],
                            ras_links.ras_links[k].get_protocol_buffer()[595],
                        );
                    }
                }
            } else {
                println!("Failed to query active WAN links information.");
            }
        }
    }

    let mtu_decrement = ndisapi::Ndisapi::get_mtu_decrement().unwrap_or(0);

    println!("\nSystem wide MTU decrement: {mtu_decrement}");

    Ok(())
}
