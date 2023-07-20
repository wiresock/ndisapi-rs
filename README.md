# NDISAPI

[![Crates.io](https://img.shields.io/crates/v/ndisapi.svg)](https://crates.io/crates/ndisapi)
[![Documentation](https://docs.rs/ndisapi/badge.svg)](https://docs.rs/ndisapi)
[![License](https://img.shields.io/crates/l/ndisapi)](https://github.com/wiresock/ndisapi/blob/main/LICENSE)

NDISAPI is a Rust crate for interacting with the [Windows Packet Filter](https://www.ntkernel.com/windows-packet-filter/) driver. It provides an easy-to-use, safe, and efficient interface to efficiently filter (inspect and modify) raw network packets at the NDIS level of the network stack with minimal impact on network activity.

Windows Packet Filter (WinpkFilter) is a high-performance, lightweight packet filtering framework for Windows, enabling developers to efficiently inspect, modify, and control raw network packets at the NDIS level. With user-friendly APIs and support for various Windows versions, WinpkFilter simplifies network packet manipulation without requiring kernel-mode programming expertise.

## Features

- Enumerate network adapters
- Query and set network adapter properties
- Capture and analyze packets
- Filter and modify packets
- Send raw packets

## Dependencies

- Rust 1.58.0 or later
- Windows 7, 8, 10, or 11
- [Windows Packet Filter](https://github.com/wiresock/ndisapi/releases) driver installed

## Installation

Add the following to your `Cargo.toml` file:

```toml
[dependencies]
ndisapi = "0.5.1"
```

## Usage

Here's an example of how to enumerate network adapters and print their information:

```rust
use ndisapi::{MacAddress, Ndisapi};

fn main() {
    let ndis = Ndisapi::new("NDISRD").expect("Failed to create NdisApi instance");

    let adapters = ndis
        .get_tcpip_bound_adapters_info()
        .expect("Failed to enumerate adapters");

    for adapter in adapters {
        println!("Adapter: {:?}", adapter.get_name());
        println!(
            "Description: {:?}",
            Ndisapi::get_friendly_adapter_name(adapter.get_name()).unwrap_or("Unknown".to_string())
        );
        println!(
            "MAC Address: {:?}",
            MacAddress::from_slice(adapter.get_hw_address()).unwrap_or_default()
        );
        println!("-------------------------------");
    }
}
```

For more examples and in-depth usage, check out the [documentation](https://docs.rs/ndisapi).

## Demo

Here is an example of how to run the `listadapters` example:

```bash
PS D:\firezone\ndisapi> cargo run --example listadapters
   Compiling ndisapi v0.5.1 (D:\firezone\ndisapi)
    Finished dev [unoptimized + debuginfo] target(s) in 3.22s
     Running `target\debug\examples\listadapters.exe`
Detected Windows Packet Filter version 3.4.3
1. Local Area Connection* 10
        \DEVICE\{EDEE8C42-F604-4A7B-BFAA-6B110923217E}
         Medium: 0
         MAC: 9A:47:3D:60:26:9D
         MTU: 1500
         FilterFlags: FilterFlags(0x0)
Getting OID_GEN_CURRENT_PACKET_FILTER Error: Data error (cyclic redundancy check).
         OID_802_3_CURRENT_ADDRESS: 9A:47:3D:60:26:9D
2. vEthernet (Default Switch)
        \DEVICE\{6FE04972-B2B5-4F5C-97E6-B8518A017192}
         Medium: 0
         MAC: 00:15:5D:91:A3:15
         MTU: 1500
         FilterFlags: FilterFlags(0x0)
         OID_GEN_CURRENT_PACKET_FILTER: 0x0000000B
         OID_802_3_CURRENT_ADDRESS: 00:15:5D:91:A3:15
...

12. vEthernet (WLAN Virtual Switch)
        \DEVICE\{05F9267C-C548-4822-8535-9A57F1A99DB7}
         Medium: 0
         MAC: 18:47:3D:60:26:9D
         MTU: 1500
         FilterFlags: FilterFlags(0x0)
         OID_GEN_CURRENT_PACKET_FILTER: 0x0000000B
         OID_802_3_CURRENT_ADDRESS: 18:47:3D:60:26:9D

```

Following is the demonstration of the async-packthru example. For this scenario, we will assume that `vEthernet (WLAN Virtual Switch)` is the default internet connection

```bash
PS D:\firezone\ndisapi> cargo run --example async-packthru -- --interface-index 12
    Finished dev [unoptimized + debuginfo] target(s) in 0.11s
     Running `target\debug\examples\async-packthru.exe --interface-index 12`
Detected Windows Packet Filter version 3.4.3
Using interface \DEVICE\{05F9267C-C548-4822-8535-9A57F1A99DB7}
Press ENTER to exit
=======================================================================================================

Interface --> MSTCP (93 bytes)

  Ipv4 Address([142, 250, 102, 108]) => Address([192, 168, 3, 126])
   TCP 993 -> 54163
=======================================================================================================

MSTCP --> Interface (89 bytes)

  Ipv4 Address([192, 168, 3, 126]) => Address([142, 250, 102, 108])
   TCP 54163 -> 993
=======================================================================================================

Interface --> MSTCP (60 bytes)

  Ipv4 Address([142, 250, 102, 108]) => Address([192, 168, 3, 126])
   TCP 993 -> 54163
=======================================================================================================

Interface --> MSTCP (202 bytes)

  Ipv4 Address([192, 168, 3, 105]) => Address([224, 0, 0, 251])
   UDP 5353 -> 5353

Interface --> MSTCP (222 bytes)

  Ipv6 Address([254, 128, 0, 0, 0, 0, 0, 0, 18, 44, 107, 255, 254, 84, 37, 126]) => Address([255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 251])
   UDP 5353 -> 5353
=======================================================================================================

Interface --> MSTCP (118 bytes)

  Ipv4 Address([142, 250, 102, 108]) => Address([192, 168, 3, 126])
   TCP 993 -> 54163
=======================================================================================================

MSTCP --> Interface (115 bytes)

  Ipv4 Address([192, 168, 3, 126]) => Address([142, 250, 102, 108])
   TCP 54163 -> 993
=======================================================================================================

Interface --> MSTCP (60 bytes)

  Ipv4 Address([142, 250, 102, 108]) => Address([192, 168, 3, 126])
   TCP 993 -> 54163
=======================================================================================================

MSTCP --> Interface (74 bytes)

  Ipv4 Address([192, 168, 3, 126]) => Address([158, 255, 51, 217])
   UDP 63616 -> 59999
=======================================================================================================

Interface --> MSTCP (80 bytes)

  Ipv4 Address([192, 168, 3, 105]) => Address([224, 0, 0, 251])
   UDP 5353 -> 5353

Interface --> MSTCP (100 bytes)

  Ipv6 Address([254, 128, 0, 0, 0, 0, 0, 0, 18, 44, 107, 255, 254, 84, 37, 126]) => Address([255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 251])
   UDP 5353 -> 5353

Shutting down...
```

## License

This project is licensed under the Apache License 2.0. See [LICENSE](https://github.com/wiresock/ndisapi/blob/main/LICENSE) for details.

