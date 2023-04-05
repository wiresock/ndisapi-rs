# NDISAPI

[![Crates.io](https://img.shields.io/crates/v/ndisapi.svg)](https://crates.io/crates/ndisapi)
[![Documentation](https://docs.rs/ndisapi/badge.svg)](https://docs.rs/ndisapi)
[![License](https://img.shields.io/crates/l/ndisapi)](https://github.com/firezone/ndisapi/blob/main/LICENSE)

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
ndisapi = "0.1.0"
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

## License

This project is licensed under the Apache License 2.0. See [LICENSE](https://github.com/firezone/ndisapi/blob/main/LICENSE) for details.

