//! # Submodule: Basic NDISAPI driver I/O control codes
//!
//! This submodule provides a collection of constants for IOCTL (Input/Output Control) codes
//! and the `ctl_code` function used to generate these codes.
//!
//! IOCTL codes are used by the Windows Packet Filter driver to communicate with the driver
//! and perform various operations such as setting packet filters, reading packets, and sending
//! packets to the adapter or MSTCP stack.
//!
//! The `ctl_code` function is used to create the IOCTL codes by taking the device type, function,
//! method, and access as input parameters.

// Device and ioctl codes
/// FILE_DEVICE_NDISRD: A constant u32 value representing the NDISRD device type.
const FILE_DEVICE_NDISRD: u32 = 0x00008300;

/// NDISRD_IOCTL_INDEX: A constant u32 value representing the NDISRD IOCTL index.
const NDISRD_IOCTL_INDEX: u32 = 0x830;

/// METHOD_BUFFERED: A constant u32 value representing the buffered method.
const METHOD_BUFFERED: u32 = 0;

/// FILE_ANY_ACCESS: A constant u32 value representing any file access.
const FILE_ANY_ACCESS: u32 = 0;

/// ctl_code function creates an IOCTL control code from the specified device type, function, method, and access values.
///
/// # Arguments
/// * `device_type`: A u32 representing the device type.
/// * `function`: A u32 representing the function.
/// * `method`: A u32 representing the method.
/// * `access`: A u32 representing the access type.
///
/// # Returns
/// * A u32 value representing the resulting IOCTL control code.
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// IOCTL_NDISRD_GET_VERSION: A constant u32 value representing the IOCTL code to get the NDISRD version.
pub const IOCTL_NDISRD_GET_VERSION: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_GET_TCPIP_INTERFACES: A constant u32 value representing the IOCTL code to get the TCPIP interfaces.
pub const IOCTL_NDISRD_GET_TCPIP_INTERFACES: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 1,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER: A constant u32 value representing the IOCTL code to send a packet to the adapter.
pub const IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 2,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SEND_PACKET_TO_MSTCP: A constant u32 value representing the IOCTL code to send a packet to MSTCP.
pub const IOCTL_NDISRD_SEND_PACKET_TO_MSTCP: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 3,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_READ_PACKET: A constant u32 value representing the IOCTL code to read a packet.
pub const IOCTL_NDISRD_READ_PACKET: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 4,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SET_ADAPTER_MODE: A constant u32 value representing the IOCTL code to set the adapter mode.
pub const IOCTL_NDISRD_SET_ADAPTER_MODE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 5,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE: A constant u32 value representing the IOCTL code to flush the adapter queue.
pub const IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 6,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SET_EVENT: A constant u32 value representing the IOCTL code to set a queued packet event.
pub const IOCTL_NDISRD_SET_EVENT: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 7,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_NDIS_SET_REQUEST: A constant u32 value representing the IOCTL code for an NDIS set request.
pub const IOCTL_NDISRD_NDIS_SET_REQUEST: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 8,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_NDIS_GET_REQUEST: A constant u32 value representing the IOCTL code for an NDIS get request.
pub const IOCTL_NDISRD_NDIS_GET_REQUEST: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 9,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SET_WAN_EVENT: A constant u32 value representing the IOCTL code to set a WAN event.
pub const IOCTL_NDISRD_SET_WAN_EVENT: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 10,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SET_ADAPTER_EVENT: A constant u32 value representing the IOCTL code to set an adapters list change event.
pub const IOCTL_NDISRD_SET_ADAPTER_EVENT: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 11,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_ADAPTER_QUEUE_SIZE: A constant u32 value representing the IOCTL code to get the adapter queue size.
pub const IOCTL_NDISRD_ADAPTER_QUEUE_SIZE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 12,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_GET_ADAPTER_MODE: A constant u32 value representing the IOCTL code to get the adapter mode.
pub const IOCTL_NDISRD_GET_ADAPTER_MODE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 13,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SET_PACKET_FILTERS: A constant u32 value representing the IOCTL code to set packet filters.
pub const IOCTL_NDISRD_SET_PACKET_FILTERS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 14,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_RESET_PACKET_FILTERS: A constant u32 value representing the IOCTL code to reset packet filters.
pub const IOCTL_NDISRD_RESET_PACKET_FILTERS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 15,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE: A constant u32 value representing the IOCTL code to get the packet filters table size.
pub const IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 16,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_GET_PACKET_FILTERS: A constant u32 value representing the IOCTL code to get packet filters.
pub const IOCTL_NDISRD_GET_PACKET_FILTERS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 17,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS: A constant u32 value representing the IOCTL code to get packet filters and reset their statistics.
pub const IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 18,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_GET_RAS_LINKS: A constant u32 value representing the IOCTL code to get active RAS links.
pub const IOCTL_NDISRD_GET_RAS_LINKS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 19,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER: A constant u32 value representing the IOCTL code to send packets to the adapter.
pub const IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 20,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP: A constant u32 value representing the IOCTL code to send packets to the MSTCP.
pub const IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 21,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_READ_PACKETS: A constant u32 value representing the IOCTL code to read packets.
pub const IOCTL_NDISRD_READ_PACKETS: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 22,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT: A constant u32 value representing the IOCTL code to set the adapter hardware filter change event.
pub const IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 23,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_INITIALIZE_FAST_IO: A constant u32 value representing the IOCTL code to initialize fast I/O.
pub const IOCTL_NDISRD_INITIALIZE_FAST_IO: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 24,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_READ_PACKETS_UNSORTED: A constant u32 value representing the IOCTL code to read packets unsorted.
pub const IOCTL_NDISRD_READ_PACKETS_UNSORTED: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 25,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED: A constant u32 value representing the IOCTL code to send packets to the adapter unsorted.
pub const IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 26,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED: A constant u32 value representing the IOCTL code to send packets to the MSTCP unsorted.
pub const IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 27,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION: A constant u32 value representing the IOCTL code to add a second fast I/O section.
pub const IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 28,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// IOCTL_NDISRD_QUERY_IB_POOL_SIZE: A constant u32 value representing the IOCTL code to query the effective size of the Windows Packet Filter internal intermediate buffer pool.
pub const IOCTL_NDISRD_QUERY_IB_POOL_SIZE: u32 = ctl_code(
    FILE_DEVICE_NDISRD,
    NDISRD_IOCTL_INDEX + 29,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
