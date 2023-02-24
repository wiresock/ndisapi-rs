use std::mem::{size_of, MaybeUninit};

use windows::{
    core::Result,
    Win32::Foundation::{GetLastError, HANDLE},
    Win32::System::IO::DeviceIoControl,
};

use super::Ndisapi;
use crate::driver::*;
use crate::ndisapi::defs::*;

pub const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001010E;

impl Ndisapi {
    /// Queries the packet filter mode for the selected network interface
    pub fn get_adapter_mode(&self, adapter_handle: HANDLE) -> Result<FilterFlags> {
        let mut adapter_mode = AdapterMode {
            adapter_handle,
            ..Default::default()
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_ADAPTER_MODE,
                Some(&adapter_mode as *const AdapterMode as *const std::ffi::c_void),
                size_of::<AdapterMode>() as u32,
                Some(&mut adapter_mode as *mut AdapterMode as *mut std::ffi::c_void),
                size_of::<AdapterMode>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(adapter_mode.flags)
        }
    }

    /// Queries current hardware packet filter (OID_GEN_CURRENT_PACKET_FILTER) for the specified network interface
    pub fn get_hw_packet_filter(&self, adapter_handle: HANDLE) -> Result<u32> {
        let mut oid = PacketOidData::new(adapter_handle, OID_GEN_CURRENT_PACKET_FILTER, 0u32);

        self.ndis_get_request::<_>(&mut oid)?;

        Ok(oid.data)
    }

    /// Queries the information about active WAN connections from the NDIS filter driver.
    pub fn get_ras_links(&self, adapter_handle: HANDLE, ras_links: &mut RasLinks) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_RAS_LINKS,
                Some(&adapter_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
                Some(ras_links as *const RasLinks as *mut std::ffi::c_void),
                size_of::<RasLinks>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// Queries information on available network interfaces
    pub fn get_tcpip_bound_adapters_info(&self) -> Result<Vec<NetworkAdapterInfo>> {
        let mut adapters: MaybeUninit<TcpAdapterList> = ::std::mem::MaybeUninit::uninit();

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_TCPIP_INTERFACES,
                Some(adapters.as_mut_ptr() as _),
                size_of::<TcpAdapterList>() as u32,
                Some(adapters.as_mut_ptr() as _),
                size_of::<TcpAdapterList>() as u32,
                None,
                None,
            )
        };

        if result.as_bool() {
            let mut result = Vec::new();
            let adapters = unsafe { adapters.assume_init() };

            for i in 0..adapters.adapter_count as usize {
                let adapter_name =
                    String::from_utf8(adapters.adapter_name_list[i].to_vec()).unwrap();
                let adapter_name = adapter_name.trim_end_matches(char::from(0)).to_owned();
                let next = NetworkAdapterInfo::new(
                    adapter_name,
                    adapters.adapter_handle[i],
                    adapters.adapter_medium_list[i],
                    adapters.current_address[i],
                    adapters.mtu[i],
                );
                result.push(next);
            }
            Ok(result)
        } else {
            Err(unsafe { GetLastError() }.into())
        }
    }

    /// Queries NDIS filter driver version
    pub fn get_version(&self) -> Result<Version> {
        let mut version = u32::MAX;

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_VERSION,
                Some(&mut version as *mut u32 as _),
                size_of::<u32>() as u32,
                Some(&mut version as *mut u32 as _),
                size_of::<u32>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(Version {
                major: (version & (0xF000)) >> 12,
                minor: (version & (0xFF000000)) >> 24,
                revision: (version & (0xFF0000)) >> 16,
            })
        }
    }

    /// This function is used to perform a query operation on the adapter pointed by oid_request.adapter_handle.
    /// With this function, it is possible to obtain various parameters of the network adapter, like the dimension
    /// of the internal buffers, the link speed or the counter of corrupted packets. The constants that define the
    /// operations are declared in the file ntddndis.h.
    pub fn ndis_get_request<T>(&self, oid_request: &mut PacketOidData<T>) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_NDIS_GET_REQUEST,
                Some(oid_request as *const PacketOidData<T> as *const std::ffi::c_void),
                size_of::<PacketOidData<T>>() as u32,
                Some(oid_request as *const PacketOidData<T> as *mut std::ffi::c_void),
                size_of::<PacketOidData<T>>() as u32,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// This function is used to perform a set operation on the adapter pointed by oid_request.adapter_handle.
    /// With this function, it is possible to set various parameters of the network adapter, like the dimension
    /// of the internal buffers, the link speed or the counter of corrupted packets. The constants that define the
    /// operations are declared in the file ntddndis.h.
    pub fn ndis_set_request<T>(&self, oid_request: &PacketOidData<T>) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_NDIS_SET_REQUEST,
                Some(oid_request as *const PacketOidData<T> as *const std::ffi::c_void),
                size_of::<PacketOidData<T>>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// The user application should create a Win32 event (with CreateEvent API call) and pass the event handle to this function.
    /// Helper driver will signal this event when TCP/IP bound adapter’s list changes (an example this happens on plug/unplug
    /// network card, disable/enable network connection or etc.).
    pub fn set_adapter_list_change_event(&self, event_handle: HANDLE) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_ADAPTER_EVENT,
                Some(&event_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// Sets the packet filter mode for the selected network interface
    /// adapter_handle: must be set to the interface handle (obtained via call to get_tcpip_bound_adapters_info).
    /// flags: combination of the XXX_LISTEN or XXX_TUNNEL flags:
    /// MSTCP_FLAG_SENT_TUNNEL – queue all packets sent from MSTCP to network interface. Original packet dropped.
    /// MSTCP_FLAG_RECV_TUNNEL – queue all packets indicated by network interface to MSTCP. Original packet dropped.
    /// MSTCP_FLAG_SENT_LISTEN – queue all packets sent from MSTCP to network interface. Original packet goes ahead.
    /// MSTCP_FLAG_RECV_LISTEN – queue all packets indicated by network interface to MSTCP. Original packet goes ahead.
    /// MSTCP_FLAG_FILTER_DIRECT – In promiscuous mode TCP/IP stack receives all packets in the Ethernet segment and replies
    /// with various ICMP packets, to prevent this set this flag. All packets with destination MAC different from
    /// FF-FF-FF-FF-FF-FF and network interface current MAC will never reach MSTCP.
    pub fn set_adapter_mode(&self, adapter_handle: HANDLE, flags: FilterFlags) -> Result<()> {
        let adapter_mode = AdapterMode {
            adapter_handle,
            flags,
        };

        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_ADAPTER_MODE,
                Some(&adapter_mode as *const AdapterMode as *const std::ffi::c_void),
                size_of::<AdapterMode>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// Sets current hardware packet filter (OID_GEN_CURRENT_PACKET_FILTER) for the specified network interface
    pub fn set_hw_packet_filter(&self, adapter_handle: HANDLE, filter: u32) -> Result<()> {
        let oid = PacketOidData::new(adapter_handle, OID_GEN_CURRENT_PACKET_FILTER, filter);

        self.ndis_set_request::<_>(&oid)?;

        Ok(())
    }

    /// The user application should create a Win32 event (with CreateEvent API call) and pass adapter handle and event handle
    /// to this function. The filter driver will signal this event when the hardware filter for the adapter changes.
    pub fn set_hw_packet_filter_event(&self, event_handle: HANDLE) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT,
                Some(&event_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }

    /// A user application should create a Win32 event (with CreateEvent API call) and pass the event handle to this function.
    /// The filter driver will signal this event when a WAN (dial-up, DSL, ADSL or etc.) connection is established or terminated.
    pub fn set_wan_event(&self, event_handle: HANDLE) -> Result<()> {
        let result = unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_SET_WAN_EVENT,
                Some(&event_handle as *const HANDLE as *const std::ffi::c_void),
                size_of::<HANDLE>() as u32,
                None,
                0,
                None,
                None,
            )
        };

        if !result.as_bool() {
            Err(unsafe { GetLastError() }.into())
        } else {
            Ok(())
        }
    }
}
