//! # Submodule: Basic NDISAPI functions
//!
//! This submodule provides a comprehensive set of functionalities for interacting with the Windows Packet Filter Kit,
//! allowing users to perform various actions on network adapters within Windows operating systems.
//! It includes methods for setting various adapter parameters, configuring packet filter modes,
//! handling hardware packet filters, and managing events related to adapter list changes
//! and WAN connections.

use std::mem::{size_of, MaybeUninit};

use windows::{core::Result, Win32::Foundation::HANDLE, Win32::System::IO::DeviceIoControl};

use super::Ndisapi;
use crate::driver::*;
use crate::ndisapi::defs::*;

pub const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001010E;

impl Ndisapi {
    /// This method takes an adapter handle as an argument and returns a Result containing
    /// the FilterFlags enum for the selected network interface. If an error occurs, the
    /// GetLastError function is called to retrieve the error and is then converted into
    /// a Result::Err variant.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle` - A HANDLE representing the network interface for which the
    ///   packet filter mode should be queried.
    ///
    /// # Returns
    ///
    /// * `Result<FilterFlags>` - A Result containing the FilterFlags enum for the selected
    ///   network interface if the query was successful, or an error if it failed.
    pub fn get_adapter_mode(&self, adapter_handle: HANDLE) -> Result<FilterFlags> {
        let mut adapter_mode = AdapterMode {
            adapter_handle,
            ..Default::default()
        };

        match unsafe {
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
        } {
            Ok(_) => Ok(adapter_mode.flags),
            Err(e) => Err(e),
        }
    }

    /// This method takes an adapter handle as an argument and returns a Result containing
    /// a u32 value representing the hardware packet filter for the specified network interface.
    /// If an error occurs, it will be propagated as a Result::Err variant.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle` - A HANDLE representing the network interface for which the
    ///   hardware packet filter should be queried.
    ///
    /// # Returns
    ///
    /// * `Result<u32>` - A Result containing a u32 value representing the hardware packet
    ///   filter for the specified network interface if the query was successful, or an error
    ///   if it failed.
    pub fn get_hw_packet_filter(&self, adapter_handle: HANDLE) -> Result<u32> {
        let mut oid = PacketOidData::new(adapter_handle, OID_GEN_CURRENT_PACKET_FILTER, 0u32);

        self.ndis_get_request::<_>(&mut oid)?;

        Ok(oid.data)
    }

    /// This method takes an adapter handle and a mutable reference to a RasLinks struct
    /// as arguments. It queries the active WAN connections from the NDIS filter driver
    /// and updates the `ras_links` argument with the received information. If an error
    /// occurs, it will be propagated as a Result::Err variant.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle` - A HANDLE representing the network interface for which the
    ///   active WAN connections should be queried.
    /// * `ras_links` - A mutable reference to a RasLinks struct that will be updated
    ///   with the information about active WAN connections.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A Result containing an empty tuple if the query was successful,
    ///   or an error if it failed.
    pub fn get_ras_links(&self, adapter_handle: HANDLE, ras_links: &mut RasLinks) -> Result<()> {
        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This method retrieves information about network interfaces that available to NDIS filter driver.
    /// It returns a Result containing a vector of NetworkAdapterInfo
    /// structs, which contain detailed information about each network interface.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<NetworkAdapterInfo>>` - A Result containing a vector of NetworkAdapterInfo
    /// structs representing the available network interfaces if the query was successful,
    /// or an error if it failed.
    pub fn get_tcpip_bound_adapters_info(&self) -> Result<Vec<NetworkAdapterInfo>> {
        let mut adapters: MaybeUninit<TcpAdapterList> = ::std::mem::MaybeUninit::uninit();

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_GET_TCPIP_INTERFACES,
                None,
                0,
                Some(adapters.as_mut_ptr() as _),
                size_of::<TcpAdapterList>() as u32,
                None,
                None,
            )
        } {
            Ok(_) => {
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
            }
            Err(e) => Err(e),
        }
    }

    /// This method retrieves the version of the NDIS filter driver currently running on the
    /// system. It returns a Result containing a Version struct with the major, minor, and
    /// revision numbers of the driver version.
    ///
    /// # Returns
    ///
    /// * `Result<Version>` - A Result containing a Version struct representing the NDIS
    ///   filter driver version if the query was successful, or an error if it failed.
    pub fn get_version(&self) -> Result<Version> {
        let mut version = u32::MAX;

        match unsafe {
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
        } {
            Ok(_) => Ok(Version {
                major: (version & (0xF000)) >> 12,
                minor: (version & (0xFF000000)) >> 24,
                revision: (version & (0xFF0000)) >> 16,
            }),
            Err(e) => Err(e),
        }
    }

    /// This function is used to obtain various parameters of the network adapter, such as the
    /// dimension of the internal buffers, the link speed, or the counter of corrupted packets.
    /// The constants that define the operations are declared in the file `ntddndis.h`.
    ///
    /// # Type Parameters
    ///
    /// * `T`: The type of data to be queried from the network adapter.
    ///
    /// # Arguments
    ///
    /// * `oid_request`: A mutable reference to a `PacketOidData<T>` struct that specifies
    ///   the adapter handle and the operation to perform.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A Result indicating whether the query operation was successful or not.
    ///   On success, returns `Ok(())`. On failure, returns an error.
    pub fn ndis_get_request<T>(&self, oid_request: &mut PacketOidData<T>) -> Result<()> {
        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This function is used to set various parameters of the network adapter, such as the
    /// dimension of the internal buffers, the link speed, or the counter of corrupted packets.
    /// The constants that define the operations are declared in the file `ntddndis.h`.
    ///
    /// # Type Parameters
    ///
    /// * `T`: The type of data to be set for the network adapter.
    ///
    /// # Arguments
    ///
    /// * `oid_request`: A reference to a `PacketOidData<T>` struct that specifies
    ///   the adapter handle and the operation to perform.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A Result indicating whether the set operation was successful or not.
    ///   On success, returns `Ok(())`. On failure, returns an error.
    pub fn ndis_set_request<T>(&self, oid_request: &PacketOidData<T>) -> Result<()> {
        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The user application should create a Win32 event (with the `CreateEvent` API call) and pass
    /// the event handle to this function. The helper driver will signal this event when the
    /// NDIS filter adapter's list changes, for example, when a network card is plugged/unplugged,
    /// a network connection is disabled/enabled, or other similar events.
    ///
    /// # Arguments
    ///
    /// * `event_handle`: A `HANDLE` to a Win32 event created by the user application.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A Result indicating whether setting the event was successful or not.
    ///   On success, returns `Ok(())`. On failure, returns an error.
    pub fn set_adapter_list_change_event(&self, event_handle: HANDLE) -> Result<()> {
        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Sets the packet filter mode for the selected network interface.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle`: A `HANDLE` to the network interface (obtained via call to `get_tcpip_bound_adapters_info`).
    /// * `flags`: A `FilterFlags` value representing the combination of packet filter mode flags.
    /// * `MSTCP_FLAG_SENT_TUNNEL` – Queue all packets sent from MSTCP to the network interface. Original packet dropped.
    /// * `MSTCP_FLAG_RECV_TUNNEL` – Queue all packets indicated by the network interface to MSTCP. Original packet dropped.
    /// * `MSTCP_FLAG_SENT_LISTEN` – Queue all packets sent from MSTCP to the network interface. Original packet goes ahead.
    /// * `MSTCP_FLAG_RECV_LISTEN` – Queue all packets indicated by the network interface to MSTCP. Original packet goes ahead.
    /// * `MSTCP_FLAG_FILTER_DIRECT` – In promiscuous mode, the TCP/IP stack receives all packets in the Ethernet segment and replies
    ///   with various ICMP packets. To prevent this, set this flag. All packets with destination MAC different from
    ///   FF-FF-FF-FF-FF-FF and the network interface's current MAC will never reach MSTCP.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A Result indicating whether setting the adapter mode was successful or not.
    ///   On success, returns `Ok(())`. On failure, returns an error.
    pub fn set_adapter_mode(&self, adapter_handle: HANDLE, flags: FilterFlags) -> Result<()> {
        let adapter_mode = AdapterMode {
            adapter_handle,
            flags,
        };

        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This method allows setting the hardware packet filter mode for the specified network interface by calling
    /// the `ndis_set_request` function.
    ///
    /// # Arguments
    ///
    /// * `adapter_handle`: A `HANDLE` to the network interface.
    /// * `filter`: A `u32` value representing the packet filter mode.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A Result indicating whether setting the hardware packet filter was successful or not.
    ///   On success, returns `Ok(())`. On failure, returns an error.
    pub fn set_hw_packet_filter(&self, adapter_handle: HANDLE, filter: u32) -> Result<()> {
        let oid = PacketOidData::new(adapter_handle, OID_GEN_CURRENT_PACKET_FILTER, filter);

        self.ndis_set_request::<_>(&oid)?;

        Ok(())
    }

    /// This method allows setting a Win32 event that will be signaled by the filter driver when the hardware packet
    /// filter for the network interface changes.
    ///
    /// # Arguments
    ///
    /// * `event_handle`: A `HANDLE` to the Win32 event created by the user application.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A Result indicating whether setting the hardware packet filter event was successful or not.
    ///   On success, returns `Ok(())`. On failure, returns an error.
    pub fn set_hw_packet_filter_event(&self, event_handle: HANDLE) -> Result<()> {
        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// This method allows setting a Win32 event that will be signaled by the filter driver when a WAN connection
    /// (such as dial-up, DSL, ADSL, etc.) is established or terminated.
    ///
    /// # Arguments
    ///
    /// * `event_handle`: A `HANDLE` to the Win32 event created by the user application.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - A Result indicating whether setting the WAN event was successful or not. On success,
    ///   returns `Ok(())`. On failure, returns an error.
    pub fn set_wan_event(&self, event_handle: HANDLE) -> Result<()> {
        match unsafe {
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
        } {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Retrieves the effective size of the Windows Packet Filter internal intermediate buffer pool.
    ///
    /// # Returns
    ///
    /// * `Result<u32>` - If the operation is successful, returns `Ok(pool_size)` where `pool_size`
    ///   is the size of the intermediate buffer pool. Otherwise, returns an `Err` with the error code.
    ///
    /// This function retrieves the size of the intermediate buffer pool used by the driver.
    /// It uses `DeviceIoControl` with the `IOCTL_NDISRD_QUERY_IB_POOL_SIZE` code to perform the operation.
    pub fn get_intermediate_buffer_pool_size(&self) -> Result<u32> {
        let mut pool_size: u32 = 0;

        match unsafe {
            DeviceIoControl(
                self.driver_handle,
                IOCTL_NDISRD_QUERY_IB_POOL_SIZE,
                None,
                0,
                Some(&mut pool_size as *mut u32 as _),
                size_of::<u32>() as u32,
                None,
                None,
            )
        } {
            Ok(_) => Ok(pool_size),
            Err(e) => Err(e),
        }
    }
}
