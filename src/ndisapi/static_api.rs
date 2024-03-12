//! # Submodule: Static NDISAPI functions
//!
//! This module provides utility functions for interacting with the Windows Registry related
//! to NDIS Filter driver and network interfaces. It defines constants for various Registry keys,
//! values, and data types that are used to access and modify settings related to network interfaces.
//! It also contains an //! implementation of Ndisapi that includes functions for setting and retrieving
//! Registry values related to NDIS filter driver and network interfaces.
//!

use windows::{
    core::{s, w, Result, PCWSTR, PWSTR},
    Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExA, RegQueryValueExW,
        RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_VALUE_TYPE,
    },
};

use super::Ndisapi;
use std::str;

/// The registry key path for the network control class.
const REGSTR_NETWORK_CONTROL_CLASS: ::windows::core::PCWSTR =
    w!(r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}");

/// The name of the registry value.
const REGSTR_VAL_NAME: ::windows::core::PCWSTR = w!("Name");

/// The name of the registry value containing the component ID.
const REGSTR_COMPONENTID: ::windows::core::PCSTR = s!("ComponentId");

/// The name of the registry value containing the linkage information.
const REGSTR_LINKAGE: ::windows::core::PCWSTR = w!("Linkage");

/// The name of the registry value containing the export information.
const REGSTR_EXPORT: ::windows::core::PCSTR = s!("Export");

/// The name of the registry value containing the MTU decrement value.
const REGSTR_MTU_DECREMENT: ::windows::core::PCWSTR = w!("MTUDecrement");

/// The name of the registry value containing the network adapter startup filter mode value.
const REGSTR_STARTUP_MODE: ::windows::core::PCWSTR = w!("StartupMode");

/// The name of the registry value containing theintermediate buffer pool size multiplier.
const REGSTR_POOL_SIZE: ::windows::core::PCWSTR = w!("PoolSize");

/// The component ID for the NDIS WAN IP driver.
const REGSTR_COMPONENTID_NDISWANIP: &str = "ms_ndiswanip";

/// The component ID for the NDIS WAN IPv6 driver.
const REGSTR_COMPONENTID_NDISWANIPV6: &str = "ms_ndiswanipv6";

/// The component ID for the NDIS WAN BH driver.
const REGSTR_COMPONENTID_NDISWANBH: &str = "ms_ndiswanbh";

/// The user-friendly name for the NDIS WAN IP interface.
const USER_NDISWANIP: &str = "WAN Network Interface (IP)";

/// The user-friendly name for the NDIS WAN BH interface.
const USER_NDISWANBH: &str = "WAN Network Interface (BH)";

/// The user-friendly name for the NDIS WAN IPv6 interface.
const USER_NDISWANIPV6: &str = "WAN Network Interface (IPv6)";

impl Ndisapi {
    /// Determines if a given network interface is an NDISWAN interface.
    ///
    /// This function enumerates all subkeys of the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`,
    /// and looks for the specified `component_id` (e.g., "ms_ndiswanip", "ms_ndiswanipv6", "ms_ndiswanbh").
    /// If a match is found, it checks the linkage subkey and export string to determine if the interface is an NDISWAN interface.
    ///
    /// # Arguments
    ///
    /// * `adapter_name: impl Into<String>`: The name of the network adapter to check.
    /// * `component_id: &str`: The component ID to look for in the registry (e.g., "ms_ndiswanip", "ms_ndiswanipv6", "ms_ndiswanbh").
    ///
    /// # Returns
    ///
    /// * `Result<bool>`: If successful, returns `Ok(true)` if the interface is an NDISWAN interface, `Ok(false)` otherwise.
    ///   If an error occurs, returns an error.
    fn is_ndiswan_interface(adapter_name: impl Into<String>, component_id: &str) -> Result<bool> {
        let adapter_name = adapter_name.into();
        // Handles to registry keys
        let mut target_key = HKEY::default();
        let mut connection_key = HKEY::default();
        let mut linkage_key = HKEY::default();

        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                REGSTR_NETWORK_CONTROL_CLASS,
                0,
                KEY_READ,
                &mut target_key,
            ).ok()
        };

        if result.is_err() {
            return Err(result.err().unwrap());
        }

        // Counter for enumerating registry keys
        let mut index = 0u32;

        // Buffers for storing registry values
        let mut buffer = vec![0u16; 256];
        let mut buffer_size = buffer.len() as u32;
        let mut temp_buffer = vec![0u8; 256];
        let mut temp_buffer_size = temp_buffer.len() as u32;

        // Set to true if found
        let mut found = false;

        while !found {
            let result = unsafe {
                RegEnumKeyExW(
                    target_key,
                    index,
                    PWSTR::from_raw(buffer.as_mut_ptr()),
                    &mut buffer_size as *mut u32,
                    None,
                    PWSTR::null(),
                    None,
                    None,
                )
            };

            if result.is_err() {
                break;
            } else {
                let result = unsafe {
                    RegOpenKeyExW(
                        target_key,
                        PCWSTR::from_raw(buffer.as_ptr()),
                        0,
                        KEY_READ,
                        &mut connection_key,
                    )
                };

                if result.is_ok() {
                    let mut value_type = REG_VALUE_TYPE::default();
                    let result = unsafe {
                        RegQueryValueExA(
                            connection_key,
                            REGSTR_COMPONENTID,
                            None,
                            Some(&mut value_type),
                            Some(temp_buffer.as_mut_ptr()),
                            Some(&mut temp_buffer_size),
                        )
                    };

                    if result.is_ok() {
                        let comp_id = if let Ok(id) =
                            str::from_utf8(&temp_buffer[..temp_buffer_size as usize])
                        {
                            id.trim_end_matches(char::from(0)).to_string()
                        } else {
                            String::default()
                        };

                        if comp_id.as_str() == component_id {
                            temp_buffer_size = temp_buffer.len() as u32;
                            let result = unsafe {
                                RegOpenKeyExW(
                                    connection_key,
                                    REGSTR_LINKAGE,
                                    0,
                                    KEY_READ,
                                    &mut linkage_key,
                                )
                            };

                            if result.is_ok() {
                                let result = unsafe {
                                    RegQueryValueExA(
                                        linkage_key,
                                        REGSTR_EXPORT,
                                        None,
                                        Some(&mut value_type),
                                        Some(temp_buffer.as_mut_ptr()),
                                        Some(&mut temp_buffer_size),
                                    )
                                };

                                if result.is_ok() {
                                    let export = if let Ok(id) =
                                        str::from_utf8(&temp_buffer[..temp_buffer_size as usize])
                                    {
                                        id.trim_end_matches(char::from(0)).to_string()
                                    } else {
                                        String::default()
                                    };

                                    if export.as_str().eq_ignore_ascii_case(adapter_name.as_str()) {
                                        found = true;
                                    }
                                }
                                let _ = unsafe { RegCloseKey(linkage_key) };
                            }
                        }
                        let _ = unsafe { RegCloseKey(connection_key) };
                    }
                    temp_buffer_size = temp_buffer.len() as u32;
                }

                index += 1;
                buffer_size = buffer.len() as u32;
            }
        }

        let _ = unsafe { RegCloseKey(target_key) };

        Ok(found)
    }

    /// Determines if a given network interface is an NDISWANIP interface.
    ///
    /// This function checks if the specified network adapter is an NDISWANIP interface by calling `is_ndiswan_interface`
    /// with the component ID "ms_ndiswanip".
    ///
    /// # Arguments
    ///
    /// * `adapter_name: impl Into<String>`: The name of the network adapter to check.
    ///
    /// # Returns
    ///
    /// * `bool`: Returns `true` if the interface is an NDISWANIP interface, `false` otherwise.
    pub fn is_ndiswan_ip(adapter_name: impl Into<String>) -> bool {
        Self::is_ndiswan_interface(adapter_name.into(), REGSTR_COMPONENTID_NDISWANIP)
            .unwrap_or(false)
    }

    /// Determines if a given network interface is an NDISWANIPV6 interface.
    ///
    /// This function checks if the specified network adapter is an NDISWANIPV6 interface by calling `is_ndiswan_interface`
    /// with the component ID "ms_ndiswanipv6".
    ///
    /// # Arguments
    ///
    /// * `adapter_name: impl Into<String>`: The name of the network adapter to check.
    ///
    /// # Returns
    ///
    /// * `bool`: Returns `true` if the interface is an NDISWANIPV6 interface, `false` otherwise.
    pub fn is_ndiswan_ipv6(adapter_name: impl Into<String>) -> bool {
        Self::is_ndiswan_interface(adapter_name.into(), REGSTR_COMPONENTID_NDISWANIPV6)
            .unwrap_or(false)
    }

    /// Determines if a given network interface is an NDISWANBH interface.
    ///
    /// This function checks if the specified network adapter is an NDISWANBH interface by calling `is_ndiswan_interface`
    /// with the component ID "ms_ndiswanbh".
    ///
    /// # Arguments
    ///
    /// * `adapter_name: impl Into<String>`: The name of the network adapter to check.
    ///
    /// # Returns
    ///
    /// * `bool`: Returns `true` if the interface is an NDISWANBH interface, `false` otherwise.
    pub fn is_ndiswan_bh(adapter_name: impl Into<String>) -> bool {
        Self::is_ndiswan_interface(adapter_name.into(), REGSTR_COMPONENTID_NDISWANBH)
            .unwrap_or(false)
    }

    /// This function checks if the specified network adapter is an NDISWAN IP, IPv6, or BH interface, and if not,
    /// attempts to find the friendly name from the registry.
    ///
    /// # Arguments
    ///
    /// * `adapter_name: impl Into<String>`: The system-level name of the network adapter to obtain the user-friendly name for.
    ///
    /// # Returns
    ///
    /// * `Result<String>`: Returns a `Result` containing the user-friendly name of the network adapter if found, or an error otherwise.

    pub fn get_friendly_adapter_name(adapter_name: impl Into<String>) -> Result<String> {
        let mut adapter_name = adapter_name.into();

        if Self::is_ndiswan_ip(adapter_name.as_str()) {
            return Ok(USER_NDISWANIP.into());
        }

        if Self::is_ndiswan_ipv6(adapter_name.as_str()) {
            return Ok(USER_NDISWANIPV6.into());
        }

        if Self::is_ndiswan_bh(adapter_name.as_str()) {
            return Ok(USER_NDISWANBH.into());
        }

        // Trim the '\DEVICE\' prefix from the adapter system name
        adapter_name = adapter_name.replace("\\DEVICE\\", "");

        let friendly_name_key = format!(
            "SYSTEM\\CurrentControlSet\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{}\\Connection",
            &adapter_name
        );

        // Convert the string to UTF16 array and get a pointer to it as PCWSTR
        let mut friendly_name_key = friendly_name_key.encode_utf16().collect::<Vec<u16>>();
        friendly_name_key.push(0);

        let mut hkey = HKEY::default();

        let mut result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR::from_raw(friendly_name_key.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            )
        }.ok();

        let mut value_type = REG_VALUE_TYPE::default();
        let mut data = vec![0u16; 256];
        let mut data_size = data.len() as u32;
        let mut friendly_name = String::default();

        if result.is_ok() {
            result = unsafe {
                RegQueryValueExW(
                    hkey,
                    REGSTR_VAL_NAME,
                    None,
                    Some(&mut value_type),
                    Some(data.as_mut_ptr() as *const u8 as *mut u8),
                    Some(&mut data_size),
                )
            }.ok();

            if result.is_ok() {
                friendly_name = if let Ok(name) = String::from_utf16(&data[..data_size as usize]) {
                    name.trim_end_matches(char::from(0)).to_string()
                } else {
                    String::default()
                }
            }

            let _ = unsafe { RegCloseKey(hkey) };
        }

        if result.is_err() {
            Err(result.err().unwrap())
        } else {
            Ok(friendly_name)
        }
    }

    /// This function sets a parameter in the registry key that the filter driver reads during its initialization.
    /// The value set in the registry is subtracted from the actual MTU (Maximum Transmission Unit) when it is requested
    /// by the MSTCP (Microsoft TCP/IP) from the network. Because this parameter is read during the initialization of the
    /// filter driver, a system reboot is required for the changes to take effect. Requires Administrator permissions.
    ///
    /// # Arguments
    ///
    /// * `mtu_decrement: u32` - The value to subtract from the actual MTU.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns a `Result` that is `Ok(())` if the MTU decrement value is set successfully in the registry, or an error otherwise.
    pub fn set_mtu_decrement(&self, mtu_decrement: u32) -> Result<()> {
        let mut hkey = HKEY::default();

        let mut result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                self.get_driver_registry_key(),
                0,
                KEY_WRITE,
                &mut hkey,
            )
        }.ok();

        if result.is_ok() {
            result = unsafe {
                RegSetValueExW(
                    hkey,
                    REGSTR_MTU_DECREMENT,
                    0,
                    REG_DWORD,
                    Some(mtu_decrement.to_ne_bytes().as_ref()),
                )
            }.ok();
        }

        result
    }

    /// This function retrieves the value set by `set_mtu_decrement` from the registry. Note that if you have not
    /// rebooted after calling `set_mtu_decrement`, the return value is meaningless. If `MTUDecrement` value is not
    /// present in the registry or an error occurred, then `None` is returned.
    ///
    /// # Returns
    ///
    /// * `Option<u32>` - Returns an `Option` containing the MTU decrement value if it is present in the registry and there are no errors, or `None` otherwise.
    pub fn get_mtu_decrement(&self) -> Option<u32> {
        let mut hkey = HKEY::default();

        let mut result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                self.get_driver_registry_key(),
                0,
                KEY_READ,
                &mut hkey,
            )
        };

        let mut value_type = REG_VALUE_TYPE::default();
        let mtu_decrement = 0u32;
        let mut data_size = std::mem::size_of::<u32>() as u32;

        if result.is_ok() {
            result = unsafe {
                RegQueryValueExW(
                    hkey,
                    REGSTR_MTU_DECREMENT,
                    None,
                    Some(&mut value_type),
                    Some(&mtu_decrement as *const u32 as *mut u8),
                    Some(&mut data_size),
                )
            };
        }

        if result.is_ok() {
            Some(mtu_decrement)
        } else {
            None
        }
    }

    /// This routine sets the default mode to be applied to each adapter as soon as it appears in the system.
    /// It can be helpful in scenarios where you need to delay a network interface from operating until your
    /// application has started. However, it's essential to note that this API call requires a system reboot to take effect.
    /// Requires Administrator permissions to succeed.
    ///
    /// # Arguments
    ///
    /// * `startup_mode: u32` - The default startup mode to be applied to each adapter.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns a `Result` indicating whether the operation succeeded or an error occurred.
    pub fn set_adapters_startup_mode(&self, startup_mode: u32) -> Result<()> {
        let mut hkey = HKEY::default();

        let mut result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                self.get_driver_registry_key(),
                0,
                KEY_WRITE,
                &mut hkey,
            )
        };

        if result.is_ok() {
            result = unsafe {
                RegSetValueExW(
                    hkey,
                    REGSTR_STARTUP_MODE,
                    0,
                    REG_DWORD,
                    Some(startup_mode.to_ne_bytes().as_ref()),
                )
            };
        }

        result.ok()
    }

    /// Returns the current default filter mode value applied to each adapter when it appears in the system.
    /// Note that if you have not rebooted after calling SetAdaptersStartupMode, the return value is meaningless.
    ///
    /// # Returns
    ///
    /// * `Option<u32>` - Returns the current default startup mode as `Some(u32)` if the value is present in the registry,
    ///   or `None` if the value is not present or an error occurred.
    pub fn get_adapters_startup_mode(&self) -> Option<u32> {
        let mut hkey = HKEY::default();

        let mut result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                self.get_driver_registry_key(),
                0,
                KEY_READ,
                &mut hkey,
            )
        };

        let mut value_type = REG_VALUE_TYPE::default();
        let startup_mode = 0u32;
        let mut data_size = std::mem::size_of::<u32>() as u32;

        if result.is_ok() {
            result = unsafe {
                RegQueryValueExW(
                    hkey,
                    REGSTR_STARTUP_MODE,
                    None,
                    Some(&mut value_type),
                    Some(&startup_mode as *const u32 as *mut u8),
                    Some(&mut data_size),
                )
            };
        }

        if result.is_ok() {
            Some(startup_mode)
        } else {
            None
        }
    }

    /// Sets the pool size multiplier for Windows Packet Filter driver in the Windows registry.
    ///
    /// This function creates or modifies the PoolSize value in the registry based on the
    /// given value. The appropriate registry key is selected depending on the
    /// Windows platform (NT/2000/XP or 9x/ME). The resulting internal packet pool size
    /// will be equal to 2048 (512 for Windows version before Vista) * PoolSize packets. The maximum
    /// effective PoolSize is 10.
    ///
    /// # Arguments
    ///
    /// * `pool_size: u32` - The desired pool size multiplier to be set in the registry.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - If the pool size multiplier is successfully set, returns `Ok(())`.
    ///   Otherwise, returns an `Err` with the error code.
    pub fn set_pool_size(&self, pool_size: u32) -> Result<()> {
        let mut hkey = HKEY::default();

        let mut result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                self.get_driver_registry_key(),
                0,
                KEY_WRITE,
                &mut hkey,
            )
        };

        if result.is_ok() {
            result = unsafe {
                RegSetValueExW(
                    hkey,
                    REGSTR_POOL_SIZE,
                    0,
                    REG_DWORD,
                    Some(pool_size.to_ne_bytes().as_ref()),
                )
            };
        }

        result.ok()
    }

    /// Retrieves the pool size multiplier for the Windows Packet Filter driver from the Windows registry.
    ///
    /// This function queries the registry for the PoolSize value and returns it.
    /// The appropriate registry key is used depending on the Windows platform
    /// (NT/2000/XP or 9x/ME). The internal packet pool size is determined by
    /// 2048 * PoolSize packets. The maximum effective PoolSize is 10.
    ///
    /// # Returns
    ///
    /// * `Option<u32>` - The pool size multiplier retrieved from the registry.
    ///   If the value is not found or an error occurs, returns `None`.
    pub fn get_pool_size(&self) -> Option<u32> {
        let mut hkey = HKEY::default();

        let mut result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                self.get_driver_registry_key(),
                0,
                KEY_READ,
                &mut hkey,
            )
        };

        let mut value_type = REG_VALUE_TYPE::default();
        let pool_size = 0u32;
        let mut data_size = std::mem::size_of::<u32>() as u32;

        if result.is_ok() {
            result = unsafe {
                RegQueryValueExW(
                    hkey,
                    REGSTR_POOL_SIZE,
                    None,
                    Some(&mut value_type),
                    Some(&pool_size as *const u32 as *mut u8),
                    Some(&mut data_size),
                )
            };
        }

        if result.is_ok() {
            Some(pool_size)
        } else {
            None
        }
    }
}
