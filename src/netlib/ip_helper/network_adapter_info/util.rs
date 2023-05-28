use windows::Win32::NetworkManagement::IpHelper::MIB_IPNET_ROW2;

/// Sets the `IsRouter` bit of the `MIB_IPNET_ROW2` structure to the given value.
///
/// # Safety
///
/// This function modifies a raw bitfield, which could lead to undefined behavior
/// if used improperly. Ensure that the `mib_row` pointer is valid and not aliased.
///
/// # Arguments
///
/// * `mib_row` - A mutable reference to the `MIB_IPNET_ROW2` structure.
/// * `value` - A boolean value indicating whether the `IsRouter` bit should be set or not.
pub unsafe fn set_is_router(mib_row: &mut MIB_IPNET_ROW2, value: bool) {
    if value {
        mib_row.Anonymous.Anonymous._bitfield |= 1 << 0;
    } else {
        mib_row.Anonymous.Anonymous._bitfield &= !(1 << 0);
    }
}

/// Sets the `IsUnreachable` bit of the `MIB_IPNET_ROW2` structure to the given value.
///
/// # Safety
///
/// This function modifies a raw bitfield, which could lead to undefined behavior
/// if used improperly. Ensure that the `mib_row` pointer is valid and not aliased.
///
/// # Arguments
///
/// * `mib_row` - A mutable reference to the `MIB_IPNET_ROW2` structure.
/// * `value` - A boolean value indicating whether the `IsUnreachable` bit should be set or not.
pub unsafe fn set_is_unreachable(mib_row: &mut MIB_IPNET_ROW2, value: bool) {
    if value {
        mib_row.Anonymous.Anonymous._bitfield |= 1 << 1;
    } else {
        mib_row.Anonymous.Anonymous._bitfield &= !(1 << 1);
    }
}
