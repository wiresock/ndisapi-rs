use std::cmp::Ordering;
use std::convert::From;
use std::fmt::{self, Debug, Display};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

/// Wrapper for the `NET_LUID_LH` struct from the `windows` crate.
///
/// This struct provides a convenient, idiomatic interface for working
/// with network interface Locally Unique Identifiers (LUIDs) in Rust,
/// including implementations of important traits like `PartialEq`, `Eq`,
/// `PartialOrd`, `Ord`, `Debug`, and `Display`.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct IfLuid(NET_LUID_LH);

impl IfLuid {
    /// Constructs a new `IfLuid` instance from a reference to a `NET_LUID_LH`.
    ///
    /// # Arguments
    ///
    /// * `net_luid_lh` - A reference to a `NET_LUID_LH` value representing the network interface's LUID.
    pub fn new(net_luid_lh: &NET_LUID_LH) -> Self {
        Self(*net_luid_lh)
    }
}

/// Implement the `From` trait for converting a `NET_LUID_LH` value into an `IfLuid` value.
impl From<NET_LUID_LH> for IfLuid {
    /// Converts a `NET_LUID_LH` value into an `IfLuid` value.
    ///
    /// # Arguments
    ///
    /// * `luid`: A `NET_LUID_LH` value to be converted into `IfLuid`.
    ///
    /// # Returns
    ///
    /// * `IfLuid`: The `IfLuid` value representing the given `NET_LUID_LH` value.
    fn from(luid: NET_LUID_LH) -> Self {
        IfLuid(luid)
    }
}

/// Implement the `Into` trait for converting an `IfLuid` value back into a `NET_LUID_LH` value.
impl From<IfLuid> for NET_LUID_LH {
    /// Converts an `IfLuid` value back into a `NET_LUID_LH` value.
    ///
    /// # Arguments
    ///
    /// * `self`: An `IfLuid` value to be converted back into a `NET_LUID_LH` value.
    ///
    /// # Returns
    ///
    /// * `NET_LUID_LH`: The `NET_LUID_LH` value represented by the given `IfLuid` value.
    fn from(val: IfLuid) -> Self {
        val.0
    }
}

/// Implements the conversion from a u64 value to an IfLuid instance.
impl From<u64> for IfLuid {
    /// Converts a u64 value into an IfLuid instance by creating a new NET_LUID_LH structure and
    /// setting its Value field to the input value.
    ///
    /// # Arguments
    ///
    /// * `value` - The u64 value that should be used to set the Value field of the NET_LUID_LH
    ///             structure.
    ///
    /// # Returns
    ///
    /// * An IfLuid instance wrapping the created NET_LUID_LH structure.
    ///
    /// # Examples
    ///
    /// ```
    /// use ndisapi::IfLuid;
    /// // Create two IfLuid instances using u64 values
    /// let value1: u64 = 42;
    /// let if_luid1 = IfLuid::from(value1);
    ///
    /// let value2: u64 = 43;
    /// let if_luid2 = IfLuid::from(value2);
    ///
    /// let value3: u64 = 42;
    /// let if_luid3 = IfLuid::from(value3);
    /// //Compare the two IfLuid instances based on their inner NET_LUID_LH values
    /// assert_ne!(if_luid1, if_luid2);
    /// assert_eq!(if_luid1, if_luid3);
    /// ```
    fn from(value: u64) -> Self {
        // Assuming that the NET_LUID_LH structure has a field `Value` of type u64
        let net_luid_lh = NET_LUID_LH { Value: value };
        IfLuid(net_luid_lh)
    }
}

/// Implementation of `PartialEq` for `IfLuid`.
///
/// Two `IfLuid` instances are considered equal if their `Value` fields are equal.
impl PartialEq for IfLuid {
    fn eq(&self, other: &Self) -> bool {
        unsafe { self.0.Value == other.0.Value }
    }
}

/// Implementation of `Eq` for `IfLuid`.
///
/// This is a marker trait that signals that `IfLuid` fulfills the properties
/// of an equivalence relation for its `PartialEq` implementation.
impl Eq for IfLuid {}

/// Implementation of `PartialOrd` for `IfLuid`.
///
/// `IfLuid` instances are ordered based on their `Value` fields.
impl PartialOrd for IfLuid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Implementation of `Ord` for `IfLuid`.
///
/// This implementation provides a total ordering for `IfLuid` instances
/// based on their `Value` fields.
impl Ord for IfLuid {
    fn cmp(&self, other: &Self) -> Ordering {
        unsafe { self.0.Value.cmp(&other.0.Value) }
    }
}

/// Implementation of `Debug` for `IfLuid`.
///
/// The debug representation displays the struct name and the `Value` field
/// of the inner `NET_LUID_LH` union.
impl Debug for IfLuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IfLuid")
            .field("Value", unsafe { &self.0.Value })
            .finish()
    }
}

/// Implementation of `Display` for `IfLuid`.
///
/// The display representation shows the struct name followed by the `Value`
/// field of the inner `NET_LUID_LH` union, enclosed in parentheses.
impl Display for IfLuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IfLuid({})", unsafe { self.0.Value })
    }
}

#[cfg(test)]
mod tests {
    use super::IfLuid;
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    #[test]
    fn test_equality() {
        let luid1 = IfLuid(NET_LUID_LH { Value: 42 });
        let luid2 = IfLuid(NET_LUID_LH { Value: 42 });
        let luid3 = IfLuid(NET_LUID_LH { Value: 84 });

        assert_eq!(luid1, luid2);
        assert_ne!(luid1, luid3);
    }

    #[test]
    fn test_ordering() {
        let luid1 = IfLuid(NET_LUID_LH { Value: 42 });
        let luid2 = IfLuid(NET_LUID_LH { Value: 84 });

        assert!(luid1 < luid2);
        assert!(luid2 > luid1);
    }

    #[test]
    fn test_debug() {
        let luid = IfLuid(NET_LUID_LH { Value: 42 });

        let debug_output = format!("{:?}", luid);
        assert_eq!(debug_output, "IfLuid { Value: 42 }");
    }

    #[test]
    fn test_display() {
        let luid = IfLuid(NET_LUID_LH { Value: 42 });

        let display_output = format!("{}", luid);
        assert_eq!(display_output, "IfLuid(42)");
    }
}
