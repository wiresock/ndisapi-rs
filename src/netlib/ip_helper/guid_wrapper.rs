use std::fmt;
use uuid::Uuid;

/// A wrapper around `Uuid` to represent a GUID.
#[derive(Default, Debug, Clone)]
pub struct GuidWrapper(Uuid);

impl GuidWrapper {
    /// Creates a new `GuidWrapper` with a nil `Uuid`.
    ///
    /// # Returns
    ///
    /// A new `GuidWrapper` instance with a nil `Uuid`.
    pub fn new() -> Self {
        GuidWrapper(Uuid::nil())
    }

    /// Creates a new `GuidWrapper` from the provided `Uuid`.
    ///
    /// # Arguments
    ///
    /// * `uuid` - The `Uuid` to wrap.
    ///
    /// # Returns
    ///
    /// A new `GuidWrapper` instance containing the provided `Uuid`.
    pub fn from_uuid(uuid: Uuid) -> Self {
        GuidWrapper(uuid)
    }

    /// Converts the wrapped `Uuid` to a hyphenated uppercase string.
    ///
    /// # Returns
    ///
    /// A `String` representation of the hyphenated uppercase `Uuid`.
    pub fn to_hyphenated_upper_string(&self) -> String {
        self.0.hyphenated().to_string().to_uppercase()
    }
}

/// Implements the `From<Uuid>` trait for `GuidWrapper`.
impl From<Uuid> for GuidWrapper {
    /// Creates a new `GuidWrapper` from the provided `Uuid`.
    ///
    /// # Arguments
    ///
    /// * `uuid` - The `Uuid` to wrap.
    ///
    /// # Returns
    ///
    /// A new `GuidWrapper` instance containing the provided `Uuid`.
    fn from(uuid: Uuid) -> Self {
        GuidWrapper::from_uuid(uuid)
    }
}

/// Implements the `Display` trait for `GuidWrapper`.
impl fmt::Display for GuidWrapper {
    /// Formats the wrapped `Uuid` as a hyphenated uppercase string.
    ///
    /// # Arguments
    ///
    /// * `f` - The mutable `Formatter` reference.
    ///
    /// # Returns
    ///
    /// A `fmt::Result` containing the result of the formatting operation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hyphenated_upper_string())
    }
}

#[cfg(test)]
mod tests {
    use super::GuidWrapper;
    use uuid::Uuid;

    #[test]
    fn test_new() {
        let guid_wrapper = GuidWrapper::new();
        assert_eq!(guid_wrapper.0, Uuid::nil());
    }

    #[test]
    fn test_from_uuid() {
        let uuid = Uuid::new_v4();
        let guid_wrapper = GuidWrapper::from_uuid(uuid);
        assert_eq!(guid_wrapper.0, uuid);
    }

    #[test]
    fn test_to_hyphenated_upper_string() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let guid_wrapper = GuidWrapper::from_uuid(uuid);
        let guid_str = guid_wrapper.to_hyphenated_upper_string();
        assert_eq!(guid_str, "550E8400-E29B-41D4-A716-446655440000");
    }

    #[test]
    fn test_display() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let guid_wrapper = GuidWrapper::from_uuid(uuid);
        let guid_str = guid_wrapper.to_string();
        assert_eq!(guid_str, "550E8400-E29B-41D4-A716-446655440000");
    }
}
