/// Domain for routing decision.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Domain {
    /// Domain matching type.
    #[prost(enumeration = "domain::Type", tag = "1")]
    pub r#type: i32,
    /// Domain value.
    #[prost(string, tag = "2")]
    pub value: ::prost::alloc::string::String,
    /// Attributes of this domain. May be used for filtering.
    #[prost(message, repeated, tag = "3")]
    pub attribute: ::prost::alloc::vec::Vec<domain::Attribute>,
}
/// Nested message and enum types in `Domain`.
pub mod domain {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Attribute {
        #[prost(string, tag = "1")]
        pub key: ::prost::alloc::string::String,
        #[prost(oneof = "attribute::TypedValue", tags = "2, 3")]
        pub typed_value: ::core::option::Option<attribute::TypedValue>,
    }
    /// Nested message and enum types in `Attribute`.
    pub mod attribute {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum TypedValue {
            #[prost(bool, tag = "2")]
            BoolValue(bool),
            #[prost(int64, tag = "3")]
            IntValue(i64),
        }
    }
    /// Type of domain value.
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum Type {
        /// The value is used as is.
        Plain = 0,
        /// The value is used as a regular expression.
        Regex = 1,
        /// The value is a root domain.
        Domain = 2,
        /// The value is a domain.
        Full = 3,
    }
    impl Type {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Type::Plain => "Plain",
                Type::Regex => "Regex",
                Type::Domain => "Domain",
                Type::Full => "Full",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "Plain" => Some(Self::Plain),
                "Regex" => Some(Self::Regex),
                "Domain" => Some(Self::Domain),
                "Full" => Some(Self::Full),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SiteGroup {
    #[prost(string, tag = "1")]
    pub tag: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "2")]
    pub domain: ::prost::alloc::vec::Vec<Domain>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SiteGroupList {
    #[prost(message, repeated, tag = "1")]
    pub site_group: ::prost::alloc::vec::Vec<SiteGroup>,
}
