pub trait PackageName {
    fn normalize(raw_package_name: &str) -> Self;
}

mod lower_case;
#[doc(inline)]
pub use lower_case::LowerCasePackageName;

#[doc(hidden)]
#[macro_export]
macro_rules! __decl_arc_str_package_name {
    ($name:ident, $from_str:ident) => {
        impl ::std::fmt::Display for $name {
            #[inline(always)]
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl $name {
            /// Not meant to compare, only for export purposes
            #[inline(always)]
            #[allow(unused)]
            pub fn as_arcstr(&self) -> rama::utils::str::arcstr::ArcStr {
                self.0.clone()
            }

            /// Not meant to compare, only for export purposes
            #[inline(always)]
            #[allow(unused)]
            pub fn into_arcstr(self) -> rama::utils::str::arcstr::ArcStr {
                self.0
            }
        }

        impl ::serde::Serialize for $name {
            #[inline(always)]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let s = ::std::borrow::Cow::<'de, str>::deserialize(deserializer)?;
                Ok(Self::from(s))
            }
        }

        impl<S: AsRef<str>> From<S> for $name {
            #[inline(always)]
            fn from(raw_package_name_value: S) -> Self {
                let raw_package_name = raw_package_name_value.as_ref();
                $from_str(raw_package_name)
            }
        }

        impl ::radix_trie::TrieKey for $name {
            #[inline(always)]
            fn encode_bytes(&self) -> Vec<u8> {
                self.0.as_bytes().to_vec()
            }
        }
    };
}
pub(crate) use crate::__decl_arc_str_package_name as decl_arc_str_package_name;
