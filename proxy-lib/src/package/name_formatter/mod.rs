/// Canonical typed package name.
///
/// Implementations own the normalized package identifier and expose a typed
/// borrowed view (`Ref<'a>`) used by generic matchers.
pub trait PackageName: Sized + Eq {
    type Ref<'a>: PackageNameRef<'a>
    where
        Self: 'a;

    fn normalize(raw_package_name: &str) -> Self;
    fn as_ref(&self) -> Self::Ref<'_>;
}

/// Borrowed typed package-name view used by glob matching.
///
/// This abstraction keeps matching logic generic and allocation-light while
/// preserving package-name type safety.
pub trait PackageNameRef<'a>: Copy + Eq {
    type MatchAfterNeedleAll: Iterator<Item = Self>;

    fn is_empty(self) -> bool;
    fn strip_prefix(self, prefix: Self) -> Option<Self>;
    fn match_after_needle_all(self, needle: Self) -> Self::MatchAfterNeedleAll;
    fn has_suffix(self, suffix: Self) -> bool;
}

#[derive(Debug, Clone)]
pub struct StrNeedleMatchesAfter<'a> {
    haystack: &'a str,
    needle: &'a str,
    scan_start: usize,
    yielded_for_empty_needle: bool,
}

impl<'a> StrNeedleMatchesAfter<'a> {
    #[inline(always)]
    pub fn new(haystack: &'a str, needle: &'a str) -> Self {
        Self {
            haystack,
            needle,
            scan_start: 0,
            yielded_for_empty_needle: false,
        }
    }
}

impl<'a> Iterator for StrNeedleMatchesAfter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.needle.is_empty() {
            if self.yielded_for_empty_needle {
                return None;
            }
            self.yielded_for_empty_needle = true;
            return Some(self.haystack);
        }

        if self.scan_start > self.haystack.len() {
            return None;
        }

        let remaining = &self.haystack[self.scan_start..];
        let relative_idx = remaining.find(self.needle)?;

        let absolute_idx = self.scan_start + relative_idx;
        let tail_start = absolute_idx + self.needle.len();

        // Advance one UTF-8 character to allow overlapping matches.
        let first_ch = self.haystack[absolute_idx..].chars().next()?;
        let step = first_ch.len_utf8();
        self.scan_start = absolute_idx + step;

        Some(&self.haystack[tail_start..])
    }
}

mod glob_set;
#[doc(inline)]
pub use glob_set::GlobSet;

mod lower_case;
#[doc(inline)]
pub use lower_case::{LowerCasePackageName, LowerCasePackageNameRef};

#[doc(hidden)]
#[macro_export]
macro_rules! __decl_arc_str_package_name {
    ($name:ident, $name_ref:ident, $from_str:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name_ref<'a>(&'a str);

        impl<'a> ::std::fmt::Display for $name_ref<'a> {
            #[inline(always)]
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                self.0.fmt(f)
            }
        }

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

        impl $crate::package::name_formatter::PackageName for $name {
            type Ref<'a>
                = $name_ref<'a>
            where
                Self: 'a;

            #[inline(always)]
            fn normalize(raw_package_name: &str) -> Self {
                $from_str(raw_package_name)
            }

            #[inline(always)]
            fn as_ref(&self) -> Self::Ref<'_> {
                $name_ref(self.0.as_str())
            }
        }

        impl<'a> $crate::package::name_formatter::PackageNameRef<'a> for $name_ref<'a> {
            type MatchAfterNeedleAll = ::std::iter::Map<
                $crate::package::name_formatter::StrNeedleMatchesAfter<'a>,
                fn(&'a str) -> Self,
            >;

            #[inline(always)]
            fn is_empty(self) -> bool {
                self.0.is_empty()
            }

            #[inline(always)]
            fn strip_prefix(self, prefix: Self) -> Option<Self> {
                self.0.strip_prefix(prefix.0).map($name_ref)
            }

            #[inline(always)]
            fn match_after_needle_all(self, needle: Self) -> Self::MatchAfterNeedleAll {
                $crate::package::name_formatter::StrNeedleMatchesAfter::new(self.0, needle.0)
                    .map($name_ref as fn(&'a str) -> Self)
            }

            #[inline(always)]
            fn has_suffix(self, suffix: Self) -> bool {
                self.0.ends_with(suffix.0)
            }
        }
    };
}
pub(crate) use crate::__decl_arc_str_package_name as decl_arc_str_package_name;
