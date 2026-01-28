use std::{borrow::Cow, fmt, hash, str::FromStr, sync::Arc};

use rama::utils::str::smol_str::{SmolStr, format_smolstr};

use serde::{Deserialize, Serialize, de::Error};

/// **SemVer version**-like struct with a lot of flexibility in the input we accept.
#[derive(Clone)]
pub struct PragmaticSemver {
    major: u64,
    minor: u64,
    patch: u64,
    fourth: u64,
    fifth: u64,
    pre: Identifier,
    build: Identifier,
}

impl Serialize for PragmaticSemver {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            major,
            minor,
            patch,
            fourth,
            fifth,
            pre,
            build,
        } = self;
        let trailer_semver = if *fifth != 0 {
            format_smolstr!(".{fourth}.{fifth}")
        } else if *fourth != 0 {
            format_smolstr!(".{fourth}")
        } else {
            SmolStr::default()
        };
        let s = if pre.0.is_some() {
            if build.0.is_some() {
                format_smolstr!("{major}.{minor}.{patch}{trailer_semver}-{pre:?}+{build:?}")
            } else {
                format_smolstr!("{major}.{minor}.{patch}{trailer_semver}-{pre:?}")
            }
        } else if build.0.is_some() {
            format_smolstr!("{major}.{minor}.{patch}{trailer_semver}+{build:?}")
        } else {
            format_smolstr!("{major}.{minor}.{patch}{trailer_semver}")
        };
        s.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PragmaticSemver {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(&s).map_err(D::Error::custom)
    }
}

impl hash::Hash for PragmaticSemver {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.major.hash(state);
        self.minor.hash(state);
        self.patch.hash(state);
        self.fourth.hash(state);
        self.fifth.hash(state);
        self.pre.hash(state);
    }
}

impl fmt::Debug for PragmaticSemver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            major,
            minor,
            patch,
            fourth,
            fifth,
            pre,
            build,
        } = self;
        write!(
            f,
            "{major}.{minor}.{patch}.{fourth}.{fifth}-{pre:?}+{build:?}"
        )
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
/// Opaque identifier that can be safely compared/
///
/// Used for pre- and build- data parts of [`PragmaticSemver`].
pub struct Identifier(Option<Arc<[u8]>>);

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (&self.0, &other.0) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Identifier {
    fn new_utf8(s: &str) -> Self {
        const ALPHA_LOWERCASE_MASK: u8 = 0b0010_0000;
        let mut iter = s
            .bytes()
            .filter_map(|c| {
                Some(match c {
                    b'A'..=b'Z' => c | ALPHA_LOWERCASE_MASK,
                    b'a'..=b'z' => c,
                    b'0'..=b'9' => c,
                    b'.' | b'-' | b'_' | b'+' => c,
                    _ => return None,
                })
            })
            .peekable();
        if iter.peek().is_some() {
            Self(Some(iter.collect()))
        } else {
            Self::empty()
        }
    }

    const fn empty() -> Self {
        Self(None)
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_bytes = self.0.as_deref().unwrap_or_default();
        // SAFETY: constructor ensures we are only dealing with ASCII alphanumeric
        let id_utf8 = unsafe { std::str::from_utf8_unchecked(id_bytes) };
        write!(f, "{}", id_utf8)
    }
}

impl PragmaticSemver {
    /// Create [`PragmaticSemver`] pure semver without pre or build tag.
    pub const fn new_semver(major: u64, minor: u64, patch: u64) -> Self {
        Self::new_four_components(major, minor, patch, 0)
    }

    /// Create [`PragmaticSemver`] with just major and minor
    #[inline(always)]
    pub const fn new_two_components(major: u64, minor: u64) -> Self {
        Self::new_semver(major, minor, 0)
    }

    /// Create [`PragmaticSemver`] with only major defined.
    #[inline(always)]
    pub const fn new_single(major: u64) -> Self {
        Self::new_two_components(major, 0)
    }

    /// Create [`PragmaticSemver`] with only zero values.
    #[inline(always)]
    pub const fn new_zeroed() -> Self {
        Self::new_single(0)
    }

    /// Create [`PragmaticSemver`] with semver + 4th part
    #[inline(always)]
    pub const fn new_four_components(major: u64, minor: u64, patch: u64, fourth: u64) -> Self {
        Self::new_five_components(major, minor, patch, fourth, 0)
    }

    /// Create [`PragmaticSemver`] with semver + 2 extr aparts
    #[inline(always)]
    pub const fn new_five_components(
        major: u64,
        minor: u64,
        patch: u64,
        fourth: u64,
        fifth: u64,
    ) -> Self {
        Self {
            major,
            minor,
            patch,
            fourth,
            fifth,
            pre: Identifier::empty(),
            build: Identifier::empty(),
        }
    }

    /// Create [`PragmaticSemver`] by parsing from string representation.
    pub fn parse(text: &str) -> Result<Self, PragmaticSemverParseError> {
        Self::from_str(text)
    }

    rama::utils::macros::generate_set_and_with! {
        /// (un)set the pre part of this [`PragmaticSemver`].
        pub fn pre(mut self, maybe_str: Option<&str>) -> Self {
            self.pre = match maybe_str {
                Some(s) => Identifier::new_utf8(s),
                None => Identifier::empty(),
            };
            self
        }
    }

    rama::utils::macros::generate_set_and_with! {
        /// (un)set the build part of this [`PragmaticSemver`].
        pub fn build(mut self, maybe_str: Option<&str>) -> Self {
            self.build = match maybe_str {
                Some(s) => Identifier::new_utf8(s),
                None => Identifier::empty(),
            };
            self
        }
    }
}

impl PartialEq for PragmaticSemver {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            major,
            minor,
            patch,
            fourth,
            fifth,
            pre,
            build: _,
        } = self;

        let Self {
            major: other_major,
            minor: other_minor,
            patch: other_patch,
            fourth: other_fourth,
            fifth: other_fifth,
            pre: other_pre,
            build: _,
        } = other;

        major == other_major
            && minor == other_minor
            && patch == other_patch
            && fourth == other_fourth
            && fifth == other_fifth
            && pre == other_pre
    }
}

impl Eq for PragmaticSemver {}

impl PartialOrd for PragmaticSemver {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PragmaticSemver {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let Self {
            major,
            minor,
            patch,
            fourth,
            fifth,
            pre,
            build: _,
        } = self;

        let Self {
            major: other_major,
            minor: other_minor,
            patch: other_patch,
            fourth: other_fourth,
            fifth: other_fifth,
            pre: other_pre,
            build: _,
        } = other;

        match major.cmp(other_major) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match minor.cmp(other_minor) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match patch.cmp(other_patch) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match fourth.cmp(other_fourth) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match fifth.cmp(other_fifth) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        pre.cmp(other_pre)
    }
}

impl FromStr for PragmaticSemver {
    type Err = PragmaticSemverParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let trimmed_text = text.trim();
        if trimmed_text.is_empty() {
            return Err(PragmaticSemverParseError::EmptyString);
        }

        let mut version = PragmaticSemver::new_zeroed();

        let Some(num_trailer_text) = parse_number_parts_from_str(trimmed_text, &mut version)?
        else {
            return Ok(version);
        };

        let maybe_pre_trailer_text = if let Some(pre_text) = num_trailer_text.strip_prefix('-') {
            match pre_text.split_once('+') {
                Some((pre_text_without_build, rem)) => {
                    version.pre = Identifier::new_utf8(pre_text_without_build.trim_matches('-'));
                    (!rem.is_empty()).then_some(rem)
                }
                None => {
                    version.pre = Identifier::new_utf8(pre_text.trim_matches('-'));
                    None
                }
            }
        } else if !num_trailer_text.contains('+') {
            version.pre = Identifier::new_utf8(num_trailer_text.trim_end_matches('-'));
            None
        } else {
            (!num_trailer_text.is_empty()).then_some(num_trailer_text)
        };

        if let Some(pre_trailer_text) = maybe_pre_trailer_text {
            // assume this to build regardless of the content,
            // this way it is not taken into account for comparisons
            version.build = Identifier::new_utf8(pre_trailer_text.trim_matches('+'));
        }

        Ok(version)
    }
}

macro_rules! try_parse_next_part {
    ($version:ident, $part:ident, $text:ident, required = $required:expr) => {
        let NumberParseOutcome { number, rem } = parse_numeric_identifier_from_str($text)?;
        let $text = match number {
            Some(number) => {
                $version.$part = number;
                match rem {
                    Some(new_text) => new_text,
                    None => return Ok(None),
                }
            }
            None => {
                return if $required {
                    Err(PragmaticSemverParseError::UnexpectedNumberEnd)
                } else {
                    Ok(rem)
                };
            }
        };
        let $text = match parse_dot_from_str($text) {
            Some(DotParseNextAction::Continue(rem)) => rem,
            Some(DotParseNextAction::BeginPreOrBuild(rem)) => return Ok(Some(rem)),
            None => return Ok(None),
        };
    };
    ($version:ident, $part:ident, $text:ident) => {
        try_parse_next_part!($version, $part, $text, required = false)
    };
}

fn parse_number_parts_from_str<'a>(
    text: &'a str,
    version: &mut PragmaticSemver,
) -> Result<Option<&'a str>, PragmaticSemverParseError> {
    try_parse_next_part!(version, major, text, required = true);
    try_parse_next_part!(version, minor, text);
    try_parse_next_part!(version, patch, text);
    try_parse_next_part!(version, fourth, text);
    try_parse_next_part!(version, fifth, text);
    Ok((!text.is_empty()).then_some(text))
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum PragmaticSemverParseError {
    EmptyString,
    OverflowNumber,
    UnexpectedNumberEnd,
}

impl fmt::Display for PragmaticSemverParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PragmaticSemverParseError::EmptyString => {
                write!(f, "PragmaticSemverParseError: empty string")
            }
            PragmaticSemverParseError::OverflowNumber => {
                write!(f, "PragmaticSemverParseError: u64 overflow for number part")
            }
            PragmaticSemverParseError::UnexpectedNumberEnd => write!(
                f,
                "PragmaticSemverParseError: unexpected number end (did not read any number yet)"
            ),
        }
    }
}

impl std::error::Error for PragmaticSemverParseError {}

struct NumberParseOutcome<'a> {
    number: Option<u64>,
    rem: Option<&'a str>,
}

enum DotParseNextAction<'a> {
    Continue(&'a str),
    BeginPreOrBuild(&'a str),
}

fn parse_numeric_identifier_from_str(
    input: &str,
) -> Result<NumberParseOutcome<'_>, PragmaticSemverParseError> {
    let mut len = 0;
    let mut value = 0u64;

    while let Some(&digit) = input.as_bytes().get(len) {
        if !digit.is_ascii_digit() {
            break;
        }
        match value
            .checked_mul(10)
            .and_then(|value| value.checked_add((digit - b'0') as u64))
        {
            Some(sum) => value = sum,
            None => return Err(PragmaticSemverParseError::OverflowNumber),
        }
        len += 1;
    }

    if len > 0 {
        Ok(NumberParseOutcome {
            number: Some(value),
            rem: Some(&input[len..]),
        })
    } else if !input[len..].is_empty() {
        Ok(NumberParseOutcome {
            number: None,
            rem: Some(&input[len..]),
        })
    } else {
        Ok(NumberParseOutcome {
            number: None,
            rem: None,
        })
    }
}

fn parse_dot_from_str(input: &str) -> Option<DotParseNextAction<'_>> {
    if let Some(rest) = input.strip_prefix('.') {
        (!rest.is_empty()).then_some(DotParseNextAction::Continue(rest))
    } else if !input.is_empty() {
        Some(DotParseNextAction::BeginPreOrBuild(input))
    } else {
        None
    }
}
