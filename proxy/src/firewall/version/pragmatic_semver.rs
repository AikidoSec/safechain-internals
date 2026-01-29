use std::{borrow::Cow, fmt, hash, str::FromStr, sync::Arc};

use rama::utils::str::smol_str::ToSmolStr as _;

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

impl fmt::Display for PragmaticSemver {
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

        write!(f, "{major}.{minor}.{patch}")?;

        if *fifth != 0 {
            write!(f, ".{fourth}.{fifth}")?;
        } else if *fourth != 0 {
            write!(f, ".{fourth}")?;
        }

        if !pre.is_empty() {
            write!(f, "-{}", pre.as_str())?;
        }

        if !build.is_empty() {
            write!(f, "+{}", build.as_str())?;
        }

        Ok(())
    }
}

impl Serialize for PragmaticSemver {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.to_smolstr();
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

impl Identifier {
    fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    fn as_str(&self) -> &str {
        let id_bytes = self.0.as_deref().unwrap_or_default();
        // SAFETY: constructor ensures we are only dealing with ASCII alphanumeric
        unsafe { std::str::from_utf8_unchecked(id_bytes) }
    }
}

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
        let mut iter = s.bytes().filter_map(normalize_identifier_byte).peekable();
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

fn normalize_identifier_byte(c: u8) -> Option<u8> {
    const ALPHA_LOWERCASE_MASK: u8 = 0b0010_0000;

    Some(match c {
        b'A'..=b'Z' => c | ALPHA_LOWERCASE_MASK,
        b'a'..=b'z' => c,
        b'0'..=b'9' => c,
        b'.' | b'-' | b'_' | b'+' => c,
        _ => return None,
    })
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
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
        let input = text.trim();
        if input.is_empty() {
            return Err(PragmaticSemverParseError::EmptyString);
        }

        let mut version = PragmaticSemver::new_zeroed();

        let remainder = parse_number_parts(input, &mut version)?;
        if let Some(tail) = remainder {
            parse_pre_and_build(tail, &mut version);
        }

        Ok(version)
    }
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

enum NextInput<'a> {
    // Continue parsing numeric parts after a dot.
    Continue(&'a str),
    // Stop numeric parsing and return the remaining text (pre and or build).
    Remainder(&'a str),
    // Stop parsing because we reached the end (or a trailing dot).
    End,
}

impl<'a> NextInput<'a> {
    fn remainder_or_end(s: &'a str) -> Self {
        let trimmed_s = s.trim();
        if trimmed_s.is_empty() {
            Self::End
        } else {
            Self::Remainder(trimmed_s)
        }
    }

    fn continue_or_end(s: &'a str) -> Self {
        let trimmed_s = s.trim();
        if trimmed_s.is_empty() {
            Self::End
        } else {
            Self::Continue(trimmed_s)
        }
    }
}

/// Parse up to 5 numeric parts: major, minor, patch, fourth, fifth.
///
/// This parser is intentionally lenient:
/// - Only the first number (major) is required to start with digits
/// - Additional parts are optional
/// - A trailing dot is allowed ("1.2.")
/// - As soon as we hit a non digit after a number, we stop numeric parsing
///   and treat the rest as pre and or build
fn parse_number_parts<'a>(
    input: &'a str,
    version: &mut PragmaticSemver,
) -> Result<Option<&'a str>, PragmaticSemverParseError> {
    // Borrow all numeric fields once, then iterate over them.
    let number_fields = [
        &mut version.major,
        &mut version.minor,
        &mut version.patch,
        &mut version.fourth,
        &mut version.fifth,
    ];

    let mut mod_input = input;
    for (idx, field) in number_fields.into_iter().enumerate() {
        let required = idx == 0;

        let (number_opt, next) = parse_one_number_part(mod_input, required)?;

        // Only assign if we actually parsed a number.
        if let Some(n) = number_opt {
            *field = n;
        }

        match next {
            NextInput::Continue(next_input) => mod_input = next_input,
            NextInput::Remainder(rem) => return Ok((!rem.is_empty()).then_some(rem)),
            NextInput::End => return Ok(None),
        }
    }

    Ok((!mod_input.is_empty()).then_some(mod_input))
}

/// Parse a single numeric part from the start of `input`.
///
/// Rules:
/// - If required and no digits: error
/// - If optional and no digits: stop numeric parsing,
///   remainder is pre and or build ([`NextInput::Remainder`])
/// - If digits are present:
///     - ".\<more\>" continues numeric parsing ([`NextInput::Continue`])
///     - "." at end ends parsing (trailing dot allowed) ([`NextInput::End`])
///     - end ends parsing ([`NextInput::End`])
///     - any other character starts pre and or build ([`NextInput::Remainder`])
fn parse_one_number_part<'a>(
    input: &'a str,
    required: bool,
) -> Result<(Option<u64>, NextInput<'a>), PragmaticSemverParseError> {
    let (number_opt, rest) = parse_u64_prefix(input)?;

    if number_opt.is_none() {
        if required {
            return Err(PragmaticSemverParseError::UnexpectedNumberEnd);
        }

        return Ok((None, NextInput::remainder_or_end(rest)));
    }

    // We parsed a number, decide what happens next.
    let next_input_action = if let Some(after_dot) = rest.strip_prefix('.') {
        NextInput::continue_or_end(after_dot)
    } else {
        NextInput::remainder_or_end(rest)
    };
    Ok((number_opt, next_input_action))
}

/// Parse a u64 prefix from `input`.
///
/// Returns:
/// - (Some(value), rest) if at least one digit was read
/// - (None, input) if no digits were read
///
/// Overflows return OverflowNumber.
fn parse_u64_prefix(input: &str) -> Result<(Option<u64>, &str), PragmaticSemverParseError> {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut value = 0u64;

    while let Some(&b) = bytes.get(i) {
        if !b.is_ascii_digit() {
            break;
        }

        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add((b - b'0') as u64))
            .ok_or(PragmaticSemverParseError::OverflowNumber)?;

        i += 1;
    }

    if i == 0 {
        Ok((None, input))
    } else {
        Ok((Some(value), &input[i..]))
    }
}

/// Parse the tail (everything after numeric parts) into pre and build.
///
/// This is intentionally permissive and matches the original behavior:
/// - pre can start with '-' or without it
/// - build starts at '+'
/// - we trim some leading and trailing separators to avoid weird artifacts
///
/// Accepted shapes:
/// - "-pre"
/// - "-pre+build"
/// - "pre"
/// - "pre+build"
/// - "+build"
fn parse_pre_and_build(tail: &str, version: &mut PragmaticSemver) {
    // explicit pre, optionally followed by "+build"
    if let Some(after_dash) = tail.strip_prefix('-') {
        let (pre, build_opt) = split_pre_build(after_dash);
        version.pre = Identifier::new_utf8(pre.trim_matches('-'));

        if let Some(build) = build_opt {
            version.build = Identifier::new_utf8(build.trim_matches('+'));
        }
        return;
    }

    // build only
    if let Some(after_plus) = tail.strip_prefix('+') {
        version.build = Identifier::new_utf8(after_plus.trim_matches('+'));
        return;
    }

    // implicit pre (without `-` prefix), optionally followed by "+build"
    let (pre, build_opt) = split_pre_build(tail);
    version.pre = Identifier::new_utf8(pre.trim_end_matches('-'));

    if let Some(build) = build_opt {
        version.build = Identifier::new_utf8(build.trim_matches('+'));
    }
}

fn split_pre_build(s: &str) -> (&str, Option<&str>) {
    match s.split_once('+') {
        Some((pre, build)) => (pre, (!build.is_empty()).then_some(build)),
        None => (s, None),
    }
}
