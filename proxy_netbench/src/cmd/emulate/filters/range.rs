use std::str::FromStr;

use rama::error::{ErrorContext as _, OpaqueError};

#[derive(Debug, Clone)]
pub struct RangeFilter {
    idx: usize,
    max: usize,
}

impl RangeFilter {
    pub(super) fn new_single() -> Self {
        Self { idx: 0, max: 0 }
    }

    pub(super) fn new_infinite() -> Self {
        Self {
            idx: 0,
            max: RANGE_MAX.saturating_sub(1),
        }
    }

    /// Returns true if the filter is still within bounds,
    /// and false otherwise (meaning stop iterating).
    pub(super) fn advance(&mut self) -> bool {
        if self.idx > self.max {
            return false;
        }

        self.idx += 1;
        true
    }
}

/// Arbitrary max limit to avoid too large runs.
const RANGE_MAX: usize = 32_000;

impl FromStr for RangeFilter {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed_s = s.trim();
        if trimmed_s.is_empty() {
            return Err(OpaqueError::from_display(
                "empty string is not a valid range",
            ));
        }

        let Some((first, second)) = trimmed_s.split_once("..") else {
            let max: usize = trimmed_s.parse().context("parse range as max value")?;
            if max == 0 {
                return Err(OpaqueError::from_display(
                    "MAX value has to be greater than zero (0)",
                ));
            }
            return Ok(RangeFilter {
                idx: 0,
                max: max - 1,
            });
        };

        let min = if first.is_empty() {
            0
        } else {
            first.parse().context("parse min value")?
        };

        let max = if second.is_empty() {
            min + RANGE_MAX
        } else {
            let (second_trimmed, is_inclusive) = second
                .strip_prefix('=')
                .map(|s| (s, true))
                .unwrap_or((second, false));

            let mut max: usize = second_trimmed.parse().context("parse max value")?;
            if !is_inclusive {
                max = max.saturating_sub(1);
            }

            if max < min {
                return Err(OpaqueError::from_display(
                    "MAX value has to be greater than or equal to MIN value",
                ));
            }

            let diff = max - min;
            if diff > RANGE_MAX {
                return Err(OpaqueError::from_display(
                    "range overflow: max iterations of {RANGE_MAX} reached",
                ));
            }

            max
        };

        Ok(RangeFilter { idx: min, max })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str, min: usize, max: usize) {
        let parsed: RangeFilter = input.parse().unwrap_or_else(|e| {
            panic!("expected Ok for input {input:?}, got Err: {e}\nerror debug: {e:?}")
        });
        assert_eq!(
            parsed.idx, min,
            "idx should always start at min for input {input:?}"
        );
        assert_eq!(parsed.max, max, "max mismatch for input {input:?}");
    }

    fn err_contains(input: &str, needle: &str) {
        let err = input.parse::<RangeFilter>().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(needle),
            "for input {input:?}, expected error containing {needle:?}, got: {msg:?}\nerror debug: {err:?}"
        );
    }

    #[test]
    fn range_filter_from_str_edge_cases() {
        // No ".." means treat it as a max value, with min fixed at 0
        ok("1", 0, 0);
        ok("  12  ", 0, 11);
        err_contains("0", "MAX value has to be greater than zero");
        err_contains("   0   ", "MAX value has to be greater than zero");
        err_contains("nope", "parse range as max value");

        // Basic range parsing
        ok("0..0", 0, 0); // exclusive end, saturating_sub keeps it 0
        ok("0..1", 0, 0); // exclusive end, 1 becomes 0
        ok("0..=0", 0, 0); // inclusive end
        ok("0..=1", 0, 1); // inclusive end
        ok("  3..=5  ", 3, 5);
        ok("3..5", 3, 4); // exclusive end

        // Missing min defaults to 0
        ok("..5", 0, 4);
        ok("..=5", 0, 5);

        // Missing max defaults to min + RANGE_MAX
        ok("..", 0, RANGE_MAX);
        ok("5..", 5, 5 + RANGE_MAX);

        // Inclusive marker with missing max still means "missing max"
        // because the code only checks '=' when second is non empty,
        // so "5..=" will attempt to parse an empty string as max and fail
        err_contains("5..=", "parse max value");

        // Validation errors
        err_contains(
            "10..5",
            "MAX value has to be greater than or equal to MIN value",
        );
        err_contains(
            "10..=5",
            "MAX value has to be greater than or equal to MIN value",
        );

        // Range overflow checks apply when max is explicitly provided
        // diff is max - min after exclusivity handling
        ok("0..=32000", 0, 32000); // diff == RANGE_MAX is allowed
        err_contains("0..=32001", "range overflow");

        ok("5..=32005", 5, 32005); // diff == RANGE_MAX is allowed
        err_contains("5..=32006", "range overflow");

        // Parse error contexts for each part
        err_contains("a..5", "parse min value");
        err_contains("1..b", "parse max value");
        err_contains("1..=b", "parse max value");

        // Weird but important: split_once("..") splits at the first ".."
        // "1...2" becomes first "1", second ".2" and then max parse fails
        err_contains("1...2", "parse max value");
        // same same
        err_contains("1..2..3", "parse max value");
    }

    #[test]
    fn advance_stops_exactly_after_max() {
        let mut rf = RangeFilter { max: 5, idx: 3 };

        // idx = 3
        assert!(rf.advance());
        assert_eq!(rf.idx, 4);

        // idx = 4
        assert!(rf.advance());
        assert_eq!(rf.idx, 5);

        // idx = 5
        assert!(rf.advance());
        assert_eq!(rf.idx, 6);

        // idx = 6, now beyond max
        assert!(!rf.advance());
        assert_eq!(rf.idx, 6);
    }

    #[test]
    fn advance_immediately_stops_when_already_out_of_bounds() {
        let mut rf = RangeFilter { max: 2, idx: 3 };

        assert!(!rf.advance());
        assert_eq!(rf.idx, 3);
    }
}
