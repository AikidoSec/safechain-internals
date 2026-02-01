use rama::http::Request;

pub mod domain;
pub mod path;
pub mod range;

#[derive(Debug)]
pub struct SourceFilter {
    range: self::range::RangeFilter,
    domain: Option<self::domain::DomainFilter>,
    path: Option<self::path::PathFilter>,
}

#[derive(Debug)]
pub enum FilterResult {
    Continue,
    Skip,
    Done,
}

impl SourceFilter {
    pub fn new_synthetic_filter(
        range: Option<self::range::RangeFilter>,
        domain: Option<self::domain::DomainFilter>,
        path: Option<self::path::PathFilter>,
    ) -> Self {
        Self {
            range: range.unwrap_or_else(self::range::RangeFilter::new_single),
            domain,
            path,
        }
    }

    pub fn new_har_filter(
        range: Option<self::range::RangeFilter>,
        domain: Option<self::domain::DomainFilter>,
        path: Option<self::path::PathFilter>,
    ) -> Self {
        Self {
            range: range.unwrap_or_else(self::range::RangeFilter::new_infinite),
            domain,
            path,
        }
    }

    pub fn filter(&mut self, req: &Request) -> FilterResult {
        if let Some(domain_matcher) = self.domain.as_ref()
            && !domain_matcher.match_req(req)
        {
            return FilterResult::Skip;
        }

        if let Some(path_matcher) = self.path.as_ref()
            && !path_matcher.match_req(req)
        {
            return FilterResult::Skip;
        }

        // IMPORTANT: range is post-filtered!
        if self.range.advance() {
            FilterResult::Done
        } else {
            FilterResult::Continue
        }
    }
}
