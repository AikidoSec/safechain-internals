use rama::http::{
    HeaderMap, HeaderName, HeaderValue,
    header::{CACHE_CONTROL, ETAG, Entry, LAST_MODIFIED},
    headers::{HeaderEncode, TypedHeader},
};
use rama::telemetry::tracing;

pub fn remove_cache_headers(headers: &mut HeaderMap) {
    for header_name in [ETAG, LAST_MODIFIED, CACHE_CONTROL] {
        match headers.entry(header_name) {
            Entry::Occupied(entry) => {
                let (key, values) = entry.remove_entry_mult();
                let removed = values.count();
                tracing::debug!(header = %key, removed, "removed cache header values");
            }
            Entry::Vacant(_) => {}
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// x-blocked-by http header that is used by the firewall
/// in case a request was blocked.
pub struct BlockedByHeader;

impl TypedHeader for BlockedByHeader {
    fn name() -> &'static HeaderName {
        static NAME: HeaderName = HeaderName::from_static("x-blocked-by");
        &NAME
    }
}

impl HeaderEncode for BlockedByHeader {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(std::iter::once(HeaderValue::from_static(
            crate::utils::env::server_identifier(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::remove_cache_headers;
    use rama::http::header::{CACHE_CONTROL, ETAG, LAST_MODIFIED};
    use rama::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_remove_cache_headers_removes_all_values() {
        let mut headers = HeaderMap::new();

        headers.insert(ETAG, HeaderValue::from_static("v1"));
        headers.append(ETAG, HeaderValue::from_static("v2"));

        headers.insert(LAST_MODIFIED, HeaderValue::from_static("yesterday"));
        headers.append(LAST_MODIFIED, HeaderValue::from_static("today"));

        headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
        headers.append(CACHE_CONTROL, HeaderValue::from_static("no-cache"));

        headers.insert("x-foo", HeaderValue::from_static("bar"));

        remove_cache_headers(&mut headers);

        assert!(!headers.contains_key(ETAG));
        assert!(!headers.contains_key(LAST_MODIFIED));
        assert!(!headers.contains_key(CACHE_CONTROL));
        assert_eq!(headers.get("x-foo"), Some(&HeaderValue::from_static("bar")));
    }
}
