use rama::http::{
    HeaderMap, HeaderName,
    header,
    headers::{CacheControl, HeaderMapExt as _},
    layer::remove_header::{
        remove_cache_policy_headers, remove_cache_validation_response_headers,
    },
};

pub const X_DEVICE_ID: HeaderName = HeaderName::from_static("x-device-id");

/// Strips all caching headers and inserts `Cache-Control: no-cache`.
///
/// Example use case is (firewall) min-package-age rules after
/// rewriting a response body so that the client cannot serve a stale,
/// unfiltered copy from its own cache.
pub fn make_response_uncacheable(headers: &mut HeaderMap) {
    remove_cache_policy_headers(headers);
    remove_cache_validation_response_headers(headers);
    headers.remove(header::CONTENT_LENGTH);
    headers.typed_insert(CacheControl::new().with_no_cache());
}
