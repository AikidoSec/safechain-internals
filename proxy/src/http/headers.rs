use rama::http::HeaderMap;

pub fn remove_cache_headers(headers: &mut HeaderMap) {
    headers.remove(rama::http::header::ETAG);
    headers.remove(rama::http::header::LAST_MODIFIED);
    headers.remove(rama::http::header::CACHE_CONTROL);
}
