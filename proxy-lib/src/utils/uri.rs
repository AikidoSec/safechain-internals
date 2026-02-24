use rama::{http::Uri, utils::str::arcstr::ArcStr};

/// Convert a URI to a safe filename for caching.
pub fn uri_to_filename(uri: &Uri) -> ArcStr {
    uri.to_string()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .into()
}
