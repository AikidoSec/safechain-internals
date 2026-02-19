use rama::{http::Uri, utils::str::arcstr::ArcStr};

/// Convert a URI to a safe filename for caching.
pub fn uri_to_filename(uri: &Uri) -> ArcStr {
    uri.to_string()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_to_filename_basic() {
        let uri = Uri::from_static("https://example.com/path");
        assert_eq!(uri_to_filename(&uri).as_str(), "https___example_com_path");
    }

    #[test]
    fn test_uri_to_filename_with_query() {
        let uri = Uri::from_static("https://example.com/foo?bar=baz&answer=42");
        assert_eq!(
            uri_to_filename(&uri).as_str(),
            "https___example_com_foo_bar_baz_answer_42"
        );
    }

    #[test]
    fn test_uri_to_filename_complex() {
        let uri = Uri::from_static("https://config.aikido.dev/api/endpoint_protection/config");
        assert_eq!(
            uri_to_filename(&uri).as_str(),
            "https___config_aikido_dev_api_endpoint_protection_config"
        );
    }
}
