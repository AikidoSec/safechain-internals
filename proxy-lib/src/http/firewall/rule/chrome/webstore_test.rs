use rama::http::HeaderValue;

use super::webstore::ChromeWebStore;

#[test]
fn test_extract_og_title_strips_suffix() {
    let html = r#"<meta property="og:title" content="uBlock Origin - Chrome Web Store">"#;
    assert_eq!(
        ChromeWebStore::extract_og_title(html),
        Some("uBlock Origin".to_owned())
    );
}

#[test]
fn test_extract_og_title_no_suffix() {
    let html = r#"<meta property="og:title" content="Chrome Web Store">"#;
    assert_eq!(ChromeWebStore::extract_og_title(html), None);
}

#[test]
fn test_extract_og_title_missing() {
    let html = r#"<title>Some Page</title>"#;
    assert_eq!(ChromeWebStore::extract_og_title(html), None);
}

#[test]
fn test_extract_og_title_empty_content() {
    let html = r#"<meta property="og:title" content="">"#;
    assert_eq!(ChromeWebStore::extract_og_title(html), None);
}

#[test]
fn test_extract_og_title_only_suffix() {
    let html = r#"<meta property="og:title" content=" - Chrome Web Store">"#;
    assert_eq!(ChromeWebStore::extract_og_title(html), None);
}

#[test]
fn test_extract_og_title_realistic_html() {
    let html = r#"
        <head>
            <meta charset="UTF-8">
            <meta property="og:type" content="website">
            <meta property="og:title" content="Into the Black Hole - Chrome Web Store">
            <meta property="og:description" content="...">
        </head>
    "#;
    assert_eq!(
        ChromeWebStore::extract_og_title(html),
        Some("Into the Black Hole".to_owned())
    );
}

#[test]
fn test_parse_redirect_location_accepts_relative_uri() {
    let location =
        HeaderValue::from_static("/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm");

    let uri = ChromeWebStore::parse_redirect_location(&location).unwrap();

    assert_eq!(
        uri.to_string(),
        "https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm"
    );
}
