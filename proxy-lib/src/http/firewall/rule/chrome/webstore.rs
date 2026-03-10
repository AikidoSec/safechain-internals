use std::time::Duration;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    http::{
        BodyExtractExt, HeaderValue, Request, Response, Uri, service::client::HttpClientExt as _,
    },
    net::uri::util::percent_encoding::percent_encode_byte,
    telemetry::tracing,
};

pub(super) struct ChromeWebStore;

const LOOKUP_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_REDIRECTS: usize = 3;

impl ChromeWebStore {
    /// Fetches the human-readable name of a Chrome extension from the Chrome Web Store.
    /// Returns `None` if the name cannot be determined (timeout, network error, not found).
    pub(super) async fn get_extension_name<C>(
        client: &C,
        extension_id: &str,
    ) -> Result<Option<String>, BoxError>
    where
        C: Service<Request, Output = Response, Error = BoxError> + Clone,
    {
        let mut uri: Uri = format!("https://chromewebstore.google.com/detail/{}", extension_id)
            .parse()
            .context("build Chrome Web Store URI")?;

        for _ in 0..=MAX_REDIRECTS {
            let resp = match tokio::time::timeout(LOOKUP_TIMEOUT, client.get(uri).send()).await {
                Ok(result) => result?,
                Err(_) => return Ok(None),
            };

            let status = resp.status();
            if status.is_redirection() {
                let Some(new_uri) = resp
                    .headers()
                    .get("location")
                    .and_then(Self::parse_redirect_location)
                else {
                    return Ok(None);
                };

                tracing::debug!(extension_id, new_uri = %new_uri, "following Chrome Web Store redirect");
                uri = new_uri;
                continue;
            }

            if !status.is_success() {
                tracing::debug!(extension_id, %status, "Chrome Web Store name lookup failed");
                return Ok(None);
            }

            let body = match tokio::time::timeout(LOOKUP_TIMEOUT, resp.try_into_string()).await {
                Ok(result) => result?,
                Err(_) => return Ok(None),
            };

            return Ok(Self::extract_og_title(&body));
        }

        Ok(None)
    }

    pub(super) fn parse_redirect_location(location: &HeaderValue) -> Option<Uri> {
        // Chrome Web Store sometimes emits raw UTF-8 bytes in the Location header.
        // `HeaderValue::to_str()` rejects those, so encode directly from the raw bytes.
        let encoded = ChromeWebStore::percent_encode_non_ascii(location.as_bytes());
        encoded
            .parse::<Uri>()
            .ok()
            .filter(|uri| uri.scheme().is_some())
            .or_else(|| {
                format!("https://chromewebstore.google.com{encoded}")
                    .parse::<Uri>()
                    .ok()
            })
    }

    /// Percent-encodes any non-ASCII bytes so the result can be parsed as a URI.
    /// ASCII bytes are left unchanged.
    fn percent_encode_non_ascii(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len());
        for &byte in bytes {
            if byte.is_ascii() {
                encoded.push(byte as char);
            } else {
                encoded.push_str(percent_encode_byte(byte));
            }
        }
        encoded
    }

    /// Extracts the extension name from a Chrome Web Store HTML page via the `og:title` meta tag,
    /// stripping the " - Chrome Web Store" suffix.
    pub(super) fn extract_og_title(html: &str) -> Option<String> {
        // Look for: <meta property="og:title" content="Extension Name - Chrome Web Store">
        let og_title_pos = html.find("og:title")?;
        let window = &html[og_title_pos..(og_title_pos + 256).min(html.len())];

        let content_start = window.find(r#"content=""#)? + r#"content=""#.len();
        let content_end = content_start + window[content_start..].find('"')?;

        let raw = &window[content_start..content_end];
        let title = raw.strip_suffix(" - Chrome Web Store")?.trim();

        (!title.is_empty()).then(|| title.to_owned())
    }
}
