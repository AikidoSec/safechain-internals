use std::time::Duration;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    http::{BodyExtractExt, HeaderValue, Request, Response, Uri, service::client::HttpClientExt as _},
    telemetry::tracing,
};

pub(super) struct ChromeWebStore;

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

        tracing::info!("looking up Chrome extension name for id {}", extension_id);
        // Chrome Web Store redirects `/detail/{id}` → `/detail/{slug}/{id}` with a 301,
        // so we follow up to 3 redirects before giving up.
        for _ in 0..=3 {
            let resp = tokio::time::timeout(Duration::from_millis(500), client.get(uri).send())
                .await
                .context("Chrome Web Store request timed out after 500ms")??;

            if resp.status().is_redirection() {
                let new_uri = resp
                    .headers()
                    .get("location")
                    .and_then(Self::parse_redirect_location);

                if let Some(new_uri) = new_uri {
                    tracing::debug!(
                        extension_id,
                        new_uri = %new_uri,
                        "following redirect from Chrome Web Store during name lookup"
                    );
                    uri = new_uri;
                    continue;
                }

                let location_header = resp
                    .headers()
                    .get("location")
                    .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                    .unwrap_or_default();
                tracing::info!(
                    extension_id,
                    location_header,
                    "Chrome Web Store redirect has unparseable Location header"
                );
                return Ok(None);
            }

            if !resp.status().is_success() {
                tracing::warn!(
                    extension_id,
                    status = %resp.status(),
                    "Chrome Web Store returned non-success status during name lookup"
                );
                return Ok(None);
            }

            let body = tokio::time::timeout(Duration::from_millis(500), resp.try_into_string())
                .await
                .context("reading Chrome Web Store response body timed out after 500ms")??;

            return Ok(Self::extract_og_title(&body));
        }

        Ok(None) // redirect limit exceeded
    }

    pub(super) fn parse_redirect_location(location: &HeaderValue) -> Option<Uri> {
        // Chrome Web Store sometimes emits raw UTF-8 bytes in the Location header.
        // `HeaderValue::to_str()` rejects those, so encode directly from the raw bytes.
        let encoded = ChromeWebStore::percent_encode_non_ascii(location.as_bytes());
        if let Ok(uri) = encoded.parse::<Uri>() {
            if uri.scheme().is_some() {
                return Some(uri);
            }
        }

        format!("https://chromewebstore.google.com{encoded}")
            .parse::<Uri>()
            .ok()
    }

    /// Percent-encodes any non-ASCII bytes so the result can be parsed as a URI.
    /// ASCII bytes are left unchanged.
    fn percent_encode_non_ascii(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len());
        for &b in bytes {
            if b.is_ascii() {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
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

        if title.is_empty() {
            return None;
        }

        Some(title.to_owned())
    }
}
