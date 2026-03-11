use std::time::Duration;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    http::{
        BodyExtractExt, HeaderValue, Request, Response, Uri, service::client::HttpClientExt as _,
        uri::PathAndQuery,
    },
    telemetry::tracing,
};

pub(super) struct ChromeWebStore;

const LOOKUP_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_REDIRECTS: usize = 3;
const CHROME_WEBSTORE_AUTHORITY: &str = "chromewebstore.google.com";
const HTTPS_SCHEME: &str = "https";

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
                tracing::info!(extension_id, %status, "Chrome Web Store name lookup failed, extension id will be shown as-is.");
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
        let location = std::str::from_utf8(location.as_bytes()).ok()?;

        location
            .parse::<Uri>()
            .ok()
            .filter(|uri| uri.scheme().is_some())
            .or_else(|| {
                Uri::builder()
                    .scheme(HTTPS_SCHEME)
                    .authority(CHROME_WEBSTORE_AUTHORITY)
                    .path_and_query(location.parse::<PathAndQuery>().ok()?)
                    .build()
                    .ok()
            })
    }

    /// Extracts the extension name from a Chrome Web Store HTML page via the `og:title` meta tag,
    /// stripping the " - Chrome Web Store" suffix.
    pub(super) fn extract_og_title(html: &str) -> Option<String> {
        // Look for: <meta property="og:title" content="Extension Name - Chrome Web Store">
        let og_title_pos = html.find("og:title")?;
        let tail = &html[og_title_pos..];

        let content_start = tail.find(r#"content=""#)? + r#"content=""#.len();
        let content_end = content_start + tail[content_start..].find('"')?;

        let raw = &tail[content_start..content_end];
        let title = raw.strip_suffix(" - Chrome Web Store")?.trim();

        (!title.is_empty()).then(|| title.to_owned())
    }
}
