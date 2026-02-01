use std::borrow::Cow;

use rama::{
    error::{ErrorContext as _, OpaqueError},
    http::{Request, Uri},
    net::http::RequestContext,
    utils::str::arcstr::ArcStr,
};

pub fn try_req_to_filename<B>(req: &Request<B>) -> Result<ArcStr, OpaqueError> {
    let uri = try_create_full_uri_for_req(req)?;
    Ok(uri_to_filename(&uri))
}

fn try_create_full_uri_for_req<B>(req: &Request<B>) -> Result<Cow<'_, Uri>, OpaqueError> {
    if req.uri().authority().is_some() {
        return Ok(Cow::Borrowed(req.uri()));
    }

    let request_ctx = RequestContext::try_from(req).context("create RequestContext from req")?;

    let mut uri_parts = req.uri().clone().into_parts();
    uri_parts.scheme = Some(
        request_ctx
            .protocol
            .as_str()
            .try_into()
            .context("use RequestContext.protocol as http scheme")?,
    );

    let authority = if request_ctx.authority_has_default_port() {
        request_ctx.authority.host.to_string()
    } else {
        request_ctx.authority.to_string()
    };

    uri_parts.authority = Some(
        authority
            .try_into()
            .context("use RequestContext.authority as http authority")?,
    );

    Ok(Cow::Owned(
        Uri::from_parts(uri_parts).context("create http uri from parts")?,
    ))
}

/// Display [`Uri`] as a appropriate string for a file name,
/// replacing all non-alphanumeric ASCII characters as an underscore `_`.
pub fn uri_to_filename(url: &Uri) -> ArcStr {
    url.to_string()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .into()
}

#[cfg(test)]
mod tests {
    use rama::http::header::HOST;
    use std::fmt;

    use super::*;

    #[test]
    fn test_url_to_filename() {
        let url = Uri::from_static("http://example.com/foo?bar=baz&answer=42");
        let filename = uri_to_filename(&url);
        assert_eq!("http___example_com_foo_bar_baz_answer_42", filename);
    }

    fn err_contains<T: fmt::Debug>(res: Result<T, OpaqueError>, needle: &str) {
        let err = res.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(needle),
            "expected error containing {needle:?}, got {msg:?}\nerror debug: {err:?}"
        );
    }

    fn req_abs(uri: &'static str) -> Request<()> {
        Request::builder().uri(uri).body(()).unwrap()
    }

    fn req_rel(path: &'static str, host: &'static str) -> Request<()> {
        Request::builder()
            .uri(path)
            .header(HOST, host)
            .body(())
            .unwrap()
    }

    #[test]
    fn uri_to_filename_replaces_non_alnum_ascii() {
        let url = Uri::from_static("http://example.com/foo?bar=baz&answer=42");
        let filename = uri_to_filename(&url);
        assert_eq!("http___example_com_foo_bar_baz_answer_42", filename);
    }

    #[test]
    fn try_req_to_filename_with_absolute_uri_uses_uri_as_is() {
        let req = req_abs("http://example.com/foo?bar=baz&answer=42");
        let filename = try_req_to_filename(&req).unwrap();

        assert_eq!(
            "http___example_com_foo_bar_baz_answer_42",
            filename.as_str()
        );
    }

    #[test]
    fn try_req_to_filename_with_relative_uri_builds_full_uri_from_context() {
        // RequestContext::try_from is expected to derive authority from Host for relative URIs.
        let req = req_rel("/foo?bar=baz&answer=42", "example.com");

        let filename = try_req_to_filename(&req).unwrap();

        // The scheme comes from RequestContext.protocol, which is typically "http" in this setup.
        assert_eq!(
            "http___example_com_foo_bar_baz_answer_42",
            filename.as_str()
        );
    }

    #[test]
    fn try_req_to_filename_strips_default_port_from_authority() {
        // If the authority has the default port, the code drops it.
        // For typical HTTP this means 80.
        let req = req_rel("/foo", "example.com:80");

        let filename = try_req_to_filename(&req).unwrap();

        assert_eq!("http___example_com_foo", filename.as_str());
    }

    #[test]
    fn try_req_to_filename_keeps_non_default_port_in_authority() {
        let req = req_rel("/foo", "example.com:8080");

        let filename = try_req_to_filename(&req).unwrap();

        assert_eq!("http___example_com_8080_foo", filename.as_str());
    }

    #[test]
    fn try_req_to_filename_errors_if_full_context_cannot_be_derived() {
        // Relative URI without authority and without Host header.
        let req = Request::builder().uri("/foo").body(()).unwrap();

        err_contains(try_req_to_filename(&req), "create RequestContext from req");
    }
}
