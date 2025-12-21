use std::convert::Infallible;

use rama::{
    Service,
    http::{
        Request, Response,
        headers::{self, HeaderMapExt as _},
        service::web::response::{Headers, Html, IntoResponse, Json},
    },
    net::address::Domain,
    service::service_fn,
};

use crate::http::RequestedContentType;

pub const CONNECTIVITY_DOMAIN: Domain = Domain::from_static("proxy.safechain.internal");

// NOTE: if this proxy is ever ran as a remote proxy
// you could also enter here network info such as ingress IP etc...

/// Create a new http service that can be used
/// as a pseudo service to easily test as an end-user
/// if connectivity to proxy is as expected.
pub fn new_connectivity_http_svc<Body: Send + 'static>()
-> impl Service<Request<Body>, Output = Response, Error = Infallible> + Clone {
    service_fn(async |req: Request<Body>| Ok(generate_connectivity_page(&req)))
}

fn generate_connectivity_page<Body>(req: &Request<Body>) -> Response {
    let method = req.method().as_str();

    let domain = crate::http::try_get_domain_for_req(req);
    let domain_str = domain.as_ref().map(|d| d.as_str());

    let path = req.uri().path();
    let query = req.uri().query();

    let ct = req
        .headers()
        .typed_get()
        .and_then(RequestedContentType::detect_from_accept_header)
        .unwrap_or(RequestedContentType::Html);

    match ct {
        RequestedContentType::Json => {
            generate_connectivity_page_json_response(method, domain_str, path, query)
        }
        RequestedContentType::Html => {
            generate_connectivity_page_html_response(method, domain_str, path, query)
        }
        RequestedContentType::Txt => {
            generate_connectivity_page_txt_response(method, domain_str, path, query)
        }
        RequestedContentType::Xml => {
            generate_connectivity_page_xml_response(method, domain_str, path, query)
        }
    }
}

fn generate_connectivity_page_html_response(
    method: &str,
    maybe_domain: Option<&str>,
    path: &str,
    maybe_query: Option<&str>,
) -> Response {
    let domain = maybe_domain.unwrap_or("(none)");
    let query = maybe_query.unwrap_or("(none)");

    Html(format!(
        r##"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{title}</title>
    <style>
        html,body{{height:100%}}
        body{{margin:0;font:16px/1.45 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;background:radial-gradient(900px 500px at 50% 0,rgba(120,110,255,.25),transparent 60%),#05061c;color:#f4f5ff;display:grid;place-items:center}}
        main{{text-align:center;padding:24px;display:flex;flex-direction:column;align-items:center}}
        h1{{margin:0;font-weight:800;letter-spacing:-.03em;font-size:clamp(40px,6vw,72px);line-height:1.05}}
        p{{margin:16px auto 0;max-width:46ch;color:rgba(255,255,255,.7)}}
        a{{display:inline-block;margin-top:28px;padding:12px 20px;border-radius:999px;background:#6f6cff;color:#fff;text-decoration:none;font-weight:700}}
        a:hover{{filter:brightness(1.05)}}
        code{{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace;font-size:.95em}}
        .ok{{display:inline-flex;align-items:center;justify-content:center;margin:22px auto 0;padding:10px 18px;border-radius:999px;background:rgba(111,108,255,.18);border:1px solid rgba(111,108,255,.55);color:#f4f5ff;font-weight:800;font-size:28px;line-height:1}}
        .details{{margin:18px auto 0;width:min(760px,92vw);text-align:left;padding:18px 20px;border-radius:18px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.10)}}
        .row{{display:grid;grid-template-columns:110px 1fr;gap:14px;padding:10px 0}}
        .k{{color:rgba(255,255,255,.55);font-size:22px;line-height:1.2}}
        .v{{color:#f4f5ff;font-size:28px;font-weight:800;letter-spacing:-.02em;overflow-wrap:anywhere;line-height:1.2}}
        @media(max-width:520px){{.ok{{font-size:22px}}.k{{font-size:18px}}.v{{font-size:22px}}.row{{grid-template-columns:92px 1fr}}}}
    </style>
</head>
<body>
    <main>
        <h1>{title}</h1>

        <p class="ok">Connected to Proxy</p>

        <div class="details" role="group" aria-label="Connectivity details">
        <div class="row"><div class="k">Method</div><div class="v"><code>{method}</code></div></div>
        <div class="row"><div class="k">Domain</div><div class="v"><code>{domain}</code></div></div>
        <div class="row"><div class="k">Path</div><div class="v"><code>{path}</code></div></div>
        <div class="row"><div class="k">Query</div><div class="v"><code>{escape_query}</code></div></div>
        </div>
    </main>
</body>
</html>
"##,
        title = crate::utils::env::project_name(),
        escape_query = escape_html(query),
    )).into_response()
}

pub fn generate_connectivity_page_json_response(
    method: &str,
    maybe_domain: Option<&str>,
    path: &str,
    maybe_query: Option<&str>,
) -> Response {
    Json(serde_json::json!({
        "ok": true,
        "service": crate::utils::env::project_name(),
        "method": method,
        "domain": maybe_domain,
        "path": path,
        "query": maybe_query,
    }))
    .into_response()
}

pub fn generate_connectivity_page_txt_response(
    method: &str,
    maybe_domain: Option<&str>,
    path: &str,
    maybe_query: Option<&str>,
) -> Response {
    let domain = maybe_domain.unwrap_or_default();
    let query = maybe_query.unwrap_or_default();

    (
        Headers::single(headers::ContentType::xml()),
        format!(
            r#"{}

Connected: true
Method: {method}
Domain: {domain}
Path: {}
Query: {}
"#,
            crate::utils::env::project_name(),
            escape_xml(path),
            escape_xml(query),
        ),
    )
        .into_response()
}

pub fn generate_connectivity_page_xml_response(
    method: &str,
    maybe_domain: Option<&str>,
    path: &str,
    maybe_query: Option<&str>,
) -> Response {
    let domain = maybe_domain.unwrap_or_default();
    let query = maybe_query.unwrap_or_default();

    (
        Headers::single(headers::ContentType::xml()),
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
    <connectivity ok="true">
      <service>{}</service>
      <method>{method}</method>
      <domain>{domain}</domain>
      <path>{}</path>
      <query>{}</query>
    </connectivity>
"#,
            crate::utils::env::project_name(),
            escape_xml(path),
            escape_xml(query),
        ),
    )
        .into_response()
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn escape_xml(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use rama::http::{Body, BodyExtractExt, Method, header::ACCEPT};

    use super::*;

    #[tokio::test]
    async fn test_generate_connectivity_page() {
        for method in [Method::GET, Method::POST, Method::DELETE] {
            for (uri, maybe_expected_domain, expected_path, maybe_expected_query) in [
                (
                    "http://example.com/foo/bar?baz=true&answer=42",
                    Some("example.com"),
                    "/foo/bar",
                    Some("baz=true&answer=42"),
                ),
                (
                    "http://example.com?baz=true&answer=42",
                    Some("example.com"),
                    "/",
                    Some("baz=true&answer=42"),
                ),
                (
                    "http://example.com/foo/bar",
                    Some("example.com"),
                    "/foo/bar",
                    None,
                ),
                ("http://example.com", Some("example.com"), "/", None),
                (
                    "/foo/bar?baz=true&answer=42",
                    None,
                    "/foo/bar",
                    Some("baz=true&answer=42"),
                ),
                (
                    "/?baz=true&answer=42",
                    None,
                    "/",
                    Some("baz=true&answer=42"),
                ),
                ("/foo/bar", None, "/foo/bar", None),
                ("/", None, "/", None),
            ] {
                for (accept, accept_test_value) in [
                    ("plain/text", "Connected: true"),
                    ("application/json", r##""ok":true"##),
                    ("text/html", "<!doctype html>"),
                    ("application/xml", "<?xml version"),
                ] {
                    let req = Request::builder()
                        .method(method.clone())
                        .uri(uri)
                        .header(ACCEPT, accept)
                        .body(Body::empty())
                        .unwrap();

                    let response = generate_connectivity_page(&req);
                    let payload = response.try_into_string().await.unwrap();

                    assert!(
                        payload.contains(method.as_str()),
                        "test = method; case {{ method = {method} ; uri = {uri} ; accept = {accept} }}",
                    );

                    if let Some(expected_domain) = maybe_expected_domain {
                        assert!(
                            payload.contains(expected_domain),
                            "test = domain; case {{ method = {method} ; uri = {uri} ; accept = {accept} }}",
                        );
                    }

                    assert!(
                        payload.contains(expected_path),
                        "test = path; case {{ method = {method} ; uri = {uri} ; accept = {accept} }}",
                    );

                    if let Some(expected_query) = maybe_expected_query {
                        assert!(
                            [
                                expected_query.to_string(),
                                escape_html(expected_query),
                                escape_xml(expected_query)
                            ]
                            .into_iter()
                            .any(|v| payload.contains(&v)),
                            "test = query; case {{ method = {method} ; uri = {uri} ; accept = {accept} }}",
                        );
                    }

                    assert!(
                        payload.contains(accept_test_value),
                        "test = content-type; case {{ method = {method} ; uri = {uri} ; accept = {accept} }}",
                    );
                }
            }
        }
    }
}
