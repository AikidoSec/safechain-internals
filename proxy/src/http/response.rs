use rama::http::{
    Request, Response, StatusCode,
    headers::{self, HeaderMapExt as _},
    service::web::response::{Headers, IntoResponse},
};

use super::RequestedContentType;

pub fn generate_generic_blocked_response_for_req(req: Request) -> Response {
    let maybe_detected_ct = req
        .headers()
        .typed_get()
        .and_then(RequestedContentType::detect_from_accept_header);

    match maybe_detected_ct {
        Some(RequestedContentType::Html) => generate_blocked_response_for_payload(
            headers::ContentType::html_utf8(),
            r##"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Blocked</title>
</head>
<body>
    <h1>Request blocked</h1>
    <p>The requested source was blocked due to your organization policy.</p>
    <p>Contact your security administrator for more information.</p>
</body>
</html>
"##,
        ),
        Some(RequestedContentType::Txt) => generate_blocked_response_for_payload(
            headers::ContentType::text_utf8(),
            r##"The requested source was blocked due to your organization policy.
Contact your security administrator for more information.
"##,
        ),
        Some(RequestedContentType::Json) => generate_blocked_response_for_payload(
            headers::ContentType::json(),
            r##"{
    "error": "blocked",
    "message": "The requested source was blocked due to your organization policy.",
    "action": "Contact your security administrator for more information."
}"##,
        ),
        Some(RequestedContentType::Xml) => generate_blocked_response_for_payload(
            headers::ContentType::xml(),
            r##"<?xml version="1.0" encoding="UTF-8"?>
<response>
    <error>blocked</error>
    <message>The requested source was blocked due to your organization policy.</message>
    <action>Contact your security administrator for more information.</action>
</response>"##,
        ),
        None => generate_blocked_response_without_payload(),
    }
}

pub fn generate_blocked_response_with_context(
    req: Request,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    reason: &str,
) -> Response {
    let maybe_detected_ct = req
        .headers()
        .typed_get()
        .and_then(RequestedContentType::detect_from_accept_header);

    let version_str = version.unwrap_or("unknown");
    match maybe_detected_ct {
        Some(RequestedContentType::Html) => generate_blocked_response_for_payload(
            headers::ContentType::html_utf8(),
            format!(
                r#"<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
    <title>Blocked by Safe Chain</title>
</head>
<body>
    <h1>Request blocked</h1>
    <p>Safe Chain blocked a {ecosystem} package download.</p>
    <ul>
        <li><strong>Package:</strong> <code>{package}</code></li>
        <li><strong>Version:</strong> <code>{version_str}</code></li>
        <li><strong>Reason:</strong> {reason}</li>
    </ul>
    <p>Installation was prevented to keep your environment secure.</p>
</body>
</html>
"#
            ),
        ),
        Some(RequestedContentType::Txt) => generate_blocked_response_for_payload(
            headers::ContentType::text_utf8(),
            format!(
                "Safe Chain blocked a {ecosystem} package.\nPackage: {package}\nVersion: {version_str}\nReason: {reason}\n"
            ),
        ),
        Some(RequestedContentType::Json) => generate_blocked_response_for_payload(
            headers::ContentType::json(),
            format!(
                r#"{{
    "error": "blocked",
    "ecosystem": "{ecosystem}",
    "package": "{package}",
    "version": "{version_str}",
    "reason": "{reason}",
    "message": "Safe Chain blocked this package download.",
    "action": "Contact your security administrator if you believe this is a mistake."
}}"#
            ),
        ),
        Some(RequestedContentType::Xml) => generate_blocked_response_for_payload(
            headers::ContentType::xml(),
            format!(
                r#"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<response>
    <error>blocked</error>
    <ecosystem>{}</ecosystem>
    <package>{}</package>
    <version>{}</version>
    <reason>{}</reason>
    <message>Safe Chain blocked this package download.</message>
    <action>Contact your security administrator if you believe this is a mistake.</action>
</response>"#,
                ecosystem, package, version_str, reason
            ),
        ),
        None => generate_blocked_response_without_payload(),
    }
}

const BLOCKED_STATUS_CODE: StatusCode = StatusCode::FORBIDDEN;

fn generate_blocked_response_for_payload(
    ct: headers::ContentType,
    body: impl IntoResponse,
) -> Response {
    (BLOCKED_STATUS_CODE, Headers::single(ct), body).into_response()
}

fn generate_blocked_response_without_payload() -> Response {
    BLOCKED_STATUS_CODE.into_response()
}
