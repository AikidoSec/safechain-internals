use rama::http::{
    Request, Response, StatusCode,
    headers::{self, HeaderMapExt as _},
    service::web::response::{Headers, IntoResponse},
};

use super::KnownContentType;

pub fn generate_generic_blocked_response_for_req(req: Request) -> Response {
    let maybe_detected_ct = req
        .headers()
        .typed_get()
        .and_then(KnownContentType::detect_from_accept_header);

    match maybe_detected_ct {
        Some(KnownContentType::Html) => generate_blocked_response_for_payload(
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
        Some(KnownContentType::Txt) => generate_blocked_response_for_payload(
            headers::ContentType::text_utf8(),
            r##"The requested source was blocked due to your organization policy.
Contact your security administrator for more information.
"##,
        ),
        Some(KnownContentType::Json) => generate_blocked_response_for_payload(
            headers::ContentType::json(),
            r##"{
    "error": "blocked",
    "message": "The requested source was blocked due to your organization policy.",
    "action": "Contact your security administrator for more information."
}"##,
        ),
        Some(KnownContentType::Xml) => generate_blocked_response_for_payload(
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

pub fn generate_malware_blocked_response_for_req(req: Request) -> Response {
    let maybe_detected_ct = req
        .headers()
        .typed_get()
        .and_then(KnownContentType::detect_from_accept_header);

    match maybe_detected_ct {
        Some(KnownContentType::Html) => generate_blocked_response_for_payload(
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
    <p>This download was blocked because it was identified as malware.</p>
    <p>Contact your security administrator for more information.</p>
</body>
</html>
"##,
        ),
        Some(KnownContentType::Txt) => generate_blocked_response_for_payload(
            headers::ContentType::text_utf8(),
            r##"This download was blocked because it was identified as malware.
Contact your security administrator for more information.
"##,
        ),
        Some(KnownContentType::Json) => generate_blocked_response_for_payload(
            headers::ContentType::json(),
            r##"{
    "error": "blocked",
    "reason": "malware",
    "message": "This download was blocked because it was identified as malware.",
    "action": "Contact your security administrator for more information."
}"##,
        ),
        Some(KnownContentType::Xml) => generate_blocked_response_for_payload(
            headers::ContentType::xml(),
            r##"<?xml version="1.0" encoding="UTF-8"?>
<response>
    <error>blocked</error>
    <reason>malware</reason>
    <message>This download was blocked because it was identified as malware.</message>
    <action>Contact your security administrator for more information.</action>
</response>"##,
        ),
        // Default to plain text when content type is unknown
        None => generate_blocked_response_for_payload(
            headers::ContentType::text_utf8(),
            r##"This download was blocked because it was identified as malware.
Contact your security administrator for more information.
"##,
        ),
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
