use rama::http::{
    Request, Response, StatusCode,
    headers::{self, Accept, HeaderMapExt},
    mime,
    service::web::response::{Headers, IntoResponse},
};

pub(super) fn generate_blocked_response_for_req(req: Request) -> Response {
    let maybe_detected_ct = req
        .headers()
        .typed_get()
        .and_then(ContentType::detect_from_accept_header);

    match maybe_detected_ct {
        Some(ContentType::Html) => generate_blocked_response_for_payload(
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
        Some(ContentType::Txt) => generate_blocked_response_for_payload(
            headers::ContentType::text_utf8(),
            r##"The requested source was blocked due to your organization policy.
Contact your security administrator for more information.
"##,
        ),
        Some(ContentType::Json) => generate_blocked_response_for_payload(
            headers::ContentType::json(),
            r##"{
    "error": "blocked",
    "message": "The requested source was blocked due to your organization policy.",
    "action": "Contact your security administrator for more information."
}"##,
        ),
        Some(ContentType::Xml) => generate_blocked_response_for_payload(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Content Type requested in Accept header from incoming Request.
enum ContentType {
    Html,
    Txt,
    Json,
    Xml,
}

impl ContentType {
    fn detect_from_accept_header(Accept(qvs): Accept) -> Option<Self> {
        qvs.iter().find_map(|qv| {
            let r#type = qv.value.subtype();
            if r#type == mime::JSON {
                Some(Self::Json)
            } else if r#type == mime::HTML {
                Some(Self::Html)
            } else if r#type == mime::TEXT {
                Some(Self::Txt)
            } else if r#type == mime::XML {
                Some(Self::Xml)
            } else {
                None
            }
        })
    }
}
