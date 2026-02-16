use rama::http::{
    Request, Response, StatusCode,
    headers::{self, HeaderMapExt as _},
    service::web::response::{Headers, IntoResponse},
};

use super::KnownContentType;

const CONTACT_ADMIN_MESSAGE: &str = "Contact your security administrator for more information.";
const GENERIC_BLOCKED_MESSAGE: &str =
    "The requested source was blocked due to your organization policy.";
const MALWARE_BLOCKED_MESSAGE: &str =
    "This download was blocked because it was identified as malware.";

fn html_blocked_payload(message: &str) -> String {
    format!(
        r##"<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
    <title>Blocked</title>
</head>
<body>
    <h1>Request blocked</h1>
    <p>{}</p>
    <p>{}</p>
</body>
</html>
"##,
        message, CONTACT_ADMIN_MESSAGE
    )
}

fn txt_blocked_payload(message: &str) -> String {
    format!("{}\n{}\n", message, CONTACT_ADMIN_MESSAGE)
}

fn json_blocked_payload(message: &str) -> String {
    format!(
        r##"{{
    \"error\": \"blocked\",
    \"message\": \"{}\",
    \"action\": \"{}\"
}}"##,
        message, CONTACT_ADMIN_MESSAGE
    )
}

fn xml_blocked_payload(message: &str) -> String {
    format!(
        r##"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<response>
    <error>blocked</error>
    <message>{}</message>
    <action>{}</action>
</response>"##,
        message, CONTACT_ADMIN_MESSAGE
    )
}

pub fn generate_generic_blocked_response_for_req(req: Request) -> Response {
    let maybe_detected_ct = req
        .headers()
        .typed_get()
        .and_then(KnownContentType::detect_from_accept_header);

    match maybe_detected_ct {
        Some(KnownContentType::Html) => generate_blocked_response_for_payload(
            headers::ContentType::html_utf8(),
            html_blocked_payload(GENERIC_BLOCKED_MESSAGE),
        ),
        Some(KnownContentType::Txt) => generate_blocked_response_for_payload(
            headers::ContentType::text_utf8(),
            txt_blocked_payload(GENERIC_BLOCKED_MESSAGE),
        ),
        Some(KnownContentType::Json) => generate_blocked_response_for_payload(
            headers::ContentType::json(),
            json_blocked_payload(GENERIC_BLOCKED_MESSAGE),
        ),
        Some(KnownContentType::Xml) => generate_blocked_response_for_payload(
            headers::ContentType::xml(),
            xml_blocked_payload(GENERIC_BLOCKED_MESSAGE),
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
            html_blocked_payload(MALWARE_BLOCKED_MESSAGE),
        ),
        Some(KnownContentType::Txt) => generate_blocked_response_for_payload(
            headers::ContentType::text_utf8(),
            txt_blocked_payload(MALWARE_BLOCKED_MESSAGE),
        ),
        Some(KnownContentType::Json) => generate_blocked_response_for_payload(
            headers::ContentType::json(),
            json_blocked_payload(MALWARE_BLOCKED_MESSAGE),
        ),
        Some(KnownContentType::Xml) => generate_blocked_response_for_payload(
            headers::ContentType::xml(),
            xml_blocked_payload(MALWARE_BLOCKED_MESSAGE),
        ),
        // Default to plain text when content type is unknown
        None => generate_blocked_response_for_payload(
            headers::ContentType::text_utf8(),
            txt_blocked_payload(MALWARE_BLOCKED_MESSAGE),
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
