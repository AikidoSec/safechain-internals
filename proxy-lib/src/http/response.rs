use rama::http::{
    Request, Response, StatusCode,
    headers::{self, HeaderMapExt as _},
    service::web::response::{Headers, IntoResponse},
};

use crate::http::firewall::events::BlockReason;

use super::KnownContentType;

const CONTACT_ADMIN_MESSAGE: &str = "Contact your security administrator for more information.";
const MALWARE_BLOCKED_MESSAGE: &str =
    "This download was blocked because it was identified as malware.";
const REJECTED_BLOCKED_MESSAGE: &str = "This download was blocked by your organization policy.";
const BLOCK_ALL_BLOCKED_MESSAGE: &str = "Your organization blocks all installs for this source.";
const REQUEST_INSTALL_BLOCKED_MESSAGE: &str =
    "Install approval is required by your organization policy.";

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

fn blocked_message_for_reason(block_reason: &BlockReason) -> &'static str {
    match block_reason {
        BlockReason::Malware => MALWARE_BLOCKED_MESSAGE,
        BlockReason::Rejected => REJECTED_BLOCKED_MESSAGE,
        BlockReason::BlockAll => BLOCK_ALL_BLOCKED_MESSAGE,
        BlockReason::RequestInstall => REQUEST_INSTALL_BLOCKED_MESSAGE,
    }
}

pub fn generate_blocked_response_for_req(req: Request, block_reason: &BlockReason) -> Response {
    let message = blocked_message_for_reason(block_reason);
    let maybe_detected_ct = req
        .headers()
        .typed_get()
        .and_then(KnownContentType::detect_from_accept_header);

    match maybe_detected_ct {
        Some(KnownContentType::Html) => generate_blocked_response_for_payload(
            headers::ContentType::html_utf8(),
            html_blocked_payload(message),
        ),
        Some(KnownContentType::Txt) => generate_blocked_response_for_payload(
            headers::ContentType::text_utf8(),
            txt_blocked_payload(message),
        ),
        Some(KnownContentType::Json) => generate_blocked_response_for_payload(
            headers::ContentType::json(),
            json_blocked_payload(message),
        ),
        Some(KnownContentType::Xml) => generate_blocked_response_for_payload(
            headers::ContentType::xml(),
            xml_blocked_payload(message),
        ),
        None => {
            if matches!(block_reason, BlockReason::Malware) {
                generate_blocked_response_for_payload(
                    headers::ContentType::text_utf8(),
                    txt_blocked_payload(message),
                )
            } else {
                generate_blocked_response_without_payload()
            }
        }
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
