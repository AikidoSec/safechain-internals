use rama::http::{
    Request, Response, StatusCode,
    headers::{self, Accept, HeaderMapExt, specifier},
    mime,
    service::web::response::{Headers, IntoResponse},
};

use smallvec::SmallVec;

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
        let mut sorted_qvs: SmallVec<[(mime::Mime, specifier::Quality); 8]> = qvs
            .into_iter()
            .map(|qvs| (qvs.value, qvs.quality))
            .collect();
        sorted_qvs.sort_by_cached_key(|a| u16::MAX - a.1.as_u16());

        sorted_qvs.iter().find_map(|(value, _)| {
            let r#type = value.subtype();
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

#[cfg(test)]
mod tests {
    use rama::http::{HeaderValue, headers::HeaderDecode};

    use super::*;

    #[test]
    fn test_detect_from_accept_header() {
        for (header_value, expected_result) in [
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                Some(ContentType::Html),
            ),
            ("text/html", Some(ContentType::Html)),
            (
                "application/xml,text/html,application/xhtml+xml,*/*;q=0.8",
                Some(ContentType::Xml),
            ),
            ("application/xml", Some(ContentType::Xml)),
            (
                "application/xml,text/html,application/xhtml+xml,*/*;q=0.8",
                Some(ContentType::Xml),
            ),
            ("application/xml", Some(ContentType::Xml)),
            ("text/html;q=0.8,application/xml", Some(ContentType::Xml)),
            (
                "text/html;q=0.8,application/json;q=0.9,application/xml,plain/text",
                Some(ContentType::Xml),
            ),
            (
                "text/html;q=0.8,application/json;q=0.9,plain/text,application/xml",
                Some(ContentType::Txt),
            ),
            (
                "text/html;q=0.8,application/json;q=0.9,plain/text;q=0.2,application/xml",
                Some(ContentType::Xml),
            ),
            ("plain/text", Some(ContentType::Txt)),
            ("plain/text; charset=utf8", Some(ContentType::Txt)),
            ("plain/text; charset=utf8; q=0.5", Some(ContentType::Txt)),
        ] {
            let accept =
                Accept::decode(&mut [&HeaderValue::from_static(header_value)].into_iter()).unwrap();
            let maybe_ct = ContentType::detect_from_accept_header(accept.clone());
            assert_eq!(
                maybe_ct, expected_result,
                "header value: {header_value}; parsed qvs: {:?}",
                accept.0
            );
        }
    }
}
