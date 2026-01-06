use rama::http::{headers::Accept, mime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Content Type requested in Accept header from incoming Request.
pub enum RequestedContentType {
    Json,
    Html,
    Txt,
    Xml,
}

impl RequestedContentType {
    pub fn detect_from_accept_header(accept: Accept) -> Option<Self> {
        let mut sorted_accept = accept;
        sorted_accept.sort_quality_values();

        sorted_accept.0.iter().find_map(|qv| {
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

#[cfg(test)]
mod tests {
    use rama::http::{HeaderValue, headers::HeaderDecode};

    use super::*;

    #[test]
    fn test_detect_from_accept_header() {
        for (header_value, expected_result) in [
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                Some(RequestedContentType::Html),
            ),
            ("text/html", Some(RequestedContentType::Html)),
            (
                "application/xml,text/html,application/xhtml+xml,*/*;q=0.8",
                Some(RequestedContentType::Xml),
            ),
            ("application/xml", Some(RequestedContentType::Xml)),
            (
                "application/xml,text/html,application/xhtml+xml,*/*;q=0.8",
                Some(RequestedContentType::Xml),
            ),
            ("application/xml", Some(RequestedContentType::Xml)),
            (
                "text/html;q=0.8,application/xml",
                Some(RequestedContentType::Xml),
            ),
            (
                "text/html;q=0.8,application/json;q=0.9,application/xml,plain/text",
                Some(RequestedContentType::Xml),
            ),
            (
                "text/html;q=0.8,application/json;q=0.9,plain/text,application/xml",
                Some(RequestedContentType::Txt),
            ),
            (
                "text/html;q=0.8,application/json;q=0.9,plain/text;q=0.2,application/xml",
                Some(RequestedContentType::Xml),
            ),
            ("plain/text", Some(RequestedContentType::Txt)),
            ("plain/text; charset=utf8", Some(RequestedContentType::Txt)),
            (
                "plain/text; charset=utf8; q=0.5",
                Some(RequestedContentType::Txt),
            ),
        ] {
            let accept =
                Accept::decode(&mut [&HeaderValue::from_static(header_value)].into_iter()).unwrap();
            let maybe_ct = RequestedContentType::detect_from_accept_header(accept.clone());
            assert_eq!(
                maybe_ct, expected_result,
                "header value: {header_value}; parsed qvs: {:?}",
                accept.0
            );
        }
    }
}
