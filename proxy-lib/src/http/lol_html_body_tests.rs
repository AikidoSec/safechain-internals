use lol_html::send::Settings;
use rama::http::{
    Body,
    body::util::BodyExt as _,
    header::{HeaderMap, HeaderName, HeaderValue},
};

use super::LolHtmlBody;

fn body_with_trailers(html: &str, chunk_size: Option<usize>, trailers: HeaderMap) -> Body {
    let chunks: Vec<Result<rama::bytes::Bytes, rama::error::BoxError>> = match chunk_size {
        None => {
            if html.is_empty() {
                vec![]
            } else {
                vec![Ok(rama::bytes::Bytes::copy_from_slice(html.as_bytes()))]
            }
        }
        Some(size) => html
            .as_bytes()
            .chunks(size)
            .map(|c| Ok(rama::bytes::Bytes::copy_from_slice(c)))
            .collect(),
    };

    Body::from_stream(rama::futures::stream::iter(chunks)).with_trailer_headers(trailers)
}

fn removing_anchor_settings() -> Settings<'static, 'static> {
    Settings {
        element_content_handlers: vec![lol_html::element!("a[href]", |el| {
            el.remove();
            Ok(())
        })],
        ..Settings::new_send()
    }
}

#[tokio::test]
async fn preserves_trailers_for_body_sizes_and_match_positions() {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        HeaderName::from_static("x-test-trailer"),
        HeaderValue::from_static("ok"),
    );

    let long_prefix = "x".repeat(128);
    let long_middle = "y".repeat(128);
    let long_suffix = "z".repeat(128);

    let cases = [
        ("no body no rule", "", None, false, ""),
        (
            "short body no rule",
            "<html><body>plain</body></html>",
            None,
            false,
            "<html><body>plain</body></html>",
        ),
        (
            "short body rule match at front",
            "<a href=\"front\">front</a><p>tail</p>",
            None,
            true,
            "<p>tail</p>",
        ),
        (
            "short body rule match in middle",
            "<p>head</p><a href=\"mid\">middle</a><p>tail</p>",
            None,
            true,
            "<p>head</p><p>tail</p>",
        ),
        (
            "short body rule match at end",
            "<p>head</p><a href=\"end\">end</a>",
            None,
            true,
            "<p>head</p>",
        ),
        (
            "short body rule match in multiple places",
            "<a href=\"one\">1</a><p>keep</p><a href=\"two\">2</a>",
            None,
            true,
            "<p>keep</p>",
        ),
        (
            "long body no rule",
            &format!("<html><body>{long_prefix}<p>keep</p>{long_suffix}</body></html>"),
            Some(31),
            false,
            &format!("<html><body>{long_prefix}<p>keep</p>{long_suffix}</body></html>"),
        ),
        (
            "long body rule match at front",
            &format!(
                "<html><body><a href=\"front\">front</a>{long_prefix}<p>tail</p></body></html>"
            ),
            Some(29),
            true,
            &format!("<html><body>{long_prefix}<p>tail</p></body></html>"),
        ),
        (
            "long body rule match in middle",
            &format!(
                "<html><body>{long_prefix}<a href=\"mid\">middle</a>{long_middle}</body></html>"
            ),
            Some(23),
            true,
            &format!("<html><body>{long_prefix}{long_middle}</body></html>"),
        ),
        (
            "long body rule match at end",
            &format!("<html><body>{long_prefix}<a href=\"end\">end</a></body></html>"),
            Some(19),
            true,
            &format!("<html><body>{long_prefix}</body></html>"),
        ),
        (
            "long body rule match in multiple places",
            &format!(
                "<html><body><a href=\"one\">1</a>{long_prefix}<a href=\"two\">2</a>{long_middle}<a href=\"three\">3</a>{long_suffix}</body></html>"
            ),
            Some(17),
            true,
            &format!("<html><body>{long_prefix}{long_middle}{long_suffix}</body></html>"),
        ),
    ];

    for (name, input, chunk_size, apply_rule, expected) in cases {
        let settings = if apply_rule {
            removing_anchor_settings()
        } else {
            Settings::new_send()
        };

        let body = body_with_trailers(input, chunk_size, trailers.clone());
        let collected = Body::new(LolHtmlBody::new(body, settings, || {}))
            .collect()
            .await
            .unwrap();

        let collected_trailers = collected.trailers().cloned();
        let rewritten = String::from_utf8(collected.to_bytes().to_vec()).unwrap();

        assert_eq!(rewritten, expected, "{name}");
        assert_eq!(collected_trailers, Some(trailers.clone()), "{name}");
    }
}
