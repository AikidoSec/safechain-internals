use lol_html::send::Settings;
use rama::http::{
    Body,
    body::{Frame, StreamingBody, util::BodyExt as _},
    header::{HeaderMap, HeaderName, HeaderValue},
};
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};

use super::LolHtmlBody;

#[derive(Debug)]
struct TestBody {
    frames: VecDeque<Result<Frame<rama::bytes::Bytes>, rama::error::BoxError>>,
}

impl TestBody {
    fn new(
        frames: impl IntoIterator<Item = Result<Frame<rama::bytes::Bytes>, rama::error::BoxError>>,
    ) -> Self {
        Self {
            frames: frames.into_iter().collect(),
        }
    }
}

impl StreamingBody for TestBody {
    type Data = rama::bytes::Bytes;
    type Error = rama::error::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front())
    }
}

#[tokio::test]
async fn rewrites_html_across_split_chunks() {
    let body = Body::new(TestBody::new([
        Ok::<_, rama::error::BoxError>(Frame::data(
            "<html><body><a href=\"https://files.pythonhosted.org/packages/source/p/pkg/".into(),
        )),
        Ok(Frame::data(
            "pkg-2.0.0.tar.gz\">new</a></body></html>".into(),
        )),
    ]));

    let settings = Settings {
        element_content_handlers: vec![lol_html::element!("a[href]", |el| {
            el.remove();
            Ok(())
        })],
        ..Settings::new_send()
    };

    let body = Body::new(LolHtmlBody::new(body, settings, || {}));
    let rewritten = body.collect().await.unwrap().to_bytes();
    let rewritten = String::from_utf8(rewritten.to_vec()).unwrap();

    assert_eq!(rewritten, "<html><body></body></html>");
}

#[tokio::test]
async fn preserves_trailer_frames() {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        HeaderName::from_static("x-test-trailer"),
        HeaderValue::from_static("ok"),
    );

    let settings = Settings::new_send();
    let mut body = Body::new(LolHtmlBody::new(
        Body::from("<html></html>").with_trailer_headers(trailers.clone()),
        settings,
        || {},
    ));

    let first = body.frame().await.unwrap().unwrap();
    assert!(first.is_data());

    let second = body.frame().await.unwrap().unwrap();
    assert!(second.is_trailers());
    assert_eq!(second.into_trailers().unwrap(), trailers);

    assert!(body.frame().await.is_none());
}
