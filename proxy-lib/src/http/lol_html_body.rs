use std::{
    collections::VecDeque,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use lol_html::send::{HtmlRewriter, Settings};
use parking_lot::Mutex;
use rama::{
    bytes::Bytes,
    error::BoxError,
    http::{
        Body,
        body::{Frame, SizeHint, StreamingBody},
    },
};
use sync_wrapper::SyncWrapper;

type Sink = Box<dyn FnMut(&[u8]) + Send>;
type PendingFrames = Arc<Mutex<VecDeque<Frame<Bytes>>>>;

/// A Rama Body wrapper that feeds each incoming chunk through an HTML rewriter.
pub(crate) struct LolHtmlBody {
    inner: Body,
    rewriter: SyncWrapper<Option<HtmlRewriter<'static, Sink>>>,
    pending_frames: PendingFrames,
    done: bool,
    on_end: SyncWrapper<Option<Box<dyn FnOnce() + Send + 'static>>>,
}

impl LolHtmlBody {
    pub(crate) fn new<F>(inner: Body, settings: Settings<'static, 'static>, on_end: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        let pending_frames: PendingFrames = Arc::new(Mutex::new(VecDeque::new()));
        let output_sink = Arc::clone(&pending_frames);
        let sink: Sink = Box::new(move |chunk: &[u8]| {
            if chunk.is_empty() {
                return;
            }
            output_sink
                .lock()
                .push_back(Frame::data(Bytes::copy_from_slice(chunk)));
        });
        Self {
            inner,
            rewriter: SyncWrapper::new(Some(HtmlRewriter::new(settings, sink))),
            pending_frames,
            done: false,
            on_end: SyncWrapper::new(Some(Box::new(on_end))),
        }
    }
}

impl StreamingBody for LolHtmlBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        loop {
            if let Some(frame) = this.pending_frames.lock().pop_front() {
                return Poll::Ready(Some(Ok(frame)));
            }

            if this.done {
                return Poll::Ready(None);
            }

            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,

                Poll::Ready(None) => {
                    // The inner body reached EOF, so finalize the rewriter and
                    // fire the completion callback once.
                    let maybe_rewriter = this.rewriter.get_mut();
                    if let Some(rewriter) = maybe_rewriter.take()
                        && let Err(e) = rewriter.end()
                    {
                        return Poll::Ready(Some(Err(e.into())));
                    }
                    if let Some(callback) = this.on_end.get_mut().take() {
                        callback();
                    }
                    this.done = true;
                }

                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),

                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        let Some(rewriter) = this.rewriter.get_mut().as_mut() else {
                            continue;
                        };
                        if let Err(e) = rewriter.write(&data) {
                            return Poll::Ready(Some(Err(e.into())));
                        }
                    }
                    Err(frame) => {
                        this.pending_frames.lock().push_back(frame);
                    }
                },
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done && self.pending_frames.lock().is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        // We may remove elements, so the output size cannot be known upfront.
        SizeHint::default()
    }
}

#[cfg(test)]
#[path = "lol_html_body_tests.rs"]
mod tests;
