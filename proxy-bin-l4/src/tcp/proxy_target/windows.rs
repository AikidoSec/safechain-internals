use std::{
    fmt, io,
    os::windows::io::{AsRawSocket, RawSocket},
    ptr,
};

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
    net::proxy::ProxyTarget,
    telemetry::tracing,
};
use windows_sys::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER,
    Networking::WinSock::{
        SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SOCKET, SOCKET_ERROR, WSAEFAULT,
        WSAGetLastError, WSAIoctl,
    },
};

pub use safechain_proxy_lib::nostd::windows::redirect_ctx::ProxyRedirectContext as L4ProxyRedirectContext;

pub type ProxyTargetFromInput<S> = ProxyTargetFromWfpContext<S, L4ProxyRedirectContextDecoder>;
pub type ProxyTargetFromInputLayer = ProxyTargetFromWfpContextLayer<L4ProxyRedirectContextDecoder>;

// NOTE:
// This is intentionally forked from Rama's Windows WFP context layer.
// We want to preserve rich context (including source process path), while also
// handling larger context payloads gracefully.
const WFP_CONTEXT_BUFFER_STACK_LEN: usize = 1024;
const WFP_CONTEXT_BUFFER_INITIAL_HEAP_LEN: usize = 4096;
const WFP_CONTEXT_BUFFER_MAX_LEN: usize = 64 * 1024;

#[inline(always)]
pub fn new_proxy_target_from_input_layer() -> ProxyTargetFromInputLayer {
    ProxyTargetFromInputLayer::new(L4ProxyRedirectContextDecoder)
}

pub trait WfpContextDecoder: Send + Sync + 'static {
    type Context: fmt::Debug + Clone + Send + Sync + 'static;
    type Error: Into<BoxError>;

    fn decode(&self, bytes: &[u8]) -> Result<(Self::Context, ProxyTarget), Self::Error>;
}

#[derive(Debug, Clone)]
pub struct ProxyTargetFromWfpContextLayer<D> {
    decoder: D,
    context_optional: bool,
}

impl<D> ProxyTargetFromWfpContextLayer<D> {
    pub fn new(decoder: D) -> Self {
        Self {
            decoder,
            context_optional: false,
        }
    }

    #[allow(dead_code)]
    pub fn optional(mut self, optional: bool) -> Self {
        self.context_optional = optional;
        self
    }
}

impl<S, D> Layer<S> for ProxyTargetFromWfpContextLayer<D>
where
    D: Clone,
{
    type Service = ProxyTargetFromWfpContext<S, D>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyTargetFromWfpContext {
            inner,
            decoder: self.decoder.clone(),
            context_optional: self.context_optional,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyTargetFromWfpContext<S, D> {
    inner: S,
    decoder: D,
    context_optional: bool,
}

impl<S, Input, D> Service<Input> for ProxyTargetFromWfpContext<S, D>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: AsRawSocket + ExtensionsMut + Send + 'static,
    D: WfpContextDecoder,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        let context_bytes = match query_wfp_redirect_context(input.as_raw_socket())
            .context("query WFP context from input stream")?
        {
            Some(context_bytes) => context_bytes,
            None if self.context_optional => {
                return self
                    .inner
                    .serve(input)
                    .await
                    .context("inner service failed");
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "missing WFP redirect context",
                )
                .into());
            }
        };

        let (context, proxy_target) = self
            .decoder
            .decode(&context_bytes)
            .context("decode WFP context")?;

        input.extensions_mut().insert(context);
        input.extensions_mut().insert(proxy_target);

        self.inner
            .serve(input)
            .await
            .context("inner service failed")
    }
}

fn query_wfp_redirect_context(socket: RawSocket) -> io::Result<Option<Vec<u8>>> {
    let socket = socket as SOCKET;
    let mut stack_buffer = [0u8; WFP_CONTEXT_BUFFER_STACK_LEN];
    let mut bytes_returned = 0u32;

    let rc = query_wfp_context_into(socket, &mut stack_buffer, &mut bytes_returned);

    if rc == 0 {
        let used = (bytes_returned as usize).min(stack_buffer.len());
        return Ok(Some(stack_buffer[..used].to_vec()));
    }

    let err_code = unsafe {
        // SAFETY: thread-local winsock error retrieval.
        WSAGetLastError()
    };

    if err_code == ERROR_INSUFFICIENT_BUFFER as i32 || err_code == WSAEFAULT {
        let mut needed = bytes_returned as usize;
        if needed == 0 {
            needed = WFP_CONTEXT_BUFFER_INITIAL_HEAP_LEN;
        }
        needed = needed.clamp(
            WFP_CONTEXT_BUFFER_INITIAL_HEAP_LEN,
            WFP_CONTEXT_BUFFER_MAX_LEN,
        );

        let mut heap_buffer = vec![0u8; needed];

        // Retry up to two times in case kernel reports a larger required size again.
        for _ in 0..2 {
            let mut final_bytes = 0u32;
            let second_rc = query_wfp_context_into(socket, &mut heap_buffer, &mut final_bytes);
            if second_rc == 0 {
                heap_buffer.truncate(final_bytes as usize);
                return Ok(Some(heap_buffer));
            }

            let second_err = last_wsa_error_code();
            if is_no_wfp_redirect_context_error(second_err) {
                return Ok(None);
            }

            if (second_err == ERROR_INSUFFICIENT_BUFFER as i32 || second_err == WSAEFAULT)
                && (final_bytes as usize) > heap_buffer.len()
                && (final_bytes as usize) <= WFP_CONTEXT_BUFFER_MAX_LEN
            {
                heap_buffer.resize(final_bytes as usize, 0u8);
                continue;
            }

            return Err(io::Error::from_raw_os_error(second_err));
        }

        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WFP context size kept growing beyond retry budget",
        ));
    }

    if is_no_wfp_redirect_context_error(err_code) {
        return Ok(None);
    }

    Err(io::Error::from_raw_os_error(err_code))
}

fn last_wsa_error_code() -> i32 {
    unsafe {
        // SAFETY: thread-local winsock error retrieval.
        WSAGetLastError()
    }
}

fn query_wfp_context_into(socket: SOCKET, out: &mut [u8], bytes_returned: &mut u32) -> i32 {
    unsafe {
        // SAFETY: synchronous WSAIoctl with valid output buffer and size.
        WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            ptr::null(),
            0,
            out.as_mut_ptr().cast(),
            out.len() as u32,
            bytes_returned,
            ptr::null_mut(),
            None,
        )
    }
}

fn is_no_wfp_redirect_context_error(err_code: i32) -> bool {
    err_code == SOCKET_ERROR
}

#[derive(Debug, Clone)]
pub struct L4ProxyRedirectContextDecoder;

impl WfpContextDecoder for L4ProxyRedirectContextDecoder {
    type Context = L4ProxyRedirectContext;
    type Error = BoxError;

    fn decode(&self, bytes: &[u8]) -> Result<(Self::Context, ProxyTarget), Self::Error> {
        let ctx: L4ProxyRedirectContext = postcard::from_bytes(bytes)
            .context("decode WFP context into L4 Safechain redirect proxy context")?;

        tracing::debug!(
            target = %ctx.destination(),
            source_pid = ctx.source_pid(),
            source_app_path = ctx.source_process_path(),
            "windows context decoder fetched redirect info for proxying",
        );

        let proxy_target = ProxyTarget(ctx.destination().into());
        Ok((ctx, proxy_target))
    }
}
