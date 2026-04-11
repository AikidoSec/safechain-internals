use std::{
    cmp, io, mem,
    os::windows::io::{AsRawSocket, RawSocket},
    ptr,
    sync::Arc,
};

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
    io::Io,
    net::{client::ConnectorService, socket::SocketOptions, transport::TryRefIntoTransportContext},
    rt::Executor,
    tcp::{
        TcpStream,
        client::{TcpStreamConnector, service::TcpConnector},
    },
    telemetry::tracing,
};

use windows_sys::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER,
    Networking::WinSock::{
        SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, SOCKET,
        SOCKET_ERROR, WSAEFAULT, WSAEINVAL, WSAENOPROTOOPT, WSAEOPNOTSUPP, WSAGetLastError,
        WSAIoctl,
    },
};

#[derive(Debug, Clone)]
pub struct WfpRedirectRecords(Vec<u8>);

impl WfpRedirectRecords {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for WfpRedirectRecords {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct WfpRedirectRecordsLayer;

impl WfpRedirectRecordsLayer {
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for WfpRedirectRecordsLayer {
    type Service = WfpRedirectRecordsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WfpRedirectRecordsService { inner }
    }
}

#[derive(Debug, Clone)]
pub struct WfpRedirectRecordsService<S> {
    inner: S,
}

impl<S, Input> Service<Input> for WfpRedirectRecordsService<S>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: AsRawSocket + ExtensionsMut + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        let inbound_socket = input.as_raw_socket();
        if let Some(records) = query_wfp_redirect_records(inbound_socket)
            .context("query WFP redirect records from input stream")?
        {
            tracing::info!(
                inbound_socket,
                redirect_records_len = records.as_bytes().len(),
                "accepted inbound socket with WFP redirect records"
            );
            input.extensions_mut().insert(records);
        } else {
            tracing::info!(
                inbound_socket,
                "accepted inbound socket without WFP redirect records"
            );
        }

        self.inner
            .serve(input)
            .await
            .context("inner service failed")
    }
}

/// Windows-specific proxy connector service.
///
/// It keeps Rama's default `TcpConnector` routing logic intact and only swaps
/// in a custom inner `TcpStreamConnector` that reapplies WFP redirect records
/// onto the outbound socket before connect.
pub fn new_tcp_connector_service_for_proxy<Input>(
    exec: Executor,
    socket_options: Arc<SocketOptions>,
) -> impl ConnectorService<Input, Connection: Io + Unpin> + Clone
where
    Input:
        ExtensionsMut + TryRefIntoTransportContext<Error: Send + Sync + 'static> + Send + 'static,
    BoxError: From<Input::Error>,
{
    WindowsProxyTcpConnectorService {
        exec,
        socket_options,
    }
}

#[derive(Debug, Clone)]
struct WindowsProxyTcpConnectorService {
    exec: Executor,
    socket_options: Arc<SocketOptions>,
}

impl<Input> Service<Input> for WindowsProxyTcpConnectorService
where
    Input:
        ExtensionsMut + TryRefIntoTransportContext<Error: Send + Sync + 'static> + Send + 'static,
    BoxError: From<Input::Error>,
{
    type Output = rama::net::client::EstablishedClientConnection<TcpStream, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let redirect_records = input.extensions().get::<WfpRedirectRecords>().cloned();
        let connector = WindowsWfpProxySocketConnector {
            socket_options: self.socket_options.clone(),
            redirect_records,
        };

        TcpConnector::new(self.exec.clone())
            .with_connector(connector)
            .serve(input)
            .await
    }
}

#[derive(Debug, Clone)]
struct WindowsWfpProxySocketConnector {
    socket_options: Arc<SocketOptions>,
    redirect_records: Option<WfpRedirectRecords>,
}

impl TcpStreamConnector for WindowsWfpProxySocketConnector {
    type Error = BoxError;

    async fn connect(&self, addr: std::net::SocketAddr) -> Result<TcpStream, Self::Error> {
        let socket_options = self.socket_options.clone();
        let redirect_records = self.redirect_records.clone();

        tokio::task::spawn_blocking(move || {
            tcp_connect_with_socket_opts_and_redirect_records(
                &socket_options,
                addr,
                redirect_records.as_ref(),
            )
        })
        .await
        .context("wait for blocking tcp connect with WFP redirect records")?
    }
}

fn tcp_connect_with_socket_opts_and_redirect_records(
    socket_options: &SocketOptions,
    addr: std::net::SocketAddr,
    redirect_records: Option<&WfpRedirectRecords>,
) -> Result<TcpStream, BoxError> {
    let socket = socket_options
        .try_build_socket(addr.into())
        .context("build outbound TCP socket")?;
    let outbound_socket = socket.as_raw_socket();

    if let Some(redirect_records) = redirect_records {
        tracing::debug!(
            outbound_socket,
            target = %addr,
            redirect_records_len = redirect_records.as_bytes().len(),
            "apply WFP redirect records to outbound proxy socket"
        );
        set_wfp_redirect_records(socket.as_raw_socket(), redirect_records)
            .context("apply WFP redirect records to outbound proxy socket")?;
    } else {
        tracing::debug!(
            outbound_socket,
            target = %addr,
            "connect outbound proxy socket without WFP redirect records"
        );
    }

    socket
        .connect(&addr.into())
        .context("connect outbound proxy socket")?;
    socket
        .set_nonblocking(true)
        .context("set outbound proxy socket non-blocking")?;

    let stream = tokio::net::TcpStream::from_std(std::net::TcpStream::from(socket))
        .context("convert outbound socket into tokio tcp stream")?;

    Ok(stream.into())
}

fn query_wfp_redirect_records(socket: RawSocket) -> io::Result<Option<WfpRedirectRecords>> {
    let socket = socket as SOCKET;
    let mut needed = 0u32;

    let rc = unsafe {
        WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            0,
            &mut needed,
            ptr::null_mut(),
            None,
        )
    };

    if rc == 0 && needed == 0 {
        tracing::debug!(
            socket,
            "WFP redirect record query returned success with empty payload"
        );
        return Ok(None);
    }

    let err = unsafe { WSAGetLastError() };

    if is_no_wfp_redirect_records_error(err) {
        tracing::debug!(
            socket,
            wsa_error = err,
            "WFP redirect records are not available on socket"
        );
        return Ok(None);
    }

    if err != ERROR_INSUFFICIENT_BUFFER as i32 && needed == 0 {
        tracing::debug!(
            socket,
            wsa_error = err,
            "WFP redirect record query failed before buffer allocation"
        );
        return Err(io::Error::from_raw_os_error(err));
    }

    let mut storage = aligned_blob_buffer(needed as usize);
    let mut returned = 0u32;

    let rc = unsafe {
        let out = aligned_blob_as_mut_bytes(&mut storage);
        WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
            ptr::null_mut(),
            0,
            out.as_mut_ptr().cast(),
            out.len() as u32,
            &mut returned,
            ptr::null_mut(),
            None,
        )
    };

    if rc == 0 {
        let out = aligned_blob_as_mut_bytes(&mut storage);
        let blob = out[..returned as usize].to_vec();
        tracing::debug!(
            socket,
            redirect_records_len = returned,
            "WFP redirect record query returned redirect metadata"
        );
        return Ok(Some(blob.into()));
    }

    let err = unsafe { WSAGetLastError() };

    if is_no_wfp_redirect_records_error(err) {
        tracing::debug!(
            socket = socket as usize,
            wsa_error = err,
            "WFP redirect records disappeared before second query"
        );
        return Ok(None);
    }

    tracing::debug!(
        socket,
        wsa_error = err,
        "WFP redirect record query failed after buffer allocation"
    );
    Err(io::Error::from_raw_os_error(err))
}

fn set_wfp_redirect_records(
    socket: RawSocket,
    redirect_records: &WfpRedirectRecords,
) -> io::Result<()> {
    let bytes = redirect_records.as_bytes();
    if bytes.is_empty() {
        return Ok(());
    }

    let socket = socket as SOCKET;

    let rc = unsafe {
        WSAIoctl(
            socket,
            SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
            bytes.as_ptr() as *mut _,
            bytes.len() as u32,
            ptr::null_mut(),
            0,
            ptr::null_mut(), // or a dummy u32 if your binding insists
            ptr::null_mut(),
            None,
        )
    };

    if rc == 0 {
        Ok(())
    } else {
        Err(last_wsa_error())
    }
}

fn last_wsa_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

fn is_no_wfp_redirect_records_error(err_code: i32) -> bool {
    matches!(
        err_code,
        WSAEFAULT | WSAEINVAL | WSAENOPROTOOPT | WSAEOPNOTSUPP | SOCKET_ERROR
    )
}

fn aligned_blob_buffer(byte_len: usize) -> Vec<usize> {
    let word = mem::size_of::<usize>();
    let words = cmp::max(1, byte_len.div_ceil(word));
    vec![0usize; words]
}

fn aligned_blob_as_mut_bytes(buf: &mut Vec<usize>) -> &mut [u8] {
    let byte_len = buf.len() * mem::size_of::<usize>();
    unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), byte_len) }
}
