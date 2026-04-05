use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    net::{address::SocketAddress, proxy::ProxyTarget},
    tcp::TcpStream,
};

#[derive(Debug, Clone)]
pub(super) struct ExtractProxyTargetFromTcpStreamLayer;

impl<S> Layer<S> for ExtractProxyTargetFromTcpStreamLayer {
    type Service = ExtractProxyTargetFromTcpStream<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ExtractProxyTargetFromTcpStream { inner }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ExtractProxyTargetFromTcpStream<S> {
    inner: S,
}

impl<S> Service<TcpStream> for ExtractProxyTargetFromTcpStream<S>
where
    S: Service<TcpStream, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut input: TcpStream) -> Result<Self::Output, Self::Error> {
        let proxy_target =
            proxy_target_from_input(&input).context("get proxy target from input stream")?;
        input.extensions.insert(ProxyTarget(proxy_target.into()));
        self.inner.serve(input).await.context("inner serve tcp")
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn proxy_target_from_input(_: &TcpStream) -> Result<SocketAddress, BoxError> {
    Err(BoxError::from(
        "platform does not support proxy_target_from_input (only linux and windows is supported)",
    ))
}

#[cfg(target_os = "windows")]
fn proxy_target_from_input(input: &TcpStream) -> Result<SocketAddress, BoxError> {
    Err(BoxError::from(
        "TODO: implement get proxy addr for windows from driver ctx",
    ))
}

#[cfg(all(not(target_os = "windows"), target_os = "linux"))]
fn proxy_target_from_input(input: &TcpStream) -> Result<SocketAddress, BoxError> {
    use std::io;
    let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let rc =
        unsafe { libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) };

    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    sockaddr_storage_to_socket_addr(&storage, len)
}

#[cfg(all(not(target_os = "windows"), target_os = "linux"))]
fn sockaddr_storage_to_std(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddress> {
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    };

    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            if len < size_of::<libc::sockaddr_in>() as libc::socklen_t {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short sockaddr_in",
                ));
            }

            let addr: libc::sockaddr_in =
                unsafe { *(storage as *const _ as *const libc::sockaddr_in) };

            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);

            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)).into())
        }
        libc::AF_INET6 => {
            if len < size_of::<libc::sockaddr_in6>() as libc::socklen_t {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short sockaddr_in6",
                ));
            }

            let addr: libc::sockaddr_in6 =
                unsafe { *(storage as *const _ as *const libc::sockaddr_in6) };

            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);

            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            ))
            .into())
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported address family: {family}"),
        )),
    }
}
