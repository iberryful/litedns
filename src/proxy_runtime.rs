use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::net::{TcpStream, UdpSocket};
use tokio_socks::tcp::Socks5Stream;
use trust_dns_resolver::name_server::{GenericConnector, RuntimeProvider};
use trust_dns_resolver::proto::iocompat::AsyncIoTokioAsStd;
use trust_dns_resolver::proto::TokioTime;
use trust_dns_resolver::TokioHandle;
use crate::configuration::{ProxyConfig};

#[derive(Clone)]
pub struct TokioRuntimeProxyProvider {
    handle: TokioHandle,
    proxy: Option<ProxyConfig>,
}

pub type ProxyConnector = GenericConnector<TokioRuntimeProxyProvider>;

impl RuntimeProvider for TokioRuntimeProxyProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        let proxy = self.proxy.clone();
        Box::pin(async move {
            let conn = if let Some(proxy) = proxy {
                connect_tcp_with_proxy(proxy, server_addr).await?
            } else {
                connect_tcp_without_proxy(server_addr).await?
            };
            Ok(AsyncIoTokioAsStd(conn))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        Box::pin(UdpSocket::bind(local_addr))
    }
}

impl TokioRuntimeProxyProvider {
    pub fn new(proxy: Option<ProxyConfig>) -> Self {
        Self {
            handle: TokioHandle::default(),
            proxy,
        }
    }
}

async fn connect_tcp_without_proxy(server_addr: SocketAddr) -> std::io::Result<TcpStream> {
    TcpStream::connect(server_addr).await
}

async fn connect_tcp_with_proxy(
    proxy: ProxyConfig,
    server_addr: SocketAddr,
) -> std::io::Result<TcpStream> {
    let socket = TcpStream::connect(proxy.addr).await?;
    socket.set_nodelay(true)?;
    let conn = if let Some(username) = proxy.username {
        Socks5Stream::connect_with_password_and_socket(
            socket,
            server_addr,
            username.as_str(),
            proxy.password.unwrap_or("".to_string()).as_str(),
        )
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
    } else {
        Socks5Stream::connect_with_socket(socket, server_addr)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
    };

    Ok(conn.into_inner())
}
