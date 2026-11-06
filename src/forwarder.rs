use std::{io::Error, net::{Ipv4Addr, SocketAddr, SocketAddrV4}};
use tokio::net::{UdpSocket};

pub struct Forwarder {
    local: UdpSocket,
    remote: UdpSocket,
}

type Result<T> = std::result::Result<T, Error>;

impl Forwarder {
    pub async fn bind(local_port: u16) -> Result<Self> {
        let local = local_socket(local_port).await?;
        let remote = local_socket(0).await?;
        Ok(Self { local, remote })
    }

    pub async fn connect(&self, remote_addr: SocketAddr) -> Result<()> {
        self.remote.connect(remote_addr).await
    }

    pub async fn recv_local(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.local.recv_from(buf).await
    }

    pub async fn send_local(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        self.local.send_to(buf, addr).await
    }

    pub async fn recv_remote(&self, buf: &mut [u8]) -> Result<usize> {
        self.remote.recv(buf).await
    }

    pub async fn send_remote(&self, buf: &[u8]) -> Result<usize> {
        self.remote.send(buf).await
    }
}

async fn local_socket(port: u16) -> Result<UdpSocket> {
    UdpSocket::bind(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)
    ).await
}