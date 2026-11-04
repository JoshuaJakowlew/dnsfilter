use std::{cell::RefCell};

use tokio::net::UdpSocket;
use thiserror::Error;

use trans_map::{DnsTransId, Origin, OriginMap};

mod trans_map;

#[derive(Error, Debug)]
enum Error {
    #[error("Failed to bind to address: {0}")]
    BindError(std::io::Error),
    #[error("Failed to connect to address: {0}")]
    ConnectError(std::io::Error),
    #[error("Failed to send data: {0}")]
    SendError(std::io::Error),
    #[error("Failed to receive data: {0}")]
    ReceiveError(std::io::Error),
    #[error("Origin map is full: {0:?}")]
    OriginMapFull(DnsTransId),
    #[error("Origin not found: {0:?}")]
    OriginNotFound(DnsTransId),
}

type Result<T> = std::result::Result<T, Error>;

async fn make_sockets() -> Result<(UdpSocket, UdpSocket)> {
    let listener = UdpSocket::bind("0.0.0.0:5354")
        .await
        .map_err(Error::BindError)?;

    let forwarder = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(Error::BindError)?;

    forwarder.connect("172.29.172.254:53")
        .await
        .map_err(Error::ConnectError)?;

    Ok((listener, forwarder))
}

async fn send_forward(listener: &UdpSocket, forwarder: &UdpSocket, buf: &mut [u8], origins: &RefCell<OriginMap>) -> Result<usize> {
    let (len, src) = listener.recv_from(buf)
        .await
        .map_err(Error::ReceiveError)?;

    let packet = &mut buf[..len];

    let origin = Origin {
        addr: src,
        trans_id: DnsTransId::from_packet(packet),
    };

    let fw_trans_id = origins
        .borrow_mut()
        .insert(origin)
        .ok_or(Error::OriginMapFull(origin.trans_id))?;

    packet[0] = fw_trans_id.0[0];
    packet[1] = fw_trans_id.0[1];

    forwarder.send(packet)
        .await
        .map_err(Error::SendError)
}

async fn send_back(listener: &UdpSocket, forwarder: &UdpSocket, buf: &mut [u8], origins: &RefCell<OriginMap>) -> Result<usize> {
    let len = forwarder.recv(buf)
            .await
            .map_err(Error::ReceiveError)?;
    
    let packet = &mut buf[..len];

    let trans_id = DnsTransId::from_packet(packet);
    let origin = origins
        .borrow_mut()
        .extract(trans_id)
        .ok_or(Error::OriginNotFound(trans_id))?;

    packet[0] = origin.trans_id.0[0];
    packet[1] = origin.trans_id.0[1];

    listener.send_to(packet, origin.addr)
            .await
            .map_err(Error::SendError)
}

#[tokio::main]
async fn main() -> Result<()> {
    let (listener, forwarder) = make_sockets().await?;
    
    let mut req_buf = [0; 4096];
    let mut resp_buf = [0; 4096];
    
    let origins = RefCell::new(OriginMap::new());

    loop {
        tokio::select! {
            res = send_forward(&listener, &forwarder, &mut req_buf, &origins) => {
                if let Err(e) = res {
                    println!("Error sending forward: {:?}", e);
                    continue;
                }
                // println!("Sent forward");
            }
            res = send_back(&listener, &forwarder, &mut resp_buf, &origins) => {
                if let Err(e) = res {
                    println!("Error sending back: {:?}", e);
                    continue;
                }
                // println!("Sent back");
            }
        }
    }
}
