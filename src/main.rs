use std::net::{IpAddr, SocketAddr};
use std::{cell::RefCell, net::SocketAddrV4, net::Ipv4Addr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;
use thiserror::Error;

use trans_map::{Transaction, TransMap};
use dns_packet::PacketId;

use crate::dns_parser::Query;
use crate::trans_manager::TransStorage;
use crate::{cleanup_timer::{CleanupTimer, elapsed_since}, dns_packet::{Packet, QnameBuffer}, dns_parser::{ParseError, parse_query}, dns_response::write_blocked_response, filter::{QnameFilter, QnamePool}, forwarder::Forwarder, packet_hash::hash_query};

mod trans_map;
mod dns_parser;
mod dns_packet;
mod dns_response;
mod packet_hash;
mod cleanup_timer;
mod filter;
mod forwarder;
mod trans_manager;

#[derive(Error, Debug)]
enum Error {
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("Transaction: {0}")]
    Transaction(trans_manager::Error),
    #[error("Failed to parse packet: {0}")]
    ParseError(ParseError),
    #[error("Failed to make filter")]
    FilterError,
}

type Result<T> = std::result::Result<T, Error>;

fn make_filter() -> Result<QnameFilter> {
    let domains = vec![
        "ya.ru",
        "vk.com",
    ];

    let mut pool = QnamePool::new();
    for domain in domains {
        let qname = QnameBuffer::from_domain(domain)
            .ok_or(Error::FilterError)?;
        pool.push(&qname);
    }

    let filter = QnameFilter::from_unique_pool(pool);
    Ok(filter)
}

fn apply_filter(filter: &QnameFilter, packet: &mut Packet, len: usize) -> Result<(usize, bool)> {
    let (pos, query) = parse_query(packet)
        .map_err(Error::ParseError)?;

    if filter.contains(query.qname.as_slice()) {
        let resp_size = write_blocked_response(packet, len, pos);
        return Ok((resp_size, false));
    }

    Ok((0, true))
}

async fn send_forward(
    forwarder: &Forwarder,
    buf: &mut Packet,
    trans_storage: &TransStorage,
    filter: &QnameFilter,
) -> Result<usize> {
    let (len, src) = forwarder.recv_local(buf)
        .await
        .map_err(Error::Io)?;

    let (_, query) = parse_query(&buf[..len])
        .map_err(Error::ParseError)?;

    if let (resp_len, false) = apply_filter(&filter, buf, len)? {
        forwarder.send_local(&buf[..resp_len], src)
            .await
            .map_err(Error::Io)?;
        return Ok(resp_len);
    }

    let fw_trans_id = trans_storage
        .insert(src, &buf[..len], &query)
        .map_err(Error::Transaction)?;

    buf[0] = fw_trans_id.0[0];
    buf[1] = fw_trans_id.0[1];

    forwarder.send_remote(&buf[..len])
        .await
        .map_err(Error::Io)
}

async fn send_back(
    forwarder: &Forwarder,
    buf: &mut Packet,
    trans_storage: &TransStorage
) -> Result<usize> {
    let len = forwarder.recv_remote(buf)
            .await
            .map_err(Error::Io)?;

    let packet = &mut buf[..len];
    let (_, query) = parse_query(packet)
        .map_err(Error::ParseError)?;

    let trans = trans_storage
        .extract(packet, &query)
        .map_err(Error::Transaction)?;

    packet[0] = trans.id.0[0];
    packet[1] = trans.id.0[1];

    forwarder.send_local(packet, trans.addr)
            .await
            .map_err(Error::Io)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let forwarder = Forwarder::bind(5354)
        .await
        .map_err(Error::Io)?;
    
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
    forwarder.connect(remote_addr)
        .await
        .map_err(Error::Io)?;

    let filter = make_filter()?;

    let mut req_buf = [0; 65536];
    let mut resp_buf = [0; 65536];
    
    let trans_storage = TransStorage::new();

    loop {
        tokio::select! {
            res = send_forward(&forwarder, &mut req_buf, &trans_storage, &filter) => {
                if let Err(e) = res {
                    println!("Error sending forward: {}", e);
                    continue;
                }
            }
            res = send_back(&forwarder, &mut resp_buf, &trans_storage) => {
                if let Err(e) = res {
                    println!("Error sending back: {}", e);
                    continue;
                }
            }
            removed = trans_storage.cleanup_expired() => {
                println!("Cleaned up: {} expired transactions", removed);
            }
        }
    }
}
