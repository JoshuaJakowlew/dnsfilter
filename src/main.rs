use std::net::{IpAddr, SocketAddr};
use std::{cell::RefCell, net::SocketAddrV4, net::Ipv4Addr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;
use thiserror::Error;

use trans_map::{Transaction, TransactionMap};
use dns_packet::PacketId;

use crate::{cleanup_timer::{CleanupTimer, elapsed_since}, dns_packet::{Packet, QnameBuffer}, dns_parser::{ParseError, parse_questions, parse_questions_with_pos}, dns_response::write_blocked_response, filter::{QnameFilter, QnamePool}, forwarder::Forwarder, packet_hash::hash_questions};

mod trans_map;
mod dns_parser;
mod dns_packet;
mod dns_response;
mod packet_hash;
mod cleanup_timer;
mod filter;
mod forwarder;

#[derive(Error, Debug)]
enum Error {
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("Transaction map is full: {0:?}")]
    TransactionMapFull(PacketId),
    #[error("Origin not found: {0:?}")]
    TransactionNotFound(PacketId),
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
    let (pos, questions) = parse_questions_with_pos(packet)
        .map_err(Error::ParseError)?;
    for question in questions {
        if filter.contains(question.qname.as_slice()) {
            let resp_size = write_blocked_response(packet, len, pos);
            return Ok((resp_size, false));
        }
    }
    Ok((0, true))
}

async fn send_forward(
    forwarder: &Forwarder,
    buf: &mut Packet,
    trans_map: &RefCell<TransactionMap>,
    epoch: Instant,
    filter: &QnameFilter,
) -> Result<usize> {
    let (len, src) = forwarder.recv_local(buf)
        .await
        .map_err(Error::Io)?;

    let questions = parse_questions(&buf[..len])
        .map_err(Error::ParseError)?;

    if let (resp_len, false) = apply_filter(&filter, buf, len)? {
        forwarder.send_local(&buf[..resp_len])
            .await
            .map_err(Error::Io)?;
        return Ok(resp_len);
    }

    let trans = Transaction {
        addr: src,
        id: PacketId::from_packet(&buf[..len]),
        hash: hash_questions(&questions),
        created_at_ms: elapsed_since(epoch),
    };

    let fw_trans_id = trans_map
        .borrow_mut()
        .insert(trans)
        .ok_or(Error::TransactionMapFull(trans.id))?;

    buf[0] = fw_trans_id.0[0];
    buf[1] = fw_trans_id.0[1];

    forwarder.send_remote(&buf[..len])
        .await
        .map_err(Error::Io)
}

async fn send_back(forwarder: &Forwarder, buf: &mut Packet, trans_map: &RefCell<TransactionMap>) -> Result<usize> {
    let len = forwarder.recv_remote(buf)
            .await
            .map_err(Error::Io)?;

    let packet = &mut buf[..len];
    let trans_id = PacketId::from_packet(packet);
    let questions = parse_questions(packet)
        .map_err(Error::ParseError)?;
    let hash = hash_questions(&questions);

    let trans = trans_map
        .borrow_mut()
        .extract(trans_id, hash)
        .ok_or(Error::TransactionNotFound(trans_id))?;

    packet[0] = trans.id.0[0];
    packet[1] = trans.id.0[1];

    forwarder.send_local(packet)
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
    
    let trans_map = RefCell::new(TransactionMap::new());
    let mut cleanup_timer = CleanupTimer::new(Duration::from_secs(1));
    let epoch = cleanup_timer.epoch();

    loop {
        tokio::select! {
            res = send_forward(&forwarder, &mut req_buf, &trans_map, epoch, &filter) => {
                if let Err(e) = res {
                    println!("Error sending forward: {:?}", e);
                    continue;
                }
            }
            res = send_back(&forwarder, &mut resp_buf, &trans_map) => {
                if let Err(e) = res {
                    println!("Error sending back: {:?}", e);
                    continue;
                }
            }
            _ = cleanup_timer.tick() => {
                const MAX_AGE_MS: u32 = 5_000;
                let removed = trans_map.borrow_mut().expire_older_than(elapsed_since(epoch), MAX_AGE_MS);
                println!("Cleaned up: {} stale transactions", removed);
            }
        }
    }
}
