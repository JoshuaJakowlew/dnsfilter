use std::net::{IpAddr, SocketAddr};
use std::net::Ipv4Addr;
use std::path::Path;

use clap::Parser;
use thiserror::Error;
use tokio::signal::unix::{SignalKind, signal};

use crate::dns::parser::Query;
use crate::filter::loader::{DomainFileLoader, FilterLoader};
use crate::trans::storage::TransStorage;
use crate::{dns::{packet::{Packet}, parser::parse_query, response::write_blocked_response}, filter::qname_set::{QnameSet}, forwarder::Forwarder};

mod dns;
mod cleanup_timer;
mod filter;
mod forwarder;
mod trans;
mod cli;

#[derive(Error, Debug)]
enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Transaction: {0}")]
    Transaction(#[from] trans::storage::Error),
    #[error("Failed to parse packet: {0}")]
    ParseError(#[from] dns::parser::ParseError),
    #[error("Failed to make filter")]
    FilterError(#[from] filter::loader::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn apply_filter(filter: &QnameSet, packet: &mut Packet, len: usize, query: &Query, q_end: usize) -> Result<(usize, bool)> {
    if filter.contains_hierarchical(&query.qname) {
        let resp_size = write_blocked_response(packet, len, q_end);
        return Ok((resp_size, false));
    }
    Ok((0, true))
}

struct ForwardLink<'a> {
    forwarder: &'a Forwarder,
    buf: [u8; 65536],
}

impl<'a> ForwardLink<'a> {
    async fn recv_query(&mut self) -> Result<(usize, SocketAddr)> {
        self.forwarder.recv_local(&mut self.buf)
            .await
            .map_err(Error::Io)
    }

    async fn send_blocked_response(&mut self, len: usize, addr: SocketAddr) -> Result<usize> {
        self.forwarder.send_local(&self.buf[..len], addr)
            .await
            .map_err(Error::Io)
    }

    async fn forward_query(&mut self, len: usize) -> Result<usize> {
        self.forwarder.send_remote(&self.buf[..len])
            .await
            .map_err(Error::Io)
    }
}

async fn send_forward(
    link: &mut ForwardLink<'_>,
    trans_storage: &TransStorage,
    filter: &QnameSet,
) -> Result<usize> {
    let (len, addr) = link.recv_query().await?;

    let (q_end, query) = parse_query(&link.buf[..len])?;

    if let (resp_len, false) = apply_filter(&filter, &mut link.buf, len, &query, q_end)? {      
        link.send_blocked_response(resp_len, addr).await?;
        return Ok(resp_len);
    }

    let trans_id = trans_storage
        .insert(addr, &link.buf[..len], &query)?;

    link.buf[0] = trans_id.0[0];
    link.buf[1] = trans_id.0[1];

    link.forward_query(len).await
}

struct BackwardLink<'a> {
    forwarder: &'a Forwarder,
    buf: [u8; 65536],
}

impl<'a> BackwardLink<'a> {
    async fn recv_remote_response(&mut self) -> Result<usize> {
        self.forwarder.recv_remote(&mut self.buf)
            .await
            .map_err(Error::Io)
    }

    async fn forward_response(&mut self, len: usize, addr: SocketAddr) -> Result<usize> {
        self.forwarder.send_local(&self.buf[..len], addr)
            .await
            .map_err(Error::Io)
    }
}

async fn send_back(
    link: &mut BackwardLink<'_>,
    trans_storage: &TransStorage
) -> Result<usize> {
    let len = link.recv_remote_response().await?;

    let packet = &mut link.buf[..len];
    let (_, query) = parse_query(packet)?;

    let trans = trans_storage.extract(packet, &query)?;

    packet[0] = trans.id.0[0];
    packet[1] = trans.id.0[1];

    link.forward_response(len, trans.addr).await
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = cli::Args::parse();

    let forwarder = Forwarder::bind(args.port).await?;
    forwarder.connect(args.remote_addr).await?;

    let filter = DomainFileLoader::from_file(&args.filter_path)?;
    println!("Loaded {} domains from file", filter.len());

    let mut forward_link = ForwardLink { forwarder: &forwarder, buf: [0; 65536] };
    let mut backward_link = BackwardLink { forwarder: &forwarder, buf: [0; 65536] };
    
    let trans_storage = TransStorage::new();

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            res = send_forward(&mut forward_link, &trans_storage, &filter) => {
                if let Err(e) = res {
                    println!("Error sending forward: {}", e);
                    continue;
                }
            }
            res = send_back(&mut backward_link, &trans_storage) => {
                if let Err(e) = res {
                    println!("Error sending back: {}", e);
                    continue;
                }
            }
            removed = trans_storage.cleanup_expired() => {
                if removed > 0 {
                    println!("Cleaned up: {} expired transactions", removed);
                }
            }
            _ = terminate.recv() => {
                println!("Got terminate signal");
                return Ok(());
            }
            _ = interrupt.recv() => {
                println!("Got interrupt signal");
                return Ok(());
            }
        }
    }
}
