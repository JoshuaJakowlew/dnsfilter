use std::{cell::RefCell, net::SocketAddr, time::Duration};

use thiserror::Error;
use tokio::time::Instant;

use crate::{cleanup_timer::{CleanupTimer, elapsed_since}, dns::{packet::PacketId, parser::Query}, packet_hash::hash_query, trans_map::{Transaction, TransMap}};

pub struct TransStorage {
    trans_map: RefCell<TransMap>,
    cleanup_timer: RefCell<CleanupTimer>,
    // epoch: Instant,
}

const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const MAX_TRANS_AGE_MS: u32 = 5_000;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Map is full")]
    MapFull,
    #[error("Not found")]
    NotFound,
}

type Result<T> = std::result::Result<T, Error>;

impl TransStorage {
    pub fn new() -> Self {
        Self {
            trans_map: RefCell::new(TransMap::new()),
            cleanup_timer: RefCell::new(CleanupTimer::new(CLEANUP_INTERVAL)),
        }
    }

    pub fn insert(&self, origin: SocketAddr, packet: &[u8], query: &Query) -> Result<PacketId> {
        let epoch = self.cleanup_timer.borrow().epoch();
        let trans = make_transaction(origin, packet, query, epoch);
        self.trans_map
            .borrow_mut()
            .insert(trans)
            .ok_or(Error::MapFull)
    }
    
    pub fn extract(&self, packet: &[u8], query: &Query) -> Result<Transaction> {
        let id = PacketId::from_packet(packet);
        let hash = hash_query(&query);
        
        self.trans_map
            .borrow_mut()
            .extract(id, hash)
            .ok_or(Error::NotFound)
    }

    pub async fn cleanup_expired(&self) -> usize {
        self.cleanup_timer.borrow_mut().tick().await;

        let epoch = self.cleanup_timer.borrow().epoch();
        let now = elapsed_since(epoch);
        self.trans_map
            .borrow_mut()
            .expire_older_than(now, MAX_TRANS_AGE_MS)
    }
}

fn make_transaction(addr: SocketAddr, packet: &[u8], query: &Query, epoch: Instant) -> Transaction {
    Transaction {
        addr,
        id: PacketId::from_packet(packet),
        hash: hash_query(&query),
        created_at_ms: elapsed_since(epoch),
    }
}