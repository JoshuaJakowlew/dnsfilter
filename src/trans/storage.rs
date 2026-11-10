use std::{cell::RefCell, net::SocketAddr, time::Duration};

use thiserror::Error;
use tokio::time::Instant;

use super::map::{Transaction, TransMap};
use crate::{cleanup_timer::{CleanupTimer, elapsed_since}, dns::{packet::PacketId, parser::{hash_query, Query}}};

pub struct TransStorage {
    trans_map: RefCell<TransMap>,
    cleanup_timer: RefCell<CleanupTimer>,
    epoch: Instant,
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
        let epoch = Instant::now();
        Self {
            trans_map: RefCell::new(TransMap::new()),
            cleanup_timer: RefCell::new(CleanupTimer::new(epoch, CLEANUP_INTERVAL)),
            epoch,
        }
    }

    pub fn insert(&self, origin: SocketAddr, packet: &[u8], query: &Query) -> Result<PacketId> {
        let trans = make_transaction(origin, packet, query, self.epoch);
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
        let now = elapsed_since(self.epoch);
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