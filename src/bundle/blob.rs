use std::{io::Read, mem::size_of};

use crate::filter::qname_set::QnamePool;

pub struct Bundle<'a> {
    payload: &'a [u8],
    payload_size: [u8; size_of::<usize>()],
    name_count: [u8; size_of::<usize>()],
}

impl<'a> Bundle<'a> {
    pub fn encode(pool: &'a QnamePool) -> Self {
        let payload = pool.as_bytes();
        let payload_size = payload.len().to_le_bytes();
        let name_count = pool.len().to_le_bytes();
        Self { payload, payload_size, name_count }
    }

    pub fn reader(&self) -> impl Read + '_ {
        self.payload.chain(&self.name_count[..]).chain(&self.payload_size[..])
    }
}