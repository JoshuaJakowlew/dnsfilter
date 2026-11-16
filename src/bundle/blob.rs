use std::{io::Read, mem::size_of};

use memmap2::Mmap;

use crate::bundle::{Error, Result};
use crate::filter::{pool_buffer::PoolBuffer, qname_set::QnamePool};

const MAGIC: [u8; 8] = *b"DNSFBNDL";
const USIZE: usize = size_of::<usize>();
const TRAILER_SIZE: usize = 2 * USIZE + MAGIC.len();

/// Layout at the end of file:
/// payload <> name_count <> payload_size <> MAGIC
pub struct Bundle<'a> {
    payload: &'a [u8],
    payload_size: [u8; USIZE],
    name_count: [u8; USIZE],
}

impl<'a> Bundle<'a> {
    pub fn new(pool: &'a QnamePool) -> Self {
        let payload = pool.as_bytes();
        let payload_size = payload.len().to_le_bytes();
        let name_count = pool.len().to_le_bytes();
        Self { payload, payload_size, name_count }
    }

    pub fn reader(&self) -> impl Read + '_ {
        self.payload
            .chain(&self.name_count[..])
            .chain(&self.payload_size[..])
            .chain(&MAGIC[..])
    }
}

/// Pool borrows payload directly from the mapping without copying
pub fn decode(map: Mmap) -> Result<QnamePool> {
    let trailer_start = map
        .len()
        .checked_sub(TRAILER_SIZE)
        .ok_or(Error::NotFound)?;
    let (name_count, rest) = map[trailer_start..].split_at(USIZE);
    let (payload_size, magic) = rest.split_at(USIZE);

    if magic != MAGIC {
        return Err(Error::NotFound);
    }

    let name_count = usize::from_le_bytes(name_count.try_into().unwrap());
    let payload_size = usize::from_le_bytes(payload_size.try_into().unwrap());
    let payload_start = trailer_start
        .checked_sub(payload_size)
        .ok_or(Error::Corrupted)?;

    let buffer = PoolBuffer::Mapped { map, range: payload_start..trailer_start };
    QnamePool::from_buffer(buffer, name_count).ok_or(Error::Corrupted)
}
