use std::{hash::Hasher, iter::FusedIterator};

use hashbrown::HashTable;
use hashbrown::hash_table::Entry;
use rapidhash::fast::RapidHasher;

use crate::dns::packet::Qname;
use crate::filter::pool_buffer::PoolBuffer;

pub struct QnamePool {
    buffer: PoolBuffer,
    len: usize,
}

impl QnamePool {
    pub fn new() -> Self {
        Self {
            buffer: PoolBuffer::Owned(Vec::new()),
            len: 0,
        }
    }

    /// Returns None if buffer is not a sequence of exactly `len` valid records
    /// Record validation is equivalent to Qname::from_bytes.
    pub fn from_buffer(buffer: PoolBuffer, len: usize) -> Option<Self> {
        let mut offset = 0;
        let mut count = 0;
        while offset < buffer.len() {
            let name_len = buffer[offset] as usize;
            let name_start = offset + 1;
            let name = buffer.get(name_start..name_start + name_len)?;
            Qname::from_bytes(name)?;
            offset = name_start + name_len;
            count += 1;
        }

        (count == len).then_some(Self { buffer, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, name: &Qname) -> usize {
        let name = name.as_bytes();
        let buffer = self.buffer.to_mut();
        let offset = buffer.len();

        buffer.reserve(1 + name.len());
        buffer.push(name.len() as u8);
        buffer.extend_from_slice(name);

        self.len += 1;

        offset
    }

    pub fn get(&self, offset: usize) -> &Qname {
        let len = self.buffer[offset] as usize;
        let name_offset = offset + 1;
        Qname::from_bytes_unchecked(&self.buffer[name_offset..name_offset + len])
    }

    pub fn iter(&self) -> QnamePoolIter<'_> {
        QnamePoolIter {
            buffer: &self.buffer,
            offset: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }
}

pub struct QnamePoolIter<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for QnamePoolIter<'a> {
    type Item = (usize, &'a Qname);
    fn next(&mut self) -> Option<Self::Item> {
        let start = self.offset;
        let len = *self.buffer.get(start)? as usize;
        let name_start = start + 1;
        let name = &self.buffer[name_start..name_start + len];
        self.offset = start + 1 + len;
        Some((start, Qname::from_bytes_unchecked(name)))
    }
}

impl FusedIterator for QnamePoolIter<'_> {}

fn hash_qname(name: &Qname) -> u64 {
    let mut hasher = RapidHasher::default();
    hasher.write(name.as_bytes());
    hasher.finish()
}

pub struct QnameSet {
    table: HashTable<usize>,
    pool: QnamePool,
}

impl QnameSet {
    /// Returns None if pool contains duplicate domains
    pub fn try_from_pool(pool: QnamePool) -> Option<Self> {
        let mut table = HashTable::with_capacity(pool.len());

        for (offset, name) in pool.iter() {
            let hash = hash_qname(name);
            match table.entry(
                hash,
                |&stored| pool.get(stored) == name,
                |&stored| hash_qname(pool.get(stored)),
            ) {
                Entry::Occupied(_) => return None,
                Entry::Vacant(entry) => {
                    entry.insert(offset);
                }
            }
        }

        Some(Self { table, pool })
    }

    pub fn len(&self) -> usize {
        self.pool.len()
    }

    pub fn contains(&self, name: &Qname) -> bool {
        let hash = hash_qname(name);
        self.table
            .find(
                hash,
                |&offset| self.pool.get(offset) == name
            )
            .is_some()
    }

    pub fn contains_hierarchical(&self, name: &Qname) -> bool {
        name
            .suffixes()
            .any(|suffix| self.contains(suffix))
    }
}
