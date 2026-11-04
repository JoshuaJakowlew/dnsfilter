use std::hash::Hasher;

use hashbrown::HashTable;
use rapidhash::fast::RapidHasher;

use crate::dns_packet::QnameBuffer;

pub struct QnamePool {
    buffer: Vec<u8>,
    len: usize,
}

impl QnamePool {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, name: &QnameBuffer) -> usize {
        let name = name.as_slice();
        let offset = self.buffer.len();

        self.buffer.reserve(1 + name.len());
        self.buffer.push(name.len() as u8);
        self.buffer.extend_from_slice(name);
        
        self.len += 1;

        offset
    }

    pub fn get(&self, offset: usize) -> &[u8] {
        let len = self.buffer[offset] as usize;
        let name_offset = offset + 1;
        &self.buffer[name_offset..name_offset + len]
    }

    pub fn iter(&self) -> QnamePoolIter<'_> {
        QnamePoolIter {
            buffer: &self.buffer,
            offset: 0,
        }
    }
}

pub struct QnamePoolIter<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for QnamePoolIter<'a> {
    type Item = (usize, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let start = self.offset;
        let len = *self.buffer.get(start)? as usize;
        let name_start = start + 1;
        let name = &self.buffer[name_start..name_start + len];
        self.offset = start + 1 + len;
        Some((start, name))
    }
}

fn hash_qname(name: &[u8]) -> u64 {
    let mut hasher = RapidHasher::default();
    hasher.write(name);
    hasher.finish()
}

pub struct QnameFilter {
    table: HashTable<usize>,
    pool: QnamePool,
}

impl QnameFilter {
    /// Constructs a QnameFilter from a pool of unique Qnames.
    pub fn from_unique_pool(pool: QnamePool) -> Self {
        let mut table = HashTable::with_capacity(pool.len());

        for (offset, name) in pool.iter() {
            let hash = hash_qname(name);
            table.insert_unique(
                hash,
                offset,
                |&stored| hash_qname(pool.get(stored))
            );
        }

        Self { table, pool }   
    }

    pub fn contains(&self, name: &[u8]) -> bool {
        let hash = hash_qname(name);
        self.table
            .find(
                hash,
                |&offset| self.pool.get(offset) == name
            )
            .is_some()
    }

    
}
