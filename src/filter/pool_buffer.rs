use std::ops::{Deref, Range};

use memmap2::Mmap;

pub enum PoolBuffer {
    Owned(Vec<u8>),
    Mapped { map: Mmap, range: Range<usize> },
}

impl PoolBuffer {
    pub fn to_mut(&mut self) -> &mut Vec<u8> {
        if let Self::Mapped { .. } = self {
            *self = Self::Owned(self.to_vec());
        }
        match self {
            Self::Owned(buffer) => buffer,
            Self::Mapped { .. } => unreachable!(),
        }
    }
}

impl Deref for PoolBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Owned(buffer) => buffer,
            Self::Mapped { map, range } => &map[range.clone()],
        }
    }
}
