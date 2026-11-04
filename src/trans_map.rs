use std::mem::MaybeUninit;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug)]
pub struct DnsTransId(pub [u8; 2]);

impl DnsTransId {
    pub fn from_index(index: usize) -> Self {
        DnsTransId([(index >> 8) as u8, (index & 0xFF) as u8])
    }

    pub fn from_packet(packet: &[u8]) -> Self {
        DnsTransId([packet[0], packet[1]])
    }
}

impl From<DnsTransId> for usize {
    fn from(id: DnsTransId) -> Self {
        let DnsTransId(bytes) = id;
        (bytes[0] as usize) << 8 | bytes[1] as usize
    }
}

#[derive(Clone, Copy)]
pub struct Transaction {
    pub addr: SocketAddr,
    pub id: DnsTransId,
}

pub struct TransactionMap {
    origins: [MaybeUninit<Transaction>; MAP_CAPACITY],
    occupancy: OccupancyBitmap,
}

impl TransactionMap {
    pub fn new() -> Self {
        Self {
            origins: [MaybeUninit::uninit(); MAP_CAPACITY],
            occupancy: OccupancyBitmap::new(),
        }
    }

    pub fn insert(&mut self, origin: Transaction) -> Option<DnsTransId> {
        let i = self.occupancy.use_free()?;
        self.write(i, origin);
        Some(DnsTransId::from_index(i))
    }

    pub fn extract(&mut self, id: DnsTransId) -> Option<Transaction> {
        let i = self.occupancy.release(id.into())?;
        let origin = self.read(i);
        Some(origin)
    }

    fn write(&mut self, index: usize, origin: Transaction) {
        unsafe {
            self.origins.get_unchecked_mut(index).write(origin);
        }
    }

    fn read(&self, index: usize) -> Transaction {
        unsafe {
            self.origins.get_unchecked(index).assume_init_read()
        }
    }
}

const MAP_CAPACITY: usize = 65536;
const BITMAP_SIZE: usize = MAP_CAPACITY / 8;
const BITMAP_CHUNKS: usize = BITMAP_SIZE / 8;

const _: () = assert!(MAP_CAPACITY == BITMAP_CHUNKS * u64::BITS as usize);
const _: () = assert!(BITMAP_CHUNKS.is_power_of_two());

struct OccupancyBitmap {
    cursor: usize,
    chunks: [u64; BITMAP_CHUNKS],
}

struct BitIndex {
    chunk: usize,
    mask: u64,
}

impl OccupancyBitmap {
    pub fn new() -> Self {
        Self {
            cursor: 0,
            chunks: [0; BITMAP_CHUNKS],
        }
    }

    #[inline(always)]
    pub fn use_free(&mut self) -> Option<usize> {
        let index = self.find_free()?;
        self.set_used(index);
        Some(index)
    }

    #[inline(always)]
    pub fn release(&mut self, index: usize) -> Option<usize> {
        if self.is_used(index) {
            self.set_free(index);
            Some(index)
        } else {
            None
        }
    }
    
    #[inline(always)]
    fn find_free(&mut self) -> Option<usize> {
        const CHUNK_INDEX_MASK: usize = BITMAP_CHUNKS - 1;

        let start = self.cursor;
        let mut i = start;
        
        loop {
            let free_bit = self.chunk(i).trailing_ones();
            if free_bit < u64::BITS {
                self.cursor = i;
                return Some((i << 6) + free_bit as usize);
            }

            i = (i + 1) & CHUNK_INDEX_MASK;
            if i == start {
                return None;
            }
        }
    }

    #[inline(always)]
    fn is_used(&self, index: usize) -> bool {
        let BitIndex { chunk, mask } = Self::bit(index);
        self.chunk(chunk) & mask != 0
    }

    #[inline(always)]
    fn set_used(&mut self, index: usize) {
        let BitIndex { chunk, mask } = Self::bit(index);
        unsafe {
            *self.chunks.get_unchecked_mut(chunk) |= mask;
        }
    }

    #[inline(always)]
    fn set_free(&mut self, index: usize) {
        let BitIndex { chunk, mask } = Self::bit(index);
        unsafe {
            *self.chunks.get_unchecked_mut(chunk) &= !mask;
        }
    }

    #[inline(always)]
    fn chunk(&self, chunk_index: usize) -> u64 {
        debug_assert!(chunk_index < BITMAP_CHUNKS);
        unsafe { *self.chunks.get_unchecked(chunk_index) }
    }

    #[inline(always)]
    fn bit(index: usize) -> BitIndex {
        debug_assert!(index < MAP_CAPACITY);
        BitIndex {
            chunk: index >> 6,
            mask: 1u64 << (index & 63),
        }
    }
}
