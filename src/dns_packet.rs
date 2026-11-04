use std::mem::MaybeUninit;

pub const MAX_PACKET_SIZE: usize = 65536;

pub type Packet = [u8; MAX_PACKET_SIZE];

#[derive(Clone, Copy, Debug)]
pub struct PacketId(pub [u8; 2]);

impl PacketId {
    pub fn from_map_index(index: usize) -> Self {
        PacketId([(index >> 8) as u8, (index & 0xFF) as u8])
    }

    pub fn from_packet(packet: &[u8]) -> Self {
        PacketId([packet[0], packet[1]])
    }
}

impl From<PacketId> for usize {
    fn from(id: PacketId) -> Self {
        let PacketId(bytes) = id;
        (bytes[0] as usize) << 8 | bytes[1] as usize
    }
}

pub const MAX_QNAME: usize = 255;

pub struct QnameBuffer {
    buffer: [MaybeUninit<u8>; MAX_QNAME],
    len: usize,
}

const UNINIT_BYTE: MaybeUninit<u8> = MaybeUninit::uninit();

impl QnameBuffer {
    pub fn new() -> Self {
        Self {
            buffer: [UNINIT_BYTE; MAX_QNAME],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            self.buffer[..self.len].assume_init_ref()
        }
    }

    // Returns a slice of the appended segment.
    pub fn append_segment(&mut self, segment: &[u8]) -> &mut [u8] {
        let start = self.len;
        let end = self.len + segment.len();
        self.len = end;
        self.buffer[start..end].write_copy_of_slice(segment)
    }
}
