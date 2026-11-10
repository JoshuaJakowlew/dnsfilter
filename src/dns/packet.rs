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
pub const MAX_QNAME_SEGMENT: usize = 63;

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

    pub fn from_domain(domain: &str) -> Option<Self> {
        let mut qname = Self::new();
        let mut domain = domain.as_bytes();

        // Remove explicit root label.
        if domain.last() == Some(&b'.') {
            domain = &domain[..domain.len() - 1];
        }

        // Empty domain is a valid Qname.
        if domain.is_empty() {
            qname.buffer[0].write(0);
            qname.len = 1;
            return Some(qname);
        }

        for segment in domain.split(|&l| l == b'.') {
            let slen = segment.len();
            
            if segment.is_empty() ||
               slen > MAX_QNAME_SEGMENT ||
               slen + qname.len + 2 > MAX_QNAME { // +2 for current size and null terminator
                return None;
            }

            let start = qname.len;
            let end = start + slen + 1;
            qname.buffer[start].write(slen as u8);
            qname.buffer[start + 1..end]
                .write_copy_of_slice(segment)
                .make_ascii_lowercase();
            qname.len = end;
        }

        qname.buffer[qname.len].write(0);
        qname.len += 1;
        Some(qname)
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
    pub fn push_segment(&mut self, segment: &[u8]) -> &mut [u8] {
        let start = self.len;
        let end = self.len + segment.len();
        self.len = end;
        self.buffer[start..end].write_copy_of_slice(segment)
    }
}
