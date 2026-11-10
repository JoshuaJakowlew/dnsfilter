use std::fmt;
use std::iter::FusedIterator;
use std::mem::MaybeUninit;
use std::ops::Deref;

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

    pub fn as_qname(&self) -> &Qname {
        let bytes = unsafe { self.buffer[..self.len].assume_init_ref() };
        Qname::from_bytes_unchecked(bytes)
    }

    // Returns a slice of the appended segment.
    pub fn push_segment(&mut self, segment: &[u8]) -> &mut [u8] {
        let start = self.len;
        let end = self.len + segment.len();
        self.len = end;
        self.buffer[start..end].write_copy_of_slice(segment)
    }
}

impl Deref for QnameBuffer {
    type Target = Qname;

    fn deref(&self) -> &Qname {
        self.as_qname()
    }
}

#[derive(PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Qname([u8]);

impl Qname {
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() > MAX_QNAME {
            return None;
        }

        let mut pos = 0;
        loop {
            let slen = *bytes.get(pos)? as usize;
            if slen > MAX_QNAME_SEGMENT {
                return None;
            }
            pos += 1 + slen;
            if slen == 0 {
                break;
            }
        }

        (pos == bytes.len()).then(|| Self::from_bytes_unchecked(bytes))
    }

    pub(crate) fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: Qname is repr(transparent) over [u8].
        unsafe { &*(bytes as *const [u8] as *const Self) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn segments(&self) -> Segments<'_> {
        Segments { rest: &self.0 }
    }
}

impl<'a> IntoIterator for &'a Qname {
    type Item = &'a [u8];
    type IntoIter = Segments<'a>;

    fn into_iter(self) -> Segments<'a> {
        self.segments()
    }
}

impl fmt::Debug for Qname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Qname(\"")?;
        for segment in self.segments() {
            write!(f, "{}.", segment.escape_ascii())?;
        }
        f.write_str("\")")
    }
}

#[derive(Clone)]
pub struct Segments<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Segments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let (&slen, tail) = self.rest.split_first()?;
        let slen = slen as usize;

        if slen == 0 || slen > tail.len() {
            self.rest = &[];
            return None;
        }

        let (segment, rest) = tail.split_at(slen);
        self.rest = rest;
        Some(segment)
    }
}

impl FusedIterator for Segments<'_> {}


