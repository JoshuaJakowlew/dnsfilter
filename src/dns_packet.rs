const MAX_PACKET_SIZE: usize = 65536;

type Packet = [u8; MAX_PACKET_SIZE];

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
