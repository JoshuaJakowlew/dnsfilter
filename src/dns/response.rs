use super::packet::Packet;

const QNAME_OFFSET: u16 = 12;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;

const TTL_SECS: u32 = 60;
const UDP_PAYLOAD_SIZE: u16 = 1232;

/// Compression pointer: `0b11` and the 14-bit offset of the question QNAME.
const QNAME_POINTER: [u8; 2] = (0xC000 | QNAME_OFFSET).to_be_bytes();

const A_IN: &[u8] = &qtype_class(TYPE_A, CLASS_IN);
const AAAA_IN: &[u8] = &qtype_class(TYPE_AAAA, CLASS_IN);

/// 12-byte header and a 4-byte RDATA of zeros (`0.0.0.0`).
const NULL_A_RR: [u8; 16] = null_rr(TYPE_A);
/// 12-byte header and a 16-byte RDATA of zeros (`::`).
const NULL_AAAA_RR: [u8; 28] = null_rr(TYPE_AAAA);
/// EDNS OPT with an empty option list. Unset bytes are extended RCODE, version, flags and RDLENGTH.
const OPT_RR: [u8; 11] = opt_rr(UDP_PAYLOAD_SIZE);

const ANCOUNT_ONE: [u8; 2] = 1u16.to_be_bytes();

const FLAGS_HI: usize = 2;
const FLAGS_LO: usize = 3;
const ANCOUNT: usize = 6;
const NSCOUNT: usize = 8;
const ARCOUNT: usize = 10;

// QR | Opcode | AA | TC | RD
const QR: u8 = 0b1000_0000;
const OPCODE_MASK: u8 = 0b0111_1000;
const RD: u8 = 0b0000_0001;

// RA | Z | AD | CD | RCODE
const RA: u8 = 0b1000_0000;
const CD: u8 = 0b0001_0000;

/// Root NAME plus TYPE. A query with EDNS starts its additional section like [`OPT_RR`].
const OPT_MARK_LEN: usize = 3;

const RR_HEADER_LEN: usize = 12;

const fn qtype_class(qtype: u16, qclass: u16) -> [u8; 4] {
    let qtype = qtype.to_be_bytes();
    let qclass = qclass.to_be_bytes();
    [qtype[0], qtype[1], qclass[0], qclass[1]]
}

const fn copy_at<const N: usize, const M: usize>(dst: &mut [u8; N], at: usize, src: [u8; M]) {
    let mut i = 0;
    while i < M {
        dst[at + i] = src[i];
        i += 1;
    }
}

/// Answer RR of `N` bytes. NAME points at the question QNAME, CLASS is IN, TTL is [`TTL_SECS`].
/// Bytes after the header stay zero, and RDLENGTH is `N - RR_HEADER_LEN`.
const fn null_rr<const N: usize>(rtype: u16) -> [u8; N] {
    assert!(N >= RR_HEADER_LEN && N - RR_HEADER_LEN <= u16::MAX as usize);

    let mut rr = [0u8; N];
    copy_at(&mut rr, 0, QNAME_POINTER);
    copy_at(&mut rr, 2, rtype.to_be_bytes());
    copy_at(&mut rr, 4, CLASS_IN.to_be_bytes());
    copy_at(&mut rr, 6, TTL_SECS.to_be_bytes());
    copy_at(&mut rr, 10, ((N - RR_HEADER_LEN) as u16).to_be_bytes());
    rr
}

const fn opt_rr(udp_payload: u16) -> [u8; 11] {
    let mut rr = [0u8; 11];
    copy_at(&mut rr, 1, TYPE_OPT.to_be_bytes());
    copy_at(&mut rr, 3, udp_payload.to_be_bytes());
    rr
}

/// Rewrites the query in `packet` into a response for a blocked name.
///
/// `A` becomes `0.0.0.0`, `AAAA` becomes `::`, and any other type becomes NODATA.
/// Returns the length of the response.
///
/// `packet[..len]` must be a query with exactly one question.
/// `q_end` is the index immediately after that question's QCLASS.
///
/// # Panics
///
/// Panics if `q_end < 4`, or if the response (and an appended OPT record, when `len > q_end`)
/// does not fit in `packet`.
pub fn write_blocked_response(packet: &mut Packet, len: usize, q_end: usize) -> usize {
    let has_opt = len > q_end && packet[q_end..q_end + OPT_MARK_LEN] == OPT_RR[..OPT_MARK_LEN];

    // QR=1, Opcode and RD preserved, AA=TC=0.
    packet[FLAGS_HI] = QR | (packet[FLAGS_HI] & (OPCODE_MASK | RD));
    // RA=1, CD preserved, Z=AD=RCODE=0.
    packet[FLAGS_LO] = RA | (packet[FLAGS_LO] & CD);
    packet[NSCOUNT..ARCOUNT + 2].fill(0);

    let pos = match &packet[q_end - 4..q_end] {
        A_IN => write_rr(packet, q_end, &NULL_A_RR),
        AAAA_IN => write_rr(packet, q_end, &NULL_AAAA_RR),
        _ => write_nodata(packet, q_end),
    };

    if has_opt {
        // High byte was cleared with NSCOUNT and ARCOUNT.
        packet[ARCOUNT + 1] = 1;
        append(packet, pos, &OPT_RR)
    } else {
        pos
    }
}

fn write_rr<const N: usize>(packet: &mut Packet, pos: usize, rr: &[u8; N]) -> usize {
    packet[ANCOUNT..ANCOUNT + 2].copy_from_slice(&ANCOUNT_ONE);
    append(packet, pos, rr)
}

fn write_nodata(packet: &mut Packet, pos: usize) -> usize {
    packet[ANCOUNT..ANCOUNT + 2].fill(0);
    pos
}

fn append<const N: usize>(packet: &mut Packet, pos: usize, bytes: &[u8; N]) -> usize {
    let end = pos + N;
    packet[pos..end].copy_from_slice(bytes);
    end
}
