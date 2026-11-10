use std::hash::Hasher;

use rapidhash::fast::RapidHasher;
use thiserror::Error;

use super::packet::QnameBuffer;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Truncated packet")]
    Truncated,
    #[error("Invalid qdcount")]
    InvalidQdcount,
    #[error("Segment too long")]
    SegmentTooLong,
    #[error("Name too long")]
    NameTooLong,
}

pub type Result<T> = std::result::Result<T, ParseError>;

pub struct Query {
    pub qname: QnameBuffer,
    pub qtype: u16,
    pub qclass: u16,
}

pub fn hash_query(query: &Query) -> u64 {
    let mut hasher = RapidHasher::default();
    hasher.write(query.qname.as_slice());
    hasher.write_u16(query.qtype);
    hasher.write_u16(query.qclass);
    hasher.finish()
}

impl Query {
    pub fn new() -> Self {
        Self {
            qname: QnameBuffer::new(),
            qtype: 0,
            qclass: 0,
        }
    }
}

const HEADER_SIZE: usize = 12;
const MAX_SEGMENT_LEN: usize = 64;
const MAX_NAME_LEN: usize = 255;

pub fn parse_query(packet: &[u8]) -> Result<(usize, Query)> {
    let qdcount = extract_qdcount(packet)?;
    validate_qdcount(qdcount)?;

    extract_query(packet)
}

fn extract_qdcount(packet: &[u8]) -> Result<usize> {
    if packet.len() < 12 {
        return Err(ParseError::Truncated);
    } else {
        let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        Ok(qdcount)
    }
}

fn validate_qdcount(qdcount: usize) -> Result<()> {
    match qdcount {
        1 => Ok(()),
        _ => Err(ParseError::InvalidQdcount),
    }
}

fn extract_query(packet: &[u8]) -> Result<(usize, Query)> {
    let mut pos = HEADER_SIZE;
    let end = packet.len();

    let mut q = Query::new();

    loop {
        if pos >= end {
            return Err(ParseError::Truncated);
        }

        let segment_len = packet[pos] as usize;
        if segment_len >= MAX_SEGMENT_LEN {
            return Err(ParseError::SegmentTooLong);
        }

        let write_len = 1 + segment_len;
        if write_len + q.qname.len() > MAX_NAME_LEN {
            return Err(ParseError::NameTooLong);
        }

        if pos + write_len > end {
            return Err(ParseError::Truncated);
        }

        let segment = q.qname.push_segment(&packet[pos..pos + write_len]);
        segment[1..].make_ascii_lowercase(); // normalize name segment

        pos += write_len;

        if segment_len == 0 {
            if pos + 4 > end {
                return Err(ParseError::Truncated);
            }

            q.qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
            q.qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);

            pos += 4;

            return Ok((pos, q));
        }
    }
}
