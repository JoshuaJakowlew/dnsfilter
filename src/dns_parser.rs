use thiserror::Error;

use crate::dns_packet::QnameBuffer;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Truncated packet")]
    Truncated,
    #[error("Bad label")]
    BadLabel,
    #[error("Name too long")]
    NameTooLong,
    #[error("Too many hops")]
    TooManyHops,
    #[error("Invalid offset")]
    InvalidOffset,
}

pub type Result<T> = std::result::Result<T, ParseError>;

pub struct Question {
    pub qname: QnameBuffer,
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    pub fn new() -> Self {
        Self {
            qname: QnameBuffer::new(),
            qtype: 0,
            qclass: 0,
        }
    }
}

const HEADER_SIZE: usize = 12;
const MAX_NAME: usize = 255;
const MAX_HOPS: usize = 128;

mod tag_mask {
    pub const MASK: u8 = 0xC0;
    pub const LEN: u8 = 0x00;
    pub const PTR: u8 = 0xC0;
    pub const PTR_OFFSET_MASK: u16 = 0x3FFF;
}

pub fn parse_questions(packet: &[u8]) -> Result<Vec<Question>> {
    let (_, questions) = parse_questions_with_pos(packet)?;
    Ok(questions)
}

pub fn parse_questions_with_pos(packet: &[u8]) -> Result<(usize, Vec<Question>)> {
    let qdcount = extract_qdcount(packet)?;
    extract_questions_with_pos(packet, qdcount)
}

fn extract_qdcount(packet: &[u8]) -> Result<usize> {
    if packet.len() < 12 {
        Err(ParseError::Truncated)
    } else {
        let  qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        Ok(qdcount)
    }
}

fn extract_questions_with_pos(packet: &[u8], qdcount: usize) -> Result<(usize, Vec<Question>)> {
    let mut pos = HEADER_SIZE;
    let end = packet.len();

    let mut questions = Vec::with_capacity(qdcount);

    let mut err: Option<ParseError> = None;
    for _ in 0..qdcount {
        // Cursor frozen at the first pointer. QTYPE starts there. Further jumps only move pos.
        // This is needed bcs if pointer points to a name segment - it parses, but original after-pointer pos is lost.
        let mut name_end: Option<usize> = None;
        let mut hops = 0usize;
        let mut written = 0usize;

        let mut q = Question::new();

        loop {
            if pos >= end {
                return Err(ParseError::Truncated);
            }

            let tag = packet[pos];
            match tag & tag_mask::MASK {
                tag_mask::LEN => {
                    let len = tag as usize;
                    let write_len = 1 + len;

                    if write_len + written > MAX_NAME {
                        err = Some(ParseError::NameTooLong);
                        break;
                    }
                    if pos + write_len > end {
                        err = Some(ParseError::Truncated);
                        break;
                    }

                    let segment = q.qname.push_segment(&packet[pos..pos + write_len]);
                    segment[1..].make_ascii_lowercase(); // normalize name segment

                    written += write_len;
                    pos += write_len;

                    if len == 0 { // end of name, parse qtype and qclass
                        pos = name_end.unwrap_or(pos);
                        if pos + 4 > end {
                            err = Some(ParseError::Truncated);
                            break;
                        }

                        q.qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
                        q.qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);

                        // We are done with this question. Prepare pos for next question.
                        pos += 4;

                        break;
                    }
                }
                tag_mask::PTR => {
                    if pos + 2 > end { // ptr is two bytes, ensure we have [pos, pos + 1]
                        err = Some(ParseError::Truncated);
                        break;
                    }

                    let offset = (u16::from_be_bytes([packet[pos], packet[pos + 1]]) & tag_mask::PTR_OFFSET_MASK) as usize;
                    if 12 > offset || offset >= pos { // offset must point on any seen entry - name segment or another seen pointer
                        err = Some(ParseError::InvalidOffset);
                        break;
                    }

                    hops += 1;
                    if hops > MAX_HOPS {
                        err = Some(ParseError::TooManyHops);
                        break;
                    }

                    // If name_end is already set - it means that we in nested pointer hop.
                    if name_end.is_none() {
                        name_end = Some(pos + 2);
                    }
                    pos = offset;
                }
                _ => {
                    err = Some(ParseError::BadLabel);
                    break;
                }
            }
        }

        if let Some(err) = err {
            return Err(err);
        }

        questions.push(q);
    }

    Ok((pos, questions))
}
