use std::hash::Hasher;

use rapidhash::fast::RapidHasher;

use crate::dns_parser::Query;

pub fn hash_query(query: &Query) -> u64 {
    let mut hasher = RapidHasher::default();
    hasher.write(query.qname.as_slice());
    hasher.write_u16(query.qtype);
    hasher.write_u16(query.qclass);
    hasher.finish()
}