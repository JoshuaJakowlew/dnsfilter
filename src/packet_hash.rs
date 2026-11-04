use std::hash::Hasher;

use rapidhash::fast::RapidHasher;

use crate::dns_parser::Question;

pub fn hash_questions(questions: &[Question]) -> u64 {
    let mut hasher = RapidHasher::default();
    for q in questions {
        hasher.write(q.qname.as_slice());
        hasher.write_u16(q.qtype);
        hasher.write_u16(q.qclass);
    }
    hasher.finish()
}