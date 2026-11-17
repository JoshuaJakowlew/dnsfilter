use std::path::Path;

use thiserror::Error;

use crate::dns::packet::QnameBuffer;
use crate::filter::qname_set::{QnamePool, QnameSet};

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid domain name")]
    InvalidDomain,
    #[error("Domain list is not unique")]
    Duplicate,
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait FilterLoader {
    fn from_file(path: &Path) -> Result<QnameSet>;
}

pub struct DomainFileLoader;

impl FilterLoader for DomainFileLoader {
    fn from_file(path: &Path) -> Result<QnameSet> {
        let bytes = std::fs::read(path)?;
        let mut pool = QnamePool::new();

        for line in bytes.split(|&b| b == b'\n') {
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }

            let domain = std::str::from_utf8(line)
                .map_err(|_| Error::InvalidDomain)?;
            let qname = QnameBuffer::from_domain(domain)
                .ok_or(Error::InvalidDomain)?;
            pool.push(&qname);
        }

        QnameSet::try_from_pool(pool)
            .ok_or(Error::Duplicate)
    }
}
