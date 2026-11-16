mod blob;
mod rename;

use std::fs::File;

use memmap2::Mmap;
use thiserror::Error;

use crate::filter::qname_set::QnamePool;

const SELF_EXE: &str = "/proc/self/exe";

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bundle is corrupted")]
    Corrupted,
    #[error("Bundle is not attached")]
    NotFound,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn load() -> Result<QnamePool> {
    let file = File::open(SELF_EXE)?;
    // SAFETY: running exe can't be opened for writing (ETXTBSY),
    // and attach_bundle replaces it via rename, leaving mapped inode intact
    // thus readonly map should be safe to use
    let map = unsafe { Mmap::map(&file)? };
    blob::decode(map)
}

pub fn attach(pool: &QnamePool) -> Result<()> {
    let bundle = blob::Bundle::new(pool);
    rename::attach_bundle(bundle)
}
