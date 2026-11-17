use std::{fs::{self, OpenOptions}, io, path::{Path, PathBuf}};

use crate::bundle::Result;
use crate::bundle::SELF_EXE;
use crate::bundle::blob::Bundle;

pub fn attach_bundle(bundle: Bundle) -> Result<()> {
    let tmp = copy_self()?;
    append_bundle(&tmp, bundle)?;
    rename_to_self(tmp, self_path()?)
}

fn copy_self() -> Result<PathBuf> {
    let tmp = tmp_path_from_self()?;
    fs::copy(SELF_EXE, &tmp)?;
    Ok(tmp)
}

fn append_bundle(path: &Path, bundle: Bundle) -> Result<()> {
    let mut file = OpenOptions::new().append(true).open(path)?;
    io::copy(&mut bundle.reader(), &mut file)?;
    Ok(())
}

fn rename_to_self(src: PathBuf, dst: PathBuf) -> Result<()> {
    fs::rename(src, dst)?;
    Ok(())
}

fn tmp_path_from_self() -> Result<PathBuf> {
    let mut tmp = self_path()?;
    tmp.as_mut_os_string().push(".tmp");
    Ok(tmp)
}

fn self_path() -> Result<PathBuf> {
    let self_path = fs::read_link(SELF_EXE)?;
    Ok(self_path)
}
