use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub filter_path: PathBuf,
    #[arg(short, long)]
    pub port: u16,
    #[arg(short, long)]
    pub remote_addr: SocketAddr,
}
