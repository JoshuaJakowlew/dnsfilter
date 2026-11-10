use std::{net::SocketAddr, path::PathBuf};

use argh::FromArgs;

/// DNS filtering forwarder
#[derive(FromArgs, Debug)]
pub struct Args {
    /// path to the file with blocked domains
    #[argh(option, short = 'f')]
    pub filter_path: PathBuf,
    /// local port to listen on
    #[argh(option, short = 'p')]
    pub port: u16,
    /// upstream DNS server address
    #[argh(option, short = 'r')]
    pub remote_addr: SocketAddr,
}
