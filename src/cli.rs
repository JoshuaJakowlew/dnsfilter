use std::{net::SocketAddr, path::PathBuf};

use argh::FromArgs;

/// DNS filtering forwarder
#[derive(FromArgs, Debug)]
pub struct Args {
    #[argh(subcommand)]
    pub cmd: Command,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum Command {
    Bundle(BundleArgs),
    Serve(ServeArgs),
}

/// Bundle domain list into this executable
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "bundle")]
pub struct BundleArgs {
    /// path to the file with blocked domains
    #[argh(option, short = 'f')]
    pub filter_path: PathBuf,
}

/// Run filtering forwarder
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "serve")]
pub struct ServeArgs {
    /// path to the file with blocked domains, attached bundle is used when omitted
    #[argh(option, short = 'f')]
    pub filter_path: Option<PathBuf>,
    /// local port to listen on
    #[argh(option, short = 'p')]
    pub port: u16,
    /// upstream DNS server address
    #[argh(option, short = 'r')]
    pub remote_addr: SocketAddr,
}
