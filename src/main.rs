use anyhow::Result;
use litedns::configuration::Configuration;
use std::path::PathBuf;
use tokio::net::{TcpListener, UdpSocket};
#[macro_use]
extern crate log;
use clap::Parser;
use litedns::args::Cli;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or(PathBuf::from("config.yaml"));

    let conf = Configuration::parse(config_path)?;
    env_logger::Builder::from_default_env()
        .format_timestamp_secs()
        .format_target(false)
        .parse_filters(conf.log_level.clone().as_str())
        .init();
    let handler = litedns::handler::DNSRequestHandler::new(conf.clone())?;
    let mut server = trust_dns_server::ServerFuture::new(handler);

    server.register_socket(UdpSocket::bind(conf.server.listen).await?);
    server.register_listener(
        TcpListener::bind(conf.server.listen).await?,
        Duration::from_secs(5),
    );

    info!("Listening on {}", conf.server.listen);

    server.block_until_done().await?;

    Ok(())
}
