use clap::Parser;
use raptorq_pep::app_v2;
use raptorq_pep::config::{CliArgs, Config};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "raptorq_pep=info".parse().unwrap()),
        )
        .init();

    let args = CliArgs::parse();
    let config = Config::from_cli(args)?;

    info!(
        mode = ?config.mode,
        mtu = config.mtu,
        symbol_size = config.symbol_size,
        ipv6 = config.ipv6,
        "starting raptorq-pep",
    );

    app_v2::run(config).await
}
