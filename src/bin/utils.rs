pub use dephy_edge::*;
use preludes::*;

use clap::{Parser, Subcommand};
use rand_core::OsRng;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    GenerateEnv {
        #[arg(short, long, env, default_value = "info")]
        log_level: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Options::parse();

    match &opt.command {
        Command::GenerateEnv { log_level } => {
            let priv_key = k256::SecretKey::random(&mut OsRng);
            let priv_key = priv_key.as_scalar_primitive();
            let priv_key = priv_key.to_string().to_lowercase();
            println!("RUST_LOG=dephy_edge={},rumqttd::*=off", log_level);
            println!("DEPHY_PRIV_KEY={}", priv_key);
        }
    }

    Ok(())
}
