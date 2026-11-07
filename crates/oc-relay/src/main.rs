use clap::Parser;
use oc_relay::{Relay, RelayConfig};
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
#[command(
    name = "oc-relay",
    about = "OpenChat relay: dumb encrypted store-and-forward server"
)]
struct Args {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// Maximum event lifetime, seconds.
    #[arg(long, default_value_t = 604_800)]
    ttl: u64,

    /// Maximum stored events per mailbox.
    #[arg(long, default_value_t = 100)]
    max_events: usize,

    /// Maximum opaque payload size, bytes.
    #[arg(long, default_value_t = 65_536)]
    max_payload: usize,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let relay = Relay::new(RelayConfig {
        ttl_seconds: args.ttl,
        max_events_per_mailbox: args.max_events,
        max_payload_bytes: args.max_payload,
    });

    let listener = TcpListener::bind(&args.listen).await?;
    // Only the listen address is logged; client addresses are never recorded.
    eprintln!("oc-relay listening on ws://{}/ws", listener.local_addr()?);
    relay.serve(listener).await
}
