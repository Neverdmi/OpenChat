//! `oc` — OpenChat command-line client.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use oc_client::invite::{peer_id_base32, short_peer_id};
use oc_client::{Client, Invite, StateStore};
use oc_transport::RelayPool;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "oc", about = "OpenChat command-line client")]
struct Args {
    /// Directory holding the encrypted state file.
    #[arg(
        long,
        global = true,
        value_name = "DIR",
        default_value_os_t = default_home(),
        env = "OPENCHAT_HOME"
    )]
    home: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new identity and encrypted state.
    Init {
        /// Relay to use (repeatable). Defaults to the bundled relay list.
        #[arg(long = "relay", value_name = "URL")]
        relays: Vec<String>,
    },

    /// Print this identity's invite link.
    Invite,

    /// Add a contact from an invite and send the X3DH handshake.
    Add {
        /// `openchat://v1/...` invite link.
        invite: String,

        /// Number of relays to publish the handshake to.
        #[arg(long, default_value_t = 3)]
        fanout: usize,
    },

    /// Encrypt and send a text message.
    Send {
        /// Peer id (full or unique prefix, base32 or hex).
        peer: String,

        /// Message text (quote it if it contains spaces).
        text: String,

        /// Number of relays to publish to.
        #[arg(long, default_value_t = 3)]
        fanout: usize,
    },

    /// Listen for incoming handshakes and messages.
    Listen {
        /// Drain currently available events and exit.
        #[arg(long)]
        once: bool,

        /// Seconds without events before returning (when --once).
        #[arg(long, default_value_t = 1)]
        idle: u64,

        /// Replay events newer than this UNIX timestamp.
        #[arg(long, default_value_t = 0)]
        since: u64,
    },

    /// List contacts.
    Contacts,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Init { relays } => init(&args.home, relays),
        Command::Invite => {
            let passphrase = passphrase(false)?;
            let client = open_client(&args.home, &passphrase)?;
            println!("{}", client.invite()?);
            Ok(())
        }
        Command::Add {
            invite: link,
            fanout,
        } => {
            let passphrase = passphrase(false)?;
            let mut client = open_client(&args.home, &passphrase)?;

            let invite = Invite::decode(&link).context("invalid invite link")?;
            let mut relays = client.relays().to_vec();
            for relay in &invite.relays {
                if !relays.contains(relay) {
                    relays.push(relay.clone());
                }
            }
            let pool = build_pool(&relays)?;

            let summary = client.add_invite(&link, &pool, fanout).await?;
            println!("added:        {}", peer_id_base32(&summary.peer_id));
            println!("safety:       {}", format_safety(&summary.safety_number));
            println!("handshake:    {} relay(s)", summary.delivered);
            Ok(())
        }
        Command::Send { peer, text, fanout } => {
            let passphrase = passphrase(false)?;
            let mut client = open_client(&args.home, &passphrase)?;
            let peer_id = resolve_peer(&client, &peer)?;
            let pool = build_pool(client.relays())?;

            let sent = client.send_text(&peer_id, &text, &pool, fanout).await?;
            println!(
                "sent {} to {} via {} relay(s)",
                hex::encode(sent.msg_id),
                short_peer_id(&peer_id),
                sent.delivered
            );
            Ok(())
        }
        Command::Listen { once, idle, since } => {
            let passphrase = passphrase(false)?;
            let mut client = open_client(&args.home, &passphrase)?;
            let pool = build_pool(client.relays())?;

            loop {
                let messages = client
                    .listen_once(&pool, Duration::from_secs(idle.max(1)), since)
                    .await?;
                for message in &messages {
                    println!("{}: {}", short_peer_id(&message.peer_id), message.text);
                }
                if once {
                    break;
                }
            }
            Ok(())
        }
        Command::Contacts => {
            let passphrase = passphrase(false)?;
            let client = open_client(&args.home, &passphrase)?;
            for contact in client.contacts() {
                println!(
                    "{}  {}{}",
                    peer_id_base32(&contact.peer_id),
                    format_safety(&contact.safety_number),
                    if contact.verified {
                        ""
                    } else {
                        "  [unverified]"
                    }
                );
            }
            Ok(())
        }
    }
}

fn init(home: &Path, mut relays: Vec<String>) -> Result<()> {
    if StateStore::exists(home) {
        bail!(
            "state already exists at {}; refusing to overwrite",
            StateStore::path_in(home).display()
        );
    }

    let passphrase = passphrase(true)?;
    if relays.is_empty() {
        relays = oc_transport::relay_list::default_relays()?;
    }

    let store = StateStore::create(home, &passphrase)?;
    let client = Client::create(store, relays)?;

    println!("identity: {}", peer_id_base32(&client.peer_id()?));
    println!("state:    {}", StateStore::path_in(home).display());
    if client.relays().is_empty() {
        println!(
            "warning: no relays configured; add one with `oc init` or an invite with relay hints"
        );
    }
    Ok(())
}

fn open_client(home: &Path, passphrase: &str) -> Result<Client> {
    let store = StateStore::open(home, passphrase)?;
    Ok(Client::open(store)?)
}

fn build_pool(relays: &[String]) -> Result<RelayPool> {
    if relays.is_empty() {
        bail!("no relays configured");
    }
    Ok(RelayPool::from_urls(relays.iter().cloned())?)
}

fn resolve_peer(client: &Client, argument: &str) -> Result<[u8; 32]> {
    let argument = argument.trim();
    if argument.len() < 4 {
        bail!("peer prefix must be at least 4 characters");
    }

    let base32_prefix = argument.to_ascii_uppercase();
    let hex_prefix = argument.to_ascii_lowercase();
    let matches: Vec<[u8; 32]> = client
        .contacts()
        .iter()
        .filter(|contact| {
            peer_id_base32(&contact.peer_id).starts_with(&base32_prefix)
                || hex::encode(contact.peer_id).starts_with(&hex_prefix)
        })
        .map(|contact| contact.peer_id)
        .collect();

    match matches.as_slice() {
        [peer_id] => Ok(*peer_id),
        [] => bail!("unknown peer: {argument}"),
        _ => bail!("ambiguous peer prefix: {argument}"),
    }
}

fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    if let Ok(value) = std::env::var("OPENCHAT_PASSPHRASE") {
        if value.is_empty() {
            bail!("OPENCHAT_PASSPHRASE is empty");
        }
        return Ok(Zeroizing::new(value));
    }

    let first = Zeroizing::new(rpassword::prompt_password("OpenChat passphrase: ")?);
    if first.len() < 8 {
        bail!("passphrase must be at least 8 characters");
    }
    if confirm {
        let second = rpassword::prompt_password("Repeat passphrase: ")?;
        if first.as_str() != second {
            bail!("passphrases do not match");
        }
    }
    Ok(first)
}

fn format_safety(bytes: &[u8; 32]) -> String {
    bytes
        .chunks(4)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(" ")
}

fn default_home() -> PathBuf {
    if let Some(home) = std::env::var_os("OPENCHAT_HOME") {
        return PathBuf::from(home);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".openchat");
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(home).join(".openchat");
    }
    PathBuf::from(".openchat")
}
