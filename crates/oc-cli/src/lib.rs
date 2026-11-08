//! `oc` — OpenChat command-line client.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use oc_client::invite::{peer_id_base32, short_peer_id};
use oc_client::{Client, Invite, ListenOutcome, StateStore};
use oc_transport::RelayPool;
use tokio::io::{AsyncBufReadExt, BufReader};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "oc",
    version,
    about = "OpenChat command-line client (text only)",
    after_help = "Quick start:\n  oc init --relay https://relay.example\n  oc invite\n  oc add <invite>\n  oc chat <peer-prefix>     # interactive: receive + send in one process\n  oc send <peer> \"hello\"    # or one-shot commands\n  oc listen                 # receive only, forever\n  oc contacts / oc relays --check / oc outbox / oc flush\n\nChat commands: /help, /peer <prefix>, /quit. Plaintext history is never\nstored: messages are printed when they arrive (or replay from the relay)."
)]
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
    Invite {
        /// Embed the full signed bundle (long link, works offline-relay
        /// style without a bundle fetch). Default is the short form.
        #[arg(long)]
        full: bool,
    },

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

    /// Interactive chat: receive and send text in one process.
    ///
    /// Without a peer argument it starts in receive-only mode; switch
    /// conversation with `/peer <prefix>`. Type `/help` inside for commands.
    Chat {
        /// Peer id (full or unique prefix, base32 or hex).
        peer: Option<String>,

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

    /// Retry every queued outgoing message now.
    Flush {
        /// Number of relays to publish to.
        #[arg(long, default_value_t = 3)]
        fanout: usize,
    },

    /// Show messages that have not reached any relay yet.
    Outbox,

    /// Rotate signed/PQ prekeys now; old invites keep working.
    Rotate,

    /// List configured relays, optionally add one or health-check them.
    Relays {
        /// Add a relay URL to the local list.
        #[arg(long = "add", value_name = "URL")]
        add: Vec<String>,

        /// Ping every relay and report reachability.
        #[arg(long)]
        check: bool,
    },
}

/// Run the CLI with the given argv (argv[0] is the program name).
///
/// This is the entry point shared by the `oc` binary and by
/// `oc-desktop --cli`, so the desktop build can drop into the exact same
/// command-line interface without a second implementation.
pub fn run_cli_from(args: Vec<std::ffi::OsString>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start tokio runtime")?;
    runtime.block_on(run_inner(args))
}

async fn run_inner(argv: Vec<std::ffi::OsString>) -> Result<()> {
    let args = Args::try_parse_from(argv).unwrap_or_else(|error| error.exit());

    match args.command {
        Command::Init { relays } => init(&args.home, relays),
        Command::Invite { full } => {
            let passphrase = passphrase(false)?;
            let client = open_client(&args.home, &passphrase)?;
            if full {
                println!("{}", client.invite_full()?);
            } else {
                println!("{}", client.invite()?);
            }
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
            if summary.queued {
                println!("handshake:    queued (relay unavailable, will retry)");
            } else {
                println!("handshake:    {} relay(s)", summary.delivered);
            }
            Ok(())
        }
        Command::Send { peer, text, fanout } => {
            let passphrase = passphrase(false)?;
            let mut client = open_client(&args.home, &passphrase)?;
            let peer_id = resolve_peer(&client, &peer)?;
            let pool = build_pool(client.relays())?;

            let sent = client.send_text(&peer_id, &text, &pool, fanout).await?;
            let state = if sent.queued {
                "queued (relay unavailable, will retry)".to_string()
            } else {
                format!("via {} relay(s)", sent.delivered)
            };
            println!(
                "sent {} to {} {state}",
                hex::encode(sent.msg_id),
                short_peer_id(&peer_id)
            );
            Ok(())
        }
        Command::Chat { peer, fanout } => {
            let passphrase = passphrase(false)?;
            let mut client = open_client(&args.home, &passphrase)?;
            let pool = build_pool(client.relays())?;
            run_chat(&mut client, &pool, peer, fanout).await
        }
        Command::Listen { once, idle, since } => {
            let passphrase = passphrase(false)?;
            let mut client = open_client(&args.home, &passphrase)?;
            let pool = build_pool(client.relays())?;

            loop {
                let outcome = client
                    .listen_once(&pool, Duration::from_secs(idle.max(1)), since)
                    .await?;
                print_outcome(&outcome);
                if once {
                    break;
                }
            }
            Ok(())
        }
        Command::Flush { fanout } => {
            let passphrase = passphrase(false)?;
            let mut client = open_client(&args.home, &passphrase)?;
            let pool = build_pool(client.relays())?;
            let pending = client.outbox().len();
            let delivered = client.flush_outbox(&pool, fanout).await?;
            let remaining = client.outbox().len();
            println!(
                "flushed: {delivered} delivered, {remaining} still queued (was {pending})"
            );
            Ok(())
        }
        Command::Outbox => {
            let passphrase = passphrase(false)?;
            let client = open_client(&args.home, &passphrase)?;
            if client.outbox().is_empty() {
                println!("outbox is empty");
            }
            for record in client.outbox() {
                println!(
                    "{}  {}  attempts={}  peer={}",
                    hex::encode(record.msg_id),
                    record.created_at,
                    record.attempts,
                    short_peer_id(&record.peer_id)
                );
            }
            Ok(())
        }
        Command::Rotate => {
            let passphrase = passphrase(false)?;
            let mut client = open_client(&args.home, &passphrase)?;
            client.rotate_prekeys()?;
            println!(
                "prekeys rotated; {} prekey(s) accept handshakes",
                client.prekey_count()
            );
            println!("new invite: {}", client.invite()?);
            Ok(())
        }
        Command::Relays { add, check } => {
            let passphrase = passphrase(false)?;
            let mut client = open_client(&args.home, &passphrase)?;
            if !add.is_empty() {
                client.add_relays(add)?;
            }

            if client.relays().is_empty() {
                println!("no relays configured");
                return Ok(());
            }
            if check {
                let pool = build_pool(client.relays())?;
                for (url, healthy) in pool.health().await {
                    println!("{}  {url}", if healthy { "ok  " } else { "dead" });
                }
            } else {
                for relay in client.relays() {
                    println!("{relay}");
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

/// One parsed line of interactive chat input.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChatAction {
    /// Blank line.
    Empty,
    /// Leave the chat.
    Quit,
    /// Show commands.
    Help,
    /// Switch conversation to the given peer prefix.
    Peer(String),
    /// Unknown slash-command (first word).
    Unknown(String),
    /// Text to send to the current peer.
    Text(String),
}

/// Parse one line typed in `oc chat`.
fn parse_chat_line(line: &str) -> ChatAction {
    let line = line.trim();
    if line.is_empty() {
        return ChatAction::Empty;
    }
    if line == "/quit" || line == "/exit" {
        return ChatAction::Quit;
    }
    if line == "/help" {
        return ChatAction::Help;
    }
    if let Some(rest) = line.strip_prefix("/peer ") {
        let prefix = rest.trim();
        if !prefix.is_empty() {
            return ChatAction::Peer(prefix.to_string());
        }
    }
    if let Some(command) = line.strip_prefix('/') {
        let first_word = command.split_whitespace().next().unwrap_or("");
        return ChatAction::Unknown(format!("/{first_word}"));
    }
    ChatAction::Text(line.to_string())
}

/// Interactive chat loop: drain incoming events, then read one input line.
///
/// Incoming events are polled with a 1-second idle window and input with a
/// 1-second timeout, alternating. That keeps a single `Client` (which is
/// not `Clone`) usable for both directions without threads; messages are
/// printed on arrival, outgoing text goes through the usual outbox path,
/// so a relay outage queues instead of losing the line.
async fn run_chat(
    client: &mut Client,
    pool: &RelayPool,
    peer: Option<String>,
    fanout: usize,
) -> Result<()> {
    let mut current: Option<[u8; 32]> = match peer {
        Some(argument) => Some(resolve_peer(client, &argument)?),
        None => None,
    };

    println!("OpenChat chat (text only)");
    match current {
        Some(peer_id) => println!("talking to {}", short_peer_id(&peer_id)),
        None => println!("no peer selected yet; use /peer <prefix> to pick one"),
    }
    println!("commands: /help  /peer <prefix>  /quit");

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        match client.listen_once(pool, Duration::from_secs(1), 0).await {
            Ok(outcome) => print_outcome(&outcome),
            Err(error) => eprintln!("listen error: {error:#}"),
        }

        let line = match tokio::time::timeout(Duration::from_secs(1), lines.next_line()).await {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                eprintln!("input error: {error}");
                break;
            }
            Err(_) => continue,
        };

        match parse_chat_line(&line) {
            ChatAction::Empty => {}
            ChatAction::Quit => break,
            ChatAction::Help => {
                println!("commands: /help  /peer <prefix>  /quit\njust type text to send it");
            }
            ChatAction::Peer(prefix) => match resolve_peer(client, &prefix) {
                Ok(peer_id) => {
                    current = Some(peer_id);
                    println!("talking to {}", short_peer_id(&peer_id));
                }
                Err(error) => eprintln!("error: {error:#}"),
            },
            ChatAction::Unknown(command) => {
                eprintln!("unknown command: {command} (try /help)");
            }
            ChatAction::Text(text) => {
                let Some(peer_id) = current else {
                    eprintln!("no peer selected; use /peer <prefix> first");
                    continue;
                };
                match client.send_text(&peer_id, &text, pool, fanout).await {
                    Ok(sent) if sent.queued => {
                        println!("queued (relay unavailable, will retry)");
                    }
                    Ok(sent) => println!("sent via {} relay(s)", sent.delivered),
                    Err(error) => eprintln!("send error: {error:#}"),
                }
            }
        }
    }
    Ok(())
}

/// Print everything one receive pass produced.
fn print_outcome(outcome: &ListenOutcome) {
    for peer_id in &outcome.added_contacts {
        println!("new contact: {}", short_peer_id(peer_id));
    }
    for message in &outcome.messages {
        println!("{}: {}", short_peer_id(&message.peer_id), message.text);
    }
    for ack in &outcome.acks {
        println!(
            "ack: {} delivered {}",
            short_peer_id(&ack.peer_id),
            hex::encode(ack.acked_msg_id)
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_line_parsing() {
        assert_eq!(parse_chat_line(""), ChatAction::Empty);
        assert_eq!(parse_chat_line("   "), ChatAction::Empty);
        assert_eq!(parse_chat_line("/quit"), ChatAction::Quit);
        assert_eq!(parse_chat_line("/exit"), ChatAction::Quit);
        assert_eq!(parse_chat_line("/help"), ChatAction::Help);
        assert_eq!(
            parse_chat_line("/peer ABCD1234"),
            ChatAction::Peer("ABCD1234".to_string())
        );
        assert_eq!(
            parse_chat_line("/bogus arg"),
            ChatAction::Unknown("/bogus".to_string())
        );
        assert_eq!(
            parse_chat_line("hello world"),
            ChatAction::Text("hello world".to_string())
        );
        // Plain text may contain slashes, just not as the first character.
        assert_eq!(
            parse_chat_line("a/b testing"),
            ChatAction::Text("a/b testing".to_string())
        );
    }

    #[test]
    fn chat_command_parses_with_and_without_peer() {
        let args = Args::try_parse_from(["oc", "chat"]).unwrap();
        assert!(matches!(args.command, Command::Chat { peer: None, .. }));

        let args = Args::try_parse_from(["oc", "chat", "ABCD1234", "--fanout", "1"]).unwrap();
        assert!(matches!(
            args.command,
            Command::Chat {
                peer: Some(ref peer),
                fanout: 1
            } if peer == "ABCD1234"
        ));
    }
}
