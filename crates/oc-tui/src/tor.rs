//! Embedded Tor via `arti-client`: no external `tor` binary needed.
//!
//! The worker bootstraps an in-process Tor client and runs a tiny
//! SOCKS5 server on top of it (127.0.0.1:9050), so the transport layer
//! keeps working through its existing SOCKS5 support unchanged.
//!
//! Bridges (obfs4/webtunnel) are optional and still need the
//! pluggable-transport binaries `obfs4proxy` / `webtunnel-client` in
//! PATH — that is how Tor pluggable transports work, including in arti.

use std::path::Path;
use std::sync::Arc;

use arti_client::config::{BridgeConfigBuilder, TorClientConfig};
use arti_client::TorClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tor_rtcompat::PreferredRuntime;

/// Bootstrapped Tor client handle.
pub type TorHandle = Arc<TorClient<PreferredRuntime>>;

/// Built-in Tor bridges (obfs4 + webtunnel), embedded so Tor works in
/// censored networks without manual config. Requires the PT binaries
/// `obfs4proxy` and `webtunnel-client`. Note: bridges in a public repo
/// get blocked faster — replace them here when they die.
pub const TOR_BRIDGES: &[&str] = &[
    "obfs4 51.38.220.224:24885 54CE8314507E15AD7B5F61DEBA6372E46C2A07EB cert=jr7h5jLJLoot4ufBd+676hitBxRE3a05vcBzjmsavf300vvY+8TfCfWNJYxwr9T5SveJfg iat-mode=0",
    "obfs4 51.161.81.197:65168 AC5FCFC2ACF33D3A800356E05D42BA68A7262AA3 cert=8mosjcVPEi3In4p/E+xGUC5sMSDKxXH2LG2SwkVK37deKnQwV6wPpHP3rRQuty3i3VbiNQ iat-mode=0",
    "webtunnel [2001:db8:3ce4:c7c7:1316:3072:b8e9:b915]:443 07E8A7DFCA7B76DD0E2F1E8C6C74D9910AAF279E url=https://shenvalleygamers.com/7HxRIWqsmkPOemUcLFTGuPaW ver=0.0.4",
    "webtunnel [2001:db8:71fb:a9be:f195:7fc:d1fa:3f41]:443 3D87781EE4EA775BFAA72B8F2D09C0BE489B6D71 url=https://104.36.85.19/bunt-senior-bucket ver=0.0.3",
];

/// Build the Arti configuration for this client.
fn build_config(home: &Path, use_bridges: bool) -> Result<TorClientConfig, String> {
    let cache_dir = home.join("tor-arti-cache");
    let state_dir = home.join("tor-arti-state");
    std::fs::create_dir_all(&cache_dir).map_err(|error| format!("tor cache dir: {error}"))?;
    std::fs::create_dir_all(&state_dir).map_err(|error| format!("tor state dir: {error}"))?;

    let mut builder = TorClientConfig::builder();
    builder
        .storage()
        .cache_dir(arti_client::config::CfgPath::new(
            cache_dir.to_string_lossy().into_owned(),
        ))
        .state_dir(arti_client::config::CfgPath::new(
            state_dir.to_string_lossy().into_owned(),
        ));

    if use_bridges {
        for line in TOR_BRIDGES {
            let bridge: BridgeConfigBuilder = line
                .parse()
                .map_err(|error| format!("bridge line invalid: {error}"))?;
            builder.bridges().bridges().push(bridge);
        }
        for protocol in ["obfs4", "webtunnel"] {
            let mut transport = arti_client::config::pt::TransportConfigBuilder::default();
            transport
                .protocols(vec![protocol.parse().unwrap()])
                .path(arti_client::config::CfgPath::new(protocol.to_string()))
                .run_on_startup(true);
            builder.bridges().transports().push(transport);
        }
        builder
            .bridges()
            .enabled(tor_config::BoolOrAuto::Explicit(true));
    }

    builder
        .build()
        .map_err(|error| format!("tor config: {error}"))
}

/// Bootstrap an in-process Tor client.
///
/// Takes 10–60 seconds on first run (directory download + circuit
/// building); subsequent runs reuse the cached directory.
pub async fn bootstrap_tor(home: &Path, use_bridges: bool) -> Result<TorHandle, String> {
    let config = build_config(home, use_bridges)?;
    TorClient::create_bootstrapped(config)
        .await
        .map_err(|error| format!("tor bootstrap failed: {error}"))
}

/// Run the SOCKS5 server loop on an already-bound listener.
pub async fn run_socks_proxy(client: TorHandle, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                let client = client.clone();
                tokio::spawn(async move {
                    let _ = handle_socks_connection(client, socket).await;
                });
            }
            Err(_) => continue,
        }
    }
}

async fn handle_socks_connection(client: TorHandle, mut socket: TcpStream) -> std::io::Result<()> {
    // Greeting: version + method count + methods.
    let mut greeting = [0u8; 2];
    socket.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(invalid("bad SOCKS version"));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    socket.read_exact(&mut methods).await?;
    socket.write_all(&[0x05, 0x00]).await?;

    // Request header: version, command, reserved, address type.
    let mut header = [0u8; 4];
    socket.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x01 {
        return Err(invalid("only CONNECT is supported"));
    }
    let host: String = match header[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            socket.read_exact(&mut addr).await?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            socket.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| invalid("bad host name"))?
        }
        0x04 => {
            let mut addr = [0u8; 16];
            socket.read_exact(&mut addr).await?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => return Err(invalid("unknown address type")),
    };
    let mut port = [0u8; 2];
    socket.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    // Connect through Tor.
    let mut stream = client
        .connect(format!("{host}:{port}"))
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))?;

    // Success reply (IPv4 zero bind address).
    socket
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    tokio::io::copy_bidirectional(&mut socket, &mut stream).await?;
    Ok(())
}

fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_bridges_parse() {
        for line in TOR_BRIDGES {
            let parsed: std::result::Result<BridgeConfigBuilder, _> = line.parse();
            assert!(parsed.is_ok(), "bridge line should parse: {line}");
        }
    }

    #[test]
    fn config_builds_with_and_without_bridges() {
        let home = std::env::temp_dir().join("oc-tui-tor-config-test");
        std::fs::create_dir_all(&home).unwrap();
        assert!(build_config(&home, false).is_ok());
        assert!(build_config(&home, true).is_ok());
        std::fs::remove_dir_all(&home).ok();
    }
}
