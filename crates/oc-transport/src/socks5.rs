//! Minimal SOCKS5 client (RFC 1928, no-auth + CONNECT only).
//!
//! Used to route carrier TCP connections through a local Tor SOCKS5
//! proxy (`tor --SocksPort 127.0.0.1:9050`). Only what Tor needs:
//! greeting with no authentication, then a CONNECT to a domain name.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Error, Result};

/// Timeout for establishing a proxied connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How carrier connections interact with Tor (SPEC §0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TorMode {
    /// Direct connections, Tor unused.
    #[default]
    Off,
    /// Direct first; on failure, retry through Tor.
    Fallback,
    /// Every connection goes through Tor; fail closed if unavailable.
    Always,
}

impl TorMode {
    /// Parse the settings-file spelling.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "fallback" => Some(Self::Fallback),
            "always" => Some(Self::Always),
            _ => None,
        }
    }

    /// Settings-file spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Fallback => "fallback",
            Self::Always => "always",
        }
    }
}

/// Tor proxy endpoint configuration for carriers.
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// Tor mode.
    pub mode: TorMode,
    /// SOCKS5 proxy host (usually a local `tor` process).
    pub proxy_host: String,
    /// SOCKS5 proxy port.
    pub proxy_port: u16,
}

impl TorConfig {
    /// Direct-only configuration (no proxy).
    pub fn direct() -> Self {
        Self {
            mode: TorMode::Off,
            proxy_host: String::new(),
            proxy_port: 0,
        }
    }
}

/// Encode a SOCKS5 CONNECT request for `host:port` (domain addressing).
pub fn build_connect_request(host: &str, port: u16) -> std::io::Result<Vec<u8>> {
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "host name too long for SOCKS5",
        ));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

/// Parse a SOCKS5 reply header; returns the bound address length so the
/// caller can skip it. Only success (`REP=0`) is accepted.
pub fn parse_connect_reply(reply: &[u8]) -> std::io::Result<usize> {
    if reply.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "short SOCKS5 reply",
        ));
    }
    if reply[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad SOCKS5 version",
        ));
    }
    if reply[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 connect refused (code {})", reply[1]),
        ));
    }
    let address_len = match reply[3] {
        0x01 => 4,  // IPv4
        0x03 => {
            let len = *reply.get(4).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short SOCKS5 reply")
            })? as usize;
            1 + len
        }
        0x04 => 16, // IPv6
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown SOCKS5 address type",
            ));
        }
    };
    // Header (4) + address + port (2).
    Ok(4 + address_len + 2)
}

/// Connect to `host:port`, optionally through a SOCKS5 proxy at
/// `proxy_host:proxy_port`. Returns the connected TCP stream; TLS and
/// WebSocket layers wrap it unchanged.
pub async fn connect_tcp(
    proxy: Option<(&str, u16)>,
    host: &str,
    port: u16,
) -> Result<tokio::net::TcpStream> {
    match proxy {
        None => tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect((host, port)),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|error| Error::Relay(format!("tcp connect: {error}"))),
        Some((proxy_host, proxy_port)) => connect_via_socks5(proxy_host, proxy_port, host, port)
            .await
            .map_err(|error| Error::Relay(format!("socks5: {error}"))),
    }
}

/// Connect honouring the Tor mode: `Always` requires the proxy,
/// `Fallback` tries direct first and retries through the proxy,
/// `Off` is always direct.
pub async fn connect_tcp_mode(
    tor: &TorConfig,
    host: &str,
    port: u16,
) -> Result<tokio::net::TcpStream> {
    match tor.mode {
        TorMode::Off => connect_tcp(None, host, port).await,
        TorMode::Always => {
            connect_tcp(Some((&tor.proxy_host, tor.proxy_port)), host, port).await
        }
        TorMode::Fallback => match connect_tcp(None, host, port).await {
            Ok(stream) => Ok(stream),
            Err(direct_error) => {
                connect_tcp(Some((&tor.proxy_host, tor.proxy_port)), host, port)
                    .await
                    .map_err(|tor_error| {
                        Error::Relay(format!(
                            "direct failed ({direct_error}); tor fallback failed ({tor_error})"
                        ))
                    })
            }
        },
    }
}

async fn connect_via_socks5(
    proxy_host: &str,
    proxy_port: u16,
    host: &str,
    port: u16,
) -> std::io::Result<tokio::net::TcpStream> {
    let mut socket = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((proxy_host, proxy_port)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "socks connect"))?
    .map_err(|error| {
        std::io::Error::new(error.kind(), format!("socks proxy connect: {error}"))
    })?;

    // Greeting: version 5, one method (no authentication).
    socket.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    socket.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 proxy requires authentication",
        ));
    }

    // CONNECT request.
    let request = build_connect_request(host, port)?;
    socket.write_all(&request).await?;

    // Reply: 4-byte header first, then the bound address whose length
    // depends on ATYP (domain names need a length byte first).
    let mut header = [0u8; 4];
    socket.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad SOCKS5 version",
        ));
    }
    if header[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 connect refused (code {})", header[1]),
        ));
    }
    let address_len = match header[3] {
        0x01 => 4,
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            1 + len[0] as usize
        }
        0x04 => 16,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown SOCKS5 address type",
            ));
        }
    };
    let mut rest = vec![0u8; address_len + 2];
    socket.read_exact(&mut rest).await?;

    // Re-validate the assembled reply through the pure parser.
    let mut full_reply = header.to_vec();
    full_reply.extend_from_slice(&rest);
    let total = parse_connect_reply(&full_reply)?;
    debug_assert_eq!(total, full_reply.len());

    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_encoding() {
        let request = build_connect_request("broker.example", 8884).unwrap();
        assert_eq!(request[0], 0x05);
        assert_eq!(request[1], 0x01); // CONNECT
        assert_eq!(request[2], 0x00); // reserved
        assert_eq!(request[3], 0x03); // domain
        assert_eq!(request[4], 14);
        assert_eq!(&request[5..19], b"broker.example");
        assert_eq!(&request[19..21], &8884u16.to_be_bytes());
        assert!(build_connect_request(&"a".repeat(300), 80).is_err());
    }

    #[test]
    fn connect_reply_parsing() {
        // Success with IPv4 bound address.
        let reply = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x23, 0x28];
        assert_eq!(parse_connect_reply(&reply).unwrap(), 10);
        // Success with domain bound address.
        let reply = [0x05, 0x00, 0x00, 0x03, 4, b'a', b'b', b'c', b'd', 0, 80];
        assert_eq!(parse_connect_reply(&reply).unwrap(), 11);
        // Refusal (0x05 = connection refused) is an error.
        let reply = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        assert!(parse_connect_reply(&reply).is_err());
        // Truncated reply is an error.
        assert!(parse_connect_reply(&[0x05, 0x00]).is_err());
    }
}
