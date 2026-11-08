# Relay lists and manifests

`default.json` is the relay list compiled into the client. It currently
points at public MQTT brokers (HiveMQ, EMQX, Eclipse Mosquitto test
broker) because no public `oc-relay` instance is deployed yet. Users can
add their own relays with:

```bash
oc relays --add https://relay.example
oc relays --check
```

## Plain list

```json
{
  "version": 1,
  "relays": [
    { "url": "https://relay.example", "note": "optional note" }
  ]
}
```

Every URL must parse. Accepted schemes: `https://`/`wss://` (WebSocket
relay), `mqtts://`/`mqtt://` (MQTT over WebSocket) and `mqtttls://`
(MQTT over native TLS).

## Built-in brokers (default.json)

| URL | Platform | Transport |
|---|---|---|
| `mqtts://broker.hivemq.com:8884/mqtt` | HiveMQ public broker | WSS |
| `mqtttls://broker.hivemq.com:8883` | HiveMQ public broker | native TLS |
| `mqtts://broker.emqx.io:8084/mqtt` | EMQX public broker | WSS |
| `mqtttls://broker.emqx.io:8883` | EMQX public broker | native TLS |
| `mqtts://test.mosquitto.org:8081/` | Eclipse Mosquitto test broker | WSS |

Caveats, honestly:

- These are **public demo/test brokers**, shared with everyone. They are
  intended for testing, may be slow, rate-limited, restarted without
  notice, or shut down. Nothing important may rely on them.
- The Mosquitto test broker's WebSocket listener is intermittently
  unavailable (the maintainer says so explicitly). The pool marks dead
  relays automatically, so a dead entry costs nothing but a failed
  health check.
- Brokers see topics (`openchat/v1/<mailbox hex>`), client IPs, timing
  and payload sizes — never message content (end-to-end encrypted) or
  sender identities (sealed sender). Still, text traffic is tiny by
  design (one small frame per message).
- For production use, run your own `oc-relay` or MQTT broker and add it
  with `oc relays --add`. Self-hosted relays are the long-term plan;
  public demo brokers are a bootstrap, not infrastructure.

Existing clients keep the relay list in their encrypted state: after
updating the client, re-run `oc init` in a new home or add the URLs
above manually with `oc relays --add`.

## Signed manifest

Remote updates use a signed, expiring manifest:

```json
{
  "version": 1,
  "issued_at": 1760000000,
  "expires_at": 1762592000,
  "relays": [
    { "url": "https://relay.example", "note": "optional note" }
  ],
  "signature": "<hex Ed25519 signature>"
}
```

The signature covers:

```
"openchat/relay-manifest/v1" || canonical_json({
  "version": ..., "issued_at": ..., "expires_at": ..., "relays": [...]
})
```

`canonical_json` is the compact `serde_json` encoding of `ManifestBody`, in the
field order shown above (the same order as the Rust struct). The signature must
be a 64-byte Ed25519 signature in hex, made by the project key.

A client accepts a manifest only if all of the following hold:

1. the signature verifies against the embedded project public key;
2. `expires_at` is zero or in the future;
3. every relay URL parses.

The manifest is fetched from several independent sources (HTTPS + IPFS). A
failed source or an invalid signature never removes locally configured relays.
