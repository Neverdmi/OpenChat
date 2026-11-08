# Relay lists and manifests

`default.json` is the relay list compiled into the client. It is intentionally
empty until a public relay is deployed; users can add relays with:

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

Every URL must parse; both `https://` and `wss://` are accepted.

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
