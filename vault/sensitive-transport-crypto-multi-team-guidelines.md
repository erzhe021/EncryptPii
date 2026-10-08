# Sensitive Transport Crypto Multi-Team Guidelines

## Recommended ownership model

- Each service/team should own its own `keyAlias`, Vault path, and rotation lifecycle.
- The starter and client contract can be shared, but cryptographic material should not be shared across teams.
- Use a single SDK/starter version across teams, but keep deployment-time configuration separate.

## Why separate keys

- Limits blast radius if one service is compromised.
- Allows independent rotation without coordinating across all teams.
- Makes access control simpler in Vault by service identity.
- Supports least-privilege access and easier auditing.

## Suggested configuration split

### Shared starter/client

- Shared request/response encryption protocol
- Shared endpoint shapes
- Shared payload models

### Per-service configuration

- `sensitive.transport.crypto.vault.key-alias`
- `sensitive.transport.crypto.vault.secret-path`
- Vault auth method and credentials
- Rotation and grace-period settings

## Vault layout example

```text
secret/data/crypto/service-a
secret/data/crypto/service-b
secret/data/crypto/service-c
```

Each service should only be allowed to read/write its own path.

## Operational guidance

- Rotate keys per service, not globally.
- Keep `public-key` exposure for clients only.
- Do not expose rotate endpoints through the application; use DevOps automation or Vault tooling instead.
- Prefer environment-specific overrides for local, staging, and production.

## When sharing a key may be acceptable

Only if multiple services truly belong to the same trust domain and are treated as one security boundary. Even then, document the exception and keep the sharing explicit.
