# EncryptPii

EncryptPii is a Spring Boot based sensitive transport crypto framework for protecting PII and other sensitive data in transit between clients and servers.

It uses a layered design:

- RSA-2048 with OAEP for client-to-server session-key transport
- AES-256-GCM for payload encryption
- per-request session keys generated at runtime
- automatic request/response encryption via Spring MVC advices
- optional HashiCorp Vault integration for key lifecycle and rotation

This project is designed to be used as a reusable starter library (`sdk`), together with demo server/client applications to show end-to-end behavior.

## Project structure

```text
EncryptPii/
├── sdk/                             # reusable Spring Boot starter / core library
│   ├── src/main/java/com/ikea/crypto/stc/
│   │   ├── annotation/              # @DecryptRequest, @EncryptResponse
│   │   ├── config/                  # auto-config and properties
│   │   ├── crypto/                  # AES / session key logic
│   │   ├── exception/               # crypto error model
│   │   ├── key/                     # key ring and server logic
│   │   ├── model/                   # payload and protocol models
│   │   ├── session/                 # request-scoped crypto context
│   │   ├── vault/                   # Vault integration
│   │   ├── web/advice/              # RequestDecryptAdvice / ResponseEncryptAdvice
│   │   └── web/endpoint/            # public key endpoint
│   └── build.gradle
├── server/                          # demo server application
│   ├── src/main/java/com/ikea/crypto/server/
│   └── src/main/resources/application.yml
├── client/                          # demo client application
│   ├── src/main/java/com/ikea/crypto/client/
│   └── src/main/resources/application.yml
├── docs/                           # design and operational references
│   ├── sensitive-transport-crypto-multi-team-guidelines.md
│   └── vault.md
├── build.gradle
├── settings.gradle
├── gradlew
├── gradlew.bat
├── .gitignore
└── README.md
```

## Core design

1. No hardcoded symmetric keys.
2. A new AES-256 session key is generated for each request.
3. The session key is encrypted with the server RSA public key before transport.
4. The request payload is encrypted with AES-GCM and includes an auth tag.
5. The server decrypts the payload automatically based on annotations and request-scoped context.
6. Response encryption is handled similarly when `@EncryptResponse` is used.

Encrypted requests transport key metadata only in `X-STC-Key-Id` and
`X-STC-Session-Key`. Their JSON body contains only `ivBase64` and
`encryptedDataBase64`. A stale key version returns HTTP 400 with
`code: "KEY_EXPIRED"` and the replacement public key in `data`; the Java demo
client installs that key and retries once with newly generated session material.

The SDK only throws typed crypto exceptions; it does not register a global
exception handler or define HTTP error response models. Applications own status
codes and error bodies. The demo Server's `CustomExceptionHandler` maps crypto
exceptions, including the `KEY_EXPIRED` replacement-key response. It sets
`X-STC-Encrypted: false` on crypto errors to keep them plaintext; business error
responses can still follow the endpoint's response-encryption policy.

## Supported security patterns

The demo application shows three common modes:

- Bidirectional encryption: both request and response are encrypted.
- Request-only encryption: the client encrypts the request body, while the server responds in plaintext.
- Response-only encryption: the server encrypts its response using the session key sent by the client.

## Encryption flow

```text
Client                               Server
  |                                    |
  |-- GET /crypto/server/public-key -->|
  |<-- RSA public key + keyId ---------|
  |                                    |
  | generate AES session key + IV      |
  | encrypt session key with RSA        |
  | encrypt payload with AES-GCM        |
  |-- POST encrypted payload ---------->|
  |                                    |-- decrypt with RSA private key
  |                                    |-- decrypt AES payload
  |                                    |-- run business logic
  |                                    |-- encrypt response if required
  |<-- encrypted response --------------|
  | decrypt response with session key   |
```

## Endpoints in the demo project

The server-side SDK automatically exposes the public key endpoint under the configured base path.

```text
GET  /crypto/server/public-key
GET  /crypto/server/public-key/{keyAlias}
POST /crypto/server/bidirectional
POST /crypto/server/request-only
POST /crypto/server/response-only
```

The default server configuration uses port 9090. The client sample points to `http://localhost:9090` and runs on port 8080.

## Dependency usage

For local development, the demo apps depend on the project module directly:

```groovy
implementation project(':sdk')
```

For external usage, the SDK is published as a starter artifact:

```groovy
implementation 'com.ikea.crypto:sensitive-transport-crypto-spring-boot-starter:1.0-SNAPSHOT'
```

Maven:

```xml
<dependency>
    <groupId>com.ikea.crypto</groupId>
    <artifactId>sensitive-transport-crypto-spring-boot-starter</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

## Main configuration

Server example (`server/src/main/resources/application.yml`):

```yaml
server:
  port: 9090

sensitive:
  transport:
    crypto:
      enabled: true
      endpoint:
        enabled: true
        base-path: /crypto/server
      key-lifecycle:
        validity-millis: ${CRYPTO_KEY_VALIDITY_MILLIS:2592000000}
        grace-period-millis: ${CRYPTO_KEY_GRACE_PERIOD_MILLIS:3600000}
        rotation-before-expiry-millis: ${CRYPTO_ROTATION_BEFORE_EXPIRY_MILLIS:259200000}
      vault:
        enabled: true
        addr: ${VAULT_ADDR:http://127.0.0.1:8200}
        auth-method: ${VAULT_AUTH_METHOD:TOKEN}
        token: ${VAULT_TOKEN:root}
        secret-path: ${VAULT_SECRET_PATH:secret/data/sensitive-transport-crypto/ciam}
        key-alias: ${VAULT_KEY_ALIAS:ciam}
```

Client example (`client/src/main/resources/application.yml`):

```yaml
server:
  port: 8080

crypto:
  server:
    base-url: http://localhost:9090
    endpoints:
      public-key: /crypto/server/public-key
      bidirectional: /crypto/server/bidirectional
      request-only: /crypto/server/request-only
      response-only: /crypto/server/response-only
```

## Vault integration

The SDK can integrate with HashiCorp Vault for key storage, rotation, and multi-version grace periods. Key material is managed as versioned secrets, while the local JVM keeps an in-memory key ring for fast decryption.

Relevant notes:

- `sensitive.transport.crypto.vault.enabled` switches Vault integration on/off.
- Public-key responses include `refreshAtEpochMillis`; clients should use this server-provided timestamp instead of configuring a separate refresh margin.
- `sensitive.transport.crypto.auto-rotate` controls automatic key rotation (defaults to `true`). Set it to `false` to require explicit rotation; the default public-key endpoint returns `KeyNotAvailableException` while the active key is expired. Initial Vault key creation is still controlled separately by `auto-bootstrap`.
- `sensitive.transport.crypto.key-lifecycle` groups key validity, grace period, and proactive-rotation window regardless of whether keys are stored in Vault. Configuration must satisfy `grace-period-millis < rotation-before-expiry-millis < validity-millis`. On each public-key request, an enabled SDK rotates when the active key is within this window. Because this is request-driven, a key is not proactively rotated while the service receives no public-key requests; rotation failures are emitted as error logs (`Automatic RSA key rotation failed`) for monitoring and alerting.
- Key validity and CAS retry interval/count must be positive; grace period, rotation window and CAS backoff must be non-negative. Invalid individual values and violations of the timing relationship prevent startup.
- `keyAlias` and `secretPath` should be isolated per service or team.
- Key versions are tracked by `keyId` (for example, `ciam:1`, `ciam:2`).
- After a key is replaced, the old key remains valid for decryption for the configured grace period, measured from the replacement key's creation time.

This behavior is described in more depth in `vault/vault.md` and `vault/sensitive-transport-crypto-multi-team-guidelines.md`.

## Quick start

Prerequisites:

- JDK 17+
- Gradle wrapper included in the repo

Run tests:

```bash
./gradlew test
```

Start the server demo:

```bash
./gradlew server:bootRun
```

Start the client demo in another shell:

```bash
./gradlew client:bootRun
```

Then call the client APIs, which are exposed under `/crypto/client`.

## Notes

- The SDK is intentionally designed to be transparent to application code: `@DecryptRequest` and `@EncryptResponse` manage the crypto flow.
- Failed decryption or tampering leads to typed crypto exceptions instead of exposing raw security details.
- In production, prefer isolating Vault paths and key aliases by application/service identity instead of sharing a single key across teams.

## Related docs

- `vault/vault.md` — Vault key lifecycle and rotation design
- `vault/sensitive-transport-crypto-multi-team-guidelines.md` — ownership and multi-team guidance
