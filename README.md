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
      exception-handler:
        enabled: true
      vault:
        enabled: true
        addr: ${VAULT_ADDR:http://127.0.0.1:8200}
        auth-method: ${VAULT_AUTH_METHOD:TOKEN}
        token: ${VAULT_TOKEN:root}
        secret-path: ${VAULT_SECRET_PATH:secret/data/sensitive-transport-crypto/ciam}
        key-alias: ${VAULT_KEY_ALIAS:ciam}
        validity-millis: ${VAULT_VALIDITY_MILLIS:60000}
        grace-period-millis: ${VAULT_GRACE_PERIOD_MILLIS:30000}
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
- `keyAlias` and `secretPath` should be isolated per service or team.
- Key versions are tracked by `keyId` (for example, `ciam:1`, `ciam:2`).
- Old keys remain valid during a configured grace period to handle rolling deployments.

This behavior is described in more depth in `docs/vault.md` and `docs/sensitive-transport-crypto-multi-team-guidelines.md`.

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

- `docs/vault.md` — Vault key lifecycle and rotation design
- `docs/sensitive-transport-crypto-multi-team-guidelines.md` — ownership and multi-team guidance
