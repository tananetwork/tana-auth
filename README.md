# tana-auth

Authentication and JWT utilities for Tana with Ed25519 signatures.

**Status:** ✅ TypeScript implementation complete (8/8 tests passing) | ⚙️ Rust implementation ready for WASM compilation

## Features

- **User-signed JWTs** - Unlike traditional JWTs signed by servers, Tana JWTs are signed by users with their private keys
- **Ed25519 signatures** - Same crypto as Tana transactions, compatible with existing key infrastructure
- **Blockchain verification** - JWTs are verified against public keys stored on the blockchain (trustless)
- **Dual implementation** - Available for both Rust (native) and TypeScript/Bun (WASM)

## Architecture

Traditional JWTs use server secrets (HS256) or server keypairs (RS256). Tana uses a different model:

```
┌─────────────┐                    ┌──────────────┐
│   User      │                    │  Blockchain  │
│             │                    │   (Ledger)   │
│ Private Key │──┐                 │              │
│ Public Key  │  │                 │  Public Key  │
└─────────────┘  │                 └──────────────┘
                 │                        ▲
                 │ Sign JWT               │ Verify
                 │ with private key       │ against public key
                 ▼                        │
        ┌────────────────┐                │
        │      JWT       │────────────────┘
        │  (self-signed) │
        └────────────────┘
```

This creates a git-like trust model where:
- Users sign their own credentials
- The blockchain is the source of truth for identity
- No central authority can forge JWTs

## Installation

### Rust

```toml
[dependencies]
tana-auth = "0.1"
```

### TypeScript/Bun

```bash
npm install @tananetwork/auth
# or
bun add @tananetwork/auth
```

## Usage

### TypeScript/Bun

```typescript
import { create_jwt, verify_jwt } from '@tananetwork/auth'

// Create JWT signed by user's private key
const jwt = create_jwt(
  "ed25519_a1b2c3...",  // user's private key
  "@alice",              // username
  90                     // days until expiration
)

// Verify JWT against user's public key from blockchain
const result = verify_jwt(jwt, "ed25519_d4e5f6...")

if (result.valid) {
  console.log(`JWT valid for user: ${result.username}`)
  console.log(`Expires: ${new Date(result.expires_at * 1000)}`)
} else {
  console.error(`JWT invalid: ${result.error}`)
}
```

### Rust

```rust
use tana_auth::{create_jwt, verify_jwt};

// Create JWT signed by user's private key
let jwt = create_jwt(
    "ed25519_a1b2c3...",
    "@alice",
    90
)?;

// Verify JWT
let result = verify_jwt(&jwt, "ed25519_d4e5f6...")?;

if result.valid {
    println!("JWT valid for user: {}", result.username.unwrap());
} else {
    println!("JWT invalid: {}", result.error.unwrap());
}
```

## Integration with Tana CLI

The Tana CLI manages user keys in `~/.config/tana/users/`:

```bash
# Show current user
tana whoami

# Switch active user
tana use @alice

# Generate JWT for git authentication
tana auth login   # Creates JWT, saves to ~/.config/tana/jwt
```

The CLI reads the active user's private key from config and creates a JWT that lasts 90 days. This JWT is then used for:
- Git push/pull authentication
- API access
- Build triggers
- Other automated workflows

## JWT Format

Tana JWTs follow standard JWT format with EdDSA algorithm:

```
{header}.{payload}.{signature}
```

**Header:**
```json
{
  "alg": "EdDSA",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": "@alice",      // username
  "iat": 1234567890,    // issued at (Unix timestamp)
  "exp": 1242343890,    // expiration (Unix timestamp)
  "iss": "self"         // always self-signed
}
```

**Signature:**
- Ed25519 signature of SHA-256 hash of `{header}.{payload}`
- Signed with user's private key
- Verified against user's public key from blockchain

## Building from Source

### Build Rust library

```bash
cargo build --release
```

### Build WASM for Node.js/Bun

```bash
npm run build
# or
bun run build
```

### Build WASM for browsers

```bash
npm run build:web
# or
bun run build:web
```

### Run tests

```bash
# Rust tests
cargo test

# WASM tests
bun run test
```

## Publishing

### Publish Rust crate

```bash
cargo publish
```

### Publish NPM package

```bash
npm run build
npm publish
```

## License

Dual-licensed under MIT OR Apache-2.0
