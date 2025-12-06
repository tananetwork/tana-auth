//! Tana Authentication Library
//!
//! JWT creation and validation using Ed25519 signatures.
//! Supports both native Rust and WebAssembly compilation.
//!
//! ## Key Features
//!
//! - User-signed JWTs (not server-signed)
//! - Ed25519 signature verification
//! - Compatible with existing Tana key format (ed25519_ prefix)
//! - WASM support for TypeScript/Bun usage
//!
//! ## Usage
//!
//! ```rust
//! use tana_auth::{create_jwt, verify_jwt};
//!
//! // Create JWT signed by user's private key
//! let jwt = create_jwt(
//!     "ed25519_abc123...",  // private key
//!     "@alice",              // username
//!     90                     // days until expiration
//! ).unwrap();
//!
//! // Verify JWT against user's public key
//! let claims = verify_jwt(&jwt, "ed25519_def456...").unwrap();
//! ```

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// JWT claims for Tana authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (username)
    pub sub: String,
    /// Network identifier (e.g., 'testnet.tana.network', 'mainnet.tana.network')
    pub net: String,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration (Unix timestamp)
    pub exp: i64,
    /// Issuer (always self-signed)
    pub iss: String,
}

/// JWT validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtValidation {
    pub valid: bool,
    pub username: Option<String>,
    pub network: Option<String>,
    pub issued_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub error: Option<String>,
}

/// Create a JWT signed with user's Ed25519 private key
///
/// # Arguments
///
/// * `private_key_hex` - Private key in hex format (with or without 'ed25519_' prefix)
/// * `username` - Username to encode in JWT (subject claim)
/// * `network` - Network identifier (e.g., 'testnet.tana.network', 'mainnet.tana.network')
/// * `expiry_days` - Number of days until JWT expires (typically 90)
///
/// # Returns
///
/// JWT string in format: `{header}.{payload}.{signature}`
///
/// # Example
///
/// ```rust
/// let jwt = tana_auth::create_jwt(
///     "ed25519_a1b2c3...",
///     "@alice",
///     "testnet.tana.network",
///     90
/// ).unwrap();
/// ```
#[wasm_bindgen]
pub fn create_jwt(
    private_key_hex: &str,
    username: &str,
    network: &str,
    expiry_days: u32,
) -> Result<String, JsValue> {
    create_jwt_impl(private_key_hex, username, network, expiry_days)
        .map_err(|e| JsValue::from_str(&e))
}

/// Verify a JWT signature against user's Ed25519 public key
///
/// # Arguments
///
/// * `jwt` - JWT string to verify
/// * `public_key_hex` - Public key in hex format (with or without 'ed25519_' prefix)
///
/// # Returns
///
/// JwtValidation object with validation result and claims
///
/// # Example
///
/// ```rust
/// let result = tana_auth::verify_jwt(&jwt, "ed25519_d4e5f6...").unwrap();
/// if result.valid {
///     println!("JWT valid for user: {}", result.username.unwrap());
/// }
/// ```
#[wasm_bindgen]
pub fn verify_jwt(jwt: &str, public_key_hex: &str) -> Result<JsValue, JsValue> {
    let result = verify_jwt_impl(jwt, public_key_hex);
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Internal implementation of JWT creation
fn create_jwt_impl(
    private_key_hex: &str,
    username: &str,
    network: &str,
    expiry_days: u32,
) -> Result<String, String> {
    // Remove 'ed25519_' prefix if present
    let clean_key = if private_key_hex.starts_with("ed25519_") {
        &private_key_hex[8..]
    } else {
        private_key_hex
    };

    // Decode private key
    let key_bytes = hex::decode(clean_key)
        .map_err(|_| "Invalid private key hex format".to_string())?;

    if key_bytes.len() != 32 {
        return Err("Invalid private key length (expected 32 bytes)".to_string());
    }

    let signing_key = SigningKey::from_bytes(&key_bytes.try_into().unwrap());

    // Create JWT claims
    let now = current_timestamp();
    let expiry = now + (expiry_days as i64 * 86400); // days to seconds

    let claims = JwtClaims {
        sub: username.to_string(),
        net: network.to_string(),
        iat: now,
        exp: expiry,
        iss: "self".to_string(),
    };

    // Create JWT header (always Ed25519)
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT"
    });

    // Encode header and payload
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());

    // Create signature input: {header}.{payload}
    let signature_input = format!("{}.{}", header_b64, payload_b64);

    // Hash the input with SHA-256 (same as transaction signing)
    let mut hasher = Sha256::new();
    hasher.update(signature_input.as_bytes());
    let message_hash = hasher.finalize();

    // Sign with Ed25519
    let signature = signing_key.sign(&message_hash);

    // Encode signature
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    // Return complete JWT
    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

/// Internal implementation of JWT verification
fn verify_jwt_impl(jwt: &str, public_key_hex: &str) -> JwtValidation {
    // Split JWT into parts
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return JwtValidation {
            valid: false,
            username: None,
            network: None,
            issued_at: None,
            expires_at: None,
            error: Some("Invalid JWT format (expected 3 parts)".to_string()),
        };
    }

    let (header_b64, payload_b64, signature_b64) = (parts[0], parts[1], parts[2]);

    // Decode and parse payload
    let payload_bytes = match URL_SAFE_NO_PAD.decode(payload_b64) {
        Ok(b) => b,
        Err(_) => {
            return JwtValidation {
                valid: false,
                username: None,
                network: None,
                issued_at: None,
                expires_at: None,
                error: Some("Invalid base64 in payload".to_string()),
            };
        }
    };

    let claims: JwtClaims = match serde_json::from_slice(&payload_bytes) {
        Ok(c) => c,
        Err(_) => {
            return JwtValidation {
                valid: false,
                username: None,
                network: None,
                issued_at: None,
                expires_at: None,
                error: Some("Invalid JSON in payload".to_string()),
            };
        }
    };

    // Check expiration
    let now = current_timestamp();
    if now > claims.exp {
        return JwtValidation {
            valid: false,
            username: Some(claims.sub),
            network: Some(claims.net),
            issued_at: Some(claims.iat),
            expires_at: Some(claims.exp),
            error: Some("JWT expired".to_string()),
        };
    }

    // Decode signature
    let signature_bytes = match URL_SAFE_NO_PAD.decode(signature_b64) {
        Ok(b) => b,
        Err(_) => {
            return JwtValidation {
                valid: false,
                username: Some(claims.sub),
                network: Some(claims.net),
                issued_at: Some(claims.iat),
                expires_at: Some(claims.exp),
                error: Some("Invalid base64 in signature".to_string()),
            };
        }
    };

    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(s) => s,
        Err(_) => {
            return JwtValidation {
                valid: false,
                username: Some(claims.sub),
                network: Some(claims.net),
                issued_at: Some(claims.iat),
                expires_at: Some(claims.exp),
                error: Some("Invalid signature format".to_string()),
            };
        }
    };

    // Decode public key
    let clean_key = if public_key_hex.starts_with("ed25519_") {
        &public_key_hex[8..]
    } else {
        public_key_hex
    };

    let key_bytes = match hex::decode(clean_key) {
        Ok(b) => b,
        Err(_) => {
            return JwtValidation {
                valid: false,
                username: Some(claims.sub),
                network: Some(claims.net),
                issued_at: Some(claims.iat),
                expires_at: Some(claims.exp),
                error: Some("Invalid public key hex format".to_string()),
            };
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&key_bytes.try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => {
            return JwtValidation {
                valid: false,
                username: Some(claims.sub),
                network: Some(claims.net),
                issued_at: Some(claims.iat),
                expires_at: Some(claims.exp),
                error: Some("Invalid public key".to_string()),
            };
        }
    };

    // Recreate signature input
    let signature_input = format!("{}.{}", header_b64, payload_b64);

    // Hash with SHA-256
    let mut hasher = Sha256::new();
    hasher.update(signature_input.as_bytes());
    let message_hash = hasher.finalize();

    // Verify signature
    match verifying_key.verify(&message_hash, &signature) {
        Ok(_) => JwtValidation {
            valid: true,
            username: Some(claims.sub),
            network: Some(claims.net),
            issued_at: Some(claims.iat),
            expires_at: Some(claims.exp),
            error: None,
        },
        Err(_) => JwtValidation {
            valid: false,
            username: Some(claims.sub),
            network: Some(claims.net),
            issued_at: Some(claims.iat),
            expires_at: Some(claims.exp),
            error: Some("Signature verification failed".to_string()),
        },
    }
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
}

/// Native Rust API (not exposed to WASM)
impl JwtClaims {
    /// Create claims for a user
    pub fn new(username: &str, network: &str, expiry_days: u32) -> Self {
        let now = current_timestamp();
        let expiry = now + (expiry_days as i64 * 86400);

        Self {
            sub: username.to_string(),
            net: network.to_string(),
            iat: now,
            exp: expiry,
            iss: "self".to_string(),
        }
    }

    /// Check if claims are expired
    pub fn is_expired(&self) -> bool {
        current_timestamp() > self.exp
    }
}

/// Helper module for hex encoding/decoding
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }

        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIVATE_KEY: &str = "ed25519_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const TEST_PUBLIC_KEY: &str = "ed25519_f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2";

    #[test]
    fn test_jwt_creation() {
        let jwt = create_jwt_impl(TEST_PRIVATE_KEY, "@alice", "testnet.tana.network", 90).unwrap();

        // JWT should have 3 parts
        assert_eq!(jwt.split('.').count(), 3);

        // Should be able to decode payload
        let parts: Vec<&str> = jwt.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: JwtClaims = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(claims.sub, "@alice");
        assert_eq!(claims.net, "testnet.tana.network");
        assert_eq!(claims.iss, "self");
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_claims_expiration() {
        let mut claims = JwtClaims::new("@alice", "testnet.tana.network", 90);
        assert!(!claims.is_expired());

        // Manually set to expired
        claims.exp = current_timestamp() - 1;
        assert!(claims.is_expired());
    }

    #[test]
    fn test_hex_decode() {
        let result = hex::decode("a1b2c3").unwrap();
        assert_eq!(result, vec![0xa1, 0xb2, 0xc3]);

        // Invalid hex
        assert!(hex::decode("xyz").is_err());

        // Odd length
        assert!(hex::decode("a1b").is_err());
    }
}
