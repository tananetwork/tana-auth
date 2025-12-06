/**
 * @tananetwork/auth
 *
 * JWT authentication utilities for Tana using Ed25519 signatures
 *
 * Unlike traditional JWTs signed by servers, Tana JWTs are signed by users
 * with their own private keys and verified against public keys from the blockchain.
 */

import { signMessage, verifySignature, sha256Hex } from '@tananetwork/crypto'

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/**
 * JWT claims for Tana authentication
 */
export interface JwtClaims {
  /** Subject (username) */
  sub: string
  /** Network identifier (e.g., 'testnet.tana.network', 'mainnet.tana.network', 'localhost:8080') */
  net: string
  /** Issued at (Unix timestamp in seconds) */
  iat: number
  /** Expiration (Unix timestamp in seconds) */
  exp: number
  /** Issuer (always 'self' for user-signed JWTs) */
  iss: string
}

/**
 * JWT validation result
 */
export interface JwtValidation {
  /** Whether the JWT is valid */
  valid: boolean
  /** Username if valid */
  username?: string
  /** Network identifier if valid */
  network?: string
  /** Issued at timestamp if valid */
  issued_at?: number
  /** Expiration timestamp if valid */
  expires_at?: number
  /** Error message if invalid */
  error?: string
}

// ============================================================================
// JWT CREATION
// ============================================================================

/**
 * Create a JWT signed with user's Ed25519 private key
 *
 * @param privateKey - Ed25519 private key (with or without 'ed25519_' prefix)
 * @param username - Username to encode in JWT (subject claim)
 * @param network - Network identifier (e.g., 'testnet.tana.network', 'mainnet.tana.network')
 * @param expiryDays - Number of days until JWT expires (typically 90)
 * @returns JWT string in format: {header}.{payload}.{signature}
 *
 * @example
 * ```typescript
 * const jwt = await createJwt(
 *   "ed25519_a1b2c3...",
 *   "@alice",
 *   "testnet.tana.network",
 *   90
 * )
 * ```
 */
export async function createJwt(
  privateKey: string,
  username: string,
  network: string,
  expiryDays: number
): Promise<string> {
  // Create JWT claims
  const now = Math.floor(Date.now() / 1000) // Unix timestamp in seconds
  const expiry = now + (expiryDays * 86400) // days to seconds

  const claims: JwtClaims = {
    sub: username,
    net: network,
    iat: now,
    exp: expiry,
    iss: 'self'
  }

  // Create JWT header (always EdDSA for Ed25519)
  const header = {
    alg: 'EdDSA',
    typ: 'JWT'
  }

  // Encode header and payload as base64url
  const headerB64 = base64UrlEncode(JSON.stringify(header))
  const payloadB64 = base64UrlEncode(JSON.stringify(claims))

  // Create signature input: {header}.{payload}
  const signatureInput = `${headerB64}.${payloadB64}`

  // Sign with user's private key (uses SHA-256 hash internally)
  const signature = await signMessage(signatureInput, privateKey)

  // Extract just the signature hex (remove 'ed25519_sig_' prefix)
  const signatureHex = signature.startsWith('ed25519_sig_')
    ? signature.substring(12)
    : signature

  // Encode signature as base64url
  const signatureB64 = base64UrlEncode(hexToBytes(signatureHex))

  // Return complete JWT
  return `${headerB64}.${payloadB64}.${signatureB64}`
}

// ============================================================================
// JWT VERIFICATION
// ============================================================================

/**
 * Verify a JWT signature against user's Ed25519 public key
 *
 * @param jwt - JWT string to verify
 * @param publicKey - Ed25519 public key (with or without 'ed25519_' prefix)
 * @returns JwtValidation object with validation result and claims
 *
 * @example
 * ```typescript
 * const result = await verifyJwt(jwt, "ed25519_d4e5f6...")
 *
 * if (result.valid) {
 *   console.log(`JWT valid for user: ${result.username}`)
 *   console.log(`Expires: ${new Date(result.expires_at! * 1000)}`)
 * } else {
 *   console.error(`JWT invalid: ${result.error}`)
 * }
 * ```
 */
export async function verifyJwt(
  jwt: string,
  publicKey: string
): Promise<JwtValidation> {
  try {
    // Split JWT into parts
    const parts = jwt.split('.')
    if (parts.length !== 3) {
      return {
        valid: false,
        error: 'Invalid JWT format (expected 3 parts)'
      }
    }

    const [headerB64, payloadB64, signatureB64] = parts

    // Decode and parse payload
    let claims: JwtClaims
    try {
      const payloadJson = base64UrlDecode(payloadB64)
      claims = JSON.parse(payloadJson)
    } catch {
      return {
        valid: false,
        error: 'Invalid JWT payload'
      }
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000)
    if (now > claims.exp) {
      return {
        valid: false,
        username: claims.sub,
        network: claims.net,
        issued_at: claims.iat,
        expires_at: claims.exp,
        error: 'JWT expired'
      }
    }

    // Recreate signature input
    const signatureInput = `${headerB64}.${payloadB64}`

    // Decode signature from base64url
    const signatureBytes = base64UrlDecodeToBytes(signatureB64)
    const signatureHex = bytesToHex(signatureBytes)

    // Add ed25519_sig_ prefix for crypto library
    const signatureWithPrefix = `ed25519_sig_${signatureHex}`

    // Verify signature using crypto library
    const verificationResult = await verifySignature(
      signatureInput,
      signatureWithPrefix,
      publicKey
    )

    if (!verificationResult.valid) {
      return {
        valid: false,
        username: claims.sub,
        network: claims.net,
        issued_at: claims.iat,
        expires_at: claims.exp,
        error: verificationResult.error || 'Signature verification failed'
      }
    }

    // JWT is valid
    return {
      valid: true,
      username: claims.sub,
      network: claims.net,
      issued_at: claims.iat,
      expires_at: claims.exp
    }

  } catch (error: any) {
    return {
      valid: false,
      error: `Unexpected error: ${error.message}`
    }
  }
}

// ============================================================================
// BASE64URL ENCODING (JWT standard)
// ============================================================================

/**
 * Encode a string as base64url (JWT standard)
 *
 * Base64url is like base64 but URL-safe:
 * - Uses '-' instead of '+'
 * - Uses '_' instead of '/'
 * - Omits padding '='
 */
function base64UrlEncode(data: string | Uint8Array): string {
  // Convert to bytes if string
  const bytes = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : data

  // Encode as base64
  const base64 = btoa(String.fromCharCode(...bytes))

  // Convert to base64url
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Decode a base64url string to UTF-8 string
 */
function base64UrlDecode(base64url: string): string {
  // Convert base64url to base64
  let base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/')

  // Add padding if needed
  while (base64.length % 4 !== 0) {
    base64 += '='
  }

  // Decode base64 to bytes
  const binaryString = atob(base64)
  const bytes = new Uint8Array(binaryString.length)
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i)
  }

  // Convert bytes to UTF-8 string
  return new TextDecoder().decode(bytes)
}

/**
 * Decode a base64url string to bytes
 */
function base64UrlDecodeToBytes(base64url: string): Uint8Array {
  // Convert base64url to base64
  let base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/')

  // Add padding if needed
  while (base64.length % 4 !== 0) {
    base64 += '='
  }

  // Decode base64 to bytes
  const binaryString = atob(base64)
  const bytes = new Uint8Array(binaryString.length)
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i)
  }

  return bytes
}

// ============================================================================
// HEX UTILITIES
// ============================================================================

/**
 * Convert hex string to bytes
 */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length')
  }

  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}
