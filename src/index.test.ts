/**
 * Tests for @tananetwork/auth
 */

import { describe, test, expect } from 'bun:test'
import { createJwt, verifyJwt } from './index'
import { generateKeypair } from '@tananetwork/crypto'

describe('JWT Creation and Verification', () => {
  test('should create and verify a valid JWT', async () => {
    // Generate a test keypair
    const { privateKey, publicKey } = await generateKeypair()

    // Create JWT
    const jwt = await createJwt(privateKey, '@alice', 'testnet.tana.network', 90)

    // JWT should have 3 parts
    expect(jwt.split('.').length).toBe(3)

    // Verify JWT
    const result = await verifyJwt(jwt, publicKey)

    expect(result.valid).toBe(true)
    expect(result.username).toBe('@alice')
    expect(result.network).toBe('testnet.tana.network')
    expect(result.error).toBeUndefined()
    expect(result.issued_at).toBeGreaterThan(0)
    expect(result.expires_at).toBeGreaterThan(result.issued_at!)
  })

  test('should reject JWT with wrong public key', async () => {
    const { privateKey } = await generateKeypair()
    const { publicKey: wrongPublicKey } = await generateKeypair()

    // Create JWT with first key
    const jwt = await createJwt(privateKey, '@alice', 'testnet.tana.network', 90)

    // Try to verify with different key
    const result = await verifyJwt(jwt, wrongPublicKey)

    expect(result.valid).toBe(false)
    expect(result.error).toBeDefined()
  })

  test('should reject expired JWT', async () => {
    const { privateKey, publicKey } = await generateKeypair()

    // Create JWT that expires immediately (0 days)
    const jwt = await createJwt(privateKey, '@alice', 'testnet.tana.network', 0)

    // Wait 1 second for it to expire
    await new Promise(resolve => setTimeout(resolve, 1100))

    // Verify should fail
    const result = await verifyJwt(jwt, publicKey)

    expect(result.valid).toBe(false)
    expect(result.error).toContain('expired')
    expect(result.username).toBe('@alice')
    expect(result.network).toBe('testnet.tana.network')
  })

  test('should reject malformed JWT', async () => {
    const { publicKey } = await generateKeypair()

    // Invalid JWT with only 2 parts
    const result1 = await verifyJwt('header.payload', publicKey)
    expect(result1.valid).toBe(false)
    expect(result1.error).toContain('Invalid JWT format')

    // Invalid JWT with 4 parts
    const result2 = await verifyJwt('a.b.c.d', publicKey)
    expect(result2.valid).toBe(false)
    expect(result2.error).toContain('Invalid JWT format')
  })

  test('should handle usernames with special characters', async () => {
    const { privateKey, publicKey } = await generateKeypair()

    const usernames = ['@alice', '@bob-123', '@charlie_dev', '@user.name']

    for (const username of usernames) {
      const jwt = await createJwt(privateKey, username, 'testnet.tana.network', 90)
      const result = await verifyJwt(jwt, publicKey)

      expect(result.valid).toBe(true)
      expect(result.username).toBe(username)
    }
  })

  test('should support different expiry durations', async () => {
    const { privateKey, publicKey } = await generateKeypair()

    const expiryDays = [1, 7, 30, 90, 365]

    for (const days of expiryDays) {
      const jwt = await createJwt(privateKey, '@alice', 'mainnet.tana.network', days)
      const result = await verifyJwt(jwt, publicKey)

      expect(result.valid).toBe(true)

      // Check that expiry is roughly correct (within 1 second tolerance)
      const expectedExpiry = result.issued_at! + (days * 86400)
      const expiryDiff = Math.abs(result.expires_at! - expectedExpiry)
      expect(expiryDiff).toBeLessThan(2)
    }
  })

  test('should work with keys that have ed25519_ prefix', async () => {
    const { privateKey, publicKey } = await generateKeypair()

    // Keys from generateKeypair already have ed25519_ prefix
    expect(privateKey).toStartWith('ed25519_')
    expect(publicKey).toStartWith('ed25519_')

    const jwt = await createJwt(privateKey, '@alice', 'localhost:8080', 90)
    const result = await verifyJwt(jwt, publicKey)

    expect(result.valid).toBe(true)
    expect(result.network).toBe('localhost:8080')
  })

  test('should work with keys without prefix', async () => {
    const { privateKey, publicKey } = await generateKeypair()

    // Strip prefixes
    const privateKeyNoPrefix = privateKey.substring(8)
    const publicKeyNoPrefix = publicKey.substring(8)

    const jwt = await createJwt(privateKeyNoPrefix, '@alice', 'testnet.tana.network', 90)
    const result = await verifyJwt(jwt, publicKeyNoPrefix)

    expect(result.valid).toBe(true)
  })

  test('should support different network identifiers', async () => {
    const { privateKey, publicKey } = await generateKeypair()

    const networks = [
      'testnet.tana.network',
      'mainnet.tana.network',
      'localhost:8080',
      'dev.local',
      '192.168.1.100:8501'
    ]

    for (const network of networks) {
      const jwt = await createJwt(privateKey, '@alice', network, 90)
      const result = await verifyJwt(jwt, publicKey)

      expect(result.valid).toBe(true)
      expect(result.network).toBe(network)
    }
  })
})
