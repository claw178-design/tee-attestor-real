/**
 * TEE Entrypoint — Starts both services inside the Trusted Execution Environment:
 *
 * 1. Reclaim attestor-core WebSocket server (port 8001)
 *    - Handles zkTLS tunnel connections from gateway proxy
 *    - Sees TLS ciphertext, verifies ZK proofs, signs claims
 *    - K2 mechanism hides API keys — attestor never sees them
 *
 * 2. Custom HTTP API server (port 8080)
 *    - /health, /attestation, /sign, /verify, /pubkey
 *    - Remote attestation (TDX/EigenCompute)
 *    - EIP-712 Ethereum-compatible signing
 *
 * Environment variables:
 *   PRIVATE_KEY              — Reclaim attestor signing key (hex, 0x-prefixed)
 *   TOPRF_SHARE_PRIVATE_KEY  — TOPRF share key (optional, for OPRF operations)
 *   TEE_ATTESTOR_PORT        — HTTP API port (default: 8080)
 *   ATTESTOR_CORE_PORT       — WebSocket port (default: 8001)
 *   DISABLE_BGP_CHECKS       — Set to "1" to skip BGP checks
 */

import { randomBytes, createHash } from 'crypto'
import { existsSync, writeFileSync, mkdirSync } from 'fs'
import { join } from 'path'
import { spawn, execSync } from 'child_process'

const TEE_PORT = parseInt(process.env.TEE_ATTESTOR_PORT || '8080', 10)
const ATTESTOR_CORE_PORT = parseInt(process.env.ATTESTOR_CORE_PORT || '8001', 10)

// ─── Key Generation ─────────────────────────────────────────────────
// Generate a deterministic key pair if none provided.
// In a real TEE deployment, keys should be derived from TEE sealing key.

function ensurePrivateKey(): string {
  if (process.env.PRIVATE_KEY) {
    return process.env.PRIVATE_KEY
  }

  const keyDir = '/app/.tee-keys'
  const keyPath = join(keyDir, 'attestor-core.key')

  if (existsSync(keyPath)) {
    const key = require('fs').readFileSync(keyPath, 'utf-8').trim()
    console.log('[entrypoint] Loaded existing attestor-core key')
    return key
  }

  // Generate new key
  const key = '0x' + randomBytes(32).toString('hex')
  if (!existsSync(keyDir)) mkdirSync(keyDir, { recursive: true })
  writeFileSync(keyPath, key, { mode: 0o600 })
  console.log('[entrypoint] Generated new attestor-core signing key')
  return key
}

// ─── Start Reclaim attestor-core ────────────────────────────────────

async function startAttestorCore(privateKey: string) {
  console.log(`[entrypoint] Starting Reclaim attestor-core on port ${ATTESTOR_CORE_PORT}...`)

  const attestorCorePath = '/app/attestor-core'
  if (!existsSync(attestorCorePath)) {
    console.error('[entrypoint] ERROR: attestor-core not found at /app/attestor-core')
    console.log('[entrypoint] Continuing with HTTP-only mode')
    return null
  }

  const env = {
    ...process.env,
    PRIVATE_KEY: privateKey,
    PORT: String(ATTESTOR_CORE_PORT),
    DISABLE_BGP_CHECKS: '1',
    NODE_ENV: 'production',
  }

  // Start attestor-core as a child process
  const child = spawn('node', [
    '--experimental-strip-types',
    '-e',
    `
    import { setCryptoImplementation } from '@reclaimprotocol/tls'
    import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'
    setCryptoImplementation(webcryptoCrypto)

    const { createServer } = await import('#src/server/index.ts')
    await createServer(${ATTESTOR_CORE_PORT})
    console.log('[attestor-core] WebSocket server ready on port ${ATTESTOR_CORE_PORT}')
    `,
  ], {
    cwd: attestorCorePath,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  child.stdout?.on('data', (data: Buffer) => {
    const lines = data.toString().trim().split('\n')
    for (const line of lines) {
      console.log(`[attestor-core] ${line}`)
    }
  })

  child.stderr?.on('data', (data: Buffer) => {
    const lines = data.toString().trim().split('\n')
    for (const line of lines) {
      console.error(`[attestor-core:err] ${line}`)
    }
  })

  child.on('exit', (code) => {
    console.error(`[attestor-core] Process exited with code ${code}`)
    // Restart after delay
    setTimeout(() => startAttestorCore(privateKey), 5000)
  })

  // Wait for it to be ready
  await new Promise<void>((resolve) => {
    const check = () => {
      try {
        const http = require('http')
        const req = http.get(`http://localhost:${ATTESTOR_CORE_PORT}/attestor-address`, (res: any) => {
          if (res.statusCode === 200) {
            let body = ''
            res.on('data', (d: Buffer) => body += d)
            res.on('end', () => {
              console.log(`[entrypoint] attestor-core ready: ${body}`)
              resolve()
            })
          } else {
            setTimeout(check, 500)
          }
        })
        req.on('error', () => setTimeout(check, 500))
        req.setTimeout(2000, () => { req.destroy(); setTimeout(check, 500) })
      } catch {
        setTimeout(check, 500)
      }
    }
    // Give it a moment to start
    setTimeout(check, 2000)
  })

  return child
}

// ─── Start HTTP TEE Server ──────────────────────────────────────────

async function startHttpServer() {
  console.log(`[entrypoint] Starting HTTP TEE server on port ${TEE_PORT}...`)
  // Dynamic import of compiled JS
  const { startTeeServer } = require('./tee-server')
  startTeeServer(TEE_PORT)
}

// ─── Main ───────────────────────────────────────────────────────────

async function main() {
  console.log('='.repeat(60))
  console.log('[entrypoint] TEE Attestor — zkTLS + HTTP Signing Server')
  console.log(`[entrypoint] HTTP API port: ${TEE_PORT}`)
  console.log(`[entrypoint] WebSocket port: ${ATTESTOR_CORE_PORT}`)
  console.log('='.repeat(60))

  const privateKey = ensurePrivateKey()
  process.env.PRIVATE_KEY = privateKey

  // Derive and log the attestor address
  const keyHash = createHash('sha256').update(privateKey).digest('hex').slice(0, 16)
  console.log(`[entrypoint] Key fingerprint: ${keyHash}`)

  // Start both services
  await Promise.all([
    startAttestorCore(privateKey),
    startHttpServer(),
  ])

  console.log('[entrypoint] All services running.')
}

main().catch((err) => {
  console.error('[entrypoint] Fatal error:', err)
  process.exit(1)
})
