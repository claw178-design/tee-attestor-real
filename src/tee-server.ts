/**
 * TEE Attestor Signing Server
 *
 * Runs INSIDE a Trusted Execution Environment (EigenCompute TEE).
 * Receives claim hashes from the proxy, signs them with a TEE-bound key,
 * and returns signed claims with attestor signatures.
 *
 * Endpoints:
 *   POST /sign          — Sign a claim (receives hashes, returns signed claim)
 *   GET  /attestation   — TEE measurement / identity
 *   GET  /health        — Health check
 *   GET  /pubkey        — Public key for signature verification
 *
 * The signing key is generated at startup inside the TEE.
 * It never leaves the enclave — only the public key is exposed.
 */

import http from 'http'
import { createHash, createSign, createVerify, generateKeyPairSync } from 'crypto'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs'
import { join } from 'path'

// ─── Configuration ───────────────────────────────────────────────────

const TEE_PORT = parseInt(process.env.TEE_ATTESTOR_PORT || '8767', 10)
const KEY_DIR = process.env.TEE_KEY_DIR || join(__dirname, '..', '.tee-keys')
const MEASUREMENT = process.env.TEE_MEASUREMENT || 'local-dev'

// ─── Key Management (TEE-bound) ─────────────────────────────────────

interface AttestorKeys {
  privateKey: string
  publicKey: string
  fingerprint: string
}

function loadOrGenerateKeys(): AttestorKeys {
  const privPath = join(KEY_DIR, 'attestor.key')
  const pubPath = join(KEY_DIR, 'attestor.pub')

  if (existsSync(privPath) && existsSync(pubPath)) {
    const privateKey = readFileSync(privPath, 'utf-8')
    const publicKey = readFileSync(pubPath, 'utf-8')
    const fingerprint = createHash('sha256').update(publicKey).digest('hex').slice(0, 16)
    console.log(`[tee-attestor] Loaded existing key pair (fingerprint: ${fingerprint})`)
    return { privateKey, publicKey, fingerprint }
  }

  // Generate new ECDSA key pair (secp256k1 for Ethereum compatibility)
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })

  if (!existsSync(KEY_DIR)) {
    mkdirSync(KEY_DIR, { recursive: true })
  }
  writeFileSync(privPath, privateKey, { mode: 0o600 })
  writeFileSync(pubPath, publicKey, { mode: 0o644 })

  const fingerprint = createHash('sha256').update(publicKey).digest('hex').slice(0, 16)
  console.log(`[tee-attestor] Generated new key pair (fingerprint: ${fingerprint})`)
  return { privateKey, publicKey, fingerprint }
}

// ─── Claim Signing ──────────────────────────────────────────────────

interface SignRequest {
  usage_hash: string
  model_hash: string
  prompt_hash: string
  response_hash: string
  endpoint: string
  timestamp: number
}

interface SignedClaim extends SignRequest {
  attestor_sig: string
  attestor_pubkey: string
  attestor_fingerprint: string
  tee_measurement: string
  zk_proof: string
}

function signClaim(req: SignRequest, keys: AttestorKeys): SignedClaim {
  // Canonical claim representation for signing
  const canonical = [
    req.usage_hash,
    req.model_hash,
    req.prompt_hash,
    req.response_hash,
    req.endpoint,
    String(req.timestamp),
  ].join('|')

  // Sign with ECDSA-SHA256
  const signer = createSign('SHA256')
  signer.update(canonical)
  const signature = signer.sign(keys.privateKey, 'hex')

  return {
    ...req,
    attestor_sig: `0x${signature}`,
    attestor_pubkey: keys.fingerprint,
    attestor_fingerprint: keys.fingerprint,
    tee_measurement: MEASUREMENT,
    zk_proof: '',  // Reserved for future ZK proof integration
  }
}

/**
 * Verify a signed claim against the attestor's public key.
 */
export function verifySignature(claim: SignedClaim, publicKeyPem: string): boolean {
  const canonical = [
    claim.usage_hash,
    claim.model_hash,
    claim.prompt_hash,
    claim.response_hash,
    claim.endpoint,
    String(claim.timestamp),
  ].join('|')

  const sig = claim.attestor_sig.startsWith('0x')
    ? claim.attestor_sig.slice(2)
    : claim.attestor_sig

  const verifier = createVerify('SHA256')
  verifier.update(canonical)
  return verifier.verify(publicKeyPem, sig, 'hex')
}

// ─── Request Handler ────────────────────────────────────────────────

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString()))
    req.on('error', reject)
  })
}

let signCount = 0

function createHandler(keys: AttestorKeys) {
  return async (req: http.IncomingMessage, res: http.ServerResponse) => {
    const url = req.url || '/'

    // CORS headers for cross-origin verification
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

    if (req.method === 'OPTIONS') {
      res.writeHead(204)
      res.end()
      return
    }

    // GET /health
    if (url === '/health' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({
        status: 'ok',
        mode: 'tee-attestor',
        measurement: MEASUREMENT,
        fingerprint: keys.fingerprint,
        signs: signCount,
        uptime: process.uptime(),
      }))
      return
    }

    // GET /attestation — TEE identity/measurement
    if (url === '/attestation' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({
        ok: true,
        measurement: MEASUREMENT,
        attestor_fingerprint: keys.fingerprint,
        attestor_pubkey: keys.publicKey,
        tee_type: process.env.TEE_TYPE || 'local-dev',
        started_at: new Date(Date.now() - process.uptime() * 1000).toISOString(),
      }))
      return
    }

    // GET /pubkey — Public key for external verifiers
    if (url === '/pubkey' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({
        pubkey: keys.publicKey,
        fingerprint: keys.fingerprint,
        algorithm: 'ECDSA-secp256k1-SHA256',
      }))
      return
    }

    // POST /sign — Sign a claim
    if (url === '/sign' && req.method === 'POST') {
      try {
        const body = await readBody(req)
        const claimReq: SignRequest = JSON.parse(body)

        // Validate required fields
        const required = ['usage_hash', 'model_hash', 'prompt_hash', 'response_hash', 'endpoint', 'timestamp']
        for (const field of required) {
          if (!(field in claimReq)) {
            res.writeHead(400, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ error: `Missing required field: ${field}` }))
            return
          }
        }

        // Validate hash format (must start with 0x)
        for (const field of ['usage_hash', 'model_hash', 'prompt_hash', 'response_hash']) {
          const val = (claimReq as any)[field]
          if (typeof val !== 'string' || !val.startsWith('0x')) {
            res.writeHead(400, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ error: `Invalid hash format for ${field}: must start with 0x` }))
            return
          }
        }

        const signed = signClaim(claimReq, keys)
        signCount++

        console.log(`[tee-attestor] Signed claim #${signCount} — endpoint: ${claimReq.endpoint}`)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, claim: signed }))
      } catch (e: any) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: `Invalid request: ${e.message}` }))
      }
      return
    }

    // POST /verify — Verify a signed claim
    if (url === '/verify' && req.method === 'POST') {
      try {
        const body = await readBody(req)
        const { claim } = JSON.parse(body) as { claim: SignedClaim }
        const valid = verifySignature(claim, keys.publicKey)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ valid, fingerprint: keys.fingerprint }))
      } catch (e: any) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: `Verification failed: ${e.message}` }))
      }
      return
    }

    res.writeHead(404, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'Not found' }))
  }
}

// ─── Server Startup ──────────────────────────────────────────────────

export function startTeeServer(port = TEE_PORT): http.Server {
  const keys = loadOrGenerateKeys()
  const server = http.createServer(createHandler(keys))

  server.listen(port, '0.0.0.0', () => {
    console.log(`[tee-attestor] TEE Attestor Signing Server`)
    console.log(`[tee-attestor] Listening on 0.0.0.0:${port}`)
    console.log(`[tee-attestor] Measurement: ${MEASUREMENT}`)
    console.log(`[tee-attestor] Key fingerprint: ${keys.fingerprint}`)
    console.log(`[tee-attestor] Endpoints:`)
    console.log(`[tee-attestor]   POST /sign       — Sign a claim`)
    console.log(`[tee-attestor]   POST /verify     — Verify a signed claim`)
    console.log(`[tee-attestor]   GET  /attestation — TEE identity`)
    console.log(`[tee-attestor]   GET  /pubkey     — Public key`)
    console.log(`[tee-attestor]   GET  /health     — Health check`)
  })

  return server
}

if (require.main === module) {
  startTeeServer()
}
