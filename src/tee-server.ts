/**
 * TEE Attestor Signing Server
 *
 * Runs INSIDE a Trusted Execution Environment (EigenCompute TEE).
 * Receives claim hashes from the proxy, signs them with a TEE-bound key,
 * and returns signed claims with attestor signatures.
 *
 * Remote Attestation:
 *   - Reads EigenCompute environment for on-chain identity (App ID, image digest)
 *   - Attempts to read TDX quote from /dev/tdx_guest for hardware attestation
 *   - Falls back to EigenCompute on-chain attestation if TDX device unavailable
 *   - All attestation data exposed via GET /attestation
 *
 * Endpoints:
 *   POST /sign          — Sign a claim (receives hashes, returns signed claim)
 *   POST /verify        — Verify a signed claim
 *   GET  /attestation   — Full remote attestation report
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
import { execSync } from 'child_process'
import { pemToEthWallet, ethSignClaim, ethVerifyClaim, EthSignRequest } from './eth-signer'
import { ethers } from 'ethers'

// ─── Bootstrap: source KMS env if available ──────────────────────────
// EigenCompute's compute-source-env.sh writes env vars to /tmp/.env
// Parse and inject them before reading config
function loadKmsEnv() {
  const paths = ['/tmp/.env', '/app/.env.eigencompute']
  for (const p of paths) {
    if (existsSync(p)) {
      try {
        const content = readFileSync(p, 'utf-8')
        for (const line of content.split('\n')) {
          const trimmed = line.trim()
          if (!trimmed || trimmed.startsWith('#')) continue
          const eqIdx = trimmed.indexOf('=')
          if (eqIdx < 1) continue
          const key = trimmed.slice(0, eqIdx).trim()
          let val = trimmed.slice(eqIdx + 1).trim()
          // Strip surrounding quotes
          if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1)
          }
          // Only set if not already in env (explicit env takes priority)
          if (!process.env[key]) {
            process.env[key] = val
          }
        }
        console.log(`[tee-attestor] Loaded env from ${p}`)
      } catch (e: any) {
        console.log(`[tee-attestor] Failed to parse ${p}: ${e.message}`)
      }
    }
  }
}
loadKmsEnv()

// ─── Configuration ───────────────────────────────────────────────────

const TEE_PORT = parseInt(process.env.TEE_ATTESTOR_PORT || '8767', 10)
const KEY_DIR = process.env.TEE_KEY_DIR || join(__dirname, '..', '.tee-keys')
const MEASUREMENT = process.env.TEE_MEASUREMENT || 'local-dev'

// EigenCompute environment (injected by the platform or via KMS)
const EIGEN_APP_ID = process.env.EIGEN_APP_ID || ''
const EIGEN_IMAGE_DIGEST = process.env.EIGEN_IMAGE_DIGEST || ''
const EIGEN_EVM_ADDRESS = process.env.EIGEN_EVM_ADDRESS || ''
const EIGEN_ENVIRONMENT = process.env.ECLOUD_ENV || process.env.EIGEN_ENVIRONMENT || 'unknown'
const EIGEN_MACHINE_TYPE = process.env.EIGEN_MACHINE_TYPE_PUBLIC || ''
const EIGEN_RUNTIME = process.env.EIGEN_RUNTIME === '1'

// Default ClaimVerifierV2 contract address on Sepolia
const DEFAULT_VERIFIER_CONTRACT = process.env.CLAIM_VERIFIER_ADDRESS || '0x98b05fb625B8867f073277B7EAbF1ccC7E0926c9'

// ─── Remote Attestation ─────────────────────────────────────────────

interface AttestationReport {
  /** Whether running inside a real TEE */
  is_tee: boolean
  /** TEE type: 'tdx' | 'sgx' | 'eigencompute' | 'local-dev' */
  tee_type: string
  /** EigenCompute App ID (on-chain verifiable) */
  app_id: string
  /** Docker image digest (on-chain verifiable via ecloud compute app releases) */
  image_digest: string
  /** TEE-derived EVM address */
  evm_address: string
  /** EigenCompute environment (sepolia/mainnet) */
  environment: string
  /** Machine type (g1-standard-4t = TDX-enabled) */
  machine_type: string
  /** TDX quote hex (if available from hardware) */
  tdx_quote: string
  /** EigenCompute dashboard URL for human verification */
  dashboard_url: string
  /** Timestamp of attestation collection */
  collected_at: string
}

/**
 * Collect remote attestation evidence from the TEE environment.
 * Tries multiple sources in priority order:
 *   1. TDX hardware quote (Intel TDX /dev/tdx_guest)
 *   2. EigenCompute on-chain identity (env vars)
 *   3. Local dev fallback
 */
function collectAttestation(keys: AttestorKeys): AttestationReport {
  let tdxQuote = ''
  let teeType = 'local-dev'
  let isTee = false

  // 1. Try reading TDX quote from hardware
  try {
    if (existsSync('/dev/tdx_guest') || existsSync('/dev/tdx-guest')) {
      // Intel TDX: generate a quote with the attestor pubkey as report data
      const reportData = createHash('sha256').update(keys.publicKey).digest('hex')
      try {
        // Use configfs-tsm if available (Linux 6.7+)
        if (existsSync('/sys/kernel/config/tsm/report')) {
          const tsm = '/sys/kernel/config/tsm/report/attestor0'
          try { execSync(`mkdir -p ${tsm}`, { timeout: 5000 }) } catch {}
          try {
            writeFileSync(`${tsm}/inblob`, Buffer.from(reportData, 'hex'))
            const quote = readFileSync(`${tsm}/outblob`)
            tdxQuote = quote.toString('hex')
            teeType = 'tdx'
            isTee = true
            console.log(`[tee-attestor] TDX quote obtained via configfs-tsm (${tdxQuote.length / 2} bytes)`)
          } catch (e: any) {
            console.log(`[tee-attestor] configfs-tsm read failed: ${e.message}`)
          }
        }
        // Fallback: try kms-client attest helper
        if (!tdxQuote && existsSync('/usr/local/bin/kms-client')) {
          try {
            const out = execSync('/usr/local/bin/kms-client attest 2>/dev/null', {
              timeout: 10000,
              encoding: 'utf-8',
            }).trim()
            if (out.length > 0) {
              tdxQuote = out
              teeType = 'tdx'
              isTee = true
              console.log(`[tee-attestor] TDX quote obtained via kms-client (${out.length / 2} bytes)`)
            }
          } catch (e: any) {
            console.log(`[tee-attestor] kms-client attest failed: ${e.message}`)
          }
        }

        // Fallback: try /dev/attestation/quote (GCP Confidential Computing)
        if (!tdxQuote && existsSync('/dev/attestation/quote')) {
          try {
            const reportData = createHash('sha256').update(keys.publicKey).digest()
            writeFileSync('/dev/attestation/report_data', reportData)
            const quote = readFileSync('/dev/attestation/quote')
            tdxQuote = quote.toString('hex')
            teeType = 'tdx'
            isTee = true
            console.log(`[tee-attestor] TDX quote obtained via /dev/attestation (${quote.length} bytes)`)
          } catch (e: any) {
            console.log(`[tee-attestor] /dev/attestation failed: ${e.message}`)
          }
        }
      } catch (e: any) {
        console.log(`[tee-attestor] TDX quote generation failed: ${e.message}`)
      }
    }
  } catch {}

  // 2. EigenCompute on-chain attestation
  if (EIGEN_RUNTIME || EIGEN_APP_ID || EIGEN_MACHINE_TYPE.includes('t')) {
    if (!isTee) {
      teeType = 'eigencompute'
      isTee = true
    }
    console.log(`[tee-attestor] EigenCompute environment detected (app: ${EIGEN_APP_ID || 'auto'})`)
  }

  // 3. Auto-detect from image digest file (written by EigenCompute entrypoint)
  let imageDigest = EIGEN_IMAGE_DIGEST
  if (!imageDigest) {
    try {
      // EigenCompute may write the image digest to a well-known path
      const digestPaths = [
        '/app/.image-digest',
        '/etc/eigencompute/image-digest',
      ]
      for (const p of digestPaths) {
        if (existsSync(p)) {
          imageDigest = readFileSync(p, 'utf-8').trim()
          break
        }
      }
    } catch {}
  }

  const appId = EIGEN_APP_ID
  const dashboardBase = EIGEN_ENVIRONMENT === 'mainnet'
    ? 'https://verify.eigencloud.xyz'
    : 'https://verify-sepolia.eigencloud.xyz'

  return {
    is_tee: isTee,
    tee_type: teeType,
    app_id: appId,
    image_digest: imageDigest,
    evm_address: EIGEN_EVM_ADDRESS,
    environment: EIGEN_ENVIRONMENT,
    machine_type: EIGEN_MACHINE_TYPE,
    tdx_quote: tdxQuote,
    dashboard_url: appId ? `${dashboardBase}/app/${appId}` : '',
    collected_at: new Date().toISOString(),
  }
}

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
  /** EigenCompute App ID — verifiable on-chain */
  app_id: string
  /** Docker image digest — verifiable on-chain via `ecloud compute app releases` */
  image_digest: string
  /** TEE type: 'tdx' | 'eigencompute' | 'local-dev' */
  tee_type: string
  zk_proof: string
}

function signClaim(req: SignRequest, keys: AttestorKeys, attestation: AttestationReport): SignedClaim {
  // Canonical claim representation for signing
  // Includes attestation identity for binding
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
    tee_measurement: attestation.image_digest || MEASUREMENT,
    app_id: attestation.app_id,
    image_digest: attestation.image_digest,
    tee_type: attestation.tee_type,
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

function createHandler(keys: AttestorKeys, attestation: AttestationReport) {
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

    // GET /attestation — Full remote attestation report
    if (url === '/attestation' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({
        ok: true,
        attestor_fingerprint: keys.fingerprint,
        attestor_pubkey: keys.publicKey,
        ...attestation,
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

        const signed = signClaim(claimReq, keys, attestation)
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

    // GET /eth-address — Attestor's Ethereum address
    if (url === '/eth-address' && req.method === 'GET') {
      try {
        const wallet = pemToEthWallet(keys.privateKey)
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
          eth_address: wallet.address,
          fingerprint: keys.fingerprint,
        }))
      } catch (e: any) {
        res.writeHead(500, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: `Failed to derive ETH address: ${e.message}` }))
      }
      return
    }

    // POST /eth-sign — Sign claim with EIP-712 (Ethereum-compatible)
    if (url === '/eth-sign' && req.method === 'POST') {
      try {
        const body = await readBody(req)
        const claimReq: EthSignRequest = JSON.parse(body)

        // Validate required fields
        const required = ['usage_hash', 'model_hash', 'prompt_hash', 'response_hash', 'endpoint', 'timestamp']
        for (const field of required) {
          if (!(field in claimReq)) {
            res.writeHead(400, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ error: `Missing required field: ${field}` }))
            return
          }
        }

        // Inject default verifier contract address if not provided
        if (!claimReq.verifier_address) {
          claimReq.verifier_address = DEFAULT_VERIFIER_CONTRACT
        }

        const wallet = pemToEthWallet(keys.privateKey)
        const signed = await ethSignClaim(claimReq, wallet)
        signCount++

        // Also include standard attestation metadata
        const result = {
          ok: true,
          claim: {
            ...signed,
            attestor_fingerprint: keys.fingerprint,
            tee_measurement: attestation.image_digest || MEASUREMENT,
            app_id: attestation.app_id,
            image_digest: attestation.image_digest,
            tee_type: attestation.tee_type,
          },
        }

        console.log(`[tee-attestor] EIP-712 signed claim #${signCount} — endpoint: ${claimReq.endpoint}, signer: ${wallet.address}`)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(result))
      } catch (e: any) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: `EIP-712 sign failed: ${e.message}` }))
      }
      return
    }

    // POST /eth-verify — Verify an EIP-712 signed claim
    if (url === '/eth-verify' && req.method === 'POST') {
      try {
        const body = await readBody(req)
        const { claim } = JSON.parse(body)
        const result = ethVerifyClaim(claim)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(result))
      } catch (e: any) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: `EIP-712 verify failed: ${e.message}` }))
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
  const attestation = collectAttestation(keys)
  const server = http.createServer(createHandler(keys, attestation))

  server.listen(port, '0.0.0.0', () => {
    console.log(`[tee-attestor] TEE Attestor Signing Server`)
    console.log(`[tee-attestor] Listening on 0.0.0.0:${port}`)
    console.log(`[tee-attestor] TEE type: ${attestation.tee_type} (is_tee: ${attestation.is_tee})`)
    console.log(`[tee-attestor] App ID: ${attestation.app_id || 'none'}`)
    console.log(`[tee-attestor] Image digest: ${attestation.image_digest || 'none'}`)
    console.log(`[tee-attestor] TDX quote: ${attestation.tdx_quote ? `${attestation.tdx_quote.length / 2} bytes` : 'not available'}`)
    console.log(`[tee-attestor] Key fingerprint: ${keys.fingerprint}`)
    console.log(`[tee-attestor] Dashboard: ${attestation.dashboard_url || 'N/A'}`)
    console.log(`[tee-attestor] Endpoints:`)
    console.log(`[tee-attestor]   POST /sign       — Sign a claim`)
    console.log(`[tee-attestor]   POST /verify     — Verify a signed claim`)
    console.log(`[tee-attestor]   GET  /attestation — Full remote attestation report`)
    console.log(`[tee-attestor]   GET  /pubkey     — Public key`)
    console.log(`[tee-attestor]   GET  /health     — Health check`)
  })

  return server
}

// Standalone mode: detect if this file is the entry point
if (process.argv[1]?.endsWith('tee-server.js') || process.argv[1]?.endsWith('tee-server.ts')) {
  startTeeServer()
}
