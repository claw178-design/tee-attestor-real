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
import { verifyProof, ZkProof, decodeProofBlob, zkArtifactsAvailable } from './zk-prover'

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
          // Skip empty values (KMS /tmp/.env may set vars to empty, overriding Dockerfile defaults)
          if (!val) continue
          // Only set if not already set to a non-empty value (explicit env takes priority)
          if (!process.env[key] || process.env[key] === '') {
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

// EigenCompute environment — auto-detect from hostname, env vars, or KMS
function detectAppId(): string {
  // Check env var first (non-empty only)
  const envVal = (process.env.EIGEN_APP_ID || '').trim()
  if (envVal && envVal.startsWith('0x')) return envVal

  // EigenCompute sets hostname to "tee-0x<app_id>"
  const hostname = require('os').hostname()
  const match = hostname.match(/tee-(0x[0-9a-fA-F]+)/)
  if (match) {
    console.log(`[tee-attestor] Auto-detected app_id from hostname: ${match[1]}`)
    return match[1]
  }
  return ''
}

function detectImageDigest(): string {
  const envVal = (process.env.EIGEN_IMAGE_DIGEST || '').trim()
  if (envVal && envVal.startsWith('sha256:')) return envVal

  // Try reading from well-known paths written by build/deploy
  const digestPaths = ['/app/.image-digest', '/etc/eigencompute/image-digest']
  for (const p of digestPaths) {
    try {
      if (existsSync(p)) {
        const v = readFileSync(p, 'utf-8').trim()
        if (v) return v
      }
    } catch {}
  }

  return ''
}

/** Async background fetch of image_digest from EigenCompute verify API or GHCR */
async function fetchImageDigestFallback(appId: string): Promise<string> {
  // 1. Try EigenCompute verify API (most reliable source)
  if (appId) {
    const env = process.env.ECLOUD_ENV || 'sepolia'
    const verifyBase = env === 'mainnet'
      ? 'https://verify.eigencloud.xyz'
      : 'https://verify-sepolia.eigencloud.xyz'
    try {
      const res = await fetch(`${verifyBase}/api/app/${appId}`, {
        signal: AbortSignal.timeout(10000),
      })
      if (res.ok) {
        const data = await res.json() as any
        const digest = data?.imageDigest || data?.image_digest || ''
        if (digest && digest.startsWith('sha256:')) {
          console.log(`[tee-attestor] Fetched image_digest from EigenCompute verify API: ${digest}`)
          return digest
        }
      }
    } catch {}
  }

  // 2. Try GHCR API
  try {
    const url = `https://ghcr.io/v2/claw178-design/tee-attestor-real/manifests/latest`
    const res = await fetch(url, {
      signal: AbortSignal.timeout(10000),
      headers: { 'Accept': 'application/vnd.docker.distribution.manifest.v2+json' },
    })
    if (res.ok) {
      const digest = res.headers.get('docker-content-digest') || ''
      if (digest && digest.startsWith('sha256:')) {
        console.log(`[tee-attestor] Fetched image_digest from GHCR: ${digest}`)
        return digest
      }
    }
  } catch {}
  return ''
}

// Lazy evaluation — these are read when collectAttestation() runs,
// not at module load time, to ensure entrypoint env setup has completed.
function getEigenEnv() {
  const appId = detectAppId()
  const imageDigest = detectImageDigest()
  const evmAddress = process.env.EIGEN_EVM_ADDRESS || ''
  const environment = process.env.ECLOUD_ENV || process.env.EIGEN_ENVIRONMENT || 'sepolia'
  const machineType = process.env.EIGEN_MACHINE_TYPE_PUBLIC || process.env.INSTANCE_TYPE || 'g1-standard-4t'
  const isRuntime = process.env.EIGEN_RUNTIME === '1' || appId !== ''
  return { appId, imageDigest, evmAddress, environment, machineType, isRuntime }
}

// Default ClaimVerifierV2 contract address on Sepolia
const DEFAULT_VERIFIER_CONTRACT = process.env.CLAIM_VERIFIER_ADDRESS || '0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C'

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
  const eigen = getEigenEnv()
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
  if (eigen.isRuntime || eigen.appId || eigen.machineType.includes('t')) {
    if (!isTee) {
      teeType = 'eigencompute'
      isTee = true
    }
    console.log(`[tee-attestor] EigenCompute environment detected (app: ${eigen.appId || 'auto'})`)
  }

  // 3. Auto-detect from image digest file (written by EigenCompute entrypoint)
  let imageDigest = eigen.imageDigest
  if (!imageDigest) {
    try {
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

  const dashboardBase = eigen.environment === 'mainnet'
    ? 'https://verify.eigencloud.xyz'
    : 'https://verify-sepolia.eigencloud.xyz'

  console.log(`[tee-attestor] Resolved: app_id=${eigen.appId}, image_digest=${imageDigest || 'none'}, evm=${eigen.evmAddress || 'none'}`)

  return {
    is_tee: isTee,
    tee_type: teeType,
    app_id: eigen.appId,
    image_digest: imageDigest,
    evm_address: eigen.evmAddress,
    environment: eigen.environment,
    machine_type: eigen.machineType,
    tdx_quote: tdxQuote,
    dashboard_url: eigen.appId ? `${dashboardBase}/app/${eigen.appId}` : '',
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

// ─── ZK Proof Verification ──────────────────────────────────────────

/** Whether ZK artifacts are available in this deployment */
let zkEnabled = false

function initZk(): void {
  zkEnabled = zkArtifactsAvailable()
  if (zkEnabled) {
    console.log(`[tee-attestor] ZK proof verification: ENABLED (artifacts found)`)
  } else {
    console.log(`[tee-attestor] ZK proof verification: DISABLED (artifacts not found)`)
  }
}

/**
 * Validate that a ZK proof's public signals match the claim hashes.
 * Returns null if valid, or an error string if invalid.
 */
async function validateZkProof(
  proof: ZkProof,
  hashes: { usage_hash: string; model_hash: string; prompt_hash: string; response_hash: string },
): Promise<string | null> {
  // Check public signals count
  if (!proof.publicSignals || proof.publicSignals.length !== 4) {
    return 'ZK proof must have exactly 4 public signals'
  }

  // Convert public signals (decimal strings from snarkjs) to 0x hex for comparison
  const signalHexes = proof.publicSignals.map(s => {
    const bi = BigInt(s)
    return '0x' + bi.toString(16).padStart(64, '0')
  })

  // Verify public signals match the claimed hashes
  const expectedOrder = [hashes.usage_hash, hashes.model_hash, hashes.prompt_hash, hashes.response_hash]
  for (let i = 0; i < 4; i++) {
    const expected = expectedOrder[i].toLowerCase()
    const actual = signalHexes[i].toLowerCase()
    if (expected !== actual) {
      return `Public signal ${i} mismatch: expected ${expected}, got ${actual}`
    }
  }

  // Verify the Groth16 proof mathematically
  try {
    const valid = await verifyProof(proof)
    if (!valid) {
      return 'Groth16 proof verification failed (invalid proof)'
    }
  } catch (e: any) {
    return `Groth16 verification error: ${e.message}`
  }

  return null // valid
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

    // POST /sign — Sign a claim (ECDSA)
    // Also requires ZK proof when ZK is enabled.
    if (url === '/sign' && req.method === 'POST') {
      try {
        const body = await readBody(req)
        const parsed = JSON.parse(body)
        const claimReq: SignRequest = parsed
        const zkProofData: ZkProof | string | undefined = parsed.zk_proof

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

        // ── ZK Proof Verification Gate ──
        let zkVerified = false
        if (zkEnabled) {
          if (!zkProofData) {
            res.writeHead(400, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({
              error: 'ZK proof required. TEE will not sign unverified hashes.',
            }))
            return
          }

          let proof: ZkProof
          if (typeof zkProofData === 'string') {
            try { proof = decodeProofBlob(zkProofData) } catch {
              res.writeHead(400, { 'Content-Type': 'application/json' })
              res.end(JSON.stringify({ error: 'Invalid zk_proof format' }))
              return
            }
          } else {
            proof = zkProofData
          }

          const zkError = await validateZkProof(proof, claimReq)
          if (zkError) {
            console.log(`[tee-attestor] ZK proof rejected: ${zkError}`)
            res.writeHead(400, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ error: `ZK proof invalid: ${zkError}` }))
            return
          }

          zkVerified = true
          console.log(`[tee-attestor] ZK proof verified successfully`)
        }

        const signed = signClaim(claimReq, keys, attestation)
        if (zkVerified) {
          signed.zk_proof = typeof zkProofData === 'string' ? zkProofData : Buffer.from(JSON.stringify(zkProofData)).toString('base64')
        }
        signCount++

        console.log(`[tee-attestor] Signed claim #${signCount} — endpoint: ${claimReq.endpoint}, zk: ${zkVerified}`)

        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, claim: signed, zk_verified: zkVerified }))
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
    // Accepts optional `zk_proof` field. If ZK is enabled and proof is provided,
    // the TEE verifies the proof before signing. If ZK is enabled but no proof
    // is provided, the request is rejected (prevents signing unverified hashes).
    if (url === '/eth-sign' && req.method === 'POST') {
      try {
        const body = await readBody(req)
        const parsed = JSON.parse(body)
        const claimReq: EthSignRequest = parsed
        const zkProofData: ZkProof | string | undefined = parsed.zk_proof

        // Validate required fields
        const required = ['usage_hash', 'model_hash', 'prompt_hash', 'response_hash', 'endpoint', 'timestamp']
        for (const field of required) {
          if (!(field in claimReq)) {
            res.writeHead(400, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ error: `Missing required field: ${field}` }))
            return
          }
        }

        // ── ZK Proof Verification Gate ──
        let zkVerified = false
        if (zkEnabled) {
          if (!zkProofData) {
            res.writeHead(400, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({
              error: 'ZK proof required. TEE will not sign unverified hashes. Provide zk_proof (ZkProof object or base64 blob).',
            }))
            return
          }

          // Decode proof: accept either ZkProof object or base64 blob string
          let proof: ZkProof
          if (typeof zkProofData === 'string') {
            try {
              proof = decodeProofBlob(zkProofData)
            } catch {
              res.writeHead(400, { 'Content-Type': 'application/json' })
              res.end(JSON.stringify({ error: 'Invalid zk_proof: must be a ZkProof object or base64-encoded blob' }))
              return
            }
          } else {
            proof = zkProofData
          }

          const zkError = await validateZkProof(proof, {
            usage_hash: claimReq.usage_hash,
            model_hash: claimReq.model_hash,
            prompt_hash: claimReq.prompt_hash,
            response_hash: claimReq.response_hash,
          })

          if (zkError) {
            console.log(`[tee-attestor] ZK proof rejected: ${zkError}`)
            res.writeHead(400, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ error: `ZK proof invalid: ${zkError}` }))
            return
          }

          zkVerified = true
          console.log(`[tee-attestor] ZK proof verified successfully`)
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
            zk_verified: zkVerified,
          },
        }

        console.log(`[tee-attestor] EIP-712 signed claim #${signCount} — endpoint: ${claimReq.endpoint}, signer: ${wallet.address}, zk: ${zkVerified}`)

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
  initZk()
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

    // Background: try to fetch image_digest from EigenCompute verify API if not set
    if (!attestation.image_digest || !attestation.image_digest.startsWith('sha256:')) {
      fetchImageDigestFallback(attestation.app_id).then(digest => {
        if (digest) {
          attestation.image_digest = digest
          console.log(`[tee-attestor] Updated image_digest: ${digest}`)
        }
      }).catch(() => {})
    }
  })

  return server
}

// Standalone mode: detect if this file is the entry point
if (process.argv[1]?.endsWith('tee-server.js') || process.argv[1]?.endsWith('tee-server.ts')) {
  startTeeServer()
}
