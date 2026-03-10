/**
 * zkTLS Client — Uses Reclaim attestor-core to create verifiable claims
 *
 * Architecture (Path B):
 *   Local Gateway → TLS tunnel via TEE Attestor → Real API
 *                        ↓
 *               TEE sees ciphertext (not API key via K2)
 *               Client generates ZK proof: hash(plaintext) == decrypt(ciphertext)
 *               TEE verifies proof + signs claim
 *
 * The attestor never sees the API key (hidden via TLS 1.3 KeyUpdate / K2)
 * The attestor sees TLS ciphertext, verifies ZK proofs, and signs the claim.
 */

import type { ProofGenerationStep } from '@reclaimprotocol/attestor-core'
import { buildOpenAIProviderParams } from './providers/openai'
import { buildGeminiProviderParams } from './providers/gemini'
import { buildClaudeProviderParams } from './providers/claude'

// ESM module — must use dynamic import at runtime
let _createClaimOnAttestor: any = null
async function getCreateClaimOnAttestor() {
  if (!_createClaimOnAttestor) {
    const mod = await import('@reclaimprotocol/attestor-core')
    _createClaimOnAttestor = mod.createClaimOnAttestor
  }
  return _createClaimOnAttestor
}

export interface ZkTlsClaimResult {
  /** The signed claim from the TEE attestor */
  claim: any
  /** Provider name (openai | gemini | claude) */
  provider: string
  /** Timestamp */
  timestamp: number
}

export interface ZkTlsClientOpts {
  /** WebSocket URL of the TEE attestor (e.g. wss://attestor.example.com/ws) */
  attestorUrl: string
  /** Owner private key for signing the claim request (hex, no 0x prefix) */
  ownerPrivateKey: string
  /** ZK engine to use */
  zkEngine?: 'snarkjs' | 'gnark'
  /** Progress callback */
  onStep?: (step: ProofGenerationStep) => void
}

/**
 * Create a zkTLS claim for an OpenAI API call.
 * The API key is hidden via K2 (TLS KeyUpdate) — the attestor never sees it.
 */
export async function createOpenAIClaim(
  opts: ZkTlsClientOpts,
  apiKey: string,
  requestBody: object,
): Promise<ZkTlsClaimResult> {
  const createClaim = await getCreateClaimOnAttestor()
  const { params, secretParams } = buildOpenAIProviderParams(apiKey, requestBody)

  const result = await createClaim({
    name: 'http',
    params,
    secretParams,
    ownerPrivateKey: opts.ownerPrivateKey,
    client: { url: opts.attestorUrl },
    zkEngine: opts.zkEngine || 'snarkjs',
    onStep: opts.onStep,
  })

  return {
    claim: result.claim,
    provider: 'openai',
    timestamp: Math.floor(Date.now() / 1000),
  }
}

/**
 * Create a zkTLS claim for a Gemini API call.
 * The API key is in the URL query param — hidden via secretParams.paramValues.
 */
export async function createGeminiClaim(
  opts: ZkTlsClientOpts,
  apiKey: string,
  model: string,
  requestBody: object,
): Promise<ZkTlsClaimResult> {
  const createClaim = await getCreateClaimOnAttestor()
  const { params, secretParams } = buildGeminiProviderParams(apiKey, model, requestBody)

  const result = await createClaim({
    name: 'http',
    params,
    secretParams,
    ownerPrivateKey: opts.ownerPrivateKey,
    client: { url: opts.attestorUrl },
    zkEngine: opts.zkEngine || 'snarkjs',
    onStep: opts.onStep,
  })

  return {
    claim: result.claim,
    provider: 'gemini',
    timestamp: Math.floor(Date.now() / 1000),
  }
}

/**
 * Create a zkTLS claim for a Claude/Anthropic API call.
 * The x-api-key header is hidden via K2 — the attestor never sees it.
 */
export async function createClaudeClaim(
  opts: ZkTlsClientOpts,
  apiKey: string,
  requestBody: object,
): Promise<ZkTlsClaimResult> {
  const createClaim = await getCreateClaimOnAttestor()
  const { params, secretParams } = buildClaudeProviderParams(apiKey, requestBody)

  const result = await createClaim({
    name: 'http',
    params,
    secretParams,
    ownerPrivateKey: opts.ownerPrivateKey,
    client: { url: opts.attestorUrl },
    zkEngine: opts.zkEngine || 'snarkjs',
    onStep: opts.onStep,
  })

  return {
    claim: result.claim,
    provider: 'claude',
    timestamp: Math.floor(Date.now() / 1000),
  }
}

/**
 * Generic zkTLS claim creation for any HTTP API.
 * Pass Reclaim HTTP provider params directly.
 */
export async function createHttpClaim(
  opts: ZkTlsClientOpts,
  params: any,
  secretParams: any,
): Promise<ZkTlsClaimResult> {
  const createClaim = await getCreateClaimOnAttestor()

  const result = await createClaim({
    name: 'http',
    params,
    secretParams,
    ownerPrivateKey: opts.ownerPrivateKey,
    client: { url: opts.attestorUrl },
    zkEngine: opts.zkEngine || 'snarkjs',
    onStep: opts.onStep,
  })

  return {
    claim: result.claim,
    provider: 'http',
    timestamp: Math.floor(Date.now() / 1000),
  }
}
