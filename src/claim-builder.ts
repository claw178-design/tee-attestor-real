/**
 * Claim Builder — orchestrates All-Hash claim creation via Reclaim attestor-core.
 *
 * Flow:
 * 1. Select provider (openai/gemini/claude)
 * 2. Build HTTP provider params with All-Hash redactions
 * 3. Call createClaimOnAttestor() → TLS tunnel → OPRF → ZK proof → signed claim
 * 4. Extract OPRF hashes from the signed claim parameters
 */

import { createClaimOnAttestor } from '@reclaimprotocol/attestor-core'
import type { AllHashClaim, ClaimResult } from './types/claim'
import { buildOpenAIProviderParams } from './providers/openai'
import { buildGeminiProviderParams } from './providers/gemini'
import { buildClaudeProviderParams } from './providers/claude'
import { ethers } from 'ethers'

export interface CreateAllHashClaimOpts {
  /** Which LLM provider */
  provider: 'openai' | 'gemini' | 'claude'
  /** API key for the provider */
  apiKey: string
  /** Request body to send to the LLM API */
  requestBody: object
  /** Gemini model name (required for gemini provider) */
  geminiModel?: string
  /** Attestor WebSocket URL (default: wss://attestor.reclaimprotocol.org) */
  attestorUrl?: string
  /** Owner private key for signing claims (hex, 0x-prefixed) */
  ownerPrivateKey?: string
  /** Progress callback */
  onStep?: (step: { name: string; [key: string]: unknown }) => void
}

const DEFAULT_ATTESTOR = 'wss://attestor.reclaimprotocol.org'

export async function createAllHashClaim(
  opts: CreateAllHashClaimOpts,
): Promise<ClaimResult> {
  const {
    provider,
    apiKey,
    requestBody,
    geminiModel,
    attestorUrl = DEFAULT_ATTESTOR,
    onStep,
  } = opts

  // Generate ephemeral owner key if not provided
  const ownerPrivateKey = opts.ownerPrivateKey || ethers.Wallet.createRandom().privateKey

  // Build provider-specific params with All-Hash strategy
  let providerParams: { params: object; secretParams: object }

  switch (provider) {
    case 'openai':
      providerParams = buildOpenAIProviderParams(apiKey, requestBody)
      break
    case 'gemini':
      if (!geminiModel) {
        return { success: false, error: 'geminiModel is required for gemini provider' }
      }
      providerParams = buildGeminiProviderParams(apiKey, geminiModel, requestBody)
      break
    case 'claude':
      providerParams = buildClaudeProviderParams(apiKey, requestBody)
      break
    default:
      return { success: false, error: `Unknown provider: ${provider}` }
  }

  try {
    // attestor-core uses 'http' as the provider name for all HTTP-based providers
    const result = await createClaimOnAttestor({
      name: 'http',
      params: providerParams.params as any,
      secretParams: providerParams.secretParams as any,
      ownerPrivateKey,
      client: {
        url: attestorUrl,
      },
      onStep: onStep as any,
    })

    // ClaimTunnelResponse structure:
    // result.claim: ProviderClaimData { provider, parameters, owner, timestampS, epoch }
    // result.signatures: { attestorAddress, claimSignature, resultSignature }
    const claimData = result.claim
    if (!claimData) {
      return {
        success: false,
        error: result.error?.message || 'No claim in attestor response',
        raw: result,
      }
    }

    // The parameters field contains the canonicalized params.
    // After OPRF processing, the original plaintext values in responseRedactions
    // are replaced with their OPRF hashes (updateParametersFromOprfData=true by default).
    const parameters = JSON.parse(claimData.parameters)

    // Extract OPRF hashes from the response redactions in the signed parameters.
    // The attestor replaces plaintext with OPRF hashes in-place,
    // so we can read them from the redacted parameters.
    const redactions = parameters.responseRedactions || []

    // Build endpoint identifier from provider config
    const endpoint = `${provider}:${parameters.url || ''}`

    const claim: AllHashClaim = {
      // Each redaction with hash='oprf' has its value replaced by the OPRF commitment
      usage_hash: extractOprfHash(redactions, 0),
      model_hash: extractOprfHash(redactions, 1),
      prompt_hash: extractOprfHash(redactions, 2),
      response_hash: extractOprfHash(redactions, 3),
      endpoint,
      timestamp: claimData.timestampS,
      attestor_sig: result.signatures
        ? bufToHex(result.signatures.claimSignature)
        : '',
      zk_proof: Buffer.from(
        JSON.stringify({
          attestorAddress: result.signatures?.attestorAddress || '',
          parameters: claimData.parameters,
          owner: claimData.owner,
          epoch: claimData.epoch,
        })
      ).toString('base64'),
    }

    return { success: true, claim, raw: result }
  } catch (err: any) {
    return {
      success: false,
      error: err.message || String(err),
      raw: err,
    }
  }
}

/**
 * Extract OPRF hash from a redaction entry at the given index.
 * After updateParametersFromOprfData, the jsonPath value in parameters
 * gets replaced with the OPRF hash string.
 */
function extractOprfHash(redactions: any[], index: number): string {
  if (index >= redactions.length) return ''
  // The hash is stored in the redaction after OPRF processing
  return redactions[index]?.hash || ''
}

/**
 * Convert Uint8Array to hex string
 */
function bufToHex(buf: Uint8Array | string): string {
  if (typeof buf === 'string') return buf
  return '0x' + Buffer.from(buf).toString('hex')
}
