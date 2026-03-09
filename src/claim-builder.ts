/**
 * Claim Builder — orchestrates All-Hash claim creation via Reclaim attestor-core.
 *
 * Flow:
 * 1. Select provider (openai/gemini/claude)
 * 2. Build HTTP provider params with All-Hash redactions
 * 3. Call createClaimOnAttestor() → TLS tunnel → OPRF → ZK proof → signed claim
 * 4. Extract OPRF hashes into AllHashClaim format
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

    // Extract claim data from attestor response
    const claimData = result.claim?.claim
    if (!claimData) {
      return { success: false, error: 'No claim in attestor response', raw: result }
    }

    // Parse the parameters to extract OPRF hashes
    const params = JSON.parse(claimData.parameters)

    const claim: AllHashClaim = {
      usage_hash: params.responseRedactions?.[0]?.hash || '',
      model_hash: params.responseRedactions?.[1]?.hash || '',
      prompt_hash: params.responseRedactions?.[2]?.hash || '',
      response_hash: params.responseRedactions?.[3]?.hash || '',
      endpoint: `${provider}:${providerParams.params}`,
      timestamp: claimData.timestampS,
      attestor_sig: result.claim?.signatures?.[0]?.signature || '',
      zk_proof: Buffer.from(
        JSON.stringify(result.claim?.signatures || [])
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
