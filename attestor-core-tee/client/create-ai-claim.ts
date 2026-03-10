/**
 * Gateway Client — Creates zkTLS claims for AI API calls
 *
 * Runs on the user's machine (gateway side).
 * Connects to the TEE attestor via WebSocket, proxies the TLS connection
 * through the attestor, and receives a signed claim with ZK proof.
 *
 * The API key is hidden from the attestor via TLS 1.3 KeyUpdate (K2).
 * The attestor never sees the key, but can verify the response integrity.
 *
 * Usage:
 *   import { createAiClaim } from './create-ai-claim'
 *   const result = await createAiClaim({
 *     provider: 'openai',
 *     apiKey: 'sk-...',
 *     model: 'gpt-4',
 *     prompt: 'Hello',
 *     attestorUrl: 'wss://attestor.example.com/ws',
 *     ownerPrivateKey: '0x...',
 *   })
 */

import { createClaimOnAttestor } from '@reclaimprotocol/attestor-core'
import type { ProviderName } from '@reclaimprotocol/attestor-core'
import { readFileSync } from 'fs'
import { join } from 'path'

export interface AiClaimOptions {
  /** AI provider: 'openai' | 'gemini' | 'claude' */
  provider: 'openai' | 'gemini' | 'claude'
  /** API key for the provider (hidden from attestor via K2) */
  apiKey: string
  /** Model to use */
  model: string
  /** Prompt text */
  prompt: string
  /** Attestor WebSocket URL */
  attestorUrl: string
  /** Owner's ETH private key (for signing the claim request) */
  ownerPrivateKey: string
  /** ZK engine: 'snarkjs' (default) or 'gnark' */
  zkEngine?: 'snarkjs' | 'gnark'
  /** Progress callback */
  onStep?: (step: { name: string; proofsDone?: number; proofsTotal?: number }) => void
}

/** Provider config templates */
const PROVIDER_CONFIGS: Record<string, {
  url: string
  method: string
  headers: Record<string, string>
  buildBody: (model: string, prompt: string) => string
  responseMatches: any[]
  responseRedactions: any[]
  secretParamBuilder: (apiKey: string) => any
}> = {
  openai: {
    url: 'https://api.openai.com/v1/chat/completions',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    buildBody: (model, prompt) => JSON.stringify({
      model,
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.7,
    }),
    responseMatches: [
      { type: 'regex', value: '"total_tokens":(?<totalTokens>\\d+)' },
      { type: 'regex', value: '"model":"(?<modelUsed>[^"]+)"' },
    ],
    responseRedactions: [
      { jsonPath: '$.usage' },
      { jsonPath: '$.choices[0].message.content' },
    ],
    secretParamBuilder: (apiKey) => ({
      authorisationHeader: `Bearer ${apiKey}`,
    }),
  },
  gemini: {
    url: 'https://generativelanguage.googleapis.com/v1beta/models/',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    buildBody: (model, prompt) => JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: 256 },
    }),
    responseMatches: [
      { type: 'regex', value: '"totalTokenCount":(?<totalTokens>\\d+)' },
    ],
    responseRedactions: [
      { jsonPath: '$.usageMetadata' },
      { jsonPath: '$.candidates[0].content.parts[0].text' },
    ],
    secretParamBuilder: (apiKey) => ({
      paramValues: { apiKey },
    }),
  },
  claude: {
    url: 'https://api.anthropic.com/v1/messages',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'anthropic-version': '2023-06-01',
    },
    buildBody: (model, prompt) => JSON.stringify({
      model,
      max_tokens: 256,
      messages: [{ role: 'user', content: prompt }],
    }),
    responseMatches: [
      { type: 'regex', value: '"output_tokens":(?<outputTokens>\\d+)' },
      { type: 'regex', value: '"model":"(?<modelUsed>[^"]+)"' },
    ],
    responseRedactions: [
      { jsonPath: '$.usage' },
      { jsonPath: '$.content[0].text' },
    ],
    secretParamBuilder: (apiKey) => ({
      headers: { 'x-api-key': apiKey },
    }),
  },
}

export async function createAiClaim(opts: AiClaimOptions) {
  const config = PROVIDER_CONFIGS[opts.provider]
  if (!config) {
    throw new Error(`Unknown provider: ${opts.provider}. Use: openai, gemini, claude`)
  }

  // Build the URL (Gemini has model in URL path)
  let url = config.url
  if (opts.provider === 'gemini') {
    url = `${config.url}${opts.model}:generateContent?key=${opts.apiKey}`
  }

  const body = config.buildBody(opts.model, opts.prompt)

  console.log(`[ai-claim] Creating zkTLS claim for ${opts.provider} (model: ${opts.model})`)
  console.log(`[ai-claim] Attestor: ${opts.attestorUrl}`)

  const result = await createClaimOnAttestor({
    name: 'http' as ProviderName,
    params: {
      url,
      method: config.method,
      headers: config.headers,
      body,
      responseMatches: config.responseMatches,
      responseRedactions: config.responseRedactions,
    },
    secretParams: config.secretParamBuilder(opts.apiKey),
    ownerPrivateKey: opts.ownerPrivateKey,
    client: { url: opts.attestorUrl },
    zkEngine: opts.zkEngine || 'snarkjs',
    onStep: opts.onStep,
  })

  if (result.error) {
    throw new Error(`Claim creation failed: ${JSON.stringify(result.error)}`)
  }

  console.log(`[ai-claim] Claim created successfully!`)
  console.log(`[ai-claim] Claim ID: ${result.identifier}`)
  console.log(`[ai-claim] Attestor address: ${result.witnesses?.[0]?.id}`)

  return {
    claim: result,
    provider: opts.provider,
    model: opts.model,
    extractedParams: result.extractedParameterValues,
  }
}

// CLI usage
if (require.main === module) {
  const args = process.argv.slice(2)
  if (args.length < 4) {
    console.log('Usage: create-ai-claim <provider> <apiKey> <model> <prompt> [attestorUrl] [ownerKey]')
    console.log('  provider: openai | gemini | claude')
    console.log('  Example: create-ai-claim openai sk-... gpt-4 "Hello world"')
    process.exit(1)
  }

  const [provider, apiKey, model, prompt, attestorUrl, ownerKey] = args

  createAiClaim({
    provider: provider as any,
    apiKey,
    model,
    prompt,
    attestorUrl: attestorUrl || 'ws://localhost:8001/ws',
    ownerPrivateKey: ownerKey || '0x' + '1'.repeat(64), // dummy key for testing
    onStep: (step) => console.log(`[ai-claim] Step: ${step.name}`),
  })
    .then((result) => {
      console.log(JSON.stringify(result, null, 2))
    })
    .catch((err) => {
      console.error(`Error: ${err.message}`)
      process.exit(1)
    })
}
