#!/usr/bin/env node
/**
 * CLI for All-Hash TEE Attestor
 *
 * Usage:
 *   npx ts-node src/cli.ts attest --provider openai --prompt "Hello world"
 *   npx ts-node src/cli.ts verify --claim claim.json --field model --value gpt-4
 *   npx ts-node src/cli.ts hash --value "some string"
 */

import { config } from 'dotenv'
import { readFileSync, writeFileSync } from 'fs'
import { createAllHashClaim } from './claim-builder'
import { createOpenAIClaim, createGeminiClaim, createClaudeClaim } from './zktls-client'
import { verifyClaim, computeOprfHash, verifyFieldHash } from './verify'

config({ path: `${__dirname}/../.env` })

const args = process.argv.slice(2)
const command = args[0]

function getArg(name: string): string | undefined {
  const idx = args.indexOf(`--${name}`)
  return idx >= 0 ? args[idx + 1] : undefined
}

function getFlag(name: string): boolean {
  return args.includes(`--${name}`)
}

function usage() {
  console.log(`
🦀 All-Hash TEE Attestor CLI

Commands:
  attest    Create an attested claim via Reclaim Protocol (or --direct)
  verify    Verify a claim against known values
  hash      Compute OPRF hash of a value

attest options:
  --provider <openai|gemini|claude>  LLM provider (required)
  --prompt <text>                    Prompt to send (default: "Hello")
  --model <model>                    Model name (provider-specific)
  --output <file>                    Save claim to JSON file
  --attestor <url>                   Custom attestor WebSocket URL
  --direct                           Call API directly (no attestor, unsigned claim)

verify options:
  --claim <file>                     Claim JSON file (required)
  --field <name>                     Field to verify: usage, model, prompt, response
  --value <text>                     Expected value for the field
  --max-age <seconds>                Max claim age (default: 3600)

hash options:
  --value <text>                     Value to hash (required)

Environment variables:
  OPENAI_API_KEY      OpenAI API key
  GEMINI_API_KEY      Google Gemini API key
  ANTHROPIC_API_KEY   Anthropic API key
  ATTESTOR_URL        Custom attestor WebSocket URL
`)
  process.exit(0)
}

async function cmdAttest() {
  const provider = getArg('provider') as 'openai' | 'gemini' | 'claude'
  if (!provider || !['openai', 'gemini', 'claude'].includes(provider)) {
    console.error('❌ --provider must be one of: openai, gemini, claude')
    process.exit(1)
  }

  const prompt = getArg('prompt') || 'Hello'
  const output = getArg('output')
  const attestorUrl = getArg('attestor') || process.env.ATTESTOR_URL

  // Get API key
  const keyMap: Record<string, string | undefined> = {
    openai: process.env.OPENAI_API_KEY,
    gemini: process.env.GEMINI_API_KEY,
    claude: process.env.ANTHROPIC_API_KEY,
  }
  const apiKey = keyMap[provider]
  if (!apiKey) {
    const envName = provider === 'openai' ? 'OPENAI_API_KEY'
      : provider === 'gemini' ? 'GEMINI_API_KEY'
      : 'ANTHROPIC_API_KEY'
    console.error(`❌ ${envName} not set. Add it to .env or environment.`)
    process.exit(1)
  }

  // Build request body per provider
  let requestBody: object
  let geminiModel: string | undefined

  switch (provider) {
    case 'openai': {
      const model = getArg('model') || 'gpt-4o-mini'
      requestBody = {
        model,
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 100,
      }
      break
    }
    case 'gemini': {
      geminiModel = getArg('model') || 'gemini-1.5-flash'
      requestBody = {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens: 100 },
      }
      break
    }
    case 'claude': {
      const model = getArg('model') || 'claude-haiku-4-5-20251001'
      requestBody = {
        model,
        max_tokens: 100,
        messages: [{ role: 'user', content: prompt }],
      }
      break
    }
  }

  const isDirect = getFlag('direct')

  console.log(`🔄 Creating ${provider} ${isDirect ? 'direct' : 'attested'} claim...`)
  console.log(`   Prompt: "${prompt}"`)

  let claim: any

  if (isDirect) {
    // Direct mode: use zkTLS client through attestor (no proxy)
    const ownerPrivateKey = require('crypto').randomBytes(32).toString('hex')
    const zkOpts = {
      attestorUrl: attestorUrl || 'ws://localhost:8001/ws',
      ownerPrivateKey,
      onStep: (step: any) => console.log(`   → ${step.name}`),
    }

    let result: any
    switch (provider) {
      case 'openai':
        result = await createOpenAIClaim(zkOpts, apiKey, requestBody)
        break
      case 'gemini':
        result = await createGeminiClaim(zkOpts, apiKey, geminiModel || 'gemini-2.5-flash', requestBody)
        break
      case 'claude':
        result = await createClaudeClaim(zkOpts, apiKey, requestBody)
        break
    }
    claim = result.claim
  } else {
    // Attestor mode: route through Reclaim
    const result = await createAllHashClaim({
      provider,
      apiKey,
      requestBody,
      geminiModel,
      attestorUrl,
      onStep: (step) => console.log(`   → ${step.name}`),
    })

    if (!result.success) {
      console.error(`❌ Attestation failed: ${result.error}`)
      process.exit(1)
    }

    claim = result.claim
  }

  console.log(`\n✅ ${isDirect ? 'Unsigned' : 'Attested'} claim created!`)
  console.log(JSON.stringify(claim, null, 2))

  if (output) {
    writeFileSync(output, JSON.stringify(claim, null, 2))
    console.log(`\n📄 Saved to ${output}`)
  }
}

function cmdVerify() {
  const claimFile = getArg('claim')
  if (!claimFile) {
    console.error('❌ --claim <file> is required')
    process.exit(1)
  }

  const claim = JSON.parse(readFileSync(claimFile, 'utf8'))
  const field = getArg('field')
  const value = getArg('value')
  const maxAge = parseInt(getArg('max-age') || '3600', 10)

  if (field && value) {
    // Single field verification
    const hashKey = `${field}_hash`
    const hash = (claim as any)[hashKey]
    if (!hash) {
      console.error(`❌ Field "${field}" not found in claim (expected ${hashKey})`)
      process.exit(1)
    }

    const match = verifyFieldHash(value, hash)
    console.log(match
      ? `✅ ${field}: verified! Hash matches.`
      : `❌ ${field}: MISMATCH. Expected ${hash}, got ${computeOprfHash(value)}`
    )
    process.exit(match ? 0 : 1)
  }

  // Full claim verification (no values to check, just structure + timestamp)
  const result = verifyClaim(claim, {}, { maxAge })
  console.log(`Timestamp: ${result.timestampValid ? '✅ valid' : '❌ expired'}`)

  if (result.errors.length > 0) {
    console.log('\nErrors:')
    for (const err of result.errors) {
      console.log(`  ❌ ${err}`)
    }
  }

  console.log(`\nOverall: ${result.valid ? '✅ VALID' : '❌ INVALID'}`)
  process.exit(result.valid ? 0 : 1)
}

function cmdHash() {
  const value = getArg('value')
  if (!value) {
    console.error('❌ --value <text> is required')
    process.exit(1)
  }

  const hash = computeOprfHash(value)
  console.log(hash)
}

async function main() {
  switch (command) {
    case 'attest':
      await cmdAttest()
      break
    case 'verify':
      cmdVerify()
      break
    case 'hash':
      cmdHash()
      break
    case '--help':
    case '-h':
    case undefined:
      usage()
      break
    default:
      console.error(`Unknown command: ${command}`)
      usage()
  }
}

main().catch(err => {
  console.error('Error:', err.message)
  process.exit(1)
})
