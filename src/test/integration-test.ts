/**
 * Phase 2 Integration Test — Real API calls.
 *
 * Two modes:
 * 1. Direct mode (default): Calls LLM APIs directly, generates local claims
 * 2. Attestor mode (--attestor): Routes through Reclaim attestor for signed claims
 *
 * Prerequisites:
 *   - Set API keys in .env or environment:
 *     OPENAI_API_KEY, GEMINI_API_KEY, ANTHROPIC_API_KEY
 *   - At least one key must be set
 *
 * Usage:
 *   npx ts-node src/test/integration-test.ts
 *   npx ts-node src/test/integration-test.ts --attestor
 *   PROVIDER=openai npx ts-node src/test/integration-test.ts
 */

import { config } from 'dotenv'
import { writeFileSync } from 'fs'
import { directCall, type DirectCallOpts } from '../direct-client'
import { verifyClaim, computeOprfHash } from '../verify'

// Lazy-load claim-builder only in attestor mode (requires @reclaimprotocol/attestor-core)
async function loadClaimBuilder() {
  const mod = await import('../claim-builder')
  return mod
}

// Load .env from project root
config({ path: `${__dirname}/../../.env` })

const OPENAI_KEY = process.env.OPENAI_API_KEY
const GEMINI_KEY = process.env.GEMINI_API_KEY
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY
const USE_ATTESTOR = process.argv.includes('--attestor')
const ATTESTOR_URL = process.env.ATTESTOR_URL || undefined

function log(msg: string) {
  console.log(`[${new Date().toISOString()}] ${msg}`)
}

// --- Direct API Tests ---

async function testDirectOpenAI() {
  if (!OPENAI_KEY) {
    console.log('⏭️  Skipping OpenAI (no OPENAI_API_KEY)')
    return null
  }

  log('🔄 Testing OpenAI direct call...')

  const result = await directCall({
    provider: 'openai',
    apiKey: OPENAI_KEY,
    requestBody: {
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'Say hello in exactly 3 words.' }],
      max_tokens: 20,
    },
  })

  if (!result.success) {
    console.error(`❌ OpenAI FAIL: ${result.error}`)
    return result
  }

  log('✅ OpenAI response received!')
  console.log('  Model:', result.response?.model)
  console.log('  Usage:', JSON.stringify(result.response?.usage))
  console.log('  Reply:', result.response?.choices?.[0]?.message?.content)
  console.log('  Claim:', JSON.stringify(result.claim, null, 2))

  // Verify our own claim
  if (result.claim && result.response) {
    const verification = verifyClaim(result.claim, {
      model: result.response.model,
      usage: JSON.stringify(result.response.usage),
    })
    console.log('  Self-verify:', verification.valid ? '✅ PASS' : '❌ FAIL')
    if (!verification.valid) {
      console.log('  Errors:', verification.errors)
    }
  }

  return result
}

async function testDirectGemini() {
  if (!GEMINI_KEY) {
    console.log('⏭️  Skipping Gemini (no GEMINI_API_KEY)')
    return null
  }

  log('🔄 Testing Gemini direct call...')

  const result = await directCall({
    provider: 'gemini',
    apiKey: GEMINI_KEY,
    geminiModel: 'gemini-2.5-flash',
    requestBody: {
      contents: [{ parts: [{ text: 'Say hello in exactly 3 words.' }] }],
      generationConfig: { maxOutputTokens: 100 },
    },
  })

  if (!result.success) {
    console.error(`❌ Gemini FAIL: ${result.error}`)
    return result
  }

  log('✅ Gemini response received!')
  console.log('  Model:', result.response?.modelVersion)
  console.log('  Usage:', JSON.stringify(result.response?.usageMetadata))
  console.log('  Reply:', result.response?.candidates?.[0]?.content?.parts?.[0]?.text)
  console.log('  Claim:', JSON.stringify(result.claim, null, 2))

  return result
}

async function testDirectClaude() {
  if (!ANTHROPIC_KEY) {
    console.log('⏭️  Skipping Claude (no ANTHROPIC_API_KEY)')
    return null
  }

  log('🔄 Testing Claude direct call...')

  const result = await directCall({
    provider: 'claude',
    apiKey: ANTHROPIC_KEY,
    requestBody: {
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 20,
      messages: [{ role: 'user', content: 'Say hello in exactly 3 words.' }],
    },
  })

  if (!result.success) {
    console.error(`❌ Claude FAIL: ${result.error}`)
    return result
  }

  log('✅ Claude response received!')
  console.log('  Model:', result.response?.model)
  console.log('  Usage:', JSON.stringify(result.response?.usage))
  console.log('  Reply:', result.response?.content?.[0]?.text)
  console.log('  Claim:', JSON.stringify(result.claim, null, 2))

  return result
}

// --- Attestor Tests ---

async function testAttestorOpenAI() {
  if (!OPENAI_KEY) {
    console.log('⏭️  Skipping OpenAI attestor (no OPENAI_API_KEY)')
    return null
  }

  log('🔄 Testing OpenAI attestation via Reclaim...')

  const { createAllHashClaim } = await loadClaimBuilder()
  const result = await createAllHashClaim({
    provider: 'openai',
    apiKey: OPENAI_KEY,
    requestBody: {
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'Say hello in exactly 3 words.' }],
      max_tokens: 20,
    },
    attestorUrl: ATTESTOR_URL,
    onStep: (step) => log(`  step: ${step.name}`),
  })

  if (!result.success) {
    console.error(`❌ OpenAI attestor FAIL: ${result.error}`)
    return result
  }

  log('✅ OpenAI attested claim created!')
  console.log('  Claim:', JSON.stringify(result.claim, null, 2))

  return result
}

async function testAttestorGemini() {
  if (!GEMINI_KEY) {
    console.log('⏭️  Skipping Gemini attestor (no GEMINI_API_KEY)')
    return null
  }

  log('🔄 Testing Gemini attestation via Reclaim...')

  const { createAllHashClaim } = await loadClaimBuilder()
  const result = await createAllHashClaim({
    provider: 'gemini',
    apiKey: GEMINI_KEY,
    geminiModel: 'gemini-2.5-flash',
    requestBody: {
      contents: [{ parts: [{ text: 'Say hello in exactly 3 words.' }] }],
      generationConfig: { maxOutputTokens: 20 },
    },
    attestorUrl: ATTESTOR_URL,
    onStep: (step) => log(`  step: ${step.name}`),
  })

  if (!result.success) {
    console.error(`❌ Gemini attestor FAIL: ${result.error}`)
    return result
  }

  log('✅ Gemini attested claim created!')
  console.log('  Claim:', JSON.stringify(result.claim, null, 2))

  return result
}

async function testAttestorClaude() {
  if (!ANTHROPIC_KEY) {
    console.log('⏭️  Skipping Claude attestor (no ANTHROPIC_API_KEY)')
    return null
  }

  log('🔄 Testing Claude attestation via Reclaim...')

  const { createAllHashClaim } = await loadClaimBuilder()
  const result = await createAllHashClaim({
    provider: 'claude',
    apiKey: ANTHROPIC_KEY,
    requestBody: {
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 20,
      messages: [{ role: 'user', content: 'Say hello in exactly 3 words.' }],
    },
    attestorUrl: ATTESTOR_URL,
    onStep: (step) => log(`  step: ${step.name}`),
  })

  if (!result.success) {
    console.error(`❌ Claude attestor FAIL: ${result.error}`)
    return result
  }

  log('✅ Claude attested claim created!')
  console.log('  Claim:', JSON.stringify(result.claim, null, 2))

  return result
}

// --- Verification Tests ---

async function testVerification() {
  log('🔄 Testing verification logic...')

  const knownModel = 'gpt-4o-mini'
  const knownUsage = '{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}'

  const mockClaim = {
    usage_hash: computeOprfHash(knownUsage),
    model_hash: computeOprfHash(knownModel),
    prompt_hash: computeOprfHash('test prompt'),
    response_hash: computeOprfHash('test response'),
    endpoint: 'openai:https://api.openai.com/v1/chat/completions',
    timestamp: Math.floor(Date.now() / 1000),
    attestor_sig: '0xmocksig',
    zk_proof: 'bW9jaw==',
  }

  // Verify with correct values
  const result1 = verifyClaim(mockClaim, {
    usage: knownUsage,
    model: knownModel,
  })
  console.assert(result1.valid, 'Verification with correct values should pass')
  console.assert(result1.fields.every(f => f.match), 'All fields should match')
  log('  ✅ Correct values verify successfully')

  // Verify with wrong values
  const result2 = verifyClaim(mockClaim, {
    model: 'gpt-3.5-turbo',
  })
  console.assert(!result2.valid, 'Verification with wrong values should fail')
  console.assert(result2.errors.length > 0, 'Should have errors')
  log('  ✅ Wrong values correctly rejected')

  // Verify expired timestamp
  const oldClaim = { ...mockClaim, timestamp: Math.floor(Date.now() / 1000) - 7200 }
  const result3 = verifyClaim(oldClaim, { model: knownModel }, { maxAge: 3600 })
  console.assert(!result3.valid, 'Expired claim should fail')
  log('  ✅ Expired timestamp correctly rejected')

  log('✅ Verification tests passed!')
}

// --- Main ---

async function main() {
  console.log('🦀 tee-attestor-real — Phase 2 Integration Tests\n')
  console.log(`Mode: ${USE_ATTESTOR ? 'ATTESTOR (via Reclaim)' : 'DIRECT (local calls)'}\n`)

  const targetProvider = process.env.PROVIDER

  // Always run verification tests
  await testVerification()

  const results: Record<string, any> = {}

  if (USE_ATTESTOR) {
    // Attestor mode — route through Reclaim
    if (!targetProvider || targetProvider === 'openai') {
      results.openai = await testAttestorOpenAI()
    }
    if (!targetProvider || targetProvider === 'gemini') {
      results.gemini = await testAttestorGemini()
    }
    if (!targetProvider || targetProvider === 'claude') {
      results.claude = await testAttestorClaude()
    }
  } else {
    // Direct mode — call APIs directly
    if (!targetProvider || targetProvider === 'openai') {
      results.openai = await testDirectOpenAI()
    }
    if (!targetProvider || targetProvider === 'gemini') {
      results.gemini = await testDirectGemini()
    }
    if (!targetProvider || targetProvider === 'claude') {
      results.claude = await testDirectClaude()
    }
  }

  // Summary
  console.log('\n--- Summary ---')
  const tested = Object.entries(results).filter(([, v]) => v !== null)
  const passed = tested.filter(([, v]) => v?.success)
  const failed = tested.filter(([, v]) => v && !v.success)
  const skipped = Object.entries(results).filter(([, v]) => v === null)

  console.log(`Tested: ${tested.length} | Passed: ${passed.length} | Failed: ${failed.length} | Skipped: ${skipped.length}`)

  if (failed.length > 0) {
    console.log('\nFailed providers:')
    for (const [name, result] of failed) {
      console.log(`  ❌ ${name}: ${result.error}`)
    }
  }

  if (tested.length === 0) {
    console.log('\n⚠️  No API keys configured. Set at least one of:')
    console.log('  OPENAI_API_KEY, GEMINI_API_KEY, ANTHROPIC_API_KEY')
    console.log('  in .env or environment variables.')
  }

  // Save claims to file if any succeeded
  const claims = Object.fromEntries(
    passed.map(([name, result]) => [name, result.claim])
  )
  if (Object.keys(claims).length > 0) {
    const outFile = `claims-${USE_ATTESTOR ? 'attested' : 'direct'}-${Date.now()}.json`
    writeFileSync(outFile, JSON.stringify(claims, null, 2))
    console.log(`\n📄 Claims saved to ${outFile}`)
  }

  console.log('\n✅ Integration tests completed!')

  if (failed.length > 0) {
    process.exit(1)
  }
}

main().catch(err => {
  console.error('Fatal error:', err)
  process.exit(1)
})
