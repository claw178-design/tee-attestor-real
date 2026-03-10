/**
 * Integration Test — Tests zkTLS flow through TEE attestor.
 *
 * Routes API calls through TEE attestor-core (WebSocket tunnel),
 * generates ZK proofs, and receives signed claims.
 *
 * No proxy needed — attestor-core IS the tunnel.
 *
 * Prerequisites:
 *   - TEE attestor running (attestor-core WebSocket on port 8001)
 *   - Set API keys in .env: GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY
 *
 * Usage:
 *   npx ts-node src/test/integration-test.ts
 *   PROVIDER=gemini npx ts-node src/test/integration-test.ts
 */

import { config } from 'dotenv'
import { randomBytes } from 'crypto'
import { writeFileSync } from 'fs'
import { verifyClaim, computeOprfHash } from '../verify'

config({ path: `${__dirname}/../../.env` })

const ATTESTOR_URL = process.env.ATTESTOR_URL || 'ws://localhost:8001/ws'
const OPENAI_KEY = process.env.OPENAI_API_KEY
const GEMINI_KEY = process.env.GEMINI_API_KEY
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY

function log(msg: string) {
  console.log(`[${new Date().toISOString()}] ${msg}`)
}

// --- zkTLS Tests ---

async function testZkTlsGemini() {
  if (!GEMINI_KEY) {
    console.log('  Skipping Gemini (no GEMINI_API_KEY)')
    return null
  }

  log('Testing Gemini zkTLS claim...')

  const { createGeminiClaim } = await import('../zktls-client')
  const result = await createGeminiClaim(
    {
      attestorUrl: ATTESTOR_URL,
      ownerPrivateKey: randomBytes(32).toString('hex'),
      onStep: (step) => log(`  step: ${step.name}`),
    },
    GEMINI_KEY,
    'gemini-2.5-flash',
    {
      contents: [{ parts: [{ text: 'Say hello in one word.' }] }],
      generationConfig: { maxOutputTokens: 20 },
    },
  )

  log('Gemini claim received!')
  console.log('  Claim:', JSON.stringify(result.claim, null, 2))

  return { success: true, claim: result.claim }
}

async function testZkTlsOpenAI() {
  if (!OPENAI_KEY) {
    console.log('  Skipping OpenAI (no OPENAI_API_KEY)')
    return null
  }

  log('Testing OpenAI zkTLS claim...')

  const { createOpenAIClaim } = await import('../zktls-client')
  const result = await createOpenAIClaim(
    {
      attestorUrl: ATTESTOR_URL,
      ownerPrivateKey: randomBytes(32).toString('hex'),
      onStep: (step) => log(`  step: ${step.name}`),
    },
    OPENAI_KEY,
    {
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'Say hello in one word.' }],
      max_tokens: 20,
    },
  )

  log('OpenAI claim received!')
  console.log('  Claim:', JSON.stringify(result.claim, null, 2))

  return { success: true, claim: result.claim }
}

async function testZkTlsClaude() {
  if (!ANTHROPIC_KEY) {
    console.log('  Skipping Claude (no ANTHROPIC_API_KEY)')
    return null
  }

  log('Testing Claude zkTLS claim...')

  const { createClaudeClaim } = await import('../zktls-client')
  const result = await createClaudeClaim(
    {
      attestorUrl: ATTESTOR_URL,
      ownerPrivateKey: randomBytes(32).toString('hex'),
      onStep: (step) => log(`  step: ${step.name}`),
    },
    ANTHROPIC_KEY,
    {
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 20,
      messages: [{ role: 'user', content: 'Say hello in one word.' }],
    },
  )

  log('Claude claim received!')
  console.log('  Claim:', JSON.stringify(result.claim, null, 2))

  return { success: true, claim: result.claim }
}

// --- Verification Tests ---

async function testVerification() {
  log('Testing verification logic...')

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

  const result1 = verifyClaim(mockClaim, { usage: knownUsage, model: knownModel })
  console.assert(result1.valid, 'Correct values should pass')
  log('  Correct values verify: PASS')

  const result2 = verifyClaim(mockClaim, { model: 'gpt-3.5-turbo' })
  console.assert(!result2.valid, 'Wrong values should fail')
  log('  Wrong values rejected: PASS')

  log('Verification tests passed!')
}

// --- Main ---

async function main() {
  console.log('tee-attestor-real — zkTLS Integration Tests\n')
  console.log(`Attestor URL: ${ATTESTOR_URL}\n`)

  await testVerification()

  const targetProvider = process.env.PROVIDER
  const results: Record<string, any> = {}

  if (!targetProvider || targetProvider === 'gemini') {
    results.gemini = await testZkTlsGemini()
  }
  if (!targetProvider || targetProvider === 'openai') {
    results.openai = await testZkTlsOpenAI()
  }
  if (!targetProvider || targetProvider === 'claude') {
    results.claude = await testZkTlsClaude()
  }

  // Summary
  console.log('\n--- Summary ---')
  const tested = Object.entries(results).filter(([, v]) => v !== null)
  const passed = tested.filter(([, v]) => v?.success)
  const failed = tested.filter(([, v]) => v && !v.success)

  console.log(`Tested: ${tested.length} | Passed: ${passed.length} | Failed: ${failed.length}`)

  if (passed.length > 0) {
    const claims = Object.fromEntries(passed.map(([name, result]) => [name, result.claim]))
    const outFile = `claims-zktls-${Date.now()}.json`
    writeFileSync(outFile, JSON.stringify(claims, null, 2))
    console.log(`Claims saved to ${outFile}`)
  }

  if (tested.length === 0) {
    console.log('\nNo API keys configured. Set GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY')
  }

  console.log('\nIntegration tests completed!')
  process.exit(failed.length > 0 ? 1 : 0)
}

main().catch(err => {
  console.error('Fatal error:', err)
  process.exit(1)
})
