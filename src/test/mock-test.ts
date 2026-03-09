/**
 * Mock test — Phase 1: Local validation without real API.
 *
 * Tests:
 * 1. Provider param building (OpenAI, Gemini, Claude)
 * 2. All-Hash redaction strategy (all fields use OPRF)
 * 3. Secret params isolation (API keys never in params)
 * 4. Claim structure validation
 */

import {
  buildOpenAIProviderParams,
  buildGeminiProviderParams,
  buildClaudeProviderParams,
} from '../providers'

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`❌ FAIL: ${msg}`)
    process.exit(1)
  }
  console.log(`✅ PASS: ${msg}`)
}

function testOpenAIProvider() {
  console.log('\n--- OpenAI Provider ---')
  const { params, secretParams } = buildOpenAIProviderParams(
    'sk-test-key-12345',
    {
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hello' }],
    },
  )

  const p = params as any
  const s = secretParams as any

  // URL correct
  assert(p.url === 'https://api.openai.com/v1/chat/completions', 'URL matches')

  // API key in secretParams only
  assert(s.headers?.Authorization === 'Bearer sk-test-key-12345', 'API key in secretParams')
  assert(!p.headers?.Authorization, 'API key NOT in params headers')

  // All response fields use OPRF hash
  assert(p.responseRedactions.length >= 3, 'Has response redactions')
  for (const r of p.responseRedactions) {
    assert(r.hash === 'oprf', `Redaction ${r.jsonPath} uses OPRF hash`)
  }

  // Body is serialized
  assert(typeof p.body === 'string', 'Body is JSON string')
  assert(JSON.parse(p.body).model === 'gpt-4', 'Body contains model')
}

function testGeminiProvider() {
  console.log('\n--- Gemini Provider ---')
  const { params, secretParams } = buildGeminiProviderParams(
    'AIzaSy-test-key',
    'gemini-1.5-pro',
    {
      contents: [{ parts: [{ text: 'Hello' }] }],
    },
  )

  const p = params as any
  const s = secretParams as any

  // URL contains model but key is templated
  assert(p.url.includes('gemini-1.5-pro'), 'URL contains model')
  assert(p.url.includes('{{apiKey}}'), 'API key is templated in URL')

  // Key in secretParams.paramValues
  assert(s.paramValues?.apiKey === 'AIzaSy-test-key', 'API key in secretParams.paramValues')

  // OPRF redactions
  for (const r of p.responseRedactions) {
    assert(r.hash === 'oprf', `Redaction ${r.jsonPath} uses OPRF hash`)
  }
}

function testClaudeProvider() {
  console.log('\n--- Claude Provider ---')
  const { params, secretParams } = buildClaudeProviderParams(
    'sk-ant-api03-test-key',
    {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      messages: [{ role: 'user', content: 'Hello' }],
    },
  )

  const p = params as any
  const s = secretParams as any

  // URL
  assert(p.url === 'https://api.anthropic.com/v1/messages', 'URL matches')

  // API key in secretParams headers
  assert(s.headers?.['x-api-key'] === 'sk-ant-api03-test-key', 'API key in secretParams')
  assert(!p.headers?.['x-api-key'], 'API key NOT in params headers')

  // anthropic-version header is public (not sensitive)
  assert(p.headers?.['anthropic-version'] === '2023-06-01', 'Version header is public')

  // OPRF redactions
  for (const r of p.responseRedactions) {
    assert(r.hash === 'oprf', `Redaction ${r.jsonPath} uses OPRF hash`)
  }
}

function testAllHashStrategy() {
  console.log('\n--- All-Hash Strategy Verification ---')

  const providers = [
    { name: 'OpenAI', build: () => buildOpenAIProviderParams('k', { model: 'gpt-4', messages: [] }) },
    { name: 'Gemini', build: () => buildGeminiProviderParams('k', 'gemini-pro', { contents: [] }) },
    { name: 'Claude', build: () => buildClaudeProviderParams('k', { model: 'claude-3', max_tokens: 1, messages: [] }) },
  ]

  for (const prov of providers) {
    const { params } = prov.build()
    const p = params as any

    // Every redaction must use OPRF — no direct reveal allowed
    for (const r of p.responseRedactions) {
      assert(
        r.hash === 'oprf',
        `${prov.name}: ${r.jsonPath} is OPRF (not direct reveal)`,
      )
    }

    // No API key in params
    const paramsStr = JSON.stringify(params)
    assert(!paramsStr.includes('sk-'), `${prov.name}: No API key leak in params`)
    assert(!paramsStr.includes('AIzaSy'), `${prov.name}: No Google key leak in params`)
  }
}

// Run all tests
console.log('🦀 tee-attestor-real — Phase 1 Mock Tests\n')
testOpenAIProvider()
testGeminiProvider()
testClaudeProvider()
testAllHashStrategy()
console.log('\n✅ All tests passed!')
