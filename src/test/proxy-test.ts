/**
 * Proxy Integration Test
 *
 * Tests the attestor proxy with real API calls.
 * The proxy intercepts traffic, generates claims, and stores them locally.
 *
 * Usage:
 *   GEMINI_API_KEY=... npx ts-node src/test/proxy-test.ts
 *   OPENAI_API_KEY=... npx ts-node src/test/proxy-test.ts
 *   ANTHROPIC_API_KEY=... npx ts-node src/test/proxy-test.ts
 */

import http from 'http'
import { startProxy } from '../proxy-server'
import { verifyClaim } from '../verify'
import dotenv from 'dotenv'
dotenv.config()

const PROXY_PORT = 18766  // Use different port for tests
let server: http.Server
let passed = 0
let failed = 0
let skipped = 0

function assert(cond: boolean, msg: string) {
  if (cond) {
    console.log(`  ✅ ${msg}`)
    passed++
  } else {
    console.log(`  ❌ ${msg}`)
    failed++
  }
}

function proxyRequest(
  path: string,
  body: object,
  headers: Record<string, string> = {},
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: any }> {
  return new Promise((resolve, reject) => {
    const bodyStr = JSON.stringify(body)
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: PROXY_PORT,
        path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(Buffer.byteLength(bodyStr)),
          ...headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString()
          let body: any
          try { body = JSON.parse(raw) } catch { body = raw }
          resolve({ statusCode: res.statusCode || 0, headers: res.headers, body })
        })
      },
    )
    req.on('error', reject)
    req.write(bodyStr)
    req.end()
  })
}

function proxyGet(path: string): Promise<any> {
  return new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${PROXY_PORT}${path}`, (res) => {
      const chunks: Buffer[] = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString())) }
        catch { resolve(null) }
      })
    }).on('error', reject)
  })
}

// ─── Tests ───────────────────────────────────────────────────────────

async function testHealth() {
  console.log('\n📋 Health Check')
  const health = await proxyGet('/attestor/health')
  assert(health.status === 'ok', 'Health endpoint returns ok')
  assert(health.mode === 'proxy-interceptor', 'Mode is proxy-interceptor')
}

async function testGeminiProxy() {
  const apiKey = process.env.GEMINI_API_KEY
  if (!apiKey) { console.log('\n⏭️  Gemini: skipped (no GEMINI_API_KEY)'); skipped++; return }

  console.log('\n🔷 Gemini Proxy Test')
  const model = 'gemini-2.5-flash'
  const requestBody = {
    contents: [{ parts: [{ text: 'Reply with exactly: PROXY_TEST_OK' }] }],
    generationConfig: { maxOutputTokens: 100 },
  }

  const res = await proxyRequest(
    `/v1beta/models/${model}:generateContent?key=${apiKey}`,
    requestBody,
  )

  assert(res.statusCode === 200, `Status: ${res.statusCode}`)
  assert(!!res.headers['x-attestor-claim-id'], `Claim ID: ${res.headers['x-attestor-claim-id']}`)

  // Verify the claim
  const claimId = res.headers['x-attestor-claim-id'] as string
  if (claimId) {
    const record = await proxyGet(`/attestor/claims/${claimId}`)
    assert(record !== null, 'Claim retrievable from store')
    assert(record.provider === 'gemini', `Provider: ${record.provider}`)

    // Verify response hash
    const parts = res.body.candidates?.[0]?.content?.parts
    let responseText = ''
    if (Array.isArray(parts)) {
      for (let i = parts.length - 1; i >= 0; i--) {
        if (parts[i].text !== undefined) { responseText = parts[i].text; break }
      }
    }
    if (responseText) {
      const verifyResult = verifyClaim(record.claim, { response: responseText }, { maxAge: 60 })
      assert(verifyResult.fields.some(f => f.field === 'response' && f.match), 'Response hash verified')
    }

    console.log(`  📄 Reply: "${responseText.slice(0, 80)}"`)
  }
}

async function testOpenAIProxy() {
  const apiKey = process.env.OPENAI_API_KEY
  if (!apiKey) { console.log('\n⏭️  OpenAI: skipped (no OPENAI_API_KEY)'); skipped++; return }

  console.log('\n🟢 OpenAI Proxy Test')
  const requestBody = {
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: 'Reply with exactly: PROXY_TEST_OK' }],
    max_tokens: 50,
  }

  const res = await proxyRequest(
    '/v1/chat/completions',
    requestBody,
    { Authorization: `Bearer ${apiKey}` },
  )

  assert(res.statusCode === 200 || res.statusCode === 429, `Status: ${res.statusCode}`)

  if (res.statusCode === 200) {
    assert(!!res.headers['x-attestor-claim-id'], `Claim ID: ${res.headers['x-attestor-claim-id']}`)
    const responseText = res.body.choices?.[0]?.message?.content || ''
    console.log(`  📄 Reply: "${responseText.slice(0, 80)}"`)
  } else {
    console.log('  ⚠️  OpenAI quota exceeded, claim not generated')
    skipped++
  }
}

async function testClaudeProxy() {
  const apiKey = process.env.ANTHROPIC_API_KEY
  if (!apiKey) { console.log('\n⏭️  Claude: skipped (no ANTHROPIC_API_KEY)'); skipped++; return }

  console.log('\n🟣 Claude Proxy Test')
  const requestBody = {
    model: 'claude-haiku-4-5-20251001',
    messages: [{ role: 'user', content: 'Reply with exactly: PROXY_TEST_OK' }],
    max_tokens: 50,
  }

  const res = await proxyRequest(
    '/v1/messages',
    requestBody,
    {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
  )

  assert(res.statusCode === 200, `Status: ${res.statusCode}`)

  if (res.statusCode === 200) {
    assert(!!res.headers['x-attestor-claim-id'], `Claim ID: ${res.headers['x-attestor-claim-id']}`)
    const responseText = res.body.content?.[0]?.text || ''
    console.log(`  📄 Reply: "${responseText.slice(0, 80)}"`)
  }
}

async function testUnknownRoute() {
  console.log('\n🚫 Unknown Route Test')
  const res = await proxyRequest('/v2/unknown', { test: true })
  assert(res.statusCode === 400, `Status: ${res.statusCode}`)
  assert(res.body.error?.includes('Unknown provider'), 'Returns unknown provider error')
}

async function testClaimsList() {
  console.log('\n📚 Claims List Test')
  const claims = await proxyGet('/attestor/claims')
  assert(Array.isArray(claims.claims), 'Returns claims array')
  assert(typeof claims.count === 'number', `Count: ${claims.count}`)
  console.log(`  📊 Total claims stored: ${claims.count}`)
}

// ─── Runner ──────────────────────────────────────────────────────────

async function main() {
  console.log('═══════════════════════════════════════════')
  console.log(' Attestor Proxy Integration Test')
  console.log(' Mode: Plan B — Proxy Interceptor')
  console.log('═══════════════════════════════════════════')

  // Start proxy on test port
  process.env.ATTESTOR_PROXY_PORT = String(PROXY_PORT)
  process.env.CLAIMS_DIR = '/tmp/attestor-proxy-test-claims'
  server = startProxy(PROXY_PORT)

  // Wait for server to be ready
  await new Promise(r => setTimeout(r, 500))

  try {
    await testHealth()
    await testUnknownRoute()
    await testGeminiProxy()
    await testOpenAIProxy()
    await testClaudeProxy()
    await testClaimsList()
  } finally {
    server.close()
  }

  console.log('\n═══════════════════════════════════════════')
  console.log(` Results: ${passed} passed, ${failed} failed, ${skipped} skipped`)
  console.log('═══════════════════════════════════════════')

  if (failed > 0) process.exit(1)
}

main().catch(e => { console.error(e); process.exit(1) })
