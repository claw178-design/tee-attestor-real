/**
 * End-to-End Test — Tests the full TEE attestor flow
 *
 * Tests:
 * 1. Health + attestation endpoints
 * 2. Sign + verify flow (HTTP signing)
 * 3. WebSocket connectivity (attestor-core /ws)
 * 4. On-chain contract read
 *
 * Usage:
 *   npx ts-node src/test/e2e-test.ts
 *   TEE_URL=https://zktls.judgeclaw.xyz:8080 npx ts-node src/test/e2e-test.ts
 */

import { createHash, createSign, generateKeyPairSync, randomBytes } from 'crypto'
import { config } from 'dotenv'

config({ path: `${__dirname}/../../.env` })

const TEE_URL = process.env.TEE_URL || 'https://zktls.judgeclaw.xyz:8080'

function sha256(data: string): string {
  return '0x' + createHash('sha256').update(data).digest('hex')
}

function log(msg: string) {
  console.log(`[${new Date().toISOString()}] ${msg}`)
}

async function fetchJson(url: string, opts?: RequestInit): Promise<any> {
  const res = await fetch(url, opts)
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
  return res.json()
}

// --- Test 1: Health ---
async function testHealth(): Promise<boolean> {
  log('Test 1: Health endpoint...')
  const data = await fetchJson(`${TEE_URL}/health`)
  console.log('  Status:', data.status)
  console.log('  Mode:', data.mode)
  console.log('  Fingerprint:', data.fingerprint)
  console.log('  Signs:', data.signs)
  console.log('  Uptime:', Math.round(data.uptime), 'seconds')
  const ok = data.status === 'ok'
  log(`  Health: ${ok ? 'PASS' : 'FAIL'}`)
  return ok
}

// --- Test 2: Attestation ---
async function testAttestation(): Promise<boolean> {
  log('Test 2: Attestation endpoint...')
  const data = await fetchJson(`${TEE_URL}/attestation`)
  console.log('  is_tee:', data.is_tee)
  console.log('  tee_type:', data.tee_type)
  console.log('  app_id:', data.app_id)
  console.log('  image_digest:', data.image_digest)
  console.log('  evm_address:', data.evm_address)
  console.log('  dashboard:', data.dashboard_url)
  const ok = data.ok && data.is_tee
  log(`  Attestation: ${ok ? 'PASS' : 'FAIL'}`)
  return ok
}

// --- Test 3: Sign + Verify ---
async function testSignVerify(): Promise<boolean> {
  log('Test 3: Sign + Verify flow...')

  const testClaim = {
    usage_hash: sha256('{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}'),
    model_hash: sha256('gemini-2.5-flash'),
    prompt_hash: sha256('Hello, world!'),
    response_hash: sha256('Hi there!'),
    endpoint: 'gemini:https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash',
    timestamp: Math.floor(Date.now() / 1000),
  }

  // Sign
  const signResult = await fetchJson(`${TEE_URL}/sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(testClaim),
  })

  const signedClaim = signResult.claim || signResult
  console.log('  Attestor sig:', signedClaim.attestor_sig?.substring(0, 40) + '...')
  console.log('  TEE measurement:', signedClaim.tee_measurement)
  console.log('  App ID:', signedClaim.app_id)

  if (!signedClaim.attestor_sig) {
    log('  Sign: FAIL (no signature)')
    return false
  }

  // Verify
  const verifyResult = await fetchJson(`${TEE_URL}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ claim: signedClaim }),
  })

  console.log('  Verify result:', verifyResult.valid)
  console.log('  Fingerprint:', verifyResult.fingerprint)

  const ok = verifyResult.valid === true
  log(`  Sign+Verify: ${ok ? 'PASS' : 'FAIL'}`)
  return ok
}

// --- Test 4: EIP-712 Sign ---
async function testEthSign(): Promise<boolean> {
  log('Test 4: EIP-712 Sign...')

  const testClaim = {
    usage_hash: sha256('{"tokens":200}'),
    model_hash: sha256('claude-haiku-4-5-20251001'),
    prompt_hash: sha256('Test EIP-712'),
    response_hash: sha256('OK'),
    endpoint: 'claude:https://api.anthropic.com/v1/messages',
    timestamp: Math.floor(Date.now() / 1000),
  }

  try {
    const result = await fetchJson(`${TEE_URL}/eth-sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(testClaim),
    })

    console.log('  EIP-712 signature:', result.eip712_signature?.substring(0, 40) + '...')
    console.log('  Signer address:', result.signer_address)
    const ok = !!result.eip712_signature
    log(`  EIP-712 Sign: ${ok ? 'PASS' : 'FAIL'}`)
    return ok
  } catch (err: any) {
    log(`  EIP-712 Sign: FAIL (${err.message})`)
    return false
  }
}

// --- Test 5: WebSocket Connectivity ---
async function testWebSocket(): Promise<boolean> {
  log('Test 5: WebSocket connectivity (/ws)...')

  const wsUrl = TEE_URL.replace('https://', 'wss://').replace('http://', 'ws://') + '/ws'
  console.log('  Connecting to:', wsUrl)

  return new Promise<boolean>((resolve) => {
    const timeout = setTimeout(() => {
      log('  WebSocket: TIMEOUT (10s)')
      resolve(false)
    }, 10000)

    import('ws').then(({ default: WS }) => {
      const ws = new WS(wsUrl)

      ws.on('open', () => {
        console.log('  WebSocket connected!')
        clearTimeout(timeout)
        ws.close()
        log('  WebSocket: PASS')
        resolve(true)
      })

      ws.on('error', (err: any) => {
        clearTimeout(timeout)
        log(`  WebSocket: FAIL (${err.message})`)
        resolve(false)
      })
    }).catch((err) => {
      clearTimeout(timeout)
      log(`  WebSocket: FAIL (ws module not found: ${err.message})`)
      resolve(false)
    })
  })
}

// --- Test 6: Public Key ---
async function testPubKey(): Promise<boolean> {
  log('Test 6: Public key endpoint...')
  const data = await fetchJson(`${TEE_URL}/pubkey`)
  console.log('  Fingerprint:', data.fingerprint)
  console.log('  PEM (first 60):', data.publicKey?.substring(0, 60) + '...')
  const ok = !!data.publicKey && !!data.fingerprint
  log(`  PubKey: ${ok ? 'PASS' : 'FAIL'}`)
  return ok
}

// --- Test 7: Real API Sign (Gemini) ---
async function testRealApiSign(): Promise<boolean> {
  const geminiKey = process.env.GEMINI_API_KEY
  if (!geminiKey) {
    log('Test 7: Skipped (no GEMINI_API_KEY)')
    return true
  }

  log('Test 7: Real Gemini API call + sign...')

  // Call Gemini API directly
  const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`
  const geminiRes = await fetch(geminiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: 'Reply with one word: hello' }] }],
      generationConfig: { maxOutputTokens: 10 },
    }),
  })

  if (!geminiRes.ok) {
    log(`  Gemini API: FAIL (${geminiRes.status})`)
    return false
  }

  const geminiData: any = await geminiRes.json()
  const responseText = geminiData.candidates?.[0]?.content?.parts?.[0]?.text || ''
  const usage = geminiData.usageMetadata || {}
  const model = geminiData.modelVersion || 'gemini-2.5-flash'

  console.log('  Gemini response:', responseText.trim())
  console.log('  Usage:', JSON.stringify(usage))

  // Build claim from real data
  const realClaim = {
    usage_hash: sha256(JSON.stringify(usage)),
    model_hash: sha256(model),
    prompt_hash: sha256('Reply with one word: hello'),
    response_hash: sha256(responseText),
    endpoint: 'gemini:https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash',
    timestamp: Math.floor(Date.now() / 1000),
  }

  // Sign via TEE
  const signResult = await fetchJson(`${TEE_URL}/sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(realClaim),
  })

  console.log('  Claim ID:', signResult.claim_id)
  console.log('  Attestor sig present:', !!signResult.attestor_sig)

  // Verify
  const verifyResult = await fetchJson(`${TEE_URL}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ claim: signResult }),
  })

  console.log('  Verify:', verifyResult.valid)

  // Self-verify: recompute hashes locally
  const localUsageHash = sha256(JSON.stringify(usage))
  const localModelHash = sha256(model)
  const hashMatch = localUsageHash === signResult.usage_hash && localModelHash === signResult.model_hash
  console.log('  Local hash verification:', hashMatch ? 'MATCH' : 'MISMATCH')

  const ok = verifyResult.valid && hashMatch
  log(`  Real API Sign: ${ok ? 'PASS' : 'FAIL'}`)
  return ok
}

// --- Main ---
async function main() {
  console.log('═══════════════════════════════════════════════════')
  console.log('  tee-attestor-real — End-to-End Test Suite')
  console.log('  TEE URL:', TEE_URL)
  console.log('═══════════════════════════════════════════════════\n')

  const results: Record<string, boolean> = {}

  results['health'] = await testHealth()
  console.log()

  results['attestation'] = await testAttestation()
  console.log()

  results['sign_verify'] = await testSignVerify()
  console.log()

  results['eth_sign'] = await testEthSign()
  console.log()

  results['websocket'] = await testWebSocket()
  console.log()

  results['pubkey'] = await testPubKey()
  console.log()

  results['real_api'] = await testRealApiSign()
  console.log()

  // Summary
  console.log('═══════════════════════════════════════════════════')
  console.log('  RESULTS')
  console.log('═══════════════════════════════════════════════════')

  let passed = 0, failed = 0
  for (const [name, ok] of Object.entries(results)) {
    const status = ok ? 'PASS' : 'FAIL'
    const icon = ok ? '✅' : '❌'
    console.log(`  ${icon} ${name}: ${status}`)
    if (ok) passed++; else failed++
  }

  console.log()
  console.log(`  Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`)
  console.log('═══════════════════════════════════════════════════')

  process.exit(failed > 0 ? 1 : 0)
}

main().catch(err => {
  console.error('Fatal:', err)
  process.exit(1)
})
