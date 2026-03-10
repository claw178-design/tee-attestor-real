/**
 * Attestor Proxy Server — Plan B Architecture
 *
 * Sits between OpenClaw gateway and upstream LLM APIs.
 * Intercepts real API traffic, extracts response data,
 * generates OPRF hashes, and stores claims locally.
 *
 * API keys flow through from the gateway — never stored in claims.
 *
 * Flow:
 *   OpenClaw Gateway → Proxy (localhost:8766) → Real API
 *                          ↓
 *                    Extract fields → Hash → Store Claim
 */

import http from 'http'
import https from 'https'
import { createHash } from 'crypto'
import { existsSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from 'fs'
import { join } from 'path'
import { computeOprfHash } from './verify'
import type { AllHashClaim } from './types/claim'
import { forwardStream, buildClaimFromStream } from './proxy-streaming'

// ─── Configuration ───────────────────────────────────────────────────

const PROXY_PORT = parseInt(process.env.ATTESTOR_PROXY_PORT || '8766', 10)
const CLAIMS_DIR = process.env.CLAIMS_DIR || join(__dirname, '..', 'claims')

// Provider detection from request path
interface ProviderRoute {
  name: string
  upstream: { host: string; port: number }
  pathPrefix: string
  /** Extract auth header name to strip from claim (but forward to upstream) */
  authHeader: string
  /** Extract response fields for hashing */
  extractFields: (data: any) => { usage: string; model: string; response: string }
}

const ROUTES: ProviderRoute[] = [
  {
    name: 'openai',
    upstream: { host: 'api.openai.com', port: 443 },
    pathPrefix: '/v1/chat/completions',
    authHeader: 'authorization',
    extractFields: (data) => ({
      usage: JSON.stringify(data.usage || {}),
      model: data.model || '',
      response: data.choices?.[0]?.message?.content || '',
    }),
  },
  {
    name: 'claude',
    upstream: { host: 'api.anthropic.com', port: 443 },
    pathPrefix: '/v1/messages',
    authHeader: 'x-api-key',
    extractFields: (data) => ({
      usage: JSON.stringify(data.usage || {}),
      model: data.model || '',
      response: data.content?.[0]?.text || '',
    }),
  },
  {
    name: 'gemini',
    upstream: { host: 'generativelanguage.googleapis.com', port: 443 },
    pathPrefix: '/v1beta/models/',
    authHeader: '',  // key is in URL query param
    extractFields: (data) => {
      // Handle thinking models: find last text part
      const parts = data.candidates?.[0]?.content?.parts
      let text = ''
      if (Array.isArray(parts)) {
        for (let i = parts.length - 1; i >= 0; i--) {
          if (parts[i].text !== undefined) { text = parts[i].text; break }
        }
      }
      return {
        usage: JSON.stringify(data.usageMetadata || {}),
        model: data.modelVersion || '',
        response: text,
      }
    },
  },
]

// ─── Claim Storage ───────────────────────────────────────────────────

function ensureClaimsDir() {
  if (!existsSync(CLAIMS_DIR)) {
    mkdirSync(CLAIMS_DIR, { recursive: true })
  }
}

function storeClaim(claim: AllHashClaim, provider: string, requestBody: any): string {
  ensureClaimsDir()
  const id = createHash('sha256')
    .update(`${claim.timestamp}-${provider}-${Math.random()}`)
    .digest('hex')
    .slice(0, 16)
  const filename = `${id}.json`
  const record = {
    id,
    provider,
    claim,
    prompt_hash: claim.prompt_hash,
    created_at: new Date().toISOString(),
  }
  writeFileSync(join(CLAIMS_DIR, filename), JSON.stringify(record, null, 2))
  return id
}

function listClaims(limit = 50): any[] {
  ensureClaimsDir()
  const files = readdirSync(CLAIMS_DIR)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse()
    .slice(0, limit)
  return files.map(f => {
    try { return JSON.parse(readFileSync(join(CLAIMS_DIR, f), 'utf-8')) }
    catch { return null }
  }).filter(Boolean)
}

function getClaim(id: string): any | null {
  const filepath = join(CLAIMS_DIR, `${id}.json`)
  if (!existsSync(filepath)) return null
  try { return JSON.parse(readFileSync(filepath, 'utf-8')) }
  catch { return null }
}

// ─── Provider Detection ──────────────────────────────────────────────

function detectProvider(
  path: string,
  headers: http.IncomingHttpHeaders,
): ProviderRoute | null {
  // Check custom header first (explicit override)
  const target = headers['x-attestor-target'] as string | undefined
  if (target) {
    const route = ROUTES.find(r => r.name === target.toLowerCase())
    if (route) return route
  }

  // Auto-detect from path
  for (const route of ROUTES) {
    if (path.startsWith(route.pathPrefix)) return route
  }

  return null
}

// ─── Request Body Reader ─────────────────────────────────────────────

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => resolve(Buffer.concat(chunks).toString()))
    req.on('error', reject)
  })
}

// ─── Upstream HTTPS Call ─────────────────────────────────────────────

function forwardToUpstream(
  route: ProviderRoute,
  method: string,
  path: string,
  headers: Record<string, string>,
  body: string,
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: route.upstream.host,
        port: route.upstream.port,
        path,
        method,
        headers: {
          ...headers,
          host: route.upstream.host,
          'content-length': String(Buffer.byteLength(body)),
        },
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 500,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          })
        })
      },
    )
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

// ─── Build Claim from Intercepted Data ───────────────────────────────

function buildClaimFromIntercept(
  route: ProviderRoute,
  requestBody: any,
  responseData: any,
): AllHashClaim {
  const fields = route.extractFields(responseData)

  return {
    usage_hash: computeOprfHash(fields.usage),
    model_hash: computeOprfHash(fields.model),
    prompt_hash: computeOprfHash(JSON.stringify(requestBody)),
    response_hash: computeOprfHash(fields.response),
    endpoint: `${route.name}:https://${route.upstream.host}${route.pathPrefix}`,
    timestamp: Math.floor(Date.now() / 1000),
    attestor_sig: 'proxy-intercepted',  // Not attestor-signed, proxy-witnessed
    zk_proof: '',  // Phase 3: add ZK proof via Reclaim attestor
  }
}

// ─── API Endpoints ───────────────────────────────────────────────────

function handleApiRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  path: string,
) {
  // GET /attestor/claims — list recent claims
  if (path === '/attestor/claims' && req.method === 'GET') {
    const claims = listClaims()
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ claims, count: claims.length }))
    return true
  }

  // GET /attestor/claims/:id — get specific claim
  if (path.startsWith('/attestor/claims/') && req.method === 'GET') {
    const id = path.split('/').pop()!
    const claim = getClaim(id)
    if (!claim) {
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Claim not found' }))
    } else {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(claim))
    }
    return true
  }

  // GET /attestor/health — health check
  if (path === '/attestor/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      status: 'ok',
      mode: 'proxy-interceptor',
      claims_stored: listClaims(9999).length,
      uptime: process.uptime(),
    }))
    return true
  }

  return false
}

// ─── Main Proxy Handler ─────────────────────────────────────────────

async function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
) {
  const path = req.url || '/'

  // Handle attestor API endpoints
  if (path.startsWith('/attestor/')) {
    if (handleApiRequest(req, res, path)) return
  }

  // Detect provider from request
  const route = detectProvider(path, req.headers)

  if (!route) {
    res.writeHead(400, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      error: 'Unknown provider. Use X-Attestor-Target header or a known path prefix.',
      known_paths: ROUTES.map(r => r.pathPrefix),
    }))
    return
  }

  try {
    // Read request body
    const bodyStr = await readBody(req)

    // Build upstream headers (forward everything except hop-by-hop)
    const upstreamHeaders: Record<string, string> = {}
    const skipHeaders = new Set([
      'host', 'connection', 'transfer-encoding',
      'x-attestor-target', 'x-attestor-skip',
    ])
    for (const [key, val] of Object.entries(req.headers)) {
      if (skipHeaders.has(key.toLowerCase())) continue
      if (val) upstreamHeaders[key] = Array.isArray(val) ? val[0] : val
    }

    // Check if claim generation should be skipped (e.g., for streaming)
    const skipClaim = req.headers['x-attestor-skip'] === 'true'

    // Parse request body
    let requestBody: any
    try { requestBody = JSON.parse(bodyStr) } catch { requestBody = bodyStr }
    const isStreaming = requestBody?.stream === true

    // ── Streaming path ──
    if (isStreaming && !skipClaim) {
      try {
        const { statusCode, accumulated } = await forwardStream(
          route.upstream.host,
          route.upstream.port,
          req.method || 'POST',
          path,
          upstreamHeaders,
          bodyStr,
          res,  // Response is already sent to client via stream
        )

        if (statusCode >= 200 && statusCode < 300) {
          const claim = buildClaimFromStream(
            route.name,
            `https://${route.upstream.host}${route.pathPrefix}`,
            requestBody,
            accumulated,
          )
          const claimId = storeClaim(claim, route.name, requestBody)
          console.log(`[${route.name}] Stream claim ${claimId} stored — model: ${accumulated.model}`)
        }
      } catch (e: any) {
        console.error(`[${route.name}] Stream proxy error: ${e.message}`)
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Stream upstream failed', detail: e.message }))
        }
      }
      return
    }

    // ── Non-streaming path ──
    const upstream = await forwardToUpstream(route, req.method || 'POST', path, upstreamHeaders, bodyStr)

    const responseHeaders: Record<string, string> = { 'content-type': 'application/json' }
    if (upstream.headers['content-type']) {
      responseHeaders['content-type'] = upstream.headers['content-type'] as string
    }

    // Generate claim from non-streaming response
    if (!skipClaim && upstream.statusCode >= 200 && upstream.statusCode < 300) {
      try {
        const responseData = JSON.parse(upstream.body)
        const claim = buildClaimFromIntercept(route, requestBody, responseData)
        const claimId = storeClaim(claim, route.name, requestBody)

        responseHeaders['x-attestor-claim-id'] = claimId
        responseHeaders['x-attestor-timestamp'] = String(claim.timestamp)

        console.log(`[${route.name}] Claim ${claimId} stored — model: ${responseData.model || 'unknown'}`)
      } catch (e: any) {
        console.error(`[${route.name}] Claim extraction failed: ${e.message}`)
      }
    }

    res.writeHead(upstream.statusCode, responseHeaders)
    res.end(upstream.body)
  } catch (err: any) {
    console.error(`[${route.name}] Proxy error: ${err.message}`)
    res.writeHead(502, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'Upstream request failed', detail: err.message }))
  }
}

// ─── Server Startup ──────────────────────────────────────────────────

export function startProxy(port = PROXY_PORT): http.Server {
  const server = http.createServer(handleRequest)
  server.listen(port, '127.0.0.1', () => {
    console.log(`[attestor-proxy] Listening on 127.0.0.1:${port}`)
    console.log(`[attestor-proxy] Claims stored in: ${CLAIMS_DIR}`)
    console.log(`[attestor-proxy] Supported providers: ${ROUTES.map(r => r.name).join(', ')}`)
    console.log(`[attestor-proxy] API: http://127.0.0.1:${port}/attestor/health`)
  })
  return server
}

// Run directly
if (require.main === module) {
  startProxy()
}
