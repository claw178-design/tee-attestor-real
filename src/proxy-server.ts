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
const TEE_ATTESTOR_URL = process.env.TEE_ATTESTOR_URL || 'http://127.0.0.1:8767'

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
    upstream: {
      host: process.env.CLAUDE_UPSTREAM_HOST || 'api.anthropic.com',
      port: parseInt(process.env.CLAUDE_UPSTREAM_PORT || '443', 10),
    },
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

// ─── Upstream Call (HTTP or HTTPS based on port) ────────────────────

function forwardToUpstream(
  route: ProviderRoute,
  method: string,
  path: string,
  headers: Record<string, string>,
  body: string,
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const isLocal = route.upstream.host === '127.0.0.1' || route.upstream.host === 'localhost'
    const transport = isLocal ? http : https
    const req = transport.request(
      {
        hostname: route.upstream.host,
        port: route.upstream.port,
        path,
        method,
        headers: {
          ...headers,
          host: isLocal ? `${route.upstream.host}:${route.upstream.port}` : route.upstream.host,
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
    req.setTimeout(60000, () => {
      req.destroy(new Error('Upstream request timed out after 60s'))
    })
    if (body) req.write(body)
    req.end()
  })
}

// ─── TEE Attestor Communication ─────────────────────────────────────

/**
 * Send unsigned claim hashes to the TEE attestor for signing.
 * Falls back to 'proxy-intercepted' if TEE is unreachable.
 */
async function requestTeeSigning(unsignedClaim: AllHashClaim): Promise<AllHashClaim> {
  const { attestor_sig, zk_proof, ...signReq } = unsignedClaim

  return new Promise((resolve) => {
    const url = new URL('/sign', TEE_ATTESTOR_URL)
    const body = JSON.stringify(signReq)
    const transport = url.protocol === 'https:' ? https : http

    const req = transport.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(Buffer.byteLength(body)),
        },
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString())
            if (data.ok && data.claim) {
              resolve({
                usage_hash: data.claim.usage_hash,
                model_hash: data.claim.model_hash,
                prompt_hash: data.claim.prompt_hash,
                response_hash: data.claim.response_hash,
                endpoint: data.claim.endpoint,
                timestamp: data.claim.timestamp,
                attestor_sig: data.claim.attestor_sig,
                zk_proof: data.claim.zk_proof || '',
              })
              return
            }
          } catch {}
          // Fallback on parse error
          console.warn('[attestor-proxy] TEE signing response invalid, using proxy-intercepted')
          resolve({ ...unsignedClaim, attestor_sig: 'proxy-intercepted' })
        })
      },
    )

    req.on('error', (err) => {
      console.warn(`[attestor-proxy] TEE attestor unreachable (${err.message}), using proxy-intercepted`)
      resolve({ ...unsignedClaim, attestor_sig: 'proxy-intercepted' })
    })

    req.setTimeout(5000, () => {
      req.destroy()
      console.warn('[attestor-proxy] TEE attestor timeout, using proxy-intercepted')
      resolve({ ...unsignedClaim, attestor_sig: 'proxy-intercepted' })
    })

    req.write(body)
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
    attestor_sig: 'unsigned',  // Will be signed by TEE attestor
    zk_proof: '',
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
      'accept-encoding',  // prevent gzip responses from upstream
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
          const unsignedClaim = buildClaimFromStream(
            route.name,
            `https://${route.upstream.host}${route.pathPrefix}`,
            requestBody,
            accumulated,
          )
          const claim = await requestTeeSigning(unsignedClaim)
          const claimId = storeClaim(claim, route.name, requestBody)
          const sigStatus = claim.attestor_sig !== 'proxy-intercepted' ? 'TEE-signed' : 'unsigned'
          console.log(`[${route.name}] Stream claim ${claimId} stored (${sigStatus}) — model: ${accumulated.model}`)
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

    // Generate claim from non-streaming response, then sign via TEE
    if (!skipClaim && upstream.statusCode >= 200 && upstream.statusCode < 300) {
      try {
        const responseData = JSON.parse(upstream.body)
        const unsignedClaim = buildClaimFromIntercept(route, requestBody, responseData)
        const claim = await requestTeeSigning(unsignedClaim)
        const claimId = storeClaim(claim, route.name, requestBody)

        responseHeaders['x-attestor-claim-id'] = claimId
        responseHeaders['x-attestor-timestamp'] = String(claim.timestamp)
        responseHeaders['x-attestor-signed'] = claim.attestor_sig !== 'proxy-intercepted' ? 'true' : 'false'

        const sigStatus = claim.attestor_sig !== 'proxy-intercepted' ? 'TEE-signed' : 'unsigned'
        console.log(`[${route.name}] Claim ${claimId} stored (${sigStatus}) — model: ${responseData.model || 'unknown'}`)
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
