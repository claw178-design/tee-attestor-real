/**
 * Streaming Support for Attestor Proxy
 *
 * Handles SSE (Server-Sent Events) streaming responses from LLM APIs.
 * Accumulates streamed chunks, then generates a claim from the full response.
 */

import http from 'http'
import https from 'https'
import { computeOprfHash } from './verify'
import type { AllHashClaim } from './types/claim'

export interface StreamAccumulator {
  chunks: string[]
  usage: any
  model: string
  id: string
  finishReason: string | null
}

/**
 * Accumulate OpenAI-format SSE chunks into a complete response.
 */
export function parseSSEChunks(rawSSE: string): StreamAccumulator {
  const acc: StreamAccumulator = {
    chunks: [],
    usage: null,
    model: '',
    id: '',
    finishReason: null,
  }

  const lines = rawSSE.split('\n')
  for (const line of lines) {
    if (!line.startsWith('data: ')) continue
    const payload = line.slice(6).trim()
    if (payload === '[DONE]') break

    try {
      const data = JSON.parse(payload)
      if (data.model) acc.model = data.model
      if (data.id) acc.id = data.id
      if (data.usage) acc.usage = data.usage

      // OpenAI / Claude streaming delta
      const delta = data.choices?.[0]?.delta?.content
        || data.delta?.text  // Claude streaming
      if (delta) acc.chunks.push(delta)

      if (data.choices?.[0]?.finish_reason) {
        acc.finishReason = data.choices[0].finish_reason
      }
    } catch {
      // skip non-JSON lines
    }
  }

  return acc
}

/**
 * Build a claim from accumulated streaming data.
 */
export function buildClaimFromStream(
  provider: string,
  endpoint: string,
  requestBody: any,
  acc: StreamAccumulator,
): AllHashClaim {
  const fullResponse = acc.chunks.join('')
  const usageStr = acc.usage ? JSON.stringify(acc.usage) : '{}'

  return {
    usage_hash: computeOprfHash(usageStr),
    model_hash: computeOprfHash(acc.model),
    prompt_hash: computeOprfHash(JSON.stringify(requestBody)),
    response_hash: computeOprfHash(fullResponse),
    endpoint: `${provider}:${endpoint}`,
    timestamp: Math.floor(Date.now() / 1000),
    attestor_sig: 'proxy-intercepted-stream',
    zk_proof: '',
  }
}

/**
 * Forward a streaming request and accumulate for claim generation.
 * Returns the accumulated data after the stream completes.
 */
export function forwardStream(
  host: string,
  port: number,
  method: string,
  path: string,
  headers: Record<string, string>,
  body: string,
  clientRes: http.ServerResponse,
): Promise<{ statusCode: number; accumulated: StreamAccumulator }> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: host,
        port,
        path,
        method,
        headers: {
          ...headers,
          host,
          'content-length': String(Buffer.byteLength(body)),
        },
      },
      (upstreamRes) => {
        // Forward status and headers to client immediately
        const fwdHeaders: Record<string, string> = {}
        for (const [k, v] of Object.entries(upstreamRes.headers)) {
          if (v) fwdHeaders[k] = Array.isArray(v) ? v[0] : v
        }
        clientRes.writeHead(upstreamRes.statusCode || 200, fwdHeaders)

        // Accumulate while forwarding
        const rawChunks: Buffer[] = []
        upstreamRes.on('data', (chunk) => {
          rawChunks.push(chunk)
          clientRes.write(chunk)  // Forward to client in real-time
        })

        upstreamRes.on('end', () => {
          clientRes.end()
          const rawSSE = Buffer.concat(rawChunks).toString()
          const accumulated = parseSSEChunks(rawSSE)
          resolve({
            statusCode: upstreamRes.statusCode || 200,
            accumulated,
          })
        })
      },
    )
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}
