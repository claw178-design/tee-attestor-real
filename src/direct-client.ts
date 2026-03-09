/**
 * Direct HTTP Client — calls LLM APIs directly (without attestor tunnel).
 *
 * Use this for:
 * 1. Testing response parsing logic against real APIs
 * 2. Generating mock claims from real responses for verification testing
 * 3. Validating provider configurations before running through attestor
 */

import https from 'https'
import { computeOprfHash } from './verify'
import type { AllHashClaim } from './types/claim'

export interface DirectCallOpts {
  provider: 'openai' | 'gemini' | 'claude'
  apiKey: string
  requestBody: object
  geminiModel?: string
}

export interface DirectCallResult {
  success: boolean
  response?: any
  claim?: AllHashClaim
  error?: string
}

/**
 * Extract text from Gemini response, handling thinking models that put
 * thoughts in early parts and actual text in later parts.
 */
function extractGeminiText(data: any): string {
  const parts = data.candidates?.[0]?.content?.parts
  if (!parts || !Array.isArray(parts)) return ''
  // Find the last part with text (skip thought parts)
  for (let i = parts.length - 1; i >= 0; i--) {
    if (parts[i].text !== undefined) return parts[i].text
  }
  return ''
}

const PROVIDER_CONFIG = {
  openai: {
    host: 'api.openai.com',
    path: '/v1/chat/completions',
    buildHeaders: (apiKey: string) => ({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    }),
    extractFields: (data: any) => ({
      usage: JSON.stringify(data.usage),
      model: data.model,
      response: data.choices?.[0]?.message?.content || '',
      id: data.id,
    }),
  },
  gemini: {
    host: 'generativelanguage.googleapis.com',
    path: '/v1beta/models/{model}:generateContent',
    buildHeaders: (_apiKey: string) => ({
      'Content-Type': 'application/json',
    }),
    extractFields: (data: any) => ({
      usage: JSON.stringify(data.usageMetadata),
      model: data.modelVersion || '',
      response: extractGeminiText(data),
      id: '',
    }),
  },
  claude: {
    host: 'api.anthropic.com',
    path: '/v1/messages',
    buildHeaders: (apiKey: string) => ({
      'Content-Type': 'application/json',
      'anthropic-version': '2023-06-01',
      'x-api-key': apiKey,
    }),
    extractFields: (data: any) => ({
      usage: JSON.stringify(data.usage),
      model: data.model,
      response: data.content?.[0]?.text || '',
      id: data.id,
    }),
  },
}

/**
 * Call the LLM API directly and generate an unsigned claim from the response.
 * The claim hashes are computed locally (not via OPRF through attestor).
 * Useful for testing and validation.
 */
export async function directCall(opts: DirectCallOpts): Promise<DirectCallResult> {
  const { provider, apiKey, requestBody, geminiModel } = opts
  const config = PROVIDER_CONFIG[provider]

  let path = config.path
  if (provider === 'gemini') {
    if (!geminiModel) {
      return { success: false, error: 'geminiModel is required for gemini provider' }
    }
    path = path.replace('{model}', geminiModel) + `?key=${apiKey}`
  }

  const headers = config.buildHeaders(apiKey)
  const body = JSON.stringify(requestBody)

  try {
    const responseData = await httpPost(config.host, path, headers, body)
    const fields = config.extractFields(responseData)

    // Build a local claim with SHA-256 hashes (not real OPRF, but structurally identical)
    const claim: AllHashClaim = {
      usage_hash: computeOprfHash(fields.usage),
      model_hash: computeOprfHash(fields.model),
      prompt_hash: computeOprfHash(JSON.stringify(requestBody)),
      response_hash: computeOprfHash(fields.response),
      endpoint: `${provider}:https://${config.host}${config.path}`,
      timestamp: Math.floor(Date.now() / 1000),
      attestor_sig: '',  // unsigned — direct call
      zk_proof: '',      // no ZK proof — direct call
    }

    return {
      success: true,
      response: responseData,
      claim,
    }
  } catch (err: any) {
    return {
      success: false,
      error: err.message || String(err),
    }
  }
}

function httpPost(
  host: string,
  path: string,
  headers: Record<string, string>,
  body: string,
): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: host,
        port: 443,
        path,
        method: 'POST',
        headers: {
          ...headers,
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = ''
        res.on('data', (chunk) => (data += chunk))
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data)
            if (res.statusCode && res.statusCode >= 400) {
              reject(new Error(`HTTP ${res.statusCode}: ${JSON.stringify(parsed)}`))
            } else {
              resolve(parsed)
            }
          } catch {
            reject(new Error(`HTTP ${res.statusCode}: ${data}`))
          }
        })
      },
    )
    req.on('error', reject)
    req.write(body)
    req.end()
  })
}
