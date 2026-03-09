/**
 * OpenAI All-Hash Provider
 *
 * All business fields (usage, model, prompt, response) are OPRF-hashed.
 * Authorization header (API key) is redacted via K2 — never revealed.
 */
import type { AllHashProviderConfig } from '../types/claim'

export const openaiProvider: AllHashProviderConfig = {
  name: 'openai',
  host: 'api.openai.com',
  path: '/v1/chat/completions',
  port: 443,
  method: 'POST',
  responseFields: {
    usage: '$.usage',
    model: '$.model',
    prompt: '$.choices[0].message.content',
    response: '$.choices[0].message.content',
  },
}

/**
 * Build Reclaim HTTP provider params for OpenAI with All-Hash strategy.
 *
 * Key design:
 * - Authorization header → secretParams (K2 hidden, never in claim)
 * - All response fields → responseRedactions with hash: 'oprf'
 * - Request body → also hashed via OPRF (contains prompt)
 */
export function buildOpenAIProviderParams(
  apiKey: string,
  requestBody: object,
) {
  const bodyStr = JSON.stringify(requestBody)

  return {
    params: {
      url: `https://${openaiProvider.host}${openaiProvider.path}`,
      method: 'POST' as const,
      headers: {
        'Content-Type': 'application/json',
      },
      body: bodyStr,
      responseMatches: [
        // Verify we got a valid chat completion response
        { type: 'regex' as const, value: '"object"\\s*:\\s*"chat\\.completion"' },
      ],
      responseRedactions: [
        // Hash ALL business fields via OPRF — no plaintext in claim
        { jsonPath: '$.usage', hash: 'oprf' as const },
        { jsonPath: '$.model', hash: 'oprf' as const },
        { jsonPath: '$.choices[0].message.content', hash: 'oprf' as const },
        { jsonPath: '$.id', hash: 'oprf' as const },
      ],
    },
    secretParams: {
      headers: {
        Authorization: `Bearer ${apiKey}`,
      },
    },
  }
}
