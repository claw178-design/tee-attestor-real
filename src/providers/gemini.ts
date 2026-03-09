/**
 * Gemini All-Hash Provider
 *
 * All business fields OPRF-hashed. API key in URL path → secretParams.
 */
import type { AllHashProviderConfig } from '../types/claim'

export const geminiProvider: AllHashProviderConfig = {
  name: 'gemini',
  host: 'generativelanguage.googleapis.com',
  path: '/v1beta/models/{model}:generateContent',
  port: 443,
  method: 'POST',
  responseFields: {
    usage: '$.usageMetadata',
    model: '$.modelVersion',
    prompt: '$.candidates[0].content.parts[0].text',
    response: '$.candidates[0].content.parts[0].text',
  },
}

export function buildGeminiProviderParams(
  apiKey: string,
  model: string,
  requestBody: object,
) {
  const path = geminiProvider.path.replace('{model}', model)
  const bodyStr = JSON.stringify(requestBody)

  return {
    params: {
      // API key is in the URL as query param — the whole URL goes to secretParams
      url: `https://${geminiProvider.host}${path}?key={{apiKey}}`,
      method: 'POST' as const,
      headers: {
        'Content-Type': 'application/json',
      },
      body: bodyStr,
      responseMatches: [
        { type: 'regex' as const, value: '"candidates"\\s*:' },
      ],
      responseRedactions: [
        { jsonPath: '$.usageMetadata', hash: 'oprf' as const },
        { jsonPath: '$.modelVersion', hash: 'oprf' as const },
        { jsonPath: '$.candidates[0].content.parts[0].text', hash: 'oprf' as const },
      ],
    },
    secretParams: {
      paramValues: {
        apiKey,
      },
    },
  }
}
