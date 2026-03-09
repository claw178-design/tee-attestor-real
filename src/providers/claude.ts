/**
 * Claude (Anthropic) All-Hash Provider
 *
 * All business fields OPRF-hashed.
 * x-api-key header → secretParams (K2 hidden).
 */
import type { AllHashProviderConfig } from '../types/claim'

export const claudeProvider: AllHashProviderConfig = {
  name: 'claude',
  host: 'api.anthropic.com',
  path: '/v1/messages',
  port: 443,
  method: 'POST',
  responseFields: {
    usage: '$.usage',
    model: '$.model',
    prompt: '$.content[0].text',
    response: '$.content[0].text',
  },
}

export function buildClaudeProviderParams(
  apiKey: string,
  requestBody: object,
) {
  const bodyStr = JSON.stringify(requestBody)

  return {
    params: {
      url: `https://${claudeProvider.host}${claudeProvider.path}`,
      method: 'POST' as const,
      headers: {
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01',
      },
      body: bodyStr,
      responseMatches: [
        { type: 'regex' as const, value: '"type"\\s*:\\s*"message"' },
      ],
      responseRedactions: [
        { jsonPath: '$.usage', hash: 'oprf' as const },
        { jsonPath: '$.model', hash: 'oprf' as const },
        { jsonPath: '$.content[0].text', hash: 'oprf' as const },
        { jsonPath: '$.id', hash: 'oprf' as const },
      ],
    },
    secretParams: {
      headers: {
        'x-api-key': apiKey,
      },
    },
  }
}
