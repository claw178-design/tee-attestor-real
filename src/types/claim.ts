/**
 * All-Hash Claim — no plaintext leaves the attestor.
 * Every business field is an OPRF commitment; verifiers check Hash(value) == hash.
 */
export interface AllHashClaim {
  /** OPRF commitment of usage data (e.g. token counts) */
  usage_hash: string
  /** OPRF commitment of model identifier */
  model_hash: string
  /** OPRF commitment of prompt/request content */
  prompt_hash: string
  /** OPRF commitment of response content */
  response_hash: string
  /** Target API endpoint (revealed — not sensitive) */
  endpoint: string
  /** Unix timestamp of attestation */
  timestamp: number
  /** Attestor's signature over the claim */
  attestor_sig: string
  /** ZK proof blob (base64) for independent verification */
  zk_proof: string
}

/**
 * Provider configuration for the All-Hash attestor.
 */
export interface AllHashProviderConfig {
  /** Provider name, e.g. 'openai', 'gemini', 'claude' */
  name: string
  /** API host, e.g. 'api.openai.com' */
  host: string
  /** API path, e.g. '/v1/chat/completions' */
  path: string
  /** Port (default 443) */
  port?: number
  /** HTTP method (default POST) */
  method?: string
  /** Response field mappings — jsonPath expressions for each field */
  responseFields: {
    usage: string    // e.g. '$.usage'
    model: string    // e.g. '$.model'
    prompt: string   // e.g. '$.choices[0].message.content' or request body
    response: string // e.g. '$.choices[0].message.content'
  }
}

/**
 * Secret parameters — never revealed, never stored in claim.
 */
export interface AllHashSecretParams {
  /** API key / bearer token — K2 hidden, never disclosed */
  apiKey: string
  /** Request body (contains prompt) */
  requestBody: string
}

/**
 * Result from claim creation.
 */
export interface ClaimResult {
  success: boolean
  claim?: AllHashClaim
  error?: string
  /** Raw attestor response for debugging */
  raw?: unknown
}
