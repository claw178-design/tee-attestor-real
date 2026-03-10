/**
 * tee-attestor-real — All-Hash TEE Attestor
 *
 * Every business field (usage, model, prompt, response) is an OPRF commitment.
 * Authorization (API Key) is K2-hidden — never revealed.
 * ZK proofs are attached to claims for trustless, independent verification.
 *
 * Usage:
 *   import { createAllHashClaim } from 'tee-attestor-real'
 *   const result = await createAllHashClaim({ provider: 'openai', apiKey, ... })
 */

export * from './types'
export * from './providers'
export { createAllHashClaim } from './claim-builder'
export { verifyClaim, computeOprfHash, verifyFieldHash } from './verify'
export { createOpenAIClaim, createGeminiClaim, createClaudeClaim, createHttpClaim } from './zktls-client'
export type { ZkTlsClientOpts, ZkTlsClaimResult } from './zktls-client'
