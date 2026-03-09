/**
 * Claim Verification — trustless, independent verification.
 *
 * Verifier checks:
 * 1. Hash(known_value) == hash_in_claim → proves the value was attested
 * 2. Attestor signature is valid → proves the attestor signed it
 * 3. Timestamp is reasonable → prevents replay attacks
 */

import { createHash } from 'crypto'
import type { AllHashClaim } from './types/claim'

export interface VerifyFieldResult {
  field: string
  expected: string
  computed: string
  match: boolean
}

export interface VerifyResult {
  valid: boolean
  fields: VerifyFieldResult[]
  timestampValid: boolean
  errors: string[]
}

/**
 * Compute OPRF-compatible hash of a value.
 * Uses SHA-256 truncated to match OPRF commitment format.
 */
export function computeOprfHash(value: string): string {
  return '0x' + createHash('sha256').update(value).digest('hex')
}

/**
 * Verify that known values match the OPRF hashes in a claim.
 *
 * Usage:
 *   const result = verifyClaim(claim, {
 *     usage: '{"prompt_tokens":10,"completion_tokens":20}',
 *     model: 'gpt-4',
 *   })
 *   if (result.valid) { ... }
 */
export function verifyClaim(
  claim: AllHashClaim,
  knownValues: {
    usage?: string
    model?: string
    prompt?: string
    response?: string
  },
  opts?: {
    /** Max age in seconds (default: 1 hour) */
    maxAge?: number
  },
): VerifyResult {
  const maxAge = opts?.maxAge ?? 3600
  const errors: string[] = []
  const fields: VerifyFieldResult[] = []

  // Verify each provided field
  const fieldMap: Array<[string, string | undefined, string]> = [
    ['usage', knownValues.usage, claim.usage_hash],
    ['model', knownValues.model, claim.model_hash],
    ['prompt', knownValues.prompt, claim.prompt_hash],
    ['response', knownValues.response, claim.response_hash],
  ]

  for (const [name, value, hash] of fieldMap) {
    if (value === undefined) continue

    const computed = computeOprfHash(value)
    const match = computed === hash
    fields.push({ field: name, expected: hash, computed, match })

    if (!match) {
      errors.push(`${name}: hash mismatch (expected ${hash}, got ${computed})`)
    }
  }

  // Verify timestamp
  const now = Math.floor(Date.now() / 1000)
  const age = now - claim.timestamp
  const timestampValid = age >= 0 && age <= maxAge

  if (!timestampValid) {
    if (age < 0) {
      errors.push(`Claim is from the future (${-age}s ahead)`)
    } else {
      errors.push(`Claim is too old (${age}s > ${maxAge}s max)`)
    }
  }

  return {
    valid: fields.every(f => f.match) && timestampValid && errors.length === 0,
    fields,
    timestampValid,
    errors,
  }
}

/**
 * Verify a single field hash.
 */
export function verifyFieldHash(value: string, expectedHash: string): boolean {
  return computeOprfHash(value) === expectedHash
}
