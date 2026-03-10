/**
 * ZK Prover — generates Groth16 proofs for All-Hash claims.
 *
 * Proves: "I know preimages (usage, model, prompt, response) such that
 *          Poseidon(preimage_i) == hash_i for all i"
 *
 * The prover runs locally (on the proxy/gateway side).
 * It never sends plaintext to the TEE — only hashes + proof.
 *
 * Flow:
 *   1. Convert raw string data → BN128 field element via SHA-256 truncation
 *   2. Compute Poseidon(field_element) → claim hash
 *   3. Generate Groth16 proof that the prover knows the preimages
 *   4. Attach proof to claim → TEE signs {hashes + proof}
 *   5. On-chain verifier checks both TEE signature AND ZK proof
 */

import { createHash } from 'crypto'
import { existsSync } from 'fs'
import { join } from 'path'

// BN128 scalar field order
const BN128_FIELD_ORDER = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
)

// Paths to ZK artifacts (relative to project root)
const ARTIFACTS_DIR = join(__dirname, '..', 'artifacts')
const WASM_PATH = join(ARTIFACTS_DIR, 'claim_hash_js', 'claim_hash.wasm')
const ZKEY_PATH = join(ARTIFACTS_DIR, 'claim_hash_final.zkey')
const VKEY_PATH = join(ARTIFACTS_DIR, 'verification_key.json')

// Lazy-loaded snarkjs (heavy module, only load when needed)
let _snarkjs: any = null
async function getSnarkjs() {
  if (!_snarkjs) {
    _snarkjs = await import('snarkjs')
  }
  return _snarkjs
}

/**
 * Convert arbitrary string data to a BN128 field element.
 * Uses SHA-256 of the data, then reduces mod field order.
 */
export function stringToFieldElement(data: string): bigint {
  const hash = createHash('sha256').update(data).digest('hex')
  const num = BigInt('0x' + hash)
  return num % BN128_FIELD_ORDER
}

/**
 * Compute Poseidon hash of a field element using the circuit's logic.
 * This uses snarkjs witness generation to compute the exact same hash
 * the circuit produces, ensuring consistency.
 *
 * For performance, we use the circomlib Poseidon JS implementation directly.
 */
export async function poseidonHash(fieldElement: bigint): Promise<bigint> {
  // Use circomlibjs Poseidon implementation (matches circom circuit)
  const { buildPoseidon } = await import('circomlibjs')
  const poseidon = await buildPoseidon()
  const result = poseidon([fieldElement])
  // poseidon returns a buffer-like F element; convert to bigint
  return BigInt(poseidon.F.toString(result))
}

/**
 * Compute all 4 Poseidon hashes for a claim.
 * Returns both the field element preimages and their Poseidon hashes.
 */
export async function computeClaimHashes(data: {
  usage: string
  model: string
  prompt: string
  response: string
}): Promise<{
  preimages: {
    usage: bigint
    model: bigint
    prompt: bigint
    response: bigint
  }
  hashes: {
    usage: bigint
    model: bigint
    prompt: bigint
    response: bigint
  }
}> {
  const preimages = {
    usage: stringToFieldElement(data.usage),
    model: stringToFieldElement(data.model),
    prompt: stringToFieldElement(data.prompt),
    response: stringToFieldElement(data.response),
  }

  const [usageHash, modelHash, promptHash, responseHash] = await Promise.all([
    poseidonHash(preimages.usage),
    poseidonHash(preimages.model),
    poseidonHash(preimages.prompt),
    poseidonHash(preimages.response),
  ])

  return {
    preimages,
    hashes: {
      usage: usageHash,
      model: modelHash,
      prompt: promptHash,
      response: responseHash,
    },
  }
}

/**
 * Format a bigint as a 0x-prefixed hex string (32 bytes, zero-padded).
 */
export function fieldToHex(value: bigint): string {
  return '0x' + value.toString(16).padStart(64, '0')
}

/**
 * Format a bigint as a decimal string (for snarkjs/Solidity compatibility).
 */
export function fieldToDecimal(value: bigint): string {
  return value.toString()
}

/**
 * ZK Proof structure matching the Groth16 verifier contract.
 */
export interface ZkProof {
  /** Groth16 proof point A [x, y] */
  pi_a: [string, string]
  /** Groth16 proof point B [[x1, x2], [y1, y2]] */
  pi_b: [[string, string], [string, string]]
  /** Groth16 proof point C [x, y] */
  pi_c: [string, string]
  /** Public signals: [usage_hash, model_hash, prompt_hash, response_hash] */
  publicSignals: [string, string, string, string]
}

/**
 * Generate a Groth16 ZK proof for the given claim data.
 *
 * @param data - The raw plaintext data (usage, model, prompt, response)
 * @returns The ZK proof, public signals (Poseidon hashes), and hex-formatted hashes
 */
export async function generateProof(data: {
  usage: string
  model: string
  prompt: string
  response: string
}): Promise<{
  proof: ZkProof
  /** Poseidon hashes as 0x hex strings (for the claim) */
  hashes: {
    usage_hash: string
    model_hash: string
    prompt_hash: string
    response_hash: string
  }
  /** Base64-encoded proof blob for the claim's zk_proof field */
  proofBlob: string
  /** Time taken to generate the proof (ms) */
  proofTimeMs: number
}> {
  // Check artifacts exist
  if (!existsSync(WASM_PATH)) {
    throw new Error(`WASM file not found: ${WASM_PATH}. Run: circom circuits/claim_hash.circom --r1cs --wasm -o artifacts/`)
  }
  if (!existsSync(ZKEY_PATH)) {
    throw new Error(`ZKey file not found: ${ZKEY_PATH}. Run the trusted setup first.`)
  }

  const startTime = Date.now()

  // Step 1: Convert strings to field elements
  const preimages = {
    usage: stringToFieldElement(data.usage),
    model: stringToFieldElement(data.model),
    prompt: stringToFieldElement(data.prompt),
    response: stringToFieldElement(data.response),
  }

  // Step 2: Build circuit input
  const circuitInput = {
    usage_preimage: preimages.usage.toString(),
    model_preimage: preimages.model.toString(),
    prompt_preimage: preimages.prompt.toString(),
    response_preimage: preimages.response.toString(),
  }

  // Step 3: Generate witness + proof using snarkjs
  const snarkjs = await getSnarkjs()
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH,
  )

  const proofTimeMs = Date.now() - startTime

  // Step 4: Format proof for contract verification
  const zkProof: ZkProof = {
    pi_a: [proof.pi_a[0], proof.pi_a[1]],
    pi_b: [
      [proof.pi_b[0][1], proof.pi_b[0][0]], // Note: snarkjs swaps x coords for BN128
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    pi_c: [proof.pi_c[0], proof.pi_c[1]],
    publicSignals: publicSignals as [string, string, string, string],
  }

  // Step 5: Convert public signals (Poseidon hashes) to hex for the claim
  const hashes = {
    usage_hash: fieldToHex(BigInt(publicSignals[0])),
    model_hash: fieldToHex(BigInt(publicSignals[1])),
    prompt_hash: fieldToHex(BigInt(publicSignals[2])),
    response_hash: fieldToHex(BigInt(publicSignals[3])),
  }

  // Step 6: Encode proof as base64 blob for the claim's zk_proof field
  const proofBlob = Buffer.from(JSON.stringify(zkProof)).toString('base64')

  return { proof: zkProof, hashes, proofBlob, proofTimeMs }
}

/**
 * Verify a ZK proof locally (without on-chain transaction).
 */
export async function verifyProof(proof: ZkProof): Promise<boolean> {
  if (!existsSync(VKEY_PATH)) {
    throw new Error(`Verification key not found: ${VKEY_PATH}`)
  }

  const snarkjs = await getSnarkjs()
  const vkey = JSON.parse(require('fs').readFileSync(VKEY_PATH, 'utf-8'))

  // Reconstruct proof format for snarkjs
  const snarkProof = {
    pi_a: [...proof.pi_a, '1'],
    pi_b: [
      [proof.pi_b[0][1], proof.pi_b[0][0]], // Swap back
      [proof.pi_b[1][1], proof.pi_b[1][0]],
      ['1', '0'],
    ],
    pi_c: [...proof.pi_c, '1'],
    protocol: 'groth16',
    curve: 'bn128',
  }

  return snarkjs.groth16.verify(vkey, proof.publicSignals, snarkProof)
}

/**
 * Decode a base64 proof blob back into a ZkProof structure.
 */
export function decodeProofBlob(blob: string): ZkProof {
  return JSON.parse(Buffer.from(blob, 'base64').toString())
}

/**
 * Format proof for Solidity contract calldata.
 * Returns the arrays needed for Groth16Verifier.verifyProof().
 */
export function proofToSolidityCalldata(proof: ZkProof): {
  pA: [string, string]
  pB: [[string, string], [string, string]]
  pC: [string, string]
  pubSignals: [string, string, string, string]
} {
  return {
    pA: proof.pi_a,
    pB: proof.pi_b,
    pC: proof.pi_c,
    pubSignals: proof.publicSignals,
  }
}

/**
 * Check if ZK artifacts are available.
 */
export function zkArtifactsAvailable(): boolean {
  return existsSync(WASM_PATH) && existsSync(ZKEY_PATH)
}
