/**
 * Ethereum-compatible EIP-712 signing for TEE claims.
 *
 * Converts the TEE attestor's secp256k1 key into an Ethereum wallet
 * and signs claims using EIP-712 typed data for on-chain verification
 * via ecrecover.
 */

import { createHash, createPrivateKey } from 'crypto'
import { ethers } from 'ethers'

// EIP-712 types matching ClaimVerifier.sol
const EIP712_DOMAIN = {
  name: 'ClaimVerifierV2',
  version: '2',
}

const CLAIM_TYPES = {
  Claim: [
    { name: 'usageHash', type: 'bytes32' },
    { name: 'modelHash', type: 'bytes32' },
    { name: 'promptHash', type: 'bytes32' },
    { name: 'responseHash', type: 'bytes32' },
    { name: 'endpoint', type: 'string' },
    { name: 'timestamp', type: 'uint256' },
  ],
}

export interface EthSignRequest {
  usage_hash: string
  model_hash: string
  prompt_hash: string
  response_hash: string
  endpoint: string
  timestamp: number
  /** Sepolia chain ID and verifier contract address for EIP-712 domain */
  chain_id?: number
  verifier_address?: string
}

export interface EthSignedClaim extends EthSignRequest {
  eth_signature: string      // 0x-prefixed 65-byte signature (r+s+v)
  eth_signer_address: string // attestor's Ethereum address
  eip712_domain: {
    name: string
    version: string
    chainId: number
    verifyingContract: string
  }
}

/**
 * Derive an ethers Wallet from a PEM-encoded secp256k1 private key.
 */
export function pemToEthWallet(privatePem: string): ethers.Wallet {
  const keyObj = createPrivateKey(privatePem)
  // Export as JWK to get the raw d parameter (private scalar)
  const jwk = keyObj.export({ format: 'jwk' })
  if (!jwk.d) throw new Error('Cannot extract private key scalar from PEM')
  // JWK d is base64url-encoded 32-byte private key
  const privBytes = Buffer.from(jwk.d, 'base64url')
  const privHex = '0x' + privBytes.toString('hex')
  return new ethers.Wallet(privHex)
}

/**
 * Sign a claim using EIP-712 typed data.
 * Returns an Ethereum-compatible signature that can be verified on-chain.
 */
export async function ethSignClaim(
  req: EthSignRequest,
  wallet: ethers.Wallet,
): Promise<EthSignedClaim> {
  const chainId = req.chain_id || 11155111 // Sepolia default
  const verifyingContract = req.verifier_address || '0x98b05fb625B8867f073277B7EAbF1ccC7E0926c9'

  const domain = {
    ...EIP712_DOMAIN,
    chainId,
    verifyingContract,
  }

  // Convert 0x-prefixed SHA256 hex strings to bytes32
  const value = {
    usageHash: toBytes32(req.usage_hash),
    modelHash: toBytes32(req.model_hash),
    promptHash: toBytes32(req.prompt_hash),
    responseHash: toBytes32(req.response_hash),
    endpoint: req.endpoint,
    timestamp: req.timestamp,
  }

  const signature = await wallet.signTypedData(domain, CLAIM_TYPES, value)

  return {
    ...req,
    eth_signature: signature,
    eth_signer_address: wallet.address,
    eip712_domain: domain,
  }
}

/**
 * Verify an EIP-712 signed claim off-chain.
 */
export function ethVerifyClaim(signed: EthSignedClaim): { valid: boolean; recoveredAddress: string } {
  const value = {
    usageHash: toBytes32(signed.usage_hash),
    modelHash: toBytes32(signed.model_hash),
    promptHash: toBytes32(signed.prompt_hash),
    responseHash: toBytes32(signed.response_hash),
    endpoint: signed.endpoint,
    timestamp: signed.timestamp,
  }

  const recovered = ethers.verifyTypedData(
    signed.eip712_domain,
    CLAIM_TYPES,
    value,
    signed.eth_signature,
  )

  return {
    valid: recovered.toLowerCase() === signed.eth_signer_address.toLowerCase(),
    recoveredAddress: recovered,
  }
}

/** Convert a 0x-prefixed hex hash to bytes32 (pad/truncate to 32 bytes) */
function toBytes32(hash: string): string {
  const hex = hash.startsWith('0x') ? hash.slice(2) : hash
  return '0x' + hex.padStart(64, '0').slice(0, 64)
}
