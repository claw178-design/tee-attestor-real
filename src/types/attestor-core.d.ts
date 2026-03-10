/**
 * Type declarations for @reclaimprotocol/attestor-core
 * Used because the package is ESM and we're CJS
 */
declare module '@reclaimprotocol/attestor-core' {
  export interface ProofGenerationStep {
    name: string
    proofsDone?: number
    proofsTotal?: number
    approxTimeLeftS?: number
  }

  export interface CreateClaimOnAttestorOpts<N extends string = string> {
    name: N
    params: any
    secretParams: any
    context?: any
    ownerPrivateKey: string
    client: { url: string } | any
    zkEngine?: 'snarkjs' | 'gnark'
    onStep?: (step: ProofGenerationStep) => void
    logger?: any
    timestampS?: number
    maxRetries?: number
    updateProviderParams?: any
    updateParametersFromOprfData?: boolean
  }

  export interface ClaimResult {
    claim: {
      identifier: string
      owner: string
      timestampS: number
      epoch: number
    }
    signatures: string[]
    witnesses: any[]
  }

  export function createClaimOnAttestor<N extends string>(
    opts: CreateClaimOnAttestorOpts<N>
  ): Promise<ClaimResult>
}

declare module '@reclaimprotocol/attestor-core/client' {
  export { createClaimOnAttestor } from '@reclaimprotocol/attestor-core'
}
