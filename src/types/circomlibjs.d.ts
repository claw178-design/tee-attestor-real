declare module 'circomlibjs' {
  export function buildPoseidon(): Promise<{
    (inputs: bigint[]): Uint8Array
    F: { toString(val: Uint8Array): string }
  }>
}
