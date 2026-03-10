/**
 * Local dev entrypoint — runs TEE signing server.
 *
 * In production, the TEE entrypoint (entrypoint-tee.ts) also starts
 * Reclaim attestor-core WebSocket server for zkTLS tunneling.
 *
 * For local testing, this starts only the HTTP server.
 * Use `node --experimental-strip-types entrypoint-tee.ts` for full mode.
 */

import { startTeeServer } from './tee-server'

const TEE_PORT = parseInt(process.env.TEE_ATTESTOR_PORT || '8767', 10)

console.log('[entrypoint] Starting TEE Attestor HTTP server...')
startTeeServer(TEE_PORT)
