/**
 * Combined entrypoint — runs both TEE signing server and proxy together.
 * Use this for local development or single-container deployment.
 *
 * In production TEE deployments, typically only tee-server runs inside the TEE,
 * and the proxy runs outside (on the gateway host).
 */

import { startTeeServer } from './tee-server'
import { startProxy } from './proxy-server'

const TEE_PORT = parseInt(process.env.TEE_ATTESTOR_PORT || '8767', 10)
const PROXY_PORT = parseInt(process.env.ATTESTOR_PROXY_PORT || '8766', 10)

console.log('[entrypoint] Starting TEE Attestor + Proxy...')

// Start TEE signing server first
startTeeServer(TEE_PORT)

// Give it a moment to bind, then start proxy
setTimeout(() => {
  startProxy(PROXY_PORT)
  console.log('[entrypoint] Both services running.')
}, 500)
