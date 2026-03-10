/**
 * TEE Entrypoint — Single-port server (8080) that combines:
 *
 * 1. Custom HTTP API: /health, /attestation, /sign, /verify, /pubkey, /eth-sign
 * 2. WebSocket proxy: /ws → internal Reclaim attestor-core (port 8001)
 *
 * The attestor-core handles zkTLS tunneling:
 *   - Gateway client connects via WebSocket to /ws
 *   - TLS traffic is routed through the TEE
 *   - K2 mechanism hides API keys (TEE never sees them)
 *   - TEE records ciphertext, verifies ZK proofs, signs claims
 *
 * Environment variables:
 *   PRIVATE_KEY              — Reclaim attestor signing key (hex, 0x-prefixed)
 *   TOPRF_SHARE_PRIVATE_KEY  — TOPRF share key (optional)
 *   TEE_ATTESTOR_PORT        — External port (default: 8080)
 *   ATTESTOR_CORE_PORT       — Internal attestor-core port (default: 8001)
 *   DISABLE_BGP_CHECKS       — Set to "1" to skip BGP checks
 */

import { randomBytes, createHash } from 'crypto'
import { existsSync, writeFileSync, mkdirSync, readFileSync } from 'fs'
import { join } from 'path'
import { spawn } from 'child_process'
import http from 'http'
import net from 'net'

const TEE_PORT = parseInt(process.env.TEE_ATTESTOR_PORT || '8080', 10)
const ATTESTOR_CORE_PORT = parseInt(process.env.ATTESTOR_CORE_PORT || '8001', 10)

// ─── Key Generation ─────────────────────────────────────────────────

function ensurePrivateKey(): string {
  if (process.env.PRIVATE_KEY) {
    return process.env.PRIVATE_KEY
  }

  const keyDir = '/app/.tee-keys'
  const keyPath = join(keyDir, 'attestor-core.key')

  if (existsSync(keyPath)) {
    const key = readFileSync(keyPath, 'utf-8').trim()
    console.log('[entrypoint] Loaded existing attestor-core key')
    return key
  }

  const key = '0x' + randomBytes(32).toString('hex')
  if (!existsSync(keyDir)) mkdirSync(keyDir, { recursive: true })
  writeFileSync(keyPath, key, { mode: 0o600 })
  console.log('[entrypoint] Generated new attestor-core signing key')
  return key
}

// ─── Start Reclaim attestor-core (internal, port 8001) ──────────────

function startAttestorCore(privateKey: string): Promise<void> {
  return new Promise((resolve, reject) => {
    console.log(`[entrypoint] Starting attestor-core on internal port ${ATTESTOR_CORE_PORT}...`)

    const attestorCorePath = '/app/attestor-core'
    if (!existsSync(attestorCorePath)) {
      console.error('[entrypoint] attestor-core not found at /app/attestor-core')
      console.log('[entrypoint] Running in HTTP-only mode (no zkTLS)')
      resolve()
      return
    }

    const env = {
      ...process.env,
      PRIVATE_KEY: privateKey,
      PORT: String(ATTESTOR_CORE_PORT),
      DISABLE_BGP_CHECKS: '1',
      NODE_ENV: 'production',
    }

    const child = spawn('node', [
      '--experimental-strip-types',
      'src/scripts/start-server.ts',
    ], {
      cwd: attestorCorePath,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    let started = false

    child.stdout?.on('data', (data: Buffer) => {
      const text = data.toString().trim()
      for (const line of text.split('\n')) {
        console.log(`[attestor-core] ${line}`)
        if (line.includes('listening') && !started) {
          started = true
          resolve()
        }
      }
    })

    child.stderr?.on('data', (data: Buffer) => {
      for (const line of data.toString().trim().split('\n')) {
        console.error(`[attestor-core:err] ${line}`)
      }
    })

    child.on('exit', (code) => {
      console.error(`[attestor-core] Process exited with code ${code}`)
      if (!started) {
        // Try to resolve anyway after a timeout — maybe logs went to stderr
        setTimeout(() => {
          if (!started) {
            started = true
            reject(new Error(`attestor-core exited with code ${code}`))
          }
        }, 1000)
      } else {
        // Restart after delay
        setTimeout(() => startAttestorCore(privateKey), 5000)
      }
    })

    // Fallback: if no "listening" log after 15s, check the port
    setTimeout(() => {
      if (started) return
      const sock = net.connect(ATTESTOR_CORE_PORT, '127.0.0.1')
      sock.on('connect', () => {
        sock.destroy()
        if (!started) {
          started = true
          console.log('[entrypoint] attestor-core port reachable (fallback check)')
          resolve()
        }
      })
      sock.on('error', () => {
        sock.destroy()
        if (!started) {
          console.log('[entrypoint] attestor-core not reachable after 15s, continuing anyway')
          started = true
          resolve()
        }
      })
    }, 15000)
  })
}

// ─── Combined HTTP + WebSocket Proxy Server (port 8080) ─────────────

async function startCombinedServer() {
  // tee-server is in the same directory (both compile to dist/)
  const { startTeeServer } = await import('./tee-server')

  // Create our HTTP server (tee-server handles all HTTP routes)
  const server: http.Server = startTeeServer(TEE_PORT)

  // Proxy WebSocket upgrades on /ws to attestor-core
  server.on('upgrade', (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
    const url = new URL(req.url || '/', 'http://localhost')

    if (url.pathname === '/ws') {
      // Proxy to internal attestor-core WebSocket
      const proxy = net.connect(ATTESTOR_CORE_PORT, '127.0.0.1', () => {
        // Reconstruct the HTTP upgrade request
        const headers = [`${req.method} ${req.url} HTTP/${req.httpVersion}`]
        for (let i = 0; i < req.rawHeaders.length; i += 2) {
          headers.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`)
        }
        headers.push('', '')
        proxy.write(headers.join('\r\n'))
        if (head.length > 0) proxy.write(head)

        // Bidirectional pipe
        socket.pipe(proxy)
        proxy.pipe(socket)
      })

      proxy.on('error', (err) => {
        console.error(`[ws-proxy] Connection to attestor-core failed: ${err.message}`)
        socket.destroy()
      })

      socket.on('error', () => proxy.destroy())
      socket.on('close', () => proxy.destroy())
      proxy.on('close', () => socket.destroy())
    } else {
      // Not a recognized WebSocket path
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n')
      socket.destroy()
    }
  })

  // Also proxy /address to attestor-core (useful for debugging)
  const origListeners = server.listeners('request')

  // Wrap the existing request handler to add /address proxy
  server.removeAllListeners('request')
  server.on('request', (req: http.IncomingMessage, res: http.ServerResponse) => {
    if (req.url === '/address' && req.method === 'GET') {
      // Proxy to attestor-core /address endpoint
      const proxyReq = http.get(
        `http://127.0.0.1:${ATTESTOR_CORE_PORT}/address`,
        (proxyRes) => {
          res.writeHead(proxyRes.statusCode || 200, proxyRes.headers)
          proxyRes.pipe(res)
        },
      )
      proxyReq.on('error', () => {
        res.writeHead(502, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'attestor-core not available' }))
      })
      proxyReq.setTimeout(5000, () => {
        proxyReq.destroy()
        res.writeHead(504, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'attestor-core timeout' }))
      })
      return
    }

    // Delegate to original handler (tee-server)
    for (const listener of origListeners) {
      (listener as any)(req, res)
    }
  })

  console.log(`[entrypoint] WebSocket proxy /ws → 127.0.0.1:${ATTESTOR_CORE_PORT}`)
  console.log(`[entrypoint] Address proxy /address → 127.0.0.1:${ATTESTOR_CORE_PORT}`)
}

// ─── Main ───────────────────────────────────────────────────────────

async function main() {
  console.log('='.repeat(60))
  console.log('[entrypoint] TEE Attestor — zkTLS + HTTP Signing Server')
  console.log(`[entrypoint] External port: ${TEE_PORT} (HTTP + WebSocket)`)
  console.log(`[entrypoint] Internal attestor-core: ${ATTESTOR_CORE_PORT}`)
  console.log('='.repeat(60))

  const privateKey = ensurePrivateKey()
  process.env.PRIVATE_KEY = privateKey

  const keyHash = createHash('sha256').update(privateKey).digest('hex').slice(0, 16)
  console.log(`[entrypoint] Key fingerprint: ${keyHash}`)

  // Start attestor-core first (needs to be ready for WebSocket proxy)
  await startAttestorCore(privateKey)

  // Start combined HTTP + WebSocket proxy server
  await startCombinedServer()

  console.log('[entrypoint] All services running.')
  console.log('[entrypoint] Endpoints:')
  console.log(`[entrypoint]   GET  /health       — Health check`)
  console.log(`[entrypoint]   GET  /attestation   — Remote attestation report`)
  console.log(`[entrypoint]   POST /sign          — Sign a claim (ECDSA)`)
  console.log(`[entrypoint]   POST /eth-sign      — Sign a claim (EIP-712)`)
  console.log(`[entrypoint]   POST /verify        — Verify a signed claim`)
  console.log(`[entrypoint]   GET  /pubkey        — Public key`)
  console.log(`[entrypoint]   GET  /address       — Attestor-core address (proxied)`)
  console.log(`[entrypoint]   WS   /ws            — zkTLS tunnel (proxied to attestor-core)`)
}

main().catch((err) => {
  console.error('[entrypoint] Fatal error:', err)
  process.exit(1)
})
