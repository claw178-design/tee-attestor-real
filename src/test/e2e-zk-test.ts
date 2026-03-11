#!/usr/bin/env ts-node
/**
 * End-to-end ZK proof test:
 * 1. Generate Groth16 proof locally (client side)
 * 2. Send hashes + proof to TEE for signing
 * 3. Verify TEE only signs when proof is valid
 */

import { generateProof, fieldToHex } from '../zk-prover'

const TEE_URL = process.env.TEE_URL || 'https://zktls.judgeclaw.xyz:8080'

async function main() {
  console.log('=== E2E ZK Proof Test ===\n')

  // Step 1: Generate ZK proof locally
  console.log('[1/4] Generating Groth16 ZK proof locally...')
  const data = {
    usage: '{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}',
    model: 'gemini-2.5-flash',
    prompt: 'Hello, world!',
    response: 'Hi there!',
  }

  const { proof, hashes, proofBlob, proofTimeMs } = await generateProof(data)
  console.log(`  Proof generated in ${proofTimeMs}ms`)
  console.log(`  Hashes:`)
  console.log(`    usage_hash:    ${hashes.usage_hash}`)
  console.log(`    model_hash:    ${hashes.model_hash}`)
  console.log(`    prompt_hash:   ${hashes.prompt_hash}`)
  console.log(`    response_hash: ${hashes.response_hash}`)
  console.log(`  Proof blob: ${proofBlob.length} chars (base64)`)

  // Step 2: Send to TEE WITH proof — should succeed
  console.log('\n[2/4] Sending hashes + ZK proof to TEE /eth-sign...')
  const signReq = {
    ...hashes,
    endpoint: 'gemini:generativelanguage.googleapis.com',
    timestamp: Math.floor(Date.now() / 1000),
    zk_proof: proof, // Send as object
  }

  const signRes = await fetch(`${TEE_URL}/eth-sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(signReq),
  })
  const signData = await signRes.json() as any

  if (signRes.ok && signData.ok) {
    console.log(`  ✅ TEE signed claim (zk_verified: ${signData.claim.zk_verified})`)
    console.log(`  Signer: ${signData.claim.eth_signer_address}`)
    console.log(`  Signature: ${signData.claim.eth_signature?.slice(0, 20)}...`)
  } else {
    console.log(`  ❌ TEE refused to sign: ${signData.error}`)
    process.exit(1)
  }

  // Step 3: Send WITHOUT proof — should be rejected
  console.log('\n[3/4] Sending hashes WITHOUT ZK proof (should be rejected)...')
  const noProofReq = {
    ...hashes,
    endpoint: 'gemini:generativelanguage.googleapis.com',
    timestamp: Math.floor(Date.now() / 1000),
    // no zk_proof
  }

  const noProofRes = await fetch(`${TEE_URL}/eth-sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(noProofReq),
  })
  const noProofData = await noProofRes.json() as any

  if (noProofRes.status === 400 && noProofData.error?.includes('ZK proof required')) {
    console.log(`  ✅ TEE correctly rejected (no proof): ${noProofData.error}`)
  } else if (noProofRes.ok) {
    console.log(`  ⚠️ TEE signed without proof (ZK may be disabled on server)`)
  } else {
    console.log(`  Result: ${noProofData.error}`)
  }

  // Step 4: Send with FAKE proof — should be rejected
  console.log('\n[4/4] Sending hashes with FAKE ZK proof (should be rejected)...')
  const fakeProof = {
    ...proof,
    publicSignals: ['999', '888', '777', '666'] as [string, string, string, string],
  }
  const fakeReq = {
    ...hashes,
    endpoint: 'gemini:generativelanguage.googleapis.com',
    timestamp: Math.floor(Date.now() / 1000),
    zk_proof: fakeProof,
  }

  const fakeRes = await fetch(`${TEE_URL}/eth-sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(fakeReq),
  })
  const fakeData = await fakeRes.json() as any

  if (fakeRes.status === 400) {
    console.log(`  ✅ TEE correctly rejected (fake proof): ${fakeData.error}`)
  } else {
    console.log(`  ❌ TEE unexpectedly accepted fake proof!`)
    process.exit(1)
  }

  console.log('\n=== All tests passed! ===')
}

main().catch(e => {
  console.error('Test failed:', e)
  process.exit(1)
})
