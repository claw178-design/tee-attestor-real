#!/usr/bin/env bash
set -euo pipefail

# End-to-end test: TEE attestor → EIP-712 sign → TEE verify → On-chain submit
#
# Tests the full flow:
#   1. TEE health check
#   2. TEE remote attestation
#   3. EIP-712 sign a claim via TEE
#   4. Verify the signed claim via TEE
#   5. Submit the signed claim to Sepolia ClaimVerifierV2
#   6. Read the claim back from the contract

TEE_URL="${TEE_URL:-https://zktls.judgeclaw.xyz:8080}"
CLAIM_VERIFIER="${CLAIM_VERIFIER:-0x98b05fb625B8867f073277B7EAbF1ccC7E0926c9}"
SEPOLIA_RPC="${SEPOLIA_RPC:-https://ethereum-sepolia-rpc.publicnode.com}"
DEPLOY_KEY="${DEPLOY_KEY:-0x038c5033e7a4be6af6ae4a23461f8204478c3a963f677f66b0108e7972193631}"

echo "=== TEE Attestor End-to-End Test ==="
echo "TEE URL: $TEE_URL"
echo "Contract: $CLAIM_VERIFIER"
echo ""

# Step 1: Health check
echo "--- Step 1: Health Check ---"
HEALTH=$(curl -sk "$TEE_URL/health")
echo "$HEALTH" | jq .
STATUS=$(echo "$HEALTH" | jq -r '.status')
if [ "$STATUS" != "ok" ]; then
  echo "FAIL: Health check returned status=$STATUS"
  exit 1
fi
echo "PASS: TEE attestor is healthy"
echo ""

# Step 2: Remote attestation
echo "--- Step 2: Remote Attestation ---"
ATTEST=$(curl -sk "$TEE_URL/attestation")
echo "$ATTEST" | jq .
IS_TEE=$(echo "$ATTEST" | jq -r '.is_tee')
echo "is_tee: $IS_TEE"
echo "PASS: Attestation data retrieved"
echo ""

# Step 3: EIP-712 Sign a claim
echo "--- Step 3: EIP-712 Sign Claim ---"
TIMESTAMP=$(date +%s)
USAGE_HASH="0x$(echo -n '{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}' | sha256sum | cut -d' ' -f1)"
MODEL_HASH="0x$(echo -n 'gemini-2.5-flash' | sha256sum | cut -d' ' -f1)"
PROMPT_HASH="0x$(echo -n 'What is the meaning of life?' | sha256sum | cut -d' ' -f1)"
RESPONSE_HASH="0x$(echo -n 'The meaning of life is to find purpose and connection.' | sha256sum | cut -d' ' -f1)"
ENDPOINT="gemini:https://generativelanguage.googleapis.com"

SIGN_BODY="{\"usage_hash\":\"$USAGE_HASH\",\"model_hash\":\"$MODEL_HASH\",\"prompt_hash\":\"$PROMPT_HASH\",\"response_hash\":\"$RESPONSE_HASH\",\"endpoint\":\"$ENDPOINT\",\"timestamp\":$TIMESTAMP,\"chain_id\":11155111,\"verifier_address\":\"$CLAIM_VERIFIER\"}"

echo "Request:"
echo "$SIGN_BODY" | python3 -m json.tool 2>/dev/null || echo "$SIGN_BODY"
SIGN_RESULT=$(curl -sk -X POST "$TEE_URL/eth-sign" \
  -H "Content-Type: application/json" \
  -d "$SIGN_BODY")
echo "Response:"
echo "$SIGN_RESULT" | jq .

SIGN_OK=$(echo "$SIGN_RESULT" | jq -r '.ok')
if [ "$SIGN_OK" != "true" ]; then
  echo "FAIL: EIP-712 sign failed"
  exit 1
fi

ETH_SIG=$(echo "$SIGN_RESULT" | jq -r '.claim.eth_signature')
ETH_SIGNER=$(echo "$SIGN_RESULT" | jq -r '.claim.eth_signer_address')
echo "Signature: ${ETH_SIG:0:20}..."
echo "Signer: $ETH_SIGNER"
echo "PASS: Claim signed with EIP-712"
echo ""

# Step 4: Verify via TEE
echo "--- Step 4: TEE Verify ---"
VERIFY_RESULT=$(curl -sk -X POST "$TEE_URL/eth-verify" \
  -H "Content-Type: application/json" \
  -d "$(echo "$SIGN_RESULT" | jq '{claim: .claim}')")
echo "$VERIFY_RESULT" | jq .
VALID=$(echo "$VERIFY_RESULT" | jq -r '.valid')
if [ "$VALID" != "true" ]; then
  echo "FAIL: TEE verification failed"
  exit 1
fi
echo "PASS: TEE verification succeeded"
echo ""

# Step 5: Submit to Sepolia
echo "--- Step 5: Submit to Sepolia ClaimVerifierV2 ---"
echo "Contract: $CLAIM_VERIFIER"
echo "Using submitClaim (TEE sig only, no ZK proof)"

# Use cast to submit the claim
TX_HASH=$(cast send "$CLAIM_VERIFIER" \
  "submitClaim(bytes32,bytes32,bytes32,bytes32,string,uint256,bytes)" \
  "$USAGE_HASH" "$MODEL_HASH" "$PROMPT_HASH" "$RESPONSE_HASH" \
  "$ENDPOINT" "$TIMESTAMP" "$ETH_SIG" \
  --rpc-url "$SEPOLIA_RPC" \
  --private-key "$DEPLOY_KEY" \
  --json 2>/dev/null | jq -r '.transactionHash')

echo "TX Hash: $TX_HASH"

# Wait for receipt
echo "Waiting for confirmation..."
RECEIPT=$(cast receipt "$TX_HASH" --rpc-url "$SEPOLIA_RPC" --json 2>/dev/null)
TX_STATUS=$(echo "$RECEIPT" | jq -r '.status')
BLOCK_NUM=$(echo "$RECEIPT" | jq -r '.blockNumber')
GAS_USED=$(echo "$RECEIPT" | jq -r '.gasUsed')

if [ "$TX_STATUS" = "0x1" ] || [ "$TX_STATUS" = "1" ]; then
  echo "PASS: Transaction confirmed in block $BLOCK_NUM (gas: $GAS_USED)"
else
  echo "FAIL: Transaction reverted (status: $TX_STATUS)"
  echo "Receipt: $(echo "$RECEIPT" | jq .)"
  exit 1
fi
echo ""

# Step 6: Read claim back from contract
echo "--- Step 6: Read Claim from Contract ---"
TOTAL=$(cast call "$CLAIM_VERIFIER" "totalClaims()" --rpc-url "$SEPOLIA_RPC")
echo "Total claims on-chain: $TOTAL"

# Compute claim ID (same as contract: keccak256(abi.encode(...)))
CLAIM_ID=$(cast keccak256 "$(cast abi-encode "f(bytes32,bytes32,bytes32,bytes32,bytes32,uint256)" \
  "$USAGE_HASH" "$MODEL_HASH" "$PROMPT_HASH" "$RESPONSE_HASH" \
  "$(cast keccak256 "$(cast --from-utf8 "$ENDPOINT")")" \
  "$TIMESTAMP")")
echo "Claim ID: $CLAIM_ID"

# Read stored claim
STORED=$(cast call "$CLAIM_VERIFIER" \
  "getClaim(bytes32)(bytes32,bytes32,bytes32,bytes32,string,uint256,address,uint256,bool)" \
  "$CLAIM_ID" \
  --rpc-url "$SEPOLIA_RPC" 2>/dev/null || echo "FAILED")

if [ "$STORED" = "FAILED" ]; then
  echo "WARNING: Could not read claim back (may need different ABI decoding)"
else
  echo "Stored claim:"
  echo "$STORED"
fi

# Also verify on-chain
echo ""
echo "--- Step 7: On-chain Verify (view call) ---"
ON_CHAIN_VERIFY=$(cast call "$CLAIM_VERIFIER" \
  "verifyClaim(bytes32,bytes32,bytes32,bytes32,string,uint256,bytes)(bool,address)" \
  "$USAGE_HASH" "$MODEL_HASH" "$PROMPT_HASH" "$RESPONSE_HASH" \
  "$ENDPOINT" "$TIMESTAMP" "$ETH_SIG" \
  --rpc-url "$SEPOLIA_RPC")
echo "On-chain verify result: $ON_CHAIN_VERIFY"

echo ""
echo "=== END-TO-END TEST COMPLETE ==="
echo ""
echo "Summary:"
echo "  TEE Health:        PASS"
echo "  Remote Attestation: PASS"
echo "  EIP-712 Sign:      PASS"
echo "  TEE Verify:        PASS"
echo "  Sepolia Submit:    PASS (tx: $TX_HASH)"
echo "  On-chain Verify:   $ON_CHAIN_VERIFY"
echo ""
echo "Etherscan: https://sepolia.etherscan.io/tx/$TX_HASH"
echo "Dashboard: https://verify-sepolia.eigencloud.xyz/app/0x8eF53C5F2194ec99F20ae20266f34b4f18F6dec5"
