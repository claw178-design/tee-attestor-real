# TEE Attestor — User Guide

How to sign, verify, and submit API usage claims on-chain.

## Overview

```
You (local)                     TEE Attestor                    Ethereum (Sepolia)
    │                               │                               │
    │ 1. Hash your data locally     │                               │
    │ 2. POST /eth-sign ──────────→ │ Sign with EIP-712             │
    │ ←────────────────── signature │                               │
    │ 3. Submit on-chain ─────────────────────────────────────────→ │ Store claim
    │ 4. Anyone can verify ───────────────────────────────────────→ │ verifyClaim()
```

- **Your API key never leaves your machine.**
- **Plaintext data never leaves your machine.** Only hashes are sent.
- **The TEE signs the hashes.** Remote attestation proves the TEE is genuine.
- **The contract verifies the signature.** Anyone can check on-chain.

## Addresses

| Component | Address |
|-----------|---------|
| **TEE Attestor** | `https://zktls.judgeclaw.xyz:8080` |
| **ClaimVerifierV2** | [`0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C`](https://sepolia.etherscan.io/address/0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C) |
| **Groth16Verifier** | [`0x4b92c5a4ac7C5783b5F149F4861E2438c303Fa22`](https://sepolia.etherscan.io/address/0x4b92c5a4ac7C5783b5F149F4861E2438c303Fa22) |
| **EigenCompute App** | [`0x8eF53C5F2194ec99F20ae20266f34b4f18F6dec5`](https://verify-sepolia.eigencloud.xyz/app/0x8eF53C5F2194ec99F20ae20266f34b4f18F6dec5) |
| **Chain** | Ethereum Sepolia (chainId: 11155111) |

## Step-by-Step

### Step 1 — Hash your data locally

Compute SHA-256 hashes of your API usage data. **Never send plaintext.**

```bash
# Example: hash your data
USAGE='{"prompt_tokens":150,"completion_tokens":80,"total_tokens":230}'
MODEL='gpt-4'
PROMPT='Tell me about quantum computing'
RESPONSE='Quantum computing uses qubits...'

USAGE_HASH=0x$(echo -n "$USAGE" | sha256sum | cut -d' ' -f1)
MODEL_HASH=0x$(echo -n "$MODEL" | sha256sum | cut -d' ' -f1)
PROMPT_HASH=0x$(echo -n "$PROMPT" | sha256sum | cut -d' ' -f1)
RESPONSE_HASH=0x$(echo -n "$RESPONSE" | sha256sum | cut -d' ' -f1)
TIMESTAMP=$(date +%s)
ENDPOINT="openai:https://api.openai.com/v1/chat/completions"
```

### Step 2 — Request TEE signature

Send hashes to the TEE attestor. It signs them with EIP-712 (Ethereum-compatible).

```bash
SIGNED=$(curl -s -X POST https://zktls.judgeclaw.xyz:8080/eth-sign \
  -H "Content-Type: application/json" \
  -d "{
    \"usage_hash\": \"$USAGE_HASH\",
    \"model_hash\": \"$MODEL_HASH\",
    \"prompt_hash\": \"$PROMPT_HASH\",
    \"response_hash\": \"$RESPONSE_HASH\",
    \"endpoint\": \"$ENDPOINT\",
    \"timestamp\": $TIMESTAMP
  }")

echo "$SIGNED" | jq .
```

**Response:**
```json
{
  "usage_hash": "0x4347...",
  "model_hash": "0xde40...",
  "prompt_hash": "0xb1aa...",
  "response_hash": "0x185f...",
  "endpoint": "openai:https://api.openai.com/v1/chat/completions",
  "timestamp": 1773200000,
  "eth_signature": "0x3045...(65 bytes r+s+v)",
  "eth_signer_address": "0x851D...",
  "eip712_domain": {
    "name": "ClaimVerifier",
    "version": "1",
    "chainId": 11155111,
    "verifyingContract": "0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C"
  }
}
```

### Step 3 — Verify the TEE is genuine (optional but recommended)

```bash
# Check remote attestation
curl -s https://zktls.judgeclaw.xyz:8080/attestation | jq .
```

Verify on the EigenCompute dashboard:
https://verify-sepolia.eigencloud.xyz/app/0x8eF53C5F2194ec99F20ae20266f34b4f18F6dec5

This confirms:
- The attestor runs inside a real TEE (TDX)
- The Docker image hash matches the open-source code
- The signing key was generated inside the TEE

### Step 4 — Verify signature on-chain (read-only, no gas)

```bash
# Using cast (Foundry)
SIGNATURE=$(echo "$SIGNED" | jq -r '.eth_signature')

cast call 0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C \
  "verifyClaim(bytes32,bytes32,bytes32,bytes32,string,uint256,bytes)(bool,address)" \
  "$USAGE_HASH" "$MODEL_HASH" "$PROMPT_HASH" "$RESPONSE_HASH" \
  "$ENDPOINT" "$TIMESTAMP" "$SIGNATURE" \
  --rpc-url https://rpc.sepolia.org
```

**Returns:** `true` + the TEE's Ethereum address.

### Step 5 — Submit claim on-chain (writes to contract, costs gas)

```bash
# Using cast with your wallet private key
cast send 0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C \
  "submitClaim(bytes32,bytes32,bytes32,bytes32,string,uint256,bytes)" \
  "$USAGE_HASH" "$MODEL_HASH" "$PROMPT_HASH" "$RESPONSE_HASH" \
  "$ENDPOINT" "$TIMESTAMP" "$SIGNATURE" \
  --rpc-url https://rpc.sepolia.org \
  --private-key YOUR_WALLET_PRIVATE_KEY
```

The contract emits a `ClaimVerified` event with the claim ID.

### Step 6 — Read your claims

```bash
# Total claims stored
cast call 0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C \
  "totalClaims()(uint256)" \
  --rpc-url https://rpc.sepolia.org

# Get a specific claim by ID
cast call 0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C \
  "getClaim(bytes32)(bytes32,bytes32,bytes32,bytes32,string,uint256,address,uint256,bool)" \
  "$CLAIM_ID" \
  --rpc-url https://rpc.sepolia.org

# Count claims by a specific submitter
cast call 0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C \
  "claimCountBySubmitter(address)(uint256)" \
  "YOUR_ADDRESS" \
  --rpc-url https://rpc.sepolia.org
```

---

## JavaScript / TypeScript Example

```typescript
import { ethers } from "ethers";
import crypto from "crypto";

// 1. Hash your data
function sha256Hex(data: string): string {
  return "0x" + crypto.createHash("sha256").update(data).digest("hex");
}

const claim = {
  usage_hash: sha256Hex('{"total_tokens":230}'),
  model_hash: sha256Hex("gpt-4"),
  prompt_hash: sha256Hex("Tell me about quantum computing"),
  response_hash: sha256Hex("Quantum computing uses qubits..."),
  endpoint: "openai:https://api.openai.com/v1/chat/completions",
  timestamp: Math.floor(Date.now() / 1000),
};

// 2. Get TEE signature
const res = await fetch("https://zktls.judgeclaw.xyz:8080/eth-sign", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(claim),
});
const signed = await res.json();

// 3. Submit on-chain
const provider = new ethers.JsonRpcProvider("https://rpc.sepolia.org");
const wallet = new ethers.Wallet("YOUR_PRIVATE_KEY", provider);

const abi = [
  "function submitClaim(bytes32,bytes32,bytes32,bytes32,string,uint256,bytes) returns (bytes32)",
  "function verifyClaim(bytes32,bytes32,bytes32,bytes32,string,uint256,bytes) view returns (bool,address)",
  "function totalClaims() view returns (uint256)",
  "function getClaim(bytes32) view returns (tuple(bytes32,bytes32,bytes32,bytes32,string,uint256,address,uint256,bool))",
];

const contract = new ethers.Contract(
  "0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C",
  abi,
  wallet
);

// Verify first (free, no gas)
const [valid, signer] = await contract.verifyClaim(
  claim.usage_hash, claim.model_hash,
  claim.prompt_hash, claim.response_hash,
  claim.endpoint, claim.timestamp,
  signed.eth_signature
);
console.log("Valid:", valid, "Signer:", signer);

// Submit (costs gas)
const tx = await contract.submitClaim(
  claim.usage_hash, claim.model_hash,
  claim.prompt_hash, claim.response_hash,
  claim.endpoint, claim.timestamp,
  signed.eth_signature
);
console.log("TX:", tx.hash);
await tx.wait();
```

---

## Python Example

```python
import hashlib, json, time, requests
from web3 import Web3

# 1. Hash your data
def sha256_hex(data: str) -> str:
    return "0x" + hashlib.sha256(data.encode()).hexdigest()

claim = {
    "usage_hash": sha256_hex('{"total_tokens":230}'),
    "model_hash": sha256_hex("gpt-4"),
    "prompt_hash": sha256_hex("Tell me about quantum computing"),
    "response_hash": sha256_hex("Quantum computing uses qubits..."),
    "endpoint": "openai:https://api.openai.com/v1/chat/completions",
    "timestamp": int(time.time()),
}

# 2. Get TEE signature
resp = requests.post(
    "https://zktls.judgeclaw.xyz:8080/eth-sign",
    json=claim,
)
signed = resp.json()
signature = signed["eth_signature"]

# 3. Verify on-chain (free)
w3 = Web3(Web3.HTTPProvider("https://rpc.sepolia.org"))

abi = json.loads('[{"inputs":[{"name":"usageHash","type":"bytes32"},{"name":"modelHash","type":"bytes32"},{"name":"promptHash","type":"bytes32"},{"name":"responseHash","type":"bytes32"},{"name":"endpoint","type":"string"},{"name":"timestamp","type":"uint256"},{"name":"signature","type":"bytes"}],"name":"verifyClaim","outputs":[{"name":"valid","type":"bool"},{"name":"signer","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"name":"usageHash","type":"bytes32"},{"name":"modelHash","type":"bytes32"},{"name":"promptHash","type":"bytes32"},{"name":"responseHash","type":"bytes32"},{"name":"endpoint","type":"string"},{"name":"timestamp","type":"uint256"},{"name":"signature","type":"bytes"}],"name":"submitClaim","outputs":[{"name":"claimId","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"}]')

contract = w3.eth.contract(
    address="0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C",
    abi=abi,
)

valid, signer = contract.functions.verifyClaim(
    bytes.fromhex(claim["usage_hash"][2:]),
    bytes.fromhex(claim["model_hash"][2:]),
    bytes.fromhex(claim["prompt_hash"][2:]),
    bytes.fromhex(claim["response_hash"][2:]),
    claim["endpoint"],
    claim["timestamp"],
    bytes.fromhex(signature[2:]),
).call()

print(f"Valid: {valid}, Signer: {signer}")

# 4. Submit on-chain (costs gas)
account = w3.eth.account.from_key("YOUR_PRIVATE_KEY")
tx = contract.functions.submitClaim(
    bytes.fromhex(claim["usage_hash"][2:]),
    bytes.fromhex(claim["model_hash"][2:]),
    bytes.fromhex(claim["prompt_hash"][2:]),
    bytes.fromhex(claim["response_hash"][2:]),
    claim["endpoint"],
    claim["timestamp"],
    bytes.fromhex(signature[2:]),
).build_transaction({
    "from": account.address,
    "nonce": w3.eth.get_transaction_count(account.address),
    "gas": 200000,
})
signed_tx = account.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
print(f"TX: {tx_hash.hex()}")
```

---

## TEE API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/attestation` | GET | Remote attestation report (TEE proof) |
| `/eth-sign` | POST | Sign claim with EIP-712 (for on-chain verification) |
| `/sign` | POST | Sign claim with raw ECDSA |
| `/verify` | POST | Verify a signed claim off-chain |
| `/pubkey` | GET | Attestor public key |
| `/eth-address` | GET | Attestor Ethereum address |
| `/ws` | WS | zkTLS tunnel (Reclaim attestor-core) |

## Contract ABI (Key Functions)

```solidity
// Verify signature (free, no gas)
function verifyClaim(
    bytes32 usageHash, bytes32 modelHash,
    bytes32 promptHash, bytes32 responseHash,
    string endpoint, uint256 timestamp,
    bytes signature
) view returns (bool valid, address signer);

// Submit claim (costs gas, stores on-chain)
function submitClaim(
    bytes32 usageHash, bytes32 modelHash,
    bytes32 promptHash, bytes32 responseHash,
    string endpoint, uint256 timestamp,
    bytes signature
) returns (bytes32 claimId);

// Submit with ZK proof (costs gas, stronger verification)
function submitClaimWithZkProof(
    bytes32 usageHash, bytes32 modelHash,
    bytes32 promptHash, bytes32 responseHash,
    string endpoint, uint256 timestamp,
    bytes signature,
    uint[2] pA, uint[2][2] pB, uint[2] pC
) returns (bytes32 claimId);

// Read stored claims
function totalClaims() view returns (uint256);
function getClaim(bytes32 claimId) view returns (StoredClaim);
function claimCountBySubmitter(address) view returns (uint256);
```

## Self-Verification Checklist

1. **TEE is genuine** — Check https://verify-sepolia.eigencloud.xyz/app/0x8eF53C5F2194ec99F20ae20266f34b4f18F6dec5
2. **Image matches source** — Compare `image_digest` with the Docker build from GitHub source
3. **Signature is valid** — Call `verifyClaim()` on-chain (free)
4. **Claim is stored** — Call `getClaim(claimId)` to read back

## Source Code

- GitHub: https://github.com/claw178-design/tee-attestor-real
- Contracts: `contracts/ClaimVerifierV2.sol`
- TEE Server: `src/tee-server.ts`
