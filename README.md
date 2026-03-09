# tee-attestor-real

All-Hash TEE Attestor using Reclaim Protocol attestor-core.

## Design

Every business field (usage, model, prompt, response) is an **OPRF commitment** — no plaintext enters the claim. Authorization (API Key) is K2-hidden and never disclosed.

ZK proofs are attached to each claim for independent, trustless verification.

### Supported Providers

| Provider | Host | Auth Method |
|----------|------|-------------|
| OpenAI | api.openai.com | Bearer token (header) |
| Gemini | generativelanguage.googleapis.com | URL query param |
| Claude | api.anthropic.com | x-api-key header |

### Claim Structure

```json
{
  "usage_hash": "0xabc...",
  "model_hash": "0xdef...",
  "prompt_hash": "0x123...",
  "response_hash": "0x456...",
  "endpoint": "openai:api.openai.com",
  "timestamp": 1772853656,
  "attestor_sig": "0x...",
  "zk_proof": "base64..."
}
```

### Self-Verification

User proves knowledge: `Hash(usage_value) == usage_hash` → contract verifies.

## Quick Start

```bash
npm install
npm run build
npm test   # Phase 1: mock tests (no API key needed)
```

## Development Phases

### Phase 1 — Local Mock (current)
- Provider param building
- OPRF redaction strategy validation
- Claim structure tests

### Phase 2 — Real API
- TLS 1.3 KeyUpdate verification
- Real OPRF proof generation via attestor
- End-to-end claim verification
