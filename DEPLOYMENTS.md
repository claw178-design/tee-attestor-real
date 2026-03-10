# Contract Deployments

## Sepolia Testnet (Chain ID: 11155111)

| Contract | Address | Description |
|----------|---------|-------------|
| Groth16Verifier | `0x02B6ae73A6f8fdcE8770E1D3126078A8cfA4D28f` | ZK proof verifier (snarkjs Groth16) |
| ClaimVerifierV2 | `0x98b05fb625B8867f073277B7EAbF1ccC7E0926c9` | Main claim verification + storage |

### Constructor Parameters (ClaimVerifierV2)
- `attestorAddress`: `0xe5Da119Fca2b36C996517DCd114CB1829f36b527` (TEE attestor ETH address)
- `zkVerifier`: `0x02B6ae73A6f8fdcE8770E1D3126078A8cfA4D28f` (Groth16Verifier)

### Owner
- `0x8733119C5AE31458EDcBA1678872aF79c09E04D7`

### Etherscan Links
- [Groth16Verifier](https://sepolia.etherscan.io/address/0x02B6ae73A6f8fdcE8770E1D3126078A8cfA4D28f)
- [ClaimVerifierV2](https://sepolia.etherscan.io/address/0x98b05fb625B8867f073277B7EAbF1ccC7E0926c9)

### Verification
```bash
# Verify Groth16Verifier
forge verify-contract 0x02B6ae73A6f8fdcE8770E1D3126078A8cfA4D28f \
  contracts/Groth16Verifier.sol:Groth16Verifier \
  --chain sepolia --etherscan-api-key <KEY>

# Verify ClaimVerifierV2
forge verify-contract 0x98b05fb625B8867f073277B7EAbF1ccC7E0926c9 \
  contracts/ClaimVerifierV2.sol:ClaimVerifierV2 \
  --chain sepolia --etherscan-api-key <KEY> \
  --constructor-args $(cast abi-encode "constructor(address,address)" 0xe5Da119Fca2b36C996517DCd114CB1829f36b527 0x02B6ae73A6f8fdcE8770E1D3126078A8cfA4D28f)
```
