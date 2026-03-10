pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * ClaimHashProof — proves knowledge of 4 preimages for 4 Poseidon hashes.
 *
 * Private inputs:  usage_preimage, model_preimage, prompt_preimage, response_preimage
 * Public outputs:  usage_hash, model_hash, prompt_hash, response_hash
 *
 * The prover demonstrates "I know the original data" without revealing it.
 * Combined with TEE remote attestation, this prevents users from
 * submitting fake hashes (they must know the real preimage).
 *
 * Each preimage is a single field element (BN128 scalar field, ~254 bits).
 * For longer data, hash externally first then use the digest as preimage.
 */
template ClaimHashProof() {
    // Private inputs — the original data (never revealed)
    signal input usage_preimage;
    signal input model_preimage;
    signal input prompt_preimage;
    signal input response_preimage;

    // Public outputs — the Poseidon hashes (written into the claim)
    signal output usage_hash;
    signal output model_hash;
    signal output prompt_hash;
    signal output response_hash;

    // Poseidon(1) for each field
    component h_usage = Poseidon(1);
    h_usage.inputs[0] <== usage_preimage;
    usage_hash <== h_usage.out;

    component h_model = Poseidon(1);
    h_model.inputs[0] <== model_preimage;
    model_hash <== h_model.out;

    component h_prompt = Poseidon(1);
    h_prompt.inputs[0] <== prompt_preimage;
    prompt_hash <== h_prompt.out;

    component h_response = Poseidon(1);
    h_response.inputs[0] <== response_preimage;
    response_hash <== h_response.out;
}

component main = ClaimHashProof();
