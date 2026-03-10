// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Groth16Verifier.sol";

/// @title ClaimVerifierV2
/// @notice Verifies TEE attestor-signed All-Hash claims with ZK proof verification.
///         Path B architecture: TEE signs hashes, ZK proof proves hash preimage knowledge.
///         Neither the TEE nor the contract ever sees plaintext data.
contract ClaimVerifierV2 {
    // --- Types ---
    struct Claim {
        bytes32 usageHash;    // Poseidon hash of usage data
        bytes32 modelHash;    // Poseidon hash of model identifier
        bytes32 promptHash;   // Poseidon hash of prompt content
        bytes32 responseHash; // Poseidon hash of response content
        string  endpoint;     // Target API endpoint (revealed)
        uint256 timestamp;    // Unix timestamp of attestation
    }

    struct ZkProof {
        uint[2]   pA;        // Groth16 proof point A
        uint[2][2] pB;       // Groth16 proof point B
        uint[2]   pC;        // Groth16 proof point C
    }

    struct StoredClaim {
        bytes32 usageHash;
        bytes32 modelHash;
        bytes32 promptHash;
        bytes32 responseHash;
        string  endpoint;
        uint256 timestamp;
        address submitter;
        uint256 blockNumber;
        bool    zkVerified;   // Whether ZK proof was verified
    }

    // --- State ---
    address public owner;
    address public attestorAddress;
    Groth16Verifier public immutable zkVerifier;

    // EIP-712 domain
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _CLAIM_TYPEHASH =
        keccak256("Claim(bytes32 usageHash,bytes32 modelHash,bytes32 promptHash,bytes32 responseHash,string endpoint,uint256 timestamp)");

    bytes32 private _cachedDomainSeparator;
    uint256 private _cachedChainId;

    // Verified claims storage
    mapping(bytes32 => StoredClaim) public claims;
    bytes32[] public claimIds;
    mapping(address => bytes32[]) public claimsBySubmitter;

    // --- Events ---
    event ClaimVerified(
        bytes32 indexed claimId,
        address indexed submitter,
        bytes32 usageHash,
        bytes32 modelHash,
        uint256 timestamp,
        bool    zkVerified
    );
    event AttestorUpdated(address indexed oldAttestor, address indexed newAttestor);
    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);

    // --- Errors ---
    error NotOwner();
    error InvalidSignature();
    error InvalidZkProof();
    error ClaimAlreadyExists();
    error ClaimNotFound();
    error ZeroAddress();
    error HashMismatch();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _attestorAddress, address _zkVerifier) {
        if (_attestorAddress == address(0)) revert ZeroAddress();
        if (_zkVerifier == address(0)) revert ZeroAddress();
        owner = msg.sender;
        attestorAddress = _attestorAddress;
        zkVerifier = Groth16Verifier(_zkVerifier);
        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _buildDomainSeparator();
    }

    // --- Admin ---
    function setOwner(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address old = owner;
        owner = newOwner;
        emit OwnerUpdated(old, newOwner);
    }

    function setAttestor(address newAttestor) external onlyOwner {
        if (newAttestor == address(0)) revert ZeroAddress();
        address old = attestorAddress;
        attestorAddress = newAttestor;
        emit AttestorUpdated(old, newAttestor);
    }

    // --- EIP-712 ---
    function domainSeparator() public view returns (bytes32) {
        if (block.chainid == _cachedChainId) return _cachedDomainSeparator;
        return _buildDomainSeparator();
    }

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            _EIP712_DOMAIN_TYPEHASH,
            keccak256(bytes("ClaimVerifierV2")),
            keccak256(bytes("2")),
            block.chainid,
            address(this)
        ));
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }

    // --- Core: Submit claim with TEE signature + ZK proof ---
    /// @notice Submit a claim verified by both TEE signature and ZK proof.
    /// @dev The ZK proof proves the submitter knows preimages for the Poseidon hashes.
    ///      The TEE signature proves the claim was generated in a trusted environment.
    function submitClaimWithZkProof(
        bytes32 usageHash,
        bytes32 modelHash,
        bytes32 promptHash,
        bytes32 responseHash,
        string calldata endpoint,
        uint256 timestamp,
        bytes calldata signature,
        uint[2] calldata pA,
        uint[2][2] calldata pB,
        uint[2] calldata pC
    ) external returns (bytes32 claimId) {
        // 1. Compute claim ID
        claimId = keccak256(abi.encode(
            usageHash, modelHash, promptHash, responseHash,
            keccak256(bytes(endpoint)), timestamp
        ));
        if (claims[claimId].timestamp != 0) revert ClaimAlreadyExists();

        // 2. Verify TEE attestor signature (EIP-712)
        bytes32 structHash = keccak256(abi.encode(
            _CLAIM_TYPEHASH,
            usageHash, modelHash, promptHash, responseHash,
            keccak256(bytes(endpoint)), timestamp
        ));
        bytes32 digest = _hashTypedData(structHash);
        address signer = _recover(digest, signature);
        if (signer != attestorAddress) revert InvalidSignature();

        // 3. Verify ZK proof — public signals must match claim hashes
        uint[4] memory pubSignals = [
            uint256(usageHash),
            uint256(modelHash),
            uint256(promptHash),
            uint256(responseHash)
        ];
        bool zkValid = zkVerifier.verifyProof(pA, pB, pC, pubSignals);
        if (!zkValid) revert InvalidZkProof();

        // 4. Store verified claim
        claims[claimId] = StoredClaim({
            usageHash: usageHash,
            modelHash: modelHash,
            promptHash: promptHash,
            responseHash: responseHash,
            endpoint: endpoint,
            timestamp: timestamp,
            submitter: msg.sender,
            blockNumber: block.number,
            zkVerified: true
        });
        claimIds.push(claimId);
        claimsBySubmitter[msg.sender].push(claimId);

        emit ClaimVerified(claimId, msg.sender, usageHash, modelHash, timestamp, true);
    }

    // --- Submit with TEE signature only (no ZK proof) ---
    /// @notice Submit a claim verified by TEE signature only.
    ///         Use when ZK proof is not available or not required.
    function submitClaim(
        bytes32 usageHash,
        bytes32 modelHash,
        bytes32 promptHash,
        bytes32 responseHash,
        string calldata endpoint,
        uint256 timestamp,
        bytes calldata signature
    ) external returns (bytes32 claimId) {
        claimId = keccak256(abi.encode(
            usageHash, modelHash, promptHash, responseHash,
            keccak256(bytes(endpoint)), timestamp
        ));
        if (claims[claimId].timestamp != 0) revert ClaimAlreadyExists();

        bytes32 structHash = keccak256(abi.encode(
            _CLAIM_TYPEHASH,
            usageHash, modelHash, promptHash, responseHash,
            keccak256(bytes(endpoint)), timestamp
        ));
        bytes32 digest = _hashTypedData(structHash);
        address signer = _recover(digest, signature);
        if (signer != attestorAddress) revert InvalidSignature();

        claims[claimId] = StoredClaim({
            usageHash: usageHash,
            modelHash: modelHash,
            promptHash: promptHash,
            responseHash: responseHash,
            endpoint: endpoint,
            timestamp: timestamp,
            submitter: msg.sender,
            blockNumber: block.number,
            zkVerified: false
        });
        claimIds.push(claimId);
        claimsBySubmitter[msg.sender].push(claimId);

        emit ClaimVerified(claimId, msg.sender, usageHash, modelHash, timestamp, false);
    }

    // --- View: verify ZK proof without storing ---
    function verifyZkProof(
        bytes32 usageHash,
        bytes32 modelHash,
        bytes32 promptHash,
        bytes32 responseHash,
        uint[2] calldata pA,
        uint[2][2] calldata pB,
        uint[2] calldata pC
    ) external view returns (bool) {
        uint[4] memory pubSignals = [
            uint256(usageHash),
            uint256(modelHash),
            uint256(promptHash),
            uint256(responseHash)
        ];
        return zkVerifier.verifyProof(pA, pB, pC, pubSignals);
    }

    // --- View: verify signature without storing ---
    function verifyClaim(
        bytes32 usageHash,
        bytes32 modelHash,
        bytes32 promptHash,
        bytes32 responseHash,
        string calldata endpoint,
        uint256 timestamp,
        bytes calldata signature
    ) external view returns (bool valid, address signer) {
        bytes32 structHash = keccak256(abi.encode(
            _CLAIM_TYPEHASH,
            usageHash, modelHash, promptHash, responseHash,
            keccak256(bytes(endpoint)), timestamp
        ));
        bytes32 digest = _hashTypedData(structHash);
        signer = _recover(digest, signature);
        valid = (signer == attestorAddress);
    }

    // --- View: compute digest for off-chain signing ---
    function claimDigest(
        bytes32 usageHash,
        bytes32 modelHash,
        bytes32 promptHash,
        bytes32 responseHash,
        string calldata endpoint,
        uint256 timestamp
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            _CLAIM_TYPEHASH,
            usageHash, modelHash, promptHash, responseHash,
            keccak256(bytes(endpoint)), timestamp
        ));
        return _hashTypedData(structHash);
    }

    // --- View helpers ---
    function totalClaims() external view returns (uint256) {
        return claimIds.length;
    }

    function claimCountBySubmitter(address submitter) external view returns (uint256) {
        return claimsBySubmitter[submitter].length;
    }

    function getClaim(bytes32 claimId) external view returns (StoredClaim memory) {
        if (claims[claimId].timestamp == 0) revert ClaimNotFound();
        return claims[claimId];
    }
}
