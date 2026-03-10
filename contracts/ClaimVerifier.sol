// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ClaimVerifier
/// @notice Verifies TEE attestor-signed All-Hash claims on-chain.
///         The attestor runs inside an EigenCompute TEE and signs claims
///         containing OPRF hashes of API usage data (no plaintext on-chain).
contract ClaimVerifier {
    // --- Types ---
    struct Claim {
        bytes32 usageHash;
        bytes32 modelHash;
        bytes32 promptHash;
        bytes32 responseHash;
        string  endpoint;
        uint256 timestamp;
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
    }

    // --- State ---
    address public owner;
    address public attestorAddress; // TEE attestor's Ethereum address

    // EIP-712 domain
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _CLAIM_TYPEHASH =
        keccak256("Claim(bytes32 usageHash,bytes32 modelHash,bytes32 promptHash,bytes32 responseHash,string endpoint,uint256 timestamp)");

    bytes32 private _cachedDomainSeparator;
    uint256 private _cachedChainId;

    // Verified claims storage
    mapping(bytes32 => StoredClaim) public claims; // claimId => StoredClaim
    bytes32[] public claimIds;
    mapping(address => bytes32[]) public claimsBySubmitter;

    // --- Events ---
    event ClaimVerified(
        bytes32 indexed claimId,
        address indexed submitter,
        bytes32 usageHash,
        bytes32 modelHash,
        uint256 timestamp
    );
    event AttestorUpdated(address indexed oldAttestor, address indexed newAttestor);
    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);

    // --- Errors ---
    error NotOwner();
    error InvalidSignature();
    error ClaimAlreadyExists();
    error ClaimNotFound();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _attestorAddress) {
        if (_attestorAddress == address(0)) revert ZeroAddress();
        owner = msg.sender;
        attestorAddress = _attestorAddress;
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
            keccak256(bytes("ClaimVerifier")),
            keccak256(bytes("1")),
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

    // --- Core: Submit and verify a signed claim ---
    function submitClaim(
        bytes32 usageHash,
        bytes32 modelHash,
        bytes32 promptHash,
        bytes32 responseHash,
        string calldata endpoint,
        uint256 timestamp,
        bytes calldata signature
    ) external returns (bytes32 claimId) {
        // Compute claim ID (unique per claim content)
        claimId = keccak256(abi.encode(
            usageHash, modelHash, promptHash, responseHash,
            keccak256(bytes(endpoint)), timestamp
        ));

        if (claims[claimId].timestamp != 0) revert ClaimAlreadyExists();

        // EIP-712 struct hash
        bytes32 structHash = keccak256(abi.encode(
            _CLAIM_TYPEHASH,
            usageHash,
            modelHash,
            promptHash,
            responseHash,
            keccak256(bytes(endpoint)),
            timestamp
        ));
        bytes32 digest = _hashTypedData(structHash);
        address signer = _recover(digest, signature);
        if (signer != attestorAddress) revert InvalidSignature();

        // Store verified claim
        claims[claimId] = StoredClaim({
            usageHash: usageHash,
            modelHash: modelHash,
            promptHash: promptHash,
            responseHash: responseHash,
            endpoint: endpoint,
            timestamp: timestamp,
            submitter: msg.sender,
            blockNumber: block.number
        });
        claimIds.push(claimId);
        claimsBySubmitter[msg.sender].push(claimId);

        emit ClaimVerified(claimId, msg.sender, usageHash, modelHash, timestamp);
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
            usageHash,
            modelHash,
            promptHash,
            responseHash,
            keccak256(bytes(endpoint)),
            timestamp
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
            usageHash,
            modelHash,
            promptHash,
            responseHash,
            keccak256(bytes(endpoint)),
            timestamp
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
