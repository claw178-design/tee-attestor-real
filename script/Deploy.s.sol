// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../contracts/ClaimVerifierV2.sol";

contract DeployClaimVerifierV2 is Script {
    function run() external {
        address attestor = 0xe5Da119Fca2b36C996517DCd114CB1829f36b527;
        address zkVerifier = 0x02B6ae73A6f8fdcE8770E1D3126078A8cfA4D28f;

        vm.startBroadcast();
        ClaimVerifierV2 verifier = new ClaimVerifierV2(attestor, zkVerifier);
        vm.stopBroadcast();

        console.log("ClaimVerifierV2 deployed to:", address(verifier));
    }
}
