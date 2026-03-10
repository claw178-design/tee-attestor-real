import fs from 'fs';
import { ethers } from 'ethers';

const RPC_URL = process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-public.nodies.app';
const PRIVATE_KEY = process.env.PK || process.env.PRIVATE_KEY;
const ATTESTOR_ADDRESS = process.env.ATTESTOR_ETH_ADDRESS;

if (!PRIVATE_KEY) throw new Error('Missing PK or PRIVATE_KEY');
if (!ATTESTOR_ADDRESS) throw new Error('Missing ATTESTOR_ETH_ADDRESS (TEE attestor Ethereum address)');

const provider = new ethers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

const abi = JSON.parse(fs.readFileSync('artifacts/ClaimVerifier.abi.json', 'utf8'));
const bytecode = fs.readFileSync('artifacts/ClaimVerifier.bytecode.txt', 'utf8').trim();

console.log('Deployer:', wallet.address);
console.log('Attestor:', ATTESTOR_ADDRESS);
console.log('Chain: Sepolia');

const factory = new ethers.ContractFactory(abi, bytecode, wallet);
const contract = await factory.deploy(ATTESTOR_ADDRESS);
console.log('Deploy TX:', contract.deploymentTransaction().hash);
await contract.waitForDeployment();
const addr = await contract.getAddress();
console.log('ClaimVerifier:', addr);
console.log('Explorer:', `https://sepolia.etherscan.io/address/${addr}`);

// Write deployment info
const info = {
  contract: 'ClaimVerifier',
  address: addr,
  deployer: wallet.address,
  attestor: ATTESTOR_ADDRESS,
  chain: 'sepolia',
  chainId: 11155111,
  deployTx: contract.deploymentTransaction().hash,
  timestamp: new Date().toISOString(),
};
fs.writeFileSync('artifacts/deployment.sepolia.json', JSON.stringify(info, null, 2));
console.log('Deployment info saved to artifacts/deployment.sepolia.json');
