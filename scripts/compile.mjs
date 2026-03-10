import fs from 'fs';
import solc from 'solc';

const source = fs.readFileSync('contracts/ClaimVerifier.sol', 'utf8');
const input = {
  language: 'Solidity',
  sources: { 'ClaimVerifier.sol': { content: source } },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } }
  }
};

const output = JSON.parse(solc.compile(JSON.stringify(input)));
if (output.errors?.length) {
  const fatal = output.errors.filter(e => e.severity === 'error');
  for (const e of output.errors) console.error(e.formattedMessage);
  if (fatal.length) process.exit(1);
}

const c = output.contracts['ClaimVerifier.sol']['ClaimVerifier'];
fs.mkdirSync('artifacts', { recursive: true });
fs.writeFileSync('artifacts/ClaimVerifier.abi.json', JSON.stringify(c.abi, null, 2));
fs.writeFileSync('artifacts/ClaimVerifier.bytecode.txt', c.evm.bytecode.object);
console.log('Compiled -> artifacts/ClaimVerifier.abi.json + .bytecode.txt');
