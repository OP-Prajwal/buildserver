const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const keysDir = path.join(__dirname, '..', 'build-server', 'keys');
if (!fs.existsSync(keysDir)) {
  fs.mkdirSync(keysDir, { recursive: true });
}

fs.writeFileSync(path.join(keysDir, 'ci-public.pem'), publicKey);
fs.writeFileSync(path.join(__dirname, 'ci_private_key.txt'), privateKey);

console.log('Keys generated successfully.');
console.log('Public key saved to build-server/keys/ci-public.pem');
console.log('Private key saved to keygen/ci_private_key.txt (Add this to GitHub Secrets as CI_PRIVATE_KEY)');
