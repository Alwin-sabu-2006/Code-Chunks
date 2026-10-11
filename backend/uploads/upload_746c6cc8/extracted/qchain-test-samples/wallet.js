// INTENTIONALLY QUANTUM-VULNERABLE demo (Q-Chain test sample).
const EC = require('elliptic').ec;
const crypto = require('crypto');

const ec = new EC('secp256k1'); // FINDING 1: secp256k1 curve

function newKeyPair() {
  return ec.genKeyPair();
}

function signHash(hashHex, keyPair) {
  return keyPair.sign(hashHex); // FINDING 2: ECDSA signing
}

function verifyHash(hashHex, signature, pubHex) {
  return ec.keyFromPublic(pubHex, 'hex').verify(hashHex, signature); // FINDING 2: ECDSA verify
}

function peerSecret() {
  // FINDING 3: ECDH key agreement on P-256 (prime256v1)
  const a = crypto.createECDH('prime256v1');
  const b = crypto.createECDH('prime256v1');
  a.generateKeys();
  b.generateKeys();
  return a.computeSecret(b.getPublicKey());
}

// FINDING 4: RSA-2048 signing
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
function rsaSign(data) {
  return crypto.sign('sha256', Buffer.from(data), privateKey);
}

// DECOY (not quantum-vulnerable): hashing
function digest(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// DECOY (not quantum-vulnerable): 256-bit symmetric encryption
function encrypt(key32, iv12, plaintext) {
  const c = crypto.createCipheriv('aes-256-gcm', key32, iv12);
  return Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
}

module.exports = { newKeyPair, signHash, verifyHash, peerSecret, rsaSign, digest, encrypt, publicKey };
