const Web3 = require("web3");

/**
 * Planted Vulnerability #3: web3.eth.accounts signing
 */
function createVoteSignature(rpcUrl, privateKey, voteHash) {
    const web3 = new Web3(rpcUrl);
    
    // VULNERABILITY #3: web3.eth.accounts.sign with secp256k1
    const signatureObject = web3.eth.accounts.sign(voteHash, privateKey);
    return signatureObject.signature;
}

module.exports = { createVoteSignature };
