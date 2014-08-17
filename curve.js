var EC = require('elliptic').ec;

// Potentially make this configurable but for now this seems to be what we are
// using
module.exports = new EC('secp256k1');
