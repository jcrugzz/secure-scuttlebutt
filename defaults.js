
var Blake2s = require('blake2s')
var crypto  = require('crypto')
var JSONB   = require('json-buffer')
var curve   = require('./curve');

var codec   = require('./codec')

// this is all the developer specifiable things
// you need to give secure-scuttlebutt to get it to work.
// these should not be user-configurable, but it will
// be handy for forks to be able to use different
// crypto or encodings etc.

//
// TODO: rethink how this works since we can use prototype methods built into
// elliptic
//
module.exports = {

  //this must return a buffer digest.
  hash: function (data, enc) {
    return new Blake2s().update(data, enc).digest()
  },

  keys: {
    //this should return a key pair:
    // {public: Buffer, private: Buffer}

    generate: function () {
      return curve.genKeyPair();
    },
    //takes a public key and a hash and returns a signature.
    //(a signature must be a node buffer)
    sign: function (pub, hash) {
      return curve.sign(hash, pub);
    },

    //takes a public key, signature, and a hash
    //and returns true if the signature was valid.
    verify: function (pub, sig, hash) {
      return curve.verify(hash, sig, pub);
    },
    //codec for keys. this handles serializing
    //and deserializing keys for storage.
    //in elliptic curves, the public key can be
    //regenerated from the private key, so you only
    //need to serialize the private key.
    //in RSA, you need to remember both public and private keys.

    //maybe it's a good idea to add checksums and stuff
    //so that you can tell that this is a valid key when
    //read off the disk?
    //
    // TODO: rethink what these return based on how they are used
    codec: {
      decode: function (buffer) {
        return curve.keyPair(buffer.toString('hex'))
      },
      encode: function (keys) {
        return new Buffer(keys.getPrivate('hex', 'hex'));
      },
      //this makes this a valid level codec.
      buffer: true
    }
  },

  // the codec that is used to persist into leveldb.
  // this is the codec that will be passed to levelup.
  // https://github.com/rvagg/node-levelup#custom_encodings
  codec: codec
}

