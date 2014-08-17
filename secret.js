var crypto = require('crypto')
var curve = require('./curve');
var bsum = require('./util').bsum
var proquint = require('proquint-')

exports.encode = function (keys) {
  var PRIVATE = (keys
    && typeof keys.getPrivate === 'function'
    && keys.getPrivate('hex')
    || keys) || exports.generate();

  keys = curve.keyPair(PRIVATE);
  // This seems inefficient (not totally sure) but there might be a better way
  // TODO: have elliptic return buffers maybe?
  // A BN instance is what we get returned without passing in hex
  // https://github.com/indutny/bn.js/blob/master/lib/bn.js
  var public = bsum(new Buffer(keys.getPublic('hex'), 'hex'));

  var contents = [
  '### FOR YOUR EYES ONLY ###',
  '#',
  '# this is your SECRET name:',
  '',
  proquint
    .encode(new Buffer(keys.getPrivate('hex'), 'hex'))
    .split('-')
    .reduce(function (s, e, i) {
      return s + (i==4?'\n':i ? '-': '') + e
    },''),
  '',
  '# this name gives you magical powers.',
  '# with it you can mark your messages so that your friends can know',
  '# that they really did come from you.',
  '#',
  '# if any one learns your secret name, ',
  '# they can use it pretend to be you, or to destroy your identity.',
  '# NEVER show this to anyone!!!',
  '',
  '# NEVER edit your secret name. That will break everything and',
  '# you will have to start over.',
  '#',
  '# instead, share your public name',
  '# your public name: ' + proquint.encodeCamelDash(public),
  '# or as a hash : ' + public.toString('hex')
  ].join('\n')

  return contents
}

exports.decode = function (buffer) {
  buffer =
    buffer.toString('utf8')
      .replace(/\s*\#[^\n]*/g, '')

  return curve.keyPair(proquint.decode(buffer).toString('hex'))
}

exports.generate = function () {
  return curve.genKeyPair()
}

