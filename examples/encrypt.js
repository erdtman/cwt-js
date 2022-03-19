/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const CWT = require('../');

// Create
const encKey = {
  k: Buffer.from('231f4c4d4d3051fdc2ec0a3851d5b383', 'hex'),
  kid: 'Symmetric128'
};

const alg = 'AES-CCM-16-64-128';
const claims = {
  iss: 'coap://as.example.com',
  sub: 'erikw',
  aud: 'coap://light.example.com',
  exp: 1444064944,
  nbf: 1443944944,
  iat: 1443944944,
  cti: '0b71'
};

const cwt = new CWT(claims);
cwt.encrypt(encKey, alg).then(cwt => {
  console.log(cwt.raw.toString('hex'));
});

// Verify
const decKey = {
  k: Buffer.from('231f4c4d4d3051fdc2ec0a3851d5b383', 'hex'),
  kid: 'Symmetric128'
};
const token = Buffer.from('d08343a1010aa2044c53796d6d6574726963313238054d99a0d7846e762c49ffe8a63e0b5858b918a11fd81e438b7f973d9e2e119bcb22424ba0f38a80f27562f400ee1d0d6c0fdb559c02421fd384fc2ebe22d7071378b0ea7428fff157444d45f7e6afcda1aae5f6495830c58627087fc5b4974f319a8707a635dd643b', 'hex');

CWT.parse(token, decKey).then(cwt => {
  console.log(cwt.claims);
});
