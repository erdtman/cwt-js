/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const CWT = require('../');

// Create
const claims = {
  iss: 'coap://as.example.com',
  sub: 'erikw',
  aud: 'coap://light.example.com',
  exp: 1444064944,
  nbf: 1443944944,
  iat: 1443944944,
  cti: '0b71'
};

const encAlg = 'AES-CCM-16-64-128';
const encKey = {
  k: Buffer.from('231f4c4d4d3051fdc2ec0a3851d5b383', 'hex'),
  kid: 'Symmetric128'
};

const signAlg = 'ES256';
const signKey = {
  d: Buffer.from('6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19', 'hex'),
  kid: 'AsymmetricECDSA256'
};

const cwt = new CWT(claims);
cwt.sign(signKey, signAlg).then(signedCWT => {
  return signedCWT.encrypt(encKey, encAlg);
}).then(encryptedCWT => {
  console.log(encryptedCWT.raw.toString('hex'));
});

// Verify
const decKey = {
  k: Buffer.from('231f4c4d4d3051fdc2ec0a3851d5b383', 'hex'),
  kid: 'Symmetric128'
};

const verifyKey = {
  x: Buffer.from('143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f', 'hex'),
  y: Buffer.from('60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9', 'hex'),
  kid: 'AsymmetricECDSA256'
};

const token = Buffer.from('d08343a1010aa2044c53796d6d6574726963313238054dc62ed9a1391053623cdb5c5c7458b7cb6c7a62c5ad2792bd1b17c18e2eb28764c81e3f359ed7fc98a6177b179475548148b37b58319d403ae5929af804a356682f881ce4e409f0c3f8003620c03afaaa3a1ccf1fc0298cd98cd21d1db0b92739862805bee7227ce98046816831ecb23b1553d097d32eeb00b3513a3dde28da557996a732fe596746e0b6b0b8725c201bc7b7321c77a91792de9c4ecda33499810962fad24ab2ff37a4fb7a85d15b3f5e1da2a7ae38067eba20439947a57e17590413df08c333', 'hex');
CWT.parse(token, decKey).then(cwt => {
  console.log('done: ' + cwt.done);
  return cwt.continue(verifyKey);
}).then((cwt) => {
  console.log('done: ' + cwt.done);
  console.log(cwt.claims);
});
