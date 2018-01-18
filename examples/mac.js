/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const CWT = require('../');

// Create
const encKey = {
  'k': Buffer.from('403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388', 'hex'),
  'kid': 'Symmetric256'
};
const alg = 'HS256/64';
const claims = {
  'iss': 'coap://as.example.com',
  'sub': 'erikw',
  'aud': 'coap://light.example.com',
  'exp': 1444064944,
  'nbf': 1443944944,
  'iat': 1443944944,
  'cti': '0b71'
};

const cwt = new CWT(claims);
cwt.mac(encKey, alg).then(cwt => {
  console.log(cwt.raw.toString('hex'));
});

// Verify
const decKey = {
  'k': Buffer.from('403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388', 'hex'),
  'kid': 'Symmetric256'
};
const token = Buffer.from('d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200', 'hex');

CWT.parse(token, decKey).then(cwt => {
  console.log(cwt.claims);
});
