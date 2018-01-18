/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const test = require('ava');
const CWT = require('../');
const jsonfile = require('jsonfile');

test('create A_3', t => {
  const example = jsonfile.readFileSync('test/rfc/A_3.json');
  const key = {
    'd': Buffer.from(example.key.d, 'hex'),
    'kid': example.key.kid
  };
  const alg = example.alg;
  const claims = example.claims;

  const cwt = new CWT(claims);
  return cwt.sign(key, alg).then(output => {
    const data = output.raw;
    t.true(Buffer.isBuffer(data));
    t.true(data.length > 0);
    t.is(data.toString('hex'), example.output);
  });
});

test('create A_4', t => {
  const example = jsonfile.readFileSync('test/rfc/A_4.json');
  const key = {
    'k': Buffer.from(example.key.k, 'hex'),
    'kid': example.key.kid
  };
  const alg = example.alg;
  const claims = example.claims;
  const options = example.options;

  const cwt = new CWT(claims);
  return cwt.mac(key, alg, options).then(output => {
    t.true(Buffer.isBuffer(output));
    t.true(output.length > 0);
    t.is(output.toString('hex'), example.output);
  });
});

test('create A_5', t => {
  const example = jsonfile.readFileSync('test/rfc/A_5.json');
  const key = {
    'k': Buffer.from(example.key.k, 'hex'),
    'kid': example.key.kid
  };
  const alg = example.alg;
  const claims = example.claims;
  const options = {
    'randomSource': (bytes) => {
      return Buffer.from(example.iv, 'hex');
    }
  };

  const cwt = new CWT(claims);
  return cwt.encrypt(key, alg, options).then(output => {
    const data = output.raw;
    t.true(Buffer.isBuffer(data));
    t.true(data.length > 0);
    t.is(data.toString('hex'), example.output);
  });
});

test('create A_6', t => {
  const example = jsonfile.readFileSync('test/rfc/A_6.json');
  const encKey = {
    'k': Buffer.from(example.encrypt.key.k, 'hex'),
    'kid': example.encrypt.key.kid
  };
  const encAlg = example.encrypt.alg;
  const encOptions = {
    'randomSource': (bytes) => {
      return Buffer.from(example.encrypt.iv, 'hex');
    }
  };

  const signKey = {
    'd': Buffer.from(example.sign.key.d, 'hex'),
    'kid': example.sign.key.kid
  };
  const signAlg = example.sign.alg;
  const claims = example.sign.claims;

  const cwt = new CWT(claims);
  return cwt.sign(signKey, signAlg).then(signedCWT => {
    t.true(Buffer.isBuffer(signedCWT.raw));
    t.true(signedCWT.raw.length > 0);
    t.is(signedCWT.raw.toString('hex'), example.sign.output);
    return signedCWT.encrypt(encKey, encAlg, encOptions);
  }).then(encryptedCWT => {
    t.true(Buffer.isBuffer(encryptedCWT.raw));
    t.true(encryptedCWT.raw.length > 0);
    t.is(encryptedCWT.raw.toString('hex'), example.encrypt.output);
  });
});

test('create A_7', t => {
  const example = jsonfile.readFileSync('test/rfc/A_7.json');
  const key = {
    'k': Buffer.from(example.key.k, 'hex'),
    'kid': example.key.kid
  };
  const alg = example.alg;
  const claims = example.claims;

  const cwt = new CWT(claims);
  return cwt.mac(key, alg).then(output => {
    t.true(Buffer.isBuffer(output));
    t.true(output.length > 0);
    t.is(output.toString('hex'), example.output);
  });
});

test('verify A_3', t => {
  const example = jsonfile.readFileSync('test/rfc/A_3.json');
  const key = {
    'x': Buffer.from(example.key.x, 'hex'),
    'y': Buffer.from(example.key.y, 'hex'),
    'kid': example.key.kid
  };
  const expectedClaims = example.claims;
  const cwt = Buffer.from(example.output, 'hex');
  return CWT.parse(cwt, key).then(cwt => {
    t.deepEqual(cwt.claims, expectedClaims);
  });
});

test('verify A_4', t => {
  const example = jsonfile.readFileSync('test/rfc/A_4.json');
  const key = {
    'k': Buffer.from(example.key.k, 'hex'),
    'kid': example.key.kid
  };
  const expectedClaims = example.claims;
  const cwt = Buffer.from(example.output, 'hex');
  return CWT.parse(cwt, key).then(cwt => {
    t.deepEqual(cwt.claims, expectedClaims);
  });
});

test('verify A_5', t => {
  const example = jsonfile.readFileSync('test/rfc/A_5.json');
  const key = {
    'k': Buffer.from(example.key.k, 'hex'),
    'kid': example.key.kid
  };
  const expectedClaims = example.claims;
  const cwt = Buffer.from(example.output, 'hex');
  return CWT.parse(cwt, key).then(cwt => {
    t.deepEqual(cwt.claims, expectedClaims);
  });
});

test('verify A_6', t => {
  const example = jsonfile.readFileSync('test/rfc/A_6.json');
  const encKey = {
    'k': Buffer.from(example.encrypt.key.k, 'hex'),
    'kid': example.encrypt.key.kid
  };

  const signKey = {
    'x': Buffer.from(example.sign.key.x, 'hex'),
    'y': Buffer.from(example.sign.key.y, 'hex'),
    'kid': example.sign.key.kid
  };

  const expectedClaims = example.sign.claims;

  const cwt = Buffer.from(example.encrypt.output, 'hex');
  return CWT.parse(cwt, encKey).then(cwt => {
    t.false(cwt.done);
    return cwt.continue(signKey);
  }).then((cwt) => {
    t.true(cwt.done);
    t.deepEqual(cwt.claims, expectedClaims);
  });
});

test('verify A_7', t => {
  const example = jsonfile.readFileSync('test/rfc/A_7.json');
  const key = {
    'k': Buffer.from(example.key.k, 'hex'),
    'kid': example.key.kid
  };
  const expectedClaims = example.claims;
  const cwt = Buffer.from(example.output, 'hex');
  return CWT.parse(cwt, key).then(cwt => {
    t.deepEqual(cwt.claims, expectedClaims);
  });
});
