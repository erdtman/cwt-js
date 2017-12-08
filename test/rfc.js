/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const test = require('ava');
const CWT = require('../');
const jsonfile = require('jsonfile');

// test('create A_3', t => {});
test('create A_3', t => {
  const example = jsonfile.readFileSync('test/rfc/A_3.json');
  const key = {
    'd': Buffer.from(example.key.d, 'hex')
  };
  const alg = example.alg;
  const claims = example.claims;
  const kid = example.key.kid;

  const cwt = CWT.create(claims);
  return cwt.sign(key, alg, kid).then(output => {
    t.true(Buffer.isBuffer(output));
    t.true(output.length > 0);
    t.is(output.toString('hex'), example.output);
  });
});

test('create A_4', t => {
  const example = jsonfile.readFileSync('test/rfc/A_4.json');
  const key = Buffer.from(example.key, 'hex');
  const alg = example.alg;
  const claims = example.claims;
  const kid = example.kid;
  const options = example.options;

  const cwt = CWT.create(claims);
  return cwt.mac(key, alg, kid, options).then(output => {
    t.true(Buffer.isBuffer(output));
    t.true(output.length > 0);
    t.is(output.toString('hex'), example.output);
  });
});

test('create A_5', t => {
  const example = jsonfile.readFileSync('test/rfc/A_5.json');
  const key = Buffer.from(example.key, 'hex');
  const alg = example.alg;
  const claims = example.claims;
  const kid = example.kid;
  const options = {
    'randomSource': (bytes) => {
      return Buffer.from(example.iv, 'hex');
    }
  };

  const cwt = CWT.create(claims);
  return cwt.encrypt(key, alg, kid, options).then(output => {
    t.true(Buffer.isBuffer(output));
    t.true(output.length > 0);
    t.is(output.toString('hex'), example.output);
  });
});

// test('create A_6', t => {});

test('create A_7', t => {
  const example = jsonfile.readFileSync('test/rfc/A_7.json');
  const key = Buffer.from(example.key, 'hex');
  const alg = example.alg;
  const claims = example.claims;
  const kid = example.kid;

  const cwt = CWT.create(claims);
  return cwt.mac(key, alg, kid).then(output => {
    t.true(Buffer.isBuffer(output));
    t.true(output.length > 0);
    t.is(output.toString('hex'), example.output);
  });
});

test('verify A_3', t => {
  const example = jsonfile.readFileSync('test/rfc/A_3.json');
  const key = {
    'x': Buffer.from(example.key.x, 'hex'),
    'y': Buffer.from(example.key.y, 'hex')
  };
  const expectedClaims = example.claims;
  const cwt = Buffer.from(example.output, 'hex');
  return CWT.read(cwt, key).then(claims => {
    t.deepEqual(claims, expectedClaims);
  });
});

test('verify A_4', t => {
  const example = jsonfile.readFileSync('test/rfc/A_4.json');
  const key = Buffer.from(example.key, 'hex');
  const expectedClaims = example.claims;
  const cwt = Buffer.from(example.output, 'hex');
  return CWT.read(cwt, key).then(claims => {
    t.deepEqual(claims, expectedClaims);
  });
});

test('verify A_5', t => {
  const example = jsonfile.readFileSync('test/rfc/A_5.json');
  const key = Buffer.from(example.key, 'hex');
  const expectedClaims = example.claims;
  const cwt = Buffer.from(example.output, 'hex');
  return CWT.read(cwt, key).then(claims => {
    t.deepEqual(claims, expectedClaims);
  });
});

// test('verify A_6', t => {});

test('verify A_7', t => {
  const example = jsonfile.readFileSync('test/rfc/A_7.json');
  const key = Buffer.from(example.key, 'hex');
  const expectedClaims = example.claims;
  const cwt = Buffer.from(example.output, 'hex');
  return CWT.read(cwt, key).then(claims => {
    t.deepEqual(claims, expectedClaims);
  });
});
