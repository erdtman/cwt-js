'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const CWT = require('../lib/index.js');
const { vector, symmetricKey, privateKey, publicKey, fixedIv } = require('./helpers/vectors.js');

/**
 * RFC 8392 appendix A, in both directions: the bytes this library produces for
 * each published example, and the claims it reads back out of the published
 * bytes.
 *
 * These are the tests that say the library implements the format rather than
 * merely implementing itself. Every assertion is against a byte string from
 * the RFC, so they cannot be satisfied by changing the library.
 */

describe('appendix A.3, a signed CWT', () => {
  const example = vector('A_3');

  it('signs the claims to the published bytes', async () => {
    const cwt = await new CWT(example.claims).sign(privateKey(example.key), example.alg);

    const actual = cwt.raw.toString('hex');
    const expected = example.output;
    assert.ok(Buffer.isBuffer(cwt.raw));
    assert.equal(actual, expected);
  });

  it('verifies the published bytes back to the claims', async () => {
    const token = Buffer.from(example.output, 'hex');

    const cwt = await CWT.parse(token, publicKey(example.key));

    const actual = cwt.claims;
    const expected = example.claims;
    assert.deepEqual(actual, expected);
    assert.equal(cwt.done, true);
  });
});

describe('appendix A.4, a MACed CWT with the CWT tag', () => {
  const example = vector('A_4');

  it('MACs the claims to the published bytes', async () => {
    const cwt = await new CWT(example.claims)
      .mac(symmetricKey(example.key), example.alg, example.options);

    const actual = cwt.raw.toString('hex');
    const expected = example.output;
    assert.equal(actual, expected);
  });

  it('starts the published bytes with the CWT tag', () => {
    // d8 3d is CBOR tag 61, which is what options.addTag asks for.
    const actual = example.output.slice(0, 4);
    const expected = 'd83d';
    assert.equal(actual, expected);
    assert.equal(CWT.CwtTag, 61);
  });

  it('verifies the published bytes back to the claims', async () => {
    const token = Buffer.from(example.output, 'hex');

    const cwt = await CWT.parse(token, symmetricKey(example.key));

    const actual = cwt.claims;
    const expected = example.claims;
    assert.deepEqual(actual, expected);
  });
});

describe('appendix A.5, an encrypted CWT', () => {
  const example = vector('A_5');

  it('encrypts the claims to the published bytes', async () => {
    const cwt = await new CWT(example.claims)
      .encrypt(symmetricKey(example.key), example.alg, fixedIv(example.iv));

    const actual = cwt.raw.toString('hex');
    const expected = example.output;
    assert.equal(actual, expected);
  });

  it('decrypts the published bytes back to the claims', async () => {
    const token = Buffer.from(example.output, 'hex');

    const cwt = await CWT.parse(token, symmetricKey(example.key));

    const actual = cwt.claims;
    const expected = example.claims;
    assert.deepEqual(actual, expected);
  });
});

describe('appendix A.6, a nested CWT', () => {
  const example = vector('A_6');

  it('signs and then encrypts to the published bytes', async () => {
    const signed = await new CWT(example.sign.claims)
      .sign(privateKey(example.sign.key), example.sign.alg);

    assert.equal(signed.raw.toString('hex'), example.sign.output);

    // encrypt() encrypts the token already held rather than the claims, which
    // is what makes the result nested.
    const encrypted = await signed.encrypt(
      symmetricKey(example.encrypt.key),
      example.encrypt.alg,
      fixedIv(example.encrypt.iv)
    );

    const actual = encrypted.raw.toString('hex');
    const expected = example.encrypt.output;
    assert.equal(actual, expected);
  });

  it('unwraps one layer per key', async () => {
    const token = Buffer.from(example.encrypt.output, 'hex');

    const outer = await CWT.parse(token, symmetricKey(example.encrypt.key));
    // The inner layer is still wrapped, so there are no claims to read yet.
    assert.equal(outer.done, false);
    assert.ok(Buffer.isBuffer(outer.raw));

    const inner = await outer.continue(publicKey(example.sign.key));

    const actual = inner.claims;
    const expected = example.sign.claims;
    assert.equal(inner.done, true);
    assert.deepEqual(actual, expected);
  });
});

describe('appendix A.7, a MACed CWT with a floating point iat', () => {
  const example = vector('A_7');

  it('MACs the claims to the published bytes', async () => {
    const cwt = await new CWT(example.claims).mac(symmetricKey(example.key), example.alg);

    const actual = cwt.raw.toString('hex');
    const expected = example.output;
    assert.equal(actual, expected);
  });

  it('verifies the published bytes back to the claims, fraction intact', async () => {
    const token = Buffer.from(example.output, 'hex');

    const cwt = await CWT.parse(token, symmetricKey(example.key));

    const actual = cwt.claims;
    const expected = example.claims;
    assert.deepEqual(actual, expected);
    assert.equal(actual.iat, 1443944944.5);
  });
});
