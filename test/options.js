'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const cbor = require('cbor');

const CWT = require('../lib/index.js');
const { vector, symmetricKey, privateKey, publicKey, fixedIv } = require('./helpers/vectors.js');

/**
 * The options every producing method takes.
 *
 * addTag decides whether the result is a bare COSE structure or one wrapped in
 * the CWT CBOR tag. Both are valid CWTs and parse accepts either, so the only
 * thing that can go wrong is quiet: the tag being dropped, or added when it
 * was not asked for.
 */

const CWT_TAG_PREFIX = 'd83d'; // CBOR tag 61 in its one-byte-argument form.

describe('addTag', () => {
  const sign = vector('A_3');
  const mac = vector('A_4');
  const encrypt = vector('A_5');

  it('wraps a signed token, which still verifies', async () => {
    const cwt = await new CWT(sign.claims)
      .sign(privateKey(sign.key), sign.alg, { addTag: true });

    const actual = cwt.raw.toString('hex');
    const expected = `${CWT_TAG_PREFIX}${sign.output}`;
    assert.equal(actual, expected);

    const parsed = await CWT.parse(cwt.raw, publicKey(sign.key));
    assert.deepEqual(parsed.claims, sign.claims);
  });

  it('wraps a MACed token, which still verifies', async () => {
    const cwt = await new CWT(mac.claims)
      .mac(symmetricKey(mac.key), mac.alg, { addTag: true });

    const parsed = await CWT.parse(cwt.raw, symmetricKey(mac.key));

    assert.equal(cwt.raw.toString('hex').slice(0, 4), CWT_TAG_PREFIX);
    assert.deepEqual(parsed.claims, mac.claims);
  });

  it('wraps an encrypted token, which still decrypts', async () => {
    const cwt = await new CWT(encrypt.claims).encrypt(
      symmetricKey(encrypt.key),
      encrypt.alg,
      { ...fixedIv(encrypt.iv), addTag: true }
    );

    const actual = cwt.raw.toString('hex');
    const expected = `${CWT_TAG_PREFIX}${encrypt.output}`;
    assert.equal(actual, expected);

    const parsed = await CWT.parse(cwt.raw, symmetricKey(encrypt.key));
    assert.deepEqual(parsed.claims, encrypt.claims);
  });

  it('adds the tag around the COSE structure, not inside it', async () => {
    const cwt = await new CWT(mac.claims)
      .mac(symmetricKey(mac.key), mac.alg, { addTag: true });

    const outer = await cbor.decodeFirst(cwt.raw);

    assert.equal(outer.tag, CWT.CwtTag);
    // COSE_Mac0 is tag 17, and it is what the CWT tag contains.
    assert.equal(outer.value.tag, 17);
  });

  it('is off by default, for every method', async () => {
    const tokens = await Promise.all([
      new CWT(sign.claims).sign(privateKey(sign.key), sign.alg),
      new CWT(mac.claims).mac(symmetricKey(mac.key), mac.alg),
      new CWT(encrypt.claims).encrypt(symmetricKey(encrypt.key), encrypt.alg, fixedIv(encrypt.iv))
    ]);

    for (const cwt of tokens) {
      assert.notEqual(cwt.raw.toString('hex').slice(0, 4), CWT_TAG_PREFIX);
    }
  });

  it('is off when options are omitted entirely', async () => {
    // Every method has to tolerate being called without an options argument.
    const cwt = await new CWT(mac.claims).mac(symmetricKey(mac.key), mac.alg);

    const actual = cwt.raw.toString('hex').slice(0, 2);
    const expected = 'd1'; // COSE_Mac0, tag 17, with nothing around it.
    assert.equal(actual, expected);
  });
});

describe('randomSource', () => {
  const example = vector('A_5');

  it('pins the IV, which is what makes a vector reproducible', async () => {
    const first = await new CWT(example.claims)
      .encrypt(symmetricKey(example.key), example.alg, fixedIv(example.iv));
    const second = await new CWT(example.claims)
      .encrypt(symmetricKey(example.key), example.alg, fixedIv(example.iv));

    assert.equal(first.raw.toString('hex'), second.raw.toString('hex'));
  });

  it('is not used when it is not given, so two tokens differ', async () => {
    const first = await new CWT(example.claims)
      .encrypt(symmetricKey(example.key), example.alg);
    const second = await new CWT(example.claims)
      .encrypt(symmetricKey(example.key), example.alg);

    assert.notEqual(first.raw.toString('hex'), second.raw.toString('hex'));
  });
});
