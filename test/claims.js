'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const cbor = require('cbor');

const CWT = require('../lib/index.js');
const { vector, symmetricKey } = require('./helpers/vectors.js');

/**
 * The claims set itself: the translation between the names a caller writes and
 * the integer labels that go on the wire, which is the part of this library
 * that is not COSE.
 *
 * RFC 8392 section 4 assigns labels 1..7 to iss, sub, aud, exp, nbf, iat and
 * cti, and cti is a byte string where the API takes hex.
 */

const LABELS = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };

describe('get and set', () => {
  it('reads back what was passed to the constructor', () => {
    const cwt = new CWT({ aud: 'samuel', sub: 'charlotte' });

    assert.equal(cwt.get('aud'), 'samuel');
    assert.equal(cwt.get('sub'), 'charlotte');
  });

  it('accepts a registered claim by name or by label', () => {
    const cwt = new CWT({ iss: 'kalle' });

    assert.equal(cwt.get('iss'), 'kalle');
    assert.equal(cwt.get(LABELS.iss), 'kalle');

    cwt.set(LABELS.sub, 'anna');
    assert.equal(cwt.get('sub'), 'anna');
    assert.equal(cwt.get(LABELS.sub), 'anna');
  });

  it('carries an unregistered claim through under its own name', () => {
    const cwt = new CWT({});

    cwt.set('unknown', 'nisse');

    assert.equal(cwt.get('unknown'), 'nisse');
    assert.deepEqual(cwt.claims, { unknown: 'nisse' });
  });

  it('carries an unregistered label through as a number', () => {
    const cwt = new CWT({});

    cwt.set(15, 'anna');

    assert.equal(cwt.get(15), 'anna');
    assert.deepEqual(cwt.claims, { 15: 'anna' });
  });

  it('overwrites a claim set twice', () => {
    const cwt = new CWT({ iss: 'first' });

    cwt.set('iss', 'second');

    assert.equal(cwt.get('iss'), 'second');
  });
});

describe('cti', () => {
  it('is hex on the way in and a byte string on the wire', () => {
    const cwt = new CWT({ cti: '0b71' });

    const actual = cwt.get('cti');
    const expected = Buffer.from([0x0b, 0x71]);
    assert.deepEqual(actual, expected);
  });

  it('comes back as hex from claims', async () => {
    const example = vector('A_4');
    const token = Buffer.from(example.output, 'hex');

    const cwt = await CWT.parse(token, symmetricKey(example.key));

    const actual = cwt.claims.cti;
    const expected = '0b71';
    assert.equal(actual, expected);
  });

  it('is the only claim translated on the way in', () => {
    // Every other registered claim is written to the map as it was given.
    const claims = { iss: 'a', sub: 'b', aud: 'c', exp: 1, nbf: 2, iat: 3 };
    const cwt = new CWT(claims);

    for (const [name, value] of Object.entries(claims)) {
      assert.equal(cwt.get(name), value, name);
    }
  });
});

describe('the claims getter', () => {
  it('round-trips every registered claim through its label', () => {
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

    const actual = cwt.claims;
    const expected = claims;
    assert.deepEqual(actual, expected);
  });

  it('is derived from the payload, so it reflects a later set', () => {
    const cwt = new CWT({ iss: 'first' });

    cwt.set('sub', 'second');

    assert.deepEqual(cwt.claims, { iss: 'first', sub: 'second' });
  });
});

describe('what goes on the wire', () => {
  it('is a CBOR map keyed by label, not by name', async () => {
    const example = vector('A_7');

    const cwt = await new CWT(example.claims).mac(symmetricKey(example.key), example.alg);
    // COSE_Mac0 is tag 17 around [protected, unprotected, payload, tag].
    const mac0 = await cbor.decodeFirst(cwt.raw);
    assert.equal(mac0.tag, 17);
    const [, , payload] = mac0.value;

    const actual = await cbor.decodeFirst(payload);
    const expected = new Map([[LABELS.iat, 1443944944.5]]);
    assert.deepEqual(actual, expected);
  });
});

describe('raw and reset', () => {
  it('has no encoded form until one is produced', () => {
    const cwt = new CWT({ iss: 'a' });

    assert.equal(cwt.raw, undefined);
    assert.equal(cwt.done, true);
  });

  it('forgets the encoded form but keeps the claims', async () => {
    const example = vector('A_7');
    const cwt = await new CWT(example.claims).mac(symmetricKey(example.key), example.alg);
    assert.ok(Buffer.isBuffer(cwt.raw));

    cwt.reset();

    assert.equal(cwt.raw, undefined);
    assert.deepEqual(cwt.claims, example.claims);
  });

  it('can re-encode to the same bytes after a reset', async () => {
    const example = vector('A_7');
    const key = symmetricKey(example.key);
    const cwt = await new CWT(example.claims).mac(key, example.alg);

    cwt.reset();
    const again = await cwt.mac(key, example.alg);

    const actual = again.raw.toString('hex');
    const expected = example.output;
    assert.equal(actual, expected);
  });
});

describe('a token built from encoded bytes', () => {
  it('holds the bytes and has no claims yet', () => {
    const token = Buffer.from('d18443a10104', 'hex');

    const cwt = new CWT(token);

    assert.equal(cwt.done, false);
    assert.equal(cwt.raw, token);
    // There is nothing to translate until a key has unwrapped it, which is
    // what parse and continue are for.
    assert.throws(() => cwt.claims, TypeError);
  });
});
