'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const cbor = require('cbor');
const cose = require('cose-js');

const CWT = require('../lib/index.js');
const { vector, symmetricKey, privateKey, publicKey } = require('./helpers/vectors.js');

/**
 * What parse does with a token it cannot accept.
 *
 * A token is an authentication decision, so the interesting cases are the
 * negative ones: a wrong key, a tampered token and a malformed one all have to
 * reject, and reject rather than resolve with claims nobody verified.
 *
 * Every rejection here used to leave the returned promise pending for ever,
 * because parse piped the token into a streaming decoder and only listened for
 * 'data'. An await on it never came back.
 */

/** Flip the last byte, which lands in the signature, tag or ciphertext. */
function tamper (hex) {
  const bytes = Buffer.from(hex, 'hex');
  bytes[bytes.length - 1] ^= 0x01;
  return bytes;
}

describe('a malformed token', () => {
  it('rejects rather than hanging', async () => {
    // 0xff is a break outside an indefinite-length item: not decodable.
    await assert.rejects(() => CWT.parse(Buffer.from('ff', 'hex'), { k: Buffer.alloc(16) }));
  });

  it('rejects when the token is truncated mid-item', async () => {
    const example = vector('A_4');
    const truncated = Buffer.from(example.output, 'hex').subarray(0, 12);

    await assert.rejects(() => CWT.parse(truncated, symmetricKey(example.key)));
  });

  it('rejects an empty token', async () => {
    // An empty input is the one case CBOR does not call an error: it decodes
    // to nothing. parse has to turn that into a rejection itself, or it
    // resolves with a token holding no claims that nothing authenticated.
    await assert.rejects(() => CWT.parse(Buffer.alloc(0), { k: Buffer.alloc(16) }), {
      message: 'Empty token'
    });
  });
});

describe('a MACed token', () => {
  const example = vector('A_4');

  it('rejects under the wrong key', async () => {
    const wrong = { k: Buffer.alloc(32), kid: example.key.kid };

    await assert.rejects(() => CWT.parse(Buffer.from(example.output, 'hex'), wrong));
  });

  it('rejects when the tag has been tampered with', async () => {
    await assert.rejects(() => CWT.parse(tamper(example.output), symmetricKey(example.key)));
  });
});

describe('a signed token', () => {
  const example = vector('A_3');

  it('rejects under the wrong public key', async () => {
    const other = vector('A_6').sign.key;
    const wrong = {
      x: Buffer.from(other.y, 'hex'), // x and y swapped: a point off the curve
      y: Buffer.from(other.x, 'hex'),
      kid: other.kid
    };

    await assert.rejects(() => CWT.parse(Buffer.from(example.output, 'hex'), wrong));
  });

  it('rejects when the signature has been tampered with', async () => {
    await assert.rejects(() => CWT.parse(tamper(example.output), publicKey(example.key)));
  });
});

describe('an encrypted token', () => {
  const example = vector('A_5');

  it('rejects under the wrong key', async () => {
    const wrong = { k: Buffer.alloc(16), kid: example.key.kid };

    await assert.rejects(() => CWT.parse(Buffer.from(example.output, 'hex'), wrong));
  });

  it('rejects when the ciphertext has been tampered with', async () => {
    await assert.rejects(() => CWT.parse(tamper(example.output), symmetricKey(example.key)));
  });
});

describe('a nested token', () => {
  const encKey = symmetricKey(vector('A_5').key);
  const macKey = symmetricKey(vector('A_4').key);
  const signed = vector('A_6').sign;

  /**
   * Wrap bytes in a COSE structure directly, the way a nested CWT is built.
   *
   * The library's own mac() and sign() always encode the claims, so only
   * encrypt() can produce a nested token through the public API. Reaching for
   * cose-js here is what lets the MACed and signed outer layers be tested at
   * all, and a token from somewhere else can have any of the three.
   */
  const wrap = {
    encrypted: inner => cose.encrypt.create(
      { p: { alg: 'AES-CCM-16-64-128' }, u: { kid: 'Symmetric128' } },
      inner,
      { key: encKey.k }
    ),
    maced: inner => cose.mac.create(
      { p: { alg: 'HS256' }, u: { kid: 'Symmetric256' } },
      inner,
      { key: macKey.k }
    ),
    signed: inner => cose.sign.create(
      { p: { alg: 'ES256' }, u: { kid: signed.key.kid } },
      inner,
      { key: privateKey(signed.key) }
    )
  };

  const outerKey = { encrypted: encKey, maced: macKey, signed: publicKey(signed.key) };

  for (const layer of Object.keys(wrap)) {
    it(`hands on the inner token when the outer layer is ${layer}`, async () => {
      const inner = Buffer.from(signed.output, 'hex');
      const token = await wrap[layer](inner);

      const outer = await CWT.parse(token, outerKey[layer]);

      // The inner token is handed on untouched. It used to come back as
      // undefined for a signed outer layer, which left nothing to continue
      // with.
      assert.equal(outer.done, false);
      assert.deepEqual(outer.raw, inner);

      const claims = await outer.continue(publicKey(signed.key));
      assert.deepEqual(claims.claims, signed.claims);
    });
  }

  for (const layer of Object.keys(wrap)) {
    it(`refuses to unwrap a tag it does not know, under a ${layer} outer layer`, async () => {
      const token = await wrap[layer](cbor.encode(new cbor.Tagged(999, [1, 2, 3])));

      await assert.rejects(() => CWT.parse(token, outerKey[layer]), {
        message: 'Unknown tag, 999'
      });
    });
  }

  it('is transparent about the CWT tag itself', async () => {
    const inner = cbor.encode(new cbor.Tagged(
      CWT.CwtTag,
      await cbor.decodeFirst(Buffer.from(signed.output, 'hex'))
    ));

    const outer = await CWT.parse(await wrap.encrypted(inner), encKey);
    const claims = await outer.continue(publicKey(signed.key));

    const actual = claims.claims;
    const expected = signed.claims;
    assert.deepEqual(actual, expected);
  });
});
