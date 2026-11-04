'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const cbor = require('cbor');

/**
 * A guard on the one dependency failure that would not look like a failure.
 *
 * cbor assembles its output through `nofilter`, whose synchronous `read()`
 * returns only the first buffered chunk on Node.js 26 instead of all of them.
 * The encoder then yields a container header with no contents:
 * `cbor.encode(new Map([[1, -7]]))` is `a1` rather than `a10126`. This library
 * would hand back tokens that are truncated CBOR, quietly, rather than
 * throwing. Both cbor 8 and cbor 10 are affected, so no version this package
 * can declare avoids it, and nor can cose-js.
 *
 * Node.js 22 and 24 are unaffected and are what CI runs. This test is here so
 * that a runtime where the encoder is broken says so in one line, instead of
 * as three dozen mismatched byte strings.
 */

describe('the CBOR encoder in this runtime', () => {
  it('encodes a map completely', () => {
    const actual = cbor.encode(new Map([[1, -7], [4, 'kid']])).toString('hex');
    const expected = 'a2012604636b6964';

    assert.equal(actual, expected, [
      `cbor ${require('cbor/package.json').version} truncates its output on`,
      `${process.version}: every token this library produces would be`,
      'invalid CBOR. See the runtime note in CONTRIBUTING.md.'
    ].join(' '));
  });

  it('encodes an array completely', () => {
    const actual = cbor.encode([1, 2, 3]).toString('hex');
    const expected = '83010203';
    assert.equal(actual, expected);
  });
});
