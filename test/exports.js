'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const CWT = require('../lib/index.js');

/**
 * The module surface. A package's exports are its contract, and the ways they
 * break are not the ways its logic breaks: a renamed method, a static that
 * stopped being reachable, a new export nobody meant to make public.
 *
 * CwtTag is here because it spent its life unreachable. It was assigned to
 * `exports`, and then `module.exports` was reassigned to the class, which
 * threw the assignment away.
 */

/** Every instance method and accessor this package documents. */
const METHODS = ['get', 'set', 'reset', 'mac', 'sign', 'encrypt', 'continue'];
const ACCESSORS = ['claims', 'raw'];

describe('the module', () => {
  it('exports the CWT class itself', () => {
    assert.equal(typeof CWT, 'function');
    assert.equal(CWT.name, 'CWT');
    assert.ok(new CWT({}) instanceof CWT);
  });

  it('exposes parse as a static', () => {
    assert.equal(typeof CWT.parse, 'function');
  });

  it('exposes the CWT CBOR tag as a reachable static', () => {
    const actual = CWT.CwtTag;
    const expected = 61;
    assert.equal(actual, expected);
  });

  it('resolves by its own name from inside the package', () => {
    // The `exports` map in package.json turns on Node's self-reference. If the
    // map and `main` ever disagree, this is where it shows.
    const actual = require('cwt-js');
    const expected = CWT;
    assert.equal(actual, expected);
  });

  it('exposes nothing else', () => {
    const actual = Object.getOwnPropertyNames(CWT)
      .filter(name => !['length', 'name', 'prototype'].includes(name))
      .sort();
    const expected = ['CwtTag', 'parse'];
    assert.deepEqual(actual, expected);
  });
});

describe('the prototype', () => {
  it('has every documented method', () => {
    for (const name of METHODS) {
      assert.equal(typeof CWT.prototype[name], 'function', name);
    }
  });

  it('has every documented accessor, as a getter only', () => {
    for (const name of ACCESSORS) {
      const descriptor = Object.getOwnPropertyDescriptor(CWT.prototype, name);
      assert.ok(descriptor, name);
      assert.equal(typeof descriptor.get, 'function', name);
      assert.equal(descriptor.set, undefined, name);
    }
  });

  it('has nothing else on it', () => {
    const actual = Object.getOwnPropertyNames(CWT.prototype)
      .filter(name => name !== 'constructor')
      .sort();
    const expected = [...METHODS, ...ACCESSORS].sort();
    assert.deepEqual(actual, expected);
  });
});

describe('an instance', () => {
  it('carries done as an own property', () => {
    // It is a property rather than a method. There used to be a done() method
    // as well, which every instance shadowed with this property, so it could
    // never be called.
    const cwt = new CWT({});

    assert.equal(typeof cwt.done, 'boolean');
    assert.ok(Object.hasOwn(cwt, 'done'));
  });
});
