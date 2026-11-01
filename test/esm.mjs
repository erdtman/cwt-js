// The `import` surface, which the CommonJS tests cannot reach.
//
// This package is CommonJS, so what `import` gives an ESM consumer depends on
// Node's interop and on the `exports` map in package.json rather than on
// anything in lib/. Worth one test of its own.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import CWT from '../lib/index.js';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

describe('import', () => {
  it('gives the same class as require', () => {
    const actual = CWT;
    const expected = require('../lib/index.js');
    assert.equal(actual, expected);
  });

  it('gives a working class, statics included', async () => {
    assert.equal(CWT.CwtTag, 61);

    const key = {
      k: Buffer.from('403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388', 'hex'),
      kid: 'Symmetric256'
    };
    const cwt = await new CWT({ iat: 1443944944.5 }).mac(key, 'HS256/64');

    const actual = cwt.raw.toString('hex');
    const expected = 'd18443a10104a1044c53796d6d65747269633235364ba106fb41d584367c20000048b8816f34c0542892';
    assert.equal(actual, expected);

    const parsed = await CWT.parse(cwt.raw, key);
    assert.deepEqual(parsed.claims, { iat: 1443944944.5 });
  });
});
