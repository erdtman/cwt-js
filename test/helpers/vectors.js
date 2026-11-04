'use strict';

const { readFileSync } = require('node:fs');
const path = require('node:path');

/**
 * The appendix A examples from RFC 8392, as committed JSON.
 *
 * Read with node:fs rather than require(), so the vectors stay data instead of
 * becoming part of the module graph, and so the suite needs no JSON-reading
 * dependency.
 *
 * @param name an appendix section, e.g. 'A_3'
 * @returns the parsed vector
 */
function vector (name) {
  return JSON.parse(readFileSync(path.join(__dirname, '..', 'rfc', `${name}.json`), 'utf8'));
}

/** The vectors carry key material as hex; the library takes Buffers. */
const symmetricKey = key => ({ k: Buffer.from(key.k, 'hex'), kid: key.kid });
const privateKey = key => ({ d: Buffer.from(key.d, 'hex'), kid: key.kid });
const publicKey = key => ({
  x: Buffer.from(key.x, 'hex'),
  y: Buffer.from(key.y, 'hex'),
  kid: key.kid
});

/**
 * Encryption options that reproduce a vector's IV. A real caller leaves
 * randomSource unset and the COSE layer uses a secure random source; pinning
 * it is the only way to compare bytes against a published example.
 */
const fixedIv = iv => ({ randomSource: () => Buffer.from(iv, 'hex') });

module.exports = { vector, symmetricKey, privateKey, publicKey, fixedIv };
