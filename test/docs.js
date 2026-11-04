'use strict';

const { execFileSync } = require('node:child_process');
const { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

/**
 * The README and examples/ are the parts of this package most likely to drift,
 * because nothing executes them. These tests do execute them: every snippet is
 * run in a child process, with `require("cwt-js")` pointed at this working
 * tree, and has to exit 0.
 *
 * That is a stronger check than it looks. The snippets end in a bare `.then()`
 * with no catch, so a token that no longer verifies, a key of the wrong shape
 * or a renamed method becomes an unhandled rejection and a non-zero exit.
 *
 * They deliberately assert that the expected shapes are still found: if the
 * documentation is restructured, these fail and have to be pointed at the new
 * shape rather than silently checking nothing.
 */

const ROOT = path.join(__dirname, '..');
const LIB = path.join(ROOT, 'lib', 'index.js');
const README = readFileSync(path.join(ROOT, 'README.md'), 'utf8');

/**
 * The environment every snippet runs in.
 *
 * Colour is pinned off because npm exports FORCE_COLOR to a lifecycle script
 * when it is attached to a terminal. With it set, console.log(claims) in these
 * children wraps every value in ANSI codes, so `iss: 'coap://...'` arrives as
 * `iss: \u001b[32m'coap://...'\u001b[39m` and nothing below matches. Pinning
 * it means `npm test` in a terminal and `npm test` in CI assert on the same
 * text.
 */
const CHILD_ENV = { ...process.env, FORCE_COLOR: '0', NO_COLOR: '1' };

/** The claims every snippet in the documentation uses, from RFC 8392. */
const DOCUMENTED_CLAIMS = [
  "iss: 'coap://as.example.com'",
  "sub: 'erikw'",
  "aud: 'coap://light.example.com'",
  'exp: 1444064944',
  'nbf: 1443944944',
  'iat: 1443944944',
  "cti: '0b71'"
];

let workspace;

before(() => {
  workspace = mkdtempSync(path.join(os.tmpdir(), 'cwt-docs-'));
});

after(() => rmSync(workspace, { recursive: true, force: true }));

/**
 * The fenced JavaScript blocks in the README, each with the heading above it.
 *
 * @returns one entry per block, in document order
 */
function readmeSnippets () {
  const snippets = [];
  let heading = '(none)';
  let open = null;

  for (const line of README.split('\n')) {
    if (open === null && line.startsWith('#')) {
      heading = line.replace(/^#+\s*/, '').trim();
    } else if (open === null && line.trim() === '```js') {
      open = { heading, lines: [] };
    } else if (open !== null && line.trim() === '```') {
      snippets.push({ heading: open.heading, source: `${open.lines.join('\n')}\n` });
      open = null;
    } else if (open !== null) {
      open.lines.push(line);
    }
  }

  assert.equal(open, null, 'an unterminated ```js fence in README.md');

  return snippets;
}

/**
 * Run a snippet against this working tree.
 *
 * @param source the snippet, requiring the package by name
 * @param name a filename stem for the temporary copy
 * @returns everything it wrote to stdout
 */
function run (source, name) {
  const file = path.join(workspace, `${name}.js`);
  writeFileSync(file, source.replaceAll('require("cwt-js")', `require(${JSON.stringify(LIB)})`));
  return execFileSync(process.execPath, [file], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: CHILD_ENV
  });
}

describe('the README snippets', () => {
  const snippets = readmeSnippets();

  it('are all there', () => {
    // Eight operations are documented: MAC, verify, sign, verify, encrypt,
    // decrypt, nest, unwrap. Fewer than that means the regex stopped matching.
    assert.ok(snippets.length >= 8, `found ${snippets.length} snippets, expected at least 8`);
  });

  it('all require the package by its published name', () => {
    for (const { heading, source } of snippets) {
      assert.match(source, /require\("cwt-js"\)/, heading);
      // A snippet that reaches into lib/ or up a directory is one that was
      // copied out of examples/ and not adjusted.
      assert.doesNotMatch(source, /require\(['"]\.\.?\//, heading);
    }
  });

  for (const [index, { heading, source }] of snippets.entries()) {
    it(`run: ${heading}`, () => {
      const output = run(source, `readme-${index}`);

      assert.notEqual(output.trim(), '', 'snippet printed nothing');

      if (source.includes('.claims')) {
        // A snippet that reads claims has to come back with the documented
        // ones, not merely come back.
        for (const claim of DOCUMENTED_CLAIMS) {
          assert.ok(output.includes(claim), `${heading} did not print ${claim}, it printed:\n${output}`);
        }
      }
    });
  }

  it('document the tokens their own deterministic snippets produce', () => {
    // MAC and ECDSA-with-RFC-6979 are deterministic, so the token a snippet
    // prints is a fixed string and must be the one the matching verify
    // snippet is documented with. Encryption picks a random IV, so its output
    // is checked by the verify snippets actually verifying instead.
    const deterministic = snippets.filter(({ source }) => (
      !source.includes('.encrypt(') && source.includes('.raw.toString("hex")')
    ));

    assert.ok(deterministic.length >= 2, `found ${deterministic.length} deterministic snippets`);

    for (const [index, { heading, source }] of deterministic.entries()) {
      const printed = run(source, `deterministic-${index}`).trim();

      assert.match(printed, /^[0-9a-f]+$/, heading);
      assert.ok(
        README.includes(printed),
        `${heading} prints a token the README does not document:\n${printed}`
      );
    }
  });
});

describe('the examples', () => {
  const files = readdirSync(path.join(ROOT, 'examples')).filter(name => name.endsWith('.js')).sort();

  it('cover every operation', () => {
    const actual = files;
    const expected = ['encrypt.js', 'mac.js', 'nested.js', 'sign.js'];
    assert.deepEqual(actual, expected);
  });

  for (const name of files) {
    it(`run: examples/${name}`, () => {
      // Run in place: the examples require the package root, which is the
      // thing being tested about them.
      const output = execFileSync(process.execPath, [path.join('examples', name)], {
        cwd: ROOT,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: CHILD_ENV
      });

      assert.notEqual(output.trim(), '', 'example printed nothing');
      for (const claim of DOCUMENTED_CLAIMS) {
        assert.ok(
          output.includes(claim),
          `examples/${name} did not print ${claim}, it printed:\n${output}`
        );
      }
    });
  }
});

describe('the README prose', () => {
  it('installs the package under its published name', () => {
    assert.match(README, /npm install cwt-js/);
  });

  it('states the Node.js version the package supports', () => {
    const { engines } = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    const floor = engines.node.replace(/[^\d.]/g, '');

    assert.ok(README.includes(floor), `README does not mention Node.js ${floor}`);
  });

  it('links the RFC the library implements', () => {
    // The old link was to the expired ACE working group draft.
    assert.match(README, /rfc8392/i);
    assert.doesNotMatch(README, /draft-ietf-ace-cbor-web-token/);
  });

  it('does not advertise a coverage service the repository no longer uses', () => {
    assert.doesNotMatch(README, /coveralls/i);
  });
});
