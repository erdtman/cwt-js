'use strict';

const { execFileSync } = require('node:child_process');
const {
  mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync,
  symlinkSync, writeFileSync
} = require('node:fs');
const { createRequire } = require('node:module');
const os = require('node:os');
const path = require('node:path');
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const CWT = require('../lib/index.js');

/**
 * What a consumer gets is the published tarball, not the working tree. These
 * tests pack the package, install it the way npm would, and exercise it from
 * the outside: the shape most likely to break silently is `files` plus `main`
 * plus `types` plus `exports` disagreeing with each other.
 *
 * Nothing here touches the network. The two runtime dependencies are symlinked
 * in from this repository's own node_modules rather than installed.
 */

const ROOT = path.join(__dirname, '..');
const EXPECTED_FILES = ['LICENSE', 'README.md', 'lib/index.d.ts', 'lib/index.js', 'package.json'];
const RUNTIME_DEPENDENCIES = ['cbor', 'cose-js'];

let workspace;
let installed;
let manifest;
/**
 * A require rooted in the workspace rather than in this file. It has to be:
 * package.json now has an `exports` map, which turns on Node's self-reference,
 * so a plain require('cwt-js') from inside this repository resolves to the
 * working tree no matter what `paths` says.
 */
let consumer;

before(() => {
  // realpath: on macOS the temp dir is a symlink, and require.resolve reports
  // the resolved path.
  workspace = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'cwt-package-')));

  execFileSync('npm', ['pack', '--pack-destination', workspace], { cwd: ROOT, stdio: 'pipe' });
  const tarball = readdirSync(workspace).find(name => name.endsWith('.tgz'));
  assert.ok(tarball, 'npm pack produced no tarball');

  execFileSync('tar', ['-xf', path.join(workspace, tarball), '-C', workspace], { stdio: 'pipe' });

  // Lay it out as node_modules/<name> so module resolution is the real thing.
  installed = path.join(workspace, 'node_modules', 'cwt-js');
  mkdirSync(path.dirname(installed), { recursive: true });
  renameSync(path.join(workspace, 'package'), installed);

  // The dependencies resolve through their realpath, so symlinking them is
  // enough for them to find their own dependencies in this repository.
  for (const name of RUNTIME_DEPENDENCIES) {
    symlinkSync(path.join(ROOT, 'node_modules', name), path.join(workspace, 'node_modules', name));
  }

  manifest = JSON.parse(readFileSync(path.join(installed, 'package.json'), 'utf8'));
  consumer = createRequire(path.join(workspace, 'consumer.js'));
});

after(() => rmSync(workspace, { recursive: true, force: true }));

/**
 * @param dir a directory in the extracted package
 * @returns every file under it, as slash-separated relative paths
 */
function filesUnder (dir, prefix = '') {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => (
    entry.isDirectory()
      ? filesUnder(path.join(dir, entry.name), `${prefix}${entry.name}/`)
      : [prefix + entry.name]
  ));
}

describe('the published tarball', () => {
  it('contains exactly the files it should', () => {
    const actual = filesUnder(installed).sort();
    const expected = EXPECTED_FILES;
    assert.deepEqual(actual, expected);
  });

  it('ships no tests, examples or tooling config', () => {
    for (const name of filesUnder(installed)) {
      assert.doesNotMatch(name, /^(test|examples|coverage|\.github)\//, name);
      assert.doesNotMatch(name, /^(tsconfig\.json|eslint\.config\.js|\.npmrc|package-lock\.json)$/, name);
      assert.doesNotMatch(name, /^(CONTRIBUTING|RELEASING|CLAUDE)\.md$/, name);
    }
  });

  it('points main, types and exports at files that are actually in it', () => {
    const published = filesUnder(installed);

    for (const target of [manifest.main, manifest.types, ...Object.values(manifest.exports['.'])]) {
      assert.ok(target, 'package.json is missing an entry point');
      assert.ok(
        published.includes(target.replace(/^\.\//, '')),
        `${target} is referenced but not published`
      );
    }
  });

  it('declares only the two dependencies it needs', () => {
    // cbor is held at ^8 deliberately: cose-js depends on ^8.1.0, and the
    // Tagged instances this library compares with `instanceof` have to come
    // from the same copy. A newer major here would install a second one.
    const actual = Object.keys(manifest.dependencies).sort();
    const expected = RUNTIME_DEPENDENCIES;
    assert.deepEqual(actual, expected);
    assert.match(
      manifest.dependencies.cbor,
      /^\^8\./,
      'cbor must stay on the major cose-js depends on; see CONTRIBUTING.md'
    );
    assert.equal(manifest.peerDependencies, undefined);
    assert.equal(manifest.engines.node, '>=22');
  });

  it('ships the declarations unchanged', () => {
    const actual = readFileSync(path.join(installed, 'lib', 'index.d.ts'), 'utf8');
    const expected = readFileSync(path.join(ROOT, 'lib', 'index.d.ts'), 'utf8');
    assert.equal(actual, expected);
  });
});

describe('the installed package', () => {
  it('resolves by name to the same class as the working tree', () => {
    const resolved = consumer.resolve('cwt-js');
    assert.equal(resolved, path.join(installed, manifest.main));

    const packed = consumer('cwt-js');
    assert.equal(packed.name, CWT.name);
    assert.equal(packed.CwtTag, CWT.CwtTag);
    assert.deepEqual(
      Object.getOwnPropertyNames(packed.prototype).sort(),
      Object.getOwnPropertyNames(CWT.prototype).sort()
    );
  });

  it('creates and verifies a token when required from outside the repository', async () => {
    const PackedCWT = consumer('cwt-js');
    const key = {
      k: Buffer.from('403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388', 'hex'),
      kid: 'Symmetric256'
    };
    const claims = { iss: 'coap://as.example.com', cti: '0b71' };

    const token = await new PackedCWT(claims).mac(key, 'HS256/64', { addTag: true });
    const parsed = await PackedCWT.parse(token.raw, key);

    const actual = parsed.claims;
    const expected = claims;
    assert.deepEqual(actual, expected);
    assert.equal(token.raw.toString('hex').slice(0, 4), 'd83d');
  });

  it('type-checks against a TypeScript consumer resolving it by name', () => {
    writeFileSync(path.join(workspace, 'consumer.ts'), [
      'import CWT = require(\'cwt-js\');',
      'const claims: CWT.Claims = { iss: \'coap://as.example.com\', cti: \'0b71\' };',
      'const key: CWT.SymmetricKey = { k: Buffer.alloc(32), kid: \'Symmetric256\' };',
      'const token = new CWT(claims);',
      'const maced: Promise<CWT> = token.mac(key, \'HS256/64\', { addTag: true });',
      'const parsed: Promise<CWT.Claims> = CWT.parse(Buffer.alloc(0), key).then(cwt => cwt.claims);',
      'const tag: 61 = CWT.CwtTag;',
      'export { maced, parsed, tag };',
      ''
    ].join('\n'));

    writeFileSync(path.join(workspace, 'tsconfig.json'), JSON.stringify({
      compilerOptions: {
        strict: true,
        noEmit: true,
        target: 'es2022',
        module: 'node16',
        moduleResolution: 'node16',
        skipLibCheck: false,
        // Buffer comes from @types/node, which is a devDependency of this
        // repository rather than of the temporary workspace.
        typeRoots: [path.join(ROOT, 'node_modules', '@types')],
        types: ['node']
      },
      include: ['consumer.ts']
    }));

    // typescript is a devDependency of this repo, not of the temp workspace.
    const tsc = require.resolve('typescript/bin/tsc');
    execFileSync(process.execPath, [tsc, '--project', workspace], { stdio: 'pipe' });
  });
});
