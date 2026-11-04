# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-11-04

The library's behaviour is unchanged except where noted under Fixed. Everything
else here is packaging, tests and tooling.

### Added

- Bundled TypeScript declarations (`lib/index.d.ts`), covering the claims set,
  the three key shapes and the options each method takes. They are checked by
  `tsc` in CI, against a compile-only test file whose `@ts-expect-error` lines
  fail the build if invalid usage stops being invalid.
- `CWT.CwtTag` is reachable. The tag was assigned to `exports` and then
  `module.exports` was reassigned to the class, which threw the assignment
  away, so `require('cwt-js').CwtTag` had always been `undefined`.
- An `exports` map and a `files` allowlist. The published tarball is now
  `lib/`, `README.md`, `LICENSE` and `package.json`; it previously included the
  tests, the examples, the RFC vectors and a stray scratch file.
- Releases are published from GitHub Actions with npm provenance attestations
  and trusted publishing, so no npm token is stored in the repository and a
  published tarball can be traced to the commit that built it. A tag that does
  not match the version in `package.json` fails the workflow, and the workflow
  stages rather than publishes, so a tag push alone cannot ship a version.
- CI runs on Node.js 22 and 24, with linting, type-checking and a 100%
  coverage gate, plus an `npm audit` job. The two runtime dependencies pull in
  a crypto stack, so an advisory against any of them is this package's problem.
  The gate is scoped to production dependencies: an advisory in eslint or tsc
  cannot reach anyone who installs this package.
- A test that this package does not work on Node.js 26, and why. `cbor`
  assembles its output through `nofilter`, whose synchronous `read()` returns
  only the first buffered chunk there, so `cbor.encode()` emits a container
  header with no contents and every token comes out as truncated CBOR —
  silently. `cbor` 8 and `cbor` 10 are both affected, and so is `cose-js`, so
  no dependency range this package can declare avoids it; it needs a fix
  upstream in `nofilter`. `test/runtime.js` turns that into one named
  assertion, and the README and CI matrix say so.
- Mutation testing (`npm run mutation`), configured and run weekly in CI.
  Stryker is fetched on demand rather than added as a dependency.
- `CHANGELOG.md`, `CONTRIBUTING.md`, `RELEASING.md` and `CLAUDE.md`.
- `.npmrc` pinning the registry, and `publishConfig.registry` doing the same
  for publishing, so neither follows a company mirror the machine happens to
  be configured for.

### Changed

- `engines` now says Node.js >=22, the oldest release still supported
  upstream. It previously said >=15, and CI tested only Node.js 16.
- `cose-js` moves to ^0.9.0.
- The library uses `async`/`await` internally instead of `.then()` chains.
  The public API is unchanged — every method still returns a promise — but
  55 lines of plumbing go away, and the three COSE tag handlers now share one
  function instead of holding a copy each. That duplication is what hid the
  lost inner token above: two copies kept the verified payload and the third
  did not, which `const raw = await …` cannot express.
- The README is rewritten: an API table, the registered claims and their
  labels, the limitations worth knowing about, and a fixed npm badge in
  place of a coverage badge for a service this repository no longer uses.

### Fixed

- `parse` rejects a token it cannot read. It decoded by piping the token into a
  streaming decoder and listening only for `'data'`, so a malformed, truncated
  or tampered token left the returned promise pending for ever: an `await` on
  it never came back. It now rejects.
- `parse` rejects an empty token. An empty input decodes to nothing rather than
  failing, so it used to resolve with a CWT holding no claims — which nothing
  had authenticated.
- The inner token was lost when the outer layer of a nested token was signed.
  The signature handler never kept the verified payload, so `raw` came back as
  `undefined` and there was nothing left to `continue` with. The MAC and
  encryption handlers were unaffected.
- `nyc` was declared as a runtime dependency, so every consumer of this package
  installed a coverage tool and its tree.
- The MAC example in the README and in `examples/mac.js` produced a token
  different from the one the matching verify example was documented with. It
  now passes `addTag`, which is the form RFC 8392 appendix A.4 publishes.

### Removed

- The `any-promise` and `nofilter` dependencies. `Promise` is a built-in, and
  `cbor.decodeFirst(token, { tags })` does what the hand-rolled `NoFilter`
  stream plumbing did.
- The `ava`, `semistandard`, `jsonfile` and `nyc` development dependencies.
  Tests use the built-in `node:test` runner and its built-in coverage, and
  linting is eslint with its own recommended rules. Formatting is not linted:
  those rules are taste rather than correctness.
- The `done()` method. Every instance set a `done` property in its constructor,
  which shadowed it, so it could never be called. `done` as a property is what
  the documentation and the tests always used.
- `test/tmp.json`, a scratch file committed by accident, and the `jshint` and
  `jslint` pragmas left over from before the repository had a linter.

### Tests

- The suite moves from ava to the built-in runner and has no test dependencies
  at all. It is layered into the RFC 8392 appendix A vectors, the claims
  mapping, the options, what `parse` refuses, the module surface, the `import`
  surface, documentation drift and the packed tarball. 91 tests, at 100% of
  lines, branches and functions in `lib/`.
- The RFC vectors are tested in both directions: the bytes this library
  produces for each published example, and the claims it reads back out of the
  published bytes.
- `parse` is tested against a malformed, empty, truncated and tampered token,
  the wrong key for each of the three COSE shapes, and an inner tag it does not
  recognise. A nested token's outer layer is tested in all three shapes, which
  is what caught the lost inner token above.
- Every README snippet and every file in `examples/` is executed, and the token
  a deterministic snippet prints is checked against the one the matching verify
  snippet documents. A broken example now fails the build rather than
  misleading a reader.
- The packed tarball is tested: its file list, that `main`, `types` and
  `exports` all point at files that are in it, that it works when required from
  outside the repository, and that it type-checks for a TypeScript consumer
  resolving it by name.

## [0.4.0] and earlier

See the [commit history](https://github.com/erdtman/cwt-js/commits/master).
These versions were published before this repository tagged its releases, so
there is nothing to compare them against here. The 0.4.0 tarball on npm was
published in January 2018 from a commit that never reached this repository;
0.3.0 is the last release whose source is in the history above.

[0.5.0]: https://github.com/erdtman/cwt-js/releases/tag/v0.5.0
