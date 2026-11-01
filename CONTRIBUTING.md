# Contributing

```sh
npm install
npm test                 # lint, type-check, then the suite
npm run watch            # re-run the suite on every change
npm run coverage         # the suite with a coverage report
npm run coverage:check   # fail below 100% lines, branches and functions
npm run lint             # eslint
npm run lint:fix
npm run lint:types       # tsc against lib/index.d.ts and test/types
npm run mutation         # mutation testing (fetches Stryker on demand)
```

Tests use the Node.js built-in test runner and `node:assert/strict`. There are
no test dependencies: the whole development tree is eslint, typescript and the
Node.js type declarations.

## The suite

| File | What it covers |
| --- | --- |
| `test/rfc.js` | The RFC 8392 appendix A examples, in both directions: the bytes this library produces for each, and the claims it reads back out of the published bytes. |
| `test/claims.js` | The claims map: names to labels and back, `cti` hex, unregistered claims, `raw` and `reset`. |
| `test/options.js` | `addTag` on each producing method, and `randomSource`. |
| `test/parse.js` | What `parse` refuses: a malformed, empty, truncated or tampered token, the wrong key, and an inner tag it does not recognise. Also the three shapes a nested token's outer layer can take. |
| `test/exports.js` | The module surface: the class, its statics, its prototype, and that nothing else is public. |
| `test/esm.mjs` | The `import` surface, which the CommonJS tests cannot reach. |
| `test/docs.js` | Every snippet in the README and every file in `examples/`, run for real. |
| `test/runtime.js` | That the CBOR encoder in this runtime encodes completely. See the runtime note below. |
| `test/package.js` | The published tarball: its contents, its entry points, and that it works when required and type-checked from outside the repository. |

The RFC tests are the ones that say this library implements the format rather
than merely implementing itself: every assertion in them is against a byte
string from RFC 8392, so they cannot be satisfied by changing the library.

The documentation tests run each README snippet in a child process with
`require("cwt-js")` pointed at the working tree. The snippets end in a bare
`.then()` with no catch, so a token that no longer verifies, a key of the wrong
shape or a renamed method becomes an unhandled rejection and a failed test.
They also check that the token a deterministic snippet prints is the one the
matching verify snippet is documented with.

Coverage counts `lib/` only and is required to stay at 100% of lines, branches
and functions. It is a floor, not a goal: a saturated percentage says nothing
about whether the tokens are still right, so the RFC vectors and the rejection
tests are what the suite actually leans on.

`npm run mutation` changes the library and expects the suite to notice, which
is the check coverage cannot give. It fetches Stryker on demand rather than
carrying it as a dependency, runs the behavioural tests only — the
documentation and tarball tests shell out to `node` and `npm` against the
working tree, which is not what a mutant changes — and runs weekly in CI. It
has no break threshold set yet; the first run establishes the baseline.

## The Node.js 26 runtime note

`cbor` assembles its output through `nofilter`, whose synchronous `read()`
returns only the first buffered chunk on Node.js 26 instead of all of them.
`cbor.encode()` then yields a container header with no contents —
`cbor.encode(new Map([[1, -7]]))` is `a1` rather than `a10126` — so this
library would hand back truncated CBOR, quietly, rather than throwing. `cbor` 8
and `cbor` 10 are both affected, and so is `cose-js`, so no dependency range
this package can declare avoids it. It needs a fix upstream in `nofilter`.

`test/runtime.js` exists so that this says so in one line rather than as three
dozen mismatched byte strings, and the CI matrix stops at Node.js 24 until it
is fixed.

## Dependencies

The library depends on `cose-js` for the COSE layer and `cbor` for encoding.
`cbor` is deliberately held at the major that `cose-js` depends on, so that the
install tree holds one copy of it: `Tagged` instances are compared with
`instanceof`, and two copies of `cbor` would mean two unrelated `Tagged`
classes. When `cose-js` moves to a new `cbor` major, this package follows.

Every push runs the suite on each Node.js version `engines` allows, under the
coverage thresholds, and audits the dependency tree. See
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). The release process is
in [RELEASING.md](RELEASING.md).
