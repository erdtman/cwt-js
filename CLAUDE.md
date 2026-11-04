# Project conventions

## Tests

Always use explicit `actual` and `expected` variables in tests rather than
inlining values directly into assertions. This improves readability.

```js
// preferred
const actual = cwt.raw.toString('hex');
const expected = example.output;
assert.equal(actual, expected);

// avoid
assert.equal(cwt.raw.toString('hex'), example.output);
```

Assert against a byte string from RFC 8392 wherever one exists. A test that
compares the library against itself cannot tell you the format is right.

## Dependencies

`cbor` stays on the major that `cose-js` depends on. `Tagged` instances are
compared with `instanceof`, so two copies of `cbor` in the tree would be two
unrelated `Tagged` classes. Check `cose-js`'s own dependency range before
bumping it here.
