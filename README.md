# cwt-js

[![CI](https://github.com/erdtman/cwt-js/actions/workflows/ci.yml/badge.svg)](https://github.com/erdtman/cwt-js/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/cwt-js.svg)](https://www.npmjs.com/package/cwt-js)

A [CBOR Web Token (RFC 8392)](https://www.rfc-editor.org/rfc/rfc8392) implementation.

A CWT is the CBOR counterpart of a JWT: a claims set, keyed by small integer
labels instead of names, carried inside a [COSE](https://www.rfc-editor.org/rfc/rfc9052)
structure. It can be signed, MACed or encrypted, and one CWT can be nested
inside another — signed and then encrypted, so that only the holder of the
decryption key learns who signed it.

This library creates and verifies all four shapes, and translates between the
integer labels on the wire and the claim names you write.

## Install

```sh
npm install cwt-js
```

Requires Node.js 22 or later. Node.js 26 does not work yet; see
[Limitations](#limitations).

## Usage

### MAC a CWT

```js
const CWT = require("cwt-js");

const encKey = {
  k: Buffer.from(
    "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
    "hex"
  ),
  kid: "Symmetric256",
};
const alg = "HS256/64";
const claims = {
  iss: "coap://as.example.com",
  sub: "erikw",
  aud: "coap://light.example.com",
  exp: 1444064944,
  nbf: 1443944944,
  iat: 1443944944,
  cti: "0b71",
};

const cwt = new CWT(claims);
cwt.mac(encKey, alg, { addTag: true }).then((cwt) => {
  console.log(cwt.raw.toString("hex"));
});
```

### Verify a MACed CWT

```js
const CWT = require("cwt-js");

const decKey = {
  k: Buffer.from(
    "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
    "hex"
  ),
  kid: "Symmetric256",
};
const token = Buffer.from(
  "d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200",
  "hex"
);

CWT.parse(token, decKey).then((cwt) => {
  console.log(cwt.claims);
});
```

### Sign a CWT

```js
const CWT = require("cwt-js");

const signKey = {
  d: Buffer.from(
    "6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19",
    "hex"
  ),
  kid: "AsymmetricECDSA256",
};
const alg = "ES256";
const claims = {
  iss: "coap://as.example.com",
  sub: "erikw",
  aud: "coap://light.example.com",
  exp: 1444064944,
  nbf: 1443944944,
  iat: 1443944944,
  cti: "0b71",
};

const cwt = new CWT(claims);
cwt.sign(signKey, alg).then((cwt) => {
  console.log(cwt.raw.toString("hex"));
});
```

### Verify a signed CWT

```js
const CWT = require("cwt-js");

const verifyKey = {
  x: Buffer.from(
    "143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f",
    "hex"
  ),
  y: Buffer.from(
    "60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9",
    "hex"
  ),
  kid: "AsymmetricECDSA256",
};

const token = Buffer.from(
  "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30",
  "hex"
);

CWT.parse(token, verifyKey).then((cwt) => {
  console.log(cwt.claims);
});
```

### Encrypt a CWT

```js
const CWT = require("cwt-js");

const encKey = {
  k: Buffer.from("231f4c4d4d3051fdc2ec0a3851d5b383", "hex"),
  kid: "Symmetric128",
};

const alg = "AES-CCM-16-64-128";
const claims = {
  iss: "coap://as.example.com",
  sub: "erikw",
  aud: "coap://light.example.com",
  exp: 1444064944,
  nbf: 1443944944,
  iat: 1443944944,
  cti: "0b71",
};

const cwt = new CWT(claims);
cwt.encrypt(encKey, alg).then((cwt) => {
  console.log(cwt.raw.toString("hex"));
});
```

### Decrypt a CWT

```js
const CWT = require("cwt-js");

const decKey = {
  k: Buffer.from("231f4c4d4d3051fdc2ec0a3851d5b383", "hex"),
  kid: "Symmetric128",
};
const token = Buffer.from(
  "d08343a1010aa2044c53796d6d6574726963313238054d99a0d7846e762c49ffe8a63e0b5858b918a11fd81e438b7f973d9e2e119bcb22424ba0f38a80f27562f400ee1d0d6c0fdb559c02421fd384fc2ebe22d7071378b0ea7428fff157444d45f7e6afcda1aae5f6495830c58627087fc5b4974f319a8707a635dd643b",
  "hex"
);

CWT.parse(token, decKey).then((cwt) => {
  console.log(cwt.claims);
});
```

### Create a nested CWT

`encrypt` encrypts the token already in hand rather than the claims, so signing
and then encrypting produces a nested CWT.

```js
const CWT = require("cwt-js");

const claims = {
  iss: "coap://as.example.com",
  sub: "erikw",
  aud: "coap://light.example.com",
  exp: 1444064944,
  nbf: 1443944944,
  iat: 1443944944,
  cti: "0b71",
};

const encAlg = "AES-CCM-16-64-128";
const encKey = {
  k: Buffer.from("231f4c4d4d3051fdc2ec0a3851d5b383", "hex"),
  kid: "Symmetric128",
};

const signAlg = "ES256";
const signKey = {
  d: Buffer.from(
    "6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19",
    "hex"
  ),
  kid: "AsymmetricECDSA256",
};

const cwt = new CWT(claims);
cwt
  .sign(signKey, signAlg)
  .then((signedCWT) => {
    return signedCWT.encrypt(encKey, encAlg);
  })
  .then((encryptedCWT) => {
    console.log(encryptedCWT.raw.toString("hex"));
  });
```

### Verify a nested CWT

`parse` removes the outer layer. While an inner layer is still wrapped `done`
is false; `continue` unwraps the next one with the next key.

```js
const CWT = require("cwt-js");

const decKey = {
  k: Buffer.from("231f4c4d4d3051fdc2ec0a3851d5b383", "hex"),
  kid: "Symmetric128",
};

const verifyKey = {
  x: Buffer.from(
    "143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f",
    "hex"
  ),
  y: Buffer.from(
    "60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9",
    "hex"
  ),
  kid: "AsymmetricECDSA256",
};

const token = Buffer.from(
  "d08343a1010aa2044c53796d6d6574726963313238054dc62ed9a1391053623cdb5c5c7458b7cb6c7a62c5ad2792bd1b17c18e2eb28764c81e3f359ed7fc98a6177b179475548148b37b58319d403ae5929af804a356682f881ce4e409f0c3f8003620c03afaaa3a1ccf1fc0298cd98cd21d1db0b92739862805bee7227ce98046816831ecb23b1553d097d32eeb00b3513a3dde28da557996a732fe596746e0b6b0b8725c201bc7b7321c77a91792de9c4ecda33499810962fad24ab2ff37a4fb7a85d15b3f5e1da2a7ae38067eba20439947a57e17590413df08c333",
  "hex"
);
CWT.parse(token, decKey)
  .then((cwt) => {
    console.log(`done: ${cwt.done}`);
    return cwt.continue(verifyKey);
  })
  .then((cwt) => {
    console.log(`done: ${cwt.done}`);
    console.log(cwt.claims);
  });
```

## API

The module exports the `CWT` class itself.

| Member | What it does |
| --- | --- |
| `new CWT(claims)` | A token from a claims set. Registered names are translated to their labels. |
| `CWT.parse(token, key)` | Verify or decrypt a token and read its claims. The token's COSE tag selects the operation. Rejects if it does not verify. |
| `CWT.CwtTag` | `61`, the CBOR tag that marks a byte string as a CWT. |
| `cwt.mac(key, alg, options?)` | MAC the claims, producing a COSE_Mac0. Resolves with the token. |
| `cwt.sign(key, alg, options?)` | Sign the claims, producing a COSE_Sign1. Resolves with the token. |
| `cwt.encrypt(key, alg, options?)` | Encrypt the token already held, or the claims if there is none, producing a COSE_Encrypt0. |
| `cwt.continue(key)` | Unwrap the next layer of a nested token. |
| `cwt.claims` | The claims, with registered labels translated back to names. |
| `cwt.raw` | The encoded token, once one of `mac`, `sign` or `encrypt` has run. |
| `cwt.done` | False while an inner layer is still wrapped, which is when `continue` has something to do. |
| `cwt.get(claim)`, `cwt.set(claim, value)` | One claim, by registered name or by label. |
| `cwt.reset()` | Forget the encoded token, keeping the claims. |

`options` takes `addTag`, which wraps the result in the CWT CBOR tag.
`encrypt` also takes `randomSource`, which exists to reproduce a published test
vector; leave it unset and the COSE layer uses a secure random source.

A key is a plain object: `{ k, kid }` to MAC or encrypt, `{ d, kid }` to sign,
`{ x, y, kid }` to verify a signature. Key material is a `Buffer`, and `kid` is
optional.

TypeScript declarations are bundled, so no `@types` package is needed.

### Claims

The seven claims registered by RFC 8392 section 4 are translated between their
names and their integer labels:

| Name | Label | Type |
| --- | --- | --- |
| `iss` | 1 | string |
| `sub` | 2 | string |
| `aud` | 3 | string |
| `exp` | 4 | seconds since the epoch |
| `nbf` | 5 | seconds since the epoch |
| `iat` | 6 | seconds since the epoch |
| `cti` | 7 | hex string, a byte string on the wire |

Any other name or label is carried through unchanged, so a claim this library
has never heard of still works.

### Limitations

- A claims set is encoded and decoded, not checked: `exp` and `nbf` are carried
  faithfully and are not compared against the clock. Verifying a token tells
  you it is authentic, not that it is currently valid.
- `parse` expects a tagged token, and rejects anything else. The COSE tag is
  what selects the verification to perform, so an untagged COSE structure —
  which RFC 8392 section 6 permits where the type is known from the context —
  is refused rather than guessed at. Tag the token, with `addTag` or with the
  COSE tag the structure already carries in every example above.
- **Node.js 26 does not work.** `cbor` assembles its output through
  `nofilter`, whose synchronous `read()` returns only the first buffered chunk
  on Node.js 26, so `cbor.encode()` emits a container header with no contents
  and every token comes out as truncated CBOR. `cbor` 8 and `cbor` 10 are both
  affected, so neither this package nor `cose-js` can declare its way around
  it: it needs a fix upstream in `nofilter`. Node.js 22 and 24 are unaffected
  and are what CI runs, and the test suite fails with that explanation rather
  than silently if it is run on Node.js 26.
- Signing and verifying go through `elliptic`, by way of `cose-js`, which
  carries a low-severity advisory for its use of a risky cryptographic
  primitive ([GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84)).
  There is no fixed release to move to. It is listed here because it is a
  runtime dependency of this package and so it is worth knowing about rather
  than discovering from `npm audit`.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the test suite and
[RELEASING.md](RELEASING.md) for how a version is published.

## License

MIT
