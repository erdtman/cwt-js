[![CI](https://github.com/erdtman/cwt-js/actions/workflows/ci.yml/badge.svg)](https://github.com/erdtman/cwt-js/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/erdtman/cwt-js/badge.svg?branch=master)](https://coveralls.io/github/erdtman/cwt-js?branch=master)

# cwt-js

[CWT](https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token) implementation.

# install

```
npm install cwt-js --save
```

# Usage

# MAC CWT

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
cwt.mac(encKey, alg).then((cwt) => {
  console.log(cwt.raw.toString("hex"));
});
```

# Verify MACed CWT

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

# Sign CWT

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

# Verify Signed CWT

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

# Encrypt CWT

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

# Decrypt CWT

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

# Create Nested CWT

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

# Verify Nested CWT

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
    console.log("done: " + cwt.done);
    return cwt.continue(verifyKey);
  })
  .then((cwt) => {
    console.log("done: " + cwt.done);
    console.log(cwt.claims);
  });
```
