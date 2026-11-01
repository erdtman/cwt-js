// Compile-only check that lib/index.d.ts matches the documented API.
//
// The @ts-expect-error lines are the point of this file: each one fails the
// build if the code below it stops being an error, which is how a declaration
// that has quietly widened to `any` gets caught. Plain tsc, no type-test
// dependency.
import CWT = require('../../lib/index.js');

// --- accepted ---------------------------------------------------------------

const claims: CWT.Claims = {
  iss: 'coap://as.example.com',
  sub: 'erikw',
  aud: 'coap://light.example.com',
  exp: 1444064944,
  nbf: 1443944944,
  iat: 1443944944,
  cti: '0b71',
  // An unregistered claim is carried through as it is.
  scope: 'read'
};

const symmetric: CWT.SymmetricKey = {
  k: Buffer.from('403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388', 'hex'),
  kid: 'Symmetric256'
};

const privateKey: CWT.PrivateKey = {
  d: Buffer.from('6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19', 'hex'),
  kid: 'AsymmetricECDSA256'
};

const publicKey: CWT.PublicKey = {
  x: Buffer.from('143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f', 'hex'),
  y: Buffer.from('60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9', 'hex'),
  kid: 'AsymmetricECDSA256'
};

// A kid is optional, and COSE allows it to be a byte string.
const byteKid: CWT.SymmetricKey = { k: symmetric.k, kid: Buffer.from('01', 'hex') };
const noKid: CWT.SymmetricKey = { k: symmetric.k };

const token = new CWT(claims);
token.set('iss', 'coap://other.example.com');
token.set(15, 'by label too');
const issuer: unknown = token.get('iss');
const byLabel: unknown = token.get(1);
const finished: boolean = token.done;

const maced: Promise<CWT> = token.mac(symmetric, 'HS256/64');
const signed: Promise<CWT> = token.sign(privateKey, 'ES256');
const tagged: Promise<CWT> = token.sign(privateKey, 'ES256', { addTag: true });
const encrypted: Promise<CWT> = token.encrypt(symmetric, 'AES-CCM-16-64-128');

// randomSource exists to reproduce a test vector; it is encrypt-only.
const reproducible: Promise<CWT> = token.encrypt(symmetric, 'AES-CCM-16-64-128', {
  addTag: false,
  randomSource: (bytes: number) => Buffer.alloc(bytes)
});

const parsed: Promise<CWT> = CWT.parse(Buffer.alloc(0), publicKey);
const parsedSymmetric: Promise<CWT> = CWT.parse(Buffer.alloc(0), symmetric);

const unwrapped: Promise<CWT.Claims> = parsed
  .then((outer: CWT) => outer.continue(publicKey))
  .then((inner: CWT) => inner.claims);

const encoded: Buffer | undefined = token.raw;
token.reset();

const tag: 61 = CWT.CwtTag;

// A token can also be built from an already encoded one, which is what parse
// does for an inner layer.
const fromBuffer = new CWT(Buffer.alloc(0));

// --- rejected ---------------------------------------------------------------

// @ts-expect-error the registered time claims are numbers, not dates
const badExp: CWT.Claims = { exp: new Date() };

// @ts-expect-error cti is hex-encoded on the way in, so a string
const badCti: CWT.Claims = { cti: Buffer.from('0b71', 'hex') };

// @ts-expect-error iss is a string
const badIss: CWT.Claims = { iss: 42 };

// @ts-expect-error mac needs a symmetric key, not a private one
token.mac(privateKey, 'HS256/64');

// @ts-expect-error sign needs a private key, not a symmetric one
token.sign(symmetric, 'ES256');

// @ts-expect-error a public key cannot sign
token.sign(publicKey, 'ES256');

// @ts-expect-error the algorithm is required
token.sign(privateKey);

// @ts-expect-error randomSource is an encrypt-only option
token.mac(symmetric, 'HS256/64', { randomSource: () => Buffer.alloc(13) });

// @ts-expect-error randomSource returns bytes, not a string
token.encrypt(symmetric, 'AES-CCM-16-64-128', { randomSource: () => 'not bytes' });

// @ts-expect-error parse takes an encoded token, not a claims set
CWT.parse(claims, symmetric);

// @ts-expect-error a private key cannot verify or decrypt
CWT.parse(Buffer.alloc(0), privateKey);

// @ts-expect-error the key is required
CWT.parse(Buffer.alloc(0));

// @ts-expect-error claims is derived from the payload, not assignable
token.claims = claims;

// @ts-expect-error raw is derived from the payload, not assignable
token.raw = Buffer.alloc(0);

// @ts-expect-error the tag is a constant of the format
CWT.CwtTag = 62;

export {
  claims, symmetric, privateKey, publicKey, byteKid, noKid, token, issuer, byLabel, finished,
  maced, signed, tagged, encrypted, reproducible, parsed, parsedSymmetric, unwrapped, encoded,
  tag, fromBuffer, badExp, badCti, badIss
};
