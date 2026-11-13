'use strict';

const cbor = require('cbor');
const cose = require('cose-js');
const Tagged = cbor.Tagged;
const Decoder = cbor.Decoder;

/** The CBOR tag that marks a byte string as a CWT. RFC 8392 section 6. */
const CwtTag = 61;

const claimsToLabels = {
  iss: 1, // 3
  sub: 2, // 3
  aud: 3, // 3
  exp: 4, // 6 tag value 1
  nbf: 5, // 6 tag value 1
  iat: 6, // 6 tag value 1
  cti: 7 // 2
};

const claimTrans = {
  cti: (value) => {
    return Buffer.from(value, 'hex');
  }
};

const claimTransBack = {
  cti: (value) => {
    return value.toString('hex');
  }
};

const labelsToClaim = [
  '',
  'iss',
  'sub',
  'aud',
  'exp',
  'nbf',
  'iat',
  'cti'
];

/**
 * The entries of a claims set, whichever shape it arrived in.
 *
 * A decoded claims set is a Map, or a plain object when every key is a string:
 * cbor only reaches for a Map once a key is not one, so a token whose claims
 * are all privately named has no integer labels and comes back as an object.
 * Reading only the Map shape is what made such a token unparseable, and it
 * does not show up in the RFC 8392 vectors because every one of them carries a
 * registered claim.
 *
 * Anything else a verified layer might hold - a byte string, an array, a
 * scalar - is not a claims set. Each of those has or inherits a forEach, or
 * indices Object.entries is happy to walk, so the shapes that used to turn
 * into claims numbered 0, 1, 2 are refused here instead.
 */
function claimEntries (claims) {
  if (claims instanceof Map) {
    return claims.entries();
  }
  if (claims !== null && typeof claims === 'object' &&
      !Array.isArray(claims) && !Buffer.isBuffer(claims)) {
    return Object.entries(claims);
  }
  throw new TypeError('Claims are not a CBOR map');
}

function translateToJSON (claims) {
  const result = {};
  for (const [param, value] of claimEntries(claims)) {
    const key = labelsToClaim[param] ? labelsToClaim[param] : param;
    const theValue = claimTransBack[key] ? claimTransBack[key](value) : value;
    result[key] = theValue;
  }
  return result;
}

/**
 * The bytes to keep for a layer that has just been created: the COSE structure
 * as cose-js returned it, or that structure wrapped in the CWT tag.
 *
 * The round trip through the decoder is what puts the tag around the COSE
 * structure rather than around the byte string holding it.
 */
async function withCwtTag (buf, options) {
  if (!options.addTag) {
    return buf;
  }
  return cbor.encode(new Tagged(CwtTag, await cbor.decodeFirst(buf)));
}

/**
 * What a COSE tag handler returns: the contents of a layer whose signature,
 * MAC or encryption has been checked.
 *
 * The wrapper is the only evidence parse has that a key was used at all. Only
 * a tag handler builds one, so everything else the decoder can hand back -
 * a bare claims map, a scalar, a tag cbor returned unchanged after swallowing
 * an error a handler threw synchronously - fails the check in parse instead of
 * being read as a token that verified.
 */
class VerifiedLayer {
  constructor (contents) {
    this.contents = contents;
  }
}

class CWT {
  constructor (claims) {
    if (Buffer.isBuffer(claims)) {
      this.done = false;
      this.data = claims;
    } else {
      this.done = true;
      this.payload = new Map();
      for (const param in claims) {
        const key = claimsToLabels[param] ? claimsToLabels[param] : param;
        const value = claimTrans[param] ? claimTrans[param](claims[param]) : claims[param];
        this.payload.set(key, value);
      }
    }
  }

  get (key) {
    const theKey = claimsToLabels[key] ? claimsToLabels[key] : key;
    return this.payload.get(theKey);
  }

  get claims () {
    return translateToJSON(this.payload);
  }

  get raw () {
    return this.data;
  }

  set (key, value) {
    const theKey = claimsToLabels[key] ? claimsToLabels[key] : key;
    this.payload.set(theKey, value);
  }

  reset () {
    delete this.data;
  }

  async mac (key, alg, options) {
    options = options || {};
    const plaintext = cbor.encode(this.payload);
    const headers = {
      p: { alg: alg },
      u: { kid: key.kid }
    };
    const recipient = {
      key: key.k
    };

    const buf = await cose.mac.create(headers, plaintext, recipient);
    this.data = await withCwtTag(buf, options);
    return this;
  }

  async sign (key, alg, options) {
    options = options || {};
    const plaintext = cbor.encode(this.payload);
    const headers = {
      p: { alg: alg },
      u: { kid: key.kid }
    };
    const signer = {
      key: key
    };

    const buf = await cose.sign.create(headers, plaintext, signer);
    this.data = await withCwtTag(buf, options);
    return this;
  }

  async encrypt (key, alg, options) {
    options = options || {};
    // Encrypts the token already held, if there is one, rather than the
    // claims: that is what makes the result a nested CWT.
    const plaintext = Buffer.isBuffer(this.data) ? this.data : cbor.encode(this.payload);
    const headers = {
      p: { alg: alg },
      u: { kid: key.kid }
    };
    const recipient = {
      key: key.k
    };
    const coseOptions = {
      randomSource: options.randomSource
    };

    const buf = await cose.encrypt.create(headers, plaintext, recipient, coseOptions);
    this.data = await withCwtTag(buf, options);
    return this;
  }

  continue (key) {
    return CWT.parse(this.data, key);
  }

  // TODO accept an untagged COSE structure, given the type to expect for it.
  // RFC 8392 section 6 lets the COSE tag be left off where the type is known
  // from the context; such a token is refused here rather than guessed at.
  static async parse (token, key) {
    if (key === null || typeof key !== 'object') {
      // Every tag handler reads key.k, or hands the key to cose-js. Without
      // this, a missing key threw inside a handler, and cbor answers a handler
      // that throws with a Tagged carrying the error rather than failing the
      // decode: parse resolved with the tag, the layer and the error message
      // as the claims of a token it had never verified.
      throw new TypeError('A key is required to parse a token');
    }

    // The tag handlers in getTags are async, and awaiting a promise resolved
    // with a promise adopts it, so this yields the layer rather than a nested
    // promise. A malformed token rejects here; it previously left the returned
    // promise pending for ever.
    const layer = await cbor.decodeFirst(token, { tags: getTags(key) });

    if (layer === Decoder.NOT_FOUND) {
      // An empty input decodes to nothing rather than failing. Without this,
      // parse would resolve with a CWT holding no claims, which nothing had
      // authenticated.
      throw new Error('Empty token');
    }

    if (!(layer instanceof VerifiedLayer)) {
      // Nothing verified: no COSE tag selected a handler, so the key was never
      // used. CBOR that happens to decode to a map is the dangerous case -
      // claims with no signature, MAC or ciphertext around them used to be
      // returned as a token with done true, so cbor.encode(claims) alone was
      // accepted as a CWT for any key.
      throw new Error('Not a CWT: no COSE_Sign1, COSE_Mac0 or COSE_Encrypt0 layer to verify');
    }

    return new CWT(layer.contents);
  }
}

CWT.CwtTag = CwtTag;

function unknownTag (tag) {
  return tag !== CwtTag &&
    tag !== cose.encrypt.Encrypt0Tag &&
    tag !== cose.encrypt.EncryptTag &&
    tag !== cose.mac.MAC0Tag &&
    tag !== cose.mac.MACTag &&
    tag !== cose.sign.Sign1Tag &&
    tag !== cose.sign.SignTag;
}

/**
 * What a COSE layer holds, once the signature, MAC or encryption over it has
 * been checked: either the claims, or the bytes of a nested token.
 *
 * Every tag handler reads its layer this way, and they share this function
 * rather than a copy each because the copies drifted: the one for signatures
 * dropped the verified payload on the floor, so the inner token of a signed
 * nesting came back undefined.
 */
async function readLayer (payload) {
  const raw = await payload;
  const obj = await cbor.decodeFirst(raw);

  if (obj instanceof Tagged) {
    if (unknownTag(obj.tag)) {
      throw new Error(`Unknown tag, ${obj.tag}`);
    }
    // A nested token. Hand back the bytes, so continue() can unwrap them with
    // the next key.
    return new VerifiedLayer(raw);
  }
  return new VerifiedLayer(translateToJSON(obj));
}

function getTags (key) {
  const tags = {};

  tags[cose.encrypt.Encrypt0Tag] = (val) => readLayer(cose.encrypt.read(
    cbor.encode(val),
    key.k,
    { defaultType: cose.encrypt.Encrypt0Tag }
  ));

  tags[cose.mac.MAC0Tag] = (val) => readLayer(cose.mac.read(
    cbor.encode(val),
    key.k
  ));

  tags[cose.sign.Sign1Tag] = (val) => readLayer(cose.sign.verify(
    cbor.encode(val),
    { key: key },
    { defaultType: cose.sign.Sign1Tag }
  ));

  tags[CwtTag] = (val) => {
    return val;
  };
  return tags;
}

module.exports = CWT;
