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

function translateToJSON (claims) {
  const result = {};
  claims.forEach((value, param) => {
    const key = labelsToClaim[param] ? labelsToClaim[param] : param;
    const theValue = claimTransBack[key] ? claimTransBack[key](value) : value;
    result[key] = theValue;
  });
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

  // TODO handle untagged stuff
  static async parse (token, key) {
    // The tag handlers in getTags are async, and awaiting a promise resolved
    // with a promise adopts it, so this yields the claims rather than a nested
    // promise. A malformed token rejects here; it previously left the returned
    // promise pending for ever.
    const claims = await cbor.decodeFirst(token, { tags: getTags(key) });

    if (claims === Decoder.NOT_FOUND) {
      // An empty input decodes to nothing rather than failing. Without this,
      // parse would resolve with a CWT holding no claims, which nothing had
      // authenticated.
      throw new Error('Empty token');
    }
    return new CWT(claims);
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
    return raw;
  }
  return translateToJSON(obj);
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
