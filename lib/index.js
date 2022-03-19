/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const Promise = require('any-promise');
const cose = require('cose-js');
const NoFilter = require('nofilter');
const Tagged = cbor.Tagged;
const Decoder = cbor.Decoder;

const CwtTag = exports.CwtTag = 61;

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
  claims.forEach((value, param, map) => {
    const key = labelsToClaim[param] ? labelsToClaim[param] : param;
    const theValue = claimTransBack[key] ? claimTransBack[key](value) : value;
    result[key] = theValue;
  });
  return result;
}

module.exports = class CWT {
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

  done () {
    return this.done;
  }

  mac (key, alg, options) {
    options = options || {};
    const plaintext = cbor.encode(this.payload);
    const headers = {
      p: { alg: alg },
      u: { kid: key.kid }
    };
    const recipent = {
      key: key.k
    };

    return cose.mac.create(
      headers,
      plaintext,
      recipent)
      .then((buf) => {
        if (options.addTag) {
          return cbor.decodeFirst(buf);
        }
        this.data = buf;
        return this;
      }).then((obj) => {
        if (options.addTag) {
          this.data = cbor.encode(new Tagged(CwtTag, obj));
        }
        return this;
      });
  }

  sign (key, alg, options) {
    options = options || {};
    const plaintext = cbor.encode(this.payload);
    const headers = {
      p: { alg: alg },
      u: { kid: key.kid }
    };
    const signer = {
      key: key
    };

    return cose.sign.create(
      headers,
      plaintext,
      signer)
      .then((buf) => {
        if (options.addTag) {
          return cbor.decodeFirst(buf);
        }
        this.data = buf;
        return this;
      }).then((obj) => {
        if (options.addTag) {
          this.data = cbor.encode(new Tagged(CwtTag, obj));
        }
        return this;
      });
  }

  encrypt (key, alg, options) {
    options = options || {};
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

    return cose.encrypt.create(
      headers,
      plaintext,
      recipient,
      coseOptions
    ).then((buf) => {
      if (options.addTag) {
        return cbor.decodeFirst(buf);
      }
      this.data = buf;
      return this;
    }).then((obj) => {
      if (options.addTag) {
        this.data = cbor.encode(new Tagged(CwtTag, obj));
      }
      return this;
    });
  }

  continue (key) {
    return CWT.parse(this.data, key);
  }

  static parse (token, key) {
    return new Promise((resolve, reject) => {
      const d = new Decoder({ tags: getTags(key) });
      const nf = new NoFilter(token);
      nf.pipe(d);
      d.on('data', (v) => {
        // TODO handle untagged stuff
        // TODO verify that we have a promise
        v.then((claims) => {
          resolve(new CWT(claims));
        });
      });
    });
  }
};

function unknownTag (tag) {
  return tag !== CwtTag &&
    tag !== cose.encrypt.Encrypt0Tag &&
    tag !== cose.encrypt.EncryptTag &&
    tag !== cose.mac.MAC0Tag &&
    tag !== cose.mac.MACTag &&
    tag !== cose.sign.Sign1Tag &&
    tag !== cose.sign.SignTag;
}

function getTags (key) {
  const tags = {};

  tags[cose.encrypt.Encrypt0Tag] = (val) => {
    const options = {
      defaultType: cose.encrypt.Encrypt0Tag
    };
    let raw;
    const cwt = cbor.encode(val);
    return cose.encrypt.read(
      cwt,
      key.k,
      options)
      .then((buf) => {
        raw = buf;
        return cbor.decodeFirst(buf);
      }).then((obj) => {
        if (obj instanceof Tagged) {
          if (unknownTag(obj.tag)) {
            throw new Error('Unknown tag, ' + obj.tag);
          }
          return raw;
        }
        return translateToJSON(obj);
      });
  };

  tags[cose.mac.MAC0Tag] = (val) => {
    let raw;
    const cwt = cbor.encode(val);
    return cose.mac.read(
      cwt,
      key.k)
      .then((buf) => {
        raw = buf;
        return cbor.decodeFirst(buf);
      }).then((obj) => {
        if (obj instanceof Tagged) {
          if (unknownTag(obj.tag)) {
            throw new Error('Unknown tag, ' + obj.tag);
          }
          return raw;
        }
        return translateToJSON(obj);
      });
  };

  tags[cose.sign.Sign1Tag] = (val) => {
    let raw;
    const cwt = cbor.encode(val);
    const verifier = {
      key: key
    };
    const options = {
      defaultType: 18
    };
    return cose.sign.verify(
      cwt,
      verifier,
      options)
      .then((buf) => {
        return cbor.decodeFirst(buf);
      }).then((obj) => {
        if (obj instanceof Tagged) {
          if (unknownTag(obj.tag)) {
            throw new Error('Unknown tag, ' + obj.tag);
          }
          return raw;
        }
        return translateToJSON(obj);
      });
  };

  tags[CwtTag] = (val) => {
    return val;
  };
  return tags;
}
