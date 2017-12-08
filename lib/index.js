/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const Promise = require('any-promise');
const cose = require('cose-js');
const NoFilter = require('nofilter');
const Tagged = cbor.Tagged;
const Decoder = cbor.Decoder;

const cwtTag = 61;

const claimsToLabels = {
  'iss': 1, // 3
  'sub': 2, // 3
  'aud': 3, // 3
  'exp': 4, // 6 tag value 1
  'nbf': 5, // 6 tag value 1
  'iat': 6, // 6 tag value 1
  'cti': 7  // 2
};

const claimTrans = {
  'cti': (value) => {
    return Buffer.from(value, 'hex');
  }
};

const claimTransBack = {
  'cti': (value) => {
    return value.toString('hex');
  }
};

let labelsToClaim = [
  '',
  'iss',
  'sub',
  'aud',
  'exp',
  'nbf',
  'iat',
  'cti'
];

function mac (key, alg, kid, options) {
  return new Promise((resolve, reject) => {
    options = options || {};
    const plaintext = cbor.encode(this.payload);
    const headers = {
      'p': {'alg': alg},
      'u': {'kid': kid}
    };
    const recipent = {
      'key': key
    };

    cose.mac.create(
      headers,
      plaintext,
      recipent)
    .then((buf) => {
      if (options.addTag) {
        cbor.decodeFirst(buf).then((obj) => {
          resolve(cbor.encode(new Tagged(cwtTag, obj)));
        });
      } else {
        resolve(buf);
      }
    });
  });
}

function sign (key, alg, kid, options) {
  return new Promise((resolve, reject) => {
    options = options || {};
    const plaintext = cbor.encode(this.payload);
    const headers = {
      'p': {'alg': alg},
      'u': {'kid': kid}
    };
    const signer = {
      'key': key
    };

    cose.sign.create(
      headers,
      plaintext,
      signer)
    .then((buf) => {
      if (options.addTag) {
        cbor.decodeFirst(buf).then((obj) => {
          resolve(cbor.encode(new Tagged(cwtTag, obj)));
        });
      } else {
        resolve(buf);
      }
    });
  });
}

function encrypt (key, alg, kid, options) {
  return new Promise((resolve, reject) => {
    options = options || {};
    const plaintext = cbor.encode(this.payload);
    const headers = {
      'p': {'alg': alg},
      'u': {'kid': kid}
    };
    const recipient = {
      'key': key
    };
    const coseOptions = {
      'randomSource': options.randomSource
    };

    cose.encrypt.create(
      headers,
      plaintext,
      recipient,
      coseOptions
    ).then((buf) => {
      if (options.addTag) {
        cbor.decodeFirst(buf).then((obj) => {
          resolve(cbor.encode(new Tagged(cwtTag, obj)));
        });
      } else {
        resolve(buf);
      }
    });
  });
}

exports.create = function (claims) {
  const payload = new Map();
  for (let param in claims) {
    const key = claimsToLabels[param] ? claimsToLabels[param] : param;
    const value = claimTrans[param] ? claimTrans[param](claims[param]) : claims[param];
    payload.set(key, value);
  }

  // TODO handle types

  return {
    'payload': payload,
    'get': (key) => {
      const theKey = claimsToLabels[key] ? claimsToLabels[key] : key;
      return payload.get(theKey);
    },
    'set': (key, value) => {
      const theKey = claimsToLabels[key] ? claimsToLabels[key] : key;
      payload.set(theKey, value);
    },
    'mac': mac,
    'sign': sign,
    'encrypt': encrypt
  };
};

function getTags (key) {
  const tags = {};
  tags[16] = (val) => {
    return new Promise((resolve, reject) => {
      const options = {
        'defaultType': 16
      };
      const cwt = cbor.encode(val);
      cose.encrypt.read(
        cwt,
        key,
        options)
      .then((buf) => {
        cbor.decodeFirst(buf).then((claims) => {
          const result = {};
          claims.forEach((value, param, map) => {
            const key = labelsToClaim[param] ? labelsToClaim[param] : param;
            const theValue = claimTransBack[key] ? claimTransBack[key](value) : value;
            result[key] = theValue;
          });
          resolve(result);
        });
      });
    });
  };
  tags[17] = (val) => {
    return new Promise((resolve, reject) => {
      const cwt = cbor.encode(val);
      cose.mac.read(
        cwt,
        key)
      .then((buf) => {
        cbor.decodeFirst(buf).then((claims) => {
          const result = {};
          claims.forEach((value, param, map) => {
            const key = labelsToClaim[param] ? labelsToClaim[param] : param;
            const theValue = claimTransBack[key] ? claimTransBack[key](value) : value;
            result[key] = theValue;
          });
          resolve(result);
        });
      });
    });
  };
  tags[18] = (val) => {
    return new Promise((resolve, reject) => {
      const cwt = cbor.encode(val);
      const verifier = {
        'key': key
      };
      const options = {
        'defaultType': 18
      };
      cose.sign.verify(
        cwt,
        verifier,
        options)
      .then((buf) => {
        cbor.decodeFirst(buf).then((claims) => {
          const result = {};
          claims.forEach((value, param, map) => {
            const key = labelsToClaim[param] ? labelsToClaim[param] : param;
            const theValue = claimTransBack[key] ? claimTransBack[key](value) : value;
            result[key] = theValue;
          });
          resolve(result);
        });
      });
    });
  };
  tags[61] = (val) => {
    return val;
  };
  return tags;
}

exports.read = function (cwt, key) {
  return new Promise((resolve, reject) => {
    const d = new Decoder({'tags': getTags(key)});
    const nf = new NoFilter(cwt);
    nf.pipe(d);
    d.on('data', (v) => {
      // TODO verify that we have a promise
      v.then((claims) => {
        resolve(claims);
      });
    });
  });
};
