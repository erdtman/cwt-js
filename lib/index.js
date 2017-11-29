/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const Promise = require('any-promise');
const cose = require('cose-js');
const Tagged = cbor.Tagged;

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
    'sign': (key, alg) => {
      throw new Error('not implemented');
    },
    'encrypt': (key, alg) => {
      throw new Error('not implemented');
    }
  };
};

exports.read = function (cwt, key) {
  return new Promise((resolve, reject) => {
    cbor.decodeFirst(cwt).then((obj) => {
      if (obj instanceof Tagged) {
        if (obj.tag !== cwtTag) {
          // TODO accept other tags too
          throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
        }
        cwt = cbor.encode(obj.value);
      }
      // TODO read another layer if this is a CWT tag

      // TODO handle other types using tag or options
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
  });
};
