/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const test = require('ava');

test.skip('get and set', (t) => {
  const CWT = require('../');
  const claims = { aud: 'samuel', sub: 'charlotte' };
  const cwt = new CWT(claims);
  t.is(cwt.get('aud'), 'samuel');
  t.is(cwt.get('sub'), 'charlotte');
  cwt.set('iss', 'kalle');
  t.is(cwt.get('iss'), 'kalle');
  cwt.set('unknown', 'nisse');
  t.is(cwt.get('unknown'), 'nisse');
  cwt.set(15, 'anna');
  t.is(cwt.get(15), 'anna');
});
