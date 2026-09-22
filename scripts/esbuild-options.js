/* Build options shared by the application build and the test suite, so
   that `npm test` exercises exactly the code — shims included — that
   ends up in the published file. */
'use strict';

const path = require('path');
const SRC = path.join(__dirname, '..', 'src');

module.exports = {
  bundle: true,
  platform: 'browser',
  target: 'es2020',
  define: { 'process.env.NODE_ENV': '"production"' },
  legalComments: 'none',
  // slip39 is written for Node: its 'crypto' is redirected to our browser
  // adapter, which exposes only the three functions actually used.
  alias: { crypto: path.join(SRC, 'crypto-shim.js') },
  // slip39 also uses Buffer, another Node global missing in the browser.
  inject: [path.join(SRC, 'buffer-shim.js')],
};
