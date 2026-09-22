#!/usr/bin/env node
/**
 * Writes the SHA-256 of the built file to SHA256SUMS and to the
 * presentation page (site/index.html), so the three always agree.
 * Run after `npm run build`.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const FILE = path.join(ROOT, 'dist', 'amnesicwallet.html');
const SUMS = path.join(ROOT, 'SHA256SUMS');
const PAGE = path.join(ROOT, 'site', 'index.html');

if (!fs.existsSync(FILE)) {
  console.error('dist/amnesicwallet.html not found. Run `npm run build` first.');
  process.exit(1);
}

const hash = crypto.createHash('sha256').update(fs.readFileSync(FILE)).digest('hex');
fs.writeFileSync(SUMS, `${hash}  amnesicwallet.html\n`);

const page = fs.readFileSync(PAGE, 'utf8');
const re = /(<code class="hash" id="sha256">)[0-9a-f]{64}(<\/code>)/;
if (!re.test(page)) { console.error('site/index.html: hash element not found'); process.exit(1); }
fs.writeFileSync(PAGE, page.replace(re, `$1${hash}$2`));

console.log(`${hash}  amnesicwallet.html`);
console.log('Written to SHA256SUMS and site/index.html');
