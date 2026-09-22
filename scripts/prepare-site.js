#!/usr/bin/env node
/**
 * Prepares site/ for publishing (run by Netlify, see netlify.toml).
 *
 * Copies dist/amnesicwallet.html next to the presentation page, after
 * checking that its SHA-256 is the one in SHA256SUMS and the one printed on
 * site/index.html. If any of the three disagree, the deploy stops: the site
 * never offers a file different from the one it describes.
 * Uses only Node's standard library, so no dependency is installed.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const FILE = path.join(ROOT, 'dist', 'amnesicwallet.html');
const SUMS = path.join(ROOT, 'SHA256SUMS');
const PAGE = path.join(ROOT, 'site', 'index.html');
const OUT = path.join(ROOT, 'site', 'amnesicwallet.html');

function fail(msg) { console.error('DEPLOY STOPPED: ' + msg); process.exit(1); }

const actual = crypto.createHash('sha256').update(fs.readFileSync(FILE)).digest('hex');
const listed = (fs.readFileSync(SUMS, 'utf8').match(/^([0-9a-f]{64})\s+amnesicwallet\.html$/m) || [])[1];
const shown = (fs.readFileSync(PAGE, 'utf8').match(/<code class="hash" id="sha256">([0-9a-f]{64})<\/code>/) || [])[1];

if (!listed) fail('SHA256SUMS has no line for amnesicwallet.html');
if (!shown) fail('site/index.html does not show a hash');
if (actual !== listed) fail(`dist/amnesicwallet.html is ${actual}, SHA256SUMS says ${listed}`);
if (actual !== shown) fail(`dist/amnesicwallet.html is ${actual}, the page shows ${shown}`);

fs.copyFileSync(FILE, OUT);
console.log('site/ ready: amnesicwallet.html ' + actual);
