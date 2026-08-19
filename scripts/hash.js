#!/usr/bin/env node
/**
 * Prints and writes the SHA-256 of the built artifact to SHA256SUMS.
 * Run after `npm run build`.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const FILE = path.join(ROOT, 'dist', 'seedforge.html');
const OUT = path.join(ROOT, 'SHA256SUMS');

if (!fs.existsSync(FILE)) {
  console.error('dist/seedforge.html not found. Run `npm run build` first.');
  process.exit(1);
}

const buf = fs.readFileSync(FILE);
const hash = crypto.createHash('sha256').update(buf).digest('hex');
const line = `${hash}  seedforge.html\n`;

fs.writeFileSync(OUT, line);
console.log(line.trim());
console.log('Written to SHA256SUMS');
