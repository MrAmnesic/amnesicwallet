#!/usr/bin/env node
/**
 * Runs tests/core.test.js against the real application core.
 *
 * The test file is bundled with exactly the esbuild options used for the
 * published page (scripts/esbuild-options.js) — including the adapters that
 * let the slip39 library run in a browser — and then executed with Node.
 * What is tested is therefore what ships.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');
const esbuild = require('esbuild');
const shared = require('./esbuild-options');

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amnesicwallet-test-'));
  const out = path.join(dir, 'core.test.mjs');
  try {
    await esbuild.build({
      ...shared,
      entryPoints: [path.join(__dirname, '..', 'tests', 'core.test.js')],
      outfile: out,
      format: 'esm',
      logLevel: 'warning',
    });
    await import(pathToFileURL(out).href);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
