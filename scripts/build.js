#!/usr/bin/env node
/**
 * Build script for AmnesicWallet.
 *
 *   1. Bundle src/app.js (+ core.js and every dependency) into a single
 *      minified IIFE with esbuild.
 *   2. Inline that bundle into src/index.html, producing a fully
 *      self-contained dist/amnesicwallet.html.
 *   3. Add a Content-Security-Policy that makes the browser refuse every
 *      request the page could make (fetch, images, frames, fonts…) and any
 *      script other than the one inlined here (identified by its SHA-256).
 *   4. Refuse to produce the file if it contains a network API, a source
 *      of non-cryptographic randomness, storage, dynamic code, or any URL.
 *      These are text checks: they catch the names as written, which is
 *      what honest code and bundled libraries contain.
 *
 * The output is deterministic given identical inputs and locked dependency
 * versions (package-lock.json), enabling reproducible-build verification.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const esbuild = require('esbuild');
const shared = require('./esbuild-options');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const DIST = path.join(ROOT, 'dist');

const ENTRY = path.join(SRC, 'app.js');
const INDEX = path.join(SRC, 'index.html');
const BUNDLE = path.join(DIST, 'bundle.min.js');
const OUTPUT = path.join(DIST, 'amnesicwallet.html');

/* Nothing on this list may appear in the published file. */
const FORBIDDEN = [
  ['fetch(', 'network request'], ['XMLHttpRequest', 'network request'], ['WebSocket', 'network connection'],
  ['EventSource', 'network connection'], ['sendBeacon', 'network beacon'], ['RTCPeerConnection', 'network connection'],
  ['importScripts', 'remote code'], ['eval(', 'dynamic code'], ['new Function', 'dynamic code'],
  ['Math.random', 'non-cryptographic randomness'],
  ['localStorage', 'persistent storage'], ['sessionStorage', 'persistent storage'],
  ['indexedDB', 'persistent storage'], ['document.cookie', 'persistent storage'],
];
/* The only URL allowed: the SVG namespace, which is a name, not an address. */
const ALLOWED_URLS = new Set(['http://www.w3.org/2000/svg']);

function fail(msg) {
  console.error('BUILD FAILED: ' + msg);
  process.exit(1);
}

async function main() {
  if (!fs.existsSync(ENTRY)) fail('missing ' + ENTRY);
  if (!fs.existsSync(INDEX)) fail('missing ' + INDEX);
  fs.mkdirSync(DIST, { recursive: true });

  await esbuild.build({ ...shared, entryPoints: [ENTRY], outfile: BUNDLE, format: 'iife', minify: true });

  const html = fs.readFileSync(INDEX, 'utf-8');
  let js = fs.readFileSync(BUNDLE, 'utf-8').replace(/\n$/, '');

  // Escape </script> and </html> inside the bundle. The replacement inserts
  // the two characters \/ so the HTML parser does not close the inline script
  // early, while the JavaScript string keeps its value: "<\/html>" === "</html>".
  // (Four backslashes here would leave a real backslash in the runtime string,
  // and printed documents would show "<\/html>".)
  js = js.replace(/<\/script>/gi, '<\\/script>');
  js = js.replace(/<\/html>/gi, '<\\/html>');

  for (const [needle, what] of FORBIDDEN) {
    if (js.includes(needle)) fail(`the bundle contains "${needle}" (${what})`);
  }
  for (const url of js.match(/https?:\/\/[^\s"'`)<>]+/g) || []) {
    if (!ALLOWED_URLS.has(url)) fail('the bundle contains a URL: ' + url);
  }

  const scriptHash = crypto.createHash('sha256').update(js, 'utf8').digest('base64');
  const csp = [
    "default-src 'none'",               // no fetch, XHR, WebSocket, fonts, frames, workers…
    `script-src 'sha256-${scriptHash}'`, // only this exact script may run; no inline handlers
    "style-src 'unsafe-inline'",
    'img-src data:',                    // QR codes are drawn locally as data: images
    "base-uri 'none'",
    "form-action 'none'",
  ].join('; ');

  const placeholder = '<script src="./bundle.js"></script>';
  const cspPlaceholder = '<!-- CSP -->';
  if (!html.includes(placeholder)) fail('placeholder script tag not found in index.html');
  if (!html.includes(cspPlaceholder)) fail('CSP placeholder not found in index.html');

  const result = html
    .replace(cspPlaceholder, () => `<meta http-equiv="Content-Security-Policy" content="${csp}">`)
    .replace(placeholder, () => '<script>' + js + '</script>');

  // The whole page, not only the script, must be free of addresses.
  for (const url of result.match(/https?:\/\/[^\s"'`)<>]+/g) || []) {
    if (!ALLOWED_URLS.has(url)) fail('the page contains a URL: ' + url);
  }

  fs.writeFileSync(OUTPUT, result);

  // Self-checks: fail the build if the artifact is broken
  let scriptClose = 0, pos = 0;
  while ((pos = result.indexOf('</script>', pos)) !== -1) { scriptClose++; pos += 9; }
  if (scriptClose !== 1) fail('expected exactly one </script>, found ' + scriptClose);
  if (result.includes('bundle.js')) fail('external bundle.js reference leaked into output');
  if (!result.trimStart().startsWith('<!DOCTYPE')) fail('output does not start with <!DOCTYPE');
  const inlined = result.slice(result.indexOf('<script>') + 8, result.indexOf('</script>'));
  if (crypto.createHash('sha256').update(inlined, 'utf8').digest('base64') !== scriptHash) fail('CSP hash does not match the inlined script');
  if (result.indexOf('Content-Security-Policy') > result.indexOf('<script>')) fail('CSP must precede the script');

  const kb = Math.round(result.length / 1024);
  console.log('Built: dist/amnesicwallet.html (' + kb + ' KB)');
  console.log('Self-checks passed: CSP with script hash, no network API, no URL, single </script>, DOCTYPE first.');
}

main().catch((e) => fail(e && e.message ? e.message : String(e)));
