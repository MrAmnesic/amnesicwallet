#!/usr/bin/env node
/**
 * Build script for SeedForge.
 *
 * Steps:
 *   1. Bundle src/app.js (+ all dependencies) into a single minified IIFE
 *      using esbuild.
 *   2. Inline that bundle into src/index.html, producing a fully
 *      self-contained dist/seedforge.html with zero runtime dependencies.
 *
 * The output is deterministic given identical inputs and locked dependency
 * versions (see package-lock.json), enabling reproducible-build verification.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const DIST = path.join(ROOT, 'dist');

const ENTRY = path.join(SRC, 'app.js');
const INDEX = path.join(SRC, 'index.html');
const BUNDLE = path.join(DIST, 'bundle.min.js');
const OUTPUT = path.join(DIST, 'seedforge.html');

function fail(msg) {
  console.error('BUILD FAILED: ' + msg);
  process.exit(1);
}

async function main() {
  if (!fs.existsSync(ENTRY)) fail('missing ' + ENTRY);
  if (!fs.existsSync(INDEX)) fail('missing ' + INDEX);
  fs.mkdirSync(DIST, { recursive: true });

  // 1. Bundle
  await esbuild.build({
    entryPoints: [ENTRY],
    bundle: true,
    outfile: BUNDLE,
    format: 'iife',
    platform: 'browser',
    target: 'es2020',
    minify: true,
    define: { 'process.env.NODE_ENV': '"production"' },
    legalComments: 'none',
    // slip39 is written for Node: its 'crypto' is redirected to our browser
    // adapter, which exposes only the three functions actually used.
    alias: { crypto: path.join(__dirname, '..', 'src', 'crypto-shim.js') },
    // slip39 also uses Buffer, another Node global missing in the browser
    inject: [path.join(__dirname, '..', 'src', 'buffer-shim.js')],
  });

  const html = fs.readFileSync(INDEX, 'utf-8');
  let js = fs.readFileSync(BUNDLE, 'utf-8');

  // 2. Escape </script> and </html> literals inside the JS bundle.
  //    The replacement inserts the two characters \/ so the HTML parser does
  //    not close the inline script early, while the JavaScript string keeps
  //    its original value: "<\/html>" and "</html>" are the same string.
  //    (Using four backslashes here would leave a real backslash in the
  //    runtime string, and printed documents would show "<\/html>".)
  js = js.replace(/<\/script>/gi, '<\\/script>');
  js = js.replace(/<\/html>/gi, '<\\/html>');

  // 3. Inline via FUNCTION replacement (neutralizes $&, $`, $' patterns)
  const placeholder = '<script src="./bundle.js"></script>';
  if (!html.includes(placeholder)) fail('placeholder script tag not found in index.html');

  const result = html
    .replace(placeholder, () => '<script>' + js + '</script>')
    .replace(
      '<link rel="preconnect" href="https://fonts.googleapis.com">',
      '<!-- Offline: system fallback fonts -->'
    )
    .replace(
      "@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');",
      '/* Offline: system fallback fonts */'
    )
    .replace(
      "--font-mono: 'JetBrains Mono', 'Courier New', monospace;",
      "--font-mono: 'JetBrains Mono', 'SF Mono', 'Fira Code', 'Cascadia Code', 'Courier New', monospace;"
    )
    .replace(
      "--font-sans: 'Space Grotesk', system-ui, sans-serif;",
      "--font-sans: 'Space Grotesk', -apple-system, 'Segoe UI', system-ui, sans-serif;"
    );

  fs.writeFileSync(OUTPUT, result);

  // 4. Self-checks: fail the build if the artifact is broken
  let scriptClose = 0, pos = 0;
  while ((pos = result.indexOf('</script>', pos)) !== -1) { scriptClose++; pos += 9; }
  if (scriptClose !== 1) fail('expected exactly one </script>, found ' + scriptClose);
  if (result.includes('bundle.js')) fail('external bundle.js reference leaked into output');
  if (!result.trimStart().startsWith('<!DOCTYPE')) fail('output does not start with <!DOCTYPE');

  const kb = Math.round(result.length / 1024);
  console.log('Built: dist/seedforge.html (' + kb + ' KB)');
  console.log('Self-checks passed: single </script>, no leaked reference, DOCTYPE first.');
}

main().catch((e) => fail(e && e.message ? e.message : String(e)));
