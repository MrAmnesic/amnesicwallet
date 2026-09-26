#!/usr/bin/env node
/**
 * Renders docs/TECHNICAL.md into docs/Technical-Documentation.pdf.
 *
 * The Markdown is turned into HTML with `marked`, styled below, and printed
 * to A4 by Chromium (Playwright), with the version and page numbers in the
 * footer. Run with `npm run pdf` after editing TECHNICAL.md.
 * Another Chromium can be named with CHROMIUM_PATH.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { marked } from 'marked';
import { chromium } from 'playwright';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'docs', 'TECHNICAL.md');
const OUT = path.join(ROOT, 'docs', 'Technical-Documentation.pdf');
const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;

const md = fs.readFileSync(SRC, 'utf8');
const title = (md.match(/^# (.+)$/m) || [])[1] || 'AmnesicWallet — Technical documentation';
const body = marked.parse(md, { gfm: true });

const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>
  body { font-family: "DejaVu Sans", "Segoe UI", Arial, sans-serif; font-size: 10pt; line-height: 1.5; color: #1f1f24; margin: 0; }
  h1 { font-size: 22pt; line-height: 1.2; margin: 0 0 10pt; }
  h1 + p strong { color: #c2570c; font-size: 11pt; }
  h2 { font-size: 14pt; margin: 18pt 0 8pt; padding-bottom: 4pt; border-bottom: 1.2pt solid #e07b15; break-after: avoid; }
  h3 { font-size: 11.5pt; margin: 14pt 0 5pt; break-after: avoid; }
  p { margin: 0 0 6pt; }
  a { color: #c2570c; text-decoration: none; }
  hr { border: 0; border-top: 0.8pt solid #e2e2e6; margin: 16pt 0; }
  code { font-family: "DejaVu Sans Mono", Consolas, monospace; font-size: 8.3pt; background: #f2f2f5; padding: 1pt 3pt; border-radius: 3pt; }
  pre { background: #f6f6f8; border: 0.6pt solid #e2e2e6; border-radius: 4pt; padding: 7pt 9pt; white-space: pre-wrap; break-inside: avoid; }
  pre code { background: none; padding: 0; }
  table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt; font-size: 9pt; break-inside: auto; }
  th, td { border: 0.6pt solid #d8d8de; padding: 3.5pt 6pt; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
  th { background: #f4f4f7; }
  tr { break-inside: avoid; }
  ul, ol { margin: 0 0 6pt; padding-left: 18pt; }
  li { margin: 2pt 0; }
</style></head><body>${body}</body></html>`;

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
try {
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'load' });
  await page.pdf({
    path: OUT,
    format: 'A4',
    margin: { top: '20mm', bottom: '20mm', left: '18mm', right: '18mm' },
    displayHeaderFooter: true,
    headerTemplate: '<div></div>',
    footerTemplate: `<div style="font-family: 'DejaVu Sans', Arial, sans-serif; font-size: 7pt; color: #555; width: 100%; padding: 0 12mm; display: flex; justify-content: space-between;">
      <span>AmnesicWallet ${version} — Technical documentation</span>
      <span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>`,
    printBackground: true,
  });
} finally {
  await browser.close();
}
console.log(`Written: ${path.relative(ROOT, OUT)} (from ${path.relative(ROOT, SRC)}, version ${version})`);
