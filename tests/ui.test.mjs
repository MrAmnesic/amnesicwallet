#!/usr/bin/env node
/**
 * Interface test: opens the published file, dist/amnesicwallet.html, in a
 * real browser and uses it the way a person would, on a computer and on
 * phones.
 *
 * For each screen size it checks that:
 *   - the page loads with no error and asks the network for nothing;
 *   - a wallet can be created from start to finish: passphrase choice,
 *     random typing, drawing, backup choice, the words, the backup check,
 *     the addresses on all four networks;
 *   - the words shown are a valid BIP-39 seed and the Bitcoin and Ethereum
 *     addresses shown are the ones that seed gives (recomputed here, outside
 *     the page);
 *   - "Check wallet" shows, for known seeds, the addresses computed
 *     independently with bip_utils / embit (tests/vectors/addresses.json);
 *   - no screen is wider than the display (nothing to scroll sideways).
 *
 * On a phone the test types as an on-screen keyboard does (text arrives
 * without key codes) and draws with a finger (touch events).
 *
 * Browser: Chromium from Playwright (`npx playwright install chromium`).
 * Another Chromium can be named with CHROMIUM_PATH.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { validateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { bech32 } from '@scure/base';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILE = path.join(ROOT, 'dist', 'amnesicwallet.html');
const URL = pathToFileURL(FILE).href;
const VECTORS = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'vectors', 'addresses.json'), 'utf8'));

const DEVICES = [
  { name: 'Computer (1366 × 768)', viewport: { width: 1366, height: 768 }, touch: false },
  { name: 'Phone (390 × 844)', viewport: { width: 390, height: 844 }, touch: true, scale: 3 },
  { name: 'Small phone (320 × 640)', viewport: { width: 320, height: 640 }, touch: true, scale: 2 },
];

/* ── Reference derivation, independent of the page ── */
function btcNativeAddress(seed) {
  const key = HDKey.fromMasterSeed(seed).derive("m/84'/0'/0'/0/0");
  const words = bech32.toWords(ripemd160(sha256(key.publicKey)));
  return bech32.encode('bc', [0, ...words]);
}
function ethAddress(seed) {
  const key = HDKey.fromMasterSeed(seed).derive("m/44'/60'/0'/0/0");
  const pub = secp256k1.getPublicKey(key.privateKey, false).slice(1);
  const hex = Buffer.from(keccak_256(pub).slice(-20)).toString('hex');
  const sum = Buffer.from(keccak_256(new TextEncoder().encode(hex))).toString('hex');
  return '0x' + [...hex].map((c, i) => (parseInt(sum[i], 16) >= 8 ? c.toUpperCase() : c)).join('');
}

/* ── Reporting ── */
let passed = 0, failed = 0;
let step = '';   // named in the report if the run stops
function check(cond, label) {
  if (cond) { passed++; console.log('  ✓ ' + label); }
  else { failed++; console.log('  ✗ ' + label); }
}

/* ── Actions that behave like the device ── */
function actions(page, device) {
  const press = (locator) => (device.touch ? locator.tap() : locator.click());
  return {
    press,
    async pressText(text) { await press(page.getByText(text, { exact: false }).first()); },

    // Random typing until the page moves on (it needs 20 keys, 10 distinct,
    // over at least 5 seconds).
    async typeRandomly() {
      const field = page.locator('#type-inp');
      await field.waitFor();
      const keys = 'qwertyuiopasdfghjklzxcvbnm1234567890';
      for (let i = 0; i < 200 && (await field.count()); i++) {
        const k = keys[(i * 7) % keys.length];
        // A phone's on-screen keyboard delivers text without key codes.
        if (device.touch) await page.keyboard.insertText(k);
        else await page.keyboard.press(k);
        await page.waitForTimeout(300);
      }
    },

    // Drawing inside the box until the page moves on (8 seconds, 100 moves,
    // 1000 px and 8 changes of direction).
    async draw() {
      const area = page.locator('#mouse-area');
      await area.waitFor();
      const box = await area.boundingBox();
      const cdp = device.touch ? await page.context().newCDPSession(page) : null;
      const point = (i) => ({
        x: Math.round(box.x + box.width * (0.5 + 0.4 * Math.sin(i / 3))),
        y: Math.round(box.y + box.height * (0.5 + 0.4 * Math.sin(i / 5))),
      });
      if (cdp) await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [point(0)] });
      else { await page.mouse.move(point(0).x, point(0).y); }
      for (let i = 1; i < 400 && (await area.count()); i++) {
        const p = point(i);
        if (cdp) await cdp.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [p] });
        else await page.mouse.move(p.x, p.y);
        await page.waitForTimeout(40);
      }
      if (cdp) await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] }).catch(() => {});
    },
  };
}

async function noSidewaysScroll(page) {
  return page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1);
}

/* ── One full run on one device ── */
async function run(browser, device) {
  console.log(`\n${device.name}`);
  const context = await browser.newContext({
    viewport: device.viewport,
    deviceScaleFactor: device.scale || 1,
    isMobile: device.touch,
    hasTouch: device.touch,
  });
  const page = await context.newPage();
  const errors = [];
  const requests = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('request', (r) => { if (!/^(file|data|blob):/.test(r.url())) requests.push(r.url()); });
  const { press, pressText, typeRandomly, draw } = actions(page, device);
  const layout = [];
  const noteLayout = async (screen) => { if (!(await noSidewaysScroll(page))) layout.push(screen); };

  step = 'opening the page';
  await page.goto(URL);
  await page.locator('#gen-classic').waitFor();
  check(true, 'the page opens');
  await noteLayout('start');

  /* 1. Create a wallet */
  step = 'choosing a personal wallet';
  await press(page.locator('#gen-classic'));
  await page.locator('#btn-generate').waitFor();
  await noteLayout('wallet settings');
  await press(page.locator('#btn-generate'));
  await press(page.locator('#pp-no'));
  await noteLayout('typing');
  step = 'typing at random';
  await typeRandomly();
  await noteLayout('drawing');
  step = 'drawing in the box';
  await draw();
  const single = page.locator('#bk-classic');
  await single.waitFor({ timeout: 15000 });
  check(true, 'typing and drawing lead to the new wallet');
  await noteLayout('backup choice');
  await press(single);
  step = 'showing the words';

  await press(page.locator('#btn-reveal-seed'));
  const words = (await page.locator('#seed-masked .word-slot').allInnerTexts())
    .map((t) => t.replace(/^\d+\s*/, '').trim());
  const mnemonic = words.join(' ');
  check(words.length === 12, 'the seed shows 12 words');
  check(validateMnemonic(mnemonic, wordlist), 'the words form a valid BIP-39 seed');
  await noteLayout('the words');

  step = 'checking the backup';
  await press(page.locator('#btn-verify-backup'));
  await page.locator('#vrf-all').fill(mnemonic);
  await press(page.locator('#vrf-check'));
  check((await page.locator('#vrf-result').innerText()).includes('Backup confirmed'), 'the backup check accepts the right words');
  const wrong = [...words]; wrong[4] = wrong[4] === 'zoo' ? 'abandon' : 'zoo';
  await page.locator('#vrf-all').fill(wrong.join(' '));
  await press(page.locator('#vrf-check'));
  check((await page.locator('#vrf-result').innerText()).includes('does not match'), 'the backup check spots a wrong word');
  await press(page.locator('#vrf-skip'));

  step = 'calculating the addresses';
  await press(page.locator('#btn-select-all'));
  await press(page.locator('#btn-derive'));
  await page.locator('#results-card .addr-value').nth(3).waitFor();
  const shown = await page.locator('#results-card .addr-value').allInnerTexts();
  check(shown.length === 4, 'addresses on all four networks');
  const seed = mnemonicToSeedSync(mnemonic, '');
  check(shown[0] === btcNativeAddress(seed), 'the Bitcoin address is the one the seed gives');
  check(shown[1] === ethAddress(seed), 'the Ethereum address is the one the seed gives');
  await page.locator('#results-card .address-qr img').nth(3).waitFor();
  check(true, 'every address has its QR code');
  await noteLayout('addresses');

  /* 2. Check wallet, with seeds whose addresses were computed elsewhere */
  for (const v of [VECTORS.seeds[0], VECTORS.seeds[VECTORS.seeds.length - 1]]) {
    step = 'Check wallet';
    const label = `${v.mnemonic.split(' ').length} words${v.passphrase ? ' + passphrase' : ''}`;
    await press(page.locator('.tab[data-tab="check"]'));
    if (await page.locator('#ctrl-seed').count()) await press(page.locator('#ctrl-seed'));
    if (await page.locator('#vf-clear').count()) await press(page.locator('#vf-clear'));
    await page.locator('#vf-words').fill(v.mnemonic);
    await page.locator('#vf-pass').fill(v.passphrase);
    for (const id of ['eth', 'trx', 'sol']) {
      if (!(await page.locator('#vf-chk-' + id).isChecked())) await press(page.locator(`label:has(#vf-chk-${id})`));
    }
    await press(page.locator('#vf-go'));
    await page.locator('#vf-results .addr-value').nth(3).waitFor();
    const got = await page.locator('#vf-results .addr-value').allInnerTexts();
    const want = [v.btc.native[0], v.eth, v.trx, v.sol];
    check(JSON.stringify(got) === JSON.stringify(want), `Check wallet (${label}): the four addresses match the independent values`);
    await noteLayout('check wallet');
  }

  /* 3. The guide */
  step = 'opening the guide';
  await press(page.locator('.tab[data-tab="guide"]'));
  await noteLayout('guide');

  check(layout.length === 0, 'nothing wider than the screen' + (layout.length ? ` (too wide: ${layout.join(', ')})` : ''));
  check(errors.length === 0, 'no error in the page' + (errors.length ? `: ${errors.join(' | ')}` : ''));
  check(requests.length === 0, 'no network request' + (requests.length ? `: ${requests.join(', ')}` : ''));
  await context.close();
}

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
try {
  for (const device of DEVICES) {
    try { await run(browser, device); }
    catch (e) { failed++; console.log(`  ✗ stopped while ${step}: ` + e.message.split('\n')[0]); }
  }
} finally {
  await browser.close();
}
console.log(`\n${passed} checks passed, ${failed} failed.`);
process.exit(failed ? 1 : 0);
