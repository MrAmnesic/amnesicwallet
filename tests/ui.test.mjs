#!/usr/bin/env node
/**
 * Interface test: opens the published file, dist/amnesicwallet.html, in
 * real browsers and uses it the way a person would, on a computer and on
 * phones.
 *
 * It runs in the three browser engines:
 *   - Chromium: Chrome, Edge, Brave, most Android browsers;
 *   - Firefox:  Firefox, and Tor Browser (the browser of Tails);
 *   - WebKit:   Safari, and the browsers on an iPhone.
 *
 * For each browser and screen size it checks that:
 *   - the page loads with no error and asks the network for nothing;
 *   - a wallet can be created from start to finish: passphrase choice,
 *     random typing, drawing, backup choice, the words, the backup check,
 *     the addresses on all four networks;
 *   - the words shown are a valid BIP-39 seed and the Bitcoin and Ethereum
 *     addresses shown are the ones that seed gives (recomputed here, outside
 *     the page);
 *   - "Check wallet" shows, for known seeds, the addresses computed
 *     independently with bip_utils / embit (tests/vectors/addresses.json);
 *   - a mistyped word is named with its position and the right word is
 *     offered; account 2, change addresses, all derivation paths, a path
 *     typed by hand and the check with a public key (zpub, and an Ethereum
 *     account key) give the values in tests/vectors/paths.json;
 *   - no screen is wider than the display (nothing to scroll sideways).
 *
 * On a phone the test taps, and types as an on-screen keyboard does (text
 * arrives without key codes). Chromium also draws with a finger (touch
 * events); Playwright cannot move a finger in WebKit, so there the drawing
 * is done with the pointer. Playwright cannot emulate a phone in Firefox:
 * there the phone sizes are narrow windows, used with mouse and keyboard.
 *
 * Browsers: Playwright's (`npx playwright install chromium firefox webkit`).
 * BROWSERS=chromium,firefox limits the run to some of them; another
 * Chromium can be named with CHROMIUM_PATH.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium, firefox, webkit } from 'playwright';
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
const PATHS = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'vectors', 'paths.json'), 'utf8'));

const BROWSERS = {
  chromium: { name: 'Chromium', type: chromium, phone: 'finger' },
  firefox: { name: 'Firefox', type: firefox, phone: 'window' },
  webkit: { name: 'WebKit', type: webkit, phone: 'tap' },
};

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
function actions(page, input) {
  const press = (locator) => (input.touch ? locator.tap() : locator.click());
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
        if (input.touch) await page.keyboard.insertText(k);
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
      const cdp = input.finger ? await page.context().newCDPSession(page) : null;
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
async function run(browser, engine, device) {
  const input = {
    touch: device.touch && engine.phone !== 'window',
    finger: device.touch && engine.phone === 'finger',
  };
  console.log(`\n${engine.name} — ${device.name}` + (device.touch && !input.touch ? ', window only' : ''));
  const context = await browser.newContext({
    viewport: device.viewport,
    deviceScaleFactor: device.scale || 1,
    ...(input.touch ? { isMobile: true, hasTouch: true } : {}),
  });
  const page = await context.newPage();
  const errors = [];
  const requests = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('request', (r) => { if (!/^(file|data|blob):/.test(r.url())) requests.push(r.url()); });
  const { press, pressText, typeRandomly, draw } = actions(page, input);
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

  /* 2b. A mistyped word, other accounts, change, every path */
  {
    const v = PATHS.seeds[1];
    const at = (chain, tpl, account) => v.paths.find(r => r.chain === chain && r.template === tpl && r.account === account);
    step = 'Check wallet: a mistyped word';
    await press(page.locator('.tab[data-tab="check"]'));
    if (await page.locator('#vf-clear').count()) await press(page.locator('#vf-clear'));
    const words = v.mnemonic.split(' ');
    const typo = [...words]; typo[2] = words[2].slice(0, -1) + words[2].slice(-1).repeat(2);   // one letter doubled
    await page.locator('#vf-words').fill(typo.join(' '));
    await page.locator('#vf-pass').fill(v.passphrase);
    for (const id of ['eth', 'trx', 'sol']) {
      if (!(await page.locator('#vf-chk-' + id).isChecked())) await press(page.locator(`label:has(#vf-chk-${id})`));
    }
    await press(page.locator('#vf-go'));
    const diag = await page.locator('#vf-err').innerText();
    check(diag.includes('Word 3') && diag.includes(typo[2]), 'a mistyped word is named with its position');
    const fix = page.locator(`.vf-sugg[data-pos="3"][data-word="${words[2]}"]`);
    check(await fix.count() === 1, 'the right word is offered');
    await press(fix);
    check((await page.locator('#vf-words').inputValue()) === v.mnemonic, 'choosing it corrects the words');
    await press(page.locator('#vf-go'));
    await page.locator('#vf-results .addr-value').nth(3).waitFor();

    step = 'Check wallet: account 2';
    await press(page.locator('#vf-acct-next'));
    check((await page.locator('#vf-acct-num').innerText()) === '2', 'account 2 selected');
    const acct2 = await page.locator('#vf-results .addr-value').allInnerTexts();
    const want2 = [at('btc', "m/84'/0'/{n}'/0/0", 1).addresses.native, at('eth', "m/44'/60'/0'/0/{n}", 1).address,
      at('trx', "m/44'/195'/0'/0/{n}", 1).address, at('sol', "m/44'/501'/{n}'/0'", 1).address];
    check(JSON.stringify(acct2) === JSON.stringify(want2), 'account 2: the four addresses match the independent values');
    const paths = await page.locator('#vf-results .address-item .path-value').allInnerTexts();
    check(paths.includes("m/84'/0'/1'/0/0") && paths.includes("m/44'/501'/1'/0'"), 'the derivation paths are shown');

    step = 'Check wallet: change addresses';
    await press(page.locator('#vf-more'));
    await press(page.locator('#vf-branch .seg-btn[data-c="1"]'));
    const change = await page.locator('.btc-more .more-addr').first().innerText();
    check(change.startsWith(v.change['native/1/1'][0]), 'account 2, first change address');

    step = 'Check wallet: all derivation paths';
    await press(page.locator('#vf-paths summary'));
    await page.locator('#vf-cpath').waitFor();
    const body = await page.locator('#vf-paths-body').innerText();
    check(body.includes(at('btc', "m/44'/60'/0'/0/{n}", 1).addresses.native), "Bitcoin on Ethereum's path is listed");
    check(body.includes(at('eth', "m/44'/60'/{n}'/0/0", 1).address), 'the Ledger Live path is listed');
    check(body.includes(at('sol', "m/44'/501'/{n}'", 1).address), "Solana's other path is listed");
    await page.locator('#vf-cchain').selectOption('eth');
    await page.locator('#vf-cpath').fill("m/44h/60h/4h/0/0");
    await press(page.locator('#vf-cgo'));
    check((await page.locator('#vf-cout').innerText()).includes(at('eth', "m/44'/60'/{n}'/0/0", 4).address), 'a path typed by hand');
    await noteLayout('all derivation paths');
    await press(page.locator('#vf-clear'));
  }

  /* 2c. Check with a public key only */
  {
    step = 'Check with a public key';
    await press(page.locator('#vf-back'));
    await press(page.locator('#ctrl-xpub'));
    const z = PATHS.xpubs.find(k => k.key.startsWith('zpub'));
    await page.locator('#xp-key').fill(z.key);
    await press(page.locator('#xp-go'));
    await page.locator('#xp-results .more-addr').nth(2).waitFor();
    const rec = (await page.locator('#xp-results .more-addr').allInnerTexts()).slice(0, 3).map(t => t.split('\n')[0]);
    check(JSON.stringify(rec) === JSON.stringify(z.receive.native), 'zpub: the receiving addresses match');
    await press(page.locator('#xp-branch .seg-btn[data-c="1"]'));
    check((await page.locator('#xp-results .more-addr').first().innerText()).startsWith(z.change.native[0]), 'zpub: the change addresses match');
    check((await page.locator('#xp-results').innerText()).includes(z.descriptor.native), 'zpub: the descriptor matches');
    const e = PATHS.xpubs.find(k => k.path === "m/44'/60'/0'");
    await page.locator('#xp-key').fill(e.key);
    await press(page.locator('#xp-go'));
    await press(page.locator('#xp-as .seg-btn[data-as="eth"]'));
    const eth = (await page.locator('#xp-results .more-addr').allInnerTexts()).slice(0, 3).map(t => t.split('\n')[0]);
    check(JSON.stringify(eth) === JSON.stringify(e.eth), 'Ethereum account key: the addresses match');
    await noteLayout('check with a public key');
    await page.locator('#xp-key').fill('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
    await press(page.locator('#xp-go'));
    check((await page.locator('#xp-err').innerText()).includes('private'), 'a private key is refused');
    check(await page.locator('#xp-results .more-addr').count() === 0, 'and no address is shown for it');
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

const wanted = (process.env.BROWSERS || Object.keys(BROWSERS).join(',')).split(',').map((b) => b.trim()).filter(Boolean);
const unknown = wanted.filter((b) => !BROWSERS[b]);
if (!wanted.length || unknown.length) {
  console.error(`BROWSERS: unknown ${unknown.join(', ') || '(empty)'}; use chromium, firefox, webkit.`);
  process.exit(1);
}

for (const id of wanted) {
  const engine = BROWSERS[id];
  let browser;
  try {
    browser = await engine.type.launch(id === 'chromium' && process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  } catch (e) {
    failed++;
    console.log(`\n${engine.name}\n  ✗ cannot start: ${e.message.split('\n')[0]}`);
    console.log(`    Install it with \`npx playwright install ${id}\`, or leave it out with BROWSERS=…`);
    continue;
  }
  try {
    for (const device of DEVICES) {
      try { await run(browser, engine, device); }
      catch (e) { failed++; console.log(`  ✗ stopped while ${step}: ` + e.message.split('\n')[0]); }
    }
  } finally {
    await browser.close();
  }
}
console.log(`\n${passed} checks passed, ${failed} failed.`);
process.exit(failed ? 1 : 0);
