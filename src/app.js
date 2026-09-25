/*
 * AmnesicWallet — offline BIP-39 wallet generator
 * Copyright (C) 2026 MrAmnesic
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Bundled third-party libraries (@noble/curves, @noble/hashes, @scure/base,
 * @scure/bip32, @scure/bip39, qrcode, slip39) are distributed under the MIT
 * licence; their notices are kept in the source tree.
 *
 * This file is the user interface. All the cryptography is in core.js.
 */

import {
  WORD_OPTIONS, ENT_BYTES, CHAINS, BTC_FORMATS, METAL_COLS,
  isSecureRandomAvailable, combineEntropy, createMouseCollector, createTypingCollector,
  diceRollsNeeded, diceBytesFrom, shamirSplit, shamirCombine, verificationCode, classicSplit,
  deriveAll, deriveBTC, deriveBTCMany, btcAccountInfo, btcPath, deriveMultisigXpub, multisigAddress, KeyError,
  slip39Create, slip39Recover, isSlip39Passphrase, metalRows, normalizeWords,
  entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic, wordlist, HDKey,
} from './core.js';
import QRCode from 'qrcode';

const SECURE_RANDOM_OK = isSecureRandomAvailable();

/* ════════════════════════════════════════════════════════════════
   UI UTILITIES (unchanged since v1)
   ════════════════════════════════════════════════════════════════ */
const SLIP39_PASS_MSG = 'A SLIP-39 passphrase can only contain ordinary keyboard characters: letters without accents, digits, spaces and the usual symbols. This is a rule of the SLIP-39 standard, shared by Trezor and every other program that reads it.';

/* Plain-language explanation for a rejected multisig key. With `plain`
   the same sentence comes back without markup, for places that show
   text only (the toast): no tag is ever stripped with a regular
   expression, it is simply never added. */
function keyErrorMessage(err, labels, plain = false) {
  const b = (t) => (plain ? t : `<strong>${t}</strong>`);
  const who = (err && Number.isInteger(err.index) && labels && labels[err.index]) ? labels[err.index] : 'One of the keys';
  switch (err && err.code) {
    case 'PRIVATE':     return `⛔ ${who} is a ${b('private')} key (xprv). Never paste or share it: it gives full control of the funds. Each participant must share only their ${b('xpub')}.`;
    case 'TESTNET':     return `${who} belongs to the Bitcoin ${b('test')} network, not to the real one.`;
    case 'SCRIPT_TYPE': return `${who} is labelled for a different kind of wallet (ypub, zpub or Ypub). For a native-SegWit multisig vault it must be an ${b('xpub')} or a ${b('Zpub')}, derived at m/48'/0'/0'/2'.`;
    case 'DUPLICATE':   return `${who} appears twice. Every participant must bring a different key — otherwise the vault needs fewer people than it seems.`;
    case 'TOO_MANY':    return 'A vault can have at most 15 keys.';
    case 'TOO_FEW':     return 'At least two keys are needed.';
    case 'THRESHOLD':   return 'The required signatures cannot exceed the number of keys.';
    default:            return `${who} is not valid: check that it was pasted in full, without spaces or broken lines.`;
  }
}

/* Options 1…n for a "signatures required" menu. */
function thresholdOptions(n, selected) {
  const max = Math.max(2, Math.min(15, n));
  const sel = Math.min(selected, max);
  return Array.from({ length: max }, (_, i) => i + 1)
    .map(v => `<option value="${v}" ${v === sel ? 'selected' : ''}>${v}</option>`).join('');
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
/* Short texts (addresses) get the strongest error correction; long ones
   (xpubs, descriptors) a lighter one, so the modules stay large enough for a
   phone camera to read. */
async function generateQR(text, size) {
  const level = text.length <= 90 ? 'H' : text.length <= 200 ? 'M' : 'L';
  return await QRCode.toDataURL(text, { width: size || 200, margin: 2, color: { dark: '#000000', light: '#ffffff' }, errorCorrectionLevel: level });
}
async function copyToClipboard(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) { await navigator.clipboard.writeText(text); return; }
  } catch (_) {}
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try {
    const ok = document.execCommand('copy');
    if (!ok) throw new Error('execCommand false');
  } catch (e) { document.body.removeChild(ta); throw new Error('Copy failed'); }
  document.body.removeChild(ta);
}
function showToast(msg, type) {
  document.querySelectorAll('.toast').forEach(t => t.remove());
  const toast = document.createElement('div');
  toast.className = 'toast toast-' + (type || 'info');
  toast.textContent = msg;
  document.body.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('toast-show'));
  setTimeout(() => { toast.classList.remove('toast-show'); setTimeout(() => toast.remove(), 300); }, 2600);
}
const printWindows = [];            // closed when the user removes everything from the page
function printHTML(html) {
  const doc = html.replace(/^\s+/, '');
  const win = window.open('', '_blank');
  if (win) {
    printWindows.push(win);
    win.document.write(doc); win.document.close(); win.focus();
    setTimeout(() => win.print(), 500);
    return;
  }
  const iframe = document.createElement('iframe');
  iframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:0;height:0;border:none';
  document.body.appendChild(iframe);
  const idoc = iframe.contentDocument || iframe.contentWindow.document;
  idoc.open(); idoc.write(doc); idoc.close();
  setTimeout(() => {
    iframe.contentWindow.focus(); iframe.contentWindow.print();
    setTimeout(() => document.body.removeChild(iframe), 1000);
  }, 500);
}

/* ════════════════════════════════════════════════════════════════
   APPLICATION STATE
   ════════════════════════════════════════════════════════════════ */
let currentTheme = 'light';       // 'dark' | 'light' — never persisted to disk
let activeTab = 'generate';           // generate | check | guide
let genPath = null;                 // null | 'classic' | 'multisig'
let ctrlPath = null;
let shamirMode = null;              // null | 'restore' | 'convert'
let currentMnemonic = null;
let currentSeed = null;
let currentEntropy = null;
let generatedAddresses = {};
let btcFormat = 'native';
let entropyMode = 'classic';       // 'classic' | 'dice' — kept in state, not only as a CSS class
let seedStandard = 'bip39';        // 'bip39' | 'slip39'
let slipConfig = null;             // {n, m} for SLIP-39
let slipShares = null;             // the generated shares
let slipRevealed = [];
let slipSecret = null;             // master secret (raw bytes)
let btcExtra = null;      // extra BTC addresses on screen
let btcAccount = null;    // xpub + descriptor for watch-only
let vfSeed = null;        // seed of the Check tab (isolated from the main wallet)
let vfMnemonic = null;
let vfResults = null;
let csResults = null;     // addresses recovered from SLIP-39 sheets (Check tab), kept apart from vf*
let vfFormat = 'native';
let vfExtra = null;
let vfAccount = null;
let pendingConfig = null;            // {words, passphrase, useDice, twoDice}
let pendingDice = null;              // {rolls:[], needed, twoDice, first}
let mouseCollector = null;
let typingCollector = null;
let entropyPurpose = 'wallet';       // wallet | multisig
let msMyXpub = null;                 // xpub of multisig section A
let msMode = null;                   // null | 'solo' | 'group'
let msSoloConfig = null;             // {n, m}
let msSoloSeeds = null;              // mnemonics of the created keys
let msSoloIndex = 0;
let msSoloRevealed = [];             // which keys are revealed on screen
let msSoloVault = null;              // {address, descriptor, n, m}
let shamirParts = null;              // generated parts, shown together
let shamirRevealed = [];
let seedUnlocked = false;
let guideView = 'guide';            // 'guide' | 'faq'
let shamirMeta = null;               // {n, m, code}


/* ════════════════════════════════════════════════════════════════
   SHELL: header, tabs, router
   ════════════════════════════════════════════════════════════════ */
function renderApp() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="container">
      <header class="app-header">
        <button class="theme-btn" id="theme-toggle" title="Change theme">${currentTheme === 'light' ? '🌙' : '☀️'}</button>
        <div class="logo-area logo-clickable" id="go-home" title="Back to the start">
          <div class="logo-icon">
            <svg viewBox="0 0 40 40" width="40" height="40">
              <rect x="2" y="2" width="36" height="36" rx="8" fill="none" stroke="currentColor" stroke-width="2.5"/>
              <path d="M12 14h16M12 20h16M12 26h10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
              <circle cx="28" cy="26" r="3" fill="currentColor"/>
            </svg>
          </div>
          <div>
            <h1>AMNESIC<span class="logo-accent">WALLET</span></h1>
            <p class="subtitle">Your wallet is born here. And stays yours alone.</p>
          </div>
        </div>
      </header>

      <nav class="tabs">
        <button class="tab ${activeTab === 'generate' ? 'tab-active' : ''}" data-tab="generate">✨ Generate wallet</button>
        <button class="tab ${activeTab === 'check' ? 'tab-active' : ''}" data-tab="check">🔍 Check wallet</button>
        <button class="tab ${activeTab === 'guide' ? 'tab-active' : ''}" data-tab="guide">📖 How it works</button>
      </nav>

      <main id="tab-content">
        ${activeTab === 'generate' ? renderGenerateTab() : ''}
        ${activeTab === 'check' ? renderCheckTab() : ''}
        ${activeTab === 'guide' ? renderGuideTab() : ''}
      </main>

      <footer><p>No connection. Nothing saved. No trace.<br>Everything happens here, on this device, and disappears when you close the page.</p>
        <p class="hint" style="margin-top:8px">AmnesicWallet — free software under the GNU GPL v3 or later, with absolutely no warranty.</p></footer>
    </div>
    <div id="overlay-root"></div>
  `;
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', currentTheme);
    document.getElementById('theme-toggle').innerHTML = currentTheme === 'light' ? '🌙' : '☀️';
  });
  document.getElementById('go-home')?.addEventListener('click', () => {
    activeTab = 'generate'; genPath = null; ctrlPath = null;
    shamirMode = null; msMode = null;
    renderApp();
  });
  wireHelp();
  wireTabs();
  if (activeTab === 'guide') wireGuide();
  if (activeTab === 'generate') {
    wireGenera();
    if (slipShares) wireSlipView();
    if (!currentMnemonic && genPath === 'multisig') wireMultisig();
  }
  if (activeTab === 'check') {
    wireCheck();
    if (ctrlPath === 'slip') wireCtrlSlip();
    if (ctrlPath === 'seed') wireVerify();
    if (ctrlPath === 'shamir') {
      if (shamirMode === 'restore') wireRecover();
      else if (shamirMode === 'convert') wireConvertShamir();
      else wireShamirChooser();
    }
    if (ctrlPath === 'multisig') wireCtrlMultisig();
  }
}

function wireTabs() {
  document.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => {
    activeTab = b.dataset.tab;
    renderApp();
  }));
}

/* ════════════════════════════════════════════════════════════════
   GENERATE TAB — configuration → entropy → seed → check → addresses
   ════════════════════════════════════════════════════════════════ */
function renderGenChooser() {
  return `
    <section>
      <div class="card hero-card">
        <h2>What would you like to create today?</h2>
        <p class="card-desc">Two paths, both guided step by step.</p>
        <div class="path-grid">
          <button class="path-card" id="gen-classic">
            <span class="path-icon">🪪</span>
            <span class="path-title">A personal wallet</span>
            <span class="path-desc">Your seed, your addresses on four networks. The right choice for most people.</span>
            <span class="path-cta">Start →</span>
          </button>
          <button class="path-card" id="gen-multisig">
            <span class="path-icon">🔐</span>
            <span class="path-title">A multisig vault</span>
            <span class="path-desc">Several keys to open it: the protection that holds even if one key is lost or stolen.</span>
            <span class="path-cta">Start →</span>
          </button>
        </div>
        <p class="hint" style="margin-top:16px">Already have a wallet and just want to check it? You'll find everything under <strong>🔍 Check wallet</strong>.</p>
      </div>
    </section>`;
}

function renderCheckTab() {
  if (ctrlPath === 'seed') return renderVerifyTab();
  if (ctrlPath === 'shamir') {
    if (shamirMode === 'restore') return renderRecoverTab();
    if (shamirMode === 'convert') return renderConvertShamir();
    return renderShamirChooser();
  }
  if (ctrlPath === 'slip') return renderCtrlSlip();
  if (ctrlPath === 'multisig') return renderCtrlMultisig();
  return `
    <section>
      <div class="card hero-card">
        <h2>Check a wallet you already own</h2>
        <p class="card-desc">Choose what you're starting from: everything happens here, without ever transmitting anything.</p>
        <div class="path-grid path-grid-3">
          <button class="path-card" id="ctrl-seed">
            <span class="path-icon">🌱</span>
            <span class="path-title">A complete seed</span>
            <span class="path-desc">You have your 12–24 words and want to see which addresses they generate, or confirm that a backup is correct.</span>
            <span class="path-cta">Check →</span>
          </button>
          <button class="path-card" id="ctrl-shamir">
            <span class="path-icon">🧩</span>
            <span class="path-title">Shamir backup</span>
            <span class="path-desc">Reassemble a backup split into parts, or turn a seed you already own into a threshold backup.</span>
            <span class="path-cta">Open →</span>
          </button>
          <button class="path-card" id="ctrl-slip">
            <span class="path-icon">📄</span>
            <span class="path-title">SLIP-39 sheets</span>
            <span class="path-desc">You have the 20-word sheets of a SLIP-39 backup — created here or by a Trezor — and want to see the addresses.</span>
            <span class="path-cta">Recover →</span>
          </button>
          <button class="path-card" id="ctrl-multisig">
            <span class="path-icon">🔐</span>
            <span class="path-title">A multisig vault</span>
            <span class="path-desc">You have the participants' xpubs and want to recalculate the address to confirm everything adds up.</span>
            <span class="path-cta">Recalculate →</span>
          </button>
        </div>
      </div>
    </section>`;
}

function wireCheck() {
  document.getElementById('ctrl-seed')?.addEventListener('click', () => { ctrlPath = 'seed'; renderApp(); });
  document.getElementById('ctrl-shamir')?.addEventListener('click', () => { ctrlPath = 'shamir'; shamirMode = null; renderApp(); });
  document.getElementById('ctrl-slip')?.addEventListener('click', () => { ctrlPath = 'slip'; renderApp(); });
  document.getElementById('ctrl-multisig')?.addEventListener('click', () => { ctrlPath = 'multisig'; renderApp(); });
}

/* ── Shamir backup section: two paths ── */
function renderShamirChooser() {
  return `
    <section>
      <div class="card hero-card">
        <h2>🧩 Shamir backup</h2>
        <p class="card-desc">The method that splits a seed into several parts, of which only some are needed to get it back. What would you like to do?</p>
        <div class="path-grid">
          <button class="path-card" id="sm-restore">
            <span class="path-icon">🔓</span>
            <span class="path-title">I have the parts, I want the seed</span>
            <span class="path-desc">Enter the parts you have — as many as the threshold required — and get back the original words of the wallet.</span>
            <span class="path-cta">Reassemble →</span>
          </button>
          <button class="path-card" id="sm-convert">
            <span class="path-icon">🔀</span>
            <span class="path-title">I have a seed, I want to split it</span>
            <span class="path-desc">Turn a seed you already own into a threshold backup. The wallet doesn't change: only the way you keep it changes.</span>
            <span class="path-cta">Split →</span>
          </button>
        </div>
        <div class="ov-row" style="margin-top:16px">
          <button class="btn btn-ghost btn-small" id="sm-back">← Back to choices</button>
        </div>
      </div>
    </section>`;
}

function wireShamirChooser() {
  document.getElementById('sm-restore')?.addEventListener('click', () => { shamirMode = 'restore'; renderApp(); });
  document.getElementById('sm-convert')?.addEventListener('click', () => { shamirMode = 'convert'; renderApp(); });
  document.getElementById('sm-back')?.addEventListener('click', () => { ctrlPath = null; shamirMode = null; renderApp(); });
}

/* ── Turn an existing seed into a threshold backup ── */
function renderConvertShamir() {
  return `
    <section>
      <div class="card">
        <div class="card-header"><span class="step-badge">🔀</span><h2>Split a seed you already own</h2></div>
        <p style="margin-bottom:12px">Works with any BIP-39 seed, even one created years ago with another program. The wallet stays exactly as it is: same addresses, same funds. Only the way you keep it changes.</p>

        <div class="ok-box" style="margin-bottom:14px">
          <strong>Why do it.</strong> A seed written on a single sheet is a single point of failure: whoever finds it takes everything. By splitting it, the same wallet becomes protected even against a burglary at home — without moving a single satoshi and without creating a new wallet.
        </div>

        <div class="warn-box" style="margin-bottom:16px">🛡️ You are about to type a seed that holds real funds: do it with the device disconnected from the network, or from a Tails system or a clean virtual machine.</div>

        <label class="config-label">The words of your seed
          <span class="hint">12, 15, 18, 21 or 24 words, separated by spaces.</span>
        </label>
        <textarea id="cv-words" class="inp" rows="3" placeholder="word1 word2 word3 …" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></textarea>

        <div class="note-box" style="margin-top:12px">
          <strong>Were you using a passphrase?</strong> There's no need to enter it here: the parts rebuild the <em>words</em>, and the passphrase remains a separate protection. Keep looking after it on its own, otherwise the wallet stays out of reach.
        </div>

        <div style="margin-top:18px">
          <button class="btn btn-primary btn-large" id="cv-go">Continue</button>
        </div>
        <p id="cv-err" style="margin-top:10px"></p>
        <div class="ov-row" style="margin-top:14px">
          <button class="btn btn-ghost btn-small" id="cv-back">← Back</button>
        </div>
      </div>
    </section>`;
}

function wireConvertShamir() {
  document.getElementById('cv-back')?.addEventListener('click', () => { shamirMode = null; renderApp(); });
  document.getElementById('cv-go')?.addEventListener('click', () => {
    const ta = document.getElementById('cv-words');
    const words = (ta.value || '').trim().toLowerCase().replace(/\s+/g, ' ');
    const err = document.getElementById('cv-err');
    if (!words) { err.innerHTML = '<span style="color:var(--danger)">Type the words of your seed.</span>'; return; }
    const n = words.split(' ').length;
    if (![12, 15, 18, 21, 24].includes(n)) {
      err.innerHTML = `<span style="color:var(--danger)">You typed ${n} words. A BIP-39 seed has 12, 15, 18, 21 or 24.</span>`;
      return;
    }
    if (!validateMnemonic(words, wordlist)) {
      err.innerHTML = '<span style="color:var(--danger)">These words do not form a valid seed. It is usually a typo or a similar but different word: check them one by one.</span>';
      return;
    }
    try {
      resetWalletState();
      currentMnemonic = words;
      currentEntropy = mnemonicToEntropy(words, wordlist);
      currentSeed = mnemonicToSeedSync(words, '');
      pendingConfig = { words: n, passphrase: '' };
      ta.value = '';
      activeTab = 'generate'; genPath = 'classic';
      ctrlPath = null; shamirMode = null;
      renderApp();
      showShamirIntro();
    } catch (e) { err.innerHTML = '<span style="color:var(--danger)">Error: ' + escapeHtml(e.message) + '</span>'; }
  });
}

/* ── Recovery from SLIP-39 sheets ── */
function renderCtrlSlip() {
  return `
    <section>
      <div class="card">
        <div class="card-header"><span class="step-badge">📄</span><h2>Recover from SLIP-39 sheets</h2></div>
        <p style="margin-bottom:12px">Enter the <strong>20-word</strong> sheets of a SLIP-39 backup, one per box. You need as many as the threshold required. It also works with sheets generated by a <strong>Trezor</strong>.</p>

        <div class="ok-box" style="margin-bottom:14px">
          <strong>How to recognise them.</strong> SLIP-39 sheets have 20 (or 33) words, and the <strong>first three are identical</strong> on every sheet of the same backup. If yours have 12 or 24 words, they aren't SLIP-39: use <em>A complete seed</em> or <em>Shamir backup</em> instead.
        </div>

        <div class="warn-box" style="margin-bottom:16px">🛡️ Reassembling a backup makes it fully usable again: do it with the device disconnected from the network, or from a Tails system or a clean virtual machine.</div>

        <div id="cs-parts"></div>
        <button class="btn btn-outline btn-small" id="cs-add" style="margin-top:10px">+ Add a sheet</button>

        <label class="config-label" style="margin-top:16px">Passphrase, if you used one
          <span class="hint">Leave empty if you never set one. Note: with SLIP-39 a wrong passphrase gives no error — it simply opens a different, empty wallet.</span>
        </label>
        <input type="password" id="cs-pass" class="inp" autocomplete="off">

        <div style="margin-top:18px">
          <button class="btn btn-primary btn-large" id="cs-go">Recover the wallet</button>
        </div>
        <div id="cs-result" style="margin-top:14px"></div>
        <div class="ov-row" style="margin-top:14px">
          <button class="btn btn-ghost btn-small" id="cs-back">← Back to choices</button>
        </div>
      </div>
      <div id="cs-addresses"></div>
    </section>`;
}

function csAddPart() {
  const box = document.getElementById('cs-parts');
  const i = box.children.length;
  const div = document.createElement('div');
  div.className = 'rec-part';
  div.innerHTML = `
    <div class="rec-part-head"><span>Sheet ${i + 1}</span></div>
    <textarea class="inp cs-words" rows="2" placeholder="The 20 words of this sheet" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></textarea>`;
  box.appendChild(div);
}

function wireCtrlSlip() {
  const box = document.getElementById('cs-parts');
  if (box && !box.children.length) { csAddPart(); csAddPart(); }
  document.getElementById('cs-add')?.addEventListener('click', csAddPart);
  document.getElementById('cs-back')?.addEventListener('click', () => { ctrlPath = null; csResults = null; renderApp(); });
  renderCsAddresses();
  document.getElementById('cs-go')?.addEventListener('click', () => {
    const out = document.getElementById('cs-result');
    const shares = [...document.querySelectorAll('.cs-words')]
      .map(t => normalizeWords(t.value)).filter(Boolean);
    if (shares.length < 1) { out.innerHTML = '<div class="note-box">Enter at least one sheet.</div>'; return; }
    for (let i = 0; i < shares.length; i++) {
      const n = shares[i].split(' ').length;
      if (n !== 20 && n !== 33) {
        out.innerHTML = `<div class="warn-box">Sheet ${i + 1} has ${n} words. SLIP-39 sheets have 20 or 33: check you have not skipped or added anything.</div>`;
        return;
      }
    }
    const pass = document.getElementById('cs-pass').value || '';
    if (!isSlip39Passphrase(pass)) {
      out.innerHTML = `<div class="warn-box">${SLIP39_PASS_MSG}</div>`;
      return;
    }
    let secret;
    try { secret = slip39Recover(shares, pass); }
    catch (err) {
      out.innerHTML = `<div class="warn-box"><strong>It was not possible to reassemble.</strong> Usually this means the sheets do not belong to the same backup, that some are missing to reach the threshold, or that there is a transcription error. Check that the first three words are the same on all of them.</div>`;
      return;
    }
    try {
      // The master secret IS the BIP-32 seed. Only the public addresses are
      // kept; the secret itself is not stored anywhere in the page state.
      // Bitcoin in all four formats: a Trezor account may use any of them,
      // and the point here is to recognise one's own addresses.
      const master = HDKey.fromMasterSeed(new Uint8Array(secret));
      csResults = {};
      for (const fmt of ['native', 'taproot', 'p2sh', 'legacy']) csResults['btc-' + fmt] = deriveBTC(master, fmt);
      Object.assign(csResults, deriveAll(secret, ['eth', 'trx', 'sol'], 'native'));
      secret.fill(0);
    } catch (e) {
      out.innerHTML = `<div class="warn-box">Derivation error: ${escapeHtml(e.message)}</div>`;
      return;
    }
    document.querySelectorAll('.cs-words').forEach(t => { t.value = ''; });   // the sheets need not stay on screen
    document.getElementById('cs-pass').value = '';
    out.innerHTML = `<div class="ok-box">✔ <strong>Wallet recovered</strong> from ${shares.length} sheets. The addresses are below: compare them with the ones you expect.</div>`;
    renderCsAddresses();
  });
}

function renderCsAddresses() {
  const box = document.getElementById('cs-addresses');
  if (!box || !csResults) return;
  const entries = Object.values(csResults);
  box.innerHTML = `
    <div class="card">
      <div class="card-header"><span class="step-badge">✓</span><h2>Addresses of this backup</h2></div>
      <div class="addresses-list">
        ${entries.map(e => `
          <div class="address-item">
            <div class="address-header"><span class="addr-icon">${escapeHtml(e.icon)}</span>
              <div class="address-header-text"><strong>${escapeHtml(e.name)}</strong></div></div>
            <div class="address-details">
              <div class="detail-row"><span class="detail-label">Address</span>
                <div class="addr-copy-row"><code class="detail-value addr-value">${escapeHtml(e.address)}</code>
                  <button class="btn btn-icon btn-copy-addr" data-addr="${escapeHtml(e.address)}" title="Copy">📋</button></div>
              </div>
              <details class="adv"><summary>Technical details</summary>
                <div class="detail-row" style="margin-top:8px"><span class="detail-label">Derivation Path</span>
                  <code class="detail-value path-value">${escapeHtml(e.path)}</code></div>
              </details>
            </div>
          </div>`).join('')}
      </div>
      <div class="note-box" style="margin-top:14px">Bitcoin is shown in all four formats: yours is the one your wallet uses, usually Native SegWit or Taproot. The SLIP-39 master secret becomes the BIP-32 root key directly — it does not go through PBKDF2 as in BIP-39 — so these are the same addresses your Trezor or Sparrow show for the first account.</div>
    </div>`;
  box.querySelectorAll('.btn-copy-addr').forEach(b => b.addEventListener('click', async (ev) => {
    try { await copyToClipboard(ev.currentTarget.dataset.addr); showToast('Address copied.', 'success'); } catch (_) {}
  }));
}

/* ── Multisig vault check: recompute from xpubs ── */
function renderCtrlMultisig() {
  return `
    <section>
      <div class="card">
        <div class="card-header"><span class="step-badge">🔐</span><h2>Recalculate a multisig vault</h2></div>
        <p style="margin-bottom:14px">Paste the participants' xpubs and the threshold: the program recalculates the vault address. If it matches the one you know, the configuration is confirmed — right keys, right threshold, all in order.</p>
        <label class="config-label">The xpubs, one per line</label>
        <textarea id="cm-xpubs" class="inp" rows="4" placeholder="xpub6...&#10;xpub6..." autocomplete="off" spellcheck="false"></textarea>
        <div class="ov-grid2" style="margin-top:12px;max-width:420px">
          <div><label class="config-label">Signatures required</label>
            <select id="cm-m" class="inp">${thresholdOptions(3, 2)}</select></div>
        </div>
        <button class="btn btn-primary" id="cm-go" style="margin-top:14px">Recalculate the address</button>
        <div id="cm-result" style="margin-top:16px"></div>
        <div class="ov-row" style="margin-top:14px">
          <button class="btn btn-ghost btn-small" id="cm-back">← Back to choices</button>
        </div>
      </div>
    </section>`;
}

function wireCtrlMultisig() {
  document.getElementById('cm-back')?.addEventListener('click', () => { ctrlPath = null; renderApp(); });
  const readCm = () => (document.getElementById('cm-xpubs')?.value || '').split('\n').map(x => x.trim()).filter(Boolean);
  document.getElementById('cm-xpubs')?.addEventListener('input', () => {
    const sel = document.getElementById('cm-m');
    if (sel) sel.innerHTML = thresholdOptions(Math.max(2, readCm().length), parseInt(sel.value) || 2);
  });
  document.getElementById('cm-go')?.addEventListener('click', async () => {
    const xpubs = readCm();
    const m = parseInt(document.getElementById('cm-m').value);
    const out = document.getElementById('cm-result');
    if (xpubs.length < 2) { out.innerHTML = '<div class="note-box">At least two xpubs are needed, one per line.</div>'; return; }
    if (m > xpubs.length) { out.innerHTML = '<div class="note-box">The required signatures cannot exceed the number of xpubs.</div>'; return; }
    let res;
    try { res = multisigAddress(xpubs, m); }
    catch (err) {
      out.innerHTML = `<div class="warn-box">${keyErrorMessage(err, xpubs.map((_, i) => `The key on line ${i + 1}`))}</div>`;
      return;
    }
    out.innerHTML = `
      <div class="share-box">
        <div class="share-head">🏠 Recalculated address (${res.m} of ${res.n} signatures)</div>
        <div class="addr-copy-row"><code class="detail-value addr-value">${escapeHtml(res.address)}</code>
          <button class="btn btn-icon" id="cm-copy" title="Copy">📋</button></div>
        <div id="cm-qr" style="display:flex;justify-content:center;margin-top:10px"></div>
        <p class="hint" style="margin-top:10px;text-align:center">Does it match the one you know? Then the vault is confirmed. The keys are sorted automatically (BIP-67): the order you paste them in does not matter.</p>
        <details class="adv" style="margin-top:10px"><summary>Descriptor</summary>
          <div class="adv-body"><code class="detail-value" style="font-size:10.5px">${escapeHtml(res.descriptor)}</code></div>
        </details>
      </div>`;
    document.getElementById('cm-copy')?.addEventListener('click', async () => {
      try { await copyToClipboard(res.address); showToast('Address copied.', 'success'); } catch (_) {}
    });
    try { document.getElementById('cm-qr').innerHTML = `<img src="${await generateQR(res.address, 170)}" style="border-radius:8px;border:4px solid #fff">`; } catch (_) {}
  });
}

function renderGenerateTab() {
  if (slipShares) return renderSlipView();
  if (currentMnemonic) return renderWalletView();
  if (genPath === 'multisig') return renderMultisigTab();
  if (genPath === null) return renderGenChooser();
  return `
    <section>
      <div class="card hero-card">
        <div class="card-icon">
          <svg viewBox="0 0 48 48" width="56" height="56"><circle cx="24" cy="24" r="20" fill="none" stroke="var(--accent)" stroke-width="2" stroke-dasharray="6 4"/><path d="M24 12v24M12 24h24" stroke="var(--accent)" stroke-width="2.5" stroke-linecap="round"/></svg>
        </div>
        <h2>Generate a new wallet</h2>
        <p class="card-desc">You are about to generate the secret words that will give life to your wallet. They won't appear on screen unless you ask: you can copy or print them away from prying eyes.</p>

        ${!SECURE_RANDOM_OK ? `<div class="rng-warning">⚠ This device does not offer a cryptographic-quality random number generator (CSPRNG). Everything has been stopped: better no wallet than a predictable one. Try again with an up-to-date browser.</div>` : ''}

        <div class="config-box">
          <div class="config-row">
            <label class="config-label config-label-center">Where does your randomness come from?${help('dice')}</label>
            <div class="mode-grid">
              <button class="mode-card ${entropyMode === 'classic' ? 'mode-active' : ''}" id="mode-classic" data-mode="classic">
                <span class="mode-icon">🖥️</span>
                <span class="mode-title">Three sources</span>
                <span class="mode-desc">The browser's generator, the rhythm of your fingers on the keyboard, the movement of the mouse.</span>
              </button>
              <button class="mode-card ${entropyMode === 'dice' ? 'mode-active' : ''}" id="mode-dice" data-mode="dice">
                <span class="mode-icon">🎲</span>
                <span class="mode-title">Four sources</span>
                <span class="mode-desc">Adds real dice rolls.</span>
              </button>
            </div>
          </div>

          <div class="config-row">
            <label class="config-label">What kind of backup do you want?${help('standard')}</label>
            <div class="std-grid">
              <button class="std-card ${seedStandard === 'bip39' ? 'std-active' : ''}" data-std="bip39">
                <span class="std-name">BIP-39</span>
                <span class="std-sub">A single phrase &middot; 12–24 words</span>
                <span class="std-desc">The universal standard since 2013: <strong>every wallet accepts it</strong>, today and twenty years from now. You can import the phrase anywhere.</span>
                <span class="std-note">Choose this if you want total freedom. It's the right choice for most people, even for significant amounts, provided you look after that sheet well. You can always split it later with Shamir.</span>
              </button>
              <button class="std-card ${seedStandard === 'slip39' ? 'std-active' : ''}" data-std="slip39">
                <span class="std-name">SLIP-39</span>
                <span class="std-sub">Several sheets with a threshold &middot; 20 words each</span>
                <span class="std-desc">The backup <strong>is born already split</strong>: several sheets, of which only some are needed. The complete phrase never exists.</span>
                <span class="std-note">Choose this if your main fear is that someone finds the backup. By distributing the sheets, no single discovery exposes the funds and you can lose one without consequence. In exchange, fewer programs read it: Trezor, Sparrow, Electrum, Rabby.</span>
              </button>
            </div>
            <p class="hint" style="margin-top:8px">Want to understand the difference better?${helpLink('g-standard', 'Learn more about BIP-39 and SLIP-39')}</p>
          </div>

          <div class="config-row" id="row-words" ${seedStandard !== 'bip39' ? 'style="display:none"' : ''}>
            <label class="config-label">How many words will your seed have?${help('words')}</label>
            <div class="seg" id="seg-words">
              ${WORD_OPTIONS.map(w => `<button class="seg-btn ${w === 12 ? 'seg-active' : ''}" data-w="${w}">${w}</button>`).join('')}
            </div>
          </div>

          <div id="slip-config" ${seedStandard !== 'slip39' ? 'style="display:none"' : ''}>

            <div class="ov-grid2" style="max-width:420px">
              <div><label class="config-label">Sheets to create</label>
                <select id="slip-n" class="inp">${[3,4,5,6,7].map(v => `<option value="${v}" ${v===5?'selected':''}>${v}</option>`).join('')}</select></div>
              <div><label class="config-label">How many are needed</label>
                <select id="slip-m" class="inp">${shamirThresholdOptions(5, 3)}</select></div>
            </div>
            <p class="hint" id="slip-summary" style="margin-top:8px"></p>
          </div>
        </div>

        <button id="btn-generate" class="btn btn-primary btn-large" ${!SECURE_RANDOM_OK ? 'disabled' : ''}>Start</button>
        <div class="ov-row" style="justify-content:center;margin-top:14px">
          <button id="gen-back" class="btn btn-ghost btn-small">← Back to choices</button>
        </div>
      </div>
    </section>
  `;
}

function wireGenera() {
  document.getElementById('gen-classic')?.addEventListener('click', () => { genPath = 'classic'; renderApp(); });
  document.getElementById('gen-multisig')?.addEventListener('click', () => { genPath = 'multisig'; msMode = null; renderApp(); });
  document.querySelectorAll('.mode-card').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('.mode-card').forEach(x => x.classList.remove('mode-active'));
    b.classList.add('mode-active');
    entropyMode = b.dataset.mode;          // survives a re-render
  }));
  document.querySelectorAll('.std-card').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('.std-card').forEach(x => x.classList.remove('std-active'));
    b.classList.add('std-active');
    seedStandard = b.dataset.std;
    document.getElementById('row-words').style.display = seedStandard === 'bip39' ? '' : 'none';
    document.getElementById('slip-config').style.display = seedStandard === 'slip39' ? '' : 'none';
    updSlipSummary();
  }));
  const updSlipSummary = () => {
    const el = document.getElementById('slip-summary');
    if (!el) return;
    const n = parseInt(document.getElementById('slip-n')?.value || '5');
    const m = Math.min(parseInt(document.getElementById('slip-m')?.value || '3'), n);
    const lost = n - m;
    el.innerHTML = `You will create <strong>${n} sheets</strong> of 20 words and <strong>${m}</strong> of them will be enough to recover everything.` +
      (lost > 0 ? ` You can lose up to <strong>${lost}</strong> with no consequences.` : ' Since all of them are needed, losing one means losing the wallet.');
  };
  document.getElementById('slip-n')?.addEventListener('change', () => {
    const n = parseInt(document.getElementById('slip-n').value);
    const sel = document.getElementById('slip-m');
    const cur = parseInt(sel.value);
    sel.innerHTML = shamirThresholdOptions(n, cur);
    updSlipSummary();
  });
  document.getElementById('slip-m')?.addEventListener('change', updSlipSummary);
  updSlipSummary();
  document.querySelectorAll('#seg-words .seg-btn').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('#seg-words .seg-btn').forEach(x => x.classList.remove('seg-active'));
    b.classList.add('seg-active');
  }));
  document.getElementById('btn-generate')?.addEventListener('click', startGeneration);
  document.getElementById('gen-back')?.addEventListener('click', () => { genPath = null; renderApp(); });
  if (currentMnemonic) wireWalletView();
}

function selectedWords() {
  const b = document.querySelector('#seg-words .seg-active');
  return b ? parseInt(b.dataset.w) : 12;
}

function startGeneration() {
  if (!SECURE_RANDOM_OK) return;
  const mode = entropyMode;
  if (seedStandard === 'slip39') {
    const n = parseInt(document.getElementById('slip-n')?.value || '5');
    const m = Math.min(parseInt(document.getElementById('slip-m')?.value || '3'), n);
    slipConfig = { n, m };
    pendingConfig = { words: 12, passphrase: '', useDice: mode === 'dice' };  // 128 bits of entropy
  } else {
    slipConfig = null;
    pendingConfig = { words: selectedWords(), passphrase: '', useDice: mode === 'dice' };
  }
  entropyPurpose = 'wallet';
  showPassphraseStep();
}

/* ════════════════════════════════════════════════════════════════
   CHECK SEED TAB — inspect a seed you already own.
   Isolated state: it never touches the wallet of the "Generate" tab.
   ════════════════════════════════════════════════════════════════ */
function renderVerifyTab() {
  return `
    <section>
      <div class="card">
        <div class="card-header"><span class="step-badge">🔍</span><h2>Check a seed you already own</h2></div>
        <p style="margin-bottom:14px">Enter your words and find out which addresses they generate. Useful to <strong>check that a backup is the right one</strong>, to find the addresses of an old wallet, or to compare them with those shown by another program.</p>

        <div class="note-box" style="margin-bottom:16px">
          🛡️ <strong>A moment to prepare properly.</strong><br>
          Typing a seed that holds real funds is the most delicate moment: if the device is compromised, malware can read it while you type. Do it only in an environment you trust:
          <br><br>
          &bull; <strong>Disconnect the device from the internet</strong> before you start (Wi-Fi off, cable unplugged)<br>
          &bull; Better still: use a system booted from a USB stick, such as <strong>Tails</strong>, which leaves no trace on the disk<br>
          &bull; Or a clean <strong>virtual machine</strong>, with no network, to be deleted after use<br>
          &bull; An old dedicated computer that has never been connected is perfectly fine<br>
          <br>
          This page transmits nothing and saves nothing — but it cannot protect you from an already infected system.
        </div>

        <label class="config-label">Your words
          <span class="hint">12, 15, 18, 21 or 24 words, separated by spaces. Capitals don't matter.</span>
        </label>
        <textarea id="vf-words" class="inp" rows="3" placeholder="word1 word2 word3 …" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></textarea>

        <label class="config-label" style="margin-top:14px">Passphrase, if you used one
          <span class="hint">The "25th word". Leave it empty if you never set one: with or without it, the addresses change completely.</span>
        </label>
        <input type="password" id="vf-pass" class="inp" autocomplete="off">

        <div class="config-row" style="margin-top:18px">
          <label class="config-label">Which networks do you want to check?</label>
          <div class="chain-grid" style="margin-top:8px">
            ${CHAINS.map(c => `
              <label class="chain-option">
                <input type="checkbox" id="vf-chk-${c.id}" value="${c.id}" ${c.id === 'btc' ? 'checked' : ''} />
                <div class="chain-box"><span class="chain-icon">${c.icon}</span><span class="chain-name">${c.name}</span><span class="chain-tag">${c.tag}</span></div>
              </label>`).join('')}
          </div>
        </div>

        <div id="vf-format-box" class="btc-fmt-box">
          <label class="config-label">Which Bitcoin format was it created with?
            <span class="hint">If you don't know, try <strong>Native SegWit</strong>: it's the most widespread standard. If the address doesn't match the one you expect, try the others — the seed stays the same.</span>
          </label>
          <div class="fmt-grid" id="vf-fmt-grid">
            ${Object.values(BTC_FORMATS).map(f => `
              <button class="fmt-card ${f.id === vfFormat ? 'fmt-active' : ''}" data-fmt="${f.id}">
                <span class="fmt-label">${f.label}</span>
                <span class="fmt-tag">${f.tag}</span>
                <span class="fmt-desc">${f.desc}</span>
              </button>`).join('')}
          </div>
        </div>

        <button id="vf-go" class="btn btn-primary btn-large" style="margin-top:16px">Show the addresses</button>
        <p id="vf-err" style="margin-top:10px"></p>
        ${vfMnemonic ? `<button id="vf-clear" class="btn btn-ghost btn-small" style="margin-top:12px">✕ Remove from the page</button>` : ''}
        <div class="ov-row" style="margin-top:14px">
          <button class="btn btn-ghost btn-small" id="vf-back">← Back to choices</button>
        </div>
      </div>

      <div id="vf-results"></div>
    </section>`;
}

function wireVerify() {
  document.querySelectorAll('#vf-fmt-grid .fmt-card').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('#vf-fmt-grid .fmt-card').forEach(x => x.classList.remove('fmt-active'));
    b.classList.add('fmt-active');
    vfFormat = b.dataset.fmt;
    if (vfSeed) runVerify(true);   // recompute immediately with the new format
  }));
  const syncFmt = () => {
    const box = document.getElementById('vf-format-box');
    if (box) box.style.display = document.getElementById('vf-chk-btc')?.checked ? 'block' : 'none';
  };
  document.getElementById('vf-chk-btc')?.addEventListener('change', syncFmt);
  syncFmt();

  document.getElementById('vf-go')?.addEventListener('click', () => runVerify(false));
  document.getElementById('vf-back')?.addEventListener('click', () => { ctrlPath = null; renderApp(); });
  document.getElementById('vf-clear')?.addEventListener('click', () => {
    vfSeed = null; vfMnemonic = null; vfResults = null; vfExtra = null; vfAccount = null;
    renderApp();
    showToast('Seed removed from the page.', 'info');
  });
  if (vfResults) renderVfResults();
}

function runVerify(keepSeed) {
  const err = document.getElementById('vf-err');
  const selected = CHAINS.map(c => c.id).filter(id => document.getElementById('vf-chk-' + id)?.checked);
  if (!selected.length) { err.innerHTML = '<span style="color:var(--danger)">Select at least one network.</span>'; return; }

  if (!keepSeed) {
    const ta = document.getElementById('vf-words');
    const words = (ta.value || '').trim().toLowerCase().replace(/\s+/g, ' ');
    if (!words) { err.innerHTML = '<span style="color:var(--danger)">Type the words of your seed.</span>'; return; }
    const n = words.split(' ').length;
    if (![12, 15, 18, 21, 24].includes(n)) {
      err.innerHTML = `<span style="color:var(--danger)">You typed ${n} words. A BIP-39 seed has 12, 15, 18, 21 or 24.</span>`;
      return;
    }
    if (!validateMnemonic(words, wordlist)) {
      err.innerHTML = '<span style="color:var(--danger)">These words do not form a valid seed. It is usually a typo or a similar but different word: check them one by one.</span>';
      return;
    }
    const pass = document.getElementById('vf-pass').value || '';
    vfMnemonic = words;
    vfSeed = mnemonicToSeedSync(words, pass);
  }

  err.innerHTML = '';
  try {
    vfResults = deriveAll(vfSeed, selected, vfFormat);
    vfExtra = null;
    vfAccount = selected.includes('btc') ? btcAccountInfo(vfSeed, vfFormat) : null;
  } catch (e) {
    err.innerHTML = '<span style="color:var(--danger)">Error: ' + escapeHtml(e.message) + '</span>';
    return;
  }
  renderApp();
  if (!keepSeed) showToast('Valid seed. Compare the addresses with the ones you expect.', 'success');
}

function renderVfResults() {
  const box = document.getElementById('vf-results');
  const entries = Object.values(vfResults || {});
  if (!entries.length) { if (box) box.innerHTML = ''; return; }
  box.innerHTML = `
    <div class="card">
      <div class="card-header"><span class="step-badge">✓</span><h2>Addresses of this seed</h2></div>
      <p class="hint" style="margin-bottom:16px">If they match the ones you expected, the backup is correct. If not, check the passphrase and — for Bitcoin — the format selected above.</p>
      <div class="addresses-list">
        ${entries.map(e => `
          <div class="address-item">
            <div class="address-header"><span class="addr-icon">${escapeHtml(e.icon)}</span>
              <div class="address-header-text"><strong>${escapeHtml(e.name)}</strong>
                ${e.evmChains ? `<div class="evm-tags">${e.evmChains.map(c => `<span class="evm-tag">${escapeHtml(c)}</span>`).join('')}</div>` : ''}
              </div>
            </div>
            <div class="address-details">
              <details class="adv"><summary>Technical details</summary>
                <div class="detail-row" style="margin-top:8px"><span class="detail-label">Derivation Path</span><code class="detail-value path-value">${escapeHtml(e.path)}</code></div>
              </details>
              <div class="detail-row"><span class="detail-label">Address</span>
                <div class="addr-copy-row"><code class="detail-value addr-value">${escapeHtml(e.address)}</code>
                  <button class="btn btn-icon btn-copy-addr" data-addr="${escapeHtml(e.address)}" title="Copy">📋</button>
                </div>
              </div>
            </div>
            <div class="address-qr" id="vfqr-${e.id}"><div class="qr-loading">Generating the QR…</div></div>
            ${e.id === 'btc' ? `
              <div class="btc-more">
                ${vfExtra ? `
                  <div class="more-head">Receiving addresses, in order</div>
                  <div class="more-list">
                    ${vfExtra.map(a => `
                      <div class="more-row">
                        <span class="more-idx">#${a.index}</span>
                        <code class="more-addr">${escapeHtml(a.address)}</code>
                        <button class="btn btn-icon btn-copy-addr" data-addr="${escapeHtml(a.address)}" title="Copy">📋</button>
                      </div>`).join('')}
                  </div>
                  <div class="ov-row" style="margin-top:10px">
                    <button class="btn btn-ghost btn-small" id="vf-more2">Show 10 more</button>
                  </div>
                ` : `
                  <button class="btn btn-outline btn-small" id="vf-more">➕ Show more Bitcoin addresses</button>
                  <p class="hint" style="margin-top:8px">Useful if the funds you're looking for are on an address after the first. On the other networks you <strong>always use the same address</strong>.</p>
                `}
              </div>` : ''}
          </div>`).join('')}
      </div>
      ${vfAccount ? `
        <div class="watch-box">
          <div class="watch-head">👁️ Check the balance with no risk (watch-only)</div>
          <p class="hint" style="margin-bottom:12px">Paste this code into <strong>Sparrow</strong> or <strong>Electrum</strong> to see balance and movements <strong>without being able to spend</strong> and without bringing the seed onto a connected device.</p>
          <div class="detail-label">Descriptor</div>
          <div class="addr-copy-row"><code class="detail-value" style="font-size:10.5px">${escapeHtml(vfAccount.descriptor)}</code>
            <button class="btn btn-icon" id="vf-copy-desc" title="Copy">📋</button></div>
          <div class="note-box" style="margin-top:10px">💡 Whoever holds this code sees all your Bitcoin movements, present and future. They cannot spend, but it is like showing a bank statement.</div>
        </div>` : ''}
    </div>`;

  entries.forEach(async (e) => {
    const c = document.getElementById(`vfqr-${e.id}`);
    if (!c) return;
    try { c.innerHTML = `<img src="${await generateQR(e.address)}" alt="QR ${escapeHtml(e.symbol)}" />`; }
    catch (_) { c.innerHTML = '<span class="qr-error">QR error</span>'; }
  });
  document.querySelectorAll('#vf-results .btn-copy-addr').forEach(b => b.addEventListener('click', async (ev) => {
    try { await copyToClipboard(ev.currentTarget.dataset.addr); showToast('Address copied.', 'success'); } catch (_) {}
  }));
  document.getElementById('vf-copy-desc')?.addEventListener('click', async () => {
    try { await copyToClipboard(vfAccount.descriptor); showToast('Descriptor copied.', 'success'); } catch (_) {}
  });
  const master = () => HDKey.fromMasterSeed(new Uint8Array(vfSeed));
  document.getElementById('vf-more')?.addEventListener('click', () => {
    vfExtra = deriveBTCMany(master(), vfFormat, 0, 10); renderVfResults();
  });
  document.getElementById('vf-more2')?.addEventListener('click', () => {
    vfExtra = vfExtra.concat(deriveBTCMany(master(), vfFormat, vfExtra.length, 10)); renderVfResults();
  });
}

/* ══════════════════════════════════════════════════════════════
   SLIP-39 — the backup is born already split. The "master secret"
   is never shown as a phrase: only the shares exist.
   The BIP-32 root key is derived from the raw master secret
   (not through PBKDF2 as in BIP-39): verified against the 45
   official vectors of the trezor/python-shamir-mnemonic project.
   ══════════════════════════════════════════════════════════════ */
function finishSlip39(entropy) {
  try {
    const secret = entropy.slice(0, 16);                        // 128 bits
    const shares = slip39Create(secret, slipConfig.m, slipConfig.n, pendingConfig.passphrase || '');
    slipSecret = secret;
    slipShares = shares;
    slipRevealed = shares.map(() => false);
    currentSeed = slipSecret;          // the master secret IS the BIP-32 seed (SLIP-39)
    currentMnemonic = null;
    currentEntropy = null;
    generatedAddresses = {};
    btcExtra = null; btcAccount = null;
    closeOverlay();
    renderApp();
    showToast(`${slipConfig.n} sheets created. ${slipConfig.m} of them are enough to recover.`, 'success');
  } catch (err) {
    closeOverlay();
    showToast(err.message === 'SLIP39_PASSPHRASE' ? SLIP39_PASS_MSG : 'Creation error: ' + err.message, 'error');
  }
}

function renderSlipView() {
  const c = slipConfig;
  return `
    <section>
      <div class="card">
        <div class="card-header"><span class="step-badge">1</span><h2>Your ${c.n} sheets</h2>
          <span class="seed-badge">✓ Protected</span></div>
        <p style="margin-bottom:6px">Each one is a part of the backup. Save them <strong>in different places</strong>: <strong>${c.m}</strong> of them will be enough to reopen the wallet.</p>
        <p class="hint" style="margin-bottom:16px">The complete phrase exists nowhere — not even in here. That is the whole point of this standard.</p>
        <div class="keys-list">
          ${slipShares.map((sh, i) => {
            const w = sh.split(' ');
            const open = slipRevealed[i];
            return `
            <div class="key-block">
              <div class="key-head">
                <span class="key-title">📄 Sheet ${i + 1}</span>
                <span class="key-tag">20 words</span>
              </div>
              <div class="part-words">${w.map((x, k) => `<span class="part-word"><em>${k + 1}</em>${open ? escapeHtml(x) : '••••••••'}</span>`).join('')}</div>
              <div class="ov-row" style="margin-top:10px">
                <button class="btn btn-outline btn-small sl-reveal" data-i="${i}">${open ? '🙈 Hide' : '👁️ Reveal'}</button>
                <button class="btn btn-outline btn-small sl-copy" data-i="${i}">📋 Copy</button>
                <button class="btn btn-outline btn-small sl-print" data-i="${i}">🖨️ Print</button>
                <button class="btn btn-outline btn-small sl-check" data-i="${i}">✅ Check again</button>
              </div>
            </div>`;
          }).join('')}
        </div>
        <div class="ov-row" style="margin-top:16px">
          <button class="btn btn-primary" id="slip-print-all">🖨️ Print all sheets</button>
          <button class="btn btn-ghost btn-danger btn-small" id="slip-reset">✕ Start over</button>
        </div>
        <div class="note-box" style="margin-top:12px">The first three words are the same on every sheet: they identify this backup and tell you at a glance whether you are combining sheets from the same set.</div>
      </div>

      <div class="card chain-card">
        <div class="card-header"><span class="step-badge">2</span><h2>Choose your networks</h2>
          <button id="btn-select-all" class="btn btn-ghost btn-small">Select all</button>
        </div>
        <div class="chain-grid">
          ${CHAINS.map(ch => `
            <label class="chain-option">
              <input type="checkbox" id="chk-${ch.id}" value="${ch.id}" ${ch.id === 'btc' ? 'checked' : ''} />
              <div class="chain-box"><span class="chain-icon">${ch.icon}</span><span class="chain-name">${ch.name}</span><span class="chain-tag">${ch.tag}</span></div>
            </label>`).join('')}
        </div>
        <div id="btc-format-box" class="btc-fmt-box" style="display:none">
          <label class="config-label">Bitcoin address format</label>
          <div class="fmt-grid" id="fmt-grid">
            ${Object.values(BTC_FORMATS).map(f => `
              <button class="fmt-card ${f.id === btcFormat ? 'fmt-active' : ''}" data-fmt="${f.id}">
                <span class="fmt-label">${f.label}</span><span class="fmt-tag">${f.tag}</span>
                <span class="fmt-desc">${f.desc}</span>
              </button>`).join('')}
          </div>
        </div>
        <button id="btn-derive" class="btn btn-primary">Calculate the addresses</button>
        <div id="watch-panel"></div>
        <div id="results-container"></div>
      </div>
    </section>`;
}

function wireSlipView() {
  document.querySelectorAll('.sl-reveal').forEach(b => b.addEventListener('click', () => {
    const i = +b.dataset.i; slipRevealed[i] = !slipRevealed[i]; renderApp();
  }));
  document.querySelectorAll('.sl-copy').forEach(b => b.addEventListener('click', async () => {
    try { await copyToClipboard(slipShares[+b.dataset.i]); showToast(`Sheet ${+b.dataset.i + 1} copied.`, 'success'); }
    catch (_) { showToast('Copy failed.', 'error'); }
  }));
  document.querySelectorAll('.sl-print').forEach(b => b.addEventListener('click', () => printSlipShare(+b.dataset.i)));
  document.querySelectorAll('.sl-check').forEach(b => b.addEventListener('click', () => {
    const i = +b.dataset.i;
    showVerifyBackup(slipShares[i], `Sheet ${i + 1} of ${slipConfig.n}`);
  }));
  document.getElementById('slip-print-all')?.addEventListener('click', printAllSlipShares);
  document.getElementById('slip-reset')?.addEventListener('click', handleReset);
  document.getElementById('btn-select-all')?.addEventListener('click', handleSelectAll);
  const syncFmt = () => {
    const box = document.getElementById('btc-format-box');
    if (box) box.style.display = document.getElementById('chk-btc')?.checked ? 'block' : 'none';
  };
  document.getElementById('chk-btc')?.addEventListener('change', syncFmt);
  document.querySelectorAll('.fmt-card').forEach(b => b.addEventListener('click', () => onFormatCard(b)));
  syncFmt();
  document.getElementById('btn-derive')?.addEventListener('click', handleDerive);
}

function slipShareHTML(i) {
  const w = slipShares[i].split(' ');
  const { m, n } = slipConfig;
  return `<div class="card">
<div class="title">Sheet ${i + 1} of ${n}</div>
<div class="grid">${w.map((x, k) => `<div class="w"><i>${k + 1}</i>${escapeHtml(x)}</div>`).join('')}</div>
<div class="meta">SLIP-39 backup &middot; any ${m} of the ${n} sheets recover the wallet</div>
</div>`;
}

const SLIP_PRINT_CSS = `*{margin:0;padding:0;box-sizing:border-box}@page{size:A4;margin:20mm}
body{font-family:'Courier New',monospace;background:#fff;color:#000}
.card{border:2px solid #000;border-radius:5px;padding:26px 30px}
.brk{page-break-after:always}
.title{text-align:center;font-size:15px;font-weight:bold;letter-spacing:4px;text-transform:uppercase;padding-bottom:14px;margin-bottom:20px;border-bottom:1px solid #ccc}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.w{border:1px solid #bbb;border-radius:3px;padding:8px 9px;font-size:12px}
.w i{color:#999;font-style:normal;margin-right:7px;font-size:10px}
.meta{margin-top:18px;padding-top:12px;border-top:1px solid #ccc;font-size:11px;line-height:1.6;color:#333}`;

function printSlipShare(i) {
  printHTML(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Sheet ${i + 1}</title>
<style>${SLIP_PRINT_CSS}</style></head><body>${slipShareHTML(i)}</body></html>`);
}

function printAllSlipShares() {
  const pages = slipShares.map((_, i) => slipShareHTML(i)).join('<div class="brk"></div>');
  printHTML(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Sheets</title>
<style>${SLIP_PRINT_CSS}</style></head><body>${pages}</body></html>`);
}

/* ══════════════════════════════════════════════════════════════
   CONTEXTUAL HELP — a "?" next to the options that deserve one.
   A short explanation on click, and a link into the guide for
   whoever wants more. This keeps the screens uncluttered.
   ══════════════════════════════════════════════════════════════ */
const HELP = {
  sources: {
    t: 'Where the randomness comes from',
    d: 'A wallet is secure only if the number it is born from is unpredictable. The program mixes several sources: the browser cryptographic generator, the rhythm of your fingers on the keyboard, the movement of the mouse, and — if you want — rolls of real dice. If one source were faulty, the others hold.',
    g: 'g-entropy',
  },
  words: {
    t: 'How many words to choose',
    d: '12 words are the standard used by almost every wallet and are already unbreakable with any known technology. 24 double the length of the secret number, in exchange for more words to write down and keep.',
    g: 'g-seed',
  },
  standard: {
    t: 'BIP-39 or SLIP-39',
    d: 'BIP-39 produces a single phrase, accepted by any wallet. SLIP-39 produces several sheets with a threshold — only some are needed — and the whole phrase never exists, but fewer programs read it (Trezor, Sparrow, Electrum and a few others).',
    g: 'g-standard',
  },
  passphrase: {
    t: 'The passphrase',
    d: 'One extra word or phrase, chosen by you, that enters the calculation together with the seed. Anyone finding your sheet would open an empty wallet. But if you forget it there is no recovery: the words alone are no longer enough.',
    g: 'g-passphrase',
  },
  dice: {
    t: 'Why the dice',
    d: 'A rolling die obeys physics, not software: it is the only source born completely outside the computer. Use real physical dice, never apps or sites that simulate them.',
    g: 'g-entropy',
  },
  backup: {
    t: 'How to keep the seed',
    d: 'A single sheet is the simplest route. Splitting it into parts removes the single weak point: whoever finds one piece gets nothing. With Shamir you can even lose some of them and still recover.',
    g: 'g-backup',
  },
  btcformat: {
    t: 'The Bitcoin formats',
    d: 'The same seed produces four kinds of address. Native SegWit is today standard, Taproot the most recent, the other two exist for compatibility with older services. Only the shape of the address and the fees change.',
    g: 'g-formats',
  },
  watch: {
    t: 'xpub and descriptor',
    d: 'Codes that let you see the balance and the movements without being able to spend. You paste them into Sparrow or Electrum and keep an eye on the wallet from a connected computer, while the seed stays safe.',
    g: 'g-watch',
  },
  networks: {
    t: 'The supported networks',
    d: 'The same seed generates addresses on four different networks. The Ethereum address also works on Polygon, Arbitrum, BSC and the other compatible networks.',
    g: 'g-networks',
  },
  multisig: {
    t: 'What a multisig vault is',
    d: 'An address that requires several keys in order to spend, for example 2 out of 3. You can lose one key without losing the funds, and whoever steals one gets nothing.',
    g: 'g-multisig',
  },
  verify: {
    t: 'Why check again',
    d: 'You retype the words looking only at your own backup. It exists to reveal today, in thirty seconds, whether the backup is wrong — instead of on the day you actually need it.',
    g: 'g-verify',
  },
  powers: {
    t: 'Powers-of-2 backup',
    d: 'Every word has a number from 1 to 2048, which is written by marking boxes whose sum gives that number. It is a way to record the seed without any readable word.',
    g: 'g-powers',
  },
};

function help(key) {
  return HELP[key] ? `<span class="help-dot" data-help="${key}" title="What does this mean?" role="button" tabindex="0">?</span>` : '';
}

/* A "?" that explains nothing itself: it jumps straight to the right spot in the guide */
function helpLink(anchor, title) {
  return `<span class="help-dot" data-jump="${anchor}" title="${escapeHtml(title || 'Go to the guide')}" role="button" tabindex="0">?</span>`;
}

function goToGuide(anchor) {
  document.getElementById('help-pop')?.remove();
  closeOverlay();
  activeTab = 'guide';
  guideView = 'faq';
  renderApp();
  setTimeout(() => {
    const el = document.getElementById(anchor);
    if (el) { el.open = true; el.scrollIntoView?.({ behavior: 'smooth', block: 'center' }); }
  }, 60);
}

/* The "?" markers also live inside overlay panels, which are
   drawn after the page has been wired. That is why delegation is used:
   a single listener on the document covers every screen, present
   and future. */
function wireHelp() { /* nothing to do: handled by delegation, see below */ }

function openHelpPopover(dot) {
  const h = HELP[dot.dataset.help];
  if (!h) return;
  document.getElementById('help-pop')?.remove();
  const pop = document.createElement('div');
  pop.id = 'help-pop';
  pop.className = 'help-pop';
  pop.innerHTML = `
    <div class="hp-title">${escapeHtml(h.t)}</div>
    <div class="hp-text">${h.d}</div>
    <div class="hp-row">
      <button class="btn btn-ghost btn-small hp-more" data-g="${h.g}">Learn more in the guide →</button>
    </div>`;
  document.body.appendChild(pop);
  const r = dot.getBoundingClientRect();
  const w = 320;
  let left = r.left + window.scrollX - w / 2 + r.width / 2;
  left = Math.max(12, Math.min(left, window.innerWidth - w - 12));
  pop.style.left = left + 'px';
  pop.style.top = (r.bottom + window.scrollY + 8) + 'px';
  pop.querySelector('.hp-more').addEventListener('click', () => goToGuide(h.g));
}

if (!window.__helpWired) {
  window.__helpWired = true;

  document.addEventListener('click', (ev) => {
    const dot = ev.target.closest?.('.help-dot');
    if (!dot) return;
    ev.preventDefault(); ev.stopPropagation();
    if (dot.dataset.jump) goToGuide(dot.dataset.jump);
    else openHelpPopover(dot);
  }, true);   // capture phase: the "?" inside a card must not select the card

  document.addEventListener('mousedown', (ev) => {
    const pop = document.getElementById('help-pop');
    if (!pop || pop.contains(ev.target) || ev.target.closest?.('.help-dot')) return;
    pop.remove();
  });

  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') document.getElementById('help-pop')?.remove();
  });
}

/* ── BACKUP METHOD CHOICE (right after generation) ──
   Before showing the seed, the user decides how to keep it.      */
function showBackupChoice() {
  const nw = currentMnemonic.split(' ').length;
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <div class="ov-badge">Wallet created &middot; ${nw} words</div>
      <h3>🎉 Your wallet is ready. How do you want to keep it?</h3>
      <p>Choose how to keep the words.${help('backup')} You can change your mind later.</p>

      <div class="split-choice" id="bk-classic">
        <div class="split-head">📄 A single backup </div>
        <p class="split-desc">You write down or print the ${nw} words on a single sheet and keep it somewhere safe.</p>
        <div class="split-pro">✔ Immediate: no extra steps, no complications.<br>✔ Recoverable anywhere, in any wallet, without needing any program.</div>
        <div class="split-con">Worth knowing: if that sheet burns, gets wet or is stolen, you have lost everything.</div>
      </div>

      <div class="split-choice" id="bk-seq">
        <div class="split-head">✂️ Split sequentially </div>
        <p class="split-desc">The words are cut into consecutive groups, to be kept in different places. With 3 parts: the first ${Math.ceil(nw / 3)} words, then the next ones, then the last ones.</p>
        <div class="split-pro">✔ A thief who finds a single group gets nowhere.<br>✔ It is reassembled by hand by putting the groups in order: no software required, ever.</div>
        <div class="split-con">Worth knowing: <strong>all</strong> the parts are needed: losing one means losing the wallet.</div>
      </div>

      <div class="split-choice" id="bk-shamir">
        <div class="split-head">🔐 Threshold — Shamir</div>
        <p class="split-desc">Your ${nw} words <strong>are never written down anywhere</strong>. In their place the program creates several parts — five, for example — and you decide how many are needed to get them back: with 3 of 5, any three sheets bring back the original seed, identical.</p>
        <div class="split-pro">✔ You can <strong>lose some of them</strong> and still recover everything.<br>✔ Below the threshold the parts reveal <strong>nothing</strong>: that's a theorem, not an estimate of difficulty.</div>
        <div class="split-con">Worth knowing: each part looks like a ${nw}-word seed, but <strong>it is not a wallet</strong> — it is a fragment. And putting them back together needs this program, so keep a copy of the file together with the parts.</div>
      </div>

      <p class="hint" style="margin-top:12px">Can't decide? <strong>A single backup</strong> is perfectly fine to start with, or for small amounts. You'll move to splitting it when the sum starts to weigh.</p>
    </div></div>`;
  document.getElementById('bk-classic').addEventListener('click', () => {
    closeOverlay();
    renderApp();
    showToast('Wallet created. Now save your words somewhere safe.', 'success');
  });
  document.getElementById('bk-seq').addEventListener('click', () => { renderApp(); showClassicSplitSetup(); });
  document.getElementById('bk-shamir').addEventListener('click', () => { renderApp(); showShamirIntro(); });
}

/* ── PASSPHRASE STEP — always asked explicitly ── */
function showPassphraseStep() {
  const modeLabel = pendingConfig.useDice ? '🎲 With real dice' : '🖱️ Classic';
  const stdLabel = seedStandard === 'slip39'
    ? `SLIP-39 &middot; ${slipConfig.n} sheets, ${slipConfig.m} needed`
    : `BIP-39 &middot; ${pendingConfig.words} words`;
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <div class="ov-badge">${modeLabel} &middot; ${stdLabel}</div>
      <h3>🔑 Do you want to add a passphrase?</h3>
      <p>Besides the backup you can add a <strong>word or phrase of your own choosing</strong>. It's called a <em>passphrase</em>: it enters the calculation together with the words and gives rise to a completely different wallet.</p>
      <p><strong>If you forget it, the words alone are no longer enough:</strong> you get a different wallet, and nobody can reach your funds any more.${helpLink('g-passphrase', 'Learn more about the passphrase')}</p>
      <div class="ov-row" style="margin-top:16px">
        <button class="btn btn-primary" id="pp-yes">Add the passphrase</button>
        <button class="btn btn-outline" id="pp-no">Continue without</button>
      </div>
      <div class="ov-row" style="margin-top:10px">
        <button class="btn btn-ghost btn-small" id="pp-back">← Back</button>
      </div>
    </div></div>`;
  document.getElementById('pp-back').addEventListener('click', closeOverlay);
  document.getElementById('pp-no').addEventListener('click', () => {
    pendingConfig.passphrase = '';
    afterPassphrase();
  });
  document.getElementById('pp-yes').addEventListener('click', showPassphraseInput);
}

function showPassphraseInput() {
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <h3>🔑 Choose your passphrase</h3>
      <p>Type it twice: a typo here would mean a different wallet from the one you expect. It can be a phrase, a sentence, anything you'll remember.</p>
      <input type="password" id="inp-pass1" class="inp" placeholder="Your passphrase" autocomplete="off">
      <input type="password" id="inp-pass2" class="inp" placeholder="Type it again, identically" autocomplete="off" style="margin-top:10px">
      <label class="chk-row" style="margin-top:12px">
        <input type="checkbox" id="pp-show"><span>Show what I type</span>
      </label>
      ${seedStandard === 'slip39' ? `<p class="hint" style="margin-top:10px">${SLIP39_PASS_MSG}</p>` : ''}
      <div class="note-box" style="margin-top:12px">Keep it somewhere <strong>different</strong> from ${seedStandard === 'slip39' ? 'the sheets' : `the ${pendingConfig.words} words`}: that separation is what makes it useful. If you lose it, the funds are unrecoverable.</div>
      <div class="ov-row" style="margin-top:16px">
        <button class="btn btn-primary" id="pp-confirm">Confirm and continue →</button>
        <button class="btn btn-ghost btn-small" id="pp-back2">← Back</button>
      </div>
      <p id="pp-err" style="margin-top:8px"></p>
    </div></div>`;
  document.getElementById('pp-back2').addEventListener('click', showPassphraseStep);
  document.getElementById('pp-show').addEventListener('change', (e) => {
    const t = e.target.checked ? 'text' : 'password';
    document.getElementById('inp-pass1').type = t;
    document.getElementById('inp-pass2').type = t;
  });
  document.getElementById('pp-confirm').addEventListener('click', () => {
    const p1 = document.getElementById('inp-pass1').value || '';
    const p2 = document.getElementById('inp-pass2').value || '';
    const err = document.getElementById('pp-err');
    if (!p1) { err.innerHTML = '<span style="color:var(--danger)">The field is empty. Type a passphrase, or go back and continue without one.</span>'; return; }
    if (p1 !== p2) { err.innerHTML = "<span style=\"color:var(--danger)\">The two passphrases don't match. Please check.</span>"; return; }
    if (p1 !== p1.trim()) { err.innerHTML = '<span style="color:var(--danger)">The passphrase begins or ends with a space. A space is invisible on paper and easy to forget: remove it, or put it between two words.</span>'; return; }
    if (seedStandard === 'slip39' && !isSlip39Passphrase(p1)) { err.innerHTML = `<span style="color:var(--danger)">${SLIP39_PASS_MSG}</span>`; return; }
    pendingConfig.passphrase = p1;
    afterPassphrase();
  });
}

function afterPassphrase() {
  if (pendingConfig.useDice) showDiceIntro();
  else showTypingOverlay(null);
}

/* ════════════════════════════════════════════════════════════════
   DICE FLOW (optional) — guided screens
   ════════════════════════════════════════════════════════════════ */
function overlayRoot() { return document.getElementById('overlay-root'); }
function closeOverlay() { overlayRoot().innerHTML = ''; }

function showDiceIntro() {
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <div class="ov-badge">Source 1 of 4 &middot; Your dice</div>
      <h3>🎲 The randomness a computer cannot manufacture</h3>
      <p>A computer produces "random" numbers by running a program. A die rolling on the table does not: it obeys physics. It is the only source that no software bug, and no tampering, could ever predict.</p>
      <p class="ov-strong">How many dice do you have in front of you?</p>
      <div class="ov-row">
        <button class="btn btn-outline btn-large" id="dice-1">1 die</button>
        <button class="btn btn-outline btn-large" id="dice-2">2 dice</button>
      </div>
      <p class="hint" style="margin-top:10px">With two dice thrown together you record two numbers at a time. Identical dice cannot be told apart, so a few more throws are asked for: about 30 double rolls instead of 50 single ones for 12 words. Use <strong>real physical dice</strong> — never an app or a website that simulates them.</p>
      <div class="ov-row" style="margin-top:10px">
        <button class="btn btn-ghost btn-small" id="dice-back">← Back</button>
        <button class="btn btn-ghost btn-small" id="dice-cancel">Cancel</button>
      </div>
    </div></div>`;
  document.getElementById('dice-1').addEventListener('click', () => startDice(false));
  document.getElementById('dice-2').addEventListener('click', () => startDice(true));
  document.getElementById('dice-back').addEventListener('click', showPassphraseStep);
  document.getElementById('dice-cancel').addEventListener('click', closeOverlay);
}

function startDice(twoDice) {
  const bits = ENT_BYTES[pendingConfig.words] * 8;
  pendingDice = { rolls: [], needed: diceRollsNeeded(bits, twoDice), twoDice, first: null };
  renderDiceScreen();
}

function renderDiceScreen() {
  const d = pendingDice;
  const done = d.twoDice ? Math.floor(d.rolls.length / 2) : d.rolls.length;
  const pct = Math.min(100, Math.round(done / d.needed * 100));
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <h3>🎲 Roll${d.twoDice ? ' the dice' : ' the die'}</h3>
      <p>Roll${d.twoDice ? ' both dice together' : ' the die'} and press the number that comes up. About <strong>${d.needed}${d.twoDice ? ' double' : ''} rolls</strong> are needed to cover the ${pendingConfig.words} words you chose.</p>
      <div class="dice-counter">Roll <strong>${Math.min(done + 1, d.needed)}</strong> of ${d.needed}</div>
      <div class="progress"><div class="progress-fill" style="width:${pct}%"></div></div>
      ${d.twoDice ? `
        <p class="ov-strong">${d.first === null ? 'First die' : 'Second die'}</p>
      ` : ''}
      <div class="dice-grid">
        ${[1,2,3,4,5,6].map(n => `<button class="dice-btn" data-n="${n}">${'⚀⚁⚂⚃⚄⚅'[n-1]}<span>${n}</span></button>`).join('')}
      </div>
      <div class="ov-row" style="margin-top:14px">
        <button class="btn btn-ghost" id="dice-undo" ${d.rolls.length === 0 ? 'disabled' : ''}>↩ Undo last roll</button>
        <button class="btn btn-ghost btn-small" id="dice-back2">← Back</button>
        <button class="btn btn-ghost btn-small" id="dice-abort">Cancel everything</button>
      </div>
    </div></div>`;
  document.querySelectorAll('.dice-btn').forEach(b => b.addEventListener('click', () => {
    const n = parseInt(b.dataset.n);
    b.classList.add('dice-pop');
    if (pendingDice.twoDice && pendingDice.first === null) {
      pendingDice.first = n;
      renderDiceScreen();
      return;
    }
    if (pendingDice.twoDice) {
      pendingDice.rolls.push(pendingDice.first, n);
      pendingDice.first = null;
    } else {
      pendingDice.rolls.push(n);
    }
    const doneNow = pendingDice.twoDice ? Math.floor(pendingDice.rolls.length / 2) : pendingDice.rolls.length;
    if (doneNow >= pendingDice.needed) {
      overlayRoot().innerHTML = `
        <div class="ov"><div class="ov-card" style="text-align:center">
          <h3>✅ Dice recorded</h3>
          <p>Well done. Now let's add the other sources.</p>
        </div></div>`;
      setTimeout(() => showTypingOverlay(diceBytesFrom(pendingDice.rolls)), 900);
    } else {
      renderDiceScreen();
    }
  }));
  document.getElementById('dice-undo')?.addEventListener('click', () => {
    if (pendingDice.twoDice) {
      if (pendingDice.first !== null) pendingDice.first = null;
      else pendingDice.rolls.splice(-2, 2);
    } else pendingDice.rolls.pop();
    renderDiceScreen();
  });
  document.getElementById('dice-back2')?.addEventListener('click', () => { pendingDice = null; showDiceIntro(); });
  document.getElementById('dice-abort')?.addEventListener('click', () => { pendingDice = null; closeOverlay(); });
}

/* ════════════════════════════════════════════════════════════════
   KEYBOARD OVERLAY — free typing, adds to the mouse
   ════════════════════════════════════════════════════════════════ */
function showTypingOverlay(diceBytes) {
  typingCollector = createTypingCollector();
  typingCollector.start();
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <div class="ov-badge">Source 2 of ${pendingConfig.useDice ? '4' : '3'} &middot; Your keyboard</div>
      <h3>⌨️ Type at random. Really at random.</h3>
      <p>Hit the keys without thinking: letters, numbers, symbols, whatever comes. <strong>You won't have to remember any of it</strong> — only the rhythm counts, not the characters.</p>
      <p class="hint">The real ingredient isn't the characters but the <em>rhythm</em> of your fingers: every keystroke is measured to the millisecond, and those micro-pauses are yours alone.</p>
      <input type="password" id="type-inp" class="inp" style="margin-top:12px;font-size:16px;letter-spacing:3px" placeholder="Type here, without thinking…" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false">
      <div class="progress"><div class="progress-fill" id="type-fill" style="width:0%"></div></div>
      <p class="hint" style="text-align:center" id="type-status">0%</p>
      <div class="ov-row" style="margin-top:6px">
        <button class="btn btn-ghost btn-small" id="type-back">← Back</button>
      </div>
    </div></div>`;

  const inp = document.getElementById('type-inp');
  const fill = document.getElementById('type-fill');
  const status = document.getElementById('type-status');
  let finished = false;

  document.getElementById('type-back').addEventListener('click', () => {
    if (entropyPurpose === 'multisig' || entropyPurpose === 'multisolo') { closeOverlay(); return; }
    if (pendingConfig && pendingConfig.useDice && pendingDice) renderDiceScreen();
    else showPassphraseStep();
  });

  let lastValue = '';
  let countedOnKeydown = false;

  function record(key) {
    if (finished) return;
    typingCollector.feed(key);
    const pct = Math.round(typingCollector.progress() * 100);
    fill.style.width = pct + '%';
    status.textContent = pct + '%';
    if (pct >= 100) {
      finished = true;
      status.textContent = 'Collected. One more step…';
      const typeBytes = typingCollector.bytes();
      inp.value = ''; lastValue = ''; // the text is no longer needed: out of memory
      inp.blur();                     // lets the on-screen keyboard close
      // Open the next screen only if the user has not pressed Back meanwhile.
      setTimeout(() => { if (document.getElementById('type-inp') === inp) showMouseOverlay(diceBytes, typeBytes); }, 700);
    }
  }

  // Physical keyboards report the key that was pressed, and that is the
  // best source: it also covers keys that leave the text unchanged.
  inp.addEventListener('keydown', (e) => {
    if (finished) return;
    if (e.key === 'Tab') return;
    // On-screen keyboards on Android report EVERY key as "Unidentified"
    // with keyCode 229. Counting those would give a single distinct key
    // and the progress bar would stop at 10% for ever. The 'input'
    // handler below reads what was actually typed instead.
    if (!e.key || e.key === 'Unidentified' || e.keyCode === 229) return;
    countedOnKeydown = true;
    record(e.key);
  });

  // On-screen keyboards: the characters are only visible here.
  inp.addEventListener('input', () => {
    if (finished) return;
    const value = inp.value;
    if (countedOnKeydown) { countedOnKeydown = false; lastValue = value; return; }
    let added = '';
    if (value.length > lastValue.length) {
      added = value.startsWith(lastValue) ? value.slice(lastValue.length) : value.slice(-1);
    }
    lastValue = value;
    if (added) for (const ch of added) record(ch);
    else record('\b');   // a deletion is a keystroke too, with its own timing
  });

  setTimeout(() => {
    inp.focus();
    // On a phone the on-screen keyboard covers the lower half of the
    // screen: bring the field and its progress bar back into view.
    if (inp.scrollIntoView) setTimeout(() => inp.scrollIntoView({ block: 'center' }), 400);
  }, 100);
}


function showMouseOverlay(diceBytes, typeBytes) {
  mouseCollector = createMouseCollector();
  mouseCollector.start();
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <div class="ov-badge">Last source &middot; Your hand</div>
      <h3>✍️ Now draw some chaos</h3>
      <p>Drag your finger — or the mouse — around inside the box. Every curve, every hesitation, every change of direction becomes randomness that nobody could reproduce.</p>
      <p class="hint">It is added to everything else${typeBytes ? ' — keyboard' : ''}${diceBytes ? ', dice' : ''} and the browser generator. No source replaces the others: they are mixed together.</p>
      <div class="mouse-area" id="mouse-area">
        <span class="mouse-hint">Move around in here ✋</span>
        <canvas id="mouse-trail" width="10" height="10"></canvas>
      </div>
      <div class="progress"><div class="progress-fill" id="mouse-fill" style="width:0%"></div></div>
      <p class="hint" style="text-align:center" id="mouse-status">0%</p>
      <div class="ov-row" style="margin-top:6px">
        <button class="btn btn-ghost btn-small" id="mouse-back">← Back</button>
      </div>
    </div></div>`;

  document.getElementById('mouse-back').addEventListener('click', () => {
    if (entropyPurpose === 'multisig' || entropyPurpose === 'multisolo') { closeOverlay(); return; }
    showTypingOverlay(diceBytes);
  });

  const area = document.getElementById('mouse-area');
  const fill = document.getElementById('mouse-fill');
  const status = document.getElementById('mouse-status');
  const canvas = document.getElementById('mouse-trail');
  const resize = () => { canvas.width = area.clientWidth; canvas.height = area.clientHeight; };
  resize();
  const ctx = canvas.getContext('2d');
  let last = null;
  let finished = false;

  area.addEventListener('pointermove', (e) => {
    if (finished) return;
    const r = area.getBoundingClientRect();
    const x = e.clientX - r.left, y = e.clientY - r.top;
    mouseCollector.feed(e.clientX, e.clientY);
    if (last && ctx) {
      ctx.strokeStyle = 'rgba(247,147,26,0.5)';
      ctx.lineWidth = 2; ctx.lineCap = 'round';
      ctx.beginPath(); ctx.moveTo(last.x, last.y); ctx.lineTo(x, y); ctx.stroke();
    }
    last = { x, y };
    const p = mouseCollector.progress();
    const pct = Math.round(p * 100);
    fill.style.width = pct + '%';
    status.textContent = pct + '%';
    // NB: the comparison uses the same rounded value shown to the user,
    // otherwise the bar can look full (99.7% → "100%") without ever completing.
    if (pct >= 100 && !finished) {
      finished = true;
      status.textContent = 'Done. Creating your wallet…';
      setTimeout(() => { if (document.getElementById('mouse-area') === area) finishGeneration(diceBytes, typeBytes); }, 500);
    }
  });
}

function finishGeneration(diceBytes, typeBytes) {
  let mouseBytes = null;
  try {
    const nBytes = ENT_BYTES[pendingConfig.words];
    mouseBytes = mouseCollector.bytes();
    const entropy = combineEntropy(nBytes, { mouse: mouseBytes, dice: diceBytes, keys: typeBytes });

    if (entropyPurpose === 'multisig') {
      closeOverlay();
      finishMultisigKey(entropy);
      return;
    }

    if (entropyPurpose === 'multisolo') {
      finishMultiSoloKeys(entropy, mouseBytes, typeBytes, diceBytes);
      return;
    }

    if (seedStandard === 'slip39') { finishSlip39(entropy); return; }

    currentEntropy = entropy;
    currentMnemonic = entropyToMnemonic(entropy, wordlist);
    currentSeed = mnemonicToSeedSync(currentMnemonic, pendingConfig.passphrase || '');
    generatedAddresses = {};
    shamirParts = null; shamirMeta = null;
    showBackupChoice();
  } catch (err) {
    closeOverlay();
    if (String(err.message).startsWith('RNG_ANOMALY')) {
      overlayRoot().innerHTML = `
        <div class="ov"><div class="ov-card">
          <h3 style="color:var(--danger)">⛔ Generation stopped</h3>
          <p>Your browser random number generator produced an anomalous result. <strong>Do not proceed</strong> — try again, and if the problem persists do not use this device to create a wallet.</p>
          <button class="btn btn-outline" id="rng-close">Close</button>
        </div></div>`;
      document.getElementById('rng-close').addEventListener('click', closeOverlay);
    } else {
      showToast('Error: ' + err.message, 'error');
    }
  } finally {
    // The source digests and the dice rolls are no longer needed: overwrite
    // them (best effort — JavaScript cannot guarantee that no copy remains).
    for (const b of [mouseBytes, diceBytes, typeBytes]) if (b) b.fill(0);
    if (pendingDice) { pendingDice.rolls.fill(0); pendingDice = null; }
  }
}

/* ════════════════════════════════════════════════════════════════
   WALLET VIEW: protected seed, backup check, chains, results,
   threshold backup (Shamir)
   ════════════════════════════════════════════════════════════════ */
let watchRevealed = false;
let watchInPrint = false;

/* If the xpub panel is open and the format or networks change, it must be realigned:
   otherwise it would show codes for a format that is no longer selected. */
function syncWatchPanel() {
  const panel = document.getElementById('watch-panel');
  const btn = document.getElementById('btn-watch');
  if (!panel) return;
  if (!watchRevealed) return;
  if (!btcAccount) {                       // Bitcoin deselected: close
    watchRevealed = false; watchInPrint = false; panel.innerHTML = '';
    if (btn) btn.innerHTML = '👁️ View xpub and descriptor';
    return;
  }
  panel.innerHTML = renderWatchPanel();
  wireWatchCard();
}

function wireWatchCard() {
  document.getElementById('wc-print')?.addEventListener('change', (e) => { watchInPrint = e.target.checked; });
  document.getElementById('wc-copy-desc')?.addEventListener('click', async () => {
    try { await copyToClipboard(btcAccount.descriptor); showToast('Descriptor copied.', 'success'); } catch (_) {}
  });
  document.getElementById('wc-copy-xpub')?.addEventListener('click', async () => {
    try { await copyToClipboard(btcAccount.xpub); showToast('xpub copied.', 'success'); } catch (_) {}
  });
}

function renderWatchPanel() {
  const a = btcAccount;
  return `
    <div class="watch-panel">
      <div class="wp-head">👁️ Read-only codes</div>
      <p class="hint" style="margin-bottom:10px">They cannot spend: they are only for watching.${help('watch')}</p>
      <div class="wc-explain">
        <div class="wc-item">
          <span class="wc-name">xpub</span>
          <span class="wc-txt">The "extended public key". On its own it generates all your Bitcoin addresses, but no signatures.</span>
        </div>
        <div class="wc-item">
          <span class="wc-name">descriptor</span>
          <span class="wc-txt">The xpub plus the instructions on how to use it: address format and path. This is what you paste into <strong>Sparrow</strong> or <strong>Electrum</strong> to see balance and movements in real time, while the seed stays safe.</span>
        </div>
      </div>
      <div class="detail-label" style="margin-top:12px">Descriptor</div>
      <div class="addr-copy-row"><code class="detail-value" style="font-size:10.5px">${escapeHtml(a.descriptor)}</code>
        <button class="btn btn-icon" id="wc-copy-desc" title="Copy">📋</button></div>
      <details class="adv" style="margin-top:10px"><summary>See the raw xpub as well</summary>
        <div class="adv-body">
          <div class="detail-label">Account xpub (${escapeHtml(a.path)})</div>
          <div class="addr-copy-row"><code class="detail-value" style="font-size:10.5px">${escapeHtml(a.xpub)}</code>
            <button class="btn btn-icon" id="wc-copy-xpub" title="Copy">📋</button></div>
          <p class="hint" style="margin-top:8px">Standard ${escapeHtml(a.format.std)} &middot; Fingerprint ${escapeHtml(a.fingerprint)} &middot; Format ${escapeHtml(a.format.label)}</p>
        </div>
      </details>
      <label class="chk-row wc-print" style="margin-top:12px">
        <input type="checkbox" id="wc-print" ${watchInPrint ? 'checked' : ''}>
        <span>Include these codes in the printed summary</span>
      </label>
      <p class="hint" style="margin-top:6px">Anyone reading the sheet will be able to see every Bitcoin movement of this wallet, present and future, but will not be able to spend anything.</p>
    </div>`;
}

/* Permanent card with the generated parts: it stays available in the
   wallet, so they are not lost when the creation screen closes. */
function renderPartsCard() {
  const { n, m, code, classic } = shamirMeta;
  const rows = shamirParts.map((p, i) => {
    const wl = classic ? p.words : p.words.split(' ');
    const off = classic ? p.from - 1 : 0;
    const open = shamirRevealed[i];
    return `
      <div class="key-block">
        <div class="key-head">
          <span class="key-title">${classic ? '✂️' : '🔐'} Part ${p.x} of ${n}</span>
          <span class="key-tag">${classic ? `words ${p.from}–${p.to}` : `${wl.length} words`}</span>
        </div>
        <div class="part-words">${wl.map((w, k) => `<span class="part-word"><em>${off + k + 1}</em>${open ? escapeHtml(w) : '••••••••'}</span>`).join('')}</div>
        <div class="ov-row" style="margin-top:10px">
          <button class="btn btn-outline btn-small pc-reveal" data-i="${i}">${open ? '🙈 Hide' : '👁️ Reveal'}</button>
          <button class="btn btn-outline btn-small pc-copy" data-i="${i}">📋 Copy</button>
          <button class="btn btn-outline btn-small pc-print" data-i="${i}">🖨️ Print</button>
          <button class="btn btn-outline btn-small pc-check" data-i="${i}">✅ Check again</button>
        </div>
      </div>`;
  }).join('');

  return `
    <div class="card">
      <div class="card-header"><span class="step-badge">${classic ? '✂️' : '🔐'}</span>
        <h2>Your ${n} parts</h2>
        <span class="seed-badge">✓ Protected</span></div>
      <p style="margin-bottom:6px">${classic
        ? `The seed is split into ${n} consecutive groups: <strong>all of them are needed</strong> to reassemble it.`
        : `Only <strong>${m} of ${n}</strong> are needed to get the seed back. Keep them in different places.`}</p>
      <p class="hint" style="margin-bottom:14px">They stay here until you close the page or press Generate a new wallet.</p>
      ${code ? `<div class="ok-box" style="margin-bottom:14px">Verification code: <strong>${escapeHtml(code)}</strong> &mdash; write it on every sheet. It confirms, at recovery time, that the reassembled seed is the right one.</div>` : ''}
      <div class="keys-list">${rows}</div>
      <div class="ov-row" style="margin-top:16px">
        <button class="btn btn-primary" id="pc-print-all">🖨️ Print all parts</button>
        <button class="btn btn-ghost btn-small" id="pc-forget">✕ Hide from the page</button>
      </div>
    </div>`;
}

function wirePartsCard() {
  if (!shamirParts) return;
  const { n, m, code, classic } = shamirMeta;
  document.querySelectorAll('.pc-reveal').forEach(b => b.addEventListener('click', () => {
    const i = +b.dataset.i; shamirRevealed[i] = !shamirRevealed[i]; renderApp();
  }));
  document.querySelectorAll('.pc-copy').forEach(b => b.addEventListener('click', async () => {
    const p = shamirParts[+b.dataset.i];
    const str = classic ? p.words.join(' ') : p.words;
    try { await copyToClipboard(str); showToast(`Part ${p.x} copied.`, 'success'); }
    catch (_) { showToast('Copy failed.', 'error'); }
  }));
  document.querySelectorAll('.pc-print').forEach(b => b.addEventListener('click', () => {
    printShamirPart(shamirParts[+b.dataset.i], n, m, code, classic);
  }));
  document.querySelectorAll('.pc-check').forEach(b => b.addEventListener('click', () => {
    const p = shamirParts[+b.dataset.i];
    const str = classic ? p.words.join(' ') : p.words;
    showVerifyBackup(str, `Part ${p.x} of ${n}`);
  }));
  document.getElementById('pc-print-all')?.addEventListener('click', () => printAllShamirParts(n, m, code, classic));
  document.getElementById('pc-forget')?.addEventListener('click', () => {
    shamirParts = null; shamirMeta = null; shamirRevealed = [];
    seedUnlocked = false;
    renderApp();
    showToast('Parts hidden. The wallet is unchanged.', 'info');
  });
}

function renderWalletView() {
  const nWords = currentMnemonic.split(' ').length;
  const split = !!shamirParts;              // the seed has been split: the parts take precedence
  return `
    <section class="wallet-section">
      ${split ? renderPartsCard() : ''}

      <div class="card seed-card">
        <div class="card-header">
          <span class="step-badge">${split ? '🔑' : '1'}</span>
          <h2>${split ? 'The original seed' : 'Your secret words'}</h2>
          <span class="status-ok"><svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M3 8l3.5 3.5L13 5" stroke-linecap="round" stroke-linejoin="round"/></svg> Protected</span>
        </div>
        ${split ? `
          <p style="margin-bottom:6px">These are the <strong>${nWords} complete words</strong> from which the parts above are born. Having split them is precisely so you never have to write them out in full: <strong>normally you don't need them</strong>, and you will find them again by reassembling the parts when the time comes.</p>
          <p class="hint" style="margin-bottom:14px">They stay hidden. Reveal them only if you have decided to keep them anyway, or for one last check before closing.</p>
        ` : `
          <p class="hint" style="margin-bottom:14px">They stay covered until you reveal them. They are the only key to your wallet.</p>
        `}
        ${(split && !seedUnlocked) ? `
          <div class="seed-locked">
            <div class="sl-icon">🔒</div>
            <div class="sl-text">The complete seed is hidden because you split it into parts.</div>
            <button class="btn btn-outline" id="btn-unlock-seed">🔓 Reveal the original seed</button>
          </div>
        ` : `
          <div class="seed-display"><div class="seed-masked" id="seed-masked">
            ${Array(nWords).fill(0).map((_, i) => `<span class="word-slot"><em>${i + 1}</em>••••••••</span>`).join('')}
          </div></div>
        `}
        <div class="seed-actions"${(split && !seedUnlocked) ? ' style="display:none"' : ''}>
          <button id="btn-reveal-seed" class="btn btn-outline">👁️ Reveal the words</button>
          <button id="btn-copy-seed" class="btn btn-outline">📋 Copy</button>
          <button id="btn-print-seed" class="btn btn-outline">🖨️ Print the Seed Card</button>
          <button id="btn-metal" class="btn btn-outline">🔢 Powers-of-2 backup</button>
          <button id="btn-verify-backup" class="btn btn-outline">✅ Check the seed again</button>
          <button id="btn-split-seed" class="btn btn-outline">🧩 Split into several parts</button>
        </div>
        <!-- Actions that never expose the seed stay available even while it is locked. -->
        <div class="seed-actions seed-actions-2">
          <button id="btn-watch" class="btn btn-outline">👁️ View xpub and descriptor</button>
          <button id="btn-reset" class="btn btn-newwallet">✨ Generate a new wallet</button>
        </div>
        <div id="watch-panel"></div>
        ${pendingConfig && pendingConfig.passphrase ? `<p class="seed-warning">🔑 You set a passphrase: it is as important as the words themselves. Without it this wallet cannot be recovered.</p>` : ''}
        <p class="seed-warning">⚠ Whoever holds these words holds your funds. Whoever loses them loses access, with no way back.</p>
      </div>

      <div class="card chain-card">
        <div class="card-header">
          <span class="step-badge">2</span>
          <h2>Choose your networks${help('networks')}</h2>
          <button id="btn-select-all" class="btn btn-ghost btn-small">Select all</button>
        </div>
        <div class="chain-grid">
          ${CHAINS.map(c => `
            <label class="chain-option">
              <input type="checkbox" id="chk-${c.id}" value="${c.id}" />
              <div class="chain-box"><span class="chain-icon">${c.icon}</span><span class="chain-name">${c.name}</span><span class="chain-tag">${c.tag}</span></div>
            </label>`).join('')}
        </div>
        <div id="btc-format-box" class="btc-fmt-box" style="display:none">
          <details class="adv"><summary>Bitcoin address format &mdash; ${escapeHtml(BTC_FORMATS[btcFormat].label)} (${escapeHtml(BTC_FORMATS[btcFormat].tag)})</summary>
          <div class="adv-body">
          <p class="hint" style="margin-bottom:10px">The default format is right for almost every case. You can change it if you need compatibility with older services or want to try Taproot.${help('btcformat')}</p>
          <div class="fmt-grid" id="fmt-grid">
            ${Object.values(BTC_FORMATS).map(f => `
              <button class="fmt-card ${f.id === btcFormat ? 'fmt-active' : ''}" data-fmt="${f.id}">
                <span class="fmt-label">${f.label}</span>
                <span class="fmt-tag">${f.tag}</span>
                <span class="fmt-desc">${f.desc}</span>
              </button>`).join('')}
          </div>
          </div>
          </details>
        </div>
        <button id="btn-derive" class="btn btn-primary">Calculate the addresses</button>
      </div>

      <div id="results-container"></div>
    </section>
  `;
}

function wireWalletView() {
  seedRevealed = false; // the view is always redrawn masked
  document.getElementById('btn-reveal-seed')?.addEventListener('click', handleRevealSeed);
  document.getElementById('btn-copy-seed')?.addEventListener('click', handleCopySeed);
  document.getElementById('btn-print-seed')?.addEventListener('click', handlePrintSeed);
  document.getElementById('btn-metal')?.addEventListener('click', showMetalIntro);
  document.getElementById('btn-watch')?.addEventListener('click', () => {
    const panel = document.getElementById('watch-panel');
    if (watchRevealed) {                       // second press: close again
      watchRevealed = false; panel.innerHTML = '';
      document.getElementById('btn-watch').innerHTML = '👁️ View xpub and descriptor';
      return;
    }
    try {
      if (!btcAccount) btcAccount = btcAccountInfo(currentSeed, btcFormat);
      watchRevealed = true;
      panel.innerHTML = renderWatchPanel();
      wireWatchCard();
      document.getElementById('btn-watch').innerHTML = '🙈 Hide xpub and descriptor';
      panel.scrollIntoView?.({ behavior: 'smooth', block: 'nearest' });
    } catch (err) { showToast('Error: ' + err.message, 'error'); }
  });

  document.getElementById('btn-verify-backup')?.addEventListener('click', () => showVerifyBackup());
  document.getElementById('btn-split-seed')?.addEventListener('click', showSplitChooser);
  document.getElementById('btn-unlock-seed')?.addEventListener('click', () => {
    seedUnlocked = true; seedRevealed = false; renderApp();
  });
  wirePartsCard();
  document.getElementById('btn-reset')?.addEventListener('click', handleReset);
  document.getElementById('btn-derive')?.addEventListener('click', handleDerive);
  document.getElementById('btn-select-all')?.addEventListener('click', handleSelectAll);
  const syncFmtBox = () => {
    const box = document.getElementById('btc-format-box');
    if (box) box.style.display = document.getElementById('chk-btc')?.checked ? 'block' : 'none';
  };
  document.getElementById('chk-btc')?.addEventListener('change', syncFmtBox);
  document.querySelectorAll('.fmt-card').forEach(b => b.addEventListener('click', () => onFormatCard(b)));
  syncFmtBox();
}

let seedRevealed = false;
function handleRevealSeed() {
  if (!currentMnemonic) return;
  const box = document.getElementById('seed-masked');
  const btn = document.getElementById('btn-reveal-seed');
  seedRevealed = !seedRevealed;
  const words = currentMnemonic.split(' ');
  box.innerHTML = words
    .map((w, i) => `<span class="word-slot"><em>${i + 1}</em>${seedRevealed ? escapeHtml(w) : '••••••••'}</span>`).join('');
  btn.innerHTML = seedRevealed ? '🙈 Hide' : '👁️ Reveal the words';
  if (seedRevealed) showToast('Words in the clear. Check that nobody is watching.', 'info');
}

async function handleCopySeed() {
  if (!currentMnemonic) return;
  const btn = document.getElementById('btn-copy-seed');
  try {
    await copyToClipboard(currentMnemonic);
    const orig = btn.innerHTML;
    btn.innerHTML = '✔ Copied!';
    btn.classList.add('btn-success');
    showToast('Words copied. Paste them where you need them, then clear the clipboard.', 'success');
    setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('btn-success'); }, 2500);
  } catch (_) {
    showToast('Could not copy. Check your browser permissions.', 'error');
  }
}

function handlePrintSeed(mnemonic) {
  const words = (typeof mnemonic === 'string' ? mnemonic : currentMnemonic).split(' ');
  printHTML(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Document</title><style>
*{margin:0;padding:0;box-sizing:border-box}@page{size:A4;margin:20mm}
body{font-family:'Courier New',monospace;background:#fff;color:#000}
.card{border:2px solid #000;border-radius:5px;padding:26px 30px}
.brk{page-break-after:always}
.title{text-align:center;font-size:15px;font-weight:bold;letter-spacing:4px;text-transform:uppercase;padding-bottom:14px;margin-bottom:20px;border-bottom:1px solid #ccc}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.w{border:1px solid #bbb;border-radius:3px;padding:8px 9px;font-size:12px}
.w i{color:#999;font-style:normal;margin-right:7px;font-size:10px}
</style></head><body><div class="card">
<div class="title">Document</div>
<div class="grid">${words.map((w, i) => `<div class="w"><i>${i + 1}</i>${escapeHtml(w)}</div>`).join('')}</div>
</div></body></html>`);
}

/* Forget every value tied to the wallet on screen, so nothing from one
   wallet (parts, xpub, extra addresses, passphrase flag) can ever be shown
   next to another one. */
function resetWalletState() {
  currentMnemonic = null; currentSeed = null; currentEntropy = null;
  generatedAddresses = {}; shamirParts = null; shamirMeta = null; shamirRevealed = [];
  btcExtra = null; btcAccount = null; seedRevealed = false; seedUnlocked = false;
  watchRevealed = false; watchInPrint = false;
  slipShares = null; slipSecret = null; slipConfig = null; slipRevealed = [];
  pendingConfig = null; pendingDice = null;
}

/* "Generate a new wallet": nothing secret from this session stays in the
   page — the wallet, the Check tab, the multisig keys, the print windows. */
function clearEverything() {
  resetWalletState();
  vfSeed = null; vfMnemonic = null; vfResults = null; vfExtra = null; vfAccount = null; csResults = null;
  msMyXpub = null; msSoloSeeds = null; msSoloVault = null; msSoloRevealed = []; msSoloConfig = null;
  recParts = [{}, {}, {}];
  while (printWindows.length) { try { printWindows.pop().close(); } catch (_) {} }
}

function handleReset() {
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card ov-narrow">
      <h3>Generate a new wallet?</h3>
      <p>The current wallet will be removed from this page and cannot be brought back here — together with anything else still open in this session: seeds being checked, multisig keys, print windows. Only proceed if you have already saved the words safely.</p>
      <div class="ov-row" style="margin-top:18px">
        <button class="btn btn-outline" id="rs-no">Cancel</button>
        <button class="btn btn-primary" id="rs-yes">Yes, generate a new wallet</button>
      </div>
    </div></div>`;
  document.getElementById('rs-no').addEventListener('click', closeOverlay);
  document.getElementById('rs-yes').addEventListener('click', () => {
    clearEverything();
    genPath = null; ctrlPath = null; shamirMode = null; msMode = null;
    closeOverlay();
    renderApp();
    showToast('Everything removed from the page.', 'info');
  });
}

function handleSelectAll() {
  const cbs = CHAINS.map(c => document.getElementById('chk-' + c.id));
  const all = cbs.every(cb => cb?.checked);
  cbs.forEach(cb => { if (cb) cb.checked = !all; });
  const btn = document.getElementById('btn-select-all');
  if (btn) btn.textContent = all ? 'Select all' : 'Deselect all';
  const box = document.getElementById('btc-format-box');
  if (box) box.style.display = document.getElementById('chk-btc')?.checked ? 'block' : 'none';
}

/* Changing the Bitcoin format recalculates what is on screen: addresses of
   two formats must never end up in the same list (or the same printout). */
function onFormatCard(b) {
  document.querySelectorAll('.fmt-card').forEach(x => x.classList.remove('fmt-active'));
  b.classList.add('fmt-active');
  if (btcFormat === b.dataset.fmt) return;
  btcFormat = b.dataset.fmt;
  const sum = b.closest('details')?.querySelector('summary');
  if (sum) sum.textContent = `Bitcoin address format — ${BTC_FORMATS[btcFormat].label} (${BTC_FORMATS[btcFormat].tag})`;
  if (Object.keys(generatedAddresses).length) handleDerive();
}

async function handleDerive() {
  if (!currentSeed) return;
  const selected = CHAINS.map(c => c.id).filter(id => document.getElementById('chk-' + id)?.checked);
  if (selected.length === 0) { showToast('Select at least one network to continue.', 'error'); return; }
  const btn = document.getElementById('btn-derive');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Calculating…';
  await new Promise(r => setTimeout(r, 150));
  try {
    generatedAddresses = deriveAll(currentSeed, selected, btcFormat);
    btcExtra = null;
    btcAccount = selected.includes('btc') ? btcAccountInfo(currentSeed, btcFormat) : null;
    syncWatchPanel();
  }
  catch (err) { showToast('Error: ' + err.message, 'error'); }
  btn.disabled = false; btn.innerHTML = 'Calculate the addresses';
  renderResults();
}

function renderResults() {
  const container = document.getElementById('results-container');
  const entries = Object.values(generatedAddresses);
  if (!entries.length) { container.innerHTML = ''; return; }
  container.innerHTML = `
    <div class="card results-card" id="results-card">
      <div class="card-header"><span class="step-badge">3</span><h2>Your public addresses</h2></div>
      <p class="hint" style="margin-bottom:16px">They are made to be shared: use them to <strong>receive</strong> funds, with no risk at all. The secret words stay with you.</p>
      <div class="addresses-list">
        ${entries.map(e => `
          <div class="address-item">
            <div class="address-header"><span class="addr-icon">${escapeHtml(e.icon)}</span>
              <div class="address-header-text"><strong>${escapeHtml(e.name)}</strong>
                ${e.evmChains ? `<div class="evm-tags">${e.evmChains.map(c => `<span class="evm-tag">${escapeHtml(c)}</span>`).join('')}</div>` : ''}
              </div>
            </div>
            <div class="address-details">
              <details class="adv"><summary>Technical details</summary>
                <div class="detail-row" style="margin-top:8px"><span class="detail-label">Derivation Path</span><code class="detail-value path-value">${escapeHtml(e.path)}</code></div>
              </details>
              <div class="detail-row"><span class="detail-label">Address</span>
                <div class="addr-copy-row"><code class="detail-value addr-value">${escapeHtml(e.address)}</code>
                  <button class="btn btn-icon btn-copy-addr" data-addr="${escapeHtml(e.address)}" title="Copy address">📋</button>
                </div>
              </div>
            </div>
            <div class="address-qr" id="qr-${e.id}"><div class="qr-loading">Generating the QR…</div></div>
            ${e.id === 'btc' ? `
              <div class="btc-more" id="btc-more">
                ${btcExtra ? `
                  <div class="more-head">Receiving addresses, in order</div>
                  <p class="hint" style="margin-bottom:10px">They all belong to the same wallet. Using a different one for each payment makes it harder, for anyone watching the blockchain, to link your incoming payments together.</p>
                  <div class="more-list">
                    ${btcExtra.map(a => `
                      <div class="more-row">
                        <span class="more-idx">#${a.index}</span>
                        <code class="more-addr">${escapeHtml(a.address)}</code>
                        <button class="btn btn-icon btn-copy-addr" data-addr="${escapeHtml(a.address)}" title="Copy">📋</button>
                      </div>`).join('')}
                  </div>
                  <div class="ov-row" style="margin-top:10px">
                    <button class="btn btn-ghost btn-small" id="btn-more-btc">Show 10 more</button>
                    <button class="btn btn-ghost btn-small" id="btn-print-more">🖨️ Print the list</button>
                  </div>
                ` : `
                  <button class="btn btn-outline btn-small" id="btn-show-more">➕ Show more Bitcoin addresses</button>
                  <p class="hint" style="margin-top:8px">Bitcoin lets you generate endless addresses from the same wallet: using a new one for each payment improves privacy. On the other networks, however, you <strong>always use the same address</strong>: that is normal and correct.</p>
                `}
              </div>` : ''}
          </div>`).join('')}
      </div>

      <button id="btn-print-report" class="btn btn-primary btn-large btn-full">🖨️ Print the summary</button>
    </div>`;
  entries.forEach(async (e) => {
    const c = document.getElementById(`qr-${e.id}`);
    if (!c) return;
    try { c.innerHTML = `<img src="${await generateQR(e.address)}" alt="QR ${escapeHtml(e.symbol)}" />`; }
    catch (_) { c.innerHTML = '<span class="qr-error">QR error</span>'; }
  });
  document.getElementById('btn-print-report')?.addEventListener('click', printReport);
  document.getElementById('btn-show-more')?.addEventListener('click', () => {
    const master = HDKey.fromMasterSeed(new Uint8Array(currentSeed));
    btcExtra = deriveBTCMany(master, btcFormat, 0, 10);
    renderResults();
  });
  document.getElementById('btn-more-btc')?.addEventListener('click', () => {
    const master = HDKey.fromMasterSeed(new Uint8Array(currentSeed));
    btcExtra = btcExtra.concat(deriveBTCMany(master, btcFormat, btcExtra.length, 10));
    renderResults();
  });
  document.getElementById('btn-print-more')?.addEventListener('click', printBtcList);
  document.querySelectorAll('.btn-copy-addr').forEach(b => b.addEventListener('click', async (ev) => {
    try { await copyToClipboard(ev.currentTarget.dataset.addr); showToast('Address copied.', 'success'); }
    catch (_) { showToast('Copy failed', 'error'); }
  }));
  setTimeout(() => document.getElementById('results-card')?.scrollIntoView?.({ behavior: 'smooth', block: 'start' }), 100);
}

/* ══════════════════════════════════════════════════════════════
   POWERS-OF-2 BACKUP — binary grid.
   Every BIP-39 word has a number from 1 to 2048. The number is
   obtained by adding up the marked columns. 1-based numbering:
   this way no row is ever empty (with 0-based numbering "abandon"
   would have no marks, indistinguishable from an unfilled row).
   ══════════════════════════════════════════════════════════════ */
function showMetalIntro() {
  const nw = currentMnemonic.split(' ').length;
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <h3>🔢 Powers-of-2 backup</h3>
      <p>Instead of the words, <strong>only dots on a grid</strong>: every word becomes a sum of powers of two.${helpLink('g-powers', 'Learn more about powers-of-2 backup')}</p>

      <div class="metal-demo">
        <div class="metal-demo-head">How it works</div>
        <p>Every word in the BIP-39 dictionary has a number from 1 to 2048. That number is written by marking some boxes: <strong>adding them up gives back the number</strong>, and looking that number up in the dictionary gives back the word.</p>
        <div class="metal-demo-row">
          <span class="mdr-label">Example &mdash; the 2045th word of the dictionary</span>
          <span class="mdr-cells">1024 + 512 + 256 + 128 + 64 + 32 + 16 + 8 + 4 + 1 = <strong>2045</strong></span>
        </div>
      </div>

      <p><strong>The words don't appear on the sheet</strong>, nor do the numbers: only the dots. At recovery time it will be up to you to add the columns and look up the words.</p>

      <div class="ok-box" style="margin-top:12px">
        <strong>You will need the numbered dictionary</strong> to turn numbers into words. You'll find it in this program, but it's worth printing it below and keeping it <em>separately</em> from the grid: on its own it reveals nothing, it's a public list identical for everyone.
      </div>

      <div class="ov-row" style="margin-top:18px">
        <button class="btn btn-primary" id="mt-print">🖨️ Print the grid</button>
        <button class="btn btn-outline" id="mt-list">📖 Print the numbered dictionary</button>
      </div>
      <div class="ov-row" style="margin-top:10px">
        <button class="btn btn-ghost btn-small" id="mt-close">← Back to wallet</button>
      </div>
    </div></div>`;
  document.getElementById('mt-close').addEventListener('click', closeOverlay);
  document.getElementById('mt-print').addEventListener('click', printMetalSheet);
  document.getElementById('mt-list').addEventListener('click', printWordlistIndex);
}

function printMetalSheet() {
  let rows;
  try { rows = metalRows(currentMnemonic); }
  catch (e) { showToast(e.message, 'error'); return; }
  const head = METAL_COLS.map(c => `<th class="cn">${c}</th>`).join('');
  const body = rows.map(r => `
    <tr>
      <td class="pos">${r.pos}</td>
      ${r.marks.map(m => `<td class="cell${m ? ' on' : ''}">${m ? '●' : ''}</td>`).join('')}
    </tr>`).join('');
  printHTML(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Document</title><style>
*{margin:0;padding:0;box-sizing:border-box}@page{size:A4;margin:14mm}
body{font-family:'Courier New',monospace;background:#fff;color:#000}
table{width:100%;border-collapse:collapse}
th,td{border:1px solid #999;text-align:center;font-size:10px;padding:4px 1px}
th{background:#eee;font-size:9px;width:7.6%}
td.pos{width:28px;background:#f4f4f4;color:#666;font-weight:bold}
td.cell{height:24px;font-size:13px}
</style></head><body>
<table>
<tr><th></th>${head}</tr>
${body}
</table>
</body></html>`);
}

function printWordlistIndex() {
  const perCol = 103, cols = 5;
  const total = wordlist.length;
  let pages = '';
  for (let start = 0; start < total; start += perCol * cols) {
    const chunk = [];
    for (let c = 0; c < cols; c++) {
      const from = start + c * perCol;
      const items = [];
      for (let i = from; i < Math.min(from + perCol, total); i++) {
        items.push(`<div class="wi"><span class="wn">${i + 1}</span>${escapeHtml(wordlist[i])}</div>`);
      }
      if (items.length) chunk.push(`<div class="col">${items.join('')}</div>`);
    }
    pages += `<div class="pg"><div class="ph">${start + 1}–${Math.min(start + perCol * cols, total)}</div><div class="cols">${chunk.join('')}</div></div>`;
  }
  printHTML(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>List</title><style>
*{margin:0;padding:0;box-sizing:border-box}@page{size:A4;margin:10mm}
body{font-family:'Courier New',monospace;background:#fff;color:#000}
.pg{page-break-after:always}
.pg:last-child{page-break-after:auto}
.ph{text-align:center;font-size:10px;letter-spacing:2px;text-transform:uppercase;padding-bottom:5px;margin-bottom:6px;border-bottom:1.5px solid #000}
.cols{display:flex;gap:8px}
.col{flex:1}
.wi{font-size:7.6px;line-height:1.62;display:flex;gap:4px;border-bottom:1px dotted #e0e0e0}
.wn{color:#888;min-width:26px;text-align:right}
</style></head><body>${pages}
</body></html>`);
}

function printBtcList() {
  const f = BTC_FORMATS[btcFormat];
  printHTML(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Addresses</title><style>
*{margin:0;padding:0;box-sizing:border-box}@page{size:A4;margin:16mm}
body{font-family:'Courier New',monospace;background:#fff;color:#000}
.h{text-align:center;padding-bottom:10px;margin-bottom:14px;border-bottom:2px solid #000}
.h h1{font-size:15px;letter-spacing:4px;text-transform:uppercase}
.h p{font-size:9px;color:#666;margin-top:3px}
table{width:100%;border-collapse:collapse}
td{border-bottom:1px dotted #bbb;padding:6px 4px;font-size:10.5px;word-break:break-all}
td.i{width:38px;color:#888;text-align:right;padding-right:10px}
.f{margin-top:14px;padding-top:10px;border-top:1px solid #ccc;text-align:center;font-size:8.5px;color:#999}
</style></head><body>
<div class="h"><h1>Addresses</h1><p>Bitcoin &middot; ${escapeHtml(f.label)} &middot; ${escapeHtml(btcPath(btcFormat, 0).replace(/\/0$/, '/i'))}</p></div>
<table>${btcExtra.map(a => `<tr><td class="i">#${a.index}</td><td>${escapeHtml(a.address)}</td></tr>`).join('')}</table>

</body></html>`);
}

async function printReport() {
  const entries = Object.values(generatedAddresses);
  if (!entries.length) return;
  const btn = document.getElementById('btn-print-report');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Preparing the document…'; }
  const qrCodes = {};
  for (const e of entries) qrCodes[e.id] = await generateQR(e.address, 160);
  if (btn) { btn.disabled = false; btn.innerHTML = '🖨️ Print the summary'; }
  printHTML(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Addresses</title><style>
*{margin:0;padding:0;box-sizing:border-box}@page{size:A4 portrait;margin:12mm}
body{font-family:'Courier New',monospace;background:#fff;color:#000}
.header{text-align:center;padding-bottom:10px;margin-bottom:12px;border-bottom:2px solid #000}
.header h1{font-size:16px;letter-spacing:5px;text-transform:uppercase;margin-bottom:3px}
.header p{font-size:9px;color:#666}
.entries{display:flex;flex-direction:column;gap:9px}
.entry{border:1.5px solid #000;border-radius:4px;padding:11px 13px;display:flex;align-items:center;gap:14px;page-break-inside:avoid}
.entry .qr img{width:104px;height:104px;image-rendering:pixelated;display:block}
.entry .info{flex:1;min-width:0}
.entry .name{font-size:12.5px;font-weight:bold;margin-bottom:6px;padding-bottom:5px;border-bottom:1px solid #ddd}
.entry .row{font-size:9px;margin-bottom:3px;color:#333}
.entry .addr{font-size:9.5px;word-break:break-all;background:#f6f6f6;padding:6px 8px;margin-top:5px;border:1px solid #ddd;border-radius:3px;line-height:1.35}
.evm-note{font-size:8px;color:#666;margin-top:4px;font-style:italic}
.footer{text-align:center;margin-top:12px;padding-top:8px;border-top:1px solid #ccc;font-size:8px;color:#999}
.watchblk{margin-top:12px;border:1.5px solid #000;border-radius:4px;padding:9px 11px}
.wb-h{font-size:8.5px;font-weight:bold;letter-spacing:1px;padding-bottom:5px;margin-bottom:6px;border-bottom:1px solid #ccc}
.wb-r{font-size:8.5px;margin-top:5px}
.wb-v{font-size:8px;word-break:break-all;background:#f5f5f5;border:1px solid #ddd;border-radius:3px;padding:5px 6px;margin-top:2px;line-height:1.4}
.wb-n{font-size:7.5px;color:#666;margin-top:6px;line-height:1.5}
</style></head><body>
<div class="header"><h1>Public addresses</h1><p>To use for receiving &middot; ${new Date().toLocaleDateString('en-GB')}</p></div>
<div class="entries">
${entries.map(e => `<div class="entry"><div class="qr"><img src="${qrCodes[e.id]}"></div><div class="info">
<div class="name">${escapeHtml(e.icon)} ${escapeHtml(e.name)}</div>
<div class="row"><strong>Path:</strong> ${escapeHtml(e.path)}</div>
<div class="addr">${escapeHtml(e.address)}</div>
${e.evmChains ? `<div class="evm-note">Same address for: ${escapeHtml(e.evmChains.join(', '))}</div>` : ''}
</div></div>`).join('\n')}
</div>
${(watchInPrint && btcAccount) ? `
<div class="watchblk">
  <div class="wb-h">READ-ONLY CODES &mdash; they cannot spend anything</div>
  <div class="wb-r"><strong>Descriptor</strong> (paste it into Sparrow or Electrum to see the balance)</div>
  <div class="wb-v">${escapeHtml(btcAccount.descriptor)}</div>
  <div class="wb-r"><strong>xpub</strong> (${escapeHtml(btcAccount.path)} &middot; ${escapeHtml(btcAccount.format.std)})</div>
  <div class="wb-v">${escapeHtml(btcAccount.xpub)}</div>
  <div class="wb-n">Anyone reading these codes can see every Bitcoin movement of this wallet, past and future, but cannot spend anything.</div>
</div>` : ''}

</body></html>`);
}

/* ── Seed double-check: the user retypes every word from the backup ── */
function showVerifyBackup(targetMnemonic, label) {
  const target = targetMnemonic || currentMnemonic;
  const words = target.split(' ');
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <h3>✅ Check ${label ? escapeHtml(label) : 'the seed'} again</h3>
      <p>Look <strong>only at your own backup</strong>, not at the screen, and write out all ${words.length} words.${help('verify')}</p>
      <textarea id="vrf-all" class="inp" rows="4" placeholder="word1 word2 word3 …" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" style="margin-top:6px"></textarea>
      <p class="hint" style="margin-top:6px">You can separate them with spaces or new lines: it makes no difference.</p>
      <div class="ov-row" style="margin-top:16px">
        <button class="btn btn-primary" id="vrf-check">Check</button>
        <button class="btn btn-ghost" id="vrf-skip">Close</button>
      </div>
      <div id="vrf-result" style="margin-top:12px"></div>
    </div></div>`;
  document.getElementById('vrf-skip').addEventListener('click', closeOverlay);
  document.getElementById('vrf-check').addEventListener('click', () => {
    const typed = (document.getElementById('vrf-all').value || '')
      .trim().toLowerCase().replace(/\s+/g, ' ').split(' ').filter(Boolean);
    const res = document.getElementById('vrf-result');

    if (!typed.length) {
      res.innerHTML = '<div class="note-box">Write the words from your backup to start the check.</div>';
      return;
    }
    if (typed.length !== words.length) {
      res.innerHTML = `<div class="note-box">You wrote <strong>${typed.length}</strong> words, but the seed has <strong>${words.length}</strong>. Check that you have not skipped or repeated one.</div>`;
      return;
    }
    // position by position: show where it differs, without revealing the right word
    const wrong = [];
    for (let i = 0; i < words.length; i++) if (typed[i] !== words[i]) wrong.push(i + 1);

    if (!wrong.length) {
      res.innerHTML = '<div class="ok-box">✔ <strong>Backup confirmed.</strong> All ${n} words are correct and in the right order. This is the moment you can relax.</div>'.replace('${n}', words.length);
      return;
    }
    const list = wrong.length <= 6 ? wrong.join(', ') : wrong.slice(0, 6).join(', ') + '…';
    res.innerHTML = `
      <div class="warn-box">
        <strong>It does not match.</strong> ${wrong.length === 1 ? 'The word in position' : 'The words in positions'} <strong>${list}</strong> ${wrong.length === 1 ? 'does not match' : 'do not match'} the seed.
        <br><br>The correct ones are not shown: the point of the check is to verify the <em>sheet</em>, not to copy it from the screen. Look at those positions on your backup, then try again.
      </div>`;
  });
}

/* ════════════════════════════════════════════════════════════════
   THRESHOLD BACKUP (Shamir over the BIP-39 mnemonic)
   ════════════════════════════════════════════════════════════════ */
/* ════════════════════════════════════════════════════════════════
   SEED SPLITTING — guided choice screen
   ════════════════════════════════════════════════════════════════ */
function showSplitChooser() {
  const nw = currentMnemonic.split(' ').length;
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <h3>🧩 A single sheet is a single weak point</h3>
      <p>By splitting the ${nw} words into several parts kept in different places, no single hiding place becomes fatal. There are <strong>two ways</strong> to do it: the guarantees differ, so choose according to what worries you most.</p>

      <div class="split-choice" id="split-classic">
        <div class="split-head">✂️ Sequential split <span class="split-tag tag-easy">within anyone's reach</span></div>
        <p class="split-desc">The ${nw} words are cut into consecutive groups. With 3 parts: the first ${Math.ceil(nw/3)}, then the next ones, then the last ones.</p>
        <div class="split-pro">✔ Transparent and without magic: to get back to the seed you just put the groups in order, by hand, on a sheet of paper. It will still work twenty years from now, without this program.</div>
        <div class="split-con">Worth knowing: <strong>all</strong> the parts are needed: losing one means losing the wallet.<br>Worth knowing: anyone who puts two of three together has few words left to guess.</div>
      </div>

      <div class="split-choice" id="split-shamir">
        <div class="split-head">🔐 Threshold splitting — Shamir <span class="split-tag tag-strong">mathematical guarantee</span></div>
        <p class="split-desc">Not a cut but a transformation: the seed becomes several parts, each as long as the original. You choose the threshold.</p>
        <div class="split-pro">✔ You can <strong>lose some of them</strong> and still recover everything: a fire or a mislaid box won't stop you.<br>✔ Below the threshold, the parts reveal <strong>nothing</strong>.</div>
        <div class="split-con">Worth knowing: each part is as long as the whole seed, so there is more to write down.<br>Worth knowing: to reassemble it you need <strong>this program</strong>.</div>
      </div>

      <p class="hint" style="margin-top:12px"><strong>Not sure?</strong> Choose <strong>Shamir</strong> if your fear is losing a part or being robbed. Choose <strong>sequential splitting</strong> if your fear is depending on software many years from now.</p>

      <div class="ov-row" style="margin-top:14px">
        <button class="btn btn-ghost btn-small" id="split-cancel">← Back to wallet</button>
      </div>
    </div></div>`;
  document.getElementById('split-classic').addEventListener('click', showClassicSplitSetup);
  document.getElementById('split-shamir').addEventListener('click', showShamirIntro);
  document.getElementById('split-cancel').addEventListener('click', closeOverlay);
}

/* How much is left to guess for someone holding every part but one.
   Each missing word is 11 bits; the BIP-39 checksum (words/3 bits) lets an
   attacker discard wrong candidates, so it is subtracted. Every candidate
   then costs a PBKDF2 derivation (2048 rounds of HMAC-SHA512). */
function seqSplitExposure(nWords, parts) {
  const missing = Math.min(...parts.map(p => p.to - p.from + 1));
  const bits = 11 * missing - nWords / 3;
  const verdict = bits <= 45
    ? '<strong>a single computer can find them in days, sometimes hours</strong>. With this split, each part is nearly as sensitive as the whole seed.'
    : bits <= 70
      ? 'guessing them takes an enormous amount of computing power: out of reach of an ordinary thief, not necessarily of a large organisation.'
      : 'guessing them is out of reach of any computer today.';
  return `Whoever gets hold of every part but one is missing only <strong>${missing} words</strong>: ${verdict}`;
}

function showClassicSplitSetup() {
  const words = currentMnemonic.split(' ');
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <h3>✂️ Sequential split</h3>
      <p>How many groups do you want to cut your ${words.length} words into?</p>
      <div class="seg" id="cs-n">
        ${[2, 3, 4].map(v => `<button class="seg-btn ${v === 3 ? 'seg-active' : ''}" data-n="${v}">${v} parts</button>`).join('')}
      </div>
      <p class="hint" id="cs-preview" style="margin-top:10px"></p>
      <div class="note-box" style="margin-top:12px">📌 With this method <strong>all the parts</strong> are needed, no exceptions. A single one lost and the wallet is gone for good. Different places, yes — but all equally safe.</div>
      <div class="ov-row" style="margin-top:14px">
        <button class="btn btn-primary" id="cs-go">Create the parts</button>
        <button class="btn btn-ghost btn-small" id="cs-back">← Back</button>
      </div>
    </div></div>`;
  const upd = () => {
    const n = parseInt(document.querySelector('#cs-n .seg-active').dataset.n);
    const parts = classicSplit(words, n);
    document.getElementById('cs-preview').innerHTML =
      parts.map(p => `Part ${p.x}: words ${p.from}-${p.to}`).join(' &middot; ') +
      '<br><br>' + seqSplitExposure(words.length, parts);
  };
  document.querySelectorAll('#cs-n .seg-btn').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('#cs-n .seg-btn').forEach(x => x.classList.remove('seg-active'));
    b.classList.add('seg-active');
    upd();
  }));
  upd();
  document.getElementById('cs-back').addEventListener('click', showSplitChooser);
  document.getElementById('cs-go').addEventListener('click', () => {
    const n = parseInt(document.querySelector('#cs-n .seg-active').dataset.n);
    shamirParts = classicSplit(words, n).map(p => ({ ...p, classic: true }));
    // No verification code here: the words are numbered and carry the BIP-39
    // checksum, and a code would only help someone guessing a missing part.
    shamirMeta = { n, m: n, code: null, classic: true, total: words.length };
    shamirRevealed = shamirParts.map(() => false);
    seedUnlocked = false;
    closeOverlay();
    renderApp();
    showToast(`Seed split into ${n} parts. You will find them below.`, 'success');
  });
}


/* Threshold menu for Shamir: from 2 (one part alone must never be enough)
   up to the number of parts. */
function shamirThresholdOptions(n, selected) {
  const sel = Math.min(Math.max(selected, 2), n);
  return Array.from({ length: n - 1 }, (_, i) => i + 2)
    .map(v => `<option value="${v}" ${v === sel ? 'selected' : ''}>${v}</option>`).join('');
}

function showShamirIntro() {
  overlayRoot().innerHTML = `
    <div class="ov"><div class="ov-card">
      <h3>🔐 Threshold splitting — Shamir</h3>
      <p>You will <strong>write the original seed nowhere</strong>. In its place you will keep several sheets, and just some of them will bring it back.</p>

      <div class="note-box" style="margin-bottom:12px">
        <strong>How it works, in three steps.</strong><br><br>
        <strong>1.</strong> You choose how many parts to split into and how many are needed: with <strong>5 parts and a threshold of 3</strong>, any three sheets are enough.<br>
        <strong>2.</strong> You keep the parts in different places. Anyone who finds two gets <em>nothing</em>, and you can lose two with no consequences.<br>
        <strong>3.</strong> When you need the wallet, open this program under <em>Check wallet → Shamir backup</em>, enter three parts and you get back <strong>exactly the same words as today</strong>. From there you use them wherever you like: Sparrow, Electrum, MetaMask, Ledger.
      </div>

      <div class="note-box" style="margin-bottom:12px">
        <strong>Two things to keep in mind.</strong><br><br>
        &bull; Each part is made of words and <em>looks like</em> a seed, but <strong>it is not a wallet</strong>: it is a fragment. Do not send funds to it and do not try to import it into a wallet.<br>
        &bull; Putting the parts back together needs <strong>this program</strong> (or one compatible with the same scheme). Keep a copy of this HTML file together with the sheets: the parts without the tool are words without a lock.
      </div>
      <div class="ov-grid2" style="margin-top:14px">
        <div><label class="config-label">Parts to create</label>
          <select id="sh-n" class="inp">${[3,4,5,6,7].map(v => `<option value="${v}" ${v===5?'selected':''}>${v}</option>`).join('')}</select></div>
        <div><label class="config-label">Threshold to recover</label>
          <select id="sh-m" class="inp">${shamirThresholdOptions(5, 3)}</select></div>
      </div>
      <p class="hint" id="sh-summary" style="margin-top:8px"></p>
      <div class="ov-row" style="margin-top:14px">
        <button class="btn btn-primary" id="sh-go">Create the parts</button>
        <button class="btn btn-ghost btn-small" id="sh-cancel">← Back</button>
      </div>
    </div></div>`;
  const upd = () => {
    const n = parseInt(document.getElementById('sh-n').value);
    const m = parseInt(document.getElementById('sh-m').value);
    document.getElementById('sh-summary').textContent = m === n
      ? `${n} parts in total, and all ${n} will be needed: losing one means losing the seed.`
      : `${n} parts in total: any ${m} of them will be enough to get the seed back, and you can lose up to ${n - m}.`;
  };
  document.getElementById('sh-n').addEventListener('change', () => {
    const sel = document.getElementById('sh-m');
    sel.innerHTML = shamirThresholdOptions(parseInt(document.getElementById('sh-n').value), parseInt(sel.value) || 3);
    upd();
  });
  document.getElementById('sh-m').addEventListener('change', upd);
  upd();
  document.getElementById('sh-cancel').addEventListener('click', showSplitChooser);
  document.getElementById('sh-go').addEventListener('click', () => {
    const n = parseInt(document.getElementById('sh-n').value);
    const m = parseInt(document.getElementById('sh-m').value);
    if (m > n) { showToast('The threshold cannot exceed the number of parts.', 'error'); return; }
    try {
      const shares = shamirSplit(currentEntropy, n, m);
      shamirParts = shares.map((y, i) => ({ x: i + 1, words: entropyToMnemonic(y, wordlist) }));
      shamirMeta = { n, m, code: verificationCode(currentEntropy) };
      shamirRevealed = shamirParts.map(() => false);
      seedUnlocked = false;
      closeOverlay();
      renderApp();
      showToast(`${n} parts created. ${m} of them are enough to get the seed back.`, 'success');
    } catch (err) { showToast('Error: ' + err.message, 'error'); }
  });
}

/* One printed sheet per part. Besides the words, it carries what is needed
   to use it years from now: the part number (Shamir needs it to recombine),
   how many parts exist, the threshold and the verification code. */
function partSheetHTML(p, n, m, code, classic) {
  const wl = classic ? p.words : p.words.split(' ');
  const off = classic ? p.from - 1 : 0;
  const info = classic
    ? `Sequential split &middot; words ${p.from}&ndash;${p.to} &middot; all ${n} parts are needed, in order`
    : `Threshold backup (Shamir) &middot; any ${m} of the ${n} parts recover the seed`;
  return `<div class="card">
<div class="title">Part ${p.x} of ${n}</div>
<div class="grid">${wl.map((w, i) => `<div class="w"><i>${off + i + 1}</i>${escapeHtml(w)}</div>`).join('')}</div>
<div class="meta">${info}${code ? `<br>Verification code: <b>${escapeHtml(code)}</b>` : ''}${classic ? '' : '<br>This is not a wallet: it is reassembled with AmnesicWallet, Check wallet &rarr; Shamir backup.'}</div>
</div>`;
}

function printAllShamirParts(n, m, code, classic) {
  const pages = shamirParts.map(p => partSheetHTML(p, n, m, code, classic)).join('<div class="brk"></div>');
  printHTML(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Parts</title><style>
${SLIP_PRINT_CSS}
</style></head><body>${pages}</body></html>`);
}

function printShamirPart(p, n, m, code, classic) {
  printHTML(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Part ${p.x} of ${n}</title><style>
${SLIP_PRINT_CSS}
</style></head><body>${partSheetHTML(p, n, m, code, classic)}</body></html>`);
}

/* ════════════════════════════════════════════════════════════════
   RECOVER-FROM-PARTS TAB
   ════════════════════════════════════════════════════════════════ */
let recParts = [{ }, { }, { }];

function renderRecoverTab() {
  return `
    <section>
      <div class="card">
        <div class="card-header"><span class="step-badge">🔐</span><h2>Reassemble a threshold backup</h2></div>
        <p style="margin-bottom:12px">This section reassembles backups created with <strong>threshold splitting (Shamir)</strong>. You don't need all the parts: just reach the threshold shown on the sheets, for example 3 of 5.</p>

        <div class="ok-box" style="margin-bottom:14px">
          <strong>How to recognise the right parts.</strong> Shamir parts have these three characteristics:<br><br>
          &bull; Each one is <strong>as long as the whole seed</strong> (12 or 24 words, not a small group)<br>
          &bull; Each one has a <strong>part number</strong>: "Part 2 of 5" (on sheets printed by older versions, just "Part 2")<br>
          &bull; Each one carries a 4-character <strong>verification code</strong>, the same on all of them (older versions asked you to copy it by hand)<br><br>
          If your sheets do not match this description, they are not Shamir parts and this section is not the right one for you.
        </div>
        <div class="note-box" style="margin-bottom:16px">🛡️ <strong>Before you start:</strong> reassembling the seed makes it fully readable again. Do it with the device <strong>disconnected from the internet</strong>, ideally booted from Tails or in a clean virtual machine — the same care you took when you created it.</div>
        <div id="rec-list">
          ${recParts.map((_, i) => recPartRow(i)).join('')}
        </div>
        <div class="ov-row" style="margin-top:10px">
          <button class="btn btn-ghost btn-small" id="rec-add">+ Add another part</button>
        </div>
        <label class="config-label" style="margin-top:16px">Verification code
  <span class="hint">The 4 characters printed on the sheets. It's optional, but without it you cannot know for certain whether the reassembled seed is the right one: enter it.</span>
</label>
        <input type="text" id="rec-code" class="inp" style="max-width:180px" placeholder="e.g. A3F9" autocomplete="off">
        <div style="margin-top:18px">
          <button class="btn btn-primary btn-large" id="rec-go">Reassemble the seed</button>
        </div>
        <div class="ov-row" style="margin-top:14px">
          <button class="btn btn-ghost btn-small" id="rec-back">← Back to choices</button>
        </div>
        <div id="rec-result" style="margin-top:16px"></div>
      </div>
    </section>`;
}

function recPartRow(i) {
  return `
    <div class="rec-part">
      <div class="rec-part-head">
        <span>Part</span>
        <select class="inp rec-x" style="width:70px">${Array.from({length:16},(_,k)=>`<option value="${k+1}">${k+1}</option>`).join('')}</select>
        <span class="hint">as printed on the sheet: "Part <strong>2</strong> of 5"</span>
      </div>
      <textarea class="inp rec-words" rows="2" placeholder="The words of this part, separated by spaces" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></textarea>
    </div>`;
}

function wireRecover() {
  document.getElementById('rec-back')?.addEventListener('click', () => { shamirMode = null; renderApp(); });
  document.getElementById('rec-add')?.addEventListener('click', () => {
    const list = document.getElementById('rec-list');
    const div = document.createElement('div');
    div.innerHTML = recPartRow(0);
    list.appendChild(div.firstElementChild);
  });
  document.getElementById('rec-go')?.addEventListener('click', () => {
    const rows = [...document.querySelectorAll('.rec-part')];
    const parts = [];
    for (const row of rows) {
      const words = (row.querySelector('.rec-words').value || '').trim().toLowerCase().replace(/\s+/g, ' ');
      if (!words) continue;
      const x = parseInt(row.querySelector('.rec-x').value);
      if (!validateMnemonic(words, wordlist)) {
        showRecResult(`<div class="warn-box">✗ The words of part ${x} are not valid. Check them one by one: it is often a typo or a similar but different word.</div>`);
        return;
      }
      if (parts.some(p => p.x === x)) {
        showRecResult(`<div class="warn-box">✗ Part ${x} appears twice. Each part must be entered once, with its own number.</div>`);
        return;
      }
      parts.push({ x, y: mnemonicToEntropy(words, wordlist) });
    }
    if (parts.length < 2) {
      showRecResult('<div class="note-box">A second part is needed to start.</div>');
      return;
    }
    const lens = new Set(parts.map(p => p.y.length));
    if (lens.size > 1) {
      showRecResult('<div class="warn-box">✗ The parts have different lengths: they do not come from the same backup.</div>');
      return;
    }
    try {
      const secret = shamirCombine(parts);
      const code = (document.getElementById('rec-code').value || '').replace(/\s+/g, '').toUpperCase();
      if (code && !/^[0-9A-F]{4}$/.test(code)) {
        showRecResult('<div class="warn-box">✗ The verification code is made of 4 characters: digits 0–9 and letters A–F. Check what you typed.</div>');
        return;
      }
      const expect = verificationCode(secret);
      if (code && code !== expect) {
        showRecResult('<div class="warn-box">✗ The verification code does not match. In all likelihood the parts do not reach the threshold, or one word is wrong. <strong>The seed obtained is not the right one: do not use it.</strong></div>');
        return;
      }
      const mnemonic = entropyToMnemonic(secret, wordlist);
      resetWalletState();
      currentEntropy = secret;
      currentMnemonic = mnemonic;
      currentSeed = mnemonicToSeedSync(mnemonic, '');
      pendingConfig = { words: mnemonic.split(' ').length, passphrase: '' };
      rows.forEach(r => { r.querySelector('.rec-words').value = ''; });   // the parts need not stay on screen
      showRecResult(`
        ${code
          ? '<div class="ok-box">✔ Seed reassembled and verification code confirmed: these are the original words (a wrong result would pass this check only once in 65,536 times).'
          : '<div class="note-box">Seed reassembled, but <strong>without the verification code it cannot be confirmed</strong>. If the parts entered are fewer than the threshold, or one comes from another backup, the result is a valid-looking but different wallet. Before using it, compare its addresses with ones you know.'}
        <br><br>You will now find it under <strong>Generate wallet</strong>: from there you can review the addresses, reprint the Seed Card, or take the words into any compatible wallet such as Sparrow or Electrum.
        <br><br><span class="hint">The parts contain only the words. If the wallet also had a passphrase, the addresses shown here are those <em>without</em> it: the passphrase is added in the wallet where you use the words.</span></div>
        <div style="margin-top:12px"><button class="btn btn-primary" id="rec-open">Open the wallet →</button></div>`);
      document.getElementById('rec-open')?.addEventListener('click', () => { activeTab = 'generate'; genPath = 'classic'; renderApp(); });
      if (!code) showToast('Seed reassembled. Compare the addresses before using it.', 'info');
    } catch (err) {
      showRecResult('<div class="warn-box">✗ Error while recombining: ' + escapeHtml(err.message) + '</div>');
    }
  });
}
function showRecResult(html) { document.getElementById('rec-result').innerHTML = html; }

/* ════════════════════════════════════════════════════════════════
   MULTISIG TAB — Bitcoin only, plain language
   ════════════════════════════════════════════════════════════════ */
function renderMultisigTab() {
  if (msMode === null) return renderMsChooser();
  if (msMode === 'solo') return renderMsSolo();
  return renderMsGroup();
}

function renderMsChooser() {
  return `
    <section>
      <div class="card">
        <div class="card-header"><span class="step-badge">🔐</span><h2>A multi-key vault</h2></div>
        <p style="margin-bottom:6px">It takes several keys to open it, and you decide how many.${help('multisig')}</p>
        <p class="hint" style="margin-bottom:16px">How do you want to use it?</p>

        <div class="split-choice" id="ms-pick-solo">
          <div class="split-head">👤 All the keys are mine</div>
          <p class="split-desc">You create all the keys yourself, here and now, and keep them in different places: home, office, safe deposit box. It's the most solid way to protect your own funds.</p>
          <div class="split-pro">✔ A burglary at home is no longer enough: several keys are needed, in different places.<br>✔ Losing one backup is no longer a tragedy: with 2 of 3 you still recover everything.</div>
        </div>

        <div class="split-choice" id="ms-pick-group">
          <div class="split-head">👥 A shared vault <span class="split-tag tag-easy">with other people</span></div>
          <p class="split-desc">Everyone creates their own key on their own device and shares only a public code (the <em>xpub</em>). Nobody ever sees anyone else's seed.</p>
          <div class="split-pro">✔ Perfect for family, company or group funds: nobody can move the money alone.</div>
        </div>
        <div class="ov-row" style="margin-top:14px">
          <button class="btn btn-ghost btn-small" id="msch-back">← Back to choices</button>
        </div>
      </div>
    </section>`;
}

/* ── SOLO MODE: all the keys belong to the user ── */
function renderMsSolo() {
  if (msSoloSeeds && msSoloVault) return renderMsSoloResult();
  return `
    <section>
      <div class="card">
        <div class="card-header"><span class="step-badge">👤</span><h2>Your personal vault</h2></div>
        <p style="margin-bottom:16px">We'll create several independent keys. You'll save them one at a time, calmly, and at the end you'll get the vault address to use for receiving.</p>

        <div class="config-row">
          <label class="config-label">How many keys do you want to create?
            <span class="hint">Three is the most common choice: one at home, one away from home, one with a trusted relative.</span>
          </label>
          <div class="seg" id="msolo-n">
            ${[2, 3, 5].map(v => `<button class="seg-btn ${v === 3 ? 'seg-active' : ''}" data-n="${v}">${v} keys</button>`).join('')}
          </div>
        </div>

        <div class="config-row" style="margin-top:14px">
          <label class="config-label">How many are needed to spend?
            <span class="hint">Fewer than the total: that way you can lose some without losing the funds.</span>
          </label>
          <div class="seg" id="msolo-m"></div>
        </div>

        <div class="ok-box" id="msolo-summary" style="margin-top:14px"></div>

        <div class="ov-row" style="margin-top:18px">
          <button class="btn btn-primary btn-large" id="msolo-gen">✨ Create the keys now</button>
          <button class="btn btn-outline" id="msolo-have">I already have my seeds</button>
        </div>

        <div id="msolo-have-box" style="display:none;margin-top:16px">
          <label class="config-label">Your seeds, one per line
            <span class="hint">They are used only to calculate the xpubs, then removed from the page.</span>
          </label>
          <textarea id="msolo-seeds" class="inp" rows="4" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></textarea>
          <button class="btn btn-primary" id="msolo-have-go" style="margin-top:10px">Calculate the vault</button>
        </div>

        <p class="hint" style="margin-top:16px">💡 As always, the best moment to do this is with the device disconnected from the internet.</p>

        <div class="ov-row" style="margin-top:12px">
          <button class="btn btn-ghost btn-small" id="msolo-back">← Change mode</button>
        </div>
      </div>
    </section>`;
}

function renderMsSoloResult() {
  const r = msSoloVault;
  const hasKeys = Array.isArray(msSoloSeeds) && msSoloSeeds.length > 0;
  return `
    <section>
      ${hasKeys ? `
      <div class="card">
        <div class="card-header"><span class="step-badge">1</span><h2>Your ${r.n} keys</h2></div>
        <p style="margin-bottom:6px">Each one is independent from the others. Save them <strong>in different places</strong>: it is the separation that protects you, not the number.</p>
        <p class="hint" style="margin-bottom:16px">They stay covered until you reveal them yourself.</p>
        <div class="keys-list">
          ${msSoloSeeds.map((mn, i) => {
            const w = mn.split(' ');
            const open = msSoloRevealed[i];
            return `
            <div class="key-block">
              <div class="key-head">
                <span class="key-title">🔑 Key ${i + 1}</span>
                <span class="key-tag">${w.length} words</span>
              </div>
              <div class="part-words">${w.map((x, k) => `<span class="part-word"><em>${k + 1}</em>${open ? escapeHtml(x) : '••••••••'}</span>`).join('')}</div>
              <div class="ov-row" style="margin-top:10px">
                <button class="btn btn-outline btn-small k-reveal" data-i="${i}">${open ? '🙈 Hide' : '👁️ Reveal'}</button>
                <button class="btn btn-outline btn-small k-copy" data-i="${i}">📋 Copy</button>
                <button class="btn btn-outline btn-small k-print" data-i="${i}">🖨️ Print</button>
                <button class="btn btn-outline btn-small k-check" data-i="${i}">✅ Check again</button>
              </div>
            </div>`;
          }).join('')}
        </div>
        <div class="ov-row" style="margin-top:16px">
          <button class="btn btn-primary" id="msolo-print-all">🖨️ Print all keys</button>
          <button class="btn btn-ghost btn-small" id="msolo-forget">✕ Remove the keys from the page</button>
        </div>
        <div class="note-box" style="margin-top:12px">Once they are all saved, remove them from this page: from then on they exist only where you put them.</div>
      </div>` : ''}

      <div class="card">
        <div class="card-header"><span class="step-badge">${hasKeys ? '2' : '✅'}</span><h2>Your vault</h2></div>
        <div class="vault-diagram">${Array.from({ length: r.n }, (_, i) => `🔑 ${i + 1}`).join(' + ')}<br>→ <strong>${r.m} signatures out of ${r.n}</strong> are enough to spend 🔒</div>
        <div class="share-box" style="margin-top:14px">
          <div class="share-head">🏠 Receiving address</div>
          <div class="addr-copy-row"><code class="detail-value addr-value">${escapeHtml(r.address)}</code>
            <button class="btn btn-icon" id="msolo-copy-addr" title="Copy">📋</button></div>
          <div id="msolo-qr" style="display:flex;justify-content:center;margin-top:10px"></div>
        </div>
        <div class="detail-label" style="margin-top:14px">Descriptor &mdash; the formula that holds the keys together</div>
        <div class="addr-copy-row"><code class="detail-value" style="font-size:10.5px">${escapeHtml(r.descriptor)}</code>
          <button class="btn btn-icon" id="msolo-copy-desc" title="Copy">📋</button></div>
        <div class="ok-box" style="margin-top:12px">📌 <strong>Keep the descriptor together with the keys.</strong> With the seeds alone, without knowing how they combine, rebuilding the vault is far more laborious. Print it or write it down.</div>
        <div class="ov-row" style="margin-top:14px">
          <button class="btn btn-outline" id="msolo-print">🖨️ Print the summary</button>
          <button class="btn btn-ghost btn-small" id="msolo-restart">← Start over</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><span class="step-badge">${hasKeys ? '3' : 'ℹ️'}</span><h2>And now, how do I use it?</h2></div>
        <p style="margin-bottom:14px">AmnesicWallet created the vault, but it does not sign transactions. To receive and spend you need a program that handles multisig: <strong>Sparrow Wallet</strong> is the reference, free and available for Windows, macOS and Linux.</p>

        <div class="steps-box">
          <div class="step-line"><span class="sl-n">1</span><span class="sl-t"><strong>Install Sparrow</strong> from sparrowwallet.com on a connected computer. You will never give it the keys, only the descriptor.</span></div>
          <div class="step-line"><span class="sl-n">2</span><span class="sl-t"><strong>File → Import Wallet → Output Descriptor.</strong> Paste the descriptor above. Sparrow rebuilds the vault and shows you the same address: <em>check that it matches</em> — it is the most important check you will make.</span></div>
          <div class="step-line"><span class="sl-n">3</span><span class="sl-t"><strong>You can receive right away</strong> and see the balance. In this form Sparrow is read-only: it cannot spend, because it does not have the keys.</span></div>
          <div class="step-line"><span class="sl-n">4</span><span class="sl-t"><strong>To spend you need ${r.m} signatures out of ${r.n}</strong>, and you have two routes. They are explained below.</span></div>
        </div>

        <div class="split-choice" style="margin-top:16px;cursor:default">
          <div class="split-head">🅰️ Signing inside Sparrow (simpler)</div>
          <p class="split-desc">You load the seeds into Sparrow and sign there. Suitable for modest amounts, or if you do it on an offline computer.</p>
          <div class="split-pro">
            Open the wallet and go to <em>Settings → Keystores</em>. For each key press the cosigner tab, choose <em>New or Imported Software Wallet</em>, enter the 12 words of that key and set the derivation path <strong>m/48'/0'/0'/2'</strong>. Repeat until you have loaded at least ${r.m} keys, then save.<br><br>
            From there: <em>Send</em> → fill in address and amount → <em>Create Transaction</em> → <em>Finalize</em> → <em>Sign</em>. Sparrow signs with the first key, then repeat <em>Sign</em> for the second, and when you reach ${r.m} signatures the <em>Broadcast</em> button becomes active.
          </div>
          <div class="split-con">Worth knowing: the seeds end up in the computer memory. If that machine is connected, multisig loses most of its advantage. Do it offline, or use route B.</div>
        </div>

        <div class="split-choice" style="margin-top:12px;cursor:default">
          <div class="split-head">🅱️ Sparrow only to watch, signing elsewhere (safer)</div>
          <p class="split-desc">Sparrow stays read-only and never sees the seeds. An external device does the signing. This is where multisig is at its best.</p>
          <div class="split-pro">
            <strong>With hardware wallets (Trezor, Ledger, ColdCard).</strong> Load each key into a different device with the <em>recovery</em> procedure, using the physical buttons. In Sparrow, under <em>Keystores</em>, choose <em>Connected Hardware Wallet</em> instead of the software wallet. When you spend, Sparrow creates the transaction and sends it to the device: you <strong>check the address on the device screen</strong> and confirm. The private key never leaves the chip. Repeat with the second device up to the threshold.<br><br>
            <strong>With an offline computer (PSBT method).</strong> On the online Sparrow press <em>Create Transaction</em> and then <em>Save PSBT</em> onto a USB stick. Take the file to a computer disconnected from the network, where you have Sparrow or <strong>Electrum</strong> with one key loaded: open the PSBT, sign, save it again. Repeat on a second machine with the second key. Only the final, already signed file goes back to the online computer for the <em>Broadcast</em>.<br><br>
            In both cases <strong>the keys never meet</strong> in the same place: which is exactly why you created a multisig vault.
          </div>
        </div>

        <div class="steps-box" style="margin-top:16px">
        </div>

        <div class="note-box" style="margin-top:14px">
          <strong>Before depositing significant amounts</strong>, do a full rehearsal: send a token amount, then take it back out by signing with ${r.m} keys. It is the only way to know for certain that the system works — and it costs a few cents in fees.
        </div>
        <p class="hint" style="margin-top:12px">Alternatives to Sparrow: <strong>Electrum</strong> (native multisig) and <strong>Nunchuk</strong>. The descriptor is a standard, so you are not tied to any of them.</p>
      </div>
    </section>`;
}

/* ── GROUP MODE: exchanging xpubs ── */
function renderMsGroup() {
  return `
    <section>
      <div class="card">
        <div class="card-header"><span class="step-badge">A</span><h2>Your key</h2></div>
        <p style="margin-bottom:14px">You create your key here. Out of it comes a public code — the <em>xpub</em> — which you can hand to the others without any worry: it was made to be shared. Your seed, on the other hand, never leaves this device.</p>
        <div class="ov-row">
          <button class="btn btn-primary" id="ms-gen">✨ Create a new key</button>
          <button class="btn btn-outline" id="ms-reuse">I'll use a seed I already have</button>
        </div>
        <div id="ms-reuse-box" style="display:none;margin-top:14px">
          <label class="config-label">Your words (12 to 24)</label>
          <textarea id="ms-seed-inp" class="inp" rows="2" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></textarea>
          <label class="config-label" style="margin-top:8px">Passphrase, if you used one</label>
          <input type="password" id="ms-pass-inp" class="inp" autocomplete="off">
          <button class="btn btn-primary" id="ms-reuse-go" style="margin-top:10px">Calculate my xpub</button>
        </div>
        <div id="ms-mykey" style="margin-top:16px"></div>
      </div>

      <div class="card">
        <div class="card-header"><span class="step-badge">B</span><h2>Build the vault</h2></div>
        <p style="margin-bottom:12px">Paste the xpubs you received from the others, one per line. Then decide how many signatures will be needed to move the funds.</p>
        <label class="config-label">The xpub codes of the other participants${msMyXpub ? ' <span class="hint">Yours is already included: no need to paste it.</span>' : ''}</label>
        <textarea id="ms-xpubs" class="inp" rows="4" placeholder="xpub6...&#10;xpub6..." autocomplete="off" spellcheck="false"></textarea>
        <div class="ov-grid2" style="margin-top:12px;max-width:420px">
          <div><label class="config-label">Signatures required</label>
            <select id="ms-m" class="inp">${thresholdOptions(3, 2)}</select></div>
          <div style="display:flex;align-items:flex-end"><span class="hint" id="ms-summary" style="padding-bottom:10px"></span></div>
        </div>
        <button class="btn btn-primary" id="ms-build" style="margin-top:14px">Calculate the address</button>
        <div id="ms-vault" style="margin-top:16px"></div>
        <div class="ov-row" style="margin-top:14px">
          <button class="btn btn-ghost btn-small" id="msg-back">← Change mode</button>
        </div>
      </div>
    </section>`;
}



function wireMultisig() {
  // — chooser —
  document.getElementById('ms-pick-solo')?.addEventListener('click', () => { msMode = 'solo'; renderApp(); });
  document.getElementById('ms-pick-group')?.addEventListener('click', () => { msMode = 'group'; renderApp(); });
  document.getElementById('msolo-back')?.addEventListener('click', () => { msMode = null; renderApp(); });
  document.getElementById('msg-back')?.addEventListener('click', () => { msMode = null; renderApp(); });
  document.getElementById('msch-back')?.addEventListener('click', () => { genPath = null; msMode = null; renderApp(); });

  // — SOLO mode: setup —
  const soloN = () => parseInt(document.querySelector('#msolo-n .seg-active')?.dataset.n || '3');
  const soloM = () => parseInt(document.querySelector('#msolo-m .seg-active')?.dataset.m || '2');
  const renderM = () => {
    const box = document.getElementById('msolo-m');
    if (!box) return;
    const n = soloN();
    const list = Array.from({ length: n }, (_, i) => i + 1);
    const def = Math.min(box.querySelector('.seg-active') ? soloM() : 2, n);
    box.innerHTML = list.map(v => `<button class="seg-btn ${v === def ? 'seg-active' : ''}" data-m="${v}">${v}</button>`).join('');
    box.querySelectorAll('.seg-btn').forEach(b => b.addEventListener('click', () => {
      box.querySelectorAll('.seg-btn').forEach(x => x.classList.remove('seg-active'));
      b.classList.add('seg-active'); updSolo();
    }));
  };
  const updSolo = () => {
    const el = document.getElementById('msolo-summary');
    if (!el) return;
    const n = soloN(), m = soloM();
    const lost = n - m;
    el.innerHTML = `You will create <strong>${n} keys</strong> and <strong>${m}</strong> of them will be enough to spend.` +
      (m === 1
        ? ` Careful: with a single signature <strong>each key alone can spend</strong>. It protects against losing keys, not against theft.`
        : lost > 0
          ? ` You can lose up to <strong>${lost}</strong> without losing the funds, and anyone stealing ${m - 1} would get nothing.`
          : ` Careful: since all ${n} are needed, losing one means losing the funds.`);
  };
  document.querySelectorAll('#msolo-n .seg-btn').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('#msolo-n .seg-btn').forEach(x => x.classList.remove('seg-active'));
    b.classList.add('seg-active'); renderM(); updSolo();
  }));
  if (document.getElementById('msolo-n')) { renderM(); updSolo(); }

  document.getElementById('msolo-gen')?.addEventListener('click', () => {
    msSoloConfig = { n: soloN(), m: soloM() };
    entropyPurpose = 'multisolo';
    pendingConfig = { words: 12, passphrase: '', useDice: false };
    showTypingOverlay(null);
  });
  document.getElementById('msolo-have')?.addEventListener('click', () => {
    const b = document.getElementById('msolo-have-box');
    b.style.display = b.style.display === 'none' ? 'block' : 'none';
  });
  document.getElementById('msolo-have-go')?.addEventListener('click', () => {
    const ta = document.getElementById('msolo-seeds');
    const lines = (ta.value || '').split('\n').map(x => x.trim().toLowerCase().replace(/\s+/g, ' ')).filter(Boolean);
    if (lines.length < 2) { showToast('At least two seeds are needed, one per line.', 'error'); return; }
    const keys = [];
    for (let i = 0; i < lines.length; i++) {
      if (!validateMnemonic(lines[i], wordlist)) { showToast(`The seed on line ${i + 1} is not valid. Check the words again.`, 'error'); return; }
      keys.push(deriveMultisigXpub(mnemonicToSeedSync(lines[i], '')));
    }
    ta.value = ''; lines.length = 0;   // out of memory before any output
    const m = Math.min(soloM(), keys.length);
    try {
      msSoloConfig = { n: keys.length, m };
      msSoloVault = multisigAddress(keys, m);
      msSoloSeeds = [];
      renderApp();
      showToast('Vault computed. The words you typed have been discarded.', 'success');
    } catch (err) {
      showToast(err instanceof KeyError ? keyErrorMessage(err, keys.map((_, i) => `The seed on line ${i + 1}`), true) : 'Error: ' + err.message, 'error');
    }
  });

  // — SOLO result —
  document.getElementById('msolo-copy-addr')?.addEventListener('click', async () => {
    try { await copyToClipboard(msSoloVault.address); showToast('Address copied.', 'success'); } catch (_) {}
  });
  document.getElementById('msolo-copy-desc')?.addEventListener('click', async () => {
    try { await copyToClipboard(msSoloVault.descriptor); showToast('Descriptor copied.', 'success'); } catch (_) {}
  });
  document.getElementById('msolo-restart')?.addEventListener('click', () => {
    msSoloSeeds = null; msSoloVault = null; msSoloConfig = null; msSoloIndex = 0; msSoloRevealed = [];
    renderApp();
  });
  document.getElementById('msolo-print')?.addEventListener('click', printSoloVault);
  document.getElementById('msolo-print-all')?.addEventListener('click', printAllSoloKeys);
  document.getElementById('msolo-forget')?.addEventListener('click', () => {
    msSoloSeeds = []; msSoloRevealed = [];
    renderApp();
    showToast('Keys removed from the page. They now exist only where you saved them.', 'info');
  });
  document.querySelectorAll('.k-reveal').forEach(b => b.addEventListener('click', () => {
    const i = +b.dataset.i;
    msSoloRevealed[i] = !msSoloRevealed[i];
    renderApp();
  }));
  document.querySelectorAll('.k-copy').forEach(b => b.addEventListener('click', async () => {
    try { await copyToClipboard(msSoloSeeds[+b.dataset.i]); showToast(`Key ${+b.dataset.i + 1} copied.`, 'success'); }
    catch (_) { showToast('Copy failed.', 'error'); }
  }));
  document.querySelectorAll('.k-print').forEach(b => b.addEventListener('click', () => printSoloKey(+b.dataset.i)));
  document.querySelectorAll('.k-check').forEach(b => b.addEventListener('click', () => {
    const i = +b.dataset.i;
    showVerifyBackup(msSoloSeeds[i], `Key ${i + 1} of ${msSoloConfig.n}`);
  }));
  if (msSoloVault && document.getElementById('msolo-qr')) {
    (async () => {
      try {
        document.getElementById('msolo-qr').innerHTML = `<img src="${await generateQR(msSoloVault.address, 180)}" style="border-radius:8px;border:4px solid #fff">`;
      } catch (_) {}
    })();
  }

  // — GROUP mode —
  document.getElementById('ms-gen')?.addEventListener('click', () => {
    entropyPurpose = 'multisig';
    pendingConfig = { words: 12, passphrase: '', useDice: false };
    showTypingOverlay(null);
  });
  document.getElementById('ms-reuse')?.addEventListener('click', () => {
    const box = document.getElementById('ms-reuse-box');
    box.style.display = box.style.display === 'none' ? 'block' : 'none';
  });
  document.getElementById('ms-reuse-go')?.addEventListener('click', () => {
    const words = (document.getElementById('ms-seed-inp').value || '').trim().toLowerCase().replace(/\s+/g, ' ');
    const pass = document.getElementById('ms-pass-inp').value || '';
    if (!validateMnemonic(words, wordlist)) { showToast('These words do not form a valid seed. Please check them.', 'error'); return; }
    const seed = mnemonicToSeedSync(words, pass);
    document.getElementById('ms-seed-inp').value = '';
    document.getElementById('ms-pass-inp').value = '';
    showMsKey(deriveMultisigXpub(seed));
  });
  document.getElementById('ms-m')?.addEventListener('change', updMsSummary);
  document.getElementById('ms-xpubs')?.addEventListener('input', updMsSummary);
  document.getElementById('ms-build')?.addEventListener('click', buildVault);
  if (document.getElementById('ms-xpubs')) updMsSummary();
  if (msMyXpub && document.getElementById('ms-mykey')) showMsKey(msMyXpub, true);
}

/* ── Guided generation of the N keys (solo mode) ── */
function finishMultiSoloKeys(entropy, mouseBytes, typeBytes, diceBytes) {
  const n = msSoloConfig.n;
  // The first key uses the entropy already combined; every further key
  // gets its own fresh CSPRNG draw (combineEntropy reads the CSPRNG anew
  // on each call), so the keys are independent of one another.
  msSoloSeeds = [entropyToMnemonic(entropy, wordlist)];
  for (let i = 1; i < n; i++) {
    const e = combineEntropy(16, { mouse: mouseBytes, dice: diceBytes, keys: typeBytes });
    msSoloSeeds.push(entropyToMnemonic(e, wordlist));
  }
  try {
    const keys = msSoloSeeds.map(x => deriveMultisigXpub(mnemonicToSeedSync(x, '')));
    msSoloVault = multisigAddress(keys, msSoloConfig.m);
    msSoloRevealed = msSoloSeeds.map(() => false);
    closeOverlay();
    renderApp();
    showToast('Vault created. Now save the keys, one at a time.', 'success');
  } catch (err) {
    msSoloSeeds = null;
    closeOverlay();
    showToast('Error: ' + err.message, 'error');
  }
}

/* Printing a single key */
function printSoloKey(i) {
  const words = msSoloSeeds[i].split(' ');
  printHTML(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Key ${i + 1}</title><style>
*{margin:0;padding:0;box-sizing:border-box}@page{size:A4;margin:20mm}
body{font-family:'Courier New',monospace;background:#fff;color:#000}
.card{border:2px solid #000;border-radius:5px;padding:26px 30px}
.brk{page-break-after:always}
.title{text-align:center;font-size:15px;font-weight:bold;letter-spacing:4px;text-transform:uppercase;padding-bottom:14px;margin-bottom:20px;border-bottom:1px solid #ccc}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.w{border:1px solid #bbb;border-radius:3px;padding:8px 9px;font-size:12px}
.w i{color:#999;font-style:normal;margin-right:7px;font-size:10px}
</style></head><body><div class="card">
<div class="title">Key ${i + 1}</div>
<div class="grid">${words.map((w, k) => `<div class="w"><i>${k + 1}</i>${escapeHtml(w)}</div>`).join('')}</div>
</div></body></html>`);
}

/* Printing every key, one per page */
function printAllSoloKeys() {
  const pages = msSoloSeeds.map((mn, i) => {
    const words = mn.split(' ');
    return `<div class="card">
<div class="title">Key ${i + 1}</div>
<div class="grid">${words.map((w, k) => `<div class="w"><i>${k + 1}</i>${escapeHtml(w)}</div>`).join('')}</div>
</div>`;
  }).join('<div class="brk"></div>');
  printHTML(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Keys</title><style>
*{margin:0;padding:0;box-sizing:border-box}@page{size:A4;margin:20mm}
body{font-family:'Courier New',monospace;background:#fff;color:#000}
.card{border:2px solid #000;border-radius:5px;padding:26px 30px}
.brk{page-break-after:always}
.title{text-align:center;font-size:15px;font-weight:bold;letter-spacing:4px;text-transform:uppercase;padding-bottom:14px;margin-bottom:20px;border-bottom:1px solid #ccc}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.w{border:1px solid #bbb;border-radius:3px;padding:8px 9px;font-size:12px}
.w i{color:#999;font-style:normal;margin-right:7px;font-size:10px}
</style></head><body>${pages}</body></html>`);
}

function printSoloVault() {
  const r = msSoloVault;
  printHTML(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Vault</title><style>
*{margin:0;padding:0;box-sizing:border-box}@page{size:A4;margin:18mm}
body{font-family:'Courier New',monospace;background:#fff;color:#000}
.card{border:3px solid #000;border-radius:6px;padding:32px 36px}
.title{text-align:center;font-size:17px;font-weight:bold;letter-spacing:3px;text-transform:uppercase}
.sub{text-align:center;font-size:11px;color:#555;margin:6px 0 20px;padding-bottom:14px;border-bottom:1px solid #ccc}
.lbl{font-size:11px;font-weight:bold;margin-top:16px;margin-bottom:5px}
.val{font-size:11px;word-break:break-all;background:#f6f6f6;border:1px solid #ddd;border-radius:3px;padding:8px 10px;line-height:1.45}
.note{margin-top:18px;font-size:10.5px;border:1.5px solid #000;border-radius:4px;padding:10px;line-height:1.6}
.foot{margin-top:18px;padding-top:12px;border-top:1px solid #ccc;text-align:center;font-size:9.5px;color:#999}
</style></head><body><div class="card">
<div class="title">Vault</div>
<div class="lbl">RECEIVING ADDRESS</div>
<div class="val">${escapeHtml(r.address)}</div>
<div class="lbl">DESCRIPTOR</div>
<div class="val">${escapeHtml(r.descriptor)}</div>
</div></body></html>`);
}

function finishMultisigKey(entropy) {
  const mn = entropyToMnemonic(entropy, wordlist);
  const seed = mnemonicToSeedSync(mn, '');
  const info = deriveMultisigXpub(seed);
  info.mnemonic = mn; // shown ONLY as a masked "save the seed" block
  showMsKey(info);
}

async function showMsKey(info, silent) {
  msMyXpub = info;
  const el = document.getElementById('ms-mykey');
  if (!el) return;
  el.innerHTML = `
    ${info.mnemonic ? `
      <div class="ok-box" style="margin-bottom:12px">🔒 <strong>Before anything else: save the seed of this key.</strong> Without it, your share of the vault is lost. It stays covered, as always.
        <div class="part-words" id="msk-words" style="margin-top:10px">${info.mnemonic.split(' ').map((w, k) => `<span class="part-word"><em>${k + 1}</em>••••••••</span>`).join('')}</div>
        <div class="ov-row" style="margin-top:10px">
          <button class="btn btn-outline btn-small" id="msk-reveal">👁️ Reveal</button>
          <button class="btn btn-outline btn-small" id="msk-copy">📋 Copy the seed</button>
          <button class="btn btn-outline btn-small" id="msk-print">🖨️ Print the Seed Card</button>
          <button class="btn btn-outline btn-small" id="msk-check">✅ Check again</button>
        </div>
      </div>` : ''}
    <div class="share-box">
      <div class="share-head">🔑 Your xpub — to be shared</div>
      <div class="addr-copy-row"><code class="detail-value addr-value" style="font-size:11px">${escapeHtml(info.xpub)}</code>
        <button class="btn btn-icon" id="msk-copyx" title="Copy">📋</button></div>
      <div id="msk-qr" style="display:flex;justify-content:center;margin-top:10px"></div>
      <p class="hint" style="margin-top:8px;text-align:center">It contains nothing secret: it only serves to work out the shared address. Feel free to hand it to the other participants.</p>
      <details class="adv" style="margin-top:8px"><summary>Show technical details</summary>
        <div class="adv-body hint">BIP-48 derivation for P2WSH multisig &middot; Path: ${info.path} &middot; Fingerprint: ${info.fingerprint}</div>
      </details>
    </div>
    <div class="warn-box" style="margin-top:10px">🚫 The <strong>seed</strong>, on the other hand, must not be shared with anyone. Never, for any reason, with any participant.</div>`;
  document.getElementById('msk-copyx')?.addEventListener('click', async () => {
    try { await copyToClipboard(info.xpub); showToast('xpub copied.', 'success'); } catch (_) { showToast('Copy failed', 'error'); }
  });
  if (info.mnemonic) {
    document.getElementById('msk-copy')?.addEventListener('click', async () => {
      try { await copyToClipboard(info.mnemonic); showToast('Seed copied to the clipboard.', 'success'); } catch (_) { showToast('Copy failed', 'error'); }
    });
    document.getElementById('msk-print')?.addEventListener('click', () => handlePrintSeed(info.mnemonic));
    document.getElementById('msk-check')?.addEventListener('click', () => showVerifyBackup(info.mnemonic, 'the seed of this key'));
    let shown = false;
    document.getElementById('msk-reveal')?.addEventListener('click', (ev) => {
      shown = !shown;
      document.getElementById('msk-words').innerHTML = info.mnemonic.split(' ')
        .map((w, k) => `<span class="part-word"><em>${k + 1}</em>${shown ? escapeHtml(w) : '••••••••'}</span>`).join('');
      ev.currentTarget.innerHTML = shown ? '🙈 Hide' : '👁️ Reveal';
    });
  }
  try { document.getElementById('msk-qr').innerHTML = `<img src="${await generateQR(info.xpub, 180)}" style="border-radius:8px;border:4px solid #fff">`; } catch (_) {}
  if (!silent) showToast('Key created. Save the seed, then share the xpub.', 'success');
  updMsSummary();
}

function collectXpubs() {
  const list = (document.getElementById('ms-xpubs')?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
  if (msMyXpub && !list.includes(msMyXpub.xpub)) list.unshift(msMyXpub.xpub);
  return list;
}

function updMsSummary() {
  const el = document.getElementById('ms-summary');
  if (!el) return;
  const n = collectXpubs().length;
  const sel = document.getElementById('ms-m');
  if (sel) sel.innerHTML = thresholdOptions(Math.max(2, n), parseInt(sel.value) || 2);
  const m = parseInt(sel?.value || '2');
  el.textContent = n >= 2 ? `out of ${n} participants: ${m} signature${m===1?'':'s'} out of ${n} will be needed to spend.` : 'At least two xpub codes are needed.';
}

async function buildVault() {
  const xpubs = collectXpubs();
  const m = parseInt(document.getElementById('ms-m').value);
  const out = document.getElementById('ms-vault');
  if (xpubs.length < 2) { showToast('At least two xpub codes are needed, including yours.', 'error'); return; }
  if (m > xpubs.length) { showToast('The required signatures cannot exceed the number of participants.', 'error'); return; }
  const keys = xpubs.map(x => (msMyXpub && x === msMyXpub.xpub) ? { xpub: x, fingerprint: msMyXpub.fingerprint } : x);
  const own = msMyXpub ? 1 : 0;
  const labels = xpubs.map((_, i) => (own && i === 0) ? 'Your own key' : `The xpub on line ${i + 1 - own}`);
  let res;
  try { res = multisigAddress(keys, m); }
  catch (err) {
    out.innerHTML = `<div class="warn-box">${keyErrorMessage(err, labels)}</div>`;
    return;
  }
  const names = ['Your key', ...Array.from({ length: xpubs.length - 1 }, (_, i) => `Key ${i + 2}`)];
  out.innerHTML = `
    <div class="vault-diagram">${names.map(n => `🔑 ${n}`).join(' + ')}<br>→ <strong>${res.m} signatures out of ${res.n}</strong> are enough to open 🔒</div>
    <div class="share-box" style="margin-top:12px">
      <div class="share-head">🏠 Your vault's address</div>
      <div class="addr-copy-row"><code class="detail-value addr-value">${escapeHtml(res.address)}</code>
        <button class="btn btn-icon" id="ms-copy-addr" title="Copy">📋</button></div>
      <div id="ms-addr-qr" style="display:flex;justify-content:center;margin-top:10px"></div>
      <details class="adv" style="margin-top:10px"><summary>Show technical details</summary>
        <div class="adv-body">
          <span class="detail-label">Descriptor &mdash; import it into Sparrow or Electrum to monitor and spend</span>
          <div class="addr-copy-row"><code class="detail-value" style="font-size:10.5px">${escapeHtml(res.descriptor)}</code>
            <button class="btn btn-icon" id="ms-copy-desc" title="Copy">📋</button></div>
          <div id="ms-desc-qr" style="display:flex;justify-content:center;margin-top:10px"></div>
          <p class="hint" style="margin-top:6px">The keys are sorted according to the BIP-67 standard, so the address is always the same regardless of the order you paste them in.</p>
        </div>
      </details>
    </div>
    <div class="note-box" style="margin-top:10px">💡 <strong>A check worth doing.</strong> Before depositing any amount, import the same xpubs into <strong>Sparrow</strong> and confirm it produces the same address. Two independent tools that agree are worth more than any promise.</div>`;
  document.getElementById('ms-copy-addr')?.addEventListener('click', async () => {
    try { await copyToClipboard(res.address); showToast('Address copied.', 'success'); } catch (_) {}
  });
  document.getElementById('ms-copy-desc')?.addEventListener('click', async () => {
    try { await copyToClipboard(res.descriptor); showToast('Descriptor copied.', 'success'); } catch (_) {}
  });
  try {
    document.getElementById('ms-addr-qr').innerHTML = `<img src="${await generateQR(res.address, 180)}" style="border-radius:8px;border:4px solid #fff">`;
    document.getElementById('ms-desc-qr').innerHTML = `<img src="${await generateQR(res.descriptor, 300)}" style="border-radius:8px;border:4px solid #fff">`;
  } catch (_) {}
}

/* ════════════════════════════════════════════════════════════════
   GUIDE TAB — FAQ in plain language
   ════════════════════════════════════════════════════════════════ */
function renderGuideTab() {
  return `
    <section>
      <div class="card">
        <div class="card-header"><span class="step-badge">📖</span><h2>How it works, no mysteries</h2></div>
        <p class="hint" style="margin-bottom:18px">A wallet that holds value deserves to be understood, not just used.</p>

        <div class="guide-nav">
          <button class="gn-btn gn-active" data-gview="guide">📘 Step-by-step guide</button>
          <button class="gn-btn" data-gview="faq">💬 Frequently asked questions</button>
        </div>
      </div>

      <div id="guide-view"></div>
    </section>`;
}

/* ── STEP-BY-STEP GUIDE ────────────────────────────────────────── */
function renderGuideSteps() {
  return `
    <div class="card">
      <div class="card-header"><span class="step-badge">1</span><h2>Creating a personal wallet</h2></div>
      <div class="steps-box">
        <div class="step-line"><span class="sl-n">1</span><span class="sl-t"><strong>Disconnect the device from the internet.</strong> For maximum protection, do it in a secure environment such as a Tails system, a clean virtual machine or a dedicated PC.</span></div>
        <div class="step-line"><span class="sl-n">2</span><span class="sl-t"><strong>Generate wallet → A personal wallet.</strong></span></div>
        <div class="step-line"><span class="sl-n">3</span><span class="sl-t"><strong>Choose where the randomness comes from:</strong> three sources (browser, keyboard, mouse) or four, adding real physical dice.</span></div>
        <div class="step-line"><span class="sl-n">4</span><span class="sl-t"><strong>Choose the type of backup:</strong> BIP-39 (a single phrase) or SLIP-39 (several sheets with a threshold). If you're undecided, BIP-39 with 12 words is fine in almost every case.</span></div>
        <div class="step-line"><span class="sl-n">5</span><span class="sl-t"><strong>Decide about the passphrase.</strong> The program asks you explicitly. It protects you if someone finds the words, but it must be kept as carefully as they are: forget it and the funds are lost. If you are unsure, carry on without. Keep in mind that it cannot be added to this wallet later: the same words with a passphrase open a different wallet, to which you would have to move the funds.</span></div>
        <div class="step-line"><span class="sl-n">6</span><span class="sl-t"><strong>Fill the entropy bars:</strong> type any keys freely and at random, then move the mouse — or, on a phone, drag your finger inside the box. If you chose the dice, enter the rolls first.</span></div>
        <div class="step-line"><span class="sl-n">7</span><span class="sl-t"><strong>Choose how to keep the seed:</strong> a single sheet, split sequentially, or with a Shamir threshold.</span></div>
        <div class="step-line"><span class="sl-n">8</span><span class="sl-t"><strong>Save the backup</strong>, then use <em>Check the seed again</em> to confirm you transcribed it correctly. You can write the words in plain text, exactly as they appear on screen. Or, for greater privacy, you can save them in a format that shows no words at all: click <em>Powers-of-2 backup</em> and you get a grid of dots. Anyone finding it sees only marked boxes, without being able to read the seed.<br><br>To read the grid back you need the numbered BIP-39 dictionary. You can download it from AmnesicWallet or find it elsewhere: what matters is that the numbering starts at <strong>1</strong> and not at 0, otherwise every word is shifted by one position and the conversion comes out wrong.</span></div>
        <div class="step-line"><span class="sl-n">9</span><span class="sl-t"><strong>Select the networks</strong> and calculate the addresses. Those are public: you can share them without risk in order to receive.</span></div>
        <div class="step-line"><span class="sl-n">10</span><span class="sl-t"><strong>Verify in a second program, still offline.</strong> On the same disconnected device, restore the words in another program — Sparrow or Electrum, for example — check that the first address matches, then delete that wallet from the program. Two independent tools that agree are worth more than any promise; typing the words into a program on a connected device would undo the care taken so far.</span></div>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><span class="step-badge">2</span><h2>Keeping the backup</h2></div>
      <p style="margin-bottom:12px">After generation you have three options, and you can change your mind later using the <em>Split into several parts</em> button.</p>
      <div class="steps-box">
        <div class="step-line"><span class="sl-n">A</span><span class="sl-t"><strong>A single backup.</strong> The words on one sheet, in a safe place. Simple and recoverable anywhere. The limit: if that sheet disappears, everything disappears.</span></div>
        <div class="step-line"><span class="sl-n">B</span><span class="sl-t"><strong>Split sequentially.</strong> Your words are simply divided into consecutive groups, to be kept in different places. It is reassembled by hand, putting the sheets in the right order, with no software needed. All the parts are required though: if even one is missing, the seed cannot be read.</span></div>
        <div class="step-line"><span class="sl-n">C</span><span class="sl-t"><strong>Shamir backup.</strong> The seed is split into several parts, of which a minimum number is enough to reassemble it. For example, with 3 parts generated and a threshold of 2, any 2 parts are enough to rebuild the parent seed. Even though each single part looks like a genuine seed, on its own it reveals nothing. To recombine the parts and obtain the original seed you need this program: so keep a copy of the file together with the parts, otherwise even having them all you won't be able to reopen the wallet.</span></div>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><span class="step-badge">3</span><h2>Creating a multisig vault</h2></div>
      <div class="steps-box">
        <div class="step-line"><span class="sl-n">1</span><span class="sl-t"><strong>Generate wallet → A multisig vault.</strong></span></div>
        <div class="step-line"><span class="sl-n">2</span><span class="sl-t"><strong>All the keys mine</strong> if you create it alone, <strong>Shared vault</strong> if each participant generates their own key on their own device.</span></div>
        <div class="step-line"><span class="sl-n">3</span><span class="sl-t"><strong>Choose how many keys and how many signatures.</strong> 2 of 3 is the most used configuration: you tolerate the loss of one key and resist the theft of one.</span></div>
        <div class="step-line"><span class="sl-n">4</span><span class="sl-t"><strong>Save each key separately</strong> and also keep the <em>descriptor</em>: without it, rebuilding the vault is much harder.</span></div>
        <div class="step-line"><span class="sl-n">5</span><span class="sl-t"><strong>Import the descriptor into Sparrow</strong> and check that it shows the same address. Then do a test with a token amount before depositing for real.</span></div>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><span class="step-badge">4</span><h2>Checking an existing wallet</h2></div>
      <p style="margin-bottom:12px">The <strong>Check wallet</strong> section has four paths.</p>
      <div class="steps-box">
        <div class="step-line"><span class="sl-n">◆</span><span class="sl-t"><strong>A complete seed.</strong> Enter your words and see which addresses they generate.</span></div>
        <div class="step-line"><span class="sl-n">◆</span><span class="sl-t"><strong>Shamir backup.</strong> Reassemble the parts to get the seed back, or turn an existing seed into a Shamir backup.</span></div>
        <div class="step-line"><span class="sl-n">◆</span><span class="sl-t"><strong>SLIP-39 sheets.</strong> Enter the 20-word sheets, including ones generated by a Trezor, and get the addresses.</span></div>
        <div class="step-line"><span class="sl-n">◆</span><span class="sl-t"><strong>Multisig vault.</strong> Paste the xpubs and the threshold to recalculate the address and confirm the configuration.</span></div>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><span class="step-badge">5</span><h2>Spending the funds</h2></div>
      <p style="margin-bottom:12px">AmnesicWallet does not sign transactions, by design: it stays a small generator that can be read and checked, with no reason ever to go online. To spend, you use the words in a wallet that signs.</p>
      <div class="steps-box">
        <div class="step-line"><span class="sl-n">₿</span><span class="sl-t"><strong>Bitcoin → Sparrow or Electrum.</strong></span></div>
        <div class="step-line"><span class="sl-n">◈</span><span class="sl-t"><strong>Ethereum and EVM networks → MetaMask or Rabby.</strong></span></div>
        <div class="step-line"><span class="sl-n">◎</span><span class="sl-t"><strong>Solana → Phantom</strong>, <strong>TRON → TronLink</strong>.</span></div>
        <div class="step-line"><span class="sl-n">🛡</span><span class="sl-t"><strong>For significant amounts: hardware wallet.</strong> Enter the seed into a Ledger or Trezor using the physical buttons. The key never touches the computer and transactions are signed inside the device.</span></div>
      </div>
      <div class="note-box" style="margin-top:14px">MetaMask has become multichain: besides Ethereum and the EVM networks it natively handles <strong>Solana</strong>, <strong>Bitcoin</strong> (since December 2025) and <strong>TRON</strong> (since January 2026). By importing the seed there you can therefore follow <strong>all four networks</strong> of AmnesicWallet from a single wallet. One useful clarification: for Bitcoin MetaMask uses only the <strong>Native SegWit</strong> format (bc1q…), so it will not show any Taproot or Legacy addresses. For Bitcoin, in any case, Sparrow remains the most specific and complete tool.</div>
    </div>`;
}

function renderGuideFaq() {
  return `
    <div class="card">
      <div class="faq-list">

        <details class="faq" id="g-entropy" open><summary>⭐ Why this way of creating the seed is different</summary><div class="faq-body">
          <p>Everything in a wallet depends on a single number: the starting one. If that number is predictable, it doesn't matter how robust the cryptography downstream is — the wallet is already lost. That is exactly how real funds have vanished, when a faulty generator produced numbers far less random than they seemed.</p>
          <p><strong>AmnesicWallet's choice is not to depend on a single source.</strong> We mix three (or four, if you use the dice), of completely different natures:</p>
          <p><strong>1 · The browser's cryptographic generator.</strong> The browser has a built-in cryptographic generator, called a CSPRNG. It is fed directly by the operating system and is made exactly for this purpose.</p>
          <p><strong>2 · The rhythm of your fingers.</strong> As you type on the keyboard we record <em>when</em> you press each key, to the millisecond. Not the characters — humans choose those badly — but the micro-pauses between one key and the next: irregularities born of your physiology that not even you could reproduce.</p>
          <p><strong>3 · The path of your hand.</strong> Hundreds of coordinates and times as you move the mouse: where you accelerate, where you hesitate, where you change direction. A human movement never repeats itself identically.</p>
          <p><strong>4 · The dice, if you choose them.</strong> The only source born <em>outside</em> the computer. No software bug can predict a rolling die.</p>
          <p>The sources are fused with <strong>SHA-256</strong>, the same function that protects the Bitcoin network. The property that matters is this: <strong>the result can never be weaker than the best source.</strong> If one gives way, the others hold. It isn't a sum of securities, it's a safety net.</p>
        </div></details>

        <details class="faq" id="g-seed"><summary>🌱 What the seed is, in plain words</summary><div class="faq-body">
          <p>The seed is a sequence of words — 12 to 24 — that represents the <strong>master key</strong> of your wallet. From it, mathematics derives all your addresses and all the keys to spend, on every network.</p>
          <p>Two truths to keep always in mind:</p>
          <p><strong>Whoever knows the words owns the funds.</strong> There is no identity check, there is no appeal. Never share them with anyone.</p>
          <p><strong>If you lose the words, you lose everything.</strong> There is no "forgot password", there is no customer service. This is the flip side of true ownership.</p>
        </div></details>

        <details class="faq" id="g-passphrase"><summary>🔑 The passphrase: a second lock</summary><div class="faq-body">
          <p>It is a word or phrase of your own choosing that is added to the 12/24 words. Technically it's called a <em>passphrase</em> and it enters the wallet calculation: the same words, with and without it, open <strong>two completely different wallets</strong>.</p>
          <p><strong>What it is really for.</strong> Your paper backup, on its own, becomes useless to whoever finds it: they will see a wallet different from yours, probably empty, without imagining that the real wallet is elsewhere.</p>
          <p><strong>The price to pay.</strong> Forgetting it means losing everything, even with every word of the seed. Keep it somewhere different from the words — it is the separation that gives it value.</p>
        </div></details>

        <details class="faq"><summary>👁️ Why the words stay covered</summary><div class="faq-body">
          <p>A passing glance, a video call left open, an automatic screenshot: a couple of seconds are enough for a seed to stop being secret. That's why, by default, we don't show it.</p>
          <p>You can copy or print it without ever seeing it, or press <strong>Reveal the words</strong> when you're sure you're alone — useful for writing it down by hand. The same applies to the parts of a split backup.</p>
        </div></details>

        <details class="faq" id="g-backup"><summary>🧩 Splitting the seed: three routes</summary><div class="faq-body">
          <p>Right after creating the wallet, the program asks you <strong>how you want to keep it</strong>: a single backup, split sequentially, or with a Shamir threshold. You can change your mind at any time using the <em>Split into several parts</em> button.</p>
          <p><strong>📄 A single backup.</strong> The words on one sheet only. It's the right choice to start with and for small amounts: immediate, recoverable anywhere. The limit is obvious: if that sheet disappears, everything disappears.</p>
          <p><strong>✂️ Sequential splitting.</strong> The words are cut into consecutive groups: with 12 words and 3 parts you get 1-4, 5-8, 9-12. To reassemble you simply put them back in order without any software. In exchange <strong>all</strong> the parts are needed, and anyone finding two out of three would have few words left to guess.</p>
          <p><strong>🔐 Shamir backup.</strong> Named after the cryptographer Adi Shamir. It doesn't cut the seed, it <em>transforms</em> it into parts that are worth something only together. You choose the threshold — 3 parts, 2 are enough — so you can lose some without consequence. And below the threshold the parts reveal <strong>nothing</strong> about the seed: not "almost nothing", zero, by theorem. (The short verification code printed on them is only a fingerprint for checking the result.)</p>
          <p><strong>How to choose:</strong> Shamir if you fear theft or loss; sequential if you fear depending on software many years from now.</p>
        </div></details>

        <details class="faq" id="g-standard"><summary>📄 SLIP-39: the backup born already split</summary><div class="faq-body">
          <p>When you create a wallet you can choose between two backup standards. <strong>BIP-39</strong> gives you a single phrase of 12 or 24 words. <strong>SLIP-39</strong> gives you instead several sheets of 20 words each, and some of them — for example 3 of 5 — are enough to reopen the wallet.</p>
          <p><strong>The difference that matters.</strong> With BIP-39 the complete phrase exists: you see it, you write it, and from that moment it is your weak point. With SLIP-39 <strong>the whole phrase never exists at any moment</strong>, not even on screen while you create it. Only the sheets exist, and each one alone reveals nothing.</p>
          <p><strong>How to recognise the sheets.</strong> They have 20 words (or 33 for 256-bit backups) and the <strong>first three words are identical</strong> on every sheet of the same backup: they exist precisely to let you see at a glance whether you are mixing sheets from different sets. The words come from a dedicated dictionary of 1024 entries, different from the BIP-39 one.</p>
          <p><strong>Where it is used.</strong> It is the standard that <strong>Trezor</strong> adopts as the default backup on recent models. It is also read by <strong>Sparrow</strong> (from version 2.0), <strong>Electrum</strong>, <strong>Rabby</strong>, <strong>BlueWallet</strong>, <strong>Wasabi</strong> and <strong>Keystone</strong>. So you are not tied to AmnesicWallet: unlike the Shamir backup, this is a public standard.</p>
        </div></details>

        <details class="faq"><summary>🔐 Shamir backup explained properly: what it does and what it doesn't</summary><div class="faq-body">
          <p><strong>What happens when you use it.</strong> The original seed is transformed into several parts — for example 5 — and you decide how many are needed to get it back, for example 3. You keep them in different places. When you need the wallet you enter three of them under <em>🔍 Check wallet → Shamir backup → I have the parts, I want the seed</em> and you get <strong>the original seed</strong>. From there you use it wherever you like — Sparrow, Electrum, MetaMask, a Ledger — and none of those programs will ever know you used Shamir, because they don't need to.</p>
          <p><strong>You can use it at two different moments, and this is what most often escapes people.</strong></p>
          <p><strong>1. While creating a new wallet.</strong> Right after generation, when the program asks how to keep the seed, choose <em>Shamir backup</em>. The complete phrase is never written out: you start with the backup already split.</p>
          <p><strong>2. On a seed you already own</strong>, even one created years ago with another program. Go to <em>🔍 Check wallet → Shamir backup → I have a seed, I want to split it</em>, enter your words and choose the threshold and number of parts. The wallet does not change: same addresses, funds in place. Only the way you keep it changes. From that moment you can destroy the sheet with the whole phrase and keep only the parts.</p>
          <p>Here is the advantage over a classic seed: with the traditional phrase, whoever finds that sheet has everything. With this system, whoever finds one part has nothing. Several fragments are needed together, someone has to realise they belong together, know this backup exists and have the right program. The difference is this: a normal seed is a single weak point. With Shamir, your funds stay safe even if some piece ends up where it shouldn't.</p>
          <p><strong>A useful way to see it:</strong> the parts are a form of encryption of the backup, where the key is "holding enough parts". With one advantage over a password: there is nothing to remember. And below the threshold no attempt will do — it isn't hard to guess, it's mathematically impossible. The 4-character verification code printed on the sheets is only a short fingerprint used to confirm the result: it leaves an attacker with at least 2¹¹² possibilities, far beyond any computer.</p>
          <p><strong>The parts are not wallets.</strong> Each one is made of words and looks every bit like a seed, but it is a fragment. Don't send funds to it and don't import it into a wallet expecting to find something there. On its own, below the threshold, it is worth nothing — and that is exactly what makes it safe.</p>
          <p><strong>You need this program to reassemble them.</strong> It is the price of the method and it must be said clearly: <strong>keep a copy of the file <em>amnesicwallet.html</em> together with the parts</strong>. If that dependency bothers you, consider <strong>SLIP-39</strong>, which does the same thing with a public standard read by Trezor, Sparrow and Electrum — but it must be chosen when creating a new wallet, it does not apply to an existing BIP-39 seed.</p>
          <p><strong>Careful not to confuse it with Trezor's Shamir.</strong> Trezor offers a feature called <em>Shamir Backup</em>, but it uses the SLIP-39 standard. Parts created here <strong>do not work</strong> in Trezor's Shamir recovery, and vice versa. They are two separate systems that share a name.</p>
        </div></details>

        <details class="faq" id="g-powers"><summary>🔢 Powers-of-2 backup</summary><div class="faq-body">
          <p>There is a way of saving the seed that uses no words: <strong>just dots on a grid</strong>.</p>
          <p><strong>The mechanism.</strong> Every word in the BIP-39 dictionary has a number from 1 to 2048, and every number can be written as a sum of powers of two: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048. The grid has one column for each. The 2045th word, for example, has the boxes 1024, 512, 256, 128, 64, 32, 16, 8, 4 and 1 marked. To find the corresponding word you just add up the numbers on each row.</p>
          <p><strong>Why it is interesting.</strong> There are no words written on the grid and whoever finds it sees only dots. The problem is not reading it, it's understanding it: you would have to know what that grid is, what those dots mean and how they are used.</p>
          <p><strong>How it's done.</strong> From the wallet, press <em>🔢 Powers-of-2 backup</em>. You get a grid with one row per word and the dots already in the right place — with no words and no numbers: the translation will be up to you at recovery time. Print the numbered dictionary as well and keep it separately.</p>
        </div></details>

        <details class="faq" id="g-formats"><summary>₿ The four Bitcoin address formats</summary><div class="faq-body">
          <p>Bitcoin has changed address format several times over the years. From the <strong>same seed</strong> you can generate all four: they are not different wallets, they are different ways of writing the same ownership.</p>
          <p><strong>Native SegWit</strong> (<em>bc1q…</em>) — Today's standard, and the default choice: low fees and accepted practically everywhere.</p>
          <p><strong>Taproot</strong> (<em>bc1p…</em>) — The most recent: even lower fees and greater privacy. Some older services don't accept it yet.</p>
          <p><strong>SegWit compatible</strong> (<em>3…</em>) — A transitional format, accepted even by the oldest services.</p>
          <p><strong>Legacy</strong> (<em>1…</em>) — The original format from 2009. It always works, but costs more in fees.</p>
          <p>Each format uses a different derivation path, so it produces different addresses. If you are recovering an old wallet and the address doesn't match, try changing format: the seed is probably right.</p>
        </div></details>

        <details class="faq" id="g-derivation"><summary>🧭 The derivation path, explained</summary><div class="faq-body">
          <p>From your seed come very many different addresses, not just one. The derivation path indicates which address you are taking among them all.</p>
          <p>It is a sequence of numbers. Each number represents a precise choice, a step along the path.</p>
          <p>Here is a derivation path explained:</p>
          <div class="path-demo">
            <code class="pd-full">m / 84' / 0' / 0' / 0 / 0</code>
            <div class="pd-legend">
              <div class="pd-row"><code>m</code><span>The root: the seed itself. Everything starts here.</span></div>
              <div class="pd-row"><code>84'</code><span><strong>Purpose</strong> — what kind of address you want. 44 Legacy, 49 SegWit compatible, 84 Native SegWit, 86 Taproot, 48 multisig.</span></div>
              <div class="pd-row"><code>0'</code><span><strong>Coin</strong> — which network. 0 Bitcoin, 60 Ethereum, 195 TRON, 501 Solana. The numbers are assigned by the SLIP-44 standard.</span></div>
              <div class="pd-row"><code>0'</code><span><strong>Account</strong> — separate accounts inside the same wallet. The first is 0, the second 1, and so on.</span></div>
              <div class="pd-row"><code>0</code><span><strong>Chain</strong> — 0 for the public addresses you give others to receive, 1 for those used for change, generated by the wallet.</span></div>
              <div class="pd-row"><code>0</code><span><strong>Index</strong> — the address's sequential number: 0, 1, 2, 3…</span></div>
            </div>
          </div>
          <p style="margin-top:14px"><strong>How many addresses can you have?</strong> Each level of the path allows around two billion possible values. This applies both to accounts and to addresses: you can have billions of different accounts and, inside each account, billions of different addresses.</p>
          <p><strong>What does the apostrophe mean?</strong> It indicates a <em>hardened</em> derivation, that is a reinforced one. Without it, anyone holding an extended public key and a single child private key could work back to the parent key. The apostrophe closes that road. That's why the first three levels always have it.</p>
          <p><strong>Why it concerns you.</strong> If you import the seed elsewhere and the addresses don't match (particularly with Bitcoin, which has several formats), it is almost always the path that differs — not the seed. It's the reason why a Legacy wallet and a Native SegWit one, though born from the same words, show completely different addresses: they simply sit on different branches of the same tree.</p>
        </div></details>

        <details class="faq" id="g-networks"><summary>📬 Why does Bitcoin have many addresses and the other networks only one?</summary><div class="faq-body">
          <p>In the Bitcoin world it is good practice to use <strong>a new address for every payment you receive</strong>. All the addresses belong to the same wallet and are controlled by the same seed, but anyone watching the blockchain has a much harder time linking your incoming payments together.</p>
          <p>That's why, after generating the wallet, you find the <em>Show more Bitcoin addresses</em> button: it generates ten at a time, all yours.</p>
          <p>On <strong>Ethereum, TRON and Solana</strong> it works differently: you always use the same address, always. That is the normal behaviour of those networks — it is not a limitation of the program.</p>
        </div></details>

        <details class="faq" id="g-watch"><summary>👁️ Seeing the balance without risking anything (watch-only)</summary><div class="faq-body">
          <p>After generating the Bitcoin addresses, the <em>View xpub and descriptor</em> button shows a <strong>descriptor</strong>: a line of text that describes your wallet <em>without containing the keys to spend</em>. For a normal wallet it is entirely optional — your words are all you need to recover. In <strong>multisig</strong>, however, <strong>it is essential</strong>: without it, rebuilding the vault is much harder.</p>
          <p>By pasting it into <strong>Sparrow</strong> (<em>File → Import Wallet → Output Descriptor</em>) or into Electrum, you get a read-only wallet: you see balance and movements in real time, but nobody — not even you, from there — can move the funds. The seed stays safe where it is, without ever touching a connected device.</p>
          <p>It's the best way to keep an eye on a cold wallet from your phone or your everyday computer.</p>
          <p><strong>A privacy warning:</strong> whoever holds the descriptor sees all your Bitcoin movements, present and future. They cannot spend, but it is like handing over a bank statement: share it only with someone you'd trust to see your accounts.</p>
        </div></details>

        <details class="faq" id="g-verify"><summary>🔍 I have an old backup: how do I check it's good?</summary><div class="faq-body">
          <p>Go to <strong>🔍 Check wallet</strong> and choose <strong>A complete seed</strong>. Type the words and the program shows you which addresses they generate, without changing anything and without taking the seed onto a connected device.</p>
          <p>If the addresses match those you remember or see in a blockchain explorer, the backup is correct. If they don't match, check in this order: the <strong>passphrase</strong> (had you set one?), the <strong>Bitcoin format</strong> (try the other three), and finally the <strong>later addresses</strong> using the button that shows ten more.</p>
          <p>⚠️ Typing a seed is by far the most delicate moment: do it with the device disconnected from the internet, or better still from a Tails system or a clean virtual machine.</p>
        </div></details>

        <details class="faq" id="g-multisig"><summary>🔐 Multisig: when one key isn't enough</summary><div class="faq-body">
          <p>A <em>multisig</em> address requires several keys to move the funds — for example 2 signatures out of 3. It is used in two very different ways:</p>
          <p><strong>👤 All the keys yours.</strong> It's the most common use, and perhaps the best security upgrade for anyone self-custodying. You create three keys and distribute them across three different places. From then on a thief who ransacks your home gets nothing, and you can lose one backup without losing a cent. The moment the keys are born together is the only one in which they coexist.</p>
          <p><strong>👥 With other people.</strong> For family, company or group funds. Everyone creates their key on their own device and shares only the <strong>xpub</strong>, a public code that reveals nothing secret. Nobody can spend alone.</p>
          <p><strong>To be kept with the backups:</strong> the <em>descriptor</em>, the formula describing how the keys combine. With the seeds alone, but without the descriptor, rebuilding the vault is far more laborious.</p>
        </div></details>

        <details class="faq"><summary>📴 Does it really connect to nothing?</summary><div class="faq-body">
          <p>Really. No network request, at any moment: no servers, no statistics, no silent updates. All the cryptographic libraries are embedded in the file, and nothing is downloaded while you use it.</p>
          <p>It is not only a promise in the code. The file carries a rule for the browser, called <em>Content-Security-Policy</em>, that forbids any connection and any script other than its own: even a bug, or a modified copy of a library, would be stopped by the browser itself.</p>
          <p>Nothing is saved either: no cookies, no local storage, no files written. The seed lives only in the page's memory, and the browser releases it when you close the tab.</p>
          <p><strong>And you can verify it yourself.</strong> Open the file on a computer disconnected from the internet: it works exactly the same way. That is in fact how we recommend using it.</p>
        </div></details>

        <details class="faq"><summary>💸 Can I spend from here?</summary><div class="faq-body">
          <p>No, and it's a deliberate choice. Spending means building transactions and sending them to the network: a whole wallet, with far more code and a reason to go online. AmnesicWallet does one thing — create wallets in a clean environment — and keeps it small enough to be checked.</p>
          <p>To receive, the address is enough. To spend, import your words into a compatible wallet: <strong>Electrum</strong> or <strong>Sparrow</strong> for Bitcoin, <strong>MetaMask</strong> or <strong>Rabby</strong> for Ethereum, <strong>TronLink</strong> and <strong>Phantom</strong> for the other networks.</p>
          <p>For significant amounts, the best choice is to import the seed into a <strong>hardware wallet</strong> such as a Ledger or Trezor: it signs transactions internally, without ever exposing the key to the computer.</p>
        </div></details>

        <details class="faq"><summary>🛡️ The five rules that matter</summary><div class="faq-body">
          <p><strong>1 · Generate offline.</strong> Disconnect the device from the network, or use a clean bootable USB stick. It's how this tool gives its best.</p>
          <p><strong>2 · Save the backup before using the wallet.</strong> The words are the only key: whoever holds them holds the funds, whoever loses them loses access. Choose the way of keeping them that you consider safest, and do it before you send any funds.</p>
          <p><strong>3 · Know your single points of failure.</strong> One sheet in one place can be lost or found. Splitting it (Shamir, SLIP-39) or a multisig vault remove that single point, at the price of more pieces to look after: weigh which risk worries you more.</p>
          <p><strong>4 · Verify before trusting.</strong> On the same offline device, restore the words in a second program such as Sparrow or Electrum and check that the address matches. Two independent tools that agree are worth more than any guarantee.</p>
          <p><strong>5 · Do a test run.</strong> Send a token amount, then try recovering it from the backup alone. <strong>An unverified backup is not a backup: it's a hope.</strong></p>
        </div></details>

      </div>
    </div>`;
}

function wireGuide() {
  const view = document.getElementById('guide-view');
  if (!view) return;
  const paint = (which) => {
    view.innerHTML = which === 'faq' ? renderGuideFaq() : renderGuideSteps();
    document.querySelectorAll('.gn-btn').forEach(b =>
      b.classList.toggle('gn-active', b.dataset.gview === which));
    guideView = which;
  };
  document.querySelectorAll('.gn-btn').forEach(b =>
    b.addEventListener('click', () => paint(b.dataset.gview)));
  paint(guideView);
}

/* ════════════════════════════════════════════════════════════════
   INIT
   ════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', renderApp);
