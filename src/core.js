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
 */

/* ════════════════════════════════════════════════════════════════
   CORE — every piece of cryptography and key handling lives here.

   Nothing in this file touches the page: no DOM, no timers, no
   storage, no network. That separation is deliberate. It means the
   exact code that runs in the browser is also the code exercised by
   `npm test`, against official test vectors, in CI.

   Every primitive comes from the @noble / @scure libraries, which
   are small, dependency-free and have been independently audited.
   ════════════════════════════════════════════════════════════════ */

import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { hmac } from '@noble/hashes/hmac.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { base58, bech32, bech32m, createBase58check } from '@scure/base';
import slip39lib from 'slip39';

export { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic, wordlist, HDKey };

const base58check = createBase58check(sha256);

export const WORD_OPTIONS = [12, 15, 18, 21, 24];
export const ENT_BYTES = { 12: 16, 15: 20, 18: 24, 21: 28, 24: 32 };

export function toHex(u) {
  return Array.from(u, b => b.toString(16).padStart(2, '0')).join('');
}

/* Words as typed by a person: trimmed, lower-case, single spaces. */
export function normalizeWords(s) {
  return String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

/* ════════════════════════════════════════════════════════════════
   ENTROPY
   ════════════════════════════════════════════════════════════════ */

export function isSecureRandomAvailable() {
  try {
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') return false;
    const probe = new Uint8Array(32);
    crypto.getRandomValues(probe);
    return probe.some(b => b !== 0);
  } catch (_) { return false; }
}

/* Three safety nets. They do not prove anything about cryptographic
   quality — nothing can, from a few bytes — but they stop generation
   if the generator has catastrophically failed (a constant, a repeated
   draw, a heavily unbalanced output). */
export function statisticalChecks(bytes) {
  const first = bytes[0];
  if (bytes.every(b => b === first)) return { ok: false, reason: 'constant' };

  const a = new Uint8Array(32), b = new Uint8Array(32);
  crypto.getRandomValues(a);
  crypto.getRandomValues(b);
  if (a.every((v, i) => v === b[i])) return { ok: false, reason: 'duplicate' };

  let ones = 0;
  for (const byte of bytes) { let v = byte; while (v) { ones += v & 1; v >>= 1; } }
  const ratio = ones / (bytes.length * 8);
  if (ratio < 0.25 || ratio > 0.75) return { ok: false, reason: 'unbalanced' };
  return { ok: true };
}

/* Domain separation: the digest can never be confused with a digest
   computed for any other purpose, by this or any other program. */
const ENTROPY_DOMAIN = new TextEncoder().encode('AmnesicWallet/entropy/v1');

/* Entropy combination. Non-negotiable rule:
   the operating system's CSPRNG (crypto.getRandomValues) is ALWAYS
   present and unconditional. The other sources are ADDED to it, they
   never replace it:

     entropy = SHA-256( domain || csprng[64]
                        || 0x01 || mouse[32] || 0x02 || dice[32] || 0x03 || keys[32] )[0..n]

   Every user source enters as a one-byte label followed by a fixed-length
   SHA-256 digest (an absent source is left out, label included), so the
   input is unambiguous: no two different sets of sources can produce it. With SHA-256 modelled as a random
   oracle, the result is unpredictable to anyone who cannot predict ALL
   the inputs: a broken or observed user source cannot weaken it, and
   a faulty CSPRNG is still covered by the dice, keyboard and pointer.

   `csprng` is a parameter only so that tests can make the output
   deterministic; the application never passes it. */
export function combineEntropy(nBytes, sources = {}, csprng = null) {
  if (!Number.isInteger(nBytes) || nBytes < 16 || nBytes > 32 || nBytes % 4) {
    throw new Error('invalid entropy length: ' + nBytes);
  }
  const base = new Uint8Array(64);
  if (csprng) base.set(csprng.subarray(0, 64));
  else crypto.getRandomValues(base);

  const chk = statisticalChecks(base);
  if (!chk.ok) throw new Error('RNG_ANOMALY:' + chk.reason);

  const parts = [ENTROPY_DOMAIN, base];
  for (const [label, key] of [[1, 'mouse'], [2, 'dice'], [3, 'keys']]) {
    const src = sources[key];
    if (src == null) continue;
    if (!(src instanceof Uint8Array) || src.length !== 32) throw new Error('invalid entropy source: ' + key);
    parts.push(Uint8Array.of(label), src);
  }
  let total = 0; for (const p of parts) total += p.length;
  const concat = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { concat.set(p, off); off += p.length; }

  const out = sha256(concat).slice(0, nBytes);
  concat.fill(0); base.fill(0);                   // best effort: JS cannot guarantee erasure
  // No statistical check on `out`: a SHA-256 digest looks random even when
  // its input is not, so such a test could only raise false alarms. The
  // checks that matter run above, on the raw generator output.
  return out;
}

/* Pointer (mouse / finger) entropy.
   Criteria, all reachable with ordinary movement: at least 8 seconds,
   100 events, 1000 px travelled and 8 changes of direction. */
export function createMouseCollector(now = () => performance.now()) {
  const samples = [];
  let startT = 0, dist = 0, turns = 0, lastDx = 0, lastDy = 0;
  return {
    start() { samples.length = 0; startT = now(); dist = 0; turns = 0; lastDx = 0; lastDy = 0; },
    feed(x, y) {
      const t = now();
      const prev = samples[samples.length - 1];
      if (prev) {
        const dx = x - prev.x, dy = y - prev.y;
        dist += Math.hypot(dx, dy);
        if ((dx !== 0 && lastDx !== 0 && Math.sign(dx) !== Math.sign(lastDx)) ||
            (dy !== 0 && lastDy !== 0 && Math.sign(dy) !== Math.sign(lastDy))) turns++;
        if (dx !== 0) lastDx = dx;
        if (dy !== 0) lastDy = dy;
      }
      samples.push({ x, y, t });
    },
    progress() {
      if (!samples.length) return 0;
      const elapsed = (now() - startT) / 1000;
      return Math.min(Math.min(elapsed / 8, 1), Math.min(samples.length / 100, 1),
                      Math.min(dist / 1000, 1), Math.min(turns / 8, 1));
    },
    bytes() {
      const buf = new Float64Array(samples.length * 3);
      samples.forEach((s, i) => { buf[i * 3] = s.x; buf[i * 3 + 1] = s.y; buf[i * 3 + 2] = s.t; });
      const h = sha256(new Uint8Array(buf.buffer));
      buf.fill(0); samples.length = 0;
      return h;
    },
  };
}

/* Keyboard entropy. The unpredictable part is not the characters
   (people choose them badly) but the timing between keystrokes.
   Requires 20 keystrokes, 5 seconds and 10 distinct keys. */
export function createTypingCollector(now = () => performance.now()) {
  const events = [];
  const seen = new Set();
  let startT = 0;
  return {
    start() { events.length = 0; seen.clear(); startT = now(); },
    feed(key) { events.push({ k: key, t: now() }); seen.add(key); },
    progress() {
      if (!events.length) return 0;
      const elapsed = (now() - startT) / 1000;
      return Math.min(Math.min(events.length / 20, 1), Math.min(elapsed / 5, 1), Math.min(seen.size / 10, 1));
    },
    count() { return events.length; },
    bytes() {
      const parts = events.map(e => e.k + ':' + e.t.toFixed(3));
      const h = sha256(new TextEncoder().encode(parts.join('|')));
      events.length = 0; seen.clear();
      return h;
    },
  };
}

/* Dice: log2(6) ≈ 2.585 bits per roll, so 128 bits need 50 rolls and
   256 bits need 100. With two dice thrown together, identical dice cannot
   be told apart and people tend to enter the smaller number first: a pair
   is then worth only log2(21) ≈ 4.39 bits (21 unordered outcomes), not
   2 × 2.585. The count assumes the worst case: 30 double rolls for 128
   bits, 59 for 256. */
export function diceRollsNeeded(entropyBits, twoDice) {
  return Math.ceil(entropyBits / Math.log2(twoDice ? 21 : 6));
}
export function diceBytesFrom(rolls) {
  if (!rolls.every(r => Number.isInteger(r) && r >= 1 && r <= 6)) throw new Error('invalid die value');
  return sha256(Uint8Array.from(rolls));
}

/* ════════════════════════════════════════════════════════════════
   SHAMIR GF(2^8) — applied directly to the BIP-39 entropy.
   Not SLIP-39 (which cannot represent an existing BIP-39 seed). Each
   part is itself encoded as a BIP-39 mnemonic of the same length, plus
   its part number (the x coordinate) and a 4-character verification
   code. The format is frozen: parts made by any earlier version must
   always reassemble (see tests/vectors/shamir-compat.json).
   ════════════════════════════════════════════════════════════════ */
export const GF = (() => {
  const exp = new Uint8Array(512), log = new Uint8Array(256);
  // Generator 0x03 with the AES polynomial 0x11b. (0x02 does NOT
  // generate the whole multiplicative group of this field; 0x03 does.)
  let x = 1;
  for (let i = 0; i < 255; i++) {
    exp[i] = x; log[x] = i;
    const xt = ((x << 1) ^ ((x & 0x80) ? 0x11b : 0)) & 0xff;   // x·2
    x = x ^ xt;                                                  // x·3
  }
  for (let i = 255; i < 512; i++) exp[i] = exp[i - 255];
  const mul = (a, b) => (a === 0 || b === 0) ? 0 : exp[log[a] + log[b]];
  const div = (a, b) => {
    if (b === 0) throw new Error('division by zero in GF(256)');
    return a === 0 ? 0 : exp[(log[a] - log[b] + 255) % 255];
  };
  return { mul, div };
})();

/* Split `secret` into n parts, any m of which reconstruct it.
   Every coefficient is drawn from the CSPRNG, independently for each
   byte. Uniform coefficients (zero included) are what the proof of
   Shamir's scheme requires: with fewer than m parts, every possible
   secret remains exactly equally likely. */
export function shamirSplit(secret, n, m, rng = (buf) => crypto.getRandomValues(buf)) {
  if (!(secret instanceof Uint8Array) || !secret.length) throw new Error('invalid secret');
  if (!Number.isInteger(n) || !Number.isInteger(m) || m < 2 || n < m || n > 16) throw new Error('invalid parameters');
  const shares = Array.from({ length: n }, () => new Uint8Array(secret.length));
  const coeffs = new Uint8Array(m);
  for (let byteI = 0; byteI < secret.length; byteI++) {
    coeffs[0] = secret[byteI];
    rng(coeffs.subarray(1));
    for (let xi = 1; xi <= n; xi++) {
      let y = 0, xp = 1;
      for (let c = 0; c < m; c++) { y ^= GF.mul(coeffs[c], xp); xp = GF.mul(xp, xi); }
      shares[xi - 1][byteI] = y;
    }
  }
  coeffs.fill(0);
  return shares;                      // shares[i] has x coordinate i + 1
}

/* Lagrange interpolation at x = 0. With at least m correct parts the
   result is the secret; with fewer it is an unrelated value, which the
   verification code detects. */
export function shamirCombine(parts) {
  if (!Array.isArray(parts) || parts.length < 1) throw new Error('no parts');
  const len = parts[0].y.length;
  const xs = new Set();
  for (const p of parts) {
    if (!Number.isInteger(p.x) || p.x < 1 || p.x > 255) throw new Error('invalid part number');
    if (xs.has(p.x)) throw new Error('duplicate part number');
    if (p.y.length !== len) throw new Error('parts of different length');
    xs.add(p.x);
  }
  const secret = new Uint8Array(len);
  for (let byteI = 0; byteI < len; byteI++) {
    let acc = 0;
    for (let i = 0; i < parts.length; i++) {
      let num = 1, den = 1;
      for (let j = 0; j < parts.length; j++) {
        if (i === j) continue;
        num = GF.mul(num, parts[j].x);
        den = GF.mul(den, parts[i].x ^ parts[j].x);
      }
      acc ^= GF.mul(parts[i].y[byteI], GF.div(num, den));
    }
    secret[byteI] = acc;
  }
  return secret;
}

/* 16 bits of SHA-256 of the entropy. A wrong reconstruction passes this
   check once in 65,536 attempts. It reveals nothing usable about the
   secret: 128 bits of entropy remain 128 bits minus 16, far beyond reach. */
export function verificationCode(entropy) {
  return toHex(sha256(entropy).slice(0, 2)).toUpperCase();
}

/* Sequential split: consecutive groups of words, rebuilt by hand. */
export function classicSplit(words, n) {
  const base = Math.floor(words.length / n);
  let extra = words.length % n;
  const out = [];
  let i = 0;
  for (let p = 0; p < n; p++) {
    const size = base + (extra > 0 ? 1 : 0);
    if (extra > 0) extra--;
    out.push({ x: p + 1, from: i + 1, to: i + size, words: words.slice(i, i + size) });
    i += size;
  }
  return out;
}

/* ════════════════════════════════════════════════════════════════
   ADDRESSES
   ════════════════════════════════════════════════════════════════ */
export const CHAINS = [
  { id: 'btc', name: 'Bitcoin',  tag: 'Native SegWit',   icon: '₿' },
  { id: 'eth', name: 'Ethereum', tag: 'EVM · 0x',        icon: 'Ξ' },
  { id: 'trx', name: 'TRON',     tag: 'TRC-20 · Base58', icon: '◆' },
  { id: 'sol', name: 'Solana',   tag: 'Base58',          icon: '◎' },
];

export const BTC_FORMATS = {
  native:  { id: 'native',  label: 'Native SegWit',     tag: 'bc1q…', purpose: 84, std: 'BIP-84',
             desc: "Today's standard: low fees and full compatibility." },
  taproot: { id: 'taproot', label: 'Taproot',           tag: 'bc1p…', purpose: 86, std: 'BIP-86',
             desc: 'The most recent: more privacy and even lower fees.' },
  p2sh:    { id: 'p2sh',    label: 'SegWit compatible', tag: '3…',    purpose: 49, std: 'BIP-49',
             desc: 'Accepted everywhere, even by older services.' },
  legacy:  { id: 'legacy',  label: 'Legacy',            tag: '1…',    purpose: 44, std: 'BIP-44',
             desc: 'The original format from 2009. Higher fees.' },
};

function taggedHash(tag, msg) {
  const t = sha256(new TextEncoder().encode(tag));
  const b = new Uint8Array(t.length * 2 + msg.length);
  b.set(t, 0); b.set(t, t.length); b.set(msg, t.length * 2);
  return sha256(b);
}

function b58check(version, payload) {
  const p = new Uint8Array(1 + payload.length);
  p[0] = version; p.set(payload, 1);
  return base58check.encode(p);
}

const hash160 = (b) => ripemd160(sha256(b));

/* BIP-341 key-path-only output key: Q = P + H_TapTweak(P)·G.
   The internal key is taken with even Y, as the standard requires. */
function taprootOutputKey(compressedPubkey) {
  const xonly = compressedPubkey.slice(1);
  const P = secp256k1.Point.fromHex('02' + toHex(xonly));
  const t = BigInt('0x' + toHex(taggedHash('TapTweak', xonly)));
  if (t >= secp256k1.Point.CURVE().n) throw new Error('taproot tweak out of range');
  const Q = P.add(secp256k1.Point.BASE.multiply(t));
  return Q.toBytes(true).slice(1);
}

export function btcAddressFromPubkey(pubkey, format) {
  if (format === 'legacy') return b58check(0x00, hash160(pubkey));
  if (format === 'p2sh') {
    const redeem = new Uint8Array(22);
    redeem[0] = 0x00; redeem[1] = 0x14; redeem.set(hash160(pubkey), 2);
    return b58check(0x05, hash160(redeem));
  }
  if (format === 'taproot') {
    return bech32m.encode('bc', [0x01, ...bech32m.toWords(taprootOutputKey(pubkey))]);
  }
  return bech32.encode('bc', [0x00, ...bech32.toWords(hash160(pubkey))]);
}

/* Account numbers start from 0 here; the interface shows them as 1, 2, 3… */
export function btcPath(format, index, change = 0, account = 0) {
  return `m/${BTC_FORMATS[format].purpose}'/0'/${account}'/${change}/${index}`;
}

function fingerprintHex(node) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, node.fingerprint >>> 0, false);   // big-endian, on any platform
  return toHex(b);
}

export function deriveBTC(master, format, index = 0, account = 0) {
  const fmt = BTC_FORMATS[format] ? format : 'native';
  const path = btcPath(fmt, index, 0, account);
  const f = BTC_FORMATS[fmt];
  return {
    name: `Bitcoin — ${f.label}`, symbol: 'BTC',
    address: btcAddressFromPubkey(master.derive(path).publicKey, fmt),
    path, icon: '₿', btcFormat: fmt,
  };
}

/* change = 1 gives the change addresses, where wallets send what is left
   of a payment. */
export function deriveBTCMany(master, format, from, count, change = 0, account = 0) {
  const out = [];
  for (let i = from; i < from + count; i++) {
    const path = btcPath(format, i, change, account);
    out.push({ index: i, path, address: btcAddressFromPubkey(master.derive(path).publicKey, format) });
  }
  return out;
}

/* ── Output descriptors (BIP-380) with checksum ─────────────────── */
const DESC_INPUT = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const DESC_CHECKSUM = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const DESC_GEN = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

function descPolymod(symbols) {
  let chk = 1n;
  for (const value of symbols) {
    const top = chk >> 35n;
    chk = ((chk & 0x7ffffffffn) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) chk ^= DESC_GEN[i];
  }
  return chk;
}

export function descriptorChecksum(desc) {
  const symbols = [];
  let groups = [];
  for (const ch of desc) {
    const v = DESC_INPUT.indexOf(ch);
    if (v < 0) throw new Error('invalid character in descriptor');
    symbols.push(v & 31);
    groups.push(v >> 5);
    if (groups.length === 3) { symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]); groups = []; }
  }
  if (groups.length === 1) symbols.push(groups[0]);
  else if (groups.length === 2) symbols.push(groups[0] * 3 + groups[1]);
  const chk = descPolymod(symbols.concat([0, 0, 0, 0, 0, 0, 0, 0])) ^ 1n;
  let out = '';
  for (let i = 0; i < 8; i++) out += DESC_CHECKSUM[Number((chk >> BigInt(5 * (7 - i))) & 31n)];
  return out;
}
export const withChecksum = (desc) => `${desc}#${descriptorChecksum(desc)}`;

/* Account xpub and descriptor, for watch-only monitoring. */
export function btcAccountInfo(seed, format, account = 0) {
  const master = HDKey.fromMasterSeed(new Uint8Array(seed));
  const f = BTC_FORMATS[format] || BTC_FORMATS.native;
  const acctPath = `m/${f.purpose}'/0'/${account}'`;
  const acct = master.derive(acctPath);
  const fp = fingerprintHex(master);
  const key = `[${fp}/${f.purpose}h/0h/${account}h]${acct.publicExtendedKey}/0/*`;
  const body = { native: `wpkh(${key})`, taproot: `tr(${key})`, p2sh: `sh(wpkh(${key}))`, legacy: `pkh(${key})` }[f.id];
  return { xpub: acct.publicExtendedKey, path: acctPath, fingerprint: fp, descriptor: withChecksum(body), format: f };
}

/* EIP-55 mixed-case checksum. */
export function toChecksumAddress(hex40) {
  const lower = hex40.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(lower)) throw new Error('invalid address');
  const h = toHex(keccak_256(new TextEncoder().encode(lower)));
  let out = '0x';
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  return out;
}

/* Last 20 bytes of Keccak-256 of the uncompressed public key (minus 0x04). */
function evmAddressBytes(compressedPubkey) {
  const full = secp256k1.Point.fromBytes(compressedPubkey).toBytes(false);
  return keccak_256(full.slice(1)).slice(-20);
}

/* For Ethereum and TRON, "Account 2" in MetaMask, Trust Wallet, TronLink
   and most wallets is the second address of the same branch. */
export function deriveETH(master, account = 0) {
  const path = `m/44'/60'/0'/0/${account}`;
  const address = toChecksumAddress(toHex(evmAddressBytes(master.derive(path).publicKey)));
  return { name: 'Ethereum (EVM compatible)', symbol: 'ETH', address, path, icon: 'Ξ',
    evmChains: ['Ethereum', 'BSC', 'Polygon', 'Arbitrum', 'Avalanche', 'Optimism', 'Base'] };
}

export function deriveTRX(master, account = 0) {
  const path = `m/44'/195'/0'/0/${account}`;
  return { name: 'TRON (TRC-20)', symbol: 'TRX', address: b58check(0x41, evmAddressBytes(master.derive(path).publicKey)), path, icon: '◆' };
}

/* SLIP-10 for ed25519: hardened derivation only. */
export function slip10Ed25519(seed, path) {
  let I = hmac(sha512, new TextEncoder().encode('ed25519 seed'), new Uint8Array(seed));
  let key = I.slice(0, 32), chain = I.slice(32);
  for (const idx of path) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= 0x80000000) throw new Error('invalid index');
    const d = new Uint8Array(37);
    d[0] = 0; d.set(key, 1);
    new DataView(d.buffer).setUint32(33, (idx | 0x80000000) >>> 0, false);
    I = hmac(sha512, chain, d);
    key = I.slice(0, 32); chain = I.slice(32);
  }
  return { key, chainCode: chain };
}

/* Phantom, Solflare and Backpack: "Account 2" is m/44'/501'/1'/0'. */
export function deriveSOL(seed, account = 0) {
  const { key } = slip10Ed25519(seed, [44, 501, account, 0]);
  const address = base58.encode(ed25519.getPublicKey(key));
  key.fill(0);
  return { name: 'Solana', symbol: 'SOL', address, path: `m/44'/501'/${account}'/0'`, icon: '◎' };
}

export function deriveAll(seed, selected, btcFormat, account = 0) {
  if (!Number.isInteger(account) || account < 0 || account >= 0x80000000) throw new Error('invalid account');
  const master = HDKey.fromMasterSeed(new Uint8Array(seed));
  const results = {};
  for (const id of selected) {
    let entry = null;
    if (id === 'btc') entry = deriveBTC(master, btcFormat, 0, account);
    else if (id === 'eth') entry = deriveETH(master, account);
    else if (id === 'trx') entry = deriveTRX(master, account);
    else if (id === 'sol') entry = deriveSOL(seed, account);
    if (entry) { entry.id = id; results[id] = entry; }
  }
  return results;
}

/* ════════════════════════════════════════════════════════════════
   DERIVATION PATHS — any path, on any network
   The same words give different addresses depending on the path a
   wallet follows. These functions compute the address at any path, so
   the check can show every known path, including unusual ones.
   ════════════════════════════════════════════════════════════════ */

/* "m/44'/60'/0'/0/0" (or with h / H for hardened) → [{ index, hardened }].
   Returns null when the text is not a valid path. */
export function parsePath(text) {
  const s = String(text || '').trim().replace(/\s+/g, '');
  if (!/^m(\/\d+['hH]?)*$/.test(s)) return null;
  const parts = [];
  for (const piece of s.split('/').slice(1)) {
    const hardened = /['hH]$/.test(piece);
    const digits = hardened ? piece.slice(0, -1) : piece;
    if (digits.length > 10) return null;
    const index = Number(digits);
    if (!Number.isSafeInteger(index) || index >= 0x80000000) return null;
    parts.push({ index, hardened });
  }
  return parts;
}

export const pathToString = (parts) => 'm' + parts.map(p => `/${p.index}${p.hardened ? "'" : ''}`).join('');

/* chain: 'btc' (with a format), 'eth', 'trx' or 'sol'.
   For Solana, path null means the key made directly from the first 32
   bytes of the seed, with no derivation (solana-keygen's default). */
export function addressAtPath(seed, chain, path, btcFormat = 'native') {
  if (chain === 'sol') {
    let key;
    if (path === null) key = new Uint8Array(seed).slice(0, 32);
    else {
      const parts = parsePath(path);
      if (!parts) throw new Error('INVALID_PATH');
      if (parts.some(p => !p.hardened)) throw new Error('SOL_HARDENED_ONLY');
      key = slip10Ed25519(seed, parts.map(p => p.index)).key;
    }
    const address = base58.encode(ed25519.getPublicKey(key));
    key.fill(0);
    return address;
  }
  if (!['btc', 'eth', 'trx'].includes(chain)) throw new Error('INVALID_CHAIN');
  return secpAddress(secpPubkey(HDKey.fromMasterSeed(new Uint8Array(seed)), path), chain, btcFormat);
}

function secpPubkey(master, path) {
  const parts = parsePath(path);
  if (!parts) throw new Error('INVALID_PATH');
  return master.derive(pathToString(parts)).publicKey;
}

function secpAddress(pubkey, chain, btcFormat) {
  if (chain === 'btc') return btcAddressFromPubkey(pubkey, BTC_FORMATS[btcFormat] ? btcFormat : 'native');
  if (chain === 'eth') return toChecksumAddress(toHex(evmAddressBytes(pubkey)));
  if (chain === 'trx') return b58check(0x41, evmAddressBytes(pubkey));
  throw new Error('INVALID_CHAIN');
}

/* Known paths per network. {n} is the account chosen on screen (0 for
   "Account 1"). 'std' marks the path the check uses by default; 'odd'
   marks paths that belong to another network or standard, where funds
   can end up through a wallet that mixes them. For Bitcoin, 'fmt' is
   the address format that normally goes with the path. */
export const PATH_SCHEMES = {
  btc: [
    { path: "m/84'/0'/{n}'/0/0",  fmt: 'native',  used: 'BIP-84 — Native SegWit (most wallets today)', std: true },
    { path: "m/86'/0'/{n}'/0/0",  fmt: 'taproot', used: 'BIP-86 — Taproot', std: true },
    { path: "m/49'/0'/{n}'/0/0",  fmt: 'p2sh',    used: 'BIP-49 — SegWit compatible', std: true },
    { path: "m/44'/0'/{n}'/0/0",  fmt: 'legacy',  used: 'BIP-44 — Legacy', std: true },
    { path: "m/84'/0'/{n}'/1/0",  fmt: 'native',  used: 'BIP-84, first change address' },
    { path: "m/0'/0/{n}",         fmt: 'legacy',  used: 'BRD (breadwallet), MultiBit HD — no accounts: the account number picks the address' },
    { path: "m/0'/0'/{n}'",       fmt: 'p2sh',    used: 'Bitcoin Core HD wallets before version 0.21 — the account number picks the address' },
    { path: "m/84'/0'/2147483646'/0/{n}", fmt: 'native', used: 'Samourai / Ashigaru, Whirlpool post-mix — the account number picks the address' },
    { path: "m/84'/0'/2147483645'/0/{n}", fmt: 'native', used: 'Samourai / Ashigaru, Whirlpool pre-mix — the account number picks the address' },
    { path: "m/44'/145'/{n}'/0/0", fmt: 'legacy', used: "Bitcoin Cash's path", odd: true },
    { path: "m/44'/60'/0'/0/{n}", fmt: 'legacy',  used: "Ethereum's path", odd: true },
    { path: "m/44'/195'/0'/0/{n}", fmt: 'legacy', used: "TRON's path", odd: true },
  ],
  eth: [
    { path: "m/44'/60'/0'/0/{n}", used: 'MetaMask, Trezor, Trust Wallet, Rabby, Exodus — "Account N" is the N-th address', std: true },
    { path: "m/44'/60'/{n}'/0/0", used: 'Ledger Live — each account is its own branch' },
    { path: "m/44'/60'/0'/{n}",   used: 'Ledger legacy path (MyEtherWallet, MyCrypto)' },
    { path: "m/44'/0'/0'/0/{n}",  used: "Bitcoin's path", odd: true },
    { path: "m/44'/195'/0'/0/{n}", used: "TRON's path", odd: true },
  ],
  trx: [
    { path: "m/44'/195'/0'/0/{n}", used: 'Trust Wallet and most wallets — "Account N" is the N-th address', std: true },
    { path: "m/44'/195'/{n}'/0/0", used: 'Ledger Live — each account is its own branch' },
    { path: "m/44'/60'/0'/0/{n}",  used: "Ethereum's path (same key as the Ethereum address)", odd: true },
    { path: "m/44'/0'/0'/0/{n}",   used: "Bitcoin's path", odd: true },
  ],
  sol: [
    { path: "m/44'/501'/{n}'/0'", used: 'Phantom, Solflare, Backpack — "Account N"', std: true },
    { path: "m/44'/501'/{n}'",    used: 'Ledger, Trust Wallet, Solflare with a Ledger path' },
    { path: "m/44'/501'",         used: "solana-keygen with the path m/44'/501' (a single address)" },
    { path: null,                 used: 'solana-keygen default: no path, the first 32 bytes of the seed (a single address)' },
  ],
};

export const fillPath = (tpl, account) => (tpl === null ? null : tpl.replace(/\{n\}/g, String(account)));

/* Every known path of one network for one account, with its address.
   For Bitcoin each path is given in all four address formats. */
export function allPaths(seed, chain, account = 0) {
  if (!Number.isInteger(account) || account < 0 || account >= 0x80000000) throw new Error('invalid account');
  const master = chain === 'sol' ? null : HDKey.fromMasterSeed(new Uint8Array(seed));
  const out = [];
  for (const s of PATH_SCHEMES[chain] || []) {
    const path = fillPath(s.path, account);
    // A path with no account number gives a single address: shown with Account 1 only.
    if (account > 0 && (s.path === null || !s.path.includes('{n}'))) continue;
    const row = { path, used: s.used, std: !!s.std, odd: !!s.odd };
    if (chain === 'btc') {
      const pk = secpPubkey(master, path);
      row.fmt = s.fmt;
      row.addresses = Object.keys(BTC_FORMATS).map(f => ({ format: f, address: btcAddressFromPubkey(pk, f) }));
    } else if (chain === 'sol') row.address = addressAtPath(seed, 'sol', path);
    else row.address = secpAddress(secpPubkey(master, path), chain);
    out.push(row);
  }
  return out;
}

/* ════════════════════════════════════════════════════════════════
   SEED DIAGNOSIS — which word is wrong, and what it might have been
   ════════════════════════════════════════════════════════════════ */

/* Edit distance counting an exchange of two neighbouring letters as one
   mistake (the commonest slip when copying by hand). */
function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/* Up to three list words close to a word that is not in the list: first
   those sharing its first four letters (BIP-39 words are unique by
   them), then those within two mistakes. */
export function suggestWords(word, max = 3) {
  const w = String(word || '').toLowerCase();
  if (!w) return [];
  const scored = [];
  for (const cand of wordlist) {
    const prefix = w.length >= 4 && cand.slice(0, 4) === w.slice(0, 4);
    const dist = editDistance(w, cand);
    if (prefix || dist <= 2) scored.push({ cand, score: prefix ? Math.min(dist, 1) - 1 : dist });
  }
  scored.sort((x, y) => x.score - y.score || x.cand.localeCompare(y.cand));
  return scored.slice(0, max).map(x => x.cand);
}

/* What is wrong with a typed seed, in terms a person can act on:
   the number of words, each word not in the list (with its position and
   suggestions), or — when every word exists — the checksum. */
export function diagnoseMnemonic(text) {
  const norm = normalizeWords(text);
  const words = norm ? norm.split(' ') : [];
  const unknown = [];
  words.forEach((w, i) => { if (!wordlist.includes(w)) unknown.push({ position: i + 1, word: w, suggestions: suggestWords(w) }); });
  const countOk = WORD_OPTIONS.includes(words.length);
  const checksumOk = countOk && unknown.length === 0 && validateMnemonic(norm, wordlist);
  return { words, count: words.length, countOk, unknown, checksumOk, valid: checksumOk };
}

/* ════════════════════════════════════════════════════════════════
   WATCH-ONLY CHECK — addresses from a public key alone
   ════════════════════════════════════════════════════════════════ */

/* Reads a single-signature account key as shared by wallets: xpub,
   ypub (SegWit compatible) or zpub (Native SegWit). The result is the
   key re-labelled as a plain xpub, with the format its label suggests.
   An xpub does not say which format it was used with (Legacy and
   Taproot both use it): the format is then left for the person to pick. */
export function readPublicKey(input) {
  const s = String(input || '').replace(/\s+/g, '');
  let raw;
  try { raw = base58check.decode(s); } catch (_) { throw new KeyError('INVALID'); }
  if (raw.length !== 78) throw new KeyError('INVALID');
  const version = new DataView(raw.buffer, raw.byteOffset).getUint32(0, false);
  const kind = VERSIONS[version];
  if (kind === 'private') throw new KeyError('PRIVATE');
  if (kind === 'testnet') throw new KeyError('TESTNET');
  if (kind === 'Ypub' || kind === 'Zpub') throw new KeyError('MULTISIG_KEY');
  if (kind !== 'xpub' && kind !== 'ypub' && kind !== 'zpub') throw new KeyError('INVALID');
  if (raw[45] !== 0x02 && raw[45] !== 0x03) throw new KeyError('INVALID');
  const out = raw.slice();
  new DataView(out.buffer).setUint32(0, XPUB, false);
  const xpub = base58check.encode(out);
  let node;
  try { node = HDKey.fromExtendedKey(xpub); } catch (_) { throw new KeyError('INVALID'); }
  const format = kind === 'ypub' ? 'p2sh' : kind === 'zpub' ? 'native' : null;
  return { xpub, kind, format, depth: node.depth };
}

/* Addresses <key>/change/i. 'as' is a Bitcoin format, 'eth' or 'trx'. */
export function addressesFromXpub(xpub, as, change = 0, from = 0, count = 10) {
  const node = HDKey.fromExtendedKey(xpub).deriveChild(change);
  const out = [];
  for (let i = from; i < from + count; i++) {
    const pk = node.deriveChild(i).publicKey;
    let address;
    if (as === 'eth') address = toChecksumAddress(toHex(evmAddressBytes(pk)));
    else if (as === 'trx') address = b58check(0x41, evmAddressBytes(pk));
    else address = btcAddressFromPubkey(pk, BTC_FORMATS[as] ? as : 'native');
    out.push({ index: i, path: `…/${change}/${i}`, address });
  }
  return out;
}

/* Watch-only descriptor for a key read above (no key origin: the xpub
   alone does not say which seed or path it came from). */
export function xpubDescriptor(xpub, format) {
  const key = `${xpub}/0/*`;
  const body = { native: `wpkh(${key})`, taproot: `tr(${key})`, p2sh: `sh(wpkh(${key}))`, legacy: `pkh(${key})` }[format];
  if (!body) throw new Error('invalid format');
  return withChecksum(body);
}

/* ════════════════════════════════════════════════════════════════
   MULTISIG — BIP-48 (P2WSH), BIP-67 key sorting, sortedmulti
   ════════════════════════════════════════════════════════════════ */
export const MULTISIG_PATH = "m/48'/0'/0'/2'";
const MULTISIG_ORIGIN = '48h/0h/0h/2h';

export function deriveMultisigXpub(seed) {
  const master = HDKey.fromMasterSeed(new Uint8Array(seed));
  const acct = master.derive(MULTISIG_PATH);
  return { xpub: acct.publicExtendedKey, fingerprint: fingerprintHex(master), path: MULTISIG_PATH };
}

/* Extended-key version bytes (BIP-32, SLIP-132). */
const XPUB = 0x0488b21e;
const VERSIONS = {
  0x0488b21e: 'xpub', 0x02aa7ed3: 'Zpub',
  0x0488ade4: 'private', 0x049d7878: 'private', 0x04b2430c: 'private', 0x0295b005: 'private', 0x02aa7a99: 'private',
  0x049d7cb2: 'ypub', 0x04b24746: 'zpub', 0x0295b43f: 'Ypub',
  0x043587cf: 'testnet', 0x04358394: 'testnet', 0x044a5262: 'testnet', 0x045f1cf6: 'testnet',
  0x024289ef: 'testnet', 0x02575483: 'testnet', 0x044a4e28: 'testnet', 0x045f18bc: 'testnet',
  0x024285b5: 'testnet', 0x02575048: 'testnet',
};

export class KeyError extends Error {
  constructor(code, index) { super(code); this.code = code; this.index = index; }
}

/* Accepts what a co-signer can legitimately share — an xpub, or the
   Zpub that Electrum shows for native-SegWit multisig — and returns it
   as a plain xpub. Refuses private keys outright, testnet keys, and
   keys labelled for a different script type. */
export function normalizeXpub(input, index = 0) {
  const s = String(input || '').replace(/\s+/g, '');
  let raw;
  try { raw = base58check.decode(s); } catch (_) { throw new KeyError('INVALID', index); }
  if (raw.length !== 78) throw new KeyError('INVALID', index);
  const version = new DataView(raw.buffer, raw.byteOffset).getUint32(0, false);
  const kind = VERSIONS[version];
  if (kind === 'private') throw new KeyError('PRIVATE', index);
  if (kind === 'testnet') throw new KeyError('TESTNET', index);
  if (kind === 'ypub' || kind === 'zpub' || kind === 'Ypub') throw new KeyError('SCRIPT_TYPE', index);
  if (kind !== 'xpub' && kind !== 'Zpub') throw new KeyError('INVALID', index);
  if (raw[45] !== 0x02 && raw[45] !== 0x03) throw new KeyError('INVALID', index);   // must hold a public key
  const out = raw.slice();
  new DataView(out.buffer).setUint32(0, XPUB, false);
  const xpub = base58check.encode(out);
  try { HDKey.fromExtendedKey(xpub); } catch (_) { throw new KeyError('INVALID', index); }
  return xpub;
}

export function bip67Sort(pubkeys) {
  return [...pubkeys].sort((a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
  });
}

/* keys: strings (xpubs) or { xpub, fingerprint } objects. When the
   fingerprint is known it is written into the descriptor as key origin,
   which lets Sparrow and hardware wallets recognise their own key. */
export function multisigAddress(keys, threshold, index = 0) {
  const list = keys.map((k, i) => {
    const o = typeof k === 'string' ? { xpub: k } : k;
    return { xpub: normalizeXpub(o.xpub, i), fingerprint: o.fingerprint || null };
  });
  const n = list.length, m = threshold;
  if (n < 2) throw new KeyError('TOO_FEW');
  if (n > 15) throw new KeyError('TOO_MANY');
  if (!Number.isInteger(m) || m < 1 || m > n) throw new KeyError('THRESHOLD');
  // Duplicates are found by what determines the derived keys — chain code
  // and public key — not by the text: two xpubs that differ only in their
  // metadata (depth, parent fingerprint, child number, version) would give
  // the same signer twice, and one person could then spend a "2 of 3" alone.
  const seen = new Set();
  list.forEach((k, i) => {
    const id = toHex(base58check.decode(k.xpub).slice(13));
    if (seen.has(id)) throw new KeyError('DUPLICATE', i);
    seen.add(id);
  });

  const pubkeys = list.map(k => HDKey.fromExtendedKey(k.xpub).deriveChild(0).deriveChild(index).publicKey);
  const sorted = bip67Sort(pubkeys);
  // witness script: OP_m <pubkey>… OP_n OP_CHECKMULTISIG
  const script = new Uint8Array(3 + n * 34);
  let off = 0;
  script[off++] = 0x50 + m;
  for (const pk of sorted) { script[off++] = 0x21; script.set(pk, off); off += 33; }
  script[off++] = 0x50 + n;
  script[off++] = 0xae;
  const address = bech32.encode('bc', [0x00, ...bech32.toWords(sha256(script))]);
  const parts = list.map(k => (k.fingerprint ? `[${k.fingerprint}/${MULTISIG_ORIGIN}]` : '') + `${k.xpub}/0/*`);
  const descriptor = withChecksum(`wsh(sortedmulti(${m},${parts.join(',')}))`);
  return { address, descriptor, n, m };
}

/* ════════════════════════════════════════════════════════════════
   SLIP-39
   ════════════════════════════════════════════════════════════════ */
/* SLIP-39 accepts only printable ASCII in the passphrase. A different
   character would be silently mangled by the library on recovery. */
export const isSlip39Passphrase = (p) => /^[\x20-\x7e]*$/.test(p);

export function slip39Create(secret, m, n, passphrase) {
  if (!isSlip39Passphrase(passphrase)) throw new Error('SLIP39_PASSPHRASE');
  const arr = Array.from(secret);
  // Iteration exponent 1 (20,000 PBKDF2 rounds protecting the passphrase),
  // the default of Trezor's reference implementation; the extendable-backup
  // flag stays at the library default, 1, as the current SLIP-39 revision
  // recommends for new shares.
  const obj = slip39lib.fromArray(arr, { passphrase, threshold: 1, groups: [[m, n]], iterationExponent: 1, extendableBackupFlag: 1 });
  const shares = obj.fromPath('r/0').mnemonics;
  // Immediate check: every threshold-sized subset must give back the secret.
  // Better to stop now than to find out in ten years.
  const same = (a) => a.length === arr.length && Array.from(a).every((b, i) => b === arr[i]);
  const subsets = (arr2, k, start = 0, acc = [], out = []) => {
    if (acc.length === k) { out.push(acc.slice()); return out; }
    for (let i = start; i < arr2.length; i++) { acc.push(arr2[i]); subsets(arr2, k, i + 1, acc, out); acc.pop(); }
    return out;
  };
  for (const sub of subsets(shares, m)) {
    if (!same(slip39lib.recoverSecret(sub, passphrase))) throw new Error('internal check failed: the sheets do not reassemble the secret');
  }
  return shares;
}

export function slip39Recover(shares, passphrase) {
  if (!isSlip39Passphrase(passphrase)) throw new Error('SLIP39_PASSPHRASE');
  return Uint8Array.from(slip39lib.recoverSecret(shares, passphrase));
}

/* ════════════════════════════════════════════════════════════════
   POWERS-OF-2 GRID
   Every BIP-39 word has a number from 1 to 2048, written as a sum of
   the marked columns. Numbering starts at 1 so that no row is ever
   empty ("abandon" would otherwise have no marks at all).
   ════════════════════════════════════════════════════════════════ */
export const METAL_COLS = [2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1];

export function metalRows(mnemonic) {
  return mnemonic.split(' ').map((w, i) => {
    const n = wordlist.indexOf(w) + 1;
    if (n < 1) throw new Error(`Word not found in the dictionary: ${w}`);
    return { pos: i + 1, word: w, n, marks: METAL_COLS.map(c => (n & c) !== 0) };
  });
}
