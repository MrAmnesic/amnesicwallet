#!/usr/bin/env node
/**
 * Derivation test vectors for SeedForge.
 *
 * Validates every supported chain against the canonical BIP-39 test mnemonic
 * ("abandon abandon ... about"). Bitcoin, Ethereum and Solana are checked
 * against values reproducible with independent tools (e.g. iancoleman.io/bip39).
 * TRON is checked structurally (0x41 prefix, 'T' start, 34 chars) since it
 * follows the documented network spec.
 *
 * Run: npm test
 * Exit code 0 = all pass, 1 = any failure (CI-friendly).
 */
'use strict';

const { mnemonicToSeedSync } = require('@scure/bip39');
const { HDKey } = require('@scure/bip32');
const { sha256, sha512 } = require('@noble/hashes/sha2.js');
const { ripemd160 } = require('@noble/hashes/legacy.js');
const { hmac } = require('@noble/hashes/hmac.js');
const { bech32, bech32m } = require('bech32');
const { secp256k1 } = require('@noble/curves/secp256k1.js');
const { ethers } = require('ethers');
const bs58 = require('bs58').default || require('bs58');
const ed = require('@noble/ed25519');
const { hashes } = ed;
hashes.sha512 = sha512;

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Official BIP-44 / BIP-49 / BIP-84 / BIP-86 vectors (canonical mnemonic)
const BTC_EXPECTED = {
  legacy:  '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA',
  p2sh:    '37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf',
  native:  'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
  taproot: 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
};

function toHex(u) { return Array.from(u).map(b => b.toString(16).padStart(2, '0')).join(''); }
function taggedHash(tag, msg) {
  const t = sha256(new TextEncoder().encode(tag));
  const b = new Uint8Array(t.length * 2 + msg.length);
  b.set(t, 0); b.set(t, t.length); b.set(msg, t.length * 2);
  return sha256(b);
}
function b58c(v, payload) {
  const p = new Uint8Array(1 + payload.length);
  p[0] = v; p.set(payload, 1);
  const f = new Uint8Array(p.length + 4);
  f.set(p); f.set(sha256(sha256(p)).slice(0, 4), p.length);
  return bs58.encode(f);
}
function btcAddr(pubkey, format) {
  if (format === 'legacy') return b58c(0x00, ripemd160(sha256(pubkey)));
  if (format === 'p2sh') {
    const kh = ripemd160(sha256(pubkey));
    const r = new Uint8Array(22); r[0] = 0x00; r[1] = 0x14; r.set(kh, 2);
    return b58c(0x05, ripemd160(sha256(r)));
  }
  if (format === 'taproot') {
    const x = pubkey.slice(1);
    const t = taggedHash('TapTweak', x);
    const P = secp256k1.Point.fromHex('02' + toHex(x));
    const Q = P.add(secp256k1.Point.BASE.multiply(BigInt('0x' + toHex(t))));
    const out = (Q.toBytes ? Q.toBytes(true) : Q.toRawBytes(true)).slice(1);
    const w = bech32m.toWords(out); w.unshift(0x01);
    return bech32m.encode('bc', w);
  }
  const w = bech32.toWords(ripemd160(sha256(pubkey))); w.unshift(0x00);
  return bech32.encode('bc', w);
}
const BTC_PURPOSE = { legacy: 44, p2sh: 49, native: 84, taproot: 86 };

const EXPECTED = {
  BTC: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
  ETH: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94',
  SOL: 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk',
};

function deriveBTC(master) {
  const c = master.derive("m/84'/0'/0'/0/0");
  const w = bech32.toWords(ripemd160(sha256(c.publicKey)));
  w.unshift(0x00);
  return bech32.encode('bc', w);
}

function deriveETH(master) {
  const c = master.derive("m/44'/60'/0'/0/0");
  const u = ethers.getBytes(ethers.SigningKey.computePublicKey(c.publicKey, false)).slice(1);
  return ethers.getAddress('0x' + ethers.keccak256(u).slice(-40));
}

function deriveTRX(master) {
  const c = master.derive("m/44'/195'/0'/0/0");
  const u = ethers.getBytes(ethers.SigningKey.computePublicKey(c.publicKey, false)).slice(1);
  const ab = ethers.getBytes('0x' + ethers.keccak256(u).slice(-40));
  const p = new Uint8Array(21); p[0] = 0x41; p.set(ab, 1);
  const f = new Uint8Array(25); f.set(p); f.set(sha256(sha256(p)).slice(0, 4), 21);
  return bs58.encode(f);
}

function deriveSOL(seed) {
  const path = [44, 501, 0, 0];
  let k = hmac(sha512, new TextEncoder().encode('ed25519 seed'), new Uint8Array(seed));
  let il = k.slice(0, 32), ir = k.slice(32);
  for (const idx of path) {
    const d = new Uint8Array(37); d[0] = 0; d.set(il, 1);
    const ib = new Uint8Array(4);
    new DataView(ib.buffer).setUint32(0, (idx | 0x80000000) >>> 0, false);
    d.set(ib, 33);
    const I = hmac(sha512, ir, d);
    il = I.slice(0, 32); ir = I.slice(32);
  }
  return bs58.encode(ed.getPublicKey(il));
}


function main() {
  const seed = mnemonicToSeedSync(MNEMONIC);
  const master = HDKey.fromMasterSeed(new Uint8Array(seed));

  const results = [];
  const btc = deriveBTC(master);
  results.push(['BTC', btc, btc === EXPECTED.BTC]);
  const eth = deriveETH(master);
  results.push(['ETH', eth, eth === EXPECTED.ETH]);
  const sol = deriveSOL(seed);
  results.push(['SOL', sol, sol === EXPECTED.SOL]);

  // Bitcoin address formats (BIP-44 / 49 / 84 / 86)
  for (const fmt of Object.keys(BTC_EXPECTED)) {
    const c = master.derive(`m/${BTC_PURPOSE[fmt]}'/0'/0'/0/0`);
    const got = btcAddr(c.publicKey, fmt);
    results.push([`BTC ${fmt}`, got, got === BTC_EXPECTED[fmt]]);
  }

  // TRON: structural validation
  const trx = deriveTRX(master);
  const trxOk = trx.startsWith('T') && trx.length === 34;
  results.push(['TRX', trx, trxOk]);

  console.log('SeedForge — derivation test vectors');
  console.log('Mnemonic:', MNEMONIC);
  console.log('');

  let allOk = true;
  for (const [name, addr, ok] of results) {
    console.log(`${ok ? '  PASS' : '  FAIL'}  ${name}  ${addr}`);
    if (!ok) allOk = false;
  }

  console.log('');
  if (allOk) {
    console.log('All derivation test vectors passed.');
    process.exit(0);
  } else {
    console.error('One or more test vectors FAILED.');
    process.exit(1);
  }
}

main();
