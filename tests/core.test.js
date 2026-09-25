/*
 * AmnesicWallet — test suite for src/core.js
 *
 * These tests import the real application core, bundled with the same
 * esbuild options (and the same slip39 shims) used for the published file.
 * Every expected value comes from outside this project:
 *
 *   bip39.json          official BIP-39 vectors (trezor/python-mnemonic)
 *   slip10-ed25519.json official SLIP-10 ed25519 vectors
 *   slip39.json         official SLIP-39 vectors (trezor/python-shamir-mnemonic)
 *   addresses.json      addresses, xpubs and vaults computed with bip_utils and
 *                       embit (Python), independently of this code
 *   shamir-compat.json  parts made by version 1.0.1, which must keep working
 *
 * plus the published examples of BIP-84/86/49/44, EIP-55 and BIP-380.
 * Run with `npm test`.
 */
import {
  WORD_OPTIONS, ENT_BYTES, toHex, normalizeWords, statisticalChecks, combineEntropy,
  createMouseCollector, createTypingCollector, diceRollsNeeded, diceBytesFrom,
  GF, shamirSplit, shamirCombine, verificationCode, classicSplit,
  btcAddressFromPubkey, deriveBTC, deriveBTCMany, btcAccountInfo, descriptorChecksum,
  toChecksumAddress, deriveAll, slip10Ed25519, deriveMultisigXpub, normalizeXpub,
  multisigAddress, isSlip39Passphrase, slip39Create, slip39Recover, metalRows,
  entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic, wordlist, HDKey,
} from '../src/core.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base58, createBase58check } from '@scure/base';

import BIP39 from './vectors/bip39.json';
import SLIP10 from './vectors/slip10-ed25519.json';
import SLIP39 from './vectors/slip39.json';
import ADDR from './vectors/addresses.json';
import COMPAT from './vectors/shamir-compat.json';

/* ── tiny harness ─────────────────────────────────────────────── */
let passed = 0, failed = 0, section = '', failedAtStart = 0;
const failures = [];
function group(name) { section = name; failedAtStart = failed; console.log('\n' + name); }
function check(cond, what) {
  if (cond) { passed++; return; }
  failed++;
  failures.push(`${section} › ${what}`);
  if (failures.length <= 40) console.log('  ✗ ' + what);
}
function eq(actual, expected, what) {
  check(actual === expected, `${what}\n      expected ${expected}\n      got      ${actual}`);
}
function throws(fn, what, test) {
  try { fn(); } catch (e) { check(!test || test(e), `${what} (wrong error: ${e && (e.code || e.message)})`); return; }
  check(false, `${what} (no error raised)`);
}
function done(label) { console.log(failed === failedAtStart ? `  ✓ ${label}` : `  ✗ ${label}: ${failed - failedAtStart} failed`); }

const hex = (h) => Uint8Array.from(h.match(/../g) || [], (b) => parseInt(b, 16));
const b58c = createBase58check(sha256);
const combos = (arr, k, start = 0, acc = [], out = []) => {
  if (acc.length === k) { out.push(acc.slice()); return out; }
  for (let i = start; i < arr.length; i++) { acc.push(arr[i]); combos(arr, k, i + 1, acc, out); acc.pop(); }
  return out;
};
/* Deterministic byte stream, for tests that must not depend on luck. */
function seededRng(seed) {
  let state = sha256(new TextEncoder().encode('test-rng/' + seed));
  let pool = [];
  return (buf) => {
    for (let i = 0; i < buf.length; i++) {
      if (!pool.length) { state = sha256(state); pool = Array.from(state); }
      buf[i] = pool.shift();
    }
    return buf;
  };
}

/* ════════════════════════════════════════════════════════════════ */
group('BIP-39 — official vectors (passphrase "TREZOR")');
for (const [entHex, mnemonic, seedHex, xprv] of BIP39) {
  eq(entropyToMnemonic(hex(entHex), wordlist), mnemonic, `entropy → words ${entHex}`);
  eq(toHex(mnemonicToEntropy(mnemonic, wordlist)), entHex, `words → entropy ${entHex}`);
  const seed = mnemonicToSeedSync(mnemonic, 'TREZOR');
  eq(toHex(seed), seedHex, `seed ${entHex}`);
  eq(HDKey.fromMasterSeed(seed).privateExtendedKey, xprv, `root xprv ${entHex}`);
}
check(!validateMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon', wordlist),
  'a wrong checksum word is rejected');
eq(normalizeWords('  Abandon\n ABOUT\t zoo '), 'abandon about zoo', 'typed words are normalised');
check(WORD_OPTIONS.every((w) => ENT_BYTES[w] * 8 === (w * 11 * 32) / 33), 'word counts match entropy lengths');
done(`${BIP39.length} vectors`);

/* ════════════════════════════════════════════════════════════════ */
group('Bitcoin — published examples of BIP-44/49/84/86');
{
  const seed = mnemonicToSeedSync('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', '');
  const master = HDKey.fromMasterSeed(seed);
  eq(deriveBTC(master, 'native').address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', 'BIP-84 first address');
  eq(deriveBTC(master, 'taproot').address, 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', 'BIP-86 first address');
  eq(deriveBTC(master, 'p2sh').address, '37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf', 'BIP-49 first address');
  eq(deriveBTC(master, 'legacy').address, '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA', 'BIP-44 first address');
  eq(deriveBTC(master, 'native').path, "m/84'/0'/0'/0/0", 'BIP-84 path');
  eq(deriveBTC(master, 'unknown-format').btcFormat, 'native', 'an unknown format falls back to Native SegWit');
  done('4 standards');
}

/* ════════════════════════════════════════════════════════════════ */
group('All networks — values computed independently with bip_utils / embit');
{
  let n = 0;
  for (const v of ADDR.seeds) {
    const seed = mnemonicToSeedSync(v.mnemonic, v.passphrase);
    eq(toHex(seed), v.seed, `seed of "${v.mnemonic.slice(0, 20)}…" / "${v.passphrase}"`);
    const master = HDKey.fromMasterSeed(seed);
    for (const fmt of ['legacy', 'p2sh', 'native', 'taproot']) {
      const many = deriveBTCMany(master, fmt, 0, v.btc[fmt].length);
      v.btc[fmt].forEach((a, i) => { eq(many[i].address, a, `BTC ${fmt} #${i}`); n++; });
      const acct = btcAccountInfo(seed, fmt);
      eq(acct.xpub, v.xpub[fmt], `account xpub ${fmt}`);
      eq(acct.fingerprint, v.fingerprint, 'master fingerprint');
      const [body, sum] = acct.descriptor.split('#');
      eq(descriptorChecksum(body), sum, `descriptor checksum ${fmt}`);
      check(body.includes(`[${v.fingerprint}/`) && body.includes(v.xpub[fmt]), `descriptor carries origin and xpub (${fmt})`);
    }
    const all = deriveAll(seed, ['btc', 'eth', 'trx', 'sol'], 'native');
    eq(all.btc.address, v.btc.native[0], 'deriveAll BTC');
    eq(all.eth.address, v.eth, 'Ethereum (EIP-55)');
    eq(all.trx.address, v.trx, 'TRON');
    eq(all.sol.address, v.sol, 'Solana');
    const ms = deriveMultisigXpub(seed);
    eq(ms.xpub, v.multisigXpub, 'BIP-48 multisig xpub');
    eq(ms.fingerprint, v.fingerprint, 'BIP-48 fingerprint');
    eq(normalizeXpub(v.multisigZpub), v.multisigXpub, 'Zpub accepted and read as the same key');
    n += 6;
  }
  done(`${ADDR.seeds.length} seeds, ${n} addresses and keys`);
}

/* ════════════════════════════════════════════════════════════════ */
group('Ethereum — EIP-55 examples');
for (const a of ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
  '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb']) {
  eq(toChecksumAddress(a.toLowerCase()), a, 'checksum of ' + a);
}
throws(() => toChecksumAddress('0x1234'), 'a short address is refused');
done('4 examples');

/* ════════════════════════════════════════════════════════════════ */
group('Solana — SLIP-10 ed25519 official vectors');
for (const v of SLIP10) {
  for (const c of v.chains) {
    const r = slip10Ed25519(hex(v.seed), c.path);
    eq(toHex(r.key), c.private, `private key m/${c.path.join("'/")}${c.path.length ? "'" : ''}`);
    eq(toHex(r.chainCode), c.chainCode, `chain code m/${c.path.join("'/")}${c.path.length ? "'" : ''}`);
  }
}
throws(() => slip10Ed25519(new Uint8Array(32), [0x80000000]), 'an index already hardened is refused');
done(`${SLIP10.length} seeds`);

/* ════════════════════════════════════════════════════════════════ */
group('Descriptors — BIP-380 checksum');
eq(descriptorChecksum('raw(deadbeef)'), '89f8spxm', 'BIP-380 example');
throws(() => descriptorChecksum('raw(dead€)'), 'a character outside the descriptor alphabet is refused');
done('checksum');

/* ════════════════════════════════════════════════════════════════ */
group('Multisig — vaults computed with embit, and every refusal');
{
  for (const v of ADDR.vaults) {
    eq(multisigAddress(v.xpubs, v.m, 0).address, v.address0, `${v.m} of ${v.xpubs.length}, address 0`);
    eq(multisigAddress(v.xpubs, v.m, 5).address, v.address5, `${v.m} of ${v.xpubs.length}, address 5`);
    const reversed = multisigAddress([...v.xpubs].reverse(), v.m, 0);
    eq(reversed.address, v.address0, 'key order does not matter (BIP-67)');
    const [body, sum] = reversed.descriptor.split('#');
    eq(descriptorChecksum(body), sum, 'vault descriptor checksum');
  }
  const seeds = ADDR.seeds.filter((s) => s.passphrase === '').map((s) => mnemonicToSeedSync(s.mnemonic, ''));
  const keys = seeds.slice(0, 3).map(deriveMultisigXpub);
  const withOrigin = multisigAddress(keys, 2);
  check(keys.every((k) => withOrigin.descriptor.includes(`[${k.fingerprint}/48h/0h/0h/2h]${k.xpub}/0/*`)), 'descriptor carries each key origin');
  eq(withOrigin.address, multisigAddress(keys.map((k) => k.xpub), 2).address, 'key origins do not change the address');

  const xpub = keys[0].xpub;
  const raw = b58c.decode(xpub);
  const reversion = (version) => { const r = raw.slice(); new DataView(r.buffer).setUint32(0, version, false); return b58c.encode(r); };
  const master = HDKey.fromMasterSeed(seeds[0]);
  const code = (c) => (e) => e && e.code === c;
  throws(() => multisigAddress([master.derive("m/48'/0'/0'/2'").privateExtendedKey, keys[1].xpub], 1), 'an xprv is refused', code('PRIVATE'));
  throws(() => normalizeXpub(reversion(0x043587cf)), 'a tpub is refused', code('TESTNET'));
  throws(() => normalizeXpub(reversion(0x04b24746)), 'a zpub is refused', code('SCRIPT_TYPE'));
  throws(() => normalizeXpub(reversion(0x049d7cb2)), 'a ypub is refused', code('SCRIPT_TYPE'));
  throws(() => normalizeXpub(xpub.slice(0, -1) + (xpub.endsWith('a') ? 'b' : 'a')), 'a mistyped xpub is refused', code('INVALID'));
  throws(() => normalizeXpub('hello'), 'garbage is refused', code('INVALID'));
  throws(() => multisigAddress([xpub, xpub], 1), 'the same key twice is refused', code('DUPLICATE'));
  throws(() => multisigAddress([xpub, reversion(0x02aa7ed3)], 1), 'the same key as xpub and Zpub is refused', code('DUPLICATE'));
  const disguise = (offset, mask) => { const r = raw.slice(); r[offset] ^= mask; return b58c.encode(r); };
  throws(() => multisigAddress([xpub, disguise(12, 1), keys[1].xpub], 2), 'the same key with another child number is refused', code('DUPLICATE'));
  throws(() => multisigAddress([xpub, disguise(5, 0xff), keys[1].xpub], 2), 'the same key with another parent fingerprint is refused', code('DUPLICATE'));
  throws(() => multisigAddress([xpub, disguise(4, 1), keys[1].xpub], 2), 'the same key with another depth is refused', code('DUPLICATE'));
  throws(() => multisigAddress([xpub], 1), 'a single key is refused', code('TOO_FEW'));
  throws(() => multisigAddress(keys.map((k) => k.xpub), 4), 'a threshold above the keys is refused', code('THRESHOLD'));
  throws(() => multisigAddress(keys.map((k) => k.xpub), 0), 'a zero threshold is refused', code('THRESHOLD'));
  const sixteen = Array.from({ length: 16 }, (_, i) => master.derive(`m/48'/0'/${i}'/2'`).publicExtendedKey);
  throws(() => multisigAddress(sixteen, 2), 'more than 15 keys are refused', code('TOO_MANY'));
  eq(multisigAddress(sixteen.slice(0, 15), 15).n, 15, '15 keys are accepted');
  done(`${ADDR.vaults.length} vaults, origins, 16 refusals`);
}

/* ════════════════════════════════════════════════════════════════ */
group('SLIP-39 — official vectors (passphrase "TREZOR")');
{
  let valid = 0, invalid = 0;
  for (const [desc, mnemonics, secretHex, xprv] of SLIP39) {
    if (secretHex) {
      const secret = slip39Recover(mnemonics, 'TREZOR');
      eq(toHex(secret), secretHex, desc);
      eq(HDKey.fromMasterSeed(secret).privateExtendedKey, xprv, desc + ' (xprv)');
      valid++;
    } else {
      throws(() => slip39Recover(mnemonics, 'TREZOR'), desc);
      invalid++;
    }
  }
  done(`${valid} valid, ${invalid} invalid — all as expected`);
}

group('SLIP-39 — creating sheets');
{
  check(isSlip39Passphrase('Correct Horse 42!~'), 'printable ASCII passphrase accepted');
  check(!isSlip39Passphrase('pässwörd') && !isSlip39Passphrase('tab\there') && !isSlip39Passphrase('🔑'), 'other characters refused');
  throws(() => slip39Create(new Uint8Array(16), 2, 3, 'città'), 'creation refuses a non-ASCII passphrase', (e) => e.message === 'SLIP39_PASSPHRASE');
  throws(() => slip39Recover([], 'città'), 'recovery refuses a non-ASCII passphrase', (e) => e.message === 'SLIP39_PASSPHRASE');
  const rng = seededRng('slip39');
  let slowest = 0;
  for (const [m, n] of [[2, 3], [3, 5], [4, 7], [2, 7], [6, 7]]) {
    for (const pass of ['', 'TREZOR']) {
      const secret = rng(new Uint8Array(16));
      const t0 = Date.now();
      const shares = slip39Create(secret, m, n, pass);
      slowest = Math.max(slowest, Date.now() - t0);
      eq(shares.length, n, `${m} of ${n}: ${n} sheets`);
      check(shares.every((s) => s.split(' ').length === 20), `${m} of ${n}: 20 words each`);
      check(new Set(shares.map((s) => s.split(' ').slice(0, 3).join(' '))).size === 1, `${m} of ${n}: same first words on every sheet`);
      const pick = shares.slice(n - m);
      eq(toHex(slip39Recover(pick, pass)), toHex(secret), `${m} of ${n}: the last ${m} sheets recover`);
      if (pass) check(toHex(slip39Recover(pick, 'wrong')) !== toHex(secret), `${m} of ${n}: a wrong passphrase gives another wallet`);
      throws(() => slip39Recover(shares.slice(0, m - 1), pass), `${m} of ${n}: ${m - 1} sheets are not enough`);
    }
  }
  done(`round trips (slowest creation, with its self-check: ${slowest} ms)`);
}

/* ════════════════════════════════════════════════════════════════ */
group('Shamir (AmnesicWallet format) — the field GF(2^8)');
{
  eq(GF.mul(0x53, 0xca), 0x01, '{53}·{CA} = {01}, the FIPS-197 example');
  eq(GF.mul(0x57, 0x83), 0xc1, '{57}·{83} = {C1}, the FIPS-197 example');
  let inverses = 0, commut = 0;
  for (let a = 1; a < 256; a++) {
    if (GF.mul(a, GF.div(1, a)) === 1) inverses++;
    for (let b = 1; b < 256; b += 17) if (GF.mul(a, b) === GF.mul(b, a)) commut++;
  }
  eq(inverses, 255, 'every non-zero element has an inverse');
  eq(commut, 255 * 15, 'multiplication is commutative');
  throws(() => GF.div(1, 0), 'division by zero is refused');
  done('field arithmetic');
}

group('Shamir — splitting and reassembling');
{
  const rng = seededRng('shamir');
  let checks = 0;
  for (const len of [16, 20, 24, 28, 32]) {
    for (const [m, n] of [[2, 3], [3, 5], [2, 2], [4, 7], [7, 7]]) {
      const secret = rng(new Uint8Array(len));
      const ys = shamirSplit(secret, n, m, rng);
      const parts = ys.map((y, i) => ({ x: i + 1, y }));
      for (const sub of combos(parts, m)) { eq(toHex(shamirCombine(sub)), toHex(secret), `${m} of ${n}, ${len} bytes`); checks++; }
      if (m < n) eq(toHex(shamirCombine(parts)), toHex(secret), `${m} of ${n}: all parts together`);
      for (const sub of combos(parts, m - 1)) {
        check(toHex(shamirCombine(sub)) !== toHex(secret), `${m} of ${n}: ${m - 1} parts do not give the secret`);
        checks++;
      }
      // each part is a valid BIP-39 phrase of the same length
      check(ys.every((y) => validateMnemonic(entropyToMnemonic(y, wordlist), wordlist)), 'parts are valid word lists');
    }
  }
  throws(() => shamirSplit(new Uint8Array(16), 3, 1), 'threshold 1 is refused');
  throws(() => shamirSplit(new Uint8Array(16), 2, 3), 'threshold above parts is refused');
  throws(() => shamirSplit(new Uint8Array(16), 17, 2), 'more than 16 parts is refused');
  throws(() => shamirSplit(new Uint8Array(0), 3, 2), 'an empty secret is refused');
  const p = shamirSplit(new Uint8Array(16).fill(7), 3, 2, rng).map((y, i) => ({ x: i + 1, y }));
  throws(() => shamirCombine([p[0], { x: 1, y: p[1].y }]), 'the same part number twice is refused');
  throws(() => shamirCombine([p[0], { x: 0, y: p[1].y }]), 'part number 0 is refused');
  throws(() => shamirCombine([p[0], { x: 2, y: p[1].y.slice(0, 12) }]), 'parts of different length are refused');
  done(`${checks} combinations`);
}

group('Shamir — below the threshold every secret stays equally likely');
{
  // With m-1 parts fixed, each candidate secret byte corresponds to exactly one
  // polynomial: count, over all 256 values of the free coefficient, which
  // secrets are consistent with two parts of a 3-of-5 split. Perfect secrecy
  // means every one of the 256 secrets appears, once.
  const rng = seededRng('secrecy');
  const secret = rng(new Uint8Array(1));
  const ys = shamirSplit(secret, 5, 3, rng);
  const known = [{ x: 2, y: ys[1] }, { x: 4, y: ys[3] }];
  const seen = new Set();
  for (let guess = 0; guess < 256; guess++) {
    // the guessed third point at x = 5 fixes the polynomial; read its value at 0
    const s = shamirCombine([...known, { x: 5, y: Uint8Array.of(guess) }]);
    seen.add(s[0]);
  }
  eq(seen.size, 256, 'two parts leave all 256 values of each byte possible');
  done('perfect secrecy');
}

group('Shamir — parts made by earlier versions still reassemble');
{
  let n = 0;
  for (const c of COMPAT.cases) {
    const parts = c.shares.map((s) => ({ x: s.x, y: hex(s.y) }));
    for (const sub of combos(parts, COMPAT.threshold)) { eq(toHex(shamirCombine(sub)), c.secret, `version 1.0.1 parts, ${c.secret.length / 2} bytes`); n++; }
    eq(verificationCode(hex(c.secret)), c.code, 'verification code unchanged');
  }
  eq(verificationCode(new Uint8Array(16)), toHex(sha256(new Uint8Array(16)).slice(0, 2)).toUpperCase(), 'code = first 2 bytes of SHA-256');
  done(`${COMPAT.cases.length} backups, ${n} combinations`);
}

group('Sequential split');
{
  const words = 'a b c d e f g h i j k l m n o'.split(' ');
  const parts = classicSplit(words, 4);
  eq(parts.map((p) => p.words.length).join(','), '4,4,4,3', '15 words in 4 parts');
  eq(parts.flatMap((p) => p.words).join(' '), words.join(' '), 'the parts, in order, give back the words');
  eq(parts.map((p) => `${p.from}-${p.to}`).join(' '), '1-4 5-8 9-12 13-15', 'word ranges');
  done('groups');
}

/* ════════════════════════════════════════════════════════════════ */
group('Entropy — combination of the sources');
{
  const csprng = seededRng('csprng')(new Uint8Array(64));
  const mouse = sha256(new TextEncoder().encode('mouse'));
  const dice = sha256(new TextEncoder().encode('dice'));
  const keys = sha256(new TextEncoder().encode('keys'));
  const domain = new TextEncoder().encode('AmnesicWallet/entropy/v1');
  const expected = (parts) => {
    const all = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
    let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
    return sha256(all);
  };
  const M = Uint8Array.of(1), D = Uint8Array.of(2), K = Uint8Array.of(3);
  for (const nBytes of [16, 20, 24, 28, 32]) {
    const out = combineEntropy(nBytes, { mouse, dice, keys }, csprng.slice());
    eq(out.length, nBytes, `${nBytes} bytes requested, ${nBytes} returned`);
    eq(toHex(out), toHex(expected([domain, csprng, M, mouse, D, dice, K, keys]).slice(0, nBytes)), `formula, ${nBytes} bytes`);
  }
  eq(toHex(combineEntropy(16, { mouse, keys }, csprng.slice())), toHex(expected([domain, csprng, M, mouse, K, keys]).slice(0, 16)), 'without dice');
  eq(toHex(combineEntropy(16, {}, csprng.slice())), toHex(expected([domain, csprng]).slice(0, 16)), 'CSPRNG alone');
  check(toHex(combineEntropy(16, { mouse, keys: dice }, csprng.slice())) !== toHex(combineEntropy(16, { mouse, dice }, csprng.slice())),
    'the same bytes as a different source give a different result (labelled inputs)');
  const base = toHex(combineEntropy(16, { mouse, dice, keys }, csprng.slice()));
  const flip = (b) => { const c = b.slice(); c[31] ^= 1; return c; };
  check(toHex(combineEntropy(16, { mouse: flip(mouse), dice, keys }, csprng.slice())) !== base, 'one bit of the pointer changes the result');
  check(toHex(combineEntropy(16, { mouse, dice: flip(dice), keys }, csprng.slice())) !== base, 'one bit of the dice changes the result');
  check(toHex(combineEntropy(16, { mouse, dice, keys: flip(keys) }, csprng.slice())) !== base, 'one bit of the keyboard changes the result');
  const c2 = csprng.slice(); c2[0] ^= 1;
  check(toHex(combineEntropy(16, { mouse, dice, keys }, c2)) !== base, 'one bit of the CSPRNG changes the result');
  check(toHex(combineEntropy(16, { mouse, dice, keys })) !== toHex(combineEntropy(16, { mouse, dice, keys })), 'two real draws differ');
  const given = csprng.slice();
  combineEntropy(16, {}, given);
  check(given.some((b) => b !== 0), 'the caller\'s buffer is not consumed');
  for (const bad of [0, 8, 15, 17, 33, 64, 16.5, '16']) throws(() => combineEntropy(bad, {}), `length ${JSON.stringify(bad)} refused`);
  throws(() => combineEntropy(16, { mouse: new Uint8Array(31) }), 'a source that is not a 32-byte digest is refused');
  throws(() => combineEntropy(16, { dice: [1, 2, 3] }), 'a source that is not bytes is refused');
  throws(() => combineEntropy(16, {}, new Uint8Array(64)), 'a CSPRNG returning zeros stops generation', (e) => e.message === 'RNG_ANOMALY:constant');
  throws(() => combineEntropy(16, {}, Uint8Array.from({ length: 64 }, (_, i) => (i % 2 ? 0xff : 0xfe))), 'a CSPRNG returning mostly ones stops generation', (e) => e.message === 'RNG_ANOMALY:unbalanced');
  check(statisticalChecks(seededRng('ok')(new Uint8Array(64))).ok, 'a normal draw passes the checks');
  done('formula, sources, refusals');
}

group('Entropy — pointer and keyboard collectors (simulated clock)');
{
  let t = 0;
  const now = () => t;
  const mc = createMouseCollector(now);
  mc.start();
  check(mc.progress() === 0, 'no movement, no progress');
  for (let i = 0; i < 99; i++) { t += 90; mc.feed((i % 10) * 30, (i % 7) * 25); }
  check(mc.progress() < 1, '99 events are not enough');
  t += 90; mc.feed(500, 500);
  eq(mc.progress(), 1, '100 varied events over 9 s: complete');
  { let t2 = 0; const quick = createMouseCollector(() => t2); quick.start();
    for (let i = 0; i < 200; i++) { t2 += 20; quick.feed((i % 10) * 30, (i % 7) * 25); }
    check(quick.progress() < 1, 'many events in only 4 s are not enough'); }
  const d1 = mc.bytes();
  eq(d1.length, 32, 'pointer digest is 32 bytes');
  eq(mc.progress(), 0, 'samples are cleared after use');
  mc.start(); t = 0; for (let i = 0; i < 100; i++) { t += 50; mc.feed((i % 10) * 30, (i % 7) * 25 + 1); }
  check(toHex(mc.bytes()) !== toHex(d1), 'a different path gives a different digest');

  t = 0;
  const tc = createTypingCollector(now);
  tc.start();
  for (let i = 0; i < 19; i++) { t += 300; tc.feed('k' + (i % 12)); }
  check(tc.progress() < 1, '19 keys are not enough');
  t += 300; tc.feed('x');
  eq(tc.progress(), 1, '20 keys, 6 s, 13 distinct: complete');
  eq(tc.count(), 20, 'count');
  const k1 = tc.bytes();
  eq(k1.length, 32, 'keyboard digest is 32 bytes');
  eq(tc.count(), 0, 'keystrokes are cleared after use');
  tc.start(); t = 0; for (let i = 0; i < 20; i++) { t += 301; tc.feed('k' + (i % 12)); }
  check(toHex(tc.bytes()) !== toHex(k1), 'a different rhythm gives a different digest');
  done('collectors');
}

group('Entropy — dice');
{
  eq(diceRollsNeeded(128, false), 50, '128 bits need 50 rolls of one die');
  eq(diceRollsNeeded(256, false), 100, '256 bits need 100 rolls');
  eq(diceRollsNeeded(128, true), 30, 'with two identical dice, 30 double rolls');
  eq(diceRollsNeeded(256, true), 59, 'with two identical dice, 59 double rolls for 256 bits');
  check(50 * Math.log2(6) >= 128 && 100 * Math.log2(6) >= 256, 'single-die counts cover the entropy');
  check(30 * Math.log2(21) >= 128 && 59 * Math.log2(21) >= 256, 'double-roll counts cover it even if pairs are entered sorted');
  eq(toHex(diceBytesFrom([1, 2, 3, 4, 5, 6])), toHex(sha256(Uint8Array.of(1, 2, 3, 4, 5, 6))), 'dice digest');
  for (const bad of [[0], [7], [1.5], ['3']]) throws(() => diceBytesFrom(bad), `die value ${JSON.stringify(bad[0])} refused`);
  done('dice');
}

/* ════════════════════════════════════════════════════════════════ */
group('Powers-of-2 grid');
{
  const rows = metalRows('abandon zoo about');
  eq(rows[0].n, 1, '"abandon" is number 1');
  eq(rows[1].n, 2048, '"zoo" is number 2048');
  eq(rows[0].marks.filter(Boolean).length, 1, 'no row is ever empty');
  check(rows.every((r) => r.marks.reduce((s, on, i) => s + (on ? [2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1][i] : 0), 0) === r.n), 'the marks add up to the number');
  throws(() => metalRows('abandon bitcoinz'), 'a word outside the dictionary is refused');
  done('grid');
}

/* ════════════════════════════════════════════════════════════════ */
group('Encoding helpers');
{
  const pub = HDKey.fromMasterSeed(new Uint8Array(32).fill(1)).derive("m/84'/0'/0'/0/0").publicKey;
  check(btcAddressFromPubkey(pub, 'native').startsWith('bc1q'), 'native starts with bc1q');
  check(btcAddressFromPubkey(pub, 'taproot').startsWith('bc1p'), 'taproot starts with bc1p');
  check(btcAddressFromPubkey(pub, 'p2sh').startsWith('3'), 'p2sh starts with 3');
  check(btcAddressFromPubkey(pub, 'legacy').startsWith('1'), 'legacy starts with 1');
  eq(base58.decode(ADDR.seeds[0].trx)[0], 0x41, 'TRON version byte 0x41');
  done('prefixes');
}

/* ════════════════════════════════════════════════════════════════ */
console.log(`\n${passed} checks passed, ${failed} failed.`);
if (failed) {
  if (failures.length > 40) console.log(`(${failures.length - 40} more failures not shown)`);
  process.exit(1);
}
