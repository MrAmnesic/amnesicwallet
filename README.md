<div align="center">

# 🔐 AmnesicWallet

**Offline, single-file wallet generator — BIP-39 and SLIP-39 seeds, Shamir backups, multisig vaults**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)
[![CI](https://github.com/MrAmnesic/amnesicwallet/actions/workflows/ci.yml/badge.svg)](https://github.com/MrAmnesic/amnesicwallet/actions/workflows/ci.yml)
[![Offline](https://img.shields.io/badge/network-none-brightgreen.svg)](#-security)
[![Single file](https://img.shields.io/badge/build-single--file-blue.svg)](#-reproducible-build)

Bitcoin · Ethereum/EVM · TRON · Solana

**[amnesicwallet.com](https://amnesicwallet.com)** · [Releases](https://github.com/MrAmnesic/amnesicwallet/releases) · [Technical documentation](./docs/TECHNICAL.md)

</div>

## What it is

AmnesicWallet creates cryptocurrency wallets **entirely on your device and entirely offline**. The whole program is **one HTML file**: you download it, check its fingerprint, disconnect from the internet and open it in a browser. Nothing is installed, nothing is sent, nothing is saved.

It generates a **BIP-39** phrase (12–24 words) or a set of **SLIP-39** sheets, and derives the public addresses for four networks. It can also split a seed into threshold parts, build Bitcoin multisig vaults, and check backups you already own.

## Features

- **No network, enforced by the browser** — the file carries a Content-Security-Policy that forbids every connection and every script other than its own. It works on a computer that has never been online.
- **Nothing saved** — no cookies, no storage, no files written.
- **Randomness from several sources** — the system CSPRNG, always, mixed with typing rhythm, pointer or finger movement and, optionally, real dice.
- **Visual privacy** — words stay covered until you ask; you can copy or print them without showing them.
- **Four networks** — Bitcoin in four address formats, Ethereum and EVM chains, TRON, Solana.
- **Threshold backups** — **SLIP-39** (read by Trezor, Sparrow, Electrum, Keystone and others) and a Shamir scheme that works on any existing BIP-39 seed.
- **Bitcoin multisig** — P2WSH `sortedmulti` vaults, with a checksummed descriptor carrying key origins, ready for Sparrow.
- **Watch-only** — account xpub and descriptor (with BIP-380 checksum) to follow a wallet without exposing it.
- **Powers-of-2 backup** — a grid of dots that records the seed with no readable word.
- **Checks** — verify a seed, reassemble Shamir parts, recover SLIP-39 sheets, recalculate a multisig vault, or see an account's addresses from its public key alone (xpub, ypub, zpub).
- **Finding a wallet** — a mistyped word is named with its position and the list words close to it; any account (Account 1, 2, 3…), Bitcoin change addresses, and every known derivation path of every network — those of the best-known wallets and unusual ones — plus any path typed by hand. Paths are always shown.
- **Printing** — Seed Card, sheets, parts, address lists and grids, with neutral titles.

## Supported chains

| Blockchain | Format | Derivation path | Standard |
|---|---|---|---|
| Bitcoin | Native SegWit (`bc1q…`) | `m/84'/0'/0'/0/i` | BIP-84 |
| Bitcoin | Taproot (`bc1p…`) | `m/86'/0'/0'/0/i` | BIP-86 |
| Bitcoin | SegWit compatible (`3…`) | `m/49'/0'/0'/0/i` | BIP-49 |
| Bitcoin | Legacy (`1…`) | `m/44'/0'/0'/0/i` | BIP-44 |
| Bitcoin | Multisig P2WSH | `m/48'/0'/0'/2'` | BIP-48, BIP-67 |
| Ethereum / EVM | Hex (`0x…`, EIP-55) | `m/44'/60'/0'/0/0` | BIP-44 |
| TRON | Base58 (`T…`) | `m/44'/195'/0'/0/0` | SLIP-44 |
| Solana | Base58 | `m/44'/501'/0'/0'` | SLIP-10 |

## How to use

1. **Download** `amnesicwallet.html` from [amnesicwallet.com](https://amnesicwallet.com) or the [releases](https://github.com/MrAmnesic/amnesicwallet/releases).
2. **Verify** its SHA-256 (below).
3. **Disconnect** the device from the internet — or, better, boot [Tails](https://tails.net) from a USB stick.
4. **Open** the file in an up-to-date browser and follow the guided steps.
5. **Keep the backup** you are shown before sending any funds: it is the only key to them.

## ⚠️ Important warnings

- **The words are the only key to the funds.** Whoever holds them controls the wallet; whoever loses them loses access, irreversibly.
- **Never type the words on a connected device**, and never into a site or an app you do not fully trust.
- For significant amounts, **check a generated address with a second, independent tool**, still offline (for example Sparrow or Electrum, or a hardware wallet).
- This software is provided "as is", without warranty (see [LICENSE](./LICENSE)).

## 🔒 Security

- **No network communication.** The build refuses to produce a file that contains a network API, and the page's Content-Security-Policy (`default-src 'none'`, script allowed only by its SHA-256) makes the browser block any connection anyway.
- **No persistence.** No `localStorage`, cookies or files; the build rejects any storage API.
- **Randomness.** `crypto.getRandomValues` is always used (never `Math.random`, which the build also rejects); the other sources are added to it through SHA-256, never in its place. Generation stops if the generator is missing or returns obviously broken output.
- **No dynamic code.** No `eval`, no `new Function`, no remote scripts: what is in the file is all that runs.
- **Audited primitives.** All cryptography comes from the [`@noble` / `@scure`](https://paulmillr.com/noble/) libraries; SLIP-39 from the `slip39` package, checked against Trezor's official vectors.

What the program protects against, and what it cannot, is described in [docs/TECHNICAL.md](./docs/TECHNICAL.md#6-security-model).

## ✅ Tests

`npm test` runs the real application core (`src/core.js`, bundled with the same options as the published file) against:

- the official **BIP-39**, **SLIP-10** and **SLIP-39** test vectors, and the published examples of BIP-44/49/84/86, EIP-55 and BIP-380;
- addresses, xpubs, descriptors and multisig vaults computed independently with the Python libraries **bip_utils** and **embit**, for several seeds and passphrases — including every derivation path the check lists, other accounts, change addresses, and addresses and descriptors from account xpubs, ypubs and zpubs;
- Shamir parts produced by the previous release, which must always reassemble;
- entropy mixing, dice, collectors, and every refusal (private keys, testnet keys, duplicates, wrong thresholds, non-ASCII SLIP-39 passphrases…).

`npm run test:ui` opens the built file in the three browser engines, on a computer screen and on two phone sizes: Chromium (Chrome, Edge, Brave), Firefox (also the engine of Tor Browser, which Tails uses) and WebKit (Safari and the browsers on an iPhone). In each, it uses the page as a person would: it creates a wallet from start to finish — typing, drawing with a finger or the mouse, the words, the backup check, the addresses on all four networks — and checks that the words are a valid seed and the addresses are the ones that seed gives; it checks known seeds in **Check wallet** against the independent values above, together with a mistyped word, account 2, change addresses, all derivation paths, a path typed by hand and the check with a public key only; and it fails on any page error, any network request, or any screen wider than the display.

CI also rebuilds the file from source on every change and compares it, byte for byte, with the committed one: a pull request that does not match fails, and a change made directly on `main` gets the rebuilt file committed by CI.

## 🔁 Integrity verification

```bash
# Linux / macOS
sha256sum amnesicwallet.html

# Windows (PowerShell)
Get-FileHash amnesicwallet.html -Algorithm SHA256
```

The value must match [`SHA256SUMS`](./SHA256SUMS), the release page and [amnesicwallet.com](https://amnesicwallet.com). See [docs/VERIFICATION.md](./docs/VERIFICATION.md).

## 🛠️ Reproducible build

You don't have to trust the distributed file — rebuild it and compare.

```bash
git clone https://github.com/MrAmnesic/amnesicwallet.git
cd amnesicwallet
npm ci            # exact versions from package-lock.json
npm test          # optional: the whole test suite
npm run build     # produces dist/amnesicwallet.html
sha256sum dist/amnesicwallet.html   # must match the release
```

Runtime dependencies (all bundled into the file): `@noble/curves`, `@noble/hashes`, `@scure/base`, `@scure/bip32`, `@scure/bip39`, `qrcode`, `slip39`. Build tool: `esbuild`.

## 📄 Documentation

- [Technical documentation](./docs/TECHNICAL.md) — architecture, entropy, derivation, Shamir format, threat model
- [Verification](./docs/VERIFICATION.md) — checking the file and rebuilding it
- [Step-by-step guide](./docs/STEP-BY-STEP.md) and [FAQ](./docs/FAQ.md) — the same texts shown in the app
- [Changelog](./CHANGELOG.md) · [Security policy](./SECURITY.md) · [Contributing](./CONTRIBUTING.md)

## 📜 Licence

AmnesicWallet is free software under the **GNU General Public License, version 3
or (at your option) any later version**. The full text is in [`LICENSE`](./LICENSE).

In plain terms: you may use it, study it, modify it and redistribute it, for any
purpose including commercial ones. What you may **not** do is take it closed —
if you distribute a modified version, you must release its source code under the
same licence, keep the copyright notices, and state what you changed.

Packaging it for a distribution (Debian, Tails, AnuBitux or any other) is
explicitly welcome and needs no permission.

If the GPL does not fit your use case, get in touch: alternative terms can be
discussed. The licence is what everyone gets by default, not the only one possible.

### Name and provenance

The **licence covers the code, not the name**. "AmnesicWallet", the project site
and the release page identify the build published here — the one whose SHA-256
appears in the release notes.

If you fork this project, please give your version a different name and do not
present it as the official build. This is not pedantry: for a program that
generates private keys, a user must be able to tell a modified copy from the
original. Renaming your fork is what makes that possible.

---

<div align="center">

Made with a focus on **transparency, verifiability, and privacy**.

**Seed custody is the user's sole responsibility.**

</div>
