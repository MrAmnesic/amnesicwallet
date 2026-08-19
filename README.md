<div align="center">

# 🔐 SeedForge

**BIP-39 deterministic wallet generator — offline, single-file, privacy-first**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)
[![Offline](https://img.shields.io/badge/network-offline-brightgreen.svg)](#-security)
[![Single File](https://img.shields.io/badge/build-single--file-blue.svg)](#-reproducible-build)
[![No Dependencies at Runtime](https://img.shields.io/badge/runtime-zero%20deps-orange.svg)](#-what-it-is)

Bitcoin · Ethereum/EVM · TRON · Solana

</div>

## What it is

SeedForge is a web application that runs **entirely locally** and generates cryptocurrency wallets securely and **fully offline**. It creates a **BIP-39** mnemonic (seed) and derives public addresses for four major blockchains, **without ever transmitting any data** and without relying on browser extensions or third-party services.

The whole app is a **single HTML file**: no installation, no connection, no runtime dependencies.

## Features

- **100% offline** — no network calls, ever. Suitable for air-gapped machines.
- **Single-file** — one `.html` contains everything: markup, style, and crypto logic.
- **Multi-source entropy** — browser CSPRNG + typing rhythm + pointer movement + (optional) physical dice rolls.
- **Visual privacy** — the seed stays covered until you ask for it; copy or print it without displaying it.
- **Multi-chain** — Bitcoin (4 formats), Ethereum/EVM, TRON, Solana.
- **Threshold backups** — internal Shamir scheme and **SLIP-39** (compatible with Trezor, Sparrow, Electrum).
- **Bitcoin multisig** — P2WSH vaults with a descriptor ready for Sparrow.
- **Powers-of-2 backup** — binary grid that records the seed with no readable words.
- **Watch-only** — descriptor and xpub to monitor balances without exposing the seed.
- **Existing wallet checks** — verify seeds, Shamir parts, SLIP-39 sheets and multisig vaults.
- **Open standards** — BIP-32/39/44/48/49/67/84/86, BIP-341, SLIP-10/39/44.
- **Audited libraries** — crypto primitives from the [`@noble`/`@scure`](https://paulmillr.com/noble/) ecosystem.
- **Entropy safety checks** — generation is blocked if the CSPRNG is missing or faulty.
- **Printing** — Seed Card, address lists, backup parts and grids, all free of identifying headers.

## Supported chains

| Blockchain | Format | Derivation Path | Standard |
|---|---|---|---|
| Bitcoin | Native SegWit (`bc1q…`) | `m/84'/0'/0'/0/i` | BIP-84 |
| Bitcoin | Taproot (`bc1p…`) | `m/86'/0'/0'/0/i` | BIP-86 |
| Bitcoin | SegWit compatible (`3…`) | `m/49'/0'/0'/0/i` | BIP-49 |
| Bitcoin | Legacy (`1…`) | `m/44'/0'/0'/0/i` | BIP-44 |
| Bitcoin | Multisig P2WSH | `m/48'/0'/0'/2'` | BIP-48 |
| Ethereum / EVM | Hex (`0x…`) | `m/44'/60'/0'/0/0` | BIP-44 |
| TRON | Base58 (`T…`) | `m/44'/195'/0'/0/0` | SLIP-44 |
| Solana | Base58 | `m/44'/501'/0'/0'` | SLIP-10 |

## How to use

1. **Download** `seedforge.html` from the [Releases](../../releases).
2. **Verify integrity** (see below).
3. **Disconnect** the device from the Internet (ideally use an air-gapped machine).
4. **Open** the file in a modern browser.
5. Generate the seed, select blockchains, derive addresses.
6. **Store the seed securely**: it is the only key to your funds.

## ⚠️ Important warnings

- **The 12-word seed is the only key controlling the funds.** Whoever holds it controls the wallet; whoever loses it loses access irreversibly.
- **Never share the seed** or enter it into untrusted sites or apps.
- For significant amounts, **always verify a generated address with a second independent tool** (hardware wallet or official library) before use.
- This software is provided "as is", without warranty (see [LICENSE](./LICENSE)).

## 🔒 Security

- No network communication: verifiable with a traffic analyzer (e.g. Wireshark).
- No persistence: the seed lives only in volatile session memory — never written to disk or `localStorage`.
- Entropy from `crypto.getRandomValues` (system CSPRNG), never `Math.random()`.
- No dynamic code loading: what's in the file is all that runs.

## 🔁 Integrity verification

Each release ships with the file's SHA-256 hash. Verify the downloaded file matches:

```bash
# Linux / macOS
sha256sum seedforge.html

# Windows (PowerShell)
Get-FileHash seedforge.html -Algorithm SHA256
```

Compare the output with the value published in [`SHA256SUMS`](./SHA256SUMS) or on the release page.

## 🛠️ Reproducible build

You don't have to trust the distributed file — rebuild it yourself and compare the hash.

```bash
git clone https://github.com/MrAmnesic/seedforge.git
cd seedforge
npm ci            # installs exact versions from package-lock.json
npm run build     # produces dist/seedforge.html
sha256sum dist/seedforge.html   # must match the release
```

## 📄 Documentation

Full technical documentation (architecture, derivation, entropy, testing) is in [`docs/`](./docs).

## 📜 Licence

SeedForge is free software under the **GNU General Public License, version 3
or (at your option) any later version**. The full text is in [`LICENSE`](./LICENSE).

In plain terms: you may use it, study it, modify it and redistribute it, for any
purpose including commercial ones. What you may **not** do is take it closed —
if you distribute a modified version, you must release its source code under the
same licence, keep the copyright notices, and state what you changed.

Packaging it for a distribution (Debian, Tails, AnubitUX or any other) is
explicitly welcome and needs no permission.

If the GPL does not fit your use case, get in touch: alternative terms can be
discussed. The licence is what everyone gets by default, not the only one possible.

### Name and provenance

The **licence covers the code, not the name**. "SeedForge", the project site
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
