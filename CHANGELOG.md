# Changelog

Notable changes are recorded here, one entry per published version.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-08

First public release.

An offline BIP-39 wallet generator contained in a single HTML file, with:

- **Multi-source entropy** — browser CSPRNG combined with typing rhythm, pointer
  movement and, optionally, physical dice rolls. Three statistical safety checks
  block generation on failure.
- **Four Bitcoin address formats** — Legacy (BIP-44), SegWit compatible (BIP-49),
  Native SegWit (BIP-84) and Taproot (BIP-86), plus Ethereum/EVM, TRON and Solana.
- **Multiple receiving addresses**, generated ten at a time, with printable list.
- **Watch-only** — account xpub and output descriptor for balance monitoring in
  Sparrow or Electrum, without exposing the seed.
- **Threshold backups** — internal Shamir scheme over GF(256) and **SLIP-39**,
  validated against the 45 official test vectors.
- **Bitcoin multisig** — P2WSH vaults, BIP-48 derivation, BIP-67 key sorting,
  descriptor output and step-by-step spending instructions for Sparrow.
- **Powers-of-2 backup** — binary grid that records the seed with no readable
  word, plus a printable numbered BIP-39 dictionary.
- **Check wallet section** — verify an existing seed, reassemble Shamir parts,
  recover from SLIP-39 sheets, or recalculate a multisig vault from xpubs.
- **Contextual help** next to the options that deserve one, a step-by-step guide
  and a FAQ, in English.
- **Reproducible single-file build** — `npm ci && npm run build` reproduces the
  published artifact byte for byte, and its SHA-256 is published with the release.
