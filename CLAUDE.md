# Notes for Claude

AmnesicWallet: an offline, single-file wallet generator (BIP-39 and SLIP-39 seeds, Shamir backups,
Bitcoin multisig; Bitcoin, Ethereum/EVM, TRON, Solana). Maintainer: MrAmnesic. Website:
https://amnesicwallet.com (Netlify, deployed automatically from `main`). Formerly SeedForge.

## Working with the maintainer

- The maintainer is not a developer and writes in Italian: answer in **Italian**, briefly, in plain
  words, with numbered steps when he has to do something himself.
- He wants to work only from the chat: make the change, run the checks, commit and push. Tell him
  in one or two sentences what changed and whether anything is left for him to do.
- Be honest about what was verified and what was not.

## Rules for the project

- Everything in the repository is in **English** (interface, docs, site, comments).
- **No prescriptions on how to keep the seed** (no "write it on paper", "never in the cloud"…).
  Only the fact: whoever holds the words holds the funds; whoever loses them loses access.
- **No network code, storage or `Math.random`** anywhere: `scripts/build.js` refuses to build.
  The page carries a Content-Security-Policy with the script's hash.
- **Backup formats are frozen.** Shamir parts made by earlier versions must always reassemble
  (`tests/vectors/shamir-compat.json`). Never change derivation paths or encodings.
- Any change to `src/core.js` needs tests in `tests/core.test.js` whose expected values come from
  outside the project (official vectors or an independent library).
- Never rewrite or force-push published history: releases and tags depend on it.
- `CHANGELOG.md` gets an entry only for a published version.

## Layout

- `src/core.js` — all cryptography, no DOM. `src/app.js` — interface and every text the user reads.
- `src/index.html` — markup and CSS. `src/*-shim.js` — adapters for the `slip39` library.
- `dist/amnesicwallet.html` — the published file (committed). `SHA256SUMS` — its hash.
- `site/` — the website; the hash line in `site/index.html` is written by `npm run hash`.
- `docs/STEP-BY-STEP.md` and `docs/FAQ.md` are generated from `src/app.js`: edit the app, not them.
  `docs/TECHNICAL.md` is written by hand; `docs/Technical-Documentation.pdf` is rendered from it.

## Commands

```bash
npm ci            # exact dependencies
npm test          # ~1,400 checks on src/core.js; must pass
npm run build     # dist/amnesicwallet.html (fails on forbidden APIs)
npm run hash      # SHA256SUMS + hash on site/index.html
npm run docs      # regenerate STEP-BY-STEP.md and FAQ.md
```

Before committing a change to `src/`: `npm test && npm run build && npm run hash && npm run docs`,
then commit `dist/`, `SHA256SUMS`, `site/index.html` and `docs/` together. (If they are missing, CI
commits them on `main`, but a pull request fails.)

## Releases

A new version: bump `version` in `package.json`, add the `CHANGELOG.md` entry, commit, then tag
`vX.Y.Z` (same number) and push the tag. The Release workflow rebuilds the file, checks it is
byte-identical to the committed one and publishes it with its `.sha256`.
