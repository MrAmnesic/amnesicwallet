# Changelog

Notable changes are recorded here, one entry per published version.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] — 2026-09

### Changed
- **Official website: [amnesicwallet.com](https://amnesicwallet.com).** The
  documentation, the package metadata and the presentation page point to it;
  `amnesicwallet.netlify.app` redirects there.

### Fixed
- **Code-scanning findings (CodeQL), none exploitable.** An error message for
  a rejected multisig key was turned into plain text by stripping tags with a
  regular expression; it is now written without markup in the first place
  (the toast displays text only, so nothing could have been injected). The
  script that extracts the guide and the FAQ from the app now removes tags
  until none is left. The generated `dist/amnesicwallet.html` is no longer
  analysed a second time: its sources in `src/` are, and the rest is
  bundled library code.

## [1.1.0] — 2026-09

### Changed
- **New name: AmnesicWallet** (previously SeedForge). The file is now
  `amnesicwallet.html` and the repository `MrAmnesic/amnesicwallet`. Every
  backup format is unchanged: seeds, SLIP-39 sheets and Shamir parts made with
  SeedForge keep working, and the test suite now checks it.
- **All cryptography moved into `src/core.js`**, a module with no interface
  code, so the test suite runs the exact code that ships.
- **Fewer libraries.** `ethers`, `bech32`, `bs58` and `@noble/ed25519` were
  removed; their work is done by the `@noble` / `@scure` libraries already
  present. The file shrank from about 730 KB to about 360 KB, and every
  dependency is now pinned to an exact version.
- The entropy mix gained a domain-separation string and labelled,
  fixed-length inputs (see `docs/TECHNICAL.md`, 3.3). The meaningless
  statistical test on the final SHA-256 output was removed; the checks on the
  raw generator output remain.
- **Two dice: 30 double rolls instead of 25** for 12 words (59 instead of 50
  for 24). Identical dice cannot be told apart, and a pair entered smaller-first
  carries less randomness than two separate rolls.
- **SLIP-39 sheets use iteration exponent 1**, like Trezor's reference
  implementation: the passphrase is protected by 20,000 PBKDF2 rounds instead
  of 10,000. Sheets made by earlier versions remain readable.

### Security
- **Content-Security-Policy.** The page now tells the browser to refuse every
  connection and every script except its own (identified by its SHA-256).
- **Stricter build.** The build refuses to produce the file if it contains a
  network API, `Math.random`, a storage API, `eval`/`new Function` or any URL.
- **Multisig keys are checked.** Private keys (xprv…) pasted by mistake,
  testnet keys, keys for another script type and duplicate keys are refused
  with an explanation. Duplicates are recognised by the key itself, so the same
  key disguised with different metadata cannot give one person two signatures.
  A co-signer's **Zpub** (as shown by Electrum) is accepted.
- **SLIP-39 passphrase rule enforced when it is chosen**, not only at the end:
  it may contain only ordinary keyboard characters, as the standard requires.
- **Passphrases with a leading or trailing space are refused** at creation:
  the space is invisible on paper.
- **Safer verification advice.** The guide no longer suggests typing the words
  into MetaMask to check them: the second check is done offline, in Sparrow or
  Electrum, on the same disconnected computer.
- **Sequential split: the real exposure is stated.** For the chosen split, the
  program says how many words someone holding every part but one would still
  have to guess, and whether a computer can do it. These parts no longer carry
  a verification code, which would only have helped such a guess.
- Values used during generation (source digests, dice rolls, recovered parts
  and SLIP-39 sheets in the input fields) are cleared after use. "Generate a
  new wallet" now removes every secret of the session — including seeds being
  checked and multisig keys — and closes the print windows. Texts no longer
  promise an "erasure from memory" that JavaScript cannot guarantee.
- GitHub Actions are pinned to commit hashes, and dependency install scripts
  never run in CI. Every change is rebuilt from source: a pull request fails if
  its committed file differs from the rebuild; a change pushed to `main`
  without the rebuilt file (for example an edit made on github.com) gets it
  committed automatically; the release stops if the tagged file differs.

### Added
- **Descriptors with checksum and key origins.** Watch-only and multisig
  descriptors now end with their BIP-380 checksum, and every key generated here
  carries its origin (`[fingerprint/48h/0h/0h/2h]`), so Sparrow and hardware
  wallets recognise their own keys.
- **Shamir sheets say what they are.** Printed parts show "Part 2 of 5", the
  threshold and the verification code; SLIP-39 sheets show "Sheet 2 of 5" and
  the threshold.
- **Honest Shamir recovery.** Without the verification code, the result is
  shown as unconfirmed, with the reason; with it, as confirmed. A malformed code
  is reported.
- **SLIP-39 recovery shows Bitcoin in all four formats**, since a Trezor
  backup may use any of them.
- The key created for a shared multisig vault can be revealed and checked again,
  like every other key.
- The threshold menus follow the number of parts, sheets or keys, and a
  threshold equal to the total is allowed where the standard allows it.
- A test suite of about 1,400 checks (`npm test`), with expected values from
  official vectors and from independent Python libraries, run on every change.
- The website now lives in the repository (`site/`, with its Netlify
  configuration); a deploy stops if the file's hash differs from the one the
  page displays.

### Fixed
- **Narrow phones (320 px wide):** word grids widened the page, so overlays
  were cut off and buttons could not be reached. Words now wrap in two columns.
- After recovering a seed from Shamir parts, or splitting an existing seed,
  parts, xpubs or the passphrase notice of the previous wallet could remain on
  screen. Every value tied to a wallet is now reset together.
- A wallet recovered from SLIP-39 sheets in the Check tab also appeared under
  "A complete seed". The two checks are now separate.
- Changing the Bitcoin format after calculating the addresses left the old
  ones on screen, and "Show 10 more" could mix two formats in one list and one
  printout. The addresses are now recalculated.
- Pressing Back in the half second after an entropy bar filled up was ignored,
  and the wallet was created anyway.
- "View xpub and descriptor" and "Generate a new wallet" were hidden while the
  original seed was locked after a split; they are always available now.
- Several texts were inaccurate: signing does not need a connection (spending
  does); a passphrase cannot be "added later" to the same wallet; the watch-only
  button was referred to by an old name. A threshold of 1 in a multisig vault is
  now explained correctly.
- Addresses and paths shown on screen are escaped like every other value, and
  long QR codes (xpubs, descriptors) use a lighter error correction so a phone
  can read them.

## [1.0.1] — 2026-08

### Fixed
- **Wallet creation was blocked on Android phones.** On-screen keyboards
  (Gboard and most others) report every key as `Unidentified` with key code
  229, so the entropy collector saw a single distinct key and the progress bar
  stopped at 10% for ever. Keystrokes are now also read from the `input`
  event, which carries the characters actually typed. The strength
  requirements are unchanged: 20 keystrokes, 5 seconds, 10 distinct keys.
- **The "Four sources" card could not be selected by tapping its centre.** The
  contextual help "?" was nested inside the button — invalid HTML, and on a
  narrow screen it sat exactly where a finger lands, so the tap opened the
  help instead of choosing dice. The "?" now belongs to the question above.

### Changed
- The entropy step and the step-by-step guide name the finger before the
  mouse, and the input field scrolls back into view when the on-screen
  keyboard covers it.

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
