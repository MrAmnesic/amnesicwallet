# Changelog

Notable changes are recorded here, one entry per published version.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] — 2026-10

### Added
- **Multisig keys can be saved as .txt and written as powers-of-2 grids**,
  like the seed, the Shamir parts and the SLIP-39 sheets: each key on its
  own, or all of them at once (*Save all as .txt*, *All in powers of 2*,
  next to *Print all keys*). The .txt with all the keys ends with the
  vault's descriptor, which the keys alone do not give. In a vault made
  with other people, the seed of your own key has the same two buttons.

## [2.0.0] — 2026-10

A new major number for a release with a new face (the "A" logo) and many
changes to how backups are printed, saved and checked. Nothing is broken:
the words, the parts, the sheets and every backup format are the same as
in 1.x, and everything made with 1.x is read as before.

### Changed
- **Printed Shamir parts carry nothing but the words** and, in a corner with
  no label, the part number and the verification code ("2 · A3F9"). The
  number is needed to reassemble, the code confirms the result. The title
  "Part 2 of 5", the threshold and the line naming the program are gone.
- **Printed SLIP-39 sheets carry only their words.** Each share already
  contains, inside its words, its number and the threshold.
- Printed pages are titled "Document".
- **Each Shamir part's number is essential, and the program says so**: on
  the parts, when one is copied, in Check wallet → Shamir backup and in
  the FAQ. The order in which parts are
  entered does not matter; each part must go in with its own number.
- The words, the parts and every backup format are unchanged; parts and
  sheets printed by earlier versions still work.
- **Check with a public key only shows Bitcoin addresses only**, in the four
  formats: the Ethereum and TRON buttons are gone.
- The title is centred, without the line beneath it, and the square icon beside it is replaced by the new "A" logo, which also heads the site's page.
- **Read-only codes** of a new wallet: the xpub comes first and is copied
  with one press, like the descriptor; what each one is opens from a "?"
  next to it instead of always being on screen.
- Every "?" shows its explanation when the pointer rests on it; a click still
  opens it, with the link to the guide.
- The warning under a new wallet's words ("Whoever holds these words…") is
  gone.
- **Save as .txt**, next to *Print the Seed Card*: the same numbered words
  as the Seed Card, as a plain text file (`document.txt`) saved where the
  browser saves downloads. Nothing is sent anywhere: the file is made in the
  page.
- *View xpub and descriptor* now sits right after *Copy*.
- **Each Shamir part and each SLIP-39 sheet** can now also be saved as
  .txt and written as a powers-of-2 grid, like the seed. A part's file and
  grid carry its number and verification code ("2 · A3F9"); a SLIP-39 grid
  uses the SLIP-39 list of 1024 words (eleven columns), whose numbered list
  the program prints too.
  *Save all as .txt* and *All in powers of 2*, next to *Print all*, do the
  same for every part or sheet at once: one file, or one grid per page.
- **A SLIP-39 wallet shows its xpub and descriptor** (*View xpub and
  descriptor*, next to *Print all sheets*).
- **Better suggestions for a mistyped word.** When one word of a seed is not
  in the list, only the close words that make the whole seed valid are
  suggested: the right one is now almost always among them (in tests, every
  time for a one- or two-letter slip in a 24-word seed). When every word is
  in the list but they do not fit together, the program lists the single
  changes that would make them fit — a word one letter away, or two
  neighbouring words in the other order — to compare with the backup.
- The same diagnosis now appears in Check wallet → Shamir backup (both when
  converting a seed and when entering a part) and in the multisig screens,
  which used to say only that the words were not valid.

### Fixed
- **The page froze after printing** (Chrome, Edge): printing opened a new
  tab, and for as long as that tab's print dialog stayed open the page could
  not be scrolled or used, even when coming back to it. Pages are now
  printed from a hidden frame of the page itself: the print dialog opens
  over the page, and no tab holding the words is left behind.
- Check wallet → Shamir backup said the part number was printed as "Part 2
  of 5"; it now points to the corner of the sheet ("2 · A3F9"), and still
  mentions the older sheets.

## [1.3.2] — 2026-10

### Added
- **Opening the program in Tails**, a new FAQ entry: in Tails, Tor Browser
  may only open files inside its own folder, so `amnesicwallet.html` goes
  into the **Tor Browser** folder (or *Persistent → Tor Browser*).
- **The browser tests also run as Tor Browser.** Firefox with Tor Browser's
  settings at its *Safer* level — fingerprinting resistance with coarse
  timers, no WebGL, no WebRTC, no JIT, no WebAssembly, no MathML — creates
  wallets, checks seeds (BIP-39 and Electrum) and keys, on a computer screen
  and the narrowest window. Nothing in the program had to change for it.

## [1.3.1] — 2026-10

### Changed
- **The four networks have their own symbols**, in their colours: Bitcoin
  orange, Ethereum grey, TRON red, Solana green. They are drawn inside the
  file (SVG) instead of being text characters.
- A **"?" next to the EVM networks** (BSC, Polygon, Arbitrum, Avalanche,
  Optimism, Base) explains that the Ethereum address is the same on all of
  them, and that funds stay on the network they were sent on; a new FAQ
  entry says more.

### Fixed
- **The Bitcoin symbol in Tails.** The ₿ character needs a font that
  contains it, and Tails has none, so an empty box appeared. The symbols no
  longer depend on any font.
- The explanation that opens from a "?" no longer runs past the edge of
  the narrowest phone screens.

## [1.3.0] — 2026-10

### Added
- **Check wallet reads seeds made by Electrum.** Electrum has a seed format
  of its own: the same English words, but other keys and other paths. Such
  words are now recognised by themselves, and the page says which kind they
  are.
  - **Standard** (`1…` addresses, `m/0/n` and `m/1/n`) and **Segwit**
    (`bc1q…`, `m/0'/0/n` and `m/0'/1/n`) seeds, with Electrum's passphrase
    (the "seed extension"): receiving and change addresses, the master
    public key as Electrum shows it, a descriptor, and the search for an
    address.
  - **Electrum 1.x** seeds (before 2014), with their own list of words.
  - **2FA** seeds are recognised; their addresses also need the keys of the
    TrustedCoin service, so the page sends you to Electrum.
  - Words that are both a valid BIP-39 seed and an Electrum seed are shown
    both ways.
- The tests compare all of this with Electrum's own test values, and with
  more seeds computed independently in Python.

### Changed
- Nothing changes for BIP-39 seeds, SLIP-39 sheets or Shamir parts: the same
  words give the same addresses as in 1.2.1, and every backup format is the
  same.

## [1.2.1] — 2026-10

### Fixed
- **QR codes in Tor Browser (Tails).** QR codes were drawn on a canvas and
  then read back as an image; Tor Browser refuses that read-back to protect
  against fingerprinting, so a blank square appeared instead of the QR. They
  are now drawn as SVG, with no canvas, and read the same in every browser.
  The browser tests now refuse canvas read-back, as Tor Browser does.

## [1.2.0] — 2026-09

### Added
- **The kind of wallet is chosen first, once.** Generate wallet opens on four
  cards, from the simplest to the most specific — Classic wallet, Shamir
  wallet, SLIP-39 wallet, Multisig vault — each saying what you get and what
  it is recovered with.
- **Shamir wallet**: a BIP-39 seed created already split into N parts, M of
  which are needed. The wallet opens on the parts and their verification code.
- **Split into groups**, on a Classic wallet, divides the words into numbered
  groups. A threshold backup of an existing seed is made from Check wallet →
  Shamir backup, which now also asks for the number of parts.
- Check wallet: Solana on `m/44'/501'/n'/0/0`, the path Exodus documents.
- Releases carry GitHub's signed certificate of origin (build provenance).

### Changed
- After the words are drawn, there is no longer a choice between BIP-39 and
  SLIP-39 nor an offer to split: both follow from the kind chosen at the start.
- Only the interface changed: with the same randomness, the words, the Shamir
  parts, the SLIP-39 sheets and the addresses are exactly those of 1.1.3, and
  every backup format is the same.

## [1.1.3] — 2026-09

### Added
- **Check wallet finds what does not match.**
  - **A mistyped word** is named with its position, with up to three list
    words close to it; pressing one corrects it. When every word exists but
    the checksum fails, the page says so plainly.
  - **Accounts and derivations, per network.** Each network has its own
    account (Account 1, 2, 3…) and a button for each derivation path that
    gives a different address: for Bitcoin the four formats and Bitcoin
    addresses on the paths of Ethereum and TRON; for Ethereum, TRON and
    Solana every path in use, labelled with the path itself.
  - **Bitcoin change addresses**, next to the receiving ones.
  - **Find the path of an address**: paste an address of the seed being
    checked, and the page tells its account and derivation path.
- **Check with a public key only**: an account xpub, ypub or zpub shows its
  receiving and change addresses (Bitcoin in any format, Ethereum, TRON) and
  a watch-only descriptor, without typing any secret word.

### Changed
- Derivation paths are always shown next to the addresses.
- "SegWit compatible" is now called **Nested SegWit**.
- Addresses and seeds are unchanged: Account 1 on the standard paths gives
  exactly the addresses of earlier versions, and every backup format is the
  same.

## [1.1.2] — 2026-09

### Added
- **The interface is tested in the three browser engines.** On every change,
  the built file is used as a person would — a wallet created from start to
  finish, known seeds checked — in Chromium, Firefox (the engine of Tor
  Browser) and WebKit (the engine of Safari), on a computer and on two phone
  sizes.

### Changed
- The reassembly screen for Shamir parts no longer carries a note about
  earlier versions. Parts made by every earlier version still reassemble.

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
- **Every backup format is unchanged**: seeds, SLIP-39 sheets and Shamir parts
  made with version 1.0.x keep working, and the test suite now checks it.
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
