# Verification Guide

How to check, by yourself, that the AmnesicWallet file you hold is the
published one and that it does what it says. You do not have to trust anyone.

---

## 1. Verify the file's fingerprint

Every release publishes the SHA-256 of `amnesicwallet.html`.

```bash
# Linux / macOS
sha256sum amnesicwallet.html

# Windows (PowerShell)
Get-FileHash amnesicwallet.html -Algorithm SHA256
```

The value must be identical in three independent places:

- [`SHA256SUMS`](../SHA256SUMS) in this repository;
- the release page, where `amnesicwallet.html.sha256` is attached;
- the official website, [amnesicwallet.com](https://amnesicwallet.com).

If they differ, **do not use the file**.

### Check where it was built (certificate of origin)

From version 1.1.3, every release file carries GitHub's signed certificate of
origin (a *build provenance attestation*, signed through Sigstore). It states
that this exact file was built by this repository's workflow, from the tagged
commit — not uploaded by hand. With the [GitHub CLI](https://cli.github.com):

```bash
gh attestation verify amnesicwallet.html --repo MrAmnesic/amnesicwallet
```

It works on any copy of the file, including the one downloaded from the
website. The certificate is signed by GitHub, not by the maintainer: a stolen
maintainer password is not enough to forge it for a file built elsewhere.

---

## 2. Rebuild it from source

```bash
git clone https://github.com/MrAmnesic/amnesicwallet.git
cd amnesicwallet
npm ci                 # exact, locked versions
npm run build          # produces dist/amnesicwallet.html
sha256sum dist/amnesicwallet.html
```

The hash must match the published one, byte for byte. This is also done
automatically on every change: continuous integration rebuilds the file and
compares it with the committed one, the release stops if they differ, and the
website refuses to deploy a file whose hash differs from `SHA256SUMS` or from
the hash it displays.

To check an older release, check out its tag first (`git checkout v1.1.0`).

---

## 3. Run the tests

```bash
npm test
```

About 1,400 checks run against the real application core (`src/core.js`),
bundled exactly as in the published file: official BIP-39, SLIP-10 and SLIP-39
vectors; values computed independently with the Python libraries bip_utils and
embit; Shamir parts made by the previous release; and every refusal the
program must make. [TECHNICAL.md, section 8.3](./TECHNICAL.md#83-test-suite)
lists them.

---

## 4. Confirm it is offline

1. Open the browser's developer tools (Network tab), start a traffic analyser
   such as Wireshark, or simply disconnect the machine.
2. Open `amnesicwallet.html`, generate a seed and derive addresses.
3. No request should appear.

The file also contains a Content-Security-Policy (`default-src 'none'`), which
you can read at the top of its source: even if code tried to connect, the
browser would refuse and log a "Content Security Policy" violation.

---

## 5. Cross-check an address

For real value, verify at least one generated address with a **second,
independent tool, still offline** — Sparrow or Electrum on the same
disconnected computer, or a hardware wallet. Restore the same words, compare
the first address, then delete that wallet from the other program. Never type
the words into a program on a connected device.

---

## 6. Read the code

All the cryptography is in [`src/core.js`](../src/core.js), about 650 lines
with no interface code. Look in particular at:

- **Entropy** — `combineEntropy`: the CSPRNG (`crypto.getRandomValues`) is
  always drawn; the other sources are added through SHA-256.
- **Shamir** — `GF`, `shamirSplit`, `shamirCombine`, `verificationCode`.
- **Derivation** — every network's path is written in plain text.
- **No network, no storage, no `Math.random`** — also enforced on the final
  bundle by [`scripts/build.js`](../scripts/build.js), which refuses to build
  otherwise.

The interface is in [`src/app.js`](../src/app.js).
