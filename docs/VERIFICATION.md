# Verification Guide

This guide explains how to independently verify that SeedForge is safe and
correct. You do not have to trust anyone — you can check everything yourself.

---

## 1. Verify file integrity

Every release publishes the SHA-256 of `seedforge.html`.

```bash
# Linux / macOS
sha256sum seedforge.html

# Windows (PowerShell)
Get-FileHash seedforge.html -Algorithm SHA256
```

Compare with the value in [`SHA256SUMS`](../SHA256SUMS) or the release page.
If they differ, **do not use the file**.

---

## 2. Reproduce the build

Rebuild the file from source and confirm you get the same hash.

```bash
git clone https://github.com/MrAmnesic/seedforge.git
cd REPO
npm ci                 # exact, locked versions
npm run build          # produces dist/seedforge.html
node scripts/hash.js   # prints the SHA-256
```

The printed hash should match the released one (bit-for-bit reproducibility
depends on identical dependency versions, which `npm ci` enforces).

---

## 3. Run the test vectors

```bash
npm test
```

This derives addresses from the canonical BIP-39 mnemonic
(`abandon abandon … about`) and compares them to known-correct values for
Bitcoin, Ethereum and Solana, plus a structural check for TRON.

---

## 4. Confirm it is offline

1. Start a network traffic analyzer (e.g. **Wireshark**), or fully disconnect
   the machine from the network.
2. Open `seedforge.html`.
3. Generate a seed and derive addresses.
4. Confirm **no outbound network packets** are produced by the page.

---

## 5. Cross-check an address

For real value, verify at least one generated address with a **second,
independent tool** — a hardware wallet, an official chain library, or a
well-established offline tool such as `iancoleman.io/bip39` (used offline).
Import the same mnemonic and confirm the addresses match.

---

## 6. Read the code

The entire application logic is in [`src/app.js`](../src/app.js). It is short
enough to read in full. Look specifically for:

- **Entropy**: only `crypto.getRandomValues` is used (never `Math.random()`).
- **No network**: there are no `fetch`, `XMLHttpRequest`, or `WebSocket` calls.
- **No persistence**: no `localStorage`, `sessionStorage`, or disk writes of
  sensitive data.
- **Derivation**: each chain uses its documented derivation path.
