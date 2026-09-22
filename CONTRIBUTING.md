# Contributing

Thank you for considering a contribution! This project values **correctness,
transparency, and security** above all.

## Ground rules

- **Never commit secrets.** No seeds, mnemonics, private keys, or `.env` files.
- **Keep it dependency-light.** New runtime dependencies must be justified and,
  ideally, come from audited crypto libraries (`@noble`, `@scure`).
- **No network calls.** The app must remain 100% offline. Any code that fetches
  from the network will be rejected.
- **No persistence of sensitive data.** Seeds/keys stay in volatile memory only.

## Development

```bash
npm ci                # install exact, locked versions
npm test              # run the test suite against src/core.js
npm run build         # produce dist/amnesicwallet.html
npm run hash          # write its SHA-256 to SHA256SUMS and site/index.html
npm run docs          # regenerate docs/STEP-BY-STEP.md and docs/FAQ.md from the app
```

All cryptography lives in `src/core.js`, which has no interface code; the
interface is in `src/app.js`. A pull request that changes `src/` must also
commit the rebuilt `dist/amnesicwallet.html`, `SHA256SUMS` and
`site/index.html`: CI rebuilds them and fails if they differ.

## Pull requests

1. Fork and create a feature branch.
2. Make focused, minimal changes with clear commit messages.
3. **Ensure the tests still pass** (`npm test`).
4. If you touch anything in `src/core.js`, add tests in `tests/core.test.js`,
   with expected values that come from outside the project (official vectors,
   or an independent library).
5. Describe *what* changed and *why* in the PR.

## Verifying derivation changes

Any change to key/address derivation **must** be validated against published
test vectors (e.g. the canonical `abandon … about` mnemonic) and cross-checked
with an independent tool. The Shamir format is frozen: parts made by earlier
versions (`tests/vectors/shamir-compat.json`) must always reassemble. PRs that
do not meet this will not be merged.

## Licensing of contributions

AmnesicWallet is released under the GNU General Public License v3 or later.

By opening a pull request you confirm that:

1. you wrote the contribution yourself, or you have the right to submit it;
2. you license it under the **GPL-3.0-or-later**, like the rest of the project; and
3. you also grant the maintainer permission to distribute your contribution
   under other licence terms, should an alternative licence ever be offered.

Point 3 keeps a single person able to answer requests for alternative terms.
Without it, every future licensing decision would require tracking down and
obtaining the agreement of every past contributor. It does not take anything
away from you: your contribution stays yours, and it stays free software under
the GPL for everyone.
