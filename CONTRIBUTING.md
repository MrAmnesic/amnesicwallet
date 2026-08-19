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
npm run build         # produce dist/seedforge.html
npm test              # run the derivation test vectors
npm run hash          # print the SHA-256 of the built file
```

## Pull requests

1. Fork and create a feature branch.
2. Make focused, minimal changes with clear commit messages.
3. **Ensure the test vectors still pass** (`npm test`).
4. If you touch derivation logic, add or update test vectors.
5. Describe *what* changed and *why* in the PR.

## Verifying derivation changes

Any change to key/address derivation **must** be validated against published
test vectors (e.g. the canonical `abandon … about` mnemonic) and, ideally,
cross-checked with an independent tool. PRs altering derivation without such
validation will not be merged.

## Licensing of contributions

SeedForge is released under the GNU General Public License v3 or later.

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
