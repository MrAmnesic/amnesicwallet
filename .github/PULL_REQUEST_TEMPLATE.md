# Description

<!-- What does this PR change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Build / CI
- [ ] Refactor (no behavior change)

## Checklist

- [ ] I did **not** commit any seed, mnemonic, private key, or secret.
- [ ] `npm test` passes.
- [ ] `npm run build` and `npm run hash` succeed, and I committed the rebuilt
      `dist/amnesicwallet.html`, `SHA256SUMS` and `site/index.html`.
- [ ] If I changed `src/core.js`, I added tests whose expected values come from
      published vectors or an independent tool.
- [ ] Shamir parts made by earlier versions still reassemble (covered by `npm test`).
- [ ] The app still makes **no network calls** and stores **no sensitive data**.
- [ ] I updated documentation / CHANGELOG where relevant.

## Notes for reviewers

<!-- Anything that helps review. -->
