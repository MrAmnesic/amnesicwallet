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
- [ ] `npm test` passes, and `npm run test:ui` passes on the rebuilt page.
- [ ] `npm run build`, `npm run hash` and `npm run docs` succeed, and I committed
      the rebuilt `dist/amnesicwallet.html`, `SHA256SUMS`, `site/index.html`,
      `docs/STEP-BY-STEP.md` and `docs/FAQ.md`.
- [ ] If I changed `src/core.js`, I added tests whose expected values come from
      published vectors or an independent tool.
- [ ] Shamir parts made by earlier versions still reassemble (covered by `npm test`).
- [ ] The app still makes **no network calls** and stores **no sensitive data**.
- [ ] I updated the documentation where relevant (`CHANGELOG.md` is written at
      release time).

## Notes for reviewers

<!-- Anything that helps review. -->
