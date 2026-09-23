# Security Policy

## Reporting a vulnerability

Security is the core promise of this project. If you discover a vulnerability,
**please report it responsibly and privately** before any public disclosure.

- Use GitHub's **[private vulnerability reporting](../../security/advisories/new)** feature, or
- Open a **draft security advisory**.

Please do **not** open a public issue for security-sensitive reports.

Include, where possible:
- A clear description of the issue and its impact.
- Steps to reproduce (a minimal proof-of-concept helps).
- The affected version (commit hash or release, and the file's SHA-256).

We aim to acknowledge reports within a reasonable time and to coordinate a fix
and disclosure timeline with you.

## Scope

In scope:
- Flaws in address/key derivation (incorrect or non-standard results).
- Weak or predictable entropy generation.
- Any network communication or data exfiltration (the app must be fully offline).
- Persistence of sensitive data (seed/keys written to disk, `localStorage`, etc.).
- Supply-chain concerns in the build (unexpected code in the bundled output).
- Weaknesses in the backup schemes (Shamir parts, SLIP-39 sheets, sequential
  split) or in the multisig key checks.
- Ways to bypass the page's Content-Security-Policy.

Out of scope:
- Issues requiring a compromised operating system or browser.
- Physical access attacks against a device already holding a printed seed.
- Social engineering of the user.

## Verifying you run authentic code

- Download from the official **Releases** page or from
  [amnesicwallet.com](https://amnesicwallet.com), the official website.
- **Verify the SHA-256** against [`SHA256SUMS`](./SHA256SUMS): the release
  page, the repository and the website must all show the same value.
- Prefer the **reproducible build**: rebuild from source and compare hashes
  (see [docs/VERIFICATION.md](./docs/VERIFICATION.md)).
