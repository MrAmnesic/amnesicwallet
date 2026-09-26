# Test vectors — sources and licences

The expected values used by `tests/core.test.js` come from outside this
project. Each file is listed with its origin.

| File | Content | Source | Licence |
|---|---|---|---|
| `bip39.json` | The 24 English BIP-39 vectors (entropy, words, seed with passphrase `TREZOR`, root xprv) | [trezor/python-mnemonic](https://github.com/trezor/python-mnemonic), `vectors.json`, commit `b57a5ad77a981e743f4167ab2f7927a55c1e82a8` | MIT, © 2013-2016 Pavol Rusnak |
| `slip39.json` | The 45 official SLIP-39 vectors (valid and invalid share sets, master secret, xprv; passphrase `TREZOR`) | [trezor/python-shamir-mnemonic](https://github.com/trezor/python-shamir-mnemonic), `vectors.json`, commit `17fcce14736afe498871d3018e4fa9330443471a` | MIT, © 2019 SatoshiLabs |
| `slip10-ed25519.json` | Test vectors 1 and 2 for ed25519 | [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md), commit `570ed55b7fde158f1116be34fc2faa35dada5912` | CC BY-SA 4.0, SatoshiLabs |
| `addresses.json` | Addresses, account xpubs, fingerprints, BIP-48 xpubs/Zpubs and multisig vaults for 5 mnemonics × 2 passphrases | Computed for this project with the Python libraries [bip_utils](https://github.com/ebellocchia/bip_utils) and [embit](https://github.com/diybitcoinhardware/embit), independently of AmnesicWallet's code | GPL-3.0-or-later (this project) |
| `paths.json` | Addresses at every derivation path the check offers (all networks, accounts 1, 2 and 5, including the old Sollet derivation), receiving and change branches, and addresses and descriptors from account xpubs, ypubs and zpubs, for 3 mnemonics | Computed for this project with [bip_utils](https://github.com/ebellocchia/bip_utils) and [embit](https://github.com/diybitcoinhardware/embit) — Bitcoin with both, cross-checked — independently of AmnesicWallet's code; the script is `paths.py`, next to it | GPL-3.0-or-later (this project) |
| `shamir-compat.json` | Shamir parts (3 of 5) produced by version 1.0.1 | Generated with version 1.0.1 of this program | GPL-3.0-or-later (this project) |

The vectors were converted to JSON without changing any value.

## MIT licence texts

**trezor/python-mnemonic**

> The MIT License (MIT)
>
> Copyright (c) 2013-2016 Pavol Rusnak
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of
> this software and associated documentation files (the "Software"), to deal in
> the Software without restriction, including without limitation the rights to
> use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
> the Software, and to permit persons to whom the Software is furnished to do so,
> subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
> FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
> COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
> IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
> CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

**trezor/python-shamir-mnemonic**

> Copyright 2019 SatoshiLabs
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this
> software and associated documentation files (the "Software"), to deal in the Software
> without restriction, including without limitation the rights to use, copy, modify,
> merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
> permit persons to whom the Software is furnished to do so, subject to the following
> conditions:
>
> The above copyright notice and this permission notice shall be included in all copies
> or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
> INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
> PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
> HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
> CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
> OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
