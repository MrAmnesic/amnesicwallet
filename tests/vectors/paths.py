#!/usr/bin/env python3
"""Writes tests/vectors/paths.json: addresses at many derivation paths,
accounts and change branches, and addresses and descriptors computed from
account xpubs / ypubs / zpubs.

Everything is computed with the Python libraries bip_utils and embit
(Bitcoin with both, cross-checked), independently of AmnesicWallet's code.

    python3 -m venv venv && ./venv/bin/pip install bip_utils embit
    ./venv/bin/python tests/vectors/paths.py > tests/vectors/paths.json
"""
import json
from bip_utils import (Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32Slip10Ed25519,
                       P2PKHAddrEncoder, P2SHAddrEncoder, P2WPKHAddrEncoder, P2TRAddrEncoder,
                       EthAddrEncoder, TrxAddrEncoder, SolAddrEncoder, Base58Encoder, CoinsConf)
from embit import bip32, script
from embit.networks import NETWORKS
from embit.descriptor.checksum import add_checksum
from nacl.signing import SigningKey

NET = NETWORKS['main']
SEEDS = [
    ('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', ''),
    ('legal winner thank year wave sausage worth useful legal winner thank yellow', 'TREZOR'),
    ('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote', ''),
]
ACCOUNTS = [0, 1, 4]
PATHS = {
    'btc': ["m/84'/0'/{n}'/0/0", "m/86'/0'/{n}'/0/0", "m/49'/0'/{n}'/0/0", "m/44'/0'/{n}'/0/0",
            "m/84'/0'/{n}'/1/0", "m/0'/0/{n}", "m/0'/0'/{n}'", "m/84'/0'/2147483646'/0/{n}",
            "m/84'/0'/2147483645'/0/{n}", "m/44'/145'/{n}'/0/0", "m/44'/60'/0'/0/{n}", "m/44'/195'/0'/0/{n}"],
    'eth': ["m/44'/60'/0'/0/{n}", "m/44'/60'/{n}'/0/0", "m/44'/60'/0'/{n}", "m/44'/0'/0'/0/{n}", "m/44'/195'/0'/0/{n}"],
    'trx': ["m/44'/195'/0'/0/{n}", "m/44'/195'/{n}'/0/0", "m/44'/60'/0'/0/{n}", "m/44'/0'/0'/0/{n}"],
    'sol': ["m/44'/501'/{n}'/0'", "m/44'/501'/{n}'", "m/44'/501'"],
}
FORMATS = ['native', 'taproot', 'p2sh', 'legacy']


def btc_bip_utils(pub, fmt):
    if fmt == 'legacy':
        return P2PKHAddrEncoder.EncodeKey(pub, net_ver=CoinsConf.BitcoinMainNet.ParamByKey('p2pkh_net_ver'))
    if fmt == 'p2sh':
        return P2SHAddrEncoder.EncodeKey(pub, net_ver=CoinsConf.BitcoinMainNet.ParamByKey('p2sh_net_ver'))
    if fmt == 'native':
        return P2WPKHAddrEncoder.EncodeKey(pub, hrp='bc')
    return P2TRAddrEncoder.EncodeKey(pub, hrp='bc')


def btc_embit(pub, fmt):
    if fmt == 'legacy':
        return script.p2pkh(pub).address(NET)
    if fmt == 'p2sh':
        return script.p2sh(script.p2wpkh(pub)).address(NET)
    if fmt == 'native':
        return script.p2wpkh(pub).address(NET)
    return script.p2tr(pub).address(NET)


def btc(pub_bytes, embit_pub, fmt):
    a, b = btc_bip_utils(pub_bytes, fmt), btc_embit(embit_pub, fmt)
    assert a == b, (a, b)
    return a


out = {'source': 'Computed with bip_utils and embit (tests/vectors/paths.py)', 'seeds': [], 'xpubs': []}
for mnemonic, passphrase in SEEDS:
    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    secp = Bip32Slip10Secp256k1.FromSeed(seed)
    ed = Bip32Slip10Ed25519.FromSeed(seed)
    root = bip32.HDKey.from_seed(seed)
    entry = {'mnemonic': mnemonic, 'passphrase': passphrase, 'paths': [], 'change': {}}
    for n in ACCOUNTS:
        for chain, tpls in PATHS.items():
            for tpl in tpls:
                if '{n}' not in tpl and n > 0:
                    continue
                path = tpl.replace('{n}', str(n))
                row = {'chain': chain, 'account': n, 'template': tpl, 'path': path}
                if chain == 'sol':
                    row['address'] = SolAddrEncoder.EncodeKey(ed.DerivePath(path).PublicKey().RawCompressed().ToBytes())
                else:
                    pub = secp.DerivePath(path).PublicKey().RawCompressed().ToBytes()
                    if chain == 'btc':
                        epub = root.derive(path).key.get_public_key()
                        row['addresses'] = {f: btc(pub, epub, f) for f in FORMATS}
                    elif chain == 'eth':
                        row['address'] = EthAddrEncoder.EncodeKey(pub)
                    else:
                        row['address'] = TrxAddrEncoder.EncodeKey(pub)
                entry['paths'].append(row)
    # solana-keygen default: the first 32 bytes of the seed as the ed25519 secret
    entry['solSeedBytes'] = Base58Encoder.Encode(bytes(SigningKey(seed[:32]).verify_key))
    # old Sollet ("deprecated" in Phantom): BIP-32 secp256k1 derivation at
    # m/501'/n'/0/0, whose private key is the ed25519 secret
    entry['solSollet'] = {}
    for n in ACCOUNTS:
        priv = secp.DerivePath(f"m/501'/{n}'/0/0").PrivateKey().Raw().ToBytes()
        entry['solSollet'][str(n)] = Base58Encoder.Encode(bytes(SigningKey(priv).verify_key))
    # receive and change branches, first five addresses, accounts 0 and 1
    for fmt, purpose in [('native', 84), ('taproot', 86), ('p2sh', 49), ('legacy', 44)]:
        for n in (0, 1):
            for change in (0, 1):
                key = f'{fmt}/{n}/{change}'
                entry['change'][key] = []
                for i in range(5):
                    path = f"m/{purpose}'/0'/{n}'/{change}/{i}"
                    pub = secp.DerivePath(path).PublicKey().RawCompressed().ToBytes()
                    entry['change'][key].append(btc(pub, root.derive(path).key.get_public_key(), fmt))
    out['seeds'].append(entry)

# Account keys as wallets export them, and what they give
VERSIONS = {'xpub': NET['xpub'], 'ypub': NET['ypub'], 'zpub': NET['zpub']}
DESC = {'native': 'wpkh({})', 'taproot': 'tr({})', 'p2sh': 'sh(wpkh({}))', 'legacy': 'pkh({})'}
seed = Bip39SeedGenerator(SEEDS[1][0]).Generate(SEEDS[1][1])
root = bip32.HDKey.from_seed(seed)
for purpose, label in [(44, 'xpub'), (49, 'ypub'), (84, 'zpub'), (86, 'xpub'), (60, 'xpub')]:
    path = f"m/{purpose}'/0'/0'" if purpose != 60 else "m/44'/60'/0'"
    acct = root.derive(path).to_public()
    plain = acct.to_base58(NET['xpub'])
    shown = acct.to_base58(VERSIONS[label])
    row = {'path': path, 'key': shown, 'xpub': plain, 'depth': acct.depth, 'receive': {}, 'change': {}, 'descriptor': {}}
    for fmt in FORMATS:
        row['receive'][fmt] = [btc_embit(acct.derive([0, i]).key, fmt) for i in range(3)]
        row['change'][fmt] = [btc_embit(acct.derive([1, i]).key, fmt) for i in range(2)]
        row['descriptor'][fmt] = add_checksum(DESC[fmt].format(plain + '/0/*'))
    secp_acct = Bip32Slip10Secp256k1.FromSeed(seed).DerivePath(path)
    row['eth'] = [EthAddrEncoder.EncodeKey(secp_acct.ChildKey(0).ChildKey(i).PublicKey().RawCompressed().ToBytes()) for i in range(3)]
    row['trx'] = [TrxAddrEncoder.EncodeKey(secp_acct.ChildKey(0).ChildKey(i).PublicKey().RawCompressed().ToBytes()) for i in range(3)]
    out['xpubs'].append(row)

print(json.dumps(out, indent=1))
