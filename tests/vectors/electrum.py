#!/usr/bin/env python3
"""Writes tests/vectors/electrum.json: Electrum seeds and what they give.

Two kinds of values, both independent of AmnesicWallet's code:

  official     copied from Electrum's own test suite (spesmilo/electrum,
               tests/test_mnemonic.py and tests/test_wallet_vertical.py):
               seed types, BIP-32 seeds, master keys, first addresses.
  computed     more addresses of those seeds, and further seeds, computed
               here with Python's hashlib/hmac/unicodedata and bip_utils,
               following Electrum's mnemonic.py and keystore.py.

    python3 -m venv venv && ./venv/bin/pip install bip_utils embit
    ./venv/bin/python tests/vectors/electrum.py > tests/vectors/electrum.json
"""
import hashlib, hmac, json, random, string, unicodedata
from bip_utils import (Bip32Slip10Secp256k1, Bip39MnemonicGenerator, Bip39WordsNum, Bip39MnemonicValidator,
                       P2PKHAddrEncoder, P2PKHPubKeyModes, P2WPKHAddrEncoder)
from bip_utils.ecc import Secp256k1, Secp256k1PublicKey
from bip_utils import ElectrumV1, ElectrumV2Standard, ElectrumV2Segwit
from bip_utils.electrum.mnemonic_v1.electrum_v1_seed_generator import ElectrumV1SeedGenerator
from bip_utils.electrum.mnemonic_v2.electrum_v2_seed_generator import ElectrumV2SeedGenerator
import bip_utils, os

UNICODE_HORROR = bytes.fromhex(
    'e282bf20f09f988020f09f98882020202020e3818620e38191e3819fe381be20e3828fe3828b2077cda2cda2cd9d68cda16fcda2cda120ccb8cda26bccb5cd9f6eccb4cd98c7ab77ccb8cc9b73cd9820cc80cc8177cd98cda2e1b8a9ccb561d289cca1cda27420cca7cc9568cc816fccb572cd8fccb5726f7273cca120ccb6cda1cda06cc4afccb665cd9fcd9f20ccb6cd9d696ecda220cd8f74cc9568ccb7cca1cd9f6520cd9fcd9f64cc9b61cd9c72cc95cda16bcca2cca820cda168ccb465cd8f61ccb7cca2cca17274cc81cd8f20ccb4ccb7cda0c3b2ccb5ccb666ccb82075cca7cd986ec3adcc9bcd9c63cda2cd8f6fccb7cd8f64ccb8cda265cca1cd9d3fcd9e'
).decode('utf-8')

# ── Electrum's rules, written again in Python ─────────────────────
CJK = [(0x4E00, 0x9FFF), (0x3400, 0x4DBF), (0x20000, 0x2A6DF), (0x2A700, 0x2B73F), (0x2B740, 0x2B81F),
       (0xF900, 0xFAFF), (0x2F800, 0x2FA1D), (0x2E80, 0x2EFF), (0x2F00, 0x2FDF), (0x31C0, 0x31EF),
       (0x3200, 0x32FF), (0x3300, 0x33FF), (0x3040, 0x309F), (0x30A0, 0x30FF), (0x31F0, 0x31FF),
       (0xFF65, 0xFF9F), (0xAC00, 0xD7AF), (0x1100, 0x11FF), (0x3130, 0x318F), (0x3190, 0x319F),
       (0x31A0, 0x31BF), (0xA000, 0xA48F), (0xA490, 0xA4CF), (0x2FF0, 0x2FFF), (0x3000, 0x303F),
       (0xFE30, 0xFE4F), (0x1F200, 0x1F2FF)]
is_cjk = lambda c: any(a <= ord(c) <= b for a, b in CJK)

def normalize(s):
    s = unicodedata.normalize('NFKD', s).lower()
    s = ''.join(c for c in s if not unicodedata.combining(c))
    s = ' '.join(s.split())
    return ''.join(s[i] for i in range(len(s)) if not (s[i] in string.whitespace and is_cjk(s[i-1]) and is_cjk(s[i+1])))

def prefix_of(words):
    return hmac.new(b'Seed version', normalize(words).encode(), hashlib.sha512).hexdigest()

def bip32_seed(words, passphrase=''):
    return hashlib.pbkdf2_hmac('sha512', normalize(words).encode(), b'electrum' + normalize(passphrase).encode(), 2048)

def addresses(seed, kind, change, count=5):
    node = Bip32Slip10Secp256k1.FromSeed(seed)
    if kind == 'segwit':
        node = node.DerivePath("0'")
    node = node.ChildKey(change)
    out = []
    for i in range(count):
        pub = node.ChildKey(i).PublicKey().RawCompressed().ToBytes()
        if kind == 'segwit':
            out.append(P2WPKHAddrEncoder.EncodeKey(pub, hrp='bc', wit_ver=0))
        else:
            out.append(P2PKHAddrEncoder.EncodeKey(pub, net_ver=b'\x00'))
    return out

N = Secp256k1.Order()
G = Secp256k1.Generator()

def old_addresses(hex_seed, change, count=5):
    a = hex_seed.encode('ascii'); x = a
    for _ in range(100000):
        x = hashlib.sha256(x + a).digest()
    mpk_point = G * (int.from_bytes(x, 'big') % N)
    mpk = Secp256k1PublicKey.FromPoint(mpk_point).RawUncompressed().ToBytes()[1:]
    out = []
    for n in range(count):
        z = int.from_bytes(hashlib.sha256(hashlib.sha256(('%d:%d:' % (n, change)).encode() + mpk).digest()).digest(), 'big') % N
        p = mpk_point + G * z
        pub = Secp256k1PublicKey.FromPoint(p).RawUncompressed().ToBytes()
        out.append(P2PKHAddrEncoder.EncodeKey(pub, net_ver=b'\x00', pub_key_mode=P2PKHPubKeyModes.UNCOMPRESSED))
    return mpk.hex(), out

# ── official values, from Electrum's tests ────────────────────────
official = {
    'bip32Seeds': [
        {'words': 'wild father tree among universe such mobile favorite target dynamic credit identify', 'passphrase': '', 'type': 'segwit',
         'seed': 'aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e3064342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756'},
        {'words': 'wild father tree among universe such mobile favorite target dynamic credit identify', 'passphrase': 'Did you ever hear the tragedy of Darth Plagueis the Wise?', 'type': 'segwit',
         'seed': '4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f'},
        {'words': 'なのか ひろい しなん まなぶ つぶす さがす おしゃれ かわく おいかける けさき かいとう さたん', 'passphrase': '', 'type': 'standard',
         'seed': 'd3eaf0e44ddae3a5769cb08a26918e8b308258bcb057bb704c6f69713245c0b35cb92c03df9c9ece5eff826091b4e74041e010b701d44d610976ce8bfb66a8ad'},
        {'words': 'なのか ひろい しなん まなぶ つぶす さがす おしゃれ かわく おいかける けさき かいとう さたん', 'passphrase': UNICODE_HORROR, 'type': 'standard',
         'seed': '251ee6b45b38ba0849e8f40794540f7e2c6d9d604c31d68d3ac50c034f8b64e4bc037c5e1e985a2fed8aad23560e690b03b120daf2e84dceb1d7857dda042457'},
        {'words': '眼 悲 叛 改 节 跃 衡 响 疆 股 遂 冬', 'passphrase': '给我一些测试向量谷歌', 'type': 'segwit',
         'seed': '6c03dd0615cf59963620c0af6840b52e867468cc64f20a1f4c8155705738e87b8edb0fc8a6cee4085776cb3a629ff88bb1a38f37085efdbf11ce9ec5a7fa5f71'},
        {'words': 'almíbar tibio superar vencer hacha peatón príncipe matar consejo polen vehículo odisea', 'passphrase': 'araña difícil solución término cárcel', 'type': 'standard',
         'seed': '363dec0e575b887cfccebee4c84fca5a3a6bed9d0e099c061fa6b85020b031f8fe3636d9af187bf432d451273c625e20f24f651ada41aae2c4ea62d87e9fa44c'},
        {'words': 'vidrio jabón muestra pájaro capucha eludir feliz rotar fogata pez rezar oír', 'type': 'segwit',
         'passphrase': '¡Viva España! repiten veinte pueblos y al hablar dan fe del ánimo español... ¡Marquen arado martillo y clarín',
         'seed': 'c274665e5453c72f82b8444e293e048d700c59bf000cacfba597629d202dcf3aab1cf9c00ba8d3456b7943428541fed714d01d8a0a4028fc3a9bb33d981cb49f'},
    ],
    'wallets': [
        {'words': 'cycle rocket west magnet parrot shuffle foot correct salt library feed song', 'passphrase': '', 'type': 'standard',
         'masterKey': 'xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U',
         'receiving0': '1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf', 'change0': '1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D'},
        {'words': 'bitter grass shiver impose acquire brush forget axis eager alone wine silver', 'passphrase': '', 'type': 'segwit',
         'masterKey': 'zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ',
         'receiving0': 'bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af', 'change0': 'bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p'},
        {'words': 'bitter grass shiver impose acquire brush forget axis eager alone wine silver', 'passphrase': UNICODE_HORROR, 'type': 'segwit',
         'masterKey': 'zpub6nD7dvF6ArArjskKHZLmEL9ky8FqaSti1LN5maDWGwFrqwwGTp1b6ic4EHwciFNaYDmCXcQYxXSiF9BjcLCMPcaYkVN2nQD6QjYQ8vpSR3Z',
         'receiving0': 'bc1qx94dutas7ysn2my645cyttujrms5d9p57f6aam', 'change0': 'bc1qcywwsy87sdp8vz5rfjh3sxdv6rt95kujdqq38g'},
        {'words': 'powerful random nobody notice nothing important anyway look away hidden message over', 'passphrase': '', 'type': 'old',
         'hexSeed': 'acb740e454c3134901d7c8f16497cc1c',
         'masterKey': 'e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3',
         'receiving0': '1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo', 'change0': '1KRW8pH6HFHZh889VDq6fEKvmrsmApwNfe'},
    ],
    'types': [
        {'words': 'bind clever room kidney crucial sausage spy edit canvas soul liquid ribbon slam open alpha suffer gate relax voice carpet law hill woman tonight abstract', 'type': '2fa'},
        {'words': 'sibling leg cable timber patient foot occur plate travel finger chef scale radio citizen promote immune must chef fluid sea sphere common acid lab', 'type': '2fa'},
        {'words': 'kiss live scene rude gate step hip quarter bunker oxygen motor glove', 'type': '2fa'},
        {'words': 'universe topic remind silver february ranch shine worth innocent cattle enhance wise', 'type': '2fa_segwit'},
    ],
}

# ── computed here: more addresses of those wallets ────────────────
for w in official['wallets']:
    if w['type'] == 'old':
        mpk, rec = old_addresses(w['hexSeed'], 0)
        _, chg = old_addresses(w['hexSeed'], 1)
        assert mpk == w['masterKey']
    else:
        seed = bip32_seed(w['words'], w['passphrase'])
        rec = addresses(seed, w['type'], 0); chg = addresses(seed, w['type'], 1)
    assert rec[0] == w['receiving0'] and chg[0] == w['change0'], w['words']
    w['receiving'] = rec; w['change'] = chg
for v in official['bip32Seeds']:
    assert bip32_seed(v['words'], v['passphrase']).hex() == v['seed'], v['words']

# ── computed here: further seeds, made the way Electrum makes them ─
rng = random.Random(20261001)
words_en = open(os.path.join(os.path.dirname(bip_utils.__file__), 'bip', 'bip39', 'wordlist', 'english.txt')).read().split()
assert len(words_en) == 2048

def make(prefix):
    while True:
        w = ' '.join(rng.choice(words_en) for _ in range(12))
        if prefix_of(w).startswith(prefix) and not Bip39MnemonicValidator().IsValid(w):
            return w

def both(prefix):
    while True:
        m = Bip39MnemonicGenerator().FromEntropy(bytes(rng.getrandbits(8) for _ in range(16))).ToStr()
        if prefix_of(m).startswith(prefix):
            return m

computed = []
for kind, prefix, passphrase in [('standard', '01', ''), ('segwit', '100', ''), ('segwit', '100', 'Électrum Ünïcode  passphrase'), ('standard', '01', 'x')]:
    w = make(prefix)
    seed = bip32_seed(w, passphrase)
    computed.append({'words': w, 'passphrase': passphrase, 'type': kind,
                     'receiving': addresses(seed, kind, 0), 'change': addresses(seed, kind, 1)})
# Words that are at once a valid BIP-39 seed and an Electrum Standard seed.
amb = both('01')
seed = bip32_seed(amb)
computed.append({'words': amb, 'passphrase': '', 'type': 'standard', 'alsoBip39': True,
                 'receiving': addresses(seed, 'standard', 0), 'change': addresses(seed, 'standard', 1)})
# Valid BIP-39 words that are no Electrum seed.
computed.append({'words': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', 'type': ''})

# ── cross-check with bip_utils' own Electrum implementation ───────
def bu_addresses(w, change):
    if w['type'] == 'old':
        e = ElectrumV1.FromSeed(ElectrumV1SeedGenerator(w['words']).Generate())
        return [e.GetAddress(change, i) for i in range(5)]
    try:
        seed = ElectrumV2SeedGenerator(w['words']).Generate(w['passphrase'])
    except ValueError:
        # bip_utils refuses words that are also valid BIP-39 (Electrum's
        # newer versions avoid making them): derive from our seed instead.
        seed = bip32_seed(w['words'], w['passphrase'])
    cls = ElectrumV2Segwit if w['type'] == 'segwit' else ElectrumV2Standard
    return [cls.FromSeed(seed).GetAddress(change, i) for i in range(5)]
for w in official['wallets'] + computed[:-1]:
    # bip_utils does not lower-case the passphrase as Electrum does: those
    # seeds are covered by Electrum's own values above.
    if normalize(w['passphrase']) != w['passphrase']:
        continue
    for change, key in ((0, 'receiving'), (1, 'change')):
        assert bu_addresses(w, change) == w[key], ('bip_utils disagrees', w['words'], key)

# The Electrum 1.x word list in the app must be bip_utils' list, in order.
old_list = open(os.path.join(os.path.dirname(bip_utils.__file__), 'electrum', 'mnemonic_v1', 'wordlist', 'english.txt')).read().split()
assert len(old_list) == 1626
import re
app_list = re.search(r'`(.*)`', open(os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'electrum-old-words.js')).read(), re.S).group(1).split()
assert app_list == old_list, 'the Electrum 1.x word list differs'

print(json.dumps({'official': official, 'computed': computed}, ensure_ascii=False, indent=1))
