# AmnesicWallet — Frequently asked questions

## ⭐ Why this way of creating the seed is different

Everything in a wallet depends on a single number: the starting one. If that number is predictable, it doesn't matter how robust the cryptography downstream is — the wallet is already lost. That is exactly how real funds have vanished, when a faulty generator produced numbers far less random than they seemed.

**AmnesicWallet's choice is not to depend on a single source.** We mix three (or four, if you use the dice), of completely different natures:

**1 · The browser's cryptographic generator.** The browser has a built-in cryptographic generator, called a CSPRNG. It is fed directly by the operating system and is made exactly for this purpose.

**2 · The rhythm of your fingers.** As you type on the keyboard we record *when* you press each key, to the millisecond. Not the characters — humans choose those badly — but the micro-pauses between one key and the next: irregularities born of your physiology that not even you could reproduce.

**3 · The path of your hand.** Hundreds of coordinates and times as you move the mouse: where you accelerate, where you hesitate, where you change direction. A human movement never repeats itself identically.

**4 · The dice, if you choose them.** The only source born *outside* the computer. No software bug can predict a rolling die.

The sources are fused with **SHA-256**, the same function that protects the Bitcoin network. The property that matters is this: **the result can never be weaker than the best source.** If one gives way, the others hold. It isn't a sum of securities, it's a safety net.

---

## 🌱 What the seed is, in plain words

The seed is a sequence of words — 12 to 24 — that represents the **master key** of your wallet. From it, mathematics derives all your addresses and all the keys to spend, on every network.

Two truths to keep always in mind:

**Whoever knows the words owns the funds.** There is no identity check, there is no appeal. Never share them with anyone.

**If you lose the words, you lose everything.** There is no "forgot password", there is no customer service. This is the flip side of true ownership.

---

## 🔑 The passphrase: a second lock

It is a word or phrase of your own choosing that is added to the 12/24 words. Technically it's called a *passphrase* and it enters the wallet calculation: the same words, with and without it, open **two completely different wallets**.

**What it is really for.** Your paper backup, on its own, becomes useless to whoever finds it: they will see a wallet different from yours, probably empty, without imagining that the real wallet is elsewhere.

**The price to pay.** Forgetting it means losing everything, even with every word of the seed. Keep it somewhere different from the words — it is the separation that gives it value.

---

## 👁️ Why the words stay covered

A passing glance, a video call left open, an automatic screenshot: a couple of seconds are enough for a seed to stop being secret. That's why, by default, we don't show it.

You can copy or print it without ever seeing it, or press **Reveal the words** when you're sure you're alone — useful for writing it down by hand. The same applies to the parts of a split backup.

---

## 🧩 Splitting the seed: three routes

Right after creating the wallet, the program asks you **how you want to keep it**: a single backup, split sequentially, or with a Shamir threshold. You can change your mind at any time using the *Split into several parts* button.

**📄 A single backup.** The words on one sheet only. It's the right choice to start with and for small amounts: immediate, recoverable anywhere. The limit is obvious: if that sheet disappears, everything disappears.

**✂️ Sequential splitting.** The words are cut into consecutive groups: with 12 words and 3 parts you get 1-4, 5-8, 9-12. To reassemble you simply put them back in order without any software. In exchange **all** the parts are needed, and anyone finding two out of three would have few words left to guess.

**🔐 Shamir backup.** Named after the cryptographer Adi Shamir. It doesn't cut the seed, it *transforms* it into parts that are worth something only together. You choose the threshold — 3 parts, 2 are enough — so you can lose some without consequence. And below the threshold the parts reveal **nothing** about the seed: not "almost nothing", zero, by theorem. (The short verification code printed on them is only a fingerprint for checking the result.)

**How to choose:** Shamir if you fear theft or loss; sequential if you fear depending on software many years from now.

---

## 📄 SLIP-39: the backup born already split

When you create a wallet you can choose between two backup standards. **BIP-39** gives you a single phrase of 12 or 24 words. **SLIP-39** gives you instead several sheets of 20 words each, and some of them — for example 3 of 5 — are enough to reopen the wallet.

**The difference that matters.** With BIP-39 the complete phrase exists: you see it, you write it, and from that moment it is your weak point. With SLIP-39 **the whole phrase never exists at any moment**, not even on screen while you create it. Only the sheets exist, and each one alone reveals nothing.

**How to recognise the sheets.** They have 20 words (or 33 for 256-bit backups) and the **first three words are identical** on every sheet of the same backup: they exist precisely to let you see at a glance whether you are mixing sheets from different sets. The words come from a dedicated dictionary of 1024 entries, different from the BIP-39 one.

**Where it is used.** It is the standard that **Trezor** adopts as the default backup on recent models. It is also read by **Sparrow** (from version 2.0), **Electrum**, **Rabby**, **BlueWallet**, **Wasabi** and **Keystone**. So you are not tied to AmnesicWallet: unlike the Shamir backup, this is a public standard.

---

## 🔐 Shamir backup explained properly: what it does and what it doesn't

**What happens when you use it.** The original seed is transformed into several parts — for example 5 — and you decide how many are needed to get it back, for example 3. You keep them in different places. When you need the wallet you enter three of them under *🔍 Check wallet → Shamir backup → I have the parts, I want the seed* and you get **the original seed**. From there you use it wherever you like — Sparrow, Electrum, MetaMask, a Ledger — and none of those programs will ever know you used Shamir, because they don't need to.

**You can use it at two different moments, and this is what most often escapes people.**

**1. While creating a new wallet.** Right after generation, when the program asks how to keep the seed, choose *Shamir backup*. The complete phrase is never written out: you start with the backup already split.

**2. On a seed you already own**, even one created years ago with another program. Go to *🔍 Check wallet → Shamir backup → I have a seed, I want to split it*, enter your words and choose the threshold and number of parts. The wallet does not change: same addresses, funds in place. Only the way you keep it changes. From that moment you can destroy the sheet with the whole phrase and keep only the parts.

Here is the advantage over a classic seed: with the traditional phrase, whoever finds that sheet has everything. With this system, whoever finds one part has nothing. Several fragments are needed together, someone has to realise they belong together, know this backup exists and have the right program. The difference is this: a normal seed is a single weak point. With Shamir, your funds stay safe even if some piece ends up where it shouldn't.

**A useful way to see it:** the parts are a form of encryption of the backup, where the key is "holding enough parts". With one advantage over a password: there is nothing to remember. And below the threshold no attempt will do — it isn't hard to guess, it's mathematically impossible. The 4-character verification code printed on the sheets is only a short fingerprint used to confirm the result: it leaves an attacker with at least 2¹¹² possibilities, far beyond any computer.

**The parts are not wallets.** Each one is made of words and looks every bit like a seed, but it is a fragment. Don't send funds to it and don't import it into a wallet expecting to find something there. On its own, below the threshold, it is worth nothing — and that is exactly what makes it safe.

**You need this program to reassemble them.** It is the price of the method and it must be said clearly: **keep a copy of the file *amnesicwallet.html* together with the parts**. If that dependency bothers you, consider **SLIP-39**, which does the same thing with a public standard read by Trezor, Sparrow and Electrum — but it must be chosen when creating a new wallet, it does not apply to an existing BIP-39 seed.

**Careful not to confuse it with Trezor's Shamir.** Trezor offers a feature called *Shamir Backup*, but it uses the SLIP-39 standard. Parts created here **do not work** in Trezor's Shamir recovery, and vice versa. They are two separate systems that share a name.

---

## 🔢 Powers-of-2 backup

There is a way of saving the seed that uses no words: **just dots on a grid**.

**The mechanism.** Every word in the BIP-39 dictionary has a number from 1 to 2048, and every number can be written as a sum of powers of two: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048. The grid has one column for each. The 2045th word, for example, has the boxes 1024, 512, 256, 128, 64, 32, 16, 8, 4 and 1 marked. To find the corresponding word you just add up the numbers on each row.

**Why it is interesting.** There are no words written on the grid and whoever finds it sees only dots. The problem is not reading it, it's understanding it: you would have to know what that grid is, what those dots mean and how they are used.

**How it's done.** From the wallet, press *🔢 Powers-of-2 backup*. You get a grid with one row per word and the dots already in the right place — with no words and no numbers: the translation will be up to you at recovery time. Print the numbered dictionary as well and keep it separately.

---

## ₿ The four Bitcoin address formats

Bitcoin has changed address format several times over the years. From the **same seed** you can generate all four: they are not different wallets, they are different ways of writing the same ownership.

**Native SegWit** (*bc1q…*) — Today's standard, and the default choice: low fees and accepted practically everywhere.

**Taproot** (*bc1p…*) — The most recent: even lower fees and greater privacy. Some older services don't accept it yet.

**SegWit compatible** (*3…*) — A transitional format, accepted even by the oldest services.

**Legacy** (*1…*) — The original format from 2009. It always works, but costs more in fees.

Each format uses a different derivation path, so it produces different addresses. If you are recovering an old wallet and the address doesn't match, try changing format: the seed is probably right.

---

## 🧭 The derivation path, explained

From your seed come very many different addresses, not just one. The derivation path indicates which address you are taking among them all.

It is a sequence of numbers. Each number represents a precise choice, a step along the path.

Here is a derivation path explained:

**How many addresses can you have?** Each level of the path allows around two billion possible values. This applies both to accounts and to addresses: you can have billions of different accounts and, inside each account, billions of different addresses.

**What does the apostrophe mean?** It indicates a *hardened* derivation, that is a reinforced one. Without it, anyone holding an extended public key and a single child private key could work back to the parent key. The apostrophe closes that road. That's why the first three levels always have it.

**Why it concerns you.** If you import the seed elsewhere and the addresses don't match (particularly with Bitcoin, which has several formats), it is almost always the path that differs — not the seed. It's the reason why a Legacy wallet and a Native SegWit one, though born from the same words, show completely different addresses: they simply sit on different branches of the same tree.

**Not every wallet counts accounts the same way.** “Account 2” in MetaMask is the second address of the first branch (`m/44'/60'/0'/0/1`); in Ledger Live it is a branch of its own (`m/44'/60'/1'/0/0`). Same words, different addresses.

**How to find a missing address.** In *Check wallet* you can change the account with the + button, see the change addresses of Bitcoin, and open *All derivation paths*: it lists, for every network, the paths of the best-known wallets and some unusual ones — for example Bitcoin addresses on Ethereum's path — and lets you type any path yourself. If you only have the account's public key (xpub, ypub or zpub), *A public key only* shows its addresses without typing any secret word.

---

## 📬 Why does Bitcoin have many addresses and the other networks only one?

In the Bitcoin world it is good practice to use **a new address for every payment you receive**. All the addresses belong to the same wallet and are controlled by the same seed, but anyone watching the blockchain has a much harder time linking your incoming payments together.

That's why, after generating the wallet, you find the *Show more Bitcoin addresses* button: it generates ten at a time, all yours.

On **Ethereum, TRON and Solana** it works differently: you always use the same address, always. That is the normal behaviour of those networks — it is not a limitation of the program.

---

## 👁️ Seeing the balance without risking anything (watch-only)

After generating the Bitcoin addresses, the *View xpub and descriptor* button shows a **descriptor**: a line of text that describes your wallet *without containing the keys to spend*. For a normal wallet it is entirely optional — your words are all you need to recover. In **multisig**, however, **it is essential**: without it, rebuilding the vault is much harder.

By pasting it into **Sparrow** (*File → Import Wallet → Output Descriptor*) or into Electrum, you get a read-only wallet: you see balance and movements in real time, but nobody — not even you, from there — can move the funds. The seed stays safe where it is, without ever touching a connected device.

It's the best way to keep an eye on a cold wallet from your phone or your everyday computer.

**A privacy warning:** whoever holds the descriptor sees all your Bitcoin movements, present and future. They cannot spend, but it is like handing over a bank statement: share it only with someone you'd trust to see your accounts.

---

## 🔍 I have an old backup: how do I check it's good?

Go to **🔍 Check wallet** and choose **A complete seed**. Type the words and the program shows you which addresses they generate, without changing anything and without taking the seed onto a connected device.

If the addresses match those you remember or see in a blockchain explorer, the backup is correct. If they don't match, check in this order: the **passphrase** (had you set one?), the **Bitcoin format** (try the other three), and finally the **later addresses** using the button that shows ten more.

⚠️ Typing a seed is by far the most delicate moment: do it with the device disconnected from the internet, or better still from a Tails system or a clean virtual machine.

---

## 🔐 Multisig: when one key isn't enough

A *multisig* address requires several keys to move the funds — for example 2 signatures out of 3. It is used in two very different ways:

**👤 All the keys yours.** It's the most common use, and perhaps the best security upgrade for anyone self-custodying. You create three keys and distribute them across three different places. From then on a thief who ransacks your home gets nothing, and you can lose one backup without losing a cent. The moment the keys are born together is the only one in which they coexist.

**👥 With other people.** For family, company or group funds. Everyone creates their key on their own device and shares only the **xpub**, a public code that reveals nothing secret. Nobody can spend alone.

**To be kept with the backups:** the *descriptor*, the formula describing how the keys combine. With the seeds alone, but without the descriptor, rebuilding the vault is far more laborious.

---

## 📴 Does it really connect to nothing?

Really. No network request, at any moment: no servers, no statistics, no silent updates. All the cryptographic libraries are embedded in the file, and nothing is downloaded while you use it.

It is not only a promise in the code. The file carries a rule for the browser, called *Content-Security-Policy*, that forbids any connection and any script other than its own: even a bug, or a modified copy of a library, would be stopped by the browser itself.

Nothing is saved either: no cookies, no local storage, no files written. The seed lives only in the page's memory, and the browser releases it when you close the tab.

**And you can verify it yourself.** Open the file on a computer disconnected from the internet: it works exactly the same way. That is in fact how we recommend using it.

---

## 💸 Can I spend from here?

No, and it's a deliberate choice. Spending means building transactions and sending them to the network: a whole wallet, with far more code and a reason to go online. AmnesicWallet does one thing — create wallets in a clean environment — and keeps it small enough to be checked.

To receive, the address is enough. To spend, import your words into a compatible wallet: **Electrum** or **Sparrow** for Bitcoin, **MetaMask** or **Rabby** for Ethereum, **TronLink** and **Phantom** for the other networks.

For significant amounts, the best choice is to import the seed into a **hardware wallet** such as a Ledger or Trezor: it signs transactions internally, without ever exposing the key to the computer.

---

## 🛡️ The five rules that matter

**1 · Generate offline.** Disconnect the device from the network, or use a clean bootable USB stick. It's how this tool gives its best.

**2 · Save the backup before using the wallet.** The words are the only key: whoever holds them holds the funds, whoever loses them loses access. Choose the way of keeping them that you consider safest, and do it before you send any funds.

**3 · Know your single points of failure.** One sheet in one place can be lost or found. Splitting it (Shamir, SLIP-39) or a multisig vault remove that single point, at the price of more pieces to look after: weigh which risk worries you more.

**4 · Verify before trusting.** On the same offline device, restore the words in a second program such as Sparrow or Electrum and check that the address matches. Two independent tools that agree are worth more than any guarantee.

**5 · Do a test run.** Send a token amount, then try recovering it from the backup alone. **An unverified backup is not a backup: it's a hope.**

---
