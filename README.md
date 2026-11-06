hx
==

A command line Swiss-army knife for **Bitcoin (BTC)** and **Bitcoin Cash (BCH)**,
built on [Haskoin](https://github.com/haskoin/haskoin-core). It began as a
Haskell port of [Sx](https://github.com/spesmilo/sx) and keeps Sx's style:
small composable commands that read from standard input and write to standard
output, so they can be chained with pipes.

[![Join the chat at https://gitter.im/np/hx](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/np/hx?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Features
--------

* **Networks**: Bitcoin mainnet, testnet3, testnet4 and regtest; Bitcoin Cash
  mainnet, testnet3, testnet4 and regtest. Every command is network-aware
  (WIF, extended-key and address prefixes, signature hashing).
* **Keys**: random key generation, WIF import and export, compressed and
  uncompressed keys, x-only (BIP340) public keys, Casascius mini keys,
  brain wallets.
* **Addresses**: P2PKH, P2SH, P2WPKH, P2SH-P2WPKH, P2WSH, P2TR (BIP86 key
  path), Bech32 and Bech32m, CashAddr, CashToken-aware CashAddr and P2SH32
  for Bitcoin Cash, conversion between all forms, address to output script
  and back, P2SH/P2WSH addresses of redeem scripts, multisig scripts (BIP67
  sorting).
* **HD wallets**: BIP32 derivation with private, public and hardened paths;
  direct derivation of BIP44, BIP49, BIP84 and BIP86 addresses from a path;
  detailed description of extended keys.
* **Mnemonics**: BIP39 (generation, entropy, seed with passphrase), SLIP-39
  Shamir secret sharing (split and combine), legacy Electrum mnemonics,
  RFC1751.
* **Transactions**: build transactions with any output type, OP_RETURN data
  outputs, version, lock time and opt-in RBF; decode (txid, wtxid,
  size, vsize, weight, witnesses, output types and addresses); sign inputs
  for legacy, SegWit v0 (BIP143) and Bitcoin Cash (SIGHASH_FORKID); set
  scripts and witnesses; verify signatures.
* **PSBT** (BIP174/BIP370): create, add UTXOs, sign with WIF keys or extended
  private keys (legacy, SegWit, Taproot key path, Bitcoin Cash), combine,
  finalize, extract, decode.
* **Signatures**: Bitcoin signed messages compatible with Bitcoin Core,
  Electrum and Electron Cash, including BIP137 SegWit headers; ECDSA and
  BIP340 Schnorr signatures of raw hashes.
* **Scripts**: assemble and disassemble scripts, including CLTV, CSV,
  Tapscript's `OP_CHECKSIGADD` and Bitcoin Cash's `OP_CHECKDATASIG`,
  `OP_CHECKDATASIGVERIFY` and `OP_REVERSEBYTES`.
* **Encodings and hashes**: hex, Base58, Base58Check, Bech32/Bech32m, Base64,
  SHA-1, SHA-256, SHA-512, RIPEMD-160, HASH160, HASH256, BIP340 tagged hashes,
  HMAC-SHA224/256/384/512, PBKDF1 and PBKDF2, satoshi and coin amounts.
* **Readable output**: YAML with colors on terminals, or JSON (`--json`)
  for `jq` and other tools.
* **Elliptic curve maths** on secp256k1: point addition, doubling,
  multiplication and field arithmetic.

Installation
------------

hx needs [Stack](https://docs.haskellstack.org/) and the
[libsecp256k1](https://github.com/bitcoin-core/secp256k1) C library (0.2.0 or
newer, built with the recovery, extrakeys and schnorrsig modules, as the Linux
distribution, Homebrew and Nixpkgs packages are).

Install libsecp256k1 and pkg-config:

    # Debian, Ubuntu
    $ sudo apt-get install libsecp256k1-dev pkg-config
    # Fedora
    $ sudo dnf install libsecp256k1-devel pkgconf-pkg-config
    # macOS
    $ brew install secp256k1 pkg-config
    # Nix: a development shell with all of the above
    $ nix-shell

Then build and install hx:

    $ git clone https://github.com/np/hx
    $ cd hx
    $ stack build
    $ stack install        # copies hx to ~/.local/bin
    $ hx help

The build uses the Stackage nightly snapshot pinned in `stack.yaml` (GHC
9.12) together with `haskoin-core` 1.6 and its newer cryptographic
dependencies from Hackage.

### Docker

    $ docker build -t hx .
    $ echo 5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS | docker run -i --rm hx addr
    1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T

### Running the tests

The `tests` directory holds more than three hundred command line tests, many
of them taken from the reference vectors of the BIPs, the CashAddr and SLIP-39
specifications and Bitcoin Core.

    $ stack build && tests/run-tests.sh
    331 passed, 0 failed

Use `tests/run-tests.sh -v tests/addr.t` to run a single test.

Usage
-----

    hx [-n|--network NETWORK] [-j|--json] [-y|--yaml] [--color[=WHEN]] COMMAND [ARGS...]

* The network defaults to `$HX_NETWORK`, or `btc` when unset. `hx networks`
  lists the networks and their aliases (`btc`, `testnet`, `testnet4`,
  `regtest`, `bch`, `bchtest`, `bchtest4`, `bchreg`, ...).
* Arguments shown as `[<ARG>]` are read from standard input when omitted, and
  a single `-` argument is replaced by standard input.
* Command names are case-insensitive.
* `hx help` prints the full list of commands.

### Output formats

Results print as **YAML** by default, laid out over several lines with
related fields together. `-j`/`--json` (or `HX_FORMAT=json`) prints **JSON**
instead, for `jq` and other tools: indented on a terminal, and on a single
line when piped. `-y`/`--yaml` switches back. The long options may also come
after the command, as in `hx showtx tx.hex --json`.

* A result that is a single value (an address, a key, a hex string) prints
  bare in YAML mode, so commands can be piped into each other:
  `hx bip39-seed | hx hd-priv`. In JSON mode it is a JSON string.
* Verifications (`validaddr`, `validsig`, `verify-hash`, `schnorr-verify`,
  `message-verify`, `verifysig-modn`) print `true` or `false`, and exit with
  status 1 when false, so they can be used directly in shell conditions.
* Colors are used when the output is a terminal. `--color=always`,
  `--color=never` (or `--no-color`) and `--color=auto` choose explicitly;
  the [`NO_COLOR`](https://no-color.org) variable and `TERM=dumb` turn
  automatic colors off. Errors on standard error are colored the same way.

```
$ hx addr-info 1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T
address: 1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T
network: btc
type: p2pkh
version: 0
hash: c4c5d791fcb4654a1ef5e03fe0ad3d9c598f9827
script:
  asm: dup hash160 [ c4c5d791fcb4654a1ef5e03fe0ad3d9c598f9827 ] equalverify checksig
  hex: 76a914c4c5d791fcb4654a1ef5e03fe0ad3d9c598f982788ac
$ hx --json addr-info 1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T | jq -r .script.hex
76a914c4c5d791fcb4654a1ef5e03fe0ad3d9c598f982788ac
$ if hx validaddr "$ADDRESS" > /dev/null; then echo valid; fi
```

On Bitcoin Cash networks addresses are printed in CashAddr form and
signatures use SIGHASH_FORKID; SegWit and Taproot outputs are not available.

Examples
--------

### Keys and addresses

Derive the public key and the four kinds of Bitcoin addresses of a key:

    $ K=L4WVo4zZ8QC795KtwPyqgH92T7Q23FC4p4wGkFeZiaWeyewugte7
    $ echo $K | hx pubkey
    03d2be3dddb497c7c4388cfcb941e14a222cf3e26fe5e2cc260da1821e60d26022
    $ echo $K | hx addr
    15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs
    $ echo $K | hx addr --type p2wpkh
    bc1q9cy7s7nmzah0m6mt2ftmu6x723esjxqkkl4wsw
    $ echo $K | hx addr --type p2sh-p2wpkh
    35uijJkf4rcCnGzEZsn12YJenTHToDKpr2
    $ echo $K | hx addr --type p2tr
    bc1ptk7g2ztd0fxmjtn09lkr245tmrjjn2vjftrwps6hqwrd7s7w22jspf7a33

The same key on Bitcoin Cash, and conversions between address forms:

    $ echo $K | hx -n bch addr
    bitcoincash:qqhqn6r60vtkal0tddf900ngme28xzgczcdd37lrxz
    $ echo bitcoincash:qqhqn6r60vtkal0tddf900ngme28xzgczcdd37lrxz | hx -n bch addr-convert --to legacy
    15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs
    $ hx -n bch addr-info bitcoincash:qqhqn6r60vtkal0tddf900ngme28xzgczcdd37lrxz
    address: bitcoincash:qqhqn6r60vtkal0tddf900ngme28xzgczcdd37lrxz
    network: bch
    type: p2pkh
    version: 0
    hash: 2e09e87a7b176efdeb6b5257be68de5473091816
    script:
      asm: dup hash160 [ 2e09e87a7b176efdeb6b5257be68de5473091816 ] equalverify checksig
      hex: 76a9142e09e87a7b176efdeb6b5257be68de547309181688ac
    legacy: 15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs
    cashaddr: bitcoincash:qqhqn6r60vtkal0tddf900ngme28xzgczcdd37lrxz
    token: bitcoincash:zqhqn6r60vtkal0tddf900ngme28xzgczc28zq39e3

Generate a new key, and convert between WIF and raw secrets:

    $ hx newkey
    KyQ...                        # random
    $ echo c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a | hx secret-to-wif
    L3p8oAcQTtuokSCRHQ7i4MhjWc9zornvpJLfmg62sYpLRJF9woSu
    $ echo L3p8oAcQTtuokSCRHQ7i4MhjWc9zornvpJLfmg62sYpLRJF9woSu | hx wif-to-secret
    c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a

Addresses and output scripts:

    $ hx addr-to-script bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0
    512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    $ hx script-to-addr 512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0
    $ echo 1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262 | hx encode-addr --p2wsh
    bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3

A 2-of-2 multisig redeem script and its addresses:

    $ R=$(hx multisig --sort 2 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 \
                                02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)
    $ echo $R | hx showscript
    2 [ 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 ] [ 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 ] 2 checkmultisig
    $ echo $R | hx script-addr --p2wsh
    bc1qzy9djrcg9r92a0ahncazwkfe988hnxzqdk90ckphsdahdvfdmuwscz2auk
    $ echo $R | hx script-addr --p2sh-p2wsh
    3CPBUk4UsoxtAWB56Ts5EfCVQxJo6Z5478
    $ echo $R | hx -n bch script-addr --p2sh32
    bitcoincash:p0qdee32stwlhpmflx8degrjzkkzhzqvwzxw5wkhttpm4gev2q2wkff905g42

### Mnemonics and HD wallets

    $ hx bip39-new 12
    ...                           # twelve random words
    $ M="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    $ echo $M | hx bip39-seed | hx hd-priv
    xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu

`hd-path` derives a path from an extended private key, an extended public
key or a seed in hex. Its first letter selects the output: `m` and `M` for
extended keys, `p`, `u`, `P`, `U` and `X` for private and public keys, and
`A` (P2PKH), `S` (P2SH-P2WPKH), `W` (P2WPKH) and `T` (P2TR) for addresses.
Hardened steps are written `'`, `h` or `H`.

    $ SEED=$(echo $M | hx bip39-seed)
    $ echo $SEED | hx hd-path "A/44'/0'/0'/0/0"         # BIP44
    1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
    $ echo $SEED | hx hd-path "S/49h/0h/0h/0/0"         # BIP49
    37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf
    $ echo $SEED | hx hd-path "W/84'/0'/0'/0/0"         # BIP84
    bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
    $ echo $SEED | hx hd-path "T/86'/0'/0'/0/0"         # BIP86
    bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
    $ echo $SEED | hx -n bch hd-path "A/44'/145'/0'/0/0"
    bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6
    $ echo $SEED | hx hd-path "M/84'/0'/0'" | hx hd-decode
    type: xpub
    network: btc
    depth: 3
    index: 0
    hardened: true
    fingerprint: fd13aac9
    parent_fingerprint: 7ef32bdb
    chain_code: 4a53a0ab21b9dc95869c4e92a161194e03c0ef3ff5014ac692f433c4765490fc
    xpub: xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V
    pubkey: 02707a62fdacc26ea9b63b1c197906f56ee0180d0bcf1966e1a2da34f5f3a09a9b
    addresses:
      p2pkh: 1Q59X2jXqdASameV9tGgGKbCg7Z3UAzUHN
      p2wpkh: bc1ql5f64jdzjsvgehlpxvdgm9ygp0xta7xpnueh03
      p2sh-p2wpkh: 36yDdNRzptaVBAv6KP9Fu31E5TKgyZSDsW
      p2tr: bc1p62cwvk8ve4mux8zhsp0h32h7dzl5ndgmmunk73hldvqx07y8pd0qd45eqq

Split a secret into SLIP-39 shares (any 2 of 3 recover it):

    $ echo 0123456789abcdef0123456789abcdef | hx slip39-split 2 3 passphrase > shares
    $ sed -n '1p;3p' shares | hx slip39-combine passphrase   # shares print as a list
    0123456789abcdef0123456789abcdef

### Signed messages and Schnorr signatures

    $ hx message-sign $K "Trust no one"
    IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk=
    $ hx message-verify 15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs \
        IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk= "Trust no one"
    true
    $ hx message-sign --type p2wpkh $K "Trust no one"   # BIP137 header for bc1q addresses

    $ hx schnorr-sign KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S \
        0000000000000000000000000000000000000000000000000000000000000000
    e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0

Use `-` to read a message from standard input verbatim (for example
`printf %s "$msg" | hx message-sign $K -`).

### Transactions with PSBT

Spend a P2WPKH output: build the unsigned transaction, wrap it in a PSBT,
attach the previous transaction, sign, finalize and extract it.

    $ hx mktx unsigned.tx --version 2 --rbf \
        --input c6da1b9c8674fd9a4d07f2a87be849f2f439ddc5ccdc1410ef3e5d760233dedd:0 \
        --output 1MyKMeDsom7rYcp69KpbKn4DcyuvLMkLYJ:90000 \
        --data 68656c6c6f
    $ hx psbt-create unsigned.tx | hx psbt-add-utxo 0 prev.tx > tx.psbt
    $ hx --json psbt-decode tx.psbt | jq .fee
    10000
    $ hx psbt-sign $K tx.psbt | hx psbt-finalize | hx psbt-extract > signed.tx
    $ hx showtx signed.tx
    txid: 171991de9084f82074f816451df5e8ce1559c93019cf3dc170bf0a969b0892a8
    wtxid: f948fe49892a78601f1392ce56f3e3dfff0801596c3cf8906021c7557f4464cd
    version: 2
    locktime: 0
    rbf: true
    size: 210
    vsize: 129
    weight: 513
    value_out: 90000
    inputs:
      - outpoint: c6da1b9c8674fd9a4d07f2a87be849f2f439ddc5ccdc1410ef3e5d760233dedd:0
        sequence: 4294967293
        address: bc1q9cy7s7nmzah0m6mt2ftmu6x723esjxqkkl4wsw
        witness:
          - 304402202f3f41d82642740cbd26c4b36466483d679c8aff50dc01cf9fc419e02ad3c2fb02207dbc347e55941ea4115eb4d2ac233031d588534e4554f61f9504663b2281297101
          - 03d2be3dddb497c7c4388cfcb941e14a222cf3e26fe5e2cc260da1821e60d26022
    outputs:
      - index: 0
        value: 90000
        type: p2pkh
        address: 1MyKMeDsom7rYcp69KpbKn4DcyuvLMkLYJ
        script:
          asm: dup hash160 [ e60921dbfe1e066113f1c6e0ea15517234187d47 ] equalverify checksig
          hex: 76a914e60921dbfe1e066113f1c6e0ea15517234187d4788ac
      - index: 1
        value: 0
        type: nulldata
        script:
          asm: return [ 68656c6c6f ]
          hex: 6a0568656c6c6f
    $ hx --json showtx signed.tx | jq -c '{txid, vsize, weight}'
    {"txid":"171991de9084f82074f816451df5e8ce1559c93019cf3dc170bf0a969b0892a8","vsize":129,"weight":513}

When the previous transaction is not at hand, give the spent amount and
script (or address) instead: `hx psbt-add-witness-utxo 0 100000 bc1q...`.
Taproot (BIP86) inputs are signed the same way with the WIF of the internal
key; on Bitcoin Cash add `-n bch` to every command.

### Low-level signing

Sign input 0 of a transaction directly. The private key is read from
standard input. SegWit (`--segwit`) and Bitcoin Cash signatures commit to the
amount of the spent output, given with `--value`.

    $ SCRIPT_CODE=$(hx rawscript dup hash160 [ 2e09e87a7b176efdeb6b5257be68de5473091816 ] equalverify checksig)
    $ SIG=$(echo $K | hx sign-input unsigned.tx 0 $SCRIPT_CODE --segwit --value 100000)
    $ hx set-witness unsigned.tx 0 $SIG $(echo $K | hx pubkey) > signed.tx
    $ echo $K | hx pubkey | hx validsig signed.tx 0 $SCRIPT_CODE $SIG --segwit --value 100000
    true

`--sighash` takes `all`, `none` or `single`, optionally followed by
`+anyonecanpay`.

### Scripts, encodings and hashes

    $ hx rawscript dup hash160 [ e60921dbfe1e066113f1c6e0ea15517234187d47 ] equalverify checksig
    76a914e60921dbfe1e066113f1c6e0ea15517234187d4788ac
    $ hx rawscript cltv drop
    b175
    $ echo ba | hx showscript
    checksigadd
    $ echo ba | hx -n bch showscript
    checkdatasig
    $ echo 68656c6c6f | hx tagged-hash TapLeaf
    cc0d501f9c9c9610e44edb939ad98d59a1a98739d0e26dbe932660ae33a8196e
    $ hx btc 123456789
    1.23456789
    $ hx satoshi 0.0001
    10000

List of commands
----------------

    # ADDRESSES
    hx addr [--type p2pkh|p2wpkh|p2sh-p2wpkh|p2tr]   (key on stdin)
    hx validaddr [<ADDRESS>]
    hx decode-addr
    hx encode-addr [--p2pkh|--p2sh|--p2wpkh|--p2wsh|--p2tr|--p2sh32|--token-p2pkh|--token-p2sh]
    hx addr-info [<ADDRESS>]
    hx addr-convert --to legacy|cashaddr|token
    hx addr-to-script [<ADDRESS>]
    hx script-to-addr [<SCRIPT>]
    hx script-addr [--p2sh|--p2wsh|--p2sh-p2wsh|--p2sh32]
    hx multisig [--sort] <M> <PUBKEY>...

    # KEYS
    hx newkey [--uncompressed]
    hx pubkey [--compressed|--uncompressed]
    hx xonly-pubkey
    hx wif-to-secret
    hx secret-to-wif [--uncompressed]
    hx mini-to-wif
    hx brainwallet <PASSPHRASE>
    hx compress
    hx uncompress

    # SIGNATURES AND MESSAGES
    hx message-sign [--type p2pkh|p2wpkh|p2sh-p2wpkh] <PRIVKEY> <MESSAGE>
    hx message-verify <ADDRESS> <SIGNATURE> <MESSAGE>
    hx sign-hash <PRIVKEY> <HEX-HASH32>
    hx verify-hash <PUBKEY> <DER-SIGNATURE> <HEX-HASH32>
    hx schnorr-sign <PRIVKEY> <HEX-MESSAGE32>
    hx schnorr-verify <XONLY-PUBKEY> <SIGNATURE> <HEX-MESSAGE32>
    hx signmsg-modn <MESSAGE-DECIMAL-INTEGER> <PRIVKEY>
    hx verifysig-modn <MESSAGE-DECIMAL-INTEGER> <PUBKEY> <SIGNATURE>

    # SCRIPTS
    hx rawscript <SCRIPT_OP>*
    hx showscript

    # TRANSACTIONS
    hx mktx <TXFILE> --input <TXID>:<INDEX>... --output <ADDR>:<SATOSHIS>...
            [--data <HEX>] [--version N] [--locktime N] [--sequence N] [--rbf]
    hx showtx [<TXFILE>]
    hx txid [<TXFILE>]
    hx sign-input <TXFILE> <INDEX> <SCRIPT_CODE> [--value SATOSHIS] [--segwit] [--sighash TYPE]
    hx set-input <TXFILE> <INDEX> <SCRIPT>
    hx set-witness <TXFILE> <INDEX> <HEX-ITEM>...
    hx validsig <TXFILE> <INDEX> <SCRIPT_CODE> <SIGNATURE> [--value SATOSHIS] [--segwit]

    # PARTIALLY SIGNED TRANSACTIONS (BIP174)
    hx psbt-create [<TXFILE>]
    hx psbt-decode [<PSBT>]
    hx psbt-add-utxo <INDEX> <PREVIOUS-TXFILE> [<PSBT>]
    hx psbt-add-witness-utxo <INDEX> <SATOSHIS> <SCRIPT|ADDRESS> [<PSBT>]
    hx psbt-sign <PRIVKEY|XPRV>... [<PSBT>]
    hx psbt-combine <PSBT> <PSBT>...
    hx psbt-finalize [<PSBT>]
    hx psbt-extract [<PSBT>]

    # HD WALLET (BIP32)
    hx hd-priv
    hx hd-priv <INDEX>
    hx hd-priv --hard <INDEX>
    hx hd-pub
    hx hd-pub <INDEX>
    hx hd-path <PATH>
    hx hd-decode
    hx hd-to-wif
    hx hd-to-address [--type p2pkh|p2wpkh|p2sh-p2wpkh|p2tr]
    hx hd-to-pubkey

    # ELECTRUM DETERMINISTIC WALLET (legacy, pre-2.0) [1]
    hx electrum-mpk
    hx electrum-priv <INDEX> [<CHANGE-0|1>] [<RANGE-STOP>]
    hx electrum-pub  <INDEX> [<CHANGE-0|1>] [<RANGE-STOP>]
    hx electrum-addr <INDEX> [<CHANGE-0|1>] [<RANGE-STOP>]
    hx electrum-seq  <INDEX> [<CHANGE-0|1>] [<RANGE-STOP>]
    hx electrum-stretch-seed

    # ELLIPTIC CURVE MATHS
    hx ec-multiply  <HEX-FIELDN> <HEX-POINT>
    hx ec-tweak-add <HEX-FIELDN> <HEX-POINT>
    hx ec-add-modp  <HEX-FIELDP> <HEX-FIELDP>
    hx ec-add-modn  <HEX-FIELDN> <HEX-FIELDN>
    hx ec-add       <HEX-POINT>  <HEX-POINT>
    hx ec-double    <HEX-POINT>
    hx ec-g | ec-p | ec-n | ec-a | ec-b | ec-inf
    hx ec-int-modp <DECIMAL-INTEGER>
    hx ec-int-modn <DECIMAL-INTEGER>
    hx ec-x <HEX-POINT>
    hx ec-y <HEX-POINT>

    # MNEMONICS AND SEED FORMATS
    hx bip39-new [<12|15|18|21|24>]
    hx bip39-mnemonic
    hx bip39-hex
    hx bip39-seed [<PASSPHRASE>]
    hx slip39-split <THRESHOLD> <SHARES> [<PASSPHRASE>]
    hx slip39-combine [<PASSPHRASE>]
    hx mnemonic                               [1]
    hx rfc1751-key
    hx rfc1751-mnemonic

    # BASIC ENCODINGS AND CONVERSIONS
    hx btc [<SATOSHIS>]                       [2]
    hx satoshi [<BTCS>]                       [2]
    hx integer
    hx hex-encode
    hx hex-decode
    hx base64-encode
    hx base64-decode
    hx base58-encode
    hx base58-decode
    hx base58check-encode [<VERSION-BYTE>]
    hx base58check-decode
    hx bech32-encode [--m] <HRP>
    hx bech32-decode

    # CHECKSUM32 (first 32bits of double sha256)
    hx chksum32 <HEX>*
    hx chksum32-encode <HEX>*
    hx chksum32-decode <HEX>*

    # HASHING
    hx ripemd-hash                            [3]
    hx sha1       [<HEX-INPUT>]
    hx sha256     [<HEX-INPUT>]
    hx sha512     [<HEX-INPUT>]
    hx ripemd160  [<HEX-INPUT>]
    hx hash160    [<HEX-INPUT>]
    hx hash256    [<HEX-INPUT>]
    hx tagged-hash <TAG> [<HEX-INPUT>]

    # HASH BASED MACs
    hx hmac-sha224 <HEX-KEY> [<HEX-INPUT>]
    hx hmac-sha256 <HEX-KEY> [<HEX-INPUT>]
    hx hmac-sha384 <HEX-KEY> [<HEX-INPUT>]
    hx hmac-sha512 <HEX-KEY> [<HEX-INPUT>]

    # PASSWORD BASED KEY DERIVATION FUNCTIONS
    hx sha1pbkdf1   [--hex] <PASSWORD> [--hex] <SALT> <COUNT>
    hx sha256pbkdf1 [--hex] <PASSWORD> [--hex] <SALT> <COUNT>
    hx sha512pbkdf1 [--hex] <PASSWORD> [--hex] <SALT> <COUNT>
    hx sha1pbkdf2   [--hex] <PASSWORD> [--hex] <SALT> <COUNT> <LENGTH>
    hx sha256pbkdf2 [--hex] <PASSWORD> [--hex] <SALT> <COUNT> <LENGTH>
    hx sha512pbkdf2 [--hex] <PASSWORD> [--hex] <SALT> <COUNT> <LENGTH>

    # MISC
    hx networks
    hx help
    hx version

    [1]: Compatible with the Electrum wallets of before version 2.0 and with
         `sx` (whose commands mpk, genpub, genpriv and genaddr are named
         electrum-mpk, electrum-pub, electrum-priv and electrum-addr here).
         electrum-seq and electrum-stretch-seed expose the inner workings of
         the key derivation.
    [2]: Rounding is upward: `hx btc 1.5` returns 0.00000002.
    [3]: ripemd-hash takes raw bytes; the other hashing commands take
         hexadecimal. `hx ripemd-hash` is `hx hex-encode | hx hash160`.

Compatibility notes
-------------------

Version 0.3 changes the output format: results are YAML or JSON documents
rather than ad hoc text.

* `showtx`, `hd-decode`, `addr-info` and `psbt-decode` have reorganized
  fields (for example `txid` instead of `hash`, scripts as `asm` and `hex`,
  inputs with an `outpoint`).
* `base58check-decode` and `bech32-decode` print documents with named fields
  instead of space-separated values; `networks`, `slip39-split` and Electrum
  key ranges print lists.
* Verifications print `true` or `false` instead of `Status: ...` and exit
  with status 1 when false.
* `mktx` ends its output with a newline when it prints to standard output.

Version 0.2 moved hx from the 2015 `haskoin` package to `haskoin-core` 1.6.
Its `pbkdf` commands use the raw bytes of `--hex` arguments rather than
their UTF-8 re-encoding.

License
-------

GPL-3.0. See [LICENSE](LICENSE).
