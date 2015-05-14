hx
==

Bitcoin CLI tools: Haskell port of [Sx](https://github.com/spesmilo/sx) using [Haskoin](https://github.com/haskoin/haskoin)

[![Join the chat at https://gitter.im/np/hx](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/np/hx?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

List of supported commands:

    # ADDRESSES

    hx addr
    hx validaddr [<ADDRESS>]
    hx decode-addr
    hx encode-addr
    hx encode-addr --script                   [0]

    # KEYS
    hx pubkey [--compressed|--uncompressed]
    hx wif-to-secret
    hx secret-to-wif
    hx brainwallet <PASSPHRASE>
    hx compress                               [0]
    hx uncompress                             [0]

    # SCRIPTS
    hx rawscript <SCRIPT_OP>*
    hx showscript

    # TRANSACTIONS
    hx mktx <TXFILE> --input <TXHASH>:<INDEX> ... --output <ADDR>:<AMOUNT>
    hx showtx [-j|--json] <TXFILE>            [1]
    hx sign-input <TXFILE> <INDEX> <SCRIPT_CODE>
    hx set-input  <TXFILE> <INDEX> <SIGNATURE_AND_PUBKEY_SCRIPT>
    hx validsig   <TXFILE> <INDEX> <SCRIPT_CODE> <SIGNATURE>

    # HD WALLET (BIP32)
    hx hd-priv                                [0]
    hx hd-priv <INDEX>
    hx hd-priv --hard <INDEX>
    hx hd-pub                                 [0]
    hx hd-pub <INDEX>
    hx hd-path <PATH>                         [0]
    hx hd-to-wif
    hx hd-to-address
    hx hd-to-pubkey                           [0]

    # ELECTRUM DETERMINISTIC WALLET [2]
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
    hx ec-add-modn  <HEX-FIELDN> <HEX-FIELDN> [0]
    hx ec-add       <HEX-POINT>  <HEX-POINT>  [0]
    hx ec-double    <HEX-POINT>               [0]
    hx ec-g                                   [0]
    hx ec-p                                   [0]
    hx ec-n                                   [0]
    hx ec-a                                   [0]
    hx ec-b                                   [0]
    hx ec-inf                                 [0]
    hx ec-int-modp <DECIMAL-INTEGER>          [0]
    hx ec-int-modn <DECIMAL-INTEGER>          [0]
    hx ec-x <HEX-POINT>                       [0]
    hx ec-y <HEX-POINT>                       [0]

    # MNEMONICS AND SEED FORMATS
    hx mnemonic
    hx bip39-mnemonic                         [0]
    hx bip39-hex                              [0]
    hx bip39-seed <PASSPHRASE>                [0]
    hx rfc1751-key                            [0]
    hx rfc1751-mnemonic                       [0]

    # BASIC ENCODINGS AND CONVERSIONS
    hx btc [<SATOSHIS>]                       [3]
    hx satoshi [<BTCS>]                       [3]
    hx integer                                [0]
    hx hex-encode                             [0]
    hx hex-decode                             [0]

    # BASE58 ENCODING
    hx base58-encode
    hx base58-decode
    hx base58check-encode [<VERSION-BYTE>]
    hx base58check-decode

    # CHECKSUM32 (first 32bits of double sha256) [0]
    hx chksum32 <HEX>*
    hx chksum32-encode <HEX>*
    hx chksum32-decode <HEX>*

    # HASHING
    hx ripemd-hash                            [4]
    hx sha256      [<HEX-INPUT>]
    hx ripemd160   [<HEX-INPUT>]              [0]
    hx sha1        [<HEX-INPUT>]              [0]
    hx hash160     [<HEX-INPUT>]              [0]
    hx hash256                                [0]

    # HASH BASED MACs
    hx hmac-sha224 <KEY> [<HEX-NPUT>]         [0]
    hx hmac-sha256 <KEY> [<HEX-NPUT>]         [0]
    hx hmac-sha384 <KEY> [<HEX-NPUT>]         [0]
    hx hmac-sha512 <KEY> [<HEX-NPUT>]         [0]

    [0]: Not available in sx
    [1]: `hx showtx` is always using JSON output,
         `-j` and `--json` are ignored.
    [2]: The compatibility has been checked with electrum and with `sx`.
         However if your `sx mpk` returns a hex representation of `64` digits,
         then you *miss* half of it.
         Moreover subsequent commands (genpub/genaddr) might behave
         non-deterministically.
         Finally they have different names:
           mpk     -> electrum-mpk
           genpub  -> electrum-pub
           genpriv -> electrum-priv
           genaddr -> electrum-addr
         The commands electrum-seq and electrum-stretch-seed expose
         the inner workings of the key derivation process.
    [3]: Rounding is done upward in `hx` and downard in `sx`.
         So they agree `btc 1.4` and `btc 1.9` but on `btc 1.5`,
         `hx` returns `0.00000002` and `sx` returns `0.00000001`.
    [4]: The `ripemd-hash` command is taking raw-bytes as input,
         while the other hashing commands are taking hexadecimal encoded inputs.
         This is for this reason that `hash160` has been added
         (`hx ripemd-hash` is equivalent to `hx encode-hex | hx hash160`
         and `hx hash160` is equivalent to `hx decode-hex | hx ripemd-hash`).

    PATH      ::= <PATH-HEAD> <PATH-CONT>
    PATH-HEAD ::= 'A'   [address (compressed)]
                | 'M'   [extended public  key]
                | 'm'   [extended private key]
                | 'P'   [public  key (compressed)]
                | 'p'   [private key (compressed)]
                | 'U'   [uncompressed public  key]
                | 'u'   [uncompressed private key]
    PATH-CONT ::=                                [empty]
                | '/' <INDEX> <PATH-CONT>        [child key]
                | '/' <INDEX> '\'' <PATH-CONT>  [hardened child key]
