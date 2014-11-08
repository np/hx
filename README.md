hx
==

Bitcoin CLI tools: Haskell port of [Sx](https://github.com/spesmilo/sx) using [Haskoin](https://github.com/haskoin/haskoin)

Supported commands:

    hx pubkey [--compressed|--uncompressed]
    hx addr
    hx validaddr <ADDRESS>
    hx wif-to-secret
    hx secret-to-wif
    hx compress                               [0]
    hx uncompress                             [0]
    hx mktx <TXFILE> --input <TXHASH>:<INDEX> ... --output <ADDR>:<AMOUNT>
    hx showtx [-j|--json] <TXFILE>            [1]
    hx sign-input <TXFILE> <INDEX> <SCRIPT_CODE>
    hx set-input  <TXFILE> <INDEX> <SIGNATURE_AND_PUBKEY_SCRIPT>
    hx validsig   <TXFILE> <INDEX> <SCRIPT_CODE> <SIGNATURE>
    hx hd-priv                                [0]
    hx hd-priv <INDEX>
    hx hd-priv --hard <INDEX>
    hx hd-pub                                 [0]
    hx hd-pub <INDEX>
    hx hd-path <PATH>                         [0]
    hx hd-to-wif
    hx hd-to-address
    hx hd-to-pubkey                           [0]
    hx base58-encode
    hx base58-decode
    hx base58check-encode [<VERSION-BYTE>]
    hx base58check-decode
    hx decode-addr
    hx encode-addr
    hx encode-addr --script                   [0]
    hx rawscript <SCRIPT_OP>*
    hx showscript
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
    hx mnemonic
    hx bip39-mnemonic                         [0]
    hx bip39-hex                              [0]
    hx bip39-seed <PASSPHRASE>                [0]
    hx rfc1751-key                            [0]
    hx rfc1751-mnemonic                       [0]
    hx brainwallet <PASSPHRASE>               [0]
    hx integer                                [0]
    hx hex-encode                             [0]
    hx hex-decode                             [0]
    hx ripemd-hash
    hx sha256
    hx sha1                                   [0]
    hx ripemd160                              [0]
    hx hash160                                [0]
    hx hash256                                [0]

    [0]: Not available in sx
    [1]: `hx showtx` is always using JSON output,
         `-j` and `--json` are ignored.

    PATH      ::= <PATH-HEAD> <PATH-CONT>
    PATH-HEAD ::= 'A'   [address (compressed)]
                | 'M'   [extended public  key]
                | 'm'   [extended private key]
                | 'P'   [public  key (compressed)]
                | 'p'   [private key (compressed)]
                | 'U'   [uncompressed public  key]
                | 'u'   [uncompressed private key]
    PATH-CONT ::=                               [empty]
                | '/' <INDEX> <PATH-CONT>       [child key]
                | '/' <INDEX> '\'' <PATH-CONT>  [hardened child key]
