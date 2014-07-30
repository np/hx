hx
==

Bitcoin CLI tools: Haskell port of [Sx](https://github.com/spesmilo/sx) using [Haskoin](https://github.com/haskoin/haskoin)

Supported commands:

    hx pubkey
    hx addr
    hx wif-to-secret
    hx secret-to-wif
    hx mktx <TXFILE> --input <TXHASH>:<INDEX> ... --output <ADDR>:<AMOUNT>
    hx sign-input <TXFILE> <INDEX> <SCRIPT_CODE>
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
    hx base58check-encode
    hx base58check-decode
    hx decode-addr
    hx encode-addr
    hx encode-addr --script                   [0]
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
    hx ec-int-p <DECIMAL-INTEGER>             [0]
    hx ec-int-n <DECIMAL-INTEGER>             [0]
    hx ec-x     <HEX-POINT>                   [0]
    hx ec-x     <HEX-POINT>                   [0]
    hx bip39-mnemonic                         [0]
    hx bip39-hex                              [0]
    hx bip39-seed <PASSPHRASE>                [0]
    hx rfc1751-key                            [0]
    hx rfc1751-mnemonic                       [0]
    hx ripemd-hash                            [1]
    hx sha256                                 [1]

    [0]: Not available in sx
    [1]: The output is consistent with openssl but NOT with sx
    PATH ::= ('M' | 'm') <PATH-CONT>
    PATH-CONT ::= {- empty -}
                | '/' <INDEX> <PATH-CONT>
                | '/' <INDEX> '\'' <PATH-CONT>
