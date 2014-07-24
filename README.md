hx
==

Bitcoin CLI tools: Haskell port of [Sx](https://github.com/spesmilo/sx) using [Haskoin](https://github.com/haskoin/haskoin)

Supported commands:

      hx pubkey
      hx addr
      hx wif-to-secret
      hx secret-to-wif
      hx hd-priv INDEX
      hx hd-priv --hard INDEX
      hx hd-pub
      hx hd-pub INDEX
      hx hd-to-wif
      hx hd-to-address
      hx btc SATOSHI
      hx satoshi BTC
      [1] hx ripemd-hash
      [1] hx sha256
      [2] hx hex-to-mnemonic
      [2] hx mnemonic-to-hex

      [1]: The output is consistent with openssl but NOT with sx
      [2]: The output is NOT consistent with sx (nor electrum I guess)
