hx
==

Bitcoin CLI tools: Haskell port of Sx using Haskoin

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
      [1] hx ripemd-hash
      [1] hx sha256
      [2] hx hex-to-mnemonic
      [2] hx mnemonic-to-hex
    
      [1]: The output is consistent with openssl but NOT with sx
      [2]: The output is NOT consistent with sx (nor electrum I guess)
