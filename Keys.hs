{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Networks, keys and addresses: the glue between the command line and
-- Haskoin.
module Keys
  ( -- * Networks
    parseNetwork,
    networkNames,
    isCashNet,

    -- * Keys
    AnyKey (..),
    getKey,
    putKey,
    pubKeyOf,
    compressKey,
    uncompressKey,
    getPubKey,
    putPubKey,
    pubBytes,
    fromWifE,
    toWifBS,
    secretToWif,
    secKeyE,
    xOnlyBytes,
    taprootOutputBytes,

    -- * Addresses
    AddrType (..),
    parseAddrType,
    addrOfPub,
    addrText,
    addrTextMaybe,
    parseAddr,
    p2pkhOfPubBytes,
    hash160E,
    hash256E,
  )
where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Data.Char (toLower)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Text as T
import Context (ctx)
import EC (integerToBytes32)
import Haskoin hiding (decodeHex, encodeHex)
import Utils

-- * Networks

networkAliases :: [([String], Network)]
networkAliases =
  [ (["btc", "bitcoin", "main", "mainnet"], btc),
    (["btctest", "btc-test", "test", "testnet", "testnet3"], btcTest),
    (["btctest4", "btc-test4", "testnet4"], btcTest4),
    (["btcreg", "btc-regtest", "btcregtest", "regtest"], btcRegTest),
    (["bch", "bitcoincash", "bitcoin-cash", "cash"], bch),
    (["bchtest", "bch-test", "bchtestnet"], bchTest),
    (["bchtest4", "bch-test4", "bchtestnet4"], bchTest4),
    (["bchreg", "bch-regtest", "bchregtest"], bchRegTest)
  ]

networkNames :: [(String, [String])]
networkNames = [(n.name, aliases) | (aliases, n) <- networkAliases]

parseNetwork :: String -> Network
parseNetwork s =
  case [n | (aliases, n) <- networkAliases, map toLower s `elem` aliases] of
    n : _ -> n
    [] ->
      error $
        "Unknown network "
          ++ show s
          ++ ", expected one of: "
          ++ unwords [n | (n, _) <- networkNames]

isCashNet :: Network -> Bool
isCashNet net = isJust net.cashAddrPrefix

-- * Keys

data AnyKey = Prv PrivateKey | Pub PublicKey

pubBytes :: PublicKey -> BS
pubBytes = marshal ctx

getPubKey :: BS -> PublicKey
getPubKey =
  either (error . ("invalid public key: " ++)) id
    . unmarshal ctx
    . decodeHex "public key"

putPubKey :: PublicKey -> BS
putPubKey = encodeHex . pubBytes

fromWifE :: Network -> BS -> PrivateKey
fromWifE net =
  fromMaybe (error "invalid WIF private key")
    . fromWif net
    . toText
    . ignoreSpaces

toWifBS :: Network -> PrivateKey -> BS
toWifBS net = fromText . toWif net

secKeyE :: BS -> SecKey
secKeyE s
  | BS.length s /= 32 =
      error $
        "invalid private key size, should be 256 bits and not "
          ++ show (BS.length s * 8)
          ++ " bits"
  | otherwise = fromMaybe (error "invalid private key") (secKey s)

secretToWif :: Network -> Bool -> Integer -> BS
secretToWif net compressed =
  toWifBS net . wrapSecKey compressed . secKeyE . integerToBytes32

-- | A key given either as a hexadecimal public key (which starts with a 0)
-- or as a WIF private key.
getKey :: Network -> BS -> AnyKey
getKey net s0
  | Just ('0', _) <- B8.uncons s = Pub (getPubKey s)
  | otherwise = Prv (fromWifE net s)
  where
    s = ignoreSpaces s0

putKey :: Network -> AnyKey -> BS
putKey net (Prv k) = toWifBS net k
putKey _ (Pub k) = putPubKey k

pubKeyOf :: AnyKey -> PublicKey
pubKeyOf (Prv k) = derivePublicKey ctx k
pubKeyOf (Pub k) = k

compressKey, uncompressKey :: AnyKey -> AnyKey
compressKey (Prv k) = Prv (PrivateKey k.key True)
compressKey (Pub k) = Pub (PublicKey k.point True)
uncompressKey (Prv k) = Prv (PrivateKey k.key False)
uncompressKey (Pub k) = Pub (PublicKey k.point False)

-- | The 32-byte x-only serialization of a public key (BIP 340).
xOnlyBytes :: PublicKey -> BS
xOnlyBytes pub = exportXOnlyPubKey ctx pub.point

-- | The x-only output key of a BIP 86 Taproot output (key path only).
taprootOutputBytes :: PublicKey -> BS
taprootOutputBytes pub =
  exportXOnlyPubKey ctx $ taprootOutputKey ctx (TaprootOutput pub.point Nothing)

-- * Addresses

data AddrType = AddrP2PKH | AddrP2WPKH | AddrP2SH_P2WPKH | AddrP2TR
  deriving (Eq, Show)

parseAddrType :: BS -> AddrType
parseAddrType s = case B8.map toLower s of
  t
    | t `elem` ["p2pkh", "legacy", "pkh"] -> AddrP2PKH
    | t `elem` ["p2wpkh", "segwit", "bech32", "wpkh"] -> AddrP2WPKH
    | t `elem` ["p2sh-p2wpkh", "p2sh-segwit", "nested", "compat", "sh-wpkh"] -> AddrP2SH_P2WPKH
    | t `elem` ["p2tr", "taproot", "tr", "bip86"] -> AddrP2TR
  _ -> error $ "Unknown address type " ++ show s ++ ", expected p2pkh, p2wpkh, p2sh-p2wpkh or p2tr"

addrOfPub :: AddrType -> PublicKey -> Address
addrOfPub AddrP2PKH pub = pubKeyAddr ctx pub
addrOfPub AddrP2WPKH pub =
  fromMaybe (error "SegWit addresses require a compressed public key") $
    pubKeyWitnessAddr ctx pub
addrOfPub AddrP2SH_P2WPKH pub =
  fromMaybe (error "SegWit addresses require a compressed public key") $
    pubKeyCompatWitnessAddr ctx pub
addrOfPub AddrP2TR pub =
  fromMaybe (error "cannot build the Taproot address") $
    witnessAddress 1 (taprootOutputBytes pub)

addrTextMaybe :: Network -> Address -> Maybe BS
addrTextMaybe net = fmap fromText . addrToText net

-- | Render an address in the native format of the network: Base58 or Bech32
-- for Bitcoin, CashAddr for Bitcoin Cash.
addrText :: Network -> Address -> BS
addrText net a =
  fromMaybe
    (error $ "This address type cannot be encoded on network " ++ net.name)
    (addrTextMaybe net a)

-- | Parse an address in any format the network accepts: Base58, Bech32 or
-- Bech32m on Bitcoin; CashAddr (with or without prefix) or legacy Base58 on
-- Bitcoin Cash.
parseAddr :: Network -> BS -> Address
parseAddr net s =
  fromMaybe (error $ "invalid address for network " ++ net.name) $
    textToAddr net t
  where
    t = T.strip (toText s)

p2pkhOfPubBytes :: BS -> Address
p2pkhOfPubBytes = p2pkhAddr . addressHash

hash160E :: BS -> Hash160
hash160E = decodeS "hash160" . decodeHexBytes "hash160" 20

hash256E :: BS -> Hash256
hash256E = decodeS "hash256" . decodeHexBytes "hash256" 32
